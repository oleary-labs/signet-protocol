package node

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"
	"go.uber.org/zap"

	"signet/tss"
	"signet/network"
)

// shardKey is the composite cache key for a stored key shard.
type shardKey struct {
	GroupID string
	KeyID   string
}

// GroupInfo holds the resolved membership for a group contract. It is
// populated at startup by the chain client and kept up to date via events.
type GroupInfo struct {
	Threshold int
	Members   []tss.PartyID // libp2p peer IDs of active members, sorted
}

// Node owns a libp2p host, an HTTP API server, and threshold signing state.
type Node struct {
	cfg    *Config
	host   *network.Host
	server *http.Server
	log    *zap.Logger
	ctx    context.Context
	cancel context.CancelFunc

	store   *KeyShardStore
	mu      sync.RWMutex
	configs map[shardKey]*tss.Config // in-memory cache: (group_id, key_id) → key config

	groupsMu sync.RWMutex
	groups   map[string]*GroupInfo // group contract address → resolved membership

	auth     *GroupAuth    // per-group OAuth trust store
	sessions *SessionStore // ephemeral session key cache
	chain    *ChainClient  // nil if no eth_rpc configured
}

// NodeInfo is returned by the /v1/info endpoint.
type NodeInfo struct {
	PeerID          string   `json:"peer_id"`
	EthereumAddress string   `json:"ethereum_address"`
	Addrs           []string `json:"addrs"`
	NodeType        string   `json:"node_type"`
}

// New creates a Node from cfg: loads/generates the secp256k1 key, starts the
// libp2p host, dials bootstrap peers, and wires up the HTTP server.
func New(cfg *Config, log *zap.Logger) (*Node, error) {
	ctx, cancel := context.WithCancel(context.Background())

	if _, err := os.Stat(cfg.DataDir); err != nil {
		cancel()
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("data directory does not exist: %s", cfg.DataDir)
		}
		return nil, fmt.Errorf("stat data dir: %w", err)
	}

	keyFile := filepath.Join(cfg.DataDir, "node.key")
	h, err := network.NewHostFromFile(ctx, keyFile, cfg.ListenAddr)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("create host: %w", err)
	}

	store, err := openKeyShardStore(cfg.DataDir)
	if err != nil {
		h.Close()
		cancel()
		return nil, fmt.Errorf("open key shard store: %w", err)
	}

	// Dial each bootstrap peer; connection failures are non-fatal.
	for _, bpStr := range cfg.BootstrapPeers {
		maddr, err := ma.NewMultiaddr(bpStr)
		if err != nil {
			store.Close()
			h.Close()
			cancel()
			return nil, fmt.Errorf("parse bootstrap peer %q: %w", bpStr, err)
		}
		pi, err := peer.AddrInfoFromP2pAddr(maddr)
		if err != nil {
			store.Close()
			h.Close()
			cancel()
			return nil, fmt.Errorf("addr info from %q: %w", bpStr, err)
		}
		if err := h.LibP2PHost().Connect(ctx, *pi); err != nil {
			log.Warn("bootstrap peer unreachable", zap.String("peer", pi.ID.String()), zap.Error(err))
			continue
		}
		h.RegisterPeer(tss.PartyID(pi.ID.String()), pi.ID)
		log.Info("connected to bootstrap peer", zap.String("peer", pi.ID.String()))
	}

	// Load circuit verification key if configured (required for production ZK auth).
	var circuitVK []byte
	if cfg.VKPath != "" {
		var err error
		circuitVK, err = os.ReadFile(cfg.VKPath)
		if err != nil {
			store.Close()
			h.Close()
			cancel()
			return nil, fmt.Errorf("read circuit VK from %s: %w", cfg.VKPath, err)
		}
		log.Info("loaded circuit verification key", zap.String("path", cfg.VKPath), zap.Int("bytes", len(circuitVK)))
	}

	n := &Node{
		cfg:     cfg,
		host:    h,
		log:     log,
		ctx:     ctx,
		cancel:  cancel,
		store:   store,
		configs: make(map[shardKey]*tss.Config),
		groups:   make(map[string]*GroupInfo),
		auth:     newGroupAuth(ctx, cfg.TestMode, circuitVK, log),
		sessions: newSessionStore(),
	}
	n.sessions.startCleanupLoop(ctx)

	// Wire the chain client when eth_rpc and factory_address are configured.
	if cfg.EthRPC != "" && cfg.FactoryAddress != "" {
		chain, err := newChainClient(cfg, h, n, log)
		if err != nil {
			store.Close()
			h.Close()
			cancel()
			return nil, fmt.Errorf("chain client: %w", err)
		}
		if err := chain.loadGroups(ctx); err != nil {
			log.Warn("chain: initial group load failed", zap.Error(err))
		}
		chain.start()
		n.chain = chain
	}

	n.registerCoordHandler()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/health", n.handleHealth)
	mux.HandleFunc("GET /v1/info", n.handleInfo)
	mux.HandleFunc("GET /v1/keys", n.handleListKeys)
	mux.HandleFunc("POST /v1/auth", n.handleAuth)
	mux.HandleFunc("POST /v1/keygen", n.handleKeygen)
	mux.HandleFunc("POST /v1/sign", n.handleSign)
	n.server = &http.Server{Addr: cfg.APIAddr, Handler: mux}

	return n, nil
}

// Start begins serving the HTTP API in a background goroutine.
func (n *Node) Start() error {
	n.log.Info("starting HTTP API", zap.String("addr", n.cfg.APIAddr))
	go func() {
		if err := n.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			n.log.Error("HTTP server error", zap.Error(err))
		}
	}()
	return nil
}

// Stop gracefully shuts down the HTTP server, the libp2p host, the worker pool,
// and the key shard store.
func (n *Node) Stop() error {
	n.log.Info("stopping node")
	if n.chain != nil {
		n.chain.close()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := n.server.Shutdown(ctx); err != nil {
		return fmt.Errorf("shutdown HTTP server: %w", err)
	}
	n.host.Close()
	if err := n.store.Close(); err != nil {
		n.log.Warn("close key shard store", zap.Error(err))
	}
	n.cancel()
	n.log.Info("node stopped")
	return nil
}

// Info returns the current node information.
func (n *Node) Info() NodeInfo {
	pid := n.host.PeerID()
	pub := n.host.LibP2PHost().Peerstore().PubKey(pid)

	ethAddr := ""
	if pub != nil {
		addr, err := network.EthereumAddress(pub)
		if err == nil {
			ethAddr = "0x" + hex.EncodeToString(addr[:])
		}
	}

	return NodeInfo{
		PeerID:          pid.String(),
		EthereumAddress: ethAddr,
		Addrs:           n.host.Addrs(),
		NodeType:        n.cfg.NodeType,
	}
}

// cachedConfig returns a config from the in-memory cache, or loads it from the
// store and caches it. Returns (nil, nil) when the (groupID, keyID) is not found.
func (n *Node) cachedConfig(groupID, keyID string) (*tss.Config, error) {
	k := shardKey{groupID, keyID}

	n.mu.RLock()
	cfg, ok := n.configs[k]
	n.mu.RUnlock()
	if ok {
		return cfg, nil
	}

	cfg, err := n.store.Get(groupID, keyID)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, nil
	}

	n.mu.Lock()
	n.configs[k] = cfg
	n.mu.Unlock()
	return cfg, nil
}

// randomNonce returns a short random hex string for sign session disambiguation.
func randomNonce() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// --- HTTP handlers ---

func (n *Node) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"ok"}`))
}

func (n *Node) handleInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(n.Info())
}

// handleListKeys returns public metadata for all persisted key shards.
//
// GET /v1/keys                       — all groups and their keys
// GET /v1/keys?group_id=0xGroupAddr  — keys for a specific group
func (n *Node) handleListKeys(w http.ResponseWriter, r *http.Request) {
	type keyEntry struct {
		GroupID         string   `json:"group_id"`
		KeyID           string   `json:"key_id"`
		EthereumAddress string   `json:"ethereum_address"`
		Threshold       int      `json:"threshold"`
		Parties         []string `json:"parties"`
	}

	filterGroup := r.URL.Query().Get("group_id")

	var groupIDs []string
	if filterGroup != "" {
		groupIDs = []string{filterGroup}
	} else {
		var err error
		groupIDs, err = n.store.ListGroups()
		if err != nil {
			httpError(w, http.StatusInternalServerError, "list groups: "+err.Error())
			return
		}
	}

	entries := make([]keyEntry, 0)
	for _, gid := range groupIDs {
		keyIDs, err := n.store.List(gid)
		if err != nil {
			httpError(w, http.StatusInternalServerError, "list keys: "+err.Error())
			return
		}
		for _, kid := range keyIDs {
			cfg, err := n.cachedConfig(gid, kid)
			if err != nil || cfg == nil {
				continue
			}
			ethAddr := ""
			if addr, err := network.EthereumAddressFromGroupKey(cfg.GroupKey); err == nil {
				ethAddr = "0x" + hex.EncodeToString(addr[:])
			}
			partyIDs := cfg.Parties
			parties := make([]string, len(partyIDs))
			for i, p := range partyIDs {
				parties[i] = string(p)
			}
			entries = append(entries, keyEntry{
				GroupID:         gid,
				KeyID:           kid,
				EthereumAddress: ethAddr,
				Threshold:       cfg.Threshold,
				Parties:         parties,
			})
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(entries)
}

// handleAuth registers an ephemeral session key with verified identity claims.
//
// POST /v1/auth
//
// Test mode:
//
//	{"group_id":"0x...","token":"eyJ...","session_pub":"02abc..."}
//
// Production mode:
//
//	{"group_id":"0x...","proof":"hex...","session_pub":"02abc...",
//	 "sub":"user123","iss":"https://...","exp":1709900000,
//	 "aud":"app.example.com","azp":"client-id","jwks_modulus":"hex..."}
func (n *Node) handleAuth(w http.ResponseWriter, r *http.Request) {
	var req struct {
		GroupID     string `json:"group_id"`
		Token       string `json:"token"`        // test mode: raw JWT
		Proof       string `json:"proof"`         // production: ZK proof hex
		SessionPub  string `json:"session_pub"`   // hex, 33-byte compressed secp256k1
		Sub         string `json:"sub"`           // production: JWT subject
		Iss         string `json:"iss"`           // production: JWT issuer
		Exp         uint64 `json:"exp"`           // production: JWT expiry unix timestamp
		Aud         string `json:"aud"`           // production: JWT audience
		Azp         string `json:"azp"`           // production: JWT authorized party
		JWKSModulus string `json:"jwks_modulus"`  // production: RSA modulus hex
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, "decode body: "+err.Error())
		return
	}
	if req.GroupID == "" || req.SessionPub == "" {
		httpError(w, http.StatusBadRequest, "group_id and session_pub are required")
		return
	}

	sessionPubBytes, err := hex.DecodeString(strings.TrimPrefix(req.SessionPub, "0x"))
	if err != nil || len(sessionPubBytes) != 33 {
		httpError(w, http.StatusBadRequest, "session_pub must be 33 hex-encoded bytes")
		return
	}

	if n.cfg.TestMode {
		// Test mode: validate JWT directly, cache session binding.
		if req.Token == "" {
			httpError(w, http.StatusBadRequest, "token is required in test mode")
			return
		}
		claims, err := n.auth.ValidateJWTForSession(r.Context(), req.GroupID, []byte(req.Token))
		if err != nil {
			httpError(w, http.StatusUnauthorized, "invalid token: "+err.Error())
			return
		}
		pubHex := sessionPubToHex(sessionPubBytes)
		n.sessions.Put(pubHex, &SessionInfo{
			Sub: claims.Sub,
			Iss: claims.Iss,
			Exp: claims.Exp,
			Aud: claims.Aud,
			Azp: claims.Azp,
		})
		n.log.Info("auth: session registered (test mode)",
			zap.String("group_id", req.GroupID),
			zap.String("sub", claims.Sub),
			zap.String("session_pub", pubHex))

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"status":     "ok",
			"sub":        claims.Sub,
			"expires_at": claims.Exp.Unix(),
		})
	} else {
		// Production mode: verify ZK proof and cache session.
		if req.Proof == "" {
			httpError(w, http.StatusBadRequest, "proof is required in production mode")
			return
		}
		if req.Sub == "" || req.Iss == "" || req.Exp == 0 {
			httpError(w, http.StatusBadRequest, "sub, iss, and exp are required in production mode")
			return
		}
		if req.JWKSModulus == "" {
			httpError(w, http.StatusBadRequest, "jwks_modulus is required in production mode")
			return
		}

		proofBytes, err := hex.DecodeString(strings.TrimPrefix(req.Proof, "0x"))
		if err != nil || len(proofBytes) == 0 {
			httpError(w, http.StatusBadRequest, "invalid proof hex")
			return
		}
		modulusBytes, err := hex.DecodeString(strings.TrimPrefix(req.JWKSModulus, "0x"))
		if err != nil || len(modulusBytes) == 0 {
			httpError(w, http.StatusBadRequest, "invalid jwks_modulus hex")
			return
		}

		ap := &AuthProof{
			Proof:       proofBytes,
			Sub:         req.Sub,
			Iss:         req.Iss,
			Exp:         req.Exp,
			Aud:         req.Aud,
			Azp:         req.Azp,
			JWKSModulus: modulusBytes,
			SessionPub:  sessionPubBytes,
		}

		sub, err := n.auth.ValidateAuthProof(r.Context(), req.GroupID, ap)
		if err != nil {
			httpError(w, http.StatusUnauthorized, "proof verification failed: "+err.Error())
			return
		}

		pubHex := sessionPubToHex(sessionPubBytes)
		n.sessions.Put(pubHex, &SessionInfo{
			Sub:         sub,
			Iss:         req.Iss,
			Exp:         time.Unix(int64(req.Exp), 0),
			Aud:         req.Aud,
			Azp:         req.Azp,
			Proof:       proofBytes,
			JWKSModulus: modulusBytes,
		})
		n.log.Info("auth: session registered (production)",
			zap.String("group_id", req.GroupID),
			zap.String("sub", sub),
			zap.String("session_pub", pubHex))

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"status":     "ok",
			"sub":        sub,
			"expires_at": int64(req.Exp),
		})
	}
}

// handleKeygen runs a distributed key generation session.
//
// POST /v1/keygen
//
//	{"group_id":"0xGroupAddr","key_id":"primary"}
//
// Session-auth mode (groups with issuers):
//
//	{"group_id":"0x...","key_suffix":"primary",
//	 "session_pub":"02abc...","request_sig":"hex64","nonce":"hex","timestamp":123}
//
// The key shard is stored under (group_id, key_id). The group members and
// threshold are resolved from the node's in-memory group map.
func (n *Node) handleKeygen(w http.ResponseWriter, r *http.Request) {
	var req struct {
		GroupID    string `json:"group_id"`
		KeyID      string `json:"key_id"`
		KeySuffix  string `json:"key_suffix"`
		SessionPub string `json:"session_pub"`
		RequestSig string `json:"request_sig"`
		Nonce      string `json:"nonce"`
		Timestamp  uint64 `json:"timestamp"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, "decode body: "+err.Error())
		return
	}
	if req.GroupID == "" {
		httpError(w, http.StatusBadRequest, "group_id is required")
		return
	}

	n.groupsMu.RLock()
	grp, ok := n.groups[req.GroupID]
	n.groupsMu.RUnlock()
	if !ok {
		httpError(w, http.StatusNotFound, "group not found: "+req.GroupID)
		return
	}

	keyID := req.KeyID
	var authToken []byte
	var authProof *AuthProof

	if n.auth.HasIssuers(req.GroupID) {
		if req.SessionPub != "" {
			// New path: session-based auth.
			ap, resolvedKeyID, err := n.validateSessionRequest(
				req.SessionPub, req.RequestSig,
				req.GroupID, req.KeyID, req.KeySuffix,
				req.Nonce, req.Timestamp,
				nil, // no message_hash for keygen
			)
			if err != nil {
				httpError(w, err.code, err.msg)
				return
			}
			keyID = resolvedKeyID
			authProof = ap
		} else if token := extractBearer(r); token != "" {
			// Legacy path: raw JWT in Authorization header.
			issAndSub, err := n.auth.ValidateJWT(r.Context(), req.GroupID, []byte(token))
			if err != nil {
				httpError(w, http.StatusUnauthorized, "invalid token: "+err.Error())
				return
			}
			keyID = issAndSub
			if req.KeySuffix != "" {
				keyID = issAndSub + ":" + req.KeySuffix
			}
			authToken = []byte(token)
		} else {
			httpError(w, http.StatusUnauthorized, "authorization required")
			return
		}
	} else if keyID == "" {
		httpError(w, http.StatusBadRequest, "key_id is required")
		return
	}

	sortedParties := tss.NewPartyIDSlice(grp.Members)
	sessID := keygenSessionID(req.GroupID, keyID)

	n.log.Info("keygen starting",
		zap.String("group_id", req.GroupID),
		zap.String("key_id", keyID),
		zap.Int("n", len(sortedParties)),
		zap.Int("threshold", grp.Threshold),
	)

	sn, err := network.NewSessionNetwork(r.Context(), n.host, sessID, sortedParties)
	if err != nil {
		httpError(w, http.StatusInternalServerError, "session network: "+err.Error())
		return
	}
	defer sn.Close()

	if err := n.broadcastCoord(r.Context(), sortedParties, coordMsg{
		Type:      msgKeygen,
		GroupID:   req.GroupID,
		KeyID:     keyID,
		Parties:   sortedParties,
		Threshold: grp.Threshold,
		AuthToken: authToken,
		Auth:      authProof,
	}); err != nil {
		httpError(w, http.StatusInternalServerError, "coordinate: "+err.Error())
		return
	}

	cfg, err := runKeygenOn(r.Context(), n.host, sn, sessID, sortedParties, grp.Threshold)
	if err != nil {
		n.log.Error("keygen failed",
			zap.String("group_id", req.GroupID),
			zap.String("key_id", keyID),
			zap.Error(err))
		httpError(w, http.StatusInternalServerError, "keygen: "+err.Error())
		return
	}

	if err := n.store.Put(req.GroupID, keyID, cfg); err != nil {
		n.log.Warn("persist shard failed",
			zap.String("group_id", req.GroupID),
			zap.String("key_id", keyID),
			zap.Error(err))
	}
	n.mu.Lock()
	n.configs[shardKey{req.GroupID, keyID}] = cfg
	n.mu.Unlock()

	ethAddr, err := network.EthereumAddressFromGroupKey(cfg.GroupKey)
	if err != nil {
		httpError(w, http.StatusInternalServerError, "eth addr: "+err.Error())
		return
	}

	n.log.Info("keygen complete",
		zap.String("group_id", req.GroupID),
		zap.String("key_id", keyID),
		zap.String("eth_addr", "0x"+hex.EncodeToString(ethAddr[:])),
	)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"group_id":         req.GroupID,
		"key_id":           keyID,
		"public_key":       "0x" + hex.EncodeToString(cfg.GroupKey),
		"ethereum_address": "0x" + hex.EncodeToString(ethAddr[:]),
	})
}

// handleSign runs a threshold signing session using a previously generated key.
//
// POST /v1/sign
//
//	{"group_id":"0xGroupAddr","key_id":"primary","message_hash":"0xdeadbeef..."}
//
// Session-auth mode (groups with issuers):
//
//	{"group_id":"0x...","key_suffix":"primary","message_hash":"0xdeadbeef...",
//	 "session_pub":"02abc...","request_sig":"hex64","nonce":"hex","timestamp":123}
func (n *Node) handleSign(w http.ResponseWriter, r *http.Request) {
	var req struct {
		GroupID     string `json:"group_id"`
		KeyID       string `json:"key_id"`
		KeySuffix   string `json:"key_suffix"`
		MessageHash string `json:"message_hash"`
		SessionPub  string `json:"session_pub"`
		RequestSig  string `json:"request_sig"`
		Nonce       string `json:"nonce"`
		Timestamp   uint64 `json:"timestamp"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, "decode body: "+err.Error())
		return
	}
	if req.GroupID == "" || req.MessageHash == "" {
		httpError(w, http.StatusBadRequest, "group_id and message_hash are required")
		return
	}

	msgHash, err := hex.DecodeString(strings.TrimPrefix(req.MessageHash, "0x"))
	if err != nil {
		httpError(w, http.StatusBadRequest, "invalid message_hash: "+err.Error())
		return
	}
	if len(msgHash) != 32 {
		httpError(w, http.StatusBadRequest, "message_hash must be exactly 32 bytes (64 hex chars)")
		return
	}

	n.groupsMu.RLock()
	grp, ok := n.groups[req.GroupID]
	n.groupsMu.RUnlock()
	if !ok {
		httpError(w, http.StatusNotFound, "group not found: "+req.GroupID)
		return
	}

	keyID := req.KeyID
	var authToken []byte
	var authProof *AuthProof

	if n.auth.HasIssuers(req.GroupID) {
		if req.SessionPub != "" {
			// New path: session-based auth.
			ap, resolvedKeyID, err := n.validateSessionRequest(
				req.SessionPub, req.RequestSig,
				req.GroupID, req.KeyID, req.KeySuffix,
				req.Nonce, req.Timestamp,
				msgHash,
			)
			if err != nil {
				httpError(w, err.code, err.msg)
				return
			}
			keyID = resolvedKeyID
			authProof = ap
		} else if token := extractBearer(r); token != "" {
			// Legacy path: raw JWT in Authorization header.
			issAndSub, err := n.auth.ValidateJWT(r.Context(), req.GroupID, []byte(token))
			if err != nil {
				httpError(w, http.StatusUnauthorized, "invalid token: "+err.Error())
				return
			}
			keyID = issAndSub
			if req.KeySuffix != "" {
				keyID = issAndSub + ":" + req.KeySuffix
			}
			authToken = []byte(token)
		} else {
			httpError(w, http.StatusUnauthorized, "authorization required")
			return
		}
	} else if keyID == "" {
		httpError(w, http.StatusBadRequest, "key_id is required")
		return
	}

	cfg, err := n.cachedConfig(req.GroupID, keyID)
	if err != nil {
		httpError(w, http.StatusInternalServerError, "load config: "+err.Error())
		return
	}
	if cfg == nil {
		httpError(w, http.StatusNotFound, fmt.Sprintf("key not found: group=%s key=%s", req.GroupID, keyID))
		return
	}

	sortedSigners := tss.NewPartyIDSlice(grp.Members)
	if !sortedSigners.Contains(cfg.ID) {
		httpError(w, http.StatusBadRequest, "this node is not a member of group "+req.GroupID)
		return
	}

	nonce, err := randomNonce()
	if err != nil {
		httpError(w, http.StatusInternalServerError, "generate nonce: "+err.Error())
		return
	}
	sessID := signSessionID(req.GroupID, keyID, nonce)

	n.log.Info("sign starting",
		zap.String("group_id", req.GroupID),
		zap.String("key_id", keyID),
		zap.Int("signers", len(sortedSigners)),
	)

	sn, err := network.NewSessionNetwork(r.Context(), n.host, sessID, sortedSigners)
	if err != nil {
		httpError(w, http.StatusInternalServerError, "session network: "+err.Error())
		return
	}
	defer sn.Close()

	if err := n.broadcastCoord(r.Context(), sortedSigners, coordMsg{
		Type:        msgSign,
		GroupID:     req.GroupID,
		KeyID:       keyID,
		SignNonce:   nonce,
		Signers:     sortedSigners,
		MessageHash: msgHash,
		AuthToken:   authToken,
		Auth:        authProof,
	}); err != nil {
		httpError(w, http.StatusInternalServerError, "coordinate: "+err.Error())
		return
	}

	sig, err := runSignOn(r.Context(), n.host, sn, sessID, cfg, sortedSigners, msgHash)
	if err != nil {
		n.log.Error("sign failed",
			zap.String("group_id", req.GroupID),
			zap.String("key_id", keyID),
			zap.Error(err))
		httpError(w, http.StatusInternalServerError, "sign: "+err.Error())
		return
	}

	ethSig, err := sig.SigEthereum()
	if err != nil {
		httpError(w, http.StatusInternalServerError, "encode signature: "+err.Error())
		return
	}

	n.log.Info("sign complete",
		zap.String("group_id", req.GroupID),
		zap.String("key_id", keyID),
	)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"group_id":           req.GroupID,
		"key_id":             keyID,
		"ethereum_signature": "0x" + hex.EncodeToString(ethSig),
	})
}

// httpErr is a typed HTTP error used by validateSessionRequest so both the
// status code and message can be returned without writing to the response.
type httpErr struct {
	code int
	msg  string
}

// validateSessionRequest validates a session-based auth request (used by both
// handleKeygen and handleSign). It returns the AuthProof to include in the
// coord message and the resolved keyID. On error it returns an httpErr.
func (n *Node) validateSessionRequest(
	sessionPubHex, requestSigHex string,
	groupID, keyID, keySuffix string,
	nonce string, timestamp uint64,
	messageHash []byte,
) (*AuthProof, string, *httpErr) {
	sessionPubBytes, err := hex.DecodeString(strings.TrimPrefix(sessionPubHex, "0x"))
	if err != nil || len(sessionPubBytes) != 33 {
		return nil, "", &httpErr{http.StatusBadRequest, "session_pub must be 33 hex-encoded bytes"}
	}
	reqSigBytes, err := hex.DecodeString(strings.TrimPrefix(requestSigHex, "0x"))
	if err != nil || len(reqSigBytes) != 64 {
		return nil, "", &httpErr{http.StatusBadRequest, "request_sig must be 64 hex-encoded bytes"}
	}
	if nonce == "" {
		return nil, "", &httpErr{http.StatusBadRequest, "nonce is required"}
	}
	if timestamp == 0 {
		return nil, "", &httpErr{http.StatusBadRequest, "timestamp is required"}
	}

	// Look up session.
	pubHex := sessionPubToHex(sessionPubBytes)
	info, ok := n.sessions.Get(pubHex)
	if !ok {
		return nil, "", &httpErr{http.StatusUnauthorized, "session not found; call POST /v1/auth first"}
	}
	if time.Now().After(info.Exp) {
		n.sessions.Delete(pubHex)
		return nil, "", &httpErr{http.StatusUnauthorized, "session expired; re-authenticate"}
	}

	// Derive key_id from session iss+sub (globally unique pair).
	resolvedKeyID := info.Iss + ":" + info.Sub
	if keySuffix != "" {
		resolvedKeyID = info.Iss + ":" + info.Sub + ":" + keySuffix
	}

	// Verify request signature. The signature must cover the resolved keyID
	// (derived from sub), not a client-supplied keyID.
	if err := verifyRequestSignature(
		sessionPubBytes, reqSigBytes,
		groupID, resolvedKeyID, nonce, timestamp,
		messageHash,
	); err != nil {
		return nil, "", &httpErr{http.StatusUnauthorized, "invalid request signature: " + err.Error()}
	}

	// Check nonce uniqueness.
	if err := n.sessions.CheckNonce(nonce); err != nil {
		return nil, "", &httpErr{http.StatusConflict, "nonce already used"}
	}

	// Check timestamp freshness.
	ts := time.Unix(int64(timestamp), 0)
	if time.Since(ts).Abs() > timestampWindow {
		return nil, "", &httpErr{http.StatusBadRequest, "timestamp too old or in the future"}
	}

	ap := &AuthProof{
		Proof:       info.Proof,
		Sub:         info.Sub,
		Iss:         info.Iss,
		Exp:         uint64(info.Exp.Unix()),
		Aud:         info.Aud,
		Azp:         info.Azp,
		JWKSModulus: info.JWKSModulus,
		SessionPub:  sessionPubBytes,
		RequestSig:  reqSigBytes,
		Nonce:       nonce,
		Timestamp:   timestamp,
		TestMode:    n.cfg.TestMode,
	}
	return ap, resolvedKeyID, nil
}

func httpError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// extractBearer returns the token from an "Authorization: Bearer <token>" header,
// or an empty string if the header is absent or malformed.
func extractBearer(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return ""
	}
	return strings.TrimPrefix(auth, "Bearer ")
}
