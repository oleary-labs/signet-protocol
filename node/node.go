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

	"signet/network"
	"signet/tss"
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

	km KeyManager // key management: LocalKeyManager (in-process) or RemoteKeyManager (KMS)

	// keygenReady tracks in-flight keygen operations so that sign coord
	// handlers arriving before the keygen has completed can wait instead
	// of immediately failing with "key not found".
	keygenReadyMu sync.Mutex
	keygenReady   map[shardKey]chan struct{}

	groupsMu sync.RWMutex
	groups   map[string]*GroupInfo // group contract address → resolved membership

	auth     *GroupAuth    // per-group OAuth trust store
	sessions *SessionStore // ephemeral session key cache
	chain    *ChainClient  // nil if no eth_rpc configured

	bootstrapPeers []peer.AddrInfo // parsed bootstrap peer addresses for reconnect

	// Reshare state: per-group job tracking, per-key session channels,
	// coordinator flags. See reshare.go for methods.
	reshareStore   *ReshareStore
	reshareMux     *network.MuxNetwork // multiplexed streams for reshare sessions
	reshareJobsMu  sync.RWMutex
	reshareJobs    map[string]*ReshareJob    // groupID → active job (nil = ACTIVE)
	reshareKeysMu  sync.Mutex
	reshareKeys    map[reshareKeyID]chan struct{} // per-key done channels
	reshareCoordMu sync.Mutex
	reshareCoord   map[string]bool               // groupID → is coordinator
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

	// Create the key manager: RemoteKeyManager when a KMS socket is
	// configured, LocalKeyManager (in-process tss) otherwise.
	var km KeyManager
	if cfg.KMSSocket != "" {
		rkm, err := NewRemoteKeyManager(ctx, cfg.KMSSocket, tss.PartyID(h.Self()))
		if err != nil {
			h.Close()
			cancel()
			return nil, fmt.Errorf("remote key manager: %w", err)
		}
		km = rkm
	} else {
		lkm, err := NewLocalKeyManager(ctx, cfg.DataDir, log)
		if err != nil {
			h.Close()
			cancel()
			return nil, fmt.Errorf("local key manager: %w", err)
		}
		km = lkm
	}

	// Parse bootstrap peer addresses; bail out on malformed entries.
	var bootstrapPeers []peer.AddrInfo
	for _, bpStr := range cfg.BootstrapPeers {
		maddr, err := ma.NewMultiaddr(bpStr)
		if err != nil {
			km.Close()
			h.Close()
			cancel()
			return nil, fmt.Errorf("parse bootstrap peer %q: %w", bpStr, err)
		}
		pi, err := peer.AddrInfoFromP2pAddr(maddr)
		if err != nil {
			km.Close()
			h.Close()
			cancel()
			return nil, fmt.Errorf("addr info from %q: %w", bpStr, err)
		}
		bootstrapPeers = append(bootstrapPeers, *pi)
	}

	// Dial each bootstrap peer with a small number of retries to survive
	// simultaneous-dial TLS races that occur when all nodes start at once.
	const bootstrapRetries = 5
	for _, pi := range bootstrapPeers {
		pi := pi
		var lastErr error
		for i := 0; i < bootstrapRetries; i++ {
			if i > 0 {
				time.Sleep(500 * time.Millisecond)
			}
			if err := h.LibP2PHost().Connect(ctx, pi); err != nil {
				lastErr = err
				continue
			}
			h.RegisterPeer(tss.PartyID(pi.ID.String()), pi.ID)
			log.Info("connected to bootstrap peer", zap.String("peer", pi.ID.String()))
			lastErr = nil
			break
		}
		if lastErr != nil {
			log.Warn("bootstrap peer unreachable after retries",
				zap.String("peer", pi.ID.String()), zap.Error(lastErr))
		}
	}

	// Load circuit verification key if configured (required for production ZK auth).
	var circuitVK []byte
	if cfg.VKPath != "" {
		var err error
		circuitVK, err = os.ReadFile(cfg.VKPath)
		if err != nil {
			km.Close()
			h.Close()
			cancel()
			return nil, fmt.Errorf("read circuit VK from %s: %w", cfg.VKPath, err)
		}
		log.Info("loaded circuit verification key", zap.String("path", cfg.VKPath), zap.Int("bytes", len(circuitVK)))
	}

	// Open reshare store. For LocalKeyManager, share the same bbolt DB.
	// For RemoteKeyManager, open a dedicated DB for job tracking (the node
	// tracks reshare orchestration state locally regardless of KManager backend).
	var reshareStore *ReshareStore
	if lkm, ok := km.(*LocalKeyManager); ok {
		reshareStore, err = NewReshareStore(lkm.store.DB())
		if err != nil {
			km.Close()
			h.Close()
			cancel()
			return nil, fmt.Errorf("reshare store: %w", err)
		}
	} else {
		// Remote KMS: open a dedicated bbolt for reshare job tracking.
		reshareDB, dbErr := openReshareDB(cfg.DataDir)
		if dbErr != nil {
			km.Close()
			h.Close()
			cancel()
			return nil, fmt.Errorf("reshare store: %w", dbErr)
		}
		reshareStore, err = NewReshareStore(reshareDB)
		if err != nil {
			reshareDB.Close()
			km.Close()
			h.Close()
			cancel()
			return nil, fmt.Errorf("reshare store: %w", err)
		}
	}

	n := &Node{
		cfg:            cfg,
		host:           h,
		log:            log,
		ctx:            ctx,
		cancel:         cancel,
		km:             km,
		keygenReady:    make(map[shardKey]chan struct{}),
		groups:         make(map[string]*GroupInfo),
		auth:           newGroupAuth(ctx, circuitVK, log),
		sessions:       newSessionStore(),
		bootstrapPeers: bootstrapPeers,
	}
	n.initReshareState(reshareStore)
	n.sessions.startCleanupLoop(ctx)
	go n.reconnectLoop(ctx)

	// Wire the chain client when eth_rpc and factory_address are configured.
	if cfg.EthRPC != "" && cfg.FactoryAddress != "" {
		chain, err := newChainClient(cfg, h, n, log)
		if err != nil {
			km.Close()
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
	// POST /v1/reshare is disabled until operator key auth is implemented.
	// Reshare is auto-triggered by chain membership events. The status
	// endpoint remains available for observability.
	// mux.HandleFunc("POST /v1/reshare", n.handleStartReshare)
	mux.HandleFunc("GET /v1/reshare/{group_id}", n.handleReshareStatus)
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
	if err := n.km.Close(); err != nil {
		n.log.Warn("close key manager", zap.Error(err))
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

// markKeygenPending registers a pending keygen for (groupID, keyID). Sign coord
// handlers can call awaitKey to wait for it to finish.
func (n *Node) markKeygenPending(groupID, keyID string) {
	k := shardKey{groupID, keyID}
	n.keygenReadyMu.Lock()
	if _, exists := n.keygenReady[k]; !exists {
		n.keygenReady[k] = make(chan struct{})
	}
	n.keygenReadyMu.Unlock()
}

// markKeygenDone signals that the keygen for (groupID, keyID) has finished.
func (n *Node) markKeygenDone(groupID, keyID string) {
	k := shardKey{groupID, keyID}
	n.keygenReadyMu.Lock()
	ch, exists := n.keygenReady[k]
	if exists {
		close(ch)
		delete(n.keygenReady, k)
	}
	n.keygenReadyMu.Unlock()
}

// awaitKey returns the KeyInfo for (groupID, keyID), waiting up to timeout
// for a concurrent keygen to finish. Returns (nil, nil) if the key is genuinely
// absent and no keygen is in flight.
func (n *Node) awaitKey(groupID, keyID string, timeout time.Duration) (*KeyInfo, error) {
	info, err := n.km.GetKeyInfo(groupID, keyID)
	if err != nil || info != nil {
		return info, err
	}

	k := shardKey{groupID, keyID}
	n.keygenReadyMu.Lock()
	ch, pending := n.keygenReady[k]
	n.keygenReadyMu.Unlock()

	if !pending {
		return nil, nil
	}

	select {
	case <-ch:
		return n.km.GetKeyInfo(groupID, keyID)
	case <-time.After(timeout):
		return nil, fmt.Errorf("timeout waiting for keygen to complete for key %s", keyID)
	case <-n.ctx.Done():
		return nil, n.ctx.Err()
	}
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
		groupIDs, err = n.km.ListGroups()
		if err != nil {
			httpError(w, http.StatusInternalServerError, "list groups: "+err.Error())
			return
		}
	}

	entries := make([]keyEntry, 0)
	for _, gid := range groupIDs {
		keyIDs, err := n.km.ListKeys(gid)
		if err != nil {
			httpError(w, http.StatusInternalServerError, "list keys: "+err.Error())
			return
		}
		for _, kid := range keyIDs {
			info, err := n.km.GetKeyInfo(gid, kid)
			if err != nil || info == nil {
				continue
			}
			ethAddr := ""
			if addr, err := network.EthereumAddressFromGroupKey(info.GroupKey); err == nil {
				ethAddr = "0x" + hex.EncodeToString(addr[:])
			}
			parties := make([]string, len(info.Parties))
			for i, p := range info.Parties {
				parties[i] = string(p)
			}
			entries = append(entries, keyEntry{
				GroupID:         gid,
				KeyID:           kid,
				EthereumAddress: ethAddr,
				Threshold:       info.Threshold,
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
// Auth key certificate:
//
//	{"group_id":"0x...","session_pub":"02abc...",
//	 "certificate":{"auth_key_pub":"02...","signature":"hex64","identity":"user1","expiry":1709900000}}
//
// OAuth/ZK proof:
//
//	{"group_id":"0x...","proof":"hex...","session_pub":"02abc...",
//	 "sub":"user123","iss":"https://...","exp":1709900000,
//	 "aud":"app.example.com","azp":"client-id","jwks_modulus":"hex..."}
func (n *Node) handleAuth(w http.ResponseWriter, r *http.Request) {
	var req struct {
		GroupID     string `json:"group_id"`
		Proof       string `json:"proof"`         // ZK proof hex
		SessionPub  string `json:"session_pub"`   // hex, 33-byte compressed secp256k1
		Sub         string `json:"sub"`           // JWT subject
		Iss         string `json:"iss"`           // JWT issuer
		Exp         uint64 `json:"exp"`           // JWT expiry unix timestamp
		Aud         string `json:"aud"`           // JWT audience
		Azp         string `json:"azp"`           // JWT authorized party
		JWKSModulus string `json:"jwks_modulus"`  // RSA modulus hex

		// Authorization key certificate fields
		Certificate *AuthCertificate `json:"certificate,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, "decode body: "+err.Error())
		return
	}
	if req.GroupID == "" || req.SessionPub == "" {
		httpError(w, http.StatusBadRequest, "group_id and session_pub are required")
		return
	}
	req.GroupID = strings.ToLower(req.GroupID)

	sessionPubBytes, err := hex.DecodeString(strings.TrimPrefix(req.SessionPub, "0x"))
	if err != nil || len(sessionPubBytes) != 33 {
		httpError(w, http.StatusBadRequest, "session_pub must be 33 hex-encoded bytes")
		return
	}

	// Authorization key certificate path.
	if req.Certificate != nil {
		cert := req.Certificate
		cert.GroupID = req.GroupID
		cert.SessionPub = req.SessionPub

		identity, err := n.auth.ValidateAuthCertificate(req.GroupID, cert)
		if err != nil {
			httpError(w, http.StatusUnauthorized, "certificate verification failed: "+err.Error())
			return
		}

		authKeyBytes, _ := hex.DecodeString(strings.TrimPrefix(cert.AuthKeyPub, "0x"))
		sigBytes, _ := hex.DecodeString(strings.TrimPrefix(cert.Signature, "0x"))

		pubHex := sessionPubToHex(sessionPubBytes)
		n.sessions.Put(pubHex, &SessionInfo{
			Sub:           identity,
			Exp:           time.Unix(int64(cert.Expiry), 0),
			Identity:      identity,
			AuthKeyPub:    authKeyBytes,
			CertSignature: sigBytes,
		})
		n.log.Info("auth: session registered (auth key certificate)",
			zap.String("group_id", req.GroupID),
			zap.String("identity", identity),
			zap.String("session_pub", pubHex))

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"status":     "ok",
			"identity":   identity,
			"expires_at": int64(cert.Expiry),
		})
		return
	}

	// OAuth/ZK proof path.
	if req.Proof == "" {
		httpError(w, http.StatusBadRequest, "proof or certificate is required")
		return
	}
	if req.Sub == "" || req.Iss == "" || req.Exp == 0 {
		httpError(w, http.StatusBadRequest, "sub, iss, and exp are required with ZK proof")
		return
	}
	if req.JWKSModulus == "" {
		httpError(w, http.StatusBadRequest, "jwks_modulus is required with ZK proof")
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
	n.log.Info("auth: session registered (ZK proof)",
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
	req.GroupID = strings.ToLower(req.GroupID)

	n.groupsMu.RLock()
	grp, ok := n.groups[req.GroupID]
	n.groupsMu.RUnlock()
	if !ok {
		httpError(w, http.StatusNotFound, "group not found: "+req.GroupID)
		return
	}

	keyID := req.KeyID
	var authProof *AuthProof

	if n.auth.HasAuthPolicy(req.GroupID) {
		if req.SessionPub == "" {
			httpError(w, http.StatusUnauthorized, "authorization required (session_pub)")
			return
		}
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
	} else if keyID == "" {
		httpError(w, http.StatusBadRequest, "key_id is required")
		return
	}

	if info, _ := n.km.GetKeyInfo(req.GroupID, keyID); info != nil {
		httpError(w, http.StatusConflict, fmt.Sprintf("key already exists: group=%s key=%s", req.GroupID, keyID))
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
		Auth:      authProof,
	}); err != nil {
		httpError(w, http.StatusInternalServerError, "coordinate: "+err.Error())
		return
	}

	info, err := n.km.RunKeygen(r.Context(), KeygenParams{
		Host:      n.host,
		SN:        sn,
		SessionID: sessID,
		GroupID:   req.GroupID,
		KeyID:     keyID,
		Parties:   sortedParties,
		Threshold: grp.Threshold,
	})
	if err != nil {
		n.log.Error("keygen failed",
			zap.String("group_id", req.GroupID),
			zap.String("key_id", keyID),
			zap.Error(err))
		httpError(w, http.StatusInternalServerError, "keygen: "+err.Error())
		return
	}

	ethAddr, err := network.EthereumAddressFromGroupKey(info.GroupKey)
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
		"public_key":       "0x" + hex.EncodeToString(info.GroupKey),
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
	req.GroupID = strings.ToLower(req.GroupID)

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
	var authProof *AuthProof

	if n.auth.HasAuthPolicy(req.GroupID) {
		if req.SessionPub == "" {
			httpError(w, http.StatusUnauthorized, "authorization required (session_pub)")
			return
		}
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
	} else if keyID == "" {
		httpError(w, http.StatusBadRequest, "key_id is required")
		return
	}

	// Block if the key is stale (pending reshare). Waits until the reshare
	// completes or triggers an on-demand reshare if no session is running.
	if n.isKeyStale(req.GroupID, keyID) {
		n.log.Info("sign: key is stale, waiting for reshare",
			zap.String("group_id", req.GroupID),
			zap.String("key_id", keyID))
		if err := n.waitForReshare(r.Context(), req.GroupID, keyID); err != nil {
			httpError(w, http.StatusServiceUnavailable, "key reshare pending: "+err.Error())
			return
		}
	}

	keyInfo, err := n.km.GetKeyInfo(req.GroupID, keyID)
	if err != nil {
		httpError(w, http.StatusInternalServerError, "load config: "+err.Error())
		return
	}
	if keyInfo == nil {
		httpError(w, http.StatusNotFound, fmt.Sprintf("key not found: group=%s key=%s", req.GroupID, keyID))
		return
	}

	sortedSigners := tss.NewPartyIDSlice(grp.Members)
	if !sortedSigners.Contains(keyInfo.PartyID) {
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
		Auth:        authProof,
	}); err != nil {
		httpError(w, http.StatusInternalServerError, "coordinate: "+err.Error())
		return
	}

	sig, err := n.km.RunSign(r.Context(), SignParams{
		Host:        n.host,
		SN:          sn,
		SessionID:   sessID,
		GroupID:     req.GroupID,
		KeyID:       keyID,
		Signers:     sortedSigners,
		MessageHash: msgHash,
	})
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

	// Derive key_id. For OAuth sessions: iss:sub. For auth key sessions: identity.
	var resolvedKeyID string
	if info.Identity != "" {
		// Auth key certificate session.
		resolvedKeyID = info.Identity
		if keySuffix != "" {
			resolvedKeyID = info.Identity + ":" + keySuffix
		}
	} else {
		// OAuth session.
		resolvedKeyID = info.Iss + ":" + info.Sub
		if keySuffix != "" {
			resolvedKeyID = info.Iss + ":" + info.Sub + ":" + keySuffix
		}
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
		Proof:         info.Proof,
		Sub:           info.Sub,
		Iss:           info.Iss,
		Exp:           uint64(info.Exp.Unix()),
		Aud:           info.Aud,
		Azp:           info.Azp,
		JWKSModulus:   info.JWKSModulus,
		SessionPub:    sessionPubBytes,
		RequestSig:    reqSigBytes,
		Nonce:         nonce,
		Timestamp:     timestamp,
		AuthKeyPub:    info.AuthKeyPub,
		CertSignature: info.CertSignature,
		Identity:      info.Identity,
	}
	return ap, resolvedKeyID, nil
}

// handleStartReshare handles POST /v1/reshare. Starts the background
// coordinator for a group that has a pending reshare job.
func (n *Node) handleStartReshare(w http.ResponseWriter, r *http.Request) {
	var req struct {
		GroupID     string `json:"group_id"`
		Concurrency int    `json:"concurrency"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	groupID := strings.ToLower(req.GroupID)
	if groupID == "" {
		httpError(w, http.StatusBadRequest, "group_id is required")
		return
	}
	concurrency := req.Concurrency
	if concurrency < 1 {
		concurrency = 1
	}

	n.reshareJobsMu.RLock()
	job := n.reshareJobs[groupID]
	n.reshareJobsMu.RUnlock()
	if job == nil {
		httpError(w, http.StatusNotFound, "no reshare job pending for this group")
		return
	}

	if err := n.startCoordinator(groupID, concurrency); err != nil {
		if strings.Contains(err.Error(), "already coordinating") {
			httpError(w, http.StatusConflict, err.Error())
		} else {
			httpError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}

	done, _ := n.reshareStore.CountKeysDone(groupID)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"group_id":    groupID,
		"keys_total":  len(job.KeysTotal),
		"keys_done":   done,
		"concurrency": concurrency,
		"status":      "started",
	})
}

// handleReshareStatus handles GET /v1/reshare/{group_id}. Returns current
// reshare status for a group.
func (n *Node) handleReshareStatus(w http.ResponseWriter, r *http.Request) {
	groupID := strings.ToLower(r.PathValue("group_id"))
	if groupID == "" {
		httpError(w, http.StatusBadRequest, "group_id is required")
		return
	}

	n.reshareJobsMu.RLock()
	job := n.reshareJobs[groupID]
	n.reshareJobsMu.RUnlock()

	if job == nil {
		// Check if we know about this group at all.
		n.groupsMu.RLock()
		_, known := n.groups[groupID]
		n.groupsMu.RUnlock()
		status := "none"
		if known {
			status = "active"
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"group_id": groupID,
			"status":   status,
		})
		return
	}

	done, _ := n.reshareStore.CountKeysDone(groupID)
	n.reshareCoordMu.Lock()
	isCoord := n.reshareCoord[groupID]
	n.reshareCoordMu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"group_id":       groupID,
		"status":         "resharing",
		"keys_total":     len(job.KeysTotal),
		"keys_done":      done,
		"keys_stale":     len(job.KeysTotal) - done,
		"started_at":     job.StartedAt.Format(time.RFC3339),
		"is_coordinator": isCoord,
	})
}

func httpError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// reconnectLoop periodically re-dials any bootstrap peer that is not currently
// connected. This recovers from simultaneous-dial TLS races at startup and from
// peers that restart after the node comes up.
func (n *Node) reconnectLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for _, pi := range n.bootstrapPeers {
				if len(n.host.LibP2PHost().Network().ConnsToPeer(pi.ID)) > 0 {
					continue // already connected
				}
				if err := n.host.LibP2PHost().Connect(ctx, pi); err != nil {
					n.log.Debug("reconnect bootstrap peer failed",
						zap.String("peer", pi.ID.String()), zap.Error(err))
					continue
				}
				n.host.RegisterPeer(tss.PartyID(pi.ID.String()), pi.ID)
				n.log.Info("reconnected to bootstrap peer", zap.String("peer", pi.ID.String()))
			}
		}
	}
}

