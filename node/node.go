package node

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
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

	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	"github.com/luxfi/threshold/protocols/cmp"

	"signet/network"
)

// Node owns a libp2p host, an HTTP API server, and threshold signing state.
type Node struct {
	cfg    *Config
	host   *network.Host
	server *http.Server
	log    *zap.Logger
	ctx    context.Context
	cancel context.CancelFunc

	pool    *pool.Pool
	mu      sync.RWMutex
	configs map[string]*cmp.Config // keygen session ID → key config
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

	if err := os.MkdirAll(filepath.Dir(cfg.KeyFile), 0700); err != nil {
		cancel()
		return nil, fmt.Errorf("create key dir: %w", err)
	}

	h, err := network.NewHostFromFile(ctx, cfg.KeyFile, cfg.ListenAddr)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("create host: %w", err)
	}

	// Dial each bootstrap peer; connection failures are non-fatal.
	for _, bpStr := range cfg.BootstrapPeers {
		maddr, err := ma.NewMultiaddr(bpStr)
		if err != nil {
			h.Close()
			cancel()
			return nil, fmt.Errorf("parse bootstrap peer %q: %w", bpStr, err)
		}
		pi, err := peer.AddrInfoFromP2pAddr(maddr)
		if err != nil {
			h.Close()
			cancel()
			return nil, fmt.Errorf("addr info from %q: %w", bpStr, err)
		}
		if err := h.LibP2PHost().Connect(ctx, *pi); err != nil {
			log.Warn("bootstrap peer unreachable", zap.String("peer", pi.ID.String()), zap.Error(err))
			continue
		}
		h.RegisterPeer(party.ID(pi.ID.String()), pi.ID)
		log.Info("connected to bootstrap peer", zap.String("peer", pi.ID.String()))
	}

	n := &Node{
		cfg:     cfg,
		host:    h,
		log:     log,
		ctx:     ctx,
		cancel:  cancel,
		pool:    pool.NewPool(0),
		configs: make(map[string]*cmp.Config),
	}

	n.registerCoordHandler()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/health", n.handleHealth)
	mux.HandleFunc("GET /v1/info", n.handleInfo)
	mux.HandleFunc("GET /v1/keys", n.handleListKeys)
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

// Stop gracefully shuts down the HTTP server, the libp2p host, and the worker pool.
func (n *Node) Stop() error {
	n.log.Info("stopping node")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := n.server.Shutdown(ctx); err != nil {
		return fmt.Errorf("shutdown HTTP server: %w", err)
	}
	n.pool.TearDown()
	n.host.Close()
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

// keyConfigPath returns the disk path for a stored keygen config.
func (n *Node) keyConfigPath(sessionID string) string {
	return filepath.Join(filepath.Dir(n.cfg.KeyFile), sessionID+".config")
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

// handleListKeys returns public metadata for all in-memory keygen configs.
func (n *Node) handleListKeys(w http.ResponseWriter, r *http.Request) {
	type keyEntry struct {
		SessionID       string   `json:"session_id"`
		EthereumAddress string   `json:"ethereum_address"`
		Threshold       int      `json:"threshold"`
		Parties         []string `json:"parties"`
	}

	n.mu.RLock()
	entries := make([]keyEntry, 0, len(n.configs))
	for id, cfg := range n.configs {
		ethAddr := ""
		if addr, err := network.EthereumAddressFromPoint(cfg.PublicPoint()); err == nil {
			ethAddr = "0x" + hex.EncodeToString(addr[:])
		}
		ids := cfg.PartyIDs()
		parties := make([]string, len(ids))
		for i, p := range ids {
			parties[i] = string(p)
		}
		entries = append(entries, keyEntry{
			SessionID:       id,
			EthereumAddress: ethAddr,
			Threshold:       cfg.Threshold,
			Parties:         parties,
		})
	}
	n.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(entries)
}

// handleKeygen runs a distributed key generation session.
//
// POST /v1/keygen
//
//	{"session_id":"mykey1","parties":["16Uiu2...","16Uiu2...","16Uiu2..."],"threshold":1}
//
// Send to any one node in the parties list. That node coordinates with the others
// automatically; the caller does not need to contact each node separately.
func (n *Node) handleKeygen(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SessionID string     `json:"session_id"`
		Parties   []party.ID `json:"parties"`
		Threshold int        `json:"threshold"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, "decode body: "+err.Error())
		return
	}
	if req.SessionID == "" || len(req.Parties) == 0 || req.Threshold <= 0 {
		httpError(w, http.StatusBadRequest, "session_id, parties (non-empty), and threshold (>0) are required")
		return
	}

	// party.NewIDSlice sorts the slice, as required by the CMP protocol.
	sortedParties := party.NewIDSlice(req.Parties)

	n.log.Info("keygen starting",
		zap.String("session_id", req.SessionID),
		zap.Int("n", len(sortedParties)),
		zap.Int("threshold", req.Threshold),
	)

	// Subscribe to the session topic before notifying peers, so we're ready to
	// receive GossipSub messages as soon as the mesh forms.
	sn, err := network.NewSessionNetwork(r.Context(), n.host, req.SessionID, sortedParties)
	if err != nil {
		httpError(w, http.StatusInternalServerError, "session network: "+err.Error())
		return
	}
	defer sn.Close()

	// Tell every other party to join and start.
	if err := n.broadcastCoord(r.Context(), sortedParties, coordMsg{
		Type:      msgKeygen,
		SessionID: req.SessionID,
		Parties:   sortedParties,
		Threshold: req.Threshold,
	}); err != nil {
		httpError(w, http.StatusInternalServerError, "coordinate: "+err.Error())
		return
	}

	cfg, err := runKeygenOn(r.Context(), n.host, sn, req.SessionID, sortedParties, req.Threshold, n.pool)
	if err != nil {
		n.log.Error("keygen failed", zap.String("session_id", req.SessionID), zap.Error(err))
		httpError(w, http.StatusInternalServerError, "keygen: "+err.Error())
		return
	}

	if err := saveConfig(n.keyConfigPath(req.SessionID), cfg); err != nil {
		n.log.Warn("persist config failed", zap.String("session_id", req.SessionID), zap.Error(err))
	}
	n.mu.Lock()
	n.configs[req.SessionID] = cfg
	n.mu.Unlock()

	pub := cfg.PublicPoint()
	pubBytes, err := pub.MarshalBinary()
	if err != nil {
		httpError(w, http.StatusInternalServerError, "marshal public key: "+err.Error())
		return
	}
	ethAddr, err := network.EthereumAddressFromPoint(pub)
	if err != nil {
		httpError(w, http.StatusInternalServerError, "eth addr: "+err.Error())
		return
	}

	n.log.Info("keygen complete",
		zap.String("session_id", req.SessionID),
		zap.String("eth_addr", "0x"+hex.EncodeToString(ethAddr[:])),
	)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"session_id":       req.SessionID,
		"public_key":       "0x" + hex.EncodeToString(pubBytes),
		"ethereum_address": "0x" + hex.EncodeToString(ethAddr[:]),
	})
}

// handleSign runs a threshold signing session using a previously generated key.
//
// POST /v1/sign
//
//	{
//	  "key_session_id":  "mykey1",
//	  "sign_session_id": "sign-001",
//	  "signers":         ["16Uiu2...","16Uiu2..."],
//	  "message_hash":    "0xdeadbeef..."
//	}
//
// Send to any one node in the signers list. That node coordinates with the others
// automatically; the caller does not need to contact each node separately.
func (n *Node) handleSign(w http.ResponseWriter, r *http.Request) {
	var req struct {
		KeySessionID  string     `json:"key_session_id"`
		SignSessionID string     `json:"sign_session_id"`
		Signers       []party.ID `json:"signers"`
		MessageHash   string     `json:"message_hash"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, "decode body: "+err.Error())
		return
	}
	if req.KeySessionID == "" || req.SignSessionID == "" || len(req.Signers) == 0 || req.MessageHash == "" {
		httpError(w, http.StatusBadRequest, "key_session_id, sign_session_id, signers, and message_hash are required")
		return
	}

	msgHash, err := hex.DecodeString(strings.TrimPrefix(req.MessageHash, "0x"))
	if err != nil {
		httpError(w, http.StatusBadRequest, "invalid message_hash: "+err.Error())
		return
	}

	// Load config: memory-first, then disk.
	n.mu.RLock()
	cfg, ok := n.configs[req.KeySessionID]
	n.mu.RUnlock()
	if !ok {
		cfg, err = loadConfig(n.keyConfigPath(req.KeySessionID))
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				httpError(w, http.StatusNotFound, "key session not found: "+req.KeySessionID)
			} else {
				httpError(w, http.StatusInternalServerError, "load config: "+err.Error())
			}
			return
		}
		n.mu.Lock()
		n.configs[req.KeySessionID] = cfg
		n.mu.Unlock()
	}

	// Validate signer set (sorted, threshold met, this node included).
	sortedSigners := party.NewIDSlice(req.Signers)
	if !cfg.CanSign(sortedSigners) {
		httpError(w, http.StatusBadRequest, "invalid signer set: threshold not met, unknown party, or this node not included")
		return
	}

	n.log.Info("sign starting",
		zap.String("key_session_id", req.KeySessionID),
		zap.String("sign_session_id", req.SignSessionID),
		zap.Int("signers", len(sortedSigners)),
	)

	sn, err := network.NewSessionNetwork(r.Context(), n.host, req.SignSessionID, sortedSigners)
	if err != nil {
		httpError(w, http.StatusInternalServerError, "session network: "+err.Error())
		return
	}
	defer sn.Close()

	if err := n.broadcastCoord(r.Context(), sortedSigners, coordMsg{
		Type:          msgSign,
		KeySessionID:  req.KeySessionID,
		SignSessionID: req.SignSessionID,
		Signers:       sortedSigners,
		MessageHash:   msgHash,
	}); err != nil {
		httpError(w, http.StatusInternalServerError, "coordinate: "+err.Error())
		return
	}

	sig, err := runSignOn(r.Context(), n.host, sn, req.SignSessionID, cfg, sortedSigners, msgHash, n.pool)
	if err != nil {
		n.log.Error("sign failed", zap.String("sign_session_id", req.SignSessionID), zap.Error(err))
		httpError(w, http.StatusInternalServerError, "sign: "+err.Error())
		return
	}

	ethSig, err := sig.SigEthereum()
	if err != nil {
		httpError(w, http.StatusInternalServerError, "encode signature: "+err.Error())
		return
	}

	n.log.Info("sign complete", zap.String("sign_session_id", req.SignSessionID))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"sign_session_id":    req.SignSessionID,
		"ethereum_signature": "0x" + hex.EncodeToString(ethSig),
	})
}

func httpError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
