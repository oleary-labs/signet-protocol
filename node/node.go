package node

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"
	circuits "github.com/oleary-labs/signet-circuits/packages/go"
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
	cfg       *Config
	host      *network.Host
	server    *http.Server
	log       *zap.Logger
	ctx       context.Context
	cancel    context.CancelFunc
	startTime time.Time

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

	// liveness tracks which group members are reachable, so signing can use
	// the minimum viable signer set instead of every member. See liveness.go.
	liveness *Liveness

	// Reshare state: per-group job tracking, per-key session channels,
	// coordinator flags. See reshare.go for methods.
	reshareStore        *ReshareStore
	reshareMux          *network.MuxNetwork // multiplexed streams for reshare sessions
	reshareJobsMu       sync.RWMutex
	reshareJobs         map[string]*ReshareJob // groupID → active job (nil = ACTIVE)
	reshareKeysMu       sync.Mutex
	reshareKeys         map[reshareKeyID]chan struct{} // per-key done channels
	resharePendingReady map[reshareKeyID]chan struct{} // closed when pending write completes
	reshareCoordMu      sync.Mutex
	reshareCoord        map[string]bool // groupID → is coordinator
}

// NodeInfo is returned by the /v1/info endpoint.
type NodeInfo struct {
	PeerID          string   `json:"peer_id"`
	EthereumAddress string   `json:"ethereum_address"`
	Addrs           []string `json:"addrs"`
	NodeType        string   `json:"node_type"`

	// Build identity, so operators can confirm they are running the same code
	// as their peers. In a multi-operator group nobody holds anybody else's SSH
	// key — deliberately — so before this the only way to check whether another
	// operator had actually deployed a fix was to ask them and take their word
	// for it. Verifying a fleet after a coordinated deploy should not depend on
	// a favour.
	//
	// Two honest limitations:
	//
	//   1. This is NOT attestation. A node reports whatever its binary says, so
	//      a malicious or compromised operator can report anything. It answers
	//      "are we running the same code?" between cooperating operators, which
	//      is an operational question, not "prove you are honest".
	//   2. /v1/info is unauthenticated, so this discloses the running version
	//      publicly, which helps someone targeting a known bug. Putting it
	//      behind auth would defeat the purpose: operators hold no shared
	//      credential, and needing one is exactly the coupling being avoided.
	//      The trade is deliberate.
	Version      string `json:"version"`                 // vcs revision, +"-dirty" if the tree was modified
	BuiltAt      string `json:"built_at,omitempty"`      // vcs commit time
	BinarySHA256 string `json:"binary_sha256,omitempty"` // sha256 of the running executable
}

// Build identity is resolved once: ReadBuildInfo walks the binary's embedded
// table, and the self-hash reads the whole executable (~46MB), neither of which
// belongs on a request path.
var (
	buildOnce sync.Once
	buildVer  string
	buildTime string
	buildHash string
)

func resolveBuildInfo() {
	buildOnce.Do(func() {
		buildVer = "unknown"
		if bi, ok := debug.ReadBuildInfo(); ok {
			var rev, modified string
			for _, s := range bi.Settings {
				switch s.Key {
				case "vcs.revision":
					rev = s.Value
				case "vcs.time":
					buildTime = s.Value
				case "vcs.modified":
					modified = s.Value
				}
			}
			if rev != "" {
				if len(rev) > 12 {
					rev = rev[:12]
				}
				buildVer = rev
				// A dirty tree is worth surfacing loudly: it means the deployed
				// artifact does not correspond to any commit, so "same version"
				// between two operators would be a false match.
				if modified == "true" {
					buildVer += "-dirty"
				}
			}
		}
		buildHash = selfSHA256()
	})
}

// selfSHA256 hashes the running executable. Best-effort: an empty string simply
// omits the field rather than failing /v1/info, since the endpoint is also the
// liveness probe and must not start returning errors because a checksum could
// not be taken.
func selfSHA256() string {
	path, err := os.Executable()
	if err != nil {
		return ""
	}
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
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
	keyPassphrase := os.Getenv(network.KeyPassphraseEnv)
	h, err := network.NewHostFromFile(ctx, keyFile, cfg.ListenAddr, keyPassphrase)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("create host: %w", err)
	}

	// Create the key manager: RemoteKeyManager when a KMS socket is
	// configured, LocalKeyManager (in-process tss) otherwise.
	var km KeyManager
	if cfg.KMSSocket != "" {
		rkm, err := NewRemoteKeyManager(ctx, cfg.KMSSocket, tss.PartyID(h.Self()), log)
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

	// Circuit VK is embedded from signet-circuits at build time.
	meta, err := circuits.JWTMetadata()
	if err != nil {
		km.Close()
		h.Close()
		cancel()
		return nil, fmt.Errorf("load circuit metadata: %w", err)
	}
	log.Info("loaded embedded circuit VK",
		zap.String("circuit_hash", meta.CircuitHash),
		zap.String("bb", meta.Toolchain.BB),
		zap.Int("vk_bytes", len(circuits.JWTVK)),
	)

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
		// Open versioned key archive (separate db for easy GC).
		vs, vsErr := openKeyVersionStore(cfg.DataDir)
		if vsErr != nil {
			km.Close()
			h.Close()
			cancel()
			return nil, fmt.Errorf("key version store: %w", vsErr)
		}
		lkm.SetVersionStore(vs)
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
		startTime:      time.Now(),
		km:             km,
		keygenReady:    make(map[shardKey]chan struct{}),
		groups:         make(map[string]*GroupInfo),
		auth:           newGroupAuth(ctx, circuits.JWTVK, log),
		sessions:       newSessionStore(),
		bootstrapPeers: bootstrapPeers,
	}
	n.initReshareState(reshareStore)
	n.sessions.startCleanupLoop(ctx)
	n.liveness = newLiveness(n, tss.PartyID(h.Self()), log)
	go n.reconnectLoop(ctx)
	go n.liveness.probeLoop(ctx)

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
	mux.HandleFunc("POST /v1/auth", n.handleAuth)
	mux.HandleFunc("POST /v1/keygen", n.handleKeygen)
	mux.HandleFunc("POST /v1/sign", n.handleSign)
	mux.HandleFunc("POST /v1/delegate", n.handleDelegate)
	mux.HandleFunc("POST /v1/keys/disable", n.handleDisableKey)
	mux.HandleFunc("POST /v1/keys/enable", n.handleEnableKey)
	mux.HandleFunc("POST /v1/keys/delete", n.handleDeleteKey)

	mux.HandleFunc("POST /admin/keys", n.handleListKeys)
	// Reshare is normally triggered via on-chain events (node add/remove or
	// requestReshare() on the group contract). POST /admin/reshare is a manual
	// trigger: a key refresh, or a leader-failover takeover when the elected
	// coordinator is offline (see handleStartReshare). Requires admin auth.
	mux.HandleFunc("POST /admin/reshare", n.handleStartReshare)
	mux.HandleFunc("POST /admin/reshare/status", n.handleReshareStatus)
	mux.HandleFunc("GET /debug/stats", n.handleDebugStats)
	// CORS outermost: a preflight must be answered before anything else looks
	// at the request, and it never reaches the mux.
	n.server = &http.Server{Addr: cfg.APIAddr, Handler: withCORS(limitRequestBody(mux))}

	return n, nil
}

// CORS policy for the browser-facing API.
//
// A literal wildcard is safe here for one specific reason, and it is worth
// stating as an invariant rather than a fact: /v1/* carries NO ambient
// authority. The per-request signature travels in the JSON body (request_sig),
// there are no cookies, and nothing under /v1 reads an Authorization header. A
// hostile page can therefore make requests a browser will send, and get
// nothing back it could not have obtained with curl, because every mutating
// call is rejected without a signature it cannot produce.
//
// Which is why Access-Control-Allow-Credentials is never set. The spec forbids
// pairing it with "*", but the real point is upstream of the header: if session
// state ever moves into a cookie or an Authorization header, the browser starts
// attaching it automatically, and this entire policy has to be redesigned
// rather than patched.
//
// The origin is a literal "*", never a reflection of the Origin header.
// Reflection is the usual route to an accidental credentialed wildcard, and it
// also makes every response origin-dependent, which requires Vary: Origin or
// caches serve one site's response to another.
//
// Scope is /v1/* only. /admin/* is authenticated by an ECDSA signature from a
// group-trusted key and /debug/* leaks group membership and per-peer RTT and is
// CIDR-restricted at the proxy; neither is a browser API and neither gets CORS
// headers. That exclusion lives here, in code shared by every operator, rather
// than in each operator's Caddyfile — six nodes across two operators must
// answer identically, and per-operator proxy config has already had to diverge
// for tls_email and rate-limit exemptions.
const (
	corsAllowOrigin  = "*"
	corsAllowMethods = "GET, POST, OPTIONS"
	corsAllowHeaders = "Content-Type"
	corsMaxAge       = "86400" // browsers clamp this (Chrome 2h); it costs nothing to ask

	// Retry-After is not on the CORS-safelist, so without exposing it a browser
	// client cannot read the header at all — it is stripped before JS sees the
	// response. Two live cases depend on it: the 409 returned while a key is
	// still settling after keygen, and Caddy's 429 when a rate-limit zone
	// trips. Both are the server telling a client exactly how to recover, and
	// both would be invisible without this line.
	corsExposeHeaders = "Retry-After"
)

// withCORS applies the policy above to /v1/* and answers preflights.
//
// Preflights must be intercepted rather than routed: routes are registered
// method-qualified ("POST /v1/sign"), and Go's ServeMux answers 405 for a known
// path with an unlisted method. A browser treats any non-2xx preflight as a
// hard failure, so without this every cross-origin call fails before the real
// request is ever sent — and listing OPTIONS in Allow-Methods does not help,
// because something still has to respond.
func withCORS(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Match on the cleaned path so a traversal like /v1/../admin/x cannot
		// pick up /v1 headers on its way to a redirect.
		if strings.HasPrefix(path.Clean(r.URL.Path)+"/", "/v1/") {
			w.Header().Set("Access-Control-Allow-Origin", corsAllowOrigin)
			w.Header().Set("Access-Control-Expose-Headers", corsExposeHeaders)

			if r.Method == http.MethodOptions {
				w.Header().Set("Access-Control-Allow-Methods", corsAllowMethods)
				w.Header().Set("Access-Control-Allow-Headers", corsAllowHeaders)
				w.Header().Set("Access-Control-Max-Age", corsMaxAge)
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
		h.ServeHTTP(w, r)
	})
}

// Request body size limits. Bounds memory/CPU spent parsing untrusted POST
// bodies. /v1/auth is unauthenticated and triggers expensive ZK verification,
// so it gets the largest allowance (proofs are sizeable); other endpoints carry
// small fixed-shape JSON.
const (
	maxBodyAuth    = 256 << 10 // 256 KiB — /v1/auth (ZK proof)
	maxBodyDefault = 64 << 10  // 64 KiB  — keygen/sign/delegate/keys
	maxBodyAdmin   = 32 << 10  // 32 KiB  — /admin/*
)

// limitRequestBody wraps h so each request's body is capped via
// http.MaxBytesReader before any handler reads it. A handler reading past the
// limit gets an error from the decoder (surfaced as 400), and the response is
// marked non-keep-alive. GET endpoints carry no body, so the cap is a no-op.
func limitRequestBody(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		limit := int64(maxBodyDefault)
		switch {
		case r.URL.Path == "/v1/auth":
			limit = maxBodyAuth
		case strings.HasPrefix(r.URL.Path, "/admin/"):
			limit = maxBodyAdmin
		}
		r.Body = http.MaxBytesReader(w, r.Body, limit)
		h.ServeHTTP(w, r)
	})
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

// Stop gracefully shuts down the node. The shutdown order is critical:
//  1. Cancel the node context so in-flight goroutines (reshare, coord handlers)
//     observe the cancellation and stop issuing new work.
//  2. Brief drain period for goroutines to finish bbolt writes.
//  3. Stop the chain poller and HTTP server.
//  4. Close the libp2p host (tears down streams).
//  5. Close the key manager (closes bbolt stores).
//
// Cancelling the context before closing the host and stores prevents goroutines
// from writing to closed bbolt databases, which would panic or corrupt data.
func (n *Node) Stop() error {
	n.log.Info("stopping node")

	// Step 1: cancel context so all goroutines begin winding down.
	n.cancel()

	// Step 2: brief drain for in-flight bbolt writes to complete.
	time.Sleep(500 * time.Millisecond)

	// Step 3: stop chain poller and HTTP server.
	if n.chain != nil {
		n.chain.close()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := n.server.Shutdown(ctx); err != nil {
		return fmt.Errorf("shutdown HTTP server: %w", err)
	}

	// Step 4: close libp2p host.
	n.host.Close()

	// Step 5: close key manager (bbolt stores).
	if err := n.km.Close(); err != nil {
		n.log.Warn("close key manager", zap.Error(err))
	}

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

	resolveBuildInfo()

	return NodeInfo{
		PeerID:          pid.String(),
		EthereumAddress: ethAddr,
		Addrs:           n.host.Addrs(),
		NodeType:        n.cfg.NodeType,
		Version:         buildVer,
		BuiltAt:         buildTime,
		BinarySHA256:    buildHash,
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
func (n *Node) awaitKey(groupID, keyID string, curve Curve, timeout time.Duration) (*KeyInfo, error) {
	info, err := n.km.GetKeyInfo(groupID, keyID, curve)
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
		return n.km.GetKeyInfo(groupID, keyID, curve)
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

// stripKeyNamespace removes the internal "oauth:", "authkey:", or
// "resolver:<addr>:" prefix from a resolved key_id, returning the logical
// key_id that clients sign over.
func stripKeyNamespace(keyID string) string {
	if after, ok := strings.CutPrefix(keyID, "oauth:"); ok {
		return after
	}
	if after, ok := strings.CutPrefix(keyID, "authkey:"); ok {
		return after
	}
	if after, ok := strings.CutPrefix(keyID, "resolver:"); ok {
		// after == "<resolverAddr>:<subject>[:<suffix>]"; drop the resolver addr.
		if _, rest, found := strings.Cut(after, ":"); found {
			return rest
		}
		return after
	}
	return keyID
}

// parseDelegationIdentity extracts iss and sub from a delegation token's
// sub-key ID. The key_id format is "oauth:<iss>:<sub>[:<suffix>]".
// Returns (iss, sub) where sub is just the user identifier (not the full path).
func parseDelegationIdentity(keyID string) (iss, sub string) {
	// Strip "oauth:" prefix if present.
	id := strings.TrimPrefix(keyID, "oauth:")
	// Split into at most 3 parts: iss components may contain colons (e.g. https://foo.bar),
	// but the sub is always the last component before the optional suffix.
	// The iss is everything from the original JWT issuer (a URL like https://accounts.google.com).
	// We reconstruct by finding the sub (user ID) after the issuer.
	//
	// Key ID format examples:
	//   oauth:https://accounts.google.com:user123:scope_suffix
	//   oauth:https://normal-elk-24.clerk.accounts.dev:user_3DPU...:403fada9
	//
	// The issuer ends before the first non-URL-like segment. Since issuer is
	// always a URL (https://...) and sub is never a URL, we split after "https://...:"
	// by finding the issuer from the session's original JWT claims.
	//
	// Simpler approach: the issuer always starts with "https://" and the sub
	// follows after the issuer's domain path.
	const prefix = "https://"
	if !strings.HasPrefix(id, prefix) {
		// Fallback: first colon-separated segment is iss, rest is sub.
		parts := strings.SplitN(id, ":", 2)
		if len(parts) == 2 {
			return parts[0], parts[1]
		}
		return "", id
	}
	// Skip "https://" then find the next ":" — that's the end of the issuer domain.
	rest := id[len(prefix):]
	idx := strings.Index(rest, ":")
	if idx < 0 {
		return id, ""
	}
	iss = id[:len(prefix)+idx]
	afterIss := rest[idx+1:]
	// afterIss is "sub[:suffix]" — take just the sub.
	if colonIdx := strings.Index(afterIss, ":"); colonIdx >= 0 {
		sub = afterIss[:colonIdx]
	} else {
		sub = afterIss
	}
	return iss, sub
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
