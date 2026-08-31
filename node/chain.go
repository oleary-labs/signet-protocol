package node

import (
	"context"
	"fmt"
	"math/big"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"go.uber.org/zap"

	"signet/network"
	"signet/tss"
)

const (
	factoryABIJSON = `[
		{"name":"getNodeGroups","type":"function","inputs":[{"name":"node","type":"address"}],"outputs":[{"name":"","type":"address[]"}],"stateMutability":"view"},
		{"name":"getNodePubkey","type":"function","inputs":[{"name":"node","type":"address"}],"outputs":[{"name":"","type":"bytes"}],"stateMutability":"view"},
		{"name":"NodeActivatedInGroup","type":"event","inputs":[{"name":"node","type":"address","indexed":true},{"name":"group","type":"address","indexed":true}],"anonymous":false},
		{"name":"NodeDeactivatedInGroup","type":"event","inputs":[{"name":"node","type":"address","indexed":true},{"name":"group","type":"address","indexed":true}],"anonymous":false}
	]`

	groupABIJSON = `[
		{"name":"getActiveNodes","type":"function","inputs":[],"outputs":[{"name":"","type":"address[]"}],"stateMutability":"view"},
		{"name":"threshold","type":"function","inputs":[],"outputs":[{"name":"","type":"uint256"}],"stateMutability":"view"},
		{"name":"getIssuers","type":"function","inputs":[],"outputs":[{"name":"","type":"tuple[]","components":[{"name":"issuer","type":"string"},{"name":"clientIds","type":"string[]"}]}],"stateMutability":"view"},
		{"name":"getAuthKeys","type":"function","inputs":[],"outputs":[{"name":"","type":"bytes[]"}],"stateMutability":"view"},
		{"name":"siweDomains","type":"function","inputs":[],"outputs":[{"name":"","type":"string[]"}],"stateMutability":"view"},
		{"name":"getAuthResolver","type":"function","inputs":[],"outputs":[{"name":"","type":"tuple","components":[{"name":"chainId","type":"uint64"},{"name":"resolver","type":"address"},{"name":"requireCanonicalSubject","type":"bool"}]}],"stateMutability":"view"},
		{"name":"NodeJoined","type":"event","inputs":[{"name":"node","type":"address","indexed":true}],"anonymous":false},
		{"name":"NodeRemoved","type":"event","inputs":[{"name":"node","type":"address","indexed":true}],"anonymous":false},
		{"name":"IssuerAdded","type":"event","inputs":[{"name":"h","type":"bytes32","indexed":true},{"name":"issuer","type":"string","indexed":false},{"name":"clientIds","type":"string[]","indexed":false}],"anonymous":false},
		{"name":"IssuerRemoved","type":"event","inputs":[{"name":"h","type":"bytes32","indexed":true},{"name":"issuer","type":"string","indexed":false}],"anonymous":false},
		{"name":"AuthKeyAdded","type":"event","inputs":[{"name":"keyHash","type":"bytes32","indexed":true},{"name":"pubkey","type":"bytes","indexed":false}],"anonymous":false},
		{"name":"AuthKeyRemoved","type":"event","inputs":[{"name":"keyHash","type":"bytes32","indexed":true},{"name":"pubkey","type":"bytes","indexed":false}],"anonymous":false},
		{"name":"AuthResolverSet","type":"event","inputs":[{"name":"chainId","type":"uint64","indexed":false},{"name":"resolver","type":"address","indexed":true},{"name":"requireCanonicalSubject","type":"bool","indexed":false}],"anonymous":false},
		{"name":"ReshareRequested","type":"event","inputs":[{"name":"requestedBy","type":"address","indexed":true}],"anonymous":false}
	]`

	// resolverABIJSON is the ISignetAuthResolver interface the node calls to
	// authorize + resolve a SIWE-recovered address (the on-chain auth lane).
	resolverABIJSON = `[
		{"name":"resolve","type":"function","inputs":[{"name":"account","type":"address"}],"outputs":[{"name":"ok","type":"bool"},{"name":"subject","type":"bytes32"}],"stateMutability":"view"},
		{"name":"typeAndVersion","type":"function","inputs":[],"outputs":[{"name":"","type":"string"}],"stateMutability":"pure"}
	]`

	// defaultPollInterval is the chain event poll cadence. Every tick costs one
	// eth_blockNumber plus (at most) one eth_getLogs regardless of group count,
	// so this is the dominant standing RPC cost of an otherwise idle node.
	// The events polled for here — membership, issuer, auth-key and resolver
	// changes — are all human-initiated and rare, so a minute of detection
	// latency is not meaningful; 12s was ~5x the cost for no practical gain.
	// Override with chain_poll_secs where faster reaction matters.
	defaultPollInterval = 60 * time.Second

	// maxPollRange caps the block span of a single eth_getLogs. Without it, a
	// node that has been offline (or whose RPC has been failing) asks for an
	// unbounded range, which providers reject outright — and since lastBlock
	// only advances on success, that oversized query is then retried every tick
	// forever, burning quota while never making progress. Catch-up instead
	// walks forward one capped chunk at a time.
	maxPollRange uint64 = 5000

	// maxCatchupChunks bounds the chunks walked in a single poll so catch-up
	// cannot monopolise the tick.
	maxCatchupChunks = 20

	// headCacheTTL is how long a chain's head block number is reused across
	// resolver reads. Bursts of auth requests otherwise each pay their own
	// eth_blockNumber for a value that changes only once per block.
	headCacheTTL = 4 * time.Second

	// maxResolverLag bounds how stale a client-pinned block may be for the
	// resolver read (R-3): head - maxResolverLag <= blockNum <= head. It is also
	// the worst-case revocation latency at the auth instant (R-5).
	maxResolverLag uint64 = 30
)

// ChainClient watches the factory and group contracts for membership changes
// and keeps n.groups up to date.
type ChainClient struct {
	eth          *ethclient.Client
	factory      common.Address
	myAddr       common.Address
	factABI      abi.ABI
	grpABI       abi.ABI
	resolverABI  abi.ABI
	log          *zap.Logger
	n            *Node
	pollInterval time.Duration

	lastBlock uint64
	stopCh    chan struct{}

	// watchedTopics is the union of every factory and group event topic0 the
	// node reacts to, precomputed so a poll can fetch all of them for all
	// contracts in one eth_getLogs instead of one call per contract.
	watchedTopics []common.Hash

	// pubkeyCache memoises factory getNodePubkey reads. A node's registered
	// pubkey is immutable for the lifetime of its address, so this is a
	// permanent cache, not a TTL one.
	pubkeyMu    sync.Mutex
	pubkeyCache map[common.Address][]byte

	// tvCache memoises resolver typeAndVersion() reads, keyed by chain+address.
	// typeAndVersion is `pure`, so the answer cannot change for a given
	// deployed contract; without this every auth paid an eth_call for a
	// constant.
	tvMu    sync.Mutex
	tvCache map[string]string

	// headCache holds a recent head block number per chain, see headCacheTTL.
	headMu    sync.Mutex
	headCache map[uint64]headEntry

	// Cross-chain RPC reach for on-chain auth resolvers. The home chain (the
	// one `eth` points at) is registered under homeChainID; other chains are
	// dialed lazily from chainRPCs and cached in resolverClients.
	homeChainID     uint64
	chainRPCs       map[uint64]string
	clientsMu       sync.Mutex
	resolverClients map[uint64]*ethclient.Client
}

type headEntry struct {
	num uint64
	at  time.Time
}

// newChainClient dials the Ethereum RPC and initialises the chain client.
func newChainClient(cfg *Config, h *network.Host, n *Node, log *zap.Logger) (*ChainClient, error) {
	eth, err := ethclient.Dial(cfg.EthRPC)
	if err != nil {
		return nil, fmt.Errorf("dial eth rpc %s: %w", cfg.EthRPC, err)
	}

	factABI, err := abi.JSON(strings.NewReader(factoryABIJSON))
	if err != nil {
		eth.Close()
		return nil, fmt.Errorf("parse factory ABI: %w", err)
	}
	grpABI, err := abi.JSON(strings.NewReader(groupABIJSON))
	if err != nil {
		eth.Close()
		return nil, fmt.Errorf("parse group ABI: %w", err)
	}
	resolverABI, err := abi.JSON(strings.NewReader(resolverABIJSON))
	if err != nil {
		eth.Close()
		return nil, fmt.Errorf("parse resolver ABI: %w", err)
	}

	// Detect the home chain's id so resolver reads targeting it reuse `eth`
	// rather than re-dialing. Best-effort: on failure the home chain simply is
	// not pre-registered and a same-chain resolver would require an explicit
	// chain_rpcs entry.
	var homeChainID uint64
	chainIDCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	if id, err := eth.ChainID(chainIDCtx); err != nil {
		log.Warn("chain: detect home chain id", zap.Error(err))
	} else {
		homeChainID = id.Uint64()
	}
	cancel()

	pub := h.LibP2PHost().Peerstore().PubKey(h.PeerID())
	addr, err := network.EthereumAddress(pub)
	if err != nil {
		eth.Close()
		return nil, fmt.Errorf("derive eth address: %w", err)
	}

	poll := defaultPollInterval
	if cfg.ChainPollSecs > 0 {
		poll = time.Duration(cfg.ChainPollSecs) * time.Second
	}

	chainRPCs := make(map[uint64]string, len(cfg.ChainRPCs))
	for id, url := range cfg.ChainRPCs {
		chainRPCs[id] = url
	}

	resolverClients := make(map[uint64]*ethclient.Client)
	if homeChainID != 0 {
		resolverClients[homeChainID] = eth
	}

	return &ChainClient{
		eth:             eth,
		factory:         common.HexToAddress(cfg.FactoryAddress),
		myAddr:          common.Address(addr),
		factABI:         factABI,
		grpABI:          grpABI,
		resolverABI:     resolverABI,
		log:             log,
		n:               n,
		pollInterval:    poll,
		stopCh:          make(chan struct{}),
		homeChainID:     homeChainID,
		chainRPCs:       chainRPCs,
		resolverClients: resolverClients,
		watchedTopics:   watchedTopics(factABI, grpABI),
		pubkeyCache:     make(map[common.Address][]byte),
		tvCache:         make(map[string]string),
		headCache:       make(map[uint64]headEntry),
	}, nil
}

// watchedTopics returns every event topic0 the poll loop dispatches on, across
// both the factory and group ABIs. Fetching the union in one query lets a poll
// cover the factory and every group with a single eth_getLogs; logs are then
// routed by their emitting address.
func watchedTopics(factABI, grpABI abi.ABI) []common.Hash {
	factEvents := []string{"NodeActivatedInGroup", "NodeDeactivatedInGroup"}
	grpEvents := []string{"NodeJoined", "NodeRemoved", "IssuerAdded", "IssuerRemoved",
		"AuthKeyAdded", "AuthKeyRemoved", "AuthResolverSet", "ReshareRequested"}

	out := make([]common.Hash, 0, len(factEvents)+len(grpEvents))
	for _, name := range factEvents {
		out = append(out, factABI.Events[name].ID)
	}
	for _, name := range grpEvents {
		out = append(out, grpABI.Events[name].ID)
	}
	return out
}

// clientForChain returns an ethclient for the given chainId, lazily dialing and
// caching it from chain_rpcs config. The home chain (and any chain dialed
// earlier) is served from the cache. Returns an error if the chain is not
// configured, so a resolver read fails closed rather than reading the wrong
// chain.
func (c *ChainClient) clientForChain(chainID uint64) (*ethclient.Client, error) {
	c.clientsMu.Lock()
	defer c.clientsMu.Unlock()

	if cl, ok := c.resolverClients[chainID]; ok {
		return cl, nil
	}
	url, ok := c.chainRPCs[chainID]
	if !ok || url == "" {
		return nil, fmt.Errorf("no RPC configured for chain %d", chainID)
	}
	cl, err := ethclient.Dial(url)
	if err != nil {
		return nil, fmt.Errorf("dial chain %d rpc: %w", chainID, err)
	}
	c.resolverClients[chainID] = cl
	return cl, nil
}

// loadGroups queries the factory for all groups this node is active in and
// populates n.groups. Records the current block number so polling starts
// from the next block.
func (c *ChainClient) loadGroups(ctx context.Context) error {
	block, err := c.eth.BlockNumber(ctx)
	if err != nil {
		return fmt.Errorf("get block number: %w", err)
	}
	c.lastBlock = block

	groups, err := c.callGetNodeGroups(ctx, c.myAddr)
	if err != nil {
		return fmt.Errorf("getNodeGroups: %w", err)
	}
	c.log.Info("chain: loading groups", zap.Int("count", len(groups)))

	for _, grpAddr := range groups {
		info, err := c.buildGroupInfo(ctx, grpAddr)
		if err != nil {
			c.log.Warn("chain: build group info",
				zap.String("group", grpAddr.Hex()), zap.Error(err))
			continue
		}
		c.n.groupsMu.Lock()
		c.n.groups[strings.ToLower(grpAddr.Hex())] = info
		c.n.groupsMu.Unlock()
		c.log.Info("chain: loaded group",
			zap.String("group", grpAddr.Hex()),
			zap.Int("members", len(info.Members)),
			zap.Int("threshold", info.Threshold),
		)
	}
	return nil
}

// buildGroupInfo fetches active nodes, threshold, and OAuth issuers for a group,
// resolving each member's Ethereum address to a libp2p party.ID.
func (c *ChainClient) buildGroupInfo(ctx context.Context, grpAddr common.Address) (*GroupInfo, error) {
	members, err := c.callGetActiveNodes(ctx, grpAddr)
	if err != nil {
		return nil, fmt.Errorf("getActiveNodes: %w", err)
	}
	thresh, err := c.callThreshold(ctx, grpAddr)
	if err != nil {
		return nil, fmt.Errorf("threshold: %w", err)
	}

	ids := make([]tss.PartyID, 0, len(members))
	for _, memberAddr := range members {
		pid, err := c.resolvePartyID(ctx, memberAddr)
		if err != nil {
			c.log.Warn("chain: resolve party ID",
				zap.String("addr", memberAddr.Hex()), zap.Error(err))
			continue
		}
		ids = append(ids, pid)
	}

	// Load OAuth issuers and register them with the auth store.
	rawIssuers, err := c.callGetIssuers(ctx, grpAddr)
	if err != nil {
		c.log.Warn("chain: getIssuers", zap.String("group", grpAddr.Hex()), zap.Error(err))
	} else if len(rawIssuers) > 0 {
		hexGrp := strings.ToLower(grpAddr.Hex())
		infos := make([]IssuerInfo, 0, len(rawIssuers))
		for _, ri := range rawIssuers {
			jwksURI, err := discoverJWKSURI(ctx, ri.Issuer)
			if err != nil {
				c.log.Warn("chain: OIDC discovery", zap.String("issuer", ri.Issuer), zap.Error(err))
				jwksURI = ""
			}
			infos = append(infos, IssuerInfo{
				Issuer:    ri.Issuer,
				ClientIds: ri.ClientIds,
				JwksURI:   jwksURI,
			})
		}
		c.n.auth.SetIssuers(ctx, hexGrp, infos)
	}

	// Load authorization keys and register them with the auth store.
	rawAuthKeys, err := c.callGetAuthKeys(ctx, grpAddr)
	if err != nil {
		c.log.Warn("chain: getAuthKeys", zap.String("group", grpAddr.Hex()), zap.Error(err))
	} else if len(rawAuthKeys) > 0 {
		hexGrp := strings.ToLower(grpAddr.Hex())
		c.n.auth.SetAuthKeys(hexGrp, rawAuthKeys)
	}

	// Load the on-chain auth resolver binding (the auth lane). getAuthResolver
	// is new; older group deployments revert/return-empty, so treat failure as
	// "no resolver" rather than failing group load.
	if cfg, err := c.callGetAuthResolver(ctx, grpAddr); err != nil {
		c.log.Debug("chain: getAuthResolver", zap.String("group", grpAddr.Hex()), zap.Error(err))
	} else {
		c.n.auth.SetAuthResolver(strings.ToLower(grpAddr.Hex()), cfg)
	}

	// Accepted SIWE domains. Like getAuthResolver this is new, so a group
	// deployed against an older implementation reverts — treat that as "no
	// domains", which disables the resolver scheme rather than opening it.
	if doms, err := c.callSiweDomains(ctx, grpAddr); err != nil {
		c.log.Debug("chain: siweDomains", zap.String("group", grpAddr.Hex()), zap.Error(err))
		c.n.auth.SetSiweDomains(strings.ToLower(grpAddr.Hex()), nil)
	} else {
		c.n.auth.SetSiweDomains(strings.ToLower(grpAddr.Hex()), doms)
	}

	return &GroupInfo{
		Threshold: int(thresh.Int64()),
		Members:   ids,
	}, nil
}

// HomeChainID is the chain the group itself lives on — whatever ETH_RPC_URL
// points at. Used as the expected ERC-4361 Chain ID, deliberately decoupled
// from the resolver's chain.
func (c *ChainClient) HomeChainID() uint64 {
	if c == nil {
		return 0
	}
	return c.homeChainID
}

// callSiweDomains reads the group's accepted SIWE domain list.
func (c *ChainClient) callSiweDomains(ctx context.Context, grpAddr common.Address) ([]string, error) {
	data, err := c.grpABI.Pack("siweDomains")
	if err != nil {
		return nil, err
	}
	result, err := c.eth.CallContract(ctx, ethereum.CallMsg{To: &grpAddr, Data: data}, nil)
	if err != nil {
		return nil, err
	}
	out, err := c.grpABI.Unpack("siweDomains", result)
	if err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("empty siweDomains result")
	}
	doms, ok := out[0].([]string)
	if !ok {
		return nil, fmt.Errorf("unexpected type %T for siweDomains result", out[0])
	}
	return doms, nil
}

// resolvePartyID fetches the node's pubkey from the factory and derives its tss.PartyID.
func (c *ChainClient) resolvePartyID(ctx context.Context, nodeAddr common.Address) (tss.PartyID, error) {
	pubkey, err := c.nodePubkey(ctx, nodeAddr)
	if err != nil {
		return "", fmt.Errorf("getNodePubkey %s: %w", nodeAddr.Hex(), err)
	}
	if len(pubkey) == 0 {
		return "", fmt.Errorf("empty pubkey for %s", nodeAddr.Hex())
	}
	peerID, err := network.PeerIDFromUncompressedPubkey(pubkey)
	if err != nil {
		return "", fmt.Errorf("peer ID from pubkey: %w", err)
	}
	return tss.PartyID(peerID.String()), nil
}

// start launches the event-polling goroutine.
func (c *ChainClient) start() {
	go c.watchLoop()
}

// close stops the polling loop and releases all eth clients (home + any
// lazily-dialed resolver chains).
func (c *ChainClient) close() {
	close(c.stopCh)
	c.clientsMu.Lock()
	for id, cl := range c.resolverClients {
		// The home client is the same handle as c.eth; close it once below.
		if id == c.homeChainID {
			continue
		}
		cl.Close()
	}
	c.resolverClients = nil
	c.clientsMu.Unlock()
	c.eth.Close()
}

func (c *ChainClient) watchLoop() {
	ticker := time.NewTicker(c.pollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			if err := c.poll(ctx); err != nil {
				c.log.Warn("chain: poll error", zap.Error(err))
			}
			cancel()
		}
	}
}

func (c *ChainClient) poll(ctx context.Context) error {
	current, err := c.eth.BlockNumber(ctx)
	if err != nil {
		return fmt.Errorf("block number: %w", err)
	}
	c.storeHead(c.homeChainID, current)
	if current <= c.lastBlock {
		return nil
	}

	// Walk forward in capped chunks so a large backlog cannot produce a query
	// the provider refuses (and would then retry unchanged every tick). In
	// steady state this loop runs exactly once.
	for chunk := 0; chunk < maxCatchupChunks && c.lastBlock < current; chunk++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		from := c.lastBlock + 1
		to := current
		if to-from+1 > maxPollRange {
			to = from + maxPollRange - 1
		}
		if err := c.pollRange(ctx, from, to); err != nil {
			return err
		}
		c.lastBlock = to
	}
	if c.lastBlock < current {
		c.log.Info("chain: catch-up still behind head",
			zap.Uint64("at", c.lastBlock), zap.Uint64("head", current))
	}
	return nil
}

// pollRange fetches every watched factory and group event in [from,to] with a
// single eth_getLogs and dispatches the results by emitting contract. Querying
// per-contract instead costs one eth_getLogs per group per tick, which is the
// single largest driver of RPC spend on an idle node.
func (c *ChainClient) pollRange(ctx context.Context, from, to uint64) error {
	c.n.groupsMu.RLock()
	known := make(map[common.Address]struct{}, len(c.n.groups))
	for hexAddr := range c.n.groups {
		known[common.HexToAddress(hexAddr)] = struct{}{}
	}
	c.n.groupsMu.RUnlock()

	addrs := make([]common.Address, 0, len(known)+1)
	addrs = append(addrs, c.factory)
	for addr := range known {
		addrs = append(addrs, addr)
	}

	logs, err := c.eth.FilterLogs(ctx, ethereum.FilterQuery{
		FromBlock: new(big.Int).SetUint64(from),
		ToBlock:   new(big.Int).SetUint64(to),
		Addresses: addrs,
		Topics:    [][]common.Hash{c.watchedTopics},
	})
	if err != nil {
		return fmt.Errorf("filter logs [%d,%d]: %w", from, to, err)
	}

	// Route by emitting address. The factory and group ABIs share no event
	// signatures, so the address alone disambiguates.
	var factoryLogs []types.Log
	byGroup := make(map[common.Address][]types.Log)
	for _, lg := range logs {
		if lg.Address == c.factory {
			factoryLogs = append(factoryLogs, lg)
			continue
		}
		byGroup[lg.Address] = append(byGroup[lg.Address], lg)
	}

	// Factory events first: an activation here may add a group whose own events
	// in this same range still need scanning.
	c.handleFactoryLogs(ctx, factoryLogs)

	for grpAddr, lgs := range byGroup {
		if err := c.handleGroupLogs(ctx, grpAddr, lgs); err != nil {
			c.log.Warn("chain: group events",
				zap.String("group", grpAddr.Hex()), zap.Error(err))
		}
	}

	// Any group activated during this range was not in the batched query's
	// address list, so scan it individually to preserve prior behaviour. This
	// is rare (group activation only), so the extra call does not affect
	// steady-state cost.
	c.n.groupsMu.RLock()
	fresh := make([]common.Address, 0)
	for hexAddr := range c.n.groups {
		addr := common.HexToAddress(hexAddr)
		if _, seen := known[addr]; !seen {
			fresh = append(fresh, addr)
		}
	}
	c.n.groupsMu.RUnlock()

	for _, grpAddr := range fresh {
		if err := c.pollGroupEvents(ctx, grpAddr, from, to); err != nil {
			c.log.Warn("chain: newly activated group events",
				zap.String("group", grpAddr.Hex()), zap.Error(err))
		}
	}
	return nil
}

// handleFactoryLogs applies factory membership events addressed to this node.
// The batched query cannot filter on the indexed node topic (it is shared with
// group events that index a different address there), so the match on myAddr
// happens here instead of server-side.
func (c *ChainClient) handleFactoryLogs(ctx context.Context, logs []types.Log) {
	activatedID := c.factABI.Events["NodeActivatedInGroup"].ID
	deactivatedID := c.factABI.Events["NodeDeactivatedInGroup"].ID
	meTopic := common.BytesToHash(c.myAddr.Bytes())

	for _, lg := range logs {
		if len(lg.Topics) < 3 {
			continue
		}
		if lg.Topics[1] != meTopic {
			continue // another node's membership change
		}
		grpAddr := common.BytesToAddress(lg.Topics[2].Bytes())
		switch lg.Topics[0] {
		case activatedID:
			key := strings.ToLower(grpAddr.Hex())
			c.n.groupsMu.RLock()
			_, exists := c.n.groups[key]
			c.n.groupsMu.RUnlock()
			if exists {
				continue
			}
			info, err := c.buildGroupInfo(ctx, grpAddr)
			if err != nil {
				c.log.Warn("chain: build group info on activation",
					zap.String("group", grpAddr.Hex()), zap.Error(err))
				continue
			}
			c.n.groupsMu.Lock()
			c.n.groups[key] = info
			c.n.groupsMu.Unlock()
			c.log.Info("chain: joined group", zap.String("group", grpAddr.Hex()),
				zap.Int("members", len(info.Members)))

		case deactivatedID:
			key := strings.ToLower(grpAddr.Hex())
			c.n.groupsMu.Lock()
			delete(c.n.groups, key)
			c.n.groupsMu.Unlock()
			c.log.Info("chain: left group", zap.String("group", grpAddr.Hex()))
		}
	}
}

// pollGroupEvents fetches and applies one group's events over a block range.
// The steady-state path batches all groups into pollRange's single query; this
// remains for groups that appear mid-range and so missed that query.
func (c *ChainClient) pollGroupEvents(ctx context.Context, grpAddr common.Address, from, to uint64) error {
	logs, err := c.eth.FilterLogs(ctx, ethereum.FilterQuery{
		FromBlock: new(big.Int).SetUint64(from),
		ToBlock:   new(big.Int).SetUint64(to),
		Addresses: []common.Address{grpAddr},
		Topics:    [][]common.Hash{c.watchedTopics},
	})
	if err != nil {
		return fmt.Errorf("filter group logs: %w", err)
	}
	return c.handleGroupLogs(ctx, grpAddr, logs)
}

func (c *ChainClient) handleGroupLogs(ctx context.Context, grpAddr common.Address, logs []types.Log) error {
	joinedID := c.grpABI.Events["NodeJoined"].ID
	removedID := c.grpABI.Events["NodeRemoved"].ID
	issuerAddedID := c.grpABI.Events["IssuerAdded"].ID
	issuerRemovedID := c.grpABI.Events["IssuerRemoved"].ID
	authKeyAddedID := c.grpABI.Events["AuthKeyAdded"].ID
	authKeyRemovedID := c.grpABI.Events["AuthKeyRemoved"].ID
	authResolverSetID := c.grpABI.Events["AuthResolverSet"].ID
	reshareRequestedID := c.grpABI.Events["ReshareRequested"].ID

	hexGrp := strings.ToLower(grpAddr.Hex())

	for _, lg := range logs {
		if len(lg.Topics) < 1 {
			continue
		}
		switch lg.Topics[0] {
		case joinedID, removedID:
			if len(lg.Topics) < 2 {
				continue
			}
			nodeAddr := common.BytesToAddress(lg.Topics[1].Bytes())
			pid, err := c.resolvePartyID(ctx, nodeAddr)
			if err != nil {
				c.log.Warn("chain: resolve party on group event",
					zap.String("addr", nodeAddr.Hex()), zap.Error(err))
				continue
			}

			// Capture old membership before updating.
			c.n.groupsMu.Lock()
			grp, ok := c.n.groups[hexGrp]
			if !ok {
				c.n.groupsMu.Unlock()
				continue
			}
			oldMembers := make([]tss.PartyID, len(grp.Members))
			copy(oldMembers, grp.Members)
			threshold := grp.Threshold

			// Apply membership change.
			switch lg.Topics[0] {
			case joinedID:
				if !containsParty(grp.Members, pid) {
					grp.Members = append(grp.Members, pid)
				}
			case removedID:
				grp.Members = removeParty(grp.Members, pid)
			}
			newMembers := make([]tss.PartyID, len(grp.Members))
			copy(newMembers, grp.Members)
			c.n.groupsMu.Unlock()

			// Trigger reshare job creation or deferral.
			eventType := "node_added"
			if lg.Topics[0] == removedID {
				eventType = "node_removed"
			}
			c.n.reshareJobsMu.RLock()
			existingJob := c.n.reshareJobs[hexGrp]
			c.n.reshareJobsMu.RUnlock()

			if existingJob != nil {
				// Already resharing: defer this event.
				if err := c.n.deferMembershipEvent(hexGrp, eventType, nodeAddr.Hex(), pid); err != nil {
					c.log.Warn("chain: defer membership event",
						zap.String("group", hexGrp), zap.Error(err))
				} else {
					c.log.Info("chain: membership event deferred (reshare in progress)",
						zap.String("group", hexGrp),
						zap.String("event", eventType))
				}
			} else {
				// Group is ACTIVE: create reshare job. Only the elected
				// leader starts the coordinator to avoid races.
				if err := c.n.createReshareJob(hexGrp, eventType, oldMembers, newMembers, threshold); err != nil {
					c.log.Warn("chain: create reshare job",
						zap.String("group", hexGrp), zap.Error(err))
				} else if c.n.isReshareLeader(hexGrp) {
					if err := c.n.startCoordinator(hexGrp, 1); err != nil {
						c.log.Debug("chain: start coordinator",
							zap.String("group", hexGrp), zap.Error(err))
					}
				} else {
					leader, _ := c.n.reshareLeader(hexGrp)
					c.log.Info("chain: not reshare leader, waiting",
						zap.String("group", hexGrp),
						zap.String("leader", string(leader)))
				}
			}

		case issuerAddedID:
			if len(lg.Topics) < 2 {
				continue
			}
			// Decode non-indexed data: issuer string + clientIds string[]
			out := make(map[string]interface{})
			if err := c.grpABI.UnpackIntoMap(out, "IssuerAdded", lg.Data); err != nil {
				c.log.Warn("chain: unpack IssuerAdded", zap.Error(err))
				continue
			}
			issuer, _ := out["issuer"].(string)
			clientIds, _ := out["clientIds"].([]string)
			jwksURI, err := discoverJWKSURI(ctx, issuer)
			if err != nil {
				c.log.Warn("chain: OIDC discovery on IssuerAdded",
					zap.String("issuer", issuer), zap.Error(err))
				jwksURI = ""
			}
			c.n.auth.AddIssuer(ctx, hexGrp, IssuerInfo{
				Issuer:    issuer,
				ClientIds: clientIds,
				JwksURI:   jwksURI,
			})
			c.log.Info("chain: issuer added", zap.String("group", hexGrp), zap.String("issuer", issuer))

		case issuerRemovedID:
			if len(lg.Topics) < 2 {
				continue
			}
			h := [32]byte(lg.Topics[1])
			c.n.auth.RemoveIssuer(hexGrp, h)
			c.log.Info("chain: issuer removed", zap.String("group", hexGrp))

		case authKeyAddedID:
			if len(lg.Topics) < 2 {
				continue
			}
			out := make(map[string]interface{})
			if err := c.grpABI.UnpackIntoMap(out, "AuthKeyAdded", lg.Data); err != nil {
				c.log.Warn("chain: unpack AuthKeyAdded", zap.Error(err))
				continue
			}
			pubkey, _ := out["pubkey"].([]byte)
			c.n.auth.AddAuthKey(hexGrp, pubkey)
			c.log.Info("chain: auth key added", zap.String("group", hexGrp))

		case authKeyRemovedID:
			if len(lg.Topics) < 2 {
				continue
			}
			h := [32]byte(lg.Topics[1])
			c.n.auth.RemoveAuthKey(hexGrp, h)
			c.log.Info("chain: auth key removed", zap.String("group", hexGrp))

		case authResolverSetID:
			// The binding changed (timelocked executeAuthResolver fired). Re-read
			// the getter for the authoritative value rather than decoding the
			// event, mirroring how the binding is loaded at startup.
			if cfg, err := c.callGetAuthResolver(ctx, grpAddr); err != nil {
				c.log.Warn("chain: getAuthResolver on AuthResolverSet",
					zap.String("group", hexGrp), zap.Error(err))
			} else {
				c.n.auth.SetAuthResolver(hexGrp, cfg)
				c.log.Info("chain: auth resolver set",
					zap.String("group", hexGrp),
					zap.String("resolver", cfg.Resolver.Hex()),
					zap.Uint64("chainId", cfg.ChainID))
			}

		case reshareRequestedID:
			// Manual reshare request from the group manager.
			// Same-committee refresh: old and new members are identical.
			c.n.groupsMu.RLock()
			grp := c.n.groups[hexGrp]
			c.n.groupsMu.RUnlock()
			if grp == nil {
				continue
			}
			members := grp.Members
			threshold := grp.Threshold

			c.log.Info("chain: reshare requested",
				zap.String("group", hexGrp),
				zap.Int("members", len(members)))

			oldMembers := make([]tss.PartyID, len(members))
			copy(oldMembers, members)

			if err := c.n.createReshareJob(hexGrp, "refresh", oldMembers, oldMembers, threshold); err != nil {
				c.log.Warn("chain: create reshare job for refresh",
					zap.String("group", hexGrp), zap.Error(err))
			} else if c.n.isReshareLeader(hexGrp) {
				if err := c.n.startCoordinator(hexGrp, 1); err != nil {
					c.log.Debug("chain: start coordinator for refresh",
						zap.String("group", hexGrp), zap.Error(err))
				}
			} else {
				leader, _ := c.n.reshareLeader(hexGrp)
				c.log.Info("chain: not reshare leader for refresh, waiting",
					zap.String("group", hexGrp),
					zap.String("leader", string(leader)))
			}
		}
	}
	return nil
}

// --- Caches ---

// nodePubkey returns a registered node's pubkey, memoising the factory read.
// A node's pubkey is fixed at registration, so a hit never goes stale; only
// successful reads are cached.
func (c *ChainClient) nodePubkey(ctx context.Context, nodeAddr common.Address) ([]byte, error) {
	c.pubkeyMu.Lock()
	if pk, ok := c.pubkeyCache[nodeAddr]; ok {
		c.pubkeyMu.Unlock()
		return pk, nil
	}
	c.pubkeyMu.Unlock()

	pk, err := c.callGetNodePubkey(ctx, nodeAddr)
	if err != nil {
		return nil, err
	}
	if len(pk) > 0 {
		c.pubkeyMu.Lock()
		c.pubkeyCache[nodeAddr] = pk
		c.pubkeyMu.Unlock()
	}
	return pk, nil
}

// headBlock returns the head block number for a chain, reusing a recent read
// for headCacheTTL. Callers needing certainty that a specific block is not
// ahead of head should use freshHeadBlock on a negative result.
func (c *ChainClient) headBlock(ctx context.Context, chainID uint64, cl *ethclient.Client) (uint64, error) {
	c.headMu.Lock()
	e, ok := c.headCache[chainID]
	c.headMu.Unlock()
	if ok && time.Since(e.at) < headCacheTTL {
		return e.num, nil
	}
	return c.freshHeadBlock(ctx, chainID, cl)
}

func (c *ChainClient) freshHeadBlock(ctx context.Context, chainID uint64, cl *ethclient.Client) (uint64, error) {
	head, err := cl.BlockNumber(ctx)
	if err != nil {
		return 0, err
	}
	c.storeHead(chainID, head)
	return head, nil
}

func (c *ChainClient) storeHead(chainID, head uint64) {
	if chainID == 0 {
		return
	}
	c.headMu.Lock()
	// Never move a cached head backwards: a lagging RPC replica would otherwise
	// make an already-accepted pinned block look "ahead of head".
	if e, ok := c.headCache[chainID]; !ok || head >= e.num {
		c.headCache[chainID] = headEntry{num: head, at: time.Now()}
	}
	c.headMu.Unlock()
}

// resolverTypeAndVersion returns a resolver's typeAndVersion(), memoised per
// chain+address. The function is `pure` and the contract at an address is
// immutable, so this is cached permanently rather than on a TTL.
func (c *ChainClient) resolverTypeAndVersion(ctx context.Context, chainID uint64, resolver common.Address) (string, error) {
	key := fmt.Sprintf("%d:%s", chainID, strings.ToLower(resolver.Hex()))

	c.tvMu.Lock()
	if tv, ok := c.tvCache[key]; ok {
		c.tvMu.Unlock()
		return tv, nil
	}
	c.tvMu.Unlock()

	tv, err := c.callResolverTypeAndVersion(ctx, chainID, resolver)
	if err != nil {
		return "", err
	}
	c.tvMu.Lock()
	c.tvCache[key] = tv
	c.tvMu.Unlock()
	return tv, nil
}

// --- ABI call helpers ---

func (c *ChainClient) callGetNodeGroups(ctx context.Context, node common.Address) ([]common.Address, error) {
	data, err := c.factABI.Pack("getNodeGroups", node)
	if err != nil {
		return nil, err
	}
	result, err := c.eth.CallContract(ctx, ethereum.CallMsg{To: &c.factory, Data: data}, nil)
	if err != nil {
		return nil, err
	}
	results, err := c.factABI.Unpack("getNodeGroups", result)
	if err != nil {
		return nil, err
	}
	return results[0].([]common.Address), nil
}

func (c *ChainClient) callGetNodePubkey(ctx context.Context, node common.Address) ([]byte, error) {
	data, err := c.factABI.Pack("getNodePubkey", node)
	if err != nil {
		return nil, err
	}
	result, err := c.eth.CallContract(ctx, ethereum.CallMsg{To: &c.factory, Data: data}, nil)
	if err != nil {
		return nil, err
	}
	results, err := c.factABI.Unpack("getNodePubkey", result)
	if err != nil {
		return nil, err
	}
	return results[0].([]byte), nil
}

func (c *ChainClient) callGetActiveNodes(ctx context.Context, grpAddr common.Address) ([]common.Address, error) {
	data, err := c.grpABI.Pack("getActiveNodes")
	if err != nil {
		return nil, err
	}
	result, err := c.eth.CallContract(ctx, ethereum.CallMsg{To: &grpAddr, Data: data}, nil)
	if err != nil {
		return nil, err
	}
	results, err := c.grpABI.Unpack("getActiveNodes", result)
	if err != nil {
		return nil, err
	}
	return results[0].([]common.Address), nil
}

// rawIssuer is the ABI-decoded representation of an OAuthIssuer tuple.
type rawIssuer struct {
	Issuer    string
	ClientIds []string
}

// callGetIssuers calls getIssuers() on a group contract and returns the result.
// go-ethereum represents tuple[] outputs via reflect, so we use reflect to
// extract fields by name.
func (c *ChainClient) callGetIssuers(ctx context.Context, grpAddr common.Address) ([]rawIssuer, error) {
	data, err := c.grpABI.Pack("getIssuers")
	if err != nil {
		return nil, err
	}
	result, err := c.eth.CallContract(ctx, ethereum.CallMsg{To: &grpAddr, Data: data}, nil)
	if err != nil {
		return nil, err
	}
	results, err := c.grpABI.Unpack("getIssuers", result)
	if err != nil {
		return nil, err
	}
	if len(results) == 0 {
		return nil, nil
	}
	v := reflect.ValueOf(results[0])
	if v.Kind() != reflect.Slice {
		return nil, fmt.Errorf("unexpected type %T for getIssuers result", results[0])
	}
	out := make([]rawIssuer, v.Len())
	for i := 0; i < v.Len(); i++ {
		elem := v.Index(i)
		out[i].Issuer = elem.FieldByName("Issuer").String()
		cidsVal := elem.FieldByName("ClientIds")
		cids := make([]string, cidsVal.Len())
		for j := 0; j < cidsVal.Len(); j++ {
			cids[j] = cidsVal.Index(j).String()
		}
		out[i].ClientIds = cids
	}
	return out, nil
}

// callGetAuthKeys calls getAuthKeys() on a group contract and returns the result.
func (c *ChainClient) callGetAuthKeys(ctx context.Context, grpAddr common.Address) ([][]byte, error) {
	data, err := c.grpABI.Pack("getAuthKeys")
	if err != nil {
		return nil, err
	}
	result, err := c.eth.CallContract(ctx, ethereum.CallMsg{To: &grpAddr, Data: data}, nil)
	if err != nil {
		return nil, err
	}
	results, err := c.grpABI.Unpack("getAuthKeys", result)
	if err != nil {
		return nil, err
	}
	if len(results) == 0 {
		return nil, nil
	}
	raw, ok := results[0].([][]byte)
	if !ok {
		return nil, fmt.Errorf("unexpected type %T for getAuthKeys result", results[0])
	}
	return raw, nil
}

func (c *ChainClient) callThreshold(ctx context.Context, grpAddr common.Address) (*big.Int, error) {
	data, err := c.grpABI.Pack("threshold")
	if err != nil {
		return nil, err
	}
	result, err := c.eth.CallContract(ctx, ethereum.CallMsg{To: &grpAddr, Data: data}, nil)
	if err != nil {
		return nil, err
	}
	results, err := c.grpABI.Unpack("threshold", result)
	if err != nil {
		return nil, err
	}
	return results[0].(*big.Int), nil
}

// callGetAuthResolver reads the group's on-chain auth resolver binding. A single
// tuple output → go-ethereum decodes via reflect, so fields are read by name.
func (c *ChainClient) callGetAuthResolver(ctx context.Context, grpAddr common.Address) (ResolverConfig, error) {
	data, err := c.grpABI.Pack("getAuthResolver")
	if err != nil {
		return ResolverConfig{}, err
	}
	result, err := c.eth.CallContract(ctx, ethereum.CallMsg{To: &grpAddr, Data: data}, nil)
	if err != nil {
		return ResolverConfig{}, err
	}
	results, err := c.grpABI.Unpack("getAuthResolver", result)
	if err != nil {
		return ResolverConfig{}, err
	}
	if len(results) == 0 {
		return ResolverConfig{}, fmt.Errorf("empty getAuthResolver result")
	}
	v := reflect.ValueOf(results[0])
	if v.Kind() != reflect.Struct {
		return ResolverConfig{}, fmt.Errorf("unexpected type %T for getAuthResolver result", results[0])
	}
	resolver, ok := v.FieldByName("Resolver").Interface().(common.Address)
	if !ok {
		return ResolverConfig{}, fmt.Errorf("unexpected resolver field type")
	}
	return ResolverConfig{
		ChainID:                 v.FieldByName("ChainId").Uint(),
		Resolver:                resolver,
		RequireCanonicalSubject: v.FieldByName("RequireCanonicalSubject").Bool(),
	}, nil
}

// callResolve performs the pinned-block resolver read (§10 R-2/R-3). It dials
// the resolver's chain, verifies the client-pinned block is fresh and its hash
// canonical in this node's own view, then eth_calls resolve(account) at exactly
// that block with from = 0x0 — so every honest node reads identical state and
// a resolver branching on msg.sender cannot split the vote. Fails closed on any
// freshness/hash mismatch.
func (c *ChainClient) callResolve(
	ctx context.Context,
	chainID uint64,
	resolver, account common.Address,
	blockNum uint64,
	blockHash common.Hash,
) (bool, [32]byte, error) {
	var zero [32]byte
	cl, err := c.clientForChain(chainID)
	if err != nil {
		return false, zero, err
	}

	head, err := c.headBlock(ctx, chainID, cl)
	if err != nil {
		return false, zero, fmt.Errorf("chain %d head: %w", chainID, err)
	}
	if blockNum > head {
		// A cached head may simply predate the client's pinned block. Confirm
		// against a fresh read before rejecting, so the cache can only cost an
		// extra call, never a false denial.
		if head, err = c.freshHeadBlock(ctx, chainID, cl); err != nil {
			return false, zero, fmt.Errorf("chain %d head: %w", chainID, err)
		}
		if blockNum > head {
			return false, zero, fmt.Errorf("pinned block %d ahead of head %d", blockNum, head)
		}
	}
	if head-blockNum > maxResolverLag {
		return false, zero, fmt.Errorf("pinned block %d too stale (head %d, max lag %d)", blockNum, head, maxResolverLag)
	}

	header, err := cl.HeaderByNumber(ctx, new(big.Int).SetUint64(blockNum))
	if err != nil {
		return false, zero, fmt.Errorf("header %d on chain %d: %w", blockNum, chainID, err)
	}
	if header.Hash() != blockHash {
		return false, zero, fmt.Errorf("pinned block hash mismatch at %d: have %s, want %s",
			blockNum, header.Hash().Hex(), blockHash.Hex())
	}

	data, err := c.resolverABI.Pack("resolve", account)
	if err != nil {
		return false, zero, err
	}
	out, err := cl.CallContract(ctx, ethereum.CallMsg{To: &resolver, Data: data}, new(big.Int).SetUint64(blockNum))
	if err != nil {
		return false, zero, fmt.Errorf("resolve eth_call: %w", err)
	}
	results, err := c.resolverABI.Unpack("resolve", out)
	if err != nil {
		return false, zero, err
	}
	if len(results) != 2 {
		return false, zero, fmt.Errorf("unexpected resolve result arity %d", len(results))
	}
	ok, _ := results[0].(bool)
	subject, _ := results[1].([32]byte)
	return ok, subject, nil
}

// callResolverTypeAndVersion reads the resolver's typeAndVersion() so the node
// can refuse unknown versions (R-2). typeAndVersion is pure, so the read is not
// block-pinned.
func (c *ChainClient) callResolverTypeAndVersion(ctx context.Context, chainID uint64, resolver common.Address) (string, error) {
	cl, err := c.clientForChain(chainID)
	if err != nil {
		return "", err
	}
	data, err := c.resolverABI.Pack("typeAndVersion")
	if err != nil {
		return "", err
	}
	out, err := cl.CallContract(ctx, ethereum.CallMsg{To: &resolver, Data: data}, nil)
	if err != nil {
		return "", fmt.Errorf("typeAndVersion eth_call: %w", err)
	}
	results, err := c.resolverABI.Unpack("typeAndVersion", out)
	if err != nil {
		return "", err
	}
	if len(results) == 0 {
		return "", fmt.Errorf("empty typeAndVersion result")
	}
	s, _ := results[0].(string)
	return s, nil
}

// --- Slice helpers ---

func containsParty(slice []tss.PartyID, id tss.PartyID) bool {
	for _, v := range slice {
		if v == id {
			return true
		}
	}
	return false
}

func removeParty(slice []tss.PartyID, id tss.PartyID) []tss.PartyID {
	for i, v := range slice {
		if v == id {
			return append(slice[:i], slice[i+1:]...)
		}
	}
	return slice
}
