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
	"github.com/ethereum/go-ethereum/ethclient"
	"go.uber.org/zap"

	"signet/tss"
	"signet/network"
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

	defaultPollInterval = 12 * time.Second

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

	// Cross-chain RPC reach for on-chain auth resolvers. The home chain (the
	// one `eth` points at) is registered under homeChainID; other chains are
	// dialed lazily from chainRPCs and cached in resolverClients.
	homeChainID     uint64
	chainRPCs       map[uint64]string
	clientsMu       sync.Mutex
	resolverClients map[uint64]*ethclient.Client
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
	}, nil
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

	return &GroupInfo{
		Threshold: int(thresh.Int64()),
		Members:   ids,
	}, nil
}

// resolvePartyID fetches the node's pubkey from the factory and derives its tss.PartyID.
func (c *ChainClient) resolvePartyID(ctx context.Context, nodeAddr common.Address) (tss.PartyID, error) {
	pubkey, err := c.callGetNodePubkey(ctx, nodeAddr)
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
	if current <= c.lastBlock {
		return nil
	}
	from := c.lastBlock + 1
	to := current

	if err := c.pollFactoryEvents(ctx, from, to); err != nil {
		c.log.Warn("chain: factory events", zap.Error(err))
	}

	c.n.groupsMu.RLock()
	groupAddrs := make([]common.Address, 0, len(c.n.groups))
	for hexAddr := range c.n.groups {
		groupAddrs = append(groupAddrs, common.HexToAddress(hexAddr))
	}
	c.n.groupsMu.RUnlock()

	for _, grpAddr := range groupAddrs {
		if err := c.pollGroupEvents(ctx, grpAddr, from, to); err != nil {
			c.log.Warn("chain: group events",
				zap.String("group", grpAddr.Hex()), zap.Error(err))
		}
	}

	c.lastBlock = to
	return nil
}

func (c *ChainClient) pollFactoryEvents(ctx context.Context, from, to uint64) error {
	activatedID := c.factABI.Events["NodeActivatedInGroup"].ID
	deactivatedID := c.factABI.Events["NodeDeactivatedInGroup"].ID

	query := ethereum.FilterQuery{
		FromBlock: new(big.Int).SetUint64(from),
		ToBlock:   new(big.Int).SetUint64(to),
		Addresses: []common.Address{c.factory},
		Topics: [][]common.Hash{
			{activatedID, deactivatedID},
			{common.BytesToHash(c.myAddr.Bytes())},
		},
	}
	logs, err := c.eth.FilterLogs(ctx, query)
	if err != nil {
		return fmt.Errorf("filter factory logs: %w", err)
	}

	for _, lg := range logs {
		if len(lg.Topics) < 3 {
			continue
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
	return nil
}

func (c *ChainClient) pollGroupEvents(ctx context.Context, grpAddr common.Address, from, to uint64) error {
	joinedID := c.grpABI.Events["NodeJoined"].ID
	removedID := c.grpABI.Events["NodeRemoved"].ID
	issuerAddedID := c.grpABI.Events["IssuerAdded"].ID
	issuerRemovedID := c.grpABI.Events["IssuerRemoved"].ID
	authKeyAddedID := c.grpABI.Events["AuthKeyAdded"].ID
	authKeyRemovedID := c.grpABI.Events["AuthKeyRemoved"].ID
	authResolverSetID := c.grpABI.Events["AuthResolverSet"].ID
	reshareRequestedID := c.grpABI.Events["ReshareRequested"].ID

	query := ethereum.FilterQuery{
		FromBlock: new(big.Int).SetUint64(from),
		ToBlock:   new(big.Int).SetUint64(to),
		Addresses: []common.Address{grpAddr},
		Topics:    [][]common.Hash{{joinedID, removedID, issuerAddedID, issuerRemovedID, authKeyAddedID, authKeyRemovedID, authResolverSetID, reshareRequestedID}},
	}
	logs, err := c.eth.FilterLogs(ctx, query)
	if err != nil {
		return fmt.Errorf("filter group logs: %w", err)
	}

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

	head, err := cl.BlockNumber(ctx)
	if err != nil {
		return false, zero, fmt.Errorf("chain %d head: %w", chainID, err)
	}
	if blockNum > head {
		return false, zero, fmt.Errorf("pinned block %d ahead of head %d", blockNum, head)
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
