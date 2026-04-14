package node

import (
	"context"
	"fmt"
	"math/big"
	"reflect"
	"strings"
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
		{"name":"NodeJoined","type":"event","inputs":[{"name":"node","type":"address","indexed":true}],"anonymous":false},
		{"name":"NodeRemoved","type":"event","inputs":[{"name":"node","type":"address","indexed":true}],"anonymous":false},
		{"name":"IssuerAdded","type":"event","inputs":[{"name":"h","type":"bytes32","indexed":true},{"name":"issuer","type":"string","indexed":false},{"name":"clientIds","type":"string[]","indexed":false}],"anonymous":false},
		{"name":"IssuerRemoved","type":"event","inputs":[{"name":"h","type":"bytes32","indexed":true},{"name":"issuer","type":"string","indexed":false}],"anonymous":false},
		{"name":"AuthKeyAdded","type":"event","inputs":[{"name":"keyHash","type":"bytes32","indexed":true},{"name":"pubkey","type":"bytes","indexed":false}],"anonymous":false},
		{"name":"AuthKeyRemoved","type":"event","inputs":[{"name":"keyHash","type":"bytes32","indexed":true},{"name":"pubkey","type":"bytes","indexed":false}],"anonymous":false}
	]`

	defaultPollInterval = 12 * time.Second
)

// ChainClient watches the factory and group contracts for membership changes
// and keeps n.groups up to date.
type ChainClient struct {
	eth          *ethclient.Client
	factory      common.Address
	myAddr       common.Address
	factABI      abi.ABI
	grpABI       abi.ABI
	log          *zap.Logger
	n            *Node
	pollInterval time.Duration

	lastBlock uint64
	stopCh    chan struct{}
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

	return &ChainClient{
		eth:          eth,
		factory:      common.HexToAddress(cfg.FactoryAddress),
		myAddr:       common.Address(addr),
		factABI:      factABI,
		grpABI:       grpABI,
		log:          log,
		n:            n,
		pollInterval: poll,
		stopCh:       make(chan struct{}),
	}, nil
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

// close stops the polling loop and releases the eth client.
func (c *ChainClient) close() {
	close(c.stopCh)
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

	query := ethereum.FilterQuery{
		FromBlock: new(big.Int).SetUint64(from),
		ToBlock:   new(big.Int).SetUint64(to),
		Addresses: []common.Address{grpAddr},
		Topics:    [][]common.Hash{{joinedID, removedID, issuerAddedID, issuerRemovedID, authKeyAddedID, authKeyRemovedID}},
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
				// Group is ACTIVE: create reshare job and auto-start coordinator.
				if err := c.n.createReshareJob(hexGrp, eventType, oldMembers, newMembers, threshold); err != nil {
					c.log.Warn("chain: create reshare job",
						zap.String("group", hexGrp), zap.Error(err))
				} else if err := c.n.startCoordinator(hexGrp, 1); err != nil {
					// Non-fatal: another node may coordinate, or on-demand
					// reshare will handle it when a sign request arrives.
					c.log.Debug("chain: auto-start coordinator",
						zap.String("group", hexGrp), zap.Error(err))
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
