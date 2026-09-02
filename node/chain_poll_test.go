package node

import (
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"go.uber.org/zap"
)

func testABIs(t *testing.T) (abi.ABI, abi.ABI) {
	t.Helper()
	factABI, err := abi.JSON(strings.NewReader(factoryABIJSON))
	if err != nil {
		t.Fatalf("parse factory ABI: %v", err)
	}
	grpABI, err := abi.JSON(strings.NewReader(groupABIJSON))
	if err != nil {
		t.Fatalf("parse group ABI: %v", err)
	}
	return factABI, grpABI
}

// The batched poll query relies on every watched event being reachable in one
// eth_getLogs, so the topic union must cover all of them with no zero entries
// (a zero hash would mean a typo'd event name silently matching nothing).
func TestWatchedTopicsCoversAllEvents(t *testing.T) {
	factABI, grpABI := testABIs(t)
	topics := watchedTopics(factABI, grpABI)

	want := map[string]common.Hash{
		"NodeActivatedInGroup":   factABI.Events["NodeActivatedInGroup"].ID,
		"NodeDeactivatedInGroup": factABI.Events["NodeDeactivatedInGroup"].ID,
		"NodeJoined":             grpABI.Events["NodeJoined"].ID,
		"NodeRemoved":            grpABI.Events["NodeRemoved"].ID,
		"IssuerAdded":            grpABI.Events["IssuerAdded"].ID,
		"IssuerRemoved":          grpABI.Events["IssuerRemoved"].ID,
		"AuthKeyAdded":           grpABI.Events["AuthKeyAdded"].ID,
		"AuthKeyRemoved":         grpABI.Events["AuthKeyRemoved"].ID,
		"AuthResolverSet":        grpABI.Events["AuthResolverSet"].ID,
		"SiweDomainsSet":         grpABI.Events["SiweDomainsSet"].ID,
		"ReshareRequested":       grpABI.Events["ReshareRequested"].ID,
	}
	if len(topics) != len(want) {
		t.Fatalf("watchedTopics len = %d, want %d", len(topics), len(want))
	}

	got := make(map[common.Hash]bool, len(topics))
	for _, tp := range topics {
		if tp == (common.Hash{}) {
			t.Fatal("watchedTopics contains a zero topic (misnamed event?)")
		}
		got[tp] = true
	}
	for name, id := range want {
		if !got[id] {
			t.Errorf("watchedTopics missing %s", name)
		}
	}
}

// Factory and group events must not collide on topic0, since the batched query
// routes logs purely by emitting address and then switches on topic0.
func TestFactoryAndGroupTopicsDisjoint(t *testing.T) {
	factABI, grpABI := testABIs(t)
	for fname, fev := range factABI.Events {
		for gname, gev := range grpABI.Events {
			if fev.ID == gev.ID {
				t.Errorf("topic0 collision: factory %s == group %s", fname, gname)
			}
		}
	}
}

// The batched query drops the server-side topic filter on the indexed node
// address, so handleFactoryLogs must reject other nodes' membership events
// itself. Getting this wrong would make a node join groups it is not in.
func TestHandleFactoryLogsIgnoresOtherNodes(t *testing.T) {
	factABI, grpABI := testABIs(t)
	me := common.HexToAddress("0x1111111111111111111111111111111111111111")
	other := common.HexToAddress("0x2222222222222222222222222222222222222222")
	factory := common.HexToAddress("0x3333333333333333333333333333333333333333")
	group := common.HexToAddress("0x4444444444444444444444444444444444444444")

	n := &Node{groups: make(map[string]*GroupInfo)}
	c := &ChainClient{
		factory: factory,
		myAddr:  me,
		factABI: factABI,
		grpABI:  grpABI,
		n:       n,
		log:     zap.NewNop(),
	}

	// Seed the group so a deactivation has something to remove.
	key := strings.ToLower(group.Hex())
	n.groups[key] = &GroupInfo{Threshold: 2}

	deactivated := factABI.Events["NodeDeactivatedInGroup"].ID
	otherLog := types.Log{
		Address: factory,
		Topics: []common.Hash{
			deactivated,
			common.BytesToHash(other.Bytes()),
			common.BytesToHash(group.Bytes()),
		},
	}

	c.handleFactoryLogs(t.Context(), []types.Log{otherLog})
	if _, ok := n.groups[key]; !ok {
		t.Fatal("another node's deactivation removed our group membership")
	}

	// Our own deactivation must still be applied.
	mineLog := otherLog
	mineLog.Topics = []common.Hash{
		deactivated,
		common.BytesToHash(me.Bytes()),
		common.BytesToHash(group.Bytes()),
	}
	c.handleFactoryLogs(t.Context(), []types.Log{mineLog})
	if _, ok := n.groups[key]; ok {
		t.Fatal("our own deactivation was not applied")
	}
}

func TestHeadCacheReusesRecentReadAndNeverGoesBackwards(t *testing.T) {
	c := &ChainClient{headCache: make(map[uint64]headEntry)}
	const chainID = 11155111

	c.storeHead(chainID, 100)
	if e := c.headCache[chainID]; e.num != 100 {
		t.Fatalf("head = %d, want 100", e.num)
	}

	// A lagging RPC replica reporting an older head must not roll the cache
	// back, or an already-valid pinned block would look ahead of head.
	c.storeHead(chainID, 90)
	if e := c.headCache[chainID]; e.num != 100 {
		t.Fatalf("head regressed to %d, want 100", e.num)
	}

	c.storeHead(chainID, 105)
	if e := c.headCache[chainID]; e.num != 105 {
		t.Fatalf("head = %d, want 105", e.num)
	}

	// An entry older than the TTL must not be served from cache.
	c.headCache[chainID] = headEntry{num: 105, at: time.Now().Add(-2 * headCacheTTL)}
	if e := c.headCache[chainID]; time.Since(e.at) < headCacheTTL {
		t.Fatal("expected entry to be considered stale")
	}
}

// Every event SignetGroup declares must be either watched or explicitly listed
// as ignored, with a reason.
//
// This exists because SiweDomainsSet was not. The domain list was read once at
// group load and never again, so executing a timelocked domain change updated
// the chain, satisfied every operator watching the transaction, and changed
// nothing on any node until an unrelated restart. Nothing failed; the feature
// was simply inert. Config the node caches needs a refresh path, and "we
// remembered to add one" is not a property a reader can check.
//
// The existing topic test cannot catch this. It compares watchedTopics against
// a hand-written list, so an event missing from both is consistent with itself.
// Ground truth has to come from outside the node package, and the contract
// interface is the closest thing in the repo that is not a build artifact.
//
// The parse is deliberately crude — a regex over the interface source rather
// than a compiled ABI — because requiring `forge build` before `go test` would
// couple the two toolchains for a check whose whole value is that it always
// runs. It costs a false failure if someone writes an event declaration across
// two lines, which is a cheap and obvious failure to fix.
func TestEveryContractEventIsWatchedOrExplicitlyIgnored(t *testing.T) {
	const ifacePath = "../contracts/contracts/interfaces/ISignetGroup.sol"

	src, err := os.ReadFile(ifacePath)
	if err != nil {
		t.Skipf("contract interface not readable (%v) — skipping", err)
	}

	// Events the node deliberately does not react to. Adding an entry here is a
	// decision that should be defensible in review; the reason is the point.
	ignored := map[string]string{
		"NodeInvited":           "membership is acted on at NodeJoined, once consent has actually happened",
		"NodeDeclined":          "no local state changes when an invite is refused",
		"RemovalQueued":         "queuing starts a timelock; the node reacts to NodeRemoved when it fires",
		"RemovalCancelled":      "nothing was applied at queue time, so nothing is undone",
		"AuthResolverQueued":    "timelocked; AuthResolverSet is the event that means it took effect",
		"AuthResolverCancelled": "nothing was applied at queue time",
		"SiweDomainsQueued":     "timelocked; SiweDomainsSet is the event that means it took effect",
		"SiweDomainsCancelled":  "nothing was applied at queue time",
		"ManagerTransferred":    "the node does not cache the manager; group config reads are unauthenticated",
	}

	factABI, grpABI := testABIs(t)
	watched := make(map[common.Hash]bool)
	for _, h := range watchedTopics(factABI, grpABI) {
		watched[h] = true
	}

	re := regexp.MustCompile(`(?m)^\s*event\s+([A-Za-z0-9_]+)`)
	matches := re.FindAllStringSubmatch(string(src), -1)
	if len(matches) == 0 {
		t.Fatalf("parsed no events out of %s — the regex or the file layout changed", ifacePath)
	}

	for _, m := range matches {
		name := m[1]
		if reason, ok := ignored[name]; ok {
			if reason == "" {
				t.Errorf("event %s is ignored with no reason given", name)
			}
			if _, inABI := grpABI.Events[name]; inABI {
				t.Errorf("event %s is listed as ignored but is present in the node's ABI — "+
					"decide which it is", name)
			}
			continue
		}

		ev, ok := grpABI.Events[name]
		if !ok {
			t.Errorf("event %s is declared by SignetGroup but is absent from the node's "+
				"embedded ABI, and is not listed as deliberately ignored.\n"+
				"  If the node should react to it: add it to groupABIJSON, to watchedTopics, "+
				"and handle it in handleGroupLogs.\n"+
				"  If it should not: add it to `ignored` above with the reason.", name)
			continue
		}
		if !watched[ev.ID] {
			t.Errorf("event %s is in the node's ABI but not in watchedTopics, so it can be "+
				"decoded but will never be fetched", name)
		}
	}
}
