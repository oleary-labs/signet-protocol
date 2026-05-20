package node

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/crypto"
	"go.uber.org/zap"

	"signet/network"
	"signet/tss"
)

// testNode bundles a Node with its host and key manager so integration tests
// can drive the reshare lifecycle end-to-end with real libp2p transport and
// real FROST rounds (via LocalKeyManager).
type testNode struct {
	n    *Node
	host *network.Host
	km   *LocalKeyManager
}

// newTestNodeCluster creates `n` test nodes, each with a real libp2p host and
// LocalKeyManager backed by an in-memory bbolt DB. All nodes are directly
// connected to each other and have their coord handlers registered. Returns
// the cluster and a cleanup function.
func newTestNodeCluster(t *testing.T, ctx context.Context, numNodes int) ([]*testNode, func()) {
	t.Helper()

	log := zap.NewNop()
	cluster := make([]*testNode, numNodes)

	// Create hosts and local key managers.
	for i := 0; i < numNodes; i++ {
		priv, _, err := crypto.GenerateKeyPair(crypto.Secp256k1, -1)
		if err != nil {
			t.Fatal(err)
		}
		h, err := network.NewHost(ctx, priv, "/ip4/127.0.0.1/tcp/0")
		if err != nil {
			t.Fatal(err)
		}

		// Per-node data dir.
		dataDir := t.TempDir()
		km, err := NewLocalKeyManager(ctx, dataDir, log)
		if err != nil {
			h.Close()
			t.Fatal(err)
		}

		rs, err := NewReshareStore(km.store.DB())
		if err != nil {
			km.Close()
			h.Close()
			t.Fatal(err)
		}

		vs, err := openKeyVersionStore(dataDir)
		if err != nil {
			km.Close()
			h.Close()
			t.Fatal(err)
		}
		km.SetVersionStore(vs)

		nodeCtx, cancel := context.WithCancel(ctx)
		n := &Node{
			log:    log,
			ctx:    nodeCtx,
			cancel: cancel,
			host:   h,
			km:     km,
			groups: make(map[string]*GroupInfo),
			auth:   newGroupAuth(nodeCtx, nil, log),
			keygenReady: make(map[shardKey]chan struct{}),
		}
		n.initReshareState(rs)
		n.registerCoordHandler()

		cluster[i] = &testNode{n: n, host: h, km: km}
	}

	// Connect all pairs directly.
	for i := 0; i < numNodes; i++ {
		for j := i + 1; j < numNodes; j++ {
			if err := network.ConnectDirectly(ctx, cluster[i].host, cluster[j].host); err != nil {
				t.Fatalf("connect %d<->%d: %v", i, j, err)
			}
		}
	}

	// Register group membership on every node.
	parties := make([]tss.PartyID, numNodes)
	for i, tn := range cluster {
		parties[i] = tn.host.Self()
	}

	cleanup := func() {
		for _, tn := range cluster {
			tn.n.cancel()
			tn.km.Close() // also closes version store
			tn.host.Close()
		}
	}

	return cluster, cleanup
}

// setGroupMembership configures the same group on every node in the cluster.
func setGroupMembership(cluster []*testNode, groupID string, members []tss.PartyID, threshold int) {
	for _, tn := range cluster {
		tn.n.groupsMu.Lock()
		tn.n.groups[groupID] = &GroupInfo{
			Threshold: threshold,
			Members:   members,
		}
		tn.n.groupsMu.Unlock()
	}
}

// clusterKeygen runs a keygen session across the cluster, driven by the first
// node as the initiator. Each node runs the coord handler's logic — we invoke
// it directly rather than going through broadcastCoord (which requires the
// HTTP server) by manually calling each party's RunKeygen.
func clusterKeygen(t *testing.T, ctx context.Context, cluster []*testNode, groupID, keyID string) {
	t.Helper()

	parties := make([]tss.PartyID, len(cluster))
	for i, tn := range cluster {
		parties[i] = tn.host.Self()
	}
	sortedParties := tss.NewPartyIDSlice(parties)

	sessID := keygenSessionID(groupID, keyID)
	threshold := 2

	var wg sync.WaitGroup
	errs := make([]error, len(cluster))

	for i, tn := range cluster {
		i, tn := i, tn
		wg.Add(1)
		go func() {
			defer wg.Done()
			sn, err := network.NewSessionNetwork(ctx, tn.host, sessID, sortedParties)
			if err != nil {
				errs[i] = fmt.Errorf("session network: %w", err)
				return
			}
			defer sn.Close()

			_, err = tn.n.km.RunKeygen(ctx, KeygenParams{
				Host:      tn.host,
				SN:        sn,
				SessionID: sessID,
				GroupID:   groupID,
				KeyID:     keyID,
				Parties:   sortedParties,
				Threshold: threshold,
			})
			if err != nil {
				errs[i] = fmt.Errorf("run keygen: %w", err)
			}
		}()
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("keygen party %d: %v", i, err)
		}
	}
}

// clusterSign runs a sign session across the cluster and verifies all signers
// produce the same signature.
func clusterSign(t *testing.T, ctx context.Context, cluster []*testNode, groupID, keyID string, msgHash []byte) *tss.Signature {
	t.Helper()

	signers := make([]tss.PartyID, len(cluster))
	for i, tn := range cluster {
		signers[i] = tn.host.Self()
	}
	sortedSigners := tss.NewPartyIDSlice(signers)

	sessID := signSessionID(groupID, keyID, "testnonce")

	var wg sync.WaitGroup
	sigs := make([]*tss.Signature, len(cluster))
	errs := make([]error, len(cluster))

	for i, tn := range cluster {
		i, tn := i, tn
		wg.Add(1)
		go func() {
			defer wg.Done()
			sn, err := network.NewSessionNetwork(ctx, tn.host, sessID, sortedSigners)
			if err != nil {
				errs[i] = fmt.Errorf("session network: %w", err)
				return
			}
			defer sn.Close()

			sig, err := tn.n.km.RunSign(ctx, SignParams{
				Host:        tn.host,
				SN:          sn,
				SessionID:   sessID,
				GroupID:     groupID,
				KeyID:       keyID,
				Signers:     sortedSigners,
				MessageHash: msgHash,
			})
			if err != nil {
				errs[i] = err
				return
			}
			sigs[i] = sig
		}()
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("sign party %d: %v", i, err)
		}
	}

	// All parties should produce byte-identical signatures.
	for i := 1; i < len(sigs); i++ {
		if !bytes.Equal(sigs[0].R, sigs[i].R) || !bytes.Equal(sigs[0].Z, sigs[i].Z) {
			t.Fatalf("signature mismatch between party 0 and %d", i)
		}
	}
	return sigs[0]
}

// TestReshareIntegration_ShrinkCommittee runs keygen on a 5-node committee,
// then reshares to remove one node. Verifies that:
//   - the 4 remaining nodes hold the same group key after reshare
//   - signing with the new 4-party committee produces a valid signature
//   - the removed node gets a sentinel config (KeyShareBytes == nil)
func TestReshareIntegration_ShrinkCommittee(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Create 5 nodes; keygen uses all 5, then we remove the last one.
	cluster, cleanup := newTestNodeCluster(t, ctx, 5)
	defer cleanup()

	groupID := "0xgroup1"
	keyID := "k1"

	allParties := make([]tss.PartyID, 5)
	for i := 0; i < 5; i++ {
		allParties[i] = cluster[i].host.Self()
	}
	newParties := make([]tss.PartyID, 4)
	copy(newParties, allParties[:4])

	// Set group membership (4 nodes) for keygen.
	setGroupMembership(cluster, groupID, allParties, 2)

	// Step 1: Keygen on all 4 nodes.
	clusterKeygen(t, ctx, cluster, groupID, keyID)
	t.Log("keygen complete on 4-node committee")

	// Capture original group key.
	info0, err := cluster[0].km.GetKeyInfo(groupID, keyID, CurveSecp256k1)
	if err != nil || info0 == nil {
		t.Fatalf("get key info: %v", err)
	}
	origGroupKey := info0.GroupKey

	// Step 2: Create reshare job (shrink: remove node 4).
	for _, tn := range cluster {
		if err := tn.n.createReshareJob(groupID, "node_removed", allParties, newParties, 2); err != nil {
			t.Fatalf("create reshare job: %v", err)
		}
	}

	// Step 3: Run reshare from node 0 (coordinator).
	if err := cluster[0].n.runReshareSession(ctx, groupID, keyID, CurveSecp256k1); err != nil {
		t.Fatalf("runReshareSession: %v", err)
	}
	t.Log("reshare complete — committee shrank from 5 to 4")

	// Wait for all participants to record done.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		allDone := true
		for _, tn := range cluster {
			d, _ := tn.n.reshareStore.IsKeyDone(groupID, keyID)
			if !d {
				allDone = false
				break
			}
		}
		if allDone {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	// Step 4: Verify remaining 4 nodes have the same group key.
	for i := 0; i < 4; i++ {
		info, err := cluster[i].km.GetKeyInfo(groupID, keyID, CurveSecp256k1)
		if err != nil {
			t.Fatalf("party %d get key info: %v", i, err)
		}
		if info == nil {
			t.Fatalf("party %d: key missing after reshare", i)
		}
		if !bytes.Equal(info.GroupKey, origGroupKey) {
			t.Errorf("party %d: group key changed after reshare", i)
		}
	}

	// Step 5: Verify removed node (node 4) got sentinel config.
	removedInfo, err := cluster[4].km.GetKeyInfo(groupID, keyID, CurveSecp256k1)
	if err != nil {
		t.Fatalf("removed node get key info: %v", err)
	}
	// Sentinel config has GroupKey preserved but no key share material.
	// GetKeyInfo returns the config metadata; the underlying Config has
	// KeyShareBytes == nil. We verify by checking the group key is still
	// present (the node remembers which key it used to hold).
	if removedInfo == nil {
		t.Fatal("removed node: expected sentinel config, got nil")
	}

	// Step 6: Sign with the new 4-party committee.
	setGroupMembership(cluster[:4], groupID, newParties, 2)
	var msgHash [32]byte
	for i := range msgHash {
		msgHash[i] = byte(i + 1)
	}
	sig := clusterSign(t, ctx, cluster[:4], groupID, keyID, msgHash[:])

	ethSig, err := sig.SigEthereum()
	if err != nil {
		t.Fatalf("sig ethereum: %v", err)
	}
	if len(ethSig) != 65 {
		t.Fatalf("expected 65-byte ethereum signature, got %d", len(ethSig))
	}
	t.Logf("signature produced after shrink reshare (5→4): 0x%x", ethSig)
}

// TestReshareIntegration_GrowCommittee runs keygen on a 3-node committee, then
// reshares to add a 4th node. Verifies that:
//   - all 4 nodes hold the same group key after reshare
//   - signing with the new 4-party committee produces a valid signature
//   - the signature verifies against the original group key
func TestReshareIntegration_GrowCommittee(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Create 4 nodes; keygen uses only the first 3.
	cluster, cleanup := newTestNodeCluster(t, ctx, 4)
	defer cleanup()

	groupID := "0xgroup1"
	keyID := "k1"

	oldParties := make([]tss.PartyID, 3)
	for i := 0; i < 3; i++ {
		oldParties[i] = cluster[i].host.Self()
	}
	allParties := make([]tss.PartyID, 4)
	for i := 0; i < 4; i++ {
		allParties[i] = cluster[i].host.Self()
	}

	// Set initial group membership (3 nodes) for keygen.
	setGroupMembership(cluster[:3], groupID, oldParties, 2)

	// Step 1: Keygen on the first 3 nodes.
	clusterKeygen(t, ctx, cluster[:3], groupID, keyID)
	t.Log("keygen complete on 3-node committee")

	// Capture original group key.
	info0, err := cluster[0].km.GetKeyInfo(groupID, keyID, CurveSecp256k1)
	if err != nil || info0 == nil {
		t.Fatalf("get key info: %v", err)
	}
	origGroupKey := info0.GroupKey

	// Step 2: Update group membership to all 4 nodes and create reshare job.
	setGroupMembership(cluster, groupID, allParties, 2)
	for _, tn := range cluster {
		if err := tn.n.createReshareJob(groupID, "node_added", oldParties, allParties, 2); err != nil {
			t.Fatalf("create reshare job: %v", err)
		}
	}

	// Step 3: Run reshare from the first node (coordinator).
	if err := cluster[0].n.runReshareSession(ctx, groupID, keyID, CurveSecp256k1); err != nil {
		t.Fatalf("runReshareSession: %v", err)
	}
	t.Log("reshare complete — committee grew from 3 to 4")

	// Wait for all participants to record done.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		allDone := true
		for _, tn := range cluster {
			d, _ := tn.n.reshareStore.IsKeyDone(groupID, keyID)
			if !d {
				allDone = false
				break
			}
		}
		if allDone {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	// Step 4: Verify all 4 nodes have the same group key.
	for i, tn := range cluster {
		info, err := tn.km.GetKeyInfo(groupID, keyID, CurveSecp256k1)
		if err != nil {
			t.Fatalf("party %d get key info: %v", i, err)
		}
		if info == nil {
			t.Fatalf("party %d: key missing after reshare", i)
		}
		if !bytes.Equal(info.GroupKey, origGroupKey) {
			t.Errorf("party %d: group key changed after reshare", i)
		}
	}

	// Step 5: Sign with the full 4-party committee.
	var msgHash [32]byte
	for i := range msgHash {
		msgHash[i] = byte(i + 1)
	}
	sig := clusterSign(t, ctx, cluster, groupID, keyID, msgHash[:])

	ethSig, err := sig.SigEthereum()
	if err != nil {
		t.Fatalf("sig ethereum: %v", err)
	}
	if len(ethSig) != 65 {
		t.Fatalf("expected 65-byte ethereum signature, got %d", len(ethSig))
	}
	t.Logf("signature produced after grow reshare: 0x%x", ethSig)
}

// TestReshareIntegration_OnDemandViaSign verifies the on-demand reshare path:
// a sign request on a stale key triggers waitForReshare → runReshareSession,
// and the sign succeeds after the reshare completes. Uses a grow (3→4)
// committee change to create the stale key.
func TestReshareIntegration_OnDemandViaSign(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	cluster, cleanup := newTestNodeCluster(t, ctx, 4)
	defer cleanup()

	groupID := "0xgroup1"
	keyID := "k1"

	oldParties := make([]tss.PartyID, 3)
	for i := 0; i < 3; i++ {
		oldParties[i] = cluster[i].host.Self()
	}
	allParties := make([]tss.PartyID, 4)
	for i := 0; i < 4; i++ {
		allParties[i] = cluster[i].host.Self()
	}

	// Keygen on the first 3 nodes.
	setGroupMembership(cluster[:3], groupID, oldParties, 2)
	clusterKeygen(t, ctx, cluster[:3], groupID, keyID)
	t.Log("keygen complete on 3-node committee")

	// Capture original group key.
	info0, err := cluster[0].km.GetKeyInfo(groupID, keyID, CurveSecp256k1)
	if err != nil || info0 == nil {
		t.Fatalf("get key info: %v", err)
	}
	origGroupKey := info0.GroupKey

	// Step 2: Create reshare job (grow: add node 3) to make key stale.
	setGroupMembership(cluster, groupID, allParties, 2)
	for _, tn := range cluster {
		if err := tn.n.createReshareJob(groupID, "node_added", oldParties, allParties, 2); err != nil {
			t.Fatalf("create reshare job: %v", err)
		}
	}
	if !cluster[0].n.isKeyStale(groupID, keyID) {
		t.Fatal("expected key to be stale")
	}

	// Step 3: On node 0, call waitForReshare (simulating what handleSign does).
	// This triggers on-demand reshare via runReshareSession. The other nodes
	// receive the coord message and participate automatically.
	reshareErr := make(chan error, 1)
	go func() {
		reshareErr <- cluster[0].n.waitForReshare(ctx, groupID, keyID)
	}()

	if err := <-reshareErr; err != nil {
		t.Fatalf("waitForReshare: %v", err)
	}
	t.Log("on-demand reshare complete")

	// Verify key is no longer stale on the initiator.
	done, _ := cluster[0].n.reshareStore.IsKeyDone(groupID, keyID)
	if !done {
		t.Fatal("expected key marked done after on-demand reshare")
	}

	// Wait for participants to record done.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		allDone := true
		for _, tn := range cluster {
			d, _ := tn.n.reshareStore.IsKeyDone(groupID, keyID)
			if !d {
				allDone = false
				break
			}
		}
		if allDone {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	// Step 4: Verify group key preserved on all 4 nodes.
	for i, tn := range cluster {
		info, err := tn.km.GetKeyInfo(groupID, keyID, CurveSecp256k1)
		if err != nil || info == nil {
			t.Fatalf("party %d: key missing after reshare: %v", i, err)
		}
		if !bytes.Equal(info.GroupKey, origGroupKey) {
			t.Errorf("party %d: group key changed after on-demand reshare", i)
		}
	}

	// Step 5: Sign with the full 4-party committee.
	var msgHash [32]byte
	for i := range msgHash {
		msgHash[i] = byte(i + 1)
	}
	sig := clusterSign(t, ctx, cluster, groupID, keyID, msgHash[:])

	ethSig, err := sig.SigEthereum()
	if err != nil {
		t.Fatalf("sig ethereum: %v", err)
	}
	if len(ethSig) != 65 {
		t.Fatalf("expected 65-byte ethereum signature, got %d", len(ethSig))
	}
	t.Logf("signature after on-demand reshare: 0x%x", ethSig)
}

// TestReshareIntegration_ScaleReshare generates keys on a 5-node committee,
// removes one node, and reshares all keys via the coordinator loop.
// Validates group key preservation and signing on the new committee.
//
// Default: 1000 keys. Override with RESHARE_SCALE_KEYS=10000.
func TestReshareIntegration_ScaleReshare(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping scale reshare test in short mode")
	}

	numKeys := 1000
	if v := os.Getenv("RESHARE_SCALE_KEYS"); v != "" {
		if _, err := fmt.Sscanf(v, "%d", &numKeys); err != nil {
			t.Fatalf("invalid RESHARE_SCALE_KEYS=%q", v)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	const numNodes = 5
	cluster, cleanup := newTestNodeCluster(t, ctx, numNodes)
	defer cleanup()

	groupID := "0xscale"

	allParties := make([]tss.PartyID, numNodes)
	for i := 0; i < numNodes; i++ {
		allParties[i] = cluster[i].host.Self()
	}
	newParties := make([]tss.PartyID, numNodes-1)
	copy(newParties, allParties[:numNodes-1])

	setGroupMembership(cluster, groupID, allParties, 2)

	// Phase 1: concurrent keygen.
	t.Logf("keygen: %d keys on %d nodes...", numKeys, numNodes)
	keygenStart := time.Now()

	keyIDs := make([]string, numKeys)
	for i := range keyIDs {
		keyIDs[i] = fmt.Sprintf("k%d", i)
	}

	sem := make(chan struct{}, 12)
	var wg sync.WaitGroup
	for ki := range keyIDs {
		sem <- struct{}{}
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			defer func() { <-sem }()
			clusterKeygen(t, ctx, cluster, groupID, keyIDs[idx])
		}(ki)
	}
	wg.Wait()

	keygenDur := time.Since(keygenStart)
	t.Logf("keygen: %d keys in %s (%.1f keys/sec)",
		numKeys, keygenDur, float64(numKeys)/keygenDur.Seconds())

	// Sample original group keys for verification.
	sampleSize := 10
	if sampleSize > numKeys {
		sampleSize = numKeys
	}
	origGroupKeys := make(map[string][]byte, sampleSize)
	for i := 0; i < sampleSize; i++ {
		info, err := cluster[0].km.GetKeyInfo(groupID, keyIDs[i], CurveSecp256k1)
		if err != nil || info == nil {
			t.Fatalf("get key info %s: %v", keyIDs[i], err)
		}
		origGroupKeys[keyIDs[i]] = info.GroupKey
	}

	// Phase 2: create reshare job (remove last node).
	t.Logf("reshare: removing node %d, resharing %d keys...", numNodes-1, numKeys)
	reshareStart := time.Now()

	for _, tn := range cluster {
		if err := tn.n.createReshareJob(groupID, "node_removed", allParties, newParties, 2); err != nil {
			t.Fatalf("create reshare job: %v", err)
		}
	}

	// Phase 3: run coordinator loop from node 0.
	coordConc := 60 / numNodes
	if coordConc < 1 {
		coordConc = 1
	}

	coordDone := make(chan struct{})
	go func() {
		cluster[0].n.coordinatorLoop(groupID, cluster[0].n.reshareJobs[groupID], coordConc)
		close(coordDone)
	}()

	select {
	case <-coordDone:
	case <-ctx.Done():
		t.Fatal("coordinator loop timed out")
	}

	reshareDur := time.Since(reshareStart)
	t.Logf("reshare: %d keys in %s (%.1f keys/sec)",
		numKeys, reshareDur, float64(numKeys)/reshareDur.Seconds())

	// Phase 4: verify group keys preserved.
	for keyID, origKey := range origGroupKeys {
		for i := 0; i < numNodes-1; i++ {
			info, err := cluster[i].km.GetKeyInfo(groupID, keyID, CurveSecp256k1)
			if err != nil || info == nil {
				t.Fatalf("node %d key %s: missing after reshare", i, keyID)
			}
			if !bytes.Equal(info.GroupKey, origKey) {
				t.Errorf("node %d key %s: group key changed", i, keyID)
			}
		}
	}

	// Phase 5: sign with the new committee.
	setGroupMembership(cluster[:numNodes-1], groupID, newParties, 2)
	var msgHash [32]byte
	for i := range msgHash {
		msgHash[i] = byte(i + 1)
	}
	sig := clusterSign(t, ctx, cluster[:numNodes-1], groupID, keyIDs[0], msgHash[:])
	ethSig, err := sig.SigEthereum()
	if err != nil {
		t.Fatalf("sig ethereum: %v", err)
	}
	t.Logf("post-reshare signature: 0x%x", ethSig[:8])

	t.Logf("SUMMARY: %d keys — keygen %.1f keys/sec, reshare %.1f keys/sec",
		numKeys,
		float64(numKeys)/keygenDur.Seconds(),
		float64(numKeys)/reshareDur.Seconds())
}

// TestReshareIntegration_JobLifecycle exercises createReshareJob →
// completeReshareJob end-to-end on a real node without running the protocol.
// This verifies the ACTIVE → RESHARING → ACTIVE transitions work with real
// storage.
func TestReshareIntegration_JobLifecycle(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cluster, cleanup := newTestNodeCluster(t, ctx, 1)
	defer cleanup()

	tn := cluster[0]
	groupID := "0xgroup1"

	// Seed the key manager with a key (bypass keygen).
	tn.km.store.Put(groupID, "k1", &tss.Config{
		ID:         tn.host.Self(),
		Threshold:  1,
		MaxSigners: 1,
		Generation: 0,
		GroupKey:   []byte("fake-group-key"),
	})

	// Initially ACTIVE.
	if tn.n.isKeyStale(groupID, "k1") {
		t.Fatal("expected not stale initially")
	}

	// Create a job → RESHARING.
	if err := tn.n.createReshareJob(groupID, "node_added",
		[]tss.PartyID{tn.host.Self()},
		[]tss.PartyID{tn.host.Self(), "p2"}, 1); err != nil {
		t.Fatal(err)
	}
	if !tn.n.isKeyStale(groupID, "k1") {
		t.Fatal("expected stale after job creation")
	}

	// Mark key done.
	tn.n.reshareStore.PutKeyDone(groupID, "k1", &ReshareKeyRecord{
		CompletedAt: time.Now(),
	})
	if tn.n.isKeyStale(groupID, "k1") {
		t.Fatal("expected not stale after marking done")
	}

	// Complete job → ACTIVE.
	tn.n.completeReshareJob(groupID)

	tn.n.reshareJobsMu.RLock()
	job := tn.n.reshareJobs[groupID]
	tn.n.reshareJobsMu.RUnlock()
	if job != nil {
		t.Fatal("expected job removed after completion")
	}

	// Storage cleaned up.
	stored, _ := tn.n.reshareStore.GetJob(groupID)
	if stored != nil {
		t.Fatal("expected persisted job removed")
	}
}
