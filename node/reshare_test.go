package node

import (
	"context"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"

	"signet/tss"
)

// mockKeyManager is a minimal KeyManager for unit-testing orchestration logic
// that doesn't need to actually run FROST rounds.
type mockKeyManager struct {
	keys map[string][]string // groupID → keyIDs
	mu   sync.Mutex

	// For tracking reshare calls in tests.
	reshareCalls   []ReshareParams
	reshareResult  *ReshareResult
	reshareErr     error
	reshareBlocked chan struct{} // if non-nil, RunReshare waits on this
}

func newMockKeyManager() *mockKeyManager {
	return &mockKeyManager{
		keys: make(map[string][]string),
	}
}

func (m *mockKeyManager) RunKeygen(ctx context.Context, p KeygenParams) (*KeyInfo, error) {
	m.mu.Lock()
	m.keys[p.GroupID] = append(m.keys[p.GroupID], p.KeyID)
	m.mu.Unlock()
	return &KeyInfo{PartyID: p.Host.Self()}, nil
}

func (m *mockKeyManager) RunSign(ctx context.Context, p SignParams) (*tss.Signature, error) {
	return &tss.Signature{}, nil
}

func (m *mockKeyManager) RunReshare(ctx context.Context, p ReshareParams) (*ReshareResult, error) {
	m.mu.Lock()
	m.reshareCalls = append(m.reshareCalls, p)
	blockCh := m.reshareBlocked
	m.mu.Unlock()

	if blockCh != nil {
		select {
		case <-blockCh:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	if m.reshareErr != nil {
		return nil, m.reshareErr
	}
	if m.reshareResult != nil {
		return m.reshareResult, nil
	}
	return &ReshareResult{OldOnly: false, Generation: 1}, nil
}

func (m *mockKeyManager) GetKeyInfo(groupID, keyID string, _ Curve) (*KeyInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, k := range m.keys[groupID] {
		if k == keyID {
			return &KeyInfo{}, nil
		}
	}
	return nil, nil
}

func (m *mockKeyManager) ListKeys(groupID string) ([]KeyEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]KeyEntry, len(m.keys[groupID]))
	for i, k := range m.keys[groupID] {
		out[i] = KeyEntry{KeyID: k, Curve: CurveSecp256k1}
	}
	return out, nil
}

func (m *mockKeyManager) ListGroups() ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, 0, len(m.keys))
	for g := range m.keys {
		out = append(out, g)
	}
	return out, nil
}

func (m *mockKeyManager) CommitReshare(groupID, keyID string, _ Curve) error               { return nil }
func (m *mockKeyManager) DiscardPendingReshare(groupID, keyID string, _ Curve) error       { return nil }
func (m *mockKeyManager) RollbackReshare(groupID, keyID string, _ Curve, gen uint64) error { return nil }
func (m *mockKeyManager) SetKeyStatus(groupID, keyID string, _ Curve, status string) error { return nil }
func (m *mockKeyManager) DeleteKey(groupID, keyID string, _ Curve) error                   { return nil }
func (m *mockKeyManager) Close() error                                                     { return nil }

var _ KeyManager = (*mockKeyManager)(nil)

// newTestNode builds a minimal Node with a mock key manager and reshare store
// for unit-testing orchestration logic. No libp2p, no HTTP, no chain client.
func newTestNode(t *testing.T) (*Node, *mockKeyManager) {
	t.Helper()
	km := newMockKeyManager()
	rs, err := NewReshareStore(openTestDB(t))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	n := &Node{
		log:    zap.NewNop(),
		ctx:    ctx,
		cancel: cancel,
		km:     km,
		groups: make(map[string]*GroupInfo),
	}
	n.initReshareState(rs)
	return n, km
}

// ---------- Orchestration unit tests ----------

func TestNode_CreateReshareJob(t *testing.T) {
	n, km := newTestNode(t)

	groupID := "0xgroup1"
	old := []tss.PartyID{"p1", "p2", "p3"}
	new_ := []tss.PartyID{"p1", "p2", "p3", "p4"}

	// Seed some keys.
	km.keys[groupID] = []string{"k1", "k2"}

	err := n.createReshareJob(groupID, "node_added", old, new_, 2)
	if err != nil {
		t.Fatal(err)
	}

	// Job is in memory.
	n.reshareJobsMu.RLock()
	job := n.reshareJobs[groupID]
	n.reshareJobsMu.RUnlock()
	if job == nil {
		t.Fatal("expected job in memory")
	}
	if len(job.KeysTotal) != 2 {
		t.Errorf("expected 2 keys, got %d", len(job.KeysTotal))
	}
	if len(job.OldParties) != 3 || len(job.NewParties) != 4 {
		t.Errorf("wrong parties: old=%d new=%d", len(job.OldParties), len(job.NewParties))
	}

	// Job is persisted.
	stored, _ := n.reshareStore.GetJob(groupID)
	if stored == nil {
		t.Fatal("expected job persisted")
	}
	if stored.EventType != "node_added" {
		t.Errorf("wrong event type: %s", stored.EventType)
	}
}

func TestNode_CreateReshareJob_NoKeys_NewOnlyNode(t *testing.T) {
	n, _ := newTestNode(t)

	// This node has no keys (new-only), but the old committee exists. A job
	// must still be created so the coord handler accepts incoming reshare
	// requests from the coordinator.
	err := n.createReshareJob("0xgroup1", "node_added",
		[]tss.PartyID{"p1"}, []tss.PartyID{"p1", "p2"}, 1)
	if err != nil {
		t.Fatal(err)
	}
	n.reshareJobsMu.RLock()
	defer n.reshareJobsMu.RUnlock()
	if n.reshareJobs["0xgroup1"] == nil {
		t.Fatal("expected job for new-only node with existing old committee")
	}
}

func TestNode_CreateReshareJob_NoKeys_NoOldParties(t *testing.T) {
	n, _ := newTestNode(t)

	// No keys and no old committee — nothing to do.
	err := n.createReshareJob("0xgroup1", "node_added",
		nil, []tss.PartyID{"p1", "p2"}, 1)
	if err != nil {
		t.Fatal(err)
	}
	n.reshareJobsMu.RLock()
	defer n.reshareJobsMu.RUnlock()
	if n.reshareJobs["0xgroup1"] != nil {
		t.Fatal("expected no job with no keys and no old committee")
	}
}

func TestNode_IsKeyStale(t *testing.T) {
	n, km := newTestNode(t)

	groupID := "0xgroup1"
	km.keys[groupID] = []string{"k1", "k2", "k3"}

	// No job — nothing is stale.
	if n.isKeyStale(groupID, "k1") {
		t.Error("expected not stale without job")
	}

	// Create job.
	_ = n.createReshareJob(groupID, "node_added",
		[]tss.PartyID{"p1", "p2"}, []tss.PartyID{"p1", "p2", "p3"}, 2)

	// All 3 keys should be stale.
	for _, k := range []string{"k1", "k2", "k3"} {
		if !n.isKeyStale(groupID, k) {
			t.Errorf("expected %s to be stale", k)
		}
	}

	// A key not in the job is not stale.
	if n.isKeyStale(groupID, "k4") {
		t.Error("expected k4 not stale (not in job)")
	}

	// Mark k2 as done — it should no longer be stale.
	_ = n.reshareStore.PutKeyDone(groupID, "k2", &ReshareKeyRecord{
		CompletedAt: time.Now(),
	})
	if n.isKeyStale(groupID, "k2") {
		t.Error("expected k2 not stale after marking done")
	}
	if !n.isKeyStale(groupID, "k1") {
		t.Error("expected k1 still stale")
	}
}

func TestNode_DeferMembershipEvent(t *testing.T) {
	n, km := newTestNode(t)

	groupID := "0xgroup1"
	km.keys[groupID] = []string{"k1"}

	// Create initial job.
	_ = n.createReshareJob(groupID, "node_added",
		[]tss.PartyID{"p1", "p2"}, []tss.PartyID{"p1", "p2", "p3"}, 2)

	// Defer a second event.
	if err := n.deferMembershipEvent(groupID, "node_removed", "0xaddr2", "p2"); err != nil {
		t.Fatal(err)
	}

	// Check deferred event was added.
	n.reshareJobsMu.RLock()
	job := n.reshareJobs[groupID]
	n.reshareJobsMu.RUnlock()
	if len(job.DeferredEvents) != 1 {
		t.Fatalf("expected 1 deferred event, got %d", len(job.DeferredEvents))
	}
	if job.DeferredEvents[0].EventType != "node_removed" {
		t.Errorf("wrong event type: %s", job.DeferredEvents[0].EventType)
	}

	// Persisted.
	stored, _ := n.reshareStore.GetJob(groupID)
	if len(stored.DeferredEvents) != 1 {
		t.Errorf("expected 1 deferred event persisted")
	}
}

func TestNode_DeferMembershipEvent_NoJob(t *testing.T) {
	n, _ := newTestNode(t)
	// Deferring with no job should error.
	if err := n.deferMembershipEvent("0xgroup1", "node_removed", "0xaddr", "p1"); err == nil {
		t.Fatal("expected error")
	}
}

func TestNode_CompleteReshareJob_NoDeferred(t *testing.T) {
	n, km := newTestNode(t)

	groupID := "0xgroup1"
	km.keys[groupID] = []string{"k1"}

	_ = n.createReshareJob(groupID, "node_added",
		[]tss.PartyID{"p1"}, []tss.PartyID{"p1", "p2"}, 1)

	// Mark all keys done and call completeReshareJob.
	_ = n.reshareStore.PutKeyDone(groupID, "k1", &ReshareKeyRecord{CompletedAt: time.Now()})
	n.completeReshareJob(groupID)

	// In-memory job removed.
	n.reshareJobsMu.RLock()
	job := n.reshareJobs[groupID]
	n.reshareJobsMu.RUnlock()
	if job != nil {
		t.Error("expected job removed")
	}

	// Persisted job deleted.
	stored, _ := n.reshareStore.GetJob(groupID)
	if stored != nil {
		t.Error("expected persisted job deleted")
	}

	// reshare_done cleared.
	count, _ := n.reshareStore.CountKeysDone(groupID)
	if count != 0 {
		t.Errorf("expected 0 done keys, got %d", count)
	}
}

// TestNode_CompleteReshareJob_WithDeferred exercises the scenario:
//
//   1. Group starts with {p1, p2, p3}
//   2. Event A: p4 added → reshare job created (old={p1,p2,p3}, new={p1,p2,p3,p4})
//   3. Event B: p2 removed while resharing → deferred
//   4. First reshare completes
//   5. New job created from deferred event: old must be {p1,p2,p3,p4} (the
//      committee that just produced shares), new must be {p1,p3,p4} (apply
//      p2 removal to old).
//
// This specifically catches the bug where oldParties was read from
// grp.Members (which has already had the deferred event applied).
func TestNode_CompleteReshareJob_WithDeferred(t *testing.T) {
	n, km := newTestNode(t)

	groupID := "0xgroup1"
	km.keys[groupID] = []string{"k1"}

	// grp.Members reflects the post-event state (the chain client
	// applies events before the reshare machinery sees them).
	// After both events, current membership = {p1, p3, p4}.
	n.groupsMu.Lock()
	n.groups[groupID] = &GroupInfo{
		Threshold: 2,
		Members:   []tss.PartyID{"p1", "p3", "p4"},
	}
	n.groupsMu.Unlock()

	// First job: p4 added. old = initial committee, new = initial ∪ {p4}.
	_ = n.createReshareJob(groupID, "node_added",
		[]tss.PartyID{"p1", "p2", "p3"},
		[]tss.PartyID{"p1", "p2", "p3", "p4"}, 2)

	// Defer p2 removal.
	_ = n.deferMembershipEvent(groupID, "node_removed", "0xaddr2", "p2")

	// Complete the current job.
	_ = n.reshareStore.PutKeyDone(groupID, "k1", &ReshareKeyRecord{CompletedAt: time.Now()})
	n.completeReshareJob(groupID)

	// A new job must now exist from the deferred event.
	n.reshareJobsMu.RLock()
	job := n.reshareJobs[groupID]
	n.reshareJobsMu.RUnlock()
	if job == nil {
		t.Fatal("expected new job from deferred event")
	}
	if job.EventType != "node_removed" {
		t.Errorf("wrong event type: %s", job.EventType)
	}
	if len(job.DeferredEvents) != 0 {
		t.Errorf("expected no remaining deferred events, got %d", len(job.DeferredEvents))
	}

	// Critical: OldParties must be the PREVIOUS job's NewParties
	// ({p1,p2,p3,p4}), not grp.Members ({p1,p3,p4}).
	expectedOld := map[tss.PartyID]bool{"p1": true, "p2": true, "p3": true, "p4": true}
	if len(job.OldParties) != 4 {
		t.Errorf("expected 4 old parties, got %d: %v", len(job.OldParties), job.OldParties)
	}
	for _, p := range job.OldParties {
		if !expectedOld[p] {
			t.Errorf("unexpected old party: %s", p)
		}
	}

	// NewParties = old with p2 removed = {p1,p3,p4}.
	expectedNew := map[tss.PartyID]bool{"p1": true, "p3": true, "p4": true}
	if len(job.NewParties) != 3 {
		t.Errorf("expected 3 new parties, got %d: %v", len(job.NewParties), job.NewParties)
	}
	for _, p := range job.NewParties {
		if !expectedNew[p] {
			t.Errorf("unexpected new party: %s", p)
		}
	}
}

// TestNode_CompleteReshareJob_MultipleDeferred exercises a chain of two
// deferred events: only the first is processed, the second remains in the
// new job's DeferredEvents list.
func TestNode_CompleteReshareJob_MultipleDeferred(t *testing.T) {
	n, km := newTestNode(t)

	groupID := "0xgroup1"
	km.keys[groupID] = []string{"k1"}

	n.groupsMu.Lock()
	n.groups[groupID] = &GroupInfo{
		Threshold: 2,
		Members:   []tss.PartyID{"p1", "p4", "p5"},
	}
	n.groupsMu.Unlock()

	// First job: add p4 to {p1,p2,p3}.
	_ = n.createReshareJob(groupID, "node_added",
		[]tss.PartyID{"p1", "p2", "p3"},
		[]tss.PartyID{"p1", "p2", "p3", "p4"}, 2)
	// Defer: remove p2, then remove p3, then add p5.
	_ = n.deferMembershipEvent(groupID, "node_removed", "0xaddr2", "p2")
	_ = n.deferMembershipEvent(groupID, "node_removed", "0xaddr3", "p3")
	_ = n.deferMembershipEvent(groupID, "node_added", "0xaddr5", "p5")

	// Complete current job.
	_ = n.reshareStore.PutKeyDone(groupID, "k1", &ReshareKeyRecord{CompletedAt: time.Now()})
	n.completeReshareJob(groupID)

	// New job must process only the first deferred event (remove p2).
	// Old = {p1,p2,p3,p4}, New = {p1,p3,p4}.
	n.reshareJobsMu.RLock()
	job := n.reshareJobs[groupID]
	n.reshareJobsMu.RUnlock()
	if job == nil {
		t.Fatal("expected new job")
	}
	if len(job.OldParties) != 4 {
		t.Errorf("expected 4 old parties, got %d: %v", len(job.OldParties), job.OldParties)
	}
	if len(job.NewParties) != 3 {
		t.Errorf("expected 3 new parties, got %d: %v", len(job.NewParties), job.NewParties)
	}
	// Remaining deferred events = {remove p3, add p5}
	if len(job.DeferredEvents) != 2 {
		t.Errorf("expected 2 remaining deferred events, got %d", len(job.DeferredEvents))
	}
	if job.DeferredEvents[0].PartyID != "p3" {
		t.Errorf("wrong remaining[0]: %s", job.DeferredEvents[0].PartyID)
	}
	if job.DeferredEvents[1].PartyID != "p5" {
		t.Errorf("wrong remaining[1]: %s", job.DeferredEvents[1].PartyID)
	}
}

// TestApplyMembershipEvent exercises the pure event-application helper.
func TestApplyMembershipEvent(t *testing.T) {
	members := []tss.PartyID{"a", "b", "c"}

	add := applyMembershipEvent(members, DeferredMembershipEvent{
		EventType: "node_added",
		PartyID:   "d",
	})
	if len(add) != 4 {
		t.Errorf("add: expected 4 members, got %d", len(add))
	}

	addDup := applyMembershipEvent(members, DeferredMembershipEvent{
		EventType: "node_added",
		PartyID:   "b",
	})
	if len(addDup) != 3 {
		t.Errorf("add duplicate: expected 3 members, got %d", len(addDup))
	}

	rem := applyMembershipEvent(members, DeferredMembershipEvent{
		EventType: "node_removed",
		PartyID:   "b",
	})
	if len(rem) != 2 {
		t.Errorf("remove: expected 2 members, got %d", len(rem))
	}
	for _, p := range rem {
		if p == "b" {
			t.Error("remove: b still present")
		}
	}

	remMissing := applyMembershipEvent(members, DeferredMembershipEvent{
		EventType: "node_removed",
		PartyID:   "z",
	})
	if len(remMissing) != 3 {
		t.Errorf("remove missing: expected 3 members, got %d", len(remMissing))
	}
}

func TestNode_TryRegisterReshareKey(t *testing.T) {
	n, _ := newTestNode(t)

	// First registration succeeds.
	if !n.tryRegisterReshareKey("g1", "k1") {
		t.Fatal("expected first register to succeed")
	}
	// Second registration fails.
	if n.tryRegisterReshareKey("g1", "k1") {
		t.Fatal("expected second register to fail")
	}

	// Different key works.
	if !n.tryRegisterReshareKey("g1", "k2") {
		t.Fatal("expected different key to register")
	}

	// Complete and re-register.
	n.completeReshareKey("g1", "k1", true)
	if !n.tryRegisterReshareKey("g1", "k1") {
		t.Fatal("expected re-register after complete")
	}
}

func TestNode_CompleteReshareKey_SignalsWaiters(t *testing.T) {
	n, _ := newTestNode(t)

	n.tryRegisterReshareKey("g1", "k1")

	var wg sync.WaitGroup
	waiterDone := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		// waitForReshare should return when the channel closes.
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = n.waitForReshare(ctx, "g1", "k1")
		close(waiterDone)
	}()

	// Give the goroutine time to enter the wait.
	time.Sleep(50 * time.Millisecond)

	// Complete the reshare — waiter should unblock.
	n.completeReshareKey("g1", "k1", true)

	select {
	case <-waiterDone:
		// ok
	case <-time.After(2 * time.Second):
		t.Fatal("waiter did not unblock")
	}
	wg.Wait()
}

// TestNode_RunReshareSession_ErrorClosesChannel verifies that when
// runReshareSession fails (at any point), it still closes the per-key
// channel so waiters do not hang. This is critical for coordinatorLoop,
// which spawns goroutines per key and does not call completeReshareKey
// on error.
func TestNode_RunReshareSession_ErrorClosesChannel(t *testing.T) {
	n, _ := newTestNode(t)

	groupID := "0xgroup1"
	// No job registered — runReshareSession will fail at the job lookup.
	// (We test this specific failure mode because it doesn't require a
	// real libp2p host.)

	// Register the key channel as a caller would.
	if !n.tryRegisterReshareKey(groupID, "k1") {
		t.Fatal("register failed")
	}

	// Verify channel exists before the call.
	n.reshareKeysMu.Lock()
	_, existed := n.reshareKeys[reshareKeyID{groupID, "k1"}]
	n.reshareKeysMu.Unlock()
	if !existed {
		t.Fatal("channel should exist before runReshareSession")
	}

	// Run the session — should fail immediately with "no reshare job".
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err := n.runReshareSession(ctx, groupID, "k1", CurveSecp256k1)
	if err == nil {
		t.Fatal("expected error")
	}

	// Channel must be cleaned up (deferred completeReshareKey).
	n.reshareKeysMu.Lock()
	_, stillExists := n.reshareKeys[reshareKeyID{groupID, "k1"}]
	n.reshareKeysMu.Unlock()
	if stillExists {
		t.Fatal("channel should have been cleaned up after error")
	}

	// A subsequent register should succeed (proves the slot is freed).
	if !n.tryRegisterReshareKey(groupID, "k1") {
		t.Fatal("expected re-register to succeed after error")
	}
}

func TestNode_StartCoordinator_NoJob(t *testing.T) {
	n, _ := newTestNode(t)

	err := n.startCoordinator("nonexistent", 1)
	if err == nil {
		t.Fatal("expected error for no job")
	}
}

func TestNode_StartCoordinator_Duplicate(t *testing.T) {
	n, km := newTestNode(t)

	groupID := "0xgroup1"
	km.keys[groupID] = []string{"k1"}
	// Block reshare indefinitely so we can test the duplicate coordinator case.
	km.reshareBlocked = make(chan struct{})
	defer close(km.reshareBlocked)

	n.groupsMu.Lock()
	n.groups[groupID] = &GroupInfo{Threshold: 1, Members: []tss.PartyID{"p1", "p2"}}
	n.groupsMu.Unlock()

	_ = n.createReshareJob(groupID, "node_added",
		[]tss.PartyID{"p1"}, []tss.PartyID{"p1", "p2"}, 1)

	// First start fails because runReshareSession will try to open a real session
	// network which requires a host — but we can still verify the flag gets set
	// by inspecting reshareCoord directly.
	n.reshareCoordMu.Lock()
	n.reshareCoord[groupID] = true
	n.reshareCoordMu.Unlock()

	// Second start attempt should fail with "already coordinating".
	err := n.startCoordinator(groupID, 1)
	if err == nil {
		t.Fatal("expected error for duplicate coordinator")
	}
}
