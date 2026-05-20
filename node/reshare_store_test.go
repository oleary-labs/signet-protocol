package node

import (
	"path/filepath"
	"testing"
	"time"

	"signet/tss"

	"go.etcd.io/bbolt"
)

func openTestDB(t *testing.T) *bbolt.DB {
	t.Helper()
	dir := t.TempDir()
	db, err := bbolt.Open(filepath.Join(dir, "test.db"), 0600, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestReshareStore_JobLifecycle(t *testing.T) {
	rs, err := NewReshareStore(openTestDB(t))
	if err != nil {
		t.Fatal(err)
	}

	groupID := "0xgroup1"

	// No job initially.
	job, err := rs.GetJob(groupID)
	if err != nil {
		t.Fatal(err)
	}
	if job != nil {
		t.Fatal("expected no job")
	}

	// Create a job.
	now := time.Now().Truncate(time.Second)
	j := &ReshareJob{
		GroupID:      groupID,
		OldParties:   []tss.PartyID{"p1", "p2", "p3"},
		NewParties:   []tss.PartyID{"p2", "p3", "p4"},
		OldThreshold: 2,
		NewThreshold: 2,
		KeysTotal:    []KeyEntry{{KeyID: "k1", Curve: CurveSecp256k1}, {KeyID: "k2", Curve: CurveSecp256k1}, {KeyID: "k3", Curve: CurveSecp256k1}},
		StartedAt:    now,
		EventType:    "node_added",
	}
	if err := rs.PutJob(j); err != nil {
		t.Fatal(err)
	}

	// Read it back.
	got, err := rs.GetJob(groupID)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("expected job")
	}
	if len(got.OldParties) != 3 || got.OldParties[0] != "p1" {
		t.Fatalf("wrong old parties: %v", got.OldParties)
	}
	if len(got.KeysTotal) != 3 {
		t.Fatalf("wrong keys total: %v", got.KeysTotal)
	}

	// ListJobs returns it.
	groups, err := rs.ListJobs()
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 1 || groups[0] != groupID {
		t.Fatalf("expected [%s], got %v", groupID, groups)
	}

	// Update with deferred event.
	j.DeferredEvents = append(j.DeferredEvents, DeferredMembershipEvent{
		EventType:  "node_removed",
		NodeAddr:   "0xaddr2",
		DetectedAt: now,
	})
	if err := rs.PutJob(j); err != nil {
		t.Fatal(err)
	}
	got, _ = rs.GetJob(groupID)
	if len(got.DeferredEvents) != 1 {
		t.Fatalf("expected 1 deferred event, got %d", len(got.DeferredEvents))
	}

	// Delete.
	if err := rs.DeleteJob(groupID); err != nil {
		t.Fatal(err)
	}
	got, _ = rs.GetJob(groupID)
	if got != nil {
		t.Fatal("expected nil after delete")
	}
}

func TestReshareStore_KeyDoneLifecycle(t *testing.T) {
	rs, err := NewReshareStore(openTestDB(t))
	if err != nil {
		t.Fatal(err)
	}

	groupID := "0xgroup1"

	// Not done initially.
	done, err := rs.IsKeyDone(groupID, "k1")
	if err != nil {
		t.Fatal(err)
	}
	if done {
		t.Fatal("expected not done")
	}

	count, _ := rs.CountKeysDone(groupID)
	if count != 0 {
		t.Fatalf("expected 0, got %d", count)
	}

	// Mark k1 done.
	rec := &ReshareKeyRecord{
		CompletedAt: time.Now(),
		ByNode:      "node1",
		OldOnly:     false,
	}
	if err := rs.PutKeyDone(groupID, "k1", rec); err != nil {
		t.Fatal(err)
	}

	done, _ = rs.IsKeyDone(groupID, "k1")
	if !done {
		t.Fatal("expected done")
	}
	done, _ = rs.IsKeyDone(groupID, "k2")
	if done {
		t.Fatal("expected k2 not done")
	}

	count, _ = rs.CountKeysDone(groupID)
	if count != 1 {
		t.Fatalf("expected 1, got %d", count)
	}

	// Mark k2 done.
	if err := rs.PutKeyDone(groupID, "k2", rec); err != nil {
		t.Fatal(err)
	}
	count, _ = rs.CountKeysDone(groupID)
	if count != 2 {
		t.Fatalf("expected 2, got %d", count)
	}

	// Clear all done for group.
	if err := rs.ClearKeysDone(groupID); err != nil {
		t.Fatal(err)
	}
	count, _ = rs.CountKeysDone(groupID)
	if count != 0 {
		t.Fatalf("expected 0 after clear, got %d", count)
	}
}

func TestReshareStore_ClearKeysDone_NoGroup(t *testing.T) {
	rs, err := NewReshareStore(openTestDB(t))
	if err != nil {
		t.Fatal(err)
	}
	// Should not error when clearing a group that has no done entries.
	if err := rs.ClearKeysDone("nonexistent"); err != nil {
		t.Fatal(err)
	}
}

// Suppress unused import warning.
var _ = tss.PartyID("")
