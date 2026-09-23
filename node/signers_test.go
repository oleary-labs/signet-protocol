package node

import (
	"testing"
	"time"

	"go.uber.org/zap"

	"signet/tss"
)

// newSelectionNode builds a Node with just enough wiring to exercise signer
// selection: a party identity, a group, and a liveness tracker with a
// controllable clock. No libp2p host is needed because selection only reads
// the tracker and the group.
func newSelectionNode(t *testing.T, self tss.PartyID, clock *time.Time) *Node {
	t.Helper()
	n := &Node{
		log:    zap.NewNop(),
		groups: make(map[string]*GroupInfo),
	}
	n.liveness = newLiveness(n, self, zap.NewNop())
	n.liveness.now = func() time.Time { return *clock }
	return n
}

func TestRequiredSigners(t *testing.T) {
	tests := []struct {
		curve     Curve
		threshold int
		want      int
	}{
		// FROST is genuinely T-of-N.
		{CurveSecp256k1, 2, 2},
		{CurveSecp256k1, 3, 3},
		{CurveEd25519, 4, 4},

		// ECDSA needs 2T-1, floored at the kms-tss minimum of 3.
		{CurveEcdsaSecp256k1, 1, 3},
		{CurveEcdsaSecp256k1, 2, 3},
		{CurveEcdsaSecp256k1, 3, 5},
		{CurveEcdsaSecp256k1, 4, 7},
		{CurveEcdsaSecp256k1, 5, 9},
	}
	for _, tc := range tests {
		if got := requiredSigners(tc.curve, tc.threshold); got != tc.want {
			t.Errorf("requiredSigners(%s, T=%d) = %d, want %d",
				tc.curve, tc.threshold, got, tc.want)
		}
	}
}

// A 3-of-5 group must use all five for ECDSA but only three for FROST — the
// difference the whole selection mechanism exists to exploit.
func TestSelectSigners_MinimumSetPerCurve(t *testing.T) {
	now := time.Now()
	n := newSelectionNode(t, "self", &now)
	grp := &GroupInfo{
		Threshold: 3,
		Members:   []tss.PartyID{"self", "b", "c", "d", "e"},
	}

	frost, err := n.selectSigners(grp, CurveSecp256k1, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(frost) != 3 {
		t.Errorf("FROST T=3: got %d signers %v, want 3", len(frost), frost)
	}
	if !frost.Contains("self") {
		t.Error("FROST: initiator must be in the signer set")
	}

	ecdsa, err := n.selectSigners(grp, CurveEcdsaSecp256k1, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(ecdsa) != 5 {
		t.Errorf("ECDSA T=3: got %d signers %v, want 5 (2T-1)", len(ecdsa), ecdsa)
	}
}

// Selection must prefer fast peers, since every ECDSA round pays the slowest
// selected peer's latency four times over.
func TestSelectSigners_PrefersLowLatency(t *testing.T) {
	now := time.Now()
	n := newSelectionNode(t, "self", &now)
	grp := &GroupInfo{
		Threshold: 2,
		Members:   []tss.PartyID{"self", "near", "mid", "far"},
	}

	n.liveness.RecordSuccess("near", 10*time.Millisecond)
	n.liveness.RecordSuccess("mid", 80*time.Millisecond)
	n.liveness.RecordSuccess("far", 250*time.Millisecond)

	got, err := n.selectSigners(grp, CurveSecp256k1, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || !got.Contains("self") || !got.Contains("near") {
		t.Errorf("got %v, want [self near]", got)
	}
}

// An unhealthy peer should be skipped while a healthy alternative exists.
func TestSelectSigners_SkipsUnhealthy(t *testing.T) {
	now := time.Now()
	n := newSelectionNode(t, "self", &now)
	grp := &GroupInfo{
		Threshold: 2,
		Members:   []tss.PartyID{"self", "dead", "alive"},
	}

	// "dead" is fast but failing; "alive" is slow but answering.
	n.liveness.RecordSuccess("dead", 5*time.Millisecond)
	for i := 0; i < unhealthyAfter; i++ {
		n.liveness.RecordFailure("dead")
	}
	n.liveness.RecordSuccess("alive", 200*time.Millisecond)

	got, err := n.selectSigners(grp, CurveSecp256k1, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.Contains("dead") {
		t.Errorf("got %v, should have skipped the unhealthy peer", got)
	}
	if !got.Contains("alive") {
		t.Errorf("got %v, want the healthy peer included", got)
	}
}

// Liveness is a hint, not an oracle. When there is no healthy alternative, an
// unhealthy peer must still be tried rather than failing the request — the
// attempt is the only authoritative test.
func TestSelectSigners_UsesUnhealthyWhenNoAlternative(t *testing.T) {
	now := time.Now()
	n := newSelectionNode(t, "self", &now)
	grp := &GroupInfo{
		Threshold: 2,
		Members:   []tss.PartyID{"self", "sick"},
	}
	for i := 0; i < unhealthyAfter+3; i++ {
		n.liveness.RecordFailure("sick")
	}

	got, err := n.selectSigners(grp, CurveSecp256k1, nil)
	if err != nil {
		t.Fatalf("should still attempt with the only peer available: %v", err)
	}
	if !got.Contains("sick") {
		t.Errorf("got %v, want the unhealthy peer as a last resort", got)
	}
}

// The retry path excludes parties that failed, and selection must route around
// them until the group genuinely cannot reach the minimum.
func TestSelectSigners_ExclusionAndExhaustion(t *testing.T) {
	now := time.Now()
	n := newSelectionNode(t, "self", &now)
	grp := &GroupInfo{
		Threshold: 3,
		Members:   []tss.PartyID{"self", "b", "c", "d", "e", "f"},
	}

	// 3-of-6 ECDSA needs 5 signers, so exactly one member may be excluded.
	excluded := map[tss.PartyID]bool{"b": true}
	got, err := n.selectSigners(grp, CurveEcdsaSecp256k1, excluded)
	if err != nil {
		t.Fatalf("one exclusion should still be satisfiable: %v", err)
	}
	if len(got) != 5 || got.Contains("b") {
		t.Errorf("got %v, want 5 signers excluding b", got)
	}

	// A second exclusion drops the pool below 2T-1.
	excluded["c"] = true
	if _, err := n.selectSigners(grp, CurveEcdsaSecp256k1, excluded); err == nil {
		t.Error("two exclusions leave only 4 of the 5 required; want an error")
	}

	// FROST needs only 3, so the same group tolerates far more loss.
	if _, err := n.selectSigners(grp, CurveSecp256k1, excluded); err != nil {
		t.Errorf("FROST T=3 with 4 members left should succeed: %v", err)
	}
}

// Non-members and a failed initiator are both hard errors.
func TestSelectSigners_Rejections(t *testing.T) {
	now := time.Now()
	n := newSelectionNode(t, "self", &now)

	outsider := &GroupInfo{Threshold: 2, Members: []tss.PartyID{"x", "y", "z"}}
	if _, err := n.selectSigners(outsider, CurveSecp256k1, nil); err == nil {
		t.Error("want an error when this node is not a group member")
	}

	grp := &GroupInfo{Threshold: 2, Members: []tss.PartyID{"self", "b"}}
	if _, err := n.selectSigners(grp, CurveSecp256k1, map[tss.PartyID]bool{"self": true}); err == nil {
		t.Error("want an error when the initiator itself is excluded")
	}
}

// ECDSA assigns the coordinator role to signer_ids[0], which must be the
// initiating node. FROST has no such constraint and keeps sorted order.
func TestOrderForCoord(t *testing.T) {
	signers := tss.NewPartyIDSlice([]tss.PartyID{"c", "a", "self", "b"})

	ecdsa := orderForCoord(signers, "self", CurveEcdsaSecp256k1)
	if ecdsa[0] != "self" {
		t.Errorf("ECDSA: got %v, want self first", ecdsa)
	}
	if len(ecdsa) != len(signers) {
		t.Errorf("ECDSA: got %d signers, want %d", len(ecdsa), len(signers))
	}
	for _, want := range signers {
		var found bool
		for _, got := range ecdsa {
			if got == want {
				found = true
			}
		}
		if !found {
			t.Errorf("ECDSA: reordering dropped %s", want)
		}
	}

	frost := orderForCoord(signers, "self", CurveSecp256k1)
	for i := range signers {
		if frost[i] != signers[i] {
			t.Errorf("FROST: order changed at %d: got %v, want %v", i, frost, signers)
			break
		}
	}
}

// A stale probe result must decay to "unknown", so a stalled probe loop makes
// the node optimistic rather than leaving peers permanently condemned.
func TestLiveness_StaleResultsDecayToOptimistic(t *testing.T) {
	now := time.Now()
	n := newSelectionNode(t, "self", &now)

	for i := 0; i < unhealthyAfter; i++ {
		n.liveness.RecordFailure("p")
	}
	if n.liveness.healthy("p") {
		t.Fatal("peer should be unhealthy immediately after consecutive failures")
	}

	now = now.Add(staleAfter + time.Second)
	if !n.liveness.healthy("p") {
		t.Error("a stale failure should decay to optimistic, not stay condemned")
	}
}

// A success must clear the failure streak.
func TestLiveness_RecoveryClearsFailures(t *testing.T) {
	now := time.Now()
	n := newSelectionNode(t, "self", &now)

	for i := 0; i < unhealthyAfter+2; i++ {
		n.liveness.RecordFailure("p")
	}
	if n.liveness.healthy("p") {
		t.Fatal("peer should be unhealthy")
	}
	n.liveness.RecordSuccess("p", 20*time.Millisecond)
	if !n.liveness.healthy("p") {
		t.Error("one success should clear the failure streak")
	}
}

// A single slow sample must not dominate the smoothed round-trip.
func TestLiveness_RTTIsSmoothed(t *testing.T) {
	now := time.Now()
	n := newSelectionNode(t, "self", &now)

	n.liveness.RecordSuccess("p", 10*time.Millisecond)
	n.liveness.RecordSuccess("p", 1000*time.Millisecond)

	got := n.liveness.rtt("p")
	if got < 10*time.Millisecond || got > 400*time.Millisecond {
		t.Errorf("EWMA = %v; one 1s outlier should move a 10ms baseline only partway", got)
	}
}
