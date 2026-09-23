package node

import (
	"context"
	"errors"
	"testing"
	"time"

	"signet/tss"
)

// These exercise the liveness machinery over real libp2p transport, which is
// the only way to be sure the failure paths behave: a unit test with a stubbed
// network cannot tell you what happens when a peer's host is actually gone.

const livenessTestGroup = "0xliveness"

// A probe must succeed against a running peer and fail against a stopped one,
// and the failure must reach the tracker.
func TestLiveness_ProbeDetectsStoppedNode(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	cluster, cleanup := newTestNodeCluster(t, ctx, 3)
	defer cleanup()

	members := make([]tss.PartyID, len(cluster))
	for i, tn := range cluster {
		members[i] = tn.host.Self()
	}
	setGroupMembership(cluster, livenessTestGroup, members, 2)

	initiator := cluster[0].n
	victim := members[2]

	// Everyone is up: the probe should succeed and record a round-trip.
	if err := initiator.sendPing(ctx, members[1], livenessTestGroup); err != nil {
		t.Fatalf("ping to a live peer failed: %v", err)
	}
	initiator.liveness.probeOne(ctx, members[1], livenessTestGroup)
	if !initiator.liveness.healthy(members[1]) {
		t.Error("a peer that answered should be healthy")
	}
	if rtt := initiator.liveness.rtt(members[1]); rtt <= 0 || rtt >= time.Hour {
		t.Errorf("expected a measured round-trip, got %v", rtt)
	}

	// Take the third node down.
	cluster[2].n.cancel()
	cluster[2].host.Close()

	if err := initiator.sendPing(ctx, victim, livenessTestGroup); err == nil {
		t.Fatal("ping to a stopped peer should fail")
	}

	// One failure is a blip; unhealthyAfter of them is a verdict.
	for i := 0; i < unhealthyAfter; i++ {
		initiator.liveness.probeOne(ctx, victim, livenessTestGroup)
	}
	if initiator.liveness.healthy(victim) {
		t.Errorf("peer should be unhealthy after %d failed probes", unhealthyAfter)
	}
}

// A probe from a peer outside the group must be refused, so the mechanism
// cannot be used by an arbitrary node to enumerate cluster state.
func TestLiveness_ProbeRejectedForNonMember(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	cluster, cleanup := newTestNodeCluster(t, ctx, 2)
	defer cleanup()

	// Register a group that contains the responder but NOT the caller.
	responder := cluster[1]
	responder.n.groupsMu.Lock()
	responder.n.groups[livenessTestGroup] = &GroupInfo{
		Threshold: 1,
		Members:   []tss.PartyID{responder.host.Self()},
	}
	responder.n.groupsMu.Unlock()

	err := cluster[0].n.sendPing(ctx, responder.host.Self(), livenessTestGroup)
	if err == nil {
		t.Fatal("a non-member's probe should be rejected")
	}

	// And an unknown group is refused rather than answered.
	if err := cluster[0].n.sendPing(ctx, responder.host.Self(), "0xnosuchgroup"); err == nil {
		t.Fatal("a probe for an unknown group should be rejected")
	}
}

// broadcastCoord must report every unreachable party, not just the first. The
// retry path depends on the full set to know who to exclude.
func TestBroadcastCoord_ReportsAllFailedParties(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	cluster, cleanup := newTestNodeCluster(t, ctx, 4)
	defer cleanup()

	members := make([]tss.PartyID, len(cluster))
	for i, tn := range cluster {
		members[i] = tn.host.Self()
	}
	setGroupMembership(cluster, livenessTestGroup, members, 2)

	// Stop two of the four.
	down := map[tss.PartyID]bool{members[2]: true, members[3]: true}
	for i := 2; i < 4; i++ {
		cluster[i].n.cancel()
		cluster[i].host.Close()
	}

	initiator := cluster[0].n
	err := initiator.broadcastCoord(ctx, members, coordMsg{
		Type:    msgPing,
		GroupID: livenessTestGroup,
	})
	if err == nil {
		t.Fatal("broadcast to two stopped peers should fail")
	}

	var bcastErr *coordBroadcastError
	if !errors.As(err, &bcastErr) {
		t.Fatalf("want a *coordBroadcastError, got %T: %v", err, err)
	}
	if len(bcastErr.Failed) != 2 {
		t.Errorf("got %d failed parties %v, want both stopped nodes",
			len(bcastErr.Failed), bcastErr.Failed)
	}
	for _, p := range bcastErr.Failed {
		if !down[p] {
			t.Errorf("%s was reported failed but was running", p)
		}
	}

	// The live peer must have been recorded as healthy, and both dead ones not.
	if !initiator.liveness.healthy(members[1]) {
		t.Error("the peer that answered should be marked healthy")
	}
	for i := 0; i < unhealthyAfter-1; i++ {
		initiator.liveness.RecordFailure(members[2])
	}
	if initiator.liveness.healthy(members[2]) {
		t.Error("a peer that failed the broadcast should trend unhealthy")
	}
}

// The end the whole mechanism exists for: with a member down, selection must
// still produce a viable signer set that excludes it.
func TestSelectSigners_RoutesAroundDownNode(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	cluster, cleanup := newTestNodeCluster(t, ctx, 4)
	defer cleanup()

	members := make([]tss.PartyID, len(cluster))
	for i, tn := range cluster {
		members[i] = tn.host.Self()
	}
	// 2-of-4: FROST needs 2, ECDSA needs 3, so one node may be lost.
	setGroupMembership(cluster, livenessTestGroup, members, 2)

	initiator := cluster[0].n
	victim := members[3]
	cluster[3].n.cancel()
	cluster[3].host.Close()

	// Let the probe loop's logic observe the failure.
	for i := 0; i < unhealthyAfter; i++ {
		initiator.liveness.probeOne(ctx, victim, livenessTestGroup)
	}

	initiator.groupsMu.RLock()
	grp := initiator.groups[livenessTestGroup]
	initiator.groupsMu.RUnlock()

	frost, err := initiator.selectSigners(grp, CurveSecp256k1, nil)
	if err != nil {
		t.Fatalf("FROST selection with 3 of 4 up should succeed: %v", err)
	}
	if frost.Contains(victim) {
		t.Errorf("FROST set %v includes the down node", frost)
	}

	ecdsa, err := initiator.selectSigners(grp, CurveEcdsaSecp256k1, nil)
	if err != nil {
		t.Fatalf("ECDSA selection with 3 of 4 up should succeed: %v", err)
	}
	if ecdsa.Contains(victim) {
		t.Errorf("ECDSA set %v includes the down node", ecdsa)
	}
	if len(ecdsa) != 3 {
		t.Errorf("ECDSA T=2 needs 2T-1=3 signers, got %d: %v", len(ecdsa), ecdsa)
	}

	// Losing a second node leaves too few for ECDSA but still enough for FROST.
	exclude := map[tss.PartyID]bool{victim: true, members[2]: true}
	if _, err := initiator.selectSigners(grp, CurveEcdsaSecp256k1, exclude); err == nil {
		t.Error("ECDSA should fail with only 2 of the required 3 available")
	}
	if _, err := initiator.selectSigners(grp, CurveSecp256k1, exclude); err != nil {
		t.Errorf("FROST should still succeed with 2 members: %v", err)
	}
}

// A party whose ID cannot be resolved to a libp2p peer must be reported
// through the normal drain path, not short-circuited.
//
// broadcastCoord used to `return` on a PeerForParty miss, before the loop that
// collects results. That handed the caller a bare error instead of a
// *coordBroadcastError, so runThresholdSign's errors.As check failed and it
// never retried without the bad party; the liveness tracker never learned the
// party was unreachable; and results from goroutines already spawned for
// earlier parties were dropped unread. Regression test for that path.
func TestBroadcastCoord_UnresolvablePartyGoesThroughDrain(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	cluster, cleanup := newTestNodeCluster(t, ctx, 2)
	defer cleanup()

	// PeerForParty falls back to peer.Decode, so only an ID that is not a
	// valid peer ID at all produces a miss.
	const bogus = tss.PartyID("not-a-decodable-peer-id")

	real := cluster[1].host.Self()
	members := []tss.PartyID{cluster[0].host.Self(), real, bogus}
	setGroupMembership(cluster, livenessTestGroup, members, 2)

	initiator := cluster[0].n
	err := initiator.broadcastCoord(ctx, members, coordMsg{
		Type:    msgPing,
		GroupID: livenessTestGroup,
	})
	if err == nil {
		t.Fatal("broadcast including an unresolvable party should fail")
	}

	var bcastErr *coordBroadcastError
	if !errors.As(err, &bcastErr) {
		t.Fatalf("want *coordBroadcastError so the retry can route around it, got %T: %v", err, err)
	}
	if !bcastErr.Failed.Contains(bogus) {
		t.Errorf("Failed = %v, want it to name the unresolvable party", bcastErr.Failed)
	}

	// The reachable peer's result must still have been drained and recorded,
	// rather than discarded by an early return.
	if !initiator.liveness.healthy(real) {
		t.Error("the reachable peer should have been probed and recorded healthy")
	}
	if rtt := initiator.liveness.rtt(real); rtt <= 0 || rtt >= time.Hour {
		t.Errorf("reachable peer should have a measured RTT, got %v", rtt)
	}
}
