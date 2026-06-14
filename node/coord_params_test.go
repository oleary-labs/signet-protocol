package node

import (
	"testing"

	"signet/tss"
)

func memberSet(ids ...tss.PartyID) map[tss.PartyID]bool {
	m := make(map[tss.PartyID]bool, len(ids))
	for _, id := range ids {
		m[id] = true
	}
	return m
}

// TestCheckKeygenParams covers the H1 keygen parameter validation: threshold
// must match the group exactly and every party must be an active member.
func TestCheckKeygenParams(t *testing.T) {
	members := memberSet("a", "b", "c")

	tests := []struct {
		name      string
		threshold int
		parties   []tss.PartyID
		msgThresh int
		wantErr   bool
	}{
		{"full set, matching threshold", 2, []tss.PartyID{"a", "b", "c"}, 2, false},
		{"subset, matching threshold", 2, []tss.PartyID{"a", "b"}, 2, false},
		{"lowered threshold rejected", 2, []tss.PartyID{"a", "b", "c"}, 1, true},
		{"raised threshold rejected", 2, []tss.PartyID{"a", "b", "c"}, 3, true},
		{"non-member party rejected", 2, []tss.PartyID{"a", "b", "evil"}, 2, true},
		{"empty party set rejected", 2, nil, 2, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := checkKeygenParams(members, tc.threshold, tc.parties, tc.msgThresh)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err=%v, wantErr=%v", err, tc.wantErr)
			}
		})
	}
}

// TestCheckSignerSet covers the H1 sign validation: every signer must be a
// member and the distinct count must meet the group threshold.
func TestCheckSignerSet(t *testing.T) {
	members := memberSet("a", "b", "c")

	tests := []struct {
		name      string
		threshold int
		signers   []tss.PartyID
		wantErr   bool
	}{
		{"full set", 2, []tss.PartyID{"a", "b", "c"}, false},
		{"exactly threshold", 2, []tss.PartyID{"a", "b"}, false},
		{"below threshold rejected", 2, []tss.PartyID{"a"}, true},
		{"non-member signer rejected", 2, []tss.PartyID{"a", "evil"}, true},
		{"duplicates do not inflate count", 2, []tss.PartyID{"a", "a", "a"}, true},
		{"empty signer set rejected", 1, nil, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := checkSignerSet(members, tc.threshold, tc.signers)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err=%v, wantErr=%v", err, tc.wantErr)
			}
		})
	}
}

// TestGroupState verifies the helper reflects local on-chain group state and
// reports unknown/empty groups.
func TestGroupState(t *testing.T) {
	n, _ := newTestNode(t)
	n.groups["0xg1"] = &GroupInfo{Threshold: 2, Members: []tss.PartyID{"a", "b", "c"}}

	members, threshold, ok := n.groupState("0xg1")
	if !ok || threshold != 2 || len(members) != 3 || !members["a"] {
		t.Fatalf("unexpected state: ok=%v threshold=%d members=%v", ok, threshold, members)
	}

	if _, _, ok := n.groupState("0xunknown"); ok {
		t.Fatal("expected ok=false for unknown group")
	}

	n.groups["0xempty"] = &GroupInfo{Threshold: 1, Members: nil}
	if _, _, ok := n.groupState("0xempty"); ok {
		t.Fatal("expected ok=false for empty-membership group")
	}
}
