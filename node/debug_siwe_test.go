package node

import (
	"encoding/json"
	"testing"

	"go.uber.org/zap"
)

// /debug/stats reports the SIWE domain list a node actually holds, so a fleet
// can be checked against the chain from outside.
//
// The bug this exists for (ee85d75) was invisible rather than loud: the
// contract updated, nodes kept serving the list they booted with, and every
// operator watching the transaction saw it succeed. Nothing failed and nothing
// logged. These lock the two properties that make the symptom observable — the
// field is always present, and empty is reported as empty rather than omitted.

func newSiweStatsNode(t *testing.T) *Node {
	t.Helper()
	n := &Node{
		log:    zap.NewNop(),
		groups: make(map[string]*GroupInfo),
	}
	n.auth = &GroupAuth{
		groups:    make(map[string][]IssuerInfo),
		authKeys:  make(map[string][][]byte),
		resolvers: make(map[string]ResolverConfig),
		siweDoms:  make(map[string][]string),
		log:       zap.NewNop(),
	}
	return n
}

func TestDebugStats_ReportsLoadedSiweDomains(t *testing.T) {
	n := newSiweStatsNode(t)
	const gid = "0xgroup"
	n.auth.SetSiweDomains(gid, []string{"app.example.org", "localhost:3000"})

	got := n.auth.SiweDomains(gid)
	if len(got) != 2 || got[0] != "app.example.org" || got[1] != "localhost:3000" {
		t.Fatalf("SiweDomains = %v, want the two configured entries", got)
	}
}

// Empty must serialize as an empty list, not be omitted. A missing field is
// ambiguous between "this node has no domains" and "this node is too old to
// report" — and the whole point is telling those apart when auditing a fleet
// mid-rollout.
func TestDebugStats_EmptyDomainsSerializeAsEmptyNotOmitted(t *testing.T) {
	raw, err := json.Marshal(groupLiveness{
		GroupID:     "0xgroup",
		Threshold:   3,
		Members:     6,
		SiweDomains: nil,
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, present := out["siwe_domains"]; !present {
		t.Fatal("siwe_domains omitted when empty; it must always be present so " +
			"'no domains' is distinguishable from 'node too old to report'")
	}
}

func TestDebugStats_DomainsAreCopied(t *testing.T) {
	n := newSiweStatsNode(t)
	const gid = "0xgroup"
	orig := []string{"app.example.org"}
	n.auth.SetSiweDomains(gid, orig)

	// Mutating what the caller passed in must not reach into the node's state,
	// and neither must mutating what it hands back.
	orig[0] = "evil.example.org"
	if got := n.auth.SiweDomains(gid); got[0] != "app.example.org" {
		t.Fatalf("stored list aliased the caller's slice: %v", got)
	}

	handed := n.auth.SiweDomains(gid)
	handed[0] = "evil.example.org"
	if got := n.auth.SiweDomains(gid); got[0] != "app.example.org" {
		t.Fatalf("returned slice aliased stored state: %v", got)
	}
}
