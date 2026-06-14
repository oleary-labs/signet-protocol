package network

import (
	"context"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"

	"signet/tss"
)

func mustKey(t *testing.T) crypto.PrivKey {
	t.Helper()
	priv, _, err := crypto.GenerateKeyPair(crypto.Secp256k1, -1)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return priv
}

// cached reports whether a partyID is currently in the in-memory mapping cache.
func (h *Host) cached(id tss.PartyID) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	_, ok := h.parties[id]
	return ok
}

func eventually(d time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return cond()
}

// TestPeerForPartyFallback verifies that PeerForParty resolves an unregistered
// partyID by decoding it (the map is a cache, partyID == peer.ID string), so
// eviction never breaks routing.
func TestPeerForPartyFallback(t *testing.T) {
	ctx := context.Background()
	h, err := NewHost(ctx, mustKey(t), "/ip4/127.0.0.1/tcp/0")
	if err != nil {
		t.Fatalf("new host: %v", err)
	}
	defer h.Close()

	other, err := NewHost(ctx, mustKey(t), "/ip4/127.0.0.1/tcp/0")
	if err != nil {
		t.Fatalf("new host: %v", err)
	}
	defer other.Close()

	otherPID := other.PeerID()
	if h.cached(tss.PartyID(otherPID.String())) {
		t.Fatal("other peer should not be cached without a connection")
	}

	got, ok := h.PeerForParty(tss.PartyID(otherPID.String()))
	if !ok || got != otherPID {
		t.Fatalf("fallback resolve: ok=%v got=%v want=%v", ok, got, otherPID)
	}

	if _, ok := h.PeerForParty(tss.PartyID("not-a-valid-peer-id")); ok {
		t.Fatal("garbage partyID should not resolve")
	}
}

// TestPeerMappingEvictedOnDisconnect verifies the party map is bounded: a peer
// registered on connect is removed once it has no remaining connections, while
// self is retained.
func TestPeerMappingEvictedOnDisconnect(t *testing.T) {
	ctx := context.Background()
	h1, err := NewHost(ctx, mustKey(t), "/ip4/127.0.0.1/tcp/0")
	if err != nil {
		t.Fatalf("new host: %v", err)
	}
	defer h1.Close()

	h2, err := NewHost(ctx, mustKey(t), "/ip4/127.0.0.1/tcp/0")
	if err != nil {
		t.Fatalf("new host: %v", err)
	}

	h2PID := h2.PeerID()
	h2Party := tss.PartyID(h2PID.String())

	if err := h1.LibP2PHost().Connect(ctx, peer.AddrInfo{
		ID:    h2PID,
		Addrs: h2.LibP2PHost().Addrs(),
	}); err != nil {
		t.Fatalf("connect: %v", err)
	}

	if !eventually(2*time.Second, func() bool { return h1.cached(h2Party) }) {
		t.Fatal("h2 not registered in h1 after connect")
	}

	// Tear down h2 entirely → h1 observes the disconnect.
	if err := h2.Close(); err != nil {
		t.Fatalf("close h2: %v", err)
	}

	if !eventually(3*time.Second, func() bool { return !h1.cached(h2Party) }) {
		t.Fatal("h2 mapping not evicted after disconnect")
	}

	// Self must never be evicted.
	if !h1.cached(h1.Self()) {
		t.Fatal("self mapping was evicted")
	}
}
