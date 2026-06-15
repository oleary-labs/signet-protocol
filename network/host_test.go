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

// connectHosts dials h2 from h1 and waits for the connection to establish.
func connectHosts(t *testing.T, ctx context.Context, h1, h2 *Host) {
	t.Helper()
	if err := h1.LibP2PHost().Connect(ctx, peer.AddrInfo{
		ID:    h2.PeerID(),
		Addrs: h2.LibP2PHost().Addrs(),
	}); err != nil {
		t.Fatalf("connect: %v", err)
	}
}

// TestSessionRejectsForgedSender verifies the H2 fix: a SessionNetwork drops a
// protocol message whose From field does not match the authenticated libp2p
// peer, but accepts one with the correct From.
func TestSessionRejectsForgedSender(t *testing.T) {
	ctx := context.Background()
	h1, err := NewHost(ctx, mustKey(t), "/ip4/127.0.0.1/tcp/0")
	if err != nil {
		t.Fatalf("h1: %v", err)
	}
	defer h1.Close()
	h2, err := NewHost(ctx, mustKey(t), "/ip4/127.0.0.1/tcp/0")
	if err != nil {
		t.Fatalf("h2: %v", err)
	}
	defer h2.Close()
	connectHosts(t, ctx, h1, h2)

	const sessID = "sess-1"
	parties := []tss.PartyID{h1.Self(), h2.Self()}
	recv, err := NewSessionNetwork(ctx, h2, sessID, parties)
	if err != nil {
		t.Fatalf("recv session: %v", err)
	}
	defer recv.Close()
	send, err := NewSessionNetwork(ctx, h1, sessID, parties)
	if err != nil {
		t.Fatalf("send session: %v", err)
	}
	defer send.Close()

	// Legit message (From == h1) is delivered — confirms the plumbing works.
	send.Send(&tss.Message{From: h1.Self(), To: h2.Self(), Round: 1, Data: []byte("ok")})
	select {
	case msg := <-recv.Incoming():
		if msg.From != h1.Self() {
			t.Fatalf("delivered msg has From=%s, want %s", msg.From, h1.Self())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("legit message was not delivered")
	}

	// Forged message (From spoofs a third party) must be dropped.
	send.Send(&tss.Message{From: "forged-party", To: h2.Self(), Round: 1, Data: []byte("evil")})
	select {
	case msg := <-recv.Incoming():
		t.Fatalf("forged message was delivered: From=%s", msg.From)
	case <-time.After(500 * time.Millisecond):
		// expected: nothing delivered
	}
}

// TestMuxRejectsForgedSender verifies the H2 fix on the reshare (mux) path.
func TestMuxRejectsForgedSender(t *testing.T) {
	ctx := context.Background()
	h1, err := NewHost(ctx, mustKey(t), "/ip4/127.0.0.1/tcp/0")
	if err != nil {
		t.Fatalf("h1: %v", err)
	}
	defer h1.Close()
	h2, err := NewHost(ctx, mustKey(t), "/ip4/127.0.0.1/tcp/0")
	if err != nil {
		t.Fatalf("h2: %v", err)
	}
	defer h2.Close()
	connectHosts(t, ctx, h1, h2)

	const sessID = "mux-sess-1"
	parties := []tss.PartyID{h1.Self(), h2.Self()}

	recvMux := NewMuxNetwork(ctx, h2)
	defer recvMux.Close()
	recv := recvMux.Session(ctx, sessID, parties)
	defer recv.Close()

	sendMux := NewMuxNetwork(ctx, h1)
	defer sendMux.Close()
	send := sendMux.Session(ctx, sessID, parties)
	defer send.Close()

	send.Send(&tss.Message{From: h1.Self(), To: h2.Self(), Round: 1, Data: []byte("ok")})
	select {
	case msg := <-recv.Incoming():
		if msg.From != h1.Self() {
			t.Fatalf("delivered msg has From=%s, want %s", msg.From, h1.Self())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("legit message was not delivered")
	}

	send.Send(&tss.Message{From: "forged-party", To: h2.Self(), Round: 1, Data: []byte("evil")})
	select {
	case msg := <-recv.Incoming():
		t.Fatalf("forged message was delivered: From=%s", msg.From)
	case <-time.After(500 * time.Millisecond):
		// expected: nothing delivered
	}
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
