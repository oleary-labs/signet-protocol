package node

import (
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
)

// An expired session used to be reaped on a 60s tick and, once gone, reported
// as "session not found; call POST /v1/auth first" — which reads as an auth
// that never happened. On the alpha (2026-09-20) a UI reused a session for 90
// minutes past its JWT expiry and that message sent two diagnoses down the
// wrong path. The entry is now kept for expiredSessionGrace so the answer names
// the real cause, while still granting nothing.

func expiredSessionNode(t *testing.T, exp time.Time) (*Node, string) {
	t.Helper()
	n := &Node{log: zap.NewNop(), sessions: newSessionStore()}
	pub := make([]byte, 33)
	pub[0] = 0x03
	pubHex := sessionPubToHex(pub)
	n.sessions.Put(pubHex, &SessionInfo{Sub: "user-1", Iss: "https://issuer.example", Exp: exp})
	return n, pubHex
}

func TestValidateSessionRequest_ExpiredSaysExpired(t *testing.T) {
	n, pubHex := expiredSessionNode(t, time.Now().Add(-90*time.Minute))
	sig := strings.Repeat("ab", 64)

	// Twice: a retry must get the same answer, not "not found" one request later.
	for attempt := 1; attempt <= 2; attempt++ {
		_, _, herr := n.validateSessionRequest(pubHex, sig, "0xgroup", "", "",
			"nonce-1", uint64(time.Now().Unix()), nil)
		if herr == nil {
			t.Fatalf("attempt %d: expired session was accepted", attempt)
		}
		if herr.code != 401 {
			t.Fatalf("attempt %d: code = %d, want 401", attempt, herr.code)
		}
		if !strings.Contains(herr.msg, "session expired") {
			t.Fatalf("attempt %d: detail = %q, want it to name expiry", attempt, herr.msg)
		}
		// The age is the diagnostic: it points at when the session was created.
		if !strings.Contains(herr.msg, "1h30m0s") {
			t.Fatalf("attempt %d: detail = %q, want the age of the session", attempt, herr.msg)
		}
	}
}

// A session that genuinely never existed must still say so.
func TestValidateSessionRequest_UnknownSaysNotFound(t *testing.T) {
	n, _ := expiredSessionNode(t, time.Now().Add(time.Hour))
	other := make([]byte, 33)
	other[0] = 0x02
	_, _, herr := n.validateSessionRequest(sessionPubToHex(other), strings.Repeat("ab", 64),
		"0xgroup", "", "", "nonce-1", uint64(time.Now().Unix()), nil)
	if herr == nil || !strings.Contains(herr.msg, "session not found") {
		t.Fatalf("herr = %v, want session not found", herr)
	}
}

// The grace period is for reporting only — an expired session grants nothing.
func TestCleanup_KeepsExpiredForGraceThenDrops(t *testing.T) {
	s := newSessionStore()
	const key = "03deadbeef"

	s.Put(key, &SessionInfo{Exp: time.Now().Add(-time.Minute)})
	s.cleanup()
	if _, ok := s.Get(key); !ok {
		t.Fatal("session dropped inside the grace period; the 401 cannot name expiry")
	}

	s.Put(key, &SessionInfo{Exp: time.Now().Add(-expiredSessionGrace - time.Minute)})
	s.cleanup()
	if _, ok := s.Get(key); ok {
		t.Fatal("session retained past the grace period")
	}
}

// Live sessions are untouched by cleanup.
func TestCleanup_KeepsLiveSessions(t *testing.T) {
	s := newSessionStore()
	s.Put("03live", &SessionInfo{Exp: time.Now().Add(time.Hour)})
	s.cleanup()
	if _, ok := s.Get("03live"); !ok {
		t.Fatal("live session was reaped")
	}
}
