package node

import (
	"context"
	"sync"
	"testing"
	"time"
)

// /v1/auth establishes a session on the initiator and forwards it to the other
// members. An operation sent to those members can arrive before the forward
// does, and rejecting it immediately costs the whole operation — exclusions are
// per-attempt, and ECDSA at T=3 of 6 needs 5 signers, so it survives exactly
// one. On the alpha (2026-09-22) two members rejected a sign coord and then
// established the same session 29ms and 45ms later; three exclusions took the
// group below the ECDSA floor and the transaction failed with 503.
//
// The initiator now waits for the broadcast before answering, so this is the
// second line of defence. These lock the property it provides.

func TestSessionAwait_ReturnsImmediatelyWhenPresent(t *testing.T) {
	s := newSessionStore()
	s.Put("03aa", &SessionInfo{Sub: "u1", Exp: time.Now().Add(time.Hour)})

	start := time.Now()
	info, ok := s.Await(context.Background(), "03aa", time.Minute)
	if !ok || info.Sub != "u1" {
		t.Fatalf("Await = %v, %v", info, ok)
	}
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Fatalf("waited %s for a session already present", elapsed)
	}
}

func TestSessionAwait_WakesOnArrival(t *testing.T) {
	s := newSessionStore()
	go func() {
		time.Sleep(30 * time.Millisecond)
		s.Put("03bb", &SessionInfo{Sub: "u2", Exp: time.Now().Add(time.Hour)})
	}()

	start := time.Now()
	info, ok := s.Await(context.Background(), "03bb", 5*time.Second)
	if !ok || info.Sub != "u2" {
		t.Fatalf("Await = %v, %v — a session arriving mid-wait must be seen", info, ok)
	}
	// Woken by Put, not by the timeout.
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("took %s; should wake on Put rather than wait out the timeout", elapsed)
	}
}

// Several members can race the same session; all of them must wake.
func TestSessionAwait_WakesEveryWaiter(t *testing.T) {
	s := newSessionStore()
	const n = 8
	var wg sync.WaitGroup
	errs := make(chan string, n)
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, ok := s.Await(context.Background(), "03cc", 5*time.Second); !ok {
				errs <- "waiter did not see the session"
			}
		}()
	}
	time.Sleep(20 * time.Millisecond)
	s.Put("03cc", &SessionInfo{Exp: time.Now().Add(time.Hour)})
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Fatal(e)
	}
}

// A session that never arrives must still be reported missing — the wait defers
// the answer, it does not change it.
func TestSessionAwait_TimesOutForUnknownSession(t *testing.T) {
	s := newSessionStore()
	start := time.Now()
	if _, ok := s.Await(context.Background(), "03dd", 50*time.Millisecond); ok {
		t.Fatal("Await reported a session that was never stored")
	}
	if elapsed := time.Since(start); elapsed < 50*time.Millisecond {
		t.Fatalf("returned after %s, before the timeout elapsed", elapsed)
	}
}

func TestSessionAwait_RespectsContextCancellation(t *testing.T) {
	s := newSessionStore()
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(20 * time.Millisecond); cancel() }()

	start := time.Now()
	if _, ok := s.Await(ctx, "03ee", time.Minute); ok {
		t.Fatal("Await reported a session that was never stored")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("ignored cancellation, waited %s", elapsed)
	}
}

// An awaited session that never arrives leaves a waiter behind; cleanup must
// reclaim it, or every bogus session_pub grows the map permanently.
func TestSessionAwait_StaleWaitersAreReaped(t *testing.T) {
	s := newSessionStore()
	done := make(chan struct{})
	go func() { defer close(done); s.Await(context.Background(), "03ff", 2*time.Second) }()

	// Let the waiter register.
	for range 100 {
		s.mu.RLock()
		n := len(s.waiters)
		s.mu.RUnlock()
		if n == 1 {
			break
		}
		time.Sleep(time.Millisecond)
	}

	// Age it past the reaping bound, then clean up.
	s.mu.Lock()
	s.waiters["03ff"].created = time.Now().Add(-sessionWaiterMaxAge - time.Second)
	s.mu.Unlock()
	s.cleanup()

	s.mu.RLock()
	left := len(s.waiters)
	s.mu.RUnlock()
	if left != 0 {
		t.Fatalf("waiters left after cleanup: %d", left)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("reaping a waiter must wake it so it can re-check and report missing")
	}
}
