package node

import (
	"testing"
	"time"
)

// The sign HTTP handler resolves keys through awaitKey rather than GetKeyInfo,
// because a keygen can still be in flight on this node for a key the client
// already considers created: the initiator answers /v1/keygen when its own DKG
// run finishes, while participants run theirs in a goroutine off the coord
// message. These cover the three outcomes the handler distinguishes — present,
// still settling, and genuinely absent — since conflating the last two is what
// made the load-test 404s unreadable.

const (
	testGroup = "0xgroup"
	testKey   = "authkey:harness:k1"
)

func newAwaitTestNode(t *testing.T) (*Node, *mockKeyManager) {
	t.Helper()
	n, km := newTestNode(t)
	n.keygenReady = make(map[shardKey]chan struct{})
	return n, km
}

// A key already on disk returns immediately, with no waiting.
func TestAwaitKey_PresentReturnsImmediately(t *testing.T) {
	n, km := newAwaitTestNode(t)
	km.keys[testGroup] = []string{testKey}

	start := time.Now()
	info, err := n.awaitKey(testGroup, testKey, CurveSecp256k1, 2*time.Second)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info == nil {
		t.Fatal("expected key info, got nil")
	}
	if elapsed > 200*time.Millisecond {
		t.Fatalf("returned in %v; a present key must not wait", elapsed)
	}
}

// A key with no keygen in flight is genuinely absent: (nil, nil), so the
// handler answers 404. This is the negative-test path the correctness suite
// exercises deliberately, and it must stay distinguishable from a settling key.
func TestAwaitKey_AbsentWithNoKeygenReturnsNilNil(t *testing.T) {
	n, _ := newAwaitTestNode(t)

	info, err := n.awaitKey(testGroup, "authkey:harness:never-existed", CurveSecp256k1, 2*time.Second)
	if err != nil {
		t.Fatalf("absent key must not error, got %v", err)
	}
	if info != nil {
		t.Fatalf("expected nil info for an absent key, got %+v", info)
	}
}

// The race itself: the key is missing when the request arrives and appears
// while it waits. This is the window that produced two 404s in the first
// mainnet load test — 17ms and 2ms before the participant's keygen completed.
func TestAwaitKey_WaitsForInFlightKeygen(t *testing.T) {
	n, km := newAwaitTestNode(t)

	n.markKeygenPending(testGroup, testKey)
	go func() {
		time.Sleep(50 * time.Millisecond)
		km.mu.Lock()
		km.keys[testGroup] = append(km.keys[testGroup], testKey)
		km.mu.Unlock()
		n.markKeygenDone(testGroup, testKey)
	}()

	info, err := n.awaitKey(testGroup, testKey, CurveSecp256k1, 2*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info == nil {
		t.Fatal("expected the key to resolve once the keygen completed")
	}
}

// A keygen that never finishes must error rather than report the key absent.
// The handler maps this to 409 + Retry-After, not 404: the distinction is the
// whole point of the change.
func TestAwaitKey_PendingKeygenThatNeverCompletesErrors(t *testing.T) {
	n, _ := newAwaitTestNode(t)

	n.markKeygenPending(testGroup, testKey)

	info, err := n.awaitKey(testGroup, testKey, CurveSecp256k1, 100*time.Millisecond)
	if err == nil {
		t.Fatal("expected a timeout error for a keygen that never completes")
	}
	if info != nil {
		t.Fatalf("expected nil info on timeout, got %+v", info)
	}
}

// markKeygenDone must release every waiter, not just the first.
func TestAwaitKey_ConcurrentWaitersAllRelease(t *testing.T) {
	n, km := newAwaitTestNode(t)

	n.markKeygenPending(testGroup, testKey)

	const waiters = 8
	errs := make(chan error, waiters)
	for i := 0; i < waiters; i++ {
		go func() {
			_, err := n.awaitKey(testGroup, testKey, CurveSecp256k1, 2*time.Second)
			errs <- err
		}()
	}

	time.Sleep(30 * time.Millisecond)
	km.mu.Lock()
	km.keys[testGroup] = append(km.keys[testGroup], testKey)
	km.mu.Unlock()
	n.markKeygenDone(testGroup, testKey)

	for i := 0; i < waiters; i++ {
		select {
		case err := <-errs:
			if err != nil {
				t.Fatalf("waiter %d errored: %v", i, err)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("waiter %d never released", i)
		}
	}
}
