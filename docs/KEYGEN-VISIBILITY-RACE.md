# Keygen visibility race

A key can exist to the client before it exists on every node. Observed on
Ethereum mainnet during the alpha's first load test, 2026-08-25.

This documents the race, the evidence, the fix, and what is deliberately still
open.

---

## Symptom

Two `404 key not found` responses in ~90,000 operations, both for key IDs that
were genuinely created moments earlier — not the `-nonexistent-` probes the
correctness suite fires on purpose.

They were initially unexplainable because **the response is identical to a key
that never existed.** That ambiguity is the interesting part of this bug; the
race itself is ordinary.

## Evidence

From OLL's journals, key `authkey:harness:harness-1787622249293-1018`:

```
oll1 (initiator)     01:47:45.462  keygen starting
oll1                 01:47:45.559  keygen complete       -> HTTP 200 to client
oll2 (participant)   01:47:45.474  coord: keygen started
oll2                 01:47:45.585  404 key not found     <- 26ms after the 200
oll2                 01:47:45.602  coord: keygen complete <- 17ms too late
```

The second, `...-1102`, is the same shape with a 2ms miss. Both landed on oll2
and none on oll3/oll4, because the harness round-robins through a `ClientRing`
and oll2 follows oll1 in ring order — the operation after a keygen goes to the
next node. The clustering is a consequence of the mechanism, not a property of
oll2.

## Cause

The initiator answers `/v1/keygen` as soon as **its own** DKG run completes
(`node/handlers.go`, "keygen complete"). Participants run their side in a
goroutine spawned off the coord message (`node/coord.go:504`), and there is no
acknowledgement back to the initiator before it responds.

So between initiator-complete and participant-persist there is a window — low
tens of milliseconds under load — in which the key is real to the client and
absent on some participant. Any client that creates a key and immediately uses
it against a different node can land in it. A load generator round-robining
across the group does so reliably enough to see it twice in 90,000 operations;
the rate depends on load and ring position, so **the observed count is a floor,
not a measure of severity.**

Note this was never a correctness problem. No bad signature is produced, no
shard is lost. A request is refused that should have succeeded.

## What already existed

The node already tracks in-flight keygens — `markKeygenPending` /
`markKeygenDone` / `awaitKey` (`node/node.go`) — and the **coord** path already
used them (`node/coord.go:584`), waiting rather than failing.

The client-facing HTTP path did not. So an internally-initiated sign waited for
a settling key while a client-facing one got a 404. The asymmetry was the bug.

## Fix

`handleSign` resolves keys through `awaitKey` instead of `GetKeyInfo`:

| State | Behaviour |
|---|---|
| Key present | Returns immediately, no waiting |
| Keygen in flight here | Waits up to `keygenSettleTimeout` (2s), then proceeds |
| Still pending after the wait | **409** + `Retry-After: 1` |
| No key, no keygen in flight | **404**, unchanged |

The 409 matters as much as the wait. "Not yet" and "never existed" are
different states, and reporting both as 404 is what made this look anomalous
instead of self-describing. A client can act on a 409; it can only be confused
by a 404.

`keygenSettleTimeout` is 2s: keygen measured p50 206ms and p99 598ms under
concurrency 10, so this is a little over 3x p99, while staying far inside any
sane client timeout. The coord path allows 10s because nothing is holding a
connection open there; an HTTP caller gets the tighter bound.

In practice the 409 should be rare — the window is tens of milliseconds and the
wait is seconds. It exists so that when it *is* hit, the answer is legible.

## Still open

**`handleSetKeyStatus` and `handleDeleteKey` still return a bare 404** for a key
whose keygen is in flight. The race applies to them in principle — a client
could create a key and immediately disable or delete it via another node.

They were left alone deliberately, because the right behaviour is not obviously
the same. Waiting for a keygen to finish so it can immediately be deleted is
defensible, but so is refusing outright, and the semantics of cancelling a key
mid-creation deserve a decision rather than an inherited default. Worth
resolving before either endpoint is used programmatically at rate.

## Client guidance

Treat `409` on sign as retryable with a short backoff. Do not treat `404` as
retryable — after this change it means the key genuinely is not on that node,
which is a real error worth surfacing.

A client that creates a key and immediately uses it should expect the create and
the first use to be causally ordered only on the node that served the create.
