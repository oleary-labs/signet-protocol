# Propagation races: when the initiator answers before the group agrees

Status: **one class, two instances, both now mitigated.** This exists because the
second instance was diagnosed from scratch after the first had already been
fixed, documented, and its general cause written down.

---

## The class

Every client-facing operation runs on one node — the initiator — and is
replicated to the rest of the group over coord messages. The initiator knows when
*its own* work is done. It does not, by default, know when anyone else's is.

So there is a window in which state is real to the client and absent on some
members. Any client that completes an operation and immediately uses its result
against the group can land in it.

| | Keygen visibility | Session propagation |
|---|---|---|
| Observed | 2026-08-25, first load test | 2026-09-22, first SIWE transaction |
| State | key shard | auth session |
| Initiator answered after | its own DKG completed | its own SIWE verification |
| Member's view | key absent | session absent |
| Client saw | `404 key not found` | `503 insufficient available signers` |
| Window measured | 2–26ms | 29–45ms |
| Record | [`KEYGEN-VISIBILITY-RACE.md`](KEYGEN-VISIBILITY-RACE.md) | this document, §Instance 2 |

Neither is a correctness problem. No bad signature, no lost shard. An operation
is refused that should have succeeded — and refused in a way that did not say so.

## Why it recurred

The August fix was applied to the instance, not the class. Its own diagnosis
states the general cause — *"there is no acknowledgement back to the initiator
before it responds"* — and its closing line generalises correctly: *"a client
that creates a key and immediately uses it should expect the create and the first
use to be causally ordered only on the node that served the create."* Substitute
*authenticates* for *creates* and that is instance 2, a month early.

What made it hard to see as the same bug is that the asymmetry inverted. In
August the **coord** path waited (`awaitKey`) while the **client-facing HTTP**
path did not, and the doc called that asymmetry the bug. In September the
client-facing auth path answered without waiting and the coord path had no wait
for sessions at all. Same class, opposite halves, different error code — and a
`503 insufficient signers` reads like a capacity problem, not a race.

## Instance 2 — session propagation

`/v1/auth` verified the SIWE message, stored the session locally, spawned the
`msgAuth` broadcast in a goroutine, and returned `200`. The client, treating 200
as "authenticated", called `/v1/sign` immediately. The sign coord raced the auth
broadcast and won on two members:

```
oll1   02:04:15.081  coord: session not found      <- sign coord, NACK
oll1   02:04:15.110  coord: session established    <- 29ms too late
oll3   02:04:15.080  coord: session not found      <- NACK
oll3   02:04:15.125  coord: session established    <- 45ms too late
```

Three members were excluded. The group is `T=3` of 6, so ECDSA needs `2T-1 = 5`
signers and tolerates exactly **one** loss. Hence
`insufficient available signers: need 5, have 3 of 6`.

Two amplifiers worth naming, because they are what turned a millisecond race into
a failed transaction:

- **Exclusions are per-attempt.** A member that rejects one message is dropped
  for that operation even though it is healthy a moment later.
- **ECDSA's floor leaves one spare.** FROST needs `T = 3` and would have survived
  this exact run. The same race is survivable or fatal depending on the curve.

It also reached further than signing: the session lookup sits behind
`requiresUserAuth` (`node/coord.go`), covering `msgSign`, `msgKeygen`,
`msgDelegateSign`, `msgSetKeyStatus` and `msgDeleteKey`. Every authenticated
operation was exposed; signing is merely the one with the highest quorum.

## The rule: spend latency where operations are rare

Auth and keygen happen once per session and once per key. Signing happens once
per operation, on the payment path. That asymmetry is a budget:

> **Rare paths should be slow and certain. The hot path should be fast and
> tolerant.**

Concretely:

- **Rare paths do not answer until the group agrees.** `/v1/auth` now waits for
  the `msgAuth` broadcast before responding, so a `200` means the group can act
  on the session rather than just this node. Cost: one round trip to the slowest
  member, tens of milliseconds, once per session.
- **The hot path never waits on propagation to *establish* anything.** It only
  tolerates residual skew, with a bounded settle: `keygenSettleTimeout` (2s) for
  keys, `sessionSettleTimeout` (2s) for sessions.
- **"Not yet" is never reported as "never".** A 404 for a settling key became a
  `409 + Retry-After`; an expired session says `session expired 1h27m3s ago`
  rather than `session not found`. An ambiguous status is what makes these look
  anomalous instead of self-describing.

The first rule is the one that was missing twice. A fast answer that the rest of
the group cannot honour is not a fast answer, it is a wrong one.

## Fix pattern, in order of preference

1. **Acknowledge before answering** on any path rare enough to afford it. This
   removes the race rather than narrowing it.
2. **Bounded wait on the receiving side** for residual skew — a member that
   acknowledged late, or was slow to schedule its handler. Defence in depth, not
   a substitute for (1).
3. **Distinguish "not yet" from "never"** in the status and the message, so the
   next occurrence diagnoses itself.

## Still open

- **Keygen still answers before participants acknowledge.** The August fix added
  tolerance on the consumer side (`awaitKey`) rather than acknowledgement on the
  producer side, so the window still exists; it is merely absorbed. Applying (1)
  to `/v1/keygen` would close it and make the 409 unreachable in practice. The
  trade is real, though: keygen takes p50 206ms / p99 598ms against auth's few
  milliseconds, and requires **all** N members, so waiting for acknowledgement
  costs more and fails more often. Worth doing, worth measuring first.
- **`handleSetKeyStatus` and `handleDeleteKey` still return a bare 404** for a
  key whose keygen is in flight — inherited unchanged from the August doc, for
  the same reason: cancelling a key mid-creation deserves a decision rather than
  an inherited default.
- **Partial establishment is reported, not prevented.** `/v1/auth` returns
  `established` and `members` so an ECDSA caller can see it lacks `2T-1` before
  it tries. Nothing yet *acts* on that — a client can still attempt a signature
  it cannot complete, and will get the same 503, just for an honest reason.

## How to recognise the next one

Grep a member's journal for the same identifier being rejected and then accepted
within milliseconds. For sessions:

```
journalctl -u signetd | grep -E 'session (not found|established)'
```

A `not found` followed closely by an `established` for the **same** `session_pub`
is this class, not a client error. The equivalent for keys is a `404` followed by
`coord: keygen complete` for the same key ID.
