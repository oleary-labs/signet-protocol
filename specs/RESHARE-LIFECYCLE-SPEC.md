# Group Reshare Lifecycle — Quint Specification

Formal model of the per-group ACTIVE/RESHARING state machine that manages key reshare jobs triggered by on-chain membership changes. Specified in [reshare_lifecycle.qnt](reshare_lifecycle.qnt).

This spec models the **node-level orchestration** layer that sits above the `KeyManager` interface (`node/keymanager.go`). It is backend-agnostic — the same state machine applies whether the underlying implementation is `LocalKeyManager` (in-process Go `tss/reshare.go`) or `RemoteKeyManager` (gRPC to the Rust KMS at `kms-frost/`). The cryptographic reshare protocol itself is modeled separately in [frost_reshare.qnt](frost_reshare.qnt).

This spec is ahead of the implementation — the design is fully specified in `docs/DESIGN-RESHARE.md` sections 4-8, but the code in `node/` does not yet include ReshareJob storage, coordinator loops, stale key checks, the `/v1/reshare` API, or a `Reshare` method on the `KeyManager` interface.

## Sources

| Source | What it informed |
|--------|-----------------|
| `docs/DESIGN-RESHARE.md` section 4 | Group state machine (ACTIVE/RESHARING transitions) |
| `docs/DESIGN-RESHARE.md` section 5 | Storage schema (`reshare_jobs`, `reshare_done`, stale key check) |
| `docs/DESIGN-RESHARE.md` section 6 | API (`POST /v1/reshare`, 404/409 semantics) |
| `docs/DESIGN-RESHARE.md` section 8 | Node behavior (chain events, sign handler blocking, coordinator loop, on-demand reshare) |
| `docs/DESIGN-RESHARE.md` section 10 | Edge cases (dual coordinator, deferred events, keygen during reshare) |
| `docs/DESIGN-KMS.md` section 7 | KeyManager interface design — this spec sits above that boundary |
| `node/chain.go` | Current event handling (NodeJoined/NodeRemoved — updates membership but no ReshareJob creation) |
| `node/node.go` | Current Node struct (no reshare fields yet) |
| `node/keymanager.go` | KeyManager interface (no Reshare method yet) |

## Architecture boundary

```
┌─────────────────────────────────────────────────────────┐
│  This spec: reshare_lifecycle.qnt                        │
│                                                          │
│  Chain events → ReshareJob → coordinator/on-demand       │
│  → stale key check → sign blocking                       │
│                                                          │
│  Calls km.Reshare(groupID, keyID, job) → success/fail   │
└──────────────────────────┬──────────────────────────────┘
                           │ KeyManager interface
                           │ (node/keymanager.go)
              ┌────────────┴────────────┐
              │                         │
   ┌──────────▼──────────┐  ┌──────────▼──────────┐
   │  LocalKeyManager    │  │  RemoteKeyManager   │
   │  (in-process Go)    │  │  (gRPC → Rust KMS)  │
   │  tss/reshare.go     │  │  kms-frost/         │
   │                     │  │                     │
   │  frost_reshare.qnt  │  │  (same protocol,    │
   │  models this layer  │  │   different runtime) │
   └─────────────────────┘  └─────────────────────┘
```

The lifecycle spec treats key reshare as an opaque operation: pick a key, start the reshare, get notified when it's done. This is intentional — the same orchestration logic applies regardless of whether FROST rounds run in-process (Go) or over gRPC (Rust KMS). The `KeyManager` interface will gain a `Reshare` method alongside this orchestration code.

## What is modeled

### State machine

```
ACTIVE ─── chain event (add/remove) ──> RESHARING
  ^                                        │
  │                                        │ new chain event while resharing
  │                                        v
  │                                     enqueue to deferredEvents
  │                                        │
  └──── all keys done ─────────────────────┘
              │
              └─ if deferred events: process next -> RESHARING again
```

### Key concepts

| Concept | Model | Design doc reference |
|---------|-------|---------------------|
| Group phase | `Active` / `Resharing` sum type | Section 4 |
| ReshareJob | Record with old/new parties, keysTotal, deferredEvents | Section 5.1 |
| Stale key check | `job exists AND key in keysTotal AND key not in keysDone` | Section 5.3 |
| Coordinator | `CoordStatus` sum type (NotCoordinator / Coordinating(n)) | Section 8.3 |
| On-demand reshare | Sign handler triggers reshare for specific stale key | Section 8.4 |
| Deferred events | Membership changes during reshare queued in job | Section 10.4 |
| Keygen during reshare | New key not in `keysTotal`, immediately signable | Section 5.1 ("born into new committee") |
| Sign blocking | `trySigning` returns `SignBlocked(keyId)` for stale keys | Section 8.2 |

### Abstraction choices

| Aspect | Model | Design doc reality |
|--------|-------|-------------------|
| Reshare per key | Instant (pick -> in-flight -> done) | 3-round cryptographic protocol via tss.Run() |
| Concurrency | Tracked as int, not enforced by semaphore | `sem = make(chan struct{}, concurrency)` |
| Storage | In-memory State record | bbolt buckets (`reshare_jobs/`, `reshare_done/`) |
| Time | Not modeled (no timestamps) | `StartedAt`, `DetectedAt`, `CompletedAt` fields |
| Retries | Not modeled | 3 retries with exponential backoff (1s, 4s, 16s) |
| Multi-node | Single node's local view | Each node maintains independent state |

## Components

| Category | Count | Description |
|----------|------:|-------------|
| Types | 10 | `GroupPhase`, `EventType`, `DeferredEvent`, `ReshareJob`, `CoordStatus`, `KeyReshareStatus`, `SignResult`, `State`, `GroupID`, `KeyID` |
| Pure functions | 11 | Event processing, job creation, stale key check, coordinator management, sign attempt, job completion |
| Actions | 9 | `init`, chain events (x2), API start, coord pick key, key complete, on-demand, finish job, keygen during reshare |
| Invariants | 11 | Safety properties (see below) |
| Witnesses | 4 | Reachability checks |
| Tests | 5 | Normal lifecycle, deferred events, on-demand reshare, keygen during reshare, duplicate coordinator |

## Safety invariants

| Invariant | Property |
|-----------|----------|
| `phaseJobConsistency` | ACTIVE iff no active job; RESHARING iff keysTotal non-empty |
| `keysDoneSubset` | keysDone is always a subset of job.keysTotal |
| `keysInFlightSubset` | keysInFlight is always a subset of stale keys |
| `activeNoInFlight` | No keys in flight when group is ACTIVE |
| `activeNoDone` | No keys marked done when group is ACTIVE |
| `activeNotCoordinating` | Coordinator status is NotCoordinator when ACTIVE |
| `freshKeysSignable` | Non-stale keys always return SignOK |
| `staleKeysBlock` | Stale keys always return SignBlocked |
| `newKeysNotStale` | Keys not in job.keysTotal are never stale |
| `keysTotalSnapshot` | job.keysTotal is a subset of the group's keys |
| `membershipAboveThreshold` | Group always has at least threshold members |

## Tests

| Test | Scenario |
|------|----------|
| `normalLifecycleTest` | N4 added -> RESHARING -> coordinator reshares K1, K2, K3 -> ACTIVE. Verifies progressive signing availability. |
| `deferredEventTest` | N4 added -> RESHARING -> N2 removed (deferred) -> complete first job -> auto-creates second job for N2 removal. |
| `onDemandReshareTest` | N4 added -> RESHARING -> sign for K2 triggers on-demand reshare (no coordinator) -> K2 signable, others still stale. |
| `keygenDuringReshareTest` | N4 added -> RESHARING -> keygen creates "key4" -> new key is not stale, immediately signable. |
| `duplicateCoordinatorTest` | Start coordinator -> second start attempt fails (409 semantics). |

## Running

```bash
# Type check
quint typecheck specs/reshare_lifecycle.qnt

# Run tests
quint test specs/reshare_lifecycle.qnt

# Simulate with safety invariant
quint run specs/reshare_lifecycle.qnt --max-steps=30 --max-samples=500 --invariant=safety

# Check witnesses (should find violations = states are reachable)
quint run specs/reshare_lifecycle.qnt --max-steps=20 --invariant=neverResharing
quint run specs/reshare_lifecycle.qnt --max-steps=30 --invariant=neverProcessesDeferred
```

## Relationship to other specs

- **frost_reshare.qnt** — Models the cryptographic protocol that runs *inside* the KeyManager (whether LocalKeyManager or RemoteKeyManager). This lifecycle spec abstracts that to "key in-flight -> key done" — the KeyManager boundary.
- Together they cover the full reshare stack: lifecycle manages **which** keys need resharing and **when** (node layer, above KeyManager); frost_reshare models **how** each key is reshared (tss/KMS layer, below KeyManager).
- The two specs are intentionally independent — you can verify lifecycle properties without modeling FROST rounds, and vice versa.

## Possible extensions

- **Multi-node view** — Model multiple nodes with independent lifecycle state to verify they converge (each creates the same ReshareJob from the same chain events).
- **Dual coordinator** — Model two nodes both calling `POST /v1/reshare` and the NACK-and-skip resolution (design doc section 10.1).
- **Node restart recovery** — Model crash + restart: read `reshare_jobs` from bbolt, resume from `reshare_done` progress.
- **Concurrency enforcement** — Model the semaphore cap (`max(1, 60/groupSize)`) and verify keys-in-flight never exceeds it.
