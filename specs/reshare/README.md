# Reshare Protocol

Models for key reshare at three layers: cryptographic protocol, single-node lifecycle, and multi-node cluster.

```
cluster.qnt                   (system-wide, multi-node)
    |
    |  contains as internal abstraction
    v
lifecycle.qnt          reshare.qnt
(single-node view)             (cryptographic protocol)
                  \               /
                   \             /
                    KeyManager interface
                   (node/keymanager.go)
```

- **`cluster.qnt`** is the coherent system-wide model for reasoning about the hardening-doc invariants (I1–I9). It models multiple nodes with per-node local state, a canonical chain, per-key share state across nodes (with a pending/committed distinction), leader election, crash/recover, and nondeterministic partial-failure outcomes for reshare attempts.
- **`lifecycle.qnt`** is the single-node view of orchestration bookkeeping. Useful for reasoning about a single node's ACTIVE/RESHARING transitions in isolation but cannot express cross-node invariants.
- **`reshare.qnt`** models the 3-round FROST reshare cryptographic protocol independently of any orchestration layer.

The cluster spec supersedes the lifecycle spec for reasoning about hardening-doc invariants. The lifecycle spec remains useful as a reference for single-node bookkeeping logic.

## Files

| File | Layer | What it models |
|------|-------|----------------|
| `cluster.qnt` | System | Multi-node lifecycle with per-key share state and commit atomicity |
| `reshare.qnt` | TSS / KMS | 3-round cryptographic reshare protocol |
| `lifecycle.qnt` | Single-node | Per-group ACTIVE/RESHARING bookkeeping (single-node view) |
| `test.qnt` | -- | Deterministic scenario tests for reshare.qnt and lifecycle.qnt |

## Implementation status

| Component | Status | File |
|-----------|--------|------|
| TSS reshare rounds 1-3 | Done | `tss/reshare.go` |
| Coord `msgReshare` handler | Not started | `node/coord.go` |
| ReshareJob storage (bbolt) | Not started | -- |
| `/v1/reshare` API endpoints | Not started | -- |
| Stale key check in sign handler | Not started | -- |
| KMS reshare | Stub | `kms-tss/src/service.rs` |

---

## reshare.qnt -- Cryptographic Protocol

Derived from `tss/reshare.go` and `docs/DESIGN-RESHARE.md`. Models the 3-round protocol where old committee members redistribute their key shares to a new committee using Lagrange-weighting and Feldman VSS, preserving the group public key.

### Parties and roles

The spec uses four parties to cover all role combinations:

| Party | Old | New | Role |
|-------|:---:|:---:|------|
| P1 | yes | no | OldOnly -- broadcasts commitments, sends sub-shares, exits after Round 2 |
| P2 | yes | yes | Both -- full participation in all 3 rounds |
| P3 | yes | yes | Both |
| P4 | no | yes | NewOnly -- receives commitments and sub-shares, builds new config |

### Protocol rounds

```
Round 1      Old parties broadcast Feldman commitments + chain key contributions.
             All parties verify: sum of commitment constant terms == group public key.

Round 1->2   Old parties unicast sub-share evaluations f_i(x_j) to each new party.
             "Both" parties skip self-send (compute own sub-share locally).

Round 2      New parties verify sub-shares via Feldman.
             New parties combine: newSecret_j = sum_i f_i(x_j).
             New parties compute combined VSS commitment and broadcast public key shares.
             Old-only parties exit with sentinel Config{ID, Generation+1, GroupKey}.

Round 3      New parties collect all pub shares.
             Chain key: SHA256(ck_1 || ... || ck_N) in sorted order.
             RID: SHA256(chainKey).
             Build final tss.Config.
```

### Abstraction choices

| Aspect | Model | Code reality |
|--------|-------|--------------|
| Scalars / group elements | `int` | `ecc.Scalar` / `ecc.Element` on secp256k1 |
| Feldman commitments | `List[int]` | `[]*ecc.Element` from `secretsharing.Commit()` |
| VSS verification | Non-zero check | `secretsharing.Verify(secp256k1, id, pubKey, commitments)` |
| Polynomial evaluations | Constant lookup table | `polynomial.Evaluate(newID)` on random polynomial |
| Self-evaluation (Both) | Local computation in `finishRound2` | `polynomial.Evaluate(myNewID)`, no self-message |
| Chain key combination | Integer sum | `sha256.New()` over sorted chain key bytes |
| RID | `chainKey + 1` | `sha256.Sum256(combinedChainKey)` |
| Network | Reliable, unordered set | libp2p direct streams with session scoping |
| Byzantine behavior | Not modeled | Honest-majority assumption |

### Safety invariants (13)

| Invariant | Property |
|-----------|----------|
| `groupKeyPreserved` | All commit messages report the same group public key |
| `generationConsistency` | All done parties agree on the new generation number |
| `generationIncremented` | New generation = old generation + 1 |
| `oldOnlySentinel` | Old-only parties produce sentinel config with no new secret |
| `newPartiesHaveShares` | New parties have a non-zero secret share when done |
| `oldOnlySkipsRound3` | Old-only parties never enter Round 3 |
| `onlyNewPartiesInRound3` | Only new parties can be in Round 3 |
| `evalsOnlyToNewParties` | Sub-share eval messages addressed only to new parties |
| `commitsOnlyFromOldParties` | Commit messages originate only from old parties |
| `pubSharesOnlyFromNewParties` | Public key share messages originate only from new parties |
| `chainKeyConsistency` | All new parties compute the same chain key |
| `ridConsistency` | All new parties compute the same RID |
| `bothPartiesSelfEval` | "Both" parties have their own sub-share when done |

### Tests (2)

| Test | Scenario |
|------|----------|
| `fullReshareTest` | All 4 parties complete the full 3-round reshare |
| `oldOnlyExitsEarlyTest` | P1 (old-only) exits after Round 2 while others continue |

---

## cluster.qnt -- System-Wide View

Derived from `docs/DESIGN-RESHARE-HARDENING.md` invariants I1–I9. Models a multi-node reshare lifecycle where per-key state is distributed across nodes. This is the spec for reasoning about the hardening-doc invariants, which are fundamentally about cross-node agreement.

### What it models

- Multi-node view: each node has its own local state (`seenMembers`, `jobActive`, `shares`, `role`)
- Canonical chain state separate from node views (I9)
- Per-key share state across nodes with a **pending → committed** distinction (I2)
- Atomic commit across all new-committee members via action preconditions (I1)
- Leader election + crash + recovery (I7)
- Nondeterministic partial-failure outcomes for reshare attempts (`AttemptAllSucceed`, `AttemptPartialFail(set)`, `AttemptAllFail`)
- Job-view matching: a node participates in an attempt only if its local job view matches the leader's (models the coord handler's ACK/NACK behavior)

### Per-node per-key share state

Five distinct situations a node can be in for a given key:

| State | Meaning |
|-------|---------|
| `NoShare` | Never held a share (or old-only after sentinel drop) |
| `OldShare` | Has the committed share from a previous reshare |
| `OldAndPending` | Both-committee node mid-reshare: has old + uncommitted new |
| `OnlyPending` | New-only node mid-reshare: has only uncommitted new |
| `NewCommitted` | Has only the new committed share (post-verification) |

### Reshare attempt outcomes

A reshare attempt is a single action with a nondeterministic outcome:

| Outcome | Effect |
|---------|--------|
| `AttemptAllSucceed` | Every eligible new-committee member advances to pending |
| `AttemptPartialFail(set)` | Named nodes fail (stay pre-reshare), others advance to pending |
| `AttemptAllFail` | No node advances; attempt can be retried |

The step function explores all three outcomes, letting the model check that partial-failure states cannot result in data loss or inconsistent commits.

### Safety invariants

| Invariant | Property | Hardening doc |
|-----------|----------|---------------|
| `ownViewConsistent` | Within a node's view of its job, no partial commit: if one same-view node is NewCommitted, all are | I1 (state-level sanity) |
| `oldSharesRetained` | No initial-committee node has NoShare for a key unless a commit has happened for it | I2 |
| `singleLeader` | At most one live node holds the `Leader` role at a time | I6 |
| `jobTracesToChain` | Every active job's committee diff traces back to a chain event | I9 |
| `exclusiveShareStates` | No node holds pending and committed simultaneously | structural |

I1 atomicity is also enforced at the **action level** by `commitKey`'s precondition: every new-committee member must be alive, have a matching job view, and hold a pending share for the key. This means commit is a group-atomic transition — no partial commits are reachable by construction.

The `leaderPossible` check (I7 precondition) is **not** in the safety bundle because crashes of all old∩new intersection members can violate it — that's a system-level failure requiring operator intervention, not a protocol bug. It's preserved as an auxiliary check.

### Witnesses (reachability)

| Witness | Verifies |
|---------|----------|
| `neverJobActive` | Nodes can enter an active job state |
| `neverFullyCommitted` | Keys can progress to NewCommitted across the new committee |
| `neverBackToIdleWithNewShares` | Jobs can complete and return to idle with new shares |
| `neverPartialPending` | Partial-failure (some pending, some not) is reachable |
| `neverLeaderElected` | Leader election fires |

All witnesses are reachable at depth 80 with 5000 samples.

### Results

```
quint run cluster.qnt --main=cluster --max-steps=100 --max-samples=10000 --invariant=safety
[ok] No violation found
```

---

## lifecycle.qnt -- Node Orchestration (single-node view)

Derived from `docs/DESIGN-RESHARE.md` sections 4-8. Models the per-group state machine that manages reshare jobs triggered by on-chain membership changes. This spec is ahead of the implementation.

Backend-agnostic: the same state machine applies whether the underlying `KeyManager` is `LocalKeyManager` (in-process Go) or `RemoteKeyManager` (gRPC to Rust KMS). Key reshare is treated as an opaque `in-flight -> done` transition.

### State machine

```
ACTIVE --- chain event (add/remove) --> RESHARING
  ^                                        |
  |                                        | new chain event while resharing
  |                                        v
  |                                     enqueue to deferredEvents
  |                                        |
  +---- all keys done ---------------------+
              |
              +- if deferred events: process next -> RESHARING again
```

### Key concepts

| Concept | Model | Design doc |
|---------|-------|------------|
| Group phase | `Active` / `Resharing` sum type | Section 4 |
| ReshareJob | Record with old/new parties, keysTotal, deferredEvents | Section 5.1 |
| Stale key check | `job exists AND key in keysTotal AND key not in keysDone` | Section 5.3 |
| Coordinator | `CoordStatus` sum type (`NotCoordinator` / `Coordinating(n)`) | Section 8.3 |
| On-demand reshare | Sign handler triggers reshare for specific stale key | Section 8.4 |
| Deferred events | Membership changes during reshare queued in job | Section 10.4 |
| Keygen during reshare | New key not in `keysTotal`, immediately signable | Section 5.1 |
| Sign blocking | `trySigning` returns `SignBlocked(keyId)` for stale keys | Section 8.2 |

### Safety invariants (11)

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

### Tests (5)

| Test | Scenario |
|------|----------|
| `normalLifecycleTest` | N4 added, coordinator reshares K1-K3, returns to ACTIVE |
| `deferredEventTest` | N4 added, N2 removed (deferred), first job completes, second job auto-created |
| `onDemandReshareTest` | Sign handler triggers on-demand reshare for stale key |
| `keygenDuringReshareTest` | New key created during reshare is immediately signable |
| `duplicateCoordinatorTest` | Second coordinator start returns 409 |

---

## Running

```bash
quint typecheck cluster.qnt
quint typecheck reshare.qnt
quint typecheck lifecycle.qnt

quint test test.qnt --main=reshare_test
quint test test.qnt --main=lifecycle_test

# Simulation with safety invariants
quint run cluster.qnt --main=cluster --max-steps=100 --max-samples=10000 --invariant=safety
quint run reshare.qnt --max-steps=30 --max-samples=500 --invariant=safety
quint run lifecycle.qnt --max-steps=30 --max-samples=500 --invariant=safety

# Witnesses (should find violations, confirming reachability)
quint run cluster.qnt --main=cluster --max-steps=80 --max-samples=5000 --invariant=neverFullyCommitted
quint run reshare.qnt --max-steps=30 --invariant=allPartiesNotDone
quint run lifecycle.qnt --max-steps=20 --invariant=neverResharing

# Exhaustive model checking (requires apalache-mc)
quint verify cluster.qnt --invariant=safety
quint verify reshare.qnt --invariant=safety
quint verify lifecycle.qnt --invariant=safety
```

## Possible extensions

- **Byzantine behavior** -- Model equivocation or wrong group key to test safety under adversarial conditions.
- **Completion verification broadcast** -- Model the `msgReshareComplete` broadcast and its failure modes (currently fire-and-forget in the implementation).
- **Atomic swap** -- Model the `swapNode(old, new)` event type from the hardening doc's atomic-swap section.
- **Network faults** -- Add message loss or reordering to verify liveness properties.
- **Coordinator election protocol** -- Model an explicit leader election algorithm rather than the current "first-to-claim" semantics.
- **Generation tracking** -- Add per-key generation numbers to enable finer-grained atomicity checks across historical commits.
