# Reshare Protocol

Models for key reshare, split into two independent layers connected by the `KeyManager` interface boundary.

```
lifecycle.qnt          reshare.qnt
(node orchestration)           (cryptographic protocol)
                  \               /
                   \             /
                    KeyManager interface
                   (node/keymanager.go)
```

The lifecycle spec manages **which** keys need resharing and **when**. The reshare spec models **how** each key is reshared. They are intentionally independent: you can verify lifecycle properties without modeling the cryptographic rounds, and vice versa.

## Files

| File | Layer | What it models |
|------|-------|----------------|
| `reshare.qnt` | TSS / KMS | 3-round cryptographic reshare protocol |
| `lifecycle.qnt` | Node | Per-group ACTIVE/RESHARING state machine |
| `test.qnt` | -- | Deterministic scenario tests for both specs |

## Implementation status

| Component | Status | File |
|-----------|--------|------|
| TSS reshare rounds 1-3 | Done | `tss/reshare.go` |
| Coord `msgReshare` handler | Not started | `node/coord.go` |
| ReshareJob storage (bbolt) | Not started | -- |
| `/v1/reshare` API endpoints | Not started | -- |
| Stale key check in sign handler | Not started | -- |
| KMS reshare | Stub | `kms-frost/src/service.rs` |

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

## lifecycle.qnt -- Node Orchestration (not yet implemented)

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
quint typecheck reshare.qnt
quint typecheck lifecycle.qnt

quint test test.qnt --main=reshare_test
quint test test.qnt --main=lifecycle_test

# Simulation with safety invariants
quint run reshare.qnt --max-steps=30 --max-samples=500 --invariant=safety
quint run lifecycle.qnt --max-steps=30 --max-samples=500 --invariant=safety

# Witnesses (should find violations, confirming reachability)
quint run reshare.qnt --max-steps=30 --invariant=allPartiesNotDone
quint run lifecycle.qnt --max-steps=20 --invariant=neverResharing

# Exhaustive model checking (requires apalache-mc)
quint verify reshare.qnt --invariant=safety
quint verify lifecycle.qnt --invariant=safety
```

## Possible extensions

- **Byzantine behavior** -- Model equivocation or wrong group key to test safety under adversarial conditions.
- **Dual coordinator** -- Model two nodes both calling `POST /v1/reshare` and the NACK-and-skip resolution.
- **Multi-node view** -- Model multiple nodes with independent lifecycle state to verify convergence.
- **Network faults** -- Add message loss or reordering to verify liveness properties.
- **Node restart recovery** -- Model crash + restart with resume from bbolt progress.
- **Concurrency enforcement** -- Model the semaphore cap and verify keys-in-flight bounds.
