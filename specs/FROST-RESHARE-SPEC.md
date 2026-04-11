# FROST Reshare Protocol — Quint Specification

Formal model of the 3-round FROST key reshare protocol. The specification is derived from both the implementation (`tss/reshare.go`, 565 lines) and the design document (`docs/DESIGN-RESHARE.md`). It captures the cryptographic round structure, party roles, message flow, and safety invariants in [frost_reshare.qnt](frost_reshare.qnt).

## Sources

| Source | What it informed |
|--------|-----------------|
| `tss/reshare.go` | Round structure (`reshareRound1/2/3`), message payloads (`reshareCommitPayload`, `reshareEvalPayload`, `resharePubSharePayload`), self-evaluation for "Both" parties, combined VSS commitment, RID computation, sentinel Config shape, duplicate rejection |
| `tss/config.go` | `Config` struct fields (Generation, GroupKey, PartyMap, ChainKey, RID, KeyShareBytes) |
| `node/coord.go` | `coordMsg` structure (msgReshare type 3 planned but not yet implemented) |
| `docs/DESIGN-RESHARE.md` | Protocol overview, roles table, group state machine, storage schema, edge cases |

## Implementation status

The TSS cryptographic layer (`tss/reshare.go`) is **fully implemented**. The node-level orchestration is not yet built:

| Component | Status | File |
|-----------|--------|------|
| TSS reshare rounds 1-3 | Done | `tss/reshare.go` |
| Coord `msgReshare` handler | Not started | `node/coord.go` (only keygen/sign) |
| ReshareJob storage (bbolt) | Not started | — |
| `/v1/reshare` API endpoints | Not started | — |
| Stale key check in sign handler | Not started | — |
| KMS reshare | Stub (`unimplemented`) | `kms-frost/src/service.rs:83` |

## What is modeled

The reshare protocol allows a signing group to rotate its membership (add/remove nodes, change threshold) without changing the group public key. Old key shares are cryptographically superseded; existing signatures remain valid.

### Parties and roles

The spec uses four parties to cover all role combinations:

| Party | Old committee | New committee | Role |
|-------|:---:|:---:|------|
| P1 | yes | no | OldOnly — broadcasts commitments, sends sub-shares, exits after Round 2 |
| P2 | yes | yes | Both — full participation in all 3 rounds |
| P3 | yes | yes | Both |
| P4 | no | yes | NewOnly — receives commitments and sub-shares, builds new config |

### Protocol rounds

```
Round 1    Old parties broadcast Feldman commitments + chain key contributions
           All parties verify: sum of commitment constant terms == group public key
           (code: reshareRound1.Finalize lines 256-267)

Round 1->2 Old parties unicast sub-share evaluations f_i(x_j) to each new party
           EXCEPT self — "Both" parties skip self-send (code: line 272-274)

Round 2    New parties verify sub-shares via Feldman (code: reshareRound2.Receive line 364)
           "Both" parties compute own sub-share locally via polynomial.Evaluate()
           (code: reshareRound2.Finalize lines 380-385 — no network message)
           New parties combine: newSecret_j = sum_i f_i(x_j) (lines 393-397)
           New parties compute combined VSS commitment (element-wise sum, lines 403-410)
           New parties broadcast public key shares
           Old-only parties exit with sentinel Config{ID, Generation+1, GroupKey}
           (code: lines 451-456 — only these 3 fields populated)

Round 3    New parties collect all pub shares (own pre-seeded at entry, line 447)
           Chain key: SHA256(ck_1 || ... || ck_N) in sorted key order (lines 513-517)
           RID: SHA256(chainKey) (line 518)
           Build final tss.Config with all fields (lines 520-532)
```

### Abstraction choices

| Aspect | Model | Code reality |
|--------|-------|--------------|
| Scalars / group elements | `int` | `ecc.Scalar` / `ecc.Element` on secp256k1 (`groupSecp256k1`) |
| Feldman commitments | `List[int]` | `[]*ecc.Element` from `secretsharing.Commit()` |
| VSS verification | Non-zero check | `secretsharing.Verify(secp256k1, id, pubKey, commitments)` |
| Polynomial evaluations | Constant lookup table | `polynomial.Evaluate(newID)` on random polynomial |
| Self-evaluation (Both) | Local computation in `finishRound2` | `polynomial.Evaluate(myNewID)` — no self-message |
| Combined VSS commitment | Abstract `[sum]` | Element-wise sum: `sum.Add(allCommitments[p][k])` |
| Chain key combination | Integer sum | `sha256.New()` over sorted chain key bytes |
| RID | `chainKey + 1` (abstract) | `sha256.Sum256(combinedChainKey)` |
| Duplicate rejection | Map key overwrite (idempotent) | Explicit `if _, dup := received[from]; dup { return error }` |
| Network | Reliable, unordered set | libp2p direct streams with session scoping |
| Byzantine behavior | Not modeled | Out of scope (honest-majority assumption) |
| Old-only sentinel Config | `{newGeneration, configBuilt}` | `Config{ID, Generation, GroupKey}` — KeyShareBytes nil |
| CBOR encoding | Not modeled | `cbor.Marshal/Unmarshal` for all payloads |

## Components

| Category | Count | Description |
|----------|------:|-------------|
| Types | 9 | `Role`, `Phase`, `CommitMsg`, `EvalMsg`, `PubShareMsg`, `Message`, `PartyState`, `State`, `PartyID` |
| Pure functions | 16 | Role determination, message processing, round transitions, Feldman verification, share combination |
| Actions | 10 | `init`, round start/complete (x3), message delivery (x3), nondeterministic `step` |
| Invariants | 13 | Safety properties (see below) |
| Witnesses | 3 | Reachability checks |
| Tests | 2 | Full reshare scenario, old-only early exit |

## Safety invariants

| Invariant | Property | Code reference |
|-----------|----------|----------------|
| `groupKeyPreserved` | All commit messages report the same group public key | `reshareRound1.Finalize:265` — `commitSum.Equal(groupKeyElem)` |
| `generationConsistency` | All done parties agree on the new generation number | `reshareRound3.Finalize:524` — `Generation: r.generation + 1` |
| `generationIncremented` | New generation = old generation + 1 | Same line; propagated from Round 1 broadcasts |
| `oldOnlySentinel` | Old-only parties produce a sentinel config with no new secret | `reshareRound2.Finalize:452-456` — nil KeyShareBytes |
| `newPartiesHaveShares` | New parties have a non-zero secret share when done | `reshareRound2.Finalize:393-397` — combined sub-shares |
| `oldOnlySkipsRound3` | Old-only parties never enter Round 3 | `reshareRound2.Finalize:451` — returns config directly |
| `onlyNewPartiesInRound3` | Only new parties can be in Round 3 | Same control flow |
| `evalsOnlyToNewParties` | Sub-share eval messages are addressed only to new parties | `reshareRound1.Finalize:271` — iterates `newParties` |
| `commitsOnlyFromOldParties` | Commit messages originate only from old parties | `reshareRound1.Receive:127` — rejects non-old senders |
| `pubSharesOnlyFromNewParties` | Public key share messages originate only from new parties | `reshareRound3.Receive:479` — rejects non-new senders |
| `chainKeyConsistency` | All new parties that finish compute the same chain key | `reshareRound3.Finalize:513-517` — deterministic sorted hash |
| `ridConsistency` | All new parties that finish compute the same RID | `reshareRound3.Finalize:518` — `SHA256(chainKey)` |
| `bothPartiesSelfEval` | "Both" parties have their own sub-share when done | `reshareRound2.Finalize:380-385` — local `polynomial.Evaluate` |

## Running

```bash
# Type check
quint typecheck specs/frost_reshare.qnt

# Run tests (full reshare + old-only early exit)
quint test specs/frost_reshare.qnt

# Simulate with safety invariant (random exploration)
quint run specs/frost_reshare.qnt --max-steps=30 --max-samples=500 --invariant=safety

# Check a witness (should find a violation = protocol can complete)
quint run specs/frost_reshare.qnt --max-steps=30 --invariant=allPartiesNotDone
```

## Possible extensions

- **Byzantine behavior** — Model equivocation (old party sends different commitments to different receivers) or wrong group key to test safety under adversarial conditions. The code does explicit Feldman verification (`secretsharing.Verify`) and group key sum check that would catch this.
- **Group reshare lifecycle** — Model the ACTIVE -> RESHARING -> ACTIVE state machine with deferred events, coordinator/on-demand paths, and key staleness tracking. This is the node-level orchestration described in `docs/DESIGN-RESHARE.md` sections 4, 8 that is not yet implemented.
- **Concurrent reshares** — Model the dual-coordinator edge case (section 10.1 of the design doc) with NACK-and-skip behavior via `reshareNonce`-based session ID disambiguation.
- **Network faults** — Add message loss or reordering to verify liveness properties. The code uses 30-second session timeouts with 3 retries and exponential backoff.
- **KMS integration** — Model the gRPC boundary between the Go node (message router) and Rust KMS (crypto oracle) for when `SessionType::Reshare` is implemented in `kms-frost/src/service.rs`.
