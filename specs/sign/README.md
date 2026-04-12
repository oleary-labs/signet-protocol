# Sign Protocol

Model of the 2-round threshold signing protocol (RFC 9591 orchestration layer). Corresponds to the Go implementation in `tss/sign.go`.

## What is modeled

The spec covers message delivery patterns, quorum logic, and agreement properties. Nonces, commitments, and partial signatures are abstract integers. The cryptographic correctness is proven in RFC 9591; the model verifies that the round structure preserves safety under arbitrary interleaving.

**State:** Per-signer local phase (`Idle`, `Committed`, `SignShareSent`, `Done`), nonces, and result. A global monotonic message set models the network.

**Actions:**

| Action | Round | What happens |
|--------|-------|-------------|
| `commit(p)` | 1 | Signer generates a nonce and broadcasts a commitment |
| `produceShare(p)` | 1 -> 2 | After receiving all commitments, broadcasts a partial signature |
| `aggregate(p)` | 2 | After receiving all shares, computes the final signature |

The `step` action picks a signer and action non-deterministically, exploring all possible message orderings.

## Files

- `sign.qnt` — Protocol model and safety invariants. Includes a `sign_3of3` instance for simulation.
- `test.qnt` — Deterministic scenario tests: happy path, interleaved commit order, commitment completeness, message counts, and a 2-of-3 threshold subset test.

## Safety invariants

| Invariant | Type | Property |
|-----------|------|----------|
| `agreement` | safety | All signers that complete produce the same signature |
| `quorumRequired` | safety | No signer completes without collecting all shares |
| `noPhantomShares` | safety | Every share in the network came from a coalition member |
| `noPhantomCommitments` | safety | Every commitment came from a coalition member |
| `commitmentCompleteness` | safety | No share is produced without first seeing all commitments |
| `atMostOneCommitPerSigner` | safety | Each signer commits exactly once |
| `atMostOneSharePerSigner` | safety | Each signer produces exactly one share |
| `nobodyDone` | witness | Expected to be violated, confirming signing can complete |

## Running

```bash
quint typecheck sign.qnt
quint test test.qnt --main=sign_test
quint test test.qnt --main=sign_threshold_test

# Random simulation with invariant checking
quint run sign.qnt --main=sign_3of3 --invariant=agreement --max-steps=20
quint run sign.qnt --main=sign_3of3 --invariant=quorumRequired --max-steps=20

# Witness: confirm signing completes (should find a violation)
quint run sign.qnt --main=sign_3of3 --invariant=nobodyDone --max-steps=20

# Exhaustive model checking (requires apalache-mc)
quint verify sign.qnt --main=sign_3of3 --invariant=agreement
```
