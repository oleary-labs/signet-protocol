# Keygen Protocol

Model of the 3-round DKG (Distributed Key Generation) protocol on secp256k1. Corresponds to the Go implementation in `tss/keygen.go`. All parties are symmetric (no old/new role split). Uses Feldman VSS via `bytemare/dkg`, driven by `tss.Run()`.

## What is modeled

The spec covers the orchestration layer: message delivery patterns, round structure, quorum logic, and agreement properties. DKG round data, key shares, and group keys are abstract integers. The cryptographic correctness is provided by the bytemare/dkg library; the model verifies that the round structure preserves safety under arbitrary interleaving.

## Parties

All parties are symmetric. The spec uses a 3-party, threshold-2 configuration:

| Party | Role |
|-------|------|
| P1 | Full participant |
| P2 | Full participant |
| P3 | Full participant |

## Protocol rounds

```
Round 1      All parties broadcast DKG Round1Data + chain key contribution.
             Each party stores own R1 locally (no self-message on network).
             Wait for all N broadcasts.

Round 1->2   All parties send unicast DKG Round2Data to each peer (not self).

Round 2      All parties collect N-1 R2 messages from peers.
             Each party calls DKG Finalize to derive keyShare, groupKey, pubKeyShare.
             Each party pre-loads own pub share and broadcasts it for R3.

Round 3      All parties collect N pub shares.
             Chain key: SHA256(ck_1 || ... || ck_N) in sorted party order.
             RID: SHA256(chainKey).
             Build Config with Generation=0.
```

## Files

| File | What it contains |
|------|------------------|
| `keygen.qnt` | Protocol model, invariants, witnesses |
| `test.qnt` | Deterministic scenario tests |

## Abstraction choices

| Aspect | Model | Code reality |
|--------|-------|--------------|
| DKG round data | `int` | `dkg.Round1Data` / `dkg.Round2Data` from bytemare |
| Key shares | `int` | `keys.KeyShare` (secp256k1 scalar) |
| Group key | `int` | 33-byte compressed secp256k1 point |
| Public key shares | `int` | `keys.PublicKeyShare` (compressed point) |
| Chain key combination | Integer sum | `sha256.New()` over sorted chain key bytes |
| RID | `chainKey + 1` | `sha256.Sum256(combinedChainKey)` |
| Self R1 delivery | Stored locally in `prepareRound1` | `keygenRound1.Finalize` stores in `r1Broadcasts[self]` |
| Self pub share | Pre-loaded in `finishRound2` | `keygenRound2.Finalize` stores in `pubShares[self]` |
| Network | Reliable, unordered set | libp2p direct streams with session scoping |
| Byzantine behavior | Not modeled | Honest-majority assumption |

## Safety invariants (12)

| Invariant | Property |
|-----------|----------|
| `groupKeyConsistency` | All done parties agree on the group key |
| `generationZero` | All done parties have generation == 0 |
| `chainKeyConsistency` | All done parties compute the same chain key |
| `ridConsistency` | All done parties compute the same RID |
| `allPartiesHaveShares` | All done parties have non-zero key shares |
| `allPartiesHaveConfig` | All done parties have configBuilt == true |
| `r1OnlyFromParties` | R1 messages only from valid parties |
| `r2OnlyToParties` | R2 messages only addressed to valid parties |
| `r2NeverToSelf` | No party sends R2 to itself |
| `pubSharesOnlyFromParties` | Pub share messages only from valid parties |
| `atMostOneR1PerParty` | Each party broadcasts R1 at most once |
| `atMostOnePubSharePerParty` | Each party broadcasts pub share at most once |

## Witnesses

| Witness | Expected |
|---------|----------|
| `allPartiesNotDone` | Violated (confirms protocol can complete) |
| `noPartyHasConfig` | Violated (confirms config is built) |

## Tests

| Test | Scenario |
|------|----------|
| `happyPathTest` | All 3 parties complete keygen in order, verify all Config fields |
| `interleavedOrderTest` | Parties start in different order (P3, P1, P2), same result |
| `agreementTest` | Pairwise equality of groupKey, chainKey, RID; uniqueness of key shares |

## Running

```bash
quint typecheck keygen.qnt
quint test test.qnt --main=keygen_test

# Simulation with safety invariant
quint run keygen.qnt --max-steps=30 --max-samples=500 --invariant=safety

# Witnesses (should find violations, confirming reachability)
quint run keygen.qnt --max-steps=30 --invariant=allPartiesNotDone
quint run keygen.qnt --max-steps=30 --invariant=noPartyHasConfig

# Exhaustive model checking (requires apalache-mc)
quint verify keygen.qnt --invariant=safety
```

## Possible extensions

- **Byzantine behavior** -- Model equivocation (party sends different R1 to different receivers) to test safety under adversarial conditions.
- **Threshold subset signing** -- Compose with the sign spec to verify that keygen output enables threshold signing.
- **Network faults** -- Add message loss or reordering to verify liveness properties.
- **Variable group sizes** -- Parameterize the module to test 2-of-3, 3-of-5, etc.
