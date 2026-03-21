# LSS Protocol Security

Security analysis and hardening status of the `signet/lss` threshold signing implementation.

---

## Fixes Applied

### 1. Nonce Commitment Phase (Schnorr Signing)

**Problem:** The original Schnorr signing protocol broadcast nonce points `K_i = k_i*G` directly in round 1. A malicious party could observe others' nonce points and adaptively choose its own nonce to manipulate the combined nonce `R = sum(K_i)`. This is the classic rogue-key / adaptive nonce attack on multi-party Schnorr.

**Fix:** Added a commit-reveal phase. The protocol is now 4 rounds:

| Round | Type      | Payload           | Purpose                          |
|-------|-----------|-------------------|----------------------------------|
| 1     | Broadcast | `H(K_i)`          | Commit to nonce point            |
| 2     | Broadcast | `K_i`             | Reveal nonce, verify vs commit   |
| 3     | Broadcast | `s_i`             | Partial Schnorr signature        |
| 4     | Local     | —                 | Combine + verify                 |

Each party commits `SHA-256(K_i)` before any nonce point is revealed. Round 2 verifies that each revealed nonce matches its commitment. An adversary cannot adapt its nonce to others because it must commit before seeing any reveals.

**Files:** `lss/sign.go` — `schnorrCommitRound`, `schnorrRevealRound`, `schnorrPartialRound`, `schnorrCombineRound`

### 2. Signer Count Validation

**Problem:** `Sign()` and `SignECDSA()` accepted any signer subset size without checking against the threshold. An operator could accidentally call `Sign()` with fewer than `threshold` parties, producing an invalid (or trivially forgeable) signature.

**Fix:** Both `Sign()` and `SignECDSA()` now validate `len(signers) >= cfg.Threshold` before starting the protocol. Returns an immediate error if the check fails. Also validates that the caller's own ID is in the signer set.

**Files:** `lss/sign.go` (`Sign()`), `lss/sign_ecdsa.go` (`SignECDSA()`)

### 3. Zero R.x Guard

**Problem:** If all nonce points sum to a point with x-coordinate 0 mod N (astronomically unlikely but theoretically possible), computing `r.Inverse()` would produce undefined behavior or a panic.

**Fix:** After computing the combined nonce point `R` and extracting `r = R.x mod N`, the protocol now checks `r.IsZero()` and returns an explicit error. Applied to both Schnorr (round 2 Finalize) and ECDSA (round 2 Finalize, which also checks for zero `k`).

**Files:** `lss/sign.go` (`schnorrRevealRound.Finalize`), `lss/sign_ecdsa.go` (`ecdsaSignRound2.Finalize`)

### 4. Sender Validation and Duplicate Rejection

**Problem:** Round handlers did not validate `msg.From` against the expected party set. In a distributed deployment, an attacker could inject messages from unknown senders or send duplicate messages to overwrite legitimate ones.

**Fix:** Every `Receive()` method in keygen, sign (Schnorr + ECDSA), and reshare now:
1. Validates `msg.From` is in the expected participant set
2. Rejects duplicate messages from the same sender in the same round

Validation is performed under the mutex before any payload processing.

**Files:** `lss/sign.go`, `lss/sign_ecdsa.go`, `lss/keygen.go`, `lss/reshare.go`

---

## Remaining Issues

### Medium Priority

#### M1. No Replay / Domain Separation

Signatures do not bind to a chain ID, contract address, or session identifier. The same signature `(R, s)` for message `m` is valid in any context that verifies against the same group public key.

**Risk:** Cross-chain or cross-protocol replay attacks.

**Mitigation:** The calling layer (node/API) must include a domain separator in the message hash: `msgHash = SHA256(chainID || contractAddr || nonce || message)`. The `SignetAccount.sol` contract mitigates this for ERC-4337 via the EntryPoint's `userOpHash`, which includes chain ID and EntryPoint address.

#### M2. Chain Key Does Not Mix Sender Identity

Keygen and reshare combine chain keys via `SHA256(ck_1 || ... || ck_N)` without including sender party IDs. Two parties sending identical chain key values produce ambiguous hashing.

**Risk:** Low. Chain key is used for RID derivation, which is not cryptographically load-bearing in the current protocol.

**Fix:** Include sender IDs: `SHA256(id_1 || ck_1 || ... || id_N || ck_N)`.

#### M3. Generation Not Consensus-Validated in Reshare

Reshare round 3 takes the generation number from the first old party's broadcast without verifying that all old parties agree. A malicious old party could set a mismatched generation.

**Risk:** Low. Generation is a consistency aid, not a cryptographic parameter.

**Fix:** Validate all old parties report the same generation before accepting.

#### M4. Synchronous / No Timeouts

The session runner (`Run()`) blocks indefinitely if any participant goes silent. There is no timeout or recovery mechanism.

**Risk:** Liveness failure in production deployments.

**Fix:** The caller should use `context.WithTimeout()`. The `Run()` function already respects context cancellation.

### Low Priority

#### L1. SchnorrVerifier Formal Verification

The on-chain Schnorr verifier (`SchnorrVerifier.sol`) uses the ecrecover trick to verify threshold Schnorr signatures at ~12k gas. The derivation is:

```
Schnorr: s*G = R + e*P  where e = R.x * msgHash
Rearranged: P = (s/e)*G - (1/e)*R
ecrecover params: hash_ec = -(s * msgHash^-1), s_ec = -(msgHash^-1), r_ec = R.x, v = R.y parity + 27
```

This is empirically validated end-to-end (17 Foundry tests pass with real LSS-generated signatures) but should be formally proven or cited from a peer-reviewed source before production use.

#### L2. Horner's Method Not Constant-Time

Polynomial evaluation in `polynomial.go` uses Horner's method without constant-time guarantees. Not exploitable in the current protocol because evaluations are always on public party ID scalars, not secret values.

#### L3. ECDSA Collaborative Nonce Security

`SignECDSA()` uses a collaborative nonce approach where all signers learn the combined nonce `k`. Any single signer can extract the group private key: `a = r^-1 * (s*k - m)`. This is documented and `SignECDSA` is explicitly not the default signing path. The Schnorr path (`Sign()`) does not have this weakness.

---

## Adversary Model

| Property | Schnorr (`Sign`) | ECDSA (`SignECDSA`) |
|----------|-------------------|---------------------|
| Threshold security during signing | Yes — nonce scalar never revealed | No — collaborative nonce leaks `k` |
| Adaptive nonce resistance | Yes — commit-reveal in rounds 1-2 | Yes — round 1 commits `K_i`, round 2 reveals and verifies `k_i` |
| Byzantine fault tolerance | Abort on invalid share/message | Abort on invalid share/message |
| Key extraction by single signer | Not possible | Possible (any signer can compute `a`) |
| On-chain verification | ecrecover trick (~12k gas) | Standard ecrecover (~3k gas) |

The protocol assumes a **semi-honest adversary** for keygen and reshare (parties follow the protocol but may try to learn others' secrets). Signing (Schnorr) provides security against a **malicious adversary** that controls fewer than `threshold` parties: such an adversary cannot forge signatures or learn the group private key.

---

## Test Coverage

| Area | Tests | Status |
|------|-------|--------|
| Schnorr keygen + sign | `TestKeygenAndSign` | Pass |
| Keygen + sign + reshare + sign | `TestKeygenSignReshareSign` | Pass |
| ECDSA + ecrecover compatibility | `TestECDSAEcrecover` | Pass |
| Config JSON roundtrip | `TestConfigJSON` | Pass |
| On-chain Schnorr verify | 9 Foundry tests | Pass |
| ERC-4337 SignetAccount | 8 Foundry tests | Pass |
| Scalar/point/polynomial math | 4 unit tests | Pass |
