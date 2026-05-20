# FROST Migration Analysis

> **Historical document — migration complete.** FROST replaced LSS for keygen and signing.
> The production implementation now uses ZcashFoundation/frost (Rust) in the `kms-tss`
> KMS process, rather than `bytemare/frost` (Go) as originally planned here. The Go
> `bytemare/frost` path is retained as a development fallback (`--no-kms`).
>
> The resharing analysis and Lagrange-weighting approach described below remain directly
> relevant — **reshare is a priority roadmap item**. The technique applies identically to
> ZF FROST key material. See [FROST-RESHARE-APPROACHES.md](FROST-RESHARE-APPROACHES.md)
> and [DESIGN-RESHARE.md](DESIGN-RESHARE.md) for the current reshare design.

Analysis of FROST (RFC 9591) as a replacement for the current LSS-based threshold signing scheme,
and the plan to adopt it with a custom resharing layer.

---

## Decision Summary

Adopt **FROST (RFC 9591)** for keygen and signing via `github.com/bytemare/frost`, and implement
**full committee resharing** on top using the standard Lagrange-weighting technique from the
threshold cryptography literature (Herzberg et al. 1995). This is not an LSS-specific technique —
it predates LSS by decades and has clean published correctness proofs.

---

## Why Replace the Current LSS Signing Scheme

The current signing implementation (`lss/sign.go`) uses a custom Schnorr variant not defined in
any published specification:

```
s_i = k_i + r · λ_i · a_i · m    where r = R.x, m = msgHash as scalar
Combined: s·G = R + r·m·X
```

This was designed specifically to enable cheap on-chain verification via the `ecrecover` trick
in `SchnorrVerifier.sol` (~12k gas). The tradeoffs:

- **No standard security proof.** The challenge `e = R.x · msgHash` does not bind the public
  key `Y`, so standard Schnorr security proofs (Pointcheval-Stern 2000) do not apply. The scheme
  is ECDSA-adjacent and likely sound, but lacks formal analysis.
- **4 signing rounds.** The commit-reveal phase (rounds 1–2) was added to prevent adaptive nonce
  attacks. This is a valid fix but costs two extra round-trips.
- **Not in the LSS paper.** The LSS paper (Seesahai 2025) describes ECDSA signing, not this
  Schnorr variant. The non-standard challenge is a local implementation choice.
- **No standard compatibility.** Signatures are not BIP-340 compatible and cannot be verified
  by standard Schnorr tooling.

The LSS paper's resharing protocol (multiplicative blinding with auxiliary secrets `w` and `q`
via a Bootstrap Dealer) was also found to have a flawed correctness proof — it relies on
`interpolate(qⱼ·zⱼ) = interpolate(qⱼ)·interpolate(zⱼ)`, which does not hold for general
Shamir shares. The reshare protocol already implemented in this codebase uses the correct
Lagrange-weighting approach, which is unrelated to the LSS paper.

---

## FROST Overview (RFC 9591)

FROST (Flexible Round-Optimized Schnorr Threshold Signatures) is a two-round threshold Schnorr
protocol with a formal security proof.

**Signing equation:**
```
z_i = k_i + c · λ_i · x_i    where c = H(R || Y || msg)
Combined: z·G = R + c·Y       (standard Schnorr verification)
```

**Key properties:**

| Property | FROST | Current LSS |
|---|---|---|
| Signing rounds | 2 | 4 |
| Challenge | `H(R ‖ Y ‖ msg)` — standard | `R.x · msgHash` — custom |
| Security proof | Tight EU-CMA in ROM | None (ECDSA-adjacent) |
| Adversary model | Malicious | Semi-honest |
| Nonce security | Binding factors `ρᵢ = H(i, msg, B)` | Commit-reveal |
| Standard compatibility | BIP-340 compatible | Non-standard |
| Native resharing | No | Yes |

**Nonce security mechanism:** FROST uses per-signer binding factors `ρᵢ = H(i, msg, B)` where
`B` is the full commitment list. Each signer's effective nonce is `Dᵢ + ρᵢ·Eᵢ`. This prevents
the adaptive nonce attack (Wagner/ROS attack) in 2 rounds rather than the 4 rounds that
commit-reveal requires.

**On-chain verification:** FROST's standard Schnorr challenge is compatible with the established
ecrecover trick (noot-style, ~29k gas) rather than the current custom verifier (~12k gas). The
higher gas cost is acceptable for this use case.

---

## FROST Resharing Gap and How We Fill It

RFC 9591 does not specify resharing. The `frost.zfnd.org` implementation provides only:

- **Share refresh** — same committee, randomized shares (proactive security)
- **Participant removal** — subset refreshes without removed party, but does not fully
  invalidate old shares (removed party retaining a pre-refresh share remains a partial threat)

Neither supports full committee rotation (new members, new threshold, no overlap required).

### The Standard Resharing Protocol

Full resharing is a well-established technique from the threshold cryptography literature:

- Herzberg, Jarecki, Krawczyk, Yung — *Proactive Secret Sharing* (1995)
- Pedersen — *A Threshold Cryptosystem Without a Trusted Party* (1991)
- Used in GG20, CGGMP21, and all serious threshold ECDSA implementations

**Protocol:**

1. Each old party `i` computes its Lagrange-weighted share: `λᵢ · aᵢ`
2. Creates a new degree-`(t_new - 1)` polynomial `fᵢ(x)` with `fᵢ(0) = λᵢ · aᵢ`
3. Broadcasts Feldman VSS commitments for the new polynomial
4. Sends encrypted evaluation `fᵢ(xⱼ)` to each new party `j`
5. New party `j` sums received evaluations: `newShareⱼ = Σᵢ fᵢ(xⱼ)`
6. Verify: new committee's group public key equals old committee's group public key

**Correctness:** For any threshold-sized subset `S` of new parties:
```
Σ_{j∈S} μⱼ · newShareⱼ = Σ_{j∈S} μⱼ · Σᵢ fᵢ(xⱼ)
                         = Σᵢ Σ_{j∈S} μⱼ · fᵢ(xⱼ)   [linearity — valid because fᵢ is polynomial]
                         = Σᵢ fᵢ(0)
                         = Σᵢ λᵢ · aᵢ
                         = a                           [Lagrange reconstruction identity]
```

No party ever holds `a` in the clear. Old shares are cryptographically invalidated — the new
sharing comes from fresh polynomials, and old `aᵢ` values cannot produce valid partial
signatures under the new committee's Lagrange coefficients.

This is not an LSS protocol. It is a general Shamir secret sharing technique that works with
any threshold scheme, including FROST.

---

## Implementation Plan

### Layer 1: bytemare/frost (keygen + signing)

`github.com/bytemare/frost` is an RFC 9591-compliant Go implementation with:
- secp256k1 support (ciphersuite ID 7, via `github.com/bytemare/ecc`)
- Clean 2-round signing API (`Commit()`, `Sign()`, `AggregateSignatures()`)
- `KeyShare.Secret *ecc.Scalar` exported — directly readable and writable
- `frost.NewKeyShare(ciphersuite, id, secretBytes, ...)` for constructing shares from raw scalars

### Layer 2: resharing protocol (custom, atop bytemare/secret-sharing)

`github.com/bytemare/secret-sharing` is the VSS library bytemare/frost already uses internally.
It exports everything needed for the reshare protocol:

- `Polynomial.Evaluate(x)` — evaluate `fᵢ(xⱼ)` for each new party
- `Polynomial.DeriveInterpolatingValue(g, id)` — Lagrange coefficient computation
- `ShardAndCommit(g, secret, threshold, n)` — create Feldman VSS polynomial with specified
  constant term (pass `λᵢ · aᵢ` as the secret)
- `Verify(g, id, pk, commitment)` — share verification against Feldman commitment

**Reshare flow:**

```
Old party i:
  λᵢ = DeriveInterpolatingValue(secp256k1, oldParties, i)
  weightedShare = keyShare.Secret · λᵢ
  poly, commits = ShardAndCommit(secp256k1, weightedShare, newThreshold, newN)
  broadcast commits
  for each new party j:
    send encrypted poly.Evaluate(xⱼ)

New party j:
  for each old party i:
    verify received share against commits[i]
  newSecret = Σᵢ receivedShare[i]
  newKeyShare = frost.NewKeyShare(secp256k1, j, newSecret.Bytes(), newPubBytes, groupPubBytes)
  // newKeyShare is immediately usable by frost signing
```

### Architecture

```
┌─────────────────────────────────────────┐
│  signet node / HTTP API                 │
├─────────────────────────────────────────┤
│  custom reshare protocol                │
│  (Lagrange-weighting, standard 1995     │
│   technique, bytemare/secret-sharing)   │
├─────────────────────────────────────────┤
│  github.com/bytemare/frost              │
│  RFC 9591, 2-round, secp256k1           │
│  keygen (DKG or trusted dealer)         │
│  signing (binding factors, malicious)   │
└─────────────────────────────────────────┘
```

---

## Resharing Deferral

Full committee resharing can be deferred since signer removal is expected to be infrequent in
production. The frost.zfnd.org share refresh (same-committee refresh) is available immediately
and handles the proactive security use case. Full resharing is a defined follow-on milestone.

When implemented, resharing will:
- Support completely disjoint old and new committees
- Support threshold changes
- Cryptographically invalidate old shares (unlike zfnd refresh)
- Produce `KeyShare` values immediately consumable by the existing FROST signing layer
- Require no changes to `bytemare/frost` internals

---

## What Changes vs. Current Implementation

| Component | Current | After Migration |
|---|---|---|
| `lss/sign.go` | Custom Schnorr, 4 rounds | Replaced by bytemare/frost |
| `lss/keygen.go` | Custom keygen, eval commitments | Replaced by bytemare/frost DKG |
| `lss/reshare.go` | Lagrange-weighting reshare | Reimplemented atop bytemare/secret-sharing |
| `lss/sign_ecdsa.go` | Collaborative nonce ECDSA (insecure) | Removed |
| `contracts/SchnorrVerifier.sol` | Custom ecrecover trick, ~12k gas | Replaced with noot-style FROST verifier |
| Signing security | Semi-honest | Malicious adversary |
| Signing rounds | 4 | 2 |
| Formal security proof | None | Standard Schnorr (ROM) |

`lss/party.go`, `lss/polynomial.go`, `lss/curve.go`, `lss/session.go` are largely superseded
by the bytemare ecosystem.

---

## References

- RFC 9591: FROST — https://datatracker.ietf.org/doc/rfc9591/
- Komlo & Goldberg (2020): FROST original paper
- Herzberg, Jarecki, Krawczyk, Yung (1995): Proactive Secret Sharing
- Pedersen (1991): A Threshold Cryptosystem Without a Trusted Party
- bytemare/frost: https://github.com/bytemare/frost
- bytemare/secret-sharing: https://github.com/bytemare/secret-sharing
- noot/schnorr-verify (FROST-compatible ecrecover): https://github.com/noot/schnorr-verify
