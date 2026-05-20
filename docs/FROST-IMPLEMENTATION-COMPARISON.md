# FROST Implementation Comparison: bytemare/frost vs ZcashFoundation/frost

> **Historical document — decision made.** ZcashFoundation/frost (Rust) was selected and
> is now the production implementation via the `kms-tss` process. `bytemare/frost` (Go)
> is retained as a development/testing fallback (`--no-kms`). This comparison is kept for
> context on the decision rationale. The reshare analysis remains relevant — **reshare is
> a priority roadmap item** and will be implemented in the Rust KMS using the
> Lagrange-weighting approach described in [FROST-RESHARE-APPROACHES.md](FROST-RESHARE-APPROACHES.md).

Comparison of the two most complete production FROST (RFC 9591) implementations as of April 2026,
in the context of signet's current stack (`bytemare/frost` + `bytemare/dkg`) and the planned
reshare implementation.

---

## Table of Contents

1. [Overview](#1-overview)
2. [Architecture](#2-architecture)
3. [DKG](#3-dkg)
4. [Signing protocol](#4-signing-protocol)
5. [Performance](#5-performance)
6. [Reshare and share refresh](#6-reshare-and-share-refresh)
7. [Security issues in ZF FROST reshare](#7-security-issues-in-zf-frost-reshare)
8. [Serialization](#8-serialization)
9. [Audit status](#9-audit-status)
10. [Implications for signet](#10-implications-for-signet)

---

## 1. Overview

| | bytemare/frost + bytemare/dkg | ZcashFoundation/frost |
|---|---|---|
| Language | Go | Rust |
| RFC 9591 compliant | Yes | Yes |
| Curves | secp256k1, ristretto255, P-256, P-384, P-521 | secp256k1, ristretto255, ed25519, ed448, P-256 |
| DKG bundled | Separate module (bytemare/dkg) | Built into frost-core |
| Reshare | Not implemented (stub in signet) | Same-committee refresh only |
| NCC audit | No | Partial (v0.6.0, core crates) |
| Active development | Yes (oleary-labs fork) | Yes |

Signet uses a fork of bytemare/frost at `github.com/oleary-labs/frost`, with bytemare/dkg for
Pedersen DKG. The `tss/` package wraps both into a round-based protocol over libp2p.

---

## 2. Architecture

**ZF FROST** is a modular Rust monorepo: `frost-core` provides generic protocol logic
parameterized over a `Ciphersuite` trait; per-curve crates (`frost-secp256k1`, etc.) re-export
it for specific curves. DKG and signing share the same library.

**bytemare/frost** is a standalone Go module for signing only. DKG is handled by the separate
`bytemare/dkg` module. Signet's `tss/` layer stitches them together, adding a custom round3
to exchange public key shares after DKG finalization — necessary because the two libraries
don't share state.

---

## 3. DKG

Both implement Pedersen DKG (Feldman VSS with commitments). The key difference:

### ZK proof of knowledge (ZF FROST only)

ZF FROST's DKG part1 includes a Schnorr proof of knowledge for each participant's constant
polynomial coefficient `a_i0`:

```
R_i = g^k                             // nonce commitment
c_i = H(identifier || φ_i0 || R_i)   // challenge
μ_i = k + a_i0 * c_i                  // response
proof = (R_i, μ_i)                    // ~64 bytes, verified by all others in part2
```

This proof prevents the **rogue-key attack**: without it, a malicious DKG participant can
adaptively choose their polynomial after seeing others' commitments, yielding a group public
key whose discrete log they know. Feldman commitments alone do not prevent this.

bytemare/dkg uses Feldman VSS without ZK proofs. For signet's threat model (permissioned
groups, on-chain node registration), this risk is reduced but not eliminated — a compromised
registered node could still execute the attack during DKG.

### Round structure

| | bytemare/dkg | ZF FROST |
|---|---|---|
| Round 1 | Broadcast commitments | Broadcast commitments + ZK proof |
| Round 2 | Unicast secret shares | Verify ZK proofs, unicast secret shares |
| Round 3 | Broadcast public key shares (signet addition) | Finalize, derive key packages |

Signet adds a round3 to exchange public key shares because bytemare/dkg's `Finalize()` doesn't
produce them for peers; ZF FROST's part3 derives all verifying shares internally.

---

## 4. Signing Protocol

Both correctly implement RFC 9591 two-round FROST signing. Differences:

**Aggregation model:** ZF FROST has an explicit coordinator role; in signet every signer
independently aggregates (calls `AggregateSignatures`) once all shares arrive. Both are
correct; signet's approach produces redundant computation.

**Nonce precomputation:** ZF FROST's `preprocess()` decouples nonce generation from the
signing session — nonces can be generated offline in batches before the message is known.
bytemare/frost generates nonces at the start of round1 (`signer.Commit()`). For high-throughput
pipelines, preprocessing reduces round1 latency.

**Cheater detection:** ZF FROST v3 makes cheater detection mandatory — `AggregateSignatures`
returns the set of invalid contributors, not just a boolean. bytemare/frost's `verify=true`
flag checks shares but doesn't surface which signer misbehaved.

---

## 5. Performance

Published benchmarks for ZF FROST on AMD Ryzen 9 5900X (secp256k1, Rust opt-level 3):

| Scenario | DKG part1 | Sign round1 | Sign round2 | Aggregate |
|---|---|---|---|---|
| 2-of-3 | 0.26 ms | 0.09 ms | 0.15 ms | 0.25 ms |
| 7-of-10 | 0.78 ms | 0.09 ms | 0.48 ms | 0.52 ms |
| 67-of-100 | 7.5 ms | 0.09 ms | 4.41 ms | 3.82 ms |
| 667-of-1000 | 123.7 ms | 0.09 ms | 46.1 ms | 37.5 ms |

**Sign round1 is O(1)** — constant ~0.09 ms regardless of group size. Round2 and aggregate
are O(n).

### ZK proof overhead

The ZK proof in DKG part1 is two scalar multiplications and one hash call. For 67-of-100,
the 7.5 ms DKG cost is dominated by 100 generator multiplications for Feldman commitments;
the ZK proof itself is ~2 of those 100 operations, roughly **2% of total DKG cost**. The
proof is generated once per DKG run, so its amortized cost over the lifetime of a key is
negligible.

No equivalent Go benchmarks are published for bytemare/frost. The Go runtime's lack of
constant-time guarantees in scalar multiplication (vs. Rust's explicit `subtle`/`serdect`
usage) is a secondary consideration for side-channel exposure.

---

## 6. Reshare and Share Refresh

### What ZF FROST provides

**Trusted dealer refresh:** Dealer generates a zero-sum polynomial (`f(0) = 0`), evaluates
it at each participant's identifier, and sends additive deltas. Each participant adds the
delta to their existing share. The group public key is invariant because `f(0) * G = 0`.

**DKG refresh (distributed):** Three-round distributed equivalent of the above, no single
trusted party.

**Repairable Threshold Scheme (RTS):** Recover a single lost share using `t` helpers.
Each helper contributes a masked delta; the recovering participant sums them. Zero-knowledge
property: no single helper learns the recovered share.

### What ZF FROST does NOT provide

| Operation | Status |
|---|---|
| Rotate shares, same committee | Supported |
| Reduce threshold | Explicitly blocked (see §7) |
| Increase threshold | Not supported |
| Remove a participant (cryptographic) | Not supported — exclusion only |
| Add a participant | Not supported — requires full re-key |
| Old committee → new committee | Not supported |

Dynamic committee changes (the case signet needs for node rotation) are not in scope.
The research path is **Dynamic-FROST** (eprint 2024/896), which combines FROST with CHURP
for committee-changing reshare with cryptographic guarantees. This is not implemented in
ZF FROST; open issue #919 tracks it.

---

## 7. Security Issues in ZF FROST Reshare

### Old shares remain cryptographically valid after refresh

This is the most significant limitation. Refresh does not invalidate previous shares —
it only establishes a new set by consensus. A participant excluded from a refresh round
still holds a valid signing share. If `t` holders of old shares collude, they can produce
valid signatures. The only enforcement is social: participants are expected to securely
delete old shares.

For signet, this matters: a node removed from an on-chain group could retain its old share
and participate in signing unless the on-chain registry and chain client actively reject
signatures from deregistered nodes.

### Threshold modification bug (fixed in v2.2.0, reported by BlockSec)

The original `compute_refreshing_shares()` accepted a `min_signers` parameter. Passing a
lower value did not reduce the threshold — the old threshold still applied — but caused
confusing signing failures. Fixed by removing the parameter; threshold is now read from
the existing `PublicKeyPackage`. ZF recommends full re-keying for key packages created
with a mismatched threshold before v2.2.0.

### RTS honest-majority assumption is unverifiable

In the Repairable scheme, a malicious helper sending a wrong `delta` silently corrupts the
recovered share — there is no mechanism for the recovering participant to detect this before
attempting a signing operation. The only defense is the honest-majority assumption, which is
assumed but not enforced by the protocol.

### No liveness guarantee under Byzantine behavior

Both DKG refresh and RTS detect misbehavior (bad commitments fail verification) but have
no abort-and-retry mechanism. A participant going offline mid-refresh stalls the round
indefinitely. There is no documented recovery path for a partially-completed refresh.

---

## 8. Serialization

| | ZF FROST | signet (bytemare) |
|---|---|---|
| Format | Postcard (compact binary) | CBOR |
| Scalar/point encoding | `serdect` constant-time wrappers | bytemare's own binary encoding |
| Side-channel hardening | Explicit constant-time serialization | Not explicit in wire layer |
| Versioning | 1-byte version field, rejects unknown | None |
| Ciphersuite tagging | UTF-8 ID or 4-byte CRC-32 in binary | Implicit (single curve per binary) |

---

## 9. Audit Status

| Component | Audited | Version | Auditor |
|---|---|---|---|
| ZF frost-core | Partial | v0.6.0 | NCC Group |
| ZF frost-secp256k1 | Not audited | — | — |
| ZF frost-secp256k1-tr (Taproot) | Not audited | — | — |
| ZF frost-rerandomized | Not audited | — | — |
| bytemare/frost | Not audited | — | — |
| bytemare/dkg | Not audited | — | — |

The NCC audit covered core signing and keygen logic. The refresh and repairable modules were
added after the audit and have not been independently reviewed.

---

## 10. Implications for Signet

### DKG ZK proof

Adding ZK proofs of knowledge to DKG is ~10–15 lines of secp256k1 Schnorr and costs ~2% of
total DKG time. Given signet's on-chain node registry partially mitigates the rogue-key
risk, this is a low-priority hardening item but worth doing before production.

### Signing aggregation

Signet currently has every node independently aggregate. Designating a coordinator
(the initiator) to aggregate and broadcast the final signature would eliminate redundant work
and align with ZF FROST's model. It also enables coordinator-side cheater detection.

### Reshare

ZF FROST's same-committee refresh is not sufficient for signet's node rotation requirement
(old committee → new committee with on-chain membership changes). The relevant reference is:

- **Zero-sum polynomial refresh** (Herzberg et al. 1995) — the technique ZF FROST uses,
  directly reusable for proactive same-committee refresh.
- **Dynamic-FROST** (eprint 2024/896) — the research basis for committee-changing reshare.
- **`docs/DESIGN-RESHARE.md`** — signet's own reshare design, which targets full committee
  change using Lagrange-weighting on top of Feldman VSS.

The key gap in ZF FROST's reshare (old shares remain valid) is addressed in signet's design
by the on-chain `Generation` counter: the chain client rejects coord messages referencing
a superseded generation, making old shares operationally invalid even if cryptographically
they are not.

### Nonce precomputation

If signing throughput becomes a bottleneck, adopting bytemare/frost's nonce preprocessing
API (or contributing it to the fork) reduces round1 latency by decoupling nonce generation
from session setup.
