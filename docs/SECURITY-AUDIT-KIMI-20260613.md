# Signet Protocol Security Audit (Kimi)

**Auditor**: Claude Code (powered by `moonshotai/kimi-k2.6`)
**Date**: 2026-06-13
**Branch**: `main`
**Commit**: `a420f5f` (plus prior history)
**Scope**: Go node (`node/`, `network/`), Rust KMS (`kms-tss/src/ecdsa_session.rs`), Solidity contracts (`contracts/contracts/`)

---

## Executive Summary

This audit was conducted with the Kimi model to assess the Signet protocol's security posture ahead of a public alpha deployment. The codebase has matured significantly since the original `SECURITY-ANALYSIS-OLD.md` was written. The most critical historical vulnerability — raw JWT forwarding that collapsed the threshold trust model to 1-of-n — has been fixed via ZK proofs bound to ephemeral session keys (commit `a420f5f`). ECDSA signature formatting (EIP-2 low-S normalization and v-byte recovery) is correctly implemented.

However, **several critical and high-severity issues remain** that could lead to key loss, unauthorized signing, or permanent group inoperability in a real-money alpha. The most serious gaps are in **authorization edge cases** in the ZK and delegation paths, **admin endpoint access control**, and **smart contract quorum protection**. **At-rest storage encryption** (key shards and node identity keys) has been resolved on `feat/at-rest-encryption`.

This document supersedes `SECURITY-ANALYSIS-OLD.md` as the canonical security assessment for the current codebase.

---

## Methodology

1. **Document Review**: Read all design docs (`DESIGN-ZK-AUTH.md`, `DESIGN-RESHARE-HARDENING.md`, `DESIGN-SCOPED-SUBKEYS.md`, etc.), `AUDIT-SCOPE.md`, and `PRODUCTION-GAPS.md`.
2. **Source Code Review**: Systematic line-by-line review of all security-critical files in `node/`, `network/`, `contracts/contracts/`, and `kms-tss/src/ecdsa_session.rs`.
3. **Threat Modeling**: Assessed each component against the stated alpha deployment parameters (5 nodes, 3-of-5 threshold, ~$100 max per key, x402/ECDSA payment flow).
4. **Gap Analysis**: Compared findings against `AUDIT-SCOPE.md` and `PRODUCTION-GAPS.md` to identify under-scoped areas.

---

## Critical (P0)

These issues could lead to immediate loss of funds, key compromise, or complete group inoperability.

### C1. Plaintext Key Shard Storage

**File**: `kms-tss/src/storage.rs`, `kms-tss/src/encrypted_store.rs`, `kms-tss/src/custody.rs`
**Status**: ✅ Resolved (`feat/at-rest-encryption`)

Key shards were previously stored as **plaintext JSON** in sled. OS file permissions (`0600`) were the only protection.

**Resolution**: The Rust KMS now supports envelope encryption via `Storage::new_encrypted()`. Each `StoredKey` value is sealed with a per-record random DEK (32 bytes) encrypted under a KEK via XChaCha20-Poly1305. The AAD binds each ciphertext to its addressing context (`version || kek_version || tree_name || record_key`) plus domain-separated literals (`dek/v1`, `val/v1`), preventing cross-key and cross-tree swapping attacks. The `value_aad` additionally includes `wrap_nonce || wrapped_dek`, pinning the value encryption to the exact wrapping that produced its DEK.

KEK management is handled by the `KeyCustody` trait (`custody.rs`), with `LocalKeyCustody` as the v1 in-process implementation. KEKs are held in `Zeroizing<[u8; 32]>` wrappers, explicitly zeroed on drop. HKDF-SHA-256 derives per-purpose wrapping sub-keys. KEK rotation is supported without bulk re-encryption — old and new KEKs are retained, and `unwrap_dek` selects the correct KEK by the `kek_version` byte in each record.

The Go `LocalKeyManager` (`node/local_keymanager.go`) still stores plaintext JSON in bbolt, but this path is **test/development-only** (`--no-kms` flag). Production deployments use the remote Rust KMS over gRPC, so this does not represent a production risk. See `KMS-INTEGRATION.md` for the production path.

---

### C2. Plaintext Node Identity Key

**File**: `network/identity.go`, `network/keyfile.go`
**Status**: ✅ Resolved (`feat/at-rest-encryption`)

The secp256k1 private key that defines the node's identity (peer ID and Ethereum address) was previously written as **raw protobuf bytes** to `node.key` with `0600` permissions and no encryption.

**Impact**: This key is the node's on-chain identity. Compromise allows full impersonation — participation in signing sessions, acceptance of group invitations, and on-chain action as the node.

**Resolution**: When the `SIGNET_NODE_KEY_PASSPHRASE` environment variable is set, a newly generated `node.key` is sealed at rest with XChaCha20-Poly1305 under a key derived from the passphrase via scrypt (`network/keyfile.go`). This mirrors the KMS at-rest envelope (a passphrase replaces the raw KEK because the identity key is unwrapped once at startup, not per-record). The envelope is self-describing via a magic prefix, so legacy plaintext keys still load — existing nodes keep working, and operators opt into encryption by setting the env var on a fresh node. When the variable is unset, the legacy plaintext format is used (encryption disabled), matching the KMS `SIGNET_KMS_KEY` opt-in behavior. `devnet-init` honors the same variable so initialized keys match what the node expects to load.

---

### C3. ZK Auth Path Missing Client ID / Audience Validation

**File**: `node/auth.go` (`ValidateAuthProof`)
**Status**: ✅ Resolved (`feat/at-rest-encryption`)

The ZK proof verification path validated expiry, issuer trust, `sub` presence, JWKS modulus match, and ZK proof validity via `bb verify`, but did **not** validate `Aud` (audience) or `Azp` (authorized party) against expected values.

This meant a valid JWT from the right issuer but for a **different application** (wrong `aud`/`azp`) would authenticate successfully against Signet.

**Impact**: Cross-application token replay. A JWT obtained for app A could be used against Signet group B if both trust the same OAuth issuer.

**Resolution**: `ValidateAuthProof` now enforces the group's `ClientIds` allowlist on the ZK path, mirroring `ValidateJWTForSession`. The client identity is resolved with `azp → aud` precedence; if the issuer has `ClientIds` configured and the identity is absent or not in the allowlist, the proof is rejected. This is sound because `proof.Aud`/`proof.Azp` are ZK public inputs (`expected_aud`/`expected_azp`): a successful `bb verify` cryptographically binds them to the real JWT, so a prover cannot claim an allowlisted client while holding a token for a different one. The check runs before `bb verify` for fail-fast rejection; the binding is what makes it sound. Covered by `TestValidateAuthProofClientIDAllowlist` in `node/auth_test.go`.

---

### C4. Delegation Token Session Bypasses Key Disable Check

**File**: `node/handlers.go` (`handleAuth` delegation path)
**Status**: ✅ Resolved (`feat/at-rest-encryption`)

When a delegation token was presented, the `handleAuth` delegation path checked only that the delegated sub-key *existed* (across all curves), not that it was active. A disabled sub-key could therefore still establish a delegation session.

**Impact**: A user who disables a compromised sub-key could still establish a delegation session for it. Note the participant-side delegate-sign handler (`coord.go`) already rejects disabled sub-keys at signing time, so actual signing was blocked there — but the originating node still accepted the session and forwarded it, contradicting the disable lifecycle.

**Resolution**: The `handleAuth` delegation path now reads `info.Status` and rejects a disabled sub-key with `http.StatusForbidden` ("delegated sub-key is disabled") before creating or forwarding the session. This fails fast at the originating node and aligns the auth path with the existing participant-side enforcement (defense-in-depth).

---

### C5. Admin Endpoints Unprotected for Groups Without Auth Keys

**Files**: `node/handlers.go` — `handleListKeys`, `handleStartReshare`, `handleReshareStatus`
**Status**: ✅ Resolved (`feat/at-rest-encryption`)

These endpoints only validated `AdminAuth` if `n.auth.HasAuthKeys(groupID)` returned true:

```go
if n.auth.HasAuthKeys(req.GroupID) {
    if err := n.auth.ValidateAdminAuth(req.GroupID, &req); err != nil {
        httpError(w, http.StatusUnauthorized, "admin auth failed")
        return
    }
}
```

For groups that had **only OAuth issuers** (no auth keys configured), these admin endpoints required **no authentication at all**.

**Impact**: Anyone with network access could list all keys for a group, trigger reshares, and query reshare status for OAuth-only groups. This leaks key metadata and could be used to disrupt operations.

**Resolution**: The `if HasAuthKeys` gate was removed from all three handlers — `ValidateAdminAuth` is now always required (fail closed). A group with no trusted authorization keys has no admin principal, so admin requests are rejected with `401`. OAuth sessions do not grant admin privileges. Covered by `TestAdminEndpointsFailClosed` (all three endpoints reject unauthenticated requests), `TestReshareStatusAllowsValidAdminKey` (valid trusted-key path still works), and `TestReshareStatusRejectsUntrustedAdminKey` in `node/handlers_admin_test.go`.

**Operational note**: OAuth-only groups must register an on-chain authorization key to use admin endpoints (list keys / reshare). A node-level operator-key mechanism (per `PRODUCTION-GAPS.md`) was considered but deferred; fail-closed was chosen as the minimal, unambiguous fix for the alpha.

---

## High (P1)

These issues could lead to unauthorized access, DoS, or operational disruption.

### H1. Coord Message Parameters Trusted from Initiator

**File**: `node/coord.go` (`msgKeygen` / `msgSign` handlers, `groupState` / `checkKeygenParams` / `checkSignerSet`)
**Status**: ✅ Resolved (`feat/at-rest-encryption`)

Participants in a keygen/signing session trusted initiator-supplied `Parties`, `Threshold`, and `Signers` from the coord message. The `MessageHash` was already protected — scoped keys recompute the hash from the forwarded payload and the session signature binds it, and unscoped keys are forbidden from carrying a payload (`coord.go`). But the party/signer set and threshold were not checked against on-chain state, so a malicious initiator could supply an off-chain party set, include a non-member signer, or set a lower threshold.

**Resolution**: Participants now validate parameters against their own on-chain-derived state (`n.groups`) before acting:
- **keygen** (`checkKeygenParams`): `msg.Threshold` must equal the group threshold exactly, the party set must be non-empty, and every party must be an active member (subset allowed). Rejected with `coordNACK`.
- **sign** (`checkSignerSet`): every signer must be an active member, and the count of *distinct* signers must be ≥ the group threshold (duplicates can't inflate the count). Rejected (session aborts).

The reshare coord paths (`msgReshare*`) are intentionally left unchanged — reshare legitimately changes committee/threshold and is gated by the deterministic leader election and on-chain-driven job creation. Pure helpers are covered by `TestCheckKeygenParams`, `TestCheckSignerSet`, and `TestGroupState` in `node/coord_params_test.go`; the full keygen/sign/reshare integration suite still passes.

---

### H2. No HTTP Request Body Size Limit

**File**: `node/node.go` (`limitRequestBody` middleware)
**Status**: ✅ Resolved (`feat/at-rest-encryption`)

All HTTP handlers used `json.NewDecoder(r.Body)` without `http.MaxBytesReader`, allowing DoS via arbitrarily large POST bodies — especially on `/v1/auth`, which is unauthenticated and triggers expensive ZK verification.

**Resolution**: A `limitRequestBody` middleware wraps the mux and applies `http.MaxBytesReader` per path before any handler reads the body: 256 KiB for `/v1/auth` (ZK proofs are sizeable), 32 KiB for `/admin/*`, and a 64 KiB default for everything else (keygen/sign/delegate/keys). Over-limit bodies surface as a decode error (400). GET endpoints carry no body, so the cap is a no-op. Covered by `TestLimitRequestBody` in `node/httplimit_test.go`.

---

### H3. SignetGroup Removal Doesn't Check Quorum

**File**: `contracts/contracts/SignetGroup.sol` (`executeRemoval`)
**Status**: ✅ Resolved (`feat/at-rest-encryption`)

`executeRemoval` removed a node without checking whether the remaining active set would drop below `threshold`. Since `threshold` is immutable after initialization, a quorum-breaking removal permanently bricks the group — all keys unrecoverable.

**Resolution**: Added `require(_activeNodes.length > threshold, "removal would break quorum")` before `_removeFromActive`. The node being removed is still counted in `_activeNodes` at this point, so the post-removal size is `length - 1`; `length > threshold` is the equivalent integer form and avoids unsigned underflow. `testIsOperational` was updated to the new invariant, and `testExecuteRemoval_RevertsIfBreaksQuorum` was added. All 74 Foundry tests pass.

---

### H4. Error Messages Leak Internal State

**File**: `node/handlers.go:1115-1119` (`httpError`)

Error messages are returned raw to the client:

```go
func httpError(w http.ResponseWriter, code int, msg string) {
    json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
```

Examples observed: `"load config: ..."`, `"key not found: group=... key=..."`, `"list keys: ..."`.

**Impact**: Information leakage aids reconnaissance for targeted attacks. An attacker can enumerate valid group IDs, key IDs, and internal error conditions.

**Recommendation**: Return generic error messages to clients (e.g., `"internal error"`, `"invalid request"`) and log detailed errors server-side with zap.

---

### H5. Reshare Leader Failover Missing

**File**: `node/reshare.go:48`

If the elected reshare leader (lexicographically smallest member) is down, reshare hangs indefinitely. There is no timeout-based failover.

```go
// TODO: If the elected leader is down or unresponsive, the reshare will
// not proceed automatically...
```

**Impact**: A single offline node can block all reshares for a group indefinitely. In a 5-node network with one external operator, this is a likely failure mode.

**Recommendation**: Implement timeout-based failover where the next node in sort order takes over if the leader hasn't started coordination within N seconds (e.g., 60s).

---

### H6. Delegation Token Parent Key Slicing Panic

**File**: `node/delegate.go` (`parentKeyFromResolved`)
**Status**: ✅ Resolved (`feat/at-rest-encryption`)

String slicing assumed `req.KeySuffix` was shorter than `resolved`:

```go
parentKeyID = resolved[:len(resolved)-len(req.KeySuffix)-1]
```

For a delegation-token session, `validateSessionRequest` returns a `resolved` key_id that is **not** derived from `req.KeySuffix`, so a crafted long suffix made the index negative → **panic (node DoS)**.

**Resolution**: Extracted `parentKeyFromResolved`, which anchors the `":<suffix>"` match at the end of `resolved` (`strings.HasSuffix`) and returns `ok=false` for an empty/absent/oversized suffix; the handler then rejects with `400` instead of slicing by length. This also cleanly blocks delegation-of-delegation. Covered by `TestParentKeyFromResolved` in `node/delegate_test.go`.

---

## Medium (P2)

### M1. No TLS on HTTP API

**File**: `node/node.go:277`

The HTTP API is plaintext. Session pubkeys, auth tokens, and signatures transit in the clear.

**Recommendation**: Terminate TLS at a reverse proxy (nginx, Caddy) or add native TLS to the Go server. This is documented in `PRODUCTION-GAPS.md` as critical.

---

### M2. No Rate Limiting

**File**: `node/node.go`

No rate limiting on any endpoint. `/v1/auth` triggers expensive `bb verify`; `/v1/keygen` and `/v1/sign` consume threshold protocol resources.

**Recommendation**: Add per-IP and per-session rate limits as middleware or at the reverse proxy.

---

### M3. JWKS Cache 1-Hour Minimum Refresh

**File**: `node/auth.go:138`

`jwk.WithMinRefreshInterval(1*time.Hour)` means a compromised JWKS key remains trusted for up to 1 hour after rotation.

**Recommendation**: Reduce to 5-15 minutes for production, or implement emergency JWKS revocation via an on-chain flag.

---

### M4. Peer Auto-Registration Without Allowlist

**File**: `network/host.go:79-82`

Any peer that connects via libp2p is auto-registered in the party mapping. There is no application-level allowlist or mutual auth beyond libp2p's transport handshake.

**Impact**: A rogue node on the network can inject itself into peer mappings and observe connection metadata.

**Recommendation**: Add application-level peer allowlisting based on on-chain group membership. Reject coord messages from unregistered peers.

---

### M5. `parseDelegationIdentity` is Fragile

**File**: `node/node.go:430-472`

The function assumes the issuer starts with `https://` and does ad-hoc string splitting. Non-standard issuers or malformed key IDs could cause incorrect parsing.

**Impact**: Incorrect identity resolution for delegation tokens with non-HTTPS issuers.

**Recommendation**: Use a robust parser that handles the full `oauth:<iss>:<sub>[:suffix]` structure explicitly, with proper URL parsing for the issuer component.

---

### M6. EIP-712 Scope: `HexToAddress` Silently Returns Zero

**File**: `node/scope.go:112`

`common.HexToAddress(typedData.Domain.VerifyingContract)` silently returns the zero address on invalid input. If the scope also encodes a zero address, a malformed payload could pass verification.

**Recommendation**: Validate that `VerifyingContract` is a valid hex address before converting, or reject zero addresses in scopes.

---

### M7. Clock Skew Sensitivity

**File**: `node/sessions.go:18`

`timestampWindow = 30 * time.Second` requires relatively synchronized clocks across nodes. Significant skew causes legitimate requests to be rejected.

**Recommendation**: Document clock synchronization requirements (NTP/chrony). Consider a slightly wider window (60s) with stricter nonce enforcement to compensate.

---

## Low / Hardening

| ID | Finding | File | Recommendation |
|---|---|---|---|
| L1 | Factory `getGroupsByManager` is O(n) | `SignetFactory.sol:198` | Not security-critical; consider reverse mapping if group count grows |
| L2 | Hardcoded secp256k1 order N | `node/handlers.go:793` | Use `crypto.S256().Params().N` instead of hex literal |
| L3 | Custom FROST challenge implementation | `node/auth.go:374-427` | Looks correct per RFC 9380/9591, but verify with test vectors |
| L4 | `LocalKeyManager.SetKeyStatus` unimplemented | `node/local_keymanager.go:304` | Returns error; blocks key lifecycle in local dev mode |
| L5 | `LocalKeyManager.DeleteKey` unimplemented | `node/local_keymanager.go:309` | Returns error; blocks key deletion in local dev mode |
| L6 | 10MB message limit | `network/host.go:22` | Adequate but could allow memory pressure with many concurrent sessions |
| L7 | No `threshold` update function | `SignetGroup.sol` | `threshold` is immutable after init; group becomes inoperable if nodes drop below quorum |

---

## Previously Fixed / Verified

| Issue | Status | Commit / Location |
|---|---|---|
| Raw JWT forwarding breaks threshold trust model | **FIXED** | Commit `a420f5f` — ZK proofs + session keys replace raw JWT forwarding |
| TestMode globally disables JWT validation | **FIXED** | `TestMode` removed from `config.go` and auth code |
| ECDSA s-value normalization | **FIXED** | Commit `71550b9` — proper EIP-2 low-S normalization |
| ECDSA v-byte recovery | **FIXED** | Commit `71550b9` — tries v=0 and v=1, fails explicitly if no match |
| Session request signature binding | **FIXED** | Commit `a420f5f` — binds to `groupID:keyID:nonce:timestamp[:messageHash]` |
| Swap-and-pop O(1) removal | **VERIFIED** | Correct 1-based indexing in `SignetFactory.sol` and `SignetGroup.sol` |
| `initializer` modifier prevents re-init | **VERIFIED** | Present on `SignetGroup.initialize()` |
| `_pubkeyToAddress` validates 65-byte format | **VERIFIED** | `require(pubkey.length == 65 && pubkey[0] == 0x04)` |

---

## ECDSA Protocol Notes (Rust KMS)

The `kms-tss/src/ecdsa_session.rs` implements the DJNPO20 robust threshold ECDSA protocol. From the first ~300 lines reviewed:

- **Polynomial generation**: Uses `thread_rng()` for randomness. Degree-t for `(k, a)`, degree-2t for `(b, d, e)` with zero constant term — correct per protocol.
- **Scalar/point serialization**: Proper 32-byte scalar and 33-byte compressed point encoding.
- **Lagrange interpolation**: Implemented correctly for both scalar and exponent forms.
- **Message size validation**: `bytes_to_scalar` rejects non-32-byte inputs.

**Out of scope for this audit** (per `AUDIT-SCOPE.md`):
- Full commitment consistency checks (R_i and W_i interpolation)
- `W == g^w` check
- Zero-hash rejection
- Coordinator aggregation and final signature verification
- Robustness against commitment-inconsistency attacks

The `AUDIT-SCOPE.md` correctly flags this as the highest-priority component for a dedicated cryptographic audit. The session state machine, message routing, and storage layer (Go side) have been reviewed here; the Rust protocol implementation needs a specialist review.

---

## Assessment of AUDIT-SCOPE.md

The existing `AUDIT-SCOPE.md` is a **good first draft** for a narrowly-focused alpha, but it underweights two categories of risk:

### Under-Scoped: The Administrative Layer

The current scope focuses heavily on the signing protocol (correctly) but omits the infrastructure that prevents key loss and unauthorized access:

1. **At-rest storage** (`node/keystore.go`, `network/identity.go`) — Completely absent. Plaintext shards are a P0 for any real-money deployment.
2. **Smart contracts** — Listed as out of scope. But `executeRemoval` lacking a quorum check can permanently brick a group.
3. **Session auth verification** (`node/auth.go`, `node/coord.go`) — Rated Medium. Auth bypasses (missing `Aud`/`Azp`, delegation token disable bypass) are too serious for Medium.
4. **Admin endpoint protection** — Not mentioned at all. Unprotected admin endpoints in OAuth-only groups are a direct access control failure.

### Under-Scoped: The DKG Foundation

The scope lists `ecdsa_session.rs` for *signing* but omits the **key generation protocol**. If the DKG is flawed (bad VSS, incorrect Feldman commitments, weak randomness), every subsequent signature is compromised regardless of how correct the signing protocol is.

### Revised Priority Table

| Component | Current Priority | Recommended Priority | Rationale |
|---|---|---|---|
| ECDSA signing protocol (Rust) | Critical | Critical | No change |
| Scope enforcement (Go) | Critical | Critical | No change |
| DKG/keygen protocol (Rust) | — | **High** | Foundation of all key security; missing entirely |
| ECDSA sig formatting (Go) | High | High | No change |
| Delegation tokens (Go) | High | High | No change |
| Session auth + ZK verify (Go) | Medium | **High** | Auth bypasses found; too important for Medium |
| At-rest storage (Go) | — | **High** | Plaintext shards = key loss on fs compromise |
| Smart contracts (Solidity) | Out of scope | **Light review / Medium** | Quorum check bug can brick group |
| Reshare coordinator (Go) | Out of scope | **Medium** | Alpha will see node churn; key loss risk |
| Protocol boundaries (Go/Rust) | Medium | Medium | Keep, but focus on coord auth verification |
| FROST Schnorr | Out of scope | Out of scope | Correct for alpha scope |
| Ed25519 | Out of scope | Out of scope | Correct for alpha scope |
| ZK circuit internals | Out of scope | Out of scope | Correct; audited separately |
| libp2p networking | Out of scope | Out of scope | Correct; standard library |
| Chain polling | Out of scope | Out of scope | Correct for alpha scope |

---

## Priority Action Items

| Priority | Issue | Effort | File(s) |
|---|---|---|---|
| **P0** | ✅ Encrypt key shards at rest | Medium | `kms-tss/src/encrypted_store.rs`, `kms-tss/src/custody.rs` |
| **P0** | ✅ Encrypt node identity key | Medium | `network/identity.go`, `network/keyfile.go` |
| **P0** | Add `Aud`/`Azp` validation to ZK auth path | Low | `node/auth.go` |
| **P0** | Fix delegation token to check key disabled status | Low | `node/handlers.go` |
| **P0** | ✅ Require admin auth for all groups | Low | `node/handlers.go` |
| **P1** | ✅ Validate coord message params against local on-chain state | Medium | `node/coord.go` |
| **P1** | ✅ Add HTTP request body size limits | Low | `node/node.go` |
| **P1** | ✅ Add quorum check to `executeRemoval` | Low | `contracts/SignetGroup.sol` |
| **P1** | Sanitize error messages returned to clients | Low | `node/handlers.go` |
| **P1** | ✅ Fix delegation parent key slicing panic | Low | `node/delegate.go` |
| **P1** | Implement reshare leader failover | Medium | `node/reshare.go` |
| **P2** | Deploy behind TLS-terminating proxy | Low | `node/node.go` (or infra) |
| **P2** | Add rate limiting | Medium | `node/node.go` (or infra) |
| **P2** | Add DKG/keygen Rust module to audit scope | Low | `kms-tss/src/` |

---

## Conclusion

The Signet protocol has **strong architectural security**: ZK auth eliminates the critical JWT-forwarding vulnerability, session binding prevents replay, and scope enforcement prevents cross-domain signing. The contract layer uses standard patterns correctly.

The remaining risks are primarily **operational and implementation-level**: missing auth checks on edge cases, DoS vectors, and contract quorum protection. These are all addressable before a production deployment and should be prioritized for the public alpha. **At-rest encryption** (key shards via Rust KMS envelope encryption, node identity key via passphrase-protected XChaCha20-Poly1305) has been implemented and verified.

The total additional scope recommended above adds approximately **1-2 days of auditor/reviewer time** and closes the gap between "signing protocol is correct" and "alpha deployment is safe."
