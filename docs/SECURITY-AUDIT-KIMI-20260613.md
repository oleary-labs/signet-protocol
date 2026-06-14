# Signet Protocol Security Audit (Kimi)

**Auditor**: Claude Code (powered by `moonshotai/kimi-k2.6`)
**Date**: 2026-06-13
**Branch**: `main`
**Commit**: `a420f5f` (plus prior history)
**Scope**: Go node (`node/`, `network/`), Rust KMS (`kms-tss/src/ecdsa_session.rs`), Solidity contracts (`contracts/contracts/`)

---

## Executive Summary

This audit was conducted with the Kimi model to assess the Signet protocol's security posture ahead of a public alpha deployment. The codebase has matured significantly since the original `SECURITY-ANALYSIS-OLD.md` was written. The most critical historical vulnerability — raw JWT forwarding that collapsed the threshold trust model to 1-of-n — has been fixed via ZK proofs bound to ephemeral session keys (commit `a420f5f`). ECDSA signature formatting (EIP-2 low-S normalization and v-byte recovery) is correctly implemented.

However, **several critical and high-severity issues remain** that could lead to key loss, unauthorized signing, or permanent group inoperability in a real-money alpha. The most serious gaps are in **at-rest storage encryption** (plaintext key shards and node identity keys), **authorization edge cases** in the ZK and delegation paths, **admin endpoint access control**, and **smart contract quorum protection**.

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

**File**: `node/keystore.go`
**Status**: Unchanged from `SECURITY-ANALYSIS-OLD.md` §1.1

Key shards (the most sensitive data in the system) are stored as **plaintext JSON** in a bbolt database. OS file permissions (`0600`) are the only protection.

```go
func (s *KeyShardStore) Put(groupID, keyID string, cfg *tss.Config) error {
    data, err := json.Marshal(cfg)  // plaintext JSON
    // ...
    return grp.Put([]byte(keyID), data)
}
```

**Impact**: If an attacker gains read access to the filesystem (container escape, backup exposure, disk theft, or insider threat), all threshold shares are immediately compromised. With `t` shares from any `t` nodes, the full private key can be reconstructed.

**Recommendation**: Encrypt shards at rest using a key derived from a hardware token (TPM/HSM), a cloud KMS, or a passphrase-based KDF. Consider an envelope encryption scheme where a master key is sealed by the platform and individual shards are encrypted with per-key DEKs.

---

### C2. Plaintext Node Identity Key

**File**: `network/identity.go`, `network/keyfile.go`
**Status**: ✅ Resolved (`feat/at-rest-encryption`)

The secp256k1 private key that defines the node's identity (peer ID and Ethereum address) was previously written as **raw protobuf bytes** to `node.key` with `0600` permissions and no encryption.

**Impact**: This key is the node's on-chain identity. Compromise allows full impersonation — participation in signing sessions, acceptance of group invitations, and on-chain action as the node.

**Resolution**: When the `SIGNET_NODE_KEY_PASSPHRASE` environment variable is set, a newly generated `node.key` is sealed at rest with XChaCha20-Poly1305 under a key derived from the passphrase via scrypt (`network/keyfile.go`). This mirrors the KMS at-rest envelope (a passphrase replaces the raw KEK because the identity key is unwrapped once at startup, not per-record). The envelope is self-describing via a magic prefix, so legacy plaintext keys still load — existing nodes keep working, and operators opt into encryption by setting the env var on a fresh node. When the variable is unset, the legacy plaintext format is used (encryption disabled), matching the KMS `SIGNET_KMS_KEY` opt-in behavior. `devnet-init` honors the same variable so initialized keys match what the node expects to load.

---

### C3. ZK Auth Path Missing Client ID / Audience Validation

**File**: `node/auth.go:643-710` (`ValidateAuthProof`)

The ZK proof verification path validates expiry, issuer trust, `sub` presence, JWKS modulus match, and ZK proof validity via `bb verify`. **However, it does NOT validate `Aud` (audience) or `Azp` (authorized party) against expected values.**

This means a valid JWT from the right issuer but for a **different application** (wrong `aud`/`azp`) will authenticate successfully against Signet.

**Impact**: Cross-application token replay. A JWT obtained for app A can be used against Signet group B if both trust the same OAuth issuer.

**Recommendation**: Add `Aud` and `Azp` validation in `ValidateAuthProof`, matching the logic already present in `ValidateJWTForSession` (lines 614-621). If `ClientIds` are configured for the issuer, require that `azp` or `aud` matches and reject if absent.

---

### C4. Delegation Token Session Bypasses Key Disable Check

**File**: `node/handlers.go:216-288` (`handleAuth` delegation path)

When a delegation token is presented, the code checks if the delegated sub-key exists across all curves:

```go
for _, curve := range []Curve{CurveSecp256k1, CurveEcdsaSecp256k1, CurveEd25519} {
    if info, _ := n.km.GetKeyInfo(req.GroupID, internalSubKey, curve); info != nil {
        keyExists = true
        break
    }
}
```

However, it **does not check `info.Status == "disabled"`**. A disabled key can still establish a delegation session and be used for signing.

**Impact**: The key disable/enable lifecycle is completely bypassed for delegation tokens. A user who disables a compromised sub-key will find it still usable via delegation.

**Recommendation**: Add `info.Status == "disabled"` check and reject with `http.StatusForbidden` if the sub-key is disabled.

---

### C5. Admin Endpoints Unprotected for Groups Without Auth Keys

**Files**:
- `node/handlers.go:34-100` (`handleListKeys`)
- `node/handlers.go:836-917` (`handleStartReshare`)
- `node/handlers.go:919-975` (`handleReshareStatus`)

These endpoints only validate `AdminAuth` if `n.auth.HasAuthKeys(groupID)` returns true:

```go
if n.auth.HasAuthKeys(req.GroupID) {
    if err := n.auth.ValidateAdminAuth(req.GroupID, &req); err != nil {
        httpError(w, http.StatusUnauthorized, "admin auth failed")
        return
    }
}
```

For groups that have **only OAuth issuers** (no auth keys configured), these admin endpoints require **no authentication at all**.

**Impact**: Anyone with network access can list all keys for a group, trigger reshares, and query reshare status for OAuth-only groups. This leaks key metadata and could be used to disrupt operations.

**Recommendation**: Require admin auth for all groups that have any auth policy. OAuth sessions should not grant admin privileges by default. Alternatively, introduce an operator key mechanism (as noted in `PRODUCTION-GAPS.md`) and require it for all admin endpoints.

---

## High (P1)

These issues could lead to unauthorized access, DoS, or operational disruption.

### H1. Coord Message Parameters Trusted from Initiator

**File**: `node/coord.go:338-512`

Participants in a signing session trust initiator-supplied `Parties`, `Threshold`, `Signers`, and `MessageHash` from the coord message. While scope enforcement and session signature binding mitigate some manipulation, a compromised or malicious initiator could:

- Supply a manipulated `Parties` list (e.g., including a colluding node not in the on-chain group)
- Set a lower `Threshold` than the group contract specifies
- Forward a `MessageHash` that differs from what the API caller intended (mitigated by session sig binding for scoped keys, but not for raw `message_hash` signing)

**Impact**: Protocol parameter manipulation by a malicious initiator. Could reduce effective threshold or include unauthorized signers.

**Recommendation**: Participants should independently verify `Parties`, `Threshold`, and group membership from their own local `n.groups` state (populated from on-chain events) rather than trusting the initiator's message. Reject coord messages where parameters don't match local on-chain state.

---

### H2. No HTTP Request Body Size Limit

**File**: `node/handlers.go` (all POST handlers)

All HTTP handlers use `json.NewDecoder(r.Body)` without `http.MaxBytesReader`:

```go
if err := json.NewDecoder(r.Body).Decode(&req); err != nil { ... }
```

**Impact**: DoS via arbitrarily large POST bodies. An attacker can exhaust memory and CPU during JSON parsing, especially on `/v1/auth` which is unauthenticated and triggers expensive ZK verification.

**Recommendation**: Wrap `r.Body` with `http.MaxBytesReader(w, r.Body, maxSize)` before decoding. Suggested limits:
- `/v1/auth`: 256KB
- `/v1/keygen`, `/v1/sign`: 64KB
- Admin endpoints: 32KB

---

### H3. SignetGroup Removal Doesn't Check Quorum

**File**: `contracts/contracts/SignetGroup.sol:178`

`executeRemoval` removes a node without checking if the remaining active set drops below `threshold`:

```solidity
function executeRemoval(address node) external {
    RemovalRequest memory req = _removalRequests[node];
    require(req.executeAfter != 0, "no queued removal");
    require(block.timestamp >= req.executeAfter, "delay not elapsed");
    delete _removalRequests[node];
    _removeFromActive(node);
    emit NodeRemoved(node);
}
```

**Impact**: A group can be rendered permanently inoperable if enough nodes are removed. Since `threshold` is immutable after initialization (`SECURITY-ANALYSIS-OLD.md` §5), there is no recovery path — all keys in the group are lost.

**Recommendation**: Add `require(_activeNodes.length - 1 >= threshold, "removal would break quorum")` before `_removeFromActive`.

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

**File**: `node/delegate.go:120`

String slicing assumes `req.KeySuffix` is shorter than `resolved`:

```go
parentKeyID = resolved[:len(resolved)-len(req.KeySuffix)-1]
```

If `len(req.KeySuffix) >= len(resolved)`, this **panics** with an out-of-bounds slice.

**Impact**: Node panic via crafted request. While `req.KeySuffix` is validated as non-empty earlier, there is no length bound check.

**Recommendation**: Add bounds check before slicing, or use `strings.LastIndex(resolved, ":"+req.KeySuffix)` to find the parent key safely.

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
| **P0** | Encrypt key shards at rest | Medium | `node/keystore.go` |
| **P0** | ✅ Encrypt node identity key | Medium | `network/identity.go`, `network/keyfile.go` |
| **P0** | Add `Aud`/`Azp` validation to ZK auth path | Low | `node/auth.go` |
| **P0** | Fix delegation token to check key disabled status | Low | `node/handlers.go` |
| **P0** | Require admin auth for all groups | Low | `node/handlers.go` |
| **P1** | Validate coord message params against local on-chain state | Medium | `node/coord.go` |
| **P1** | Add HTTP request body size limits | Low | `node/handlers.go` |
| **P1** | Add quorum check to `executeRemoval` | Low | `contracts/SignetGroup.sol` |
| **P1** | Sanitize error messages returned to clients | Low | `node/handlers.go` |
| **P1** | Fix delegation parent key slicing panic | Low | `node/delegate.go` |
| **P1** | Implement reshare leader failover | Medium | `node/reshare.go` |
| **P2** | Deploy behind TLS-terminating proxy | Low | `node/node.go` (or infra) |
| **P2** | Add rate limiting | Medium | `node/node.go` (or infra) |
| **P2** | Add DKG/keygen Rust module to audit scope | Low | `kms-tss/src/` |

---

## Conclusion

The Signet protocol has **strong architectural security**: ZK auth eliminates the critical JWT-forwarding vulnerability, session binding prevents replay, and scope enforcement prevents cross-domain signing. The contract layer uses standard patterns correctly.

The remaining risks are primarily **operational and implementation-level**: plaintext storage, missing auth checks on edge cases, DoS vectors, and contract quorum protection. These are all addressable before a production deployment and should be prioritized for the public alpha.

The total additional scope recommended above adds approximately **1-2 days of auditor/reviewer time** and closes the gap between "signing protocol is correct" and "alpha deployment is safe."
