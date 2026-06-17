# Signet Protocol Security Audit (Kimi)

**Auditor**: Claude Code (powered by `moonshotai/kimi-k2.6`)
**Date**: 2026-06-13
**Branch**: `main`
**Commit**: `a420f5f` (plus prior history)
**Scope**: Go node (`node/`, `network/`), Rust KMS (`kms-tss/src/ecdsa_session.rs`), Solidity contracts (`contracts/contracts/`)

---

## Executive Summary

This audit was conducted with the Kimi model to assess the Signet protocol's security posture ahead of a public alpha deployment. The codebase has matured significantly since the original `SECURITY-ANALYSIS-OLD.md` was written. The most critical historical vulnerability — raw JWT forwarding that collapsed the threshold trust model to 1-of-n — has been fixed via ZK proofs bound to ephemeral session keys (commit `a420f5f`). ECDSA signature formatting (EIP-2 low-S normalization and v-byte recovery) is correctly implemented.

All critical (C1–C5) and high-severity (H1–H7) findings have since been addressed on the `feat/at-rest-encryption` branch: **at-rest storage encryption** (key shards in the Rust KMS, and the node identity key), the **ZK/delegation authorization edge cases** (C3, C4), **admin endpoint access control** (C5), **coord parameter validation** (H1), **protocol message sender binding** (H2), **smart contract quorum protection** (H4), and the H3/H5/H7 hardening items — with H6 (reshare leader failover) partially mitigated (manual takeover; automatic failover deferred). The Medium tier (TLS, rate limiting, JWKS refresh, etc.) is largely open. See per-finding **Status** lines below.

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

**File**: `kms-tss/src/storage.rs`, `kms-tss/src/encrypted_store.rs`, `kms-tss/src/custody.rs` (production); `node/keystore.go` (dev path)
**Status**: ✅ Resolved for the production path (`feat/at-rest-encryption`); Go dev path unchanged (dev-only)

Key shards (the most sensitive data in the system) were stored as **plaintext JSON**. OS file permissions (`0600`) were the only protection.

**Impact**: If an attacker gains read access to the filesystem (container escape, backup exposure, disk theft, or insider threat), all threshold shares are immediately compromised. With `t` shares from any `t` nodes, the full private key can be reconstructed.

**Resolution**: The production path is the Rust KMS, which now does envelope encryption (`Storage::new_encrypted`): each stored value is sealed with a per-record random DEK wrapped by a KEK via XChaCha20-Poly1305, with AAD binding ciphertext to its addressing context (anti-swap) and a `KeyCustody` trait (`LocalKeyCustody`, `Zeroizing` KEKs, HKDF subkeys, rotation by `kek_version`). See `docs/at-rest-encryption-spec.md`. The Go `LocalKeyManager` (`node/keystore.go`) still stores plaintext JSON in bbolt, but that path is **dev/test-only** (`--no-kms`); production uses the remote KMS over gRPC.

---

### C2. Plaintext Node Identity Key

**File**: `network/identity.go`, `network/keyfile.go`
**Status**: ✅ Resolved (`feat/at-rest-encryption`)

The secp256k1 private key that defines the node's identity (peer ID and Ethereum address) was written as **raw protobuf bytes** to `node.key` with `0600` permissions and no encryption.

**Impact**: This key is the node's on-chain identity. Compromise allows full impersonation — participation in signing sessions, acceptance of group invitations, and on-chain action as the node.

**Resolution**: When `SIGNET_NODE_KEY_PASSPHRASE` is set, a newly generated `node.key` is sealed with XChaCha20-Poly1305 under a scrypt-derived key (`network/keyfile.go`). The envelope is self-describing via a magic prefix, so legacy plaintext keys still load (opt-in for existing nodes); `devnet-init` honors the same variable. Unset = legacy plaintext, matching the KMS `SIGNET_KMS_KEY` opt-in. Covered by `network/keyfile_test.go`.

---

### C3. ZK Auth Path Missing Client ID / Audience Validation

**File**: `node/auth.go` (`ValidateAuthProof`)
**Status**: ✅ Resolved (`feat/at-rest-encryption`)

The ZK proof verification path validated expiry, issuer trust, `sub` presence, JWKS modulus match, and ZK proof validity via `bb verify`, but did **not** validate `Aud`/`Azp`.

**Impact**: Cross-application token replay. A JWT obtained for app A could be used against Signet group B if both trust the same OAuth issuer.

**Resolution**: `ValidateAuthProof` now enforces the group's `ClientIds` allowlist (client identity resolved `azp → aud`), mirroring `ValidateJWTForSession`. This is sound because `proof.Aud`/`proof.Azp` are ZK public inputs — a successful `bb verify` binds them to the real JWT. Covered by `TestValidateAuthProofClientIDAllowlist` in `node/auth_test.go`.

---

### C4. Delegation Token Session Bypasses Key Disable Check

**File**: `node/handlers.go` (`handleAuth` delegation path)
**Status**: ✅ Resolved (`feat/at-rest-encryption`)

When a delegation token was presented, the `handleAuth` delegation path checked only that the delegated sub-key *existed*, not that it was active.

**Impact**: A user who disables a compromised sub-key could still establish a delegation session for it. (The participant-side delegate-sign handler in `coord.go` already rejected disabled keys at signing time, so signing was blocked there — but the originating node still accepted and forwarded the session.)

**Resolution**: The delegation path now reads `info.Status` and rejects a disabled sub-key with `http.StatusForbidden` before creating or forwarding the session — fail-fast, aligned with the existing participant-side enforcement.

---

### C5. Admin Endpoints Unprotected for Groups Without Auth Keys

**Files**: `node/handlers.go` — `handleListKeys`, `handleStartReshare`, `handleReshareStatus`
**Status**: ✅ Resolved (`feat/at-rest-encryption`)

These endpoints only validated `AdminAuth` when `n.auth.HasAuthKeys(groupID)` returned true, so groups with **only OAuth issuers** (no auth keys) exposed them with **no authentication**.

**Impact**: Anyone with network access could list keys, trigger reshares, and query status for OAuth-only groups.

**Resolution**: The `HasAuthKeys` gate was removed — `ValidateAdminAuth` is now always required (fail closed). A group with no trusted authorization key has no admin principal and is rejected with `401`. Admin auth is group-scoped (key must be trusted for the target group; signature covers `adminAuthHash(groupID,…)`), so a group-A admin cannot act on group B. OAuth-only groups must register an on-chain authorization key to use admin endpoints. Covered by `TestAdminEndpointsFailClosed`, `TestAdminAuthIsGroupScoped`, `TestReshareStatusAllowsValidAdminKey`, `TestReshareStatusRejectsUntrustedAdminKey` in `node/handlers_admin_test.go`.

---

## High (P1)

These issues could lead to unauthorized access, DoS, or operational disruption.

### H1. Coord Message Parameters Trusted from Initiator

**File**: `node/coord.go` (`groupState`, `checkKeygenParams`, `checkSignerSet`)
**Status**: ✅ Resolved (`feat/at-rest-encryption`)

Participants in a signing session previously trusted initiator-supplied `Parties`, `Threshold`, and `Signers` from the coord message without validating them against on-chain state.

**Resolution**: Participants now validate parameters against their own on-chain-derived state (`n.groups`) before acting:
- **keygen** (`checkKeygenParams`): `msg.Threshold` must exactly match the group threshold, the party set must be non-empty, and every party must be an active member (subset allowed). Rejected with `coordNACK`.
- **sign** (`checkSignerSet`): every signer must be an active member, and the count of distinct signers must be ≥ the group threshold. Rejected (session aborts).

The reshare coord paths are intentionally unchanged — reshare legitimately changes committee/threshold and is gated by deterministic leader election and on-chain-driven job creation. Covered by `TestCheckKeygenParams`, `TestCheckSignerSet`, and `TestGroupState` in `node/coord_params_test.go`.

---

### H2. Protocol Message Sender Impersonation

**File**: `network/session.go` (`handleStream`), `network/mux.go` (`handleInbound`)
**Status**: ✅ Resolved (`feat/at-rest-encryption`)

The libp2p `handleStream` handler reads `tss.Message` from a peer stream and enqueues it into the session's incoming channel **without verifying that `msg.From` matches the authenticated transport peer** (`s.Conn().RemotePeer()`). libp2p authenticates the transport layer (you know which peer opened the stream), but the application layer blindly trusts the `From` field embedded in the CBOR message body.

```go
func (sn *SessionNetwork) handleStream(s libp2pnet.Stream) {
    defer s.Close()
    msg, err := readMessage(s)
    // ... no check that msg.From == s.Conn().RemotePeer() ...
    select {
    case sn.incoming <- msg:
    // ...
    }
}
```

**Attack scenario**: Node A is compromised. It opens an authenticated stream to Node B (provably as A), but sends a message with `msg.From = "party-C"`. Node B forwards `From = "party-C"` to the KMS, which processes it as if it came from C.

**Impact by protocol**:

| Protocol | What forged `From` enables |
|---|---|
| **FROST Sign** | Overwrite an honest party's commitment with a malicious one, causing signature failure or nonce bias |
| **ECDSA Sign** | Inject invalid R2/R3/R4 values attributed to an honest party, causing interpolation failure or invalid signature |
| **FROST Keygen** | Corrupt an honest party's DKG package, causing an invalid group key |
| **Reshare** | Inject invalid reshare values attributed to an honest party, corrupting the new committee's shares |

The FROST/ECDSA libraries validate cryptographic inputs (serialization lengths, curve points, consistency checks, zero-hash rejection), but they rely on the caller's guarantee that each message was sent by the claimed party. The robustness guarantees assume "up to t malicious **participants**" — not "up to t malicious **streams that can impersonate anyone**". This collapses the effective security from t-of-n to 1-of-n for message injection.

**Resolution**: Both inbound protocol-message handlers now bind `msg.From` to the authenticated libp2p peer and drop any mismatch:

```go
if expected := tss.PartyID(s.Conn().RemotePeer().String()); msg.From != expected {
    // log + return (drop)
}
```

- `SessionNetwork.handleStream` (`network/session.go`) — keygen/sign path.
- `MuxNetwork.handleInbound` (`network/mux.go`) — reshare path (checks `env.Msg.From`).

This is safe for legitimate traffic because a `tss.PartyID` is exactly the peer ID string, and every party sets `From` to its own identity when sending — so legit `From` always equals the authenticated sender. Covered by `TestSessionRejectsForgedSender` and `TestMuxRejectsForgedSender` in `network/host_test.go` (a forged-`From` message is dropped while a correctly-attributed one is delivered); the full keygen/sign/reshare integration suite still passes.

---

### H3. No HTTP Request Body Size Limit

**File**: `node/node.go` (`limitRequestBody` middleware)
**Status**: ✅ Resolved (`feat/at-rest-encryption`)

All HTTP handlers used `json.NewDecoder(r.Body)` with no limit — DoS via arbitrarily large POST bodies, especially on the unauthenticated, ZK-verifying `/v1/auth`.

**Resolution**: A `limitRequestBody` middleware wraps the mux and applies `http.MaxBytesReader` per path: 256 KiB for `/v1/auth`, 32 KiB for `/admin/*`, 64 KiB default. Over-limit bodies surface as a decode error (400). Covered by `TestLimitRequestBody` in `node/httplimit_test.go`.

---

### H4. SignetGroup Removal Doesn't Check Quorum

**File**: `contracts/contracts/SignetGroup.sol` (`executeRemoval`)
**Status**: ✅ Resolved (`feat/at-rest-encryption`)

`executeRemoval` removed a node without checking that the remaining active set stays ≥ `threshold`. Since `threshold` is immutable after init, a quorum-breaking removal permanently bricks the group (all keys unrecoverable).

**Resolution**: Added `require(_activeNodes.length > threshold, "removal would break quorum")` before `_removeFromActive` (the node is still counted, so post-removal size is `length - 1`; the `> threshold` form is equivalent and avoids unsigned underflow). `testIsOperational` updated and `testExecuteRemoval_RevertsIfBreaksQuorum` added; all Foundry tests pass.

---

### H5. Error Messages Leak Internal State

**File**: `node/handlers.go` (`(*Node).httpError`, `genericErrorMessage`)
**Status**: ✅ Resolved (`feat/at-rest-encryption`)

Error messages were returned raw to the client (`"key not found: group=... key=..."`, etc.), enabling enumeration of valid group/key IDs.

**Resolution**: `httpError` is now a method on `*Node`. For `401`/`403`/`404`/`500` it logs full detail server-side and returns a generic message; `400`/`409`/`503` keep useful non-sensitive detail. All 90 call sites converted; the two free 400-only helpers use a raw `writeJSONError`. Covered by `TestHTTPErrorSanitization`, `TestGenericErrorMessage` in `node/httperror_test.go`.

---

### H6. Reshare Leader Failover Missing

**File**: `node/reshare.go`, `node/handlers.go` (`handleStartReshare`), `node/node.go`
**Status**: ⚠️ Partially mitigated (`feat/at-rest-encryption`); automatic failover deferred

If the elected reshare leader (lexicographically smallest member) is down, a chain-event-driven reshare does not start automatically.

**Mitigation (implemented)**: `POST /admin/reshare` is now routed (was an unrouted handler) as a **manual** failover under group-scoped admin auth — it takes over an existing stalled job from any live node (or creates a refresh). Combined with the existing on-demand self-heal (a sign on a stale key lets any member coordinate it), operators have recourse.

**Residual / deferred**: Concurrent coordinators across different nodes are not prevented (generation tracking prevents corruption, not churn) — operators must only take over when the leader is confirmed down. Automatic, split-brain-safe failover (staggered-timeout takeover + single-coordinator enforcement) is specified under "Leader Failover (H5)" in `docs/DESIGN-RESHARE-HARDENING.md`.

---

### H7. Delegation Token Parent Key Slicing Panic

**File**: `node/delegate.go` (`parentKeyFromResolved`)
**Status**: ✅ Resolved (`feat/at-rest-encryption`)

`parentKeyID = resolved[:len(resolved)-len(req.KeySuffix)-1]` panicked when `len(req.KeySuffix) >= len(resolved)` — reachable via a delegation-token session whose `resolved` key_id is not derived from the suffix.

**Resolution**: Extracted `parentKeyFromResolved`, which anchors the `":<suffix>"` match at the end of `resolved` and returns `ok=false` (→ 400) for empty/absent/oversized suffixes instead of slicing by length. Also blocks delegation-of-delegation. Covered by `TestParentKeyFromResolved` in `node/delegate_test.go`.

---

## Medium (P2)

### M1. No TLS on HTTP API

**File**: `node/node.go:277`
**Status**: ⚠️ Open — not yet addressed

The HTTP API is plaintext. Session pubkeys, auth tokens, and signatures transit in the clear.

**Recommendation**: Terminate TLS at a reverse proxy (nginx, Caddy) or add native TLS to the Go server. This is documented in `PRODUCTION-GAPS.md` as critical.

---

### M2. No Rate Limiting

**File**: `node/node.go`
**Status**: ⚠️ Open — not yet addressed

No rate limiting on any endpoint. `/v1/auth` triggers expensive `bb verify`; `/v1/keygen` and `/v1/sign` consume threshold protocol resources.

**Recommendation**: Add per-IP and per-session rate limits as middleware or at the reverse proxy.

---

### M3. JWKS Cache 1-Hour Minimum Refresh

**File**: `node/auth.go:138`
**Status**: ⚠️ Open — not yet addressed

`jwk.WithMinRefreshInterval(1*time.Hour)` means a compromised JWKS key remains trusted for up to 1 hour after rotation.

**Recommendation**: Reduce to 5-15 minutes for production, or implement emergency JWKS revocation via an on-chain flag.

---

### M4. Peer Auto-Registration Without Allowlist

**File**: `network/host.go`
**Status**: ⚠️ Resource angle fixed (`feat/at-rest-encryption`); impersonation angle low-risk; member allowlist deferred

Any peer that connects via libp2p was auto-registered in the party mapping, with no application-level allowlist beyond libp2p's transport handshake.

**Impersonation/metadata impact (low-risk, by design):** `partyID` *is* the libp2p peer ID string, and the peer ID is the cryptographic hash of the peer's public key, authenticated by the transport handshake. A rogue peer can therefore only register *itself* — it cannot spoof a member's `partyID`. The mapping is a lookup cache, not an authorization boundary: all sensitive coord operations are independently gated by on-chain membership (reshare `senderIsMember`; keygen/sign `Parties`/`Signers` ⊆ members + threshold via H1) and session/admin auth, and TSS sessions are built from explicit member lists. So a rogue in the map gains no signing ability and cannot impersonate.

**Resource/availability impact (the real issue — fixed):** `Disconnected` was a no-op, so the `parties`/`peers` maps grew unboundedly as distinct (including ephemeral/rogue) peers connected and disconnected — a slow memory-exhaustion vector — and no `ConnManager` bounded concurrent connections ("zombie peers"). Resolution:
- `Disconnected` now evicts a peer's mapping once it has no remaining connections, bounding the map to currently-connected peers (`deregisterPeer`). `self` is never evicted.
- `PeerForParty` falls back to decoding the `partyID` (it equals the peer ID string), so the map is a pure cache and eviction never breaks message routing.
- A libp2p `ConnManager` (low/high watermarks 96/192, 1-min grace) now bounds concurrent connections; the grace period exceeds a 30s session so active members aren't pruned mid-session.
- Covered by `TestPeerForPartyFallback` and `TestPeerMappingEvictedOnDisconnect` in `network/host_test.go`.

**Deferred — member allowlist (defense-in-depth):** Restrict registration (and/or reject coord streams) to peers in the node's **allowed set = the union of active members across *all* groups the node participates in** (not a single group — a node may belong to several). This is a layering change: the `network` package would need group-membership state from the `node` layer (e.g. an injected `isAllowedPeer(peerID) bool` predicate backed by `n.groups`). It complements H1's per-message checks and the connection-manager bounds above; tracked as future hardening.

---

### M5. `parseDelegationIdentity` is Fragile

**File**: `node/node.go:430-472`
**Status**: ⚠️ Open — not yet addressed

The function assumes the issuer starts with `https://` and does ad-hoc string splitting. Non-standard issuers or malformed key IDs could cause incorrect parsing.

**Impact**: Incorrect identity resolution for delegation tokens with non-HTTPS issuers.

**Recommendation**: Use a robust parser that handles the full `oauth:<iss>:<sub>[:suffix]` structure explicitly, with proper URL parsing for the issuer component.

---

### M6. EIP-712 Scope: `HexToAddress` Silently Returns Zero

**File**: `node/scope.go` (`verifyEIP712Scope`)
**Status**: ✅ Resolved (`main`)

`common.HexToAddress(typedData.Domain.VerifyingContract)` silently returns the zero address on invalid input. If the scope also encoded a zero address, a malformed payload could pass verification.

**Resolution**: `verifyEIP712Scope` now rejects an empty `verifyingContract` and rejects the zero address after conversion (so malformed/empty input can no longer fail open). This landed alongside a broader scope-tightening: `0x03` scopes now also bind the EIP-712 **primary type** via `keccak256(encodeType(primaryType))` (scope grew 29→61 bytes), and require `chainId`/`verifyingContract` to be declared in the `EIP712Domain` type (closing a checked-vs-signed mismatch). A new `ValidateScope` is run at keygen so malformed scopes fail fast. Covered by `TestScopeRejectsZeroContract`, `TestScopeRejectsDifferentTypeSameDomain`, `TestScopeRejectsUndeclaredDomainFields`, `TestBuildEIP712ScopeRejectsBadTypeHash` in `node/scope_test.go`. **Note:** this is a breaking scope-format change — SDK/clients must build the 61-byte typed scope (see `docs/DESIGN-SCOPED-SUBKEYS.md`).

---

### M7. Clock Skew Sensitivity

**File**: `node/sessions.go:18`
**Status**: ⚠️ Open — not yet addressed

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
| L7 | No `threshold` update function | `SignetGroup.sol` | `threshold` is immutable after init. Removal below quorum is now blocked (see H4), so a group can no longer be driven below quorum via removal; a `threshold` update path is still absent (future work) |

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
| **P0** | Encrypt node identity key | Medium | `network/identity.go` |
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
