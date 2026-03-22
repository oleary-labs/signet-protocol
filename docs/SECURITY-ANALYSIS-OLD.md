# Signet Security Analysis

## Architecture Overview

The system is a threshold signing network where nodes hold key shards, coordinate via libp2p, derive trust from on-chain smart contracts, and optionally authenticate callers via OAuth JWT. Here's the security breakdown across every layer.

---

## 1. Critical Issues

### 1.1 No At-Rest Encryption for Key Shards

**`node/keystore.go`** — Key shards (the most sensitive data in the system) are stored as plaintext JSON in a bbolt database. OS file permissions (`0600`) are the only protection.

**Impact:** If an attacker gains read access to the filesystem (container escape, backup exposure, disk theft), all threshold shares are immediately compromised. Combined with shares from `t` nodes, the full private key can be reconstructed.

**Recommendation:** Encrypt shards at rest using a key derived from a hardware token, KMS, or passphrase-based KDF. Consider sealing shards with a platform TPM or using an envelope encryption scheme.

### 1.2 Node Identity Key Stored Plaintext

**`network/identity.go`** — The secp256k1 private key that defines the node's identity (peer ID and Ethereum address) is written as raw protobuf bytes to `node.key` with `0600` permissions and no encryption.

**Impact:** This key is the node's on-chain identity. Compromise allows impersonation — the attacker can participate in signing sessions, accept group invitations, and act as the node on-chain.

### 1.3 `TestMode` Globally Disables JWT Crypto Validation

**`node/config.go:19`** / **`node/auth.go:138-139`**

```go
if g.testMode {
    verified = insecure  // signature and expiry checks completely skipped
}
```

`TestMode` is a single YAML boolean that disables signature verification and expiry checking for **all groups on the node**. If a production node is accidentally (or maliciously) started with `test_mode: true`, any crafted JWT with a matching `iss` and `sub` is accepted regardless of signature.

**Recommendation:** Remove `TestMode` from production builds entirely (build tag) or restrict it to a per-group override that cannot be set via config file. At minimum, log a prominent startup warning.

### 1.4 Raw JWT Forwarded to All Participants — Breaks Threshold Trust Model

**`node/coord.go:51`** — The raw JWT bearer token is embedded in the CBOR `coordMsg` and broadcast to every participant in the signing group.

```go
AuthToken []byte `cbor:"9,keyasint,omitempty"`
```

**Why this is critical:** The fundamental security assumption of a threshold signing system is that **no single compromised node can break the protocol**. Forwarding the raw JWT violates this assumption. A single malicious or compromised node can extract the bearer token from the coord message and replay it against any node's HTTP API to initiate unauthorized keygen or sign sessions — effectively impersonating the original user for the lifetime of the token.

This collapses the threshold trust model from "t-of-n nodes must collude" to "any 1 node can act as the user." The compromised node doesn't even need to participate in the threshold protocol — it just calls `/v1/keygen` or `/v1/sign` with the stolen JWT.

**Impact:**
- A single compromised node can generate new keys under the victim's identity (`sub`)
- A single compromised node can sign arbitrary messages under existing keys owned by the victim
- The attack window is the token's remaining lifetime (often 1 hour for OIDC tokens)
- The attack is invisible to the original caller — it looks like a legitimate API request

**Recommendation:** Replace raw token forwarding with a derived proof that each node can verify independently but cannot replay:

1. **Session-bound proof:** The initiator signs a session-specific challenge (e.g., `HMAC(token, sessionID)` or a signature over `groupID || keyID || nonce`) using a claim derived from the JWT. Participants verify the proof without seeing the original token.
2. **Token hash + attestation:** Forward only a hash of the token. The initiating node attests to having validated it, and participants trust the attestation based on the initiator's on-chain identity. This is weaker (trust shifts to the initiator) but still better than exposing the raw credential.
3. **Short-lived session tokens:** The initiator mints a single-use, session-scoped token (signed with its node key) that references the original JWT's `sub` and `iss`. Participants verify the node signature and the session binding.

---

## 2. High Severity Issues

### 2.1 HTTP API Has No Authentication (for groups without issuers)

**`node/node.go:151-157`** — The HTTP API is a raw `http.ServeMux` with no middleware. For groups that have no on-chain issuers configured, the `/v1/keygen` and `/v1/sign` endpoints require only a `group_id` and `key_id` — no bearer token, no API key, no mTLS.

```go
} else if keyID == "" {
    httpError(w, http.StatusBadRequest, "key_id is required")
    return
}
```

**Impact:** Anyone with network access to the API port can trigger key generation or sign arbitrary messages for any group without issuers. This is by design for backward compatibility, but it means groups are fully open by default.

**Recommendation:** Consider requiring authentication for all groups, or at minimum binding the API to localhost and documenting the exposure clearly.

### 2.2 No Rate Limiting or Request Throttling

The HTTP API and the libp2p coord stream handler have no rate limiting. An attacker can:
- Flood `/v1/keygen` to exhaust the worker pool and fill disk with shards
- Flood `/v1/sign` to saturate CPU with threshold signing
- Flood coord streams to DoS peer nodes

### ~~2.3~~ Moved to 1.4 (Raw JWT Forwarding — see Critical Issues)

### 2.4 Client ID Validation is Optional and Loose

**`node/auth.go:158-170`** — If `azp`/`client_id` is missing from the token, the check is silently skipped. A token without an `azp` claim bypasses client ID restrictions entirely:

```go
if azp != "" && !containsString(matched.ClientIds, azp) {
    return "", fmt.Errorf("untrusted client_id: %s", azp)
}
// If azp == "" -> passes silently
```

**Impact:** An attacker with a valid token from the right issuer but without `azp`/`client_id` claims can bypass client restriction. This depends on the OAuth provider, but some providers omit `azp` for certain grant types.

**Recommendation:** If `ClientIds` are configured, require that `azp` or `client_id` is present and matches — don't silently pass when the claim is absent.

---

## 3. Medium Severity Issues

### 3.1 No Peer Authentication at Application Level

**`network/discovery.go`** — mDNS discovery uses a hardcoded service tag (`"threshold-mpc"`). Any node on the local network advertising this tag is auto-connected and registered as a valid party. DHT discovery is similarly open.

**`network/host.go`** — The `connectionNotifee` automatically registers any connected peer into the party mapping. There is no allowlist or mutual authentication beyond libp2p's transport handshake.

**Impact:** A rogue node on the local network can inject itself into peer mappings. While it can't participate in an existing threshold signing session (it won't have the key shard), it can observe connection metadata and potentially disrupt session formation.

### 3.2 Coord Message Trusts Initiator-Supplied Parameters

**`node/coord.go:34-52`** — The coord message includes `Parties`, `Threshold`, `Signers`, and `MessageHash`, all supplied by the initiator. The receiving node trusts these values and uses them directly to configure the protocol session.

A compromised or malicious initiator could:
- Supply a manipulated `Parties` list (e.g., including a colluding node not in the on-chain group)
- Set a lower `Threshold` than what the group contract specifies
- Forward a `MessageHash` that differs from what the API caller intended

**Recommendation:** Recipients should independently verify `Parties`, `Threshold`, and group membership from their own local state (the `n.groups` map), rather than trusting the initiator's message.

### 3.3 No `aud` (Audience) Claim Validation

**`node/auth.go:99-155`** — JWT validation checks `iss`, `sub`, `azp`/`client_id`, signature, and expiry — but never validates `aud` (audience). This means a token issued for a different service (but from the same OAuth provider) could be reused against Signet.

### 3.4 On-Chain Issuer Changes Have Polling Latency

**`node/chain.go:39`** — Chain events are polled every 2 seconds. Between an on-chain `IssuerRemoved` event and the next poll, a removed issuer's tokens are still accepted. Similarly, `IssuerAdded` events aren't reflected until the next poll cycle.

### 3.5 `executeRemoval` / `executeAddIssuer` / `executeRemoveIssuer` Are Callable by Anyone

**`contracts/contracts/SignetGroup.sol:169-177`** — After the timelock delay, anyone can call `executeRemoval(node)`, `executeAddIssuer(hash)`, or `executeRemoveIssuer(hash)`. This is a common pattern (the timelock itself is the security mechanism), but it means a frontrunner or MEV bot could execute removals at unfavorable times.

---

## 4. Lower Severity / Hardening

| Area | Finding |
|------|---------|
| **No TLS on HTTP API** | `ListenAndServe` serves plain HTTP. In production, the API should be behind a TLS-terminating proxy or use `ListenAndServeTLS`. |
| **Error messages leak internals** | `httpError` returns raw error strings (e.g., `"load config: ..."`) that could reveal internal state to attackers. |
| **10MB message limit** | `network/host.go` caps messages at 10MB, which is adequate but could still allow memory pressure with many concurrent sessions. |
| **No request body size limit** | HTTP handlers use `json.NewDecoder(r.Body)` without `http.MaxBytesReader`, allowing arbitrarily large POST bodies. |
| **JWKS cache lifetime** | 1-hour minimum refresh interval means a compromised JWKS key remains trusted for up to 1 hour after rotation. |
| **No `threshold` validation on node removal** | `SignetGroup.executeRemoval` doesn't check if removing the node would drop the active set below `threshold + 1` (quorum). |

---

## 5. Smart Contract Notes

The Solidity contracts are relatively clean with proper patterns:
- Swap-and-pop O(1) removal (correct 1-based indexing)
- Timelocked operations for node removal and issuer management
- Manager-only access control on sensitive operations
- `initializer` modifier prevents re-initialization
- `_pubkeyToAddress` correctly validates 65-byte uncompressed key format

One gap: the `threshold` value is immutable after `initialize()`. There is no function to update it, which means if nodes are removed below quorum, the group becomes permanently inoperable without deploying a new group.

---

## 6. Summary Priorities

| Priority | Issue | Effort |
|----------|-------|--------|
| **P0** | Replace raw JWT forwarding with ZK proof + session key (breaks threshold trust model) — see `DESIGN-ZK-AUTH.md` | High |
| **P0** | Encrypt key shards at rest | Medium |
| **P0** | Remove or guard `TestMode` for production | Low |
| **P1** | Validate coord message params against local state | Medium |
| **P1** | Require `azp`/`client_id` when `ClientIds` configured | Low |
| **P1** | Add `aud` claim validation | Low |
| **P1** | Add HTTP request body size limits | Low |
| **P2** | Rate limiting on API and coord streams | Medium |
| **P2** | Peer allowlisting / mutual auth | Medium |
| **P2** | TLS or Unix socket for HTTP API | Low |
