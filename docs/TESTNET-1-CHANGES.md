# Testnet 1 Changes

Changes from testnet 0 (single-curve FROST secp256k1 with ZK auth) to
testnet 1 (multi-scheme signing, scoped sub-keys, delegation tokens,
key lifecycle management).

---

## 1. Multi-Scheme Signing

Testnet 0 supported only FROST Schnorr on secp256k1. Testnet 1 adds
two additional signing schemes, all sharing the same DKG and storage
infrastructure.

| Scheme | Curve | Use case |
|--------|-------|----------|
| FROST Schnorr | secp256k1 | On-chain Schnorr verification, general signing |
| FROST Schnorr | Ed25519 | Solana (Ed25519SigVerify precompile) |
| Threshold ECDSA | secp256k1 | EVM ecrecover, EIP-3009, EIP-712, x402 payments |

### Threshold ECDSA (DJNPO20)

4-round robust protocol (3 presign + 1 sign). Requires N >= 2t+1.
Produces standard ECDSA signatures compatible with on-chain ecrecover.

- Degree-t polynomials for nonce (k) and blinding (a)
- Degree-2t zero-secret polynomials for masking (b, d, e)
- Coordinator (initiating node) aggregates signature shares
- ECDSA signatures include recovery byte v for ecrecover
- s-value normalized to lower half of curve order (EIP-2)

### Storage

Curve-prefixed keys in sled: `0x01` secp256k1, `0x02` ed25519,
`0x03` ecdsa_secp256k1. Same key_id with different curves = different
keys. Caller always specifies curve.

### API

All keygen/sign/reshare endpoints accept an optional `curve` field.
Defaults to `secp256k1` (FROST Schnorr) for backwards compatibility.
Sign response includes `ecdsa_signature` (65-byte r||s||v) for ECDSA
keys and `ethereum_signature` (65-byte R.x||z||v) for FROST Schnorr.

---

## 2. Scoped Sub-Keys

Keys can optionally be created with a signing scope that restricts
what payloads the key may sign. The scope is set at keygen time and
is immutable.

### Scope Format

`[1-byte scheme][scheme-specific bytes]`

| Scheme | Byte | Binding | Bytes |
|--------|------|---------|-------|
| Unscoped | `0x00` or absent | Signs any hash | 0 |
| EIP-712 domain | `0x03` | chainId + verifyingContract | 29 (1+8+20) |

### Key Suffix Derivation

When a scope is provided at keygen, the key_suffix is derived
deterministically: `hex(sha256(scope_bytes)[:8])`. Same user + same
scope = same key. The caller does not choose the suffix.

### Structured Sign

Scoped keys reject raw `message_hash` signing. The caller must provide
a structured `payload` with scheme-specific data (e.g. EIP-712 typed
data). Every signing participant independently:

1. Loads the key's scope from local storage
2. Parses the payload per scheme
3. Verifies the payload matches the scope (e.g. chainId, contract)
4. Computes the hash from the payload
5. Signs the locally-computed hash

No node trusts the initiator's hash.

### Reshare

Scope is preserved through reshare. Old-committee nodes extract the
scope from the existing key and thread it through all three reshare
rounds into the new StoredKey.

---

## 3. Delegation Tokens

A delegation token is a JWT signed by the group's threshold key. It
grants an agent long-lived access to a specific sub-key without
requiring the user's OAuth session.

### Lifecycle

1. User authenticates (OAuth/ZK or auth key certificate)
2. User creates a parent key (unscoped ECDSA or FROST key)
3. User creates scoped sub-key(s) under the parent
4. User requests delegation: `POST /v1/delegate`
5. Node threshold-signs a JWT using the parent key
6. Agent authenticates: `POST /v1/auth` with `delegation_token`
7. Agent signs using the session, constrained by the sub-key's scope

### JWT Claims

```json
{
  "iss": "0x<group_address>",
  "sub": "<sub_key_id>",
  "kid": "<parent_key_id>",
  "scheme": "ecdsa_secp256k1",
  "grp": "0x<group_address>",
  "exp": 1680000000,
  "iat": 1677000000,
  "parent_key_pub": "0x<hex>"
}
```

Key IDs in JWT claims do not contain internal namespace prefixes
(`oauth:`, `authkey:`). These are internal to the protocol.

### Verification

Delegation tokens are self-validating. The `scheme` field identifies
the signing scheme (FROST Schnorr or ECDSA). Verification loads the
parent key by `kid` and `scheme`, then verifies the threshold
signature over SHA256(header.payload).

### Delegation Sessions

When an agent authenticates with a delegation token, the session is
locked to the delegated sub-key (`DelegatedKeyID`). Sign requests
auto-resolve to the sub-key without the agent needing to specify
`key_id` or `key_suffix`.

### Revocation

Delete or disable the sub-key. The delegation token becomes useless.
No separate revocation registry.

---

## 4. Session Auth Refactor

Testnet 0 re-verified the full ZK proof on every keygen/sign coord
message (every participant shelled out to `bb verify` per operation).
Testnet 1 verifies the proof once and caches the session.

### Flow

1. Client calls `POST /v1/auth` on one node
2. Node verifies the proof (ZK, auth cert, or delegation token)
3. Node broadcasts `msgAuth` to all group members
4. Each participant independently verifies the proof and caches the
   session
5. Subsequent keygen/sign/delegate coord messages carry a lightweight
   `SessionAuth` (session pub + request sig + nonce + timestamp)
6. Participants verify the request signature against their cached
   session — no ZK re-verification

### Coord Message Types

| Type | Auth | Purpose |
|------|------|---------|
| `msgAuth` (8) | Full proof | Establish session on participants |
| `msgKeygen` (1) | SessionAuth | Distributed key generation |
| `msgSign` (2) | SessionAuth | Threshold signing |
| `msgDelegateSign` (7) | SessionAuth | Sign delegation token JWT |
| `msgSetKeyStatus` (9) | SessionAuth | Disable/enable key |
| `msgDeleteKey` (10) | SessionAuth | Permanently delete key |

---

## 5. Key Lifecycle Management

Keys have a `status` field: `active` (default) or `disabled`.

### Endpoints

| Endpoint | Effect |
|----------|--------|
| `POST /v1/keys/disable` | Set status to disabled |
| `POST /v1/keys/enable` | Set status to active |
| `POST /v1/keys/delete` | Permanently remove |

All three are session-authenticated and coordinated across all group
members via coord messages. Every node independently validates auth
and applies the change.

### Enforcement

Disabled keys are rejected at:
- Sign handler (initiator): 403 "key is disabled"
- Sign coord (participant): silently drops
- Delegate handler: 403 for disabled sub-key or parent key
- Delegate-sign coord (participant): silently drops

Disabled keys remain visible in key listings with `"status":"disabled"`.
Keygen rejects creation of a key that already exists (any status).

---

## 6. Namespace Prefix Cleanup

Internal key ID prefixes (`oauth:`, `authkey:`) are no longer visible
to clients. All HTTP responses, JWT claims, and delegation token
fields return unprefixed key IDs. The prefixes exist only in internal
storage and coord message processing.

---

## 7. ZK Circuit Update

Updated signet-circuits dependency to v0.3.0. The `aud` and `azp`
JWT claims are now optional in the ZK circuit — if the expected value
has length 0, the claim check is skipped. This enables OAuth providers
that don't include `azp` (e.g. Clerk, Better Auth) without requiring
separate circuits.

---

## 8. Infrastructure

- KMS renamed from `kms-frost` to `kms-tss` (reflects multi-scheme)
- KMS CLI: `list-keys`, `migrate-group` commands
- Refactored Go handlers into `handlers.go` (extracted from `node.go`)
- Helper extraction: `normalizeGroupID`, `parseCurve`, `lookupGroup`,
  `applySessionAuth`, `runSession`, `PartyIDsToStrings`

---

## Breaking Changes

- **Storage format**: curve-prefixed sled keys. Existing testnet 0
  keys are not readable. Clean wipe required.
- **Coord protocol**: new message types (msgAuth, msgDelegateSign,
  msgSetKeyStatus, msgDeleteKey). Not backwards compatible with
  testnet 0 nodes.
- **API responses**: key_id fields no longer contain `oauth:` prefix.
  Clients that parsed or stored the prefixed form need updating.
- **KMS binary**: renamed from `kms-frost` to `kms-tss`. Deployment
  scripts and systemd units need updating.
