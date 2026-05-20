# Scoped Sub-Keys and Delegation Tokens

Design for agent-friendly key management: OAuth-scoped sub-keys with
signing constraints and long-lived delegation tokens.

---

## 1. Motivation

Applications like WAIaaS need to create keys on behalf of users that
agents can operate autonomously. These keys must be:

- **Scoped to a user** — derived from OAuth identity, can't leak across tenants
- **Constrained in what they sign** — bound to a specific wallet/account
- **Long-lived** — agents operate beyond OAuth token lifetimes
- **Independently revocable** — user can kill an agent's access without affecting other keys

The current system has the primitives (OAuth sessions, key_suffix
namespacing) but lacks signing constraints and delegation lifecycle.

---

## 2. Design

### 2.1 Key Scope

A **scope** is an optional constraint stored with the key that restricts
what payloads the key may sign. Format: `[1-byte scheme][scheme-specific bytes]`.

| Scheme | Byte | Binding data | Verification |
|--------|------|-------------|-------------|
| Unscoped | `0x00` or absent | — | Signs any hash (backwards compat) |
| EVM UserOp | `0x01` | `entryPoint (20) \| chainId (8) \| sender (20)` | Extract sender from packed UserOp at known offset, verify match, hash as `keccak256(abi.encode(userOp, entryPoint, chainId))` |
| Solana tx | `0x02` | `wallet_pubkey (32)` | Extract authority from transaction message, verify match, hash per Solana conventions |
| EIP-712 domain | `0x03` | `chainId (8) \| verifyingContract (20)` | Extract EIP-712 domain from structured payload, verify chainId + verifyingContract match scope, compute `hashTypedData` and sign |

Keys without a scope work exactly as they do today. Keys with a scope
reject raw hash signing — the caller must provide a structured payload.

### 2.2 Key ID Derivation

The sub-key's suffix is derived from the scope:

```
key_suffix = hex(sha256(scope)[:8])
```

The full key_id becomes `oauth:<iss>:<sub>:<scope_hash>`. This ensures:
- Same user + same scope = same key (no duplicates)
- The caller doesn't choose arbitrary names
- The scope is the identity of the key's purpose

### 2.3 Scope Storage

The scope is stored in the KMS alongside the key material as an opaque
byte field on `StoredKey`. Set at keygen time, immutable. Returned via
`GetPublicKey` so the Go node can read it at sign time.

Reshare does not affect the scope — it's metadata, not key material.

### 2.4 Structured Sign Flow

For scoped keys, the sign API accepts a structured payload instead of
a raw hash:

```
POST /v1/sign
{
  "group_id": "0x...",
  "key_id": "...",
  "payload": {
    "scheme": "evm-userop",
    "data": "0x<packed userop bytes>"
  },
  ...session auth...
}
```

The initiating node:
1. Loads the key's scope from storage
2. Parses the payload per scheme
3. Extracts the target (e.g. `sender` from UserOp)
4. Verifies target matches the scope's binding
5. Computes the hash from the structured payload
6. Broadcasts the coord message with the payload included

Each participating node independently:
1. Receives the payload in the coord message
2. Loads the key's scope from its own storage
3. Re-extracts target, re-verifies binding, re-computes hash
4. Only then contributes a signature share

No node trusts the initiator's hash — every node computes it from the
payload. This is the security property: a malicious initiator cannot
trick participants into signing a hash for the wrong target.

### 2.5 Delegation Tokens

A **delegation token** is a JWT signed by the group's FROST threshold
key. It grants an agent long-lived access to a specific sub-key without
requiring the user's OAuth session.

**Lifecycle:**

1. User authenticates via OAuth → session on a node
2. User creates a **parent key** (unscoped FROST or ECDSA key)
3. User creates **sub-keys** scoped to specific purposes under the parent
4. User requests delegation for a sub-key: `POST /v1/delegate`
5. Node constructs JWT claims: `group_id`, `key_id`, `parent_key_id`, `exp`
6. Node initiates threshold signing of the JWT hash using the **parent key**
7. Returns signed JWT to user
8. User provides JWT to agent infrastructure (e.g. WAIaaS persists it)
9. Agent authenticates: `POST /v1/auth` with `delegation_token`
10. Node verifies JWT signature against the **parent key's public key**, checks `exp`, checks sub-key exists → creates session
11. Agent signs using the session, constrained by the sub-key's scope

**Revocation:** User authenticates, deletes the sub-key. The delegation
token becomes useless — it references a nonexistent key. No separate
revocation registry.

**Expiry:** In the JWT `exp` claim. Stateless from the node's
perspective — no storage to garbage collect. When it expires, the user
mints a new one.

**Token format:**

```json
{
  "iss": "0x<group_address>",
  "sub": "<sub_key_id>",
  "kid": "<parent_key_id>",
  "grp": "0x<group_address>",
  "exp": 1680000000,
  "iat": 1677000000
}
```

Signature: threshold-signed by the user's **parent key** (FROST Schnorr
or ECDSA depending on the parent key's scheme). The JWT `kid` field
identifies the parent key used for signing.

### 2.6 Auth Paths (Updated)

| Path | Use case | Session creation |
|------|----------|-----------------|
| OAuth/ZK | User in browser, interactive | ZK proof of JWT → session |
| Auth key certificate | Admin/testing, group bootstrap | Signed cert → session |
| Delegation token | Agent, long-lived autonomous | FROST-signed JWT → session |

All three paths produce a session. The session is scoped to the
authenticated identity and can only operate on keys under that identity.

### 2.7 ZK for Delegation Tokens (Future)

In the current design, nodes see the delegation token in plaintext. A
rogue node could replay it. For the POC this is acceptable — nodes are
semi-trusted (they hold key shares and must cooperate to sign).

Future hardening: a ZK circuit that proves possession of a valid
FROST-Schnorr-signed JWT without revealing it. This requires a new
circuit (the existing `jwt_auth` circuit handles RSA signatures only).
This is significant work but tractable.

---

## 3. API Changes

### 3.1 Keygen

```
POST /v1/keygen
{
  "group_id": "0x...",
  "scope": "0x01<entryPoint><chainId><sender>",   // optional
  ...session auth...
}
```

- `scope` is optional. If provided, the key_suffix is derived from it.
- `key_suffix` is no longer caller-specified when scope is present.
- Response includes `scope` and the derived `key_id`.

### 3.2 Sign (scoped)

```
POST /v1/sign
{
  "group_id": "0x...",
  "key_id": "...",
  "payload": {
    "scheme": "evm-userop",
    "data": "0x..."
  },
  ...session auth...
}
```

- `payload` and `message_hash` are mutually exclusive.
- If the key has a scope, `payload` is required; `message_hash` is rejected.
- If the key is unscoped, `message_hash` works as before.

### 3.3 Delegate

```
POST /v1/delegate
{
  "group_id": "0x...",
  "key_id": "...",
  "expires_in": 2592000,    // seconds, e.g. 30 days
  ...session auth...
}
→ {
  "token": "eyJ...",
  "key_id": "...",
  "expires_at": 1680000000
}
```

Requires active OAuth session. The user must own the key (key_id must
be under their identity namespace).

### 3.4 Auth (delegation path)

```
POST /v1/auth
{
  "group_id": "0x...",
  "delegation_token": "eyJ...",
  "session_pub": "02..."
}
```

Node verifies the JWT, creates a session scoped to the token's key_id.

### 3.5 Delete Key

```
POST /v1/keys/delete
{
  "group_id": "0x...",
  "key_id": "...",
  ...session auth...
}
```

Deletes key material from all nodes. Effectively revokes any delegation
tokens referencing this key. User must own the key.

---

## 4. Storage Changes

### 4.1 KMS (StoredKey)

Add `scope` field:

```rust
pub struct StoredKey {
    pub key_package: Vec<u8>,
    pub public_key_package: Vec<u8>,
    pub group_key: Vec<u8>,
    pub verifying_share: Vec<u8>,
    pub generation: u64,
    #[serde(default)]
    pub scope: Vec<u8>,          // new: empty = unscoped
}
```

Backwards compatible via `serde(default)`.

### 4.2 Proto (PublicKeyResponse)

Add `scope` field:

```protobuf
message PublicKeyResponse {
  bytes  group_key       = 1;
  bytes  verifying_share = 2;
  uint64 generation      = 3;
  bytes  scope           = 4;   // new
}
```

### 4.3 Coord Message

Add `payload` field for scoped signing:

```go
type coordMsg struct {
    // ...existing fields...
    Payload []byte `cbor:"17,keyasint,omitempty"` // structured payload for scoped keys
}
```

---

## 5. Implementation Steps

### Step 1: Scope in Storage (KMS + Proto)

- Add `scope: Vec<u8>` to `StoredKey` (serde default empty)
- Add `scope` to keygen CBOR params
- Store scope at keygen time, return via `GetPublicKey`
- Add `scope` to proto `PublicKeyResponse`
- Update Go `KeyInfo` to include `Scope []byte`

No behavior change — just plumbing the data through.

### Step 2: Scoped Keygen API

- Add `scope` field to keygen request
- Derive key_suffix from scope hash when scope is provided
- Pass scope through coord message so all participants store it
- Return scope and derived key_id in response

### Step 3: Structured Sign (EVM UserOp scheme)

- Add `payload` field to sign request (mutually exclusive with `message_hash`)
- Implement scheme `0x01` (EVM UserOp): extract sender at fixed offset, verify against scope, compute UserOp hash
- Add `payload` to coord message
- Each participant independently verifies scope + computes hash
- Sign the locally-computed hash

### Step 4: Delegation Token Minting

- New endpoint `POST /v1/delegate`
- Caller specifies the sub-key to delegate and the parent key to sign with
- Construct JWT claims: `group_id`, `key_id` (sub-key), `parent_key_id`, `exp`
- Threshold-sign the JWT hash using the **parent key** (regular sign operation)
- Return the signed JWT with the parent key's public key as `kid`

### Step 5: Delegation Token Auth Path

- New auth path in `POST /v1/auth` for `delegation_token`
- Verify JWT signature against the **parent key's public key** (loaded from storage)
- Check `exp`, check sub-key exists, check parent key exists
- Create session scoped to the sub-key's identity namespace

### Step 6: Key Deletion

- New endpoint `POST /v1/keys/delete`
- Verify caller owns the key (identity namespace check)
- Delete from all nodes (KMS storage + local keystore)
- Effectively revokes all delegation tokens for this key

### Step 7: Solana Scheme

- Implement scheme `0x02` (Solana transaction)
- Extract authority/signer from transaction message
- Verify against scope, compute Solana transaction hash
- Same coord message pattern as EVM

### Step 8: EIP-712 Domain Scheme (x402 Payments, Permit2, etc.)

- Implement scheme `0x03` (EIP-712 domain binding)
- Scope format: `0x03 | chainId (8 bytes, uint64 BE) | verifyingContract (20 bytes)` — 29 bytes total
- Caller sends structured EIP-712 payload (domain + types + message)
- Node extracts `chainId` and `verifyingContract` from the payload's domain fields
- Byte comparison against the scope — no ABI encoding or keccak needed
- Node computes `hashTypedData` (EIP-712 struct hash + domain separator → keccak256) and signs
- The typed data structure (primaryType, types, message) is **unconstrained** — only the domain is checked

**x402 compatibility.** The x402 protocol defines three EVM payment mechanisms, all compatible with this scope:

| x402 method | EIP-712 verifyingContract | Typed data | Scope binding |
|-------------|--------------------------|------------|---------------|
| EIP-3009 (`transferWithAuthorization`) | Token contract (e.g. USDC `0x8335...`) | `TransferWithAuthorization{from,to,value,...}` | `chainId + USDC address` |
| Permit2 (`permitWitnessTransferFrom`) | Permit2 contract (`0x0000...22D4...`) | `PermitWitnessTransferFrom{...}` + `Witness{to,validAfter}` | `chainId + Permit2 address` |
| ERC-7710 (delegation) | N/A (uses opaque permissionContext) | Not EIP-712 — payer grants a smart-account delegation out-of-band; facilitator redeems it via `delegationManager.redeemDelegations()` | Not applicable — no Signet signature at payment time. The delegation is established beforehand (e.g. via EIP-7715 session key provisioning, which *would* use scope `0x01`). |

A single key scoped to `chainId:8453 + USDC:0x8335...` can sign EIP-3009
authorizations on Base but cannot sign Permit2 authorizations (different
verifyingContract) or authorizations on other chains (different chainId).
To support both EIP-3009 and Permit2, create two sub-keys with different scopes.

**Security property:** the key can only produce signatures valid under a
specific EIP-712 domain. It cannot sign arbitrary messages, raw hashes,
or typed data for a different contract. The `from` field in EIP-3009 is
implicitly the key's own address — the token contract verifies
`ecrecover(sig) == from`.

**Verified in WAIaaS POC:** The full EIP-3009 flow works end-to-end —
Google OAuth → Signet Robust ECDSA keygen → EIP-712 typed data signing →
Coinbase CDP facilitator verification → on-chain USDC transfer on Base.
Tested against Nansen's x402 API ($0.01/query, USDC on Base mainnet).

### Future: ZK for Delegation Tokens

- New ZK circuit for FROST-Schnorr JWT verification
- Parallel to the existing RSA JWT circuit
- Agent proves possession of valid delegation token without revealing it
- Significant standalone effort — separate design doc

---

## 6. Security Properties

- **Scope enforcement is distributed** — every signing participant independently verifies the scope against the payload. No single node can bypass it.
- **No raw hash signing for scoped keys** — the hash is always computed by the node from the structured payload. A malicious caller cannot submit an arbitrary hash.
- **Delegation tokens are self-validating** — any node can verify the FROST signature without external calls.
- **Revocation is deletion** — no separate revocation registry to manage. Delete the key, the token is dead.
- **Backwards compatible** — unscoped keys work exactly as before. Scope is opt-in at keygen time.

---

## 7. App Binding and Delegation Tokens

### 7.1 Why Not Bind Scopes to Apps?

A natural question: can a scope constrain *who* uses a key, not just
*what* it signs? For example, "this key can only be used from WAIaaS."

This turns out to be the wrong layer for that constraint. The delegation
token already determines who can use a key:

- The delegation token is a bearer credential scoped to a specific sub-key.
- Only the entity holding the token (e.g. WAIaaS) can create a session
  and sign with that key.
- If the token leaks, the user revokes by deleting the sub-key.

Attempting to bind the scope to an "app identity" (auth key, domain,
code hash) adds complexity without meaningful security gain:

- **Auth key binding:** the app proves identity via its auth key, but
  the delegation token already implies the app received authorized
  access. Adding an auth key check at sign time is redundant.
- **Domain/origin binding:** the node sees HTTP requests, not TLS certs
  from the caller. There's no reliable way to verify the request
  originated from a specific domain.
- **Code hash binding:** requires attestation infrastructure that
  doesn't exist in this architecture.

### 7.2 Separation of Concerns

The clean split is:

- **Scopes constrain *what* the key signs** — EVM UserOps for a specific
  sender, EIP-3009 authorizations for a specific token/chain, Solana
  transactions for a specific wallet. Enforced by every signing
  participant independently.
- **Delegation tokens constrain *who* can use the key** — the bearer
  token is the access credential. The app (WAIaaS) holds it and manages
  its own authorization rules (policies, spending limits, domain
  allowlists) on top.
- **App-layer policy constrains *when* and *how much*** — WAIaaS's
  policy engine (spending limits, domain allowlists, approval tiers)
  provides defense-in-depth. Not enforced by Signet, but the app is
  trusted for application-behavior decisions.

This mirrors the trust model from the WAIaaS POC design doc (§1.2):
Signet owns key custody and signing constraints, the application owns
behavioral policy, and (in the end-state) the smart wallet owns
runtime enforcement.
