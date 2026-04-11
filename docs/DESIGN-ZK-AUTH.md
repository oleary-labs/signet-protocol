# Zero-Knowledge JWT Authentication

This document describes the ZK-based authentication scheme for Signet threshold signing. It replaces raw JWT forwarding between nodes with a zero-knowledge proof of JWT validity bound to an ephemeral session key.

## Problem

The previous auth design forwards the raw JWT bearer token from the initiating node to all participants via the coord message. This breaks the threshold trust model: any single compromised node can extract the JWT and replay it to impersonate the user — collapsing the t-of-n security guarantee to 1-of-n.

See `SECURITY-ANALYSIS.md` section 1.4 for the full threat analysis.

## Design Goals

1. **No node sees the JWT signature.** The JWT credential never leaves the client.
2. **Every node independently verifies the user's identity.** No trust delegation to the initiating node.
3. **Session binding.** Proofs cannot be replayed across groups, keys, or sessions.
4. **Fast.** One-time proof generation (~2-7s browser, <1s server). All subsequent requests are a single ECDSA signature (<1ms).
5. **Browser-viable.** The proof can be generated client-side in a web browser via WASM. A server-side fallback exists for constrained clients.

## Scheme Overview

The scheme has two phases:

- **Auth phase** (once per JWT lifetime): The client generates a ZK proof that it holds a valid JWT from a trusted issuer, and binds the proof to an ephemeral session public key.
- **Request phase** (every keygen/sign): The client signs request parameters with the session private key. Nodes verify the signature against the session public key that was bound in the proof.

```
┌─────────────────────────────────────────────────────┐
│                    Client                           │
│                                                     │
│  OAuth login ──▶ JWT (header.payload.signature)     │
│                                                     │
│  ┌─────────────────────────────────┐                │
│  │ Auth phase (once)               │                │
│  │                                 │                │
│  │ 1. Generate session keypair     │                │
│  │    priv = random scalar         │                │
│  │    pub  = priv * G              │                │
│  │                                 │                │
│  │ 2. Fetch OIDC JWKS (RSA mod n)  │                │
│  │                                 │                │
│  │ 3. Generate ZK proof:           │                │
│  │    "I know sig S such that      │                │
│  │     RSA_Verify(n, H.P, S)       │                │
│  │     = true"                     │                │
│  │    Public inputs include:       │                │
│  │      session_pub                │                │
│  │                                 │                │
│  │ 4. POST /v1/auth               │                │
│  │    { header, payload, proof,    │                │
│  │      session_pub }              │                │
│  └─────────────────────────────────┘                │
│                                                     │
│  ┌─────────────────────────────────┐                │
│  │ Request phase (per operation)   │                │
│  │                                 │                │
│  │ 1. Sign request params with     │                │
│  │    session_priv                 │                │
│  │                                 │                │
│  │ 2. POST /v1/keygen or /v1/sign  │                │
│  │    { group_id, key_id, nonce,   │                │
│  │      timestamp, session_pub,    │                │
│  │      request_sig }              │                │
│  └─────────────────────────────────┘                │
└─────────────────────────────────────────────────────┘
```

## Auth Phase

### Client Steps

1. **Generate session keypair.** The client generates a random secp256k1 keypair in memory. The private key is never persisted.

2. **Fetch OIDC JWKS.** The client fetches the OIDC provider's public key (RSA modulus `n`) from `{issuer}/.well-known/openid-configuration` → `jwks_uri`. This is the same key the provider used to sign the JWT.

3. **Generate ZK proof.** Using the noir-jwt circuit (see Circuit Design below), the client proves:
   - It knows a value `S` (the JWT signature) such that `RSA_Verify(n, SHA256(header || "." || payload), S) = true`
   - The proof binds to the session public key and the extracted claims

4. **Submit auth request.** The client sends the proof and unsigned JWT claims (header + payload, no signature) to any Signet node.

### Node Steps (on receiving auth)

1. **Verify the ZK proof** against the public inputs.
2. **Check the JWKS modulus** matches the node's own cached OIDC JWKS for the claimed issuer. This prevents a client from using a fake RSA key.
3. **Check JWT expiry** from the `exp` public input.
4. **Cache the session binding:** `session_pub → { sub, iss, exp }`.

### Proof Public Inputs and Private Witness

| Field | Public / Private | Purpose |
|-------|-----------------|---------|
| `claims_hash` | Public | `SHA256(base64(header) \|\| "." \|\| base64(payload))` — lets nodes read claims |
| `iss` | Public | Issuer URL — nodes check against on-chain trusted issuers |
| `sub` | Public | Subject (user ID) — used for key scoping |
| `exp` | Public | JWT expiry timestamp — nodes reject expired proofs |
| `aud` | Public | Audience claim — nodes check it matches expected value |
| `azp` or `client_id` | Public | Authorized party — nodes check against on-chain client ID list |
| `jwks_modulus` | Public | RSA public key modulus (2048-bit) — nodes verify against OIDC JWKS |
| `session_pub` | Public | Ephemeral secp256k1 public key — binds proof to session |
| JWT signature (`S`) | **Private** | RSA signature — never revealed to any node |

The RSA exponent `e = 65537` is hardcoded in the circuit (standard for all OIDC providers).

## Request Phase

### Client Steps

For each keygen or sign operation:

1. **Build the request body:**
   ```json
   {
     "group_id": "0x...",
     "key_id": "my-key",
     "nonce": "random-16-bytes-hex",
     "timestamp": 1709900000
   }
   ```
   For sign requests, `message_hash` is also included.

2. **Sign the canonical request** with the session private key:
   ```
   request_sig = secp256k1_sign(session_priv, SHA256(canonical(request_body)))
   ```

3. **Send to any node:**
   ```json
   {
     "group_id": "0x...",
     "key_id": "my-key",
     "nonce": "...",
     "timestamp": 1709900000,
     "session_pub": "compressed-33-bytes-hex",
     "request_sig": "64-bytes-hex"
   }
   ```

### Node Steps (on receiving request)

1. **Look up `session_pub`** in the session cache. Reject if not found (client must auth first).
2. **Verify `request_sig`** against `session_pub`.
3. **Check `timestamp`** is within an acceptable window (e.g., 30 seconds).
4. **Check `nonce`** has not been seen before.
5. **Check `exp`** from the cached session. Reject if the JWT has expired.
6. **Derive `key_id`** from the cached `sub` (same logic as current auth: `key_id = sub` or `sub + ":" + key_suffix`).
7. **Proceed with keygen/sign.**

## Coord Message Format

The coord message replaces the current `AuthToken []byte` field with a structured auth block:

```
coordMsg {
  // ... existing fields (Type, GroupID, KeyID, Parties, etc.)

  Auth: AuthProof {
    // ZK proof (verified independently by each node)
    Proof         []byte     // serialized noir proof
    ClaimsHash    [32]byte   // SHA256(header.payload)
    Sub           string     // JWT subject
    Iss           string     // JWT issuer
    Exp           uint64     // JWT expiry unix timestamp
    Aud           string     // JWT audience
    Azp           string     // authorized party / client_id
    JWKSModulus   []byte     // RSA modulus from proof public inputs

    // Session binding
    SessionPub    []byte     // 33-byte compressed secp256k1 public key

    // Request binding (per-operation)
    RequestSig    []byte     // secp256k1 signature over session params
    Nonce         []byte     // random, single-use
    Timestamp     uint64     // unix seconds
  }
}
```

### Participant Verification (on receiving coord message)

Each participant independently:

1. Verifies the ZK `Proof` against `(ClaimsHash, Sub, Iss, Exp, Aud, Azp, JWKSModulus, SessionPub)`.
2. Checks `JWKSModulus` matches its own cached OIDC JWKS for `Iss`.
3. Checks `Exp > now`.
4. Checks `Aud` matches expected audience (if configured).
5. Checks `Azp` is in the on-chain client ID list for the group's issuer (if configured).
6. Verifies `RequestSig` against `SessionPub` over `(GroupID || KeyID || Nonce || Timestamp)`.
7. Checks `Nonce` uniqueness and `Timestamp` freshness.
8. Uses `Sub` for key scoping.

No participant sees the JWT signature. No participant trusts the initiator's attestation. Every verification is self-contained.

## Security Properties

### Attacks and Mitigations

| Attack | Mitigation |
|--------|-----------|
| Node replays ZK proof for a different operation | `RequestSig` is required — node does not have `session_priv` and cannot sign new requests |
| Node replays exact proof + request sig | `Nonce` uniqueness check + `Timestamp` freshness window |
| Node forges request for different group/key | `RequestSig` covers `(group_id, key_id, nonce, timestamp)` — forged params fail verification |
| Node reconstructs JWT from proof | ZK soundness — signature is a private witness, never appears in the proof |
| Node extracts session private key | ECDLP hardness — `session_pub` does not reveal `session_priv` |
| Attacker without JWT fabricates auth | ZK soundness — cannot produce a valid proof without a valid RSA signature under the OIDC provider's key |
| Attacker uses JWT signed by wrong key | Nodes check `JWKSModulus` against their own OIDC JWKS cache — proof with wrong modulus is rejected |
| Stolen session key after browser closes | `session_priv` is held in memory only, never written to disk or storage — cleared on tab/app close |
| JWT expires mid-session | Nodes check `Exp` from the proof's public inputs on every request |
| Token for wrong audience reused | `Aud` is a public input — nodes verify it matches expected value |
| Client ID bypass (missing azp) | `Azp` is a public input extracted in-circuit — nodes reject if missing when client IDs are configured |

### Trust Model

| Entity | Trust assumption |
|--------|-----------------|
| Client | Holds a legitimate JWT from a real OAuth flow. Generates session keypair honestly. (If a client forges their own identity, they can only affect their own keys.) |
| OIDC provider | Issues JWTs with correct claims and valid RSA signatures. Publishes accurate JWKS. |
| Signet nodes | **Untrusted individually.** Cannot impersonate the user. Cannot replay credentials. Cannot learn the JWT signature. Protocol security requires t-of-n honest nodes (standard threshold assumption). |
| On-chain contracts | Correctly record trusted issuers and client IDs. Protected by blockchain consensus and timelocked governance. |

## Circuit Design

The ZK circuit is built on existing Noir libraries from the zk-email project.

### Dependencies

- **[noir-jwt](https://github.com/zkemail/noir-jwt)** — JWT verification circuit: base64 decoding, claim extraction, SHA-256 hashing, RSA signature verification.
- **[noir_rsa](https://github.com/noir-lang/noir_rsa)** — RSA-2048 PKCS#1 v1.5 signature verification (~7,131 UltraHonk gates for a single verification).
- **[noir-bignum](https://github.com/noir-lang/noir-bignum)** — Big integer arithmetic in Montgomery form for RSA modular exponentiation.
- **[Barretenberg](https://github.com/AztecProtocol/barretenberg)** — Backend prover (WASM for browser, native for server) and verifier.

### Circuit Pseudocode

```noir
// signet_jwt_auth.nr

use dep::noir_jwt;
use dep::noir_rsa;
use dep::std;

fn main(
    // Private witness
    jwt_signature: [u8; 256],        // RSA-2048 signature (256 bytes)

    // Public inputs
    jwt_header_payload: [u8; MAX_JWT_LEN],  // base64(header) || "." || base64(payload)
    jwt_len: u32,                           // actual length
    jwks_modulus: [u8; 256],                // RSA public key modulus (256 bytes)
    expected_iss: [u8; MAX_ISS_LEN],        // issuer string
    expected_sub: [u8; MAX_SUB_LEN],        // subject string
    expected_exp: u64,                      // expiry timestamp
    expected_aud: [u8; MAX_AUD_LEN],        // audience string
    expected_azp: [u8; MAX_AZP_LEN],        // authorized party
    session_pub: [u8; 33],                  // compressed secp256k1 public key
) {
    // 1. Hash the JWT header.payload
    let hash = std::sha256(jwt_header_payload[..jwt_len]);

    // 2. Verify RSA signature: sig^65537 mod n == PKCS1v15_pad(hash)
    noir_rsa::verify_sha256_pkcs1v15(
        jwks_modulus,
        jwt_signature,
        hash,
    );

    // 3. Base64-decode the payload and extract claims
    let claims = noir_jwt::decode_payload(jwt_header_payload, jwt_len);
    assert(claims.iss == expected_iss);
    assert(claims.sub == expected_sub);
    assert(claims.exp == expected_exp);
    assert(claims.aud == expected_aud);
    assert(claims.azp == expected_azp);

    // 4. session_pub is a public input — it is automatically bound to the proof
    //    by virtue of being in the public inputs. No explicit constraint needed.
    //    The verifier checks that the proof was generated with this exact session_pub.
}
```

The `session_pub` binding works because public inputs are part of the proof statement. A proof generated with `session_pub = P1` will not verify against public inputs containing `session_pub = P2`. The client cannot change the binding after proof generation, and nodes cannot substitute a different key.

### Circuit Size Estimate

| Component | Approximate Gates (UltraHonk) |
|-----------|------------------------------|
| RSA-2048 verify | ~7,000 |
| SHA-256 (JWT header+payload) | ~20,000-40,000 (depends on JWT length) |
| Base64 decode + claim extraction | ~10,000-20,000 |
| Claim equality checks | ~1,000 |
| **Total** | **~40,000-70,000** |

This is well within browser proving capability.

## Performance

### Per-Operation Cost

| Operation | Where | Time | Frequency |
|-----------|-------|------|-----------|
| ZK proof generation | Client browser (WASM) | ~2-7 seconds | Once per JWT lifetime |
| ZK proof generation | App server (native) | ~260-800 ms | Once per JWT lifetime (fallback) |
| ZK proof verification | Each node | ~1-2 ms | Once per session (cached) |
| Session key signing | Client | <1 ms | Every request |
| Session sig verification | Each node | <1 ms | Every request |

### Data Sizes

| Field | Size |
|-------|------|
| ZK proof (UltraHonk) | ~2-4 KB |
| Session public key | 33 bytes |
| Request signature | 64 bytes |
| Nonce | 16 bytes |
| Total auth overhead per coord message | ~3-5 KB |

## Session Lifecycle

```
Browser opens
  └─▶ Generate session keypair (random, in-memory)

User logs in via OAuth
  └─▶ Receive JWT from provider

First Signet operation
  └─▶ Generate ZK proof binding (JWT, session_pub)      [2-7s]
  └─▶ POST /v1/auth { header, payload, proof, session_pub }
  └─▶ Node verifies proof, caches session_pub → {sub, iss, exp}

Subsequent operations (keygen, sign, ...)
  └─▶ Sign request with session_priv                     [<1ms]
  └─▶ POST /v1/keygen or /v1/sign { ..., session_pub, request_sig }
  └─▶ Node verifies sig against cached session_pub       [<1ms]

JWT expires
  └─▶ Nodes reject requests (exp check fails)
  └─▶ Client re-authenticates via OAuth, gets new JWT
  └─▶ Generate new ZK proof (can reuse same session keypair or generate new)

Browser/app closes
  └─▶ session_priv lost (in-memory only)
```

## Server-Side Proof Generation (Fallback)

For mobile clients or constrained environments where browser WASM proving is too slow or uses too much memory:

```
Client  ──JWT──▶  App Backend  ──proof──▶  Client  ──proof──▶  Signet Node
                  (app's own                (forwards
                   server,                   proof only,
                   trusted by               no JWT)
                   the user)
```

1. The client sends the JWT to its own application backend (the server that initiated the OAuth flow — it already knows the JWT).
2. The app backend generates the ZK proof using native Barretenberg (~260-800ms).
3. The app backend returns the proof to the client.
4. The client forwards the proof (not the JWT) to the Signet node.

The session private key stays client-side. The app backend generates the proof but does not learn `session_priv` and cannot sign requests on behalf of the user. The Signet nodes never see the JWT.

## Migration Path

### Phase 1: Add ZK auth alongside existing auth

- Implement the noir-jwt circuit and proof generation.
- Add the `/v1/auth` endpoint and session key verification to nodes.
- Add `AuthProof` to the coord message as an alternative to `AuthToken`.
- Nodes accept either `AuthToken` (legacy) or `AuthProof` (new) during transition.
- Groups can opt in to ZK-only auth via an on-chain flag.

### Phase 2: Deprecate raw JWT forwarding ✅

- Remove `AuthToken` from the coord message. ✅
- All authenticated groups require ZK proofs or auth key certificates. ✅
- Remove `TestMode` JWT bypass. ✅

### Phase 3: On-chain proof verification (optional)

- Deploy a Solidity verifier contract (auto-generated by Barretenberg) that verifies UltraHonk proofs on-chain.
- Groups can optionally require on-chain proof submission for high-value operations.
- Gas cost: ~200-300k gas per verification.

## Client SDK

The client-side integration requires a JavaScript/TypeScript SDK that wraps:

1. **Session key management** — generate, store in memory, sign requests.
2. **ZK proof generation** — load the Barretenberg WASM prover, generate witness from JWT + session pubkey, produce proof.
3. **OIDC JWKS fetching** — fetch the provider's RSA public key for use as a circuit input.
4. **Request signing** — sign keygen/sign request parameters with the session key.

```typescript
// Usage sketch

import { SignetAuth } from '@signet/auth';

// Once per session
const auth = await SignetAuth.create();

// Once per JWT (after OAuth login)
const jwt = getJwtFromOAuthFlow();
await auth.authenticate(jwt, nodeUrl);  // generates ZK proof, registers session

// Per operation (instant)
const result = await auth.keygen(nodeUrl, {
  group_id: '0x...',
  key_suffix: 'primary',
});

const sig = await auth.sign(nodeUrl, {
  group_id: '0x...',
  key_suffix: 'primary',
  message_hash: '0xdeadbeef...',
});
```

## Authorization Keys (Planned)

OAuth/OIDC is the right auth mechanism for consumer-facing applications with human
users. For use cases where OAuth is not natural — agentic payments, machine-to-machine
signing, programmatic key management — a more general mechanism is needed.

### The impersonation requirement

The core security property of ZK auth is not privacy — it is that **a rogue node
cannot impersonate a user to the rest of the group.** Nodes verify ZK proofs but
never see the JWT signature, so they cannot forge a new proof bound to a different
session key. Any alternative auth mechanism must preserve this property.

### Design: application-managed authorization keys

The application registers one or more **authorization keys** (secp256k1 public keys)
on the group contract, using the same time-delayed add/remove lifecycle as OAuth
issuers. The application holds the corresponding private keys and uses them to
authorize entities — human users, agents, services — by signing session key bindings.

**Auth flow:**

```
Application                       Entity (user/agent)              Signet Node
    │                                    │                              │
    │  ◄── request session access ──     │                              │
    │                                    │                              │
    │   sign(auth_key_priv,              │                              │
    │     identity, session_pub,         │                              │
    │     group_id, expiry)              │                              │
    │                                    │                              │
    │  ── authorization certificate ──►  │                              │
    │                                    │                              │
    │                                    │  ── POST /v1/auth ──────►   │
    │                                    │     { certificate,           │
    │                                    │       session_pub }          │
    │                                    │                              │
    │                                    │     verify cert sig against  │
    │                                    │     group's registered       │
    │                                    │     auth keys                │
    │                                    │                              │
    │                                    │  ◄── session established ──  │
    │                                    │                              │
    │                                    │  (subsequent requests use    │
    │                                    │   session key, identical     │
    │                                    │   to OAuth path)             │
```

**Anti-impersonation property:** Nodes see the authorization certificate (a
signature) but cannot forge a new one for a different session key because they
do not hold the application's authorization key. This is the same security
guarantee as the ZK auth path — nodes can verify but not produce credentials.

### Auth policy types

A group contract supports two auth policy types:

| Policy | Use case | Credential | Node can impersonate? |
|---|---|---|---|
| **OAuth issuer** | Consumer apps, human users | ZK proof of JWT binding session_pub | No — can't forge proof without JWT |
| **Authorization key** | Agents, services, M2M, apps without OAuth | App-signed certificate binding identity + session_pub | No — can't forge sig without auth key |

Both produce session keys. Both are countable for billing (unique identity per
period). Both are unforgeable by nodes. The request phase (session key signing,
nonce, timestamp) is identical for both paths.

### Identity derivation

For OAuth, the identity is the JWT `sub` claim. For authorization keys, the
identity is the `identity` field in the certificate — defined by the application.
This could be an agent ID, a service account name, an on-chain address, or any
string the application uses to identify the entity. Key IDs are scoped the same
way: `identity` or `identity:suffix`.

### Contract changes

The group contract gains authorization key management alongside issuer management:

- `queueAddAuthKey(pubkey)` — queue an authorization key with time delay
- `executeAddAuthKey(pubkey)` — activate after delay
- `queueRemoveAuthKey(pubkey)` — queue removal with time delay
- `executeRemoveAuthKey(pubkey)` — remove after delay
- `isAuthKeyTrusted(pubkey)` — view

Same time-delayed lifecycle as issuers, same security properties.

### Billing compatibility

From the billing model's perspective, an authorization key session is identical
to an OAuth session — it produces a unique identity that established a session
in the billing period. The billing contract counts unique identities regardless
of which auth policy produced them.

### Status

Implemented. The group contract supports time-delayed add/remove of
authorization keys alongside OAuth issuers. The Go node loads auth keys
from on-chain, handles `AuthKeyAdded`/`AuthKeyRemoved` events, and accepts
certificate-based session establishment via `POST /v1/auth` with a
`certificate` field. The request phase (session key signing, nonce,
timestamp) is identical to the OAuth path.

---

## References

- [noir-jwt](https://github.com/zkemail/noir-jwt) — Noir JWT verification circuit (zk-email)
- [noir_rsa](https://github.com/noir-lang/noir_rsa) — RSA-2048 verification in Noir (~7,131 UltraHonk gates)
- [noir-bignum](https://github.com/noir-lang/noir-bignum) — Big integer arithmetic for Noir
- [Barretenberg](https://github.com/AztecProtocol/barretenberg) — UltraHonk prover/verifier (WASM + native)
- [Mopro](https://zkmopro.org/) — Mobile native ZK proving SDK
- [zk-email](https://zk.email/) — Production ZK email/DKIM verification
- [Sui zkLogin](https://docs.sui.io/concepts/cryptography/zklogin) — Production ZK JWT auth on Sui
- [dmpierre/zkrsa](https://github.com/dmpierre/zkrsa) — Browser-based RSA ZK proof (Circom, reference implementation)
- [RISC Zero jwt-validator](https://github.com/risc0/risc0/tree/main/examples/jwt-validator) — zkVM-based JWT verification
