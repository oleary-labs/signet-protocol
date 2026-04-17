# ZK Proof Build & Toolchain Reference

This document describes the ZK proving pipeline used for JWT authentication in the Signet Console. It covers the circuit, toolchain versions, build process, and client-side proving architecture.

## Overview

Users authenticate via Google OAuth. Instead of forwarding the raw JWT to Signet nodes (which would let any compromised node impersonate the user), the client generates a **zero-knowledge proof** that the JWT is valid. The proof is bound to an ephemeral session key. Nodes verify the proof but never see the JWT signature.

The proof is generated **entirely client-side in the browser** using WASM (~2-7 seconds).

## Toolchain Versions

These three must stay in lockstep. Mismatched versions cause serialization errors.

| Component | Version | Purpose |
|---|---|---|
| `nargo` | `1.0.0-beta.11` | Noir compiler — compiles the circuit and generates witnesses |
| `@noir-lang/noir_js` | `1.0.0-beta.11` | JS/WASM witness generation from compiled circuit |
| `@aztec/bb.js` | `0.82.2` | Barretenberg WASM prover — generates UltraHonk proofs in browser |

Install nargo:
```bash
curl -fsSL https://raw.githubusercontent.com/noir-lang/noirup/refs/heads/main/install | bash
noirup --version 1.0.0-beta.11
```

## Circuit

### Location

- **Source:** `../signet-protocol/circuits/jwt_auth/src/main.nr`
- **Library:** `../signet-protocol/circuits/noir-jwt-local/` (forked from [zkemail/noir-jwt](https://github.com/zkemail/noir-jwt))
- **Compiled artifact:** `public/circuits/jwt_auth.json` (1.5MB, committed)

### Circuit Dependencies (Nargo.toml)

```toml
[dependencies]
rsa = { git = "https://github.com/zkpassport/noir_rsa", tag = "v0.9.1" }
sha256 = { git = "https://github.com/noir-lang/sha256", tag = "v0.2.1" }
base64 = { git = "https://github.com/noir-lang/noir_base64", tag = "v0.4.2" }
string_search = { git = "https://github.com/noir-lang/noir_string_search", tag = "v0.3.3" }
bignum = { git = "https://github.com/noir-lang/noir-bignum", tag = "v0.8.0" }
nodash = { git = "https://github.com/olehmisar/nodash/", tag = "v0.42.0" }
```

**Important:** These dependency versions use `u1` which was removed in nargo 1.0.0-beta.20+. Upgrading the compiler requires updating all upstream deps (noir_base64, sha512, etc.) to versions that replace `u1` with `bool`.

### Circuit Inputs

```noir
fn main(
    // Private witness (never revealed)
    data: BoundedVec<u8, 1024>,           // JWT signed data (base64 header.payload)
    base64_decode_offset: u32,             // header length + 1
    redc_params_limbs: [u128; 18],         // Barrett reduction parameter
    signature_limbs: [u128; 18],           // RSA signature (2048-bit, 18 × 120-bit limbs)

    // Public inputs (verified by nodes)
    pubkey_modulus_limbs: pub [u128; 18],  // RSA modulus from JWKS
    expected_iss: pub BoundedVec<u8, 128>, // "https://accounts.google.com"
    expected_sub: pub BoundedVec<u8, 128>, // stable user ID
    expected_exp: pub u64,                 // JWT expiry timestamp
    expected_aud: pub BoundedVec<u8, 128>, // OAuth audience
    expected_azp: pub BoundedVec<u8, 128>, // OAuth client ID
    session_pub: pub [u8; 33],            // compressed secp256k1 session public key
)
```

The circuit:
1. Verifies the RSA-SHA256 signature over the JWT header.payload
2. Asserts the decoded claims match the public inputs
3. Binds the proof to `session_pub` (a proof generated with one session key won't verify against another)

### Compiling the Circuit

Only needed if the noir source changes:

```bash
cd ../signet-protocol/circuits/jwt_auth
nargo compile --force
cp target/jwt_auth.json ../../signet-ui/public/circuits/jwt_auth.json
```

Or from this repo:
```bash
bun run circuit:rebuild
```

## Client-Side Proving Architecture

### SDK Location

All proving code lives in `src/lib/signet-sdk/`:

| File | Purpose |
|---|---|
| `proof.ts` | Orchestrates the full proof flow |
| `witness.ts` | Builds circuit witness from JWT + JWKS + session key |
| `generate-inputs.ts` | Core RSA/JWT witness builder (from noir-jwt-local) |
| `partial-sha.ts` | SHA256 partial hashing for constraint optimization |
| `jwt.ts` | JWT parsing — extracts signed data, signature, kid |
| `jwks.ts` | Fetches Google's JWKS, extracts RSA modulus |
| `session.ts` | secp256k1 session keypair generation |
| `oauth.ts` | Google OAuth PKCE flow |
| `bootstrap.ts` | POST proof to bootstrap nodes /v1/auth |

### Proof Generation Flow

```
1. Parse JWT
   ├── Extract header.payload (signed data) as bytes
   ├── Extract RSA signature (base64url decode)
   └── Extract kid from header

2. Fetch JWKS
   ├── GET https://www.googleapis.com/oauth2/v3/certs
   ├── Find RSA key matching kid
   └── Decode modulus (base64url → bigint)

3. Build witness (generate-inputs.ts)
   ├── Split RSA modulus into 18 × 120-bit limbs (little-endian)
   ├── Split RSA signature into 18 × 120-bit limbs
   ├── Compute Barrett reduction parameter: floor(2^4100 / modulus)
   ├── Split redc param into 18 × 120-bit limbs
   ├── Pad signed data to 1024 bytes
   └── Encode claims as BoundedVec (128-byte storage + length)

4. Execute circuit (noir_js WASM)
   ├── Load compiled circuit from /circuits/jwt_auth.json
   ├── Noir.execute(witness) → ACIR witness
   └── ~1-2 seconds

5. Generate proof (bb.js WASM)
   ├── UltraHonkBackend(bytecode)
   ├── backend.generateProof(acirWitness)
   └── ~2-5 seconds

6. Result
   ├── proof: Uint8Array (~2-4 KB)
   └── publicInputs: string[]
```

### RSA Limb Encoding

RSA-2048 values (modulus, signature, redc param) are split into 18 limbs of 120 bits each, in **little-endian** order (limb 0 is least significant):

```typescript
function splitToLimbs(n: bigint): string[] {
  const mask = (1n << 120n) - 1n;
  const limbs: string[] = [];
  let tmp = n;
  for (let i = 0; i < 18; i++) {
    limbs.push((tmp & mask).toString(10));  // decimal strings
    tmp >>= 120n;
  }
  return limbs;
}
```

The Barrett reduction parameter is: `floor(2^(2*2048+4) / modulus)`

### Prover.toml Format

The witness is serialized to TOML for nargo compatibility:

```toml
base64_decode_offset = 36
expected_exp = 1735689600
redc_params_limbs = ["12345...", "67890...", ...]  # 18 quoted decimal strings
signature_limbs = ["12345...", "67890...", ...]
pubkey_modulus_limbs = ["12345...", "67890...", ...]
session_pub = [2, 171, 205, ...]  # 33 bytes (compressed secp256k1)

[data]
storage = [101, 121, 74, ...]  # 1024 bytes (padded signed data)
len = 487

[expected_iss]
storage = [104, 116, 116, ...]  # 128 bytes (padded)
len = 27

[expected_sub]
storage = [49, 49, 52, ...]
len = 21

[expected_aud]
storage = [50, 48, 51, ...]
len = 67

[expected_azp]
storage = [50, 48, 51, ...]
len = 67
```

## Server-Side Verification

Signet nodes verify proofs using `bb verify` (native Barretenberg CLI). The verification code is in `signet-protocol/node/zkverify.go`.

### Public Inputs Encoding (for bb verify)

568 field elements × 32 bytes (BN254 big-endian) = 18,176 bytes:

| Field | Elements | Format |
|---|---|---|
| `pubkey_modulus_limbs` | 18 | 120-bit limbs, LE order, each as 32-byte BE field |
| `expected_iss` | 129 | 128 storage bytes + 1 length (u32 BE) |
| `expected_sub` | 129 | same |
| `expected_exp` | 1 | u64 BE in 32-byte field |
| `expected_aud` | 129 | same as iss/sub |
| `expected_azp` | 129 | same |
| `session_pub` | 33 | each byte as its own 32-byte field |

### Node Auth Request Format

```json
{
  "group_id": "0x...",
  "session_pub": "02abcd...",
  "proof": "hex-encoded proof bytes",
  "sub": "114810956681671373980",
  "iss": "https://accounts.google.com",
  "exp": 1735689600,
  "aud": "203385367894-...",
  "azp": "203385367894-...",
  "jwks_modulus": "hex-encoded RSA modulus bytes"
}
```

The node:
1. Verifies the ZK proof against the public inputs
2. Checks `jwks_modulus` matches its own cached Google JWKS
3. Checks `exp > now`
4. Registers session: `session_pub → { sub, iss, exp }`

### Verification Key

The VK is generated alongside the proof (`bb prove --write_vk`). Nodes must be configured with the VK matching the compiled circuit artifact. If the circuit is recompiled, a new VK must be distributed to all nodes.

Node config: `vk_path: /path/to/vk`

## Upgrading

To upgrade the noir toolchain:

1. Update all noir library deps in `circuits/noir-jwt-local/Nargo.toml` to versions compatible with the new compiler
2. Install matching nargo: `noirup --version <new-version>`
3. Recompile: `cd circuits/jwt_auth && nargo compile --force`
4. Copy artifact: `cp target/jwt_auth.json signet-ui/public/circuits/jwt_auth.json`
5. Update npm packages: `bun add @noir-lang/noir_js@<matching> @aztec/bb.js@<matching>`
6. Generate a new VK and distribute to all nodes
7. Test end-to-end: OAuth → proof → node verification

**The three versions (nargo, noir_js, bb.js) must be compatible.** Mismatched versions cause msgpack serialization errors.

## References

- [DESIGN-ZK-AUTH.md](../../signet-protocol/docs/DESIGN-ZK-AUTH.md) — full security design
- [zkemail/noir-jwt](https://github.com/zkemail/noir-jwt) — upstream JWT circuit
- [Barretenberg](https://github.com/AztecProtocol/barretenberg) — WASM prover
- [Noir Lang](https://noir-lang.org/) — ZK DSL
