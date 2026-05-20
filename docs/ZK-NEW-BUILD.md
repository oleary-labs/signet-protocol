# ZK Proof — Node-Side Reference

> **Note:** The circuit, toolchain pinning, and build pipeline now live in the
> [`signet-circuits`](https://github.com/oleary-labs/signet-circuits) repo. For circuit
> source, toolchain versions, build process, and client-side proving, see:
>
> - `signet-circuits/README.md`
> - `signet-circuits/docs/architecture.md`
> - `signet-circuits/docs/consumers.md`
> - `signet-circuits/docs/versioning.md`
> - `signet-circuits/toolchain.json` (single source of truth for `nargo`, `bb`, and `bb.js` versions)
>
> The compiled circuit + VK reach this repo via Go module
> `github.com/oleary-labs/signet-circuits/packages/go` (currently v0.3.0).
>
> This file retains only the bits specific to **node-side verification** of incoming
> auth proofs, which is what `signet-protocol` actually owns.

## Overview

Users authenticate via Google OAuth. Instead of forwarding the raw JWT to Signet nodes
(which would let any compromised node impersonate the user), the client generates a
**zero-knowledge proof** that the JWT is valid, bound to an ephemeral session key. Nodes
verify the proof but never see the JWT signature.

Proofs are generated either in the browser (via `@oleary-labs/signet-sdk/proof` +
`@aztec/bb.js`) or server-side by `signet-min-bundler` (via `POST /v1/prove`). Both
paths produce the same proof format; the node doesn't care which.

## Server-Side Verification

Signet nodes verify proofs using `bb verify` (native Barretenberg CLI). The verification
code is in `node/zkverify.go`. The verifying key is loaded from the embedded signet-circuits
Go module rather than from disk.

### Public Inputs Encoding (for bb verify)

568 field elements × 32 bytes (BN254 big-endian) = 18,176 bytes:

| Field | Elements | Format |
|---|---|---|
| `pubkey_modulus_limbs` | 18 | 120-bit limbs, LE order, each as 32-byte BE field |
| `expected_iss` | 129 | 128 storage bytes + 1 length (u32 BE) |
| `expected_sub` | 129 | same |
| `expected_exp` | 1 | u64 BE in 32-byte field |
| `expected_aud` | 129 | same as iss/sub (optional since circuit v0.3.0) |
| `expected_azp` | 129 | same (optional since circuit v0.3.0) |
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

The VK travels with the compiled circuit inside the signet-circuits Go module. When the
embedded module version is bumped (via `go get
github.com/oleary-labs/signet-circuits/packages/go@vX.Y.Z`), the VK is updated
automatically — there is no separate VK distribution step for this repo.

For the alternative "embed bb WASM in the Go node and verify in-process" approach (no
`bb` CLI dependency), see [DESIGN-BARRETENBERG-WASM-GO.md](DESIGN-BARRETENBERG-WASM-GO.md).

## Upgrading the Circuit

The build/upgrade flow lives in signet-circuits. From this repo's perspective the
upgrade is two commands:

```bash
go get github.com/oleary-labs/signet-circuits/packages/go@vX.Y.Z
go mod tidy
```

That refreshes the embedded circuit JSON, Noir source, `Nargo.toml`, and VK in one step.
If the upgrade changes the public-input layout, update the encoder in `node/zkverify.go`
and the documentation table above. The `circuits.AssertToolchain()` call at startup
catches `nargo` / `bb` version drift for any operations that still shell out.

## References

- [DESIGN-ZK-AUTH.md](DESIGN-ZK-AUTH.md) — full security design
- [DESIGN-BARRETENBERG-WASM-GO.md](DESIGN-BARRETENBERG-WASM-GO.md) — alternative in-process verification path (deferred)
- [signet-circuits/docs/architecture.md](https://github.com/oleary-labs/signet-circuits/blob/main/docs/architecture.md) — single-source-of-truth pattern across consumers
- [zkemail/noir-jwt](https://github.com/zkemail/noir-jwt) — upstream JWT circuit
- [Barretenberg](https://github.com/AztecProtocol/barretenberg) — UltraHonk prover
