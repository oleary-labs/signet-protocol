# Curves and Signing Schemes — Quick Reference

This is the single source of truth for the three canonical curve strings used across
the Signet stack. Every consumer (SDK, UI, MCP server, bundler) speaks these exact
strings to the node's HTTP API.

For the design rationale, see [DESIGN-MULTI-CURVE.md](DESIGN-MULTI-CURVE.md).
For the Testnet 1 changelog, see [TESTNET-1-CHANGES.md](TESTNET-1-CHANGES.md).

## The three curves

| Curve string | Algorithm | KMS impl | Storage prefix | On-chain verifier |
|---|---|---|---|---|
| `frost_secp256k1` | FROST Schnorr / secp256k1 (RFC 9591) | `kms-tss` via `frost-secp256k1` | `0x01` | `FROSTVerifier.sol` (custom; not `ecrecover`) |
| `frost_ed25519` | FROST Schnorr / Ed25519 | `kms-tss` via `frost-ed25519` | `0x02` | Native Ed25519 verifiers (Solana, Cosmos, etc.) |
| `ecdsa_secp256k1` | Threshold ECDSA / secp256k1 (DJNPO20, 4-round robust) | `kms-tss` via `k256` | `0x03` | Native `ecrecover` |

The storage prefix means a given `key_id` paired with a different `curve` is a
**different key**. Callers always pass `curve` explicitly; the node never guesses.

## Where each curve is used

| Curve | Console main flow | x402 / agent flow | Admin / bootstrap | MCP server (v1) |
|---|---|---|---|---|
| `frost_secp256k1` | ✅ UserOp signing via bootstrap group | — | ✅ admin auth | — |
| `frost_ed25519` | — | — | — | — |
| `ecdsa_secp256k1` | — | ✅ scoped sub-keys, EIP-712, delegation | — | ✅ all tool surfaces hard-code this |

`frost_ed25519` is implemented end-to-end in the KMS and node but currently has no
production consumer in the EVM-first stack. Solana support would light it up.

## HTTP API surface

All signing endpoints on `signetd` take a `curve` parameter. Behavior is identical
across curves except where noted.

### `POST /v1/keygen`

```json
{
  "group_id": "0x...",
  "curve":    "ecdsa_secp256k1",
  "scope":    "0x03...",        // optional, scope bytes per scoped-subkeys spec
  "key_suffix": "agent-1",      // optional
  "session_pub": "...",
  "request_sig": "...",
  "nonce": "...",
  "timestamp": "..."
}
```

Returns the key ID, the (Ethereum) address for secp256k1 curves, and the group
public key.

### `POST /v1/sign`

Same envelope; payload shape depends on the scheme:

```json
{
  "group_id": "0x...",
  "key_id":   "...",
  "curve":    "ecdsa_secp256k1",
  "payload": {
    "scheme":     "eip712",            // or "raw_hash", "personal_sign"
    "typed_data": { ... }              // EIP-712 typed-data, when scheme=eip712
  },
  /* session auth fields ... */
}
```

### `POST /v1/delegate`

Same `curve` field. Delegation tokens are JWTs signed by the parent key in the
parent's native scheme.

### `POST /v1/keys/{disable,enable,delete}`

`curve` is required to disambiguate keys that share an ID across schemes
(remember: storage is curve-prefixed).

## Response shapes

| Field | Present for | Format | Notes |
|---|---|---|---|
| `signature` | all curves | raw `R \|\| Z` bytes — protocol-native shape | Lowest-common-denominator field |
| `ethereum_signature` | `frost_secp256k1` only | 65 bytes: `R.x(32) \|\| z(32) \|\| v(1)` | Consumed by `FROSTVerifier.sol` |
| `ecdsa_signature` | `ecdsa_secp256k1` only | 65 bytes: `r \|\| s \|\| v` | Directly `ecrecover`-ready, EIP-2 normalized |

Multi-curve generic code should consume `signature`; EVM-specific code should consume
`ecdsa_signature` for ECDSA keys or `ethereum_signature` for FROST/secp256k1 keys.

## Picking a curve

| Use case | Curve |
|---|---|
| Agent payments on EVM (x402, EIP-712, EIP-3009) | `ecdsa_secp256k1` |
| ERC-4337 UserOp signed by a Signet group account | `frost_secp256k1` (Console main flow) |
| Bitcoin Taproot / BIP-340 / off-chain Schnorr verifier | `frost_secp256k1` |
| Solana / any Ed25519-native chain | `frost_ed25519` |
| Anywhere `ecrecover` is the only available verifier | `ecdsa_secp256k1` |

If you need a key that signs over EVM-bound typed data **and** the verifier is an EVM
contract using `ecrecover`, you must use `ecdsa_secp256k1` — a FROST Schnorr signature
over the same hash would be cryptographically valid but unverifiable on-chain.

## Where this enum is consumed

| Repo | File | Note |
|---|---|---|
| `signet-protocol` | `node/handlers.go` (`parseCurve` helper) | Server-side parsing + dispatch |
| `signet-protocol` | `kms-tss/src/main.rs` | Rust enum dispatch into FROST or DJNPO20 sessions |
| `signet-sdk` | `src/keygen.ts`, `src/scopedSign.ts`, `src/delegate.ts` | Passed through as a string parameter |
| `signet-ui` | `src/app/demo/x402/*` | Hard-codes `ecdsa_secp256k1` |
| `signet-better-mcp` | `src/tools/*.ts` | Hard-codes `ecdsa_secp256k1` (see DESIGN-V1.md §"What this means for the MCP tool surface") |

If you add a new curve, update this file first, then the storage prefix table, then
the KMS dispatch, then propagate the string out to consumers.
