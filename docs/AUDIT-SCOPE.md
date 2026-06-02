# Signet Protocol — Preliminary Audit Scope

## Overview

Signet is a threshold signing protocol. A group of n nodes collectively
hold key shares; any threshold-many can produce a signature without any
single node ever holding the full private key. The protocol supports
FROST Schnorr (secp256k1, Ed25519) and threshold ECDSA (secp256k1).

**Target deployment: public alpha.** A 5-node network operated primarily
by us, with one external operator for independent validation. The
primary application is an MCP server we build and run that enables AI
agents to make small-value payments and transfers (x402 / EIP-3009 / NEAR Intents) using scoped
threshold ECDSA keys. The goal is to showcase the technology with real
transactions on mainnet while limiting individual key balances (target
max ~$100 per key).

This is not a full production launch — it is a controlled environment
designed to validate the protocol under real conditions, demonstrate
the security model to potential customers and investors, and surface
issues before scaling. The audit scope is sized accordingly: we are
focused on the code paths that directly protect funds, not the full
system surface.

## Architecture

```
Client (browser / agent)
  │
  ├─ POST /v1/auth    → ZK proof of OAuth JWT, bound to ephemeral session key
  ├─ POST /v1/keygen   → Distributed key generation (Feldman VSS DKG)
  ├─ POST /v1/sign     → Threshold signing (FROST or ECDSA)
  └─ POST /v1/delegate → Mint delegation token (JWT signed by parent key)
  │
  ▼
Go Node (signetd) ── libp2p P2P ── Go Node ── ... (n nodes)
  │
  ▼
Rust KMS (kms-tss) ── gRPC ── holds key shares, executes protocol rounds
```

- **Go node**: HTTP API, session management, auth verification, coordination
  message routing, chain polling for group membership.
- **Rust KMS**: Key material storage (sled), FROST and ECDSA protocol
  execution. Communicates with the Go node over a local Unix socket (gRPC).
  Key material never crosses the network — only protocol messages do.
- **Backing chain** (TBD): Group membership registry, OAuth
  issuer configuration, authorization keys. No funds stored on-chain.

## Deployment Parameters

- 5 nodes, key threshold = 3 (3-of-5 signing)
- ECDSA signing sessions use 3 participants (tolerates 1 malicious per
  session; coordinator retries with different subsets on failure)
- Scoped sub-keys restrict signing to a specific EIP-712 domain
  (chainId + verifyingContract)

## Audit Focus Areas

### 1. Threshold ECDSA Signing (Critical)

**Files**: `kms-tss/src/ecdsa_session.rs` (~900 lines Rust)

Implementation of the DJNPO20 robust threshold ECDSA protocol (4-round:
3 presign + 1 sign). Based on the NEAR MPC team's analysis of the same
protocol.

- Damgård, Jakobsen, Nielsen, Pagter, Østergaard. "Improved Threshold
  Signatures, Proactive Secret Sharing, and Input Certification from LSS
  Isomorphisms." TCC 2020. https://eprint.iacr.org/2020/514
- NEAR MPC analysis: https://github.com/near/threshold-signatures/blob/main/docs/ecdsa/robust_ecdsa/signing.md

**Build-or-reuse assessment**: We implemented DJNPO20 from the paper and
NEAR's analysis rather than wrapping an existing library. The NEAR MPC
crate (`crates/threshold-signatures`) implements the same protocol but
is tightly coupled to NEAR's runtime and chain-signature infrastructure.
We'd welcome the auditor's assessment of whether our implementation is
sound or whether adopting / adapting an audited library would be
preferable. If NEAR's implementation has been independently audited,
that changes the calculus.

**What to verify**:
- Polynomial generation: degree-t for (k, a), degree-2t with zero
  constant for (b, d, e).
- Share accumulation and interpolation correctness.
- Commitment consistency checks: R_i and W_i exponent interpolation
  verification for indices > t+1.
- W == g^w check (binds the blinding to the nonce).
- Signature share linearization (Lagrange coefficients applied before
  sending to coordinator).
- Low-S normalization (EIP-2 compliance).
- Zero-hash rejection.
- Coordinator aggregation and final signature verification.

**Security properties to confirm**:
- A coalition of < threshold nodes cannot forge a signature or recover the
  private key, regardless of behavior during signing.
- A single malicious participant cannot bias the signature or extract
  other participants' shares.
- The protocol is robust against commitment-inconsistency attacks (rounds
  2–3 checks).

### 2. Scope Enforcement (Critical)

**Files**: `node/scope.go` (~100 lines Go), scope verification in
`node/coord.go` (~30 lines)

Scoped keys reject raw hash signing. The caller provides a structured
EIP-712 typed data payload. Every signing participant independently
extracts the domain (chainId, verifyingContract), verifies it matches
the key's scope, and computes the hash locally. No participant trusts
the initiator's hash.

**What to verify**:
- A scoped key cannot be used to sign a raw message hash (bypass check).
- The EIP-712 domain extraction correctly isolates chainId and
  verifyingContract from the typed data.
- A malicious initiator cannot trick participants into signing a hash
  for a different domain (each participant re-computes independently).
- The scope is immutable after keygen (stored in the KMS, not modifiable
  via any API).

### 3. ECDSA Signature Formatting (High)

**Files**: `node/handlers.go` (~30 lines Go)

The Go node formats the raw (r, s) output from the KMS into a 65-byte
recoverable signature (r || s || v) for on-chain ecrecover.

**What to verify**:
- s-value is normalized to the lower half of the secp256k1 curve order
  (EIP-2).
- Recovery byte v is computed by trying ecrecover with v=0 and v=1 and
  matching against the known group public key.
- The handler fails explicitly if recovery fails (no silent fallthrough).

### 4. Delegation Tokens (High)

**Files**: `node/delegate.go` (~400 lines Go)

A delegation token is a JWT threshold-signed by a user's parent key. It
grants an agent long-lived access to a specific scoped sub-key. The JWT
`sub` field names the sub-key; the `kid` and `scheme` fields identify
the parent key and signing scheme.

**What to verify**:
- Tokens cannot be forged (signature verification uses the parent key's
  stored public key via FROST Schnorr verify or ECDSA ecrecover).
- Tokens are bound to a specific sub-key (namespace validation: sub-key
  must be under the parent's identity namespace).
- Token expiry is enforced.
- The delegation session is locked to the specific sub-key
  (`DelegatedKeyID`) — the agent cannot use the token to sign with any
  other key.

### 5. Session Auth (Medium)

**Files**: `node/auth.go` (~300 lines), `node/zkverify.go` (~170 lines)

Two auth paths: (a) ZK proof of OAuth JWT validity, bound to an
ephemeral session key; (b) authorization key certificate (secp256k1
signature from an on-chain registered key).

**What to verify**:
- ZK proof binds the session public key to the JWT claims (session_pub
  is a public input to the circuit).
- JWKS modulus verification prevents fake RSA key attacks.
- Session replay protection: nonce uniqueness (5-minute retention) +
  timestamp freshness (30-second window).
- Canonical request hash construction is unambiguous (no length-extension
  or delimiter confusion).

### 6. Protocol Boundaries and Message Transport (Medium)

**Files**: `node/coord.go` (~900 lines Go), `node/remote_keymanager.go`
(~500 lines Go), `kms-tss/src/service.rs` (~370 lines Rust)

The Go node acts as a message router between the Rust KMS and the P2P
network. Protocol messages from the KMS traverse: Rust KMS → gRPC →
Go node → libp2p stream → remote Go node → gRPC → remote Rust KMS.

**What to verify**:
- Messages are not modified in transit between KMS and network (the Go
  node passes opaque byte payloads).
- Session isolation: messages from one signing session cannot leak into
  another (session IDs are used for routing).
- The coordinator cannot selectively drop, delay, or reorder messages
  between participants in a way that compromises safety (liveness
  disruption is accepted).
- The libp2p peer ID authentication ensures a node cannot impersonate
  another node in the P2P layer.
- The CBOR-encoded coordination messages (coord.go) cannot be malformed
  in a way that bypasses auth checks or scope enforcement on the
  receiving participant.

### Out of Scope (for this engagement)

- FROST Schnorr signing (not used in the x402 payment flow)
- Ed25519 signing (Solana — not deployed in alpha)
- Smart contracts (OpenZeppelin-based, no funds stored)
- Reshare protocol (key refresh — operational, not fund-critical)
- ZK circuit internals (audited separately as part of signet-circuits)
- libp2p networking (standard library)
- Chain polling / event handling

## Code Summary

| Component | Language | LOC | Priority |
|-----------|----------|-----|----------|
| ECDSA signing protocol | Rust | ~900 | Critical |
| Scope enforcement | Go | ~130 | Critical |
| ECDSA signature formatting | Go | ~30 | High |
| Delegation tokens | Go | ~400 | High |
| Session auth + ZK verify | Go | ~470 | Medium |
| Protocol boundaries + coord | Go/Rust | ~1,770 | Medium |
| **Total** | | **~3,700** | |

The protocol boundary code (coord.go, remote_keymanager.go, service.rs)
is larger by LOC but is primarily message routing — the security-critical
logic is concentrated in the components above it in the table. The
auditor may choose to review it at a lighter depth focused on the
specific verification points listed in §6.

## Repository

https://github.com/oleary-labs/signet-protocol

Branch: `main` (all code merged as of testnet 1 deployment).

Key entry points:
- `kms-tss/src/ecdsa_session.rs` — threshold ECDSA protocol
- `node/scope.go` — scope enforcement
- `node/handlers.go` — HTTP API + ECDSA signature formatting
- `node/delegate.go` — delegation token minting and verification
- `node/auth.go` — session authentication
- `node/zkverify.go` — ZK proof verification (bb verify integration)
- `node/coord.go` — coordination message handling + participant-side
  auth and scope verification
