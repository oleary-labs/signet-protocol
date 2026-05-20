# Key Management Server Design

Separation of key material and cryptographic protocol execution into a standalone KMS
process, with the Go node acting as a message router.

> **Status (Testnet 1):** Implemented as `kms-tss/` (Rust). The KMS hosts three signing
> schemes — FROST Schnorr/secp256k1, FROST Schnorr/Ed25519, and threshold ECDSA/secp256k1
> (DJNPO20, 4-round robust) — over a single gRPC interface. The directory was originally
> named `kms-frost/`; it was renamed to `kms-tss/` when ECDSA was added so the name
> reflects the multi-scheme reality. See `docs/TESTNET-1-CHANGES.md` for the change log
> and `docs/DESIGN-MULTI-CURVE.md` for the curve dispatch logic on the node side.
>
> The original FROST-centric rationale below is retained because the architectural
> motivations (TEE-readiness, separation of key material from network handlers, Rust
> memory safety) apply equally to the ECDSA scheme — the same KMS process hosts both.

---

## Table of Contents

1. [Motivation](#1-motivation)
2. [Architecture](#2-architecture)
3. [Why ZF FROST for the KMS](#3-why-zf-frost-for-the-kms)
4. [Wire format and migration implications](#4-wire-format-and-migration-implications)
5. [Key share migration](#5-key-share-migration)
6. [IPC design](#6-ipc-design)
7. [What changes in the Go node](#7-what-changes-in-the-go-node)
8. [Phased implementation](#8-phased-implementation)

---

## 1. Motivation

The current architecture has key material in the same process as a server that accepts
connections from the internet. Best-practice security separates these:

- A compromised HTTP or libp2p handler cannot directly access signing key material if
  the keys live in a separate process with a narrow, well-defined interface.
- A separate KMS process is a natural unit for TEE deployment (AWS Nitro Enclaves,
  Intel TDX): the enclave is small, auditable, and has no external network access.
- The KMS boundary is also the right place to absorb the migration from
  `bytemare/frost` (Go) to ZcashFoundation/frost (Rust), which is the more robust
  long-term implementation.

TEE attestation (enclaves proving to peers that they are running legitimate KMS code)
is a planned follow-on but is not in scope for the initial KMS implementation.

---

## 2. Architecture

**Option B: node as message router, KMS as crypto oracle.**

```
┌─────────────────────────────────────────┐
│  signet node (Go)                        │
│                                          │
│  HTTP API  ──►  session auth             │
│  libp2p    ──►  coord protocol           │
│                 message routing ─────────┼──► Unix socket / vsock
│  chain client (reads membership/events) │
└─────────────────────────────────────────┘
                                            │
                                   ┌────────▼────────┐
                                   │  KMS (Rust)      │
                                   │                  │
                                   │  ZF FROST        │
                                   │  keygen          │
                                   │  signing         │
                                   │  reshare         │
                                   │  key storage     │
                                   └──────────────────┘
```

The node handles everything that touches the network: HTTP requests, libp2p peer
connections, session authentication, chain polling, and the coord protocol. It does
not perform any cryptographic key operations and does not hold key material.

The KMS handles everything involving key material: running FROST round loops,
storing key shares, and returning outputs. It has no external network access. The
only communication is inbound from the local node process over a socket.

**FROST message flow:**

```
peer node ──[libp2p]──► node coord handler
                              │
                              ▼
                        KMS: ProcessMessage(sessionID, msgBytes)
                              │
                              ▼
                        node coord handler ──[libp2p]──► peer nodes
```

The node does not parse FROST round messages. It treats them as opaque byte blobs,
forwarding them between the peer network and the KMS socket. Session coordination
(who is in the session, what group and key, which round) remains in the coord
protocol but FROST message content is owned entirely by the KMS.

---

## 3. Why ZF FROST for the KMS

ZcashFoundation/frost is the stronger long-term choice for the FROST implementation:

- **Audit**: NCC Group partial audit of `frost-core` at v0.6.0. No equivalent audit
  exists for `bytemare/frost`.
- **Cheater detection**: mandatory in v3 — misbehaving signers are identified by
  participant identifier, not just detected as a boolean.
- **Reshare support**: same-committee proactive refresh (same-committee rotation) and
  repairable threshold scheme (lost share recovery) are production-ready. The committee-
  change reshare signet needs (`DESIGN-RESHARE.md`) will also be implemented on top of
  ZF FROST's Feldman VSS primitives — the same math applies.
- **DKG ZK proofs**: Schnorr proofs of knowledge in DKG part1 prevent rogue-key
  attacks. Cost is ~2% of total DKG time for typical group sizes.
- **Active maintenance**: v3.0.0-rc.0 released January 2026; responsive to audit findings.
- **Rust memory safety**: `zeroize` on sensitive types, constant-time serialization —
  classes of vulnerabilities that require explicit discipline in Go.

See `FROST-IMPLEMENTATION-COMPARISON.md` for the full FROST-vs-FROST analysis.

### Why the same KMS process also hosts threshold ECDSA

When ECDSA was added, we kept it inside the same Rust process rather than splitting it
into a separate service. The justification is essentially the same as for FROST:

- **Shared key-material boundary.** Both schemes' shares live behind the same gRPC
  interface and the same `sled` persistence layer. A single audit surface and a single
  TEE attestation target is cheaper to reason about than two parallel KMSes.
- **secp256k1 stack already present.** The Rust `k256` crate handles both ECDSA scalar
  arithmetic and the Schnorr operations FROST already needed; little incremental code.
- **DJNPO20 protocol fit.** The 4-round robust ECDSA protocol slots into the same
  session/coordinator machinery as FROST round 1/2 message routing. The Go node-side
  dispatcher only needed a `curve` parameter and per-scheme message types.

The cost is a slightly larger Rust binary and a wider audit surface. The benefit is that
adding a third scheme (e.g. BLS) later is a code addition, not a new deployment unit.

---

## 4. Wire Format and Migration Implications

This is the most important constraint to understand before planning the migration.

ZF FROST's FROST session messages (nonce commitments, signature shares) are serialized
in ZF FROST's format (Postcard + ciphersuite tag). The current signet protocol uses
CBOR with bytemare's encoding. **These are not compatible on the wire.**

FROST signing is a multi-party protocol: the binding factor and challenge computations
depend on the serialized encoding of nonce commitments. All nodes in a session must
use the same wire format. A node running the ZF FROST KMS cannot participate in a
signing session with a node still running bytemare/frost directly.

**Consequence: migration is per-group and must be coordinated.** All nodes in a group
cut over simultaneously. Mixed-version groups are not supported.

**Prerequisite to verify before migration:** confirm that both implementations use
the RFC 9591 secp256k1 ciphersuite context string `"FROST-secp256k1-SHA256-v1"`
identically. If the context strings match, translated key shares are fully usable in
ZF FROST sessions. If they differ, a re-keygen is required for each group. This is a
single grep against both codebases and should be confirmed early.

---

## 5. Key Share Migration

Existing key shares stored in bbolt (bytemare encoding) do **not** require a new DKG
ceremony. The mathematical values are compatible:

- A key share is a scalar `s_i ∈ Z_q` plus a group public key point. These are curve
  elements with no implementation-specific structure.
- Both implementations produce shares of the same form via Pedersen DKG over secp256k1.
- Migration is a format translation: decode bytemare's binary encoding, extract the
  scalar and public key values, re-encode in ZF FROST's `KeyPackage` format.

A `cmd/migrate-keys` tool will handle this as part of Phase 2. It reads the existing
bbolt store, translates each key share, and writes to the KMS's storage format. The
migration is idempotent and non-destructive (old store is not deleted until verified).

---

## 6. IPC Design

**Transport:** Unix domain socket for local deployment; vsock for TEE (AWS Nitro or
similar). gRPC is the protocol — language-agnostic, strongly typed, good tooling on
both `tonic` (Rust) and `grpc-go` (Go).

**Schema (protobuf):**

```protobuf
service KeyManager {
  // Session lifecycle
  rpc StartSession(StartSessionRequest)    returns (StartSessionResponse);
  rpc ProcessMessage(stream SessionMessage) returns (stream SessionMessage);
  rpc AbortSession(AbortSessionRequest)    returns (AbortSessionResponse);

  // Key queries (no key material crosses the boundary)
  rpc GetPublicKey(KeyRef)   returns (PublicKeyResponse);
  rpc ListKeys(GroupRef)     returns (KeyListResponse);
}

message StartSessionRequest {
  string session_id  = 1;
  SessionType type   = 2;  // KEYGEN, SIGN, RESHARE
  bytes  params      = 3;  // CBOR-encoded session params (parties, threshold, etc.)
}

message SessionMessage {
  string session_id = 1;
  string from       = 2;  // sender PartyID
  string to         = 3;  // recipient PartyID; empty = broadcast
  bytes  payload    = 4;  // opaque FROST round message bytes
}

message PublicKeyResponse {
  bytes group_key        = 1;  // 33-byte compressed secp256k1 point
  bytes verifying_share  = 2;  // this node's public key share
  uint64 generation      = 3;
}
```

`ProcessMessage` is a bidirectional streaming RPC: the node feeds it incoming peer
messages and reads back outgoing messages to forward. The KMS drives the ZF FROST round
loop internally; the node sees only the message stream.

---

## 7. What Changes in the Go Node

### The `KeyManager` interface

A new interface in `node/` is the central abstraction. The node calls this for all key
operations; it does not import `signet/tss` directly.

```go
// KeyManager is the interface between the node and whatever process holds key material.
// Today that is LocalKeyManager (in-process tss); in Phase 2 it is RemoteKeyManager
// (KMS over gRPC).
type KeyManager interface {
    Keygen(ctx context.Context, p KeygenParams) error
    Sign(ctx context.Context, p SignParams) (*tss.Signature, error)
    Reshare(ctx context.Context, p ReshareParams) error
    GetPublicKey(groupID, keyID string) ([]byte, error)
    ListKeys(groupID string) ([]string, error)
}
```

### LocalKeyManager (Phase 0)

Wraps the existing `tss` package and `KeyShardStore`. Behavior is identical to today;
the interface boundary is the only change.

```
node/
  keymanager.go         — KeyManager interface + param types
  local_keymanager.go   — LocalKeyManager: wraps tss + KeyShardStore
  remote_keymanager.go  — RemoteKeyManager: gRPC client stub (Phase 1 stub, Phase 2 full)
```

### Node struct changes (Phase 0)

The `Node` struct loses direct `tss` and store references; these move into
`LocalKeyManager`:

```go
// Before
type Node struct {
    store   *KeyShardStore
    configs map[shardKey]*tss.Config
    ...
}

// After
type Node struct {
    km KeyManager   // LocalKeyManager today; RemoteKeyManager after migration
    ...
}
```

The `configs` in-memory cache and `store` bbolt handle are owned by `LocalKeyManager`.
The coord handler and HTTP handlers call `n.km.Sign(...)`, `n.km.Keygen(...)` etc.

### What the node stops doing (Phase 2)

Once `RemoteKeyManager` is wired in:
- `signet/tss` is no longer imported by `node/`
- `node/keystore.go` is no longer used (key storage owned by KMS)
- FROST round messages in `coord.go` become opaque — the coord handler forwards bytes
  to `n.km` rather than parsing them as `tss.Message` structs

---

## 8. Phased Implementation

### Phase 0 — Code re-org (immediate, no behavior change)

Goal: establish the seam that later phases will exploit. Zero change to runtime behavior.

1. Add `node/keymanager.go` — `KeyManager` interface and param types.
2. Add `node/local_keymanager.go` — `LocalKeyManager` wrapping existing `tss` calls and
   `KeyShardStore`. Move `configs` cache and `store` field here from `Node`.
3. Update `Node` struct: replace `store`, `configs` with `km KeyManager`.
4. Update all call sites in `node/coord.go`, `node/node.go` to call through `n.km`.
5. Add `node/remote_keymanager.go` — `RemoteKeyManager` stub that returns
   `errors.New("not implemented")`. Wired in only when `cfg.KMSSocket != ""`.

No changes to `tss/`, `network/`, contracts, or any other package.

**Deliverable:** `node/` no longer has a hard dependency on `signet/tss`; the interface
boundary is explicit and testable.

### Phase 1 — gRPC schema + stubs

Goal: define the protocol contract so Go and Rust development can proceed in parallel.

1. Add `proto/keymanager.proto` — the full gRPC schema from §6.
2. Generate Go client stubs (`grpc-go`) and Rust server stubs (`tonic`).
3. Implement `RemoteKeyManager` in Go using the generated client.
4. Add `kms/` directory at repo root — Rust crate skeleton with `tonic` server,
   placeholder handlers that return `unimplemented`.
5. Add `cfg.KMSSocket` to `node/config.go`; when set, `node.New` creates a
   `RemoteKeyManager` instead of `LocalKeyManager`.
6. Integration test: Go node + KMS stub, verify gRPC connection and error propagation.

**Deliverable:** The IPC contract is locked. Both sides can be implemented independently.

### Phase 2 — Full KMS implementation

Goal: KMS runs ZF FROST; nodes can migrate groups to it.

1. Implement ZF FROST keygen, signing, and reshare in the Rust KMS behind the gRPC
   interface.
2. Add key storage in the KMS (bbolt via `heed`/`sled`, or sqlite — TBD).
3. Implement `cmd/migrate-keys` — reads existing bbolt store, translates bytemare key
   shares to ZF FROST `KeyPackage` format, writes to KMS storage.
4. Verify RFC 9591 context string compatibility between bytemare/frost and ZF FROST
   (prerequisite for key share translation — see §4).
5. Update coord protocol: FROST round messages become opaque payload bytes; routing
   metadata (session ID, from, to) remains in the coord envelope.
6. Per-group migration runbook: stop group, run `migrate-keys`, restart all nodes in
   group with `kms_socket` set, verify.

**Deliverable:** End-to-end keygen and signing via KMS. Existing groups migratable
without re-keygen.

### Phase 3 — TEE packaging (deferred)

Goal: KMS runs inside an attestable enclave.

1. AWS Nitro Enclave build target for the KMS binary.
2. vsock transport replacing Unix socket.
3. Enclave attestation document generation at KMS startup.
4. Node includes attestation in libp2p peer handshake or FROST session establishment.
5. Peers verify attestation before accepting FROST messages from a KMS-backed node.

**Deliverable:** Key material is protected even if the host OS is compromised. Peers
can verify the enclave is running legitimate code.
