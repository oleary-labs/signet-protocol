# Rust KMS Integration

## Overview

The Rust `kms-tss` process handles all FROST threshold cryptography (keygen and signing) over a gRPC Unix domain socket, replacing the in-process Go TSS implementation as the default for production use. The Go implementation is retained for testing and development (`--no-kms` flag).

## Architecture

```
┌──────────────┐     gRPC/UDS      ┌──────────────┐
│   signetd    │ ◄────────────────► │  kms-tss   │
│  (Go node)   │  ProcessMessage    │   (Rust)     │
│              │  bidi stream       │              │
│  libp2p p2p  │                    │  sled store  │
│  HTTP API    │                    │  FROST crypto│
└──────────────┘                    └──────────────┘
```

Each node runs a dedicated `kms-tss` instance. The node's `RemoteKeyManager` bridges the libp2p session network with the KMS's `ProcessMessage` bidirectional gRPC stream:

1. **StartSession** — node sends CBOR-encoded params, KMS returns initial outgoing FROST messages
2. **ProcessMessage stream** — peer messages from libp2p are forwarded to the KMS; KMS responses are forwarded back to peers
3. **Result** — KMS sends a `SessionResult` (group key for keygen, signature for sign) and closes the stream

Key material (FROST `KeyPackage`, `PublicKeyPackage`) is persisted in sled on the KMS side, never transmitted to the Go node.

## Bugs Fixed During Integration

### 1. Session state corruption (Rust)
`SessionInner::process_message` used `&mut self` with `mem::replace` + early `?` return, permanently losing state on error. Fixed by making `process_message` consuming (`self` → `(Self, Result)`), always returning state.

### 2. DKG round 1 package count (Rust)
`dkg::part3` received N packages (including self) instead of N-1. Fixed by passing filtered `others` map.

### 3. Payload encoding mismatch (Go)
`bridgeSession` sent `msg.MarshalBinary()` (full CBOR-wrapped `tss.Message`) as payload instead of `msg.Data` (raw FROST bytes). The KMS couldn't deserialize the CBOR wrapper as a FROST package, buffered everything as wrong-round, and never progressed.

### 4. Bridge goroutine deadlock (Go)
After the KMS stream closed (EOF), the peer→KMS goroutine blocked forever on `sn.Incoming()` — no more peer messages arrived, and the channel was never closed. `wg.Wait()` blocked the return. Fixed by introducing a `bridgeCtx` that gets cancelled when the KMS stream ends.

### 5. Group ID format mismatch (Go + Rust)
Keygen stored keys under the `0x`-prefixed group ID string from CBOR params (`"0xe451..."`). `GetPublicKey`/`ListKeys` hex-decoded the `0x`-prefixed ID (which fails — `hex.DecodeString` rejects `0x`), producing empty bytes and looking up the wrong storage tree. Fixed by stripping `0x` before hex-decoding on the Go side and normalizing group IDs in the Rust storage layer.

### 6. gRPC NotFound not mapped to nil (Go)
The `KeyManager` interface expects `(nil, nil)` for missing keys, but `GetKeyInfo` propagated gRPC `NotFound` as an error. This caused the sign handler to return 500 instead of 404. Fixed by mapping `NotFound` status to `(nil, nil)`.

### 7. Missing PartyID in RemoteKeyManager (Go)
`GetKeyInfo` returned an empty `PartyID`, causing the sign handler's group membership check to always fail with "not a member of group". Fixed by storing the node's peer ID in `RemoteKeyManager` and returning it in `KeyInfo`.

## Performance Comparison

Measured on the same machine, same 3-node devnet, same harness configuration (`-duration 15s -concurrency 3 -pool 5`):

### Throughput (ops/sec)

| Scenario | Go TSS | Rust KMS | Speedup |
|---|---|---|---|
| Sequential keygen | 44.1 | 72.3 | 1.6x |
| Sequential sign | 44.1 | 72.3 | 1.6x |
| Concurrent keygen | 51.2 | 77.9 | 1.5x |
| Concurrent sign | 568.4 | 772.9 | 1.4x |
| Mixed keygen | 45.2 | 66.1 | 1.5x |
| Mixed sign | 126.3 | 152.5 | 1.2x |

### Latency (p50)

| Scenario | Go TSS | Rust KMS | Improvement |
|---|---|---|---|
| Sequential keygen | 17ms | 9ms | 1.9x |
| Sequential sign | 5ms | 2ms | 2.5x |
| Concurrent keygen | 58ms | 37ms | 1.6x |
| Concurrent sign | 4ms | 3ms | 1.3x |
| Mixed keygen | 21ms | 14ms | 1.5x |
| Mixed sign | 16ms | 13ms | 1.2x |

### Reliability

| Metric | Go TSS | Rust KMS |
|---|---|---|
| Total operations | 12,194 | 16,217 |
| Errors | 2 (0.02%) | 0 (0%) |

The Rust KMS is **1.2–2.5x faster** depending on scenario, with the largest gains in sequential operations where crypto dominates. Under high concurrency the gap narrows as network round-trips become the bottleneck. The Go implementation had 2 sporadic key-not-found races; the Rust KMS had zero errors across all scenarios.

## Devnet Usage

```bash
# Default: Rust KMS (recommended)
devnet/start.sh

# In-process Go TSS (for development/testing without Rust toolchain)
devnet/start.sh --no-kms
```

## Files Changed

- `kms-tss/src/session.rs` — consuming state machine, out-of-order buffering, test suite (12 tests)
- `kms-tss/src/service.rs` — gRPC service with bidi streaming
- `kms-tss/src/storage.rs` — group ID normalization
- `kms-tss/src/params.rs` — `Clone` derives for restore closures
- `node/remote_keymanager.go` — bridge deadlock fix, payload fix, group ID fix, NotFound mapping, PartyID
- `node/node.go` — pass peer ID to RemoteKeyManager
- `devnet/start.sh` — KMS build, launch, socket wait, `--no-kms` flag
- `devnet/stop.sh` — KMS process shutdown and socket cleanup
- `devnet/clean.sh` — KMS data/log/socket cleanup
