# Protocol Performance Analysis

Analysis of keygen and signing performance based on test logs from `TestLibp2pKeygen` and `TestLibp2pSign` (3-node, 2-of-3 threshold, localhost).

---

## Test Structure

`TestLibp2pKeygen` and `TestLibp2pSign` are separate tests. `TestLibp2pSign` internally runs its own keygen first, then signing:

| Phase | Duration | Notes |
|-------|----------|-------|
| TestLibp2pKeygen | **2.86s** | 3 nodes, 5 rounds |
| TestLibp2pSign (keygen phase) | **3.27s** | Keygen run internally before signing |
| TestLibp2pSign (sign phase) | **3.55s** | Actual CMP signing |

---

## Keygen: Round-by-Round Timing

All timestamps are wall-clock from first node entering a round to all nodes entering the next round.

| Round | Compute time | `tryAdvanceRound` calls | Notes |
|-------|-------------|------------------------|-------|
| 1 | 403ms | 24 | Commitment + nonce generation |
| 2 | 10ms | 93 | Broadcast exchange (near-instant) |
| 3 | **1096ms** | **542** | Pedersen/Schnorr ZK proofs — bottleneck |
| 4 | 1185ms | 37 | Paillier key proof |
| 5 | ~12ms | 97 | Final output assembly |

Round 3's 542 `tryAdvanceRound` calls confirms the 10ms polling loop spinning for ~1 second while ZK proofs compute.

---

## Signing: Round-by-Round Timing

CMP sign protocol (3-of-3, localhost, no pre-signing).

| Round | First node in | Node spread | Gap from prev round | Polls | Notes |
|-------|--------------|-------------|--------------------:|-------|-------|
| 1 | +11ms | 0ms | — | 12 | All nodes sync instantly |
| 2 | +166ms | 20ms | 155ms | 18 | Commitment phase |
| 3 | +953ms | 102ms | **767ms** | 18 | ZK proof generation |
| 4 | +2235ms | 304ms | **1180ms** | 21 | MtA / Paillier — heaviest |
| 5 | +2539ms | **1013ms** | 0ms | 10 | Large node spread |

**Total sign time: 3552ms**

Round 5's 1013ms spread between fastest and slowest node points to unequal Paillier computation load — the designated combiner role in CMP differs per party, causing asymmetric work.

---

## The 15ms Claim

The luxfi/threshold library benchmarks (historical reference) state:

```
Key generation (5-of-9): ~28 ms
Signing (5 parties): ~15 ms
```

These numbers appear under the **LSS (Linear Secret Sharing)** section and refer to `protocols/lss`, not CMP. The two protocols differ fundamentally:

| | LSS | CMP |
|---|---|---|
| Signing time | ~15ms | ~3.5–5s |
| ZK proofs | Minimal | Full Paillier + MtA |
| Security model | Semi-honest | Malicious adversary |
| Identifiable abort | No | Yes (presign variant) |

### Baseline Verification

Running `TestRound` directly against the sign package — pure in-memory CBOR transport, no libp2p, no handler overhead — confirms the crypto cost:

```
sign/TestRound     (3-of-3, in-memory): 4.74s
presign/TestRound  (4-of-4, in-memory): 8.95s
```

Our libp2p test (3.55s) is actually *faster* than the library's own in-memory baseline (4.74s), meaning the network transport and handler add no measurable overhead. The bottleneck is purely cryptographic.

### What Makes CMP Signing Expensive

The heavy computation is in sign round 2 (`sign/round2.go`), which runs per other party:

```go
// 2x Paillier affine-group ZK proofs (MtA)
DeltaBeta, DeltaD, DeltaF, DeltaProof := mta.ProveAffG(...)
ChiBeta, ChiD, ChiF, ChiProof := mta.ProveAffG(...)
// 1x log* ZK proof
proof := zklogstar.NewProof(...)
```

Each `ProveAffG` involves multiple modular exponentiations over 2048-bit Paillier ciphertexts. For 3-of-3 signing: 2 parties × 3 proofs each = 6 heavy ZK operations minimum, accounting for the ~950ms–1180ms gap in rounds 3–4.

### CMP's Fast Path: Presign + Online

CMP supports a two-phase approach that can achieve near-instant signing at request time:

1. **Presign (offline, 7 rounds, ~8.95s)** — precomputes a signature share independent of the message, run ahead of time
2. **PresignOnline (online, 1 round, ~milliseconds)** — combines presign shares with the message hash at signing time

The current implementation uses `cmp.Sign` which performs all rounds inline. Switching to `cmp.Presign` + `cmp.PresignOnline` would decouple the expensive ZK work from the latency-sensitive signing path.

---

## Handler Performance Issues

Beyond the cryptographic cost, the handler has structural inefficiencies that add overhead and log noise.

### 1. 10ms Polling Loop Spins After Round Finalization

`roundProcessor` (`handler.go:528`) fires `tryAdvanceRound` every 10ms regardless of state:

```go
ticker := time.NewTicker(10 * time.Millisecond)
```

After a round finalizes, `currentRound` cannot advance until next-round messages arrive from other nodes. During that window (which equals other nodes' computation time), the poller fires every 10ms hitting the "round already finalized" guard uselessly.

**Observed impact across both tests:**
- 793 total `tryAdvanceRound` calls
- 564 total "round already finalized" log entries
- Up to 542 calls for a single round (keygen round 3)

### 2. Artificial 20ms Sleep in `initializeRound`

```go
// handler.go:926
time.Sleep(20 * time.Millisecond)
```

Added to handle a Doerner protocol edge case, this sleep fires on every round initialization for every protocol. Over 10 rounds (keygen + sign combined): **200ms of guaranteed artificial latency**.

### 3. Three Concurrent Triggers Racing on `tryAdvanceRound`

When the last message for a round arrives, three sources fire nearly simultaneously:
- The 10ms ticker (just happened to wake)
- `processMessage` callback (just stored the last message)
- A goroutine spawned by `initializeRound` (10ms delay)

This produces the visible bursts of simultaneous "round already finalized" entries in the logs.

### Fix Direction

Replace the polling loop with event-driven advancement: wake `tryAdvanceRound` only when a new message is stored. The `roundProcessor` ticker should be removed in favor of a channel signal emitted by the message store on each new insertion. The 20ms sleep in `initializeRound` should be removed or scoped to Doerner-only paths.

---

## Summary

| Issue | Impact | Fix |
|-------|--------|-----|
| CMP crypto cost (Paillier/MtA ZK proofs) | 3.5–4.7s per sign | Use Presign + PresignOnline for latency-sensitive paths |
| 10ms polling after round finalization | ~100–200ms noise, 564 wasted log entries | Event-driven advancement via message-arrival channel |
| 20ms sleep in `initializeRound` | ~200ms artificial latency per full protocol | Remove or scope to Doerner only |
| Three concurrent `tryAdvanceRound` triggers | Log noise, minor CPU waste | Single event-driven trigger |
| Pool `workerSearch` deadlock | Benchmark suite cannot run | Investigate pool lifecycle across concurrent protocol instances |
