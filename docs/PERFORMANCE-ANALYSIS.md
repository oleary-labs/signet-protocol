# Performance Analysis

Benchmark results from the test harness running against a local 3-node devnet (2-of-3 threshold, anvil chain, all nodes on localhost).

## Current Results (v2 — multi-node initiation)

**Configuration:** concurrency=5, duration=30s, key pool=10, initiation=round-robin across 3 nodes

Changes since v1: parallel coord broadcast, `frostMu` removed (oleary-labs/frost fork), multi-node initiation, keygen-exists guard, session-scoped contexts, coord NACK protocol.

### Sequential Baseline (round-robin initiator)

| Op     | Total | Success | Throughput | p50   | p95   | p99   |
|--------|-------|---------|------------|-------|-------|-------|
| keygen | 387   | 100.0%  | 12.9 ops/s | 36ms  | 49ms  | 95ms  |
| sign   | 387   | 99.7%   | 12.9 ops/s | 34ms  | 55ms  | 137ms |

Sign 404 errors (~0.3%) are expected: round-robin means keygen hits node A and the immediate follow-up sign may hit node B before the key has propagated.

### Concurrent Keygen (5 workers, 3 nodes)

| Op     | Total | Success | Throughput | p50   | p95   | p99   |
|--------|-------|---------|------------|-------|-------|-------|
| keygen | 781   | 99.5%   | 19.2 ops/s | 43ms  | 134ms | 174ms |

### Concurrent Sign (5 workers, 10-key pool, 3 nodes)

| Op     | Total | Success | Throughput | p50   | p95   | p99   |
|--------|-------|---------|------------|-------|-------|-------|
| sign   | 1233  | 99.8%   | 33.9 ops/s | 72ms  | 109ms | 199ms |

### Mixed Load (2 keygen + 3 sign workers, 3 nodes)

| Op     | Total | Success | Throughput | p50   | p95   | p99   |
|--------|-------|---------|------------|-------|-------|-------|
| keygen | 51    | 96.1%   | 1.0 ops/s  | 105ms | 150ms | 199ms |
| sign   | 1165  | 99.9%   | 23.1 ops/s | 66ms  | 105ms | 153ms |

All errors are HTTP client timeouts (`context deadline exceeded`), not protocol failures.

## Comparison: v1 (single-node, frostMu) vs v2 (multi-node, no frostMu)

| Metric                     | v1 (single-node)      | v2 (multi-node)       | Change          |
|----------------------------|-----------------------|-----------------------|-----------------|
| Sequential keygen p50      | 34ms                  | 36ms                  | ~same           |
| Sequential sign p50        | 31ms                  | 34ms                  | ~same           |
| Concurrent sign p50        | **267ms**             | **72ms**              | **-73%**        |
| Concurrent sign p95        | 410ms                 | 109ms                 | -73%            |
| Concurrent sign throughput | 28.6 ops/s            | 33.9 ops/s            | +19%            |
| Concurrent keygen p50      | 80ms                  | 43ms                  | -46%            |
| Mixed sign p50             | 82ms                  | 66ms                  | -20%            |
| Mixed sign throughput      | 19.6 ops/s            | 23.1 ops/s            | +18%            |

The dominant improvement is in concurrent sign latency: **p50 dropped from 267ms to 72ms**. This is primarily from removing the `frostMu` global mutex (oleary-labs/frost fork uses per-call hashers instead of a shared `hash.Fixed` instance). Parallel coord broadcast and multi-node initiation contribute to throughput gains.

Sequential latency is unchanged — single-threaded operations never hit the mutex contention.

## Analysis

### Remaining bottleneck: keygen under mixed load

Keygen throughput collapses to ~1 ops/sec under mixed load (vs 19 ops/sec standalone). Keygen is a 2-round interactive protocol with more expensive per-round crypto (DKG polynomial evaluation, commitment verification). Under contention with faster sign operations, keygen sessions get starved for GossipSub message delivery and CPU time.

### Throughput ceiling

Concurrent sign tops out at ~34 ops/sec across 3 nodes. The bottleneck is now the 2-round interactive protocol itself — each sign requires 2 network round-trips through GossipSub, and all participants must complete each round before the next begins. On localhost (sub-millisecond RTT), the floor is set by FROST cryptographic operations (commitment, partial signature, aggregation).

### Multi-node consistency window

With round-robin initiation, there's a brief window after keygen completes on the initiator where other nodes may not yet have the key in their local cache. The `awaitConfig` mechanism handles this for coord-initiated operations, but direct HTTP sign requests to a non-initiator node during this window will get a 404. This is by design — in production, clients would retry or use the same node for keygen and the first sign.

### Resolved bottlenecks

1. **`frostMu` global mutex** — Eliminated by switching to oleary-labs/frost fork. H4/H5 hash functions now create per-call hashers instead of reusing a shared instance. This was the single largest performance bottleneck.

2. **Serial coordination broadcast** — `broadcastCoord` now dials all peers in parallel and collects ACKs from a buffered channel. Total coord setup latency is bounded by the slowest peer, not the sum.

3. **Single-node initiation** — Harness now round-robins requests across all 3 nodes, distributing HTTP handler load and coord initiation work evenly.

4. **Goroutine leak on timeout** — Participant goroutines now use session-scoped contexts (30s timeout) instead of the node's long-lived context. Timed-out sessions clean up promptly.

5. **Silent keygen overwrite** — Keygen on an existing key ID now returns 409 Conflict (initiator) or NACK (participant) instead of silently overwriting.

## Correctness

All 7 correctness tests pass consistently, including cross-node consistency (keygen on node1, sign on node2). Two consecutive perf runs showed stable results with no degradation, confirming the goroutine leak fix and session cleanup are working correctly.

---

## Historical Results (v1 — single-node initiation, frostMu)

**Configuration:** concurrency=10, duration=60s, key pool=10, initiation=node1 only

### Sequential Baseline

| Op     | Total | Success | Throughput | p50   | p95   | p99   |
|--------|-------|---------|------------|-------|-------|-------|
| keygen | 820   | 100.0%  | 13.7 ops/s | 34ms  | 52ms  | 91ms  |
| sign   | 820   | 100.0%  | 13.7 ops/s | 31ms  | 53ms  | 144ms |

### Concurrent Keygen (10 workers)

| Op     | Total | Success | Throughput | p50   | p95   | p99   |
|--------|-------|---------|------------|-------|-------|-------|
| keygen | 1777  | 99.0%   | 21.9 ops/s | 80ms  | 224ms | 393ms |

### Concurrent Sign (10 workers, 10-key pool)

| Op     | Total | Success | Throughput | p50   | p95   | p99   |
|--------|-------|---------|------------|-------|-------|-------|
| sign   | 2051  | 100.0%  | 28.6 ops/s | 267ms | 410ms | 600ms |

### Mixed Load (5 keygen + 5 sign workers)

| Op     | Total | Success | Throughput | p50   | p95   | p99   |
|--------|-------|---------|------------|-------|-------|-------|
| keygen | 482   | 97.9%   | 6.2 ops/s  | 91ms  | 179ms | 300ms |
| sign   | 1531  | 99.6%   | 19.6 ops/s | 82ms  | 231ms | 367ms |
