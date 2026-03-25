# Performance Analysis

Benchmark results from the test harness running against a local 3-node devnet (2-of-3 threshold, anvil chain, all nodes on localhost).

**Configuration:** concurrency=10, duration=60s, key pool=10

## Results

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

All errors are HTTP client timeouts (`context deadline exceeded`), not protocol failures.

## Analysis

### Throughput does not scale with concurrency

Sequential baseline achieves ~14 ops/sec for both keygen and sign. At concurrency=10, keygen reaches only ~22 ops/sec (1.6x) and sign ~29 ops/sec (2.1x). Both are far below the theoretical 10x improvement, indicating the system saturates early.

### Latency explodes under load

Sign p50 increases from 31ms (sequential) to 267ms (10 concurrent) — an 8.6x increase for a 2x throughput gain. This is classic queuing delay: requests wait for their turn through a bottleneck rather than executing in parallel.

### Sign scales better than keygen

Sign reaches 29 ops/sec vs keygen's 22 ops/sec under the same concurrency. Sign is a 2-round interactive protocol; keygen is 3 rounds with more expensive crypto (polynomial evaluation, ZK proofs in the DKG). The round-count and per-round cost difference explains the gap.

### Keygen starves under mixed load

When keygen and sign compete for the same resources, keygen throughput drops to 6.2 ops/sec (vs 22 ops/sec when running alone). Sign's faster rounds complete and release resources more frequently, effectively starving the longer keygen operations.

## Bottlenecks (priority order)

### 1. Serial coordination broadcast

`broadcastCoord` dials each peer sequentially over libp2p streams, waiting for an ACK from each before moving to the next. For a 3-node group this means 2 serial round-trips before the protocol can start. Parallelizing this would cut coordination setup latency by ~2x.

### 2. Single-node routing

All harness traffic is routed through node1 as the initiator. The HTTP handler blocks for the full protocol duration, so node1's handler goroutines become the system's throughput ceiling. Any node should be able to initiate; load-balancing initiators across all 3 nodes would roughly 3x capacity.

### 3. Global `frostMu` lock

The `bytemare/frost` library uses a package-level shared hasher (`hash.Fixed`) for its ciphersuite that is not goroutine-safe. All `Sign()` and `AggregateSignatures()` calls within a process are serialized behind a single `sync.Mutex` (`frostMu`). Concurrent sign sessions on the same node block each other even though they have no logical dependency.

Options:
- Upstream fix to `bytemare/frost` to use per-call hashers instead of a shared instance
- Instantiate separate ciphersuite objects per session (not currently supported by the library API)
- Accept the limitation — in production each signer is a separate OS process, so the lock only contends within a single node's concurrent sessions

### 4. Synchronous HTTP model

The HTTP handler blocks until the full interactive protocol completes (2-3 network round-trips). An async model (submit request, return immediately with a session ID, poll or callback for result) would decouple client concurrency from protocol concurrency and improve perceived throughput.

## Correctness

The sequential baseline achieved 820/820 keygen and 820/820 sign with zero failures. This validates the fix for the keygen-sign race condition (participant config not yet persisted when a fast follow-up sign arrives). The `awaitConfig` mechanism in the sign coord handler ensures participants wait for any in-flight keygen to complete before proceeding.
