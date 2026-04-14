# Reshare Hardening

## Status: Draft

## Problem Statement

Reshare is fundamentally different from keygen and sign. When a group membership change is committed on-chain, all existing keys under that group are marked stale in the database — they need to be migrated to the new committee to be considered valid under the new topology.

Keygen and sign are safe to retry or abandon:
- A failed keygen leaves no state — just try again.
- A failed sign can be retried with the same key — no data changes.

Reshare is a **migration**. The critical insight is: **as long as group parameters haven't changed again, the system is in a safe state.** The old key material is still valid and usable — it just needs to be reshared before it can be used under the new committee. This means:

1. **On-demand reshare is always available.** If a signature is requested for a stale key, the system can and should reshare that single key on-the-fly before signing. This is the safety net — no key is truly "lost" as long as the old shares exist and the system knows the key needs migration.

2. **Background batch reshare is the performance path.** We need to re-process all stale keys as quickly as possible, because on-demand reshare adds latency to every sign request. But the batch process is an optimization, not a correctness requirement.

3. **One group-level reshare at a time.** Individual key reshares within a group are independent (own session, own nonce, own shares) and should run concurrently for throughput. What must not overlap is group-level reshares — a second topology change arriving before the first completes produces keys in mixed states across different committee definitions, which is extremely hard to reason about and recover from. This is why the batch process must complete as fast as possible: the group is in a transient state where further topology changes cannot be safely applied.

4. **Each key reshare must be atomic.** A single key's reshare either succeeds on all new-committee members (new shares persisted everywhere) or it fails entirely, leaving the old shares intact and the key still marked stale. The failure case is not a problem — the key can be retried in the next batch pass or migrated on-demand when needed.

The danger is not a single failed reshare attempt. The danger is a failed reshare that **partially overwrites state** — some nodes think the key is migrated, others don't, and the old shares have been discarded. That is data loss. Everything else is recoverable.

## Invariants

### I1: Per-key atomicity
A single key's reshare either completes on **all** new-committee members (every node persists its new share) or it fails entirely with no state changes. There is no partial success. A failed attempt must leave the old shares intact and the key still marked stale.

### I2: Old shares are the backup — never discard prematurely
Old-committee nodes must retain their shares until the reshare for that key is verified complete across all new-committee members. The old shares are what make the system recoverable. As long as old shares exist and the key is marked stale, it can be reshared on-demand or retried in batch.

### I3: Stale keys are usable, not lost
A key marked stale after a group change is not broken — it just needs migration. The system must be able to reshare it on-the-fly when a sign request arrives. "Stale" is a migration status, not an error state.

### I4: No key left behind
Every key that existed under the old committee must be accounted for. The system must not consider a group fully migrated while any key remains stale. The background batch process must eventually reach every key, and any key it misses is caught by on-demand reshare at sign time.

### I5: Background batch is idempotent
The batch reshare process can be interrupted and restarted at any time. Each key it processes either fully succeeds (all new-committee nodes confirm) or fully fails (key remains stale, retry later). Running the batch twice on the same key set produces the same result. This follows from I1.

### I6: One group-level reshare at a time
Individual key reshares within a group are independent and can (and should) run concurrently — each has its own session, nonce, and shares. What must not overlap is **group-level reshares**: a second topology change must not begin processing until the first is fully complete. Overlapping group-level reshares produce keys in mixed states across different committee definitions, which is extremely difficult to reason about and recover from. This is why completing the overall reshare as fast as possible matters — the group is in a transient state where further topology changes cannot be safely applied.

### I7: Coordinator failure cannot cause data loss
The coordinator is a convenience for orchestration, not a custodian of correctness. If the coordinator crashes, another node must be able to resume the batch from where it left off. No key's fate depends on a single node's uptime.

### I8: Deferred events must not outrun migration
A second membership change arriving during an active reshare must not begin processing until the first reshare is verified complete. Chaining events on top of a partially-migrated key set produces keys in an inconsistent state — some held by committee A, some by committee B.

### I9: The chain event is the source of truth
The on-chain membership change is what makes reshare necessary. Nodes must detect and act on chain events autonomously. An API-triggered reshare is a convenience for testing/refresh, not the production trigger.

## Current State (uncommitted hardening changes)

There are in-progress changes that improve robustness of the current reshare implementation. These got us close to — but not quite — 10k keys reshared without failure. The changes include:

1. **Mux network: pool → ephemeral streams.** Replaced the persistent stream pool (`muxPeerPool`, round-robin across `muxStreamsPerPeer=4` long-lived streams) with ephemeral streams (open, write one envelope, close). This avoids yamux flow-control window exhaustion under sustained cross-region traffic. Each `MuxSession` now carries a session-scoped context so in-flight sends are cancelled on timeout.

2. **Session-scoped context propagation.** `MuxNetwork.Session()` now takes a `ctx` parameter. `MuxSession.Close()` cancels its context first, then waits up to 5s for in-flight sends to drain (previously blocked indefinitely on `sendWG.Wait()`).

3. **Longer reshare timeouts.** Per-key reshare timeout bumped from 30s to 60s (both coordinator and participant paths).

4. **Retry budget increase.** `coordinatorLoop` max retries bumped from 3 to 10.

5. **Coordinator loop simplification.** Removed the "wait for on-demand" path in the coordinator loop that tried to detect and wait on in-progress on-demand reshares. Now just skips keys it can't register (via `tryRegisterReshareKey`).

6. **Batch reshare coord message.** Added `msgReshareBatch` (type 5) and `msgReshareComplete` (type 4). Batch sends one coord message with multiple `(keyID, nonce)` pairs, then processes each key sequentially. Reduces coord stream overhead from O(keys) to O(batches).

7. **Auto-create reshare job on coord receive.** Participants that receive a reshare coord message but don't have a local job will auto-create one (for API-triggered refresh where the coordinator creates the job but participants haven't seen a chain event).

8. **POST /v1/reshare re-enabled.** Creates a same-committee reshare job (key refresh) and starts the coordinator. Previously disabled pending operator key auth.

The mux and batch changes are genuine improvements. However, the timeout and retry changes reflect a "something is going wrong, try harder" bias — longer timeouts, more retries — which is the wrong mental model. Given that the system is in a safe state as long as old shares exist and keys are marked stale, the correct approach is not to push harder against transient failures but to **accept them gracefully and recover automatically**. A long-running distributed process over thousands of keys will inevitably hit network blips, slow nodes, and temporary unavailability. The redesign should bias toward idempotence and elegant automatic recovery rather than brute-force retry budgets.

## Current Weaknesses

### Single-node coordinator with no recovery
`coordinatorLoop` runs on one node. If it crashes, pending keys sit in bbolt with no mechanism to restart coordination. `initReshareState` reloads jobs on startup but does not resume the coordinator role.

### Broadcast is all-or-nothing at the wrong level
`broadcastCoord` fails the entire key if any single peer fails to ACK. This conflates "peer is temporarily slow" with "peer is permanently gone." A network blip on one node shouldn't fail-fast a key's reshare — it should retry that peer.

### No distributed completion verification
Each node independently writes `PutKeyDone` to local bbolt. The coordinator marks a key done based on its own success, with no confirmation that all other new-committee members also succeeded. A participant could fail after ACKing the coord message, and the coordinator would never know.

### Retry logic is undifferentiated
The coordinator retries failed keys up to 10x with exponential backoff but does not distinguish transient errors (network timeout, stream reset) from permanent errors (node removed from group, key missing). Permanent errors waste all retry budget.

### Deferred event chaining assumes atomic completion
`completeReshareJob` uses the prior job's `NewParties` as the next job's `OldParties`. If the prior job only partially completed, the chained job operates on an inconsistent base — some keys held by old committee, some by new.

### On-demand reshare races with coordinator
The `waitForReshare` (triggered by a sign request on a stale key) and `coordinatorLoop` both call `tryRegisterReshareKey`. They generate independent random nonces, producing different session IDs. The per-node mutex prevents double-run on the same node, but two different nodes could attempt to coordinate the same key simultaneously.

### Completion broadcast is fire-and-forget
`msgReshareComplete` is sent best-effort. If it fails, remote nodes remain in "resharing" state with no recovery path.

## Design Goals

1. **Zero key loss** under any single-node failure during reshare.
2. **Autonomous recovery** — any surviving node in old-intersection-new can resume coordination.
3. **Verified completion** — a key is not done until all new-committee members confirm.
4. **Clear state machine** — group reshare state transitions are well-defined and auditable.
5. **Distributed leader election** — deterministic coordinator selection with failover, not API-triggered.

## Two Reshare Paths

### On-demand (sign-time)
When a sign request arrives for a stale key:
1. Detect that the key is stale (group membership has changed since last reshare).
2. Reshare that single key to the new committee — all new-committee members must participate.
3. Verify all new-committee members persisted their share.
4. Mark the key as migrated.
5. Proceed with signing under the new committee.

This adds latency to the sign request but guarantees the key is always recoverable. It is the correctness backstop.

### Background batch
When a group membership change is detected:
1. Snapshot all keys that need migration.
2. Process them concurrently with bounded parallelism. Individual key reshares are independent — each has its own session and shares — so parallelism is safe and necessary for throughput.
3. Each key: coordinate reshare across all new-committee members, verify completion, mark migrated.
4. If a key fails: log it, leave it stale, move on. It will be retried next pass or caught on-demand.
5. When all keys are migrated (or the pass completes), loop back and check for any remaining stale keys.

The batch process is the performance optimization — it migrates keys proactively so sign requests don't pay the reshare latency. But it is not required for correctness. Speed matters here because the group is in a transient state during reshare: a second topology change cannot be safely applied until the current reshare completes (I6). The faster we finish, the smaller the window of vulnerability.

The batch and on-demand paths must not conflict. If a sign request triggers on-demand reshare for a key the batch is about to process, the batch should detect that the key is no longer stale and skip it. If the batch is mid-reshare on a key when a sign request arrives, the sign request should wait for the batch to finish that key rather than starting a second concurrent reshare.

## Atomic Swap (Add + Remove as One Operation)

In practice, removing a node from a group rarely means the operator wants a smaller group. The common case is **replacement**: drop node C, add node D, keep the same group size and threshold. Today this requires two sequential on-chain operations (remove → reshare all keys → add → reshare all keys again), doubling the migration cost.

A **swap** operation would express this as a single group change: `oldParties = [A,B,C]`, `newParties = [A,B,D]`. The reshare protocol already supports arbitrary old/new committee definitions — a swap is just one reshare pass instead of two. The benefits:

- **Half the reshare work.** One migration pass over all keys instead of two.
- **No intermediate state.** With two sequential operations, there's a window between the remove-reshare completing and the add-reshare starting where the group is running at reduced size. A swap transitions directly from old topology to new topology.
- **Simpler deferred event handling.** Two rapid membership changes (remove then add) currently produce two deferred events that chain. A swap is a single event.

### Contract implications
`SignetGroup.sol` currently has separate `queueRemoval`/`executeRemoval` and `addNode` functions. A swap would need either:
- A new `swapNode(address oldNode, address newNode)` function that atomically removes one and adds another in a single transaction.
- Or the ability to batch a remove + add into one event that the node layer interprets as a single reshare with the combined old/new committees.

The removal delay (currently 24h for security) would still apply to the outgoing node. The swap would be queued, and after the delay, executed atomically.

### Node layer implications
The reshare job already carries `OldParties` and `NewParties` as independent lists. A swap produces a job where the removed node is in `OldParties` but not `NewParties`, and the added node is in `NewParties` but not `OldParties` — which is exactly what the current `tss.Reshare` protocol expects. The main work is on the contract side and event detection.

## Open Questions

- **Completion verification mechanism.** How does the coordinator confirm all new-committee members persisted their share? Options: (a) explicit "done" message from each participant, (b) new committee produces a test signature as proof, (c) trust the protocol — if `tss.Run` returns success on the coordinator, the protocol guarantees all parties completed. Need to understand what the FROST reshare protocol actually guarantees here.
- **Unreachable new-committee node.** If a node in the new committee is offline, the reshare for every key is blocked. How long do we wait before escalating? The only real fix is operator intervention (remove the unreachable node on-chain), which triggers yet another reshare. Need a clear escalation path.
- **Threshold changes.** If the new committee has a different threshold, old shares cannot produce valid signatures even with the old committee intact. This weakens the "old shares are the backup" guarantee (I2). On-demand reshare still works, but signing is blocked until the reshare completes — there's no fallback to old-committee signing.
- **Coordinator election.** How is the batch coordinator selected? Options: (a) deterministic — lowest party ID in old∩new, (b) first node to detect the chain event, (c) explicit leader election protocol. Needs failover when the coordinator goes down.
- **Batch restart after crash.** The batch must be resumable. The stale-key list in bbolt provides this — on restart, re-scan for stale keys and pick up where we left off. But need to ensure no key is in an intermediate state from a half-finished reshare (follows from I1).

## Next Steps

- [ ] Define the group reshare state machine with clear transitions
- [ ] Design per-key atomicity guarantee (how to ensure I1 in practice)
- [ ] Design coordinator election and failover
- [ ] Design batch/on-demand coordination (mutual exclusion per key)
- [ ] Audit what `tss.Run` guarantees about all-party completion
- [ ] Prototype and test under failure injection (kill coordinator mid-batch, kill participant mid-reshare, network partition)
