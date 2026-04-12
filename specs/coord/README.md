# Coordination Protocol

Model of the barrier synchronization layer that precedes every TSS operation (keygen, sign, reshare). Corresponds to `node/coord.go`. An initiator broadcasts a `coordMsg` to all participants, each validates independently and responds ACK/NACK. The TSS protocol starts only after all participants ACK. Any NACK aborts.

This spec models the coordination layer only, not the TSS rounds that follow. The existing keygen, sign, and reshare specs model what happens after coordination succeeds. This spec models whether coordination succeeds.

## What is modeled

The spec covers the initiator broadcast, participant validation, ACK/NACK response collection, and abort semantics. Auth validation is abstracted to a boolean (the spec does not model ZK proofs or certificate verification internals). Nonce uniqueness and timestamp freshness are modeled explicitly since they affect coordination outcomes.

**Initiator phases:** `Idle -> Broadcasting -> AllAcked` (happy path) or `Idle -> Broadcasting -> Aborted` (any NACK).

**Participant phases:** `PIdle -> Received -> Validated -> Acked` (happy path) or `PIdle -> Received -> Nacked` (validation failure).

## Parties

The spec uses an asymmetric 3-party configuration:

| Party | Role |
|-------|------|
| P1 | Initiator (broadcasts coordMsg, collects responses) |
| P2 | Participant (validates, responds ACK/NACK) |
| P3 | Participant |

## Protocol flow

```
Initiator                              Participant
  |                                       |
  |-- coordMsg (broadcast) -------------->|
  |                                       |-- decode
  |                                       |-- validate auth (if policy)
  |                                       |-- check nonce uniqueness
  |                                       |-- check timestamp freshness
  |                                       |-- check key constraints
  |                                       |-- register session network
  |<-- ACK (0x01) or NACK (0x00) ---------|
  |                                       |
  |  (all ACKs => AllAcked, TSS starts)   |
  |  (any NACK => Aborted)                |
```

## Files

| File | What it contains |
|------|------------------|
| `coord.qnt` | Protocol model, invariants, witnesses |
| `test.qnt` | Deterministic scenario tests |

## Abstraction choices

| Aspect | Model | Code reality |
|--------|-------|--------------|
| Auth validation | Boolean `valid` field | ZK proof / auth key cert verification |
| Nonce uniqueness | `seenNonces: Set[str]` (prior sessions) | 5-min retention map in sessions store |
| Timestamp freshness | Integer comparison within window | `time.Now()` within 30-second tolerance |
| Key existence | `keyStore: Set[str]` | bbolt key shard lookup |
| TSS parameters | Omitted (threshold, signers, message hash) | Pass through coordination transparently |
| Network | Reliable, unordered set | libp2p direct streams |
| Parallel broadcast | Sequential actions (order irrelevant) | Goroutines with fail-fast on first error |

## Safety invariants (6)

| Invariant | Property |
|-----------|----------|
| `noProtocolWithoutAllACKs` | AllAcked implies all participants Acked |
| `nackMeansAbort` | Any participant Nacked implies initiator not AllAcked |
| `responseOnlyFromParticipants` | Responses only from group members |
| `atMostOneResponsePerParticipant` | Each participant responds at most once |
| `keyExistsBlocksKeygen` | Keygen participant cannot ACK if key exists |
| `authRequiredWhenPolicy` | No ACK without auth when group has auth policy |

## Witnesses

| Witness | Expected |
|---------|----------|
| `protocolNeverStarts` | Violated (confirms AllAcked reachable) |
| `neverAborted` | Violated (confirms Aborted reachable) |

## Tests

| Test | Scenario |
|------|----------|
| `happyPathKeygenTest` | Initiator broadcasts keygen, both participants validate + ACK, AllAcked |
| `keyExistsNACKTest` | Key in store, keygen participant NACKs, initiator aborts |
| `authFailureNACKTest` | Invalid auth, participant NACKs, initiator aborts |
| `happyPathSignTest` | Sign with key in store, both ACK, AllAcked |
| `missingAuthNACKTest` | Auth policy set but auth missing, participant NACKs |
| `signWithoutKeyNACKTest` | Sign without key in store, participant NACKs |

## Running

```bash
quint typecheck coord.qnt
quint test test.qnt --main=coord_test

# Simulation with safety invariant
quint run coord.qnt --max-steps=20 --max-samples=500 --invariant=safety

# Witnesses (should find violations, confirming reachability)
quint run coord.qnt --max-steps=20 --invariant=protocolNeverStarts
quint run coord.qnt --max-steps=20 --invariant=neverAborted

# Exhaustive model checking (requires apalache-mc)
quint verify coord.qnt --invariant=safety
```

## Possible extensions

- **Nonce replay across sessions** -- Model two sequential coordination attempts to verify nonce replay rejection.
- **Dual coordinator** -- Model two nodes both initiating coordination for the same key and the NACK-and-skip resolution.
- **Timeout behavior** -- Model stream timeouts and partial ACK collection.
- **Byzantine participants** -- Model a participant that ACKs but does not run the TSS protocol.
