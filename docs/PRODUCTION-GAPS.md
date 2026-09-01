# Production Readiness Gap Analysis

Single consolidated list of everything between the current codebase and
a production-grade mainnet deployment. Supersedes the previous
`PRODUCTION-TODOS.md` and `TODO-RESHARE-ACCEPTANCE.md`.

For the alpha-scoped audit, see [AUDIT-SCOPE.md](AUDIT-SCOPE.md).

---

## Critical — blocks any real-money deployment

### TLS on HTTP API
The node API is plaintext HTTP. Session keys, auth tokens, and
signatures transit in the clear. Production requires TLS — either
terminate at a reverse proxy (nginx, Caddy) or add native TLS to the
Go server. Reverse proxy is the standard approach.

### Rate Limiting
No rate limiting on any endpoint. `/v1/auth` triggers expensive
`bb verify`; `/v1/keygen` and `/v1/sign` consume threshold protocol
resources. Needs per-IP and per-session limits. Can be middleware in
Go or at the reverse proxy.

### Backup / Recovery
No mechanism to backup or restore key shards beyond copying the sled
database file. Node data loss = permanent key loss (below threshold).

Designed in `docs/DESIGN-BACKUP-RECOVERY.md`; not implemented. Two tiers:
reshare to a replacement node for any loss up to `N-T` (the common case,
needs no backup and already works), and sealed-shard export/restore for
correlated loss beyond that. Online backup is safe because each record is
independently sealed, so no atomic snapshot is required.

One thing blocks it now:
- `ExportShards` KMS RPC (streams records still encrypted; never touches
  the KEK). Not built.

**KEK escrow was the other blocker and is done**, arranged per operator and out
of band. See `testnet/ALPHA-RUNBOOK.md` §"Identity escrow" for the custody
requirement; locations are deliberately not recorded in this repo.

That closes the custody half and none of the durability half. Escrow covers
identity — enough that a rebuilt node keeps its peer ID and on-chain
registration — and **no shards at all**. Restoring from it gives the right node
with an empty key store, so read it as identity escrow, not as backup. The gap
above is unchanged in substance; what changed is that the key which would unwrap
a shard export now has custody, and the export does not exist to be unwrapped.

Note the constraint that shapes the design: `T` operators' backups
reconstruct every key, so backups must never be aggregated across
operators. A centralised backup store undoes the threshold scheme.

### Key Import
No ability to import an existing private key into threshold custody.
ECDSA import is straightforward (Feldman VSS split client-side, send
shares to nodes). FROST import requires constructing compatible
KeyPackage structures.

---

## High — needed before public alpha

### Signing Retry with Subset Selection
The sign handler runs once and returns an error on failure. No
automatic retry with different signer subsets. For 5-node groups, the
coordinator should try alternative 3-of-5 subsets to route around a
griefing or offline node. Core of the "no single operator can block
signing" argument.

### Reshare Coordinator Failover
If the elected reshare leader is down, reshare hangs indefinitely
(`node/reshare.go:48` TODO). Needs timeout-based failover so another
node can take over coordination.

### Persistent Audit Logging
Logging goes to stdout via zap. No persistent, tamper-evident audit
trail. Sensitive operations need structured records shipped to durable
storage for incident response and compliance.

### Generation Field in Reshare
`node/remote_keymanager.go:141` hardcodes `Generation: 1` after
reshare. Breaks version tracking on multiple reshares. Needs to parse
the actual generation from the KMS result.

### Liveness False-Negatives Under Sustained Load
**Observed on mainnet, 2026-08-25, not yet diagnosed.** During a sustained
ECDSA keygen run SFLuv saw seven 30-second timeouts across five nodes. It
recovered unattended, and neither shorter run reproduced it — it appears to
need sustained load.

Two symptoms were originally filed together here and have since been separated
(`3f30ef7`). **The 503s reporting peer health at 1–2 of 6 are not part of this
finding.** A parallel deploy across OLL's four-node batch takes four nodes down
at once and leaves exactly the two that were reported, and a deploy overlapping
a load run reproduces the figure precisely; `serial: 1` (`9b9de30`) now prevents
it. Only the 30-second timeouts remain unexplained.

Keeping them apart matters because their implications are opposite: a tracker
false-negative under load is a design problem on the payments path, while
concurrent restarts were a procedure that has since been fixed. Filed as one
finding, it would have sent the next person hunting a load bug that a deploy
caused.

### ~~Leading hypothesis — probe starvation~~ (withdrawn, 2026-09-01)

The original reading was that `probeInterval = 15s` × `unhealthyAfter = 2` = the
observed 30 seconds, with `probeTimeout = 3s` starved under 4-round ECDSA load.
Recorded here rather than deleted, because the reasoning was seductive and
someone will reconstruct it from the same constants.

It fails on two independent counts, either sufficient:

1. **The 30s was the observer's own clock.** `cmd/harness/main.go` defaulted
   `-timeout` to 30s, and the run that produced the finding did not override it.
   A "client-side 30s timeout" measured the client's patience, not anything about
   the nodes. The agreement with 15 × 2 is a coincidence between unrelated
   constants.

2. **The tracker cannot deny a signature.** `selectSigners` filters candidates by
   `exclude` — peers that failed a real session — and never by health
   (`node/signers.go`). `rank()` sorts unhealthy peers last but leaves them
   eligible, deliberately: *"Liveness is a hint, not an oracle."* Marking every
   peer unhealthy would not reduce the candidate set or trip the capacity check.
   So a tracker false-negative costs preference ordering, not signing capacity,
   and the premise that it "directly removes capacity from the payments path" was
   wrong.

Corollary worth keeping: `insufficient available signers` can *only* arise from
`exclude`, which independently confirms the deploy attribution above.

**Current hypothesis — the client's deadline equalled the node's.** Three 30s
values were in play and two of them collide:

| Source | Value |
|---|---|
| harness `-timeout` default (`cmd/harness/main.go`) | 30s, now 90s |
| participant session context (`node/coord.go`) | 30s |
| `probeInterval` × `unhealthyAfter` | 30s — coincidence |

Participants bound each session at 30s. `runThresholdSign` (`node/signers.go`)
retries with a fresh signer set on failure, carrying the failed peer forward in
`excluded`, and each attempt costs a full round of latency. With the client
timing out at 30s as well, there was no time in which a retry could run: the
client gave up at the instant the first attempt failed. The fault tolerance
existed and could not engage.

The client default is now 90s, which is the cheap half of the fix and enough to
tell whether the timeouts were retryable failures all along. The remaining
question is whether the 30s participant bound is itself right for a saturated
4-round ECDSA session; lowering it would surface failures earlier and leave more
room to retry, at the cost of abandoning sessions that would have completed.

**General rule this is an instance of:** a client deadline must exceed the
server's internal attempt bound by at least one retry, or the retry is
decorative. That relationship was accidental here rather than chosen.

To confirm next time, capture `/debug/stats` during the event: `consecutive_fails`
and `rtt_ms` per peer distinguish "probes were starved" from "the peer was
genuinely unreachable". Correlate against whether TSS sessions to that same peer
were succeeding at the time. That evidence is still worth having — it is now
diagnosis of a secondary effect rather than of the cause.

Two observations from reading `node/liveness.go`, neither load-bearing for the
above:

- Liveness probes dial their own streams, while TSS traffic goes over
  `MuxNetwork` — which exists specifically because long-lived streams hit yamux
  flow-control limits. The probe path does not share that treatment.
- `record()` returns early on failure without updating `rtt`, so a timed-out
  probe contributes nothing to the ranking and a slow peer retains its old fast
  round-trip. Minor, given ranking is all health affects.

Still worth doing on its own merits: **fold session success into the liveness
tracker.** A peer we are exchanging TSS messages with right now is provably
alive, and that evidence is currently discarded in favour of a dedicated ping.
It is also most abundant exactly when load makes pings least reliable.

---

## Medium — before mainnet / full production

### Key Lifecycle Endpoints During Keygen
`handleSetKeyStatus` and `handleDeleteKey` return a bare 404 for a key whose
keygen is still settling on that node, so disable/delete inherit the visibility
race that sign no longer has. Sign was fixed (409 + `Retry-After`, see
`docs/KEYGEN-VISIBILITY-RACE.md`); these were left because the correct
behaviour differs — waiting for a keygen in order to delete the result is
defensible, and so is refusing. Needs a decision, not a copied fix, before
either endpoint is driven programmatically at rate.

### Keygen Attestation
No verification that keygen ran the threshold protocol. A malicious
coordinator could generate a key locally. Fix: each participant signs
the group public key during DKG; coordinator returns threshold-many
attestations; client verifies.

### Required Signer Enforcement
No mechanism to require a specific node in every signing session.
Implementation: `required_signers` field on the group, checked by
every participant before contributing a share.

### Prometheus Metrics
Only a JSON `/debug/stats` endpoint. Need histograms for sign latency,
keygen duration, error rates, session counts, sled DB size, gRPC
latency. Essential for production monitoring and alerting.

### Key Rotation / Expiry Policies
Keys persist indefinitely. No TTL, no automatic rotation schedule.
Needs optional TTL on keys, automatic reshare scheduling, and policy
enforcement at sign time.

### FROST Schnorr Audit
Our FROST adapter wraps the Zcash Foundation `frost-core` (partial
NCC audit at v0.6.0). The session state machine, message routing, and
storage layer have not been independently reviewed.

### Ed25519 Production Path
Works end-to-end in tests but has no production consumer. Needs
integration testing against real chain verification (Solana
Ed25519SigVerify, NEAR native verification).

### Smart Contract Upgrade Governance
Upgrades require the factory owner EOA. No timelock, no multisig. For
production: add a timelock or multisig as upgrade authority.

---

## Low — hardening / future

### Session Isolation Testing
Session IDs route messages, but no formal testing of concurrent
sessions with adversarial message injection.

### Coordinator Crash Recovery
ECDSA coordinator crash after round 3 loses the session. No
checkpointing. Retry from scratch is the recovery path.

### gRPC Authentication to KMS
Unix socket with `insecure.NewCredentials()`. Correct for local
deployment, but remote KMS would need mTLS.

### On-Chain Participation Verification
Group contract registers nodes but doesn't verify keygen participation.
Related to keygen attestation but at the chain layer.

---

## Performance & Storage (from previous PRODUCTION-TODOS.md)

### Batch Reshare Commits
Synchronous per-key `msgReshareCommit` adds a full network round-trip
per key (~2.4x slowdown). Batch completed keys into a single message
and consolidate bbolt writes into a single transaction.

### Deduplicate tss.Config
Every key shard stores the full `tss.Config` including group-level
data identical across all keys. Factor group-level config into a
shared record and store only the per-key delta.

### Compact Group ID Keys in bbolt
Group IDs are full Ethereum address hex strings used as bucket names.
Consider shorter internal identifiers to reduce storage overhead.

---

## Smart Contracts

### Bound Unbounded Arrays
`SignetFactory.registeredNodes` and `SignetFactory.groups` are unbounded
storage arrays. Gate with economic constraints (staking to register,
escrow to create group) to naturally limit growth.

### Mutable Removal Delay
`SignetGroup.removalDelay` is immutable after init. Should be
changeable, but changes must be subject to the current delay
(`queueUpdateRemovalDelay` / `executeUpdateRemovalDelay` pattern).

### Protocol-Level Minimum Removal Delay
`MIN_REMOVAL_DELAY` is a constant. Should be a mutable factory-level
parameter controlled by time-delayed governance.

---

## Reshare — Remaining Test Coverage

### Integration Tests — Multi-Key
- [ ] Coordinator loop with multiple keys (3+ keys, verify all reshared)
- [ ] Bounded concurrency (semaphore limits concurrent sessions)

### Integration Tests — Deferred Events
- [ ] Chain-triggered deferred event (two rapid membership changes)

### Integration Tests — Error & Recovery
- [ ] Crash recovery (kill/restart node, verify job resumes from bbolt)
- [ ] Timeout / unreachable node (30s session timeout, channel cleanup)
- [ ] Partial completion recovery (restart mid-batch, skip done keys)

### Integration Tests — Coord Protocol
- [ ] NACK for unknown group
- [ ] Idempotent ACK for already-done key
- [ ] NACK for duplicate session

### Operator Key Auth
- [ ] Operator key on-chain (factory or group contract field)
- [ ] Operator key validation for admin endpoints
- [ ] Re-enable same-committee reshare (gated by operator auth)

### Remote KMS Reshare
- [ ] Wire up `RemoteKeyManager.RunReshare` (currently returns error;
  Rust KMS reshare is implemented but the Go adapter for reshare
  uses the local key manager path)

---

## Summary

| Category | Items | Effort |
|----------|-------|--------|
| Critical | TLS, rate limiting, backup, key import | 1–2 weeks |
| High | Sign retry, reshare failover, audit logging, generation fix | 1–2 weeks |
| Medium | Keygen attestation, required signers, metrics, key rotation, FROST audit, Ed25519 prod, contract governance | 3–4 weeks |
| Low + Performance + Contracts | Session isolation, crash recovery, batch commits, dedup, contract hardening | 2–3 weeks |
| Reshare test coverage | Integration tests, operator auth, remote KMS | 1–2 weeks |
| **Total** | | **~8–13 weeks** |
