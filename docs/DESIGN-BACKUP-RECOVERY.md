# Backup and Recovery

Status: **design**. Nothing here is implemented. Closes the "Backup / Recovery"
item in `docs/PRODUCTION-GAPS.md`.

Zero downtime is achievable, and not because of anything clever — it falls out
of the record format. The rest of this document is mostly about the constraints
that make a *naive* backup design dangerous.

---

## 1. The constraint that shapes everything

A backup of key shards is a copy of the most sensitive material in the system,
and threshold cryptography changes what "sensitive" means here:

- **A backup of fewer than `T` shards is worthless to an attacker.** It is below
  threshold and reveals nothing about the key.
- **A backup of `T` or more shards reconstructs every key in the group.** At
  `T=3`, three shards are equivalent to holding the private keys outright — with
  no on-chain trace, no consent step, and no reshare to invalidate them.

**Count shards, not operators.** It is tempting to state this as "one operator's
backup is harmless", and that is only true where an operator holds fewer than
`T` shards. The alpha does not satisfy that: O'Leary Labs runs **4 of 6 nodes at
`T=3`**, so OLL's backup alone is above threshold and reconstructs every key in
the group. `create-group` prints the distribution precisely so this is visible
rather than assumed (`shards per operator ... oll 4 of 6 <- reaches the
threshold alone`).

This is a property of the topology, not of the backup design, and the backup
does not make it worse: an attacker who compromises OLL's infrastructure already
holds `≥ T` shards, because each node carries both its sealed store and its KEK
in `/etc/signet/secrets/kms.env`. What it does mean is that such an operator's
backup custody is **key-reconstructing material** and must be treated as such —
not as "encrypted config".

The runbook's direction of travel — more operators holding fewer shards each,
ultimately one apiece — is what makes the harmless-fragment reading true. Until
then it is aspiration, and a design that assumes it will give the wrong answer
to a custody question asked today.

So the first design rule is not about durability at all:

> **Backups must never be aggregated across operators.** No shared bucket, no
> central backup service, no "the coordinator collects them", no cross-operator
> replication for redundancy.

This is the same principle already applied to SSH keys per cloud, ACME contacts
per operator, and node keys per node — and it matters more here, because a
centralised backup store silently recreates the single point of compromise the
entire threshold design exists to remove. A backup system is one of the few
things that can quietly undo a threshold scheme.

Where a backup *is* sub-threshold, the bar for where it may live is lower than
intuition suggests — ordinary encrypted object storage in the operator's own
account is appropriate. Where it is not, as with OLL today, the destination is
custody of the group's keys and should be chosen on that basis: hardware-backed
multi-factor, deliberate limits on who inside the organisation can read it, and
awareness that co-locating the ciphertext with whatever unlocks it collapses two
factors into one.

What is never appropriate, at any shard count, is one place holding several
operators' backups.

## 2. Recovery is two-tier, and the common case needs no backup

Losing a node is not the same event as losing a key, and conflating them
produces a worse design.

### Tier 1 — Reshare to a replacement (up to `N-T` nodes lost)

This is the normal path and it already works. Membership changes drive it:
stand up a replacement node, register it, add it to the group on-chain, and the
chain poller creates a reshare job (`node/chain.go`). The surviving committee
redistributes, and the replacement receives a **fresh** share.

It is strictly better than restoring a backup:

- No backup is needed, and no KEK from the dead node is needed.
- The new share is at the **current generation** — no stale-shard risk.
- The old shard, wherever its disk ended up, is cryptographically dead: reshare
  re-randomises the polynomial, so an attacker recovering the failed disk holds
  a share that no longer combines with anything.

For a 6-node `T=3` group this covers losing any one node — which is every
routine failure: instance loss, disk failure, a cloud region going away.

**This path should be exercised deliberately before it is needed.** It is the
one that will actually be used.

### Tier 2 — Restore from backup (more than `N-T` lost at once)

Backup exists for the case Tier 1 cannot serve: fewer than `T` shares survive,
so there is nothing left to reshare *from*. Correlated loss — an operator's
account terminated, a region destroyed, a mistaken `wipe-state.yml` across a
whole org.

Tier 2 is the disaster path. It should be rare, and the design should not
optimise for it at Tier 1's expense.

## 3. Why online backup is safe here

The obvious objection to backing up a live embedded database is that a copy
taken while writes are in flight may be torn. That objection does not apply,
for a specific reason.

`docs/at-rest-encryption-spec.md` defines each record as independently sealed:
a per-record DEK, wrapped by the KEK, with AAD binding the ciphertext to
`tree_name || record_key`. Each shard is therefore a **self-contained,
individually verifiable unit**. There is no cross-record invariant to preserve.

So a backup does not need a globally atomic snapshot. It needs each record to
be internally consistent, which sled's per-key atomicity already guarantees. A
backup in which key A is at generation 3 and key B at generation 4 is not
corrupt — it is simply a set of independently valid shards, and each key is
recovered independently anyway.

**That is the whole reason zero downtime is available.** It is a property of the
record format, not of the backup mechanism.

## 4. Proposed mechanism

### 4.1 `ExportShards` — a new KMS RPC

```proto
rpc ExportShards(ExportShardsRequest) returns (stream SealedShard);

message SealedShard {
  string group_id   = 1;
  string key_id     = 2;
  Curve  curve      = 3;
  uint64 generation = 4;   // plaintext, for staleness checks at restore
  uint32 kek_version = 5;  // which KEK generation sealed this
  bytes  sealed     = 6;   // the record EXACTLY as stored — still encrypted
  string tree_name  = 7;   // AAD binding; restore must re-insert identically
}
```

The critical property: **`sealed` is emitted verbatim, never decrypted.** The
export path does not touch the KEK and cannot produce plaintext. A compromised
backup job, a compromised backup destination, and a leaked export stream are all
equivalent to leaking ciphertext — which alone is not a threshold, and not
usable without the KEK.

`generation` and `kek_version` are surfaced as plaintext metadata because they
are needed to make restore decisions and are not sensitive. Everything else
stays sealed.

Backups run against a live node, concurrent with signing. `tree.iter()` is
already used this way (`storage.rs`, `list_keys`).

### 4.2 What must be backed up, and where it must not be

| Artifact | Contains | Custody |
|---|---|---|
| Sealed shard export | Encrypted key material | Operator's own object storage |
| **KEK** (`SIGNET_KMS_KEY`) | Unwraps everything above | **Separate custody, not beside the export** |
| `node.key` + passphrase | libp2p identity | With the KEK; determines peer ID |
| Manifest | group/key/curve/generation | With the export |

The KEK is the whole game. Ciphertext plus KEK in one bucket is plaintext in one
bucket. They must have different custodians, different credentials, and ideally
different providers — the property being that compromising one storage account
yields nothing.

Today the KEK lives in ansible-vault `host_vars` on an operator laptop and in
`/etc/signet/secrets/kms.env` on the node. Neither is a backup. **A KEK escrow
step is required and is currently missing** — if the laptop and the node are lost
together, the ciphertext backup is unrecoverable and the shards are gone even
though the bytes survived.

`node.key` is worth backing up but is a different class: losing it costs a
peer-ID change and on-chain re-registration (real ETH, and the operator consent
flow again), not key loss.

### 4.3 Restore, and the generation problem

The danger in restore is not corruption, it is **staleness**. A shard from
before a reshare does not combine with current shards. Restoring one silently
gives a node material that will fail to sign — or, worse, participates in ways
that waste threshold capacity while appearing healthy.

Rather than build generation reconciliation across the committee, the design
sidesteps it:

> **Every restore is followed by a mandatory reshare.**

Restore the sealed shards, bring the node up, then immediately reshare across
the recovered committee. This:

- re-randomises all shares, so any stale restored material is superseded;
- proves the restored shares actually interoperate — a reshare that completes is
  positive evidence the backup was good;
- brings every node to a common generation without anyone having to reconcile
  counters;
- invalidates any copy of the backup that leaked in the meantime.

The restore path should refuse to activate a shard whose `generation` is lower
than one already present locally, as a cheap guard — but the reshare is what
makes correctness not depend on that check being right.

## 5. Downtime analysis

| Phase | Group downtime |
|---|---|
| Backup (`ExportShards` on a live node) | **none** — concurrent with signing |
| Tier 1: reshare to replacement | **none** — `N-T` tolerance covers the dead node |
| Tier 2: restore to a dead node | **none for the group** — that node is already down |
| Post-restore mandatory reshare | **none** — existing online machinery |

Zero downtime end to end, with one honest caveat: Tier 2 is invoked precisely
when more than `N-T` nodes are gone, so the group is *already* below threshold
and not signing. The design adds no downtime; it does not conjure availability
that was already lost.

Backup cadence should be driven by keygen rate rather than a clock — a shard
created after the last backup and lost before the next is unrecoverable by Tier
2. An export triggered on keygen volume, with a periodic floor, fits the actual
risk better than a nightly cron.

## 6. Deliberately not proposed

- **Cross-operator backup replication.** Durability improvement, threshold
  destruction. See §1.
- **Plaintext export**, even to an HSM boundary. There is no requirement it
  serves that sealed export does not.
- **Backing up the sled directory by file copy.** It works (crash-consistent;
  sled recovers from its log) and is a reasonable stopgap *today* via a cloud
  volume snapshot, but it couples backup granularity to the whole disk, captures
  unrelated state, and offers no per-key restore. Acceptable as an interim
  measure while §4.1 does not exist; not the design.
- **Automatic restore.** Restore should be a deliberate operator action. An
  automatic path is a mechanism for silently reintroducing superseded key
  material.

## 7. Open questions

1. **KEK escrow mechanism.** The gap that makes the rest moot. Options: split
   across operator-internal custodians (Shamir, but *within* one operator —
   splitting across operators does not help, since one operator's KEK unlocks
   only its own sub-threshold shard), a cloud KMS in a separate account, or an
   HSM. Needs a decision.
2. **Backup destination per operator.** Each operator chooses, but the runbook
   should state the requirement (separate credentials from the KEK) rather than
   leave it to taste.
3. **Does Tier 1 actually work end to end?** The reshare machinery supports
   disjoint committees (`docs/DESIGN-RESHARE.md`), and the chain poller creates
   jobs on membership change, but node-replacement has not been rehearsed on the
   alpha. It should be, before it is needed in anger — and it is testable today
   without any of §4 existing.
