# Production TODOs

Items to address before considering the reshare system production-ready.

## Performance

### Batch reshare commits
The synchronous per-key `msgReshareCommit` broadcast adds a full network round-trip per key (~2.4x slowdown measured locally). Batch completed keys into a single `msgReshareCommitBatch` message and consolidate the per-participant bbolt writes into a single transaction.

## Storage

### Deduplicate tss.Config
Every key shard stores the full `tss.Config`, which includes group-level data that is identical across all keys in a group: `GroupKey`, `Parties`, `PartyMap`, `PublicKeyShares`. This is highly redundant at scale (1000+ keys per group). Factor group-level config into a shared record and store only the per-key delta (key share, identifier, generation).

### Compact group ID keys in bbolt
Group IDs are full Ethereum addresses (20-byte hex hashes) used as bbolt bucket/key names. These are large and repeated for every key entry. Consider using a shorter internal identifier or a lookup table to reduce storage overhead.

## Smart Contracts

### Bound unbounded arrays with economic constraints
`SignetFactory.registeredNodes` and `SignetFactory.groups` are unbounded storage arrays. Without a cap, unchecked growth could eventually brick the contracts (e.g. `getRegisteredNodes()` or `getGroups()` hitting the block gas limit). The planned solution is to gate these with economic constraints: require staking to register a node, and require USDC escrow to create a group. This naturally limits growth while aligning incentives.
