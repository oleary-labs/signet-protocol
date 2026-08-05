# On-Chain Auth Resolver (SIWE → on-chain identity)

**Status:** Implemented (core), on branch `feat/onchain-auth-resolver`.
Generalizes the CCID login path
([`signet-product/chainlink/demo-login-with-ccid.md`](../../signet-product/chainlink/demo-login-with-ccid.md))
into a provider-agnostic auth scheme. ACE/CCID becomes the first *adapter*,
not a special case.

**Implementation status (vs. §10):**
- Built: `ISignetAuthResolver` + timelocked `SignetGroup` binding (R-1
  namespacing + mandatory timelock); cross-chain pinned-block resolver read with
  `from=0x0` + block-hash/freshness checks (R-2/R-3); SIWE verification with
  domain/chainId/session_pub/expiry bindings (R-4); `resolver:<addr>:<subject>`
  session namespacing with independent per-participant re-verification;
  protocol-constant resolver version accept-list (R-2). Concrete provider
  adapters (ACE/CCID, allowlist) live in a separate repo (license); this repo
  ships the interface + a mock.
- Deferred: rate limiting on `/v1/auth` (R-6, tracked under audit M2 — a
  prerequisite for production use; a TODO marks the call site); resolver-upgrade
  key migration mechanics (R-1 leaves keys created under an old resolver
  addressable only under that resolver's namespace).

---

## 1. The pattern

Strip the CCID specifics out of "log on with CCID" and the general shape is:

1. **Recover** an address from a SIWE signature (ERC-4361 — an Ethereum
   standard, scheme-independent, lives in the node).
2. **Authorize** the recovered address against an on-chain authority (is this
   address allowed to open a session for this group?).
3. **Resolve** the address to a canonical principal id (the durable identity to
   namespace the session under — so a user's many addresses converge to one
   identity, and address rotation doesn't fragment them).

CCID is one instantiation of (2)+(3). The same shape covers an allowlist
contract, an ERC-8004 registry, a soulbound-token check, or any future on-chain
identity authority. So the scheme is an **on-chain auth resolver**, and the
returned `bytes32` is a generic **subject**, not a CCID.

This is the *auth* lane — "who may open a session" — a sibling of the existing
trusted-issuer mechanism, **not** of key scopes (which constrain *what a key may
sign*). Keep the two distinct.

---

## 2. The resolver interface

Rather than bind a list of raw calls (chain + addresses + selectors + decode
rules) into the group and orchestrate them in the node, define **one** Signet
interface and let the group owner point at any implementation:

```solidity
interface ISignetAuthResolver {
  /// @notice Authorize + resolve an address in a single view call.
  /// @dev MUST be a non-reverting view. Return ok=false on any failure.
  /// @param account The SIWE-recovered address.
  /// @return ok       Whether this address may open a session for the group.
  /// @return subject  Canonical principal to namespace the session under.
  ///                  bytes32(0) = authorized but no canonical id (see §5).
  function resolve(address account) external view returns (bool ok, bytes32 subject);

  /// @notice Versioning so nodes can refuse unknown resolver versions.
  function typeAndVersion() external pure returns (string memory);
}
```

The node makes **one** `eth_call` to a stable interface and learns nothing
provider-specific. The adapter encapsulates "which underlying calls" — for ACE
it internally does `CredentialRegistryIdentityValidator.validate(account, "")`
then `IdentityRegistry.getIdentity(account)`. New provider = new adapter
contract; **zero node releases**.

This mirrors ACE's own design: `IIdentityValidator.validate` is *their*
pluggable hook. We are defining Signet's.

Combining authorize + resolve into one call is deliberate: it's atomic (no
TOCTOU where the gate passes but the id read is inconsistent) and halves the
round-trips. Binding ACE *directly* (no adapter) would need the two separate
calls because ACE exposes no combined method — which is itself the argument for
the thin adapter.

---

## 3. Where the binding lives — the group contract

The group contract is already the canonical, replicated home for auth config:
`SignetGroup` holds trusted OAuth issuers (`addIssuer`/`removeIssuer`/
`getIssuers`) and auth-key certs (`addAuthKey`/`removeAuthKey`), all
`onlyManager`. The resolver is the **on-chain sibling of trusted issuers** and
slots in with the same pattern:

```solidity
struct AuthResolver {
  uint64  chainId;     // chain the resolver lives on (may differ from the group's)
  address resolver;    // ISignetAuthResolver implementation
}

// manager-only, mirroring addIssuer/removeIssuer
function setAuthResolver(uint64 chainId, address resolver) external onlyManager;
function getAuthResolver() external view returns (AuthResolver memory);
```

Only **two** values are bound on-chain: `chainId` and `resolver`. The third
thing we discussed binding — "which calls to make" — moves *into* the adapter
contract, which is the correct home for it because it is the one
provider-specific part.

**Security-critical:** the binding comes from the group contract, never from the
request. The request carries only the SIWE message + signature; *where to verify*
is group config. Otherwise a malicious initiator points the check at a resolver
it controls. (Same principle as the H1 fix: the verification target is config,
not caller-supplied.)

Governance follows the existing issuer model (`onlyManager`), but with a
**mandatory timelock** on `setAuthResolver` (reuse the node-removal
`removalDelay` pattern). The resolver's blast radius is strictly larger than an
issuer's — it authorizes addresses unilaterally, whereas a rogue issuer still
needs the external IdP to actually sign a token — so the delay is a requirement,
not a decision. See §10 R-1.

---

## 4. Node flow

New `/v1/auth` branch, `scheme: "onchain_resolver"`:

```jsonc
{
  "scheme": "onchain_resolver",
  "siwe_message": "<ERC-4361 message text>",   // binds session_pub, nonce, domain, expiry
  "siwe_signature": "0x...",
  "session_pub": "02...",
  "block_number": 12345678,                    // client-pinned recent block for the resolver read (§10 R-3)
  "block_hash": "0x..."                        // canonical hash at that height — reorg-safe pin
}
```

Each node, independently:

1. Verify the SIWE message (ERC-4361): domain, nonce, issued-at/expiry, and that
   `siwe_signature` recovers to the message's `address`. The message MUST commit
   to `session_pub` (statement or resources) so the proof binds the session key.
   *(Node-side, scheme-independent.)*
2. Load `(chainId, resolver)` from the group contract (cached/polled like
   issuers and membership).
3. Validate the client-pinned block: `block_hash` is canonical at `block_number`
   in this node's own view, and `head - maxLag ≤ block_number ≤ head`. Fail
   closed (abstain) if not — the client retries against a fresher block. Then
   `eth_call resolver.resolve(recoveredAddr)` **at that block, with
   `from = 0x0`**, on `chainId` → `(ok, subject)`. (§10 R-2, R-3.)
4. If `!ok` → reject. Else create a session keyed by `session_pub`, namespace
   `resolver:<subject>` (see §5 for `subject == 0`).

**Every signing participant runs steps 1–4 itself** — the initiator's
"authenticated" claim is never trusted, same distributed-enforcement rule as
scope verification. Because nodes read at slightly different blocks, allow a
small block-lag tolerance on the resolver read (identity/credential state moves
slowly; this matches how membership/issuers are already polled).

---

## 5. Design decisions / requirements

- **`subject == 0` convention.** `ok=true, subject=0` means "authorized, no
  canonical id." Two options: namespace by the raw address, or reject. Make it a
  group flag (`requireCanonicalSubject`) — for CCID you'd require a subject; for
  a bare allowlist you might not have one.
- **Namespace by subject, not address.** A user's many addresses must converge
  to one identity; namespacing by address fragments identity across wallets and
  breaks on rotation. This is the whole reason step 3 exists.
- **Adapter is in the auth TCB.** The resolver is trusted to answer honestly —
  but it's owner-configured (same trust as setting issuers/members) and every
  node calls it identically as a view, so no new trust class is introduced.
- **Cross-chain read dependency.** The resolver may live on a different chain
  than the group, so auth liveness now couples to that chain's RPC. Acceptable,
  but note it.
- **Versioning.** Nodes check `typeAndVersion()` and refuse unknown versions.
- **Determinism.** `resolve` must be a pure function of chain state at a block
  (non-reverting view, no oracles with per-call randomness), so independent
  nodes agree. The node enforces its half too: all nodes read at the same
  client-pinned block and with `from = 0x0` (§10 R-2, R-3), and the accepted
  `typeAndVersion()` set is group config, never per-node.

---

## 6. Operational implications: per-chain RPC reach

This scheme changes the node operating baseline, and it's worth stating
explicitly.

**New requirement.** A group that configures an on-chain resolver requires its
member nodes to have RPC access to the resolver's chain(s). Previously a node
needed RPC only to the **one** chain hosting the Signet core contracts
(factory/group). Now a node serving such a group needs reach to *every* chain
that group's resolver(s) live on. This is a real increase in the operational
baseline — but it's scoped: it applies only to groups that opt into on-chain
auth, and is a per-group cost, not a network-wide one.

**It must be a *trusted* RPC.** The `resolve()` read gates session creation, so a
lying endpoint could authorize an address that shouldn't be (or deny one that
should). This is the same trust the node already places in its Signet-core RPC —
new in *scope* (potentially several chains), not in *kind*. Because each node
resolves independently, one node's bad RPC only corrupts that node's own vote,
and the threshold tolerates a bounded number of faulty participants. The real
risk is **correlated** trust — many nodes behind the same compromised provider.
Mitigations for high-value groups: light clients, operator-run full nodes, or a
multi-RPC quorum on the resolver read rather than a single third-party endpoint.

**The line that predicts this cost.** The requirement comes specifically from
features where nodes must **read external chain state** — the auth resolver is
one. Features that only **produce signatures** (scoped signing, x402 payments)
impose no such requirement: the node signs, the client submits, nobody reads the
target chain. So the test for whether a future feature adds per-chain RPC burden
is simply "does a node have to read foreign chain state to do its job?"

**Nodes should advertise network capability.** Operators should register which
networks they can serve, so group formation can reconcile a group's resolver
chain(s) against its members' reach. Two enforcement points fall out:
(a) a node only joins/serves a group whose required chains it supports; and
(b) setting a resolver on a chain not all current members can reach should be
rejected or flagged at config time. Where to advertise: alongside node
registration (the factory node registry) and/or node info (`/v1/info`, gossip).

**Liveness.** Auth now fails closed across more chains — if a group's members
lose access to the resolver chain, that group's logins halt. The operability SLA
for a group spans every chain its config touches.

**Permissioning, and why openness is preserved.** A resolver (and, later,
possibly other config) may point at a **private or permissioned** network. Then
only operators with access to that network can serve the group, which segments
the operator set per group. This is permissioning at the **group layer**, via
capability requirements — *not* at the protocol layer. The base protocol stays
permissionless: anyone can run a node and form groups on public chains. A group
that requires a private network is a voluntary arrangement between its operators
and its app/users — **enabled by the architecture, neither required nor
disallowed.** What changes is that specific groups may be servable only by a
capable subset of operators, by their own choice; the system's underlying
openness is unchanged.

---

## 7. Adapters

| Adapter | `resolve(account)` does | `subject` |
|---|---|---|
| **ACE / CCID** (first) | `CredentialRegistryIdentityValidator.validate(account,"")` && `IdentityRegistry.getIdentity(account) != 0` → ok; subject = the CCID | CCID `bytes32` |
| Allowlist | membership check on a registry → ok | `bytes32(uint160(account))` or a group-assigned id |
| ERC-8004 | resolve agent → owner; check registration | owner/agent id |
| Soulbound / NFT | `balanceOf(account) > 0` | token-derived id |

The CCID demo (`demo-login-with-ccid.md`) is recast as: deploy a thin
`ISignetAuthResolver` adapter wrapping ACE's two view calls, point the group's
resolver at it. The node code is identical across all adapters.

---

## 8. Relationship to existing mechanisms

- **Trusted issuers (OAuth/ZK):** off-chain identity authority (JWT issuer).
  The resolver is the **on-chain** counterpart. Both answer "who may open a
  session," both group-level, both `onlyManager`. Could later unify under a
  general "auth providers" list on the group.
- **Auth-key certs:** app-managed signing identity. Orthogonal — that's a
  credential the app holds, not an on-chain lookup.
- **Key scopes (`0x03`, etc.):** the *signing* lane — what a session's keys may
  sign. Entirely separate from this auth lane. A session opened via the resolver
  still operates scoped sub-keys exactly as today.

---

## 9. Open questions

1. **Single resolver vs. set.** One resolver per group, or a list (OR across
   providers, like multiple issuers)? Start with one; generalize if needed.
2. **Subject collision across adapters.** If a group ever swaps adapters, do
   subjects remain stable / namespaced per-resolver? Likely namespace as
   `resolver:<resolverAddr>:<subject>` to avoid cross-provider collision.
   **Resolved (§10 R-1):** adopt that namespacing — it also closes the
   resolver-swap hijack, at the cost of treating resolver upgrades as key
   migrations.
3. **Block-lag tolerance window.** Concrete value / policy for cross-node
   agreement on the resolver read. **Resolved (§10 R-3):** client-pinned
   `(block_number, block_hash)` plus a `head - maxLag` freshness window;
   `maxLag` remains the one value to set.
4. **Delay on resolver changes.** Immediate (`onlyManager`) like issuers, or
   delayed like node removal? Higher-stakes than an issuer swap, arguably.
   **Resolved (§10 R-1):** delayed — the timelock is mandatory.
5. **Caching.** Per-node cache TTL for `resolve` results vs. revocation
   latency (a revoked credential should stop opening sessions promptly).
   **Reframed (§10 R-5):** the load-bearing quantity is the revocation SLA
   (= session TTL); caching is just an optimization bounded under it.
6. **Capability advertisement (§6).** Where do nodes declare supported
   networks — an on-chain field in the factory node registry, or off-chain node
   info/gossip? And does group membership *enforce* `resolver-chains ⊆
   member-capabilities` at config/join time, or merely warn?
7. **Resolver-read trust policy (§6).** Single trusted RPC vs. light client vs.
   multi-RPC quorum — per group, or a network default for high-value groups?

---

## 10. Pressure-test findings & hardening requirements

A design pressure-test surfaced six issues, all in the trust/determinism
boundary rather than the architecture. Each is stated here as a **requirement**
on the implementation. Where one resolves an open question in §9, the resolution
is noted there too. The first three (R-1, R-2/R-3, R-5) are on the critical path
and should be settled before coding; R-4 and R-6 are hardening that can be
specified alongside.

### R-1 — Resolver swap is a privilege-escalation vector

A resolver gates *who is whom*. Namespacing sessions by `subject` alone lets a
compromised or malicious manager swap in a resolver that returns
`subject = victim's id` for an attacker-controlled address, hijacking the
victim's key namespace. This is the **C4 pattern** (a later grant overriding an
identity an earlier grant established). But namespacing per-resolver-address
orphans keys on every *legitimate* upgrade. You cannot have both.

**Requirements:**
- Namespace sessions/keys as `resolver:<resolverAddr>:<subject>` (adopts Q2).
  Cross-resolver hijack becomes impossible; the cost is that a resolver upgrade
  is a **key migration**, not a transparent swap.
- `setAuthResolver` MUST be timelocked (reuse node-removal `removalDelay`) — no
  longer optional (supersedes Q4). The resolver's blast radius exceeds an
  issuer's: it authorizes addresses unilaterally, whereas a rogue issuer still
  needs the external IdP to sign.
- Migration mechanics (keep old resolver readable for existing keys vs. an
  explicit re-bind) remain open — but the *namespacing decision* is closed.

### R-2 — Node-side determinism: pin the call, not just the adapter

§5 puts determinism on the adapter, but three non-determinism sources are the
node's to close:
- **Pin `from = 0x0` on the `eth_call`.** Stops a resolver that branches on
  `msg.sender`/`tx.origin` (even accidentally) from returning per-node answers.
- **Pin the read block** — see R-3.
- **The accepted `typeAndVersion()` set is group config or a protocol constant,
  never per-node.** Otherwise nodes upgraded at different times disagree on
  acceptance → split brain.

### R-3 — Client-committed block pin for the resolver read

The mechanism for R-2's block pin; it also bounds R-5 and R-6. The request
commits to a specific block and every node reads `resolve()` at exactly that
block, so all honest nodes read identical state.

- Request carries `(block_number, block_hash)` (see §4); nodes `eth_call` at
  that block.
- **Reorg safety via hash, not number.** Each node verifies `block_hash` is the
  canonical hash at `block_number` in its own view. A node that doesn't see that
  hash (lagging sync or reorg) **fails closed and abstains**; the client retries
  with a fresher block. Committing to the number alone would let a reorg
  silently change the read.
- **Freshness window bounds client choice.** The node requires
  `head - maxLag ≤ block_number ≤ head` against *its own* head. The client
  cannot replay an old block where a since-revoked credential was still valid;
  worst-case staleness is `maxLag`, which is precisely the revocation latency
  at the auth instant (ties R-5). Resolves Q3.
- **Not a §3 violation.** The trust target (resolver addr + chain) still comes
  from group config; the block is only a freshness/consistency parameter, and
  each node independently bounds it to its own head — a malicious initiator can
  at most choose a block within the honest window.
- **Cost:** the client now needs read access to the target chain to obtain a
  recent `(number, hash)`. Reasonable — the client already drives a
  chain-specific auth — but it extends §6's RPC-reach observation to the client
  side. Nodes still need their own RPC (they validate the hash and do the read);
  block-pinning adds determinism, it does not remove node RPC.
- For chains exposing a `finalized` tag, a node MAY additionally require
  `block_number ≤ finalized` to sidestep reorgs entirely, trading latency for
  safety. Per-group policy (folds into Q7).

### R-4 — SIWE replay hardening: the `session_pub` binding is the whole boundary

SIWE signatures are produced all over the web; the *only* thing stopping a sig
minted for another dApp (same address) from opening a Signet session is the
message committing to `session_pub`. §4 hand-waves it, so harden it:

- **`session_pub` MUST be carried in a fixed-form ERC-4361 `Resources` URI**,
  e.g. `signet://session/<session_pub_hex>` — not parsed from the free-text
  statement (brittle + an injection surface). Reject messages without exactly
  this resource.
- **`domain` MUST equal a node/group-expected value.** "Verify domain" against
  nothing is vacuous.
- **Pin the SIWE `Chain ID` field** and define which chain it is — recommend it
  equal the resolver `chainId` (three chains are in play: group home, resolver,
  SIWE). The message SHOULD also commit the R-3 `(block_number, block_hash)` so
  a malicious initiator can't swap the read block (optional given R-3's per-node
  window, but cheap).
- **Bound session TTL by the SIWE `expirationTime`**, mirroring the JWT path
  binding a session to `exp`.

### R-5 — Authorization binds at session creation: name the revocation SLA

The resolver gates *auth*, not each *sign* — a credential revoked on-chain keeps
signing until the session expires. Q5 frames this as cache TTL; it is really the
revocation SLA.

- State it plainly: **revocation latency = session TTL** (re-checking per sign
  reintroduces the `eth_call` on the hot path — rejected). With R-3 it also
  equals `maxLag` at the auth instant.
- Make session TTL a group knob, bounded against the strictest adapter's
  revocation expectation (a CCID revocation should land faster than a 24h JWT).
- Same family as C4 (delegation outliving key-disable). Standing principle worth
  adopting protocol-wide: *every revocable authorization must name where it
  re-checks.*

### R-6 — DoS / billing amplification on `/v1/auth` (depends on M2)

Each request fans out to an `eth_call` — possibly cross-chain, possibly against
a **metered** RPC — on every node. SIWE recovery is cheap, so one keypair can
mint unlimited valid requests with fresh nonces, each forcing foreign-chain RPC
spend ×N.

- Verify SIWE fully **before** the resolver read (§4 already orders this) —
  necessary, not sufficient.
- **Rate-limit before the `eth_call`, keyed on recovered address and/or
  `session_pub`.** This makes the open **M2** a *prerequisite* for any group
  enabling this scheme, not a nice-to-have.
- Optionally cache `resolve()` per `(resolverAddr, account, block-window)` to
  collapse retries (bounded by R-5's TTL).

## 11. Sources

- CCID demo / ACE call shapes — `signet-product/chainlink/demo-login-with-ccid.md`
- Group auth config precedent — `contracts/contracts/SignetGroup.sol`
  (`addIssuer`/`removeIssuer`/`getIssuers`, `onlyManager`)
- ACE pluggable validator — `chainlink-ace` `IIdentityValidator.validate`
