# On-Chain Auth Resolver (SIWE → on-chain identity)

**Status:** Design. Generalizes the CCID login path
([`signet-product/chainlink/demo-login-with-ccid.md`](../../signet-product/chainlink/demo-login-with-ccid.md))
into a provider-agnostic auth scheme. ACE/CCID becomes the first *adapter*,
not a special case.

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

Governance follows the existing issuer model (`onlyManager`, immediate). If
auth-provider changes warrant a delay, reuse the node-removal `removalDelay`
pattern — a decision, not a requirement.

---

## 4. Node flow

New `/v1/auth` branch, `scheme: "onchain_resolver"`:

```jsonc
{
  "scheme": "onchain_resolver",
  "siwe_message": "<ERC-4361 message text>",   // binds session_pub, nonce, domain, expiry
  "siwe_signature": "0x...",
  "session_pub": "02..."
}
```

Each node, independently:

1. Verify the SIWE message (ERC-4361): domain, nonce, issued-at/expiry, and that
   `siwe_signature` recovers to the message's `address`. The message MUST commit
   to `session_pub` (statement or resources) so the proof binds the session key.
   *(Node-side, scheme-independent.)*
2. Load `(chainId, resolver)` from the group contract (cached/polled like
   issuers and membership).
3. `eth_call resolver.resolve(recoveredAddr)` on `chainId` → `(ok, subject)`.
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
  nodes agree.

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
3. **Block-lag tolerance window.** Concrete value / policy for cross-node
   agreement on the resolver read.
4. **Delay on resolver changes.** Immediate (`onlyManager`) like issuers, or
   delayed like node removal? Higher-stakes than an issuer swap, arguably.
5. **Caching.** Per-node cache TTL for `resolve` results vs. revocation
   latency (a revoked credential should stop opening sessions promptly).
6. **Capability advertisement (§6).** Where do nodes declare supported
   networks — an on-chain field in the factory node registry, or off-chain node
   info/gossip? And does group membership *enforce* `resolver-chains ⊆
   member-capabilities` at config/join time, or merely warn?
7. **Resolver-read trust policy (§6).** Single trusted RPC vs. light client vs.
   multi-RPC quorum — per group, or a network default for high-value groups?

---

## 10. Sources

- CCID demo / ACE call shapes — `signet-product/chainlink/demo-login-with-ccid.md`
- Group auth config precedent — `contracts/contracts/SignetGroup.sol`
  (`addIssuer`/`removeIssuer`/`getIssuers`, `onlyManager`)
- ACE pluggable validator — `chainlink-ace` `IIdentityValidator.validate`
