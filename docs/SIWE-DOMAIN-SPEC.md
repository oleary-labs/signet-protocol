# SIWE domain binding — move to per-group, allow multiple

**Status:** decided, not yet implemented. The open questions at the end of the
first draft are resolved below and marked **Decision**.

**Change:** `siwe_domain` is node config today. It must be per-group, on-chain,
and a list rather than a single value.

**Why on-chain rather than per-group node config:** the domain check gates session
creation, so it is consensus-relevant. Any per-node config can drift, and drifted
config means some nodes accept a session while others reject it — a threshold
failure with a confusing error instead of a clean denial. The group contract is
already the agreement point for members, issuers, and the resolver; domains belong
in the same place.

---

## 1. Domain and resolver are separate axes

| | Answers | Changes | Blast radius |
|---|---|---|---|
| **Resolver** | who is this principal, and what is their canonical subject | almost never | catastrophic — a new resolver address means a new key namespace, and there is no key migration between namespaces (R-1) |
| **SIWE domains** | which relying party may ask | routinely — new app, staging, rebrand | serious — a listed domain can, given a user signature, open a session and sign as that subject |

Keep them as **separate fields with separate timelocks**. Binding them together
forces the routine change to inherit the catastrophic one's ceremony, or loosens
the catastrophic one to make the routine one bearable.

The domain is deliberately **not** part of the key namespace
(`resolver:<addr>:<subject>`). A user signing in at `app.example.org` or
`admin.example.org` must reach the same key. That is what makes the two axes
separable.

Domains are still an authorization surface, not cosmetic config — adding one
grants an application the ability to act for every subject in the group.
Manager-only and timelocked; the delay can be shorter than the resolver's, since
it orphans nothing.

---

## 2. Matching rule

The signer chooses the domain, but it sits inside the signed payload, so they can
only present one they hold a signature for, and a signature minted for `a.com`
cannot be replayed as `b.com`. Presentation is therefore safe.

```
parse SIWE message
  → canonicalize its domain
  → membership test against the group's canonicalized list
  → reject if absent
  → pass the matched entry to siwe.Verify
```

Exact match. No suffix matching, no fallback, no port normalization.

**Implementation note.** `siwe-go`'s `msg.Verify(sig, &expectedDomain, ...)` takes
one expected value, so the flow above parses first and does its own membership
test, then hands the matched entry to `Verify`. That makes `Verify`'s own domain
check tautological — **the membership comparison becomes the real check, and its
semantics are consensus-critical.** Hence §3.

---

## 3. Canonical form (protocol constant, both sides)

The genuine risk here is not wildcards, it is normalization drift: if one node
lowercases and another does not, they disagree and the session fails to reach
threshold. Nastier than a wildcard because it fails intermittently.

A domain is valid iff, byte-for-byte:

1. **ASCII only** — every byte < 0x80. *The important one.* It removes unicode
   confusables and makes case folding deterministic; Go's and Solidity's unicode
   case handling will not agree. Punycode (`xn--…`) is ASCII, so IDNs are still
   representable.
2. **Lowercase**, ASCII folding only (`A-Z` → `a-z`).
3. **Authority only**: `[a-z0-9.-]`, plus an optional `:` followed by a port.
   No scheme, no path, no `@`, no `*`, no whitespace.

   **Decision — the port is range-checked.** 1–65535, no leading zeros. "1–5
   digits" would admit `:0` and `:99999`, which are not ports, and would make
   `:080` a second distinct entry for port 80 that silently never matches. A
   rule claiming to be byte-exact should not accept strings that cannot occur.
4. No leading or trailing `.` or `-`; no `..`.
5. Length 1–255; each label 1–63.

Canonicalize at write time. Nodes canonicalize the message's domain and compare
bytes. Both use the same rule, and the rule is a **protocol constant, not config**
— same reasoning as `acceptedResolverVersions`.

**Ports do not normalize.** `example.org` and `example.org:443` are distinct
entries; browsers omit default ports, so list the bare host. List `localhost:3000`
explicitly for dev rather than special-casing it.

---

## 4. Contract surface

```solidity
function queueSiweDomains(string[] calldata domains) external onlyManager;
function cancelSiweDomains() external;      // initiator only, as with the resolver
function executeSiweDomains() external;     // after the delay
function siweDomains() external view returns (string[] memory);
```

Separate from `queueAuthResolver`. Validate on write with a byte loop over §3 —
gas is irrelevant for a manager-only call, and it fails fast on a typo while
making the invariant visible to anyone auditing the group.

**Decision — the list is replaced wholesale, not diffed.** `queueSiweDomains`
takes the complete future list, deliberately unlike the `addIssuer` /
`removeIssuer` lifecycle it otherwise resembles. A timelocked change should be
auditable *before* it executes, and a complete list answers "what will this
group accept?" directly, where a pending diff only answers "what is changing".
The costs are real and accepted: two concurrent queues are last-write-wins, and
an add cannot be pending independently of a remove.

**Decision — the timelock is the group's existing `removalDelay`.** No new
storage, no new floor, no third delay to set wrong. The first draft argued for a
shorter delay so a routine change need not inherit the catastrophic one's
ceremony — but the resolver timelock is not a separate long constant, it is
`removalDelay` (`SignetGroup.sol:303`), floored by the factory's
`minRemovalDelay` of 10 minutes and set to 600s on the alpha group. There is no
ceremony to escape. If the resolver delay is ever lengthened to match its blast
radius, split this then; doing it now buys nothing and costs a slot and a setter.

**Decision — storage is appended, never added to `AuthResolver`.** New state goes
**above `__gap`** with the gap shrunk by the same slot count, per the convention
at `SignetGroup.sol:58-66`. This is not stylistic. `AuthResolver` is packed into
one slot and nested inside `PendingResolver`, so widening it shifts every slot
beneath: `_pendingResolver.executeAfter` would then be read from the old packed
`next`, which is non-zero on any group that ever configured a resolver, and the
`executeAfter == 0` guard at `SignetGroup.sol:294` would permanently reject every
future resolver change. On a live beacon upgrade that breaks deployed groups with
no recovery short of another upgrade.

**But on-chain validation is a guardrail, not the enforcement point.** A node
serves groups it did not deploy and cannot assume the contract version validated
anything. The node re-validates. Always.

Dedupe and cap the list at write time so the node's loop is bounded and the list
stays inspectable.

**Store plaintext, not `keccak256(domain)`.** Hashing is marginally cheaper, but
the list is a trust declaration — an auditor should be able to read which apps can
act for the group's users. There is no secrecy to protect; it is on-chain either
way.

---

## 5. Node behaviour

- **Reject, do not ignore.** An entry failing §3 is simply not a match for
  anything. State it as a total function rather than a "skip invalid entries"
  pass: the moment two nodes disagree about what counts as ignorable, you are back
  to split votes.
- **Empty list = resolver path disabled.** Preserve today's fail-closed default.
  Empty must never mean "any domain."
- **A domain not in the list = session refused**, with the standard sanitized
  error.

**Decision — `siwe_domain` is deleted from node config entirely.** Not deprecated,
not a fallback, no precedence rule. Any surviving per-node path reinstates exactly
the drift this change exists to remove, and a fallback is worse than the current
state because it fails only sometimes.

Migration is a no-op. The scheme is unusable today — `siwe_domain` is unset on
every deployed node and empty means the scheme is rejected — so there is no
configured group to carry over. Existing groups get an empty on-chain list, which
means the same thing it means now.

**Decision — removing a domain does not revoke live sessions.** Removal stops new
sessions; sessions already minted under that domain keep signing until they
expire. This is the existing rule for the resolver path stated in R-5 —
*revocation latency = session TTL* — and applying a different rule to domains
would mean tracking the originating domain per session, carrying it in the
`msgAuth` coord message, and adding a removal path the chain poller acts on: a
new consensus-relevant surface to bound an event that should be rare.

It must be **written down where an operator will read it**, because the intuition
runs the other way. Someone removing a compromised application's domain during an
incident will expect it to take effect immediately. It does not. The exposure
window is the session TTL, itself bounded by the SIWE `expirationTime`, and an
incident response that needs to be faster than that needs a different mechanism —
not this one used hopefully.

---

## 6. Chain ID and wildcards

**Decision — decouple the SIWE `Chain ID` from the resolver; pin it to the
group's home chain.** Today the node passes the resolver's chain
(`resolver.go:68` hands `cfg.ChainID` to `verifySIWE`), which makes a user-facing
message describe where an identity contract happens to be deployed.

That is the wrong axis. ERC-4361's `chainId` describes the *account's* context —
it is where an ERC-1271 contract account's `isValidSignature` must be called — so
tying it to the resolver means a smart-account signature would be verified against
the wrong chain the moment the resolver is not co-located with the user's wallet.
For plain EOAs the field is advisory and nothing breaks, which is precisely why
this would sit unnoticed until the first contract account.

Pinning to the group's home chain keeps deployment topology out of the message and
leaves the resolver free to move without changing what users sign. If a customer's
users ever live on a chain that is neither the home chain nor the resolver's, this
becomes a third per-group value; not before.

**Decide it now.** Changing which chain id a message must claim invalidates every
message already minted under the old rule. The scheme is unused today, so the cost
is zero; after a PoC ships it is a breaking change to signed payloads.

**No wildcards, and specifically never on a shared suffix.** `*.vercel.app` would
be catastrophic — anyone can deploy there. If preview deployments need to
authenticate, point a domain you control at them and list that. No pattern support
at all: the list is short and exact entries are auditable.
