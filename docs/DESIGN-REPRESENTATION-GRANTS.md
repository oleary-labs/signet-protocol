# Representation Grants (person → server, revocably)

**Status:** Proposal. No code yet.

Builds entirely on shipped machinery: the `onchain_resolver` auth scheme
([`DESIGN-ONCHAIN-AUTH-RESOLVER.md`](DESIGN-ONCHAIN-AUTH-RESOLVER.md)) and
on-chain SIWE domain binding ([`SIWE-DOMAIN-SPEC.md`](SIWE-DOMAIN-SPEC.md)).
The companion sketch — a non-custodial AAuth person server — lives in
`signet-ps` (`internal/attest`, `internal/store/registry.go`). This document is
the protocol-side half: what Signet must add, and what it explicitly must not.

**One-line claim:** a *representation grant* — "this address may act for me,
under these bounds, until I say otherwise" — needs **no new auth scheme**. It is
an `ISignetAuthResolver` implementation. The only protocol change is that
`resolve()` must be able to return **bounds**, not just a boolean.

---

## 1. The requirement

A person wants a server — a person server, an agent runtime, an MCP host — to
act on their behalf. The properties that make this worth doing at all:

| | |
|---|---|
| **Authored by the person** | The server cannot fabricate its own authority. |
| **Revocable by the person alone** | No cooperation from the server, no admin, no censorship. |
| **Verified, not asserted** | Every signing participant re-checks; the initiator's claim is never trusted. |
| **Bounded** | The grant carries limits, and the limits are enforced where the signing happens. |
| **Portable** | Revoking one server and granting another must not orphan the person's keys. |

Signet has four auth paths and **none** of them expresses this. OAuth/ZK,
auth-key certs, and `onchain_resolver` all authenticate a principal directly.
Delegation tokens narrow authority but are minted *by* an already-authenticated
session, so they inherit rather than establish it.

The gap has a characteristic failure mode. A service that wants to act for a
user, given only these primitives, becomes the user's identity provider — it
mints the credential that authenticates the user to Signet. At that point an
N-of-M threshold group terminates in a 1-of-1 trust root, and the "grant" is a
policy the service chooses to honour rather than a fact the protocol enforces.
This is not hypothetical; it is what `signet-better-mcp` does today
(`src/auth.ts`, `mintJwtForUser` — mints a Signet-bound JWT for any user id,
with no user presence, signed by a key in the same process).

A representation grant inverts that: the person signs, the server presents, the
chain adjudicates.

---

## 2. What SIWE changed

This design was previously blocked on a recursion. If the person's root identity
were a Signet key, then authoring a grant would require a Signet session, which
would require an auth path, which — for a person with no institutional issuer —
meant an IdP. The non-custodial property collapsed back into §1's failure mode
one level down.

With `onchain_resolver` shipped, **the person's wallet is a first-class Signet
principal with no IdP in the loop.** `POST /v1/auth` with `scheme:
"onchain_resolver"` takes a SIWE message binding `session_pub`, recovers an
address, and gates it on-chain. Nothing else is involved.

So: **root = the person's wallet.** The recursion is gone, and with it the main
argument against putting representation grants in the protocol at all.

---

## 3. The resolver is already the grant registry

Read the shipped interface as a question:

```solidity
function resolve(address account) external view returns (bool ok, bytes32 subject);
```

> *"May this address open a session, and on whose behalf?"*

That is precisely the question a representation grant answers. The `subject`
return exists so that a principal's many addresses converge on one identity —
which is the same mechanism by which a *representative's* address resolves to
the *person* it represents. Nothing needs to be invented.

### 3.1 The registry adapter

```solidity
contract RepresentationRegistry is ISignetAuthResolver {
    struct Grant {
        address root;        // the person
        uint64  notBefore;
        uint64  notAfter;
        uint64  revokedAt;   // 0 = live
        bytes   caveats;     // §4
    }

    // representative address => grant
    mapping(address => Grant) public grants;

    function grant(address representative, uint64 notAfter, bytes calldata caveats) external;
    function revoke(address representative) external;                 // by root
    function revokeFor(address root, address representative,          // gasless: anyone relays
                       bytes calldata rootSig) external;

    function resolve(address account) external view returns (bool ok, bytes32 subject) {
        Grant storage g = grants[account];
        if (g.root == address(0)) return (false, bytes32(0));
        if (g.revokedAt != 0) return (false, bytes32(0));
        if (block.timestamp < g.notBefore || block.timestamp >= g.notAfter) return (false, bytes32(0));
        return (true, bytes32(uint256(uint160(g.root))));
    }

    function typeAndVersion() external pure returns (string memory) {
        return "SignetRepresentationRegistry 1.0.0";
    }
}
```

The flow, with no node changes at all:

1. The person signs a `grant(...)` transaction (or a root-signed blob that
   anyone relays) naming the server's address.
2. The **server** authenticates to Signet under **its own** address, via the
   ordinary `onchain_resolver` SIWE flow. It proves possession of its own key
   and nothing more.
3. Every node independently reads `resolve(serverAddr)` at the client-pinned
   block and gets `(true, root)`.
4. The session is namespaced `resolver:<registryAddr>:<root>` — under **the
   person**, not the server.

Three properties fall out of step 4 rather than being designed in:

- **Portability is free.** Revoke server A, grant server B; B's sessions resolve
  to the same `subject`, so the person's keys are unchanged. The `signet-ps`
  `/export` endpoint stops being load-bearing for key continuity.
- **The server holds no bearer credential for the person.** It holds one for
  *itself*; its authority is a chain read that the person can invalidate.
- **Revocation is uncensorable.** `revokeFor` lets any relayer — including a
  rival server the person is migrating to — land the revocation.

### 3.2 Mapping

| `signet-ps` concept | Protocol-side home |
|---|---|
| Root key | The person's wallet — a SIWE-capable account (see R-1) |
| `PersonServerAuthorization` | A `Grant` row: `(representative, notAfter, caveats)` |
| `Scope` | The `caveats` blob (§4) |
| Revocation registry `(root, nonce)` | The same contract's `revoke`/`revokeFor` |
| `AgentGrant` | A `Grant` on the agent's address — agents are representatives too |
| I5 portability / `/export` | `subject = root` namespacing (§3.1) |
| Person server "issuer key" | Deleted. There is no issuer. |

The last row is the point. A person server that represents someone through this
path issues **nothing**. It authenticates as itself and lets the chain say who
that makes it. Its off-chain AAuth token minting remains — for AAuth resources
that are not Signet nodes — but that is a separate verification path over the
same grant, not the basis of its Signet authority.

---

## 4. What the protocol actually has to add: caveats

`resolve()` returns a boolean. There is nowhere for "≤ $50 total", "step up above
$10", "sessions no longer than 15 minutes" to land. Without this, a
representation grant is all-or-nothing, which is a materially weaker thing than
what `signet-ps` already models in `attest.Scope`.

### 4.1 Interface

Add a sibling method rather than changing `resolve()` — existing adapters
(ACE/CCID, allowlist) keep working untouched:

```solidity
interface ISignetAuthResolverV2 is ISignetAuthResolver {
    /// @notice Authorize + resolve + bound, in one view call.
    /// @return caveats Opaque, versioned bounds on the resulting session.
    ///                 Empty = unbounded (identical to resolve()).
    function resolveWithCaveats(address account)
        external view returns (bool ok, bytes32 subject, bytes memory caveats);
}
```

Node behaviour: if `typeAndVersion()` is on the group's accept-list *and* the
resolver advertises V2, call `resolveWithCaveats`; otherwise `resolve`. Same
`from = 0x0`, same client-pinned block, same accept-list discipline as R-2 of
the resolver doc — the determinism argument transfers unchanged.

`caveats` is a versioned blob: leading byte = codec id, decoded per **protocol
constant**, never per-node config. An unknown codec id is a **fail-closed**
rejection, not an ignored field. A node that cannot interpret a bound must not
open the session — the opposite ordering silently converts a bounded grant into
an unbounded one.

### 4.2 Carrying and enforcing

`SessionInfo` (`node/sessions.go`) grows one field:

```go
// Caveats bound what this session may do, decoded from the resolver's
// resolveWithCaveats() return. Nil = unbounded. Enforced in
// validateSessionRequest alongside DelegatedKeyID.
Caveats *SessionCaveats
```

Enforcement sits in `validateSessionRequest` (`node/handlers.go:~1124`),
immediately alongside the existing `DelegatedKeyID` check — which is worth
naming for what it is: **a caveat set with exactly one possible caveat.**
Generalizing it is the whole change.

### 4.3 The enforceability boundary — read this before adding fields

A caveat the node cannot check is a comment. Signet signs a **digest**; it
cannot in general read a value out of a payload. So caveats split cleanly:

| Class | Examples | Enforceable? |
|---|---|---|
| **Session-level** | max session TTL; allowed key suffixes; may/may-not mint delegations; allowed scope schemes | **Always.** The node holds all the inputs. |
| **Payload-level** | payment cap; step-up threshold; destination allowlist | **Only** for typed scopes (`0x03` EIP-712) *and* only with a node-side decoder for that type. |

`attest.Scope`'s `PaymentCapWei` and `StepUpAboveWei` are payload-level. For an
unscoped (`0x00`) key the node sees 32 opaque bytes and can enforce neither.

**Requirement:** ship **session-level caveats only** in v0. Payload-level bounds
stay where they already work — the person server enforces them at token-mint
time, exactly as `tokens.checkPaymentEnvelope` does now. Promoting them into the
protocol requires a typed-payload decoder, which is a separate piece of work
with its own (large) surface, and is tracked as OQ-3.

Stating this plainly matters more than the feature: a v0 that accepted
`paymentCapWei` and quietly failed to enforce it would be worse than one that
refuses the field.

### 4.4 v0 codec

```
byte  0      codec id = 0x01
bytes 1..8   maxSessionTTLSeconds (uint64, big-endian; 0 = group default)
byte  9      flags: bit0 = may mint delegation tokens
                    bit1 = may create new keys
byte  10     allowedScopeSchemes bitmap (0x00 unscoped, 0x01 UserOp, 0x03 EIP-712)
byte  11     keySuffixCount (0 = any key under this subject)
bytes 12..   keySuffixCount × 8-byte key suffixes
```

Flat and enumerable, deliberately — a constraint envelope, not a policy
language. Same stance the AAuth draft takes on missions, and the same stance
`attest.Scope` takes.

---

## 5. Step-up, and what it settles

[`DESIGN-APP-COSIGNING.md`](DESIGN-APP-COSIGNING.md) OQ-2 asks whether to build
*enforced* co-signing — a necessary-AND second signature — and declines pending
a real use case, on two objections: it introduces a new **necessary** trust
party, and it couples signing liveness to that party's availability.

Step-up (`signet-ps` I3, `consent.TierElevated`) is the same mechanism with the
objections removed:

- The co-signer is **the person's own root key**, not an app's. No new trust
  party — the person's authority was already necessary.
- It fires only **above a threshold**. Routine operations have no liveness
  coupling; the person is in the loop exactly when they'd want to be.
- It cannot collapse to 1-of-1 the way §3 of that doc warns, because the root is
  not also a *sufficient* authenticator for the representative's session — it
  authorizes the representative, it does not impersonate it.

That is a real answer to OQ-2, and it arrives from the person side rather than
the app side. **But** it is payload-level by §4.3: the node can only enforce
"amount > threshold ⇒ require fresh root signature" if it can read the amount.
So v0 keeps step-up in the person server, and OQ-2 stays open *in the protocol*
until the typed decoder exists. What changes is that the answer is now known;
only the mechanism is pending.

---

## 6. Relationship to existing mechanisms

- **Trusted issuers (OAuth/ZK).** An issuer asserts *who someone is*. A
  representation grant asserts *who may act for whom*. Both are the auth lane,
  both group-level — but the issuer is trusted by the group, whereas the grant
  is authored by the person. Different trust origin, same slot.
- **Auth-key certs.** An app's own signing identity. Orthogonal; a
  representative could hold one, but it says nothing about representation.
- **Delegation tokens.** A session narrowing itself. `DelegatedKeyID` is the
  degenerate one-caveat case of §4 and should be folded into it once the caveat
  set exists. Note the direction of authority differs: delegation flows *down*
  from an authenticated session; a representation grant flows *in* from outside.
- **Key scopes (`0x03` etc.).** The signing lane — what a key may sign. Untouched.
  A represented session drives scoped sub-keys exactly as any other session does.
- **`disable_key`.** See R-4. It is not a revocation primitive for this purpose.

The three lanes now read cleanly: **who may open a session** (auth), **what this
grant may do** (caveats), **what a key may sign** (scopes). The middle one is
what was missing.

---

## 7. Operational implications

Almost entirely inherited from
[`DESIGN-ONCHAIN-AUTH-RESOLVER.md`](DESIGN-ONCHAIN-AUTH-RESOLVER.md) §6 and §10:

- **Per-chain RPC reach.** A group configuring a representation registry needs
  member-node RPC to that registry's chain. Same requirement, same trust
  argument, same correlated-provider risk.
- **Client-pinned block (R-3).** Applies verbatim. The representative supplies
  `(block_number, block_hash)`; nodes fail closed outside `head - maxLag`.
- **Revocation SLA (R-5).** Revocation latency = session TTL, bounded by
  `maxLag` at the auth instant and by `siweMaxSessionTTL` (24h, `node/siwe.go`).
  A grant registry raises the stakes: this is now the window in which a
  compromised server keeps acting for a person after they revoke. Groups
  enabling this scheme should set session TTL well below the resolver default —
  minutes, not hours — and the v0 caveat codec (§4.4) makes that per-grant.
- **DoS (R-6).** Unchanged and still a prerequisite: rate-limit before the
  `eth_call`, keyed on recovered address.

Nothing here is a new operating cost class. That is the argument for this shape
over a bespoke scheme.

---

## 8. Open questions

1. **One registry or many?** Resolver doc OQ-1 asks the same of resolvers. A
   person may want their grants in a registry they chose, while the group has
   configured a different one. Start with one per group; the general answer is
   probably a resolver *set*, and it should be answered once for both.
2. **Grant discovery.** A representative must learn the `(registry, chain)` its
   grant lives in to construct a session. Group config already publishes it, so
   v0 is fine — but a person with grants across groups has no index.
3. **Typed-payload decoder.** The prerequisite for payload-level caveats (§4.3)
   and for protocol-enforced step-up (§5). Scope schemes `0x01`/`0x03` are the
   natural targets. Large enough to be its own design.
4. **Sub-delegation.** May a representative grant onward? The registry could
   express it (grant with `root = representative`) but the subject-namespacing
   consequences are unexamined, and it interacts with delegation tokens (§6).
   Default: no, until asked for.
5. **Caveat intersection.** If a session opened under caveats mints a delegation
   token, the token's authority must be the intersection, not the union. Where
   is that computed and by whom?
6. **Registry migration.** Inherits the resolver doc's R-1 cost, and it bites
   harder here — see R-3 below.

---

## 9. Pressure-test findings & hardening requirements

### R-1 — SIWE verification is ecrecover-only; smart-account roots do not work

`verifySIWE` (`node/siwe.go:49`) validates via `siwe-go`'s `msg.Verify`, which
recovers a secp256k1 signature. ERC-1271 is *anticipated* in the surrounding
comments (`node/siwe.go:42`, `SIWE-DOMAIN-SPEC.md:198` correctly specify that
the SIWE chain id is where a contract account's `isValidSignature` must be
called) but is **not implemented**.

Consequence: a root must be an EOA. Passkey-controlled and multisig accounts —
the accounts a person would actually want as a durable root, and the ones that
make "key-rooted without being seed-phrase-rooted" true — cannot sign a SIWE
message Signet accepts. The `signet-ps` verifier already handles this
(`verifyRootSig` falls back to ERC-1271); the node does not.

**Requirement:** add ERC-1271 fallback to `verifySIWE` before this scheme is
usable for real people. On recovery failure, call
`isValidSignature(hash, sig)` on the message's `address` at the SIWE chain id,
at the same client-pinned block, with `from = 0x0`. Note it is a second
chain read on the auth path, so it lands inside R-6's rate limit and inside §7's
RPC-reach requirement. Node-side change; no contract change.

### R-2 — A caveat the node cannot enforce must be rejected, not ignored

Covered in §4.3, restated as a requirement because it is the single easiest way
for this design to become security theatre: an unknown codec id, an unsupported
caveat field, or a payload-level bound on an untyped scope MUST fail the session
open. Silently dropping an uninterpretable bound converts a grant the person
believed was capped into an unbounded one — the failure is invisible to
precisely the party it harms.

Corollary for the codec: caveats are **not** extensible by adding optional
fields. New bounds need a new codec id and an accept-list entry.

### R-3 — Registry choice is a long-term commitment, not a config value

Resolver-doc R-1 established `resolver:<resolverAddr>:<subject>` namespacing, so
a resolver swap is a key migration. That cost is sharper here because the
registry is also **the person's revocation authority**. Two consequences:

- Migrating registries orphans every key the person holds under the old one, so
  a person cannot cheaply move their revocation authority.
- The group's `queueAuthResolver`/`executeAuthResolver` timelock is the person's
  only protection against the group pointing at a registry that answers
  differently. It is mandatory already; it is *load-bearing* here.

**Requirement:** document the migration path before deploying a registry that
real grants depend on, and treat "which registry" as a group-formation decision
with the same weight as membership. OQ-6.

### R-4 — Revocation must not depend on the credential being revoked

Signet's existing kill switch, `disable_key`, requires a valid session to call.
For a compromised representative that is the wrong ordering: the person may not
hold a session, and the attacker does. The registry's `revoke`/`revokeFor` has
the right ordering — a root signature, landable by any relayer, requiring no
session and no cooperation from the party being revoked.

**Requirement:** when a group runs a representation registry, the registry is
the **source of truth** for representation revocation; `disable_key` remains a
per-key convenience for the person's own keys and MUST NOT be presented as the
way to revoke a representative.

This extends the standing principle from resolver-doc R-5 — *every revocable
authorization must name where it re-checks* — with its ordering twin: **the
revocation path must not require the authorization being revoked.**

### R-5 — The representative's key is a bearer credential for the grant window

Between compromise of a server's SIWE key and revocation landing, the attacker
*is* the representative. The grant does not distinguish them; §7's revocation
SLA is the entire exposure.

**Requirements:**
- Caveat-set `maxSessionTTLSeconds` (§4.4) SHOULD be minutes for grants that can
  sign value, not the 24h SIWE ceiling.
- A representative address SHOULD be single-purpose and rotatable: grant to a
  fresh address per deployment so rotation is a grant+revoke, not a key recovery.
- Grants that permit key creation or delegation minting (§4.4 flag bits) are
  strictly more dangerous than signing grants, because their effects outlive the
  session. Default both bits off.

### R-6 — One grant, two verifiers: they must check the same terms

A person server verifying AAuth tokens off-chain checks the EIP-712
`PersonServerAuthorization`; a Signet node checks the on-chain `Grant`. Same
grant, two representations, and nothing currently forces them to agree — the
person could revoke on-chain while a stale PSA still validates off-chain, or the
two could carry different scopes.

There is a related concrete hazard in the current sketch:
`attest.ContentHash` (`internal/attest/psa.go`) hashes `json.Marshal` output and
relies on Go struct field order. The by-reference `psa` claim is a
`URL#s256=…`, so any non-Go verifier computes a different hash and rejects a
valid grant — in a protocol whose premise is third-party verification. The code
notes JCS (RFC 8785) as a v1 item; that undersells it.

**Requirement:** make the on-chain registry authoritative and give both
verifiers the *same* canonical reference — the **EIP-712 digest**, which is
canonical by construction, already computed on both sides, and already the thing
the root signed. Store it in the `Grant` row; have the off-chain verifier
reference grants by it. JSON canonicalization then never enters the picture, and
divergence between the two views becomes detectable rather than silent.

---

## 10. Sequencing

1. **ERC-1271 in `verifySIWE`** (R-1). Independently useful — it unblocks
   smart-account roots for the existing `onchain_resolver` scheme too, with no
   contract changes and no dependency on anything else here.
2. **`RepresentationRegistry`** (§3.1) as an `ISignetAuthResolver` adapter,
   plus `revokeFor`. Zero node changes; this is the whole grant story minus
   bounds, and it is testable end-to-end on its own.
3. **`ISignetAuthResolverV2` + session-level caveats** (§4). Node-side decode,
   `SessionInfo.Caveats`, enforcement at `validateSessionRequest`. Fold
   `DelegatedKeyID` in.
4. **Typed-payload decoder** (OQ-3) — only if payment caps or protocol-enforced
   step-up are actually wanted at the node rather than at the person server.

Steps 1 and 2 deliver "the person grants, the person revokes, the chain
adjudicates" with no protocol change beyond a signature-verification fallback.
That is the property worth having first.

---

## 11. Sources

- Auth scheme this builds on — [`DESIGN-ONCHAIN-AUTH-RESOLVER.md`](DESIGN-ONCHAIN-AUTH-RESOLVER.md)
  (R-1 namespacing, R-2/R-3 determinism + block pinning, R-5 revocation SLA, R-6 DoS)
- SIWE binding + on-chain domains — [`SIWE-DOMAIN-SPEC.md`](SIWE-DOMAIN-SPEC.md), `node/siwe.go`, `node/resolver.go`
- Interface + group binding — `contracts/contracts/interfaces/ISignetAuthResolver.sol`,
  `ISignetGroup.sol` (`queueAuthResolver`/`executeAuthResolver`, `requireCanonicalSubject`)
- Enforcement point — `node/sessions.go` (`SessionInfo`), `node/handlers.go` (`validateSessionRequest`)
- Co-signing trade-offs this bears on — [`DESIGN-APP-COSIGNING.md`](DESIGN-APP-COSIGNING.md) §3, §5, OQ-2
- Signing lane, kept distinct — [`DESIGN-SCOPED-SUBKEYS.md`](DESIGN-SCOPED-SUBKEYS.md) §7.1–§7.2
- Person-server sketch — `signet-ps`: `DESIGN.md` (I1–I5), `internal/attest/psa.go`
  (`Scope`, `PersonServerAuthorization`, `AgentGrant`), `internal/store/registry.go`
  (`GrantRegistry` sketch, `revokeFor`), `internal/tokens/tokens.go`
  (`checkPaymentEnvelope`), `internal/consent/consent.go` (`TierElevated`, `ApprovalDigest`)
- The failure mode in §1 — `signet-better-mcp`: `src/auth.ts` (`mintJwtForUser`), `src/index.ts`
