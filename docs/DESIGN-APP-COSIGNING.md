# Enforced App Co-Signing and the App-Trust Model

**Status:** Exploratory. No implementation, not scheduled. This captures a
design discussion so the trade-offs aren't lost. Nothing here is committed;
the point is to frame the decision for a future testnet.

**Relationship to other docs:** This revisits and partially challenges
[`DESIGN-SCOPED-SUBKEYS.md` §7](DESIGN-SCOPED-SUBKEYS.md) ("App Binding and
Delegation Tokens"), which argued *against* binding app identity at sign
time. That conclusion still holds for app *identity*; this doc is about a
different thing — an app *co-signature* as an enforced authorization gate.

---

## 1. Motivation

Today, a scoped key constrains **what** can be signed (chain, contract,
EIP-712 primary type) but not **how much** or **how often**. Value- and
rate-level policy (spend ≤ $X/day, allowlisted recipients, approval tiers)
lives in the application, enforced server-side, and Signet trusts the app to
have done it. `DESIGN-SCOPED-SUBKEYS.md` §7 deliberately put that policy
outside Signet, on the view that the real source of truth is the chain /
smart account.

The market hasn't settled there. Concretely:

- **Ampersand** is an agentic wallet that manages agent rules in its app
  server. It *also* operates smart wallets that custody agent funds — so it
  has the on-chain surface available, and has still explicitly chosen to
  enforce rules in the app rather than in the smart account.
- That choice is pragmatic, not principled. There are no off-the-shelf
  Solidity libraries for these rule types (per-agent daily caps, recipient
  allowlists, tiered approvals). Doing it on-chain means building, auditing,
  and maintaining a non-trivial policy contract — a large delta versus a
  server-side check.

So the near-term reality is: **the app is the policy authority, and that's
not going to change soon.** The question this doc explores is whether Signet
should let that app-side policy be *cryptographically required* at signing
time, instead of merely trusted to have happened out of band.

Our position: enforcing these rules on-chain (smart account / source of
truth) is the right long-term design. Enforced app co-signing is a bridge
for the current market, not the destination.

---

## 2. The mechanism: enforced per-payload co-signing

The idea: a key can require that every payload it signs also carry a valid
signature from a designated **approver key** (the app's key). Signet
participants won't contribute a signature share unless that co-signature is
present and valid.

This makes the app's policy gate a **necessary input** to signing rather
than an off-to-the-side trust assumption. Signet still doesn't understand
the policy (it doesn't know the daily limit) — it only refuses to sign
anything the app didn't bless. A leaked or rogue agent session can no longer
sign on its own; the app must co-sign each payload.

Mechanically it's a 2-of-2 over the same request:

- the **session key** proves possession ("a legitimate agent is asking"), and
- the **approver key** proves policy approval ("the app authorized *this*
  payload").

### What the approver signs

The co-signature must bind the *request*, not just the payload hash. If the
app signs only the EIP-712 payload hash, its approval is replayable across
sessions and nonces. It should sign the canonical request preimage —
`groupID : keyID : nonce : timestamp : payloadHash` — the same construction
the H1 fix uses to bind the session signature. That pins the approval to one
request and prevents replay.

### Verification properties (must preserve)

- **Distributed enforcement.** Every participant verifies the co-signature
  independently, exactly as each one independently re-derives and checks the
  scope today. No single node (including the initiator) can waive it.
- **Address + ecrecover.** Store the 20-byte approver address; verify with a
  recoverable secp256k1 signature and compare the recovered signer.
  Consistent with the existing ECDSA path; cheaper than carrying a pubkey.
- **Opt-in per key.** The requirement applies only when a key opts into it
  (via its scope / metadata). It must not become a group-wide mandate —
  that would break interactive OAuth keys that legitimately sign without an
  app in the loop.

---

## 3. The semantic distinction: OR vs AND

This is the crux, and the reason the co-signer must **not** be folded into
the existing registered-key mechanism without an explicit role.

Signet already has group-level registered keys (auth key certificates). Their
semantics are **sufficient / OR**: register an auth key, and possession of it
is *enough* to authorize a signature. Any one registered credential suffices.
It's a disjunction, and it's fundamentally **authentication** — "who is
allowed to act."

The co-signer is the opposite: **necessary / AND**. The approver key's
signature must be present, but it is *not sufficient on its own* — the
session must still be valid and the scope must still pass. It's a
conjunction, and it's **authorization** — "was this specific payload
approved." Sufficient-OR vs necessary-AND; authentication vs authorization.
"Registered group key" is only the shared wire format underneath both.

### Why overloading is a trap

If the same registered-key set is read as "any of these can authorize" in one
path and "this one is required" in another, a key's role becomes ambiguous —
and worse, a key that is *both* a sufficient authenticator and the required
co-signer collapses the 2-of-2 back to 1-of-1. If the app's co-signing key
leaks and that key is also a sufficient authenticator, the attacker doesn't
just gain co-sign ability — they can open their own session and sign
unilaterally, defeating the entire point.

**Therefore it must be possible to register a key that can *only* co-sign and
cannot itself authenticate.** Necessary-but-not-sufficient is the whole
security property.

---

## 4. Data model options

Observation that drove this section: for a given app, the co-signing key is
likely a single app-controlled key. Embedding 20 bytes of approver address in
*every* scope is redundant storage of one logical fact.

### Option A — Embed approver in each scope

Append an approver block to the scope (e.g. compound/TLV scope:
`[0x03 | chain | contract | typeHash][0x04 | approver(20)]`).

- **Pro:** self-contained; a node verifies with zero state beyond the key's
  own scope. The approver is part of `sha256(scope)[:8]`, so it's baked into
  the key's identity — two keys with different approvers are correctly
  different keys.
- **Con:** redundant bytes across every key; rotating the app key means
  re-keying everything (new scope → new suffix → new address to fund).

### Option B — Group-level approver registry + per-scope reference

Store approver(s) once at the group level; the scope carries a small
reference (id), not the address. Empty reference = no co-signer.

- **Pro:** normalized — one approver entry, N references. Rotation = update
  the registry entry; keys pointing at it keep working with no re-keying.
  Identity property preserved *as long as the reference (not the resolved
  address) is in the scope* — the id is still in the suffix preimage.
- **Con:** the co-sig check now depends on synchronized group state rather
  than being purely local to the key. Adds a governance surface (who can
  rotate an approver, on what delay).

**Strong precedent for Option B:** trusted OAuth issuers are *already* exactly
this shape — a group-level, on-chain set with a time-delayed add/remove
lifecycle, loaded at startup and polled. An approver registry is the same
object. The "consistently replicated group config that every participant
checks against" machinery already exists; the co-sign check reads from it the
way scope-time issuer checks already do.

### Reconciling with the OR/AND distinction

The clean synthesis: **one** group-level registry of keys, stored once, where
each entry carries an explicit **role** — `sufficient-authenticator`,
`required-cosigner`, or `both` (only by deliberate choice). The scope's
approver reference points specifically at the `required-cosigner` role, never
the general auth set. This satisfies "store the app key once" (normalization)
while keeping the OR-set and AND-set semantically distinct (no accidental
1-of-1 collapse), and keeps the AND per-key opt-in via the scope reference.

---

## 5. Trade-offs of the AND model

Worth sitting with before building any of it — the AND is a real shift from
where §7 landed:

- **New necessary-trust party.** The app moves from a convenience /
  defense-in-depth layer to a mandatory participant in every signature. That
  is more centralization at the authorization layer, not less.
- **Liveness coupling.** If the app's co-signer is offline, signing halts.
  Fail-closed is arguably the desired safety property, but it's a hard
  availability dependency that didn't exist before.
- **It relocates trust; it doesn't remove it.** Signet still can't see the
  policy. The app can co-sign anything its own logic permits. The gain is
  that the app's approval becomes *verifiable and required* rather than
  *assumed* — not that Signet validates the rule.
- **Rotation/governance** (Option B) becomes a privileged group operation
  with its own delay/authority model, mirroring issuers.

The honest framing: this is a pragmatic bridge for apps like Ampersand that
have chosen app-server policy, letting their gate be enforced rather than
trusted — while the long-term answer remains pushing value/rate policy to the
smart account / chain, where it's the actual source of truth and doesn't
depend on an app being honest or online.

---

## 6. On-chain enforcement: ERC-8004 × ACE (prior art and the destination)

Chainlink's **Automated Compliance Engine (ACE)** is a concrete, shipping
instantiation of the on-chain "destination" this doc keeps pointing at. It's
worth understanding precisely, because it reframes where the co-signer sits
and partly corrects a premise in §1.

### How ACE actually works

ACE is an institutional/RWA compliance framework on Chainlink's CRE (launched
with Apex Group, GLEIF, the ERC-3643 Association). Three pieces matter:

- **CCID (Cross-Chain Identifier)** — a reusable identity layer. Two on-chain
  registries: an `IdentityRegistry` mapping wallet addresses → a universal
  CCID, and a `CredentialRegistry` holding credentials (KYC, AML, accredited
  status) issued by trusted Credential Issuers (IDV providers, e.g. Persona).
  PII stays off-chain; only cryptographic proof (optionally ZK) goes on-chain.
  CCID is compatible with DID, vLEI, ONCHAINID, EAS.
- **CCT Compliance Extension** — a lightweight interface that makes a *token*
  compliance-aware, wiring it to CCID and the Policy Manager. Works across
  ERC-20, ERC-3643, etc.
- **Policy Manager / PolicyEngine** — a modular rules engine. On every call to
  a *protected function* (e.g. transfer), it evaluates a chain of policies and
  returns allow/revert. Policies are add/remove/reorderable without touching
  the token. Prebuilt audited modules include **Allow/Deny lists, Volume
  Limits, Secure Mint** (~12 templates).

The crucial architectural fact: **enforcement lives in the asset, at
execution, on-chain.** ACE is not a signer, co-signer, or a destination you
send to — a compliance-wrapped token queries the Policy Manager when its
transfer is invoked. Compliance is a property of the token, not the signature.

(Note: the chainlink-for-agents deck pairs "ERC-8004 × ACE," but ACE's native
identity layer is CCID, not ERC-8004. ERC-8004 is the *agent*-identity ERC;
the deck splices it in as forward positioning. Real ACE today targets
regulated tokenized assets, not agent spend-limits.)

### The three enforcement loci

| Locus | Mechanism | Expresses | Trust / availability |
|---|---|---|---|
| **By construction** | Signet scoped key — *cannot* sign out of scope | Static constraints (chain / contract / method) | Cryptographic, no extra party |
| **By co-signature** | App must co-sign each payload (the AND, §2–§5) | Dynamic policy (amount/day, allowlists) | Off-chain; app is a necessary trust + liveness party |
| **By interception** | ACE checks every protected-asset transfer | Dynamic policy | On-chain, source of truth |

The co-signer sits exactly in the middle — the off-chain bridge between
Signet's static cryptographic scoping and ACE's on-chain dynamic interception.
This gives the co-signer a concrete **sunset condition**: where ACE-style
on-chain enforcement is present, the off-chain AND-gate is largely redundant.
ACE is therefore complementary, not a competitor.

### Premise correction to §1

§1 claims there are "no off-the-shelf Solidity libraries" for rules like
per-agent daily caps. ACE's **Volume Limits** Policy Accelerator is exactly
that — an audited on-chain module for the spend-cap rule Ampersand hand-rolls
server-side. The catch: it comes bundled with the CCT / ERC-3643 / CCID
framework, so it's "off-the-shelf" only if you're already in the
institutional-token world. For plain USDC-on-Base agent payments it's
heavyweight. So the §1 premise holds for the consumer/dev case and is wrong
for the institutional case.

### Three ways ACE could integrate

1. **Scope-to-compliant-asset (cleanest).** Scope a sub-key's
   `verifyingContract` to a CCT/ERC-3643 compliance-wrapped token. The
   existing `0x03` scheme already expresses this — no new scheme. Every
   payment the key authorizes is then policy-checked by ACE on-chain at
   settlement, because the *token* enforces it. Enforcement-by-construction
   composing with enforcement-by-interception — and, unlike the co-signer,
   **no new trust party and no liveness coupling.** Caveat: the scope only
   guarantees "this key may only touch this one compliance-wrapped asset"; the
   policy enforcement still lives in the target contract — a scope can't
   conjure compliance onto a plain token.
2. **Signer under ERC-8004 / ACE.** Signet is the scoped, revocable,
   threshold-held custody layer beneath an ERC-8004 agent identity, with ACE
   doing on-chain policy. Complementary layering; Signet does signing, the
   chain does enforcement.
3. **Destination-binding scope (future `0x01`).** "The key may only sign calls
   whose *destination* is the ACE router" is a constraint on the call `to`
   address — meaningful only for raw-tx / UserOp signing (the unbuilt `0x01`
   scheme), not for typed-data signing where `verifyingContract` is the only
   "target" notion and `0x03` already binds it.

Net: shape #1 is the most attractive integration because it keeps Signet doing
what it's good at and lets the chain enforce — the concrete form of "co-signer
is a bridge; on-chain is the destination."

---

## 7. The app-auth question: API keys, DID, and CCID

This came up alongside the co-signer discussion and is worth recording
because it's the same underlying theme — *how much do we let an app
short-circuit?*

The existing auth key certificate path exists to serve apps that want to
manage all authentication themselves rather than use an external provider
(OAuth/OIDC). Concern: this lets an app bypass everything — it's a blanket
"trust me, I authenticated the user" credential, with no external anchor.

A preferable direction for app-managed / self-managed auth would be to
integrate a real external-identity standard — e.g. **self-sovereign DID** —
rather than an API-key mechanism that short-circuits the auth model entirely.
That keeps an external, verifiable identity anchor in the loop instead of
collapsing to "the app says so."

This is not a decision yet, but it interacts with §3 above: if the auth key
path is reworked or removed, the "registered keys" set that the co-signer
model wants to live alongside changes shape too. Settle the auth-path
direction and the co-signer's registry model should follow from it.

### CCID as an auth scheme

CCID (§6) is a strong candidate for the "external verifiable identity, not an
API key" direction — arguably the most architecturally aligned of the options.

Today Signet has three auth paths (`DESIGN-SCOPED-SUBKEYS.md` §2.6): OAuth/ZK,
auth-key certificate, and delegation token. Each proves "who" and opens a
session under an identity namespace; scoped keys live under that identity. A
CCID path would slot in as a fourth, and mechanically it's clean:

1. **Wallet-control proof (SIWX).** The client signs a challenge with the key
   for an address it controls — proving control of that address, nothing more.
2. **On-chain resolution.** The node resolves address → CCID via the
   `IdentityRegistry`, then checks the `CredentialRegistry` for the credential
   predicate the *group* requires (e.g. "holds KYC-Verified from issuer set
   X"). This is a plain on-chain read — the node already does chain reads for
   membership and issuers.
3. **Session binding.** Bind the session key to the CCID; keys are namespaced
   under the CCID instead of `oauth:iss:sub`.

Why it fits well:

- **Self-validating, like delegation tokens.** Resolution is an on-chain read
  every node can do independently — no JWKS fetch, no external OAuth provider,
  no Signet ZK circuit required for the basic path. That preserves the
  no-single-trusted-node property better than OAuth does.
- **Matches the DID instinct.** CCID is DID/vLEI/ONCHAINID-compatible, so this
  *is* the DID direction, in its institutional form.
- **Maps onto parent + delegation.** Identity in the ERC-8004/ACE world traces
  agent → accountable owner. So the natural anchor is the **owner's CCID as
  the parent identity**, with the agent operating a delegated sub-key — exactly
  Signet's existing parent-key + delegation model.

Caveats / open points:

- **It imports a policy dimension into auth.** Unlike OAuth (which just checks
  issuer + sub), a CCID gate checks a *credential predicate*. That required-
  credential set is group-level config — mirrors trusted issuers, but it's a
  new policy axis to model and govern.
- **Chain/registry dependency.** Auth liveness now depends on RPC availability
  and ACE's registries being deployed on a chain the node reads. Same coupling
  class as the approver registry in §4.
- **Institutional bias / maturity.** CCID is RWA/accredited-investor oriented
  and still early. For consumer agent payments it may be as heavyweight as ACE
  itself — likely the right anchor for the institutional lane, overkill for the
  consumer one.
- **Whose CCID — owner or agent?** Almost certainly the owner's, with the agent
  as a delegate; worth pinning down explicitly.

---

## 8. Open questions / decision log

1. **Is a group a per-app boundary, or can it host multiple apps?** If
   per-app, the approver is just a single field on the group and most of §4
   dissolves. If multi-tenant, Option B (registry + reference) is required.
2. **AND or stay OR?** Do we actually want enforced co-signing, or is the
   current trusted side-channel sufficient until on-chain policy is viable?
   Don't build until an app asks for *enforced* (not trusted) co-signing.
3. **Approver rotation governance.** Who can add/rotate/remove an approver,
   and on what delay? Default assumption: same lifecycle as trusted issuers.
4. **Auth-path direction (§7).** Keep API-key certs, replace with DID/CCID
   external auth, or both? This gates the registry model in §4.
5. **Encoding if Option A.** Compound/TLV scope changes `scope[0]` from a
   single scheme selector to a block parser (`ValidateScope` /
   `VerifyScopeAndHash` grow a loop). Acceptable, but it's a model change to
   make deliberately.
6. **Which market — institutional or consumer agent finance?** This is the
   meta-question under several others. Institutional → ACE/CCID are the
   compliance + identity anchors and Signet is the custody/signing layer
   beneath them. Consumer/dev → ACE/CCID are overkill and the co-signer bridge
   (or a small bespoke on-chain policy) fits. Much of §6–§7 collapses once
   this is chosen.
7. **CCID auth scheme (§7).** Build a SIWX-proof + on-chain-credential-gate
   auth path anchored on the owner's CCID, with agents as delegates? Most
   aligned with the no-single-trusted-node property and the DID instinct, but
   institution-biased and registry-dependent.
8. **ACE integration shape (§6).** If pursued, default to shape #1 (scope a
   sub-key to a compliance-wrapped asset) — no new scheme, no new trust party.
   Shapes #2/#3 are larger and gated by the market question.
