# Signer Selection and Liveness

How a signing request decides *which* nodes run the protocol, and what that
means for choosing a group size and threshold.

---

## The problem

Before this, every signing session used every group member:

```go
sortedSigners := tss.NewPartyIDSlice(grp.Members)   // node/handlers.go
```

and `broadcastCoord` returned on the first unreachable peer. So a single node
being down failed every signature, regardless of threshold. The fault tolerance
existed in the cryptography and nowhere else.

There was also no way to know a node was down. The only `Connectedness` call in
the tree was inside `deregisterPeer` for cache eviction; `/v1/health` reports
the node you asked and has no view of its peers.

---

## How many signers a signature actually needs

**FROST** (secp256k1, Ed25519) is genuinely `T`-of-`N`. Any `T` members sign.

**ECDSA** (DJNPO20) is not, and this is the part that shapes the deployment.
`kms-tss` derives its own security parameter from the *signer set*:

```rust
let max_malicious = (n - 1) / 2;      // ecdsa_session.rs
```

while the share it loads lies on the degree-`T-1` polynomial from the DKG. The
signature share carries `beta_me = c_me * secret_share`, so its degree in the
party index is `t + (T-1)`. The coordinator reconstructs by Lagrange
interpolation over the `n` participating points, which is exact only up to
degree `n-1`. Therefore:

```
(n-1)/2 + T - 1  ≤  n - 1     ⟹     n ≥ 2T - 1
```

Below that bound the protocol **completes and returns a well-formed signature
that does not verify under the group key**. It is not an error you see at
signing time — it surfaces downstream as a failed `ecrecover` or a reverted
EIP-3009 transfer. `kms-tss` also refuses fewer than 3 ECDSA signers outright.

`requiredSigners` in `node/signers.go` encodes both rules. The bound is enforced
in three places, deliberately redundant:

| Layer | Location |
|---|---|
| Selection (initiator) | `requiredSigners`, `node/signers.go` |
| Coord boundary (participant) | `checkSignerSet`, `node/coord.go` |
| KMS (authoritative) | `EcdsaSession::start`, `kms-tss/src/ecdsa_session.rs` |

Covered by `TestRequiredSigners`, `TestCheckSignerSet`, and the
`test_ecdsa_t*` cases in `kms-tss/src/session.rs`.

### What this costs in fault tolerance

ECDSA spare capacity is `N - (2T-1)`. Odd `N` therefore always yields an *even*
number of spares — there is no configuration of 7 nodes that tolerates exactly
one being down. Exactly one spare requires even `N` with `T = N/2`.

| N | T | ECDSA needs | Can be down | Nodes to collude |
|---|---|---|---|---|
| 5 | 2 | 3 | 2 | 2 |
| 5 | 3 | 5 | 0 | 3 |
| 6 | 3 | 5 | 1 | 3 |
| 7 | 3 | 5 | 2 | 3 |
| 7 | 4 | 7 | 0 | 4 |
| 8 | 4 | 7 | 1 | 4 |

`T=5` at `N=7` is impossible: it would need 9 signers.

---

## Liveness

Two signals feed "can this member sign right now", and neither is sufficient
alone:

- **libp2p connectedness** — free and instant, but transport-level only. A peer
  can hold a healthy connection while its KMS socket is dead, ACK the coord
  message, and then never produce a share.
- **`msgPing`** — a coord-protocol probe that round-trips through the peer's
  handler into its key manager via `GetKeyInfo`, so it exercises the whole path
  a signature depends on. `GetKeyInfo` returns `(nil, nil)` for a missing key,
  so a sentinel key ID works and nothing needs to exist. Probes are answered
  only for a group both peers belong to, so the mechanism cannot be used by an
  arbitrary node to enumerate cluster state.

The probe loop runs every 15s alongside `reconnectLoop`. Results feed a per-peer
record: consecutive failures, and an EWMA of round-trip time.

**Unknown peers count as healthy.** A node that has just joined, or one whose
probe results have gone stale (>3 probe intervals), is tried rather than
excluded. Being wrong that way costs one retry; the opposite error can make a
group that could sign refuse to.

**Liveness is a hint, not an oracle.** Ground truth is the attempt. A peer can
die between the probe and the session, so selection is optimistic and the sign
path retries.

---

## Selection

`Node.selectSigners` picks the smallest viable set:

1. Self is always included — this node runs the session locally and, for ECDSA,
   must be `signer_ids[0]` to take the coordinator role.
2. Remaining slots go to the best-ranked members: healthy before unhealthy,
   then lowest smoothed RTT, then party ID for determinism.
3. Unhealthy members are ranked last but stay eligible, so a group with no
   healthy alternative still tries rather than refusing.
4. If the pool cannot reach the required count, the request fails **503** with
   how many were needed versus available.

Ranking by latency matters more than it looks: ECDSA is a 4-round protocol, so
the slowest selected peer's RTT is paid four times per signature. This is also
why concentrating a deployment geographically helps — inter-node latency is
multiplied, client latency is not.

---

## Retry

`runThresholdSign` (shared by `/v1/sign` and `/v1/delegate`) retries up to
`maxSignAttempts` (3) times, excluding parties that failed.

Only **coord-broadcast** failures are retried, because only they identify the
party at fault. `broadcastCoord` now drains every result instead of returning on
the first error, and reports a `coordBroadcastError` naming all failed parties.
A failure inside `RunSign` is not attributable to a peer from the initiator — it
is as likely a bad payload or a local key-manager fault — so retrying would
spend another full round of latency on a request that fails the same way.

Each attempt draws a fresh nonce, hence a fresh session ID and libp2p protocol
ID. Participants stranded by a partial broadcast are therefore never disturbed
by the retry; their sessions lapse on the coord handler's own 30s timeout.

---

## Observability

`GET /debug/stats` reports per-group signing readiness:

```json
{
  "groups": [{
    "group_id": "0x...",
    "threshold": 3,
    "members": 6, "healthy": 5,
    "need_frost": 3, "need_ecdsa": 5,
    "can_sign_frost": true, "can_sign_ecdsa": true,
    "peers": [{"party_id": "16Uiu2H...", "healthy": true, "rtt_ms": 12}]
  }]
}
```

This is what explains a 503 or an unexpected choice of signer set.

---

## Known limits

- **Mid-session dropout is not recovered.** Selection and retry cover a peer
  that is down *before* the session starts. A peer that dies mid-protocol fails
  the session; the request returns 500 and the caller retries. The ECDSA round
  logic waits for all `n` selected signers and aborts on inconsistency, so there
  is no partial-completion path to salvage.
- **`RunSign` failures are not attributed.** See above — no peer-level retry.
- **Stranded participant sessions hold a slot for up to 30s** after a partial
  broadcast. There is no explicit abort message; `AbortSession` exists on the
  KMS but is not wired to a coord message. Worth adding if stress testing shows
  slot exhaustion.
- **Keygen and reshare still use the full committee**, correctly — DKG needs
  every member to hold a share.
