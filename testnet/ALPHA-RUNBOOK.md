# Alpha Stand-Up Runbook (multi-operator)

Standing up the alpha across two or more independent operators, where **no
operator ever holds another's private key material**.

Assumed here: **O'Leary Labs** (2 AWS + 2 Vultr) and **SFLuv** (2 GCP) — six
nodes at `T=3`. A third operator slots in by repeating a column with its own
org name; nothing below is specific to two.

| Org | Nodes | Cloud | Region |
|---|---|---|---|
| OLL | oll1, oll2 | AWS | us-west-1, us-west-2 |
| OLL | oll3, oll4 | Vultr | sjc, lax |
| SFLuv | sfluv1, sfluv2 | GCP | us-west1-a, us-west2-a |

`T=3` over six nodes: FROST needs 3 signers, ECDSA needs `2T-1 = 5`, so **one
node may be down**.

At this split OLL's four clear the threshold alone and SFLuv's two cannot.

### On topology being a choice

Signet does not constrain how shards are distributed across operators, and
deliberately so. A customer picks its own topology: nodes from several
independent operators, or several nodes from one — whatever it judges
appropriate — and it can change that later by resharding. Nothing in the
protocol enforces a spread, and `create-group` reports the distribution rather
than refusing any particular one.

The usual arrangement is that node operators are professional infrastructure
outfits and the customer runs nothing at all. Here SFLuv runs two nodes because
there is currently only one other operator, so its participation is what adds
diversity even though two shards is below `T=3`. The direction of travel is
more independent operators holding fewer shards each — ultimately one shard per
operator — at which point no operator reaches a threshold by itself as a
consequence of the topology rather than a rule.

Note what the ECDSA bound costs here: with one shard per operator, `2T-1`
signers means roughly **2×T operators** are needed to sustain a collusion
threshold of `T` with any spare capacity. FROST would need `T + spares`. That
shapes how many independent operators the network has to recruit for a given
security claim.

### Getting to 2/2/2 later — add before you remove

Committee changes are driven by on-chain membership events: the chain poller
sees an add or remove on the group contract and creates a reshare job
(`node/chain.go:666`). So the migration preserves keys — it is a reshare, not a
re-keygen, and no wipe is involved. `/admin/reshare` is a *refresh* of the same
committee (`handlers.go:949`), not the mechanism for this.

Sequence matters, because ECDSA needs `2T-1 = 5` signers throughout:

| Step | N | ECDSA needs | Result |
|---|---|---|---|
| now | 6 | 5 | 1 spare |
| remove 2 OLL **first** | 4 | 5 | **payments dead** |
| add 2 (third org) first | 8 | 5 | 3 spare |
| then remove 2 OLL | 6 | 5 | 1 spare |

Add the third operator's nodes, let the reshare settle, and only then remove
OLL's two. Doing it the other way round leaves the group unable to produce an
ECDSA signature until the additions land.

Three providers is deliberate — a control-plane or network failure at any one
costs at most the nodes hosted there, which is what makes that one spare node
worth having. Vultr `sjc` (Silicon Valley) is the closest region any of the
three offers to San Francisco; AWS `us-west-1` is Northern California, and
GCP's nearest are Oregon and Los Angeles.

---

## Why the flow is shaped this way

`SignetFactory.registerNode` enforces:

```solidity
require(_pubkeyToAddress(pubkey) == msg.sender, "pubkey does not match sender");
```

A node can only be registered by a transaction signed with **its own key**. The
contract already draws the trust boundary; the old `deploy-contracts.sh` fought
it by holding every node's private key in one `nodes.json` on one machine.
`alpha-contracts.sh` splits into phases so each is run by whoever legitimately
holds what it needs.

| Phase | Who | Private material touched |
|---|---|---|
| `deploy-factory` | deployer (OLL) | `DEPLOYER_PK` |
| `init-alpha.sh` | **each org** | that org's node keys, KEKs, passphrases |
| `fund` | deployer (OLL) | `DEPLOYER_PK` only — node addresses are public |
| `register` | **each org** | that org's node keys, its nodes only |
| `create-group` | deployer (OLL) | `DEPLOYER_PK` only — member addresses are public |
| `deploy.yml` | **each org** | that org's `host_vars`, `--limit` to own nodes |

The only file crossing organisational boundaries is `manifest-<org>.json`:
name, org, `peer_id`, `eth_address`, `pubkey`. `init-alpha.sh` greps its own
output for secret field names and refuses to write a manifest that contains any.

---

## Prerequisites, per operator

- Own machine, own cloud account, own SSH keypair. Not shared.
- `go`, `jq`, `openssl`, `ansible`, Foundry
- The collection for each cloud you run, and its credentials:

  | Cloud | Collection | Credentials |
  |---|---|---|
  | AWS | `amazon.aws` (+ `pip3 install boto3`) | `aws login` / profile |
  | GCP | `google.cloud` (+ `pip3 install google-auth requests`) | `gcloud auth application-default login` |
  | Vultr | `vultr.cloud` | `export VULTR_API_KEY=...` |
- `../signet-circuits` cloned as a sibling — the `bb` role reads its
  `toolchain.json` and fails without it
- Agreement on: node names, node count per org, and the threshold

Only the deployer needs `DEPLOYER_PK` funded with Sepolia ETH.

> **Choose the threshold before Phase 3.** ECDSA needs `2T-1` signers, so a
> group of `N` tolerates `N - (2T-1)` nodes being down. Odd `N` always yields an
> even number of spares. See `docs/DESIGN-SIGNER-SELECTION.md`.

---

## Phase 1 — Identities (each operator, in parallel)

On your own machine, for your own nodes only:

```bash
# O'Leary Labs
ALPHA_ORG=oll ALPHA_DOMAIN=nodes.olearylabs.com \
  ALPHA_OPERATOR=0x<oll-operator-address> \
  ALPHA_NODES="oll1 oll2 oll3 oll4" testnet/scripts/init-alpha.sh

# SFLuv
ALPHA_ORG=sfluv ALPHA_DOMAIN=nodes.sfluv.org \
  ALPHA_OPERATOR=0x<sfluv-operator-address> \
  ALPHA_NODES="sfluv1 sfluv2" testnet/scripts/init-alpha.sh
```

`ALPHA_OPERATOR` is an address the org controls. It is recorded on-chain per
node by `registerNode`, and `SignetGroup` uses it to authorise join and leave
for those nodes (`SignetGroup.sol:149,158,166`). Left unset, the factory treats
each node as its own operator (`SignetFactory.sol:232`) — workable, but then
nothing on-chain records that several nodes belong to one organisation, so a
customer inspecting the group cannot see the concentration.

It is not a one-way door: `setOperator` can change it later. Setting it at
registration just avoids a second transaction per node.

`ALPHA_DOMAIN` names this org's nodes for TLS, and each operator uses a domain
**it** controls. A shared domain would let whoever holds the zone issue
certificates for every other operator's nodes — the same central point the key
split exists to remove. The names go into the manifest so the other operators
and the harness know them.

This generates per-node `node.key` (encrypted — verified against the `SIGNETK1`
magic, aborting rather than shipping a plaintext identity), a per-node KMS KEK,
and a per-node node-key passphrase.

Then, immediately:

```bash
ansible-vault encrypt testnet/ansible/host_vars/*.yml
```

`host_vars/` is gitignored, but gitignored is not encrypted, and an operator
laptop is exactly what got compromised.

**Exchange**: send `testnet/data/manifest-<org>.json` to the other operators and
drop theirs into your own `testnet/data/`.

---

## Phase 2 — Provision (each operator, in parallel)

Each operator provisions its own machines in its own account.

```bash
cd testnet/ansible

# OLL — AWS
ansible-playbook provision-alpha.yml -e ssh_cidr=<your-ip>/32

# OLL — Vultr
export VULTR_API_KEY=...
ansible-playbook provision-vultr.yml -e ssh_cidr=<your-ip>/32

# SFLuv — GCP
ansible-playbook provision-gcp-alpha.yml \
  -e gcp_project=<project-id> -e ssh_cidr=<your-ip>/32
```

`provision-gcp.yml` (singular) is the old single-node playbook for an external
operator joining the testnet; it is left alone. Use `provision-gcp-alpha.yml`.

Each provisioner appends two fragments rather than overwriting, so running
several on one machine accumulates correctly:

- `testnet/.hosts-alpha` — `name=IP`
- `testnet/.clouds-alpha` — `name=cloud`

Merge all operators' fragments into one copy of each and share them. Neither is
secret, and every node needs every other node's address for `bootstrap_peers`.

`.clouds-alpha` is what sets the login user: **Vultr images log in as `root`,
AWS and GCP as `ubuntu`.** Since SFLuv spans two clouds, the user cannot be a
group-level setting — `build-inventory.sh` resolves it per host. Without that
file every host defaults to `ubuntu` and the Vultr nodes silently fail to
connect; the script warns when it is missing.

```bash
testnet/scripts/build-inventory.sh
```

Writes `testnet/ansible/inventory-alpha.yml`: all nodes, grouped `org_<name>`,
with per-host `ansible_user` and `cloud`, and no secrets. Every operator holds
an identical copy. It cross-checks each `peer_id` against your local `host_vars`
and fails on a mismatch, which is how you catch a node that was re-initialised
after its manifest was shared.

Verify before going further:

```bash
ansible-inventory -i inventory-alpha.yml --list \
  | jq -r '._meta.hostvars | to_entries[] | "\(.key) \(.value.cloud) \(.value.ansible_user)"'
ansible -i inventory-alpha.yml signet_nodes --limit org_sfluv --list-hosts
```

### DNS

Once provisioning has produced addresses, each operator points its own records
at its own nodes:

```
sfluv1.nodes.sfluv.org        A   <sfluv1 IP>
...
oll1.nodes.olearylabs.com     A   <oll1 IP>
```

**Do this before Phase 4.** Caddy obtains certificates via the ACME HTTP-01
challenge on port 80, which requires the name to already resolve to the node.
`init-alpha.sh` prints the exact records to create.

---

## Phase 3 — Contracts

Every chain-touching phase requires both `ETH_RPC_URL` and `CHAIN_ID`, and
refuses to act if the RPC reports a different chain than `CHAIN_ID` claims.

That guard is not only about wasted gas. Scoped keys bind a chainId at keygen
time (the `0x03` EIP-712 scope), so a key created against the wrong chain is
silently mis-scoped and fails much later, when a signature is rejected or a
transfer reverts. It also means each operator confirms the chain independently
before registering, rather than assuming its RPC and the deployer's agree.

`SEPOLIA_RPC_URL` still works as a deprecated alias, with a notice.

**3a. Deployer only:**

```bash
export ETH_RPC_URL=https://...
export CHAIN_ID=11155111          # Sepolia; 1 = mainnet
export DEPLOYER_PK=0x...          # fresh key — the old one is compromised
testnet/scripts/alpha-contracts.sh deploy-factory
```

On mainnet (`CHAIN_ID=1`) each phase additionally prompts for confirmation
before spending; set `MAINNET_CONFIRMED=yes` to skip that in automation.

Share the printed `CHAIN_ID` and `FACTORY_ADDRESS`. Note that whoever holds `DEPLOYER_PK` owns
the factory and the `UpgradeableBeacon`, and can upgrade the `SignetGroup`
implementation under every group. That is a standing power, not a one-time one.

**3b. Deployer funds every node** (public addresses only, skips already-funded):

```bash
export FACTORY_ADDRESS=0x...
testnet/scripts/alpha-contracts.sh fund
```

**3c. Each operator registers its own nodes:**

```bash
export ETH_RPC_URL=... CHAIN_ID=11155111 FACTORY_ADDRESS=0x...
ALPHA_ORG=sfluv testnet/scripts/alpha-contracts.sh register
```

Signed with your node keys. Re-runnable; already-registered nodes are skipped.

**3d. Deployer creates the group**, once everyone has registered:

```bash
testnet/scripts/alpha-contracts.sh create-group 3
```

Prints the membership, the resulting FROST/ECDSA signer requirements, how many
nodes may be down, and the shard distribution per operator:

```
  shards per operator
    oll          4 of 6   <- reaches the threshold alone
    sfluv        2 of 6
```

That last part is informational. It refuses only for things that would not
work — an unregistered member, or `N < 2T-1` — never for a distribution it
disapproves of.

---

## Phase 4 — Deploy (each operator, own nodes only)

```bash
GOOS=linux GOARCH=amd64 go build -o build/signetd-linux-amd64 ./cmd/signetd

cd kms-tss && cross build --release --target x86_64-unknown-linux-gnu   # needs Docker
cp target/x86_64-unknown-linux-gnu/release/kms-tss ../build/kms-tss-linux-amd64

# Caddy with the rate-limit plugin. Stock Caddy does not know the `rate_limit`
# directive and would fail to start, so the role asserts this file exists.
go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
GOOS=linux GOARCH=amd64 xcaddy build \
  --with github.com/mholt/caddy-ratelimit --output build/caddy-linux-amd64

cd testnet/ansible
FACTORY_ADDRESS=0x... ETH_RPC_URL=... \
ansible-playbook -i inventory-alpha.yml deploy.yml \
  --limit org_sfluv --ask-vault-pass
```

**`--limit` is not optional.** Without it Ansible targets every host in the
inventory, including the other operator's, which will fail on SSH — but the
intent is that you never even attempt it.

At-rest encryption is on by default (`kms_at_rest_encryption: true`). The KEK
lands in `/etc/signet/secrets/kms.env` mode 0640, referenced by an
`EnvironmentFile` with no leading `-`, so a missing file fails the unit rather
than silently starting a **plaintext** store.

TLS is on by default too (`use_tls: true`), which changes the shape of the
deploy: signetd binds `127.0.0.1:8080` and Caddy serves 443 in front of it. Set
`tls_email` (the ACME account contact) in `group_vars` or the role asserts.

While iterating, point at Let's Encrypt staging — production rate limits are
per registered domain and easy to exhaust across six nodes and repeated
wipe-and-redeploy cycles:

```yaml
acme_ca: "https://acme-staging-v02.api.letsencrypt.org/directory"
```

Staging certificates are not publicly trusted, so pass `-e tls_verify=false`
to skip the role's post-install HTTPS check while using them.

Rate limiting is on by default (`use_rate_limit: true`), per client IP:

| Endpoint | Default / min | Why |
|---|---|---|
| `/v1/auth` | 10 | Shells out to `bb verify` and broadcasts to every member — the most expensive thing an unauthenticated caller can trigger |
| `/v1/keygen` | 10 | Full DKG across the committee |
| `/v1/delegate` | 30 | Threshold-signs a JWT |
| `/v1/keys/*` | 30 | Coordinated across all nodes |
| `/admin/*` | 60 | Already authenticated |
| `/v1/sign` | 120 | Payment hot path — kept generous |
| `/v1/health`, `/v1/info` | unlimited | Monitoring polls them and they do no work |

**The perf harness will trip these.** It drives sustained load from one source
address, and the existing baseline sustained ~20 sign/sec — far above 120/min.
Put the runner's address in `rate_limit_exempt_cidrs` rather than loosening the
limits for everyone:

```yaml
rate_limit_exempt_cidrs:
  - 203.0.113.9/32   # perf harness runner
```

---

## Phase 5 — Verify

```bash
# Over TLS, by name.
for h in oll1.nodes.olearylabs.com oll2.nodes.olearylabs.com \
         oll3.nodes.olearylabs.com oll4.nodes.olearylabs.com \
         sfluv1.nodes.sfluv.org sfluv2.nodes.sfluv.org; do
  printf "%-32s " "$h"; curl -s --max-time 5 "https://$h/v1/health"; echo
done
```

Confirm the cleartext port is genuinely closed — if 8080 still answers from
outside, the TLS termination is decorative:

```bash
for ip in $(cut -d= -f2 testnet/.hosts-alpha); do
  printf "%-16s 8080: " "$ip"
  curl -s --max-time 5 "http://$ip:8080/v1/health" && echo "  <-- REACHABLE, fix the firewall" \
    || echo "closed (expected)"
done
```

Then check signing readiness, which is the new part:

```bash
# /debug/* is blocked at the proxy by default (it reports group membership and
# per-peer health), so read it over an SSH tunnel or widen debug_allow_cidrs.
ssh -L 8080:127.0.0.1:8080 <user>@<node> -N &
curl -s http://127.0.0.1:8080/debug/stats | jq '.groups'
```

```json
{ "threshold": 3, "members": 6, "healthy": 6,
  "need_frost": 3, "need_ecdsa": 5,
  "can_sign_frost": true, "can_sign_ecdsa": true }
```

Confirm at-rest encryption actually engaged — this is the one that fails silently:

```bash
ansible -i inventory-alpha.yml org_sfluv -b -m shell \
  -a 'journalctl -u kms-tss | grep "at-rest encryption"'
```

Must read `at-rest encryption enabled (KEK from SIGNET_KMS_KEY)`. If it says
*disabled*, the store is plaintext and there is no migration path — wipe and
redeploy before the first keygen.

---

## Phase 6 — Test, then wipe

```bash
go build -o build/harness ./cmd/harness
./build/harness -env testnet/.env-alpha correctness
./build/harness -env testnet/.env-alpha perf -concurrency 10 -duration 300s -out testnet/perf-alpha.jsonl
```

Worth testing explicitly, since it is newly real: stop one node and confirm
signing continues.

```bash
ansible-playbook -i inventory-alpha.yml manage.yml -e action=stop --limit oll4
./build/harness -env testnet/.env-alpha correctness
```

Then wipe the stress-test garbage before calling the alpha done. Each operator,
own nodes:

```bash
ansible-playbook -i inventory-alpha.yml wipe-state.yml --limit org_sfluv
ansible-playbook -i inventory-alpha.yml manage.yml -e action=restart --limit org_sfluv
```

`wipe-state.yml` removes the sled store while preserving `node.key`, so peer IDs
and on-chain registrations survive. **Do not use `manage.yml -e action=clean`** —
it deletes the whole data directory, `node.key` included, which changes every
peer ID and orphans the registrations.

Shards live only in the sled store; nonce and session caches are in-memory and
gone on restart; keygen writes nothing on-chain. So the wipe is complete.

---

## Teardown

Each operator tears down its own:

```bash
ansible-playbook teardown-alpha.yml                              # OLL, AWS
ansible-playbook teardown-gcp-alpha.yml -e gcp_project=<id>      # SFLuv, GCP
ansible-playbook teardown-vultr.yml                              # SFLuv, Vultr
```

All three prompt before destroying, because destroying an instance destroys its
key shard and there is no backup mechanism.

`teardown-vultr.yml` finds instances by the `signet-alpha` **tag**, so it
catches nodes dropped from the playbook's `nodes` block. The AWS and GCP
teardowns iterate a declared region/zone list and cannot — an instance in a
region no longer listed survives. That is exactly how the us-west-1 orphan in
commit `0ef0c0a` outlived its playbook. Sweep with:

```bash
testnet/scripts/audit-instances.sh                                   # all AWS regions
gcloud compute instances list --filter="labels.project=signet-alpha"  # all GCP zones
```

## Gaps

- **The old `teardown.yml` only sweeps us-east-1** and covers the retired
  testnet, not the alpha.
- **No backup mechanism** (`docs/PRODUCTION-GAPS.md`). Losing more than `N-T`
  nodes is permanent key loss.
- **No CI.** Nothing verifies a PR server-side; the repo is not `gofmt`-clean.
- **Rate limiting on `/v1/auth`** before any public exposure (audit M2 / R-6).
- **Mid-session dropout is not recovered** — see
  `docs/DESIGN-SIGNER-SELECTION.md`.
