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
| `gen-auth-key` | **manager (SFLuv)** | the group's authorization key |
| `create-group` | **manager (SFLuv)** | manager key only — member addresses are public |
| `accept` | **each org** | that org's operator key, its nodes only |
| `deploy.yml` | **each org** | that org's `host_vars`, `--limit` to own nodes |

The only file crossing organisational boundaries is `manifest-<org>.json`:
name, org, `peer_id`, `eth_address`, `pubkey`. `init-alpha.sh` greps its own
output for secret field names and refuses to write a manifest that contains any.

---

## Prerequisites, per operator

- Own machine, own cloud account, own SSH keypair. Not shared.
- **One SSH key per cloud, not per operator.** OLL spans AWS and Vultr, and the
  Vultr deploy may run from a different machine, so a single key across
  providers would let one compromised laptop reach every node:

  ```bash
  ssh-keygen -t ed25519 -f ~/.ssh/signet-alpha-aws   -C signet-alpha-aws
  ssh-keygen -t ed25519 -f ~/.ssh/signet-alpha-vultr -C signet-alpha-vultr
  ssh-keygen -t ed25519 -f ~/.ssh/signet-alpha-gcp   -C signet-alpha-gcp
  ```

  Each provisioner imports its own, and `build-inventory.sh` resolves
  `ansible_ssh_private_key_file` per host from `.clouds-alpha`. Override with
  `ALPHA_SSH_KEY_<org>_<cloud>`, or `ALPHA_SSH_KEY_<org>` for one key across an
  org's clouds.
- `go`, `jq`, `openssl`, `ansible`, Foundry
- The collection for each cloud you run, and its credentials:

  | Cloud | Collection | Credentials |
  |---|---|---|
  | AWS | `amazon.aws` (+ `boto3`, and `botocore[crt]` — see below) | `aws login` / profile |
  | GCP | `google.cloud` (+ `pip3 install google-auth requests`) | `gcloud auth application-default login` |
  | Vultr | `vultr.cloud` | `export VULTR_API_KEY=...` |
- `../signet-circuits` cloned as a sibling — the `bb` role reads its
  `toolchain.json` and fails without it

> **`aws login` needs `botocore[crt]` for Ansible.** The AWS CLI bundles its own
> dependencies, so `aws sts get-caller-identity` succeeds while every
> `amazon.aws` task fails with:
>
> ```
> Couldn't connect to AWS: Missing Dependency: Using the login credential
> provider requires an additional dependency.
> ```
>
> Install it into the interpreter Ansible actually uses (`ansible --version`
> prints it — a Homebrew install has its own venv, not your system Python):
>
> ```bash
> "$(ansible --version | sed -n 's/.*(\(.*python\))/\1/p')" -m pip install "botocore[crt]"
> ```
>
> Alternatively skip the dependency by handing Ansible static credentials:
> `eval "$(aws configure export-credentials --format env)"`. Those are the same
> temporary credentials and expire with the session.
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
export ADMIN_ADDRESS=0x...        # COLD. Must not be the deployer.
testnet/scripts/alpha-contracts.sh deploy-factory
```

**`ADMIN_ADDRESS` is not the deploy key, and the script refuses if it is.**
`DEPLOYER_PK` is hot by construction — it sits in a shell for the length of the
install and signs from a laptop. The factory owner holds standing power for the
lifetime of the deployment: `upgradeGroupImplementation` swaps the
`SignetGroup` logic behind **every** group through the shared beacon, so it can
rewrite auth and membership rules under groups it does not manage, and
`_authorizeUpgrade` lets it replace the factory itself.

Set it correctly at deploy rather than transferring later. The factory uses OZ
v5 `OwnableUpgradeable`, which is **single-step** — `transferOwnership` has no
acceptance leg, so one wrong address permanently loses the factory and the
beacon with it, and no group could ever be upgraded again. Use a hardware
wallet or a multisig. `ALLOW_HOT_ADMIN=yes` overrides for a throwaway devnet.

After `fund`, the deployer key has no standing power at all — everything from
that point is the manager's or the operators'.

On mainnet (`CHAIN_ID=1`) each phase additionally prompts for confirmation
before spending; set `MAINNET_CONFIRMED=yes` to skip that in automation.

Share the printed `CHAIN_ID` and `FACTORY_ADDRESS`. Note that whoever holds `DEPLOYER_PK` owns
the factory and the `UpgradeableBeacon`, and can upgrade the `SignetGroup`
implementation under every group. That is a standing power, not a one-time one.

**3b. Deployer funds every node and every operator** (public addresses only,
skips already-funded). Operators need gas too: with closed nodes it is the
operator that sends `acceptInvite`, one transaction per node, and an unfunded
operator leaves every member stuck in Pending:

```bash
export FACTORY_ADDRESS=0x...
testnet/scripts/alpha-contracts.sh fund
```

**3c. Each operator registers its own nodes:**

```bash
export ETH_RPC_URL=... CHAIN_ID=11155111 FACTORY_ADDRESS=0x...
ALPHA_ORG=oll ALPHA_OPERATOR=0x<address this org controls> \
  testnet/scripts/alpha-contracts.sh register
```

Signed with your node keys. Re-runnable; already-registered nodes are skipped.

**An operator address is required.** It is what makes several nodes one
organisation on-chain, and `SignetGroup` checks it for every consent action —
`acceptInvite`, `declineInvite` and `queueRemoval` all require `msg.sender` to
be the node's effective operator (`SignetGroup.sol:150,159,167`). Unset, the
factory falls back to treating each node as its own operator, so every consent
action needs that individual node's key and nothing records the grouping.

`ALPHA_OPERATOR` here overrides whatever `init-alpha.sh` recorded, so a missing
or wrong operator is fixable without regenerating identities. It is also
changeable on-chain later via `setOperator`, so it is not a one-way door.
`ALPHA_NO_OPERATOR=yes` registers without one deliberately.

Treat the operator address as a control key, not a hot one: it authorises
joining and leaving groups on behalf of every node in the org.

**Nodes register closed (`isOpen=false`).** An open node is added to *any*
group the moment its manager names it — `inviteNode` skips Pending and
activates it outright (`SignetGroup.sol:139`). A stranger could create a group
naming your nodes, and they would run DKG and hold shards for it, on your
hardware, without you agreeing. Closed means the node lands in Pending until
its operator accepts, which is the consent step the invite lifecycle exists
for. `ALPHA_OPEN_NODES=yes` overrides; `updateOpenStatus` changes it later.

**3d. The manager mints the authorization key** (SFLuv, not the deployer —
`addAuthKey` is `onlyManager`, and the key authorizes operations on SFLuv's own
keys, so OLL should never hold it):

```bash
testnet/scripts/alpha-contracts.sh gen-auth-key harness
```

This is not optional bookkeeping. A group created with no issuers, no auth keys
and no resolver has **no auth policy**, and the node then skips authentication
entirely (`node/handlers.go:1280`):

```go
if !n.auth.HasAuthPolicy(groupID) { return keyID, nil, true }
```

So a policy-less group serves `/v1/keygen` and `/v1/sign` to anyone who can
reach the port — which after Phase 4 is the public internet. TLS and rate
limiting would be guarding an unlocked door. `create-group` refuses to create
such a group unless you set `ALPHA_OPEN_GROUP=yes` deliberately.

The on-chain form is 34 bytes: a scheme prefix (`0x00` = secp256k1 ECDSA,
`node/auth.go:28`) followed by the 33-byte compressed pubkey. `SignetGroup` does
not validate the length, and the node compares the bytes verbatim against the
certificate's `auth_key_pub`, so a malformed key surfaces only as a 401 much
later. The script builds and checks it for you.

`testnet/data/auth-key-harness.json` is written `0600` and holds the private
key — the credential that authorizes every operation on the group. To trust a
key held elsewhere instead, skip this phase and pass
`ALPHA_AUTH_KEY_PUB=0x<34 bytes>` to `create-group`.

**3e. The manager creates the group**, once everyone has registered:

```bash
export MANAGER_PK=0x...            # SFLuv's key — becomes the group manager
testnet/scripts/alpha-contracts.sh create-group 3
```

`createGroup` is permissionless and makes `msg.sender` the manager
(`SignetFactory.sol:135`), so the key that sends it owns the group. `MANAGER_PK`
keeps that separate from `DEPLOYER_PK`; passing only `DEPLOYER_PK` still works
for a single-party devnet but prints a notice.

**The threshold is immutable.** `initialize` sets it and there is no setter;
`executeRemoval` refuses to drop the active set below it, because doing so would
brick every key in the group permanently. `threshold <= nodeAddrs.length` is
also checked at creation, so creating the group before all members are
registered permanently caps how high `T` can ever go. Register all six first.

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

**3f. Each operator accepts its invitations:**

```bash
export FACTORY_ADDRESS=0x... GROUP_ADDRESS=0x...
ALPHA_ORG=oll OPERATOR_PK=0x<operator key> \
  testnet/scripts/alpha-contracts.sh accept
```

Because nodes are closed, `create-group` leaves **every member Pending and none
Active** — `isOperational()` is false and no keygen is possible until the
operators accept. That is not a failure state, it is the consent step:

```
  active:  []
  pending: 6 node(s)
  operational: false
```

`acceptInvite` must be signed by the address recorded as the node's operator
(`SignetGroup.sol:150`), so this needs `OPERATOR_PK` — the key for the address
you passed at registration, funded in 3b. The script checks the on-chain
operator per node first, so a wrong key names the mismatch instead of producing
a bare revert. Re-runnable; already-active nodes are skipped.

It reports progress toward the threshold as it goes, so you can see when the
group crosses into operational:

```
==> Accepted 4. Group now has 4 active member(s), threshold 3.
```

**3g. Build the harness env file** (anyone, once the group exists and all the
`.hosts-alpha` fragments are merged):

```bash
testnet/scripts/alpha-contracts.sh write-env
```

Writes `testnet/.env-alpha` (`0600`) from `testnet/data/factory.env` plus every
`manifest-*.json` — this is the file Phase 6 runs against. It carries
`HARNESS_AUTH_KEY` when an auth key exists, which is what lets the harness past
the 401 the auth policy now produces. It prefers each
node's TLS hostname and only falls back to `http://<ip>:8080`, which it marks
`INSECURE` and warns about, because a cleartext endpoint leaks delegation
tokens. A `FILL_IP` in the output means a manifest arrived without a hostname
and that node's address is missing from the merged fragments.

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

**The deploy rolls one node at a time** (`serial: 1`), so it is slower than it
looks like it should be — each node is restarted and health-checked before the
next is touched, and the group keeps signing throughout. That bound is
`N-(2T-1)`: ECDSA needs `2T-1 = 5` signers, so six nodes at `T=3` tolerate
exactly one being down. Two at once stops the payment path until the first
returns.

Note `--forks` does not do this. It caps how many hosts run a single task
concurrently, while the play still advances task-by-task across the batch — so
every node would have signetd stopped before any reached its health check.
Override deliberately when nothing depends on the group, such as the initial
stand-up: `-e deploy_serial=4`.

At-rest encryption is on by default (`kms_at_rest_encryption: true`). The KEK
lands in `/etc/signet/secrets/kms.env` mode 0640, referenced by an
`EnvironmentFile` with no leading `-`, so a missing file fails the unit rather
than silently starting a **plaintext** store.

TLS is on by default too (`use_tls: true`), which changes the shape of the
deploy: signetd binds `127.0.0.1:8080` and Caddy serves 443 in front of it. Set
`tls_email` (the ACME account contact) in **`group_vars/org_<name>.yml`**, not
in `group_vars/signet_nodes.yml` — that file applies to the whole fleet, and
Caddy creates the ACME account per contact address, so a value there would put
one operator's address on another's certificates and send them the expiry
warnings for hosts they do not run. `org_<name>` is a child of `signet_nodes`
in the generated inventory, so the per-operator value wins. Left unset the role
asserts, which is the intended failure: better a refused deploy than a
certificate issued under someone else's account.

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

After a coordinated deploy, confirm the whole fleet is actually on the same
build. Operators hold no SSH access to each other's nodes — deliberately — so
`/v1/info` is the only way to check this without asking and taking the answer on
trust:

```bash
for h in oll1.nodes.oleary.com oll2.nodes.oleary.com \
         oll3.nodes.oleary.com oll4.nodes.oleary.com \
         sfluv1.nodes.sfluv.org sfluv2.nodes.sfluv.org; do
  printf "%-26s " "$h"
  curl -s --max-time 5 "https://$h/v1/info" \
    | jq -r '"\(.version)  \(.binary_sha256[0:16])"'
done
```

Every row should match. `binary_sha256` is the sha256 of the running executable,
so it also equals `sha256sum` of the artifact you built — worth comparing
against your local `build/signetd-linux-amd64` after a deploy.

A `-dirty` suffix on the version means that node was built from a modified
working tree, so it corresponds to no commit and a version match with another
node would be a false match.

Two things this is not. It is **not attestation**: a node reports whatever its
binary says, so it answers "are we running the same code?" between cooperating
operators, not "prove you are honest". And because `/v1/info` is
unauthenticated, it discloses the running version publicly — the alternative
would require a shared credential between operators, which is exactly the
coupling the design avoids.

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

## Phase 7 — Upgrading the group implementation

Applies to any change to `SignetGroup.sol` after the group exists. Written
against the SIWE domain change (`862b2cf`), which is the first one.

### What makes this different from a deploy

`SignetGroup` sits behind a `BeaconProxy`. The proxy holds the state; the
implementation supplies only code. So an upgrade does not migrate anything — it
**reinterprets live storage in place**, for every group behind the beacon, in a
single transaction. Get the layout wrong and there is no failed transaction to
notice: the upgrade succeeds and the data quietly means something else.

Two consequences worth internalising before touching anything:

- **There is no per-group rollout.** `upgradeGroupImplementation` swaps the logic
  under *every* group at once, including groups other organisations manage.
  Today sfluv's is the only group, so "upgrade sfluv's group" and "upgrade every
  group" are the same act. That stops being true the moment there is a second.
- **Unit tests cannot verify it.** They build their state with the *new*
  contract. The only state that proves anything was written by the *old* one, and
  it exists in exactly one place. Hence the fork rehearsal below, which is not
  optional.

### Who can do what

| Action | Address | Notes |
|---|---|---|
| Deploy the implementation | anyone with gas | Permissionless. Deploying is not adopting. |
| `upgradeGroupImplementation` | **factory owner** `0x180E9a32…` | Cold. The only address that can. |
| `queueSiweDomains` | **group manager** `0x762F9681…` | Cannot upgrade anything. |
| `executeSiweDomains` | anyone with gas | Permissionless, mirroring `executeRemoval`. |

**The manager cannot perform the upgrade.** `upgradeGroupImplementation` is
`onlyOwner` on the factory, the beacon's owner *is* the factory, and the
factory's owner is the cold key. There is no manager path to it, by design —
that separation is the reason `deploy-factory` refuses to make the deploy key the
admin.

### 0. Fund the cold key first

`0x180E9a32…` has been used exactly once, to be set as owner at deploy, and
**holds no ETH**. It cannot send the upgrade transaction as it stands. Send it
gas before the ceremony, not during it.

Measured on a fork of live state:

| Step | Gas | Signer |
|---|---:|---|
| Deploy implementation | 4,557,923 | deployer (anyone) |
| `upgradeGroupImplementation` | 45,590 | cold owner |
| `queueSiweDomains(["app.sfluv.org"])` | 135,509 | manager |
| `executeSiweDomains()` | 99,574 | anyone |

The deploy dominates by two orders of magnitude. Total cost is entirely a
function of gas price on the day — at 1 gwei the whole sequence is ~0.005 ETH,
at 30 gwei ~0.14 ETH. Check `cast gas-price` rather than budgeting from a figure
written here.

### 1. Rehearse against a fork — every time

```bash
ETH_RPC_URL=<archive-capable RPC> testnet/scripts/rehearse-upgrade.sh
```

Forks the live chain into anvil, confirms it is running the *old* implementation,
then drives the real phase scripts through deploy → upgrade → queue → timelock →
execute against a copy of real group state. It asserts that members, threshold,
quorum, manager, auth keys and operational status all read back identically, and
that the new fields start empty rather than inheriting whatever those slots held.

It aborts if the forked chain already has the upgrade, because that run would go
green while testing nothing.

**Use an RPC that serves archive requests.** `ethereum-rpc.publicnode.com` works
only at `latest` and rejects a pinned `FORK_BLOCK` with "Archive requests require
a personal token", which makes runs racy. Alchemy — what the nodes already use —
is the better source here.

### 2. Check the layout

```bash
testnet/scripts/alpha-contracts.sh check-layout
```

Compares the working tree against `contracts/storage-layout-baseline.tsv`, which
records the layout that is **deployed** — not what is in the source. New state
may only come from the head of `__gap`, and the total footprint must not move.

It runs `forge clean` first, deliberately. `forge inspect … storage` reads a
cached artifact and the layout is not in the default output selection, so a tree
built by an ordinary `forge build` either fails outright or, worse in principle,
answers from a build that is not the one being deployed. The rebuild is the price
of the check meaning anything.

### 3. Deploy the implementation

```bash
export ETH_RPC_URL=<RPC> CHAIN_ID=1
DEPLOYER_PK=0x... FACTORY_ADDRESS=0x86EB99… \
  testnet/scripts/alpha-contracts.sh deploy-group-impl
```

Runs `check-layout` first and refuses to proceed if it fails. Nothing is upgraded
by this — the beacon still serves the old implementation and every group is
untouched.

The address is CREATE2-derived from the init code alone, so it does not depend on
which key deployed it. Give the cold signer both the address and the init-code
hash: they can rebuild this source and confirm the address holds the code they
think it does, rather than taking the deployer's word for it.

### 4. The cold key signs

```bash
FACTORY_ADDRESS=0x86EB99… GROUP_ADDRESS=0x86fe2814… GROUP_IMPL=0x<new> \
  testnet/scripts/alpha-contracts.sh upgrade-beacon
```

Prints the exact transaction and stops. It verifies the target has code — an
address with none is accepted by the beacon and bricks every group behind it,
with every call returning success and empty data — and checks that the slots the
new implementation claims are still zero on `GROUP_ADDRESS`.

That last check sees only the group it was given. It cannot speak for groups it
does not know about.

Then, on the machine holding the key:

```bash
cast send --ledger --rpc-url "$ETH_RPC_URL" \
  0x86EB99… 'upgradeGroupImplementation(address)' 0x<new>
```

The phase refuses to send this itself on chain 1 even if `ADMIN_PK` is set. A
cold key read out of a shell to save a step is not cold.

Confirm, from any key:

```bash
cast call 0xE37C3768… 'implementation()(address)' --rpc-url "$ETH_RPC_URL"
```

### 5. Re-baseline immediately

```bash
testnet/scripts/alpha-contracts.sh check-layout --write-baseline
```

Then edit the provenance header in `contracts/storage-layout-baseline.tsv` with
the new implementation address. Do this while it is true — the file's whole value
is that it describes what is deployed, and a stale one silently approves the next
upgrade against the wrong layout.

### 6. Set the SIWE domains

```bash
export GROUP_ADDRESS=0x86fe2814…
MANAGER_PK=0x... testnet/scripts/alpha-contracts.sh siwe-domains queue app.sfluv.org
# wait removalDelay (600s on this group), then:
MANAGER_PK=0x... testnet/scripts/alpha-contracts.sh siwe-domains execute
testnet/scripts/alpha-contracts.sh siwe-domains show
```

`queue` takes the **complete future list**, not a delta — it replaces the list
wholesale. Passing one domain to a group that already trusts three removes the
other two.

An empty list disables the `onchain_resolver` scheme for the group. Empty never
means "any domain".

### 7. Roll the nodes

Only after the above. The node reads the domain list from the group contract and
`siwe_domain` is gone from node config entirely — no fallback, no deprecation
period.

Ordering is not delicate here, because SIWE is unused today and empty already
meant disabled: a new node against an old contract sees the call revert and
treats it as an empty list, which disables the scheme rather than opening it. An
old node never calls it at all. So there is no window in which anything
regresses, in either order.

Nodes pick up an executed change on their next chain poll — `chain_poll_secs`,
default 60s.

---

## Identity escrow (what it covers, and what it does not)

Each operator is expected to hold an encrypted escrow copy of its own node
identity material, independently of this repo and of the deploy machine.

**Where it lives, and what it is called, belongs in each operator's internal ops
notes — not here.** This document is public. Naming the store, the item, or the
file layout would publish a target list and tell a reader exactly what a given
compromise is worth, which is a meaningful advantage handed over for no
operational benefit. What is worth stating publicly is the *shape* of the
requirement and, more importantly, its limits.

### Custody requirement

The escrow copy and the credential that opens it must have **separate custody**.
Together they reconstruct an operator's node identities; apart, neither is worth
much. Storing them in one place collapses two factors into one and is the single
most likely way this arrangement fails.

The same rule applies across operators: at `T=3` over six nodes, some operators
clear the threshold alone, so escrow copies must never be aggregated into a
shared store. See `docs/DESIGN-BACKUP-RECOVERY.md` §1.

### What escrow does NOT cover

**It is not a backup of the alpha, and reading it as one is the mistake this
section exists to prevent.** Identity escrow holds no key shards — the KMS sled
store is not in it, because `ExportShards`
(`docs/DESIGN-BACKUP-RECOVERY.md` §4.1) is designed but not built. Restoring
from escrow rebuilds a node with its original identity and on-chain registration
and an **empty key store**.

Losing more than `N-T` nodes at once is still permanent key loss. For the common
case — up to `N-T` lost — the recovery path is **reshare to a replacement**,
which needs neither an escrow copy nor the dead node's KEK, and which gives the
new node a share at the current generation. Escrow is for the case where reshare
is not available.

What escrow actually buys: a rebuilt node keeps its peer ID, so its
`SignetFactory` registration is not orphaned. Without it, a replacement gets a
new peer ID and must re-register on mainnet (real ETH) and be re-accepted into
the group.

### Verifying a copy

Verify **currency**, not just integrity. A copy can pass its own checksums
perfectly and still be stale — one taken before a KEK rotation restores a node
that cannot read its own store, which is the failure that looks like success.
Integrity checks catch corruption; only comparison against the live files
catches staleness. Do both, and delete any extracted copy afterwards.

Staleness conditions are narrow and worth knowing, because they bound how often
this needs redoing: regenerating node identities (`init-alpha.sh`), rotating a
KEK, or changing the vault password. Keygen, signing and reshare do **not** touch
this material, so ordinary operation never invalidates an escrow copy.

Each operator verifies its own and records the date in its own ops notes. SFLuv's
was last verified 2026-09-01, current against the live files.

---

## Teardown

Each operator tears down its own:

```bash
ansible-playbook teardown-alpha.yml                              # OLL, AWS
ansible-playbook teardown-vultr.yml                              # OLL, Vultr
ansible-playbook teardown-gcp-alpha.yml -e gcp_project=<id>      # SFLuv, GCP
```

All three prompt before destroying, because destroying an instance destroys its
key shard and there is no shard backup. Identity escrow does NOT cover this — it
restores a node's identity, not its key material. See §"Identity escrow".

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
- **No shard backup** (`docs/PRODUCTION-GAPS.md`). Losing more than `N-T` nodes
  is permanent key loss. Identity is escrowed (§"Identity escrow"); key
  material is not, and the two are easy to confuse in the direction that gets
  you hurt.
- **Tier 1 reshare is unrehearsed.** It is the recovery path for every routine
  failure and the only one that works today, and node replacement has never been
  exercised on the alpha (`docs/DESIGN-BACKUP-RECOVERY.md` §7).
- **No CI.** Nothing verifies a PR server-side; the repo is not `gofmt`-clean.
- **Rate limiting is per node, not per group.** Caddy counts per client IP on
  each machine independently, so a caller spread across six nodes gets six times
  the quota, and one behind a shared NAT is throttled on behalf of everyone
  sharing it. Adequate for the alpha; not a substitute for per-identity limits.
- **Mid-session dropout is not recovered** — see
  `docs/DESIGN-SIGNER-SELECTION.md`.
