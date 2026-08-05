# Testnet Redeploy Checklist

Code-only redeploy to the **existing** 4-node Sepolia testnet. Key shards
survive; no wipe, no re-keygen, no new group.

For standing up a *fresh* testnet instead, see `README.md` — that path wipes
state and is the right moment to enable at-rest encryption (see §7).

---

## 0. Why this is wipe-free

Verified across the four layers that can force a wipe:

| Layer | Change since deployed build | Verdict |
|---|---|---|
| Contracts | Resolver state appended above gap, `[50]`→`[46]` (4 slots) | Beacon-upgrade safe; groups keep address + state |
| Coord wire | New CBOR keys 18–21, all `omitempty`; no strict decoding | Additive |
| Namespacing | `resolver:` added; `oauth:`/`authkey:` untouched | Additive |
| KMS storage | At-rest encryption gated on `SIGNET_KMS_KEY`, never set here | Same plaintext sled store |

`proto/keymanager.proto` is unchanged since the deployed build, so the
signetd↔KMS interface is stable.

**The one rule:** stop all nodes before deploying (§4). `a420f5f` changed what
the scoped-sign payload signature covers and `4c720c7` binds protocol `From` to
the authenticated peer, so a new participant rejects an old initiator's
messages. A rolling restart produces a mixed-version window; a coordinated one
does not.

---

## 1. Decide what you're deploying

- [ ] Merge PR #5, or accept deploying from `feat/onchain-auth-resolver`.
      Deploying an unmerged branch works but leaves no clean "what's running"
      answer later.
- [ ] Record the commit SHA you deploy — nothing in the repo tracks it today
      (see §8).

## 2. Pre-flight

- [ ] `go test ./...` green
- [ ] `cd contracts && forge test` green (85 tests)
- [ ] `echo $SEPOLIA_RPC_URL` — set
- [ ] `echo $FACTORY_ADDRESS` — set
- [ ] `echo $SIGNET_SSH_KEY` — set (or `~/.ssh/signet-testnet.pem` exists;
      `signet-testnet1` uses `~/.ssh/signet-testnet-gcp`)
- [ ] `testnet/ansible/inventory.yml` IPs current (gitignored, local only)
- [ ] `testnet/ansible/host_vars/*.yml` populated with `peer_id`,
      `eth_privkey`, `local_node_key_path`
- [ ] **`SIGNET_KMS_KEY` is NOT set** anywhere in the environment or ansible
      vars. Setting it makes the new KMS unable to read existing plaintext
      shards — there is no migration path.
- [ ] Sibling repo `../signet-circuits/toolchain.json` present — the `bb` role
      reads the pinned bb version from it and fails without it.

```bash
cd testnet/ansible
ansible -m ping signet_nodes          # all 4 reachable
ansible-playbook manage.yml -e action=status
```

## 3. Build

`deploy.yml` uploads `build/signetd-linux-amd64`. The currently-deployed May 21
binary sits at that exact path and is your rollback copy, so build to
`.staged` first and swap deliberately:

```bash
# From repo root. Go binary is the only mandatory rebuild.
GOOS=linux GOARCH=amd64 go build -o build/signetd-linux-amd64.staged ./cmd/signetd

# Keep the running build as the rollback copy, then promote the new one.
cp build/signetd-linux-amd64 build/signetd-linux-amd64.rollback
mv build/signetd-linux-amd64.staged build/signetd-linux-amd64
```

⚠️ Running `deploy.yml` before that `mv` redeploys the **old** May 21 binary —
a silent no-op that looks like a successful deploy.

KMS rebuild is **optional this round** — the proto is unchanged and the only
KMS source change since the deployed build is at-rest encryption, which stays
off. Skipping it also avoids the Docker dependency. To rebuild anyway:

```bash
# Requires Docker running.
cd kms-tss && cross build --release --target x86_64-unknown-linux-gnu
cp target/x86_64-unknown-linux-gnu/release/kms-tss ../build/kms-tss-linux-amd64
```

- [ ] `build/signetd-linux-amd64` freshly built
- [ ] Previous binary kept for rollback (§6)

## 4. Back up before touching anything

There is no backup mechanism (`docs/PRODUCTION-GAPS.md`). Node data loss below
threshold is permanent key loss, so snapshot first:

```bash
cd testnet/ansible
ansible signet_nodes -b -m shell -a \
  'tar czf /root/signet-backup-$(date +%F-%H%M).tgz /opt/signet/data /opt/signet/kms-data'
ansible signet_nodes -b -m shell -a 'ls -la /root/signet-backup-*.tgz'
```

- [ ] Snapshot taken on all 4 nodes, sizes look sane (non-empty)

## 5. Deploy

Stop everything first — this is what avoids the mixed-version window. Ansible
runs hosts in parallel (4 hosts, default forks 5), so all four go down together.

```bash
cd testnet/ansible
ansible-playbook manage.yml -e action=stop
ansible-playbook deploy.yml                 # use_kms=true comes from group_vars
```

`deploy.yml` uploads the binary + config, installs the systemd unit, and starts
services. Handler order is correct: the `kms-tss` role is applied before
`signetd`, so its restart handler fires first.

- [ ] `manage.yml -e action=stop` completed on all 4
- [ ] `deploy.yml` completed with no failed tasks

⚠️ Never run `manage.yml -e action=clean` here — it deletes the data directory.

## 6. Verify

```bash
ansible-playbook manage.yml -e action=status
ansible-playbook manage.yml -e action=logs
```

Per node (`API_PORT` 8080):

```bash
for ip in 54.90.227.156 44.214.181.89 44.205.254.164 136.119.229.55; do
  echo "--- $ip"; curl -s --max-time 5 "http://$ip:8080/v1/health"
  curl -s --max-time 5 "http://$ip:8080/v1/info"
done
```

- [ ] All 4 healthy

Listing keys needs admin credentials — it is `POST /admin/keys` with an
`AdminAuth` ECDSA signature from a group-trusted authorization key, not an
unauthenticated `GET /v1/keys` (CLAUDE.md is stale on this). Without a
credential to hand, confirm shards survived via startup logs instead:

```bash
ansible signet_nodes -b -m shell -a \
  'journalctl -u signetd --since "5 min ago" | grep -E "loaded group|keyshard|threshold"'
```

- [ ] Startup logs show groups loaded with expected member + threshold counts
- [ ] Logs show `chain: loading groups` with the expected member + threshold count
- [ ] Logs show no `chain: poll error` / `getAuthResolver` warnings beyond the
      expected debug line (old group impl has no `getAuthResolver`)
- [ ] A test sign against an existing key succeeds
- [ ] Alchemy dashboard: request rate drops ~9x over the next hour
      (60s poll, one `eth_getLogs` per tick instead of one per group)

## 7. Rollback

```bash
cd testnet/ansible
ansible-playbook manage.yml -e action=stop
# Restore binary + data from the §4 snapshot, then:
ansible-playbook manage.yml -e action=start
```

- [ ] Rollback path confirmed before starting (know which backup file, which
      previous binary)

## 8. Optional: contract beacon upgrade

Not required for the node deploy. Needed only to exercise the on-chain auth
resolver (`queueAuthResolver` does not exist on the deployed implementation) or
to pick up H3 (quorum-breaking removal block).

- [ ] Deploy new `SignetGroup` implementation
- [ ] `UpgradeableBeacon.upgradeTo(newImpl)` from the factory owner
- [ ] Binding a resolver is timelocked by the group's `removalDelay` —
      `queueAuthResolver` → wait → `executeAuthResolver`
- [ ] Add `siwe_domain` to `config.yaml.j2` — **without it the node rejects the
      `onchain_resolver` scheme outright** (`node/config.go`: "If empty, the
      onchain_resolver scheme is rejected"). The template sets neither
      `siwe_domain` nor `chain_rpcs` today, so the scheme stays inert even
      after the beacon upgrade.
- [ ] Add `chain_rpcs` if the resolver lives on a chain other than Sepolia

## 9. Follow-ups this exposed

- No CI (`.github/workflows/` does not exist) — nothing verifies a PR server-side
- No deployed-version record — consider having `deploy.yml` write the commit SHA
  to `/opt/signet/VERSION` and exposing it from `/v1/info`
- `roles/bb/tasks/main.yml` header comment says bb is "symlinked" to
  `/usr/local/bin`; the task actually copies it (correct — a symlink breaks the
  CRS cache). Comment is stale.
- Rate limiting on `/v1/auth` before any public exposure (R-6 / audit M2)
