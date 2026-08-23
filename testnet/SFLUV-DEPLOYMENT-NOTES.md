# SFLuv Deployment Notes

Field notes from standing up SFLuv's two GCP nodes for the alpha on
**2026-08-23**. `ALPHA-RUNBOOK.md` is the procedure; this records what the
procedure did not say, what broke, and what OLL should expect on the same code
path.

Everything here was found by running it, not by reading it.

---

## 1. Read this first if you are deploying OLL's nodes

Two bugs in **shared** roles blocked the deploy. Both are fixed in `e81d443`.
Neither is GCP-specific and both will hit `org_oll`.

### `roles/bb` — installs to one path, checks another

The role resolved paths from `ansible_env.HOME`. `deploy.yml` sets
`become: true` at play level, so facts are gathered **as root** and
`ansible_env.HOME` is `/root` — while every task in the role runs
`become: false` as the login user. So `bbup` installed into the login user's
real `$HOME`, the `creates:` guard pointed at `/root` and never matched (the
install was never idempotent), and the version check died reading
`/root/.bb/bb`:

```
Permission denied: b'/root/.bb/bb'
```

**This hides on part of your fleet.** Vultr images log in as `root`, where
`ansible_env.HOME` and the real `$HOME` coincide, so `oll3`/`oll4` pass by
luck. `oll1`/`oll2` on AWS fail exactly as SFLuv's did. If you see it on AWS
and not Vultr, that is this bug, not a cloud difference.

The fix resolves the home of the user the tasks actually run as.

### `roles/caddy` — presents as a certificate failure, is not one

Symptom, after twelve retries:

```
Wait for Caddy to serve HTTPS ... Connection refused
https://<host>/v1/health
```

It reads like ACME. It is not — **connection refused means nothing is on 443
at all**, so look at what Caddy bound before you look at certificates. Two
independent causes, compounding:

**a. Handlers run too late.** `Write Caddyfile` and the binary copy both
`notify:` handlers, and Ansible defers handlers to the *end of the play*.
Meanwhile `apt` installs Caddy already running with its stock
`:80 { file_server }` config, so `state: started` is a no-op and picks up
neither the new Caddyfile nor the xcaddy binary copied over `/usr/bin/caddy`.
The verification then failed, the play aborted — and the handler never ran at
all. The task meant to catch a broken node was the reason the node stayed
broken.

The tell is in the Caddy log:

```json
{"level":"warn","logger":"http.auto_https",
 "msg":"server is listening only on the HTTP port, so no automatic HTTPS will be applied",
 "server_name":"srv0","http_port":80}
```

That message means the site block has no hostname — i.e. Caddy is serving the
stock config, not ours. Check `/etc/caddy/Caddyfile` on disk against what the
running process actually loaded; ours was correct on disk the whole time.

Worth knowing: the running process kept the **old apt binary** mapped, which
does not know `rate_limit`. The config validates fine — `validate` shells out
to the new binary on disk — while the process serving traffic could not have
parsed it. Fixed with `meta: flush_handlers` before the check.

**b. The role's own `validate` locks Caddy out of its log.**
`caddy validate` does not merely parse; it *opens* the configured log writer.
It runs as root, so it creates the access log as `root:root 0600`. Caddy runs
`User=caddy` and exits at startup:

```
Error: loading initial config: ... opening log writer ...
open /var/log/caddy/sfluv1.access.log: permission denied
```

Creating `/var/log/caddy` as `caddy:caddy` was already handled and is **not
enough** — the file inside it is what blocks. Fixed by re-owning after
validate.

---

## 2. Building the binaries

`signetd` and Caddy are plain Go and need nothing special:

```bash
GOOS=linux GOARCH=amd64 go build -o build/signetd-linux-amd64 ./cmd/signetd

go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
GOOS=linux GOARCH=amd64 xcaddy build \
  --with github.com/mholt/caddy-ratelimit --output build/caddy-linux-amd64
```

### kms-tss without Docker

The runbook says `cross build`, which needs Docker. Neither operator had Docker
installed, and it turns out not to be necessary: **every `kms-tss` dependency is
pure Rust** — no OpenSSL, no `ring`, and no TLS feature on `tonic` — so it
builds anywhere a Rust toolchain does.

The two operators took different routes, and both work. Prefer the first.

**Cross-compile locally to static musl (OLL, canonical).** No Docker, no VM, no
builder to clean up; ~23s. `rust-lld` ships with rustup, and Rust bundles musl
itself, so `link-self-contained` needs no C toolchain. The result is a
static-PIE binary with no libc coupling to the node image at all:

```bash
curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --no-modify-path
export PATH="$HOME/.cargo/bin:$PATH"
rustup target add x86_64-unknown-linux-musl

cd kms-tss
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=rust-lld
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_RUSTFLAGS="-C link-self-contained=yes"
export PATH="$(dirname "$(find ~/.rustup/toolchains -name rust-lld -type f | head -1)"):$PATH"
cargo build --release --locked --target x86_64-unknown-linux-musl
cp target/x86_64-unknown-linux-musl/release/kms-tss ../build/kms-tss-linux-amd64
```

`--no-modify-path` leaves an existing Homebrew `rust` alone; the `export PATH`
above is then required in every shell that builds this.

**Native build on a throwaway VM (SFLuv).** Use when the local toolchain is
awkward. Produces a gnu-ABI binary, which is fine — the nodes run Ubuntu 24.04
— but couples the artifact to that glibc:

```bash
# any Ubuntu 24.04 x86_64 instance (4 vCPU is plenty; ~2 min build)
sudo apt-get install -y build-essential pkg-config protobuf-compiler curl
curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
cargo build --release --locked
```

Two things that are easy to get wrong on this route:

- **`build.rs` compiles `../proto/keymanager.proto`.** Copying `kms-tss/`
  alone fails. Preserve the sibling layout:

  ```bash
  rsync -az --exclude 'target/' ./kms-tss ./proto ubuntu@<builder>:~/signet/
  ```

- **`protobuf-compiler` is required** and is not implied by the Rust
  toolchain. `tonic-build` shells out to `protoc`.

Then pull `target/release/kms-tss` back to `build/kms-tss-linux-amd64`,
**compare `sha256sum` on both ends**, and destroy the builder.

**Do not expect the two operators' binaries to match.** Different targets and
different compiler versions produce entirely different hashes — OLL's is
`static-pie` musl, SFLuv's is dynamically linked gnu. That is expected, not a
tampering signal. The checksum rule is narrower than it sounds: verify the
binary you *transported* matches the one you *built*. Build the binary you
deploy; do not accept one from another operator without reproducing it from
your own source.

### Also required before deploying

- `../signet-circuits` cloned as a **sibling** of this repo — the `bb` role
  reads its `toolchain.json` and fails without it. Currently pins bb
  `3.0.0-nightly.20251104`.
- `tls_email` in `group_vars/org_<name>.yml`. Since `bcfe7f4` this is
  per-operator and the fleet-wide value is deliberately empty, so each org's
  certificates are issued under its own ACME account. `org_oll.yml` already
  carries `ops@oleary.com`.

---

## 3. Deploying

```bash
export ETH_RPC_URL=<your RPC>
export FACTORY_ADDRESS=0x86EB99D569AaD51c3160C5C50ec3093e6771c07a
ansible-playbook -i inventory-alpha.yml deploy.yml \
  --limit org_oll --ask-vault-pass
```

**Use a real RPC, not a public endpoint.** It is written into
`/etc/signet/config.yaml` and the chain poller hits it every 60s. That poller is
what drives membership changes and creates reshare jobs (`node/chain.go`), so if
it is rate-limited the node silently stops seeing on-chain events. SFLuv's nodes
run against Alchemy.

`--limit` is not optional — without it Ansible targets the other operator's
hosts too.

DNS must resolve **before** this runs: Caddy's ACME HTTP-01 challenge needs the
name pointing at the node on port 80. Use `A` records only — no `AAAA` (the
instances have no IPv6 and a stray record makes Let's Encrypt prefer it and
fail), and no CDN proxying, which terminates TLS itself and breaks both the
challenge and node-to-node connections.

Certificates are **production** Let's Encrypt (`acme_ca` is commented out). The
limits that apply are not the ones people usually quote:

| Limit | Value | What trips it |
|---|---|---|
| Certificates per registered domain | **50 / week** | Distinct hostnames. Six nodes across two domains is nowhere near it. |
| **Duplicate certificate** | **5 / week** | Re-issuing the *same* hostname set. This is the one that bites. |
| Failed validations | 5 / hostname / hour | Broken DNS or a blocked port 80. Resets hourly. |

So the risk is not breadth, it is repetition: five successful issuances for
`oll1.nodes.oleary.com` in one week and that name is locked out until the window
rolls, while the other nodes are unaffected. Failures are comparatively cheap —
they burn the hourly validation budget, not the weekly certificate one.

If you expect to iterate on one host, point at staging first and pass
`-e tls_verify=false` (staging certificates are not publicly trusted, so the
role's post-install HTTPS check would otherwise fail).

---

## 4. Verification — both of these fail silently

```bash
# 1. At-rest encryption. MUST read:
#      at-rest encryption enabled (KEK from SIGNET_KMS_KEY)
#    If it says disabled, the sled store is PLAINTEXT and there is no migration
#    path in either direction — wipe and redeploy BEFORE the first keygen.
ansible -i inventory-alpha.yml org_oll -b -m shell \
  -a 'journalctl -u kms-tss | grep "at-rest encryption"' --ask-vault-pass

# 2. Cleartext 8080 must not answer from outside. With TLS on, signetd binds
#    loopback and Caddy fronts 443. If 8080 answers, the TLS is decorative.
for ip in <your node IPs>; do
  curl -s --max-time 5 "http://$ip:8080/v1/health" \
    && echo "  <-- REACHABLE, fix the firewall" || echo "$ip closed (expected)"
done
```

Then signing readiness. `/debug/*` is loopback-only by default, so tunnel:

```bash
ssh -L 8080:127.0.0.1:8080 <user>@<node> -N &
curl -s http://127.0.0.1:8080/debug/stats | jq '.groups'
```

---

## 5. State as of these notes

On-chain (**Ethereum mainnet, `CHAIN_ID=1`** — note the runbook's examples are
all Sepolia; every phase here spends real ETH):

| | |
|---|---|
| Factory | `0x86EB99D569AaD51c3160C5C50ec3093e6771c07a` |
| Group | `0x86fe28144034fdaf86d3c964296dd33e4b94ac59` |
| Threshold | 3, immutable |
| Members | 6, **all six registered and active** |

SFLuv's two nodes are live: HTTPS with production certificates, cleartext 8080
closed, at-rest encryption confirmed enabled, chain poller reading the group
correctly, and the two peered at ~28 ms.

What OLL's deploy unblocks — at `T=3` over 6, FROST needs 3 signers and ECDSA
needs `2T-1 = 5`:

| OLL nodes up | Healthy | FROST | ECDSA (payments) |
|---|---|---|---|
| 0 | 2 | no | no |
| 1 | 3 | yes | no |
| 2 | 4 | yes | no |
| 3 | 5 | yes | yes, no spare |
| 4 | 6 | yes | yes, one may be down |

So **nothing can sign payments until three of OLL's four are up**, and all four
are needed for any fault tolerance. A rolling deploy passes through every row,
so a group that answers FROST but refuses ECDSA mid-deploy is expected, not a
fault.

Once they are, from either operator:

```bash
go build -o build/harness ./cmd/harness
./build/harness -env testnet/.env-alpha correctness
```

**`.env-alpha` is per-machine and is not in the repo.** It is generated from
`factory.env` plus every `manifest-*.json`, so each operator writes its own once
all the fragments are merged:

```bash
testnet/scripts/alpha-contracts.sh write-env
```

Running it locally also avoids inheriting the stale `RPC_URL` noted in §6.

---

## 6. Caveats

- **The playbook has not run green end-to-end.** SFLuv's nodes were repaired by
  hand to get them up, and the fixes in `e81d443` were written afterwards to
  match. They should be equivalent, but that is a reconstruction, not an
  observation. If something unexpected happens, this is the likeliest gap.

  So the first deploy on the fixed path is a test of it. Run one host —
  `--limit oll1` — and verify it fully before the rest. A failure then costs one
  node instead of four, and one duplicate-certificate slot instead of four.
- `write-env` recorded `RPC_URL` as the public endpoint used for chain reads
  during stand-up, not SFLuv's Alchemy URL. It affects only the harness's own
  reads, not the nodes.
- **No backup mechanism exists** (`docs/PRODUCTION-GAPS.md`). Destroying an
  instance destroys its key shard. Losing more than `N-T` nodes is permanent
  key loss.
