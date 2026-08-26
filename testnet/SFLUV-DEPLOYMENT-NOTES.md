# SFLuv Deployment Notes

Field notes from standing up SFLuv's two GCP nodes for the alpha on
**2026-08-23**. `ALPHA-RUNBOOK.md` is the procedure; this records what the
procedure did not say, what broke, and what OLL should expect on the same code
path.

Everything here was found by running it, not by reading it.

---

## 1. Read this first if you are deploying OLL's nodes

Two bugs in **shared** roles blocked the deploy, fixed in `e81d443` — and the
Caddy half needed a second pass in `901ad4c` after `oll1` hit the remainder.
Neither is GCP-specific and both will hit `org_oll`. Make sure you have
`901ad4c`, not just `e81d443`.

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
parsed it.

`e81d443` fixed this with `meta: flush_handlers` before the check, which was
right but insufficient, and `oll1` found the rest. `flush_handlers` runs
handlers in **handler-file order, not notification order**, and `reload` was
defined first — but a reload cannot swap an executable, so it re-parsed our
config inside the stock binary and died on the unknown `rate_limit` module. The
play aborted before `restart` ran, leaving the node on the stock config: the
same failure shape, one step later.

`901ad4c` defines `restart` before `reload` and adds a recovery task, because
ordering alone would not rescue a node already left in that state — after the
aborted run the binary and Caddyfile match on disk, so a re-run notifies
nothing. It detects the replaced-but-still-mapped executable via
`/proc/<pid>/exe` reading `(deleted)`.

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

### Reading the PLAY RECAP

`failed=0` and `unreachable=0` on every host is the bar. Exact `ok=` counts are
not quoted here deliberately — they move whenever a task is added, and a stale
number reads as drift when it is not.

Two things look like drift on a repeat run and are not:

- **`changed=1` on a converged host is expected**, and it is
  `bb : Install bb at pinned version`. That task deliberately has no `creates:`
  guard — bbup is what enforces the pin, so guarding on "some bb exists" would
  make a `toolchain.json` bump silently never take effect. Do not "fix" this to
  reach `changed=0`.
- **A one-task difference between hosts is expected.** `Check for the locally
  built Caddy binary` is `run_once` and delegated to localhost, so it appears
  against one host only.

Anything *else* reporting `changed` on a second run is real drift and worth
reading. But note the converse trap from §8: a run where nothing changed has
also exercised none of the handler paths, so it is weak evidence that a fix to
those paths works.

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

Running it locally also avoids inheriting the stale `RPC_URL` noted in §8.

---

## 6. Running the harness

Four traps, all of which cost time on the alpha.

### The auth key has to reach the process, not just the file

`write-env` writes `HARNESS_AUTH_KEY` into `.env-alpha`, and until `1abb73a` the
harness read it **only from the process environment**. So the invocation the
runbook documents ran completely unauthenticated and every request came back
401 — with a correct key, on-chain, matching `getAuthKeys` the whole time.

`1abb73a` makes the harness parse it from the env file, so on current `main`
this just works. On an older build, export it first:

```bash
set -a; . ./testnet/.env-alpha; set +a
```

**The diagnostic is one line of output.** An authenticated run prints:

```
auth: identity "harness", session 029eb06f8a0a49a0…, expires ...
registering session on all nodes... ok
```

If those lines are absent, auth is off. Since `1abb73a` an unconfigured run says
so explicitly instead of proceeding quietly.

### You cannot see why the other operator's node rejected you

The node deliberately returns a generic body — `{"error":"unauthorized"}`,
`{"error":"not found"}` — and logs the real reason server-side
(`handlers.go`, `genericErrorMessage`). The 401 above was actually:

```
WARN  http error  {"code": 401, "detail": "authorization required (session_pub)"}
```

which names the cause immediately. **But that log is on whichever node served
the request**, and the harness round-robins across all six. When the failing
node belongs to the other operator you cannot read it at all — that is the key
split working as designed, not a misconfiguration. Expect to ask them, and give
them a UTC window:

```bash
journalctl -u signetd --since "<UTC start>" --until "<UTC end>" | grep -i "http error"
```

### Correctness trips its own rate limit

Nearly every test does a keygen and `rate_limit_keygen_events` is 10/min, so an
unexempted runner exhausts its quota around test 8 and every remaining test
fails `429`. The runbook warns about this for the *perf* harness; correctness
hits it just as hard.

Both operators must exempt the runner — the suite touches all six nodes, so
`org_sfluv.yml` alone leaves the tests that reach OLL's nodes failing:

```yaml
rate_limit_exempt_cidrs:
  - <runner IP>/32
```

Note whose address that is: each operator is exempting *someone else's* client
from the limits on its own hardware. Worth removing when the alpha ends.

### perf flags: `-out` is global, `-duration` is per scenario

`-out` belongs to the top-level flag set, so it must come **before** the
subcommand. After it, you get `flag provided but not defined: -out`:

```bash
./build/harness -env testnet/.env-alpha -out testnet/perf.jsonl \
  perf -concurrency 10 -duration 300s
```

And `-duration` is **per scenario**, not total. `RunPerf` runs seven
(sequential-baseline, concurrent keygen/sign for FROST and ECDSA, scoped sign,
mixed-load), plus three unmetered key-pool builds — so `-duration 300s` is a
**~35 minute** run, not five. `83341d7` fixed the flag help; the runbook example
still reads like a five-minute job, and it is easy to conclude it has hung
around minute ten.

The run drives load from *your* machine, so it must stay awake. `caffeinate -i
-w <pid>` holds off idle sleep and exits by itself when the run does — though it
does not stop a lid-close.

### The auth session expires mid-run, and the run does not stop

`-auth-ttl` defaults to **one hour**, and the session is minted once at startup
and never refreshed. A run longer than that keeps going and 401s every request
from the moment it lapses — no abort, no warning, just a scenario whose numbers
are entirely fictional.

This ate the last two scenarios of a 700s × 7 run here. The arithmetic is
unforgiving and easy to miss:

```
-duration 700s × 7 scenarios ≈ 82 min  >  60 min default TTL
```

The harness prints the expiry on the second line of output. Compare it against
your expected finish before starting:

```
auth: identity "harness", session 020bb58d…, expires 2026-08-25T12:35:04-07:00
```

For any run over ~45 minutes, raise it: `-auth-ttl 4h`. The tell afterwards is a
scenario reporting a huge operation count with a near-100% error rate and p50 of
0 ms — those are 401s returning instantly, not work.

---

## 7. Validation results

All figures from the six-node group above, on mainnet, `T=3`.

### Correctness: 23/23

Covers considerably more than the FROST-secp256k1 happy path:

| Tests | Coverage |
|---|---|
| 1–7 | FROST secp256k1 — keygen, sign, verify, non-determinism, concurrent isolation, cross-node |
| 8–9 | FROST Ed25519 |
| 10–13 | Threshold ECDSA, including `s` normalization and concurrent signing |
| 20–23 | Scoped keys — EIP-712 binding, and correctly *rejecting* raw hashes, wrong chain, wrong contract |
| 30–35 | Key lifecycle — disable/enable/delete, coordinated cross-node, status listing |

The negative cases (21–23) matter more than the positive ones: they confirm
scoped keys refuse what they should.

### Perf, and what `log_level` actually cost

Two runs, `-concurrency 10 -duration 300s`, both from a wiped store, differing
only in `log_level`:

| Scenario / op | `debug` | `info` | Δ | p50 `debug`→`info` |
|---|---:|---:|---:|---|
| sequential-baseline / keygen | 4.6 | 4.8 | +3.1% | 108 → 115 ms |
| sequential-baseline / sign | 4.6 | 4.8 | +3.1% | 66 → 62 ms |
| concurrent-keygen-frost | 39.5 | 39.4 | −0.2% | 206 → 211 ms |
| **concurrent-sign-frost** | **93.9** | **120.7** | **+28.6%** | **95 → 69 ms** |
| concurrent-keygen-ecdsa | 29.5 | 30.6 | +3.7% | 308 → 302 ms |
| concurrent-sign-ecdsa | 37.6 | 37.2 | −0.8% | 256 → 257 ms |
| concurrent-sign-scoped | 35.5 | 37.1 | +4.6% | 266 → 258 ms |
| mixed-load / sign | 42.8 | 43.9 | +2.5% | 78 → 103 ms |
| mixed-load / keygen | 18.5 | 18.1 | −1.8% | 255 → 260 ms |

Throughput in ops/sec. 91,923 operations on `debug`, 100,995 on `info`.

**Only FROST sign moved.** Everything else is inside ±5%, which is noise at this
sample size. The mechanism is consistent rather than mysterious: per-operation
logging cost scales with operations per second, so the only scenario fast enough
for it to matter is the only one that improved. Keygen scenarios are dominated
by DKG rounds across the committee and swallow it whole.

So `debug` was not a general drag — it was throttling the payment hot path
specifically, by roughly a quarter. `18dc93f` moved the default to `info`.

Headline: **~121 FROST sign/sec at 69 ms p50** across six nodes, two operators
and three clouds — about 6× the ~20/sec of the old single-operator baseline.
ECDSA runs ~37/sec at 257 ms p50, which is the expected shape: `2T-1 = 5`
signers over 4 rounds against FROST's 3 signers over 2. Scoped keys cost
essentially nothing over plain ECDSA (37.1 vs 37.2 ops/sec), so the EIP-712
binding is free.

### The 404s: a real race, now fixed

Two `HTTP 404`s on sign in the `info` run, both for keys that had *just* been
created. They looked anomalous for a reason worth understanding, because the
same trap will catch the next person.

**They are in `sequential-baseline`, the least-loaded scenario** — one operation
at a time at ~4.8 ops/sec — while the concurrent scenarios running 25× that rate
produced none. That inverts the usual intuition, and the explanation is
structural rather than statistical: `sequential-baseline` is the **only**
scenario that signs a key it just created. Every other sign scenario calls
`BuildKeyPool` first and signs from a pool that is minutes old. So the other
scenarios were not 25× less exposed; they were **not exposed at all**.

The mechanism, from OLL's journals (key `…-1018`):

```
oll1 (initiator)    01:47:45.559  keygen complete        -> HTTP 200 to client
oll2 (participant)  01:47:45.585  404 key not found      <- 26ms after the 200
oll2                01:47:45.602  coord: keygen complete <- 17ms too late
```

The initiator answers `/v1/keygen` when its **own** DKG run finishes, while each
participant runs its side in a goroutine off the coord message with no ack back
before the response. Between those two points the key is real to the client and
absent on a participant. The harness round-robins, so the operation after a
keygen goes to the next node in the ring — which is why both landed on the node
following the initiator, and none elsewhere. That clustering is confirming
evidence, not coincidence.

**This is not a test artifact.** Any client that creates a key and immediately
uses it against a different node can land in the window. A load generator just
does it often enough to be seen.

`42c31a3` fixes it, and the root cause is sharper than the symptom: the node
already had `markKeygenPending`/`awaitKey`, and the **coord path already used
it** — waiting rather than failing. Only the client-facing path did not, so an
internal sign waited while a client-facing one 404'd. `handleSign` now resolves
through `awaitKey`: present returns immediately, in flight waits up to 2s,
genuinely absent still 404s. The 2s is ~3× the measured keygen p99 of 598 ms.

The status code matters as much as the wait. "Not yet" and "never existed" were
the same response, which is exactly why this looked unexplainable — the race's
404 was indistinguishable from the deliberate ones `4-sign-missing-key` fires.
In-flight is now `409` with `Retry-After`.

**Verification:** 3,151 keygen→sign pairs in `sequential-baseline` after the
fix, zero errors, zero 404s, zero 409s. Against the observed rate of 2-in-1,437
(p ≈ 0.139%), the chance of seeing zero by luck is ~1.3%, so ~98.7% confidence.
State plainly what that is: evidence the race no longer *manifests* at a
detectable rate. The mechanism is established by the journals and the code path,
which is stronger evidence than any black-box run. The zero `409`s is its own
result — `awaitKey` never exhausted its 2s budget across 3,151 pairs, so the
window stays well inside it.

### Store size: measurable, and smaller than `du` suggests

A third run reused the ~101k keys left by the second instead of wiping, which
isolates store size (both runs `info`):

| Scenario | wiped | ~101k keys | Δ |
|---|---:|---:|---:|
| sequential-baseline / keygen | 4.8 | 4.5 | −6.0% |
| sequential-baseline / sign | 4.8 | 4.5 | −6.0% |
| **concurrent-keygen-frost** | 39.4 | 33.2 | **−16.0%** |
| concurrent-sign-frost | 120.7 | 109.2 | −9.6% |
| concurrent-keygen-ecdsa | 30.6 | 28.0 | −8.4% |
| concurrent-sign-ecdsa | 37.2 | 36.7 | −1.3% |

Writes degrade more than reads (keygen −16% against ECDSA sign −1.3%), which is
what sled write amplification on a larger tree looks like. Treat these as an
upper bound: the third run used a longer per-scenario duration and the store
kept growing *during* it, so the confound points the same way as the effect.

On disk size specifically — **`du` overstates it badly**. The store measured
~290 MB at 101k keys, and still ~290 MB after another ~46k keygens. Both numbers
are preallocated sled segments, not live data, so dividing store size by key
count (~3 KB/key) measures baseline overhead amortised, not marginal cost. Any
storage optimisation should start from a before/after delta on a quiesced node,
not from that ratio.

The structural cost worth knowing is in `StoredKey.public_key_package`: it holds
a verifying share per participant, so per-key storage is **O(committee size)**.
At N=6 that is ~400 B; the direction of travel toward one shard per operator
makes it the dominant term.

### Still open

- **One `HTTP 504`** on a FROST sign at peak concurrency in the `debug` run,
  150 ms in. Caddy giving up on signetd, not a signing failure, and 150 ms is
  far below any sensible proxy timeout — more likely a transient reset surfacing
  as 504. It has not recurred across two later runs that did more FROST signing.
- **A liveness wobble under sustained ECDSA keygen** — seven client-side 30s
  timeouts across five nodes in the third run's `concurrent-keygen-ecdsa`.
  Recorded with analysis in `docs/PRODUCTION-GAPS.md` (`103161e`); the lead is
  that `liveness.go` uses `probeInterval 15s` × `unhealthyAfter 2` = exactly the
  30s observed, with a `probeTimeout` of 3s that is tight for a node saturated
  by 4-round ECDSA sessions. If that is right the peers were never unreachable
  and the tracker was wrong, which costs real signing capacity on a path with no
  margin. Capture per-peer `consecutive_fails` and `rtt_ms` from `/debug/stats`
  next time it appears.

  **Two 503s in the same run are probably a different thing** and should not be
  folded in:

  ```
  select signers: insufficient available signers: need 5, have 2 of 6 members
  ```

  `9b9de30` records that a parallel deploy across OLL's four-node batch left the
  group at exactly two healthy members — the same figure. A deploy overlapping a
  load run reproduces this precisely, and it is now prevented by `serial: 1`
  rather than being a load phenomenon. Check whether a deploy was in flight
  before treating a 503 of this shape as the liveness issue above.

---

## 8. Caveats

- **SFLuv's nodes were repaired by hand before `e81d443` was written**, so that
  commit was a reconstruction rather than an observation.

  So the first deploy on the fixed path is a test of it. Run one host —
  `--limit oll1` — and verify it fully before the rest. A failure then costs one
  node instead of four, and one duplicate-certificate slot instead of four.

- **A green re-run proves less than it looks like.** SFLuv re-ran `deploy.yml`
  over `org_sfluv` after the hand-repair and it went green on both hosts,
  `Wait for Caddy to serve HTTPS` included. That was read as confirming the
  fix. It did not: `oll1` then failed on the very next real deploy, which is
  what `901ad4c` fixes.

  The reason is worth internalising, because it generalises past Caddy.
  **Handlers only fire on `changed`.** The hand-repaired nodes already had the
  right binary and Caddyfile on disk, so nothing reported `changed`, nothing
  notified, and the flush ran no handlers at all. The green run therefore never
  exercised the handler path — the only part under test. A converged host
  cannot verify a fix to convergence.

  Verifying that class of fix takes a host that is genuinely in the *before*
  state: a fresh node, or `oll1` on its first deploy. That is the same property
  `901ad4c`'s recovery task exists for — a node left mid-deploy looks converged
  on disk while serving from a replaced binary.
- `write-env` recorded `RPC_URL` as the public endpoint used for chain reads
  during stand-up, not SFLuv's Alchemy URL. It affects only the harness's own
  reads, not the nodes.
- **No backup mechanism exists** (`docs/PRODUCTION-GAPS.md`). Destroying an
  instance destroys its key shard. Losing more than `N-T` nodes is permanent
  key loss.
