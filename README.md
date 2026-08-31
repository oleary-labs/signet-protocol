# signet

Threshold signing governed by on-chain policy — trusted issuers, signing scopes, and committee changes — enforced independently by every node, with no node ever holding a whole key.

Three signing schemes share one DKG, storage, and coordination stack, selected per request with a `curve` parameter:

| Scheme | Curve | Typical use |
|--------|-------|-------------|
| FROST Schnorr (RFC 9591) | secp256k1 | On-chain Schnorr verification, general signing |
| FROST Schnorr | Ed25519 | Solana |
| Threshold ECDSA (DJNPO20) | secp256k1 | EVM `ecrecover`, EIP-712, EIP-3009 |

See [`docs/CURVES.md`](docs/CURVES.md) for the canonical curve strings and per-scheme response shapes.

Nodes hold persistent secp256k1 identities, connect over a libp2p mesh, and expose an HTTP API for distributed key generation and threshold signing. Response signature format depends on the scheme — Ethereum-compatible 65-byte R+S+V for secp256k1 schemes, raw 64-byte signatures for Ed25519.

Group membership and trust configuration are managed on-chain via `SignetFactory` and `SignetGroup` smart contracts. Clients authenticate by one of four routes: an auth-key certificate, a ZK proof of OAuth identity (the JWT never reaches the network), a delegation token, or SIWE against an on-chain identity resolver.

A client sends a single request to **any one node** in the group. That node coordinates the session with the other participants automatically.

---

## Contents

- [Repository layout](#repository-layout)
- [Build](#build)
- [Configuration](#configuration)
- [Running a network](#running-a-network)
- [API reference](#api-reference)
- [Authentication](#authentication)
- [End-to-end walkthrough](#end-to-end-walkthrough)
- [Running tests](#running-tests)
- [Architecture notes](#architecture-notes)

---

## Repository layout

```
cmd/signetd/        — node binary
cmd/devnet-init/    — key-init helper used by devnet scripts
cmd/harness/        — multi-node test harness (correctness + performance)
cmd/testvector/     — test vector generator
cmd/verify-ed25519/ — standalone Ed25519 signature verifier
node/               — HTTP API, coordinator, chain client, auth
tss/                — FROST adapter (keygen/sign round runner, Go fallback path)
kms-tss/            — Rust KMS: FROST + threshold ECDSA over gRPC (production default)
kms/                — gRPC client and generated protobuf (Go side)
proto/              — keymanager.proto (Go ↔ KMS interface)
network/            — libp2p host + session network
contracts/          — Solidity (Foundry): SignetFactory, SignetGroup
devnet/             — local devnet scripts (Anvil + 3 nodes + KMS instances)
testnet/            — Ansible deploy tooling for the Sepolia testnet
docs/               — design and security documents
```

The Noir ZK circuit lives in the separate [`signet-circuits`](https://github.com/oleary-labs/signet-circuits) repo and is consumed here as a Go module; its verification key is embedded at build time.

---

## Build

**Requirements:** Go 1.26+, Rust toolchain (for KMS)

```bash
git clone https://github.com/oleary-labs/signet-protocol
cd signet-protocol

go build ./cmd/signetd/

# Build the Rust KMS (production default)
cd kms-tss && cargo build --release
```

The node binary is `./signetd`. The KMS binary is `kms-tss/target/release/kms-tss`.

To run without the Rust KMS (in-process Go FROST, for development), pass `--no-kms` to the devnet scripts or omit `kms_socket` from the node config.

**Contracts** (requires [Foundry](https://getfoundry.sh)):

```bash
cd contracts && forge build
```

**ZK circuit** — no local build step. The circuit lives in the [`signet-circuits`](https://github.com/oleary-labs/signet-circuits) repo and its verification key is embedded via the Go module, so `go build` is sufficient. To bump it:

```bash
go get github.com/oleary-labs/signet-circuits/packages/go@vX.Y.Z
go mod tidy
```

Verifying proofs at runtime still needs the `bb` binary on `PATH` or at `~/.bb/bb`, pinned to the version in the circuits repo's `toolchain.json`.

---

## Configuration

`signetd` reads a YAML config file (default `./config.yaml`). A default file is written on first run.

```yaml
data_dir:         ./data                       # directory for node.key and keyshards.db
listen_addr:      /ip4/0.0.0.0/tcp/9000        # libp2p listen multiaddr
api_addr:         :8080                        # HTTP API listen address
announce_addr:    ""                           # optional public multiaddr to advertise
bootstrap_peers:  []                           # multiaddrs of peers to dial on startup
node_type:        public                       # "public" or "permissioned"

# Blockchain integration (required to resolve group membership)
eth_rpc:          ""                           # e.g. http://localhost:8545
factory_address:  ""                           # SignetFactory contract address (0x...)
chain_poll_secs:  60                           # chain event poll interval; 0 = default (60)

# KMS (Rust multi-scheme process)
kms_socket:       ""                           # Unix socket path to kms-tss; empty = in-process Go FROST

# On-chain auth resolver (SIWE). Both unset = scheme disabled.
siwe_domain:      ""                           # ERC-4361 domain; REQUIRED, else the scheme is rejected
chain_rpcs:       {}                           # chainId → RPC URL, for resolvers off the home chain
```

The circuit verification key is embedded at build time — there is no `vk_path` setting.

Pass a custom config file with `-config`:

```bash
./signetd -config node1.yaml
```

Control log verbosity with `-log-level` (default `info`):

```bash
./signetd -config node1.yaml -log-level debug
```

Accepted values: `debug`, `info`, `warn`, `error`.

---

## Running a network

### Quickstart: local devnet

The devnet scripts start Anvil, deploy the contracts, register three nodes, create a signing group, and launch all three `signetd` processes in one command:

```bash
# Default: Rust KMS (recommended)
devnet/start.sh

# In-process Go FROST (no Rust toolchain required)
devnet/start.sh --no-kms
```

See [devnet/README.md](devnet/README.md) for full details, port assignments, and cleanup commands.

### Manual three-node setup

If you want to run nodes manually (without the devnet scripts), you need:

1. A running Ethereum RPC endpoint (`eth_rpc`) with the factory contract deployed.
2. Nodes registered on-chain and added to a group — groups are resolved from the chain at startup.

**Node 1:**

```bash
cat > node1.yaml <<EOF
data_dir:        ./data/node1
listen_addr:     /ip4/0.0.0.0/tcp/9000
api_addr:        :8080
eth_rpc:         http://localhost:8545
factory_address: 0xYourFactoryAddress
EOF

mkdir -p data/node1
./signetd -config node1.yaml
# INFO  node ready  {"peer_id": "16Uiu2HAmXXX...", ...}
```

**Nodes 2 and 3** — include node 1's multiaddr in `bootstrap_peers`:

```bash
cat > node2.yaml <<EOF
data_dir:         ./data/node2
listen_addr:      /ip4/0.0.0.0/tcp/9001
api_addr:         :8081
bootstrap_peers:
  - /ip4/127.0.0.1/tcp/9000/p2p/16Uiu2HAmXXX...
eth_rpc:          http://localhost:8545
factory_address:  0xYourFactoryAddress
EOF

mkdir -p data/node2
./signetd -config node2.yaml
```

---

## API reference

All endpoints speak JSON. Keygen and sign requests **block** until the protocol completes.

**A client only needs to contact one node.** The receiving node coordinates with the other group members over the internal `/signet/coord/1.0.0` libp2p protocol.

Group membership and threshold are resolved from the chain — they are not passed in API requests.

All keygen, sign, delegate, and key-lifecycle endpoints accept a `curve` parameter — one of `frost_secp256k1`, `frost_ed25519`, or `ecdsa_secp256k1`. See [`docs/CURVES.md`](docs/CURVES.md) for the canonical reference (per-curve algorithm, response shapes, picking guidance).

### CORS

`/v1/*` is callable from a browser from any origin:

```
Access-Control-Allow-Origin:    *
Access-Control-Allow-Methods:   GET, POST, OPTIONS      (preflight only)
Access-Control-Allow-Headers:   Content-Type            (preflight only)
Access-Control-Max-Age:         86400                   (preflight only)
Access-Control-Expose-Headers:  Retry-After
```

`Access-Control-Allow-Credentials` is **never** set, and the origin is a literal `*` rather than a reflection of the request's `Origin`.

The wildcard is safe because `/v1/*` carries **no ambient authority**: the per-request signature travels in the JSON body (`request_sig`), there are no cookies, and no `Authorization` header is read. A hostile page can make requests, but gets nothing it could not have obtained with `curl` — every mutating call is rejected without a signature it cannot produce. If session state ever moves to a cookie or an `Authorization` header this policy must be redesigned, not amended.

**`Retry-After` is exposed deliberately.** It is not on the CORS safelist, so without this a browser client cannot read it at all. Two responses depend on it: `409` while a key is still settling after keygen, and `429` when a rate-limit zone trips. Both tell the client exactly how to recover, so a browser SDK should honour it rather than hardcoding backoff.

`/admin/*` and `/debug/*` are **not** browser APIs and carry no CORS headers. Admin endpoints are authenticated by an ECDSA signature from a group-trusted key; `/debug/*` exposes group membership and per-peer RTT and is CIDR-restricted at the proxy.

One consequence worth knowing: a wildcard means any page a user visits can drive `/v1/*` requests **from that user's IP**, which can consume their per-IP rate limit — notably the `/v1/auth` zone at 10/min. Nothing is compromised, but a browser SDK should not treat rate limits as private to itself.

### `GET /v1/health`

Liveness check.

```
200 OK
{"status":"ok"}
```

### `GET /v1/info`

Returns this node's identity.

```json
{
  "peer_id":          "16Uiu2HAm...",
  "ethereum_address": "0xabc123...",
  "addrs":            ["/ip4/0.0.0.0/tcp/9000"],
  "node_type":        "public"
}
```

### `POST /admin/keys`

Lists key shard metadata for one group. Group-scoped and authenticated — it requires an `AdminAuth` ECDSA signature from an authorization key trusted by that group. There is no unauthenticated `GET /v1/keys`.

```json
{
  "group_id":     "0xGroupAddr",
  "auth_key_pub": "02...",
  "signature":    "hex64",
  "nonce":        "hex",
  "timestamp":    1709900000
}
```

- `auth_key_pub` — 34-byte scheme-prefixed key (hex)
- `signature` — over `SHA256(group_id : nonce : timestamp_8bytes_BE)`; 64 bytes ECDSA or 65 bytes Schnorr

```json
[
  {
    "group_id":         "0x...",
    "key_id":           "k1",
    "curve":            "frost_secp256k1",
    "public_key":       "0x03abcd...",
    "ethereum_address": "0xabc123...",
    "threshold":        2,
    "parties":          ["16Uiu2HAm...", "16Uiu2HAm...", "16Uiu2HAm..."],
    "status":           "enabled"
  }
]
```

### `POST /v1/auth`

Registers an ephemeral session key bound to a verified identity. Required before keygen/sign on groups that have auth policies (OAuth issuers or auth keys) configured.

**Auth key certificate**:

```json
{
  "group_id":    "0x...",
  "session_pub": "02abc...",
  "certificate": {
    "auth_key_pub": "02...",
    "signature":    "hex64",
    "identity":     "user1",
    "expiry":       1709900000
  }
}
```

- `auth_key_pub` — compressed secp256k1 public key of a trusted auth key registered on-chain
- `signature` — 64-byte [R||S] ECDSA signature over `SHA256(identity:group_id:session_pub_hex:expiry_8bytes_BE)`

**OAuth/ZK proof**:

```json
{
  "group_id":     "0x...",
  "proof":        "hex...",
  "session_pub":  "02abc...",
  "sub":          "user@example.com",
  "iss":          "https://accounts.google.com",
  "exp":          1709900000,
  "aud":          "app.example.com",
  "azp":          "client-id",
  "jwks_modulus": "hex..."
}
```

- `proof` — Barretenberg ZK proof (hex) generated by the client
- `jwks_modulus` — RSA-2048 public key modulus used to verify the proof (hex)
- The node verifies the proof via `bb verify` against the circuit VK embedded at build time, and checks the modulus against its cached OIDC JWKS

**SIWE / on-chain resolver** — requires `siwe_domain` to be configured, and a resolver bound on the group contract:

```json
{
  "group_id":       "0x...",
  "session_pub":    "02abc...",
  "siwe_message":   "example.com wants you to sign in...",
  "siwe_signature": "hex65",
  "block_number":   12345678,
  "block_hash":     "0x..."
}
```

The node recovers the address from the SIWE signature, then reads the group's resolver at the client-pinned block with `from = 0x0`, so every node reads identical state. See [`docs/DESIGN-ONCHAIN-AUTH-RESOLVER.md`](docs/DESIGN-ONCHAIN-AUTH-RESOLVER.md).

Response:

```json
{
  "status":     "ok",
  "identity":   "user@example.com",
  "expires_at": 1709900000
}
```

### `POST /v1/keygen`

Runs a distributed key generation session (FROST DKG).

**Without auth** (groups without issuers):

```json
{
  "group_id": "0xGroupAddr",
  "key_id":   "k1"
}
```

**With session auth** (groups with issuers):

```json
{
  "group_id":    "0xGroupAddr",
  "key_suffix":  "optional-label",
  "session_pub": "02abc...",
  "request_sig": "64-byte-hex",
  "nonce":       "hex",
  "timestamp":   1709900000
}
```

- `group_id` — group contract address (lower-cased)
- `key_id` — caller-chosen label scoped to the group; must be unique within the group
- `key_suffix` — with auth: appended to the resolved key ID as `sub:suffix`
- `session_pub` / `request_sig` / `nonce` / `timestamp` — session-auth fields (see [Authentication](#authentication))

Response:

```json
{
  "group_id":         "0x...",
  "key_id":           "k1",
  "public_key":       "0x03abcd...",
  "ethereum_address": "0xabc123..."
}
```

### `POST /v1/sign`

Runs a threshold signing session (FROST, 2 rounds).

**Without auth:**

```json
{
  "group_id":     "0xGroupAddr",
  "key_id":       "k1",
  "message_hash": "0xdeadbeef..."
}
```

**With session auth:**

```json
{
  "group_id":     "0xGroupAddr",
  "key_suffix":   "optional-label",
  "message_hash": "0xdeadbeef...",
  "session_pub":  "02abc...",
  "request_sig":  "64-byte-hex",
  "nonce":        "hex",
  "timestamp":    1709900000
}
```

- `message_hash` — 32-byte hash to sign (hex, `0x` prefix optional)

Response:

```json
{
  "group_id":           "0x...",
  "key_id":             "k1",
  "ethereum_signature": "0x..."
}
```

The response field depends on the scheme:

| Curve | Field | Format |
|-------|-------|--------|
| `frost_secp256k1` | `ethereum_signature` | 65 bytes, R.x ++ z ++ v |
| `ecdsa_secp256k1` | `ecdsa_signature` | 65 bytes, r ++ s ++ v — verifies under `ecrecover` |
| `frost_ed25519` | `signature` | 64 bytes, standard Ed25519 |

### Other endpoints

- `POST /v1/delegate` — issue a delegation token scoped to a sub-key
- `POST /v1/keys/disable`, `/v1/keys/enable`, `/v1/keys/delete` — key lifecycle
- `POST /admin/reshare`, `POST /admin/reshare/status` — reshare control
- `GET /debug/stats` — peer, connection, and memory stats (unauthenticated)

---

## Authentication

Groups can be created with one or more trusted OAuth issuers. When a group has issuers configured, keygen and sign requests require authentication.

### Session key scheme

To avoid forwarding raw JWTs across the network:

1. The client obtains an OAuth JWT and generates an ephemeral secp256k1 keypair.
2. The client calls `POST /v1/auth` with either the raw JWT (test mode) or a ZK proof binding the JWT to the session public key (production).
3. The node verifies the credential and caches the session binding (`session_pub → sub`).
4. For subsequent keygen/sign requests, the client signs a canonical request hash with the session private key and includes `session_pub`, `request_sig`, `nonce`, and `timestamp`.

The canonical request hash is `SHA256(group_id : key_id : nonce : timestamp_8bytes_BE [: message_hash])`.

For scoped (payload-based) signing, `message_hash` in the canonical request hash is the payload hash the client computes locally — for `scheme=eip712`, the EIP-712 `hashTypedData` of the typed data being sent. Every node independently recomputes this hash from the forwarded payload before accepting the session signature, so the payload cannot be substituted in transit or by the initiating node.

### ZK auth (production)

The Noir circuit — now in the [`signet-circuits`](https://github.com/oleary-labs/signet-circuits) repo — proves that a valid JWT signed by a trusted RSA key commits to a given session public key, without revealing the JWT to the network. Its verification key is embedded at build time, so there is nothing to configure; the `bb verify` binary must be on `PATH` or at `~/.bb/bb`.

Where a group has OAuth issuers registered with a non-empty client ID allowlist, the token's `azp` (falling back to `aud`) must appear in that list. An empty array means "any client from this issuer" — an array containing an empty string does **not**, and will reject every client.

See [docs/DESIGN-ZK-AUTH.md](docs/DESIGN-ZK-AUTH.md) for the full design, and [docs/SECURITY-AUDIT-KIMI-20260613.md](docs/SECURITY-AUDIT-KIMI-20260613.md) plus [docs/AUDIT-SCOPE.md](docs/AUDIT-SCOPE.md) for the threat model and audit scope.

---

## End-to-end walkthrough

This example uses the devnet (three nodes at ports 8080–8082, no auth).

```bash
devnet/start.sh
source devnet/.env   # sets GROUP_ADDRESS, RPC_URL, etc.
```

### 1. Keygen

```bash
curl -s -X POST http://localhost:8080/v1/keygen \
  -H 'Content-Type: application/json' \
  -d "{\"group_id\":\"$GROUP_ADDRESS\",\"key_id\":\"k1\"}" | jq .
```

```json
{
  "group_id":         "0x...",
  "key_id":           "k1",
  "public_key":       "0x03abcd...",
  "ethereum_address": "0xabc123..."
}
```

All three nodes now hold their secret shares.

### 2. Sign

```bash
HASH="0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"

curl -s -X POST http://localhost:8080/v1/sign \
  -H 'Content-Type: application/json' \
  -d "{\"group_id\":\"$GROUP_ADDRESS\",\"key_id\":\"k1\",\"message_hash\":\"$HASH\"}" | jq .
```

```json
{
  "group_id":           "0x...",
  "key_id":             "k1",
  "ethereum_signature": "0x..."
}
```

The 65-byte signature can be verified on-chain against the Ethereum address returned by keygen.

---

## Running tests

```bash
# Go: node + network + threshold math
go test ./...

# Verbose with timeout (includes libp2p integration tests)
go test -v -timeout 3m ./...

# Solidity contracts (requires Foundry)
cd contracts && forge test

# Rust KMS
cd kms-tss && cargo test
```

ZK circuit tests live in the [`signet-circuits`](https://github.com/oleary-labs/signet-circuits) repo, which pins its own `nargo` + `bb` toolchain. This repo only consumes the compiled verification key.

---

## Architecture notes

### Identity

Each node's libp2p peer ID is derived from a persistent secp256k1 private key stored in `data_dir/node.key`. The same key produces the node's Ethereum address, which is registered on-chain in `SignetFactory`.

Because this key is the node's on-chain identity, it can be encrypted at rest. Set the `SIGNET_NODE_KEY_PASSPHRASE` environment variable before first start: a newly generated `node.key` is then sealed with XChaCha20-Poly1305 under a scrypt-derived key, and the same passphrase is required on every subsequent start. Leaving the variable unset stores the key in the legacy plaintext format. Encrypted files are self-describing, so an existing plaintext `node.key` keeps loading after you opt in (it is not re-encrypted in place — regenerate or migrate the key to encrypt it). This mirrors the KMS at-rest encryption gated by `SIGNET_KMS_KEY`.

### Group membership

Group membership is not passed in API requests. At startup, the chain client calls `getNodeGroups(myAddr)` on the factory to discover which groups this node belongs to, then loads membership and threshold from each group contract.

It then stays in sync by polling for membership, issuer, auth-key, and resolver events. Each tick issues a single `eth_getLogs` covering the factory and every group at once, routing results by emitting address, so RPC cost is flat in group count rather than linear. The default interval is 60s (`chain_poll_secs`); devnet uses 2s since a local Anvil is free.

### Session coordination

When a node receives a keygen or sign request it acts as the **initiator**:

1. Opens a direct libp2p stream (`/signet/coord/1.0.0`) to each other party and sends a CBOR-encoded session invitation (type, group ID, key ID, auth proof if present).
2. Each receiving node verifies the auth proof independently, registers a session stream handler, and sends a ready ACK.
3. The initiator waits for all ACKs, then starts the FROST protocol.

### Message transport

All protocol messages travel over direct libp2p streams using a session-scoped protocol ID. Broadcast messages are fanned out as individual unicast sends. A `SessionNetwork` fans inbound messages into a single channel that the round-state machine consumes.

### Cryptography

Three schemes over one gRPC interface, implemented in Rust via `frost-core`, `frost-ed25519`, `frost-secp256k1`, and `k256`:

- **FROST Schnorr / secp256k1** (RFC 9591) — two-round signing
- **FROST Schnorr / Ed25519** (RFC 9591)
- **Threshold ECDSA / secp256k1** (DJNPO20) — 4-round robust protocol (3 presign + 1 sign), produces `ecrecover`-compatible signatures. Unlike FROST it is **not** T-of-N: signing a T-of-N key needs **at least `2T-1` signers in the session**, so a 3-of-6 group tolerates one node being down and a 2-of-3 group tolerates none. Below that bound the protocol completes and returns a well-formed signature that does not verify. See [docs/DESIGN-SIGNER-SELECTION.md](docs/DESIGN-SIGNER-SELECTION.md)

The production path runs keygen and signing in a dedicated Rust KMS process (`kms-tss`) connected to the Go node over a gRPC Unix domain socket. A Go fallback path (`--no-kms`) using `bytemare/frost` is retained for development; it supports FROST secp256k1 only.

See [docs/KMS-INTEGRATION.md](docs/KMS-INTEGRATION.md) for the KMS architecture, bug fixes, and performance comparison.

### Key storage

**With KMS (default):** Key material is persisted in sled on the KMS side, never transmitted to the Go node — the node only sees public keys. Sled keys are curve-prefixed (`0x01` secp256k1, `0x02` ed25519, `0x03` ecdsa_secp256k1), so the same `key_id` under different curves is a different key. Values can be encrypted at rest by setting `SIGNET_KMS_KEY`; note there is no migration path from a plaintext store, so enabling it on existing data requires a wipe.

**Without KMS (`--no-kms`):** Key shards are persisted in a bbolt database (`data_dir/keyshards.db`) in nested buckets: `keyshards → <groupID> → <keyID> → JSON`.

### Smart contracts

- `SignetFactory` — UUPS upgradeable factory. Registers nodes, deploys `SignetGroup` beacon proxies, maintains a reverse mapping of node → groups.
- `SignetGroup` — Per-group state: active member set, threshold, OAuth issuer registry, authorization-key registry, and a timelocked on-chain auth resolver binding. Notifies the factory on member activation/deactivation.
