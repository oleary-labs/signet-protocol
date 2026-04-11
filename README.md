# signet

Research implementation of a threshold signing network using FROST (RFC 9591) on secp256k1.

Nodes hold persistent secp256k1 identities, connect over a libp2p mesh, and expose an HTTP API for distributed key generation and threshold signing. Signatures are produced in Ethereum-compatible format (65-byte R+S+V).

Group membership and trust configuration are managed on-chain via `SignetFactory` and `SignetGroup` smart contracts. An optional ZK-based authentication layer lets clients prove OAuth identity without forwarding JWTs to the network.

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
cmd/signetd/       — node binary
cmd/devnet-init/   — key-init helper used by devnet scripts
cmd/harness/       — multi-node test harness (correctness + performance)
cmd/zkbench/       — ZK proof benchmark tool
node/              — HTTP API, coordinator, chain client, auth
tss/               — FROST adapter (keygen/sign round runner, Go fallback path)
kms-frost/         — Rust KMS: ZF FROST keygen/signing over gRPC (production default)
kms/               — gRPC client and generated protobuf (Go side)
network/           — libp2p host + session network
contracts/         — Solidity (Foundry): SignetFactory, SignetGroup
circuits/jwt_auth/ — Noir ZK circuit: JWT → session key binding
devnet/            — local devnet scripts (Anvil + 3 nodes + KMS instances)
docs/              — design and security documents
```

---

## Build

**Requirements:** Go 1.22+, Rust toolchain (for KMS)

```bash
git clone https://github.com/oleary-labs/signet-protocol
cd signet-protocol

go build ./cmd/signetd/

# Build the Rust KMS (production default)
cd kms-frost && cargo build --release
```

The node binary is `./signetd`. The KMS binary is `kms-frost/target/release/kms-frost`.

To run without the Rust KMS (in-process Go FROST, for development), pass `--no-kms` to the devnet scripts or omit `kms_socket` from the node config.

**Contracts** (requires [Foundry](https://getfoundry.sh)):

```bash
cd contracts && forge build
```

**ZK circuit** (requires [nargo](https://noir-lang.org) + [bb](https://github.com/AztecProtocol/aztec-packages)):

```bash
cd circuits/jwt_auth
nargo compile --force
```

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

# KMS (Rust FROST process)
kms_socket:       ""                           # Unix socket path to kms-frost; empty = in-process Go FROST

# Auth options
vk_path:          ""                           # path to circuit verification key (required for ZK auth)
```

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

### `GET /v1/keys`

Lists all key shards held by this node.

```
GET /v1/keys                       — all groups
GET /v1/keys?group_id=0xGroupAddr  — one group
```

```json
[
  {
    "group_id":         "0x...",
    "key_id":           "k1",
    "ethereum_address": "0xabc123...",
    "threshold":        1,
    "parties":          ["16Uiu2HAm...", "16Uiu2HAm...", "16Uiu2HAm..."]
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
- The node verifies the proof via `bb verify` against the circuit VK at `vk_path`

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

The signature is 65 bytes in Ethereum format (R ++ S ++ V).

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

### ZK auth (production)

The Noir circuit at `circuits/jwt_auth/` proves that a valid JWT signed by a trusted RSA key commits to a given session public key, without revealing the JWT to the network. The `bb verify` binary must be on `PATH` or at `~/.bb/bb`, and `vk_path` must point to the compiled circuit verification key.

See [docs/DESIGN-ZK-AUTH.md](docs/DESIGN-ZK-AUTH.md) and [docs/SECURITY-ANALYSIS.md](docs/SECURITY-ANALYSIS.md) for the full design and threat model.

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

# ZK circuit (requires nargo + bb)
cd circuits/jwt_auth && nargo compile --force && nargo execute bench_witness
bb prove -b target/jwt_auth.json -w target/bench_witness.gz -o target/proof --write_vk
bb verify -k target/proof/vk -p target/proof/proof -i target/proof/public_inputs
```

---

## Architecture notes

### Identity

Each node's libp2p peer ID is derived from a persistent secp256k1 private key stored in `data_dir/node.key`. The same key produces the node's Ethereum address, which is registered on-chain in `SignetFactory`.

### Group membership

Group membership is not passed in API requests. At startup, the chain client calls `getNodeGroups(myAddr)` on the factory to discover which groups this node belongs to, then loads membership and threshold from each group contract. It polls every two seconds for `NodeActivatedInGroup`, `NodeDeactivatedInGroup`, and issuer events to stay in sync with chain state.

### Session coordination

When a node receives a keygen or sign request it acts as the **initiator**:

1. Opens a direct libp2p stream (`/signet/coord/1.0.0`) to each other party and sends a CBOR-encoded session invitation (type, group ID, key ID, auth proof if present).
2. Each receiving node verifies the auth proof independently, registers a session stream handler, and sends a ready ACK.
3. The initiator waits for all ACKs, then starts the FROST protocol.

### Message transport

All protocol messages travel over direct libp2p streams using a session-scoped protocol ID. Broadcast messages are fanned out as individual unicast sends. A `SessionNetwork` fans inbound messages into a single channel that the round-state machine consumes.

### Cryptography

FROST (RFC 9591) on secp256k1, implemented via ZcashFoundation/frost (Rust). The production path runs FROST keygen and signing in a dedicated Rust KMS process (`kms-frost`) connected to the Go node over a gRPC Unix domain socket. A Go fallback path (`--no-kms`) using `bytemare/frost` is retained for development.

See [docs/KMS-INTEGRATION.md](docs/KMS-INTEGRATION.md) for the KMS architecture, bug fixes, and performance comparison.

### Key storage

**With KMS (default):** Key material (FROST `KeyPackage`, `PublicKeyPackage`) is persisted in sled on the KMS side, never transmitted to the Go node. The node only sees public keys.

**Without KMS (`--no-kms`):** Key shards are persisted in a bbolt database (`data_dir/keyshards.db`) in nested buckets: `keyshards → <groupID> → <keyID> → JSON`.

### Smart contracts

- `SignetFactory` — UUPS upgradeable factory. Registers nodes, deploys `SignetGroup` beacon proxies, maintains a reverse mapping of node → groups.
- `SignetGroup` — Per-group state: active member set, threshold, OAuth issuer registry with time-delayed add/remove. Notifies the factory on member activation/deactivation.
