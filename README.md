# signet

Research implementation of a threshold signing network using a custom LSS (Linear Secret Sharing) MPC protocol over libp2p.

Nodes hold persistent secp256k1 identities, connect to each other over a libp2p mesh, and expose an HTTP API for distributed key generation and threshold signing. Signatures are produced in Ethereum-compatible format (65-byte R+S+V).

A client sends a single request to **any one node** in the group. That node coordinates the session with the other participants automatically — no need to contact every node separately.

---

## Contents

- [Build](#build)
- [Configuration](#configuration)
- [Running a network](#running-a-network)
- [API reference](#api-reference)
- [End-to-end walkthrough](#end-to-end-walkthrough)
- [Running tests](#running-tests)
- [Architecture notes](#architecture-notes)

---

## Build

**Requirements:** Go 1.22+

```bash
git clone https://github.com/oleary-labs/signet-research
cd signet-research

go build ./cmd/signetd/
```

The binary is `./signetd`.

---

## Configuration

On first run `signetd` writes a default `config.yaml` if none exists:

```yaml
key_file: ./data/node.key             # secp256k1 identity key (created on first run)
listen_addr: /ip4/0.0.0.0/tcp/9000   # libp2p listen multiaddr
api_addr: :8080                       # HTTP API listen address
announce_addr: ""                     # optional public multiaddr to advertise
bootstrap_peers: []                   # multiaddrs of peers to dial on startup
node_type: public                     # "public" or "permissioned"
```

Pass a custom config file with `-config`:

```bash
./signetd -config node1.yaml
```

### Log level

Control verbosity with `-log-level` (default `info`):

```bash
./signetd -config node1.yaml -log-level debug
```

Accepted values: `debug`, `info`, `warn`, `error`.

---

## Running a network

### Local three-node setup

**Node 1** — start first, note the peer ID printed at startup:

```bash
cat > node1.yaml <<EOF
key_file: ./data/node1.key
listen_addr: /ip4/0.0.0.0/tcp/9000
api_addr: :8080
node_type: public
EOF

./signetd -config node1.yaml
# INFO  node ready  {"peer_id": "16Uiu2HAmXXX...", "addrs": ["/ip4/0.0.0.0/tcp/9000"]}
```

**Node 2** — use node 1's peer ID in `bootstrap_peers`:

```bash
cat > node2.yaml <<EOF
key_file: ./data/node2.key
listen_addr: /ip4/0.0.0.0/tcp/9001
api_addr: :8081
bootstrap_peers:
  - /ip4/127.0.0.1/tcp/9000/p2p/16Uiu2HAmXXX...
node_type: public
EOF

./signetd -config node2.yaml
# INFO  connected to bootstrap peer  {"peer": "16Uiu2HAmXXX..."}
```

**Node 3** — bootstrap from either existing node:

```bash
cat > node3.yaml <<EOF
key_file: ./data/node3.key
listen_addr: /ip4/0.0.0.0/tcp/9002
api_addr: :8082
bootstrap_peers:
  - /ip4/127.0.0.1/tcp/9000/p2p/16Uiu2HAmXXX...
node_type: public
EOF

./signetd -config node3.yaml
```

Once all three nodes are running and connected, proceed to the walkthrough below.

### Key persistence

After keygen, each node writes its secret share to `data/<session_id>.config` (CBOR, mode `0600`). On a subsequent sign request, the file is loaded automatically if the config is not already in memory.

---

## API reference

All endpoints speak JSON. Keygen and sign requests **block** until the protocol completes and return the result to the caller.

**A client only needs to contact one node.** The receiving node coordinates with the other participants over the internal `/signet/coord/1.0.0` libp2p protocol — it sends each other party a CBOR-encoded session invitation, waits for ready ACKs, then starts the cryptographic protocol once all parties have joined.

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

Lists all keygen configs held in memory (public metadata only).

```json
[
  {
    "session_id":       "mykey1",
    "ethereum_address": "0xabc123...",
    "threshold":        1,
    "parties":          ["16Uiu2HAm...", "16Uiu2HAm...", "16Uiu2HAm..."]
  }
]
```

### `POST /v1/keygen`

Runs a distributed key generation session (LSS protocol, 3 rounds).

Send to **any one node** in the `parties` list. It will coordinate with the others.

Request:

```json
{
  "session_id": "mykey1",
  "parties":    ["16Uiu2HAm...", "16Uiu2HAm...", "16Uiu2HAm..."],
  "threshold":  1
}
```

- `session_id` — unique identifier for this key; used as the session topic name and the filename for the persisted config
- `parties` — peer IDs of every participating node (obtain from `GET /v1/info` on each node)
- `threshold` — maximum corruptions tolerated; `threshold + 1` parties are required to produce a signature

Response (once the protocol completes):

```json
{
  "session_id":       "mykey1",
  "public_key":       "0x03abcd...",
  "ethereum_address": "0xabc123..."
}
```

### `POST /v1/sign`

Runs a threshold signing session (LSS protocol, 3 rounds).

Send to **any one node** in the `signers` list. It will coordinate with the others.

Request:

```json
{
  "key_session_id":  "mykey1",
  "sign_session_id": "sign-001",
  "signers":         ["16Uiu2HAm...", "16Uiu2HAm..."],
  "message_hash":    "0xdeadbeef..."
}
```

- `key_session_id` — the `session_id` used during keygen
- `sign_session_id` — unique identifier for this signing round; must differ for every signature
- `signers` — peer IDs of the signing subset; must include the node being contacted and satisfy `threshold + 1`
- `message_hash` — 32-byte hash to sign (hex, `0x` prefix optional)

Response:

```json
{
  "sign_session_id":    "sign-001",
  "ethereum_signature": "0x..."
}
```

The signature is 65 bytes in Ethereum format (R ++ S ++ V).

---

## End-to-end walkthrough

This example uses three nodes running locally at ports 8080–8082. Substitute the actual peer IDs from your nodes.

### 1. Fetch peer IDs

```bash
NODE1=$(curl -s :8080/v1/info | jq -r .peer_id)
NODE2=$(curl -s :8081/v1/info | jq -r .peer_id)
NODE3=$(curl -s :8082/v1/info | jq -r .peer_id)

echo $NODE1 $NODE2 $NODE3
```

### 2. Keygen (threshold = 1, any 2-of-3 can sign)

Send a single request to node 1. It contacts nodes 2 and 3 automatically.

```bash
curl -s -X POST :8080/v1/keygen \
  -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg a "$NODE1" --arg b "$NODE2" --arg c "$NODE3" \
    '{"session_id":"mykey1","parties":[$a,$b,$c],"threshold":1}')"
```

Response:

```json
{
  "session_id":       "mykey1",
  "public_key":       "0x03abcd...",
  "ethereum_address": "0xabc123..."
}
```

All three nodes now hold their secret shares. The public key and Ethereum address are the same on every node.

### 3. Sign a message hash

Send a single request to node 1. It contacts node 2 automatically.

```bash
HASH="0x$(openssl dgst -sha256 -binary <<< 'hello signet' | xxd -p -c 32)"

curl -s -X POST :8080/v1/sign \
  -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg a "$NODE1" --arg b "$NODE2" --arg h "$HASH" \
    '{"key_session_id":"mykey1","sign_session_id":"sign-001","signers":[$a,$b],"message_hash":$h}')"
```

Response:

```json
{
  "sign_session_id":    "sign-001",
  "ethereum_signature": "0x..."
}
```

The 65-byte signature can be verified on-chain against the Ethereum address returned by keygen.

---

## Running tests

```bash
# All tests (includes libp2p keygen integration test, ~1 min)
go test ./...

# Verbose output
go test -v ./...

# Just the fast unit tests
go test -run TestEthereumAddress ./...

# Just the keygen integration test
go test -v -run TestLibp2pKeygen -timeout 3m ./...
```

---

## Architecture notes

### Identity

Each node's libp2p peer ID is derived from a persistent secp256k1 private key (`key_file`). This same key is used as the node's `lss.PartyID` in the LSS protocol — threshold key shares are permanently bound to the node's network identity.

### Session coordination

When a node receives a keygen or sign request it acts as the **initiator**:

1. Subscribes to the session's GossipSub topic (so it is ready before peers start sending)
2. Opens a direct libp2p stream (`/signet/coord/1.0.0`) to each other party and sends a CBOR-encoded invitation containing the session parameters
3. Each receiving node subscribes to the topic, then sends a ready ACK
4. The initiator waits for all ACKs, pauses briefly for the GossipSub mesh to form, then starts the CMP protocol handler

### Message transport

The LSS protocol sends two kinds of messages per round:

| Type | Transport | How |
|---|---|---|
| Directed (unicast) | libp2p stream | `/signet/session/1.0.0` protocol, CBOR payload |
| Broadcast | GossipSub | `/signet/session/<id>` topic, CBOR payload |

A `SessionNetwork` joins the per-session GossipSub topic and fans both message types into a single `Incoming()` channel. `lss.Run()` drives the round state machine: it calls `Finalize()`, sends outgoing messages, and advances rounds as messages arrive.

### Protocol

LSS (Linear Secret Sharing) is a 3-round semi-honest threshold ECDSA protocol. Keygen runs 3 rounds; signing runs 3 rounds. After keygen every party holds a distinct secret share; during signing, `threshold + 1` parties collaborate to reconstruct the signature without any party ever holding the full private key.

### Key storage

After keygen, each party's secret share is persisted to `data/<session_id>.config` using CBOR serialization (the library's own `MarshalBinary` format). The file is written with mode `0600`. On a sign request, configs are loaded from disk on first access and cached in memory for subsequent requests.
