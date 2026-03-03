# Signet Devnet

Scripts for running a local three-node Signet devnet backed by a local Anvil
chain. The devnet handles everything in one command: key generation, contract
deployment, on-chain node registration, and node startup.

## Prerequisites

| Tool | How to install |
|------|---------------|
| Go ≥ 1.22 | https://go.dev/dl |
| Foundry (`anvil`, `forge`, `cast`) | `curl -L https://foundry.paradigm.xyz \| bash && foundryup` |
| `jq` | `brew install jq` / `apt install jq` |

All commands are run from the **repository root**.

## Scripts

| Script | Purpose |
|--------|---------|
| `devnet/start.sh` | Start the devnet (anvil + contracts + nodes) |
| `devnet/stop.sh` | Stop all devnet processes |
| `devnet/clean.sh` | Delete all generated state (data dirs, logs) |

## Start

```
devnet/start.sh
```

`start.sh` performs these steps in order:

1. **Build** `signetd` and `devnet-init` from source.

2. **Generate node keys.** `devnet-init` reads `data/node{1,2,3}/node.key`
   (creating each file if it does not exist) and outputs a JSON summary
   containing each node's libp2p peer ID, Ethereum address, uncompressed
   secp256k1 public key, and raw Ethereum private key. Because keys are
   written before anything else starts, the devnet is fully deterministic
   across restarts as long as the data directories are kept.

3. **Write node configs.** Generates `devnet/node{1,2,3}.yaml` with the
   correct peer IDs baked into the `bootstrap_peers` field.

4. **Start Anvil** on `http://localhost:8545` with 1-second block times.
   Uses the standard Foundry test mnemonic so account addresses are
   deterministic.

5. **Deploy `SignetFactory`.** Runs `forge script contracts/script/DeployFactory.s.sol`
   with the Anvil deployer key. The factory owner is set to Anvil account 0.
   Deployed addresses are parsed from the script output and saved to
   `devnet/.env`.

6. **Register nodes.** Each node's Ethereum address is funded with 0.1 ETH
   from the deployer, then `registerNode(bytes pubkey, bool isOpen)` is called
   from that node's own address. Registration validates that
   `keccak256(pubkey[1:65]) == msg.sender`, linking the on-chain identity to
   the libp2p key.

7. **Start signetd nodes** on the ports below and wait for their health
   endpoints to respond.

On success the terminal prints a summary:

```
Signet devnet is up.

  Chain RPC : http://localhost:8545
  Factory   : 0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0
  Beacon    : 0x75537828f2ce51be7289709686A69CbFDbB714F1

  node1  eth=0x0a1d...  api=:8080  p2p=:9000
  node2  eth=0x9c9a...  api=:8081  p2p=:9001
  node3  eth=0x51e7...  api=:8082  p2p=:9002

  Env file  : devnet/.env
  Logs      : devnet/{anvil,node1,node2,node3}.log
  Stop      : devnet/stop.sh
```

## Ports

| Service | Port | Protocol |
|---------|------|----------|
| Anvil RPC | 8545 | HTTP |
| node1 HTTP API | 8080 | HTTP |
| node2 HTTP API | 8081 | HTTP |
| node3 HTTP API | 8082 | HTTP |
| node1 libp2p | 9000 | TCP |
| node2 libp2p | 9001 | TCP |
| node3 libp2p | 9002 | TCP |

## Generated files

`start.sh` writes these files (all gitignored):

| File | Contents |
|------|----------|
| `devnet/.env` | Factory address, RPC URL, node addresses and peer IDs |
| `devnet/node{1,2,3}.yaml` | Per-node signetd config with peer IDs baked in |
| `devnet/anvil.log` | Anvil stdout/stderr |
| `devnet/node{1,2,3}.log` | signetd stdout/stderr |
| `devnet/.pids` | PIDs used by `stop.sh` |
| `data/node{1,2,3}/node.key` | Persistent libp2p identity keys |
| `data/node{1,2,3}/keyshards.db` | bbolt key-shard store |

## Stop

```
devnet/stop.sh
```

Sends `SIGTERM` to all processes tracked in `devnet/.pids` and removes the
file. The data directories and logs are preserved so the devnet can be
restarted without re-registering nodes.

## Restart (keeping existing keys)

```
devnet/stop.sh
devnet/start.sh
```

Keys in `data/node*/node.key` are reused, so the same peer IDs and Ethereum
addresses come back. Steps 5–6 (deployment and registration) run again
because Anvil's state is ephemeral; a fresh chain is started each time.

## Clean reset

```
devnet/stop.sh   # must stop first
devnet/clean.sh
```

Deletes `data/node{1,2,3}/`, all logs, and all generated config files.
The next `start.sh` will generate new keys and redeploy everything.

## Interacting with the devnet

Source the env file to get the addresses into your shell:

```bash
source devnet/.env
```

### Node info

```bash
curl -s http://localhost:8080/v1/info | jq .
```

### Keygen (2-of-3)

Send a keygen request to any one node; it coordinates with the others
automatically.

```bash
source devnet/.env

curl -s -X POST http://localhost:8080/v1/keygen \
  -H 'Content-Type: application/json' \
  -d "{
    \"session_id\": \"key1\",
    \"parties\":    [\"$NODE1_PEER\", \"$NODE2_PEER\", \"$NODE3_PEER\"],
    \"threshold\":  1
  }" | jq .
```

Response:

```json
{
  "session_id": "key1",
  "public_key": "0x02...",
  "ethereum_address": "0x..."
}
```

### Sign

```bash
source devnet/.env

curl -s -X POST http://localhost:8080/v1/sign \
  -H 'Content-Type: application/json' \
  -d "{
    \"key_session_id\":  \"key1\",
    \"sign_session_id\": \"sig1\",
    \"signers\":         [\"$NODE1_PEER\", \"$NODE2_PEER\"],
    \"message_hash\":    \"0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef\"
  }" | jq .
```

Response:

```json
{
  "sign_session_id": "sig1",
  "ethereum_signature": "0x..."
}
```

### Query the factory contract

```bash
source devnet/.env

# Check a registered node
cast call $FACTORY_ADDRESS "getNode(address)(bytes,bool,bool,uint256)" \
  $NODE1_ETH --rpc-url $RPC_URL

# List all registered nodes
cast call $FACTORY_ADDRESS "getRegisteredNodes()(address[])" \
  --rpc-url $RPC_URL
```

## Architecture

```
devnet/start.sh
│
├── go build ./cmd/devnet-init   (key init tool)
├── go build ./cmd/signetd       (node binary)
│
├── devnet-init data/node{1,2,3}
│     Reads or generates secp256k1 keys.
│     Outputs JSON: peer_id, eth_address, eth_privkey, pubkey (65-byte uncompressed).
│
├── anvil --port 8545
│
├── forge script DeployFactory.s.sol --broadcast
│     Deploys: SignetGroup impl → SignetFactory impl → ERC1967Proxy (factory)
│              └─ initialize() deploys UpgradeableBeacon inside the proxy tx
│
├── cast send  (×3)  fund each node address (0.1 ETH from deployer)
├── cast send  (×3)  registerNode(pubkey, isOpen=true) from each node's own key
│
└── signetd -config devnet/node{1,2,3}.yaml  (×3)
```
