#!/usr/bin/env bash
# devnet/start.sh — spin up a local Signet devnet:
#   • anvil  (local EVM, port 8545)
#   • SignetFactory deployed and all three nodes registered on-chain
#   • signetd node{1,2,3} with p2p + HTTP APIs

set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
DEVNET="$REPO/devnet"
CONTRACTS="$REPO/contracts"
BUILD="$REPO/build"
PIDS_FILE="$DEVNET/.pids"
ENV_FILE="$DEVNET/.env"

RPC="http://localhost:8545"

# Anvil account 0 — well-known deterministic test key.
DEPLOYER_ADDR="0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
DEPLOYER_PK="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

# --------------------------------------------------------------------------
die()  { echo "ERROR: $*" >&2; exit 1; }
info() { echo "==> $*"; }

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || die "'$1' not found — install Foundry (https://getfoundry.sh)"
}

require_cmd anvil
require_cmd forge
require_cmd cast
command -v jq >/dev/null 2>&1 || die "'jq' not found — install jq"

if [[ -f "$PIDS_FILE" ]]; then
    die "devnet appears to be running already (found $PIDS_FILE). Run devnet/stop.sh first."
fi

# --------------------------------------------------------------------------
# 1. Build binaries
# --------------------------------------------------------------------------
info "Building binaries..."
cd "$REPO"
mkdir -p "$BUILD"
go build -o "$BUILD/signetd"     ./cmd/signetd
go build -o "$BUILD/devnet-init" ./cmd/devnet-init

# --------------------------------------------------------------------------
# 2. Generate (or load) node identity keys, write configs
# --------------------------------------------------------------------------
info "Initialising node keys..."

NODE_JSON=$("$BUILD/devnet-init" data/node1 data/node2 data/node3)

get() { echo "$NODE_JSON" | jq -r ".nodes[$1].$2"; }

PEER_1=$(get 0 peer_id); PEER_2=$(get 1 peer_id); PEER_3=$(get 2 peer_id)
ADDR_1=$(get 0 eth_address); ADDR_2=$(get 1 eth_address); ADDR_3=$(get 2 eth_address)
PK_1=$(get 0 eth_privkey);   PK_2=$(get 1 eth_privkey);   PK_3=$(get 2 eth_privkey)
PUB_1=$(get 0 pubkey);       PUB_2=$(get 1 pubkey);       PUB_3=$(get 2 pubkey)

echo "    node1  peer=${PEER_1}  eth=${ADDR_1}"
echo "    node2  peer=${PEER_2}  eth=${ADDR_2}"
echo "    node3  peer=${PEER_3}  eth=${ADDR_3}"

# Write devnet-local config files (correct peer IDs baked in).
cat > "$DEVNET/node1.yaml" <<EOF
data_dir: ./data/node1
listen_addr: /ip4/0.0.0.0/tcp/9000
api_addr: :8080
bootstrap_peers:
  - /ip4/127.0.0.1/tcp/9001/p2p/${PEER_2}
  - /ip4/127.0.0.1/tcp/9002/p2p/${PEER_3}
node_type: public
EOF

cat > "$DEVNET/node2.yaml" <<EOF
data_dir: ./data/node2
listen_addr: /ip4/0.0.0.0/tcp/9001
api_addr: :8081
bootstrap_peers:
  - /ip4/127.0.0.1/tcp/9000/p2p/${PEER_1}
  - /ip4/127.0.0.1/tcp/9002/p2p/${PEER_3}
node_type: public
EOF

cat > "$DEVNET/node3.yaml" <<EOF
data_dir: ./data/node3
listen_addr: /ip4/0.0.0.0/tcp/9002
api_addr: :8082
bootstrap_peers:
  - /ip4/127.0.0.1/tcp/9000/p2p/${PEER_1}
  - /ip4/127.0.0.1/tcp/9001/p2p/${PEER_2}
node_type: public
EOF

# --------------------------------------------------------------------------
# 3. Start Anvil
# --------------------------------------------------------------------------
info "Starting anvil (port 8545, 1-second blocks)..."
anvil \
    --port 8545 \
    --block-time 1 \
    --silent \
    > "$DEVNET/anvil.log" 2>&1 &
echo "ANVIL_PID=$!" > "$PIDS_FILE"

# Wait for anvil to accept connections (up to 10 s).
for i in $(seq 1 40); do
    cast block-number --rpc-url "$RPC" >/dev/null 2>&1 && break
    sleep 0.25
    [[ $i -eq 40 ]] && die "anvil did not start within 10 s — see devnet/anvil.log"
done

# --------------------------------------------------------------------------
# 4. Deploy factory
# --------------------------------------------------------------------------
info "Deploying SignetFactory..."
cd "$CONTRACTS"

DEPLOY_OUT=$(
    ADMIN_ADDRESS="$DEPLOYER_ADDR" \
    forge script script/DeployFactory.s.sol \
        --rpc-url "$RPC" \
        --broadcast \
        --private-key "$DEPLOYER_PK" 2>&1
)

# Extract addresses from the machine-readable DEPLOY: lines.
_deploy_val() { echo "$DEPLOY_OUT" | grep "DEPLOY:$1=" | sed "s/.*DEPLOY:$1=//"; }
FACTORY=$(_deploy_val factory)
GROUP_IMPL=$(_deploy_val groupImpl)
BEACON=$(_deploy_val beacon)

[[ -z "$FACTORY" ]] && {
    echo "$DEPLOY_OUT" >&2
    die "could not parse factory address — see output above"
}

echo "    factory:   $FACTORY"
echo "    beacon:    $BEACON"
echo "    groupImpl: $GROUP_IMPL"

cd "$REPO"

# --------------------------------------------------------------------------
# 5. Fund node addresses and register them on-chain
# --------------------------------------------------------------------------
info "Funding and registering nodes..."

for i in 1 2 3; do
    addr_var="ADDR_$i"; pk_var="PK_$i"; pub_var="PUB_$i"
    ADDR="${!addr_var}"; PK="${!pk_var}"; PUB="${!pub_var}"

    # Send 0.1 ETH from the deployer so the node can pay for its own registration.
    cast send \
        --private-key "$DEPLOYER_PK" \
        --rpc-url "$RPC" \
        "$ADDR" \
        --value 0.1ether \
        >/dev/null

    # registerNode(bytes pubkey, bool isOpen) — must come from the node's own address.
    cast send \
        --private-key "$PK" \
        --rpc-url "$RPC" \
        "$FACTORY" \
        "registerNode(bytes,bool)" "$PUB" true \
        >/dev/null

    echo "    node${i} registered: ${ADDR}"
done

# --------------------------------------------------------------------------
# 6. Start signet nodes
# --------------------------------------------------------------------------
info "Starting signet nodes..."

for i in 1 2 3; do
    "$BUILD/signetd" \
        -config "$DEVNET/node${i}.yaml" \
        -log-level info \
        > "$DEVNET/node${i}.log" 2>&1 &
    echo "NODE${i}_PID=$!" >> "$PIDS_FILE"
done

# Wait for all three HTTP APIs to be healthy (up to 15 s).
wait_http() {
    local url="$1" label="$2"
    for i in $(seq 1 60); do
        curl -sf "$url" >/dev/null 2>&1 && return 0
        sleep 0.25
    done
    die "$label did not become healthy — see devnet/${label}.log"
}

wait_http "http://localhost:8080/v1/health" "node1"
wait_http "http://localhost:8081/v1/health" "node2"
wait_http "http://localhost:8082/v1/health" "node3"

# --------------------------------------------------------------------------
# 7. Write .env summary and print status
# --------------------------------------------------------------------------
cat > "$ENV_FILE" <<EOF
RPC_URL=${RPC}
FACTORY_ADDRESS=${FACTORY}
GROUP_BEACON=${BEACON}
GROUP_IMPL=${GROUP_IMPL}
NODE1_PEER=${PEER_1}
NODE2_PEER=${PEER_2}
NODE3_PEER=${PEER_3}
NODE1_ETH=${ADDR_1}
NODE2_ETH=${ADDR_2}
NODE3_ETH=${ADDR_3}
NODE1_API=http://localhost:8080
NODE2_API=http://localhost:8081
NODE3_API=http://localhost:8082
EOF

echo ""
echo "Signet devnet is up."
echo ""
echo "  Chain RPC : $RPC"
echo "  Factory   : $FACTORY"
echo "  Beacon    : $BEACON"
echo ""
echo "  node1  eth=${ADDR_1}  api=:8080  p2p=:9000"
echo "  node2  eth=${ADDR_2}  api=:8081  p2p=:9001"
echo "  node3  eth=${ADDR_3}  api=:8082  p2p=:9002"
echo ""
echo "  Env file  : devnet/.env"
echo "  Logs      : devnet/{anvil,node1,node2,node3}.log"
echo "  Stop      : devnet/stop.sh"
echo ""
echo "Quick test (keygen):"
echo "  curl -s http://localhost:8080/v1/info | jq ."
echo "  curl -s -X POST http://localhost:8080/v1/keygen \\"
echo "    -d '{\"session_id\":\"key1\",\"parties\":[\"${PEER_1}\",\"${PEER_2}\",\"${PEER_3}\"],\"threshold\":1}' | jq ."
