#!/usr/bin/env bash
# testnet/scripts/init-nodes.sh — Generate node identities for the testnet.
#
# Creates 3 node key directories under testnet/data/node{1..3}, runs devnet-init
# to generate deterministic identities, and writes Ansible host_vars files with
# peer_id, eth_address, eth_privkey, and pubkey for each node.
#
# Usage:
#   testnet/scripts/init-nodes.sh

set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
TESTNET="$REPO/testnet"
BUILD="$REPO/build"
HOST_VARS="$TESTNET/ansible/host_vars"

# Build devnet-init if needed.
if [[ ! -x "$BUILD/devnet-init" ]]; then
    echo "==> Building devnet-init..."
    (cd "$REPO" && go build -o "$BUILD/devnet-init" ./cmd/devnet-init)
fi

# Node names — first 3 are AWS (bootstrap group), 4th is GCP (added later).
NODE_NAMES=(node1 node2 node3 signet-testnet1)
NODE_DIRS=()
for name in "${NODE_NAMES[@]}"; do
    NODE_DIRS+=("$TESTNET/data/$name")
done

# Generate identities.
echo "==> Generating node identities..."
mkdir -p "$TESTNET/data"
NODE_JSON=$("$BUILD/devnet-init" "${NODE_DIRS[@]}")

echo "$NODE_JSON" > "$TESTNET/data/nodes.json"

get() { echo "$NODE_JSON" | jq -r ".nodes[$1].$2"; }

# Write Ansible host_vars for each node.
mkdir -p "$HOST_VARS"
for i in $(seq 0 $((${#NODE_NAMES[@]} - 1))); do
    name="${NODE_NAMES[$i]}"
    PEER=$(get $i peer_id)
    ADDR=$(get $i eth_address)
    PK=$(get $i eth_privkey)
    PUB=$(get $i pubkey)
    DATA=$(get $i data_dir)

    cat > "$HOST_VARS/${name}.yml" <<EOF
---
peer_id: "${PEER}"
eth_address: "${ADDR}"
eth_privkey: "${PK}"
pubkey: "${PUB}"
local_node_key_path: "${DATA}/node.key"
EOF

    echo "    ${name}  peer=${PEER}  eth=${ADDR}"
done

echo ""
echo "Node identities written to:"
echo "  Data:      testnet/data/{${NODE_NAMES[*]}}/"
echo "  Host vars: testnet/ansible/host_vars/{${NODE_NAMES[*]}}.yml"
echo "  JSON:      testnet/data/nodes.json"
