#!/usr/bin/env bash
# testnet/scripts/deploy-contracts.sh — Deploy SignetFactory to Sepolia,
# fund and register nodes, create a 2-of-3 signing group with Google OAuth.
#
# Prerequisites:
#   - Node identities generated (run init-nodes.sh first)
#   - Environment variables:
#       SEPOLIA_RPC_URL    — Alchemy/Infura Sepolia endpoint
#       DEPLOYER_PK        — Private key with Sepolia ETH for deployment
#   - Foundry (forge, cast) installed
#
# Usage:
#   SEPOLIA_RPC_URL=https://eth-sepolia.g.alchemy.com/v2/... \
#   DEPLOYER_PK=0x... \
#   testnet/scripts/deploy-contracts.sh

set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
TESTNET="$REPO/testnet"
CONTRACTS="$REPO/contracts"
NODES_JSON="$TESTNET/data/nodes.json"
ENV_FILE="$TESTNET/.env"

# --------------------------------------------------------------------------
# Validate
# --------------------------------------------------------------------------
die()  { echo "ERROR: $*" >&2; exit 1; }
info() { echo "==> $*"; }

[[ -z "${SEPOLIA_RPC_URL:-}" ]] && die "SEPOLIA_RPC_URL not set"
[[ -z "${DEPLOYER_PK:-}" ]] && die "DEPLOYER_PK not set"
[[ -f "$NODES_JSON" ]] || die "nodes.json not found — run init-nodes.sh first"

command -v forge >/dev/null 2>&1 || die "'forge' not found — install Foundry"
command -v cast >/dev/null 2>&1 || die "'cast' not found — install Foundry"
command -v jq >/dev/null 2>&1 || die "'jq' not found"

RPC="$SEPOLIA_RPC_URL"
DEPLOYER_ADDR=$(cast wallet address "$DEPLOYER_PK")
NUM_NODES=$(jq '.nodes | length' "$NODES_JSON")
# Bootstrap group uses the first 3 nodes. Additional nodes are registered
# but not included in the initial group (added later via on-chain ops).
BOOTSTRAP_NODES="${BOOTSTRAP_NODES:-3}"

info "Deployer:        $DEPLOYER_ADDR"
info "RPC:             $RPC"
info "Total nodes:     $NUM_NODES"
info "Bootstrap group: $BOOTSTRAP_NODES"

# --------------------------------------------------------------------------
# 1. Deploy factory
# --------------------------------------------------------------------------
info "Deploying SignetFactory to Sepolia..."
cd "$CONTRACTS"

DEPLOY_OUT=$(
    ADMIN_ADDRESS="$DEPLOYER_ADDR" \
    forge script script/DeployFactory.s.sol \
        --rpc-url "$RPC" \
        --broadcast \
        --private-key "$DEPLOYER_PK" 2>&1
)

_deploy_val() { echo "$DEPLOY_OUT" | grep "DEPLOY:$1=" | sed "s/.*DEPLOY:$1=//"; }
FACTORY=$(_deploy_val factory)
GROUP_IMPL=$(_deploy_val groupImpl)
BEACON=$(_deploy_val beacon)

[[ -z "$FACTORY" ]] && {
    echo "$DEPLOY_OUT" >&2
    die "Could not parse factory address"
}

info "Factory:   $FACTORY"
info "Beacon:    $BEACON"
info "GroupImpl: $GROUP_IMPL"

cd "$REPO"

# --------------------------------------------------------------------------
# 2. Fund nodes and register on-chain
# --------------------------------------------------------------------------
info "Funding and registering nodes..."

ADDR_LIST=""
for i in $(seq 0 $((NUM_NODES - 1))); do
    n=$((i + 1))
    ADDR=$(jq -r ".nodes[$i].eth_address" "$NODES_JSON")
    PK=$(jq -r ".nodes[$i].eth_privkey" "$NODES_JSON")
    PUB=$(jq -r ".nodes[$i].pubkey" "$NODES_JSON")

    # Fund node with 0.01 Sepolia ETH (enough for registration tx).
    cast send \
        --private-key "$DEPLOYER_PK" \
        --rpc-url "$RPC" \
        "$ADDR" \
        --value 0.01ether \
        >/dev/null

    # Register node: registerNode(bytes pubkey, bool isOpen, address operator)
    cast send \
        --private-key "$PK" \
        --rpc-url "$RPC" \
        "$FACTORY" \
        "registerNode(bytes,bool,address)" "$PUB" true "0x0000000000000000000000000000000000000000" \
        >/dev/null

    info "  node${n} registered: ${ADDR}"

    if [[ -n "$ADDR_LIST" ]]; then
        ADDR_LIST="${ADDR_LIST},${ADDR}"
    else
        ADDR_LIST="${ADDR}"
    fi
done

# --------------------------------------------------------------------------
# 3. Create signing group (2-of-3: threshold=2, quorum=2) with Google OAuth
# --------------------------------------------------------------------------
info "Creating signing group (threshold=2, $BOOTSTRAP_NODES nodes)..."

# Build address list for the bootstrap group only.
BOOTSTRAP_ADDR_LIST=""
for i in $(seq 0 $((BOOTSTRAP_NODES - 1))); do
    ADDR=$(jq -r ".nodes[$i].eth_address" "$NODES_JSON")
    if [[ -n "$BOOTSTRAP_ADDR_LIST" ]]; then
        BOOTSTRAP_ADDR_LIST="${BOOTSTRAP_ADDR_LIST},${ADDR}"
    else
        BOOTSTRAP_ADDR_LIST="${ADDR}"
    fi
done

# Issuers are added post-deploy via addIssuer() — start with an empty list
# so the group is initially unauthenticated (easier to test).
ISSUERS="[]"

GROUP_CREATED_TOPIC=$(cast keccak "GroupCreated(address,address,uint256)")

CREATE_RECEIPT=$(cast send \
    --private-key "$DEPLOYER_PK" \
    --rpc-url "$RPC" \
    "$FACTORY" \
    "createGroup(address[],uint256,uint256,(string,string[])[],bytes[])" \
    "[$BOOTSTRAP_ADDR_LIST]" 2 600 "$ISSUERS" "[]" \
    --json)

GROUP_RAW=$(echo "$CREATE_RECEIPT" | jq -r \
    --arg topic "$GROUP_CREATED_TOPIC" \
    '.logs[] | select(.topics[0] == $topic) | .topics[1]')
GROUP="0x${GROUP_RAW: -40}"

[[ -z "$GROUP" || "$GROUP" == "0x" ]] && die "Could not parse group address from receipt"

info "Group: $GROUP (threshold=2, bootstrap=$BOOTSTRAP_NODES, total=$NUM_NODES)"

# --------------------------------------------------------------------------
# 4. Write .env file
# --------------------------------------------------------------------------
info "Writing testnet/.env..."

{
    echo "RPC_URL=${RPC}"
    echo "FACTORY_ADDRESS=${FACTORY}"
    echo "GROUP_BEACON=${BEACON}"
    echo "GROUP_IMPL=${GROUP_IMPL}"
    echo "GROUP_ADDRESS=${GROUP}"
    echo "USE_KMS=true"
    echo ""

    # Read IPs from .hosts if available, otherwise leave API URLs as placeholders.
    HOSTS_FILE="$TESTNET/.hosts"
    for i in $(seq 0 $((NUM_NODES - 1))); do
        n=$((i + 1))
        ADDR=$(jq -r ".nodes[$i].eth_address" "$NODES_JSON")
        PEER=$(jq -r ".nodes[$i].peer_id" "$NODES_JSON")

        echo "NODE${n}_ETH=${ADDR}"
        echo "NODE${n}_PEER=${PEER}"

        if [[ -f "$HOSTS_FILE" ]]; then
            IP=$(grep "^node${n}=" "$HOSTS_FILE" | cut -d= -f2)
            echo "NODE${n}_API=http://${IP}:8080"
        else
            echo "NODE${n}_API=http://FILL_IP:8080"
        fi
    done

    # Region annotations for harness output.
    echo ""
    echo "NODE1_REGION=us-east-1a"
    echo "NODE2_REGION=us-east-1b"
    echo "NODE3_REGION=us-east-1c"
} > "$ENV_FILE"

# Also export FACTORY_ADDRESS for Ansible to pick up.
echo ""
echo "Deployment complete."
echo ""
echo "  Factory: $FACTORY"
echo "  Group:   $GROUP"
echo "  Env:     testnet/.env"
echo ""
echo "Next steps:"
echo "  1. Cross-compile: GOOS=linux GOARCH=amd64 go build -o build/signetd-linux-amd64 ./cmd/signetd"
echo "  2. Deploy nodes:  cd testnet/ansible && FACTORY_ADDRESS=$FACTORY SEPOLIA_RPC_URL=$RPC ansible-playbook deploy.yml"
echo "  3. Run harness:   ./build/harness -env testnet/.env correctness"
