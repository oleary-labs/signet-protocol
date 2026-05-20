#!/usr/bin/env bash
# devnet/start.sh — spin up a local Signet devnet:
#   • anvil  (local EVM, port 8545)
#   • SignetFactory deployed and all three nodes registered on-chain
#   • A SignetGroup created with all three nodes as members
#   • kms-tss instances (one per node, unless --no-kms)
#   • signetd node{1,2,3} with p2p + HTTP APIs
#
# Usage:
#   devnet/start.sh                  # default: nodes use external Rust KMS, no auth
#   devnet/start.sh --no-kms         # nodes use in-process Go TSS (no KMS)
#   devnet/start.sh --auth           # seed Google OAuth issuer (ZK auth required)
#   devnet/start.sh --no-kms --auth  # Go TSS + ZK auth

set -euo pipefail

# Parse flags.
USE_KMS=true
USE_AUTH=false
for arg in "$@"; do
    case "$arg" in
        --no-kms) USE_KMS=false ;;
        --auth)   USE_AUTH=true ;;
        *) echo "Unknown flag: $arg" >&2; exit 1 ;;
    esac
done

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

if $USE_KMS; then
    info "Building kms-tss..."
    command -v cargo >/dev/null 2>&1 || die "'cargo' not found — install Rust (https://rustup.rs)"
    (cd "$REPO/kms-tss" && cargo build --release --quiet)
    cp "$REPO/kms-tss/target/release/kms-tss" "$BUILD/kms-tss"
    # macOS invalidates adhoc code signatures on copy; re-sign.
    codesign -s - "$BUILD/kms-tss" 2>/dev/null || true
fi

# --------------------------------------------------------------------------
# 2. Generate (or load) node identity keys
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

# --------------------------------------------------------------------------
# 3. Start Anvil
# --------------------------------------------------------------------------
info "Starting anvil (port 8545, 12-second blocks)..."
anvil \
    --port 8545 \
    --block-time 12 \
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

# --------------------------------------------------------------------------
# 4b. Deploy SignetAccountFactory (from signet-wallet repo)
# --------------------------------------------------------------------------
WALLET_REPO="$REPO/../signet-wallet"
if [[ -d "$WALLET_REPO" ]]; then
    info "Deploying SignetAccountFactory..."
    cd "$WALLET_REPO"

    ACCT_DEPLOY_OUT=$(
        forge script script/DeploySignetAccountFactory.s.sol \
            --rpc-url "$RPC" \
            --broadcast \
            --private-key "$DEPLOYER_PK" 2>&1
    )

    ACCOUNT_FACTORY=$(echo "$ACCT_DEPLOY_OUT" | grep "DEPLOY:accountFactory=" | sed "s/.*DEPLOY:accountFactory=//")

    [[ -z "$ACCOUNT_FACTORY" ]] && {
        echo "$ACCT_DEPLOY_OUT" >&2
        die "could not parse account factory address — see output above"
    }

    echo "    accountFactory: $ACCOUNT_FACTORY"

    info "Deploying FROSTValidator..."
    VALIDATOR_DEPLOY_OUT=$(
        forge script script/DeployFROSTValidator.s.sol \
            --rpc-url "$RPC" \
            --broadcast \
            --private-key "$DEPLOYER_PK" 2>&1
    )

    FROST_VALIDATOR=$(echo "$VALIDATOR_DEPLOY_OUT" | grep "DEPLOY:frostValidator=" | sed "s/.*DEPLOY:frostValidator=//")

    [[ -z "$FROST_VALIDATOR" ]] && {
        echo "$VALIDATOR_DEPLOY_OUT" >&2
        die "could not parse frost validator address — see output above"
    }

    echo "    frostValidator: $FROST_VALIDATOR"
else
    echo "    (signet-wallet not found at $WALLET_REPO — skipping wallet contracts)"
    ACCOUNT_FACTORY=""
    FROST_VALIDATOR=""
fi

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

    # registerNode(bytes pubkey, bool isOpen, address operator) — must come from the node's own address.
    cast send \
        --private-key "$PK" \
        --rpc-url "$RPC" \
        "$FACTORY" \
        "registerNode(bytes,bool,address)" "$PUB" true "0x0000000000000000000000000000000000000000" \
        >/dev/null

    echo "    node${i} registered: ${ADDR}"
done

# --------------------------------------------------------------------------
# 6. Create a signing group with all three nodes (threshold=2, 2-of-3)
# --------------------------------------------------------------------------
info "Creating signing group..."

# OAuth issuer configuration — when --auth is passed, seed the group with Google
# as a trusted issuer so ZK auth is required. Without --auth, the group has no
# auth policy and requests are unauthenticated (the existing devnet behavior).
if $USE_AUTH; then
    GOOGLE_ISS="https://accounts.google.com"
    CID1="203385367894-0uhir5bt81bsg1gcflfg6tdt1m3eeo0s.apps.googleusercontent.com"
    CID2="203385367894-30dkghcu30d4sjacullkc1q49epnvnrt.apps.googleusercontent.com"
    ISSUERS="[(${GOOGLE_ISS},[${CID1},${CID2}])]"
    echo "    issuer: ${GOOGLE_ISS}"
    echo "      client_id: ${CID1}"
    echo "      client_id: ${CID2}"
else
    ISSUERS="[]"
fi

# GroupCreated(address indexed group, address indexed creator, uint256 threshold)
GROUP_CREATED_TOPIC=$(cast keccak "GroupCreated(address,address,uint256)")

CREATE_RECEIPT=$(cast send \
    --private-key "$DEPLOYER_PK" \
    --rpc-url "$RPC" \
    "$FACTORY" \
    "createGroup(address[],uint256,uint256,(string,string[])[],bytes[])" \
    "[$ADDR_1,$ADDR_2,$ADDR_3]" 2 600 "$ISSUERS" "[]" \
    --json)

# topics[1] is the group address zero-padded to 32 bytes; take the last 40 hex chars.
GROUP_RAW=$(echo "$CREATE_RECEIPT" | jq -r \
    --arg topic "$GROUP_CREATED_TOPIC" \
    '.logs[] | select(.topics[0] == $topic) | .topics[1]')
GROUP="0x${GROUP_RAW: -40}"

[[ -z "$GROUP" || "$GROUP" == "0x" ]] && die "could not parse group address from receipt"

echo "    group: $GROUP"

# --------------------------------------------------------------------------
# 7. Write node configs (peer IDs, chain RPC, factory and group addresses baked in)
# --------------------------------------------------------------------------
info "Writing node configs..."

write_config() {
    local n="$1" port="$2" api_port="$3"
    local bp1_peer bp1_port bp2_peer bp2_port
    case "$n" in
        1) bp1_peer="$PEER_2"; bp1_port=9001; bp2_peer="$PEER_3"; bp2_port=9002 ;;
        2) bp1_peer="$PEER_1"; bp1_port=9000; bp2_peer="$PEER_3"; bp2_port=9002 ;;
        3) bp1_peer="$PEER_1"; bp1_port=9000; bp2_peer="$PEER_2"; bp2_port=9001 ;;
    esac

    cat > "$DEVNET/node${n}.yaml" <<EOF
data_dir: ./data/node${n}
listen_addr: /ip4/0.0.0.0/tcp/${port}
api_addr: :${api_port}
bootstrap_peers:
  - /ip4/127.0.0.1/tcp/${bp1_port}/p2p/${bp1_peer}
  - /ip4/127.0.0.1/tcp/${bp2_port}/p2p/${bp2_peer}
node_type: public
eth_rpc: ${RPC}
factory_address: ${FACTORY}
EOF

    if $USE_KMS; then
        echo "kms_socket: ${DEVNET}/kms${n}.sock" >> "$DEVNET/node${n}.yaml"
    fi
}

write_config 1 9000 8080
write_config 2 9001 8081
write_config 3 9002 8082

# --------------------------------------------------------------------------
# 8. Start KMS instances (if enabled)
# --------------------------------------------------------------------------
if $USE_KMS; then
    info "Starting KMS instances..."

    for i in 1 2 3; do
        KMS_SOCK="$DEVNET/kms${i}.sock"
        KMS_DATA="$DEVNET/data/kms${i}"
        mkdir -p "$KMS_DATA"

        # Remove stale socket.
        rm -f "$KMS_SOCK"

        RUST_LOG=kms_tss=info "$BUILD/kms-tss" "$KMS_SOCK" "$KMS_DATA" \
            > "$DEVNET/kms${i}.log" 2>&1 &
        echo "KMS${i}_PID=$!" >> "$PIDS_FILE"
    done

    # Wait for KMS sockets to appear (up to 5 s).
    for i in 1 2 3; do
        KMS_SOCK="$DEVNET/kms${i}.sock"
        for attempt in $(seq 1 20); do
            [[ -S "$KMS_SOCK" ]] && break
            sleep 0.25
            [[ $attempt -eq 20 ]] && die "kms${i} socket did not appear — see devnet/kms${i}.log"
        done
        echo "    kms${i} ready: $KMS_SOCK"
    done
fi

# --------------------------------------------------------------------------
# 9. Start signet nodes
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
# 10. Write .env summary and print status
# --------------------------------------------------------------------------
cat > "$ENV_FILE" <<EOF
RPC_URL=${RPC}
FACTORY_ADDRESS=${FACTORY}
GROUP_BEACON=${BEACON}
GROUP_IMPL=${GROUP_IMPL}
GROUP_ADDRESS=${GROUP}
NODE1_PEER=${PEER_1}
NODE2_PEER=${PEER_2}
NODE3_PEER=${PEER_3}
NODE1_ETH=${ADDR_1}
NODE2_ETH=${ADDR_2}
NODE3_ETH=${ADDR_3}
NODE1_API=http://localhost:8080
NODE2_API=http://localhost:8081
NODE3_API=http://localhost:8082
USE_KMS=${USE_KMS}
ACCOUNT_FACTORY=${ACCOUNT_FACTORY}
FROST_VALIDATOR=${FROST_VALIDATOR}
EOF

echo ""
echo "Signet devnet is up."
echo ""
echo "  Chain RPC : $RPC"
echo "  Factory   : $FACTORY"
echo "  Beacon    : $BEACON"
echo "  Group     : $GROUP  (threshold=2, nodes=3)"
if [[ -n "$ACCOUNT_FACTORY" ]]; then
echo "  AcctFactory: $ACCOUNT_FACTORY"
echo "  Validator  : $FROST_VALIDATOR"
fi
if $USE_KMS; then
echo "  KMS       : Rust kms-tss (devnet/kms{1,2,3}.sock)"
else
echo "  KMS       : disabled (in-process Go TSS)"
fi
echo ""
echo "  node1  eth=${ADDR_1}  api=:8080  p2p=:9000"
echo "  node2  eth=${ADDR_2}  api=:8081  p2p=:9001"
echo "  node3  eth=${ADDR_3}  api=:8082  p2p=:9002"
echo ""
echo "  Env file  : devnet/.env"
if $USE_KMS; then
echo "  Logs      : devnet/{anvil,kms{1,2,3},node{1,2,3}}.log"
else
echo "  Logs      : devnet/{anvil,node{1,2,3}}.log"
fi
echo "  Stop      : devnet/stop.sh"
echo ""
echo "Quick test:"
echo "  source devnet/.env"
echo ""
echo "  # Keygen — generate key 'k1' for the group"
echo "  curl -s -X POST http://localhost:8080/v1/keygen \\"
echo "    -H 'Content-Type: application/json' \\"
echo "    -d '{\"group_id\":\"${GROUP}\",\"key_id\":\"k1\"}' | jq ."
echo ""
echo "  # Sign — sign a message with key 'k1'"
echo "  curl -s -X POST http://localhost:8080/v1/sign \\"
echo "    -H 'Content-Type: application/json' \\"
echo "    -d '{\"group_id\":\"${GROUP}\",\"key_id\":\"k1\",\"message_hash\":\"0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef\"}' | jq ."
