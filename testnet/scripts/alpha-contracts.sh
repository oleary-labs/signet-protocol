#!/usr/bin/env bash
# testnet/scripts/alpha-contracts.sh — Contract deployment for a multi-operator
# alpha, split into phases along the trust boundary.
#
# deploy-contracts.sh assumes ONE operator holding every node's private key: it
# sends each registerNode transaction with `--private-key "$PK"` read from a
# single nodes.json. That is incompatible with independent operators, and it is
# also unnecessary — SignetFactory.registerNode enforces
#
#     require(_pubkeyToAddress(pubkey) == msg.sender, "pubkey does not match sender")
#
# so a node can ONLY be registered by a transaction signed with its own key.
# The contract already draws the boundary; this script stops fighting it.
#
# Phases and who runs them:
#
#   deploy-factory   deployer  — needs DEPLOYER_PK with Sepolia ETH
#   fund             deployer  — sends gas to each node address (public info only)
#   register         each org  — signs with ITS OWN node keys, its nodes only
#   create-group     deployer  — needs only the member addresses
#   write-env        anyone    — builds the harness env file
#
# Only `register` touches private key material, and it only ever reads the
# running operator's own testnet/data/nodes-<org>.json.
#
# Every chain-touching phase requires ETH_RPC_URL and CHAIN_ID, and refuses to
# act if the RPC reports a different chain than CHAIN_ID claims. Mainnet
# additionally prompts unless MAINNET_CONFIRMED=yes.
#
# Usage:
#   export ETH_RPC_URL=https://...  CHAIN_ID=11155111   # Sepolia
#
#   DEPLOYER_PK=0x... testnet/scripts/alpha-contracts.sh deploy-factory
#   DEPLOYER_PK=0x... FACTORY_ADDRESS=0x... testnet/scripts/alpha-contracts.sh fund
#   FACTORY_ADDRESS=0x... ALPHA_ORG=sfluv testnet/scripts/alpha-contracts.sh register
#   DEPLOYER_PK=0x... FACTORY_ADDRESS=0x... testnet/scripts/alpha-contracts.sh create-group 3
#
# `fund`, `create-group` and `write-env` read every testnet/data/manifest-*.json
# present, so collect the other operators' manifests first.

set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
TESTNET="$REPO/testnet"
CONTRACTS="$REPO/contracts"
DATA="$TESTNET/data"
ENV_FILE="$TESTNET/.env-alpha"

die()  { echo "ERROR: $*" >&2; exit 1; }
info() { echo "==> $*"; }

command -v jq   >/dev/null 2>&1 || die "'jq' not found"
command -v cast >/dev/null 2>&1 || die "'cast' not found — install Foundry"

# The chain is a value, not a variable name. SEPOLIA_RPC_URL baked the network
# into the interface, so a mainnet deploy would have been performed by pointing
# a variable called SEPOLIA at mainnet — misleading to read and impossible to
# validate. ETH_RPC_URL is the name now; the old one still works so a
# stand-up already in progress does not break.
need_rpc() {
    RPC="${ETH_RPC_URL:-}"
    if [[ -z "$RPC" && -n "${SEPOLIA_RPC_URL:-}" ]]; then
        RPC="$SEPOLIA_RPC_URL"
        echo "NOTE: SEPOLIA_RPC_URL is deprecated; use ETH_RPC_URL." >&2
    fi
    [[ -n "$RPC" ]] || die "ETH_RPC_URL not set"
}

chain_name() {
    case "$1" in
        1)        echo "Ethereum MAINNET" ;;
        11155111) echo "Sepolia" ;;
        17000)    echo "Holesky" ;;
        560048)   echo "Hoodi" ;;
        8453)     echo "Base" ;;
        84532)    echo "Base Sepolia" ;;
        31337)    echo "local (anvil/hardhat)" ;;
        *)        echo "chain $1" ;;
    esac
}

# need_chain refuses to act until the operator's stated CHAIN_ID matches what
# the RPC actually reports.
#
# This matters beyond "wrong network, wasted gas". Scoped keys bind a chainId
# at keygen time (the 0x03 EIP-712 scope), so a key created against the wrong
# chain is silently mis-scoped and only fails much later, when a signature is
# rejected or a transfer reverts. Catching it here is the difference between an
# error message and a debugging session.
#
# It also means every operator independently confirms the chain before
# registering, rather than trusting that the deployer's RPC and theirs agree.
need_chain() {
    need_rpc
    [[ -n "${CHAIN_ID:-}" ]] || die "CHAIN_ID not set (11155111 = Sepolia, 1 = mainnet)"

    local actual
    actual=$(cast chain-id --rpc-url "$RPC" 2>/dev/null) \
        || die "could not read the chain id from the RPC — is ETH_RPC_URL reachable?"

    if [[ "$actual" != "$CHAIN_ID" ]]; then
        die "chain mismatch — refusing to continue.
     you asked for : $CHAIN_ID ($(chain_name "$CHAIN_ID"))
     the RPC is    : $actual ($(chain_name "$actual"))
     Either the RPC URL or CHAIN_ID is wrong. Fix whichever one you did not
     intend before any on-chain state is created."
    fi

    info "Chain: $(chain_name "$actual") ($actual)"

    # Mainnet spends real money and creates permanent state. Make it deliberate.
    if [[ "$actual" == "1" && "${MAINNET_CONFIRMED:-}" != "yes" ]]; then
        echo
        read -r -p "This is Ethereum MAINNET. Type 'mainnet' to proceed: " reply
        [[ "$reply" == "mainnet" ]] || die "aborted (set MAINNET_CONFIRMED=yes to skip this prompt in automation)"
    fi
}
need_deployer() {
    [[ -n "${DEPLOYER_PK:-}" ]] || die "DEPLOYER_PK not set"
}
need_factory() {
    [[ -n "${FACTORY_ADDRESS:-}" ]] || die "FACTORY_ADDRESS not set"
    FACTORY="$FACTORY_ADDRESS"
}

# manifests prints every manifest path, or dies if none were found.
manifests() {
    local found=()
    while IFS= read -r m; do found+=("$m"); done \
        < <(find "$DATA" -maxdepth 1 -name 'manifest-*.json' | sort)
    [[ ${#found[@]} -gt 0 ]] || die "no testnet/data/manifest-*.json found — run init-alpha.sh and collect the other operators' manifests"
    printf '%s\n' "${found[@]}"
}

# all_nodes emits one "org name eth_address pubkey peer_id" line per node
# across every manifest, ordered by org then name so all operators derive the
# same member ordering from the same inputs.
all_nodes() {
    # shellcheck disable=SC2046
    jq -r '(.operator // "") as $op | .nodes[]
           | [.org, .name, .eth_address, .pubkey, .peer_id, (.hostname // ""), $op] | @tsv' \
        $(manifests) | sort -k1,1 -k2,2
}

# --------------------------------------------------------------------------
cmd_deploy_factory() {
    need_chain; need_deployer
    local deployer
    deployer=$(cast wallet address "$DEPLOYER_PK")
    info "Deployer: $deployer"
    info "Deploying SignetFactory..."

    local out
    out=$(cd "$CONTRACTS" && ADMIN_ADDRESS="$deployer" \
        forge script script/DeployFactory.s.sol \
            --rpc-url "$RPC" --broadcast --private-key "$DEPLOYER_PK" 2>&1)

    _val() { grep "DEPLOY:$1=" <<< "$out" | sed "s/.*DEPLOY:$1=//"; }
    local factory beacon impl
    factory=$(_val factory); beacon=$(_val beacon); impl=$(_val groupImpl)
    [[ -n "$factory" ]] || { echo "$out" >&2; die "could not parse factory address"; }

    cat <<EOF

Factory:   $factory
Beacon:    $beacon
GroupImpl: $impl

Share these with the other operators — they need both to register, and the
chain id is what stops them registering against the wrong network.

  export CHAIN_ID=$CHAIN_ID
  export FACTORY_ADDRESS=$factory
EOF
    printf 'CHAIN_ID=%s\nFACTORY_ADDRESS=%s\nGROUP_BEACON=%s\nGROUP_IMPL=%s\n' \
        "$CHAIN_ID" "$factory" "$beacon" "$impl" > "$DATA/factory.env"
    info "Wrote $DATA/factory.env"
}

# --------------------------------------------------------------------------
cmd_fund() {
    need_chain; need_deployer
    local amount="${FUND_AMOUNT:-0.02ether}"
    info "Funding every manifest node with $amount (gas for its own registerNode)"

    while read -r org name addr _pub _peer _host _op; do
        local bal
        bal=$(cast balance "$addr" --rpc-url "$RPC" 2>/dev/null || echo 0)
        if [[ "$bal" != "0" ]]; then
            info "  $org/$name $addr — already funded ($(cast from-wei "$bal") ETH), skipping"
            continue
        fi
        cast send --private-key "$DEPLOYER_PK" --rpc-url "$RPC" \
            "$addr" --value "$amount" >/dev/null
        info "  $org/$name $addr — funded"
    done < <(all_nodes)
}

# --------------------------------------------------------------------------
cmd_register() {
    need_chain; need_factory
    local org="${ALPHA_ORG:-}"
    [[ -n "$org" ]] || die "ALPHA_ORG not set — register only handles your own org's nodes"

    local nodes_json="$DATA/nodes-${org}.json"
    [[ -f "$nodes_json" ]] || die "$nodes_json not found — run init-alpha.sh on this machine first"

    # Zero means "the node is its own operator" (SignetFactory._effectiveOperator).
    # A real address records that these nodes belong to one organisation, and is
    # what SignetGroup checks for join/leave authorisation.
    local operator
    operator=$(jq -r '.operator // ""' "$nodes_json")
    [[ -n "$operator" ]] || operator="0x0000000000000000000000000000000000000000"

    info "Registering ${org} nodes against factory $FACTORY"
    info "  operator: ${operator}"

    local count
    count=$(jq '.nodes | length' "$nodes_json")
    for i in $(seq 0 $((count - 1))); do
        local name addr pk pub already
        name=$(jq -r ".nodes[$i].name"        "$nodes_json")
        addr=$(jq -r ".nodes[$i].eth_address" "$nodes_json")
        pk=$(  jq -r ".nodes[$i].eth_privkey" "$nodes_json")
        pub=$( jq -r ".nodes[$i].pubkey"      "$nodes_json")

        # registerNode reverts with "already registered" on a second call, so
        # check first and keep this re-runnable.
        already=$(cast call "$FACTORY" "getNode(address)((bytes,bool,bool,uint256,address))" \
                    "$addr" --rpc-url "$RPC" 2>/dev/null | grep -c "true" || true)
        if [[ "$already" != "0" ]]; then
            info "  $name $addr — already registered, skipping"
            continue
        fi

        # Signed with the NODE's key, not the deployer's: the factory requires
        # _pubkeyToAddress(pubkey) == msg.sender.
        cast send --private-key "$pk" --rpc-url "$RPC" "$FACTORY" \
            "registerNode(bytes,bool,address)" "$pub" true "$operator" >/dev/null
        info "  $name $addr — registered"
    done

    echo
    info "Done. Tell the deployer operator that ${org} is registered."
}

# --------------------------------------------------------------------------
cmd_create_group() {
    need_chain; need_deployer; need_factory
    local threshold="${1:-}"
    [[ -n "$threshold" ]] || die "usage: alpha-contracts.sh create-group <threshold>"

    local addrs=() names=() orgs=()
    while read -r org name addr _pub _peer _host _op; do
        addrs+=("$addr"); names+=("$org/$name"); orgs+=("$org")
    done < <(all_nodes)

    local n=${#addrs[@]}
    local need_ecdsa=$(( 2 * threshold - 1 ))
    (( need_ecdsa < 3 )) && need_ecdsa=3

    cat <<EOF

Group to create
  members    $n  (${names[*]})
  threshold  $threshold
  FROST      needs $threshold signers, tolerates $(( n - threshold )) down
  ECDSA      needs $need_ecdsa signers, tolerates $(( n - need_ecdsa )) down
EOF

    # Shard distribution across operators. Reported, never enforced: the
    # topology is the customer's choice — several independent operators, or
    # several nodes from one — and reshare can change it later. The point is
    # that the concentration is visible at the moment of choosing.
    echo
    echo "  shards per operator"
    local seen="" o c
    for o in "${orgs[@]}"; do
        case " $seen " in *" $o "*) continue ;; esac
        seen="$seen $o"
        c=0
        for x in "${orgs[@]}"; do [[ "$x" == "$o" ]] && c=$((c + 1)); done
        printf "    %-12s %d of %d" "$o" "$c" "$n"
        if (( c >= threshold )); then
            printf "   <- reaches the threshold alone"
        fi
        echo
    done
    echo
    (( n < need_ecdsa )) && die "only $n members but ECDSA needs $need_ecdsa (n >= 2T-1) — lower the threshold or add nodes"

    # Every member must already be registered, or createGroup will revert.
    for i in "${!addrs[@]}"; do
        local ok
        ok=$(cast call "$FACTORY" "getNode(address)((bytes,bool,bool,uint256,address))" \
                "${addrs[$i]}" --rpc-url "$RPC" 2>/dev/null | grep -c "true" || true)
        [[ "$ok" != "0" ]] || die "${names[$i]} (${addrs[$i]}) is not registered yet — that operator must run 'register' first"
    done

    read -r -p "Create this group? [y/N] " confirm
    [[ "$confirm" == "y" ]] || die "aborted"

    local list
    list=$(IFS=,; echo "${addrs[*]}")
    local topic receipt raw group
    topic=$(cast keccak "GroupCreated(address,address,uint256)")
    receipt=$(cast send --private-key "$DEPLOYER_PK" --rpc-url "$RPC" "$FACTORY" \
        "createGroup(address[],uint256,uint256,(string,string[])[],bytes[])" \
        "[$list]" "$threshold" 600 "[]" "[]" --json)
    raw=$(jq -r --arg t "$topic" '.logs[] | select(.topics[0] == $t) | .topics[1]' <<< "$receipt")
    group="0x${raw: -40}"
    [[ "$group" != "0x" ]] || die "could not parse group address from receipt"

    info "Group: $group"
    printf 'GROUP_ADDRESS=%s\nGROUP_THRESHOLD=%s\n' "$group" "$threshold" >> "$DATA/factory.env"
    info "Appended to $DATA/factory.env — share GROUP_ADDRESS with the other operators"
}

# --------------------------------------------------------------------------
cmd_write_env() {
    need_rpc
    [[ -f "$DATA/factory.env" ]] || die "$DATA/factory.env not found"
    # shellcheck disable=SC1090
    source "$DATA/factory.env"

    local hosts="$TESTNET/.hosts-alpha"
    {
        echo "RPC_URL=${RPC}"
        echo "CHAIN_ID=${CHAIN_ID:-unknown}"
        echo "FACTORY_ADDRESS=${FACTORY_ADDRESS}"
        echo "GROUP_ADDRESS=${GROUP_ADDRESS:-FILL_ME}"
        echo "USE_KMS=true"
        echo ""
        local i=0
        while read -r org name addr _pub peer host _op; do
            i=$((i + 1))
            echo "NODE${i}_ETH=${addr}"
            echo "NODE${i}_PEER=${peer}"
            echo "NODE${i}_ORG=${org}"
            # Prefer the TLS hostname. Falling back to http://IP is a cleartext
            # endpoint that leaks delegation tokens, so it is marked as such
            # rather than quietly emitted.
            if [[ -n "$host" ]]; then
                echo "NODE${i}_API=https://${host}"
            elif [[ -f "$hosts" ]] && grep -q "^${name}=" "$hosts"; then
                echo "NODE${i}_API=http://$(grep "^${name}=" "$hosts" | cut -d= -f2):8080   # INSECURE: no hostname in manifest"
            else
                echo "NODE${i}_API=http://FILL_IP:8080   # ${name} — INSECURE"
            fi
        done < <(all_nodes)
    } > "$ENV_FILE"
    info "Wrote $ENV_FILE"
    if grep -q "FILL_IP" "$ENV_FILE"; then
        echo "    NOTE: some API URLs need IPs — merge the other operators' .hosts-alpha fragments"
    fi
    if grep -q "INSECURE" "$ENV_FILE"; then
        echo "    WARNING: some nodes have no TLS hostname and fall back to cleartext http://."
        echo "             /v1/auth delegation tokens are bearer credentials; do not use"
        echo "             those endpoints for anything but local testing."
    fi
}

# --------------------------------------------------------------------------
case "${1:-}" in
    deploy-factory) shift; cmd_deploy_factory "$@" ;;
    fund)           shift; cmd_fund "$@" ;;
    register)       shift; cmd_register "$@" ;;
    create-group)   shift; cmd_create_group "$@" ;;
    write-env)      shift; cmd_write_env "$@" ;;
    *)
        sed -n '2,42p' "$0" | sed 's/^# \{0,1\}//'
        exit 1
        ;;
esac
