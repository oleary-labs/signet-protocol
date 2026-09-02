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
#   deploy-factory   deployer  — needs DEPLOYER_PK with ETH, and a COLD ADMIN_ADDRESS
#   fund             deployer  — sends gas to each node address (public info only)
#   register         each org  — signs with ITS OWN node keys, its nodes only
#   gen-auth-key     manager   — mints the authorization key the group trusts
#   create-group     manager   — needs MANAGER_PK; member addresses are public
#   accept           each org  — operator consents to its nodes joining the group
#   write-env        anyone    — builds the harness env file
#
# Upgrade phases, run long after stand-up:
#
#   check-layout       anyone    — storage-layout diff; no chain, no key
#   deploy-group-impl  deployer  — deploys a new SignetGroup logic contract
#   upgrade-beacon     COLD OWNER— points the beacon at it (see the warning below)
#   siwe-domains       manager   — show/queue/execute the group's SIWE domain list
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
#   testnet/scripts/alpha-contracts.sh gen-auth-key harness
#   MANAGER_PK=0x...  FACTORY_ADDRESS=0x... testnet/scripts/alpha-contracts.sh create-group 3
#   OPERATOR_PK=0x... FACTORY_ADDRESS=0x... ALPHA_ORG=oll testnet/scripts/alpha-contracts.sh accept
#
#   testnet/scripts/alpha-contracts.sh check-layout
#   DEPLOYER_PK=0x... testnet/scripts/alpha-contracts.sh deploy-group-impl
#   FACTORY_ADDRESS=0x... GROUP_IMPL=0x... testnet/scripts/alpha-contracts.sh upgrade-beacon
#   MANAGER_PK=0x... GROUP_ADDRESS=0x... testnet/scripts/alpha-contracts.sh siwe-domains queue app.sfluv.org
#
# `fund`, `create-group` and `write-env` read every testnet/data/manifest-*.json
# present, so collect the other operators' manifests first.
#
# Rehearse the upgrade phases before running them for real:
# testnet/scripts/rehearse-upgrade.sh forks the live chain into anvil and drives
# deploy → upgrade → queue → execute against a copy of real group state.

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

# The group manager is not the factory deployer. createGroup is permissionless
# and makes msg.sender the manager (SignetFactory.sol:135), so the key that
# creates the group is the customer's, not the infrastructure operator's — the
# app owns and manages its group. MANAGER_PK keeps that distinction visible;
# DEPLOYER_PK is honoured with a notice for a single-party devnet.
MANAGER_KEY=""
need_manager() {
    MANAGER_KEY="${MANAGER_PK:-}"
    # UNLOCKED impersonates rather than signs, so there is no key to require.
    # See _send — it refuses to do this anywhere but a fork.
    #
    # Written as an `if` and not `[[ … ]] && return 0`: under `set -e` that idiom
    # exits the whole script when the test is false, because the && chain's
    # status becomes the function's.
    if [[ "${UNLOCKED:-}" == "yes" ]]; then
        return 0
    fi
    if [[ -z "$MANAGER_KEY" && -n "${DEPLOYER_PK:-}" ]]; then
        MANAGER_KEY="$DEPLOYER_PK"
        echo "NOTE: using DEPLOYER_PK as the group manager. The manager owns the group" >&2
        echo "      and can add authorization keys to it; normally that is the app, not" >&2
        echo "      the factory deployer. Set MANAGER_PK to be explicit." >&2
    fi
    [[ -n "$MANAGER_KEY" ]] || die "MANAGER_PK not set — this is the key that will own and manage the group"
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

    # The factory owner is NOT the deploy key.
    #
    # DEPLOYER_PK is hot by construction: it lives in an operator's shell for
    # the length of the install and signs from a laptop. The factory owner, by
    # contrast, holds standing power for the lifetime of the deployment —
    # upgradeGroupImplementation replaces the SignetGroup logic behind EVERY
    # group through the shared beacon, so it can rewrite auth checks and
    # membership rules under groups it does not manage, and _authorizeUpgrade
    # lets it replace the factory itself. Those must not be the same key.
    #
    # Get it right here rather than transferring afterwards: the factory uses
    # OZ v5 OwnableUpgradeable, which is single-step. transferOwnership has no
    # acceptance leg, so one wrong address permanently loses the factory and
    # the beacon with it — no group could ever be upgraded again.
    local admin="${ADMIN_ADDRESS:-}"
    [[ -n "$admin" ]] || die "ADMIN_ADDRESS not set.

     This is the address that will OWN the factory and its UpgradeableBeacon —
     it can replace the SignetGroup implementation under every group, including
     groups other organisations manage. Use a hardware wallet or a multisig,
     not the deploy key.

     Ownership transfer is single-step (OZ v5 Ownable), so a mistake here is
     unrecoverable. Set it deliberately:
       export ADMIN_ADDRESS=0x<cold address>"
    [[ "$admin" =~ ^0x[0-9a-fA-F]{40}$ ]] || die "ADMIN_ADDRESS must be a 0x-prefixed 20-byte address, got '$admin'"

    # tr rather than ${x,,} — macOS ships bash 3.2, where that expansion is a
    # syntax error, and addresses differ only in EIP-55 checksum casing.
    if [[ "$(printf %s "$admin" | tr 'A-F' 'a-f')" == "$(printf %s "$deployer" | tr 'A-F' 'a-f')" ]]; then
        [[ "${ALLOW_HOT_ADMIN:-}" == "yes" ]] || die "ADMIN_ADDRESS equals the deployer address ($deployer).

     That makes the hot install key the permanent owner of the factory and the
     beacon. Use a separate cold address, or set ALLOW_HOT_ADMIN=yes if this is
     a throwaway devnet."
        echo "WARNING: factory owner is the hot deploy key (ALLOW_HOT_ADMIN=yes)." >&2
    fi

    info "Deployer:      $deployer  (hot — no standing power after 'fund')"
    info "Factory owner: $admin"
    info "Deploying SignetFactory..."

    local out
    out=$(cd "$CONTRACTS" && ADMIN_ADDRESS="$admin" \
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
Owner:     $admin

Share these with the other operators — they need both to register, and the
chain id is what stops them registering against the wrong network.

  export CHAIN_ID=$CHAIN_ID
  export FACTORY_ADDRESS=$factory
EOF
    printf 'CHAIN_ID=%s\nFACTORY_ADDRESS=%s\nGROUP_BEACON=%s\nGROUP_IMPL=%s\nFACTORY_OWNER=%s\n' \
        "$CHAIN_ID" "$factory" "$beacon" "$impl" "$admin" > "$DATA/factory.env"
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

    # Operator addresses need gas too. Nodes register themselves, but with
    # isOpen=false it is the OPERATOR that sends acceptInvite, one transaction
    # per node. An unfunded operator leaves the group stuck with every member
    # Pending and none Active — isOperational() false, no keygen possible.
    local seen_ops=""
    while read -r _org _name _addr _pub _peer _host op; do
        [[ -n "$op" && "$op" != "0x0000000000000000000000000000000000000000" ]] || continue
        case " $seen_ops " in *" $op "*) continue ;; esac
        seen_ops="$seen_ops $op"
        local obal
        obal=$(cast balance "$op" --rpc-url "$RPC" 2>/dev/null || echo 0)
        if [[ "$obal" != "0" ]]; then
            info "  operator $op — already funded ($(cast from-wei "$obal") ETH), skipping"
            continue
        fi
        cast send --private-key "$DEPLOYER_PK" --rpc-url "$RPC" \
            "$op" --value "$amount" >/dev/null
        info "  operator $op — funded (gas for acceptInvite)"
    done < <(all_nodes)
}

# --------------------------------------------------------------------------
cmd_register() {
    need_chain; need_factory
    local org="${ALPHA_ORG:-}"
    [[ -n "$org" ]] || die "ALPHA_ORG not set — register only handles your own org's nodes"

    local nodes_json="$DATA/nodes-${org}.json"
    [[ -f "$nodes_json" ]] || die "$nodes_json not found — run init-alpha.sh on this machine first"

    # The operator address is what makes several nodes one organisation on-chain.
    # SignetGroup checks it for join/leave authorisation — acceptInvite,
    # declineInvite and queueRemoval all require msg.sender to be the node's
    # effective operator (SignetGroup.sol:150,159,167).
    #
    # Left unset, SignetFactory._effectiveOperator falls back to the node
    # itself. That works, but it means every consent action must be sent from
    # that node's own key, one transaction per node, and nothing on-chain
    # records that these nodes belong together. Refuse rather than default:
    # this used to fall through to the zero address with only an info line.
    #
    # ALPHA_OPERATOR overrides the value init-alpha.sh recorded, so a wrong or
    # missing operator is fixable without regenerating identities.
    local operator="${ALPHA_OPERATOR:-}"
    [[ -n "$operator" ]] || operator=$(jq -r '.operator // ""' "$nodes_json")
    if [[ -z "$operator" ]]; then
        [[ "${ALPHA_NO_OPERATOR:-}" == "yes" ]] || die "no operator address for org '${org}'.

     ${nodes_json##*/} records no operator, so each node would become its own
     operator on-chain: every acceptInvite or queueRemoval would need to be
     signed by that individual node's key, and nothing would record that these
     ${org} nodes are one organisation.

     Supply one without regenerating identities:
       ALPHA_OPERATOR=0x<address this org controls> ... register

     It is changeable later via SignetFactory.setOperator, so this is not a
     one-way door. To register with each node as its own operator anyway, set
     ALPHA_NO_OPERATOR=yes."
        operator="0x0000000000000000000000000000000000000000"
        echo "WARNING: registering ${org} with no operator (ALPHA_NO_OPERATOR=yes)." >&2
    else
        [[ "$operator" =~ ^0x[0-9a-fA-F]{40}$ ]] || die "operator must be a 0x-prefixed 20-byte address, got '$operator'"
    fi

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
        #
        # isOpen=false. An open node is added to ANY group the moment its
        # manager names it — SignetGroup.inviteNode skips Pending entirely and
        # activates it (SignetGroup.sol:139). So an open node can be conscripted
        # by a stranger's group and will run DKG and hold shards for them, on
        # this operator's hardware, without anyone here agreeing to it.
        #
        # Closed means the node lands in Pending and the operator must call
        # acceptInvite. That is the consent step the invite lifecycle exists
        # for. Reversible either way via SignetFactory.updateOpenStatus.
        local is_open="false"
        if [[ "${ALPHA_OPEN_NODES:-}" == "yes" ]]; then
            is_open="true"
            echo "WARNING: registering $name as OPEN — any group may add it without asking." >&2
        fi
        cast send --private-key "$pk" --rpc-url "$RPC" "$FACTORY" \
            "registerNode(bytes,bool,address)" "$pub" "$is_open" "$operator" >/dev/null
        info "  $name $addr — registered"
    done

    echo
    info "Done. Tell the deployer operator that ${org} is registered."
}

# --------------------------------------------------------------------------
# Mint an authorization key for the group to trust.
#
# A group created with no issuers, no auth keys and no resolver has NO auth
# policy, and node/handlers.go:1280 then skips authentication entirely:
#
#     if !n.auth.HasAuthPolicy(groupID) { return keyID, nil, true }
#
# So a policy-less group leaves /v1/keygen and /v1/sign open to anyone who can
# reach them — which, once Caddy is serving 443, is the whole internet. TLS and
# rate limiting would be guarding an unlocked door. create-group therefore
# refuses to create such a group unless ALPHA_OPEN_GROUP=yes is set explicitly.
#
# On-chain form is 34 bytes: a scheme prefix (0x00 = secp256k1 ECDSA,
# node/auth.go:28) followed by the 33-byte compressed pubkey. The bytes are
# compared verbatim against the certificate's auth_key_pub, and SignetGroup
# does not validate the length, so getting it wrong here surfaces only as a 401
# much later.
cmd_gen_auth_key() {
    local label="${1:-harness}"
    [[ "$label" =~ ^[a-z0-9._-]+$ ]] || die "label must be lowercase alphanumeric/dot/dash/underscore"

    mkdir -p "$DATA"
    local out="$DATA/auth-key-${label}.json"
    [[ ! -f "$out" ]] || die "$out already exists — refusing to overwrite.
     Regenerating orphans the key the group already trusts; remove it
     deliberately if that is what you want."

    local pk pub x y compressed onchain
    pk=$(cast wallet new --json | jq -r '.[0].private_key')
    pub=$(cast wallet public-key --raw-private-key "$pk")
    pub="${pub#0x}"
    [[ ${#pub} -eq 128 ]] || die "expected a 64-byte uncompressed pubkey, got ${#pub} hex chars"

    # Compress: 0x02 for an even Y, 0x03 for odd, then X.
    x="${pub:0:64}"
    y="${pub:64:64}"
    case "${y: -1}" in
        [02468aAcCeE]) compressed="02${x}" ;;
        *)             compressed="03${x}" ;;
    esac
    onchain="00${compressed}"
    [[ ${#onchain} -eq 68 ]] || die "internal error: auth key is ${#onchain} hex chars, want 68"

    jq -n --arg l "$label" --arg pk "$pk" --arg pub "$onchain" --arg c "$compressed" \
        '{label: $l, private_key: $pk, auth_key_pub: $pub, compressed_pubkey: $c}' > "$out"
    chmod 600 "$out"

    info "Wrote $out (0600)"
    echo "    identity      $label"
    echo "    auth_key_pub  0x$onchain"
    echo
    echo "  This is a SECRET — the private key authorizes every operation on the"
    echo "  group. It is the credential the harness signs with. Keep it off shared"
    echo "  machines and out of git; testnet/data is gitignored."
    echo
    echo "  create-group picks it up automatically. To trust an externally held key"
    echo "  instead, set ALPHA_AUTH_KEY_PUB=0x<34 bytes> and skip this phase."
}

cmd_create_group() {
    need_chain; need_manager; need_factory
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
  manager    $(cast wallet address "$MANAGER_KEY")
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

    # --- Authorization policy ---
    #
    # A group with no issuers, no auth keys and no resolver has no auth policy
    # at all, and the node then serves /v1/keygen and /v1/sign to anyone who can
    # reach the port (node/handlers.go:1280). Refuse by default.
    local auth_pub="${ALPHA_AUTH_KEY_PUB:-}"
    if [[ -z "$auth_pub" ]]; then
        local generated
        generated=$(ls "$DATA"/auth-key-*.json 2>/dev/null | head -1 || true)
        if [[ -n "$generated" ]]; then
            auth_pub=$(jq -r '.auth_key_pub' "$generated")
            info "Using auth key from ${generated##*/}"
        fi
    fi
    auth_pub="${auth_pub#0x}"

    local auth_list="[]"
    if [[ -n "$auth_pub" ]]; then
        [[ "$auth_pub" =~ ^[0-9a-fA-F]{68}$ ]] || die "ALPHA_AUTH_KEY_PUB must be 34 bytes (68 hex chars): 1 scheme prefix + 33 compressed pubkey, got ${#auth_pub} chars"
        [[ "${auth_pub:0:2}" == "00" || "${auth_pub:0:2}" == "01" ]] || die "auth key scheme prefix must be 00 (ECDSA) or 01 (Schnorr), got ${auth_pub:0:2}"
        auth_list="[0x${auth_pub}]"
        echo "  auth key   0x${auth_pub:0:18}… (group requires signed sessions)"
    elif [[ "${ALPHA_OPEN_GROUP:-}" == "yes" ]]; then
        echo "  auth key   NONE — ALPHA_OPEN_GROUP=yes"
        echo "             /v1/keygen and /v1/sign will accept UNAUTHENTICATED requests."
    else
        die "no authorization key configured.

     A group with no issuers, no auth keys and no resolver has no auth policy,
     and the node skips authentication entirely for it — /v1/keygen and /v1/sign
     would be open to anyone who can reach the API. After Phase 4 that is the
     public internet.

     Mint one first:
       testnet/scripts/alpha-contracts.sh gen-auth-key harness

     Or pass an externally held key with ALPHA_AUTH_KEY_PUB=0x<34 bytes>.
     To create a genuinely open group anyway, set ALPHA_OPEN_GROUP=yes."
    fi
    echo

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
    receipt=$(cast send --private-key "$MANAGER_KEY" --rpc-url "$RPC" "$FACTORY" \
        "createGroup(address[],uint256,uint256,(string,string[])[],bytes[])" \
        "[$list]" "$threshold" 600 "[]" "$auth_list" --json)
    raw=$(jq -r --arg t "$topic" '.logs[] | select(.topics[0] == $t) | .topics[1]' <<< "$receipt")
    group="0x${raw: -40}"
    [[ "$group" != "0x" ]] || die "could not parse group address from receipt"

    info "Group: $group"
    printf 'GROUP_ADDRESS=%s\nGROUP_THRESHOLD=%s\n' "$group" "$threshold" >> "$DATA/factory.env"
    info "Appended to $DATA/factory.env — share GROUP_ADDRESS with the other operators"
}

# --------------------------------------------------------------------------
# Accept this org's invitations into a group.
#
# With isOpen=false, createGroup and inviteNode put a node in Pending rather
# than Active (SignetGroup.sol:105,142). Nothing signs for it until its operator
# calls acceptInvite — which is the point: it is the operator agreeing to serve
# this particular customer, not merely to exist in the registry.
#
# Sent by the operator address recorded at registration
# (SignetGroup.sol:150 requires msg.sender == getNodeOperator(node)), so this
# needs OPERATOR_PK — the key for that address, funded by `fund`.
cmd_accept() {
    need_chain; need_factory
    local org="${ALPHA_ORG:-}"
    [[ -n "$org" ]] || die "ALPHA_ORG not set — accept only handles your own org's nodes"
    [[ -n "${OPERATOR_PK:-}" ]] || die "OPERATOR_PK not set — acceptInvite must be signed by the address recorded as this org's operator"

    local group="${GROUP_ADDRESS:-}"
    if [[ -z "$group" && -f "$DATA/factory.env" ]]; then
        # shellcheck disable=SC1090
        group=$(grep '^GROUP_ADDRESS=' "$DATA/factory.env" 2>/dev/null | cut -d= -f2 || true)
    fi
    [[ -n "$group" ]] || die "GROUP_ADDRESS not set and not in testnet/data/factory.env — the manager must create the group first and share it"

    local manifest="$DATA/manifest-${org}.json"
    [[ -f "$manifest" ]] || die "$manifest not found"

    local signer
    signer=$(cast wallet address "$OPERATOR_PK")
    info "Accepting ${org} invitations into group $group"
    info "  operator: $signer"

    local bal
    bal=$(cast balance "$signer" --rpc-url "$RPC" 2>/dev/null || echo 0)
    [[ "$bal" != "0" ]] || die "operator $signer has no ETH — the deployer must run 'fund' first"

    local accepted=0 count
    count=$(jq '.nodes | length' "$manifest")
    for i in $(seq 0 $((count - 1))); do
        local name addr onchain_op status
        name=$(jq -r ".nodes[$i].name"        "$manifest")
        addr=$(jq -r ".nodes[$i].eth_address" "$manifest")

        # nodeStatus: 0 None, 1 Pending, 2 Active.
        status=$(cast call "$group" "nodeStatus(address)(uint8)" "$addr" --rpc-url "$RPC" 2>/dev/null || echo "")
        status="${status%% *}"
        case "$status" in
            2) info "  $name $addr — already active, skipping"; continue ;;
            1) ;;
            0) info "  $name $addr — not in this group (status None), skipping"; continue ;;
            *) die "could not read nodeStatus for $name from $group" ;;
        esac

        # The contract will reject a mismatch, but failing here names the
        # problem instead of surfacing it as a bare revert.
        onchain_op=$(cast call "$FACTORY" "getNodeOperator(address)(address)" "$addr" --rpc-url "$RPC" 2>/dev/null || echo "")
        if [[ "$(printf %s "$onchain_op" | tr 'A-F' 'a-f')" != "$(printf %s "$signer" | tr 'A-F' 'a-f')" ]]; then
            die "$name is operated by $onchain_op, not $signer — OPERATOR_PK is the wrong key for this node"
        fi

        cast send --private-key "$OPERATOR_PK" --rpc-url "$RPC" "$group" \
            "acceptInvite(address)" "$addr" >/dev/null
        info "  $name $addr — accepted"
        accepted=$((accepted + 1))
    done

    echo
    local active threshold
    active=$(cast call "$group" "getActiveNodes()(address[])" --rpc-url "$RPC" 2>/dev/null | grep -o '0x[0-9a-fA-F]\{40\}' | wc -l | tr -d ' ')
    threshold=$(cast call "$group" "quorum()(uint256)" --rpc-url "$RPC" 2>/dev/null | awk '{print $1}')
    info "Accepted $accepted. Group now has $active active member(s), threshold $threshold."
    if [[ -n "$threshold" && "$active" -lt "$threshold" ]]; then
        echo "    Not operational yet — waiting on the other operators to accept."
    fi
}

cmd_write_env() {
    need_rpc
    [[ -f "$DATA/factory.env" ]] || die "$DATA/factory.env not found"
    # shellcheck disable=SC1090
    source "$DATA/factory.env"

    local hosts="$TESTNET/.hosts-alpha"
    local auth_key_file
    auth_key_file=$(ls "$DATA"/auth-key-*.json 2>/dev/null | head -1 || true)
    {
        echo "RPC_URL=${RPC}"
        echo "CHAIN_ID=${CHAIN_ID:-unknown}"
        echo "FACTORY_ADDRESS=${FACTORY_ADDRESS}"
        echo "GROUP_ADDRESS=${GROUP_ADDRESS:-FILL_ME}"
        echo "USE_KMS=true"
        # The harness sends unauthenticated requests unless HARNESS_AUTH_KEY is
        # set, and a group with an auth policy answers those with 401.
        if [[ -n "$auth_key_file" ]]; then
            echo "HARNESS_AUTH_KEY=$(jq -r '.private_key' "$auth_key_file")"
            echo "HARNESS_AUTH_IDENTITY=$(jq -r '.label' "$auth_key_file")"
        fi
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
    # It carries HARNESS_AUTH_KEY when one is configured — a private key that
    # authorizes every operation on the group — so it is not world-readable.
    chmod 600 "$ENV_FILE"
    info "Wrote $ENV_FILE (0600)"
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
# Upgrade phases.
#
# These run long after stand-up and against groups that already hold key
# material, so they are deliberately more suspicious than the deploy phases.
# --------------------------------------------------------------------------

BASELINE="$CONTRACTS/storage-layout-baseline.tsv"

# _send <signer> <key-or-empty> <cast-send-args...>
#
# UNLOCKED=yes sends from an impersonated account instead of a signature, which
# is how the fork rehearsal drives phases whose real signer is a hardware wallet
# it does not have. It is refused on any chain that is not a local fork, because
# the whole value of rehearsing is that the code path is the same one — a mode
# that quietly worked on a real chain too would be a way to skip the signer.
_send() {
    local from="$1" key="$2"; shift 2
    if [[ "${UNLOCKED:-}" == "yes" ]]; then
        [[ "$CHAIN_ID" == "31337" ]] || die "UNLOCKED=yes is fork-rehearsal only, and CHAIN_ID is $CHAIN_ID.
     It impersonates the signer instead of signing. Start anvil with
     --chain-id 31337 (rehearse-upgrade.sh does), or use the real key."
        cast send --unlocked --from "$from" --rpc-url "$RPC" "$@"
    else
        [[ -n "$key" ]] || die "no key available to sign as $from"
        cast send --private-key "$key" --rpc-url "$RPC" "$@"
    fi
}

# _layout emits the normalized storage layout of SignetGroup as
# "slot<TAB>offset<TAB>label<TAB>type" lines.
#
# The normalization drops the AST node ids solc appends to struct and enum type
# names. Those move whenever a line is added anywhere above the declaration, so
# an unnormalized comparison reports drift on every build and would train the
# reader to ignore it. Array lengths are deliberately NOT stripped: the gap
# shrinking from 46 to 42 is the measurement, not noise.
#
# It cleans first, every time. `forge inspect ... storage` reads a cached
# artifact, and the storage layout is not in the default output selection, so a
# tree built by an ordinary `forge build` yields "storage layout missing from
# artifact" — and, worse in principle, a tree built from different source could
# answer from cache. A slow check that describes the code being deployed beats a
# fast one that might describe the previous build; this gates a beacon upgrade,
# so the rebuild is cheap at the price.
_layout() {
    ( cd "$CONTRACTS" \
        && forge clean >/dev/null 2>&1 \
        && forge inspect SignetGroup storage --json 2>/dev/null ) \
        | jq -r '.storage[] | "\(.slot)\t\(.offset)\t\(.label)\t\(.type)"' \
        | sed -e 's/\(t_struct([A-Za-z0-9_]*)\)[0-9]*/\1/g' \
              -e 's/\(t_enum([A-Za-z0-9_]*)\)[0-9]*/\1/g'
}

_baseline_rows() { grep -v '^#' "$BASELINE" | grep -v '^[[:space:]]*$'; }

# cmd_check_layout compares the working tree's SignetGroup against the layout
# that is deployed, and refuses the upgrade unless the new one is a pure
# extension of it.
#
# This is the check that a beacon upgrade actually needs. BeaconProxy keeps
# state in the proxy and takes only code from the implementation, so a new
# implementation does not migrate storage — it reinterprets it in place, for
# every group behind the beacon at once, including groups this repo does not
# manage. There is no failed transaction to notice: the upgrade succeeds and the
# data quietly means something else.
cmd_check_layout() {
    [[ -f "$BASELINE" ]] || die "missing $BASELINE"

    local write_baseline=""
    if [[ "${1:-}" == "--write-baseline" ]]; then write_baseline=yes; fi

    info "Building SignetGroup and reading its storage layout..."
    local new_layout
    new_layout=$(_layout) || die "forge inspect failed — does the contract compile?"
    [[ -n "$new_layout" ]] || die "empty storage layout from forge inspect"

    if [[ -n "$write_baseline" ]]; then
        local tmp
        tmp=$(mktemp)
        grep '^#' "$BASELINE" > "$tmp"
        printf '%s\n' "$new_layout" >> "$tmp"
        mv "$tmp" "$BASELINE"
        info "Rewrote $BASELINE from the working tree."
        echo "    Update the provenance header — the addresses in it are now stale." >&2
        return 0
    fi

    # 1. Every non-gap baseline entry must survive unchanged. Slot, offset,
    #    label and type all matter: a rename with the same type still means the
    #    two implementations disagree about what the slot holds, which is
    #    exactly the confusion this is meant to catch.
    local failed=0 line slot offset label type match
    while IFS=$'\t' read -r slot offset label type; do
        [[ "$label" == "__gap" ]] && continue
        match=$(printf '%s\n' "$new_layout" | awk -F'\t' -v s="$slot" '$1 == s')
        if [[ -z "$match" ]]; then
            echo "  MISSING  slot $slot — baseline has '$label' ($type), candidate has nothing" >&2
            failed=1
        elif [[ "$match" != "$slot	$offset	$label	$type" ]]; then
            echo "  CHANGED  slot $slot" >&2
            echo "             baseline : $label ($type) offset $offset" >&2
            echo "             candidate: $(printf '%s' "$match" | cut -f3) ($(printf '%s' "$match" | cut -f4)) offset $(printf '%s' "$match" | cut -f2)" >&2
            failed=1
        fi
    done < <(_baseline_rows)

    # 2 and 3. The gap absorbs the new state and the footprint does not move.
    #    Reading the length out of the type string is not elegant, but it is the
    #    only place solc reports it, and the alternative — trusting the
    #    declaration in the source — is the thing being verified.
    local old_gap new_gap old_slot old_len new_slot new_len
    old_gap=$(_baseline_rows | awk -F'\t' '$3 == "__gap"')
    new_gap=$(printf '%s\n' "$new_layout" | awk -F'\t' '$3 == "__gap"')
    [[ -n "$old_gap" ]] || die "baseline has no __gap entry"
    [[ -n "$new_gap" ]] || die "candidate has no __gap entry — the upgrade-safe gap was removed"

    old_slot=$(printf '%s' "$old_gap" | cut -f1)
    new_slot=$(printf '%s' "$new_gap" | cut -f1)
    old_len=$(printf '%s' "$old_gap" | cut -f4 | sed 's/.*)\([0-9]*\)_storage/\1/')
    new_len=$(printf '%s' "$new_gap" | cut -f4 | sed 's/.*)\([0-9]*\)_storage/\1/')

    local old_end=$(( old_slot + old_len )) new_end=$(( new_slot + new_len ))
    local added=$(( new_slot - old_slot ))

    if [[ "$new_slot" -lt "$old_slot" ]]; then
        echo "  GAP MOVED BACKWARDS — candidate __gap starts at $new_slot, deployed at $old_slot." >&2
        echo "                        State was removed, not added." >&2
        failed=1
    fi
    if [[ "$old_end" != "$new_end" ]]; then
        echo "  FOOTPRINT CHANGED — deployed occupies slots 0..$(( old_end - 1 )), candidate 0..$(( new_end - 1 ))." >&2
        echo "                      New state must be taken FROM the gap, not added beside it:" >&2
        echo "                      shrink __gap by the number of slots you added." >&2
        failed=1
    fi

    if [[ "$failed" != 0 ]]; then
        die "storage layout is NOT upgrade-safe — see above. Do not deploy this."
    fi

    if [[ "$added" == 0 ]]; then
        info "Storage layout unchanged from the deployed implementation."
    else
        info "Storage layout is upgrade-safe: $added new slot(s) taken from __gap."
        printf '%s\n' "$new_layout" \
            | awk -F'\t' -v lo="$old_slot" -v hi="$new_slot" \
                  '$1 >= lo && $1 < hi { printf "      + slot %s  %s  %s\n", $1, $3, $4 }'
        echo
        echo "    These slots must be ZERO on every live proxy before the upgrade."
        echo "    'upgrade-beacon' checks that on the group it is pointed at; it cannot"
        echo "    check groups it does not know about."
    fi
}

# --------------------------------------------------------------------------
cmd_deploy_group_impl() {
    cmd_check_layout
    echo
    need_chain; need_deployer

    info "Deploying a new SignetGroup implementation (does NOT touch the beacon)"

    local out
    out=$(cd "$CONTRACTS" && forge script script/DeployGroupImpl.s.sol \
            --rpc-url "$RPC" --broadcast --private-key "$DEPLOYER_PK" 2>&1)

    local impl hash
    impl=$(grep "UPGRADE:groupImpl=" <<< "$out" | sed 's/.*UPGRADE:groupImpl=//')
    hash=$(grep "UPGRADE:initCodeHash=" <<< "$out" | sed 's/.*UPGRADE:initCodeHash=//')
    [[ -n "$impl" ]] || { echo "$out" >&2; die "could not parse the implementation address"; }

    cat <<EOF

GroupImpl:    $impl
InitCodeHash: $hash

Nothing is upgraded yet. The beacon still serves the old implementation and
every group is untouched — deploying logic and adopting it are separate acts,
and only the second one is irreversible.

Give the cold signer BOTH values. The address is derived from the init code via
CREATE2, so they can rebuild this source and confirm the address holds the code
they think it does rather than taking your word for it.

  FACTORY_ADDRESS=${FACTORY_ADDRESS:-0x<factory>} GROUP_IMPL=$impl \\
    testnet/scripts/alpha-contracts.sh upgrade-beacon
EOF
}

# --------------------------------------------------------------------------
# cmd_upgrade_beacon is the irreversible one.
#
# It prints the transaction for a cold signer rather than sending it. ADMIN_PK
# exists only so the anvil rehearsal can drive the same code path; on a real
# chain the owner is a hardware wallet or a multisig, and a phase that reads a
# cold key out of the environment would defeat the reason it is cold.
cmd_upgrade_beacon() {
    need_chain; need_factory
    local impl="${GROUP_IMPL:-}"
    [[ -n "$impl" ]] || die "GROUP_IMPL not set — the implementation address from 'deploy-group-impl'"
    [[ "$impl" =~ ^0x[0-9a-fA-F]{40}$ ]] || die "GROUP_IMPL must be a 0x-prefixed 20-byte address, got '$impl'"

    local beacon owner current code
    beacon=$(cast call "$FACTORY" 'groupBeacon()(address)' --rpc-url "$RPC") \
        || die "could not read groupBeacon() — is FACTORY_ADDRESS a SignetFactory?"
    owner=$(cast call "$FACTORY" 'owner()(address)' --rpc-url "$RPC")
    current=$(cast call "$beacon" 'implementation()(address)' --rpc-url "$RPC")

    # An address with no code is the whole failure mode in one mistake: the
    # beacon accepts it, every group behind it delegatecalls into nothing, and
    # every call returns success with empty data. Recovery needs the cold key
    # again.
    code=$(cast code "$impl" --rpc-url "$RPC")
    [[ "$code" != "0x" && -n "$code" ]] || die "GROUP_IMPL $impl has NO CODE on this chain.
     Pointing the beacon at it bricks every group behind it — calls would
     succeed and do nothing. Check the address and the chain."

    if [[ "$(printf %s "$current" | tr 'A-F' 'a-f')" == "$(printf %s "$impl" | tr 'A-F' 'a-f')" ]]; then
        info "Beacon already serves $impl — nothing to do."
        return 0
    fi

    # Where a group address is known, confirm the slots the new implementation
    # claims are still zero. This is a spot check, not a proof: the beacon backs
    # every group, and this can only see the one it was given.
    local group="${GROUP_ADDRESS:-}"
    if [[ -n "$group" ]]; then
        local old_slot new_slot s v dirty=0
        old_slot=$(_baseline_rows | awk -F'\t' '$3 == "__gap" {print $1}')
        new_slot=$(_layout | awk -F'\t' '$3 == "__gap" {print $1}')
        for (( s = old_slot; s < new_slot; s++ )); do
            v=$(cast storage "$group" "$s" --rpc-url "$RPC")
            if [[ "$v" != "0x0000000000000000000000000000000000000000000000000000000000000000" ]]; then
                echo "  slot $s on $group is NOT zero: $v" >&2
                dirty=1
            fi
        done
        if [[ "$dirty" != 0 ]]; then
            die "the group already has data in slots the new implementation claims.
     Upgrading would read that data as SIWE state. Stop and work out what wrote it."
        fi
        info "Checked $group: slots $old_slot..$(( new_slot - 1 )) are zero."
    else
        echo "NOTE: GROUP_ADDRESS unset, so the new slots were not checked against a" >&2
        echo "      live group. Set it to have this verified." >&2
    fi

    local calldata
    calldata=$(cast calldata 'upgradeGroupImplementation(address)' "$impl")

    cat <<EOF

=== BEACON UPGRADE — this replaces the logic under EVERY group ===

  chain    : $(chain_name "$CHAIN_ID") ($CHAIN_ID)
  factory  : $FACTORY
  beacon   : $beacon
  from     : $current
  to       : $impl
  signer   : $owner   <-- must be this address, and nothing else can do it

  to       : $FACTORY
  value    : 0
  data     : $calldata

This takes effect on the next block, for every group behind the beacon at once.
There is no per-group rollout and no staging: groups other organisations manage
change implementation in the same transaction as yours.

EOF

    if [[ -n "${ADMIN_PK:-}" || "${UNLOCKED:-}" == "yes" ]]; then
        if [[ -n "${ADMIN_PK:-}" ]]; then
            local signer
            signer=$(cast wallet address "$ADMIN_PK")
            if [[ "$(printf %s "$signer" | tr 'A-F' 'a-f')" != "$(printf %s "$owner" | tr 'A-F' 'a-f')" ]]; then
                die "ADMIN_PK is $signer but the factory owner is $owner — that key cannot upgrade."
            fi
            if [[ "$CHAIN_ID" == "1" && "${ALLOW_HOT_ADMIN:-}" != "yes" ]]; then
                die "refusing to send a MAINNET beacon upgrade from a key in the environment.
     The factory owner holds standing power over every group; putting it in a
     shell to save a step is how it stops being cold. Sign the transaction above
     with the hardware wallet or multisig that owns the factory.
     ALLOW_HOT_ADMIN=yes overrides, and should not be needed on chain 1."
            fi
        fi
        info "Sending upgradeGroupImplementation as $owner..."
        _send "$owner" "${ADMIN_PK:-}" \
            "$FACTORY" 'upgradeGroupImplementation(address)' "$impl" >/dev/null
        local now
        now=$(cast call "$beacon" 'implementation()(address)' --rpc-url "$RPC")
        info "Beacon now serves: $now"
        [[ "$(printf %s "$now" | tr 'A-F' 'a-f')" == "$(printf %s "$impl" | tr 'A-F' 'a-f')" ]] \
            || die "beacon did not change — expected $impl"
        echo
        echo "Update contracts/storage-layout-baseline.tsv now, while it is true:"
        echo "  testnet/scripts/alpha-contracts.sh check-layout --write-baseline"
    else
        echo "Send it with the owner's key. Ledger, for example:"
        echo
        echo "  cast send --ledger --rpc-url \"\$ETH_RPC_URL\" \\"
        echo "    $FACTORY 'upgradeGroupImplementation(address)' $impl"
        echo
        echo "Then confirm, from any key:"
        echo
        echo "  cast call $beacon 'implementation()(address)' --rpc-url \"\$ETH_RPC_URL\""
    fi
}

# --------------------------------------------------------------------------
# cmd_siwe_domains manages the group's SIWE domain list.
#
# The list is replaced wholesale, so `queue` takes the COMPLETE future list and
# not a delta. Passing one domain to a group that already trusts three removes
# the other two.
cmd_siwe_domains() {
    local action="${1:-show}"; shift || true
    need_chain
    local group="${GROUP_ADDRESS:-}"
    [[ -n "$group" ]] || die "GROUP_ADDRESS not set"

    # An implementation without siweDomains() reverts here rather than returning
    # empty, which is the tell that the beacon upgrade has not happened yet.
    _read_domains() {
        cast call "$group" 'siweDomains()(string[])' --rpc-url "$RPC" 2>/dev/null \
            || die "siweDomains() reverted on $group.
     The group is still on an implementation that predates the SIWE domain list.
     Run 'upgrade-beacon' first."
    }

    # cast renders a uint256 as "1788223447 [1.788e9]" — the bracketed part is a
    # readability aid, not part of the value. Comparing or date-formatting the
    # whole string silently misbehaves, so take the first field.
    _execute_after() {
        cast call "$group" 'getPendingSiweDomains()(string[],uint256,address)' --rpc-url "$RPC" \
            | sed -n '2p' | awk '{print $1}'
    }

    # Read once, here: every mutating branch sends as the manager, and the
    # impersonated path needs the address even when there is no key.
    local onchain_manager
    onchain_manager=$(cast call "$group" 'manager()(address)' --rpc-url "$RPC")

    case "$action" in
    show)
        echo "current : $(_read_domains)"
        local pending ea
        pending=$(cast call "$group" 'getPendingSiweDomains()(string[],uint256,address)' --rpc-url "$RPC")
        ea=$(awk 'NR==2 {print $1}' <<< "$pending")
        if [[ -n "$ea" && "$ea" != "0" ]]; then
            echo "pending : $(sed -n '1p' <<< "$pending")"
            echo "          executes after $ea ($(date -r "$ea" 2>/dev/null || echo "$ea"))"
            echo "          queued by $(sed -n '3p' <<< "$pending")"
        else
            echo "pending : none"
        fi
        ;;

    queue)
        need_manager
        [[ $# -gt 0 ]] || die "usage: siwe-domains queue <domain> [domain...]
     Pass the COMPLETE future list — it replaces the current one wholesale.
     To disable the scheme, pass no domains via: siwe-domains queue-empty"
        local signer
        if [[ -n "$MANAGER_KEY" ]]; then
            signer=$(cast wallet address "$MANAGER_KEY")
            [[ "$(printf %s "$onchain_manager" | tr 'A-F' 'a-f')" == "$(printf %s "$signer" | tr 'A-F' 'a-f')" ]] \
                || die "MANAGER_PK is $signer but the group manager is $onchain_manager"
        fi

        # Validate locally before spending gas. The contract checks this too,
        # but a revert string costs a transaction to read and this costs
        # nothing — and the rule is subtle enough to trip on (lowercase only,
        # no scheme, no path, no trailing dot).
        local d
        for d in "$@"; do
            [[ "$d" =~ ^[a-z0-9.-]+(:[0-9]{1,5})?$ ]] \
                || die "'$d' is not a canonical SIWE domain.
     Lowercase ASCII authority only: no scheme, no path, no uppercase.
     'https://app.example.org/' is wrong; 'app.example.org' is right."
        done

        echo "Replacing the list with:"
        printf '  %s\n' "$@"
        echo "Current list: $(_read_domains)"
        echo

        local args
        args=$(printf '"%s",' "$@"); args="[${args%,}]"
        _send "$onchain_manager" "$MANAGER_KEY" \
            "$group" 'queueSiweDomains(string[])' "$args" >/dev/null

        local ea delay
        ea=$(_execute_after)
        delay=$(cast call "$group" 'removalDelay()(uint256)' --rpc-url "$RPC")
        info "Queued. Executable after $ea (removalDelay is ${delay}s)."
        echo "    Nothing changes until 'siwe-domains execute'. Until then the group"
        echo "    still accepts only: $(_read_domains)"
        ;;

    execute)
        # Permissionless, mirroring executeRemoval — any funded key will do.
        need_manager
        _send "$onchain_manager" "$MANAGER_KEY" \
            "$group" 'executeSiweDomains()' >/dev/null
        info "Applied. The group now accepts: $(_read_domains)"
        echo "    Nodes on a build that watches SiweDomainsSet pick this up on their next"
        echo "    chain poll (chain_poll_secs, default 60s). Builds before that event was"
        echo "    watched read the list ONLY at startup and will keep enforcing whatever"
        echo "    they loaded when they booted — restart them, or the change is inert."
        echo "    Check /v1/info against a build that has the handler."
        ;;

    cancel)
        need_manager
        _send "$onchain_manager" "$MANAGER_KEY" \
            "$group" 'cancelSiweDomains()' >/dev/null
        info "Cancelled. The list is unchanged: $(_read_domains)"
        ;;

    *)
        die "unknown action '$action' — one of: show, queue, execute, cancel"
        ;;
    esac
}

# --------------------------------------------------------------------------
case "${1:-}" in
    deploy-factory) shift; cmd_deploy_factory "$@" ;;
    fund)           shift; cmd_fund "$@" ;;
    register)       shift; cmd_register "$@" ;;
    gen-auth-key)   shift; cmd_gen_auth_key "$@" ;;
    create-group)   shift; cmd_create_group "$@" ;;
    accept)         shift; cmd_accept "$@" ;;
    write-env)      shift; cmd_write_env "$@" ;;

    check-layout)      shift; cmd_check_layout "$@" ;;
    deploy-group-impl) shift; cmd_deploy_group_impl "$@" ;;
    upgrade-beacon)    shift; cmd_upgrade_beacon "$@" ;;
    siwe-domains)      shift; cmd_siwe_domains "$@" ;;
    *)
        sed -n '2,59p' "$0" | sed 's/^# \{0,1\}//'
        exit 1
        ;;
esac
