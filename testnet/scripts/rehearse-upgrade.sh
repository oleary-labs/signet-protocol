#!/usr/bin/env bash
# testnet/scripts/rehearse-upgrade.sh — run the beacon upgrade against a fork of
# the live chain, end to end, before the cold key signs anything for real.
#
# WHAT THIS IS FOR
#
# A beacon upgrade is not a deploy. BeaconProxy keeps state in the proxy and
# takes only code from the implementation, so a new implementation does not
# migrate anything — it reinterprets live storage in place, for every group
# behind the beacon, in one transaction. There is no failed transaction to
# notice when it goes wrong: the upgrade succeeds and the data quietly means
# something else.
#
# Unit tests cannot catch that, because they build their state with the new
# contract. The only state that proves anything is state written by the OLD
# implementation, which exists in exactly one place. So this forks it.
#
# WHAT IT ACTUALLY VERIFIES
#
#   1. The fork really is running the old implementation (siweDomains() reverts).
#   2. The layout check passes against the deployed baseline.
#   3. The upgrade lands, from the real owner address, via the real phase script.
#   4. Every piece of pre-existing group state reads back identically afterwards:
#      members, threshold, quorum, manager, auth keys, operational status.
#   5. The new state starts empty rather than inheriting whatever those slots
#      held — the thing the layout check predicts, confirmed rather than assumed.
#   6. The full SIWE lifecycle works on that upgraded group: queue, timelock
#      refusal, execute, read back.
#
# WHAT IT CANNOT VERIFY
#
# The signature. The real upgrade is signed by a cold key this script does not
# have and should not have, so it impersonates the owner via anvil instead. That
# one step — and only that step — is untested until it happens for real. It is
# also the step with the least in it: one call, one argument, printed in full by
# `upgrade-beacon` before it asks for anything.
#
# Usage:
#   ETH_RPC_URL=https://... testnet/scripts/rehearse-upgrade.sh
#
# Optional:
#   SIWE_DOMAINS="app.sfluv.org"   domains to rehearse (space separated)
#   FORK_PORT=8546                 anvil port
#   FORK_BLOCK=<n>                 pin the fork block (default: latest)

set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
DATA="$REPO/testnet/data"
ALPHA="$REPO/testnet/scripts/alpha-contracts.sh"

PORT="${FORK_PORT:-8546}"
FORK_RPC="http://127.0.0.1:$PORT"
DOMAINS="${SIWE_DOMAINS:-app.sfluv.org}"

# anvil's first dev account. Public, funded on every anvil, worthless anywhere
# else — it pays for the implementation deploy on the fork.
DEV_PK=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

die()  { echo "ERROR: $*" >&2; exit 1; }
info() { echo; echo "=== $* ==="; }
ok()   { echo "  ok   $*"; }

PASS=0
FAIL=0
check() { # check <label> <expected> <actual>
    if [[ "$2" == "$3" ]]; then
        ok "$1"
        PASS=$((PASS + 1))
    else
        echo "  FAIL $1" >&2
        echo "         expected: $2" >&2
        echo "         actual  : $3" >&2
        FAIL=$((FAIL + 1))
    fi
}

for c in anvil cast forge jq; do
    command -v "$c" >/dev/null 2>&1 || die "'$c' not found"
done

[[ -n "${ETH_RPC_URL:-}" ]] || die "ETH_RPC_URL not set — this is the chain to FORK, and it is only ever read"
[[ -f "$DATA/factory.env" ]] || die "missing $DATA/factory.env — nothing to rehearse against"

# shellcheck disable=SC1091
source "$DATA/factory.env"
: "${FACTORY_ADDRESS:?not in factory.env}"
: "${GROUP_ADDRESS:?not in factory.env}"
: "${GROUP_BEACON:?not in factory.env}"

ANVIL_PID=""
cleanup() {
    if [[ -n "$ANVIL_PID" ]] && kill -0 "$ANVIL_PID" 2>/dev/null; then
        kill "$ANVIL_PID" 2>/dev/null || true
        wait "$ANVIL_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

# --------------------------------------------------------------------------
info "Forking $(cast chain-id --rpc-url "$ETH_RPC_URL") into anvil on port $PORT"

# --chain-id 31337 deliberately, while forking a chain that is not 31337.
#
# The fork carries the real state, which is the point; the chain id is only a
# label, and no contract here reads block.chainid. Reporting 1 would make every
# mainnet guard in alpha-contracts.sh fire on a fork — and the way past those
# guards would be MAINNET_CONFIRMED and ALLOW_HOT_ADMIN, which are exactly the
# habits not worth building. A rehearsal should not be practice at overriding
# the safety rails.
ANVIL_ARGS=(--fork-url "$ETH_RPC_URL" --chain-id 31337 --port "$PORT" --auto-impersonate --silent)
[[ -n "${FORK_BLOCK:-}" ]] && ANVIL_ARGS+=(--fork-block-number "$FORK_BLOCK")

anvil "${ANVIL_ARGS[@]}" &
ANVIL_PID=$!

for _ in $(seq 1 40); do
    if cast chain-id --rpc-url "$FORK_RPC" >/dev/null 2>&1; then break; fi
    sleep 0.5
done
cast chain-id --rpc-url "$FORK_RPC" >/dev/null 2>&1 || die "anvil did not come up on $FORK_RPC"
ok "fork up at block $(cast block-number --rpc-url "$FORK_RPC")"

R=(--rpc-url "$FORK_RPC")

# --------------------------------------------------------------------------
info "Pre-upgrade state (this is what must survive)"

PRE_IMPL=$(cast call "$GROUP_BEACON" 'implementation()(address)' "${R[@]}")
PRE_NODES=$(cast call "$GROUP_ADDRESS" 'getActiveNodes()(address[])' "${R[@]}")
PRE_THRESH=$(cast call "$GROUP_ADDRESS" 'threshold()(uint256)' "${R[@]}")
PRE_QUORUM=$(cast call "$GROUP_ADDRESS" 'quorum()(uint256)' "${R[@]}")
PRE_MANAGER=$(cast call "$GROUP_ADDRESS" 'manager()(address)' "${R[@]}")
PRE_KEYS=$(cast call "$GROUP_ADDRESS" 'getAuthKeys()(bytes[])' "${R[@]}")
PRE_OPER=$(cast call "$GROUP_ADDRESS" 'isOperational()(bool)' "${R[@]}")
PRE_DELAY=$(cast call "$GROUP_ADDRESS" 'removalDelay()(uint256)' "${R[@]}")
OWNER=$(cast call "$FACTORY_ADDRESS" 'owner()(address)' "${R[@]}")

echo "  beacon impl : $PRE_IMPL"
echo "  members     : $(tr -cd ',' <<< "$PRE_NODES" | wc -c | tr -d ' ') + 1"
echo "  threshold   : $PRE_THRESH   quorum: $PRE_QUORUM   operational: $PRE_OPER"
echo "  manager     : $PRE_MANAGER"
echo "  auth keys   : $PRE_KEYS"
echo "  removalDelay: ${PRE_DELAY}s"
echo "  factory owner: $OWNER"

# The fork is only worth anything if it is running the OLD code. If siweDomains()
# answers here, the chain being forked already has the upgrade and this whole run
# would be testing nothing while looking green.
info "Confirming the fork is on the OLD implementation"
if cast call "$GROUP_ADDRESS" 'siweDomains()(string[])' "${R[@]}" >/dev/null 2>&1; then
    die "siweDomains() already answers on the fork — the forked chain is ALREADY upgraded.
     Nothing below would be a rehearsal. Check which chain ETH_RPC_URL points at."
fi
ok "siweDomains() reverts pre-upgrade, as it must"

# --------------------------------------------------------------------------
info "Phase: check-layout"
"$ALPHA" check-layout

# --------------------------------------------------------------------------
info "Phase: deploy-group-impl"
DEPLOY_OUT=$(ETH_RPC_URL="$FORK_RPC" CHAIN_ID=31337 DEPLOYER_PK="$DEV_PK" \
    FACTORY_ADDRESS="$FACTORY_ADDRESS" "$ALPHA" deploy-group-impl)
echo "$DEPLOY_OUT"
NEW_IMPL=$(grep -E '^GroupImpl:' <<< "$DEPLOY_OUT" | awk '{print $2}')
[[ -n "$NEW_IMPL" ]] || die "could not parse the new implementation address"

# CREATE2 means this address is a function of the init code alone, so the address
# a real deploy produces from this source is the same one. Worth printing: it is
# checkable ahead of time rather than after the fact.
echo
echo "  A mainnet deploy of this source lands at the same address: $NEW_IMPL"

# --------------------------------------------------------------------------
info "Phase: upgrade-beacon (impersonating the cold owner)"
cast rpc anvil_setBalance "$OWNER" 0xDE0B6B3A7640000 "${R[@]}" >/dev/null

ETH_RPC_URL="$FORK_RPC" CHAIN_ID=31337 UNLOCKED=yes \
    FACTORY_ADDRESS="$FACTORY_ADDRESS" GROUP_ADDRESS="$GROUP_ADDRESS" \
    GROUP_IMPL="$NEW_IMPL" "$ALPHA" upgrade-beacon

# --------------------------------------------------------------------------
info "Did the upgrade preserve everything it did not mean to touch?"

POST_IMPL=$(cast call "$GROUP_BEACON" 'implementation()(address)' "${R[@]}")
check "beacon now serves the new implementation" \
    "$(tr 'A-F' 'a-f' <<< "$NEW_IMPL")" "$(tr 'A-F' 'a-f' <<< "$POST_IMPL")"

check "active node set unchanged"  "$PRE_NODES"   "$(cast call "$GROUP_ADDRESS" 'getActiveNodes()(address[])' "${R[@]}")"
check "threshold unchanged"        "$PRE_THRESH"  "$(cast call "$GROUP_ADDRESS" 'threshold()(uint256)' "${R[@]}")"
check "quorum unchanged"           "$PRE_QUORUM"  "$(cast call "$GROUP_ADDRESS" 'quorum()(uint256)' "${R[@]}")"
check "manager unchanged"          "$PRE_MANAGER" "$(cast call "$GROUP_ADDRESS" 'manager()(address)' "${R[@]}")"
check "auth keys unchanged"        "$PRE_KEYS"    "$(cast call "$GROUP_ADDRESS" 'getAuthKeys()(bytes[])' "${R[@]}")"
check "still operational"          "$PRE_OPER"    "$(cast call "$GROUP_ADDRESS" 'isOperational()(bool)' "${R[@]}")"
check "removalDelay unchanged"     "$PRE_DELAY"   "$(cast call "$GROUP_ADDRESS" 'removalDelay()(uint256)' "${R[@]}")"

# The layout check predicts this. Reading it back is what turns the prediction
# into a result: if the new fields had landed on occupied slots, they would come
# back holding whatever was there rather than empty.
info "Does the new state start empty, rather than inheriting old bytes?"
check "siweDomains() is empty"     "[]"           "$(cast call "$GROUP_ADDRESS" 'siweDomains()(string[])' "${R[@]}")"
PENDING=$(cast call "$GROUP_ADDRESS" 'getPendingSiweDomains()(string[],uint256,address)' "${R[@]}")
check "nothing queued (executeAfter)" "0"                                            "$(sed -n '2p' <<< "$PENDING")"
check "no initiator"                  "0x0000000000000000000000000000000000000000"   "$(sed -n '3p' <<< "$PENDING")"

# --------------------------------------------------------------------------
info "Phase: siwe-domains queue $DOMAINS"
cast rpc anvil_setBalance "$PRE_MANAGER" 0xDE0B6B3A7640000 "${R[@]}" >/dev/null

# shellcheck disable=SC2086
ETH_RPC_URL="$FORK_RPC" CHAIN_ID=31337 UNLOCKED=yes \
    GROUP_ADDRESS="$GROUP_ADDRESS" "$ALPHA" siwe-domains queue $DOMAINS

check "list is NOT applied yet" "[]" "$(cast call "$GROUP_ADDRESS" 'siweDomains()(string[])' "${R[@]}")"

# The timelock has to actually refuse, or it is decoration.
info "Does the timelock hold?"
if cast call "$GROUP_ADDRESS" 'executeSiweDomains()' "${R[@]}" >/dev/null 2>&1; then
    echo "  FAIL executeSiweDomains() succeeded before the delay elapsed" >&2
    FAIL=$((FAIL + 1))
else
    ok "execute refused before the delay elapsed"
    PASS=$((PASS + 1))
fi

cast rpc evm_increaseTime "$((PRE_DELAY + 1))" "${R[@]}" >/dev/null
cast rpc evm_mine "${R[@]}" >/dev/null
ok "advanced $((PRE_DELAY + 1))s"

info "Phase: siwe-domains execute"
ETH_RPC_URL="$FORK_RPC" CHAIN_ID=31337 UNLOCKED=yes \
    GROUP_ADDRESS="$GROUP_ADDRESS" "$ALPHA" siwe-domains execute

EXPECT=$(printf '"%s", ' $DOMAINS); EXPECT="[${EXPECT%, }]"
check "group accepts the rehearsed domains" "$EXPECT" \
    "$(cast call "$GROUP_ADDRESS" 'siweDomains()(string[])' "${R[@]}")"

PENDING=$(cast call "$GROUP_ADDRESS" 'getPendingSiweDomains()(string[],uint256,address)' "${R[@]}")
check "queue cleared after execute" "0" "$(sed -n '2p' <<< "$PENDING")"

check "members STILL intact after the whole sequence" "$PRE_NODES" \
    "$(cast call "$GROUP_ADDRESS" 'getActiveNodes()(address[])' "${R[@]}")"

# --------------------------------------------------------------------------
info "Result"
echo "  passed: $PASS"
echo "  failed: $FAIL"
echo
if [[ "$FAIL" != 0 ]]; then
    die "rehearsal FAILED — do not run this upgrade on the real chain"
fi

cat <<EOF
Rehearsal passed against a fork of the live chain.

Untested, and only this: the cold key's signature on

  $FACTORY_ADDRESS  upgradeGroupImplementation($NEW_IMPL)

Everything else above ran the same code path the real upgrade will.

The fork is discarded when this script exits. Nothing was sent to
$ETH_RPC_URL — it was read from, never written to.
EOF
