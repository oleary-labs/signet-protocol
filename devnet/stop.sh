#!/usr/bin/env bash
# devnet/stop.sh — gracefully stop all devnet processes.

set -euo pipefail

DEVNET="$(cd "$(dirname "$0")" && pwd)"
PIDS_FILE="$DEVNET/.pids"

if [[ ! -f "$PIDS_FILE" ]]; then
    echo "devnet is not running (no $PIDS_FILE found)"
    exit 0
fi

# Source the PIDs file so we get ANVIL_PID, NODE1_PID, etc.
# shellcheck disable=SC1090
source "$PIDS_FILE"

stop_pid() {
    local label="$1" pid="$2"
    if kill -0 "$pid" 2>/dev/null; then
        kill "$pid" 2>/dev/null && echo "  stopped $label (pid $pid)"
    else
        echo "  $label (pid $pid) was not running"
    fi
}

echo "Stopping devnet..."

[[ -n "${NODE1_PID:-}" ]] && stop_pid "node1"  "$NODE1_PID"
[[ -n "${NODE2_PID:-}" ]] && stop_pid "node2"  "$NODE2_PID"
[[ -n "${NODE3_PID:-}" ]] && stop_pid "node3"  "$NODE3_PID"
[[ -n "${KMS1_PID:-}"  ]] && stop_pid "kms1"   "$KMS1_PID"
[[ -n "${KMS2_PID:-}"  ]] && stop_pid "kms2"   "$KMS2_PID"
[[ -n "${KMS3_PID:-}"  ]] && stop_pid "kms3"   "$KMS3_PID"
[[ -n "${ANVIL_PID:-}" ]] && stop_pid "anvil"  "$ANVIL_PID"

# Clean up KMS sockets.
rm -f "$DEVNET"/kms*.sock

rm -f "$PIDS_FILE"
echo "Done."
