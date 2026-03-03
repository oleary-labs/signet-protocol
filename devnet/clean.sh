#!/usr/bin/env bash
# devnet/clean.sh — remove all generated devnet state (data dirs, logs, env files).
# The devnet must be stopped first.

set -euo pipefail

DEVNET="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$DEVNET/.." && pwd)"
PIDS_FILE="$DEVNET/.pids"

if [[ -f "$PIDS_FILE" ]]; then
    echo "ERROR: devnet appears to be running. Run devnet/stop.sh first." >&2
    exit 1
fi

echo "Cleaning devnet state..."

# Node data directories (bbolt databases, key files).
for n in 1 2 3; do
    dir="$REPO/data/node${n}"
    if [[ -d "$dir" ]]; then
        rm -rf "$dir"
        echo "  removed $dir"
    fi
done

# Generated config files and logs.
for f in \
    "$DEVNET/node1.yaml" \
    "$DEVNET/node2.yaml" \
    "$DEVNET/node3.yaml" \
    "$DEVNET/anvil.log" \
    "$DEVNET/node1.log" \
    "$DEVNET/node2.log" \
    "$DEVNET/node3.log" \
    "$DEVNET/.env"
do
    if [[ -f "$f" ]]; then
        rm -f "$f"
        echo "  removed $f"
    fi
done

# Forge broadcast artifacts from the last devnet deploy.
BROADCAST_DIR="$REPO/contracts/broadcast"
if [[ -d "$BROADCAST_DIR" ]]; then
    rm -rf "$BROADCAST_DIR"
    echo "  removed $BROADCAST_DIR"
fi

echo "Done. Run devnet/start.sh to start fresh."
