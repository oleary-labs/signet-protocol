#!/usr/bin/env bash
# devnet/zkbench.sh — build and run the ZK proof benchmark.
#
# Generates a test JWT, writes circuit inputs, then measures:
#   compile -> witness -> prove -> verify
#
# Prerequisites:
#   nargo  (noirup)
#   bb     (bbup -nv <noir-version>)

set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="$REPO/build"

export PATH="$HOME/.nargo/bin:$HOME/.bb:$PATH"

# Check toolchain.
for cmd in nargo bb go; do
  if ! command -v "$cmd" &>/dev/null; then
    echo "error: $cmd not found in PATH" >&2
    exit 1
  fi
done

# Build.
echo "Building zkbench..."
go build -o "$BUILD/zkbench" "$REPO/cmd/zkbench"

# Run.
cd "$REPO"
exec "$BUILD/zkbench" "$@"
