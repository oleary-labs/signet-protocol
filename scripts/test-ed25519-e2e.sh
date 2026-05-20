#!/usr/bin/env bash
# test-ed25519-e2e.sh — End-to-end test for FROST Ed25519 signatures.
#
# Runs against a live devnet (must be running with KMS):
#   1. Keygen with curve=ed25519
#   2. Sign a test message
#   3. Verify with Go crypto/ed25519
#   4. Verify on Solana devnet via Ed25519SigVerify precompile
#
# Prerequisites:
#   - devnet running with KMS and without auth:
#       devnet/stop.sh && devnet/clean.sh && devnet/start.sh
#     (Ed25519 requires KMS; --no-kms uses bytemare/frost which lacks Ed25519)
#     (--auth requires ZK proof credentials; omit for this test)
#   - source devnet/.env
#   - Node.js installed (for Solana verification script)
#
# Usage:
#   source devnet/.env
#   scripts/test-ed25519-e2e.sh

set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"

die()  { echo "FAIL: $*" >&2; exit 1; }
info() { echo "==> $*"; }
ok()   { echo "  OK: $*"; }

# Require devnet env.
API="${NODE1_API:-http://localhost:8080}"
GROUP="${GROUP_ADDRESS:-}"
[[ -z "$GROUP" ]] && die "GROUP_ADDRESS not set — source devnet/.env first"

KEY_ID="ed25519-test-$(date +%s)"
MESSAGE_HASH="deadbeef01234567deadbeef01234567deadbeef01234567deadbeef01234567"

# -------------------------------------------------------------------------
# 1. Keygen
# -------------------------------------------------------------------------
info "Ed25519 keygen (key_id=$KEY_ID)..."

KEYGEN_RESP=$(curl -s -X POST "$API/v1/keygen" \
    -H 'Content-Type: application/json' \
    -d "{\"group_id\":\"$GROUP\",\"key_id\":\"$KEY_ID\",\"curve\":\"ed25519\"}")

echo "  response: $KEYGEN_RESP"

PUBKEY=$(echo "$KEYGEN_RESP" | jq -r '.public_key')
CURVE=$(echo "$KEYGEN_RESP" | jq -r '.curve')

[[ "$PUBKEY" == "null" || -z "$PUBKEY" ]] && die "keygen failed: $KEYGEN_RESP"
[[ "$CURVE" == "ed25519" ]] || die "unexpected curve: $CURVE"
ok "keygen: pubkey=$PUBKEY curve=$CURVE"

# -------------------------------------------------------------------------
# 2. Sign
# -------------------------------------------------------------------------
info "Ed25519 sign (message_hash=0x$MESSAGE_HASH)..."

SIGN_RESP=$(curl -s -X POST "$API/v1/sign" \
    -H 'Content-Type: application/json' \
    -d "{\"group_id\":\"$GROUP\",\"key_id\":\"$KEY_ID\",\"curve\":\"ed25519\",\"message_hash\":\"0x$MESSAGE_HASH\"}")

echo "  response: $SIGN_RESP"

SIGNATURE=$(echo "$SIGN_RESP" | jq -r '.signature')

[[ "$SIGNATURE" == "null" || -z "$SIGNATURE" ]] && die "sign failed: $SIGN_RESP"
ok "sign: signature=$SIGNATURE"

# -------------------------------------------------------------------------
# 3. Go Ed25519 verification
# -------------------------------------------------------------------------
info "Go crypto/ed25519 verification..."

go run "$REPO/cmd/verify-ed25519" \
    --pubkey "$PUBKEY" \
    --message "0x$MESSAGE_HASH" \
    --signature "$SIGNATURE"

ok "Go Ed25519 verification passed"

# -------------------------------------------------------------------------
# 4. Solana devnet verification
# -------------------------------------------------------------------------
info "Solana Ed25519SigVerify verification..."

# Install deps if needed.
if [ ! -d "$REPO/scripts/node_modules" ]; then
    info "Installing @solana/web3.js..."
    (cd "$REPO/scripts" && npm install --silent)
fi

node "$REPO/scripts/verify-solana-ed25519.mjs" \
    --pubkey "$PUBKEY" \
    --message "0x$MESSAGE_HASH" \
    --signature "$SIGNATURE"

ok "Solana Ed25519SigVerify passed"

# -------------------------------------------------------------------------
echo ""
echo "All Ed25519 verification tests passed."
echo "  Pubkey:    $PUBKEY"
echo "  Message:   0x$MESSAGE_HASH"
echo "  Signature: $SIGNATURE"
