#!/usr/bin/env bash
# test-ecdsa-e2e.sh — End-to-end test for threshold ECDSA signing.
#
# Prerequisites:
#   - devnet running with KMS (devnet/start.sh, no --no-kms)
#   - source devnet/.env
#
# Usage:
#   source devnet/.env
#   scripts/test-ecdsa-e2e.sh

set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"

die()  { echo "FAIL: $*" >&2; exit 1; }
info() { echo "==> $*"; }
ok()   { echo "  OK: $*"; }

API="${NODE1_API:-http://localhost:8080}"
GROUP="${GROUP_ADDRESS:-}"
[[ -z "$GROUP" ]] && die "GROUP_ADDRESS not set — source devnet/.env first"

KEY_ID="ecdsa-test-$(date +%s)"
MESSAGE_HASH="deadbeef01234567deadbeef01234567deadbeef01234567deadbeef01234567"

# -------------------------------------------------------------------------
# 1. Keygen with ecdsa_secp256k1
# -------------------------------------------------------------------------
info "ECDSA keygen (key_id=$KEY_ID)..."

KEYGEN_RESP=$(curl -s -X POST "$API/v1/keygen" \
    -H 'Content-Type: application/json' \
    -d "{\"group_id\":\"$GROUP\",\"key_id\":\"$KEY_ID\",\"curve\":\"ecdsa_secp256k1\"}")

echo "  response: $KEYGEN_RESP"

PUBKEY=$(echo "$KEYGEN_RESP" | jq -r '.public_key')
CURVE=$(echo "$KEYGEN_RESP" | jq -r '.curve')
ETH_ADDR=$(echo "$KEYGEN_RESP" | jq -r '.ethereum_address')

[[ "$PUBKEY" == "null" || -z "$PUBKEY" ]] && die "keygen failed: $KEYGEN_RESP"
[[ "$CURVE" == "ecdsa_secp256k1" ]] || die "unexpected curve: $CURVE"
ok "keygen: pubkey=$PUBKEY curve=$CURVE eth_addr=$ETH_ADDR"

# -------------------------------------------------------------------------
# 2. Sign with ecdsa_secp256k1
# -------------------------------------------------------------------------
info "ECDSA sign (message_hash=0x$MESSAGE_HASH)..."

SIGN_RESP=$(curl -s -X POST "$API/v1/sign" \
    -H 'Content-Type: application/json' \
    -d "{\"group_id\":\"$GROUP\",\"key_id\":\"$KEY_ID\",\"curve\":\"ecdsa_secp256k1\",\"message_hash\":\"0x$MESSAGE_HASH\"}")

echo "  response: $SIGN_RESP"

SIGNATURE=$(echo "$SIGN_RESP" | jq -r '.signature')
ECDSA_SIG=$(echo "$SIGN_RESP" | jq -r '.ecdsa_signature')
RESP_CURVE=$(echo "$SIGN_RESP" | jq -r '.curve')

[[ "$SIGNATURE" == "null" || -z "$SIGNATURE" ]] && die "sign failed: $SIGN_RESP"
[[ "$RESP_CURVE" == "ecdsa_secp256k1" ]] || die "unexpected response curve: $RESP_CURVE"
ok "sign: signature=$SIGNATURE (${#SIGNATURE} chars)"

# -------------------------------------------------------------------------
# 3. Verify (TODO: add Go ECDSA verifier)
# -------------------------------------------------------------------------
info "Signature details:"
echo "  Public key:       $PUBKEY"
echo "  Ethereum address: $ETH_ADDR"
echo "  Message hash:     0x$MESSAGE_HASH"
echo "  ECDSA signature:  $ECDSA_SIG"
echo "  Curve:            $RESP_CURVE"

echo ""
echo "ECDSA threshold signing test completed."
echo "Signature is standard ECDSA (r || s) — verifiable via ecrecover."
