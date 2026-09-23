#!/usr/bin/env bash
# testnet/scripts/init-alpha.sh — Generate alpha node identities and secrets.
#
# Like init-nodes.sh, but for the alpha cluster, and it additionally generates
# the two at-rest secrets that can only be set at creation time:
#
#   kms_kek             — 32-byte KEK for the kms-tss sled store. kms-tss keys
#                         encryption off the presence of SIGNET_KMS_KEY and has
#                         no migration path either way, so this must exist
#                         before the first keygen.
#   node_key_passphrase — passphrase for node.key. network.LoadOrGenerateKey
#                         only encrypts a *newly generated* key; an existing
#                         plaintext node.key is never re-encrypted in place.
#                         Fresh identities are the only chance to turn this on.
#
# Both are per-node. devnet-init reads the passphrase from the environment and
# applies it to every directory in one invocation, so it is called once per node
# rather than once for all of them.
#
# Each organisation runs this on ITS OWN machine, for ITS OWN nodes only.
# Private material (node.key, eth_privkey, KEK, passphrase) never leaves that
# machine. The script also emits a PUBLIC manifest — peer_id, eth_address,
# pubkey — which is the only thing that needs to be shared with the other
# operators.
#
# This split is not merely good practice: SignetFactory.registerNode requires
#   _pubkeyToAddress(pubkey) == msg.sender
# so a node can only be registered by a transaction signed with its own key.
# No operator can register another operator's nodes even if it wanted to.
#
# ALPHA_OPERATOR is an Ethereum address this org controls. It is recorded
# on-chain per node via registerNode, and SignetGroup uses it to authorise
# join/leave for those nodes (SignetGroup.sol:149,158,166). Left unset, the
# factory falls back to treating each node as its own operator
# (SignetFactory.sol:232), which is what the testnet does today — it works, but
# nothing on-chain then records that several nodes belong to one organisation.
#
# Recording it is informational, not a constraint: a customer picks whatever
# topology it wants — nodes from several independent operators, or several from
# one — and can change that later by resharding. The point is that the choice
# is visible rather than implicit.
#
# ALPHA_DOMAIN names this org's nodes for TLS. Each operator uses a domain it
# controls, so it issues and renews its own certificates: a shared domain would
# let whoever holds the zone issue certs for every other operator's nodes.
#
# Usage:
#   ALPHA_ORG=sfluv ALPHA_DOMAIN=nodes.sfluv.org \
#     ALPHA_NODES="sfluv1 sfluv2 sfluv3 sfluv4" testnet/scripts/init-alpha.sh
#   ALPHA_ORG=oll ALPHA_DOMAIN=nodes.olearylabs.com \
#     ALPHA_NODES="oll1 oll2" testnet/scripts/init-alpha.sh
#
# Afterwards, encrypt the secrets (strongly recommended — plaintext operator
# secrets on a laptop are what forced this rebuild):
#   ansible-vault encrypt testnet/ansible/host_vars/*.yml

set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
TESTNET="$REPO/testnet"
BUILD="$REPO/build"
HOST_VARS="$TESTNET/ansible/host_vars"
DATA="$TESTNET/data"

die() { echo "ERROR: $*" >&2; exit 1; }

command -v jq      >/dev/null 2>&1 || die "'jq' not found"
command -v openssl >/dev/null 2>&1 || die "'openssl' not found"

ORG="${ALPHA_ORG:-}"
[[ -n "$ORG" ]] || die "ALPHA_ORG not set (e.g. ALPHA_ORG=sfluv or ALPHA_ORG=oll)"
[[ "$ORG" =~ ^[a-z0-9-]+$ ]] || die "ALPHA_ORG must be lowercase alphanumeric/dash"

# This org's nodes only. Keep in sync with the `nodes` block in the
# provisioner this org runs.
read -r -a NODE_NAMES <<< "${ALPHA_NODES:-}"
[[ ${#NODE_NAMES[@]} -gt 0 ]] || die "ALPHA_NODES not set (e.g. ALPHA_NODES=\"sfluv1 sfluv2\")"

# Optional: without it the manifest carries no hostname and TLS cannot be
# enabled for this org's nodes (ACME will not issue for a bare IP).
DOMAIN="${ALPHA_DOMAIN:-}"
if [[ -n "$DOMAIN" ]]; then
    [[ "$DOMAIN" =~ ^[a-z0-9.-]+\.[a-z]{2,}$ ]] || die "ALPHA_DOMAIN must be a domain name, got '$DOMAIN'"
fi

# Optional: an address this org controls, recorded as the on-chain operator
# for its nodes. Can be changed later with setOperator, so this is not a
# one-way door.
OPERATOR="${ALPHA_OPERATOR:-}"
if [[ -n "$OPERATOR" ]]; then
    [[ "$OPERATOR" =~ ^0x[0-9a-fA-F]{40}$ ]] || die "ALPHA_OPERATOR must be a 0x-prefixed 20-byte address, got '$OPERATOR'"
fi

MANIFEST="$DATA/manifest-${ORG}.json"

if [[ ! -x "$BUILD/devnet-init" ]]; then
    echo "==> Building devnet-init..."
    (cd "$REPO" && go build -o "$BUILD/devnet-init" ./cmd/devnet-init)
fi

mkdir -p "$DATA" "$HOST_VARS"

# Refuse to clobber. Regenerating an identity for a node that is already
# registered on-chain silently orphans its registration, and regenerating a KEK
# makes that node's existing sled store undecryptable.
for name in "${NODE_NAMES[@]}"; do
    if [[ -f "$DATA/$name/node.key" ]]; then
        die "$DATA/$name/node.key already exists — refusing to overwrite.
     Remove testnet/data/$name to regenerate, but note that an on-chain
     registration for the old identity will be left dangling."
    fi
done

echo "==> [${ORG}] Generating ${#NODE_NAMES[@]} node identities: ${NODE_NAMES[*]}"
if [[ -n "$OPERATOR" ]]; then
    echo "    operator: ${OPERATOR}"
else
    echo "    operator: (unset — each node will be its own operator on-chain)"
fi
echo

merged='{"nodes":[]}'
public='{"org":"","operator":"","nodes":[]}'
public=$(jq --arg o "$ORG" --arg op "$OPERATOR" '.org=$o | .operator=$op' <<< "$public")

for name in "${NODE_NAMES[@]}"; do
    node_dir="$DATA/$name"

    passphrase="$(openssl rand -hex 32)"
    kek="$(openssl rand -hex 32)"

    # One invocation per node so each node.key gets its own passphrase.
    node_json="$(SIGNET_NODE_KEY_PASSPHRASE="$passphrase" \
                 "$BUILD/devnet-init" "$node_dir")"

    peer=$(jq -r '.nodes[0].peer_id'     <<< "$node_json")
    addr=$(jq -r '.nodes[0].eth_address' <<< "$node_json")
    pk=$(  jq -r '.nodes[0].eth_privkey' <<< "$node_json")
    pub=$( jq -r '.nodes[0].pubkey'      <<< "$node_json")

    [[ -n "$peer" && "$peer" != "null" ]] || die "devnet-init produced no peer_id for $name"

    # Sanity-check that the passphrase actually took effect. An encrypted
    # envelope starts with the 8-byte magic "SIGNETK1" (network/keyfile.go);
    # a legacy plaintext key is raw libp2p protobuf and never does. Catching a
    # silent fallback here beats discovering it after deploy.
    if [[ "$(head -c 8 "$node_dir/node.key")" != "SIGNETK1" ]]; then
        die "$name/node.key is not encrypted (missing SIGNETK1 magic).
     SIGNET_NODE_KEY_PASSPHRASE did not take effect — aborting rather than
     shipping a plaintext identity key."
    fi

    cat > "$HOST_VARS/${name}.yml" <<EOF
---
# Generated by testnet/scripts/init-alpha.sh — contains SECRETS.
# Encrypt before this file goes anywhere:
#   ansible-vault encrypt testnet/ansible/host_vars/${name}.yml
peer_id: "${peer}"
eth_address: "${addr}"
eth_privkey: "${pk}"
pubkey: "${pub}"
local_node_key_path: "${node_dir}/node.key"

# 32-byte KEK for the kms-tss sled store (SIGNET_KMS_KEY).
# Changing this after the first keygen makes existing shards unreadable.
kms_kek: "${kek}"

# Passphrase for node.key. Must match what the key was generated with —
# there is no way to recover the identity if this is lost.
node_key_passphrase: "${passphrase}"
EOF
    chmod 600 "$HOST_VARS/${name}.yml"

    merged=$(jq --argjson n "$(jq '.nodes[0]' <<< "$node_json")" \
                --arg name "$name" \
                '.nodes += [$n + {name: $name}]' <<< "$merged")

    # Public manifest: deliberately excludes eth_privkey, kms_kek and the
    # node-key passphrase. This is the file that gets shared.
    hostname=""
    [[ -n "$DOMAIN" ]] && hostname="${name}.${DOMAIN}"
    public=$(jq --arg name "$name" --arg org "$ORG" \
                --arg peer "$peer" --arg addr "$addr" --arg pub "$pub" \
                --arg host "$hostname" \
                '.nodes += [{name: $name, org: $org, peer_id: $peer,
                             eth_address: $addr, pubkey: $pub,
                             hostname: $host}]' <<< "$public")

    echo "    ${name}  peer=${peer}  eth=${addr}${hostname:+  host=${hostname}}"
done

# Carry the operator into the private summary too — `register` reads it from
# there alongside the node keys.
merged=$(jq --arg op "$OPERATOR" '.operator=$op' <<< "$merged")

echo "$merged" > "$DATA/nodes-${ORG}.json"
chmod 600 "$DATA/nodes-${ORG}.json"

echo "$public" > "$MANIFEST"
chmod 644 "$MANIFEST"

# Fail loudly if anything secret leaked into the shareable file.
for forbidden in eth_privkey kms_kek node_key_passphrase private; do
    if grep -qi "$forbidden" "$MANIFEST"; then
        die "manifest $MANIFEST contains '$forbidden' — refusing to continue"
    fi
done

cat <<EOF

Written for org '${ORG}':

  PRIVATE — never leaves this machine
    Identities   testnet/data/{$(IFS=,; echo "${NODE_NAMES[*]}")}/node.key  (encrypted)
    Host vars    testnet/ansible/host_vars/*.yml                            (0600)
    Summary      testnet/data/nodes-${ORG}.json                             (0600)

  PUBLIC — share this with the other operators
    Manifest     ${MANIFEST}

NEXT

  1. Encrypt the secrets. host_vars is gitignored, but gitignored is not
     encrypted, and a laptop compromise is what forced this rebuild:

       ansible-vault encrypt testnet/ansible/host_vars/*.yml

  2. Send ${MANIFEST##*/} to the other operators, and collect theirs into
     testnet/data/. It carries no private material — the check above enforces
     that.
$(if [[ -n "$DOMAIN" ]]; then cat <<INNER

  2b. Point DNS at the provisioned addresses before deploying — Caddy cannot
      obtain a certificate until each name resolves to its node:
$(for n in "${NODE_NAMES[@]}"; do echo "        ${n}.${DOMAIN}  ->  <${n} public IP>"; done)
INNER
else cat <<INNER

  2b. ALPHA_DOMAIN was not set, so no hostnames were recorded and TLS cannot be
      enabled for these nodes. Re-run with ALPHA_DOMAIN to fix that before
      exposing the API.
INNER
fi)

  3. Follow testnet/ALPHA-RUNBOOK.md from "Phase 2".
EOF
