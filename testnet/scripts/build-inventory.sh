#!/usr/bin/env bash
# testnet/scripts/build-inventory.sh — Assemble the shared alpha inventory from
# each operator's public manifest plus the host fragments from provisioning.
#
# Every operator needs an inventory listing ALL nodes, because
# roles/signetd/templates/config.yaml.j2 iterates groups['signet_nodes'] to
# build bootstrap_peers — a node cannot dial peers it has never heard of. But
# each operator only holds host_vars (secrets) for its own nodes, and only
# deploys to its own nodes.
#
# So the inventory is public, shared, and identical for everyone; the secrets
# beside it are not. Deploy with --limit so you only touch your own hosts:
#
#   ansible-playbook -i inventory-alpha.yml deploy.yml --limit org_sfluv
#
# Inputs (all in testnet/):
#   data/manifest-<org>.json   one per operator — name, org, peer_id, addresses
#   .hosts-alpha               name=IP lines, concatenated from each operator's
#                              provisioning run
#   .clouds-alpha              name=cloud lines, written by each provisioner.
#                              Determines the login user: Vultr images log in
#                              as root, AWS and GCP as ubuntu. An org spanning
#                              two clouds therefore cannot have one user for
#                              the whole group, so ansible_user is per host.
#
# Usage:
#   testnet/scripts/build-inventory.sh
#   ALPHA_SSH_USER_sfluv1=sfluv-ops testnet/scripts/build-inventory.sh
#   ALPHA_SSH_KEY_oll_vultr=~/.ssh/other-key testnet/scripts/build-inventory.sh
#
# SSH keys are resolved per host, not per org. An org can span clouds — OLL runs
# AWS and Vultr — and a per-cloud key means a compromised key, or a laptop that
# only ever touches one provider, is contained to that provider. Resolution
# order, first hit wins:
#
#   ALPHA_SSH_KEY_<org>_<cloud>   e.g. ALPHA_SSH_KEY_oll_vultr
#   ALPHA_SSH_KEY_<org>           one key for the whole org
#   ~/.ssh/signet-alpha-<cloud>   the convention the provisioners default to
#
# Nothing is emitted if none of those resolve, leaving Ansible's own default.
#
# The default is emitted as a TILDE path on purpose. This inventory is shared
# verbatim between operators, so an absolute /Users/<someone>/.ssh/... would be
# meaningless on every other machine; ~/.ssh/signet-alpha-<cloud> resolves for
# whoever runs it. Ansible expanduser()s it before handing it to ssh
# (plugins/connection/ssh.py). Setting the env vars above bypasses this — the
# shell expands ~ at assignment, baking in one machine's home directory.

set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
TESTNET="$REPO/testnet"
DATA="$TESTNET/data"
HOST_VARS="$TESTNET/ansible/host_vars"
HOSTS="$TESTNET/.hosts-alpha"
CLOUDS="$TESTNET/.clouds-alpha"
OUT="$TESTNET/ansible/inventory-alpha.yml"

die()  { echo "ERROR: $*" >&2; exit 1; }
info() { echo "==> $*"; }

command -v jq >/dev/null 2>&1 || die "'jq' not found"

missing_hostnames=""

# Plain while-read rather than `mapfile`: macOS ships bash 3.2, which has no
# mapfile, and operators run this from their laptops.
MANIFESTS=()
while IFS= read -r m; do MANIFESTS+=("$m"); done \
    < <(find "$DATA" -maxdepth 1 -name 'manifest-*.json' | sort)
[[ ${#MANIFESTS[@]} -gt 0 ]] || die "no testnet/data/manifest-*.json found"

info "Manifests: ${MANIFESTS[*]##*/}"
[[ -f "$HOSTS" ]] || info "WARNING: $HOSTS missing — hosts will get a placeholder IP"

# Cross-check: where this operator holds a node's host_vars, the peer_id there
# must match the manifest. A mismatch means a node was re-initialised after its
# manifest was shared, which would silently produce an unreachable bootstrap
# entry on every other operator's nodes.
check_peer_id() {
    local name="$1" manifest_peer="$2" hv="$HOST_VARS/$1.yml"
    [[ -f "$hv" ]] || return 0
    head -c 16 "$hv" | grep -q '\$ANSIBLE_VAULT' && return 0   # vaulted, cannot read
    local local_peer
    local_peer=$(grep -E '^peer_id:' "$hv" | head -1 | sed 's/.*"\(.*\)".*/\1/')
    [[ -z "$local_peer" || "$local_peer" == "$manifest_peer" ]] || die \
        "peer_id mismatch for $name:
     manifest:  $manifest_peer
     host_vars: $local_peer
     One of them is stale. Re-share the manifest, or restore the identity."
}

ip_for() {
    local name="$1"
    [[ -f "$HOSTS" ]] && grep -m1 "^${name}=" "$HOSTS" | cut -d= -f2 || true
}

cloud_for() {
    local name="$1"
    [[ -f "$CLOUDS" ]] && grep -m1 "^${name}=" "$CLOUDS" | cut -d= -f2 || true
}

# Default login user per provider. Vultr Linux images have no unprivileged
# default account; AWS and GCP Ubuntu images use `ubuntu`. Override per node
# with ALPHA_SSH_USER_<node>.
user_for() {
    local name="$1" cloud="$2"
    local override
    override=$(eval "echo \${ALPHA_SSH_USER_${name}:-}")
    if [[ -n "$override" ]]; then echo "$override"; return; fi
    case "$cloud" in
        vultr) echo root ;;
        *)     echo ubuntu ;;
    esac
}

# Per host rather than per org — see the header. Prints nothing when no key
# resolves, so the caller omits the line entirely.
key_for() {
    local org="$1" cloud="$2"
    local v
    v=$(eval "echo \${ALPHA_SSH_KEY_${org}_${cloud}:-}")
    if [[ -n "$v" ]]; then echo "$v"; return; fi
    v=$(eval "echo \${ALPHA_SSH_KEY_${org}:-}")
    if [[ -n "$v" ]]; then echo "$v"; return; fi
    if [[ "$cloud" != "unknown" && -f "$HOME/.ssh/signet-alpha-${cloud}" ]]; then
        echo "~/.ssh/signet-alpha-${cloud}"
    fi
}

{
    echo "---"
    echo "# Generated by testnet/scripts/build-inventory.sh — do not hand-edit."
    echo "# PUBLIC: contains no secrets. Every operator holds an identical copy."
    echo "# Secrets live in host_vars/, which each operator has only for its own nodes."
    echo "all:"
    echo "  children:"
    echo "    signet_nodes:"
    echo "      children:"

    for m in "${MANIFESTS[@]}"; do
        org=$(jq -r '.org' "$m")
        echo "        org_${org}:"
        echo "          hosts:"
        while IFS=$'\t' read -r name peer host; do
            check_peer_id "$name" "$peer"
            ip=$(ip_for "$name")
            if [[ -z "$ip" ]]; then
                ip="0.0.0.0"
                echo "            # WARNING: no IP in .hosts-alpha for $name" >&2
            fi
            cloud=$(cloud_for "$name")
            [[ -n "$cloud" ]] || cloud=unknown
            echo "            ${name}:"
            echo "              ansible_host: ${ip}"
            echo "              peer_id: \"${peer}\""
            echo "              org: ${org}"
            echo "              cloud: ${cloud}"
            echo "              ansible_user: $(user_for "$name" "$cloud")"
            keyfile=$(key_for "$org" "$cloud")
            if [[ -n "$keyfile" ]]; then
                echo "              ansible_ssh_private_key_file: ${keyfile}"
            else
                echo "            # NOTE: no SSH key resolved for $name ($cloud)" >&2
            fi
            # node_hostname drives the Caddy vhost and the ACME certificate.
            # Absent means this org did not set ALPHA_DOMAIN, so TLS is off
            # for the node and the API would be served in cleartext.
            if [[ -n "$host" && "$host" != "null" ]]; then
                echo "              node_hostname: ${host}"
            else
                echo "              # WARNING: no hostname — TLS cannot be enabled for this node"
                missing_hostnames="${missing_hostnames} ${name}"
            fi
        done < <(jq -r '.nodes[] | [.name, .peer_id, (.hostname // "")] | @tsv' "$m")

        # ansible_user and ansible_ssh_private_key_file are both set per host
        # above: an org can span clouds with different default accounts AND
        # different keys, so neither can be a group-level var.
    done

    echo "      vars:"
    echo "        ansible_python_interpreter: /usr/bin/python3"
} > "$OUT"

info "Wrote $OUT"
echo
total=$(jq -s '[.[].nodes[]] | length' "${MANIFESTS[@]}")
echo "  $total nodes across ${#MANIFESTS[@]} operators"
for m in "${MANIFESTS[@]}"; do
    org=$(jq -r '.org' "$m")
    n=$(jq '.nodes | length' "$m")
    clouds=""
    while IFS= read -r nm; do
        c=$(cloud_for "$nm"); [[ -n "$c" ]] || c=unknown
        case " $clouds " in *" $c "*) ;; *) clouds="$clouds $c" ;; esac
    done < <(jq -r '.nodes[].name' "$m")
    echo "    org_${org}: $n node(s) on${clouds}  → deploy with --limit org_${org}"
done

if [[ -n "$missing_hostnames" ]]; then
    echo
    echo "  WARNING: no hostname for:${missing_hostnames}"
    echo "           Those nodes cannot get a certificate — ACME will not issue"
    echo "           for a bare IP. Re-run init-alpha.sh with ALPHA_DOMAIN set,"
    echo "           re-share the manifest, and rebuild. Deploying with"
    echo "           use_tls=true will fail the assert in the caddy role."
fi

if [[ ! -f "$CLOUDS" ]]; then
    echo
    echo "  WARNING: no $CLOUDS — every host defaulted to ansible_user=ubuntu."
    echo "           Vultr nodes need root and will fail to connect."
fi
echo
echo "Reminder: ECDSA needs 2T-1 signers, so a threshold of T over $total nodes"
echo "tolerates $total - (2T-1) of them being down. See docs/DESIGN-SIGNER-SELECTION.md."
