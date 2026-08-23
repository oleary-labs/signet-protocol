#!/usr/bin/env bash
# testnet/scripts/audit-instances.sh — Find every Signet EC2 instance in every
# AWS region, regardless of what any playbook's region list claims.
#
# Why this exists: teardown playbooks select on `tag:Project` within a
# hardcoded region list, so an instance launched in a region that later gets
# dropped from that list survives every teardown and bills forever. Commit
# 0ef0c0a records exactly this — the abandoned 5-region provisioner left "an
# orphan" in us-west-1, and teardown.yml only ever looks at us-east-1.
#
# Read-only. Prints what it finds and terminates nothing.
#
# Usage:
#   testnet/scripts/audit-instances.sh
#   testnet/scripts/audit-instances.sh --all-tags   # ignore the Project filter

set -euo pipefail

die() { echo "ERROR: $*" >&2; exit 1; }

command -v aws >/dev/null 2>&1 || die "'aws' not found"
command -v jq  >/dev/null 2>&1 || die "'jq' not found"

aws sts get-caller-identity >/dev/null 2>&1 \
    || die "no usable AWS credentials — run 'aws login' (or configure a profile) first"

ALL_TAGS=false
[[ "${1:-}" == "--all-tags" ]] && ALL_TAGS=true

echo "==> Account: $(aws sts get-caller-identity --query Account --output text)"
echo "==> Enumerating regions..."

# Only regions actually enabled for this account; describe-instances against a
# disabled region errors out.
REGIONS=$(aws ec2 describe-regions \
            --filters Name=opt-in-status,Values=opt-in-not-required,opted-in \
            --query 'Regions[].RegionName' --output text)

REGION_COUNT=$(wc -w <<< "$REGIONS" | tr -d ' ')
echo "==> Sweeping $REGION_COUNT regions"
echo

if $ALL_TAGS; then
    FILTERS=(--filters "Name=instance-state-name,Values=pending,running,stopping,stopped")
else
    FILTERS=(--filters "Name=tag:Project,Values=signet-*"
             "Name=instance-state-name,Values=pending,running,stopping,stopped")
fi

TOTAL=0
FOUND_REGIONS=()

for region in $REGIONS; do
    json=$(aws ec2 describe-instances --region "$region" "${FILTERS[@]}" \
             --query 'Reservations[].Instances[].{
                 id:InstanceId,
                 state:State.Name,
                 type:InstanceType,
                 ip:PublicIpAddress,
                 launched:LaunchTime,
                 project:(Tags[?Key==`Project`].Value | [0]),
                 node:(Tags[?Key==`Node`].Value | [0]),
                 name:(Tags[?Key==`Name`].Value | [0])
             }' --output json 2>/dev/null) || {
        echo "  ! $region — describe-instances failed (skipped)"
        continue
    }

    count=$(jq 'length' <<< "$json")
    [[ "$count" -eq 0 ]] && continue

    TOTAL=$((TOTAL + count))
    FOUND_REGIONS+=("$region")

    echo "--- $region  ($count)"
    jq -r '.[] | "    \(.id)  \(.state    // "?" | . + "        "[:8])  " +
                 "\(.type   // "?")  \(.ip // "-")  " +
                 "project=\(.project // "-")  node=\(.node // .name // "-")  " +
                 "launched=\(.launched // "-")"' <<< "$json"
    echo
done

echo "=========================================="
if [[ "$TOTAL" -eq 0 ]]; then
    echo "No matching instances in any region."
else
    echo "$TOTAL instance(s) across: ${FOUND_REGIONS[*]}"
    echo
    echo "Cross-check against the region lists that teardown actually uses:"
    echo "  teardown.yml        → us-east-1 only"
    echo "  teardown-alpha.yml  → regions derived from its own 'nodes' block"
    echo
    echo "Anything above in a region not covered there will survive teardown."
fi

echo
echo "NOTE: this sweeps AWS only, and Vultr not at all. The testnet's GCP node"
echo "      (signet-signet-testnet1, 136.119.229.55, provisioned by"
echo "      ansible/provision-gcp.yml) was deleted on 2026-08-23; the alpha's"
echo "      GCP nodes live in project sfluv-842cb. Sweep the other clouds:"
echo "        gcloud compute instances list --project=sfluv-842cb"
echo "        gcloud projects list   # then repeat per project — nodes have"
echo "                               # landed in more than one before"
