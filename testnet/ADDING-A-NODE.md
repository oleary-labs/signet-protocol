# Adding a Node to the Signet Testnet

This guide walks through adding a new node to the existing Signet
testnet. The node joins the cluster, registers on-chain, and can then
be added to signing groups.

## What you need

- A Linux server (Ubuntu 24.04 LTS, 2 vCPU / 4 GB minimum)
  - AWS: t3.medium
  - GCP: e2-medium
  - Any VPS with a public IP works
- Ports **9000** (libp2p) and **8080** (HTTP API) open
- SSH access from your local machine
- Sepolia ETH (~0.01) for the node registration transaction
- The testnet factory address: `0xB4c55139db4ad9c481DAA82B249F934CBbB73b91`

## Overview

1. Provision a server (or use an existing one)
2. Generate a node identity
3. Register the node on-chain
4. Add the node to the Ansible inventory
5. Deploy with Ansible

## Step 0: Provision a server (optional)

If you don't already have a server, use one of the provisioning playbooks:

**AWS:**
```bash
cd testnet/ansible
ansible-playbook provision-single-region.yml -e ssh_key_name=signet-testnet
```

**GCP:**
```bash
cd testnet/ansible
ansible-playbook provision-gcp.yml \
  -e gcp_project=your-project-id \
  -e node_name=node4
```

Both create an Ubuntu 24.04 instance with the right firewall rules and
add it to the inventory. Skip to Step 2 if using these.

## Step 1: Generate a node identity

```bash
go build -o build/devnet-init ./cmd/devnet-init
./build/devnet-init testnet/data/node4
```

This outputs the node's **peer ID**, **Ethereum address**, and
**public key**. Save these — you'll need them for registration and
Ansible config.

Create the Ansible host_vars file at `testnet/ansible/host_vars/node4.yml`:

```yaml
---
peer_id: "16Uiu2HAm..."
eth_address: "0x..."
eth_privkey: "0x..."
pubkey: "0x..."
local_node_key_path: "testnet/data/node4/node.key"
```

## Step 2: Register on-chain

Fund the node's Ethereum address with Sepolia ETH, then register it
with the factory contract:

```bash
cast send \
  --private-key <NODE_PRIVKEY> \
  --rpc-url $SEPOLIA_RPC_URL \
  0xB4c55139db4ad9c481DAA82B249F934CBbB73b91 \
  "registerNode(bytes,bool,address)" \
  <NODE_PUBKEY> true "0x0000000000000000000000000000000000000000"
```

The `true` flag marks the node as "open" — available to join groups.

## Step 3: Add to Ansible inventory

Edit `testnet/ansible/inventory.yml` and add the new node:

```yaml
        node4:
          ansible_host: <PUBLIC_IP>
          aws_region: us-east-1
          node_index: 4
```

## Step 4: Deploy with Ansible

```bash
cd testnet/ansible

# Deploy signetd + kms-tss + bb to the new node only
FACTORY_ADDRESS=0xB4c55139db4ad9c481DAA82B249F934CBbB73b91 \
SEPOLIA_RPC_URL=https://... \
ansible-playbook deploy.yml -l node4
```

This uploads binaries, writes the config (with bootstrap peers to
existing nodes), installs systemd units, installs Barretenberg, and
starts all services.

### Verify

```bash
# Check services
ansible-playbook manage.yml -e action=status -l node4

# Check connectivity
curl http://<PUBLIC_IP>:8080/v1/health
curl http://<PUBLIC_IP>:8080/v1/info | jq .
```

The node should show connected bootstrap peers in the info response.

## Step 5: Join a signing group

The group owner adds your node on-chain:

```bash
cast send \
  --private-key $GROUP_OWNER_PK \
  --rpc-url $SEPOLIA_RPC_URL \
  <GROUP_ADDRESS> \
  "addNode(address)" \
  <NODE_ETH_ADDRESS>
```

All nodes detect the membership change from chain events. An automatic
reshare redistributes key shares to include the new node within seconds.

## Troubleshooting

**Node can't connect to bootstrap peers:**
- Check that ports 9000 and 8080 are open (security group / firewall)
- Verify `announce_addr` in the generated config uses the public IP
- Check logs: `ansible-playbook manage.yml -e action=logs -l node4`

**"bb binary not found" on auth requests:**
- The deploy playbook installs bb automatically. If it failed, check:
  `ansible-playbook manage.yml -e action=logs -l node4`
- bb is installed to `/usr/local/bin/bb` (copied, not symlinked)
- The signetd systemd unit sets `HOME=/opt/signet` for the CRS cache

**"key not found" on sign requests:**
- The node must be in the signing group and hold key shares
- After being added to a group, reshare distributes shares automatically
- Check: `curl http://<IP>:8080/v1/keys -X POST -d '{"group_id":"<GROUP>"}'`

## Manual setup (without Ansible)

If you're not using Ansible, see the deploy playbook and role templates
for the exact steps:
- `roles/signetd/tasks/main.yml` — binary, config, systemd
- `roles/kms-tss/tasks/main.yml` — KMS binary, systemd
- `roles/bb/tasks/main.yml` — Barretenberg installation
- `roles/signetd/templates/config.yaml.j2` — node config with bootstrap peers
- `roles/signetd/templates/signetd.service.j2` — systemd unit (note `HOME=/opt/signet`)
