# Signet Testnet

3-node Signet cluster on AWS (us-east-1, multi-AZ) with contracts on Sepolia.

## Current deployment

| Node  | AZ           | API                          |
|-------|-------------|------------------------------|
| node1 | us-east-1a   | http://54.90.227.156:8080    |
| node2 | us-east-1b   | http://44.214.181.89:8080    |
| node3 | us-east-1c   | http://44.205.254.164:8080   |

- **Instance type:** t3.medium (2 vCPU, 4 GB)
- **Signing group:** 2-of-3 (threshold=2)
- **Chain:** Sepolia
- **Auth:** Google OAuth (accounts.google.com)
- **KMS:** enabled (Rust kms-tss, FROST keygen/sign/reshare)
- **Barretenberg:** installed on each node for ZK proof verification
- **Factory:** `0xB4c55139db4ad9c481DAA82B249F934CBbB73b91`
- **Group:** `0xf75bfc536ecf70006361685f1ed0b005ea08b773`

## Prerequisites

- AWS CLI configured (`aws sso login`)
- Ansible 2.14+ with `amazon.aws` collection (`ansible-galaxy collection install amazon.aws`)
- Python boto3 (`pip3 install boto3`)
- Foundry (`forge`, `cast`)
- Go 1.22+
- jq
- SSH key pair `signet-testnet` in us-east-1
- Funded Sepolia deployer key
- Sepolia RPC URL (Alchemy / Infura)

## Full deploy from scratch

### 1. Generate node identities

```bash
testnet/scripts/init-nodes.sh
```

Creates `testnet/data/node{1..3}/` with key material and writes Ansible
`host_vars/node{1..3}.yml`.

### 2. Provision EC2 instances

```bash
cd testnet/ansible
ansible-playbook provision-single-region.yml -e ssh_key_name=signet-testnet
```

Launches 3 instances across AZs in us-east-1. Creates security group,
writes IPs to `testnet/.hosts`, and updates `inventory.yml`.

### 3. Deploy contracts to Sepolia

```bash
SEPOLIA_RPC_URL=https://... \
DEPLOYER_PK=0x... \
testnet/scripts/deploy-contracts.sh
```

Deploys SignetFactory, registers all 3 nodes, creates a 2-of-3 group
with Google OAuth as a trusted issuer. Writes `testnet/.env`.

### 4. Cross-compile and deploy

```bash
# signetd
GOOS=linux GOARCH=amd64 go build -o build/signetd-linux-amd64 ./cmd/signetd

# kms-tss (requires cross toolchain or Docker)
# Pre-built binary: build/kms-tss-linux-amd64

# Deploy everything: signetd + kms-tss + bb (Barretenberg)
cd testnet/ansible
FACTORY_ADDRESS=0x... SEPOLIA_RPC_URL=https://... \
ansible-playbook deploy.yml
```

The deploy playbook installs:
- `signetd` binary + config + systemd unit
- `kms-tss` binary + systemd unit (started before signetd)
- `bb` (Barretenberg) for ZK proof verification

### 5. Verify

```bash
ansible-playbook manage.yml -e action=status
```

All 3 nodes should show `active (running)` for both `signetd` and
`kms-tss` services.

## Management

From `testnet/ansible/`:

```bash
# Status (signetd + kms-tss)
ansible-playbook manage.yml -e action=status

# Logs
ansible-playbook manage.yml -e action=logs
ansible-playbook manage.yml -e action=logs -e log_lines=200
ansible-playbook manage.yml -e action=logs-kms

# Stop / start / restart
ansible-playbook manage.yml -e action=stop
ansible-playbook manage.yml -e action=start
ansible-playbook manage.yml -e action=restart

# Wipe data (stops services, removes data dirs)
ansible-playbook manage.yml -e action=clean

# Target single node
ansible-playbook manage.yml -e action=logs -l node2
```

## Testing

```bash
# Build harness
go build -o build/harness ./cmd/harness

# Correctness smoke test
./build/harness -env testnet/.env correctness

# Performance — 10 concurrent, 5 min
./build/harness -env testnet/.env perf -concurrency 10 -duration 300s -pool 100

# Scalability sweep
./build/harness -env testnet/.env scale -max-concurrency 50 -step 5 -duration 60s -pool 50
```

## Teardown

```bash
cd testnet/ansible
ansible-playbook teardown.yml
```

Terminates EC2 instances. Contracts on Sepolia persist.

## Directory structure

```
testnet/
  README.md
  ADDING-A-NODE.md                # guide for external node operators
  .env                            # generated: contract addresses, node APIs
  .hosts                          # generated: node IPs from provisioning
  data/
    nodes.json                    # all node identities
    node{1..3}/node.key           # per-node identity keys
  scripts/
    init-nodes.sh                 # generate node identities
    deploy-contracts.sh           # deploy to Sepolia, register, create group
  ansible/
    inventory.yml                 # node hosts, IPs, connection vars
    provision-single-region.yml   # launch EC2 in us-east-1 (multi-AZ)
    provision.yml                 # launch EC2 across 5 regions (alternative)
    deploy.yml                    # upload binaries + config, start services
    manage.yml                    # stop/start/restart/status/logs/clean
    teardown.yml                  # terminate EC2 instances
    group_vars/
      signet_nodes.yml            # shared settings (log level, KMS paths)
    host_vars/
      node{1..3}.yml              # generated: peer_id, eth_address, etc.
    roles/
      signetd/                    # signetd binary + config + systemd
      kms-tss/                  # kms-tss binary + systemd
      bb/                         # Barretenberg install (ZK verify)
```
