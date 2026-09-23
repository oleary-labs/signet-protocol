package node

import (
	"os"
	"path/filepath"
	"testing"
)

// The rendered form of testnet/ansible/roles/signetd/templates/config.yaml.j2
// when chain_rpcs is set. A Celo resolver is bound to the 6-node alpha group, so
// an unparsed or mistyped chain id here presents as "no RPC configured for chain
// 42220" on every SIWE login — which is what it did on 2026-09-21.
func TestLoadConfig_ParsesChainRPCs(t *testing.T) {
	const rendered = `data_dir: /opt/signet/data
listen_addr: /ip4/0.0.0.0/tcp/9000
api_addr: 127.0.0.1:8080
node_type: public
eth_rpc: https://eth-mainnet.example/v2/KEY
factory_address: 0x86EB99D569AaD51c3160C5C50ec3093e6771c07a
chain_poll_secs: 60
chain_rpcs:
  42220: "https://forno.celo.org"
`
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(rendered), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	got, ok := cfg.ChainRPCs[42220]
	if !ok {
		t.Fatalf("chain 42220 missing; ChainRPCs = %#v", cfg.ChainRPCs)
	}
	if got != "https://forno.celo.org" {
		t.Fatalf("chain 42220 = %q", got)
	}
}
