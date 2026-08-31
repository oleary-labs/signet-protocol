package node

import (
	"os"

	"gopkg.in/yaml.v3"
)

// Config holds all configuration for a signet node.
type Config struct {
	DataDir        string   `yaml:"data_dir"`
	ListenAddr     string   `yaml:"listen_addr"`
	APIAddr        string   `yaml:"api_addr"`
	AnnounceAddr   string   `yaml:"announce_addr"`
	BootstrapPeers []string `yaml:"bootstrap_peers"`
	NodeType       string   `yaml:"node_type"`
	EthRPC         string   `yaml:"eth_rpc"`
	FactoryAddress string   `yaml:"factory_address"`
	KMSSocket      string   `yaml:"kms_socket"`      // Unix socket path to external KMS; empty = in-process tss
	ChainPollSecs  int      `yaml:"chain_poll_secs"` // chain event poll interval in seconds; 0 = default (60)

	// ChainRPCs maps a chainId to an RPC URL for chains OTHER than the home
	// chain (the one EthRPC points at). Used by the on-chain auth resolver: a
	// group's resolver may live on a different chain, and a node serving such a
	// group must have trusted RPC reach to that chain. The home chain is
	// registered automatically from EthRPC (its chainId is detected at dial
	// time), so it need not appear here.
	ChainRPCs map[uint64]string `yaml:"chain_rpcs"`

	// NOTE: siwe_domain was removed. The accepted ERC-4361 domains are read from
	// the group contract (SignetGroup.siweDomains) rather than node config.
	//
	// Not deprecated with a fallback — deleted. The check gates session creation
	// and is therefore consensus-relevant, so a per-node value can drift into
	// some nodes accepting a session while others reject it, which fails
	// intermittently and points nowhere. A fallback would be worse than the old
	// behaviour because it would fail only sometimes.
}

// LoadConfig reads a YAML config file and applies defaults for missing fields.
// If the file does not exist, defaults are returned with no error.
func LoadConfig(path string) (*Config, error) {
	cfg := &Config{
		DataDir:    "./data",
		ListenAddr: "/ip4/0.0.0.0/tcp/9000",
		APIAddr:    ":8080",
		NodeType:   "public",
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return nil, err
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}
