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
	TestMode       bool     `yaml:"test_mode"` // skip JWT signature + expiry checks
	VKPath         string   `yaml:"vk_path"`   // path to circuit verification key (bb format)
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
