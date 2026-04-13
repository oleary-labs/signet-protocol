package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// deployerPK returns the DEPLOYER_PK from the OS environment (not the .env file).
func (e *Env) deployerPK() string {
	return os.Getenv("DEPLOYER_PK")
}

// Node represents a single signet node the harness can talk to.
type Node struct {
	Name   string
	API    string // e.g. "http://localhost:8080"
	PeerID string
	Eth    string
	Region string // optional, e.g. "us-east-1"
}

// Env holds all environment configuration loaded from a .env file.
type Env struct {
	RPCURL         string
	FactoryAddress string
	GroupAddress   string
	Nodes          []Node
}

// LoadEnv parses a devnet/.env or testnet/.env file.
func LoadEnv(path string) (*Env, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open env file: %w", err)
	}
	defer f.Close()

	vals := map[string]string{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		vals[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read env file: %w", err)
	}

	env := &Env{
		RPCURL:         vals["RPC_URL"],
		FactoryAddress: vals["FACTORY_ADDRESS"],
		GroupAddress:   vals["GROUP_ADDRESS"],
	}

	if env.GroupAddress == "" {
		return nil, fmt.Errorf("GROUP_ADDRESS not found in %s", path)
	}

	// Discover nodes by looking for NODE<N>_API keys.
	for i := 1; ; i++ {
		prefix := fmt.Sprintf("NODE%d_", i)
		api := vals[prefix+"API"]
		if api == "" {
			break
		}
		env.Nodes = append(env.Nodes, Node{
			Name:   fmt.Sprintf("node%d", i),
			API:    api,
			PeerID: vals[prefix+"PEER"],
			Eth:    vals[prefix+"ETH"],
			Region: vals[prefix+"REGION"],
		})
	}

	if len(env.Nodes) == 0 {
		return nil, fmt.Errorf("no NODE<N>_API entries found in %s", path)
	}

	return env, nil
}
