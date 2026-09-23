package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
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

	// AuthKey/AuthIdentity come from the env file, which is where
	// alpha-contracts.sh write-env puts them. They were previously read only
	// from the process environment, so the documented invocation
	//
	//	./build/harness -env testnet/.env-alpha correctness
	//
	// picked up neither: every request went out unauthenticated and a group
	// with an auth policy answered 401 to all of them. The process
	// environment still wins, so exporting either continues to override.
	AuthKey      string
	AuthIdentity string
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
		AuthKey:        vals["HARNESS_AUTH_KEY"],
		AuthIdentity:   vals["HARNESS_AUTH_IDENTITY"],
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

// stopTestnetNodes stops all signetd processes via ansible. Called as a deferred
// cleanup to prevent idle nodes from burning RPC quota. Best-effort: logs
// errors but does not fail the harness run.
func stopTestnetNodes(envFile string, env *Env) {
	// Derive ansible dir: testnet/.env → testnet/ansible/
	envDir := filepath.Dir(envFile)
	ansibleDir := filepath.Join(envDir, "ansible")
	playbook := filepath.Join(ansibleDir, "manage.yml")

	if _, err := os.Stat(playbook); err != nil {
		fmt.Fprintf(os.Stderr, "\nstop-after: ansible playbook not found at %s, skipping\n", playbook)
		return
	}

	fmt.Printf("\n[stop-after] stopping testnet nodes via ansible...\n")

	cmd := exec.Command("ansible-playbook", "manage.yml", "-e", "action=stop")
	cmd.Dir = ansibleDir
	// Pass RPC_URL and FACTORY_ADDRESS so ansible inventory resolves.
	cmd.Env = append(os.Environ(),
		"SEPOLIA_RPC_URL="+env.RPCURL,
		"FACTORY_ADDRESS="+env.FactoryAddress,
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	done := make(chan error, 1)
	go func() { done <- cmd.Run() }()

	select {
	case err := <-done:
		if err != nil {
			fmt.Fprintf(os.Stderr, "[stop-after] ansible stop failed: %v\n", err)
		} else {
			fmt.Println("[stop-after] all nodes stopped")
		}
	case <-time.After(60 * time.Second):
		fmt.Fprintf(os.Stderr, "[stop-after] ansible stop timed out after 60s\n")
		cmd.Process.Kill()
	}
}
