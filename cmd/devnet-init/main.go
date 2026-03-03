// devnet-init generates (or loads) secp256k1 identity keys for signet nodes and
// prints a JSON summary of each node's peer ID, Ethereum address, uncompressed
// public key, and raw Ethereum private key.
//
// Usage:
//
//	devnet-init <data-dir> [<data-dir> ...]
//
// Each data directory is created if it does not exist. If a node.key file is
// already present the existing key is loaded; otherwise a new key is generated
// and written to disk. The tool is idempotent: repeated runs with the same data
// directories always produce the same output.
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"golang.org/x/crypto/sha3"

	"signet/network"
)

// NodeSummary contains the identity information for a single node.
type NodeSummary struct {
	DataDir    string `json:"data_dir"`
	PeerID     string `json:"peer_id"`
	EthAddress string `json:"eth_address"` // 0x-prefixed, checksum not applied
	EthPrivKey string `json:"eth_privkey"` // 0x + 32-byte hex — the raw secp256k1 scalar
	Pubkey     string `json:"pubkey"`      // 0x04 + x + y — 65-byte uncompressed form
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: devnet-init <data-dir> [<data-dir> ...]")
		os.Exit(1)
	}

	dirs := os.Args[1:]
	nodes := make([]NodeSummary, 0, len(dirs))

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			fatalf("mkdir %s: %v", dir, err)
		}
		s, err := summarise(dir)
		if err != nil {
			fatalf("node info for %s: %v", dir, err)
		}
		nodes = append(nodes, s)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(map[string]any{"nodes": nodes}); err != nil {
		fatalf("encode: %v", err)
	}
}

func summarise(dataDir string) (NodeSummary, error) {
	keyPath := dataDir + "/node.key"

	priv, err := network.LoadOrGenerateKey(keyPath)
	if err != nil {
		return NodeSummary{}, fmt.Errorf("load/generate key: %w", err)
	}

	// Peer ID (= libp2p peer.ID string, used as party.ID in MPC sessions).
	partyID, err := network.PartyIDFromPrivKey(priv)
	if err != nil {
		return NodeSummary{}, fmt.Errorf("peer ID: %w", err)
	}

	// Raw private key scalar (32 bytes for secp256k1).
	// This IS the Ethereum private key — same curve, same scalar.
	rawPriv, err := priv.Raw()
	if err != nil {
		return NodeSummary{}, fmt.Errorf("raw privkey: %w", err)
	}

	// libp2p secp256k1 Raw() returns the 33-byte compressed public key.
	rawPub, err := priv.GetPublic().Raw()
	if err != nil {
		return NodeSummary{}, fmt.Errorf("raw pubkey: %w", err)
	}

	// Decompress to the 65-byte uncompressed form (0x04 || x || y).
	pk, err := secp.ParsePubKey(rawPub)
	if err != nil {
		return NodeSummary{}, fmt.Errorf("parse pubkey: %w", err)
	}
	uncompressed := pk.SerializeUncompressed()

	// Ethereum address = keccak256(uncompressed[1:])[12:]
	h := sha3.NewLegacyKeccak256()
	h.Write(uncompressed[1:])
	digest := h.Sum(nil)

	return NodeSummary{
		DataDir:    dataDir,
		PeerID:     string(partyID),
		EthAddress: "0x" + hex.EncodeToString(digest[12:]),
		EthPrivKey: "0x" + hex.EncodeToString(rawPriv),
		Pubkey:     "0x" + hex.EncodeToString(uncompressed),
	}, nil
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "devnet-init: "+format+"\n", args...)
	os.Exit(1)
}
