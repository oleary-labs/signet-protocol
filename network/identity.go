package network

import (
	"fmt"
	"os"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	"golang.org/x/crypto/sha3"
)

// LoadOrGenerateKey loads a private key from path, or generates and saves a new secp256k1 key.
// File format: raw protobuf bytes from crypto.MarshalPrivateKey. Perms: 0600.
func LoadOrGenerateKey(path string) (crypto.PrivKey, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		return crypto.UnmarshalPrivateKey(data)
	}
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read key file %s: %w", path, err)
	}

	// Generate new secp256k1 key.
	priv, _, err := crypto.GenerateKeyPair(crypto.Secp256k1, -1)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}

	data, err = crypto.MarshalPrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("marshal key: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return nil, fmt.Errorf("write key file %s: %w", path, err)
	}

	return priv, nil
}

// PartyIDFromPrivKey derives party.ID = party.ID(peer.IDFromPrivateKey(priv).String()).
func PartyIDFromPrivKey(priv crypto.PrivKey) (party.ID, error) {
	pid, err := peer.IDFromPrivateKey(priv)
	if err != nil {
		return "", fmt.Errorf("peer ID from key: %w", err)
	}
	return party.ID(pid.String()), nil
}

// EthereumAddress derives the Ethereum address from a secp256k1 public key.
// It returns the last 20 bytes of keccak256(uncompressed pubkey bytes without 0x04 prefix).
func EthereumAddress(pub crypto.PubKey) ([20]byte, error) {
	raw, err := pub.Raw()
	if err != nil {
		return [20]byte{}, fmt.Errorf("raw public key: %w", err)
	}
	// libp2p secp256k1 Raw() returns the 33-byte compressed form.
	// We need the 65-byte uncompressed form to follow Ethereum's convention.
	uncompressed, err := decompressSecp256k1(raw)
	if err != nil {
		return [20]byte{}, fmt.Errorf("decompress pubkey: %w", err)
	}
	// Hash the 64-byte body (skip the 0x04 prefix byte).
	d := sha3.NewLegacyKeccak256()
	d.Write(uncompressed[1:])
	h := d.Sum(nil)
	var addr [20]byte
	copy(addr[:], h[12:])
	return addr, nil
}

// EthereumAddressFromPoint derives the Ethereum address from a secp256k1 curve.Point
// as returned by the threshold library (e.g. cfg.PublicPoint()).
func EthereumAddressFromPoint(pt curve.Point) ([20]byte, error) {
	compressed, err := pt.MarshalBinary()
	if err != nil {
		return [20]byte{}, fmt.Errorf("marshal point: %w", err)
	}
	uncompressed, err := decompressSecp256k1(compressed)
	if err != nil {
		return [20]byte{}, fmt.Errorf("decompress point: %w", err)
	}
	d := sha3.NewLegacyKeccak256()
	d.Write(uncompressed[1:]) // skip 0x04 prefix
	h := d.Sum(nil)
	var addr [20]byte
	copy(addr[:], h[12:])
	return addr, nil
}

// decompressSecp256k1 converts a 33-byte compressed public key to 65-byte uncompressed form.
func decompressSecp256k1(compressed []byte) ([]byte, error) {
	pk, err := secp.ParsePubKey(compressed)
	if err != nil {
		return nil, err
	}
	return pk.SerializeUncompressed(), nil
}
