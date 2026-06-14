package network

import (
	"fmt"
	"os"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"golang.org/x/crypto/sha3"

	"signet/tss"
)

// KeyPassphraseEnv is the environment variable holding the passphrase used to
// encrypt the node identity key at rest. When unset/empty, the key is stored in
// the legacy plaintext format.
const KeyPassphraseEnv = "SIGNET_NODE_KEY_PASSPHRASE"

// LoadOrGenerateKey loads a private key from path, or generates and saves a new
// secp256k1 key. Perms: 0600.
//
// If passphrase is non-empty, a newly generated key is encrypted at rest with
// XChaCha20-Poly1305 under a scrypt-derived key (see keyfile.go); on load, an
// encrypted file is decrypted with the same passphrase. An empty passphrase
// stores/loads the legacy plaintext format (raw protobuf from
// crypto.MarshalPrivateKey). Encrypted files are self-describing via a magic
// prefix, so a legacy plaintext key still loads even when a passphrase is set —
// this keeps existing nodes working while new nodes get encryption.
func LoadOrGenerateKey(path, passphrase string) (crypto.PrivKey, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		if isEncryptedKeyFile(data) {
			data, err = decryptKeyFile(data, passphrase)
			if err != nil {
				return nil, fmt.Errorf("decrypt key file %s: %w", path, err)
			}
		}
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

	if passphrase != "" {
		data, err = encryptKeyFile(data, passphrase)
		if err != nil {
			return nil, fmt.Errorf("encrypt key file %s: %w", path, err)
		}
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return nil, fmt.Errorf("write key file %s: %w", path, err)
	}

	return priv, nil
}

// PartyIDFromPrivKey derives tss.PartyID from a libp2p private key.
func PartyIDFromPrivKey(priv crypto.PrivKey) (tss.PartyID, error) {
	pid, err := peer.IDFromPrivateKey(priv)
	if err != nil {
		return "", fmt.Errorf("peer ID from key: %w", err)
	}
	return tss.PartyID(pid.String()), nil
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

// EthereumAddressFromGroupKey derives the Ethereum address from a 33-byte
// compressed secp256k1 public key (e.g. cfg.GroupKey).
func EthereumAddressFromGroupKey(compressed []byte) ([20]byte, error) {
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

// PeerIDFromUncompressedPubkey derives a libp2p peer.ID from a 65-byte uncompressed
// secp256k1 public key (0x04 prefix). This is the inverse of how devnet-init prints pubkeys.
func PeerIDFromUncompressedPubkey(uncompressed []byte) (peer.ID, error) {
	pk, err := secp.ParsePubKey(uncompressed)
	if err != nil {
		return "", fmt.Errorf("parse uncompressed pubkey: %w", err)
	}
	libp2pKey, err := crypto.UnmarshalSecp256k1PublicKey(pk.SerializeCompressed())
	if err != nil {
		return "", fmt.Errorf("unmarshal secp256k1 pubkey: %w", err)
	}
	return peer.IDFromPublicKey(libp2pKey)
}

// decompressSecp256k1 converts a 33-byte compressed public key to 65-byte uncompressed form.
func decompressSecp256k1(compressed []byte) ([]byte, error) {
	pk, err := secp.ParsePubKey(compressed)
	if err != nil {
		return nil, err
	}
	return pk.SerializeUncompressed(), nil
}
