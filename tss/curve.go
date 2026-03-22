package tss

import (
	secp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"golang.org/x/crypto/sha3"
)

// EthereumAddressFromGroupKey derives the Ethereum address from a 33-byte
// compressed secp256k1 public key.
// address = keccak256(uncompressed_pubkey[1:])[12:]
func EthereumAddressFromGroupKey(compressed []byte) ([20]byte, error) {
	pub, err := secp256k1.ParsePubKey(compressed)
	if err != nil {
		return [20]byte{}, err
	}
	uncompressed := pub.SerializeUncompressed()
	h := sha3.NewLegacyKeccak256()
	h.Write(uncompressed[1:])
	digest := h.Sum(nil)
	var addr [20]byte
	copy(addr[:], digest[12:])
	return addr, nil
}
