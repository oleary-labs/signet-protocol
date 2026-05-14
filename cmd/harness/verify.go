package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// secp256k1N is the curve order for secp256k1.
var secp256k1N, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)

// VerifyFROSTSignature verifies a FROST ethereum signature (65-byte hex: rx||z||v)
// against the group public key (33-byte compressed hex) and message hash (32-byte hex).
//
// This replicates the ecrecover-based verification used by the on-chain FROSTVerifier
// and mirrors tss/ethereum_test.go:TestSigEthereumEcrecover.
func VerifyFROSTSignature(sigHex, groupPubKeyHex, msgHashHex string) error {
	sigBytes, err := decodeHex(sigHex)
	if err != nil {
		return fmt.Errorf("decode sig: %w", err)
	}
	if len(sigBytes) != 65 {
		return fmt.Errorf("sig must be 65 bytes, got %d", len(sigBytes))
	}

	groupKey, err := decodeHex(groupPubKeyHex)
	if err != nil {
		return fmt.Errorf("decode group key: %w", err)
	}

	msgHash, err := decodeHex(msgHashHex)
	if err != nil {
		return fmt.Errorf("decode msg hash: %w", err)
	}
	if len(msgHash) != 32 {
		return fmt.Errorf("msg hash must be 32 bytes, got %d", len(msgHash))
	}

	// Reconstruct R compressed from rx and v.
	rx := new(big.Int).SetBytes(sigBytes[:32])
	z := new(big.Int).SetBytes(sigBytes[32:64])
	v := sigBytes[64] // R.y parity: 0=even (0x02), 1=odd (0x03)

	rPrefix := byte(0x02)
	if v == 1 {
		rPrefix = 0x03
	}
	rCompressed := make([]byte, 33)
	rCompressed[0] = rPrefix
	rx.FillBytes(rCompressed[1:])

	// c = FROST challenge H2(R_compressed || groupPubKey || msgHash)
	c := frostChallenge(rCompressed, groupKey, msgHash)
	if c.Sign() == 0 {
		return fmt.Errorf("FROST challenge is zero")
	}

	// cInv = c^(-1) mod N
	cInv := new(big.Int).ModInverse(c, secp256k1N)

	// sEc = -rx * cInv mod N
	sEc := new(big.Int).Mul(rx, cInv)
	sEc.Mod(sEc, secp256k1N)
	sEc.Sub(secp256k1N, sEc)

	// hashEc = -rx * z * cInv mod N
	hashEc := new(big.Int).Mul(rx, z)
	hashEc.Mul(hashEc, cInv)
	hashEc.Mod(hashEc, secp256k1N)
	hashEc.Sub(secp256k1N, hashEc)

	var ecSig [65]byte
	rx.FillBytes(ecSig[:32])
	sEc.FillBytes(ecSig[32:64])
	ecSig[64] = v

	hashEcBytes := make([]byte, 32)
	hashEc.FillBytes(hashEcBytes)

	recoveredPub, err := crypto.Ecrecover(hashEcBytes, ecSig[:])
	if err != nil {
		return fmt.Errorf("ecrecover: %w", err)
	}
	recoveredAddr := common.BytesToAddress(crypto.Keccak256(recoveredPub[1:])[12:])

	ecdsaPub, err := crypto.DecompressPubkey(groupKey)
	if err != nil {
		return fmt.Errorf("decompress group key: %w", err)
	}
	expectedAddr := crypto.PubkeyToAddress(*ecdsaPub)

	if recoveredAddr != expectedAddr {
		return fmt.Errorf("ecrecover address mismatch: got %s, want %s",
			recoveredAddr.Hex(), expectedAddr.Hex())
	}
	return nil
}

// frostChallenge computes c = H2(R || PK || msg) using expand_message_xmd
// (RFC 9380) with SHA-256 and DST "FROST-secp256k1-SHA256-v1chal".
func frostChallenge(rCompressed, groupPubKey, message []byte) *big.Int {
	const dst = "FROST-secp256k1-SHA256-v1chal"
	dstPrime := append([]byte(dst), byte(len(dst)))

	input := make([]byte, 0, len(rCompressed)+len(groupPubKey)+len(message))
	input = append(input, rCompressed...)
	input = append(input, groupPubKey...)
	input = append(input, message...)

	h := sha256.New()
	h.Write(make([]byte, 64))
	h.Write(input)
	h.Write([]byte{0x00, 0x30})
	h.Write([]byte{0x00})
	h.Write(dstPrime)
	b0 := h.Sum(nil)

	h.Reset()
	h.Write(b0)
	h.Write([]byte{0x01})
	h.Write(dstPrime)
	b1 := h.Sum(nil)

	b1XorB0 := make([]byte, 32)
	for i := range b1XorB0 {
		b1XorB0[i] = b1[i] ^ b0[i]
	}
	h.Reset()
	h.Write(b1XorB0)
	h.Write([]byte{0x02})
	h.Write(dstPrime)
	b2 := h.Sum(nil)

	uniform := append(b1, b2[:16]...)
	c := new(big.Int).SetBytes(uniform)
	c.Mod(c, secp256k1N)
	return c
}

// VerifyECDSASignature verifies a recoverable ECDSA signature (65-byte hex: r||s||v)
// against the group public key (33-byte compressed hex) and message hash (32-byte hex).
func VerifyECDSASignature(sigHex, groupPubKeyHex, msgHashHex string) error {
	sigBytes, err := decodeHex(sigHex)
	if err != nil {
		return fmt.Errorf("decode sig: %w", err)
	}
	if len(sigBytes) != 65 {
		return fmt.Errorf("ecdsa sig must be 65 bytes, got %d", len(sigBytes))
	}

	groupKey, err := decodeHex(groupPubKeyHex)
	if err != nil {
		return fmt.Errorf("decode group key: %w", err)
	}

	msgHash, err := decodeHex(msgHashHex)
	if err != nil {
		return fmt.Errorf("decode msg hash: %w", err)
	}
	if len(msgHash) != 32 {
		return fmt.Errorf("msg hash must be 32 bytes, got %d", len(msgHash))
	}

	// Verify s is in the lower half (EIP-2).
	s := new(big.Int).SetBytes(sigBytes[32:64])
	halfN := new(big.Int).Rsh(secp256k1N, 1)
	if s.Cmp(halfN) > 0 {
		return fmt.Errorf("ECDSA s not normalized (EIP-2): s > N/2")
	}

	// ecrecover and compare.
	recovered, err := crypto.Ecrecover(msgHash, sigBytes)
	if err != nil {
		return fmt.Errorf("ecrecover: %w", err)
	}

	pubKey, err := crypto.DecompressPubkey(groupKey)
	if err != nil {
		return fmt.Errorf("decompress group key: %w", err)
	}
	expected := crypto.FromECDSAPub(pubKey)

	if !equal(recovered, expected) {
		recoveredAddr := common.BytesToAddress(crypto.Keccak256(recovered[1:])[12:])
		expectedAddr := crypto.PubkeyToAddress(*pubKey)
		return fmt.Errorf("ecrecover mismatch: got %s, want %s", recoveredAddr.Hex(), expectedAddr.Hex())
	}
	return nil
}

func equal(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// IsValidCompressedPubkey returns true if s is a valid 33-byte compressed secp256k1 point.
func IsValidCompressedPubkey(s string) bool {
	b, err := decodeHex(s)
	if err != nil || len(b) != 33 {
		return false
	}
	_, err = crypto.DecompressPubkey(b)
	return err == nil
}

func decodeHex(s string) ([]byte, error) {
	s = strings.TrimPrefix(s, "0x")
	return hex.DecodeString(s)
}
