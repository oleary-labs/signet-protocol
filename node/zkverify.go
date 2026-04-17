package node

import (
	"encoding/binary"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
)

const (
	fieldElementSize = 32  // BN254 field element size in bytes
	numModulusLimbs  = 18  // RSA-2048 modulus split into 18 u128 limbs
	limbBits         = 120 // bits per limb (matches noir-jwt circuit)
	maxClaimLen      = 128 // MAX_ISS/SUB/AUD/AZP_LENGTH in the circuit
	sessionPubLen    = 33  // compressed secp256k1 public key

	// Total public input field elements:
	//   18 modulus limbs + 4×(128 storage + 1 len) + 1 exp + 33 session_pub = 568
	totalPIElements = numModulusLimbs + 4*(maxClaimLen+1) + 1 + sessionPubLen
)

// encodePublicInputs serializes AuthProof fields into the binary format
// expected by `bb verify -i <file>`: concatenated 32-byte big-endian BN254
// field elements matching the circuit's public input declaration order in
// circuits/jwt_auth/src/main.nr:
//
//	pubkey_modulus_limbs  [u128; 18]
//	expected_iss          BoundedVec<u8, 128>  (128 storage + 1 len)
//	expected_sub          BoundedVec<u8, 128>
//	expected_exp          u64
//	expected_aud          BoundedVec<u8, 128>
//	expected_azp          BoundedVec<u8, 128>
//	session_pub           [u8; 33]
func encodePublicInputs(proof *AuthProof) ([]byte, error) {
	if len(proof.JWKSModulus) == 0 {
		return nil, fmt.Errorf("JWKSModulus is empty")
	}
	if len(proof.SessionPub) != sessionPubLen {
		return nil, fmt.Errorf("session_pub must be %d bytes, got %d", sessionPubLen, len(proof.SessionPub))
	}

	buf := make([]byte, totalPIElements*fieldElementSize)
	off := 0

	// 1. pubkey_modulus_limbs: big-endian RSA modulus → 18 × 120-bit limbs (LE order).
	modulus := new(big.Int).SetBytes(proof.JWKSModulus)
	limbs := splitToLimbs(modulus, limbBits, numModulusLimbs)
	for _, limb := range limbs {
		writeFieldElement(buf[off:], limb.Bytes())
		off += fieldElementSize
	}

	// 2. expected_iss
	off = writeBoundedVecField(buf, off, []byte(proof.Iss))

	// 3. expected_sub
	off = writeBoundedVecField(buf, off, []byte(proof.Sub))

	// 4. expected_exp
	var expBuf [8]byte
	binary.BigEndian.PutUint64(expBuf[:], proof.Exp)
	writeFieldElement(buf[off:], expBuf[:])
	off += fieldElementSize

	// 5. expected_aud
	off = writeBoundedVecField(buf, off, []byte(proof.Aud))

	// 6. expected_azp
	off = writeBoundedVecField(buf, off, []byte(proof.Azp))

	// 7. session_pub: each byte → its own field element.
	for _, b := range proof.SessionPub {
		writeFieldElement(buf[off:], []byte{b})
		off += fieldElementSize
	}

	return buf, nil
}

// writeFieldElement writes val right-aligned into a 32-byte big-endian slot.
func writeFieldElement(dst, val []byte) {
	// dst is already zeroed from make; right-align the value.
	copy(dst[fieldElementSize-len(val):fieldElementSize], val)
}

// writeBoundedVecField encodes a BoundedVec<u8, 128> as 128 storage elements
// followed by 1 length element, each as a 32-byte field element. Returns the
// new byte offset.
func writeBoundedVecField(buf []byte, off int, data []byte) int {
	for i := 0; i < maxClaimLen; i++ {
		if i < len(data) {
			writeFieldElement(buf[off:], []byte{data[i]})
		}
		off += fieldElementSize
	}
	// Length element.
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(data)))
	writeFieldElement(buf[off:], lenBuf[:])
	off += fieldElementSize
	return off
}

// splitToLimbs splits n into numChunks limbs of chunkBits each, returned in
// little-endian order (limbs[0] is the least significant chunk). This matches
// noir-jwt's BigNumInstance limb layout.
func splitToLimbs(n *big.Int, chunkBits, numChunks int) []*big.Int {
	mask := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(chunkBits)), big.NewInt(1))
	limbs := make([]*big.Int, numChunks)
	tmp := new(big.Int).Set(n)
	for i := 0; i < numChunks; i++ {
		limbs[i] = new(big.Int).And(tmp, mask)
		tmp.Rsh(tmp, uint(chunkBits))
	}
	return limbs
}

// verifyBBProof reconstructs the full Honk proof blob (metadata + public inputs
// + proof) and shells out to `bb verify`. bb.js splits the proof and public
// inputs apart; the CLI expects the combined format:
//
//	[4-byte BE size in fields] [public inputs] [proof]
func verifyBBProof(proof, publicInputs, vk []byte) error {
	bbPath, err := findBB()
	if err != nil {
		return err
	}

	dir, err := os.MkdirTemp("", "bb-verify-*")
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(dir)

	// Reconstruct the full proof blob: 4-byte metadata + publicInputs + proof.
	totalFields := (len(publicInputs) + len(proof)) / fieldElementSize
	fullProof := make([]byte, 4+len(publicInputs)+len(proof))
	binary.BigEndian.PutUint32(fullProof[0:4], uint32(totalFields))
	copy(fullProof[4:4+len(publicInputs)], publicInputs)
	copy(fullProof[4+len(publicInputs):], proof)

	proofPath := filepath.Join(dir, "proof")
	vkPath := filepath.Join(dir, "vk")

	if err := os.WriteFile(proofPath, fullProof, 0600); err != nil {
		return fmt.Errorf("write proof: %w", err)
	}
	if err := os.WriteFile(vkPath, vk, 0600); err != nil {
		return fmt.Errorf("write vk: %w", err)
	}

	cmd := exec.Command(bbPath, "verify", "-k", vkPath, "-p", proofPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("bb verify: %w\noutput: %s", err, output)
	}
	return nil
}

// findBB locates the bb binary on PATH or in common install locations.
func findBB() (string, error) {
	if p, err := exec.LookPath("bb"); err == nil {
		return p, nil
	}
	// Check common install location (~/.bb/bb).
	if home, err := os.UserHomeDir(); err == nil {
		p := filepath.Join(home, ".bb", "bb")
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("bb binary not found (install from https://github.com/AztecProtocol/aztec-packages)")
}
