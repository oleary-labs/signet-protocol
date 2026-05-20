package tss

import "fmt"

// Signature is the output of a threshold FROST signing session.
// R and Z are variable length to support multiple curves:
//   - secp256k1: R=33 bytes (compressed point), Z=32 bytes
//   - Ed25519:   R=32 bytes, Z=32 bytes (standard Ed25519 R||s)
type Signature struct {
	R []byte
	Z []byte
}

// Bytes returns the concatenated R||Z signature.
func (sig *Signature) Bytes() []byte {
	out := make([]byte, len(sig.R)+len(sig.Z))
	copy(out, sig.R)
	copy(out[len(sig.R):], sig.Z)
	return out
}

// SigEthereum returns a 65-byte signature encoding: R.x(32) || z(32) || v(1).
// v is the recovery bit (R.y parity: 0=even, 1=odd).
// This format is used by the on-chain FROSTVerifier for secp256k1 signatures.
// Returns an error if the signature is not secp256k1 (R must be 33 bytes).
func (sig *Signature) SigEthereum() ([]byte, error) {
	if len(sig.R) != 33 {
		return nil, fmt.Errorf("SigEthereum requires secp256k1 signature (R=33 bytes), got R=%d bytes", len(sig.R))
	}

	// R[0] is 0x02 (even y) or 0x03 (odd y).
	v := byte(0)
	if sig.R[0] == 0x03 {
		v = 1
	}

	out := make([]byte, 65)
	copy(out[:32], sig.R[1:]) // R.x (32 bytes, skip the prefix byte)
	copy(out[32:64], sig.Z[:])
	out[64] = v
	return out, nil
}
