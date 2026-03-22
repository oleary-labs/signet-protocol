package tss

// Signature is the output of a threshold FROST signing session.
type Signature struct {
	R [33]byte // compressed nonce point R (secp256k1)
	Z [32]byte // aggregate signature scalar z
}

// SigEthereum returns a 65-byte signature encoding: R.x(32) || z(32) || v(1).
// v is the recovery bit (R.y parity: 0=even, 1=odd).
// This format is used by the on-chain FROSTVerifier.
func (sig *Signature) SigEthereum() ([]byte, error) {
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
