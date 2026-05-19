package node

// Curve identifies a signing scheme for keygen, sign, and storage.
type Curve string

const (
	CurveSecp256k1      Curve = "secp256k1"
	CurveEd25519        Curve = "ed25519"
	CurveEcdsaSecp256k1 Curve = "ecdsa_secp256k1"
)

// Normalize resolves aliases to canonical curve names.
// Returns the canonical Curve and true, or ("", false) if unrecognized.
func (c Curve) Normalize() (Curve, bool) {
	switch c {
	case CurveSecp256k1, "frost_secp256k1":
		return CurveSecp256k1, true
	case CurveEd25519, "frost_ed25519":
		return CurveEd25519, true
	case CurveEcdsaSecp256k1:
		return CurveEcdsaSecp256k1, true
	default:
		return "", false
	}
}

// Valid returns true if c is a recognized curve (including aliases).
func (c Curve) Valid() bool {
	_, ok := c.Normalize()
	return ok
}

// String returns the wire name (used in CBOR params and API responses).
func (c Curve) String() string {
	return string(c)
}

// StoragePrefix returns the single-byte prefix used in KMS sled storage keys.
// Matches kms-tss/src/curve.rs Curve::storage_prefix().
func (c Curve) StoragePrefix() byte {
	switch c {
	case CurveSecp256k1:
		return 0x01
	case CurveEd25519:
		return 0x02
	case CurveEcdsaSecp256k1:
		return 0x03
	default:
		return 0x00
	}
}

// CurveFromStoragePrefix returns the Curve for a storage prefix byte.
func CurveFromStoragePrefix(b byte) (Curve, bool) {
	switch b {
	case 0x01:
		return CurveSecp256k1, true
	case 0x02:
		return CurveEd25519, true
	case 0x03:
		return CurveEcdsaSecp256k1, true
	default:
		return "", false
	}
}

// IsSecp256k1 returns true if this scheme uses secp256k1 keygen.
// Both Secp256k1 (FROST Schnorr) and EcdsaSecp256k1 share the same DKG.
func (c Curve) IsSecp256k1() bool {
	return c == CurveSecp256k1 || c == CurveEcdsaSecp256k1
}

// KeyEntry identifies a stored key by its ID and curve.
type KeyEntry struct {
	KeyID string
	Curve Curve
}
