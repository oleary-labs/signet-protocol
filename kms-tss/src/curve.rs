//! Signing scheme identifier shared across KMS modules.
//!
//! `Curve` identifies the signing scheme (not just the curve) for keygen,
//! sign, and storage. `Secp256k1` and `Ed25519` use FROST Schnorr.
//! `EcdsaSecp256k1` uses threshold ECDSA (DJNPO20) over secp256k1,
//! producing standard ECDSA signatures compatible with EVM ecrecover.

use serde::{Deserialize, Serialize};

/// Supported signing schemes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Curve {
    /// FROST Schnorr over secp256k1.
    Secp256k1,
    /// FROST Schnorr over Ed25519.
    Ed25519,
    /// Threshold ECDSA over secp256k1 (DJNPO20 robust protocol).
    /// Produces standard ECDSA signatures (r, s) compatible with ecrecover.
    /// Uses the same DKG/reshare as Secp256k1 (FROST keygen), but a different
    /// 4-round signing protocol. See ecdsa_session.rs for references.
    EcdsaSecp256k1,
}

impl Curve {
    /// Wire name used in CBOR params and API requests.
    pub fn as_str(&self) -> &'static str {
        match self {
            Curve::Secp256k1 => "secp256k1",
            Curve::Ed25519 => "ed25519",
            Curve::EcdsaSecp256k1 => "ecdsa_secp256k1",
        }
    }

    /// Single-byte prefix for storage keys. Ensures same key_id with
    /// different schemes maps to different storage entries.
    pub fn storage_prefix(&self) -> u8 {
        match self {
            Curve::Secp256k1 => 0x01,
            Curve::Ed25519 => 0x02,
            Curve::EcdsaSecp256k1 => 0x03,
        }
    }

    /// Whether this scheme uses secp256k1 keygen (FROST DKG).
    /// Both Secp256k1 (FROST Schnorr) and EcdsaSecp256k1 share the same
    /// keygen — only the signing protocol differs.
    pub fn uses_secp256k1_keygen(&self) -> bool {
        matches!(self, Curve::Secp256k1 | Curve::EcdsaSecp256k1)
    }
}

impl Curve {
    /// Map a frost_core Ciphersuite type to its Curve value.
    /// Used in generic code where C is known at compile time.
    pub fn from_ciphersuite<C: frost_core::Ciphersuite>() -> Self {
        // Compare group key serialization size: 33 = secp256k1, 32 = ed25519.
        // This is a compile-time-resolvable dispatch since the Serialization
        // type is fixed per Ciphersuite.
        let id = C::ID;
        if id.starts_with("FROST-secp256k1") {
            Curve::Secp256k1
        } else if id.starts_with("FROST-Ed25519") || id.starts_with("FROST-ED25519") {
            Curve::Ed25519
        } else {
            panic!("unknown ciphersuite ID: {id}");
        }
    }
}

impl std::fmt::Display for Curve {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}
