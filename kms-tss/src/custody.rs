//! Key custody: KEK management and DEK wrapping/unwrapping.
//!
//! The `KeyCustody` trait is the migration seam for TEE integration.
//! `LocalKeyCustody` holds KEK material in process memory (v1).
//! A future `EnclaveKeyCustody` would perform the same operations
//! inside a TEE via vsock.

use std::collections::BTreeMap;

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::XChaCha20Poly1305;
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

/// A 32-byte data encryption key, zeroed on drop.
pub type Dek = Zeroizing<[u8; 32]>;

/// A wrapped (encrypted) DEK with metadata.
#[derive(Clone)]
pub struct WrappedDek {
    pub kek_version: u8,
    pub nonce: [u8; 24],
    pub ciphertext: [u8; 48], // 32 (DEK) + 16 (Poly1305 tag)
}

/// Errors from custody operations.
#[derive(Debug)]
pub enum CustodyError {
    UnknownKekVersion(u8),
    Aead,
    NoKeysConfigured,
}

impl std::fmt::Display for CustodyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CustodyError::UnknownKekVersion(v) => write!(f, "unknown KEK version: {}", v),
            CustodyError::Aead => write!(f, "AEAD failure (decrypt/verify)"),
            CustodyError::NoKeysConfigured => write!(f, "no KEK configured"),
        }
    }
}

impl std::error::Error for CustodyError {}

/// Trait for KEK custody. Today: in-process. Tomorrow: TEE enclave.
pub trait KeyCustody: Send + Sync {
    /// The KEK version used for new wraps.
    fn current_kek_version(&self) -> u8;

    /// Wrap a freshly generated DEK with the current KEK.
    fn wrap_dek(&self, dek: &Dek, aad: &[u8]) -> Result<WrappedDek, CustodyError>;

    /// Unwrap a DEK previously wrapped by any known KEK version.
    fn unwrap_dek(&self, wrapped: &WrappedDek, aad: &[u8]) -> Result<Dek, CustodyError>;
}

/// In-process KEK custody. KEKs are held in memory, zeroed on drop.
pub struct LocalKeyCustody {
    keks: BTreeMap<u8, Zeroizing<[u8; 32]>>,
    current: u8,
}

impl LocalKeyCustody {
    /// Create custody from a single KEK (version 1).
    pub fn new(kek: [u8; 32]) -> Self {
        let mut keks = BTreeMap::new();
        keks.insert(1, Zeroizing::new(kek));
        LocalKeyCustody { keks, current: 1 }
    }

    /// Create custody from multiple KEK versions.
    pub fn with_versions(keks: BTreeMap<u8, [u8; 32]>, current: u8) -> Result<Self, CustodyError> {
        if !keks.contains_key(&current) {
            return Err(CustodyError::UnknownKekVersion(current));
        }
        let keks = keks
            .into_iter()
            .map(|(v, k)| (v, Zeroizing::new(k)))
            .collect();
        Ok(LocalKeyCustody { keks, current })
    }

    /// Derive the wrapping sub-key from a KEK via HKDF.
    fn derive_wrap_key(&self, kek_version: u8) -> Result<Zeroizing<[u8; 32]>, CustodyError> {
        let kek = self
            .keks
            .get(&kek_version)
            .ok_or(CustodyError::UnknownKekVersion(kek_version))?;

        let hk = Hkdf::<Sha256>::new(None, kek.as_ref());
        let mut okm = Zeroizing::new([0u8; 32]);
        hk.expand(b"at-rest/dek-kek/v1", okm.as_mut())
            .expect("32 bytes is a valid HKDF output length");
        Ok(okm)
    }
}

impl KeyCustody for LocalKeyCustody {
    fn current_kek_version(&self) -> u8 {
        self.current
    }

    fn wrap_dek(&self, dek: &Dek, aad: &[u8]) -> Result<WrappedDek, CustodyError> {
        let wrap_key = self.derive_wrap_key(self.current)?;
        let cipher = XChaCha20Poly1305::new(wrap_key.as_ref().into());

        let mut nonce = [0u8; 24];
        getrandom::getrandom(&mut nonce).expect("CSPRNG failure");

        let ct = cipher
            .encrypt(
                nonce.as_ref().into(),
                chacha20poly1305::aead::Payload {
                    msg: dek.as_ref(),
                    aad,
                },
            )
            .map_err(|_| CustodyError::Aead)?;

        let mut ciphertext = [0u8; 48];
        ciphertext.copy_from_slice(&ct);

        Ok(WrappedDek {
            kek_version: self.current,
            nonce,
            ciphertext,
        })
    }

    fn unwrap_dek(&self, wrapped: &WrappedDek, aad: &[u8]) -> Result<Dek, CustodyError> {
        let wrap_key = self.derive_wrap_key(wrapped.kek_version)?;
        let cipher = XChaCha20Poly1305::new(wrap_key.as_ref().into());

        let plaintext = cipher
            .decrypt(
                wrapped.nonce.as_ref().into(),
                chacha20poly1305::aead::Payload {
                    msg: &wrapped.ciphertext,
                    aad,
                },
            )
            .map_err(|_| CustodyError::Aead)?;

        let mut dek = Zeroizing::new([0u8; 32]);
        dek.copy_from_slice(&plaintext);
        Ok(dek)
    }
}

impl Drop for LocalKeyCustody {
    fn drop(&mut self) {
        for (_, kek) in self.keks.iter_mut() {
            kek.zeroize();
        }
    }
}

/// No-op custody that passes values through unencrypted.
/// Used when encryption is disabled (e.g., development/testing).
pub struct NullCustody;

impl KeyCustody for NullCustody {
    fn current_kek_version(&self) -> u8 {
        0
    }

    fn wrap_dek(&self, _dek: &Dek, _aad: &[u8]) -> Result<WrappedDek, CustodyError> {
        Err(CustodyError::NoKeysConfigured)
    }

    fn unwrap_dek(&self, _wrapped: &WrappedDek, _aad: &[u8]) -> Result<Dek, CustodyError> {
        Err(CustodyError::NoKeysConfigured)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_kek() -> [u8; 32] {
        [0xAA; 32]
    }

    #[test]
    fn test_wrap_unwrap_roundtrip() {
        let custody = LocalKeyCustody::new(test_kek());
        let mut dek = Zeroizing::new([0u8; 32]);
        getrandom::getrandom(dek.as_mut()).unwrap();

        let aad = b"test-tree\x00test-key";
        let wrapped = custody.wrap_dek(&dek, aad).unwrap();
        let recovered = custody.unwrap_dek(&wrapped, aad).unwrap();

        assert_eq!(dek.as_ref(), recovered.as_ref());
    }

    #[test]
    fn test_wrong_aad_fails() {
        let custody = LocalKeyCustody::new(test_kek());
        let mut dek = Zeroizing::new([0u8; 32]);
        getrandom::getrandom(dek.as_mut()).unwrap();

        let wrapped = custody.wrap_dek(&dek, b"correct-aad").unwrap();
        let result = custody.unwrap_dek(&wrapped, b"wrong-aad");

        assert!(result.is_err());
    }

    #[test]
    fn test_unknown_kek_version() {
        let custody = LocalKeyCustody::new(test_kek());
        let wrapped = WrappedDek {
            kek_version: 0xFF,
            nonce: [0; 24],
            ciphertext: [0; 48],
        };

        let result = custody.unwrap_dek(&wrapped, b"aad");
        assert!(matches!(result, Err(CustodyError::UnknownKekVersion(0xFF))));
    }

    #[test]
    fn test_kek_rotation() {
        let mut keks = BTreeMap::new();
        keks.insert(1, [0xAA; 32]);
        keks.insert(2, [0xBB; 32]);
        let custody = LocalKeyCustody::with_versions(keks, 2).unwrap();

        let mut dek = Zeroizing::new([0u8; 32]);
        getrandom::getrandom(dek.as_mut()).unwrap();
        let aad = b"test";

        // Wrap with v2 (current).
        let wrapped = custody.wrap_dek(&dek, aad).unwrap();
        assert_eq!(wrapped.kek_version, 2);

        // Unwrap with v2 works.
        let recovered = custody.unwrap_dek(&wrapped, aad).unwrap();
        assert_eq!(dek.as_ref(), recovered.as_ref());

        // Simulate a record wrapped with old v1 KEK.
        let old_custody = LocalKeyCustody::new([0xAA; 32]);
        let old_wrapped = old_custody.wrap_dek(&dek, aad).unwrap();

        // Current custody (knows both KEKs) can unwrap v1 records.
        let recovered_old = custody.unwrap_dek(&old_wrapped, aad).unwrap();
        assert_eq!(dek.as_ref(), recovered_old.as_ref());
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let custody = LocalKeyCustody::new(test_kek());
        let mut dek = Zeroizing::new([0u8; 32]);
        getrandom::getrandom(dek.as_mut()).unwrap();

        let mut wrapped = custody.wrap_dek(&dek, b"aad").unwrap();
        wrapped.ciphertext[0] ^= 0xFF; // flip a bit

        assert!(custody.unwrap_dek(&wrapped, b"aad").is_err());
    }
}
