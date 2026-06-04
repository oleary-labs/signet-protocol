//! Envelope-encrypted storage layer.
//!
//! Wraps a raw key-value storage backend with per-record envelope encryption.
//! Each record gets a fresh random DEK encrypted (wrapped) by the KEK via
//! the `KeyCustody` trait. Values are encrypted with XChaCha20-Poly1305.
//!
//! Record format (v1):
//!   version(1) | kek_version(1) | wrap_nonce(24) | wrapped_dek(48) |
//!   value_nonce(24) | value_ciphertext(variable, includes 16-byte tag)
//!
//! See docs/at-rest-encryption-spec.md for the full design.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::XChaCha20Poly1305;
use zeroize::Zeroizing;

use crate::custody::{CustodyError, Dek, KeyCustody, WrappedDek};

const RECORD_VERSION: u8 = 0x01;
const FIXED_OVERHEAD: usize = 1 + 1 + 24 + 48 + 24; // 98 bytes
const TAG_LEN: usize = 16;

/// Errors from the encrypted store.
#[derive(Debug)]
pub enum EncryptedStoreError {
    Custody(CustodyError),
    Aead,
    InvalidRecord(String),
    Storage(String),
}

impl std::fmt::Display for EncryptedStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EncryptedStoreError::Custody(e) => write!(f, "custody: {}", e),
            EncryptedStoreError::Aead => write!(f, "AEAD verification failed"),
            EncryptedStoreError::InvalidRecord(msg) => write!(f, "invalid record: {}", msg),
            EncryptedStoreError::Storage(msg) => write!(f, "storage: {}", msg),
        }
    }
}

impl std::error::Error for EncryptedStoreError {}

impl From<CustodyError> for EncryptedStoreError {
    fn from(e: CustodyError) -> Self {
        EncryptedStoreError::Custody(e)
    }
}

/// Build the common AAD prefix: version || kek_version || tree_name_len || tree_name || key_len || key
fn build_common_prefix(version: u8, kek_version: u8, tree: &str, key: &[u8]) -> Vec<u8> {
    let mut prefix = Vec::with_capacity(2 + 2 + tree.len() + 4 + key.len());
    prefix.push(version);
    prefix.push(kek_version);
    prefix.extend_from_slice(&(tree.len() as u16).to_be_bytes());
    prefix.extend_from_slice(tree.as_bytes());
    prefix.extend_from_slice(&(key.len() as u32).to_be_bytes());
    prefix.extend_from_slice(key);
    prefix
}

/// Encrypt a value into the envelope record format.
pub fn seal_record(
    custody: &dyn KeyCustody,
    tree: &str,
    key: &[u8],
    value: &[u8],
) -> Result<Vec<u8>, EncryptedStoreError> {
    // Generate a fresh DEK.
    let mut dek: Dek = Zeroizing::new([0u8; 32]);
    getrandom::getrandom(dek.as_mut()).expect("CSPRNG failure");

    let kek_version = custody.current_kek_version();

    // Build AAD for DEK wrapping.
    let common = build_common_prefix(RECORD_VERSION, kek_version, tree, key);
    let mut dek_aad = common.clone();
    dek_aad.extend_from_slice(b"dek/v1");

    // Wrap DEK.
    let wrapped = custody.wrap_dek(&dek, &dek_aad)?;

    // Build AAD for value encryption (includes wrap_nonce + wrapped_dek).
    let mut value_aad = common;
    value_aad.extend_from_slice(b"val/v1");
    value_aad.extend_from_slice(&wrapped.nonce);
    value_aad.extend_from_slice(&wrapped.ciphertext);

    // Encrypt value with DEK.
    let cipher = XChaCha20Poly1305::new(dek.as_ref().into());
    let mut value_nonce = [0u8; 24];
    getrandom::getrandom(&mut value_nonce).expect("CSPRNG failure");

    let value_ct = cipher
        .encrypt(
            value_nonce.as_ref().into(),
            chacha20poly1305::aead::Payload {
                msg: value,
                aad: &value_aad,
            },
        )
        .map_err(|_| EncryptedStoreError::Aead)?;

    // Serialize record.
    let mut record = Vec::with_capacity(FIXED_OVERHEAD + value_ct.len());
    record.push(RECORD_VERSION);
    record.push(wrapped.kek_version);
    record.extend_from_slice(&wrapped.nonce);
    record.extend_from_slice(&wrapped.ciphertext);
    record.extend_from_slice(&value_nonce);
    record.extend_from_slice(&value_ct);

    Ok(record)
}

/// Decrypt a value from the envelope record format.
pub fn open_record(
    custody: &dyn KeyCustody,
    tree: &str,
    key: &[u8],
    record: &[u8],
) -> Result<Zeroizing<Vec<u8>>, EncryptedStoreError> {
    if record.len() < FIXED_OVERHEAD + TAG_LEN {
        return Err(EncryptedStoreError::InvalidRecord(format!(
            "record too short: {} bytes (minimum {})",
            record.len(),
            FIXED_OVERHEAD + TAG_LEN
        )));
    }

    let version = record[0];
    if version != RECORD_VERSION {
        return Err(EncryptedStoreError::InvalidRecord(format!(
            "unsupported record version: 0x{:02x}",
            version
        )));
    }

    let kek_version = record[1];

    let mut wrap_nonce = [0u8; 24];
    wrap_nonce.copy_from_slice(&record[2..26]);

    let mut wrapped_ct = [0u8; 48];
    wrapped_ct.copy_from_slice(&record[26..74]);

    let mut value_nonce = [0u8; 24];
    value_nonce.copy_from_slice(&record[74..98]);

    let value_ct = &record[98..];

    // Build AAD for DEK unwrapping.
    let common = build_common_prefix(version, kek_version, tree, key);
    let mut dek_aad = common.clone();
    dek_aad.extend_from_slice(b"dek/v1");

    // Unwrap DEK.
    let wrapped = WrappedDek {
        kek_version,
        nonce: wrap_nonce,
        ciphertext: wrapped_ct,
    };
    let dek = custody.unwrap_dek(&wrapped, &dek_aad)?;

    // Build AAD for value decryption.
    let mut value_aad = common;
    value_aad.extend_from_slice(b"val/v1");
    value_aad.extend_from_slice(&wrap_nonce);
    value_aad.extend_from_slice(&wrapped_ct);

    // Decrypt value.
    let cipher = XChaCha20Poly1305::new(dek.as_ref().into());
    let plaintext = cipher
        .decrypt(
            value_nonce.as_ref().into(),
            chacha20poly1305::aead::Payload {
                msg: value_ct,
                aad: &value_aad,
            },
        )
        .map_err(|_| EncryptedStoreError::Aead)?;

    Ok(Zeroizing::new(plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::custody::LocalKeyCustody;

    fn test_custody() -> LocalKeyCustody {
        LocalKeyCustody::new([0xAA; 32])
    }

    #[test]
    fn test_seal_open_roundtrip() {
        let custody = test_custody();
        let value = b"secret key material here";

        let record = seal_record(&custody, "keys/group1", b"\x01mykey", value).unwrap();
        let recovered = open_record(&custody, "keys/group1", b"\x01mykey", &record).unwrap();

        assert_eq!(recovered.as_slice(), value);
    }

    #[test]
    fn test_empty_value() {
        let custody = test_custody();
        let record = seal_record(&custody, "tree", b"key", b"").unwrap();
        let recovered = open_record(&custody, "tree", b"key", &record).unwrap();
        assert!(recovered.is_empty());
    }

    #[test]
    fn test_different_ciphertexts() {
        let custody = test_custody();
        let value = b"same value";
        let r1 = seal_record(&custody, "t", b"k", value).unwrap();
        let r2 = seal_record(&custody, "t", b"k", value).unwrap();
        // Different DEK + nonce each time.
        assert_ne!(r1, r2);
        // Both decrypt to same value.
        assert_eq!(
            open_record(&custody, "t", b"k", &r1).unwrap().as_slice(),
            open_record(&custody, "t", b"k", &r2).unwrap().as_slice(),
        );
    }

    #[test]
    fn test_tamper_value_ciphertext() {
        let custody = test_custody();
        let mut record = seal_record(&custody, "t", b"k", b"secret").unwrap();
        let last = record.len() - 1;
        record[last] ^= 0xFF;
        assert!(open_record(&custody, "t", b"k", &record).is_err());
    }

    #[test]
    fn test_tamper_wrapped_dek() {
        let custody = test_custody();
        let mut record = seal_record(&custody, "t", b"k", b"secret").unwrap();
        record[30] ^= 0xFF; // inside wrapped_dek
        assert!(open_record(&custody, "t", b"k", &record).is_err());
    }

    #[test]
    fn test_tamper_wrap_nonce() {
        let custody = test_custody();
        let mut record = seal_record(&custody, "t", b"k", b"secret").unwrap();
        record[5] ^= 0xFF; // inside wrap_nonce
        assert!(open_record(&custody, "t", b"k", &record).is_err());
    }

    #[test]
    fn test_tamper_value_nonce() {
        let custody = test_custody();
        let mut record = seal_record(&custody, "t", b"k", b"secret").unwrap();
        record[80] ^= 0xFF; // inside value_nonce
        assert!(open_record(&custody, "t", b"k", &record).is_err());
    }

    #[test]
    fn test_tamper_version() {
        let custody = test_custody();
        let mut record = seal_record(&custody, "t", b"k", b"secret").unwrap();
        record[0] = 0x02;
        assert!(open_record(&custody, "t", b"k", &record).is_err());
    }

    #[test]
    fn test_truncated_record() {
        let custody = test_custody();
        let record = seal_record(&custody, "t", b"k", b"secret").unwrap();
        assert!(open_record(&custody, "t", b"k", &record[..50]).is_err());
    }

    #[test]
    fn test_anti_swap_same_tree() {
        let custody = test_custody();
        let r_a = seal_record(&custody, "t", b"key-a", b"value-a").unwrap();
        let r_b = seal_record(&custody, "t", b"key-b", b"value-b").unwrap();

        // Swap: try to open record A with key B's address.
        assert!(open_record(&custody, "t", b"key-b", &r_a).is_err());
        assert!(open_record(&custody, "t", b"key-a", &r_b).is_err());
    }

    #[test]
    fn test_anti_swap_cross_tree() {
        let custody = test_custody();
        let record = seal_record(&custody, "tree-x", b"k", b"value").unwrap();
        // Same key, different tree.
        assert!(open_record(&custody, "tree-y", b"k", &record).is_err());
    }

    #[test]
    fn test_kek_rotation() {
        use std::collections::BTreeMap;

        // Create record with KEK v1.
        let custody_v1 = LocalKeyCustody::new([0xAA; 32]);
        let record = seal_record(&custody_v1, "t", b"k", b"secret").unwrap();

        // Upgrade to KEK v2 (keeps v1 for reading old records).
        let mut keks = BTreeMap::new();
        keks.insert(1, [0xAA; 32]);
        keks.insert(2, [0xBB; 32]);
        let custody_v2 = LocalKeyCustody::with_versions(keks, 2).unwrap();

        // Old record still decrypts.
        let recovered = open_record(&custody_v2, "t", b"k", &record).unwrap();
        assert_eq!(recovered.as_slice(), b"secret");

        // New records use v2.
        let new_record = seal_record(&custody_v2, "t", b"k2", b"new-secret").unwrap();
        assert_eq!(new_record[1], 2); // kek_version byte
    }

    #[test]
    fn test_unknown_kek_version() {
        let custody = test_custody();
        let mut record = seal_record(&custody, "t", b"k", b"secret").unwrap();
        record[1] = 0xFF; // unknown kek_version
        let result = open_record(&custody, "t", b"k", &record);
        assert!(matches!(
            result,
            Err(EncryptedStoreError::Custody(CustodyError::UnknownKekVersion(0xFF)))
        ));
    }
}
