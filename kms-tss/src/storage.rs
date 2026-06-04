//! sled-based key storage for FROST key material.
//!
//! Data is organized into three tree families per group:
//!   - `keys/<group_id>`    — active key shards (hot path: sign, keygen)
//!   - `pending/<group_id>` — in-flight reshare results (at most one per key)
//!   - `archive/<group_id>` — previous generations (for rollback)
//!
//! Within each tree, the sled key is `<curve_prefix_byte><key_id>`. This ensures
//! the same key_id with different curves maps to distinct storage entries.
//!
//! Sled transactions span multiple trees for atomic commit/rollback operations.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use sled::Transactional;

use crate::custody::KeyCustody;
use crate::curve::Curve;
use crate::encrypted_store;

/// Key status — controls whether the key can be used for signing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyStatus {
    Active,
    Disabled,
}

impl Default for KeyStatus {
    fn default() -> Self {
        KeyStatus::Active
    }
}

/// Persistent key material for a single key shard.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredKey {
    /// FROST KeyPackage serialized bytes (curve-specific).
    pub key_package: Vec<u8>,
    /// FROST PublicKeyPackage serialized bytes (curve-specific).
    pub public_key_package: Vec<u8>,
    /// Compressed group public key (33 bytes secp256k1, 32 bytes Ed25519).
    pub group_key: Vec<u8>,
    /// This node's compressed public key share.
    pub verifying_share: Vec<u8>,
    /// Key generation counter (0 for initial keygen, incremented on reshare).
    pub generation: u64,
    /// Optional signing scope constraint. Format: [1-byte scheme][scheme-specific].
    /// Empty = unscoped (signs any hash). Set at keygen time, immutable.
    #[serde(default)]
    pub scope: Vec<u8>,
    /// Key status. Disabled keys reject sign requests but remain visible.
    /// Defaults to Active for backwards compatibility with existing stored keys.
    #[serde(default)]
    pub status: KeyStatus,
}

/// sled-backed key storage with separate trees for active, pending, and archive.
/// Optionally encrypts values at rest via envelope encryption.
pub struct Storage {
    db: sled::Db,
    custody: Option<Arc<dyn KeyCustody>>,
}

/// Build the sled key: `<curve_prefix_byte><key_id_bytes>`.
fn storage_key(curve: &Curve, key_id: &str) -> Vec<u8> {
    let mut k = Vec::with_capacity(1 + key_id.len());
    k.push(curve.storage_prefix());
    k.extend_from_slice(key_id.as_bytes());
    k
}

impl Storage {
    /// Open (or create) a sled database at the given path. No encryption.
    pub fn new(path: &str) -> Result<Self, String> {
        let db = sled::open(path).map_err(|e| format!("open sled db: {e}"))?;
        Ok(Storage { db, custody: None })
    }

    /// Open (or create) a sled database with at-rest encryption.
    pub fn new_encrypted(path: &str, custody: Arc<dyn KeyCustody>) -> Result<Self, String> {
        let db = sled::open(path).map_err(|e| format!("open sled db: {e}"))?;
        Ok(Storage {
            db,
            custody: Some(custody),
        })
    }

    /// Flush all pending writes to disk.
    pub fn flush(&self) {
        let _ = self.db.flush();
    }

    /// Normalize a group_id to lowercase hex without "0x" prefix.
    fn normalize_group_id(group_id: &str) -> String {
        group_id
            .strip_prefix("0x")
            .or_else(|| group_id.strip_prefix("0X"))
            .unwrap_or(group_id)
            .to_ascii_lowercase()
    }

    fn active_tree_name(group_id: &str) -> String {
        format!("keys/{}", Self::normalize_group_id(group_id))
    }

    fn pending_tree_name(group_id: &str) -> String {
        format!("pending/{}", Self::normalize_group_id(group_id))
    }

    fn archive_tree_name(group_id: &str) -> String {
        format!("archive/{}", Self::normalize_group_id(group_id))
    }

    // -------------------------------------------------------------------------
    // Active key operations (hot path)
    // -------------------------------------------------------------------------

    /// Store an active key under (group_id, curve, key_id). Flushes immediately.
    pub fn put_key(&self, group_id: &str, key_id: &str, curve: &Curve, key: &StoredKey) -> Result<(), String> {
        let tree_name = Self::active_tree_name(group_id);
        let tree = self.db.open_tree(&tree_name).map_err(|e| format!("open tree: {e}"))?;
        let sk = storage_key(curve, key_id);
        let data = self.seal_value(&tree_name, &sk, key)?;
        tree.insert(sk, data).map_err(|e| format!("insert key: {e}"))?;
        tree.flush().map_err(|e| format!("flush: {e}"))?;
        Ok(())
    }

    /// Retrieve an active key by (group_id, curve, key_id). Returns None if not found.
    pub fn get_key(&self, group_id: &str, key_id: &str, curve: &Curve) -> Result<Option<StoredKey>, String> {
        let tree_name = Self::active_tree_name(group_id);
        let tree = self.db.open_tree(&tree_name).map_err(|e| format!("open tree: {e}"))?;
        self.get_from_tree(&tree_name, &tree, &storage_key(curve, key_id))
    }

    /// List all active keys for a group, returning (key_id, curve) pairs.
    pub fn list_keys(&self, group_id: &str) -> Result<Vec<(String, Curve)>, String> {
        let tree = self
            .db
            .open_tree(Self::active_tree_name(group_id))
            .map_err(|e| format!("open tree: {e}"))?;
        let mut entries = Vec::new();
        for entry in tree.iter() {
            let (key, _) = entry.map_err(|e| format!("iter: {e}"))?;
            if key.is_empty() { continue; }
            let prefix = key[0];
            let curve = match prefix {
                0x01 => Curve::Secp256k1,
                0x02 => Curve::Ed25519,
                0x03 => Curve::EcdsaSecp256k1,
                _ => continue, // skip unknown prefixes
            };
            let id = String::from_utf8(key[1..].to_vec()).map_err(|e| format!("key utf8: {e}"))?;
            entries.push((id, curve));
        }
        Ok(entries)
    }

    /// Update the status of an active key. Returns error if key not found.
    pub fn set_key_status(&self, group_id: &str, key_id: &str, curve: &Curve, status: KeyStatus) -> Result<(), String> {
        let tree_name = Self::active_tree_name(group_id);
        let tree = self.db.open_tree(&tree_name).map_err(|e| format!("open tree: {e}"))?;
        let sk = storage_key(curve, key_id);
        let mut key: StoredKey = self.get_from_tree(&tree_name, &tree, &sk)?
            .ok_or_else(|| format!("key not found: {group_id}/{key_id}"))?;
        key.status = status;
        let data = self.seal_value(&tree_name, &sk, &key)?;
        tree.insert(sk, data).map_err(|e| format!("update key: {e}"))?;
        tree.flush().map_err(|e| format!("flush: {e}"))?;
        Ok(())
    }

    /// Permanently delete an active key. Returns error if key not found.
    pub fn delete_key(&self, group_id: &str, key_id: &str, curve: &Curve) -> Result<(), String> {
        let tree = self
            .db
            .open_tree(Self::active_tree_name(group_id))
            .map_err(|e| format!("open tree: {e}"))?;
        let sk = storage_key(curve, key_id);
        let removed = tree.remove(&sk).map_err(|e| format!("remove key: {e}"))?;
        if removed.is_none() {
            return Err(format!("key not found: {group_id}/{key_id}"));
        }
        tree.flush().map_err(|e| format!("flush: {e}"))?;
        Ok(())
    }

    // -------------------------------------------------------------------------
    // Pending key operations (reshare in-flight)
    // -------------------------------------------------------------------------

    /// Store a pending reshare result.
    pub fn put_pending(&self, group_id: &str, key_id: &str, curve: &Curve, key: &StoredKey) -> Result<(), String> {
        let tree_name = Self::pending_tree_name(group_id);
        let tree = self.db.open_tree(&tree_name).map_err(|e| format!("open pending tree: {e}"))?;
        let sk = storage_key(curve, key_id);
        let data = self.seal_value(&tree_name, &sk, key)?;
        tree.insert(sk, data).map_err(|e| format!("insert pending: {e}"))?;
        Ok(())
    }

    /// Retrieve a pending reshare result.
    pub fn get_pending(&self, group_id: &str, key_id: &str, curve: &Curve) -> Result<Option<StoredKey>, String> {
        let tree_name = Self::pending_tree_name(group_id);
        let tree = self.db.open_tree(&tree_name).map_err(|e| format!("open pending tree: {e}"))?;
        self.get_from_tree(&tree_name, &tree, &storage_key(curve, key_id))
    }

    // -------------------------------------------------------------------------
    // Reshare lifecycle (atomic via sled transactions)
    // -------------------------------------------------------------------------

    /// Atomically promote a pending reshare result to active, archiving the
    /// previous active key. Returns the new generation number.
    pub fn commit_reshare(&self, group_id: &str, key_id: &str, curve: &Curve) -> Result<u64, String> {
        let active_tree_name = Self::active_tree_name(group_id);
        let pending_tree_name = Self::pending_tree_name(group_id);
        let archive_tree_name = Self::archive_tree_name(group_id);

        let active_tree = self.db.open_tree(&active_tree_name)
            .map_err(|e| format!("open active tree: {e}"))?;
        let pending_tree = self.db.open_tree(&pending_tree_name)
            .map_err(|e| format!("open pending tree: {e}"))?;
        let archive_tree = self.db.open_tree(&archive_tree_name)
            .map_err(|e| format!("open archive tree: {e}"))?;

        let sled_key = storage_key(curve, key_id);

        // Read and decrypt pending outside transaction.
        let pending_raw = pending_tree
            .get(&sled_key)
            .map_err(|e| format!("read pending: {e}"))?
            .ok_or_else(|| format!("no pending reshare for {group_id}/{key_id}"))?;
        let pending = self.open_value(&pending_tree_name, &sled_key, &pending_raw)?;
        let generation = pending.generation;

        // Re-encrypt for the active tree (different tree name = different AAD).
        let active_data = self.seal_value(&active_tree_name, &sled_key, &pending)?;

        // If there's a current active key, re-encrypt for the archive tree.
        let archive_entry = if let Some(current_raw) = active_tree
            .get(&sled_key)
            .map_err(|e| format!("read active: {e}"))?
        {
            let current = self.open_value(&active_tree_name, &sled_key, &current_raw)?;
            let ak = format!("gen{g}/{key_id}", g = current.generation);
            let archive_data = self.seal_value(&archive_tree_name, ak.as_bytes(), &current)?;
            Some((ak, archive_data))
        } else {
            None
        };

        // Atomic transaction across all three trees.
        (&active_tree, &pending_tree, &archive_tree)
            .transaction(|(active_tx, pending_tx, archive_tx)| {
                if let Some((ref ak, ref data)) = archive_entry {
                    archive_tx.insert(ak.as_bytes(), data.as_slice())?;
                }
                active_tx.insert(sled_key.as_slice(), active_data.as_slice())?;
                pending_tx.remove(sled_key.as_slice())?;
                Ok(())
            })
            .map_err(|e: sled::transaction::TransactionError<()>| {
                format!("commit transaction failed: {e:?}")
            })?;

        self.db.flush().map_err(|e| format!("flush: {e}"))?;

        Ok(generation)
    }

    /// Discard a pending reshare result without promoting.
    pub fn discard_pending_reshare(&self, group_id: &str, key_id: &str, curve: &Curve) -> Result<(), String> {
        let tree = self
            .db
            .open_tree(Self::pending_tree_name(group_id))
            .map_err(|e| format!("open pending tree: {e}"))?;
        tree.remove(storage_key(curve, key_id))
            .map_err(|e| format!("remove pending: {e}"))?;
        Ok(())
    }

    /// Rollback: restore a specific archived generation as the active key.
    pub fn rollback_reshare(
        &self,
        group_id: &str,
        key_id: &str,
        curve: &Curve,
        generation: u64,
    ) -> Result<(), String> {
        let active_tree = self
            .db
            .open_tree(Self::active_tree_name(group_id))
            .map_err(|e| format!("open active tree: {e}"))?;
        let archive_tree = self
            .db
            .open_tree(Self::archive_tree_name(group_id))
            .map_err(|e| format!("open archive tree: {e}"))?;
        let pending_tree = self
            .db
            .open_tree(Self::pending_tree_name(group_id))
            .map_err(|e| format!("open pending tree: {e}"))?;

        let archive_key_name = format!("gen{g}/{key_id}", g = generation);
        let sled_key = storage_key(curve, key_id);

        let archived_data = archive_tree
            .get(archive_key_name.as_bytes())
            .map_err(|e| format!("read archive: {e}"))?
            .ok_or_else(|| {
                format!("no archived key at generation {generation} for {group_id}/{key_id}")
            })?;

        // Atomic: replace active + remove any pending.
        (&active_tree, &pending_tree)
            .transaction(|(active_tx, pending_tx)| {
                active_tx.insert(sled_key.as_slice(), archived_data.clone())?;
                pending_tx.remove(sled_key.as_slice())?;
                Ok(())
            })
            .map_err(|e: sled::transaction::TransactionError<()>| {
                format!("rollback transaction failed: {e:?}")
            })?;

        self.db.flush().map_err(|e| format!("flush: {e}"))?;
        Ok(())
    }

    /// Migrate all keys from one group to another. Moves key data from the
    /// old group's active tree to the new group's active tree, then drops
    /// the old tree.
    pub fn migrate_group(&self, old_group_id: &str, new_group_id: &str) -> Result<usize, String> {
        let old_tree = self
            .db
            .open_tree(Self::active_tree_name(old_group_id))
            .map_err(|e| format!("open old tree: {e}"))?;
        let new_tree = self
            .db
            .open_tree(Self::active_tree_name(new_group_id))
            .map_err(|e| format!("open new tree: {e}"))?;

        let mut count = 0;
        for entry in old_tree.iter() {
            let (key, value) = entry.map_err(|e| format!("iter: {e}"))?;
            new_tree
                .insert(key, value)
                .map_err(|e| format!("insert: {e}"))?;
            count += 1;
        }
        self.db.flush().map_err(|e| format!("flush: {e}"))?;

        // Drop the old tree.
        self.db
            .drop_tree(Self::active_tree_name(old_group_id).as_bytes())
            .map_err(|e| format!("drop old tree: {e}"))?;

        Ok(count)
    }

    /// Drop all pending keys for a group.
    pub fn drop_pending(&self, group_id: &str) -> Result<(), String> {
        let name = Self::pending_tree_name(group_id);
        self.db
            .drop_tree(name.as_bytes())
            .map_err(|e| format!("drop pending tree: {e}"))?;
        Ok(())
    }

    /// Drop all archived keys for a group.
    pub fn drop_archive(&self, group_id: &str) -> Result<(), String> {
        let name = Self::archive_tree_name(group_id);
        self.db
            .drop_tree(name.as_bytes())
            .map_err(|e| format!("drop archive tree: {e}"))?;
        Ok(())
    }

    // -------------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------------

    /// Serialize and optionally encrypt a StoredKey value for writing to sled.
    fn seal_value(&self, tree_name: &str, sled_key: &[u8], key: &StoredKey) -> Result<Vec<u8>, String> {
        let plaintext = serde_json::to_vec(key).map_err(|e| format!("serialize key: {e}"))?;
        match &self.custody {
            Some(custody) => encrypted_store::seal_record(
                custody.as_ref(),
                tree_name,
                sled_key,
                &plaintext,
            )
            .map_err(|e| format!("encrypt: {e}")),
            None => Ok(plaintext),
        }
    }

    /// Read and optionally decrypt a StoredKey value from sled.
    fn open_value(&self, tree_name: &str, sled_key: &[u8], data: &[u8]) -> Result<StoredKey, String> {
        let plaintext = match &self.custody {
            Some(custody) => {
                let pt = encrypted_store::open_record(
                    custody.as_ref(),
                    tree_name,
                    sled_key,
                    data,
                )
                .map_err(|e| format!("decrypt: {e}"))?;
                pt.to_vec()
            }
            None => data.to_vec(),
        };
        serde_json::from_slice(&plaintext).map_err(|e| format!("deserialize key: {e}"))
    }

    fn get_from_tree(&self, tree_name: &str, tree: &sled::Tree, sled_key: &[u8]) -> Result<Option<StoredKey>, String> {
        match tree.get(sled_key) {
            Ok(Some(data)) => {
                let key = self.open_value(tree_name, sled_key, &data)?;
                Ok(Some(key))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(format!("get key: {e}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_put_get_list() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new(dir.path().to_str().unwrap()).unwrap();

        let key = StoredKey {
            key_package: vec![1, 2, 3],
            public_key_package: vec![4, 5, 6],
            group_key: vec![0x02; 33],
            verifying_share: vec![0x03; 33],
            generation: 0,
                scope: vec![],
                status: KeyStatus::Active,
        };

        storage.put_key("group-1", "key-a", &Curve::Secp256k1, &key).unwrap();
        storage.put_key("group-1", "key-b", &Curve::Secp256k1, &key).unwrap();

        let loaded = storage.get_key("group-1", "key-a", &Curve::Secp256k1).unwrap().unwrap();
        assert_eq!(loaded.key_package, vec![1, 2, 3]);
        assert_eq!(loaded.generation, 0);

        assert!(storage.get_key("group-1", "key-missing", &Curve::Secp256k1).unwrap().is_none());

        // Same key_id with different curve should not be found.
        assert!(storage.get_key("group-1", "key-a", &Curve::Ed25519).unwrap().is_none());

        let ids = storage.list_keys("group-1").unwrap();
        assert_eq!(ids, vec![
            ("key-a".to_string(), Curve::Secp256k1),
            ("key-b".to_string(), Curve::Secp256k1),
        ]);

        let empty = storage.list_keys("group-missing").unwrap();
        assert!(empty.is_empty());
    }

    #[test]
    fn test_same_keyid_different_curves() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new(dir.path().to_str().unwrap()).unwrap();

        let secp_key = StoredKey {
            key_package: vec![1],
            public_key_package: vec![2],
            group_key: vec![0x02; 33],
            verifying_share: vec![0x03; 33],
            generation: 0,
                scope: vec![],
                status: KeyStatus::Active,
        };
        let ed_key = StoredKey {
            key_package: vec![10],
            public_key_package: vec![20],
            group_key: vec![0x04; 32],
            verifying_share: vec![0x05; 32],
            generation: 0,
                scope: vec![],
                status: KeyStatus::Active,
        };

        storage.put_key("group-1", "k1", &Curve::Secp256k1, &secp_key).unwrap();
        storage.put_key("group-1", "k1", &Curve::Ed25519, &ed_key).unwrap();

        let loaded_secp = storage.get_key("group-1", "k1", &Curve::Secp256k1).unwrap().unwrap();
        assert_eq!(loaded_secp.key_package, vec![1]);

        let loaded_ed = storage.get_key("group-1", "k1", &Curve::Ed25519).unwrap().unwrap();
        assert_eq!(loaded_ed.key_package, vec![10]);
    }

    #[test]
    fn test_pending_lifecycle() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new(dir.path().to_str().unwrap()).unwrap();
        let c = Curve::Secp256k1;

        let key_gen0 = StoredKey {
            key_package: vec![1],
            public_key_package: vec![2],
            group_key: vec![0x02; 33],
            verifying_share: vec![0x03; 33],
            generation: 0,
                scope: vec![],
                status: KeyStatus::Active,
        };
        storage.put_key("group-1", "k1", &c, &key_gen0).unwrap();

        let key_gen1 = StoredKey {
            key_package: vec![10],
            public_key_package: vec![20],
            group_key: vec![0x02; 33],
            verifying_share: vec![0x04; 33],
            generation: 1,
                scope: vec![],
                status: KeyStatus::Active,
        };
        storage.put_pending("group-1", "k1", &c, &key_gen1).unwrap();

        assert_eq!(storage.get_key("group-1", "k1", &c).unwrap().unwrap().generation, 0);

        let new_gen = storage.commit_reshare("group-1", "k1", &c).unwrap();
        assert_eq!(new_gen, 1);

        let active = storage.get_key("group-1", "k1", &c).unwrap().unwrap();
        assert_eq!(active.generation, 1);
        assert_eq!(active.key_package, vec![10]);

        assert!(storage.get_pending("group-1", "k1", &c).unwrap().is_none());
    }

    #[test]
    fn test_rollback() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new(dir.path().to_str().unwrap()).unwrap();
        let c = Curve::Secp256k1;

        let key_gen0 = StoredKey {
            key_package: vec![1],
            public_key_package: vec![2],
            group_key: vec![0x02; 33],
            verifying_share: vec![0x03; 33],
            generation: 0,
                scope: vec![],
                status: KeyStatus::Active,
        };
        storage.put_key("group-1", "k1", &c, &key_gen0).unwrap();

        let key_gen1 = StoredKey {
            key_package: vec![10],
            public_key_package: vec![20],
            group_key: vec![0x02; 33],
            verifying_share: vec![0x04; 33],
            generation: 1,
                scope: vec![],
                status: KeyStatus::Active,
        };
        storage.put_pending("group-1", "k1", &c, &key_gen1).unwrap();
        storage.commit_reshare("group-1", "k1", &c).unwrap();

        storage.rollback_reshare("group-1", "k1", &c, 0).unwrap();
        let active = storage.get_key("group-1", "k1", &c).unwrap().unwrap();
        assert_eq!(active.generation, 0);
        assert_eq!(active.key_package, vec![1]);
    }

    #[test]
    fn test_discard_pending() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new(dir.path().to_str().unwrap()).unwrap();
        let c = Curve::Secp256k1;

        let key = StoredKey {
            key_package: vec![99],
            public_key_package: vec![],
            group_key: vec![],
            verifying_share: vec![],
            generation: 1,
                scope: vec![],
                status: KeyStatus::Active,
        };
        storage.put_pending("group-1", "k1", &c, &key).unwrap();
        assert!(storage.get_pending("group-1", "k1", &c).unwrap().is_some());

        storage.discard_pending_reshare("group-1", "k1", &c).unwrap();
        assert!(storage.get_pending("group-1", "k1", &c).unwrap().is_none());
    }

    #[test]
    fn test_drop_archive() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new(dir.path().to_str().unwrap()).unwrap();
        let c = Curve::Secp256k1;

        let key = StoredKey {
            key_package: vec![1],
            public_key_package: vec![2],
            group_key: vec![0x02; 33],
            verifying_share: vec![0x03; 33],
            generation: 0,
                scope: vec![],
                status: KeyStatus::Active,
        };
        storage.put_key("group-1", "k1", &c, &key).unwrap();

        let key1 = StoredKey { generation: 1, ..key.clone() };
        storage.put_pending("group-1", "k1", &c, &key1).unwrap();
        storage.commit_reshare("group-1", "k1", &c).unwrap();

        storage.drop_archive("group-1").unwrap();

        assert_eq!(storage.get_key("group-1", "k1", &c).unwrap().unwrap().generation, 1);

        assert!(storage.rollback_reshare("group-1", "k1", &c, 0).is_err());
    }
}
