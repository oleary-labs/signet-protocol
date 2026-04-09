//! sled-based key storage for FROST KeyPackage and PublicKeyPackage.

use serde::{Deserialize, Serialize};

/// Persistent key material for a single key shard.
#[derive(Debug, Serialize, Deserialize)]
pub struct StoredKey {
    /// frost-secp256k1 KeyPackage serialized bytes.
    pub key_package: Vec<u8>,
    /// frost-secp256k1 PublicKeyPackage serialized bytes.
    pub public_key_package: Vec<u8>,
    /// 33-byte compressed secp256k1 group public key.
    pub group_key: Vec<u8>,
    /// This node's compressed public key share.
    pub verifying_share: Vec<u8>,
    /// Key generation counter (0 for initial keygen, incremented on reshare).
    pub generation: u64,
}

/// sled-backed key storage.
pub struct Storage {
    db: sled::Db,
}

impl Storage {
    /// Open (or create) a sled database at the given path.
    pub fn new(path: &str) -> Result<Self, String> {
        let db = sled::open(path).map_err(|e| format!("open sled db: {e}"))?;
        Ok(Storage { db })
    }

    /// Normalize a group_id to lowercase hex without "0x" prefix.
    fn normalize_group_id(group_id: &str) -> String {
        group_id
            .strip_prefix("0x")
            .or_else(|| group_id.strip_prefix("0X"))
            .unwrap_or(group_id)
            .to_ascii_lowercase()
    }

    /// Tree name for a group's keys.
    fn tree_name(group_id: &str) -> String {
        let normalized = Self::normalize_group_id(group_id);
        format!("keys/{normalized}")
    }

    /// Store a key under (group_id, key_id).
    pub fn put_key(&self, group_id: &str, key_id: &str, key: &StoredKey) -> Result<(), String> {
        let tree = self
            .db
            .open_tree(Self::tree_name(group_id))
            .map_err(|e| format!("open tree: {e}"))?;
        let data = serde_json::to_vec(key).map_err(|e| format!("serialize key: {e}"))?;
        tree.insert(key_id.as_bytes(), data)
            .map_err(|e| format!("insert key: {e}"))?;
        tree.flush().map_err(|e| format!("flush: {e}"))?;
        Ok(())
    }

    /// Retrieve a key by (group_id, key_id). Returns None if not found.
    pub fn get_key(&self, group_id: &str, key_id: &str) -> Result<Option<StoredKey>, String> {
        let tree = self
            .db
            .open_tree(Self::tree_name(group_id))
            .map_err(|e| format!("open tree: {e}"))?;
        match tree.get(key_id.as_bytes()) {
            Ok(Some(data)) => {
                let key: StoredKey =
                    serde_json::from_slice(&data).map_err(|e| format!("deserialize key: {e}"))?;
                Ok(Some(key))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(format!("get key: {e}")),
        }
    }

    /// List all key IDs for a group.
    pub fn list_keys(&self, group_id: &str) -> Result<Vec<String>, String> {
        let tree = self
            .db
            .open_tree(Self::tree_name(group_id))
            .map_err(|e| format!("open tree: {e}"))?;
        let mut ids = Vec::new();
        for entry in tree.iter() {
            let (key, _) = entry.map_err(|e| format!("iter: {e}"))?;
            let id = String::from_utf8(key.to_vec()).map_err(|e| format!("key utf8: {e}"))?;
            ids.push(id);
        }
        Ok(ids)
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
        };

        storage.put_key("group-1", "key-a", &key).unwrap();
        storage.put_key("group-1", "key-b", &key).unwrap();

        let loaded = storage.get_key("group-1", "key-a").unwrap().unwrap();
        assert_eq!(loaded.key_package, vec![1, 2, 3]);
        assert_eq!(loaded.generation, 0);

        assert!(storage.get_key("group-1", "key-missing").unwrap().is_none());

        let ids = storage.list_keys("group-1").unwrap();
        assert_eq!(ids, vec!["key-a", "key-b"]);

        let empty = storage.list_keys("group-missing").unwrap();
        assert!(empty.is_empty());
    }
}
