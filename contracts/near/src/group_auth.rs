use near_sdk::store::{LookupMap, UnorderedSet};
use near_sdk::{env, near};

use crate::events;
use crate::types::*;
use crate::{group_hash_map, group_hash_set, SignetContract, SignetContractExt};

#[near]
impl SignetContract {
    /// Add a trusted OAuth issuer to a group. Manager only.
    pub fn add_issuer(&mut self, group_id: GroupId, issuer: String, client_ids: Vec<String>) {
        let meta = self.group_meta.get(&group_id).expect("group not found");
        assert!(env::predecessor_account_id() == meta.manager, "not manager");

        let hash = Self::issuer_hash(&issuer);

        let mut issuer_hashes: UnorderedSet<[u8; 32]> = group_hash_set(&group_id, "ih");
        assert!(!issuer_hashes.contains(&hash), "issuer already exists");

        let mut issuers: LookupMap<[u8; 32], OAuthIssuer> = group_hash_map(&group_id, "is");
        issuers.insert(hash, OAuthIssuer {
            issuer: issuer.clone(),
            client_ids,
        });
        issuer_hashes.insert(hash);

        self.bump_group_version(&group_id);
        events::issuer_added(&group_id, &hash, &issuer);
    }

    /// Remove a trusted OAuth issuer from a group. Manager only.
    pub fn remove_issuer(&mut self, group_id: GroupId, issuer_hash: Vec<u8>) {
        let meta = self.group_meta.get(&group_id).expect("group not found");
        assert!(env::predecessor_account_id() == meta.manager, "not manager");

        let hash: [u8; 32] = issuer_hash.try_into().expect("issuer_hash must be 32 bytes");

        let mut issuer_hashes: UnorderedSet<[u8; 32]> = group_hash_set(&group_id, "ih");
        assert!(issuer_hashes.contains(&hash), "issuer not found");

        let mut issuers: LookupMap<[u8; 32], OAuthIssuer> = group_hash_map(&group_id, "is");
        let issuer = issuers.get(&hash).expect("issuer data missing").clone();
        issuers.remove(&hash);
        issuer_hashes.remove(&hash);

        self.bump_group_version(&group_id);
        events::issuer_removed(&group_id, &hash, &issuer.issuer);
    }

    /// Add a trusted authorization key to a group. Manager only.
    #[payable]
    pub fn add_auth_key(&mut self, group_id: GroupId, pubkey: Vec<u8>) {
        let meta = self.group_meta.get(&group_id).expect("group not found");
        assert!(env::predecessor_account_id() == meta.manager, "not manager");

        let hash = Self::key_hash(&pubkey);

        let mut auth_key_hashes: UnorderedSet<[u8; 32]> = group_hash_set(&group_id, "akh");
        assert!(!auth_key_hashes.contains(&hash), "auth key already exists");

        let mut auth_keys: LookupMap<[u8; 32], Vec<u8>> = group_hash_map(&group_id, "ak");
        auth_keys.insert(hash, pubkey);
        auth_key_hashes.insert(hash);

        self.bump_group_version(&group_id);
        events::auth_key_added(&group_id, &hash);
    }

    /// Remove a trusted authorization key from a group. Manager only.
    pub fn remove_auth_key(&mut self, group_id: GroupId, key_hash: Vec<u8>) {
        let meta = self.group_meta.get(&group_id).expect("group not found");
        assert!(env::predecessor_account_id() == meta.manager, "not manager");

        let hash: [u8; 32] = key_hash.try_into().expect("key_hash must be 32 bytes");

        let mut auth_key_hashes: UnorderedSet<[u8; 32]> = group_hash_set(&group_id, "akh");
        assert!(auth_key_hashes.contains(&hash), "auth key not found");

        let mut auth_keys: LookupMap<[u8; 32], Vec<u8>> = group_hash_map(&group_id, "ak");
        auth_keys.remove(&hash);
        auth_key_hashes.remove(&hash);

        self.bump_group_version(&group_id);
        events::auth_key_removed(&group_id, &hash);
    }
}
