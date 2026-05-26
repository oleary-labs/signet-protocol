use near_sdk::store::{LookupMap, UnorderedSet};
use near_sdk::{near, AccountId};

use crate::types::*;
use crate::{group_account_map, group_account_set, group_hash_map, group_hash_set, SignetContract, SignetContractExt};

#[near]
impl SignetContract {
    // --- Version counters (change detection) ---

    pub fn get_state_version(&self) -> u64 {
        self.state_version
    }

    pub fn get_group_version(&self, group_id: GroupId) -> u64 {
        self.group_meta
            .get(&group_id)
            .map(|m| m.version)
            .unwrap_or(0)
    }

    // --- Node registry views ---

    pub fn get_node(&self, node: AccountId) -> Option<NodeInfoView> {
        self.nodes.get(&node).map(|info| NodeInfoView {
            account_id: node,
            pubkey: info.pubkey.clone(),
            is_open: info.is_open,
            registered_at: info.registered_at,
            operator: info.operator.clone(),
        })
    }

    pub fn get_node_pubkey(&self, node: AccountId) -> Option<Vec<u8>> {
        self.nodes.get(&node).map(|info| info.pubkey.clone())
    }

    pub fn get_registered_nodes(&self) -> Vec<AccountId> {
        self.registered_nodes.iter().cloned().collect()
    }

    pub fn get_node_groups(&self, node: AccountId) -> Vec<GroupId> {
        self.node_groups
            .get(&node)
            .map(|set| set.iter().cloned().collect())
            .unwrap_or_default()
    }

    // --- Group views ---

    pub fn get_groups(&self) -> Vec<GroupId> {
        self.groups.iter().cloned().collect()
    }

    pub fn get_active_nodes(&self, group_id: GroupId) -> Vec<AccountId> {
        let active: UnorderedSet<AccountId> = group_account_set(&group_id, "an");
        active.iter().cloned().collect()
    }

    pub fn get_pending_nodes(&self, group_id: GroupId) -> Vec<AccountId> {
        let pending: UnorderedSet<AccountId> = group_account_set(&group_id, "pn");
        pending.iter().cloned().collect()
    }

    pub fn get_threshold(&self, group_id: GroupId) -> u32 {
        self.group_meta
            .get(&group_id)
            .map(|m| m.threshold)
            .unwrap_or(0)
    }

    pub fn get_manager(&self, group_id: GroupId) -> Option<AccountId> {
        self.group_meta.get(&group_id).map(|m| m.manager.clone())
    }

    pub fn is_operational(&self, group_id: GroupId) -> bool {
        let meta = match self.group_meta.get(&group_id) {
            Some(m) => m,
            None => return false,
        };
        let active: UnorderedSet<AccountId> = group_account_set(&group_id, "an");
        active.len() >= meta.threshold
    }

    pub fn get_removal_request(
        &self,
        group_id: GroupId,
        node: AccountId,
    ) -> Option<RemovalRequest> {
        let removal_requests: LookupMap<AccountId, RemovalRequest> =
            group_account_map(&group_id, "rr");
        removal_requests.get(&node).cloned()
    }

    // --- Auth views ---

    pub fn get_issuers(&self, group_id: GroupId) -> Vec<OAuthIssuerView> {
        let issuer_hashes: UnorderedSet<[u8; 32]> = group_hash_set(&group_id, "ih");
        let issuers: LookupMap<[u8; 32], OAuthIssuer> = group_hash_map(&group_id, "is");
        issuer_hashes
            .iter()
            .filter_map(|hash| {
                issuers.get(hash).map(|iss| OAuthIssuerView {
                    issuer_hash: hash.to_vec(),
                    issuer: iss.issuer.clone(),
                    client_ids: iss.client_ids.clone(),
                })
            })
            .collect()
    }

    pub fn get_auth_keys(&self, group_id: GroupId) -> Vec<Vec<u8>> {
        let auth_key_hashes: UnorderedSet<[u8; 32]> = group_hash_set(&group_id, "akh");
        let auth_keys: LookupMap<[u8; 32], Vec<u8>> = group_hash_map(&group_id, "ak");
        auth_key_hashes
            .iter()
            .filter_map(|hash| auth_keys.get(hash).cloned())
            .collect()
    }
}
