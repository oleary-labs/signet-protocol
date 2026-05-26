use near_sdk::store::{LookupMap, UnorderedSet};
use near_sdk::{env, near, AccountId};
use sha2::{Digest, Sha256};

use crate::events;
use crate::types::*;
use crate::{
    group_account_map, group_account_set, group_hash_map, group_hash_set, SignetContract,
    SignetContractExt,
};

#[near]
impl SignetContract {
    /// Create a new signing group with the given nodes, threshold, and auth config.
    #[payable]
    pub fn create_group(
        &mut self,
        group_id: GroupId,
        node_accounts: Vec<AccountId>,
        threshold: u32,
        removal_delay_secs: u64,
        initial_issuers: Vec<InitialIssuer>,
        initial_auth_keys: Vec<Vec<u8>>,
    ) {
        let caller = env::predecessor_account_id();
        assert!(!self.groups.contains(&group_id), "group already exists");
        assert!(threshold >= 1, "threshold must be >= 1");
        assert!(
            threshold <= node_accounts.len() as u32,
            "threshold must be <= number of nodes"
        );
        assert!(
            removal_delay_secs >= self.min_removal_delay_secs,
            "removal delay must be >= min_removal_delay_secs ({})",
            self.min_removal_delay_secs
        );

        let meta = GroupMeta {
            manager: caller.clone(),
            threshold,
            removal_delay_secs,
            version: 1,
        };

        // Create per-group collections.
        let mut active_nodes: UnorderedSet<AccountId> = group_account_set(&group_id, "an");
        let mut pending_nodes: UnorderedSet<AccountId> = group_account_set(&group_id, "pn");
        let mut node_status: LookupMap<AccountId, NodeStatus> =
            group_account_map(&group_id, "ns");
        let mut issuer_hashes: UnorderedSet<[u8; 32]> = group_hash_set(&group_id, "ih");
        let mut issuers: LookupMap<[u8; 32], OAuthIssuer> = group_hash_map(&group_id, "is");
        let mut auth_key_hashes: UnorderedSet<[u8; 32]> = group_hash_set(&group_id, "akh");
        let mut auth_keys: LookupMap<[u8; 32], Vec<u8>> = group_hash_map(&group_id, "ak");

        // Add initial nodes.
        for node in &node_accounts {
            let info = self.nodes.get(node).expect("node not registered");
            if info.is_open {
                active_nodes.insert(node.clone());
                node_status.insert(node.clone(), NodeStatus::Active);
                self.add_node_group(node, &group_id);
                events::node_joined(&group_id, node);
            } else {
                pending_nodes.insert(node.clone());
                node_status.insert(node.clone(), NodeStatus::Pending);
                events::node_invited(&group_id, node);
            }
        }

        // Add initial issuers.
        for ii in &initial_issuers {
            let hash = Self::issuer_hash(&ii.issuer);
            issuers.insert(hash, OAuthIssuer {
                issuer: ii.issuer.clone(),
                client_ids: ii.client_ids.clone(),
            });
            issuer_hashes.insert(hash);
            events::issuer_added(&group_id, &hash, &ii.issuer);
        }

        // Add initial auth keys.
        for key in &initial_auth_keys {
            let hash = Self::key_hash(key);
            auth_keys.insert(hash, key.clone());
            auth_key_hashes.insert(hash);
            events::auth_key_added(&group_id, &hash);
        }

        self.group_meta.insert(group_id.clone(), meta);
        self.groups.insert(group_id.clone());
        self.state_version += 1;

        events::group_created(&group_id, &caller, threshold);
    }

    /// Invite a node to the group. Manager only.
    pub fn invite_node(&mut self, group_id: GroupId, node: AccountId) {
        let meta = self.group_meta.get(&group_id).expect("group not found").clone();
        assert!(env::predecessor_account_id() == meta.manager, "not manager");

        let info = self.nodes.get(&node).expect("node not registered");
        let mut node_status: LookupMap<AccountId, NodeStatus> =
            group_account_map(&group_id, "ns");
        let status = node_status.get(&node).copied().unwrap_or(NodeStatus::None);
        assert!(status == NodeStatus::None, "node already in group");

        if info.is_open {
            let mut active: UnorderedSet<AccountId> = group_account_set(&group_id, "an");
            active.insert(node.clone());
            node_status.insert(node.clone(), NodeStatus::Active);
            self.add_node_group(&node, &group_id);
            events::node_joined(&group_id, &node);
        } else {
            let mut pending: UnorderedSet<AccountId> = group_account_set(&group_id, "pn");
            pending.insert(node.clone());
            node_status.insert(node.clone(), NodeStatus::Pending);
            events::node_invited(&group_id, &node);
        }

        self.bump_group_version(&group_id);
    }

    /// Accept a pending invitation. Caller must be the node's operator.
    pub fn accept_invite(&mut self, group_id: GroupId, node: AccountId) {
        self.assert_operator(&node);

        let mut node_status: LookupMap<AccountId, NodeStatus> =
            group_account_map(&group_id, "ns");
        let status = node_status.get(&node).copied().unwrap_or(NodeStatus::None);
        assert!(status == NodeStatus::Pending, "node is not pending");

        let mut pending: UnorderedSet<AccountId> = group_account_set(&group_id, "pn");
        let mut active: UnorderedSet<AccountId> = group_account_set(&group_id, "an");
        pending.remove(&node);
        active.insert(node.clone());
        node_status.insert(node.clone(), NodeStatus::Active);
        self.add_node_group(&node, &group_id);

        self.bump_group_version(&group_id);
        events::node_joined(&group_id, &node);
    }

    /// Decline a pending invitation. Caller must be the node's operator.
    pub fn decline_invite(&mut self, group_id: GroupId, node: AccountId) {
        self.assert_operator(&node);

        let mut node_status: LookupMap<AccountId, NodeStatus> =
            group_account_map(&group_id, "ns");
        let status = node_status.get(&node).copied().unwrap_or(NodeStatus::None);
        assert!(status == NodeStatus::Pending, "node is not pending");

        let mut pending: UnorderedSet<AccountId> = group_account_set(&group_id, "pn");
        pending.remove(&node);
        node_status.insert(node.clone(), NodeStatus::None);

        self.bump_group_version(&group_id);
        events::node_declined(&group_id, &node);
    }

    /// Queue a node for removal after the group's removal delay.
    pub fn queue_removal(&mut self, group_id: GroupId, node: AccountId) {
        let caller = env::predecessor_account_id();
        let meta = self.group_meta.get(&group_id).expect("group not found").clone();

        let node_status: LookupMap<AccountId, NodeStatus> =
            group_account_map(&group_id, "ns");
        let status = node_status.get(&node).copied().unwrap_or(NodeStatus::None);
        assert!(status == NodeStatus::Active, "node is not active");

        let is_manager = caller == meta.manager;
        let is_operator = caller == self.effective_operator(&node);
        assert!(is_manager || is_operator, "caller is not manager or operator");

        let mut removal_requests: LookupMap<AccountId, RemovalRequest> =
            group_account_map(&group_id, "rr");
        assert!(!removal_requests.contains_key(&node), "removal already queued");

        let execute_after = env::block_timestamp() + meta.removal_delay_secs * 1_000_000_000;
        removal_requests.insert(node.clone(), RemovalRequest {
            execute_after,
            initiator: caller.clone(),
        });

        self.bump_group_version(&group_id);
        events::removal_queued(&group_id, &node, &caller, execute_after);
    }

    /// Cancel a queued removal. Caller must be the original initiator.
    pub fn cancel_removal(&mut self, group_id: GroupId, node: AccountId) {
        let caller = env::predecessor_account_id();

        let mut removal_requests: LookupMap<AccountId, RemovalRequest> =
            group_account_map(&group_id, "rr");
        let request = removal_requests.get(&node).expect("no removal queued").clone();
        assert!(caller == request.initiator, "only the initiator can cancel");

        removal_requests.remove(&node);
        self.bump_group_version(&group_id);
        events::removal_cancelled(&group_id, &node, &caller);
    }

    /// Execute a queued removal after the delay has elapsed. Permissionless.
    pub fn execute_removal(&mut self, group_id: GroupId, node: AccountId) {
        let mut removal_requests: LookupMap<AccountId, RemovalRequest> =
            group_account_map(&group_id, "rr");
        let request = removal_requests.get(&node).expect("no removal queued").clone();
        assert!(
            env::block_timestamp() >= request.execute_after,
            "removal delay not elapsed"
        );

        removal_requests.remove(&node);

        let mut active: UnorderedSet<AccountId> = group_account_set(&group_id, "an");
        let mut node_status: LookupMap<AccountId, NodeStatus> =
            group_account_map(&group_id, "ns");
        active.remove(&node);
        node_status.insert(node.clone(), NodeStatus::None);
        self.remove_node_group(&node, &group_id);

        self.bump_group_version(&group_id);
        events::node_removed(&group_id, &node);
    }

    /// Transfer group management to a new account. Manager only.
    pub fn transfer_manager(&mut self, group_id: GroupId, new_manager: AccountId) {
        let mut meta = self.group_meta.get(&group_id).expect("group not found").clone();
        assert!(env::predecessor_account_id() == meta.manager, "not manager");

        let old_manager = meta.manager.clone();
        meta.manager = new_manager.clone();
        meta.version += 1;
        self.group_meta.insert(group_id.clone(), meta);
        self.state_version += 1;

        events::manager_transferred(&group_id, &old_manager, &new_manager);
    }

    /// Trigger a same-committee key reshare. Manager only.
    pub fn request_reshare(&mut self, group_id: GroupId) {
        let caller = env::predecessor_account_id();
        let meta = self.group_meta.get(&group_id).expect("group not found");
        assert!(caller == meta.manager, "not manager");

        let active: UnorderedSet<AccountId> = group_account_set(&group_id, "an");
        assert!(
            active.len() >= meta.threshold,
            "not enough active nodes for reshare"
        );

        self.state_version += 1;
        events::reshare_requested(&group_id, &caller);
    }

    // --- Internal helpers ---

    pub(crate) fn bump_group_version(&mut self, group_id: &str) {
        if let Some(mut meta) = self.group_meta.get(group_id).cloned() {
            meta.version += 1;
            self.group_meta.insert(group_id.to_string(), meta);
        }
        self.state_version += 1;
    }

    pub(crate) fn add_node_group(&mut self, node: &AccountId, group_id: &str) {
        if !self.node_groups.contains_key(node) {
            let prefix = format!("ngr:{}:", node);
            self.node_groups
                .insert(node.clone(), UnorderedSet::new(prefix.into_bytes()));
        }
        self.node_groups
            .get_mut(node)
            .unwrap()
            .insert(group_id.to_string());
    }

    fn remove_node_group(&mut self, node: &AccountId, group_id: &str) {
        if let Some(groups) = self.node_groups.get_mut(node) {
            groups.remove(&group_id.to_string());
        }
    }

    pub(crate) fn issuer_hash(issuer: &str) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(issuer.as_bytes());
        hasher.finalize().into()
    }

    pub(crate) fn key_hash(key: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(key);
        hasher.finalize().into()
    }
}
