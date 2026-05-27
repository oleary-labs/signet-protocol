//! Signet NEAR contract — node registry, group management, and auth configuration.
//!
//! Single contract managing all groups. Replaces the EVM SignetFactory + SignetGroup
//! pair with NEAR's prefix-keyed storage model.
//!
//! Group collections (active_nodes, issuers, etc.) are stored as top-level
//! trie-prefixed collections keyed by `g:{group_id}:{suffix}`. Scalar group
//! metadata (manager, threshold, version) is stored in a LookupMap<GroupId, GroupMeta>.

use near_sdk::store::{LookupMap, UnorderedSet};
use near_sdk::{near, AccountId, PanicOnDefault};

mod events;
mod group;
mod group_auth;
mod node_registry;
mod types;
mod views;

pub use types::*;

#[cfg(test)]
mod tests;

/// Build a storage prefix for a per-group collection.
fn group_prefix(group_id: &str, suffix: &str) -> Vec<u8> {
    format!("g:{}:{}", group_id, suffix).into_bytes()
}

/// Create an UnorderedSet<AccountId> for a group collection.
fn group_account_set(group_id: &str, suffix: &str) -> UnorderedSet<AccountId> {
    UnorderedSet::new(group_prefix(group_id, suffix))
}

/// Create an UnorderedSet<[u8; 32]> for a group hash set.
fn group_hash_set(group_id: &str, suffix: &str) -> UnorderedSet<[u8; 32]> {
    UnorderedSet::new(group_prefix(group_id, suffix))
}

/// Create a LookupMap<AccountId, V> for a group.
fn group_account_map<V: near_sdk::borsh::BorshSerialize + near_sdk::borsh::BorshDeserialize>(
    group_id: &str,
    suffix: &str,
) -> LookupMap<AccountId, V> {
    LookupMap::new(group_prefix(group_id, suffix))
}

/// Create a LookupMap<[u8; 32], V> for a group.
fn group_hash_map<V: near_sdk::borsh::BorshSerialize + near_sdk::borsh::BorshDeserialize>(
    group_id: &str,
    suffix: &str,
) -> LookupMap<[u8; 32], V> {
    LookupMap::new(group_prefix(group_id, suffix))
}

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct SignetContract {
    /// Contract owner (can set min_removal_delay_secs).
    pub owner: AccountId,

    /// Minimum removal delay in seconds (protocol governance parameter).
    pub min_removal_delay_secs: u64,

    /// Monotonically increasing version counter. Incremented on every state
    /// mutation. The Go node polls this to detect changes without event parsing.
    pub state_version: u64,

    // --- Node registry ---
    pub nodes: LookupMap<AccountId, NodeInfo>,
    pub registered_nodes: UnorderedSet<AccountId>,

    // --- Groups (scalar metadata only; collections are trie-prefixed) ---
    pub groups: UnorderedSet<GroupId>,
    pub group_meta: LookupMap<GroupId, GroupMeta>,

    // --- Reverse index: node → groups where active ---
    pub node_groups: LookupMap<AccountId, UnorderedSet<GroupId>>,
}

#[near]
impl SignetContract {
    /// Initialize the contract. Called once on deployment.
    #[init]
    pub fn new(owner: AccountId, min_removal_delay_secs: u64) -> Self {
        Self {
            owner,
            min_removal_delay_secs,
            state_version: 0,
            nodes: LookupMap::new(b"n".to_vec()),
            registered_nodes: UnorderedSet::new(b"rn".to_vec()),
            groups: UnorderedSet::new(b"gs".to_vec()),
            group_meta: LookupMap::new(b"gm".to_vec()),
            node_groups: LookupMap::new(b"ng".to_vec()),
        }
    }

    /// Update the minimum removal delay. Owner only.
    pub fn set_min_removal_delay(&mut self, delay_secs: u64) {
        assert!(
            near_sdk::env::predecessor_account_id() == self.owner,
            "only owner"
        );
        self.min_removal_delay_secs = delay_secs;
    }
}
