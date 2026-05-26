use near_sdk::{env, near, AccountId};

use crate::events;
use crate::types::NodeInfo;
use crate::{SignetContract, SignetContractExt};

#[near]
impl SignetContract {
    /// Register the caller as a node with the given secp256k1 public key.
    /// The pubkey is stored alongside the NEAR account ID for libp2p identity resolution.
    #[payable]
    pub fn register_node(
        &mut self,
        pubkey: Vec<u8>,
        is_open: bool,
        operator: Option<AccountId>,
    ) {
        let caller = env::predecessor_account_id();
        assert!(pubkey.len() == 65, "pubkey must be 65 bytes (uncompressed secp256k1)");
        assert!(pubkey[0] == 0x04, "pubkey must start with 0x04 (uncompressed)");
        assert!(
            !self.nodes.contains_key(&caller),
            "node already registered"
        );

        let info = NodeInfo {
            pubkey,
            is_open,
            registered_at: env::block_timestamp(),
            operator,
        };

        self.nodes.insert(caller.clone(), info);
        self.registered_nodes.insert(caller.clone());
        self.state_version += 1;

        events::node_registered(&caller, is_open);
    }

    /// Update the is_open flag for a node. Caller must be the node's effective operator.
    pub fn update_open_status(&mut self, node: AccountId, is_open: bool) {
        self.assert_operator(&node);
        let mut info = self.nodes.get(&node).expect("node not registered").clone();
        info.is_open = is_open;
        self.nodes.insert(node, info);
        self.state_version += 1;
    }

    /// Change the operator for a node. Caller must be the current effective operator.
    pub fn set_operator(&mut self, node: AccountId, new_operator: AccountId) {
        self.assert_operator(&node);
        let mut info = self.nodes.get(&node).expect("node not registered").clone();
        info.operator = Some(new_operator);
        self.nodes.insert(node, info);
        self.state_version += 1;
    }

    // --- Internal helpers ---

    /// Returns the effective operator for a node (the node itself if no operator is set).
    pub(crate) fn effective_operator(&self, node: &AccountId) -> AccountId {
        let info = self.nodes.get(node).expect("node not registered");
        info.operator.clone().unwrap_or_else(|| node.clone())
    }

    /// Asserts that the caller is the effective operator for the given node.
    pub(crate) fn assert_operator(&self, node: &AccountId) {
        let caller = env::predecessor_account_id();
        let operator = self.effective_operator(node);
        assert!(
            caller == operator,
            "caller {} is not operator {} for node {}",
            caller, operator, node
        );
    }
}
