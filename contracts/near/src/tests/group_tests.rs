use near_sdk::test_utils::VMContextBuilder;
use near_sdk::testing_env;

use crate::SignetContract;

fn test_pubkey(seed: u8) -> Vec<u8> {
    let mut key = vec![0x04];
    key.extend_from_slice(&[seed; 64]);
    key
}

fn setup_with_nodes() -> SignetContract {
    let ctx = VMContextBuilder::new()
        .predecessor_account_id("owner.near".parse().unwrap())
        .build();
    testing_env!(ctx);
    let mut contract = SignetContract::new("owner.near".parse().unwrap(), 60);

    for (name, seed) in [("node1.near", 0xAA), ("node2.near", 0xBB), ("node3.near", 0xCC)] {
        let ctx = VMContextBuilder::new()
            .predecessor_account_id(name.parse().unwrap())
            .attached_deposit(near_sdk::NearToken::from_near(1))
            .build();
        testing_env!(ctx);
        contract.register_node(test_pubkey(seed), true, None);
    }

    contract
}

fn set_caller(account: &str) {
    let ctx = VMContextBuilder::new()
        .predecessor_account_id(account.parse().unwrap())
        .attached_deposit(near_sdk::NearToken::from_near(1))
        .build();
    testing_env!(ctx);
}

#[test]
fn test_create_group() {
    let mut contract = setup_with_nodes();
    set_caller("owner.near");

    contract.create_group(
        "group-1".to_string(),
        vec![
            "node1.near".parse().unwrap(),
            "node2.near".parse().unwrap(),
            "node3.near".parse().unwrap(),
        ],
        2,
        60,
        vec![],
        vec![],
    );

    let groups = contract.get_groups();
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0], "group-1");

    let active = contract.get_active_nodes("group-1".to_string());
    assert_eq!(active.len(), 3);

    assert_eq!(contract.get_threshold("group-1".to_string()), 2);
    assert!(contract.is_operational("group-1".to_string()));
}

#[test]
fn test_node_groups_reverse_index() {
    let mut contract = setup_with_nodes();
    set_caller("owner.near");

    contract.create_group(
        "group-1".to_string(),
        vec!["node1.near".parse().unwrap(), "node2.near".parse().unwrap()],
        2,
        60,
        vec![],
        vec![],
    );

    let groups = contract.get_node_groups("node1.near".parse().unwrap());
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0], "group-1");

    // node3 is not in the group.
    let groups = contract.get_node_groups("node3.near".parse().unwrap());
    assert_eq!(groups.len(), 0);
}

#[test]
#[should_panic(expected = "group already exists")]
fn test_create_group_duplicate() {
    let mut contract = setup_with_nodes();
    set_caller("owner.near");

    contract.create_group(
        "group-1".to_string(),
        vec!["node1.near".parse().unwrap()],
        1,
        60,
        vec![],
        vec![],
    );
    contract.create_group(
        "group-1".to_string(),
        vec!["node1.near".parse().unwrap()],
        1,
        60,
        vec![],
        vec![],
    );
}

#[test]
fn test_invite_and_accept() {
    let mut contract = setup_with_nodes();

    // Register a closed node.
    set_caller("closed.near");
    contract.register_node(test_pubkey(0xDD), false, None);

    // Create group without the closed node.
    set_caller("owner.near");
    contract.create_group(
        "group-1".to_string(),
        vec!["node1.near".parse().unwrap()],
        1,
        60,
        vec![],
        vec![],
    );

    // Invite closed node — should go to pending.
    contract.invite_node("group-1".to_string(), "closed.near".parse().unwrap());
    let pending = contract.get_pending_nodes("group-1".to_string());
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].as_str(), "closed.near");

    // Accept as the node itself.
    set_caller("closed.near");
    contract.accept_invite("group-1".to_string(), "closed.near".parse().unwrap());

    let active = contract.get_active_nodes("group-1".to_string());
    assert_eq!(active.len(), 2);
    let pending = contract.get_pending_nodes("group-1".to_string());
    assert_eq!(pending.len(), 0);
}

#[test]
fn test_decline_invite() {
    let mut contract = setup_with_nodes();

    set_caller("closed.near");
    contract.register_node(test_pubkey(0xDD), false, None);

    set_caller("owner.near");
    contract.create_group(
        "group-1".to_string(),
        vec!["node1.near".parse().unwrap()],
        1,
        60,
        vec![],
        vec![],
    );
    contract.invite_node("group-1".to_string(), "closed.near".parse().unwrap());

    set_caller("closed.near");
    contract.decline_invite("group-1".to_string(), "closed.near".parse().unwrap());

    let pending = contract.get_pending_nodes("group-1".to_string());
    assert_eq!(pending.len(), 0);
}

#[test]
fn test_removal_lifecycle() {
    let mut contract = setup_with_nodes();
    set_caller("owner.near");

    contract.create_group(
        "group-1".to_string(),
        vec![
            "node1.near".parse().unwrap(),
            "node2.near".parse().unwrap(),
            "node3.near".parse().unwrap(),
        ],
        2,
        60,
        vec![],
        vec![],
    );

    // Queue removal.
    contract.queue_removal("group-1".to_string(), "node3.near".parse().unwrap());

    let req = contract.get_removal_request(
        "group-1".to_string(),
        "node3.near".parse().unwrap(),
    );
    assert!(req.is_some());

    // Cancel removal.
    contract.cancel_removal("group-1".to_string(), "node3.near".parse().unwrap());

    let req = contract.get_removal_request(
        "group-1".to_string(),
        "node3.near".parse().unwrap(),
    );
    assert!(req.is_none());

    // node3 still active.
    let active = contract.get_active_nodes("group-1".to_string());
    assert_eq!(active.len(), 3);
}

#[test]
fn test_execute_removal() {
    let mut contract = setup_with_nodes();
    set_caller("owner.near");

    contract.create_group(
        "group-1".to_string(),
        vec![
            "node1.near".parse().unwrap(),
            "node2.near".parse().unwrap(),
            "node3.near".parse().unwrap(),
        ],
        2,
        1, // 1 second delay
        vec![],
        vec![],
    );

    contract.queue_removal("group-1".to_string(), "node3.near".parse().unwrap());

    // Advance time past the delay.
    let ctx = VMContextBuilder::new()
        .predecessor_account_id("anyone.near".parse().unwrap())
        .block_timestamp(near_sdk::env::block_timestamp() + 2_000_000_000) // +2 seconds
        .build();
    testing_env!(ctx);

    contract.execute_removal("group-1".to_string(), "node3.near".parse().unwrap());

    let active = contract.get_active_nodes("group-1".to_string());
    assert_eq!(active.len(), 2);

    // node3 removed from reverse index.
    let groups = contract.get_node_groups("node3.near".parse().unwrap());
    assert_eq!(groups.len(), 0);
}

#[test]
fn test_transfer_manager() {
    let mut contract = setup_with_nodes();
    set_caller("owner.near");

    contract.create_group(
        "group-1".to_string(),
        vec!["node1.near".parse().unwrap()],
        1,
        60,
        vec![],
        vec![],
    );

    contract.transfer_manager("group-1".to_string(), "newmgr.near".parse().unwrap());

    let mgr = contract.get_manager("group-1".to_string()).unwrap();
    assert_eq!(mgr.as_str(), "newmgr.near");
}

#[test]
fn test_group_version_increments() {
    let mut contract = setup_with_nodes();
    set_caller("owner.near");

    contract.create_group(
        "group-1".to_string(),
        vec!["node1.near".parse().unwrap()],
        1,
        60,
        vec![],
        vec![],
    );

    let v1 = contract.get_group_version("group-1".to_string());
    assert!(v1 > 0);

    contract.invite_node("group-1".to_string(), "node2.near".parse().unwrap());
    let v2 = contract.get_group_version("group-1".to_string());
    assert!(v2 > v1);
}
