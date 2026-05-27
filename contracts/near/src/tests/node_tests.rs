use near_sdk::test_utils::VMContextBuilder;
use near_sdk::testing_env;

use crate::SignetContract;

fn test_pubkey() -> Vec<u8> {
    let mut key = vec![0x04];
    key.extend_from_slice(&[0xAA; 64]);
    key
}

fn setup() -> SignetContract {
    let ctx = VMContextBuilder::new()
        .predecessor_account_id("owner.near".parse().unwrap())
        .build();
    testing_env!(ctx);
    SignetContract::new("owner.near".parse().unwrap(), 600)
}

fn set_caller(account: &str) {
    let ctx = VMContextBuilder::new()
        .predecessor_account_id(account.parse().unwrap())
        .attached_deposit(near_sdk::NearToken::from_near(1))
        .build();
    testing_env!(ctx);
}

#[test]
fn test_register_node() {
    let mut contract = setup();
    set_caller("node1.near");

    contract.register_node(test_pubkey(), true, None);

    let info = contract.get_node("node1.near".parse().unwrap());
    assert!(info.is_some());
    let info = info.unwrap();
    assert!(info.is_open);
    assert_eq!(info.pubkey, test_pubkey());
    assert!(info.operator.is_none());
}

#[test]
fn test_register_node_with_operator() {
    let mut contract = setup();
    set_caller("node1.near");

    contract.register_node(
        test_pubkey(),
        false,
        Some("operator.near".parse().unwrap()),
    );

    let info = contract.get_node("node1.near".parse().unwrap()).unwrap();
    assert!(!info.is_open);
    assert_eq!(info.operator.unwrap().as_str(), "operator.near");
}

#[test]
#[should_panic(expected = "node already registered")]
fn test_register_node_duplicate() {
    let mut contract = setup();
    set_caller("node1.near");
    contract.register_node(test_pubkey(), true, None);
    contract.register_node(test_pubkey(), true, None);
}

#[test]
#[should_panic(expected = "pubkey must be 65 bytes")]
fn test_register_node_bad_pubkey() {
    let mut contract = setup();
    set_caller("node1.near");
    contract.register_node(vec![0x04; 33], true, None);
}

#[test]
fn test_update_open_status() {
    let mut contract = setup();
    set_caller("node1.near");
    contract.register_node(test_pubkey(), true, None);

    contract.update_open_status("node1.near".parse().unwrap(), false);

    let info = contract.get_node("node1.near".parse().unwrap()).unwrap();
    assert!(!info.is_open);
}

#[test]
fn test_set_operator() {
    let mut contract = setup();
    set_caller("node1.near");
    contract.register_node(test_pubkey(), true, None);

    contract.set_operator(
        "node1.near".parse().unwrap(),
        "newop.near".parse().unwrap(),
    );

    let info = contract.get_node("node1.near".parse().unwrap()).unwrap();
    assert_eq!(info.operator.unwrap().as_str(), "newop.near");
}

#[test]
#[should_panic(expected = "is not operator")]
fn test_update_open_status_wrong_caller() {
    let mut contract = setup();
    set_caller("node1.near");
    contract.register_node(test_pubkey(), true, None);

    set_caller("attacker.near");
    contract.update_open_status("node1.near".parse().unwrap(), false);
}

#[test]
fn test_get_registered_nodes() {
    let mut contract = setup();

    set_caller("node1.near");
    contract.register_node(test_pubkey(), true, None);

    let mut key2 = vec![0x04];
    key2.extend_from_slice(&[0xBB; 64]);
    set_caller("node2.near");
    contract.register_node(key2, true, None);

    let nodes = contract.get_registered_nodes();
    assert_eq!(nodes.len(), 2);
}

#[test]
fn test_state_version_increments() {
    let mut contract = setup();
    assert_eq!(contract.get_state_version(), 0);

    set_caller("node1.near");
    contract.register_node(test_pubkey(), true, None);
    assert_eq!(contract.get_state_version(), 1);

    contract.update_open_status("node1.near".parse().unwrap(), false);
    assert_eq!(contract.get_state_version(), 2);
}
