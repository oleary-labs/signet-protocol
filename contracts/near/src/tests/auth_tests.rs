use near_sdk::test_utils::VMContextBuilder;
use near_sdk::testing_env;

use crate::SignetContract;

fn test_pubkey(seed: u8) -> Vec<u8> {
    let mut key = vec![0x04];
    key.extend_from_slice(&[seed; 64]);
    key
}

fn set_caller(account: &str) {
    let ctx = VMContextBuilder::new()
        .predecessor_account_id(account.parse().unwrap())
        .attached_deposit(near_sdk::NearToken::from_near(1))
        .build();
    testing_env!(ctx);
}

fn setup_with_group() -> SignetContract {
    let ctx = VMContextBuilder::new()
        .predecessor_account_id("owner.near".parse().unwrap())
        .build();
    testing_env!(ctx);
    let mut contract = SignetContract::new("owner.near".parse().unwrap(), 60);

    set_caller("node1.near");
    contract.register_node(test_pubkey(0xAA), true, None);

    set_caller("owner.near");
    contract.create_group(
        "group-1".to_string(),
        vec!["node1.near".parse().unwrap()],
        1,
        60,
        vec![],
        vec![],
    );

    contract
}

#[test]
fn test_add_and_get_issuer() {
    let mut contract = setup_with_group();
    set_caller("owner.near");

    contract.add_issuer(
        "group-1".to_string(),
        "https://accounts.google.com".to_string(),
        vec!["client-123".to_string()],
    );

    let issuers = contract.get_issuers("group-1".to_string());
    assert_eq!(issuers.len(), 1);
    assert_eq!(issuers[0].issuer, "https://accounts.google.com");
    assert_eq!(issuers[0].client_ids, vec!["client-123"]);
}

#[test]
fn test_remove_issuer() {
    let mut contract = setup_with_group();
    set_caller("owner.near");

    contract.add_issuer(
        "group-1".to_string(),
        "https://accounts.google.com".to_string(),
        vec!["client-123".to_string()],
    );

    let issuers = contract.get_issuers("group-1".to_string());
    let hash = issuers[0].issuer_hash.clone();

    contract.remove_issuer("group-1".to_string(), hash);

    let issuers = contract.get_issuers("group-1".to_string());
    assert_eq!(issuers.len(), 0);
}

#[test]
#[should_panic(expected = "issuer already exists")]
fn test_add_issuer_duplicate() {
    let mut contract = setup_with_group();
    set_caller("owner.near");

    contract.add_issuer(
        "group-1".to_string(),
        "https://accounts.google.com".to_string(),
        vec![],
    );
    contract.add_issuer(
        "group-1".to_string(),
        "https://accounts.google.com".to_string(),
        vec![],
    );
}

#[test]
#[should_panic(expected = "not manager")]
fn test_add_issuer_not_manager() {
    let mut contract = setup_with_group();
    set_caller("attacker.near");

    contract.add_issuer(
        "group-1".to_string(),
        "https://evil.com".to_string(),
        vec![],
    );
}

#[test]
fn test_add_and_get_auth_key() {
    let mut contract = setup_with_group();
    set_caller("owner.near");

    let key = vec![0x01; 34]; // scheme-prefixed pubkey
    contract.add_auth_key("group-1".to_string(), key.clone());

    let keys = contract.get_auth_keys("group-1".to_string());
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0], key);
}

#[test]
fn test_remove_auth_key() {
    let mut contract = setup_with_group();
    set_caller("owner.near");

    let key = vec![0x01; 34];
    contract.add_auth_key("group-1".to_string(), key.clone());

    // Compute hash to remove.
    use sha2::{Digest, Sha256};
    let hash: Vec<u8> = Sha256::digest(&key).to_vec();

    contract.remove_auth_key("group-1".to_string(), hash);

    let keys = contract.get_auth_keys("group-1".to_string());
    assert_eq!(keys.len(), 0);
}

#[test]
#[should_panic(expected = "auth key already exists")]
fn test_add_auth_key_duplicate() {
    let mut contract = setup_with_group();
    set_caller("owner.near");

    let key = vec![0x01; 34];
    contract.add_auth_key("group-1".to_string(), key.clone());
    contract.add_auth_key("group-1".to_string(), key);
}

#[test]
fn test_initial_issuers_and_keys() {
    let ctx = VMContextBuilder::new()
        .predecessor_account_id("owner.near".parse().unwrap())
        .build();
    testing_env!(ctx);
    let mut contract = SignetContract::new("owner.near".parse().unwrap(), 60);

    set_caller("node1.near");
    contract.register_node(test_pubkey(0xAA), true, None);

    set_caller("owner.near");
    contract.create_group(
        "group-1".to_string(),
        vec!["node1.near".parse().unwrap()],
        1,
        60,
        vec![crate::types::InitialIssuer {
            issuer: "https://accounts.google.com".to_string(),
            client_ids: vec!["cid-1".to_string()],
        }],
        vec![vec![0x02; 34]],
    );

    let issuers = contract.get_issuers("group-1".to_string());
    assert_eq!(issuers.len(), 1);
    assert_eq!(issuers[0].issuer, "https://accounts.google.com");

    let keys = contract.get_auth_keys("group-1".to_string());
    assert_eq!(keys.len(), 1);
}

#[test]
fn test_request_reshare() {
    let mut contract = setup_with_group();
    set_caller("owner.near");

    let v_before = contract.get_state_version();
    contract.request_reshare("group-1".to_string());
    let v_after = contract.get_state_version();
    assert!(v_after > v_before);
}
