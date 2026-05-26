//! NEP-297 structured event emission.
//!
//! Events are logged as JSON for indexer consumption. The Go node does not
//! depend on these (it polls view methods + version counters), but they
//! provide an audit trail and enable future indexer-based consumers.

use near_sdk::AccountId;

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

const EVENT_STANDARD: &str = "signet";
const EVENT_VERSION: &str = "1.0.0";

fn emit(event: &str, data: &str) {
    near_sdk::env::log_str(&format!(
        r#"EVENT_JSON:{{"standard":"{}","version":"{}","event":"{}","data":{}}}"#,
        EVENT_STANDARD, EVENT_VERSION, event, data
    ));
}

pub fn node_registered(node: &AccountId, is_open: bool) {
    emit("node_registered", &format!(
        r#"{{"node":"{}","is_open":{}}}"#, node, is_open
    ));
}

pub fn node_joined(group_id: &str, node: &AccountId) {
    emit("node_joined", &format!(
        r#"{{"group_id":"{}","node":"{}"}}"#, group_id, node
    ));
}

pub fn node_invited(group_id: &str, node: &AccountId) {
    emit("node_invited", &format!(
        r#"{{"group_id":"{}","node":"{}"}}"#, group_id, node
    ));
}

pub fn node_declined(group_id: &str, node: &AccountId) {
    emit("node_declined", &format!(
        r#"{{"group_id":"{}","node":"{}"}}"#, group_id, node
    ));
}

pub fn node_removed(group_id: &str, node: &AccountId) {
    emit("node_removed", &format!(
        r#"{{"group_id":"{}","node":"{}"}}"#, group_id, node
    ));
}

pub fn removal_queued(group_id: &str, node: &AccountId, initiator: &AccountId, execute_after: u64) {
    emit("removal_queued", &format!(
        r#"{{"group_id":"{}","node":"{}","initiator":"{}","execute_after":{}}}"#,
        group_id, node, initiator, execute_after
    ));
}

pub fn removal_cancelled(group_id: &str, node: &AccountId, cancelled_by: &AccountId) {
    emit("removal_cancelled", &format!(
        r#"{{"group_id":"{}","node":"{}","cancelled_by":"{}"}}"#,
        group_id, node, cancelled_by
    ));
}

pub fn group_created(group_id: &str, creator: &AccountId, threshold: u32) {
    emit("group_created", &format!(
        r#"{{"group_id":"{}","creator":"{}","threshold":{}}}"#,
        group_id, creator, threshold
    ));
}

pub fn manager_transferred(group_id: &str, old_manager: &AccountId, new_manager: &AccountId) {
    emit("manager_transferred", &format!(
        r#"{{"group_id":"{}","old_manager":"{}","new_manager":"{}"}}"#,
        group_id, old_manager, new_manager
    ));
}

pub fn issuer_added(group_id: &str, issuer_hash: &[u8], issuer: &str) {
    emit("issuer_added", &format!(
        r#"{{"group_id":"{}","issuer_hash":"{}","issuer":"{}"}}"#,
        group_id, hex_encode(issuer_hash), issuer
    ));
}

pub fn issuer_removed(group_id: &str, issuer_hash: &[u8], issuer: &str) {
    emit("issuer_removed", &format!(
        r#"{{"group_id":"{}","issuer_hash":"{}","issuer":"{}"}}"#,
        group_id, hex_encode(issuer_hash), issuer
    ));
}

pub fn auth_key_added(group_id: &str, key_hash: &[u8]) {
    emit("auth_key_added", &format!(
        r#"{{"group_id":"{}","key_hash":"{}"}}"#,
        group_id, hex_encode(key_hash)
    ));
}

pub fn auth_key_removed(group_id: &str, key_hash: &[u8]) {
    emit("auth_key_removed", &format!(
        r#"{{"group_id":"{}","key_hash":"{}"}}"#,
        group_id, hex_encode(key_hash)
    ));
}

pub fn reshare_requested(group_id: &str, requested_by: &AccountId) {
    emit("reshare_requested", &format!(
        r#"{{"group_id":"{}","requested_by":"{}"}}"#,
        group_id, requested_by
    ));
}
