use near_sdk::near;
use near_sdk::AccountId;

/// Group identifier — caller-specified string, must be unique.
pub type GroupId = String;

/// Node status within a group.
#[near(serializers = [borsh])]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NodeStatus {
    /// Not in the group.
    None,
    /// Invited but not yet accepted.
    Pending,
    /// Active member, eligible for signing.
    Active,
}

/// Registered node metadata.
#[near(serializers = [borsh, json])]
#[derive(Clone)]
pub struct NodeInfo {
    /// 65-byte uncompressed secp256k1 public key (0x04 prefix).
    pub pubkey: Vec<u8>,
    /// If true, the node auto-joins groups on invite.
    pub is_open: bool,
    /// Block timestamp (nanoseconds) when the node registered.
    pub registered_at: u64,
    /// Optional operator account. None = the node account is its own operator.
    pub operator: Option<AccountId>,
}

/// Scalar group metadata (no nested collections). Stored in LookupMap.
#[near(serializers = [borsh])]
#[derive(Clone)]
pub struct GroupMeta {
    pub manager: AccountId,
    pub threshold: u32,
    pub removal_delay_secs: u64,
    pub version: u64,
}

/// Queued removal with time delay.
#[near(serializers = [borsh, json])]
#[derive(Clone)]
pub struct RemovalRequest {
    /// Nanosecond timestamp after which removal can be executed.
    pub execute_after: u64,
    /// Account that initiated the removal.
    pub initiator: AccountId,
}

/// OAuth issuer configuration.
#[near(serializers = [borsh, json])]
#[derive(Clone)]
pub struct OAuthIssuer {
    /// OIDC discovery URL (e.g. "https://accounts.google.com").
    pub issuer: String,
    /// Allowed OAuth client IDs for this issuer.
    pub client_ids: Vec<String>,
}

/// Initial issuer for group creation.
#[near(serializers = [json])]
pub struct InitialIssuer {
    pub issuer: String,
    pub client_ids: Vec<String>,
}

/// View-friendly version of NodeInfo.
#[near(serializers = [json])]
pub struct NodeInfoView {
    pub account_id: AccountId,
    pub pubkey: Vec<u8>,
    pub is_open: bool,
    pub registered_at: u64,
    pub operator: Option<AccountId>,
}

/// View-friendly version of OAuthIssuer.
#[near(serializers = [json])]
pub struct OAuthIssuerView {
    pub issuer_hash: Vec<u8>,
    pub issuer: String,
    pub client_ids: Vec<String>,
}
