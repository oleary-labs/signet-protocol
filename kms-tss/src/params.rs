//! CBOR deserialization of session parameters sent by the Go node.

use serde::Deserialize;

use crate::curve::Curve;

/// Parameters for a keygen (DKG) session.
#[derive(Debug, Clone, Deserialize)]
pub struct KeygenParams {
    pub group_id: String,
    pub key_id: String,
    pub party_id: String,
    pub party_ids: Vec<String>,
    pub threshold: u16,
    /// Curve for this keygen. Defaults to secp256k1 if absent (backwards compat).
    #[serde(default = "default_curve")]
    pub curve: Curve,
    /// Optional signing scope constraint. Set at keygen, stored with the key.
    /// Format: [1-byte scheme][scheme-specific bytes]. Empty = unscoped.
    #[serde(default)]
    pub scope: Vec<u8>,
}

fn default_curve() -> Curve {
    Curve::Secp256k1
}

/// Parameters for a signing session.
#[derive(Debug, Clone, Deserialize)]
pub struct SignParams {
    pub group_id: String,
    pub key_id: String,
    pub party_id: String,
    pub signer_ids: Vec<String>,
    pub message: Vec<u8>,
    /// Curve for this signing session. Defaults to secp256k1 if absent.
    #[serde(default = "default_curve")]
    pub curve: Curve,
}

/// Decode CBOR bytes into keygen params.
pub fn decode_keygen_params(data: &[u8]) -> Result<KeygenParams, String> {
    ciborium::from_reader(data).map_err(|e| format!("decode keygen params: {e}"))
}

/// Decode CBOR bytes into sign params.
pub fn decode_sign_params(data: &[u8]) -> Result<SignParams, String> {
    ciborium::from_reader(data).map_err(|e| format!("decode sign params: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_keygen_params() {
        // Encode with ciborium to verify round-trip.
        let mut buf = Vec::new();
        ciborium::into_writer(
            &ciborium::value::Value::Map(vec![
                (
                    ciborium::value::Value::Text("group_id".into()),
                    ciborium::value::Value::Text("abc123".into()),
                ),
                (
                    ciborium::value::Value::Text("key_id".into()),
                    ciborium::value::Value::Text("key-1".into()),
                ),
                (
                    ciborium::value::Value::Text("party_id".into()),
                    ciborium::value::Value::Text("peer-A".into()),
                ),
                (
                    ciborium::value::Value::Text("party_ids".into()),
                    ciborium::value::Value::Array(vec![
                        ciborium::value::Value::Text("peer-A".into()),
                        ciborium::value::Value::Text("peer-B".into()),
                        ciborium::value::Value::Text("peer-C".into()),
                    ]),
                ),
                (
                    ciborium::value::Value::Text("threshold".into()),
                    ciborium::value::Value::Integer(2.into()),
                ),
            ]),
            &mut buf,
        )
        .unwrap();

        let p = decode_keygen_params(&buf).unwrap();
        assert_eq!(p.group_id, "abc123");
        assert_eq!(p.key_id, "key-1");
        assert_eq!(p.party_id, "peer-A");
        assert_eq!(p.party_ids, vec!["peer-A", "peer-B", "peer-C"]);
        assert_eq!(p.threshold, 2);
    }
}
