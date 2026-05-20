//! Shared types for session state machines.

/// A message the KMS wants to send to a peer (or broadcast).
pub struct OutgoingMessage {
    pub session_id: String,
    pub from: String,
    pub to: String, // empty = broadcast
    pub payload: Vec<u8>,
}

/// The result of a completed session.
pub struct SessionResult {
    pub group_key: Option<Vec<u8>>,
    pub verifying_share: Option<Vec<u8>>,
    pub signature_r: Option<Vec<u8>>,
    pub signature_z: Option<Vec<u8>>,
}

/// Output from processing a message or starting a session.
pub struct StepOutput {
    pub messages: Vec<OutgoingMessage>,
    pub result: Option<SessionResult>,
}

/// Distinguishes errors that may resolve on retry (wrong round) from errors
/// that will never succeed.
pub(crate) enum ProcessError {
    /// Message arrived in the wrong round — buffer and retry after the next
    /// state transition.
    WrongRound(String),
    /// Permanently invalid — drop the message.
    Invalid(String),
}

/// CBOR-encode a serializable value.
pub(crate) fn cbor_encode<T: serde::Serialize>(val: &T) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    ciborium::into_writer(val, &mut buf).map_err(|e| format!("cbor encode: {e}"))?;
    Ok(buf)
}

/// CBOR-decode a deserializable value.
pub(crate) fn cbor_decode<T: serde::de::DeserializeOwned>(data: &[u8]) -> Result<T, String> {
    ciborium::from_reader(data).map_err(|e| format!("cbor decode: {e}"))
}
