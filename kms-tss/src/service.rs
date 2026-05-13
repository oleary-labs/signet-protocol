//! gRPC KeyManager service implementation.

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::Mutex;
use tonic::{Request, Response, Status};
use tracing::{info, warn};

use crate::curve::Curve;
use crate::params;
use crate::proto;
use crate::proto::key_manager_server::KeyManager;
use crate::proto::*;
use crate::session::Session;
use crate::storage::Storage;
use crate::types::{OutgoingMessage, StepOutput};

/// Shared state for the KMS service.
///
/// Sessions use per-session locking (Arc<Mutex<Session>>) so that concurrent
/// sessions don't block each other. The session map itself uses a separate
/// lock only for insert/remove/lookup — never held during message processing.
pub struct KmsService {
    storage: Arc<Storage>,
    sessions: Arc<Mutex<HashMap<String, Arc<tokio::sync::Mutex<Session>>>>>,
}

/// Parse a curve string from proto, defaulting to secp256k1 if empty.
fn parse_curve(s: &str) -> Result<Curve, Status> {
    match s {
        "" | "secp256k1" => Ok(Curve::Secp256k1),
        "ed25519" => Ok(Curve::Ed25519),
        "ecdsa_secp256k1" => Ok(Curve::EcdsaSecp256k1),
        _ => Err(Status::invalid_argument(format!("unknown curve: {s}"))),
    }
}

impl KmsService {
    pub fn new(storage: Arc<Storage>) -> Self {
        KmsService {
            storage,
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Convert session outgoing messages to proto SessionMessages.
    fn to_proto_messages(msgs: Vec<OutgoingMessage>) -> Vec<SessionMessage> {
        msgs.into_iter()
            .map(|m| SessionMessage {
                session_id: m.session_id,
                from: m.from,
                to: m.to,
                payload: m.payload,
                result: None,
            })
            .collect()
    }

    /// Convert a session result to a proto SessionResult.
    fn to_proto_result(r: crate::types::SessionResult) -> proto::SessionResult {
        proto::SessionResult {
            signature_r: r.signature_r.unwrap_or_default(),
            signature_z: r.signature_z.unwrap_or_default(),
            group_key: r.group_key.unwrap_or_default(),
            verifying_share: r.verifying_share.unwrap_or_default(),
        }
    }
}

#[tonic::async_trait]
impl KeyManager for KmsService {
    async fn start_session(
        &self,
        request: Request<StartSessionRequest>,
    ) -> Result<Response<StartSessionResponse>, Status> {
        let req = request.into_inner();
        let session_id = req.session_id.clone();

        info!(
            session_id = %session_id,
            session_type = req.r#type,
            "start_session"
        );

        let (session, output) = match SessionType::try_from(req.r#type) {
            Ok(SessionType::Keygen) => {
                let p = params::decode_keygen_params(&req.params)
                    .map_err(|e| Status::invalid_argument(e))?;
                Session::start_keygen(&session_id, p)
                    .map_err(|e| Status::internal(e))?
            }
            Ok(SessionType::Sign) => {
                let p = params::decode_sign_params(&req.params)
                    .map_err(|e| Status::invalid_argument(e))?;
                Session::start_sign(&session_id, p, &self.storage)
                    .map_err(|e| Status::internal(e))?
            }
            Ok(SessionType::Reshare) => {
                let p = crate::reshare::decode_reshare_params(&req.params)
                    .map_err(|e| Status::invalid_argument(e))?;
                Session::start_reshare(&session_id, p, &self.storage)
                    .map_err(|e| Status::internal(e))?
            }
            _ => {
                return Err(Status::invalid_argument("unknown session type"));
            }
        };

        // Store the session with its own lock.
        self.sessions.lock().await.insert(
            session_id,
            Arc::new(tokio::sync::Mutex::new(session)),
        );

        let outgoing = Self::to_proto_messages(output.messages);

        Ok(Response::new(StartSessionResponse { outgoing }))
    }

    type ProcessMessageStream =
        tokio_stream::wrappers::ReceiverStream<Result<SessionMessage, Status>>;

    async fn process_message(
        &self,
        request: Request<tonic::Streaming<SessionMessage>>,
    ) -> Result<Response<Self::ProcessMessageStream>, Status> {
        let mut in_stream = request.into_inner();
        let sessions = self.sessions.clone();
        let storage = self.storage.clone();

        let (tx, rx) = tokio::sync::mpsc::channel(64);

        tokio::spawn(async move {
            // Read the first message to learn the session ID, then grab a
            // per-session lock from the map. The map lock is held only for
            // the lookup — never during message processing.
            let first_msg = match in_stream.message().await {
                Ok(Some(msg)) => msg,
                Ok(None) => return,
                Err(e) => {
                    warn!(error = %e, "process_message: no first message");
                    return;
                }
            };
            let session_id = first_msg.session_id.clone();

            let session_arc = {
                let sessions_guard = sessions.lock().await;
                match sessions_guard.get(&session_id) {
                    Some(s) => Arc::clone(s),
                    None => {
                        warn!(session_id = %session_id, "unknown session");
                        let _ = tx
                            .send(Err(Status::not_found(format!(
                                "unknown session: {session_id}"
                            ))))
                            .await;
                        return;
                    }
                }
            };

            // Run the message loop. When it exits for any reason (completion,
            // error, stream disconnect), clean up the session from the map.
            let mut msgs_to_process = vec![first_msg];

            'outer: loop {
                for msg in msgs_to_process.drain(..) {
                    let mut session = session_arc.lock().await;
                    let step_result =
                        session.process_message(&msg.from, &msg.to, &msg.payload, &storage);
                    drop(session);

                    match step_result {
                        Ok(StepOutput { messages, result }) => {
                            for out in messages {
                                let proto_msg = SessionMessage {
                                    session_id: out.session_id,
                                    from: out.from,
                                    to: out.to,
                                    payload: out.payload,
                                    result: None,
                                };
                                if tx.send(Ok(proto_msg)).await.is_err() {
                                    break 'outer;
                                }
                            }

                            if let Some(r) = result {
                                let result_msg = SessionMessage {
                                    session_id: session_id.clone(),
                                    from: String::new(),
                                    to: String::new(),
                                    payload: vec![],
                                    result: Some(KmsService::to_proto_result(r)),
                                };
                                let _ = tx.send(Ok(result_msg)).await;
                                break 'outer;
                            }
                        }
                        Err(e) => {
                            warn!(session_id = %session_id, error = %e, "process_message error");
                            let _ = tx.send(Err(Status::internal(e))).await;
                            break 'outer;
                        }
                    }
                }

                match in_stream.message().await {
                    Ok(Some(msg)) => msgs_to_process.push(msg),
                    Ok(None) => break,
                    Err(e) => {
                        warn!(error = %e, "process_message stream error");
                        break;
                    }
                }
            }

            // Always clean up: remove session from map on any exit path.
            sessions.lock().await.remove(&session_id);
        });

        Ok(Response::new(tokio_stream::wrappers::ReceiverStream::new(rx)))
    }

    async fn abort_session(
        &self,
        request: Request<AbortSessionRequest>,
    ) -> Result<Response<AbortSessionResponse>, Status> {
        let session_id = request.into_inner().session_id;
        info!(session_id = %session_id, "abort_session");
        self.sessions.lock().await.remove(&session_id);
        Ok(Response::new(AbortSessionResponse {}))
    }

    async fn commit_reshare(
        &self,
        request: Request<KeyRef>,
    ) -> Result<Response<CommitReshareResponse>, Status> {
        let req = request.into_inner();
        let group_id = hex::encode(&req.group_id);
        let key_id = &req.key_id;
        info!(group_id = %group_id, key_id = %key_id, "commit_reshare");

        let curve = parse_curve(&req.curve)?;
        let generation = self
            .storage
            .commit_reshare(&group_id, key_id, &curve)
            .map_err(|e| Status::internal(e))?;

        Ok(Response::new(CommitReshareResponse { generation }))
    }

    async fn discard_pending_reshare(
        &self,
        request: Request<KeyRef>,
    ) -> Result<Response<DiscardPendingReshareResponse>, Status> {
        let req = request.into_inner();
        let group_id = hex::encode(&req.group_id);
        let key_id = &req.key_id;
        info!(group_id = %group_id, key_id = %key_id, "discard_pending_reshare");

        let curve = parse_curve(&req.curve)?;
        self.storage
            .discard_pending_reshare(&group_id, key_id, &curve)
            .map_err(|e| Status::internal(e))?;

        Ok(Response::new(DiscardPendingReshareResponse {}))
    }

    async fn rollback_reshare(
        &self,
        request: Request<RollbackReshareRequest>,
    ) -> Result<Response<RollbackReshareResponse>, Status> {
        let req = request.into_inner();
        let group_id = hex::encode(&req.group_id);
        let key_id = &req.key_id;
        let generation = req.generation;
        info!(group_id = %group_id, key_id = %key_id, generation = generation, "rollback_reshare");

        let curve = parse_curve(&req.curve)?;
        self.storage
            .rollback_reshare(&group_id, key_id, &curve, generation)
            .map_err(|e| Status::internal(e))?;

        Ok(Response::new(RollbackReshareResponse {}))
    }

    async fn get_public_key(
        &self,
        request: Request<KeyRef>,
    ) -> Result<Response<PublicKeyResponse>, Status> {
        let req = request.into_inner();
        let group_id = hex::encode(&req.group_id);
        let key_id = &req.key_id;

        let curve = parse_curve(&req.curve)?;
        let stored = self
            .storage
            .get_key(&group_id, key_id, &curve)
            .map_err(|e| Status::internal(e))?
            .ok_or_else(|| Status::not_found(format!("key not found: {group_id}/{key_id} curve={curve}")))?;

        let status = match stored.status {
            crate::storage::KeyStatus::Active => "active",
            crate::storage::KeyStatus::Disabled => "disabled",
        };
        Ok(Response::new(PublicKeyResponse {
            group_key: stored.group_key,
            verifying_share: stored.verifying_share,
            generation: stored.generation,
            scope: stored.scope,
            status: status.to_string(),
        }))
    }

    async fn list_keys(
        &self,
        request: Request<GroupRef>,
    ) -> Result<Response<KeyListResponse>, Status> {
        let group_id = hex::encode(&request.into_inner().group_id);

        let keys = self
            .storage
            .list_keys(&group_id)
            .map_err(|e| Status::internal(e))?;

        let entries: Vec<KeyListEntry> = keys.into_iter()
            .map(|(id, curve)| KeyListEntry {
                key_id: id,
                curve: curve.as_str().to_string(),
            })
            .collect();

        Ok(Response::new(KeyListResponse { entries }))
    }

    async fn set_key_status(
        &self,
        request: Request<SetKeyStatusRequest>,
    ) -> Result<Response<SetKeyStatusResponse>, Status> {
        let req = request.into_inner();
        let group_id = hex::encode(&req.group_id);
        let key_id = &req.key_id;
        let curve = parse_curve(&req.curve)?;

        let status = match req.status.as_str() {
            "active" => crate::storage::KeyStatus::Active,
            "disabled" => crate::storage::KeyStatus::Disabled,
            other => return Err(Status::invalid_argument(format!("invalid status: {other}"))),
        };

        info!(group_id = %group_id, key_id = %key_id, status = %req.status, "set_key_status");

        self.storage
            .set_key_status(&group_id, key_id, &curve, status)
            .map_err(|e| Status::internal(e))?;

        Ok(Response::new(SetKeyStatusResponse {}))
    }

    async fn delete_key(
        &self,
        request: Request<KeyRef>,
    ) -> Result<Response<DeleteKeyResponse>, Status> {
        let req = request.into_inner();
        let group_id = hex::encode(&req.group_id);
        let key_id = &req.key_id;
        let curve = parse_curve(&req.curve)?;

        info!(group_id = %group_id, key_id = %key_id, "delete_key");

        self.storage
            .delete_key(&group_id, key_id, &curve)
            .map_err(|e| Status::internal(e))?;

        Ok(Response::new(DeleteKeyResponse {}))
    }
}
