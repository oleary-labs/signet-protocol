//! gRPC KeyManager service implementation.

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::Mutex;
use tonic::{Request, Response, Status};
use tracing::{info, warn};

use crate::params;
use crate::proto;
use crate::proto::key_manager_server::KeyManager;
use crate::proto::*;
use crate::session::{OutgoingMessage, Session, StepOutput};
use crate::storage::Storage;

/// Shared state for the KMS service.
pub struct KmsService {
    storage: Arc<Storage>,
    sessions: Arc<Mutex<HashMap<String, Session>>>,
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
    fn to_proto_result(r: crate::session::SessionResult) -> proto::SessionResult {
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
                return Err(Status::unimplemented("reshare not implemented"));
            }
            _ => {
                return Err(Status::invalid_argument("unknown session type"));
            }
        };

        // Store the session.
        self.sessions.lock().await.insert(session_id, session);

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
            loop {
                let msg_result = in_stream.message().await;
                let msg = match msg_result {
                    Ok(Some(msg)) => msg,
                    Ok(None) => return,
                    Err(e) => {
                        warn!(error = %e, "process_message stream error");
                        return;
                    }
                };
                let session_id = msg.session_id.clone();

                let mut sessions_guard = sessions.lock().await;
                let session = match sessions_guard.get_mut(&session_id) {
                    Some(s) => s,
                    None => {
                        warn!(session_id = %session_id, "unknown session");
                        let _ = tx
                            .send(Err(Status::not_found(format!(
                                "unknown session: {session_id}"
                            ))))
                            .await;
                        return;
                    }
                };

                let step_result =
                    session.process_message(&msg.from, &msg.to, &msg.payload, &storage);
                // Drop the lock before sending on the channel.
                drop(sessions_guard);

                match step_result {
                    Ok(StepOutput { messages, result }) => {
                        // Send outgoing messages to peers.
                        for out in messages {
                            let proto_msg = SessionMessage {
                                session_id: out.session_id,
                                from: out.from,
                                to: out.to,
                                payload: out.payload,
                                result: None,
                            };
                            if tx.send(Ok(proto_msg)).await.is_err() {
                                return; // client disconnected
                            }
                        }

                        // If session produced a result, send it and close.
                        if let Some(r) = result {
                            let result_msg = SessionMessage {
                                session_id: session_id.clone(),
                                from: String::new(),
                                to: String::new(),
                                payload: vec![],
                                result: Some(KmsService::to_proto_result(r)),
                            };
                            let _ = tx.send(Ok(result_msg)).await;

                            // Clean up completed session.
                            sessions.lock().await.remove(&session_id);
                            return;
                        }
                    }
                    Err(e) => {
                        warn!(session_id = %session_id, error = %e, "process_message error");
                        let _ = tx.send(Err(Status::internal(e))).await;
                        sessions.lock().await.remove(&session_id);
                        return;
                    }
                }
            }
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

    async fn get_public_key(
        &self,
        request: Request<KeyRef>,
    ) -> Result<Response<PublicKeyResponse>, Status> {
        let req = request.into_inner();
        let group_id = hex::encode(&req.group_id);
        let key_id = &req.key_id;

        let stored = self
            .storage
            .get_key(&group_id, key_id)
            .map_err(|e| Status::internal(e))?
            .ok_or_else(|| Status::not_found(format!("key not found: {group_id}/{key_id}")))?;

        Ok(Response::new(PublicKeyResponse {
            group_key: stored.group_key,
            verifying_share: stored.verifying_share,
            generation: stored.generation,
        }))
    }

    async fn list_keys(
        &self,
        request: Request<GroupRef>,
    ) -> Result<Response<KeyListResponse>, Status> {
        let group_id = hex::encode(&request.into_inner().group_id);

        let key_ids = self
            .storage
            .list_keys(&group_id)
            .map_err(|e| Status::internal(e))?;

        Ok(Response::new(KeyListResponse { key_ids }))
    }
}
