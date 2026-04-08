use std::path::PathBuf;

use tonic::{transport::Server, Request, Response, Status};
use tracing::{info, warn};

pub mod proto {
    tonic::include_proto!("signet.kms.v1");
}

use proto::key_manager_server::{KeyManager, KeyManagerServer};
use proto::*;

/// KMS server with placeholder handlers.
///
/// All RPCs return Unimplemented until Phase 2 wires in ZF FROST.
#[derive(Debug, Default)]
pub struct KmsService;

#[tonic::async_trait]
impl KeyManager for KmsService {
    async fn start_session(
        &self,
        request: Request<StartSessionRequest>,
    ) -> Result<Response<StartSessionResponse>, Status> {
        let req = request.into_inner();
        warn!(
            session_id = %req.session_id,
            session_type = req.r#type,
            "start_session: not implemented"
        );
        Err(Status::unimplemented("start_session not implemented"))
    }

    type ProcessMessageStream =
        tokio_stream::wrappers::ReceiverStream<Result<SessionMessage, Status>>;

    async fn process_message(
        &self,
        request: Request<tonic::Streaming<SessionMessage>>,
    ) -> Result<Response<Self::ProcessMessageStream>, Status> {
        let _ = request;
        warn!("process_message: not implemented");
        Err(Status::unimplemented("process_message not implemented"))
    }

    async fn abort_session(
        &self,
        request: Request<AbortSessionRequest>,
    ) -> Result<Response<AbortSessionResponse>, Status> {
        let req = request.into_inner();
        warn!(session_id = %req.session_id, "abort_session: not implemented");
        Err(Status::unimplemented("abort_session not implemented"))
    }

    async fn get_public_key(
        &self,
        request: Request<KeyRef>,
    ) -> Result<Response<PublicKeyResponse>, Status> {
        let req = request.into_inner();
        warn!(key_id = %req.key_id, "get_public_key: not implemented");
        Err(Status::unimplemented("get_public_key not implemented"))
    }

    async fn list_keys(
        &self,
        request: Request<GroupRef>,
    ) -> Result<Response<KeyListResponse>, Status> {
        let _ = request;
        warn!("list_keys: not implemented");
        Err(Status::unimplemented("list_keys not implemented"))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "kms_frost=info".into()),
        )
        .init();

    let socket_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/tmp/signet-kms.sock".to_string());
    let socket_path = PathBuf::from(&socket_path);

    // Remove stale socket file if it exists.
    if socket_path.exists() {
        std::fs::remove_file(&socket_path)?;
    }

    let uds = tokio::net::UnixListener::bind(&socket_path)?;
    let uds_stream = tokio_stream::wrappers::UnixListenerStream::new(uds);

    info!(path = %socket_path.display(), "kms-frost listening");

    Server::builder()
        .add_service(KeyManagerServer::new(KmsService))
        .serve_with_incoming_shutdown(uds_stream, async {
            tokio::signal::ctrl_c().await.ok();
            info!("shutting down");
        })
        .await?;

    Ok(())
}
