use std::path::PathBuf;
use std::sync::Arc;

use tonic::transport::Server;
use tracing::info;

pub mod proto {
    tonic::include_proto!("signet.kms.v1");
}

mod curve;
mod custody;
mod ecdsa_session;
mod encrypted_store;
mod params;
mod reshare;
mod reshare_session;
mod service;
mod session;
mod storage;
mod types;

fn parse_hex_key(hex_str: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(hex_str)?;
    if bytes.len() != 32 {
        return Err(format!("SIGNET_KMS_KEY must be 32 bytes (64 hex chars), got {}", bytes.len()).into());
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

use proto::key_manager_server::KeyManagerServer;
use custody::{KeyCustody, LocalKeyCustody};
use service::KmsService;
use storage::Storage;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "kms_tss=info".into()),
        )
        .init();

    let args: Vec<String> = std::env::args().collect();

    // CLI subcommand: list-keys <data_dir> <group_id>
    if args.get(1).map(|s| s.as_str()) == Some("list-keys") {
        let data_dir = args.get(2).expect("usage: kms-tss list-keys <data_dir> <group_id>");
        let group_id = args.get(3).expect("missing group_id");
        let storage = Storage::new(data_dir).map_err(|e| format!("open storage: {e}"))?;
        let keys = storage.list_keys(group_id)?;
        if keys.is_empty() {
            println!("no keys found for group {group_id}");
        } else {
            for (key_id, curve) in &keys {
                println!("{curve}\t{key_id}");
            }
            println!("\n{} keys total", keys.len());
        }
        return Ok(());
    }

    // CLI subcommand: migrate-group <data_dir> <old_group_id> <new_group_id>
    if args.get(1).map(|s| s.as_str()) == Some("migrate-group") {
        let data_dir = args.get(2).expect("usage: kms-tss migrate-group <data_dir> <old_group> <new_group>");
        let old_group = args.get(3).expect("missing old_group_id");
        let new_group = args.get(4).expect("missing new_group_id");
        let storage = Storage::new(data_dir).map_err(|e| format!("open storage: {e}"))?;
        let count = storage.migrate_group(old_group, new_group)?;
        println!("migrated {count} keys from {old_group} to {new_group}");
        storage.flush();
        return Ok(());
    }

    let socket_path = args
        .get(1)
        .map(|s| s.as_str())
        .unwrap_or("/tmp/signet-kms.sock");
    let data_dir = args
        .get(2)
        .map(|s| s.as_str())
        .unwrap_or("/tmp/signet-kms-data");

    let socket_path = PathBuf::from(socket_path);

    // Open key storage FIRST. The sled lock is what makes "only one KMS per
    // data dir" true, so it must be acquired before this process touches any
    // shared resource. Unlinking the socket first — as this did previously —
    // means a second instance destroys the live instance's socket path and
    // only then discovers it cannot have the database: the loser of the race
    // takes the winner down with it, leaving a KMS that holds the data but has
    // no name any client can reach.
    let storage = if let Ok(hex_key) = std::env::var("SIGNET_KMS_KEY") {
        let kek = parse_hex_key(&hex_key)?;
        let custody = Arc::new(LocalKeyCustody::new(kek));
        info!("at-rest encryption enabled (KEK from SIGNET_KMS_KEY)");
        Arc::new(Storage::new_encrypted(data_dir, custody)
            .map_err(|e| format!("open encrypted storage: {e}"))?)
    } else {
        info!("at-rest encryption disabled (set SIGNET_KMS_KEY to enable)");
        Arc::new(Storage::new(data_dir).map_err(|e| format!("open storage: {e}"))?)
    };

    // Only now, holding the storage lock, clear a socket left behind by an
    // unclean shutdown. Reaching this point proves no other instance is live.
    if socket_path.exists() {
        std::fs::remove_file(&socket_path)?;
    }

    let uds = tokio::net::UnixListener::bind(&socket_path)?;
    let uds_stream = tokio_stream::wrappers::UnixListenerStream::new(uds);

    info!(
        path = %socket_path.display(),
        data_dir = %data_dir,
        "kms-tss listening"
    );

    Server::builder()
        .add_service(KeyManagerServer::new(KmsService::new(storage.clone())))
        .serve_with_incoming_shutdown(uds_stream, async {
            tokio::signal::ctrl_c().await.ok();
            info!("shutting down");
        })
        .await?;

    // Explicit flush on shutdown — sled flushes on drop but that isn't
    // guaranteed to run during abrupt process exit.
    storage.flush();
    info!("storage flushed, exiting");

    Ok(())
}
