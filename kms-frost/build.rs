fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .build_server(true)
        .build_client(false) // client is Go-side
        .compile_protos(&["../proto/keymanager.proto"], &["../proto"])?;
    Ok(())
}
