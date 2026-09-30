use anyhow::Result;
use hopper_ipc::ServiceStatus;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let status = ServiceStatus::default();
    info!(?status, "Hopper service starting");

    // Next milestone: real local IPC server.
    // Windows: Named Pipes. macOS/Linux: local Unix domain socket.
    tokio::signal::ctrl_c().await?;

    info!("Hopper service stopping");
    Ok(())
}
