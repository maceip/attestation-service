//! attestation-service entrypoint.
//!
//! Binds `127.0.0.1:8080` by default so it drops in as the loopback workload
//! behind `attested-workload`'s app-proxy. Override with `AS_BIND`.

use attestation_service::service::{http::router, state::AppState};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "attestation_service=info,tower_http=info".into()),
        )
        .init();

    let state = AppState::from_env();
    let bind = std::env::var("AS_BIND").unwrap_or_else(|_| "127.0.0.1:8080".to_string());

    let app = router(state.clone());
    let listener = tokio::net::TcpListener::bind(&bind).await?;

    tracing::info!(%bind, mode = %state.mode, "attestation-service listening");
    eprintln!("[attestation-service] listening on {bind} ({})", state.mode);

    axum::serve(listener, app).await?;
    Ok(())
}
