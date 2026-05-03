//! Binary entrypoint: load config, init tracing, run the server.

use lethe_server::{config::Config, run};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _ = dotenvy::dotenv();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "lethe_server=info,tower_http=info".into()),
        )
        .compact()
        .init();
    let cfg = Config::from_env().map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
    run(cfg).await
}
