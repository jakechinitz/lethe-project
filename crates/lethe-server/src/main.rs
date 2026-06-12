//! Binary entrypoint: load config, init tracing, run the server.

use lethe_server::{config::Config, run};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _ = dotenvy::dotenv();
    // `tower_http` stays at `warn` by default: we intentionally wire no
    // request-trace layer (request URIs carry invite codes / room ids /
    // thread ids — see the note in `lib::router`). Keeping it below
    // `info` means even an accidentally-added TraceLayer won't log those
    // URIs unless an operator explicitly opts in via RUST_LOG.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "lethe_server=info,tower_http=warn".into()),
        )
        .compact()
        .init();
    let cfg = Config::from_env().map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
    run(cfg).await
}
