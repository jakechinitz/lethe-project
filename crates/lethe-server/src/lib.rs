//! Lethe server library. Exposed for integration tests; the binary in
//! `main.rs` is a thin wrapper that calls [`run`] with env-derived config.
//!
//! Layering rules (see plan):
//!   routes/  → logic/  → db/  + crypto.rs
//! No reverse imports. No SQL outside db/. No `ed25519_dalek` outside
//! crypto.rs.

#![forbid(unsafe_code)]

pub mod config;
pub mod crypto;
pub mod csp;
pub mod db;
pub mod error;
pub mod ids;
pub mod logic;
pub mod pow;
pub mod routes;
pub mod state;
pub mod time;

use axum::{
    http::{HeaderName, HeaderValue, StatusCode},
    routing::{get, post},
    Router,
};
use config::Config;
use sqlx::PgPool;
use state::AppState;
use std::net::SocketAddr;
use tower::limit::ConcurrencyLimitLayer;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::set_header::SetResponseHeaderLayer;

const MAX_BODY_BYTES: usize = 64 * 1024;
/// Global circuit-breaker. Single-process bound on simultaneously-served
/// requests; high enough that legitimate use is unaffected, low enough
/// that an unauthenticated flood cannot exhaust connections or memory.
const MAX_INFLIGHT_REQUESTS: usize = 256;

async fn healthz() -> StatusCode {
    StatusCode::OK
}

pub fn router(state: AppState) -> Router {
    let api = Router::new()
        .route("/boards/:id", get(routes::boards::get))
        .route("/feed", get(routes::feed::get))
        .route("/threads", post(routes::threads::create))
        .route(
            "/threads/:thread_id/posts",
            post(routes::posts::create).get(routes::posts::list),
        )
        .route("/rooms", post(routes::rooms::create))
        .route(
            "/rooms/by-invite/:code/join",
            post(routes::rooms::join),
        )
        .route("/rooms/:room_id/wrap", post(routes::rooms::wrap))
        .route("/rooms/:room_id/members", get(routes::rooms::members))
        .route("/rooms/:room_id/provenance", get(routes::rooms::provenance))
        .route("/rooms/:room_id/messages", post(routes::rooms::send_message))
        .route(
            "/rooms/:room_id/messages/list",
            post(routes::rooms::list_messages),
        )
        .route("/rooms/:room_id/remove", post(routes::rooms::remove));

    let pages = Router::new()
        .route("/", get(routes::pages::index))
        .route("/about", get(routes::pages::about))
        .route("/b/:board", get(routes::pages::board))
        .route(
            "/b/:board/t/:thread_id",
            get(routes::pages::thread),
        )
        .route("/r/new", get(routes::pages::room_create))
        .route("/r/join/:invite_code", get(routes::pages::room_join))
        .route("/r/:room_id", get(routes::pages::room))
        .fallback(get(routes::pages::not_found));

    let static_dir = std::env::var("LETHE_STATIC_DIR")
        .unwrap_or_else(|_| "crates/lethe-server/static".to_string());

    let mut app = Router::new()
        .route("/healthz", get(healthz))
        .merge(pages)
        .nest("/api", api)
        .nest_service("/static", tower_http::services::ServeDir::new(static_dir))
        .layer(RequestBodyLimitLayer::new(MAX_BODY_BYTES))
        .layer(ConcurrencyLimitLayer::new(MAX_INFLIGHT_REQUESTS))
        .with_state(state);

    for (name, value) in csp::headers() {
        app = app.layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static(name),
            HeaderValue::from_static(value),
        ));
    }
    app
}

pub async fn build_state(cfg: Config) -> Result<AppState, sqlx::Error> {
    let db: PgPool = db::connect(&cfg.database_url).await?;
    Ok(AppState { db, cfg })
}

pub async fn run(cfg: Config) -> Result<(), Box<dyn std::error::Error>> {
    let bind: SocketAddr = cfg.bind_addr;
    let state = build_state(cfg).await?;
    spawn_retention_worker(state.db.clone(), std::time::Duration::from_secs(3600));
    let app = router(state);
    let listener = tokio::net::TcpListener::bind(bind).await?;
    tracing::info!(%bind, "lethe-server listening");
    axum::serve(listener, app).await?;
    Ok(())
}

/// Background loop that prunes expired threads and room messages.
/// Logs counts only; never row identifiers.
pub fn spawn_retention_worker(db: PgPool, interval: std::time::Duration) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(interval);
        // Don't fire instantly on startup; first sweep happens after
        // `interval`, giving the server a stable initial state.
        tick.tick().await;
        loop {
            tick.tick().await;
            match db::retention::run_once(&db).await {
                Ok(stats) => tracing::info!(
                    threads_deleted = stats.threads_deleted,
                    room_messages_deleted = stats.room_messages_deleted,
                    "retention sweep",
                ),
                Err(e) => tracing::warn!(error = ?e, "retention sweep failed"),
            }
        }
    });
}
