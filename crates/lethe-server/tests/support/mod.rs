//! Shared test helpers: in-process server bring-up, browser-side crypto
//! mimicked via `dryoc` (libsodium-compatible), PoW solver.

#![allow(dead_code)]

pub mod browser;

use lethe_server::{
    config::Config, db, federation::Identity, moderation::classifier::NoopClassifier, router,
    state::AppState,
};
use sqlx::PgPool;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

static DB_COUNTER: AtomicU32 = AtomicU32::new(0);

const ADMIN_DATABASE_URL: &str = "postgres://postgres:dev@127.0.0.1:5432/postgres";

pub struct TestServer {
    pub base_url: String,
    pub db: PgPool,
    pub pow_bits: u32,
    pub server_pubkey: [u8; 32],
    pub admin_token: String,
    _handle: JoinHandle<()>,
}

/// Boots a fresh database, runs migrations, and starts the server in-process
/// on an ephemeral port. PoW difficulty is intentionally low so tests are fast.
pub async fn spawn() -> TestServer {
    let pow_bits = 4u32;

    let db_name = format!(
        "lethe_test_{}_{}",
        std::process::id(),
        DB_COUNTER.fetch_add(1, Ordering::SeqCst)
    );
    create_db(&db_name).await;

    let database_url = format!("postgres://postgres:dev@127.0.0.1:5432/{db_name}");
    let cfg = Config {
        database_url,
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        default_pow_bits: pow_bits as u8,
        federation_enabled: false,
        pull_interval: std::time::Duration::from_secs(60),
        admin_token: Some("test-admin-token".to_string()),
        moderation_summary: None,
        operator_label: None,
    };
    // Tests are short-lived and largely sequential within a single test
    // case; one connection per server is enough and keeps the total
    // postgres connection count manageable when many tests run in parallel.
    let pool = db::connect_with_pool_size(&cfg.database_url, 1)
        .await
        .expect("db connect");
    let identity = Identity::load_or_create(&pool).await.expect("identity");
    let server_pubkey = *identity.pubkey();
    let admin_token = cfg.admin_token.clone().unwrap();
    let state = AppState {
        db: pool.clone(),
        cfg,
        classifier: std::sync::Arc::new(NoopClassifier),
        identity: Some(std::sync::Arc::new(identity)),
    };
    let app = router(state);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    TestServer {
        base_url: format!("http://{addr}"),
        db: pool,
        pow_bits,
        server_pubkey,
        admin_token,
        _handle: handle,
    }
}

/// Triggers a single federation pull cycle synchronously, for tests
/// that need deterministic ordering instead of waiting on the
/// background worker. Returns the per-cycle stats so callers can
/// assert on accept/reject counts.
pub async fn pull_once(server: &TestServer) -> lethe_server::federation::pull::PullStats {
    use lethe_server::{federation::Identity, moderation::classifier::NoopClassifier};
    let identity = Identity::load_or_create(&server.db).await.expect("identity");
    let classifier = NoopClassifier;
    lethe_server::federation::pull::run_once(&server.db, &identity, &classifier)
        .await
        .expect("pull run")
}

async fn create_db(name: &str) {
    let admin: PgPool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(std::time::Duration::from_secs(60))
        .connect(ADMIN_DATABASE_URL)
        .await
        .expect("admin connect");
    sqlx::query(&format!("CREATE DATABASE \"{name}\""))
        .execute(&admin)
        .await
        .expect("create db");
    // Close eagerly so we don't sit on the connection while many tests
    // share a single Postgres instance.
    admin.close().await;
}
