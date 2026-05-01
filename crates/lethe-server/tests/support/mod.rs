//! Shared test helpers: in-process server bring-up, browser-side crypto
//! mimicked via `dryoc` (libsodium-compatible), PoW solver.

#![allow(dead_code)]

pub mod browser;

use lethe_server::{config::Config, db, router, state::AppState};
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
    };
    let pool = db::connect(&cfg.database_url).await.expect("db connect");
    let state = AppState { db: pool.clone(), cfg };
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
        _handle: handle,
    }
}

async fn create_db(name: &str) {
    let admin: PgPool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(ADMIN_DATABASE_URL)
        .await
        .expect("admin connect");
    sqlx::query(&format!("CREATE DATABASE \"{name}\""))
        .execute(&admin)
        .await
        .expect("create db");
}
