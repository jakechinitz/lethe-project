//! Database access layer. All `sqlx` calls live in this module tree.
//!
//! Row structs (`*Row`) MUST NOT leave this module. Routes return DTOs from
//! `lethe-types`; conversion happens in `From` impls right next to the row
//! struct that produces them.

use sqlx::PgPool;

pub mod feed;
pub mod nonces;
pub mod posts;
pub mod retention;
pub mod rooms;
pub mod threads;

pub async fn connect(database_url: &str) -> Result<PgPool, sqlx::Error> {
    connect_with_pool_size(database_url, 8).await
}

pub async fn connect_with_pool_size(
    database_url: &str,
    max_connections: u32,
) -> Result<PgPool, sqlx::Error> {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(max_connections)
        .connect(database_url)
        .await?;
    sqlx::migrate!("./migrations").run(&pool).await?;
    Ok(pool)
}
