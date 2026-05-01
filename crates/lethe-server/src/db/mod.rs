//! Database access layer. All `sqlx` calls live in this module tree.
//!
//! Row structs (`*Row`) MUST NOT leave this module. Routes return DTOs from
//! `lethe-types`; conversion happens in `From` impls right next to the row
//! struct that produces them.

use sqlx::PgPool;

pub mod posts;
pub mod rooms;
pub mod threads;

pub async fn connect(database_url: &str) -> Result<PgPool, sqlx::Error> {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(8)
        .connect(database_url)
        .await?;
    sqlx::migrate!("./migrations").run(&pool).await?;
    Ok(pool)
}
