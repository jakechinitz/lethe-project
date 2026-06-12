//! Thread reads/writes.

use sqlx::PgPool;
use time::Date;

pub async fn create(
    db: &PgPool,
    id: &[u8],
    board_id: &str,
    title: &str,
    created_at: Date,
    expires_at: Option<Date>,
    origin_server_id: &[u8],
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO threads (id, board_id, title, created_at, expires_at, origin_server_id)
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(id)
    .bind(board_id)
    .bind(title)
    .bind(created_at)
    .bind(expires_at)
    .bind(origin_server_id)
    .execute(db)
    .await?;
    Ok(())
}

/// Idempotently ensures a federated thread row exists locally. Used by
/// the federation pull worker the first time a peer reports a post in
/// a thread we haven't seen. The thread id is the origin server's
/// thread id (federated copies share that id by design — the same
/// thread on different servers is the same row from the pull worker's
/// perspective).
pub async fn ensure_for_federation(
    db: &PgPool,
    id: &[u8],
    board_id: &str,
    title: &str,
    created_at: Date,
    origin_server_id: &[u8],
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO threads (id, board_id, title, created_at, origin_server_id)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(id)
    .bind(board_id)
    .bind(title)
    .bind(created_at)
    .bind(origin_server_id)
    .execute(db)
    .await?;
    Ok(())
}

pub async fn exists(db: &PgPool, id: &[u8]) -> Result<bool, sqlx::Error> {
    let row: Option<(i32,)> = sqlx::query_as("SELECT 1 FROM threads WHERE id = $1")
        .bind(id)
        .fetch_optional(db)
        .await?;
    Ok(row.is_some())
}

pub async fn board_id_for(db: &PgPool, id: &[u8]) -> Result<Option<String>, sqlx::Error> {
    let row: Option<(String,)> = sqlx::query_as("SELECT board_id FROM threads WHERE id = $1")
        .bind(id)
        .fetch_optional(db)
        .await?;
    Ok(row.map(|r| r.0))
}

pub async fn get_title(db: &PgPool, id: &[u8]) -> Result<Option<String>, sqlx::Error> {
    let row: Option<(String,)> = sqlx::query_as("SELECT title FROM threads WHERE id = $1")
        .bind(id)
        .fetch_optional(db)
        .await?;
    Ok(row.map(|r| r.0))
}

#[derive(Debug)]
pub struct ThreadListItem {
    pub id: Vec<u8>,
    pub title: String,
}

pub async fn list_for_board(
    db: &PgPool,
    board_id: &str,
    limit: i64,
) -> Result<Vec<ThreadListItem>, sqlx::Error> {
    let rows: Vec<(Vec<u8>, String)> = sqlx::query_as(
        "SELECT id, title FROM threads WHERE board_id = $1
         ORDER BY created_at DESC, id DESC LIMIT $2",
    )
    .bind(board_id)
    .bind(limit)
    .fetch_all(db)
    .await?;
    Ok(rows.into_iter().map(|(id, title)| ThreadListItem { id, title }).collect())
}
