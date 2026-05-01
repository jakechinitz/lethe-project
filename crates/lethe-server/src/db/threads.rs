//! Thread reads/writes.

use sqlx::PgPool;
use time::OffsetDateTime;

pub async fn create(
    db: &PgPool,
    id: &[u8],
    board_id: &str,
    title: &str,
    created_at: OffsetDateTime,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO threads (id, board_id, title, created_at) VALUES ($1, $2, $3, $4)",
    )
    .bind(id)
    .bind(board_id)
    .bind(title)
    .bind(created_at)
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
        "SELECT id, title FROM threads WHERE board_id = $1 ORDER BY created_at DESC LIMIT $2",
    )
    .bind(board_id)
    .bind(limit)
    .fetch_all(db)
    .await?;
    Ok(rows.into_iter().map(|(id, title)| ThreadListItem { id, title }).collect())
}
