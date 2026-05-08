//! Moderation log writes + reads.

use crate::ids;
use sqlx::PgPool;
use time::Date;

pub async fn insert(
    db: &PgPool,
    board_id: Option<&str>,
    body_hash: &[u8],
    reason: &str,
) -> Result<(), sqlx::Error> {
    let id = ids::new_id();
    sqlx::query(
        "INSERT INTO moderation_actions (id, board_id, body_hash, reason)
         VALUES ($1, $2, $3, $4)",
    )
    .bind(&id[..])
    .bind(board_id)
    .bind(body_hash)
    .bind(reason)
    .execute(db)
    .await?;
    Ok(())
}

#[derive(Debug)]
pub struct LogEntry {
    pub id: Vec<u8>,
    pub board_id: Option<String>,
    pub body_hash: Vec<u8>,
    pub reason: String,
    pub decided_at: Date,
}

type LogTuple = (Vec<u8>, Option<String>, Vec<u8>, String, Date);

pub async fn list_recent(
    db: &PgPool,
    limit: i64,
    cursor: Option<(Date, Vec<u8>)>,
) -> Result<Vec<LogEntry>, sqlx::Error> {
    let rows: Vec<LogTuple> = match cursor {
        None => sqlx::query_as(
            "SELECT id, board_id, body_hash, reason, decided_at
             FROM moderation_actions
             ORDER BY decided_at DESC, id DESC
             LIMIT $1",
        )
        .bind(limit)
        .fetch_all(db)
        .await?,
        Some((ts, id)) => sqlx::query_as(
            "SELECT id, board_id, body_hash, reason, decided_at
             FROM moderation_actions
             WHERE (decided_at, id) < ($1, $2)
             ORDER BY decided_at DESC, id DESC
             LIMIT $3",
        )
        .bind(ts)
        .bind(id)
        .bind(limit)
        .fetch_all(db)
        .await?,
    };

    Ok(rows
        .into_iter()
        .map(|(id, board_id, body_hash, reason, decided_at)| LogEntry {
            id,
            board_id,
            body_hash,
            reason,
            decided_at,
        })
        .collect())
}
