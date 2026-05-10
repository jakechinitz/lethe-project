//! Reads/writes for post-facto post takedowns.
//!
//! A removal substitutes the body with a tombstone in the read path
//! without deleting the row — this keeps per-thread `seq` continuity
//! and the per-thread author signature chain intact for posts after
//! the removed one.

use sqlx::PgPool;
use time::Date;

#[derive(Debug, Clone, Copy)]
pub enum Scope {
    Local,
    Global,
}

impl Scope {
    fn as_str(self) -> &'static str {
        match self {
            Scope::Local => "local",
            Scope::Global => "global",
        }
    }
}

pub struct NewRemoval<'a> {
    pub post_id: &'a [u8],
    pub reason: &'a str,
    pub scope: Scope,
    pub origin_server_id: Option<&'a [u8]>,
    pub origin_signature: Option<&'a [u8]>,
    pub removed_at: Date,
}

/// Inserts a removal. Idempotent: a second call for the same post id
/// is a no-op (the existing row wins).
pub async fn insert(db: &PgPool, r: NewRemoval<'_>) -> Result<bool, sqlx::Error> {
    let res = sqlx::query(
        "INSERT INTO post_removals
            (post_id, reason, scope, origin_server_id, origin_signature, removed_at)
         VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (post_id) DO NOTHING",
    )
    .bind(r.post_id)
    .bind(r.reason)
    .bind(r.scope.as_str())
    .bind(r.origin_server_id)
    .bind(r.origin_signature)
    .bind(r.removed_at)
    .execute(db)
    .await?;
    Ok(res.rows_affected() > 0)
}

pub async fn is_removed(db: &PgPool, post_id: &[u8]) -> Result<bool, sqlx::Error> {
    let row: Option<(i32,)> = sqlx::query_as("SELECT 1 FROM post_removals WHERE post_id = $1")
        .bind(post_id)
        .fetch_optional(db)
        .await?;
    Ok(row.is_some())
}

#[derive(Debug)]
pub struct RemovalRow {
    pub post_id: Vec<u8>,
    pub reason: String,
    pub scope: String,
    pub removed_at: Date,
    pub origin_server_id: Option<Vec<u8>>,
    pub origin_signature: Option<Vec<u8>>,
}

type RemovalRowTuple = (Vec<u8>, String, String, Date, Option<Vec<u8>>, Option<Vec<u8>>);

/// Returns globally-scoped removals for posts the given server originated.
/// Used by `/api/federation/events` so peers can re-apply the takedown.
pub async fn list_global_for_origin(
    db: &PgPool,
    origin_server_id: &[u8],
    cursor: Option<(Date, Vec<u8>)>,
    limit: i64,
) -> Result<Vec<RemovalRow>, sqlx::Error> {
    let rows: Vec<RemovalRowTuple> = match cursor {
            None => sqlx::query_as(
                "SELECT pr.post_id, pr.reason, pr.scope, pr.removed_at,
                        pr.origin_server_id, pr.origin_signature
                 FROM post_removals pr
                 JOIN posts p ON p.id = pr.post_id
                 WHERE pr.scope = 'global'
                   AND p.origin_server_id = $1
                 ORDER BY pr.removed_at ASC, pr.post_id ASC
                 LIMIT $2",
            )
            .bind(origin_server_id)
            .bind(limit)
            .fetch_all(db)
            .await?,
            Some((d, id)) => sqlx::query_as(
                "SELECT pr.post_id, pr.reason, pr.scope, pr.removed_at,
                        pr.origin_server_id, pr.origin_signature
                 FROM post_removals pr
                 JOIN posts p ON p.id = pr.post_id
                 WHERE pr.scope = 'global'
                   AND p.origin_server_id = $1
                   AND (pr.removed_at, pr.post_id) > ($2, $3)
                 ORDER BY pr.removed_at ASC, pr.post_id ASC
                 LIMIT $4",
            )
            .bind(origin_server_id)
            .bind(d)
            .bind(id)
            .bind(limit)
            .fetch_all(db)
            .await?,
        };
    Ok(rows
        .into_iter()
        .map(
            |(post_id, reason, scope, removed_at, origin_server_id, origin_signature)| RemovalRow {
                post_id,
                reason,
                scope,
                removed_at,
                origin_server_id,
                origin_signature,
            },
        )
        .collect())
}
