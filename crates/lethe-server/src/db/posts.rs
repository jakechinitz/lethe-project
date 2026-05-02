//! Post reads/writes. `seq` is per-thread monotonic, assigned on insert.

use crate::ids;
use lethe_types::{posts::PostView, CoarseTime};
use sqlx::PgPool;
use time::OffsetDateTime;

pub struct NewPost<'a> {
    pub thread_id: &'a [u8],
    pub body: &'a str,
    pub pow_nonce: &'a [u8],
    pub pubkey: Option<&'a [u8]>,
    pub signature: Option<&'a [u8]>,
    pub created_at: OffsetDateTime,
}

pub struct Inserted {
    pub post_id: [u8; 16],
    pub seq: i32,
}

/// Inserts a post, bumps the parent thread's activity counters, and
/// returns the assigned sequence number. Both writes happen in one
/// transaction so the feed's `last_post_at` index never observes a stale
/// state where a post exists but the thread hasn't been updated yet.
pub async fn insert(db: &PgPool, p: NewPost<'_>) -> Result<Inserted, sqlx::Error> {
    let post_id = ids::new_ulid();
    let mut tx = db.begin().await?;
    let row: (i32,) = sqlx::query_as(
        "INSERT INTO posts (id, thread_id, seq, body, pow_nonce, pubkey, signature, created_at)
         VALUES (
             $1, $2,
             COALESCE((SELECT MAX(seq) FROM posts WHERE thread_id = $2), 0) + 1,
             $3, $4, $5, $6, $7
         )
         RETURNING seq",
    )
    .bind(post_id)
    .bind(p.thread_id)
    .bind(p.body)
    .bind(p.pow_nonce)
    .bind(p.pubkey)
    .bind(p.signature)
    .bind(p.created_at)
    .fetch_one(&mut *tx)
    .await?;
    sqlx::query(
        "UPDATE threads
         SET last_post_at = GREATEST(last_post_at, $2),
             post_count = post_count + 1
         WHERE id = $1",
    )
    .bind(p.thread_id)
    .bind(p.created_at)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Inserted { post_id, seq: row.0 })
}

/// Earliest `seq` in this thread that the given pubkey signed; `None` if
/// it never signed in this thread.
pub async fn signer_first_seq(
    db: &PgPool,
    thread_id: &[u8],
    pubkey: &[u8],
) -> Result<Option<i32>, sqlx::Error> {
    let row: Option<(i32,)> = sqlx::query_as(
        "SELECT MIN(seq) FROM posts WHERE thread_id = $1 AND pubkey = $2",
    )
    .bind(thread_id)
    .bind(pubkey)
    .fetch_optional(db)
    .await?;
    Ok(row.map(|r| r.0))
}

/// Whether the given pubkey signed at least one post in this thread.
/// Used by the room-provenance verifier.
pub async fn pubkey_signed_in_thread(
    db: &PgPool,
    thread_id: &[u8],
    pubkey: &[u8],
) -> Result<bool, sqlx::Error> {
    let row: Option<(i32,)> = sqlx::query_as(
        "SELECT 1 FROM posts WHERE thread_id = $1 AND pubkey = $2 LIMIT 1",
    )
    .bind(thread_id)
    .bind(pubkey)
    .fetch_optional(db)
    .await?;
    Ok(row.is_some())
}

#[derive(sqlx::FromRow)]
struct PostRow {
    id: Vec<u8>,
    seq: i32,
    body: String,
    created_at: OffsetDateTime,
    pubkey: Option<Vec<u8>>,
}

pub async fn list_in_thread(
    db: &PgPool,
    thread_id: &[u8],
    since_seq: i32,
    limit: i64,
) -> Result<Vec<PostView>, sqlx::Error> {
    let rows: Vec<PostRow> = sqlx::query_as(
        "SELECT id, seq, body, created_at, pubkey
         FROM posts
         WHERE thread_id = $1 AND seq > $2
         ORDER BY seq ASC
         LIMIT $3",
    )
    .bind(thread_id)
    .bind(since_seq)
    .bind(limit)
    .fetch_all(db)
    .await?;

    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        let signer_first_seq = match &r.pubkey {
            Some(pk) => signer_first_seq(db, thread_id, pk).await?,
            None => None,
        };
        out.push(PostView {
            post_id: ids::b64(&r.id),
            seq: r.seq,
            body: r.body,
            created_at: CoarseTime(r.created_at),
            pubkey: r.pubkey.as_ref().map(|p| ids::b64(p)),
            signer_first_seq,
        });
    }
    Ok(out)
}
