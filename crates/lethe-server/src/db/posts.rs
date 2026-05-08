//! Post reads/writes. `seq` is per-thread monotonic, assigned on insert.

use crate::ids;
use lethe_types::{posts::PostView, CoarseDate};
use sqlx::PgPool;
use time::Date;

pub struct NewPost<'a> {
    pub thread_id: &'a [u8],
    pub body: &'a str,
    pub pow_nonce: &'a [u8],
    pub pubkey: Option<&'a [u8]>,
    pub signature: Option<&'a [u8]>,
    pub created_at: Date,
    /// 32-byte Ed25519 pubkey of this server. Federated copies will
    /// carry this same value back when they're pulled by peers.
    pub origin_server_id: &'a [u8],
}

pub struct Inserted {
    pub post_id: [u8; 16],
    pub seq: i32,
}

/// Inserts a locally-authored post, bumps the parent thread's activity
/// counters, and returns the assigned sequence number. Both writes
/// happen in one transaction so the feed's `last_post_at` index never
/// observes a stale state.
///
/// `origin_post_id` is set equal to the freshly-minted local id, so a
/// peer that pulls this post and dedupes on `(origin_server_id,
/// origin_post_id)` is comparing against the same value the origin
/// server used as its primary key.
pub async fn insert(db: &PgPool, p: NewPost<'_>) -> Result<Inserted, sqlx::Error> {
    let post_id = ids::new_id();
    let mut tx = db.begin().await?;
    let row: (i32,) = sqlx::query_as(
        "INSERT INTO posts (id, thread_id, seq, body, pow_nonce, pubkey, signature,
                            created_at, origin_server_id, origin_post_id)
         VALUES (
             $1, $2,
             COALESCE((SELECT MAX(seq) FROM posts WHERE thread_id = $2), 0) + 1,
             $3, $4, $5, $6, $7, $8, $1
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
    .bind(p.origin_server_id)
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

pub struct FederatedPost<'a> {
    pub thread_id: &'a [u8],
    pub body: &'a str,
    pub pubkey: Option<&'a [u8]>,
    pub signature: Option<&'a [u8]>,
    pub created_at: Date,
    pub origin_server_id: &'a [u8],
    pub origin_post_id: &'a [u8],
}

/// Inserts a federated post pulled from a peer. Differences from the
/// local insert: no `pow_nonce` (PoW is meaningless for relayed
/// content), and the seq is computed against whatever rows already
/// exist in the local thread. Idempotent on
/// `(origin_server_id, origin_post_id)` — a duplicate pull is a no-op.
///
/// Caller is responsible for ensuring the thread row exists first
/// (see `db::threads::ensure_for_federation`).
pub async fn insert_federated(
    db: &PgPool,
    p: FederatedPost<'_>,
) -> Result<Option<Inserted>, sqlx::Error> {
    let local_id = ids::new_id();
    let mut tx = db.begin().await?;
    let row: Option<(Vec<u8>, i32)> = sqlx::query_as(
        "INSERT INTO posts (id, thread_id, seq, body, pow_nonce, pubkey, signature,
                            created_at, origin_server_id, origin_post_id)
         VALUES (
             $1, $2,
             COALESCE((SELECT MAX(seq) FROM posts WHERE thread_id = $2), 0) + 1,
             $3, $4, $5, $6, $7, $8, $9
         )
         ON CONFLICT (origin_server_id, origin_post_id)
             WHERE origin_server_id IS NOT NULL AND origin_post_id IS NOT NULL
             DO NOTHING
         RETURNING id, seq",
    )
    .bind(&local_id[..])
    .bind(p.thread_id)
    .bind(p.body)
    .bind(&[] as &[u8])
    .bind(p.pubkey)
    .bind(p.signature)
    .bind(p.created_at)
    .bind(p.origin_server_id)
    .bind(p.origin_post_id)
    .fetch_optional(&mut *tx)
    .await?;

    match row {
        None => {
            tx.rollback().await?;
            Ok(None)
        }
        Some((id_bytes, seq)) => {
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
            let mut id = [0u8; 16];
            id.copy_from_slice(&id_bytes);
            Ok(Some(Inserted { post_id: id, seq }))
        }
    }
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

/// True iff a post with this id exists. Used to validate report targets
/// before inserting.
pub async fn exists(db: &PgPool, post_id: &[u8]) -> Result<bool, sqlx::Error> {
    let row: Option<(i32,)> = sqlx::query_as("SELECT 1 FROM posts WHERE id = $1")
        .bind(post_id)
        .fetch_optional(db)
        .await?;
    Ok(row.is_some())
}

/// Body shown in place of a removed post. The shape stays parsable so
/// clients don't need to special-case removed posts; the prefix is
/// stable enough for a future UI to detect.
pub fn tombstone_body(reason: &str) -> String {
    format!("[removed: {reason}]")
}

#[derive(sqlx::FromRow)]
struct PostRow {
    id: Vec<u8>,
    seq: i32,
    body: String,
    created_at: Date,
    pubkey: Option<Vec<u8>>,
    removal_reason: Option<String>,
    origin_server_id: Option<Vec<u8>>,
    origin_server_label: Option<String>,
}

pub async fn list_in_thread(
    db: &PgPool,
    thread_id: &[u8],
    self_pubkey: &[u8; 32],
    since_seq: i32,
    limit: i64,
) -> Result<Vec<PostView>, sqlx::Error> {
    let rows: Vec<PostRow> = sqlx::query_as(
        "SELECT p.id, p.seq, p.body, p.created_at, p.pubkey,
                pr.reason AS removal_reason,
                p.origin_server_id,
                fp.label AS origin_server_label
         FROM posts p
         LEFT JOIN post_removals pr ON pr.post_id = p.id
         LEFT JOIN federation_peers fp ON fp.server_pubkey = p.origin_server_id
         WHERE p.thread_id = $1 AND p.seq > $2
         ORDER BY p.seq ASC
         LIMIT $3",
    )
    .bind(thread_id)
    .bind(since_seq)
    .bind(limit)
    .fetch_all(db)
    .await?;

    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        let removed = r.removal_reason.is_some();
        let body = match &r.removal_reason {
            Some(reason) => tombstone_body(reason),
            None => r.body,
        };
        let pubkey = if removed { None } else { r.pubkey };
        let signer_first_seq = match &pubkey {
            Some(pk) => signer_first_seq(db, thread_id, pk).await?,
            None => None,
        };
        // Hide origin labels for posts originated on this server —
        // unfederated reads stay clean. A federated copy from a
        // labelled peer surfaces the label so the client can render
        // "from <peer>".
        let local = r
            .origin_server_id
            .as_deref()
            .map(|o| o == &self_pubkey[..])
            .unwrap_or(true);
        let origin_server_id = if local {
            None
        } else {
            r.origin_server_id.as_ref().map(|o| ids::b64(o))
        };
        let origin_server_label = if local { None } else { r.origin_server_label };
        out.push(PostView {
            post_id: ids::b64(&r.id),
            seq: r.seq,
            body,
            created_at: CoarseDate(r.created_at),
            pubkey: pubkey.as_ref().map(|p| ids::b64(p)),
            signer_first_seq,
            origin_server_id,
            origin_server_label,
        });
    }
    Ok(out)
}
