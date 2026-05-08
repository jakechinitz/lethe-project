//! Reads/writes for federation: peer list, event-stream queries.
//!
//! The peer list is operator-managed (CLI / admin route). The event-
//! stream queries serve `/api/federation/events`: locally-originated
//! posts and globally-scoped removals, both ordered by
//! `(created_at|removed_at, id)` so peers can resume from a stable
//! cursor. We deliberately do NOT relay-sign third-party events at
//! MVP — peers reach further-hop content by peering with more servers.

use crate::db;
use sqlx::PgPool;
use time::Date;

#[derive(Debug, Clone)]
pub struct Peer {
    pub server_pubkey: Vec<u8>,
    pub endpoint: String,
    pub label: Option<String>,
    pub last_cursor: Option<Vec<u8>>,
    pub enabled: bool,
}

pub async fn upsert_peer(
    pool: &PgPool,
    server_pubkey: &[u8],
    endpoint: &str,
    label: Option<&str>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO federation_peers (server_pubkey, endpoint, label, enabled)
         VALUES ($1, $2, $3, TRUE)
         ON CONFLICT (server_pubkey) DO UPDATE SET
             endpoint = EXCLUDED.endpoint,
             label = EXCLUDED.label,
             enabled = TRUE",
    )
    .bind(server_pubkey)
    .bind(endpoint)
    .bind(label)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn set_enabled(
    pool: &PgPool,
    server_pubkey: &[u8],
    enabled: bool,
) -> Result<bool, sqlx::Error> {
    let res = sqlx::query(
        "UPDATE federation_peers SET enabled = $2 WHERE server_pubkey = $1",
    )
    .bind(server_pubkey)
    .bind(enabled)
    .execute(pool)
    .await?;
    Ok(res.rows_affected() > 0)
}

type PeerRow = (Vec<u8>, String, Option<String>, Option<Vec<u8>>, bool);

pub async fn list_peers(pool: &PgPool) -> Result<Vec<Peer>, sqlx::Error> {
    let rows: Vec<PeerRow> = sqlx::query_as(
        "SELECT server_pubkey, endpoint, label, last_cursor, enabled
         FROM federation_peers
         ORDER BY added_at ASC, server_pubkey ASC",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(pk, ep, label, last_cursor, enabled)| Peer {
            server_pubkey: pk,
            endpoint: ep,
            label,
            last_cursor,
            enabled,
        })
        .collect())
}

pub async fn list_enabled_peers(pool: &PgPool) -> Result<Vec<Peer>, sqlx::Error> {
    let peers = list_peers(pool).await?;
    Ok(peers.into_iter().filter(|p| p.enabled).collect())
}

pub async fn save_cursor(
    pool: &PgPool,
    server_pubkey: &[u8],
    cursor: &[u8],
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE federation_peers
         SET last_cursor = $2, last_pulled_at = now()
         WHERE server_pubkey = $1",
    )
    .bind(server_pubkey)
    .bind(cursor)
    .execute(pool)
    .await?;
    Ok(())
}

#[derive(Debug, Clone)]
pub struct PostStreamRow {
    pub board_id: String,
    pub thread_id: Vec<u8>,
    pub thread_origin_server_id: Option<Vec<u8>>,
    pub thread_title: String,
    pub origin_server_id: Vec<u8>,
    pub origin_post_id: Vec<u8>,
    pub body: String,
    pub created_at: Date,
    pub author_pubkey: Option<Vec<u8>>,
    pub author_signature: Option<Vec<u8>>,
}

type PostStreamTuple = (
    String,
    Vec<u8>,
    Option<Vec<u8>>,
    String,
    Vec<u8>,
    Vec<u8>,
    String,
    Date,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
);

/// Returns posts originated by the given server, in `(created_at, id)`
/// order, after the cursor. The id used for ordering is `posts.id`
/// (the local row id, which equals `origin_post_id` for local rows).
pub async fn list_outgoing_posts(
    pool: &PgPool,
    origin_server_id: &[u8],
    cursor: Option<(Date, Vec<u8>)>,
    limit: i64,
) -> Result<Vec<PostStreamRow>, sqlx::Error> {
    let rows: Vec<PostStreamTuple> = match cursor {
        None => sqlx::query_as(
            "SELECT t.board_id, p.thread_id, t.origin_server_id, t.title,
                    p.origin_server_id, p.origin_post_id, p.body, p.created_at,
                    p.pubkey, p.signature
             FROM posts p
             JOIN threads t ON t.id = p.thread_id
             WHERE p.origin_server_id = $1
             ORDER BY p.created_at ASC, p.id ASC
             LIMIT $2",
        )
        .bind(origin_server_id)
        .bind(limit)
        .fetch_all(pool)
        .await?,
        Some((d, id)) => sqlx::query_as(
            "SELECT t.board_id, p.thread_id, t.origin_server_id, t.title,
                    p.origin_server_id, p.origin_post_id, p.body, p.created_at,
                    p.pubkey, p.signature
             FROM posts p
             JOIN threads t ON t.id = p.thread_id
             WHERE p.origin_server_id = $1
               AND (p.created_at, p.id) > ($2, $3)
             ORDER BY p.created_at ASC, p.id ASC
             LIMIT $4",
        )
        .bind(origin_server_id)
        .bind(d)
        .bind(id)
        .bind(limit)
        .fetch_all(pool)
        .await?,
    };
    Ok(rows
        .into_iter()
        .map(|r| PostStreamRow {
            board_id: r.0,
            thread_id: r.1,
            thread_origin_server_id: r.2,
            thread_title: r.3,
            origin_server_id: r.4,
            origin_post_id: r.5,
            body: r.6,
            created_at: r.7,
            author_pubkey: r.8,
            author_signature: r.9,
        })
        .collect())
}

/// Looks up the local row id for a federated post by `(origin_server_id,
/// origin_post_id)`. Used when applying an incoming `RemovalEvent`.
pub async fn local_id_for_origin(
    pool: &PgPool,
    origin_server_id: &[u8],
    origin_post_id: &[u8],
) -> Result<Option<Vec<u8>>, sqlx::Error> {
    let row: Option<(Vec<u8>,)> = sqlx::query_as(
        "SELECT id FROM posts
         WHERE origin_server_id = $1 AND origin_post_id = $2",
    )
    .bind(origin_server_id)
    .bind(origin_post_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|r| r.0))
}

/// Convenience wrapper around the global-removals stream. Lives here to
/// keep all federation event-stream queries in one place even though
/// the row type lives in `db::post_removals`.
pub async fn list_outgoing_removals(
    pool: &PgPool,
    origin_server_id: &[u8],
    cursor: Option<(Date, Vec<u8>)>,
    limit: i64,
) -> Result<Vec<db::post_removals::RemovalRow>, sqlx::Error> {
    db::post_removals::list_global_for_origin(pool, origin_server_id, cursor, limit).await
}
