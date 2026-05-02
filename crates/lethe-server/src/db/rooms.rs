//! Room reads/writes. The server stores opaque ciphertext only.

use crate::ids;
use lethe_types::{rooms::*, CoarseTime};
use sqlx::PgPool;
use time::OffsetDateTime;

pub struct NewRoom<'a> {
    pub origin_thread: Option<&'a [u8]>,
    pub invite_code: &'a str,
    pub creator_box_pubkey: &'a [u8],
    pub creator_sig_pubkey: &'a [u8],
    pub wrapped_key_for_creator: &'a [u8],
    pub creator_thread_pubkey: Option<&'a [u8]>,
    pub provenance_sig: Option<&'a [u8]>,
    pub created_at: OffsetDateTime,
}

/// Inserts a `rooms` row plus the creator's `room_members` row in one
/// transaction.
pub async fn create(db: &PgPool, r: NewRoom<'_>) -> Result<[u8; 16], sqlx::Error> {
    let room_id = ids::new_ulid();
    let mut tx = db.begin().await?;
    sqlx::query(
        "INSERT INTO rooms
            (id, origin_thread, invite_code, created_at,
             creator_thread_pubkey, provenance_sig)
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(&room_id[..])
    .bind(r.origin_thread)
    .bind(r.invite_code)
    .bind(r.created_at)
    .bind(r.creator_thread_pubkey)
    .bind(r.provenance_sig)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO room_members
            (room_id, member_box_pubkey, member_sig_pubkey,
             wrapped_key, joined_at, invited_by_box_pubkey)
         VALUES ($1, $2, $3, $4, $5, NULL)",
    )
    .bind(&room_id[..])
    .bind(r.creator_box_pubkey)
    .bind(r.creator_sig_pubkey)
    .bind(r.wrapped_key_for_creator)
    .bind(r.created_at)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(room_id)
}

#[derive(Debug)]
pub struct RoomMeta {
    pub id: Vec<u8>,
    pub origin_thread: Option<Vec<u8>>,
    pub creator_thread_pubkey: Option<Vec<u8>>,
    pub provenance_sig: Option<Vec<u8>>,
    pub created_at: OffsetDateTime,
}

type RoomMetaTuple = (
    Vec<u8>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    OffsetDateTime,
);

fn meta_from_tuple(t: RoomMetaTuple) -> RoomMeta {
    let (id, origin_thread, creator_thread_pubkey, provenance_sig, created_at) = t;
    RoomMeta { id, origin_thread, creator_thread_pubkey, provenance_sig, created_at }
}

pub async fn meta_by_id(db: &PgPool, id: &[u8]) -> Result<Option<RoomMeta>, sqlx::Error> {
    let row: Option<RoomMetaTuple> = sqlx::query_as(
        "SELECT id, origin_thread, creator_thread_pubkey, provenance_sig, created_at
         FROM rooms WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(db)
    .await?;
    Ok(row.map(meta_from_tuple))
}

pub async fn meta_by_invite(db: &PgPool, code: &str) -> Result<Option<RoomMeta>, sqlx::Error> {
    let row: Option<RoomMetaTuple> = sqlx::query_as(
        "SELECT id, origin_thread, creator_thread_pubkey, provenance_sig, created_at
         FROM rooms WHERE invite_code = $1",
    )
    .bind(code)
    .fetch_optional(db)
    .await?;
    Ok(row.map(meta_from_tuple))
}

pub async fn add_member(
    db: &PgPool,
    room_id: &[u8],
    box_pubkey: &[u8],
    sig_pubkey: &[u8],
    joined_at: OffsetDateTime,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO room_members
            (room_id, member_box_pubkey, member_sig_pubkey, wrapped_key, joined_at)
         VALUES ($1, $2, $3, NULL, $4)
         ON CONFLICT (room_id, member_box_pubkey) DO NOTHING",
    )
    .bind(room_id)
    .bind(box_pubkey)
    .bind(sig_pubkey)
    .bind(joined_at)
    .execute(db)
    .await?;
    Ok(())
}

/// Stores a wrapped room key for a pending member and records who invited
/// them (the inviter must already be a member of this room).
pub async fn grant_wrap(
    db: &PgPool,
    room_id: &[u8],
    for_box_pubkey: &[u8],
    wrapped_key: &[u8],
    inviter_box_pubkey: &[u8],
) -> Result<bool, sqlx::Error> {
    let res = sqlx::query(
        "UPDATE room_members
         SET wrapped_key = $3,
             invited_by_box_pubkey = $4,
             verification_state = 'continuity'
         WHERE room_id = $1
           AND member_box_pubkey = $2
           AND wrapped_key IS NULL
           AND EXISTS (
               SELECT 1 FROM room_members
                WHERE room_id = $1 AND member_box_pubkey = $4
           )",
    )
    .bind(room_id)
    .bind(for_box_pubkey)
    .bind(wrapped_key)
    .bind(inviter_box_pubkey)
    .execute(db)
    .await?;
    Ok(res.rows_affected() == 1)
}

pub async fn is_member(
    db: &PgPool,
    room_id: &[u8],
    sig_pubkey: &[u8],
) -> Result<bool, sqlx::Error> {
    let row: Option<(i32,)> = sqlx::query_as(
        "SELECT 1 FROM room_members
         WHERE room_id = $1 AND member_sig_pubkey = $2",
    )
    .bind(room_id)
    .bind(sig_pubkey)
    .fetch_optional(db)
    .await?;
    Ok(row.is_some())
}

/// Returns the joined_at timestamp of a member identified by their sig
/// pubkey. `None` if not a member of this room.
pub async fn joined_at_for_sig_member(
    db: &PgPool,
    room_id: &[u8],
    sig_pubkey: &[u8],
) -> Result<Option<OffsetDateTime>, sqlx::Error> {
    let row: Option<(OffsetDateTime,)> = sqlx::query_as(
        "SELECT joined_at FROM room_members
         WHERE room_id = $1 AND member_sig_pubkey = $2",
    )
    .bind(room_id)
    .bind(sig_pubkey)
    .fetch_optional(db)
    .await?;
    Ok(row.map(|r| r.0))
}

pub async fn is_member_by_box(
    db: &PgPool,
    room_id: &[u8],
    box_pubkey: &[u8],
) -> Result<bool, sqlx::Error> {
    let row: Option<(i32,)> = sqlx::query_as(
        "SELECT 1 FROM room_members
         WHERE room_id = $1 AND member_box_pubkey = $2",
    )
    .bind(room_id)
    .bind(box_pubkey)
    .fetch_optional(db)
    .await?;
    Ok(row.is_some())
}

#[derive(sqlx::FromRow)]
struct MemberRow {
    member_box_pubkey: Vec<u8>,
    member_sig_pubkey: Vec<u8>,
    wrapped_key: Option<Vec<u8>>,
    joined_at: OffsetDateTime,
    invited_by_box_pubkey: Option<Vec<u8>>,
}

pub async fn list_members(db: &PgPool, room_id: &[u8]) -> Result<Vec<MemberView>, sqlx::Error> {
    let rows: Vec<MemberRow> = sqlx::query_as(
        "SELECT member_box_pubkey, member_sig_pubkey, wrapped_key, joined_at,
                invited_by_box_pubkey
         FROM room_members
         WHERE room_id = $1
         ORDER BY joined_at ASC",
    )
    .bind(room_id)
    .fetch_all(db)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| MemberView {
            box_pubkey: ids::b64(&r.member_box_pubkey),
            sig_pubkey: ids::b64(&r.member_sig_pubkey),
            wrapped_key: r.wrapped_key.as_ref().map(|k| ids::b64(k)),
            joined_at: CoarseTime(r.joined_at),
            invited_by_box_pubkey: r.invited_by_box_pubkey.as_ref().map(|k| ids::b64(k)),
        })
        .collect())
}

pub struct NewMessage<'a> {
    pub room_id: &'a [u8],
    pub sender_sig_pubkey: &'a [u8],
    pub nonce: &'a [u8],
    pub ciphertext: &'a [u8],
    pub sender_sig: &'a [u8],
    pub created_at: OffsetDateTime,
}

pub async fn insert_message(db: &PgPool, m: NewMessage<'_>) -> Result<[u8; 16], sqlx::Error> {
    let id = ids::new_ulid();
    sqlx::query(
        "INSERT INTO room_messages
            (id, room_id, sender_sig_pubkey, nonce, ciphertext, sender_sig, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(&id[..])
    .bind(m.room_id)
    .bind(m.sender_sig_pubkey)
    .bind(m.nonce)
    .bind(m.ciphertext)
    .bind(m.sender_sig)
    .bind(m.created_at)
    .execute(db)
    .await?;
    Ok(id)
}

#[derive(sqlx::FromRow)]
struct MessageRow {
    id: Vec<u8>,
    sender_sig_pubkey: Vec<u8>,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
    sender_sig: Vec<u8>,
    created_at: OffsetDateTime,
}

/// Lists messages visible to a member, applying the history gate
/// (`created_at >= joined_at`). The caller must have already verified the
/// requester is a member of this room.
pub async fn list_messages_for_member(
    db: &PgPool,
    room_id: &[u8],
    member_joined_at: OffsetDateTime,
    since: Option<&[u8]>,
    limit: i64,
) -> Result<Vec<MessageView>, sqlx::Error> {
    let rows: Vec<MessageRow> = match since {
        Some(s) => sqlx::query_as(
            "SELECT id, sender_sig_pubkey, nonce, ciphertext, sender_sig, created_at
             FROM room_messages
             WHERE room_id = $1 AND created_at >= $2 AND id > $3
             ORDER BY id ASC LIMIT $4",
        )
        .bind(room_id)
        .bind(member_joined_at)
        .bind(s)
        .bind(limit)
        .fetch_all(db)
        .await?,
        None => sqlx::query_as(
            "SELECT id, sender_sig_pubkey, nonce, ciphertext, sender_sig, created_at
             FROM room_messages
             WHERE room_id = $1 AND created_at >= $2
             ORDER BY id ASC LIMIT $3",
        )
        .bind(room_id)
        .bind(member_joined_at)
        .bind(limit)
        .fetch_all(db)
        .await?,
    };
    Ok(rows
        .into_iter()
        .map(|r| MessageView {
            message_id: ids::b64(&r.id),
            sender_sig_pubkey: ids::b64(&r.sender_sig_pubkey),
            nonce: ids::b64(&r.nonce),
            ciphertext: ids::b64(&r.ciphertext),
            sender_sig: ids::b64(&r.sender_sig),
            created_at: CoarseTime(r.created_at),
        })
        .collect())
}
