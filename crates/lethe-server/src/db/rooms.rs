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
    /// Optional invitee allowlist. `None` = open, `Some(vec)` = restricted.
    pub allowlist_thread_pubkeys: Option<&'a [Vec<u8>]>,
}

/// Inserts a `rooms` row plus the creator's `room_members` row in one
/// transaction.
pub async fn create(db: &PgPool, r: NewRoom<'_>) -> Result<[u8; 16], sqlx::Error> {
    let room_id = ids::new_ulid();
    let mut tx = db.begin().await?;
    sqlx::query(
        "INSERT INTO rooms
            (id, origin_thread, invite_code, created_at,
             creator_thread_pubkey, provenance_sig,
             allowlist_thread_pubkeys)
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(&room_id[..])
    .bind(r.origin_thread)
    .bind(r.invite_code)
    .bind(r.created_at)
    .bind(r.creator_thread_pubkey)
    .bind(r.provenance_sig)
    .bind(r.allowlist_thread_pubkeys)
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
    pub allowlist_thread_pubkeys: Option<Vec<Vec<u8>>>,
}

type RoomMetaTuple = (
    Vec<u8>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    OffsetDateTime,
    Option<Vec<Vec<u8>>>,
);

fn meta_from_tuple(t: RoomMetaTuple) -> RoomMeta {
    let (id, origin_thread, creator_thread_pubkey, provenance_sig, created_at, allowlist) = t;
    RoomMeta {
        id,
        origin_thread,
        creator_thread_pubkey,
        provenance_sig,
        created_at,
        allowlist_thread_pubkeys: allowlist,
    }
}

pub async fn meta_by_id(db: &PgPool, id: &[u8]) -> Result<Option<RoomMeta>, sqlx::Error> {
    let row: Option<RoomMetaTuple> = sqlx::query_as(
        "SELECT id, origin_thread, creator_thread_pubkey, provenance_sig, created_at,
                allowlist_thread_pubkeys
         FROM rooms WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(db)
    .await?;
    Ok(row.map(meta_from_tuple))
}

pub async fn meta_by_invite(db: &PgPool, code: &str) -> Result<Option<RoomMeta>, sqlx::Error> {
    let row: Option<RoomMetaTuple> = sqlx::query_as(
        "SELECT id, origin_thread, creator_thread_pubkey, provenance_sig, created_at,
                allowlist_thread_pubkeys
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

/// Soft-removes a member by sig pubkey. Returns true iff a row was
/// flipped from active → removed.
pub async fn soft_remove_by_sig(
    db: &PgPool,
    room_id: &[u8],
    sig_pubkey: &[u8],
    now: OffsetDateTime,
) -> Result<bool, sqlx::Error> {
    let res = sqlx::query(
        "UPDATE room_members
         SET removed_at = $3
         WHERE room_id = $1
           AND member_sig_pubkey = $2
           AND removed_at IS NULL",
    )
    .bind(room_id)
    .bind(sig_pubkey)
    .bind(now)
    .execute(db)
    .await?;
    Ok(res.rows_affected() == 1)
}

pub async fn active_member_count(
    db: &PgPool,
    room_id: &[u8],
) -> Result<i64, sqlx::Error> {
    let row: (i64,) = sqlx::query_as(
        "SELECT count(*) FROM room_members
         WHERE room_id = $1 AND removed_at IS NULL",
    )
    .bind(room_id)
    .fetch_one(db)
    .await?;
    Ok(row.0)
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
         WHERE room_id = $1
           AND member_sig_pubkey = $2
           AND removed_at IS NULL",
    )
    .bind(room_id)
    .bind(sig_pubkey)
    .fetch_optional(db)
    .await?;
    Ok(row.is_some())
}

/// True iff `sig_pubkey` is the creator of this room (the only member
/// without an inviter). Removed creators are still considered creator
/// for this check — they're the only authority that can re-issue keys.
pub async fn is_creator_by_sig(
    db: &PgPool,
    room_id: &[u8],
    sig_pubkey: &[u8],
) -> Result<bool, sqlx::Error> {
    let row: Option<(i32,)> = sqlx::query_as(
        "SELECT 1 FROM room_members
         WHERE room_id = $1
           AND member_sig_pubkey = $2
           AND invited_by_box_pubkey IS NULL
           AND removed_at IS NULL",
    )
    .bind(room_id)
    .bind(sig_pubkey)
    .fetch_optional(db)
    .await?;
    Ok(row.is_some())
}

/// Returns the joined_at timestamp of a still-active member identified
/// by their sig pubkey. `None` if not a member of this room or if
/// removed.
pub async fn joined_at_for_sig_member(
    db: &PgPool,
    room_id: &[u8],
    sig_pubkey: &[u8],
) -> Result<Option<OffsetDateTime>, sqlx::Error> {
    let row: Option<(OffsetDateTime,)> = sqlx::query_as(
        "SELECT joined_at FROM room_members
         WHERE room_id = $1
           AND member_sig_pubkey = $2
           AND removed_at IS NULL",
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
         WHERE room_id = $1
           AND member_box_pubkey = $2
           AND removed_at IS NULL",
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
    removed_at: Option<OffsetDateTime>,
}

pub async fn list_members(db: &PgPool, room_id: &[u8]) -> Result<Vec<MemberView>, sqlx::Error> {
    let rows: Vec<MemberRow> = sqlx::query_as(
        "SELECT member_box_pubkey, member_sig_pubkey, wrapped_key, joined_at,
                invited_by_box_pubkey, removed_at
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
            removed_at: r.removed_at.map(CoarseTime),
        })
        .collect())
}

pub async fn current_epoch(db: &PgPool, room_id: &[u8]) -> Result<i32, sqlx::Error> {
    let row: (i32,) = sqlx::query_as("SELECT current_epoch FROM rooms WHERE id = $1")
        .bind(room_id)
        .fetch_one(db)
        .await?;
    Ok(row.0)
}

/// Soft-removes a member, bumps the room's epoch, and overwrites the
/// `wrapped_key` of every still-active member with the new wrap supplied
/// by the caller. All in one transaction so observers either see the
/// pre-rekey state or the fully-rotated state, never a half-applied one.
///
/// Returns the new epoch. Errors:
///   - `target` is not a current member of the room
///   - any `for_box_pubkey` in `wraps` is not a current non-target member
///   - the set of `wraps` does not exactly match the surviving member set
pub async fn remove_and_rekey(
    db: &PgPool,
    room_id: &[u8],
    target_box_pubkey: &[u8],
    wraps: &[(Vec<u8>, Vec<u8>)],
    now: OffsetDateTime,
) -> Result<i32, sqlx::Error> {
    let mut tx = db.begin().await?;

    // 1. Soft-remove the target. Must currently be active.
    let res = sqlx::query(
        "UPDATE room_members
         SET removed_at = $3
         WHERE room_id = $1
           AND member_box_pubkey = $2
           AND removed_at IS NULL",
    )
    .bind(room_id)
    .bind(target_box_pubkey)
    .bind(now)
    .execute(&mut *tx)
    .await?;
    if res.rows_affected() != 1 {
        return Err(sqlx::Error::RowNotFound);
    }

    // 2. Snapshot of surviving members. Used to check the wraps cover
    //    every remaining member exactly.
    let survivors: Vec<(Vec<u8>,)> = sqlx::query_as(
        "SELECT member_box_pubkey FROM room_members
         WHERE room_id = $1 AND removed_at IS NULL",
    )
    .bind(room_id)
    .fetch_all(&mut *tx)
    .await?;

    if survivors.len() != wraps.len() {
        return Err(sqlx::Error::Protocol(
            "wrap count mismatch with surviving member count".into(),
        ));
    }
    let survivor_set: std::collections::HashSet<&[u8]> =
        survivors.iter().map(|(k,)| k.as_slice()).collect();
    for (pk, _) in wraps {
        if !survivor_set.contains(pk.as_slice()) {
            return Err(sqlx::Error::Protocol(
                "wrap target is not a surviving member".into(),
            ));
        }
    }

    // 3. Apply each new wrap.
    for (for_box, new_wrapped) in wraps {
        sqlx::query(
            "UPDATE room_members
             SET wrapped_key = $3
             WHERE room_id = $1
               AND member_box_pubkey = $2
               AND removed_at IS NULL",
        )
        .bind(room_id)
        .bind(for_box)
        .bind(new_wrapped)
        .execute(&mut *tx)
        .await?;
    }

    // 4. Bump the epoch.
    let row: (i32,) = sqlx::query_as(
        "UPDATE rooms SET current_epoch = current_epoch + 1
         WHERE id = $1
         RETURNING current_epoch",
    )
    .bind(room_id)
    .fetch_one(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(row.0)
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
