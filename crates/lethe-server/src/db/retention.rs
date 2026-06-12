//! Retention queries: delete public threads and private-room messages
//! per the board / room / thread retention policy.
//!
//! Returns counts only; never logs which rows were deleted.
//!
//! Threads are deleted when EITHER:
//!   * the author-set `threads.expires_at` has arrived
//!     (`expires_at <= current_date`), or
//!   * the board has a non-NULL `retention_days` and the thread is
//!     older than `current_date - retention_days`.
//!
//! `boards.retention_days IS NULL` (the default since migration 0017)
//! means board-wide pruning is off and threads persist until their own
//! `expires_at`, if any. The SQL needs no special-casing: comparing
//! against `current_date - NULL` is NULL, which is not TRUE, so the
//! row survives.
//!
//! Cutoffs are exact at day granularity, matching the DATE columns
//! they filter on. A row from yesterday with `retention_days = 0` is
//! deleted; one from today is kept.

use sqlx::PgPool;
use time::Duration;

#[derive(Debug, Default, Clone, Copy)]
pub struct RetentionStats {
    pub threads_deleted: u64,
    pub room_messages_deleted: u64,
    pub request_nonces_deleted: u64,
}

pub async fn run_once(db: &PgPool) -> Result<RetentionStats, sqlx::Error> {
    let mut stats = RetentionStats::default();

    // Threads (with their posts cascading via FK). Author-set expiry
    // OR board-level retention, whichever applies; NULL board
    // retention disables the second arm entirely.
    let res = sqlx::query(
        "DELETE FROM threads
         WHERE (expires_at IS NOT NULL AND expires_at <= current_date)
            OR created_at <
               current_date - (
                   SELECT retention_days
                     FROM boards WHERE id = threads.board_id
               )",
    )
    .execute(db)
    .await?;
    stats.threads_deleted = res.rows_affected();

    // Room messages (rooms themselves persist; only old ciphertext is pruned).
    let res = sqlx::query(
        "DELETE FROM room_messages
         WHERE created_at <
            current_date - (
                SELECT message_retention_days
                  FROM rooms WHERE id = room_messages.room_id
            )",
    )
    .execute(db)
    .await?;
    stats.room_messages_deleted = res.rows_affected();

    // Replay-protection nonces older than the freshness window are
    // useless; the handlers reject any ts beyond ±60 s anyway. We keep
    // a generous buffer so a tiny clock skew doesn't risk a false "fresh"
    // for a nonce we already pruned.
    stats.request_nonces_deleted =
        super::nonces::prune_older_than(db, time::Duration::seconds(600)).await?;

    Ok(stats)
}

/// Smallest sleep allowed between retention sweeps. Stops a misconfigured
/// caller from busy-looping the DB.
pub fn min_interval() -> Duration {
    Duration::seconds(60)
}
