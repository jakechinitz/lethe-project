//! Front-page feed: a flat list of threads across boards, optionally
//! filtered to a single category, sortable by latest activity or by
//! creation time. Cursor-paginated by `(sort-key, thread_id)`.
//!
//! The sort key is a `DATE`, so within a single day the feed orders by
//! id (and ids are random — see `ids::new_id`). That gives a stable
//! pagination tie-break without leaking sub-day timing.

use crate::ids;
use lethe_types::{feed::*, CoarseDate};
use sqlx::PgPool;
use time::Date;

/// Boards visible in the front-page feed. The legacy `general` board is
/// reachable directly via `/b/general` but excluded from the new tabs.
pub const FEED_BOARDS: &[&str] = &["government", "economy", "science_tech", "all_other"];

#[derive(sqlx::FromRow)]
struct FeedRow {
    id: Vec<u8>,
    board_id: String,
    title: String,
    created_at: Date,
    last_post_at: Date,
    post_count: i32,
}

impl From<FeedRow> for FeedItem {
    fn from(r: FeedRow) -> Self {
        FeedItem {
            thread_id: ids::b64(&r.id),
            board_id: r.board_id,
            title: r.title,
            created_at: CoarseDate(r.created_at),
            last_post_at: CoarseDate(r.last_post_at),
            post_count: r.post_count,
        }
    }
}

pub async fn list(
    db: &PgPool,
    category: Option<&str>,
    sort: FeedSort,
    cursor: Option<FeedCursor>,
    limit: i64,
) -> Result<Vec<FeedItem>, sqlx::Error> {
    let boards: &[&str] = match category {
        Some(c) if FEED_BOARDS.contains(&c) => std::slice::from_ref(
            FEED_BOARDS.iter().find(|&&b| b == c).unwrap(),
        ),
        Some(_) => return Ok(Vec::new()), // unknown category
        None => FEED_BOARDS,
    };

    // sqlx PG can take &[&str] via ANY($n).
    let rows: Vec<FeedRow> = match (sort, cursor) {
        (FeedSort::LastComment, None) => sqlx::query_as(
            "SELECT id, board_id, title, created_at, last_post_at, post_count
             FROM threads
             WHERE board_id = ANY($1)
             ORDER BY last_post_at DESC, id DESC
             LIMIT $2",
        )
        .bind(boards)
        .bind(limit)
        .fetch_all(db)
        .await?,
        (FeedSort::LastComment, Some(c)) => sqlx::query_as(
            "SELECT id, board_id, title, created_at, last_post_at, post_count
             FROM threads
             WHERE board_id = ANY($1)
               AND (last_post_at, id) < ($2, $3)
             ORDER BY last_post_at DESC, id DESC
             LIMIT $4",
        )
        .bind(boards)
        .bind(c.sort_value)
        .bind(c.thread_id)
        .bind(limit)
        .fetch_all(db)
        .await?,
        (FeedSort::Newest, None) => sqlx::query_as(
            "SELECT id, board_id, title, created_at, last_post_at, post_count
             FROM threads
             WHERE board_id = ANY($1)
             ORDER BY created_at DESC, id DESC
             LIMIT $2",
        )
        .bind(boards)
        .bind(limit)
        .fetch_all(db)
        .await?,
        (FeedSort::Newest, Some(c)) => sqlx::query_as(
            "SELECT id, board_id, title, created_at, last_post_at, post_count
             FROM threads
             WHERE board_id = ANY($1)
               AND (created_at, id) < ($2, $3)
             ORDER BY created_at DESC, id DESC
             LIMIT $4",
        )
        .bind(boards)
        .bind(c.sort_value)
        .bind(c.thread_id)
        .bind(limit)
        .fetch_all(db)
        .await?,
    };

    Ok(rows.into_iter().map(Into::into).collect())
}

pub struct FeedCursor {
    pub sort_value: Date,
    pub thread_id: Vec<u8>,
}
