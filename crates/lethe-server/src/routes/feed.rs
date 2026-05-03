//! `GET /api/feed?cat=&sort=&cursor_ts=&cursor_id=` — front-page feed.

use crate::{
    db,
    error::{AppError, AppResult},
    ids,
    state::AppState,
};
use axum::{
    extract::{Query, State},
    Json,
};
use lethe_types::feed::*;
use serde::Deserialize;
use time::OffsetDateTime;

const PAGE_LIMIT: i64 = 50;

#[derive(Deserialize)]
pub struct FeedQuery {
    pub cat: Option<String>,
    #[serde(default)]
    pub sort: FeedSort,
    /// Cursor: ISO-8601 timestamp of the last item the client already has,
    /// paired with its thread id. Both must come together.
    pub cursor_ts: Option<String>,
    pub cursor_id: Option<String>,
}

pub async fn get(
    State(state): State<AppState>,
    Query(q): Query<FeedQuery>,
) -> AppResult<Json<FeedResp>> {
    let cursor = match (q.cursor_ts.as_deref(), q.cursor_id.as_deref()) {
        (Some(ts), Some(id)) => {
            let parsed = OffsetDateTime::parse(
                ts,
                &time::format_description::well_known::Iso8601::DEFAULT,
            )
            .map_err(|_| AppError::BadRequest("cursor_ts must be ISO-8601"))?;
            let id = ids::unb64(id).map_err(|_| AppError::BadRequest("cursor_id b64"))?;
            Some(db::feed::FeedCursor { sort_value: parsed, thread_id: id })
        }
        (None, None) => None,
        _ => return Err(AppError::BadRequest("cursor_ts and cursor_id come together")),
    };

    let items =
        db::feed::list(&state.db, q.cat.as_deref(), q.sort, cursor, PAGE_LIMIT).await?;
    Ok(Json(FeedResp {
        items,
        category: q.cat,
        sort: q.sort,
    }))
}
