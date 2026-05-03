//! `POST /api/threads/:thread_id/posts` and `GET .../posts?since_seq=...`

use crate::{error::AppResult, logic, state::AppState};
use axum::{
    extract::{Path, Query, State},
    Json,
};
use lethe_types::posts::{CreatePostReq, CreatePostResp, PostView};
use serde::Deserialize;

pub async fn create(
    State(state): State<AppState>,
    Path(thread_id): Path<String>,
    Json(req): Json<CreatePostReq>,
) -> AppResult<Json<CreatePostResp>> {
    let resp = logic::posts::create_post(
        &state.db,
        state.cfg.default_pow_bits as u32,
        state.classifier.as_ref(),
        &thread_id,
        req,
    )
    .await?;
    Ok(Json(resp))
}

#[derive(Deserialize)]
pub struct ListQuery {
    #[serde(default)]
    pub since_seq: i32,
}

#[derive(serde::Serialize)]
pub struct ListResp {
    pub posts: Vec<PostView>,
}

pub async fn list(
    State(state): State<AppState>,
    Path(thread_id): Path<String>,
    Query(q): Query<ListQuery>,
) -> AppResult<Json<ListResp>> {
    let posts = logic::posts::list_posts(&state.db, &thread_id, q.since_seq).await?;
    Ok(Json(ListResp { posts }))
}
