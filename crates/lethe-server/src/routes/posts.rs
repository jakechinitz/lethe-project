//! `POST /api/threads/:thread_id/posts`, `GET .../posts?since_seq=...`,
//! and `POST /api/posts/:post_id/delete` (author self-delete).

use crate::{error::{AppError, AppResult}, logic, state::AppState};
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use lethe_types::posts::{CreatePostReq, CreatePostResp, DeletePostReq, PostView};
use serde::Deserialize;

pub async fn create(
    State(state): State<AppState>,
    Path(thread_id): Path<String>,
    Json(req): Json<CreatePostReq>,
) -> AppResult<Json<CreatePostResp>> {
    let identity = state
        .identity
        .as_ref()
        .ok_or(AppError::Internal("server identity unavailable"))?;
    let resp = logic::posts::create_post(
        &state.db,
        state.cfg.default_pow_bits as u32,
        state.classifier.as_ref(),
        identity.pubkey(),
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
    let identity = state
        .identity
        .as_ref()
        .ok_or(AppError::Internal("server identity unavailable"))?;
    let posts =
        logic::posts::list_posts(&state.db, identity.pubkey(), &thread_id, q.since_seq).await?;
    Ok(Json(ListResp { posts }))
}

pub async fn delete(
    State(state): State<AppState>,
    Path(post_id): Path<String>,
    Json(req): Json<DeletePostReq>,
) -> AppResult<StatusCode> {
    logic::posts::delete_post(&state.db, &post_id, req).await?;
    Ok(StatusCode::NO_CONTENT)
}
