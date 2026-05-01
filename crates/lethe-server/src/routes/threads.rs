//! `POST /api/threads` — create a new thread.

use crate::{error::AppResult, logic, state::AppState};
use axum::{extract::State, Json};
use lethe_types::posts::{CreateThreadReq, CreateThreadResp};

pub async fn create(
    State(state): State<AppState>,
    Json(req): Json<CreateThreadReq>,
) -> AppResult<Json<CreateThreadResp>> {
    let resp =
        logic::posts::create_thread(&state.db, state.cfg.default_pow_bits as u32, req).await?;
    Ok(Json(resp))
}
