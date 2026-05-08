//! `POST /api/posts/:post_id/reports` — submit an anonymous report.

use crate::{error::AppResult, logic, state::AppState};
use axum::{
    extract::{Path, State},
    Json,
};
use lethe_types::posts::{ReportPostReq, ReportPostResp};

pub async fn create(
    State(state): State<AppState>,
    Path(post_id): Path<String>,
    Json(req): Json<ReportPostReq>,
) -> AppResult<Json<ReportPostResp>> {
    let resp = logic::reports::report_post(
        &state.db,
        state.cfg.default_pow_bits as u32,
        &post_id,
        req,
    )
    .await?;
    Ok(Json(resp))
}
