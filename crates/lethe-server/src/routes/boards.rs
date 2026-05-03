//! `GET /api/boards/:id` — minimal metadata so the client can read PoW
//! difficulty without scraping the HTML page.

use crate::{error::{AppError, AppResult}, state::AppState};
use axum::{
    extract::{Path, State},
    Json,
};
use lethe_types::Board;

pub async fn get(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> AppResult<Json<Board>> {
    let row: Option<(String, String, i16)> =
        sqlx::query_as("SELECT id, title, pow_bits FROM boards WHERE id = $1")
            .bind(&id)
            .fetch_optional(&state.db)
            .await?;
    let (id, title, pow_bits) = row.ok_or(AppError::NotFound)?;
    Ok(Json(Board {
        id,
        title,
        pow_bits: pow_bits as u8,
    }))
}
