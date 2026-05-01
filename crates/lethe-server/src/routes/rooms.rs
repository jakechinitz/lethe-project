//! Room HTTP endpoints: create, join-by-invite, wrap, members, provenance,
//! send/list messages.

use crate::{error::AppResult, logic, state::AppState};
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use lethe_types::rooms::*;
use serde::Deserialize;

pub async fn create(
    State(state): State<AppState>,
    Json(req): Json<CreateRoomReq>,
) -> AppResult<Json<CreateRoomResp>> {
    Ok(Json(logic::rooms::create(&state.db, req).await?))
}

pub async fn join(
    State(state): State<AppState>,
    Path(invite_code): Path<String>,
    Json(req): Json<JoinRoomReq>,
) -> AppResult<Json<JoinRoomResp>> {
    Ok(Json(logic::rooms::join(&state.db, &invite_code, req).await?))
}

pub async fn wrap(
    State(state): State<AppState>,
    Path(room_id): Path<String>,
    Json(req): Json<WrapKeyReq>,
) -> AppResult<StatusCode> {
    logic::rooms::wrap(&state.db, &room_id, req).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn members(
    State(state): State<AppState>,
    Path(room_id): Path<String>,
) -> AppResult<Json<MembersResp>> {
    Ok(Json(logic::rooms::members(&state.db, &room_id).await?))
}

pub async fn provenance(
    State(state): State<AppState>,
    Path(room_id): Path<String>,
) -> AppResult<Json<ProvenanceResp>> {
    Ok(Json(logic::rooms::provenance(&state.db, &room_id).await?))
}

pub async fn send_message(
    State(state): State<AppState>,
    Path(room_id): Path<String>,
    Json(req): Json<SendMessageReq>,
) -> AppResult<Json<SendMessageResp>> {
    Ok(Json(logic::rooms::send_message(&state.db, &room_id, req).await?))
}

#[derive(Deserialize)]
pub struct ListMessagesQuery {
    pub since: Option<String>,
}

pub async fn list_messages(
    State(state): State<AppState>,
    Path(room_id): Path<String>,
    Query(q): Query<ListMessagesQuery>,
) -> AppResult<Json<MessagesResp>> {
    Ok(Json(
        logic::rooms::list_messages(&state.db, &room_id, q.since.as_deref()).await?,
    ))
}
