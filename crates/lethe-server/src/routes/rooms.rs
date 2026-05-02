//! Room HTTP endpoints: create, join-by-invite, wrap, members, provenance,
//! send/list messages.

use crate::{error::AppResult, logic, state::AppState};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use lethe_types::rooms::*;

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

pub async fn list_messages(
    State(state): State<AppState>,
    Path(room_id): Path<String>,
    Json(req): Json<ListMessagesReq>,
) -> AppResult<Json<MessagesResp>> {
    Ok(Json(
        logic::rooms::list_messages_authed(&state.db, &room_id, req).await?,
    ))
}

pub async fn remove(
    State(state): State<AppState>,
    Path(room_id): Path<String>,
    Json(req): Json<RemoveMemberReq>,
) -> AppResult<Json<RemoveMemberResp>> {
    Ok(Json(
        logic::rooms::remove_and_rekey(&state.db, &room_id, req).await?,
    ))
}
