//! HTTP endpoints for federation:
//!
//!   GET  /api/federation/events  — signed event stream (locally-
//!                                  originated only, by design)
//!   GET  /api/federation/info    — verifiability metadata
//!   GET  /api/federation/peers   — admin: list peers (token-gated)
//!   POST /api/federation/peers   — admin: add/upsert peer
//!   POST /api/federation/peers/disable — admin: defederate
//!
//! The events endpoint is the wire interface every other Lethe server
//! pulls from. It MUST NOT serve any private-room content; the queries
//! it issues touch `posts`, `threads`, and `post_removals` only —
//! never `rooms`, `room_members`, or `room_messages`.
//!
//! Admin endpoints are gated on a shared static bearer token from the
//! `LETHE_ADMIN_TOKEN` env var (loaded into `Config`). When the token
//! is absent, the admin routes respond 503 — there is no implicit "no
//! auth required" mode.

use crate::{
    db,
    error::{AppError, AppResult},
    federation::{events, info},
    ids,
    state::AppState,
};
use axum::{
    extract::{Query, State},
    http::HeaderMap,
    Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};
use time::Date;

const EVENTS_PAGE_LIMIT: i64 = 200;

#[derive(Debug, Deserialize)]
pub struct EventsQuery {
    #[serde(default)]
    pub since_post: Option<String>,
    #[serde(default)]
    pub since_removal: Option<String>,
}

pub async fn events(
    State(state): State<AppState>,
    Query(q): Query<EventsQuery>,
) -> AppResult<Json<events::EventsResponse>> {
    let identity = state.identity.as_ref().ok_or(AppError::NotFound)?;
    let server_pubkey = identity.pubkey();

    let post_cursor = parse_cursor(q.since_post.as_deref())
        .map_err(|_| AppError::BadRequest("since_post cursor"))?;
    let removal_cursor = parse_cursor(q.since_removal.as_deref())
        .map_err(|_| AppError::BadRequest("since_removal cursor"))?;

    let post_rows = db::federation::list_outgoing_posts(
        &state.db,
        server_pubkey,
        post_cursor,
        EVENTS_PAGE_LIMIT,
    )
    .await?;
    let removal_rows = db::federation::list_outgoing_removals(
        &state.db,
        server_pubkey,
        removal_cursor,
        EVENTS_PAGE_LIMIT,
    )
    .await?;

    let next_post_cursor = post_rows.last().map(|r| {
        encode_cursor(r.created_at, &r.origin_post_id)
    });
    let next_removal_cursor = removal_rows.last().map(|r| {
        encode_cursor(r.removed_at, &r.post_id)
    });

    let posts: Vec<events::PostEvent> = post_rows
        .iter()
        .map(|r| {
            let thread_origin = r
                .thread_origin_server_id
                .as_deref()
                .unwrap_or(&r.origin_server_id[..]);
            events::build_post_event(
                identity,
                &events::PostEventFields {
                    board_id: &r.board_id,
                    thread_id: &r.thread_id,
                    thread_origin_server_id: thread_origin,
                    thread_title: &r.thread_title,
                    origin_server_id: &r.origin_server_id,
                    origin_post_id: &r.origin_post_id,
                    body: &r.body,
                    created_at: r.created_at,
                    author_pubkey: r.author_pubkey.as_deref(),
                    author_signature: r.author_signature.as_deref(),
                },
            )
        })
        .collect();

    let removals: Vec<events::RemovalEvent> = removal_rows
        .iter()
        .map(|r| {
            // The local post id == origin_post_id for our own posts
            // (see `db::posts::insert`), so we hand back the local id
            // as origin_post_id. For posts that were federated *in*
            // and then removed locally, scope='local' so they're not
            // in this stream.
            events::build_removal_event(
                identity,
                &events::RemovalEventFields {
                    origin_server_id: server_pubkey,
                    origin_post_id: &r.post_id,
                    reason: &r.reason,
                    removed_at: r.removed_at,
                },
            )
        })
        .collect();

    Ok(Json(events::EventsResponse {
        posts,
        removals,
        next_post_cursor,
        next_removal_cursor,
    }))
}

pub async fn info(State(state): State<AppState>) -> AppResult<Json<info::InfoResponse>> {
    let identity = state.identity.as_ref().ok_or(AppError::NotFound)?;
    Ok(Json(info::build(
        identity.pubkey(),
        state
            .cfg
            .moderation_summary
            .clone()
            .unwrap_or_else(|| "baseline".to_string()),
        state.cfg.operator_label.clone(),
    )))
}

#[derive(Debug, Serialize)]
pub struct PeerView {
    pub server_pubkey: String,
    pub endpoint: String,
    pub label: Option<String>,
    pub enabled: bool,
}

#[derive(Debug, Serialize)]
pub struct PeersList {
    pub peers: Vec<PeerView>,
}

#[derive(Debug, Deserialize)]
pub struct AddPeerReq {
    pub server_pubkey: String,
    pub endpoint: String,
    #[serde(default)]
    pub label: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct DisablePeerReq {
    pub server_pubkey: String,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_enabled() -> bool {
    false
}

pub async fn list_peers(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<PeersList>> {
    require_admin(&state, &headers)?;
    let peers = db::federation::list_peers(&state.db).await?;
    Ok(Json(PeersList {
        peers: peers
            .into_iter()
            .map(|p| PeerView {
                server_pubkey: URL_SAFE_NO_PAD.encode(&p.server_pubkey),
                endpoint: p.endpoint,
                label: p.label,
                enabled: p.enabled,
            })
            .collect(),
    }))
}

pub async fn add_peer(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<AddPeerReq>,
) -> AppResult<Json<serde_json::Value>> {
    require_admin(&state, &headers)?;
    let pk = ids::unb64_array::<32>(&req.server_pubkey)
        .map_err(|_| AppError::BadRequest("server_pubkey"))?;
    if let Some(identity) = state.identity.as_ref() {
        if &pk == identity.pubkey() {
            return Err(AppError::BadRequest("cannot peer with self"));
        }
    }
    if req.endpoint.is_empty() || req.endpoint.len() > 1024 {
        return Err(AppError::BadRequest("endpoint length"));
    }
    db::federation::upsert_peer(&state.db, &pk, &req.endpoint, req.label.as_deref()).await?;
    Ok(Json(serde_json::json!({"status": "ok"})))
}

pub async fn set_peer_enabled(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<DisablePeerReq>,
) -> AppResult<Json<serde_json::Value>> {
    require_admin(&state, &headers)?;
    let pk = ids::unb64_array::<32>(&req.server_pubkey)
        .map_err(|_| AppError::BadRequest("server_pubkey"))?;
    let updated = db::federation::set_enabled(&state.db, &pk, req.enabled).await?;
    if !updated {
        return Err(AppError::NotFound);
    }
    Ok(Json(serde_json::json!({"status": "ok", "enabled": req.enabled})))
}

fn require_admin(state: &AppState, headers: &HeaderMap) -> AppResult<()> {
    let configured = state
        .cfg
        .admin_token
        .as_deref()
        .ok_or(AppError::Forbidden("admin token not configured"))?;
    let header = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .unwrap_or("");
    if !constant_time_eq(configured.as_bytes(), header.as_bytes()) {
        return Err(AppError::Forbidden("bad admin token"));
    }
    Ok(())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        acc |= x ^ y;
    }
    acc == 0
}

/// Cursor wire format: "<julian_day>.<base64url_id>".
fn parse_cursor(s: Option<&str>) -> Result<Option<(Date, Vec<u8>)>, ()> {
    let Some(s) = s else { return Ok(None) };
    if s.is_empty() {
        return Ok(None);
    }
    let (day_str, id_str) = s.split_once('.').ok_or(())?;
    let day: i32 = day_str.parse().map_err(|_| ())?;
    let date = Date::from_julian_day(day).map_err(|_| ())?;
    let id = URL_SAFE_NO_PAD.decode(id_str).map_err(|_| ())?;
    if id.len() != 16 {
        return Err(());
    }
    Ok(Some((date, id)))
}

fn encode_cursor(d: Date, id: &[u8]) -> String {
    format!("{}.{}", d.to_julian_day(), URL_SAFE_NO_PAD.encode(id))
}
