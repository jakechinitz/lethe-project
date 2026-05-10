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
    let manifest_sha = state
        .cfg
        .release_manifest_path
        .as_deref()
        .and_then(info::manifest_sha256);
    Ok(Json(info::build(
        identity.pubkey(),
        state
            .cfg
            .moderation_summary
            .clone()
            .unwrap_or_else(|| "baseline".to_string()),
        state.cfg.operator_label.clone(),
        manifest_sha,
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

/// `GET /api/federation/peers/public` — unauthenticated. Returns just
/// the labels, endpoints, and pubkeys of currently-enabled peers so
/// end users can see which other Lethe servers this one is federating
/// with. Cursor / `last_pulled_at` are NOT exposed; those are admin
/// data.
pub async fn list_peers_public(
    State(state): State<AppState>,
) -> AppResult<Json<PeersList>> {
    let peers = db::federation::list_enabled_peers(&state.db).await?;
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

pub async fn list_peers(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<PeersList>> {
    require_admin(&state, &headers).await?;
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
    require_admin(&state, &headers).await?;
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
    let cursor_bytes = backfill_cursor(state.cfg.pull_horizon_days);
    db::federation::upsert_peer(
        &state.db,
        &pk,
        &req.endpoint,
        req.label.as_deref(),
        cursor_bytes.as_deref(),
    )
    .await?;
    Ok(Json(serde_json::json!({"status": "ok"})))
}

/// Builds an initial peer cursor that says "skip events older than
/// `horizon_days`". The cursor is the same on-the-wire shape that the
/// pull worker writes after a successful pull, so the first pull just
/// resumes from this synthetic point. Returns `None` for full-history
/// backfill (`horizon_days = 0`).
fn backfill_cursor(horizon_days: i64) -> Option<Vec<u8>> {
    if horizon_days <= 0 {
        return None;
    }
    let today = crate::time::today_utc();
    let horizon_julian = today.to_julian_day().saturating_sub(horizon_days as i32);
    // Sentinel id: 16 zero bytes. Any real post id sorts strictly
    // greater under `(date, id) > (cursor_date, cursor_id)`.
    let zero_id = vec![0u8; 16];
    let post_cursor = format!("{}.{}", horizon_julian, URL_SAFE_NO_PAD.encode(&zero_id));
    let stored = serde_json::json!({
        "post": post_cursor,
        "removal": post_cursor,
    });
    Some(serde_json::to_vec(&stored).expect("json serialize"))
}

#[derive(Debug, Deserialize)]
pub struct MintTokenReq {
    pub label: String,
}

#[derive(Debug, Serialize)]
pub struct MintTokenResp {
    pub label: String,
    /// Plaintext token. Returned exactly once; not retrievable later.
    pub token: String,
}

#[derive(Debug, Serialize)]
pub struct TokenView {
    pub label: String,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TokensList {
    pub tokens: Vec<TokenView>,
}

#[derive(Debug, Deserialize)]
pub struct RevokeTokenReq {
    pub label: String,
}

pub async fn mint_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<MintTokenReq>,
) -> AppResult<Json<MintTokenResp>> {
    require_admin(&state, &headers).await?;
    if req.label.is_empty() || req.label.len() > 64 {
        return Err(AppError::BadRequest("label length"));
    }
    // 32 random bytes, urlsafe-b64 → 43 chars. Comfortably above
    // bearer-token entropy norms.
    use rand::RngCore as _;
    let mut buf = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut buf);
    let token = URL_SAFE_NO_PAD.encode(buf);
    db::admin_tokens::insert(&state.db, &req.label, &token)
        .await
        .map_err(|e| match &e {
            sqlx::Error::Database(d) if d.constraint() == Some("admin_tokens_pkey") => {
                AppError::Conflict("token collision; try again")
            }
            _ => AppError::Db(e),
        })?;
    Ok(Json(MintTokenResp {
        label: req.label,
        token,
    }))
}

pub async fn list_tokens(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<TokensList>> {
    require_admin(&state, &headers).await?;
    let rows = db::admin_tokens::list(&state.db).await?;
    Ok(Json(TokensList {
        tokens: rows
            .into_iter()
            .map(|t| TokenView {
                label: t.label,
                created_at: t.created_at.to_string(),
                revoked_at: t.revoked_at.map(|d| d.to_string()),
            })
            .collect(),
    }))
}

pub async fn revoke_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<RevokeTokenReq>,
) -> AppResult<Json<serde_json::Value>> {
    require_admin(&state, &headers).await?;
    let updated = db::admin_tokens::revoke(&state.db, &req.label).await?;
    if updated == 0 {
        return Err(AppError::NotFound);
    }
    Ok(Json(serde_json::json!({"status": "ok", "revoked": updated})))
}

pub async fn set_peer_enabled(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<DisablePeerReq>,
) -> AppResult<Json<serde_json::Value>> {
    require_admin(&state, &headers).await?;
    let pk = ids::unb64_array::<32>(&req.server_pubkey)
        .map_err(|_| AppError::BadRequest("server_pubkey"))?;
    let updated = db::federation::set_enabled(&state.db, &pk, req.enabled).await?;
    if !updated {
        return Err(AppError::NotFound);
    }
    Ok(Json(serde_json::json!({"status": "ok", "enabled": req.enabled})))
}

async fn require_admin(state: &AppState, headers: &HeaderMap) -> AppResult<()> {
    let presented = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .unwrap_or("");

    // Path 1: bootstrap env token. Keeps single-operator deployments
    // simple and lets a fresh DB issue its first table-backed token
    // before any have been minted.
    if let Some(configured) = state.cfg.admin_token.as_deref() {
        if !configured.is_empty()
            && constant_time_eq(configured.as_bytes(), presented.as_bytes())
        {
            return Ok(());
        }
    }

    // Path 2: table-backed token. Hashed lookup; revoked rows don't
    // count.
    if !presented.is_empty() {
        if let Some(_label) = db::admin_tokens::verify(&state.db, presented).await? {
            return Ok(());
        }
    }

    if state.cfg.admin_token.is_none() {
        // Neither bootstrap nor table can authenticate this caller,
        // and no env token is configured at all — give the operator
        // a more specific message so they know how to recover.
        let any_table_token: Option<(i64,)> = sqlx::query_as(
            "SELECT 1 FROM admin_tokens WHERE revoked_at IS NULL LIMIT 1",
        )
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten();
        if any_table_token.is_none() {
            return Err(AppError::Forbidden("admin token not configured"));
        }
    }
    Err(AppError::Forbidden("bad admin token"))
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
