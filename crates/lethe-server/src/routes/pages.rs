//! Server-rendered HTML pages.
//!
//! Each page is a separate askama template loading exactly one TS module
//! from `/static/js`. Strict CSP forbids inline JS, so all logic lives in
//! the TS bundle.

use crate::{db, error::{AppError, AppResult}, ids, state::AppState};
use askama::Template;
use askama_axum::IntoResponse;
use axum::{
    extract::{Path, Query, State},
    response::Response,
};
use serde::Deserialize;

#[derive(Template)]
#[template(path = "board.html")]
struct BoardPage {
    board_id: String,
    pow_bits: u8,
    threads: Vec<ThreadEntry>,
}

struct ThreadEntry {
    id_b64: String,
    title: String,
}

pub async fn board(
    State(state): State<AppState>,
    Path(board_id): Path<String>,
) -> AppResult<Response> {
    let row: Option<(i16,)> = sqlx::query_as("SELECT pow_bits FROM boards WHERE id = $1")
        .bind(&board_id)
        .fetch_optional(&state.db)
        .await?;
    let pow_bits = row.ok_or(AppError::NotFound)?.0 as u8;
    let threads = db::threads::list_for_board(&state.db, &board_id, 100)
        .await?
        .into_iter()
        .map(|t| ThreadEntry {
            id_b64: ids::b64(&t.id),
            title: t.title,
        })
        .collect();
    Ok(BoardPage {
        board_id,
        pow_bits,
        threads,
    }
    .into_response())
}

#[derive(Template)]
#[template(path = "thread.html")]
struct ThreadPage {
    board_id: String,
    thread_id_b64: String,
    title: String,
    pow_bits: u8,
}

pub async fn thread(
    State(state): State<AppState>,
    Path((board_id, thread_id_b64)): Path<(String, String)>,
) -> AppResult<Response> {
    let thread_id =
        ids::unb64(&thread_id_b64).map_err(|_| AppError::BadRequest("thread id"))?;
    let title = db::threads::get_title(&state.db, &thread_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let row: Option<(i16,)> = sqlx::query_as("SELECT pow_bits FROM boards WHERE id = $1")
        .bind(&board_id)
        .fetch_optional(&state.db)
        .await?;
    let pow_bits = row.ok_or(AppError::NotFound)?.0 as u8;
    Ok(ThreadPage {
        board_id,
        thread_id_b64,
        title,
        pow_bits,
    }
    .into_response())
}

#[derive(Deserialize)]
pub struct RoomNewQuery {
    pub from: Option<String>,
}

#[derive(Template)]
#[template(path = "room_create.html")]
struct RoomCreatePage {
    from_thread_id: String,
}

pub async fn room_create(Query(q): Query<RoomNewQuery>) -> AppResult<Response> {
    Ok(RoomCreatePage {
        from_thread_id: q.from.unwrap_or_default(),
    }
    .into_response())
}

#[derive(Template)]
#[template(path = "room_join.html")]
struct RoomJoinPage {
    invite_code: String,
}

pub async fn room_join(Path(invite_code): Path<String>) -> AppResult<Response> {
    Ok(RoomJoinPage { invite_code }.into_response())
}

#[derive(Template)]
#[template(path = "room.html")]
struct RoomPage {
    room_id_b64: String,
}

pub async fn room(Path(room_id_b64): Path<String>) -> AppResult<Response> {
    Ok(RoomPage { room_id_b64 }.into_response())
}

#[derive(Template)]
#[template(path = "index.html")]
struct IndexPage {}

pub async fn index() -> AppResult<Response> {
    Ok(IndexPage {}.into_response())
}
