//! Moderation pipeline:
//!   - link-density spam is rejected at submit time and logged,
//!   - identical bodies within 24 h are rejected as duplicates,
//!   - bodies that pass the rules sail through (the default classifier
//!     is a no-op),
//!   - the public moderation log lists rejections without exposing the
//!     body content.

mod support;

use serde_json::json;
use support::browser;

async fn submit_thread(
    client: &reqwest::Client,
    base_url: &str,
    pow_bits: u32,
    board: &str,
    title: &str,
    body: &str,
) -> reqwest::Response {
    let nonce = browser::solve_pow(board.as_bytes(), body, pow_bits);
    client
        .post(format!("{base_url}/api/threads"))
        .json(&json!({
            "board_id": board,
            "title": title,
            "body": body,
            "pow_nonce": browser::b64(&nonce),
        }))
        .send()
        .await
        .unwrap()
}

#[tokio::test]
async fn link_density_spam_is_rejected_and_logged() {
    let s = support::spawn().await;
    let client = reqwest::Client::new();
    let body = "buy https://a.example https://b.example https://c.example https://d.example";
    let resp = submit_thread(&client, &s.base_url, s.pow_bits, "economy", "deal", body).await;
    assert_eq!(resp.status().as_u16(), 400);
    let text = resp.text().await.unwrap();
    assert!(text.contains("spam_link_density"), "got: {text}");

    // The moderation log should now have one row for this rejection,
    // with the right reason and a body hash but no body content.
    type ModRow = (Vec<u8>, Option<String>, Vec<u8>, String);
    let rows: Vec<ModRow> = sqlx::query_as(
        "SELECT id, board_id, body_hash, reason FROM moderation_actions ORDER BY decided_at DESC",
    )
    .fetch_all(&s.db)
    .await
    .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].1.as_deref(), Some("economy"));
    assert_eq!(rows[0].3, "spam_link_density");
    // body_hash is a SHA-256, so 32 bytes.
    assert_eq!(rows[0].2.len(), 32);
}

#[tokio::test]
async fn duplicate_body_within_window_is_rejected() {
    let s = support::spawn().await;
    let client = reqwest::Client::new();
    let body = "this is a perfectly normal post about a topic of interest";

    let r1 = submit_thread(&client, &s.base_url, s.pow_bits, "economy", "first", body).await;
    assert!(r1.status().is_success(), "first: {:?}", r1);

    let r2 = submit_thread(&client, &s.base_url, s.pow_bits, "economy", "second", body).await;
    assert_eq!(r2.status().as_u16(), 400);
    let text = r2.text().await.unwrap();
    assert!(text.contains("spam_duplicate"), "got: {text}");
}

#[tokio::test]
async fn duplicate_across_boards_is_allowed() {
    // The duplicate rule is per-board; a thread on /economy doesn't
    // block the same body appearing on /science_tech.
    let s = support::spawn().await;
    let client = reqwest::Client::new();
    let body = "i am a body that exists on more than one board";

    let r1 = submit_thread(&client, &s.base_url, s.pow_bits, "economy", "a", body).await;
    assert!(r1.status().is_success());

    let r2 = submit_thread(&client, &s.base_url, s.pow_bits, "science_tech", "b", body).await;
    assert!(r2.status().is_success(), "cross-board duplicate should pass: {:?}", r2);
}

#[tokio::test]
async fn ok_post_passes_and_no_log_entry_is_written() {
    let s = support::spawn().await;
    let client = reqwest::Client::new();
    let body = "a thoughtful first post about something worth discussing";
    let resp = submit_thread(&client, &s.base_url, s.pow_bits, "economy", "ok", body).await;
    assert!(resp.status().is_success());

    let count: (i64,) = sqlx::query_as("SELECT count(*) FROM moderation_actions")
        .fetch_one(&s.db)
        .await
        .unwrap();
    assert_eq!(count.0, 0);
}

#[tokio::test]
async fn too_short_body_is_rejected() {
    let s = support::spawn().await;
    let client = reqwest::Client::new();
    let resp = submit_thread(&client, &s.base_url, s.pow_bits, "economy", "tiny", "ok").await;
    assert_eq!(resp.status().as_u16(), 400);
    let text = resp.text().await.unwrap();
    assert!(text.contains("spam_too_short"), "got: {text}");
}
