//! `POST /api/posts/:post_id/reports`: PoW-gated, anonymous, write-only.

mod support;

use lethe_types::posts::*;
use serde_json::json;
use support::browser;

async fn create_thread_and_get_op(
    client: &reqwest::Client,
    base_url: &str,
    pow_bits: u32,
) -> (String, String) {
    let board = "general";
    let body = "report-target body";
    let nonce = browser::solve_pow(board.as_bytes(), body, pow_bits);
    let created: CreateThreadResp = client
        .post(format!("{base_url}/api/threads"))
        .json(&json!({
            "board_id": board,
            "title": "t",
            "body": body,
            "pow_nonce": browser::b64(&nonce),
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let posts: serde_json::Value = client
        .get(format!("{}/api/threads/{}/posts", base_url, created.thread_id))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let op = &posts["posts"][0];
    let post_id = op["post_id"].as_str().unwrap().to_string();
    (created.thread_id, post_id)
}

#[tokio::test]
async fn report_creates_row_and_validates_pow() {
    let s = support::spawn().await;
    let client = reqwest::Client::new();
    let (_thread, post_id) = create_thread_and_get_op(&client, &s.base_url, s.pow_bits).await;
    let post_id_bytes = browser::unb64(&post_id);

    let reason = "spam";
    let nonce = browser::solve_pow(&post_id_bytes, reason, s.pow_bits);
    let resp = client
        .post(format!("{}/api/posts/{}/reports", s.base_url, post_id))
        .json(&json!({
            "reason": reason,
            "pow_nonce": browser::b64(&nonce),
        }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "report: {resp:?}");
    let body: ReportPostResp = resp.json().await.unwrap();
    assert!(!body.report_id.is_empty());

    let row: (Vec<u8>, Option<String>) = sqlx::query_as(
        "SELECT post_id, reason_text FROM reports WHERE post_id = $1",
    )
    .bind(&post_id_bytes)
    .fetch_one(&s.db)
    .await
    .unwrap();
    assert_eq!(row.0, post_id_bytes);
    assert_eq!(row.1.as_deref(), Some("spam"));
}

#[tokio::test]
async fn report_without_reason_succeeds() {
    let s = support::spawn().await;
    let client = reqwest::Client::new();
    let (_thread, post_id) = create_thread_and_get_op(&client, &s.base_url, s.pow_bits).await;
    let post_id_bytes = browser::unb64(&post_id);

    // Reason omitted → PoW is over the empty string.
    let nonce = browser::solve_pow(&post_id_bytes, "", s.pow_bits);
    let resp = client
        .post(format!("{}/api/posts/{}/reports", s.base_url, post_id))
        .json(&json!({ "pow_nonce": browser::b64(&nonce) }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "report: {resp:?}");

    let row: (Option<String>,) = sqlx::query_as(
        "SELECT reason_text FROM reports WHERE post_id = $1",
    )
    .bind(&post_id_bytes)
    .fetch_one(&s.db)
    .await
    .unwrap();
    assert!(row.0.is_none());
}

#[tokio::test]
async fn report_with_bad_pow_is_rejected() {
    use sha2::{Digest, Sha256};
    let s = support::spawn().await;
    let client = reqwest::Client::new();
    let (_thread, post_id) = create_thread_and_get_op(&client, &s.base_url, s.pow_bits).await;
    let post_id_bytes = browser::unb64(&post_id);

    // Find a nonce whose digest deterministically fails the difficulty
    // check, instead of relying on a probabilistic miss.
    let mut nonce = [0u8; 8];
    loop {
        let mut h = Sha256::new();
        h.update(&post_id_bytes);
        h.update(b"spam");
        h.update(nonce);
        let digest = h.finalize();
        let leading = digest.iter().take_while(|b| **b == 0).count() as u32 * 8
            + digest.iter().find(|b| **b != 0).map(|b| b.leading_zeros()).unwrap_or(0);
        if leading < s.pow_bits {
            break;
        }
        for byte in nonce.iter_mut() {
            *byte = byte.wrapping_add(1);
            if *byte != 0 {
                break;
            }
        }
    }

    let resp = client
        .post(format!("{}/api/posts/{}/reports", s.base_url, post_id))
        .json(&json!({
            "reason": "spam",
            "pow_nonce": browser::b64(&nonce),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 400);
}

#[tokio::test]
async fn report_for_unknown_post_is_404() {
    let s = support::spawn().await;
    let client = reqwest::Client::new();
    let fake = browser::b64(&[0xAAu8; 16]);
    let nonce = browser::solve_pow(&[0xAAu8; 16], "spam", s.pow_bits);
    let resp = client
        .post(format!("{}/api/posts/{}/reports", s.base_url, fake))
        .json(&json!({ "reason": "spam", "pow_nonce": browser::b64(&nonce) }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 404);
}
