//! Anonymous thread creation and reply, end-to-end through the HTTP API.

mod support;

use lethe_types::posts::*;
use serde_json::json;
use support::browser;

#[tokio::test]
async fn anonymous_thread_and_reply() {
    let s = support::spawn().await;
    let client = reqwest::Client::new();

    let board = "general";
    let body = "first post in this thread";
    let nonce = browser::solve_pow(board.as_bytes(), body, s.pow_bits);

    let create = client
        .post(format!("{}/api/threads", s.base_url))
        .json(&json!({
            "board_id": board,
            "title": "hello",
            "body": body,
            "pow_nonce": browser::b64(&nonce),
        }))
        .send()
        .await
        .unwrap();
    assert!(create.status().is_success(), "create thread: {create:?}");
    let created: CreateThreadResp = create.json().await.unwrap();
    assert_eq!(created.seq, 1);

    let body2 = "anon reply";
    let thread_id_bytes = browser::unb64(&created.thread_id);
    let nonce2 = browser::solve_pow(&thread_id_bytes, body2, s.pow_bits);
    let post = client
        .post(format!("{}/api/threads/{}/posts", s.base_url, created.thread_id))
        .json(&json!({ "body": body2, "pow_nonce": browser::b64(&nonce2) }))
        .send()
        .await
        .unwrap();
    assert!(post.status().is_success());
    let posted: CreatePostResp = post.json().await.unwrap();
    assert_eq!(posted.seq, 2);
    assert!(posted.signer_first_seq.is_none());

    let list: serde_json::Value = client
        .get(format!("{}/api/threads/{}/posts", s.base_url, created.thread_id))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let posts = list["posts"].as_array().unwrap();
    assert_eq!(posts.len(), 2);
    assert_eq!(posts[0]["seq"], 1);
    assert_eq!(posts[1]["seq"], 2);
}

#[tokio::test]
async fn rejects_insufficient_pow() {
    let s = support::spawn().await;
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/api/threads", s.base_url))
        .json(&json!({
            "board_id": "general",
            "title": "x",
            "body": "x",
            "pow_nonce": browser::b64(&[0u8; 8]),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 400);
}
