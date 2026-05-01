//! Thread-local Ed25519 signing: server returns `signer_first_seq` so the UI
//! can render "same anon as #N", and tampered signatures are rejected.

mod support;

use lethe_types::posts::*;
use serde_json::json;
use support::browser;

async fn create_seed_thread(s: &support::TestServer) -> CreateThreadResp {
    let body = "seed";
    let nonce = browser::solve_pow(b"general", body, s.pow_bits);
    reqwest::Client::new()
        .post(format!("{}/api/threads", s.base_url))
        .json(&json!({
            "board_id": "general",
            "title": "seeded",
            "body": body,
            "pow_nonce": browser::b64(&nonce),
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

#[tokio::test]
async fn signer_first_seq_matches_first_signed_post() {
    let s = support::spawn().await;
    let client = reqwest::Client::new();
    let thread = create_seed_thread(&s).await;
    let thread_id = browser::unb64(&thread.thread_id);
    let me = browser::new_thread_identity();

    // First signed reply.
    let body1 = "first signed";
    let n1 = browser::solve_pow(&thread_id, body1, s.pow_bits);
    let sig1 = browser::sign_post(&thread_id, body1, &me.private_key);
    let r1: CreatePostResp = client
        .post(format!("{}/api/threads/{}/posts", s.base_url, thread.thread_id))
        .json(&json!({
            "body": body1,
            "pow_nonce": browser::b64(&n1),
            "pubkey": browser::b64(&me.public_key),
            "signature": browser::b64(&sig1),
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let first_seq = r1.seq;
    assert_eq!(r1.signer_first_seq, Some(first_seq));

    // Second signed reply with the same key.
    let body2 = "second signed";
    let n2 = browser::solve_pow(&thread_id, body2, s.pow_bits);
    let sig2 = browser::sign_post(&thread_id, body2, &me.private_key);
    let r2: CreatePostResp = client
        .post(format!("{}/api/threads/{}/posts", s.base_url, thread.thread_id))
        .json(&json!({
            "body": body2,
            "pow_nonce": browser::b64(&n2),
            "pubkey": browser::b64(&me.public_key),
            "signature": browser::b64(&sig2),
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r2.signer_first_seq, Some(first_seq));
    assert!(r2.seq > first_seq);
}

#[tokio::test]
async fn rejects_tampered_signature() {
    let s = support::spawn().await;
    let client = reqwest::Client::new();
    let thread = create_seed_thread(&s).await;
    let thread_id = browser::unb64(&thread.thread_id);
    let me = browser::new_thread_identity();

    let body = "to be tampered";
    let nonce = browser::solve_pow(&thread_id, body, s.pow_bits);
    // Sign over a *different* body; submit with the original body.
    let bad_sig = browser::sign_post(&thread_id, "different body", &me.private_key);

    let resp = client
        .post(format!("{}/api/threads/{}/posts", s.base_url, thread.thread_id))
        .json(&json!({
            "body": body,
            "pow_nonce": browser::b64(&nonce),
            "pubkey": browser::b64(&me.public_key),
            "signature": browser::b64(&bad_sig),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 400);
}
