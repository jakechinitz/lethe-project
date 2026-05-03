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
async fn op_can_claim_identity_and_followups_link_to_seq_1() {
    let s = support::spawn().await;
    let client = reqwest::Client::new();

    // OP mints the thread id locally, signs the OP body, includes both
    // in the create request.
    let me = browser::new_thread_identity();
    let thread_id_bytes: [u8; 16] = {
        use rand::RngCore as _;
        let mut b = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut b);
        b
    };
    let body = "this is the OP and i am claiming identity";
    let nonce = browser::solve_pow(b"economy", body, s.pow_bits);
    let sig = browser::sign_post(&thread_id_bytes, body, &me.private_key);

    let resp: CreateThreadResp = client
        .post(format!("{}/api/threads", s.base_url))
        .json(&json!({
            "board_id": "economy",
            "title": "claim",
            "body": body,
            "pow_nonce": browser::b64(&nonce),
            "thread_id": browser::b64(&thread_id_bytes),
            "pubkey": browser::b64(&me.public_key),
            "signature": browser::b64(&sig),
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(resp.seq, 1);
    assert_eq!(browser::unb64(&resp.thread_id), thread_id_bytes.to_vec());

    // Reply with the same key. signer_first_seq should point to OP (#1),
    // which is the property that makes the client render the reply as "OP".
    let reply_body = "and now i am replying as the same anon";
    let reply_nonce = browser::solve_pow(&thread_id_bytes, reply_body, s.pow_bits);
    let reply_sig = browser::sign_post(&thread_id_bytes, reply_body, &me.private_key);
    let reply: CreatePostResp = client
        .post(format!("{}/api/threads/{}/posts", s.base_url, resp.thread_id))
        .json(&json!({
            "body": reply_body,
            "pow_nonce": browser::b64(&reply_nonce),
            "pubkey": browser::b64(&me.public_key),
            "signature": browser::b64(&reply_sig),
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(reply.signer_first_seq, Some(1));
}

#[tokio::test]
async fn create_thread_with_pubkey_but_no_thread_id_is_rejected() {
    let s = support::spawn().await;
    let client = reqwest::Client::new();
    let me = browser::new_thread_identity();
    let body = "claim without thread_id";
    let nonce = browser::solve_pow(b"economy", body, s.pow_bits);
    // Sign over arbitrary bytes — server should reject before signature
    // verification because thread_id is missing.
    let bogus_sig = browser::sign_post(&[0u8; 16], body, &me.private_key);
    let resp = client
        .post(format!("{}/api/threads", s.base_url))
        .json(&json!({
            "board_id": "economy",
            "title": "x",
            "body": body,
            "pow_nonce": browser::b64(&nonce),
            "pubkey": browser::b64(&me.public_key),
            "signature": browser::b64(&bogus_sig),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 400);
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
