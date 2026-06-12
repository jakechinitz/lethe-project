//! Author self-delete:
//!   - the key that signed a post can delete it,
//!   - the body / signature / pubkey are scrubbed from the row,
//!   - readers see a "[removed: deleted by author]" tombstone,
//!   - a different key is rejected,
//!   - fully anonymous posts cannot be deleted,
//!   - the same delete signature can't be replayed.

mod support;

use serde_json::json;
use support::browser;

struct SignedPost {
    thread_id_b64: String,
    thread_id: Vec<u8>,
    post_id_b64: String,
    author: browser::ThreadIdentity,
}

/// Creates a thread (anonymous OP) plus one signed reply, returning the
/// reply's ids and the author identity.
async fn thread_with_signed_reply(s: &support::TestServer) -> SignedPost {
    let client = reqwest::Client::new();
    let body0 = "op body for author-delete tests";
    let nonce0 = browser::solve_pow(b"general", body0, s.pow_bits);
    let thread: lethe_types::posts::CreateThreadResp = client
        .post(format!("{}/api/threads", s.base_url))
        .json(&json!({
            "board_id": "general",
            "title": "author-delete",
            "body": body0,
            "pow_nonce": browser::b64(&nonce0),
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let thread_id = browser::unb64(&thread.thread_id);

    let author = browser::new_thread_identity();
    let body = "a signed reply that will be deleted";
    let nonce = browser::solve_pow(&thread_id, body, s.pow_bits);
    let sig = browser::sign_post(&thread_id, body, &author.private_key);
    let created: lethe_types::posts::CreatePostResp = client
        .post(format!("{}/api/threads/{}/posts", s.base_url, thread.thread_id))
        .json(&json!({
            "body": body,
            "pow_nonce": browser::b64(&nonce),
            "pubkey": browser::b64(&author.public_key),
            "signature": browser::b64(&sig),
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    SignedPost {
        thread_id_b64: thread.thread_id,
        thread_id,
        post_id_b64: created.post_id,
        author,
    }
}

#[tokio::test]
async fn author_can_delete_own_post_and_content_is_scrubbed() {
    let s = support::spawn().await;
    let client = reqwest::Client::new();
    let p = thread_with_signed_reply(&s).await;
    let post_id = browser::unb64(&p.post_id_b64);

    let ts = time::OffsetDateTime::now_utc().unix_timestamp();
    let sig = browser::sign_post_delete(&post_id, ts, &p.author.private_key);
    let resp = client
        .post(format!("{}/api/posts/{}/delete", s.base_url, p.post_id_b64))
        .json(&json!({
            "pubkey": browser::b64(&p.author.public_key),
            "ts": ts,
            "sig": browser::b64(&sig),
        }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "delete: {resp:?}");

    // Reader sees a tombstone with no pubkey.
    let listed: serde_json::Value = client
        .get(format!(
            "{}/api/threads/{}/posts?since_seq=0",
            s.base_url, p.thread_id_b64
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let posts = listed["posts"].as_array().unwrap();
    let deleted = posts.iter().find(|x| x["seq"] == 2).unwrap();
    assert_eq!(
        deleted["body"].as_str().unwrap(),
        "[removed: deleted by author]"
    );
    assert!(deleted.get("pubkey").is_none() || deleted["pubkey"].is_null());

    // And the row itself holds nothing: body empty, pubkey/signature NULL.
    let row: (String, Option<Vec<u8>>, Option<Vec<u8>>) = sqlx::query_as(
        "SELECT body, pubkey, signature FROM posts WHERE id = $1",
    )
    .bind(&post_id[..])
    .fetch_one(&s.db)
    .await
    .unwrap();
    assert_eq!(row.0, "");
    assert!(row.1.is_none());
    assert!(row.2.is_none());

    // The original text exists nowhere in the posts table.
    let leak: Option<(i32,)> = sqlx::query_as(
        "SELECT 1 FROM posts WHERE body LIKE '%signed reply that will be deleted%' LIMIT 1",
    )
    .fetch_optional(&s.db)
    .await
    .unwrap();
    assert!(leak.is_none(), "deleted body still present somewhere");

    // Replay of the same signature is rejected (nonce dedupe).
    let replay = client
        .post(format!("{}/api/posts/{}/delete", s.base_url, p.post_id_b64))
        .json(&json!({
            "pubkey": browser::b64(&p.author.public_key),
            "ts": ts,
            "sig": browser::b64(&sig),
        }))
        .send()
        .await
        .unwrap();
    assert!(!replay.status().is_success());
}

#[tokio::test]
async fn non_author_key_cannot_delete() {
    let s = support::spawn().await;
    let client = reqwest::Client::new();
    let p = thread_with_signed_reply(&s).await;
    let post_id = browser::unb64(&p.post_id_b64);

    // Mallory has a perfectly valid signature — from the wrong key.
    let mallory = browser::new_thread_identity();
    let ts = time::OffsetDateTime::now_utc().unix_timestamp();
    let sig = browser::sign_post_delete(&post_id, ts, &mallory.private_key);
    let resp = client
        .post(format!("{}/api/posts/{}/delete", s.base_url, p.post_id_b64))
        .json(&json!({
            "pubkey": browser::b64(&mallory.public_key),
            "ts": ts,
            "sig": browser::b64(&sig),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 403);

    // Post body untouched.
    let row: (String,) = sqlx::query_as("SELECT body FROM posts WHERE id = $1")
        .bind(&post_id[..])
        .fetch_one(&s.db)
        .await
        .unwrap();
    assert_eq!(row.0, "a signed reply that will be deleted");
}

#[tokio::test]
async fn anonymous_post_cannot_be_deleted() {
    let s = support::spawn().await;
    let client = reqwest::Client::new();
    let p = thread_with_signed_reply(&s).await;

    // Post an anonymous (unsigned) reply.
    let body = "fully anonymous reply";
    let nonce = browser::solve_pow(&p.thread_id, body, s.pow_bits);
    let created: lethe_types::posts::CreatePostResp = client
        .post(format!("{}/api/threads/{}/posts", s.base_url, p.thread_id_b64))
        .json(&json!({
            "body": body,
            "pow_nonce": browser::b64(&nonce),
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    // Even a syntactically-valid request is refused: there is no key on
    // the post for the server to verify ownership against.
    let anon_post_id = browser::unb64(&created.post_id);
    let somebody = browser::new_thread_identity();
    let ts = time::OffsetDateTime::now_utc().unix_timestamp();
    let sig = browser::sign_post_delete(&anon_post_id, ts, &somebody.private_key);
    let resp = client
        .post(format!("{}/api/posts/{}/delete", s.base_url, created.post_id))
        .json(&json!({
            "pubkey": browser::b64(&somebody.public_key),
            "ts": ts,
            "sig": browser::b64(&sig),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 403);
}
