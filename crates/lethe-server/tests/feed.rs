//! Front-page feed: category filter, sort by last comment vs newest,
//! cursor pagination, and last_post_at bumping when a thread gets a
//! reply.

mod support;

use lethe_types::feed::*;
use serde_json::json;
use support::browser;

async fn create_thread(
    client: &reqwest::Client,
    base_url: &str,
    pow_bits: u32,
    board: &str,
    title: &str,
) -> String {
    let nonce = browser::solve_pow(board.as_bytes(), title, pow_bits);
    let resp: lethe_types::posts::CreateThreadResp = client
        .post(format!("{base_url}/api/threads"))
        .json(&json!({
            "board_id": board,
            "title": title,
            "body": title,
            "pow_nonce": browser::b64(&nonce),
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    resp.thread_id
}

async fn reply(
    client: &reqwest::Client,
    base_url: &str,
    pow_bits: u32,
    thread_id_b64: &str,
    body: &str,
) {
    let thread_id = browser::unb64(thread_id_b64);
    let nonce = browser::solve_pow(&thread_id, body, pow_bits);
    let resp = client
        .post(format!("{base_url}/api/threads/{thread_id_b64}/posts"))
        .json(&json!({ "body": body, "pow_nonce": browser::b64(&nonce) }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "reply: {:?}", resp);
}

#[tokio::test]
async fn default_feed_lists_all_categories() {
    let s = support::spawn().await;
    let client = reqwest::Client::new();
    let g = create_thread(&client, &s.base_url, s.pow_bits, "government", "policy").await;
    let e = create_thread(&client, &s.base_url, s.pow_bits, "economy", "rates").await;
    let t = create_thread(&client, &s.base_url, s.pow_bits, "science_tech", "fusion").await;
    let o = create_thread(&client, &s.base_url, s.pow_bits, "all_other", "music").await;

    let resp: FeedResp = client
        .get(format!("{}/api/feed", s.base_url))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let ids: std::collections::HashSet<&str> =
        resp.items.iter().map(|i| i.thread_id.as_str()).collect();
    assert!(ids.contains(g.as_str()));
    assert!(ids.contains(e.as_str()));
    assert!(ids.contains(t.as_str()));
    assert!(ids.contains(o.as_str()));
}

#[tokio::test]
async fn category_filter_excludes_other_boards() {
    let s = support::spawn().await;
    let client = reqwest::Client::new();
    create_thread(&client, &s.base_url, s.pow_bits, "government", "filter-test-gov").await;
    create_thread(&client, &s.base_url, s.pow_bits, "economy", "filter-test-econ").await;

    let resp: FeedResp = client
        .get(format!("{}/api/feed?cat=government", s.base_url))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(!resp.items.is_empty());
    for i in &resp.items {
        assert_eq!(i.board_id, "government");
    }
}

#[tokio::test]
async fn legacy_general_board_excluded_from_feed() {
    let s = support::spawn().await;
    let client = reqwest::Client::new();
    // 'general' still exists for back-compat tests but must be hidden
    // from the new front-page feed.
    create_thread(&client, &s.base_url, s.pow_bits, "general", "old-school").await;
    create_thread(&client, &s.base_url, s.pow_bits, "economy", "in-feed").await;

    let resp: FeedResp = client
        .get(format!("{}/api/feed", s.base_url))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    for i in &resp.items {
        assert_ne!(i.board_id, "general", "general must not appear in feed");
    }
}

#[tokio::test]
async fn last_post_at_bumps_on_reply_and_resorts() {
    let s = support::spawn().await;
    let client = reqwest::Client::new();
    let older = create_thread(&client, &s.base_url, s.pow_bits, "economy", "older").await;
    // Sleep so the next thread lands in a strictly later 60s bucket.
    tokio::time::sleep(std::time::Duration::from_millis(60_500)).await;
    let newer = create_thread(&client, &s.base_url, s.pow_bits, "economy", "newer").await;

    // Default sort is last_comment, so right now `newer` is on top.
    let resp: FeedResp = client
        .get(format!("{}/api/feed?cat=economy", s.base_url))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(resp.items.first().unwrap().thread_id, newer);

    // Reply on `older` and wait past the bucket; it should now be on top.
    tokio::time::sleep(std::time::Duration::from_millis(60_500)).await;
    reply(&client, &s.base_url, s.pow_bits, &older, "fresh comment").await;

    let resp: FeedResp = client
        .get(format!("{}/api/feed?cat=economy", s.base_url))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(resp.items.first().unwrap().thread_id, older);

    // 'newest' sort, however, still puts `newer` first.
    let resp: FeedResp = client
        .get(format!("{}/api/feed?cat=economy&sort=newest", s.base_url))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(resp.items.first().unwrap().thread_id, newer);
}

#[tokio::test]
async fn unknown_category_returns_empty() {
    let s = support::spawn().await;
    let client = reqwest::Client::new();
    create_thread(&client, &s.base_url, s.pow_bits, "economy", "unknown-cat-test").await;
    let resp: FeedResp = client
        .get(format!("{}/api/feed?cat=does_not_exist", s.base_url))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(resp.items.is_empty());
}

#[tokio::test]
async fn post_count_matches_post_count_on_thread() {
    let s = support::spawn().await;
    let client = reqwest::Client::new();
    let t = create_thread(&client, &s.base_url, s.pow_bits, "economy", "counter").await;
    reply(&client, &s.base_url, s.pow_bits, &t, "first reply").await;
    reply(&client, &s.base_url, s.pow_bits, &t, "second reply").await;

    let resp: FeedResp = client
        .get(format!("{}/api/feed?cat=economy", s.base_url))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let item = resp.items.iter().find(|i| i.thread_id == t).unwrap();
    assert_eq!(item.post_count, 3);
}
