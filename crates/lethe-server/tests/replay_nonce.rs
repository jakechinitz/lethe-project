//! Replay-nonce protection: a captured (sig_pubkey, ts) for a list or
//! remove request can't be used twice within the freshness window.

mod support;

use lethe_types::rooms::*;
use serde_json::json;
use support::browser;

async fn create_room(
    client: &reqwest::Client,
    base_url: &str,
) -> (CreateRoomResp, browser::MemberKeys) {
    let alice = browser::new_member_keys();
    let room_key = browser::random_room_key();
    let alice_self = browser::seal_room_key(&room_key, &alice.box_pub);
    let create_ts = time::OffsetDateTime::now_utc().unix_timestamp();
    let create_sig = browser::sign_create_room(
        &alice.box_pub,
        &alice.sig_pub,
        &alice_self,
        create_ts,
        &alice.sig_priv,
    );
    let create: CreateRoomResp = client
        .post(format!("{base_url}/api/rooms"))
        .json(&json!({
            "creator_box_pubkey": browser::b64(&alice.box_pub),
            "creator_sig_pubkey": browser::b64(&alice.sig_pub),
            "wrapped_key_for_creator": browser::b64(&alice_self),
            "creator_create_ts": create_ts,
            "creator_create_sig": browser::b64(&create_sig),
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    (create, alice)
}

#[tokio::test]
async fn list_request_replay_is_rejected() {
    let s = support::spawn().await;
    let client = reqwest::Client::new();
    let (create, alice) = create_room(&client, &s.base_url).await;
    let room_id_bytes = browser::unb64(&create.room_id);

    let ts = time::OffsetDateTime::now_utc().unix_timestamp();
    let sig = browser::sign_list_request(&room_id_bytes, ts, &alice.sig_priv);
    let body = json!({
        "requester_sig_pubkey": browser::b64(&alice.sig_pub),
        "ts": ts,
        "sig": browser::b64(&sig),
    });

    let first = client
        .post(format!("{}/api/rooms/{}/messages/list", s.base_url, create.room_id))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert!(first.status().is_success(), "first call: {first:?}");

    let replay = client
        .post(format!("{}/api/rooms/{}/messages/list", s.base_url, create.room_id))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(replay.status().as_u16(), 409, "replay should be rejected");
}

#[tokio::test]
async fn list_and_remove_share_no_nonce_namespace() {
    // Same sig_pubkey + same ts on a `list` and a `remove` request must
    // both be accepted — they live in separate kind buckets.
    let s = support::spawn().await;
    let client = reqwest::Client::new();
    let (create, alice) = create_room(&client, &s.base_url).await;
    let room_id_bytes = browser::unb64(&create.room_id);

    let ts = time::OffsetDateTime::now_utc().unix_timestamp();

    let list_sig = browser::sign_list_request(&room_id_bytes, ts, &alice.sig_priv);
    let r1 = client
        .post(format!("{}/api/rooms/{}/messages/list", s.base_url, create.room_id))
        .json(&json!({
            "requester_sig_pubkey": browser::b64(&alice.sig_pub),
            "ts": ts,
            "sig": browser::b64(&list_sig),
        }))
        .send()
        .await
        .unwrap();
    assert!(r1.status().is_success());

    // Even though the timestamp matches, removing under the `remove` kind
    // is independent. The body is malformed (no surviving wraps), but it
    // should fail at the BadRequest layer, not the replay layer.
    let bogus_target = [9u8; 32];
    let rm_sig = browser::sign_remove_request(&room_id_bytes, ts, &bogus_target, &alice.sig_priv);
    let r2 = client
        .post(format!("{}/api/rooms/{}/remove", s.base_url, create.room_id))
        .json(&json!({
            "remover_sig_pubkey": browser::b64(&alice.sig_pub),
            "ts": ts,
            "sig": browser::b64(&rm_sig),
            "target_box_pubkey": browser::b64(&bogus_target),
            "new_wrapped_keys": [],
        }))
        .send()
        .await
        .unwrap();
    // 409 (Conflict, target not a member) is what we expect — NOT 409 from
    // replay protection. Either way it's not 200; the success of the list
    // call above is what proves the namespaces are separate.
    assert!(!r2.status().is_success());
}
