//! Self-leave: a member removes themselves from a room. After leaving:
//!   - they cannot post,
//!   - they cannot list messages (history-gate path returns 403),
//!   - their member row shows `removed_at`,
//!   - leaving twice is rejected.

mod support;

use lethe_types::rooms::*;
use serde_json::json;
use support::browser;

async fn create_room_with_two_members(
    client: &reqwest::Client,
    base_url: &str,
) -> (CreateRoomResp, browser::MemberKeys, browser::MemberKeys, [u8; 32]) {
    let alice = browser::new_member_keys();
    let room_key = browser::random_room_key();
    let alice_self = browser::seal_room_key(&room_key, &alice.box_pub);
    let create: CreateRoomResp = client
        .post(format!("{base_url}/api/rooms"))
        .json(&json!({
            "creator_box_pubkey": browser::b64(&alice.box_pub),
            "creator_sig_pubkey": browser::b64(&alice.sig_pub),
            "wrapped_key_for_creator": browser::b64(&alice_self),
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let bob = browser::new_member_keys();
    client
        .post(format!("{base_url}/api/rooms/by-invite/{}/join", create.invite_code))
        .json(&json!({
            "box_pubkey": browser::b64(&bob.box_pub),
            "sig_pubkey": browser::b64(&bob.sig_pub),
        }))
        .send()
        .await
        .unwrap();
    let bob_wrapped = browser::seal_room_key(&room_key, &bob.box_pub);
    client
        .post(format!("{base_url}/api/rooms/{}/wrap", create.room_id))
        .json(&json!({
            "for_box_pubkey": browser::b64(&bob.box_pub),
            "wrapped_key": browser::b64(&bob_wrapped),
            "inviter_box_pubkey": browser::b64(&alice.box_pub),
        }))
        .send()
        .await
        .unwrap();

    (create, alice, bob, room_key)
}

#[tokio::test]
async fn member_can_leave_and_is_locked_out() {
    let s = support::spawn().await;
    let client = reqwest::Client::new();
    let (create, _alice, bob, room_key) =
        create_room_with_two_members(&client, &s.base_url).await;
    let room_id_bytes = browser::unb64(&create.room_id);

    let ts = time::OffsetDateTime::now_utc().unix_timestamp();
    let leave_sig = browser::sign_leave_request(&room_id_bytes, ts, &bob.sig_priv);
    let leave_resp = client
        .post(format!("{}/api/rooms/{}/leave", s.base_url, create.room_id))
        .json(&json!({
            "sig_pubkey": browser::b64(&bob.sig_pub),
            "ts": ts,
            "sig": browser::b64(&leave_sig),
        }))
        .send()
        .await
        .unwrap();
    assert!(leave_resp.status().is_success(), "leave: {leave_resp:?}");

    // Bob now cannot post.
    let (n, ct) = browser::encrypt_message("after leaving", &room_id_bytes, &room_key);
    let post_sig =
        browser::sign_message_envelope(&room_id_bytes, &n, &ct, &bob.sig_priv);
    let resp = client
        .post(format!("{}/api/rooms/{}/messages", s.base_url, create.room_id))
        .json(&json!({
            "sender_sig_pubkey": browser::b64(&bob.sig_pub),
            "nonce": browser::b64(&n),
            "ciphertext": browser::b64(&ct),
            "sender_sig": browser::b64(&post_sig),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 403);

    // Bob cannot list messages either — different ts so we don't trip the
    // replay-nonce table (but the result we want is 403, not 409).
    let ts2 = time::OffsetDateTime::now_utc().unix_timestamp() + 1;
    let list_sig = browser::sign_list_request(&room_id_bytes, ts2, &bob.sig_priv);
    let resp = client
        .post(format!("{}/api/rooms/{}/messages/list", s.base_url, create.room_id))
        .json(&json!({
            "requester_sig_pubkey": browser::b64(&bob.sig_pub),
            "ts": ts2,
            "sig": browser::b64(&list_sig),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 403);

    // members endpoint shows him as removed.
    let members: MembersResp = client
        .get(format!("{}/api/rooms/{}/members", s.base_url, create.room_id))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let bob_b64 = browser::b64(&bob.box_pub);
    let row = members.members.iter().find(|m| m.box_pubkey == bob_b64).unwrap();
    assert!(row.removed_at.is_some());
}

#[tokio::test]
async fn leaving_twice_is_rejected() {
    let s = support::spawn().await;
    let client = reqwest::Client::new();
    let (create, _alice, bob, _) = create_room_with_two_members(&client, &s.base_url).await;
    let room_id_bytes = browser::unb64(&create.room_id);

    let ts = time::OffsetDateTime::now_utc().unix_timestamp();
    let leave_sig = browser::sign_leave_request(&room_id_bytes, ts, &bob.sig_priv);
    let body = json!({
        "sig_pubkey": browser::b64(&bob.sig_pub),
        "ts": ts,
        "sig": browser::b64(&leave_sig),
    });
    let r1 = client
        .post(format!("{}/api/rooms/{}/leave", s.base_url, create.room_id))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert!(r1.status().is_success());

    // Same signature → replay-nonce conflict. (We test this rather than
    // a fresh signature for an already-removed member because the dedup
    // catches it first; either way it's a 4xx.)
    let r2 = client
        .post(format!("{}/api/rooms/{}/leave", s.base_url, create.room_id))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert!(!r2.status().is_success());
}

#[tokio::test]
async fn non_member_cannot_leave() {
    let s = support::spawn().await;
    let client = reqwest::Client::new();
    let (create, _alice, _bob, _) = create_room_with_two_members(&client, &s.base_url).await;
    let room_id_bytes = browser::unb64(&create.room_id);

    let stranger = browser::new_member_keys();
    let ts = time::OffsetDateTime::now_utc().unix_timestamp();
    let sig = browser::sign_leave_request(&room_id_bytes, ts, &stranger.sig_priv);
    let resp = client
        .post(format!("{}/api/rooms/{}/leave", s.base_url, create.room_id))
        .json(&json!({
            "sig_pubkey": browser::b64(&stranger.sig_pub),
            "ts": ts,
            "sig": browser::b64(&sig),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 403);
}
