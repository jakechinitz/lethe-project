//! History gate: a member who joins late cannot fetch messages that
//! predated their `joined_at`. The server enforces this via a signed
//! list-request and a SQL `created_at >= joined_at` filter.

mod support;

use lethe_types::rooms::*;
use serde_json::json;
use support::browser;

async fn create_room(client: &reqwest::Client, base_url: &str) -> (CreateRoomResp, browser::MemberKeys, [u8; 32]) {
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
    (create, alice, room_key)
}

#[tokio::test]
async fn late_joiner_cannot_see_earlier_messages() {
    let s = support::spawn().await;
    let client = reqwest::Client::new();

    let (create, alice, room_key) = create_room(&client, &s.base_url).await;
    let room_id_bytes = browser::unb64(&create.room_id);

    // Alice posts the "secret history" message before Bob joins.
    let secret = "ancient secret";
    let (n1, ct1) = browser::encrypt_message(secret, &room_id_bytes, &room_key);
    let s1 = browser::sign_message_envelope(&room_id_bytes, &n1, &ct1, &alice.sig_priv);
    client
        .post(format!("{}/api/rooms/{}/messages", s.base_url, create.room_id))
        .json(&json!({
            "sender_sig_pubkey": browser::b64(&alice.sig_pub),
            "nonce": browser::b64(&n1),
            "ciphertext": browser::b64(&ct1),
            "sender_sig": browser::b64(&s1),
        }))
        .send()
        .await
        .unwrap();

    // Bob's `joined_at` is the day he joins (DATE granularity). To make
    // Alice's first message strictly older than Bob's join, backdate
    // both Alice's joined_at and her message in the database — sleeping
    // wouldn't help since both rows would land on the same calendar
    // date. Alice still sees her message because we keep her joined_at
    // earlier than the message.
    sqlx::query(
        "UPDATE room_members
         SET joined_at = current_date - interval '2 days'
         WHERE room_id = $1",
    )
    .bind(&room_id_bytes[..])
    .execute(&s.db)
    .await
    .unwrap();
    sqlx::query(
        "UPDATE room_messages
         SET created_at = current_date - interval '1 day'
         WHERE room_id = $1",
    )
    .bind(&room_id_bytes[..])
    .execute(&s.db)
    .await
    .unwrap();

    // Bob joins.
    let bob = browser::new_member_keys();
    client
        .post(format!(
            "{}/api/rooms/by-invite/{}/join",
            s.base_url, create.invite_code
        ))
        .json(&json!({
            "box_pubkey": browser::b64(&bob.box_pub),
            "sig_pubkey": browser::b64(&bob.sig_pub),
        }))
        .send()
        .await
        .unwrap();

    let bob_wrapped = browser::seal_room_key(&room_key, &bob.box_pub);
    client
        .post(format!("{}/api/rooms/{}/wrap", s.base_url, create.room_id))
        .json(&json!({
            "for_box_pubkey": browser::b64(&bob.box_pub),
            "wrapped_key": browser::b64(&bob_wrapped),
            "inviter_box_pubkey": browser::b64(&alice.box_pub),
        }))
        .send()
        .await
        .unwrap();

    // Alice posts a new message AFTER Bob joined. Same-day as Bob's
    // join, which the gate accepts (`created_at >= joined_at`).
    let visible = "post-Bob message";
    let (n2, ct2) = browser::encrypt_message(visible, &room_id_bytes, &room_key);
    let s2 = browser::sign_message_envelope(&room_id_bytes, &n2, &ct2, &alice.sig_priv);
    client
        .post(format!("{}/api/rooms/{}/messages", s.base_url, create.room_id))
        .json(&json!({
            "sender_sig_pubkey": browser::b64(&alice.sig_pub),
            "nonce": browser::b64(&n2),
            "ciphertext": browser::b64(&ct2),
            "sender_sig": browser::b64(&s2),
        }))
        .send()
        .await
        .unwrap();

    // Bob lists messages — should see only the post-join one.
    let ts = time::OffsetDateTime::now_utc().unix_timestamp();
    let bob_sig = browser::sign_list_request(&room_id_bytes, ts, &bob.sig_priv);
    let bob_view: MessagesResp = client
        .post(format!("{}/api/rooms/{}/messages/list", s.base_url, create.room_id))
        .json(&json!({
            "requester_sig_pubkey": browser::b64(&bob.sig_pub),
            "ts": ts,
            "sig": browser::b64(&bob_sig),
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(bob_view.messages.len(), 1, "Bob should only see the post-join message");
    let only = &bob_view.messages[0];
    let only_n: [u8; 24] = browser::unb64(&only.nonce).try_into().unwrap();
    let only_ct = browser::unb64(&only.ciphertext);
    let pt = browser::decrypt_message(&only_ct, &only_n, &room_id_bytes, &room_key);
    assert_eq!(std::str::from_utf8(&pt).unwrap(), visible);

    // Alice (creator) sees both.
    let alice_sig = browser::sign_list_request(&room_id_bytes, ts, &alice.sig_priv);
    let alice_view: MessagesResp = client
        .post(format!("{}/api/rooms/{}/messages/list", s.base_url, create.room_id))
        .json(&json!({
            "requester_sig_pubkey": browser::b64(&alice.sig_pub),
            "ts": ts,
            "sig": browser::b64(&alice_sig),
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(alice_view.messages.len(), 2);
}

#[tokio::test]
async fn list_request_rejects_non_member() {
    let s = support::spawn().await;
    let client = reqwest::Client::new();
    let (create, _alice, _room_key) = create_room(&client, &s.base_url).await;
    let room_id_bytes = browser::unb64(&create.room_id);

    let stranger = browser::new_member_keys();
    let ts = time::OffsetDateTime::now_utc().unix_timestamp();
    let sig = browser::sign_list_request(&room_id_bytes, ts, &stranger.sig_priv);
    let resp = client
        .post(format!("{}/api/rooms/{}/messages/list", s.base_url, create.room_id))
        .json(&json!({
            "requester_sig_pubkey": browser::b64(&stranger.sig_pub),
            "ts": ts,
            "sig": browser::b64(&sig),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 403);
}

#[tokio::test]
async fn list_request_rejects_stale_timestamp() {
    let s = support::spawn().await;
    let client = reqwest::Client::new();
    let (create, alice, _room_key) = create_room(&client, &s.base_url).await;
    let room_id_bytes = browser::unb64(&create.room_id);

    let ts = time::OffsetDateTime::now_utc().unix_timestamp() - 600;
    let sig = browser::sign_list_request(&room_id_bytes, ts, &alice.sig_priv);
    let resp = client
        .post(format!("{}/api/rooms/{}/messages/list", s.base_url, create.room_id))
        .json(&json!({
            "requester_sig_pubkey": browser::b64(&alice.sig_pub),
            "ts": ts,
            "sig": browser::b64(&sig),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 400);
}
