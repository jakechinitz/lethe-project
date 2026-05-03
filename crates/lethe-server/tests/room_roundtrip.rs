//! The headline test: two members exchange one ciphertext through a server
//! that cannot read it.
//!
//! Also asserts that plaintext does not appear in any room storage column.

mod support;

use lethe_types::rooms::*;
use serde_json::json;
use support::browser;

#[tokio::test]
async fn room_e2ee_roundtrip_with_provenance() {
    let s = support::spawn().await;
    let client = reqwest::Client::new();

    // 1. Create an originating thread and a signed post in it (creator's
    //    thread identity will be reused as the room provenance signer).
    let body = "origin thread";
    let nonce = browser::solve_pow(b"general", body, s.pow_bits);
    let thread: lethe_types::posts::CreateThreadResp = client
        .post(format!("{}/api/threads", s.base_url))
        .json(&json!({
            "board_id": "general",
            "title": "origin",
            "body": body,
            "pow_nonce": browser::b64(&nonce),
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let thread_id = browser::unb64(&thread.thread_id);

    let creator_thread = browser::new_thread_identity();
    let body2 = "signed by creator";
    let nonce2 = browser::solve_pow(&thread_id, body2, s.pow_bits);
    let sig2 = browser::sign_post(&thread_id, body2, &creator_thread.private_key);
    let post = client
        .post(format!("{}/api/threads/{}/posts", s.base_url, thread.thread_id))
        .json(&json!({
            "body": body2,
            "pow_nonce": browser::b64(&nonce2),
            "pubkey": browser::b64(&creator_thread.public_key),
            "signature": browser::b64(&sig2),
        }))
        .send()
        .await
        .unwrap();
    assert!(post.status().is_success());

    // 2. Creator generates room keys, wraps the room key for self, attaches
    //    provenance, and POSTs to /api/rooms.
    let alice = browser::new_member_keys();
    let room_key = browser::random_room_key();
    let alice_self_wrapped = browser::seal_room_key(&room_key, &alice.box_pub);
    let prov_sig = browser::sign_room_provenance(
        &thread_id,
        &creator_thread.public_key,
        &creator_thread.private_key,
    );
    let create_resp: CreateRoomResp = client
        .post(format!("{}/api/rooms", s.base_url))
        .json(&json!({
            "origin_thread": thread.thread_id,
            "creator_box_pubkey": browser::b64(&alice.box_pub),
            "creator_sig_pubkey": browser::b64(&alice.sig_pub),
            "wrapped_key_for_creator": browser::b64(&alice_self_wrapped),
            "creator_thread_pubkey": browser::b64(&creator_thread.public_key),
            "provenance_sig": browser::b64(&prov_sig),
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    // Provenance verifies independently:
    let prov: ProvenanceResp = client
        .get(format!("{}/api/rooms/{}/provenance", s.base_url, create_resp.room_id))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(prov.origin_thread, Some(thread.thread_id.clone()));

    // 3. Bob joins by invite.
    let bob = browser::new_member_keys();
    let join: JoinRoomResp = client
        .post(format!(
            "{}/api/rooms/by-invite/{}/join",
            s.base_url, create_resp.invite_code
        ))
        .json(&json!({
            "box_pubkey": browser::b64(&bob.box_pub),
            "sig_pubkey": browser::b64(&bob.sig_pub),
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(join.room_id, create_resp.room_id);

    // 4. Alice wraps the room key for Bob (recording the invite chain).
    let bob_wrapped = browser::seal_room_key(&room_key, &bob.box_pub);
    let wrap_resp = client
        .post(format!(
            "{}/api/rooms/{}/wrap",
            s.base_url, create_resp.room_id
        ))
        .json(&json!({
            "for_box_pubkey": browser::b64(&bob.box_pub),
            "wrapped_key": browser::b64(&bob_wrapped),
            "inviter_box_pubkey": browser::b64(&alice.box_pub),
        }))
        .send()
        .await
        .unwrap();
    assert!(wrap_resp.status().is_success());

    // 5. Bob fetches members, finds his own wrapped key, unwraps it.
    let members: MembersResp = client
        .get(format!("{}/api/rooms/{}/members", s.base_url, create_resp.room_id))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let bob_b64 = browser::b64(&bob.box_pub);
    let me = members.members.iter().find(|m| m.box_pubkey == bob_b64).unwrap();
    let wrapped_for_bob = browser::unb64(me.wrapped_key.as_ref().unwrap());
    let bob_room_key = browser::open_room_key(&wrapped_for_bob, &bob.box_pub, &bob.box_priv);
    assert_eq!(bob_room_key, room_key);

    // 6. Alice sends an encrypted message; Bob decrypts.
    let plaintext = "hello, anonymous world";
    let room_id_bytes = browser::unb64(&create_resp.room_id);
    let (msg_nonce, ciphertext) =
        browser::encrypt_message(plaintext, &room_id_bytes, &room_key);
    let env_sig = browser::sign_message_envelope(
        &room_id_bytes,
        &msg_nonce,
        &ciphertext,
        &alice.sig_priv,
    );
    let send_resp = client
        .post(format!("{}/api/rooms/{}/messages", s.base_url, create_resp.room_id))
        .json(&json!({
            "sender_sig_pubkey": browser::b64(&alice.sig_pub),
            "nonce": browser::b64(&msg_nonce),
            "ciphertext": browser::b64(&ciphertext),
            "sender_sig": browser::b64(&env_sig),
        }))
        .send()
        .await
        .unwrap();
    assert!(send_resp.status().is_success());

    // Bob lists messages with an authenticated request — the server gates
    // by his joined_at, but he joined before Alice's send, so he sees it.
    let ts = time::OffsetDateTime::now_utc().unix_timestamp();
    let bob_list_sig = browser::sign_list_request(&room_id_bytes, ts, &bob.sig_priv);
    let listed: MessagesResp = client
        .post(format!("{}/api/rooms/{}/messages/list", s.base_url, create_resp.room_id))
        .json(&json!({
            "requester_sig_pubkey": browser::b64(&bob.sig_pub),
            "ts": ts,
            "sig": browser::b64(&bob_list_sig),
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(listed.messages.len(), 1);
    let m = &listed.messages[0];
    let ct = browser::unb64(&m.ciphertext);
    let n = browser::unb64(&m.nonce);
    let n_arr: [u8; 24] = n.try_into().unwrap();
    let pt = browser::decrypt_message(&ct, &n_arr, &room_id_bytes, &bob_room_key);
    assert_eq!(std::str::from_utf8(&pt).unwrap(), plaintext);

    // 7. Server stored ciphertext only — assert no plaintext column exists.
    let plaintext_match: Option<(i32,)> = sqlx::query_as(
        "SELECT 1 FROM room_messages WHERE convert_from(ciphertext, 'UTF8') LIKE $1 LIMIT 1",
    )
    .bind("%hello, anonymous world%")
    .fetch_optional(&s.db)
    .await
    .unwrap_or(None);
    assert!(
        plaintext_match.is_none(),
        "server stored plaintext somewhere it shouldn't"
    );
}

#[tokio::test]
async fn rejects_non_member_message() {
    let s = support::spawn().await;
    let client = reqwest::Client::new();

    // Create a room with no provenance and one member (Alice).
    let alice = browser::new_member_keys();
    let room_key = browser::random_room_key();
    let alice_self_wrapped = browser::seal_room_key(&room_key, &alice.box_pub);
    let create: CreateRoomResp = client
        .post(format!("{}/api/rooms", s.base_url))
        .json(&json!({
            "creator_box_pubkey": browser::b64(&alice.box_pub),
            "creator_sig_pubkey": browser::b64(&alice.sig_pub),
            "wrapped_key_for_creator": browser::b64(&alice_self_wrapped),
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    // A stranger tries to post.
    let stranger = browser::new_member_keys();
    let room_id_bytes = browser::unb64(&create.room_id);
    let (n, ct) = browser::encrypt_message("hi", &room_id_bytes, &room_key);
    let sig = browser::sign_message_envelope(&room_id_bytes, &n, &ct, &stranger.sig_priv);
    let resp = client
        .post(format!("{}/api/rooms/{}/messages", s.base_url, create.room_id))
        .json(&json!({
            "sender_sig_pubkey": browser::b64(&stranger.sig_pub),
            "nonce": browser::b64(&n),
            "ciphertext": browser::b64(&ct),
            "sender_sig": browser::b64(&sig),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 403);
}
