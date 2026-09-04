//! Member removal + room rekey:
//!   - the room creator can remove a member and rotate the key in one
//!     atomic call,
//!   - the removed member's old wrapped key still decrypts the
//!     pre-removal ciphertext (because they had it locally),
//!   - they cannot post or list messages after removal,
//!   - they cannot decrypt new messages encrypted under the new key,
//!   - non-creators cannot remove anyone.

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

    let bob = browser::new_member_keys();
    client
        .post(format!(
            "{base_url}/api/rooms/by-invite/{}/join",
            create.invite_code
        ))
        .json(&json!({
            "box_pubkey": browser::b64(&bob.box_pub),
            "sig_pubkey": browser::b64(&bob.sig_pub),
        }))
        .send()
        .await
        .unwrap();
    let bob_wrapped = browser::seal_room_key(&room_key, &bob.box_pub);
    let room_id_bytes = browser::unb64(&create.room_id);
    let wrap_ts = time::OffsetDateTime::now_utc().unix_timestamp();
    let wrap_sig = browser::sign_wrap_request(
        &room_id_bytes,
        &bob.box_pub,
        &bob_wrapped,
        wrap_ts,
        &alice.sig_priv,
    );
    client
        .post(format!("{base_url}/api/rooms/{}/wrap", create.room_id))
        .json(&json!({
            "for_box_pubkey": browser::b64(&bob.box_pub),
            "wrapped_key": browser::b64(&bob_wrapped),
            "inviter_box_pubkey": browser::b64(&alice.box_pub),
            "inviter_sig_pubkey": browser::b64(&alice.sig_pub),
            "inviter_ts": wrap_ts,
            "inviter_sig": browser::b64(&wrap_sig),
        }))
        .send()
        .await
        .unwrap();

    (create, alice, bob, room_key)
}

#[tokio::test]
async fn creator_removes_member_and_rekeys() {
    let s = support::spawn().await;
    let client = reqwest::Client::new();
    let (create, alice, bob, old_key) = create_room_with_two_members(&client, &s.base_url).await;
    let room_id_bytes = browser::unb64(&create.room_id);

    // Alice (creator) is the only surviving member, plus Charlie whom we'll
    // add now to make the rekey actually exercise the multi-member case.
    let charlie = browser::new_member_keys();
    client
        .post(format!(
            "{}/api/rooms/by-invite/{}/join",
            s.base_url, create.invite_code
        ))
        .json(&json!({
            "box_pubkey": browser::b64(&charlie.box_pub),
            "sig_pubkey": browser::b64(&charlie.sig_pub),
        }))
        .send()
        .await
        .unwrap();
    let charlie_wrapped = browser::seal_room_key(&old_key, &charlie.box_pub);
    let charlie_wrap_ts = time::OffsetDateTime::now_utc().unix_timestamp();
    let charlie_wrap_sig = browser::sign_wrap_request(
        &room_id_bytes,
        &charlie.box_pub,
        &charlie_wrapped,
        charlie_wrap_ts,
        &alice.sig_priv,
    );
    client
        .post(format!("{}/api/rooms/{}/wrap", s.base_url, create.room_id))
        .json(&json!({
            "for_box_pubkey": browser::b64(&charlie.box_pub),
            "wrapped_key": browser::b64(&charlie_wrapped),
            "inviter_box_pubkey": browser::b64(&alice.box_pub),
            "inviter_sig_pubkey": browser::b64(&alice.sig_pub),
            "inviter_ts": charlie_wrap_ts,
            "inviter_sig": browser::b64(&charlie_wrap_sig),
        }))
        .send()
        .await
        .unwrap();

    // Pre-removal: Bob can still send.
    let (n_pre, ct_pre) = browser::encrypt_message("before removal", &room_id_bytes, &old_key);
    let s_pre = browser::sign_message_envelope(&room_id_bytes, &n_pre, &ct_pre, &bob.sig_priv);
    let resp = client
        .post(format!("{}/api/rooms/{}/messages", s.base_url, create.room_id))
        .json(&json!({
            "sender_sig_pubkey": browser::b64(&bob.sig_pub),
            "nonce": browser::b64(&n_pre),
            "ciphertext": browser::b64(&ct_pre),
            "sender_sig": browser::b64(&s_pre),
        }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());

    // Alice removes Bob, rotating to a fresh room key.
    let new_key = browser::random_room_key();
    let alice_new_wrap = browser::seal_room_key(&new_key, &alice.box_pub);
    let charlie_new_wrap = browser::seal_room_key(&new_key, &charlie.box_pub);
    let ts = time::OffsetDateTime::now_utc().unix_timestamp();
    let sig = browser::sign_remove_request(&room_id_bytes, ts, &bob.box_pub, &alice.sig_priv);
    let remove_resp = client
        .post(format!("{}/api/rooms/{}/remove", s.base_url, create.room_id))
        .json(&json!({
            "remover_sig_pubkey": browser::b64(&alice.sig_pub),
            "ts": ts,
            "sig": browser::b64(&sig),
            "target_box_pubkey": browser::b64(&bob.box_pub),
            "new_wrapped_keys": [
                {
                    "for_box_pubkey": browser::b64(&alice.box_pub),
                    "wrapped_key": browser::b64(&alice_new_wrap),
                },
                {
                    "for_box_pubkey": browser::b64(&charlie.box_pub),
                    "wrapped_key": browser::b64(&charlie_new_wrap),
                },
            ],
        }))
        .send()
        .await
        .unwrap();
    assert!(remove_resp.status().is_success(), "remove: {remove_resp:?}");
    let body: RemoveMemberResp = remove_resp.json().await.unwrap();
    assert_eq!(body.current_epoch, 1);

    // Bob can no longer post (server says 403).
    let (n_post, ct_post) =
        browser::encrypt_message("after removal", &room_id_bytes, &old_key);
    let s_post =
        browser::sign_message_envelope(&room_id_bytes, &n_post, &ct_post, &bob.sig_priv);
    let resp = client
        .post(format!("{}/api/rooms/{}/messages", s.base_url, create.room_id))
        .json(&json!({
            "sender_sig_pubkey": browser::b64(&bob.sig_pub),
            "nonce": browser::b64(&n_post),
            "ciphertext": browser::b64(&ct_post),
            "sender_sig": browser::b64(&s_post),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 403);

    // Bob can no longer list messages.
    let bob_list_sig = browser::sign_list_request(&room_id_bytes, ts, &bob.sig_priv);
    let resp = client
        .post(format!(
            "{}/api/rooms/{}/messages/list",
            s.base_url, create.room_id
        ))
        .json(&json!({
            "requester_sig_pubkey": browser::b64(&bob.sig_pub),
            "ts": ts,
            "sig": browser::b64(&bob_list_sig),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 403);

    // Charlie can: he gets the new wrapped key, unwraps to recover the
    // new room key, and can decrypt new messages.
    let mts = time::OffsetDateTime::now_utc().unix_timestamp();
    let msig = browser::sign_members_request(&room_id_bytes, mts, &charlie.sig_priv);
    let members: MembersResp = client
        .post(format!("{}/api/rooms/{}/members", s.base_url, create.room_id))
        .json(&json!({
            "requester_sig_pubkey": browser::b64(&charlie.sig_pub),
            "ts": mts,
            "sig": browser::b64(&msig),
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(members.current_epoch, 1);
    let charlie_b64 = browser::b64(&charlie.box_pub);
    let charlie_row = members.members.iter().find(|m| m.box_pubkey == charlie_b64).unwrap();
    let new_wrapped_for_charlie = browser::unb64(charlie_row.wrapped_key.as_ref().unwrap());
    let charlie_recovered_new =
        browser::open_room_key(&new_wrapped_for_charlie, &charlie.box_pub, &charlie.box_priv);
    assert_eq!(charlie_recovered_new, new_key);

    // Alice sends a new-epoch message; Charlie decrypts with the new key.
    let (n2, ct2) = browser::encrypt_message("post-rekey", &room_id_bytes, &new_key);
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
    let charlie_list_sig = browser::sign_list_request(&room_id_bytes, ts, &charlie.sig_priv);
    let resp: MessagesResp = client
        .post(format!(
            "{}/api/rooms/{}/messages/list",
            s.base_url, create.room_id
        ))
        .json(&json!({
            "requester_sig_pubkey": browser::b64(&charlie.sig_pub),
            "ts": ts,
            "sig": browser::b64(&charlie_list_sig),
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let last = resp.messages.last().unwrap();
    let n: [u8; 24] = browser::unb64(&last.nonce).try_into().unwrap();
    let ct = browser::unb64(&last.ciphertext);
    let pt = browser::decrypt_message(&ct, &n, &room_id_bytes, &charlie_recovered_new);
    assert_eq!(std::str::from_utf8(&pt).unwrap(), "post-rekey");
}

#[tokio::test]
async fn non_creator_cannot_remove() {
    let s = support::spawn().await;
    let client = reqwest::Client::new();
    let (create, alice, bob, _) = create_room_with_two_members(&client, &s.base_url).await;
    let room_id_bytes = browser::unb64(&create.room_id);

    // Bob (not the creator) tries to remove Alice. Even with a perfectly
    // valid signature he must be rejected.
    let ts = time::OffsetDateTime::now_utc().unix_timestamp();
    let sig = browser::sign_remove_request(&room_id_bytes, ts, &alice.box_pub, &bob.sig_priv);
    let resp = client
        .post(format!("{}/api/rooms/{}/remove", s.base_url, create.room_id))
        .json(&json!({
            "remover_sig_pubkey": browser::b64(&bob.sig_pub),
            "ts": ts,
            "sig": browser::b64(&sig),
            "target_box_pubkey": browser::b64(&alice.box_pub),
            "new_wrapped_keys": [],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 403);
}

#[tokio::test]
async fn rejects_incomplete_wrap_set() {
    let s = support::spawn().await;
    let client = reqwest::Client::new();
    let (create, alice, bob, _) = create_room_with_two_members(&client, &s.base_url).await;
    let room_id_bytes = browser::unb64(&create.room_id);

    // Alice removes Bob but supplies NO new wraps — Alice herself is a
    // surviving member who needs a fresh wrap. Server must reject.
    let ts = time::OffsetDateTime::now_utc().unix_timestamp();
    let sig = browser::sign_remove_request(&room_id_bytes, ts, &bob.box_pub, &alice.sig_priv);
    let resp = client
        .post(format!("{}/api/rooms/{}/remove", s.base_url, create.room_id))
        .json(&json!({
            "remover_sig_pubkey": browser::b64(&alice.sig_pub),
            "ts": ts,
            "sig": browser::b64(&sig),
            "target_box_pubkey": browser::b64(&bob.box_pub),
            "new_wrapped_keys": [],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 400);
}
