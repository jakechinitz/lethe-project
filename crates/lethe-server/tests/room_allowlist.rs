//! Restricted-invite (allowlist) flow:
//!   - creator restricts the invite to a set of thread-signing pubkeys,
//!   - a holder of one of those keys can prove ownership and join,
//!   - someone without a matching key gets 403,
//!   - someone with a matching key but a stale proof timestamp gets 400.

mod support;

use lethe_types::rooms::*;
use serde_json::json;
use support::browser;

async fn create_thread_and_signers(
    client: &reqwest::Client,
    base_url: &str,
    pow_bits: u32,
    n_signed: usize,
) -> (String, Vec<browser::ThreadIdentity>) {
    let body0 = "thread origin post for allowlist tests";
    let nonce0 = browser::solve_pow(b"economy", body0, pow_bits);
    let thread: lethe_types::posts::CreateThreadResp = client
        .post(format!("{base_url}/api/threads"))
        .json(&json!({
            "board_id": "economy",
            "title": "allowlist",
            "body": body0,
            "pow_nonce": browser::b64(&nonce0),
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let thread_id_bytes = browser::unb64(&thread.thread_id);

    let mut idents = Vec::with_capacity(n_signed);
    for i in 0..n_signed {
        let me = browser::new_thread_identity();
        let body = format!("signed post number {i} from a unique anon");
        let nonce = browser::solve_pow(&thread_id_bytes, &body, pow_bits);
        let sig = browser::sign_post(&thread_id_bytes, &body, &me.private_key);
        let resp = client
            .post(format!("{base_url}/api/threads/{}/posts", thread.thread_id))
            .json(&json!({
                "body": body,
                "pow_nonce": browser::b64(&nonce),
                "pubkey": browser::b64(&me.public_key),
                "signature": browser::b64(&sig),
            }))
            .send()
            .await
            .unwrap();
        assert!(resp.status().is_success(), "signed post: {resp:?}");
        idents.push(me);
    }

    (thread.thread_id, idents)
}

#[tokio::test]
async fn restricted_invite_lets_only_allowlisted_anons_join() {
    let s = support::spawn().await;
    let client = reqwest::Client::new();
    let (thread_id, signers) = create_thread_and_signers(&client, &s.base_url, s.pow_bits, 3).await;
    let (alice_thread, bob_thread, charlie_thread) = (&signers[0], &signers[1], &signers[2]);

    // Alice creates a restricted room. She invites only Bob.
    let alice_member = browser::new_member_keys();
    let room_key = browser::random_room_key();
    let alice_self = browser::seal_room_key(&room_key, &alice_member.box_pub);
    let create: CreateRoomResp = client
        .post(format!("{}/api/rooms", s.base_url))
        .json(&json!({
            "origin_thread": thread_id,
            "creator_box_pubkey": browser::b64(&alice_member.box_pub),
            "creator_sig_pubkey": browser::b64(&alice_member.sig_pub),
            "wrapped_key_for_creator": browser::b64(&alice_self),
            "allowlist_thread_pubkeys": [browser::b64(&bob_thread.public_key)],
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    // Public invite info shows it's restricted.
    let info: InviteInfo = client
        .get(format!(
            "{}/api/rooms/by-invite/{}/info",
            s.base_url, create.invite_code
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(info.restricted);
    assert_eq!(info.origin_thread, Some(thread_id.clone()));
    assert_eq!(
        info.allowlist_thread_pubkeys.as_ref().unwrap().len(),
        1
    );

    // Bob can join with a valid proof.
    let bob_member = browser::new_member_keys();
    let ts = time::OffsetDateTime::now_utc().unix_timestamp();
    let bob_proof = browser::sign_join_proof(
        &create.invite_code,
        &bob_member.box_pub,
        ts,
        &bob_thread.private_key,
    );
    let resp = client
        .post(format!(
            "{}/api/rooms/by-invite/{}/join",
            s.base_url, create.invite_code
        ))
        .json(&json!({
            "box_pubkey": browser::b64(&bob_member.box_pub),
            "sig_pubkey": browser::b64(&bob_member.sig_pub),
            "proof_thread_pubkey": browser::b64(&bob_thread.public_key),
            "proof_ts": ts,
            "proof_sig": browser::b64(&bob_proof),
        }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "bob join: {resp:?}");

    // Charlie (signed in the thread but NOT on the allowlist) is rejected.
    let charlie_member = browser::new_member_keys();
    let charlie_proof = browser::sign_join_proof(
        &create.invite_code,
        &charlie_member.box_pub,
        ts,
        &charlie_thread.private_key,
    );
    let resp = client
        .post(format!(
            "{}/api/rooms/by-invite/{}/join",
            s.base_url, create.invite_code
        ))
        .json(&json!({
            "box_pubkey": browser::b64(&charlie_member.box_pub),
            "sig_pubkey": browser::b64(&charlie_member.sig_pub),
            "proof_thread_pubkey": browser::b64(&charlie_thread.public_key),
            "proof_ts": ts,
            "proof_sig": browser::b64(&charlie_proof),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 403);

    // Stranger with no thread identity at all is rejected too.
    let stranger_member = browser::new_member_keys();
    let resp = client
        .post(format!(
            "{}/api/rooms/by-invite/{}/join",
            s.base_url, create.invite_code
        ))
        .json(&json!({
            "box_pubkey": browser::b64(&stranger_member.box_pub),
            "sig_pubkey": browser::b64(&stranger_member.sig_pub),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 403);

    // Reusing alice's thread identity (not on the allowlist either) — also rejected.
    let mallory_member = browser::new_member_keys();
    let mallory_proof = browser::sign_join_proof(
        &create.invite_code,
        &mallory_member.box_pub,
        ts,
        &alice_thread.private_key,
    );
    let resp = client
        .post(format!(
            "{}/api/rooms/by-invite/{}/join",
            s.base_url, create.invite_code
        ))
        .json(&json!({
            "box_pubkey": browser::b64(&mallory_member.box_pub),
            "sig_pubkey": browser::b64(&mallory_member.sig_pub),
            "proof_thread_pubkey": browser::b64(&alice_thread.public_key),
            "proof_ts": ts,
            "proof_sig": browser::b64(&mallory_proof),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 403);
}

#[tokio::test]
async fn restricted_invite_rejects_stale_proof() {
    let s = support::spawn().await;
    let client = reqwest::Client::new();
    let (thread_id, signers) = create_thread_and_signers(&client, &s.base_url, s.pow_bits, 1).await;
    let bob_thread = &signers[0];

    let alice_member = browser::new_member_keys();
    let room_key = browser::random_room_key();
    let alice_self = browser::seal_room_key(&room_key, &alice_member.box_pub);
    let create: CreateRoomResp = client
        .post(format!("{}/api/rooms", s.base_url))
        .json(&json!({
            "origin_thread": thread_id,
            "creator_box_pubkey": browser::b64(&alice_member.box_pub),
            "creator_sig_pubkey": browser::b64(&alice_member.sig_pub),
            "wrapped_key_for_creator": browser::b64(&alice_self),
            "allowlist_thread_pubkeys": [browser::b64(&bob_thread.public_key)],
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let bob_member = browser::new_member_keys();
    let stale_ts = time::OffsetDateTime::now_utc().unix_timestamp() - 600;
    let proof = browser::sign_join_proof(
        &create.invite_code,
        &bob_member.box_pub,
        stale_ts,
        &bob_thread.private_key,
    );
    let resp = client
        .post(format!(
            "{}/api/rooms/by-invite/{}/join",
            s.base_url, create.invite_code
        ))
        .json(&json!({
            "box_pubkey": browser::b64(&bob_member.box_pub),
            "sig_pubkey": browser::b64(&bob_member.sig_pub),
            "proof_thread_pubkey": browser::b64(&bob_thread.public_key),
            "proof_ts": stale_ts,
            "proof_sig": browser::b64(&proof),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 400);
}

#[tokio::test]
async fn create_with_allowlist_pubkey_not_in_thread_is_rejected() {
    let s = support::spawn().await;
    let client = reqwest::Client::new();
    let (thread_id, _) = create_thread_and_signers(&client, &s.base_url, s.pow_bits, 0).await;

    let alice_member = browser::new_member_keys();
    let room_key = browser::random_room_key();
    let alice_self = browser::seal_room_key(&room_key, &alice_member.box_pub);
    // Random key that never signed anything anywhere.
    let bogus = browser::new_thread_identity();
    let resp = client
        .post(format!("{}/api/rooms", s.base_url))
        .json(&json!({
            "origin_thread": thread_id,
            "creator_box_pubkey": browser::b64(&alice_member.box_pub),
            "creator_sig_pubkey": browser::b64(&alice_member.sig_pub),
            "wrapped_key_for_creator": browser::b64(&alice_self),
            "allowlist_thread_pubkeys": [browser::b64(&bogus.public_key)],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 403);
}
