//! Room size cap: the 50th member is the last one accepted; the 51st
//! gets a 409. Re-joining as an existing member is idempotent.

mod support;

use lethe_types::rooms::*;
use serde_json::json;
use support::browser;

#[tokio::test]
async fn room_caps_at_fifty_active_members() {
    let s = support::spawn().await;
    let client = reqwest::Client::new();

    // Creator counts as member #1.
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
        .post(format!("{}/api/rooms", s.base_url))
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

    // Members #2 .. #50: forty-nine successful joins.
    let mut members = Vec::with_capacity(49);
    for _ in 0..49 {
        let m = browser::new_member_keys();
        let resp = client
            .post(format!(
                "{}/api/rooms/by-invite/{}/join",
                s.base_url, create.invite_code
            ))
            .json(&json!({
                "box_pubkey": browser::b64(&m.box_pub),
                "sig_pubkey": browser::b64(&m.sig_pub),
            }))
            .send()
            .await
            .unwrap();
        assert!(resp.status().is_success());
        members.push(m);
    }

    // The 51st should be rejected with Conflict.
    let too_many = browser::new_member_keys();
    let resp = client
        .post(format!(
            "{}/api/rooms/by-invite/{}/join",
            s.base_url, create.invite_code
        ))
        .json(&json!({
            "box_pubkey": browser::b64(&too_many.box_pub),
            "sig_pubkey": browser::b64(&too_many.sig_pub),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 409);

    // Re-joining as one of the existing members is still allowed.
    let same = &members[0];
    let resp = client
        .post(format!(
            "{}/api/rooms/by-invite/{}/join",
            s.base_url, create.invite_code
        ))
        .json(&json!({
            "box_pubkey": browser::b64(&same.box_pub),
            "sig_pubkey": browser::b64(&same.sig_pub),
        }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
}
