//! Room vouches end to end:
//!   - /members is member-only (unsigned → 4xx, stranger → 403, member → 200),
//!   - /roster is 404 until the creator publishes epoch 1, then public,
//!   - a member's vouch on a public post is accepted and served verbatim,
//!   - a non-member can't forge one, a stale epoch is rejected, and a
//!     tampered body fails verification,
//!   - the same member vouching twice in one thread shares a key image
//!     (thread-scoped linkability), and gets a different one elsewhere.

mod support;

use lethe_types::{posts::*, rooms::*};
use serde_json::json;
use support::browser;

struct Room {
    create: CreateRoomResp,
    room_id: Vec<u8>,
    alice: browser::MemberKeys,
    bob: browser::MemberKeys,
}

/// Alice creates a room and wraps Bob in, so both are *accepted*.
async fn room_with_two(s: &support::TestServer) -> Room {
    let client = reqwest::Client::new();
    let alice = browser::new_member_keys();
    let room_key = browser::random_room_key();
    let alice_self = browser::seal_room_key(&room_key, &alice.box_pub);
    let ts = time::OffsetDateTime::now_utc().unix_timestamp();
    let sig = browser::sign_create_room(&alice.box_pub, &alice.sig_pub, &alice_self, ts, &alice.sig_priv);
    let create: CreateRoomResp = client
        .post(format!("{}/api/rooms", s.base_url))
        .json(&json!({
            "creator_box_pubkey": browser::b64(&alice.box_pub),
            "creator_sig_pubkey": browser::b64(&alice.sig_pub),
            "wrapped_key_for_creator": browser::b64(&alice_self),
            "creator_create_ts": ts,
            "creator_create_sig": browser::b64(&sig),
        }))
        .send().await.unwrap().json().await.unwrap();
    let room_id = browser::unb64(&create.room_id);

    let bob = browser::new_member_keys();
    client
        .post(format!("{}/api/rooms/by-invite/{}/join", s.base_url, create.invite_code))
        .json(&json!({
            "box_pubkey": browser::b64(&bob.box_pub),
            "sig_pubkey": browser::b64(&bob.sig_pub),
        }))
        .send().await.unwrap();
    let bob_wrapped = browser::seal_room_key(&room_key, &bob.box_pub);
    let wts = time::OffsetDateTime::now_utc().unix_timestamp();
    let wsig = browser::sign_wrap_request(&room_id, &bob.box_pub, &bob_wrapped, wts, &alice.sig_priv);
    let r = client
        .post(format!("{}/api/rooms/{}/wrap", s.base_url, create.room_id))
        .json(&json!({
            "for_box_pubkey": browser::b64(&bob.box_pub),
            "wrapped_key": browser::b64(&bob_wrapped),
            "inviter_box_pubkey": browser::b64(&alice.box_pub),
            "inviter_sig_pubkey": browser::b64(&alice.sig_pub),
            "inviter_ts": wts,
            "inviter_sig": browser::b64(&wsig),
        }))
        .send().await.unwrap();
    assert!(r.status().is_success(), "wrap: {r:?}");
    Room { create, room_id, alice, bob }
}

fn sorted_ring(keys: &[&browser::MemberKeys]) -> Vec<Vec<u8>> {
    let mut ring: Vec<Vec<u8>> = keys.iter().map(|k| k.sig_pub.to_vec()).collect();
    ring.sort();
    ring
}

async fn publish_roster(s: &support::TestServer, room: &Room, epoch: i32, ring: &[Vec<u8>]) -> reqwest::Response {
    let sig = browser::sign_roster(&room.room_id, epoch, ring, &room.alice.sig_priv);
    reqwest::Client::new()
        .post(format!("{}/api/rooms/{}/roster", s.base_url, room.create.room_id))
        .json(&json!({
            "epoch": epoch,
            "member_sig_pubkeys": ring.iter().map(|p| browser::b64(p)).collect::<Vec<_>>(),
            "creator_sig": browser::b64(&sig),
        }))
        .send().await.unwrap()
}

async fn new_thread(s: &support::TestServer, tag: &str) -> (String, Vec<u8>) {
    // Unique per call: the moderation rules reject a duplicate body
    // on the same board within 24 h.
    let body = format!("thread for vouch tests ({tag})");
    let nonce = browser::solve_pow(b"government", &body, s.pow_bits);
    let t: CreateThreadResp = reqwest::Client::new()
        .post(format!("{}/api/threads", s.base_url))
        .json(&json!({ "board_id": "government", "title": format!("vouch {tag}"), "body": &body, "pow_nonce": browser::b64(&nonce) }))
        .send().await.unwrap().json().await.unwrap();
    let id = browser::unb64(&t.thread_id);
    (t.thread_id, id)
}

async fn post_with_vouch(
    s: &support::TestServer,
    thread_id_b64: &str,
    thread_id: &[u8],
    body: &str,
    vouch: &VouchPayload,
) -> reqwest::Response {
    let nonce = browser::solve_pow(thread_id, body, s.pow_bits);
    reqwest::Client::new()
        .post(format!("{}/api/threads/{}/posts", s.base_url, thread_id_b64))
        .json(&json!({ "body": body, "pow_nonce": browser::b64(&nonce), "vouch": vouch }))
        .send().await.unwrap()
}

#[tokio::test]
async fn members_list_is_member_only() {
    let s = support::spawn().await;
    let room = room_with_two(&s).await;
    let client = reqwest::Client::new();
    let url = format!("{}/api/rooms/{}/members", s.base_url, room.create.room_id);

    // GET is gone; unsigned POST is a bad request.
    assert!(!client.get(&url).send().await.unwrap().status().is_success());
    assert!(!client.post(&url).json(&json!({})).send().await.unwrap().status().is_success());

    // Stranger with a valid signature: 403.
    let stranger = browser::new_member_keys();
    let ts = time::OffsetDateTime::now_utc().unix_timestamp();
    let sig = browser::sign_members_request(&room.room_id, ts, &stranger.sig_priv);
    let r = client.post(&url).json(&json!({
        "requester_sig_pubkey": browser::b64(&stranger.sig_pub), "ts": ts, "sig": browser::b64(&sig),
    })).send().await.unwrap();
    assert_eq!(r.status().as_u16(), 403);

    // Bob (member): 200 with the full list.
    let sig = browser::sign_members_request(&room.room_id, ts, &room.bob.sig_priv);
    let r: MembersResp = client.post(&url).json(&json!({
        "requester_sig_pubkey": browser::b64(&room.bob.sig_pub), "ts": ts, "sig": browser::b64(&sig),
    })).send().await.unwrap().json().await.unwrap();
    assert_eq!(r.members.len(), 2);
    assert!(!r.vouching_enabled);
}

#[tokio::test]
async fn roster_lifecycle_and_vouch_roundtrip() {
    let s = support::spawn().await;
    let room = room_with_two(&s).await;
    let client = reqwest::Client::new();
    let roster_url = format!("{}/api/rooms/{}/roster", s.base_url, room.create.room_id);

    // Not public before vouching is enabled.
    assert_eq!(client.get(&roster_url).send().await.unwrap().status().as_u16(), 404);

    // Wrong set (missing Bob) is rejected even with a valid creator sig.
    let bad = publish_roster(&s, &room, 1, &sorted_ring(&[&room.alice])).await;
    assert_eq!(bad.status().as_u16(), 409);

    // Bob can't publish (not the creator) — sig won't verify under Alice's key.
    let ring = sorted_ring(&[&room.alice, &room.bob]);
    let bob_sig = browser::sign_roster(&room.room_id, 1, &ring, &room.bob.sig_priv);
    let r = client.post(&roster_url).json(&json!({
        "epoch": 1,
        "member_sig_pubkeys": ring.iter().map(|p| browser::b64(p)).collect::<Vec<_>>(),
        "creator_sig": browser::b64(&bob_sig),
    })).send().await.unwrap();
    assert_eq!(r.status().as_u16(), 400);

    // Creator publishes epoch 1.
    let ok = publish_roster(&s, &room, 1, &ring).await;
    assert!(ok.status().is_success(), "publish: {ok:?}");
    let roster: RosterResp = client.get(&roster_url).send().await.unwrap().json().await.unwrap();
    assert_eq!(roster.epoch, 1);
    assert_eq!(roster.member_sig_pubkeys.len(), 2);
    assert_eq!(roster.creator_sig_pubkey, browser::b64(&room.alice.sig_pub));
    let creator_sig = browser::unb64(&roster.creator_sig);

    // Bob vouches on a public post.
    let (thread_b64, thread_id) = new_thread(&s, "one").await;
    let body = "agents at 5th and main, illegal arrests";
    let v = browser::build_vouch(&room.room_id, &thread_id, body, 1, &creator_sig, &ring, &room.bob);
    let r = post_with_vouch(&s, &thread_b64, &thread_id, body, &v).await;
    assert!(r.status().is_success(), "vouched post: {r:?}");

    // Served back verbatim.
    let listed: serde_json::Value = client
        .get(format!("{}/api/threads/{}/posts?since_seq=0", s.base_url, thread_b64))
        .send().await.unwrap().json().await.unwrap();
    let post = listed["posts"].as_array().unwrap().iter().find(|p| p["seq"] == 2).unwrap();
    let served: VouchPayload = serde_json::from_value(post["vouch"].clone()).unwrap();
    assert_eq!(served, v);

    // Tampered body: same vouch, different text → signature fails.
    let r = post_with_vouch(&s, &thread_b64, &thread_id, "agents at 9th and elm", &v).await;
    assert_eq!(r.status().as_u16(), 400);

    // Stranger builds a "vouch" with a ring they are not in: they cannot
    // produce a valid LSAG for it. Simulate by signing as Bob but with
    // the stranger's scalar substituted — simplest: forge s[] randomly.
    let mut forged = v.clone();
    forged.s[0] = browser::b64(&[7u8; 32]);
    let r = post_with_vouch(&s, &thread_b64, &thread_id, body, &forged).await;
    assert_eq!(r.status().as_u16(), 400);

    // Alice vouches twice in the same thread: same key image (linkable).
    let a1 = browser::build_vouch(&room.room_id, &thread_id, "first", 1, &creator_sig, &ring, &room.alice);
    let a2 = browser::build_vouch(&room.room_id, &thread_id, "second", 1, &creator_sig, &ring, &room.alice);
    assert_eq!(a1.key_image, a2.key_image);
    assert_ne!(a1.key_image, v.key_image, "different members, different images");
    assert!(post_with_vouch(&s, &thread_b64, &thread_id, "first", &a1).await.status().is_success());
    assert!(post_with_vouch(&s, &thread_b64, &thread_id, "second", &a2).await.status().is_success());

    // …but a different thread gives Alice a different key image.
    let (thread2_b64, thread2_id) = new_thread(&s, "two").await;
    let a3 = browser::build_vouch(&room.room_id, &thread2_id, "elsewhere", 1, &creator_sig, &ring, &room.alice);
    assert_ne!(a3.key_image, a1.key_image);
    assert!(post_with_vouch(&s, &thread2_b64, &thread2_id, "elsewhere", &a3).await.status().is_success());

    // Feed surfaces the OP's claimed vouch room. Make a vouched OP.
    let op_body = "vouched op";
    let nonce = browser::solve_pow(b"economy", op_body, s.pow_bits);
    let tid = [42u8; 16];
    let op_v = browser::build_vouch(&room.room_id, &tid, op_body, 1, &creator_sig, &ring, &room.bob);
    let r = client.post(format!("{}/api/threads", s.base_url)).json(&json!({
        "board_id": "economy", "title": "vouched", "body": op_body,
        "pow_nonce": browser::b64(&nonce), "thread_id": browser::b64(&tid), "vouch": op_v,
    })).send().await.unwrap();
    assert!(r.status().is_success(), "vouched thread: {r:?}");
    let feed: serde_json::Value = client
        .get(format!("{}/api/feed?cat=economy", s.base_url))
        .send().await.unwrap().json().await.unwrap();
    let item = feed["items"].as_array().unwrap().iter().find(|i| i["title"] == "vouched").unwrap();
    assert_eq!(item["op_vouch_room_id"], room.create.room_id);
    assert_eq!(item["vouch_room_ids"].as_array().unwrap().len(), 1);

    // The first thread has an *unvouched* OP but vouched replies: the
    // feed must surface the room in `vouch_room_ids` (a stranger's
    // thread that an organizer answered belongs in the organizer's
    // network) while `op_vouch_room_id` stays absent.
    let feed: serde_json::Value = client
        .get(format!("{}/api/feed?cat=government", s.base_url))
        .send().await.unwrap().json().await.unwrap();
    let one = feed["items"].as_array().unwrap().iter().find(|i| i["title"] == "vouch one").unwrap();
    assert!(one.get("op_vouch_room_id").is_none() || one["op_vouch_room_id"].is_null());
    assert_eq!(one["vouch_room_ids"], json!([room.create.room_id]));

    // Roster advances (epoch 2 with the same set is allowed — creator
    // may re-sign). A vouch citing epoch 1 is now stale → 409.
    assert!(publish_roster(&s, &room, 2, &ring).await.status().is_success());
    let stale = browser::build_vouch(&room.room_id, &thread_id, "late", 1, &creator_sig, &ring, &room.bob);
    assert_eq!(post_with_vouch(&s, &thread_b64, &thread_id, "late", &stale).await.status().as_u16(), 409);

    // Skipping an epoch is rejected.
    assert_eq!(publish_roster(&s, &room, 4, &ring).await.status().as_u16(), 409);
}

#[tokio::test]
async fn removed_member_drops_out_of_roster() {
    let s = support::spawn().await;
    let room = room_with_two(&s).await;
    let client = reqwest::Client::new();
    let ring = sorted_ring(&[&room.alice, &room.bob]);
    assert!(publish_roster(&s, &room, 1, &ring).await.status().is_success());

    // Alice removes Bob (rekey with only herself surviving).
    let new_key = browser::random_room_key();
    let alice_wrap = browser::seal_room_key(&new_key, &room.alice.box_pub);
    let ts = time::OffsetDateTime::now_utc().unix_timestamp();
    let sig = browser::sign_remove_request(&room.room_id, ts, &room.bob.box_pub, &room.alice.sig_priv);
    let r = client.post(format!("{}/api/rooms/{}/remove", s.base_url, room.create.room_id)).json(&json!({
        "remover_sig_pubkey": browser::b64(&room.alice.sig_pub), "ts": ts, "sig": browser::b64(&sig),
        "target_box_pubkey": browser::b64(&room.bob.box_pub),
        "new_wrapped_keys": [{ "for_box_pubkey": browser::b64(&room.alice.box_pub), "wrapped_key": browser::b64(&alice_wrap) }],
    })).send().await.unwrap();
    assert!(r.status().is_success(), "remove: {r:?}");

    // The old roster (with Bob) can no longer be re-published; the new
    // accepted set is Alice alone.
    assert_eq!(publish_roster(&s, &room, 2, &ring).await.status().as_u16(), 409);
    assert!(publish_roster(&s, &room, 2, &sorted_ring(&[&room.alice])).await.status().is_success());

    // Bob's vouch against the current (epoch 2) roster is impossible —
    // he isn't in the ring — and against epoch 1 it's stale.
    let roster: RosterResp = client
        .get(format!("{}/api/rooms/{}/roster", s.base_url, room.create.room_id))
        .send().await.unwrap().json().await.unwrap();
    assert_eq!(roster.member_sig_pubkeys.len(), 1);
}

/// Cross-implementation check: a ring signature produced by the
/// browser code (`client/src/lib/ringsig.ts`, run under Node with the
/// same libsodium build) must verify under the server's dalek-based
/// `crypto::verify_vouch`. Regenerate the fixture with the script in
/// the commit that introduced it if the byte layout ever changes.
#[test]
fn ts_signed_vector_verifies_in_rust() {
    #[derive(serde::Deserialize)]
    struct Vector {
        room_id: String,
        thread_id: String,
        body: String,
        roster_epoch: i32,
        ring: Vec<String>,
        key_image: String,
        c0: String,
        s: Vec<String>,
    }
    let raw = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/vouch_vector_ts.json"
    ))
    .expect("fixture");
    let v: Vector = serde_json::from_str(raw.trim()).expect("fixture json");
    let room_id = browser::unb64(&v.room_id);
    let thread_id = browser::unb64(&v.thread_id);
    let ring: Vec<Vec<u8>> = v.ring.iter().map(|p| browser::unb64(p)).collect();
    let key_image: [u8; 32] = browser::unb64(&v.key_image).try_into().unwrap();
    let c0: [u8; 32] = browser::unb64(&v.c0).try_into().unwrap();
    let s: Vec<[u8; 32]> = v.s.iter().map(|x| browser::unb64(x).try_into().unwrap()).collect();

    let tampered = format!("{}!", v.body);
    let genuine = lethe_server::crypto::VouchParts {
        room_id: &room_id,
        thread_id: &thread_id,
        body: &v.body,
        roster_epoch: v.roster_epoch,
        ring: &ring,
        key_image: &key_image,
        c0: &c0,
        s: &s,
    };
    let forged = lethe_server::crypto::VouchParts {
        body: &tampered,
        ..genuine
    };
    assert!(
        lethe_server::crypto::verify_vouch(&genuine).is_ok(),
        "browser-produced ring signature must verify on the server"
    );
    assert!(lethe_server::crypto::verify_vouch(&forged).is_err());
}
