//! Post creation and listing logic: PoW gate, optional Ed25519 verify,
//! `signer_first_seq` lookup.

use crate::{
    crypto, db, error::{AppError, AppResult},
    ids, moderation, pow, time as ltime,
};
use lethe_types::posts::*;
use sqlx::PgPool;

const MAX_TITLE: usize = 256;
const MAX_BODY: usize = 16 * 1024;
/// Upper bound on author-set thread expiry (~10 years). Mostly a
/// sanity rail against typos; NULL/absent means "never".
const MAX_EXPIRES_IN_DAYS: i32 = 3650;

pub async fn create_thread(
    db: &PgPool,
    pow_bits: u32,
    classifier: &dyn moderation::classifier::Classifier,
    server_pubkey: &[u8; 32],
    req: CreateThreadReq,
) -> AppResult<CreateThreadResp> {
    if req.title.is_empty() || req.title.len() > MAX_TITLE {
        return Err(AppError::BadRequest("title length"));
    }
    if req.body.is_empty() || req.body.len() > MAX_BODY {
        return Err(AppError::BadRequest("body length"));
    }
    let nonce = ids::unb64(&req.pow_nonce).map_err(|_| AppError::BadRequest("pow_nonce b64"))?;

    // For thread creation we PoW over the *board id* (no thread id yet) so
    // that the client can compute it without a server round-trip first.
    if !pow::verify(req.board_id.as_bytes(), &req.body, &nonce, pow_bits) {
        return Err(AppError::BadRequest("insufficient pow"));
    }

    if let moderation::Verdict::Reject(reason) =
        moderation::evaluate(db, &req.board_id, &req.body, classifier).await?
    {
        moderation::log_reject(db, Some(&req.board_id), &req.body, reason).await?;
        return Err(AppError::BadRequest(reason_static(reason)));
    }

    // Client may pre-mint the thread id so it can be folded into the OP
    // signature. Required when pubkey is present.
    let thread_id_vec: Vec<u8> = match &req.thread_id {
        Some(b) => {
            let v = ids::unb64(b).map_err(|_| AppError::BadRequest("thread_id b64"))?;
            if v.len() != 16 {
                return Err(AppError::BadRequest("thread_id length"));
            }
            v
        }
        None => ids::new_id().to_vec(),
    };

    let (pubkey_bytes, signature_bytes) = match (&req.pubkey, &req.signature) {
        (None, None) => (None, None),
        (Some(pk), Some(sig)) => {
            if req.thread_id.is_none() {
                return Err(AppError::BadRequest(
                    "thread_id required when claiming OP identity",
                ));
            }
            let pk = ids::unb64(pk).map_err(|_| AppError::BadRequest("pubkey b64"))?;
            let sig = ids::unb64(sig).map_err(|_| AppError::BadRequest("signature b64"))?;
            crypto::verify_post_signature(&pk, &sig, &thread_id_vec, &req.body)?;
            (Some(pk), Some(sig))
        }
        _ => return Err(AppError::BadRequest("pubkey/signature must come together")),
    };

    // A vouch binds the thread id, so the client must have minted it.
    let vouch = match &req.vouch {
        Some(v) => {
            if req.thread_id.is_none() {
                return Err(AppError::BadRequest("thread_id required when vouching"));
            }
            Some(validate_vouch(db, v, &thread_id_vec, &req.body).await?)
        }
        None => None,
    };

    // Author-set expiry: optional; converted to an absolute DATE at
    // creation so the retention worker needs no arithmetic per sweep.
    let now = ltime::today_utc();
    let expires_at = match req.expires_in_days {
        None => None,
        Some(d) if (1..=MAX_EXPIRES_IN_DAYS).contains(&d) => Some(
            time::Date::from_julian_day(now.to_julian_day().saturating_add(d))
                .map_err(|_| AppError::BadRequest("expires_in_days"))?,
        ),
        Some(_) => return Err(AppError::BadRequest("expires_in_days out of range")),
    };

    db::threads::create(
        db,
        &thread_id_vec,
        &req.board_id,
        &req.title,
        now,
        expires_at,
        server_pubkey,
    )
    .await
    .map_err(|e| match &e {
        sqlx::Error::Database(d) if d.constraint() == Some("threads_pkey") => {
            AppError::Conflict("thread_id already exists")
        }
        _ => AppError::Db(e),
    })?;
    let inserted = db::posts::insert(
        db,
        db::posts::NewPost {
            thread_id: &thread_id_vec,
            body: &req.body,
            pow_nonce: &nonce,
            pubkey: pubkey_bytes.as_deref(),
            signature: signature_bytes.as_deref(),
            created_at: now,
            origin_server_id: server_pubkey,
            vouch: vouch.as_ref().map(|(json, room)| (json.as_str(), room.as_slice())),
        },
    )
    .await?;
    Ok(CreateThreadResp {
        thread_id: ids::b64(&thread_id_vec),
        seq: inserted.seq,
    })
}

/// Validates a room vouch against the room's current signed roster and
/// verifies its ring signature. Returns the canonical JSON to store
/// plus the room id.
///
/// The server's acceptance is defense in depth only — readers verify
/// again locally, because the server is untrusted. What the server
/// *does* enforce that readers can't: the ring must be the room's
/// current roster, so a member removed since the last roster signing
/// can't get a fresh vouch stored.
async fn validate_vouch(
    db: &PgPool,
    v: &VouchPayload,
    thread_id: &[u8],
    body: &str,
) -> AppResult<(String, Vec<u8>)> {
    let room_id = ids::unb64(&v.room_id).map_err(|_| AppError::BadRequest("vouch room_id b64"))?;
    if room_id.len() != 16 {
        return Err(AppError::BadRequest("vouch room_id length"));
    }
    if v.ring.is_empty() || v.ring.len() > VOUCH_MAX_RING || v.s.len() != v.ring.len() {
        return Err(AppError::BadRequest("vouch ring size"));
    }
    let mut ring: Vec<Vec<u8>> = Vec::with_capacity(v.ring.len());
    for p in &v.ring {
        let b = ids::unb64(p).map_err(|_| AppError::BadRequest("vouch ring b64"))?;
        if b.len() != 32 {
            return Err(AppError::BadRequest("vouch ring pubkey length"));
        }
        ring.push(b);
    }
    let key_image: [u8; 32] = ids::unb64_array(&v.key_image)
        .map_err(|_| AppError::BadRequest("vouch key_image"))?;
    let c0: [u8; 32] = ids::unb64_array(&v.c0).map_err(|_| AppError::BadRequest("vouch c0"))?;
    let mut s: Vec<[u8; 32]> = Vec::with_capacity(v.s.len());
    for x in &v.s {
        s.push(ids::unb64_array(x).map_err(|_| AppError::BadRequest("vouch s"))?);
    }
    let creator_sig =
        ids::unb64(&v.creator_sig).map_err(|_| AppError::BadRequest("vouch creator_sig b64"))?;

    let meta = db::rooms::meta_by_id(db, &room_id)
        .await?
        .ok_or(AppError::BadRequest("vouch room not found"))?;
    if !meta.vouching_enabled {
        return Err(AppError::Forbidden("vouching is not enabled for that room"));
    }
    if v.roster_epoch != meta.roster_epoch {
        return Err(AppError::Conflict("vouch cites a stale roster epoch"));
    }
    let stored = db::rooms::roster_at(db, &room_id, v.roster_epoch)
        .await?
        .ok_or(AppError::Conflict("roster epoch missing"))?;
    if stored.member_sig_pubkeys != ring || stored.creator_sig != creator_sig {
        return Err(AppError::Forbidden("vouch ring does not match the signed roster"));
    }

    crypto::verify_vouch(&crypto::VouchParts {
        room_id: &room_id,
        thread_id,
        body,
        roster_epoch: v.roster_epoch,
        ring: &ring,
        key_image: &key_image,
        c0: &c0,
        s: &s,
    })?;

    let json = serde_json::to_string(v).map_err(|_| AppError::Internal("vouch serialize"))?;
    Ok((json, room_id))
}

/// Maps a moderation reason to a stable static string suitable for an
/// `AppError::BadRequest` payload.
fn reason_static(r: moderation::Reason) -> &'static str {
    match r {
        moderation::Reason::SpamDuplicate    => "rejected: spam_duplicate",
        moderation::Reason::SpamLinkDensity  => "rejected: spam_link_density",
        moderation::Reason::SpamTooShort     => "rejected: spam_too_short",
        moderation::Reason::MalwareLink      => "rejected: malware_link",
        moderation::Reason::HarassmentOrHate => "rejected: harassment_or_hate",
        moderation::Reason::AiClassifier     => "rejected: ai_classifier",
    }
}

pub async fn create_post(
    db: &PgPool,
    pow_bits: u32,
    classifier: &dyn moderation::classifier::Classifier,
    server_pubkey: &[u8; 32],
    thread_id_b64: &str,
    req: CreatePostReq,
) -> AppResult<CreatePostResp> {
    if req.body.is_empty() || req.body.len() > MAX_BODY {
        return Err(AppError::BadRequest("body length"));
    }
    let thread_id = ids::unb64(thread_id_b64)
        .map_err(|_| AppError::BadRequest("thread_id b64"))?;
    if !db::threads::exists(db, &thread_id).await? {
        return Err(AppError::NotFound);
    }
    let nonce = ids::unb64(&req.pow_nonce).map_err(|_| AppError::BadRequest("pow_nonce b64"))?;
    if !pow::verify(&thread_id, &req.body, &nonce, pow_bits) {
        return Err(AppError::BadRequest("insufficient pow"));
    }

    let board_id = db::threads::board_id_for(db, &thread_id)
        .await?
        .ok_or(AppError::NotFound)?;
    if let moderation::Verdict::Reject(reason) =
        moderation::evaluate(db, &board_id, &req.body, classifier).await?
    {
        moderation::log_reject(db, Some(&board_id), &req.body, reason).await?;
        return Err(AppError::BadRequest(reason_static(reason)));
    }

    let (pubkey_bytes, signature_bytes) = match (&req.pubkey, &req.signature) {
        (None, None) => (None, None),
        (Some(pk), Some(sig)) => {
            let pk = ids::unb64(pk).map_err(|_| AppError::BadRequest("pubkey b64"))?;
            let sig = ids::unb64(sig).map_err(|_| AppError::BadRequest("signature b64"))?;
            crypto::verify_post_signature(&pk, &sig, &thread_id, &req.body)?;
            (Some(pk), Some(sig))
        }
        _ => return Err(AppError::BadRequest("pubkey/signature must come together")),
    };

    let vouch = match &req.vouch {
        Some(v) => Some(validate_vouch(db, v, &thread_id, &req.body).await?),
        None => None,
    };

    let now = ltime::today_utc();
    let inserted = db::posts::insert(
        db,
        db::posts::NewPost {
            thread_id: &thread_id,
            body: &req.body,
            pow_nonce: &nonce,
            pubkey: pubkey_bytes.as_deref(),
            signature: signature_bytes.as_deref(),
            created_at: now,
            origin_server_id: server_pubkey,
            vouch: vouch.as_ref().map(|(json, room)| (json.as_str(), room.as_slice())),
        },
    )
    .await?;

    let signer_first_seq = match &pubkey_bytes {
        Some(pk) => db::posts::signer_first_seq(db, &thread_id, pk).await?,
        None => None,
    };

    Ok(CreatePostResp {
        post_id: ids::b64(&inserted.post_id),
        seq: inserted.seq,
        signer_first_seq,
    })
}

/// Author self-delete. The request must be signed by the same Ed25519
/// key that signed the post; fully anonymous posts cannot be deleted
/// (nobody can prove they wrote them — that's the price of posting
/// without a thread identity).
///
/// Deletion is real: the body, signature, and pubkey are scrubbed from
/// the row, and a `post_removals` tombstone (scope `global`) is written
/// so federation peers replicate the takedown through the existing
/// removals stream.
pub async fn delete_post(
    db: &PgPool,
    post_id_b64: &str,
    req: DeletePostReq,
) -> AppResult<()> {
    let post_id =
        ids::unb64(post_id_b64).map_err(|_| AppError::BadRequest("post_id b64"))?;
    if post_id.len() != 16 {
        return Err(AppError::BadRequest("post_id length"));
    }
    let pubkey = ids::unb64(&req.pubkey).map_err(|_| AppError::BadRequest("pubkey b64"))?;
    if pubkey.len() != 32 {
        return Err(AppError::BadRequest("pubkey length"));
    }
    let sig = ids::unb64(&req.sig).map_err(|_| AppError::BadRequest("sig b64"))?;
    if sig.len() != 64 {
        return Err(AppError::BadRequest("sig length"));
    }

    let now_ts = time::OffsetDateTime::now_utc().unix_timestamp();
    if (now_ts - req.ts).abs() > 60 {
        return Err(AppError::BadRequest("ts outside ±60s window"));
    }
    crypto::verify_post_delete(&pubkey, &sig, &post_id, req.ts)?;

    if !db::nonces::record(db, "postdel", &pubkey, req.ts).await? {
        return Err(AppError::Conflict("replay: this signature was already used"));
    }

    // Ownership: the post must exist, must be signed, and the stored
    // pubkey must match the one that just proved control.
    match db::posts::author_pubkey(db, &post_id).await? {
        None => return Err(AppError::NotFound),
        Some(None) => {
            return Err(AppError::Forbidden(
                "anonymous posts cannot be self-deleted",
            ))
        }
        Some(Some(stored)) if stored == pubkey => {}
        Some(Some(_)) => {
            return Err(AppError::Forbidden(
                "pubkey does not match the post author",
            ))
        }
    }

    let now = ltime::today_utc();
    let deleted =
        db::posts::author_delete(db, &post_id, "deleted by author", now).await?;
    if !deleted {
        return Err(AppError::Conflict("post is already removed"));
    }
    Ok(())
}

pub async fn list_posts(
    db: &PgPool,
    self_pubkey: &[u8; 32],
    thread_id_b64: &str,
    since_seq: i32,
) -> AppResult<Vec<PostView>> {
    let thread_id =
        ids::unb64(thread_id_b64).map_err(|_| AppError::BadRequest("thread_id b64"))?;
    if !db::threads::exists(db, &thread_id).await? {
        return Err(AppError::NotFound);
    }
    Ok(db::posts::list_in_thread(db, &thread_id, self_pubkey, since_seq, 500).await?)
}
