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

    let now = ltime::today_utc();
    db::threads::create(db, &thread_id_vec, &req.board_id, &req.title, now, server_pubkey)
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
        },
    )
    .await?;
    Ok(CreateThreadResp {
        thread_id: ids::b64(&thread_id_vec),
        seq: inserted.seq,
    })
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

pub async fn list_posts(
    db: &PgPool,
    thread_id_b64: &str,
    since_seq: i32,
) -> AppResult<Vec<PostView>> {
    let thread_id =
        ids::unb64(thread_id_b64).map_err(|_| AppError::BadRequest("thread_id b64"))?;
    if !db::threads::exists(db, &thread_id).await? {
        return Err(AppError::NotFound);
    }
    Ok(db::posts::list_in_thread(db, &thread_id, since_seq, 500).await?)
}
