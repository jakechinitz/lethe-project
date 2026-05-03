//! Room logic: provenance verification, member-only writes, opaque blob
//! storage. Server never sees plaintext or unwrapped room keys.

use crate::{
    crypto, db, error::{AppError, AppResult},
    ids, time as ltime,
};
use lethe_types::rooms::*;
use sqlx::PgPool;

const PUBKEY_LEN: usize = 32;
const SIG_LEN: usize = 64;
const NONCE_LEN: usize = 24;
const MAX_CIPHERTEXT: usize = 64 * 1024;
const MAX_WRAPPED_KEY: usize = 256;
/// Hard cap on simultaneously-active members per room. Removed members
/// don't count. Re-joining as the same box pubkey is idempotent and
/// doesn't push past the cap.
pub const MAX_ROOM_MEMBERS: i64 = 50;

pub async fn create(db: &PgPool, req: CreateRoomReq) -> AppResult<CreateRoomResp> {
    let creator_box = decode_pubkey(&req.creator_box_pubkey, "creator_box_pubkey")?;
    let creator_sig = decode_pubkey(&req.creator_sig_pubkey, "creator_sig_pubkey")?;
    let wrapped =
        ids::unb64(&req.wrapped_key_for_creator).map_err(|_| AppError::BadRequest("wrapped b64"))?;
    if wrapped.len() > MAX_WRAPPED_KEY {
        return Err(AppError::BadRequest("wrapped_key too large"));
    }

    let origin_thread = match &req.origin_thread {
        Some(s) => Some(ids::unb64(s).map_err(|_| AppError::BadRequest("origin_thread b64"))?),
        None => None,
    };
    let creator_thread_pubkey = match &req.creator_thread_pubkey {
        Some(s) => Some(decode_pubkey(s, "creator_thread_pubkey")?),
        None => None,
    };
    let provenance_sig = match &req.provenance_sig {
        Some(s) => {
            let v = ids::unb64(s).map_err(|_| AppError::BadRequest("provenance_sig b64"))?;
            if v.len() != SIG_LEN {
                return Err(AppError::BadRequest("provenance_sig length"));
            }
            Some(v)
        }
        None => None,
    };

    // Provenance signature is all-or-nothing: `creator_thread_pubkey` and
    // `provenance_sig` must come together and require `origin_thread`.
    // `origin_thread` alone is allowed (used by the invitee allowlist
    // flow to pin a thread without attaching a provenance attestation).
    let now = ltime::now_coarse();
    let (origin_for_db, creator_pk_for_db, sig_for_db) = match (
        &origin_thread,
        &creator_thread_pubkey,
        &provenance_sig,
    ) {
        (Some(thread), Some(pk), Some(sig)) => {
            if !db::posts::pubkey_signed_in_thread(db, thread, pk).await? {
                return Err(AppError::Forbidden(
                    "creator_thread_pubkey did not sign in origin_thread",
                ));
            }
            crypto::verify_room_provenance(pk, sig, thread)?;
            (
                Some(thread.as_slice()),
                Some(pk.as_slice()),
                Some(sig.as_slice()),
            )
        }
        (Some(thread), None, None) => (Some(thread.as_slice()), None, None),
        (None, None, None) => (None, None, None),
        _ => {
            return Err(AppError::BadRequest(
                "creator_thread_pubkey and provenance_sig must come together with origin_thread",
            ))
        }
    };

    // Allowlist: only meaningful with origin_thread. Each pubkey must
    // actually have signed in that thread, otherwise the entry is dead
    // weight that no one can prove ownership of.
    let allowlist_bytes: Option<Vec<Vec<u8>>> = match &req.allowlist_thread_pubkeys {
        None => None,
        Some(list) if list.is_empty() => None,
        Some(list) => {
            let thread = origin_thread
                .as_ref()
                .ok_or(AppError::BadRequest(
                    "allowlist requires origin_thread",
                ))?;
            let mut decoded: Vec<Vec<u8>> = Vec::with_capacity(list.len());
            for pk in list {
                let bytes = decode_pubkey(pk, "allowlist_thread_pubkey")?;
                if !db::posts::pubkey_signed_in_thread(db, thread, &bytes).await? {
                    return Err(AppError::Forbidden(
                        "allowlist pubkey did not sign in origin_thread",
                    ));
                }
                decoded.push(bytes);
            }
            Some(decoded)
        }
    };

    let invite_code = ids::random_invite_code();
    let room_id = db::rooms::create(
        db,
        db::rooms::NewRoom {
            origin_thread: origin_for_db,
            invite_code: &invite_code,
            creator_box_pubkey: &creator_box,
            creator_sig_pubkey: &creator_sig,
            wrapped_key_for_creator: &wrapped,
            creator_thread_pubkey: creator_pk_for_db,
            provenance_sig: sig_for_db,
            created_at: now,
            allowlist_thread_pubkeys: allowlist_bytes.as_deref(),
        },
    )
    .await?;

    Ok(CreateRoomResp {
        room_id: ids::b64(&room_id),
        invite_code,
    })
}

pub async fn join(
    db: &PgPool,
    invite_code: &str,
    req: JoinRoomReq,
) -> AppResult<JoinRoomResp> {
    let box_pk = decode_pubkey(&req.box_pubkey, "box_pubkey")?;
    let sig_pk = decode_pubkey(&req.sig_pubkey, "sig_pubkey")?;
    let meta = db::rooms::meta_by_invite(db, invite_code)
        .await?
        .ok_or(AppError::NotFound)?;

    // Restricted invites: require a fresh signature from one of the
    // allowlisted thread-signing keys over a payload that binds the
    // invite code and the joiner's box pubkey.
    if let Some(allowlist) = meta.allowlist_thread_pubkeys.as_ref() {
        let proof_pk_b64 = req.proof_thread_pubkey.as_ref().ok_or(
            AppError::Forbidden("this invite is restricted; proof_thread_pubkey required"),
        )?;
        let proof_ts = req
            .proof_ts
            .ok_or(AppError::Forbidden("proof_ts required"))?;
        let proof_sig_b64 = req
            .proof_sig
            .as_ref()
            .ok_or(AppError::Forbidden("proof_sig required"))?;

        let proof_pk = decode_pubkey(proof_pk_b64, "proof_thread_pubkey")?;
        let proof_sig = ids::unb64(proof_sig_b64)
            .map_err(|_| AppError::BadRequest("proof_sig b64"))?;
        if proof_sig.len() != SIG_LEN {
            return Err(AppError::BadRequest("proof_sig length"));
        }
        let now_ts = time::OffsetDateTime::now_utc().unix_timestamp();
        if (now_ts - proof_ts).abs() > 60 {
            return Err(AppError::BadRequest("proof_ts outside ±60s window"));
        }
        if !allowlist.iter().any(|k| k.as_slice() == proof_pk.as_slice()) {
            return Err(AppError::Forbidden(
                "thread pubkey is not on this invite's allowlist",
            ));
        }
        crypto::verify_join_proof(&proof_pk, &proof_sig, invite_code, &box_pk, proof_ts)?;
    }

    // Cap the room size. Re-joining as the same box pubkey is idempotent
    // (the INSERT is ON CONFLICT DO NOTHING), so allow that even at the
    // cap by checking membership first.
    let already_member = db::rooms::is_member_by_box(db, &meta.id, &box_pk).await?;
    if !already_member {
        let count = db::rooms::active_member_count(db, &meta.id).await?;
        if count >= MAX_ROOM_MEMBERS {
            return Err(AppError::Conflict("room is at the 50-member cap"));
        }
    }

    let now = ltime::now_coarse();
    db::rooms::add_member(db, &meta.id, &box_pk, &sig_pk, now).await?;
    let members = db::rooms::list_members(db, &meta.id).await?;
    Ok(JoinRoomResp {
        room_id: ids::b64(&meta.id),
        members,
    })
}

pub async fn invite_info(
    db: &PgPool,
    invite_code: &str,
) -> AppResult<InviteInfo> {
    let meta = db::rooms::meta_by_invite(db, invite_code)
        .await?
        .ok_or(AppError::NotFound)?;
    let restricted = meta.allowlist_thread_pubkeys.is_some();
    Ok(InviteInfo {
        room_id: ids::b64(&meta.id),
        origin_thread: meta.origin_thread.as_ref().map(|b| ids::b64(b)),
        restricted,
        allowlist_thread_pubkeys: meta
            .allowlist_thread_pubkeys
            .as_ref()
            .map(|v| v.iter().map(|b| ids::b64(b)).collect()),
    })
}

pub async fn wrap(
    db: &PgPool,
    room_id_b64: &str,
    req: WrapKeyReq,
) -> AppResult<()> {
    let room_id = ids::unb64(room_id_b64).map_err(|_| AppError::BadRequest("room_id b64"))?;
    let for_box = decode_pubkey(&req.for_box_pubkey, "for_box_pubkey")?;
    let inviter = decode_pubkey(&req.inviter_box_pubkey, "inviter_box_pubkey")?;
    let wrapped = ids::unb64(&req.wrapped_key).map_err(|_| AppError::BadRequest("wrapped b64"))?;
    if wrapped.len() > MAX_WRAPPED_KEY {
        return Err(AppError::BadRequest("wrapped_key too large"));
    }
    if !db::rooms::is_member_by_box(db, &room_id, &inviter).await? {
        return Err(AppError::Forbidden("inviter is not a member"));
    }
    let ok = db::rooms::grant_wrap(db, &room_id, &for_box, &wrapped, &inviter).await?;
    if !ok {
        return Err(AppError::Conflict("no pending member matches"));
    }
    Ok(())
}

pub async fn members(db: &PgPool, room_id_b64: &str) -> AppResult<MembersResp> {
    let room_id = ids::unb64(room_id_b64).map_err(|_| AppError::BadRequest("room_id b64"))?;
    if db::rooms::meta_by_id(db, &room_id).await?.is_none() {
        return Err(AppError::NotFound);
    }
    Ok(MembersResp {
        members: db::rooms::list_members(db, &room_id).await?,
        current_epoch: db::rooms::current_epoch(db, &room_id).await?,
    })
}

/// Removes a member and rekeys the room atomically. Only the room's
/// creator may call this. The caller MUST also supply a fresh
/// `wrapped_key` for every other surviving member, otherwise the
/// transaction aborts. Returns the post-rekey epoch.
pub async fn remove_and_rekey(
    db: &PgPool,
    room_id_b64: &str,
    req: RemoveMemberReq,
) -> AppResult<RemoveMemberResp> {
    let room_id = ids::unb64(room_id_b64).map_err(|_| AppError::BadRequest("room_id b64"))?;
    if db::rooms::meta_by_id(db, &room_id).await?.is_none() {
        return Err(AppError::NotFound);
    }

    let remover_pk = decode_pubkey(&req.remover_sig_pubkey, "remover_sig_pubkey")?;
    let sig = ids::unb64(&req.sig).map_err(|_| AppError::BadRequest("sig b64"))?;
    if sig.len() != SIG_LEN {
        return Err(AppError::BadRequest("sig length"));
    }
    let target_box = decode_pubkey(&req.target_box_pubkey, "target_box_pubkey")?;

    let now_ts = time::OffsetDateTime::now_utc().unix_timestamp();
    if (now_ts - req.ts).abs() > 60 {
        return Err(AppError::BadRequest("ts outside ±60s window"));
    }
    crypto::verify_remove_request(&remover_pk, &sig, &room_id, req.ts, &target_box)?;

    if !db::nonces::record(db, "remove", &remover_pk, req.ts).await? {
        return Err(AppError::Conflict("replay: this signature was already used"));
    }

    if !db::rooms::is_creator_by_sig(db, &room_id, &remover_pk).await? {
        return Err(AppError::Forbidden(
            "only the room creator may remove members",
        ));
    }

    let mut wraps: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(req.new_wrapped_keys.len());
    for w in &req.new_wrapped_keys {
        let pk = decode_pubkey(&w.for_box_pubkey, "for_box_pubkey")?;
        if pk == target_box {
            return Err(AppError::BadRequest(
                "cannot rewrap for the removed target",
            ));
        }
        let wrapped = ids::unb64(&w.wrapped_key)
            .map_err(|_| AppError::BadRequest("wrapped_key b64"))?;
        if wrapped.is_empty() || wrapped.len() > MAX_WRAPPED_KEY {
            return Err(AppError::BadRequest("wrapped_key length"));
        }
        wraps.push((pk, wrapped));
    }

    let now = time::OffsetDateTime::now_utc();
    let new_epoch = db::rooms::remove_and_rekey(db, &room_id, &target_box, &wraps, now)
        .await
        .map_err(|e| match e {
            sqlx::Error::RowNotFound => AppError::Conflict("target is not a current member"),
            sqlx::Error::Protocol(msg) if msg.contains("wrap count") => {
                AppError::BadRequest("new_wrapped_keys must cover every surviving member exactly")
            }
            sqlx::Error::Protocol(_) => {
                AppError::BadRequest("new_wrapped_keys must cover every surviving member exactly")
            }
            other => AppError::Db(other),
        })?;

    Ok(RemoveMemberResp { current_epoch: new_epoch })
}

pub async fn provenance(db: &PgPool, room_id_b64: &str) -> AppResult<ProvenanceResp> {
    let room_id = ids::unb64(room_id_b64).map_err(|_| AppError::BadRequest("room_id b64"))?;
    let meta = db::rooms::meta_by_id(db, &room_id)
        .await?
        .ok_or(AppError::NotFound)?;
    Ok(ProvenanceResp {
        origin_thread: meta.origin_thread.as_ref().map(|b| ids::b64(b)),
        creator_thread_pubkey: meta.creator_thread_pubkey.as_ref().map(|b| ids::b64(b)),
        provenance_sig: meta.provenance_sig.as_ref().map(|b| ids::b64(b)),
        created_at: lethe_types::CoarseTime(meta.created_at),
    })
}

pub async fn send_message(
    db: &PgPool,
    room_id_b64: &str,
    req: SendMessageReq,
) -> AppResult<SendMessageResp> {
    let room_id = ids::unb64(room_id_b64).map_err(|_| AppError::BadRequest("room_id b64"))?;
    let sender = decode_pubkey(&req.sender_sig_pubkey, "sender_sig_pubkey")?;
    let nonce = ids::unb64(&req.nonce).map_err(|_| AppError::BadRequest("nonce b64"))?;
    if nonce.len() != NONCE_LEN {
        return Err(AppError::BadRequest("nonce length"));
    }
    let ciphertext =
        ids::unb64(&req.ciphertext).map_err(|_| AppError::BadRequest("ciphertext b64"))?;
    if ciphertext.is_empty() || ciphertext.len() > MAX_CIPHERTEXT {
        return Err(AppError::BadRequest("ciphertext length"));
    }
    let sender_sig =
        ids::unb64(&req.sender_sig).map_err(|_| AppError::BadRequest("sender_sig b64"))?;
    if sender_sig.len() != SIG_LEN {
        return Err(AppError::BadRequest("sender_sig length"));
    }

    if !db::rooms::is_member(db, &room_id, &sender).await? {
        return Err(AppError::Forbidden("sender is not a member"));
    }
    crypto::verify_room_message_sender(&sender, &sender_sig, &room_id, &nonce, &ciphertext)?;

    let now = ltime::now_coarse();
    let id = db::rooms::insert_message(
        db,
        db::rooms::NewMessage {
            room_id: &room_id,
            sender_sig_pubkey: &sender,
            nonce: &nonce,
            ciphertext: &ciphertext,
            sender_sig: &sender_sig,
            created_at: now,
        },
    )
    .await?;
    Ok(SendMessageResp {
        message_id: ids::b64(&id),
        created_at: lethe_types::CoarseTime(now),
    })
}

/// Authenticated, history-gated listing.
///
/// Trust gate: the request is signed by `requester_sig_pubkey` over a
/// canonical payload that includes the `room_id` and a fresh timestamp.
/// Server verifies the signature, checks membership, and filters messages
/// to those at-or-after the requester's `joined_at`. This prevents a new
/// member from reading messages that predated their join.
pub async fn list_messages_authed(
    db: &PgPool,
    room_id_b64: &str,
    req: ListMessagesReq,
) -> AppResult<MessagesResp> {
    let room_id = ids::unb64(room_id_b64).map_err(|_| AppError::BadRequest("room_id b64"))?;
    if db::rooms::meta_by_id(db, &room_id).await?.is_none() {
        return Err(AppError::NotFound);
    }

    let requester_pk = decode_pubkey(&req.requester_sig_pubkey, "requester_sig_pubkey")?;
    let sig = ids::unb64(&req.sig).map_err(|_| AppError::BadRequest("sig b64"))?;
    if sig.len() != SIG_LEN {
        return Err(AppError::BadRequest("sig length"));
    }
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    if (now - req.ts).abs() > 60 {
        return Err(AppError::BadRequest("ts outside ±60s window"));
    }
    crypto::verify_list_request(&requester_pk, &sig, &room_id, req.ts)?;

    if !db::nonces::record(db, "list", &requester_pk, req.ts).await? {
        return Err(AppError::Conflict("replay: this signature was already used"));
    }

    let joined_at = db::rooms::joined_at_for_sig_member(db, &room_id, &requester_pk)
        .await?
        .ok_or(AppError::Forbidden("requester is not a member"))?;

    let since_bytes = match &req.since {
        Some(s) => Some(ids::unb64(s).map_err(|_| AppError::BadRequest("since b64"))?),
        None => None,
    };
    Ok(MessagesResp {
        messages: db::rooms::list_messages_for_member(
            db,
            &room_id,
            joined_at,
            since_bytes.as_deref(),
            500,
        )
        .await?,
    })
}

fn decode_pubkey(s: &str, label: &'static str) -> AppResult<Vec<u8>> {
    let v = ids::unb64(s).map_err(|_| AppError::BadRequest(label))?;
    if v.len() != PUBKEY_LEN {
        return Err(AppError::BadRequest(label));
    }
    Ok(v)
}
