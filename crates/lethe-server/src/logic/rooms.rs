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

    // Provenance is all-or-nothing: if any field is present, all must be,
    // and the signature must verify against an actual thread participant.
    let now = ltime::now_coarse();
    let (origin_for_db, creator_pk_for_db, sig_for_db) =
        match (&origin_thread, &creator_thread_pubkey, &provenance_sig) {
            (Some(thread), Some(pk), Some(sig)) => {
                if !db::posts::pubkey_signed_in_thread(db, thread, pk).await? {
                    return Err(AppError::Forbidden(
                        "creator_thread_pubkey did not sign in origin_thread",
                    ));
                }
                crypto::verify_room_provenance(pk, sig, thread)?;
                (Some(thread.as_slice()), Some(pk.as_slice()), Some(sig.as_slice()))
            }
            (None, None, None) => (None, None, None),
            _ => return Err(AppError::BadRequest("provenance fields must come together")),
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
    let now = ltime::now_coarse();
    db::rooms::add_member(db, &meta.id, &box_pk, &sig_pk, now).await?;
    let members = db::rooms::list_members(db, &meta.id).await?;
    Ok(JoinRoomResp {
        room_id: ids::b64(&meta.id),
        members,
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
    })
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

pub async fn list_messages(
    db: &PgPool,
    room_id_b64: &str,
    since: Option<&str>,
) -> AppResult<MessagesResp> {
    let room_id = ids::unb64(room_id_b64).map_err(|_| AppError::BadRequest("room_id b64"))?;
    if db::rooms::meta_by_id(db, &room_id).await?.is_none() {
        return Err(AppError::NotFound);
    }
    let since_bytes = match since {
        Some(s) => Some(ids::unb64(s).map_err(|_| AppError::BadRequest("since b64"))?),
        None => None,
    };
    Ok(MessagesResp {
        messages: db::rooms::list_messages(db, &room_id, since_bytes.as_deref(), 500).await?,
    })
}

fn decode_pubkey(s: &str, label: &'static str) -> AppResult<Vec<u8>> {
    let v = ids::unb64(s).map_err(|_| AppError::BadRequest(label))?;
    if v.len() != PUBKEY_LEN {
        return Err(AppError::BadRequest(label));
    }
    Ok(v)
}
