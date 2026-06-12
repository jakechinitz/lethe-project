//! All Ed25519 verification on the server lives here.
//!
//! `ed25519_dalek` types are intentionally not exposed: the rest of the
//! codebase calls these named verbs and stays free of crypto-library
//! specifics.

use ed25519_dalek::{Signature, VerifyingKey};
use lethe_types::{posts::canonical_post_payload, rooms};

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("malformed public key")]
    BadPubkey,
    #[error("malformed signature")]
    BadSignature,
    #[error("signature does not verify")]
    VerifyFailed,
}

/// Verifies a thread-local signature on a post body.
pub fn verify_post_signature(
    pubkey: &[u8],
    signature: &[u8],
    thread_id: &[u8],
    body: &str,
) -> Result<(), CryptoError> {
    let payload = canonical_post_payload(thread_id, body);
    verify_ed25519(pubkey, signature, &payload)
}

/// Verifies an author's self-delete request against the pubkey stored
/// on the post.
pub fn verify_post_delete(
    pubkey: &[u8],
    sig: &[u8],
    post_id: &[u8],
    ts: i64,
) -> Result<(), CryptoError> {
    let payload = lethe_types::posts::canonical_delete_request(post_id, ts);
    verify_ed25519(pubkey, sig, &payload)
}

/// Verifies the room-creation provenance signature.
pub fn verify_room_provenance(
    creator_thread_pubkey: &[u8],
    provenance_sig: &[u8],
    origin_thread: &[u8],
) -> Result<(), CryptoError> {
    let payload = rooms::canonical_room_provenance(origin_thread, creator_thread_pubkey);
    verify_ed25519(creator_thread_pubkey, provenance_sig, &payload)
}

/// Verifies a self-leave request signed by the leaving member.
pub fn verify_leave_request(
    sig_pubkey: &[u8],
    sig: &[u8],
    room_id: &[u8],
    ts: i64,
) -> Result<(), CryptoError> {
    let payload = rooms::canonical_leave_request(room_id, ts);
    verify_ed25519(sig_pubkey, sig, &payload)
}

/// Verifies a join proof for a restricted (allowlisted) room invite.
pub fn verify_join_proof(
    proof_thread_pubkey: &[u8],
    proof_sig: &[u8],
    invite_code: &str,
    box_pubkey: &[u8],
    ts: i64,
) -> Result<(), CryptoError> {
    let payload = rooms::canonical_join_proof(invite_code, box_pubkey, ts);
    verify_ed25519(proof_thread_pubkey, proof_sig, &payload)
}

/// Verifies the signature on a remove-and-rekey request.
pub fn verify_remove_request(
    remover_sig_pubkey: &[u8],
    sig: &[u8],
    room_id: &[u8],
    ts: i64,
    target_box_pubkey: &[u8],
) -> Result<(), CryptoError> {
    let payload = rooms::canonical_remove_request(room_id, ts, target_box_pubkey);
    verify_ed25519(remover_sig_pubkey, sig, &payload)
}

/// Verifies the signature on an authenticated message-list request.
pub fn verify_list_request(
    requester_sig_pubkey: &[u8],
    sig: &[u8],
    room_id: &[u8],
    ts: i64,
) -> Result<(), CryptoError> {
    let payload = rooms::canonical_list_request(room_id, ts);
    verify_ed25519(requester_sig_pubkey, sig, &payload)
}

/// Verifies that a room message was signed by the claimed sender pubkey.
pub fn verify_room_message_sender(
    sender_sig_pubkey: &[u8],
    sender_sig: &[u8],
    room_id: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
) -> Result<(), CryptoError> {
    let payload = rooms::canonical_message_payload(room_id, nonce, ciphertext);
    verify_ed25519(sender_sig_pubkey, sender_sig, &payload)
}

/// Verifies the signature on `POST /api/rooms` from the room creator.
pub fn verify_create_room(
    creator_sig_pubkey: &[u8],
    sig: &[u8],
    creator_box_pubkey: &[u8],
    wrapped_key_for_creator: &[u8],
    ts: i64,
) -> Result<(), CryptoError> {
    let payload = rooms::canonical_create_room(
        creator_box_pubkey,
        creator_sig_pubkey,
        wrapped_key_for_creator,
        ts,
    );
    verify_ed25519(creator_sig_pubkey, sig, &payload)
}

/// Verifies the signature on `POST /api/rooms/:room_id/wrap`.
pub fn verify_wrap_request(
    inviter_sig_pubkey: &[u8],
    sig: &[u8],
    room_id: &[u8],
    for_box_pubkey: &[u8],
    wrapped_key: &[u8],
    ts: i64,
) -> Result<(), CryptoError> {
    let payload = rooms::canonical_wrap_request(room_id, for_box_pubkey, wrapped_key, ts);
    verify_ed25519(inviter_sig_pubkey, sig, &payload)
}

fn verify_ed25519(pubkey: &[u8], sig: &[u8], msg: &[u8]) -> Result<(), CryptoError> {
    let pk_arr: [u8; 32] = pubkey.try_into().map_err(|_| CryptoError::BadPubkey)?;
    let sig_arr: [u8; 64] = sig.try_into().map_err(|_| CryptoError::BadSignature)?;
    let vk = VerifyingKey::from_bytes(&pk_arr).map_err(|_| CryptoError::BadPubkey)?;
    let signature = Signature::from_bytes(&sig_arr);
    vk.verify_strict(msg, &signature)
        .map_err(|_| CryptoError::VerifyFailed)
}
