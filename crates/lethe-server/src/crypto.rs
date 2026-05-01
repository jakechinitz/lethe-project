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

/// Verifies the room-creation provenance signature.
pub fn verify_room_provenance(
    creator_thread_pubkey: &[u8],
    provenance_sig: &[u8],
    origin_thread: &[u8],
) -> Result<(), CryptoError> {
    let payload = rooms::canonical_room_provenance(origin_thread, creator_thread_pubkey);
    verify_ed25519(creator_thread_pubkey, provenance_sig, &payload)
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

fn verify_ed25519(pubkey: &[u8], sig: &[u8], msg: &[u8]) -> Result<(), CryptoError> {
    let pk_arr: [u8; 32] = pubkey.try_into().map_err(|_| CryptoError::BadPubkey)?;
    let sig_arr: [u8; 64] = sig.try_into().map_err(|_| CryptoError::BadSignature)?;
    let vk = VerifyingKey::from_bytes(&pk_arr).map_err(|_| CryptoError::BadPubkey)?;
    let signature = Signature::from_bytes(&sig_arr);
    vk.verify_strict(msg, &signature)
        .map_err(|_| CryptoError::VerifyFailed)
}
