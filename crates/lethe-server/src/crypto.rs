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

/// Verifies a creator-signed room roster.
pub fn verify_roster_sig(
    creator_sig_pubkey: &[u8],
    sig: &[u8],
    room_id: &[u8],
    epoch: i32,
    member_sig_pubkeys: &[Vec<u8>],
) -> Result<(), CryptoError> {
    let payload = rooms::canonical_roster(room_id, epoch, member_sig_pubkeys);
    verify_ed25519(creator_sig_pubkey, sig, &payload)
}

/// Verifies the signature on an authenticated members-list request.
pub fn verify_members_request(
    requester_sig_pubkey: &[u8],
    sig: &[u8],
    room_id: &[u8],
    ts: i64,
) -> Result<(), CryptoError> {
    let payload = rooms::canonical_members_request(room_id, ts);
    verify_ed25519(requester_sig_pubkey, sig, &payload)
}

/// Decoded, length-checked vouch ready for ring verification.
pub struct VouchParts<'a> {
    pub room_id: &'a [u8],
    pub thread_id: &'a [u8],
    pub body: &'a str,
    pub roster_epoch: i32,
    /// Sorted ascending, 1..=50 entries of 32 bytes.
    pub ring: &'a [Vec<u8>],
    pub key_image: &'a [u8; 32],
    pub c0: &'a [u8; 32],
    pub s: &'a [[u8; 32]],
}

/// Verifies a room vouch's linkable ring signature (LSAG over Ed25519).
/// Mirrors `client/src/lib/ringsig.ts` byte-for-byte; the layout is
/// documented on `lethe_types::posts::VouchPayload`.
///
/// Rejects non-canonical scalars and any ring key or key image that is
/// not a torsion-free, non-identity point — the same set libsodium's
/// `crypto_core_ed25519_is_valid_point` accepts on the browser side.
// `nonspec_map_to_curve` is deprecated upstream because it is not an
// RFC 9380 hash-to-curve. We want exactly its non-spec behaviour:
// Elligator2 over SHA-512, byte-identical to libsodium's
// `crypto_core_ed25519_from_uniform`, which is what the browser runs.
#[allow(deprecated)]
pub fn verify_vouch(v: &VouchParts<'_>) -> Result<(), CryptoError> {
    use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
    use curve25519_dalek::scalar::Scalar;
    use curve25519_dalek::traits::IsIdentity;
    use lethe_types::posts::{
        vouch_challenge_input, vouch_key_image_input, vouch_message_input, VOUCH_MAX_RING,
    };
    use sha2::{Digest, Sha256, Sha512};

    let n = v.ring.len();
    if n == 0 || n > VOUCH_MAX_RING || v.s.len() != n {
        return Err(CryptoError::BadSignature);
    }

    fn valid_point(bytes: &[u8]) -> Result<EdwardsPoint, CryptoError> {
        let arr: [u8; 32] = bytes.try_into().map_err(|_| CryptoError::BadPubkey)?;
        let p = CompressedEdwardsY(arr)
            .decompress()
            .ok_or(CryptoError::BadPubkey)?;
        if p.is_small_order() || !p.is_torsion_free() || p.is_identity() {
            return Err(CryptoError::BadPubkey);
        }
        Ok(p)
    }
    fn canonical_scalar(bytes: &[u8; 32]) -> Result<Scalar, CryptoError> {
        Option::<Scalar>::from(Scalar::from_canonical_bytes(*bytes))
            .ok_or(CryptoError::BadSignature)
    }

    let key_image = valid_point(v.key_image)?;
    let mut points = Vec::with_capacity(n);
    let mut bases = Vec::with_capacity(n);
    for (i, pk) in v.ring.iter().enumerate() {
        if i > 0 && v.ring[i - 1] >= *pk {
            return Err(CryptoError::BadSignature); // not strictly sorted
        }
        points.push(valid_point(pk)?);
        let base = EdwardsPoint::nonspec_map_to_curve::<Sha512>(&vouch_key_image_input(
            v.room_id,
            v.thread_id,
            pk,
        ));
        bases.push(base);
    }

    let body_hash: [u8; 32] = Sha256::digest(v.body.as_bytes()).into();
    let m: [u8; 64] = Sha512::digest(vouch_message_input(
        v.room_id,
        v.thread_id,
        &body_hash,
        v.roster_epoch,
        v.ring,
        v.key_image,
    ))
    .into();

    let c0 = canonical_scalar(v.c0)?;
    let mut c = c0;
    for i in 0..n {
        let s_i = canonical_scalar(&v.s[i])?;
        let l = EdwardsPoint::vartime_double_scalar_mul_basepoint(&c, &points[i], &s_i);
        let r = s_i * bases[i] + c * key_image;
        let wide: [u8; 64] = Sha512::digest(vouch_challenge_input(
            &m,
            &l.compress().to_bytes(),
            &r.compress().to_bytes(),
        ))
        .into();
        c = Scalar::from_bytes_mod_order_wide(&wide);
    }
    if c == c0 {
        Ok(())
    } else {
        Err(CryptoError::VerifyFailed)
    }
}

fn verify_ed25519(pubkey: &[u8], sig: &[u8], msg: &[u8]) -> Result<(), CryptoError> {
    let pk_arr: [u8; 32] = pubkey.try_into().map_err(|_| CryptoError::BadPubkey)?;
    let sig_arr: [u8; 64] = sig.try_into().map_err(|_| CryptoError::BadSignature)?;
    let vk = VerifyingKey::from_bytes(&pk_arr).map_err(|_| CryptoError::BadPubkey)?;
    let signature = Signature::from_bytes(&sig_arr);
    vk.verify_strict(msg, &signature)
        .map_err(|_| CryptoError::VerifyFailed)
}
