//! Browser-side crypto, mimicked using libsodium-compatible primitives.
//!
//! Mirrors `client/src/lib/{threadkey,roomkey}.ts` — same byte assemblies,
//! same primitives. If the browser and this module ever drift, the
//! integration tests will fail.
//!
//! Implementation choices:
//!   - `dryoc::classic::crypto_sign` for Ed25519 (matches libsodium).
//!   - `dryoc::classic::crypto_box` for X25519 keygen and sealed boxes.
//!   - `chacha20poly1305::XChaCha20Poly1305` for the AEAD (dryoc doesn't
//!     expose `crypto_aead_xchacha20poly1305_ietf` directly, but the bytes
//!     are byte-for-byte compatible with libsodium's IETF construction).

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::XChaCha20Poly1305;
use dryoc::classic::crypto_box::{crypto_box_keypair, crypto_box_seal, crypto_box_seal_open};
use dryoc::classic::crypto_sign::{crypto_sign_detached, crypto_sign_keypair};

type Signature = [u8; 64];
type SigningPublicKey = [u8; 32];
type SigningSecretKey = [u8; 64];
type BoxSecretKey = [u8; 32];
use sha2::{Digest, Sha256, Sha512};

pub fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn unb64(s: &str) -> Vec<u8> {
    URL_SAFE_NO_PAD.decode(s).expect("base64")
}

/// SHA-256 hashcash search. Identical bytes-on-the-wire to the server's
/// `pow.rs` and the browser's `pow.worker.ts`.
pub fn solve_pow(prefix: &[u8], body: &str, bits: u32) -> Vec<u8> {
    let mut nonce: u64 = 0;
    loop {
        let nonce_bytes = nonce.to_le_bytes();
        let mut h = Sha256::new();
        h.update(prefix);
        h.update(body.as_bytes());
        h.update(nonce_bytes);
        let digest = h.finalize();
        if leading_zero_bits(&digest) >= bits {
            return nonce_bytes.to_vec();
        }
        nonce = nonce.wrapping_add(1);
    }
}

fn leading_zero_bits(digest: &[u8]) -> u32 {
    let mut count = 0;
    for byte in digest {
        if *byte == 0 {
            count += 8;
        } else {
            count += byte.leading_zeros();
            return count;
        }
    }
    count
}

pub struct ThreadIdentity {
    pub public_key: SigningPublicKey,
    pub private_key: SigningSecretKey,
}

pub fn new_thread_identity() -> ThreadIdentity {
    let (pk, sk) = crypto_sign_keypair();
    ThreadIdentity { public_key: pk, private_key: sk }
}

pub fn sign_post(thread_id: &[u8], body: &str, sk: &SigningSecretKey) -> Signature {
    let mut payload = Vec::with_capacity(13 + thread_id.len() + body.len());
    payload.extend_from_slice(b"lethe-post-v1");
    payload.extend_from_slice(thread_id);
    payload.extend_from_slice(body.as_bytes());
    let mut sig: Signature = [0u8; 64];
    crypto_sign_detached(&mut sig, &payload, sk).expect("sign");
    sig
}

pub fn sign_members_request(room_id: &[u8], ts: i64, sk: &SigningSecretKey) -> Signature {
    let payload = lethe_types::rooms::canonical_members_request(room_id, ts);
    let mut sig: Signature = [0u8; 64];
    crypto_sign_detached(&mut sig, &payload, sk).expect("sign");
    sig
}

pub fn sign_roster(
    room_id: &[u8],
    epoch: i32,
    ring: &[Vec<u8>],
    creator_sk: &SigningSecretKey,
) -> Signature {
    let payload = lethe_types::rooms::canonical_roster(room_id, epoch, ring);
    let mut sig: Signature = [0u8; 64];
    crypto_sign_detached(&mut sig, &payload, creator_sk).expect("sign");
    sig
}

/// Ed25519 secret scalar from a 64-byte libsodium-style secret key
/// (seed || pubkey): SHA-512(seed)[..32], clamped, reduced mod l.
/// Mirrors `client/src/lib/ringsig.ts::scalarFromSigningKey`.
pub fn scalar_from_signing_key(sk: &SigningSecretKey) -> curve25519_dalek::scalar::Scalar {
    let h = Sha512::digest(&sk[..32]);
    let mut clamped = [0u8; 32];
    clamped.copy_from_slice(&h[..32]);
    clamped[0] &= 248;
    clamped[31] &= 127;
    clamped[31] |= 64;
    curve25519_dalek::scalar::Scalar::from_bytes_mod_order(clamped)
}

/// Browser-equivalent LSAG signer. Produces a `VouchPayload` for
/// `body` in `thread_id` as `signer` (a member of the room whose
/// current roster is `ring`, already sorted). Byte-for-byte the same
/// construction as `client/src/lib/ringsig.ts`.
#[allow(deprecated)] // nonspec_map_to_curve: deliberate, see crypto::verify_vouch
pub fn build_vouch(
    room_id: &[u8],
    thread_id: &[u8],
    body: &str,
    roster_epoch: i32,
    creator_sig: &[u8],
    ring: &[Vec<u8>],
    signer: &MemberKeys,
) -> lethe_types::posts::VouchPayload {
    use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
    use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
    use curve25519_dalek::scalar::Scalar;
    use lethe_types::posts::{vouch_challenge_input, vouch_key_image_input, vouch_message_input};
    use rand::RngCore as _;

    let n = ring.len();
    let signer_index = ring
        .iter()
        .position(|p| p.as_slice() == &signer.sig_pub[..])
        .expect("signer must be in ring");
    let x = scalar_from_signing_key(&signer.sig_priv);

    let points: Vec<EdwardsPoint> = ring
        .iter()
        .map(|p| {
            let mut a = [0u8; 32];
            a.copy_from_slice(p);
            CompressedEdwardsY(a).decompress().expect("ring point")
        })
        .collect();
    let bases: Vec<EdwardsPoint> = ring
        .iter()
        .map(|p| {
            EdwardsPoint::nonspec_map_to_curve::<Sha512>(&vouch_key_image_input(
                room_id, thread_id, p,
            ))
        })
        .collect();
    let key_image = (x * bases[signer_index]).compress().to_bytes();

    let body_hash: [u8; 32] = Sha256::digest(body.as_bytes()).into();
    let m: [u8; 64] = Sha512::digest(vouch_message_input(
        room_id,
        thread_id,
        &body_hash,
        roster_epoch,
        ring,
        &key_image,
    ))
    .into();
    let ki_point = CompressedEdwardsY(key_image).decompress().unwrap();

    let challenge = |l: &EdwardsPoint, r: &EdwardsPoint| -> Scalar {
        let wide: [u8; 64] = Sha512::digest(vouch_challenge_input(
            &m,
            &l.compress().to_bytes(),
            &r.compress().to_bytes(),
        ))
        .into();
        Scalar::from_bytes_mod_order_wide(&wide)
    };
    let random_scalar = || {
        let mut b = [0u8; 64];
        rand::thread_rng().fill_bytes(&mut b);
        Scalar::from_bytes_mod_order_wide(&b)
    };

    let mut c: Vec<Option<Scalar>> = vec![None; n];
    let mut s: Vec<Option<Scalar>> = vec![None; n];

    let alpha = random_scalar();
    let l_pi = &alpha * ED25519_BASEPOINT_TABLE;
    let r_pi = alpha * bases[signer_index];
    c[(signer_index + 1) % n] = Some(challenge(&l_pi, &r_pi));

    for k in 1..n {
        let i = (signer_index + k) % n;
        let s_i = random_scalar();
        s[i] = Some(s_i);
        let c_i = c[i].unwrap();
        let l = &s_i * ED25519_BASEPOINT_TABLE + c_i * points[i];
        let r = s_i * bases[i] + c_i * ki_point;
        c[(i + 1) % n] = Some(challenge(&l, &r));
    }
    let c_pi = c[signer_index].unwrap();
    s[signer_index] = Some(alpha - c_pi * x);

    lethe_types::posts::VouchPayload {
        room_id: b64(room_id),
        roster_epoch,
        creator_sig: b64(creator_sig),
        ring: ring.iter().map(|p| b64(p)).collect(),
        key_image: b64(&key_image),
        c0: b64(&c[0].unwrap().to_bytes()),
        s: s.iter().map(|v| b64(&v.unwrap().to_bytes())).collect(),
    }
}

pub fn sign_post_delete(post_id: &[u8], ts: i64, sk: &SigningSecretKey) -> Signature {
    let mut payload = Vec::with_capacity(16 + post_id.len() + 8);
    payload.extend_from_slice(b"lethe-delete-v1\x00");
    payload.extend_from_slice(post_id);
    payload.extend_from_slice(&ts.to_le_bytes());
    let mut sig: Signature = [0u8; 64];
    crypto_sign_detached(&mut sig, &payload, sk).expect("sign");
    sig
}

pub fn sign_room_provenance(
    origin_thread: &[u8],
    creator_thread_pubkey: &[u8],
    sk: &SigningSecretKey,
) -> Signature {
    let mut payload = Vec::with_capacity(14 + origin_thread.len() + 32);
    payload.extend_from_slice(b"lethe-room-v1\x00");
    payload.extend_from_slice(origin_thread);
    payload.extend_from_slice(creator_thread_pubkey);
    let mut sig: Signature = [0u8; 64];
    crypto_sign_detached(&mut sig, &payload, sk).expect("sign");
    sig
}

pub struct MemberKeys {
    pub box_pub: [u8; 32],
    pub box_priv: BoxSecretKey,
    pub sig_pub: SigningPublicKey,
    pub sig_priv: SigningSecretKey,
}

pub fn new_member_keys() -> MemberKeys {
    let (box_pub, box_priv) = crypto_box_keypair();
    let (sig_pub, sig_priv) = crypto_sign_keypair();
    MemberKeys { box_pub, box_priv, sig_pub, sig_priv }
}

pub fn random_room_key() -> [u8; 32] {
    use rand::RngCore as _;
    let mut k = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut k);
    k
}

pub fn seal_room_key(room_key: &[u8; 32], recipient_box_pub: &[u8; 32]) -> Vec<u8> {
    let mut out = vec![0u8; 32 + 16 + room_key.len()];
    crypto_box_seal(&mut out, room_key, recipient_box_pub).expect("seal");
    out
}

pub fn open_room_key(
    sealed: &[u8],
    recipient_box_pub: &[u8; 32],
    recipient_box_priv: &BoxSecretKey,
) -> [u8; 32] {
    let mut out = vec![0u8; sealed.len() - 32 - 16];
    crypto_box_seal_open(&mut out, sealed, recipient_box_pub, recipient_box_priv)
        .expect("open seal");
    let mut k = [0u8; 32];
    k.copy_from_slice(&out);
    k
}

pub fn encrypt_message(
    plaintext: &str,
    room_id: &[u8],
    room_key: &[u8; 32],
) -> ([u8; 24], Vec<u8>) {
    use rand::RngCore as _;
    let cipher = XChaCha20Poly1305::new(room_key.into());
    let mut nonce = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(
            &nonce.into(),
            Payload {
                msg: plaintext.as_bytes(),
                aad: room_id,
            },
        )
        .expect("encrypt");
    (nonce, ct)
}

pub fn decrypt_message(
    ciphertext: &[u8],
    nonce: &[u8; 24],
    room_id: &[u8],
    room_key: &[u8; 32],
) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new(room_key.into());
    cipher
        .decrypt(
            nonce.into(),
            Payload {
                msg: ciphertext,
                aad: room_id,
            },
        )
        .expect("decrypt")
}

pub fn sign_leave_request(
    room_id: &[u8],
    ts: i64,
    sk: &SigningSecretKey,
) -> Signature {
    let mut payload = Vec::with_capacity(15 + room_id.len() + 8);
    payload.extend_from_slice(b"lethe-leave-v1\x00");
    payload.extend_from_slice(room_id);
    payload.extend_from_slice(&ts.to_le_bytes());
    let mut sig: Signature = [0u8; 64];
    crypto_sign_detached(&mut sig, &payload, sk).expect("sign");
    sig
}

pub fn sign_join_proof(
    invite_code: &str,
    box_pubkey: &[u8],
    ts: i64,
    sk: &SigningSecretKey,
) -> Signature {
    let mut payload = Vec::with_capacity(14 + invite_code.len() + 32 + 8);
    payload.extend_from_slice(b"lethe-join-v1\x00");
    payload.extend_from_slice(invite_code.as_bytes());
    payload.extend_from_slice(box_pubkey);
    payload.extend_from_slice(&ts.to_le_bytes());
    let mut sig: Signature = [0u8; 64];
    crypto_sign_detached(&mut sig, &payload, sk).expect("sign");
    sig
}

pub fn sign_remove_request(
    room_id: &[u8],
    ts: i64,
    target_box_pubkey: &[u8],
    sk: &SigningSecretKey,
) -> Signature {
    let mut payload = Vec::with_capacity(16 + room_id.len() + 8 + 32);
    payload.extend_from_slice(b"lethe-remove-v1\x00");
    payload.extend_from_slice(room_id);
    payload.extend_from_slice(&ts.to_le_bytes());
    payload.extend_from_slice(target_box_pubkey);
    let mut sig: Signature = [0u8; 64];
    crypto_sign_detached(&mut sig, &payload, sk).expect("sign");
    sig
}

pub fn sign_list_request(
    room_id: &[u8],
    ts: i64,
    sk: &SigningSecretKey,
) -> Signature {
    let mut payload = Vec::with_capacity(14 + room_id.len() + 8);
    payload.extend_from_slice(b"lethe-list-v1\x00");
    payload.extend_from_slice(room_id);
    payload.extend_from_slice(&ts.to_le_bytes());
    let mut sig: Signature = [0u8; 64];
    crypto_sign_detached(&mut sig, &payload, sk).expect("sign");
    sig
}

pub fn sign_message_envelope(
    room_id: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    sk: &SigningSecretKey,
) -> Signature {
    let mut payload =
        Vec::with_capacity(13 + room_id.len() + nonce.len() + ciphertext.len());
    payload.extend_from_slice(b"lethe-msg-v1\x00");
    payload.extend_from_slice(room_id);
    payload.extend_from_slice(nonce);
    payload.extend_from_slice(ciphertext);
    let mut sig: Signature = [0u8; 64];
    crypto_sign_detached(&mut sig, &payload, sk).expect("sign");
    sig
}

pub fn sign_create_room(
    creator_box_pubkey: &[u8],
    creator_sig_pubkey: &[u8],
    wrapped_key_for_creator: &[u8],
    ts: i64,
    sk: &SigningSecretKey,
) -> Signature {
    let mut payload = Vec::with_capacity(
        16 + 8
            + creator_box_pubkey.len()
            + creator_sig_pubkey.len()
            + wrapped_key_for_creator.len(),
    );
    payload.extend_from_slice(b"lethe-create-v1\x00");
    payload.extend_from_slice(&ts.to_le_bytes());
    payload.extend_from_slice(creator_box_pubkey);
    payload.extend_from_slice(creator_sig_pubkey);
    payload.extend_from_slice(wrapped_key_for_creator);
    let mut sig: Signature = [0u8; 64];
    crypto_sign_detached(&mut sig, &payload, sk).expect("sign");
    sig
}

pub fn sign_wrap_request(
    room_id: &[u8],
    for_box_pubkey: &[u8],
    wrapped_key: &[u8],
    ts: i64,
    sk: &SigningSecretKey,
) -> Signature {
    let mut payload = Vec::with_capacity(
        14 + 8 + room_id.len() + for_box_pubkey.len() + wrapped_key.len(),
    );
    payload.extend_from_slice(b"lethe-wrap-v1\x00");
    payload.extend_from_slice(&ts.to_le_bytes());
    payload.extend_from_slice(room_id);
    payload.extend_from_slice(for_box_pubkey);
    payload.extend_from_slice(wrapped_key);
    let mut sig: Signature = [0u8; 64];
    crypto_sign_detached(&mut sig, &payload, sk).expect("sign");
    sig
}
