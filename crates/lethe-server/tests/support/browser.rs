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
use sha2::{Digest, Sha256};

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
