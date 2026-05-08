//! 16-byte random ids and urlsafe-base64 helpers used at HTTP boundaries.
//!
//! Ids are uniform random — not time-encoded — so a captured id reveals
//! nothing about when the row was created. Within a thread, posts are
//! ordered by their per-thread `seq`. In the front-page feed, threads
//! are ordered by `created_at` / `last_post_at` at DATE granularity with
//! id as a stable tie-break inside the day.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::RngCore as _;

/// 16 uniform-random bytes. Globally unique with overwhelming
/// probability; opaque to clients.
pub fn new_id() -> [u8; 16] {
    let mut buf = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut buf);
    buf
}

pub fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn unb64(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    URL_SAFE_NO_PAD.decode(s)
}

/// Decode urlsafe-base64 into a fixed-size array.
pub fn unb64_array<const N: usize>(s: &str) -> Result<[u8; N], &'static str> {
    let v = unb64(s).map_err(|_| "invalid base64")?;
    let arr: [u8; N] = v.try_into().map_err(|_| "wrong byte length")?;
    Ok(arr)
}

/// Generate a 22-character urlsafe-base64 invite code (16 random bytes).
pub fn random_invite_code() -> String {
    b64(&new_id())
}
