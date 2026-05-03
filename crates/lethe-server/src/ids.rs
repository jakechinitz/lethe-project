//! ULID generation and urlsafe-base64 helpers used at HTTP boundaries.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

/// 16-byte ULID. Sortable by creation, opaque to clients.
pub fn new_ulid() -> [u8; 16] {
    ulid::Ulid::new().to_bytes()
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
    use rand::RngCore as _;
    let mut buf = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut buf);
    b64(&buf)
}
