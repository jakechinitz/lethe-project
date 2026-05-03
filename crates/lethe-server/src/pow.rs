//! SHA-256 hashcash proof-of-work, server-side verification.
//!
//! Browser computes `SHA-256(thread_id || body || nonce_u64_LE)` and
//! searches for a digest with `bits` leading zero bits. Server recomputes
//! the same hash and counts. Endianness of the nonce is little-endian on
//! both sides — see `client/src/lib/pow.ts`.

use sha2::{Digest, Sha256};

pub fn verify(thread_id: &[u8], body: &str, nonce: &[u8], bits: u32) -> bool {
    let mut h = Sha256::new();
    h.update(thread_id);
    h.update(body.as_bytes());
    h.update(nonce);
    leading_zero_bits(&h.finalize()) >= bits
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_leading_zero_bits() {
        assert_eq!(leading_zero_bits(&[0x00, 0x80]), 8);
        assert_eq!(leading_zero_bits(&[0x00, 0x00, 0x40]), 17);
        assert_eq!(leading_zero_bits(&[0xff]), 0);
    }

    #[test]
    fn rejects_when_too_few_zeros() {
        assert!(!verify(b"tid", "body", b"nope", 30));
    }
}
