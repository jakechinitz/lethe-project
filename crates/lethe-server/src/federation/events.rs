//! Wire format for federated events: posts and removals.
//!
//! Two event kinds, both prefixed with a `protocol_version` and a
//! `constitution_version` so receivers can negotiate, refuse, or log
//! events from peers running incompatible versions. Both are signed by
//! the originating server's Ed25519 key over a domain-tagged canonical
//! byte encoding (see `canonical_*_payload`); receivers re-derive the
//! bytes from the deserialized struct and verify against the peer's
//! claimed `origin_server_id`.
//!
//! The canonical encoding uses explicit length prefixes rather than
//! deterministic JSON because deterministic JSON is fragile across
//! library versions and easy to get wrong silently. Any future field
//! addition needs a new domain tag (`lethe-fed-post-v2`, ...).

use crate::federation::identity::{verify_server_signature, Identity};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};
use time::Date;

pub const PROTOCOL_VERSION: &str = "lethe-fed-v1";

const POST_EVENT_DOMAIN: &[u8] = b"lethe-fed-post-v1\0";
const REMOVAL_EVENT_DOMAIN: &[u8] = b"lethe-fed-removal-v1\0";

/// A signed copy of a public post.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostEvent {
    pub protocol_version: String,
    pub constitution_version: String,
    pub board_id: String,
    /// 16 bytes, base64url no-pad.
    pub thread_id: String,
    /// 32 bytes — the server that originated the *thread*. May differ
    /// from `origin_server_id` when a post is replied to a thread that
    /// originated elsewhere; in MVP we don't relay-sign, so in
    /// practice this equals `origin_server_id`.
    pub thread_origin_server_id: String,
    pub thread_title: String,
    /// 32 bytes — the server that originated the *post*.
    pub origin_server_id: String,
    /// 16 bytes — the post id assigned by the origin server.
    pub origin_post_id: String,
    pub body: String,
    /// ISO-8601 date ("YYYY-MM-DD").
    pub created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author_pubkey: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author_signature: Option<String>,
    /// 64 bytes — `Ed25519_sign(server_priv, canonical_post_payload(...))`.
    pub server_signature: String,
}

/// A signed takedown of a previously-accepted post. Only the post's
/// origin server can issue a global removal at MVP; quorum-signed
/// cross-server removals are deliberately deferred.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemovalEvent {
    pub protocol_version: String,
    pub constitution_version: String,
    /// 32 bytes.
    pub origin_server_id: String,
    /// 16 bytes — the targeted post's `origin_post_id`.
    pub origin_post_id: String,
    pub reason: String,
    /// ISO-8601 date ("YYYY-MM-DD").
    pub removed_at: String,
    /// 64 bytes.
    pub server_signature: String,
}

/// What `/api/federation/events` returns. Cursors are opaque to the
/// peer; the peer just stores the `next_*_cursor` it received and
/// passes it back on the next pull.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EventsResponse {
    #[serde(default)]
    pub posts: Vec<PostEvent>,
    #[serde(default)]
    pub removals: Vec<RemovalEvent>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_post_cursor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_removal_cursor: Option<String>,
}

/// Concrete fields for a post event, in the natural in-memory shape.
/// Used by the route handler to build a `PostEvent` and by `pull` to
/// destructure a received one.
pub struct PostEventFields<'a> {
    pub board_id: &'a str,
    pub thread_id: &'a [u8],
    pub thread_origin_server_id: &'a [u8],
    pub thread_title: &'a str,
    pub origin_server_id: &'a [u8],
    pub origin_post_id: &'a [u8],
    pub body: &'a str,
    pub created_at: Date,
    pub author_pubkey: Option<&'a [u8]>,
    pub author_signature: Option<&'a [u8]>,
}

pub struct RemovalEventFields<'a> {
    pub origin_server_id: &'a [u8],
    pub origin_post_id: &'a [u8],
    pub reason: &'a str,
    pub removed_at: Date,
}

pub fn canonical_post_payload(f: &PostEventFields<'_>) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(POST_EVENT_DOMAIN);
    write_str(&mut buf, PROTOCOL_VERSION);
    write_str(&mut buf, super::constitution::VERSION);
    write_str(&mut buf, f.board_id);
    write_bytes(&mut buf, f.thread_id);
    write_bytes(&mut buf, f.thread_origin_server_id);
    write_str(&mut buf, f.thread_title);
    write_bytes(&mut buf, f.origin_server_id);
    write_bytes(&mut buf, f.origin_post_id);
    write_str(&mut buf, f.body);
    write_date(&mut buf, f.created_at);
    write_opt_bytes(&mut buf, f.author_pubkey);
    write_opt_bytes(&mut buf, f.author_signature);
    buf
}

pub fn canonical_removal_payload(f: &RemovalEventFields<'_>) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(REMOVAL_EVENT_DOMAIN);
    write_str(&mut buf, PROTOCOL_VERSION);
    write_str(&mut buf, super::constitution::VERSION);
    write_bytes(&mut buf, f.origin_server_id);
    write_bytes(&mut buf, f.origin_post_id);
    write_str(&mut buf, f.reason);
    write_date(&mut buf, f.removed_at);
    buf
}

pub fn build_post_event(identity: &Identity, f: &PostEventFields<'_>) -> PostEvent {
    let payload = canonical_post_payload(f);
    let sig = identity.sign(&payload);
    PostEvent {
        protocol_version: PROTOCOL_VERSION.to_string(),
        constitution_version: super::constitution::VERSION.to_string(),
        board_id: f.board_id.to_string(),
        thread_id: b64(f.thread_id),
        thread_origin_server_id: b64(f.thread_origin_server_id),
        thread_title: f.thread_title.to_string(),
        origin_server_id: b64(f.origin_server_id),
        origin_post_id: b64(f.origin_post_id),
        body: f.body.to_string(),
        created_at: format_date(f.created_at),
        author_pubkey: f.author_pubkey.map(b64),
        author_signature: f.author_signature.map(b64),
        server_signature: b64(&sig),
    }
}

pub fn build_removal_event(
    identity: &Identity,
    f: &RemovalEventFields<'_>,
) -> RemovalEvent {
    let payload = canonical_removal_payload(f);
    let sig = identity.sign(&payload);
    RemovalEvent {
        protocol_version: PROTOCOL_VERSION.to_string(),
        constitution_version: super::constitution::VERSION.to_string(),
        origin_server_id: b64(f.origin_server_id),
        origin_post_id: b64(f.origin_post_id),
        reason: f.reason.to_string(),
        removed_at: format_date(f.removed_at),
        server_signature: b64(&sig),
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DecodeError {
    #[error("base64 decode failed: {0}")]
    Base64(&'static str),
    #[error("wrong byte length: {0}")]
    Length(&'static str),
    #[error("date parse failed")]
    Date,
    #[error("protocol_version mismatch: got {0}")]
    Protocol(String),
    #[error("signature does not verify")]
    Signature,
}

pub struct DecodedPost {
    pub board_id: String,
    pub thread_id: [u8; 16],
    pub thread_origin_server_id: [u8; 32],
    pub thread_title: String,
    pub origin_server_id: [u8; 32],
    pub origin_post_id: [u8; 16],
    pub body: String,
    pub created_at: Date,
    pub author_pubkey: Option<[u8; 32]>,
    pub author_signature: Option<[u8; 64]>,
}

pub struct DecodedRemoval {
    pub origin_server_id: [u8; 32],
    pub origin_post_id: [u8; 16],
    pub reason: String,
    pub removed_at: Date,
}

/// Decodes and verifies a `PostEvent`. The `expected_signer` is the
/// pubkey of the peer the event was pulled from — receiving an event
/// signed by something else is treated as a verification failure.
pub fn verify_post_event(
    e: &PostEvent,
    expected_signer: &[u8; 32],
) -> Result<DecodedPost, DecodeError> {
    if e.protocol_version != PROTOCOL_VERSION {
        return Err(DecodeError::Protocol(e.protocol_version.clone()));
    }
    let thread_id = decode_fixed::<16>(&e.thread_id, "thread_id")?;
    let thread_origin_server_id =
        decode_fixed::<32>(&e.thread_origin_server_id, "thread_origin_server_id")?;
    let origin_server_id = decode_fixed::<32>(&e.origin_server_id, "origin_server_id")?;
    let origin_post_id = decode_fixed::<16>(&e.origin_post_id, "origin_post_id")?;
    let server_signature = decode_fixed::<64>(&e.server_signature, "server_signature")?;
    let author_pubkey = match &e.author_pubkey {
        None => None,
        Some(s) => Some(decode_fixed::<32>(s, "author_pubkey")?),
    };
    let author_signature = match &e.author_signature {
        None => None,
        Some(s) => Some(decode_fixed::<64>(s, "author_signature")?),
    };
    let created_at = parse_date(&e.created_at)?;

    if &origin_server_id != expected_signer {
        return Err(DecodeError::Signature);
    }

    let payload = canonical_post_payload(&PostEventFields {
        board_id: &e.board_id,
        thread_id: &thread_id,
        thread_origin_server_id: &thread_origin_server_id,
        thread_title: &e.thread_title,
        origin_server_id: &origin_server_id,
        origin_post_id: &origin_post_id,
        body: &e.body,
        created_at,
        author_pubkey: author_pubkey.as_ref().map(|a| &a[..]),
        author_signature: author_signature.as_ref().map(|a| &a[..]),
    });
    verify_server_signature(&origin_server_id, &server_signature, &payload)
        .map_err(|_| DecodeError::Signature)?;

    Ok(DecodedPost {
        board_id: e.board_id.clone(),
        thread_id,
        thread_origin_server_id,
        thread_title: e.thread_title.clone(),
        origin_server_id,
        origin_post_id,
        body: e.body.clone(),
        created_at,
        author_pubkey,
        author_signature,
    })
}

pub fn verify_removal_event(
    e: &RemovalEvent,
    expected_signer: &[u8; 32],
) -> Result<DecodedRemoval, DecodeError> {
    if e.protocol_version != PROTOCOL_VERSION {
        return Err(DecodeError::Protocol(e.protocol_version.clone()));
    }
    let origin_server_id = decode_fixed::<32>(&e.origin_server_id, "origin_server_id")?;
    let origin_post_id = decode_fixed::<16>(&e.origin_post_id, "origin_post_id")?;
    let server_signature = decode_fixed::<64>(&e.server_signature, "server_signature")?;
    let removed_at = parse_date(&e.removed_at)?;

    if &origin_server_id != expected_signer {
        return Err(DecodeError::Signature);
    }

    let payload = canonical_removal_payload(&RemovalEventFields {
        origin_server_id: &origin_server_id,
        origin_post_id: &origin_post_id,
        reason: &e.reason,
        removed_at,
    });
    verify_server_signature(&origin_server_id, &server_signature, &payload)
        .map_err(|_| DecodeError::Signature)?;

    Ok(DecodedRemoval {
        origin_server_id,
        origin_post_id,
        reason: e.reason.clone(),
        removed_at,
    })
}

fn write_str(buf: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    buf.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    buf.extend_from_slice(bytes);
}

fn write_bytes(buf: &mut Vec<u8>, b: &[u8]) {
    buf.extend_from_slice(&(b.len() as u32).to_be_bytes());
    buf.extend_from_slice(b);
}

fn write_opt_bytes(buf: &mut Vec<u8>, b: Option<&[u8]>) {
    match b {
        None => buf.push(0),
        Some(b) => {
            buf.push(1);
            write_bytes(buf, b);
        }
    }
}

fn write_date(buf: &mut Vec<u8>, d: Date) {
    let ord = d.to_julian_day();
    buf.extend_from_slice(&ord.to_be_bytes());
}

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn decode_fixed<const N: usize>(s: &str, field: &'static str) -> Result<[u8; N], DecodeError> {
    let v = URL_SAFE_NO_PAD.decode(s).map_err(|_| DecodeError::Base64(field))?;
    v.try_into().map_err(|_| DecodeError::Length(field))
}

fn parse_date(s: &str) -> Result<Date, DecodeError> {
    use time::format_description::FormatItem;
    use time::macros::format_description;
    const FMT: &[FormatItem<'_>] = format_description!("[year]-[month]-[day]");
    Date::parse(s, FMT).map_err(|_| DecodeError::Date)
}

fn format_date(d: Date) -> String {
    use time::format_description::FormatItem;
    use time::macros::format_description;
    const FMT: &[FormatItem<'_>] = format_description!("[year]-[month]-[day]");
    d.format(FMT).expect("date format")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rand_bytes<const N: usize>() -> [u8; N] {
        use rand::RngCore as _;
        let mut b = [0u8; N];
        rand::thread_rng().fill_bytes(&mut b);
        b
    }

    #[tokio::test]
    async fn round_trip_post_event_signs_and_verifies() {
        // We can't easily build an Identity without a DB, so build the
        // SigningKey directly and replicate the canonical signing path.
        use ed25519_dalek::{Signer, SigningKey};
        let seed: [u8; 32] = rand_bytes();
        let sk = SigningKey::from_bytes(&seed);
        let pubkey = sk.verifying_key().to_bytes();

        let thread_id: [u8; 16] = rand_bytes();
        let post_id: [u8; 16] = rand_bytes();
        let f = PostEventFields {
            board_id: "general",
            thread_id: &thread_id,
            thread_origin_server_id: &pubkey,
            thread_title: "hello",
            origin_server_id: &pubkey,
            origin_post_id: &post_id,
            body: "first post",
            created_at: Date::from_calendar_date(2026, time::Month::May, 8).unwrap(),
            author_pubkey: None,
            author_signature: None,
        };
        let payload = canonical_post_payload(&f);
        let sig = sk.sign(&payload).to_bytes();

        let evt = PostEvent {
            protocol_version: PROTOCOL_VERSION.to_string(),
            constitution_version: super::super::constitution::VERSION.to_string(),
            board_id: f.board_id.to_string(),
            thread_id: b64(f.thread_id),
            thread_origin_server_id: b64(f.thread_origin_server_id),
            thread_title: f.thread_title.to_string(),
            origin_server_id: b64(f.origin_server_id),
            origin_post_id: b64(f.origin_post_id),
            body: f.body.to_string(),
            created_at: format_date(f.created_at),
            author_pubkey: None,
            author_signature: None,
            server_signature: b64(&sig),
        };
        let decoded = verify_post_event(&evt, &pubkey).expect("verify");
        assert_eq!(decoded.body, "first post");
        assert_eq!(decoded.thread_id, thread_id);

        // Wrong expected signer fails verification.
        let other: [u8; 32] = rand_bytes();
        assert!(verify_post_event(&evt, &other).is_err());
    }
}
