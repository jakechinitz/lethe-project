//! Public-board post DTOs: thread creation, replies, listings.

use crate::{B64, CoarseDate};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateThreadReq {
    pub board_id: String,
    pub title: String,
    pub body: String,
    pub pow_nonce: B64,
    /// Client-minted 16-byte ULID. Required when `pubkey` is present
    /// because the signature payload includes the thread id; optional
    /// otherwise (server generates one).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thread_id: Option<B64>,
    /// Optional Ed25519 public key, identical semantics to a signed
    /// reply: any later post signed with the same key shows as the
    /// same anon (and as "OP" since it's post #1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pubkey: Option<B64>,
    /// Detached Ed25519 signature over
    /// `b"lethe-post-v1" || thread_id || body`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<B64>,
    /// Author-chosen thread lifetime in days. `None` (the default)
    /// means the thread never expires; a number means the retention
    /// worker deletes the whole thread (posts cascade) once
    /// `created_at + expires_in_days` arrives. 1..=3650.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_in_days: Option<i32>,
    /// Optional room vouch on the OP. Requires `thread_id` (the vouch
    /// binds it). See [`VouchPayload`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vouch: Option<VouchPayload>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateThreadResp {
    pub thread_id: B64,
    pub seq: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreatePostReq {
    pub body: String,
    pub pow_nonce: B64,
    /// Ed25519 public key (32 bytes) the client used for thread-local
    /// continuity. `None` = fully anonymous post.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pubkey: Option<B64>,
    /// Detached Ed25519 signature over the canonical payload
    /// `b"lethe-post-v1" || thread_id || body`. Must be `Some` iff `pubkey` is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<B64>,
    /// Optional room vouch. See [`VouchPayload`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vouch: Option<VouchPayload>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreatePostResp {
    pub post_id: B64,
    pub seq: i32,
    /// If the post was signed, the earliest `seq` in this thread that the
    /// same pubkey signed. Powers "same anon as #N" in the UI.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_first_seq: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostView {
    pub post_id: B64,
    pub seq: i32,
    pub body: String,
    pub created_at: CoarseDate,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pubkey: Option<B64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_first_seq: Option<i32>,
    /// 32-byte Ed25519 pubkey of the server this post originated on.
    /// May be absent on legacy rows; clients should treat absent as
    /// "this server" for backwards compatibility.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin_server_id: Option<B64>,
    /// Human label of the origin server, joined from
    /// `federation_peers.label`. `None` when the origin is the
    /// reading server itself, or when it's an un-labelled peer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin_server_label: Option<String>,
    /// Room vouch, served verbatim. Readers verify it locally against
    /// the room's public roster; the server's acceptance is not a
    /// trust signal (the server is untrusted).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vouch: Option<VouchPayload>,
}

/// A room vouch: a linkable ring signature (LSAG over Ed25519) by one
/// of the room's accepted members over this post, pinned to a
/// creator-signed roster.
///
/// Wire/verification contract (server, browser, and tests all
/// implement exactly this):
///
/// * `ring` is the roster's member signing pubkeys, sorted ascending
///   by their 32 raw bytes, 1..=50 entries. Sorted order hides the
///   signer's position.
/// * `creator_sig` is the room creator's Ed25519 signature over
///   [`crate::rooms::canonical_roster`]`(room_id, roster_epoch, ring)`.
/// * Key-image base for ring member `P_i`:
///   `Hp_i = H2P(b"lethe-vouch-ki-v1\0" || room_id || thread_id || P_i)`
///   where `H2P(x)` = libsodium `crypto_core_ed25519_from_uniform`
///   applied to the first 32 bytes of `SHA-512(x)` (identical to
///   curve25519-dalek's `nonspec_map_to_curve::<Sha512>(x)`).
/// * `key_image = x_signer * Hp_signer`. Deterministic per
///   `(member, room, thread)`: two vouches by the same member in the
///   same thread share it (linkable); across threads they don't.
/// * Message digest
///   `m = SHA-512(b"lethe-vouch-msg-v1\0" || room_id || thread_id ||
///      SHA-256(body) || epoch_le4 || n_le2 || ring || key_image)`.
/// * Challenge `c_{i+1} = reduce_mod_l(SHA-512(b"lethe-vouch-ch-v1\0"
///   || m || L_i || R_i))` with `L_i = s_i*G + c_i*P_i`,
///   `R_i = s_i*Hp_i + c_i*I`. Verification starts at `c0`, walks the
///   ring, and requires the final challenge to equal `c0`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VouchPayload {
    pub room_id: B64,
    pub roster_epoch: i32,
    pub creator_sig: B64,
    pub ring: Vec<B64>,
    pub key_image: B64,
    pub c0: B64,
    pub s: Vec<B64>,
}

pub const VOUCH_MAX_RING: usize = 50;

/// Bytes hashed to derive ring member `i`'s key-image base point.
pub fn vouch_key_image_input(room_id: &[u8], thread_id: &[u8], member_pubkey: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(18 + room_id.len() + thread_id.len() + member_pubkey.len());
    buf.extend_from_slice(b"lethe-vouch-ki-v1\x00");
    buf.extend_from_slice(room_id);
    buf.extend_from_slice(thread_id);
    buf.extend_from_slice(member_pubkey);
    buf
}

/// Bytes hashed (SHA-512) to form the ring-signature message `m`.
/// `body_sha256` is the 32-byte SHA-256 of the post body.
pub fn vouch_message_input(
    room_id: &[u8],
    thread_id: &[u8],
    body_sha256: &[u8; 32],
    roster_epoch: i32,
    ring: &[Vec<u8>],
    key_image: &[u8],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(19 + 16 + 16 + 32 + 4 + 2 + ring.len() * 32 + 32);
    buf.extend_from_slice(b"lethe-vouch-msg-v1\x00");
    buf.extend_from_slice(room_id);
    buf.extend_from_slice(thread_id);
    buf.extend_from_slice(body_sha256);
    buf.extend_from_slice(&(roster_epoch as u32).to_le_bytes());
    buf.extend_from_slice(&(ring.len() as u16).to_le_bytes());
    for p in ring {
        buf.extend_from_slice(p);
    }
    buf.extend_from_slice(key_image);
    buf
}

/// Bytes hashed (SHA-512, then reduced mod l) for each ring challenge.
pub fn vouch_challenge_input(m: &[u8; 64], l: &[u8; 32], r: &[u8; 32]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(18 + 64 + 64);
    buf.extend_from_slice(b"lethe-vouch-ch-v1\x00");
    buf.extend_from_slice(m);
    buf.extend_from_slice(l);
    buf.extend_from_slice(r);
    buf
}

/// Canonical bytes that a thread-signing key signs over for a post.
/// Server and browser MUST produce identical bytes.
pub fn canonical_post_payload(thread_id: &[u8], body: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(13 + thread_id.len() + body.len());
    buf.extend_from_slice(b"lethe-post-v1");
    buf.extend_from_slice(thread_id);
    buf.extend_from_slice(body.as_bytes());
    buf
}

/// Body of `POST /api/posts/:post_id/delete`. Only the author of a
/// *signed* post can delete it: the request must carry a fresh
/// signature from the same Ed25519 key that signed the post. Fully
/// anonymous posts have no key and therefore no owner who can prove
/// the right to delete — they cannot be self-deleted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeletePostReq {
    /// Must equal the pubkey stored on the post.
    pub pubkey: B64,
    /// Unix timestamp (seconds). Server rejects if more than 60 s skew.
    pub ts: i64,
    /// Detached Ed25519 sig over `canonical_delete_request(post_id, ts)`.
    pub sig: B64,
}

/// Canonical bytes the author signs to delete their own post:
///   `b"lethe-delete-v1\0" || post_id || ts_le8`.
/// Binding the post id stops one capture deleting a different post;
/// binding ts + the request-nonce table stops replays.
pub fn canonical_delete_request(post_id: &[u8], ts: i64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(16 + post_id.len() + 8);
    buf.extend_from_slice(b"lethe-delete-v1\x00");
    buf.extend_from_slice(post_id);
    buf.extend_from_slice(&ts.to_le_bytes());
    buf
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportPostReq {
    /// Optional free-text reason from the reporter. Capped at 500 chars
    /// server-side; empty / missing means "no reason given."
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// PoW nonce computed over `post_id || reason_bytes || nonce`. The
    /// server applies the same difficulty as a regular post so reporting
    /// isn't a free flood vector.
    pub pow_nonce: B64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportPostResp {
    pub report_id: B64,
}
