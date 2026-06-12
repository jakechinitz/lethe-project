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
