//! Public-board post DTOs: thread creation, replies, listings.

use crate::{B64, CoarseTime};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateThreadReq {
    pub board_id: String,
    pub title: String,
    pub body: String,
    pub pow_nonce: B64,
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
    pub created_at: CoarseTime,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pubkey: Option<B64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_first_seq: Option<i32>,
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
