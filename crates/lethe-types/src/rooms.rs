//! Private-room DTOs.
//!
//! The server stores opaque ciphertext only. The contract here is exactly
//! what crosses the wire — nothing about the symmetric room key, plaintext
//! messages, or any private key is representable in these types.

use crate::{B64, CoarseTime};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateRoomReq {
    /// If present, the client claims the room was created from this thread by
    /// `creator_thread_pubkey`. Server verifies the signature and that the
    /// pubkey actually signed at least one post in that thread.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin_thread: Option<B64>,
    pub creator_box_pubkey: B64,
    pub creator_sig_pubkey: B64,
    pub wrapped_key_for_creator: B64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub creator_thread_pubkey: Option<B64>,
    /// Detached Ed25519 sig over `canonical_room_provenance(...)`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance_sig: Option<B64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateRoomResp {
    pub room_id: B64,
    pub invite_code: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JoinRoomReq {
    pub box_pubkey: B64,
    pub sig_pubkey: B64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JoinRoomResp {
    pub room_id: B64,
    pub members: Vec<MemberView>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrapKeyReq {
    pub for_box_pubkey: B64,
    pub wrapped_key: B64,
    /// MUST equal the calling member's own box pubkey. Recorded as
    /// `invited_by_box_pubkey` on the recipient's member row.
    pub inviter_box_pubkey: B64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberView {
    pub box_pubkey: B64,
    pub sig_pubkey: B64,
    /// `None` while the joiner is still pending a key wrap.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wrapped_key: Option<B64>,
    pub joined_at: CoarseTime,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invited_by_box_pubkey: Option<B64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MembersResp {
    pub members: Vec<MemberView>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvenanceResp {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin_thread: Option<B64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub creator_thread_pubkey: Option<B64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance_sig: Option<B64>,
    pub created_at: CoarseTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendMessageReq {
    pub sender_sig_pubkey: B64,
    pub nonce: B64,
    pub ciphertext: B64,
    pub sender_sig: B64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendMessageResp {
    pub message_id: B64,
    pub created_at: CoarseTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageView {
    pub message_id: B64,
    pub sender_sig_pubkey: B64,
    pub nonce: B64,
    pub ciphertext: B64,
    pub sender_sig: B64,
    pub created_at: CoarseTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessagesResp {
    pub messages: Vec<MessageView>,
}

/// Authenticated request to list messages. The server gates the response
/// to messages with `created_at >= requester's joined_at`. The signature
/// proves membership and the timestamp prevents replays.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListMessagesReq {
    pub requester_sig_pubkey: B64,
    /// Unix timestamp (seconds). Server rejects if more than 60 s skew.
    pub ts: i64,
    pub sig: B64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<B64>,
}

/// Canonical bytes signed for an authenticated message list request.
pub fn canonical_list_request(room_id: &[u8], ts: i64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(14 + room_id.len() + 8);
    buf.extend_from_slice(b"lethe-list-v1\x00");
    buf.extend_from_slice(room_id);
    buf.extend_from_slice(&ts.to_le_bytes());
    buf
}

/// Canonical bytes the room creator signs to attest provenance.
///
/// SLICE LIMITATION: this binds `(origin_thread, creator_thread_pubkey)` only —
/// it does NOT bind a specific `room_id`. A malicious server could replay the
/// same signature on multiple rooms claiming the same provenance. The trust
/// signal it provides is "the creator was a signed participant in this
/// thread," nothing more. A future revision should switch to a
/// client-proposed `room_id` and include it in the payload.
pub fn canonical_room_provenance(origin_thread: &[u8], creator_thread_pubkey: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(14 + origin_thread.len() + 32);
    buf.extend_from_slice(b"lethe-room-v1\x00");
    buf.extend_from_slice(origin_thread);
    buf.extend_from_slice(creator_thread_pubkey);
    buf
}

/// Canonical bytes that a room member signs over to authenticate a message
/// blob to other members. The server verifies this too, only as a coarse
/// "the sender is a member of this room" gate — clients re-verify locally.
pub fn canonical_message_payload(room_id: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(13 + room_id.len() + nonce.len() + ciphertext.len());
    buf.extend_from_slice(b"lethe-msg-v1\x00");
    buf.extend_from_slice(room_id);
    buf.extend_from_slice(nonce);
    buf.extend_from_slice(ciphertext);
    buf
}
