//! Private-room DTOs.
//!
//! The server stores opaque ciphertext only. The contract here is exactly
//! what crosses the wire — nothing about the symmetric room key, plaintext
//! messages, or any private key is representable in these types.

use crate::{B64, CoarseDate};
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
    /// If present and non-empty, only joiners able to prove control of one
    /// of these thread-signing pubkeys may join via the invite link. The
    /// pubkeys must each have signed at least one post in `origin_thread`;
    /// the server enforces that when the room is created. Requires
    /// `origin_thread` to be set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowlist_thread_pubkeys: Option<Vec<B64>>,
    /// Unix timestamp (seconds). Server rejects if more than 60 s skew.
    pub creator_create_ts: i64,
    /// Detached Ed25519 sig by `creator_sig_pubkey` over
    /// `canonical_create_room(...)`. Proves the caller controls
    /// `creator_sig_pubkey` and consented to room creation under
    /// `creator_box_pubkey`.
    pub creator_create_sig: B64,
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
    /// For restricted (allowlisted) rooms, the joiner proves ownership of
    /// one of the allowed thread-signing pubkeys. Three fields together:
    /// `proof_thread_pubkey` (the Ed25519 thread key), `proof_ts` (a
    /// fresh unix timestamp), and `proof_sig` (a detached signature over
    /// `canonical_join_proof(invite_code, box_pubkey, ts)`). Open rooms
    /// accept the request without these fields.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_thread_pubkey: Option<B64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_ts: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_sig: Option<B64>,
}

/// Public, unauthenticated view of an invite, used by the join page to
/// figure out whether the invite is open or restricted before generating
/// keys.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InviteInfo {
    pub room_id: B64,
    /// Originating thread, if any. `None` for free-standing rooms.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin_thread: Option<B64>,
    /// `true` iff joining requires proving ownership of one of the
    /// allowed thread-signing pubkeys.
    pub restricted: bool,
    /// Allowlisted thread-signing pubkeys, if restricted. Public so the
    /// joiner can confirm they have a matching key locally.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowlist_thread_pubkeys: Option<Vec<B64>>,
    /// How many days the server keeps message ciphertext before the
    /// retention worker deletes it. Shown to joiners up front so the
    /// ephemerality of room history is never a surprise.
    #[serde(default)]
    pub message_retention_days: i16,
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
    /// The inviter's Ed25519 signing pubkey. Server checks that
    /// `(inviter_sig_pubkey, inviter_box_pubkey)` is an active member
    /// row, so the inviter can't claim someone else's box pubkey.
    pub inviter_sig_pubkey: B64,
    pub inviter_ts: i64,
    /// Detached Ed25519 sig by `inviter_sig_pubkey` over
    /// `canonical_wrap_request(...)`.
    pub inviter_sig: B64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MembersResp {
    pub members: Vec<MemberView>,
    pub current_epoch: i32,
    /// Server-side ciphertext lifetime in days; the room page surfaces
    /// it next to the message list ("messages are deleted from the
    /// server after N days").
    #[serde(default)]
    pub message_retention_days: i16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberView {
    pub box_pubkey: B64,
    pub sig_pubkey: B64,
    /// `None` while the joiner is still pending a key wrap.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wrapped_key: Option<B64>,
    pub joined_at: CoarseDate,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invited_by_box_pubkey: Option<B64>,
    /// `Some(ts)` if this member has been removed from the room. Removed
    /// members cannot post or list messages but their entry remains for
    /// invite-chain auditability.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub removed_at: Option<CoarseDate>,
}

/// Body of `POST /api/rooms/:room_id/remove`. The creator removes a
/// member AND rekeys the room in one atomic call: the request body
/// carries the new `wrapped_key` for every still-active member.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoveMemberReq {
    pub remover_sig_pubkey: B64,
    pub ts: i64,
    pub sig: B64,
    pub target_box_pubkey: B64,
    pub new_wrapped_keys: Vec<RewrapEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewrapEntry {
    pub for_box_pubkey: B64,
    pub wrapped_key: B64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoveMemberResp {
    pub current_epoch: i32,
}

/// Canonical bytes signed for a remove-and-rekey request.
///
/// The `new_wrapped_keys` aren't included in the payload because the only
/// signer with authority to sign this is the creator, the server validates
/// `for_box_pubkey` against the actual member list before applying any
/// change, and including them would require a stable serialization order.
///
/// Server checks: `(now - ts).abs() <= 60`.
pub fn canonical_remove_request(
    room_id: &[u8],
    ts: i64,
    target_box_pubkey: &[u8],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(16 + room_id.len() + 8 + 32);
    buf.extend_from_slice(b"lethe-remove-v1\x00");
    buf.extend_from_slice(room_id);
    buf.extend_from_slice(&ts.to_le_bytes());
    buf.extend_from_slice(target_box_pubkey);
    buf
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvenanceResp {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin_thread: Option<B64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub creator_thread_pubkey: Option<B64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance_sig: Option<B64>,
    pub created_at: CoarseDate,
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
    pub created_at: CoarseDate,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageView {
    pub message_id: B64,
    /// Per-room monotonic insertion ordinal. Stable across reads and
    /// the only field clients should use for ordering or cursors —
    /// `message_id` is uniform random and `created_at` is date-only.
    pub seq: i64,
    pub sender_sig_pubkey: B64,
    pub nonce: B64,
    pub ciphertext: B64,
    pub sender_sig: B64,
    pub created_at: CoarseDate,
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
    /// Cursor: the largest `seq` the client already has. The server
    /// returns messages with `seq > since_seq`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since_seq: Option<i64>,
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

/// Body of `POST /api/rooms/:room_id/leave`. The signer's `sig_pubkey`
/// is taken to be the leaving member.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaveRoomReq {
    pub sig_pubkey: B64,
    pub ts: i64,
    pub sig: B64,
}

/// Canonical bytes the leaving member signs:
///   `b"lethe-leave-v1\0" || room_id || ts_le8`.
pub fn canonical_leave_request(room_id: &[u8], ts: i64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(15 + room_id.len() + 8);
    buf.extend_from_slice(b"lethe-leave-v1\x00");
    buf.extend_from_slice(room_id);
    buf.extend_from_slice(&ts.to_le_bytes());
    buf
}

/// Canonical bytes a joiner signs to prove ownership of an allowlisted
/// thread-signing key when joining a restricted room. Binds the invite
/// code (so a captured signature can't be reused on another invite) and
/// the joiner's box pubkey (so the proof can't be replayed by someone
/// else who knows the same thread key but a different box pair).
pub fn canonical_join_proof(invite_code: &str, box_pubkey: &[u8], ts: i64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(14 + invite_code.len() + 32 + 8);
    buf.extend_from_slice(b"lethe-join-v1\x00");
    buf.extend_from_slice(invite_code.as_bytes());
    buf.extend_from_slice(box_pubkey);
    buf.extend_from_slice(&ts.to_le_bytes());
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

/// Canonical bytes a room creator signs to authenticate `POST /api/rooms`.
///
/// Binds the creator's two pubkeys, the self-wrapped room key, and a
/// fresh timestamp. The optional thread-provenance fields aren't bound
/// because the server already verifies the provenance signature
/// separately against the creator's *thread* key, which is a different
/// signing identity from `creator_sig_pubkey`.
///
/// Server checks: `(now - ts).abs() <= 60`.
pub fn canonical_create_room(
    creator_box_pubkey: &[u8],
    creator_sig_pubkey: &[u8],
    wrapped_key_for_creator: &[u8],
    ts: i64,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(
        16 + 8 + creator_box_pubkey.len() + creator_sig_pubkey.len() + wrapped_key_for_creator.len(),
    );
    buf.extend_from_slice(b"lethe-create-v1\x00");
    buf.extend_from_slice(&ts.to_le_bytes());
    buf.extend_from_slice(creator_box_pubkey);
    buf.extend_from_slice(creator_sig_pubkey);
    buf.extend_from_slice(wrapped_key_for_creator);
    buf
}

/// Canonical bytes an existing member signs to authenticate a
/// `POST /api/rooms/:room_id/wrap` call. Binds the room id, the
/// recipient's box pubkey, the wrapped-key bytes, and a fresh ts so
/// captured wraps can't be replayed (`request_nonces` dedupes
/// `(kind="wrap:<for_box_pubkey>", sig_pubkey, ts)`).
///
/// Server checks: `(now - ts).abs() <= 60`.
pub fn canonical_wrap_request(
    room_id: &[u8],
    for_box_pubkey: &[u8],
    wrapped_key: &[u8],
    ts: i64,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(
        14 + room_id.len() + 8 + for_box_pubkey.len() + wrapped_key.len(),
    );
    buf.extend_from_slice(b"lethe-wrap-v1\x00");
    buf.extend_from_slice(&ts.to_le_bytes());
    buf.extend_from_slice(room_id);
    buf.extend_from_slice(for_box_pubkey);
    buf.extend_from_slice(wrapped_key);
    buf
}
