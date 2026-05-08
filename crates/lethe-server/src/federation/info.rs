//! Payload for `GET /api/federation/info` — what code and what
//! moderation floor a server is running, in a single JSON document.
//!
//! This is the verifiability layer: peers (and curious end users) can
//! see the server's pubkey, the protocol version, the constitution
//! version + hash, the build's code version + commit, and a free-form
//! note about whether local moderation is at the floor or stricter.
//! There is no reproducible-build claim here yet — `code_commit` is
//! verifiable only by reading source, not by attestation. That's
//! honest at MVP; signed reproducible releases are a separate work
//! item.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct InfoResponse {
    pub server_pubkey: String,
    pub protocol_version: &'static str,
    pub constitution_version: &'static str,
    pub constitution_hash: &'static str,
    pub code_version: &'static str,
    pub code_commit: &'static str,
    pub local_moderation_summary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operator_label: Option<String>,
}

pub fn build(
    server_pubkey: &[u8; 32],
    local_moderation_summary: String,
    operator_label: Option<String>,
) -> InfoResponse {
    InfoResponse {
        server_pubkey: URL_SAFE_NO_PAD.encode(server_pubkey),
        protocol_version: super::events::PROTOCOL_VERSION,
        constitution_version: super::constitution::VERSION,
        constitution_hash: super::constitution::HASH,
        code_version: env!("CARGO_PKG_VERSION"),
        code_commit: env!("LETHE_GIT_COMMIT"),
        local_moderation_summary,
        operator_label,
    }
}
