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
    /// SHA-256 of the published multi-key signed release manifest, if
    /// the operator pointed `LETHE_RELEASE_MANIFEST` at one. `None`
    /// means "this binary is running without a signed manifest" —
    /// peers that require attested releases should refuse to peer
    /// with such a server.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub release_manifest_sha256: Option<String>,
}

pub fn build(
    server_pubkey: &[u8; 32],
    local_moderation_summary: String,
    operator_label: Option<String>,
    release_manifest_sha256: Option<String>,
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
        release_manifest_sha256,
    }
}

/// Reads the release-manifest file at the given path and returns its
/// SHA-256, hex-encoded. Errors are logged at startup, not surfaced
/// to peers — a missing/unreadable manifest just means
/// `release_manifest_sha256` stays `None` in the info response.
pub fn manifest_sha256(path: &str) -> Option<String> {
    use sha2::{Digest, Sha256};
    let bytes = std::fs::read(path).ok()?;
    let mut h = Sha256::new();
    h.update(&bytes);
    let digest = h.finalize();
    let mut s = String::with_capacity(64);
    for b in digest {
        s.push_str(&format!("{b:02x}"));
    }
    Some(s)
}
