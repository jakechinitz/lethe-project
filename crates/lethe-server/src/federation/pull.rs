//! Background worker that pulls signed events from each enabled peer.
//!
//! Per cycle, for each enabled peer:
//!   1. Read the peer's stored `last_cursor` (encoded as JSON of two
//!      opaque sub-cursors, one per event kind).
//!   2. GET `<peer.endpoint>/api/federation/events?since_post=...`.
//!   3. For each `PostEvent`: verify the signature against the peer's
//!      pubkey, run the body through `moderation::evaluate`, and call
//!      `db::posts::insert_federated`. On insert, the local
//!      moderation pipeline applies — so a stricter operator drops
//!      what a looser peer accepted.
//!   4. For each `RemovalEvent`: verify the signature, look up the
//!      local row id by `(origin_server_id, origin_post_id)`, and
//!      insert a `post_removals` row with `scope='global'`. The
//!      `origin_signature` is preserved so an audit can re-verify the
//!      takedown later.
//!   5. Persist the new cursor and timestamp.
//!
//! Errors are logged and the worker moves on; one bad peer doesn't
//! poison the rest. A peer whose cursor returns nothing new is
//! silent.

use crate::{
    db,
    federation::{events, identity::Identity},
    moderation,
};
use base64::Engine as _;
use lethe_types::posts::canonical_post_payload;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::sync::Arc;
use std::time::Duration;

/// User-Agent set on every outbound federation pull. Identical
/// across all Lethe servers regardless of build, so peer logs can't
/// distinguish individual pullers by their reqwest minor version or
/// reqwest patch level. See the comment in `run_once` for why a
/// fixed string is preferable to the default per-build UA.
pub(crate) const USER_AGENT: &str = "Lethe-Federation/lethe-fed-v1";

#[derive(Debug, Default, Serialize, Deserialize)]
struct StoredCursor {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    post: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    removal: Option<String>,
}

pub fn spawn(
    db: PgPool,
    identity: Arc<Identity>,
    classifier: Arc<dyn moderation::classifier::Classifier>,
    interval: Duration,
) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(interval);
        // First tick fires immediately; we let it, so first-pull
        // happens at startup rather than after one full interval.
        loop {
            tick.tick().await;
            if let Err(e) = run_once(&db, &identity, classifier.as_ref()).await {
                tracing::warn!(error = ?e, "federation pull cycle failed");
            }
        }
    });
}

#[derive(Debug, Default)]
pub struct PullStats {
    pub peers_visited: usize,
    pub posts_accepted: usize,
    pub posts_rejected: usize,
    pub removals_applied: usize,
}

pub async fn run_once(
    db: &PgPool,
    identity: &Identity,
    classifier: &dyn moderation::classifier::Classifier,
) -> Result<PullStats, Box<dyn std::error::Error + Send + Sync>> {
    let peers = db::federation::list_enabled_peers(db).await?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        // Fixed UA across every Lethe server. The path
        // `/api/federation/events` already announces Lethe to anyone
        // observing the request; what we *don't* want is the default
        // `reqwest/<version>` string differentiating servers by their
        // build date. Using `lethe-fed-v1` (the protocol version,
        // never bumped within a major) keeps every Lethe puller
        // looking identical.
        .user_agent(USER_AGENT)
        .build()?;

    let mut stats = PullStats::default();
    for peer in peers {
        if peer.server_pubkey.len() != 32 {
            tracing::warn!(
                pubkey_len = peer.server_pubkey.len(),
                "skipping peer with malformed pubkey"
            );
            continue;
        }
        let mut peer_pubkey = [0u8; 32];
        peer_pubkey.copy_from_slice(&peer.server_pubkey);

        let cursor: StoredCursor = peer
            .last_cursor
            .as_deref()
            .and_then(|b| serde_json::from_slice(b).ok())
            .unwrap_or_default();

        let url = build_url(&peer.endpoint, &cursor);
        let resp = match client.get(&url).send().await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(error = %e, peer = %peer.endpoint, "fetch failed");
                continue;
            }
        };
        if !resp.status().is_success() {
            tracing::warn!(status = %resp.status(), peer = %peer.endpoint, "non-success");
            continue;
        }
        let body: events::EventsResponse = match resp.json().await {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(error = %e, peer = %peer.endpoint, "decode failed");
                continue;
            }
        };

        let mut posts_accepted = 0usize;
        let mut posts_rejected = 0usize;
        for evt in &body.posts {
            match apply_post_event(db, classifier, evt, &peer_pubkey, identity.pubkey()).await {
                Ok(true) => posts_accepted += 1,
                Ok(false) => posts_rejected += 1,
                Err(e) => {
                    // Production logs get a coarse classifier so a
                    // peer-correlated journal entry never carries the
                    // inner DB error / event content. Operators
                    // wanting specifics flip RUST_LOG=debug on the
                    // affected node and replay.
                    tracing::warn!(
                        kind = ingest_error_kind(e.as_ref()),
                        peer = %peer.endpoint,
                        "post event ingest failed",
                    );
                    tracing::debug!(error = ?e, peer = %peer.endpoint, "post event ingest failed (detail)");
                    posts_rejected += 1;
                }
            }
        }

        let mut removals_applied = 0usize;
        for evt in &body.removals {
            match apply_removal_event(db, evt, &peer_pubkey).await {
                Ok(true) => removals_applied += 1,
                Ok(false) => {}
                Err(e) => {
                    tracing::warn!(
                        kind = ingest_error_kind(e.as_ref()),
                        peer = %peer.endpoint,
                        "removal event ingest failed",
                    );
                    tracing::debug!(error = ?e, peer = %peer.endpoint, "removal event ingest failed (detail)");
                }
            }
        }

        stats.peers_visited += 1;
        stats.posts_accepted += posts_accepted;
        stats.posts_rejected += posts_rejected;
        stats.removals_applied += removals_applied;

        let next_cursor = StoredCursor {
            post: body.next_post_cursor.or(cursor.post),
            removal: body.next_removal_cursor.or(cursor.removal),
        };
        let encoded = serde_json::to_vec(&next_cursor)?;
        db::federation::save_cursor(db, &peer.server_pubkey, &encoded).await?;

        if posts_accepted + posts_rejected + removals_applied > 0 {
            tracing::info!(
                peer = %peer.endpoint,
                accepted = posts_accepted,
                rejected = posts_rejected,
                removals = removals_applied,
                "federation pull",
            );
        }
    }

    Ok(stats)
}

fn build_url(endpoint: &str, cursor: &StoredCursor) -> String {
    let base = endpoint.trim_end_matches('/');
    let mut url = format!("{base}/api/federation/events");
    let mut q = Vec::new();
    if let Some(c) = &cursor.post {
        q.push(format!("since_post={}", urlencode(c)));
    }
    if let Some(c) = &cursor.removal {
        q.push(format!("since_removal={}", urlencode(c)));
    }
    if !q.is_empty() {
        url.push('?');
        url.push_str(&q.join("&"));
    }
    url
}

fn urlencode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// Returns Ok(true) if the post was newly accepted, Ok(false) if it was
/// rejected by local moderation or already known, Err on transport /
/// signature / decode failure.
async fn apply_post_event(
    db: &PgPool,
    classifier: &dyn moderation::classifier::Classifier,
    evt: &events::PostEvent,
    expected_signer: &[u8; 32],
    self_pubkey: &[u8; 32],
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    // Drop our own posts that come back via a peer (e.g. A→B→A loop).
    let claimed_origin = base64_decode_32(&evt.origin_server_id)?;
    if &claimed_origin == self_pubkey {
        return Ok(false);
    }

    let decoded = events::verify_post_event(evt, expected_signer)?;

    // Optional author signature is verified against the per-thread key
    // and the canonical post payload. A bad author signature drops the
    // post but does NOT discredit the federated copy itself — the
    // server signature already authenticates origin.
    if let (Some(pk), Some(sig)) = (decoded.author_pubkey, decoded.author_signature) {
        let payload = canonical_post_payload(&decoded.thread_id, &decoded.body);
        if ed25519_verify(&pk, &sig, &payload).is_err() {
            tracing::warn!("dropped federated post: author signature mismatch");
            return Ok(false);
        }
    }

    // Local moderation gate at ingest. If the local pipeline rejects,
    // we drop the post and log a moderation_actions row, exactly like
    // the local write path would.
    if let moderation::Verdict::Reject(reason) =
        moderation::evaluate(db, &decoded.board_id, &decoded.body, classifier).await?
    {
        tracing::debug!(?reason, "dropped federated post: local moderation");
        moderation::log_reject(db, Some(&decoded.board_id), &decoded.body, reason).await?;
        return Ok(false);
    }

    // Upsert the thread first so the post insert finds it.
    db::threads::ensure_for_federation(
        db,
        &decoded.thread_id,
        &decoded.board_id,
        &decoded.thread_title,
        decoded.created_at,
        &decoded.thread_origin_server_id,
    )
    .await?;

    let inserted = db::posts::insert_federated(
        db,
        db::posts::FederatedPost {
            thread_id: &decoded.thread_id,
            body: &decoded.body,
            pubkey: decoded.author_pubkey.as_ref().map(|a| &a[..]),
            signature: decoded.author_signature.as_ref().map(|a| &a[..]),
            created_at: decoded.created_at,
            origin_server_id: &decoded.origin_server_id,
            origin_post_id: &decoded.origin_post_id,
        },
    )
    .await?;
    Ok(inserted.is_some())
}

async fn apply_removal_event(
    db: &PgPool,
    evt: &events::RemovalEvent,
    expected_signer: &[u8; 32],
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    let decoded = events::verify_removal_event(evt, expected_signer)?;
    let server_sig: [u8; 64] = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&evt.server_signature)?
        .try_into()
        .map_err(|_| "removal signature length")?;

    let local_id = match db::federation::local_id_for_origin(
        db,
        &decoded.origin_server_id,
        &decoded.origin_post_id,
    )
    .await?
    {
        Some(id) => id,
        // We don't have the post yet — nothing to remove. The plan
        // explicitly does not buffer pending removals at MVP.
        None => return Ok(false),
    };

    let inserted = db::post_removals::insert(
        db,
        db::post_removals::NewRemoval {
            post_id: &local_id,
            reason: &decoded.reason,
            scope: db::post_removals::Scope::Global,
            origin_server_id: Some(&decoded.origin_server_id),
            origin_signature: Some(&server_sig),
            removed_at: decoded.removed_at,
        },
    )
    .await?;
    Ok(inserted)
}

fn base64_decode_32(s: &str) -> Result<[u8; 32], &'static str> {
    let v = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| "base64")?;
    v.try_into().map_err(|_| "length")
}

/// Re-implementation of crypto::verify_post_signature without taking a
/// dep on that module's error type — the federation worker logs and
/// drops, it doesn't need a structured `AppError`.
fn ed25519_verify(pubkey: &[u8; 32], sig: &[u8; 64], msg: &[u8]) -> Result<(), &'static str> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let vk = VerifyingKey::from_bytes(pubkey).map_err(|_| "bad pubkey")?;
    vk.verify(msg, &Signature::from_bytes(sig))
        .map_err(|_| "verify failed")
}

/// Coarse classifier for ingest failures, used as the only field in
/// the warn-level log line. The full Debug repr lands at debug
/// level, so an operator who needs specifics enables
/// `RUST_LOG=lethe_server=debug` on the affected node.
///
/// Invariant: this function returns one of a small fixed set of
/// `&'static str` values and never reflects user content (post
/// bodies, peer-supplied JSON, SQL parameter values).
///
/// The string-only error paths (e.g. `.map_err(|_| "...")?` for a
/// length check) classify as `"other"` because `&'static str` does
/// not implement `std::error::Error` and so can't be downcast back
/// out of a `Box<dyn Error>`. That's accepted: those paths are rare
/// length-validation errors, the warn line still fires, and an
/// operator wanting detail flips on debug logging.
fn ingest_error_kind(e: &(dyn std::error::Error + 'static)) -> &'static str {
    if e.downcast_ref::<events::DecodeError>().is_some() {
        return "decode";
    }
    if e.downcast_ref::<sqlx::Error>().is_some() {
        return "db";
    }
    if e.downcast_ref::<base64::DecodeError>().is_some() {
        return "base64";
    }
    "other"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ingest_error_kind_classifies_known_variants() {
        let e: Box<dyn std::error::Error + Send + Sync> =
            Box::new(events::DecodeError::Signature);
        assert_eq!(ingest_error_kind(e.as_ref()), "decode");

        let e: Box<dyn std::error::Error + Send + Sync> =
            Box::new(sqlx::Error::Configuration("anything".into()));
        assert_eq!(ingest_error_kind(e.as_ref()), "db");
    }

    #[test]
    fn ingest_error_kind_returns_static_strings_only() {
        // Anything not specifically classified falls into "other" —
        // the warn line still fires and operators flip debug level
        // to investigate.
        let kinds = ["decode", "db", "base64", "other"];
        let dummy: Box<dyn std::error::Error + Send + Sync> =
            Box::new(std::io::Error::other("x"));
        assert!(kinds.contains(&ingest_error_kind(dummy.as_ref())));
    }

    #[test]
    fn user_agent_is_protocol_version_only() {
        // The whole point of fixing M2 is that every Lethe puller
        // looks identical. If someone bumps the UA to include the
        // crate version (`Lethe-Federation/0.1.0`) or the reqwest
        // version, this test fails — the cure would re-introduce
        // build-date fingerprintability across servers.
        assert_eq!(USER_AGENT, "Lethe-Federation/lethe-fed-v1");
        assert!(
            !USER_AGENT.contains(env!("CARGO_PKG_VERSION")),
            "UA must not embed the crate version",
        );
        assert!(
            !USER_AGENT.contains("reqwest"),
            "UA must not embed the reqwest version",
        );
    }
}

