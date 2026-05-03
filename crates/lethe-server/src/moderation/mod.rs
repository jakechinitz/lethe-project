//! Public-content moderation.
//!
//! Two layers run on every public post submission, after PoW verification
//! and before insert. Both produce the same `Verdict` shape.
//!
//! 1. `rules` — deterministic checks: duplicate body within 24 h, body
//!    too short, link-density spam pattern, host blocklist match.
//! 2. `classifier` — pluggable AI classifier. The default
//!    implementation is a no-op that always allows; plugging in a real
//!    model is a single trait impl swap.
//!
//! A reject from either layer:
//!   - aborts the submit (the post is never inserted),
//!   - records a `moderation_actions` row (board_id + body hash + reason),
//!   - surfaces the reason to the client as a 400 so the user knows why.
//!
//! This module never sees private-room ciphertext. The hook lives in
//! `logic::posts` only.

pub mod classifier;
pub mod rules;

use crate::db;
use sqlx::PgPool;

/// What to do with a submission. `Allow` lets it through; `Reject` cancels
/// the insert and records a reason in the public moderation log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    Reject(Reason),
}

/// Short, stable, machine-readable reason codes. The public moderation
/// log displays these verbatim, so additions need to stay terse and
/// honest. New variants must remain narrow — vague catch-alls don't
/// belong here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    SpamDuplicate,
    SpamLinkDensity,
    SpamTooShort,
    MalwareLink,
    HarassmentOrHate,
    AiClassifier,
}

impl Reason {
    pub fn code(&self) -> &'static str {
        match self {
            Reason::SpamDuplicate    => "spam_duplicate",
            Reason::SpamLinkDensity  => "spam_link_density",
            Reason::SpamTooShort     => "spam_too_short",
            Reason::MalwareLink      => "malware_link",
            Reason::HarassmentOrHate => "harassment_or_hate",
            Reason::AiClassifier     => "ai_classifier",
        }
    }
}

/// Runs the full pipeline. Returns the verdict; the caller is
/// responsible for logging the reason (and for not inserting the post).
pub async fn evaluate(
    db: &PgPool,
    board_id: &str,
    body: &str,
    cls: &dyn classifier::Classifier,
) -> Result<Verdict, sqlx::Error> {
    if let Some(reason) = rules::evaluate(db, board_id, body).await? {
        return Ok(Verdict::Reject(reason));
    }
    if let Some(reason) = cls.classify(body) {
        return Ok(Verdict::Reject(reason));
    }
    Ok(Verdict::Allow)
}

/// SHA-256 of the rejected body, used both for the moderation-log row
/// and for fast duplicate detection.
pub fn body_hash(body: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(body.as_bytes());
    h.finalize().into()
}

/// Logs a moderation reject. Called by the post-submit handler.
pub async fn log_reject(
    pool: &PgPool,
    board_id: Option<&str>,
    body: &str,
    reason: Reason,
) -> Result<(), sqlx::Error> {
    let hash = body_hash(body);
    db::moderation::insert(pool, board_id, &hash, reason.code()).await
}
