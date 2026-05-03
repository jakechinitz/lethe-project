//! Deterministic pre-insert rules. Cheap, dependency-free, no model.
//!
//! Each rule is narrow enough that an auto-action ("delete and tell the
//! user why") is defensible per the JSM grounding principle the site
//! ships under: only the obvious cases short-circuit a submission. The
//! gray-area rule categories (substances, gambling, harassment,
//! impersonation, doxxing) live in `classifier` instead, behind a
//! pluggable model that's stubbed out by default.

use super::Reason;
use sqlx::PgPool;

/// Bodies shorter than this (after trim) are rejected as junk.
const MIN_BODY_CHARS: usize = 3;

/// A submission with this many or more URL-looking tokens AND fewer than
/// this many non-link characters is considered spam. The thresholds are
/// deliberately loose; a chatty post about a single linked article still
/// passes.
const LINK_DENSITY_LINK_COUNT: usize = 4;
const LINK_DENSITY_TEXT_BUDGET: usize = 80;

/// Hosts whose substrings always reject. Empty by default; operators
/// can extend this list. Compared as lowercase substring of the URL,
/// not full host equality, so `evil.example.com` matches if
/// `example.com` is in the list.
const MALWARE_HOST_BLOCKLIST: &[&str] = &[];

pub async fn evaluate(
    db: &PgPool,
    board_id: &str,
    body: &str,
) -> Result<Option<Reason>, sqlx::Error> {
    let trimmed = body.trim();
    if trimmed.chars().count() < MIN_BODY_CHARS {
        return Ok(Some(Reason::SpamTooShort));
    }

    if has_blocklisted_host(body) {
        return Ok(Some(Reason::MalwareLink));
    }

    if is_link_density_spam(body) {
        return Ok(Some(Reason::SpamLinkDensity));
    }

    if is_severe_harassment(body) {
        return Ok(Some(Reason::HarassmentOrHate));
    }

    if is_recent_duplicate(db, board_id, body).await? {
        return Ok(Some(Reason::SpamDuplicate));
    }

    Ok(None)
}

/// Hate-speech / severe-harassment check via `rustrict`. Targets exactly
/// the categories the site's rules already prohibit (harassment, hate
/// speech, slurs) and deliberately leaves profanity-per-se alone — the
/// JSM grounding principle on the welcome page says we don't censor
/// strong language unless it crosses into harm.
///
/// The check fires only when rustrict reports BOTH:
///   - severity = SEVERE, AND
///   - category includes OFFENSIVE (slurs / hate speech) or MEAN
///     (targeted harassment).
///
/// "fuck this is great" stays through (PROFANE, not OFFENSIVE/MEAN).
/// A racial slur, severe insult-attack at a person, or obvious bypass
/// attempt ("n i g r", "f@gg0t") is rejected.
fn is_severe_harassment(body: &str) -> bool {
    use rustrict::{Censor, Type};
    let typ: Type = Censor::from_str(body).analyze();
    typ.is(Type::SEVERE) && (typ.is(Type::OFFENSIVE) || typ.is(Type::MEAN))
}

fn has_blocklisted_host(body: &str) -> bool {
    if MALWARE_HOST_BLOCKLIST.is_empty() {
        return false;
    }
    let lower = body.to_ascii_lowercase();
    MALWARE_HOST_BLOCKLIST.iter().any(|h| lower.contains(h))
}

fn is_link_density_spam(body: &str) -> bool {
    let links: usize = body
        .split_ascii_whitespace()
        .filter(|tok| tok.starts_with("http://") || tok.starts_with("https://"))
        .count();
    if links < LINK_DENSITY_LINK_COUNT {
        return false;
    }
    let non_link_chars: usize = body
        .split_ascii_whitespace()
        .filter(|tok| !(tok.starts_with("http://") || tok.starts_with("https://")))
        .map(|tok| tok.chars().count())
        .sum();
    non_link_chars < LINK_DENSITY_TEXT_BUDGET
}

async fn is_recent_duplicate(
    db: &PgPool,
    board_id: &str,
    body: &str,
) -> Result<bool, sqlx::Error> {
    // Same body text in the same board within the last 24 hours.
    // The body column is plain text and small enough; a body_hash
    // index would be a nice future optimization but isn't needed yet.
    let row: Option<(i32,)> = sqlx::query_as(
        "SELECT 1 FROM posts
         JOIN threads ON threads.id = posts.thread_id
         WHERE threads.board_id = $1
           AND posts.body = $2
           AND posts.created_at > now() - interval '24 hours'
         LIMIT 1",
    )
    .bind(board_id)
    .bind(body)
    .fetch_optional(db)
    .await?;
    Ok(row.is_some())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn link_density_triggers_at_threshold() {
        let spam = "buy now https://a https://b https://c https://d";
        assert!(is_link_density_spam(spam));
    }

    #[test]
    fn link_density_lets_a_chatty_post_through() {
        let ok =
            "I read a great article about anonymous publishing yesterday and \
             wanted to share what I thought about it https://example.com/post";
        assert!(!is_link_density_spam(ok));
    }
}
