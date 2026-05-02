//! AI-classifier hook.
//!
//! The trait here is the only contract a future model needs to satisfy.
//! Plug a real classifier in by replacing `NoopClassifier` in
//! `state::AppState` with your own `impl Classifier`. The default
//! implementation deliberately returns `None` for every input — i.e.,
//! no AI moderation runs until someone explicitly enables it.
//!
//! Why a stub by default:
//!   - The product spec says "for maximum trust, avoid third-party AI
//!     APIs entirely." Wiring an external API silently would break that.
//!   - Operators differ on what categories they want auto-actioned.
//!     Ship inert; let them opt in.

use super::Reason;

pub trait Classifier: Send + Sync {
    /// Returns `Some(reason)` if the body should be rejected, `None` to
    /// allow. Implementations MUST be deterministic given the same input
    /// or document otherwise — flaky moderation is hostile to users.
    fn classify(&self, body: &str) -> Option<Reason>;
}

/// The default. Allows everything. Suitable for production until you
/// have a model you want to run.
pub struct NoopClassifier;

impl Classifier for NoopClassifier {
    fn classify(&self, _body: &str) -> Option<Reason> {
        None
    }
}
