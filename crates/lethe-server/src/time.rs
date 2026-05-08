//! Today-as-UTC-Date for stamping new rows.
//!
//! User-facing `created_at` / `joined_at` / `decided_at` columns are all
//! `DATE`. A row reveals only the day an action happened, not the minute
//! or second. Combined with random (non-time-encoded) ids in
//! [`crate::ids`], a database snapshot can't reconstruct fine-grained
//! activity timing.
//!
//! Internal replay-protection timestamps (`request_nonces.seen_at`)
//! deliberately keep sub-day precision and are checked elsewhere.

use time::{Date, OffsetDateTime};

/// Today's date in UTC.
pub fn today_utc() -> Date {
    OffsetDateTime::now_utc().date()
}
