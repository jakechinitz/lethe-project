//! Coarsens timestamps to 60-second buckets.
//!
//! Hygiene only — does not defeat traffic analysis. The intent is to avoid
//! gratuitously fine-grained timestamps in stored rows and API responses.

use time::OffsetDateTime;

const BUCKET_SECONDS: i64 = 60;

pub fn now_coarse() -> OffsetDateTime {
    coarsen(OffsetDateTime::now_utc())
}

pub fn coarsen(t: OffsetDateTime) -> OffsetDateTime {
    let unix = t.unix_timestamp();
    let bucketed = unix - unix.rem_euclid(BUCKET_SECONDS);
    OffsetDateTime::from_unix_timestamp(bucketed).expect("coarsened in range")
}

#[allow(dead_code)]
pub fn unix_bucket(t: OffsetDateTime) -> i64 {
    coarsen(t).unix_timestamp()
}
