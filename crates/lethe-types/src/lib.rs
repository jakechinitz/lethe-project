//! Shared serde DTOs for the Lethe HTTP API.
//!
//! These types are the only contract between the server (`lethe-server`) and
//! integration tests / the browser client. Database row structs live in
//! `lethe-server::db` and never leave that module — convert at the boundary.
//!
//! All binary fields are urlsafe-base64 (no padding) on the wire.
//!
//! Timestamps cross the wire as ISO-8601 dates ("YYYY-MM-DD") at day
//! granularity. The server has no minute/second resolution to share
//! because the underlying columns are `DATE` (see migration 0009).

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use time::Date;

pub mod feed;
pub mod posts;
pub mod rooms;

/// urlsafe-base64 (no padding) encoded byte string.
pub type B64 = String;

/// ISO-8601 date ("YYYY-MM-DD"). The server stores no finer-grained
/// timestamp for user-facing rows, so this is the entire wire form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoarseDate(#[serde(with = "iso8601_date")] pub Date);

mod iso8601_date {
    use serde::{Deserialize, Deserializer, Serializer};
    use time::format_description::FormatItem;
    use time::macros::format_description;
    use time::Date;

    const FMT: &[FormatItem<'_>] = format_description!("[year]-[month]-[day]");

    pub fn serialize<S: Serializer>(d: &Date, ser: S) -> Result<S::Ok, S::Error> {
        let s = d.format(FMT).map_err(serde::ser::Error::custom)?;
        ser.serialize_str(&s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<Date, D::Error> {
        let s = String::deserialize(de)?;
        Date::parse(&s, FMT).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Board {
    pub id: String,
    pub title: String,
    pub pow_bits: u8,
}
