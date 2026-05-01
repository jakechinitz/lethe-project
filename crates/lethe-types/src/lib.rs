//! Shared serde DTOs for the Lethe HTTP API.
//!
//! These types are the only contract between the server (`lethe-server`) and
//! integration tests / the browser client. Database row structs live in
//! `lethe-server::db` and never leave that module — convert at the boundary.
//!
//! All binary fields are urlsafe-base64 (no padding) on the wire.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

pub mod posts;
pub mod rooms;

/// urlsafe-base64 (no padding) encoded byte string.
pub type B64 = String;

/// ISO-8601 timestamp coarsened to a 60-second bucket on the server.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct CoarseTime(#[serde(with = "time::serde::iso8601")] pub OffsetDateTime);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Board {
    pub id: String,
    pub title: String,
    pub pow_bits: u8,
}
