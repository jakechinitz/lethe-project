//! The frozen v1 constitution text and its build-time SHA-256.
//!
//! Bumping the moderation floor means a new file (e.g. `v1.1.txt`,
//! `v2.txt`) with a new hash. Existing peers can detect the drift via
//! `/api/federation/info` and decide whether to keep peering.

/// Identifier reported on the wire and in `/api/federation/info`.
pub const VERSION: &str = "v1";

/// Frozen constitution text, embedded at compile time.
pub const TEXT: &str = include_str!("../../constitution/v1.txt");

/// SHA-256 hex of [`TEXT`], computed by `build.rs` at compile time.
pub const HASH: &str = env!("LETHE_CONSTITUTION_V1_HASH");
