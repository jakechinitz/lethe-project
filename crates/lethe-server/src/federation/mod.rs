//! Federation of the public forum.
//!
//! Architecture, in one paragraph: each Lethe server has a persistent
//! Ed25519 server identity (see [`identity`]). Each server pulls signed
//! events from a manually-curated list of peers (`federation_peers`),
//! re-runs the local moderation pipeline at ingest, and inserts what
//! passes. Public posts and threads carry `origin_server_id` so any
//! federated copy is traceable to the server that authored it. Private
//! rooms are not federated and never appear in any event stream — see
//! the explicit assertion in [`route::events`] that `rooms`,
//! `room_members`, and `room_messages` are never queried here.
//!
//! Wire format and signing live in [`events`]. The pull worker lives in
//! [`pull`]. The HTTP endpoints (`/api/federation/events`,
//! `/api/federation/info`) and the operator-facing peer management
//! routes live in [`route`].
//!
//! Design intent: this is the **MVP** described in the federation plan.
//! Bilateral pull-based peering with origin tracking and post-facto
//! removal propagation. Quorum-signed network registry, multi-sig
//! governance, and a signed constitution document are intentionally
//! out of scope. The wire format already carries `protocol_version`
//! and `constitution_version` so those additions are forward-compatible.

pub mod constitution;
pub mod events;
pub mod identity;
pub mod info;
pub mod pull;
pub mod route;

pub use identity::Identity;
