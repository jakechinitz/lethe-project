//! Server-visible trust facts.
//!
//! In the slice, the entire trust card is computed client-side from the
//! members list (`/api/rooms/:id/members`) plus the room's provenance
//! (`/api/rooms/:id/provenance`). This module is the intended home for
//! future server-side helpers — invite-chain walking with cycle detection,
//! attestation aggregation, group fingerprinting — that the client cannot
//! compute alone, e.g. when ceremony attestations land in a future
//! migration.
//!
//! It deliberately exports nothing today.
