//! Business logic layer. Sits between routes (HTTP) and db (sqlx).
//!
//! Functions here orchestrate validation, crypto verification, and DB
//! writes. They never see `axum`, `Request`, or `Response`.

pub mod posts;
pub mod reports;
pub mod rooms;
pub mod trust;
