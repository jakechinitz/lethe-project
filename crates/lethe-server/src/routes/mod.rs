//! HTTP routing layer. Handlers are intentionally thin: parse → call into
//! `logic::*` → shape the response.

pub mod boards;
pub mod feed;
pub mod pages;
pub mod posts;
pub mod rooms;
pub mod threads;
