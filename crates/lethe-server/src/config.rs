//! Environment-driven config. Read once at startup, never mutated.

use std::net::SocketAddr;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct Config {
    pub database_url: String,
    pub bind_addr: SocketAddr,
    pub default_pow_bits: u8,
    /// When true, spawn the federation pull worker at startup. When
    /// false, the federation routes are still mounted (so peers can
    /// still pull *from* this server) but no outbound pulls happen.
    pub federation_enabled: bool,
    pub pull_interval: Duration,
    /// Bearer token required for `POST /api/federation/peers*`.
    /// `None` disables admin endpoints (they respond 403).
    pub admin_token: Option<String>,
    /// Free-form note rendered in `/api/federation/info` describing
    /// the local moderation posture, e.g. "baseline" or "stricter:
    /// blocks crypto-pump links". Defaults to "baseline".
    pub moderation_summary: Option<String>,
    /// Human label for `/api/federation/info`, e.g. "Columbia Lethe Node".
    pub operator_label: Option<String>,
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        let database_url = std::env::var("DATABASE_URL")
            .map_err(|_| "DATABASE_URL is required".to_string())?;
        let bind_addr: SocketAddr = std::env::var("BIND_ADDR")
            .unwrap_or_else(|_| "127.0.0.1:8080".to_string())
            .parse()
            .map_err(|e| format!("BIND_ADDR: {e}"))?;
        let default_pow_bits: u8 = std::env::var("DEFAULT_BOARD_POW_BITS")
            .unwrap_or_else(|_| "18".to_string())
            .parse()
            .map_err(|e| format!("DEFAULT_BOARD_POW_BITS: {e}"))?;
        let federation_enabled: bool = std::env::var("LETHE_FEDERATION_ENABLED")
            .map(|s| matches!(s.to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
            .unwrap_or(false);
        let pull_interval = Duration::from_secs(
            std::env::var("LETHE_PULL_INTERVAL_SECS")
                .unwrap_or_else(|_| "60".to_string())
                .parse()
                .map_err(|e| format!("LETHE_PULL_INTERVAL_SECS: {e}"))?,
        );
        let admin_token = std::env::var("LETHE_ADMIN_TOKEN").ok().filter(|s| !s.is_empty());
        let moderation_summary = std::env::var("LETHE_MODERATION_SUMMARY").ok();
        let operator_label = std::env::var("LETHE_OPERATOR_LABEL").ok();
        Ok(Self {
            database_url,
            bind_addr,
            default_pow_bits,
            federation_enabled,
            pull_interval,
            admin_token,
            moderation_summary,
            operator_label,
        })
    }
}
