//! Environment-driven config. Read once at startup, never mutated.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct Config {
    pub database_url: String,
    pub bind_addr: SocketAddr,
    pub default_pow_bits: u8,
    /// Path to the 32-byte Ed25519 seed file for this server's
    /// federation identity. Must be a regular file with mode 0600
    /// owned by the user the server runs as. The file is created on
    /// first boot if absent; if `instance_identity.server_privkey`
    /// holds a legacy seed it is migrated into this file once and
    /// then NULLed in the database. See [`federation::identity`].
    pub server_key_path: PathBuf,
    /// When true, spawn the federation pull worker at startup. When
    /// false, the federation routes are still mounted (so peers can
    /// still pull *from* this server) but no outbound pulls happen.
    pub federation_enabled: bool,
    pub pull_interval: Duration,
    /// First-time pulls from a freshly-added peer skip events older
    /// than this many days. Defaults to 30. Set to 0 to disable the
    /// horizon (full-history backfill — slow on long-lived peers).
    pub pull_horizon_days: i64,
    /// Bearer token required for `POST /api/federation/peers*`.
    /// `None` disables admin endpoints (they respond 403).
    pub admin_token: Option<String>,
    /// Free-form note rendered in `/api/federation/info` describing
    /// the local moderation posture, e.g. "baseline" or "stricter:
    /// blocks crypto-pump links". Defaults to "baseline".
    pub moderation_summary: Option<String>,
    /// Human label for `/api/federation/info`, e.g. "Columbia Lethe Node".
    pub operator_label: Option<String>,
    /// Path to a release-manifest JSON file (see RELEASE.md). When
    /// present, the server reports its SHA-256 in
    /// `/api/federation/info` so peers + users can confirm what build
    /// is running without trusting `code_commit` alone.
    pub release_manifest_path: Option<String>,
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
        let server_key_path: PathBuf = std::env::var("LETHE_SERVER_KEY_PATH")
            .unwrap_or_else(|_| "./server-key".to_string())
            .into();
        let federation_enabled: bool = std::env::var("LETHE_FEDERATION_ENABLED")
            .map(|s| matches!(s.to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
            .unwrap_or(false);
        let pull_interval = Duration::from_secs(
            std::env::var("LETHE_PULL_INTERVAL_SECS")
                .unwrap_or_else(|_| "60".to_string())
                .parse()
                .map_err(|e| format!("LETHE_PULL_INTERVAL_SECS: {e}"))?,
        );
        let pull_horizon_days: i64 = std::env::var("LETHE_PULL_HORIZON_DAYS")
            .unwrap_or_else(|_| "30".to_string())
            .parse()
            .map_err(|e| format!("LETHE_PULL_HORIZON_DAYS: {e}"))?;
        let admin_token = std::env::var("LETHE_ADMIN_TOKEN").ok().filter(|s| !s.is_empty());
        let moderation_summary = std::env::var("LETHE_MODERATION_SUMMARY").ok();
        let operator_label = std::env::var("LETHE_OPERATOR_LABEL").ok();
        let release_manifest_path = std::env::var("LETHE_RELEASE_MANIFEST").ok();
        Ok(Self {
            database_url,
            bind_addr,
            default_pow_bits,
            server_key_path,
            federation_enabled,
            pull_interval,
            pull_horizon_days,
            admin_token,
            moderation_summary,
            operator_label,
            release_manifest_path,
        })
    }
}
