//! Environment-driven config. Read once at startup, never mutated.

use std::net::SocketAddr;

#[derive(Debug, Clone)]
pub struct Config {
    pub database_url: String,
    pub bind_addr: SocketAddr,
    pub default_pow_bits: u8,
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
        Ok(Self {
            database_url,
            bind_addr,
            default_pow_bits,
        })
    }
}
