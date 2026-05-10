//! Admin-token table CRUD. Tokens are SHA-256-hashed before insert
//! and lookup; the plaintext leaves the server only at mint time
//! (returned to the operator once, never stored).

use sha2::{Digest, Sha256};
use sqlx::PgPool;
use time::Date;

#[derive(Debug, Clone)]
pub struct TokenRow {
    pub label: String,
    pub created_at: Date,
    pub revoked_at: Option<Date>,
}

pub fn hash(token: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(token.as_bytes());
    h.finalize().into()
}

/// Inserts a hashed token. Returns Err on duplicate label so callers
/// don't accidentally shadow an existing one.
pub async fn insert(db: &PgPool, label: &str, token: &str) -> Result<(), sqlx::Error> {
    let h = hash(token);
    sqlx::query(
        "INSERT INTO admin_tokens (token_hash, label) VALUES ($1, $2)",
    )
    .bind(&h[..])
    .bind(label)
    .execute(db)
    .await?;
    Ok(())
}

/// True iff the token hashes to a non-revoked row.
pub async fn verify(db: &PgPool, token: &str) -> Result<Option<String>, sqlx::Error> {
    let h = hash(token);
    let row: Option<(String,)> = sqlx::query_as(
        "SELECT label FROM admin_tokens
         WHERE token_hash = $1 AND revoked_at IS NULL",
    )
    .bind(&h[..])
    .fetch_optional(db)
    .await?;
    Ok(row.map(|r| r.0))
}

/// Marks all tokens with the given label as revoked. Returns the
/// number of rows updated.
pub async fn revoke(db: &PgPool, label: &str) -> Result<u64, sqlx::Error> {
    let res = sqlx::query(
        "UPDATE admin_tokens SET revoked_at = CURRENT_DATE
         WHERE label = $1 AND revoked_at IS NULL",
    )
    .bind(label)
    .execute(db)
    .await?;
    Ok(res.rows_affected())
}

pub async fn list(db: &PgPool) -> Result<Vec<TokenRow>, sqlx::Error> {
    let rows: Vec<(String, Date, Option<Date>)> = sqlx::query_as(
        "SELECT label, created_at, revoked_at FROM admin_tokens
         ORDER BY created_at ASC, label ASC",
    )
    .fetch_all(db)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(label, created_at, revoked_at)| TokenRow {
            label,
            created_at,
            revoked_at,
        })
        .collect())
}
