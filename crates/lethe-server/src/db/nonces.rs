//! Replay-nonce dedupe for authenticated room requests.
//!
//! `kind` is a short string discriminator: `"list"`, `"remove"`. Pairing
//! it with `sig_pubkey + ts` means a captured signature for one
//! endpoint cannot be replayed against another (and vice-versa).

use sqlx::PgPool;

/// Inserts a fresh nonce. Returns `true` on success, `false` if the
/// (kind, sig_pubkey, ts) tuple was already seen — i.e. this is a replay.
pub async fn record(
    db: &PgPool,
    kind: &str,
    sig_pubkey: &[u8],
    ts: i64,
) -> Result<bool, sqlx::Error> {
    let res = sqlx::query(
        "INSERT INTO request_nonces (kind, sig_pubkey, ts)
         VALUES ($1, $2, $3)
         ON CONFLICT DO NOTHING",
    )
    .bind(kind)
    .bind(sig_pubkey)
    .bind(ts)
    .execute(db)
    .await?;
    Ok(res.rows_affected() == 1)
}

/// Deletes nonces older than the freshness window. Called by the
/// retention worker.
pub async fn prune_older_than(
    db: &PgPool,
    age: time::Duration,
) -> Result<u64, sqlx::Error> {
    let secs = age.whole_seconds();
    let res = sqlx::query(
        "DELETE FROM request_nonces
         WHERE seen_at < now() - make_interval(secs => $1)",
    )
    .bind(secs as f64)
    .execute(db)
    .await?;
    Ok(res.rows_affected())
}
