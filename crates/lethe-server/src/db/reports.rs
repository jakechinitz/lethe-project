//! User-submitted reports against public posts. Write-only at MVP:
//! operators query directly to triage. The schema enforces no PII —
//! reports are anonymous by construction.

use crate::ids;
use sqlx::PgPool;

pub async fn insert(
    db: &PgPool,
    post_id: &[u8],
    reason_text: Option<&str>,
) -> Result<[u8; 16], sqlx::Error> {
    let id = ids::new_id();
    sqlx::query(
        "INSERT INTO reports (id, post_id, reason_text)
         VALUES ($1, $2, $3)",
    )
    .bind(&id[..])
    .bind(post_id)
    .bind(reason_text)
    .execute(db)
    .await?;
    Ok(id)
}
