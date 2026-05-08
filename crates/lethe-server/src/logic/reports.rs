//! Report submission. PoW-gated like a regular post; the proof binds
//! the post id, the (optional) reason text, and the reporter's nonce so
//! a captured nonce can't be replayed against a different post.

use crate::{
    db,
    error::{AppError, AppResult},
    ids, pow,
};
use lethe_types::posts::{ReportPostReq, ReportPostResp};
use sqlx::PgPool;

const MAX_REASON: usize = 500;

pub async fn report_post(
    db: &PgPool,
    pow_bits: u32,
    post_id_b64: &str,
    req: ReportPostReq,
) -> AppResult<ReportPostResp> {
    let post_id =
        ids::unb64(post_id_b64).map_err(|_| AppError::BadRequest("post_id b64"))?;
    if post_id.len() != 16 {
        return Err(AppError::BadRequest("post_id length"));
    }
    if !db::posts::exists(db, &post_id).await? {
        return Err(AppError::NotFound);
    }

    let reason = req
        .reason
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    if let Some(r) = reason {
        if r.len() > MAX_REASON {
            return Err(AppError::BadRequest("reason length"));
        }
    }

    let nonce = ids::unb64(&req.pow_nonce)
        .map_err(|_| AppError::BadRequest("pow_nonce b64"))?;
    let pow_body = reason.unwrap_or("");
    if !pow::verify(&post_id, pow_body, &nonce, pow_bits) {
        return Err(AppError::BadRequest("insufficient pow"));
    }

    let id = db::reports::insert(db, &post_id, reason).await?;
    Ok(ReportPostResp { report_id: ids::b64(&id) })
}
