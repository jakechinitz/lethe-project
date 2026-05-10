//! `AppError` is the single error type returned by route handlers.
//! It implements `IntoResponse` so handlers can `?` freely.
//!
//! Client-visible message redaction policy:
//!   - `Db` and `Internal` log full detail server-side via tracing
//!     and return `"internal error"` to the client. The underlying
//!     sqlx::Error / static description never crosses the wire — DB
//!     constraint names, table names, query syntax errors, and
//!     conflicting key values can leak the schema and (for some
//!     PostgreSQL error variants) a column value.
//!   - `BadRequest`, `Forbidden`, `Conflict`, `NotFound`, and
//!     `Crypto` carry deliberately-curated short strings and are
//!     safe to expose; clients use them to fix their request.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("bad request: {0}")]
    BadRequest(&'static str),
    #[error("not found")]
    NotFound,
    #[error("forbidden: {0}")]
    Forbidden(&'static str),
    #[error("conflict: {0}")]
    Conflict(&'static str),
    #[error("internal: {0}")]
    Internal(&'static str),
    #[error(transparent)]
    Db(#[from] sqlx::Error),
    #[error(transparent)]
    Crypto(#[from] crate::crypto::CryptoError),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, code, message): (StatusCode, &'static str, String) = match &self {
            AppError::BadRequest(_) => (StatusCode::BAD_REQUEST, "bad_request", self.to_string()),
            AppError::NotFound => (StatusCode::NOT_FOUND, "not_found", self.to_string()),
            AppError::Forbidden(_) => (StatusCode::FORBIDDEN, "forbidden", self.to_string()),
            AppError::Conflict(_) => (StatusCode::CONFLICT, "conflict", self.to_string()),
            AppError::Crypto(_) => (StatusCode::BAD_REQUEST, "bad_signature", self.to_string()),
            AppError::Db(e) => {
                tracing::error!(error = ?e, "db error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal",
                    "internal error".to_string(),
                )
            }
            AppError::Internal(msg) => {
                tracing::error!(msg, "internal error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal",
                    "internal error".to_string(),
                )
            }
        };
        let body = Json(json!({ "error": code, "message": message }));
        (status, body).into_response()
    }
}

pub type AppResult<T> = Result<T, AppError>;

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;

    async fn body_string(resp: Response) -> String {
        // 64 KB is well above any error-response body we produce.
        let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn db_error_message_does_not_leak_inner_detail() {
        // Use a sqlx::Error variant whose Display would otherwise
        // betray a constraint name / query detail.
        let inner = sqlx::Error::Configuration(
            "constraint posts_origin_idx violated by row XYZ".into(),
        );
        let resp = AppError::Db(inner).into_response();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = body_string(resp).await;
        assert!(
            !body.contains("posts_origin_idx") && !body.contains("constraint"),
            "client-visible body must not include inner DB detail; got: {body}",
        );
        assert!(body.contains("internal"));
    }

    #[tokio::test]
    async fn internal_error_message_is_generic() {
        let resp = AppError::Internal("some sensitive context").into_response();
        let body = body_string(resp).await;
        assert!(
            !body.contains("some sensitive context"),
            "client-visible body must not include the static internal context: {body}",
        );
    }

    #[tokio::test]
    async fn bad_request_message_is_preserved() {
        // Curated short strings ARE safe to expose — they tell the
        // client what to fix.
        let resp = AppError::BadRequest("body length").into_response();
        let body = body_string(resp).await;
        assert!(body.contains("body length"), "got: {body}");
    }

    #[tokio::test]
    async fn crypto_error_message_is_preserved() {
        let resp = AppError::Crypto(crate::crypto::CryptoError::VerifyFailed).into_response();
        let body = body_string(resp).await;
        assert!(body.contains("does not verify"), "got: {body}");
    }
}
