use axum::{http::StatusCode, response::{IntoResponse, Response}, Json};
use serde_json::json;

#[derive(Debug)]
pub struct ApiError(pub StatusCode, pub &'static str);

impl ApiError {
    pub fn bad(message: &'static str) -> Self { Self(StatusCode::BAD_REQUEST, message) }
    pub fn unauthorized() -> Self { Self(StatusCode::UNAUTHORIZED, "unauthorized") }
    pub fn forbidden() -> Self { Self(StatusCode::FORBIDDEN, "access_denied") }
    pub fn not_found() -> Self { Self(StatusCode::NOT_FOUND, "not_found") }
    pub fn internal() -> Self { Self(StatusCode::INTERNAL_SERVER_ERROR, "internal_error") }
}
impl IntoResponse for ApiError {
    fn into_response(self) -> Response { (self.0, Json(json!({"error":self.1}))).into_response() }
}
impl From<sqlx::Error> for ApiError {
    fn from(error: sqlx::Error) -> Self { tracing::error!(?error, "database failure"); Self::internal() }
}
impl From<reqwest::Error> for ApiError {
    fn from(error: reqwest::Error) -> Self { tracing::warn!(?error, "upstream failure"); Self(StatusCode::BAD_GATEWAY, "upstream_error") }
}
