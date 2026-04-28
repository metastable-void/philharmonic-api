//! Structured API error envelope.
//!
//! Sub-phase A pins the wire shape used by all later handlers. Later
//! sub-phases extend [`ErrorCode`] with authentication, authorization,
//! rate-limit, validation, and endpoint-specific errors.

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};

use crate::ResolverError;

/// Top-level JSON error envelope.
#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorEnvelope {
    /// Error body.
    pub error: ErrorBody,
}

/// Structured error body carried inside [`ErrorEnvelope`].
#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorBody {
    /// Machine-readable error code.
    pub code: ErrorCode,
    /// Human-readable message.
    pub message: String,
    /// Optional code-specific details.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
    /// Request correlation ID.
    pub correlation_id: uuid::Uuid,
}

/// Machine-readable error code.
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// The request could not be resolved to tenant or operator scope.
    UnscopedRequest,
    /// Catch-all for internal failures.
    InternalError,
    /// No route matched the request.
    NotFound,
    /// The path matched but the HTTP method is unsupported.
    MethodNotAllowed,
    /// Stub endpoint placeholder.
    NotImplemented,
}

/// API error variants used by sub-phase A middleware and handlers.
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    /// Request scope resolution failed.
    #[error("unscoped request")]
    Unscoped(#[from] ResolverError),
    /// Internal API failure.
    #[error("internal error: {0}")]
    Internal(String),
    /// Endpoint exists as a stub but has no implementation yet.
    #[error("not implemented")]
    NotImplemented,
}

impl ApiError {
    /// Return the machine-readable error code.
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Unscoped(ResolverError::Unscoped) => ErrorCode::UnscopedRequest,
            Self::Unscoped(ResolverError::Internal(_)) | Self::Internal(_) => {
                ErrorCode::InternalError
            }
            Self::NotImplemented => ErrorCode::NotImplemented,
        }
    }

    /// Return the HTTP status code.
    pub fn http_status(&self) -> StatusCode {
        match self {
            Self::Unscoped(ResolverError::Unscoped) => StatusCode::BAD_REQUEST,
            Self::Unscoped(ResolverError::Internal(_)) | Self::Internal(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
            Self::NotImplemented => StatusCode::NOT_IMPLEMENTED,
        }
    }

    /// Build an error response using the supplied correlation ID.
    pub fn into_response_with_correlation_id(self, correlation_id: uuid::Uuid) -> Response {
        let status = self.http_status();
        let envelope = ErrorEnvelope {
            error: ErrorBody {
                code: self.code(),
                message: self.to_string(),
                details: None,
                correlation_id,
            },
        };

        (status, Json(envelope)).into_response()
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let correlation_id = uuid::Uuid::new_v4();
        tracing::warn!(
            %correlation_id,
            "api error converted without request correlation context"
        );
        self.into_response_with_correlation_id(correlation_id)
    }
}

pub(crate) fn envelope_response(
    status: StatusCode,
    code: ErrorCode,
    message: impl Into<String>,
    correlation_id: uuid::Uuid,
) -> Response {
    let envelope = ErrorEnvelope {
        error: ErrorBody {
            code,
            message: message.into(),
            details: None,
            correlation_id,
        },
    };

    (status, Json(envelope)).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{Body, to_bytes};

    #[test]
    fn api_error_variants_map_to_codes_and_statuses() {
        let cases = [
            (
                ApiError::Unscoped(ResolverError::Unscoped),
                ErrorCode::UnscopedRequest,
                StatusCode::BAD_REQUEST,
            ),
            (
                ApiError::Unscoped(ResolverError::Internal("store offline".to_string())),
                ErrorCode::InternalError,
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
            (
                ApiError::Internal("failed".to_string()),
                ErrorCode::InternalError,
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
            (
                ApiError::NotImplemented,
                ErrorCode::NotImplemented,
                StatusCode::NOT_IMPLEMENTED,
            ),
        ];

        for (error, code, status) in cases {
            assert_eq!(error.code(), code);
            assert_eq!(error.http_status(), status);
        }
    }

    #[test]
    fn error_envelope_json_round_trips() {
        let envelope = ErrorEnvelope {
            error: ErrorBody {
                code: ErrorCode::NotFound,
                message: "missing".to_string(),
                details: Some(serde_json::json!({"path": "/missing"})),
                correlation_id: uuid::Uuid::new_v4(),
            },
        };

        let json = serde_json::to_string(&envelope).unwrap();
        let decoded: ErrorEnvelope = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded.error.code, ErrorCode::NotFound);
        assert_eq!(decoded.error.message, "missing");
        assert!(decoded.error.details.is_some());
    }

    #[tokio::test]
    async fn into_response_generates_json_body_and_status() {
        let response = ApiError::NotImplemented.into_response();

        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let envelope: ErrorEnvelope = serde_json::from_slice(&body).unwrap();

        assert_eq!(envelope.error.code, ErrorCode::NotImplemented);
        assert_eq!(envelope.error.message, "not implemented");
        assert_ne!(envelope.error.correlation_id, uuid::Uuid::nil());
    }

    #[tokio::test]
    async fn explicit_correlation_id_is_preserved() {
        let correlation_id = uuid::Uuid::new_v4();
        let response = ApiError::Internal("failed".to_string())
            .into_response_with_correlation_id(correlation_id);

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let envelope: ErrorEnvelope = serde_json::from_slice(&body).unwrap();

        assert_eq!(envelope.error.correlation_id, correlation_id);
    }

    #[test]
    fn envelope_response_uses_requested_code() {
        let correlation_id = uuid::Uuid::new_v4();
        let response = envelope_response(
            StatusCode::NOT_FOUND,
            ErrorCode::NotFound,
            "not found",
            correlation_id,
        );

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let _body: Body = response.into_body();
    }
}
