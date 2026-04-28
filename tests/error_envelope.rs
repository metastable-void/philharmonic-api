use std::sync::Arc;

use async_trait::async_trait;
use axum::http::{Request, StatusCode};
use philharmonic_api::{
    ErrorCode, ErrorEnvelope, PhilharmonicApiBuilder, RequestScope, RequestScopeResolver,
    ResolverError,
};
use tower::ServiceExt;

struct OperatorResolver;

#[async_trait]
impl RequestScopeResolver for OperatorResolver {
    async fn resolve(&self, _parts: &http::request::Parts) -> Result<RequestScope, ResolverError> {
        Ok(RequestScope::Operator)
    }
}

fn router() -> axum::Router {
    PhilharmonicApiBuilder::new()
        .request_scope_resolver(Arc::new(OperatorResolver))
        .build()
        .unwrap()
        .into_router()
}

#[tokio::test]
async fn version_endpoint_returns_json() {
    let response = router()
        .oneshot(
            Request::builder()
                .uri("/v1/_meta/version")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["version"], env!("CARGO_PKG_VERSION"));
}

#[tokio::test]
async fn bogus_path_returns_structured_not_found() {
    let response = router()
        .oneshot(
            Request::builder()
                .uri("/bogus")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let envelope: ErrorEnvelope = serde_json::from_slice(&body).unwrap();

    assert_eq!(envelope.error.code, ErrorCode::NotFound);
    assert_ne!(envelope.error.correlation_id, uuid::Uuid::nil());
}
