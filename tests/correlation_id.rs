use std::sync::Arc;

use async_trait::async_trait;
use axum::http::{Request, StatusCode};
use philharmonic_api::{RequestScope, RequestScopeResolver, ResolverError};
use tower::ServiceExt;

mod common;

struct OperatorResolver;

#[async_trait]
impl RequestScopeResolver for OperatorResolver {
    async fn resolve(&self, _parts: &http::request::Parts) -> Result<RequestScope, ResolverError> {
        Ok(RequestScope::Operator)
    }
}

fn router() -> axum::Router {
    common::builder(
        Arc::new(OperatorResolver),
        common::MockStore::new(),
        common::test_api_verifying_key_registry(),
    )
    .build()
    .unwrap()
    .into_router()
}

#[tokio::test]
async fn caller_supplied_correlation_id_is_echoed() {
    let correlation_id = uuid::Uuid::new_v4();
    let response = router()
        .oneshot(
            Request::builder()
                .uri("/v1/_meta/health")
                .header("X-Correlation-Id", correlation_id.to_string())
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let echoed = response
        .headers()
        .get("X-Correlation-Id")
        .and_then(|value| value.to_str().ok())
        .unwrap();

    assert_eq!(echoed, correlation_id.to_string());
}

#[tokio::test]
async fn missing_correlation_id_gets_fresh_uuid() {
    let response = router()
        .oneshot(
            Request::builder()
                .uri("/v1/_meta/health")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let echoed = response
        .headers()
        .get("X-Correlation-Id")
        .and_then(|value| value.to_str().ok())
        .unwrap();
    let parsed = uuid::Uuid::parse_str(echoed).unwrap();

    assert_ne!(parsed, uuid::Uuid::nil());
}
