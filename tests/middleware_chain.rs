use std::sync::Arc;

use async_trait::async_trait;
use axum::{
    Json, Router,
    extract::Extension,
    http::{Request, StatusCode},
    response::IntoResponse,
    routing::get,
};
use philharmonic_api::{
    ErrorCode, ErrorEnvelope, RequestContext, RequestScope, RequestScopeResolver, ResolverError,
};
use philharmonic_policy::Tenant;
use philharmonic_types::EntityId;
use tower::ServiceExt;

mod common;

struct PathResolver;

#[async_trait]
impl RequestScopeResolver for PathResolver {
    async fn resolve(&self, parts: &http::request::Parts) -> Result<RequestScope, ResolverError> {
        match parts.uri.path() {
            "/v1/_meta/operator" => Ok(RequestScope::Operator),
            "/v1/scope-test/tenant" => Ok(RequestScope::Tenant(tenant_id())),
            "/v1/scope-test/operator" => Ok(RequestScope::Operator),
            "/v1/scope-test/unscoped" => Err(ResolverError::Unscoped),
            _ => Ok(RequestScope::Operator),
        }
    }
}

fn tenant_id() -> EntityId<Tenant> {
    common::new_typed_id::<Tenant>()
}

fn router() -> Router {
    let extra_routes = Router::new()
        .route("/v1/_meta/operator", get(scope_kind))
        .route("/v1/scope-test/tenant", get(scope_kind))
        .route("/v1/scope-test/operator", get(scope_kind))
        .route("/v1/scope-test/unscoped", get(scope_kind));

    common::builder(
        Arc::new(PathResolver),
        common::MockStore::new(),
        common::test_api_verifying_key_registry(),
    )
    .extra_routes(extra_routes)
    .build()
    .unwrap()
    .into_router()
}

async fn scope_kind(Extension(context): Extension<RequestContext>) -> impl IntoResponse {
    let scope = match context.scope {
        RequestScope::Tenant(_) => "tenant",
        RequestScope::Operator => "operator",
    };

    Json(serde_json::json!({
        "scope": scope,
        "auth_is_none": context.auth.is_none(),
    }))
}

#[tokio::test]
async fn meta_paths_always_resolve_to_operator() {
    let response = router()
        .oneshot(
            Request::builder()
                .uri("/v1/_meta/operator")
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

    assert_eq!(json["scope"], "operator");
    assert_eq!(json["auth_is_none"], true);
}

#[tokio::test]
async fn scope_resolver_runs_on_non_meta_paths() {
    let response = router()
        .oneshot(
            Request::builder()
                .uri("/v1/scope-test/tenant")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "scope resolved successfully, then auth rejected (no bearer token)"
    );
}

#[tokio::test]
async fn middleware_returns_structured_unscoped_error() {
    let response = router()
        .oneshot(
            Request::builder()
                .uri("/v1/scope-test/unscoped")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let envelope: ErrorEnvelope = serde_json::from_slice(&body).unwrap();

    assert_eq!(envelope.error.code, ErrorCode::UnscopedRequest);
    assert_ne!(envelope.error.correlation_id, uuid::Uuid::nil());
}
