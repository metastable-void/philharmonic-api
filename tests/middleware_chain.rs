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
    ErrorCode, ErrorEnvelope, PhilharmonicApiBuilder, RequestContext, RequestScope,
    RequestScopeResolver, ResolverError,
};
use philharmonic_policy::Tenant;
use philharmonic_types::{EntityId, Identity, Uuid};
use tower::ServiceExt;

struct PathResolver;

#[async_trait]
impl RequestScopeResolver for PathResolver {
    async fn resolve(&self, parts: &http::request::Parts) -> Result<RequestScope, ResolverError> {
        match parts.uri.path() {
            "/tenant" => Ok(RequestScope::Tenant(tenant_id())),
            "/operator" => Ok(RequestScope::Operator),
            "/unscoped" => Err(ResolverError::Unscoped),
            _ => Ok(RequestScope::Operator),
        }
    }
}

fn tenant_id() -> EntityId<Tenant> {
    Identity {
        internal: Uuid::now_v7(),
        public: Uuid::new_v4(),
    }
    .typed()
    .unwrap()
}

fn router() -> Router {
    let extra_routes = Router::new()
        .route("/tenant", get(scope_kind))
        .route("/operator", get(scope_kind))
        .route("/unscoped", get(scope_kind));

    PhilharmonicApiBuilder::new()
        .request_scope_resolver(Arc::new(PathResolver))
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
async fn middleware_attaches_tenant_scope() {
    let response = router()
        .oneshot(
            Request::builder()
                .uri("/tenant")
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

    assert_eq!(json["scope"], "tenant");
    assert_eq!(json["auth_is_none"], true);
}

#[tokio::test]
async fn middleware_attaches_operator_scope() {
    let response = router()
        .oneshot(
            Request::builder()
                .uri("/operator")
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
async fn middleware_returns_structured_unscoped_error() {
    let response = router()
        .oneshot(
            Request::builder()
                .uri("/unscoped")
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
