//! Route table for the public API.
//!
//! Sub-phase E exposes meta smoke-test endpoints, workflow management, and
//! endpoint-config management. Identity, token-minting, audit, rate-limit,
//! tenant, and operator routes land in later Phase 8 sub-phases.

pub mod endpoints;
pub mod meta;
pub mod workflows;

use axum::{
    Router,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
};

use crate::{
    RequestContext,
    context::CorrelationContext,
    error::{ErrorCode, envelope_response},
};

/// Build the sub-phase E route table.
pub fn router() -> Router {
    Router::new()
        .route("/v1/_meta/version", get(meta::version))
        .route("/v1/_meta/health", get(meta::health))
        .merge(workflows::router())
        .merge(endpoints::router())
        .fallback(not_found)
}

async fn not_found(request: axum::extract::Request) -> Response {
    let correlation_id = request
        .extensions()
        .get::<RequestContext>()
        .map(|context| context.correlation_id)
        .or_else(|| {
            request
                .extensions()
                .get::<CorrelationContext>()
                .map(|context| context.correlation_id)
        })
        .unwrap_or_else(uuid::Uuid::new_v4);

    envelope_response(
        StatusCode::NOT_FOUND,
        ErrorCode::NotFound,
        "not found",
        correlation_id,
    )
    .into_response()
}
