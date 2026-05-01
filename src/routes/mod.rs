//! Route table for the public API.
//!
//! Sub-phase H exposes meta smoke-test endpoints, workflow management,
//! endpoint-config management, identity-management CRUD, and token minting.
//! It also adds tenant administration, audit-log access, and deployment
//! operator tenant management.

pub mod audit;
pub mod authorities;
pub mod endpoints;
mod identity;
pub mod memberships;
pub mod meta;
pub mod mint;
pub mod operator;
pub mod principals;
pub mod roles;
pub mod tenant;
pub mod whoami;
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

/// Build the sub-phase H route table.
pub fn router() -> Router {
    Router::new()
        .route("/v1/_meta/version", get(meta::version))
        .route("/v1/_meta/health", get(meta::health))
        .route("/v1/whoami", get(whoami::whoami))
        .merge(workflows::router())
        .merge(endpoints::router())
        .merge(principals::router())
        .merge(roles::router())
        .merge(memberships::router())
        .merge(authorities::router())
        .merge(mint::router())
        .merge(tenant::router())
        .merge(audit::router())
        .merge(operator::router())
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
