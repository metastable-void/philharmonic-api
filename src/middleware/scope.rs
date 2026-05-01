//! Request-scope resolution middleware.
//!
//! Invokes the deployment-supplied resolver and attaches the resolved
//! [`crate::RequestContext`]. Paths under `/v1/_meta/` bypass the
//! resolver and receive [`crate::RequestScope::Operator`] directly
//! (meta endpoints are public and require no scope).

use std::{sync::Arc, time::Instant};

use axum::{extract::Request, middleware::Next, response::Response};

use crate::{
    ApiError, RequestContext, RequestScope, RequestScopeResolver, context::CorrelationContext,
};

const META_PREFIX: &str = "/v1/_meta/";

/// Resolve tenant/operator scope and attach [`RequestContext`].
pub async fn resolve_scope(
    axum::extract::State(resolver): axum::extract::State<Arc<dyn RequestScopeResolver>>,
    mut request: Request,
    next: Next,
) -> Response {
    let correlation = request
        .extensions()
        .get::<CorrelationContext>()
        .cloned()
        .unwrap_or_else(|| {
            let correlation_id = uuid::Uuid::new_v4();
            tracing::warn!(
                %correlation_id,
                "scope middleware ran without correlation context"
            );
            CorrelationContext {
                correlation_id,
                started_at: Instant::now(),
            }
        });

    let is_meta = request.uri().path().starts_with(META_PREFIX);

    let (mut parts, body) = request.into_parts();
    let scope = if is_meta {
        RequestScope::Operator
    } else {
        match resolver.resolve(&parts).await {
            Ok(scope) => scope,
            Err(error) => {
                return ApiError::from(error)
                    .into_response_with_correlation_id(correlation.correlation_id);
            }
        }
    };

    parts.extensions.insert(RequestContext {
        correlation_id: correlation.correlation_id,
        started_at: correlation.started_at,
        scope,
        auth: None,
    });

    request = Request::from_parts(parts, body);
    next.run(request).await
}
