//! Request-scope resolution middleware.
//!
//! Sub-phase A invokes the deployment-supplied resolver and attaches the
//! resolved [`crate::RequestContext`]. Sub-phase C later enforces scope
//! compatibility with endpoint authorization requirements.

use std::{sync::Arc, time::Instant};

use axum::{extract::Request, middleware::Next, response::Response};

use crate::{ApiError, RequestContext, RequestScopeResolver, context::CorrelationContext};

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

    let (mut parts, body) = request.into_parts();
    let scope = match resolver.resolve(&parts).await {
        Ok(scope) => scope,
        Err(error) => {
            return ApiError::from(error)
                .into_response_with_correlation_id(correlation.correlation_id);
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
