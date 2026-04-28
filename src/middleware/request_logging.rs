//! Structured request logging middleware.
//!
//! Sub-phase A emits start/end request logs. Later observability work can
//! add metrics without changing the handler surface.

use axum::{extract::Request, middleware::Next, response::Response};
use tracing::Instrument;

use crate::context::CorrelationContext;

/// Emit structured tracing events around each request.
pub async fn request_logging(request: Request, next: Next) -> Response {
    let method = request.method().clone();
    let uri = request.uri().clone();
    let correlation = request.extensions().get::<CorrelationContext>().cloned();
    let correlation_id = correlation.map(|context| context.correlation_id);

    let span = tracing::info_span!(
        "api.request",
        %method,
        %uri,
        correlation_id = correlation_id.map(|id| id.to_string()).unwrap_or_else(|| "missing".to_string()),
        scope = "pending",
    );

    async move {
        tracing::info!("request started");
        let response = next.run(request).await;
        let status = response.status();
        tracing::info!(%status, "request finished");
        response
    }
    .instrument(span)
    .await
}
