//! Correlation ID propagation middleware.
//!
//! Sub-phase A generates or propagates `X-Correlation-Id` and stores the
//! initial timing context used by later middleware.

use std::time::Instant;

use axum::{
    body::Body,
    extract::Request,
    http::{HeaderName, HeaderValue},
    middleware::Next,
    response::Response,
};

use crate::context::CorrelationContext;

/// Header used for request/response correlation IDs.
pub const CORRELATION_ID_HEADER: HeaderName = HeaderName::from_static("x-correlation-id");

/// Generate or propagate a request correlation ID.
pub async fn correlation_id(mut request: Request, next: Next) -> Response {
    let correlation_id = request
        .headers()
        .get(&CORRELATION_ID_HEADER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| uuid::Uuid::parse_str(value).ok())
        .unwrap_or_else(uuid::Uuid::new_v4);

    request.extensions_mut().insert(CorrelationContext {
        correlation_id,
        started_at: Instant::now(),
    });

    let mut response = next.run(request).await;
    insert_correlation_id_header(response.headers_mut(), correlation_id);
    response
}

fn insert_correlation_id_header(headers: &mut http::HeaderMap, correlation_id: uuid::Uuid) {
    let value = correlation_id.to_string();
    match HeaderValue::from_str(&value) {
        Ok(header_value) => {
            headers.insert(CORRELATION_ID_HEADER, header_value);
        }
        Err(error) => {
            tracing::warn!(%correlation_id, %error, "failed to format correlation id header");
        }
    }
}

#[allow(dead_code)]
fn _body_type_is_send(_: Body) {}
