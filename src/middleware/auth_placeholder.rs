//! Placeholder authentication middleware.
//!
//! TODO(sub-phase B): replace this no-op with real long-lived `pht_`
//! token lookup and ephemeral COSE_Sign1 verification. Sub-phase A leaves
//! `RequestContext.auth` as `None` so handlers and tests can exercise the
//! middleware chain without authentication behavior.

use axum::{extract::Request, middleware::Next, response::Response};

/// Leave authentication empty until sub-phase B.
pub async fn auth_placeholder(request: Request, next: Next) -> Response {
    tracing::debug!("auth-placeholder: real auth lands in sub-phase B");
    next.run(request).await
}
