//! Placeholder authorization middleware.
//!
//! TODO(sub-phase C): replace this no-op with permission-atom evaluation,
//! tenant-scope checks, operator-scope checks, and ephemeral instance-scope
//! enforcement.

use axum::{extract::Request, middleware::Next, response::Response};

/// Permit all requests until sub-phase C.
pub async fn authz_placeholder(request: Request, next: Next) -> Response {
    tracing::debug!("authz-placeholder: real authz lands in sub-phase C");
    next.run(request).await
}
