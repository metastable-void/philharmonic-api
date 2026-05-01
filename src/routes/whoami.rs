//! Authenticated caller identity endpoint.

use axum::{Extension, Json, http::StatusCode, response::IntoResponse};
use serde::Serialize;

use crate::{ApiError, RequestContext};

/// Response body for `/v1/whoami`.
#[derive(Debug, Serialize)]
pub struct WhoamiResponse {
    /// Public tenant UUID (use as `X-Tenant-Id` header value).
    pub tenant_id: uuid::Uuid,
    /// Authentication method (`"principal"` or `"ephemeral"`).
    pub auth_type: &'static str,
}

/// Return the authenticated caller's tenant identity.
pub async fn whoami(
    Extension(context): Extension<RequestContext>,
) -> Result<impl IntoResponse, ApiError> {
    let auth = context.auth.as_ref().ok_or(ApiError::Unauthenticated)?;
    let tenant_id = auth.tenant_id().public().as_uuid();
    let auth_type = if auth.is_principal() {
        "principal"
    } else {
        "ephemeral"
    };
    Ok((
        StatusCode::OK,
        Json(WhoamiResponse {
            tenant_id,
            auth_type,
        }),
    ))
}
