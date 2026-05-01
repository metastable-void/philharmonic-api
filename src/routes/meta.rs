//! Meta smoke-test and branding endpoints.

use std::sync::Arc;

use axum::{Extension, Json};
use serde::Serialize;

/// Version response body.
#[derive(Debug, Serialize)]
pub struct VersionResponse {
    /// Crate version.
    pub version: &'static str,
}

/// Health response body.
#[derive(Debug, Serialize)]
pub struct HealthResponse {
    /// Health status.
    pub status: &'static str,
}

/// Branding response body.
#[derive(Debug, Serialize)]
pub struct BrandingResponse {
    /// Display name for the deployment.
    pub name: String,
    /// First character of the display name (for monogram icons).
    pub monogram: String,
}

/// Shared branding state injected by the deployment binary.
#[derive(Clone, Debug)]
pub struct BrandingState {
    /// Configured brand name.
    pub name: Arc<str>,
}

/// Return the crate version.
pub async fn version() -> Json<VersionResponse> {
    Json(VersionResponse {
        version: env!("CARGO_PKG_VERSION"),
    })
}

/// Return a basic health response.
pub async fn health() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok" })
}

/// Return the deployment branding.
pub async fn branding(Extension(state): Extension<BrandingState>) -> Json<BrandingResponse> {
    let monogram = state
        .name
        .chars()
        .next()
        .map(|c| c.to_uppercase().to_string())
        .unwrap_or_default();
    Json(BrandingResponse {
        name: state.name.to_string(),
        monogram,
    })
}
