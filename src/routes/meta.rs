//! Meta smoke-test endpoints.
//!
//! Sub-phase A uses these endpoints to prove the middleware chain and
//! structured response shapes work before real API handlers land.

use axum::Json;
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
