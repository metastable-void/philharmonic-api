//! `philharmonic-api` — public HTTP API for Philharmonic.
//!
//! This crate hosts the HTTP-facing layer that sits in front of the
//! workflow engine. Deployments provide the process, sockets, ingress,
//! TLS termination, and request-to-scope mapping; this library provides a
//! ready-to-serve [`axum::Router`] once its required trait surfaces are
//! plugged into [`PhilharmonicApiBuilder`].
//!
//! # Architecture
//!
//! The API layer treats tenant and operator scope as deployment-supplied
//! input. A host binary provides a [`RequestScopeResolver`] that can read
//! subdomains, path prefixes, client certificates, fixed deployment
//! settings, or any other local convention and returns a [`RequestScope`].
//! The middleware chain resolves that scope, attaches a [`RequestContext`],
//! emits structured request logs, and returns structured JSON errors.
//!
//! # Builder
//!
//! Sub-phase A has one required dependency: the request-scope resolver.
//! Later sub-phases add authentication, authorization, substrate access,
//! workflow execution, signing-key lookup, and endpoint handlers.
//!
//! ```no_run
//! use std::sync::Arc;
//!
//! use async_trait::async_trait;
//! use philharmonic_api::{
//!     PhilharmonicApiBuilder, RequestScope, RequestScopeResolver, ResolverError,
//! };
//!
//! struct OperatorOnly;
//!
//! #[async_trait]
//! impl RequestScopeResolver for OperatorOnly {
//!     async fn resolve(
//!         &self,
//!         _parts: &http::request::Parts,
//!     ) -> Result<RequestScope, ResolverError> {
//!         Ok(RequestScope::Operator)
//!     }
//! }
//!
//! let api = PhilharmonicApiBuilder::new()
//!     .request_scope_resolver(Arc::new(OperatorOnly))
//!     .build()?;
//! let router = api.into_router();
//! # Ok::<(), philharmonic_api::BuilderError>(())
//! ```
//!
//! # Sub-phase A scope
//!
//! This skeleton includes the axum router, scope-resolution middleware,
//! request context type, correlation ID propagation, structured logging,
//! error envelope, and smoke-test meta endpoints. Authentication and
//! authorization are explicitly placeholder layers: sub-phase B replaces
//! authentication and sub-phase C replaces authorization. Real workflow,
//! endpoint-config, principal, role, token-minting, audit, rate-limit, and
//! operator handlers land in later Phase 8 sub-phases.
//!
//! See `docs/design/10-api-layer.md` and `ROADMAP.md` Phase 8 in the
//! Philharmonic workspace for the full endpoint plan.

mod auth;
mod context;
mod error;
mod middleware;
mod routes;
mod scope;

pub use auth::AuthContext;
pub use context::RequestContext;
pub use error::{ApiError, ErrorBody, ErrorCode, ErrorEnvelope};
pub use scope::{EntityId, RequestScope, RequestScopeResolver, ResolverError, Tenant};

use std::sync::Arc;

use axum::Router;
use tower::ServiceBuilder;

/// Builder for [`PhilharmonicApi`].
///
/// The builder constructs the axum router and middleware chain once all
/// required trait implementations have been plugged in. Sub-phase A only
/// requires a [`RequestScopeResolver`]; later Phase 8 sub-phases add the
/// store, executor client, lowerer, authentication dependencies, signing
/// keys, and rate-limit/audit dependencies.
#[derive(Default)]
pub struct PhilharmonicApiBuilder {
    request_scope_resolver: Option<Arc<dyn RequestScopeResolver>>,
    extra_routes: Option<Router>,
}

impl PhilharmonicApiBuilder {
    /// Create an empty API builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Plug in the deployment-supplied request-scope resolver.
    pub fn request_scope_resolver(mut self, resolver: Arc<dyn RequestScopeResolver>) -> Self {
        self.request_scope_resolver = Some(resolver);
        self
    }

    /// Merge additional routes before the middleware chain is applied.
    ///
    /// Sub-phase A uses this hook for smoke tests. Later sub-phases can
    /// replace it with more specific builder dependencies as endpoint
    /// families are implemented.
    pub fn extra_routes(mut self, router: Router) -> Self {
        self.extra_routes = Some(router);
        self
    }

    /// Build the fully-constructed API router.
    pub fn build(self) -> Result<PhilharmonicApi, BuilderError> {
        let resolver = self
            .request_scope_resolver
            .ok_or(BuilderError::MissingDependency("request_scope_resolver"))?;

        let mut router = routes::router();
        if let Some(extra_routes) = self.extra_routes {
            router = router.merge(extra_routes);
        }

        let router = router.layer(
            ServiceBuilder::new()
                .layer(axum::middleware::from_fn(
                    middleware::correlation_id::correlation_id,
                ))
                .layer(axum::middleware::from_fn(
                    middleware::request_logging::request_logging,
                ))
                .layer(axum::middleware::from_fn_with_state(
                    resolver,
                    middleware::scope::resolve_scope,
                ))
                .layer(axum::middleware::from_fn(
                    middleware::auth_placeholder::auth_placeholder,
                ))
                .layer(axum::middleware::from_fn(
                    middleware::authz_placeholder::authz_placeholder,
                )),
        );

        Ok(PhilharmonicApi { router })
    }
}

/// The fully-constructed public HTTP API.
///
/// This wraps the concrete [`axum::Router`] so callers receive a
/// ready-to-serve service without depending on the router's internal state
/// shape.
pub struct PhilharmonicApi {
    router: Router,
}

impl PhilharmonicApi {
    /// Consume the API and return the underlying axum router.
    pub fn into_router(self) -> Router {
        self.router
    }

    /// Consume the API and return an axum make-service for serving.
    pub fn into_make_service(self) -> axum::routing::IntoMakeService<Router> {
        self.router.into_make_service()
    }
}

/// Errors returned while constructing [`PhilharmonicApi`].
#[derive(Debug, thiserror::Error)]
pub enum BuilderError {
    /// A dependency required by this sub-phase was not provided.
    #[error("missing required dependency: {0}")]
    MissingDependency(&'static str),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_reports_missing_scope_resolver() {
        let result = PhilharmonicApiBuilder::new().build();
        assert!(matches!(
            result,
            Err(BuilderError::MissingDependency("request_scope_resolver"))
        ));
    }
}
