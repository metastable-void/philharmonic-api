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
//! Sub-phase B has three required dependencies: the request-scope resolver,
//! substrate store, and API verifying-key registry. Sub-phase C requires that
//! the store also expose content blobs so role permission documents can be
//! evaluated. Later sub-phases add workflow execution, endpoint handlers, rate
//! limiting, and audit dependencies.
//!
//! ```no_run
//! use std::sync::Arc;
//!
//! use async_trait::async_trait;
//! use philharmonic_api::{
//!     PhilharmonicApiBuilder, RequestScope, RequestScopeResolver, ResolverError,
//! };
//! use philharmonic_policy::ApiVerifyingKeyRegistry;
//! use philharmonic_api::ApiStore;
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
//! # fn main() -> Result<(), philharmonic_api::BuilderError> {
//! let api = PhilharmonicApiBuilder::new()
//!     .request_scope_resolver(Arc::new(OperatorOnly))
//!     # .store(todo_store())
//!     .api_verifying_key_registry(ApiVerifyingKeyRegistry::new())
//!     .build()?;
//! let router = api.into_router();
//! # Ok::<(), philharmonic_api::BuilderError>(())
//! # }
//! # fn todo_store() -> Arc<dyn ApiStore> { todo!() }
//! ```
//!
//! # Current scope (sub-phase C)
//!
//! The crate includes the axum router, scope-resolution middleware,
//! request context type, correlation ID propagation, structured logging,
//! error envelope, real authentication (long-lived `pht_` token lookup
//! and ephemeral COSE_Sign1 verification via `philharmonic-policy`),
//! real authorization against route-declared permission atoms, and smoke-test
//! meta endpoints. Real workflow, endpoint-config, principal, role,
//! token-minting, audit, rate-limit, and operator handlers land in later
//! Phase 8 sub-phases.
//!
//! See `docs/design/10-api-layer.md` and `ROADMAP.md` Phase 8 in the
//! Philharmonic workspace for the full endpoint plan.

mod auth;
mod context;
mod error;
mod middleware;
mod routes;
mod scope;
mod store;

pub use auth::AuthContext;
pub use context::RequestContext;
pub use error::{ApiError, ErrorBody, ErrorCode, ErrorEnvelope};
pub use middleware::authz::{AuthzState, RequestInstanceScope, RequiredPermission, authorize};
pub use scope::{EntityId, RequestScope, RequestScopeResolver, ResolverError, Tenant};
pub use store::ApiStore;

use std::sync::Arc;

use axum::Router;
use philharmonic_policy::ApiVerifyingKeyRegistry;

/// Builder for [`PhilharmonicApi`].
///
/// The builder constructs the axum router and middleware chain once all
/// required trait implementations have been plugged in. Sub-phase B
/// requires a [`RequestScopeResolver`], [`ApiStore`], and API verifying-key
/// registry; later Phase 8 sub-phases add executor, handler, and rate-limit
/// or audit dependencies.
#[derive(Default)]
pub struct PhilharmonicApiBuilder {
    request_scope_resolver: Option<Arc<dyn RequestScopeResolver>>,
    store: Option<Arc<dyn ApiStore>>,
    api_verifying_key_registry: Option<ApiVerifyingKeyRegistry>,
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

    /// Plug in the storage substrate used by middleware and handlers.
    pub fn store(mut self, store: Arc<dyn ApiStore>) -> Self {
        self.store = Some(store);
        self
    }

    /// Plug in API signing-key verifiers for ephemeral-token authentication.
    pub fn api_verifying_key_registry(mut self, registry: ApiVerifyingKeyRegistry) -> Self {
        self.api_verifying_key_registry = Some(registry);
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
        let store = self.store.ok_or(BuilderError::MissingDependency("store"))?;
        let registry = self
            .api_verifying_key_registry
            .ok_or(BuilderError::MissingDependency(
                "api_verifying_key_registry",
            ))?;
        let auth_state = middleware::auth::AuthState::new(Arc::clone(&store), Arc::new(registry));
        let authz_state = middleware::authz::AuthzState::new(store);

        let mut router = routes::router();
        if let Some(extra_routes) = self.extra_routes {
            router = router.merge(extra_routes);
        }

        let router = router
            .layer(axum::middleware::from_fn(middleware::authz::authorize))
            .layer(axum::Extension(authz_state))
            .layer(axum::middleware::from_fn(middleware::auth::authenticate))
            .layer(axum::Extension(auth_state))
            .layer(axum::middleware::from_fn_with_state(
                resolver,
                middleware::scope::resolve_scope,
            ))
            .layer(axum::middleware::from_fn(
                middleware::request_logging::request_logging,
            ))
            .layer(axum::middleware::from_fn(
                middleware::correlation_id::correlation_id,
            ));

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
