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
//! Sub-phase G requires a request-scope resolver, substrate store, API
//! verifying-key registry, API signing key and issuer, workflow step executor,
//! and config lowerer. The API builder constructs the workflow engine
//! internally from those dependencies.
//!
//! ```no_run
//! use std::sync::Arc;
//!
//! use async_trait::async_trait;
//! use philharmonic_api::{
//!     PhilharmonicApiBuilder, RequestScope, RequestScopeResolver, ResolverError,
//!     StubExecutor, StubLowerer,
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
//!     # .api_signing_key(todo_signing_key())
//!     .issuer("philharmonic-api.example".to_string())
//!     .step_executor(Arc::new(StubExecutor))
//!     .config_lowerer(Arc::new(StubLowerer))
//!     .build()?;
//! let router = api.into_router();
//! # Ok::<(), philharmonic_api::BuilderError>(())
//! # }
//! # fn todo_store() -> Arc<dyn ApiStore> { todo!() }
//! # fn todo_signing_key() -> philharmonic_policy::ApiSigningKey { todo!() }
//! ```
//!
//! # Current scope (sub-phase G)
//!
//! The crate includes the axum router, scope-resolution middleware,
//! request context type, correlation ID propagation, structured logging,
//! error envelope, real authentication (long-lived `pht_` token lookup
//! and ephemeral COSE_Sign1 verification via `philharmonic-policy`),
//! real authorization against route-declared permission atoms, smoke-test
//! meta endpoints, workflow template/instance management endpoints, and
//! endpoint-config management endpoints with SCK encryption at rest, plus
//! principal, role, role-membership, and minting-authority CRUD, plus the
//! token-minting endpoint. Audit, rate-limit, tenant, and operator handlers
//! land in later Phase 8 sub-phases.
//!
//! See `docs/design/10-api-layer.md` and `ROADMAP.md` Phase 8 in the
//! Philharmonic workspace for the full endpoint plan.

mod auth;
mod context;
mod error;
mod middleware;
mod pagination;
mod routes;
mod scope;
mod store;
mod workflow;

pub use auth::AuthContext;
pub use context::RequestContext;
pub use error::{ApiError, ErrorBody, ErrorCode, ErrorEnvelope};
pub use middleware::authz::{AuthzState, RequestInstanceScope, RequiredPermission, authorize};
pub use pagination::{PaginatedResponse, PaginationParams};
pub use scope::{EntityId, RequestScope, RequestScopeResolver, ResolverError, Tenant};
pub use store::ApiStore;
pub use workflow::{StubExecutor, StubLowerer};

use std::sync::Arc;

use axum::Router;
use philharmonic_policy::{ApiSigningKey, ApiVerifyingKeyRegistry, Sck};
use philharmonic_workflow::{ConfigLowerer, StepExecutor, WorkflowEngine};

use crate::{
    routes::{
        authorities::AuthorityState, endpoints::EndpointState, memberships::MembershipState,
        mint::MintState, principals::PrincipalState, roles::RoleState, workflows::WorkflowState,
    },
    store::ApiStoreHandle,
    workflow::{SharedConfigLowerer, SharedStepExecutor},
};

/// Builder for [`PhilharmonicApi`].
///
/// The builder constructs the axum router and middleware chain once all
/// required trait implementations have been plugged in. Sub-phase G requires a
/// [`RequestScopeResolver`], [`ApiStore`], API verifying-key registry, API
/// signing key, issuer, workflow [`StepExecutor`], and workflow
/// [`ConfigLowerer`]. Later Phase 8 sub-phases add rate-limit and audit
/// dependencies.
#[derive(Default)]
pub struct PhilharmonicApiBuilder {
    request_scope_resolver: Option<Arc<dyn RequestScopeResolver>>,
    store: Option<Arc<dyn ApiStore>>,
    api_verifying_key_registry: Option<ApiVerifyingKeyRegistry>,
    api_signing_key: Option<ApiSigningKey>,
    issuer: Option<String>,
    step_executor: Option<Arc<dyn StepExecutor>>,
    config_lowerer: Option<Arc<dyn ConfigLowerer>>,
    sck: Option<Arc<Sck>>,
    key_version: i64,
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

    /// Plug in the API signing key used by the token-minting endpoint.
    pub fn api_signing_key(mut self, key: ApiSigningKey) -> Self {
        self.api_signing_key = Some(key);
        self
    }

    /// Set the issuer string carried by freshly minted ephemeral API tokens.
    pub fn issuer(mut self, issuer: String) -> Self {
        self.issuer = Some(issuer);
        self
    }

    /// Plug in the workflow step executor used by instance execution.
    pub fn step_executor(mut self, executor: Arc<dyn StepExecutor>) -> Self {
        self.step_executor = Some(executor);
        self
    }

    /// Plug in the workflow abstract-config lowerer.
    pub fn config_lowerer(mut self, lowerer: Arc<dyn ConfigLowerer>) -> Self {
        self.config_lowerer = Some(lowerer);
        self
    }

    /// Plug in the substrate credential key used by endpoint-config routes.
    pub fn sck(mut self, sck: Sck) -> Self {
        self.sck = Some(Arc::new(sck));
        self
    }

    /// Set the current SCK key version written by endpoint-config routes.
    pub fn key_version(mut self, key_version: i64) -> Self {
        self.key_version = key_version;
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
        let signing_key = self
            .api_signing_key
            .ok_or(BuilderError::MissingDependency("api_signing_key"))?;
        let issuer = self
            .issuer
            .ok_or(BuilderError::MissingDependency("issuer"))?;
        let executor = self
            .step_executor
            .ok_or(BuilderError::MissingDependency("step_executor"))?;
        let lowerer = self
            .config_lowerer
            .ok_or(BuilderError::MissingDependency("config_lowerer"))?;
        if let Some(entry) = registry.lookup(signing_key.kid()) {
            if entry.issuer != *issuer {
                return Err(BuilderError::ConfigurationMismatch(
                    "builder issuer does not match the verifying-key registry entry's issuer for the signing key kid",
                ));
            }
        } else {
            return Err(BuilderError::ConfigurationMismatch(
                "signing key kid not found in the verifying-key registry",
            ));
        }

        let auth_state = middleware::auth::AuthState::new(Arc::clone(&store), Arc::new(registry));
        let authz_state = middleware::authz::AuthzState::new(Arc::clone(&store));
        let workflow_store = ApiStoreHandle::new(Arc::clone(&store));
        let workflow_state = WorkflowState::new(
            Arc::clone(&store),
            Arc::new(WorkflowEngine::new(
                workflow_store,
                SharedStepExecutor::new(executor),
                SharedConfigLowerer::new(lowerer),
            )),
        );
        let endpoint_state = EndpointState::new(
            Arc::clone(&store),
            self.sck.as_ref().map(Arc::clone),
            self.key_version,
        );
        let principal_state = PrincipalState::new(Arc::clone(&store));
        let role_state = RoleState::new(Arc::clone(&store));
        let membership_state = MembershipState::new(Arc::clone(&store));
        let authority_state = AuthorityState::new(Arc::clone(&store));
        let mint_state =
            MintState::new(Arc::clone(&store), Arc::new(signing_key), Arc::from(issuer));

        let mut router = routes::router();
        if let Some(extra_routes) = self.extra_routes {
            router = router.merge(extra_routes);
        }

        let router = router
            .layer(axum::middleware::from_fn(middleware::authz::authorize))
            .layer(axum::Extension(authz_state))
            .layer(axum::Extension(authority_state))
            .layer(axum::Extension(mint_state))
            .layer(axum::Extension(membership_state))
            .layer(axum::Extension(role_state))
            .layer(axum::Extension(principal_state))
            .layer(axum::Extension(endpoint_state))
            .layer(axum::Extension(workflow_state))
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
    /// A configuration inconsistency was detected at build time.
    #[error("configuration mismatch: {0}")]
    ConfigurationMismatch(&'static str),
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroizing;

    #[test]
    fn builder_reports_missing_scope_resolver() {
        let result = PhilharmonicApiBuilder::new().build();
        assert!(matches!(
            result,
            Err(BuilderError::MissingDependency("request_scope_resolver"))
        ));
    }

    #[test]
    fn builder_reports_missing_executor() {
        let result = PhilharmonicApiBuilder::new()
            .request_scope_resolver(Arc::new(NoopResolver))
            .store(Arc::new(NoopStore))
            .api_verifying_key_registry(ApiVerifyingKeyRegistry::new())
            .api_signing_key(signing_key())
            .issuer("philharmonic-api.example".to_string())
            .config_lowerer(Arc::new(StubLowerer))
            .build();
        assert!(matches!(
            result,
            Err(BuilderError::MissingDependency("step_executor"))
        ));
    }

    #[test]
    fn builder_reports_missing_signing_key() {
        let result = PhilharmonicApiBuilder::new()
            .request_scope_resolver(Arc::new(NoopResolver))
            .store(Arc::new(NoopStore))
            .api_verifying_key_registry(ApiVerifyingKeyRegistry::new())
            .issuer("philharmonic-api.example".to_string())
            .step_executor(Arc::new(StubExecutor))
            .config_lowerer(Arc::new(StubLowerer))
            .build();
        assert!(matches!(
            result,
            Err(BuilderError::MissingDependency("api_signing_key"))
        ));
    }

    #[test]
    fn builder_reports_missing_issuer() {
        let result = PhilharmonicApiBuilder::new()
            .request_scope_resolver(Arc::new(NoopResolver))
            .store(Arc::new(NoopStore))
            .api_verifying_key_registry(ApiVerifyingKeyRegistry::new())
            .api_signing_key(signing_key())
            .step_executor(Arc::new(StubExecutor))
            .config_lowerer(Arc::new(StubLowerer))
            .build();
        assert!(matches!(
            result,
            Err(BuilderError::MissingDependency("issuer"))
        ));
    }

    #[test]
    fn builder_reports_missing_lowerer() {
        let result = PhilharmonicApiBuilder::new()
            .request_scope_resolver(Arc::new(NoopResolver))
            .store(Arc::new(NoopStore))
            .api_verifying_key_registry(ApiVerifyingKeyRegistry::new())
            .api_signing_key(signing_key())
            .issuer("philharmonic-api.example".to_string())
            .step_executor(Arc::new(StubExecutor))
            .build();
        assert!(matches!(
            result,
            Err(BuilderError::MissingDependency("config_lowerer"))
        ));
    }

    fn signing_key() -> ApiSigningKey {
        ApiSigningKey::from_seed(Zeroizing::new([7; 32]), "api.test".to_string())
    }

    struct NoopResolver;

    #[async_trait::async_trait]
    impl RequestScopeResolver for NoopResolver {
        async fn resolve(
            &self,
            _parts: &http::request::Parts,
        ) -> Result<RequestScope, ResolverError> {
            Ok(RequestScope::Operator)
        }
    }

    struct NoopStore;

    #[async_trait::async_trait]
    impl philharmonic_store::IdentityStore for NoopStore {
        async fn mint(
            &self,
        ) -> Result<philharmonic_types::Identity, philharmonic_store::StoreError> {
            Err(philharmonic_store::StoreError::Backend(
                philharmonic_store::BackendError::fatal("noop"),
            ))
        }

        async fn resolve_public(
            &self,
            _public: philharmonic_types::Uuid,
        ) -> Result<Option<philharmonic_types::Identity>, philharmonic_store::StoreError> {
            Ok(None)
        }

        async fn resolve_internal(
            &self,
            _internal: philharmonic_types::Uuid,
        ) -> Result<Option<philharmonic_types::Identity>, philharmonic_store::StoreError> {
            Ok(None)
        }
    }

    #[async_trait::async_trait]
    impl philharmonic_store::EntityStore for NoopStore {
        async fn create_entity(
            &self,
            _identity: philharmonic_types::Identity,
            _kind: philharmonic_types::Uuid,
        ) -> Result<(), philharmonic_store::StoreError> {
            Ok(())
        }

        async fn get_entity(
            &self,
            _entity_id: philharmonic_types::Uuid,
        ) -> Result<Option<philharmonic_store::EntityRow>, philharmonic_store::StoreError> {
            Ok(None)
        }

        async fn append_revision(
            &self,
            _entity_id: philharmonic_types::Uuid,
            _revision_seq: u64,
            _input: &philharmonic_store::RevisionInput,
        ) -> Result<(), philharmonic_store::StoreError> {
            Ok(())
        }

        async fn get_revision(
            &self,
            _entity_id: philharmonic_types::Uuid,
            _revision_seq: u64,
        ) -> Result<Option<philharmonic_store::RevisionRow>, philharmonic_store::StoreError>
        {
            Ok(None)
        }

        async fn get_latest_revision(
            &self,
            _entity_id: philharmonic_types::Uuid,
        ) -> Result<Option<philharmonic_store::RevisionRow>, philharmonic_store::StoreError>
        {
            Ok(None)
        }

        async fn list_revisions_referencing(
            &self,
            _target_entity_id: philharmonic_types::Uuid,
            _attribute_name: &str,
        ) -> Result<Vec<philharmonic_store::RevisionRef>, philharmonic_store::StoreError> {
            Ok(Vec::new())
        }

        async fn find_by_scalar(
            &self,
            _kind: philharmonic_types::Uuid,
            _attribute_name: &str,
            _value: &philharmonic_types::ScalarValue,
        ) -> Result<Vec<philharmonic_store::EntityRow>, philharmonic_store::StoreError> {
            Ok(Vec::new())
        }
    }

    #[async_trait::async_trait]
    impl philharmonic_store::ContentStore for NoopStore {
        async fn put(
            &self,
            _value: &philharmonic_types::ContentValue,
        ) -> Result<(), philharmonic_store::StoreError> {
            Ok(())
        }

        async fn get(
            &self,
            _hash: philharmonic_types::Sha256,
        ) -> Result<Option<philharmonic_types::ContentValue>, philharmonic_store::StoreError>
        {
            Ok(None)
        }

        async fn exists(
            &self,
            _hash: philharmonic_types::Sha256,
        ) -> Result<bool, philharmonic_store::StoreError> {
            Ok(false)
        }
    }
}
