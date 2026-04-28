//! Request scope types and deployment-supplied resolver trait.
//!
//! Sub-phase A defines the trait surface only. Deployments provide the
//! resolver implementation, and sub-phase C later enforces tenant/operator
//! scope against endpoint authorization rules.

pub use philharmonic_policy::Tenant;
pub use philharmonic_types::EntityId;

/// Scope resolved for an incoming request.
#[derive(Debug, Clone)]
pub enum RequestScope {
    /// A tenant-scoped request for the supplied tenant.
    Tenant(EntityId<Tenant>),
    /// A deployment-operator request.
    Operator,
}

/// Deployment-supplied resolver for request scope.
#[async_trait::async_trait]
pub trait RequestScopeResolver: Send + Sync + 'static {
    /// Resolve the request into tenant or operator scope.
    async fn resolve(&self, parts: &http::request::Parts) -> Result<RequestScope, ResolverError>;
}

/// Errors returned by a [`RequestScopeResolver`].
#[derive(Debug, thiserror::Error)]
pub enum ResolverError {
    /// The request carried neither tenant nor operator scope.
    #[error("request does not carry tenant or operator scope")]
    Unscoped,
    /// The resolver failed internally.
    #[error("scope-resolver internal error: {0}")]
    Internal(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use philharmonic_types::{Identity, Uuid};

    fn tenant_id() -> EntityId<Tenant> {
        Identity {
            internal: Uuid::now_v7(),
            public: Uuid::new_v4(),
        }
        .typed()
        .unwrap()
    }

    #[test]
    fn request_scope_debug_includes_variant() {
        let tenant = RequestScope::Tenant(tenant_id());
        assert!(format!("{tenant:?}").contains("Tenant"));
        assert_eq!(format!("{:?}", RequestScope::Operator), "Operator");
    }
}
