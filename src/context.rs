//! Per-request context attached by middleware.
//!
//! Sub-phase A attaches correlation, timing, request scope, and an empty
//! authentication slot. Sub-phase B populates `auth`, and sub-phase C uses
//! the context for authorization decisions.

use std::time::Instant;

use crate::{AuthContext, RequestScope};

/// Request data shared between middleware and handlers.
#[derive(Debug, Clone)]
pub struct RequestContext {
    /// Correlation ID propagated through logs and response headers.
    pub correlation_id: uuid::Uuid,
    /// Instant when the request entered the API middleware chain.
    pub started_at: Instant,
    /// Deployment-resolved request scope.
    pub scope: RequestScope,
    /// Authenticated caller context, populated by sub-phase B.
    pub auth: Option<AuthContext>,
}

#[derive(Debug, Clone)]
pub(crate) struct CorrelationContext {
    pub(crate) correlation_id: uuid::Uuid,
    pub(crate) started_at: Instant,
}

#[cfg(test)]
mod tests {
    use super::*;
    use philharmonic_types::{Identity, Uuid};

    fn tenant_id() -> crate::EntityId<crate::Tenant> {
        Identity {
            internal: Uuid::now_v7(),
            public: Uuid::new_v4(),
        }
        .typed()
        .unwrap()
    }

    #[test]
    fn request_context_construction_keeps_fields() {
        let correlation_id = uuid::Uuid::new_v4();
        let context = RequestContext {
            correlation_id,
            started_at: Instant::now(),
            scope: RequestScope::Tenant(tenant_id()),
            auth: None,
        };

        assert_eq!(context.correlation_id, correlation_id);
        assert!(matches!(context.scope, RequestScope::Tenant(_)));
        assert!(context.auth.is_none());
    }

    #[test]
    fn correlation_ids_are_unique() {
        let first = uuid::Uuid::new_v4();
        let second = uuid::Uuid::new_v4();

        assert_ne!(first, second);
    }
}
