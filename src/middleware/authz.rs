//! Authorization middleware for the public API.

use std::sync::Arc;

use axum::{
    Extension,
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use philharmonic_policy::evaluate_permission;
use philharmonic_types::Uuid;

use crate::{
    ApiError, AuthContext, RequestContext, RequestScope,
    context::CorrelationContext,
    error::{ErrorCode, envelope_response},
    store::{ApiStore, ApiStoreHandle},
};

/// Permission atom required by a protected route or route group.
#[derive(Clone, Debug)]
pub struct RequiredPermission(pub &'static str);

/// Workflow instance ID extracted from a request URL.
///
/// Sub-phase D route code can attach this extension before authorization
/// runs for endpoints whose URL carries a workflow-instance identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RequestInstanceScope(pub Uuid);

/// State required by the authorization middleware.
#[derive(Clone)]
pub struct AuthzState {
    store: ApiStoreHandle,
}

impl AuthzState {
    /// Construct authorization middleware state.
    pub fn new(store: Arc<dyn ApiStore>) -> Self {
        Self {
            store: ApiStoreHandle::new(store),
        }
    }
}

/// Enforce route-declared permission atoms and request scope constraints.
pub async fn authorize(
    Extension(state): Extension<AuthzState>,
    request: Request,
    next: Next,
) -> Response {
    let Some(required) = request.extensions().get::<RequiredPermission>().cloned() else {
        return next.run(request).await;
    };

    let correlation_id = correlation_id(&request);
    let Some(context) = request.extensions().get::<RequestContext>().cloned() else {
        tracing::warn!(%correlation_id, "authz middleware ran without request context");
        return ApiError::Internal("missing request context".to_string())
            .into_response_with_correlation_id(correlation_id);
    };

    let Some(auth_context) = context.auth.as_ref() else {
        return forbidden_response(
            "authentication required for protected endpoint",
            correlation_id,
        );
    };

    if !tenant_scope_allows(&context.scope, auth_context) {
        return forbidden_response(
            "authenticated tenant does not match request scope",
            correlation_id,
        );
    }

    let allowed = match auth_context {
        AuthContext::Principal {
            principal_id,
            tenant_id,
        } => evaluate_permission(&state.store, *principal_id, *tenant_id, required.0).await,
        AuthContext::Ephemeral { permissions, .. } => Ok(permissions
            .iter()
            .any(|permission| permission == required.0)),
    };

    match allowed {
        Ok(true) => {}
        Ok(false) => return forbidden_response("permission denied", correlation_id),
        Err(error) => {
            tracing::warn!(%correlation_id, ?error, "permission evaluation failed");
            return ApiError::Internal("permission evaluation failed".to_string())
                .into_response_with_correlation_id(correlation_id);
        }
    }

    if !instance_scope_allows(auth_context, &request) {
        return forbidden_response(
            "instance scope does not permit this request",
            correlation_id,
        );
    }

    next.run(request).await
}

fn tenant_scope_allows(scope: &RequestScope, auth_context: &AuthContext) -> bool {
    match scope {
        RequestScope::Tenant(scope_tenant) => auth_context.tenant_id() == *scope_tenant,
        RequestScope::Operator => true,
    }
}

fn instance_scope_allows(auth_context: &AuthContext, request: &Request) -> bool {
    let AuthContext::Ephemeral {
        instance_scope: Some(instance_scope),
        ..
    } = auth_context
    else {
        return true;
    };

    request
        .extensions()
        .get::<RequestInstanceScope>()
        .is_none_or(|request_scope| request_scope.0 == *instance_scope)
}

fn forbidden_response(message: &'static str, correlation_id: uuid::Uuid) -> Response {
    envelope_response(
        StatusCode::FORBIDDEN,
        ErrorCode::Forbidden,
        message,
        correlation_id,
    )
    .into_response()
}

fn correlation_id(request: &Request) -> uuid::Uuid {
    request
        .extensions()
        .get::<RequestContext>()
        .map(|context| context.correlation_id)
        .or_else(|| {
            request
                .extensions()
                .get::<CorrelationContext>()
                .map(|context| context.correlation_id)
        })
        .unwrap_or_else(uuid::Uuid::new_v4)
}
