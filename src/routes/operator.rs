//! Deployment-operator tenant-management routes.

use std::sync::Arc;

use axum::{
    Extension, Json, Router,
    extract::Path,
    http::StatusCode,
    middleware::from_fn,
    response::{IntoResponse, Response},
    routing::{MethodRouter, post},
};
use philharmonic_policy::{Tenant, TenantStatus, atom, validate_subdomain_name};
use philharmonic_store::{EntityStoreExt, RevisionInput, StoreExt};
use philharmonic_types::{JsonValue, ScalarValue, UnixMillis, Uuid};
use serde::{Deserialize, Serialize};

use crate::{
    ApiError, AuthContext, RequestContext, RequestScope, RequiredPermission,
    middleware::authz::authorize,
    routes::identity::{
        i64_scalar, latest_revision, next_revision_seq, optional_content_hash, put_json,
        resolve_public_id, store_error,
    },
    store::{ApiStore, ApiStoreHandle},
};

/// Shared operator route state.
#[derive(Clone)]
pub(crate) struct OperatorState {
    store: ApiStoreHandle,
}

impl OperatorState {
    pub(crate) fn new(store: Arc<dyn ApiStore>) -> Self {
        Self {
            store: ApiStoreHandle::new(store),
        }
    }
}

/// Build deployment-operator routes.
pub fn router() -> Router {
    Router::new()
        .route(
            "/v1/operator/tenants",
            protected(post(create_tenant), atom::DEPLOYMENT_TENANT_MANAGE),
        )
        .route(
            "/v1/operator/tenants/{id}/suspend",
            protected(post(suspend_tenant), atom::DEPLOYMENT_TENANT_MANAGE),
        )
        .route(
            "/v1/operator/tenants/{id}/unsuspend",
            protected(post(unsuspend_tenant), atom::DEPLOYMENT_TENANT_MANAGE),
        )
}

fn protected(route: MethodRouter, permission: &'static str) -> MethodRouter {
    route
        .route_layer(from_fn(authorize))
        .route_layer(Extension(RequiredPermission(permission)))
}

async fn create_tenant(
    Extension(state): Extension<OperatorState>,
    Extension(context): Extension<RequestContext>,
    Json(request): Json<CreateTenantRequest>,
) -> Result<Response, ApiError> {
    require_operator_principal(&context)?;
    validate_subdomain_name(&request.subdomain_name)
        .map_err(|error| ApiError::InvalidRequest(error.to_string()))?;

    let tenant = state
        .store
        .create_entity_minting::<Tenant>()
        .await
        .map_err(store_error)?;
    let display_name_hash =
        put_json(&state.store, &JsonValue::String(request.display_name)).await?;
    let settings_hash = put_json(
        &state.store,
        &serde_json::json!({ "subdomain_name": request.subdomain_name }),
    )
    .await?;
    let revision = RevisionInput::new()
        .with_content("display_name", display_name_hash)
        .with_content("settings", settings_hash)
        .with_scalar("status", ScalarValue::I64(TenantStatus::Active.as_i64()));
    state
        .store
        .append_revision_typed::<Tenant>(tenant, 0, &revision)
        .await
        .map_err(store_error)?;
    let latest = latest_revision::<Tenant>(&state.store, tenant).await?;

    Ok((
        StatusCode::CREATED,
        Json(TenantStatusResponse {
            tenant_id: tenant.public().as_uuid(),
            status: "active",
            updated_at: latest.created_at,
        }),
    )
        .into_response())
}

async fn suspend_tenant(
    Extension(state): Extension<OperatorState>,
    Extension(context): Extension<RequestContext>,
    Path(id): Path<Uuid>,
) -> Result<Json<TenantStatusResponse>, ApiError> {
    require_operator_principal(&context)?;
    update_tenant_status(&state.store, id, TenantStatus::Suspended).await
}

async fn unsuspend_tenant(
    Extension(state): Extension<OperatorState>,
    Extension(context): Extension<RequestContext>,
    Path(id): Path<Uuid>,
) -> Result<Json<TenantStatusResponse>, ApiError> {
    require_operator_principal(&context)?;
    update_tenant_status(&state.store, id, TenantStatus::Active).await
}

#[derive(Deserialize)]
struct CreateTenantRequest {
    subdomain_name: String,
    display_name: String,
}

#[derive(Serialize)]
struct TenantStatusResponse {
    tenant_id: Uuid,
    status: &'static str,
    updated_at: UnixMillis,
}

fn require_operator_principal(context: &RequestContext) -> Result<(), ApiError> {
    match (&context.scope, context.auth.as_ref()) {
        (RequestScope::Operator, Some(AuthContext::Principal { .. })) => Ok(()),
        (RequestScope::Operator, Some(AuthContext::Ephemeral { .. })) => Err(ApiError::Forbidden),
        (RequestScope::Operator, None) => Err(ApiError::Unauthenticated),
        (RequestScope::Tenant(_), _) => Err(ApiError::Forbidden),
    }
}

async fn update_tenant_status(
    store: &ApiStoreHandle,
    public_id: Uuid,
    status: TenantStatus,
) -> Result<Json<TenantStatusResponse>, ApiError> {
    let tenant = resolve_public_id::<Tenant>(store, public_id).await?;
    let latest = latest_revision::<Tenant>(store, tenant).await?;
    let current = TenantStatus::try_from(i64_scalar(&latest, "status")?)
        .map_err(|_| ApiError::Internal("invalid tenant status".to_string()))?;
    if current == TenantStatus::Retired {
        return Err(ApiError::InvalidRequest("tenant is retired".to_string()));
    }

    let next_revision_seq = next_revision_seq(&latest, "tenant")?;
    let mut revision =
        RevisionInput::new().with_scalar("status", ScalarValue::I64(status.as_i64()));
    if let Some(display_name_hash) = optional_content_hash(&latest, "display_name") {
        revision = revision.with_content("display_name", display_name_hash);
    }
    if let Some(settings_hash) = optional_content_hash(&latest, "settings") {
        revision = revision.with_content("settings", settings_hash);
    }
    store
        .append_revision_typed::<Tenant>(tenant, next_revision_seq, &revision)
        .await
        .map_err(store_error)?;
    let updated = latest_revision::<Tenant>(store, tenant).await?;

    Ok(Json(TenantStatusResponse {
        tenant_id: public_id,
        status: tenant_status_name(i64_scalar(&updated, "status")?)?,
        updated_at: updated.created_at,
    }))
}

fn tenant_status_name(value: i64) -> Result<&'static str, ApiError> {
    match TenantStatus::try_from(value)
        .map_err(|_| ApiError::Internal(format!("invalid tenant status {value}")))?
    {
        TenantStatus::Active => Ok("active"),
        TenantStatus::Suspended => Ok("suspended"),
        TenantStatus::Retired => Ok("retired"),
    }
}
