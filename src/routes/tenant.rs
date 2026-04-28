//! Tenant-administration routes.

use std::sync::Arc;

use axum::{
    Extension, Json, Router,
    middleware::from_fn,
    routing::{MethodRouter, get, patch},
};
use philharmonic_policy::{Tenant, TenantStatus, atom};
use philharmonic_store::{EntityStoreExt, RevisionInput};
use philharmonic_types::{EntityId, JsonValue, ScalarValue, UnixMillis, Uuid};
use serde::{Deserialize, Serialize};

use crate::{
    ApiError, RequestContext, RequiredPermission,
    middleware::authz::authorize,
    routes::identity::{
        i64_scalar, latest_revision, next_revision_seq, optional_content_hash, put_json,
        store_error, tenant_scope,
    },
    store::{ApiStore, ApiStoreHandle},
};

/// Shared tenant-administration route state.
#[derive(Clone)]
pub(crate) struct TenantState {
    store: ApiStoreHandle,
}

impl TenantState {
    pub(crate) fn new(store: Arc<dyn ApiStore>) -> Self {
        Self {
            store: ApiStoreHandle::new(store),
        }
    }
}

/// Build tenant-administration routes.
pub fn router() -> Router {
    Router::new()
        .route(
            "/v1/tenant",
            protected(get(read_tenant), atom::TENANT_SETTINGS_READ),
        )
        .route(
            "/v1/tenant",
            protected(patch(update_tenant), atom::TENANT_SETTINGS_MANAGE),
        )
}

fn protected(route: MethodRouter, permission: &'static str) -> MethodRouter {
    route
        .route_layer(from_fn(authorize))
        .route_layer(Extension(RequiredPermission(permission)))
}

async fn read_tenant(
    Extension(state): Extension<TenantState>,
    Extension(context): Extension<RequestContext>,
) -> Result<Json<TenantResponse>, ApiError> {
    let tenant = tenant_scope(&context)?;
    let row = state
        .store
        .get_entity_typed::<Tenant>(tenant)
        .await
        .map_err(store_error)?
        .ok_or_else(|| ApiError::NotFound("tenant not found".to_string()))?;
    let latest = latest_revision::<Tenant>(&state.store, tenant).await?;
    Ok(Json(
        tenant_response(&state.store, tenant, &row, &latest).await?,
    ))
}

async fn update_tenant(
    Extension(state): Extension<TenantState>,
    Extension(context): Extension<RequestContext>,
    Json(request): Json<UpdateTenantRequest>,
) -> Result<Json<TenantResponse>, ApiError> {
    let tenant = tenant_scope(&context)?;
    let Some(display_name) = request.display_name else {
        return Err(ApiError::InvalidRequest(
            "tenant update must change at least one field".to_string(),
        ));
    };

    let row = state
        .store
        .get_entity_typed::<Tenant>(tenant)
        .await
        .map_err(store_error)?
        .ok_or_else(|| ApiError::NotFound("tenant not found".to_string()))?;
    let latest = latest_revision::<Tenant>(&state.store, tenant).await?;
    let next_revision_seq = next_revision_seq(&latest, "tenant")?;
    let display_name_hash = put_json(&state.store, &JsonValue::String(display_name)).await?;
    let mut revision = RevisionInput::new()
        .with_content("display_name", display_name_hash)
        .with_scalar("status", ScalarValue::I64(i64_scalar(&latest, "status")?));
    if let Some(settings_hash) = optional_content_hash(&latest, "settings") {
        revision = revision.with_content("settings", settings_hash);
    }

    state
        .store
        .append_revision_typed::<Tenant>(tenant, next_revision_seq, &revision)
        .await
        .map_err(store_error)?;
    let updated = latest_revision::<Tenant>(&state.store, tenant).await?;
    Ok(Json(
        tenant_response(&state.store, tenant, &row, &updated).await?,
    ))
}

#[derive(Deserialize)]
struct UpdateTenantRequest {
    display_name: Option<String>,
}

#[derive(Serialize)]
struct TenantResponse {
    tenant_id: Uuid,
    display_name: String,
    status: &'static str,
    created_at: UnixMillis,
    updated_at: UnixMillis,
    latest_revision: u64,
}

async fn tenant_response(
    store: &ApiStoreHandle,
    tenant: EntityId<Tenant>,
    row: &philharmonic_store::EntityRow,
    revision: &philharmonic_store::RevisionRow,
) -> Result<TenantResponse, ApiError> {
    Ok(TenantResponse {
        tenant_id: tenant.public().as_uuid(),
        display_name: tenant_display_name(store, revision).await?,
        status: tenant_status_name(i64_scalar(revision, "status")?)?,
        created_at: row.created_at,
        updated_at: revision.created_at,
        latest_revision: revision.revision_seq,
    })
}

async fn tenant_display_name(
    store: &ApiStoreHandle,
    revision: &philharmonic_store::RevisionRow,
) -> Result<String, ApiError> {
    let Some(hash) = optional_content_hash(revision, "display_name") else {
        return Ok(String::new());
    };
    match crate::routes::identity::load_json(store, hash).await? {
        JsonValue::String(value) => Ok(value),
        _ => Err(ApiError::Internal(
            "invalid stored tenant display name".to_string(),
        )),
    }
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
