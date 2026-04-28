//! Role-definition management routes.

use std::sync::Arc;

use axum::{
    Extension, Json, Router,
    extract::{Path, Query},
    http::StatusCode,
    middleware::from_fn,
    routing::{MethodRouter, get, patch, post},
};
use philharmonic_policy::{RoleDefinition, atom};
use philharmonic_store::{EntityRefValue, EntityStoreExt, RevisionInput, StoreExt};
use philharmonic_types::{EntityId, JsonValue, ScalarValue, UnixMillis, Uuid};
use serde::{Deserialize, Serialize};

use crate::{
    ApiError, PaginatedResponse, PaginationParams, RequestContext, RequiredPermission,
    middleware::authz::authorize,
    pagination::CursorKey,
    routes::identity::{
        bool_scalar, dedupe_rows, display_name, ensure_revision_tenant, latest_revision,
        next_revision_seq, paginate_items, permission_array_json, permissions_from_revision,
        put_json, require_tenant_principal, required_content_hash, required_entity_ref,
        resolve_public_id, store_error,
    },
    store::{ApiStore, ApiStoreHandle},
};

/// Shared role route state.
#[derive(Clone)]
pub(crate) struct RoleState {
    store: ApiStoreHandle,
}

impl RoleState {
    pub(crate) fn new(store: Arc<dyn ApiStore>) -> Self {
        Self {
            store: ApiStoreHandle::new(store),
        }
    }
}

/// Build role-definition management routes.
pub fn router() -> Router {
    Router::new()
        .route(
            "/v1/roles",
            protected(post(create_role), atom::TENANT_ROLE_MANAGE),
        )
        .route(
            "/v1/roles",
            protected(get(list_roles), atom::TENANT_ROLE_MANAGE),
        )
        .route(
            "/v1/roles/{id}",
            protected(patch(update_role), atom::TENANT_ROLE_MANAGE),
        )
        .route(
            "/v1/roles/{id}/retire",
            protected(post(retire_role), atom::TENANT_ROLE_MANAGE),
        )
}

fn protected(route: MethodRouter, permission: &'static str) -> MethodRouter {
    route
        .route_layer(from_fn(authorize))
        .route_layer(Extension(RequiredPermission(permission)))
}

async fn create_role(
    Extension(state): Extension<RoleState>,
    Extension(context): Extension<RequestContext>,
    Json(request): Json<CreateRoleRequest>,
) -> Result<(StatusCode, Json<CreateRoleResponse>), ApiError> {
    let tenant = require_tenant_principal(&context)?;
    let permissions = permission_array_json(request.permissions)?;
    let role_id = state
        .store
        .create_entity_minting::<RoleDefinition>()
        .await
        .map_err(store_error)?;
    let display_name_hash =
        put_json(&state.store, &JsonValue::String(request.display_name)).await?;
    let permissions_hash = put_json(&state.store, &permissions).await?;

    let revision = RevisionInput::new()
        .with_content("display_name", display_name_hash)
        .with_content("permissions", permissions_hash)
        .with_entity(
            "tenant",
            EntityRefValue::pinned(tenant.internal().as_uuid(), 0),
        )
        .with_scalar("is_retired", ScalarValue::Bool(false));

    state
        .store
        .append_revision_typed::<RoleDefinition>(role_id, 0, &revision)
        .await
        .map_err(store_error)?;

    Ok((
        StatusCode::CREATED,
        Json(CreateRoleResponse {
            role_id: role_id.public().as_uuid(),
        }),
    ))
}

async fn list_roles(
    Extension(state): Extension<RoleState>,
    Extension(context): Extension<RequestContext>,
    Query(params): Query<PaginationParams>,
) -> Result<Json<PaginatedResponse<RoleResponse>>, ApiError> {
    let tenant = require_tenant_principal(&context)?;
    let mut rows = Vec::new();
    rows.extend(
        state
            .store
            .find_by_scalar_typed::<RoleDefinition>("is_retired", &ScalarValue::Bool(false))
            .await
            .map_err(store_error)?,
    );
    rows.extend(
        state
            .store
            .find_by_scalar_typed::<RoleDefinition>("is_retired", &ScalarValue::Bool(true))
            .await
            .map_err(store_error)?,
    );
    dedupe_rows(&mut rows);

    let items = role_items(&state.store, rows, tenant).await?;
    Ok(Json(paginate_items(items, &params)?))
}

async fn update_role(
    Extension(state): Extension<RoleState>,
    Extension(context): Extension<RequestContext>,
    Path(id): Path<Uuid>,
    Json(request): Json<UpdateRoleRequest>,
) -> Result<Json<RoleResponse>, ApiError> {
    let tenant = require_tenant_principal(&context)?;
    if request.display_name.is_none() && request.permissions.is_none() {
        return Err(ApiError::InvalidRequest(
            "role update must change at least one field".to_string(),
        ));
    }

    let role_id = resolve_public_id::<RoleDefinition>(&state.store, id).await?;
    let row = state
        .store
        .get_entity_typed::<RoleDefinition>(role_id)
        .await
        .map_err(store_error)?
        .ok_or_else(|| ApiError::NotFound("role definition not found".to_string()))?;
    let latest = latest_revision::<RoleDefinition>(&state.store, role_id).await?;
    ensure_revision_tenant(&latest, tenant, "role definition")?;
    if bool_scalar(&latest, "is_retired")? {
        return Err(ApiError::InvalidRequest(
            "role definition is retired".to_string(),
        ));
    }

    let display_name_hash = match request.display_name {
        Some(display_name) => put_json(&state.store, &JsonValue::String(display_name)).await?,
        None => required_content_hash(&latest, "display_name")?,
    };
    let permissions_hash = match request.permissions {
        Some(permissions) => {
            let permissions = permission_array_json(permissions)?;
            put_json(&state.store, &permissions).await?
        }
        None => required_content_hash(&latest, "permissions")?,
    };
    let next_revision_seq = next_revision_seq(&latest, "role definition")?;
    let revision = RevisionInput::new()
        .with_content("display_name", display_name_hash)
        .with_content("permissions", permissions_hash)
        .with_entity("tenant", required_entity_ref(&latest, "tenant")?)
        .with_scalar("is_retired", ScalarValue::Bool(false));

    state
        .store
        .append_revision_typed::<RoleDefinition>(role_id, next_revision_seq, &revision)
        .await
        .map_err(store_error)?;
    let updated = latest_revision::<RoleDefinition>(&state.store, role_id).await?;
    Ok(Json(role_response(&state.store, &row, &updated).await?))
}

async fn retire_role(
    Extension(state): Extension<RoleState>,
    Extension(context): Extension<RequestContext>,
    Path(id): Path<Uuid>,
) -> Result<Json<RetireRoleResponse>, ApiError> {
    let tenant = require_tenant_principal(&context)?;
    let role_id = resolve_public_id::<RoleDefinition>(&state.store, id).await?;
    let latest = latest_revision::<RoleDefinition>(&state.store, role_id).await?;
    ensure_revision_tenant(&latest, tenant, "role definition")?;
    if bool_scalar(&latest, "is_retired")? {
        return Err(ApiError::InvalidRequest(
            "role definition is retired".to_string(),
        ));
    }

    let next_revision_seq = next_revision_seq(&latest, "role definition")?;
    let revision = RevisionInput::new()
        .with_content(
            "display_name",
            required_content_hash(&latest, "display_name")?,
        )
        .with_content(
            "permissions",
            required_content_hash(&latest, "permissions")?,
        )
        .with_entity("tenant", required_entity_ref(&latest, "tenant")?)
        .with_scalar("is_retired", ScalarValue::Bool(true));

    state
        .store
        .append_revision_typed::<RoleDefinition>(role_id, next_revision_seq, &revision)
        .await
        .map_err(store_error)?;

    Ok(Json(RetireRoleResponse {
        role_id: id,
        is_retired: true,
    }))
}

#[derive(Deserialize)]
struct CreateRoleRequest {
    display_name: String,
    permissions: Vec<String>,
}

#[derive(Serialize)]
struct CreateRoleResponse {
    role_id: Uuid,
}

#[derive(Deserialize)]
struct UpdateRoleRequest {
    display_name: Option<String>,
    permissions: Option<Vec<String>>,
}

#[derive(Serialize)]
struct RoleResponse {
    role_id: Uuid,
    display_name: String,
    permissions: Vec<String>,
    latest_revision: u64,
    created_at: UnixMillis,
    updated_at: UnixMillis,
    is_retired: bool,
}

#[derive(Serialize)]
struct RetireRoleResponse {
    role_id: Uuid,
    is_retired: bool,
}

async fn role_items(
    store: &ApiStoreHandle,
    rows: Vec<philharmonic_store::EntityRow>,
    tenant: EntityId<crate::Tenant>,
) -> Result<Vec<(CursorKey, RoleResponse)>, ApiError> {
    let mut items = Vec::new();
    for row in rows {
        let role_id = row
            .identity
            .typed::<RoleDefinition>()
            .map_err(|error| ApiError::Internal(format!("invalid role identity: {error}")))?;
        let latest = latest_revision::<RoleDefinition>(store, role_id).await?;
        if required_entity_ref(&latest, "tenant")?.target_entity_id != tenant.internal().as_uuid() {
            continue;
        }
        items.push((
            CursorKey::new(row.created_at, row.identity.public),
            role_response(store, &row, &latest).await?,
        ));
    }
    Ok(items)
}

async fn role_response(
    store: &ApiStoreHandle,
    row: &philharmonic_store::EntityRow,
    latest: &philharmonic_store::RevisionRow,
) -> Result<RoleResponse, ApiError> {
    Ok(RoleResponse {
        role_id: row.identity.public,
        display_name: display_name(store, latest, "role").await?,
        permissions: permissions_from_revision(store, latest, "permissions").await?,
        latest_revision: latest.revision_seq,
        created_at: row.created_at,
        updated_at: latest.created_at,
        is_retired: bool_scalar(latest, "is_retired")?,
    })
}
