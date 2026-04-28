//! Role-membership management routes.

use std::sync::Arc;

use axum::{
    Extension, Json, Router,
    extract::{Path, Query},
    http::StatusCode,
    middleware::from_fn,
    routing::{MethodRouter, delete, get, post},
};
use philharmonic_policy::{Principal, RoleDefinition, RoleMembership, atom};
use philharmonic_store::{EntityRefValue, EntityStoreExt, RevisionInput, StoreExt};
use philharmonic_types::{EntityId, ScalarValue, UnixMillis, Uuid};
use serde::{Deserialize, Serialize};

use crate::{
    ApiError, PaginatedResponse, PaginationParams, RequestContext, RequiredPermission,
    middleware::authz::authorize,
    pagination::CursorKey,
    routes::identity::{
        bool_scalar, dedupe_rows, ensure_revision_tenant, latest_revision, next_revision_seq,
        paginate_items, public_for_internal, require_tenant_principal, required_entity_ref,
        resolve_public_id, store_error,
    },
    store::{ApiStore, ApiStoreHandle},
};

/// Shared role-membership route state.
#[derive(Clone)]
pub(crate) struct MembershipState {
    store: ApiStoreHandle,
}

impl MembershipState {
    pub(crate) fn new(store: Arc<dyn ApiStore>) -> Self {
        Self {
            store: ApiStoreHandle::new(store),
        }
    }
}

/// Build role-membership management routes.
pub fn router() -> Router {
    Router::new()
        .route(
            "/v1/role-memberships",
            protected(post(create_membership), atom::TENANT_ROLE_MANAGE),
        )
        .route(
            "/v1/role-memberships",
            protected(get(list_memberships), atom::TENANT_ROLE_MANAGE),
        )
        .route(
            "/v1/role-memberships/{id}",
            protected(delete(retire_membership), atom::TENANT_ROLE_MANAGE),
        )
}

fn protected(route: MethodRouter, permission: &'static str) -> MethodRouter {
    route
        .route_layer(from_fn(authorize))
        .route_layer(Extension(RequiredPermission(permission)))
}

async fn create_membership(
    Extension(state): Extension<MembershipState>,
    Extension(context): Extension<RequestContext>,
    Json(request): Json<CreateMembershipRequest>,
) -> Result<(StatusCode, Json<CreateMembershipResponse>), ApiError> {
    let tenant = require_tenant_principal(&context)?;
    let principal_id = resolve_public_id::<Principal>(&state.store, request.principal_id).await?;
    let principal_latest = latest_revision::<Principal>(&state.store, principal_id).await?;
    ensure_revision_tenant(&principal_latest, tenant, "principal")?;
    if bool_scalar(&principal_latest, "is_retired")? {
        return Err(ApiError::InvalidRequest("principal is retired".to_string()));
    }

    let role_id = resolve_public_id::<RoleDefinition>(&state.store, request.role_id).await?;
    let role_latest = latest_revision::<RoleDefinition>(&state.store, role_id).await?;
    ensure_revision_tenant(&role_latest, tenant, "role definition")?;
    if bool_scalar(&role_latest, "is_retired")? {
        return Err(ApiError::InvalidRequest(
            "role definition is retired".to_string(),
        ));
    }

    let membership_id = state
        .store
        .create_entity_minting::<RoleMembership>()
        .await
        .map_err(store_error)?;
    let revision = RevisionInput::new()
        .with_entity(
            "tenant",
            EntityRefValue::pinned(tenant.internal().as_uuid(), 0),
        )
        .with_entity(
            "principal",
            EntityRefValue::pinned(principal_id.internal().as_uuid(), 0),
        )
        .with_entity(
            "role",
            EntityRefValue::pinned(role_id.internal().as_uuid(), 0),
        )
        .with_scalar("is_retired", ScalarValue::Bool(false));

    state
        .store
        .append_revision_typed::<RoleMembership>(membership_id, 0, &revision)
        .await
        .map_err(store_error)?;

    Ok((
        StatusCode::CREATED,
        Json(CreateMembershipResponse {
            membership_id: membership_id.public().as_uuid(),
        }),
    ))
}

async fn list_memberships(
    Extension(state): Extension<MembershipState>,
    Extension(context): Extension<RequestContext>,
    Query(params): Query<PaginationParams>,
) -> Result<Json<PaginatedResponse<MembershipResponse>>, ApiError> {
    let tenant = require_tenant_principal(&context)?;
    let mut rows = Vec::new();
    rows.extend(
        state
            .store
            .find_by_scalar_typed::<RoleMembership>("is_retired", &ScalarValue::Bool(false))
            .await
            .map_err(store_error)?,
    );
    rows.extend(
        state
            .store
            .find_by_scalar_typed::<RoleMembership>("is_retired", &ScalarValue::Bool(true))
            .await
            .map_err(store_error)?,
    );
    dedupe_rows(&mut rows);

    let items = membership_items(&state.store, rows, tenant).await?;
    Ok(Json(paginate_items(items, &params)?))
}

async fn retire_membership(
    Extension(state): Extension<MembershipState>,
    Extension(context): Extension<RequestContext>,
    Path(id): Path<Uuid>,
) -> Result<Json<RetireMembershipResponse>, ApiError> {
    let tenant = require_tenant_principal(&context)?;
    let membership_id = resolve_public_id::<RoleMembership>(&state.store, id).await?;
    let latest = latest_revision::<RoleMembership>(&state.store, membership_id).await?;
    ensure_revision_tenant(&latest, tenant, "role membership")?;
    if bool_scalar(&latest, "is_retired")? {
        return Err(ApiError::InvalidRequest(
            "role membership is retired".to_string(),
        ));
    }

    let next_revision_seq = next_revision_seq(&latest, "role membership")?;
    let revision = RevisionInput::new()
        .with_entity("tenant", required_entity_ref(&latest, "tenant")?)
        .with_entity("principal", required_entity_ref(&latest, "principal")?)
        .with_entity("role", required_entity_ref(&latest, "role")?)
        .with_scalar("is_retired", ScalarValue::Bool(true));

    state
        .store
        .append_revision_typed::<RoleMembership>(membership_id, next_revision_seq, &revision)
        .await
        .map_err(store_error)?;

    Ok(Json(RetireMembershipResponse {
        membership_id: id,
        is_retired: true,
    }))
}

#[derive(Deserialize)]
struct CreateMembershipRequest {
    principal_id: Uuid,
    role_id: Uuid,
}

#[derive(Serialize)]
struct CreateMembershipResponse {
    membership_id: Uuid,
}

#[derive(Serialize)]
struct MembershipResponse {
    membership_id: Uuid,
    principal_id: Uuid,
    role_id: Uuid,
    latest_revision: u64,
    created_at: UnixMillis,
    updated_at: UnixMillis,
    is_retired: bool,
}

#[derive(Serialize)]
struct RetireMembershipResponse {
    membership_id: Uuid,
    is_retired: bool,
}

async fn membership_items(
    store: &ApiStoreHandle,
    rows: Vec<philharmonic_store::EntityRow>,
    tenant: EntityId<crate::Tenant>,
) -> Result<Vec<(CursorKey, MembershipResponse)>, ApiError> {
    let mut items = Vec::new();
    for row in rows {
        let membership_id = row
            .identity
            .typed::<RoleMembership>()
            .map_err(|error| ApiError::Internal(format!("invalid membership identity: {error}")))?;
        let latest = latest_revision::<RoleMembership>(store, membership_id).await?;
        if required_entity_ref(&latest, "tenant")?.target_entity_id != tenant.internal().as_uuid() {
            continue;
        }
        items.push((
            CursorKey::new(row.created_at, row.identity.public),
            membership_response(store, &row, &latest).await?,
        ));
    }
    Ok(items)
}

async fn membership_response(
    store: &ApiStoreHandle,
    row: &philharmonic_store::EntityRow,
    latest: &philharmonic_store::RevisionRow,
) -> Result<MembershipResponse, ApiError> {
    let principal_ref = required_entity_ref(latest, "principal")?;
    let role_ref = required_entity_ref(latest, "role")?;
    Ok(MembershipResponse {
        membership_id: row.identity.public,
        principal_id: public_for_internal::<Principal>(store, principal_ref.target_entity_id)
            .await?,
        role_id: public_for_internal::<RoleDefinition>(store, role_ref.target_entity_id).await?,
        latest_revision: latest.revision_seq,
        created_at: row.created_at,
        updated_at: latest.created_at,
        is_retired: bool_scalar(latest, "is_retired")?,
    })
}
