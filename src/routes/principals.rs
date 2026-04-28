//! Principal management routes.

use std::sync::Arc;

use axum::{
    Extension, Json, Router,
    extract::{Path, Query},
    http::StatusCode,
    middleware::from_fn,
    response::{IntoResponse, Response},
    routing::{MethodRouter, get, post},
};
use philharmonic_policy::{Principal, PrincipalKind, atom, generate_api_token};
use philharmonic_store::{EntityRefValue, EntityStoreExt, RevisionInput, StoreExt};
use philharmonic_types::{EntityId, JsonValue, ScalarValue, UnixMillis, Uuid};
use serde::{Deserialize, Serialize};

use crate::{
    ApiError, PaginatedResponse, PaginationParams, RequestContext, RequiredPermission,
    middleware::authz::authorize,
    pagination::CursorKey,
    routes::identity::{
        bool_scalar, dedupe_rows, display_name, ensure_revision_tenant, i64_scalar,
        latest_revision, next_revision_seq, optional_content_hash, paginate_items, put_json,
        put_token_hash, require_tenant_principal, required_content_hash, required_entity_ref,
        resolve_public_id, store_error,
    },
    store::{ApiStore, ApiStoreHandle},
};

/// Shared principal route state.
#[derive(Clone)]
pub(crate) struct PrincipalState {
    store: ApiStoreHandle,
}

impl PrincipalState {
    pub(crate) fn new(store: Arc<dyn ApiStore>) -> Self {
        Self {
            store: ApiStoreHandle::new(store),
        }
    }
}

/// Build principal-management routes.
pub fn router() -> Router {
    Router::new()
        .route(
            "/v1/principals",
            protected(post(create_principal), atom::TENANT_PRINCIPAL_MANAGE),
        )
        .route(
            "/v1/principals",
            protected(get(list_principals), atom::TENANT_PRINCIPAL_MANAGE),
        )
        .route(
            "/v1/principals/{id}/rotate",
            protected(post(rotate_principal), atom::TENANT_PRINCIPAL_MANAGE),
        )
        .route(
            "/v1/principals/{id}/retire",
            protected(post(retire_principal), atom::TENANT_PRINCIPAL_MANAGE),
        )
}

fn protected(route: MethodRouter, permission: &'static str) -> MethodRouter {
    route
        .route_layer(from_fn(authorize))
        .route_layer(Extension(RequiredPermission(permission)))
}

async fn create_principal(
    Extension(state): Extension<PrincipalState>,
    Extension(context): Extension<RequestContext>,
    Json(request): Json<CreatePrincipalRequest>,
) -> Result<Response, ApiError> {
    let tenant = require_tenant_principal(&context)?;
    let kind = parse_principal_kind(&request.kind)?;
    let principal_id = state
        .store
        .create_entity_minting::<Principal>()
        .await
        .map_err(store_error)?;
    let (token, token_hash) = generate_api_token();
    let credential_hash = put_token_hash(&state.store, token_hash).await?;
    let display_name_hash =
        put_json(&state.store, &JsonValue::String(request.display_name)).await?;

    let revision = RevisionInput::new()
        .with_content("credential_hash", credential_hash)
        .with_content("display_name", display_name_hash)
        .with_entity(
            "tenant",
            EntityRefValue::pinned(tenant.internal().as_uuid(), 0),
        )
        .with_scalar("kind", ScalarValue::I64(kind.as_i64()))
        .with_scalar("epoch", ScalarValue::I64(0))
        .with_scalar("is_retired", ScalarValue::Bool(false));

    state
        .store
        .append_revision_typed::<Principal>(principal_id, 0, &revision)
        .await
        .map_err(store_error)?;

    let response = (
        StatusCode::CREATED,
        Json(TokenPrincipalResponse {
            principal_id: principal_id.public().as_uuid(),
            token: token.as_str(),
        }),
    )
        .into_response();
    Ok(response)
}

async fn list_principals(
    Extension(state): Extension<PrincipalState>,
    Extension(context): Extension<RequestContext>,
    Query(params): Query<PaginationParams>,
) -> Result<Json<PaginatedResponse<PrincipalSummaryResponse>>, ApiError> {
    let tenant = require_tenant_principal(&context)?;
    let mut rows = Vec::new();
    rows.extend(
        state
            .store
            .find_by_scalar_typed::<Principal>("is_retired", &ScalarValue::Bool(false))
            .await
            .map_err(store_error)?,
    );
    rows.extend(
        state
            .store
            .find_by_scalar_typed::<Principal>("is_retired", &ScalarValue::Bool(true))
            .await
            .map_err(store_error)?,
    );
    dedupe_rows(&mut rows);

    let items = principal_items(&state.store, rows, tenant).await?;
    Ok(Json(paginate_items(items, &params)?))
}

async fn rotate_principal(
    Extension(state): Extension<PrincipalState>,
    Extension(context): Extension<RequestContext>,
    Path(id): Path<Uuid>,
) -> Result<Response, ApiError> {
    let tenant = require_tenant_principal(&context)?;
    let principal_id = resolve_public_id::<Principal>(&state.store, id).await?;
    let latest = latest_revision::<Principal>(&state.store, principal_id).await?;
    ensure_revision_tenant(&latest, tenant, "principal")?;
    if bool_scalar(&latest, "is_retired")? {
        return Err(ApiError::InvalidRequest("principal is retired".to_string()));
    }

    let (token, token_hash) = generate_api_token();
    let credential_hash = put_token_hash(&state.store, token_hash).await?;
    let next_revision_seq = next_revision_seq(&latest, "principal")?;
    let mut revision = RevisionInput::new()
        .with_content("credential_hash", credential_hash)
        .with_entity("tenant", required_entity_ref(&latest, "tenant")?)
        .with_scalar("kind", ScalarValue::I64(i64_scalar(&latest, "kind")?))
        .with_scalar("epoch", ScalarValue::I64(i64_scalar(&latest, "epoch")?))
        .with_scalar("is_retired", ScalarValue::Bool(false));
    if let Some(hash) = optional_content_hash(&latest, "display_name") {
        revision = revision.with_content("display_name", hash);
    }

    state
        .store
        .append_revision_typed::<Principal>(principal_id, next_revision_seq, &revision)
        .await
        .map_err(store_error)?;

    let response = Json(TokenPrincipalResponse {
        principal_id: id,
        token: token.as_str(),
    })
    .into_response();
    Ok(response)
}

async fn retire_principal(
    Extension(state): Extension<PrincipalState>,
    Extension(context): Extension<RequestContext>,
    Path(id): Path<Uuid>,
) -> Result<Json<RetirePrincipalResponse>, ApiError> {
    let tenant = require_tenant_principal(&context)?;
    let principal_id = resolve_public_id::<Principal>(&state.store, id).await?;
    let latest = latest_revision::<Principal>(&state.store, principal_id).await?;
    ensure_revision_tenant(&latest, tenant, "principal")?;
    if bool_scalar(&latest, "is_retired")? {
        return Err(ApiError::InvalidRequest("principal is retired".to_string()));
    }

    let next_revision_seq = next_revision_seq(&latest, "principal")?;
    let mut revision = RevisionInput::new()
        .with_content(
            "credential_hash",
            required_content_hash(&latest, "credential_hash")?,
        )
        .with_entity("tenant", required_entity_ref(&latest, "tenant")?)
        .with_scalar("kind", ScalarValue::I64(i64_scalar(&latest, "kind")?))
        .with_scalar("epoch", ScalarValue::I64(i64_scalar(&latest, "epoch")?))
        .with_scalar("is_retired", ScalarValue::Bool(true));
    if let Some(hash) = optional_content_hash(&latest, "display_name") {
        revision = revision.with_content("display_name", hash);
    }

    state
        .store
        .append_revision_typed::<Principal>(principal_id, next_revision_seq, &revision)
        .await
        .map_err(store_error)?;

    Ok(Json(RetirePrincipalResponse {
        principal_id: id,
        is_retired: true,
    }))
}

#[derive(Deserialize)]
struct CreatePrincipalRequest {
    display_name: String,
    kind: String,
}

#[derive(Serialize)]
struct TokenPrincipalResponse<'a> {
    principal_id: Uuid,
    token: &'a str,
}

#[derive(Serialize)]
struct PrincipalSummaryResponse {
    principal_id: Uuid,
    display_name: String,
    kind: &'static str,
    latest_revision: u64,
    created_at: UnixMillis,
    updated_at: UnixMillis,
    is_retired: bool,
}

#[derive(Serialize)]
struct RetirePrincipalResponse {
    principal_id: Uuid,
    is_retired: bool,
}

fn parse_principal_kind(value: &str) -> Result<PrincipalKind, ApiError> {
    match value {
        "user" => Ok(PrincipalKind::User),
        "service" => Ok(PrincipalKind::ServiceAccount),
        _ => Err(ApiError::InvalidRequest(
            "principal kind must be user or service".to_string(),
        )),
    }
}

fn principal_kind_name(value: i64) -> Result<&'static str, ApiError> {
    match PrincipalKind::try_from(value)
        .map_err(|_| ApiError::Internal(format!("invalid principal kind {value}")))?
    {
        PrincipalKind::User => Ok("user"),
        PrincipalKind::ServiceAccount => Ok("service"),
    }
}

async fn principal_items(
    store: &ApiStoreHandle,
    rows: Vec<philharmonic_store::EntityRow>,
    tenant: EntityId<crate::Tenant>,
) -> Result<Vec<(CursorKey, PrincipalSummaryResponse)>, ApiError> {
    let mut items = Vec::new();
    for row in rows {
        let principal_id = row
            .identity
            .typed::<Principal>()
            .map_err(|error| ApiError::Internal(format!("invalid principal identity: {error}")))?;
        let latest = latest_revision::<Principal>(store, principal_id).await?;
        if required_entity_ref(&latest, "tenant")?.target_entity_id != tenant.internal().as_uuid() {
            continue;
        }
        items.push((
            CursorKey::new(row.created_at, row.identity.public),
            PrincipalSummaryResponse {
                principal_id: row.identity.public,
                display_name: display_name(store, &latest, "principal").await?,
                kind: principal_kind_name(i64_scalar(&latest, "kind")?)?,
                latest_revision: latest.revision_seq,
                created_at: row.created_at,
                updated_at: latest.created_at,
                is_retired: bool_scalar(&latest, "is_retired")?,
            },
        ));
    }
    Ok(items)
}
