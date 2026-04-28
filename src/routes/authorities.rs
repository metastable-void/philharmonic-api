//! Minting-authority management routes.

use std::sync::Arc;

use axum::{
    Extension, Json, Router,
    extract::{Path, Query},
    http::StatusCode,
    middleware::from_fn,
    response::{IntoResponse, Response},
    routing::{MethodRouter, get, patch, post},
};
use philharmonic_policy::{MintingAuthority, atom, generate_api_token};
use philharmonic_store::{EntityRefValue, EntityStoreExt, RevisionInput, StoreExt};
use philharmonic_types::{EntityId, JsonValue, ScalarValue, UnixMillis, Uuid};
use serde::{Deserialize, Serialize};

use crate::{
    ApiError, PaginatedResponse, PaginationParams, RequestContext, RequiredPermission,
    middleware::authz::authorize,
    pagination::CursorKey,
    routes::identity::{
        bool_scalar, dedupe_rows, display_name, ensure_revision_tenant, i64_scalar,
        latest_revision, next_revision_seq, paginate_items, permission_array_json,
        permissions_from_revision, put_json, put_token_hash, require_tenant_principal,
        required_content_hash, required_entity_ref, resolve_public_id, store_error,
    },
    store::{ApiStore, ApiStoreHandle},
};

/// Shared minting-authority route state.
#[derive(Clone)]
pub(crate) struct AuthorityState {
    store: ApiStoreHandle,
}

impl AuthorityState {
    pub(crate) fn new(store: Arc<dyn ApiStore>) -> Self {
        Self {
            store: ApiStoreHandle::new(store),
        }
    }
}

/// Build minting-authority management routes.
pub fn router() -> Router {
    Router::new()
        .route(
            "/v1/minting-authorities",
            protected(post(create_authority), atom::TENANT_MINTING_MANAGE),
        )
        .route(
            "/v1/minting-authorities",
            protected(get(list_authorities), atom::TENANT_MINTING_MANAGE),
        )
        .route(
            "/v1/minting-authorities/{id}",
            protected(patch(update_authority), atom::TENANT_MINTING_MANAGE),
        )
        .route(
            "/v1/minting-authorities/{id}/rotate",
            protected(post(rotate_authority), atom::TENANT_MINTING_MANAGE),
        )
        .route(
            "/v1/minting-authorities/{id}/bump-epoch",
            protected(post(bump_authority_epoch), atom::TENANT_MINTING_MANAGE),
        )
        .route(
            "/v1/minting-authorities/{id}/retire",
            protected(post(retire_authority), atom::TENANT_MINTING_MANAGE),
        )
}

fn protected(route: MethodRouter, permission: &'static str) -> MethodRouter {
    route
        .route_layer(from_fn(authorize))
        .route_layer(Extension(RequiredPermission(permission)))
}

async fn create_authority(
    Extension(state): Extension<AuthorityState>,
    Extension(context): Extension<RequestContext>,
    Json(request): Json<CreateAuthorityRequest>,
) -> Result<Response, ApiError> {
    let tenant = require_tenant_principal(&context)?;
    let permission_envelope = permission_array_json(request.permission_envelope)?;
    let constraints = constraints_json(request.max_lifetime_seconds);
    let authority_id = state
        .store
        .create_entity_minting::<MintingAuthority>()
        .await
        .map_err(store_error)?;
    let (token, token_hash) = generate_api_token();
    let credential_hash = put_token_hash(&state.store, token_hash).await?;
    let display_name_hash =
        put_json(&state.store, &JsonValue::String(request.display_name)).await?;
    let permission_envelope_hash = put_json(&state.store, &permission_envelope).await?;
    let constraints_hash = put_json(&state.store, &constraints).await?;

    let revision = RevisionInput::new()
        .with_content("credential_hash", credential_hash)
        .with_content("display_name", display_name_hash)
        .with_content("permission_envelope", permission_envelope_hash)
        .with_content("minting_constraints", constraints_hash)
        .with_entity(
            "tenant",
            EntityRefValue::pinned(tenant.internal().as_uuid(), 0),
        )
        .with_scalar("epoch", ScalarValue::I64(0))
        .with_scalar("is_retired", ScalarValue::Bool(false));

    state
        .store
        .append_revision_typed::<MintingAuthority>(authority_id, 0, &revision)
        .await
        .map_err(store_error)?;

    let response = (
        StatusCode::CREATED,
        Json(TokenAuthorityResponse {
            authority_id: authority_id.public().as_uuid(),
            token: token.as_str(),
        }),
    )
        .into_response();
    Ok(response)
}

async fn list_authorities(
    Extension(state): Extension<AuthorityState>,
    Extension(context): Extension<RequestContext>,
    Query(params): Query<PaginationParams>,
) -> Result<Json<PaginatedResponse<AuthorityResponse>>, ApiError> {
    let tenant = require_tenant_principal(&context)?;
    let mut rows = Vec::new();
    rows.extend(
        state
            .store
            .find_by_scalar_typed::<MintingAuthority>("is_retired", &ScalarValue::Bool(false))
            .await
            .map_err(store_error)?,
    );
    rows.extend(
        state
            .store
            .find_by_scalar_typed::<MintingAuthority>("is_retired", &ScalarValue::Bool(true))
            .await
            .map_err(store_error)?,
    );
    dedupe_rows(&mut rows);

    let items = authority_items(&state.store, rows, tenant).await?;
    Ok(Json(paginate_items(items, &params)?))
}

async fn update_authority(
    Extension(state): Extension<AuthorityState>,
    Extension(context): Extension<RequestContext>,
    Path(id): Path<Uuid>,
    Json(request): Json<UpdateAuthorityRequest>,
) -> Result<Json<AuthorityResponse>, ApiError> {
    let tenant = require_tenant_principal(&context)?;
    if request.display_name.is_none()
        && request.permission_envelope.is_none()
        && request.max_lifetime_seconds.is_none()
    {
        return Err(ApiError::InvalidRequest(
            "minting authority update must change at least one field".to_string(),
        ));
    }

    let authority_id = resolve_public_id::<MintingAuthority>(&state.store, id).await?;
    let row = state
        .store
        .get_entity_typed::<MintingAuthority>(authority_id)
        .await
        .map_err(store_error)?
        .ok_or_else(|| ApiError::NotFound("minting authority not found".to_string()))?;
    let latest = latest_revision::<MintingAuthority>(&state.store, authority_id).await?;
    ensure_revision_tenant(&latest, tenant, "minting authority")?;
    if bool_scalar(&latest, "is_retired")? {
        return Err(ApiError::InvalidRequest(
            "minting authority is retired".to_string(),
        ));
    }

    let display_name_hash = match request.display_name {
        Some(display_name) => put_json(&state.store, &JsonValue::String(display_name)).await?,
        None => required_content_hash(&latest, "display_name")?,
    };
    let permission_envelope_hash = match request.permission_envelope {
        Some(permission_envelope) => {
            let permission_envelope = permission_array_json(permission_envelope)?;
            put_json(&state.store, &permission_envelope).await?
        }
        None => required_content_hash(&latest, "permission_envelope")?,
    };
    let constraints_hash = match request.max_lifetime_seconds {
        Some(max_lifetime_seconds) => {
            put_json(&state.store, &constraints_json(max_lifetime_seconds)).await?
        }
        None => required_content_hash(&latest, "minting_constraints")?,
    };
    let next_revision_seq = next_revision_seq(&latest, "minting authority")?;
    let revision = RevisionInput::new()
        .with_content(
            "credential_hash",
            required_content_hash(&latest, "credential_hash")?,
        )
        .with_content("display_name", display_name_hash)
        .with_content("permission_envelope", permission_envelope_hash)
        .with_content("minting_constraints", constraints_hash)
        .with_entity("tenant", required_entity_ref(&latest, "tenant")?)
        .with_scalar("epoch", ScalarValue::I64(i64_scalar(&latest, "epoch")?))
        .with_scalar("is_retired", ScalarValue::Bool(false));

    state
        .store
        .append_revision_typed::<MintingAuthority>(authority_id, next_revision_seq, &revision)
        .await
        .map_err(store_error)?;
    let updated = latest_revision::<MintingAuthority>(&state.store, authority_id).await?;
    Ok(Json(
        authority_response(&state.store, &row, &updated).await?,
    ))
}

async fn rotate_authority(
    Extension(state): Extension<AuthorityState>,
    Extension(context): Extension<RequestContext>,
    Path(id): Path<Uuid>,
) -> Result<Response, ApiError> {
    let tenant = require_tenant_principal(&context)?;
    let authority_id = resolve_public_id::<MintingAuthority>(&state.store, id).await?;
    let latest = latest_revision::<MintingAuthority>(&state.store, authority_id).await?;
    ensure_revision_tenant(&latest, tenant, "minting authority")?;
    if bool_scalar(&latest, "is_retired")? {
        return Err(ApiError::InvalidRequest(
            "minting authority is retired".to_string(),
        ));
    }

    let (token, token_hash) = generate_api_token();
    let credential_hash = put_token_hash(&state.store, token_hash).await?;
    let next_revision_seq = next_revision_seq(&latest, "minting authority")?;
    let revision = RevisionInput::new()
        .with_content("credential_hash", credential_hash)
        .with_content(
            "display_name",
            required_content_hash(&latest, "display_name")?,
        )
        .with_content(
            "permission_envelope",
            required_content_hash(&latest, "permission_envelope")?,
        )
        .with_content(
            "minting_constraints",
            required_content_hash(&latest, "minting_constraints")?,
        )
        .with_entity("tenant", required_entity_ref(&latest, "tenant")?)
        .with_scalar("epoch", ScalarValue::I64(i64_scalar(&latest, "epoch")?))
        .with_scalar("is_retired", ScalarValue::Bool(false));

    state
        .store
        .append_revision_typed::<MintingAuthority>(authority_id, next_revision_seq, &revision)
        .await
        .map_err(store_error)?;

    let response = Json(TokenAuthorityResponse {
        authority_id: id,
        token: token.as_str(),
    })
    .into_response();
    Ok(response)
}

async fn bump_authority_epoch(
    Extension(state): Extension<AuthorityState>,
    Extension(context): Extension<RequestContext>,
    Path(id): Path<Uuid>,
) -> Result<Json<BumpAuthorityEpochResponse>, ApiError> {
    let tenant = require_tenant_principal(&context)?;
    let authority_id = resolve_public_id::<MintingAuthority>(&state.store, id).await?;
    let latest = latest_revision::<MintingAuthority>(&state.store, authority_id).await?;
    ensure_revision_tenant(&latest, tenant, "minting authority")?;
    if bool_scalar(&latest, "is_retired")? {
        return Err(ApiError::InvalidRequest(
            "minting authority is retired".to_string(),
        ));
    }

    let epoch = i64_scalar(&latest, "epoch")?
        .checked_add(1)
        .ok_or_else(|| ApiError::Internal("minting authority epoch overflow".to_string()))?;
    let next_revision_seq = next_revision_seq(&latest, "minting authority")?;
    let revision = RevisionInput::new()
        .with_content(
            "credential_hash",
            required_content_hash(&latest, "credential_hash")?,
        )
        .with_content(
            "display_name",
            required_content_hash(&latest, "display_name")?,
        )
        .with_content(
            "permission_envelope",
            required_content_hash(&latest, "permission_envelope")?,
        )
        .with_content(
            "minting_constraints",
            required_content_hash(&latest, "minting_constraints")?,
        )
        .with_entity("tenant", required_entity_ref(&latest, "tenant")?)
        .with_scalar("epoch", ScalarValue::I64(epoch))
        .with_scalar("is_retired", ScalarValue::Bool(false));

    state
        .store
        .append_revision_typed::<MintingAuthority>(authority_id, next_revision_seq, &revision)
        .await
        .map_err(store_error)?;

    Ok(Json(BumpAuthorityEpochResponse {
        authority_id: id,
        epoch,
    }))
}

async fn retire_authority(
    Extension(state): Extension<AuthorityState>,
    Extension(context): Extension<RequestContext>,
    Path(id): Path<Uuid>,
) -> Result<Json<RetireAuthorityResponse>, ApiError> {
    let tenant = require_tenant_principal(&context)?;
    let authority_id = resolve_public_id::<MintingAuthority>(&state.store, id).await?;
    let latest = latest_revision::<MintingAuthority>(&state.store, authority_id).await?;
    ensure_revision_tenant(&latest, tenant, "minting authority")?;
    if bool_scalar(&latest, "is_retired")? {
        return Err(ApiError::InvalidRequest(
            "minting authority is retired".to_string(),
        ));
    }

    let next_revision_seq = next_revision_seq(&latest, "minting authority")?;
    let revision = RevisionInput::new()
        .with_content(
            "credential_hash",
            required_content_hash(&latest, "credential_hash")?,
        )
        .with_content(
            "display_name",
            required_content_hash(&latest, "display_name")?,
        )
        .with_content(
            "permission_envelope",
            required_content_hash(&latest, "permission_envelope")?,
        )
        .with_content(
            "minting_constraints",
            required_content_hash(&latest, "minting_constraints")?,
        )
        .with_entity("tenant", required_entity_ref(&latest, "tenant")?)
        .with_scalar("epoch", ScalarValue::I64(i64_scalar(&latest, "epoch")?))
        .with_scalar("is_retired", ScalarValue::Bool(true));

    state
        .store
        .append_revision_typed::<MintingAuthority>(authority_id, next_revision_seq, &revision)
        .await
        .map_err(store_error)?;

    Ok(Json(RetireAuthorityResponse {
        authority_id: id,
        is_retired: true,
    }))
}

#[derive(Deserialize)]
struct CreateAuthorityRequest {
    display_name: String,
    permission_envelope: Vec<String>,
    max_lifetime_seconds: u64,
}

#[derive(Deserialize)]
struct UpdateAuthorityRequest {
    display_name: Option<String>,
    permission_envelope: Option<Vec<String>>,
    max_lifetime_seconds: Option<u64>,
}

#[derive(Serialize)]
struct TokenAuthorityResponse<'a> {
    authority_id: Uuid,
    token: &'a str,
}

#[derive(Serialize)]
struct AuthorityResponse {
    authority_id: Uuid,
    display_name: String,
    permission_envelope: Vec<String>,
    max_lifetime_seconds: u64,
    epoch: i64,
    latest_revision: u64,
    created_at: UnixMillis,
    updated_at: UnixMillis,
    is_retired: bool,
}

#[derive(Serialize)]
struct BumpAuthorityEpochResponse {
    authority_id: Uuid,
    epoch: i64,
}

#[derive(Serialize)]
struct RetireAuthorityResponse {
    authority_id: Uuid,
    is_retired: bool,
}

fn constraints_json(max_lifetime_seconds: u64) -> JsonValue {
    JsonValue::Object(serde_json::Map::from_iter([(
        "max_lifetime_seconds".to_string(),
        JsonValue::Number(serde_json::Number::from(max_lifetime_seconds)),
    )]))
}

async fn authority_items(
    store: &ApiStoreHandle,
    rows: Vec<philharmonic_store::EntityRow>,
    tenant: EntityId<crate::Tenant>,
) -> Result<Vec<(CursorKey, AuthorityResponse)>, ApiError> {
    let mut items = Vec::new();
    for row in rows {
        let authority_id = row
            .identity
            .typed::<MintingAuthority>()
            .map_err(|error| ApiError::Internal(format!("invalid authority identity: {error}")))?;
        let latest = latest_revision::<MintingAuthority>(store, authority_id).await?;
        if required_entity_ref(&latest, "tenant")?.target_entity_id != tenant.internal().as_uuid() {
            continue;
        }
        items.push((
            CursorKey::new(row.created_at, row.identity.public),
            authority_response(store, &row, &latest).await?,
        ));
    }
    Ok(items)
}

async fn authority_response(
    store: &ApiStoreHandle,
    row: &philharmonic_store::EntityRow,
    latest: &philharmonic_store::RevisionRow,
) -> Result<AuthorityResponse, ApiError> {
    Ok(AuthorityResponse {
        authority_id: row.identity.public,
        display_name: display_name(store, latest, "minting authority").await?,
        permission_envelope: permissions_from_revision(store, latest, "permission_envelope")
            .await?,
        max_lifetime_seconds: max_lifetime_seconds(store, latest).await?,
        epoch: i64_scalar(latest, "epoch")?,
        latest_revision: latest.revision_seq,
        created_at: row.created_at,
        updated_at: latest.created_at,
        is_retired: bool_scalar(latest, "is_retired")?,
    })
}

async fn max_lifetime_seconds(
    store: &ApiStoreHandle,
    latest: &philharmonic_store::RevisionRow,
) -> Result<u64, ApiError> {
    let constraints = crate::routes::identity::load_json(
        store,
        required_content_hash(latest, "minting_constraints")?,
    )
    .await?;
    constraints
        .get("max_lifetime_seconds")
        .and_then(JsonValue::as_u64)
        .ok_or_else(|| {
            ApiError::Internal(
                "invalid stored minting constraints max_lifetime_seconds".to_string(),
            )
        })
}
