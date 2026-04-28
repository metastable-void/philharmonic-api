//! Endpoint-config management routes.

use std::{collections::HashSet, sync::Arc};

use axum::{
    Extension, Json, Router,
    extract::{Path, Query},
    http::StatusCode,
    middleware::from_fn,
    routing::{MethodRouter, get, post},
};
use philharmonic_policy::{Sck, TenantEndpointConfig, atom, sck_decrypt, sck_encrypt};
use philharmonic_store::{
    ContentStore, ContentStoreExt, EntityRefValue, EntityStoreExt, IdentityStore, RevisionInput,
    RevisionRow, StoreExt,
};
use philharmonic_types::{
    CanonicalJson, ContentHash, ContentValue, Entity, EntityId, JsonValue, ScalarValue, Sha256,
    UnixMillis, Uuid,
};
use serde::{Deserialize, Serialize};

use crate::{
    ApiError, AuthContext, PaginatedResponse, PaginationParams, RequestContext, RequestScope,
    RequiredPermission,
    middleware::authz::authorize,
    pagination::{CursorKey, PaginationError, decode_cursor, encode_cursor, page_size},
    store::{ApiStore, ApiStoreHandle},
};

/// Shared endpoint-config route state.
#[derive(Clone)]
pub(crate) struct EndpointState {
    store: ApiStoreHandle,
    sck: Option<Arc<Sck>>,
    key_version: i64,
}

impl EndpointState {
    pub(crate) fn new(store: Arc<dyn ApiStore>, sck: Option<Arc<Sck>>, key_version: i64) -> Self {
        Self {
            store: ApiStoreHandle::new(store),
            sck,
            key_version,
        }
    }
}

/// Build endpoint-config management routes.
pub fn router() -> Router {
    Router::new()
        .route(
            "/v1/endpoints",
            protected(post(create_endpoint), atom::ENDPOINT_CREATE),
        )
        .route(
            "/v1/endpoints",
            protected(get(list_endpoints), atom::ENDPOINT_READ_METADATA),
        )
        .route(
            "/v1/endpoints/{id}",
            protected(get(read_endpoint_metadata), atom::ENDPOINT_READ_METADATA),
        )
        .route(
            "/v1/endpoints/{id}/decrypted",
            protected(get(read_endpoint_decrypted), atom::ENDPOINT_READ_DECRYPTED),
        )
        .route(
            "/v1/endpoints/{id}/rotate",
            protected(post(rotate_endpoint), atom::ENDPOINT_ROTATE),
        )
        .route(
            "/v1/endpoints/{id}/retire",
            protected(post(retire_endpoint), atom::ENDPOINT_RETIRE),
        )
}

fn protected(route: MethodRouter, permission: &'static str) -> MethodRouter {
    route
        .route_layer(from_fn(authorize))
        .route_layer(Extension(RequiredPermission(permission)))
}

async fn create_endpoint(
    Extension(state): Extension<EndpointState>,
    Extension(context): Extension<RequestContext>,
    Json(request): Json<CreateEndpointRequest>,
) -> Result<(StatusCode, Json<CreateEndpointResponse>), ApiError> {
    let tenant = require_tenant_principal(&context)?;
    let sck = require_sck(&state)?;
    let endpoint_id = state
        .store
        .create_entity_minting::<TenantEndpointConfig>()
        .await
        .map_err(store_error)?;
    let encrypted_config_hash = encrypt_config(
        &state,
        sck,
        tenant,
        endpoint_id,
        &request.config,
        state.key_version,
    )
    .await?;
    let display_name_hash =
        put_json(&state.store, &JsonValue::String(request.display_name)).await?;

    let revision = RevisionInput::new()
        .with_content("display_name", display_name_hash)
        .with_content("encrypted_config", encrypted_config_hash)
        .with_entity(
            "tenant",
            EntityRefValue::pinned(tenant.internal().as_uuid(), 0),
        )
        .with_scalar("key_version", ScalarValue::I64(state.key_version))
        .with_scalar("is_retired", ScalarValue::Bool(false));

    state
        .store
        .append_revision_typed::<TenantEndpointConfig>(endpoint_id, 0, &revision)
        .await
        .map_err(store_error)?;

    Ok((
        StatusCode::CREATED,
        Json(CreateEndpointResponse {
            endpoint_id: endpoint_id.public().as_uuid(),
        }),
    ))
}

async fn list_endpoints(
    Extension(state): Extension<EndpointState>,
    Extension(context): Extension<RequestContext>,
    Query(params): Query<PaginationParams>,
) -> Result<Json<PaginatedResponse<EndpointMetadataResponse>>, ApiError> {
    require_sck(&state)?;
    let tenant = require_tenant_principal(&context)?;
    let mut rows = Vec::new();
    rows.extend(
        state
            .store
            .find_by_scalar_typed::<TenantEndpointConfig>("is_retired", &ScalarValue::Bool(false))
            .await
            .map_err(store_error)?,
    );
    rows.extend(
        state
            .store
            .find_by_scalar_typed::<TenantEndpointConfig>("is_retired", &ScalarValue::Bool(true))
            .await
            .map_err(store_error)?,
    );
    dedupe_rows(&mut rows);

    let items = endpoint_items(&state.store, rows, tenant).await?;
    Ok(Json(paginate_items(items, &params)?))
}

async fn read_endpoint_metadata(
    Extension(state): Extension<EndpointState>,
    Extension(context): Extension<RequestContext>,
    Path(id): Path<Uuid>,
) -> Result<Json<EndpointMetadataResponse>, ApiError> {
    require_sck(&state)?;
    let tenant = require_tenant_principal(&context)?;
    let endpoint_id = resolve_public_id::<TenantEndpointConfig>(&state.store, id).await?;
    let row = state
        .store
        .get_entity_typed::<TenantEndpointConfig>(endpoint_id)
        .await
        .map_err(store_error)?
        .ok_or_else(|| ApiError::NotFound("endpoint config not found".to_string()))?;
    let latest = latest_revision::<TenantEndpointConfig>(&state.store, endpoint_id).await?;
    ensure_revision_tenant(&latest, tenant, "endpoint config")?;
    Ok(Json(
        endpoint_metadata_response(&state.store, &row, &latest).await?,
    ))
}

async fn read_endpoint_decrypted(
    Extension(state): Extension<EndpointState>,
    Extension(context): Extension<RequestContext>,
    Path(id): Path<Uuid>,
) -> Result<Json<JsonValue>, ApiError> {
    let tenant = require_tenant_principal(&context)?;
    let sck = require_sck(&state)?;
    let endpoint_id = resolve_public_id::<TenantEndpointConfig>(&state.store, id).await?;
    let latest = latest_revision::<TenantEndpointConfig>(&state.store, endpoint_id).await?;
    ensure_revision_tenant(&latest, tenant, "endpoint config")?;
    let key_version = i64_scalar(&latest, "key_version")?;
    let encrypted_config = load_bytes(
        &state.store,
        required_content_hash(&latest, "encrypted_config")?,
        "encrypted endpoint config",
    )
    .await?;
    let plaintext = sck_decrypt(
        sck,
        encrypted_config.bytes(),
        tenant.internal().as_uuid(),
        endpoint_id.internal().as_uuid(),
        key_version,
    )
    .map_err(|_| ApiError::Internal("endpoint config decryption failed".to_string()))?;
    let config = serde_json::from_slice(plaintext.as_slice())
        .map_err(|_| ApiError::Internal("stored endpoint config is invalid JSON".to_string()))?;
    Ok(Json(config))
}

async fn rotate_endpoint(
    Extension(state): Extension<EndpointState>,
    Extension(context): Extension<RequestContext>,
    Path(id): Path<Uuid>,
    Json(request): Json<RotateEndpointRequest>,
) -> Result<Json<EndpointMetadataResponse>, ApiError> {
    let tenant = require_tenant_principal(&context)?;
    let sck = require_sck(&state)?;
    let endpoint_id = resolve_public_id::<TenantEndpointConfig>(&state.store, id).await?;
    let row = state
        .store
        .get_entity_typed::<TenantEndpointConfig>(endpoint_id)
        .await
        .map_err(store_error)?
        .ok_or_else(|| ApiError::NotFound("endpoint config not found".to_string()))?;
    let latest = latest_revision::<TenantEndpointConfig>(&state.store, endpoint_id).await?;
    ensure_revision_tenant(&latest, tenant, "endpoint config")?;
    if bool_scalar(&latest, "is_retired")? {
        return Err(ApiError::InvalidRequest(
            "endpoint config is retired".to_string(),
        ));
    }

    let encrypted_config_hash = encrypt_config(
        &state,
        sck,
        tenant,
        endpoint_id,
        &request.config,
        state.key_version,
    )
    .await?;
    let display_name_hash = match request.display_name {
        Some(display_name) => Some(put_json(&state.store, &JsonValue::String(display_name)).await?),
        None => optional_content_hash(&latest, "display_name"),
    };
    let next_revision_seq = latest
        .revision_seq
        .checked_add(1)
        .ok_or(ApiError::Internal(
            "endpoint config revision sequence overflow".to_string(),
        ))?;
    let tenant_ref = required_entity_ref(&latest, "tenant")?;

    let mut revision = RevisionInput::new()
        .with_content("encrypted_config", encrypted_config_hash)
        .with_entity("tenant", tenant_ref)
        .with_scalar("key_version", ScalarValue::I64(state.key_version))
        .with_scalar("is_retired", ScalarValue::Bool(false));
    if let Some(hash) = display_name_hash {
        revision = revision.with_content("display_name", hash);
    }

    state
        .store
        .append_revision_typed::<TenantEndpointConfig>(endpoint_id, next_revision_seq, &revision)
        .await
        .map_err(store_error)?;
    let updated = latest_revision::<TenantEndpointConfig>(&state.store, endpoint_id).await?;
    Ok(Json(
        endpoint_metadata_response(&state.store, &row, &updated).await?,
    ))
}

async fn retire_endpoint(
    Extension(state): Extension<EndpointState>,
    Extension(context): Extension<RequestContext>,
    Path(id): Path<Uuid>,
) -> Result<Json<RetireEndpointResponse>, ApiError> {
    require_sck(&state)?;
    let tenant = require_tenant_principal(&context)?;
    let endpoint_id = resolve_public_id::<TenantEndpointConfig>(&state.store, id).await?;
    let latest = latest_revision::<TenantEndpointConfig>(&state.store, endpoint_id).await?;
    ensure_revision_tenant(&latest, tenant, "endpoint config")?;
    let next_revision_seq = latest
        .revision_seq
        .checked_add(1)
        .ok_or(ApiError::Internal(
            "endpoint config revision sequence overflow".to_string(),
        ))?;
    let tenant_ref = required_entity_ref(&latest, "tenant")?;
    let mut revision = RevisionInput::new()
        .with_content(
            "encrypted_config",
            required_content_hash(&latest, "encrypted_config")?,
        )
        .with_entity("tenant", tenant_ref)
        .with_scalar(
            "key_version",
            ScalarValue::I64(i64_scalar(&latest, "key_version")?),
        )
        .with_scalar("is_retired", ScalarValue::Bool(true));
    if let Some(hash) = optional_content_hash(&latest, "display_name") {
        revision = revision.with_content("display_name", hash);
    }

    state
        .store
        .append_revision_typed::<TenantEndpointConfig>(endpoint_id, next_revision_seq, &revision)
        .await
        .map_err(store_error)?;

    Ok(Json(RetireEndpointResponse {
        endpoint_id: id,
        is_retired: true,
    }))
}

#[derive(Deserialize)]
struct CreateEndpointRequest {
    display_name: String,
    config: JsonValue,
}

#[derive(Serialize)]
struct CreateEndpointResponse {
    endpoint_id: Uuid,
}

#[derive(Deserialize)]
struct RotateEndpointRequest {
    display_name: Option<String>,
    config: JsonValue,
}

#[derive(Serialize)]
struct EndpointMetadataResponse {
    endpoint_id: Uuid,
    display_name: String,
    latest_revision: u64,
    created_at: UnixMillis,
    updated_at: UnixMillis,
    is_retired: bool,
    key_version: i64,
}

#[derive(Serialize)]
struct RetireEndpointResponse {
    endpoint_id: Uuid,
    is_retired: bool,
}

fn require_tenant_principal(context: &RequestContext) -> Result<EntityId<crate::Tenant>, ApiError> {
    let tenant = tenant_scope(context)?;
    match context.auth.as_ref() {
        Some(AuthContext::Principal { tenant_id, .. }) if *tenant_id == tenant => Ok(tenant),
        Some(AuthContext::Principal { .. }) => Err(ApiError::Forbidden),
        Some(AuthContext::Ephemeral { .. }) => Err(ApiError::Forbidden),
        None => Err(ApiError::Unauthenticated),
    }
}

fn tenant_scope(context: &RequestContext) -> Result<EntityId<crate::Tenant>, ApiError> {
    match context.scope {
        RequestScope::Tenant(tenant) => Ok(tenant),
        RequestScope::Operator => Err(ApiError::Forbidden),
    }
}

fn require_sck(state: &EndpointState) -> Result<&Sck, ApiError> {
    state
        .sck
        .as_deref()
        .ok_or_else(|| ApiError::Internal("SCK not configured".to_string()))
}

async fn resolve_public_id<T: Entity>(
    store: &ApiStoreHandle,
    public: Uuid,
) -> Result<EntityId<T>, ApiError> {
    let identity = store
        .resolve_public(public)
        .await
        .map_err(store_error)?
        .ok_or_else(|| ApiError::NotFound(format!("{} not found", T::NAME)))?;
    let typed = identity
        .typed::<T>()
        .map_err(|error| ApiError::Internal(format!("invalid {} identity: {error}", T::NAME)))?;
    let _ = store
        .get_entity_typed::<T>(typed)
        .await
        .map_err(store_error)?
        .ok_or_else(|| ApiError::NotFound(format!("{} not found", T::NAME)))?;
    Ok(typed)
}

async fn latest_revision<T: Entity>(
    store: &ApiStoreHandle,
    id: EntityId<T>,
) -> Result<RevisionRow, ApiError> {
    store
        .get_latest_revision_typed::<T>(id)
        .await
        .map_err(store_error)?
        .ok_or_else(|| ApiError::NotFound(format!("{} revision not found", T::NAME)))
}

fn ensure_revision_tenant(
    revision: &RevisionRow,
    tenant: EntityId<crate::Tenant>,
    entity_name: &'static str,
) -> Result<(), ApiError> {
    let tenant_ref = required_entity_ref(revision, "tenant")?;
    if tenant_ref.target_entity_id == tenant.internal().as_uuid() {
        Ok(())
    } else {
        Err(ApiError::NotFound(format!("{entity_name} not found")))
    }
}

async fn encrypt_config(
    state: &EndpointState,
    sck: &Sck,
    tenant: EntityId<crate::Tenant>,
    endpoint_id: EntityId<TenantEndpointConfig>,
    config: &JsonValue,
    key_version: i64,
) -> Result<Sha256, ApiError> {
    let canonical = CanonicalJson::from_value(config)
        .map_err(|error| ApiError::InvalidRequest(format!("invalid config JSON: {error}")))?;
    let wire = sck_encrypt(
        sck,
        canonical.as_bytes(),
        tenant.internal().as_uuid(),
        endpoint_id.internal().as_uuid(),
        key_version,
    )
    .map_err(|_| ApiError::Internal("endpoint config encryption failed".to_string()))?;
    put_bytes(&state.store, &wire).await
}

async fn put_bytes(store: &ApiStoreHandle, bytes: &[u8]) -> Result<Sha256, ApiError> {
    let content = ContentValue::new(bytes.to_vec());
    let hash = content.digest();
    store.put(&content).await.map_err(store_error)?;
    Ok(hash)
}

async fn put_json(store: &ApiStoreHandle, value: &JsonValue) -> Result<Sha256, ApiError> {
    let canonical = CanonicalJson::from_value(value)
        .map_err(|error| ApiError::InvalidRequest(format!("invalid JSON: {error}")))?;
    let hash = store.put_typed(&canonical).await.map_err(store_error)?;
    Ok(hash.as_digest())
}

async fn load_json(store: &ApiStoreHandle, hash: Sha256) -> Result<JsonValue, ApiError> {
    let typed_hash = ContentHash::<CanonicalJson>::from_digest_unchecked(hash);
    let canonical = store
        .get_typed::<CanonicalJson>(typed_hash)
        .await
        .map_err(store_error)?
        .ok_or_else(|| ApiError::Internal("missing JSON content blob".to_string()))?;
    canonical
        .to_deserializable()
        .map_err(|error| ApiError::Internal(format!("invalid stored JSON: {error}")))
}

async fn load_bytes(
    store: &ApiStoreHandle,
    hash: Sha256,
    label: &'static str,
) -> Result<ContentValue, ApiError> {
    store
        .get(hash)
        .await
        .map_err(store_error)?
        .ok_or_else(|| ApiError::Internal(format!("missing {label} content blob")))
}

fn required_content_hash(revision: &RevisionRow, attr: &'static str) -> Result<Sha256, ApiError> {
    revision
        .content_attrs
        .get(attr)
        .copied()
        .ok_or_else(|| ApiError::Internal(format!("missing content attribute {attr}")))
}

fn optional_content_hash(revision: &RevisionRow, attr: &'static str) -> Option<Sha256> {
    revision.content_attrs.get(attr).copied()
}

fn required_entity_ref(
    revision: &RevisionRow,
    attr: &'static str,
) -> Result<EntityRefValue, ApiError> {
    revision
        .entity_attrs
        .get(attr)
        .copied()
        .ok_or_else(|| ApiError::Internal(format!("missing entity attribute {attr}")))
}

fn bool_scalar(revision: &RevisionRow, attr: &'static str) -> Result<bool, ApiError> {
    match revision.scalar_attrs.get(attr) {
        Some(ScalarValue::Bool(value)) => Ok(*value),
        Some(ScalarValue::I64(_)) => Err(ApiError::Internal(format!(
            "invalid scalar type for {attr}: expected bool"
        ))),
        None => Err(ApiError::Internal(format!(
            "missing scalar attribute {attr}"
        ))),
    }
}

fn i64_scalar(revision: &RevisionRow, attr: &'static str) -> Result<i64, ApiError> {
    match revision.scalar_attrs.get(attr) {
        Some(ScalarValue::I64(value)) => Ok(*value),
        Some(ScalarValue::Bool(_)) => Err(ApiError::Internal(format!(
            "invalid scalar type for {attr}: expected i64"
        ))),
        None => Err(ApiError::Internal(format!(
            "missing scalar attribute {attr}"
        ))),
    }
}

async fn endpoint_items(
    store: &ApiStoreHandle,
    rows: Vec<philharmonic_store::EntityRow>,
    tenant: EntityId<crate::Tenant>,
) -> Result<Vec<(CursorKey, EndpointMetadataResponse)>, ApiError> {
    let mut items = Vec::new();
    for row in rows {
        let endpoint_id = row
            .identity
            .typed::<TenantEndpointConfig>()
            .map_err(|error| {
                ApiError::Internal(format!("invalid endpoint config identity: {error}"))
            })?;
        let latest = latest_revision::<TenantEndpointConfig>(store, endpoint_id).await?;
        if required_entity_ref(&latest, "tenant")?.target_entity_id != tenant.internal().as_uuid() {
            continue;
        }
        items.push((
            CursorKey::new(row.created_at, row.identity.public),
            endpoint_metadata_response(store, &row, &latest).await?,
        ));
    }
    Ok(items)
}

async fn endpoint_metadata_response(
    store: &ApiStoreHandle,
    row: &philharmonic_store::EntityRow,
    latest: &RevisionRow,
) -> Result<EndpointMetadataResponse, ApiError> {
    Ok(EndpointMetadataResponse {
        endpoint_id: row.identity.public,
        display_name: display_name(store, latest).await?,
        latest_revision: latest.revision_seq,
        created_at: row.created_at,
        updated_at: latest.created_at,
        is_retired: bool_scalar(latest, "is_retired")?,
        key_version: i64_scalar(latest, "key_version")?,
    })
}

async fn display_name(store: &ApiStoreHandle, revision: &RevisionRow) -> Result<String, ApiError> {
    match load_json(store, required_content_hash(revision, "display_name")?).await? {
        JsonValue::String(value) => Ok(value),
        _ => Err(ApiError::Internal(
            "invalid stored endpoint display name".to_string(),
        )),
    }
}

fn paginate_items<T>(
    mut items: Vec<(CursorKey, T)>,
    params: &PaginationParams,
) -> Result<PaginatedResponse<T>, ApiError> {
    let cursor = decode_cursor(params.cursor.as_deref()).map_err(pagination_error)?;
    items.sort_by_key(|(key, _)| (key.created_at, key.id.as_u128()));
    if let Some(cursor) = cursor {
        items.retain(|(key, _)| cursor_after(*key, cursor));
    }

    let limit = page_size(params.limit).map_err(pagination_error)?;
    let overfetch = limit
        .checked_add(1)
        .ok_or(ApiError::Internal("pagination limit overflow".to_string()))?;
    let mut page = items.into_iter().take(overfetch).collect::<Vec<_>>();
    let next_cursor = if page.len() > limit {
        page.truncate(limit);
        page.last()
            .map(|(key, _)| encode_cursor(*key))
            .transpose()
            .map_err(pagination_error)?
    } else {
        None
    };

    Ok(PaginatedResponse {
        items: page.into_iter().map(|(_, item)| item).collect(),
        next_cursor,
    })
}

fn cursor_after(key: CursorKey, cursor: CursorKey) -> bool {
    (key.created_at, key.id.as_u128()) > (cursor.created_at, cursor.id.as_u128())
}

fn dedupe_rows(rows: &mut Vec<philharmonic_store::EntityRow>) {
    let mut seen = HashSet::new();
    rows.retain(|row| seen.insert(row.identity.internal));
}

fn pagination_error(error: PaginationError) -> ApiError {
    match error {
        PaginationError::InvalidCursor => ApiError::InvalidRequest(error.to_string()),
        PaginationError::LimitConversion => ApiError::Internal(error.to_string()),
    }
}

fn store_error(error: philharmonic_store::StoreError) -> ApiError {
    ApiError::Internal(error.to_string())
}
