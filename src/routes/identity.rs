//! Shared helpers for tenant identity-management routes.

use std::collections::HashSet;

use philharmonic_policy::{ALL_ATOMS, PermissionDocument, TokenHash};
use philharmonic_store::{
    ContentStore, ContentStoreExt, EntityRefValue, EntityStoreExt, IdentityStore, RevisionRow,
};
use philharmonic_types::{
    CanonicalJson, ContentHash, ContentValue, Entity, EntityId, JsonValue, ScalarValue, Sha256,
    Uuid,
};

use crate::{
    ApiError, AuthContext, PaginatedResponse, PaginationParams, RequestContext, RequestScope,
    pagination::{CursorKey, PaginationError, decode_cursor, encode_cursor, page_size},
    store::ApiStoreHandle,
};

/// Require a tenant-scoped persistent principal for management routes.
pub(super) fn require_tenant_principal(
    context: &RequestContext,
) -> Result<EntityId<crate::Tenant>, ApiError> {
    let tenant = tenant_scope(context)?;
    match context.auth.as_ref() {
        Some(AuthContext::Principal { tenant_id, .. }) if *tenant_id == tenant => Ok(tenant),
        Some(AuthContext::Principal { .. }) => Err(ApiError::Forbidden),
        Some(AuthContext::Ephemeral { .. }) => Err(ApiError::Forbidden),
        None => Err(ApiError::Unauthenticated),
    }
}

/// Return the tenant request scope, rejecting operator-scoped calls.
pub(super) fn tenant_scope(context: &RequestContext) -> Result<EntityId<crate::Tenant>, ApiError> {
    match context.scope {
        RequestScope::Tenant(tenant) => Ok(tenant),
        RequestScope::Operator => Err(ApiError::Forbidden),
    }
}

/// Resolve a public UUID to a typed entity ID, hiding kind mismatches as 404.
pub(super) async fn resolve_public_id<T: Entity>(
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
        .map_err(|_| ApiError::NotFound(format!("{} not found", T::NAME)))?;
    let _ = store
        .get_entity_typed::<T>(typed)
        .await
        .map_err(store_error)?
        .ok_or_else(|| ApiError::NotFound(format!("{} not found", T::NAME)))?;
    Ok(typed)
}

/// Load the latest revision for a typed entity.
pub(super) async fn latest_revision<T: Entity>(
    store: &ApiStoreHandle,
    id: EntityId<T>,
) -> Result<RevisionRow, ApiError> {
    store
        .get_latest_revision_typed::<T>(id)
        .await
        .map_err(store_error)?
        .ok_or_else(|| ApiError::NotFound(format!("{} revision not found", T::NAME)))
}

/// Ensure a revision belongs to the request tenant.
pub(super) fn ensure_revision_tenant(
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

/// Return the next revision sequence, detecting overflow.
pub(super) fn next_revision_seq(
    revision: &RevisionRow,
    entity_name: &'static str,
) -> Result<u64, ApiError> {
    revision
        .revision_seq
        .checked_add(1)
        .ok_or_else(|| ApiError::Internal(format!("{entity_name} revision sequence overflow")))
}

/// Store canonical JSON and return its content digest.
pub(super) async fn put_json(
    store: &ApiStoreHandle,
    value: &JsonValue,
) -> Result<Sha256, ApiError> {
    let canonical = CanonicalJson::from_value(value)
        .map_err(|error| ApiError::InvalidRequest(format!("invalid JSON: {error}")))?;
    let hash = store.put_typed(&canonical).await.map_err(store_error)?;
    Ok(hash.as_digest())
}

/// Load canonical JSON from a content slot.
pub(super) async fn load_json(store: &ApiStoreHandle, hash: Sha256) -> Result<JsonValue, ApiError> {
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

/// Store an API token hash as opaque content and return the content digest.
pub(super) async fn put_token_hash(
    store: &ApiStoreHandle,
    token_hash: TokenHash,
) -> Result<Sha256, ApiError> {
    let content = ContentValue::new(token_hash.0.to_vec());
    let hash = content.digest();
    store.put(&content).await.map_err(store_error)?;
    Ok(hash)
}

/// Return a required content hash from a revision.
pub(super) fn required_content_hash(
    revision: &RevisionRow,
    attr: &'static str,
) -> Result<Sha256, ApiError> {
    revision
        .content_attrs
        .get(attr)
        .copied()
        .ok_or_else(|| ApiError::Internal(format!("missing content attribute {attr}")))
}

/// Return an optional content hash from a revision.
pub(super) fn optional_content_hash(revision: &RevisionRow, attr: &'static str) -> Option<Sha256> {
    revision.content_attrs.get(attr).copied()
}

/// Return a required entity reference from a revision.
pub(super) fn required_entity_ref(
    revision: &RevisionRow,
    attr: &'static str,
) -> Result<EntityRefValue, ApiError> {
    revision
        .entity_attrs
        .get(attr)
        .copied()
        .ok_or_else(|| ApiError::Internal(format!("missing entity attribute {attr}")))
}

/// Return a required bool scalar from a revision.
pub(super) fn bool_scalar(revision: &RevisionRow, attr: &'static str) -> Result<bool, ApiError> {
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

/// Return a required i64 scalar from a revision.
pub(super) fn i64_scalar(revision: &RevisionRow, attr: &'static str) -> Result<i64, ApiError> {
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

/// Load a required display name string from a revision.
pub(super) async fn display_name(
    store: &ApiStoreHandle,
    revision: &RevisionRow,
    entity_name: &'static str,
) -> Result<String, ApiError> {
    match load_json(store, required_content_hash(revision, "display_name")?).await? {
        JsonValue::String(value) => Ok(value),
        _ => Err(ApiError::Internal(format!(
            "invalid stored {entity_name} display name"
        ))),
    }
}

/// Validate permission atoms and return their canonical JSON array.
pub(super) fn permission_array_json(permissions: Vec<String>) -> Result<JsonValue, ApiError> {
    for permission in &permissions {
        if !ALL_ATOMS.contains(&permission.as_str()) {
            return Err(ApiError::InvalidRequest(format!(
                "unknown permission atom: {permission}"
            )));
        }
    }
    Ok(JsonValue::Array(
        permissions.into_iter().map(JsonValue::String).collect(),
    ))
}

/// Load a permission document from a revision content slot.
pub(super) async fn permissions_from_revision(
    store: &ApiStoreHandle,
    revision: &RevisionRow,
    attr: &'static str,
) -> Result<Vec<String>, ApiError> {
    let value = load_json(store, required_content_hash(revision, attr)?).await?;
    let document = serde_json::from_value::<PermissionDocument>(value).map_err(|error| {
        ApiError::Internal(format!("invalid stored permission document: {error}"))
    })?;
    Ok(document.permissions().to_vec())
}

/// Convert an internal entity UUID back to a public typed UUID.
pub(super) async fn public_for_internal<T: Entity>(
    store: &ApiStoreHandle,
    internal: Uuid,
) -> Result<Uuid, ApiError> {
    let identity = store
        .resolve_internal(internal)
        .await
        .map_err(store_error)?
        .ok_or_else(|| ApiError::Internal(format!("missing {} identity", T::NAME)))?;
    let _ = identity
        .typed::<T>()
        .map_err(|error| ApiError::Internal(format!("invalid {} identity: {error}", T::NAME)))?;
    Ok(identity.public)
}

/// Paginate items using the API cursor contract.
pub(super) fn paginate_items<T>(
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

/// Remove duplicate entity rows discovered through scalar indexes.
pub(super) fn dedupe_rows(rows: &mut Vec<philharmonic_store::EntityRow>) {
    let mut seen = HashSet::new();
    rows.retain(|row| seen.insert(row.identity.internal));
}

/// Map substrate store errors into API internal errors.
pub(super) fn store_error(error: philharmonic_store::StoreError) -> ApiError {
    ApiError::Internal(error.to_string())
}

fn cursor_after(key: CursorKey, cursor: CursorKey) -> bool {
    (key.created_at, key.id.as_u128()) > (cursor.created_at, cursor.id.as_u128())
}

fn pagination_error(error: PaginationError) -> ApiError {
    match error {
        PaginationError::InvalidCursor => ApiError::InvalidRequest(error.to_string()),
        PaginationError::LimitConversion => ApiError::Internal(error.to_string()),
    }
}
