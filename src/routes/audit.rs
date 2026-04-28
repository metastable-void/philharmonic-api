//! Tenant audit-log routes.

use std::{collections::HashSet, sync::Arc};

use axum::{
    Extension, Json, Router,
    extract::Query,
    middleware::from_fn,
    routing::{MethodRouter, get},
};
use philharmonic_policy::{AuditEvent, Tenant, atom};
use philharmonic_store::{
    ContentStoreExt, EntityRefValue, EntityStore, EntityStoreExt, RevisionInput,
};
use philharmonic_types::{
    CanonicalJson, Entity, EntityId, JsonValue, ScalarValue, UnixMillis, Uuid,
};
use serde::{Deserialize, Serialize};

use crate::{
    ApiError, PaginatedResponse, PaginationParams, RequestContext, RequiredPermission,
    middleware::authz::authorize,
    pagination::{CursorKey, DEFAULT_LIMIT, MAX_LIMIT},
    routes::identity::{
        i64_scalar, load_json, paginate_items, required_content_hash, store_error, tenant_scope,
    },
    store::{ApiStore, ApiStoreHandle},
};

/// Shared audit-log route state.
#[derive(Clone)]
pub(crate) struct AuditState {
    store: ApiStoreHandle,
}

impl AuditState {
    pub(crate) fn new(store: Arc<dyn ApiStore>) -> Self {
        Self {
            store: ApiStoreHandle::new(store),
        }
    }
}

/// Build audit-log routes.
pub fn router() -> Router {
    Router::new().route("/v1/audit", protected(get(list_audit), atom::AUDIT_READ))
}

fn protected(route: MethodRouter, permission: &'static str) -> MethodRouter {
    route
        .route_layer(from_fn(authorize))
        .route_layer(Extension(RequiredPermission(permission)))
}

async fn list_audit(
    Extension(state): Extension<AuditState>,
    Extension(context): Extension<RequestContext>,
    Query(query): Query<AuditQuery>,
) -> Result<Json<PaginatedResponse<AuditEventResponse>>, ApiError> {
    let tenant = tenant_scope(&context)?;
    validate_time_range(&query)?;
    let rows = audit_rows_for_tenant(&state.store, tenant).await?;
    let mut items = Vec::new();

    for row in rows {
        let event_id = row.identity.typed::<AuditEvent>().map_err(|error| {
            ApiError::Internal(format!("invalid audit event identity: {error}"))
        })?;
        let latest = state
            .store
            .get_latest_revision_typed::<AuditEvent>(event_id)
            .await
            .map_err(store_error)?
            .ok_or_else(|| ApiError::Internal("audit event revision not found".to_string()))?;
        let event_type = i64_scalar(&latest, "event_type")?;
        let timestamp = UnixMillis(i64_scalar(&latest, "timestamp")?);
        if !audit_filter_matches(&query, event_type, timestamp) {
            continue;
        }

        let event_data =
            load_json(&state.store, required_content_hash(&latest, "event_data")?).await?;
        let principal_id = event_principal_id(&event_data);
        if query.principal_id.is_some() && principal_id != query.principal_id {
            continue;
        }

        items.push((
            CursorKey::new(timestamp, row.identity.public),
            AuditEventResponse {
                audit_event_id: row.identity.public,
                event_type,
                timestamp,
                principal_id,
                event_data,
                created_at: row.created_at,
            },
        ));
    }

    let pagination = query.pagination();
    Ok(Json(paginate_items(items, &pagination)?))
}

/// Input used to append an [`AuditEvent`] entity.
pub struct AuditEventInput {
    /// Tenant that owns the audit event.
    pub tenant: EntityId<Tenant>,
    /// Deployment-defined audit event type discriminant.
    pub event_type: i64,
    /// Event timestamp in Unix milliseconds.
    pub timestamp: UnixMillis,
    /// JSON payload with event-specific context.
    pub event_data: JsonValue,
}

/// Append an [`AuditEvent`] entity to the store.
pub async fn write_audit_event(
    store: &dyn ApiStore,
    input: AuditEventInput,
) -> Result<EntityId<AuditEvent>, ApiError> {
    let identity = store.mint().await.map_err(store_error)?;
    let event_id = identity
        .typed::<AuditEvent>()
        .map_err(|error| ApiError::Internal(format!("invalid minted audit identity: {error}")))?;
    store
        .create_entity_typed::<AuditEvent>(event_id)
        .await
        .map_err(store_error)?;
    let event_data = CanonicalJson::from_value(&input.event_data)
        .map_err(|error| ApiError::InvalidRequest(format!("invalid audit event JSON: {error}")))?;
    let event_data_hash = store
        .put_typed(&event_data)
        .await
        .map_err(store_error)?
        .as_digest();
    let revision = RevisionInput::new()
        .with_content("event_data", event_data_hash)
        .with_entity(
            "tenant",
            EntityRefValue::pinned(input.tenant.internal().as_uuid(), 0),
        )
        .with_scalar("event_type", ScalarValue::I64(input.event_type))
        .with_scalar("timestamp", ScalarValue::I64(input.timestamp.as_i64()));
    store
        .append_revision_typed::<AuditEvent>(event_id, 0, &revision)
        .await
        .map_err(store_error)?;
    Ok(event_id)
}

#[derive(Deserialize)]
struct AuditQuery {
    cursor: Option<String>,
    limit: Option<u32>,
    event_type: Option<i64>,
    since: Option<UnixMillis>,
    until: Option<UnixMillis>,
    principal_id: Option<Uuid>,
}

impl AuditQuery {
    fn pagination(&self) -> PaginationParams {
        PaginationParams {
            cursor: self.cursor.clone(),
            limit: self.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT),
        }
    }
}

#[derive(Serialize)]
struct AuditEventResponse {
    audit_event_id: Uuid,
    event_type: i64,
    timestamp: UnixMillis,
    principal_id: Option<Uuid>,
    event_data: JsonValue,
    created_at: UnixMillis,
}

async fn audit_rows_for_tenant(
    store: &ApiStoreHandle,
    tenant: EntityId<Tenant>,
) -> Result<Vec<philharmonic_store::EntityRow>, ApiError> {
    let refs = store
        .list_revisions_referencing(tenant.internal().as_uuid(), "tenant")
        .await
        .map_err(store_error)?;
    let mut seen = HashSet::new();
    let mut rows = Vec::new();
    for reference in refs {
        if !seen.insert(reference.entity_id) {
            continue;
        }
        let Some(row) = store
            .get_entity(reference.entity_id)
            .await
            .map_err(store_error)?
        else {
            continue;
        };
        if row.kind == AuditEvent::KIND {
            rows.push(row);
        }
    }
    Ok(rows)
}

fn validate_time_range(query: &AuditQuery) -> Result<(), ApiError> {
    match (query.since, query.until) {
        (Some(since), Some(until)) if since > until => Err(ApiError::InvalidRequest(
            "since must be less than or equal to until".to_string(),
        )),
        _ => Ok(()),
    }
}

fn audit_filter_matches(query: &AuditQuery, event_type: i64, timestamp: UnixMillis) -> bool {
    if query
        .event_type
        .is_some_and(|expected| event_type != expected)
    {
        return false;
    }
    if query.since.is_some_and(|since| timestamp < since) {
        return false;
    }
    if query.until.is_some_and(|until| timestamp > until) {
        return false;
    }
    true
}

fn event_principal_id(event_data: &JsonValue) -> Option<Uuid> {
    let value = event_data.get("principal_id")?.as_str()?;
    value.parse::<Uuid>().ok()
}
