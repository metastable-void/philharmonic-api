//! Workflow template and instance management routes.

use std::{collections::HashSet, sync::Arc};

use axum::{
    Extension, Json, Router,
    extract::{Path, Query, Request},
    http::StatusCode,
    middleware::{Next, from_fn},
    response::Response,
    routing::{MethodRouter, get, patch, post},
};
use philharmonic_policy::{TenantEndpointConfig, atom};
use philharmonic_store::{
    ContentStore, ContentStoreExt, EntityRefValue, EntityStore, EntityStoreExt, IdentityStore,
    RevisionInput, RevisionRow, StoreExt,
};
use philharmonic_types::{
    CanonicalJson, ContentHash, ContentValue, Entity, EntityId, JsonValue, ScalarValue, Sha256,
    UnixMillis, Uuid,
};
use philharmonic_workflow::{
    InstanceStatus, MintingAuthority as WorkflowMintingAuthority, StepRecord, StepResult,
    SubjectContext, SubjectKind, Tenant as WorkflowTenant, WorkflowError, WorkflowInstance,
    WorkflowTemplate,
};
use serde::{Deserialize, Serialize};

use crate::{
    ApiError, AuthContext, PaginatedResponse, PaginationParams, RequestContext, RequestScope,
    RequiredPermission,
    middleware::authz::{RequestInstanceScope, authorize},
    pagination::{CursorKey, PaginationError, decode_cursor, encode_cursor, page_size},
    store::{ApiStore, ApiStoreHandle},
    workflow::ApiWorkflowEngine,
};

/// Shared workflow route state.
#[derive(Clone)]
pub(crate) struct WorkflowState {
    store: ApiStoreHandle,
    engine: Arc<ApiWorkflowEngine>,
}

impl WorkflowState {
    pub(crate) fn new(store: Arc<dyn ApiStore>, engine: Arc<ApiWorkflowEngine>) -> Self {
        Self {
            store: ApiStoreHandle::new(store),
            engine,
        }
    }
}

/// Build workflow-management routes.
pub fn router() -> Router {
    Router::new()
        .route(
            "/v1/workflows/templates",
            protected(post(create_template), atom::WORKFLOW_TEMPLATE_CREATE),
        )
        .route(
            "/v1/workflows/templates",
            protected(get(list_templates), atom::WORKFLOW_TEMPLATE_READ),
        )
        .route(
            "/v1/workflows/templates/{id}",
            protected(get(read_template), atom::WORKFLOW_TEMPLATE_READ),
        )
        .route(
            "/v1/workflows/templates/{id}",
            protected(patch(update_template), atom::WORKFLOW_TEMPLATE_CREATE),
        )
        .route(
            "/v1/workflows/templates/{id}/retire",
            protected(post(retire_template), atom::WORKFLOW_TEMPLATE_RETIRE),
        )
        .route(
            "/v1/workflows/instances",
            protected(post(create_instance), atom::WORKFLOW_INSTANCE_CREATE),
        )
        .route(
            "/v1/workflows/instances",
            protected(get(list_instances), atom::WORKFLOW_INSTANCE_READ),
        )
        .route(
            "/v1/workflows/instances/{id}",
            instance_protected(get(read_instance), atom::WORKFLOW_INSTANCE_READ),
        )
        .route(
            "/v1/workflows/instances/{id}/history",
            instance_protected(get(instance_history), atom::WORKFLOW_INSTANCE_READ),
        )
        .route(
            "/v1/workflows/instances/{id}/steps",
            instance_protected(get(instance_steps), atom::WORKFLOW_INSTANCE_READ),
        )
        .route(
            "/v1/workflows/instances/{id}/execute",
            instance_protected(post(execute_instance), atom::WORKFLOW_INSTANCE_EXECUTE),
        )
        .route(
            "/v1/workflows/instances/{id}/complete",
            instance_protected(post(complete_instance), atom::WORKFLOW_INSTANCE_EXECUTE),
        )
        .route(
            "/v1/workflows/instances/{id}/cancel",
            instance_protected(post(cancel_instance), atom::WORKFLOW_INSTANCE_CANCEL),
        )
}

fn protected(route: MethodRouter, permission: &'static str) -> MethodRouter {
    route
        .route_layer(from_fn(authorize))
        .route_layer(Extension(RequiredPermission(permission)))
}

fn instance_protected(route: MethodRouter, permission: &'static str) -> MethodRouter {
    route
        .route_layer(from_fn(authorize))
        .route_layer(from_fn(attach_instance_scope))
        .route_layer(Extension(RequiredPermission(permission)))
}

async fn attach_instance_scope(Path(id): Path<Uuid>, mut request: Request, next: Next) -> Response {
    request.extensions_mut().insert(RequestInstanceScope(id));
    next.run(request).await
}

async fn create_template(
    Extension(state): Extension<WorkflowState>,
    Extension(context): Extension<RequestContext>,
    Json(request): Json<CreateTemplateRequest>,
) -> Result<(StatusCode, Json<CreateTemplateResponse>), ApiError> {
    let tenant = require_tenant_principal(&context)?;
    validate_abstract_config(&state.store, tenant, &request.abstract_config).await?;

    let template_id = state
        .store
        .create_entity_minting::<WorkflowTemplate>()
        .await
        .map_err(store_error)?;
    let script_hash = put_bytes(&state.store, request.script_source.as_bytes()).await?;
    let config_hash = put_json(&state.store, &request.abstract_config).await?;
    let display_name_hash =
        put_json(&state.store, &JsonValue::String(request.display_name)).await?;

    let revision = RevisionInput::new()
        .with_content("script", script_hash)
        .with_content("config", config_hash)
        .with_content("display_name", display_name_hash)
        .with_entity(
            "tenant",
            EntityRefValue::pinned(tenant.internal().as_uuid(), 0),
        )
        .with_scalar("is_retired", ScalarValue::Bool(false));

    state
        .store
        .append_revision_typed::<WorkflowTemplate>(template_id, 0, &revision)
        .await
        .map_err(store_error)?;

    Ok((
        StatusCode::CREATED,
        Json(CreateTemplateResponse {
            template_id: template_id.public().as_uuid(),
        }),
    ))
}

async fn list_templates(
    Extension(state): Extension<WorkflowState>,
    Extension(context): Extension<RequestContext>,
    Query(params): Query<PaginationParams>,
) -> Result<Json<PaginatedResponse<TemplateSummaryResponse>>, ApiError> {
    let tenant = require_tenant_principal(&context)?;
    let mut rows = Vec::new();
    rows.extend(
        state
            .store
            .find_by_scalar_typed::<WorkflowTemplate>("is_retired", &ScalarValue::Bool(false))
            .await
            .map_err(store_error)?,
    );
    rows.extend(
        state
            .store
            .find_by_scalar_typed::<WorkflowTemplate>("is_retired", &ScalarValue::Bool(true))
            .await
            .map_err(store_error)?,
    );
    dedupe_rows(&mut rows);

    let items = template_items(&state.store, rows, tenant).await?;
    Ok(Json(paginate_items(items, &params)?))
}

async fn read_template(
    Extension(state): Extension<WorkflowState>,
    Extension(context): Extension<RequestContext>,
    Path(id): Path<Uuid>,
) -> Result<Json<TemplateResponse>, ApiError> {
    let tenant = require_tenant_principal(&context)?;
    let template_id = resolve_public_id::<WorkflowTemplate>(&state.store, id).await?;
    let row = state
        .store
        .get_entity_typed::<WorkflowTemplate>(template_id)
        .await
        .map_err(store_error)?
        .ok_or_else(|| ApiError::NotFound("workflow template not found".to_string()))?;
    let latest = latest_revision::<WorkflowTemplate>(&state.store, template_id).await?;
    ensure_revision_tenant(&latest, tenant, "workflow template")?;
    Ok(Json(template_response(&state.store, &row, &latest).await?))
}

async fn update_template(
    Extension(state): Extension<WorkflowState>,
    Extension(context): Extension<RequestContext>,
    Path(id): Path<Uuid>,
    Json(request): Json<UpdateTemplateRequest>,
) -> Result<Json<TemplateResponse>, ApiError> {
    let tenant = require_tenant_principal(&context)?;
    if request.script_source.is_none()
        && request.abstract_config.is_none()
        && request.display_name.is_none()
    {
        return Err(ApiError::InvalidRequest(
            "template update must change at least one field".to_string(),
        ));
    }

    if let Some(config) = request.abstract_config.as_ref() {
        validate_abstract_config(&state.store, tenant, config).await?;
    }

    let template_id = resolve_public_id::<WorkflowTemplate>(&state.store, id).await?;
    let row = state
        .store
        .get_entity_typed::<WorkflowTemplate>(template_id)
        .await
        .map_err(store_error)?
        .ok_or_else(|| ApiError::NotFound("workflow template not found".to_string()))?;
    let latest = latest_revision::<WorkflowTemplate>(&state.store, template_id).await?;
    ensure_revision_tenant(&latest, tenant, "workflow template")?;

    let script_hash = match request.script_source {
        Some(source) => put_bytes(&state.store, source.as_bytes()).await?,
        None => required_content_hash(&latest, "script")?,
    };
    let config_hash = match request.abstract_config {
        Some(config) => put_json(&state.store, &config).await?,
        None => required_content_hash(&latest, "config")?,
    };
    let display_name_hash = match request.display_name {
        Some(display_name) => Some(put_json(&state.store, &JsonValue::String(display_name)).await?),
        None => optional_content_hash(&latest, "display_name"),
    };
    let is_retired = bool_scalar(&latest, "is_retired")?;
    let tenant_ref = required_entity_ref(&latest, "tenant")?;
    let next_revision_seq = latest
        .revision_seq
        .checked_add(1)
        .ok_or(ApiError::Internal(
            "template revision sequence overflow".to_string(),
        ))?;

    let mut revision = RevisionInput::new()
        .with_content("script", script_hash)
        .with_content("config", config_hash)
        .with_entity("tenant", tenant_ref)
        .with_scalar("is_retired", ScalarValue::Bool(is_retired));
    if let Some(hash) = display_name_hash {
        revision = revision.with_content("display_name", hash);
    }

    state
        .store
        .append_revision_typed::<WorkflowTemplate>(template_id, next_revision_seq, &revision)
        .await
        .map_err(store_error)?;
    let updated = latest_revision::<WorkflowTemplate>(&state.store, template_id).await?;

    Ok(Json(template_response(&state.store, &row, &updated).await?))
}

async fn retire_template(
    Extension(state): Extension<WorkflowState>,
    Extension(context): Extension<RequestContext>,
    Path(id): Path<Uuid>,
) -> Result<Json<RetireTemplateResponse>, ApiError> {
    let tenant = require_tenant_principal(&context)?;
    let template_id = resolve_public_id::<WorkflowTemplate>(&state.store, id).await?;
    let latest = latest_revision::<WorkflowTemplate>(&state.store, template_id).await?;
    ensure_revision_tenant(&latest, tenant, "workflow template")?;
    let next_revision_seq = latest
        .revision_seq
        .checked_add(1)
        .ok_or(ApiError::Internal(
            "template revision sequence overflow".to_string(),
        ))?;
    let tenant_ref = required_entity_ref(&latest, "tenant")?;
    let mut revision = RevisionInput::new()
        .with_content("script", required_content_hash(&latest, "script")?)
        .with_content("config", required_content_hash(&latest, "config")?)
        .with_entity("tenant", tenant_ref)
        .with_scalar("is_retired", ScalarValue::Bool(true));
    if let Some(hash) = optional_content_hash(&latest, "display_name") {
        revision = revision.with_content("display_name", hash);
    }

    state
        .store
        .append_revision_typed::<WorkflowTemplate>(template_id, next_revision_seq, &revision)
        .await
        .map_err(store_error)?;

    Ok(Json(RetireTemplateResponse {
        template_id: id,
        is_retired: true,
    }))
}

async fn create_instance(
    Extension(state): Extension<WorkflowState>,
    Extension(context): Extension<RequestContext>,
    Json(request): Json<CreateInstanceRequest>,
) -> Result<(StatusCode, Json<CreateInstanceResponse>), ApiError> {
    let tenant = require_tenant_principal(&context)?;
    let template_id =
        resolve_public_id::<WorkflowTemplate>(&state.store, request.template_id).await?;
    let template_latest = latest_revision::<WorkflowTemplate>(&state.store, template_id).await?;
    ensure_revision_tenant(&template_latest, tenant, "workflow template")?;
    if bool_scalar(&template_latest, "is_retired")? {
        return Err(ApiError::InvalidRequest(
            "workflow template is retired".to_string(),
        ));
    }

    let args = CanonicalJson::from_value(&request.args)
        .map_err(|error| ApiError::InvalidRequest(format!("invalid args JSON: {error}")))?;
    let subject = subject_context(&context)?;
    let instance_id = state
        .engine
        .create_instance(template_id, args, subject)
        .await
        .map_err(workflow_error)?;

    Ok((
        StatusCode::CREATED,
        Json(CreateInstanceResponse {
            instance_id: instance_id.public().as_uuid(),
        }),
    ))
}

async fn list_instances(
    Extension(state): Extension<WorkflowState>,
    Extension(context): Extension<RequestContext>,
    Query(params): Query<PaginationParams>,
) -> Result<Json<PaginatedResponse<InstanceSummaryResponse>>, ApiError> {
    let tenant = require_tenant_principal(&context)?;
    let mut rows = Vec::new();
    for status in [
        InstanceStatus::Pending,
        InstanceStatus::Running,
        InstanceStatus::Completed,
        InstanceStatus::Failed,
        InstanceStatus::Cancelled,
    ] {
        rows.extend(
            state
                .store
                .find_by_scalar_typed::<WorkflowInstance>(
                    "status",
                    &ScalarValue::I64(status.as_i64()),
                )
                .await
                .map_err(store_error)?,
        );
    }
    dedupe_rows(&mut rows);

    let items = instance_items(&state.store, rows, tenant).await?;
    Ok(Json(paginate_items(items, &params)?))
}

async fn read_instance(
    Extension(state): Extension<WorkflowState>,
    Extension(context): Extension<RequestContext>,
    Path(id): Path<Uuid>,
) -> Result<Json<InstanceResponse>, ApiError> {
    let tenant = require_tenant_principal(&context)?;
    let instance_id = resolve_public_id::<WorkflowInstance>(&state.store, id).await?;
    let row = state
        .store
        .get_entity_typed::<WorkflowInstance>(instance_id)
        .await
        .map_err(store_error)?
        .ok_or_else(|| ApiError::NotFound("workflow instance not found".to_string()))?;
    let latest = latest_revision::<WorkflowInstance>(&state.store, instance_id).await?;
    ensure_revision_tenant(&latest, tenant, "workflow instance")?;
    Ok(Json(instance_response(&state.store, &row, &latest).await?))
}

async fn instance_history(
    Extension(state): Extension<WorkflowState>,
    Extension(context): Extension<RequestContext>,
    Path(id): Path<Uuid>,
    Query(params): Query<PaginationParams>,
) -> Result<Json<PaginatedResponse<InstanceRevisionResponse>>, ApiError> {
    let tenant = require_tenant_principal(&context)?;
    let instance_id = resolve_public_id::<WorkflowInstance>(&state.store, id).await?;
    let latest = latest_revision::<WorkflowInstance>(&state.store, instance_id).await?;
    ensure_revision_tenant(&latest, tenant, "workflow instance")?;

    let mut seq = 0_u64;
    let mut items = Vec::new();
    loop {
        if let Some(revision) = state
            .store
            .get_revision(instance_id.internal().as_uuid(), seq)
            .await
            .map_err(store_error)?
        {
            items.push((
                CursorKey::new(revision.created_at, instance_id.public().as_uuid()),
                instance_revision_response(&state.store, &revision).await?,
            ));
        }
        if seq == latest.revision_seq {
            break;
        }
        seq = seq
            .checked_add(1)
            .ok_or(ApiError::Internal("revision sequence overflow".to_string()))?;
    }

    Ok(Json(paginate_items(items, &params)?))
}

async fn instance_steps(
    Extension(state): Extension<WorkflowState>,
    Extension(context): Extension<RequestContext>,
    Path(id): Path<Uuid>,
    Query(params): Query<PaginationParams>,
) -> Result<Json<PaginatedResponse<StepRecordResponse>>, ApiError> {
    let tenant = require_tenant_principal(&context)?;
    let instance_id = resolve_public_id::<WorkflowInstance>(&state.store, id).await?;
    let latest = latest_revision::<WorkflowInstance>(&state.store, instance_id).await?;
    ensure_revision_tenant(&latest, tenant, "workflow instance")?;
    let items = step_items(&state.store, instance_id).await?;
    Ok(Json(paginate_items(items, &params)?))
}

async fn execute_instance(
    Extension(state): Extension<WorkflowState>,
    Extension(context): Extension<RequestContext>,
    Path(id): Path<Uuid>,
    Json(request): Json<ExecuteInstanceRequest>,
) -> Result<Json<ExecuteInstanceResponse>, ApiError> {
    let tenant = tenant_scope(&context)?;
    let instance_id = resolve_public_id::<WorkflowInstance>(&state.store, id).await?;
    let latest = latest_revision::<WorkflowInstance>(&state.store, instance_id).await?;
    ensure_revision_tenant(&latest, tenant, "workflow instance")?;
    let input = CanonicalJson::from_value(&request.input)
        .map_err(|error| ApiError::InvalidRequest(format!("invalid input JSON: {error}")))?;
    let subject = subject_context(&context)?;
    let result = state
        .engine
        .execute_step(instance_id, input, subject)
        .await
        .map_err(workflow_error)?;
    Ok(Json(ExecuteInstanceResponse::from_result(result)))
}

async fn complete_instance(
    Extension(state): Extension<WorkflowState>,
    Extension(context): Extension<RequestContext>,
    Path(id): Path<Uuid>,
) -> Result<Json<InstanceStatusResponse>, ApiError> {
    let tenant = require_tenant_principal(&context)?;
    let instance_id = resolve_public_id::<WorkflowInstance>(&state.store, id).await?;
    let latest = latest_revision::<WorkflowInstance>(&state.store, instance_id).await?;
    ensure_revision_tenant(&latest, tenant, "workflow instance")?;
    let subject = subject_context(&context)?;
    state
        .engine
        .complete(instance_id, subject)
        .await
        .map_err(workflow_error)?;
    let latest = latest_revision::<WorkflowInstance>(&state.store, instance_id).await?;
    Ok(Json(instance_status_response(id, &latest)?))
}

async fn cancel_instance(
    Extension(state): Extension<WorkflowState>,
    Extension(context): Extension<RequestContext>,
    Path(id): Path<Uuid>,
) -> Result<Json<InstanceStatusResponse>, ApiError> {
    let tenant = require_tenant_principal(&context)?;
    let instance_id = resolve_public_id::<WorkflowInstance>(&state.store, id).await?;
    let latest = latest_revision::<WorkflowInstance>(&state.store, instance_id).await?;
    ensure_revision_tenant(&latest, tenant, "workflow instance")?;
    let subject = subject_context(&context)?;
    state
        .engine
        .cancel(instance_id, subject)
        .await
        .map_err(workflow_error)?;
    let latest = latest_revision::<WorkflowInstance>(&state.store, instance_id).await?;
    Ok(Json(instance_status_response(id, &latest)?))
}

#[derive(Deserialize)]
struct CreateTemplateRequest {
    display_name: String,
    script_source: String,
    abstract_config: JsonValue,
}

#[derive(Serialize)]
struct CreateTemplateResponse {
    template_id: Uuid,
}

#[derive(Deserialize)]
struct UpdateTemplateRequest {
    display_name: Option<String>,
    script_source: Option<String>,
    abstract_config: Option<JsonValue>,
}

#[derive(Serialize)]
struct RetireTemplateResponse {
    template_id: Uuid,
    is_retired: bool,
}

#[derive(Serialize)]
struct TemplateSummaryResponse {
    template_id: Uuid,
    display_name: Option<String>,
    latest_revision: u64,
    created_at: UnixMillis,
    updated_at: UnixMillis,
    is_retired: bool,
}

#[derive(Serialize)]
struct TemplateResponse {
    template_id: Uuid,
    display_name: Option<String>,
    script_source: String,
    abstract_config: JsonValue,
    latest_revision: u64,
    created_at: UnixMillis,
    updated_at: UnixMillis,
    is_retired: bool,
}

#[derive(Deserialize)]
struct CreateInstanceRequest {
    template_id: Uuid,
    args: JsonValue,
}

#[derive(Serialize)]
struct CreateInstanceResponse {
    instance_id: Uuid,
}

#[derive(Serialize)]
struct InstanceSummaryResponse {
    instance_id: Uuid,
    template_id: Uuid,
    template_revision: u64,
    status: &'static str,
    latest_revision: u64,
    created_at: UnixMillis,
    updated_at: UnixMillis,
}

#[derive(Serialize)]
struct InstanceResponse {
    instance_id: Uuid,
    template_id: Uuid,
    template_revision: u64,
    status: &'static str,
    latest_revision: u64,
    created_at: UnixMillis,
    updated_at: UnixMillis,
    args: JsonValue,
    context: JsonValue,
}

#[derive(Serialize)]
struct InstanceRevisionResponse {
    revision_seq: u64,
    created_at: UnixMillis,
    status: &'static str,
    args: JsonValue,
    context: JsonValue,
}

#[derive(Serialize)]
struct StepRecordResponse {
    step_record_id: Uuid,
    step_seq: i64,
    outcome: &'static str,
    created_at: UnixMillis,
    input: JsonValue,
    output: Option<JsonValue>,
    error: Option<JsonValue>,
    subject: JsonValue,
}

#[derive(Deserialize)]
struct ExecuteInstanceRequest {
    input: JsonValue,
}

#[derive(Serialize)]
struct ExecuteInstanceResponse {
    output: JsonValue,
    context: JsonValue,
    status: &'static str,
    step_seq: u64,
}

impl ExecuteInstanceResponse {
    fn from_result(result: StepResult) -> Self {
        Self {
            output: result.output,
            context: result.context,
            status: status_name(result.status),
            step_seq: result.step_seq,
        }
    }
}

#[derive(Serialize)]
struct InstanceStatusResponse {
    instance_id: Uuid,
    status: &'static str,
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

fn subject_context(context: &RequestContext) -> Result<SubjectContext, ApiError> {
    match context.auth.as_ref() {
        Some(AuthContext::Principal {
            principal_id,
            tenant_id,
        }) => Ok(SubjectContext {
            kind: SubjectKind::Principal,
            id: principal_id.public().as_uuid().to_string(),
            tenant_id: tenant_id
                .untyped()
                .typed::<WorkflowTenant>()
                .map_err(workflow_identity_error)?,
            authority_id: None,
            claims: JsonValue::Object(Default::default()),
        }),
        Some(AuthContext::Ephemeral {
            subject,
            tenant_id,
            authority_id,
            injected_claims,
            ..
        }) => Ok(SubjectContext {
            kind: SubjectKind::Ephemeral,
            id: subject.clone(),
            tenant_id: tenant_id
                .untyped()
                .typed::<WorkflowTenant>()
                .map_err(workflow_identity_error)?,
            authority_id: Some(
                authority_id
                    .untyped()
                    .typed::<WorkflowMintingAuthority>()
                    .map_err(workflow_identity_error)?,
            ),
            claims: injected_claims.clone(),
        }),
        None => Err(ApiError::Unauthenticated),
    }
}

fn workflow_identity_error(error: philharmonic_types::IdentityKindError) -> ApiError {
    ApiError::Internal(format!("invalid workflow identity: {error}"))
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

async fn load_optional_json(
    store: &ApiStoreHandle,
    hash: Option<Sha256>,
) -> Result<Option<JsonValue>, ApiError> {
    match hash {
        Some(hash) => load_json(store, hash).await.map(Some),
        None => Ok(None),
    }
}

async fn load_script(store: &ApiStoreHandle, hash: Sha256) -> Result<String, ApiError> {
    let content = store
        .get(hash)
        .await
        .map_err(store_error)?
        .ok_or_else(|| ApiError::Internal("missing script content blob".to_string()))?;
    String::from_utf8(content.bytes().to_vec())
        .map_err(|error| ApiError::Internal(format!("invalid stored script UTF-8: {error}")))
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

fn status_from_revision(revision: &RevisionRow) -> Result<InstanceStatus, ApiError> {
    let value = i64_scalar(revision, "status")?;
    InstanceStatus::try_from_i64(value)
        .ok_or_else(|| ApiError::Internal(format!("invalid instance status {value}")))
}

fn status_name(status: InstanceStatus) -> &'static str {
    match status {
        InstanceStatus::Pending => "pending",
        InstanceStatus::Running => "running",
        InstanceStatus::Completed => "completed",
        InstanceStatus::Failed => "failed",
        InstanceStatus::Cancelled => "cancelled",
    }
}

fn outcome_name(value: i64) -> Result<&'static str, ApiError> {
    match value {
        0 => Ok("success"),
        1 => Ok("failure"),
        _ => Err(ApiError::Internal(format!("invalid step outcome {value}"))),
    }
}

async fn template_items(
    store: &ApiStoreHandle,
    rows: Vec<philharmonic_store::EntityRow>,
    tenant: EntityId<crate::Tenant>,
) -> Result<Vec<(CursorKey, TemplateSummaryResponse)>, ApiError> {
    let mut items = Vec::new();
    for row in rows {
        let template_id = row
            .identity
            .typed::<WorkflowTemplate>()
            .map_err(|error| ApiError::Internal(format!("invalid template identity: {error}")))?;
        let latest = latest_revision::<WorkflowTemplate>(store, template_id).await?;
        if required_entity_ref(&latest, "tenant")?.target_entity_id != tenant.internal().as_uuid() {
            continue;
        }
        let display_name = display_name(store, &latest).await?;
        let is_retired = bool_scalar(&latest, "is_retired")?;
        items.push((
            CursorKey::new(row.created_at, row.identity.public),
            TemplateSummaryResponse {
                template_id: row.identity.public,
                display_name,
                latest_revision: latest.revision_seq,
                created_at: row.created_at,
                updated_at: latest.created_at,
                is_retired,
            },
        ));
    }
    Ok(items)
}

async fn template_response(
    store: &ApiStoreHandle,
    row: &philharmonic_store::EntityRow,
    latest: &RevisionRow,
) -> Result<TemplateResponse, ApiError> {
    Ok(TemplateResponse {
        template_id: row.identity.public,
        display_name: display_name(store, latest).await?,
        script_source: load_script(store, required_content_hash(latest, "script")?).await?,
        abstract_config: load_json(store, required_content_hash(latest, "config")?).await?,
        latest_revision: latest.revision_seq,
        created_at: row.created_at,
        updated_at: latest.created_at,
        is_retired: bool_scalar(latest, "is_retired")?,
    })
}

async fn display_name(
    store: &ApiStoreHandle,
    revision: &RevisionRow,
) -> Result<Option<String>, ApiError> {
    let Some(value) =
        load_optional_json(store, optional_content_hash(revision, "display_name")).await?
    else {
        return Ok(None);
    };
    match value {
        JsonValue::String(value) => Ok(Some(value)),
        _ => Err(ApiError::Internal(
            "invalid stored template display name".to_string(),
        )),
    }
}

async fn instance_items(
    store: &ApiStoreHandle,
    rows: Vec<philharmonic_store::EntityRow>,
    tenant: EntityId<crate::Tenant>,
) -> Result<Vec<(CursorKey, InstanceSummaryResponse)>, ApiError> {
    let mut items = Vec::new();
    for row in rows {
        let instance_id = row
            .identity
            .typed::<WorkflowInstance>()
            .map_err(|error| ApiError::Internal(format!("invalid instance identity: {error}")))?;
        let latest = latest_revision::<WorkflowInstance>(store, instance_id).await?;
        if required_entity_ref(&latest, "tenant")?.target_entity_id != tenant.internal().as_uuid() {
            continue;
        }
        items.push((
            CursorKey::new(row.created_at, row.identity.public),
            instance_summary_response(store, &row, &latest).await?,
        ));
    }
    Ok(items)
}

async fn instance_summary_response(
    store: &ApiStoreHandle,
    row: &philharmonic_store::EntityRow,
    latest: &RevisionRow,
) -> Result<InstanceSummaryResponse, ApiError> {
    let template_ref = required_entity_ref(latest, "template")?;
    let template_revision = template_ref.target_revision_seq.ok_or_else(|| {
        ApiError::Internal("instance template reference is not pinned".to_string())
    })?;
    Ok(InstanceSummaryResponse {
        instance_id: row.identity.public,
        template_id: public_for_internal::<WorkflowTemplate>(store, template_ref.target_entity_id)
            .await?,
        template_revision,
        status: status_name(status_from_revision(latest)?),
        latest_revision: latest.revision_seq,
        created_at: row.created_at,
        updated_at: latest.created_at,
    })
}

async fn instance_response(
    store: &ApiStoreHandle,
    row: &philharmonic_store::EntityRow,
    latest: &RevisionRow,
) -> Result<InstanceResponse, ApiError> {
    let template_ref = required_entity_ref(latest, "template")?;
    let template_revision = template_ref.target_revision_seq.ok_or_else(|| {
        ApiError::Internal("instance template reference is not pinned".to_string())
    })?;
    Ok(InstanceResponse {
        instance_id: row.identity.public,
        template_id: public_for_internal::<WorkflowTemplate>(store, template_ref.target_entity_id)
            .await?,
        template_revision,
        status: status_name(status_from_revision(latest)?),
        latest_revision: latest.revision_seq,
        created_at: row.created_at,
        updated_at: latest.created_at,
        args: load_json(store, required_content_hash(latest, "args")?).await?,
        context: load_json(store, required_content_hash(latest, "context")?).await?,
    })
}

async fn public_for_internal<T: Entity>(
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

async fn instance_revision_response(
    store: &ApiStoreHandle,
    revision: &RevisionRow,
) -> Result<InstanceRevisionResponse, ApiError> {
    Ok(InstanceRevisionResponse {
        revision_seq: revision.revision_seq,
        created_at: revision.created_at,
        status: status_name(status_from_revision(revision)?),
        args: load_json(store, required_content_hash(revision, "args")?).await?,
        context: load_json(store, required_content_hash(revision, "context")?).await?,
    })
}

async fn step_items(
    store: &ApiStoreHandle,
    instance_id: EntityId<WorkflowInstance>,
) -> Result<Vec<(CursorKey, StepRecordResponse)>, ApiError> {
    let refs = store
        .list_revisions_referencing(instance_id.internal().as_uuid(), "instance")
        .await
        .map_err(store_error)?;
    let mut items = Vec::new();
    for reference in refs {
        let Some(row) = store
            .get_entity(reference.entity_id)
            .await
            .map_err(store_error)?
        else {
            continue;
        };
        if row.kind != StepRecord::KIND {
            continue;
        }
        let Some(revision) = store
            .get_revision(reference.entity_id, reference.revision_seq)
            .await
            .map_err(store_error)?
        else {
            continue;
        };
        items.push((
            CursorKey::new(revision.created_at, row.identity.public),
            StepRecordResponse {
                step_record_id: row.identity.public,
                step_seq: i64_scalar(&revision, "step_seq")?,
                outcome: outcome_name(i64_scalar(&revision, "outcome")?)?,
                created_at: revision.created_at,
                input: load_json(store, required_content_hash(&revision, "input")?).await?,
                output: load_optional_json(store, optional_content_hash(&revision, "output"))
                    .await?,
                error: load_optional_json(store, optional_content_hash(&revision, "error")).await?,
                subject: load_json(store, required_content_hash(&revision, "subject")?).await?,
            },
        ));
    }
    Ok(items)
}

fn instance_status_response(
    instance_id: Uuid,
    latest: &RevisionRow,
) -> Result<InstanceStatusResponse, ApiError> {
    Ok(InstanceStatusResponse {
        instance_id,
        status: status_name(status_from_revision(latest)?),
    })
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

async fn validate_abstract_config(
    store: &ApiStoreHandle,
    tenant: EntityId<crate::Tenant>,
    config: &JsonValue,
) -> Result<(), ApiError> {
    let JsonValue::Object(bindings) = config else {
        return Err(ApiError::InvalidRequest(
            "abstract_config must be a JSON object".to_string(),
        ));
    };

    for value in bindings.values() {
        let Some(id) = value.as_str() else {
            return Err(ApiError::InvalidRequest(
                "abstract_config values must be endpoint config UUID strings".to_string(),
            ));
        };
        let id = Uuid::parse_str(id)
            .map_err(|_| ApiError::InvalidRequest("invalid endpoint config UUID".to_string()))?;
        let config_id = resolve_public_id::<TenantEndpointConfig>(store, id).await?;
        let latest = latest_revision::<TenantEndpointConfig>(store, config_id).await?;
        ensure_revision_tenant(&latest, tenant, "endpoint config")?;
        if bool_scalar(&latest, "is_retired")? {
            return Err(ApiError::InvalidRequest(
                "endpoint config is retired".to_string(),
            ));
        }
    }

    Ok(())
}

fn workflow_error(error: WorkflowError) -> ApiError {
    match error {
        WorkflowError::TemplateNotFound { .. }
        | WorkflowError::TemplateRevisionNotFound { .. }
        | WorkflowError::InstanceNotFound { .. }
        | WorkflowError::InstanceRevisionMissing { .. } => ApiError::NotFound(error.to_string()),
        WorkflowError::InvalidTransition { .. } | WorkflowError::InstanceTerminal { .. } => {
            ApiError::InvalidRequest(error.to_string())
        }
        _ => ApiError::Internal(error.to_string()),
    }
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
