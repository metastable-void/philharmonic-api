use std::{collections::HashMap, sync::Arc, time::Instant};

use axum::{
    Extension, Json, Router,
    extract::Request,
    http::StatusCode,
    middleware::{Next, from_fn},
    response::IntoResponse,
    routing::get,
};
use philharmonic_api::{
    AuthContext, AuthzState, ErrorCode, ErrorEnvelope, RequestContext, RequestInstanceScope,
    RequestScope, RequiredPermission, authorize,
};
use philharmonic_policy::{
    MintingAuthority, Principal, PrincipalKind, RoleDefinition, RoleMembership, Tenant, atom,
};
use philharmonic_store::{ContentStore, EntityRefValue, RevisionRow};
use philharmonic_types::{ContentValue, EntityId, ScalarValue, Sha256, UnixMillis, Uuid};
use tower::ServiceExt;

mod common;

const REQUIRED_ATOM: &str = atom::AUDIT_READ;

async fn ok_handler() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok" }))
}

fn router(
    store: Arc<common::MockStore>,
    scope: RequestScope,
    auth: Option<AuthContext>,
    required_permission: Option<RequiredPermission>,
    request_instance_scope: Option<Uuid>,
) -> Router {
    let mut router = Router::new().route("/protected", get(ok_handler));
    router = router.layer(from_fn(authorize));

    if let Some(required_permission) = required_permission {
        router = router.layer(Extension(required_permission));
    }

    if let Some(instance_scope) = request_instance_scope {
        router = router.layer(Extension(RequestInstanceScope(instance_scope)));
    }

    router
        .layer(Extension(AuthzState::new(store)))
        .layer(from_fn(move |mut request: Request, next: Next| {
            let scope = scope.clone();
            let auth = auth.clone();
            async move {
                request.extensions_mut().insert(RequestContext {
                    correlation_id: uuid::Uuid::new_v4(),
                    started_at: Instant::now(),
                    scope,
                    auth,
                });
                next.run(request).await
            }
        }))
}

fn request() -> axum::http::Request<axum::body::Body> {
    axum::http::Request::builder()
        .uri("/protected")
        .body(axum::body::Body::empty())
        .unwrap()
}

async fn response_json(response: axum::response::Response) -> serde_json::Value {
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&body).unwrap()
}

async fn error_envelope(response: axum::response::Response) -> (String, ErrorEnvelope) {
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_text = String::from_utf8(body.to_vec()).unwrap();
    let envelope = serde_json::from_slice(&body).unwrap();
    (body_text, envelope)
}

fn tenant(store: &common::MockStore) -> EntityId<Tenant> {
    let tenant = common::new_typed_id::<Tenant>();
    store.insert_entity(tenant);
    store.insert_revision(RevisionRow {
        entity_id: tenant.internal().as_uuid(),
        revision_seq: 1,
        created_at: UnixMillis(2),
        content_attrs: HashMap::new(),
        entity_attrs: HashMap::new(),
        scalar_attrs: HashMap::from([("status".to_string(), ScalarValue::I64(0))]),
    });
    tenant
}

fn principal(store: &common::MockStore, tenant: EntityId<Tenant>) -> EntityId<Principal> {
    let principal = common::new_typed_id::<Principal>();
    store.insert_entity(principal);
    store.insert_revision(RevisionRow {
        entity_id: principal.internal().as_uuid(),
        revision_seq: 1,
        created_at: UnixMillis(2),
        content_attrs: HashMap::new(),
        entity_attrs: HashMap::from([(
            "tenant".to_string(),
            EntityRefValue::latest(tenant.internal().as_uuid()),
        )]),
        scalar_attrs: HashMap::from([
            (
                "kind".to_string(),
                ScalarValue::I64(PrincipalKind::User.as_i64()),
            ),
            ("epoch".to_string(), ScalarValue::I64(0)),
            ("is_retired".to_string(), ScalarValue::Bool(false)),
        ]),
    });
    principal
}

async fn role_with_permissions(
    store: &common::MockStore,
    tenant: EntityId<Tenant>,
    permissions_json: &[u8],
) -> EntityId<RoleDefinition> {
    let role = common::new_typed_id::<RoleDefinition>();
    let permissions = put_content(store, permissions_json).await;
    store.insert_entity(role);
    store.insert_revision(RevisionRow {
        entity_id: role.internal().as_uuid(),
        revision_seq: 1,
        created_at: UnixMillis(2),
        content_attrs: HashMap::from([("permissions".to_string(), permissions)]),
        entity_attrs: HashMap::from([(
            "tenant".to_string(),
            EntityRefValue::latest(tenant.internal().as_uuid()),
        )]),
        scalar_attrs: HashMap::from([("is_retired".to_string(), ScalarValue::Bool(false))]),
    });
    role
}

fn membership(
    store: &common::MockStore,
    tenant: EntityId<Tenant>,
    principal: EntityId<Principal>,
    role: EntityId<RoleDefinition>,
) {
    let membership = common::new_typed_id::<RoleMembership>();
    store.insert_entity(membership);
    store.insert_revision(RevisionRow {
        entity_id: membership.internal().as_uuid(),
        revision_seq: 1,
        created_at: UnixMillis(2),
        content_attrs: HashMap::new(),
        entity_attrs: HashMap::from([
            (
                "tenant".to_string(),
                EntityRefValue::latest(tenant.internal().as_uuid()),
            ),
            (
                "principal".to_string(),
                EntityRefValue::latest(principal.internal().as_uuid()),
            ),
            (
                "role".to_string(),
                EntityRefValue::latest(role.internal().as_uuid()),
            ),
        ]),
        scalar_attrs: HashMap::from([("is_retired".to_string(), ScalarValue::Bool(false))]),
    });
}

async fn put_content(store: &common::MockStore, bytes: &[u8]) -> Sha256 {
    let value = ContentValue::new(bytes.to_vec());
    let hash = value.digest();
    store.put(&value).await.unwrap();
    hash
}

async fn principal_auth_with_permissions(
    store: &common::MockStore,
    tenant: EntityId<Tenant>,
    permissions_json: &[u8],
) -> AuthContext {
    let principal = principal(store, tenant);
    let role = role_with_permissions(store, tenant, permissions_json).await;
    membership(store, tenant, principal, role);
    AuthContext::Principal {
        principal_id: principal,
        tenant_id: tenant,
    }
}

fn ephemeral_auth(tenant: EntityId<Tenant>, permissions: Vec<&'static str>) -> AuthContext {
    AuthContext::Ephemeral {
        subject: "subject-42".to_string(),
        tenant_id: tenant,
        authority_id: common::new_typed_id::<MintingAuthority>(),
        permissions: permissions
            .into_iter()
            .map(std::string::ToString::to_string)
            .collect(),
        injected_claims: serde_json::json!({}),
        instance_scope: None,
    }
}

fn required_permission() -> Option<RequiredPermission> {
    Some(RequiredPermission(REQUIRED_ATOM))
}

#[tokio::test]
async fn principal_happy_path_allows_granted_permission() {
    let store = common::MockStore::new();
    let tenant = tenant(&store);
    let auth = principal_auth_with_permissions(&store, tenant, br#"["audit:read"]"#).await;

    let response = router(
        store,
        RequestScope::Tenant(tenant),
        Some(auth),
        required_permission(),
        None,
    )
    .oneshot(request())
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response_json(response).await["status"], "ok");
}

#[tokio::test]
async fn principal_permission_denied_returns_403() {
    let store = common::MockStore::new();
    let tenant = tenant(&store);
    let auth =
        principal_auth_with_permissions(&store, tenant, br#"["workflow:template_read"]"#).await;

    let response = router(
        store,
        RequestScope::Tenant(tenant),
        Some(auth),
        required_permission(),
        None,
    )
    .oneshot(request())
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn ephemeral_happy_path_allows_claim_permission() {
    let store = common::MockStore::new();
    let tenant = tenant(&store);
    let auth = ephemeral_auth(tenant, vec![REQUIRED_ATOM]);

    let response = router(
        store,
        RequestScope::Tenant(tenant),
        Some(auth),
        required_permission(),
        None,
    )
    .oneshot(request())
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn ephemeral_permission_denied_returns_403() {
    let store = common::MockStore::new();
    let tenant = tenant(&store);
    let auth = ephemeral_auth(tenant, vec![atom::WORKFLOW_TEMPLATE_READ]);

    let response = router(
        store,
        RequestScope::Tenant(tenant),
        Some(auth),
        required_permission(),
        None,
    )
    .oneshot(request())
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn tenant_scope_mismatch_returns_403() {
    let store = common::MockStore::new();
    let auth_tenant = tenant(&store);
    let request_tenant = tenant(&store);
    let auth = ephemeral_auth(auth_tenant, vec![REQUIRED_ATOM]);

    let response = router(
        store,
        RequestScope::Tenant(request_tenant),
        Some(auth),
        required_permission(),
        None,
    )
    .oneshot(request())
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn operator_scope_skips_tenant_check() {
    let store = common::MockStore::new();
    let tenant = tenant(&store);
    let auth = ephemeral_auth(tenant, vec![REQUIRED_ATOM]);

    let response = router(
        store,
        RequestScope::Operator,
        Some(auth),
        required_permission(),
        None,
    )
    .oneshot(request())
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn unauthenticated_caller_on_protected_endpoint_returns_403() {
    let store = common::MockStore::new();
    let tenant = tenant(&store);

    let response = router(
        store,
        RequestScope::Tenant(tenant),
        None,
        required_permission(),
        None,
    )
    .oneshot(request())
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn public_endpoint_without_required_permission_skips_authz() {
    let store = common::MockStore::new();
    let tenant = tenant(&store);

    let response = router(store, RequestScope::Tenant(tenant), None, None, None)
        .oneshot(request())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn forbidden_response_has_structured_envelope_without_sensitive_details() {
    let store = common::MockStore::new();
    let tenant = tenant(&store);
    let auth = ephemeral_auth(tenant, vec![atom::WORKFLOW_TEMPLATE_READ]);

    let response = router(
        store,
        RequestScope::Tenant(tenant),
        Some(auth),
        required_permission(),
        None,
    )
    .oneshot(request())
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let (body_text, envelope) = error_envelope(response).await;

    assert_eq!(envelope.error.code, ErrorCode::Forbidden);
    assert_ne!(envelope.error.correlation_id, uuid::Uuid::nil());
    assert!(envelope.error.details.is_none());
    assert!(!body_text.contains(REQUIRED_ATOM));
    assert!(!body_text.contains("subject-42"));
}

#[tokio::test]
async fn ephemeral_instance_scope_mismatch_returns_403_when_request_scope_is_attached() {
    let store = common::MockStore::new();
    let tenant = tenant(&store);
    let instance_scope = Uuid::new_v4();
    let mut auth = ephemeral_auth(tenant, vec![REQUIRED_ATOM]);
    if let AuthContext::Ephemeral {
        instance_scope: auth_instance_scope,
        ..
    } = &mut auth
    {
        *auth_instance_scope = Some(instance_scope);
    }

    let response = router(
        store,
        RequestScope::Tenant(tenant),
        Some(auth),
        required_permission(),
        Some(Uuid::new_v4()),
    )
    .oneshot(request())
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn ephemeral_instance_scope_is_irrelevant_without_request_instance_id() {
    let store = common::MockStore::new();
    let tenant = tenant(&store);
    let mut auth = ephemeral_auth(tenant, vec![REQUIRED_ATOM]);
    if let AuthContext::Ephemeral { instance_scope, .. } = &mut auth {
        *instance_scope = Some(Uuid::new_v4());
    }

    let response = router(
        store,
        RequestScope::Tenant(tenant),
        Some(auth),
        required_permission(),
        None,
    )
    .oneshot(request())
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}
