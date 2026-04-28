use std::{collections::HashMap, sync::Arc};

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use philharmonic_api::{ApiStore, RequestScope};
use philharmonic_policy::{
    Principal, PrincipalKind, RoleDefinition, RoleMembership, Tenant, TenantStatus, TokenHash,
    atom, generate_api_token,
};
use philharmonic_store::{ContentStore, EntityRefValue, RevisionRow};
use philharmonic_types::{
    CanonicalJson, ContentValue, EntityId, JsonValue, ScalarValue, Sha256, UnixMillis, Uuid,
};
use serde_json::json;
use tower::ServiceExt;

mod common;

struct Fixture {
    router: axum::Router,
    store: Arc<common::MockStore>,
    tenant: EntityId<Tenant>,
    principal_token: String,
}

async fn fixture(permissions: &[&str]) -> Fixture {
    let store = common::MockStore::new();
    let tenant = active_tenant(&store);
    let (principal_token, token_hash) = generate_api_token();
    let principal = seed_principal(
        &store,
        tenant,
        "Admin",
        PrincipalKind::User,
        Some(token_hash_content_hash(token_hash)),
        false,
    )
    .await;
    let role = seed_role(&store, tenant, "Admin role", permissions, false).await;
    seed_membership(&store, tenant, principal, role, false);
    let router = router(store.clone(), tenant);

    Fixture {
        router,
        store,
        tenant,
        principal_token: principal_token.to_string(),
    }
}

fn router(store: Arc<dyn ApiStore>, tenant: EntityId<Tenant>) -> axum::Router {
    common::builder(
        Arc::new(common::FixedResolver::new(RequestScope::Tenant(tenant))),
        store,
        common::test_api_verifying_key_registry(),
    )
    .build()
    .unwrap()
    .into_router()
}

fn active_tenant(store: &common::MockStore) -> EntityId<Tenant> {
    let tenant = common::new_typed_id::<Tenant>();
    store.insert_entity(tenant);
    store.insert_revision(RevisionRow {
        entity_id: tenant.internal().as_uuid(),
        revision_seq: 0,
        created_at: UnixMillis(1),
        content_attrs: HashMap::new(),
        entity_attrs: HashMap::new(),
        scalar_attrs: HashMap::from([(
            "status".to_string(),
            ScalarValue::I64(TenantStatus::Active.as_i64()),
        )]),
    });
    tenant
}

async fn seed_principal(
    store: &common::MockStore,
    tenant: EntityId<Tenant>,
    display_name: &str,
    kind: PrincipalKind,
    credential_hash: Option<Sha256>,
    is_retired: bool,
) -> EntityId<Principal> {
    let principal = common::new_typed_id::<Principal>();
    let display_name = put_json(store, &JsonValue::String(display_name.to_string())).await;
    let mut content_attrs = HashMap::from([("display_name".to_string(), display_name)]);
    if let Some(credential_hash) = credential_hash {
        content_attrs.insert("credential_hash".to_string(), credential_hash);
    }
    store.insert_entity(principal);
    store.insert_revision(RevisionRow {
        entity_id: principal.internal().as_uuid(),
        revision_seq: 0,
        created_at: UnixMillis(2),
        content_attrs,
        entity_attrs: HashMap::from([(
            "tenant".to_string(),
            EntityRefValue::pinned(tenant.internal().as_uuid(), 0),
        )]),
        scalar_attrs: HashMap::from([
            ("kind".to_string(), ScalarValue::I64(kind.as_i64())),
            ("epoch".to_string(), ScalarValue::I64(0)),
            ("is_retired".to_string(), ScalarValue::Bool(is_retired)),
        ]),
    });
    principal
}

async fn seed_role(
    store: &common::MockStore,
    tenant: EntityId<Tenant>,
    display_name: &str,
    permissions: &[&str],
    is_retired: bool,
) -> EntityId<RoleDefinition> {
    let role = common::new_typed_id::<RoleDefinition>();
    let display_name = put_json(store, &JsonValue::String(display_name.to_string())).await;
    let permissions = serde_json::to_vec(permissions).unwrap();
    let permissions = put_content(store, &permissions).await;
    store.insert_entity(role);
    store.insert_revision(RevisionRow {
        entity_id: role.internal().as_uuid(),
        revision_seq: 0,
        created_at: UnixMillis(3),
        content_attrs: HashMap::from([
            ("display_name".to_string(), display_name),
            ("permissions".to_string(), permissions),
        ]),
        entity_attrs: HashMap::from([(
            "tenant".to_string(),
            EntityRefValue::pinned(tenant.internal().as_uuid(), 0),
        )]),
        scalar_attrs: HashMap::from([("is_retired".to_string(), ScalarValue::Bool(is_retired))]),
    });
    role
}

fn seed_membership(
    store: &common::MockStore,
    tenant: EntityId<Tenant>,
    principal: EntityId<Principal>,
    role: EntityId<RoleDefinition>,
    is_retired: bool,
) -> EntityId<RoleMembership> {
    let membership = common::new_typed_id::<RoleMembership>();
    store.insert_entity(membership);
    store.insert_revision(RevisionRow {
        entity_id: membership.internal().as_uuid(),
        revision_seq: 0,
        created_at: UnixMillis(4),
        content_attrs: HashMap::new(),
        entity_attrs: HashMap::from([
            (
                "tenant".to_string(),
                EntityRefValue::pinned(tenant.internal().as_uuid(), 0),
            ),
            (
                "principal".to_string(),
                EntityRefValue::pinned(principal.internal().as_uuid(), 0),
            ),
            (
                "role".to_string(),
                EntityRefValue::pinned(role.internal().as_uuid(), 0),
            ),
        ]),
        scalar_attrs: HashMap::from([("is_retired".to_string(), ScalarValue::Bool(is_retired))]),
    });
    membership
}

async fn put_json(store: &common::MockStore, value: &JsonValue) -> Sha256 {
    let canonical = CanonicalJson::from_value(value).unwrap();
    put_content(store, canonical.as_bytes()).await
}

async fn put_content(store: &common::MockStore, bytes: &[u8]) -> Sha256 {
    let value = ContentValue::new(bytes.to_vec());
    let hash = value.digest();
    store.put(&value).await.unwrap();
    hash
}

fn token_hash_content_hash(token_hash: TokenHash) -> Sha256 {
    ContentValue::new(token_hash.0.to_vec()).digest()
}

fn json_request(method: &str, uri: &str, token: &str, body: JsonValue) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap()
}

fn empty_request(method: &str, uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

async fn response_json(response: axum::response::Response) -> JsonValue {
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&body).unwrap()
}

async fn response_body_string(response: axum::response::Response) -> String {
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    String::from_utf8(body.to_vec()).unwrap()
}

async fn create_principal(router: axum::Router, token: &str, display_name: &str) -> (Uuid, String) {
    let response = router
        .oneshot(json_request(
            "POST",
            "/v1/principals",
            token,
            json!({
                "display_name": display_name,
                "kind": "service"
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let body = response_json(response).await;
    let principal_id = body["principal_id"].as_str().unwrap().parse().unwrap();
    let token = body["token"].as_str().unwrap().to_string();
    (principal_id, token)
}

async fn create_role(
    router: axum::Router,
    token: &str,
    display_name: &str,
    permissions: &[&str],
) -> Uuid {
    let response = router
        .oneshot(json_request(
            "POST",
            "/v1/roles",
            token,
            json!({
                "display_name": display_name,
                "permissions": permissions
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    response_json(response).await["role_id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap()
}

async fn create_membership(
    router: axum::Router,
    token: &str,
    principal_id: Uuid,
    role_id: Uuid,
) -> Uuid {
    let response = router
        .oneshot(json_request(
            "POST",
            "/v1/role-memberships",
            token,
            json!({
                "principal_id": principal_id.to_string(),
                "role_id": role_id.to_string()
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    response_json(response).await["membership_id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap()
}

#[tokio::test]
async fn principal_lifecycle_create_list_rotate_new_token_and_retire() {
    let fixture = fixture(&[atom::TENANT_PRINCIPAL_MANAGE, atom::TENANT_ROLE_MANAGE]).await;
    let (principal_id, first_token) = create_principal(
        fixture.router.clone(),
        &fixture.principal_token,
        "Worker principal",
    )
    .await;
    assert!(first_token.starts_with("pht_"));

    let response = fixture
        .router
        .clone()
        .oneshot(empty_request(
            "GET",
            "/v1/principals",
            &fixture.principal_token,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let listed = response_json(response).await;
    assert!(
        listed["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["principal_id"] == principal_id.to_string())
    );

    let self_manage_role = create_role(
        fixture.router.clone(),
        &fixture.principal_token,
        "Principal manager",
        &[atom::TENANT_PRINCIPAL_MANAGE],
    )
    .await;
    create_membership(
        fixture.router.clone(),
        &fixture.principal_token,
        principal_id,
        self_manage_role,
    )
    .await;

    let response = fixture
        .router
        .clone()
        .oneshot(empty_request(
            "POST",
            &format!("/v1/principals/{principal_id}/rotate"),
            &fixture.principal_token,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let rotated = response_json(response).await;
    let rotated_token = rotated["token"].as_str().unwrap();
    assert_ne!(rotated_token, first_token);

    let response = fixture
        .router
        .clone()
        .oneshot(empty_request("GET", "/v1/principals", rotated_token))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let response = fixture
        .router
        .clone()
        .oneshot(empty_request(
            "POST",
            &format!("/v1/principals/{principal_id}/retire"),
            &fixture.principal_token,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response_json(response).await["is_retired"], true);
}

#[tokio::test]
async fn token_returned_only_once_for_principal_create() {
    let fixture = fixture(&[atom::TENANT_PRINCIPAL_MANAGE]).await;
    let (principal_id, token) = create_principal(
        fixture.router.clone(),
        &fixture.principal_token,
        "One time token",
    )
    .await;

    let response = fixture
        .router
        .oneshot(empty_request(
            "GET",
            "/v1/principals",
            &fixture.principal_token,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response_body_string(response).await;
    assert!(!body.contains(&token));
    assert!(!body.contains("\"token\""));
    assert!(body.contains(&principal_id.to_string()));
}

#[tokio::test]
async fn role_lifecycle_create_list_modify_and_retire() {
    let fixture = fixture(&[atom::TENANT_ROLE_MANAGE]).await;
    let role_id = create_role(
        fixture.router.clone(),
        &fixture.principal_token,
        "Auditor",
        &[atom::AUDIT_READ],
    )
    .await;

    let response = fixture
        .router
        .clone()
        .oneshot(empty_request("GET", "/v1/roles", &fixture.principal_token))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let listed = response_json(response).await;
    assert!(
        listed["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["role_id"] == role_id.to_string())
    );

    let response = fixture
        .router
        .clone()
        .oneshot(json_request(
            "PATCH",
            &format!("/v1/roles/{role_id}"),
            &fixture.principal_token,
            json!({
                "display_name": "Workflow operator",
                "permissions": [atom::WORKFLOW_INSTANCE_EXECUTE]
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let updated = response_json(response).await;
    assert_eq!(updated["display_name"], "Workflow operator");
    assert_eq!(updated["latest_revision"], 1);

    let response = fixture
        .router
        .oneshot(empty_request(
            "POST",
            &format!("/v1/roles/{role_id}/retire"),
            &fixture.principal_token,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response_json(response).await["is_retired"], true);
}

#[tokio::test]
async fn membership_assign_list_and_remove() {
    let fixture = fixture(&[atom::TENANT_PRINCIPAL_MANAGE, atom::TENANT_ROLE_MANAGE]).await;
    let (principal_id, _token) = create_principal(
        fixture.router.clone(),
        &fixture.principal_token,
        "Role subject",
    )
    .await;
    let role_id = create_role(
        fixture.router.clone(),
        &fixture.principal_token,
        "Audit reader",
        &[atom::AUDIT_READ],
    )
    .await;
    let membership_id = create_membership(
        fixture.router.clone(),
        &fixture.principal_token,
        principal_id,
        role_id,
    )
    .await;

    let response = fixture
        .router
        .clone()
        .oneshot(empty_request(
            "GET",
            "/v1/role-memberships",
            &fixture.principal_token,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let listed = response_json(response).await;
    assert!(
        listed["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["membership_id"] == membership_id.to_string()
                && item["principal_id"] == principal_id.to_string()
                && item["role_id"] == role_id.to_string())
    );

    let response = fixture
        .router
        .oneshot(empty_request(
            "DELETE",
            &format!("/v1/role-memberships/{membership_id}"),
            &fixture.principal_token,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response_json(response).await["is_retired"], true);
}

#[tokio::test]
async fn authority_lifecycle_create_list_bump_rotate_modify_and_retire() {
    let fixture = fixture(&[atom::TENANT_MINTING_MANAGE]).await;
    let response = fixture
        .router
        .clone()
        .oneshot(json_request(
            "POST",
            "/v1/minting-authorities",
            &fixture.principal_token,
            json!({
                "display_name": "Browser sessions",
                "permission_envelope": [atom::WORKFLOW_INSTANCE_EXECUTE],
                "max_lifetime_seconds": 600
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let created = response_json(response).await;
    let authority_id: Uuid = created["authority_id"].as_str().unwrap().parse().unwrap();
    let first_token = created["token"].as_str().unwrap().to_string();
    assert!(first_token.starts_with("pht_"));

    let response = fixture
        .router
        .clone()
        .oneshot(empty_request(
            "GET",
            "/v1/minting-authorities",
            &fixture.principal_token,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let list_body = response_body_string(response).await;
    assert!(!list_body.contains(&first_token));
    let listed: JsonValue = serde_json::from_str(&list_body).unwrap();
    assert!(
        listed["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["authority_id"] == authority_id.to_string()
                && item["max_lifetime_seconds"] == 600)
    );

    let response = fixture
        .router
        .clone()
        .oneshot(empty_request(
            "POST",
            &format!("/v1/minting-authorities/{authority_id}/bump-epoch"),
            &fixture.principal_token,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response_json(response).await["epoch"], 1);

    let response = fixture
        .router
        .clone()
        .oneshot(empty_request(
            "POST",
            &format!("/v1/minting-authorities/{authority_id}/rotate"),
            &fixture.principal_token,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let rotated = response_json(response).await;
    assert_ne!(rotated["token"].as_str().unwrap(), first_token);

    let response = fixture
        .router
        .clone()
        .oneshot(json_request(
            "PATCH",
            &format!("/v1/minting-authorities/{authority_id}"),
            &fixture.principal_token,
            json!({
                "permission_envelope": [
                    atom::WORKFLOW_INSTANCE_EXECUTE,
                    atom::AUDIT_READ
                ],
                "max_lifetime_seconds": 300
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let updated = response_json(response).await;
    assert_eq!(updated["max_lifetime_seconds"], 300);
    assert_eq!(updated["epoch"], 1);

    let response = fixture
        .router
        .oneshot(empty_request(
            "POST",
            &format!("/v1/minting-authorities/{authority_id}/retire"),
            &fixture.principal_token,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response_json(response).await["is_retired"], true);
}

#[tokio::test]
async fn create_principal_without_permission_returns_403() {
    let fixture = fixture(&[atom::TENANT_ROLE_MANAGE]).await;

    let response = fixture
        .router
        .oneshot(json_request(
            "POST",
            "/v1/principals",
            &fixture.principal_token,
            json!({
                "display_name": "Forbidden",
                "kind": "user"
            }),
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn cross_tenant_principals_are_not_visible() {
    let fixture = fixture(&[atom::TENANT_PRINCIPAL_MANAGE]).await;
    let other_tenant = active_tenant(&fixture.store);
    let (other_token, other_hash) = generate_api_token();
    let other_principal = seed_principal(
        &fixture.store,
        other_tenant,
        "Other tenant",
        PrincipalKind::User,
        Some(token_hash_content_hash(other_hash)),
        false,
    )
    .await;

    let response = fixture
        .router
        .oneshot(empty_request(
            "GET",
            "/v1/principals",
            &fixture.principal_token,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response_body_string(response).await;
    assert!(!body.contains(&other_principal.public().as_uuid().to_string()));
    assert!(!body.contains(other_token.as_str()));
    assert!(body.contains(&fixture.tenant.public().as_uuid().to_string()) || !body.is_empty());
}
