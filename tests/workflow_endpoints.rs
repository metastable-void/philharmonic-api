use std::{collections::HashMap, sync::Arc};

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use philharmonic_api::{ApiStore, RequestScope};
use philharmonic_policy::{
    EphemeralApiTokenClaims, MintingAuthority, Principal, PrincipalKind, RoleDefinition,
    RoleMembership, Tenant, TenantStatus, TokenHash, atom, generate_api_token,
    mint_ephemeral_api_token,
};
use philharmonic_store::{ContentStore, EntityRefValue, RevisionRow};
use philharmonic_types::{
    CanonicalJson, ContentValue, EntityId, JsonValue, ScalarValue, Sha256, UnixMillis,
};
use serde_json::json;
use tower::ServiceExt;

mod common;

struct Fixture {
    router: axum::Router,
    principal_token: String,
    tenant: EntityId<Tenant>,
    authority: EntityId<MintingAuthority>,
}

async fn fixture(permissions: &[&str]) -> Fixture {
    let store = common::MockStore::new();
    let tenant = active_tenant(&store);
    let (principal_token, token_hash) = generate_api_token();
    let principal = principal(&store, tenant, token_hash_content_hash(token_hash), false);
    let role = role_with_permissions(&store, tenant, permissions).await;
    membership(&store, tenant, principal, role);
    let authority = authority(&store, tenant, false, 7);
    let router = router(store, tenant);

    Fixture {
        router,
        principal_token: principal_token.to_string(),
        tenant,
        authority,
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

fn principal(
    store: &common::MockStore,
    tenant: EntityId<Tenant>,
    credential_hash: Sha256,
    is_retired: bool,
) -> EntityId<Principal> {
    let principal = common::new_typed_id::<Principal>();
    store.insert_entity(principal);
    store.insert_revision(RevisionRow {
        entity_id: principal.internal().as_uuid(),
        revision_seq: 0,
        created_at: UnixMillis(2),
        content_attrs: HashMap::from([("credential_hash".to_string(), credential_hash)]),
        entity_attrs: HashMap::from([(
            "tenant".to_string(),
            EntityRefValue::pinned(tenant.internal().as_uuid(), 0),
        )]),
        scalar_attrs: HashMap::from([
            (
                "kind".to_string(),
                ScalarValue::I64(PrincipalKind::User.as_i64()),
            ),
            ("epoch".to_string(), ScalarValue::I64(0)),
            ("is_retired".to_string(), ScalarValue::Bool(is_retired)),
        ]),
    });
    principal
}

async fn role_with_permissions(
    store: &common::MockStore,
    tenant: EntityId<Tenant>,
    permissions: &[&str],
) -> EntityId<RoleDefinition> {
    let role = common::new_typed_id::<RoleDefinition>();
    let permissions = serde_json::to_vec(permissions).unwrap();
    let permissions_hash = put_content(store, &permissions).await;
    store.insert_entity(role);
    store.insert_revision(RevisionRow {
        entity_id: role.internal().as_uuid(),
        revision_seq: 0,
        created_at: UnixMillis(3),
        content_attrs: HashMap::from([("permissions".to_string(), permissions_hash)]),
        entity_attrs: HashMap::from([(
            "tenant".to_string(),
            EntityRefValue::pinned(tenant.internal().as_uuid(), 0),
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
        scalar_attrs: HashMap::from([("is_retired".to_string(), ScalarValue::Bool(false))]),
    });
}

fn authority(
    store: &common::MockStore,
    tenant: EntityId<Tenant>,
    is_retired: bool,
    epoch: i64,
) -> EntityId<MintingAuthority> {
    let authority = common::new_typed_id::<MintingAuthority>();
    store.insert_entity(authority);
    store.insert_revision(RevisionRow {
        entity_id: authority.internal().as_uuid(),
        revision_seq: 0,
        created_at: UnixMillis(5),
        content_attrs: HashMap::new(),
        entity_attrs: HashMap::from([(
            "tenant".to_string(),
            EntityRefValue::pinned(tenant.internal().as_uuid(), 0),
        )]),
        scalar_attrs: HashMap::from([
            ("epoch".to_string(), ScalarValue::I64(epoch)),
            ("is_retired".to_string(), ScalarValue::Bool(is_retired)),
        ]),
    });
    authority
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

fn ephemeral_header(
    tenant: EntityId<Tenant>,
    authority: EntityId<MintingAuthority>,
    instance_scope: philharmonic_types::Uuid,
) -> String {
    let now = UnixMillis::now();
    let claims = EphemeralApiTokenClaims {
        iss: common::TEST_API_ISSUER.to_owned(),
        iat: now,
        exp: UnixMillis(now.as_i64() + 3_600_000),
        sub: "subject-42".to_owned(),
        tenant: tenant.internal().as_uuid(),
        authority: authority.internal().as_uuid(),
        authority_epoch: 7,
        instance: Some(instance_scope),
        permissions: vec![atom::WORKFLOW_INSTANCE_EXECUTE.to_string()],
        claims: CanonicalJson::from_bytes(br#"{"role":"tester"}"#).unwrap(),
        kid: common::TEST_API_KID.to_owned(),
    };
    let token =
        mint_ephemeral_api_token(&common::test_api_signing_key(), &claims, UnixMillis::now())
            .unwrap();
    URL_SAFE_NO_PAD.encode(token.to_bytes().unwrap())
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

async fn create_template(
    router: axum::Router,
    token: &str,
    display_name: &str,
) -> philharmonic_types::Uuid {
    let response = router
        .oneshot(json_request(
            "POST",
            "/v1/workflows/templates",
            token,
            json!({
                "display_name": display_name,
                "script_source": "export default async function main() {}",
                "abstract_config": {}
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    response_json(response).await["template_id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap()
}

async fn create_instance(
    router: axum::Router,
    token: &str,
    template_id: philharmonic_types::Uuid,
) -> philharmonic_types::Uuid {
    let response = router
        .oneshot(json_request(
            "POST",
            "/v1/workflows/instances",
            token,
            json!({
                "template_id": template_id,
                "args": { "conversation_id": "c-1" }
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    response_json(response).await["instance_id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap()
}

#[tokio::test]
async fn template_crud_flow() {
    let fixture = fixture(&[
        atom::WORKFLOW_TEMPLATE_CREATE,
        atom::WORKFLOW_TEMPLATE_READ,
        atom::WORKFLOW_TEMPLATE_RETIRE,
    ])
    .await;
    let template_id =
        create_template(fixture.router.clone(), &fixture.principal_token, "Draft").await;

    let response = fixture
        .router
        .clone()
        .oneshot(empty_request(
            "GET",
            &format!("/v1/workflows/templates/{template_id}"),
            &fixture.principal_token,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response_json(response).await;
    assert_eq!(body["display_name"], "Draft");

    let response = fixture
        .router
        .clone()
        .oneshot(empty_request(
            "GET",
            "/v1/workflows/templates",
            &fixture.principal_token,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response_json(response).await;
    assert!(
        body["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| { item["template_id"].as_str() == Some(&template_id.to_string()) })
    );

    let response = fixture
        .router
        .clone()
        .oneshot(json_request(
            "PATCH",
            &format!("/v1/workflows/templates/{template_id}"),
            &fixture.principal_token,
            json!({
                "display_name": "Published",
                "script_source": "export default async function main() { return true; }"
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response_json(response).await;
    assert_eq!(body["display_name"], "Published");
    assert_eq!(body["latest_revision"], 1);

    let response = fixture
        .router
        .oneshot(empty_request(
            "POST",
            &format!("/v1/workflows/templates/{template_id}/retire"),
            &fixture.principal_token,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response_json(response).await;
    assert_eq!(body["is_retired"], true);
}

#[tokio::test]
async fn instance_lifecycle_flow() {
    let fixture = fixture(&[
        atom::WORKFLOW_TEMPLATE_CREATE,
        atom::WORKFLOW_INSTANCE_CREATE,
        atom::WORKFLOW_INSTANCE_READ,
        atom::WORKFLOW_INSTANCE_EXECUTE,
    ])
    .await;
    let template_id = create_template(
        fixture.router.clone(),
        &fixture.principal_token,
        "Lifecycle",
    )
    .await;
    let instance_id = create_instance(
        fixture.router.clone(),
        &fixture.principal_token,
        template_id,
    )
    .await;

    let response = fixture
        .router
        .clone()
        .oneshot(empty_request(
            "GET",
            &format!("/v1/workflows/instances/{instance_id}"),
            &fixture.principal_token,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response_json(response).await["status"], "pending");

    let response = fixture
        .router
        .clone()
        .oneshot(json_request(
            "POST",
            &format!("/v1/workflows/instances/{instance_id}/execute"),
            &fixture.principal_token,
            json!({ "input": { "message": "hello" } }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response_json(response).await["status"], "running");

    let response = fixture
        .router
        .clone()
        .oneshot(empty_request(
            "GET",
            &format!("/v1/workflows/instances/{instance_id}"),
            &fixture.principal_token,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response_json(response).await["status"], "running");

    let response = fixture
        .router
        .clone()
        .oneshot(empty_request(
            "GET",
            &format!("/v1/workflows/instances/{instance_id}/steps"),
            &fixture.principal_token,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response_json(response).await["items"]
            .as_array()
            .unwrap()
            .len(),
        1
    );

    let response = fixture
        .router
        .oneshot(empty_request(
            "POST",
            &format!("/v1/workflows/instances/{instance_id}/complete"),
            &fixture.principal_token,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response_json(response).await["status"], "completed");
}

#[tokio::test]
async fn create_template_without_permission_is_forbidden() {
    let fixture = fixture(&[atom::WORKFLOW_TEMPLATE_READ]).await;
    let response = fixture
        .router
        .oneshot(json_request(
            "POST",
            "/v1/workflows/templates",
            &fixture.principal_token,
            json!({
                "display_name": "Forbidden",
                "script_source": "export default async function main() {}",
                "abstract_config": {}
            }),
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn instance_scoped_ephemeral_token_cannot_execute_other_instance() {
    let fixture = fixture(&[
        atom::WORKFLOW_TEMPLATE_CREATE,
        atom::WORKFLOW_INSTANCE_CREATE,
        atom::WORKFLOW_INSTANCE_EXECUTE,
    ])
    .await;
    let template_id =
        create_template(fixture.router.clone(), &fixture.principal_token, "Scoped").await;
    let instance_a = create_instance(
        fixture.router.clone(),
        &fixture.principal_token,
        template_id,
    )
    .await;
    let instance_b = create_instance(
        fixture.router.clone(),
        &fixture.principal_token,
        template_id,
    )
    .await;
    let token = ephemeral_header(fixture.tenant, fixture.authority, instance_a);

    let response = fixture
        .router
        .oneshot(json_request(
            "POST",
            &format!("/v1/workflows/instances/{instance_b}/execute"),
            &token,
            json!({ "input": { "message": "wrong instance" } }),
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn template_list_uses_cursor_pagination() {
    let fixture = fixture(&[atom::WORKFLOW_TEMPLATE_CREATE, atom::WORKFLOW_TEMPLATE_READ]).await;
    let mut created = Vec::new();
    for index in 0..3 {
        created.push(
            create_template(
                fixture.router.clone(),
                &fixture.principal_token,
                &format!("Template {index}"),
            )
            .await,
        );
    }

    let response = fixture
        .router
        .clone()
        .oneshot(empty_request(
            "GET",
            "/v1/workflows/templates?limit=2",
            &fixture.principal_token,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let first_page = response_json(response).await;
    assert_eq!(first_page["items"].as_array().unwrap().len(), 2);
    let cursor = first_page["next_cursor"].as_str().unwrap();

    let response = fixture
        .router
        .oneshot(empty_request(
            "GET",
            &format!("/v1/workflows/templates?limit=2&cursor={cursor}"),
            &fixture.principal_token,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let second_page = response_json(response).await;
    assert_eq!(second_page["items"].as_array().unwrap().len(), 1);

    let listed = first_page["items"]
        .as_array()
        .unwrap()
        .iter()
        .chain(second_page["items"].as_array().unwrap())
        .filter_map(|item| item["template_id"].as_str())
        .collect::<Vec<_>>();
    for id in created {
        assert!(listed.iter().any(|listed_id| *listed_id == id.to_string()));
    }
}
