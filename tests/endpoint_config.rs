use std::{collections::HashMap, sync::Arc};

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use philharmonic_api::{ApiStore, RequestScope};
use philharmonic_policy::{
    Principal, PrincipalKind, RoleDefinition, RoleMembership, Sck, Tenant, TenantEndpointConfig,
    TenantStatus, TokenHash, atom, generate_api_token, sck_encrypt,
};
use philharmonic_store::{
    ContentStore, EntityRefValue, EntityStoreExt, IdentityStore, RevisionRow,
};
use philharmonic_types::{
    CanonicalJson, ContentValue, EntityId, JsonValue, ScalarValue, Sha256, UnixMillis,
};
use serde_json::json;
use tower::ServiceExt;

mod common;

const SCK_BYTES: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];
const KEY_VERSION: i64 = 11;

struct Fixture {
    router: axum::Router,
    store: Arc<common::MockStore>,
    principal_token: String,
}

async fn fixture(permissions: &[&str]) -> Fixture {
    let store = common::MockStore::new();
    let tenant = active_tenant(&store);
    let (principal_token, token_hash) = generate_api_token();
    let principal = principal(&store, tenant, token_hash_content_hash(token_hash), false);
    let role = role_with_permissions(&store, tenant, permissions).await;
    membership(&store, tenant, principal, role);
    let router = router(store.clone(), tenant, Some(Sck::from_bytes(SCK_BYTES)));

    Fixture {
        router,
        store,
        principal_token: principal_token.to_string(),
    }
}

fn router(store: Arc<dyn ApiStore>, tenant: EntityId<Tenant>, sck: Option<Sck>) -> axum::Router {
    let mut builder = common::builder(
        Arc::new(common::FixedResolver::new(RequestScope::Tenant(tenant))),
        store,
        common::test_api_verifying_key_registry(),
    )
    .key_version(KEY_VERSION);
    if let Some(sck) = sck {
        builder = builder.sck(sck);
    }
    builder.build().unwrap().into_router()
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

async fn create_endpoint(
    router: axum::Router,
    token: &str,
    display_name: &str,
    config: JsonValue,
) -> philharmonic_types::Uuid {
    let response = router
        .oneshot(json_request(
            "POST",
            "/v1/endpoints",
            token,
            json!({
                "display_name": display_name,
                "config": config
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    response_json(response).await["endpoint_id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap()
}

async fn stored_ciphertext(
    store: &common::MockStore,
    endpoint_id: philharmonic_types::Uuid,
) -> Vec<u8> {
    let identity = store
        .resolve_public(endpoint_id)
        .await
        .unwrap()
        .unwrap()
        .typed::<TenantEndpointConfig>()
        .unwrap();
    let latest = store
        .get_latest_revision_typed::<TenantEndpointConfig>(identity)
        .await
        .unwrap()
        .unwrap();
    let hash = latest.content_attrs["encrypted_config"];
    store.get(hash).await.unwrap().unwrap().bytes().to_vec()
}

async fn seed_endpoint_for_tenant(
    store: &common::MockStore,
    tenant: EntityId<Tenant>,
    display_name: &str,
    config: JsonValue,
) -> EntityId<TenantEndpointConfig> {
    let endpoint = common::new_typed_id::<TenantEndpointConfig>();
    store.insert_entity(endpoint);
    let canonical = CanonicalJson::from_value(&config).unwrap();
    let wire = sck_encrypt(
        &Sck::from_bytes(SCK_BYTES),
        canonical.as_bytes(),
        tenant.internal().as_uuid(),
        endpoint.internal().as_uuid(),
        KEY_VERSION,
    )
    .unwrap();
    let display_name = CanonicalJson::from_value(&JsonValue::String(display_name.to_string()))
        .unwrap()
        .into_bytes();
    let encrypted_hash = put_content(store, &wire).await;
    let display_name_hash = put_content(store, &display_name).await;
    store.insert_revision(RevisionRow {
        entity_id: endpoint.internal().as_uuid(),
        revision_seq: 0,
        created_at: UnixMillis(8),
        content_attrs: HashMap::from([
            ("display_name".to_string(), display_name_hash),
            ("encrypted_config".to_string(), encrypted_hash),
        ]),
        entity_attrs: HashMap::from([(
            "tenant".to_string(),
            EntityRefValue::pinned(tenant.internal().as_uuid(), 0),
        )]),
        scalar_attrs: HashMap::from([
            ("key_version".to_string(), ScalarValue::I64(KEY_VERSION)),
            ("is_retired".to_string(), ScalarValue::Bool(false)),
        ]),
    });
    endpoint
}

#[tokio::test]
async fn create_read_metadata_and_read_decrypted_round_trip() {
    let fixture = fixture(&[
        atom::ENDPOINT_CREATE,
        atom::ENDPOINT_READ_METADATA,
        atom::ENDPOINT_READ_DECRYPTED,
    ])
    .await;
    let config = json!({
        "realm": "mysql",
        "impl": "mysql",
        "config": { "dsn": "postgres://example", "secret": "secret-token" }
    });
    let endpoint_id = create_endpoint(
        fixture.router.clone(),
        &fixture.principal_token,
        "Primary DB",
        config.clone(),
    )
    .await;

    let response = fixture
        .router
        .clone()
        .oneshot(empty_request(
            "GET",
            &format!("/v1/endpoints/{endpoint_id}"),
            &fixture.principal_token,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let metadata = response_json(response).await;
    assert_eq!(metadata["endpoint_id"], endpoint_id.to_string());
    assert_eq!(metadata["display_name"], "Primary DB");
    assert_eq!(metadata["is_retired"], false);
    assert_eq!(metadata["key_version"], KEY_VERSION);

    let response = fixture
        .router
        .oneshot(empty_request(
            "GET",
            &format!("/v1/endpoints/{endpoint_id}/decrypted"),
            &fixture.principal_token,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response_json(response).await, config);
}

#[tokio::test]
async fn rotate_endpoint_updates_decrypted_config() {
    let fixture = fixture(&[
        atom::ENDPOINT_CREATE,
        atom::ENDPOINT_ROTATE,
        atom::ENDPOINT_READ_DECRYPTED,
    ])
    .await;
    let endpoint_id = create_endpoint(
        fixture.router.clone(),
        &fixture.principal_token,
        "Primary DB",
        json!({ "config": { "secret": "old" } }),
    )
    .await;
    let new_config = json!({ "config": { "secret": "new" } });

    let response = fixture
        .router
        .clone()
        .oneshot(json_request(
            "POST",
            &format!("/v1/endpoints/{endpoint_id}/rotate"),
            &fixture.principal_token,
            json!({ "config": new_config }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response_json(response).await["latest_revision"], 1);

    let response = fixture
        .router
        .oneshot(empty_request(
            "GET",
            &format!("/v1/endpoints/{endpoint_id}/decrypted"),
            &fixture.principal_token,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response_json(response).await, new_config);
}

#[tokio::test]
async fn retire_endpoint_marks_latest_revision_retired() {
    let fixture = fixture(&[
        atom::ENDPOINT_CREATE,
        atom::ENDPOINT_READ_METADATA,
        atom::ENDPOINT_RETIRE,
    ])
    .await;
    let endpoint_id = create_endpoint(
        fixture.router.clone(),
        &fixture.principal_token,
        "Retirable",
        json!({ "config": { "secret": "soon-retired" } }),
    )
    .await;

    let response = fixture
        .router
        .clone()
        .oneshot(empty_request(
            "POST",
            &format!("/v1/endpoints/{endpoint_id}/retire"),
            &fixture.principal_token,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response_json(response).await["is_retired"], true);

    let response = fixture
        .router
        .oneshot(empty_request(
            "GET",
            &format!("/v1/endpoints/{endpoint_id}"),
            &fixture.principal_token,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response_json(response).await["is_retired"], true);
}

#[tokio::test]
async fn list_endpoints_uses_cursor_pagination() {
    let fixture = fixture(&[atom::ENDPOINT_CREATE, atom::ENDPOINT_READ_METADATA]).await;
    let mut created = Vec::new();
    for index in 0..3 {
        created.push(
            create_endpoint(
                fixture.router.clone(),
                &fixture.principal_token,
                &format!("Endpoint {index}"),
                json!({ "config": { "index": index } }),
            )
            .await,
        );
    }

    let response = fixture
        .router
        .clone()
        .oneshot(empty_request(
            "GET",
            "/v1/endpoints?limit=2",
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
            &format!("/v1/endpoints?limit=2&cursor={cursor}"),
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
        .filter_map(|item| item["endpoint_id"].as_str())
        .collect::<Vec<_>>();
    for id in created {
        assert!(listed.iter().any(|listed_id| *listed_id == id.to_string()));
    }
}

#[tokio::test]
async fn read_decrypted_without_permission_is_forbidden() {
    let fixture = fixture(&[atom::ENDPOINT_CREATE, atom::ENDPOINT_READ_METADATA]).await;
    let endpoint_id = create_endpoint(
        fixture.router.clone(),
        &fixture.principal_token,
        "Forbidden decrypted read",
        json!({ "config": { "secret": "not-for-this-token" } }),
    )
    .await;

    let response = fixture
        .router
        .oneshot(empty_request(
            "GET",
            &format!("/v1/endpoints/{endpoint_id}/decrypted"),
            &fixture.principal_token,
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn endpoint_routes_without_sck_return_internal_error() {
    let store = common::MockStore::new();
    let tenant = active_tenant(&store);
    let (principal_token, token_hash) = generate_api_token();
    let principal = principal(&store, tenant, token_hash_content_hash(token_hash), false);
    let role = role_with_permissions(&store, tenant, &[atom::ENDPOINT_CREATE]).await;
    membership(&store, tenant, principal, role);
    let router = router(store, tenant, None);

    let response = router
        .oneshot(json_request(
            "POST",
            "/v1/endpoints",
            &principal_token,
            json!({
                "display_name": "Missing SCK",
                "config": { "secret": "not-stored" }
            }),
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let body = response_json(response).await;
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("SCK not configured")
    );
}

#[tokio::test]
async fn metadata_read_contains_no_plaintext_or_ciphertext() {
    let fixture = fixture(&[atom::ENDPOINT_CREATE, atom::ENDPOINT_READ_METADATA]).await;
    let endpoint_id = create_endpoint(
        fixture.router.clone(),
        &fixture.principal_token,
        "Metadata only",
        json!({ "config": { "secret": "secret-token" } }),
    )
    .await;
    let ciphertext = stored_ciphertext(&fixture.store, endpoint_id).await;

    let response = fixture
        .router
        .oneshot(empty_request(
            "GET",
            &format!("/v1/endpoints/{endpoint_id}"),
            &fixture.principal_token,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response_body_string(response).await;
    let metadata: JsonValue = serde_json::from_str(&body).unwrap();

    assert!(metadata.get("config").is_none());
    assert!(metadata.get("encrypted_config").is_none());
    assert!(!body.contains("secret-token"));
    assert!(
        !body
            .as_bytes()
            .windows(ciphertext.len())
            .any(|window| window == ciphertext)
    );
}

#[tokio::test]
async fn cross_tenant_read_returns_not_found() {
    let fixture = fixture(&[atom::ENDPOINT_READ_METADATA]).await;
    let other_tenant = active_tenant(&fixture.store);
    let endpoint = seed_endpoint_for_tenant(
        &fixture.store,
        other_tenant,
        "Other tenant",
        json!({ "config": { "secret": "other" } }),
    )
    .await;

    let response = fixture
        .router
        .oneshot(empty_request(
            "GET",
            &format!("/v1/endpoints/{}", endpoint.public().as_uuid()),
            &fixture.principal_token,
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}
