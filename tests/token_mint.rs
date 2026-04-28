use std::{collections::HashMap, sync::Arc};

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use philharmonic_api::{ApiStore, ErrorCode, ErrorEnvelope, RequestScope};
use philharmonic_policy::{
    EphemeralApiTokenClaims, MintingAuthority, Principal, PrincipalKind, Tenant, TenantStatus,
    TokenHash, atom, generate_api_token, verify_ephemeral_api_token,
};
use philharmonic_store::{ContentStore, EntityRefValue, RevisionRow};
use philharmonic_types::{
    CanonicalJson, ContentValue, EntityId, JsonValue, ScalarValue, Sha256, UnixMillis, Uuid,
};
use philharmonic_workflow::WorkflowInstance;
use serde_json::json;
use tower::ServiceExt;

mod common;

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

async fn authority(
    store: &common::MockStore,
    tenant: EntityId<Tenant>,
    permission_envelope: &[&str],
    max_lifetime_seconds: u64,
    is_retired: bool,
    epoch: i64,
) -> (EntityId<MintingAuthority>, String) {
    let authority = common::new_typed_id::<MintingAuthority>();
    let (token, token_hash) = generate_api_token();
    let permission_envelope = JsonValue::Array(
        permission_envelope
            .iter()
            .map(|permission| JsonValue::String((*permission).to_string()))
            .collect(),
    );
    let constraints = json!({ "max_lifetime_seconds": max_lifetime_seconds });
    store.insert_entity(authority);
    store.insert_revision(RevisionRow {
        entity_id: authority.internal().as_uuid(),
        revision_seq: 0,
        created_at: UnixMillis(2),
        content_attrs: HashMap::from([
            (
                "credential_hash".to_string(),
                token_hash_content_hash(token_hash),
            ),
            (
                "permission_envelope".to_string(),
                put_json(store, &permission_envelope).await,
            ),
            (
                "minting_constraints".to_string(),
                put_json(store, &constraints).await,
            ),
        ]),
        entity_attrs: HashMap::from([(
            "tenant".to_string(),
            EntityRefValue::pinned(tenant.internal().as_uuid(), 0),
        )]),
        scalar_attrs: HashMap::from([
            ("epoch".to_string(), ScalarValue::I64(epoch)),
            ("is_retired".to_string(), ScalarValue::Bool(is_retired)),
        ]),
    });
    (authority, token.to_string())
}

fn principal(store: &common::MockStore, tenant: EntityId<Tenant>) -> String {
    let principal = common::new_typed_id::<Principal>();
    let (token, token_hash) = generate_api_token();
    store.insert_entity(principal);
    store.insert_revision(RevisionRow {
        entity_id: principal.internal().as_uuid(),
        revision_seq: 0,
        created_at: UnixMillis(3),
        content_attrs: HashMap::from([(
            "credential_hash".to_string(),
            token_hash_content_hash(token_hash),
        )]),
        entity_attrs: HashMap::from([(
            "tenant".to_string(),
            EntityRefValue::pinned(tenant.internal().as_uuid(), 0),
        )]),
        scalar_attrs: HashMap::from([
            (
                "kind".to_string(),
                ScalarValue::I64(PrincipalKind::ServiceAccount.as_i64()),
            ),
            ("epoch".to_string(), ScalarValue::I64(0)),
            ("is_retired".to_string(), ScalarValue::Bool(false)),
        ]),
    });
    token.to_string()
}

fn workflow_instance(
    store: &common::MockStore,
    tenant: EntityId<Tenant>,
) -> EntityId<WorkflowInstance> {
    let instance = common::new_typed_id::<WorkflowInstance>();
    store.insert_entity(instance);
    store.insert_revision(RevisionRow {
        entity_id: instance.internal().as_uuid(),
        revision_seq: 0,
        created_at: UnixMillis(4),
        content_attrs: HashMap::new(),
        entity_attrs: HashMap::from([(
            "tenant".to_string(),
            EntityRefValue::pinned(tenant.internal().as_uuid(), 0),
        )]),
        scalar_attrs: HashMap::from([("status".to_string(), ScalarValue::I64(0))]),
    });
    instance
}

async fn put_json(store: &common::MockStore, value: &JsonValue) -> Sha256 {
    let canonical = CanonicalJson::from_value(value).unwrap();
    let content = ContentValue::new(canonical.as_bytes().to_vec());
    let hash = content.digest();
    store.put(&content).await.unwrap();
    hash
}

fn token_hash_content_hash(token_hash: TokenHash) -> Sha256 {
    ContentValue::new(token_hash.0.to_vec()).digest()
}

fn mint_request(token: &str, body: JsonValue) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/v1/tokens/mint")
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap()
}

async fn response_json(response: axum::response::Response) -> JsonValue {
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&body).unwrap()
}

async fn minted_claims(response: axum::response::Response) -> (JsonValue, EphemeralApiTokenClaims) {
    assert_eq!(response.status(), StatusCode::OK);
    let body = response_json(response).await;
    let token = body["token"].as_str().unwrap();
    let token_bytes = URL_SAFE_NO_PAD.decode(token).unwrap();
    let claims = verify_ephemeral_api_token(
        &token_bytes,
        &common::test_api_verifying_key_registry(),
        UnixMillis::now(),
    )
    .unwrap();
    (body, claims)
}

async fn assert_error(
    response: axum::response::Response,
    status: StatusCode,
    code: ErrorCode,
) -> ErrorEnvelope {
    assert_eq!(response.status(), status);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let envelope: ErrorEnvelope = serde_json::from_slice(&body).unwrap();
    assert_eq!(envelope.error.code, code);
    assert!(envelope.error.details.is_none());
    envelope
}

#[tokio::test]
async fn happy_path_mints_verifiable_token() {
    let store = common::MockStore::new();
    let tenant = active_tenant(&store);
    let (authority, token) = authority(
        &store,
        tenant,
        &[atom::MINT_EPHEMERAL_TOKEN, atom::WORKFLOW_INSTANCE_EXECUTE],
        600,
        false,
        7,
    )
    .await;

    let response = router(store, tenant)
        .oneshot(mint_request(
            &token,
            json!({
                "subject": "subject-42",
                "lifetime_seconds": 300,
                "requested_permissions": [atom::WORKFLOW_INSTANCE_EXECUTE],
                "injected_claims": {
                    "account_tier": "pro",
                    "user_id": "u_12345"
                }
            }),
        ))
        .await
        .unwrap();
    let (body, claims) = minted_claims(response).await;

    assert_eq!(body["subject"], "subject-42");
    assert!(body["expires_at"].as_str().unwrap().ends_with('Z'));
    assert_eq!(claims.iss, common::TEST_API_ISSUER);
    assert_eq!(claims.sub, "subject-42");
    assert_eq!(claims.tenant, tenant.internal().as_uuid());
    assert_eq!(claims.authority, authority.internal().as_uuid());
    assert_eq!(claims.authority_epoch, 7);
    assert_eq!(claims.instance, None);
    assert_eq!(
        claims.permissions,
        vec![atom::WORKFLOW_INSTANCE_EXECUTE.to_string()]
    );
    assert_eq!(claims.kid, common::TEST_API_KID);
    let injected: JsonValue = claims.claims.to_deserializable().unwrap();
    assert_eq!(injected["user_id"], "u_12345");
}

#[tokio::test]
async fn permission_clipping_removes_permissions_outside_envelope() {
    let store = common::MockStore::new();
    let tenant = active_tenant(&store);
    let (_authority, token) = authority(
        &store,
        tenant,
        &[atom::MINT_EPHEMERAL_TOKEN, atom::WORKFLOW_INSTANCE_EXECUTE],
        600,
        false,
        7,
    )
    .await;

    let response = router(store, tenant)
        .oneshot(mint_request(
            &token,
            json!({
                "subject": "subject-42",
                "lifetime_seconds": 300,
                "requested_permissions": [
                    atom::WORKFLOW_INSTANCE_EXECUTE,
                    atom::AUDIT_READ
                ],
                "injected_claims": {}
            }),
        ))
        .await
        .unwrap();
    let (_body, claims) = minted_claims(response).await;

    assert_eq!(
        claims.permissions,
        vec![atom::WORKFLOW_INSTANCE_EXECUTE.to_string()]
    );
}

#[tokio::test]
async fn lifetime_exceeding_authority_max_returns_400() {
    let store = common::MockStore::new();
    let tenant = active_tenant(&store);
    let (_authority, token) =
        authority(&store, tenant, &[atom::MINT_EPHEMERAL_TOKEN], 60, false, 7).await;

    let response = router(store, tenant)
        .oneshot(mint_request(
            &token,
            json!({
                "subject": "subject-42",
                "lifetime_seconds": 61,
                "requested_permissions": [],
                "injected_claims": {}
            }),
        ))
        .await
        .unwrap();

    assert_error(response, StatusCode::BAD_REQUEST, ErrorCode::InvalidRequest).await;
}

#[tokio::test]
async fn oversized_injected_claims_return_400() {
    let store = common::MockStore::new();
    let tenant = active_tenant(&store);
    let (_authority, token) =
        authority(&store, tenant, &[atom::MINT_EPHEMERAL_TOKEN], 600, false, 7).await;

    let response = router(store, tenant)
        .oneshot(mint_request(
            &token,
            json!({
                "subject": "subject-42",
                "lifetime_seconds": 60,
                "requested_permissions": [],
                "injected_claims": {
                    "large": "x".repeat(4_200)
                }
            }),
        ))
        .await
        .unwrap();

    assert_error(response, StatusCode::BAD_REQUEST, ErrorCode::InvalidRequest).await;
}

#[tokio::test]
async fn instance_scoped_mint_carries_instance_id() {
    let store = common::MockStore::new();
    let tenant = active_tenant(&store);
    let (_authority, token) = authority(
        &store,
        tenant,
        &[atom::MINT_EPHEMERAL_TOKEN, atom::WORKFLOW_INSTANCE_EXECUTE],
        600,
        false,
        7,
    )
    .await;
    let instance = workflow_instance(&store, tenant);

    let response = router(store, tenant)
        .oneshot(mint_request(
            &token,
            json!({
                "subject": "subject-42",
                "lifetime_seconds": 60,
                "instance_id": instance.public().as_uuid(),
                "requested_permissions": [atom::WORKFLOW_INSTANCE_EXECUTE],
                "injected_claims": {}
            }),
        ))
        .await
        .unwrap();
    let (body, claims) = minted_claims(response).await;

    assert_eq!(body["instance_id"], instance.public().as_uuid().to_string());
    assert_eq!(claims.instance, Some(instance.public().as_uuid()));
}

#[tokio::test]
async fn missing_instance_scope_returns_400() {
    let store = common::MockStore::new();
    let tenant = active_tenant(&store);
    let (_authority, token) =
        authority(&store, tenant, &[atom::MINT_EPHEMERAL_TOKEN], 600, false, 7).await;

    let response = router(store, tenant)
        .oneshot(mint_request(
            &token,
            json!({
                "subject": "subject-42",
                "lifetime_seconds": 60,
                "instance_id": Uuid::new_v4(),
                "requested_permissions": [],
                "injected_claims": {}
            }),
        ))
        .await
        .unwrap();

    assert_error(response, StatusCode::BAD_REQUEST, ErrorCode::InvalidRequest).await;
}

#[tokio::test]
async fn non_authority_principal_returns_403() {
    let store = common::MockStore::new();
    let tenant = active_tenant(&store);
    let token = principal(&store, tenant);

    let response = router(store, tenant)
        .oneshot(mint_request(
            &token,
            json!({
                "subject": "subject-42",
                "lifetime_seconds": 60,
                "requested_permissions": [],
                "injected_claims": {}
            }),
        ))
        .await
        .unwrap();

    assert_error(response, StatusCode::FORBIDDEN, ErrorCode::Forbidden).await;
}

#[tokio::test]
async fn retired_authority_returns_403() {
    let store = common::MockStore::new();
    let tenant = active_tenant(&store);
    let (_authority, token) =
        authority(&store, tenant, &[atom::MINT_EPHEMERAL_TOKEN], 600, true, 7).await;

    let response = router(store, tenant)
        .oneshot(mint_request(
            &token,
            json!({
                "subject": "subject-42",
                "lifetime_seconds": 60,
                "requested_permissions": [],
                "injected_claims": {}
            }),
        ))
        .await
        .unwrap();

    assert_error(response, StatusCode::FORBIDDEN, ErrorCode::Forbidden).await;
}

#[tokio::test]
async fn cross_tenant_authority_returns_403() {
    let store = common::MockStore::new();
    let request_tenant = active_tenant(&store);
    let authority_tenant = active_tenant(&store);
    let (_authority, token) = authority(
        &store,
        authority_tenant,
        &[atom::MINT_EPHEMERAL_TOKEN],
        600,
        false,
        7,
    )
    .await;

    let response = router(store, request_tenant)
        .oneshot(mint_request(
            &token,
            json!({
                "subject": "subject-42",
                "lifetime_seconds": 60,
                "requested_permissions": [],
                "injected_claims": {}
            }),
        ))
        .await
        .unwrap();

    assert_error(response, StatusCode::FORBIDDEN, ErrorCode::Forbidden).await;
}
