use std::{collections::HashMap, sync::Arc};

use axum::{
    Json, Router,
    extract::Extension,
    http::{Request, StatusCode},
    response::IntoResponse,
    routing::get,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use philharmonic_api::{AuthContext, ErrorCode, ErrorEnvelope, RequestContext, RequestScope};
use philharmonic_policy::{
    ApiSigningKey, ApiVerifyingKeyEntry, ApiVerifyingKeyRegistry, EphemeralApiTokenClaims,
    MintingAuthority, Principal, Tenant, TenantStatus, TokenHash, VerifyingKey, generate_api_token,
    mint_ephemeral_api_token,
};
use philharmonic_store::{EntityRefValue, RevisionRow, StoreExt};
use philharmonic_types::{CanonicalJson, ContentValue, EntityId, ScalarValue, Sha256, UnixMillis};
use tower::ServiceExt;
use zeroize::Zeroizing;

mod common;

const SEED: [u8; 32] = [
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
];
const PUBLIC: [u8; 32] = [
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
];
const ISSUER: &str = "philharmonic-api.example";
const KID: &str = "api.test-2026-04-28-deadbeef";

fn router(
    store: Arc<dyn StoreExt>,
    registry: ApiVerifyingKeyRegistry,
    scope: RequestScope,
) -> Router {
    let extra_routes = Router::new().route("/inspect", get(inspect_auth));
    common::builder(Arc::new(common::FixedResolver::new(scope)), store, registry)
        .extra_routes(extra_routes)
        .build()
        .unwrap()
        .into_router()
}

async fn inspect_auth(Extension(context): Extension<RequestContext>) -> impl IntoResponse {
    let body = match context.auth.as_ref() {
        Some(AuthContext::Principal {
            principal_id,
            tenant_id,
        }) => serde_json::json!({
            "kind": "principal",
            "principal_id": principal_id.internal().as_uuid().to_string(),
            "tenant_id": tenant_id.internal().as_uuid().to_string(),
            "tenant_id_method": context.auth.as_ref().unwrap().tenant_id().internal().as_uuid().to_string(),
            "is_principal": context.auth.as_ref().unwrap().is_principal(),
            "is_ephemeral": context.auth.as_ref().unwrap().is_ephemeral(),
        }),
        Some(AuthContext::Ephemeral {
            subject,
            tenant_id,
            authority_id,
            permissions,
            injected_claims,
            instance_scope,
        }) => serde_json::json!({
            "kind": "ephemeral",
            "subject": subject,
            "tenant_id": tenant_id.internal().as_uuid().to_string(),
            "authority_id": authority_id.internal().as_uuid().to_string(),
            "permissions": permissions,
            "injected_claims": injected_claims,
            "instance_scope": (*instance_scope).map(|id| id.to_string()),
            "tenant_id_method": context.auth.as_ref().unwrap().tenant_id().internal().as_uuid().to_string(),
            "is_principal": context.auth.as_ref().unwrap().is_principal(),
            "is_ephemeral": context.auth.as_ref().unwrap().is_ephemeral(),
        }),
        None => serde_json::json!({ "kind": "none" }),
    };
    Json(body)
}

fn signing_key() -> ApiSigningKey {
    ApiSigningKey::from_seed(Zeroizing::new(SEED), KID.to_owned())
}

fn registry() -> ApiVerifyingKeyRegistry {
    let now = UnixMillis::now();
    let mut registry = ApiVerifyingKeyRegistry::new();
    registry
        .insert(
            KID.to_owned(),
            ApiVerifyingKeyEntry {
                vk: VerifyingKey::from_bytes(&PUBLIC).unwrap(),
                issuer: ISSUER.to_owned(),
                not_before: UnixMillis(now.as_i64() - 60_000),
                not_after: UnixMillis(now.as_i64() + 86_400_000),
            },
        )
        .unwrap();
    registry
}

fn active_tenant(store: &common::MockStore) -> EntityId<Tenant> {
    tenant_with_status(store, TenantStatus::Active)
}

fn suspended_tenant(store: &common::MockStore) -> EntityId<Tenant> {
    tenant_with_status(store, TenantStatus::Suspended)
}

fn tenant_with_status(store: &common::MockStore, status: TenantStatus) -> EntityId<Tenant> {
    let tenant = common::new_typed_id::<Tenant>();
    store.insert_entity(tenant);
    store.insert_revision(RevisionRow {
        entity_id: tenant.internal().as_uuid(),
        revision_seq: 1,
        created_at: UnixMillis(2),
        content_attrs: HashMap::new(),
        entity_attrs: HashMap::new(),
        scalar_attrs: HashMap::from([("status".to_string(), ScalarValue::I64(status.as_i64()))]),
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
    store.insert_revision(principal_revision(
        principal.internal().as_uuid(),
        tenant,
        Some(credential_hash),
        is_retired,
    ));
    principal
}

fn principal_revision(
    entity_id: philharmonic_types::Uuid,
    tenant: EntityId<Tenant>,
    credential_hash: Option<Sha256>,
    is_retired: bool,
) -> RevisionRow {
    let content_attrs = credential_hash
        .map(|hash| HashMap::from([("credential_hash".to_string(), hash)]))
        .unwrap_or_default();
    RevisionRow {
        entity_id,
        revision_seq: 1,
        created_at: UnixMillis(2),
        content_attrs,
        entity_attrs: HashMap::from([(
            "tenant".to_string(),
            EntityRefValue::latest(tenant.internal().as_uuid()),
        )]),
        scalar_attrs: HashMap::from([
            ("kind".to_string(), ScalarValue::I64(0)),
            ("epoch".to_string(), ScalarValue::I64(0)),
            ("is_retired".to_string(), ScalarValue::Bool(is_retired)),
        ]),
    }
}

fn authority(
    store: &common::MockStore,
    tenant: EntityId<Tenant>,
    credential_hash: Option<Sha256>,
    is_retired: bool,
    epoch: i64,
) -> EntityId<MintingAuthority> {
    let authority = common::new_typed_id::<MintingAuthority>();
    store.insert_entity(authority);
    store.insert_revision(authority_revision(
        authority.internal().as_uuid(),
        tenant,
        credential_hash,
        is_retired,
        epoch,
    ));
    authority
}

fn authority_revision(
    entity_id: philharmonic_types::Uuid,
    tenant: EntityId<Tenant>,
    credential_hash: Option<Sha256>,
    is_retired: bool,
    epoch: i64,
) -> RevisionRow {
    let content_attrs = credential_hash
        .map(|hash| HashMap::from([("credential_hash".to_string(), hash)]))
        .unwrap_or_default();
    RevisionRow {
        entity_id,
        revision_seq: 1,
        created_at: UnixMillis(2),
        content_attrs,
        entity_attrs: HashMap::from([(
            "tenant".to_string(),
            EntityRefValue::latest(tenant.internal().as_uuid()),
        )]),
        scalar_attrs: HashMap::from([
            ("epoch".to_string(), ScalarValue::I64(epoch)),
            ("is_retired".to_string(), ScalarValue::Bool(is_retired)),
        ]),
    }
}

fn token_hash_content_hash(token_hash: TokenHash) -> Sha256 {
    ContentValue::new(token_hash.0.to_vec()).digest()
}

fn claims(
    tenant: EntityId<Tenant>,
    authority: EntityId<MintingAuthority>,
) -> EphemeralApiTokenClaims {
    let now = UnixMillis::now();
    EphemeralApiTokenClaims {
        iss: ISSUER.to_owned(),
        iat: now,
        exp: UnixMillis(now.as_i64() + 3_600_000),
        sub: "subject-42".to_owned(),
        tenant: tenant.internal().as_uuid(),
        authority: authority.internal().as_uuid(),
        authority_epoch: 7,
        instance: Some(philharmonic_types::Uuid::new_v4()),
        permissions: vec!["workflow:instance_execute".to_string()],
        claims: CanonicalJson::from_bytes(br#"{"role":"viewer","session":"s-1"}"#).unwrap(),
        kid: KID.to_owned(),
    }
}

fn bearer_request(token: &str) -> Request<axum::body::Body> {
    Request::builder()
        .uri("/inspect")
        .header("Authorization", format!("Bearer {token}"))
        .body(axum::body::Body::empty())
        .unwrap()
}

fn ephemeral_header(claims: &EphemeralApiTokenClaims) -> String {
    let token = mint_ephemeral_api_token(&signing_key(), claims, UnixMillis::now()).unwrap();
    let bytes = token.to_bytes().unwrap();
    URL_SAFE_NO_PAD.encode(bytes)
}

async fn response_json(response: axum::response::Response) -> serde_json::Value {
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&body).unwrap()
}

async fn assert_unauthenticated(response: axum::response::Response) {
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_text = String::from_utf8(body.to_vec()).unwrap();
    let envelope: ErrorEnvelope = serde_json::from_slice(&body).unwrap();
    assert_eq!(envelope.error.code, ErrorCode::Unauthenticated);
    assert_eq!(envelope.error.message, "invalid token");
    assert!(envelope.error.details.is_none());
    assert!(!body_text.contains(KID));
    assert!(!body_text.contains("signature"));
    assert!(!body_text.contains("expiry"));
    assert!(!body_text.contains("epoch"));
}

#[tokio::test]
async fn long_lived_happy_path_populates_principal_auth() {
    let store = common::MockStore::new();
    let tenant = active_tenant(&store);
    let (token, token_hash) = generate_api_token();
    let principal = principal(&store, tenant, token_hash_content_hash(token_hash), false);
    let response = router(store, registry(), RequestScope::Tenant(tenant))
        .oneshot(bearer_request(&token))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let json = response_json(response).await;
    assert_eq!(json["kind"], "principal");
    assert_eq!(
        json["principal_id"],
        principal.internal().as_uuid().to_string()
    );
    assert_eq!(json["tenant_id"], tenant.internal().as_uuid().to_string());
    assert_eq!(json["is_principal"], true);
    assert_eq!(json["is_ephemeral"], false);
}

#[tokio::test]
async fn ephemeral_happy_path_populates_ephemeral_auth() {
    let store = common::MockStore::new();
    let tenant = active_tenant(&store);
    let authority = authority(&store, tenant, None, false, 7);
    let claims = claims(tenant, authority);
    let token = ephemeral_header(&claims);

    let response = router(store, registry(), RequestScope::Tenant(tenant))
        .oneshot(bearer_request(&token))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let json = response_json(response).await;
    assert_eq!(json["kind"], "ephemeral");
    assert_eq!(json["subject"], "subject-42");
    assert_eq!(json["tenant_id"], tenant.internal().as_uuid().to_string());
    assert_eq!(
        json["authority_id"],
        authority.internal().as_uuid().to_string()
    );
    assert_eq!(json["permissions"][0], "workflow:instance_execute");
    assert_eq!(json["injected_claims"]["role"], "viewer");
    assert_eq!(json["is_principal"], false);
    assert_eq!(json["is_ephemeral"], true);
}

#[tokio::test]
async fn missing_authorization_header_returns_generic_401() {
    let store = common::MockStore::new();
    let tenant = active_tenant(&store);
    let response = router(store, registry(), RequestScope::Tenant(tenant))
        .oneshot(
            Request::builder()
                .uri("/inspect")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_unauthenticated(response).await;
}

#[tokio::test]
async fn malformed_bearer_returns_generic_401() {
    let store = common::MockStore::new();
    let tenant = active_tenant(&store);
    let response = router(store, registry(), RequestScope::Tenant(tenant))
        .oneshot(
            Request::builder()
                .uri("/inspect")
                .header("Authorization", "Bearer")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_unauthenticated(response).await;
}

#[tokio::test]
async fn invalid_pht_token_returns_generic_401() {
    let store = common::MockStore::new();
    let tenant = active_tenant(&store);
    let response = router(store, registry(), RequestScope::Tenant(tenant))
        .oneshot(bearer_request("pht_short"))
        .await
        .unwrap();

    assert_unauthenticated(response).await;
}

#[tokio::test]
async fn pht_token_not_found_returns_generic_401() {
    let store = common::MockStore::new();
    let tenant = active_tenant(&store);
    let (token, _) = generate_api_token();
    let response = router(store, registry(), RequestScope::Tenant(tenant))
        .oneshot(bearer_request(&token))
        .await
        .unwrap();

    assert_unauthenticated(response).await;
}

#[tokio::test]
async fn pht_token_found_but_principal_retired_returns_generic_401() {
    let store = common::MockStore::new();
    let tenant = active_tenant(&store);
    let (token, token_hash) = generate_api_token();
    principal(&store, tenant, token_hash_content_hash(token_hash), true);
    let response = router(store, registry(), RequestScope::Tenant(tenant))
        .oneshot(bearer_request(&token))
        .await
        .unwrap();

    assert_unauthenticated(response).await;
}

#[tokio::test]
async fn pht_token_found_but_tenant_suspended_returns_generic_401() {
    let store = common::MockStore::new();
    let tenant = suspended_tenant(&store);
    let (token, token_hash) = generate_api_token();
    principal(&store, tenant, token_hash_content_hash(token_hash), false);
    let response = router(store, registry(), RequestScope::Tenant(tenant))
        .oneshot(bearer_request(&token))
        .await
        .unwrap();

    assert_unauthenticated(response).await;
}

#[tokio::test]
async fn ephemeral_bad_signature_returns_generic_401() {
    let store = common::MockStore::new();
    let tenant = active_tenant(&store);
    let authority = authority(&store, tenant, None, false, 7);
    let mut token = mint_ephemeral_api_token(
        &signing_key(),
        &claims(tenant, authority),
        UnixMillis::now(),
    )
    .unwrap()
    .to_bytes()
    .unwrap();
    let last = token.last_mut().unwrap();
    *last ^= 0x01;
    let response = router(store, registry(), RequestScope::Tenant(tenant))
        .oneshot(bearer_request(&URL_SAFE_NO_PAD.encode(token)))
        .await
        .unwrap();

    assert_unauthenticated(response).await;
}

#[tokio::test]
async fn ephemeral_authority_not_found_returns_generic_401() {
    let store = common::MockStore::new();
    let tenant = active_tenant(&store);
    let missing_authority = common::new_typed_id::<MintingAuthority>();
    let token = ephemeral_header(&claims(tenant, missing_authority));
    let response = router(store, registry(), RequestScope::Tenant(tenant))
        .oneshot(bearer_request(&token))
        .await
        .unwrap();

    assert_unauthenticated(response).await;
}

#[tokio::test]
async fn ephemeral_authority_tenant_mismatch_returns_generic_401() {
    let store = common::MockStore::new();
    let tenant_a = active_tenant(&store);
    let tenant_b = active_tenant(&store);
    let authority = authority(&store, tenant_b, None, false, 7);
    let token = ephemeral_header(&claims(tenant_a, authority));
    let response = router(store, registry(), RequestScope::Tenant(tenant_a))
        .oneshot(bearer_request(&token))
        .await
        .unwrap();

    assert_unauthenticated(response).await;
}

#[tokio::test]
async fn ephemeral_authority_retired_returns_generic_401() {
    let store = common::MockStore::new();
    let tenant = active_tenant(&store);
    let authority = authority(&store, tenant, None, true, 7);
    let token = ephemeral_header(&claims(tenant, authority));
    let response = router(store, registry(), RequestScope::Tenant(tenant))
        .oneshot(bearer_request(&token))
        .await
        .unwrap();

    assert_unauthenticated(response).await;
}

#[tokio::test]
async fn ephemeral_authority_epoch_mismatch_returns_generic_401() {
    let store = common::MockStore::new();
    let tenant = active_tenant(&store);
    let authority = authority(&store, tenant, None, false, 8);
    let token = ephemeral_header(&claims(tenant, authority));
    let response = router(store, registry(), RequestScope::Tenant(tenant))
        .oneshot(bearer_request(&token))
        .await
        .unwrap();

    assert_unauthenticated(response).await;
}

#[tokio::test]
async fn ephemeral_authority_negative_epoch_returns_generic_401() {
    let store = common::MockStore::new();
    let tenant = active_tenant(&store);
    let authority = authority(&store, tenant, None, false, -1);
    let token = ephemeral_header(&claims(tenant, authority));
    let response = router(store, registry(), RequestScope::Tenant(tenant))
        .oneshot(bearer_request(&token))
        .await
        .unwrap();

    assert_unauthenticated(response).await;
}

#[tokio::test]
async fn meta_endpoint_without_auth_still_succeeds() {
    let response = common::basic_builder()
        .build()
        .unwrap()
        .into_router()
        .oneshot(
            Request::builder()
                .uri("/v1/_meta/health")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}
