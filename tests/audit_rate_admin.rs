use std::{collections::HashMap, sync::Arc};

use axum::{
    body::Body,
    http::{Method, Request, StatusCode, header::RETRY_AFTER},
};
use philharmonic_api::{
    ApiStore, ErrorCode, ErrorEnvelope, RateLimitBucketConfig, RateLimitConfig, RequestScope,
};
use philharmonic_policy::{
    AuditEvent, Principal, PrincipalKind, RoleDefinition, RoleMembership, Tenant, TenantStatus,
    TokenHash, atom, generate_api_token,
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
    token: String,
}

async fn tenant_fixture(permissions: &[&str]) -> Fixture {
    tenant_fixture_with_rate(permissions, RateLimitConfig::default()).await
}

async fn tenant_fixture_with_rate(
    permissions: &[&str],
    rate_limit_config: RateLimitConfig,
) -> Fixture {
    let store = common::MockStore::new();
    let tenant = seed_tenant(&store, "Acme", TenantStatus::Active).await;
    let token = seed_principal_with_roles(&store, tenant, permissions).await;
    let router = common::builder(
        Arc::new(common::FixedResolver::new(RequestScope::Tenant(tenant))),
        store.clone(),
        common::test_api_verifying_key_registry(),
    )
    .rate_limit_config(rate_limit_config)
    .build()
    .unwrap()
    .into_router();

    Fixture {
        router,
        store,
        tenant,
        token,
    }
}

async fn operator_fixture(permissions: &[&str]) -> Fixture {
    let store = common::MockStore::new();
    let tenant = seed_tenant(&store, "Operator", TenantStatus::Active).await;
    let token = seed_principal_with_roles(&store, tenant, permissions).await;
    let router = common::builder(
        Arc::new(common::FixedResolver::new(RequestScope::Operator)),
        store.clone(),
        common::test_api_verifying_key_registry(),
    )
    .build()
    .unwrap()
    .into_router();

    Fixture {
        router,
        store,
        tenant,
        token,
    }
}

fn router_for_scope(
    store: Arc<dyn ApiStore>,
    scope: RequestScope,
    rate_limit_config: RateLimitConfig,
) -> axum::Router {
    common::builder(
        Arc::new(common::FixedResolver::new(scope)),
        store,
        common::test_api_verifying_key_registry(),
    )
    .rate_limit_config(rate_limit_config)
    .build()
    .unwrap()
    .into_router()
}

async fn seed_tenant(
    store: &common::MockStore,
    display_name: &str,
    status: TenantStatus,
) -> EntityId<Tenant> {
    let tenant = common::new_typed_id::<Tenant>();
    let display_name = put_json(store, &JsonValue::String(display_name.to_string())).await;
    store.insert_entity(tenant);
    store.insert_revision(RevisionRow {
        entity_id: tenant.internal().as_uuid(),
        revision_seq: 0,
        created_at: UnixMillis(1),
        content_attrs: HashMap::from([("display_name".to_string(), display_name)]),
        entity_attrs: HashMap::new(),
        scalar_attrs: HashMap::from([("status".to_string(), ScalarValue::I64(status.as_i64()))]),
    });
    tenant
}

async fn seed_principal_with_roles(
    store: &common::MockStore,
    tenant: EntityId<Tenant>,
    permissions: &[&str],
) -> String {
    let (token, token_hash) = generate_api_token();
    let principal = common::new_typed_id::<Principal>();
    store.insert_entity(principal);
    store.insert_revision(RevisionRow {
        entity_id: principal.internal().as_uuid(),
        revision_seq: 0,
        created_at: UnixMillis(2),
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
                ScalarValue::I64(PrincipalKind::User.as_i64()),
            ),
            ("epoch".to_string(), ScalarValue::I64(0)),
            ("is_retired".to_string(), ScalarValue::Bool(false)),
        ]),
    });

    let role = common::new_typed_id::<RoleDefinition>();
    let permissions = serde_json::to_vec(permissions).unwrap();
    let permissions = put_content(store, &permissions).await;
    store.insert_entity(role);
    store.insert_revision(RevisionRow {
        entity_id: role.internal().as_uuid(),
        revision_seq: 0,
        created_at: UnixMillis(3),
        content_attrs: HashMap::from([("permissions".to_string(), permissions)]),
        entity_attrs: HashMap::from([(
            "tenant".to_string(),
            EntityRefValue::pinned(tenant.internal().as_uuid(), 0),
        )]),
        scalar_attrs: HashMap::from([("is_retired".to_string(), ScalarValue::Bool(false))]),
    });

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

    token.to_string()
}

async fn seed_audit_event(
    store: &common::MockStore,
    tenant: EntityId<Tenant>,
    event_type: i64,
    timestamp: UnixMillis,
    principal_id: Option<Uuid>,
) -> EntityId<AuditEvent> {
    let event = common::new_typed_id::<AuditEvent>();
    let mut event_data = json!({ "summary": format!("event-{event_type}") });
    if let Some(principal_id) = principal_id {
        event_data["principal_id"] = JsonValue::String(principal_id.to_string());
    }
    store.insert_entity(event);
    store.insert_revision(RevisionRow {
        entity_id: event.internal().as_uuid(),
        revision_seq: 0,
        created_at: timestamp,
        content_attrs: HashMap::from([(
            "event_data".to_string(),
            put_json(store, &event_data).await,
        )]),
        entity_attrs: HashMap::from([(
            "tenant".to_string(),
            EntityRefValue::pinned(tenant.internal().as_uuid(), 0),
        )]),
        scalar_attrs: HashMap::from([
            ("event_type".to_string(), ScalarValue::I64(event_type)),
            (
                "timestamp".to_string(),
                ScalarValue::I64(timestamp.as_i64()),
            ),
        ]),
    });
    event
}

async fn put_json(store: &common::MockStore, value: &JsonValue) -> Sha256 {
    let canonical = CanonicalJson::from_value(value).unwrap();
    put_content(store, canonical.as_bytes()).await
}

async fn put_content(store: &common::MockStore, value: &[u8]) -> Sha256 {
    let content = ContentValue::new(value.to_vec());
    let hash = content.digest();
    store.put(&content).await.unwrap();
    hash
}

fn token_hash_content_hash(token_hash: TokenHash) -> Sha256 {
    ContentValue::new(token_hash.0.to_vec()).digest()
}

fn request(method: Method, uri: &str, token: &str, body: Option<JsonValue>) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("Authorization", format!("Bearer {token}"));
    if body.is_some() {
        builder = builder.header("Content-Type", "application/json");
    }
    let body = match body {
        Some(value) => Body::from(serde_json::to_vec(&value).unwrap()),
        None => Body::empty(),
    };
    builder.body(body).unwrap()
}

async fn response_json(response: axum::response::Response) -> JsonValue {
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&body).unwrap()
}

async fn error_code(response: axum::response::Response) -> ErrorCode {
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let envelope: ErrorEnvelope = serde_json::from_slice(&body).unwrap();
    envelope.error.code
}

#[tokio::test]
async fn tenant_settings_read_returns_metadata() {
    let fixture = tenant_fixture(&[atom::TENANT_SETTINGS_READ]).await;

    let response = fixture
        .router
        .oneshot(request(Method::GET, "/v1/tenant", &fixture.token, None))
        .await
        .unwrap();

    let status = response.status();
    let body = response_json(response).await;
    assert_eq!(status, StatusCode::OK, "body: {body:?}");
    assert_eq!(
        body["tenant_id"],
        fixture.tenant.public().as_uuid().to_string()
    );
    assert_eq!(body["display_name"], "Acme");
    assert_eq!(body["status"], "active");
}

#[tokio::test]
async fn tenant_settings_update_returns_and_persists_change() {
    let fixture = tenant_fixture(&[atom::TENANT_SETTINGS_MANAGE, atom::TENANT_SETTINGS_READ]).await;

    let response = fixture
        .router
        .clone()
        .oneshot(request(
            Method::PATCH,
            "/v1/tenant",
            &fixture.token,
            Some(json!({ "display_name": "Acme Updated" })),
        ))
        .await
        .unwrap();

    let status = response.status();
    let body = response_json(response).await;
    assert_eq!(status, StatusCode::OK, "body: {body:?}");
    assert_eq!(body["display_name"], "Acme Updated");

    let response = fixture
        .router
        .oneshot(request(Method::GET, "/v1/tenant", &fixture.token, None))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response_json(response).await;
    assert_eq!(body["display_name"], "Acme Updated");
}

#[tokio::test]
async fn audit_list_is_paginated() {
    let fixture = tenant_fixture(&[atom::AUDIT_READ]).await;
    let first = seed_audit_event(&fixture.store, fixture.tenant, 10, UnixMillis(1_000), None).await;
    let second =
        seed_audit_event(&fixture.store, fixture.tenant, 20, UnixMillis(2_000), None).await;

    let response = fixture
        .router
        .clone()
        .oneshot(request(
            Method::GET,
            "/v1/audit?limit=1",
            &fixture.token,
            None,
        ))
        .await
        .unwrap();

    let status = response.status();
    let body = response_json(response).await;
    assert_eq!(status, StatusCode::OK, "body: {body:?}");
    assert_eq!(body["items"].as_array().unwrap().len(), 1);
    assert_eq!(
        body["items"][0]["audit_event_id"],
        second.public().as_uuid().to_string(),
        "first page should return the newer item"
    );
    let cursor = body["next_cursor"].as_str().unwrap();

    let response = fixture
        .router
        .oneshot(request(
            Method::GET,
            &format!("/v1/audit?limit=1&cursor={cursor}"),
            &fixture.token,
            None,
        ))
        .await
        .unwrap();

    let status = response.status();
    let body = response_json(response).await;
    assert_eq!(status, StatusCode::OK, "body: {body:?}");
    assert_eq!(body["items"].as_array().unwrap().len(), 1);
    assert_eq!(
        body["items"][0]["audit_event_id"],
        first.public().as_uuid().to_string(),
        "second page should return the older item"
    );
    assert!(body["next_cursor"].is_null());
}

#[tokio::test]
async fn audit_list_filters_event_type_time_and_principal() {
    let fixture = tenant_fixture(&[atom::AUDIT_READ]).await;
    let principal_id = Uuid::new_v4();
    let matching = seed_audit_event(
        &fixture.store,
        fixture.tenant,
        30,
        UnixMillis(2_000),
        Some(principal_id),
    )
    .await;
    let _ = seed_audit_event(
        &fixture.store,
        fixture.tenant,
        31,
        UnixMillis(3_000),
        Some(principal_id),
    )
    .await;

    let uri = format!("/v1/audit?event_type=30&since=1500&until=2500&principal_id={principal_id}");
    let response = fixture
        .router
        .oneshot(request(Method::GET, &uri, &fixture.token, None))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response_json(response).await;
    assert_eq!(body["items"].as_array().unwrap().len(), 1);
    assert_eq!(
        body["items"][0]["audit_event_id"],
        matching.public().as_uuid().to_string()
    );
}

#[tokio::test]
async fn rate_limit_exceeded_returns_429_retry_after_and_code() {
    let rate_limit_config = RateLimitConfig {
        admin: RateLimitBucketConfig::new(1, 1),
        ..RateLimitConfig::default()
    };
    let fixture = tenant_fixture_with_rate(&[atom::TENANT_SETTINGS_READ], rate_limit_config).await;

    let response = fixture
        .router
        .clone()
        .oneshot(request(Method::GET, "/v1/tenant", &fixture.token, None))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let response = fixture
        .router
        .oneshot(request(Method::GET, "/v1/tenant", &fixture.token, None))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(response.headers().contains_key(RETRY_AFTER));
    assert_eq!(error_code(response).await, ErrorCode::RateLimited);
}

#[tokio::test]
async fn operator_create_tenant_returns_created_id() {
    let fixture = operator_fixture(&[atom::DEPLOYMENT_TENANT_MANAGE]).await;

    let response = fixture
        .router
        .oneshot(request(
            Method::POST,
            "/v1/operator/tenants",
            &fixture.token,
            Some(json!({
                "subdomain_name": "new-tenant",
                "display_name": "New Tenant"
            })),
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
    let body = response_json(response).await;
    assert!(body["tenant_id"].as_str().is_some());
    assert_eq!(body["status"], "active");
}

#[tokio::test]
async fn operator_suspend_and_unsuspend_tenant() {
    let fixture = operator_fixture(&[atom::DEPLOYMENT_TENANT_MANAGE]).await;
    let target = seed_tenant(&fixture.store, "Target", TenantStatus::Active).await;

    let response = fixture
        .router
        .clone()
        .oneshot(request(
            Method::POST,
            &format!("/v1/operator/tenants/{}/suspend", target.public().as_uuid()),
            &fixture.token,
            None,
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response_json(response).await;
    assert_eq!(body["status"], "suspended");

    let response = fixture
        .router
        .oneshot(request(
            Method::POST,
            &format!(
                "/v1/operator/tenants/{}/unsuspend",
                target.public().as_uuid()
            ),
            &fixture.token,
            None,
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response_json(response).await;
    assert_eq!(body["status"], "active");
}

#[tokio::test]
async fn operator_endpoint_from_tenant_scope_returns_forbidden_envelope() {
    let store = common::MockStore::new();
    let tenant = seed_tenant(&store, "Operator", TenantStatus::Active).await;
    let token = seed_principal_with_roles(&store, tenant, &[atom::DEPLOYMENT_TENANT_MANAGE]).await;
    let router = router_for_scope(
        store,
        RequestScope::Tenant(tenant),
        RateLimitConfig::default(),
    );

    let response = router
        .oneshot(request(
            Method::POST,
            "/v1/operator/tenants",
            &token,
            Some(json!({
                "subdomain_name": "wrong-scope",
                "display_name": "Wrong Scope"
            })),
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(error_code(response).await, ErrorCode::Forbidden);
}

#[tokio::test]
async fn tenant_endpoint_from_operator_scope_returns_forbidden_envelope() {
    let store = common::MockStore::new();
    let tenant = seed_tenant(&store, "Operator", TenantStatus::Active).await;
    let token = seed_principal_with_roles(&store, tenant, &[atom::TENANT_SETTINGS_READ]).await;
    let router = router_for_scope(store, RequestScope::Operator, RateLimitConfig::default());

    let response = router
        .oneshot(request(Method::GET, "/v1/tenant", &token, None))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(error_code(response).await, ErrorCode::Forbidden);
}
