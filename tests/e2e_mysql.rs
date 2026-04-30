use std::{sync::Arc, time::Duration};

use philharmonic_api::{
    ApiStore, AuditEventInput, PhilharmonicApiBuilder, RequestScope, StubExecutor, StubLowerer,
    write_audit_event,
};
use philharmonic_policy::{
    ALL_ATOMS, Principal, PrincipalKind, RoleDefinition, RoleMembership, Tenant, TenantStatus,
    TokenHash, generate_api_token,
};
use philharmonic_store::{
    ContentStore, EntityRefValue, EntityStoreExt, RevisionInput, StoreError, StoreExt,
};
use philharmonic_store_sqlx_mysql::{SinglePool, SqlStore, migrate};
use philharmonic_types::{
    CanonicalJson, ContentValue, EntityId, JsonValue, ScalarValue, Sha256, UnixMillis, Uuid,
};
use reqwest::{Client, Method, Response, StatusCode};
use serde_json::json;
use sqlx::{MySqlPool, mysql::MySqlPoolOptions};
use testcontainers_modules::{
    mysql::Mysql,
    testcontainers::{ContainerAsync, ImageExt, core::IntoContainerPort, runners::AsyncRunner},
};
use tokio::{net::TcpListener, task::JoinHandle};

mod common;

type TestResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
type ContainerHandle = ContainerAsync<Mysql>;

struct TestContext {
    _container: ContainerHandle,
    _pool: MySqlPool,
    store: Arc<SqlStore<SinglePool>>,
    client: Client,
    base_url: String,
    token: String,
    tenant: EntityId<Tenant>,
    server: JoinHandle<()>,
}

impl TestContext {
    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    fn request(&self, method: Method, path: &str) -> reqwest::RequestBuilder {
        self.client
            .request(method, self.url(path))
            .bearer_auth(&self.token)
    }
}

impl Drop for TestContext {
    fn drop(&mut self) {
        self.server.abort();
    }
}

async fn setup() -> TestResult<TestContext> {
    let container = Mysql::default()
        .with_startup_timeout(Duration::from_secs(180))
        .start()
        .await?;
    let host = container.get_host().await?;
    let port = container.get_host_port_ipv4(3306.tcp()).await?;

    let database_url = format!("mysql://root@{}:{}/test", host, port);
    let pool = MySqlPoolOptions::new()
        .max_connections(8)
        .acquire_timeout(Duration::from_secs(10))
        .connect(&database_url)
        .await?;
    migrate_schema(&pool).await?;

    let store = Arc::new(SqlStore::from_pool(pool.clone()));
    let tenant = seed_tenant(store.as_ref(), "E2E Tenant", TenantStatus::Active).await?;
    let token = seed_principal_with_roles(store.as_ref(), tenant, &ALL_ATOMS).await?;

    let api_store: Arc<dyn ApiStore> = store.clone();
    let api = PhilharmonicApiBuilder::new()
        .request_scope_resolver(Arc::new(common::FixedResolver::new(RequestScope::Tenant(
            tenant,
        ))))
        .store(api_store)
        .api_verifying_key_registry(common::test_api_verifying_key_registry())
        .api_signing_key(common::test_api_signing_key())
        .issuer(common::TEST_API_ISSUER.to_string())
        .step_executor(Arc::new(StubExecutor))
        .config_lowerer(Arc::new(StubLowerer))
        .build()?;

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let router = api.into_router();
    let server = tokio::spawn(async move {
        if let Err(error) = axum::serve(listener, router).await {
            panic!("e2e API server stopped unexpectedly: {error}");
        }
    });

    Ok(TestContext {
        _container: container,
        _pool: pool,
        store,
        client: Client::new(),
        base_url: format!("http://{addr}"),
        token,
        tenant,
        server,
    })
}

async fn migrate_schema(pool: &MySqlPool) -> TestResult<()> {
    match migrate(pool).await {
        Ok(()) => Ok(()),
        // The current SQL schema creates this index inline and then the
        // idempotent index migration may see it as already present.
        Err(StoreError::Backend(error))
            if error
                .message
                .contains("Duplicate key name 'ix_attr_content_hash'") =>
        {
            Ok(())
        }
        Err(error) => Err(error.into()),
    }
}

async fn seed_tenant(
    store: &SqlStore<SinglePool>,
    display_name: &str,
    status: TenantStatus,
) -> TestResult<EntityId<Tenant>> {
    let tenant = store.create_entity_minting::<Tenant>().await?;
    let display_name = put_json(store, &JsonValue::String(display_name.to_string())).await?;
    let revision = RevisionInput::new()
        .with_content("display_name", display_name)
        .with_scalar("status", ScalarValue::I64(status.as_i64()));
    store
        .append_revision_typed::<Tenant>(tenant, 0, &revision)
        .await?;
    Ok(tenant)
}

async fn seed_principal_with_roles(
    store: &SqlStore<SinglePool>,
    tenant: EntityId<Tenant>,
    permissions: &[&str],
) -> TestResult<String> {
    let (token, token_hash) = generate_api_token();
    let principal = seed_principal(
        store,
        tenant,
        "E2E Admin",
        PrincipalKind::User,
        Some(token_hash_content_hash(token_hash)),
    )
    .await?;
    let role = seed_role(store, tenant, "E2E Admin Role", permissions).await?;
    seed_membership(store, tenant, principal, role).await?;
    Ok(token.to_string())
}

async fn seed_principal(
    store: &SqlStore<SinglePool>,
    tenant: EntityId<Tenant>,
    display_name: &str,
    kind: PrincipalKind,
    credential_hash: Option<Sha256>,
) -> TestResult<EntityId<Principal>> {
    let principal = store.create_entity_minting::<Principal>().await?;
    let display_name = put_json(store, &JsonValue::String(display_name.to_string())).await?;
    let mut revision = RevisionInput::new()
        .with_content("display_name", display_name)
        .with_entity(
            "tenant",
            EntityRefValue::pinned(tenant.internal().as_uuid(), 0),
        )
        .with_scalar("kind", ScalarValue::I64(kind.as_i64()))
        .with_scalar("epoch", ScalarValue::I64(0))
        .with_scalar("is_retired", ScalarValue::Bool(false));
    if let Some(credential_hash) = credential_hash {
        revision = revision.with_content("credential_hash", credential_hash);
    }
    store
        .append_revision_typed::<Principal>(principal, 0, &revision)
        .await?;
    Ok(principal)
}

async fn seed_role(
    store: &SqlStore<SinglePool>,
    tenant: EntityId<Tenant>,
    display_name: &str,
    permissions: &[&str],
) -> TestResult<EntityId<RoleDefinition>> {
    let role = store.create_entity_minting::<RoleDefinition>().await?;
    let display_name = put_json(store, &JsonValue::String(display_name.to_string())).await?;
    let permissions = put_json(store, &serde_json::to_value(permissions)?).await?;
    let revision = RevisionInput::new()
        .with_content("display_name", display_name)
        .with_content("permissions", permissions)
        .with_entity(
            "tenant",
            EntityRefValue::pinned(tenant.internal().as_uuid(), 0),
        )
        .with_scalar("is_retired", ScalarValue::Bool(false));
    store
        .append_revision_typed::<RoleDefinition>(role, 0, &revision)
        .await?;
    Ok(role)
}

async fn seed_membership(
    store: &SqlStore<SinglePool>,
    tenant: EntityId<Tenant>,
    principal: EntityId<Principal>,
    role: EntityId<RoleDefinition>,
) -> TestResult<EntityId<RoleMembership>> {
    let membership = store.create_entity_minting::<RoleMembership>().await?;
    let revision = RevisionInput::new()
        .with_entity(
            "tenant",
            EntityRefValue::pinned(tenant.internal().as_uuid(), 0),
        )
        .with_entity(
            "principal",
            EntityRefValue::pinned(principal.internal().as_uuid(), 0),
        )
        .with_entity("role", EntityRefValue::pinned(role.internal().as_uuid(), 0))
        .with_scalar("is_retired", ScalarValue::Bool(false));
    store
        .append_revision_typed::<RoleMembership>(membership, 0, &revision)
        .await?;
    Ok(membership)
}

async fn put_json(store: &SqlStore<SinglePool>, value: &JsonValue) -> TestResult<Sha256> {
    let canonical = CanonicalJson::from_value(value)?;
    put_content(store, canonical.as_bytes()).await
}

async fn put_content(store: &SqlStore<SinglePool>, bytes: &[u8]) -> TestResult<Sha256> {
    let value = ContentValue::new(bytes.to_vec());
    let hash = value.digest();
    store.put(&value).await?;
    Ok(hash)
}

fn token_hash_content_hash(token_hash: TokenHash) -> Sha256 {
    ContentValue::new(token_hash.0.to_vec()).digest()
}

async fn expect_json(response: Response, expected: StatusCode) -> TestResult<JsonValue> {
    let status = response.status();
    let body = response.text().await?;
    assert_eq!(status, expected, "response body: {body}");
    Ok(serde_json::from_str(&body)?)
}

async fn create_template(ctx: &TestContext, display_name: &str) -> TestResult<Uuid> {
    let response = ctx
        .request(Method::POST, "/v1/workflows/templates")
        .json(&json!({
            "display_name": display_name,
            "script_source": "export default async function main() {}",
            "abstract_config": {}
        }))
        .send()
        .await?;
    let body = expect_json(response, StatusCode::CREATED).await?;
    Ok(body["template_id"]
        .as_str()
        .expect("create template response includes template_id")
        .parse()?)
}

async fn create_instance(ctx: &TestContext, template_id: Uuid) -> TestResult<Uuid> {
    let response = ctx
        .request(Method::POST, "/v1/workflows/instances")
        .json(&json!({
            "template_id": template_id,
            "args": { "conversation_id": "e2e-1" }
        }))
        .send()
        .await?;
    let body = expect_json(response, StatusCode::CREATED).await?;
    Ok(body["instance_id"]
        .as_str()
        .expect("create instance response includes instance_id")
        .parse()?)
}

async fn create_principal(ctx: &TestContext, display_name: &str) -> TestResult<(Uuid, String)> {
    let response = ctx
        .request(Method::POST, "/v1/principals")
        .json(&json!({
            "display_name": display_name,
            "kind": "service"
        }))
        .send()
        .await?;
    let body = expect_json(response, StatusCode::CREATED).await?;
    Ok((
        body["principal_id"]
            .as_str()
            .expect("create principal response includes principal_id")
            .parse()?,
        body["token"]
            .as_str()
            .expect("create principal response includes token")
            .to_string(),
    ))
}

async fn create_role(
    ctx: &TestContext,
    display_name: &str,
    permissions: &[&str],
) -> TestResult<Uuid> {
    let response = ctx
        .request(Method::POST, "/v1/roles")
        .json(&json!({
            "display_name": display_name,
            "permissions": permissions
        }))
        .send()
        .await?;
    let body = expect_json(response, StatusCode::CREATED).await?;
    Ok(body["role_id"]
        .as_str()
        .expect("create role response includes role_id")
        .parse()?)
}

async fn create_membership(
    ctx: &TestContext,
    principal_id: Uuid,
    role_id: Uuid,
) -> TestResult<Uuid> {
    let response = ctx
        .request(Method::POST, "/v1/role-memberships")
        .json(&json!({
            "principal_id": principal_id,
            "role_id": role_id
        }))
        .send()
        .await?;
    let body = expect_json(response, StatusCode::CREATED).await?;
    Ok(body["membership_id"]
        .as_str()
        .expect("create membership response includes membership_id")
        .parse()?)
}

/// Requires Docker with a MySQL testcontainer; ignored by default so default CI stays green.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires MySQL testcontainer"]
#[serial_test::file_serial(docker)]
async fn health_and_version() -> TestResult<()> {
    let ctx = setup().await?;

    let response = ctx.client.get(ctx.url("/v1/_meta/health")).send().await?;
    let body = expect_json(response, StatusCode::OK).await?;
    assert_eq!(body["status"], "ok");

    let response = ctx.client.get(ctx.url("/v1/_meta/version")).send().await?;
    let body = expect_json(response, StatusCode::OK).await?;
    assert_eq!(body["version"], env!("CARGO_PKG_VERSION"));

    Ok(())
}

/// Requires Docker with a MySQL testcontainer; ignored by default so default CI stays green.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires MySQL testcontainer"]
#[serial_test::file_serial(docker)]
async fn workflow_template_crud() -> TestResult<()> {
    let ctx = setup().await?;
    let template_id = create_template(&ctx, "Draft").await?;

    let response = ctx
        .request(Method::GET, "/v1/workflows/templates")
        .send()
        .await?;
    let body = expect_json(response, StatusCode::OK).await?;
    assert!(
        body["items"]
            .as_array()
            .expect("template list includes items")
            .iter()
            .any(|item| item["template_id"] == template_id.to_string())
    );

    let response = ctx
        .request(
            Method::GET,
            &format!("/v1/workflows/templates/{template_id}"),
        )
        .send()
        .await?;
    let body = expect_json(response, StatusCode::OK).await?;
    assert_eq!(body["template_id"], template_id.to_string());
    assert_eq!(body["display_name"], "Draft");

    let response = ctx
        .request(
            Method::PATCH,
            &format!("/v1/workflows/templates/{template_id}"),
        )
        .json(&json!({
            "display_name": "Published",
            "script_source": "export default async function main() { return true; }"
        }))
        .send()
        .await?;
    let body = expect_json(response, StatusCode::OK).await?;
    assert_eq!(body["display_name"], "Published");
    assert_eq!(body["latest_revision"], 1);

    let response = ctx
        .request(
            Method::POST,
            &format!("/v1/workflows/templates/{template_id}/retire"),
        )
        .send()
        .await?;
    let body = expect_json(response, StatusCode::OK).await?;
    assert_eq!(body["template_id"], template_id.to_string());
    assert_eq!(body["is_retired"], true);

    Ok(())
}

/// Requires Docker with a MySQL testcontainer; ignored by default so default CI stays green.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires MySQL testcontainer"]
#[serial_test::file_serial(docker)]
async fn workflow_instance_lifecycle() -> TestResult<()> {
    let ctx = setup().await?;
    let template_id = create_template(&ctx, "Lifecycle").await?;
    let instance_id = create_instance(&ctx, template_id).await?;

    let response = ctx
        .request(
            Method::GET,
            &format!("/v1/workflows/instances/{instance_id}"),
        )
        .send()
        .await?;
    let body = expect_json(response, StatusCode::OK).await?;
    assert_eq!(body["instance_id"], instance_id.to_string());
    assert_eq!(body["template_id"], template_id.to_string());
    assert_eq!(body["status"], "pending");

    Ok(())
}

/// Requires Docker with a MySQL testcontainer; ignored by default so default CI stays green.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires MySQL testcontainer"]
#[serial_test::file_serial(docker)]
async fn principal_crud() -> TestResult<()> {
    let ctx = setup().await?;
    let (principal_id, first_token) = create_principal(&ctx, "Worker principal").await?;
    assert!(first_token.starts_with("pht_"));

    let response = ctx.request(Method::GET, "/v1/principals").send().await?;
    let body = expect_json(response, StatusCode::OK).await?;
    assert!(
        body["items"]
            .as_array()
            .expect("principal list includes items")
            .iter()
            .any(|item| item["principal_id"] == principal_id.to_string())
    );

    let response = ctx
        .request(
            Method::POST,
            &format!("/v1/principals/{principal_id}/rotate"),
        )
        .send()
        .await?;
    let body = expect_json(response, StatusCode::OK).await?;
    let rotated_token = body["token"]
        .as_str()
        .expect("rotate principal response includes token");
    assert!(rotated_token.starts_with("pht_"));
    assert_ne!(rotated_token, first_token);

    let response = ctx
        .request(
            Method::POST,
            &format!("/v1/principals/{principal_id}/retire"),
        )
        .send()
        .await?;
    let body = expect_json(response, StatusCode::OK).await?;
    assert_eq!(body["principal_id"], principal_id.to_string());
    assert_eq!(body["is_retired"], true);

    Ok(())
}

/// Requires Docker with a MySQL testcontainer; ignored by default so default CI stays green.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires MySQL testcontainer"]
#[serial_test::file_serial(docker)]
async fn role_and_membership() -> TestResult<()> {
    let ctx = setup().await?;
    let (principal_id, _token) = create_principal(&ctx, "Role subject").await?;
    let role_id = create_role(&ctx, "Audit reader", &["audit:read"]).await?;
    let membership_id = create_membership(&ctx, principal_id, role_id).await?;

    let response = ctx
        .request(Method::GET, "/v1/role-memberships")
        .send()
        .await?;
    let body = expect_json(response, StatusCode::OK).await?;
    assert!(
        body["items"]
            .as_array()
            .expect("membership list includes items")
            .iter()
            .any(|item| item["membership_id"] == membership_id.to_string()
                && item["principal_id"] == principal_id.to_string()
                && item["role_id"] == role_id.to_string())
    );

    let response = ctx
        .request(
            Method::DELETE,
            &format!("/v1/role-memberships/{membership_id}"),
        )
        .send()
        .await?;
    let body = expect_json(response, StatusCode::OK).await?;
    assert_eq!(body["membership_id"], membership_id.to_string());
    assert_eq!(body["is_retired"], true);

    Ok(())
}

/// Requires Docker with a MySQL testcontainer; ignored by default so default CI stays green.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires MySQL testcontainer"]
#[serial_test::file_serial(docker)]
async fn tenant_settings() -> TestResult<()> {
    let ctx = setup().await?;

    let response = ctx.request(Method::GET, "/v1/tenant").send().await?;
    let body = expect_json(response, StatusCode::OK).await?;
    assert_eq!(body["tenant_id"], ctx.tenant.public().as_uuid().to_string());
    assert_eq!(body["display_name"], "E2E Tenant");
    assert_eq!(body["status"], "active");

    let response = ctx
        .request(Method::PATCH, "/v1/tenant")
        .json(&json!({ "display_name": "E2E Tenant Updated" }))
        .send()
        .await?;
    let body = expect_json(response, StatusCode::OK).await?;
    assert_eq!(body["display_name"], "E2E Tenant Updated");

    let response = ctx.request(Method::GET, "/v1/tenant").send().await?;
    let body = expect_json(response, StatusCode::OK).await?;
    assert_eq!(body["display_name"], "E2E Tenant Updated");
    assert_eq!(body["latest_revision"], 1);

    Ok(())
}

/// Requires Docker with a MySQL testcontainer; ignored by default so default CI stays green.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires MySQL testcontainer"]
#[serial_test::file_serial(docker)]
async fn audit_log_records_operations() -> TestResult<()> {
    let ctx = setup().await?;
    let (principal_id, _token) = create_principal(&ctx, "Audited principal").await?;
    let role_id = create_role(&ctx, "Audited role", &["audit:read"]).await?;

    let first_event = write_audit_event(
        ctx.store.as_ref(),
        AuditEventInput {
            tenant: ctx.tenant,
            event_type: 100,
            timestamp: UnixMillis(1_000),
            event_data: json!({
                "summary": "principal-created",
                "principal_id": principal_id.to_string()
            }),
        },
    )
    .await?;
    let second_event = write_audit_event(
        ctx.store.as_ref(),
        AuditEventInput {
            tenant: ctx.tenant,
            event_type: 101,
            timestamp: UnixMillis(2_000),
            event_data: json!({
                "summary": "role-created",
                "role_id": role_id.to_string()
            }),
        },
    )
    .await?;

    let response = ctx.request(Method::GET, "/v1/audit").send().await?;
    let body = expect_json(response, StatusCode::OK).await?;
    let items = body["items"]
        .as_array()
        .expect("audit list response includes items");
    assert!(items.iter().any(|item| {
        item["audit_event_id"] == first_event.public().as_uuid().to_string()
            && item["event_type"] == 100
            && item["event_data"]["summary"] == "principal-created"
            && item["principal_id"] == principal_id.to_string()
    }));
    assert!(items.iter().any(|item| {
        item["audit_event_id"] == second_event.public().as_uuid().to_string()
            && item["event_type"] == 101
            && item["event_data"]["summary"] == "role-created"
    }));

    let response = ctx
        .request(
            Method::GET,
            &format!("/v1/audit?event_type=100&principal_id={principal_id}"),
        )
        .send()
        .await?;
    let body = expect_json(response, StatusCode::OK).await?;
    let filtered = body["items"]
        .as_array()
        .expect("filtered audit response includes items");
    assert_eq!(filtered.len(), 1);
    assert_eq!(
        filtered[0]["audit_event_id"],
        first_event.public().as_uuid().to_string()
    );

    Ok(())
}
