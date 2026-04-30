use std::{collections::HashMap, sync::Arc, time::Duration};

use axum::{
    Json, Router,
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response as AxumResponse},
    routing::post,
};
use coset::CborSerializable;
use ed25519_dalek::SigningKey;
use ml_kem::{EncodedSizeUser, KemCore, MlKem768};
use philharmonic_api::{ApiStore, PhilharmonicApiBuilder, RequestScope, StubExecutor, StubLowerer};
use philharmonic_connector_client::{AeadAadInputs, LowererSigningKey, encrypt_payload};
use philharmonic_connector_common::{ConnectorTokenClaims, RealmId, RealmPublicKey};
use philharmonic_connector_impl_api::{Implementation, ImplementationError, JsonValue};
use philharmonic_connector_impl_vector_search::VectorSearch;
use philharmonic_connector_service::{
    MintingKeyEntry, MintingKeyRegistry, RealmPrivateKeyEntry, RealmPrivateKeyRegistry, UnixMillis,
    verify_and_decrypt,
};
use philharmonic_policy::{
    ALL_ATOMS, Principal, PrincipalKind, RoleDefinition, RoleMembership, Sck, Tenant, TenantStatus,
    TokenHash, generate_api_token,
};
use philharmonic_store::{
    ContentStore, EntityRefValue, EntityStoreExt, IdentityStore, RevisionInput, StoreError,
    StoreExt,
};
use philharmonic_store_sqlx_mysql::{SinglePool, SqlStore, migrate};
use philharmonic_types::{CanonicalJson, ContentValue, EntityId, ScalarValue, Sha256, Uuid};
use philharmonic_workflow::WorkflowInstance;
use rand_core::OsRng;
use reqwest::{Client, Method, Response};
use serde::Deserialize;
use serde_json::json;
use sqlx::{MySqlPool, mysql::MySqlPoolOptions};
use testcontainers_modules::{
    mysql::Mysql,
    testcontainers::{ContainerAsync, ImageExt, core::IntoContainerPort, runners::AsyncRunner},
};
use tokio::{net::TcpListener, task::JoinHandle};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

mod common;

type TestResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
type ContainerHandle = ContainerAsync<Mysql>;
type ImplementationRegistry = HashMap<String, Box<dyn Implementation>>;

const SERVICE_REALM: &str = "test-realm";
const REALM_KID: &str = "test-realm-kid";
const LOWERER_KID: &str = "test-lowerer-kid";
const LOWERER_ISSUER: &str = "e2e-full-pipeline";
const ENCRYPTED_PAYLOAD_HEADER: &str = "x-encrypted-payload";

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

struct ConnectorContext {
    base_url: String,
    server: JoinHandle<()>,
}

impl Drop for ConnectorContext {
    fn drop(&mut self) {
        self.server.abort();
    }
}

#[derive(Clone)]
struct ConnectorState {
    service_realm: String,
    minting_registry: MintingKeyRegistry,
    realm_registry: RealmPrivateKeyRegistry,
    implementations: Arc<ImplementationRegistry>,
}

#[derive(Deserialize)]
struct DecryptedPayload {
    realm: String,
    #[serde(rename = "impl")]
    implementation: String,
    config: JsonValue,
}

#[derive(serde::Serialize)]
struct ErrorEnvelope {
    error: ErrorBody,
}

#[derive(serde::Serialize)]
struct ErrorBody {
    kind: &'static str,
    message: String,
}

#[derive(Clone)]
struct CryptoKeys {
    signing_key: LowererSigningKey,
    minting_registry: MintingKeyRegistry,
    realm_public_key: RealmPublicKey,
    realm_registry: RealmPrivateKeyRegistry,
}

async fn setup_api() -> TestResult<TestContext> {
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
    let tenant = seed_tenant(store.as_ref(), "Full Pipeline Tenant", TenantStatus::Active).await?;
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
        .sck(Sck::from_bytes([0x42; 32]))
        .key_version(1)
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

async fn setup_connector(keys: &CryptoKeys) -> TestResult<ConnectorContext> {
    let mut implementations = ImplementationRegistry::new();
    let vector_search = VectorSearch::new();
    implementations.insert(
        vector_search.name().to_string(),
        Box::new(vector_search) as Box<dyn Implementation>,
    );

    let state = ConnectorState {
        service_realm: SERVICE_REALM.to_string(),
        minting_registry: keys.minting_registry.clone(),
        realm_registry: keys.realm_registry.clone(),
        implementations: Arc::new(implementations),
    };
    let app = Router::new()
        .route("/", post(handle_connector_request))
        .with_state(state);

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let server = tokio::spawn(async move {
        if let Err(error) = axum::serve(listener, app).await {
            panic!("e2e connector server stopped unexpectedly: {error}");
        }
    });

    Ok(ConnectorContext {
        base_url: format!("http://{addr}"),
        server,
    })
}

fn generate_crypto_keys() -> CryptoKeys {
    let ed_signing_key = SigningKey::generate(&mut OsRng);
    let ed_verifying_key = ed_signing_key.verifying_key();

    let (dk, ek) = MlKem768::generate(&mut OsRng);
    let kem_sk = dk
        .as_bytes()
        .to_vec()
        .try_into()
        .expect("ML-KEM-768 decapsulation key must be 2400 bytes");
    let kem_public = ek.as_bytes().to_vec();

    let x25519_sk = StaticSecret::random_from_rng(OsRng);
    let x25519_pk = PublicKey::from(&x25519_sk);

    let not_before = UnixMillis(1_700_000_000_000);
    let not_after = UnixMillis(1_950_000_000_000);

    let mut minting_registry = MintingKeyRegistry::new();
    minting_registry.insert(
        LOWERER_KID.to_string(),
        MintingKeyEntry {
            vk: ed_verifying_key,
            not_before,
            not_after,
        },
    );

    let mut realm_registry = RealmPrivateKeyRegistry::new();
    realm_registry.insert(
        REALM_KID.to_string(),
        RealmPrivateKeyEntry {
            kem_sk: Zeroizing::new(kem_sk),
            ecdh_sk: x25519_sk,
            realm: RealmId::new(SERVICE_REALM),
            not_before,
            not_after,
        },
    );

    let realm_public_key = RealmPublicKey::new(
        REALM_KID,
        RealmId::new(SERVICE_REALM),
        kem_public,
        x25519_pk.to_bytes(),
        not_before,
        not_after,
    )
    .expect("generated realm public key must be valid");

    CryptoKeys {
        signing_key: LowererSigningKey::from_seed(
            Zeroizing::new(ed_signing_key.to_bytes()),
            LOWERER_KID.to_string(),
        ),
        minting_registry,
        realm_public_key,
        realm_registry,
    }
}

async fn handle_connector_request(
    State(state): State<ConnectorState>,
    headers: HeaderMap,
    body: Bytes,
) -> AxumResponse {
    match handle_connector_request_inner(state, headers, body).await {
        Ok(response) => Json(response).into_response(),
        Err(error) => error.into_response(),
    }
}

async fn handle_connector_request_inner(
    state: ConnectorState,
    headers: HeaderMap,
    body: Bytes,
) -> Result<JsonValue, ServiceError> {
    let token_cose_bytes = bearer_token_bytes(&headers)?;
    let encrypted_payload_bytes = encrypted_payload_bytes(&headers)?;
    let request = serde_json::from_slice::<JsonValue>(&body).map_err(|error| {
        ServiceError::bad_request(format!("request body must be valid JSON: {error}"))
    })?;

    let verified = verify_and_decrypt(
        &token_cose_bytes,
        &encrypted_payload_bytes,
        &state.service_realm,
        &state.minting_registry,
        &state.realm_registry,
        UnixMillis::now(),
    )
    .map_err(|error| ServiceError::unauthorized(format!("token verification failed: {error}")))?;

    let payload =
        serde_json::from_slice::<DecryptedPayload>(&verified.plaintext).map_err(|error| {
            ServiceError::bad_request(format!("decrypted connector payload is invalid: {error}"))
        })?;
    if payload.realm != state.service_realm {
        return Err(ServiceError::unauthorized(format!(
            "decrypted connector payload realm '{}' does not match service realm '{}'",
            payload.realm, state.service_realm
        )));
    }

    let implementation = state
        .implementations
        .get(&payload.implementation)
        .ok_or_else(|| {
            ServiceError::not_found(format!(
                "unknown connector implementation '{}'",
                payload.implementation
            ))
        })?;

    implementation
        .execute(&payload.config, &request, &verified.context)
        .await
        .map_err(ServiceError::implementation)
}

fn bearer_token_bytes(headers: &HeaderMap) -> Result<Vec<u8>, ServiceError> {
    let value = headers
        .get(header::AUTHORIZATION)
        .ok_or_else(|| ServiceError::unauthorized("missing Authorization bearer token"))?
        .to_str()
        .map_err(|_| ServiceError::unauthorized("Authorization header is not valid ASCII"))?;
    let Some(token) = value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))
    else {
        return Err(ServiceError::unauthorized(
            "Authorization header must use Bearer scheme",
        ));
    };
    decode_hex_header(token, "Authorization bearer token").map_err(ServiceError::unauthorized)
}

fn encrypted_payload_bytes(headers: &HeaderMap) -> Result<Vec<u8>, ServiceError> {
    let value = headers
        .get(ENCRYPTED_PAYLOAD_HEADER)
        .ok_or_else(|| ServiceError::bad_request("missing X-Encrypted-Payload header"))?
        .to_str()
        .map_err(|_| ServiceError::bad_request("X-Encrypted-Payload header is not valid ASCII"))?;
    decode_hex_header(value, "X-Encrypted-Payload header").map_err(ServiceError::bad_request)
}

fn decode_hex_header(value: &str, label: &str) -> Result<Vec<u8>, String> {
    let compact = value
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect::<String>();
    if compact.is_empty() {
        return Err(format!("{label} is empty"));
    }
    hex::decode(&compact)
        .map_err(|error| format!("{label} must be hex-encoded COSE bytes: {error}"))
}

struct ServiceError {
    status: StatusCode,
    kind: &'static str,
    message: String,
}

impl ServiceError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            kind: "bad_request",
            message: message.into(),
        }
    }

    fn unauthorized(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            kind: "unauthorized",
            message: message.into(),
        }
    }

    fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            kind: "not_found",
            message: message.into(),
        }
    }

    fn implementation(error: ImplementationError) -> Self {
        let status = implementation_status(&error);
        Self {
            status,
            kind: implementation_error_kind(&error),
            message: error.to_string(),
        }
    }
}

impl IntoResponse for ServiceError {
    fn into_response(self) -> AxumResponse {
        (
            self.status,
            Json(ErrorEnvelope {
                error: ErrorBody {
                    kind: self.kind,
                    message: self.message,
                },
            }),
        )
            .into_response()
    }
}

fn implementation_status(error: &ImplementationError) -> StatusCode {
    match error {
        ImplementationError::InvalidConfig { .. } | ImplementationError::InvalidRequest { .. } => {
            StatusCode::BAD_REQUEST
        }
        ImplementationError::SchemaValidationFailed { .. } => StatusCode::UNPROCESSABLE_ENTITY,
        ImplementationError::UpstreamError { .. }
        | ImplementationError::UpstreamUnreachable { .. }
        | ImplementationError::ResponseTooLarge { .. } => StatusCode::BAD_GATEWAY,
        ImplementationError::UpstreamTimeout => StatusCode::GATEWAY_TIMEOUT,
        ImplementationError::Internal { .. } => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

fn implementation_error_kind(error: &ImplementationError) -> &'static str {
    match error {
        ImplementationError::InvalidConfig { .. } => "invalid_config",
        ImplementationError::UpstreamError { .. } => "upstream_error",
        ImplementationError::UpstreamUnreachable { .. } => "upstream_unreachable",
        ImplementationError::UpstreamTimeout => "upstream_timeout",
        ImplementationError::SchemaValidationFailed { .. } => "schema_validation_failed",
        ImplementationError::ResponseTooLarge { .. } => "response_too_large",
        ImplementationError::InvalidRequest { .. } => "invalid_request",
        ImplementationError::Internal { .. } => "internal",
    }
}

fn lower_config(
    abstract_config: &JsonValue,
    instance_id: EntityId<WorkflowInstance>,
    step_seq: u64,
    tenant: Uuid,
    keys: &CryptoKeys,
) -> TestResult<JsonValue> {
    let object = abstract_config
        .as_object()
        .expect("abstract config must be a JSON object");

    let realm = object["realm"]
        .as_str()
        .expect("abstract config realm must be a string")
        .to_string();
    let implementation = object["impl"]
        .as_str()
        .expect("abstract config impl must be a string")
        .to_string();
    let config_uuid = Uuid::parse_str(
        object["config_uuid"]
            .as_str()
            .expect("abstract config config_uuid must be a string"),
    )?;
    let config = object["config"].clone();

    let inst = instance_id.internal().as_uuid();
    let kid = keys.signing_key.kid();

    let plaintext = serde_json::to_vec(&json!({
        "realm": realm,
        "impl": implementation,
        "config": config,
    }))?;

    let encrypted_payload = encrypt_payload(
        &plaintext,
        &keys.realm_public_key,
        AeadAadInputs {
            realm: &realm,
            tenant,
            inst,
            step: step_seq,
            config_uuid,
            kid,
        },
        &mut OsRng,
    )?;
    let encrypted_payload_bytes = encrypted_payload.into_inner().to_vec()?;
    let payload_hash = Sha256::of(&encrypted_payload_bytes);
    let now = UnixMillis::now();
    let exp = UnixMillis(now.as_i64() + 600_000);

    let claims = ConnectorTokenClaims {
        iss: LOWERER_ISSUER.to_string(),
        exp,
        iat: now,
        kid: kid.to_string(),
        realm,
        tenant,
        inst,
        step: step_seq,
        config_uuid,
        payload_hash,
    };

    let token = keys.signing_key.mint_token(&claims)?;
    let token_bytes = token.into_inner().to_vec()?;

    Ok(json!({
        "token": hex::encode(token_bytes),
        "encrypted_payload": hex::encode(encrypted_payload_bytes),
    }))
}

async fn migrate_schema(pool: &MySqlPool) -> TestResult<()> {
    match migrate(pool).await {
        Ok(()) => Ok(()),
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
        "Full Pipeline Admin",
        PrincipalKind::User,
        Some(token_hash_content_hash(token_hash)),
    )
    .await?;
    let role = seed_role(store, tenant, "Full Pipeline Admin Role", permissions).await?;
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

async fn create_template(
    ctx: &TestContext,
    display_name: &str,
    abstract_config: &JsonValue,
) -> TestResult<Uuid> {
    let response = ctx
        .request(Method::POST, "/v1/workflows/templates")
        .json(&json!({
            "display_name": display_name,
            "script_source": "export default async function main() {}",
            "abstract_config": abstract_config
        }))
        .send()
        .await?;
    let body = expect_json(response, StatusCode::CREATED).await?;
    Ok(body["template_id"]
        .as_str()
        .expect("create template response includes template_id")
        .parse()?)
}

async fn create_endpoint(
    ctx: &TestContext,
    display_name: &str,
    config: &JsonValue,
) -> TestResult<Uuid> {
    let response = ctx
        .request(Method::POST, "/v1/endpoints")
        .json(&json!({
            "display_name": display_name,
            "config": config
        }))
        .send()
        .await?;
    let body = expect_json(response, StatusCode::CREATED).await?;
    Ok(body["endpoint_id"]
        .as_str()
        .expect("create endpoint response includes endpoint_id")
        .parse()?)
}

async fn create_instance(ctx: &TestContext, template_id: Uuid) -> TestResult<Uuid> {
    let response = ctx
        .request(Method::POST, "/v1/workflows/instances")
        .json(&json!({
            "template_id": template_id,
            "args": { "conversation_id": "full-pipeline-1" }
        }))
        .send()
        .await?;
    let body = expect_json(response, StatusCode::CREATED).await?;
    Ok(body["instance_id"]
        .as_str()
        .expect("create instance response includes instance_id")
        .parse()?)
}

async fn resolve_instance_id(
    store: &SqlStore<SinglePool>,
    public: Uuid,
) -> TestResult<EntityId<WorkflowInstance>> {
    let identity = store
        .resolve_public(public)
        .await?
        .expect("workflow instance public ID must resolve");
    Ok(identity.typed()?)
}

fn abstract_vector_search_config(config_uuid: Uuid) -> JsonValue {
    json!({
        "realm": SERVICE_REALM,
        "impl": "vector_search",
        "config_uuid": config_uuid.to_string(),
        "config": {
            "max_corpus_size": 10,
            "timeout_ms": 2_000
        }
    })
}

fn vector_search_request() -> JsonValue {
    json!({
        "query_vector": [1.0, 0.0],
        "corpus": [
            {
                "id": "alpha",
                "vector": [1.0, 0.0],
                "payload": { "title": "Exact match" }
            },
            {
                "id": "beta",
                "vector": [0.5, 0.5],
                "payload": { "title": "Nearby match" }
            },
            {
                "id": "gamma",
                "vector": [0.0, 1.0],
                "payload": { "title": "Orthogonal match" }
            }
        ],
        "top_k": 2
    })
}

/// Requires Docker with a MySQL testcontainer; ignored by default so default CI stays green.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires MySQL testcontainer"]
#[serial_test::file_serial(docker)]
async fn full_pipeline_step_execution() -> TestResult<()> {
    let keys = generate_crypto_keys();
    let connector = setup_connector(&keys).await?;
    let ctx = setup_api().await?;

    let endpoint_id = create_endpoint(
        &ctx,
        "Vector search endpoint",
        &json!({
            "realm": SERVICE_REALM,
            "impl": "vector_search",
            "config": {
                "max_corpus_size": 10,
                "timeout_ms": 2_000
            }
        }),
    )
    .await?;
    let template_abstract_config = json!({ "vector_search": endpoint_id.to_string() });
    let connector_config = abstract_vector_search_config(endpoint_id);
    let template_id = create_template(
        &ctx,
        "Full pipeline vector search",
        &template_abstract_config,
    )
    .await?;
    let instance_public_id = create_instance(&ctx, template_id).await?;
    let instance_id = resolve_instance_id(ctx.store.as_ref(), instance_public_id).await?;

    let lowered = lower_config(
        &connector_config,
        instance_id,
        1,
        ctx.tenant.internal().as_uuid(),
        &keys,
    )?;
    let response = ctx
        .client
        .post(&connector.base_url)
        .bearer_auth(
            lowered["token"]
                .as_str()
                .expect("lowered config contains token"),
        )
        .header(
            "X-Encrypted-Payload",
            lowered["encrypted_payload"]
                .as_str()
                .expect("lowered config contains encrypted_payload"),
        )
        .json(&vector_search_request())
        .send()
        .await?;

    let body = expect_json(response, StatusCode::OK).await?;
    let results = body["results"]
        .as_array()
        .expect("vector_search response contains results");
    let ids = results
        .iter()
        .map(|item| item["id"].as_str().expect("result id must be a string"))
        .collect::<Vec<_>>();

    assert_eq!(ids, vec!["alpha", "beta"]);
    assert_eq!(results[0]["payload"]["title"], "Exact match");
    assert_eq!(results[1]["payload"]["title"], "Nearby match");

    Ok(())
}
