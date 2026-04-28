//! Authentication middleware for the public API.
//!
//! Long-lived `pht_` tokens authenticate persistent principals by
//! substrate lookup. Other bearer values are treated as base64url-encoded
//! ephemeral COSE_Sign1 tokens and verified with `philharmonic-policy`.

use std::sync::Arc;

use axum::{
    Extension,
    extract::Request,
    http::{StatusCode, header::AUTHORIZATION},
    middleware::Next,
    response::{IntoResponse, Response},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use philharmonic_policy::{
    ApiTokenVerifyError, ApiVerifyingKeyRegistry, MAX_TOKEN_BYTES, MintingAuthority, Principal,
    TOKEN_PREFIX, Tenant, TenantStatus, parse_api_token, verify_ephemeral_api_token,
};
use philharmonic_store::{
    EntityRefValue, EntityRow, EntityStoreExt, RevisionRow, StoreError, StoreExt,
};
use philharmonic_types::{ContentValue, Entity, EntityId, IdentityKindError, ScalarValue};
use philharmonic_types::{UnixMillis, Uuid};

use crate::{
    ApiError, AuthContext, RequestContext,
    context::CorrelationContext,
    error::{ErrorCode, envelope_response},
    store::{ApiStore, ApiStoreHandle},
};

const CREDENTIAL_HASH_ATTR: &str = "credential_hash";
const TENANT_ATTR: &str = "tenant";
const IS_RETIRED_ATTR: &str = "is_retired";
const TENANT_STATUS_ATTR: &str = "status";
const AUTHORITY_EPOCH_ATTR: &str = "epoch";
const META_PREFIX: &str = "/v1/_meta/";

/// State required by the authentication middleware.
#[derive(Clone)]
pub struct AuthState {
    store: ApiStoreHandle,
    registry: Arc<ApiVerifyingKeyRegistry>,
}

impl AuthState {
    /// Construct authentication middleware state.
    pub fn new(store: Arc<dyn ApiStore>, registry: Arc<ApiVerifyingKeyRegistry>) -> Self {
        Self {
            store: ApiStoreHandle::new(store),
            registry,
        }
    }
}

/// Authenticate non-meta API requests and attach [`AuthContext`].
pub async fn authenticate(
    Extension(state): Extension<AuthState>,
    mut request: Request,
    next: Next,
) -> Response {
    if request.uri().path().starts_with(META_PREFIX) {
        return next.run(request).await;
    }

    let correlation_id = correlation_id(&request);
    let token = match bearer_token(&request) {
        Ok(token) => token,
        Err(failure) => {
            tracing::warn!(?failure, "authentication rejected");
            return unauthenticated_response(correlation_id);
        }
    };
    let result = authenticate_token(&state, token).await;
    let auth_context = match result {
        Ok(auth_context) => auth_context,
        Err(failure) => {
            tracing::warn!(?failure, "authentication rejected");
            return unauthenticated_response(correlation_id);
        }
    };

    let Some(context) = request.extensions_mut().get_mut::<RequestContext>() else {
        tracing::warn!(%correlation_id, "auth middleware ran without request context");
        return ApiError::Internal("missing request context".to_string())
            .into_response_with_correlation_id(correlation_id);
    };
    context.auth = Some(auth_context);

    next.run(request).await
}

async fn authenticate_token(state: &AuthState, token: String) -> Result<AuthContext, AuthFailure> {
    if token.starts_with(TOKEN_PREFIX) {
        authenticate_long_lived(&state.store, &token).await
    } else {
        authenticate_ephemeral(&state.store, state.registry.as_ref(), &token).await
    }
}

fn bearer_token(request: &Request) -> Result<String, AuthFailure> {
    let value = request
        .headers()
        .get(AUTHORIZATION)
        .ok_or(AuthFailure::MissingBearer)?;
    let value = value.to_str().map_err(|_| AuthFailure::MalformedBearer)?;
    let Some((scheme, token)) = value.split_once(' ') else {
        return Err(AuthFailure::MalformedBearer);
    };
    if !scheme.eq_ignore_ascii_case("Bearer") || token.is_empty() || token.trim() != token {
        return Err(AuthFailure::MalformedBearer);
    }
    Ok(token.to_string())
}

async fn authenticate_long_lived(
    store: &dyn StoreExt,
    token: &str,
) -> Result<AuthContext, AuthFailure> {
    let token_hash = parse_api_token(token).map_err(|error| AuthFailure::LongLivedParse {
        error: error.to_string(),
    })?;
    let credential_hash = ContentValue::new(token_hash.0.to_vec()).digest();

    let principal_rows = store
        .find_by_content_typed::<Principal>(CREDENTIAL_HASH_ATTR, credential_hash)
        .await?;
    if let Some(row) = exactly_one(principal_rows)? {
        return long_lived_principal_context(store, row).await;
    }

    let authority_rows = store
        .find_by_content_typed::<MintingAuthority>(CREDENTIAL_HASH_ATTR, credential_hash)
        .await?;
    let Some(row) = exactly_one(authority_rows)? else {
        return Err(AuthFailure::CredentialNotFound);
    };
    long_lived_principal_context(store, row).await
}

async fn long_lived_principal_context(
    store: &dyn StoreExt,
    row: EntityRow,
) -> Result<AuthContext, AuthFailure> {
    let revision = latest_revision(store, row.identity.internal).await?;
    reject_if_retired(&revision)?;
    let tenant_uuid = tenant_ref(&revision)?;
    let tenant_id = active_tenant_id(store, tenant_uuid).await?;
    let principal_id = row
        .identity
        .typed::<Principal>()
        .map_err(AuthFailure::Identity)?;
    Ok(AuthContext::Principal {
        principal_id,
        tenant_id,
    })
}

const MAX_BEARER_ENCODED_LEN: usize = MAX_TOKEN_BYTES * 4 / 3 + 4;

async fn authenticate_ephemeral(
    store: &dyn StoreExt,
    registry: &ApiVerifyingKeyRegistry,
    token: &str,
) -> Result<AuthContext, AuthFailure> {
    if token.len() > MAX_BEARER_ENCODED_LEN {
        return Err(AuthFailure::MalformedBearer);
    }
    let token_bytes = URL_SAFE_NO_PAD
        .decode(token)
        .map_err(|_| AuthFailure::MalformedBearer)?;
    let claims = verify_ephemeral_api_token(&token_bytes, registry, UnixMillis::now())
        .map_err(AuthFailure::EphemeralVerify)?;

    let authority_row = store
        .get_entity(claims.authority)
        .await?
        .ok_or(AuthFailure::AuthorityNotFound)?;
    if authority_row.kind != MintingAuthority::KIND {
        return Err(AuthFailure::InvalidSubstrate("authority kind mismatch"));
    }

    let authority_id = authority_row
        .identity
        .typed::<MintingAuthority>()
        .map_err(AuthFailure::Identity)?;
    let revision = latest_revision(store, claims.authority).await?;
    let authority_tenant = tenant_ref(&revision)?;
    if authority_tenant != claims.tenant {
        return Err(AuthFailure::AuthorityTenantMismatch);
    }

    reject_if_retired(&revision)?;
    let stored_epoch = i64_scalar(&revision, AUTHORITY_EPOCH_ATTR)?;
    let epoch = u64::try_from(stored_epoch).map_err(|_| AuthFailure::NegativeAuthorityEpoch)?;
    if epoch != claims.authority_epoch {
        return Err(AuthFailure::AuthorityEpochMismatch);
    }

    let tenant_id = active_tenant_id(store, claims.tenant).await?;
    AuthContext::from_ephemeral_claims(claims, tenant_id, authority_id)
        .map_err(|error| AuthFailure::InjectedClaimsJson(error.to_string()))
}

async fn latest_revision(
    store: &dyn StoreExt,
    entity_id: Uuid,
) -> Result<RevisionRow, AuthFailure> {
    store
        .get_latest_revision(entity_id)
        .await?
        .ok_or(AuthFailure::MissingLatestRevision)
}

async fn active_tenant_id(
    store: &dyn StoreExt,
    tenant_uuid: Uuid,
) -> Result<EntityId<Tenant>, AuthFailure> {
    let tenant_row = store
        .get_entity(tenant_uuid)
        .await?
        .ok_or(AuthFailure::TenantNotFound)?;
    if tenant_row.kind != Tenant::KIND {
        return Err(AuthFailure::InvalidSubstrate("tenant kind mismatch"));
    }

    let revision = latest_revision(store, tenant_uuid).await?;
    let status = i64_scalar(&revision, TENANT_STATUS_ATTR)?;
    let status = TenantStatus::try_from(status)
        .map_err(|_| AuthFailure::InvalidSubstrate("invalid tenant status"))?;
    if status != TenantStatus::Active {
        return Err(AuthFailure::TenantSuspended);
    }

    tenant_row
        .identity
        .typed::<Tenant>()
        .map_err(AuthFailure::Identity)
}

fn reject_if_retired(revision: &RevisionRow) -> Result<(), AuthFailure> {
    match revision.scalar_attrs.get(IS_RETIRED_ATTR) {
        Some(ScalarValue::Bool(false)) => Ok(()),
        Some(ScalarValue::Bool(true)) => Err(AuthFailure::EntityRetired),
        _ => Err(AuthFailure::InvalidSubstrate("missing is_retired bool")),
    }
}

fn tenant_ref(revision: &RevisionRow) -> Result<Uuid, AuthFailure> {
    match revision.entity_attrs.get(TENANT_ATTR) {
        Some(EntityRefValue {
            target_entity_id, ..
        }) => Ok(*target_entity_id),
        None => Err(AuthFailure::InvalidSubstrate("missing tenant reference")),
    }
}

fn i64_scalar(revision: &RevisionRow, attribute_name: &'static str) -> Result<i64, AuthFailure> {
    match revision.scalar_attrs.get(attribute_name) {
        Some(ScalarValue::I64(value)) => Ok(*value),
        _ => Err(AuthFailure::InvalidSubstrate("missing i64 scalar")),
    }
}

fn exactly_one(rows: Vec<EntityRow>) -> Result<Option<EntityRow>, AuthFailure> {
    let mut rows = rows.into_iter();
    let Some(first) = rows.next() else {
        return Ok(None);
    };
    if rows.next().is_some() {
        return Err(AuthFailure::AmbiguousCredential);
    }
    Ok(Some(first))
}

fn unauthenticated_response(correlation_id: uuid::Uuid) -> Response {
    envelope_response(
        StatusCode::UNAUTHORIZED,
        ErrorCode::Unauthenticated,
        "invalid token",
        correlation_id,
    )
    .into_response()
}

fn correlation_id(request: &Request) -> uuid::Uuid {
    request
        .extensions()
        .get::<RequestContext>()
        .map(|context| context.correlation_id)
        .or_else(|| {
            request
                .extensions()
                .get::<CorrelationContext>()
                .map(|context| context.correlation_id)
        })
        .unwrap_or_else(uuid::Uuid::new_v4)
}

enum AuthFailure {
    MissingBearer,
    MalformedBearer,
    LongLivedParse { error: String },
    CredentialNotFound,
    AmbiguousCredential,
    AuthorityNotFound,
    AuthorityTenantMismatch,
    EntityRetired,
    AuthorityEpochMismatch,
    NegativeAuthorityEpoch,
    TenantNotFound,
    TenantSuspended,
    MissingLatestRevision,
    InvalidSubstrate(&'static str),
    InjectedClaimsJson(String),
    Identity(IdentityKindError),
    Store(StoreError),
    EphemeralVerify(ApiTokenVerifyError),
}

impl From<StoreError> for AuthFailure {
    fn from(value: StoreError) -> Self {
        Self::Store(value)
    }
}

impl std::fmt::Debug for AuthFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingBearer => f.write_str("MissingBearer"),
            Self::MalformedBearer => f.write_str("MalformedBearer"),
            Self::LongLivedParse { error } => f
                .debug_struct("LongLivedParse")
                .field("error", error)
                .finish(),
            Self::CredentialNotFound => f.write_str("CredentialNotFound"),
            Self::AmbiguousCredential => f.write_str("AmbiguousCredential"),
            Self::AuthorityNotFound => f.write_str("AuthorityNotFound"),
            Self::AuthorityTenantMismatch => f.write_str("AuthorityTenantMismatch"),
            Self::EntityRetired => f.write_str("EntityRetired"),
            Self::AuthorityEpochMismatch => f.write_str("AuthorityEpochMismatch"),
            Self::NegativeAuthorityEpoch => f.write_str("NegativeAuthorityEpoch"),
            Self::TenantNotFound => f.write_str("TenantNotFound"),
            Self::TenantSuspended => f.write_str("TenantSuspended"),
            Self::MissingLatestRevision => f.write_str("MissingLatestRevision"),
            Self::InvalidSubstrate(detail) => {
                f.debug_tuple("InvalidSubstrate").field(detail).finish()
            }
            Self::InjectedClaimsJson(error) => {
                f.debug_tuple("InjectedClaimsJson").field(error).finish()
            }
            Self::Identity(error) => f.debug_tuple("Identity").field(error).finish(),
            Self::Store(error) => f.debug_tuple("Store").field(error).finish(),
            Self::EphemeralVerify(error) => f.debug_tuple("EphemeralVerify").field(error).finish(),
        }
    }
}
