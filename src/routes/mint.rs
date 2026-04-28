//! Ephemeral API token minting route.

use std::sync::Arc;

use axum::{
    Extension, Json, Router,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use philharmonic_policy::{
    ALL_ATOMS, ApiSigningKey, EphemeralApiTokenClaims, MAX_INJECTED_CLAIMS_BYTES,
    MintingAuthority, PermissionDocument, Principal, atom, mint_ephemeral_api_token,
};
use philharmonic_store::{EntityStore, EntityStoreExt};
use philharmonic_types::{CanonicalJson, Entity, EntityId, JsonValue, UnixMillis, Uuid};
use philharmonic_workflow::WorkflowInstance;
use serde::{Deserialize, Serialize};

use crate::{
    ApiError, AuthContext, RequestContext,
    routes::identity::{
        bool_scalar, ensure_revision_tenant, i64_scalar, latest_revision, load_json,
        required_content_hash, required_entity_ref, resolve_public_id, store_error, tenant_scope,
    },
    store::{ApiStore, ApiStoreHandle},
};

const SYSTEM_MAX_LIFETIME_SECONDS: u64 = 86_400;
const MILLIS_PER_SECOND: i64 = 1000;
const SECONDS_PER_DAY: i64 = 86_400;
const UNIX_EPOCH_DAY_OFFSET: i64 = 719_468;

/// Shared token-minting route state.
#[derive(Clone)]
pub(crate) struct MintState {
    store: ApiStoreHandle,
    signing_key: Arc<ApiSigningKey>,
    issuer: Arc<str>,
}

impl MintState {
    pub(crate) fn new(
        store: Arc<dyn ApiStore>,
        signing_key: Arc<ApiSigningKey>,
        issuer: Arc<str>,
    ) -> Self {
        Self {
            store: ApiStoreHandle::new(store),
            signing_key,
            issuer,
        }
    }
}

/// Build token-minting routes.
pub fn router() -> Router {
    Router::new().route("/v1/tokens/mint", post(mint_token))
}

async fn mint_token(
    Extension(state): Extension<MintState>,
    Extension(context): Extension<RequestContext>,
    Json(request): Json<MintTokenRequest>,
) -> Result<Response, ApiError> {
    let scope_tenant = tenant_scope(&context)?;
    let (authority_id, tenant_id) = require_minting_authority_context(&state, &context).await?;
    if tenant_id != scope_tenant {
        return Err(ApiError::Forbidden);
    }

    validate_permission_atoms(&request.requested_permissions)?;
    let authority = load_authority(&state, authority_id, tenant_id).await?;
    authority.ensure_can_mint()?;
    validate_lifetime_seconds(request.lifetime_seconds, authority.max_lifetime_seconds)?;
    let permissions = clip_permissions(
        &request.requested_permissions,
        &authority.permission_envelope,
        authority_id,
    );
    let claims = canonical_claims(&request.injected_claims)?;
    validate_instance_scope(&state.store, tenant_id, request.instance_id).await?;

    let iat = UnixMillis::now();
    let lifetime_millis = lifetime_millis(request.lifetime_seconds)?;
    let exp = UnixMillis(
        iat.as_i64()
            .checked_add(lifetime_millis)
            .ok_or_else(|| ApiError::Internal("token expiry overflow".to_string()))?,
    );
    let token_claims = EphemeralApiTokenClaims {
        iss: state.issuer.to_string(),
        iat,
        exp,
        sub: request.subject.clone(),
        tenant: tenant_id.internal().as_uuid(),
        authority: authority_id.internal().as_uuid(),
        authority_epoch: authority.epoch,
        instance: request.instance_id,
        permissions,
        claims,
        kid: state.signing_key.kid().to_string(),
    };

    let token =
        mint_ephemeral_api_token(&state.signing_key, &token_claims, iat).map_err(|error| {
            tracing::warn!(?error, "ephemeral token signing failed");
            ApiError::Internal("token signing failed".to_string())
        })?;
    let token_bytes = token.to_bytes().map_err(|error| {
        tracing::warn!(?error, "ephemeral token serialization failed");
        ApiError::Internal("token signing failed".to_string())
    })?;
    if token_bytes.len() > philharmonic_policy::MAX_TOKEN_BYTES {
        return Err(ApiError::InvalidRequest(
            "minted token exceeds maximum token size; reduce subject length or permissions"
                .to_string(),
        ));
    }
    let encoded = URL_SAFE_NO_PAD.encode(token_bytes);

    let audit_instance_id = request.instance_id.map(|id| id.to_string());
    tracing::info!(
        subject = %request.subject,
        authority_id = %authority_id.internal().as_uuid(),
        tenant_id = %tenant_id.internal().as_uuid(),
        instance_id = audit_instance_id.as_deref(),
        "token minting event"
    );

    Ok((
        StatusCode::OK,
        Json(MintTokenResponse {
            token: encoded,
            expires_at: unix_millis_rfc3339(exp)?,
            subject: request.subject,
            instance_id: request.instance_id,
        }),
    )
        .into_response())
}

async fn require_minting_authority_context(
    state: &MintState,
    context: &RequestContext,
) -> Result<(EntityId<MintingAuthority>, EntityId<crate::Tenant>), ApiError> {
    let Some(AuthContext::Principal {
        principal_id,
        tenant_id,
    }) = context.auth.as_ref()
    else {
        return Err(ApiError::Forbidden);
    };

    let entity = state
        .store
        .get_entity(principal_id.internal().as_uuid())
        .await
        .map_err(store_error)?
        .ok_or_else(|| {
            ApiError::Internal("authenticated principal entity not found".to_string())
        })?;

    if entity.kind == Principal::KIND {
        return Err(ApiError::Forbidden);
    }
    if entity.kind != MintingAuthority::KIND {
        return Err(ApiError::Internal(
            "authenticated principal has unexpected entity kind".to_string(),
        ));
    }

    let authority_id = principal_id
        .untyped()
        .typed::<MintingAuthority>()
        .map_err(|error| {
            ApiError::Internal(format!("invalid minting authority identity: {error}"))
        })?;
    Ok((authority_id, *tenant_id))
}

struct LoadedAuthority {
    permission_envelope: PermissionDocument,
    epoch: u64,
    max_lifetime_seconds: u64,
    is_retired: bool,
}

impl LoadedAuthority {
    fn ensure_can_mint(&self) -> Result<(), ApiError> {
        if self.is_retired {
            return Err(ApiError::Forbidden);
        }
        if !self
            .permission_envelope
            .contains(atom::MINT_EPHEMERAL_TOKEN)
        {
            return Err(ApiError::Forbidden);
        }
        Ok(())
    }
}

async fn load_authority(
    state: &MintState,
    authority_id: EntityId<MintingAuthority>,
    tenant_id: EntityId<crate::Tenant>,
) -> Result<LoadedAuthority, ApiError> {
    let latest = state
        .store
        .get_latest_revision_typed::<MintingAuthority>(authority_id)
        .await
        .map_err(store_error)?
        .ok_or_else(|| ApiError::Internal("minting authority revision not found".to_string()))?;
    if required_entity_ref(&latest, "tenant")?.target_entity_id != tenant_id.internal().as_uuid() {
        return Err(ApiError::Forbidden);
    }

    let epoch = u64::try_from(i64_scalar(&latest, "epoch")?)
        .map_err(|_| ApiError::Internal("minting authority epoch is negative".to_string()))?;
    let permission_envelope = load_permission_envelope(&state.store, &latest).await?;
    let max_lifetime_seconds = load_max_lifetime_seconds(&state.store, &latest).await?;

    Ok(LoadedAuthority {
        permission_envelope,
        epoch,
        max_lifetime_seconds,
        is_retired: bool_scalar(&latest, "is_retired")?,
    })
}

async fn load_permission_envelope(
    store: &ApiStoreHandle,
    latest: &philharmonic_store::RevisionRow,
) -> Result<PermissionDocument, ApiError> {
    let value = load_json(store, required_content_hash(latest, "permission_envelope")?).await?;
    serde_json::from_value(value)
        .map_err(|error| ApiError::Internal(format!("invalid stored permission envelope: {error}")))
}

async fn load_max_lifetime_seconds(
    store: &ApiStoreHandle,
    latest: &philharmonic_store::RevisionRow,
) -> Result<u64, ApiError> {
    let constraints =
        load_json(store, required_content_hash(latest, "minting_constraints")?).await?;
    constraints
        .get("max_lifetime_seconds")
        .and_then(JsonValue::as_u64)
        .ok_or_else(|| {
            ApiError::Internal(
                "invalid stored minting constraints max_lifetime_seconds".to_string(),
            )
        })
}

fn validate_lifetime_seconds(
    requested: u64,
    authority_max_lifetime_seconds: u64,
) -> Result<(), ApiError> {
    if requested == 0 {
        return Err(ApiError::InvalidRequest(
            "lifetime_seconds must be greater than zero".to_string(),
        ));
    }
    if requested > authority_max_lifetime_seconds {
        return Err(ApiError::InvalidRequest(
            "lifetime_seconds exceeds minting authority maximum".to_string(),
        ));
    }
    if requested > SYSTEM_MAX_LIFETIME_SECONDS {
        return Err(ApiError::InvalidRequest(
            "lifetime_seconds exceeds system maximum".to_string(),
        ));
    }
    Ok(())
}

fn validate_permission_atoms(requested: &[String]) -> Result<(), ApiError> {
    for atom in requested {
        if !ALL_ATOMS.contains(&atom.as_str()) {
            return Err(ApiError::InvalidRequest(format!(
                "unknown permission atom: {atom}"
            )));
        }
    }
    Ok(())
}

fn clip_permissions(
    requested: &[String],
    envelope: &PermissionDocument,
    authority_id: EntityId<MintingAuthority>,
) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut clipped = Vec::new();
    let mut stripped = Vec::new();
    for permission in requested {
        if !seen.insert(permission.clone()) {
            continue;
        }
        if envelope.contains(permission) {
            clipped.push(permission.clone());
        } else {
            stripped.push(permission.clone());
        }
    }

    if !stripped.is_empty() {
        tracing::info!(
            authority_id = %authority_id.internal().as_uuid(),
            stripped_permissions = ?stripped,
            "stripped token permissions outside minting authority envelope"
        );
    }

    clipped
}

fn canonical_claims(value: &JsonValue) -> Result<CanonicalJson, ApiError> {
    let raw = serde_json::to_vec(value)
        .map_err(|error| ApiError::InvalidRequest(format!("invalid injected_claims: {error}")))?;
    if raw.len() > MAX_INJECTED_CLAIMS_BYTES {
        return Err(ApiError::InvalidRequest(
            "injected_claims exceeds maximum size".to_string(),
        ));
    }

    let canonical = CanonicalJson::from_value(value)
        .map_err(|error| ApiError::InvalidRequest(format!("invalid injected_claims: {error}")))?;
    if canonical.as_bytes().len() > MAX_INJECTED_CLAIMS_BYTES {
        return Err(ApiError::InvalidRequest(
            "injected_claims exceeds maximum size".to_string(),
        ));
    }
    Ok(canonical)
}

async fn validate_instance_scope(
    store: &ApiStoreHandle,
    tenant: EntityId<crate::Tenant>,
    instance_id: Option<Uuid>,
) -> Result<(), ApiError> {
    let Some(instance_id) = instance_id else {
        return Ok(());
    };

    let instance = resolve_public_id::<WorkflowInstance>(store, instance_id)
        .await
        .map_err(|error| match error {
            ApiError::NotFound(_) => {
                ApiError::InvalidRequest("instance_id not found in tenant".to_string())
            }
            other => other,
        })?;
    let latest = latest_revision::<WorkflowInstance>(store, instance)
        .await
        .map_err(|error| match error {
            ApiError::NotFound(_) => {
                ApiError::InvalidRequest("instance_id not found in tenant".to_string())
            }
            other => other,
        })?;
    ensure_revision_tenant(&latest, tenant, "workflow instance").map_err(|error| match error {
        ApiError::NotFound(_) => {
            ApiError::InvalidRequest("instance_id not found in tenant".to_string())
        }
        other => other,
    })
}

fn lifetime_millis(lifetime_seconds: u64) -> Result<i64, ApiError> {
    let lifetime_millis = lifetime_seconds
        .checked_mul(1000)
        .ok_or_else(|| ApiError::Internal("token lifetime overflow".to_string()))?;
    i64::try_from(lifetime_millis)
        .map_err(|_| ApiError::Internal("token lifetime overflow".to_string()))
}

fn unix_millis_rfc3339(timestamp: UnixMillis) -> Result<String, ApiError> {
    let millis = timestamp.as_i64();
    if millis < 0 {
        return Err(ApiError::Internal(
            "negative token expiry timestamp".to_string(),
        ));
    }

    let seconds = millis / MILLIS_PER_SECOND;
    let sub_millis = millis % MILLIS_PER_SECOND;
    let days = seconds / SECONDS_PER_DAY;
    let seconds_of_day = seconds % SECONDS_PER_DAY;
    let (year, month, day) = civil_from_unix_days(days)?;
    let hour = seconds_of_day / 3600;
    let minute = (seconds_of_day % 3600) / 60;
    let second = seconds_of_day % 60;

    if sub_millis == 0 {
        Ok(format!(
            "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z"
        ))
    } else {
        Ok(format!(
            "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{sub_millis:03}Z"
        ))
    }
}

fn civil_from_unix_days(days: i64) -> Result<(i64, u32, u32), ApiError> {
    let z = days
        .checked_add(UNIX_EPOCH_DAY_OFFSET)
        .ok_or_else(|| ApiError::Internal("token expiry date overflow".to_string()))?;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    let year = y + if month <= 2 { 1 } else { 0 };
    let month = u32::try_from(month)
        .map_err(|_| ApiError::Internal("token expiry month overflow".to_string()))?;
    let day = u32::try_from(day)
        .map_err(|_| ApiError::Internal("token expiry day overflow".to_string()))?;
    Ok((year, month, day))
}

#[derive(Deserialize)]
struct MintTokenRequest {
    subject: String,
    lifetime_seconds: u64,
    instance_id: Option<Uuid>,
    requested_permissions: Vec<String>,
    injected_claims: JsonValue,
}

#[derive(Serialize)]
struct MintTokenResponse {
    token: String,
    expires_at: String,
    subject: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    instance_id: Option<Uuid>,
}
