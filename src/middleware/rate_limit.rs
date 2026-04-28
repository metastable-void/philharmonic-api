//! In-memory API rate limiting middleware.

use std::{collections::HashMap, sync::Arc, time::Instant};

use axum::{Extension, extract::Request, middleware::Next, response::Response};
use philharmonic_types::Uuid;
use tokio::sync::Mutex;

use crate::{ApiError, AuthContext, RequestContext, RequestScope, context::CorrelationContext};

const SCALE: u128 = 1_000_000;
const NANOS_PER_SECOND: u128 = 1_000_000_000;

/// Per-family rate-limit configuration for the API middleware.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RateLimitConfig {
    /// Tenant workflow endpoint bucket.
    pub workflow: RateLimitBucketConfig,
    /// Tenant credential endpoint bucket.
    pub credential: RateLimitBucketConfig,
    /// Token-minting endpoint bucket.
    pub minting: RateLimitBucketConfig,
    /// Audit-log endpoint bucket.
    pub audit: RateLimitBucketConfig,
    /// Tenant-administration and operator endpoint bucket.
    pub admin: RateLimitBucketConfig,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            workflow: RateLimitBucketConfig::new(200, 100),
            credential: RateLimitBucketConfig::new(60, 30),
            minting: RateLimitBucketConfig::new(20, 10),
            audit: RateLimitBucketConfig::new(40, 20),
            admin: RateLimitBucketConfig::new(40, 20),
        }
    }
}

/// Token-bucket settings for one endpoint family.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RateLimitBucketConfig {
    /// Maximum burst size.
    pub capacity: u32,
    /// Refill rate in whole tokens per second.
    pub refill_per_second: u32,
}

impl RateLimitBucketConfig {
    /// Construct token-bucket settings.
    pub const fn new(capacity: u32, refill_per_second: u32) -> Self {
        Self {
            capacity,
            refill_per_second,
        }
    }
}

#[derive(Clone)]
pub(crate) struct RateLimitState {
    config: RateLimitConfig,
    buckets: Arc<Mutex<HashMap<RateLimitKey, Bucket>>>,
}

impl RateLimitState {
    pub(crate) fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            buckets: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    async fn check(&self, key: RateLimitKey, family: EndpointFamily) -> Option<u64> {
        let config = self.config.for_family(family);
        let now = Instant::now();
        let mut buckets = self.buckets.lock().await;
        let bucket = buckets
            .entry(key)
            .or_insert_with(|| Bucket::new(config, now));
        bucket.take_one(config, now)
    }
}

impl RateLimitConfig {
    fn for_family(self, family: EndpointFamily) -> RateLimitBucketConfig {
        match family {
            EndpointFamily::Workflow => self.workflow,
            EndpointFamily::Credential => self.credential,
            EndpointFamily::Minting => self.minting,
            EndpointFamily::Audit => self.audit,
            EndpointFamily::Admin => self.admin,
        }
    }
}

/// Enforce per-scope token-bucket rate limits.
pub async fn rate_limit(
    Extension(state): Extension<RateLimitState>,
    request: Request,
    next: Next,
) -> Response {
    let Some(family) = endpoint_family(request.uri().path()) else {
        return next.run(request).await;
    };
    let correlation_id = correlation_id(&request);
    let Some(context) = request.extensions().get::<RequestContext>().cloned() else {
        tracing::warn!(%correlation_id, "rate-limit middleware ran without request context");
        return ApiError::Internal("missing request context".to_string())
            .into_response_with_correlation_id(correlation_id);
    };

    let key = RateLimitKey::from_context(&context, family);
    if let Some(retry_after_seconds) = state.check(key, family).await {
        return ApiError::RateLimited {
            retry_after_seconds,
        }
        .into_response_with_correlation_id(correlation_id);
    }

    next.run(request).await
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EndpointFamily {
    Workflow,
    Credential,
    Minting,
    Audit,
    Admin,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
struct RateLimitKey {
    scope: ScopeKey,
    family: EndpointFamilyKey,
    minting_authority: Option<Uuid>,
}

impl RateLimitKey {
    fn from_context(context: &RequestContext, family: EndpointFamily) -> Self {
        Self {
            scope: match context.scope {
                RequestScope::Tenant(tenant) => ScopeKey::Tenant(tenant.internal().as_uuid()),
                RequestScope::Operator => ScopeKey::Operator,
            },
            family: EndpointFamilyKey::from(family),
            minting_authority: minting_authority_key(context, family),
        }
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
enum ScopeKey {
    Tenant(Uuid),
    Operator,
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
enum EndpointFamilyKey {
    Workflow,
    Credential,
    Minting,
    Audit,
    Admin,
}

impl From<EndpointFamily> for EndpointFamilyKey {
    fn from(value: EndpointFamily) -> Self {
        match value {
            EndpointFamily::Workflow => Self::Workflow,
            EndpointFamily::Credential => Self::Credential,
            EndpointFamily::Minting => Self::Minting,
            EndpointFamily::Audit => Self::Audit,
            EndpointFamily::Admin => Self::Admin,
        }
    }
}

struct Bucket {
    tokens: u128,
    updated_at: Instant,
}

impl Bucket {
    fn new(config: RateLimitBucketConfig, now: Instant) -> Self {
        Self {
            tokens: u128::from(config.capacity).saturating_mul(SCALE),
            updated_at: now,
        }
    }

    fn take_one(&mut self, config: RateLimitBucketConfig, now: Instant) -> Option<u64> {
        self.refill(config, now);
        if self.tokens >= SCALE {
            self.tokens = self.tokens.saturating_sub(SCALE);
            return None;
        }

        Some(retry_after_seconds(
            config,
            SCALE.saturating_sub(self.tokens),
        ))
    }

    fn refill(&mut self, config: RateLimitBucketConfig, now: Instant) {
        let elapsed = now.duration_since(self.updated_at).as_nanos();
        let added = elapsed
            .saturating_mul(u128::from(config.refill_per_second))
            .saturating_mul(SCALE)
            / NANOS_PER_SECOND;
        let capacity = u128::from(config.capacity).saturating_mul(SCALE);
        self.tokens = self.tokens.saturating_add(added).min(capacity);
        self.updated_at = now;
    }
}

fn retry_after_seconds(config: RateLimitBucketConfig, token_deficit: u128) -> u64 {
    let denominator = u128::from(config.refill_per_second).saturating_mul(SCALE);
    if denominator == 0 {
        return 1;
    }
    let nanos = token_deficit
        .saturating_mul(NANOS_PER_SECOND)
        .saturating_add(denominator.saturating_sub(1))
        / denominator;
    let seconds = nanos.saturating_add(NANOS_PER_SECOND.saturating_sub(1)) / NANOS_PER_SECOND;
    match u64::try_from(seconds) {
        Ok(value) => value.max(1),
        Err(_) => u64::MAX,
    }
}

fn endpoint_family(path: &str) -> Option<EndpointFamily> {
    if path.starts_with("/v1/_meta/") {
        None
    } else if path.starts_with("/v1/workflows/") || path == "/v1/workflows" {
        Some(EndpointFamily::Workflow)
    } else if path.starts_with("/v1/endpoints/") || path == "/v1/endpoints" {
        Some(EndpointFamily::Credential)
    } else if path == "/v1/tokens/mint" {
        Some(EndpointFamily::Minting)
    } else if path.starts_with("/v1/audit/") || path == "/v1/audit" {
        Some(EndpointFamily::Audit)
    } else {
        Some(EndpointFamily::Admin)
    }
}

fn minting_authority_key(context: &RequestContext, family: EndpointFamily) -> Option<Uuid> {
    if family != EndpointFamily::Minting {
        return None;
    }
    match context.auth.as_ref() {
        Some(AuthContext::Principal { principal_id, .. }) => {
            Some(principal_id.internal().as_uuid())
        }
        Some(AuthContext::Ephemeral { authority_id, .. }) => {
            Some(authority_id.internal().as_uuid())
        }
        None => None,
    }
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
