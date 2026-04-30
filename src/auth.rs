//! Authentication context types.
//!
//! Sub-phase B populates this enum from long-lived `pht_` token lookup and
//! ephemeral COSE_Sign1 verification.

use philharmonic_policy::{EphemeralApiTokenClaims, MintingAuthority, Principal, Tenant};
use philharmonic_types::{EntityId, Uuid};

/// Authenticated caller context.
#[derive(Debug, Clone)]
pub enum AuthContext {
    /// A persistent principal authenticated with a long-lived API token.
    Principal {
        /// Authenticated principal ID.
        principal_id: EntityId<Principal>,
        /// Tenant the principal belongs to.
        tenant_id: EntityId<Tenant>,
    },
    /// A tenant end-user authenticated with an ephemeral API token.
    Ephemeral {
        /// Subject string supplied by the minting authority.
        subject: String,
        /// Tenant carried by the ephemeral token.
        tenant_id: EntityId<Tenant>,
        /// Minting authority that issued the token.
        authority_id: EntityId<MintingAuthority>,
        /// Permission atoms embedded in the token.
        permissions: Vec<String>,
        /// Claims injected into workflow execution context.
        injected_claims: serde_json::Value,
        /// Optional workflow-instance scope.
        ///
        /// Raw UUID rather than `EntityId<WorkflowInstance>` because
        /// `WorkflowInstance` is not in the API crate's dependency
        /// surface. Functionally equivalent for scope enforcement.
        instance_scope: Option<Uuid>,
    },
}

impl AuthContext {
    /// Return the tenant associated with this authenticated caller.
    pub fn tenant_id(&self) -> EntityId<Tenant> {
        match self {
            Self::Principal { tenant_id, .. } | Self::Ephemeral { tenant_id, .. } => *tenant_id,
        }
    }

    /// Whether this context came from an ephemeral API token.
    pub fn is_ephemeral(&self) -> bool {
        matches!(self, Self::Ephemeral { .. })
    }

    /// Whether this context came from a long-lived API token.
    pub fn is_principal(&self) -> bool {
        matches!(self, Self::Principal { .. })
    }

    /// Build an ephemeral auth context from verified token claims and the
    /// substrate identities that were checked by the middleware.
    pub fn from_ephemeral_claims(
        claims: EphemeralApiTokenClaims,
        tenant_id: EntityId<Tenant>,
        authority_id: EntityId<MintingAuthority>,
    ) -> Result<Self, serde_json::Error> {
        let injected_claims = serde_json::from_slice(claims.claims.as_bytes())?;
        Ok(Self::Ephemeral {
            subject: claims.sub,
            tenant_id,
            authority_id,
            permissions: claims.permissions,
            injected_claims,
            instance_scope: claims.instance,
        })
    }
}
