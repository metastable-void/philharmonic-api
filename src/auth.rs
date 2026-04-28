//! Authentication context types.
//!
//! Sub-phase A defines the enum used by downstream handlers. The
//! authentication middleware is a documented no-op until sub-phase B adds
//! long-lived `pht_` token lookup and ephemeral COSE_Sign1 verification.

use philharmonic_policy::{MintingAuthority, Principal, Tenant};
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
        /// TODO(sub-phase D): replace this raw UUID with
        /// `EntityId<WorkflowInstance>` once `WorkflowInstance` is exposed
        /// through the API crate's dependency surface.
        instance_scope: Option<Uuid>,
    },
}
