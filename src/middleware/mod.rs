//! Middleware chain for the public API.
//!
//! Sub-phase B wires real authentication after deployment-supplied scope
//! resolution. Authorization remains a placeholder until sub-phase C.

pub mod auth;
pub mod authz_placeholder;
pub mod correlation_id;
pub mod request_logging;
pub mod scope;
