//! Middleware chain for the public API.
//!
//! Sub-phase A wires correlation IDs, request logging, deployment-supplied
//! scope resolution, and placeholder authentication/authorization layers.

pub mod auth_placeholder;
pub mod authz_placeholder;
pub mod correlation_id;
pub mod request_logging;
pub mod scope;
