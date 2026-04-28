//! Middleware chain for the public API.
//!
//! Sub-phase C wires real authentication and authorization after
//! deployment-supplied scope resolution.

pub mod auth;
pub mod authz;
pub mod correlation_id;
pub mod request_logging;
pub mod scope;
