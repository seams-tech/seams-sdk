#![forbid(unsafe_code)]
//! Core derivation and service protocol types for Router/A/B signing.
//!
//! Platform adapters live outside this crate. Cloudflare Workers, local SQLite,
//! and future server runtimes should depend on these pure Rust APIs.

pub mod derivation;
pub mod protocol;

pub use derivation::*;
pub use protocol::*;
