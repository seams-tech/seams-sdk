//! Browser boundary for wallet custody ceremonies.
//!
//! A custody ceremony derives the owner signing roots *and* establishes or
//! verifies the key manifest: initial registration and recovery
//! re-establishment. Both need the Ed25519 Yao and Router A/B ECDSA protocol
//! crates, which `near_signer` does not link, and neither can hand a
//! seed-derived root to its protocol without crossing JavaScript unless one
//! module reaches both. That is what this module is.
//!
//! What crosses this boundary: public protocol messages, ciphertext, and public
//! records. Never a seed, a root, a KEK, a factor secret, or a manifest
//! verification token. The ceremony's state lives in wasm memory between
//! rounds — including the ECDSA role-local pending blob, which carries the
//! client's scalar share in the clear and therefore must not be handed to
//! JavaScript the way the standalone bootstrap module does it.
//!
//! Adding a factor to an existing wallet and unlocking are not ceremonies:
//! neither derives roots, so both stay in `near_signer`.

pub mod ceremony;
pub mod wasm;

/// The ceremony driven through the real Router A/B circuit. Its dependencies
/// are dev-only, so it is compiled only for tests.
#[cfg(test)]
mod circuit_tests;
