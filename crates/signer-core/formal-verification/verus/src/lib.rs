//! Verus verification crate for `signer-core`.
//!
//! This crate mirrors the narrow shared-helper slices we want to prove without
//! pulling verification annotations into production code.

pub mod near_threshold_ed25519;
pub mod secp256k1;
