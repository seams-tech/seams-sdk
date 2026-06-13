#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! Threshold PRF prototype for deriving project-scoped server HSS inputs.
//!
//! Production signing integrations should use share partials and combine them
//! through the configurable threshold API. Direct root evaluation exists as a
//! reference path for tests and vectors.

mod context;
mod error;
mod prf;
mod shamir;
mod suite;

pub use context::{PrfContext, PrfOutputEncoding, PrfPurpose};
pub use error::{ThresholdPrfError, ThresholdPrfResult};
pub use prf::{
    combine_verified_partials, evaluate_partial, evaluate_partial_with_dleq_proof,
    verify_partial_dleq_proof, PrfDleqProof, PrfOutput32, PrfPartial, PrfPartialProofBundle,
    PrfPartialWire, SigningRootShareCommitment,
};
pub use shamir::{
    generate_signing_root, split_signing_root, SigningRootScalar, SigningRootShare,
    SigningRootShareWire, ThresholdPolicy, ThresholdShareId, ValidatedThresholdSet,
    MAX_SHARE_COUNT,
};
pub use suite::SuiteId;

/// Reference-only helpers for vectors, audits, and parity tests.
pub mod reference {
    pub use crate::prf::evaluate_direct_reference;
}

/// Recovery helpers that reconstruct root material from a validated threshold set.
pub mod recovery {
    pub use crate::shamir::reconstruct_signing_root;
}

/// Trusted local helpers for already-authenticated partials.
pub mod trusted {
    pub use crate::prf::combine_partials;
}
