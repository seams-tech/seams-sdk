#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! Threshold PRF prototype for deriving project-scoped server HSS inputs.
//!
//! Production signing should use share partials and combine them. For
//! one-runtime Option A, use `derive_output_from_signing_root_shares`. Direct
//! root evaluation exists as a reference path for tests and vectors.

mod context;
mod error;
mod prf;
mod shamir;
mod suite;

pub use context::{PrfContext, PrfPurpose};
pub use error::{ThresholdPrfError, ThresholdPrfResult};
pub use prf::{
    combine_partials, combine_verified_partials, derive_output_from_signing_root_share_wires,
    derive_output_from_signing_root_shares, evaluate_direct_reference, evaluate_partial,
    evaluate_partial_with_dleq_proof, verify_partial_dleq_proof, PrfDleqProofV1, PrfOutput32,
    PrfPartial, PrfPartialProofBundleV1, PrfPartialWireV1, SigningRootShareCommitmentV1,
};
pub use shamir::{
    generate_signing_root, reconstruct_signing_root_2_of_3, refresh_signing_root_shares_2_of_3,
    split_signing_root_2_of_3, SigningRootScalar, SigningRootShare, SigningRootShareId,
    SigningRootShareWireV1,
};
pub use suite::SuiteId;
