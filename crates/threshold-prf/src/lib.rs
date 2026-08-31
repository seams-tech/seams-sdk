#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! Threshold PRF prototype for deriving project-scoped server Router A/B ECDSA derivation inputs.
//!
//! Production signing integrations should use share partials and combine them
//! through the configurable threshold API. Direct root evaluation exists as a
//! reference path for tests and vectors.

mod context;
mod ed25519_role_targets;
mod error;
mod prf;
mod refresh;
mod shamir;
mod suite;

pub use context::{PrfContext, PrfOutputEncoding, PrfPurpose};
pub use ed25519_role_targets::{
    complete_ed25519_deriver_a_target_v1, complete_ed25519_deriver_b_target_v1,
    prepare_ed25519_deriver_a_target_v1, prepare_ed25519_deriver_b_target_v1,
    Ed25519DeriverAThresholdPrfRootV1, Ed25519DeriverAToBTargetProofBundleV1,
    Ed25519DeriverBThresholdPrfRootV1, Ed25519DeriverBToATargetProofBundleV1,
    PreparedEd25519DeriverATargetV1, PreparedEd25519DeriverBTargetV1,
};
pub use error::{ThresholdPrfError, ThresholdPrfResult};
pub use prf::{
    combine_verified_partials, combine_verified_partials_bound_to_digest, evaluate_partial,
    evaluate_partial_with_dleq_proof, evaluate_partial_with_dleq_proof_bound_to_digest,
    verify_partial_dleq_proof, verify_partial_dleq_proof_bound_to_digest, PrfDleqProof,
    PrfOutput32, PrfPartial, PrfPartialProofBundle, PrfPartialWire, SigningRootShareCommitment,
};
pub use refresh::{
    apply_two_party_root_share_refresh, generate_two_party_root_share, prove_root_share_knowledge,
    verify_root_share_knowledge, verify_two_party_root_share_refresh, RootShareKnowledgeProof,
    RootShareRefreshCoefficient, RootShareRefreshCoefficientCommitment,
    RootShareRefreshContributionWire, TwoPartyDeriverRole, TwoPartyRootCommitment,
    TwoPartyRootShareCommitments, VerifiedRootShareRefreshContribution,
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
