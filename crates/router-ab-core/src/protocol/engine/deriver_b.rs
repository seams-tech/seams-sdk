use rand_core::{CryptoRng, RngCore};

use crate::derivation::{
    evaluate_mpc_prf_signer_output_batch_with_threshold_backend_v1,
    MpcPrfThresholdSignerBatchInputV1, MpcPrfThresholdSignerBatchOutputV1, Role,
    RouterAbDerivationError, RouterAbDerivationErrorCode, RouterAbDerivationResult,
};

/// Platform-agnostic Deriver B role guard.
#[derive(Debug, Clone, Copy, Default)]
pub struct DeriverBEngine;

impl DeriverBEngine {
    /// Creates a Deriver B role guard.
    pub fn new() -> Self {
        Self
    }

    /// Evaluates Deriver B's selected threshold-PRF output batch.
    pub fn evaluate_mpc_prf_output_batch<R>(
        &self,
        input: MpcPrfThresholdSignerBatchInputV1,
        proof_rng: &mut R,
    ) -> RouterAbDerivationResult<MpcPrfThresholdSignerBatchOutputV1>
    where
        R: RngCore + CryptoRng,
    {
        if input.signer_input.signer_role != Role::SignerB {
            return Err(RouterAbDerivationError::new(
                RouterAbDerivationErrorCode::SignerIdentityMismatch,
                "Deriver B engine requires Deriver B batch input",
            ));
        }
        evaluate_mpc_prf_signer_output_batch_with_threshold_backend_v1(input, proof_rng)
    }
}
