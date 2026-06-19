use rand_core::{CryptoRng, RngCore};

use crate::derivation::{
    evaluate_mpc_prf_signer_output_batch_with_threshold_backend_v1,
    MpcPrfThresholdSignerBatchInputV1, MpcPrfThresholdSignerBatchOutputV1, Role,
    RouterAbDerivationError, RouterAbDerivationErrorCode, RouterAbDerivationResult,
};

/// Platform-agnostic Deriver A role guard.
#[derive(Debug, Clone, Copy, Default)]
pub struct DeriverAEngine;

impl DeriverAEngine {
    /// Creates a Deriver A role guard.
    pub fn new() -> Self {
        Self
    }

    /// Evaluates Deriver A's selected threshold-PRF output batch.
    pub fn evaluate_mpc_prf_output_batch<R>(
        &self,
        input: MpcPrfThresholdSignerBatchInputV1,
        proof_rng: &mut R,
    ) -> RouterAbDerivationResult<MpcPrfThresholdSignerBatchOutputV1>
    where
        R: RngCore + CryptoRng,
    {
        if input.signer_input.signer_role != Role::SignerA {
            return Err(RouterAbDerivationError::new(
                RouterAbDerivationErrorCode::SignerIdentityMismatch,
                "Deriver A engine requires Deriver A batch input",
            ));
        }
        evaluate_mpc_prf_signer_output_batch_with_threshold_backend_v1(input, proof_rng)
    }
}
