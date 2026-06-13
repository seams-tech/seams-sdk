use rand_core::{CryptoRng, RngCore};

use crate::derivation::{
    evaluate_mpc_prf_signer_output_batch_with_threshold_backend_v1,
    MpcPrfThresholdSignerBatchInputV1, MpcPrfThresholdSignerBatchOutputV1, Role,
    RouterAbDerivationError, RouterAbDerivationErrorCode, RouterAbDerivationResult,
};

/// Platform-agnostic Deriver B engine wrapper.
#[derive(Debug, Clone)]
pub struct DeriverBEngine<H> {
    host: H,
}

impl<H> DeriverBEngine<H> {
    /// Creates a Deriver B engine over a host implementation.
    pub fn new(host: H) -> Self {
        Self { host }
    }

    /// Returns the host implementation.
    pub fn host(&self) -> &H {
        &self.host
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
