use crate::derivation::{
    MpcPrfSigningRootShareWireV1, MpcPrfThresholdSignerBatchInputV1, SignerInputPlaintextV1,
};

use crate::protocol::error::RouterAbProtocolResult;
use crate::protocol::payload::{build_mpc_prf_signer_partial_input_v1, RouterToSignerPayloadV1};

/// Builds Candidate A signer batch input with caller-supplied role-local root share.
pub fn build_mpc_prf_threshold_signer_batch_input_v1(
    payload: &RouterToSignerPayloadV1,
    plaintext: &SignerInputPlaintextV1,
    signing_root_share_wire: MpcPrfSigningRootShareWireV1,
) -> RouterAbProtocolResult<MpcPrfThresholdSignerBatchInputV1> {
    Ok(MpcPrfThresholdSignerBatchInputV1 {
        signer_input: build_mpc_prf_signer_partial_input_v1(payload, plaintext)?,
        signing_root_share_wire,
    })
}
