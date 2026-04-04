use crate::ddh::{
    DdhHiddenEvalCheckpoint, DdhHiddenEvalOutputBundles, DdhHiddenEvalProbe, DdhHiddenEvalProfile,
};
use crate::protocol::PreparedSession;
use crate::shared::{public_key_from_base_shares, FExpandInput, ProtoResult};

impl PreparedSession {
    pub fn materialize_hidden_outputs_for_debug(
        &self,
        output: &DdhHiddenEvalOutputBundles,
    ) -> ProtoResult<([u8; 32], [u8; 32], [u8; 32])> {
        let evaluator_session = self.evaluator_session();
        let garbler_session = self.garbler_session();
        let x_client_base = evaluator_session
            .ddh_evaluator
            .decode_client_bit_bundle_array(&output.x_client_base)?;
        let x_relayer_bundle = garbler_session
            .ddh_garbler
            .join_share_bundle(&output.x_relayer_base_left, &output.x_relayer_base_right)?;
        let x_relayer_base = garbler_session
            .ddh_garbler
            .decode_server_bit_bundle_array(&x_relayer_bundle)?;
        let public_key = public_key_from_base_shares(x_client_base, x_relayer_base)?;
        Ok((x_client_base, x_relayer_base, public_key))
    }

    pub fn profile_hidden_eval_for_clear_input(
        &self,
        input: &FExpandInput,
    ) -> ProtoResult<DdhHiddenEvalProfile> {
        crate::ddh::hidden_eval_executor::execute_prime_order_ddh_hidden_eval_program_for_clear_input_profiled_with_pool(
            self.hidden_eval_program(),
            self.ddh_backend(),
            self.hidden_eval_constants(),
            input,
        )
    }

    pub fn probe_hidden_eval_for_clear_input(
        &self,
        input: &FExpandInput,
        stop_after: DdhHiddenEvalCheckpoint,
    ) -> ProtoResult<DdhHiddenEvalProbe> {
        crate::ddh::hidden_eval_executor::probe_prime_order_ddh_hidden_eval_program_with_pool(
            self.hidden_eval_program(),
            self.ddh_backend(),
            self.hidden_eval_constants(),
            input,
            stop_after,
        )
    }
}
