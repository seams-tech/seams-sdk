use crate::ddh::{
    DdhHiddenEvalCheckpoint, DdhHiddenEvalOutputBundles, DdhHiddenEvalProbe, DdhHiddenEvalProfile,
    DdhHiddenEvalRun,
};
use crate::protocol::PreparedSession;
use crate::runtime::evaluation::{elapsed_ns_u64, monotonic_now_ns, EvaluateTiming};
use crate::shared::{public_key_from_base_shares, FExpandInput, ProtoError, ProtoResult};
use crate::wire::EvaluationReport;

fn ensure_debug_input_context(session: &PreparedSession, input: &FExpandInput) -> ProtoResult<()> {
    let input_context_binding = input.context.binding_digest()?;
    if input_context_binding != session.candidate().context_binding {
        return Err(ProtoError::InvalidInput(
            "input context does not match prepared prime-order succinct HSS session".to_string(),
        ));
    }
    Ok(())
}

impl PreparedSession {
    pub fn evaluate_for_clear_input_debug(
        &self,
        input: &FExpandInput,
    ) -> ProtoResult<EvaluationReport> {
        ensure_debug_input_context(self, input)?;
        let runtime = self.shared_runtime();
        let garbler_session = self.garbler_session();
        let evaluator_session = self.evaluator_session();
        let (client_packet, evaluator_ot_state) = evaluator_session.prepare_client_ot_request(
            &garbler_session.client_ot_offer,
            input.y_client,
            input.tau_client,
        )?;
        let (ddh_run, _timing) = garbler_session.evaluate_hidden_run_same_process_timed(
            &evaluator_session,
            &runtime.hidden_eval_program,
            self.hidden_eval_constants(),
            &evaluator_ot_state,
            &client_packet,
            input.y_relayer,
            input.tau_relayer,
        )?;
        Ok(evaluator_session
            .build_final_report_from_hidden_run(&runtime, &garbler_session, ddh_run)?
            .0)
    }

    pub fn evaluate_hidden_run_for_clear_input_debug(
        &self,
        input: &FExpandInput,
    ) -> ProtoResult<DdhHiddenEvalRun> {
        ensure_debug_input_context(self, input)?;
        let runtime = self.shared_runtime();
        let garbler_session = self.garbler_session();
        let evaluator_session = self.evaluator_session();
        let (client_packet, evaluator_ot_state) = evaluator_session.prepare_client_ot_request(
            &garbler_session.client_ot_offer,
            input.y_client,
            input.tau_client,
        )?;
        Ok(garbler_session
            .evaluate_hidden_run_same_process_timed(
                &evaluator_session,
                &runtime.hidden_eval_program,
                self.hidden_eval_constants(),
                &evaluator_ot_state,
                &client_packet,
                input.y_relayer,
                input.tau_relayer,
            )?
            .0)
    }

    pub fn evaluate_with_timing_for_clear_input_debug(
        &self,
        input: &FExpandInput,
    ) -> ProtoResult<(EvaluationReport, EvaluateTiming)> {
        ensure_debug_input_context(self, input)?;
        let runtime = self.shared_runtime();
        let garbler_session = self.garbler_session();
        let evaluator_session = self.evaluator_session();
        let mut timing = EvaluateTiming::default();
        let ot_open_join_started = monotonic_now_ns();
        let (client_packet, evaluator_ot_state) = evaluator_session.prepare_client_ot_request(
            &garbler_session.client_ot_offer,
            input.y_client,
            input.tau_client,
        )?;
        timing.ot_open_join_duration_ns = elapsed_ns_u64(ot_open_join_started);
        let (ddh_run, evaluation_timing) = garbler_session.evaluate_hidden_run_same_process_timed(
            &evaluator_session,
            &runtime.hidden_eval_program,
            self.hidden_eval_constants(),
            &evaluator_ot_state,
            &client_packet,
            input.y_relayer,
            input.tau_relayer,
        )?;
        timing.add_assign(evaluation_timing);
        let (report, result_assembly_duration_ns, output_sealing_finalization_duration_ns) =
            evaluator_session.build_final_report_from_hidden_run(
                &runtime,
                &garbler_session,
                ddh_run,
            )?;
        timing.result_assembly_duration_ns = timing
            .result_assembly_duration_ns
            .saturating_add(result_assembly_duration_ns);
        timing.output_sealing_finalization_duration_ns = timing
            .output_sealing_finalization_duration_ns
            .saturating_add(output_sealing_finalization_duration_ns);
        Ok((report, timing))
    }

    pub fn evaluate_hidden_run_with_timing_for_clear_input_debug(
        &self,
        input: &FExpandInput,
    ) -> ProtoResult<(DdhHiddenEvalRun, EvaluateTiming)> {
        ensure_debug_input_context(self, input)?;
        let runtime = self.shared_runtime();
        let garbler_session = self.garbler_session();
        let evaluator_session = self.evaluator_session();
        let mut timing = EvaluateTiming::default();
        let ot_open_join_started = monotonic_now_ns();
        let (client_packet, evaluator_ot_state) = evaluator_session.prepare_client_ot_request(
            &garbler_session.client_ot_offer,
            input.y_client,
            input.tau_client,
        )?;
        timing.ot_open_join_duration_ns = elapsed_ns_u64(ot_open_join_started);
        let (ddh_run, evaluation_timing) = garbler_session.evaluate_hidden_run_same_process_timed(
            &evaluator_session,
            &runtime.hidden_eval_program,
            self.hidden_eval_constants(),
            &evaluator_ot_state,
            &client_packet,
            input.y_relayer,
            input.tau_relayer,
        )?;
        timing.add_assign(evaluation_timing);
        Ok((ddh_run, timing))
    }

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
