use crate::ddh::DdhHiddenEvalRun;
use crate::protocol::{prepare_prime_order_succinct_hss, PreparedSession};
use crate::runtime::evaluation::{elapsed_ns_u64, monotonic_now_ns, EvaluateTiming};
use crate::server::ServerOtState;
use crate::shared::{FExpandInput, ProtoError, ProtoResult};
use crate::wire::{ClientOtOffer, EvaluationReport, OutputDelivery, WireMessage};

pub fn evaluate_prime_order_succinct_hss(input: &FExpandInput) -> ProtoResult<EvaluationReport> {
    prepare_prime_order_succinct_hss(&input.context)?.evaluate(input)
}

impl PreparedSession {
    pub fn prepare_client_ot_offer_message(&self) -> ProtoResult<WireMessage> {
        self.garbler_session().client_ot_offer_message()
    }

    pub fn prepare_garbler_ot_state(&self) -> ProtoResult<ServerOtState> {
        Ok(self.garbler_session().garbler_ot_state.clone())
    }

    pub fn prepare_client_ot_request_from_offer_message(
        &self,
        offer_message: &WireMessage,
        y_client: [u8; 32],
        tau_client: [u8; 32],
    ) -> ProtoResult<(WireMessage, crate::client::ClientOtState)> {
        self.evaluator_session()
            .prepare_client_ot_request_from_offer_message(offer_message, y_client, tau_client)
    }

    pub fn prepare_server_message(
        &self,
        garbler_ot_state: &ServerOtState,
        client_request_message: &WireMessage,
        y_relayer: [u8; 32],
        tau_relayer: [u8; 32],
    ) -> ProtoResult<WireMessage> {
        let garbler_session = self.garbler_session();
        self.validate_garbler_ot_state(garbler_ot_state, &garbler_session.client_ot_offer)?;
        garbler_session.prepare_server_message(client_request_message, y_relayer, tau_relayer)
    }

    pub fn evaluate_from_transport_messages(
        &self,
        client_request_message: &WireMessage,
        evaluator_ot_state: &crate::client::ClientOtState,
        server_message: &WireMessage,
    ) -> ProtoResult<EvaluationReport> {
        let (runtime, garbler_session, evaluator_session) = self.split_runtime();
        let evaluation_result_message = evaluator_session
            .evaluate_result_message_from_transport_messages(
                &runtime,
                client_request_message,
                evaluator_ot_state,
                server_message,
            )?;
        garbler_session
            .finalize_report_from_evaluation_result_message(&runtime, &evaluation_result_message)
    }

    pub fn deliver_output_from_transport_messages(
        &self,
        client_request_message: &WireMessage,
        evaluator_ot_state: &crate::client::ClientOtState,
        server_message: &WireMessage,
    ) -> ProtoResult<OutputDelivery> {
        Ok(self
            .evaluate_from_transport_messages(
                client_request_message,
                evaluator_ot_state,
                server_message,
            )?
            .output_delivery)
    }

    pub fn evaluate(&self, input: &FExpandInput) -> ProtoResult<EvaluationReport> {
        self.ensure_input_context(input)?;
        let runtime = self.shared_runtime();
        let garbler_session = self.garbler_session();
        let evaluator_session = self.evaluator_session();
        let (client_packet, evaluator_ot_state) = evaluator_session.prepare_client_ot_request(
            &garbler_session.client_ot_offer,
            input.y_client,
            input.tau_client,
        )?;
        let (trusted_server_eval, _timing) = garbler_session.prepare_trusted_server_eval_timed(
            &client_packet,
            input.y_relayer,
            input.tau_relayer,
        )?;
        let hidden_eval_constants = evaluator_session.hidden_eval_constant_pool()?;
        let (ddh_run, _timing) = evaluator_session
            .evaluate_hidden_run_from_trusted_server_eval_timed(
                &evaluator_session.ddh_evaluator,
                &runtime.hidden_eval_program,
                &hidden_eval_constants,
                &evaluator_ot_state,
                &trusted_server_eval,
            )?;
        Ok(evaluator_session
            .build_final_report_from_hidden_run(&runtime, &garbler_session, ddh_run)?
            .0)
    }

    pub fn evaluate_hidden_run(&self, input: &FExpandInput) -> ProtoResult<DdhHiddenEvalRun> {
        self.ensure_input_context(input)?;
        let runtime = self.shared_runtime();
        let garbler_session = self.garbler_session();
        let evaluator_session = self.evaluator_session();
        let (client_packet, evaluator_ot_state) = evaluator_session.prepare_client_ot_request(
            &garbler_session.client_ot_offer,
            input.y_client,
            input.tau_client,
        )?;
        let (trusted_server_eval, _timing) = garbler_session.prepare_trusted_server_eval_timed(
            &client_packet,
            input.y_relayer,
            input.tau_relayer,
        )?;
        let hidden_eval_constants = evaluator_session.hidden_eval_constant_pool()?;
        Ok(evaluator_session
            .evaluate_hidden_run_from_trusted_server_eval_timed(
                &evaluator_session.ddh_evaluator,
                &runtime.hidden_eval_program,
                &hidden_eval_constants,
                &evaluator_ot_state,
                &trusted_server_eval,
            )?
            .0)
    }

    pub fn evaluate_with_timing(
        &self,
        input: &FExpandInput,
    ) -> ProtoResult<(EvaluationReport, EvaluateTiming)> {
        self.ensure_input_context(input)?;
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
        let (trusted_server_eval, garbler_prepare_timing) = garbler_session
            .prepare_trusted_server_eval_timed(
                &client_packet,
                input.y_relayer,
                input.tau_relayer,
            )?;
        timing.add_assign(garbler_prepare_timing);
        let hidden_eval_constants = evaluator_session.hidden_eval_constant_pool()?;
        let (ddh_run, evaluation_timing) = evaluator_session
            .evaluate_hidden_run_from_trusted_server_eval_timed(
                &evaluator_session.ddh_evaluator,
                &runtime.hidden_eval_program,
                &hidden_eval_constants,
                &evaluator_ot_state,
                &trusted_server_eval,
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

    pub fn evaluate_hidden_run_with_timing(
        &self,
        input: &FExpandInput,
    ) -> ProtoResult<(DdhHiddenEvalRun, EvaluateTiming)> {
        self.ensure_input_context(input)?;
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
        let (trusted_server_eval, garbler_prepare_timing) = garbler_session
            .prepare_trusted_server_eval_timed(
                &client_packet,
                input.y_relayer,
                input.tau_relayer,
            )?;
        timing.add_assign(garbler_prepare_timing);
        let hidden_eval_constants = evaluator_session.hidden_eval_constant_pool()?;
        let (ddh_run, evaluation_timing) = evaluator_session
            .evaluate_hidden_run_from_trusted_server_eval_timed(
                &evaluator_session.ddh_evaluator,
                &runtime.hidden_eval_program,
                &hidden_eval_constants,
                &evaluator_ot_state,
                &trusted_server_eval,
            )?;
        timing.add_assign(evaluation_timing);
        Ok((ddh_run, timing))
    }

    fn ensure_input_context(&self, input: &FExpandInput) -> ProtoResult<()> {
        let input_context_binding = input.context.binding_digest()?;
        if input_context_binding != self.candidate().context_binding {
            return Err(ProtoError::InvalidInput(
                "input context does not match prepared prime-order succinct HSS session"
                    .to_string(),
            ));
        }
        Ok(())
    }

    fn validate_garbler_ot_state(
        &self,
        garbler_ot_state: &ServerOtState,
        client_ot_offer: &ClientOtOffer,
    ) -> ProtoResult<()> {
        let garbler_session = self.garbler_session();
        if garbler_ot_state.context_binding != self.candidate().context_binding {
            return Err(ProtoError::InvalidInput(
                "garbler OT state context binding does not match prepared session".to_string(),
            ));
        }
        garbler_session
            .ddh_garbler
            .validate_client_input_ot_bundle_offer(
                &client_ot_offer.y_client_offer,
                &garbler_ot_state.y_client_sender_state,
                &garbler_ot_state.y_client_remote,
            )?;
        garbler_session
            .ddh_garbler
            .validate_client_input_ot_bundle_offer(
                &client_ot_offer.tau_client_offer,
                &garbler_ot_state.tau_client_sender_state,
                &garbler_ot_state.tau_client_remote,
            )?;
        Ok(())
    }
}
