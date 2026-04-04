use crate::client::{
    ot::build_client_ot_request, ClientDriverState, ClientOtState, ClientOutputOpener,
    ClientSession, ClientSessionState, SeedOutputOpener,
};
use crate::ddh::hidden_eval_executor::DdhHiddenEvalConstantPool;
use crate::ddh::{
    DdhHiddenEvalRun, DdhHssEvaluator, DdhHssInputShareBundle, DdhHssTransportPurpose,
    HiddenEvalProgram,
};
use crate::runtime::{
    evaluation::{elapsed_ns_u64, monotonic_now_ns, TrustedServerEval},
    EvaluateTiming, SharedRuntime,
};
use crate::shared::{ProtoError, ProtoResult};
use crate::wire::{
    deserialize_server_inputs_payload_opened, ClientOtOffer, ClientOutputPacket, ClientPacket,
    EvaluationReport, EvaluationResult, EvaluatorWitness, OpenedServerInputs, OutputDelivery,
    RunBindings, SeedOutputPacket, ServerPacket, TransportKind, WireMessage,
};

impl ClientSessionState {
    pub fn materialize(&self) -> ClientSession {
        ClientSession {
            context_binding: self.context_binding,
            ddh_evaluator: self.ddh_evaluator.clone(),
            client_ot_offer: self.client_ot_offer.clone(),
        }
    }
}

impl ClientDriverState {
    pub fn materialize(&self) -> ProtoResult<(SharedRuntime, ClientSession)> {
        Ok((
            self.runtime.materialize()?,
            self.evaluator_session.materialize(),
        ))
    }
}

impl ClientSession {
    pub fn client_output_opener(&self) -> ClientOutputOpener {
        ClientOutputOpener {
            evaluator: self.ddh_evaluator.clone(),
            context_binding: self.context_binding,
        }
    }

    pub fn seed_output_opener(&self) -> SeedOutputOpener {
        SeedOutputOpener {
            evaluator: self.ddh_evaluator.clone(),
            context_binding: self.context_binding,
        }
    }

    pub fn prepare_client_ot_request_from_offer_message(
        &self,
        offer_message: &WireMessage,
        y_client: [u8; 32],
        tau_client: [u8; 32],
    ) -> ProtoResult<(WireMessage, ClientOtState)> {
        let offer: ClientOtOffer = crate::wire::decode_transport_message(
            self.context_binding,
            TransportKind::ClientOtOffer,
            offer_message,
        )?;
        let (client_packet, evaluator_state) =
            self.prepare_client_ot_request(&offer, y_client, tau_client)?;
        Ok((
            crate::wire::encode_transport_message(
                self.context_binding,
                TransportKind::ClientOtRequest,
                &client_packet,
            )?,
            evaluator_state,
        ))
    }

    pub fn prepare_client_ot_request(
        &self,
        offer: &ClientOtOffer,
        y_client: [u8; 32],
        tau_client: [u8; 32],
    ) -> ProtoResult<(crate::wire::ClientPacket, ClientOtState)> {
        build_client_ot_request(
            &self.ddh_evaluator,
            self.context_binding,
            offer,
            y_client,
            tau_client,
        )
    }

    pub fn validate_evaluator_ot_state(
        &self,
        evaluator_ot_state: &ClientOtState,
    ) -> ProtoResult<()> {
        crate::client::ot::validate_evaluator_ot_state(self.context_binding, evaluator_ot_state)
    }

    pub(crate) fn open_server_inputs_packet(
        &self,
        packet: &crate::wire::ServerInputsPacket,
    ) -> ProtoResult<OpenedServerInputs> {
        if packet.context_binding != self.context_binding {
            return Err(ProtoError::InvalidInput(
                "server input packet context binding does not match evaluator session".to_string(),
            ));
        }
        let aad = crate::protocol::transcript::server_input_packet_aad(
            packet.context_binding,
            packet.server_input_commitment,
        );
        let plaintext = self.ddh_evaluator.open_message(
            DdhHssTransportPurpose::ServerInput,
            &aad,
            packet.nonce,
            &packet.ciphertext,
        )?;
        deserialize_server_inputs_payload_opened(&plaintext)
    }

    pub fn reconstruct_client_input_bundles(
        &self,
        client_packet: &ClientPacket,
        evaluator_ot_state: &ClientOtState,
        server_packet: &ServerPacket,
    ) -> ProtoResult<(DdhHssInputShareBundle, DdhHssInputShareBundle)> {
        crate::protocol::invariants::validate_client_packet_context(
            self.context_binding,
            client_packet,
        )?;
        self.validate_evaluator_ot_state(evaluator_ot_state)?;
        self.validate_server_packet(server_packet)?;
        if client_packet.y_client_request.commitment
            != server_packet.ot_transcript.y_client_request_commitment
            || client_packet.tau_client_request.commitment
                != server_packet.ot_transcript.tau_client_request_commitment
        {
            return Err(ProtoError::InvalidInput(
                "server delivery packet OT request commitments do not match client packet"
                    .to_string(),
            ));
        }
        let y_client_bundle = self.ddh_evaluator.reconstruct_client_ot_bundle(
            self.context_binding,
            &server_packet.y_client_response,
            &evaluator_ot_state.y_client_local_state,
            &server_packet.y_client_remote_release,
        )?;
        let tau_client_bundle = self.ddh_evaluator.reconstruct_client_ot_bundle(
            self.context_binding,
            &server_packet.tau_client_response,
            &evaluator_ot_state.tau_client_local_state,
            &server_packet.tau_client_remote_release,
        )?;
        Ok((y_client_bundle, tau_client_bundle))
    }

    pub fn evaluate_hidden_run_from_packets(
        &self,
        ddh_evaluator: &DdhHssEvaluator,
        hidden_eval_program: &HiddenEvalProgram,
        hidden_eval_constants: &DdhHiddenEvalConstantPool,
        client_packet: &ClientPacket,
        evaluator_ot_state: &ClientOtState,
        server_packet: &ServerPacket,
    ) -> ProtoResult<DdhHiddenEvalRun> {
        let (y_client_bundle, tau_client_bundle) = self.reconstruct_client_input_bundles(
            client_packet,
            evaluator_ot_state,
            server_packet,
        )?;
        let expected_client_input_commitment = self.ddh_evaluator.combined_input_commitment(
            crate::ddh::HiddenEvalInputOwner::Client,
            &[&y_client_bundle, &tau_client_bundle],
        );
        let opened_server_inputs = self.open_server_inputs_packet(&server_packet.server_inputs)?;
        let run = crate::ddh::hidden_eval_executor::execute_prime_order_ddh_hidden_eval_program_with_transport_server_inputs_with_pool(
            hidden_eval_program,
            ddh_evaluator,
            hidden_eval_constants,
            &y_client_bundle,
            &opened_server_inputs.y_relayer_left,
            &opened_server_inputs.y_relayer_right,
            &tau_client_bundle,
            &opened_server_inputs.tau_relayer_left,
            &opened_server_inputs.tau_relayer_right,
        )?;
        if run.client_input_commitment != expected_client_input_commitment {
            return Err(ProtoError::InvalidInput(
                "client delivery packet commitment does not match evaluated run".to_string(),
            ));
        }
        if run.server_input_commitment != server_packet.server_inputs.server_input_commitment {
            return Err(ProtoError::InvalidInput(
                "server delivery packet commitment does not match evaluated run".to_string(),
            ));
        }
        Ok(run)
    }

    pub(crate) fn reconstruct_client_input_bundles_from_trusted_server_eval_timed(
        &self,
        evaluator_ot_state: &ClientOtState,
        trusted_server_eval: &TrustedServerEval,
    ) -> ProtoResult<(
        DdhHssInputShareBundle,
        DdhHssInputShareBundle,
        EvaluateTiming,
    )> {
        let (y_client_bundle, y_timing) = self
            .ddh_evaluator
            .reconstruct_client_ot_bundle_timed_trusted(
                self.context_binding,
                &trusted_server_eval.y_client_response,
                &evaluator_ot_state.y_client_local_state,
                &trusted_server_eval.y_client_remote_release,
            )?;
        let (tau_client_bundle, tau_timing) = self
            .ddh_evaluator
            .reconstruct_client_ot_bundle_timed_trusted(
                self.context_binding,
                &trusted_server_eval.tau_client_response,
                &evaluator_ot_state.tau_client_local_state,
                &trusted_server_eval.tau_client_remote_release,
            )?;
        let mut timing = EvaluateTiming::default();
        timing.add_ot_reconstruct_timing(y_timing);
        timing.add_ot_reconstruct_timing(tau_timing);
        Ok((y_client_bundle, tau_client_bundle, timing))
    }

    pub(crate) fn evaluate_hidden_run_from_trusted_server_eval_timed(
        &self,
        ddh_evaluator: &DdhHssEvaluator,
        hidden_eval_program: &HiddenEvalProgram,
        hidden_eval_constants: &DdhHiddenEvalConstantPool,
        evaluator_ot_state: &ClientOtState,
        trusted_server_eval: &TrustedServerEval,
    ) -> ProtoResult<(DdhHiddenEvalRun, EvaluateTiming)> {
        let mut timing = EvaluateTiming::default();
        let ot_open_join_started = monotonic_now_ns();
        let (y_client_bundle, tau_client_bundle, ot_timing) = self
            .reconstruct_client_input_bundles_from_trusted_server_eval_timed(
                evaluator_ot_state,
                trusted_server_eval,
            )?;
        timing.ot_open_join_duration_ns = elapsed_ns_u64(ot_open_join_started);
        timing.add_assign(ot_timing);
        let expected_client_input_commitment = self.ddh_evaluator.combined_input_commitment(
            crate::ddh::HiddenEvalInputOwner::Client,
            &[&y_client_bundle, &tau_client_bundle],
        );
        let run = crate::ddh::hidden_eval_executor::execute_prime_order_ddh_hidden_eval_program_with_split_server_inputs_with_pool(
            hidden_eval_program,
            ddh_evaluator,
            hidden_eval_constants,
            &y_client_bundle,
            &trusted_server_eval.trusted_server_inputs.y_relayer_bits,
            &tau_client_bundle,
            &trusted_server_eval.trusted_server_inputs.tau_relayer_bits,
        )?;
        if run.client_input_commitment != expected_client_input_commitment {
            return Err(ProtoError::InvalidInput(
                "client delivery packet commitment does not match evaluated run".to_string(),
            ));
        }
        if run.server_input_commitment != trusted_server_eval.server_input_commitment {
            return Err(ProtoError::InvalidInput(
                "server delivery packet commitment does not match evaluated run".to_string(),
            ));
        }
        Ok((run, timing))
    }

    pub fn evaluate_result_message_from_transport_messages(
        &self,
        runtime: &SharedRuntime,
        client_request_message: &WireMessage,
        evaluator_ot_state: &ClientOtState,
        server_message: &WireMessage,
    ) -> ProtoResult<WireMessage> {
        let client_packet: ClientPacket = crate::wire::decode_transport_message(
            self.context_binding,
            TransportKind::ClientOtRequest,
            client_request_message,
        )?;
        let server_packet: ServerPacket = crate::wire::decode_transport_message(
            self.context_binding,
            TransportKind::ServerPacket,
            server_message,
        )?;
        let ddh_run = self.evaluate_hidden_run_from_packets(
            &runtime.ddh_evaluator,
            &runtime.hidden_eval_program,
            &runtime.hidden_eval_constants,
            &client_packet,
            evaluator_ot_state,
            &server_packet,
        )?;
        let evaluation_result = self
            .build_evaluation_result_from_hidden_run(runtime, ddh_run)?
            .0;
        crate::wire::encode_transport_message(
            self.context_binding,
            TransportKind::EvaluationResult,
            &evaluation_result,
        )
    }

    pub fn seal_client_output_packet_message(
        &self,
        run_binding: [u8; 32],
        evaluation_digest: [u8; 32],
        bundle: &DdhHssInputShareBundle,
    ) -> ProtoResult<WireMessage> {
        let aad = crate::protocol::transcript::output_packet_aad(
            b"client_output",
            self.context_binding,
            run_binding,
            evaluation_digest,
        );
        let plaintext = crate::wire::serialize_encoded_bundle_payload(bundle)?;
        let (nonce, ciphertext) = self.ddh_evaluator.seal_message(
            DdhHssTransportPurpose::ClientOutput,
            &aad,
            &plaintext,
        )?;
        let packet = ClientOutputPacket {
            context_binding: self.context_binding,
            run_binding,
            evaluation_digest,
            nonce,
            ciphertext,
        };
        crate::wire::encode_transport_message(
            self.context_binding,
            TransportKind::ClientOutput,
            &packet,
        )
    }

    pub fn seal_seed_output_packet_message(
        &self,
        run_binding: [u8; 32],
        evaluation_digest: [u8; 32],
        bundle: &DdhHssInputShareBundle,
    ) -> ProtoResult<WireMessage> {
        let aad = crate::protocol::transcript::output_packet_aad(
            b"seed_output",
            self.context_binding,
            run_binding,
            evaluation_digest,
        );
        let plaintext = crate::wire::serialize_encoded_bundle_payload(bundle)?;
        let (nonce, ciphertext) = self.ddh_evaluator.seal_message(
            DdhHssTransportPurpose::ClientOutput,
            &aad,
            &plaintext,
        )?;
        let packet = SeedOutputPacket {
            context_binding: self.context_binding,
            run_binding,
            evaluation_digest,
            nonce,
            ciphertext,
        };
        crate::wire::encode_transport_message(
            self.context_binding,
            TransportKind::SeedOutput,
            &packet,
        )
    }

    pub fn build_evaluation_result_from_hidden_run(
        &self,
        runtime: &SharedRuntime,
        ddh_run: DdhHiddenEvalRun,
    ) -> ProtoResult<(EvaluationResult, u64, u64)> {
        let result_assembly_started = monotonic_now_ns();
        let run_binding = self.ddh_evaluator.run_binding(
            runtime.artifact.artifact_digest,
            ddh_run.client_input_commitment,
            ddh_run.server_input_commitment,
        );
        let evaluation_digest = crate::protocol::transcript::compute_evaluation_digest(
            runtime.artifact.artifact_digest,
            run_binding,
            &runtime.execution_result,
            &ddh_run.output,
        );
        let result_assembly_duration_ns = elapsed_ns_u64(result_assembly_started);
        let output_sealing_started = monotonic_now_ns();
        let client_output = self.seal_client_output_packet_message(
            run_binding,
            evaluation_digest,
            &ddh_run.output.x_client_base,
        )?;
        let client_output_binding = crate::protocol::transcript::nested_output_message_binding(
            self.context_binding,
            run_binding,
            evaluation_digest,
            b"client_output_message",
            &client_output.bytes,
        );
        let seed_output = self.seal_seed_output_packet_message(
            run_binding,
            evaluation_digest,
            &ddh_run.output.canonical_seed,
        )?;
        let seed_output_binding = crate::protocol::transcript::nested_output_message_binding(
            self.context_binding,
            run_binding,
            evaluation_digest,
            b"seed_output_message",
            &seed_output.bytes,
        );
        let server_output_payload = crate::wire::serialize_transport_pair_payload(
            "server_output_bundle",
            &ddh_run.output.x_relayer_base_left,
            &ddh_run.output.x_relayer_base_right,
        )?;
        let server_output_payload_binding =
            crate::protocol::transcript::server_output_payload_binding(
                self.context_binding,
                run_binding,
                evaluation_digest,
                &server_output_payload,
            );
        let output_sealing_finalization_duration_ns = elapsed_ns_u64(output_sealing_started);
        Ok((
            EvaluationResult {
                context_binding: self.context_binding,
                bindings: RunBindings {
                    client_input_commitment: ddh_run.client_input_commitment,
                    server_input_commitment: ddh_run.server_input_commitment,
                    run_binding,
                    evaluation_digest,
                },
                evaluator_witness: crate::wire::EvaluatorWitness {
                    total_steps: runtime.execution_program.trace.total_steps,
                    curve_cost_units: runtime.execution_program.trace.estimated_curve_cost_units,
                    evaluator_ops: runtime.execution_program.trace.evaluator_ops.clone(),
                    output_checksum: runtime.execution_result.output_checksum,
                    final_point_compressed: runtime.execution_result.final_point_compressed,
                },
                client_output,
                client_output_binding,
                seed_output,
                seed_output_binding,
                server_output_payload_binding,
                server_output_payload,
            },
            result_assembly_duration_ns,
            output_sealing_finalization_duration_ns,
        ))
    }

    pub(crate) fn build_final_report_from_hidden_run(
        &self,
        runtime: &SharedRuntime,
        garbler_session: &crate::server::ServerSession,
        ddh_run: DdhHiddenEvalRun,
    ) -> ProtoResult<(EvaluationReport, u64, u64)> {
        let result_assembly_started = monotonic_now_ns();
        let run_binding = self.ddh_evaluator.run_binding(
            runtime.artifact.artifact_digest,
            ddh_run.client_input_commitment,
            ddh_run.server_input_commitment,
        );
        let evaluation_digest = crate::protocol::transcript::compute_evaluation_digest(
            runtime.artifact.artifact_digest,
            run_binding,
            &runtime.execution_result,
            &ddh_run.output,
        );
        let result_assembly_duration_ns = elapsed_ns_u64(result_assembly_started);
        let output_sealing_started = monotonic_now_ns();
        let client_output = self.seal_client_output_packet_message(
            run_binding,
            evaluation_digest,
            &ddh_run.output.x_client_base,
        )?;
        let seed_output = self.seal_seed_output_packet_message(
            run_binding,
            evaluation_digest,
            &ddh_run.output.canonical_seed,
        )?;
        let server_output = garbler_session.seal_server_output_packet_message(
            run_binding,
            evaluation_digest,
            &ddh_run.output.x_relayer_base_left,
            &ddh_run.output.x_relayer_base_right,
        )?;
        let output_sealing_finalization_duration_ns = elapsed_ns_u64(output_sealing_started);
        Ok((
            EvaluationReport {
                report_version: crate::wire::PRIME_ORDER_SUCCINCT_HSS_REPORT_VERSION.to_string(),
                backend_family: crate::candidate::CandidateBackendFamily::PrimeOrderSizeOptimized,
                fixed_function_id: runtime.candidate.fixed_function_id.clone(),
                hidden_core_materialization: crate::wire::HiddenCoreMaterialization::DdhPrimitiveBaseline,
                artifact: runtime.artifact.clone(),
                bindings: RunBindings {
                    client_input_commitment: ddh_run.client_input_commitment,
                    server_input_commitment: ddh_run.server_input_commitment,
                    run_binding,
                    evaluation_digest,
                },
                evaluator_witness: EvaluatorWitness {
                    total_steps: runtime.execution_program.trace.total_steps,
                    curve_cost_units: runtime.execution_program.trace.estimated_curve_cost_units,
                    evaluator_ops: runtime.execution_program.trace.evaluator_ops.clone(),
                    output_checksum: runtime.execution_result.output_checksum,
                    final_point_compressed: runtime.execution_result.final_point_compressed,
                },
                output_delivery: OutputDelivery {
                    client: client_output,
                    seed: seed_output,
                    server: server_output,
                },
                notes: vec![
                    "Prepared session is bound to the encoded prime-order artifact and its compiled evaluator program.".to_string(),
                    "Per-run input sharing and transcript binding now run through the DDH primitive baseline owned by the prepared session.".to_string(),
                    "The DDH transport/output surface is now split into garbler/evaluator role views instead of one undifferentiated transport backend.".to_string(),
                    "The hidden evaluator now consumes pre-shared bit bundles instead of reconstructing clear F_expand inputs inside the executor.".to_string(),
                    "Evaluator-side execution now emits a serialized evaluation-result message that the garbler finalizes into the server output packet and final report.".to_string(),
                    "Output delivery now seals the hidden client/server base-share bundles directly; clear output bytes are only materialized through role-gated openers.".to_string(),
                    "This report is built on the current DDH primitive foundation; remaining work is final 2-party delivery semantics, security review, and performance hardening.".to_string(),
                ],
            },
            result_assembly_duration_ns,
            output_sealing_finalization_duration_ns,
        ))
    }

    pub fn validate_server_packet(&self, packet: &ServerPacket) -> ProtoResult<()> {
        crate::protocol::invariants::validate_evaluator_server_packet(self, packet)
    }
}
