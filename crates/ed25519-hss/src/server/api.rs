#[cfg(not(target_arch = "wasm32"))]
use crate::ddh::hidden_eval_executor::trace_prime_order_ddh_hidden_eval_program_with_split_server_inputs_with_pool;
use crate::ddh::hidden_eval_executor::{
    advance_message_schedule_continuation_with_pool, advance_round_core_continuation_with_pool,
    compute_message_schedule_completed_digest, compute_round_core_completed_digest,
    execute_prime_order_ddh_hidden_eval_program_profiled_with_pool,
    initialize_round_core_continuation_from_message_schedule_with_pool,
    materialize_server_output_bundles_from_continuations_with_pool,
    materialize_staged_server_execution_with_split_server_inputs_with_pool,
    prepare_ddh_hidden_eval_constant_pool, DdhHiddenEvalConstantPool, DdhHiddenEvalInputBundles,
    DdhHiddenEvalServerInputs, DdhHiddenEvalStageProfile,
};
use crate::ddh::{
    DdhHiddenEvalRun, DdhHssInputShareBundle, DdhHssOtReleasedRemoteBundle, DdhHssOtResponseBundle,
    HiddenEvalProgram,
};
use crate::ddh::{DdhHssTransportBundle, DdhHssTransportPurpose};
use crate::runtime::{
    evaluation::{elapsed_ns_u64, monotonic_now_ns},
    EvaluateTiming, SharedRuntime, SharedRuntimeAdvanceContext, SharedRuntimeAdvanceMaterial,
    SharedRuntimeFinalizeContext,
};
use crate::server::{
    ot::prepare_garbler_ot_state_for_session, ServerDriverState, ServerEvalFinalizeOutput,
    ServerEvalOperation, ServerEvalServerRoots, ServerEvalState, ServerOutputOpener, ServerSession,
    ServerSessionState,
};
use crate::shared::{ProtoError, ProtoResult};
#[cfg(test)]
use crate::wire::ServerPacket;
use crate::wire::{
    AddStageRequestPayload, AddStageResponsePayload, ClientOutputPacket, ClientPacket,
    ClientStageRequestPacket, EvaluationReport, HiddenCoreMaterialization,
    MessageScheduleResponsePayload, OutputDelivery, OutputProjectionResponsePayload,
    RoleSeparatedServerInputDeliveryPacket, RoleSeparatedServerInputsPacket,
    RoundCoreResponsePayload, SeedOutputPacket, ServerAssistInitPacket, ServerEvalHandle,
    ServerFinalizePacket, ServerOutputPacket, ServerStageCommitments, ServerStagePayload,
    ServerStageResponsePacket, StagedEvaluatorArtifact, TransportKind, WireMessage,
    PRIME_ORDER_SUCCINCT_HSS_REPORT_VERSION,
};
use rand_core::{OsRng, RngCore};

struct SameProcessTrustedEvalMaterial {
    y_client_response: DdhHssOtResponseBundle,
    tau_client_response: DdhHssOtResponseBundle,
    y_client_remote_release: DdhHssOtReleasedRemoteBundle,
    tau_client_remote_release: DdhHssOtReleasedRemoteBundle,
    server_input_commitment: [u8; 32],
    trusted_server_inputs: DdhHiddenEvalServerInputs,
}

struct ServerAssistInitMaterial {
    packet: ServerAssistInitPacket,
    state: ServerEvalState,
    y_server_bundle: DdhHssInputShareBundle,
    tau_server_bundle: DdhHssInputShareBundle,
    timing: EvaluateTiming,
}

#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug, Clone, PartialEq, Eq)]
struct SameProcessExecutionCheckpoints {
    add_stage_digest: [u8; 32],
    message_schedule_digest: [u8; 32],
    round_core_digest: [u8; 32],
    output_projection_digest: [u8; 32],
}

impl ServerSessionState {
    fn validate_current_backend(&self) -> ProtoResult<()> {
        if self.backend_version != self.ddh_garbler.evaluation_key().backend_version {
            return Err(crate::shared::ProtoError::InvalidInput(
                "server session state backend version does not match garbler".to_string(),
            ));
        }
        if self.backend_version != crate::ddh::DdhHssBackendVersion::CURRENT {
            return Err(crate::shared::ProtoError::InvalidInput(format!(
                "server session state backend version is stale: {}",
                self.backend_version.as_str()
            )));
        }
        Ok(())
    }

    pub fn materialize(&self) -> ProtoResult<ServerSession> {
        self.validate_current_backend()?;
        if self.client_ot_offer.backend_version != self.backend_version {
            return Err(crate::shared::ProtoError::InvalidInput(
                "server session OT offer backend version does not match session".to_string(),
            ));
        }
        if self.garbler_ot_state.backend_version != self.backend_version {
            return Err(crate::shared::ProtoError::InvalidInput(
                "server session OT state backend version does not match session".to_string(),
            ));
        }
        let prepared_ot_state = prepare_garbler_ot_state_for_session(
            &self.ddh_garbler,
            &self.client_ot_offer,
            &self.garbler_ot_state,
        )?;
        Ok(ServerSession {
            context_binding: self.context_binding,
            ddh_garbler: self.ddh_garbler.clone(),
            client_ot_offer: self.client_ot_offer.clone(),
            garbler_ot_state: self.garbler_ot_state.clone(),
            y_client_sender_words_prepared: prepared_ot_state.y_client_sender_words_prepared,
            tau_client_sender_words_prepared: prepared_ot_state.tau_client_sender_words_prepared,
        })
    }

    pub fn server_output_opener(&self) -> ProtoResult<ServerOutputOpener> {
        self.validate_current_backend()?;
        Ok(ServerOutputOpener {
            garbler: self.ddh_garbler.clone(),
            context_binding: self.context_binding,
        })
    }

    pub fn run_binding(
        &self,
        artifact_digest: [u8; 32],
        client_input_commitment: [u8; 32],
        server_input_commitment: [u8; 32],
    ) -> ProtoResult<[u8; 32]> {
        self.validate_current_backend()?;
        Ok(self.ddh_garbler.run_binding(
            artifact_digest,
            client_input_commitment,
            server_input_commitment,
        ))
    }

    pub fn seal_server_output_packet_message(
        &self,
        run_binding: [u8; 32],
        evaluation_digest: [u8; 32],
        left: &DdhHssTransportBundle,
        right: &DdhHssTransportBundle,
    ) -> ProtoResult<WireMessage> {
        self.validate_current_backend()?;
        let plaintext =
            crate::wire::serialize_transport_pair_payload("server_output_bundle", left, right)?;
        let aad = crate::protocol::transcript::output_packet_aad(
            b"server_output",
            self.context_binding,
            run_binding,
            evaluation_digest,
        );
        let (nonce, ciphertext) = self.ddh_garbler.seal_message(
            DdhHssTransportPurpose::ServerOutput,
            &aad,
            &plaintext,
        )?;
        let packet = ServerOutputPacket {
            context_binding: self.context_binding,
            run_binding,
            evaluation_digest,
            nonce,
            ciphertext,
        };
        crate::wire::encode_transport_message(
            self.context_binding,
            TransportKind::ServerOutput,
            &packet,
        )
    }

    pub fn prepare_server_finalize_packet_from_finalize_context(
        &self,
        finalize_context: &SharedRuntimeFinalizeContext,
        server_eval_state: &ServerEvalState,
        artifact: &StagedEvaluatorArtifact,
    ) -> ProtoResult<(ServerFinalizePacket, EvaluationReport)> {
        self.validate_current_backend()?;
        if server_eval_state.status != crate::server::ServerEvalStatus::Finalized {
            return Err(ProtoError::InvalidInput(
                "server finalize requires a finalized server eval state".to_string(),
            ));
        }
        let finalize_state = server_eval_state.finalize_state().ok_or_else(|| {
            ProtoError::InvalidInput("server finalize requires stored finalize state".to_string())
        })?;
        if finalize_context.context_binding != self.context_binding
            || server_eval_state.context_binding != self.context_binding
            || finalize_context.artifact.context_binding != self.context_binding
            || artifact.context_binding != self.context_binding
        {
            return Err(ProtoError::InvalidInput(
                "finalize context, session, state, and artifact context bindings must match"
                    .to_string(),
            ));
        }
        if artifact.backend_version != self.ddh_garbler.evaluation_key().backend_version {
            return Err(ProtoError::InvalidInput(
                "staged evaluator artifact backend version does not match garbler state"
                    .to_string(),
            ));
        }
        if artifact.bindings.client_input_commitment != finalize_state.client_input_commitment {
            return Err(ProtoError::InvalidInput(
                "staged evaluator artifact client input commitment does not match finalize state"
                    .to_string(),
            ));
        }
        if artifact.bindings.server_input_commitment != finalize_state.server_input_commitment {
            return Err(ProtoError::InvalidInput(
                "staged evaluator artifact server input commitment does not match finalize state"
                    .to_string(),
            ));
        }
        let expected_run_binding = self.run_binding(
            finalize_context.artifact.artifact_digest,
            finalize_state.client_input_commitment,
            finalize_state.server_input_commitment,
        )?;
        if artifact.bindings.run_binding != expected_run_binding {
            return Err(ProtoError::InvalidInput(
                "staged evaluator artifact run binding does not match finalize state".to_string(),
            ));
        }
        let client_packet: ClientOutputPacket = crate::wire::decode_transport_message(
            self.context_binding,
            TransportKind::ClientOutput,
            &artifact.client_output,
        )?;
        let seed_packet: SeedOutputPacket = crate::wire::decode_transport_message(
            self.context_binding,
            TransportKind::SeedOutput,
            &artifact.seed_output,
        )?;
        if client_packet.run_binding != artifact.bindings.run_binding
            || client_packet.evaluation_digest != artifact.bindings.evaluation_digest
        {
            return Err(ProtoError::InvalidInput(
                "evaluation result client output packet is not bound to the reported run"
                    .to_string(),
            ));
        }
        if client_packet.projection_mode != artifact.projection_mode {
            return Err(ProtoError::InvalidInput(
                "evaluation result client output projection mode does not match artifact"
                    .to_string(),
            ));
        }
        if client_packet.value_kind != artifact.client_output_value_kind {
            return Err(ProtoError::InvalidInput(
                "evaluation result client output value kind does not match artifact metadata"
                    .to_string(),
            ));
        }
        let expected_client_output_value_kind =
            crate::wire::ClientOutputValueKind::for_projection_mode(&artifact.projection_mode);
        if artifact.client_output_value_kind != expected_client_output_value_kind {
            return Err(ProtoError::InvalidInput(
                "evaluation result client output value kind does not match projection mode"
                    .to_string(),
            ));
        }
        if seed_packet.run_binding != artifact.bindings.run_binding
            || seed_packet.evaluation_digest != artifact.bindings.evaluation_digest
        {
            return Err(ProtoError::InvalidInput(
                "evaluation result seed output packet is not bound to the reported run".to_string(),
            ));
        }
        let expected_client_output_binding =
            crate::protocol::transcript::nested_output_message_binding(
                artifact.context_binding,
                artifact.bindings.run_binding,
                artifact.bindings.evaluation_digest,
                b"client_output_message",
                &artifact.client_output.bytes,
            );
        if artifact.client_output_binding != expected_client_output_binding {
            return Err(ProtoError::InvalidInput(
                "evaluation result client output binding is invalid".to_string(),
            ));
        }
        let expected_seed_output_binding =
            crate::protocol::transcript::nested_output_message_binding(
                artifact.context_binding,
                artifact.bindings.run_binding,
                artifact.bindings.evaluation_digest,
                b"seed_output_message",
                &artifact.seed_output.bytes,
            );
        if artifact.seed_output_binding != expected_seed_output_binding {
            return Err(ProtoError::InvalidInput(
                "evaluation result seed output binding is invalid".to_string(),
            ));
        }
        let expected_evaluation_digest =
            crate::protocol::transcript::compute_evaluation_digest_from_output_commitments(
                finalize_context.artifact.artifact_digest,
                expected_run_binding,
                &finalize_context.execution_result,
                finalize_state.output.canonical_seed_commitment,
                artifact.client_output_value_kind,
                artifact.client_output_commitment,
                crate::protocol::transcript::server_output_value_commitment(
                    &finalize_state.output.x_server_base_left,
                    &finalize_state.output.x_server_base_right,
                )?,
                artifact.output_projector_binding,
            );
        if artifact.bindings.evaluation_digest != expected_evaluation_digest {
            return Err(ProtoError::InvalidInput(
                "evaluation result digest does not match server output".to_string(),
            ));
        }
        let server_output_message = self.seal_server_output_packet_message(
            artifact.bindings.run_binding,
            artifact.bindings.evaluation_digest,
            &finalize_state.output.x_server_base_left,
            &finalize_state.output.x_server_base_right,
        )?;
        let output_delivery = OutputDelivery {
            client: artifact.client_output.clone(),
            seed: artifact.seed_output.clone(),
            server: server_output_message,
        };
        let report = EvaluationReport {
            report_version: PRIME_ORDER_SUCCINCT_HSS_REPORT_VERSION.to_string(),
            backend_version: self.backend_version,
            backend_family: crate::candidate::CandidateBackendFamily::PrimeOrderSizeOptimized,
            fixed_function_id: finalize_context.fixed_function_id.clone(),
            hidden_core_materialization: HiddenCoreMaterialization::DdhPrimitiveBaseline,
            artifact: finalize_context.artifact.clone(),
            bindings: artifact.bindings.clone(),
            projection_mode: artifact.projection_mode.clone(),
            output_projector_binding: artifact.output_projector_binding,
            evaluator_witness: artifact.evaluator_witness.clone(),
            output_delivery,
            notes: vec![
                "Prepared session is bound to the encoded prime-order artifact and its compiled evaluator program.".to_string(),
                "Per-run input sharing and transcript binding now run through the DDH primitive baseline owned by the prepared session.".to_string(),
                "The DDH transport/output surface is now split into garbler/evaluator role views instead of one undifferentiated transport backend.".to_string(),
                "The hidden evaluator now consumes pre-shared bit bundles instead of reconstructing clear F_expand inputs inside the executor.".to_string(),
                "Evaluator-side execution now emits a staged evaluator artifact that the garbler finalizes into the server output packet and final report.".to_string(),
                "Output delivery now seals the hidden client/server base-share bundles directly; clear output bytes are only materialized through role-gated openers.".to_string(),
                "This report is built on the current DDH primitive foundation; remaining work is final 2-party delivery semantics, security review, and performance hardening.".to_string(),
            ],
        };
        let allowed_output_kind =
            ServerSession::allowed_output_kind_for_operation(server_eval_state.operation);
        let seed_output = match allowed_output_kind {
            crate::wire::AllowedOutputKind::ClientOutputOnly => None,
            crate::wire::AllowedOutputKind::ClientOutputAndSeedOutput => {
                Some(report.output_delivery.seed.clone())
            }
        };
        Ok((
            ServerFinalizePacket {
                context_binding: self.context_binding,
                server_eval_handle: server_eval_state.handle,
                final_transcript_digest: server_eval_state.current_transcript_digest,
                allowed_output_kind,
                projection_mode: artifact.projection_mode.clone(),
                client_output: report.output_delivery.client.clone(),
                seed_output,
            },
            report,
        ))
    }
}

impl ServerDriverState {
    fn validate_advance_runtime(&self) -> ProtoResult<()> {
        let context_binding = self.runtime.prepared_context.binding_digest()?;
        let evaluation_key = self.garbler_session.ddh_garbler.evaluation_key();
        if self.advance_runtime.context_binding != context_binding {
            return Err(ProtoError::InvalidInput(
                "server advance runtime context binding does not match prepared runtime"
                    .to_string(),
            ));
        }
        if self.advance_runtime.projection_mode != self.runtime.projection_mode {
            return Err(ProtoError::InvalidInput(
                "server advance runtime projection mode does not match prepared runtime"
                    .to_string(),
            ));
        }
        if self.advance_runtime.artifact.context_binding != context_binding {
            return Err(ProtoError::InvalidInput(
                "server advance artifact context binding does not match prepared runtime"
                    .to_string(),
            ));
        }
        if self.advance_runtime.finalize_context.context_binding != context_binding {
            return Err(ProtoError::InvalidInput(
                "server advance finalize context binding does not match prepared runtime"
                    .to_string(),
            ));
        }
        if self.advance_runtime.finalize_context.artifact != self.advance_runtime.artifact {
            return Err(ProtoError::InvalidInput(
                "server advance finalize context artifact does not match advance artifact"
                    .to_string(),
            ));
        }
        if self.garbler_session.context_binding != context_binding {
            return Err(ProtoError::InvalidInput(
                "server advance garbler session context binding does not match prepared runtime"
                    .to_string(),
            ));
        }
        if evaluation_key.context_binding != context_binding {
            return Err(ProtoError::InvalidInput(
                "server advance evaluation key context binding does not match prepared runtime"
                    .to_string(),
            ));
        }
        if evaluation_key.candidate_digest != self.advance_runtime.artifact.candidate_digest {
            return Err(ProtoError::InvalidInput(
                "server advance evaluation key candidate digest does not match artifact"
                    .to_string(),
            ));
        }
        if evaluation_key.program_digest != self.advance_runtime.program_digest {
            return Err(ProtoError::InvalidInput(
                "server advance evaluation key program digest does not match advance program"
                    .to_string(),
            ));
        }
        Ok(())
    }

    pub fn materialize(&self) -> ProtoResult<(SharedRuntime, ServerSession)> {
        Ok((
            self.runtime.materialize()?,
            self.garbler_session.materialize()?,
        ))
    }

    pub fn advance_runtime_context(&self) -> ProtoResult<SharedRuntimeAdvanceContext> {
        self.validate_advance_runtime()?;
        Ok(self.advance_runtime.clone())
    }

    pub fn advance_runtime_material(&self) -> ProtoResult<SharedRuntimeAdvanceMaterial> {
        self.validate_advance_runtime()?;
        let material = self.advance_runtime.materialize()?;
        if self
            .garbler_session
            .ddh_garbler
            .evaluation_key()
            .primitive_kind
            != material.hidden_eval_program.primitive_kind
        {
            return Err(ProtoError::InvalidInput(
                "server advance evaluation key primitive kind does not match advance program"
                    .to_string(),
            ));
        }
        Ok(material)
    }

    pub fn materialize_for_advance(
        &self,
    ) -> ProtoResult<(SharedRuntimeAdvanceMaterial, ServerSession)> {
        Ok((
            self.advance_runtime_material()?,
            self.garbler_session.materialize()?,
        ))
    }
}

impl ServerSession {
    pub fn hidden_eval_constant_pool(&self) -> ProtoResult<DdhHiddenEvalConstantPool> {
        prepare_ddh_hidden_eval_constant_pool(self.ddh_garbler.backend())
    }

    fn allowed_output_kind_for_operation(
        operation: ServerEvalOperation,
    ) -> crate::wire::AllowedOutputKind {
        match operation {
            ServerEvalOperation::ExplicitKeyExport => {
                // Explicit key export intentionally falls outside the non-export
                // server-root secrecy invariant. This flow is allowed to hand
                // canonical-seed/private-key-equivalent material to the
                // authorized client runtime because export is the operation
                // where the user explicitly asks to receive the key. A
                // compromised client runtime can therefore abuse this flow by
                // design, which is why the stronger secrecy guarantee only
                // applies to non-export operations.
                crate::wire::AllowedOutputKind::ClientOutputAndSeedOutput
            }
            ServerEvalOperation::Registration
            | ServerEvalOperation::TxSigning
            | ServerEvalOperation::LinkDevice
            | ServerEvalOperation::EmailRecovery
            | ServerEvalOperation::WarmSessionReconstruction => {
                crate::wire::AllowedOutputKind::ClientOutputOnly
            }
        }
    }

    fn new_server_eval_handle(&self) -> ServerEvalHandle {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        ServerEvalHandle { bytes }
    }

    pub fn run_binding(
        &self,
        artifact_digest: [u8; 32],
        client_input_commitment: [u8; 32],
        server_input_commitment: [u8; 32],
    ) -> [u8; 32] {
        self.ddh_garbler.run_binding(
            artifact_digest,
            client_input_commitment,
            server_input_commitment,
        )
    }

    pub fn client_ot_offer_message(&self) -> ProtoResult<WireMessage> {
        crate::wire::encode_transport_message(
            self.context_binding,
            TransportKind::ClientOtOffer,
            &self.client_ot_offer,
        )
    }

    pub fn server_output_opener(&self) -> ServerOutputOpener {
        ServerOutputOpener {
            garbler: self.ddh_garbler.clone(),
            context_binding: self.context_binding,
        }
    }

    #[cfg(test)]
    fn prepare_server_message(
        &self,
        client_request_message: &WireMessage,
        y_server: [u8; 32],
        tau_server: [u8; 32],
    ) -> ProtoResult<WireMessage> {
        let client_packet: ClientPacket = crate::wire::decode_transport_message(
            self.context_binding,
            TransportKind::ClientOtRequest,
            client_request_message,
        )?;
        let server_packet = self.prepare_server_packet(&client_packet, y_server, tau_server)?;
        crate::wire::encode_transport_message(
            self.context_binding,
            TransportKind::ServerPacket,
            &server_packet,
        )
    }

    pub fn prepare_server_assist_init_message(
        &self,
        client_request_message: &WireMessage,
        y_server: [u8; 32],
        tau_server: [u8; 32],
        operation: ServerEvalOperation,
    ) -> ProtoResult<(WireMessage, ServerEvalState)> {
        let client_packet: ClientPacket = crate::wire::decode_transport_message(
            self.context_binding,
            TransportKind::ClientOtRequest,
            client_request_message,
        )?;
        let (packet, state) =
            self.prepare_server_assist_init(&client_packet, y_server, tau_server, operation)?;
        let message = crate::wire::encode_transport_message(
            self.context_binding,
            TransportKind::ServerAssistInit,
            &packet,
        )?;
        Ok((message, state))
    }

    pub(crate) fn materialize_execution_state_from_add_stage_request(
        &self,
        runtime: &SharedRuntime,
        evaluator_session: &crate::client::ClientSession,
        state: &ServerEvalState,
        request: &ClientStageRequestPacket,
    ) -> ProtoResult<ServerEvalState> {
        self.materialize_execution_state_from_add_stage_request_with_program(
            &runtime.hidden_eval_program,
            evaluator_session,
            state,
            request,
        )
    }

    pub(crate) fn materialize_execution_state_from_add_stage_request_with_program(
        &self,
        hidden_eval_program: &HiddenEvalProgram,
        evaluator_session: &crate::client::ClientSession,
        state: &ServerEvalState,
        request: &ClientStageRequestPacket,
    ) -> ProtoResult<ServerEvalState> {
        if state.execution_state.is_some() {
            return Ok(state.clone());
        }
        let crate::wire::ClientStagePayload::AddStage(AddStageRequestPayload {
            client_input_commitment,
            y_client_bundle_payload,
            tau_client_bundle_payload,
            ..
        }) = &request.client_stage_payload
        else {
            return Err(crate::shared::ProtoError::InvalidInput(
                "execution state materialization requires an add-stage request payload".to_string(),
            ));
        };
        let y_client_bundle =
            crate::wire::deserialize_encoded_bundle_payload_unsealed(y_client_bundle_payload)?;
        let tau_client_bundle =
            crate::wire::deserialize_encoded_bundle_payload_unsealed(tau_client_bundle_payload)?;
        let expected_client_input_commitment =
            evaluator_session.ddh_evaluator.combined_input_commitment(
                crate::ddh::HiddenEvalInputOwner::Client,
                &[&y_client_bundle, &tau_client_bundle],
            );
        if expected_client_input_commitment != *client_input_commitment {
            return Err(crate::shared::ProtoError::InvalidInput(
                "add-stage request client input commitment does not match the supplied client bundles"
                    .to_string(),
            ));
        }
        let server_inputs = if let Some(server_input_bundles) = state.server_input_bundles() {
            server_input_bundles.clone()
        } else {
            let server_roots = state.server_roots().ok_or_else(|| {
                crate::shared::ProtoError::InvalidInput(
                    "server eval state no longer retains input material for execution materialization"
                        .to_string(),
                )
            })?;
            let y_server_bundle = self
                .ddh_garbler
                .share_server_input_bit_bundle("y_server_bits", &server_roots.y_server)?;
            let tau_server_bundle = self
                .ddh_garbler
                .share_server_input_bit_bundle("tau_server_bits", &server_roots.tau_server)?;
            DdhHiddenEvalServerInputs::from_joint_bundles(&y_server_bundle, &tau_server_bundle)
        };
        let hidden_eval_constants = evaluator_session.hidden_eval_constant_pool()?;
        let staged_materialization =
            materialize_staged_server_execution_with_split_server_inputs_with_pool(
                hidden_eval_program,
                &evaluator_session.ddh_evaluator,
                &hidden_eval_constants,
                &y_client_bundle,
                &server_inputs.y_server_bits,
                &tau_client_bundle,
                &server_inputs.tau_server_bits,
            )?;
        Ok(state.with_add_stage_materialization(
            hidden_eval_program.clone(),
            staged_materialization.message_schedule,
            staged_materialization.projector_inputs,
            staged_materialization.client_input_commitment,
            staged_materialization.server_input_commitment,
        ))
    }

    pub fn build_staged_evaluator_artifact_from_transport_messages(
        &self,
        runtime: &SharedRuntime,
        evaluator_session: &crate::client::ClientSession,
        evaluator_ot_state: &crate::client::ClientOtState,
        client_request_message: &WireMessage,
        y_server: [u8; 32],
        tau_server: [u8; 32],
        operation: ServerEvalOperation,
    ) -> ProtoResult<(StagedEvaluatorArtifact, ServerEvalFinalizeOutput)> {
        let constant_pool = prepare_ddh_hidden_eval_constant_pool(self.ddh_garbler.backend())?;
        self.build_staged_evaluator_artifact_from_transport_messages_with_pool(
            runtime,
            evaluator_session,
            evaluator_ot_state,
            client_request_message,
            y_server,
            tau_server,
            operation,
            &constant_pool,
        )
    }

    pub fn build_staged_evaluator_artifact_from_transport_messages_profiled(
        &self,
        runtime: &SharedRuntime,
        evaluator_session: &crate::client::ClientSession,
        evaluator_ot_state: &crate::client::ClientOtState,
        client_request_message: &WireMessage,
        y_server: [u8; 32],
        tau_server: [u8; 32],
        operation: ServerEvalOperation,
    ) -> ProtoResult<(
        StagedEvaluatorArtifact,
        ServerEvalFinalizeOutput,
        DdhHiddenEvalStageProfile,
        EvaluateTiming,
    )> {
        let constant_pool = prepare_ddh_hidden_eval_constant_pool(self.ddh_garbler.backend())?;
        self.build_staged_evaluator_artifact_from_transport_messages_profiled_with_pool(
            runtime,
            evaluator_session,
            evaluator_ot_state,
            client_request_message,
            y_server,
            tau_server,
            operation,
            &constant_pool,
        )
    }

    pub fn build_staged_evaluator_artifact_from_transport_messages_with_pool(
        &self,
        runtime: &SharedRuntime,
        evaluator_session: &crate::client::ClientSession,
        evaluator_ot_state: &crate::client::ClientOtState,
        client_request_message: &WireMessage,
        y_server: [u8; 32],
        tau_server: [u8; 32],
        _operation: ServerEvalOperation,
        constant_pool: &DdhHiddenEvalConstantPool,
    ) -> ProtoResult<(StagedEvaluatorArtifact, ServerEvalFinalizeOutput)> {
        let (artifact, server_output, _stage_profile, _timing) = self
            .build_staged_evaluator_artifact_from_transport_messages_profiled_with_pool(
                runtime,
                evaluator_session,
                evaluator_ot_state,
                client_request_message,
                y_server,
                tau_server,
                _operation,
                constant_pool,
            )?;
        Ok((artifact, server_output))
    }

    pub fn build_staged_evaluator_artifact_from_transport_messages_profiled_with_pool(
        &self,
        runtime: &SharedRuntime,
        evaluator_session: &crate::client::ClientSession,
        evaluator_ot_state: &crate::client::ClientOtState,
        client_request_message: &WireMessage,
        y_server: [u8; 32],
        tau_server: [u8; 32],
        _operation: ServerEvalOperation,
        constant_pool: &DdhHiddenEvalConstantPool,
    ) -> ProtoResult<(
        StagedEvaluatorArtifact,
        ServerEvalFinalizeOutput,
        DdhHiddenEvalStageProfile,
        EvaluateTiming,
    )> {
        let client_packet: ClientPacket = crate::wire::decode_transport_message(
            self.context_binding,
            TransportKind::ClientOtRequest,
            client_request_message,
        )?;
        let (run, stage_profile, mut timing) = self
            .build_hidden_eval_run_from_transport_messages_with_pool(
                evaluator_session,
                evaluator_ot_state,
                &client_packet,
                &runtime.hidden_eval_program,
                y_server,
                tau_server,
                constant_pool,
            )?;
        let server_output = ServerEvalFinalizeOutput::from_hidden_eval_outputs(&run.output);
        let (artifact, result_assembly_duration_ns, output_sealing_finalization_duration_ns) =
            evaluator_session.build_staged_evaluator_artifact_from_hidden_eval_outputs(
                runtime,
                run.client_input_commitment,
                run.server_input_commitment,
                run.output,
                None,
            )?;
        timing.result_assembly_duration_ns = result_assembly_duration_ns;
        timing.output_sealing_finalization_duration_ns = output_sealing_finalization_duration_ns;
        Ok((artifact, server_output, stage_profile, timing))
    }

    fn build_hidden_eval_run_from_transport_messages_with_pool(
        &self,
        evaluator_session: &crate::client::ClientSession,
        evaluator_ot_state: &crate::client::ClientOtState,
        client_packet: &ClientPacket,
        hidden_eval_program: &HiddenEvalProgram,
        y_server: [u8; 32],
        tau_server: [u8; 32],
        constant_pool: &DdhHiddenEvalConstantPool,
    ) -> ProtoResult<(DdhHiddenEvalRun, DdhHiddenEvalStageProfile, EvaluateTiming)> {
        let (trusted_server_eval, mut timing) =
            self.prepare_trusted_server_eval_timed(client_packet, y_server, tau_server)?;
        let ot_reconstruct_started = monotonic_now_ns();
        let (y_client_bundle, y_timing) = evaluator_session
            .ddh_evaluator
            .reconstruct_client_ot_bundle_timed(
                evaluator_session.context_binding,
                &trusted_server_eval.y_client_response,
                &evaluator_ot_state.y_client_local_state,
                &trusted_server_eval.y_client_remote_release,
            )?;
        let (tau_client_bundle, tau_timing) = evaluator_session
            .ddh_evaluator
            .reconstruct_client_ot_bundle_timed(
                evaluator_session.context_binding,
                &trusted_server_eval.tau_client_response,
                &evaluator_ot_state.tau_client_local_state,
                &trusted_server_eval.tau_client_remote_release,
            )?;
        timing.ot_open_join_duration_ns = timing
            .ot_open_join_duration_ns
            .saturating_add(elapsed_ns_u64(ot_reconstruct_started));
        timing.add_ot_reconstruct_timing(y_timing);
        timing.add_ot_reconstruct_timing(tau_timing);
        let expected_client_input_commitment =
            evaluator_session.ddh_evaluator.combined_input_commitment(
                crate::ddh::HiddenEvalInputOwner::Client,
                &[&y_client_bundle, &tau_client_bundle],
            );
        let input_bundles = DdhHiddenEvalInputBundles {
            y_client_bits: y_client_bundle,
            server_inputs: trusted_server_eval.trusted_server_inputs,
            tau_client_bits: tau_client_bundle,
        };
        let profile = execute_prime_order_ddh_hidden_eval_program_profiled_with_pool(
            hidden_eval_program,
            &evaluator_session.ddh_evaluator,
            constant_pool,
            &input_bundles,
        )?;
        let run = profile.run;
        if run.client_input_commitment != expected_client_input_commitment {
            return Err(crate::shared::ProtoError::InvalidInput(
                "client delivery packet commitment does not match evaluated run".to_string(),
            ));
        }
        if run.server_input_commitment != trusted_server_eval.server_input_commitment {
            return Err(crate::shared::ProtoError::InvalidInput(
                "server delivery packet commitment does not match evaluated run".to_string(),
            ));
        }
        Ok((run, profile.stage_profile, timing))
    }

    pub fn prepare_server_ceremony_from_transport_messages(
        &self,
        runtime: &SharedRuntime,
        evaluator_session: &crate::client::ClientSession,
        evaluator_ot_state: &crate::client::ClientOtState,
        client_request_message: &WireMessage,
        y_server: [u8; 32],
        tau_server: [u8; 32],
        operation: ServerEvalOperation,
    ) -> ProtoResult<(
        WireMessage,
        StagedEvaluatorArtifact,
        ServerEvalFinalizeOutput,
    )> {
        let client_packet: ClientPacket = crate::wire::decode_transport_message(
            self.context_binding,
            TransportKind::ClientOtRequest,
            client_request_message,
        )?;
        let (server_assist_init, _server_eval_state) =
            self.prepare_server_assist_init(&client_packet, y_server, tau_server, operation)?;
        let (artifact, server_output) = self
            .build_staged_evaluator_artifact_from_transport_messages_with_pool(
                runtime,
                evaluator_session,
                evaluator_ot_state,
                client_request_message,
                y_server,
                tau_server,
                operation,
                &prepare_ddh_hidden_eval_constant_pool(self.ddh_garbler.backend())?,
            )?;
        let server_assist_init_message = crate::wire::encode_transport_message(
            self.context_binding,
            TransportKind::ServerAssistInit,
            &server_assist_init,
        )?;
        Ok((server_assist_init_message, artifact, server_output))
    }

    pub fn prepare_add_stage_response(
        &self,
        state: &ServerEvalState,
        request: &ClientStageRequestPacket,
    ) -> ProtoResult<(ServerStageResponsePacket, ServerEvalState)> {
        crate::protocol::invariants::validate_add_stage_request_packet(state, request)?;
        let request_digest =
            crate::protocol::transcript::compute_client_stage_request_digest(request)?;
        if let Some(previous_request_digest) = state.last_request_digest {
            if previous_request_digest != request_digest {
                return Err(crate::shared::ProtoError::InvalidInput(
                    "client stage request digest does not match the prior request for this handle"
                        .to_string(),
                ));
            }
        }
        let server_stage_token = crate::protocol::transcript::compute_add_stage_response_token(
            state.handle,
            state.transcript_id,
            request.stage_id,
            request.prior_transcript_digest,
            request_digest,
            state.server_input_commitment,
        );
        let server_stage_digest = crate::protocol::transcript::compute_add_stage_response_digest(
            state.context_binding,
            state.handle,
            request.stage_id,
            request.prior_transcript_digest,
            state.server_input_commitment,
            server_stage_token,
        );
        let execution_checkpoint_digest = state
            .current_execution_checkpoint_digest()
            .unwrap_or(server_stage_digest);
        let response = ServerStageResponsePacket {
            context_binding: state.context_binding,
            server_eval_handle: state.handle,
            stage_id: request.stage_id,
            next_transcript_digest: server_stage_digest,
            server_stage_payload: ServerStagePayload::AddStage(AddStageResponsePayload {
                server_stage_token,
                server_input_commitment: state.server_input_commitment,
                server_stage_digest,
                execution_checkpoint_digest,
            }),
            server_stage_commitments: ServerStageCommitments {
                digests: vec![
                    state.server_input_commitment,
                    server_stage_digest,
                    execution_checkpoint_digest,
                ],
            },
        };
        crate::protocol::invariants::validate_add_stage_response_packet(state, request, &response)?;
        Ok((
            response,
            state.advance_after_add_stage(server_stage_digest, request_digest),
        ))
    }

    pub fn prepare_add_stage_response_message(
        &self,
        state: &ServerEvalState,
        client_stage_request_message: &WireMessage,
    ) -> ProtoResult<(WireMessage, ServerEvalState)> {
        let request: ClientStageRequestPacket = crate::wire::decode_transport_message(
            self.context_binding,
            TransportKind::ClientStageRequest,
            client_stage_request_message,
        )?;
        let (response, next_state) = self.prepare_add_stage_response(state, &request)?;
        let message = crate::wire::encode_transport_message(
            self.context_binding,
            TransportKind::ServerStageResponse,
            &response,
        )?;
        Ok((message, next_state))
    }

    pub fn prepare_add_stage_response_message_with_runtime(
        &self,
        runtime: &SharedRuntime,
        evaluator_session: &crate::client::ClientSession,
        state: &ServerEvalState,
        client_stage_request_message: &WireMessage,
    ) -> ProtoResult<(WireMessage, ServerEvalState)> {
        let request: ClientStageRequestPacket = crate::wire::decode_transport_message(
            self.context_binding,
            TransportKind::ClientStageRequest,
            client_stage_request_message,
        )?;
        let state = if state.execution_state.is_none() {
            self.materialize_execution_state_from_add_stage_request(
                runtime,
                evaluator_session,
                state,
                &request,
            )?
        } else {
            state.clone()
        };
        let (response, next_state) = self.prepare_add_stage_response(&state, &request)?;
        let message = crate::wire::encode_transport_message(
            self.context_binding,
            TransportKind::ServerStageResponse,
            &response,
        )?;
        Ok((message, next_state))
    }

    pub fn prepare_add_stage_response_message_with_program(
        &self,
        hidden_eval_program: &HiddenEvalProgram,
        evaluator_session: &crate::client::ClientSession,
        state: &ServerEvalState,
        client_stage_request_message: &WireMessage,
    ) -> ProtoResult<(WireMessage, ServerEvalState)> {
        let request: ClientStageRequestPacket = crate::wire::decode_transport_message(
            self.context_binding,
            TransportKind::ClientStageRequest,
            client_stage_request_message,
        )?;
        let state = if state.execution_state.is_none() {
            self.materialize_execution_state_from_add_stage_request_with_program(
                hidden_eval_program,
                evaluator_session,
                state,
                &request,
            )?
        } else {
            state.clone()
        };
        let (response, next_state) = self.prepare_add_stage_response(&state, &request)?;
        let message = crate::wire::encode_transport_message(
            self.context_binding,
            TransportKind::ServerStageResponse,
            &response,
        )?;
        Ok((message, next_state))
    }

    pub fn prepare_message_schedule_response(
        &self,
        state: &ServerEvalState,
        request: &ClientStageRequestPacket,
    ) -> ProtoResult<(ServerStageResponsePacket, ServerEvalState)> {
        let constant_pool = self.hidden_eval_constant_pool()?;
        self.prepare_message_schedule_response_with_pool(state, request, &constant_pool)
    }

    pub fn prepare_message_schedule_response_with_pool(
        &self,
        state: &ServerEvalState,
        request: &ClientStageRequestPacket,
        constant_pool: &DdhHiddenEvalConstantPool,
    ) -> ProtoResult<(ServerStageResponsePacket, ServerEvalState)> {
        crate::protocol::invariants::validate_message_schedule_request_packet(state, request)?;
        let request_digest =
            crate::protocol::transcript::compute_client_stage_request_digest(request)?;
        let next_stage_token = crate::protocol::transcript::compute_message_schedule_response_token(
            state.handle,
            state.transcript_id,
            request.stage_id,
            request.prior_transcript_digest,
            request_digest,
        );
        let crate::wire::ClientStagePayload::MessageSchedule(payload) =
            &request.client_stage_payload
        else {
            return Err(crate::shared::ProtoError::InvalidInput(
                "client stage request payload must be message-schedule".to_string(),
            ));
        };
        let server_schedule_digest =
            crate::protocol::transcript::compute_message_schedule_response_digest(
                state.context_binding,
                state.handle,
                request.stage_id,
                payload.schedule_step,
                payload.prior_server_stage_digest,
                next_stage_token,
            );
        let hidden_eval_program = state.hidden_eval_program.as_ref().ok_or_else(|| {
            crate::shared::ProtoError::InvalidInput(
                "message-schedule response requires stored hidden-eval program".to_string(),
            )
        })?;
        let next_message_schedule = match &state.execution_state {
            Some(crate::server::ServerEvalExecutionState::MessageSchedule(schedule_state)) => {
                Some(advance_message_schedule_continuation_with_pool(
                    self.ddh_garbler.backend(),
                    constant_pool,
                    &schedule_state.message_schedule,
                )?)
            }
            _ => None,
        };
        let execution_checkpoint_digest = next_message_schedule
            .as_ref()
            .map(compute_message_schedule_completed_digest)
            .transpose()?
            .unwrap_or_else(|| {
                state
                    .current_execution_checkpoint_digest()
                    .unwrap_or(server_schedule_digest)
            });
        let final_schedule_round = state.current_stage.ordinal + 1
            >= crate::wire::ServerEvalStageId::MESSAGE_SCHEDULE_ROUNDS;
        let next_round_core = if final_schedule_round {
            Some(
                initialize_round_core_continuation_from_message_schedule_with_pool(
                    hidden_eval_program,
                    self.ddh_garbler.backend(),
                    constant_pool,
                    next_message_schedule.as_ref().ok_or_else(|| {
                        crate::shared::ProtoError::InvalidInput(
                            "message-schedule response requires next schedule continuation"
                                .to_string(),
                        )
                    })?,
                )?,
            )
        } else {
            None
        };
        let response = ServerStageResponsePacket {
            context_binding: state.context_binding,
            server_eval_handle: state.handle,
            stage_id: request.stage_id,
            next_transcript_digest: server_schedule_digest,
            server_stage_payload: ServerStagePayload::MessageSchedule(
                MessageScheduleResponsePayload {
                    schedule_step: payload.schedule_step,
                    server_schedule_digest,
                    next_stage_token,
                    execution_checkpoint_digest,
                },
            ),
            server_stage_commitments: ServerStageCommitments {
                digests: vec![
                    server_schedule_digest,
                    next_stage_token,
                    execution_checkpoint_digest,
                ],
            },
        };
        let next_state = state.advance_after_message_schedule(
            server_schedule_digest,
            request_digest,
            next_message_schedule,
            next_round_core,
        );
        crate::protocol::invariants::validate_message_schedule_response_packet(
            &next_state,
            request,
            &response,
        )?;
        Ok((response, next_state))
    }

    pub fn prepare_message_schedule_response_message(
        &self,
        state: &ServerEvalState,
        client_stage_request_message: &WireMessage,
    ) -> ProtoResult<(WireMessage, ServerEvalState)> {
        let constant_pool = self.hidden_eval_constant_pool()?;
        self.prepare_message_schedule_response_message_with_pool(
            state,
            client_stage_request_message,
            &constant_pool,
        )
    }

    pub fn prepare_message_schedule_response_message_with_pool(
        &self,
        state: &ServerEvalState,
        client_stage_request_message: &WireMessage,
        constant_pool: &DdhHiddenEvalConstantPool,
    ) -> ProtoResult<(WireMessage, ServerEvalState)> {
        let request: ClientStageRequestPacket = crate::wire::decode_transport_message(
            self.context_binding,
            TransportKind::ClientStageRequest,
            client_stage_request_message,
        )?;
        let (response, next_state) =
            self.prepare_message_schedule_response_with_pool(state, &request, constant_pool)?;
        let message = crate::wire::encode_transport_message(
            self.context_binding,
            TransportKind::ServerStageResponse,
            &response,
        )?;
        Ok((message, next_state))
    }

    pub fn prepare_round_core_response(
        &self,
        state: &ServerEvalState,
        request: &ClientStageRequestPacket,
    ) -> ProtoResult<(ServerStageResponsePacket, ServerEvalState)> {
        let constant_pool = self.hidden_eval_constant_pool()?;
        self.prepare_round_core_response_with_pool(state, request, &constant_pool)
    }

    pub fn prepare_round_core_response_with_pool(
        &self,
        state: &ServerEvalState,
        request: &ClientStageRequestPacket,
        constant_pool: &DdhHiddenEvalConstantPool,
    ) -> ProtoResult<(ServerStageResponsePacket, ServerEvalState)> {
        crate::protocol::invariants::validate_round_core_request_packet(state, request)?;
        let request_digest =
            crate::protocol::transcript::compute_client_stage_request_digest(request)?;
        let next_stage_token = crate::protocol::transcript::compute_round_core_response_token(
            state.handle,
            state.transcript_id,
            request.stage_id,
            request.prior_transcript_digest,
            request_digest,
        );
        let crate::wire::ClientStagePayload::RoundCore(payload) = &request.client_stage_payload
        else {
            return Err(crate::shared::ProtoError::InvalidInput(
                "client stage request payload must be round-core".to_string(),
            ));
        };
        let server_round_digest = crate::protocol::transcript::compute_round_core_response_digest(
            state.context_binding,
            state.handle,
            request.stage_id,
            payload.round_index,
            payload.prior_server_stage_digest,
            next_stage_token,
        );
        let next_round_core = match &state.execution_state {
            Some(crate::server::ServerEvalExecutionState::RoundCore(round_core_state)) => {
                advance_round_core_continuation_with_pool(
                    self.ddh_garbler.backend(),
                    constant_pool,
                    &round_core_state.round_core,
                )?
            }
            _ => {
                return Err(crate::shared::ProtoError::InvalidInput(
                    "round-core response requires stored round-core continuation state".to_string(),
                ));
            }
        };
        let execution_checkpoint_digest = compute_round_core_completed_digest(&next_round_core)?;
        let response = ServerStageResponsePacket {
            context_binding: state.context_binding,
            server_eval_handle: state.handle,
            stage_id: request.stage_id,
            next_transcript_digest: server_round_digest,
            server_stage_payload: ServerStagePayload::RoundCore(RoundCoreResponsePayload {
                round_index: payload.round_index,
                server_round_digest,
                next_stage_token,
                execution_checkpoint_digest,
            }),
            server_stage_commitments: ServerStageCommitments {
                digests: vec![
                    server_round_digest,
                    next_stage_token,
                    execution_checkpoint_digest,
                ],
            },
        };
        let next_state =
            state.advance_after_round_core(server_round_digest, request_digest, next_round_core);
        crate::protocol::invariants::validate_round_core_response_packet(
            &next_state,
            request,
            &response,
        )?;
        Ok((response, next_state))
    }

    pub fn prepare_round_core_response_message(
        &self,
        state: &ServerEvalState,
        client_stage_request_message: &WireMessage,
    ) -> ProtoResult<(WireMessage, ServerEvalState)> {
        let constant_pool = self.hidden_eval_constant_pool()?;
        self.prepare_round_core_response_message_with_pool(
            state,
            client_stage_request_message,
            &constant_pool,
        )
    }

    pub fn prepare_round_core_response_message_with_pool(
        &self,
        state: &ServerEvalState,
        client_stage_request_message: &WireMessage,
        constant_pool: &DdhHiddenEvalConstantPool,
    ) -> ProtoResult<(WireMessage, ServerEvalState)> {
        let request: ClientStageRequestPacket = crate::wire::decode_transport_message(
            self.context_binding,
            TransportKind::ClientStageRequest,
            client_stage_request_message,
        )?;
        let (response, next_state) =
            self.prepare_round_core_response_with_pool(state, &request, constant_pool)?;
        let message = crate::wire::encode_transport_message(
            self.context_binding,
            TransportKind::ServerStageResponse,
            &response,
        )?;
        Ok((message, next_state))
    }

    pub fn prepare_output_projection_response(
        &self,
        state: &ServerEvalState,
        request: &ClientStageRequestPacket,
    ) -> ProtoResult<(ServerStageResponsePacket, ServerEvalState)> {
        let constant_pool = self.hidden_eval_constant_pool()?;
        self.prepare_output_projection_response_with_pool(state, request, &constant_pool)
    }

    pub fn prepare_output_projection_response_with_pool(
        &self,
        state: &ServerEvalState,
        request: &ClientStageRequestPacket,
        constant_pool: &DdhHiddenEvalConstantPool,
    ) -> ProtoResult<(ServerStageResponsePacket, ServerEvalState)> {
        crate::protocol::invariants::validate_output_projection_request_packet(state, request)?;
        let request_digest =
            crate::protocol::transcript::compute_client_stage_request_digest(request)?;
        let output_release_token =
            crate::protocol::transcript::compute_output_projection_response_token(
                state.handle,
                state.transcript_id,
                request.stage_id,
                request.prior_transcript_digest,
                request_digest,
            );
        let crate::wire::ClientStagePayload::OutputProjection(payload) =
            &request.client_stage_payload
        else {
            return Err(crate::shared::ProtoError::InvalidInput(
                "client stage request payload must be output-projection".to_string(),
            ));
        };
        let projection_mode = payload.projection_mode.clone();
        let allowed_output_kind = Self::allowed_output_kind_for_operation(state.operation);
        let final_server_digest =
            crate::protocol::transcript::compute_output_projection_response_digest(
                state.context_binding,
                state.handle,
                request.stage_id,
                payload.prior_server_stage_digest,
                output_release_token,
                allowed_output_kind,
                &projection_mode,
            );
        let execution_checkpoint_digest = state
            .current_execution_checkpoint_digest()
            .unwrap_or(final_server_digest);
        let Some(crate::server::ServerEvalExecutionState::OutputProjection(output_state)) =
            &state.execution_state
        else {
            return Err(crate::shared::ProtoError::InvalidInput(
                "output-projection response requires stored output-projection continuation state"
                    .to_string(),
            ));
        };
        let hidden_eval_program = state.hidden_eval_program.as_ref().ok_or_else(|| {
            crate::shared::ProtoError::InvalidInput(
                "output-projection response requires stored hidden-eval program".to_string(),
            )
        })?;
        let output = materialize_server_output_bundles_from_continuations_with_pool(
            hidden_eval_program,
            self.ddh_garbler.backend(),
            constant_pool,
            &output_state.round_core,
            &output_state.projector_inputs,
        )?;
        let finalize = crate::server::ServerEvalFinalizeState {
            client_input_commitment: output_state.client_input_commitment,
            server_input_commitment: output_state.server_input_commitment,
            output: crate::server::ServerEvalFinalizeOutput::from_server_output_bundles(&output),
        };
        let response = ServerStageResponsePacket {
            context_binding: state.context_binding,
            server_eval_handle: state.handle,
            stage_id: request.stage_id,
            next_transcript_digest: final_server_digest,
            server_stage_payload: ServerStagePayload::OutputProjection(
                OutputProjectionResponsePayload {
                    final_server_digest,
                    output_release_token,
                    allowed_output_kind,
                    projection_mode: projection_mode.clone(),
                    execution_checkpoint_digest,
                },
            ),
            server_stage_commitments: ServerStageCommitments {
                digests: vec![
                    final_server_digest,
                    output_release_token,
                    execution_checkpoint_digest,
                    crate::protocol::transcript::digest_output_projection_mode(&projection_mode),
                ],
            },
        };
        crate::protocol::invariants::validate_output_projection_response_packet(
            state, request, &response,
        )?;
        Ok((
            response,
            state.advance_after_output_projection(final_server_digest, request_digest, finalize),
        ))
    }

    pub fn prepare_output_projection_response_message(
        &self,
        state: &ServerEvalState,
        client_stage_request_message: &WireMessage,
    ) -> ProtoResult<(WireMessage, ServerEvalState)> {
        let constant_pool = self.hidden_eval_constant_pool()?;
        self.prepare_output_projection_response_message_with_pool(
            state,
            client_stage_request_message,
            &constant_pool,
        )
    }

    pub fn prepare_output_projection_response_message_with_pool(
        &self,
        state: &ServerEvalState,
        client_stage_request_message: &WireMessage,
        constant_pool: &DdhHiddenEvalConstantPool,
    ) -> ProtoResult<(WireMessage, ServerEvalState)> {
        let request: ClientStageRequestPacket = crate::wire::decode_transport_message(
            self.context_binding,
            TransportKind::ClientStageRequest,
            client_stage_request_message,
        )?;
        let (response, next_state) =
            self.prepare_output_projection_response_with_pool(state, &request, constant_pool)?;
        let message = crate::wire::encode_transport_message(
            self.context_binding,
            TransportKind::ServerStageResponse,
            &response,
        )?;
        Ok((message, next_state))
    }

    #[cfg(test)]
    fn prepare_server_packet(
        &self,
        client_packet: &ClientPacket,
        y_server: [u8; 32],
        tau_server: [u8; 32],
    ) -> ProtoResult<ServerPacket> {
        Ok(self
            .prepare_server_packet_with_trusted_inputs(client_packet, y_server, tau_server)?
            .0)
    }

    pub(crate) fn validate_garbler_ot_state(&self) -> ProtoResult<()> {
        if self.client_ot_offer.backend_version != self.ddh_garbler.evaluation_key().backend_version
        {
            return Err(crate::shared::ProtoError::InvalidInput(
                "client OT offer backend version does not match garbler session".to_string(),
            ));
        }
        if self.garbler_ot_state.backend_version
            != self.ddh_garbler.evaluation_key().backend_version
        {
            return Err(crate::shared::ProtoError::InvalidInput(
                "garbler OT state backend version does not match garbler session".to_string(),
            ));
        }
        if self.garbler_ot_state.context_binding != self.context_binding {
            return Err(crate::shared::ProtoError::InvalidInput(
                "garbler OT state context binding does not match garbler session".to_string(),
            ));
        }
        self.ddh_garbler.validate_client_input_ot_bundle_offer(
            &self.client_ot_offer.y_client_offer,
            &self.garbler_ot_state.y_client_sender_state,
            &self.garbler_ot_state.y_client_remote,
        )?;
        self.ddh_garbler.validate_client_input_ot_bundle_offer(
            &self.client_ot_offer.tau_client_offer,
            &self.garbler_ot_state.tau_client_sender_state,
            &self.garbler_ot_state.tau_client_remote,
        )?;
        Ok(())
    }

    fn prepare_trusted_server_eval_timed(
        &self,
        client_packet: &ClientPacket,
        y_server: [u8; 32],
        tau_server: [u8; 32],
    ) -> ProtoResult<(SameProcessTrustedEvalMaterial, EvaluateTiming)> {
        crate::protocol::invariants::validate_client_packet_context(
            self.context_binding,
            self.ddh_garbler.evaluation_key().backend_version,
            client_packet,
        )?;
        let mut timing = EvaluateTiming::default();
        let ot_open_join_started = monotonic_now_ns();
        let (y_client_response, y_client_remote_release) = self
            .ddh_garbler
            .resolve_client_input_ot_selection_trusted_prepared(
                self.context_binding,
                &self.client_ot_offer.y_client_offer,
                &self.y_client_sender_words_prepared,
                &self.garbler_ot_state.y_client_remote,
                &client_packet.y_client_request,
            )?;
        let (tau_client_response, tau_client_remote_release) = self
            .ddh_garbler
            .resolve_client_input_ot_selection_trusted_prepared(
                self.context_binding,
                &self.client_ot_offer.tau_client_offer,
                &self.tau_client_sender_words_prepared,
                &self.garbler_ot_state.tau_client_remote,
                &client_packet.tau_client_request,
            )?;
        timing.ot_open_join_duration_ns = elapsed_ns_u64(ot_open_join_started);
        let server_input_phase_started = monotonic_now_ns();
        let server_input_share_started = monotonic_now_ns();
        let y_server_bundle = self
            .ddh_garbler
            .share_server_input_bit_bundle("y_server_bits", &y_server)?;
        let tau_server_bundle = self
            .ddh_garbler
            .share_server_input_bit_bundle("tau_server_bits", &tau_server)?;
        timing.server_input_share_duration_ns = elapsed_ns_u64(server_input_share_started);
        let server_input_commitment_started = monotonic_now_ns();
        let server_input_commitment = self.ddh_garbler.combined_input_commitment(
            crate::ddh::HiddenEvalInputOwner::Server,
            &[&y_server_bundle, &tau_server_bundle],
        );
        timing.server_input_commitment_duration_ns =
            elapsed_ns_u64(server_input_commitment_started);
        let trusted_server_inputs =
            crate::ddh::hidden_eval_executor::DdhHiddenEvalServerInputs::from_joint_bundles(
                &y_server_bundle,
                &tau_server_bundle,
            );
        let ot_transcript_started = monotonic_now_ns();
        let _ = crate::protocol::transcript::build_ot_transcript(
            self.context_binding,
            &self.client_ot_offer,
            client_packet,
            &y_client_response,
            &tau_client_response,
            &y_client_remote_release,
            &tau_client_remote_release,
        );
        timing.server_input_transcript_duration_ns = elapsed_ns_u64(ot_transcript_started);
        timing.server_input_open_duration_ns = elapsed_ns_u64(server_input_phase_started);
        Ok((
            SameProcessTrustedEvalMaterial {
                y_client_response,
                tau_client_response,
                y_client_remote_release,
                tau_client_remote_release,
                server_input_commitment,
                trusted_server_inputs,
            },
            timing,
        ))
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn evaluate_hidden_run_same_process_timed(
        &self,
        evaluator_session: &crate::client::ClientSession,
        hidden_eval_program: &HiddenEvalProgram,
        hidden_eval_constants: &DdhHiddenEvalConstantPool,
        evaluator_ot_state: &crate::client::ClientOtState,
        client_packet: &ClientPacket,
        y_server: [u8; 32],
        tau_server: [u8; 32],
    ) -> ProtoResult<(DdhHiddenEvalRun, EvaluateTiming)> {
        let (run, _execution_checkpoints, timing) = self
            .evaluate_hidden_run_same_process_with_execution_checkpoints_timed(
                evaluator_session,
                hidden_eval_program,
                hidden_eval_constants,
                evaluator_ot_state,
                client_packet,
                y_server,
                tau_server,
            )?;
        Ok((run, timing))
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn evaluate_hidden_run_same_process_with_execution_checkpoints_timed(
        &self,
        evaluator_session: &crate::client::ClientSession,
        hidden_eval_program: &HiddenEvalProgram,
        hidden_eval_constants: &DdhHiddenEvalConstantPool,
        evaluator_ot_state: &crate::client::ClientOtState,
        client_packet: &ClientPacket,
        y_server: [u8; 32],
        tau_server: [u8; 32],
    ) -> ProtoResult<(
        DdhHiddenEvalRun,
        SameProcessExecutionCheckpoints,
        EvaluateTiming,
    )> {
        let (trusted_server_eval, mut timing) =
            self.prepare_trusted_server_eval_timed(client_packet, y_server, tau_server)?;
        let ot_open_join_started = monotonic_now_ns();
        let (y_client_bundle, y_timing) = evaluator_session
            .ddh_evaluator
            .reconstruct_client_ot_bundle_timed_trusted(
                evaluator_session.context_binding,
                &trusted_server_eval.y_client_response,
                &evaluator_ot_state.y_client_local_state,
                &trusted_server_eval.y_client_remote_release,
            )?;
        let (tau_client_bundle, tau_timing) = evaluator_session
            .ddh_evaluator
            .reconstruct_client_ot_bundle_timed_trusted(
                evaluator_session.context_binding,
                &trusted_server_eval.tau_client_response,
                &evaluator_ot_state.tau_client_local_state,
                &trusted_server_eval.tau_client_remote_release,
            )?;
        timing.ot_open_join_duration_ns = timing
            .ot_open_join_duration_ns
            .saturating_add(elapsed_ns_u64(ot_open_join_started));
        timing.add_ot_reconstruct_timing(y_timing);
        timing.add_ot_reconstruct_timing(tau_timing);
        let expected_client_input_commitment =
            evaluator_session.ddh_evaluator.combined_input_commitment(
                crate::ddh::HiddenEvalInputOwner::Client,
                &[&y_client_bundle, &tau_client_bundle],
            );
        let trace = trace_prime_order_ddh_hidden_eval_program_with_split_server_inputs_with_pool(
            hidden_eval_program,
            &evaluator_session.ddh_evaluator,
            hidden_eval_constants,
            &y_client_bundle,
            &trusted_server_eval.trusted_server_inputs.y_server_bits,
            &tau_client_bundle,
            &trusted_server_eval.trusted_server_inputs.tau_server_bits,
        )?;
        if trace.run.client_input_commitment != expected_client_input_commitment {
            return Err(crate::shared::ProtoError::InvalidInput(
                "client delivery packet commitment does not match evaluated run".to_string(),
            ));
        }
        if trace.run.server_input_commitment != trusted_server_eval.server_input_commitment {
            return Err(crate::shared::ProtoError::InvalidInput(
                "server delivery packet commitment does not match evaluated run".to_string(),
            ));
        }
        Ok((
            trace.run,
            SameProcessExecutionCheckpoints {
                add_stage_digest: trace.checkpoint_digests.add_stage,
                message_schedule_digest: trace.checkpoint_digests.message_schedule,
                round_core_digest: trace.checkpoint_digests.round_core,
                output_projection_digest: trace.checkpoint_digests.output_projection,
            },
            timing,
        ))
    }

    pub fn prepare_server_assist_init(
        &self,
        client_packet: &ClientPacket,
        y_server: [u8; 32],
        tau_server: [u8; 32],
        operation: ServerEvalOperation,
    ) -> ProtoResult<(ServerAssistInitPacket, ServerEvalState)> {
        let (packet, state, _timing) =
            self.prepare_server_assist_init_timed(client_packet, y_server, tau_server, operation)?;
        Ok((packet, state))
    }

    pub fn prepare_role_separated_server_input_delivery(
        &self,
        client_packet: &ClientPacket,
        y_server: [u8; 32],
        tau_server: [u8; 32],
        operation: ServerEvalOperation,
    ) -> ProtoResult<(RoleSeparatedServerInputDeliveryPacket, ServerEvalState)> {
        let (delivery, state, _timing) = self.prepare_role_separated_server_input_delivery_timed(
            client_packet,
            y_server,
            tau_server,
            operation,
        )?;
        Ok((delivery, state))
    }

    pub fn prepare_role_separated_server_input_delivery_timed(
        &self,
        client_packet: &ClientPacket,
        y_server: [u8; 32],
        tau_server: [u8; 32],
        operation: ServerEvalOperation,
    ) -> ProtoResult<(
        RoleSeparatedServerInputDeliveryPacket,
        ServerEvalState,
        EvaluateTiming,
    )> {
        let mut material = self.prepare_server_assist_init_material_timed(
            client_packet,
            y_server,
            tau_server,
            operation,
        )?;
        let y_server_split = self
            .ddh_garbler
            .split_share_bundle(&material.y_server_bundle);
        let tau_server_split = self
            .ddh_garbler
            .split_share_bundle(&material.tau_server_bundle);
        let state_server_inputs = DdhHiddenEvalServerInputs::from_joint_bundles(
            &material.y_server_bundle,
            &material.tau_server_bundle,
        );
        let server_input_seal_started = monotonic_now_ns();
        let server_inputs = self.seal_role_separated_server_inputs_packet(
            material.packet.server_input_commitment,
            &y_server_split,
            &tau_server_split,
        )?;
        material.timing.server_input_seal_duration_ns = elapsed_ns_u64(server_input_seal_started);
        Ok((
            RoleSeparatedServerInputDeliveryPacket {
                context_binding: material.packet.context_binding,
                server_eval_handle: material.packet.server_eval_handle,
                transcript_id: material.packet.transcript_id,
                server_input_commitment: material.packet.server_input_commitment,
                y_client_response: material.packet.y_client_response,
                tau_client_response: material.packet.tau_client_response,
                y_client_remote_release: material.packet.y_client_remote_release,
                tau_client_remote_release: material.packet.tau_client_remote_release,
                server_inputs,
            },
            material
                .state
                .with_role_separated_server_input_bundles(state_server_inputs),
            material.timing,
        ))
    }

    pub fn prepare_role_separated_server_input_delivery_message(
        &self,
        client_request_message: &WireMessage,
        y_server: [u8; 32],
        tau_server: [u8; 32],
        operation: ServerEvalOperation,
    ) -> ProtoResult<(RoleSeparatedServerInputDeliveryPacket, ServerEvalState)> {
        let (delivery, state, _timing) = self
            .prepare_role_separated_server_input_delivery_message_timed(
                client_request_message,
                y_server,
                tau_server,
                operation,
            )?;
        Ok((delivery, state))
    }

    pub fn prepare_role_separated_server_input_delivery_message_timed(
        &self,
        client_request_message: &WireMessage,
        y_server: [u8; 32],
        tau_server: [u8; 32],
        operation: ServerEvalOperation,
    ) -> ProtoResult<(
        RoleSeparatedServerInputDeliveryPacket,
        ServerEvalState,
        EvaluateTiming,
    )> {
        let client_packet: ClientPacket = crate::wire::decode_transport_message(
            self.context_binding,
            TransportKind::ClientOtRequest,
            client_request_message,
        )?;
        self.prepare_role_separated_server_input_delivery_timed(
            &client_packet,
            y_server,
            tau_server,
            operation,
        )
    }

    pub fn prepare_server_assist_init_timed(
        &self,
        client_packet: &ClientPacket,
        y_server: [u8; 32],
        tau_server: [u8; 32],
        operation: ServerEvalOperation,
    ) -> ProtoResult<(ServerAssistInitPacket, ServerEvalState, EvaluateTiming)> {
        let material = self.prepare_server_assist_init_material_timed(
            client_packet,
            y_server,
            tau_server,
            operation,
        )?;
        Ok((material.packet, material.state, material.timing))
    }

    fn prepare_server_assist_init_material_timed(
        &self,
        client_packet: &ClientPacket,
        y_server: [u8; 32],
        tau_server: [u8; 32],
        operation: ServerEvalOperation,
    ) -> ProtoResult<ServerAssistInitMaterial> {
        crate::protocol::invariants::validate_client_packet_context(
            self.context_binding,
            self.ddh_garbler.evaluation_key().backend_version,
            client_packet,
        )?;
        let mut timing = EvaluateTiming::default();
        let ot_open_join_started = monotonic_now_ns();
        let (y_client_response, y_client_remote_release) = self
            .ddh_garbler
            .resolve_client_input_ot_selection_trusted_prepared(
                self.context_binding,
                &self.client_ot_offer.y_client_offer,
                &self.y_client_sender_words_prepared,
                &self.garbler_ot_state.y_client_remote,
                &client_packet.y_client_request,
            )?;
        let (tau_client_response, tau_client_remote_release) = self
            .ddh_garbler
            .resolve_client_input_ot_selection_trusted_prepared(
                self.context_binding,
                &self.client_ot_offer.tau_client_offer,
                &self.tau_client_sender_words_prepared,
                &self.garbler_ot_state.tau_client_remote,
                &client_packet.tau_client_request,
            )?;
        timing.ot_open_join_duration_ns = elapsed_ns_u64(ot_open_join_started);

        let server_input_phase_started = monotonic_now_ns();
        let server_input_share_started = monotonic_now_ns();
        let y_server_bundle = self
            .ddh_garbler
            .share_server_input_bit_bundle("y_server_bits", &y_server)?;
        let tau_server_bundle = self
            .ddh_garbler
            .share_server_input_bit_bundle("tau_server_bits", &tau_server)?;
        timing.server_input_share_duration_ns = elapsed_ns_u64(server_input_share_started);

        let server_input_commitment_started = monotonic_now_ns();
        let server_input_commitment = self.ddh_garbler.combined_input_commitment(
            crate::ddh::HiddenEvalInputOwner::Server,
            &[&y_server_bundle, &tau_server_bundle],
        );
        timing.server_input_commitment_duration_ns =
            elapsed_ns_u64(server_input_commitment_started);

        let ot_transcript_started = monotonic_now_ns();
        let ot_transcript = crate::protocol::transcript::build_ot_transcript(
            self.context_binding,
            &self.client_ot_offer,
            client_packet,
            &y_client_response,
            &tau_client_response,
            &y_client_remote_release,
            &tau_client_remote_release,
        );
        timing.server_input_transcript_duration_ns = elapsed_ns_u64(ot_transcript_started);

        let server_eval_handle = self.new_server_eval_handle();
        let transcript_id = crate::protocol::transcript::derive_server_assist_transcript_id(
            self.context_binding,
            &ot_transcript,
            server_input_commitment,
        );
        let current_transcript_digest = crate::protocol::transcript::derive_server_stage_digest(
            self.context_binding,
            server_eval_handle,
            transcript_id,
            crate::wire::ServerEvalStageId::add_stage(),
            server_input_commitment,
            &ot_transcript,
        );
        timing.server_input_open_duration_ns = elapsed_ns_u64(server_input_phase_started);

        let packet = ServerAssistInitPacket {
            context_binding: self.context_binding,
            server_eval_handle,
            transcript_id,
            server_input_commitment,
            y_client_response,
            tau_client_response,
            y_client_remote_release,
            tau_client_remote_release,
        };
        let state = ServerEvalState::new(
            server_eval_handle,
            self.context_binding,
            transcript_id,
            current_transcript_digest,
            operation,
            server_input_commitment,
            ot_transcript,
            ServerEvalServerRoots {
                y_server,
                tau_server,
            },
        );

        Ok(ServerAssistInitMaterial {
            packet,
            state,
            y_server_bundle,
            tau_server_bundle,
            timing,
        })
    }

    #[cfg(test)]
    fn prepare_server_packet_with_trusted_inputs_timed(
        &self,
        client_packet: &ClientPacket,
        y_server: [u8; 32],
        tau_server: [u8; 32],
    ) -> ProtoResult<(
        ServerPacket,
        crate::ddh::hidden_eval_executor::DdhHiddenEvalServerInputs,
        EvaluateTiming,
    )> {
        crate::protocol::invariants::validate_client_packet_context(
            self.context_binding,
            self.ddh_garbler.evaluation_key().backend_version,
            client_packet,
        )?;
        let mut timing = EvaluateTiming::default();
        let ot_open_join_started = monotonic_now_ns();
        let (y_client_response, y_client_remote_release) = self
            .ddh_garbler
            .resolve_client_input_ot_selection_trusted_prepared(
                self.context_binding,
                &self.client_ot_offer.y_client_offer,
                &self.y_client_sender_words_prepared,
                &self.garbler_ot_state.y_client_remote,
                &client_packet.y_client_request,
            )?;
        let (tau_client_response, tau_client_remote_release) = self
            .ddh_garbler
            .resolve_client_input_ot_selection_trusted_prepared(
                self.context_binding,
                &self.client_ot_offer.tau_client_offer,
                &self.tau_client_sender_words_prepared,
                &self.garbler_ot_state.tau_client_remote,
                &client_packet.tau_client_request,
            )?;
        timing.ot_open_join_duration_ns = elapsed_ns_u64(ot_open_join_started);
        let server_input_open_started = monotonic_now_ns();
        let server_input_share_started = monotonic_now_ns();
        let y_server_bundle = self
            .ddh_garbler
            .share_server_input_bit_bundle("y_server_bits", &y_server)?;
        let tau_server_bundle = self
            .ddh_garbler
            .share_server_input_bit_bundle("tau_server_bits", &tau_server)?;
        timing.server_input_share_duration_ns = elapsed_ns_u64(server_input_share_started);
        let server_input_commitment_started = monotonic_now_ns();
        let server_input_commitment = self.ddh_garbler.combined_input_commitment(
            crate::ddh::HiddenEvalInputOwner::Server,
            &[&y_server_bundle, &tau_server_bundle],
        );
        timing.server_input_commitment_duration_ns =
            elapsed_ns_u64(server_input_commitment_started);
        let trusted_server_inputs =
            crate::ddh::hidden_eval_executor::DdhHiddenEvalServerInputs::from_joint_bundles(
                &y_server_bundle,
                &tau_server_bundle,
            );
        let ot_transcript_started = monotonic_now_ns();
        let ot_transcript = crate::protocol::transcript::build_ot_transcript(
            self.context_binding,
            &self.client_ot_offer,
            client_packet,
            &y_client_response,
            &tau_client_response,
            &y_client_remote_release,
            &tau_client_remote_release,
        );
        timing.server_input_transcript_duration_ns = elapsed_ns_u64(ot_transcript_started);
        let y_server_split = self.ddh_garbler.split_share_bundle(&y_server_bundle);
        let tau_server_split = self.ddh_garbler.split_share_bundle(&tau_server_bundle);
        let server_input_seal_started = monotonic_now_ns();
        let sealed_server_inputs = self.seal_server_inputs_packet(
            server_input_commitment,
            &y_server_split,
            &tau_server_split,
        )?;
        timing.server_input_seal_duration_ns = elapsed_ns_u64(server_input_seal_started);
        timing.server_input_open_duration_ns = elapsed_ns_u64(server_input_open_started);
        Ok((
            ServerPacket {
                context_binding: self.context_binding,
                ot_transcript,
                y_client_response,
                tau_client_response,
                y_client_remote_release,
                tau_client_remote_release,
                server_inputs: sealed_server_inputs,
            },
            trusted_server_inputs,
            timing,
        ))
    }

    #[cfg(test)]
    fn prepare_server_packet_with_trusted_inputs(
        &self,
        client_packet: &ClientPacket,
        y_server: [u8; 32],
        tau_server: [u8; 32],
    ) -> ProtoResult<(
        ServerPacket,
        crate::ddh::hidden_eval_executor::DdhHiddenEvalServerInputs,
    )> {
        let (server_packet, trusted_server_inputs, _timing) = self
            .prepare_server_packet_with_trusted_inputs_timed(client_packet, y_server, tau_server)?;
        Ok((server_packet, trusted_server_inputs))
    }

    pub fn prepare_server_finalize_packet_from_staged_evaluator_artifact(
        &self,
        runtime: &SharedRuntime,
        server_eval_state: &ServerEvalState,
        artifact: &StagedEvaluatorArtifact,
    ) -> ProtoResult<(ServerFinalizePacket, EvaluationReport)> {
        if server_eval_state.status != crate::server::ServerEvalStatus::Finalized {
            return Err(crate::shared::ProtoError::InvalidInput(
                "server finalize requires a finalized server eval state".to_string(),
            ));
        }
        let finalize_state = server_eval_state.finalize_state().ok_or_else(|| {
            crate::shared::ProtoError::InvalidInput(
                "server finalize requires stored finalize state".to_string(),
            )
        })?;
        if artifact.bindings.client_input_commitment != finalize_state.client_input_commitment {
            return Err(crate::shared::ProtoError::InvalidInput(
                "staged evaluator artifact client input commitment does not match finalize state"
                    .to_string(),
            ));
        }
        if artifact.bindings.server_input_commitment != finalize_state.server_input_commitment {
            return Err(crate::shared::ProtoError::InvalidInput(
                "staged evaluator artifact server input commitment does not match finalize state"
                    .to_string(),
            ));
        }
        let expected_run_binding = self.run_binding(
            runtime.artifact.artifact_digest,
            finalize_state.client_input_commitment,
            finalize_state.server_input_commitment,
        );
        if artifact.bindings.run_binding != expected_run_binding {
            return Err(crate::shared::ProtoError::InvalidInput(
                "staged evaluator artifact run binding does not match finalize state".to_string(),
            ));
        }
        let expected_client_output_value_kind =
            crate::wire::ClientOutputValueKind::for_projection_mode(&artifact.projection_mode);
        if artifact.client_output_value_kind != expected_client_output_value_kind {
            return Err(crate::shared::ProtoError::InvalidInput(
                "staged evaluator artifact client output value kind does not match projection mode"
                    .to_string(),
            ));
        }
        let expected_evaluation_digest =
            crate::protocol::transcript::compute_evaluation_digest_from_output_commitments(
                runtime.artifact.artifact_digest,
                expected_run_binding,
                &runtime.execution_result,
                finalize_state.output.canonical_seed_commitment,
                artifact.client_output_value_kind,
                artifact.client_output_commitment,
                crate::protocol::transcript::server_output_value_commitment(
                    &finalize_state.output.x_server_base_left,
                    &finalize_state.output.x_server_base_right,
                )?,
                artifact.output_projector_binding,
            );
        if artifact.bindings.evaluation_digest != expected_evaluation_digest {
            return Err(crate::shared::ProtoError::InvalidInput(
                "staged evaluator artifact evaluation digest does not match finalize state"
                    .to_string(),
            ));
        }
        let report = runtime.finalize_report_from_staged_evaluator_artifact(
            self,
            artifact,
            &finalize_state.output,
        )?;
        let allowed_output_kind =
            Self::allowed_output_kind_for_operation(server_eval_state.operation);
        let seed_output = match allowed_output_kind {
            crate::wire::AllowedOutputKind::ClientOutputOnly => None,
            crate::wire::AllowedOutputKind::ClientOutputAndSeedOutput => {
                Some(report.output_delivery.seed.clone())
            }
        };
        Ok((
            ServerFinalizePacket {
                context_binding: self.context_binding,
                server_eval_handle: server_eval_state.handle,
                final_transcript_digest: server_eval_state.current_transcript_digest,
                allowed_output_kind,
                projection_mode: artifact.projection_mode.clone(),
                client_output: report.output_delivery.client.clone(),
                seed_output,
            },
            report,
        ))
    }

    pub fn prepare_server_finalize_message_from_staged_evaluator_artifact(
        &self,
        runtime: &SharedRuntime,
        server_eval_state: &ServerEvalState,
        artifact: &StagedEvaluatorArtifact,
    ) -> ProtoResult<(WireMessage, EvaluationReport)> {
        let (packet, report) = self.prepare_server_finalize_packet_from_staged_evaluator_artifact(
            runtime,
            server_eval_state,
            artifact,
        )?;
        let message = crate::wire::encode_transport_message(
            self.context_binding,
            TransportKind::ServerFinalize,
            &packet,
        )?;
        Ok((message, report))
    }

    pub fn seal_server_output_packet_message(
        &self,
        run_binding: [u8; 32],
        evaluation_digest: [u8; 32],
        left: &DdhHssTransportBundle,
        right: &DdhHssTransportBundle,
    ) -> ProtoResult<WireMessage> {
        let plaintext =
            crate::wire::serialize_transport_pair_payload("server_output_bundle", left, right)?;
        let aad = crate::protocol::transcript::output_packet_aad(
            b"server_output",
            self.context_binding,
            run_binding,
            evaluation_digest,
        );
        let (nonce, ciphertext) = self.ddh_garbler.seal_message(
            DdhHssTransportPurpose::ServerOutput,
            &aad,
            &plaintext,
        )?;
        let packet = ServerOutputPacket {
            context_binding: self.context_binding,
            run_binding,
            evaluation_digest,
            nonce,
            ciphertext,
        };
        crate::wire::encode_transport_message(
            self.context_binding,
            TransportKind::ServerOutput,
            &packet,
        )
    }

    pub(crate) fn seal_role_separated_server_inputs_packet(
        &self,
        server_input_commitment: [u8; 32],
        y_server: &(DdhHssTransportBundle, DdhHssTransportBundle),
        tau_server: &(DdhHssTransportBundle, DdhHssTransportBundle),
    ) -> ProtoResult<RoleSeparatedServerInputsPacket> {
        let aad = crate::protocol::transcript::server_input_packet_aad(
            self.context_binding,
            server_input_commitment,
        );
        let plaintext = crate::wire::serialize_server_inputs_payload(y_server, tau_server)?;
        let (nonce, ciphertext) =
            self.ddh_garbler
                .seal_message(DdhHssTransportPurpose::ServerInput, &aad, &plaintext)?;
        Ok(RoleSeparatedServerInputsPacket {
            context_binding: self.context_binding,
            server_input_commitment,
            nonce,
            ciphertext,
        })
    }

    #[cfg(test)]
    pub(crate) fn seal_server_inputs_packet(
        &self,
        server_input_commitment: [u8; 32],
        y_server: &(DdhHssTransportBundle, DdhHssTransportBundle),
        tau_server: &(DdhHssTransportBundle, DdhHssTransportBundle),
    ) -> ProtoResult<crate::wire::ServerInputsPacket> {
        let aad = crate::protocol::transcript::server_input_packet_aad(
            self.context_binding,
            server_input_commitment,
        );
        let plaintext = crate::wire::serialize_server_inputs_payload(y_server, tau_server)?;
        let (nonce, ciphertext) =
            self.ddh_garbler
                .seal_message(DdhHssTransportPurpose::ServerInput, &aad, &plaintext)?;
        Ok(crate::wire::ServerInputsPacket {
            context_binding: self.context_binding,
            server_input_commitment,
            nonce,
            ciphertext,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ddh::ddh_hss::{DdhHssShareSide, DdhHssTransportBundle};
    use crate::fixtures::deterministic_fixture_corpus;

    fn boundary_fixture() -> crate::fixtures::FExpandFixture {
        deterministic_fixture_corpus()
            .expect("fixture corpus")
            .into_iter()
            .find(|fixture| {
                let has_entropy = |bytes: &[u8; 32]| {
                    let distinct = bytes
                        .iter()
                        .copied()
                        .collect::<std::collections::BTreeSet<_>>();
                    distinct.len() >= 8
                };
                has_entropy(&fixture.input.y_client)
                    && has_entropy(&fixture.input.tau_client)
                    && has_entropy(&fixture.input.y_server)
                    && has_entropy(&fixture.input.tau_server)
            })
            .expect("non-degenerate boundary fixture")
    }

    fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }

    fn serialized_size<T: serde::Serialize>(value: &T) -> u64 {
        bincode::serialized_size(value).expect("serialized size")
    }

    fn decode_trusted_server_input_bundle(
        session: &ServerSession,
        bundle: &crate::ddh::hidden_eval_executor::DdhHiddenEvalServerInputBundle,
    ) -> crate::shared::ProtoResult<[u8; 32]> {
        let left = DdhHssTransportBundle {
            owner: bundle.owner,
            label: bundle.label.clone(),
            share_side: DdhHssShareSide::Left,
            words: bundle.left_words.clone(),
            commitment: bundle.commitment,
        };
        let right = DdhHssTransportBundle {
            owner: bundle.owner,
            label: bundle.label.clone(),
            share_side: DdhHssShareSide::Right,
            words: bundle.right_words.clone(),
            commitment: bundle.commitment,
        };
        let joined = session.ddh_garbler.join_share_bundle(&left, &right)?;
        session.ddh_garbler.decode_server_bit_bundle_array(&joined)
    }

    #[test]
    fn current_trusted_server_eval_contains_reconstructable_server_roots() {
        let fixture = boundary_fixture();
        let session = crate::protocol::prepare_prime_order_succinct_hss(&fixture.input.context)
            .expect("prepare session");
        let (_runtime, garbler_session, evaluator_session) = session.split_runtime();

        let client_ot_offer_message = garbler_session
            .client_ot_offer_message()
            .expect("prepare client OT offer");
        let (client_request_message, _evaluator_ot_state) = evaluator_session
            .prepare_client_ot_request_from_offer_message(
                &client_ot_offer_message,
                fixture.input.y_client,
                fixture.input.tau_client,
            )
            .expect("prepare client request");
        let client_packet: crate::wire::ClientPacket = crate::wire::decode_transport_message(
            session.candidate().context_binding,
            crate::wire::TransportKind::ClientOtRequest,
            &client_request_message,
        )
        .expect("decode client packet");

        let (trusted_server_eval, _timing) = garbler_session
            .prepare_trusted_server_eval_timed(
                &client_packet,
                fixture.input.y_server,
                fixture.input.tau_server,
            )
            .expect("prepare trusted server eval");

        let decoded_y_server = decode_trusted_server_input_bundle(
            &garbler_session,
            &trusted_server_eval.trusted_server_inputs.y_server_bits,
        )
        .expect("decode reconstructable y_server from trusted server eval");
        let decoded_tau_server = decode_trusted_server_input_bundle(
            &garbler_session,
            &trusted_server_eval.trusted_server_inputs.tau_server_bits,
        )
        .expect("decode reconstructable tau_server from trusted server eval");

        assert_eq!(
            decoded_y_server, fixture.input.y_server,
            "current production TrustedServerEval leaks reconstructable y_server",
        );
        assert_eq!(
            decoded_tau_server, fixture.input.tau_server,
            "current production TrustedServerEval leaks reconstructable tau_server",
        );
    }

    #[test]
    fn current_server_packet_contains_reconstructable_server_roots() {
        let fixture = boundary_fixture();
        let session = crate::protocol::prepare_prime_order_succinct_hss(&fixture.input.context)
            .expect("prepare session");
        let (_runtime, garbler_session, evaluator_session) = session.split_runtime();

        let client_ot_offer_message = garbler_session
            .client_ot_offer_message()
            .expect("prepare client OT offer");
        let (client_request_message, _evaluator_ot_state) = evaluator_session
            .prepare_client_ot_request_from_offer_message(
                &client_ot_offer_message,
                fixture.input.y_client,
                fixture.input.tau_client,
            )
            .expect("prepare client request");
        let server_message = garbler_session
            .prepare_server_message(
                &client_request_message,
                fixture.input.y_server,
                fixture.input.tau_server,
            )
            .expect("prepare server message");
        let server_packet: crate::wire::ServerPacket = crate::wire::decode_transport_message(
            session.candidate().context_binding,
            crate::wire::TransportKind::ServerPacket,
            &server_message,
        )
        .expect("decode server packet");
        let decoded_payload = {
            let aad = crate::protocol::transcript::server_input_packet_aad(
                server_packet.server_inputs.context_binding,
                server_packet.server_inputs.server_input_commitment,
            );
            let plaintext = garbler_session
                .ddh_garbler
                .open_message(
                    DdhHssTransportPurpose::ServerInput,
                    &aad,
                    server_packet.server_inputs.nonce,
                    &server_packet.server_inputs.ciphertext,
                )
                .expect("open server inputs packet");
            crate::wire::deserialize_server_inputs_payload(&plaintext)
                .expect("decode server input payload")
        };

        let decoded_y_server = garbler_session
            .ddh_garbler
            .decode_server_bit_bundle_array(
                &garbler_session
                    .ddh_garbler
                    .join_share_bundle(
                        &decoded_payload.y_server_left,
                        &decoded_payload.y_server_right,
                    )
                    .expect("join y_server bundle"),
            )
            .expect("decode reconstructable y_server");
        let decoded_tau_server = garbler_session
            .ddh_garbler
            .decode_server_bit_bundle_array(
                &garbler_session
                    .ddh_garbler
                    .join_share_bundle(
                        &decoded_payload.tau_server_left,
                        &decoded_payload.tau_server_right,
                    )
                    .expect("join tau_server bundle"),
            )
            .expect("decode reconstructable tau_server");

        assert_eq!(
            decoded_y_server, fixture.input.y_server,
            "current production server packet leaks reconstructable y_server",
        );
        assert_eq!(
            decoded_tau_server, fixture.input.tau_server,
            "current production server packet leaks reconstructable tau_server",
        );
    }

    #[test]
    fn prepare_server_assist_init_keeps_server_roots_in_server_state() {
        let fixture = boundary_fixture();
        let session = crate::protocol::prepare_prime_order_succinct_hss(&fixture.input.context)
            .expect("prepare session");
        let (_runtime, garbler_session, evaluator_session) = session.split_runtime();

        let client_ot_offer_message = garbler_session
            .client_ot_offer_message()
            .expect("prepare client OT offer");
        let (client_request_message, _evaluator_ot_state) = evaluator_session
            .prepare_client_ot_request_from_offer_message(
                &client_ot_offer_message,
                fixture.input.y_client,
                fixture.input.tau_client,
            )
            .expect("prepare client request");
        let client_packet: crate::wire::ClientPacket = crate::wire::decode_transport_message(
            session.candidate().context_binding,
            crate::wire::TransportKind::ClientOtRequest,
            &client_request_message,
        )
        .expect("decode client packet");

        let (packet, state, _timing) = garbler_session
            .prepare_server_assist_init_timed(
                &client_packet,
                fixture.input.y_server,
                fixture.input.tau_server,
                ServerEvalOperation::Registration,
            )
            .expect("prepare server assist init");

        assert_eq!(state.context_binding, session.candidate().context_binding);
        assert_eq!(state.handle, packet.server_eval_handle);
        assert_eq!(state.transcript_id, packet.transcript_id);
        assert_eq!(
            state.server_input_commitment,
            packet.server_input_commitment
        );
        assert_eq!(
            state.current_stage,
            crate::wire::ServerEvalStageId::add_stage()
        );
        assert_eq!(state.operation, ServerEvalOperation::Registration);
        let server_roots = state
            .server_roots()
            .expect("raw server roots on init state");
        assert_eq!(server_roots.y_server, fixture.input.y_server);
        assert_eq!(server_roots.tau_server, fixture.input.tau_server);
        assert_eq!(
            state.ot_transcript.y_client_request_commitment,
            client_packet.y_client_request.commitment,
        );
        assert_eq!(
            state.ot_transcript.tau_client_request_commitment,
            client_packet.tau_client_request.commitment,
        );

        let packet_bytes = bincode::serialize(&packet).expect("serialize server assist init");
        assert!(
            !contains_subslice(&packet_bytes, &fixture.input.y_server),
            "server assist init packet must not embed clear y_server bytes",
        );
        assert!(
            !contains_subslice(&packet_bytes, &fixture.input.tau_server),
            "server assist init packet must not embed clear tau_server bytes",
        );
    }

    #[test]
    fn same_process_hidden_eval_execution_checkpoints_are_deterministic_and_input_bound() {
        let fixture = boundary_fixture();
        let session = crate::protocol::prepare_prime_order_succinct_hss(&fixture.input.context)
            .expect("prepare session");
        let (runtime, garbler_session, evaluator_session) = session.split_runtime();

        let client_ot_offer_message = garbler_session
            .client_ot_offer_message()
            .expect("prepare client OT offer");
        let (client_request_message, evaluator_ot_state) = evaluator_session
            .prepare_client_ot_request_from_offer_message(
                &client_ot_offer_message,
                fixture.input.y_client,
                fixture.input.tau_client,
            )
            .expect("prepare client request");
        let client_packet: crate::wire::ClientPacket = crate::wire::decode_transport_message(
            session.candidate().context_binding,
            crate::wire::TransportKind::ClientOtRequest,
            &client_request_message,
        )
        .expect("decode client packet");
        let hidden_eval_constants = evaluator_session
            .hidden_eval_constant_pool()
            .expect("hidden eval constants");

        let (_run_a, checkpoints_a, _timing_a) = garbler_session
            .evaluate_hidden_run_same_process_with_execution_checkpoints_timed(
                &evaluator_session,
                &runtime.hidden_eval_program,
                &hidden_eval_constants,
                &evaluator_ot_state,
                &client_packet,
                fixture.input.y_server,
                fixture.input.tau_server,
            )
            .expect("same-process hidden eval with checkpoints");
        let (_run_b, checkpoints_b, _timing_b) = garbler_session
            .evaluate_hidden_run_same_process_with_execution_checkpoints_timed(
                &evaluator_session,
                &runtime.hidden_eval_program,
                &hidden_eval_constants,
                &evaluator_ot_state,
                &client_packet,
                fixture.input.y_server,
                fixture.input.tau_server,
            )
            .expect("same-process hidden eval with repeated checkpoints");

        assert_eq!(
            checkpoints_a, checkpoints_b,
            "same-process execution checkpoints must be stable for identical inputs",
        );
        assert_ne!(checkpoints_a.add_stage_digest, [0u8; 32]);
        assert_ne!(checkpoints_a.message_schedule_digest, [0u8; 32]);
        assert_ne!(checkpoints_a.round_core_digest, [0u8; 32]);
        assert_ne!(checkpoints_a.output_projection_digest, [0u8; 32]);

        let mut changed_y_server = fixture.input.y_server;
        changed_y_server[0] ^= 1;
        let (_run_c, checkpoints_c, _timing_c) = garbler_session
            .evaluate_hidden_run_same_process_with_execution_checkpoints_timed(
                &evaluator_session,
                &runtime.hidden_eval_program,
                &hidden_eval_constants,
                &evaluator_ot_state,
                &client_packet,
                changed_y_server,
                fixture.input.tau_server,
            )
            .expect("same-process hidden eval with changed server root");

        assert_ne!(
            checkpoints_a.add_stage_digest, checkpoints_c.add_stage_digest,
            "add-stage checkpoint must change when y_server changes",
        );
        assert_ne!(
            checkpoints_a.output_projection_digest, checkpoints_c.output_projection_digest,
            "output-projection checkpoint must change when server-owned execution input changes",
        );
    }

    #[test]
    fn staged_flow_materializes_stage_local_continuation_and_drops_raw_roots() {
        let fixture = boundary_fixture();
        let session = crate::protocol::prepare_prime_order_succinct_hss(&fixture.input.context)
            .expect("prepare session");
        let garbler_ot_state = session
            .prepare_garbler_ot_state()
            .expect("garbler OT state");
        let client_ot_offer_message = session
            .prepare_client_ot_offer_message()
            .expect("client OT offer message");
        let (client_request_message, evaluator_ot_state) = session
            .prepare_client_ot_request_from_offer_message(
                &client_ot_offer_message,
                fixture.input.y_client,
                fixture.input.tau_client,
            )
            .expect("client request message");
        let flow = session
            .prepare_server_assist_flow_to_output_projection(
                &garbler_ot_state,
                &client_request_message,
                &evaluator_ot_state,
                fixture.input.y_server,
                fixture.input.tau_server,
                crate::server::ServerEvalOperation::Registration,
            )
            .expect("prepare staged flow");

        assert!(
            flow.final_server_eval_state
                .stores_stage_local_continuation(),
            "staged flow should materialize a stage-local continuation",
        );
        assert!(
            !flow.final_server_eval_state.retains_raw_server_roots(),
            "staged flow must not retain raw server roots after add-stage materialization",
        );
    }

    #[test]
    fn client_request_and_ot_state_sizes_are_word_vector_dominated() {
        #[derive(serde::Serialize)]
        struct SelectionPayloadWord {
            receiver_public: [u8; 32],
        }

        #[derive(serde::Serialize)]
        struct ReceiverStatePayloadWord {
            selected_branch: u8,
            shared_point: [u8; 32],
        }

        let fixture = boundary_fixture();
        let session = crate::protocol::prepare_prime_order_succinct_hss(&fixture.input.context)
            .expect("prepare session");
        let (_runtime, garbler_session, evaluator_session) = session.split_runtime();

        let client_ot_offer_message = garbler_session
            .client_ot_offer_message()
            .expect("prepare client OT offer");
        let (client_request_message, evaluator_ot_state) = evaluator_session
            .prepare_client_ot_request_from_offer_message(
                &client_ot_offer_message,
                fixture.input.y_client,
                fixture.input.tau_client,
            )
            .expect("prepare client request");
        let client_packet: crate::wire::ClientPacket = crate::wire::decode_transport_message(
            session.candidate().context_binding,
            crate::wire::TransportKind::ClientOtRequest,
            &client_request_message,
        )
        .expect("decode client packet");

        let client_packet_bytes = serialized_size(&client_packet);
        let client_packet_word_bytes = serialized_size(
            &client_packet
                .y_client_request
                .words
                .iter()
                .map(|word| SelectionPayloadWord {
                    receiver_public: word.receiver_public,
                })
                .collect::<Vec<_>>(),
        ) + serialized_size(
            &client_packet
                .tau_client_request
                .words
                .iter()
                .map(|word| SelectionPayloadWord {
                    receiver_public: word.receiver_public,
                })
                .collect::<Vec<_>>(),
        );
        let client_packet_wrapper_bytes = client_packet_bytes - client_packet_word_bytes;

        let evaluator_ot_state_bytes = serialized_size(&evaluator_ot_state);
        let evaluator_ot_state_word_bytes = serialized_size(
            &evaluator_ot_state
                .y_client_local_state
                .words
                .iter()
                .map(|word| ReceiverStatePayloadWord {
                    selected_branch: word.selected_branch,
                    shared_point: word.shared_point,
                })
                .collect::<Vec<_>>(),
        ) + serialized_size(
            &evaluator_ot_state
                .tau_client_local_state
                .words
                .iter()
                .map(|word| ReceiverStatePayloadWord {
                    selected_branch: word.selected_branch,
                    shared_point: word.shared_point,
                })
                .collect::<Vec<_>>(),
        );
        let evaluator_ot_state_wrapper_bytes =
            evaluator_ot_state_bytes - evaluator_ot_state_word_bytes;

        assert!(
            client_packet_word_bytes * 100 / client_packet_bytes >= 85,
            "client packet should be dominated by OT word vectors, got words={} total={}",
            client_packet_word_bytes,
            client_packet_bytes,
        );
        assert!(
            evaluator_ot_state_word_bytes * 100 / evaluator_ot_state_bytes >= 85,
            "evaluator OT state should be dominated by OT word vectors, got words={} total={}",
            evaluator_ot_state_word_bytes,
            evaluator_ot_state_bytes,
        );
        assert!(
            client_packet_wrapper_bytes < client_packet_word_bytes,
            "client packet wrappers should not dominate serialized size",
        );
        assert!(
            evaluator_ot_state_wrapper_bytes < evaluator_ot_state_word_bytes,
            "evaluator OT state wrappers should not dominate serialized size",
        );
    }
}
