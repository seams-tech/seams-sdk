use crate::client::{
    ot::build_client_ot_request, ClientDriverState, ClientOtState, ClientOutputOpener,
    ClientSession, ClientSessionState, SeedOutputOpener,
};
use crate::ddh::hidden_eval_executor::{
    execute_prime_order_ddh_hidden_eval_program_with_split_server_inputs_and_client_output_projection_profiled_with_pool,
    DdhHiddenEvalConstantPool, DdhHiddenEvalServerInputBundle, DdhHiddenEvalServerInputs,
};
use crate::ddh::{
    DdhHiddenEvalClientOutputProjection, DdhHiddenEvalRun, DdhHiddenEvalStageProfile,
    DdhHssInputShareBundle, DdhHssShareSide, DdhHssTransportBundle, DdhHssTransportPurpose,
    HiddenEvalInputOwner,
};
use crate::runtime::{
    evaluation::{elapsed_ns_u64, monotonic_now_ns},
    SharedRuntime,
};
use crate::shared::{ProtoError, ProtoResult};
use crate::wire::{
    AddStageRequestPayload, AddStageResponsePayload, ClientOtOffer, ClientOutputPacket,
    ClientOutputValueKind, ClientPacket, ClientStageCommitments, ClientStagePayload,
    ClientStageRequestPacket, MessageScheduleRequestPayload, MessageScheduleResponsePayload,
    OutputProjectionMode, OutputProjectionRequestPayload, OutputProjectionResponsePayload,
    RoleSeparatedAddStageRequestPayload, RoleSeparatedClientStagePayload,
    RoleSeparatedClientStageRequestPacket, RoleSeparatedOutputDeliveryPacket,
    RoleSeparatedOutputDeliveryPayload, RoleSeparatedServerInputDeliveryPacket,
    RoleSeparatedServerInputsPacket, RoundCoreRequestPayload, RoundCoreResponsePayload,
    RunBindings, SeedOutputPacket, ServerAssistInitPacket, ServerEvalHandle, ServerFinalizePacket,
    ServerStagePayload, ServerStageResponsePacket, StagedEvaluatorArtifact, TransportKind,
    WireMessage,
};
#[cfg(not(target_arch = "wasm32"))]
use crate::wire::{EvaluationReport, EvaluatorWitness, OutputDelivery};
use rand_core::{OsRng, RngCore};

struct AddStageRequestParts {
    prior_transcript_digest: [u8; 32],
    client_input_commitment: [u8; 32],
    client_stage_openings_digest: [u8; 32],
    client_stage_nonce: [u8; 16],
    y_client_bundle: DdhHssInputShareBundle,
    tau_client_bundle: DdhHssInputShareBundle,
}

impl ClientSessionState {
    pub fn materialize(&self) -> ProtoResult<ClientSession> {
        if self.backend_version != self.ddh_evaluator.evaluation_key().backend_version {
            return Err(ProtoError::InvalidInput(
                "client session state backend version does not match evaluator".to_string(),
            ));
        }
        if self.backend_version != crate::ddh::DdhHssBackendVersion::CURRENT {
            return Err(ProtoError::InvalidInput(format!(
                "client session state backend version is stale: {}",
                self.backend_version.as_str()
            )));
        }
        Ok(ClientSession {
            context_binding: self.context_binding,
            ddh_evaluator: self.ddh_evaluator.clone(),
        })
    }
}

impl ClientDriverState {
    pub fn materialize(&self) -> ProtoResult<(SharedRuntime, ClientSession)> {
        Ok((
            self.runtime.materialize()?,
            self.evaluator_session.materialize()?,
        ))
    }
}

impl ClientSession {
    pub fn hidden_eval_constant_pool(&self) -> ProtoResult<DdhHiddenEvalConstantPool> {
        crate::ddh::hidden_eval_executor::prepare_ddh_hidden_eval_constant_pool(&self.ddh_evaluator)
    }

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
        crate::client::ot::validate_evaluator_ot_state(
            self.context_binding,
            &self.ddh_evaluator,
            evaluator_ot_state,
        )
    }

    pub fn validate_server_assist_init_packet(
        &self,
        client_packet: &ClientPacket,
        evaluator_ot_state: &ClientOtState,
        packet: &ServerAssistInitPacket,
    ) -> ProtoResult<()> {
        self.validate_evaluator_ot_state(evaluator_ot_state)?;
        crate::protocol::invariants::validate_server_assist_init_packet(
            self,
            client_packet,
            evaluator_ot_state,
            packet,
        )
    }

    pub fn decode_server_assist_init_message(
        &self,
        client_request_message: &WireMessage,
        evaluator_ot_state: &ClientOtState,
        server_assist_init_message: &WireMessage,
    ) -> ProtoResult<ServerAssistInitPacket> {
        let client_packet: ClientPacket = crate::wire::decode_transport_message(
            self.context_binding,
            TransportKind::ClientOtRequest,
            client_request_message,
        )?;
        let packet: ServerAssistInitPacket = crate::wire::decode_transport_message(
            self.context_binding,
            TransportKind::ServerAssistInit,
            server_assist_init_message,
        )?;
        self.validate_server_assist_init_packet(&client_packet, evaluator_ot_state, &packet)?;
        Ok(packet)
    }

    fn reconstruct_client_input_bundles_from_server_assist_init(
        &self,
        evaluator_ot_state: &ClientOtState,
        packet: &ServerAssistInitPacket,
    ) -> ProtoResult<(DdhHssInputShareBundle, DdhHssInputShareBundle)> {
        let y_client_bundle = self.ddh_evaluator.reconstruct_client_ot_bundle(
            self.context_binding,
            &packet.y_client_response,
            &evaluator_ot_state.y_client_local_state,
            &packet.y_client_remote_release,
        )?;
        let tau_client_bundle = self.ddh_evaluator.reconstruct_client_ot_bundle(
            self.context_binding,
            &packet.tau_client_response,
            &evaluator_ot_state.tau_client_local_state,
            &packet.tau_client_remote_release,
        )?;
        Ok((y_client_bundle, tau_client_bundle))
    }

    fn server_assist_init_from_role_separated_delivery(
        packet: &RoleSeparatedServerInputDeliveryPacket,
    ) -> ServerAssistInitPacket {
        ServerAssistInitPacket {
            context_binding: packet.context_binding,
            server_eval_handle: packet.server_eval_handle,
            transcript_id: packet.transcript_id,
            server_input_commitment: packet.server_input_commitment,
            y_client_response: packet.y_client_response.clone(),
            tau_client_response: packet.tau_client_response.clone(),
            y_client_remote_release: packet.y_client_remote_release.clone(),
            tau_client_remote_release: packet.tau_client_remote_release.clone(),
        }
    }

    fn server_input_bundle_from_transport_pair(
        expected_label: &str,
        left: DdhHssTransportBundle,
        right: DdhHssTransportBundle,
    ) -> ProtoResult<DdhHiddenEvalServerInputBundle> {
        if left.owner != HiddenEvalInputOwner::Server || right.owner != HiddenEvalInputOwner::Server
        {
            return Err(ProtoError::InvalidInput(format!(
                "role-separated server input {expected_label} owner must be server"
            )));
        }
        if left.label != expected_label || right.label != expected_label {
            return Err(ProtoError::InvalidInput(format!(
                "role-separated server input label mismatch for {expected_label}"
            )));
        }
        if left.share_side != DdhHssShareSide::Left || right.share_side != DdhHssShareSide::Right {
            return Err(ProtoError::InvalidInput(format!(
                "role-separated server input share sides are invalid for {expected_label}"
            )));
        }
        if left.commitment != right.commitment {
            return Err(ProtoError::InvalidInput(format!(
                "role-separated server input commitment mismatch for {expected_label}"
            )));
        }
        Ok(DdhHiddenEvalServerInputBundle {
            owner: HiddenEvalInputOwner::Server,
            label: expected_label.to_string(),
            left_words: left.words,
            right_words: right.words,
            commitment: left.commitment,
        })
    }

    pub fn open_role_separated_server_inputs(
        &self,
        packet: &RoleSeparatedServerInputsPacket,
    ) -> ProtoResult<DdhHiddenEvalServerInputs> {
        if packet.context_binding != self.context_binding {
            return Err(ProtoError::InvalidInput(
                "role-separated server input context binding does not match evaluator session"
                    .to_string(),
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
        let payload = crate::wire::deserialize_server_inputs_payload(&plaintext)?;
        Ok(DdhHiddenEvalServerInputs {
            y_relayer_bits: Self::server_input_bundle_from_transport_pair(
                "y_relayer_bits",
                payload.y_relayer_left,
                payload.y_relayer_right,
            )?,
            tau_relayer_bits: Self::server_input_bundle_from_transport_pair(
                "tau_relayer_bits",
                payload.tau_relayer_left,
                payload.tau_relayer_right,
            )?,
        })
    }

    pub fn build_client_owned_staged_evaluator_artifact_from_role_separated_delivery(
        &self,
        runtime: &SharedRuntime,
        client_packet: &ClientPacket,
        evaluator_ot_state: &ClientOtState,
        packet: &RoleSeparatedServerInputDeliveryPacket,
        client_output_mask: [u8; 32],
    ) -> ProtoResult<StagedEvaluatorArtifact> {
        self.build_client_owned_staged_evaluator_artifact_from_role_separated_delivery_with_projection(
            runtime,
            client_packet,
            evaluator_ot_state,
            packet,
            DdhHiddenEvalClientOutputProjection::client_masked_projection(client_output_mask),
        )
    }

    pub fn build_client_owned_staged_evaluator_artifact_from_role_separated_delivery_profiled(
        &self,
        runtime: &SharedRuntime,
        client_packet: &ClientPacket,
        evaluator_ot_state: &ClientOtState,
        packet: &RoleSeparatedServerInputDeliveryPacket,
        client_output_mask: [u8; 32],
    ) -> ProtoResult<(StagedEvaluatorArtifact, DdhHiddenEvalStageProfile)> {
        self.build_client_owned_staged_evaluator_artifact_from_role_separated_delivery_with_projection_profiled(
            runtime,
            client_packet,
            evaluator_ot_state,
            packet,
            DdhHiddenEvalClientOutputProjection::client_masked_projection(client_output_mask),
        )
    }

    fn build_client_owned_staged_evaluator_artifact_from_role_separated_delivery_with_projection(
        &self,
        runtime: &SharedRuntime,
        client_packet: &ClientPacket,
        evaluator_ot_state: &ClientOtState,
        packet: &RoleSeparatedServerInputDeliveryPacket,
        client_output_projection: DdhHiddenEvalClientOutputProjection,
    ) -> ProtoResult<StagedEvaluatorArtifact> {
        self.build_client_owned_staged_evaluator_artifact_from_role_separated_delivery_with_projection_profiled(
            runtime,
            client_packet,
            evaluator_ot_state,
            packet,
            client_output_projection,
        )
        .map(|(artifact, _)| artifact)
    }

    fn build_client_owned_staged_evaluator_artifact_from_role_separated_delivery_with_projection_profiled(
        &self,
        runtime: &SharedRuntime,
        client_packet: &ClientPacket,
        evaluator_ot_state: &ClientOtState,
        packet: &RoleSeparatedServerInputDeliveryPacket,
        client_output_projection: DdhHiddenEvalClientOutputProjection,
    ) -> ProtoResult<(StagedEvaluatorArtifact, DdhHiddenEvalStageProfile)> {
        let assist = Self::server_assist_init_from_role_separated_delivery(packet);
        self.validate_server_assist_init_packet(client_packet, evaluator_ot_state, &assist)?;
        let (y_client_bundle, tau_client_bundle) = self
            .reconstruct_client_input_bundles_from_server_assist_init(
                evaluator_ot_state,
                &assist,
            )?;
        let server_inputs = self.open_role_separated_server_inputs(&packet.server_inputs)?;
        let hidden_eval_constants = self.hidden_eval_constant_pool()?;
        let (run, stage_profile) =
            execute_prime_order_ddh_hidden_eval_program_with_split_server_inputs_and_client_output_projection_profiled_with_pool(
            &runtime.hidden_eval_program,
            &self.ddh_evaluator,
            &hidden_eval_constants,
            &y_client_bundle,
            &server_inputs.y_relayer_bits,
            &tau_client_bundle,
            &server_inputs.tau_relayer_bits,
            client_output_projection,
        )?;
        let expected_client_input_commitment = self.ddh_evaluator.combined_input_commitment(
            HiddenEvalInputOwner::Client,
            &[&y_client_bundle, &tau_client_bundle],
        );
        if run.client_input_commitment != expected_client_input_commitment {
            return Err(ProtoError::InvalidInput(
                "role-separated client materialization commitment does not match client inputs"
                    .to_string(),
            ));
        }
        if run.server_input_commitment != packet.server_input_commitment {
            return Err(ProtoError::InvalidInput(
                "role-separated client materialization commitment does not match server inputs"
                    .to_string(),
            ));
        }
        self.build_staged_evaluator_artifact_from_hidden_eval_outputs(
            runtime,
            run.client_input_commitment,
            run.server_input_commitment,
            run.output,
            client_output_projection.client_output_mask(),
        )
        .map(|(artifact, _, _)| (artifact, stage_profile))
    }

    pub fn build_client_owned_staged_evaluator_artifact_from_role_separated_delivery_message(
        &self,
        runtime: &SharedRuntime,
        client_request_message: &WireMessage,
        evaluator_ot_state: &ClientOtState,
        packet: &RoleSeparatedServerInputDeliveryPacket,
        client_output_mask: [u8; 32],
    ) -> ProtoResult<StagedEvaluatorArtifact> {
        let client_packet: ClientPacket = crate::wire::decode_transport_message(
            self.context_binding,
            TransportKind::ClientOtRequest,
            client_request_message,
        )?;
        self.build_client_owned_staged_evaluator_artifact_from_role_separated_delivery(
            runtime,
            &client_packet,
            evaluator_ot_state,
            packet,
            client_output_mask,
        )
    }

    pub fn build_client_owned_staged_evaluator_artifact_from_role_separated_delivery_message_profiled(
        &self,
        runtime: &SharedRuntime,
        client_request_message: &WireMessage,
        evaluator_ot_state: &ClientOtState,
        packet: &RoleSeparatedServerInputDeliveryPacket,
        client_output_mask: [u8; 32],
    ) -> ProtoResult<(StagedEvaluatorArtifact, DdhHiddenEvalStageProfile)> {
        let client_packet: ClientPacket = crate::wire::decode_transport_message(
            self.context_binding,
            TransportKind::ClientOtRequest,
            client_request_message,
        )?;
        self.build_client_owned_staged_evaluator_artifact_from_role_separated_delivery_profiled(
            runtime,
            &client_packet,
            evaluator_ot_state,
            packet,
            client_output_mask,
        )
    }

    fn prepare_add_stage_request_parts(
        &self,
        client_packet: &ClientPacket,
        evaluator_ot_state: &ClientOtState,
        packet: &ServerAssistInitPacket,
    ) -> ProtoResult<AddStageRequestParts> {
        self.validate_server_assist_init_packet(client_packet, evaluator_ot_state, packet)?;
        let (y_client_bundle, tau_client_bundle) = self
            .reconstruct_client_input_bundles_from_server_assist_init(evaluator_ot_state, packet)?;
        let client_input_commitment = self.ddh_evaluator.combined_input_commitment(
            crate::ddh::HiddenEvalInputOwner::Client,
            &[&y_client_bundle, &tau_client_bundle],
        );
        let mut client_stage_nonce = [0u8; 16];
        OsRng.fill_bytes(&mut client_stage_nonce);
        let client_stage_openings_digest =
            crate::protocol::transcript::compute_add_stage_openings_digest(
                self.context_binding,
                packet.server_eval_handle,
                crate::wire::ServerEvalStageId::add_stage(),
                client_stage_nonce,
                client_input_commitment,
                y_client_bundle.commitment,
                tau_client_bundle.commitment,
            );
        let ot_transcript_digest =
            crate::protocol::transcript::compute_ot_transcript_digest_from_commitments(
                self.context_binding,
                evaluator_ot_state
                    .offer_commitments
                    .y_client_offer_commitment,
                client_packet.y_client_request.commitment,
                packet.y_client_response.commitment,
                packet.y_client_remote_release.transcript_binding,
                evaluator_ot_state
                    .offer_commitments
                    .tau_client_offer_commitment,
                client_packet.tau_client_request.commitment,
                packet.tau_client_response.commitment,
                packet.tau_client_remote_release.transcript_binding,
            );
        let prior_transcript_digest =
            crate::protocol::transcript::derive_server_stage_digest_from_ot_transcript_digest(
                self.context_binding,
                packet.server_eval_handle,
                packet.transcript_id,
                crate::wire::ServerEvalStageId::add_stage(),
                packet.server_input_commitment,
                ot_transcript_digest,
            );

        Ok(AddStageRequestParts {
            prior_transcript_digest,
            client_input_commitment,
            client_stage_openings_digest,
            client_stage_nonce,
            y_client_bundle,
            tau_client_bundle,
        })
    }

    pub fn build_add_stage_request(
        &self,
        client_packet: &ClientPacket,
        evaluator_ot_state: &ClientOtState,
        packet: &ServerAssistInitPacket,
    ) -> ProtoResult<ClientStageRequestPacket> {
        let parts =
            self.prepare_add_stage_request_parts(client_packet, evaluator_ot_state, packet)?;
        Ok(ClientStageRequestPacket {
            context_binding: self.context_binding,
            server_eval_handle: packet.server_eval_handle,
            stage_id: crate::wire::ServerEvalStageId::add_stage(),
            prior_transcript_digest: parts.prior_transcript_digest,
            client_stage_payload: ClientStagePayload::AddStage(AddStageRequestPayload {
                client_input_commitment: parts.client_input_commitment,
                client_stage_openings_digest: parts.client_stage_openings_digest,
                client_stage_nonce: parts.client_stage_nonce,
                y_client_bundle_payload: crate::wire::serialize_encoded_bundle_payload(
                    &parts.y_client_bundle,
                )?,
                tau_client_bundle_payload: crate::wire::serialize_encoded_bundle_payload(
                    &parts.tau_client_bundle,
                )?,
            }),
            client_stage_commitments: ClientStageCommitments {
                digests: vec![
                    parts.client_input_commitment,
                    parts.client_stage_openings_digest,
                ],
            },
        })
    }

    pub fn build_role_separated_add_stage_request(
        &self,
        client_packet: &ClientPacket,
        evaluator_ot_state: &ClientOtState,
        packet: &ServerAssistInitPacket,
    ) -> ProtoResult<RoleSeparatedClientStageRequestPacket> {
        let parts =
            self.prepare_add_stage_request_parts(client_packet, evaluator_ot_state, packet)?;
        Ok(RoleSeparatedClientStageRequestPacket {
            context_binding: self.context_binding,
            server_eval_handle: packet.server_eval_handle,
            stage_id: crate::wire::ServerEvalStageId::add_stage(),
            prior_transcript_digest: parts.prior_transcript_digest,
            client_stage_payload: RoleSeparatedClientStagePayload::AddStage(
                RoleSeparatedAddStageRequestPayload {
                    client_input_commitment: parts.client_input_commitment,
                    client_stage_openings_digest: parts.client_stage_openings_digest,
                    client_stage_nonce: parts.client_stage_nonce,
                },
            ),
            client_stage_commitments: ClientStageCommitments {
                digests: vec![
                    parts.client_input_commitment,
                    parts.client_stage_openings_digest,
                ],
            },
        })
    }

    pub fn prepare_add_stage_request_message(
        &self,
        client_request_message: &WireMessage,
        evaluator_ot_state: &ClientOtState,
        server_assist_init_message: &WireMessage,
    ) -> ProtoResult<WireMessage> {
        let client_packet: ClientPacket = crate::wire::decode_transport_message(
            self.context_binding,
            TransportKind::ClientOtRequest,
            client_request_message,
        )?;
        let packet = self.decode_server_assist_init_message(
            client_request_message,
            evaluator_ot_state,
            server_assist_init_message,
        )?;
        let request = self.build_add_stage_request(&client_packet, evaluator_ot_state, &packet)?;
        crate::wire::encode_transport_message(
            self.context_binding,
            TransportKind::ClientStageRequest,
            &request,
        )
    }

    pub fn validate_add_stage_response_packet(
        &self,
        request: &ClientStageRequestPacket,
        packet: &ServerAssistInitPacket,
        response: &ServerStageResponsePacket,
    ) -> ProtoResult<()> {
        crate::protocol::invariants::validate_add_stage_response_packet(
            &crate::server::ServerEvalState::new(
                packet.server_eval_handle,
                packet.context_binding,
                packet.transcript_id,
                request.prior_transcript_digest,
                crate::server::ServerEvalOperation::Registration,
                packet.server_input_commitment,
                crate::wire::OtTranscript {
                    context_binding: self.context_binding,
                    y_client_offer_commitment: [0u8; 32],
                    y_client_request_commitment: [0u8; 32],
                    y_client_response_commitment: packet.y_client_response.commitment,
                    y_client_remote_release_binding: packet
                        .y_client_remote_release
                        .transcript_binding,
                    tau_client_offer_commitment: [0u8; 32],
                    tau_client_request_commitment: [0u8; 32],
                    tau_client_response_commitment: packet.tau_client_response.commitment,
                    tau_client_remote_release_binding: packet
                        .tau_client_remote_release
                        .transcript_binding,
                    transcript_digest: [0u8; 32],
                },
                crate::server::ServerEvalRelayerRoots {
                    y_relayer: [0u8; 32],
                    tau_relayer: [0u8; 32],
                },
            ),
            request,
            response,
        )?;
        let ServerStagePayload::AddStage(AddStageResponsePayload {
            server_stage_token,
            server_input_commitment,
            server_stage_digest,
            execution_checkpoint_digest,
        }) = &response.server_stage_payload
        else {
            return Err(ProtoError::InvalidInput(
                "server stage response payload must be add-stage".to_string(),
            ));
        };
        let request_digest =
            crate::protocol::transcript::compute_client_stage_request_digest(request)?;
        let expected_token = crate::protocol::transcript::compute_add_stage_response_token(
            packet.server_eval_handle,
            packet.transcript_id,
            request.stage_id,
            request.prior_transcript_digest,
            request_digest,
            packet.server_input_commitment,
        );
        if *server_stage_token != expected_token {
            return Err(ProtoError::InvalidInput(
                "server stage response token is invalid".to_string(),
            ));
        }
        let expected_digest = crate::protocol::transcript::compute_add_stage_response_digest(
            self.context_binding,
            packet.server_eval_handle,
            request.stage_id,
            request.prior_transcript_digest,
            *server_input_commitment,
            *server_stage_token,
        );
        if *server_stage_digest != expected_digest
            || response.next_transcript_digest != expected_digest
        {
            return Err(ProtoError::InvalidInput(
                "server stage response digest is invalid".to_string(),
            ));
        }
        if response.server_stage_commitments.digests.len() < 3
            || response.server_stage_commitments.digests[2] != *execution_checkpoint_digest
        {
            return Err(ProtoError::InvalidInput(
                "server stage response execution checkpoint digest is not bound to add-stage commitments"
                    .to_string(),
            ));
        }
        Ok(())
    }

    pub fn decode_add_stage_response_message(
        &self,
        client_request_message: &WireMessage,
        evaluator_ot_state: &ClientOtState,
        server_assist_init_message: &WireMessage,
        client_stage_request_message: &WireMessage,
        server_stage_response_message: &WireMessage,
    ) -> ProtoResult<ServerStageResponsePacket> {
        let packet = self.decode_server_assist_init_message(
            client_request_message,
            evaluator_ot_state,
            server_assist_init_message,
        )?;
        let request: ClientStageRequestPacket = crate::wire::decode_transport_message(
            self.context_binding,
            TransportKind::ClientStageRequest,
            client_stage_request_message,
        )?;
        let response: ServerStageResponsePacket = crate::wire::decode_transport_message(
            self.context_binding,
            TransportKind::ServerStageResponse,
            server_stage_response_message,
        )?;
        self.validate_add_stage_response_packet(&request, &packet, &response)?;
        Ok(response)
    }

    pub fn build_message_schedule_request(
        &self,
        prior_stage_response: &ServerStageResponsePacket,
    ) -> ProtoResult<ClientStageRequestPacket> {
        let (stage_id, prior_server_stage_digest) = match &prior_stage_response.server_stage_payload
        {
            ServerStagePayload::AddStage(add_stage_payload) => (
                crate::wire::ServerEvalStageId::message_schedule(0),
                add_stage_payload.execution_checkpoint_digest,
            ),
            ServerStagePayload::MessageSchedule(message_schedule_payload) => (
                crate::wire::ServerEvalStageId::message_schedule(
                    message_schedule_payload.schedule_step + 1,
                ),
                message_schedule_payload.execution_checkpoint_digest,
            ),
            _ => {
                return Err(ProtoError::InvalidInput(
                    "message-schedule requests must follow add-stage or message-schedule responses"
                        .to_string(),
                ));
            }
        };
        let client_schedule_digest =
            crate::protocol::transcript::compute_message_schedule_request_digest(
                self.context_binding,
                prior_stage_response.server_eval_handle,
                stage_id,
                stage_id.ordinal,
                prior_server_stage_digest,
            );
        Ok(ClientStageRequestPacket {
            context_binding: self.context_binding,
            server_eval_handle: prior_stage_response.server_eval_handle,
            stage_id,
            prior_transcript_digest: prior_stage_response.next_transcript_digest,
            client_stage_payload: ClientStagePayload::MessageSchedule(
                MessageScheduleRequestPayload {
                    schedule_step: stage_id.ordinal,
                    client_schedule_digest,
                    prior_server_stage_digest,
                },
            ),
            client_stage_commitments: ClientStageCommitments {
                digests: vec![client_schedule_digest, prior_server_stage_digest],
            },
        })
    }

    pub fn prepare_message_schedule_request_message(
        &self,
        prior_stage_response_message: &WireMessage,
    ) -> ProtoResult<WireMessage> {
        let prior_stage_response: ServerStageResponsePacket =
            crate::wire::decode_transport_message(
                self.context_binding,
                TransportKind::ServerStageResponse,
                prior_stage_response_message,
            )?;
        let request = self.build_message_schedule_request(&prior_stage_response)?;
        crate::wire::encode_transport_message(
            self.context_binding,
            TransportKind::ClientStageRequest,
            &request,
        )
    }

    pub fn validate_message_schedule_response_packet(
        &self,
        packet: &ServerAssistInitPacket,
        request: &ClientStageRequestPacket,
        response: &ServerStageResponsePacket,
    ) -> ProtoResult<()> {
        if response.context_binding != self.context_binding
            || response.context_binding != packet.context_binding
        {
            return Err(ProtoError::InvalidInput(
                "message-schedule response context binding is invalid".to_string(),
            ));
        }
        if response.server_eval_handle != packet.server_eval_handle
            || response.server_eval_handle != request.server_eval_handle
        {
            return Err(ProtoError::InvalidInput(
                "message-schedule response handle is invalid".to_string(),
            ));
        }
        if response.stage_id != request.stage_id {
            return Err(ProtoError::InvalidInput(
                "message-schedule response stage id does not match the request".to_string(),
            ));
        }
        let ServerStagePayload::MessageSchedule(MessageScheduleResponsePayload {
            schedule_step,
            server_schedule_digest,
            next_stage_token,
            execution_checkpoint_digest,
        }) = &response.server_stage_payload
        else {
            return Err(ProtoError::InvalidInput(
                "server stage response payload must be message-schedule".to_string(),
            ));
        };
        let ClientStagePayload::MessageSchedule(MessageScheduleRequestPayload {
            schedule_step: request_schedule_step,
            client_schedule_digest: _,
            prior_server_stage_digest,
        }) = &request.client_stage_payload
        else {
            return Err(ProtoError::InvalidInput(
                "client stage request payload must be message-schedule".to_string(),
            ));
        };
        if *schedule_step != *request_schedule_step {
            return Err(ProtoError::InvalidInput(
                "message-schedule response step does not match the request".to_string(),
            ));
        }
        let request_digest =
            crate::protocol::transcript::compute_client_stage_request_digest(request)?;
        let expected_token = crate::protocol::transcript::compute_message_schedule_response_token(
            response.server_eval_handle,
            packet.transcript_id,
            request.stage_id,
            request.prior_transcript_digest,
            request_digest,
        );
        let expected_digest = crate::protocol::transcript::compute_message_schedule_response_digest(
            self.context_binding,
            response.server_eval_handle,
            request.stage_id,
            *schedule_step,
            *prior_server_stage_digest,
            expected_token,
        );
        if *next_stage_token != expected_token {
            return Err(ProtoError::InvalidInput(
                "message-schedule response token is invalid".to_string(),
            ));
        }
        if *server_schedule_digest != expected_digest
            || response.next_transcript_digest != expected_digest
        {
            return Err(ProtoError::InvalidInput(
                "message-schedule response digest is invalid".to_string(),
            ));
        }
        if response.server_stage_commitments.digests.len() < 3
            || response.server_stage_commitments.digests[2] != *execution_checkpoint_digest
        {
            return Err(ProtoError::InvalidInput(
                "message-schedule response execution checkpoint digest is not bound to commitments"
                    .to_string(),
            ));
        }
        Ok(())
    }

    pub fn decode_message_schedule_response_message(
        &self,
        server_assist_init_message: &WireMessage,
        client_stage_request_message: &WireMessage,
        server_stage_response_message: &WireMessage,
    ) -> ProtoResult<ServerStageResponsePacket> {
        let packet: ServerAssistInitPacket = crate::wire::decode_transport_message(
            self.context_binding,
            TransportKind::ServerAssistInit,
            server_assist_init_message,
        )?;
        let request: ClientStageRequestPacket = crate::wire::decode_transport_message(
            self.context_binding,
            TransportKind::ClientStageRequest,
            client_stage_request_message,
        )?;
        let response: ServerStageResponsePacket = crate::wire::decode_transport_message(
            self.context_binding,
            TransportKind::ServerStageResponse,
            server_stage_response_message,
        )?;
        self.validate_message_schedule_response_packet(&packet, &request, &response)?;
        Ok(response)
    }

    pub fn build_round_core_request(
        &self,
        prior_stage_response: &ServerStageResponsePacket,
    ) -> ProtoResult<ClientStageRequestPacket> {
        let (stage_id, prior_server_stage_digest) = match &prior_stage_response.server_stage_payload
        {
            ServerStagePayload::MessageSchedule(message_schedule_payload) => {
                if message_schedule_payload.schedule_step + 1
                    != crate::wire::ServerEvalStageId::MESSAGE_SCHEDULE_ROUNDS
                {
                    return Err(ProtoError::InvalidInput(
                        "round-core requests may only begin after the final message-schedule round"
                            .to_string(),
                    ));
                }
                (
                    crate::wire::ServerEvalStageId::round_core(0),
                    message_schedule_payload.execution_checkpoint_digest,
                )
            }
            ServerStagePayload::RoundCore(round_core_payload) => (
                crate::wire::ServerEvalStageId::round_core(round_core_payload.round_index + 1),
                round_core_payload.execution_checkpoint_digest,
            ),
            _ => {
                return Err(ProtoError::InvalidInput(
                    "round-core requests must follow a final message-schedule or round-core response"
                        .to_string(),
                ));
            }
        };
        let client_round_digest = crate::protocol::transcript::compute_round_core_request_digest(
            self.context_binding,
            prior_stage_response.server_eval_handle,
            stage_id,
            stage_id.ordinal,
            prior_server_stage_digest,
        );
        Ok(ClientStageRequestPacket {
            context_binding: self.context_binding,
            server_eval_handle: prior_stage_response.server_eval_handle,
            stage_id,
            prior_transcript_digest: prior_stage_response.next_transcript_digest,
            client_stage_payload: ClientStagePayload::RoundCore(RoundCoreRequestPayload {
                round_index: stage_id.ordinal,
                client_round_digest,
                prior_server_stage_digest,
            }),
            client_stage_commitments: ClientStageCommitments {
                digests: vec![client_round_digest, prior_server_stage_digest],
            },
        })
    }

    pub fn prepare_round_core_request_message(
        &self,
        prior_stage_response_message: &WireMessage,
    ) -> ProtoResult<WireMessage> {
        let prior_stage_response: ServerStageResponsePacket =
            crate::wire::decode_transport_message(
                self.context_binding,
                TransportKind::ServerStageResponse,
                prior_stage_response_message,
            )?;
        let request = self.build_round_core_request(&prior_stage_response)?;
        crate::wire::encode_transport_message(
            self.context_binding,
            TransportKind::ClientStageRequest,
            &request,
        )
    }

    pub fn validate_round_core_response_packet(
        &self,
        packet: &ServerAssistInitPacket,
        request: &ClientStageRequestPacket,
        response: &ServerStageResponsePacket,
    ) -> ProtoResult<()> {
        if response.context_binding != self.context_binding
            || response.context_binding != packet.context_binding
        {
            return Err(ProtoError::InvalidInput(
                "round-core response context binding is invalid".to_string(),
            ));
        }
        if response.server_eval_handle != packet.server_eval_handle
            || response.server_eval_handle != request.server_eval_handle
        {
            return Err(ProtoError::InvalidInput(
                "round-core response handle is invalid".to_string(),
            ));
        }
        if response.stage_id != request.stage_id {
            return Err(ProtoError::InvalidInput(
                "round-core response stage id does not match the request".to_string(),
            ));
        }
        let ServerStagePayload::RoundCore(RoundCoreResponsePayload {
            round_index,
            server_round_digest,
            next_stage_token,
            execution_checkpoint_digest,
        }) = &response.server_stage_payload
        else {
            return Err(ProtoError::InvalidInput(
                "server stage response payload must be round-core".to_string(),
            ));
        };
        let ClientStagePayload::RoundCore(RoundCoreRequestPayload {
            round_index: request_round_index,
            client_round_digest: _,
            prior_server_stage_digest,
        }) = &request.client_stage_payload
        else {
            return Err(ProtoError::InvalidInput(
                "client stage request payload must be round-core".to_string(),
            ));
        };
        if *round_index != *request_round_index {
            return Err(ProtoError::InvalidInput(
                "round-core response index does not match the request".to_string(),
            ));
        }
        let request_digest =
            crate::protocol::transcript::compute_client_stage_request_digest(request)?;
        let expected_token = crate::protocol::transcript::compute_round_core_response_token(
            response.server_eval_handle,
            packet.transcript_id,
            request.stage_id,
            request.prior_transcript_digest,
            request_digest,
        );
        let expected_digest = crate::protocol::transcript::compute_round_core_response_digest(
            self.context_binding,
            response.server_eval_handle,
            request.stage_id,
            *round_index,
            *prior_server_stage_digest,
            expected_token,
        );
        if *next_stage_token != expected_token {
            return Err(ProtoError::InvalidInput(
                "round-core response token is invalid".to_string(),
            ));
        }
        if *server_round_digest != expected_digest
            || response.next_transcript_digest != expected_digest
        {
            return Err(ProtoError::InvalidInput(
                "round-core response digest is invalid".to_string(),
            ));
        }
        if response.server_stage_commitments.digests.len() < 3
            || response.server_stage_commitments.digests[2] != *execution_checkpoint_digest
        {
            return Err(ProtoError::InvalidInput(
                "round-core response execution checkpoint digest is not bound to commitments"
                    .to_string(),
            ));
        }
        Ok(())
    }

    pub fn decode_round_core_response_message(
        &self,
        server_assist_init_message: &WireMessage,
        client_stage_request_message: &WireMessage,
        server_stage_response_message: &WireMessage,
    ) -> ProtoResult<ServerStageResponsePacket> {
        let packet: ServerAssistInitPacket = crate::wire::decode_transport_message(
            self.context_binding,
            TransportKind::ServerAssistInit,
            server_assist_init_message,
        )?;
        let request: ClientStageRequestPacket = crate::wire::decode_transport_message(
            self.context_binding,
            TransportKind::ClientStageRequest,
            client_stage_request_message,
        )?;
        let response: ServerStageResponsePacket = crate::wire::decode_transport_message(
            self.context_binding,
            TransportKind::ServerStageResponse,
            server_stage_response_message,
        )?;
        self.validate_round_core_response_packet(&packet, &request, &response)?;
        Ok(response)
    }

    pub fn build_output_projection_request(
        &self,
        prior_stage_response: &ServerStageResponsePacket,
    ) -> ProtoResult<ClientStageRequestPacket> {
        self.build_output_projection_request_with_projection_mode(
            prior_stage_response,
            &OutputProjectionMode::trusted_server_projection(),
        )
    }

    pub fn build_output_projection_request_with_projection_mode(
        &self,
        prior_stage_response: &ServerStageResponsePacket,
        projection_mode: &OutputProjectionMode,
    ) -> ProtoResult<ClientStageRequestPacket> {
        let ServerStagePayload::RoundCore(round_core_payload) =
            &prior_stage_response.server_stage_payload
        else {
            return Err(ProtoError::InvalidInput(
                "output-projection requests must follow a round-core response".to_string(),
            ));
        };
        if round_core_payload.round_index + 1 != crate::wire::ServerEvalStageId::ROUND_CORE_ROUNDS {
            return Err(ProtoError::InvalidInput(
                "output-projection requests may only begin after the final round-core round"
                    .to_string(),
            ));
        }
        let stage_id = crate::wire::ServerEvalStageId::output_projection();
        let final_client_digest =
            crate::protocol::transcript::compute_output_projection_request_digest(
                self.context_binding,
                prior_stage_response.server_eval_handle,
                stage_id,
                prior_stage_response.next_transcript_digest,
                projection_mode,
            );
        let prior_server_stage_digest = round_core_payload.execution_checkpoint_digest;
        Ok(ClientStageRequestPacket {
            context_binding: self.context_binding,
            server_eval_handle: prior_stage_response.server_eval_handle,
            stage_id,
            prior_transcript_digest: prior_stage_response.next_transcript_digest,
            client_stage_payload: ClientStagePayload::OutputProjection(
                OutputProjectionRequestPayload {
                    final_client_digest,
                    prior_server_stage_digest,
                    projection_mode: projection_mode.clone(),
                },
            ),
            client_stage_commitments: ClientStageCommitments {
                digests: vec![
                    final_client_digest,
                    prior_server_stage_digest,
                    crate::protocol::transcript::digest_output_projection_mode(projection_mode),
                ],
            },
        })
    }

    pub fn prepare_output_projection_request_message(
        &self,
        prior_stage_response_message: &WireMessage,
    ) -> ProtoResult<WireMessage> {
        self.prepare_output_projection_request_message_with_projection_mode(
            prior_stage_response_message,
            &OutputProjectionMode::trusted_server_projection(),
        )
    }

    pub fn prepare_output_projection_request_message_with_projection_mode(
        &self,
        prior_stage_response_message: &WireMessage,
        projection_mode: &OutputProjectionMode,
    ) -> ProtoResult<WireMessage> {
        let prior_stage_response: ServerStageResponsePacket =
            crate::wire::decode_transport_message(
                self.context_binding,
                TransportKind::ServerStageResponse,
                prior_stage_response_message,
            )?;
        let request = self.build_output_projection_request_with_projection_mode(
            &prior_stage_response,
            projection_mode,
        )?;
        crate::wire::encode_transport_message(
            self.context_binding,
            TransportKind::ClientStageRequest,
            &request,
        )
    }

    pub fn validate_output_projection_response_packet(
        &self,
        packet: &ServerAssistInitPacket,
        request: &ClientStageRequestPacket,
        response: &ServerStageResponsePacket,
    ) -> ProtoResult<()> {
        if response.context_binding != self.context_binding
            || response.context_binding != packet.context_binding
        {
            return Err(ProtoError::InvalidInput(
                "output-projection response context binding is invalid".to_string(),
            ));
        }
        if response.server_eval_handle != packet.server_eval_handle
            || response.server_eval_handle != request.server_eval_handle
        {
            return Err(ProtoError::InvalidInput(
                "output-projection response handle is invalid".to_string(),
            ));
        }
        if response.stage_id != request.stage_id {
            return Err(ProtoError::InvalidInput(
                "output-projection response stage id does not match the request".to_string(),
            ));
        }
        let ServerStagePayload::OutputProjection(OutputProjectionResponsePayload {
            final_server_digest,
            output_release_token,
            allowed_output_kind,
            projection_mode,
            execution_checkpoint_digest,
        }) = &response.server_stage_payload
        else {
            return Err(ProtoError::InvalidInput(
                "server stage response payload must be output-projection".to_string(),
            ));
        };
        let ClientStagePayload::OutputProjection(OutputProjectionRequestPayload {
            final_client_digest: _,
            prior_server_stage_digest,
            projection_mode: request_projection_mode,
        }) = &request.client_stage_payload
        else {
            return Err(ProtoError::InvalidInput(
                "client stage request payload must be output-projection".to_string(),
            ));
        };
        let request_digest =
            crate::protocol::transcript::compute_client_stage_request_digest(request)?;
        let expected_token = crate::protocol::transcript::compute_output_projection_response_token(
            response.server_eval_handle,
            packet.transcript_id,
            request.stage_id,
            request.prior_transcript_digest,
            request_digest,
        );
        let expected_digest =
            crate::protocol::transcript::compute_output_projection_response_digest(
                self.context_binding,
                response.server_eval_handle,
                request.stage_id,
                *prior_server_stage_digest,
                expected_token,
                *allowed_output_kind,
                projection_mode,
            );
        if *output_release_token != expected_token {
            return Err(ProtoError::InvalidInput(
                "output-projection response token is invalid".to_string(),
            ));
        }
        if *final_server_digest != expected_digest
            || response.next_transcript_digest != expected_digest
        {
            return Err(ProtoError::InvalidInput(
                "output-projection response digest is invalid".to_string(),
            ));
        }
        if projection_mode != request_projection_mode {
            return Err(ProtoError::InvalidInput(
                "output-projection response projection mode does not match the request".to_string(),
            ));
        }
        if response.server_stage_commitments.digests.len() < 4
            || response.server_stage_commitments.digests[2] != *execution_checkpoint_digest
            || response.server_stage_commitments.digests[3]
                != crate::protocol::transcript::digest_output_projection_mode(projection_mode)
        {
            return Err(ProtoError::InvalidInput(
                "output-projection response execution checkpoint or projection mode is not bound to commitments"
                    .to_string(),
            ));
        }
        Ok(())
    }

    pub fn decode_output_projection_response_message(
        &self,
        server_assist_init_message: &WireMessage,
        client_stage_request_message: &WireMessage,
        server_stage_response_message: &WireMessage,
    ) -> ProtoResult<ServerStageResponsePacket> {
        let packet: ServerAssistInitPacket = crate::wire::decode_transport_message(
            self.context_binding,
            TransportKind::ServerAssistInit,
            server_assist_init_message,
        )?;
        let request: ClientStageRequestPacket = crate::wire::decode_transport_message(
            self.context_binding,
            TransportKind::ClientStageRequest,
            client_stage_request_message,
        )?;
        let response: ServerStageResponsePacket = crate::wire::decode_transport_message(
            self.context_binding,
            TransportKind::ServerStageResponse,
            server_stage_response_message,
        )?;
        self.validate_output_projection_response_packet(&packet, &request, &response)?;
        Ok(response)
    }

    pub fn validate_server_finalize_packet(
        &self,
        output_projection_response: &ServerStageResponsePacket,
        packet: &ServerFinalizePacket,
    ) -> ProtoResult<()> {
        if packet.context_binding != self.context_binding {
            return Err(ProtoError::InvalidInput(
                "server finalize packet context binding does not match evaluator session"
                    .to_string(),
            ));
        }
        if packet.server_eval_handle != output_projection_response.server_eval_handle {
            return Err(ProtoError::InvalidInput(
                "server finalize packet handle does not match the staged flow".to_string(),
            ));
        }
        if packet.final_transcript_digest != output_projection_response.next_transcript_digest {
            return Err(ProtoError::InvalidInput(
                "server finalize packet digest does not match output-projection response"
                    .to_string(),
            ));
        }
        let ServerStagePayload::OutputProjection(output_payload) =
            &output_projection_response.server_stage_payload
        else {
            return Err(ProtoError::InvalidInput(
                "server finalize validation requires an output-projection response".to_string(),
            ));
        };
        if packet.allowed_output_kind != output_payload.allowed_output_kind {
            return Err(ProtoError::InvalidInput(
                "server finalize allowed output kind does not match output-projection response"
                    .to_string(),
            ));
        }
        let client_output_packet: ClientOutputPacket = crate::wire::decode_transport_message(
            self.context_binding,
            TransportKind::ClientOutput,
            &packet.client_output,
        )?;
        if client_output_packet.projection_mode != packet.projection_mode {
            return Err(ProtoError::InvalidInput(
                "server finalize client output projection mode does not match packet metadata"
                    .to_string(),
            ));
        }
        let expected_value_kind =
            ClientOutputValueKind::for_projection_mode(&packet.projection_mode);
        if client_output_packet.value_kind != expected_value_kind {
            return Err(ProtoError::InvalidInput(
                "server finalize client output value kind does not match projection mode"
                    .to_string(),
            ));
        }
        match packet.allowed_output_kind {
            crate::wire::AllowedOutputKind::ClientOutputOnly => {
                if packet.seed_output.is_some() {
                    return Err(ProtoError::InvalidInput(
                        "server finalize packet must not include seed output for client-only flows"
                            .to_string(),
                    ));
                }
            }
            crate::wire::AllowedOutputKind::ClientOutputAndSeedOutput => {
                if packet.seed_output.is_none() {
                    return Err(ProtoError::InvalidInput(
                        "server finalize packet must include seed output for export flows"
                            .to_string(),
                    ));
                }
            }
        }
        Ok(())
    }

    pub fn decode_server_finalize_message(
        &self,
        output_projection_response_message: &WireMessage,
        server_finalize_message: &WireMessage,
    ) -> ProtoResult<ServerFinalizePacket> {
        let output_projection_response: ServerStageResponsePacket =
            crate::wire::decode_transport_message(
                self.context_binding,
                TransportKind::ServerStageResponse,
                output_projection_response_message,
            )?;
        let packet: ServerFinalizePacket = crate::wire::decode_transport_message(
            self.context_binding,
            TransportKind::ServerFinalize,
            server_finalize_message,
        )?;
        self.validate_server_finalize_packet(&output_projection_response, &packet)?;
        Ok(packet)
    }

    pub fn validate_server_assist_flow_to_output_projection(
        &self,
        client_request_message: &WireMessage,
        evaluator_ot_state: &ClientOtState,
        server_assist_init_message: &WireMessage,
        add_stage_request_message: &WireMessage,
        add_stage_response_message: &WireMessage,
        message_schedule_request_messages: &[WireMessage],
        message_schedule_response_messages: &[WireMessage],
        round_core_request_messages: &[WireMessage],
        round_core_response_messages: &[WireMessage],
        output_projection_request_message: &WireMessage,
        output_projection_response_message: &WireMessage,
    ) -> ProtoResult<ServerStageResponsePacket> {
        if message_schedule_request_messages.len()
            != crate::wire::ServerEvalStageId::MESSAGE_SCHEDULE_ROUNDS as usize
            || message_schedule_response_messages.len()
                != crate::wire::ServerEvalStageId::MESSAGE_SCHEDULE_ROUNDS as usize
        {
            return Err(ProtoError::InvalidInput(
                "message-schedule flow must include every configured round".to_string(),
            ));
        }
        if round_core_request_messages.len()
            != crate::wire::ServerEvalStageId::ROUND_CORE_ROUNDS as usize
            || round_core_response_messages.len()
                != crate::wire::ServerEvalStageId::ROUND_CORE_ROUNDS as usize
        {
            return Err(ProtoError::InvalidInput(
                "round-core flow must include every configured round".to_string(),
            ));
        }

        let mut prior_stage_response = self.decode_add_stage_response_message(
            client_request_message,
            evaluator_ot_state,
            server_assist_init_message,
            add_stage_request_message,
            add_stage_response_message,
        )?;

        for (request_message, response_message) in message_schedule_request_messages
            .iter()
            .zip(message_schedule_response_messages.iter())
        {
            let request: ClientStageRequestPacket = crate::wire::decode_transport_message(
                self.context_binding,
                TransportKind::ClientStageRequest,
                request_message,
            )?;
            let expected_request = self.build_message_schedule_request(&prior_stage_response)?;
            if request != expected_request {
                return Err(ProtoError::InvalidInput(
                    "message-schedule request does not match the expected staged flow".to_string(),
                ));
            }
            prior_stage_response = self.decode_message_schedule_response_message(
                server_assist_init_message,
                request_message,
                response_message,
            )?;
        }

        for (request_message, response_message) in round_core_request_messages
            .iter()
            .zip(round_core_response_messages.iter())
        {
            let request: ClientStageRequestPacket = crate::wire::decode_transport_message(
                self.context_binding,
                TransportKind::ClientStageRequest,
                request_message,
            )?;
            let expected_request = self.build_round_core_request(&prior_stage_response)?;
            if request != expected_request {
                return Err(ProtoError::InvalidInput(
                    "round-core request does not match the expected staged flow".to_string(),
                ));
            }
            prior_stage_response = self.decode_round_core_response_message(
                server_assist_init_message,
                request_message,
                response_message,
            )?;
        }

        let output_request: ClientStageRequestPacket = crate::wire::decode_transport_message(
            self.context_binding,
            TransportKind::ClientStageRequest,
            output_projection_request_message,
        )?;
        let expected_output_request =
            self.build_output_projection_request(&prior_stage_response)?;
        if output_request != expected_output_request {
            return Err(ProtoError::InvalidInput(
                "output-projection request does not match the expected staged flow".to_string(),
            ));
        }

        self.decode_output_projection_response_message(
            server_assist_init_message,
            output_projection_request_message,
            output_projection_response_message,
        )
    }

    pub fn validate_server_assist_flow_to_finalize(
        &self,
        client_request_message: &WireMessage,
        evaluator_ot_state: &ClientOtState,
        server_assist_init_message: &WireMessage,
        add_stage_request_message: &WireMessage,
        add_stage_response_message: &WireMessage,
        message_schedule_request_messages: &[WireMessage],
        message_schedule_response_messages: &[WireMessage],
        round_core_request_messages: &[WireMessage],
        round_core_response_messages: &[WireMessage],
        output_projection_request_message: &WireMessage,
        output_projection_response_message: &WireMessage,
        server_finalize_message: &WireMessage,
    ) -> ProtoResult<ServerFinalizePacket> {
        let _ = self.validate_server_assist_flow_to_output_projection(
            client_request_message,
            evaluator_ot_state,
            server_assist_init_message,
            add_stage_request_message,
            add_stage_response_message,
            message_schedule_request_messages,
            message_schedule_response_messages,
            round_core_request_messages,
            round_core_response_messages,
            output_projection_request_message,
            output_projection_response_message,
        )?;
        self.decode_server_finalize_message(
            output_projection_response_message,
            server_finalize_message,
        )
    }

    pub fn seal_client_output_packet_message(
        &self,
        run_binding: [u8; 32],
        evaluation_digest: [u8; 32],
        bundle: &DdhHssInputShareBundle,
    ) -> ProtoResult<WireMessage> {
        self.seal_client_output_packet_message_with_projection_mode(
            run_binding,
            evaluation_digest,
            OutputProjectionMode::trusted_server_projection(),
            bundle,
        )
    }

    pub fn seal_client_output_packet_message_with_projection_mode(
        &self,
        run_binding: [u8; 32],
        evaluation_digest: [u8; 32],
        projection_mode: OutputProjectionMode,
        bundle: &DdhHssInputShareBundle,
    ) -> ProtoResult<WireMessage> {
        let value_kind = ClientOutputValueKind::for_projection_mode(&projection_mode);
        if bundle.label != value_kind.bundle_label() {
            return Err(ProtoError::InvalidInput(format!(
                "client output bundle label does not match {:?}",
                value_kind
            )));
        }
        let aad = crate::protocol::transcript::client_output_packet_aad(
            self.context_binding,
            run_binding,
            evaluation_digest,
            &projection_mode,
            value_kind,
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
            projection_mode,
            value_kind,
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

    pub fn build_role_separated_output_delivery_packet(
        &self,
        server_eval_handle: ServerEvalHandle,
        final_transcript_digest: [u8; 32],
        allowed_output_kind: crate::wire::AllowedOutputKind,
        artifact: &StagedEvaluatorArtifact,
    ) -> ProtoResult<RoleSeparatedOutputDeliveryPacket> {
        if artifact.context_binding != self.context_binding {
            return Err(ProtoError::InvalidInput(
                "role-separated output delivery context binding does not match evaluator session"
                    .to_string(),
            ));
        }
        let payload = match allowed_output_kind {
            crate::wire::AllowedOutputKind::ClientOutputOnly => {
                RoleSeparatedOutputDeliveryPayload::ClientOutputOnly {
                    client_output: artifact.client_output.clone(),
                    client_output_binding: artifact.client_output_binding,
                }
            }
            crate::wire::AllowedOutputKind::ClientOutputAndSeedOutput => {
                RoleSeparatedOutputDeliveryPayload::ClientOutputAndSeedOutput {
                    client_output: artifact.client_output.clone(),
                    client_output_binding: artifact.client_output_binding,
                    seed_output: artifact.seed_output.clone(),
                    seed_output_binding: artifact.seed_output_binding,
                }
            }
        };
        Ok(RoleSeparatedOutputDeliveryPacket {
            context_binding: self.context_binding,
            server_eval_handle,
            final_transcript_digest,
            bindings: artifact.bindings.clone(),
            projection_mode: artifact.projection_mode.clone(),
            allowed_output_kind,
            payload,
        })
    }

    pub fn build_staged_evaluator_artifact_from_hidden_run(
        &self,
        runtime: &SharedRuntime,
        ddh_run: DdhHiddenEvalRun,
    ) -> ProtoResult<(StagedEvaluatorArtifact, u64, u64)> {
        self.build_staged_evaluator_artifact_from_hidden_eval_outputs(
            runtime,
            ddh_run.client_input_commitment,
            ddh_run.server_input_commitment,
            ddh_run.output,
            None,
        )
    }

    pub fn build_staged_evaluator_artifact_from_hidden_eval_outputs(
        &self,
        runtime: &SharedRuntime,
        client_input_commitment: [u8; 32],
        server_input_commitment: [u8; 32],
        output: crate::ddh::DdhHiddenEvalOutputBundles,
        client_output_mask: Option<[u8; 32]>,
    ) -> ProtoResult<(StagedEvaluatorArtifact, u64, u64)> {
        let result_assembly_started = monotonic_now_ns();
        let run_binding = self.ddh_evaluator.run_binding(
            runtime.artifact.artifact_digest,
            client_input_commitment,
            server_input_commitment,
        );
        let evaluation_digest = crate::protocol::transcript::compute_evaluation_digest(
            runtime.artifact.artifact_digest,
            run_binding,
            &runtime.execution_result,
            &output,
        );
        let projection_mode = match (output.client_output.value_kind, client_output_mask) {
            (ClientOutputValueKind::UnmaskedClientBase, None) => {
                OutputProjectionMode::trusted_server_projection()
            }
            (ClientOutputValueKind::ClientBlindedBase, Some(mask)) => {
                let mask_commitment = crate::protocol::transcript::client_output_mask_commitment(
                    self.context_binding,
                    run_binding,
                    evaluation_digest,
                    mask,
                );
                OutputProjectionMode::client_masked_projection(mask_commitment)
            }
            (ClientOutputValueKind::UnmaskedClientBase, Some(_)) => {
                return Err(ProtoError::InvalidInput(
                    "client output mask requires a blinded client output bundle".to_string(),
                ));
            }
            (ClientOutputValueKind::ClientBlindedBase, None) => {
                return Err(ProtoError::InvalidInput(
                    "blinded client output bundle requires a client output mask".to_string(),
                ));
            }
        };
        let result_assembly_duration_ns = elapsed_ns_u64(result_assembly_started);
        let output_sealing_started = monotonic_now_ns();
        let client_output = self.seal_client_output_packet_message_with_projection_mode(
            run_binding,
            evaluation_digest,
            projection_mode.clone(),
            output.client_output.as_bundle(),
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
            &output.canonical_seed,
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
            &output.x_relayer_base_left,
            &output.x_relayer_base_right,
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
            StagedEvaluatorArtifact {
                backend_version: self.ddh_evaluator.evaluation_key().backend_version,
                context_binding: self.context_binding,
                bindings: RunBindings {
                    client_input_commitment,
                    server_input_commitment,
                    run_binding,
                    evaluation_digest,
                },
                projection_mode,
                output_projector_binding: output.output_projector_binding,
                client_output_value_kind: output.client_output.value_kind,
                client_output_commitment: output.client_output.as_bundle().commitment,
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

    #[cfg(not(target_arch = "wasm32"))]
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
            ddh_run.output.client_output.as_bundle(),
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
                backend_version: self.ddh_evaluator.evaluation_key().backend_version,
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
                projection_mode: OutputProjectionMode::trusted_server_projection(),
                output_projector_binding: ddh_run.output.output_projector_binding,
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
}
