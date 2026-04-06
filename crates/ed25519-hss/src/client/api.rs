use crate::client::{
    ot::build_client_ot_request, ClientDriverState, ClientOtState, ClientOutputOpener,
    ClientSession, ClientSessionState, SeedOutputOpener,
};
use crate::ddh::hidden_eval_executor::DdhHiddenEvalConstantPool;
use crate::ddh::{
    DdhHiddenEvalRun, DdhHssInputShareBundle, DdhHssTransportPurpose,
};
use crate::runtime::{
    evaluation::{elapsed_ns_u64, monotonic_now_ns},
    SharedRuntime,
};
use crate::shared::{ProtoError, ProtoResult};
use crate::wire::{
    AddStageRequestPayload, AddStageResponsePayload, ClientOtOffer, ClientOutputPacket,
    ClientPacket, ClientStageCommitments, ClientStagePayload, ClientStageRequestPacket,
    MessageScheduleRequestPayload, MessageScheduleResponsePayload,
    OutputProjectionRequestPayload, OutputProjectionResponsePayload, RoundCoreRequestPayload,
    RoundCoreResponsePayload, RunBindings, SeedOutputPacket, ServerAssistInitPacket,
    ServerFinalizePacket, ServerStagePayload, ServerStageResponsePacket,
    StagedEvaluatorArtifact, TransportKind, WireMessage,
};
#[cfg(not(target_arch = "wasm32"))]
use crate::wire::{EvaluationReport, EvaluatorWitness, OutputDelivery};
use rand_core::{OsRng, RngCore};

impl ClientSessionState {
    pub fn materialize(&self) -> ClientSession {
        ClientSession {
            context_binding: self.context_binding,
            ddh_evaluator: self.ddh_evaluator.clone(),
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
        crate::client::ot::validate_evaluator_ot_state(self.context_binding, evaluator_ot_state)
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

    pub fn build_add_stage_request(
        &self,
        client_packet: &ClientPacket,
        evaluator_ot_state: &ClientOtState,
        packet: &ServerAssistInitPacket,
    ) -> ProtoResult<ClientStageRequestPacket> {
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

        Ok(ClientStageRequestPacket {
            context_binding: self.context_binding,
            server_eval_handle: packet.server_eval_handle,
            stage_id: crate::wire::ServerEvalStageId::add_stage(),
            prior_transcript_digest,
            client_stage_payload: ClientStagePayload::AddStage(AddStageRequestPayload {
                client_input_commitment,
                client_stage_openings_digest,
                client_stage_nonce,
                y_client_bundle_payload: crate::wire::serialize_encoded_bundle_payload(
                    &y_client_bundle,
                )?,
                tau_client_bundle_payload: crate::wire::serialize_encoded_bundle_payload(
                    &tau_client_bundle,
                )?,
            }),
            client_stage_commitments: ClientStageCommitments {
                digests: vec![client_input_commitment, client_stage_openings_digest],
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
                },
            ),
            client_stage_commitments: ClientStageCommitments {
                digests: vec![final_client_digest, prior_server_stage_digest],
            },
        })
    }

    pub fn prepare_output_projection_request_message(
        &self,
        prior_stage_response_message: &WireMessage,
    ) -> ProtoResult<WireMessage> {
        let prior_stage_response: ServerStageResponsePacket =
            crate::wire::decode_transport_message(
                self.context_binding,
                TransportKind::ServerStageResponse,
                prior_stage_response_message,
            )?;
        let request = self.build_output_projection_request(&prior_stage_response)?;
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
        if response.server_stage_commitments.digests.len() < 3
            || response.server_stage_commitments.digests[2] != *execution_checkpoint_digest
        {
            return Err(ProtoError::InvalidInput(
                "output-projection response execution checkpoint digest is not bound to commitments"
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
        )
    }

    pub fn build_staged_evaluator_artifact_from_hidden_eval_outputs(
        &self,
        runtime: &SharedRuntime,
        client_input_commitment: [u8; 32],
        server_input_commitment: [u8; 32],
        output: crate::ddh::DdhHiddenEvalOutputBundles,
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
        let result_assembly_duration_ns = elapsed_ns_u64(result_assembly_started);
        let output_sealing_started = monotonic_now_ns();
        let client_output = self.seal_client_output_packet_message(
            run_binding,
            evaluation_digest,
            &output.x_client_base,
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
                context_binding: self.context_binding,
                bindings: RunBindings {
                    client_input_commitment,
                    server_input_commitment,
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

}
