use crate::ddh::{DdhHssTransportBundle, DdhHssTransportPurpose};
use crate::runtime::{
    evaluation::{elapsed_ns_u64, monotonic_now_ns, TrustedServerEval},
    EvaluateTiming, SharedRuntime,
};
use crate::server::{
    ot::prepare_garbler_ot_state_for_session, ServerDriverState, ServerOutputOpener, ServerSession,
    ServerSessionState,
};
use crate::shared::ProtoResult;
use crate::wire::{
    deserialize_server_inputs_payload_opened, ClientPacket, EvaluationReport, EvaluationResult,
    OpenedServerInputs, ServerOutputPacket, ServerPacket, TransportKind, WireMessage,
};

impl ServerSessionState {
    pub fn materialize(&self) -> ProtoResult<ServerSession> {
        let prepared_ot_state =
            prepare_garbler_ot_state_for_session(&self.client_ot_offer, &self.garbler_ot_state)?;
        Ok(ServerSession {
            context_binding: self.context_binding,
            ddh_garbler: self.ddh_garbler.clone(),
            client_ot_offer: self.client_ot_offer.clone(),
            garbler_ot_state: self.garbler_ot_state.clone(),
            y_client_sender_words_prepared: prepared_ot_state.y_client_sender_words_prepared,
            tau_client_sender_words_prepared: prepared_ot_state.tau_client_sender_words_prepared,
        })
    }
}

impl ServerDriverState {
    pub fn materialize(&self) -> ProtoResult<(SharedRuntime, ServerSession)> {
        Ok((
            self.runtime.materialize()?,
            self.garbler_session.materialize()?,
        ))
    }
}

impl ServerSession {
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

    pub fn prepare_server_message(
        &self,
        client_request_message: &WireMessage,
        y_relayer: [u8; 32],
        tau_relayer: [u8; 32],
    ) -> ProtoResult<WireMessage> {
        let client_packet: ClientPacket = crate::wire::decode_transport_message(
            self.context_binding,
            TransportKind::ClientOtRequest,
            client_request_message,
        )?;
        let server_packet = self.prepare_server_packet(&client_packet, y_relayer, tau_relayer)?;
        crate::wire::encode_transport_message(
            self.context_binding,
            TransportKind::ServerPacket,
            &server_packet,
        )
    }

    pub fn prepare_server_packet(
        &self,
        client_packet: &ClientPacket,
        y_relayer: [u8; 32],
        tau_relayer: [u8; 32],
    ) -> ProtoResult<ServerPacket> {
        Ok(self
            .prepare_server_packet_with_trusted_inputs(client_packet, y_relayer, tau_relayer)?
            .0)
    }

    pub(crate) fn validate_garbler_ot_state(&self) -> ProtoResult<()> {
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

    pub(crate) fn prepare_trusted_server_eval_timed(
        &self,
        client_packet: &ClientPacket,
        y_relayer: [u8; 32],
        tau_relayer: [u8; 32],
    ) -> ProtoResult<(TrustedServerEval, EvaluateTiming)> {
        crate::protocol::invariants::validate_client_packet_context(
            self.context_binding,
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
        let y_relayer_bundle = self
            .ddh_garbler
            .share_server_input_bit_bundle("y_relayer_bits", &y_relayer)?;
        let tau_relayer_bundle = self
            .ddh_garbler
            .share_server_input_bit_bundle("tau_relayer_bits", &tau_relayer)?;
        timing.server_input_share_duration_ns = elapsed_ns_u64(server_input_share_started);
        let server_input_commitment_started = monotonic_now_ns();
        let server_input_commitment = self.ddh_garbler.combined_input_commitment(
            crate::ddh::HiddenEvalInputOwner::Server,
            &[&y_relayer_bundle, &tau_relayer_bundle],
        );
        timing.server_input_commitment_duration_ns =
            elapsed_ns_u64(server_input_commitment_started);
        let trusted_server_inputs =
            crate::ddh::hidden_eval_executor::DdhHiddenEvalServerInputs::from_joint_bundles(
                &y_relayer_bundle,
                &tau_relayer_bundle,
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
            TrustedServerEval {
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

    pub(crate) fn prepare_server_packet_with_trusted_inputs_timed(
        &self,
        client_packet: &ClientPacket,
        y_relayer: [u8; 32],
        tau_relayer: [u8; 32],
    ) -> ProtoResult<(
        ServerPacket,
        crate::ddh::hidden_eval_executor::DdhHiddenEvalServerInputs,
        EvaluateTiming,
    )> {
        crate::protocol::invariants::validate_client_packet_context(
            self.context_binding,
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
        let y_relayer_bundle = self
            .ddh_garbler
            .share_server_input_bit_bundle("y_relayer_bits", &y_relayer)?;
        let tau_relayer_bundle = self
            .ddh_garbler
            .share_server_input_bit_bundle("tau_relayer_bits", &tau_relayer)?;
        timing.server_input_share_duration_ns = elapsed_ns_u64(server_input_share_started);
        let server_input_commitment_started = monotonic_now_ns();
        let server_input_commitment = self.ddh_garbler.combined_input_commitment(
            crate::ddh::HiddenEvalInputOwner::Server,
            &[&y_relayer_bundle, &tau_relayer_bundle],
        );
        timing.server_input_commitment_duration_ns =
            elapsed_ns_u64(server_input_commitment_started);
        let trusted_server_inputs =
            crate::ddh::hidden_eval_executor::DdhHiddenEvalServerInputs::from_joint_bundles(
                &y_relayer_bundle,
                &tau_relayer_bundle,
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
        let y_relayer_split = self.ddh_garbler.split_share_bundle(&y_relayer_bundle);
        let tau_relayer_split = self.ddh_garbler.split_share_bundle(&tau_relayer_bundle);
        let server_input_seal_started = monotonic_now_ns();
        let sealed_server_inputs = self.seal_server_inputs_packet(
            server_input_commitment,
            &y_relayer_split,
            &tau_relayer_split,
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

    pub(crate) fn prepare_server_packet_with_trusted_inputs(
        &self,
        client_packet: &ClientPacket,
        y_relayer: [u8; 32],
        tau_relayer: [u8; 32],
    ) -> ProtoResult<(
        ServerPacket,
        crate::ddh::hidden_eval_executor::DdhHiddenEvalServerInputs,
    )> {
        let (server_packet, trusted_server_inputs, _timing) = self
            .prepare_server_packet_with_trusted_inputs_timed(
                client_packet,
                y_relayer,
                tau_relayer,
            )?;
        Ok((server_packet, trusted_server_inputs))
    }

    pub fn validate_server_message(&self, server_message: &WireMessage) -> ProtoResult<()> {
        let packet: ServerPacket = crate::wire::decode_transport_message(
            self.context_binding,
            TransportKind::ServerPacket,
            server_message,
        )?;
        self.validate_server_packet(&packet)
    }

    pub fn validate_server_packet(&self, packet: &ServerPacket) -> ProtoResult<()> {
        crate::protocol::invariants::validate_garbler_server_packet(self, packet)
    }

    pub(crate) fn open_server_inputs_packet(
        &self,
        packet: &crate::wire::ServerInputsPacket,
    ) -> ProtoResult<OpenedServerInputs> {
        if packet.context_binding != self.context_binding {
            return Err(crate::shared::ProtoError::InvalidInput(
                "server input packet context binding does not match garbler session".to_string(),
            ));
        }
        let aad = crate::protocol::transcript::server_input_packet_aad(
            packet.context_binding,
            packet.server_input_commitment,
        );
        let plaintext = self.ddh_garbler.open_message(
            DdhHssTransportPurpose::ServerInput,
            &aad,
            packet.nonce,
            &packet.ciphertext,
        )?;
        deserialize_server_inputs_payload_opened(&plaintext)
    }

    pub fn finalize_report_from_evaluation_result_message(
        &self,
        runtime: &SharedRuntime,
        evaluation_result_message: &WireMessage,
    ) -> ProtoResult<EvaluationReport> {
        let evaluation_result: EvaluationResult = crate::wire::decode_transport_message(
            self.context_binding,
            TransportKind::EvaluationResult,
            evaluation_result_message,
        )?;
        runtime.finalize_report_from_evaluation_result(self, &evaluation_result)
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

    pub(crate) fn seal_server_inputs_packet(
        &self,
        server_input_commitment: [u8; 32],
        y_relayer: &(DdhHssTransportBundle, DdhHssTransportBundle),
        tau_relayer: &(DdhHssTransportBundle, DdhHssTransportBundle),
    ) -> ProtoResult<crate::wire::ServerInputsPacket> {
        let aad = crate::protocol::transcript::server_input_packet_aad(
            self.context_binding,
            server_input_commitment,
        );
        let plaintext = crate::wire::serialize_server_inputs_payload(y_relayer, tau_relayer)?;
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
