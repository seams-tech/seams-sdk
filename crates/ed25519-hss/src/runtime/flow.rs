use crate::protocol::PreparedSession;
use crate::runtime::SharedRuntime;
use crate::server::{ServerEvalOperation, ServerEvalState, ServerEvalStatus, ServerOtState};
use crate::shared::{ProtoError, ProtoResult};
use crate::wire::{
    ClientOtOffer, ClientStageRequestPacket, EvaluationReport, OutputProjectionMode,
    RoleSeparatedServerInputDeliveryPacket, ServerAssistInitPacket, StagedEvaluatorArtifact,
    TransportKind, WireMessage,
};

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct ServerEvalAdvanceTimingsMs {
    pub add_stage_response_ms: f64,
    pub message_schedule_rounds_ms: f64,
    pub round_core_rounds_ms: f64,
    pub output_projection_ms: f64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct AdvancedServerEvalState {
    pub state: ServerEvalState,
    pub prior_stage_response_message: WireMessage,
    pub timings: ServerEvalAdvanceTimingsMs,
}

#[derive(Clone, Debug, PartialEq)]
pub struct FinalizedServerEvalState {
    pub state: ServerEvalState,
    pub timings: ServerEvalAdvanceTimingsMs,
}

pub struct PreparedServerAssistFlow {
    pub server_assist_init_message: WireMessage,
    pub add_stage_request_message: WireMessage,
    pub add_stage_response_message: WireMessage,
    pub message_schedule_request_messages: Vec<WireMessage>,
    pub message_schedule_response_messages: Vec<WireMessage>,
    pub round_core_request_messages: Vec<WireMessage>,
    pub round_core_response_messages: Vec<WireMessage>,
    pub output_projection_request_message: WireMessage,
    pub output_projection_response_message: WireMessage,
    pub final_server_eval_state: ServerEvalState,
}

fn elapsed_ms(now_ms: &mut impl FnMut() -> f64, started_ms: f64) -> f64 {
    (now_ms() - started_ms).max(0.0)
}

fn zero_ms() -> f64 {
    0.0
}

pub fn advance_server_eval_state_to_output_projection_request(
    runtime: &SharedRuntime,
    garbler_session: &crate::server::ServerSession,
    evaluator_session: &crate::client::ClientSession,
    server_eval_state: &ServerEvalState,
    add_stage_request_message: &WireMessage,
) -> ProtoResult<AdvancedServerEvalState> {
    advance_server_eval_state_to_output_projection_request_profiled(
        runtime,
        garbler_session,
        evaluator_session,
        server_eval_state,
        add_stage_request_message,
        zero_ms,
    )
}

pub fn advance_server_eval_state_to_output_projection_request_profiled(
    runtime: &SharedRuntime,
    garbler_session: &crate::server::ServerSession,
    evaluator_session: &crate::client::ClientSession,
    server_eval_state: &ServerEvalState,
    add_stage_request_message: &WireMessage,
    mut now_ms: impl FnMut() -> f64,
) -> ProtoResult<AdvancedServerEvalState> {
    if server_eval_state.status == ServerEvalStatus::Finalized {
        return Err(ProtoError::InvalidInput(
            "server eval state is already finalized and cannot be advanced".to_string(),
        ));
    }

    let add_stage_response_started_ms = now_ms();
    let (add_stage_response_message, mut server_eval_state) = garbler_session
        .prepare_add_stage_response_message_with_runtime(
            runtime,
            evaluator_session,
            server_eval_state,
            add_stage_request_message,
        )?;
    let add_stage_response_ms = elapsed_ms(&mut now_ms, add_stage_response_started_ms);
    let mut prior_stage_response_message = add_stage_response_message;
    let hidden_eval_constant_pool = garbler_session.hidden_eval_constant_pool()?;

    let message_schedule_rounds_started_ms = now_ms();
    for _ in 0..crate::wire::ServerEvalStageId::MESSAGE_SCHEDULE_ROUNDS {
        let request_message = evaluator_session
            .prepare_message_schedule_request_message(&prior_stage_response_message)?;
        let (response_message, next_server_eval_state) = garbler_session
            .prepare_message_schedule_response_message_with_pool(
                &server_eval_state,
                &request_message,
                &hidden_eval_constant_pool,
            )?;
        prior_stage_response_message = response_message;
        server_eval_state = next_server_eval_state;
    }
    let message_schedule_rounds_ms = elapsed_ms(&mut now_ms, message_schedule_rounds_started_ms);

    let round_core_rounds_started_ms = now_ms();
    for _ in 0..crate::wire::ServerEvalStageId::ROUND_CORE_ROUNDS {
        let request_message =
            evaluator_session.prepare_round_core_request_message(&prior_stage_response_message)?;
        let (response_message, next_server_eval_state) = garbler_session
            .prepare_round_core_response_message_with_pool(
                &server_eval_state,
                &request_message,
                &hidden_eval_constant_pool,
            )?;
        prior_stage_response_message = response_message;
        server_eval_state = next_server_eval_state;
    }
    let round_core_rounds_ms = elapsed_ms(&mut now_ms, round_core_rounds_started_ms);

    Ok(AdvancedServerEvalState {
        state: server_eval_state,
        prior_stage_response_message,
        timings: ServerEvalAdvanceTimingsMs {
            add_stage_response_ms,
            message_schedule_rounds_ms,
            round_core_rounds_ms,
            output_projection_ms: 0.0,
        },
    })
}

pub fn finalize_advanced_server_eval_state_with_output_projection(
    garbler_session: &crate::server::ServerSession,
    evaluator_session: &crate::client::ClientSession,
    server_eval_state: &ServerEvalState,
    prior_stage_response_message: &WireMessage,
    projection_mode: &OutputProjectionMode,
) -> ProtoResult<FinalizedServerEvalState> {
    finalize_advanced_server_eval_state_with_output_projection_profiled(
        garbler_session,
        evaluator_session,
        server_eval_state,
        prior_stage_response_message,
        projection_mode,
        zero_ms,
    )
}

pub fn finalize_advanced_server_eval_state_with_output_projection_profiled(
    garbler_session: &crate::server::ServerSession,
    evaluator_session: &crate::client::ClientSession,
    server_eval_state: &ServerEvalState,
    prior_stage_response_message: &WireMessage,
    projection_mode: &OutputProjectionMode,
    mut now_ms: impl FnMut() -> f64,
) -> ProtoResult<FinalizedServerEvalState> {
    let output_projection_started_ms = now_ms();
    let output_projection_request_message = evaluator_session
        .prepare_output_projection_request_message_with_projection_mode(
            prior_stage_response_message,
            projection_mode,
        )?;
    let hidden_eval_constant_pool = garbler_session.hidden_eval_constant_pool()?;
    let (_output_projection_response_message, final_server_eval_state) = garbler_session
        .prepare_output_projection_response_message_with_pool(
            server_eval_state,
            &output_projection_request_message,
            &hidden_eval_constant_pool,
        )?;
    let output_projection_ms = elapsed_ms(&mut now_ms, output_projection_started_ms);
    Ok(FinalizedServerEvalState {
        state: final_server_eval_state,
        timings: ServerEvalAdvanceTimingsMs {
            output_projection_ms,
            ..ServerEvalAdvanceTimingsMs::default()
        },
    })
}

pub fn finalize_server_eval_state_from_add_stage_request(
    runtime: &SharedRuntime,
    garbler_session: &crate::server::ServerSession,
    evaluator_session: &crate::client::ClientSession,
    server_eval_state: &ServerEvalState,
    add_stage_request_message: &WireMessage,
    projection_mode: &OutputProjectionMode,
) -> ProtoResult<FinalizedServerEvalState> {
    finalize_server_eval_state_from_add_stage_request_profiled(
        runtime,
        garbler_session,
        evaluator_session,
        server_eval_state,
        add_stage_request_message,
        projection_mode,
        zero_ms,
    )
}

pub fn finalize_server_eval_state_from_add_stage_request_profiled(
    runtime: &SharedRuntime,
    garbler_session: &crate::server::ServerSession,
    evaluator_session: &crate::client::ClientSession,
    server_eval_state: &ServerEvalState,
    add_stage_request_message: &WireMessage,
    projection_mode: &OutputProjectionMode,
    mut now_ms: impl FnMut() -> f64,
) -> ProtoResult<FinalizedServerEvalState> {
    if server_eval_state.status == ServerEvalStatus::Finalized {
        return Ok(FinalizedServerEvalState {
            state: server_eval_state.clone(),
            timings: ServerEvalAdvanceTimingsMs::default(),
        });
    }

    let advanced = advance_server_eval_state_to_output_projection_request_profiled(
        runtime,
        garbler_session,
        evaluator_session,
        server_eval_state,
        add_stage_request_message,
        &mut now_ms,
    )?;
    let finalized = finalize_advanced_server_eval_state_with_output_projection_profiled(
        garbler_session,
        evaluator_session,
        &advanced.state,
        &advanced.prior_stage_response_message,
        projection_mode,
        &mut now_ms,
    )?;
    Ok(FinalizedServerEvalState {
        state: finalized.state,
        timings: ServerEvalAdvanceTimingsMs {
            add_stage_response_ms: advanced.timings.add_stage_response_ms,
            message_schedule_rounds_ms: advanced.timings.message_schedule_rounds_ms,
            round_core_rounds_ms: advanced.timings.round_core_rounds_ms,
            output_projection_ms: finalized.timings.output_projection_ms,
        },
    })
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

    pub fn prepare_server_assist_init_message(
        &self,
        garbler_ot_state: &ServerOtState,
        client_request_message: &WireMessage,
        y_server: [u8; 32],
        tau_server: [u8; 32],
        operation: ServerEvalOperation,
    ) -> ProtoResult<(WireMessage, ServerEvalState)> {
        let garbler_session = self.garbler_session();
        self.validate_garbler_ot_state(garbler_ot_state, &garbler_session.client_ot_offer)?;
        garbler_session.prepare_server_assist_init_message(
            client_request_message,
            y_server,
            tau_server,
            operation,
        )
    }

    pub fn prepare_add_stage_request_message(
        &self,
        client_request_message: &WireMessage,
        evaluator_ot_state: &crate::client::ClientOtState,
        server_assist_init_message: &WireMessage,
    ) -> ProtoResult<WireMessage> {
        self.evaluator_session().prepare_add_stage_request_message(
            client_request_message,
            evaluator_ot_state,
            server_assist_init_message,
        )
    }

    pub fn prepare_add_stage_response_message(
        &self,
        server_eval_state: &ServerEvalState,
        client_stage_request_message: &WireMessage,
    ) -> ProtoResult<(WireMessage, ServerEvalState)> {
        let mut server_eval_state = server_eval_state.clone();
        if server_eval_state.execution_state.is_none() {
            let request: ClientStageRequestPacket = crate::wire::decode_transport_message(
                self.candidate().context_binding,
                crate::wire::TransportKind::ClientStageRequest,
                client_stage_request_message,
            )?;
            server_eval_state = self
                .garbler_session()
                .materialize_execution_state_from_add_stage_request(
                    &self.shared_runtime(),
                    &self.evaluator_session(),
                    &server_eval_state,
                    &request,
                )?;
        }
        self.garbler_session()
            .prepare_add_stage_response_message(&server_eval_state, client_stage_request_message)
    }

    pub fn prepare_message_schedule_request_message(
        &self,
        prior_stage_response_message: &WireMessage,
    ) -> ProtoResult<WireMessage> {
        self.evaluator_session()
            .prepare_message_schedule_request_message(prior_stage_response_message)
    }

    pub fn prepare_message_schedule_response_message(
        &self,
        server_eval_state: &ServerEvalState,
        client_stage_request_message: &WireMessage,
    ) -> ProtoResult<(WireMessage, ServerEvalState)> {
        self.garbler_session()
            .prepare_message_schedule_response_message(
                server_eval_state,
                client_stage_request_message,
            )
    }

    pub fn prepare_round_core_request_message(
        &self,
        prior_stage_response_message: &WireMessage,
    ) -> ProtoResult<WireMessage> {
        self.evaluator_session()
            .prepare_round_core_request_message(prior_stage_response_message)
    }

    pub fn prepare_round_core_response_message(
        &self,
        server_eval_state: &ServerEvalState,
        client_stage_request_message: &WireMessage,
    ) -> ProtoResult<(WireMessage, ServerEvalState)> {
        self.garbler_session()
            .prepare_round_core_response_message(server_eval_state, client_stage_request_message)
    }

    pub fn prepare_output_projection_request_message(
        &self,
        prior_stage_response_message: &WireMessage,
    ) -> ProtoResult<WireMessage> {
        self.evaluator_session()
            .prepare_output_projection_request_message_with_projection_mode(
                prior_stage_response_message,
                self.output_projection_mode(),
            )
    }

    pub fn prepare_output_projection_response_message(
        &self,
        server_eval_state: &ServerEvalState,
        client_stage_request_message: &WireMessage,
    ) -> ProtoResult<(WireMessage, ServerEvalState)> {
        self.garbler_session()
            .prepare_output_projection_response_message(
                server_eval_state,
                client_stage_request_message,
            )
    }

    pub fn prepare_server_assist_flow_to_output_projection(
        &self,
        garbler_ot_state: &ServerOtState,
        client_request_message: &WireMessage,
        evaluator_ot_state: &crate::client::ClientOtState,
        y_server: [u8; 32],
        tau_server: [u8; 32],
        operation: ServerEvalOperation,
    ) -> ProtoResult<PreparedServerAssistFlow> {
        let (server_assist_init_message, server_eval_state) = self
            .prepare_server_assist_init_message(
                garbler_ot_state,
                client_request_message,
                y_server,
                tau_server,
                operation,
            )?;
        self.prepare_server_assist_flow_to_output_projection_from_server_assist_init(
            &server_eval_state,
            client_request_message,
            evaluator_ot_state,
            server_assist_init_message,
        )
    }

    pub fn prepare_server_assist_flow_to_output_projection_from_role_separated_delivery(
        &self,
        server_eval_state: &ServerEvalState,
        client_request_message: &WireMessage,
        evaluator_ot_state: &crate::client::ClientOtState,
        delivery: &RoleSeparatedServerInputDeliveryPacket,
    ) -> ProtoResult<PreparedServerAssistFlow> {
        if delivery.context_binding != server_eval_state.context_binding {
            return Err(ProtoError::InvalidInput(
                "role-separated delivery context binding does not match server eval state"
                    .to_string(),
            ));
        }
        if delivery.server_eval_handle != server_eval_state.handle {
            return Err(ProtoError::InvalidInput(
                "role-separated delivery handle does not match server eval state".to_string(),
            ));
        }
        if delivery.transcript_id != server_eval_state.transcript_id {
            return Err(ProtoError::InvalidInput(
                "role-separated delivery transcript id does not match server eval state"
                    .to_string(),
            ));
        }
        if delivery.server_input_commitment != server_eval_state.server_input_commitment {
            return Err(ProtoError::InvalidInput(
                "role-separated delivery server input commitment does not match server eval state"
                    .to_string(),
            ));
        }
        let server_assist_init = ServerAssistInitPacket::from_role_separated_delivery(delivery);
        let server_assist_init_message = crate::wire::encode_transport_message(
            self.candidate().context_binding,
            TransportKind::ServerAssistInit,
            &server_assist_init,
        )?;
        self.prepare_server_assist_flow_to_output_projection_from_server_assist_init(
            server_eval_state,
            client_request_message,
            evaluator_ot_state,
            server_assist_init_message,
        )
    }

    pub fn prepare_server_assist_flow_to_output_projection_from_server_assist_init(
        &self,
        server_eval_state: &ServerEvalState,
        client_request_message: &WireMessage,
        evaluator_ot_state: &crate::client::ClientOtState,
        server_assist_init_message: WireMessage,
    ) -> ProtoResult<PreparedServerAssistFlow> {
        let mut server_eval_state = server_eval_state.clone();
        let add_stage_request_message = self.prepare_add_stage_request_message(
            client_request_message,
            evaluator_ot_state,
            &server_assist_init_message,
        )?;
        let (add_stage_response_message, next_server_eval_state) = self
            .prepare_add_stage_response_message(&server_eval_state, &add_stage_request_message)?;
        server_eval_state = next_server_eval_state;
        let hidden_eval_constant_pool = self.garbler_session().hidden_eval_constant_pool()?;

        let mut message_schedule_request_messages =
            Vec::with_capacity(crate::wire::ServerEvalStageId::MESSAGE_SCHEDULE_ROUNDS as usize);
        let mut message_schedule_response_messages =
            Vec::with_capacity(crate::wire::ServerEvalStageId::MESSAGE_SCHEDULE_ROUNDS as usize);
        let mut prior_stage_response_message = add_stage_response_message.clone();
        for _ in 0..crate::wire::ServerEvalStageId::MESSAGE_SCHEDULE_ROUNDS {
            let request_message =
                self.prepare_message_schedule_request_message(&prior_stage_response_message)?;
            let (response_message, next_server_eval_state) = self
                .garbler_session()
                .prepare_message_schedule_response_message_with_pool(
                    &server_eval_state,
                    &request_message,
                    &hidden_eval_constant_pool,
                )?;
            message_schedule_request_messages.push(request_message);
            message_schedule_response_messages.push(response_message.clone());
            prior_stage_response_message = response_message;
            server_eval_state = next_server_eval_state;
        }

        let mut round_core_request_messages =
            Vec::with_capacity(crate::wire::ServerEvalStageId::ROUND_CORE_ROUNDS as usize);
        let mut round_core_response_messages =
            Vec::with_capacity(crate::wire::ServerEvalStageId::ROUND_CORE_ROUNDS as usize);
        for _ in 0..crate::wire::ServerEvalStageId::ROUND_CORE_ROUNDS {
            let request_message =
                self.prepare_round_core_request_message(&prior_stage_response_message)?;
            let (response_message, next_server_eval_state) = self
                .garbler_session()
                .prepare_round_core_response_message_with_pool(
                    &server_eval_state,
                    &request_message,
                    &hidden_eval_constant_pool,
                )?;
            round_core_request_messages.push(request_message);
            round_core_response_messages.push(response_message.clone());
            prior_stage_response_message = response_message;
            server_eval_state = next_server_eval_state;
        }

        let output_projection_request_message =
            self.prepare_output_projection_request_message(&prior_stage_response_message)?;
        let (output_projection_response_message, final_server_eval_state) = self
            .garbler_session()
            .prepare_output_projection_response_message_with_pool(
                &server_eval_state,
                &output_projection_request_message,
                &hidden_eval_constant_pool,
            )?;

        Ok(PreparedServerAssistFlow {
            server_assist_init_message,
            add_stage_request_message,
            add_stage_response_message,
            message_schedule_request_messages,
            message_schedule_response_messages,
            round_core_request_messages,
            round_core_response_messages,
            output_projection_request_message,
            output_projection_response_message,
            final_server_eval_state,
        })
    }

    pub fn build_server_owned_staged_evaluator_artifact_from_transport_messages(
        &self,
        garbler_ot_state: &ServerOtState,
        client_request_message: &WireMessage,
        evaluator_ot_state: &crate::client::ClientOtState,
        y_server: [u8; 32],
        tau_server: [u8; 32],
        operation: ServerEvalOperation,
    ) -> ProtoResult<StagedEvaluatorArtifact> {
        let flow = self.prepare_server_assist_flow_to_output_projection(
            garbler_ot_state,
            client_request_message,
            evaluator_ot_state,
            y_server,
            tau_server,
            operation,
        )?;
        self.build_server_owned_staged_evaluator_artifact_from_server_eval_state(
            &flow.final_server_eval_state,
        )
    }

    pub fn build_server_owned_staged_evaluator_artifact_from_server_eval_state(
        &self,
        server_eval_state: &ServerEvalState,
    ) -> ProtoResult<StagedEvaluatorArtifact> {
        let _ = server_eval_state.finalize_state().ok_or_else(|| {
            ProtoError::InvalidInput(
                "staged flow did not materialize server finalize state".to_string(),
            )
        })?;
        Err(ProtoError::InvalidInput(
            "server-owned staged evaluator artifacts are no longer materialized from finalize state; use client-owned materialization from role-separated delivery".to_string(),
        ))
    }

    pub fn validate_server_assist_flow_to_output_projection(
        &self,
        client_request_message: &WireMessage,
        evaluator_ot_state: &crate::client::ClientOtState,
        flow: &PreparedServerAssistFlow,
    ) -> ProtoResult<crate::wire::ServerStageResponsePacket> {
        self.evaluator_session()
            .validate_server_assist_flow_to_output_projection(
                client_request_message,
                evaluator_ot_state,
                &flow.server_assist_init_message,
                &flow.add_stage_request_message,
                &flow.add_stage_response_message,
                &flow.message_schedule_request_messages,
                &flow.message_schedule_response_messages,
                &flow.round_core_request_messages,
                &flow.round_core_response_messages,
                &flow.output_projection_request_message,
                &flow.output_projection_response_message,
            )
    }

    pub fn prepare_server_finalize_message_from_staged_evaluator_artifact(
        &self,
        runtime: &SharedRuntime,
        server_eval_state: &ServerEvalState,
        artifact: &StagedEvaluatorArtifact,
    ) -> ProtoResult<(WireMessage, EvaluationReport)> {
        self.garbler_session()
            .prepare_server_finalize_message_from_staged_evaluator_artifact(
                runtime,
                server_eval_state,
                artifact,
            )
    }

    pub fn prepare_server_finalize_from_staged_evaluator_artifact(
        &self,
        runtime: &SharedRuntime,
        server_eval_state: &ServerEvalState,
        artifact: &crate::wire::StagedEvaluatorArtifact,
    ) -> ProtoResult<(crate::wire::ServerFinalizePacket, EvaluationReport)> {
        self.garbler_session()
            .prepare_server_finalize_packet_from_staged_evaluator_artifact(
                runtime,
                server_eval_state,
                artifact,
            )
    }

    pub fn validate_server_assist_flow_to_finalize(
        &self,
        client_request_message: &WireMessage,
        evaluator_ot_state: &crate::client::ClientOtState,
        flow: &PreparedServerAssistFlow,
        server_finalize_message: &WireMessage,
    ) -> ProtoResult<crate::wire::ServerFinalizePacket> {
        self.evaluator_session()
            .validate_server_assist_flow_to_finalize(
                client_request_message,
                evaluator_ot_state,
                &flow.server_assist_init_message,
                &flow.add_stage_request_message,
                &flow.add_stage_response_message,
                &flow.message_schedule_request_messages,
                &flow.message_schedule_response_messages,
                &flow.round_core_request_messages,
                &flow.round_core_response_messages,
                &flow.output_projection_request_message,
                &flow.output_projection_response_message,
                server_finalize_message,
            )
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
