use ed25519_hss::fixtures::deterministic_fixture_corpus;
use ed25519_hss::protocol::prepare_prime_order_succinct_hss;
use ed25519_hss::runtime::flow::PreparedServerAssistFlow;
use ed25519_hss::server::ServerEvalOperation;
use ed25519_hss::wire::{
    ClientStageRequestPacket, ServerAssistInitPacket, ServerStageResponsePacket,
};

use crate::support::{
    contains_subslice, decode_server_input_delivery, decode_transport_message,
    TransportKind,
};

fn boundary_fixture() -> ed25519_hss::fixtures::FExpandFixture {
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
                && has_entropy(&fixture.input.y_relayer)
                && has_entropy(&fixture.input.tau_relayer)
        })
        .expect("non-degenerate boundary fixture")
}

fn second_boundary_fixture() -> ed25519_hss::fixtures::FExpandFixture {
    let fixtures = deterministic_fixture_corpus().expect("fixture corpus");
    let primary = boundary_fixture();
    let has_entropy = |bytes: &[u8; 32]| {
        let distinct = bytes
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>();
        distinct.len() >= 8
    };
    fixtures
        .into_iter()
        .find(|fixture| {
            fixture.input.context != primary.input.context
                && has_entropy(&fixture.input.y_client)
                && has_entropy(&fixture.input.tau_client)
                && has_entropy(&fixture.input.y_relayer)
                && has_entropy(&fixture.input.tau_relayer)
        })
        .expect("fixture with distinct context")
}

fn extend_staged_flow_bytes(
    accumulated_bytes: &mut Vec<u8>,
    client_request_message: &ed25519_hss::wire::WireMessage,
    flow: &PreparedServerAssistFlow,
) {
    for bytes in [
        client_request_message.bytes.as_slice(),
        flow.server_assist_init_message.bytes.as_slice(),
        flow.add_stage_request_message.bytes.as_slice(),
        flow.add_stage_response_message.bytes.as_slice(),
        flow.output_projection_request_message.bytes.as_slice(),
        flow.output_projection_response_message.bytes.as_slice(),
    ] {
        accumulated_bytes.extend_from_slice(bytes);
    }
    for message in &flow.message_schedule_request_messages {
        accumulated_bytes.extend_from_slice(&message.bytes);
    }
    for message in &flow.message_schedule_response_messages {
        accumulated_bytes.extend_from_slice(&message.bytes);
    }
    for message in &flow.round_core_request_messages {
        accumulated_bytes.extend_from_slice(&message.bytes);
    }
    for message in &flow.round_core_response_messages {
        accumulated_bytes.extend_from_slice(&message.bytes);
    }
}

fn assert_staged_flow_messages_do_not_drive_legacy_decoder(
    session: &ed25519_hss::protocol::PreparedSession,
    flow: &PreparedServerAssistFlow,
) {
    for (label, message) in [
        ("server_assist_init", &flow.server_assist_init_message),
        ("add_stage_response", &flow.add_stage_response_message),
        (
            "final_message_schedule_response",
            flow.message_schedule_response_messages
                .last()
                .expect("message-schedule response"),
        ),
        (
            "final_round_core_response",
            flow.round_core_response_messages
                .last()
                .expect("round-core response"),
        ),
        (
            "output_projection_response",
            &flow.output_projection_response_message,
        ),
    ] {
        assert!(
            decode_server_input_delivery(session, message).is_err(),
            "{label} must not reconstruct relayer roots through the legacy server-input decoder",
        );
    }
}

#[test]
fn evaluator_driver_state_serialization_excludes_garbler_sender_state() {
    let fixture = boundary_fixture();
    let session =
        prepare_prime_order_succinct_hss(&fixture.input.context).expect("prepare session");

    let evaluator_driver_state_json = serde_json::to_string(&session.evaluator_driver_state())
        .expect("serialize evaluator state");

    assert!(
        !evaluator_driver_state_json.contains("garbler_ot_state"),
        "evaluator driver state must not expose garbler OT state",
    );
    assert!(
        !evaluator_driver_state_json.contains("y_client_sender_state"),
        "evaluator driver state must not expose garbler sender-state material",
    );
    assert!(
        !evaluator_driver_state_json.contains("tau_client_sender_state"),
        "evaluator driver state must not expose garbler sender-state material",
    );
    assert!(
        !evaluator_driver_state_json.contains("ddh_garbler"),
        "evaluator driver state must not expose garbler DDH state",
    );
}

#[test]
fn evaluator_runtime_state_serialization_does_not_embed_relayer_roots_or_joined_input_artifacts() {
    let fixture = boundary_fixture();
    let session =
        prepare_prime_order_succinct_hss(&fixture.input.context).expect("prepare session");

    let evaluator_driver_state = session.evaluator_driver_state();
    let client_runtime_state = session.client_runtime_state();

    let serialized_surfaces = [
        serde_json::to_vec(&evaluator_driver_state).expect("serialize evaluator driver state json"),
        bincode::serialize(&evaluator_driver_state)
            .expect("serialize evaluator driver state bincode"),
        serde_json::to_vec(&client_runtime_state).expect("serialize client runtime state json"),
        bincode::serialize(&client_runtime_state).expect("serialize client runtime state bincode"),
    ];

    for bytes in serialized_surfaces {
        assert!(
            !contains_subslice(&bytes, &fixture.input.y_relayer),
            "serialized evaluator-visible runtime state must not embed clear y_relayer bytes",
        );
        assert!(
            !contains_subslice(&bytes, &fixture.input.tau_relayer),
            "serialized evaluator-visible runtime state must not embed clear tau_relayer bytes",
        );
    }

    let evaluator_driver_state_json =
        serde_json::to_string(&evaluator_driver_state).expect("serialize evaluator driver state");
    let client_runtime_state_json =
        serde_json::to_string(&client_runtime_state).expect("serialize client runtime state");

    for json in [&evaluator_driver_state_json, &client_runtime_state_json] {
        assert!(
            !json.contains("server_inputs"),
            "evaluator-visible runtime state must not expose joined server-input packets",
        );
        assert!(
            !json.contains("trusted_server_inputs"),
            "evaluator-visible runtime state must not expose trusted joined server inputs",
        );
        assert!(
            !json.contains("OpenedServerInputs"),
            "evaluator-visible runtime state must not expose opened joined server inputs",
        );
        assert!(
            !json.contains("TrustedServerEval"),
            "evaluator-visible runtime state must not expose trusted joined-input helpers",
        );
    }
}

#[test]
fn wire_messages_do_not_embed_clear_client_or_server_inputs() {
    let fixture = boundary_fixture();
    let session =
        prepare_prime_order_succinct_hss(&fixture.input.context).expect("prepare session");
    let client_ot_offer_message = session
        .prepare_client_ot_offer_message()
        .expect("prepare client OT offer");
    let garbler_ot_state = session
        .prepare_garbler_ot_state()
        .expect("prepare garbler ot state");
    let (client_request_message, evaluator_ot_state) = session
        .prepare_client_ot_request_from_offer_message(
            &client_ot_offer_message,
            fixture.input.y_client,
            fixture.input.tau_client,
        )
        .expect("prepare client request");
    let flow = session
        .prepare_server_assist_flow_to_output_projection(
            &garbler_ot_state,
            &client_request_message,
            &evaluator_ot_state,
            fixture.input.y_relayer,
            fixture.input.tau_relayer,
            ServerEvalOperation::Registration,
        )
        .expect("prepare staged assist flow");
    let runtime = session.shared_runtime();
    let staged_evaluator_artifact = session
        .build_server_owned_staged_evaluator_artifact_from_server_eval_state(
            &flow.final_server_eval_state,
        )
        .expect("build staged evaluator artifact");
    let (server_finalize_message, _report) = session
        .prepare_server_finalize_message_from_staged_evaluator_artifact(
            &runtime,
            &flow.final_server_eval_state,
            &staged_evaluator_artifact,
        )
        .expect("prepare server finalize message");

    let mut messages: Vec<(&str, &[u8])> = vec![
        ("client_ot_offer", client_ot_offer_message.bytes.as_slice()),
        ("client_request", client_request_message.bytes.as_slice()),
        (
            "server_assist_init",
            flow.server_assist_init_message.bytes.as_slice(),
        ),
        (
            "add_stage_request",
            flow.add_stage_request_message.bytes.as_slice(),
        ),
        (
            "add_stage_response",
            flow.add_stage_response_message.bytes.as_slice(),
        ),
        (
            "output_projection_request",
            flow.output_projection_request_message.bytes.as_slice(),
        ),
        (
            "output_projection_response",
            flow.output_projection_response_message.bytes.as_slice(),
        ),
        ("server_finalize", server_finalize_message.bytes.as_slice()),
    ];
    for message in &flow.message_schedule_request_messages {
        messages.push(("message_schedule_request", message.bytes.as_slice()));
    }
    for message in &flow.message_schedule_response_messages {
        messages.push(("message_schedule_response", message.bytes.as_slice()));
    }
    for message in &flow.round_core_request_messages {
        messages.push(("round_core_request", message.bytes.as_slice()));
    }
    for message in &flow.round_core_response_messages {
        messages.push(("round_core_response", message.bytes.as_slice()));
    }

    for (label, message_bytes) in messages {
        assert!(
            !contains_subslice(message_bytes, &fixture.input.y_client),
            "{label} must not embed clear y_client bytes",
        );
        assert!(
            !contains_subslice(message_bytes, &fixture.input.tau_client),
            "{label} must not embed clear tau_client bytes",
        );
        assert!(
            !contains_subslice(message_bytes, &fixture.input.y_relayer),
            "{label} must not embed clear y_relayer bytes",
        );
        assert!(
            !contains_subslice(message_bytes, &fixture.input.tau_relayer),
            "{label} must not embed clear tau_relayer bytes",
        );
    }
}

#[test]
fn server_assist_init_message_validates_without_exposing_clear_relayer_roots() {
    let fixture = boundary_fixture();
    let session =
        prepare_prime_order_succinct_hss(&fixture.input.context).expect("prepare session");
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

    let (server_assist_init_message, server_eval_state) = garbler_session
        .prepare_server_assist_init_message(
            &client_request_message,
            fixture.input.y_relayer,
            fixture.input.tau_relayer,
            ServerEvalOperation::Registration,
        )
        .expect("prepare server assist init message");

    let packet = evaluator_session
        .decode_server_assist_init_message(
            &client_request_message,
            &evaluator_ot_state,
            &server_assist_init_message,
        )
        .expect("decode and validate server assist init");

    assert_eq!(packet.server_eval_handle, server_eval_state.handle);
    assert_eq!(packet.transcript_id, server_eval_state.transcript_id);
    assert_eq!(
        packet.server_input_commitment,
        server_eval_state.server_input_commitment,
    );
    assert!(
        !contains_subslice(&server_assist_init_message.bytes, &fixture.input.y_relayer),
        "server assist init message must not embed clear y_relayer bytes",
    );
    assert!(
        !contains_subslice(
            &server_assist_init_message.bytes,
            &fixture.input.tau_relayer
        ),
        "server assist init message must not embed clear tau_relayer bytes",
    );
}

#[test]
fn add_stage_round_advances_handle_without_exposing_clear_relayer_roots() {
    let fixture = boundary_fixture();
    let session =
        prepare_prime_order_succinct_hss(&fixture.input.context).expect("prepare session");
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

    let (server_assist_init_message, server_eval_state) = garbler_session
        .prepare_server_assist_init_message(
            &client_request_message,
            fixture.input.y_relayer,
            fixture.input.tau_relayer,
            ServerEvalOperation::Registration,
        )
        .expect("prepare server assist init message");

    let client_stage_request_message = evaluator_session
        .prepare_add_stage_request_message(
            &client_request_message,
            &evaluator_ot_state,
            &server_assist_init_message,
        )
        .expect("prepare add-stage request message");

    let (server_stage_response_message, next_server_eval_state) = garbler_session
        .prepare_add_stage_response_message(&server_eval_state, &client_stage_request_message)
        .expect("prepare add-stage response message");

    let response = evaluator_session
        .decode_add_stage_response_message(
            &client_request_message,
            &evaluator_ot_state,
            &server_assist_init_message,
            &client_stage_request_message,
            &server_stage_response_message,
        )
        .expect("decode add-stage response message");

    assert_eq!(
        next_server_eval_state.current_stage,
        ed25519_hss::wire::ServerEvalStageId::message_schedule(0),
    );
    assert_eq!(
        next_server_eval_state.current_transcript_digest,
        response.next_transcript_digest,
    );
    assert!(
        !contains_subslice(
            &client_stage_request_message.bytes,
            &fixture.input.y_relayer
        ),
        "client add-stage request must not embed clear y_relayer bytes",
    );
    assert!(
        !contains_subslice(
            &client_stage_request_message.bytes,
            &fixture.input.tau_relayer
        ),
        "client add-stage request must not embed clear tau_relayer bytes",
    );
    assert!(
        !contains_subslice(
            &server_stage_response_message.bytes,
            &fixture.input.y_relayer
        ),
        "server add-stage response must not embed clear y_relayer bytes",
    );
    assert!(
        !contains_subslice(
            &server_stage_response_message.bytes,
            &fixture.input.tau_relayer
        ),
        "server add-stage response must not embed clear tau_relayer bytes",
    );
}

#[test]
fn message_schedule_round_advances_handle_without_exposing_clear_relayer_roots() {
    let fixture = boundary_fixture();
    let session =
        prepare_prime_order_succinct_hss(&fixture.input.context).expect("prepare session");
    let client_ot_offer_message = session
        .prepare_client_ot_offer_message()
        .expect("client ot offer message");
    let garbler_ot_state = session
        .prepare_garbler_ot_state()
        .expect("garbler ot state");
    let (client_request_message, evaluator_ot_state) = session
        .prepare_client_ot_request_from_offer_message(
            &client_ot_offer_message,
            fixture.input.y_client,
            fixture.input.tau_client,
        )
        .expect("prepare client request from offer");

    let evaluator_session = session.evaluator_session();

    let (server_assist_init_message, server_eval_state) = session
        .prepare_server_assist_init_message(
            &garbler_ot_state,
            &client_request_message,
            fixture.input.y_relayer,
            fixture.input.tau_relayer,
            ServerEvalOperation::Registration,
        )
        .expect("prepare server assist init message");

    let client_add_stage_request_message = session
        .prepare_add_stage_request_message(
            &client_request_message,
            &evaluator_ot_state,
            &server_assist_init_message,
        )
        .expect("prepare add-stage request message");

    let (server_add_stage_response_message, next_server_eval_state) = session
        .prepare_add_stage_response_message(&server_eval_state, &client_add_stage_request_message)
        .expect("prepare add-stage response message");

    let client_message_schedule_request_message = session
        .prepare_message_schedule_request_message(&server_add_stage_response_message)
        .expect("prepare message-schedule request message");

    let (server_message_schedule_response_message, final_server_eval_state) = session
        .prepare_message_schedule_response_message(
            &next_server_eval_state,
            &client_message_schedule_request_message,
        )
        .expect("prepare message-schedule response message");

    let response = evaluator_session
        .decode_message_schedule_response_message(
            &server_assist_init_message,
            &client_message_schedule_request_message,
            &server_message_schedule_response_message,
        )
        .expect("decode message-schedule response message");

    assert_eq!(
        final_server_eval_state.current_stage,
        ed25519_hss::wire::ServerEvalStageId::message_schedule(1),
    );
    assert_eq!(
        final_server_eval_state.current_transcript_digest,
        response.next_transcript_digest,
    );
    assert!(
        !contains_subslice(
            &client_message_schedule_request_message.bytes,
            &fixture.input.y_relayer
        ),
        "client message-schedule request must not embed clear y_relayer bytes",
    );
    assert!(
        !contains_subslice(
            &client_message_schedule_request_message.bytes,
            &fixture.input.tau_relayer
        ),
        "client message-schedule request must not embed clear tau_relayer bytes",
    );
    assert!(
        !contains_subslice(
            &server_message_schedule_response_message.bytes,
            &fixture.input.y_relayer
        ),
        "server message-schedule response must not embed clear y_relayer bytes",
    );
    assert!(
        !contains_subslice(
            &server_message_schedule_response_message.bytes,
            &fixture.input.tau_relayer
        ),
        "server message-schedule response must not embed clear tau_relayer bytes",
    );
}

#[test]
fn message_schedule_round_can_repeat_without_exposing_clear_relayer_roots() {
    let fixture = boundary_fixture();
    let session =
        prepare_prime_order_succinct_hss(&fixture.input.context).expect("prepare session");
    let client_ot_offer_message = session
        .prepare_client_ot_offer_message()
        .expect("client ot offer message");
    let garbler_ot_state = session
        .prepare_garbler_ot_state()
        .expect("garbler ot state");
    let (client_request_message, evaluator_ot_state) = session
        .prepare_client_ot_request_from_offer_message(
            &client_ot_offer_message,
            fixture.input.y_client,
            fixture.input.tau_client,
        )
        .expect("prepare client request from offer");

    let evaluator_session = session.evaluator_session();

    let (server_assist_init_message, server_eval_state) = session
        .prepare_server_assist_init_message(
            &garbler_ot_state,
            &client_request_message,
            fixture.input.y_relayer,
            fixture.input.tau_relayer,
            ServerEvalOperation::Registration,
        )
        .expect("prepare server assist init message");

    let client_add_stage_request_message = session
        .prepare_add_stage_request_message(
            &client_request_message,
            &evaluator_ot_state,
            &server_assist_init_message,
        )
        .expect("prepare add-stage request message");

    let (server_add_stage_response_message, next_server_eval_state) = session
        .prepare_add_stage_response_message(&server_eval_state, &client_add_stage_request_message)
        .expect("prepare add-stage response message");

    let client_message_schedule_request_0 = session
        .prepare_message_schedule_request_message(&server_add_stage_response_message)
        .expect("prepare first message-schedule request");
    let (server_message_schedule_response_0, next_server_eval_state) = session
        .prepare_message_schedule_response_message(
            &next_server_eval_state,
            &client_message_schedule_request_0,
        )
        .expect("prepare first message-schedule response");

    let response_0 = evaluator_session
        .decode_message_schedule_response_message(
            &server_assist_init_message,
            &client_message_schedule_request_0,
            &server_message_schedule_response_0,
        )
        .expect("decode first message-schedule response");

    let client_message_schedule_request_1 = session
        .prepare_message_schedule_request_message(&server_message_schedule_response_0)
        .expect("prepare second message-schedule request");
    let (server_message_schedule_response_1, final_server_eval_state) = session
        .prepare_message_schedule_response_message(
            &next_server_eval_state,
            &client_message_schedule_request_1,
        )
        .expect("prepare second message-schedule response");

    let response_1 = evaluator_session
        .decode_message_schedule_response_message(
            &server_assist_init_message,
            &client_message_schedule_request_1,
            &server_message_schedule_response_1,
        )
        .expect("decode second message-schedule response");

    assert_eq!(
        response_0.stage_id,
        ed25519_hss::wire::ServerEvalStageId::message_schedule(0),
    );
    assert_eq!(
        response_1.stage_id,
        ed25519_hss::wire::ServerEvalStageId::message_schedule(1),
    );
    assert_eq!(
        final_server_eval_state.current_stage,
        ed25519_hss::wire::ServerEvalStageId::message_schedule(2),
    );
    assert_eq!(
        final_server_eval_state.current_transcript_digest,
        response_1.next_transcript_digest,
    );
    for bytes in [
        &client_message_schedule_request_0.bytes,
        &server_message_schedule_response_0.bytes,
        &client_message_schedule_request_1.bytes,
        &server_message_schedule_response_1.bytes,
    ] {
        assert!(
            !contains_subslice(bytes, &fixture.input.y_relayer),
            "repeated message-schedule artifacts must not embed clear y_relayer bytes",
        );
        assert!(
            !contains_subslice(bytes, &fixture.input.tau_relayer),
            "repeated message-schedule artifacts must not embed clear tau_relayer bytes",
        );
    }
}

#[test]
fn accumulated_new_flow_artifacts_do_not_reconstruct_relayer_roots_via_legacy_decoder() {
    let fixture = boundary_fixture();
    let session =
        prepare_prime_order_succinct_hss(&fixture.input.context).expect("prepare session");
    let client_ot_offer_message = session
        .prepare_client_ot_offer_message()
        .expect("client ot offer message");
    let garbler_ot_state = session
        .prepare_garbler_ot_state()
        .expect("garbler ot state");
    let (client_request_message, evaluator_ot_state) = session
        .prepare_client_ot_request_from_offer_message(
            &client_ot_offer_message,
            fixture.input.y_client,
            fixture.input.tau_client,
        )
        .expect("prepare client request from offer");

    let (server_assist_init_message, server_eval_state) = session
        .prepare_server_assist_init_message(
            &garbler_ot_state,
            &client_request_message,
            fixture.input.y_relayer,
            fixture.input.tau_relayer,
            ServerEvalOperation::Registration,
        )
        .expect("prepare server assist init message");

    let client_add_stage_request_message = session
        .prepare_add_stage_request_message(
            &client_request_message,
            &evaluator_ot_state,
            &server_assist_init_message,
        )
        .expect("prepare add-stage request message");

    let (server_add_stage_response_message, next_server_eval_state) = session
        .prepare_add_stage_response_message(&server_eval_state, &client_add_stage_request_message)
        .expect("prepare add-stage response message");

    let client_message_schedule_request_0 = session
        .prepare_message_schedule_request_message(&server_add_stage_response_message)
        .expect("prepare first message-schedule request");
    let (server_message_schedule_response_0, next_server_eval_state) = session
        .prepare_message_schedule_response_message(
            &next_server_eval_state,
            &client_message_schedule_request_0,
        )
        .expect("prepare first message-schedule response");

    let client_message_schedule_request_1 = session
        .prepare_message_schedule_request_message(&server_message_schedule_response_0)
        .expect("prepare second message-schedule request");
    let (server_message_schedule_response_1, _) = session
        .prepare_message_schedule_response_message(
            &next_server_eval_state,
            &client_message_schedule_request_1,
        )
        .expect("prepare second message-schedule response");

    for (label, message) in [
        ("server_assist_init", &server_assist_init_message),
        ("add_stage_response", &server_add_stage_response_message),
        (
            "message_schedule_response_0",
            &server_message_schedule_response_0,
        ),
        (
            "message_schedule_response_1",
            &server_message_schedule_response_1,
        ),
    ] {
        assert!(
            decode_server_input_delivery(&session, message).is_err(),
            "{label} must not reconstruct relayer roots through the legacy server-input decoder",
        );
    }

    let mut accumulated_bytes = Vec::new();
    for bytes in [
        client_request_message.bytes.as_slice(),
        server_assist_init_message.bytes.as_slice(),
        client_add_stage_request_message.bytes.as_slice(),
        server_add_stage_response_message.bytes.as_slice(),
        client_message_schedule_request_0.bytes.as_slice(),
        server_message_schedule_response_0.bytes.as_slice(),
        client_message_schedule_request_1.bytes.as_slice(),
        server_message_schedule_response_1.bytes.as_slice(),
    ] {
        accumulated_bytes.extend_from_slice(bytes);
    }

    assert!(
        !contains_subslice(&accumulated_bytes, &fixture.input.y_relayer),
        "accumulated new-flow artifacts must not embed clear y_relayer bytes",
    );
    assert!(
        !contains_subslice(&accumulated_bytes, &fixture.input.tau_relayer),
        "accumulated new-flow artifacts must not embed clear tau_relayer bytes",
    );
}

#[test]
fn round_core_round_begins_after_final_message_schedule_without_exposing_clear_relayer_roots() {
    let fixture = boundary_fixture();
    let session =
        prepare_prime_order_succinct_hss(&fixture.input.context).expect("prepare session");
    let evaluator_session = session.evaluator_session();
    let client_ot_offer_message = session
        .prepare_client_ot_offer_message()
        .expect("client ot offer message");
    let garbler_ot_state = session
        .prepare_garbler_ot_state()
        .expect("garbler ot state");
    let (client_request_message, evaluator_ot_state) = session
        .prepare_client_ot_request_from_offer_message(
            &client_ot_offer_message,
            fixture.input.y_client,
            fixture.input.tau_client,
        )
        .expect("prepare client request from offer");

    let (server_assist_init_message, server_eval_state) = session
        .prepare_server_assist_init_message(
            &garbler_ot_state,
            &client_request_message,
            fixture.input.y_relayer,
            fixture.input.tau_relayer,
            ServerEvalOperation::Registration,
        )
        .expect("prepare server assist init message");

    let client_add_stage_request_message = session
        .prepare_add_stage_request_message(
            &client_request_message,
            &evaluator_ot_state,
            &server_assist_init_message,
        )
        .expect("prepare add-stage request message");

    let (server_stage_response_message, mut server_eval_state) = session
        .prepare_add_stage_response_message(&server_eval_state, &client_add_stage_request_message)
        .expect("prepare add-stage response message");

    let mut prior_stage_response_message = server_stage_response_message;
    for _ in 0..ed25519_hss::wire::ServerEvalStageId::MESSAGE_SCHEDULE_ROUNDS {
        let client_message_schedule_request_message = session
            .prepare_message_schedule_request_message(&prior_stage_response_message)
            .expect("prepare message-schedule request message");
        let (server_message_schedule_response_message, next_server_eval_state) = session
            .prepare_message_schedule_response_message(
                &server_eval_state,
                &client_message_schedule_request_message,
            )
            .expect("prepare message-schedule response message");
        prior_stage_response_message = server_message_schedule_response_message;
        server_eval_state = next_server_eval_state;
    }

    let client_round_core_request_message = session
        .prepare_round_core_request_message(&prior_stage_response_message)
        .expect("prepare round-core request message");
    let (server_round_core_response_message, final_server_eval_state) = session
        .prepare_round_core_response_message(&server_eval_state, &client_round_core_request_message)
        .expect("prepare round-core response message");

    let response = evaluator_session
        .decode_round_core_response_message(
            &server_assist_init_message,
            &client_round_core_request_message,
            &server_round_core_response_message,
        )
        .expect("decode round-core response message");

    assert_eq!(
        final_server_eval_state.current_stage,
        ed25519_hss::wire::ServerEvalStageId::round_core(1),
    );
    assert_eq!(
        final_server_eval_state.current_transcript_digest,
        response.next_transcript_digest,
    );
    assert_eq!(
        response.stage_id,
        ed25519_hss::wire::ServerEvalStageId::round_core(0),
    );
    assert!(
        !contains_subslice(
            &client_round_core_request_message.bytes,
            &fixture.input.y_relayer
        ),
        "client round-core request must not embed clear y_relayer bytes",
    );
    assert!(
        !contains_subslice(
            &client_round_core_request_message.bytes,
            &fixture.input.tau_relayer
        ),
        "client round-core request must not embed clear tau_relayer bytes",
    );
    assert!(
        !contains_subslice(
            &server_round_core_response_message.bytes,
            &fixture.input.y_relayer
        ),
        "server round-core response must not embed clear y_relayer bytes",
    );
    assert!(
        !contains_subslice(
            &server_round_core_response_message.bytes,
            &fixture.input.tau_relayer
        ),
        "server round-core response must not embed clear tau_relayer bytes",
    );
}

#[test]
fn round_core_round_can_repeat_without_exposing_clear_relayer_roots() {
    let fixture = boundary_fixture();
    let session =
        prepare_prime_order_succinct_hss(&fixture.input.context).expect("prepare session");
    let evaluator_session = session.evaluator_session();
    let client_ot_offer_message = session
        .prepare_client_ot_offer_message()
        .expect("client ot offer message");
    let garbler_ot_state = session
        .prepare_garbler_ot_state()
        .expect("garbler ot state");
    let (client_request_message, evaluator_ot_state) = session
        .prepare_client_ot_request_from_offer_message(
            &client_ot_offer_message,
            fixture.input.y_client,
            fixture.input.tau_client,
        )
        .expect("prepare client request from offer");

    let (server_assist_init_message, server_eval_state) = session
        .prepare_server_assist_init_message(
            &garbler_ot_state,
            &client_request_message,
            fixture.input.y_relayer,
            fixture.input.tau_relayer,
            ServerEvalOperation::Registration,
        )
        .expect("prepare server assist init message");

    let client_add_stage_request_message = session
        .prepare_add_stage_request_message(
            &client_request_message,
            &evaluator_ot_state,
            &server_assist_init_message,
        )
        .expect("prepare add-stage request message");

    let (server_stage_response_message, mut server_eval_state) = session
        .prepare_add_stage_response_message(&server_eval_state, &client_add_stage_request_message)
        .expect("prepare add-stage response message");

    let mut prior_stage_response_message = server_stage_response_message;
    for _ in 0..ed25519_hss::wire::ServerEvalStageId::MESSAGE_SCHEDULE_ROUNDS {
        let client_message_schedule_request_message = session
            .prepare_message_schedule_request_message(&prior_stage_response_message)
            .expect("prepare message-schedule request message");
        let (server_message_schedule_response_message, next_server_eval_state) = session
            .prepare_message_schedule_response_message(
                &server_eval_state,
                &client_message_schedule_request_message,
            )
            .expect("prepare message-schedule response message");
        prior_stage_response_message = server_message_schedule_response_message;
        server_eval_state = next_server_eval_state;
    }

    let client_round_core_request_0 = session
        .prepare_round_core_request_message(&prior_stage_response_message)
        .expect("prepare first round-core request message");
    let (server_round_core_response_0, server_eval_state) = session
        .prepare_round_core_response_message(&server_eval_state, &client_round_core_request_0)
        .expect("prepare first round-core response message");

    let client_round_core_request_1 = session
        .prepare_round_core_request_message(&server_round_core_response_0)
        .expect("prepare second round-core request message");
    let (server_round_core_response_1, final_server_eval_state) = session
        .prepare_round_core_response_message(&server_eval_state, &client_round_core_request_1)
        .expect("prepare second round-core response message");

    let response_1 = evaluator_session
        .decode_round_core_response_message(
            &server_assist_init_message,
            &client_round_core_request_1,
            &server_round_core_response_1,
        )
        .expect("decode second round-core response message");

    assert_eq!(
        response_1.stage_id,
        ed25519_hss::wire::ServerEvalStageId::round_core(1),
    );
    assert_eq!(
        final_server_eval_state.current_stage,
        ed25519_hss::wire::ServerEvalStageId::round_core(2),
    );
    assert_eq!(
        final_server_eval_state.current_transcript_digest,
        response_1.next_transcript_digest,
    );
    for bytes in [
        &client_round_core_request_0.bytes,
        &server_round_core_response_0.bytes,
        &client_round_core_request_1.bytes,
        &server_round_core_response_1.bytes,
    ] {
        assert!(
            !contains_subslice(bytes, &fixture.input.y_relayer),
            "repeated round-core artifacts must not embed clear y_relayer bytes",
        );
        assert!(
            !contains_subslice(bytes, &fixture.input.tau_relayer),
            "repeated round-core artifacts must not embed clear tau_relayer bytes",
        );
    }
}

#[test]
fn output_projection_round_begins_after_final_round_core_without_exposing_clear_relayer_roots() {
    let fixture = boundary_fixture();
    let session =
        prepare_prime_order_succinct_hss(&fixture.input.context).expect("prepare session");
    let evaluator_session = session.evaluator_session();
    let client_ot_offer_message = session
        .prepare_client_ot_offer_message()
        .expect("client ot offer message");
    let garbler_ot_state = session
        .prepare_garbler_ot_state()
        .expect("garbler ot state");
    let (client_request_message, evaluator_ot_state) = session
        .prepare_client_ot_request_from_offer_message(
            &client_ot_offer_message,
            fixture.input.y_client,
            fixture.input.tau_client,
        )
        .expect("prepare client request from offer");

    let (server_assist_init_message, mut server_eval_state) = session
        .prepare_server_assist_init_message(
            &garbler_ot_state,
            &client_request_message,
            fixture.input.y_relayer,
            fixture.input.tau_relayer,
            ServerEvalOperation::Registration,
        )
        .expect("prepare server assist init message");

    let client_add_stage_request_message = session
        .prepare_add_stage_request_message(
            &client_request_message,
            &evaluator_ot_state,
            &server_assist_init_message,
        )
        .expect("prepare add-stage request message");

    let (mut prior_stage_response_message, next_server_eval_state) = session
        .prepare_add_stage_response_message(&server_eval_state, &client_add_stage_request_message)
        .expect("prepare add-stage response message");
    server_eval_state = next_server_eval_state;

    for _ in 0..ed25519_hss::wire::ServerEvalStageId::MESSAGE_SCHEDULE_ROUNDS {
        let client_message_schedule_request_message = session
            .prepare_message_schedule_request_message(&prior_stage_response_message)
            .expect("prepare message-schedule request message");
        let (server_message_schedule_response_message, next_server_eval_state) = session
            .prepare_message_schedule_response_message(
                &server_eval_state,
                &client_message_schedule_request_message,
            )
            .expect("prepare message-schedule response message");
        prior_stage_response_message = server_message_schedule_response_message;
        server_eval_state = next_server_eval_state;
    }

    for _ in 0..ed25519_hss::wire::ServerEvalStageId::ROUND_CORE_ROUNDS {
        let client_round_core_request_message = session
            .prepare_round_core_request_message(&prior_stage_response_message)
            .expect("prepare round-core request message");
        let (server_round_core_response_message, next_server_eval_state) = session
            .prepare_round_core_response_message(
                &server_eval_state,
                &client_round_core_request_message,
            )
            .expect("prepare round-core response message");
        prior_stage_response_message = server_round_core_response_message;
        server_eval_state = next_server_eval_state;
    }

    let client_output_projection_request_message = session
        .prepare_output_projection_request_message(&prior_stage_response_message)
        .expect("prepare output-projection request message");
    let (server_output_projection_response_message, final_server_eval_state) = session
        .prepare_output_projection_response_message(
            &server_eval_state,
            &client_output_projection_request_message,
        )
        .expect("prepare output-projection response message");

    let response = evaluator_session
        .decode_output_projection_response_message(
            &server_assist_init_message,
            &client_output_projection_request_message,
            &server_output_projection_response_message,
        )
        .expect("decode output-projection response message");

    assert_eq!(
        response.stage_id,
        ed25519_hss::wire::ServerEvalStageId::output_projection(),
    );
    assert_eq!(
        final_server_eval_state.current_stage,
        ed25519_hss::wire::ServerEvalStageId::output_projection(),
    );
    assert_eq!(
        final_server_eval_state.current_transcript_digest,
        response.next_transcript_digest,
    );
    assert_eq!(
        final_server_eval_state.status,
        ed25519_hss::server::ServerEvalStatus::Finalized,
    );
    assert!(
        !contains_subslice(
            &client_output_projection_request_message.bytes,
            &fixture.input.y_relayer
        ),
        "client output-projection request must not embed clear y_relayer bytes",
    );
    assert!(
        !contains_subslice(
            &client_output_projection_request_message.bytes,
            &fixture.input.tau_relayer
        ),
        "client output-projection request must not embed clear tau_relayer bytes",
    );
    assert!(
        !contains_subslice(
            &server_output_projection_response_message.bytes,
            &fixture.input.y_relayer
        ),
        "server output-projection response must not embed clear y_relayer bytes",
    );
    assert!(
        !contains_subslice(
            &server_output_projection_response_message.bytes,
            &fixture.input.tau_relayer
        ),
        "server output-projection response must not embed clear tau_relayer bytes",
    );
}

#[test]
fn accumulated_full_new_flow_artifacts_do_not_reconstruct_relayer_roots_via_legacy_decoder() {
    let fixture = boundary_fixture();
    let session =
        prepare_prime_order_succinct_hss(&fixture.input.context).expect("prepare session");
    let client_ot_offer_message = session
        .prepare_client_ot_offer_message()
        .expect("client ot offer message");
    let garbler_ot_state = session
        .prepare_garbler_ot_state()
        .expect("garbler ot state");
    let (client_request_message, evaluator_ot_state) = session
        .prepare_client_ot_request_from_offer_message(
            &client_ot_offer_message,
            fixture.input.y_client,
            fixture.input.tau_client,
        )
        .expect("prepare client request from offer");

    let (server_assist_init_message, mut server_eval_state) = session
        .prepare_server_assist_init_message(
            &garbler_ot_state,
            &client_request_message,
            fixture.input.y_relayer,
            fixture.input.tau_relayer,
            ServerEvalOperation::Registration,
        )
        .expect("prepare server assist init message");

    let client_add_stage_request_message = session
        .prepare_add_stage_request_message(
            &client_request_message,
            &evaluator_ot_state,
            &server_assist_init_message,
        )
        .expect("prepare add-stage request message");
    let (server_add_stage_response_message, next_server_eval_state) = session
        .prepare_add_stage_response_message(&server_eval_state, &client_add_stage_request_message)
        .expect("prepare add-stage response message");
    server_eval_state = next_server_eval_state;

    let mut prior_stage_response_message = server_add_stage_response_message.clone();
    let mut accumulated_bytes = Vec::new();
    for bytes in [
        client_request_message.bytes.as_slice(),
        server_assist_init_message.bytes.as_slice(),
        client_add_stage_request_message.bytes.as_slice(),
        prior_stage_response_message.bytes.as_slice(),
    ] {
        accumulated_bytes.extend_from_slice(bytes);
    }

    for _ in 0..ed25519_hss::wire::ServerEvalStageId::MESSAGE_SCHEDULE_ROUNDS {
        let client_message_schedule_request_message = session
            .prepare_message_schedule_request_message(&prior_stage_response_message)
            .expect("prepare message-schedule request message");
        let (server_message_schedule_response_message, next_server_eval_state) = session
            .prepare_message_schedule_response_message(
                &server_eval_state,
                &client_message_schedule_request_message,
            )
            .expect("prepare message-schedule response message");
        accumulated_bytes.extend_from_slice(&client_message_schedule_request_message.bytes);
        accumulated_bytes.extend_from_slice(&server_message_schedule_response_message.bytes);
        prior_stage_response_message = server_message_schedule_response_message;
        server_eval_state = next_server_eval_state;
    }

    for _ in 0..ed25519_hss::wire::ServerEvalStageId::ROUND_CORE_ROUNDS {
        let client_round_core_request_message = session
            .prepare_round_core_request_message(&prior_stage_response_message)
            .expect("prepare round-core request message");
        let (server_round_core_response_message, next_server_eval_state) = session
            .prepare_round_core_response_message(
                &server_eval_state,
                &client_round_core_request_message,
            )
            .expect("prepare round-core response message");
        accumulated_bytes.extend_from_slice(&client_round_core_request_message.bytes);
        accumulated_bytes.extend_from_slice(&server_round_core_response_message.bytes);
        prior_stage_response_message = server_round_core_response_message;
        server_eval_state = next_server_eval_state;
    }

    let client_output_projection_request_message = session
        .prepare_output_projection_request_message(&prior_stage_response_message)
        .expect("prepare output-projection request message");
    let (server_output_projection_response_message, _final_server_eval_state) = session
        .prepare_output_projection_response_message(
            &server_eval_state,
            &client_output_projection_request_message,
        )
        .expect("prepare output-projection response message");
    accumulated_bytes.extend_from_slice(&client_output_projection_request_message.bytes);
    accumulated_bytes.extend_from_slice(&server_output_projection_response_message.bytes);

    for (label, message) in [
        ("server_assist_init", &server_assist_init_message),
        ("add_stage_response", &server_add_stage_response_message),
        ("final_round_core_response", &prior_stage_response_message),
        (
            "output_projection_response",
            &server_output_projection_response_message,
        ),
    ] {
        assert!(
            decode_server_input_delivery(&session, message).is_err(),
            "{label} must not reconstruct relayer roots through the legacy server-input decoder",
        );
    }

    assert!(
        !contains_subslice(&accumulated_bytes, &fixture.input.y_relayer),
        "accumulated full new-flow artifacts must not embed clear y_relayer bytes",
    );
    assert!(
        !contains_subslice(&accumulated_bytes, &fixture.input.tau_relayer),
        "accumulated full new-flow artifacts must not embed clear tau_relayer bytes",
    );
}

#[test]
fn prepared_server_assist_flow_wrapper_does_not_expose_reconstructable_relayer_roots() {
    let fixture = boundary_fixture();
    let session =
        prepare_prime_order_succinct_hss(&fixture.input.context).expect("prepare session");
    let client_ot_offer_message = session
        .prepare_client_ot_offer_message()
        .expect("prepare client ot offer message");
    let garbler_ot_state = session
        .prepare_garbler_ot_state()
        .expect("prepare garbler ot state");
    let (client_request_message, evaluator_ot_state) = session
        .prepare_client_ot_request_from_offer_message(
            &client_ot_offer_message,
            fixture.input.y_client,
            fixture.input.tau_client,
        )
        .expect("prepare client request from offer");

    let flow = session
        .prepare_server_assist_flow_to_output_projection(
            &garbler_ot_state,
            &client_request_message,
            &evaluator_ot_state,
            fixture.input.y_relayer,
            fixture.input.tau_relayer,
            ServerEvalOperation::Registration,
        )
        .expect("prepare staged assist flow");

    assert_eq!(
        flow.final_server_eval_state.status,
        ed25519_hss::server::ServerEvalStatus::Finalized,
    );

    assert_staged_flow_messages_do_not_drive_legacy_decoder(&session, &flow);

    let mut accumulated_bytes = Vec::new();
    extend_staged_flow_bytes(&mut accumulated_bytes, &client_request_message, &flow);

    assert!(
        !contains_subslice(&accumulated_bytes, &fixture.input.y_relayer),
        "wrapper-driven staged artifacts must not embed clear y_relayer bytes",
    );
    assert!(
        !contains_subslice(&accumulated_bytes, &fixture.input.tau_relayer),
        "wrapper-driven staged artifacts must not embed clear tau_relayer bytes",
    );
}

#[test]
fn repeated_run_same_account_staged_artifacts_do_not_reconstruct_relayer_roots() {
    let fixture = boundary_fixture();
    let session =
        prepare_prime_order_succinct_hss(&fixture.input.context).expect("prepare session");
    let client_ot_offer_message = session
        .prepare_client_ot_offer_message()
        .expect("prepare client ot offer message");
    let garbler_ot_state = session
        .prepare_garbler_ot_state()
        .expect("prepare garbler ot state");

    let (client_request_message_a, evaluator_ot_state_a) = session
        .prepare_client_ot_request_from_offer_message(
            &client_ot_offer_message,
            fixture.input.y_client,
            fixture.input.tau_client,
        )
        .expect("prepare client request A from offer");
    let flow_a = session
        .prepare_server_assist_flow_to_output_projection(
            &garbler_ot_state,
            &client_request_message_a,
            &evaluator_ot_state_a,
            fixture.input.y_relayer,
            fixture.input.tau_relayer,
            ServerEvalOperation::Registration,
        )
        .expect("prepare staged assist flow A");

    let (client_request_message_b, evaluator_ot_state_b) = session
        .prepare_client_ot_request_from_offer_message(
            &client_ot_offer_message,
            fixture.input.y_client,
            fixture.input.tau_client,
        )
        .expect("prepare client request B from offer");
    let flow_b = session
        .prepare_server_assist_flow_to_output_projection(
            &garbler_ot_state,
            &client_request_message_b,
            &evaluator_ot_state_b,
            fixture.input.y_relayer,
            fixture.input.tau_relayer,
            ServerEvalOperation::Registration,
        )
        .expect("prepare staged assist flow B");

    assert_staged_flow_messages_do_not_drive_legacy_decoder(&session, &flow_a);
    assert_staged_flow_messages_do_not_drive_legacy_decoder(&session, &flow_b);

    let mut accumulated_bytes = Vec::new();
    extend_staged_flow_bytes(&mut accumulated_bytes, &client_request_message_a, &flow_a);
    extend_staged_flow_bytes(&mut accumulated_bytes, &client_request_message_b, &flow_b);

    assert!(
        !contains_subslice(&accumulated_bytes, &fixture.input.y_relayer),
        "same-account repeated staged runs must not embed clear y_relayer bytes",
    );
    assert!(
        !contains_subslice(&accumulated_bytes, &fixture.input.tau_relayer),
        "same-account repeated staged runs must not embed clear tau_relayer bytes",
    );
}

#[test]
fn repeated_run_cross_account_staged_artifacts_do_not_reconstruct_relayer_roots() {
    let fixture_a = boundary_fixture();
    let fixture_b = second_boundary_fixture();
    let session_a =
        prepare_prime_order_succinct_hss(&fixture_a.input.context).expect("prepare session A");
    let session_b =
        prepare_prime_order_succinct_hss(&fixture_b.input.context).expect("prepare session B");

    let client_ot_offer_message_a = session_a
        .prepare_client_ot_offer_message()
        .expect("prepare client ot offer message A");
    let garbler_ot_state_a = session_a
        .prepare_garbler_ot_state()
        .expect("prepare garbler ot state A");
    let (client_request_message_a, evaluator_ot_state_a) = session_a
        .prepare_client_ot_request_from_offer_message(
            &client_ot_offer_message_a,
            fixture_a.input.y_client,
            fixture_a.input.tau_client,
        )
        .expect("prepare client request A from offer");
    let flow_a = session_a
        .prepare_server_assist_flow_to_output_projection(
            &garbler_ot_state_a,
            &client_request_message_a,
            &evaluator_ot_state_a,
            fixture_a.input.y_relayer,
            fixture_a.input.tau_relayer,
            ServerEvalOperation::Registration,
        )
        .expect("prepare staged assist flow A");

    let client_ot_offer_message_b = session_b
        .prepare_client_ot_offer_message()
        .expect("prepare client ot offer message B");
    let garbler_ot_state_b = session_b
        .prepare_garbler_ot_state()
        .expect("prepare garbler ot state B");
    let (client_request_message_b, evaluator_ot_state_b) = session_b
        .prepare_client_ot_request_from_offer_message(
            &client_ot_offer_message_b,
            fixture_b.input.y_client,
            fixture_b.input.tau_client,
        )
        .expect("prepare client request B from offer");
    let flow_b = session_b
        .prepare_server_assist_flow_to_output_projection(
            &garbler_ot_state_b,
            &client_request_message_b,
            &evaluator_ot_state_b,
            fixture_b.input.y_relayer,
            fixture_b.input.tau_relayer,
            ServerEvalOperation::Registration,
        )
        .expect("prepare staged assist flow B");

    assert_staged_flow_messages_do_not_drive_legacy_decoder(&session_a, &flow_a);
    assert_staged_flow_messages_do_not_drive_legacy_decoder(&session_b, &flow_b);

    let mut accumulated_bytes_a = Vec::new();
    extend_staged_flow_bytes(&mut accumulated_bytes_a, &client_request_message_a, &flow_a);
    assert!(
        !contains_subslice(&accumulated_bytes_a, &fixture_a.input.y_relayer),
        "cross-account staged flow A must not embed clear y_relayer bytes",
    );
    assert!(
        !contains_subslice(&accumulated_bytes_a, &fixture_a.input.tau_relayer),
        "cross-account staged flow A must not embed clear tau_relayer bytes",
    );

    let mut accumulated_bytes_b = Vec::new();
    extend_staged_flow_bytes(&mut accumulated_bytes_b, &client_request_message_b, &flow_b);
    assert!(
        !contains_subslice(&accumulated_bytes_b, &fixture_b.input.y_relayer),
        "cross-account staged flow B must not embed clear y_relayer bytes",
    );
    assert!(
        !contains_subslice(&accumulated_bytes_b, &fixture_b.input.tau_relayer),
        "cross-account staged flow B must not embed clear tau_relayer bytes",
    );
}

#[test]
fn retry_and_idempotent_stage_replays_do_not_reconstruct_relayer_roots() {
    let fixture = boundary_fixture();
    let session =
        prepare_prime_order_succinct_hss(&fixture.input.context).expect("prepare session");
    let client_ot_offer_message = session
        .prepare_client_ot_offer_message()
        .expect("prepare client ot offer message");
    let garbler_ot_state = session
        .prepare_garbler_ot_state()
        .expect("prepare garbler ot state");
    let (client_request_message, evaluator_ot_state) = session
        .prepare_client_ot_request_from_offer_message(
            &client_ot_offer_message,
            fixture.input.y_client,
            fixture.input.tau_client,
        )
        .expect("prepare client request from offer");

    let (server_assist_init_message, initial_server_eval_state) = session
        .prepare_server_assist_init_message(
            &garbler_ot_state,
            &client_request_message,
            fixture.input.y_relayer,
            fixture.input.tau_relayer,
            ServerEvalOperation::Registration,
        )
        .expect("prepare server assist init message");
    let add_stage_request_message = session
        .prepare_add_stage_request_message(
            &client_request_message,
            &evaluator_ot_state,
            &server_assist_init_message,
        )
        .expect("prepare add-stage request message");
    let (add_stage_response_message_a, add_stage_state_a) = session
        .prepare_add_stage_response_message(&initial_server_eval_state, &add_stage_request_message)
        .expect("prepare add-stage response message A");
    let (add_stage_response_message_b, add_stage_state_b) = session
        .prepare_add_stage_response_message(&initial_server_eval_state, &add_stage_request_message)
        .expect("prepare add-stage response message B");

    assert_eq!(
        add_stage_response_message_a, add_stage_response_message_b,
        "duplicate add-stage retries must be idempotent"
    );
    assert_eq!(
        add_stage_state_a, add_stage_state_b,
        "duplicate add-stage retries must keep the same next server state"
    );

    let message_schedule_request_message = session
        .prepare_message_schedule_request_message(&add_stage_response_message_a)
        .expect("prepare message-schedule request message");
    let (message_schedule_response_message_a, message_schedule_state_a) = session
        .prepare_message_schedule_response_message(
            &add_stage_state_a,
            &message_schedule_request_message,
        )
        .expect("prepare message-schedule response message A");
    let (message_schedule_response_message_b, message_schedule_state_b) = session
        .prepare_message_schedule_response_message(
            &add_stage_state_a,
            &message_schedule_request_message,
        )
        .expect("prepare message-schedule response message B");

    assert_eq!(
        message_schedule_response_message_a, message_schedule_response_message_b,
        "duplicate message-schedule retries must be idempotent"
    );
    assert_eq!(
        message_schedule_state_a, message_schedule_state_b,
        "duplicate message-schedule retries must keep the same next server state"
    );

    for (label, message) in [
        ("server_assist_init", &server_assist_init_message),
        ("add_stage_response_retry_a", &add_stage_response_message_a),
        ("add_stage_response_retry_b", &add_stage_response_message_b),
        (
            "message_schedule_response_retry_a",
            &message_schedule_response_message_a,
        ),
        (
            "message_schedule_response_retry_b",
            &message_schedule_response_message_b,
        ),
    ] {
        assert!(
            decode_server_input_delivery(&session, message).is_err(),
            "{label} must not reconstruct relayer roots through the legacy server-input decoder",
        );
    }

    let mut accumulated_bytes = Vec::new();
    for bytes in [
        client_request_message.bytes.as_slice(),
        server_assist_init_message.bytes.as_slice(),
        add_stage_request_message.bytes.as_slice(),
        add_stage_response_message_a.bytes.as_slice(),
        add_stage_response_message_b.bytes.as_slice(),
        message_schedule_request_message.bytes.as_slice(),
        message_schedule_response_message_a.bytes.as_slice(),
        message_schedule_response_message_b.bytes.as_slice(),
    ] {
        accumulated_bytes.extend_from_slice(bytes);
    }

    assert!(
        !contains_subslice(&accumulated_bytes, &fixture.input.y_relayer),
        "retry/idempotent staged artifacts must not embed clear y_relayer bytes",
    );
    assert!(
        !contains_subslice(&accumulated_bytes, &fixture.input.tau_relayer),
        "retry/idempotent staged artifacts must not embed clear tau_relayer bytes",
    );
}

#[test]
fn client_visible_staged_packets_do_not_reconstruct_relayer_roots() {
    let fixture = boundary_fixture();
    let session =
        prepare_prime_order_succinct_hss(&fixture.input.context).expect("prepare session");
    let client_ot_offer_message = session
        .prepare_client_ot_offer_message()
        .expect("prepare client ot offer message");
    let garbler_ot_state = session
        .prepare_garbler_ot_state()
        .expect("prepare garbler ot state");
    let (client_request_message, evaluator_ot_state) = session
        .prepare_client_ot_request_from_offer_message(
            &client_ot_offer_message,
            fixture.input.y_client,
            fixture.input.tau_client,
        )
        .expect("prepare client request from offer");

    let flow = session
        .prepare_server_assist_flow_to_output_projection(
            &garbler_ot_state,
            &client_request_message,
            &evaluator_ot_state,
            fixture.input.y_relayer,
            fixture.input.tau_relayer,
            ServerEvalOperation::Registration,
        )
        .expect("prepare staged assist flow");
    let runtime = session.shared_runtime();
    let staged_evaluator_artifact = session
        .build_server_owned_staged_evaluator_artifact_from_server_eval_state(
            &flow.final_server_eval_state,
        )
        .expect("build staged evaluator artifact");
    let (server_finalize_message, _report) = session
        .prepare_server_finalize_message_from_staged_evaluator_artifact(
            &runtime,
            &flow.final_server_eval_state,
            &staged_evaluator_artifact,
        )
        .expect("prepare server finalize message");

    let mut client_visible_messages: Vec<(&str, &ed25519_hss::wire::WireMessage)> = vec![
        ("client_request", &client_request_message),
        ("server_assist_init", &flow.server_assist_init_message),
        ("add_stage_request", &flow.add_stage_request_message),
        ("add_stage_response", &flow.add_stage_response_message),
        (
            "output_projection_request",
            &flow.output_projection_request_message,
        ),
        (
            "output_projection_response",
            &flow.output_projection_response_message,
        ),
        ("server_finalize", &server_finalize_message),
    ];
    for (idx, message) in flow.message_schedule_request_messages.iter().enumerate() {
        client_visible_messages.push(("message_schedule_request", message));
        debug_assert!(idx < ed25519_hss::wire::ServerEvalStageId::MESSAGE_SCHEDULE_ROUNDS as usize);
    }
    for (idx, message) in flow.message_schedule_response_messages.iter().enumerate() {
        client_visible_messages.push(("message_schedule_response", message));
        debug_assert!(idx < ed25519_hss::wire::ServerEvalStageId::MESSAGE_SCHEDULE_ROUNDS as usize);
    }
    for (idx, message) in flow.round_core_request_messages.iter().enumerate() {
        client_visible_messages.push(("round_core_request", message));
        debug_assert!(idx < ed25519_hss::wire::ServerEvalStageId::ROUND_CORE_ROUNDS as usize);
    }
    for (idx, message) in flow.round_core_response_messages.iter().enumerate() {
        client_visible_messages.push(("round_core_response", message));
        debug_assert!(idx < ed25519_hss::wire::ServerEvalStageId::ROUND_CORE_ROUNDS as usize);
    }

    let mut accumulated_bytes = Vec::new();
    for (label, message) in client_visible_messages {
        assert!(
            decode_server_input_delivery(&session, message).is_err(),
            "{label} must not reconstruct relayer roots through the legacy server-input decoder",
        );
        accumulated_bytes.extend_from_slice(&message.bytes);
    }

    assert!(
        !contains_subslice(&accumulated_bytes, &fixture.input.y_relayer),
        "client-visible staged packets must not embed clear y_relayer bytes",
    );
    assert!(
        !contains_subslice(&accumulated_bytes, &fixture.input.tau_relayer),
        "client-visible staged packets must not embed clear tau_relayer bytes",
    );
}

#[test]
fn decoded_new_flow_wire_packets_do_not_expose_server_owned_transport_bundles() {
    let fixture = boundary_fixture();
    let session =
        prepare_prime_order_succinct_hss(&fixture.input.context).expect("prepare session");
    let client_ot_offer_message = session
        .prepare_client_ot_offer_message()
        .expect("prepare client ot offer message");
    let garbler_ot_state = session
        .prepare_garbler_ot_state()
        .expect("prepare garbler ot state");
    let (client_request_message, evaluator_ot_state) = session
        .prepare_client_ot_request_from_offer_message(
            &client_ot_offer_message,
            fixture.input.y_client,
            fixture.input.tau_client,
        )
        .expect("prepare client request from offer");
    let flow = session
        .prepare_server_assist_flow_to_output_projection(
            &garbler_ot_state,
            &client_request_message,
            &evaluator_ot_state,
            fixture.input.y_relayer,
            fixture.input.tau_relayer,
            ServerEvalOperation::Registration,
        )
        .expect("prepare staged assist flow");

    let server_assist_init: ServerAssistInitPacket = decode_transport_message(
        fixture.output.context_binding,
        TransportKind::ServerAssistInit,
        &flow.server_assist_init_message,
    )
    .expect("decode server assist init packet");
    let add_stage_request: ClientStageRequestPacket = decode_transport_message(
        fixture.output.context_binding,
        TransportKind::ClientStageRequest,
        &flow.add_stage_request_message,
    )
    .expect("decode add-stage request packet");
    let add_stage_response: ServerStageResponsePacket = decode_transport_message(
        fixture.output.context_binding,
        TransportKind::ServerStageResponse,
        &flow.add_stage_response_message,
    )
    .expect("decode add-stage response packet");
    let final_schedule_request: ClientStageRequestPacket = decode_transport_message(
        fixture.output.context_binding,
        TransportKind::ClientStageRequest,
        flow.message_schedule_request_messages
            .last()
            .expect("final message-schedule request"),
    )
    .expect("decode final message-schedule request packet");
    let final_schedule_response: ServerStageResponsePacket = decode_transport_message(
        fixture.output.context_binding,
        TransportKind::ServerStageResponse,
        flow.message_schedule_response_messages
            .last()
            .expect("final message-schedule response"),
    )
    .expect("decode final message-schedule response packet");
    let final_round_core_request: ClientStageRequestPacket = decode_transport_message(
        fixture.output.context_binding,
        TransportKind::ClientStageRequest,
        flow.round_core_request_messages
            .last()
            .expect("final round-core request"),
    )
    .expect("decode final round-core request packet");
    let final_round_core_response: ServerStageResponsePacket = decode_transport_message(
        fixture.output.context_binding,
        TransportKind::ServerStageResponse,
        flow.round_core_response_messages
            .last()
            .expect("final round-core response"),
    )
    .expect("decode final round-core response packet");
    let output_projection_request: ClientStageRequestPacket = decode_transport_message(
        fixture.output.context_binding,
        TransportKind::ClientStageRequest,
        &flow.output_projection_request_message,
    )
    .expect("decode output-projection request packet");
    let output_projection_response: ServerStageResponsePacket = decode_transport_message(
        fixture.output.context_binding,
        TransportKind::ServerStageResponse,
        &flow.output_projection_response_message,
    )
    .expect("decode output-projection response packet");

    assert_eq!(
        server_assist_init.y_client_response.owner,
        ed25519_hss::ddh::HiddenEvalInputOwner::Client,
        "decoded init packet must only expose client-owned OT response bundles",
    );
    assert_eq!(
        server_assist_init.tau_client_response.owner,
        ed25519_hss::ddh::HiddenEvalInputOwner::Client,
        "decoded init packet must only expose client-owned OT response bundles",
    );
    assert_eq!(
        server_assist_init.y_client_remote_release.owner,
        ed25519_hss::ddh::HiddenEvalInputOwner::Client,
        "decoded init packet must only expose client-owned remote releases",
    );
    assert_eq!(
        server_assist_init.tau_client_remote_release.owner,
        ed25519_hss::ddh::HiddenEvalInputOwner::Client,
        "decoded init packet must only expose client-owned remote releases",
    );

    let decoded_bytes = [
        bincode::serialize(&server_assist_init).expect("serialize init packet"),
        bincode::serialize(&add_stage_request).expect("serialize add-stage request"),
        bincode::serialize(&add_stage_response).expect("serialize add-stage response"),
        bincode::serialize(&final_schedule_request)
            .expect("serialize final message-schedule request"),
        bincode::serialize(&final_schedule_response)
            .expect("serialize final message-schedule response"),
        bincode::serialize(&final_round_core_request).expect("serialize final round-core request"),
        bincode::serialize(&final_round_core_response)
            .expect("serialize final round-core response"),
        bincode::serialize(&output_projection_request)
            .expect("serialize output-projection request"),
        bincode::serialize(&output_projection_response)
            .expect("serialize output-projection response"),
    ];

    for bytes in decoded_bytes {
        assert!(
            !contains_subslice(&bytes, &fixture.input.y_relayer),
            "decoded staged wire packet must not embed clear y_relayer bytes",
        );
        assert!(
            !contains_subslice(&bytes, &fixture.input.tau_relayer),
            "decoded staged wire packet must not embed clear tau_relayer bytes",
        );
    }
}
