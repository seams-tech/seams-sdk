use ed25519_hss::ddh::HiddenEvalInputOwner;
use ed25519_hss::fixtures::deterministic_fixture_corpus;
use ed25519_hss::protocol::prepare_prime_order_succinct_hss;
use ed25519_hss::server::{ServerEvalExecutionState, ServerEvalOperation};
use ed25519_hss::shared::{public_key_from_base_shares, ProtoError};
use ed25519_hss::wire::{
    ClientStagePayload, ClientStageRequestPacket, HiddenCoreMaterialization,
    ServerAssistInitPacket, ServerStageResponsePacket,
};

use crate::support::{
    decode_client_offer, decode_client_output_message, decode_client_request,
    decode_server_input_delivery, decode_transport_message, first_fixture, TransportKind,
};

#[test]
fn prime_order_succinct_hss_prepares_delivery_packets() {
    let fixture = first_fixture();
    let session =
        prepare_prime_order_succinct_hss(&fixture.input.context).expect("prepare session");
    let delivery_material = session.delivery_material();
    let (_runtime, garbler_session, evaluator_session) = session.split_runtime();
    let client_ot_offer_message = garbler_session
        .client_ot_offer_message()
        .expect("prepare client OT offer message");
    let client_ot_offer =
        decode_client_offer(fixture.output.context_binding, &client_ot_offer_message)
            .expect("decode client OT offer message");
    let (client_request_message, evaluator_ot_state) = evaluator_session
        .prepare_client_ot_request_from_offer_message(
            &client_ot_offer_message,
            fixture.input.y_client,
            fixture.input.tau_client,
        )
        .expect("prepare client OT request from offer");
    let client_packet =
        decode_client_request(fixture.output.context_binding, &client_request_message)
            .expect("decode client OT request message");
    let (server_assist_init_message, server_eval_state) = garbler_session
        .prepare_server_assist_init_message(
            &client_request_message,
            fixture.input.y_relayer,
            fixture.input.tau_relayer,
            ServerEvalOperation::Registration,
        )
        .expect("prepare server assist init message");
    let server_assist_init: ServerAssistInitPacket = decode_transport_message(
        fixture.output.context_binding,
        TransportKind::ServerAssistInit,
        &server_assist_init_message,
    )
    .expect("decode server assist init message");

    assert_eq!(
        delivery_material.artifact.context_binding,
        fixture.output.context_binding
    );
    assert_eq!(
        delivery_material.evaluation_key.key_id,
        session.ddh_backend().evaluation_key().key_id
    );
    assert_eq!(
        client_packet.context_binding,
        fixture.output.context_binding
    );
    assert_eq!(
        server_assist_init.context_binding,
        fixture.output.context_binding
    );
    assert_eq!(
        client_ot_offer.context_binding,
        fixture.output.context_binding
    );
    assert_eq!(
        client_ot_offer.y_client_offer.owner,
        HiddenEvalInputOwner::Client
    );
    assert_eq!(
        client_ot_offer.tau_client_offer.owner,
        HiddenEvalInputOwner::Client
    );
    assert_eq!(client_ot_offer.y_client_offer.words.len(), 256);
    assert_eq!(client_ot_offer.tau_client_offer.words.len(), 256);
    assert_eq!(
        client_packet.y_client_request.owner,
        HiddenEvalInputOwner::Client
    );
    assert_eq!(
        client_packet.tau_client_request.owner,
        HiddenEvalInputOwner::Client
    );
    assert_eq!(client_packet.y_client_request.words.len(), 256);
    assert_eq!(client_packet.tau_client_request.words.len(), 256);
    assert_eq!(
        evaluator_ot_state.y_client_local_state.owner,
        HiddenEvalInputOwner::Client
    );
    assert_eq!(
        evaluator_ot_state.tau_client_local_state.owner,
        HiddenEvalInputOwner::Client
    );
    assert_eq!(
        server_assist_init
            .y_client_remote_release
            .request_commitment,
        client_packet.y_client_request.commitment
    );
    assert_eq!(
        server_assist_init
            .tau_client_remote_release
            .request_commitment,
        client_packet.tau_client_request.commitment
    );
    assert_eq!(
        server_assist_init.y_client_remote_release.offer_commitment,
        client_ot_offer.y_client_offer.commitment
    );
    assert_eq!(
        server_assist_init
            .tau_client_remote_release
            .offer_commitment,
        client_ot_offer.tau_client_offer.commitment
    );
    assert_eq!(
        server_assist_init.y_client_remote_release.owner,
        HiddenEvalInputOwner::Client
    );
    assert_eq!(
        server_assist_init.tau_client_remote_release.owner,
        HiddenEvalInputOwner::Client
    );
    assert_eq!(
        server_assist_init.server_eval_handle,
        server_eval_state.handle
    );
    assert_eq!(
        server_assist_init.transcript_id,
        server_eval_state.transcript_id
    );
    assert_eq!(
        server_assist_init.server_input_commitment,
        server_eval_state.server_input_commitment
    );
    assert_eq!(
        server_assist_init.y_client_response.owner,
        HiddenEvalInputOwner::Client
    );
    assert_eq!(
        server_assist_init.tau_client_response.owner,
        HiddenEvalInputOwner::Client
    );
    assert_eq!(
        server_assist_init
            .y_client_remote_release
            .request_commitment,
        client_packet.y_client_request.commitment
    );
    assert_eq!(
        server_assist_init
            .tau_client_remote_release
            .request_commitment,
        client_packet.tau_client_request.commitment
    );
    assert_eq!(
        server_assist_init
            .y_client_remote_release
            .response_commitment,
        server_assist_init.y_client_response.commitment
    );
    assert_eq!(
        server_assist_init
            .tau_client_remote_release
            .response_commitment,
        server_assist_init.tau_client_response.commitment
    );
    assert_eq!(
        server_assist_init
            .y_client_remote_release
            .transcript_binding,
        server_eval_state
            .ot_transcript
            .y_client_remote_release_binding
    );
    assert_eq!(
        server_assist_init
            .tau_client_remote_release
            .transcript_binding,
        server_eval_state
            .ot_transcript
            .tau_client_remote_release_binding
    );
    let expected_y_relayer_bundle = session
        .ddh_backend()
        .share_input_bit_bundle(
            HiddenEvalInputOwner::Server,
            "y_relayer_bits",
            &fixture.input.y_relayer,
        )
        .expect("share relayer y bits");
    let expected_tau_relayer_bundle = session
        .ddh_backend()
        .share_input_bit_bundle(
            HiddenEvalInputOwner::Server,
            "tau_relayer_bits",
            &fixture.input.tau_relayer,
        )
        .expect("share relayer tau bits");
    assert_eq!(
        server_assist_init.server_input_commitment,
        session.ddh_backend().combined_input_commitment(
            HiddenEvalInputOwner::Server,
            &[&expected_y_relayer_bundle, &expected_tau_relayer_bundle],
        )
    );
    assert!(String::from_utf8(server_assist_init_message.bytes.clone()).is_err());
}

#[test]
#[ignore = "output delivery packet verification now runs the full DDH hidden evaluator and is too expensive for the default debug lane"]
fn prime_order_succinct_hss_splits_output_delivery_packets() {
    let fixture = first_fixture();
    let session =
        prepare_prime_order_succinct_hss(&fixture.input.context).expect("prepare session");
    let report = session
        .evaluate_for_clear_input_debug(&fixture.input)
        .expect("evaluate session");
    let delivery = report.output_delivery.clone();
    let output_openers = session.output_openers();
    let client_packet =
        decode_client_output_message(fixture.output.context_binding, &delivery.client)
            .expect("decode client output message");
    assert_eq!(
        client_packet.context_binding,
        fixture.output.context_binding
    );
    assert_eq!(client_packet.run_binding, report.bindings.run_binding);
    assert_eq!(
        client_packet.evaluation_digest,
        report.bindings.evaluation_digest
    );
    let x_client_base = output_openers
        .client
        .open(&delivery.client)
        .expect("open client output packet");
    let x_relayer_base = output_openers
        .server
        .open(&delivery.server)
        .expect("open server output packet");
    assert_eq!(x_client_base, fixture.output.x_client_base);
    assert_eq!(x_relayer_base, fixture.output.x_relayer_base);
    assert_eq!(
        public_key_from_base_shares(x_client_base, x_relayer_base)
            .expect("derive public key from opened shares"),
        fixture.output.public_key
    );
}

#[test]
fn prime_order_succinct_hss_delivery_packets_round_trip_encoded_inputs() {
    let fixture = first_fixture();
    let session =
        prepare_prime_order_succinct_hss(&fixture.input.context).expect("prepare session");
    let (_runtime, garbler_session, evaluator_session) = session.split_runtime();
    let client_ot_offer_message = garbler_session
        .client_ot_offer_message()
        .expect("prepare client OT offer message");
    let (client_request_message, evaluator_ot_state) = evaluator_session
        .prepare_client_ot_request_from_offer_message(
            &client_ot_offer_message,
            fixture.input.y_client,
            fixture.input.tau_client,
        )
        .expect("prepare client OT request from offer");
    let (server_assist_init_message, _server_eval_state) = garbler_session
        .prepare_server_assist_init_message(
            &client_request_message,
            fixture.input.y_relayer,
            fixture.input.tau_relayer,
            ServerEvalOperation::Registration,
        )
        .expect("prepare server assist init message");
    let add_stage_request_message = evaluator_session
        .prepare_add_stage_request_message(
            &client_request_message,
            &evaluator_ot_state,
            &server_assist_init_message,
        )
        .expect("prepare add-stage request message");
    let add_stage_request: ClientStageRequestPacket = decode_transport_message(
        fixture.output.context_binding,
        TransportKind::ClientStageRequest,
        &add_stage_request_message,
    )
    .expect("decode add-stage request");
    let ClientStagePayload::AddStage(add_stage_payload) = add_stage_request.client_stage_payload
    else {
        panic!("expected add-stage request payload");
    };
    assert_eq!(
        add_stage_payload.client_input_commitment,
        add_stage_request.client_stage_commitments.digests[0]
    );
    assert_eq!(
        add_stage_payload.client_stage_openings_digest,
        add_stage_request.client_stage_commitments.digests[1]
    );
    assert!(
        decode_server_input_delivery(&session, &server_assist_init_message).is_err(),
        "server assist init must not decode through the legacy server-input seam",
    );
    assert!(String::from_utf8(server_assist_init_message.bytes.clone()).is_err());
}

#[test]
fn prime_order_succinct_hss_prepared_session_exposes_new_server_assist_rounds() {
    let fixture = first_fixture();
    let session =
        prepare_prime_order_succinct_hss(&fixture.input.context).expect("prepare session");
    let client_ot_offer_message = session
        .prepare_client_ot_offer_message()
        .expect("prepare client OT offer message");
    let garbler_ot_state = session
        .prepare_garbler_ot_state()
        .expect("prepare garbler ot state");
    let (client_request_message, evaluator_ot_state) = session
        .prepare_client_ot_request_from_offer_message(
            &client_ot_offer_message,
            fixture.input.y_client,
            fixture.input.tau_client,
        )
        .expect("prepare client ot request from offer");

    let (server_assist_init_message, server_eval_state) = session
        .prepare_server_assist_init_message(
            &garbler_ot_state,
            &client_request_message,
            fixture.input.y_relayer,
            fixture.input.tau_relayer,
            ServerEvalOperation::Registration,
        )
        .expect("prepare server assist init message");
    let server_assist_init: ServerAssistInitPacket = decode_transport_message(
        fixture.output.context_binding,
        TransportKind::ServerAssistInit,
        &server_assist_init_message,
    )
    .expect("decode server assist init message");

    let add_stage_request_message = session
        .prepare_add_stage_request_message(
            &client_request_message,
            &evaluator_ot_state,
            &server_assist_init_message,
        )
        .expect("prepare add-stage request message");
    let add_stage_request: ClientStageRequestPacket = decode_transport_message(
        fixture.output.context_binding,
        TransportKind::ClientStageRequest,
        &add_stage_request_message,
    )
    .expect("decode add-stage request message");

    let (add_stage_response_message, server_eval_state) = session
        .prepare_add_stage_response_message(&server_eval_state, &add_stage_request_message)
        .expect("prepare add-stage response message");
    let add_stage_response: ServerStageResponsePacket = decode_transport_message(
        fixture.output.context_binding,
        TransportKind::ServerStageResponse,
        &add_stage_response_message,
    )
    .expect("decode add-stage response message");
    let ed25519_hss::wire::ClientStagePayload::AddStage(add_stage_request_payload) =
        &add_stage_request.client_stage_payload
    else {
        panic!("expected add-stage request payload");
    };
    let ed25519_hss::wire::ServerStagePayload::AddStage(add_stage_response_payload) =
        &add_stage_response.server_stage_payload
    else {
        panic!("expected add-stage response payload");
    };

    let message_schedule_request_message = session
        .prepare_message_schedule_request_message(&add_stage_response_message)
        .expect("prepare message-schedule request message");
    let message_schedule_request: ClientStageRequestPacket = decode_transport_message(
        fixture.output.context_binding,
        TransportKind::ClientStageRequest,
        &message_schedule_request_message,
    )
    .expect("decode message-schedule request message");

    let (message_schedule_response_message, server_eval_state) = session
        .prepare_message_schedule_response_message(
            &server_eval_state,
            &message_schedule_request_message,
        )
        .expect("prepare message-schedule response message");
    let message_schedule_response: ServerStageResponsePacket = decode_transport_message(
        fixture.output.context_binding,
        TransportKind::ServerStageResponse,
        &message_schedule_response_message,
    )
    .expect("decode message-schedule response message");

    assert_eq!(
        server_assist_init.context_binding,
        fixture.output.context_binding
    );
    assert_eq!(
        add_stage_request.stage_id,
        ed25519_hss::wire::ServerEvalStageId::add_stage()
    );
    assert_eq!(
        add_stage_response.stage_id,
        ed25519_hss::wire::ServerEvalStageId::add_stage()
    );
    assert!(
        !add_stage_request_payload.y_client_bundle_payload.is_empty(),
        "add-stage request must carry the encoded y_client bundle for server-owned execution seeding"
    );
    assert!(
        !add_stage_request_payload.tau_client_bundle_payload.is_empty(),
        "add-stage request must carry the encoded tau_client bundle for server-owned execution seeding"
    );
    let ed25519_hss::wire::ClientStagePayload::MessageSchedule(message_schedule_request_payload) =
        &message_schedule_request.client_stage_payload
    else {
        panic!("expected message-schedule request payload");
    };
    assert_eq!(
        add_stage_response_payload.execution_checkpoint_digest,
        message_schedule_request_payload.prior_server_stage_digest
    );
    assert!(
        !server_eval_state.retains_raw_relayer_roots(),
        "post-add-stage server state must drop raw relayer roots"
    );
    match server_eval_state
        .execution_state
        .as_ref()
        .expect("post-add-stage execution state")
    {
        ServerEvalExecutionState::MessageSchedule(_) => {}
        other => panic!(
            "post-add-stage state should advance into message-schedule continuation, got {other:?}"
        ),
    }
    assert_eq!(
        message_schedule_request.stage_id,
        ed25519_hss::wire::ServerEvalStageId::message_schedule(0)
    );
    assert_eq!(
        message_schedule_response.stage_id,
        ed25519_hss::wire::ServerEvalStageId::message_schedule(0)
    );
    assert_eq!(
        server_eval_state.current_stage,
        ed25519_hss::wire::ServerEvalStageId::message_schedule(1)
    );
}

#[test]
fn prime_order_succinct_hss_prepared_session_exposes_first_round_core_round() {
    let fixture = first_fixture();
    let session =
        prepare_prime_order_succinct_hss(&fixture.input.context).expect("prepare session");
    let client_ot_offer_message = session
        .prepare_client_ot_offer_message()
        .expect("prepare client OT offer message");
    let garbler_ot_state = session
        .prepare_garbler_ot_state()
        .expect("prepare garbler ot state");
    let (client_request_message, evaluator_ot_state) = session
        .prepare_client_ot_request_from_offer_message(
            &client_ot_offer_message,
            fixture.input.y_client,
            fixture.input.tau_client,
        )
        .expect("prepare client ot request from offer");

    let (server_assist_init_message, mut server_eval_state) = session
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
    let (mut prior_stage_response_message, next_server_eval_state) = session
        .prepare_add_stage_response_message(&server_eval_state, &add_stage_request_message)
        .expect("prepare add-stage response message");
    server_eval_state = next_server_eval_state;

    for _ in 0..ed25519_hss::wire::ServerEvalStageId::MESSAGE_SCHEDULE_ROUNDS {
        let request_message = session
            .prepare_message_schedule_request_message(&prior_stage_response_message)
            .expect("prepare message-schedule request message");
        let (response_message, next_server_eval_state) = session
            .prepare_message_schedule_response_message(&server_eval_state, &request_message)
            .expect("prepare message-schedule response message");
        prior_stage_response_message = response_message;
        server_eval_state = next_server_eval_state;
    }

    let round_core_request_message = session
        .prepare_round_core_request_message(&prior_stage_response_message)
        .expect("prepare round-core request message");
    let round_core_request: ClientStageRequestPacket = decode_transport_message(
        fixture.output.context_binding,
        TransportKind::ClientStageRequest,
        &round_core_request_message,
    )
    .expect("decode round-core request message");

    let (round_core_response_message, server_eval_state) = session
        .prepare_round_core_response_message(&server_eval_state, &round_core_request_message)
        .expect("prepare round-core response message");
    let round_core_response: ServerStageResponsePacket = decode_transport_message(
        fixture.output.context_binding,
        TransportKind::ServerStageResponse,
        &round_core_response_message,
    )
    .expect("decode round-core response message");

    assert_eq!(
        round_core_request.stage_id,
        ed25519_hss::wire::ServerEvalStageId::round_core(0)
    );
    assert_eq!(
        round_core_response.stage_id,
        ed25519_hss::wire::ServerEvalStageId::round_core(0)
    );
    assert_eq!(
        server_eval_state.current_stage,
        ed25519_hss::wire::ServerEvalStageId::round_core(1)
    );
}

#[test]
fn prime_order_succinct_hss_prepared_session_exposes_repeatable_round_core_rounds() {
    let fixture = first_fixture();
    let session =
        prepare_prime_order_succinct_hss(&fixture.input.context).expect("prepare session");
    let client_ot_offer_message = session
        .prepare_client_ot_offer_message()
        .expect("prepare client OT offer message");
    let garbler_ot_state = session
        .prepare_garbler_ot_state()
        .expect("prepare garbler ot state");
    let (client_request_message, evaluator_ot_state) = session
        .prepare_client_ot_request_from_offer_message(
            &client_ot_offer_message,
            fixture.input.y_client,
            fixture.input.tau_client,
        )
        .expect("prepare client ot request from offer");

    let (server_assist_init_message, mut server_eval_state) = session
        .prepare_server_assist_init_message(
            &garbler_ot_state,
            &client_request_message,
            fixture.input.y_relayer,
            fixture.input.tau_relayer,
            ServerEvalOperation::Registration,
        )
        .expect("prepare server assist init message");
    let _ = server_assist_init_message;

    let add_stage_request_message = session
        .prepare_add_stage_request_message(
            &client_request_message,
            &evaluator_ot_state,
            &server_assist_init_message,
        )
        .expect("prepare add-stage request message");
    let (mut prior_stage_response_message, next_server_eval_state) = session
        .prepare_add_stage_response_message(&server_eval_state, &add_stage_request_message)
        .expect("prepare add-stage response message");
    server_eval_state = next_server_eval_state;

    for _ in 0..ed25519_hss::wire::ServerEvalStageId::MESSAGE_SCHEDULE_ROUNDS {
        let request_message = session
            .prepare_message_schedule_request_message(&prior_stage_response_message)
            .expect("prepare message-schedule request message");
        let (response_message, next_server_eval_state) = session
            .prepare_message_schedule_response_message(&server_eval_state, &request_message)
            .expect("prepare message-schedule response message");
        prior_stage_response_message = response_message;
        server_eval_state = next_server_eval_state;
    }

    let round_core_request_message_0 = session
        .prepare_round_core_request_message(&prior_stage_response_message)
        .expect("prepare first round-core request message");
    let (round_core_response_message_0, next_server_eval_state) = session
        .prepare_round_core_response_message(&server_eval_state, &round_core_request_message_0)
        .expect("prepare first round-core response message");
    server_eval_state = next_server_eval_state;

    let round_core_request_message_1 = session
        .prepare_round_core_request_message(&round_core_response_message_0)
        .expect("prepare second round-core request message");
    let round_core_request_1: ClientStageRequestPacket = decode_transport_message(
        fixture.output.context_binding,
        TransportKind::ClientStageRequest,
        &round_core_request_message_1,
    )
    .expect("decode second round-core request message");

    let (round_core_response_message_1, server_eval_state) = session
        .prepare_round_core_response_message(&server_eval_state, &round_core_request_message_1)
        .expect("prepare second round-core response message");
    let round_core_response_1: ServerStageResponsePacket = decode_transport_message(
        fixture.output.context_binding,
        TransportKind::ServerStageResponse,
        &round_core_response_message_1,
    )
    .expect("decode second round-core response message");

    assert_eq!(
        round_core_request_1.stage_id,
        ed25519_hss::wire::ServerEvalStageId::round_core(1)
    );
    assert_eq!(
        round_core_response_1.stage_id,
        ed25519_hss::wire::ServerEvalStageId::round_core(1)
    );
    assert_eq!(
        server_eval_state.current_stage,
        ed25519_hss::wire::ServerEvalStageId::round_core(2)
    );
}

#[test]
fn prime_order_succinct_hss_prepared_session_exposes_output_projection_round() {
    let fixture = first_fixture();
    let session =
        prepare_prime_order_succinct_hss(&fixture.input.context).expect("prepare session");
    let client_ot_offer_message = session
        .prepare_client_ot_offer_message()
        .expect("prepare client OT offer message");
    let garbler_ot_state = session
        .prepare_garbler_ot_state()
        .expect("prepare garbler ot state");
    let (client_request_message, evaluator_ot_state) = session
        .prepare_client_ot_request_from_offer_message(
            &client_ot_offer_message,
            fixture.input.y_client,
            fixture.input.tau_client,
        )
        .expect("prepare client ot request from offer");

    let (server_assist_init_message, mut server_eval_state) = session
        .prepare_server_assist_init_message(
            &garbler_ot_state,
            &client_request_message,
            fixture.input.y_relayer,
            fixture.input.tau_relayer,
            ServerEvalOperation::Registration,
        )
        .expect("prepare server assist init message");
    let _ = server_assist_init_message;

    let add_stage_request_message = session
        .prepare_add_stage_request_message(
            &client_request_message,
            &evaluator_ot_state,
            &server_assist_init_message,
        )
        .expect("prepare add-stage request message");
    let (mut prior_stage_response_message, next_server_eval_state) = session
        .prepare_add_stage_response_message(&server_eval_state, &add_stage_request_message)
        .expect("prepare add-stage response message");
    server_eval_state = next_server_eval_state;

    for _ in 0..ed25519_hss::wire::ServerEvalStageId::MESSAGE_SCHEDULE_ROUNDS {
        let request_message = session
            .prepare_message_schedule_request_message(&prior_stage_response_message)
            .expect("prepare message-schedule request message");
        let (response_message, next_server_eval_state) = session
            .prepare_message_schedule_response_message(&server_eval_state, &request_message)
            .expect("prepare message-schedule response message");
        prior_stage_response_message = response_message;
        server_eval_state = next_server_eval_state;
    }

    for _ in 0..ed25519_hss::wire::ServerEvalStageId::ROUND_CORE_ROUNDS {
        let request_message = session
            .prepare_round_core_request_message(&prior_stage_response_message)
            .expect("prepare round-core request message");
        let (response_message, next_server_eval_state) = session
            .prepare_round_core_response_message(&server_eval_state, &request_message)
            .expect("prepare round-core response message");
        prior_stage_response_message = response_message;
        server_eval_state = next_server_eval_state;
    }

    let output_projection_request_message = session
        .prepare_output_projection_request_message(&prior_stage_response_message)
        .expect("prepare output-projection request message");
    let output_projection_request: ClientStageRequestPacket = decode_transport_message(
        fixture.output.context_binding,
        TransportKind::ClientStageRequest,
        &output_projection_request_message,
    )
    .expect("decode output-projection request message");

    let (output_projection_response_message, server_eval_state) = session
        .prepare_output_projection_response_message(
            &server_eval_state,
            &output_projection_request_message,
        )
        .expect("prepare output-projection response message");
    let output_projection_response: ServerStageResponsePacket = decode_transport_message(
        fixture.output.context_binding,
        TransportKind::ServerStageResponse,
        &output_projection_response_message,
    )
    .expect("decode output-projection response message");

    assert_eq!(
        output_projection_request.stage_id,
        ed25519_hss::wire::ServerEvalStageId::output_projection()
    );
    assert_eq!(
        output_projection_response.stage_id,
        ed25519_hss::wire::ServerEvalStageId::output_projection()
    );
    assert_eq!(
        server_eval_state.current_stage,
        ed25519_hss::wire::ServerEvalStageId::output_projection()
    );
    assert_eq!(
        server_eval_state.status,
        ed25519_hss::server::ServerEvalStatus::Finalized
    );
}

#[test]
fn prime_order_succinct_hss_prepared_session_can_drive_staged_flow_to_output_projection() {
    let fixture = first_fixture();
    let session =
        prepare_prime_order_succinct_hss(&fixture.input.context).expect("prepare session");
    let client_ot_offer_message = session
        .prepare_client_ot_offer_message()
        .expect("prepare client OT offer message");
    let garbler_ot_state = session
        .prepare_garbler_ot_state()
        .expect("prepare garbler ot state");
    let (client_request_message, evaluator_ot_state) = session
        .prepare_client_ot_request_from_offer_message(
            &client_ot_offer_message,
            fixture.input.y_client,
            fixture.input.tau_client,
        )
        .expect("prepare client ot request from offer");

    let flow = session
        .prepare_server_assist_flow_to_output_projection(
            &garbler_ot_state,
            &client_request_message,
            &evaluator_ot_state,
            fixture.input.y_relayer,
            fixture.input.tau_relayer,
            ServerEvalOperation::Registration,
        )
        .expect("prepare staged flow to output projection");

    let server_assist_init: ServerAssistInitPacket = decode_transport_message(
        fixture.output.context_binding,
        TransportKind::ServerAssistInit,
        &flow.server_assist_init_message,
    )
    .expect("decode server assist init");
    let output_projection_response: ServerStageResponsePacket = decode_transport_message(
        fixture.output.context_binding,
        TransportKind::ServerStageResponse,
        &flow.output_projection_response_message,
    )
    .expect("decode output projection response");
    let ed25519_hss::wire::ServerStagePayload::OutputProjection(output_projection_payload) =
        &output_projection_response.server_stage_payload
    else {
        panic!("expected output-projection payload");
    };

    assert_eq!(
        server_assist_init.context_binding,
        fixture.output.context_binding
    );
    assert_eq!(
        flow.message_schedule_request_messages.len(),
        ed25519_hss::wire::ServerEvalStageId::MESSAGE_SCHEDULE_ROUNDS as usize
    );
    assert_eq!(
        flow.message_schedule_response_messages.len(),
        ed25519_hss::wire::ServerEvalStageId::MESSAGE_SCHEDULE_ROUNDS as usize
    );
    assert_eq!(
        flow.round_core_request_messages.len(),
        ed25519_hss::wire::ServerEvalStageId::ROUND_CORE_ROUNDS as usize
    );
    assert_eq!(
        flow.round_core_response_messages.len(),
        ed25519_hss::wire::ServerEvalStageId::ROUND_CORE_ROUNDS as usize
    );
    assert_eq!(
        output_projection_response.stage_id,
        ed25519_hss::wire::ServerEvalStageId::output_projection()
    );
    assert_eq!(
        flow.final_server_eval_state.current_stage,
        ed25519_hss::wire::ServerEvalStageId::output_projection()
    );
    assert_eq!(
        flow.final_server_eval_state.status,
        ed25519_hss::server::ServerEvalStatus::Finalized
    );
    assert!(
        flow.final_server_eval_state.stores_stage_local_continuation(),
        "staged flow should store a stage-local continuation"
    );
    assert_ne!(
        output_projection_payload.execution_checkpoint_digest,
        flow.final_server_eval_state
            .current_execution_checkpoint_digest()
            .expect("finalized output-projection digest on staged flow state"),
        "output-projection response should bind the pre-finalize continuation digest, not the finalized output digest",
    );
    assert!(
        flow.final_server_eval_state.finalize_state().is_some(),
        "output-projection completion should materialize finalize state",
    );
}

#[test]
fn prime_order_succinct_hss_validates_staged_flow_to_output_projection() {
    let fixture = first_fixture();
    let session =
        prepare_prime_order_succinct_hss(&fixture.input.context).expect("prepare session");
    let client_ot_offer_message = session
        .prepare_client_ot_offer_message()
        .expect("prepare client OT offer message");
    let garbler_ot_state = session
        .prepare_garbler_ot_state()
        .expect("prepare garbler ot state");
    let (client_request_message, evaluator_ot_state) = session
        .prepare_client_ot_request_from_offer_message(
            &client_ot_offer_message,
            fixture.input.y_client,
            fixture.input.tau_client,
        )
        .expect("prepare client ot request from offer");
    let flow = session
        .prepare_server_assist_flow_to_output_projection(
            &garbler_ot_state,
            &client_request_message,
            &evaluator_ot_state,
            fixture.input.y_relayer,
            fixture.input.tau_relayer,
            ServerEvalOperation::Registration,
        )
        .expect("prepare staged flow to output projection");

    let final_response = session
        .validate_server_assist_flow_to_output_projection(
            &client_request_message,
            &evaluator_ot_state,
            &flow,
        )
        .expect("validate staged flow to output projection");

    assert_eq!(
        final_response.stage_id,
        ed25519_hss::wire::ServerEvalStageId::output_projection()
    );
    assert_eq!(
        final_response.next_transcript_digest,
        flow.final_server_eval_state.current_transcript_digest
    );
}

#[test]
fn prime_order_succinct_hss_prepares_server_finalize_message_from_staged_flow() {
    let fixture = first_fixture();
    let session =
        prepare_prime_order_succinct_hss(&fixture.input.context).expect("prepare session");
    let runtime = session.shared_runtime();
    let client_ot_offer_message = session
        .prepare_client_ot_offer_message()
        .expect("prepare client OT offer message");
    let garbler_ot_state = session
        .prepare_garbler_ot_state()
        .expect("prepare garbler ot state");
    let (client_request_message, evaluator_ot_state) = session
        .prepare_client_ot_request_from_offer_message(
            &client_ot_offer_message,
            fixture.input.y_client,
            fixture.input.tau_client,
        )
        .expect("prepare client ot request from offer");
    let flow = session
        .prepare_server_assist_flow_to_output_projection(
            &garbler_ot_state,
            &client_request_message,
            &evaluator_ot_state,
            fixture.input.y_relayer,
            fixture.input.tau_relayer,
            ServerEvalOperation::Registration,
        )
        .expect("prepare staged flow to output projection");
    let _ = session
        .validate_server_assist_flow_to_output_projection(
            &client_request_message,
            &evaluator_ot_state,
            &flow,
        )
        .expect("validate staged flow");
    let staged_evaluator_artifact = session
        .build_server_owned_staged_evaluator_artifact_from_server_eval_state(
            &flow.final_server_eval_state,
        )
        .expect("server-owned staged evaluator artifact");
    let (server_finalize_message, report) = session
        .prepare_server_finalize_message_from_staged_evaluator_artifact(
            &runtime,
            &flow.final_server_eval_state,
            &staged_evaluator_artifact,
        )
        .expect("prepare server finalize message");
    let server_finalize = session
        .validate_server_assist_flow_to_finalize(
            &client_request_message,
            &evaluator_ot_state,
            &flow,
            &server_finalize_message,
        )
        .expect("validate staged flow to finalize");

    assert_eq!(
        server_finalize.context_binding,
        fixture.output.context_binding
    );
    assert_eq!(
        server_finalize.server_eval_handle,
        flow.final_server_eval_state.handle
    );
    assert_eq!(
        server_finalize.final_transcript_digest,
        flow.final_server_eval_state.current_transcript_digest
    );
    assert_eq!(server_finalize.client_output, report.output_delivery.client);
    assert!(server_finalize.seed_output.is_none());
}

#[test]
fn prime_order_succinct_hss_prepares_server_finalize_from_staged_evaluator_artifact() {
    let fixture = first_fixture();
    let session =
        prepare_prime_order_succinct_hss(&fixture.input.context).expect("prepare session");
    let runtime = session.shared_runtime();
    let client_ot_offer_message = session
        .prepare_client_ot_offer_message()
        .expect("prepare client OT offer message");
    let garbler_ot_state = session
        .prepare_garbler_ot_state()
        .expect("prepare garbler ot state");
    let (client_request_message, evaluator_ot_state) = session
        .prepare_client_ot_request_from_offer_message(
            &client_ot_offer_message,
            fixture.input.y_client,
            fixture.input.tau_client,
        )
        .expect("prepare client ot request from offer");
    let flow = session
        .prepare_server_assist_flow_to_output_projection(
            &garbler_ot_state,
            &client_request_message,
            &evaluator_ot_state,
            fixture.input.y_relayer,
            fixture.input.tau_relayer,
            ServerEvalOperation::Registration,
        )
        .expect("prepare staged flow to output projection");
    let _ = session
        .validate_server_assist_flow_to_finalize(
            &client_request_message,
            &evaluator_ot_state,
            &flow,
            &session
                .prepare_server_finalize_message_from_staged_evaluator_artifact(
                    &runtime,
                    &flow.final_server_eval_state,
                    &session
                        .build_server_owned_staged_evaluator_artifact_from_server_eval_state(
                            &flow.final_server_eval_state,
                        )
                        .expect("server-owned staged evaluator artifact"),
                )
                .expect("prepare server finalize message")
                .0,
        )
        .expect("validate staged flow to finalize");

    let artifact = session
        .build_server_owned_staged_evaluator_artifact_from_server_eval_state(
            &flow.final_server_eval_state,
        )
        .expect("server-owned staged evaluator artifact");
    let (server_finalize, report) = session
        .prepare_server_finalize_from_staged_evaluator_artifact(
            &runtime,
            &flow.final_server_eval_state,
            &artifact,
        )
        .expect("prepare server finalize from staged artifact");

    assert_eq!(
        server_finalize.context_binding,
        fixture.output.context_binding
    );
    assert_eq!(
        server_finalize.server_eval_handle,
        flow.final_server_eval_state.handle
    );
    assert_eq!(
        server_finalize.final_transcript_digest,
        flow.final_server_eval_state.current_transcript_digest
    );
    assert_eq!(server_finalize.client_output, report.output_delivery.client);
    assert!(server_finalize.seed_output.is_none());
}

#[test]
#[ignore = "end-to-end delivery packet evaluation now runs the full DDH hidden evaluator and is too expensive for the default debug lane"]
fn prime_order_succinct_hss_delivery_packets_round_trip_end_to_end() {
    let fixture = first_fixture();
    let session =
        prepare_prime_order_succinct_hss(&fixture.input.context).expect("prepare session");
    let evaluated = session
        .evaluate_for_clear_input_debug(&fixture.input)
        .expect("evaluate prepared session");
    let output_openers = session.output_openers();
    assert_eq!(
        output_openers
            .client
            .open(&evaluated.output_delivery.client)
            .expect("open client output"),
        fixture.output.x_client_base
    );
    assert_eq!(
        output_openers
            .seed
            .open(&evaluated.output_delivery.seed)
            .expect("open seed output"),
        fixture.output.d
    );
    assert_eq!(
        output_openers
            .server
            .open(&evaluated.output_delivery.server)
            .expect("open server output"),
        fixture.output.x_relayer_base
    );
}

#[test]
#[ignore = "single-fixture DDH hidden-eval conformance is currently too expensive for the default debug test lane"]
fn prime_order_succinct_hss_matches_reference_fixture_smoke() {
    let fixture = first_fixture();
    let session =
        prepare_prime_order_succinct_hss(&fixture.input.context).expect("prepare session");
    let report = session
        .evaluate_for_clear_input_debug(&fixture.input)
        .expect("evaluate prepared session");

    let output_openers = session.output_openers();
    let x_client_base = output_openers
        .client
        .open(&report.output_delivery.client)
        .expect("open client output");
    let canonical_seed = output_openers
        .seed
        .open(&report.output_delivery.seed)
        .expect("open seed output");
    let x_relayer_base = output_openers
        .server
        .open(&report.output_delivery.server)
        .expect("open server output");
    assert_eq!(canonical_seed, fixture.output.d);
    assert_eq!(x_client_base, fixture.output.x_client_base);
    assert_eq!(x_relayer_base, fixture.output.x_relayer_base);
    assert_eq!(
        public_key_from_base_shares(x_client_base, x_relayer_base).expect("derive public key"),
        fixture.output.public_key
    );
    assert_eq!(
        report.hidden_core_materialization,
        HiddenCoreMaterialization::DdhPrimitiveBaseline
    );
    assert_eq!(report.artifact.artifact_bytes, 138_256);
    assert_eq!(
        report.artifact.context_binding,
        fixture.output.context_binding
    );
    assert_eq!(session.hidden_eval_program().active_window_records, 180);
    assert_eq!(
        report.evaluator_witness.total_steps,
        session.execution_program().trace.total_steps
    );
}

#[test]
#[ignore = "full five-fixture DDH hidden-eval conformance remains a Phase 3b milestone"]
fn prime_order_succinct_hss_matches_reference_fixtures() {
    for fixture in deterministic_fixture_corpus().expect("fixture corpus") {
        let session =
            prepare_prime_order_succinct_hss(&fixture.input.context).expect("prepare session");
        let report = session
            .evaluate_for_clear_input_debug(&fixture.input)
            .expect("evaluate prepared session");
        let output_openers = session.output_openers();
        let x_client_base = output_openers
            .client
            .open(&report.output_delivery.client)
            .expect("open client output");
        let x_relayer_base = output_openers
            .server
            .open(&report.output_delivery.server)
            .expect("open server output");
        assert_eq!(x_client_base, fixture.output.x_client_base);
        assert_eq!(x_relayer_base, fixture.output.x_relayer_base);
        assert_eq!(
            public_key_from_base_shares(x_client_base, x_relayer_base).expect("derive public key"),
            fixture.output.public_key
        );
    }
}

#[test]
fn prime_order_succinct_hss_rejects_context_mismatch() {
    let fixtures = deterministic_fixture_corpus().expect("fixture corpus");
    let session =
        prepare_prime_order_succinct_hss(&fixtures[0].input.context).expect("prepare session");
    let err = session
        .evaluate_for_clear_input_debug(&fixtures[1].input)
        .expect_err("mismatched context should fail");

    assert!(matches!(err, ProtoError::InvalidInput(_)));
}
