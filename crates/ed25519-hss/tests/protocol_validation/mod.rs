use ed25519_hss::fixtures::committed_fixture_corpus;
use ed25519_hss::protocol::prepare_prime_order_succinct_hss;

use crate::support::{
    build_server_owned_staged_evaluator_artifact, decode_transport_message,
    encode_transport_message, first_fixture, TransportKind,
};

#[test]
fn prime_order_succinct_hss_rejects_server_assist_init_from_different_request_same_context() {
    let fixture = first_fixture();
    let session =
        prepare_prime_order_succinct_hss(&fixture.input.context).expect("prepare session");
    let (_runtime, garbler_session, evaluator_session) = session.split_runtime();
    let client_ot_offer_message = garbler_session
        .client_ot_offer_message()
        .expect("prepare client OT offer message");

    let (request_a, evaluator_ot_state_a) = evaluator_session
        .prepare_client_ot_request_from_offer_message(
            &client_ot_offer_message,
            fixture.input.y_client,
            fixture.input.tau_client,
        )
        .expect("prepare request a");

    let mut y_client_b = fixture.input.y_client;
    y_client_b[0] ^= 0x01;
    let (request_b, _evaluator_ot_state_b) = evaluator_session
        .prepare_client_ot_request_from_offer_message(
            &client_ot_offer_message,
            y_client_b,
            fixture.input.tau_client,
        )
        .expect("prepare request b");

    let (server_assist_init_message_b, _server_eval_state_b) = garbler_session
        .prepare_server_assist_init_message(
            &request_b,
            fixture.input.y_relayer,
            fixture.input.tau_relayer,
            ed25519_hss::server::ServerEvalOperation::Registration,
        )
        .expect("prepare server assist init for request b");

    let err = evaluator_session
        .decode_server_assist_init_message(
            &request_a,
            &evaluator_ot_state_a,
            &server_assist_init_message_b,
        )
        .expect_err("same-context request/release mismatch must fail");
    assert!(
        err.to_string().contains("request")
            || err.to_string().contains("transcript")
            || err.to_string().contains("remote-share")
            || err.to_string().contains("open OT branch payload")
            || err.to_string().contains("aead"),
        "unexpected same-context mismatch error: {err}"
    );
}

#[test]
fn prime_order_succinct_hss_rejects_swapped_server_assist_init_releases_same_context() {
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
        .expect("prepare client OT request");
    let (server_assist_init_message, _server_eval_state) = garbler_session
        .prepare_server_assist_init_message(
            &client_request_message,
            fixture.input.y_relayer,
            fixture.input.tau_relayer,
            ed25519_hss::server::ServerEvalOperation::Registration,
        )
        .expect("prepare server assist init");
    let mut server_assist_init: ed25519_hss::wire::ServerAssistInitPacket =
        decode_transport_message(
            fixture.output.context_binding,
            TransportKind::ServerAssistInit,
            &server_assist_init_message,
        )
        .expect("decode server assist init");
    std::mem::swap(
        &mut server_assist_init.y_client_remote_release,
        &mut server_assist_init.tau_client_remote_release,
    );
    let swapped_server_assist_init_message = encode_transport_message(
        fixture.output.context_binding,
        TransportKind::ServerAssistInit,
        &server_assist_init,
    )
    .expect("encode swapped server assist init");

    let err = evaluator_session
        .decode_server_assist_init_message(
            &client_request_message,
            &evaluator_ot_state,
            &swapped_server_assist_init_message,
        )
        .expect_err("swapped same-context OT releases must fail");
    assert!(
        err.to_string().contains("label")
            || err.to_string().contains("request")
            || err.to_string().contains("remote-share"),
        "unexpected swapped-release error: {err}"
    );
}

#[test]
fn prime_order_succinct_hss_rejects_server_assist_init_release_with_tampered_context_binding() {
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
        .expect("prepare client OT request");
    let (server_assist_init_message, _server_eval_state) = garbler_session
        .prepare_server_assist_init_message(
            &client_request_message,
            fixture.input.y_relayer,
            fixture.input.tau_relayer,
            ed25519_hss::server::ServerEvalOperation::Registration,
        )
        .expect("prepare server assist init");
    let mut server_assist_init: ed25519_hss::wire::ServerAssistInitPacket =
        decode_transport_message(
            fixture.output.context_binding,
            TransportKind::ServerAssistInit,
            &server_assist_init_message,
        )
        .expect("decode server assist init");
    server_assist_init.y_client_remote_release.context_binding[0] ^= 0x01;
    let tampered_server_assist_init_message = encode_transport_message(
        fixture.output.context_binding,
        TransportKind::ServerAssistInit,
        &server_assist_init,
    )
    .expect("encode tampered server assist init");

    let err = evaluator_session
        .decode_server_assist_init_message(
            &client_request_message,
            &evaluator_ot_state,
            &tampered_server_assist_init_message,
        )
        .expect_err("tampered release context binding must fail");
    assert!(
        err.to_string().contains("context binding"),
        "unexpected tampered-context error: {err}"
    );
}

#[test]
fn prime_order_succinct_hss_rejects_add_stage_response_with_tampered_context_binding() {
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
        .expect("prepare client OT request");
    let (server_assist_init_message, server_eval_state) = garbler_session
        .prepare_server_assist_init_message(
            &client_request_message,
            fixture.input.y_relayer,
            fixture.input.tau_relayer,
            ed25519_hss::server::ServerEvalOperation::Registration,
        )
        .expect("prepare server assist init");
    let add_stage_request_message = evaluator_session
        .prepare_add_stage_request_message(
            &client_request_message,
            &evaluator_ot_state,
            &server_assist_init_message,
        )
        .expect("prepare add-stage request");
    let (add_stage_response_message, _next_state) = garbler_session
        .prepare_add_stage_response_message(&server_eval_state, &add_stage_request_message)
        .expect("prepare add-stage response");

    let mut add_stage_response: ed25519_hss::wire::ServerStageResponsePacket =
        decode_transport_message(
            fixture.output.context_binding,
            TransportKind::ServerStageResponse,
            &add_stage_response_message,
        )
        .expect("decode add-stage response");
    add_stage_response.context_binding[0] ^= 0x01;
    let tampered_add_stage_response_message = encode_transport_message(
        fixture.output.context_binding,
        TransportKind::ServerStageResponse,
        &add_stage_response,
    )
    .expect("encode tampered add-stage response");

    let err = evaluator_session
        .decode_add_stage_response_message(
            &client_request_message,
            &evaluator_ot_state,
            &server_assist_init_message,
            &add_stage_request_message,
            &tampered_add_stage_response_message,
        )
        .expect_err("tampered add-stage response context binding must fail");
    assert!(
        err.to_string().contains("context binding"),
        "unexpected add-stage tampered-context error: {err}"
    );
}

#[test]
fn prime_order_succinct_hss_rejects_cross_account_message_schedule_response() {
    let fixtures = committed_fixture_corpus().expect("fixture corpus");
    let session_a =
        prepare_prime_order_succinct_hss(&fixtures[0].input.context).expect("prepare session a");
    let session_b =
        prepare_prime_order_succinct_hss(&fixtures[1].input.context).expect("prepare session b");

    let evaluator_session_a = session_a.evaluator_session();
    let client_ot_offer_message_a = session_a
        .prepare_client_ot_offer_message()
        .expect("prepare client OT offer message a");
    let garbler_ot_state_a = session_a
        .prepare_garbler_ot_state()
        .expect("prepare garbler ot state a");
    let (client_request_message_a, evaluator_ot_state_a) = session_a
        .prepare_client_ot_request_from_offer_message(
            &client_ot_offer_message_a,
            fixtures[0].input.y_client,
            fixtures[0].input.tau_client,
        )
        .expect("prepare client OT request a");
    let (server_assist_init_message_a, server_eval_state_a) = session_a
        .prepare_server_assist_init_message(
            &garbler_ot_state_a,
            &client_request_message_a,
            fixtures[0].input.y_relayer,
            fixtures[0].input.tau_relayer,
            ed25519_hss::server::ServerEvalOperation::Registration,
        )
        .expect("prepare server assist init a");
    let add_stage_request_message_a = session_a
        .prepare_add_stage_request_message(
            &client_request_message_a,
            &evaluator_ot_state_a,
            &server_assist_init_message_a,
        )
        .expect("prepare add-stage request a");
    let (add_stage_response_message_a, _next_state_a) = session_a
        .prepare_add_stage_response_message(&server_eval_state_a, &add_stage_request_message_a)
        .expect("prepare add-stage response a");
    let message_schedule_request_message_a = session_a
        .prepare_message_schedule_request_message(&add_stage_response_message_a)
        .expect("prepare message-schedule request a");

    let client_ot_offer_message_b = session_b
        .prepare_client_ot_offer_message()
        .expect("prepare client OT offer message b");
    let garbler_ot_state_b = session_b
        .prepare_garbler_ot_state()
        .expect("prepare garbler ot state b");
    let (client_request_message_b, evaluator_ot_state_b) = session_b
        .prepare_client_ot_request_from_offer_message(
            &client_ot_offer_message_b,
            fixtures[1].input.y_client,
            fixtures[1].input.tau_client,
        )
        .expect("prepare client OT request b");
    let (server_assist_init_message_b, server_eval_state_b) = session_b
        .prepare_server_assist_init_message(
            &garbler_ot_state_b,
            &client_request_message_b,
            fixtures[1].input.y_relayer,
            fixtures[1].input.tau_relayer,
            ed25519_hss::server::ServerEvalOperation::Registration,
        )
        .expect("prepare server assist init b");
    let add_stage_request_message_b = session_b
        .prepare_add_stage_request_message(
            &client_request_message_b,
            &evaluator_ot_state_b,
            &server_assist_init_message_b,
        )
        .expect("prepare add-stage request b");
    let (add_stage_response_message_b, next_state_b) = session_b
        .prepare_add_stage_response_message(&server_eval_state_b, &add_stage_request_message_b)
        .expect("prepare add-stage response b");
    let message_schedule_request_message_b = session_b
        .prepare_message_schedule_request_message(&add_stage_response_message_b)
        .expect("prepare message-schedule request b");
    let (message_schedule_response_message_b, _next_state_b) = session_b
        .prepare_message_schedule_response_message(
            &next_state_b,
            &message_schedule_request_message_b,
        )
        .expect("prepare message-schedule response b");

    let err = evaluator_session_a
        .decode_message_schedule_response_message(
            &server_assist_init_message_a,
            &message_schedule_request_message_a,
            &message_schedule_response_message_b,
        )
        .expect_err("cross-account message-schedule response must fail");
    assert!(
        err.to_string().contains("context binding")
            || err.to_string().contains("handle")
            || err.to_string().contains("stage id"),
        "unexpected cross-account message-schedule error: {err}"
    );
}

#[test]
fn prime_order_succinct_hss_rejects_output_projection_replay_after_finalization() {
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
            ed25519_hss::server::ServerEvalOperation::Registration,
        )
        .expect("prepare staged flow to output projection");

    let err = session
        .prepare_output_projection_response_message(
            &flow.final_server_eval_state,
            &flow.output_projection_request_message,
        )
        .expect_err("finalized handle must reject output-projection replay");
    assert!(
        err.to_string().contains("finalized"),
        "unexpected finalized replay error: {err}"
    );
}

#[test]
fn prime_order_succinct_hss_rejects_server_finalize_artifact_that_does_not_match_finalize_state() {
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
            ed25519_hss::server::ServerEvalOperation::Registration,
        )
        .expect("prepare staged flow to output projection");
    let mut artifact = session
        .build_server_owned_staged_evaluator_artifact_from_server_eval_state(
            &flow.final_server_eval_state,
        )
        .expect("server-owned staged evaluator artifact");
    artifact.bindings.evaluation_digest[0] ^= 0x01;

    let err = session
        .prepare_server_finalize_from_staged_evaluator_artifact(
            &runtime,
            &flow.final_server_eval_state,
            &artifact,
        )
        .expect_err("tampered artifact must fail finalize-state binding");
    assert!(
        err.to_string().contains("finalize state")
            || err.to_string().contains("evaluation digest"),
        "unexpected finalize-state mismatch error: {err}"
    );
}

#[test]
fn prime_order_succinct_hss_rejects_tampered_server_output_payload_in_evaluation_result() {
    let fixture = first_fixture();
    let session =
        prepare_prime_order_succinct_hss(&fixture.input.context).expect("prepare session");
    let (runtime, garbler_session, evaluator_session) = session.split_runtime();
    let client_ot_offer_message = garbler_session
        .client_ot_offer_message()
        .expect("prepare client OT offer message");
    let _ = evaluator_session
        .prepare_client_ot_request_from_offer_message(
            &client_ot_offer_message,
            fixture.input.y_client,
            fixture.input.tau_client,
        )
        .expect("prepare client OT request");
    let mut staged_evaluator_artifact =
        build_server_owned_staged_evaluator_artifact(&session, &fixture.input)
            .expect("staged evaluator artifact");
    staged_evaluator_artifact.server_output_payload[0] ^= 0x01;

    let err = runtime
        .finalize_report_from_staged_evaluator_artifact(&garbler_session, &staged_evaluator_artifact)
        .expect_err("tampered server output payload must fail");
    assert!(
        err.to_string().contains("server output payload binding"),
        "unexpected tampered-server-output error: {err}"
    );
}

#[test]
fn prime_order_succinct_hss_rejects_tampered_client_output_in_evaluation_result() {
    let fixture = first_fixture();
    let session =
        prepare_prime_order_succinct_hss(&fixture.input.context).expect("prepare session");
    let (runtime, garbler_session, evaluator_session) = session.split_runtime();
    let client_ot_offer_message = garbler_session
        .client_ot_offer_message()
        .expect("prepare client OT offer message");
    let _ = evaluator_session
        .prepare_client_ot_request_from_offer_message(
            &client_ot_offer_message,
            fixture.input.y_client,
            fixture.input.tau_client,
        )
        .expect("prepare client OT request");
    let mut staged_evaluator_artifact =
        build_server_owned_staged_evaluator_artifact(&session, &fixture.input)
            .expect("staged evaluator artifact");
    let last_idx = staged_evaluator_artifact.client_output.bytes.len() - 1;
    staged_evaluator_artifact.client_output.bytes[last_idx] ^= 0x01;

    let err = runtime
        .finalize_report_from_staged_evaluator_artifact(&garbler_session, &staged_evaluator_artifact)
        .expect_err("tampered client output must fail");
    assert!(
        err.to_string().contains("client output binding"),
        "unexpected tampered-client-output error: {err}"
    );
}

#[test]
fn prime_order_succinct_hss_rejects_swapped_client_output_between_same_context_runs() {
    let fixtures = committed_fixture_corpus().expect("fixture corpus");
    let session =
        prepare_prime_order_succinct_hss(&fixtures[0].input.context).expect("prepare session");
    let (runtime, garbler_session, evaluator_session) = session.split_runtime();
    let client_ot_offer_message = garbler_session
        .client_ot_offer_message()
        .expect("prepare client OT offer message");

    let _ = evaluator_session
        .prepare_client_ot_request_from_offer_message(
            &client_ot_offer_message,
            fixtures[0].input.y_client,
            fixtures[0].input.tau_client,
        )
        .expect("prepare client OT request A");
    let mut staged_evaluator_artifact_a =
        build_server_owned_staged_evaluator_artifact(&session, &fixtures[0].input)
            .expect("staged evaluator artifact A");

    let _ = evaluator_session
        .prepare_client_ot_request_from_offer_message(
            &client_ot_offer_message,
            fixtures[1].input.y_client,
            fixtures[1].input.tau_client,
        )
        .expect("prepare client OT request B");
    let mut same_context_input_b = fixtures[1].input.clone();
    same_context_input_b.context = fixtures[0].input.context.clone();
    let staged_evaluator_artifact_b =
        build_server_owned_staged_evaluator_artifact(&session, &same_context_input_b)
            .expect("staged evaluator artifact B");

    staged_evaluator_artifact_a.client_output = staged_evaluator_artifact_b.client_output;

    let err = runtime
        .finalize_report_from_staged_evaluator_artifact(
            &garbler_session,
            &staged_evaluator_artifact_a,
        )
        .expect_err("swapped client output between same-context runs must fail");
    assert!(
        err.to_string().contains("client output packet")
            || err.to_string().contains("client output binding"),
        "unexpected swapped-client-output error: {err}"
    );
}

#[test]
fn prime_order_succinct_hss_rejects_swapped_server_output_payload_between_same_context_runs() {
    let fixtures = committed_fixture_corpus().expect("fixture corpus");
    let session =
        prepare_prime_order_succinct_hss(&fixtures[0].input.context).expect("prepare session");
    let (runtime, garbler_session, evaluator_session) = session.split_runtime();
    let client_ot_offer_message = garbler_session
        .client_ot_offer_message()
        .expect("prepare client OT offer message");

    let _ = evaluator_session
        .prepare_client_ot_request_from_offer_message(
            &client_ot_offer_message,
            fixtures[0].input.y_client,
            fixtures[0].input.tau_client,
        )
        .expect("prepare client OT request A");
    let mut staged_evaluator_artifact_a =
        build_server_owned_staged_evaluator_artifact(&session, &fixtures[0].input)
            .expect("staged evaluator artifact A");

    let _ = evaluator_session
        .prepare_client_ot_request_from_offer_message(
            &client_ot_offer_message,
            fixtures[1].input.y_client,
            fixtures[1].input.tau_client,
        )
        .expect("prepare client OT request B");
    let mut same_context_input_b = fixtures[1].input.clone();
    same_context_input_b.context = fixtures[0].input.context.clone();
    let staged_evaluator_artifact_b =
        build_server_owned_staged_evaluator_artifact(&session, &same_context_input_b)
            .expect("staged evaluator artifact B");

    staged_evaluator_artifact_a.server_output_payload =
        staged_evaluator_artifact_b.server_output_payload;

    let err = runtime
        .finalize_report_from_staged_evaluator_artifact(
            &garbler_session,
            &staged_evaluator_artifact_a,
        )
        .expect_err("swapped server output payload between same-context runs must fail");
    assert!(
        err.to_string().contains("server output payload binding"),
        "unexpected swapped-server-output error: {err}"
    );
}
