use ed25519_hss::fixtures::committed_fixture_corpus;
use ed25519_hss::protocol::prepare_prime_order_succinct_hss;

use crate::support::{
    decode_evaluation_result_message, decode_server_message, encode_transport_message,
    first_fixture, TransportKind,
};

#[test]
fn prime_order_succinct_hss_rejects_server_message_from_different_request_same_context() {
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

    let server_message_b = garbler_session
        .prepare_server_message(
            &request_b,
            fixture.input.y_relayer,
            fixture.input.tau_relayer,
        )
        .expect("prepare server message for request b");

    let err = session
        .evaluate_from_transport_messages(&request_a, &evaluator_ot_state_a, &server_message_b)
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
fn prime_order_succinct_hss_rejects_swapped_remote_releases_same_context() {
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
    let server_message = garbler_session
        .prepare_server_message(
            &client_request_message,
            fixture.input.y_relayer,
            fixture.input.tau_relayer,
        )
        .expect("prepare server message");
    let mut server_packet = decode_server_message(fixture.output.context_binding, &server_message)
        .expect("decode server message");
    std::mem::swap(
        &mut server_packet.y_client_remote_release,
        &mut server_packet.tau_client_remote_release,
    );
    let swapped_server_message = encode_transport_message(
        fixture.output.context_binding,
        TransportKind::ServerPacket,
        &server_packet,
    )
    .expect("encode swapped server message");

    let err = session
        .evaluate_from_transport_messages(
            &client_request_message,
            &evaluator_ot_state,
            &swapped_server_message,
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
fn prime_order_succinct_hss_rejects_remote_release_with_tampered_context_binding() {
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
    let server_message = garbler_session
        .prepare_server_message(
            &client_request_message,
            fixture.input.y_relayer,
            fixture.input.tau_relayer,
        )
        .expect("prepare server message");
    let mut server_packet = decode_server_message(fixture.output.context_binding, &server_message)
        .expect("decode server message");
    server_packet.y_client_remote_release.context_binding[0] ^= 0x01;
    let tampered_server_message = encode_transport_message(
        fixture.output.context_binding,
        TransportKind::ServerPacket,
        &server_packet,
    )
    .expect("encode tampered server message");

    let err = session
        .evaluate_from_transport_messages(
            &client_request_message,
            &evaluator_ot_state,
            &tampered_server_message,
        )
        .expect_err("tampered release context binding must fail");
    assert!(
        err.to_string().contains("context binding"),
        "unexpected tampered-context error: {err}"
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
    let (client_request_message, evaluator_ot_state) = evaluator_session
        .prepare_client_ot_request_from_offer_message(
            &client_ot_offer_message,
            fixture.input.y_client,
            fixture.input.tau_client,
        )
        .expect("prepare client OT request");
    let server_message = garbler_session
        .prepare_server_message(
            &client_request_message,
            fixture.input.y_relayer,
            fixture.input.tau_relayer,
        )
        .expect("prepare server message");
    let evaluation_result_message = evaluator_session
        .evaluate_result_message_from_transport_messages(
            &runtime,
            &client_request_message,
            &evaluator_ot_state,
            &server_message,
        )
        .expect("evaluate result message");
    let mut evaluation_result = decode_evaluation_result_message(
        fixture.output.context_binding,
        &evaluation_result_message,
    )
    .expect("decode evaluation result message");
    evaluation_result.server_output_payload[0] ^= 0x01;
    let tampered_evaluation_result_message = encode_transport_message(
        fixture.output.context_binding,
        TransportKind::EvaluationResult,
        &evaluation_result,
    )
    .expect("encode tampered evaluation result message");

    let err = garbler_session
        .finalize_report_from_evaluation_result_message(
            &runtime,
            &tampered_evaluation_result_message,
        )
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
    let (client_request_message, evaluator_ot_state) = evaluator_session
        .prepare_client_ot_request_from_offer_message(
            &client_ot_offer_message,
            fixture.input.y_client,
            fixture.input.tau_client,
        )
        .expect("prepare client OT request");
    let server_message = garbler_session
        .prepare_server_message(
            &client_request_message,
            fixture.input.y_relayer,
            fixture.input.tau_relayer,
        )
        .expect("prepare server message");
    let evaluation_result_message = evaluator_session
        .evaluate_result_message_from_transport_messages(
            &runtime,
            &client_request_message,
            &evaluator_ot_state,
            &server_message,
        )
        .expect("evaluate result message");
    let mut evaluation_result = decode_evaluation_result_message(
        fixture.output.context_binding,
        &evaluation_result_message,
    )
    .expect("decode evaluation result message");
    let last_idx = evaluation_result.client_output.bytes.len() - 1;
    evaluation_result.client_output.bytes[last_idx] ^= 0x01;
    let tampered_evaluation_result_message = encode_transport_message(
        fixture.output.context_binding,
        TransportKind::EvaluationResult,
        &evaluation_result,
    )
    .expect("encode tampered evaluation result message");

    let err = garbler_session
        .finalize_report_from_evaluation_result_message(
            &runtime,
            &tampered_evaluation_result_message,
        )
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

    let (client_request_message_a, evaluator_ot_state_a) = evaluator_session
        .prepare_client_ot_request_from_offer_message(
            &client_ot_offer_message,
            fixtures[0].input.y_client,
            fixtures[0].input.tau_client,
        )
        .expect("prepare client OT request A");
    let server_message_a = garbler_session
        .prepare_server_message(
            &client_request_message_a,
            fixtures[0].input.y_relayer,
            fixtures[0].input.tau_relayer,
        )
        .expect("prepare server message A");
    let evaluation_result_message_a = evaluator_session
        .evaluate_result_message_from_transport_messages(
            &runtime,
            &client_request_message_a,
            &evaluator_ot_state_a,
            &server_message_a,
        )
        .expect("evaluate result message A");
    let mut evaluation_result_a = decode_evaluation_result_message(
        fixtures[0].output.context_binding,
        &evaluation_result_message_a,
    )
    .expect("decode evaluation result A");

    let (client_request_message_b, evaluator_ot_state_b) = evaluator_session
        .prepare_client_ot_request_from_offer_message(
            &client_ot_offer_message,
            fixtures[1].input.y_client,
            fixtures[1].input.tau_client,
        )
        .expect("prepare client OT request B");
    let server_message_b = garbler_session
        .prepare_server_message(
            &client_request_message_b,
            fixtures[1].input.y_relayer,
            fixtures[1].input.tau_relayer,
        )
        .expect("prepare server message B");
    let evaluation_result_message_b = evaluator_session
        .evaluate_result_message_from_transport_messages(
            &runtime,
            &client_request_message_b,
            &evaluator_ot_state_b,
            &server_message_b,
        )
        .expect("evaluate result message B");
    let evaluation_result_b = decode_evaluation_result_message(
        fixtures[0].output.context_binding,
        &evaluation_result_message_b,
    )
    .expect("decode evaluation result B");

    evaluation_result_a.client_output = evaluation_result_b.client_output;
    let tampered_evaluation_result_message = encode_transport_message(
        fixtures[0].output.context_binding,
        TransportKind::EvaluationResult,
        &evaluation_result_a,
    )
    .expect("encode tampered evaluation result");

    let err = garbler_session
        .finalize_report_from_evaluation_result_message(
            &runtime,
            &tampered_evaluation_result_message,
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

    let (client_request_message_a, evaluator_ot_state_a) = evaluator_session
        .prepare_client_ot_request_from_offer_message(
            &client_ot_offer_message,
            fixtures[0].input.y_client,
            fixtures[0].input.tau_client,
        )
        .expect("prepare client OT request A");
    let server_message_a = garbler_session
        .prepare_server_message(
            &client_request_message_a,
            fixtures[0].input.y_relayer,
            fixtures[0].input.tau_relayer,
        )
        .expect("prepare server message A");
    let evaluation_result_message_a = evaluator_session
        .evaluate_result_message_from_transport_messages(
            &runtime,
            &client_request_message_a,
            &evaluator_ot_state_a,
            &server_message_a,
        )
        .expect("evaluate result message A");
    let mut evaluation_result_a = decode_evaluation_result_message(
        fixtures[0].output.context_binding,
        &evaluation_result_message_a,
    )
    .expect("decode evaluation result A");

    let (client_request_message_b, evaluator_ot_state_b) = evaluator_session
        .prepare_client_ot_request_from_offer_message(
            &client_ot_offer_message,
            fixtures[1].input.y_client,
            fixtures[1].input.tau_client,
        )
        .expect("prepare client OT request B");
    let server_message_b = garbler_session
        .prepare_server_message(
            &client_request_message_b,
            fixtures[1].input.y_relayer,
            fixtures[1].input.tau_relayer,
        )
        .expect("prepare server message B");
    let evaluation_result_message_b = evaluator_session
        .evaluate_result_message_from_transport_messages(
            &runtime,
            &client_request_message_b,
            &evaluator_ot_state_b,
            &server_message_b,
        )
        .expect("evaluate result message B");
    let evaluation_result_b = decode_evaluation_result_message(
        fixtures[0].output.context_binding,
        &evaluation_result_message_b,
    )
    .expect("decode evaluation result B");

    evaluation_result_a.server_output_payload = evaluation_result_b.server_output_payload;
    let tampered_evaluation_result_message = encode_transport_message(
        fixtures[0].output.context_binding,
        TransportKind::EvaluationResult,
        &evaluation_result_a,
    )
    .expect("encode tampered evaluation result");

    let err = garbler_session
        .finalize_report_from_evaluation_result_message(
            &runtime,
            &tampered_evaluation_result_message,
        )
        .expect_err("swapped server output payload between same-context runs must fail");
    assert!(
        err.to_string().contains("server output payload binding"),
        "unexpected swapped-server-output error: {err}"
    );
}
