use ed25519_hss::fixtures::deterministic_fixture_corpus;
use ed25519_hss::protocol::prepare_prime_order_succinct_hss;

use crate::support::contains_subslice;

#[test]
fn evaluator_driver_state_serialization_excludes_garbler_sender_state() {
    let fixture = deterministic_fixture_corpus()
        .expect("fixture corpus")
        .into_iter()
        .next()
        .expect("fixture");
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
fn wire_messages_do_not_embed_clear_client_or_server_inputs() {
    let fixture = deterministic_fixture_corpus()
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
        .expect("non-degenerate boundary fixture");
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
    let server_message = garbler_session
        .prepare_server_message(
            &client_request_message,
            fixture.input.y_relayer,
            fixture.input.tau_relayer,
        )
        .expect("prepare server message");
    let evaluation_result_message = evaluator_session
        .evaluate_result_message_from_transport_messages(
            &session.shared_runtime(),
            &client_request_message,
            &evaluator_ot_state,
            &server_message,
        )
        .expect("evaluate result message");
    let report = garbler_session
        .finalize_report_from_evaluation_result_message(
            &session.shared_runtime(),
            &evaluation_result_message,
        )
        .expect("finalize report");

    for (label, message_bytes) in [
        ("client_ot_offer", client_ot_offer_message.bytes.as_slice()),
        ("client_request", client_request_message.bytes.as_slice()),
        ("server_message", server_message.bytes.as_slice()),
        (
            "evaluation_result",
            evaluation_result_message.bytes.as_slice(),
        ),
        (
            "client_output",
            report.output_delivery.client.bytes.as_slice(),
        ),
        ("seed_output", report.output_delivery.seed.bytes.as_slice()),
        (
            "server_output",
            report.output_delivery.server.bytes.as_slice(),
        ),
    ] {
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
