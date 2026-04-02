use ed25519_hss::reference::public_key_from_base_shares;
use ed25519_hss::{
    prepare_prime_order_succinct_hss, HiddenCoreMaterialization, HiddenEvalInputOwner,
};

use crate::support::{
    decode_client_input_delivery, decode_client_offer, decode_client_output_message,
    decode_client_request, decode_server_input_delivery, decode_server_input_payload_json,
    decode_server_message, first_fixture,
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
    let server_message = garbler_session
        .prepare_server_message(
            &client_request_message,
            fixture.input.y_relayer,
            fixture.input.tau_relayer,
        )
        .expect("prepare server message");
    let server_packet = decode_server_message(fixture.output.context_binding, &server_message)
        .expect("decode server message");

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
        server_packet.context_binding,
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
        server_packet.ot_transcript.y_client_request_commitment,
        client_packet.y_client_request.commitment
    );
    assert_eq!(
        server_packet.ot_transcript.tau_client_request_commitment,
        client_packet.tau_client_request.commitment
    );
    assert_eq!(
        server_packet.ot_transcript.y_client_offer_commitment,
        client_ot_offer.y_client_offer.commitment
    );
    assert_eq!(
        server_packet.ot_transcript.tau_client_offer_commitment,
        client_ot_offer.tau_client_offer.commitment
    );
    assert_eq!(
        server_packet.y_client_remote_release.owner,
        HiddenEvalInputOwner::Client
    );
    assert_eq!(
        server_packet.tau_client_remote_release.owner,
        HiddenEvalInputOwner::Client
    );
    assert_eq!(
        server_packet.y_client_response.owner,
        HiddenEvalInputOwner::Client
    );
    assert_eq!(
        server_packet.tau_client_response.owner,
        HiddenEvalInputOwner::Client
    );
    assert_eq!(
        server_packet.y_client_remote_release.request_commitment,
        client_packet.y_client_request.commitment
    );
    assert_eq!(
        server_packet.tau_client_remote_release.request_commitment,
        client_packet.tau_client_request.commitment
    );
    assert_eq!(
        server_packet.y_client_remote_release.response_commitment,
        server_packet.y_client_response.commitment
    );
    assert_eq!(
        server_packet.tau_client_remote_release.response_commitment,
        server_packet.tau_client_response.commitment
    );
    assert_eq!(
        server_packet.y_client_remote_release.transcript_binding,
        server_packet.ot_transcript.y_client_remote_release_binding
    );
    assert_eq!(
        server_packet.tau_client_remote_release.transcript_binding,
        server_packet
            .ot_transcript
            .tau_client_remote_release_binding
    );
    let decoded_server_inputs = decode_server_input_delivery(&session, &server_message)
        .expect("decode sealed server input delivery");
    assert_eq!(decoded_server_inputs.0, fixture.input.y_relayer);
    assert_eq!(decoded_server_inputs.1, fixture.input.tau_relayer);
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
        server_packet.server_inputs.server_input_commitment,
        session.ddh_backend().combined_input_commitment(
            HiddenEvalInputOwner::Server,
            &[&expected_y_relayer_bundle, &expected_tau_relayer_bundle],
        )
    );
    assert!(String::from_utf8(server_message.bytes.clone()).is_err());
    let server_input_payload_json = decode_server_input_payload_json(&session, &server_message)
        .expect("decode server input payload json");
    assert!(!server_input_payload_json.contains("left_word"));
    assert!(!server_input_payload_json.contains("right_word"));
    assert!(server_input_payload_json.contains("share_word"));
}

#[test]
#[ignore = "output delivery packet verification now runs the full DDH hidden evaluator and is too expensive for the default debug lane"]
fn prime_order_succinct_hss_splits_output_delivery_packets() {
    let fixture = first_fixture();
    let session =
        prepare_prime_order_succinct_hss(&fixture.input.context).expect("prepare session");
    let report = session.evaluate(&fixture.input).expect("evaluate session");
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
    let server_message = garbler_session
        .prepare_server_message(
            &client_request_message,
            fixture.input.y_relayer,
            fixture.input.tau_relayer,
        )
        .expect("prepare server message");
    let decoded_client = decode_client_input_delivery(
        &session,
        &client_request_message,
        &evaluator_ot_state,
        &server_message,
    )
    .expect("decode client input delivery");
    assert_eq!(decoded_client.0, fixture.input.y_client);
    assert_eq!(decoded_client.1, fixture.input.tau_client);
    let decoded_server = decode_server_input_delivery(&session, &server_message)
        .expect("decode server input delivery");
    assert_eq!(decoded_server.0, fixture.input.y_relayer);
    assert_eq!(decoded_server.1, fixture.input.tau_relayer);
    assert!(String::from_utf8(server_message.bytes.clone()).is_err());
    let server_input_payload_json = decode_server_input_payload_json(&session, &server_message)
        .expect("decode server input payload json");
    assert!(!server_input_payload_json.contains("left_word"));
    assert!(!server_input_payload_json.contains("right_word"));
    assert!(server_input_payload_json.contains("share_word"));
}

#[test]
#[ignore = "end-to-end delivery packet evaluation now runs the full DDH hidden evaluator and is too expensive for the default debug lane"]
fn prime_order_succinct_hss_delivery_packets_round_trip_end_to_end() {
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
    let server_message = garbler_session
        .prepare_server_message(
            &client_request_message,
            fixture.input.y_relayer,
            fixture.input.tau_relayer,
        )
        .expect("prepare server message");

    let evaluated = session
        .evaluate_from_transport_messages(
            &client_request_message,
            &evaluator_ot_state,
            &server_message,
        )
        .expect("evaluate transport messages");
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
        .evaluate(&fixture.input)
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
    for fixture in ed25519_hss::deterministic_fixture_corpus().expect("fixture corpus") {
        let session =
            prepare_prime_order_succinct_hss(&fixture.input.context).expect("prepare session");
        let report = session
            .evaluate(&fixture.input)
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
    let fixtures = ed25519_hss::deterministic_fixture_corpus().expect("fixture corpus");
    let session =
        prepare_prime_order_succinct_hss(&fixtures[0].input.context).expect("prepare session");
    let err = session
        .evaluate(&fixtures[1].input)
        .expect_err("mismatched context should fail");

    assert!(matches!(err, ed25519_hss::ProtoError::InvalidInput(_)));
}
