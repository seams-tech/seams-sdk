use curve25519_dalek::scalar::Scalar;
use ed25519_hss::client::ClientDriverState;
use ed25519_hss::client::{ClientSession, OutputOpeners};
use ed25519_hss::ddh::DdhHssBackendVersion;
use ed25519_hss::fixtures::deterministic_fixture_corpus;
use ed25519_hss::protocol::prepare_prime_order_succinct_hss;
use ed25519_hss::runtime::flow::{
    advance_server_eval_state_to_output_projection_request,
    finalize_advanced_server_eval_state_with_output_projection,
    finalize_server_eval_state_from_add_stage_request, PreparedServerAssistFlow,
};
use ed25519_hss::runtime::SharedRuntime;
use ed25519_hss::server::{ServerDriverState, ServerEvalOperation, ServerEvalState, ServerSession};
use ed25519_hss::wire::{
    ClientStageRequestPacket, OutputProjectionMode, RoleSeparatedClientStagePayload,
    RoleSeparatedOutputDeliveryPayload, ServerAssistInitPacket, ServerStageResponsePacket,
    StagedEvaluatorArtifact, WireMessage,
};

use crate::support::{
    build_client_owned_staged_evaluator_artifact, contains_subslice, decode_client_request,
    decode_server_input_delivery, decode_transport_message, encode_transport_message,
    TransportKind, TEST_CLIENT_OUTPUT_MASK,
};

const STALE_DDH_HSS_BACKEND_VERSION: &str = "ddh_hss_backend_v1_output_projector_binding";

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
                && has_entropy(&fixture.input.y_server)
                && has_entropy(&fixture.input.tau_server)
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
                && has_entropy(&fixture.input.y_server)
                && has_entropy(&fixture.input.tau_server)
        })
        .expect("fixture with distinct context")
}

fn replace_json_string_values(value: &mut serde_json::Value, from: &str, to: &str) {
    match value {
        serde_json::Value::String(raw) if raw == from => {
            *raw = to.to_string();
        }
        serde_json::Value::Array(items) => {
            for item in items {
                replace_json_string_values(item, from, to);
            }
        }
        serde_json::Value::Object(map) => {
            for item in map.values_mut() {
                replace_json_string_values(item, from, to);
            }
        }
        _ => {}
    }
}

fn stale_backend_json_value<T: serde::Serialize>(value: &T) -> serde_json::Value {
    let mut json = serde_json::to_value(value).expect("serialize driver state");
    replace_json_string_values(
        &mut json,
        DdhHssBackendVersion::CURRENT.as_str(),
        STALE_DDH_HSS_BACKEND_VERSION,
    );
    json
}

struct RegistrationAdvanceFixture {
    runtime: SharedRuntime,
    garbler_session: ServerSession,
    evaluator_session: ClientSession,
    initial_server_eval_state: ServerEvalState,
    add_stage_request_message: WireMessage,
    staged_evaluator_artifact: StagedEvaluatorArtifact,
    output_openers: OutputOpeners,
}

fn registration_advance_fixture(
    input: &ed25519_hss::shared::FExpandInput,
) -> RegistrationAdvanceFixture {
    let session = prepare_prime_order_succinct_hss(&input.context).expect("prepare session");
    let runtime = session.shared_runtime();
    let garbler_session = session.garbler_session();
    let evaluator_session = session.evaluator_session();
    let client_ot_offer_message = garbler_session
        .client_ot_offer_message()
        .expect("client OT offer message");
    let (client_request_message, evaluator_ot_state) = evaluator_session
        .prepare_client_ot_request_from_offer_message(
            &client_ot_offer_message,
            input.y_client,
            input.tau_client,
        )
        .expect("client OT request message");
    let client_packet =
        decode_client_request(session.candidate().context_binding, &client_request_message)
            .expect("decode client request");
    let (delivery, initial_server_eval_state) = garbler_session
        .prepare_role_separated_server_input_delivery(
            &client_packet,
            input.y_server,
            input.tau_server,
            ServerEvalOperation::Registration,
        )
        .expect("role-separated server input delivery");
    let server_assist_init = ServerAssistInitPacket::from_role_separated_delivery(&delivery);
    let server_assist_init_message = encode_transport_message(
        session.candidate().context_binding,
        TransportKind::ServerAssistInit,
        &server_assist_init,
    )
    .expect("server assist init message");
    let add_stage_request_message = session
        .prepare_add_stage_request_message(
            &client_request_message,
            &evaluator_ot_state,
            &server_assist_init_message,
        )
        .expect("add-stage request message");
    let staged_evaluator_artifact = evaluator_session
        .build_client_owned_staged_evaluator_artifact_from_role_separated_delivery(
            &runtime,
            &client_packet,
            &evaluator_ot_state,
            &delivery,
            TEST_CLIENT_OUTPUT_MASK,
        )
        .expect("client-owned staged evaluator artifact");

    RegistrationAdvanceFixture {
        runtime,
        garbler_session,
        evaluator_session,
        initial_server_eval_state,
        add_stage_request_message,
        staged_evaluator_artifact,
        output_openers: session.output_openers(),
    }
}

#[test]
fn prepared_add_stage_request_validates_client_owned_artifact_commitment() {
    let fixture = boundary_fixture();
    let session =
        prepare_prime_order_succinct_hss(&fixture.input.context).expect("prepare session");
    let runtime = session.shared_runtime();
    let garbler_session = session.garbler_session();
    let evaluator_session = session.evaluator_session();
    let client_ot_offer_message = garbler_session
        .client_ot_offer_message()
        .expect("client OT offer message");
    let (client_request_message, evaluator_ot_state) = evaluator_session
        .prepare_client_ot_request_from_offer_message(
            &client_ot_offer_message,
            fixture.input.y_client,
            fixture.input.tau_client,
        )
        .expect("client OT request message");
    let client_packet =
        decode_client_request(session.candidate().context_binding, &client_request_message)
            .expect("decode client request");
    let (delivery, _initial_server_eval_state) = garbler_session
        .prepare_role_separated_server_input_delivery(
            &client_packet,
            fixture.input.y_server,
            fixture.input.tau_server,
            ServerEvalOperation::Registration,
        )
        .expect("role-separated server input delivery");
    let add_stage_request_message_a = evaluator_session
        .prepare_add_stage_request_message_from_role_separated_delivery(
            &client_request_message,
            &evaluator_ot_state,
            &delivery,
        )
        .expect("prepare add-stage request message A");
    let add_stage_request_message_b = evaluator_session
        .prepare_add_stage_request_message_from_role_separated_delivery(
            &client_request_message,
            &evaluator_ot_state,
            &delivery,
        )
        .expect("prepare add-stage request message B");
    assert_ne!(
        add_stage_request_message_a, add_stage_request_message_b,
        "add-stage request messages carry a fresh client nonce"
    );

    let artifact = evaluator_session
        .build_client_owned_staged_evaluator_artifact_from_role_separated_delivery(
            &runtime,
            &client_packet,
            &evaluator_ot_state,
            &delivery,
            TEST_CLIENT_OUTPUT_MASK,
        )
        .expect("client-owned staged evaluator artifact");
    evaluator_session
        .validate_add_stage_request_message_from_role_separated_delivery_for_commitment(
            &client_request_message,
            &evaluator_ot_state,
            &delivery,
            &add_stage_request_message_a,
            artifact.bindings.client_input_commitment,
        )
        .expect("prepared add-stage request validates against artifact commitment");
    assert!(
        evaluator_session
            .validate_add_stage_request_message_from_role_separated_delivery_for_commitment(
                &client_request_message,
                &evaluator_ot_state,
                &delivery,
                &add_stage_request_message_a,
                [0u8; 32],
            )
            .is_err(),
        "wrong artifact commitment must be rejected"
    );
}

#[test]
#[ignore = "full durable-advance/replay equivalence is too expensive for the default debug test lane"]
fn durable_advanced_eval_round_trip_matches_current_finalize_replay() {
    let fixture = boundary_fixture();
    let prepared = registration_advance_fixture(&fixture.input);
    let advanced = advance_server_eval_state_to_output_projection_request(
        &prepared.runtime,
        &prepared.garbler_session,
        &prepared.evaluator_session,
        &prepared.initial_server_eval_state,
        &prepared.add_stage_request_message,
    )
    .expect("advance server eval state");
    assert!(
        advanced.state.finalize_state().is_none(),
        "advanced state must stop before output projection"
    );

    let advanced_state_bytes =
        serde_json::to_vec(&advanced.state).expect("serialize advanced server state");
    let advanced_state_round_trip: ServerEvalState =
        serde_json::from_slice(&advanced_state_bytes).expect("deserialize advanced server state");
    let prior_stage_response_bytes = serde_json::to_vec(&advanced.prior_stage_response_message)
        .expect("serialize prior stage response");
    let prior_stage_response_round_trip: WireMessage =
        serde_json::from_slice(&prior_stage_response_bytes).expect("deserialize prior response");

    let finalized_from_advanced = finalize_advanced_server_eval_state_with_output_projection(
        &prepared.garbler_session,
        &prepared.evaluator_session,
        &advanced_state_round_trip,
        &prior_stage_response_round_trip,
        &prepared.staged_evaluator_artifact.projection_mode,
    )
    .expect("finalize advanced server eval state");
    let finalized_from_replay = finalize_server_eval_state_from_add_stage_request(
        &prepared.runtime,
        &prepared.garbler_session,
        &prepared.evaluator_session,
        &prepared.initial_server_eval_state,
        &prepared.add_stage_request_message,
        &prepared.staged_evaluator_artifact.projection_mode,
    )
    .expect("finalize server eval state from add-stage request");

    assert!(
        finalized_from_advanced.state.finalize_state().is_some(),
        "advanced path must produce finalized server state"
    );
    assert!(
        finalized_from_replay.state.finalize_state().is_some(),
        "replay path must produce finalized server state"
    );
    let (_packet_from_advanced, report_from_advanced) = prepared
        .garbler_session
        .prepare_server_finalize_packet_from_staged_evaluator_artifact(
            &prepared.runtime,
            &finalized_from_advanced.state,
            &prepared.staged_evaluator_artifact,
        )
        .expect("server finalize packet from advanced state");
    let (_packet_from_replay, report_from_replay) = prepared
        .garbler_session
        .prepare_server_finalize_packet_from_staged_evaluator_artifact(
            &prepared.runtime,
            &finalized_from_replay.state,
            &prepared.staged_evaluator_artifact,
        )
        .expect("server finalize packet from replay state");

    let advanced_seed_output = prepared
        .output_openers
        .seed
        .open(&report_from_advanced.output_delivery.seed)
        .expect("open advanced seed output");
    let replay_seed_output = prepared
        .output_openers
        .seed
        .open(&report_from_replay.output_delivery.seed)
        .expect("open replay seed output");
    let advanced_server_output = prepared
        .output_openers
        .server
        .open(&report_from_advanced.output_delivery.server)
        .expect("open advanced server output");
    let replay_server_output = prepared
        .output_openers
        .server
        .open(&report_from_replay.output_delivery.server)
        .expect("open replay server output");

    assert_eq!(advanced_seed_output, replay_seed_output);
    assert_eq!(advanced_server_output, replay_server_output);
    assert_eq!(
        report_from_advanced.artifact.context_binding,
        report_from_replay.artifact.context_binding
    );
}

#[test]
fn durable_advanced_eval_rejects_tampered_or_context_mismatched_add_stage_request() {
    let fixture = boundary_fixture();
    let prepared = registration_advance_fixture(&fixture.input);
    let mut tampered_add_stage_request = prepared.add_stage_request_message.clone();
    let last_byte = tampered_add_stage_request
        .bytes
        .last_mut()
        .expect("add-stage request byte");
    *last_byte ^= 0x01;

    let tampered_err = advance_server_eval_state_to_output_projection_request(
        &prepared.runtime,
        &prepared.garbler_session,
        &prepared.evaluator_session,
        &prepared.initial_server_eval_state,
        &tampered_add_stage_request,
    )
    .expect_err("tampered add-stage request must fail");
    assert!(
        tampered_err.to_string().contains("decode")
            || tampered_err.to_string().contains("commitment")
            || tampered_err.to_string().contains("transcript"),
        "unexpected tampered add-stage request error: {tampered_err}"
    );

    let other_fixture = second_boundary_fixture();
    let other_prepared = registration_advance_fixture(&other_fixture.input);
    let context_err = advance_server_eval_state_to_output_projection_request(
        &other_prepared.runtime,
        &other_prepared.garbler_session,
        &other_prepared.evaluator_session,
        &other_prepared.initial_server_eval_state,
        &prepared.add_stage_request_message,
    )
    .expect_err("context-mismatched add-stage request must fail");
    assert!(
        context_err.to_string().contains("context")
            || context_err.to_string().contains("binding")
            || context_err.to_string().contains("transcript"),
        "unexpected context-mismatched add-stage request error: {context_err}"
    );
}

#[test]
fn client_output_mask_scalar_round_trip_recovers_base_share() {
    let x_client_base = Scalar::from_bytes_mod_order([0x42; 32]);
    let client_output_mask = Scalar::from_bytes_mod_order([0x5a; 32]);
    let blinded = x_client_base + client_output_mask;
    let opened = blinded - client_output_mask;

    assert_eq!(opened.to_bytes(), x_client_base.to_bytes());
    assert_ne!(blinded.to_bytes(), x_client_base.to_bytes());
}

#[test]
fn serialized_evaluator_driver_state_rejects_stale_backend_wire_string() {
    let fixture = boundary_fixture();
    let session =
        prepare_prime_order_succinct_hss(&fixture.input.context).expect("prepare session");
    let stale_json = stale_backend_json_value(&session.evaluator_driver_state());
    let err = serde_json::from_value::<ClientDriverState>(stale_json)
        .expect_err("stale evaluator driver state must be rejected");

    assert!(
        err.to_string()
            .contains("unsupported DDH HSS backend version"),
        "unexpected stale evaluator state error: {err}"
    );
}

#[test]
fn serialized_garbler_driver_state_rejects_stale_backend_wire_string() {
    let fixture = boundary_fixture();
    let session =
        prepare_prime_order_succinct_hss(&fixture.input.context).expect("prepare session");
    let stale_json = stale_backend_json_value(&session.garbler_driver_state());
    let err = serde_json::from_value::<ServerDriverState>(stale_json)
        .expect_err("stale garbler driver state must be rejected");

    assert!(
        err.to_string()
            .contains("unsupported DDH HSS backend version"),
        "unexpected stale garbler state error: {err}"
    );
}

#[test]
fn server_driver_state_rejects_corrupt_advance_runtime_checkpoint() {
    let fixture = boundary_fixture();
    let session =
        prepare_prime_order_succinct_hss(&fixture.input.context).expect("prepare session");
    let valid = session.garbler_driver_state();
    valid
        .advance_runtime_material()
        .expect("valid advance runtime checkpoint");

    let mut wrong_context = valid.clone();
    wrong_context.advance_runtime.context_binding[0] ^= 0x01;
    let wrong_context_err = wrong_context
        .advance_runtime_material()
        .expect_err("wrong advance context binding must be rejected");
    assert!(
        wrong_context_err.to_string().contains("context binding"),
        "unexpected wrong-context error: {wrong_context_err}"
    );

    let mut wrong_artifact_digest = valid.clone();
    wrong_artifact_digest
        .advance_runtime
        .artifact
        .artifact_digest[0] ^= 0x01;
    wrong_artifact_digest
        .advance_runtime
        .finalize_context
        .artifact
        .artifact_digest[0] ^= 0x01;
    let wrong_artifact_digest_err = wrong_artifact_digest
        .advance_runtime_material()
        .expect_err("wrong advance artifact digest must be rejected");
    assert!(
        wrong_artifact_digest_err
            .to_string()
            .contains("artifact bytes do not match artifact digest"),
        "unexpected wrong-artifact-digest error: {wrong_artifact_digest_err}"
    );

    let mut truncated_artifact = valid.clone();
    truncated_artifact.advance_runtime.artifact_bytes.truncate(
        truncated_artifact
            .advance_runtime
            .artifact_bytes
            .len()
            .saturating_sub(1),
    );
    let truncated_artifact_err = truncated_artifact
        .advance_runtime_material()
        .expect_err("truncated advance artifact bytes must be rejected");
    assert!(
        truncated_artifact_err
            .to_string()
            .contains("artifact bytes do not match artifact digest"),
        "unexpected truncated-artifact error: {truncated_artifact_err}"
    );

    let mut wrong_program_digest = valid;
    wrong_program_digest.advance_runtime.program_digest[0] ^= 0x01;
    let wrong_program_digest_err = wrong_program_digest
        .advance_runtime_material()
        .expect_err("wrong advance program digest must be rejected");
    assert!(
        wrong_program_digest_err
            .to_string()
            .contains("program digest"),
        "unexpected wrong-program-digest error: {wrong_program_digest_err}"
    );
}

#[test]
fn staged_artifact_rejects_stale_backend_wire_string() {
    let fixture = boundary_fixture();
    let session =
        prepare_prime_order_succinct_hss(&fixture.input.context).expect("prepare session");
    let artifact = build_client_owned_staged_evaluator_artifact(&session, &fixture.input)
        .expect("client-owned staged evaluator artifact");
    let stale_json = stale_backend_json_value(&artifact);
    let err = serde_json::from_value::<ed25519_hss::wire::StagedEvaluatorArtifact>(stale_json)
        .expect_err("stale staged artifact must be rejected");

    assert!(
        err.to_string()
            .contains("unsupported DDH HSS backend version"),
        "unexpected stale staged artifact error: {err}"
    );
}

#[test]
fn server_finalize_state_omits_client_output_bundle_and_commitment_metadata() {
    let fixture = boundary_fixture();
    let session =
        prepare_prime_order_succinct_hss(&fixture.input.context).expect("prepare session");
    let garbler_ot_state = session
        .prepare_garbler_ot_state()
        .expect("prepare garbler OT state");
    let client_ot_offer_message = session
        .prepare_client_ot_offer_message()
        .expect("prepare client OT offer");
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
            fixture.input.y_server,
            fixture.input.tau_server,
            ServerEvalOperation::Registration,
        )
        .expect("prepare staged flow");
    let finalize_state = flow
        .final_server_eval_state
        .finalize_state()
        .expect("finalize state");
    let output_debug = format!("{:?}", finalize_state.output);

    assert!(
        !output_debug.contains("client_output_value_kind"),
        "server finalize output state must not retain client-output value-kind metadata",
    );
    assert!(
        !output_debug.contains("client_output_commitment"),
        "server finalize output state must not retain client-output commitment metadata",
    );
    assert!(
        !output_debug.contains("DdhHiddenEvalClientOutputBundle"),
        "server finalize output state must not retain the client output bundle",
    );
    assert!(
        !output_debug.contains("bundle:"),
        "server finalize output state must not retain a client output bundle field",
    );
    assert!(
        !output_debug.contains("x_client_base:"),
        "server finalize output state must not expose an unmasked x_client_base field name",
    );
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
            "{label} must not reconstruct server roots through the legacy server-input decoder",
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
fn evaluator_runtime_state_serialization_does_not_embed_server_roots_or_joined_input_artifacts() {
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
            !contains_subslice(&bytes, &fixture.input.y_server),
            "serialized evaluator-visible runtime state must not embed clear y_server bytes",
        );
        assert!(
            !contains_subslice(&bytes, &fixture.input.tau_server),
            "serialized evaluator-visible runtime state must not embed clear tau_server bytes",
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
            fixture.input.y_server,
            fixture.input.tau_server,
            ServerEvalOperation::Registration,
        )
        .expect("prepare staged assist flow");
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
            !contains_subslice(message_bytes, &fixture.input.y_server),
            "{label} must not embed clear y_server bytes",
        );
        assert!(
            !contains_subslice(message_bytes, &fixture.input.tau_server),
            "{label} must not embed clear tau_server bytes",
        );
    }
}

#[test]
fn server_assist_init_message_validates_without_exposing_clear_server_roots() {
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
            fixture.input.y_server,
            fixture.input.tau_server,
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
        !contains_subslice(&server_assist_init_message.bytes, &fixture.input.y_server),
        "server assist init message must not embed clear y_server bytes",
    );
    assert!(
        !contains_subslice(&server_assist_init_message.bytes, &fixture.input.tau_server),
        "server assist init message must not embed clear tau_server bytes",
    );
}

#[test]
fn add_stage_round_advances_handle_without_exposing_clear_server_roots() {
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
            fixture.input.y_server,
            fixture.input.tau_server,
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
        !contains_subslice(&client_stage_request_message.bytes, &fixture.input.y_server),
        "client add-stage request must not embed clear y_server bytes",
    );
    assert!(
        !contains_subslice(
            &client_stage_request_message.bytes,
            &fixture.input.tau_server
        ),
        "client add-stage request must not embed clear tau_server bytes",
    );
    assert!(
        !contains_subslice(
            &server_stage_response_message.bytes,
            &fixture.input.y_server
        ),
        "server add-stage response must not embed clear y_server bytes",
    );
    assert!(
        !contains_subslice(
            &server_stage_response_message.bytes,
            &fixture.input.tau_server
        ),
        "server add-stage response must not embed clear tau_server bytes",
    );
}

#[test]
fn role_separated_add_stage_request_omits_joined_client_bundles() {
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
    let client_packet =
        decode_client_request(fixture.output.context_binding, &client_request_message)
            .expect("decode client request");

    let (server_assist_init_message, _server_eval_state) = garbler_session
        .prepare_server_assist_init_message(
            &client_request_message,
            fixture.input.y_server,
            fixture.input.tau_server,
            ServerEvalOperation::Registration,
        )
        .expect("prepare server assist init message");
    let server_assist_init = evaluator_session
        .decode_server_assist_init_message(
            &client_request_message,
            &evaluator_ot_state,
            &server_assist_init_message,
        )
        .expect("decode server assist init message");

    let request = evaluator_session
        .build_role_separated_add_stage_request(
            &client_packet,
            &evaluator_ot_state,
            &server_assist_init,
        )
        .expect("build role-separated add-stage request");

    let RoleSeparatedClientStagePayload::AddStage(payload) = &request.client_stage_payload else {
        panic!("role-separated request must carry add-stage payload");
    };
    assert_eq!(
        request.stage_id,
        ed25519_hss::wire::ServerEvalStageId::add_stage()
    );
    assert_eq!(
        request.client_stage_commitments.digests,
        vec![
            payload.client_input_commitment,
            payload.client_stage_openings_digest,
        ],
    );

    let request_json = serde_json::to_string(&request).expect("serialize request json");
    assert!(
        !request_json.contains("y_client_bundle_payload"),
        "role-separated add-stage request must not expose joined y_client bundle payload",
    );
    assert!(
        !request_json.contains("tau_client_bundle_payload"),
        "role-separated add-stage request must not expose joined tau_client bundle payload",
    );

    let request_wire = bincode::serialize(&request).expect("serialize request bincode");
    for (label, secret) in [
        ("y_client", &fixture.input.y_client),
        ("tau_client", &fixture.input.tau_client),
        ("y_server", &fixture.input.y_server),
        ("tau_server", &fixture.input.tau_server),
    ] {
        assert!(
            !contains_subslice(&request_wire, secret),
            "role-separated add-stage request must not embed clear {label} bytes",
        );
    }
}

#[test]
fn role_separated_client_materialization_keeps_client_bundles_off_server_packet() {
    let fixture = boundary_fixture();
    let session =
        prepare_prime_order_succinct_hss(&fixture.input.context).expect("prepare session");
    let (runtime, garbler_session, evaluator_session) = session.split_runtime();

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
    let client_packet =
        decode_client_request(fixture.output.context_binding, &client_request_message)
            .expect("decode client request");

    let (delivery, server_eval_state) = garbler_session
        .prepare_role_separated_server_input_delivery(
            &client_packet,
            fixture.input.y_server,
            fixture.input.tau_server,
            ServerEvalOperation::Registration,
        )
        .expect("prepare role-separated server input delivery");
    let delivery_json = serde_json::to_string(&delivery).expect("serialize delivery json");
    for forbidden_field in [
        "y_client_bundle_payload",
        "tau_client_bundle_payload",
        "evaluator_ot_state",
        "evaluatorOtStateB64u",
    ] {
        assert!(
            !delivery_json.contains(forbidden_field),
            "role-separated server input delivery must not expose {forbidden_field}",
        );
    }
    let delivery_wire = bincode::serialize(&delivery).expect("serialize delivery bincode");
    for (label, secret) in [
        ("y_client", &fixture.input.y_client),
        ("tau_client", &fixture.input.tau_client),
        ("y_server", &fixture.input.y_server),
        ("tau_server", &fixture.input.tau_server),
    ] {
        assert!(
            !contains_subslice(&delivery_wire, secret),
            "role-separated server input delivery must not embed clear {label} bytes",
        );
    }

    let client_output_mask = [0x5a; 32];
    let masked_artifact = evaluator_session
        .build_client_owned_staged_evaluator_artifact_from_role_separated_delivery(
            &runtime,
            &client_packet,
            &evaluator_ot_state,
            &delivery,
            client_output_mask,
        )
        .expect("build masked client-owned staged evaluator artifact");
    match masked_artifact.projection_mode {
        OutputProjectionMode::ClientMaskedProjection { mask_commitment } => {
            assert_ne!(mask_commitment, [0u8; 32]);
        }
        OutputProjectionMode::TrustedServerProjection => {
            panic!("masked artifact must carry client-masked projection mode");
        }
    }
    assert!(
        evaluator_session
            .client_output_opener()
            .open(&masked_artifact.client_output)
            .is_err(),
        "masked client output must not open as an unmasked x_client_base packet",
    );
    let unmasked_x_client_base = evaluator_session
        .client_output_opener()
        .open_masked(&masked_artifact.client_output, client_output_mask)
        .expect("open masked client output");
    assert_eq!(unmasked_x_client_base, fixture.output.x_client_base);
    let wrong_client_output_mask = [0xa5; 32];
    assert!(
        evaluator_session
            .client_output_opener()
            .open_masked(&masked_artifact.client_output, wrong_client_output_mask)
            .is_err(),
        "masked client output must reject a mask with the wrong commitment",
    );

    let mut downgraded_artifact = masked_artifact.clone();
    downgraded_artifact.projection_mode = OutputProjectionMode::trusted_server_projection();
    let flow = session
        .prepare_server_assist_flow_to_output_projection_from_role_separated_delivery(
            &server_eval_state,
            &client_request_message,
            &evaluator_ot_state,
            &delivery,
        )
        .expect("prepare server assist flow");
    let finalize_state = flow
        .final_server_eval_state
        .finalize_state()
        .expect("finalized server state");
    assert!(
        runtime
            .finalize_report_from_staged_evaluator_artifact(
                &garbler_session,
                &downgraded_artifact,
                &finalize_state.output,
            )
            .is_err(),
        "server finalization must reject projection-mode downgrade metadata",
    );

    let report = runtime
        .finalize_report_from_staged_evaluator_artifact(
            &garbler_session,
            &masked_artifact,
            &finalize_state.output,
        )
        .expect("finalize masked client-owned artifact");
    assert_eq!(report.projection_mode, masked_artifact.projection_mode);
    assert!(
        evaluator_session
            .client_output_opener()
            .open(&report.output_delivery.client)
            .is_err(),
        "final report must preserve the masked client output packet",
    );
    let report_x_client_base = evaluator_session
        .client_output_opener()
        .open_masked(&report.output_delivery.client, client_output_mask)
        .expect("open masked final report client output");
    assert!(
        evaluator_session
            .client_output_opener()
            .open_masked(&report.output_delivery.client, wrong_client_output_mask)
            .is_err(),
        "masked final report client output must reject the wrong mask",
    );
    let report_x_server_base = garbler_session
        .server_output_opener()
        .open(&report.output_delivery.server)
        .expect("open final report server output");
    assert_eq!(report_x_client_base, fixture.output.x_client_base);
    assert_eq!(report_x_server_base, fixture.output.x_server_base);
}

#[test]
fn role_separated_output_delivery_omits_server_private_output_material() {
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
    let garbler_ot_state = session
        .prepare_garbler_ot_state()
        .expect("prepare garbler OT state");
    let flow = session
        .prepare_server_assist_flow_to_output_projection(
            &garbler_ot_state,
            &client_request_message,
            &evaluator_ot_state,
            fixture.input.y_server,
            fixture.input.tau_server,
            ServerEvalOperation::Registration,
        )
        .expect("prepare staged flow");
    let artifact = build_client_owned_staged_evaluator_artifact(&session, &fixture.input)
        .expect("build client-owned staged artifact");
    let delivery = evaluator_session
        .build_role_separated_output_delivery_packet(
            flow.final_server_eval_state.handle,
            flow.final_server_eval_state.current_transcript_digest,
            ed25519_hss::wire::AllowedOutputKind::ClientOutputOnly,
            &artifact,
        )
        .expect("build role-separated output delivery");

    let RoleSeparatedOutputDeliveryPayload::ClientOutputOnly {
        client_output,
        client_output_binding,
    } = &delivery.payload
    else {
        panic!("registration delivery must expose only client output");
    };
    assert_eq!(delivery.bindings, artifact.bindings);
    assert_eq!(client_output, &artifact.client_output);
    assert_eq!(*client_output_binding, artifact.client_output_binding);

    let delivery_json = serde_json::to_string(&delivery).expect("serialize delivery json");
    for forbidden_field in [
        "server_output_payload",
        "server_output_payload_binding",
        "seed_output",
        "seed_output_binding",
    ] {
        assert!(
            !delivery_json.contains(forbidden_field),
            "role-separated client delivery must not expose {forbidden_field}",
        );
    }

    let delivery_wire = bincode::serialize(&delivery).expect("serialize delivery bincode");
    for (label, secret) in [
        ("y_client", &fixture.input.y_client),
        ("tau_client", &fixture.input.tau_client),
        ("y_server", &fixture.input.y_server),
        ("tau_server", &fixture.input.tau_server),
    ] {
        assert!(
            !contains_subslice(&delivery_wire, secret),
            "role-separated client delivery must not embed clear {label} bytes",
        );
    }
}

#[test]
fn message_schedule_round_advances_handle_without_exposing_clear_server_roots() {
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
            fixture.input.y_server,
            fixture.input.tau_server,
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
            &fixture.input.y_server
        ),
        "client message-schedule request must not embed clear y_server bytes",
    );
    assert!(
        !contains_subslice(
            &client_message_schedule_request_message.bytes,
            &fixture.input.tau_server
        ),
        "client message-schedule request must not embed clear tau_server bytes",
    );
    assert!(
        !contains_subslice(
            &server_message_schedule_response_message.bytes,
            &fixture.input.y_server
        ),
        "server message-schedule response must not embed clear y_server bytes",
    );
    assert!(
        !contains_subslice(
            &server_message_schedule_response_message.bytes,
            &fixture.input.tau_server
        ),
        "server message-schedule response must not embed clear tau_server bytes",
    );
}

#[test]
fn message_schedule_round_can_repeat_without_exposing_clear_server_roots() {
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
            fixture.input.y_server,
            fixture.input.tau_server,
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
            !contains_subslice(bytes, &fixture.input.y_server),
            "repeated message-schedule artifacts must not embed clear y_server bytes",
        );
        assert!(
            !contains_subslice(bytes, &fixture.input.tau_server),
            "repeated message-schedule artifacts must not embed clear tau_server bytes",
        );
    }
}

#[test]
fn accumulated_new_flow_artifacts_do_not_reconstruct_server_roots_via_legacy_decoder() {
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
            fixture.input.y_server,
            fixture.input.tau_server,
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
            "{label} must not reconstruct server roots through the legacy server-input decoder",
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
        !contains_subslice(&accumulated_bytes, &fixture.input.y_server),
        "accumulated new-flow artifacts must not embed clear y_server bytes",
    );
    assert!(
        !contains_subslice(&accumulated_bytes, &fixture.input.tau_server),
        "accumulated new-flow artifacts must not embed clear tau_server bytes",
    );
}

#[test]
fn round_core_round_begins_after_final_message_schedule_without_exposing_clear_server_roots() {
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
            fixture.input.y_server,
            fixture.input.tau_server,
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
            &fixture.input.y_server
        ),
        "client round-core request must not embed clear y_server bytes",
    );
    assert!(
        !contains_subslice(
            &client_round_core_request_message.bytes,
            &fixture.input.tau_server
        ),
        "client round-core request must not embed clear tau_server bytes",
    );
    assert!(
        !contains_subslice(
            &server_round_core_response_message.bytes,
            &fixture.input.y_server
        ),
        "server round-core response must not embed clear y_server bytes",
    );
    assert!(
        !contains_subslice(
            &server_round_core_response_message.bytes,
            &fixture.input.tau_server
        ),
        "server round-core response must not embed clear tau_server bytes",
    );
}

#[test]
fn round_core_round_can_repeat_without_exposing_clear_server_roots() {
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
            fixture.input.y_server,
            fixture.input.tau_server,
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
            !contains_subslice(bytes, &fixture.input.y_server),
            "repeated round-core artifacts must not embed clear y_server bytes",
        );
        assert!(
            !contains_subslice(bytes, &fixture.input.tau_server),
            "repeated round-core artifacts must not embed clear tau_server bytes",
        );
    }
}

#[test]
fn output_projection_round_begins_after_final_round_core_without_exposing_clear_server_roots() {
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
            fixture.input.y_server,
            fixture.input.tau_server,
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
            &fixture.input.y_server
        ),
        "client output-projection request must not embed clear y_server bytes",
    );
    assert!(
        !contains_subslice(
            &client_output_projection_request_message.bytes,
            &fixture.input.tau_server
        ),
        "client output-projection request must not embed clear tau_server bytes",
    );
    assert!(
        !contains_subslice(
            &server_output_projection_response_message.bytes,
            &fixture.input.y_server
        ),
        "server output-projection response must not embed clear y_server bytes",
    );
    assert!(
        !contains_subslice(
            &server_output_projection_response_message.bytes,
            &fixture.input.tau_server
        ),
        "server output-projection response must not embed clear tau_server bytes",
    );
}

#[test]
fn accumulated_full_new_flow_artifacts_do_not_reconstruct_server_roots_via_legacy_decoder() {
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
            fixture.input.y_server,
            fixture.input.tau_server,
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
            "{label} must not reconstruct server roots through the legacy server-input decoder",
        );
    }

    assert!(
        !contains_subslice(&accumulated_bytes, &fixture.input.y_server),
        "accumulated full new-flow artifacts must not embed clear y_server bytes",
    );
    assert!(
        !contains_subslice(&accumulated_bytes, &fixture.input.tau_server),
        "accumulated full new-flow artifacts must not embed clear tau_server bytes",
    );
}

#[test]
fn prepared_server_assist_flow_wrapper_does_not_expose_reconstructable_server_roots() {
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
            fixture.input.y_server,
            fixture.input.tau_server,
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
        !contains_subslice(&accumulated_bytes, &fixture.input.y_server),
        "wrapper-driven staged artifacts must not embed clear y_server bytes",
    );
    assert!(
        !contains_subslice(&accumulated_bytes, &fixture.input.tau_server),
        "wrapper-driven staged artifacts must not embed clear tau_server bytes",
    );
}

#[test]
fn repeated_run_same_account_staged_artifacts_do_not_reconstruct_server_roots() {
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
            fixture.input.y_server,
            fixture.input.tau_server,
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
            fixture.input.y_server,
            fixture.input.tau_server,
            ServerEvalOperation::Registration,
        )
        .expect("prepare staged assist flow B");

    assert_staged_flow_messages_do_not_drive_legacy_decoder(&session, &flow_a);
    assert_staged_flow_messages_do_not_drive_legacy_decoder(&session, &flow_b);

    let mut accumulated_bytes = Vec::new();
    extend_staged_flow_bytes(&mut accumulated_bytes, &client_request_message_a, &flow_a);
    extend_staged_flow_bytes(&mut accumulated_bytes, &client_request_message_b, &flow_b);

    assert!(
        !contains_subslice(&accumulated_bytes, &fixture.input.y_server),
        "same-account repeated staged runs must not embed clear y_server bytes",
    );
    assert!(
        !contains_subslice(&accumulated_bytes, &fixture.input.tau_server),
        "same-account repeated staged runs must not embed clear tau_server bytes",
    );
}

#[test]
fn repeated_run_cross_account_staged_artifacts_do_not_reconstruct_server_roots() {
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
            fixture_a.input.y_server,
            fixture_a.input.tau_server,
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
            fixture_b.input.y_server,
            fixture_b.input.tau_server,
            ServerEvalOperation::Registration,
        )
        .expect("prepare staged assist flow B");

    assert_staged_flow_messages_do_not_drive_legacy_decoder(&session_a, &flow_a);
    assert_staged_flow_messages_do_not_drive_legacy_decoder(&session_b, &flow_b);

    let mut accumulated_bytes_a = Vec::new();
    extend_staged_flow_bytes(&mut accumulated_bytes_a, &client_request_message_a, &flow_a);
    assert!(
        !contains_subslice(&accumulated_bytes_a, &fixture_a.input.y_server),
        "cross-account staged flow A must not embed clear y_server bytes",
    );
    assert!(
        !contains_subslice(&accumulated_bytes_a, &fixture_a.input.tau_server),
        "cross-account staged flow A must not embed clear tau_server bytes",
    );

    let mut accumulated_bytes_b = Vec::new();
    extend_staged_flow_bytes(&mut accumulated_bytes_b, &client_request_message_b, &flow_b);
    assert!(
        !contains_subslice(&accumulated_bytes_b, &fixture_b.input.y_server),
        "cross-account staged flow B must not embed clear y_server bytes",
    );
    assert!(
        !contains_subslice(&accumulated_bytes_b, &fixture_b.input.tau_server),
        "cross-account staged flow B must not embed clear tau_server bytes",
    );
}

#[test]
fn retry_and_idempotent_stage_replays_do_not_reconstruct_server_roots() {
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
            fixture.input.y_server,
            fixture.input.tau_server,
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
            "{label} must not reconstruct server roots through the legacy server-input decoder",
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
        !contains_subslice(&accumulated_bytes, &fixture.input.y_server),
        "retry/idempotent staged artifacts must not embed clear y_server bytes",
    );
    assert!(
        !contains_subslice(&accumulated_bytes, &fixture.input.tau_server),
        "retry/idempotent staged artifacts must not embed clear tau_server bytes",
    );
}

#[test]
fn client_visible_staged_packets_do_not_reconstruct_server_roots() {
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
            fixture.input.y_server,
            fixture.input.tau_server,
            ServerEvalOperation::Registration,
        )
        .expect("prepare staged assist flow");
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
            "{label} must not reconstruct server roots through the legacy server-input decoder",
        );
        accumulated_bytes.extend_from_slice(&message.bytes);
    }

    assert!(
        !contains_subslice(&accumulated_bytes, &fixture.input.y_server),
        "client-visible staged packets must not embed clear y_server bytes",
    );
    assert!(
        !contains_subslice(&accumulated_bytes, &fixture.input.tau_server),
        "client-visible staged packets must not embed clear tau_server bytes",
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
            fixture.input.y_server,
            fixture.input.tau_server,
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
            !contains_subslice(&bytes, &fixture.input.y_server),
            "decoded staged wire packet must not embed clear y_server bytes",
        );
        assert!(
            !contains_subslice(&bytes, &fixture.input.tau_server),
            "decoded staged wire packet must not embed clear tau_server bytes",
        );
    }
}
