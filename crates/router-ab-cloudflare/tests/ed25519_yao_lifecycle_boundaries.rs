mod support;

use support::{extract_function_body, read_src_file};

#[test]
fn pair_lifecycle_is_pair_bound_and_has_signed_readiness_states() {
    let source = read_src_file("ed25519_yao_lifecycle.rs");
    for required in [
        "enum PairYaoSessionRecordV1",
        "Prepared",
        "Burned",
        "pair_digest",
        "input_digest",
        "root_metadata_digest",
        "Ed25519YaoRoleReadinessReceiptV1",
        "PreparePair",
        "ClaimPair",
        "StartPair",
        "BeginPair",
        "Ed25519YaoRoleStartAcceptanceV1",
        "CompletePair",
        "ReadCompletedPair",
    ] {
        assert!(
            source.contains(required),
            "pair-bound lifecycle must include `{required}`"
        );
    }
}

#[test]
fn deriver_a_claim_does_not_hold_the_durable_object_across_yao_execution() {
    let source = read_src_file("ed25519_yao_lifecycle.rs");
    let body = extract_function_body(&source, "handle_claim_pair");
    assert!(
        body.contains("DeriverAYaoSessionResponseV1::Claimed"),
        "Deriver A claim must return the claimed execution envelope"
    );
    assert!(
        !body.contains("execute_deriver_a_role"),
        "Deriver A Durable Object must not own the Yao network stream"
    );
}

#[test]
fn deriver_b_completed_read_returns_an_explicit_acknowledgement_envelope() {
    let source = read_src_file("ed25519_yao_lifecycle.rs");
    let body = extract_function_body(
        &source,
        "handle_cloudflare_ed25519_yao_deriver_b_read_completed_pair_v1",
    );
    assert!(
        source.contains("CloudflareEd25519YaoPairCompletionAcknowledgementV1"),
        "B completion acknowledgement must be a named boundary type"
    );
    assert!(
        body.contains("acknowledgement.validate_for_request"),
        "B completion read must validate the acknowledgement identity"
    );
}

#[test]
fn pair_websocket_requires_the_exact_pair_digest_and_peer_receipt() {
    let source = read_src_file("ed25519_yao_lifecycle.rs");
    let body = extract_function_body(&source, "handle_pair_bound_deriver_b_websocket");
    for required in [
        "binding.pair_digest",
        "x-seams-yao-readiness-receipt",
        "EXECUTION_ID_HEADER",
        "verify_role_readiness_receipt_v1",
        "BeginPair",
        "PairStarted",
        "sign_role_start_acceptance_v1",
        "START_ACCEPTANCE_HEADER",
    ] {
        assert!(
            body.contains(required),
            "pair-bound WebSocket must enforce `{required}`"
        );
    }
}
