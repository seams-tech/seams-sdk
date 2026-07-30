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
        "StartPair",
        "BeginPair",
        "Ed25519YaoRoleStartAcceptanceV1",
        "CompletePair",
    ] {
        assert!(
            source.contains(required),
            "pair-bound lifecycle must include `{required}`"
        );
    }
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
