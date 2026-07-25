mod support;

use support::{extract_function_body, read_src_file};

#[test]
fn yao_session_lifecycle_has_absorbing_failure_and_expiry_states() {
    let source = read_src_file("ed25519_yao_lifecycle.rs");
    for required in [
        "enum YaoSessionRecordV1",
        "Staged",
        "Running",
        "Completed",
        "Failed",
        "Expired",
        "YAO_STAGED_INPUT_LIFETIME_MS",
        "YAO_RUNNING_LIFETIME_MS",
        "yao_expiry_from_now",
    ] {
        assert!(
            source.contains(required),
            "Yao session lifecycle must include `{required}`"
        );
    }
    assert!(
        !source.contains("STAGED_INPUT_STORAGE_KEY"),
        "Yao staged ciphertext must live in the discriminated lifecycle record"
    );
}

#[test]
fn yao_websocket_prepares_transport_before_consuming_staged_input() {
    let source = read_src_file("ed25519_yao_lifecycle.rs");
    let body = extract_function_body(
        &source,
        "handle_cloudflare_ed25519_yao_deriver_b_websocket_v1",
    );
    let pair = body
        .find("WebSocketPair::new")
        .expect("WebSocket pair must be prepared");
    let response = body
        .find("Response::from_websocket")
        .expect("upgrade response must be prepared");
    let begin = body
        .find("DeriverBYaoSessionCommandV1::Begin")
        .expect("staged input must be consumed");
    let fail = body
        .find("DeriverBYaoSessionCommandV1::Fail")
        .expect("asynchronous role failure must become terminal");
    assert!(
        pair < response && response < begin && begin < fail,
        "all fallible WebSocket setup must precede Begin, and role failures must persist Fail"
    );
}

#[test]
fn yao_result_reads_surface_terminal_states_without_polling() {
    let source = read_src_file("ed25519_yao_lifecycle.rs");
    let body = extract_function_body(&source, "handle_cloudflare_ed25519_yao_deriver_b_result_v1");
    for required in [
        "DeriverBYaoSessionResponseV1::Failed",
        "Deriver B role execution failed",
        "DeriverBYaoSessionResponseV1::Expired",
        "Deriver B role execution expired",
    ] {
        assert!(
            body.contains(required),
            "Yao result reads must surface `{required}`"
        );
    }
}

#[test]
fn deriver_a_overlaps_root_validation_with_staged_websocket_connection() {
    let source = read_src_file("ed25519_yao_lifecycle.rs");
    let body = extract_function_body(&source, "execute_deriver_a_role");
    let open_input = body
        .find("open_ed25519_yao_activation_deriver_a_input_v1")
        .expect("Deriver A input must be opened before external coordination");
    let joined_work = body
        .find("futures::try_join!")
        .expect("root validation and staged WebSocket connection must overlap");
    assert!(
        open_input < joined_work,
        "invalid Deriver A ciphertext must fail before the Deriver B connection starts"
    );
    for required in ["load_deriver_a_yao_root", "connect_deriver_b"] {
        assert!(
            source.contains(required),
            "parallel staged connection must retain `{required}`"
        );
    }
}
