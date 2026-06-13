use std::fs;
use std::path::{Path, PathBuf};

#[test]
fn production_adapter_source_does_not_reference_joined_state_material() {
    let forbidden_patterns = [
        "joined d",
        "joined_d",
        "joined a",
        "joined_a",
        "joined x_client_base",
        "joined_x_client_base",
        "joined y_relayer",
        "joined_y_relayer",
        "joined tau_relayer",
        "joined_tau_relayer",
        "DdhHssSharedWord",
        "DdhHiddenEvalProjectorInputs",
    ];

    for path in rust_source_files() {
        let source = fs::read_to_string(&path).expect("source file should read");
        let lower = source.to_lowercase();
        for forbidden in forbidden_patterns {
            assert!(
                !lower.contains(&forbidden.to_lowercase()),
                "{} contains forbidden joined-state marker `{forbidden}`",
                path.display()
            );
        }
    }
}

#[test]
fn production_adapter_source_does_not_combine_recipient_outputs() {
    let forbidden_patterns = [
        "combine_mpc_prf_batch_outputs_with_threshold_backend_v1",
        "MpcPrfThresholdBatchCombinedOutputV1",
        "MpcPrfThresholdCombinedOutputV1",
    ];

    for path in rust_source_files() {
        let source = fs::read_to_string(&path).expect("source file should read");
        for forbidden in forbidden_patterns {
            assert!(
                !source.contains(forbidden),
                "{} imports or calls recipient-side combine path `{forbidden}`",
                path.display()
            );
        }
    }
}

#[test]
fn cloudflare_route_boundaries_do_not_decode_signer_plaintext() {
    let lib_rs = read_src_file("lib.rs");
    for function_name in [
        "handle_cloudflare_router_recipient_proof_bundle_public_request_v1",
        "validate_cloudflare_signer_private_request_v1",
        "decode_and_validate_cloudflare_signer_envelope_hpke_payload_v1",
        "handle_cloudflare_signer_recipient_proof_bundle_private_fetch_v1",
        "handle_cloudflare_signer_recipient_proof_bundle_private_request_v1",
        "validate_cloudflare_signer_peer_request_v1",
        "handle_cloudflare_signer_peer_fetch_v1",
        "handle_cloudflare_signer_peer_request_v1",
    ] {
        let body = extract_function_body(&lib_rs, function_name);
        for forbidden in [
            "SignerInputPlaintextV1",
            "decode_signer_input_plaintext_v1",
            "decode_and_validate_cloudflare_signer_input_plaintext_v1",
            "validate_cloudflare_signer_private_request_plaintext_v1",
            "decrypt_and_validate_cloudflare_signer_input_plaintext_v1",
            "decrypt_cloudflare_validated_signer_private_request_v1",
        ] {
            assert!(
                !body.contains(forbidden),
                "{function_name} crosses signer plaintext boundary through `{forbidden}`"
            );
        }
    }
}

#[test]
fn strict_router_route_derives_admission_from_bearer_jwt() {
    let strict_worker_rs = read_src_file("strict_worker.rs");
    let body = extract_function_body(&strict_worker_rs, "handle_strict_router_fetch_v1");
    for forbidden in [
        "CloudflareStrictRouterBootstrapRequestV1",
        "CloudflareRouterTrustedAdmissionV1",
        "trusted_admission",
        "handle_cloudflare_router_recipient_proof_bundle_public_request_v1",
    ] {
        assert!(
            !body.contains(forbidden),
            "strict Router route must not accept caller-supplied admission through `{forbidden}`"
        );
    }
    for required in [
        "parse_cloudflare_router_bearer_authorization_from_request_v1",
        "load_cloudflare_router_ed25519_jwks_jwt_verifier_v1",
        "handle_cloudflare_router_recipient_proof_bundle_authenticated_public_request_v1",
    ] {
        assert!(
            body.contains(required),
            "strict Router route must derive admission through `{required}`"
        );
    }
}

#[test]
fn normal_signing_routes_do_not_invoke_ab_derivation_handlers() {
    let lib_rs = read_src_file("lib.rs");
    for function_name in [
        "handle_cloudflare_router_normal_signing_authenticated_public_request_v1",
        "build_cloudflare_router_to_signing_worker_normal_signing_request_v1",
        "handle_cloudflare_signing_worker_normal_signing_private_request_v1",
        "handle_cloudflare_signing_worker_normal_signing_private_fetch_v1",
        "execute_cloudflare_signing_worker_normal_signing_service_call_v1",
    ] {
        let body = extract_function_body(&lib_rs, function_name);
        for forbidden in [
            "build_mpc_prf_threshold_signer_batch_input_v1",
            "decrypt_and_handle_cloudflare_mpc_prf_recipient_proof_bundle_signer_private_request_v1",
            "handle_cloudflare_validated_mpc_prf_recipient_proof_bundle_signer_request_v1",
            "handle_cloudflare_signer_recipient_proof_bundle_private_request_v1",
            "recipient_proof_bundle_wire_message_from_ab_proof_batch_v1",
            "DeriverAEngine",
            "DeriverBEngine",
            "AbDerivationProofBatchPayloadV1",
        ] {
            assert!(
                !body.contains(forbidden),
                "{function_name} must not cross into derivation handler `{forbidden}`"
            );
        }
    }
}

#[test]
fn signing_worker_normal_signing_loads_active_material_before_handler() {
    let lib_rs = read_src_file("lib.rs");
    let body = extract_function_body(
        &lib_rs,
        "handle_cloudflare_signing_worker_normal_signing_private_fetch_v1",
    );
    let state_lookup = body
        .find("active_signing_worker_state_get_call")
        .expect("normal signing must load active SigningWorker state");
    let material_lookup = body
        .find("signing_worker_output_material_get_call")
        .expect("normal signing must load active SigningWorker material");
    let handler_call = body
        .find("handle_cloudflare_signing_worker_normal_signing_private_request_v1")
        .expect("normal signing must call the materialized handler");

    assert!(
        state_lookup < material_lookup,
        "normal signing must load active state before material"
    );
    assert!(
        material_lookup < handler_call,
        "normal signing must load material before invoking the handler"
    );
}

#[test]
fn normal_signing_boundary_uses_signing_worker_api_names() {
    let forbidden_patterns = [
        "ActiveRelayerStateV1",
        "RouterToRelayerSigningRequestV1",
        "CloudflareRelayerRecipientProofBundleActivation",
        "CloudflareRelayerOutputActivationReceiptV1",
        "CloudflareRelayerOutputActivationRecordV1",
        "CloudflareActiveRelayerStateLookupV1",
        "CloudflareRelayerNormalSigningHandlerV1",
        "build_cloudflare_router_to_relayer_normal_signing_request_v1",
        "RelayerOutputActivate",
        "RelayerOutputActiveStateGet",
        "relayer_output_activate(",
        "relayer_output_active_state_get(",
        "active_relayer_state",
        "relayer_material_handle",
        "active-relayer/",
    ];

    for path in rust_source_files() {
        let source = fs::read_to_string(&path).expect("source file should read");
        for forbidden in forbidden_patterns {
            assert!(
                !source.contains(forbidden),
                "{} still exposes relayer-labelled normal-signing API `{forbidden}`",
                path.display()
            );
        }
    }
}

#[test]
fn signing_worker_activation_request_carries_public_context_not_router_payload() {
    let lib_rs = read_src_file("lib.rs");
    let block = extract_struct_block(
        &lib_rs,
        "CloudflareSigningWorkerRecipientProofBundleActivationRequestV1",
    );

    assert!(
        block.contains("SigningWorkerActivationContextV1"),
        "SigningWorker activation request must carry the narrow public activation context"
    );
    assert!(
        !block.contains("RouterToSignerPayloadV1"),
        "SigningWorker activation request must not store a Router-to-deriver payload"
    );
}

#[test]
fn router_normal_signing_reserves_replay_before_forwarding() {
    let lib_rs = read_src_file("lib.rs");
    let body = extract_function_body(
        &lib_rs,
        "handle_cloudflare_router_normal_signing_authenticated_public_request_v1",
    );
    let admission = body
        .find("derive_cloudflare_router_normal_signing_trusted_admission_from_worker_stores_v1")
        .expect("normal signing route must evaluate Router-owned admission stores");
    let replay_builder = body
        .find("normal_signing_replay_reserve_call")
        .expect("normal signing route must build a replay reservation");
    let replay_execute = body
        .find("execute_cloudflare_router_replay_reserve_v1")
        .expect("normal signing route must execute replay reservation");
    let replay_reject = body
        .find("ReplayedLocalRequest")
        .expect("normal signing route must reject replayed requests");
    let signing_worker_forward = body
        .find("execute_cloudflare_signing_worker_normal_signing_service_call_v1")
        .expect("normal signing route must forward to SigningWorker");

    assert!(
        admission < replay_builder,
        "normal signing route must evaluate admission before replay reservation"
    );
    assert!(
        admission < signing_worker_forward,
        "normal signing route must evaluate admission before forwarding"
    );
    assert!(
        replay_builder < signing_worker_forward,
        "normal signing route must build replay reservation before forwarding"
    );
    assert!(
        replay_execute < signing_worker_forward,
        "normal signing route must execute replay reservation before forwarding"
    );
    assert!(
        replay_reject < signing_worker_forward,
        "normal signing route must reject replay before forwarding"
    );
}

#[test]
fn strict_signing_worker_entrypoint_routes_normal_signing() {
    let strict_worker_rs = read_src_file("strict_worker.rs");
    let body = extract_function_body(&strict_worker_rs, "handle_strict_signing_worker_fetch_v1");

    for required in [
        "CLOUDFLARE_SIGNING_WORKER_PROOF_BUNDLE_ACTIVATION_PATH_V1",
        "handle_cloudflare_signing_worker_recipient_proof_bundle_activation_fetch_v1",
        "CLOUDFLARE_SIGNING_WORKER_NORMAL_SIGNING_PATH_V1",
        "handle_cloudflare_signing_worker_normal_signing_private_fetch_v1",
    ] {
        assert!(
            body.contains(required),
            "strict SigningWorker entrypoint must route through `{required}`"
        );
    }
}

fn read_src_file(file_name: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join(file_name);
    fs::read_to_string(path).expect("source file should read")
}

fn rust_source_files() -> Vec<PathBuf> {
    let mut out = Vec::new();
    collect_rust_files(&Path::new(env!("CARGO_MANIFEST_DIR")).join("src"), &mut out);
    out
}

fn collect_rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).expect("source directory should read") {
        let entry = entry.expect("source entry should read");
        let path = entry.path();
        if path.is_dir() {
            collect_rust_files(&path, out);
        } else if path.extension().and_then(|ext| ext.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

fn extract_struct_block(source: &str, struct_name: &str) -> String {
    let marker = format!("struct {struct_name}");
    let start = source
        .find(&marker)
        .unwrap_or_else(|| panic!("struct marker `{marker}` should exist"));
    let body_start = source[start..]
        .find('{')
        .map(|offset| start + offset)
        .unwrap_or_else(|| panic!("struct `{struct_name}` should have a body"));
    let mut depth = 0usize;
    for (offset, ch) in source[body_start..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth = depth
                    .checked_sub(1)
                    .expect("struct body braces should stay balanced");
                if depth == 0 {
                    return source[start..=body_start + offset].to_owned();
                }
            }
            _ => {}
        }
    }
    panic!("struct `{struct_name}` body should end");
}

fn extract_function_body(source: &str, function_name: &str) -> String {
    let marker = format!("fn {function_name}");
    let start = source
        .find(&marker)
        .unwrap_or_else(|| panic!("function marker `{marker}` should exist"));
    let body_start = source[start..]
        .find('{')
        .map(|offset| start + offset)
        .unwrap_or_else(|| panic!("function `{function_name}` should have a body"));
    let mut depth = 0usize;
    for (offset, ch) in source[body_start..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth = depth
                    .checked_sub(1)
                    .expect("function body braces should stay balanced");
                if depth == 0 {
                    return source[body_start..=body_start + offset].to_owned();
                }
            }
            _ => {}
        }
    }
    panic!("function `{function_name}` body should end");
}
