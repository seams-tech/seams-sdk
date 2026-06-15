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
        "joined y_server",
        "joined_y_server",
        "joined tau_server",
        "joined_tau_server",
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
fn strict_router_public_keyset_route_applies_cors_boundary() {
    let strict_worker_rs = read_src_file("strict_worker.rs");
    let route_body = extract_function_body(&strict_worker_rs, "handle_strict_router_fetch_v1");
    for required in [
        "is_cloudflare_router_public_keyset_path_v1",
        "Method::Options",
        "cloudflare_router_public_keyset_preflight_response_v1",
        "cloudflare_router_public_keyset_response_v1",
    ] {
        assert!(
            route_body.contains(required),
            "strict Router keyset route must route through `{required}`"
        );
    }

    let cors_body =
        extract_function_body(&strict_worker_rs, "cloudflare_router_public_keyset_cors_v1");
    for required in [
        "ROUTER_AB_PUBLIC_KEYSET_CORS_ORIGINS_ENV",
        "Access-Control-Allow-Origin",
        "Access-Control-Allow-Methods",
        "Access-Control-Allow-Headers",
        "Access-Control-Max-Age",
    ] {
        assert!(
            cors_body.contains(required),
            "strict Router keyset CORS helper must set `{required}`"
        );
    }
}

#[test]
fn strict_router_normal_signing_routes_apply_cors_boundary() {
    let strict_worker_rs = read_src_file("strict_worker.rs");
    let route_body = extract_function_body(&strict_worker_rs, "handle_strict_router_fetch_v1");
    for required in [
        "is_cloudflare_router_normal_signing_public_path_v2",
        "Method::Options",
        "cloudflare_router_normal_signing_preflight_response_v1",
        "cloudflare_router_normal_signing_response_v1",
        "CLOUDFLARE_ROUTER_NORMAL_SIGNING_ROUND1_PREPARE_PUBLIC_REQUEST_PATH_V2",
        "CLOUDFLARE_ROUTER_NORMAL_SIGNING_PUBLIC_REQUEST_PATH_V2",
    ] {
        assert!(
            route_body.contains(required),
            "strict Router normal-signing route must route through `{required}`"
        );
    }

    let lib_rs = read_src_file("lib.rs");
    assert!(
        lib_rs.contains(r#""/v2/hss/sign/prepare""#) && lib_rs.contains(r#""/v2/hss/sign""#),
        "strict Router normal-signing public paths must use explicit v2 routes"
    );
    assert!(
        !lib_rs.contains(r#""/v1/hss/sign/prepare""#) && !lib_rs.contains(r#""/v1/hss/sign""#),
        "strict Router normal-signing public paths must not keep v1 route literals"
    );

    let cors_body = extract_function_body(
        &strict_worker_rs,
        "cloudflare_router_normal_signing_cors_v1",
    );
    for required in [
        "ROUTER_AB_NORMAL_SIGNING_CORS_ORIGINS_ENV",
        "Access-Control-Allow-Origin",
        "Access-Control-Allow-Methods",
        "Access-Control-Allow-Headers",
        "Access-Control-Max-Age",
    ] {
        assert!(
            cors_body.contains(required),
            "strict Router normal-signing CORS helper must set `{required}`"
        );
    }
    assert!(
        cors_body.contains("cloudflare_router_normal_signing_cors_allowed_origin_v1"),
        "strict Router normal-signing CORS helper must use the exact-origin allowlist parser"
    );
    assert!(
        !cors_body.contains("unwrap_or_else(|| \"*\".to_string())"),
        "strict Router normal-signing CORS must not default bearer routes to wildcard Origin"
    );
    assert!(
        !cors_body.contains("origin == \"*\""),
        "strict Router normal-signing CORS must not allow wildcard Origins"
    );
    assert!(
        !cors_body.contains("Access-Control-Allow-Credentials"),
        "bearer-only normal-signing CORS must not enable credentialed browser requests"
    );
}

#[test]
fn strict_router_normal_signing_routes_use_boundary_parsers() {
    let strict_worker_rs = read_src_file("strict_worker.rs");
    let route_body = extract_function_body(&strict_worker_rs, "handle_strict_router_fetch_v1");
    for required in [
        "request.bytes().await",
        "parse_router_ab_ed25519_normal_signing_prepare_request_v2_json",
        "parse_router_ab_ed25519_normal_signing_finalize_request_v2_json",
    ] {
        assert!(
            route_body.contains(required),
            "strict Router normal-signing route must parse raw bodies through `{required}`"
        );
    }
    for forbidden in [
        "json::<RouterAbEd25519NormalSigningPrepareRequestV2>",
        "json::<RouterAbEd25519NormalSigningFinalizeRequestV2>",
    ] {
        assert!(
            !route_body.contains(forbidden),
            "strict Router normal-signing route must not deserialize directly through `{forbidden}`"
        );
    }
}

#[test]
fn normal_signing_routes_do_not_invoke_ab_derivation_handlers() {
    let lib_rs = read_src_file("lib.rs");
    for function_name in [
        "handle_cloudflare_router_normal_signing_prepare_authenticated_public_request_v2",
        "handle_cloudflare_router_normal_signing_finalize_authenticated_public_request_v2",
        "handle_cloudflare_signing_worker_normal_signing_prepare_private_request_v2",
        "handle_cloudflare_signing_worker_normal_signing_finalize_private_request_v2",
        "handle_cloudflare_signing_worker_normal_signing_round1_prepare_private_fetch_v1",
        "handle_cloudflare_signing_worker_normal_signing_private_fetch_v1",
        "execute_cloudflare_signing_worker_normal_signing_prepare_service_call_v2",
        "execute_cloudflare_signing_worker_normal_signing_finalize_service_call_v2",
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
fn legacy_normal_signing_v1_flow_symbols_are_absent() {
    let lib_rs = read_src_file("lib.rs");
    for deleted_symbol in [
        "CloudflareRouterVerifiedNormalSigningJwtClaimsV1",
        "CloudflareRouterNormalSigningJwtVerifierV1",
        "verify_normal_signing_jwt",
        "verify_normal_signing_round1_prepare_jwt",
        "handle_cloudflare_router_normal_signing_authenticated_public_request_v1",
        "handle_cloudflare_router_normal_signing_round1_prepare_authenticated_public_request_v1",
        "build_cloudflare_router_to_signing_worker_normal_signing_request_v1",
        "execute_cloudflare_signing_worker_normal_signing_service_call_v1",
        "execute_cloudflare_signing_worker_normal_signing_round1_prepare_service_call_v1",
        "CloudflareSigningWorkerAdmittedNormalSigningRequestV1",
        "CloudflareSigningWorkerAdmittedNormalSigningRound1PrepareRequestV1",
        "CloudflareSigningWorkerMaterializedNormalSigningRequestV1",
        "CloudflareSigningWorkerMaterializedNormalSigningRound1PrepareRequestV1",
        "CloudflareSigningWorkerNormalSigningHandlerV1",
        "CloudflareSigningWorkerNormalSigningRound1PrepareHandlerV1",
        "handle_cloudflare_signing_worker_normal_signing_private_request_v1",
        "handle_cloudflare_signing_worker_normal_signing_round1_prepare_private_request_v1",
        "derive_cloudflare_router_normal_signing_trusted_admission_v1",
        "derive_cloudflare_router_normal_signing_round1_prepare_trusted_admission_v1",
        "normal_signing_replay_reserve_call",
        "normal_signing_admission_store_calls_at",
        "normal_signing_round1_prepare_admission_store_calls_at",
        "NormalSigningRequestV1",
        "NormalSigningRound1PrepareRequestV1",
        "RouterToSigningWorkerSigningRequestV1",
    ] {
        assert!(
            !lib_rs.contains(deleted_symbol),
            "legacy normal-signing v1 flow symbol `{deleted_symbol}` must stay deleted"
        );
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
        .find("handle_cloudflare_signing_worker_normal_signing_finalize_private_request_v2")
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
        "ActiveServerStateV1",
        "RouterToServerSigningRequestV1",
        "CloudflareServerRecipientProofBundleActivation",
        "CloudflareServerOutputActivationReceiptV1",
        "CloudflareServerOutputActivationRecordV1",
        "CloudflareActiveServerStateLookupV1",
        "CloudflareServerNormalSigningHandlerV1",
        "build_cloudflare_router_to_server_normal_signing_request_v1",
        "ServerOutputActivate",
        "ServerOutputActiveStateGet",
        "server_output_activate(",
        "server_output_active_state_get(",
        "active_server_state",
        "server_material_handle",
        "active-server/",
    ];

    for path in rust_source_files() {
        let source = fs::read_to_string(&path).expect("source file should read");
        for forbidden in forbidden_patterns {
            assert!(
                !source.contains(forbidden),
                "{} still exposes server-labelled normal-signing API `{forbidden}`",
                path.display()
            );
        }
    }
}

#[test]
fn strict_signing_worker_handler_is_protocol_aware() {
    let strict_worker_rs = read_src_file("strict_worker.rs");
    let route_body =
        extract_function_body(&strict_worker_rs, "handle_strict_signing_worker_fetch_v1");
    let lib_rs = read_src_file("lib.rs");
    let fetch_body = extract_function_body(
        &lib_rs,
        "handle_cloudflare_signing_worker_normal_signing_private_fetch_v1",
    );
    let prepare_handler_body = extract_braced_block_after_marker(
        &lib_rs,
        "impl CloudflareSigningWorkerNormalSigningPrepareHandlerV2\n    for CloudflareRoleSeparatedEd25519NormalSigningHandlerV1",
    );
    let finalize_handler_body = extract_braced_block_after_marker(
        &lib_rs,
        "impl CloudflareSigningWorkerNormalSigningFinalizeHandlerV2\n    for CloudflareRoleSeparatedEd25519NormalSigningHandlerV1",
    );

    assert!(
        !strict_worker_rs.contains("strict SigningWorker normal-signing handler is not configured"),
        "strict SigningWorker normal-signing handler must not return the old config stub"
    );
    assert!(
        route_body.contains("CloudflareRoleSeparatedEd25519NormalSigningHandlerV1"),
        "strict SigningWorker entrypoint must use the production normal-signing handler"
    );
    assert!(
        prepare_handler_body.contains("prepare_role_separated_ed25519_round1_v1"),
        "strict SigningWorker normal-signing prepare handler must create server round-1 material"
    );
    assert!(
        finalize_handler_body.contains("NormalSigningProtocolV1::Ed25519TwoPartyFrostFinalizeV1"),
        "strict SigningWorker normal-signing finalize handler must branch on the production protocol"
    );
    assert!(
        fetch_body.contains("server_round1_handle"),
        "strict SigningWorker fetch wrapper must take persisted server round-1 state by handle"
    );
    assert!(
        finalize_handler_body.contains("server_round1"),
        "strict SigningWorker normal-signing handler must consume server round-1 state"
    );
    assert!(
        finalize_handler_body.contains("finalize_role_separated_ed25519_server_signature_v1"),
        "strict SigningWorker normal-signing handler must finalize through the role-separated HSS API"
    );
}

#[test]
fn production_normal_signing_paths_do_not_import_joined_hss_state() {
    let forbidden = [
        "recover_a_from_base_shares",
        "SigningKey::from_bytes",
        "expand_ed25519_seed",
        "x_client_base",
        "\"y_server\"",
        " y_server",
        "y_server:",
        "\"tau_server\"",
        " tau_server",
        "tau_server:",
        "joined d",
        "joined_d",
        "joined a",
        "joined_a",
    ];
    let functions = [
        (
            "lib.rs",
            "handle_cloudflare_router_normal_signing_prepare_authenticated_public_request_v2",
        ),
        (
            "lib.rs",
            "handle_cloudflare_router_normal_signing_finalize_authenticated_public_request_v2",
        ),
        (
            "lib.rs",
            "handle_cloudflare_signing_worker_normal_signing_prepare_private_request_v2",
        ),
        (
            "lib.rs",
            "handle_cloudflare_signing_worker_normal_signing_finalize_private_request_v2",
        ),
        (
            "lib.rs",
            "handle_cloudflare_signing_worker_normal_signing_round1_prepare_private_fetch_v1",
        ),
        (
            "lib.rs",
            "handle_cloudflare_signing_worker_normal_signing_private_fetch_v1",
        ),
        (
            "lib.rs",
            "execute_cloudflare_signing_worker_normal_signing_prepare_service_call_v2",
        ),
        (
            "lib.rs",
            "execute_cloudflare_signing_worker_normal_signing_finalize_service_call_v2",
        ),
    ];

    for (file_name, function_name) in functions {
        let source = read_src_file(file_name);
        let body = extract_function_body(&source, function_name);
        for pattern in forbidden {
            assert!(
                !body.contains(pattern),
                "{function_name} must not reference forbidden HSS material `{pattern}`"
            );
        }
    }
    let lib_rs = read_src_file("lib.rs");
    let handler_body = extract_braced_block_after_marker(
        &lib_rs,
        "for CloudflareRoleSeparatedEd25519NormalSigningHandlerV1",
    );
    for pattern in forbidden {
        assert!(
            !handler_body.contains(pattern),
            "production normal-signing handler must not reference forbidden HSS material `{pattern}`"
        );
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
        "handle_cloudflare_router_normal_signing_prepare_authenticated_public_request_v2",
    );
    let admission = body
        .find("derive_cloudflare_router_normal_signing_prepare_trusted_admission_from_worker_stores_v2")
        .expect("normal signing route must evaluate Router-owned admission stores");
    let replay_builder = body
        .find("normal_signing_v2_prepare_replay_reserve_call")
        .expect("normal signing route must build a replay reservation");
    let replay_execute = body
        .find("execute_cloudflare_router_replay_reserve_v1")
        .expect("normal signing route must execute replay reservation");
    let replay_reject = body
        .find("ReplayedLocalRequest")
        .expect("normal signing route must reject replayed requests");
    let signing_worker_forward = body
        .find("execute_cloudflare_signing_worker_normal_signing_prepare_service_call_v2")
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
fn router_normal_signing_uses_admission_candidate_before_worker_forwarding() {
    let lib_rs = read_src_file("lib.rs");
    for forbidden in [
        "CloudflareRouterNormalSigningAdmissionV2",
        "CloudflareRouterNormalSigningFinalizeAdmissionV2",
        "to_normal_signing_admission_v2",
        "pub admission: CloudflareRouterNormalSigningPrepareAdmissionCandidateV2",
    ] {
        assert!(
            !lib_rs.contains(forbidden),
            "normal-signing pre-gate admission must use candidate naming, found `{forbidden}`"
        );
    }
    for required in [
        "CloudflareRouterNormalSigningPrepareAdmissionCandidateV2",
        "CloudflareRouterNormalSigningFinalizeAdmissionCandidateV2",
        "admission_candidate: CloudflareRouterNormalSigningPrepareAdmissionCandidateV2",
    ] {
        assert!(
            lib_rs.contains(required),
            "normal-signing lifecycle boundary must include `{required}`"
        );
    }
}

#[test]
fn signing_worker_normal_signing_private_routes_do_not_parse_wallet_session() {
    let lib_rs = read_src_file("lib.rs");
    for function_name in [
        "handle_cloudflare_signing_worker_normal_signing_round1_prepare_private_fetch_v1",
        "handle_cloudflare_signing_worker_normal_signing_private_fetch_v1",
        "handle_cloudflare_signing_worker_normal_signing_prepare_private_request_v2",
        "handle_cloudflare_signing_worker_normal_signing_finalize_private_request_v2",
    ] {
        let body = extract_function_body(&lib_rs, function_name);
        for forbidden in [
            "CloudflareRouterWalletSessionCredentialV1",
            "parse_cloudflare_router_bearer_authorization_from_request_v1",
            "verify_wallet_session",
            "Authorization",
        ] {
            assert!(
                !body.contains(forbidden),
                "`{function_name}` must not parse Wallet Session material `{forbidden}`"
            );
        }
    }
}

#[test]
fn strict_signing_worker_entrypoint_routes_normal_signing() {
    let strict_worker_rs = read_src_file("strict_worker.rs");
    let body = extract_function_body(&strict_worker_rs, "handle_strict_signing_worker_fetch_v1");

    for required in [
        "CLOUDFLARE_SIGNING_WORKER_PROOF_BUNDLE_ACTIVATION_PATH_V1",
        "handle_cloudflare_signing_worker_recipient_proof_bundle_activation_fetch_v1",
        "CLOUDFLARE_SIGNING_WORKER_NORMAL_SIGNING_ROUND1_PREPARE_PATH_V1",
        "handle_cloudflare_signing_worker_normal_signing_round1_prepare_private_fetch_v1",
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

fn extract_braced_block_after_marker(source: &str, marker: &str) -> String {
    let start = source
        .find(marker)
        .unwrap_or_else(|| panic!("marker `{marker}` should exist"));
    let body_start = source[start..]
        .find('{')
        .map(|offset| start + offset)
        .unwrap_or_else(|| panic!("marker `{marker}` should have a braced block"));
    let mut depth = 0usize;
    for (offset, ch) in source[body_start..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth = depth
                    .checked_sub(1)
                    .expect("braced block should stay balanced");
                if depth == 0 {
                    return source[body_start..=body_start + offset].to_owned();
                }
            }
            _ => {}
        }
    }
    panic!("marker `{marker}` braced block should end");
}
