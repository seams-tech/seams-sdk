use std::fs;

mod support;

use support::{
    extract_braced_block_after_marker, extract_function_body, extract_struct_block, read_src_file,
    rust_source_files,
};

#[test]
fn normal_signing_routes_do_not_invoke_ab_derivation_handlers() {
    let lib_rs = read_src_file("lib.rs");
    for function_name in [
        "handle_cloudflare_router_normal_signing_prepare_authenticated_public_request_v2",
        "handle_cloudflare_router_normal_signing_finalize_authenticated_public_request_v2",
        "handle_cloudflare_router_normal_signing_presign_pool_prepare_authenticated_public_request_v2",
        "handle_cloudflare_router_normal_signing_presign_pool_hit_finalize_authenticated_public_request_v2",
        "handle_cloudflare_signing_worker_normal_signing_prepare_private_request_v2",
        "handle_cloudflare_signing_worker_normal_signing_finalize_private_request_v2",
        "handle_cloudflare_signing_worker_normal_signing_presign_pool_prepare_private_request_v2",
        "handle_cloudflare_signing_worker_normal_signing_presign_pool_hit_finalize_private_request_v2",
        "handle_cloudflare_signing_worker_normal_signing_round1_prepare_private_fetch_v1",
        "handle_cloudflare_signing_worker_normal_signing_private_fetch_v1",
        "handle_cloudflare_signing_worker_normal_signing_presign_pool_prepare_private_fetch_v1",
        "handle_cloudflare_signing_worker_normal_signing_presign_pool_hit_finalize_private_fetch_v1",
        "execute_cloudflare_signing_worker_normal_signing_prepare_service_call_v2",
        "execute_cloudflare_signing_worker_normal_signing_finalize_service_call_v2",
        "execute_cloudflare_signing_worker_normal_signing_presign_pool_prepare_service_call_v2",
        "execute_cloudflare_signing_worker_normal_signing_presign_pool_hit_finalize_service_call_v2",
    ] {
        let body = extract_function_body(&lib_rs, function_name);
        for forbidden in [
            "build_mpc_prf_threshold_signer_batch_input_v1",
            "decrypt_and_handle_cloudflare_ecdsa_hss_export_signer_private_request_v1",
            "decrypt_and_handle_cloudflare_mpc_prf_recipient_proof_bundle_signer_private_request_v1",
            "handle_cloudflare_validated_mpc_prf_client_recipient_proof_bundle_signer_request_v1",
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
    let ecdsa_finalize_handler_body = extract_braced_block_after_marker(
        &lib_rs,
        "impl CloudflareSigningWorkerEcdsaHssEvmDigestFinalizeHandlerV1\n    for CloudflareRoleSeparatedEcdsaHssEvmDigestFinalizeHandlerV1",
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
        route_body.contains("CloudflareRoleSeparatedEcdsaHssEvmDigestFinalizeHandlerV1"),
        "strict SigningWorker entrypoint must use the production ECDSA-HSS finalize handler"
    );
    assert!(
        prepare_handler_body.contains("prepare_role_separated_ed25519_round1_v1"),
        "strict SigningWorker normal-signing prepare handler must create server round-1 material"
    );
    assert!(
        finalize_handler_body
            .contains("RouterAbEd25519NormalSigningFinalizeProtocolV2::Ed25519TwoPartyFrostFinalizeV1"),
        "strict SigningWorker normal-signing finalize handler must branch on the v2 production protocol"
    );
    assert!(
        finalize_handler_body.contains("request.active_signing_worker.account_public_key"),
        "strict SigningWorker normal-signing finalize handler must load the group key from active SigningWorker state"
    );
    assert!(
        !finalize_handler_body.contains("protocol.group_public_key"),
        "strict SigningWorker normal-signing finalize handler must not trust client-supplied group_public_key"
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
    for required in [
        "threshold_ecdsa_finalize_signature",
        "server_k_share32_b64u",
        "server_sigma_share32_b64u",
        "rerandomization_entropy32_b64u",
        "client_signature_share32",
    ] {
        assert!(
            ecdsa_finalize_handler_body.contains(required),
            "strict SigningWorker ECDSA-HSS finalize handler must use `{required}`"
        );
    }
}

#[test]
fn strict_private_worker_dispatchers_require_internal_auth_before_parsing() {
    let strict_worker_rs = read_src_file("strict_worker.rs");
    for (function_name, first_runtime_marker) in [
        (
            "handle_strict_deriver_a_fetch_v1",
            "CloudflareDeriverAWorkerRuntimeV1::from_worker_env",
        ),
        (
            "handle_strict_signing_worker_fetch_v1",
            "CloudflareSigningWorkerRuntimeV1::from_worker_env",
        ),
        (
            "handle_strict_deriver_b_fetch_v1",
            "CloudflareDeriverBWorkerRuntimeV1::from_worker_env",
        ),
    ] {
        let body = extract_function_body(&strict_worker_rs, function_name);
        let auth_index = body
            .find("require_cloudflare_internal_service_auth_request_v1")
            .unwrap_or_else(|| panic!("{function_name} must require internal service auth"));
        let runtime_index = body
            .find(first_runtime_marker)
            .unwrap_or_else(|| panic!("{function_name} must construct its strict runtime"));
        assert!(
            auth_index < runtime_index,
            "{function_name} must require internal service auth before runtime construction"
        );
        if let Some(json_index) = body.find(".json::<") {
            assert!(
                auth_index < json_index,
                "{function_name} must require internal service auth before body parsing"
            );
        }
    }
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
        "CLOUDFLARE_SIGNING_WORKER_PROOF_BUNDLE_ACTIVATION_PATH",
        "handle_cloudflare_signing_worker_recipient_proof_bundle_activation_fetch_v1",
        "CLOUDFLARE_SIGNING_WORKER_ECDSA_HSS_ACTIVATION_PATH",
        "handle_cloudflare_ecdsa_hss_signing_worker_activation_fetch_v1",
        "CLOUDFLARE_SIGNING_WORKER_NORMAL_SIGNING_ROUND1_PREPARE_PATH",
        "handle_cloudflare_signing_worker_normal_signing_round1_prepare_private_fetch_v1",
        "CLOUDFLARE_SIGNING_WORKER_NORMAL_SIGNING_PATH",
        "handle_cloudflare_signing_worker_normal_signing_private_fetch_v1",
        "CLOUDFLARE_SIGNING_WORKER_ECDSA_HSS_PRESIGNATURE_POOL_PUT_PATH",
        "handle_cloudflare_signing_worker_ecdsa_hss_presignature_pool_put_private_fetch_v1",
        "CLOUDFLARE_SIGNING_WORKER_ECDSA_HSS_SIGNING_PREPARE_PATH",
        "handle_cloudflare_signing_worker_ecdsa_hss_evm_digest_prepare_private_fetch_from_pool_v1",
        "CLOUDFLARE_SIGNING_WORKER_ECDSA_HSS_SIGNING_PATH",
        "handle_cloudflare_signing_worker_ecdsa_hss_evm_digest_finalize_private_fetch_v1",
    ] {
        assert!(
            body.contains(required),
            "strict SigningWorker entrypoint must route through `{required}`"
        );
    }
}
