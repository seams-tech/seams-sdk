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
        "is_cloudflare_router_public_keyset_path",
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
    assert!(
        cors_body.contains("PUBLIC_KEYSET_CORS_CONFIG_V1"),
        "strict Router keyset CORS wrapper must use the public-keyset config"
    );
    let keyset_config =
        extract_braced_block_after_marker(&strict_worker_rs, "const PUBLIC_KEYSET_CORS_CONFIG_V1");
    for required in [
        "ROUTER_AB_PUBLIC_KEYSET_CORS_ORIGINS_ENV",
        "default_origins: Some(\"*\")",
        "allow_wildcard: true",
    ] {
        assert!(
            keyset_config.contains(required),
            "strict Router keyset CORS config must set `{required}`"
        );
    }
    let apply_cors_body =
        extract_function_body(&strict_worker_rs, "cloudflare_router_apply_cors_v1");
    for required in [
        "Access-Control-Allow-Origin",
        "Access-Control-Allow-Methods",
        "Access-Control-Allow-Headers",
        "Access-Control-Max-Age",
    ] {
        assert!(
            apply_cors_body.contains(required),
            "strict Router shared CORS helper must set `{required}`"
        );
    }
}

#[test]
fn strict_router_normal_signing_routes_apply_cors_boundary() {
    let strict_worker_rs = read_src_file("strict_worker.rs");
    let route_body = extract_function_body(&strict_worker_rs, "handle_strict_router_fetch_v1");
    for required in [
        "is_cloudflare_router_normal_signing_public_path",
        "Method::Options",
        "cloudflare_router_normal_signing_preflight_response_v1",
        "cloudflare_router_normal_signing_response_v1",
        "CLOUDFLARE_ROUTER_NORMAL_SIGNING_ROUND1_PREPARE_PUBLIC_REQUEST_PATH",
        "CLOUDFLARE_ROUTER_NORMAL_SIGNING_PUBLIC_REQUEST_PATH",
    ] {
        assert!(
            route_body.contains(required),
            "strict Router normal-signing route must route through `{required}`"
        );
    }

    let lib_rs = read_src_file("lib.rs");
    assert!(
        lib_rs.contains(r#""/router-ab/ed25519/sign/prepare""#)
            && lib_rs.contains(r#""/router-ab/ed25519/sign""#),
        "strict Router normal-signing public paths must use explicit unversioned routes"
    );
    assert!(
        !lib_rs.contains(r#""/v1/hss/sign/prepare""#) && !lib_rs.contains(r#""/v1/hss/sign""#),
        "strict Router normal-signing public paths must not keep legacy route literals"
    );

    let cors_body = extract_function_body(
        &strict_worker_rs,
        "cloudflare_router_normal_signing_cors_v1",
    );
    assert!(
        cors_body.contains("NORMAL_SIGNING_CORS_CONFIG_V1"),
        "strict Router normal-signing CORS wrapper must use the normal-signing config"
    );
    let normal_config =
        extract_braced_block_after_marker(&strict_worker_rs, "const NORMAL_SIGNING_CORS_CONFIG_V1");
    for required in [
        "ROUTER_AB_NORMAL_SIGNING_CORS_ORIGINS_ENV",
        "default_origins: None",
        "allow_wildcard: false",
    ] {
        assert!(
            normal_config.contains(required),
            "strict Router normal-signing CORS config must set `{required}`"
        );
    }
    let apply_cors_body =
        extract_function_body(&strict_worker_rs, "cloudflare_router_apply_cors_v1");
    for required in [
        "Access-Control-Allow-Origin",
        "Access-Control-Allow-Methods",
        "Access-Control-Allow-Headers",
        "Access-Control-Max-Age",
    ] {
        assert!(
            apply_cors_body.contains(required),
            "strict Router shared CORS helper must set `{required}`"
        );
    }
    let origin_body = extract_function_body(
        &strict_worker_rs,
        "cloudflare_router_cors_allowed_origin_v1",
    );
    assert!(
        origin_body.contains("cloudflare_router_normal_signing_cors_allowed_origin_v1"),
        "strict Router normal-signing CORS helper must use the exact-origin allowlist parser"
    );
    assert!(
        !normal_config.contains("Some(\"*\")"),
        "strict Router normal-signing CORS must not default bearer routes to wildcard Origin"
    );
    assert!(
        !normal_config.contains("allow_wildcard: true"),
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
        "read_router_public_body_v1",
        "parse_router_public_body_v1",
        "parse_router_ab_ed25519_normal_signing_prepare_request_v2_json",
        "parse_cloudflare_router_budgeted_ed25519_finalize_request_v2_json",
    ] {
        assert!(
            route_body.contains(required),
            "strict Router normal-signing route must parse raw bodies through `{required}`"
        );
    }
    let read_body = extract_function_body(&strict_worker_rs, "read_router_public_body_v1");
    assert!(
        read_body.contains("request.bytes().await"),
        "strict Router shared body helper must read raw Worker request bytes"
    );
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
fn strict_router_ecdsa_hss_routes_apply_cors_and_boundary_parsers() {
    let strict_worker_rs = read_src_file("strict_worker.rs");
    let route_body = extract_function_body(&strict_worker_rs, "handle_strict_router_fetch_v1");
    for required in [
        "is_cloudflare_router_ecdsa_hss_public_path",
        "CLOUDFLARE_ROUTER_ECDSA_HSS_REGISTRATION_PUBLIC_REQUEST_PATH",
        "CLOUDFLARE_ROUTER_ECDSA_HSS_EXPORT_PUBLIC_REQUEST_PATH",
        "CLOUDFLARE_ROUTER_ECDSA_HSS_SIGNING_PREPARE_PUBLIC_REQUEST_PATH",
        "CLOUDFLARE_ROUTER_ECDSA_HSS_SIGNING_PUBLIC_REQUEST_PATH",
        "read_router_public_body_v1",
        "parse_router_public_body_v1",
        "parse_router_ab_ecdsa_hss_registration_bootstrap_request_v1_json",
        "parse_router_ab_ecdsa_hss_explicit_export_request_v1_json",
        "parse_router_ab_ecdsa_hss_evm_digest_signing_request_v1_json",
        "parse_cloudflare_router_budgeted_ecdsa_hss_finalize_request_v1_json",
        "handle_cloudflare_router_ecdsa_hss_registration_bootstrap_authenticated_public_request_v1",
        "handle_cloudflare_router_ecdsa_hss_explicit_export_authenticated_public_request_v1",
        "handle_cloudflare_router_ecdsa_hss_evm_digest_signing_prepare_authenticated_public_request_v1",
        "handle_cloudflare_router_ecdsa_hss_evm_digest_signing_finalize_authenticated_public_request_v1",
        "cloudflare_router_normal_signing_response_v1",
    ] {
        assert!(
            route_body.contains(required),
            "strict Router ECDSA-HSS public route must pass through `{required}`"
        );
    }
    let read_body = extract_function_body(&strict_worker_rs, "read_router_public_body_v1");
    assert!(
        read_body.contains("request.bytes().await"),
        "strict Router shared body helper must read raw Worker request bytes"
    );
    for forbidden in [
        "json::<RouterAbEcdsaHssRegistrationBootstrapRequestV1>",
        "json::<RouterAbEcdsaHssExplicitExportRequestV1>",
        "CloudflareRouterTrustedAdmissionV1",
        "trusted_admission",
        "handle_cloudflare_router_recipient_proof_bundle_public_request_v1",
    ] {
        assert!(
            !route_body.contains(forbidden),
            "strict Router ECDSA-HSS route must not cross boundary through `{forbidden}`"
        );
    }

    let lib_rs = read_src_file("lib.rs");
    assert!(
        lib_rs.contains(r#""/router-ab/ecdsa-hss/register""#)
            && lib_rs.contains(r#""/router-ab/ecdsa-hss/export""#)
            && lib_rs.contains(r#""/router-ab/ecdsa-hss/sign/prepare""#)
            && lib_rs.contains(r#""/router-ab/ecdsa-hss/sign""#),
        "strict Router ECDSA-HSS public paths must use explicit unversioned routes"
    );
}

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
fn ecdsa_hss_export_uses_client_only_deriver_path() {
    let lib_rs = read_src_file("lib.rs");
    let export_body = extract_function_body(
        &lib_rs,
        "handle_cloudflare_router_ecdsa_hss_explicit_export_authenticated_public_request_v1",
    );
    for required in [
        "execute_cloudflare_ecdsa_hss_deriver_export_service_call_v1",
        "CloudflareRouterEcdsaHssExportAdmissionResponseV1::forwarded",
    ] {
        assert!(
            export_body.contains(required),
            "ECDSA-HSS export route must pass through `{required}`"
        );
    }
    for forbidden in [
        "execute_cloudflare_signer_recipient_proof_bundle_service_call_v1",
        "CloudflareSigningWorkerRecipientProofBundleActivationV1",
        "execute_cloudflare_ecdsa_hss_signing_worker_activation_service_call_v1",
        "server_bundle",
        "deriver_b_server_bundle",
    ] {
        assert!(
            !export_body.contains(forbidden),
            "ECDSA-HSS export route must not produce server output through `{forbidden}`"
        );
    }

    let service_body = extract_function_body(
        &lib_rs,
        "execute_cloudflare_ecdsa_hss_deriver_export_service_call_v1",
    );
    for required in [
        "CloudflareEcdsaHssDeriverExportPrivateRequestV1",
        "CloudflareSignerClientRecipientProofBundleResponseV1",
        "cloudflare_ecdsa_hss_deriver_export_service_url",
        "validate_cloudflare_signer_client_recipient_proof_bundle_private_response_v1",
    ] {
        assert!(
            service_body.contains(required),
            "ECDSA-HSS export service call must use `{required}`"
        );
    }
    assert!(
        !service_body.contains("CloudflareSignerRecipientProofBundleResponseV1"),
        "ECDSA-HSS export service call must not deserialize the activation-capable response"
    );

    let client_response_body = extract_braced_block_after_marker(
        &lib_rs,
        "pub struct CloudflareSignerClientRecipientProofBundleResponseV1",
    );
    assert!(
        client_response_body.contains("client_bundle"),
        "client-only Deriver response must carry a client bundle"
    );
    assert!(
        !client_response_body.contains("server_bundle")
            && !client_response_body.contains("deriver_b_server_bundle"),
        "client-only Deriver response must not expose server bundles"
    );
}

#[test]
fn ecdsa_hss_registration_uses_protocol_specific_deriver_path() {
    let lib_rs = read_src_file("lib.rs");
    let registration_body = extract_function_body(
        &lib_rs,
        "handle_cloudflare_router_ecdsa_hss_registration_bootstrap_authenticated_public_request_v1",
    );
    for required in [
        "execute_cloudflare_ecdsa_hss_deriver_registration_service_call_v1",
        "CloudflareSigningWorkerRecipientProofBundleActivationV1::new",
        "execute_cloudflare_ecdsa_hss_signing_worker_activation_service_call_v1",
    ] {
        assert!(
            registration_body.contains(required),
            "ECDSA-HSS registration route must pass through `{required}`"
        );
    }
    assert!(
        !registration_body
            .contains("execute_cloudflare_signer_recipient_proof_bundle_service_call_v1"),
        "ECDSA-HSS registration must not use the generic Deriver private service path"
    );

    let service_body = extract_function_body(
        &lib_rs,
        "execute_cloudflare_ecdsa_hss_deriver_registration_service_call_v1",
    );
    for required in [
        "CloudflareEcdsaHssDeriverRegistrationPrivateRequestV1",
        "CloudflareSignerRecipientProofBundleResponseV1",
        "cloudflare_ecdsa_hss_deriver_registration_service_url",
        "validate_cloudflare_signer_recipient_proof_bundle_private_response_v1",
    ] {
        assert!(
            service_body.contains(required),
            "ECDSA-HSS registration service call must use `{required}`"
        );
    }
}

#[test]
fn strict_deriver_ecdsa_hss_export_routes_are_protocol_specific() {
    let strict_worker_rs = read_src_file("strict_worker.rs");
    let signer_a_body =
        extract_function_body(&strict_worker_rs, "handle_strict_deriver_a_fetch_v1");
    let signer_b_body =
        extract_function_body(&strict_worker_rs, "handle_strict_deriver_b_fetch_v1");
    for (name, body, runtime_variant) in [
        (
            "Deriver A",
            signer_a_body,
            "StrictDeriverRuntimeV1::DeriverA",
        ),
        (
            "Deriver B",
            signer_b_body,
            "StrictDeriverRuntimeV1::DeriverB",
        ),
    ] {
        assert!(
            body.contains("handle_strict_deriver_fetch_v1"),
            "{name} strict Deriver must delegate to the shared Deriver dispatcher"
        );
        assert!(
            body.contains(runtime_variant),
            "{name} strict Deriver must pass the role-specific runtime variant"
        );
    }
    let shared_body = extract_function_body(&strict_worker_rs, "handle_strict_deriver_fetch_v1");
    for required in [
        "CloudflareEcdsaHssDeriverRegistrationPrivateRequestV1",
        "decrypt_and_handle_cloudflare_ecdsa_hss_registration_signer_private_request_v1",
        "CloudflareEcdsaHssDeriverExportPrivateRequestV1",
        "decrypt_and_handle_cloudflare_ecdsa_hss_export_signer_private_request_v1",
        "registration_private_path",
        "export_private_path",
    ] {
        assert!(
            shared_body.contains(required),
            "shared strict Deriver dispatcher must use `{required}`"
        );
    }
}

#[test]
fn ecdsa_hss_normal_signing_binding_does_not_invoke_derivers() {
    let lib_rs = read_src_file("lib.rs");
    let body = extract_function_body(
        &lib_rs,
        "validate_cloudflare_ecdsa_hss_normal_signing_active_material_v1",
    );
    for required in [
        "cloudflare_ecdsa_hss_public_identity_from_normal_signing_material_v1",
        "active_signing_worker.activation_transcript_digest",
        "scope.public_identity",
    ] {
        assert!(
            body.contains(required),
            "ECDSA-HSS normal-signing binding must check `{required}`"
        );
    }
    for forbidden in [
        "execute_cloudflare_signer_recipient_proof_bundle_service_call_v1",
        "execute_cloudflare_ecdsa_hss_deriver_export_service_call_v1",
        "decrypt_and_handle_cloudflare_ecdsa_hss_export_signer_private_request_v1",
        "CloudflareEcdsaHssDeriverExportPrivateRequestV1",
        "CloudflareEcdsaHssSigningWorkerActivationRequestV1",
        "CloudflareSigningWorkerRecipientProofBundleActivationV1",
    ] {
        assert!(
            !body.contains(forbidden),
            "ECDSA-HSS normal-signing binding must not call setup/export path `{forbidden}`"
        );
    }
}

#[test]
fn ecdsa_hss_normal_signing_materialized_request_uses_active_material_only() {
    let lib_rs = read_src_file("lib.rs");
    let body = extract_braced_block_after_marker(
        &lib_rs,
        "impl CloudflareSigningWorkerMaterializedEcdsaHssEvmDigestSigningRequestV1",
    );
    for required in [
        "self.request.request.validate_at(self.materialized_at_ms)",
        "validate_cloudflare_ecdsa_hss_normal_signing_active_material_v1",
        "&self.request.request.scope",
        "&self.active_signing_worker",
        "&self.material",
    ] {
        assert!(
            body.contains(required),
            "ECDSA-HSS materialized normal-signing request must check `{required}`"
        );
    }
    for forbidden in [
        "execute_cloudflare_signer_recipient_proof_bundle_service_call_v1",
        "execute_cloudflare_ecdsa_hss_deriver_export_service_call_v1",
        "decrypt_and_handle_cloudflare_ecdsa_hss_export_signer_private_request_v1",
        "CloudflareEcdsaHssDeriverExportPrivateRequestV1",
        "CloudflareEcdsaHssSigningWorkerActivationRequestV1",
        "CloudflareSigningWorkerRecipientProofBundleActivationV1",
    ] {
        assert!(
            !body.contains(forbidden),
            "ECDSA-HSS materialized normal-signing request must not call `{forbidden}`"
        );
    }
}

#[test]
fn ecdsa_hss_active_state_lookup_uses_full_scope_session_identity() {
    let durable_object_rs = read_src_file("durable_object.rs");
    let lookup_body =
        extract_function_body(&durable_object_rs, "from_ecdsa_hss_normal_signing_scope");
    for required in [
        "scope.wallet_id.clone()",
        "scope.active_state_session_id()?",
        "scope.signing_worker.server_id.clone()",
    ] {
        assert!(
            lookup_body.contains(required),
            "ECDSA-HSS active-state lookup must bind `{required}`"
        );
    }
    assert!(
        !lookup_body.contains("scope.context.ecdsa_threshold_key_id.clone()"),
        "ECDSA-HSS active-state lookup must not key only by threshold key id"
    );

    let lib_rs = read_src_file("lib.rs");
    let active_material_body = extract_function_body(
        &lib_rs,
        "validate_cloudflare_ecdsa_hss_normal_signing_active_material_v1",
    );
    assert!(
        active_material_body.contains("cloudflare_ecdsa_hss_active_state_session_id_from_scope_v1"),
        "ECDSA-HSS active material validation must use the full active-state session id"
    );
    assert!(
        !active_material_body.contains("scope.context.ecdsa_threshold_key_id"),
        "ECDSA-HSS active material validation must not compare only the threshold key id"
    );
}

#[test]
fn ecdsa_hss_finalize_helper_materializes_presignature_before_handler() {
    let lib_rs = read_src_file("lib.rs");
    let body = extract_function_body(
        &lib_rs,
        "handle_cloudflare_signing_worker_ecdsa_hss_evm_digest_finalize_private_request_v1",
    );
    let materialized = body
        .find("CloudflareSigningWorkerMaterializedEcdsaHssEvmDigestFinalizeRequestV1::new")
        .expect("ECDSA-HSS finalize helper must materialize active state and presignature");
    let prepare_request = body
        .find("materialized.prepare_request()?")
        .expect("ECDSA-HSS finalize helper must derive prepare request");
    let handler = body
        .find("handler.handle_ecdsa_hss_evm_digest_finalize_request_v1")
        .expect("ECDSA-HSS finalize helper must call the handler");
    let response_validation = body
        .find("response.validate_for_request(&prepare_request)?")
        .expect("ECDSA-HSS finalize helper must validate response binding");
    assert!(
        materialized < prepare_request && prepare_request < handler && handler < response_validation,
        "ECDSA-HSS finalize helper must materialize, derive prepare binding, call handler, then validate response"
    );
    for forbidden in [
        "execute_cloudflare_signer_recipient_proof_bundle_service_call_v1",
        "execute_cloudflare_ecdsa_hss_deriver_export_service_call_v1",
        "decrypt_and_handle_cloudflare_ecdsa_hss_export_signer_private_request_v1",
        "CloudflareEcdsaHssDeriverExportPrivateRequestV1",
        "CloudflareEcdsaHssSigningWorkerActivationRequestV1",
        "CloudflareSigningWorkerRecipientProofBundleActivationV1",
    ] {
        assert!(
            !body.contains(forbidden),
            "ECDSA-HSS digest signing helper must not call `{forbidden}`"
        );
    }
}

#[test]
fn ecdsa_hss_finalize_private_fetch_takes_one_use_presignature() {
    let lib_rs = read_src_file("lib.rs");
    let body = extract_function_body(
        &lib_rs,
        "handle_cloudflare_signing_worker_ecdsa_hss_evm_digest_finalize_private_fetch_v1",
    );
    for required in [
        "CLOUDFLARE_SIGNING_WORKER_ECDSA_HSS_SIGNING_PATH",
        "CloudflareSigningWorkerAdmittedEcdsaHssEvmDigestFinalizeRequestV1",
        "CloudflareActiveSigningWorkerStateLookupV1::from_ecdsa_hss_normal_signing_scope",
        "active_signing_worker_state_get_call",
        "signing_worker_output_material_get_call",
        "CloudflareSigningWorkerEcdsaPresignatureLookupV1::new",
        "signing_worker_ecdsa_presignature_take_call",
        "require_signing_worker_ecdsa_presignature_take_response_v1",
        "handle_cloudflare_signing_worker_ecdsa_hss_evm_digest_finalize_private_request_v1",
        "worker::Response::from_json(&response)",
    ] {
        assert!(
            body.contains(required),
            "ECDSA-HSS finalize private fetch must include `{required}`"
        );
    }
    let state_lookup = body
        .find("active_signing_worker_state_get_call")
        .expect("ECDSA-HSS finalize must load active state");
    let material_lookup = body
        .find("signing_worker_output_material_get_call")
        .expect("ECDSA-HSS finalize must load material");
    let take = body
        .find("signing_worker_ecdsa_presignature_take_call")
        .expect("ECDSA-HSS finalize must take presignature");
    let handler = body
        .find("handle_cloudflare_signing_worker_ecdsa_hss_evm_digest_finalize_private_request_v1")
        .expect("ECDSA-HSS finalize must invoke materialized handler");
    assert!(
        state_lookup < material_lookup && material_lookup < take && take < handler,
        "ECDSA-HSS finalize must load state/material, take presignature, then invoke handler"
    );
    for forbidden in [
        "execute_cloudflare_ecdsa_hss_deriver_registration_service_call_v1",
        "execute_cloudflare_ecdsa_hss_deriver_export_service_call_v1",
        "decrypt_and_handle_cloudflare_ecdsa_hss_export_signer_private_request_v1",
        "CloudflareSigningWorkerRecipientProofBundleActivationV1",
    ] {
        assert!(
            !body.contains(forbidden),
            "ECDSA-HSS finalize private fetch must not call `{forbidden}`"
        );
    }
}

#[test]
fn ecdsa_hss_router_prepare_admission_uses_wallet_session_and_replay() {
    let lib_rs = read_src_file("lib.rs");
    for required in [
        "pub client_presignature_id: String",
        "request.client_presignature_id.clone()",
        "self.client_presignature_id != request.client_presignature_id",
    ] {
        assert!(
            lib_rs.contains(required),
            "ECDSA-HSS Router prepare admission must bind `{required}`"
        );
    }
    let body = extract_function_body(
        &lib_rs,
        "handle_cloudflare_router_ecdsa_hss_evm_digest_signing_prepare_authenticated_public_request_v1",
    );
    for required in [
        "verify_wallet_session",
        "validate_for_ecdsa_hss_evm_digest_signing_request_v1",
        "CloudflareRouterEcdsaHssEvmDigestPrepareAdmissionCandidateV1::from_prepare_request",
        "derive_cloudflare_router_ecdsa_hss_evm_digest_prepare_trusted_admission_from_worker_stores_v1",
        "allows_signing_worker_forwarding",
        "ecdsa_hss_evm_digest_prepare_replay_reserve_call",
        "execute_cloudflare_router_replay_reserve_v1",
        "CloudflareSigningWorkerAdmittedEcdsaHssEvmDigestSigningRequestV1::new",
        "execute_cloudflare_signing_worker_ecdsa_hss_evm_digest_prepare_service_call_v1",
    ] {
        assert!(
            body.contains(required),
            "ECDSA-HSS Router prepare admission must include `{required}`"
        );
    }

    let admission = body
        .find("from_prepare_request")
        .expect("ECDSA-HSS Router prepare must build admission");
    let replay = body
        .find("execute_cloudflare_router_replay_reserve_v1")
        .expect("ECDSA-HSS Router prepare must reserve replay");
    let forward = body
        .find("execute_cloudflare_signing_worker_ecdsa_hss_evm_digest_prepare_service_call_v1")
        .expect("ECDSA-HSS Router prepare must forward to SigningWorker");
    assert!(
        admission < replay && replay < forward,
        "ECDSA-HSS Router prepare must derive admission, reserve replay, then forward"
    );
    for forbidden in [
        "execute_cloudflare_ecdsa_hss_deriver_registration_service_call_v1",
        "execute_cloudflare_ecdsa_hss_deriver_export_service_call_v1",
        "decrypt_and_handle_cloudflare_ecdsa_hss_export_signer_private_request_v1",
        "CloudflareSigningWorkerRecipientProofBundleActivationV1",
    ] {
        assert!(
            !body.contains(forbidden),
            "ECDSA-HSS Router prepare must not call `{forbidden}`"
        );
    }
}

#[test]
fn ecdsa_hss_router_finalize_admission_uses_wallet_session_and_presignature_take() {
    let lib_rs = read_src_file("lib.rs");
    let body = extract_function_body(
        &lib_rs,
        "handle_cloudflare_router_ecdsa_hss_evm_digest_signing_finalize_authenticated_public_request_v1",
    );
    for required in [
        "verify_wallet_session",
        "validate_for_ecdsa_hss_evm_digest_finalize_request_v1",
        "CloudflareRouterEcdsaHssEvmDigestFinalizeAdmissionCandidateV1::from_finalize_request",
        "derive_cloudflare_router_ecdsa_hss_evm_digest_finalize_trusted_admission_from_worker_stores_v1",
        "allows_signing_worker_forwarding",
        "CloudflareSigningWorkerAdmittedEcdsaHssEvmDigestFinalizeRequestV1::new",
        "execute_cloudflare_signing_worker_ecdsa_hss_evm_digest_finalize_service_call_v1",
    ] {
        assert!(
            body.contains(required),
            "ECDSA-HSS Router finalize admission must include `{required}`"
        );
    }
    assert!(
        !body.contains("execute_cloudflare_router_replay_reserve_v1")
            && !body.contains("ecdsa_hss_evm_digest_prepare_replay_reserve_call"),
        "ECDSA-HSS Router finalize must rely on SigningWorker one-use presignature take, not a prepare replay reserve"
    );
    let admission = body
        .find("from_finalize_request")
        .expect("ECDSA-HSS Router finalize must build admission");
    let forward = body
        .find("execute_cloudflare_signing_worker_ecdsa_hss_evm_digest_finalize_service_call_v1")
        .expect("ECDSA-HSS Router finalize must forward to SigningWorker");
    assert!(
        admission < forward,
        "ECDSA-HSS Router finalize must derive admission before forwarding"
    );
    for forbidden in [
        "execute_cloudflare_ecdsa_hss_deriver_registration_service_call_v1",
        "execute_cloudflare_ecdsa_hss_deriver_export_service_call_v1",
        "decrypt_and_handle_cloudflare_ecdsa_hss_export_signer_private_request_v1",
        "CloudflareSigningWorkerRecipientProofBundleActivationV1",
    ] {
        assert!(
            !body.contains(forbidden),
            "ECDSA-HSS Router finalize must not call `{forbidden}`"
        );
    }
}

#[test]
fn ecdsa_hss_prepare_private_fetch_from_pool_reserves_then_binds_presignature() {
    let lib_rs = read_src_file("lib.rs");
    let body = extract_function_body(
        &lib_rs,
        "handle_cloudflare_signing_worker_ecdsa_hss_evm_digest_prepare_private_fetch_from_pool_v1",
    );
    for required in [
        "CLOUDFLARE_SIGNING_WORKER_ECDSA_HSS_SIGNING_PREPARE_PATH",
        "CloudflareSigningWorkerAdmittedEcdsaHssEvmDigestSigningRequestV1",
        "CloudflareActiveSigningWorkerStateLookupV1::from_ecdsa_hss_normal_signing_scope",
        "CloudflareSigningWorkerEcdsaPresignaturePoolLookupV1::new",
        "signing_worker_ecdsa_presignature_pool_take_call",
        "require_signing_worker_ecdsa_presignature_pool_take_response_v1",
        "cloudflare_random_bytes_v1(32)",
        "prepare_cloudflare_role_separated_ecdsa_hss_evm_digest_from_pool_record_v1",
        "signing_worker_ecdsa_presignature_put_call",
        "prepared.validate_put_receipt",
        "worker::Response::from_json(&prepared.response)",
    ] {
        assert!(
            body.contains(required),
            "ECDSA-HSS pool-backed prepare private fetch must include `{required}`"
        );
    }
    let pool_take = body
        .find("signing_worker_ecdsa_presignature_pool_take_call")
        .expect("pool-backed prepare must reserve the pool record");
    let bind = body
        .find("prepare_cloudflare_role_separated_ecdsa_hss_evm_digest_from_pool_record_v1")
        .expect("pool-backed prepare must bind reserved pool record");
    let request_bound_put = body
        .find("signing_worker_ecdsa_presignature_put_call")
        .expect("pool-backed prepare must persist the request-bound record");
    assert!(
        pool_take < bind && bind < request_bound_put,
        "pool-backed prepare must reserve, bind, then persist request-bound presignature state"
    );
}

#[test]
fn ecdsa_hss_presignature_pool_put_private_fetch_derives_active_state() {
    let lib_rs = read_src_file("lib.rs");
    let body = extract_function_body(
        &lib_rs,
        "handle_cloudflare_signing_worker_ecdsa_hss_presignature_pool_put_private_fetch_v1",
    );
    for required in [
        "CLOUDFLARE_SIGNING_WORKER_ECDSA_HSS_PRESIGNATURE_POOL_PUT_PATH",
        "CloudflareSigningWorkerEcdsaHssPresignaturePoolPutRequestV1",
        "parsed.validate_at(now_unix_ms)",
        "CloudflareActiveSigningWorkerStateLookupV1::from_ecdsa_hss_normal_signing_scope",
        "active_signing_worker_state_get_call",
        "parsed.to_pool_record(active_signing_worker, now_unix_ms)",
        "signing_worker_ecdsa_presignature_pool_put_call",
        "require_signing_worker_ecdsa_presignature_pool_put_response_v1",
        "worker::Response::from_json(&receipt)",
    ] {
        assert!(
            body.contains(required),
            "ECDSA-HSS pool-fill private fetch must include `{required}`"
        );
    }
    assert!(
        !body.contains("CloudflareSigningWorkerEcdsaPresignaturePoolRecordV1::new("),
        "pool-fill fetch must delegate record construction to the validated boundary type"
    );
}

#[test]
fn ecdsa_hss_presignature_state_uses_distinct_one_use_storage() {
    let durable_object_rs = read_src_file("durable_object.rs");
    for required in [
        "CloudflareSigningWorkerEcdsaPresignatureRecordV1",
        "CloudflareSigningWorkerEcdsaPresignatureLookupV1",
        "CloudflareSigningWorkerEcdsaPresignaturePutReceiptV1",
        "CloudflareSigningWorkerEcdsaPresignaturePoolRecordV1",
        "CloudflareSigningWorkerEcdsaPresignaturePoolLookupV1",
        "CloudflareSigningWorkerEcdsaPresignaturePoolPutReceiptV1",
        "signing-worker-ecdsa-presignature",
        "signing-worker-ecdsa-presignature-pool",
        "SigningWorkerEcdsaPresignaturePut",
        "SigningWorkerEcdsaPresignatureTake",
        "SigningWorkerEcdsaPresignatureCleanupExpired",
        "SigningWorkerEcdsaPresignaturePoolPut",
        "SigningWorkerEcdsaPresignaturePoolTake",
        "SigningWorkerEcdsaPresignaturePoolCleanupExpired",
        "rerandomization_entropy32_b64u",
        "record.validate_for_lookup(lookup)?",
        "take_signing_worker_ecdsa_presignature",
        "take_signing_worker_ecdsa_presignature_pool",
        "worker_storage_delete(storage, &storage_key, call.operation_kind()).await?",
    ] {
        assert!(
            durable_object_rs.contains(required),
            "ECDSA-HSS presignature Durable Object state must include `{required}`"
        );
    }

    let receipt_body = extract_braced_block_after_marker(
        &durable_object_rs,
        "pub struct CloudflareSigningWorkerEcdsaPresignaturePutReceiptV1",
    );
    for forbidden in ["server_k_share32_b64u", "server_sigma_share32_b64u"] {
        assert!(
            !receipt_body.contains(forbidden),
            "ECDSA-HSS presignature put receipt must not expose `{forbidden}`"
        );
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
fn ecdsa_hss_explicit_export_emits_sanitized_audit_event() {
    let lib_rs = read_src_file("lib.rs");
    let host_rs = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("router-ab-core")
            .join("src")
            .join("protocol")
            .join("engine")
            .join("host.rs"),
    )
    .expect("router-ab-core host source should read");
    let audit_event_block = extract_braced_block_after_marker(&host_rs, "pub enum AuditEventV1");
    assert!(
        audit_event_block.contains("EcdsaHssExplicitExportDecision"),
        "core audit events must include the ECDSA-HSS explicit export decision"
    );

    let handler_body = extract_function_body(
        &lib_rs,
        "handle_cloudflare_router_ecdsa_hss_explicit_export_authenticated_public_request_v1",
    );
    for required in [
        "emit_cloudflare_ecdsa_hss_explicit_export_audit_event_v1",
        "EcdsaHssExplicitExportAuditDecisionV1::Rejected",
        "EcdsaHssExplicitExportAuditDecisionV1::Forwarded",
        "EcdsaHssExplicitExportAuditDecisionV1::Stopped",
    ] {
        assert!(
            handler_body.contains(required),
            "ECDSA-HSS explicit export handler must emit `{required}`"
        );
    }

    let audit_body = extract_function_body(
        &lib_rs,
        "emit_cloudflare_ecdsa_hss_explicit_export_audit_event_v1",
    );
    for required in [
        "request_digest_b64u",
        "wallet_id",
        "account_id",
        "session_id",
        "selected_server_id",
        "application_binding_digest_b64u",
        "export_authorization_digest_b64u",
        "decision",
        "reason_code",
        "router_ab_audit_event_v1",
    ] {
        assert!(
            audit_body.contains(required),
            "ECDSA-HSS explicit export audit event must include `{required}`"
        );
    }
    for forbidden in [
        "privateKeyHex",
        "private_key_hex",
        "x_relayer_export",
        "x_server_base",
        "decrypted",
        "signature_b64u",
        "server_export_share",
        "client_share",
    ] {
        assert!(
            !audit_body.contains(forbidden),
            "ECDSA-HSS explicit export audit event must not include `{forbidden}`"
        );
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

#[test]
fn ecdsa_hss_registration_and_export_have_separate_activation_boundaries() {
    let lib_rs = read_src_file("lib.rs");
    let registration_body = extract_function_body(
        &lib_rs,
        "handle_cloudflare_router_ecdsa_hss_registration_bootstrap_authenticated_public_request_v1",
    );
    let export_body = extract_function_body(
        &lib_rs,
        "handle_cloudflare_router_ecdsa_hss_explicit_export_authenticated_public_request_v1",
    );
    for required in [
        "CloudflareEcdsaHssSigningWorkerActivationRequestV1::new",
        "execute_cloudflare_ecdsa_hss_signing_worker_activation_service_call_v1",
        "CloudflareRouterEcdsaHssRegistrationAdmissionResponseV1::forwarded",
    ] {
        assert!(
            registration_body.contains(required),
            "ECDSA-HSS registration must activate through `{required}`"
        );
    }
    for forbidden in [
        "CloudflareEcdsaHssSigningWorkerActivationRequestV1::new",
        "execute_cloudflare_ecdsa_hss_signing_worker_activation_service_call_v1",
        "CloudflareSigningWorkerRecipientProofBundleActivationV1::new",
    ] {
        assert!(
            !export_body.contains(forbidden),
            "ECDSA-HSS export must not activate SigningWorker material through `{forbidden}`"
        );
    }
    assert!(
        export_body.contains("CloudflareRouterEcdsaHssExportAdmissionResponseV1::forwarded"),
        "ECDSA-HSS export must return the export-specific response"
    );

    let identity_body = extract_function_body(
        &lib_rs,
        "cloudflare_ecdsa_hss_public_identity_from_activation_material_v1",
    );
    assert!(
        identity_body.contains("derive_relayer_share_for_client_public"),
        "ECDSA-HSS activation must derive public identity through the ECDSA-HSS crate"
    );
}

#[test]
fn ecdsa_hss_direct_activation_delivery_excludes_client_and_export_bundles() {
    let lib_rs = read_src_file("lib.rs");
    let delivery_struct = extract_struct_block(
        &lib_rs,
        "CloudflareSigningWorkerDirectRecipientProofBundleActivationDeliveryV1",
    );
    for required in [
        "activation_context",
        "deriver_role",
        "signing_worker_bundle",
    ] {
        assert!(
            delivery_struct.contains(required),
            "direct activation delivery must carry `{required}`"
        );
    }
    for forbidden in [
        "client_bundle",
        "deriver_a_client_bundle",
        "deriver_b_client_bundle",
        "export_request",
        "CloudflareEcdsaHssDeriverExportPrivateRequestV1",
    ] {
        assert!(
            !delivery_struct.contains(forbidden),
            "direct activation delivery struct must not carry `{forbidden}`"
        );
    }

    let delivery_impl = extract_braced_block_after_marker(
        &lib_rs,
        "impl CloudflareSigningWorkerDirectRecipientProofBundleActivationDeliveryV1",
    );
    for required in [
        "Role::Server",
        "OpenedShareKind::XServerBase",
        "validate_cloudflare_recipient_proof_bundle_envelope_for_activation_context_v1",
    ] {
        assert!(
            delivery_impl.contains(required),
            "direct activation delivery validation must enforce `{required}`"
        );
    }
    for forbidden in [
        "Role::Client",
        "OpenedShareKind::XClientBase",
        "cloudflare_ecdsa_hss_deriver_export_service_url",
        "CLOUDFLARE_SIGNER_A_ECDSA_HSS_EXPORT_PRIVATE_REQUEST_PATH",
        "CLOUDFLARE_SIGNER_B_ECDSA_HSS_EXPORT_PRIVATE_REQUEST_PATH",
    ] {
        assert!(
            !delivery_impl.contains(forbidden),
            "direct activation delivery validation must not use `{forbidden}`"
        );
    }

    let aggregate_impl = extract_braced_block_after_marker(
        &lib_rs,
        "impl CloudflareSigningWorkerDirectRecipientProofBundleActivationAggregateV1",
    );
    for required in [
        "Role::SignerA",
        "Role::SignerB",
        "CloudflareSigningWorkerRecipientProofBundleActivationV1::new",
    ] {
        assert!(
            aggregate_impl.contains(required),
            "direct activation aggregate must require `{required}`"
        );
    }
    for forbidden in [
        "client_bundle",
        "CloudflareRouterRecipientProofBundleResponseV1",
        "CloudflareSignerClientRecipientProofBundleResponseV1",
        "CloudflareEcdsaHssDeriverExportPrivateRequestV1",
    ] {
        assert!(
            !aggregate_impl.contains(forbidden),
            "direct activation aggregate must not carry client/export surface through `{forbidden}`"
        );
    }
}

#[test]
fn ecdsa_hss_strict_derivers_send_direct_activation_only_for_activation_flows() {
    let lib_rs = read_src_file("lib.rs");
    let strict_worker_rs = read_src_file("strict_worker.rs");
    let dispatcher_body =
        extract_function_body(&strict_worker_rs, "handle_strict_deriver_fetch_v1");
    let helper_body = extract_function_body(
        &strict_worker_rs,
        "send_strict_deriver_direct_activation_delivery_v1",
    );
    assert_eq!(
        dispatcher_body
            .matches("send_strict_deriver_direct_activation_delivery_v1")
            .count(),
        2,
        "strict Deriver dispatcher must send direct activation for registration and refresh only"
    );
    for required in [
        "CloudflareSigningWorkerDirectRecipientProofBundleActivationDeliveryV1::from_signer_response",
        "execute_cloudflare_signing_worker_direct_recipient_proof_bundle_activation_service_call_v1",
        "runtime.signing_worker_peer()",
    ] {
        assert!(
            helper_body.contains(required),
            "strict Deriver direct activation helper must use `{required}`"
        );
    }
    let direct_route_body = extract_function_body(
        &lib_rs,
        "handle_cloudflare_ecdsa_hss_signing_worker_activation_fetch_v1",
    );
    for required in [
        "CloudflareEcdsaHssSigningWorkerActivationRequestV1",
        "CloudflareSigningWorkerDirectRecipientProofBundleActivationDeliveryV1",
        "activate_cloudflare_signing_worker_direct_recipient_proof_bundle_delivery_v1",
    ] {
        assert!(
            direct_route_body.contains(required),
            "ECDSA-HSS SigningWorker activation route must accept `{required}`"
        );
    }
    let env_validation_body =
        extract_function_body(&lib_rs, "validate_cloudflare_worker_env_bindings_v1");
    assert!(
        env_validation_body
            .matches("require_worker_service(env, &bindings.signing_worker)")
            .count()
            >= 3,
        "Worker env validation must require Router, Deriver A, and Deriver B SigningWorker service bindings"
    );
}

#[test]
fn ecdsa_hss_cloudflare_boundaries_do_not_reconstruct_canonical_export_keys() {
    let lib_rs = read_src_file("lib.rs");
    let strict_worker_rs = read_src_file("strict_worker.rs");
    let forbidden_canonical_material = [
        "privateKeyHex",
        "private_key_hex",
        "reconstruct_export_key",
        "reconstructExportKey",
        "x_export",
        "canonical_x",
        "canonicalX",
        "clientRootShare32B64u",
        "serverExportShare32B64u",
        "raw_root",
        "rawRoot",
        "root_material",
        "rootMaterial",
    ];

    for function_name in [
        "handle_cloudflare_router_ecdsa_hss_registration_bootstrap_authenticated_public_request_v1",
        "handle_cloudflare_router_ecdsa_hss_explicit_export_authenticated_public_request_v1",
        "handle_cloudflare_router_ecdsa_hss_recovery_authenticated_public_request_v1",
        "handle_cloudflare_router_ecdsa_hss_activation_refresh_authenticated_public_request_v1",
        "handle_cloudflare_router_ecdsa_hss_evm_digest_signing_prepare_authenticated_public_request_v1",
        "handle_cloudflare_router_ecdsa_hss_evm_digest_signing_finalize_authenticated_public_request_v1",
        "decrypt_and_handle_cloudflare_ecdsa_hss_registration_signer_private_request_v1",
        "decrypt_and_handle_cloudflare_ecdsa_hss_export_signer_private_request_v1",
        "decrypt_and_handle_cloudflare_ecdsa_hss_recovery_signer_private_request_v1",
        "decrypt_and_handle_cloudflare_ecdsa_hss_activation_refresh_signer_private_request_v1",
        "handle_cloudflare_ecdsa_hss_signing_worker_activation_fetch_v1",
        "handle_cloudflare_ecdsa_hss_signing_worker_activation_refresh_fetch_v1",
        "cloudflare_ecdsa_hss_public_identity_from_activation_material_v1",
        "cloudflare_ecdsa_hss_activation_receipt_from_material_v1",
        "cloudflare_ecdsa_hss_activation_refresh_receipt_from_material_v1",
        "cloudflare_ecdsa_hss_public_identity_from_normal_signing_material_v1",
    ] {
        let body = extract_function_body(&lib_rs, function_name);
        for forbidden in forbidden_canonical_material {
            assert!(
                !body.contains(forbidden),
                "{function_name} must not materialize canonical export/private key material through `{forbidden}`"
            );
        }
    }

    let strict_router_body =
        extract_function_body(&strict_worker_rs, "handle_strict_router_fetch_v1");
    for forbidden in forbidden_canonical_material {
        assert!(
            !strict_router_body.contains(forbidden),
            "strict Router ECDSA-HSS routing must not expose canonical export/private key material through `{forbidden}`"
        );
    }

    for marker in [
        "pub struct CloudflareEcdsaHssSigningWorkerActivationReceiptV1",
        "pub enum CloudflareRouterEcdsaHssRegistrationAdmissionResponseV1",
        "pub enum CloudflareRouterEcdsaHssExportAdmissionResponseV1",
        "pub enum CloudflareRouterEcdsaHssRecoveryAdmissionResponseV1",
        "pub enum CloudflareRouterEcdsaHssActivationRefreshAdmissionResponseV1",
    ] {
        let block = extract_braced_block_after_marker(&lib_rs, marker);
        for forbidden in forbidden_canonical_material {
            assert!(
                !block.contains(forbidden),
                "{marker} must not expose canonical export/private key material through `{forbidden}`"
            );
        }
    }

    let durable_object_rs = read_src_file("durable_object.rs");
    for marker in [
        "pub struct CloudflareSigningWorkerOutputActivationReceiptV1",
        "pub struct CloudflareSigningWorkerEcdsaPresignaturePutReceiptV1",
        "pub struct CloudflareSigningWorkerEcdsaPresignaturePoolPutReceiptV1",
    ] {
        let block = extract_braced_block_after_marker(&durable_object_rs, marker);
        for forbidden in [
            "privateKeyHex",
            "private_key_hex",
            "reconstruct_export_key",
            "x_export",
            "canonical_x",
            "server_k_share32_b64u",
            "server_sigma_share32_b64u",
        ] {
            assert!(
                !block.contains(forbidden),
                "{marker} must not expose export keys or presignature scalar shares through `{forbidden}`"
            );
        }
    }
}

fn read_src_file(file_name: &str) -> String {
    let src_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    if file_name == "lib.rs" {
        return read_aggregate_rust_source(&src_dir);
    }
    if file_name == "strict_worker.rs" {
        return read_module_rust_source(&src_dir.join("strict_worker"));
    }
    if file_name == "durable_object.rs" {
        return read_module_rust_source(&src_dir.join("durable_object"));
    }
    let path = src_dir.join(file_name);
    fs::read_to_string(path).expect("source file should read")
}

fn read_aggregate_rust_source(src_dir: &Path) -> String {
    let mut files = Vec::new();
    collect_rust_files(src_dir, &mut files);
    read_joined_sources(files)
}

fn read_module_rust_source(module_dir: &Path) -> String {
    let mut files = Vec::new();
    collect_rust_files(module_dir, &mut files);
    read_joined_sources(files)
}

fn read_joined_sources(mut files: Vec<PathBuf>) -> String {
    files.sort();
    files
        .into_iter()
        .map(|path| {
            let source = fs::read_to_string(&path).expect("source file should read");
            format!("\n// source: {}\n{source}", path.display())
        })
        .collect::<Vec<_>>()
        .join("\n")
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
