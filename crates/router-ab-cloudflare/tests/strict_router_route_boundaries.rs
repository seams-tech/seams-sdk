mod support;

use support::{extract_function_body, read_src_file};

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
fn strict_router_ecdsa_hss_routes_apply_boundary_parsers() {
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
        "ECDSA-HSS Router finalize must rely on SigningWorker one-use presignature take"
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
