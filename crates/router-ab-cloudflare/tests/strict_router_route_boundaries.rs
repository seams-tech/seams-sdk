mod support;

use support::{extract_function_body, read_src_file};

#[test]
fn strict_router_exposes_no_generic_split_derivation_route() {
    let strict_worker_rs = read_src_file("strict_worker.rs");
    let body = extract_function_body(&strict_worker_rs, "handle_strict_router_fetch_v1");
    for forbidden in [
        "/router-ab/split-derivation",
        "CLOUDFLARE_ROUTER_SPLIT_DERIVATION_PUBLIC_REQUEST_PATH",
        "json::<PublicRouterRequestV1>",
        "CloudflareStrictRouterBootstrapRequestV1",
        "CloudflareRouterTrustedAdmissionV1",
        "trusted_admission",
        "handle_cloudflare_router_recipient_proof_bundle_public_request_v1",
        "handle_cloudflare_router_recipient_proof_bundle_authenticated_public_request_v1",
    ] {
        assert!(
            !body.contains(forbidden),
            "strict Router must not expose generic split derivation through `{forbidden}`"
        );
    }

    let paths_rs = read_src_file("paths.rs");
    assert!(
        !paths_rs.contains("/router-ab/split-derivation")
            && !paths_rs.contains("CLOUDFLARE_ROUTER_SPLIT_DERIVATION_PUBLIC_REQUEST_PATH"),
        "the removed generic split-derivation route must remain absent from public paths"
    );

    let lib_rs = read_src_file("lib.rs");
    for forbidden in [
        "handle_cloudflare_router_recipient_proof_bundle_public_request_v1",
        "handle_cloudflare_router_recipient_proof_bundle_authenticated_public_request_v1",
        "CloudflareRouterRecipientProofBundleAdmissionResponseV1",
        "execute_cloudflare_signer_recipient_proof_bundle_service_call_v1",
        "execute_cloudflare_signing_worker_recipient_proof_bundle_activation_service_call_v1",
        "cloudflare_signer_service_url",
        "cloudflare_signing_worker_recipient_proof_bundle_activation_service_url",
    ] {
        assert!(
            !lib_rs.contains(forbidden),
            "removed generic split-derivation owner `{forbidden}` must stay absent"
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
fn strict_router_router_ab_ecdsa_derivation_routes_apply_boundary_parsers() {
    let strict_worker_rs = read_src_file("strict_worker.rs");
    let route_body = extract_function_body(&strict_worker_rs, "handle_strict_router_fetch_v1");
    for required in [
        "is_cloudflare_router_ab_ecdsa_derivation_public_path",
        "CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_REGISTRATION_PUBLIC_REQUEST_PATH",
        "CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_ADD_SIGNER_PUBLIC_REQUEST_PATH",
        "CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_EXPORT_PUBLIC_REQUEST_PATH",
        "CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_RECOVERY_PUBLIC_REQUEST_PATH",
        "CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_REFRESH_PUBLIC_REQUEST_PATH",
        "CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_SIGNING_PREPARE_PUBLIC_REQUEST_PATH",
        "CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_SIGNING_PUBLIC_REQUEST_PATH",
        "read_router_public_body_v1",
        "parse_router_public_body_v1",
        "parse_router_ab_ecdsa_derivation_registration_bootstrap_request_v1_json",
        "router_ab_ecdsa_derivation_registration_purpose_for_public_path",
        "validate_for_registration_purpose",
        "parse_cloudflare_router_ab_ecdsa_derivation_export_command_v1_json",
        "parse_router_ab_ecdsa_derivation_recovery_request_v1_json",
        "parse_router_ab_ecdsa_derivation_activation_refresh_request_v1_json",
        "parse_router_ab_ecdsa_derivation_evm_digest_signing_request_v1_json",
        "parse_cloudflare_router_budgeted_router_ab_ecdsa_derivation_finalize_request_v1_json",
        "handle_cloudflare_router_ab_ecdsa_derivation_registration_bootstrap_authenticated_public_request_v1",
        "handle_cloudflare_router_ab_ecdsa_derivation_explicit_export_authenticated_public_request_v1",
        "handle_cloudflare_router_ab_ecdsa_derivation_recovery_authenticated_public_request_v1",
        "handle_cloudflare_router_ab_ecdsa_derivation_activation_refresh_authenticated_public_request_v1",
        "handle_cloudflare_router_ab_ecdsa_derivation_evm_digest_signing_prepare_authenticated_public_request_v1",
        "handle_cloudflare_router_ab_ecdsa_derivation_evm_digest_signing_finalize_authenticated_public_request_v1",
        "cloudflare_router_normal_signing_response_v1",
    ] {
        assert!(
            route_body.contains(required),
            "strict Router Router A/B ECDSA derivation public route must pass through `{required}`"
        );
    }
    let read_body = extract_function_body(&strict_worker_rs, "read_router_public_body_v1");
    assert!(
        read_body.contains("request.bytes().await"),
        "strict Router shared body helper must read raw Worker request bytes"
    );
    for forbidden in [
        "json::<RouterAbEcdsaDerivationRegistrationBootstrapRequestV1>",
        "json::<RouterAbEcdsaDerivationExplicitExportRequestV1>",
        "CloudflareRouterTrustedAdmissionV1",
        "trusted_admission",
        "handle_cloudflare_router_recipient_proof_bundle_public_request_v1",
    ] {
        assert!(
            !route_body.contains(forbidden),
            "strict Router Router A/B ECDSA derivation route must not cross boundary through `{forbidden}`"
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
fn router_ab_ecdsa_derivation_router_prepare_admission_uses_wallet_session_and_replay() {
    let lib_rs = read_src_file("lib.rs");
    for required in [
        "pub client_presignature_id: String",
        "request.client_presignature_id.clone()",
        "self.client_presignature_id != request.client_presignature_id",
    ] {
        assert!(
            lib_rs.contains(required),
            "Router A/B ECDSA derivation Router prepare admission must bind `{required}`"
        );
    }
    let body = extract_function_body(
        &lib_rs,
        "handle_cloudflare_router_ab_ecdsa_derivation_evm_digest_signing_prepare_authenticated_public_request_v1",
    );
    for required in [
        "verify_wallet_session",
        "validate_for_router_ab_ecdsa_derivation_evm_digest_signing_request_v1",
        "CloudflareRouterAbEcdsaDerivationEvmDigestPrepareAdmissionCandidateV1::from_prepare_request",
        "derive_cloudflare_router_ab_ecdsa_derivation_evm_digest_prepare_trusted_admission_from_worker_stores_v1",
        "allows_signing_worker_forwarding",
        "router_ab_ecdsa_derivation_evm_digest_prepare_replay_reserve_call",
        "execute_cloudflare_router_replay_reserve_v1",
        "CloudflareSigningWorkerAdmittedRouterAbEcdsaDerivationEvmDigestSigningRequestV1::new",
        "execute_cloudflare_signing_worker_router_ab_ecdsa_derivation_evm_digest_prepare_service_call_v1",
    ] {
        assert!(
            body.contains(required),
            "Router A/B ECDSA derivation Router prepare admission must include `{required}`"
        );
    }

    let admission = body
        .find("from_prepare_request")
        .expect("Router A/B ECDSA derivation Router prepare must build admission");
    let replay = body
        .find("execute_cloudflare_router_replay_reserve_v1")
        .expect("Router A/B ECDSA derivation Router prepare must reserve replay");
    let forward = body
        .find("execute_cloudflare_signing_worker_router_ab_ecdsa_derivation_evm_digest_prepare_service_call_v1")
        .expect("Router A/B ECDSA derivation Router prepare must forward to SigningWorker");
    assert!(
        admission < replay && replay < forward,
        "Router A/B ECDSA derivation Router prepare must derive admission, reserve replay, then forward"
    );
    for forbidden in [
        "execute_cloudflare_router_ab_ecdsa_derivation_deriver_registration_service_call_v1",
        "execute_cloudflare_router_ab_ecdsa_derivation_deriver_export_service_call_v1",
        "decrypt_and_handle_cloudflare_router_ab_ecdsa_derivation_export_signer_private_request_v1",
        "CloudflareSigningWorkerRecipientProofBundleActivationV1",
    ] {
        assert!(
            !body.contains(forbidden),
            "Router A/B ECDSA derivation Router prepare must not call `{forbidden}`"
        );
    }
}

#[test]
fn router_ab_ecdsa_derivation_router_finalize_admission_uses_wallet_session_and_presignature_take()
{
    let lib_rs = read_src_file("lib.rs");
    let body = extract_function_body(
        &lib_rs,
        "handle_cloudflare_router_ab_ecdsa_derivation_evm_digest_signing_finalize_authenticated_public_request_v1",
    );
    for required in [
        "verify_wallet_session",
        "validate_for_router_ab_ecdsa_derivation_evm_digest_finalize_request_v1",
        "CloudflareRouterAbEcdsaDerivationEvmDigestFinalizeAdmissionCandidateV1::from_finalize_request",
        "derive_cloudflare_router_ab_ecdsa_derivation_evm_digest_finalize_trusted_admission_from_worker_stores_v1",
        "allows_signing_worker_forwarding",
        "CloudflareSigningWorkerAdmittedRouterAbEcdsaDerivationEvmDigestFinalizeRequestV1::new",
        "execute_cloudflare_signing_worker_router_ab_ecdsa_derivation_evm_digest_finalize_service_call_v1",
    ] {
        assert!(
            body.contains(required),
            "Router A/B ECDSA derivation Router finalize admission must include `{required}`"
        );
    }
    assert!(
        !body.contains("execute_cloudflare_router_replay_reserve_v1")
            && !body.contains("router_ab_ecdsa_derivation_evm_digest_prepare_replay_reserve_call"),
        "Router A/B ECDSA derivation Router finalize must rely on SigningWorker one-use presignature take"
    );
    let admission = body
        .find("from_finalize_request")
        .expect("Router A/B ECDSA derivation Router finalize must build admission");
    let forward = body
        .find("execute_cloudflare_signing_worker_router_ab_ecdsa_derivation_evm_digest_finalize_service_call_v1")
        .expect("Router A/B ECDSA derivation Router finalize must forward to SigningWorker");
    assert!(
        admission < forward,
        "Router A/B ECDSA derivation Router finalize must derive admission before forwarding"
    );
    for forbidden in [
        "execute_cloudflare_router_ab_ecdsa_derivation_deriver_registration_service_call_v1",
        "execute_cloudflare_router_ab_ecdsa_derivation_deriver_export_service_call_v1",
        "decrypt_and_handle_cloudflare_router_ab_ecdsa_derivation_export_signer_private_request_v1",
        "CloudflareSigningWorkerRecipientProofBundleActivationV1",
    ] {
        assert!(
            !body.contains(forbidden),
            "Router A/B ECDSA derivation Router finalize must not call `{forbidden}`"
        );
    }
}
