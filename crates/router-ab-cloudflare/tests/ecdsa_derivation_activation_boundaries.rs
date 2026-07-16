use std::fs;
use std::path::Path;

mod support;

use support::{
    extract_braced_block_after_marker, extract_function_body, extract_struct_block, read_src_file,
};

#[test]
fn signing_worker_opens_and_verifies_encrypted_proof_bundles_before_registry_bound_combine() {
    let hpke_rs = read_src_file("hpke.rs");
    let body = extract_function_body(
        &hpke_rs,
        "cloudflare_server_output_material_record_from_activation_request_v1",
    );
    let open_a = body
        .find("open_cloudflare_recipient_proof_bundle_hpke_payload_v1")
        .expect("SigningWorker must open Deriver A proof bundle");
    let open_b = body[open_a + 1..]
        .find("open_cloudflare_recipient_proof_bundle_hpke_payload_v1")
        .map(|index| index + open_a + 1)
        .expect("SigningWorker must open Deriver B proof bundle");
    let combine = body
        .find("combine_mpc_prf_signing_worker_output_from_activation_context_v1")
        .expect("SigningWorker must combine verified proof bundles");

    assert!(
        open_a < open_b && open_b < combine,
        "SigningWorker must open and verify both recipient ciphertexts before combining"
    );
    assert!(
        body.contains("commitment_registry"),
        "SigningWorker combine must require the authenticated root-share commitment registry"
    );
}

#[test]
fn router_ab_ecdsa_derivation_export_uses_client_only_deriver_path() {
    let lib_rs = read_src_file("lib.rs");
    let export_body = extract_function_body(
        &lib_rs,
        "handle_cloudflare_router_ab_ecdsa_derivation_explicit_export_authenticated_public_request_v1",
    );
    for required in [
        "execute_cloudflare_router_ab_ecdsa_derivation_deriver_export_service_call_v1",
        "CloudflareRouterAbEcdsaDerivationExportAdmissionResponseV1::forwarded",
    ] {
        assert!(
            export_body.contains(required),
            "Router A/B ECDSA derivation export route must pass through `{required}`"
        );
    }
    for forbidden in [
        "execute_cloudflare_signer_recipient_proof_bundle_service_call_v1",
        "CloudflareSigningWorkerRecipientProofBundleActivationV1",
        "execute_cloudflare_router_ab_ecdsa_derivation_signing_worker_activation_service_call_v1",
        "server_bundle",
        "deriver_b_server_bundle",
    ] {
        assert!(
            !export_body.contains(forbidden),
            "Router A/B ECDSA derivation export route must not produce server output through `{forbidden}`"
        );
    }

    let service_body = extract_function_body(
        &lib_rs,
        "execute_cloudflare_router_ab_ecdsa_derivation_deriver_export_service_call_v1",
    );
    for required in [
        "CloudflareRouterAbEcdsaDerivationDeriverExportPrivateRequestV1",
        "CloudflareSignerClientRecipientProofBundleResponseV1",
        "cloudflare_router_ab_ecdsa_derivation_deriver_export_service_url",
        "validate_cloudflare_signer_client_recipient_proof_bundle_private_response_v1",
    ] {
        assert!(
            service_body.contains(required),
            "Router A/B ECDSA derivation export service call must use `{required}`"
        );
    }
    assert!(
        !service_body.contains("CloudflareSignerRecipientProofBundleResponseV1"),
        "Router A/B ECDSA derivation export service call must not deserialize the activation-capable response"
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
fn router_ab_ecdsa_derivation_registration_uses_protocol_specific_deriver_path() {
    let lib_rs = read_src_file("lib.rs");
    let registration_body = extract_function_body(
        &lib_rs,
        "handle_cloudflare_router_ab_ecdsa_derivation_registration_bootstrap_authenticated_public_request_v1",
    );
    for required in [
        "execute_cloudflare_router_ab_ecdsa_derivation_deriver_registration_service_call_v1",
        "CloudflareSigningWorkerRecipientProofBundleActivationV1::new",
        "execute_cloudflare_router_ab_ecdsa_derivation_signing_worker_activation_service_call_v1",
    ] {
        assert!(
            registration_body.contains(required),
            "Router A/B ECDSA derivation registration route must pass through `{required}`"
        );
    }
    assert!(
        !registration_body
            .contains("execute_cloudflare_signer_recipient_proof_bundle_service_call_v1"),
        "Router A/B ECDSA derivation registration must not use the generic Deriver private service path"
    );

    let service_body = extract_function_body(
        &lib_rs,
        "execute_cloudflare_router_ab_ecdsa_derivation_deriver_registration_service_call_v1",
    );
    for required in [
        "CloudflareRouterAbEcdsaDerivationDeriverRegistrationPrivateRequestV1",
        "CloudflareSignerRecipientProofBundleResponseV1",
        "cloudflare_router_ab_ecdsa_derivation_deriver_registration_service_url",
        "validate_cloudflare_signer_recipient_proof_bundle_private_response_v1",
    ] {
        assert!(
            service_body.contains(required),
            "Router A/B ECDSA derivation registration service call must use `{required}`"
        );
    }
}

#[test]
fn strict_deriver_router_ab_ecdsa_derivation_export_routes_are_protocol_specific() {
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
        "CloudflareRouterAbEcdsaDerivationDeriverRegistrationPrivateRequestV1",
        "decrypt_and_handle_cloudflare_router_ab_ecdsa_derivation_registration_signer_private_request_v1",
        "CloudflareRouterAbEcdsaDerivationDeriverExportPrivateRequestV1",
        "decrypt_and_handle_cloudflare_router_ab_ecdsa_derivation_export_signer_private_request_v1",
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
fn router_ab_ecdsa_derivation_explicit_export_emits_sanitized_audit_event() {
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
        audit_event_block.contains("RouterAbEcdsaDerivationExplicitExportDecision"),
        "core audit events must include the Router A/B ECDSA derivation explicit export decision"
    );

    let handler_body = extract_function_body(
        &lib_rs,
        "handle_cloudflare_router_ab_ecdsa_derivation_explicit_export_authenticated_public_request_v1",
    );
    for required in [
        "emit_cloudflare_router_ab_ecdsa_derivation_explicit_export_audit_event_v1",
        "RouterAbEcdsaDerivationExplicitExportAuditDecisionV1::Rejected",
        "RouterAbEcdsaDerivationExplicitExportAuditDecisionV1::Forwarded",
        "RouterAbEcdsaDerivationExplicitExportAuditDecisionV1::Stopped",
    ] {
        assert!(
            handler_body.contains(required),
            "Router A/B ECDSA derivation explicit export handler must emit `{required}`"
        );
    }

    let audit_body = extract_function_body(
        &lib_rs,
        "emit_cloudflare_router_ab_ecdsa_derivation_explicit_export_audit_event_v1",
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
            "Router A/B ECDSA derivation explicit export audit event must include `{required}`"
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
            "Router A/B ECDSA derivation explicit export audit event must not include `{forbidden}`"
        );
    }
}

#[test]
fn router_ab_ecdsa_derivation_registration_and_export_have_separate_activation_boundaries() {
    let lib_rs = read_src_file("lib.rs");
    let registration_body = extract_function_body(
        &lib_rs,
        "handle_cloudflare_router_ab_ecdsa_derivation_registration_bootstrap_authenticated_public_request_v1",
    );
    let export_body = extract_function_body(
        &lib_rs,
        "handle_cloudflare_router_ab_ecdsa_derivation_explicit_export_authenticated_public_request_v1",
    );
    for required in [
        "CloudflareRouterAbEcdsaDerivationSigningWorkerActivationRequestV1::new",
        "execute_cloudflare_router_ab_ecdsa_derivation_signing_worker_activation_service_call_v1",
        "CloudflareRouterAbEcdsaDerivationRegistrationAdmissionResponseV1::forwarded",
    ] {
        assert!(
            registration_body.contains(required),
            "Router A/B ECDSA derivation registration must activate through `{required}`"
        );
    }
    for forbidden in [
        "CloudflareRouterAbEcdsaDerivationSigningWorkerActivationRequestV1::new",
        "execute_cloudflare_router_ab_ecdsa_derivation_signing_worker_activation_service_call_v1",
        "CloudflareSigningWorkerRecipientProofBundleActivationV1::new",
    ] {
        assert!(
            !export_body.contains(forbidden),
            "Router A/B ECDSA derivation export must not activate SigningWorker material through `{forbidden}`"
        );
    }
    assert!(
        export_body
            .contains("CloudflareRouterAbEcdsaDerivationExportAdmissionResponseV1::forwarded"),
        "Router A/B ECDSA derivation export must return the export-specific response"
    );

    let identity_body = extract_function_body(
        &lib_rs,
        "cloudflare_router_ab_ecdsa_derivation_public_identity_from_activation_material_v1",
    );
    assert!(
        identity_body.contains("derive_relayer_share_for_client_public"),
        "Router A/B ECDSA derivation activation must derive public identity through the Router A/B ECDSA derivation crate"
    );
}

#[test]
fn router_ab_ecdsa_derivation_direct_activation_delivery_excludes_client_and_export_bundles() {
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
        "CloudflareRouterAbEcdsaDerivationDeriverExportPrivateRequestV1",
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
        "cloudflare_router_ab_ecdsa_derivation_deriver_export_service_url",
        "CLOUDFLARE_DERIVER_A_ROUTER_AB_ECDSA_DERIVATION_EXPORT_PRIVATE_REQUEST_PATH",
        "CLOUDFLARE_DERIVER_B_ROUTER_AB_ECDSA_DERIVATION_EXPORT_PRIVATE_REQUEST_PATH",
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
        "CloudflareRouterAbEcdsaDerivationDeriverExportPrivateRequestV1",
    ] {
        assert!(
            !aggregate_impl.contains(forbidden),
            "direct activation aggregate must not carry client/export surface through `{forbidden}`"
        );
    }
}

#[test]
fn router_ab_ecdsa_derivation_strict_derivers_send_direct_activation_only_for_activation_flows() {
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
        "handle_cloudflare_router_ab_ecdsa_derivation_signing_worker_activation_fetch_v1",
    );
    for required in [
        "CloudflareRouterAbEcdsaDerivationSigningWorkerActivationRequestV1",
        "CloudflareSigningWorkerDirectRecipientProofBundleActivationDeliveryV1",
        "activate_cloudflare_signing_worker_direct_recipient_proof_bundle_delivery_v1",
    ] {
        assert!(
            direct_route_body.contains(required),
            "Router A/B ECDSA derivation SigningWorker activation route must accept `{required}`"
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
fn router_ab_ecdsa_derivation_cloudflare_boundaries_do_not_reconstruct_canonical_export_keys() {
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
        "handle_cloudflare_router_ab_ecdsa_derivation_registration_bootstrap_authenticated_public_request_v1",
        "handle_cloudflare_router_ab_ecdsa_derivation_explicit_export_authenticated_public_request_v1",
        "handle_cloudflare_router_ab_ecdsa_derivation_recovery_authenticated_public_request_v1",
        "handle_cloudflare_router_ab_ecdsa_derivation_activation_refresh_authenticated_public_request_v1",
        "handle_cloudflare_router_ab_ecdsa_derivation_evm_digest_signing_prepare_authenticated_public_request_v1",
        "handle_cloudflare_router_ab_ecdsa_derivation_evm_digest_signing_finalize_authenticated_public_request_v1",
        "decrypt_and_handle_cloudflare_router_ab_ecdsa_derivation_registration_signer_private_request_v1",
        "decrypt_and_handle_cloudflare_router_ab_ecdsa_derivation_export_signer_private_request_v1",
        "decrypt_and_handle_cloudflare_router_ab_ecdsa_derivation_recovery_signer_private_request_v1",
        "decrypt_and_handle_cloudflare_router_ab_ecdsa_derivation_activation_refresh_signer_private_request_v1",
        "handle_cloudflare_router_ab_ecdsa_derivation_signing_worker_activation_fetch_v1",
        "handle_cloudflare_router_ab_ecdsa_derivation_signing_worker_activation_refresh_fetch_v1",
        "cloudflare_router_ab_ecdsa_derivation_public_identity_from_activation_material_v1",
        "cloudflare_router_ab_ecdsa_derivation_activation_receipt_from_material_v1",
        "cloudflare_router_ab_ecdsa_derivation_activation_refresh_receipt_from_material_v1",
        "cloudflare_router_ab_ecdsa_derivation_public_identity_from_normal_signing_material_v1",
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
            "strict Router Router A/B ECDSA derivation routing must not expose canonical export/private key material through `{forbidden}`"
        );
    }

    for marker in [
        "pub struct CloudflareRouterAbEcdsaDerivationSigningWorkerActivationReceiptV1",
        "pub enum CloudflareRouterAbEcdsaDerivationRegistrationAdmissionResponseV1",
        "pub enum CloudflareRouterAbEcdsaDerivationExportAdmissionResponseV1",
        "pub enum CloudflareRouterAbEcdsaDerivationRecoveryAdmissionResponseV1",
        "pub enum CloudflareRouterAbEcdsaDerivationActivationRefreshAdmissionResponseV1",
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
