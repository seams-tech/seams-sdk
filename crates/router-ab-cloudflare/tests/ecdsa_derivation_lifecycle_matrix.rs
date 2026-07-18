mod support;

use support::{extract_function_body, read_src_file};

struct LifecycleRouteExpectation {
    name: &'static str,
    handler: &'static str,
    required: &'static [&'static str],
    forbidden: &'static [&'static str],
}

fn assert_lifecycle_route(lib_rs: &str, expectation: &LifecycleRouteExpectation) {
    let body = extract_function_body(lib_rs, expectation.handler);
    for required in expectation.required {
        assert!(
            body.contains(required),
            "{} must route through `{required}`",
            expectation.name,
        );
    }
    for forbidden in expectation.forbidden {
        assert!(
            !body.contains(forbidden),
            "{} must not route through `{forbidden}`",
            expectation.name,
        );
    }
}

#[test]
fn strict_router_ab_ecdsa_derivation_lifecycle_matrix_has_exact_owners() {
    let lib_rs = read_src_file("lib.rs");
    let expectations = [
        LifecycleRouteExpectation {
            name: "registration/bootstrap and add-signer",
            handler:
                "handle_cloudflare_router_ab_ecdsa_derivation_registration_bootstrap_authenticated_public_request_v1",
            required: &[
                "execute_cloudflare_router_ab_ecdsa_derivation_deriver_registration_service_call_v1",
                "CloudflareSigningWorkerRecipientProofBundleActivationV1::new",
                "execute_cloudflare_router_ab_ecdsa_derivation_signing_worker_activation_service_call_v1",
            ],
            forbidden: &[
                "execute_cloudflare_router_ab_ecdsa_derivation_deriver_export_service_call_v1",
                "execute_cloudflare_router_ab_ecdsa_derivation_deriver_recovery_service_call_v1",
                "execute_cloudflare_router_ab_ecdsa_derivation_deriver_activation_refresh_service_call_v1",
            ],
        },
        LifecycleRouteExpectation {
            name: "explicit export",
            handler:
                "handle_cloudflare_router_ab_ecdsa_derivation_explicit_export_authenticated_public_request_v1",
            required: &[
                "execute_cloudflare_router_ab_ecdsa_derivation_deriver_export_service_call_v1",
                "CloudflareRouterAbEcdsaDerivationExportAdmissionResponseV1::forwarded",
            ],
            forbidden: &[
                "execute_cloudflare_router_ab_ecdsa_derivation_signing_worker_activation_service_call_v1",
                "execute_cloudflare_router_ab_ecdsa_derivation_signing_worker_activation_refresh_service_call_v1",
                "execute_cloudflare_signing_worker_router_ab_ecdsa_derivation_evm_digest_prepare_service_call_v1",
            ],
        },
        LifecycleRouteExpectation {
            name: "recovery",
            handler:
                "handle_cloudflare_router_ab_ecdsa_derivation_recovery_authenticated_public_request_v1",
            required: &[
                "execute_cloudflare_router_ab_ecdsa_derivation_deriver_recovery_service_call_v1",
                "CloudflareRouterAbEcdsaDerivationRecoveryAdmissionResponseV1::forwarded",
            ],
            forbidden: &[
                "execute_cloudflare_router_ab_ecdsa_derivation_signing_worker_activation_service_call_v1",
                "execute_cloudflare_router_ab_ecdsa_derivation_signing_worker_activation_refresh_service_call_v1",
                "execute_cloudflare_signing_worker_router_ab_ecdsa_derivation_evm_digest_prepare_service_call_v1",
            ],
        },
        LifecycleRouteExpectation {
            name: "activation refresh",
            handler:
                "handle_cloudflare_router_ab_ecdsa_derivation_activation_refresh_authenticated_public_request_v1",
            required: &[
                "execute_cloudflare_router_ab_ecdsa_derivation_deriver_activation_refresh_service_call_v1",
                "execute_cloudflare_router_ab_ecdsa_derivation_signing_worker_activation_refresh_service_call_v1",
            ],
            forbidden: &[
                "execute_cloudflare_router_ab_ecdsa_derivation_deriver_registration_service_call_v1",
                "execute_cloudflare_router_ab_ecdsa_derivation_deriver_export_service_call_v1",
                "execute_cloudflare_signing_worker_router_ab_ecdsa_derivation_evm_digest_prepare_service_call_v1",
            ],
        },
        LifecycleRouteExpectation {
            name: "ordinary signing prepare",
            handler:
                "handle_cloudflare_router_ab_ecdsa_derivation_evm_digest_signing_prepare_authenticated_public_request_v1",
            required: &[
                "execute_cloudflare_signing_worker_router_ab_ecdsa_derivation_evm_digest_prepare_service_call_v1",
            ],
            forbidden: &[
                "execute_cloudflare_router_ab_ecdsa_derivation_deriver_registration_service_call_v1",
                "execute_cloudflare_router_ab_ecdsa_derivation_deriver_export_service_call_v1",
                "execute_cloudflare_router_ab_ecdsa_derivation_deriver_recovery_service_call_v1",
                "execute_cloudflare_router_ab_ecdsa_derivation_deriver_activation_refresh_service_call_v1",
            ],
        },
        LifecycleRouteExpectation {
            name: "ordinary signing finalize",
            handler:
                "handle_cloudflare_router_ab_ecdsa_derivation_evm_digest_signing_finalize_authenticated_public_request_v1",
            required: &[
                "execute_cloudflare_signing_worker_router_ab_ecdsa_derivation_evm_digest_finalize_service_call_v1",
            ],
            forbidden: &[
                "execute_cloudflare_router_ab_ecdsa_derivation_deriver_registration_service_call_v1",
                "execute_cloudflare_router_ab_ecdsa_derivation_deriver_export_service_call_v1",
                "execute_cloudflare_router_ab_ecdsa_derivation_deriver_recovery_service_call_v1",
                "execute_cloudflare_router_ab_ecdsa_derivation_deriver_activation_refresh_service_call_v1",
            ],
        },
        LifecycleRouteExpectation {
            name: "presignature creation and refill",
            handler:
                "handle_cloudflare_signing_worker_router_ab_ecdsa_derivation_presignature_pool_put_private_fetch_v1",
            required: &[
                "CloudflareSigningWorkerRouterAbEcdsaDerivationPresignaturePoolPutRequestV1",
                "signing_worker_ecdsa_pool_mutate_call",
            ],
            forbidden: &[
                "execute_cloudflare_router_ab_ecdsa_derivation_deriver_registration_service_call_v1",
                "execute_cloudflare_router_ab_ecdsa_derivation_deriver_export_service_call_v1",
                "execute_cloudflare_router_ab_ecdsa_derivation_deriver_recovery_service_call_v1",
                "execute_cloudflare_router_ab_ecdsa_derivation_deriver_activation_refresh_service_call_v1",
            ],
        },
    ];

    for expectation in &expectations {
        assert_lifecycle_route(&lib_rs, expectation);
    }
}

#[test]
fn registration_and_add_signer_paths_select_exact_protocol_purpose() {
    let strict_worker_rs = read_src_file("strict_worker.rs");
    let body = extract_function_body(
        &strict_worker_rs,
        "router_ab_ecdsa_derivation_registration_purpose_for_public_path",
    );
    for required in [
        "CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_REGISTRATION_PUBLIC_REQUEST_PATH",
        "RouterAbEcdsaDerivationRegistrationPurposeV1::WalletRegistration",
        "CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_ADD_SIGNER_PUBLIC_REQUEST_PATH",
        "RouterAbEcdsaDerivationRegistrationPurposeV1::WalletAddSigner",
    ] {
        assert!(
            body.contains(required),
            "registration purpose selection must contain `{required}`",
        );
    }
}
