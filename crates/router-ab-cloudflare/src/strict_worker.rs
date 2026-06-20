#![cfg(any(
    feature = "strict-worker-router-entrypoint",
    feature = "strict-worker-signer-a-entrypoint",
    feature = "strict-worker-signer-b-entrypoint",
    feature = "strict-worker-signing-worker-entrypoint"
))]

use crate::cloudflare_router_error_status;
#[cfg(feature = "strict-worker-router-entrypoint")]
use crate::{
    build_cloudflare_router_public_keyset_v2, cloudflare_now_unix_ms_v1,
    cloudflare_router_normal_signing_cors_allowed_origin_v1, cloudflare_trusted_source_digest_v1,
    handle_cloudflare_router_ecdsa_hss_activation_refresh_authenticated_public_request_v1,
    handle_cloudflare_router_ecdsa_hss_evm_digest_signing_finalize_authenticated_public_request_v1,
    handle_cloudflare_router_ecdsa_hss_evm_digest_signing_prepare_authenticated_public_request_v1,
    handle_cloudflare_router_ecdsa_hss_explicit_export_authenticated_public_request_v1,
    handle_cloudflare_router_ecdsa_hss_recovery_authenticated_public_request_v1,
    handle_cloudflare_router_ecdsa_hss_registration_bootstrap_authenticated_public_request_v1,
    handle_cloudflare_router_normal_signing_finalize_authenticated_public_request_v2,
    handle_cloudflare_router_normal_signing_prepare_authenticated_public_request_v2,
    handle_cloudflare_router_normal_signing_presign_pool_hit_finalize_authenticated_public_request_v2,
    handle_cloudflare_router_normal_signing_presign_pool_prepare_authenticated_public_request_v2,
    handle_cloudflare_router_recipient_proof_bundle_authenticated_public_request_v1,
    handle_cloudflare_router_wallet_budget_put_grant_private_fetch_v1,
    handle_cloudflare_router_wallet_budget_status_authenticated_public_request_v1,
    load_cloudflare_router_ed25519_jwks_jwt_verifier_v1,
    parse_cloudflare_router_bearer_authorization_from_request_v1,
    parse_cloudflare_router_budgeted_ecdsa_hss_finalize_request_v1_json,
    parse_cloudflare_router_budgeted_ed25519_finalize_request_v2_json,
    CloudflareRouterWalletSessionCredentialV1, CloudflareRouterWorkerRuntimeV1,
    CloudflareWorkerEnvReaderV1, CLOUDFLARE_ROUTER_ECDSA_HSS_EXPORT_PUBLIC_REQUEST_PATH_V1,
    CLOUDFLARE_ROUTER_ECDSA_HSS_RECOVERY_PUBLIC_REQUEST_PATH_V1,
    CLOUDFLARE_ROUTER_ECDSA_HSS_REFRESH_PUBLIC_REQUEST_PATH_V1,
    CLOUDFLARE_ROUTER_ECDSA_HSS_REGISTRATION_PUBLIC_REQUEST_PATH_V1,
    CLOUDFLARE_ROUTER_ECDSA_HSS_SIGNING_PREPARE_PUBLIC_REQUEST_PATH_V1,
    CLOUDFLARE_ROUTER_ECDSA_HSS_SIGNING_PUBLIC_REQUEST_PATH_V1,
    CLOUDFLARE_ROUTER_NORMAL_SIGNING_PRESIGN_POOL_PREPARE_PUBLIC_REQUEST_PATH_V2,
    CLOUDFLARE_ROUTER_NORMAL_SIGNING_PUBLIC_REQUEST_PATH_V2,
    CLOUDFLARE_ROUTER_NORMAL_SIGNING_ROUND1_PREPARE_PUBLIC_REQUEST_PATH_V2,
    CLOUDFLARE_ROUTER_PUBLIC_KEYSET_PATH_V2, CLOUDFLARE_ROUTER_PUBLIC_KEYSET_WELL_KNOWN_PATH_V2,
    CLOUDFLARE_ROUTER_PUBLIC_REQUEST_PATH_V1,
    CLOUDFLARE_ROUTER_WALLET_BUDGET_PUT_GRANT_PRIVATE_REQUEST_PATH_V1,
    CLOUDFLARE_ROUTER_WALLET_BUDGET_STATUS_PUBLIC_REQUEST_PATH_V1,
};
#[cfg(any(
    feature = "strict-worker-signer-a-entrypoint",
    feature = "strict-worker-signer-b-entrypoint"
))]
use crate::{
    cloudflare_now_unix_ms_v1,
    decrypt_and_handle_cloudflare_ecdsa_hss_activation_refresh_signer_private_request_v1,
    decrypt_and_handle_cloudflare_ecdsa_hss_export_signer_private_request_v1,
    decrypt_and_handle_cloudflare_ecdsa_hss_recovery_signer_private_request_v1,
    decrypt_and_handle_cloudflare_ecdsa_hss_registration_signer_private_request_v1,
    decrypt_and_handle_cloudflare_mpc_prf_recipient_proof_bundle_signer_private_request_v1,
    execute_cloudflare_signing_worker_direct_recipient_proof_bundle_activation_service_call_v1,
    CloudflareEcdsaHssDeriverActivationRefreshPrivateRequestV1,
    CloudflareEcdsaHssDeriverExportPrivateRequestV1,
    CloudflareEcdsaHssDeriverRecoveryPrivateRequestV1,
    CloudflareEcdsaHssDeriverRegistrationPrivateRequestV1, CloudflarePeerBindingV1,
    CloudflarePreloadedSignerHostV1, CloudflareSignerEnvelopeHpkeDecryptKeyBindingSetV1,
    CloudflareSignerHostPreloadInputV1, CloudflareSignerHostPreloadPlanV1,
    CloudflareSignerPeerSigningKeyBindingV1, CloudflareSignerPrivateBootstrapRequestV1,
    CloudflareSignerRecipientProofBundleResponseV1,
    CloudflareSigningWorkerDirectRecipientProofBundleActivationDeliveryV1, CloudflareWorkerRoleV1,
};
#[cfg(feature = "strict-worker-signing-worker-entrypoint")]
use crate::{
    cloudflare_now_unix_ms_v1, handle_cloudflare_ecdsa_hss_signing_worker_activation_fetch_v1,
    handle_cloudflare_ecdsa_hss_signing_worker_activation_refresh_fetch_v1,
    handle_cloudflare_signing_worker_ecdsa_hss_evm_digest_finalize_private_fetch_v1,
    handle_cloudflare_signing_worker_ecdsa_hss_evm_digest_prepare_private_fetch_from_pool_v1,
    handle_cloudflare_signing_worker_ecdsa_hss_presignature_pool_put_private_fetch_v1,
    handle_cloudflare_signing_worker_normal_signing_presign_pool_hit_finalize_private_fetch_v1,
    handle_cloudflare_signing_worker_normal_signing_presign_pool_prepare_private_fetch_v1,
    handle_cloudflare_signing_worker_normal_signing_private_fetch_v1,
    handle_cloudflare_signing_worker_normal_signing_round1_prepare_private_fetch_v1,
    handle_cloudflare_signing_worker_recipient_proof_bundle_activation_fetch_v1,
    CloudflareRoleSeparatedEcdsaHssEvmDigestFinalizeHandlerV1,
    CloudflareRoleSeparatedEd25519NormalSigningHandlerV1, CloudflareSigningWorkerRuntimeV1,
    CLOUDFLARE_SIGNING_WORKER_ECDSA_HSS_ACTIVATION_PATH_V1,
    CLOUDFLARE_SIGNING_WORKER_ECDSA_HSS_PRESIGNATURE_POOL_PUT_PATH_V1,
    CLOUDFLARE_SIGNING_WORKER_ECDSA_HSS_REFRESH_PATH_V1,
    CLOUDFLARE_SIGNING_WORKER_ECDSA_HSS_SIGNING_PATH_V1,
    CLOUDFLARE_SIGNING_WORKER_ECDSA_HSS_SIGNING_PREPARE_PATH_V1,
    CLOUDFLARE_SIGNING_WORKER_NORMAL_SIGNING_PATH_V1,
    CLOUDFLARE_SIGNING_WORKER_NORMAL_SIGNING_PRESIGN_POOL_PATH_V1,
    CLOUDFLARE_SIGNING_WORKER_NORMAL_SIGNING_PRESIGN_POOL_PREPARE_PATH_V1,
    CLOUDFLARE_SIGNING_WORKER_NORMAL_SIGNING_ROUND1_PREPARE_PATH_V1,
    CLOUDFLARE_SIGNING_WORKER_PROOF_BUNDLE_ACTIVATION_PATH_V1,
};
#[cfg(any(
    feature = "strict-worker-router-entrypoint",
    feature = "strict-worker-signer-a-entrypoint",
    feature = "strict-worker-signer-b-entrypoint",
    feature = "strict-worker-signing-worker-entrypoint"
))]
use crate::{
    cloudflare_private_service_auth_error_response_v1,
    require_cloudflare_internal_service_auth_request_v1,
};
#[cfg(feature = "strict-worker-signer-a-entrypoint")]
use crate::{
    preload_cloudflare_deriver_a_host_v1, CloudflareDeriverAWorkerRuntimeV1,
    CLOUDFLARE_SIGNER_A_ECDSA_HSS_EXPORT_PRIVATE_REQUEST_PATH_V1,
    CLOUDFLARE_SIGNER_A_ECDSA_HSS_RECOVERY_PRIVATE_REQUEST_PATH_V1,
    CLOUDFLARE_SIGNER_A_ECDSA_HSS_REFRESH_PRIVATE_REQUEST_PATH_V1,
    CLOUDFLARE_SIGNER_A_ECDSA_HSS_REGISTRATION_PRIVATE_REQUEST_PATH_V1,
    CLOUDFLARE_SIGNER_A_PRIVATE_REQUEST_PATH_V1,
};
#[cfg(feature = "strict-worker-signer-b-entrypoint")]
use crate::{
    preload_cloudflare_deriver_b_host_v1, CloudflareDeriverBWorkerRuntimeV1,
    CLOUDFLARE_SIGNER_B_ECDSA_HSS_EXPORT_PRIVATE_REQUEST_PATH_V1,
    CLOUDFLARE_SIGNER_B_ECDSA_HSS_RECOVERY_PRIVATE_REQUEST_PATH_V1,
    CLOUDFLARE_SIGNER_B_ECDSA_HSS_REFRESH_PRIVATE_REQUEST_PATH_V1,
    CLOUDFLARE_SIGNER_B_ECDSA_HSS_REGISTRATION_PRIVATE_REQUEST_PATH_V1,
    CLOUDFLARE_SIGNER_B_PRIVATE_REQUEST_PATH_V1,
};
use router_ab_core::RouterAbProtocolError;
#[cfg(any(
    feature = "strict-worker-signer-a-entrypoint",
    feature = "strict-worker-signer-b-entrypoint"
))]
use router_ab_core::{
    decode_router_to_signer_payload_v1, AbPeerMessageVerifyingKeyV1, Role, RouterAbProtocolResult,
    SignerSetV1, SigningWorkerActivationContextV1,
};
#[cfg(feature = "strict-worker-router-entrypoint")]
use router_ab_core::{
    parse_router_ab_ecdsa_hss_activation_refresh_request_v1_json,
    parse_router_ab_ecdsa_hss_evm_digest_signing_request_v1_json,
    parse_router_ab_ecdsa_hss_explicit_export_request_v1_json,
    parse_router_ab_ecdsa_hss_recovery_request_v1_json,
    parse_router_ab_ecdsa_hss_registration_bootstrap_request_v1_json,
    parse_router_ab_ed25519_normal_signing_prepare_request_v2_json,
    parse_router_ab_ed25519_presign_pool_hit_finalize_request_v2_json,
    parse_router_ab_ed25519_presign_pool_prepare_request_v2_json, PublicRouterRequestV1,
};
#[cfg(feature = "strict-worker-router-entrypoint")]
use worker::Method;
use worker::{Context, Env, Request, Response};

#[cfg(feature = "strict-worker-router-entrypoint")]
/// Optional comma-separated Origin allowlist for the public Router/A/B keyset route.
pub const ROUTER_AB_PUBLIC_KEYSET_CORS_ORIGINS_ENV: &str = "ROUTER_AB_PUBLIC_KEYSET_CORS_ORIGINS";
#[cfg(feature = "strict-worker-router-entrypoint")]
/// Required comma-separated Origin allowlist for public normal-signing routes.
pub const ROUTER_AB_NORMAL_SIGNING_CORS_ORIGINS_ENV: &str = "ROUTER_AB_NORMAL_SIGNING_CORS_ORIGINS";
#[cfg(feature = "strict-worker-router-entrypoint")]
const ROUTER_AB_PUBLIC_KEYSET_CACHE_CONTROL_V1: &str = "max-age=60, stale-while-revalidate=600";
#[cfg(feature = "strict-worker-router-entrypoint")]
const ROUTER_AB_PUBLIC_KEYSET_CORS_ALLOW_METHODS_V1: &str = "GET,OPTIONS";
#[cfg(feature = "strict-worker-router-entrypoint")]
const ROUTER_AB_PUBLIC_KEYSET_CORS_ALLOW_HEADERS_V1: &str = "Accept,Content-Type,Authorization";
#[cfg(feature = "strict-worker-router-entrypoint")]
const ROUTER_AB_NORMAL_SIGNING_CORS_ALLOW_METHODS_V1: &str = "POST,OPTIONS";
#[cfg(feature = "strict-worker-router-entrypoint")]
const ROUTER_AB_NORMAL_SIGNING_CORS_ALLOW_HEADERS_V1: &str = "Accept,Content-Type,Authorization";

/// Deployable workers-rs fetch entrypoint for strict Router/A/B proof-bundle Workers.
#[worker::event(fetch)]
pub async fn fetch(request: Request, env: Env, _ctx: Context) -> worker::Result<Response> {
    #[cfg(feature = "strict-worker-router-entrypoint")]
    {
        return handle_strict_router_fetch_v1(request, env).await;
    }
    #[cfg(feature = "strict-worker-signer-a-entrypoint")]
    {
        return handle_strict_deriver_a_fetch_v1(request, env).await;
    }
    #[cfg(feature = "strict-worker-signer-b-entrypoint")]
    {
        return handle_strict_deriver_b_fetch_v1(request, env).await;
    }
    #[cfg(feature = "strict-worker-signing-worker-entrypoint")]
    {
        return handle_strict_signing_worker_fetch_v1(request, env).await;
    }
}

#[cfg(feature = "strict-worker-router-entrypoint")]
async fn handle_strict_router_fetch_v1(mut request: Request, env: Env) -> worker::Result<Response> {
    let path = request.path();
    if is_cloudflare_router_public_keyset_path_v2(&path) {
        if request.method() == Method::Options {
            return cloudflare_router_public_keyset_preflight_response_v1(&request, &env);
        }
        if request.method() != Method::Get {
            let response = Response::error("Router A/B public keyset route requires GET", 405)?;
            return cloudflare_router_public_keyset_response_v1(response, &request, &env);
        }
        let reader = CloudflareWorkerEnvReaderV1::new(&env);
        let response = match build_cloudflare_router_public_keyset_v2(&reader) {
            Ok(keyset) => Response::from_json(&keyset)?,
            Err(err) => cloudflare_protocol_error_response_v1(err)?,
        };
        return cloudflare_router_public_keyset_response_v1(response, &request, &env);
    }

    if path == CLOUDFLARE_ROUTER_WALLET_BUDGET_PUT_GRANT_PRIVATE_REQUEST_PATH_V1 {
        if let Err(err) = require_cloudflare_internal_service_auth_request_v1(&request, &env) {
            return cloudflare_private_service_auth_error_response_v1(err);
        }
        let runtime = match CloudflareRouterWorkerRuntimeV1::from_worker_env(&env) {
            Ok(runtime) => runtime,
            Err(err) => return cloudflare_protocol_error_response_v1(err),
        };
        let now_unix_ms = match cloudflare_now_unix_ms_v1() {
            Ok(now_unix_ms) => now_unix_ms,
            Err(err) => return cloudflare_protocol_error_response_v1(err),
        };
        return handle_cloudflare_router_wallet_budget_put_grant_private_fetch_v1(
            request,
            &env,
            &runtime,
            now_unix_ms,
        )
        .await;
    }

    if request.method() == Method::Options
        && (is_cloudflare_router_normal_signing_public_path_v2(&path)
            || is_cloudflare_router_ecdsa_hss_public_path_v1(&path))
    {
        return cloudflare_router_normal_signing_preflight_response_v1(&request, &env);
    }

    if request.method() != Method::Post {
        return Response::error("Router A/B strict public route requires POST", 405);
    }
    if path != CLOUDFLARE_ROUTER_PUBLIC_REQUEST_PATH_V1
        && path != CLOUDFLARE_ROUTER_NORMAL_SIGNING_ROUND1_PREPARE_PUBLIC_REQUEST_PATH_V2
        && path != CLOUDFLARE_ROUTER_NORMAL_SIGNING_PRESIGN_POOL_PREPARE_PUBLIC_REQUEST_PATH_V2
        && path != CLOUDFLARE_ROUTER_NORMAL_SIGNING_PUBLIC_REQUEST_PATH_V2
        && path != CLOUDFLARE_ROUTER_ECDSA_HSS_REGISTRATION_PUBLIC_REQUEST_PATH_V1
        && path != CLOUDFLARE_ROUTER_ECDSA_HSS_EXPORT_PUBLIC_REQUEST_PATH_V1
        && path != CLOUDFLARE_ROUTER_ECDSA_HSS_RECOVERY_PUBLIC_REQUEST_PATH_V1
        && path != CLOUDFLARE_ROUTER_ECDSA_HSS_REFRESH_PUBLIC_REQUEST_PATH_V1
        && path != CLOUDFLARE_ROUTER_ECDSA_HSS_SIGNING_PREPARE_PUBLIC_REQUEST_PATH_V1
        && path != CLOUDFLARE_ROUTER_ECDSA_HSS_SIGNING_PUBLIC_REQUEST_PATH_V1
        && path != CLOUDFLARE_ROUTER_WALLET_BUDGET_STATUS_PUBLIC_REQUEST_PATH_V1
    {
        return Response::error(
            format!(
                "Router A/B strict public request must be served at {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, or {}",
                CLOUDFLARE_ROUTER_PUBLIC_REQUEST_PATH_V1,
                CLOUDFLARE_ROUTER_NORMAL_SIGNING_ROUND1_PREPARE_PUBLIC_REQUEST_PATH_V2,
                CLOUDFLARE_ROUTER_NORMAL_SIGNING_PRESIGN_POOL_PREPARE_PUBLIC_REQUEST_PATH_V2,
                CLOUDFLARE_ROUTER_NORMAL_SIGNING_PUBLIC_REQUEST_PATH_V2,
                CLOUDFLARE_ROUTER_ECDSA_HSS_REGISTRATION_PUBLIC_REQUEST_PATH_V1,
                CLOUDFLARE_ROUTER_ECDSA_HSS_EXPORT_PUBLIC_REQUEST_PATH_V1,
                CLOUDFLARE_ROUTER_ECDSA_HSS_RECOVERY_PUBLIC_REQUEST_PATH_V1,
                CLOUDFLARE_ROUTER_ECDSA_HSS_REFRESH_PUBLIC_REQUEST_PATH_V1,
                CLOUDFLARE_ROUTER_ECDSA_HSS_SIGNING_PREPARE_PUBLIC_REQUEST_PATH_V1,
                CLOUDFLARE_ROUTER_ECDSA_HSS_SIGNING_PUBLIC_REQUEST_PATH_V1,
                CLOUDFLARE_ROUTER_WALLET_BUDGET_STATUS_PUBLIC_REQUEST_PATH_V1
            ),
            404,
        );
    }
    let authorization = match parse_cloudflare_router_bearer_authorization_from_request_v1(&request)
    {
        Ok(authorization) => authorization,
        Err(err) => return cloudflare_protocol_error_response_v1(err),
    };
    let trusted_source_digest = match cloudflare_trusted_source_digest_v1(&request) {
        Ok(digest) => digest,
        Err(err) => return cloudflare_protocol_error_response_v1(err),
    };
    let runtime = match CloudflareRouterWorkerRuntimeV1::from_worker_env(&env) {
        Ok(runtime) => runtime,
        Err(err) => return cloudflare_protocol_error_response_v1(err),
    };
    let now_unix_ms = match cloudflare_now_unix_ms_v1() {
        Ok(now_unix_ms) => now_unix_ms,
        Err(err) => return cloudflare_protocol_error_response_v1(err),
    };
    let verifier = match load_cloudflare_router_ed25519_jwks_jwt_verifier_v1(
        &runtime.admission_bindings().jwt,
    )
    .await
    {
        Ok(verifier) => verifier,
        Err(err) => return cloudflare_protocol_error_response_v1(err),
    };

    if path == CLOUDFLARE_ROUTER_WALLET_BUDGET_STATUS_PUBLIC_REQUEST_PATH_V1 {
        let credential = match CloudflareRouterWalletSessionCredentialV1::bearer(authorization) {
            Ok(credential) => credential,
            Err(err) => {
                let response = cloudflare_protocol_error_response_v1(err)?;
                return cloudflare_router_normal_signing_response_v1(response, &request, &env);
            }
        };
        let response =
            handle_cloudflare_router_wallet_budget_status_authenticated_public_request_v1(
                &mut request,
                &env,
                &runtime,
                now_unix_ms,
                credential,
                trusted_source_digest,
                verifier,
            )
            .await?;
        return cloudflare_router_normal_signing_response_v1(response, &request, &env);
    }

    if path == CLOUDFLARE_ROUTER_NORMAL_SIGNING_ROUND1_PREPARE_PUBLIC_REQUEST_PATH_V2 {
        let request_body = match request.bytes().await {
            Ok(bytes) => bytes,
            Err(err) => {
                let response = Response::error(
                    format!("Router A/B strict normal-signing v2 prepare body read failed: {err}"),
                    400,
                )?;
                return cloudflare_router_normal_signing_response_v1(response, &request, &env);
            }
        };
        let prepare_request =
            match parse_router_ab_ed25519_normal_signing_prepare_request_v2_json(&request_body) {
                Ok(parsed) => parsed,
                Err(err) => {
                    let response = cloudflare_protocol_error_response_v1(err)?;
                    return cloudflare_router_normal_signing_response_v1(response, &request, &env);
                }
            };
        let credential = match CloudflareRouterWalletSessionCredentialV1::bearer(authorization) {
            Ok(credential) => credential,
            Err(err) => {
                let response = cloudflare_protocol_error_response_v1(err)?;
                return cloudflare_router_normal_signing_response_v1(response, &request, &env);
            }
        };
        return match handle_cloudflare_router_normal_signing_prepare_authenticated_public_request_v2(
            &env,
            &runtime,
            now_unix_ms,
            prepare_request,
            credential,
            trusted_source_digest,
            verifier,
        )
        .await
        {
            Ok(response) => {
                let response = Response::from_json(&response)?;
                cloudflare_router_normal_signing_response_v1(response, &request, &env)
            }
            Err(err) => {
                let response = cloudflare_protocol_error_response_v1(err)?;
                cloudflare_router_normal_signing_response_v1(response, &request, &env)
            }
        };
    }

    if path == CLOUDFLARE_ROUTER_NORMAL_SIGNING_PRESIGN_POOL_PREPARE_PUBLIC_REQUEST_PATH_V2 {
        let request_body = match request.bytes().await {
            Ok(bytes) => bytes,
            Err(err) => {
                let response = Response::error(
                    format!(
                        "Router A/B strict normal-signing v2 presign-pool prepare body read failed: {err}"
                    ),
                    400,
                )?;
                return cloudflare_router_normal_signing_response_v1(response, &request, &env);
            }
        };
        let prepare_request =
            match parse_router_ab_ed25519_presign_pool_prepare_request_v2_json(&request_body) {
                Ok(parsed) => parsed,
                Err(err) => {
                    let response = cloudflare_protocol_error_response_v1(err)?;
                    return cloudflare_router_normal_signing_response_v1(response, &request, &env);
                }
            };
        let credential = match CloudflareRouterWalletSessionCredentialV1::bearer(authorization) {
            Ok(credential) => credential,
            Err(err) => {
                let response = cloudflare_protocol_error_response_v1(err)?;
                return cloudflare_router_normal_signing_response_v1(response, &request, &env);
            }
        };
        return match handle_cloudflare_router_normal_signing_presign_pool_prepare_authenticated_public_request_v2(
            &env,
            &runtime,
            now_unix_ms,
            prepare_request,
            credential,
            trusted_source_digest,
            verifier,
        )
        .await
        {
            Ok(response) => {
                let response = Response::from_json(&response)?;
                cloudflare_router_normal_signing_response_v1(response, &request, &env)
            }
            Err(err) => {
                let response = cloudflare_protocol_error_response_v1(err)?;
                cloudflare_router_normal_signing_response_v1(response, &request, &env)
            }
        };
    }

    if path == CLOUDFLARE_ROUTER_NORMAL_SIGNING_PUBLIC_REQUEST_PATH_V2 {
        let request_body = match request.bytes().await {
            Ok(bytes) => bytes,
            Err(err) => {
                let response = Response::error(
                    format!("Router A/B strict normal-signing finalize body read failed: {err}"),
                    400,
                )?;
                return cloudflare_router_normal_signing_response_v1(response, &request, &env);
            }
        };
        match parse_cloudflare_router_budgeted_ed25519_finalize_request_v2_json(&request_body) {
            Ok((finalize_request, budget_metadata)) => {
                let credential =
                    match CloudflareRouterWalletSessionCredentialV1::bearer(authorization) {
                        Ok(credential) => credential,
                        Err(err) => {
                            let response = cloudflare_protocol_error_response_v1(err)?;
                            return cloudflare_router_normal_signing_response_v1(
                                response, &request, &env,
                            );
                        }
                    };
                return match handle_cloudflare_router_normal_signing_finalize_authenticated_public_request_v2(
                    &env,
                    &runtime,
                    now_unix_ms,
                    finalize_request,
                    budget_metadata,
                    credential,
                    trusted_source_digest,
                    verifier,
                )
                .await
                {
                    Ok(response) => {
                        let response = Response::from_json(&response)?;
                        cloudflare_router_normal_signing_response_v1(response, &request, &env)
                    }
                    Err(err) => {
                        let response = cloudflare_protocol_error_response_v1(err)?;
                        cloudflare_router_normal_signing_response_v1(response, &request, &env)
                    }
                };
            }
            Err(finalize_err) => {
                let pool_hit_request =
                    match parse_router_ab_ed25519_presign_pool_hit_finalize_request_v2_json(
                        &request_body,
                    ) {
                        Ok(parsed) => parsed,
                        Err(_) => {
                            let response = cloudflare_protocol_error_response_v1(finalize_err)?;
                            return cloudflare_router_normal_signing_response_v1(
                                response, &request, &env,
                            );
                        }
                    };
                let credential =
                    match CloudflareRouterWalletSessionCredentialV1::bearer(authorization) {
                        Ok(credential) => credential,
                        Err(err) => {
                            let response = cloudflare_protocol_error_response_v1(err)?;
                            return cloudflare_router_normal_signing_response_v1(
                                response, &request, &env,
                            );
                        }
                    };
                return match handle_cloudflare_router_normal_signing_presign_pool_hit_finalize_authenticated_public_request_v2(
                    &env,
                    &runtime,
                    now_unix_ms,
                    pool_hit_request,
                    credential,
                    trusted_source_digest,
                    verifier,
                )
                .await
                {
                    Ok(response) => {
                        let response = Response::from_json(&response)?;
                        cloudflare_router_normal_signing_response_v1(response, &request, &env)
                    }
                    Err(err) => {
                        let response = cloudflare_protocol_error_response_v1(err)?;
                        cloudflare_router_normal_signing_response_v1(response, &request, &env)
                    }
                };
            }
        }
    }

    if path == CLOUDFLARE_ROUTER_ECDSA_HSS_REGISTRATION_PUBLIC_REQUEST_PATH_V1 {
        let request_body = match request.bytes().await {
            Ok(bytes) => bytes,
            Err(err) => {
                let response = Response::error(
                    format!("Router A/B strict ECDSA-HSS registration body read failed: {err}"),
                    400,
                )?;
                return cloudflare_router_normal_signing_response_v1(response, &request, &env);
            }
        };
        let registration_request =
            match parse_router_ab_ecdsa_hss_registration_bootstrap_request_v1_json(&request_body) {
                Ok(parsed) => parsed,
                Err(err) => {
                    let response = cloudflare_protocol_error_response_v1(err)?;
                    return cloudflare_router_normal_signing_response_v1(response, &request, &env);
                }
            };
        return match handle_cloudflare_router_ecdsa_hss_registration_bootstrap_authenticated_public_request_v1(
            &env,
            &runtime,
            now_unix_ms,
            registration_request,
            authorization,
            trusted_source_digest,
            verifier,
        )
        .await
        {
            Ok(response) => {
                let response = Response::from_json(&response)?;
                cloudflare_router_normal_signing_response_v1(response, &request, &env)
            }
            Err(err) => {
                let response = cloudflare_protocol_error_response_v1(err)?;
                cloudflare_router_normal_signing_response_v1(response, &request, &env)
            }
        };
    }

    if path == CLOUDFLARE_ROUTER_ECDSA_HSS_EXPORT_PUBLIC_REQUEST_PATH_V1 {
        let request_body = match request.bytes().await {
            Ok(bytes) => bytes,
            Err(err) => {
                let response = Response::error(
                    format!("Router A/B strict ECDSA-HSS export body read failed: {err}"),
                    400,
                )?;
                return cloudflare_router_normal_signing_response_v1(response, &request, &env);
            }
        };
        let export_request =
            match parse_router_ab_ecdsa_hss_explicit_export_request_v1_json(&request_body) {
                Ok(parsed) => parsed,
                Err(err) => {
                    let response = cloudflare_protocol_error_response_v1(err)?;
                    return cloudflare_router_normal_signing_response_v1(response, &request, &env);
                }
            };
        return match handle_cloudflare_router_ecdsa_hss_explicit_export_authenticated_public_request_v1(
            &env,
            &runtime,
            now_unix_ms,
            export_request,
            authorization,
            trusted_source_digest,
            verifier,
        )
        .await
        {
            Ok(response) => {
                let response = Response::from_json(&response)?;
                cloudflare_router_normal_signing_response_v1(response, &request, &env)
            }
            Err(err) => {
                let response = cloudflare_protocol_error_response_v1(err)?;
                cloudflare_router_normal_signing_response_v1(response, &request, &env)
            }
        };
    }

    if path == CLOUDFLARE_ROUTER_ECDSA_HSS_RECOVERY_PUBLIC_REQUEST_PATH_V1 {
        let request_body = match request.bytes().await {
            Ok(bytes) => bytes,
            Err(err) => {
                let response = Response::error(
                    format!("Router A/B strict ECDSA-HSS recovery body read failed: {err}"),
                    400,
                )?;
                return cloudflare_router_normal_signing_response_v1(response, &request, &env);
            }
        };
        let recovery_request =
            match parse_router_ab_ecdsa_hss_recovery_request_v1_json(&request_body) {
                Ok(parsed) => parsed,
                Err(err) => {
                    let response = cloudflare_protocol_error_response_v1(err)?;
                    return cloudflare_router_normal_signing_response_v1(response, &request, &env);
                }
            };
        return match handle_cloudflare_router_ecdsa_hss_recovery_authenticated_public_request_v1(
            &env,
            &runtime,
            now_unix_ms,
            recovery_request,
            authorization,
            trusted_source_digest,
            verifier,
        )
        .await
        {
            Ok(response) => {
                let response = Response::from_json(&response)?;
                cloudflare_router_normal_signing_response_v1(response, &request, &env)
            }
            Err(err) => {
                let response = cloudflare_protocol_error_response_v1(err)?;
                cloudflare_router_normal_signing_response_v1(response, &request, &env)
            }
        };
    }

    if path == CLOUDFLARE_ROUTER_ECDSA_HSS_REFRESH_PUBLIC_REQUEST_PATH_V1 {
        let request_body = match request.bytes().await {
            Ok(bytes) => bytes,
            Err(err) => {
                let response = Response::error(
                    format!(
                        "Router A/B strict ECDSA-HSS activation-refresh body read failed: {err}"
                    ),
                    400,
                )?;
                return cloudflare_router_normal_signing_response_v1(response, &request, &env);
            }
        };
        let refresh_request =
            match parse_router_ab_ecdsa_hss_activation_refresh_request_v1_json(&request_body) {
                Ok(parsed) => parsed,
                Err(err) => {
                    let response = cloudflare_protocol_error_response_v1(err)?;
                    return cloudflare_router_normal_signing_response_v1(response, &request, &env);
                }
            };
        return match handle_cloudflare_router_ecdsa_hss_activation_refresh_authenticated_public_request_v1(
            &env,
            &runtime,
            now_unix_ms,
            refresh_request,
            authorization,
            trusted_source_digest,
            verifier,
        )
        .await
        {
            Ok(response) => {
                let response = Response::from_json(&response)?;
                cloudflare_router_normal_signing_response_v1(response, &request, &env)
            }
            Err(err) => {
                let response = cloudflare_protocol_error_response_v1(err)?;
                cloudflare_router_normal_signing_response_v1(response, &request, &env)
            }
        };
    }

    if path == CLOUDFLARE_ROUTER_ECDSA_HSS_SIGNING_PREPARE_PUBLIC_REQUEST_PATH_V1 {
        let request_body = match request.bytes().await {
            Ok(bytes) => bytes,
            Err(err) => {
                let response = Response::error(
                    format!("Router A/B strict ECDSA-HSS prepare body read failed: {err}"),
                    400,
                )?;
                return cloudflare_router_normal_signing_response_v1(response, &request, &env);
            }
        };
        let prepare_request =
            match parse_router_ab_ecdsa_hss_evm_digest_signing_request_v1_json(&request_body) {
                Ok(parsed) => parsed,
                Err(err) => {
                    let response = cloudflare_protocol_error_response_v1(err)?;
                    return cloudflare_router_normal_signing_response_v1(response, &request, &env);
                }
            };
        let credential = match CloudflareRouterWalletSessionCredentialV1::bearer(authorization) {
            Ok(credential) => credential,
            Err(err) => {
                let response = cloudflare_protocol_error_response_v1(err)?;
                return cloudflare_router_normal_signing_response_v1(response, &request, &env);
            }
        };
        return match handle_cloudflare_router_ecdsa_hss_evm_digest_signing_prepare_authenticated_public_request_v1(
            &env,
            &runtime,
            now_unix_ms,
            prepare_request,
            credential,
            trusted_source_digest,
            verifier,
        )
        .await
        {
            Ok(response) => {
                let response = Response::from_json(&response)?;
                cloudflare_router_normal_signing_response_v1(response, &request, &env)
            }
            Err(err) => {
                let response = cloudflare_protocol_error_response_v1(err)?;
                cloudflare_router_normal_signing_response_v1(response, &request, &env)
            }
        };
    }

    if path == CLOUDFLARE_ROUTER_ECDSA_HSS_SIGNING_PUBLIC_REQUEST_PATH_V1 {
        let request_body = match request.bytes().await {
            Ok(bytes) => bytes,
            Err(err) => {
                let response = Response::error(
                    format!("Router A/B strict ECDSA-HSS finalize body read failed: {err}"),
                    400,
                )?;
                return cloudflare_router_normal_signing_response_v1(response, &request, &env);
            }
        };
        let (finalize_request, budget_metadata) =
            match parse_cloudflare_router_budgeted_ecdsa_hss_finalize_request_v1_json(&request_body)
            {
                Ok(parsed) => parsed,
                Err(err) => {
                    let response = cloudflare_protocol_error_response_v1(err)?;
                    return cloudflare_router_normal_signing_response_v1(response, &request, &env);
                }
            };
        let credential = match CloudflareRouterWalletSessionCredentialV1::bearer(authorization) {
            Ok(credential) => credential,
            Err(err) => {
                let response = cloudflare_protocol_error_response_v1(err)?;
                return cloudflare_router_normal_signing_response_v1(response, &request, &env);
            }
        };
        return match handle_cloudflare_router_ecdsa_hss_evm_digest_signing_finalize_authenticated_public_request_v1(
            &env,
            &runtime,
            now_unix_ms,
            finalize_request,
            budget_metadata,
            credential,
            trusted_source_digest,
            verifier,
        )
        .await
        {
            Ok(response) => {
                let response = Response::from_json(&response)?;
                cloudflare_router_normal_signing_response_v1(response, &request, &env)
            }
            Err(err) => {
                let response = cloudflare_protocol_error_response_v1(err)?;
                cloudflare_router_normal_signing_response_v1(response, &request, &env)
            }
        };
    }

    let public_request = match request.json::<PublicRouterRequestV1>().await {
        Ok(parsed) => parsed,
        Err(err) => {
            return Response::error(
                format!("Router A/B strict public request JSON parse failed: {err}"),
                400,
            );
        }
    };
    match handle_cloudflare_router_recipient_proof_bundle_authenticated_public_request_v1(
        &env,
        &runtime,
        now_unix_ms,
        public_request,
        authorization,
        trusted_source_digest,
        verifier,
    )
    .await
    {
        Ok(response) => Response::from_json(&response),
        Err(err) => cloudflare_protocol_error_response_v1(err),
    }
}

#[cfg(feature = "strict-worker-router-entrypoint")]
fn is_cloudflare_router_public_keyset_path_v2(path: &str) -> bool {
    let normalized = path.strip_suffix('/').unwrap_or(path);
    normalized == CLOUDFLARE_ROUTER_PUBLIC_KEYSET_WELL_KNOWN_PATH_V2
        || normalized == CLOUDFLARE_ROUTER_PUBLIC_KEYSET_PATH_V2
}

#[cfg(feature = "strict-worker-router-entrypoint")]
fn is_cloudflare_router_normal_signing_public_path_v2(path: &str) -> bool {
    let normalized = path.strip_suffix('/').unwrap_or(path);
    normalized == CLOUDFLARE_ROUTER_NORMAL_SIGNING_ROUND1_PREPARE_PUBLIC_REQUEST_PATH_V2
        || normalized
            == CLOUDFLARE_ROUTER_NORMAL_SIGNING_PRESIGN_POOL_PREPARE_PUBLIC_REQUEST_PATH_V2
        || normalized == CLOUDFLARE_ROUTER_NORMAL_SIGNING_PUBLIC_REQUEST_PATH_V2
        || normalized == CLOUDFLARE_ROUTER_WALLET_BUDGET_STATUS_PUBLIC_REQUEST_PATH_V1
}

#[cfg(feature = "strict-worker-router-entrypoint")]
fn is_cloudflare_router_ecdsa_hss_public_path_v1(path: &str) -> bool {
    let normalized = path.strip_suffix('/').unwrap_or(path);
    normalized == CLOUDFLARE_ROUTER_ECDSA_HSS_REGISTRATION_PUBLIC_REQUEST_PATH_V1
        || normalized == CLOUDFLARE_ROUTER_ECDSA_HSS_EXPORT_PUBLIC_REQUEST_PATH_V1
        || normalized == CLOUDFLARE_ROUTER_ECDSA_HSS_RECOVERY_PUBLIC_REQUEST_PATH_V1
        || normalized == CLOUDFLARE_ROUTER_ECDSA_HSS_REFRESH_PUBLIC_REQUEST_PATH_V1
        || normalized == CLOUDFLARE_ROUTER_ECDSA_HSS_SIGNING_PREPARE_PUBLIC_REQUEST_PATH_V1
        || normalized == CLOUDFLARE_ROUTER_ECDSA_HSS_SIGNING_PUBLIC_REQUEST_PATH_V1
}

#[cfg(feature = "strict-worker-router-entrypoint")]
fn cloudflare_router_public_keyset_preflight_response_v1(
    request: &Request,
    env: &Env,
) -> worker::Result<Response> {
    let response = Response::empty()?.with_status(204);
    cloudflare_router_public_keyset_response_v1(response, request, env)
}

#[cfg(feature = "strict-worker-router-entrypoint")]
fn cloudflare_router_public_keyset_response_v1(
    mut response: Response,
    request: &Request,
    env: &Env,
) -> worker::Result<Response> {
    response
        .headers_mut()
        .set("Cache-Control", ROUTER_AB_PUBLIC_KEYSET_CACHE_CONTROL_V1)?;
    cloudflare_router_public_keyset_cors_v1(&mut response, request, env)?;
    Ok(response)
}

#[cfg(feature = "strict-worker-router-entrypoint")]
fn cloudflare_router_public_keyset_cors_v1(
    response: &mut Response,
    request: &Request,
    env: &Env,
) -> worker::Result<()> {
    let configured = env
        .var(ROUTER_AB_PUBLIC_KEYSET_CORS_ORIGINS_ENV)
        .ok()
        .map(|value| value.to_string())
        .unwrap_or_else(|| "*".to_string());
    let origins = configured
        .split(',')
        .map(str::trim)
        .filter(|origin| !origin.is_empty())
        .collect::<Vec<_>>();
    let origin_header = request.headers().get("Origin")?.unwrap_or_default();
    let allow_origin = if origins.is_empty() || origins.iter().any(|origin| *origin == "*") {
        Some("*")
    } else if origins
        .iter()
        .any(|origin| *origin == origin_header.as_str())
    {
        Some(origin_header.as_str())
    } else {
        None
    };
    let headers = response.headers_mut();
    if let Some(origin) = allow_origin {
        headers.set("Access-Control-Allow-Origin", origin)?;
        if origin != "*" {
            headers.append("Vary", "Origin")?;
        }
    }
    headers.set(
        "Access-Control-Allow-Methods",
        ROUTER_AB_PUBLIC_KEYSET_CORS_ALLOW_METHODS_V1,
    )?;
    headers.set(
        "Access-Control-Allow-Headers",
        ROUTER_AB_PUBLIC_KEYSET_CORS_ALLOW_HEADERS_V1,
    )?;
    headers.set("Access-Control-Max-Age", "600")?;
    Ok(())
}

#[cfg(feature = "strict-worker-router-entrypoint")]
fn cloudflare_router_normal_signing_preflight_response_v1(
    request: &Request,
    env: &Env,
) -> worker::Result<Response> {
    let response = Response::empty()?.with_status(204);
    cloudflare_router_normal_signing_response_v1(response, request, env)
}

#[cfg(feature = "strict-worker-router-entrypoint")]
fn cloudflare_router_normal_signing_response_v1(
    mut response: Response,
    request: &Request,
    env: &Env,
) -> worker::Result<Response> {
    cloudflare_router_normal_signing_cors_v1(&mut response, request, env)?;
    Ok(response)
}

#[cfg(feature = "strict-worker-router-entrypoint")]
fn cloudflare_router_normal_signing_cors_v1(
    response: &mut Response,
    request: &Request,
    env: &Env,
) -> worker::Result<()> {
    let configured = env
        .var(ROUTER_AB_NORMAL_SIGNING_CORS_ORIGINS_ENV)
        .ok()
        .map(|value| value.to_string());
    let origin_header = request.headers().get("Origin")?.unwrap_or_default();
    let allow_origin = cloudflare_router_normal_signing_cors_allowed_origin_v1(
        configured.as_deref(),
        origin_header.as_str(),
    );
    let headers = response.headers_mut();
    if let Some(origin) = allow_origin.as_deref() {
        headers.set("Access-Control-Allow-Origin", origin)?;
        headers.append("Vary", "Origin")?;
    }
    headers.set(
        "Access-Control-Allow-Methods",
        ROUTER_AB_NORMAL_SIGNING_CORS_ALLOW_METHODS_V1,
    )?;
    headers.set(
        "Access-Control-Allow-Headers",
        ROUTER_AB_NORMAL_SIGNING_CORS_ALLOW_HEADERS_V1,
    )?;
    headers.set("Access-Control-Max-Age", "600")?;
    Ok(())
}

#[cfg(feature = "strict-worker-signer-a-entrypoint")]
async fn handle_strict_deriver_a_fetch_v1(request: Request, env: Env) -> worker::Result<Response> {
    if let Err(err) = require_cloudflare_internal_service_auth_request_v1(&request, &env) {
        return cloudflare_private_service_auth_error_response_v1(err);
    }
    let runtime = match CloudflareDeriverAWorkerRuntimeV1::from_worker_env(&env) {
        Ok(runtime) => StrictDeriverRuntimeV1::DeriverA(runtime),
        Err(err) => return cloudflare_protocol_error_response_v1(err),
    };
    handle_strict_deriver_fetch_v1(request, env, runtime).await
}

#[cfg(any(
    feature = "strict-worker-signer-a-entrypoint",
    feature = "strict-worker-signer-b-entrypoint"
))]
enum StrictDeriverRuntimeV1 {
    #[cfg(feature = "strict-worker-signer-a-entrypoint")]
    DeriverA(CloudflareDeriverAWorkerRuntimeV1),
    #[cfg(feature = "strict-worker-signer-b-entrypoint")]
    DeriverB(CloudflareDeriverBWorkerRuntimeV1),
}

#[cfg(any(
    feature = "strict-worker-signer-a-entrypoint",
    feature = "strict-worker-signer-b-entrypoint"
))]
impl StrictDeriverRuntimeV1 {
    fn label(&self) -> &'static str {
        match self {
            #[cfg(feature = "strict-worker-signer-a-entrypoint")]
            Self::DeriverA(_) => "Deriver A",
            #[cfg(feature = "strict-worker-signer-b-entrypoint")]
            Self::DeriverB(_) => "Deriver B",
        }
    }

    fn worker_role(&self) -> CloudflareWorkerRoleV1 {
        match self {
            #[cfg(feature = "strict-worker-signer-a-entrypoint")]
            Self::DeriverA(_) => CloudflareWorkerRoleV1::SignerA,
            #[cfg(feature = "strict-worker-signer-b-entrypoint")]
            Self::DeriverB(_) => CloudflareWorkerRoleV1::SignerB,
        }
    }

    fn protocol_role(&self) -> Role {
        match self {
            #[cfg(feature = "strict-worker-signer-a-entrypoint")]
            Self::DeriverA(_) => Role::SignerA,
            #[cfg(feature = "strict-worker-signer-b-entrypoint")]
            Self::DeriverB(_) => Role::SignerB,
        }
    }

    fn bootstrap_private_path(&self) -> &'static str {
        match self {
            #[cfg(feature = "strict-worker-signer-a-entrypoint")]
            Self::DeriverA(_) => CLOUDFLARE_SIGNER_A_PRIVATE_REQUEST_PATH_V1,
            #[cfg(feature = "strict-worker-signer-b-entrypoint")]
            Self::DeriverB(_) => CLOUDFLARE_SIGNER_B_PRIVATE_REQUEST_PATH_V1,
        }
    }

    fn registration_private_path(&self) -> &'static str {
        match self {
            #[cfg(feature = "strict-worker-signer-a-entrypoint")]
            Self::DeriverA(_) => CLOUDFLARE_SIGNER_A_ECDSA_HSS_REGISTRATION_PRIVATE_REQUEST_PATH_V1,
            #[cfg(feature = "strict-worker-signer-b-entrypoint")]
            Self::DeriverB(_) => CLOUDFLARE_SIGNER_B_ECDSA_HSS_REGISTRATION_PRIVATE_REQUEST_PATH_V1,
        }
    }

    fn export_private_path(&self) -> &'static str {
        match self {
            #[cfg(feature = "strict-worker-signer-a-entrypoint")]
            Self::DeriverA(_) => CLOUDFLARE_SIGNER_A_ECDSA_HSS_EXPORT_PRIVATE_REQUEST_PATH_V1,
            #[cfg(feature = "strict-worker-signer-b-entrypoint")]
            Self::DeriverB(_) => CLOUDFLARE_SIGNER_B_ECDSA_HSS_EXPORT_PRIVATE_REQUEST_PATH_V1,
        }
    }

    fn recovery_private_path(&self) -> &'static str {
        match self {
            #[cfg(feature = "strict-worker-signer-a-entrypoint")]
            Self::DeriverA(_) => CLOUDFLARE_SIGNER_A_ECDSA_HSS_RECOVERY_PRIVATE_REQUEST_PATH_V1,
            #[cfg(feature = "strict-worker-signer-b-entrypoint")]
            Self::DeriverB(_) => CLOUDFLARE_SIGNER_B_ECDSA_HSS_RECOVERY_PRIVATE_REQUEST_PATH_V1,
        }
    }

    fn refresh_private_path(&self) -> &'static str {
        match self {
            #[cfg(feature = "strict-worker-signer-a-entrypoint")]
            Self::DeriverA(_) => CLOUDFLARE_SIGNER_A_ECDSA_HSS_REFRESH_PRIVATE_REQUEST_PATH_V1,
            #[cfg(feature = "strict-worker-signer-b-entrypoint")]
            Self::DeriverB(_) => CLOUDFLARE_SIGNER_B_ECDSA_HSS_REFRESH_PRIVATE_REQUEST_PATH_V1,
        }
    }

    fn peer_verifying_keys_for_signer_set(
        &self,
        signer_set: &SignerSetV1,
    ) -> RouterAbProtocolResult<Vec<AbPeerMessageVerifyingKeyV1>> {
        match self {
            #[cfg(feature = "strict-worker-signer-a-entrypoint")]
            Self::DeriverA(runtime) => runtime.peer_verifying_keys_for_signer_set(signer_set),
            #[cfg(feature = "strict-worker-signer-b-entrypoint")]
            Self::DeriverB(runtime) => runtime.peer_verifying_keys_for_signer_set(signer_set),
        }
    }

    fn envelope_decrypt_key(&self) -> &CloudflareSignerEnvelopeHpkeDecryptKeyBindingSetV1 {
        match self {
            #[cfg(feature = "strict-worker-signer-a-entrypoint")]
            Self::DeriverA(runtime) => runtime.envelope_decrypt_key(),
            #[cfg(feature = "strict-worker-signer-b-entrypoint")]
            Self::DeriverB(runtime) => runtime.envelope_decrypt_key(),
        }
    }

    fn peer_signing_key(&self) -> &CloudflareSignerPeerSigningKeyBindingV1 {
        match self {
            #[cfg(feature = "strict-worker-signer-a-entrypoint")]
            Self::DeriverA(runtime) => runtime.peer_signing_key(),
            #[cfg(feature = "strict-worker-signer-b-entrypoint")]
            Self::DeriverB(runtime) => runtime.peer_signing_key(),
        }
    }

    fn signing_worker_peer(&self) -> &CloudflarePeerBindingV1 {
        match self {
            #[cfg(feature = "strict-worker-signer-a-entrypoint")]
            Self::DeriverA(runtime) => runtime.signing_worker_peer(),
            #[cfg(feature = "strict-worker-signer-b-entrypoint")]
            Self::DeriverB(runtime) => runtime.signing_worker_peer(),
        }
    }

    async fn preload_host(
        &self,
        env: &Env,
        input: CloudflareSignerHostPreloadInputV1,
    ) -> RouterAbProtocolResult<CloudflarePreloadedSignerHostV1> {
        match self {
            #[cfg(feature = "strict-worker-signer-a-entrypoint")]
            Self::DeriverA(runtime) => {
                preload_cloudflare_deriver_a_host_v1(env, runtime, input).await
            }
            #[cfg(feature = "strict-worker-signer-b-entrypoint")]
            Self::DeriverB(runtime) => {
                preload_cloudflare_deriver_b_host_v1(env, runtime, input).await
            }
        }
    }

    fn route_error_message(&self) -> String {
        format!(
            "{} strict Worker route must be served at {}, {}, {}, {}, or {}",
            self.label(),
            self.bootstrap_private_path(),
            self.registration_private_path(),
            self.export_private_path(),
            self.recovery_private_path(),
            self.refresh_private_path()
        )
    }
}

#[cfg(any(
    feature = "strict-worker-signer-a-entrypoint",
    feature = "strict-worker-signer-b-entrypoint"
))]
async fn handle_strict_deriver_fetch_v1(
    mut request: Request,
    env: Env,
    runtime: StrictDeriverRuntimeV1,
) -> worker::Result<Response> {
    let path = request.path();
    let worker_role = runtime.worker_role();
    let protocol_role = runtime.protocol_role();
    let label = runtime.label();
    let now_unix_ms = match cloudflare_now_unix_ms_v1() {
        Ok(now_unix_ms) => now_unix_ms,
        Err(err) => return cloudflare_protocol_error_response_v1(err),
    };

    if path == runtime.registration_private_path() {
        let registration_request = match request
            .json::<CloudflareEcdsaHssDeriverRegistrationPrivateRequestV1>()
            .await
        {
            Ok(parsed) => parsed,
            Err(err) => {
                return Response::error(
                    format!(
                        "Router A/B strict {label} ECDSA-HSS registration JSON parse failed: {err}"
                    ),
                    400,
                );
            }
        };
        if let Err(err) = registration_request.validate_for_worker_role(worker_role) {
            return cloudflare_protocol_error_response_v1(err);
        }
        let (preload_plan, host) = match preload_strict_deriver_host_v1(
            &env,
            &runtime,
            &registration_request.signer_bootstrap,
        )
        .await
        {
            Ok(loaded) => loaded,
            Err(err) => return cloudflare_protocol_error_response_v1(err),
        };
        let root_share_metadata =
            match host.root_share_startup_metadata(protocol_role, &preload_plan.root_share_epoch) {
                Ok(metadata) => metadata,
                Err(err) => return cloudflare_protocol_error_response_v1(err),
            };
        let registration_bootstrap = registration_request.signer_bootstrap.clone();
        let response =
            match decrypt_and_handle_cloudflare_ecdsa_hss_registration_signer_private_request_v1(
                &env,
                worker_role,
                &host,
                registration_request,
                runtime.envelope_decrypt_key(),
                runtime.peer_signing_key(),
                root_share_metadata,
                now_unix_ms,
            )
            .await
            {
                Ok(response) => response,
                Err(err) => return cloudflare_protocol_error_response_v1(err),
            };
        if let Err(err) = send_strict_deriver_direct_activation_delivery_v1(
            &env,
            &runtime,
            &registration_bootstrap,
            &response,
        )
        .await
        {
            return cloudflare_protocol_error_response_v1(err);
        }
        return Response::from_json(&response);
    }

    if path == runtime.export_private_path() {
        let export_request = match request
            .json::<CloudflareEcdsaHssDeriverExportPrivateRequestV1>()
            .await
        {
            Ok(parsed) => parsed,
            Err(err) => {
                return Response::error(
                    format!("Router A/B strict {label} ECDSA-HSS export JSON parse failed: {err}"),
                    400,
                );
            }
        };
        if let Err(err) = export_request.validate_for_worker_role(worker_role) {
            return cloudflare_protocol_error_response_v1(err);
        }
        let (preload_plan, host) =
            match preload_strict_deriver_host_v1(&env, &runtime, &export_request.signer_bootstrap)
                .await
            {
                Ok(loaded) => loaded,
                Err(err) => return cloudflare_protocol_error_response_v1(err),
            };
        let root_share_metadata =
            match host.root_share_startup_metadata(protocol_role, &preload_plan.root_share_epoch) {
                Ok(metadata) => metadata,
                Err(err) => return cloudflare_protocol_error_response_v1(err),
            };
        return match decrypt_and_handle_cloudflare_ecdsa_hss_export_signer_private_request_v1(
            &env,
            worker_role,
            &host,
            export_request,
            runtime.envelope_decrypt_key(),
            runtime.peer_signing_key(),
            root_share_metadata,
            now_unix_ms,
        )
        .await
        {
            Ok(response) => Response::from_json(&response),
            Err(err) => cloudflare_protocol_error_response_v1(err),
        };
    }

    if path == runtime.recovery_private_path() {
        let recovery_request = match request
            .json::<CloudflareEcdsaHssDeriverRecoveryPrivateRequestV1>()
            .await
        {
            Ok(parsed) => parsed,
            Err(err) => {
                return Response::error(
                    format!(
                        "Router A/B strict {label} ECDSA-HSS recovery JSON parse failed: {err}"
                    ),
                    400,
                );
            }
        };
        if let Err(err) = recovery_request.validate_for_worker_role(worker_role) {
            return cloudflare_protocol_error_response_v1(err);
        }
        let (preload_plan, host) = match preload_strict_deriver_host_v1(
            &env,
            &runtime,
            &recovery_request.signer_bootstrap,
        )
        .await
        {
            Ok(loaded) => loaded,
            Err(err) => return cloudflare_protocol_error_response_v1(err),
        };
        let root_share_metadata =
            match host.root_share_startup_metadata(protocol_role, &preload_plan.root_share_epoch) {
                Ok(metadata) => metadata,
                Err(err) => return cloudflare_protocol_error_response_v1(err),
            };
        return match decrypt_and_handle_cloudflare_ecdsa_hss_recovery_signer_private_request_v1(
            &env,
            worker_role,
            &host,
            recovery_request,
            runtime.envelope_decrypt_key(),
            runtime.peer_signing_key(),
            root_share_metadata,
            now_unix_ms,
        )
        .await
        {
            Ok(response) => Response::from_json(&response),
            Err(err) => cloudflare_protocol_error_response_v1(err),
        };
    }

    if path == runtime.refresh_private_path() {
        let refresh_request = match request
            .json::<CloudflareEcdsaHssDeriverActivationRefreshPrivateRequestV1>()
            .await
        {
            Ok(parsed) => parsed,
            Err(err) => {
                return Response::error(
                    format!("Router A/B strict {label} ECDSA-HSS refresh JSON parse failed: {err}"),
                    400,
                );
            }
        };
        if let Err(err) = refresh_request.validate_for_worker_role(worker_role) {
            return cloudflare_protocol_error_response_v1(err);
        }
        let (preload_plan, host) =
            match preload_strict_deriver_host_v1(&env, &runtime, &refresh_request.signer_bootstrap)
                .await
            {
                Ok(loaded) => loaded,
                Err(err) => return cloudflare_protocol_error_response_v1(err),
            };
        let root_share_metadata =
            match host.root_share_startup_metadata(protocol_role, &preload_plan.root_share_epoch) {
                Ok(metadata) => metadata,
                Err(err) => return cloudflare_protocol_error_response_v1(err),
            };
        let refresh_bootstrap = refresh_request.signer_bootstrap.clone();
        let response = match decrypt_and_handle_cloudflare_ecdsa_hss_activation_refresh_signer_private_request_v1(
            &env,
            worker_role,
            &host,
            refresh_request,
            runtime.envelope_decrypt_key(),
            runtime.peer_signing_key(),
            root_share_metadata,
            now_unix_ms,
        )
        .await
        {
            Ok(response) => response,
            Err(err) => return cloudflare_protocol_error_response_v1(err),
        };
        if let Err(err) = send_strict_deriver_direct_activation_delivery_v1(
            &env,
            &runtime,
            &refresh_bootstrap,
            &response,
        )
        .await
        {
            return cloudflare_protocol_error_response_v1(err);
        }
        return Response::from_json(&response);
    }

    if path == runtime.bootstrap_private_path() {
        let bootstrap = match request
            .json::<CloudflareSignerPrivateBootstrapRequestV1>()
            .await
        {
            Ok(parsed) => parsed,
            Err(err) => {
                return Response::error(
                    format!("Router A/B strict {label} bootstrap JSON parse failed: {err}"),
                    400,
                );
            }
        };
        if let Err(err) = bootstrap.validate_for_worker_role(worker_role) {
            return cloudflare_protocol_error_response_v1(err);
        }
        let (preload_plan, host) =
            match preload_strict_deriver_host_v1(&env, &runtime, &bootstrap).await {
                Ok(loaded) => loaded,
                Err(err) => return cloudflare_protocol_error_response_v1(err),
            };
        let root_share_metadata =
            match host.root_share_startup_metadata(protocol_role, &preload_plan.root_share_epoch) {
                Ok(metadata) => metadata,
                Err(err) => return cloudflare_protocol_error_response_v1(err),
            };
        let message = bootstrap.message;
        let aad = bootstrap.aad;
        let router_request_digest = bootstrap.router_request_digest;
        return match decrypt_and_handle_cloudflare_mpc_prf_recipient_proof_bundle_signer_private_request_v1(
            &env,
            worker_role,
            &host,
            message,
            runtime.envelope_decrypt_key(),
            runtime.peer_signing_key(),
            &aad,
            router_request_digest,
            root_share_metadata,
            now_unix_ms,
        )
        .await
        {
            Ok(response) => Response::from_json(&response),
            Err(err) => cloudflare_protocol_error_response_v1(err),
        };
    }

    Response::error(runtime.route_error_message(), 404)
}

#[cfg(any(
    feature = "strict-worker-signer-a-entrypoint",
    feature = "strict-worker-signer-b-entrypoint"
))]
async fn preload_strict_deriver_host_v1(
    env: &Env,
    runtime: &StrictDeriverRuntimeV1,
    bootstrap: &CloudflareSignerPrivateBootstrapRequestV1,
) -> RouterAbProtocolResult<(
    CloudflareSignerHostPreloadPlanV1,
    CloudflarePreloadedSignerHostV1,
)> {
    let preload_plan = CloudflareSignerHostPreloadPlanV1::from_private_bootstrap(
        runtime.worker_role(),
        bootstrap,
    )?;
    let verifying_keys = runtime.peer_verifying_keys_for_signer_set(&preload_plan.signer_set)?;
    let preload_input = preload_plan.to_host_preload_input(Vec::new(), verifying_keys, 0)?;
    let host = runtime.preload_host(env, preload_input).await?;
    Ok((preload_plan, host))
}

#[cfg(any(
    feature = "strict-worker-signer-a-entrypoint",
    feature = "strict-worker-signer-b-entrypoint"
))]
async fn send_strict_deriver_direct_activation_delivery_v1(
    env: &Env,
    runtime: &StrictDeriverRuntimeV1,
    bootstrap: &CloudflareSignerPrivateBootstrapRequestV1,
    response: &CloudflareSignerRecipientProofBundleResponseV1,
) -> RouterAbProtocolResult<()> {
    bootstrap.validate_for_worker_role(runtime.worker_role())?;
    response.validate()?;
    let router_payload = decode_router_to_signer_payload_v1(bootstrap.message.payload.as_bytes())?;
    let activation_context =
        SigningWorkerActivationContextV1::from_router_payload(&router_payload)?;
    let delivery = CloudflareSigningWorkerDirectRecipientProofBundleActivationDeliveryV1::from_signer_response(
        activation_context,
        response.clone(),
    )?;
    execute_cloudflare_signing_worker_direct_recipient_proof_bundle_activation_service_call_v1(
        env,
        runtime.signing_worker_peer(),
        &delivery,
    )
    .await?;
    Ok(())
}

#[cfg(feature = "strict-worker-signing-worker-entrypoint")]
async fn handle_strict_signing_worker_fetch_v1(
    request: Request,
    env: Env,
) -> worker::Result<Response> {
    if let Err(err) = require_cloudflare_internal_service_auth_request_v1(&request, &env) {
        return cloudflare_private_service_auth_error_response_v1(err);
    }
    let runtime = match CloudflareSigningWorkerRuntimeV1::from_worker_env(&env) {
        Ok(runtime) => runtime,
        Err(err) => return cloudflare_protocol_error_response_v1(err),
    };
    if request.path() == CLOUDFLARE_SIGNING_WORKER_PROOF_BUNDLE_ACTIVATION_PATH_V1 {
        return handle_cloudflare_signing_worker_recipient_proof_bundle_activation_fetch_v1(
            request, &env, &runtime,
        )
        .await;
    }
    if request.path() == CLOUDFLARE_SIGNING_WORKER_ECDSA_HSS_ACTIVATION_PATH_V1 {
        return handle_cloudflare_ecdsa_hss_signing_worker_activation_fetch_v1(
            request, &env, &runtime,
        )
        .await;
    }
    if request.path() == CLOUDFLARE_SIGNING_WORKER_ECDSA_HSS_REFRESH_PATH_V1 {
        return handle_cloudflare_ecdsa_hss_signing_worker_activation_refresh_fetch_v1(
            request, &env, &runtime,
        )
        .await;
    }
    if request.path() == CLOUDFLARE_SIGNING_WORKER_NORMAL_SIGNING_ROUND1_PREPARE_PATH_V1 {
        let now_unix_ms = match cloudflare_now_unix_ms_v1() {
            Ok(now_unix_ms) => now_unix_ms,
            Err(err) => return cloudflare_protocol_error_response_v1(err),
        };
        let handler = CloudflareRoleSeparatedEd25519NormalSigningHandlerV1;
        return handle_cloudflare_signing_worker_normal_signing_round1_prepare_private_fetch_v1(
            request,
            &env,
            &runtime,
            &handler,
            now_unix_ms,
        )
        .await;
    }
    if request.path() == CLOUDFLARE_SIGNING_WORKER_NORMAL_SIGNING_PRESIGN_POOL_PREPARE_PATH_V1 {
        let now_unix_ms = match cloudflare_now_unix_ms_v1() {
            Ok(now_unix_ms) => now_unix_ms,
            Err(err) => return cloudflare_protocol_error_response_v1(err),
        };
        let handler = CloudflareRoleSeparatedEd25519NormalSigningHandlerV1;
        return handle_cloudflare_signing_worker_normal_signing_presign_pool_prepare_private_fetch_v1(
            request,
            &env,
            &runtime,
            &handler,
            now_unix_ms,
        )
        .await;
    }
    if request.path() == CLOUDFLARE_SIGNING_WORKER_NORMAL_SIGNING_PRESIGN_POOL_PATH_V1 {
        let now_unix_ms = match cloudflare_now_unix_ms_v1() {
            Ok(now_unix_ms) => now_unix_ms,
            Err(err) => return cloudflare_protocol_error_response_v1(err),
        };
        let handler = CloudflareRoleSeparatedEd25519NormalSigningHandlerV1;
        return handle_cloudflare_signing_worker_normal_signing_presign_pool_hit_finalize_private_fetch_v1(
            request,
            &env,
            &runtime,
            &handler,
            now_unix_ms,
        )
        .await;
    }
    if request.path() == CLOUDFLARE_SIGNING_WORKER_NORMAL_SIGNING_PATH_V1 {
        let now_unix_ms = match cloudflare_now_unix_ms_v1() {
            Ok(now_unix_ms) => now_unix_ms,
            Err(err) => return cloudflare_protocol_error_response_v1(err),
        };
        let handler = CloudflareRoleSeparatedEd25519NormalSigningHandlerV1;
        return handle_cloudflare_signing_worker_normal_signing_private_fetch_v1(
            request,
            &env,
            &runtime,
            &handler,
            now_unix_ms,
        )
        .await;
    }
    if request.path() == CLOUDFLARE_SIGNING_WORKER_ECDSA_HSS_PRESIGNATURE_POOL_PUT_PATH_V1 {
        let now_unix_ms = match cloudflare_now_unix_ms_v1() {
            Ok(now_unix_ms) => now_unix_ms,
            Err(err) => return cloudflare_protocol_error_response_v1(err),
        };
        return handle_cloudflare_signing_worker_ecdsa_hss_presignature_pool_put_private_fetch_v1(
            request,
            &env,
            &runtime,
            now_unix_ms,
        )
        .await;
    }
    if request.path() == CLOUDFLARE_SIGNING_WORKER_ECDSA_HSS_SIGNING_PREPARE_PATH_V1 {
        let now_unix_ms = match cloudflare_now_unix_ms_v1() {
            Ok(now_unix_ms) => now_unix_ms,
            Err(err) => return cloudflare_protocol_error_response_v1(err),
        };
        return handle_cloudflare_signing_worker_ecdsa_hss_evm_digest_prepare_private_fetch_from_pool_v1(
            request,
            &env,
            &runtime,
            now_unix_ms,
        )
        .await;
    }
    if request.path() == CLOUDFLARE_SIGNING_WORKER_ECDSA_HSS_SIGNING_PATH_V1 {
        let now_unix_ms = match cloudflare_now_unix_ms_v1() {
            Ok(now_unix_ms) => now_unix_ms,
            Err(err) => return cloudflare_protocol_error_response_v1(err),
        };
        let handler = CloudflareRoleSeparatedEcdsaHssEvmDigestFinalizeHandlerV1;
        return handle_cloudflare_signing_worker_ecdsa_hss_evm_digest_finalize_private_fetch_v1(
            request,
            &env,
            &runtime,
            &handler,
            now_unix_ms,
        )
        .await;
    }
    Response::error(
        format!(
            "SigningWorker strict Worker route must be served at {}, {}, {}, {}, {}, {}, {}, or {}",
            CLOUDFLARE_SIGNING_WORKER_PROOF_BUNDLE_ACTIVATION_PATH_V1,
            CLOUDFLARE_SIGNING_WORKER_ECDSA_HSS_ACTIVATION_PATH_V1,
            CLOUDFLARE_SIGNING_WORKER_ECDSA_HSS_REFRESH_PATH_V1,
            CLOUDFLARE_SIGNING_WORKER_NORMAL_SIGNING_ROUND1_PREPARE_PATH_V1,
            CLOUDFLARE_SIGNING_WORKER_NORMAL_SIGNING_PATH_V1,
            CLOUDFLARE_SIGNING_WORKER_ECDSA_HSS_PRESIGNATURE_POOL_PUT_PATH_V1,
            CLOUDFLARE_SIGNING_WORKER_ECDSA_HSS_SIGNING_PREPARE_PATH_V1,
            CLOUDFLARE_SIGNING_WORKER_ECDSA_HSS_SIGNING_PATH_V1
        ),
        404,
    )
}

#[cfg(feature = "strict-worker-signer-b-entrypoint")]
async fn handle_strict_deriver_b_fetch_v1(request: Request, env: Env) -> worker::Result<Response> {
    if let Err(err) = require_cloudflare_internal_service_auth_request_v1(&request, &env) {
        return cloudflare_private_service_auth_error_response_v1(err);
    }
    let runtime = match CloudflareDeriverBWorkerRuntimeV1::from_worker_env(&env) {
        Ok(runtime) => StrictDeriverRuntimeV1::DeriverB(runtime),
        Err(err) => return cloudflare_protocol_error_response_v1(err),
    };
    handle_strict_deriver_fetch_v1(request, env, runtime).await
}

fn cloudflare_protocol_error_response_v1(err: RouterAbProtocolError) -> worker::Result<Response> {
    Response::error(
        format!("{:?}: {}", err.code(), err.message()),
        cloudflare_router_error_status(err.code()),
    )
}
