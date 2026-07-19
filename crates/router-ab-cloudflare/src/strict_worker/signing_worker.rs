use super::*;

#[cfg(feature = "strict-worker-signing-worker-entrypoint")]
pub(super) async fn handle_strict_signing_worker_fetch_v1(
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
    let path = request.path();
    match path.as_str() {
        CLOUDFLARE_SIGNING_WORKER_ED25519_YAO_DERIVER_A_PATH => {
            match handle_cloudflare_signing_worker_ed25519_yao_deriver_a_v1(request, &env).await {
                Ok(response) => Ok(response),
                Err(err) => cloudflare_protocol_error_response_v1(err),
            }
        }
        CLOUDFLARE_SIGNING_WORKER_ED25519_YAO_DERIVER_B_PATH => {
            match handle_cloudflare_signing_worker_ed25519_yao_deriver_b_v1(request, &env).await {
                Ok(response) => Ok(response),
                Err(err) => cloudflare_protocol_error_response_v1(err),
            }
        }
        CLOUDFLARE_SIGNING_WORKER_ED25519_YAO_RECOVERY_PROMOTE_PATH => {
            match handle_cloudflare_signing_worker_ed25519_yao_recovery_promote_v1(
                request, &env,
            )
            .await
            {
                Ok(response) => Ok(response),
                Err(err) => cloudflare_protocol_error_response_v1(err),
            }
        }
        CLOUDFLARE_SIGNING_WORKER_PROOF_BUNDLE_ACTIVATION_PATH => {
            handle_cloudflare_signing_worker_recipient_proof_bundle_activation_fetch_v1(
                request, &env, &runtime,
            )
            .await
        }
        CLOUDFLARE_SIGNING_WORKER_ROUTER_AB_ECDSA_DERIVATION_ACTIVATION_PATH => {
            handle_cloudflare_router_ab_ecdsa_derivation_signing_worker_activation_fetch_v1(
                request, &env, &runtime,
            )
            .await
        }
        CLOUDFLARE_SIGNING_WORKER_ROUTER_AB_ECDSA_DERIVATION_REFRESH_PATH => {
            handle_cloudflare_router_ab_ecdsa_derivation_signing_worker_activation_refresh_fetch_v1(
                request, &env, &runtime,
            )
            .await
        }
        CLOUDFLARE_SIGNING_WORKER_ROUTER_AB_ECDSA_DERIVATION_EXPORT_SHARE_PATH => {
            let now_unix_ms = match cloudflare_now_unix_ms_v1() {
                Ok(now_unix_ms) => now_unix_ms,
                Err(err) => return cloudflare_protocol_error_response_v1(err),
            };
            handle_cloudflare_signing_worker_ecdsa_export_share_private_fetch_v1(
                request,
                &env,
                &runtime,
                now_unix_ms,
            )
            .await
        }
        CLOUDFLARE_SIGNING_WORKER_NORMAL_SIGNING_ROUND1_PREPARE_PATH => {
            let now_unix_ms = match cloudflare_now_unix_ms_v1() {
                Ok(now_unix_ms) => now_unix_ms,
                Err(err) => return cloudflare_protocol_error_response_v1(err),
            };
            let handler = CloudflareEd25519YaoNormalSigningHandlerV1;
            handle_cloudflare_signing_worker_normal_signing_round1_prepare_private_fetch_v1(
                request,
                &env,
                &runtime,
                &handler,
                now_unix_ms,
            )
            .await
        }
        CLOUDFLARE_SIGNING_WORKER_NORMAL_SIGNING_PATH => {
            let now_unix_ms = match cloudflare_now_unix_ms_v1() {
                Ok(now_unix_ms) => now_unix_ms,
                Err(err) => return cloudflare_protocol_error_response_v1(err),
            };
            let handler = CloudflareEd25519YaoNormalSigningHandlerV1;
            handle_cloudflare_signing_worker_normal_signing_private_fetch_v1(
                request,
                &env,
                &runtime,
                &handler,
                now_unix_ms,
            )
            .await
        }
        CLOUDFLARE_SIGNING_WORKER_ROUTER_AB_ECDSA_DERIVATION_PRESIGNATURE_POOL_PUT_PATH => {
            let now_unix_ms = match cloudflare_now_unix_ms_v1() {
                Ok(now_unix_ms) => now_unix_ms,
                Err(err) => return cloudflare_protocol_error_response_v1(err),
            };
            handle_cloudflare_signing_worker_router_ab_ecdsa_derivation_presignature_pool_put_private_fetch_v1(
                request,
                &env,
                &runtime,
                now_unix_ms,
            )
            .await
        }
        CLOUDFLARE_SIGNING_WORKER_ROUTER_AB_ECDSA_DERIVATION_PRESIGNATURE_SESSION_INIT_PATH => {
            let now_unix_ms = match cloudflare_now_unix_ms_v1() {
                Ok(now_unix_ms) => now_unix_ms,
                Err(err) => return cloudflare_protocol_error_response_v1(err),
            };
            handle_cloudflare_signing_worker_ecdsa_presign_session_init_private_fetch_v1(
                request,
                &env,
                &runtime,
                now_unix_ms,
            )
            .await
        }
        CLOUDFLARE_SIGNING_WORKER_ROUTER_AB_ECDSA_DERIVATION_PRESIGNATURE_SESSION_STEP_PATH => {
            let now_unix_ms = match cloudflare_now_unix_ms_v1() {
                Ok(now_unix_ms) => now_unix_ms,
                Err(err) => return cloudflare_protocol_error_response_v1(err),
            };
            handle_cloudflare_signing_worker_ecdsa_presign_session_step_private_fetch_v1(
                request,
                &env,
                &runtime,
                now_unix_ms,
            )
            .await
        }
        CLOUDFLARE_SIGNING_WORKER_ROUTER_AB_ECDSA_DERIVATION_SIGNING_PREPARE_PATH => {
            let now_unix_ms = match cloudflare_now_unix_ms_v1() {
                Ok(now_unix_ms) => now_unix_ms,
                Err(err) => return cloudflare_protocol_error_response_v1(err),
            };
            handle_cloudflare_signing_worker_router_ab_ecdsa_derivation_evm_digest_prepare_private_fetch_from_pool_v1(
                request,
                &env,
                &runtime,
                now_unix_ms,
            )
            .await
        }
        CLOUDFLARE_SIGNING_WORKER_ROUTER_AB_ECDSA_DERIVATION_SIGNING_PATH => {
            let now_unix_ms = match cloudflare_now_unix_ms_v1() {
                Ok(now_unix_ms) => now_unix_ms,
                Err(err) => return cloudflare_protocol_error_response_v1(err),
            };
            let handler = CloudflareRoleSeparatedRouterAbEcdsaDerivationEvmDigestFinalizeHandlerV1;
            handle_cloudflare_signing_worker_router_ab_ecdsa_derivation_evm_digest_finalize_private_fetch_v1(
                request,
                &env,
                &runtime,
                &handler,
                now_unix_ms,
            )
            .await
        }
        _ => Response::error(
            format!(
                "SigningWorker strict Worker route must be served at {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, or {}",
                CLOUDFLARE_SIGNING_WORKER_ED25519_YAO_DERIVER_A_PATH,
                CLOUDFLARE_SIGNING_WORKER_ED25519_YAO_DERIVER_B_PATH,
                CLOUDFLARE_SIGNING_WORKER_ED25519_YAO_RECOVERY_PROMOTE_PATH,
                CLOUDFLARE_SIGNING_WORKER_PROOF_BUNDLE_ACTIVATION_PATH,
                CLOUDFLARE_SIGNING_WORKER_ROUTER_AB_ECDSA_DERIVATION_ACTIVATION_PATH,
                CLOUDFLARE_SIGNING_WORKER_ROUTER_AB_ECDSA_DERIVATION_REFRESH_PATH,
                CLOUDFLARE_SIGNING_WORKER_ROUTER_AB_ECDSA_DERIVATION_EXPORT_SHARE_PATH,
                CLOUDFLARE_SIGNING_WORKER_NORMAL_SIGNING_ROUND1_PREPARE_PATH,
                CLOUDFLARE_SIGNING_WORKER_NORMAL_SIGNING_PATH,
                CLOUDFLARE_SIGNING_WORKER_ROUTER_AB_ECDSA_DERIVATION_PRESIGNATURE_POOL_PUT_PATH,
                CLOUDFLARE_SIGNING_WORKER_ROUTER_AB_ECDSA_DERIVATION_PRESIGNATURE_SESSION_INIT_PATH,
                CLOUDFLARE_SIGNING_WORKER_ROUTER_AB_ECDSA_DERIVATION_PRESIGNATURE_SESSION_STEP_PATH,
                CLOUDFLARE_SIGNING_WORKER_ROUTER_AB_ECDSA_DERIVATION_SIGNING_PREPARE_PATH,
                CLOUDFLARE_SIGNING_WORKER_ROUTER_AB_ECDSA_DERIVATION_SIGNING_PATH
            ),
            404,
        ),
    }
}
