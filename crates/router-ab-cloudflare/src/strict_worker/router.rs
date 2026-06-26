use super::cors::{
    cloudflare_router_normal_signing_preflight_response_v1,
    cloudflare_router_normal_signing_response_v1,
    cloudflare_router_public_keyset_preflight_response_v1,
    cloudflare_router_public_keyset_response_v1,
};
use super::*;
use crate::CloudflareRouterBearerAuthorizationV1;
use router_ab_core::RouterAbProtocolResult;

#[cfg(feature = "strict-worker-router-entrypoint")]
pub(super) async fn handle_strict_router_fetch_v1(
    mut request: Request,
    env: Env,
) -> worker::Result<Response> {
    let path = request.path();
    if is_cloudflare_router_public_keyset_path(&path) {
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

    if path == CLOUDFLARE_ROUTER_WALLET_BUDGET_PUT_GRANT_PRIVATE_REQUEST_PATH {
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
        && (is_cloudflare_router_normal_signing_public_path(&path)
            || is_cloudflare_router_ecdsa_hss_public_path(&path))
    {
        return cloudflare_router_normal_signing_preflight_response_v1(&request, &env);
    }

    if request.method() != Method::Post {
        return Response::error("Router A/B strict public route requires POST", 405);
    }
    if path != CLOUDFLARE_ROUTER_SPLIT_DERIVATION_PUBLIC_REQUEST_PATH
        && path != CLOUDFLARE_ROUTER_NORMAL_SIGNING_ROUND1_PREPARE_PUBLIC_REQUEST_PATH
        && path != CLOUDFLARE_ROUTER_NORMAL_SIGNING_PRESIGN_POOL_PREPARE_PUBLIC_REQUEST_PATH
        && path != CLOUDFLARE_ROUTER_NORMAL_SIGNING_PUBLIC_REQUEST_PATH
        && path != CLOUDFLARE_ROUTER_ECDSA_HSS_REGISTRATION_PUBLIC_REQUEST_PATH
        && path != CLOUDFLARE_ROUTER_ECDSA_HSS_EXPORT_PUBLIC_REQUEST_PATH
        && path != CLOUDFLARE_ROUTER_ECDSA_HSS_RECOVERY_PUBLIC_REQUEST_PATH
        && path != CLOUDFLARE_ROUTER_ECDSA_HSS_REFRESH_PUBLIC_REQUEST_PATH
        && path != CLOUDFLARE_ROUTER_ECDSA_HSS_SIGNING_PREPARE_PUBLIC_REQUEST_PATH
        && path != CLOUDFLARE_ROUTER_ECDSA_HSS_SIGNING_PUBLIC_REQUEST_PATH
        && path != CLOUDFLARE_ROUTER_WALLET_BUDGET_STATUS_PUBLIC_REQUEST_PATH
    {
        return Response::error(
            format!(
                "Router A/B strict public request must be served at {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, or {}",
                CLOUDFLARE_ROUTER_SPLIT_DERIVATION_PUBLIC_REQUEST_PATH,
                CLOUDFLARE_ROUTER_NORMAL_SIGNING_ROUND1_PREPARE_PUBLIC_REQUEST_PATH,
                CLOUDFLARE_ROUTER_NORMAL_SIGNING_PRESIGN_POOL_PREPARE_PUBLIC_REQUEST_PATH,
                CLOUDFLARE_ROUTER_NORMAL_SIGNING_PUBLIC_REQUEST_PATH,
                CLOUDFLARE_ROUTER_ECDSA_HSS_REGISTRATION_PUBLIC_REQUEST_PATH,
                CLOUDFLARE_ROUTER_ECDSA_HSS_EXPORT_PUBLIC_REQUEST_PATH,
                CLOUDFLARE_ROUTER_ECDSA_HSS_RECOVERY_PUBLIC_REQUEST_PATH,
                CLOUDFLARE_ROUTER_ECDSA_HSS_REFRESH_PUBLIC_REQUEST_PATH,
                CLOUDFLARE_ROUTER_ECDSA_HSS_SIGNING_PREPARE_PUBLIC_REQUEST_PATH,
                CLOUDFLARE_ROUTER_ECDSA_HSS_SIGNING_PUBLIC_REQUEST_PATH,
                CLOUDFLARE_ROUTER_WALLET_BUDGET_STATUS_PUBLIC_REQUEST_PATH
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

    if path == CLOUDFLARE_ROUTER_WALLET_BUDGET_STATUS_PUBLIC_REQUEST_PATH {
        let credential = match router_wallet_session_credential_v1(&authorization, &request, &env)?
        {
            Ok(credential) => credential,
            Err(response) => return Ok(response),
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

    if path == CLOUDFLARE_ROUTER_NORMAL_SIGNING_ROUND1_PREPARE_PUBLIC_REQUEST_PATH {
        let request_body = match read_router_public_body_v1(
            &mut request,
            &env,
            "Router A/B strict normal-signing v2 prepare",
        )
        .await?
        {
            Ok(bytes) => bytes,
            Err(response) => return Ok(response),
        };
        let prepare_request = match parse_router_public_body_v1(
            &request_body,
            parse_router_ab_ed25519_normal_signing_prepare_request_v2_json,
            &request,
            &env,
        )? {
            Ok(parsed) => parsed,
            Err(response) => return Ok(response),
        };
        let credential = match router_wallet_session_credential_v1(&authorization, &request, &env)?
        {
            Ok(credential) => credential,
            Err(response) => return Ok(response),
        };
        let response =
            handle_cloudflare_router_normal_signing_prepare_authenticated_public_request_v2(
                &env,
                &runtime,
                now_unix_ms,
                prepare_request,
                credential,
                trusted_source_digest,
                verifier,
            )
            .await;
        return router_json_cors_response_v1(response, &request, &env);
    }

    if path == CLOUDFLARE_ROUTER_NORMAL_SIGNING_PRESIGN_POOL_PREPARE_PUBLIC_REQUEST_PATH {
        let request_body = match read_router_public_body_v1(
            &mut request,
            &env,
            "Router A/B strict normal-signing v2 presign-pool prepare",
        )
        .await?
        {
            Ok(bytes) => bytes,
            Err(response) => return Ok(response),
        };
        let prepare_request = match parse_router_public_body_v1(
            &request_body,
            parse_router_ab_ed25519_presign_pool_prepare_request_v2_json,
            &request,
            &env,
        )? {
            Ok(parsed) => parsed,
            Err(response) => return Ok(response),
        };
        let credential = match router_wallet_session_credential_v1(&authorization, &request, &env)?
        {
            Ok(credential) => credential,
            Err(response) => return Ok(response),
        };
        let response = handle_cloudflare_router_normal_signing_presign_pool_prepare_authenticated_public_request_v2(
            &env,
            &runtime,
            now_unix_ms,
            prepare_request,
            credential,
            trusted_source_digest,
            verifier,
        )
        .await;
        return router_json_cors_response_v1(response, &request, &env);
    }

    if path == CLOUDFLARE_ROUTER_NORMAL_SIGNING_PUBLIC_REQUEST_PATH {
        let request_body = match read_router_public_body_v1(
            &mut request,
            &env,
            "Router A/B strict normal-signing finalize",
        )
        .await?
        {
            Ok(bytes) => bytes,
            Err(response) => return Ok(response),
        };
        match parse_cloudflare_router_budgeted_ed25519_finalize_request_v2_json(&request_body) {
            Ok((finalize_request, budget_metadata)) => {
                let credential =
                    match router_wallet_session_credential_v1(&authorization, &request, &env)? {
                        Ok(credential) => credential,
                        Err(response) => return Ok(response),
                    };
                let response = handle_cloudflare_router_normal_signing_finalize_authenticated_public_request_v2(
                    &env,
                    &runtime,
                    now_unix_ms,
                    finalize_request,
                    budget_metadata,
                    credential,
                    trusted_source_digest,
                    verifier,
                )
                .await;
                return router_json_cors_response_v1(response, &request, &env);
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
                    match router_wallet_session_credential_v1(&authorization, &request, &env)? {
                        Ok(credential) => credential,
                        Err(response) => return Ok(response),
                    };
                let response = handle_cloudflare_router_normal_signing_presign_pool_hit_finalize_authenticated_public_request_v2(
                    &env,
                    &runtime,
                    now_unix_ms,
                    pool_hit_request,
                    credential,
                    trusted_source_digest,
                    verifier,
                )
                .await;
                return router_json_cors_response_v1(response, &request, &env);
            }
        }
    }

    if path == CLOUDFLARE_ROUTER_ECDSA_HSS_REGISTRATION_PUBLIC_REQUEST_PATH {
        let request_body = match read_router_public_body_v1(
            &mut request,
            &env,
            "Router A/B strict ECDSA-HSS registration",
        )
        .await?
        {
            Ok(bytes) => bytes,
            Err(response) => return Ok(response),
        };
        let registration_request = match parse_router_public_body_v1(
            &request_body,
            parse_router_ab_ecdsa_hss_registration_bootstrap_request_v1_json,
            &request,
            &env,
        )? {
            Ok(parsed) => parsed,
            Err(response) => return Ok(response),
        };
        let response = handle_cloudflare_router_ecdsa_hss_registration_bootstrap_authenticated_public_request_v1(
            &env,
            &runtime,
            now_unix_ms,
            registration_request,
            authorization,
            trusted_source_digest,
            verifier,
        )
        .await;
        return router_json_cors_response_v1(response, &request, &env);
    }

    if path == CLOUDFLARE_ROUTER_ECDSA_HSS_EXPORT_PUBLIC_REQUEST_PATH {
        let request_body = match read_router_public_body_v1(
            &mut request,
            &env,
            "Router A/B strict ECDSA-HSS export",
        )
        .await?
        {
            Ok(bytes) => bytes,
            Err(response) => return Ok(response),
        };
        let export_request = match parse_router_public_body_v1(
            &request_body,
            parse_router_ab_ecdsa_hss_explicit_export_request_v1_json,
            &request,
            &env,
        )? {
            Ok(parsed) => parsed,
            Err(response) => return Ok(response),
        };
        let response =
            handle_cloudflare_router_ecdsa_hss_explicit_export_authenticated_public_request_v1(
                &env,
                &runtime,
                now_unix_ms,
                export_request,
                authorization,
                trusted_source_digest,
                verifier,
            )
            .await;
        return router_json_cors_response_v1(response, &request, &env);
    }

    if path == CLOUDFLARE_ROUTER_ECDSA_HSS_RECOVERY_PUBLIC_REQUEST_PATH {
        let request_body = match read_router_public_body_v1(
            &mut request,
            &env,
            "Router A/B strict ECDSA-HSS recovery",
        )
        .await?
        {
            Ok(bytes) => bytes,
            Err(response) => return Ok(response),
        };
        let recovery_request = match parse_router_public_body_v1(
            &request_body,
            parse_router_ab_ecdsa_hss_recovery_request_v1_json,
            &request,
            &env,
        )? {
            Ok(parsed) => parsed,
            Err(response) => return Ok(response),
        };
        let response = handle_cloudflare_router_ecdsa_hss_recovery_authenticated_public_request_v1(
            &env,
            &runtime,
            now_unix_ms,
            recovery_request,
            authorization,
            trusted_source_digest,
            verifier,
        )
        .await;
        return router_json_cors_response_v1(response, &request, &env);
    }

    if path == CLOUDFLARE_ROUTER_ECDSA_HSS_REFRESH_PUBLIC_REQUEST_PATH {
        let request_body = match read_router_public_body_v1(
            &mut request,
            &env,
            "Router A/B strict ECDSA-HSS activation-refresh",
        )
        .await?
        {
            Ok(bytes) => bytes,
            Err(response) => return Ok(response),
        };
        let refresh_request = match parse_router_public_body_v1(
            &request_body,
            parse_router_ab_ecdsa_hss_activation_refresh_request_v1_json,
            &request,
            &env,
        )? {
            Ok(parsed) => parsed,
            Err(response) => return Ok(response),
        };
        let response =
            handle_cloudflare_router_ecdsa_hss_activation_refresh_authenticated_public_request_v1(
                &env,
                &runtime,
                now_unix_ms,
                refresh_request,
                authorization,
                trusted_source_digest,
                verifier,
            )
            .await;
        return router_json_cors_response_v1(response, &request, &env);
    }

    if path == CLOUDFLARE_ROUTER_ECDSA_HSS_SIGNING_PREPARE_PUBLIC_REQUEST_PATH {
        let request_body = match read_router_public_body_v1(
            &mut request,
            &env,
            "Router A/B strict ECDSA-HSS prepare",
        )
        .await?
        {
            Ok(bytes) => bytes,
            Err(response) => return Ok(response),
        };
        let prepare_request = match parse_router_public_body_v1(
            &request_body,
            parse_router_ab_ecdsa_hss_evm_digest_signing_request_v1_json,
            &request,
            &env,
        )? {
            Ok(parsed) => parsed,
            Err(response) => return Ok(response),
        };
        let credential = match router_wallet_session_credential_v1(&authorization, &request, &env)?
        {
            Ok(credential) => credential,
            Err(response) => return Ok(response),
        };
        let response = handle_cloudflare_router_ecdsa_hss_evm_digest_signing_prepare_authenticated_public_request_v1(
            &env,
            &runtime,
            now_unix_ms,
            prepare_request,
            credential,
            trusted_source_digest,
            verifier,
        )
        .await;
        return router_json_cors_response_v1(response, &request, &env);
    }

    if path == CLOUDFLARE_ROUTER_ECDSA_HSS_SIGNING_PUBLIC_REQUEST_PATH {
        let request_body = match read_router_public_body_v1(
            &mut request,
            &env,
            "Router A/B strict ECDSA-HSS finalize",
        )
        .await?
        {
            Ok(bytes) => bytes,
            Err(response) => return Ok(response),
        };
        let (finalize_request, budget_metadata) = match parse_router_public_body_v1(
            &request_body,
            parse_cloudflare_router_budgeted_ecdsa_hss_finalize_request_v1_json,
            &request,
            &env,
        )? {
            Ok(parsed) => parsed,
            Err(response) => return Ok(response),
        };
        let credential = match router_wallet_session_credential_v1(&authorization, &request, &env)?
        {
            Ok(credential) => credential,
            Err(response) => return Ok(response),
        };
        let response = handle_cloudflare_router_ecdsa_hss_evm_digest_signing_finalize_authenticated_public_request_v1(
            &env,
            &runtime,
            now_unix_ms,
            finalize_request,
            budget_metadata,
            credential,
            trusted_source_digest,
            verifier,
        )
        .await;
        return router_json_cors_response_v1(response, &request, &env);
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
async fn read_router_public_body_v1(
    request: &mut Request,
    env: &Env,
    label: &'static str,
) -> worker::Result<Result<Vec<u8>, Response>> {
    match request.bytes().await {
        Ok(bytes) => Ok(Ok(bytes)),
        Err(err) => {
            let response = Response::error(format!("{label} body read failed: {err}"), 400)?;
            Ok(Err(cloudflare_router_normal_signing_response_v1(
                response, request, env,
            )?))
        }
    }
}

#[cfg(feature = "strict-worker-router-entrypoint")]
fn parse_router_public_body_v1<T>(
    body: &[u8],
    parser: fn(&[u8]) -> RouterAbProtocolResult<T>,
    request: &Request,
    env: &Env,
) -> worker::Result<Result<T, Response>> {
    match parser(body) {
        Ok(parsed) => Ok(Ok(parsed)),
        Err(err) => {
            let response = cloudflare_protocol_error_response_v1(err)?;
            Ok(Err(cloudflare_router_normal_signing_response_v1(
                response, request, env,
            )?))
        }
    }
}

#[cfg(feature = "strict-worker-router-entrypoint")]
fn router_wallet_session_credential_v1(
    authorization: &CloudflareRouterBearerAuthorizationV1,
    request: &Request,
    env: &Env,
) -> worker::Result<Result<CloudflareRouterWalletSessionCredentialV1, Response>> {
    match CloudflareRouterWalletSessionCredentialV1::bearer(authorization.clone()) {
        Ok(credential) => Ok(Ok(credential)),
        Err(err) => {
            let response = cloudflare_protocol_error_response_v1(err)?;
            Ok(Err(cloudflare_router_normal_signing_response_v1(
                response, request, env,
            )?))
        }
    }
}

#[cfg(feature = "strict-worker-router-entrypoint")]
fn router_json_cors_response_v1<T: serde::Serialize>(
    result: RouterAbProtocolResult<T>,
    request: &Request,
    env: &Env,
) -> worker::Result<Response> {
    match result {
        Ok(response) => {
            let response = Response::from_json(&response)?;
            cloudflare_router_normal_signing_response_v1(response, request, env)
        }
        Err(err) => {
            let response = cloudflare_protocol_error_response_v1(err)?;
            cloudflare_router_normal_signing_response_v1(response, request, env)
        }
    }
}

#[cfg(feature = "strict-worker-router-entrypoint")]
fn is_cloudflare_router_public_keyset_path(path: &str) -> bool {
    let normalized = path.strip_suffix('/').unwrap_or(path);
    normalized == CLOUDFLARE_ROUTER_PUBLIC_KEYSET_WELL_KNOWN_PATH
        || normalized == CLOUDFLARE_ROUTER_PUBLIC_KEYSET_PATH
}

#[cfg(feature = "strict-worker-router-entrypoint")]
fn is_cloudflare_router_normal_signing_public_path(path: &str) -> bool {
    let normalized = path.strip_suffix('/').unwrap_or(path);
    normalized == CLOUDFLARE_ROUTER_NORMAL_SIGNING_ROUND1_PREPARE_PUBLIC_REQUEST_PATH
        || normalized == CLOUDFLARE_ROUTER_NORMAL_SIGNING_PRESIGN_POOL_PREPARE_PUBLIC_REQUEST_PATH
        || normalized == CLOUDFLARE_ROUTER_NORMAL_SIGNING_PUBLIC_REQUEST_PATH
        || normalized == CLOUDFLARE_ROUTER_WALLET_BUDGET_STATUS_PUBLIC_REQUEST_PATH
}

#[cfg(feature = "strict-worker-router-entrypoint")]
fn is_cloudflare_router_ecdsa_hss_public_path(path: &str) -> bool {
    let normalized = path.strip_suffix('/').unwrap_or(path);
    normalized == CLOUDFLARE_ROUTER_ECDSA_HSS_REGISTRATION_PUBLIC_REQUEST_PATH
        || normalized == CLOUDFLARE_ROUTER_ECDSA_HSS_EXPORT_PUBLIC_REQUEST_PATH
        || normalized == CLOUDFLARE_ROUTER_ECDSA_HSS_RECOVERY_PUBLIC_REQUEST_PATH
        || normalized == CLOUDFLARE_ROUTER_ECDSA_HSS_REFRESH_PUBLIC_REQUEST_PATH
        || normalized == CLOUDFLARE_ROUTER_ECDSA_HSS_SIGNING_PREPARE_PUBLIC_REQUEST_PATH
        || normalized == CLOUDFLARE_ROUTER_ECDSA_HSS_SIGNING_PUBLIC_REQUEST_PATH
}
