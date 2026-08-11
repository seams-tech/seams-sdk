use super::cors::{
    cloudflare_router_normal_signing_preflight_response_v1,
    cloudflare_router_normal_signing_response_v1,
    cloudflare_router_public_keyset_preflight_response_v1,
    cloudflare_router_public_keyset_response_v1,
};
use super::*;
use crate::{
    execute_cloudflare_signing_worker_linked_device_ecdsa_finalize_service_call_v1,
    handle_cloudflare_router_ab_ecdsa_derivation_evm_digest_signing_finalize_internal_step_up_request_v1,
    handle_cloudflare_router_ab_ecdsa_derivation_evm_digest_signing_prepare_internal_step_up_request_v1,
    handle_cloudflare_router_normal_signing_finalize_internal_step_up_request_v2,
    handle_cloudflare_router_normal_signing_prepare_internal_step_up_request_v2,
    parse_cloudflare_router_authorized_ed25519_prepare_request_v2_json,
    parse_cloudflare_router_authorized_linked_device_ecdsa_finalize_request_v1_json,
    CloudflareRouterBearerAuthorizationV1, CloudflareRouterEcdsaAcceptedAuthorizedOperationV1,
    CloudflareRouterEcdsaAcceptedCapabilityBindingV1,
    CloudflareRouterEd25519AcceptedAuthorizedOperationV1,
    CloudflareRouterEd25519AcceptedCapabilityBindingV1, CloudflareRouterEd25519JwksJwtVerifierV1,
};
use router_ab_core::{
    PublicDigest32, RouterAbEcdsaDerivationEvmDigestSigningFinalizeRequestV1,
    RouterAbEcdsaDerivationEvmDigestSigningRequestV1,
    RouterAbEd25519NormalSigningFinalizeRequestV2, RouterAbEd25519NormalSigningPrepareRequestV2,
    RouterAbProtocolErrorCode, RouterAbProtocolResult,
};

#[cfg(feature = "strict-worker-router-entrypoint")]
enum StrictRouterNormalSigningRequestV1 {
    Ed25519Prepare {
        request: RouterAbEd25519NormalSigningPrepareRequestV2,
        authorized_operation: CloudflareRouterEd25519AcceptedAuthorizedOperationV1,
    },
    Ed25519Finalize {
        request: RouterAbEd25519NormalSigningFinalizeRequestV2,
        authorized_operation: CloudflareRouterEd25519AcceptedAuthorizedOperationV1,
    },
    EcdsaPrepare {
        request: RouterAbEcdsaDerivationEvmDigestSigningRequestV1,
        authorized_operation: CloudflareRouterEcdsaAcceptedAuthorizedOperationV1,
    },
    EcdsaFinalize {
        request: RouterAbEcdsaDerivationEvmDigestSigningFinalizeRequestV1,
        authorized_operation: CloudflareRouterEcdsaAcceptedAuthorizedOperationV1,
    },
}

#[cfg(feature = "strict-worker-router-entrypoint")]
impl StrictRouterNormalSigningRequestV1 {
    fn is_operation_step_up(&self) -> bool {
        match self {
            Self::Ed25519Prepare {
                authorized_operation,
                ..
            }
            | Self::Ed25519Finalize {
                authorized_operation,
                ..
            } => matches!(
                &authorized_operation.binding,
                CloudflareRouterEd25519AcceptedCapabilityBindingV1::OperationStepUp { .. }
            ),
            Self::EcdsaPrepare {
                authorized_operation,
                ..
            }
            | Self::EcdsaFinalize {
                authorized_operation,
                ..
            } => matches!(
                &authorized_operation.binding,
                CloudflareRouterEcdsaAcceptedCapabilityBindingV1::OperationStepUp { .. }
            ),
        }
    }
}

#[cfg(feature = "strict-worker-router-entrypoint")]
pub(super) async fn handle_strict_router_fetch_v1(
    mut request: Request,
    env: Env,
) -> worker::Result<Response> {
    let path = request.path();
    if path == CLOUDFLARE_INTERNAL_PREWARM_PATH {
        return handle_router_prewarm_v1(&request, &env).await;
    }
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

    if path == CLOUDFLARE_ROUTER_ED25519_YAO_EXECUTE_PRIVATE_REQUEST_PATH {
        return handle_cloudflare_router_ed25519_yao_execute_private_fetch_v1(request, &env).await;
    }
    if path == CLOUDFLARE_ROUTER_ED25519_YAO_LANE_EXECUTE_PRIVATE_REQUEST_PATH {
        return handle_cloudflare_router_ed25519_yao_lane_execute_private_fetch_v1(request, &env)
            .await;
    }
    if path == CLOUDFLARE_ROUTER_ED25519_YAO_RECOVERY_PROMOTE_PRIVATE_REQUEST_PATH {
        return handle_cloudflare_router_ed25519_yao_recovery_promote_private_fetch_v1(
            request, &env,
        )
        .await;
    }

    if request.method() == Method::Options
        && (is_cloudflare_router_normal_signing_public_path(&path)
            || is_cloudflare_router_ab_ecdsa_derivation_public_path(&path))
    {
        return cloudflare_router_normal_signing_preflight_response_v1(&request, &env);
    }

    if request.method() != Method::Post {
        return Response::error("Router A/B strict public route requires POST", 405);
    }
    if path == CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_LINKED_SIGNING_PRIVATE_REQUEST_PATH {
        if let Err(err) = require_cloudflare_internal_service_auth_request_v1(&request, &env) {
            return cloudflare_private_service_auth_error_response_v1(err);
        }
        let runtime = match CloudflareRouterWorkerRuntimeV1::from_worker_env(&env) {
            Ok(runtime) => runtime,
            Err(err) => return cloudflare_protocol_error_response_v1(err),
        };
        let request_body =
            match read_router_public_body_v1(&mut request, &env, "linked ECDSA finalize request")
                .await?
            {
                Ok(bytes) => bytes,
                Err(response) => return Ok(response),
            };
        let parsed =
            match parse_cloudflare_router_authorized_linked_device_ecdsa_finalize_request_v1_json(
                &request_body,
            ) {
                Ok(parsed) => parsed,
                Err(err) => return cloudflare_protocol_error_response_v1(err),
            };
        let response =
            execute_cloudflare_signing_worker_linked_device_ecdsa_finalize_service_call_v1(
                &env,
                runtime.signing_worker_peer(),
                parsed,
            )
            .await;
        return match response {
            Ok(response) => Response::from_json(&response),
            Err(err) => cloudflare_protocol_error_response_v1(err),
        };
    }
    if path == CLOUDFLARE_ROUTER_NORMAL_SIGNING_ROUND1_PREPARE_PUBLIC_REQUEST_PATH
        || path == CLOUDFLARE_ROUTER_NORMAL_SIGNING_PUBLIC_REQUEST_PATH
        || path == CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_SIGNING_PREPARE_PUBLIC_REQUEST_PATH
        || path == CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_SIGNING_PUBLIC_REQUEST_PATH
    {
        if let Err(err) = require_cloudflare_internal_service_auth_request_v1(&request, &env) {
            return cloudflare_private_service_auth_error_response_v1(err);
        }
    }
    if path != CLOUDFLARE_ROUTER_NORMAL_SIGNING_ROUND1_PREPARE_PUBLIC_REQUEST_PATH
        && path != CLOUDFLARE_ROUTER_NORMAL_SIGNING_PUBLIC_REQUEST_PATH
        && path != CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_REGISTRATION_PUBLIC_REQUEST_PATH
        && path != CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_ACTIVATION_PUBLIC_REQUEST_PATH
        && path != CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_ADD_SIGNER_PUBLIC_REQUEST_PATH
        && path != CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_EXPORT_PUBLIC_REQUEST_PATH
        && path != CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_REFRESH_PUBLIC_REQUEST_PATH
        && path != CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_SIGNING_PREPARE_PUBLIC_REQUEST_PATH
        && path != CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_SIGNING_PUBLIC_REQUEST_PATH
    {
        return Response::error(
            format!(
                "Router A/B strict public request must be served at {}, {}, {}, {}, {}, {}, {}, {}, or {}",
                CLOUDFLARE_ROUTER_NORMAL_SIGNING_ROUND1_PREPARE_PUBLIC_REQUEST_PATH,
                CLOUDFLARE_ROUTER_NORMAL_SIGNING_PUBLIC_REQUEST_PATH,
                CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_REGISTRATION_PUBLIC_REQUEST_PATH,
                CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_ACTIVATION_PUBLIC_REQUEST_PATH,
                CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_ADD_SIGNER_PUBLIC_REQUEST_PATH,
                CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_EXPORT_PUBLIC_REQUEST_PATH,
                CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_REFRESH_PUBLIC_REQUEST_PATH,
                CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_SIGNING_PREPARE_PUBLIC_REQUEST_PATH,
                CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_SIGNING_PUBLIC_REQUEST_PATH
            ),
            404,
        );
    }
    let parsed_normal_signing = if path
        == CLOUDFLARE_ROUTER_NORMAL_SIGNING_ROUND1_PREPARE_PUBLIC_REQUEST_PATH
        || path == CLOUDFLARE_ROUTER_NORMAL_SIGNING_PUBLIC_REQUEST_PATH
        || path == CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_SIGNING_PREPARE_PUBLIC_REQUEST_PATH
        || path == CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_SIGNING_PUBLIC_REQUEST_PATH
    {
        match parse_strict_router_normal_signing_request_v1(&mut request, &env, &path).await? {
            Ok(parsed) => Some(parsed),
            Err(response) => return Ok(response),
        }
    } else {
        None
    };
    let authorization = match parse_cloudflare_router_bearer_authorization_from_request_v1(&request)
    {
        Ok(authorization) => Some(authorization),
        Err(_err)
            if parsed_normal_signing
                .as_ref()
                .is_some_and(StrictRouterNormalSigningRequestV1::is_operation_step_up) =>
        {
            None
        }
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
    let verifier = match build_cloudflare_router_ed25519_jwks_jwt_verifier_v1(
        &runtime.admission_bindings().jwt,
    ) {
        Ok(verifier) => verifier,
        Err(err) => return cloudflare_protocol_error_response_v1(err),
    };

    if let Some(parsed) = parsed_normal_signing {
        return execute_strict_router_normal_signing_request_v1(
            parsed,
            authorization.as_ref(),
            &request,
            &env,
            &runtime,
            now_unix_ms,
            trusted_source_digest,
            verifier,
        )
        .await;
    }
    let authorization = match authorization {
        Some(authorization) => authorization,
        None => {
            return cloudflare_protocol_error_response_v1(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "Bearer authorization is required",
            ));
        }
    };

    if path == CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_ACTIVATION_PUBLIC_REQUEST_PATH {
        let trace_id = match router_ecdsa_trace_context_v1(&request, &env)? {
            Ok(trace_id) => trace_id,
            Err(response) => return Ok(response),
        };
        let request_body = match read_router_public_body_v1(
            &mut request,
            &env,
            "Router A/B strict ECDSA registration activation",
        )
        .await?
        {
            Ok(bytes) => bytes,
            Err(response) => return Ok(response),
        };
        let activation_request = match parse_router_public_body_v1(
            &request_body,
            parse_cloudflare_router_ab_ecdsa_derivation_activation_request_v1_json,
            &request,
            &env,
        )? {
            Ok(parsed) => parsed,
            Err(response) => return Ok(response),
        };
        let mut timing = CloudflareEcdsaBoundaryTimingV1::with_trace_id(trace_id);
        let response =
            handle_cloudflare_router_ab_ecdsa_derivation_activation_authenticated_public_request_v1(
                &env,
                &runtime,
                now_unix_ms,
                activation_request,
                authorization,
                trusted_source_digest,
                verifier,
                &mut timing,
            )
            .await;
        return router_ecdsa_timed_json_cors_response_v1(response, &timing, &request, &env);
    }

    if let Some(registration_purpose) =
        router_ab_ecdsa_derivation_registration_purpose_for_public_path(&path)
    {
        let trace_id = match router_ecdsa_trace_context_v1(&request, &env)? {
            Ok(trace_id) => trace_id,
            Err(response) => return Ok(response),
        };
        let request_body = match read_router_public_body_v1(
            &mut request,
            &env,
            "Router A/B strict Router A/B ECDSA derivation registration",
        )
        .await?
        {
            Ok(bytes) => bytes,
            Err(response) => return Ok(response),
        };
        let registration_request = match parse_router_public_body_v1(
            &request_body,
            parse_router_ab_ecdsa_derivation_registration_bootstrap_request_v1_json,
            &request,
            &env,
        )? {
            Ok(parsed) => parsed,
            Err(response) => return Ok(response),
        };
        if let Err(err) =
            registration_request.validate_for_registration_purpose(registration_purpose)
        {
            let response = cloudflare_protocol_error_response_v1(err)?;
            return cloudflare_router_normal_signing_response_v1(response, &request, &env);
        }
        let mut timing = CloudflareEcdsaBoundaryTimingV1::with_trace_id(trace_id);
        let response = handle_cloudflare_router_ab_ecdsa_derivation_registration_bootstrap_authenticated_public_request_v1(
            &env,
            &runtime,
            now_unix_ms,
            registration_request,
            authorization,
            trusted_source_digest,
            verifier,
            &mut timing,
        )
        .await;
        return router_ecdsa_timed_json_cors_response_v1(response, &timing, &request, &env);
    }

    if path == CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_EXPORT_PUBLIC_REQUEST_PATH {
        let request_body = match read_router_public_body_v1(
            &mut request,
            &env,
            "Router A/B strict Router A/B ECDSA derivation export",
        )
        .await?
        {
            Ok(bytes) => bytes,
            Err(response) => return Ok(response),
        };
        let export_request = match parse_router_public_body_v1(
            &request_body,
            parse_cloudflare_router_ab_ecdsa_derivation_export_command_v1_json,
            &request,
            &env,
        )? {
            Ok(parsed) => parsed,
            Err(response) => return Ok(response),
        };
        let response =
            handle_cloudflare_router_ab_ecdsa_derivation_explicit_export_authenticated_public_request_v1(
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

    if path == CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_REFRESH_PUBLIC_REQUEST_PATH {
        let request_body = match read_router_public_body_v1(
            &mut request,
            &env,
            "Router A/B strict Router A/B ECDSA derivation activation-refresh",
        )
        .await?
        {
            Ok(bytes) => bytes,
            Err(response) => return Ok(response),
        };
        let refresh_request = match parse_router_public_body_v1(
            &request_body,
            parse_cloudflare_router_ab_ecdsa_derivation_activation_refresh_request_v1_json,
            &request,
            &env,
        )? {
            Ok(parsed) => parsed,
            Err(response) => return Ok(response),
        };
        let response =
            handle_cloudflare_router_ab_ecdsa_derivation_activation_refresh_authenticated_public_request_v1(
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

    Response::error("Router A/B strict public route is unavailable", 404)
}

#[cfg(feature = "strict-worker-router-entrypoint")]
async fn parse_strict_router_normal_signing_request_v1(
    request: &mut Request,
    env: &Env,
    path: &str,
) -> worker::Result<Result<StrictRouterNormalSigningRequestV1, Response>> {
    let request_body =
        match read_router_public_body_v1(request, env, "Router A/B strict normal-signing request")
            .await?
        {
            Ok(bytes) => bytes,
            Err(response) => return Ok(Err(response)),
        };
    let parsed = match path {
        CLOUDFLARE_ROUTER_NORMAL_SIGNING_ROUND1_PREPARE_PUBLIC_REQUEST_PATH => {
            parse_router_public_body_v1(
                &request_body,
                parse_cloudflare_router_authorized_ed25519_prepare_request_v2_json,
                request,
                env,
            )?
            .map(|(request, authorized_operation)| {
                StrictRouterNormalSigningRequestV1::Ed25519Prepare {
                    request,
                    authorized_operation,
                }
            })
        }
        CLOUDFLARE_ROUTER_NORMAL_SIGNING_PUBLIC_REQUEST_PATH => parse_router_public_body_v1(
            &request_body,
            parse_cloudflare_router_authorized_ed25519_finalize_request_v2_json,
            request,
            env,
        )?
        .map(|(request, authorized_operation)| {
            StrictRouterNormalSigningRequestV1::Ed25519Finalize {
                request,
                authorized_operation,
            }
        }),
        CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_SIGNING_PREPARE_PUBLIC_REQUEST_PATH => {
            parse_router_public_body_v1(
                &request_body,
                parse_cloudflare_router_authorized_router_ab_ecdsa_derivation_prepare_request_v1_json,
                request,
                env,
            )?
            .map(|(request, authorized_operation)| {
                StrictRouterNormalSigningRequestV1::EcdsaPrepare {
                    request,
                    authorized_operation,
                }
            })
        }
        CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_SIGNING_PUBLIC_REQUEST_PATH => {
            parse_router_public_body_v1(
                &request_body,
                parse_cloudflare_router_authorized_router_ab_ecdsa_derivation_finalize_request_v1_json,
                request,
                env,
            )?
            .map(|(request, authorized_operation)| {
                StrictRouterNormalSigningRequestV1::EcdsaFinalize {
                    request,
                    authorized_operation,
                }
            })
        }
        _ => {
            return Ok(Err(Response::error(
                "Router A/B strict normal-signing route is unavailable",
                404,
            )?));
        }
    };
    Ok(parsed)
}

#[cfg(feature = "strict-worker-router-entrypoint")]
async fn execute_strict_router_normal_signing_request_v1(
    parsed: StrictRouterNormalSigningRequestV1,
    authorization: Option<&CloudflareRouterBearerAuthorizationV1>,
    request: &Request,
    env: &Env,
    runtime: &CloudflareRouterWorkerRuntimeV1,
    now_unix_ms: u64,
    trusted_source_digest: PublicDigest32,
    verifier: CloudflareRouterEd25519JwksJwtVerifierV1,
) -> worker::Result<Response> {
    let operation_step_up = parsed.is_operation_step_up();
    if !operation_step_up && authorization.is_none() {
        return router_json_cors_response_v1::<()>(
            Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "Reusable Wallet Session authorization requires a Bearer credential",
            )),
            request,
            env,
        );
    }
    match parsed {
        StrictRouterNormalSigningRequestV1::Ed25519Prepare {
            request: signing_request,
            authorized_operation,
        } if operation_step_up => {
            let response =
                handle_cloudflare_router_normal_signing_prepare_internal_step_up_request_v2(
                    env,
                    runtime,
                    now_unix_ms,
                    signing_request,
                    authorized_operation,
                    trusted_source_digest,
                )
                .await;
            router_json_cors_response_v1(response, request, env)
        }
        StrictRouterNormalSigningRequestV1::Ed25519Prepare {
            request: signing_request,
            authorized_operation,
        } => {
            let credential = match router_wallet_session_credential_v1(
                authorization.expect("reusable authorization checked"),
                request,
                env,
            )? {
                Ok(credential) => credential,
                Err(response) => return Ok(response),
            };
            let response =
                handle_cloudflare_router_normal_signing_prepare_authenticated_public_request_v2(
                    env,
                    runtime,
                    now_unix_ms,
                    signing_request,
                    authorized_operation,
                    credential,
                    trusted_source_digest,
                    verifier,
                )
                .await;
            router_json_cors_response_v1(response, request, env)
        }
        StrictRouterNormalSigningRequestV1::Ed25519Finalize {
            request: signing_request,
            authorized_operation,
        } if operation_step_up => {
            let response =
                handle_cloudflare_router_normal_signing_finalize_internal_step_up_request_v2(
                    env,
                    runtime,
                    now_unix_ms,
                    signing_request,
                    authorized_operation,
                    trusted_source_digest,
                )
                .await;
            router_json_cors_response_v1(response, request, env)
        }
        StrictRouterNormalSigningRequestV1::Ed25519Finalize {
            request: signing_request,
            authorized_operation,
        } => {
            let credential = match router_wallet_session_credential_v1(
                authorization.expect("reusable authorization checked"),
                request,
                env,
            )? {
                Ok(credential) => credential,
                Err(response) => return Ok(response),
            };
            let response =
                handle_cloudflare_router_normal_signing_finalize_authenticated_public_request_v2(
                    env,
                    runtime,
                    now_unix_ms,
                    signing_request,
                    authorized_operation,
                    credential,
                    trusted_source_digest,
                    verifier,
                )
                .await;
            router_json_cors_response_v1(response, request, env)
        }
        StrictRouterNormalSigningRequestV1::EcdsaPrepare {
            request: signing_request,
            authorized_operation,
        } if operation_step_up => {
            let response = handle_cloudflare_router_ab_ecdsa_derivation_evm_digest_signing_prepare_internal_step_up_request_v1(
                env,
                runtime,
                now_unix_ms,
                signing_request,
                authorized_operation,
                trusted_source_digest,
            )
            .await;
            router_json_cors_response_v1(response, request, env)
        }
        StrictRouterNormalSigningRequestV1::EcdsaPrepare {
            request: signing_request,
            authorized_operation,
        } => {
            let credential = match router_wallet_session_credential_v1(
                authorization.expect("reusable authorization checked"),
                request,
                env,
            )? {
                Ok(credential) => credential,
                Err(response) => return Ok(response),
            };
            let response = handle_cloudflare_router_ab_ecdsa_derivation_evm_digest_signing_prepare_authenticated_public_request_v1(
                env,
                runtime,
                now_unix_ms,
                signing_request,
                authorized_operation,
                credential,
                trusted_source_digest,
                verifier,
            )
            .await;
            router_json_cors_response_v1(response, request, env)
        }
        StrictRouterNormalSigningRequestV1::EcdsaFinalize {
            request: signing_request,
            authorized_operation,
        } if operation_step_up => {
            let response = handle_cloudflare_router_ab_ecdsa_derivation_evm_digest_signing_finalize_internal_step_up_request_v1(
                env,
                runtime,
                now_unix_ms,
                signing_request,
                authorized_operation,
                trusted_source_digest,
            )
            .await;
            router_json_cors_response_v1(response, request, env)
        }
        StrictRouterNormalSigningRequestV1::EcdsaFinalize {
            request: signing_request,
            authorized_operation,
        } => {
            let credential = match router_wallet_session_credential_v1(
                authorization.expect("reusable authorization checked"),
                request,
                env,
            )? {
                Ok(credential) => credential,
                Err(response) => return Ok(response),
            };
            let response = handle_cloudflare_router_ab_ecdsa_derivation_evm_digest_signing_finalize_authenticated_public_request_v1(
                env,
                runtime,
                now_unix_ms,
                signing_request,
                authorized_operation,
                credential,
                trusted_source_digest,
                verifier,
            )
            .await;
            router_json_cors_response_v1(response, request, env)
        }
    }
}

#[cfg(feature = "strict-worker-router-entrypoint")]
async fn handle_router_prewarm_v1(request: &Request, env: &Env) -> worker::Result<Response> {
    if let Err(err) = require_cloudflare_internal_service_auth_request_v1(request, env) {
        return cloudflare_private_service_auth_error_response_v1(err);
    }
    if request.method() != Method::Post {
        return cloudflare_prewarm_response_v1(request);
    }
    if let Err(err) = CloudflareRouterWorkerRuntimeV1::from_worker_env(env) {
        return cloudflare_protocol_error_response_v1(err);
    }
    let result = await_prewarm_fanout_v1(
        prewarm_service_binding_v1(env, "DERIVER_A"),
        prewarm_service_binding_v1(env, "DERIVER_B"),
        prewarm_service_binding_v1(env, "SIGNING_WORKER"),
    )
    .await;
    if result.is_err() {
        return Response::error("Router A/B prewarm fan-out failed", 502);
    }
    cloudflare_prewarm_response_v1(request)
}

#[cfg(feature = "strict-worker-router-entrypoint")]
async fn prewarm_service_binding_v1(env: &Env, binding_name: &str) -> Result<(), ()> {
    let fetcher = env.service(binding_name).map_err(|_| ())?;
    let headers = worker::Headers::new();
    set_cloudflare_internal_service_auth_header_v1(env, &headers, "Worker prewarm")
        .map_err(|_| ())?;
    let mut init = worker::RequestInit::new();
    init.with_method(Method::Post).with_headers(headers);
    let request =
        Request::new_with_init("https://router-ab-prewarm.internal/internal/prewarm", &init)
            .map_err(|_| ())?;
    let response = fetcher.fetch_request(request).await.map_err(|_| ())?;
    if !(200..=299).contains(&response.status_code()) {
        return Err(());
    }
    Ok(())
}

#[cfg(feature = "strict-worker-router-entrypoint")]
async fn await_prewarm_fanout_v1<A, B, C, E>(a: A, b: B, c: C) -> Result<(), E>
where
    A: core::future::Future<Output = Result<(), E>>,
    B: core::future::Future<Output = Result<(), E>>,
    C: core::future::Future<Output = Result<(), E>>,
{
    futures::try_join!(a, b, c)?;
    Ok(())
}

#[cfg(all(test, feature = "strict-worker-router-entrypoint"))]
mod prewarm_tests {
    use super::await_prewarm_fanout_v1;
    use core::task::Poll;
    use futures::future::poll_fn;
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;
    use std::task::Waker;

    fn gated_prewarm_child(
        started: Rc<Cell<usize>>,
        waiting: Rc<RefCell<Vec<Waker>>>,
    ) -> impl core::future::Future<Output = Result<(), ()>> {
        let mut entered = false;
        poll_fn(move |context| {
            if !entered {
                entered = true;
                started.set(started.get() + 1);
            }
            if started.get() == 3 {
                for waker in waiting.borrow_mut().drain(..) {
                    waker.wake();
                }
                return Poll::Ready(Ok(()));
            }
            waiting.borrow_mut().push(context.waker().clone());
            Poll::Pending
        })
    }

    #[test]
    fn router_prewarm_polls_all_three_role_bindings_concurrently() {
        let started = Rc::new(Cell::new(0));
        let waiting = Rc::new(RefCell::new(Vec::new()));
        let result = futures::executor::block_on(await_prewarm_fanout_v1(
            gated_prewarm_child(started.clone(), waiting.clone()),
            gated_prewarm_child(started.clone(), waiting.clone()),
            gated_prewarm_child(started.clone(), waiting),
        ));

        assert_eq!(result, Ok(()));
        assert_eq!(started.get(), 3);
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

/// As `router_json_cors_response_v1`, but attaches the Router's ECDSA boundary
/// spans as `Server-Timing` (Refactor 94B Phase 0). The response body is
/// untouched — the Gateway reads the header and drops it before the browser.
/// A failed leg still carries whatever spans completed before it failed.
#[cfg(feature = "strict-worker-router-entrypoint")]
fn router_ecdsa_timed_json_cors_response_v1<T: serde::Serialize>(
    result: RouterAbProtocolResult<T>,
    timing: &CloudflareEcdsaBoundaryTimingV1,
    request: &Request,
    env: &Env,
) -> worker::Result<Response> {
    let response = router_json_cors_response_v1(result, request, env)?;
    timing.apply_to(&response)?;
    Ok(response)
}

#[cfg(feature = "strict-worker-router-entrypoint")]
fn router_ecdsa_trace_context_v1(
    request: &Request,
    env: &Env,
) -> worker::Result<Result<Option<CloudflareTraceIdV1>, Response>> {
    match parse_cloudflare_trace_id_from_request_v1(request) {
        Ok(trace_id) => Ok(Ok(trace_id)),
        Err(error) => {
            let response = cloudflare_protocol_error_response_v1(error)?;
            Ok(Err(cloudflare_router_normal_signing_response_v1(
                response, request, env,
            )?))
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
        || normalized == CLOUDFLARE_ROUTER_NORMAL_SIGNING_PUBLIC_REQUEST_PATH
}

#[cfg(feature = "strict-worker-router-entrypoint")]
fn is_cloudflare_router_ab_ecdsa_derivation_public_path(path: &str) -> bool {
    let normalized = path.strip_suffix('/').unwrap_or(path);
    normalized == CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_REGISTRATION_PUBLIC_REQUEST_PATH
        || normalized == CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_ACTIVATION_PUBLIC_REQUEST_PATH
        || normalized == CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_ADD_SIGNER_PUBLIC_REQUEST_PATH
        || normalized == CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_EXPORT_PUBLIC_REQUEST_PATH
        || normalized == CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_REFRESH_PUBLIC_REQUEST_PATH
        || normalized == CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_SIGNING_PREPARE_PUBLIC_REQUEST_PATH
        || normalized == CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_SIGNING_PUBLIC_REQUEST_PATH
}

#[cfg(feature = "strict-worker-router-entrypoint")]
fn router_ab_ecdsa_derivation_registration_purpose_for_public_path(
    path: &str,
) -> Option<RouterAbEcdsaDerivationRegistrationPurposeV1> {
    let normalized = path.strip_suffix('/').unwrap_or(path);
    match normalized {
        CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_REGISTRATION_PUBLIC_REQUEST_PATH => {
            Some(RouterAbEcdsaDerivationRegistrationPurposeV1::WalletRegistration)
        }
        CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_ADD_SIGNER_PUBLIC_REQUEST_PATH => {
            Some(RouterAbEcdsaDerivationRegistrationPurposeV1::WalletAddSigner)
        }
        _ => None,
    }
}
