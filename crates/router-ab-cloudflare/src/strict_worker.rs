#![cfg(any(
    feature = "strict-worker-entrypoint",
    feature = "strict-worker-router-entrypoint",
    feature = "strict-worker-signer-a-entrypoint",
    feature = "strict-worker-signer-b-entrypoint",
    feature = "strict-worker-signing-worker-entrypoint"
))]

use crate::{
    build_cloudflare_router_public_keyset_v1, cloudflare_now_unix_ms_v1,
    cloudflare_router_error_status, cloudflare_router_normal_signing_cors_allowed_origin_v1,
    cloudflare_trusted_source_digest_v1,
    decrypt_and_handle_cloudflare_mpc_prf_recipient_proof_bundle_signer_private_request_v1,
    handle_cloudflare_router_normal_signing_finalize_authenticated_public_request_v2,
    handle_cloudflare_router_normal_signing_prepare_authenticated_public_request_v2,
    handle_cloudflare_router_recipient_proof_bundle_authenticated_public_request_v1,
    handle_cloudflare_signing_worker_normal_signing_private_fetch_v1,
    handle_cloudflare_signing_worker_normal_signing_round1_prepare_private_fetch_v1,
    handle_cloudflare_signing_worker_recipient_proof_bundle_activation_fetch_v1,
    load_cloudflare_router_ed25519_jwks_jwt_verifier_v1,
    parse_cloudflare_router_bearer_authorization_from_request_v1,
    preload_cloudflare_deriver_a_host_v1, preload_cloudflare_deriver_b_host_v1,
    CloudflareEnvReaderV1, CloudflareRoleSeparatedEd25519NormalSigningHandlerV1,
    CloudflareRouterWalletSessionCredentialV1, CloudflareRouterWorkerRuntimeV1,
    CloudflareSignerAWorkerRuntimeV1, CloudflareSignerBWorkerRuntimeV1,
    CloudflareSignerHostPreloadPlanV1, CloudflareSignerPrivateBootstrapRequestV1,
    CloudflareSigningWorkerRuntimeV1, CloudflareWorkerEnvReaderV1, CloudflareWorkerRoleV1,
    CLOUDFLARE_ROUTER_NORMAL_SIGNING_PUBLIC_REQUEST_PATH_V2,
    CLOUDFLARE_ROUTER_NORMAL_SIGNING_ROUND1_PREPARE_PUBLIC_REQUEST_PATH_V2,
    CLOUDFLARE_ROUTER_PUBLIC_KEYSET_PATH_V1, CLOUDFLARE_ROUTER_PUBLIC_KEYSET_WELL_KNOWN_PATH_V1,
    CLOUDFLARE_ROUTER_PUBLIC_REQUEST_PATH_V1, CLOUDFLARE_SIGNER_A_PRIVATE_REQUEST_PATH_V1,
    CLOUDFLARE_SIGNER_B_PRIVATE_REQUEST_PATH_V1, CLOUDFLARE_SIGNING_WORKER_NORMAL_SIGNING_PATH_V1,
    CLOUDFLARE_SIGNING_WORKER_NORMAL_SIGNING_ROUND1_PREPARE_PATH_V1,
    CLOUDFLARE_SIGNING_WORKER_PROOF_BUNDLE_ACTIVATION_PATH_V1,
};
use router_ab_core::{
    parse_router_ab_ed25519_normal_signing_finalize_request_v2_json,
    parse_router_ab_ed25519_normal_signing_prepare_request_v2_json, PublicRouterRequestV1, Role,
    RouterAbProtocolError, RouterAbProtocolErrorCode, RouterAbProtocolResult,
};
use serde::{Deserialize, Serialize};
use worker::{Context, Env, Method, Request, Response};

/// Worker Env key that selects the Router/A/B role for this deployed bundle.
pub const ROUTER_AB_WORKER_ROLE_ENV: &str = "ROUTER_AB_WORKER_ROLE";
/// Worker Env key that selects the route profile for this deployed bundle.
pub const ROUTER_AB_ROUTE_PROFILE_ENV: &str = "ROUTER_AB_ROUTE_PROFILE";
/// Optional comma-separated Origin allowlist for the public Router/A/B keyset route.
pub const ROUTER_AB_PUBLIC_KEYSET_CORS_ORIGINS_ENV: &str = "ROUTER_AB_PUBLIC_KEYSET_CORS_ORIGINS";
/// Required comma-separated Origin allowlist for public normal-signing routes.
pub const ROUTER_AB_NORMAL_SIGNING_CORS_ORIGINS_ENV: &str = "ROUTER_AB_NORMAL_SIGNING_CORS_ORIGINS";
/// Strict proof-bundle route profile value.
pub const ROUTER_AB_STRICT_PROOF_BUNDLE_ROUTE_PROFILE_V1: &str = "strict_proof_bundle";

const ROUTER_AB_PUBLIC_KEYSET_CACHE_CONTROL_V1: &str = "max-age=60, stale-while-revalidate=600";
const ROUTER_AB_PUBLIC_KEYSET_CORS_ALLOW_METHODS_V1: &str = "GET,OPTIONS";
const ROUTER_AB_PUBLIC_KEYSET_CORS_ALLOW_HEADERS_V1: &str = "Accept,Content-Type,Authorization";
const ROUTER_AB_NORMAL_SIGNING_CORS_ALLOW_METHODS_V1: &str = "POST,OPTIONS";
const ROUTER_AB_NORMAL_SIGNING_CORS_ALLOW_HEADERS_V1: &str = "Accept,Content-Type,Authorization";

/// Strict Worker route profile selected at startup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CloudflareStrictRouteProfileV1 {
    /// Strict recipient proof-bundle delivery.
    StrictProofBundle,
}

impl CloudflareStrictRouteProfileV1 {
    /// Returns the stable Env value for this profile.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StrictProofBundle => ROUTER_AB_STRICT_PROOF_BUNDLE_ROUTE_PROFILE_V1,
        }
    }
}

/// Deployable workers-rs fetch entrypoint for strict Router/A/B proof-bundle Workers.
#[worker::event(fetch)]
pub async fn fetch(request: Request, env: Env, _ctx: Context) -> worker::Result<Response> {
    #[cfg(feature = "strict-worker-entrypoint")]
    {
        return handle_cloudflare_strict_worker_fetch_v1(request, env).await;
    }
    #[cfg(feature = "strict-worker-router-entrypoint")]
    {
        if let Err(err) = require_cloudflare_strict_route_profile_v1(&env) {
            return cloudflare_protocol_error_response_v1(err);
        }
        return handle_strict_router_fetch_v1(request, env).await;
    }
    #[cfg(feature = "strict-worker-signer-a-entrypoint")]
    {
        if let Err(err) = require_cloudflare_strict_route_profile_v1(&env) {
            return cloudflare_protocol_error_response_v1(err);
        }
        return handle_strict_signer_a_fetch_v1(request, env).await;
    }
    #[cfg(feature = "strict-worker-signer-b-entrypoint")]
    {
        if let Err(err) = require_cloudflare_strict_route_profile_v1(&env) {
            return cloudflare_protocol_error_response_v1(err);
        }
        return handle_strict_signer_b_fetch_v1(request, env).await;
    }
    #[cfg(feature = "strict-worker-signing-worker-entrypoint")]
    {
        if let Err(err) = require_cloudflare_strict_route_profile_v1(&env) {
            return cloudflare_protocol_error_response_v1(err);
        }
        return handle_strict_signing_worker_fetch_v1(request, env).await;
    }
}

/// Dispatches one strict proof-bundle Worker request by configured Router/A/B role.
pub async fn handle_cloudflare_strict_worker_fetch_v1(
    request: Request,
    env: Env,
) -> worker::Result<Response> {
    let role = match parse_cloudflare_strict_worker_role_v1(&env) {
        Ok(role) => role,
        Err(err) => return cloudflare_protocol_error_response_v1(err),
    };
    if let Err(err) = require_cloudflare_strict_route_profile_v1(&env) {
        return cloudflare_protocol_error_response_v1(err);
    }
    match role {
        CloudflareWorkerRoleV1::Router => handle_strict_router_fetch_v1(request, env).await,
        CloudflareWorkerRoleV1::SignerA => handle_strict_signer_a_fetch_v1(request, env).await,
        CloudflareWorkerRoleV1::SignerB => handle_strict_signer_b_fetch_v1(request, env).await,
        CloudflareWorkerRoleV1::SigningWorker => {
            handle_strict_signing_worker_fetch_v1(request, env).await
        }
    }
}

/// Parses the configured strict Worker role from Env.
pub fn parse_cloudflare_strict_worker_role_v1(
    env: &Env,
) -> RouterAbProtocolResult<CloudflareWorkerRoleV1> {
    let value = require_cloudflare_bootstrap_env_text_v1(env, ROUTER_AB_WORKER_ROLE_ENV)?;
    match value.as_str() {
        "router" => Ok(CloudflareWorkerRoleV1::Router),
        "signer_a" => Ok(CloudflareWorkerRoleV1::SignerA),
        "signer_b" => Ok(CloudflareWorkerRoleV1::SignerB),
        "signing_worker" => Ok(CloudflareWorkerRoleV1::SigningWorker),
        _ => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "Router A/B Worker role Env value is unsupported",
        )),
    }
}

/// Parses the configured strict route profile from Env.
pub fn parse_cloudflare_strict_route_profile_v1(
    env: &Env,
) -> RouterAbProtocolResult<CloudflareStrictRouteProfileV1> {
    let value = require_cloudflare_bootstrap_env_text_v1(env, ROUTER_AB_ROUTE_PROFILE_ENV)?;
    match value.as_str() {
        ROUTER_AB_STRICT_PROOF_BUNDLE_ROUTE_PROFILE_V1 => {
            Ok(CloudflareStrictRouteProfileV1::StrictProofBundle)
        }
        _ => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "Router A/B route profile Env value is unsupported",
        )),
    }
}

fn require_cloudflare_strict_route_profile_v1(env: &Env) -> RouterAbProtocolResult<()> {
    let profile = parse_cloudflare_strict_route_profile_v1(env)?;
    if profile == CloudflareStrictRouteProfileV1::StrictProofBundle {
        return Ok(());
    }
    Err(RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
        "Router A/B Worker route profile must be strict proof-bundle",
    ))
}

async fn handle_strict_router_fetch_v1(mut request: Request, env: Env) -> worker::Result<Response> {
    let path = request.path();
    if is_cloudflare_router_public_keyset_path_v1(&path) {
        if request.method() == Method::Options {
            return cloudflare_router_public_keyset_preflight_response_v1(&request, &env);
        }
        if request.method() != Method::Get {
            let response = Response::error("Router A/B public keyset route requires GET", 405)?;
            return cloudflare_router_public_keyset_response_v1(response, &request, &env);
        }
        let reader = CloudflareWorkerEnvReaderV1::new(&env);
        let response = match build_cloudflare_router_public_keyset_v1(&reader) {
            Ok(keyset) => Response::from_json(&keyset)?,
            Err(err) => cloudflare_protocol_error_response_v1(err)?,
        };
        return cloudflare_router_public_keyset_response_v1(response, &request, &env);
    }

    if request.method() == Method::Options
        && is_cloudflare_router_normal_signing_public_path_v2(&path)
    {
        return cloudflare_router_normal_signing_preflight_response_v1(&request, &env);
    }

    if request.method() != Method::Post {
        return Response::error("Router A/B strict public route requires POST", 405);
    }
    if path != CLOUDFLARE_ROUTER_PUBLIC_REQUEST_PATH_V1
        && path != CLOUDFLARE_ROUTER_NORMAL_SIGNING_ROUND1_PREPARE_PUBLIC_REQUEST_PATH_V2
        && path != CLOUDFLARE_ROUTER_NORMAL_SIGNING_PUBLIC_REQUEST_PATH_V2
    {
        return Response::error(
            format!(
                "Router A/B strict public request must be served at {}, {}, or {}",
                CLOUDFLARE_ROUTER_PUBLIC_REQUEST_PATH_V1,
                CLOUDFLARE_ROUTER_NORMAL_SIGNING_ROUND1_PREPARE_PUBLIC_REQUEST_PATH_V2,
                CLOUDFLARE_ROUTER_NORMAL_SIGNING_PUBLIC_REQUEST_PATH_V2
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
        let finalize_request =
            match parse_router_ab_ed25519_normal_signing_finalize_request_v2_json(&request_body) {
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
        return match handle_cloudflare_router_normal_signing_finalize_authenticated_public_request_v2(
            &env,
            &runtime,
            now_unix_ms,
            finalize_request,
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

fn is_cloudflare_router_public_keyset_path_v1(path: &str) -> bool {
    let normalized = path.strip_suffix('/').unwrap_or(path);
    normalized == CLOUDFLARE_ROUTER_PUBLIC_KEYSET_WELL_KNOWN_PATH_V1
        || normalized == CLOUDFLARE_ROUTER_PUBLIC_KEYSET_PATH_V1
}

fn is_cloudflare_router_normal_signing_public_path_v2(path: &str) -> bool {
    let normalized = path.strip_suffix('/').unwrap_or(path);
    normalized == CLOUDFLARE_ROUTER_NORMAL_SIGNING_ROUND1_PREPARE_PUBLIC_REQUEST_PATH_V2
        || normalized == CLOUDFLARE_ROUTER_NORMAL_SIGNING_PUBLIC_REQUEST_PATH_V2
}

fn cloudflare_router_public_keyset_preflight_response_v1(
    request: &Request,
    env: &Env,
) -> worker::Result<Response> {
    let response = Response::empty()?.with_status(204);
    cloudflare_router_public_keyset_response_v1(response, request, env)
}

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

fn cloudflare_router_normal_signing_preflight_response_v1(
    request: &Request,
    env: &Env,
) -> worker::Result<Response> {
    let response = Response::empty()?.with_status(204);
    cloudflare_router_normal_signing_response_v1(response, request, env)
}

fn cloudflare_router_normal_signing_response_v1(
    mut response: Response,
    request: &Request,
    env: &Env,
) -> worker::Result<Response> {
    cloudflare_router_normal_signing_cors_v1(&mut response, request, env)?;
    Ok(response)
}

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

async fn handle_strict_signer_a_fetch_v1(
    mut request: Request,
    env: Env,
) -> worker::Result<Response> {
    let runtime = match CloudflareSignerAWorkerRuntimeV1::from_worker_env(&env) {
        Ok(runtime) => runtime,
        Err(err) => return cloudflare_protocol_error_response_v1(err),
    };
    if request.path() == CLOUDFLARE_SIGNER_A_PRIVATE_REQUEST_PATH_V1 {
        let bootstrap = match request
            .json::<CloudflareSignerPrivateBootstrapRequestV1>()
            .await
        {
            Ok(parsed) => parsed,
            Err(err) => {
                return Response::error(
                    format!("Router A/B strict Signer A bootstrap JSON parse failed: {err}"),
                    400,
                );
            }
        };
        if let Err(err) = bootstrap.validate_for_worker_role(CloudflareWorkerRoleV1::SignerA) {
            return cloudflare_protocol_error_response_v1(err);
        }
        let preload_plan = match CloudflareSignerHostPreloadPlanV1::from_private_bootstrap(
            CloudflareWorkerRoleV1::SignerA,
            &bootstrap,
        ) {
            Ok(plan) => plan,
            Err(err) => return cloudflare_protocol_error_response_v1(err),
        };
        let verifying_keys =
            match runtime.peer_verifying_keys_for_signer_set(&preload_plan.signer_set) {
                Ok(keys) => keys,
                Err(err) => return cloudflare_protocol_error_response_v1(err),
            };
        let preload_input = match preload_plan.to_host_preload_input(Vec::new(), verifying_keys, 0)
        {
            Ok(input) => input,
            Err(err) => return cloudflare_protocol_error_response_v1(err),
        };
        let host = match preload_cloudflare_deriver_a_host_v1(&env, &runtime, preload_input).await {
            Ok(host) => host,
            Err(err) => return cloudflare_protocol_error_response_v1(err),
        };
        let root_share_metadata =
            match host.root_share_startup_metadata(Role::SignerA, &preload_plan.root_share_epoch) {
                Ok(metadata) => metadata,
                Err(err) => return cloudflare_protocol_error_response_v1(err),
            };
        let message = bootstrap.message;
        let aad = bootstrap.aad;
        let router_request_digest = bootstrap.router_request_digest;
        return match decrypt_and_handle_cloudflare_mpc_prf_recipient_proof_bundle_signer_private_request_v1(
            &env,
            CloudflareWorkerRoleV1::SignerA,
            &host,
            message,
            runtime.envelope_decrypt_key(),
            runtime.peer_signing_key(),
            &aad,
            router_request_digest,
            root_share_metadata,
        )
        .await
        {
            Ok(response) => Response::from_json(&response),
            Err(err) => cloudflare_protocol_error_response_v1(err),
        };
    }
    Response::error(
        format!(
            "Signer A strict Worker route must be served at {}",
            CLOUDFLARE_SIGNER_A_PRIVATE_REQUEST_PATH_V1
        ),
        404,
    )
}

async fn handle_strict_signing_worker_fetch_v1(
    request: Request,
    env: Env,
) -> worker::Result<Response> {
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
    Response::error(
        format!(
            "SigningWorker strict Worker route must be served at {}, {}, or {}",
            CLOUDFLARE_SIGNING_WORKER_PROOF_BUNDLE_ACTIVATION_PATH_V1,
            CLOUDFLARE_SIGNING_WORKER_NORMAL_SIGNING_ROUND1_PREPARE_PATH_V1,
            CLOUDFLARE_SIGNING_WORKER_NORMAL_SIGNING_PATH_V1
        ),
        404,
    )
}

async fn handle_strict_signer_b_fetch_v1(
    mut request: Request,
    env: Env,
) -> worker::Result<Response> {
    let runtime = match CloudflareSignerBWorkerRuntimeV1::from_worker_env(&env) {
        Ok(runtime) => runtime,
        Err(err) => return cloudflare_protocol_error_response_v1(err),
    };
    if request.path() == CLOUDFLARE_SIGNER_B_PRIVATE_REQUEST_PATH_V1 {
        let bootstrap = match request
            .json::<CloudflareSignerPrivateBootstrapRequestV1>()
            .await
        {
            Ok(parsed) => parsed,
            Err(err) => {
                return Response::error(
                    format!("Router A/B strict Signer B bootstrap JSON parse failed: {err}"),
                    400,
                );
            }
        };
        if let Err(err) = bootstrap.validate_for_worker_role(CloudflareWorkerRoleV1::SignerB) {
            return cloudflare_protocol_error_response_v1(err);
        }
        let preload_plan = match CloudflareSignerHostPreloadPlanV1::from_private_bootstrap(
            CloudflareWorkerRoleV1::SignerB,
            &bootstrap,
        ) {
            Ok(plan) => plan,
            Err(err) => return cloudflare_protocol_error_response_v1(err),
        };
        let verifying_keys =
            match runtime.peer_verifying_keys_for_signer_set(&preload_plan.signer_set) {
                Ok(keys) => keys,
                Err(err) => return cloudflare_protocol_error_response_v1(err),
            };
        let preload_input = match preload_plan.to_host_preload_input(Vec::new(), verifying_keys, 0)
        {
            Ok(input) => input,
            Err(err) => return cloudflare_protocol_error_response_v1(err),
        };
        let host = match preload_cloudflare_deriver_b_host_v1(&env, &runtime, preload_input).await {
            Ok(host) => host,
            Err(err) => return cloudflare_protocol_error_response_v1(err),
        };
        let root_share_metadata =
            match host.root_share_startup_metadata(Role::SignerB, &preload_plan.root_share_epoch) {
                Ok(metadata) => metadata,
                Err(err) => return cloudflare_protocol_error_response_v1(err),
            };
        let message = bootstrap.message;
        let aad = bootstrap.aad;
        let router_request_digest = bootstrap.router_request_digest;
        return match decrypt_and_handle_cloudflare_mpc_prf_recipient_proof_bundle_signer_private_request_v1(
            &env,
            CloudflareWorkerRoleV1::SignerB,
            &host,
            message,
            runtime.envelope_decrypt_key(),
            runtime.peer_signing_key(),
            &aad,
            router_request_digest,
            root_share_metadata,
        )
        .await
        {
            Ok(response) => Response::from_json(&response),
            Err(err) => cloudflare_protocol_error_response_v1(err),
        };
    }
    Response::error(
        format!(
            "Signer B strict Worker route must be served at {}",
            CLOUDFLARE_SIGNER_B_PRIVATE_REQUEST_PATH_V1
        ),
        404,
    )
}

fn require_cloudflare_bootstrap_env_text_v1(
    env: &Env,
    key: &str,
) -> RouterAbProtocolResult<String> {
    let reader = CloudflareWorkerEnvReaderV1::new(env);
    let value = reader.get_text(key)?.ok_or_else(|| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MissingLocalBinding,
            format!("Router A/B bootstrap Env key {key} is missing"),
        )
    })?;
    let value = value.trim().to_string();
    if value.is_empty() {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::EmptyField,
            format!("Router A/B bootstrap Env key {key} must be non-empty"),
        ));
    }
    Ok(value)
}

fn cloudflare_protocol_error_response_v1(err: RouterAbProtocolError) -> worker::Result<Response> {
    Response::error(
        format!("{:?}: {}", err.code(), err.message()),
        cloudflare_router_error_status(err.code()),
    )
}
