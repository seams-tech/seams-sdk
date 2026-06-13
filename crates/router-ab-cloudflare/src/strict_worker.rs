#![cfg(any(
    feature = "strict-worker-entrypoint",
    feature = "strict-worker-router-entrypoint",
    feature = "strict-worker-signer-a-entrypoint",
    feature = "strict-worker-signer-b-entrypoint",
    feature = "strict-worker-signing-worker-entrypoint"
))]

use crate::{
    cloudflare_now_unix_ms_v1, cloudflare_router_error_status, cloudflare_trusted_source_digest_v1,
    decrypt_and_handle_cloudflare_mpc_prf_recipient_proof_bundle_signer_private_request_v1,
    handle_cloudflare_router_normal_signing_authenticated_public_request_v1,
    handle_cloudflare_router_recipient_proof_bundle_authenticated_public_request_v1,
    handle_cloudflare_signing_worker_normal_signing_private_fetch_v1,
    handle_cloudflare_signing_worker_recipient_proof_bundle_activation_fetch_v1,
    load_cloudflare_router_ed25519_jwks_jwt_verifier_v1,
    parse_cloudflare_router_bearer_authorization_from_request_v1,
    preload_cloudflare_deriver_a_host_v1, preload_cloudflare_deriver_b_host_v1,
    CloudflareEnvReaderV1, CloudflareRouterWorkerRuntimeV1, CloudflareSignerAWorkerRuntimeV1,
    CloudflareSignerBWorkerRuntimeV1, CloudflareSignerHostPreloadPlanV1,
    CloudflareSignerPrivateBootstrapRequestV1,
    CloudflareSigningWorkerMaterializedNormalSigningRequestV1,
    CloudflareSigningWorkerNormalSigningHandlerV1, CloudflareSigningWorkerRuntimeV1,
    CloudflareWorkerEnvReaderV1, CloudflareWorkerRoleV1,
    CLOUDFLARE_ROUTER_NORMAL_SIGNING_PUBLIC_REQUEST_PATH_V1,
    CLOUDFLARE_ROUTER_PUBLIC_REQUEST_PATH_V1, CLOUDFLARE_SIGNER_A_PRIVATE_REQUEST_PATH_V1,
    CLOUDFLARE_SIGNER_B_PRIVATE_REQUEST_PATH_V1, CLOUDFLARE_SIGNING_WORKER_NORMAL_SIGNING_PATH_V1,
    CLOUDFLARE_SIGNING_WORKER_PROOF_BUNDLE_ACTIVATION_PATH_V1,
};
use router_ab_core::{
    NormalSigningRequestV1, NormalSigningResponseV1, PublicRouterRequestV1, Role,
    RouterAbProtocolError, RouterAbProtocolErrorCode, RouterAbProtocolResult,
};
use serde::{Deserialize, Serialize};
use worker::{Context, Env, Method, Request, Response};

/// Worker Env key that selects the Router/A/B role for this deployed bundle.
pub const ROUTER_AB_WORKER_ROLE_ENV: &str = "ROUTER_AB_WORKER_ROLE";
/// Worker Env key that selects the route profile for this deployed bundle.
pub const ROUTER_AB_ROUTE_PROFILE_ENV: &str = "ROUTER_AB_ROUTE_PROFILE";
/// Strict proof-bundle route profile value.
pub const ROUTER_AB_STRICT_PROOF_BUNDLE_ROUTE_PROFILE_V1: &str = "strict_proof_bundle";

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
    if request.method() != Method::Post {
        return Response::error("Router A/B strict public route requires POST", 405);
    }
    let path = request.path();
    if path != CLOUDFLARE_ROUTER_PUBLIC_REQUEST_PATH_V1
        && path != CLOUDFLARE_ROUTER_NORMAL_SIGNING_PUBLIC_REQUEST_PATH_V1
    {
        return Response::error(
            format!(
                "Router A/B strict public request must be served at {} or {}",
                CLOUDFLARE_ROUTER_PUBLIC_REQUEST_PATH_V1,
                CLOUDFLARE_ROUTER_NORMAL_SIGNING_PUBLIC_REQUEST_PATH_V1
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

    if path == CLOUDFLARE_ROUTER_NORMAL_SIGNING_PUBLIC_REQUEST_PATH_V1 {
        let normal_signing_request = match request.json::<NormalSigningRequestV1>().await {
            Ok(parsed) => parsed,
            Err(err) => {
                return Response::error(
                    format!("Router A/B strict normal-signing request JSON parse failed: {err}"),
                    400,
                );
            }
        };
        return match handle_cloudflare_router_normal_signing_authenticated_public_request_v1(
            &env,
            &runtime,
            now_unix_ms,
            normal_signing_request,
            authorization,
            trusted_source_digest,
            verifier,
        )
        .await
        {
            Ok(response) => Response::from_json(&response),
            Err(err) => cloudflare_protocol_error_response_v1(err),
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
    if request.path() == CLOUDFLARE_SIGNING_WORKER_NORMAL_SIGNING_PATH_V1 {
        let now_unix_ms = match cloudflare_now_unix_ms_v1() {
            Ok(now_unix_ms) => now_unix_ms,
            Err(err) => return cloudflare_protocol_error_response_v1(err),
        };
        let handler = CloudflareStrictSigningWorkerNormalSigningHandlerV1;
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
            "SigningWorker strict Worker route must be served at {} or {}",
            CLOUDFLARE_SIGNING_WORKER_PROOF_BUNDLE_ACTIVATION_PATH_V1,
            CLOUDFLARE_SIGNING_WORKER_NORMAL_SIGNING_PATH_V1
        ),
        404,
    )
}

struct CloudflareStrictSigningWorkerNormalSigningHandlerV1;

impl CloudflareSigningWorkerNormalSigningHandlerV1
    for CloudflareStrictSigningWorkerNormalSigningHandlerV1
{
    fn handle_normal_signing_request(
        &self,
        _request: CloudflareSigningWorkerMaterializedNormalSigningRequestV1,
    ) -> RouterAbProtocolResult<NormalSigningResponseV1> {
        Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "strict SigningWorker normal-signing handler is not configured",
        ))
    }
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
