use super::*;

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

#[cfg(feature = "strict-worker-router-entrypoint")]
struct CloudflareRouterCorsConfigV1 {
    origins_env: &'static str,
    default_origins: Option<&'static str>,
    allow_wildcard: bool,
    allow_methods: &'static str,
    allow_headers: &'static str,
}

#[cfg(feature = "strict-worker-router-entrypoint")]
const PUBLIC_KEYSET_CORS_CONFIG_V1: CloudflareRouterCorsConfigV1 = CloudflareRouterCorsConfigV1 {
    origins_env: ROUTER_AB_PUBLIC_KEYSET_CORS_ORIGINS_ENV,
    default_origins: Some("*"),
    allow_wildcard: true,
    allow_methods: ROUTER_AB_PUBLIC_KEYSET_CORS_ALLOW_METHODS_V1,
    allow_headers: ROUTER_AB_PUBLIC_KEYSET_CORS_ALLOW_HEADERS_V1,
};

#[cfg(feature = "strict-worker-router-entrypoint")]
const NORMAL_SIGNING_CORS_CONFIG_V1: CloudflareRouterCorsConfigV1 = CloudflareRouterCorsConfigV1 {
    origins_env: ROUTER_AB_NORMAL_SIGNING_CORS_ORIGINS_ENV,
    default_origins: None,
    allow_wildcard: false,
    allow_methods: ROUTER_AB_NORMAL_SIGNING_CORS_ALLOW_METHODS_V1,
    allow_headers: ROUTER_AB_NORMAL_SIGNING_CORS_ALLOW_HEADERS_V1,
};

#[cfg(feature = "strict-worker-router-entrypoint")]
pub(super) fn cloudflare_router_public_keyset_preflight_response_v1(
    request: &Request,
    env: &Env,
) -> worker::Result<Response> {
    let response = Response::empty()?.with_status(204);
    cloudflare_router_public_keyset_response_v1(response, request, env)
}

#[cfg(feature = "strict-worker-router-entrypoint")]
pub(super) fn cloudflare_router_public_keyset_response_v1(
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
pub(super) fn cloudflare_router_public_keyset_cors_v1(
    response: &mut Response,
    request: &Request,
    env: &Env,
) -> worker::Result<()> {
    cloudflare_router_apply_cors_v1(response, request, env, &PUBLIC_KEYSET_CORS_CONFIG_V1)
}

#[cfg(feature = "strict-worker-router-entrypoint")]
pub(super) fn cloudflare_router_normal_signing_preflight_response_v1(
    request: &Request,
    env: &Env,
) -> worker::Result<Response> {
    let response = Response::empty()?.with_status(204);
    cloudflare_router_normal_signing_response_v1(response, request, env)
}

#[cfg(feature = "strict-worker-router-entrypoint")]
pub(super) fn cloudflare_router_normal_signing_response_v1(
    mut response: Response,
    request: &Request,
    env: &Env,
) -> worker::Result<Response> {
    cloudflare_router_normal_signing_cors_v1(&mut response, request, env)?;
    Ok(response)
}

#[cfg(feature = "strict-worker-router-entrypoint")]
pub(super) fn cloudflare_router_normal_signing_cors_v1(
    response: &mut Response,
    request: &Request,
    env: &Env,
) -> worker::Result<()> {
    cloudflare_router_apply_cors_v1(response, request, env, &NORMAL_SIGNING_CORS_CONFIG_V1)
}

#[cfg(feature = "strict-worker-router-entrypoint")]
fn cloudflare_router_apply_cors_v1(
    response: &mut Response,
    request: &Request,
    env: &Env,
    config: &CloudflareRouterCorsConfigV1,
) -> worker::Result<()> {
    let configured = env
        .var(config.origins_env)
        .ok()
        .map(|value| value.to_string())
        .or_else(|| config.default_origins.map(str::to_owned));
    let origin_header = request.headers().get("Origin")?.unwrap_or_default();
    let allow_origin = cloudflare_router_cors_allowed_origin_v1(
        configured.as_deref(),
        origin_header.as_str(),
        config.allow_wildcard,
    );
    let headers = response.headers_mut();
    if let Some(origin) = allow_origin.as_deref() {
        headers.set("Access-Control-Allow-Origin", origin)?;
        if origin != "*" {
            headers.append("Vary", "Origin")?;
        }
    }
    headers.set("Access-Control-Allow-Methods", config.allow_methods)?;
    headers.set("Access-Control-Allow-Headers", config.allow_headers)?;
    headers.set("Access-Control-Max-Age", "600")?;
    Ok(())
}

#[cfg(feature = "strict-worker-router-entrypoint")]
fn cloudflare_router_cors_allowed_origin_v1(
    configured: Option<&str>,
    request_origin: &str,
    allow_wildcard: bool,
) -> Option<String> {
    if !allow_wildcard {
        return cloudflare_router_normal_signing_cors_allowed_origin_v1(configured, request_origin);
    }
    let configured = configured?;
    let origins = configured
        .split(',')
        .map(str::trim)
        .filter(|origin| !origin.is_empty())
        .collect::<Vec<_>>();
    if origins.is_empty() || origins.iter().any(|origin| *origin == "*") {
        return Some("*".to_string());
    }
    origins
        .iter()
        .any(|origin| *origin == request_origin)
        .then(|| request_origin.to_string())
}
