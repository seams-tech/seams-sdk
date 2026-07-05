mod support;

use support::{extract_braced_block_after_marker, extract_function_body, read_src_file};

#[test]
fn strict_router_public_keyset_route_applies_cors_boundary() {
    let strict_worker_rs = read_src_file("strict_worker.rs");
    let route_body = extract_function_body(&strict_worker_rs, "handle_strict_router_fetch_v1");
    for required in [
        "is_cloudflare_router_public_keyset_path",
        "Method::Options",
        "cloudflare_router_public_keyset_preflight_response_v1",
        "cloudflare_router_public_keyset_response_v1",
    ] {
        assert!(
            route_body.contains(required),
            "strict Router keyset route must route through `{required}`"
        );
    }

    let cors_body =
        extract_function_body(&strict_worker_rs, "cloudflare_router_public_keyset_cors_v1");
    assert!(
        cors_body.contains("PUBLIC_KEYSET_CORS_CONFIG_V1"),
        "strict Router keyset CORS wrapper must use the public-keyset config"
    );
    let keyset_config =
        extract_braced_block_after_marker(&strict_worker_rs, "const PUBLIC_KEYSET_CORS_CONFIG_V1");
    for required in [
        "ROUTER_AB_PUBLIC_KEYSET_CORS_ORIGINS_ENV",
        "default_origins: Some(\"*\")",
        "allow_wildcard: true",
    ] {
        assert!(
            keyset_config.contains(required),
            "strict Router keyset CORS config must set `{required}`"
        );
    }
    let apply_cors_body =
        extract_function_body(&strict_worker_rs, "cloudflare_router_apply_cors_v1");
    for required in [
        "Access-Control-Allow-Origin",
        "Access-Control-Allow-Methods",
        "Access-Control-Allow-Headers",
        "Access-Control-Max-Age",
    ] {
        assert!(
            apply_cors_body.contains(required),
            "strict Router shared CORS helper must set `{required}`"
        );
    }
}

#[test]
fn strict_router_normal_signing_routes_apply_cors_boundary() {
    let strict_worker_rs = read_src_file("strict_worker.rs");
    let route_body = extract_function_body(&strict_worker_rs, "handle_strict_router_fetch_v1");
    for required in [
        "is_cloudflare_router_normal_signing_public_path",
        "Method::Options",
        "cloudflare_router_normal_signing_preflight_response_v1",
        "cloudflare_router_normal_signing_response_v1",
        "CLOUDFLARE_ROUTER_NORMAL_SIGNING_ROUND1_PREPARE_PUBLIC_REQUEST_PATH",
        "CLOUDFLARE_ROUTER_NORMAL_SIGNING_PUBLIC_REQUEST_PATH",
    ] {
        assert!(
            route_body.contains(required),
            "strict Router normal-signing route must route through `{required}`"
        );
    }

    let cors_body = extract_function_body(
        &strict_worker_rs,
        "cloudflare_router_normal_signing_cors_v1",
    );
    assert!(
        cors_body.contains("NORMAL_SIGNING_CORS_CONFIG_V1"),
        "strict Router normal-signing CORS wrapper must use the normal-signing config"
    );
    let normal_config =
        extract_braced_block_after_marker(&strict_worker_rs, "const NORMAL_SIGNING_CORS_CONFIG_V1");
    for required in [
        "ROUTER_AB_NORMAL_SIGNING_CORS_ORIGINS_ENV",
        "default_origins: None",
        "allow_wildcard: false",
    ] {
        assert!(
            normal_config.contains(required),
            "strict Router normal-signing CORS config must set `{required}`"
        );
    }
    let apply_cors_body =
        extract_function_body(&strict_worker_rs, "cloudflare_router_apply_cors_v1");
    for required in [
        "Access-Control-Allow-Origin",
        "Access-Control-Allow-Methods",
        "Access-Control-Allow-Headers",
        "Access-Control-Max-Age",
    ] {
        assert!(
            apply_cors_body.contains(required),
            "strict Router shared CORS helper must set `{required}`"
        );
    }
    let origin_body = extract_function_body(
        &strict_worker_rs,
        "cloudflare_router_cors_allowed_origin_v1",
    );
    assert!(
        origin_body.contains("cloudflare_router_normal_signing_cors_allowed_origin_v1"),
        "strict Router normal-signing CORS helper must use the exact-origin allowlist parser"
    );
    assert!(
        !normal_config.contains("Some(\"*\")"),
        "strict Router normal-signing CORS must not default bearer routes to wildcard Origin"
    );
    assert!(
        !normal_config.contains("allow_wildcard: true"),
        "strict Router normal-signing CORS must not allow wildcard Origins"
    );
    assert!(
        !cors_body.contains("Access-Control-Allow-Credentials"),
        "bearer-only normal-signing CORS must not enable credentialed browser requests"
    );
}
