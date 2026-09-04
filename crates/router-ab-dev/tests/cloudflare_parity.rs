use router_ab_cloudflare::{
    cloudflare_service_json_request_body_bytes_v1, CLOUDFLARE_DERIVER_A_PEER_REQUEST_PATH,
    CLOUDFLARE_DERIVER_A_PRIVATE_REQUEST_PATH, CLOUDFLARE_DERIVER_B_PEER_REQUEST_PATH,
    CLOUDFLARE_DERIVER_B_PRIVATE_REQUEST_PATH,
    CLOUDFLARE_ROUTER_NORMAL_SIGNING_PUBLIC_REQUEST_PATH,
    CLOUDFLARE_SIGNING_WORKER_NORMAL_SIGNING_PATH,
};
use router_ab_dev::{
    local_dev_http_handle_request_v1, local_env_materialization_plan_v1,
    local_worker_owned_paths_v1, parse_local_env_file_contents_v1,
    parse_local_worker_role_config_for_role_v1, run_example_local_router_ab_dev_http_ceremony_v1,
    LocalDevHttpRequestPartsV1, LocalDevHttpTopologyV1, LOCAL_DERIVER_A_ED25519_YAO_BURN_PAIR_PATH,
    LOCAL_DERIVER_A_ED25519_YAO_EXECUTE_PAIR_PATH, LOCAL_DERIVER_A_ED25519_YAO_PREPARE_PAIR_PATH,
    LOCAL_DERIVER_A_ED25519_YAO_READ_PAIR_STATUS_PATH, LOCAL_DERIVER_A_PEER_PATH,
    LOCAL_DERIVER_A_PRIVATE_PATH, LOCAL_DERIVER_B_ED25519_YAO_BURN_PAIR_PATH,
    LOCAL_DERIVER_B_ED25519_YAO_PREPARE_PAIR_PATH,
    LOCAL_DERIVER_B_ED25519_YAO_READ_PAIR_STATUS_PATH, LOCAL_DERIVER_B_PEER_PATH,
    LOCAL_DERIVER_B_PRIVATE_PATH, LOCAL_ROUTER_AB_INTERNAL_SERVICE_AUTH_DEFAULT_SECRET_V1,
    LOCAL_ROUTER_ED25519_YAO_EXECUTE_PATH, LOCAL_ROUTER_ED25519_YAO_RECOVERY_PROMOTE_PATH,
    LOCAL_ROUTER_NORMAL_SIGNING_PATH, LOCAL_SIGNING_WORKER_NORMAL_SIGNING_PATH,
};

#[test]
fn local_worker_routes_match_cloudflare_worker_routes() {
    assert_eq!(
        LOCAL_ROUTER_NORMAL_SIGNING_PATH,
        CLOUDFLARE_ROUTER_NORMAL_SIGNING_PUBLIC_REQUEST_PATH
    );
    assert_eq!(
        LOCAL_DERIVER_A_PRIVATE_PATH,
        CLOUDFLARE_DERIVER_A_PRIVATE_REQUEST_PATH
    );
    assert_eq!(
        LOCAL_DERIVER_B_PRIVATE_PATH,
        CLOUDFLARE_DERIVER_B_PRIVATE_REQUEST_PATH
    );
    assert_eq!(
        LOCAL_DERIVER_A_PEER_PATH,
        CLOUDFLARE_DERIVER_A_PEER_REQUEST_PATH
    );
    assert_eq!(
        LOCAL_DERIVER_B_PEER_PATH,
        CLOUDFLARE_DERIVER_B_PEER_REQUEST_PATH
    );
    assert_eq!(
        LOCAL_SIGNING_WORKER_NORMAL_SIGNING_PATH,
        CLOUDFLARE_SIGNING_WORKER_NORMAL_SIGNING_PATH
    );
}

#[test]
fn local_pair_lifecycle_routes_match_strict_worker_paths_and_are_owned_by_role_workers() {
    let role_routes = [
        (
            router_ab_core::LocalServiceRoleV1::DeriverA,
            &[
                (
                    LOCAL_DERIVER_A_ED25519_YAO_PREPARE_PAIR_PATH,
                    "/router-ab/deriver-a/ed25519-yao/prepare-pair",
                ),
                (
                    LOCAL_DERIVER_A_ED25519_YAO_EXECUTE_PAIR_PATH,
                    "/router-ab/deriver-a/ed25519-yao/execute-pair",
                ),
                (
                    LOCAL_DERIVER_A_ED25519_YAO_READ_PAIR_STATUS_PATH,
                    "/router-ab/deriver-a/ed25519-yao/read-pair-status",
                ),
                (
                    LOCAL_DERIVER_A_ED25519_YAO_BURN_PAIR_PATH,
                    "/router-ab/deriver-a/ed25519-yao/burn-pair",
                ),
            ] as &[(&str, &str)],
        ),
        (
            router_ab_core::LocalServiceRoleV1::DeriverB,
            &[
                (
                    LOCAL_DERIVER_B_ED25519_YAO_PREPARE_PAIR_PATH,
                    "/router-ab/deriver-b/ed25519-yao/prepare-pair",
                ),
                (
                    LOCAL_DERIVER_B_ED25519_YAO_READ_PAIR_STATUS_PATH,
                    "/router-ab/deriver-b/ed25519-yao/read-pair-status",
                ),
                (
                    LOCAL_DERIVER_B_ED25519_YAO_BURN_PAIR_PATH,
                    "/router-ab/deriver-b/ed25519-yao/burn-pair",
                ),
            ] as &[(&str, &str)],
        ),
    ];
    for (role, routes) in role_routes {
        for &(local, strict_worker_path) in routes {
            assert_eq!(local, strict_worker_path);
            assert!(local_worker_owned_paths_v1(role).contains(&local));
        }
    }
}

#[test]
fn local_router_boundary_requires_an_installed_native_dispatcher() {
    let plan = local_env_materialization_plan_v1(&[7_u8; 32]).expect("local env plan");
    let router_env = plan
        .files
        .iter()
        .find(|file| file.role == router_ab_core::LocalServiceRoleV1::Router)
        .expect("Router env file");
    let config = parse_local_worker_role_config_for_role_v1(
        router_ab_core::LocalServiceRoleV1::Router,
        parse_local_env_file_contents_v1(&router_env.contents).expect("Router env entries"),
    )
    .expect("Router config");
    let router = match &config {
        router_ab_dev::LocalWorkerRoleConfigV1::Router(config) => config,
        _ => panic!("expected Router config"),
    };

    for path in ["/healthz", "/readyz"] {
        let health = LocalDevHttpRequestPartsV1 {
            method: "GET".to_owned(),
            path: path.to_owned(),
            authorization: None,
            internal_service_auth: None,
            body: Vec::new(),
        };
        let (health_status, health_body) =
            local_dev_http_handle_request_v1(LocalDevHttpTopologyV1::Router(router), &health)
                .expect("Router health response");
        assert_eq!(health_status, 200);
        assert!(health_body.contains("\"role\":\"router\""));
    }

    for path in [
        LOCAL_ROUTER_ED25519_YAO_EXECUTE_PATH,
        LOCAL_ROUTER_ED25519_YAO_RECOVERY_PROMOTE_PATH,
    ] {
        let request = LocalDevHttpRequestPartsV1 {
            method: "POST".to_owned(),
            path: path.to_owned(),
            authorization: None,
            internal_service_auth: Some(
                LOCAL_ROUTER_AB_INTERNAL_SERVICE_AUTH_DEFAULT_SECRET_V1.to_owned(),
            ),
            body: Vec::new(),
        };
        let (status, body) =
            local_dev_http_handle_request_v1(LocalDevHttpTopologyV1::Router(router), &request)
                .expect("Router route response without dispatcher");
        assert_eq!(status, 501);
        assert!(body.contains("strict Wrangler local mode"));

        let unauthorized = LocalDevHttpRequestPartsV1 {
            internal_service_auth: Some("wrong".to_owned()),
            ..request
        };
        let (status, _) =
            local_dev_http_handle_request_v1(LocalDevHttpTopologyV1::Router(router), &unauthorized)
                .expect("unauthorized Router route response");
        assert_eq!(status, 401);
    }
}

#[test]
fn local_http_wire_message_bodies_match_cloudflare_service_binding_bytes() {
    let ceremony = run_example_local_router_ab_dev_http_ceremony_v1().expect("typed HTTP ceremony");
    let cases = [
        (
            "Router to Deriver A request",
            &ceremony.deriver_a_request.envelope.message,
        ),
        (
            "Router to Deriver B request",
            &ceremony.deriver_b_request.envelope.message,
        ),
        (
            "Deriver A to Deriver B peer request",
            &ceremony
                .core_http_ceremony
                .deriver_a_peer_request
                .envelope
                .message,
        ),
        (
            "Deriver B to Deriver A peer request",
            &ceremony
                .core_http_ceremony
                .deriver_b_peer_request
                .envelope
                .message,
        ),
    ];

    for (label, message) in cases {
        let local_body = serde_json::to_vec(message).expect("local JSON request body");
        let cloudflare_body =
            cloudflare_service_json_request_body_bytes_v1(label, message).expect(label);
        assert_eq!(local_body, cloudflare_body, "{label}");
    }
}

#[test]
fn local_env_templates_match_wrangler_startup_manifests() {
    let router = ManifestPair {
        local: include_str!("../env/router.local.example"),
        wrangler: include_str!("../../router-ab-cloudflare/wrangler.router.toml"),
    };
    router.assert_local("ROUTER_AB_LOCAL_WORKER_ROLE=router");
    router.assert_wrangler("name = \"router-ab-mpc-router\"");
    router.assert_wrangler("[env.staging]");
    router.assert_wrangler("name = \"router-ab-mpc-router-staging\"");
    router.assert_wrangler("service = \"router-ab-deriver-a-staging\"");
    router.assert_wrangler("service = \"router-ab-deriver-b-staging\"");
    router.assert_wrangler("service = \"router-ab-signing-worker-staging\"");
    router.assert_wrangler_absent("[env.production]");
    router.assert_wrangler_absent("ROUTER_AB_WORKER_ROLE");
    router.assert_wrangler_absent("ROUTER_AB_ROUTE_PROFILE");
    router.assert_wrangler("binding = \"DERIVER_A\"");
    router.assert_wrangler("binding = \"DERIVER_B\"");
    router.assert_wrangler("binding = \"SIGNING_WORKER\"");
    router.assert_wrangler("[durable_objects]");
    router.assert_wrangler(
        "name = \"ROUTER_TENANT_ROOT_CREATION_DO\", class_name = \"RouterAbTenantRootCreationDurableObject\"",
    );
    router.assert_wrangler("[[migrations]]");
    router.assert_wrangler("tag = \"router_ab_router_tenant_root_creation_v1\"");
    router.assert_wrangler("new_sqlite_classes = [\"RouterAbTenantRootCreationDurableObject\"]");
    router.assert_wrangler("[[env.staging.durable_objects.bindings]]");
    router.assert_wrangler(
        "name = \"ROUTER_TENANT_ROOT_CREATION_DO\"\nclass_name = \"RouterAbTenantRootCreationDurableObject\"",
    );
    router.assert_wrangler("[[env.production-testnet.durable_objects.bindings]]");
    router.assert_wrangler(
        "name = \"ROUTER_TENANT_ROOT_CREATION_DO\"\nclass_name = \"RouterAbTenantRootCreationDurableObject\"",
    );
    router.assert_wrangler_absent("[[d1_databases]]");
    router.assert_local("DERIVER_A_URL=http://127.0.0.1:4103");
    router.assert_local("DERIVER_B_URL=http://127.0.0.1:4104");
    router.assert_local("SIGNING_WORKER_URL=http://127.0.0.1:4105");
    router.assert_local_absent("STORAGE_PATH");

    let deriver_a = ManifestPair {
        local: include_str!("../env/deriver-a.local.example"),
        wrangler: include_str!("../../router-ab-cloudflare/wrangler.deriver-a.toml"),
    };
    deriver_a.assert_local("ROUTER_AB_LOCAL_WORKER_ROLE=deriver-a");
    deriver_a.assert_wrangler("name = \"router-ab-deriver-a\"");
    deriver_a.assert_wrangler("name = \"router-ab-deriver-a-staging\"");
    deriver_a.assert_wrangler("service = \"router-ab-deriver-b-staging\"");
    deriver_a.assert_wrangler_absent("[env.production]");
    deriver_a.assert_wrangler_absent("ROUTER_AB_WORKER_ROLE");
    deriver_a.assert_wrangler_absent("ROUTER_AB_ROUTE_PROFILE");
    deriver_a.assert_wrangler("binding = \"DERIVER_B\"");
    deriver_a.assert_wrangler("binding = \"DERIVER_ROLE_PRIVATE_DB\"");
    deriver_a.assert_wrangler(
        "DERIVER_A_ENVELOPE_HPKE_PRIVATE_KEY_BINDING = \"DERIVER_A_ENVELOPE_HPKE_PRIVATE_KEY\"",
    );
    deriver_a
        .assert_wrangler("DERIVER_A_PEER_SIGNING_KEY_BINDING = \"DERIVER_A_PEER_SIGNING_KEY\"");
    deriver_a.assert_local("DERIVER_B_URL=http://127.0.0.1:4104");
    deriver_a.assert_local("DERIVER_A_ENVELOPE_HPKE_PRIVATE_KEY=");
    deriver_a.assert_local("DERIVER_A_PEER_SIGNING_KEY=");
    deriver_a.assert_local(
        "DERIVER_A_ROLE_PRIVATE_STORAGE_PATH=.router-ab-local/deriver-a/role-private.sqlite",
    );

    let deriver_b = ManifestPair {
        local: include_str!("../env/deriver-b.local.example"),
        wrangler: include_str!("../../router-ab-cloudflare/wrangler.deriver-b.toml"),
    };
    deriver_b.assert_local("ROUTER_AB_LOCAL_WORKER_ROLE=deriver-b");
    deriver_b.assert_wrangler("name = \"router-ab-deriver-b\"");
    deriver_b.assert_wrangler("name = \"router-ab-deriver-b-staging\"");
    deriver_b.assert_wrangler("service = \"router-ab-deriver-a-staging\"");
    deriver_b.assert_wrangler_absent("[env.production]");
    deriver_b.assert_wrangler_absent("ROUTER_AB_WORKER_ROLE");
    deriver_b.assert_wrangler_absent("ROUTER_AB_ROUTE_PROFILE");
    deriver_b.assert_wrangler("binding = \"DERIVER_A\"");
    deriver_b.assert_wrangler("binding = \"DERIVER_ROLE_PRIVATE_DB\"");
    deriver_b.assert_wrangler(
        "DERIVER_B_ENVELOPE_HPKE_PRIVATE_KEY_BINDING = \"DERIVER_B_ENVELOPE_HPKE_PRIVATE_KEY\"",
    );
    deriver_b
        .assert_wrangler("DERIVER_B_PEER_SIGNING_KEY_BINDING = \"DERIVER_B_PEER_SIGNING_KEY\"");
    deriver_b.assert_local("DERIVER_A_URL=http://127.0.0.1:4103");
    deriver_b.assert_local("DERIVER_B_ENVELOPE_HPKE_PRIVATE_KEY=");
    deriver_b.assert_local("DERIVER_B_PEER_SIGNING_KEY=");
    deriver_b.assert_local(
        "DERIVER_B_ROLE_PRIVATE_STORAGE_PATH=.router-ab-local/deriver-b/role-private.sqlite",
    );

    let signing_worker = ManifestPair {
        local: include_str!("../env/signing-worker.local.example"),
        wrangler: include_str!("../../router-ab-cloudflare/wrangler.signing-worker.toml"),
    };
    signing_worker.assert_local("ROUTER_AB_LOCAL_WORKER_ROLE=signing-worker");
    signing_worker.assert_wrangler("name = \"router-ab-signing-worker\"");
    signing_worker.assert_wrangler("name = \"router-ab-signing-worker-staging\"");
    signing_worker.assert_wrangler_absent("[env.production]");
    signing_worker.assert_wrangler_absent("ROUTER_AB_WORKER_ROLE");
    signing_worker.assert_wrangler_absent("ROUTER_AB_ROUTE_PROFILE");
    signing_worker.assert_wrangler(
        "SIGNING_WORKER_PRESIGN_SESSION_DO_BINDING = \"SIGNING_WORKER_PRESIGN_SESSION_DO\"",
    );
    signing_worker.assert_wrangler("binding = \"SIGNING_WORKER_PRIVATE_DB\"");
    signing_worker.assert_wrangler(
        "SIGNING_WORKER_SERVER_OUTPUT_HPKE_PRIVATE_KEY_BINDING = \"SIGNING_WORKER_SERVER_OUTPUT_HPKE_PRIVATE_KEY\"",
    );
    signing_worker.assert_wrangler(
        "SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY = \"x25519:d0a06a6445d78bc87f449dfac2b427ad1857a0b00d91e20f152031ad49c18010\"",
    );
    signing_worker.assert_local("SIGNING_WORKER_URL=http://127.0.0.1:4105");
    signing_worker.assert_local("SIGNING_WORKER_ID=local-signing-worker");
    signing_worker.assert_local("SIGNING_WORKER_KEY_EPOCH=epoch-1");
    signing_worker.assert_local(
        "SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY=x25519:3333333333333333333333333333333333333333333333333333333333333333",
    );
    signing_worker.assert_local("SIGNING_WORKER_SERVER_OUTPUT_HPKE_PRIVATE_KEY=");
    signing_worker.assert_local(
        "SIGNING_WORKER_PRIVATE_STORAGE_PATH=.router-ab-local/signing-worker/role-private.sqlite",
    );

    // R120: each Deriver reads authoritative creation state through its own
    // external binding to the Router-owned Durable Object. The Router keeps the
    // class and migrations; the Derivers name the matching Router script per env
    // and declare no migrations of their own.
    for deriver in [&deriver_a, &deriver_b] {
        deriver.assert_wrangler("name = \"ROUTER_TENANT_ROOT_CREATION_DO\"");
        deriver.assert_wrangler("class_name = \"RouterAbTenantRootCreationDurableObject\"");
        deriver.assert_wrangler("script_name = \"router-ab-mpc-router\"");
        deriver.assert_wrangler("script_name = \"router-ab-mpc-router-staging\"");
        deriver.assert_wrangler("script_name = \"router-ab-mpc-router-testnet\"");
        deriver.assert_wrangler_absent("[[migrations]]");
        deriver.assert_wrangler_absent("new_sqlite_classes");
    }
    // The Router owns the class: it declares the migration and no script_name.
    router.assert_wrangler("[[migrations]]");
    router.assert_wrangler("new_sqlite_classes = [\"RouterAbTenantRootCreationDurableObject\"]");
    router.assert_wrangler_absent("script_name");

    // R120 tenant-root control plane: sole holder of the issuer private
    // signing key; reads authoritative lifecycle state through an external
    // binding to the Router-owned creation Durable Object.
    let control_plane = ManifestPair {
        local: include_str!("../env/tenant-root-control-plane.local.example"),
        wrangler: include_str!("../../router-ab-cloudflare/wrangler.tenant-root-control-plane.toml"),
    };
    control_plane.assert_local("ROUTER_AB_LOCAL_WORKER_ROLE=tenant-root-control-plane");
    control_plane.assert_wrangler("name = \"router-ab-tenant-root-control-plane\"");
    control_plane.assert_wrangler("name = \"router-ab-tenant-root-control-plane-staging\"");
    control_plane.assert_wrangler("name = \"router-ab-tenant-root-control-plane-testnet\"");
    control_plane.assert_wrangler_absent("[env.production]");
    control_plane.assert_wrangler_absent("ROUTER_AB_WORKER_ROLE");
    control_plane.assert_wrangler(
        "TENANT_ROOT_CONTROL_PLANE_ISSUER_SIGNING_KEY_BINDING = \"TENANT_ROOT_CONTROL_PLANE_ISSUER_SIGNING_KEY\"",
    );
    control_plane.assert_wrangler(
        "TENANT_ROOT_CONTROL_PLANE_ISSUER_SIGNING_KEY_ID = \"control-plane-issuer-v1\"",
    );
    // External DO binding: the Router keeps the class; every env names the
    // matching Router script.
    control_plane.assert_wrangler("name = \"ROUTER_TENANT_ROOT_CREATION_DO\"");
    control_plane.assert_wrangler("class_name = \"RouterAbTenantRootCreationDurableObject\"");
    control_plane.assert_wrangler("script_name = \"router-ab-mpc-router\"");
    control_plane.assert_wrangler("script_name = \"router-ab-mpc-router-staging\"");
    control_plane.assert_wrangler("script_name = \"router-ab-mpc-router-testnet\"");
    // It owns no migrations, no D1, no shares, and no Router auth config.
    control_plane.assert_wrangler_absent("[[migrations]]");
    control_plane.assert_wrangler_absent("d1_databases");
    control_plane.assert_wrangler_absent("ROOT_SHARE");
    control_plane.assert_wrangler_absent("ROUTER_JWT");
    control_plane.assert_wrangler_absent("ROUTER_TENANT_ROOT_CREATION_ISSUER_VERIFYING_KEYS_JSON");
    control_plane.assert_local("TENANT_ROOT_CONTROL_PLANE_URL=http://127.0.0.1:4106");
    control_plane.assert_local("TENANT_ROOT_CONTROL_PLANE_ISSUER_SIGNING_KEY_ID=local-control-plane-issuer-v1");
    control_plane.assert_local("TENANT_ROOT_CONTROL_PLANE_ISSUER_SIGNING_KEY=");

    // The Router reaches the control plane through a service binding in every env.
    router.assert_wrangler("service = \"router-ab-tenant-root-control-plane\"");
    router.assert_wrangler("service = \"router-ab-tenant-root-control-plane-staging\"");
    router.assert_wrangler("service = \"router-ab-tenant-root-control-plane-testnet\"");
}

struct ManifestPair {
    local: &'static str,
    wrangler: &'static str,
}

impl ManifestPair {
    fn assert_local(&self, expected: &str) {
        assert!(
            self.local.contains(expected),
            "local env template missing {expected}"
        );
    }

    fn assert_wrangler(&self, expected: &str) {
        assert!(
            self.wrangler.contains(expected),
            "wrangler manifest missing {expected}"
        );
    }

    fn assert_local_absent(&self, forbidden: &str) {
        assert!(
            !self.local.contains(forbidden),
            "local env template still contains {forbidden}"
        );
    }

    fn assert_wrangler_absent(&self, forbidden: &str) {
        assert!(
            !self.wrangler.contains(forbidden),
            "wrangler manifest still contains {forbidden}"
        );
    }
}
