use router_ab_cloudflare::{
    cloudflare_service_json_request_body_bytes_v1,
    CLOUDFLARE_ROUTER_NORMAL_SIGNING_PUBLIC_REQUEST_PATH_V2,
    CLOUDFLARE_SIGNER_A_PEER_REQUEST_PATH_V1, CLOUDFLARE_SIGNER_A_PRIVATE_REQUEST_PATH_V1,
    CLOUDFLARE_SIGNER_B_PEER_REQUEST_PATH_V1, CLOUDFLARE_SIGNER_B_PRIVATE_REQUEST_PATH_V1,
    CLOUDFLARE_SIGNING_WORKER_NORMAL_SIGNING_PATH_V1,
    CLOUDFLARE_SIGNING_WORKER_PROOF_BUNDLE_ACTIVATION_PATH_V1,
};
use router_ab_dev::{
    run_example_local_router_ab_hss_dev_http_ceremony_v1, LOCAL_DERIVER_A_PEER_PATH_V1,
    LOCAL_DERIVER_A_PRIVATE_PATH_V1, LOCAL_DERIVER_B_PEER_PATH_V1, LOCAL_DERIVER_B_PRIVATE_PATH_V1,
    LOCAL_ROUTER_NORMAL_SIGNING_PATH_V2, LOCAL_SIGNING_WORKER_ACTIVATION_PATH_V1,
    LOCAL_SIGNING_WORKER_NORMAL_SIGNING_PATH_V1,
};

#[test]
fn local_worker_routes_match_cloudflare_worker_routes() {
    assert_eq!(
        LOCAL_ROUTER_NORMAL_SIGNING_PATH_V2,
        CLOUDFLARE_ROUTER_NORMAL_SIGNING_PUBLIC_REQUEST_PATH_V2
    );
    assert_eq!(
        LOCAL_DERIVER_A_PRIVATE_PATH_V1,
        CLOUDFLARE_SIGNER_A_PRIVATE_REQUEST_PATH_V1
    );
    assert_eq!(
        LOCAL_DERIVER_B_PRIVATE_PATH_V1,
        CLOUDFLARE_SIGNER_B_PRIVATE_REQUEST_PATH_V1
    );
    assert_eq!(
        LOCAL_DERIVER_A_PEER_PATH_V1,
        CLOUDFLARE_SIGNER_A_PEER_REQUEST_PATH_V1
    );
    assert_eq!(
        LOCAL_DERIVER_B_PEER_PATH_V1,
        CLOUDFLARE_SIGNER_B_PEER_REQUEST_PATH_V1
    );
    assert_eq!(
        LOCAL_SIGNING_WORKER_ACTIVATION_PATH_V1,
        CLOUDFLARE_SIGNING_WORKER_PROOF_BUNDLE_ACTIVATION_PATH_V1
    );
    assert_eq!(
        LOCAL_SIGNING_WORKER_NORMAL_SIGNING_PATH_V1,
        CLOUDFLARE_SIGNING_WORKER_NORMAL_SIGNING_PATH_V1
    );
}

#[test]
fn local_http_wire_message_bodies_match_cloudflare_service_binding_bytes() {
    let ceremony =
        run_example_local_router_ab_hss_dev_http_ceremony_v1("derived-gamma", "split-epoch-1")
            .expect("typed HTTP ceremony");
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
    router.assert_wrangler("name = \"router-ab-strict-router\"");
    router.assert_wrangler("[env.staging]");
    router.assert_wrangler("name = \"router-ab-strict-router-staging\"");
    router.assert_wrangler("service = \"router-ab-strict-signer-a-staging\"");
    router.assert_wrangler("service = \"router-ab-strict-signer-b-staging\"");
    router.assert_wrangler("service = \"router-ab-strict-signing-worker-staging\"");
    router.assert_wrangler("[env.production]");
    router.assert_wrangler("name = \"router-ab-strict-router-prod\"");
    router.assert_wrangler("service = \"router-ab-strict-signer-a-prod\"");
    router.assert_wrangler("service = \"router-ab-strict-signer-b-prod\"");
    router.assert_wrangler("service = \"router-ab-strict-signing-worker-prod\"");
    router.assert_wrangler_absent("ROUTER_AB_WORKER_ROLE");
    router.assert_wrangler_absent("ROUTER_AB_ROUTE_PROFILE");
    router.assert_wrangler("binding = \"SIGNER_A\"");
    router.assert_wrangler("binding = \"SIGNER_B\"");
    router.assert_wrangler("binding = \"SIGNING_WORKER\"");
    router.assert_wrangler("ROUTER_REPLAY_DO_BINDING = \"ROUTER_REPLAY_DO\"");
    router.assert_wrangler("ROUTER_LIFECYCLE_DO_BINDING = \"ROUTER_LIFECYCLE_DO\"");
    router.assert_wrangler("ROUTER_PROJECT_POLICY_DO_BINDING = \"ROUTER_PROJECT_POLICY_DO\"");
    router.assert_wrangler("ROUTER_QUOTA_DO_BINDING = \"ROUTER_QUOTA_DO\"");
    router.assert_wrangler("ROUTER_ABUSE_DO_BINDING = \"ROUTER_ABUSE_DO\"");
    router.assert_local("DERIVER_A_URL=http://127.0.0.1:9091");
    router.assert_local("DERIVER_B_URL=http://127.0.0.1:9092");
    router.assert_local("SIGNING_WORKER_URL=http://127.0.0.1:9093");
    router.assert_local("ROUTER_REPLAY_STORAGE_PATH=.router-ab-local/router/replay.sqlite");
    router.assert_local("ROUTER_LIFECYCLE_STORAGE_PATH=.router-ab-local/router/lifecycle.sqlite");
    router.assert_local(
        "ROUTER_PROJECT_POLICY_STORAGE_PATH=.router-ab-local/router/project-policy.sqlite",
    );
    router.assert_local("ROUTER_QUOTA_STORAGE_PATH=.router-ab-local/router/quota.sqlite");
    router.assert_local("ROUTER_ABUSE_STORAGE_PATH=.router-ab-local/router/abuse.sqlite");

    let deriver_a = ManifestPair {
        local: include_str!("../env/deriver-a.local.example"),
        wrangler: include_str!("../../router-ab-cloudflare/wrangler.signer-a.toml"),
    };
    deriver_a.assert_local("ROUTER_AB_LOCAL_WORKER_ROLE=deriver-a");
    deriver_a.assert_wrangler("name = \"router-ab-strict-signer-a\"");
    deriver_a.assert_wrangler("name = \"router-ab-strict-signer-a-staging\"");
    deriver_a.assert_wrangler("service = \"router-ab-strict-signer-b-staging\"");
    deriver_a.assert_wrangler("name = \"router-ab-strict-signer-a-prod\"");
    deriver_a.assert_wrangler("service = \"router-ab-strict-signer-b-prod\"");
    deriver_a.assert_wrangler_absent("ROUTER_AB_WORKER_ROLE");
    deriver_a.assert_wrangler_absent("ROUTER_AB_ROUTE_PROFILE");
    deriver_a.assert_wrangler("binding = \"SIGNER_B\"");
    deriver_a.assert_wrangler("SIGNER_A_ROOT_SHARE_DO_BINDING = \"SIGNER_A_ROOT_SHARE_DO\"");
    deriver_a.assert_wrangler(
        "SIGNER_A_ROOT_SHARE_WIRE_SECRET_BINDING = \"SIGNER_A_ROOT_SHARE_WIRE_SECRET\"",
    );
    deriver_a.assert_wrangler(
        "SIGNER_A_ENVELOPE_HPKE_PRIVATE_KEY_BINDING = \"SIGNER_A_ENVELOPE_HPKE_PRIVATE_KEY\"",
    );
    deriver_a.assert_wrangler("SIGNER_A_PEER_SIGNING_KEY_BINDING = \"SIGNER_A_PEER_SIGNING_KEY\"");
    deriver_a.assert_local("DERIVER_B_URL=http://127.0.0.1:9092");
    deriver_a.assert_local("DERIVER_A_ENVELOPE_HPKE_PRIVATE_KEY=");
    deriver_a.assert_local("DERIVER_A_ROOT_SHARE_WIRE_SECRET=");
    deriver_a.assert_local("DERIVER_A_PEER_SIGNING_KEY=");
    deriver_a.assert_local(
        "DERIVER_A_ROOT_SHARE_STORAGE_PATH=.router-ab-local/deriver-a/root-share.sqlite",
    );
    deriver_a.assert_local(
        "DERIVER_A_SEALED_ROOT_SHARES_PATH=.router-ab-local/deriver-a/sealed-root-shares.sqlite",
    );

    let deriver_b = ManifestPair {
        local: include_str!("../env/deriver-b.local.example"),
        wrangler: include_str!("../../router-ab-cloudflare/wrangler.signer-b.toml"),
    };
    deriver_b.assert_local("ROUTER_AB_LOCAL_WORKER_ROLE=deriver-b");
    deriver_b.assert_wrangler("name = \"router-ab-strict-signer-b\"");
    deriver_b.assert_wrangler("name = \"router-ab-strict-signer-b-staging\"");
    deriver_b.assert_wrangler("service = \"router-ab-strict-signer-a-staging\"");
    deriver_b.assert_wrangler("name = \"router-ab-strict-signer-b-prod\"");
    deriver_b.assert_wrangler("service = \"router-ab-strict-signer-a-prod\"");
    deriver_b.assert_wrangler_absent("ROUTER_AB_WORKER_ROLE");
    deriver_b.assert_wrangler_absent("ROUTER_AB_ROUTE_PROFILE");
    deriver_b.assert_wrangler("binding = \"SIGNER_A\"");
    deriver_b.assert_wrangler("SIGNER_B_ROOT_SHARE_DO_BINDING = \"SIGNER_B_ROOT_SHARE_DO\"");
    deriver_b.assert_wrangler(
        "SIGNER_B_ROOT_SHARE_WIRE_SECRET_BINDING = \"SIGNER_B_ROOT_SHARE_WIRE_SECRET\"",
    );
    deriver_b.assert_wrangler(
        "SIGNER_B_ENVELOPE_HPKE_PRIVATE_KEY_BINDING = \"SIGNER_B_ENVELOPE_HPKE_PRIVATE_KEY\"",
    );
    deriver_b.assert_wrangler("SIGNER_B_PEER_SIGNING_KEY_BINDING = \"SIGNER_B_PEER_SIGNING_KEY\"");
    deriver_b.assert_local("DERIVER_A_URL=http://127.0.0.1:9091");
    deriver_b.assert_local("DERIVER_B_ENVELOPE_HPKE_PRIVATE_KEY=");
    deriver_b.assert_local("DERIVER_B_ROOT_SHARE_WIRE_SECRET=");
    deriver_b.assert_local("DERIVER_B_PEER_SIGNING_KEY=");
    deriver_b.assert_local(
        "DERIVER_B_ROOT_SHARE_STORAGE_PATH=.router-ab-local/deriver-b/root-share.sqlite",
    );
    deriver_b.assert_local(
        "DERIVER_B_SEALED_ROOT_SHARES_PATH=.router-ab-local/deriver-b/sealed-root-shares.sqlite",
    );

    let signing_worker = ManifestPair {
        local: include_str!("../env/signing-worker.local.example"),
        wrangler: include_str!("../../router-ab-cloudflare/wrangler.signing-worker.toml"),
    };
    signing_worker.assert_local("ROUTER_AB_LOCAL_WORKER_ROLE=signing-worker");
    signing_worker.assert_wrangler("name = \"router-ab-strict-signing-worker\"");
    signing_worker.assert_wrangler("name = \"router-ab-strict-signing-worker-staging\"");
    signing_worker.assert_wrangler("name = \"router-ab-strict-signing-worker-prod\"");
    signing_worker.assert_wrangler_absent("ROUTER_AB_WORKER_ROLE");
    signing_worker.assert_wrangler_absent("ROUTER_AB_ROUTE_PROFILE");
    signing_worker.assert_wrangler(
        "SIGNING_WORKER_SERVER_OUTPUT_DO_BINDING = \"SIGNING_WORKER_SERVER_OUTPUT_DO\"",
    );
    signing_worker.assert_wrangler(
        "SIGNING_WORKER_SERVER_OUTPUT_HPKE_PRIVATE_KEY_BINDING = \"SIGNING_WORKER_SERVER_OUTPUT_HPKE_PRIVATE_KEY\"",
    );
    signing_worker.assert_wrangler(
        "SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY = \"x25519:3333333333333333333333333333333333333333333333333333333333333333\"",
    );
    signing_worker.assert_local("SIGNING_WORKER_URL=http://127.0.0.1:9093");
    signing_worker.assert_local("SIGNING_WORKER_ID=local-signing-worker");
    signing_worker.assert_local("SIGNING_WORKER_KEY_EPOCH=epoch-1");
    signing_worker.assert_local(
        "SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY=x25519:3333333333333333333333333333333333333333333333333333333333333333",
    );
    signing_worker.assert_local("SIGNING_WORKER_SERVER_OUTPUT_HPKE_PRIVATE_KEY=");
    signing_worker.assert_local(
        "SIGNING_WORKER_SERVER_OUTPUT_STORAGE_PATH=.router-ab-local/signing-worker/server-output.sqlite",
    );
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

    fn assert_wrangler_absent(&self, forbidden: &str) {
        assert!(
            !self.wrangler.contains(forbidden),
            "wrangler manifest still contains {forbidden}"
        );
    }
}
