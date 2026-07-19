use router_ab_core::{
    CanonicalWireBytesV1, Ed25519YaoDeriverRoleV1, Ed25519YaoPackageKindV1, LocalHttpPathV1,
    LocalServiceRoleV1, RouterAbProtocolErrorCode,
};
use router_ab_dev::{
    local_env_materialization_plan_v1, local_http_service_binding_endpoint_v1,
    local_http_service_binding_path_v1, local_http_service_binding_url_v1,
    local_worker_bind_addr_v1, local_worker_health_response_json_v1, local_worker_owned_paths_v1,
    local_worker_owns_path_v1, open_local_ed25519_yao_client_package_v1,
    parse_local_env_file_contents_v1, parse_local_service_role_label_v1,
    parse_local_worker_role_config_for_role_v1, parse_local_worker_role_config_v1,
    seal_local_ed25519_yao_package_v1, LocalEd25519YaoRecipientPrivateKeyV1,
    LocalHttpServiceBindingClientV1, LocalWorkerRoleConfigV1,
    LOCAL_DERIVER_A_ENVELOPE_HPKE_PRIVATE_KEY_ENV_V1, LOCAL_DERIVER_A_ENV_FILE_V1,
    LOCAL_DERIVER_A_PEER_PATH, LOCAL_DERIVER_A_PEER_SIGNING_KEY_ENV_V1,
    LOCAL_DERIVER_A_PRIVATE_PATH, LOCAL_DERIVER_A_STATE_DIR_V1,
    LOCAL_DERIVER_B_ENVELOPE_HPKE_PRIVATE_KEY_ENV_V1, LOCAL_DERIVER_B_ENV_FILE_V1,
    LOCAL_DERIVER_B_PEER_PATH, LOCAL_DERIVER_B_PEER_SIGNING_KEY_ENV_V1,
    LOCAL_DERIVER_B_PRIVATE_PATH, LOCAL_DERIVER_B_STATE_DIR_V1, LOCAL_GATEWAY_PUBLIC_URL_ENV_V1,
    LOCAL_HTTP_CANONICAL_WIRE_CONTENT_TYPE_V1, LOCAL_HTTP_JSON_CONTENT_TYPE_V1,
    LOCAL_ROUTER_AB_ECDSA_DERIVATION_SIGNING_PATH,
    LOCAL_ROUTER_AB_ECDSA_DERIVATION_SIGNING_PREPARE_PATH, LOCAL_ROUTER_ENV_FILE_V1,
    LOCAL_ROUTER_NORMAL_SIGNING_PATH, LOCAL_ROUTER_NORMAL_SIGNING_PREPARE_PATH,
    LOCAL_ROUTER_STATE_DIR_V1, LOCAL_SIGNING_WORKER_ENV_FILE_V1,
    LOCAL_SIGNING_WORKER_NORMAL_SIGNING_PATH, LOCAL_SIGNING_WORKER_NORMAL_SIGNING_PREPARE_PATH,
    LOCAL_SIGNING_WORKER_ROUTER_AB_ECDSA_DERIVATION_PRESIGNATURE_POOL_PUT_PATH,
    LOCAL_SIGNING_WORKER_ROUTER_AB_ECDSA_DERIVATION_SIGNING_PATH,
    LOCAL_SIGNING_WORKER_ROUTER_AB_ECDSA_DERIVATION_SIGNING_PREPARE_PATH,
    LOCAL_SIGNING_WORKER_SERVER_OUTPUT_HPKE_PRIVATE_KEY_ENV_V1,
    LOCAL_SIGNING_WORKER_SERVER_OUTPUT_STORAGE_PATH_ENV_V1, LOCAL_SIGNING_WORKER_STATE_DIR_V1,
    LOCAL_WORKER_HEALTH_PATH, LOCAL_WORKER_READY_PATH, LOCAL_WORKER_ROLE_ENV_V1,
    LOCAL_WORKER_STARTUP_EPOCH_V1,
};
use std::{
    io::{Read, Write},
    net::TcpListener,
    thread,
};

#[test]
fn local_worker_env_templates_parse_into_role_specific_configs() {
    let router = parse_template(include_str!("../env/router.local.example"));
    let deriver_a = parse_template(include_str!("../env/deriver-a.local.example"));
    let deriver_b = parse_template(include_str!("../env/deriver-b.local.example"));
    let signing_worker = parse_template(include_str!("../env/signing-worker.local.example"));

    assert!(matches!(
        parse_local_worker_role_config_v1(router).expect("router template parses"),
        LocalWorkerRoleConfigV1::Router(_)
    ));
    assert!(matches!(
        parse_local_worker_role_config_v1(deriver_a).expect("deriver A template parses"),
        LocalWorkerRoleConfigV1::DeriverA(_)
    ));
    assert!(matches!(
        parse_local_worker_role_config_v1(deriver_b).expect("deriver B template parses"),
        LocalWorkerRoleConfigV1::DeriverB(_)
    ));
    assert!(matches!(
        parse_local_worker_role_config_v1(signing_worker).expect("SigningWorker template parses"),
        LocalWorkerRoleConfigV1::SigningWorker(_)
    ));
}

#[test]
fn local_worker_env_role_labels_accept_cli_and_env_forms() {
    assert_eq!(
        parse_local_service_role_label_v1("router").expect("router role"),
        LocalServiceRoleV1::Router
    );
    assert_eq!(
        parse_local_service_role_label_v1("deriver-a").expect("deriver-a role"),
        LocalServiceRoleV1::DeriverA
    );
    assert_eq!(
        parse_local_service_role_label_v1("deriver_a").expect("deriver_a role"),
        LocalServiceRoleV1::DeriverA
    );
    assert_eq!(
        parse_local_service_role_label_v1("signing-worker").expect("signing-worker role"),
        LocalServiceRoleV1::SigningWorker
    );
}

#[test]
fn local_worker_env_rejects_selected_role_mismatch() {
    let err = parse_local_worker_role_config_for_role_v1(
        LocalServiceRoleV1::Router,
        parse_template(include_str!("../env/deriver-a.local.example")),
    )
    .expect_err("selected Router cannot use Deriver A env");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidRole);
}

#[test]
fn local_router_env_rejects_deriver_and_signing_worker_secret_keys() {
    let mut env = parse_template(include_str!("../env/router.local.example"));
    env.push((
        LOCAL_DERIVER_A_ENVELOPE_HPKE_PRIVATE_KEY_ENV_V1.to_owned(),
        "leaked-a-key".to_owned(),
    ));
    let err = parse_local_worker_role_config_v1(env).expect_err("Router rejects Deriver A key");
    assert_eq!(err.code(), RouterAbProtocolErrorCode::ForbiddenLocalBinding);

    let mut env = parse_template(include_str!("../env/router.local.example"));
    env.push((
        LOCAL_SIGNING_WORKER_SERVER_OUTPUT_HPKE_PRIVATE_KEY_ENV_V1.to_owned(),
        "leaked-signing-worker-key".to_owned(),
    ));
    let err = parse_local_worker_role_config_v1(env).expect_err("Router rejects SigningWorker key");
    assert_eq!(err.code(), RouterAbProtocolErrorCode::ForbiddenLocalBinding);
}

#[test]
fn local_deriver_env_rejects_peer_private_material_and_signing_worker_storage() {
    let mut env = parse_template(include_str!("../env/deriver-a.local.example"));
    env.push((
        LOCAL_DERIVER_B_PEER_SIGNING_KEY_ENV_V1.to_owned(),
        "leaked-b-peer-signing-key".to_owned(),
    ));
    let err = parse_local_worker_role_config_v1(env).expect_err("Deriver A rejects B key");
    assert_eq!(err.code(), RouterAbProtocolErrorCode::ForbiddenLocalBinding);

    let mut env = parse_template(include_str!("../env/deriver-b.local.example"));
    env.push((
        LOCAL_DERIVER_A_PEER_SIGNING_KEY_ENV_V1.to_owned(),
        "leaked-a-peer-signing-key".to_owned(),
    ));
    let err = parse_local_worker_role_config_v1(env).expect_err("Deriver B rejects A key");
    assert_eq!(err.code(), RouterAbProtocolErrorCode::ForbiddenLocalBinding);

    let mut env = parse_template(include_str!("../env/deriver-a.local.example"));
    env.push((
        LOCAL_SIGNING_WORKER_SERVER_OUTPUT_STORAGE_PATH_ENV_V1.to_owned(),
        ".router-ab-local/signing-worker/server-output.sqlite".to_owned(),
    ));
    let err = parse_local_worker_role_config_v1(env)
        .expect_err("Deriver A rejects SigningWorker storage");
    assert_eq!(err.code(), RouterAbProtocolErrorCode::ForbiddenLocalBinding);
}

#[test]
fn local_signing_worker_env_rejects_deriver_private_material() {
    let mut env = parse_template(include_str!("../env/signing-worker.local.example"));
    env.push((
        LOCAL_DERIVER_B_ENVELOPE_HPKE_PRIVATE_KEY_ENV_V1.to_owned(),
        "leaked-b-envelope-key".to_owned(),
    ));
    let err =
        parse_local_worker_role_config_v1(env).expect_err("SigningWorker rejects Deriver B key");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::ForbiddenLocalBinding);
}

#[test]
fn local_worker_env_rejects_missing_empty_and_duplicate_required_keys() {
    let mut env = parse_template(include_str!("../env/router.local.example"));
    env.retain(|(key, _)| key != LOCAL_GATEWAY_PUBLIC_URL_ENV_V1);
    let err = parse_local_worker_role_config_v1(env).expect_err("missing Router URL fails");
    assert_eq!(err.code(), RouterAbProtocolErrorCode::MissingLocalBinding);

    let mut env = parse_template(include_str!("../env/router.local.example"));
    for (key, value) in &mut env {
        if key == LOCAL_GATEWAY_PUBLIC_URL_ENV_V1 {
            value.clear();
        }
    }
    let err = parse_local_worker_role_config_v1(env).expect_err("empty Router URL fails");
    assert_eq!(err.code(), RouterAbProtocolErrorCode::EmptyField);

    let mut env = parse_template(include_str!("../env/router.local.example"));
    env.push((LOCAL_WORKER_ROLE_ENV_V1.to_owned(), "router".to_owned()));
    let err = parse_local_worker_role_config_v1(env).expect_err("duplicate role key fails");
    assert_eq!(
        err.code(),
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig
    );
}

#[test]
fn local_worker_helpers_bind_to_role_urls_and_redact_health() {
    let router = parse_local_worker_role_config_v1(parse_template(include_str!(
        "../env/router.local.example"
    )))
    .expect("router template parses");
    let deriver_a = parse_local_worker_role_config_v1(parse_template(include_str!(
        "../env/deriver-a.local.example"
    )))
    .expect("deriver A template parses");

    assert_eq!(
        local_worker_bind_addr_v1(&router).expect("router bind addr"),
        "127.0.0.1:9090"
    );
    assert_eq!(
        local_worker_bind_addr_v1(&deriver_a).expect("deriver A bind addr"),
        "127.0.0.1:9101"
    );

    let health = local_worker_health_response_json_v1(&deriver_a).expect("health JSON");
    let value: serde_json::Value = serde_json::from_str(&health).expect("health parses");
    assert_eq!(value["role"], "deriver_a");
    assert_eq!(value["status"], "ready");
    assert_eq!(value["startup_epoch"], LOCAL_WORKER_STARTUP_EPOCH_V1);
    assert!(!health.contains("PRIVATE"));
    assert!(!health.contains("SECRET"));
    assert!(!health.contains("dev-only"));
}

#[test]
fn local_worker_route_ownership_uses_production_style_paths() {
    assert_eq!(
        local_worker_owned_paths_v1(LocalServiceRoleV1::Router),
        &[
            LOCAL_WORKER_HEALTH_PATH,
            LOCAL_WORKER_READY_PATH,
            LOCAL_ROUTER_NORMAL_SIGNING_PREPARE_PATH,
            LOCAL_ROUTER_NORMAL_SIGNING_PATH,
            LOCAL_ROUTER_AB_ECDSA_DERIVATION_SIGNING_PREPARE_PATH,
            LOCAL_ROUTER_AB_ECDSA_DERIVATION_SIGNING_PATH,
        ]
    );
    assert!(local_worker_owns_path_v1(
        LocalServiceRoleV1::SigningWorker,
        LOCAL_SIGNING_WORKER_NORMAL_SIGNING_PREPARE_PATH
    ));
    assert!(local_worker_owns_path_v1(
        LocalServiceRoleV1::SigningWorker,
        LOCAL_SIGNING_WORKER_NORMAL_SIGNING_PATH
    ));
    assert!(local_worker_owns_path_v1(
        LocalServiceRoleV1::SigningWorker,
        LOCAL_SIGNING_WORKER_ROUTER_AB_ECDSA_DERIVATION_PRESIGNATURE_POOL_PUT_PATH
    ));
    assert!(local_worker_owns_path_v1(
        LocalServiceRoleV1::SigningWorker,
        LOCAL_SIGNING_WORKER_ROUTER_AB_ECDSA_DERIVATION_SIGNING_PREPARE_PATH
    ));
    assert!(local_worker_owns_path_v1(
        LocalServiceRoleV1::SigningWorker,
        LOCAL_SIGNING_WORKER_ROUTER_AB_ECDSA_DERIVATION_SIGNING_PATH
    ));
    assert!(local_worker_owns_path_v1(
        LocalServiceRoleV1::DeriverA,
        LOCAL_DERIVER_A_PRIVATE_PATH
    ));
    assert!(local_worker_owns_path_v1(
        LocalServiceRoleV1::DeriverA,
        LOCAL_DERIVER_A_PEER_PATH
    ));
    assert!(!local_worker_owns_path_v1(
        LocalServiceRoleV1::DeriverB,
        LOCAL_DERIVER_A_PRIVATE_PATH
    ));
}

#[test]
fn local_http_service_binding_maps_checked_paths_to_production_routes() {
    assert_eq!(
        local_http_service_binding_path_v1(LocalHttpPathV1::RouterToSignerA),
        LOCAL_DERIVER_A_PRIVATE_PATH
    );
    assert_eq!(
        local_http_service_binding_path_v1(LocalHttpPathV1::RouterToSignerB),
        LOCAL_DERIVER_B_PRIVATE_PATH
    );
    assert_eq!(
        local_http_service_binding_path_v1(LocalHttpPathV1::SignerAToSignerB),
        LOCAL_DERIVER_B_PEER_PATH
    );
    assert_eq!(
        local_http_service_binding_path_v1(LocalHttpPathV1::SignerBToSignerA),
        LOCAL_DERIVER_A_PEER_PATH
    );

    let endpoint = local_http_service_binding_endpoint_v1(
        "http://127.0.0.1:9101",
        LocalHttpPathV1::RouterToSignerA,
    )
    .expect("endpoint parses");
    assert_eq!(endpoint.owner, LocalServiceRoleV1::DeriverA);
    assert_eq!(endpoint.bind_addr, "127.0.0.1:9101");
    assert_eq!(endpoint.path, LOCAL_DERIVER_A_PRIVATE_PATH);
    assert_eq!(
        endpoint.url,
        local_http_service_binding_url_v1(
            "http://127.0.0.1:9101/",
            LocalHttpPathV1::RouterToSignerA
        )
        .expect("url parses")
    );
}

#[test]
fn local_http_service_binding_client_posts_canonical_wire_bytes() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
    let addr = listener.local_addr().expect("listener addr");
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept request");
        let mut request = Vec::new();
        stream.read_to_end(&mut request).expect("read request");
        let header_end = request
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .expect("request header terminator");
        let headers =
            std::str::from_utf8(&request[..header_end]).expect("request headers are UTF-8");
        assert!(headers.starts_with("POST /router-ab/deriver-a HTTP/1.1"));
        assert!(headers.contains(&format!(
            "content-type: {LOCAL_HTTP_CANONICAL_WIRE_CONTENT_TYPE_V1}"
        )));
        assert_eq!(&request[header_end + 4..], &[0xaa, 0xbb]);
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\ncontent-length: 3\r\nconnection: close\r\n\r\n\x01\x02\x03",
            )
            .expect("write response");
    });

    let client = LocalHttpServiceBindingClientV1::default();
    let body = CanonicalWireBytesV1::new(vec![0xaa, 0xbb]).expect("request body");
    let response = client
        .post_canonical_wire_bytes_v1(
            &format!("http://{addr}"),
            LocalHttpPathV1::RouterToSignerA,
            &body,
        )
        .expect("local HTTP service-binding response");
    assert_eq!(response.as_bytes(), &[0x01, 0x02, 0x03]);
    handle.join().expect("server thread completes");
}

#[test]
fn local_http_service_binding_client_posts_worker_shaped_json() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
    let addr = listener.local_addr().expect("listener addr");
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept request");
        let mut request = Vec::new();
        stream.read_to_end(&mut request).expect("read request");
        let header_end = request
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .expect("request header terminator");
        let headers =
            std::str::from_utf8(&request[..header_end]).expect("request headers are UTF-8");
        assert!(headers.starts_with("POST /router-ab/deriver-b/peer HTTP/1.1"));
        assert!(headers.contains(&format!("content-type: {LOCAL_HTTP_JSON_CONTENT_TYPE_V1}")));
        let body: serde_json::Value =
            serde_json::from_slice(&request[header_end + 4..]).expect("request JSON parses");
        assert_eq!(body["kind"], "peer");
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 15\r\nconnection: close\r\n\r\n{\"ok\":true}",
            )
            .expect("write response");
    });

    let client = LocalHttpServiceBindingClientV1::default();
    let response: serde_json::Value = client
        .post_json_v1(
            &format!("http://{addr}"),
            LocalHttpPathV1::SignerAToSignerB,
            &serde_json::json!({ "kind": "peer" }),
        )
        .expect("local HTTP JSON service-binding response");
    assert_eq!(response["ok"], true);
    handle.join().expect("server thread completes");
}

#[test]
fn local_env_materialization_plan_generates_parseable_role_env_files() {
    let plan =
        local_env_materialization_plan_v1(b"test-seed-1").expect("local env materialization plan");

    assert_eq!(
        plan.directories,
        vec![
            LOCAL_ROUTER_STATE_DIR_V1.to_owned(),
            LOCAL_DERIVER_A_STATE_DIR_V1.to_owned(),
            LOCAL_DERIVER_B_STATE_DIR_V1.to_owned(),
            LOCAL_SIGNING_WORKER_STATE_DIR_V1.to_owned(),
        ]
    );
    assert_eq!(
        plan.files
            .iter()
            .map(|file| file.path.as_str())
            .collect::<Vec<_>>(),
        vec![
            LOCAL_ROUTER_ENV_FILE_V1,
            LOCAL_DERIVER_A_ENV_FILE_V1,
            LOCAL_DERIVER_B_ENV_FILE_V1,
            LOCAL_SIGNING_WORKER_ENV_FILE_V1,
        ]
    );
    for file in &plan.files {
        assert!(!file.contents.contains("dev-only-deriver"));
        assert!(!file.contents.contains("dev-only-signing-worker"));
        match file.role {
            LocalServiceRoleV1::DeriverA | LocalServiceRoleV1::DeriverB => {
                assert!(file.contents.contains("dev-only-generated-"));
            }
            LocalServiceRoleV1::SigningWorker => {
                assert!(!file
                    .contents
                    .contains("dev-only-signing-worker-server-output-hpke-private-key"));
                assert!(!file.contents.contains(
                    "x25519:3333333333333333333333333333333333333333333333333333333333333333"
                ));
            }
            LocalServiceRoleV1::Router => {}
        }
        let config = parse_local_worker_role_config_for_role_v1(
            file.role,
            parse_local_env_file_contents_v1(&file.contents).expect("generated env parses"),
        )
        .expect("generated env validates against role");
        assert_eq!(config.role(), file.role);
    }
}

#[test]
fn local_env_materialization_plan_is_seed_bound() {
    let first = local_env_materialization_plan_v1(b"seed-a").expect("first plan");
    let second = local_env_materialization_plan_v1(b"seed-a").expect("second plan");
    let third = local_env_materialization_plan_v1(b"seed-b").expect("third plan");

    assert_eq!(first, second);
    assert_ne!(first, third);
}

#[test]
fn local_env_materialization_exposes_only_public_keys_matching_role_private_keys() {
    let plan = local_env_materialization_plan_v1(b"key-coherence-seed").expect("materialization");
    let configs = plan
        .files
        .iter()
        .map(|file| {
            parse_local_worker_role_config_for_role_v1(
                file.role,
                parse_local_env_file_contents_v1(&file.contents).expect("env parses"),
            )
            .expect("config parses")
        })
        .collect::<Vec<_>>();
    let router = configs
        .iter()
        .find_map(|config| match config {
            LocalWorkerRoleConfigV1::Router(router) => Some(router),
            _ => None,
        })
        .expect("Router config");
    let deriver_a = configs
        .iter()
        .find_map(|config| match config {
            LocalWorkerRoleConfigV1::DeriverA(deriver) => Some(deriver),
            _ => None,
        })
        .expect("Deriver A config");
    let deriver_b = configs
        .iter()
        .find_map(|config| match config {
            LocalWorkerRoleConfigV1::DeriverB(deriver) => Some(deriver),
            _ => None,
        })
        .expect("Deriver B config");
    let signing_worker = configs
        .iter()
        .find_map(|config| match config {
            LocalWorkerRoleConfigV1::SigningWorker(worker) => Some(worker),
            _ => None,
        })
        .expect("SigningWorker config");

    assert_hpke_key_pair(
        &router.deriver_a_ed25519_yao_input_public_key,
        &deriver_a.envelope_hpke_private_key,
        Ed25519YaoDeriverRoleV1::DeriverA,
    );
    assert_hpke_key_pair(
        &router.deriver_b_ed25519_yao_input_public_key,
        &deriver_b.envelope_hpke_private_key,
        Ed25519YaoDeriverRoleV1::DeriverB,
    );
    assert_eq!(
        router.signing_worker_ed25519_yao_recipient_public_key,
        signing_worker.server_output_hpke_public_key
    );
    assert_hpke_key_pair(
        &router.signing_worker_ed25519_yao_recipient_public_key,
        &signing_worker.server_output_hpke_private_key,
        Ed25519YaoDeriverRoleV1::DeriverA,
    );
}

#[test]
fn local_env_materialization_plan_rejects_empty_seed() {
    let err = local_env_materialization_plan_v1(&[]).expect_err("empty seed rejected");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::EmptyField);
}

fn parse_template(contents: &str) -> Vec<(String, String)> {
    contents
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| {
            let (key, value) = line.split_once('=').expect("template line has =");
            (key.to_owned(), value.to_owned())
        })
        .collect()
}

fn assert_hpke_key_pair(public_key: &str, private_key: &str, deriver: Ed25519YaoDeriverRoleV1) {
    let public_key: [u8; 32] = hex::decode(
        public_key
            .strip_prefix("x25519:")
            .expect("public key prefix"),
    )
    .expect("public key hex")
    .try_into()
    .expect("public key length");
    let private_key: [u8; 32] = hex::decode(private_key)
        .expect("private key hex")
        .try_into()
        .expect("private key length");
    let envelope = seal_local_ed25519_yao_package_v1(
        Ed25519YaoPackageKindV1::ActivationClient,
        deriver,
        [1; 32],
        [2; 32],
        public_key,
        b"key-coherence",
    )
    .expect("seal with public key");
    let opened = open_local_ed25519_yao_client_package_v1(
        &envelope,
        &LocalEd25519YaoRecipientPrivateKeyV1::from_bytes(private_key),
    )
    .expect("open with private key");
    assert_eq!(opened.as_slice(), b"key-coherence");
}
