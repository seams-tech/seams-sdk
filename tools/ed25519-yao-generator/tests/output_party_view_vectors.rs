use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::SigningKey;
use ed25519_yao_generator::{
    canonical_output_party_view_vector_corpus_json_bytes_v1,
    canonical_output_party_view_vector_corpus_v1,
    parse_canonical_output_party_view_vector_corpus_json_v1,
    OUTPUT_PARTY_VIEW_VECTOR_CORPUS_SCHEMA_V1, OUTPUT_PARTY_VIEW_VECTOR_EVIDENCE_SCOPE_V1,
};
use serde_json::Value;

const COMMITTED: &[u8] = include_bytes!("../vectors/ed25519-yao-output-party-views-v1.json");
const SEMANTIC: &[u8] = include_bytes!("../vectors/ed25519-yao-semantic-lifecycle-v1.json");

#[test]
fn committed_bytes_headers_and_five_case_order_are_exact() {
    let generated = canonical_output_party_view_vector_corpus_json_bytes_v1();
    assert_eq!(generated, COMMITTED);
    assert!(COMMITTED.ends_with(b"\n"));
    assert!(!COMMITTED[..COMMITTED.len() - 1].ends_with(b"\n"));

    let corpus = canonical_output_party_view_vector_corpus_v1();
    assert_eq!(corpus.schema(), OUTPUT_PARTY_VIEW_VECTOR_CORPUS_SCHEMA_V1);
    assert_eq!(corpus.protocol_id(), "router_ab_ed25519_yao_v1");
    assert_eq!(
        corpus.evidence_scope(),
        OUTPUT_PARTY_VIEW_VECTOR_EVIDENCE_SCOPE_V1
    );
    assert_eq!(corpus.case_count(), 5);

    let value = output_corpus();
    let cases = value["cases"].as_array().expect("cases");
    let expected = [
        (
            "registration",
            "registration_output_party_views_package_prepared_v1",
            "registration_package_prepared",
        ),
        (
            "activation",
            "activation_output_party_views_metadata_consumed_v1",
            "activation_metadata_consumed",
        ),
        (
            "recovery",
            "recovery_output_party_views_package_prepared_v1",
            "recovery_package_prepared",
        ),
        (
            "refresh",
            "refresh_output_party_views_package_prepared_v1",
            "refresh_package_prepared",
        ),
        (
            "export",
            "export_output_party_views_released_v1",
            "export_released",
        ),
    ];
    for (case, (kind, case_id, stage)) in cases.iter().zip(expected) {
        assert_eq!(case["request_kind"], kind);
        assert_eq!(case["vector"]["case_id"], case_id);
        assert_eq!(case["vector"]["stage"], stage);
    }

    let text = std::str::from_utf8(COMMITTED).expect("UTF-8 corpus");
    assert_substrings_in_order(
        text,
        &[
            "\"schema\"",
            "\"protocol_id\"",
            "\"evidence_scope\"",
            "\"cases\"",
            "registration_output_party_views_package_prepared_v1",
            "activation_output_party_views_metadata_consumed_v1",
            "recovery_output_party_views_package_prepared_v1",
            "refresh_output_party_views_package_prepared_v1",
            "export_output_party_views_released_v1",
        ],
    );
}

#[test]
fn public_digests_and_metadata_consumption_cross_link_semantic_lifecycle() {
    let output = output_corpus();
    let semantic: Value = serde_json::from_slice(SEMANTIC).expect("semantic corpus");
    let output_cases = output["cases"].as_array().expect("output cases");
    let semantic_cases = semantic["cases"].as_array().expect("semantic cases");

    for index in [0_usize, 2, 3] {
        assert_activation_public_crosslinks(&output_cases[index], &semantic_cases[index]);
    }
    assert_activation_control_crosslinks(&output_cases[1], &semantic_cases[1]);
    assert_export_public_crosslinks(&output_cases[4], &semantic_cases[4]);

    let registered_keys: Vec<_> = [0_usize, 2, 3, 4]
        .into_iter()
        .map(|index| {
            output_cases[index]["vector"]["common_public"]["registered_public_key_hex"]
                .as_str()
                .expect("registered key")
        })
        .collect();
    assert!(registered_keys.windows(2).all(|pair| pair[0] == pair[1]));
    for origin in output_cases[1]["vector"]["common_public"]["origin_metadata_projections"]
        .as_array()
        .expect("activation origins")
    {
        assert_eq!(
            origin["registered_public_key_hex"].as_str(),
            Some(registered_keys[0])
        );
    }
}

#[test]
fn private_share_relations_and_public_points_hold() {
    let output = output_corpus();
    let cases = output["cases"].as_array().expect("cases");
    for index in [0_usize, 2, 3] {
        let vector = &cases[index]["vector"];
        let extensions = &vector["role_extensions"];
        let common = &vector["common_public"];
        let projection = &common["package_projection"];

        let client_a = scalar_hex(&extensions["deriver_a"]["client_scalar_share_hex"]);
        let client_b = scalar_hex(&extensions["deriver_b"]["client_scalar_share_hex"]);
        let worker_a = scalar_hex(&extensions["deriver_a"]["signing_worker_scalar_share_hex"]);
        let worker_b = scalar_hex(&extensions["deriver_b"]["signing_worker_scalar_share_hex"]);
        let client = client_a + client_b;
        let worker = worker_a + worker_b;

        assert_eq!(extensions["client"]["kind"], "client_no_private_output");
        assert_eq!(
            point_hex(client_a),
            projection["deriver_a_client"]["share_point_hex"]
        );
        assert_eq!(
            point_hex(client_b),
            projection["deriver_b_client"]["share_point_hex"]
        );
        assert_eq!(
            point_hex(worker_a),
            projection["deriver_a_signing_worker"]["share_point_hex"]
        );
        assert_eq!(
            point_hex(worker_b),
            projection["deriver_b_signing_worker"]["share_point_hex"]
        );
        assert_eq!(point_hex(client), common["x_client_hex"]);
        assert_eq!(point_hex(worker), common["x_server_hex"]);
        let registered = (ED25519_BASEPOINT_POINT * (client + client - worker))
            .compress()
            .to_bytes();
        assert_eq!(registered, hex_32(&common["registered_public_key_hex"]));
    }

    let export = &cases[4]["vector"];
    let extensions = &export["role_extensions"];
    let seed_a = hex_32(&extensions["deriver_a"]["seed_share_hex"]);
    let seed_b = hex_32(&extensions["deriver_b"]["seed_share_hex"]);
    let seed = wrapping_add_le_256(seed_a, seed_b);
    assert_eq!(seed, hex_32(&extensions["client"]["seed_hex"]));
    assert_eq!(
        SigningKey::from_bytes(&seed).verifying_key().to_bytes(),
        hex_32(&export["common_public"]["registered_public_key_hex"])
    );
}

#[test]
fn role_extensions_are_sealed_and_forbidden_fields_are_absent() {
    let output = output_corpus();
    let cases = output["cases"].as_array().expect("cases");
    let role_order = [
        "deriver_a",
        "deriver_b",
        "client",
        "signing_worker",
        "router",
        "observer",
        "diagnostics_logs",
    ];

    for case in cases {
        let extensions = case["vector"]["role_extensions"]
            .as_object()
            .expect("role extensions");
        assert_eq!(extensions.len(), role_order.len());
        for role in role_order {
            assert!(extensions.contains_key(role));
        }
    }

    for index in [0_usize, 2, 3] {
        let extensions = &cases[index]["vector"]["role_extensions"];
        assert_eq!(object_len(&extensions["deriver_a"]), 3);
        assert_eq!(object_len(&extensions["deriver_b"]), 3);
        assert_eq!(object_len(&extensions["client"]), 1);
        for role in ["signing_worker", "router", "observer", "diagnostics_logs"] {
            assert_eq!(object_len(&extensions[role]), 1);
        }
        assert_no_key_containing(&cases[index]["vector"], "seed");
    }

    let activation_extensions = &cases[1]["vector"]["role_extensions"];
    for role in role_order {
        assert_eq!(object_len(&activation_extensions[role]), 1);
    }
    assert_no_key_containing(&cases[1]["vector"], "scalar");
    assert_no_key_containing(&cases[1]["vector"], "seed");

    let export = &cases[4]["vector"];
    assert_eq!(object_len(&export["role_extensions"]["deriver_a"]), 2);
    assert_eq!(object_len(&export["role_extensions"]["deriver_b"]), 2);
    assert_eq!(object_len(&export["role_extensions"]["client"]), 2);
    assert_no_key_containing(export, "scalar");
    assert!(!export["common_public"]
        .as_object()
        .expect("export common")
        .contains_key("x_server_hex"));

    let forbidden = [
        "clear_reference_trace",
        "host_only_source_reference",
        "host_only_joined_output",
        "host_only_joined_outputs",
        "host_only_reference_randomness",
        "client_root_hex",
        "deriver_a_root_hex",
        "deriver_b_root_hex",
        "contributions",
        "joined_seed_hex",
        "sha512_digest_hex",
        "clamped_scalar_bytes_hex",
        "signing_scalar_hex",
        "tau_a_hex",
        "tau_b_hex",
        "tau_hex",
        "x_server_base_hex",
        "y_a_hex",
        "y_b_hex",
        "joined_y_hex",
        "refresh_delta_y_hex",
        "refresh_delta_tau_hex",
        "credential_hex",
        "recovery_envelope_hex",
        "ciphertext_bytes_hex",
        "recipient_decryption_key_hex",
        "garbling_seed_hex",
        "label_hex",
        "mask_hex",
        "ot_state_hex",
    ];
    assert_forbidden_keys_absent(&output, &forbidden);
}

#[test]
fn static_observations_match_only_their_source_role_extension() {
    let output = output_corpus();
    for case in output["cases"].as_array().expect("cases") {
        let vector = &case["vector"];
        let observations = &vector["static_deriver_observations"];
        for (role, kind) in [
            ("deriver_a", "static_consuming_deriver_a"),
            ("deriver_b", "static_consuming_deriver_b"),
        ] {
            let observation = &observations[role];
            assert_eq!(observation["observation_kind"], kind);
            assert_eq!(observation["source_case_id"], vector["case_id"]);
            assert_eq!(observation["source_stage"], vector["stage"]);
            assert_eq!(observation["extension"], vector["role_extensions"][role]);
            let observation_object = observation.as_object().expect("observation object");
            assert_eq!(observation_object.len(), 4);
            assert!(!observation_object.contains_key(if role == "deriver_a" {
                "deriver_b"
            } else {
                "deriver_a"
            }));
        }
    }
}

#[test]
fn parser_accepts_only_exact_lf_terminated_canonical_bytes() {
    assert!(parse_canonical_output_party_view_vector_corpus_json_v1(COMMITTED).is_ok());

    let without_lf = &COMMITTED[..COMMITTED.len() - 1];
    assert!(parse_canonical_output_party_view_vector_corpus_json_v1(without_lf).is_err());

    let mut extra_lf = COMMITTED.to_vec();
    extra_lf.push(b'\n');
    assert!(parse_canonical_output_party_view_vector_corpus_json_v1(&extra_lf).is_err());

    let crlf = String::from_utf8(COMMITTED.to_vec())
        .expect("UTF-8 corpus")
        .replace('\n', "\r\n");
    assert!(parse_canonical_output_party_view_vector_corpus_json_v1(crlf.as_bytes()).is_err());

    let mut whitespace = COMMITTED.to_vec();
    whitespace.insert(1, b' ');
    assert!(parse_canonical_output_party_view_vector_corpus_json_v1(&whitespace).is_err());

    let reordered = std::str::from_utf8(COMMITTED)
        .expect("UTF-8 corpus")
        .replacen(
            "  \"schema\": \"seams:router-ab:ed25519-yao:output-party-views-vectors:v1\",\n  \"protocol_id\": \"router_ab_ed25519_yao_v1\",",
            "  \"protocol_id\": \"router_ab_ed25519_yao_v1\",\n  \"schema\": \"seams:router-ab:ed25519-yao:output-party-views-vectors:v1\",",
            1,
        );
    assert!(parse_canonical_output_party_view_vector_corpus_json_v1(reordered.as_bytes()).is_err());
}

fn output_corpus() -> Value {
    serde_json::from_slice(COMMITTED).expect("output party-view corpus")
}

fn assert_activation_public_crosslinks(output: &Value, semantic: &Value) {
    let common = &output["vector"]["common_public"];
    let semantic_vector = &semantic["vector"];
    assert_eq!(
        common["semantic_lifecycle_case_id"],
        semantic_vector["case_id"]
    );
    assert_eq!(
        common["public_request_context_digest_hex"],
        semantic_vector["ceremony"]["public_request_context_digest_sha256_hex"]
    );
    assert_eq!(
        common["authorization_digest_hex"],
        semantic_vector["ceremony"]["authorization_digest_sha256_hex"]
    );
    assert_eq!(
        common["transcript_digest_hex"],
        semantic_vector["ceremony"]["transcript_digest_sha256_hex"]
    );
    assert_eq!(
        common["package_set_digest_hex"],
        semantic_vector["packages"]["package_set_digest_sha256_hex"]
    );
    assert_eq!(
        common["receipt_body_digest_hex"],
        semantic_vector["receipt"]["receipt_body_digest_sha256_hex"]
    );
    let identity = &semantic_vector["persistence"]["projection"]["identity"];
    for key in [
        "one_use_execution_id_hex",
        "package_set_digest_hex",
        "activation_epoch",
        "registered_public_key_hex",
    ] {
        assert_eq!(common[key], identity[key]);
    }
    assert_eq!(
        common["receipt_body_digest_hex"],
        identity["receipt_digest_hex"]
    );
}

fn assert_activation_control_crosslinks(output: &Value, semantic: &Value) {
    let common = &output["vector"]["common_public"];
    let semantic_vector = &semantic["vector"];
    assert_eq!(
        common["semantic_lifecycle_case_id"],
        semantic_vector["case_id"]
    );
    let origins = common["origin_metadata_projections"]
        .as_array()
        .expect("origins");
    let semantic_origins = semantic_vector["metadata_consumed"]
        .as_array()
        .expect("semantic origins");
    assert_eq!(origins.len(), 3);
    for (origin, semantic_origin) in origins.iter().zip(semantic_origins) {
        assert_eq!(origin["origin_kind"], semantic_origin["origin_kind"]);
        assert_eq!(origin["origin_case_id"], semantic_origin["origin_case_id"]);
        let projection = &semantic_origin["persistence"]["projection"];
        let identity = &projection["committed"]["identity"];
        for key in [
            "origin_request_context_digest_hex",
            "origin_authorization_digest_hex",
            "origin_transcript_digest_hex",
            "one_use_execution_id_hex",
            "package_set_digest_hex",
            "activation_epoch",
            "registered_public_key_hex",
        ] {
            assert_eq!(origin[key], identity[key]);
        }
        assert_eq!(
            origin["receipt_body_digest_hex"],
            identity["receipt_digest_hex"]
        );
        for key in [
            "activation_request_context_digest_hex",
            "activation_authorization_digest_hex",
            "activation_transcript_digest_hex",
        ] {
            assert_eq!(origin[key], projection[key]);
        }
        assert_eq!(
            origin["zero_reevaluation"],
            semantic_origin["zero_reevaluation"]
        );
    }
}

fn assert_export_public_crosslinks(output: &Value, semantic: &Value) {
    let common = &output["vector"]["common_public"];
    let semantic_vector = &semantic["vector"];
    assert_eq!(
        common["semantic_lifecycle_case_id"],
        semantic_vector["case_id"]
    );
    assert_eq!(
        common["public_request_context_digest_hex"],
        semantic_vector["ceremony"]["public_request_context_digest_sha256_hex"]
    );
    assert_eq!(
        common["authorization_digest_hex"],
        semantic_vector["ceremony"]["authorization_digest_sha256_hex"]
    );
    assert_eq!(
        common["transcript_digest_hex"],
        semantic_vector["ceremony"]["transcript_digest_sha256_hex"]
    );
    assert_eq!(
        common["package_set_digest_hex"],
        semantic_vector["packages"]["package_set_digest_sha256_hex"]
    );
    assert_eq!(
        common["receipt_body_digest_hex"],
        semantic_vector["receipt"]["receipt_body_digest_sha256_hex"]
    );
    assert_eq!(common["state_effect"], semantic_vector["state_effect"]);
}

fn scalar_hex(value: &Value) -> Scalar {
    Option::<Scalar>::from(Scalar::from_canonical_bytes(hex_32(value)))
        .expect("canonical fixture scalar")
}

fn point_hex(scalar: Scalar) -> Value {
    Value::String(hex::encode(
        (ED25519_BASEPOINT_POINT * scalar).compress().to_bytes(),
    ))
}

fn hex_32(value: &Value) -> [u8; 32] {
    let text = value.as_str().expect("hex string");
    assert_eq!(text.len(), 64);
    let mut output = [0_u8; 32];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).expect("lower hex");
    }
    output
}

fn wrapping_add_le_256(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut output = [0_u8; 32];
    let mut carry = 0_u16;
    for index in 0..32 {
        let sum = left[index] as u16 + right[index] as u16 + carry;
        output[index] = sum as u8;
        carry = sum >> 8;
    }
    output
}

fn object_len(value: &Value) -> usize {
    value.as_object().expect("object").len()
}

fn assert_no_key_containing(value: &Value, needle: &str) {
    match value {
        Value::Object(object) => {
            for (key, child) in object {
                assert!(!key.contains(needle), "unexpected key: {key}");
                assert_no_key_containing(child, needle);
            }
        }
        Value::Array(values) => {
            for child in values {
                assert_no_key_containing(child, needle);
            }
        }
        _ => {}
    }
}

fn assert_forbidden_keys_absent(value: &Value, forbidden: &[&str]) {
    match value {
        Value::Object(object) => {
            for (key, child) in object {
                assert!(!forbidden.contains(&key.as_str()), "forbidden key: {key}");
                for suffix in [
                    "_coin_hex",
                    "_root",
                    "_root_hex",
                    "_contribution",
                    "_contribution_hex",
                    "_private_key_hex",
                    "_decryption_key_hex",
                ] {
                    assert!(!key.ends_with(suffix), "forbidden key suffix: {key}");
                }
                assert_forbidden_keys_absent(child, forbidden);
            }
        }
        Value::Array(values) => {
            for child in values {
                assert_forbidden_keys_absent(child, forbidden);
            }
        }
        _ => {}
    }
}

fn assert_substrings_in_order(value: &str, expected: &[&str]) {
    let mut offset = 0;
    for item in expected {
        let relative = value[offset..].find(item).expect("ordered substring");
        offset += relative + item.len();
    }
}

mod hex {
    pub fn encode(bytes: [u8; 32]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut output = String::with_capacity(64);
        for byte in bytes {
            output.push(HEX[(byte >> 4) as usize] as char);
            output.push(HEX[(byte & 0x0f) as usize] as char);
        }
        output
    }
}
