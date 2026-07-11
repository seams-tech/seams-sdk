use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::SigningKey;
use ed25519_yao_generator::{
    canonical_evaluation_input_party_view_vector_corpus_json_bytes_v1,
    canonical_evaluation_input_party_view_vector_corpus_v1, clamp_rfc8032,
    parse_canonical_evaluation_input_party_view_vector_corpus_json_v1,
    EVALUATION_INPUT_PARTY_VIEW_VECTOR_CORPUS_SCHEMA_V1,
    EVALUATION_INPUT_PARTY_VIEW_VECTOR_EVIDENCE_SCOPE_V1,
};
use serde_json::{Map, Value};
use sha2::{Digest, Sha512};

const COMMITTED: &[u8] =
    include_bytes!("../vectors/ed25519-yao-evaluation-input-party-views-v1.json");
const CEREMONY: &[u8] = include_bytes!("../vectors/ed25519-yao-ceremony-context-v1.json");
const PROVENANCE: &[u8] = include_bytes!("../vectors/ed25519-yao-provenance-v1.json");
const SEMANTIC: &[u8] = include_bytes!("../vectors/ed25519-yao-semantic-lifecycle-v1.json");
const OUTPUT: &[u8] = include_bytes!("../vectors/ed25519-yao-output-party-views-v1.json");

#[test]
fn committed_bytes_headers_order_and_parser_are_exact() {
    let generated = canonical_evaluation_input_party_view_vector_corpus_json_bytes_v1();
    assert_eq!(generated, COMMITTED);
    assert!(COMMITTED.ends_with(b"\n"));
    assert!(!COMMITTED[..COMMITTED.len() - 1].ends_with(b"\n"));

    let corpus = canonical_evaluation_input_party_view_vector_corpus_v1();
    assert_eq!(
        corpus.schema(),
        EVALUATION_INPUT_PARTY_VIEW_VECTOR_CORPUS_SCHEMA_V1
    );
    assert_eq!(corpus.protocol_id(), "router_ab_ed25519_yao_v1");
    assert_eq!(
        corpus.evidence_scope(),
        EVALUATION_INPUT_PARTY_VIEW_VECTOR_EVIDENCE_SCOPE_V1
    );
    assert_eq!(corpus.case_count(), 5);

    let input = input_corpus();
    let cases = cases(&input);
    let expected = [
        (
            "registration",
            "registration_evaluation_input_party_views_v1",
            "registration_evaluation_accepted",
        ),
        (
            "activation",
            "activation_no_evaluation_input_party_views_v1",
            "activation_continuation_accepted",
        ),
        (
            "recovery",
            "recovery_evaluation_input_party_views_v1",
            "recovery_evaluation_accepted",
        ),
        (
            "refresh",
            "refresh_evaluation_input_party_views_v1",
            "refresh_evaluation_accepted",
        ),
        (
            "export",
            "export_evaluation_input_party_views_v1",
            "export_evaluation_accepted",
        ),
    ];
    for (case, (kind, case_id, stage)) in cases.iter().zip(expected) {
        assert_eq!(case["request_kind"], kind);
        assert_eq!(case["vector"]["case_id"], case_id);
        assert_eq!(case["vector"]["stage"], stage);
        assert_eq!(case["vector"]["common_public"]["stage"], stage);
        assert_eq!(case["vector"]["common_public"]["request_kind"], kind);
    }

    let mut appended = COMMITTED.to_vec();
    appended.push(b'\n');
    assert!(parse_canonical_evaluation_input_party_view_vector_corpus_json_v1(&appended).is_err());
    let mut changed = COMMITTED.to_vec();
    let position = changed
        .windows("registration_evaluation_accepted".len())
        .position(|window| window == b"registration_evaluation_accepted")
        .expect("stage occurs");
    changed[position] = b'R';
    assert!(parse_canonical_evaluation_input_party_view_vector_corpus_json_v1(&changed).is_err());
}

#[test]
fn producing_common_values_cross_link_ceremony_provenance_and_named_companions() {
    let input = input_corpus();
    let ceremony = parse(CEREMONY);
    let provenance = parse(PROVENANCE);
    let semantic = parse(SEMANTIC);
    let output = parse(OUTPUT);

    for index in [0_usize, 2, 3, 4] {
        let vector = &cases(&input)[index]["vector"];
        let sources = &vector["host_only_source_references"];
        let common = &vector["common_public"];
        let ceremony_case = case_by_id(&ceremony, string(sources, "ceremony_context_case_id"));
        let expected = &ceremony_case["vector"]["expected"];
        assert_eq!(
            common["public_request_context_digest_hex"],
            expected["public_request_context_digest_sha256_hex"]
        );
        assert_eq!(
            common["authorization_digest_hex"],
            expected["authorization_digest_sha256_hex"]
        );
        assert_eq!(
            common["transcript_digest_hex"],
            expected["transcript_digest_sha256_hex"]
        );

        let provenance_case = case_by_id(&provenance, string(sources, "provenance_case_id"));
        let provenance_vector = &provenance_case["vector"];
        assert_eq!(
            common["public_request_context_digest_hex"],
            provenance_vector["public_request_context_digest_hex"]
        );
        assert_eq!(
            common["authorization_digest_hex"],
            provenance_vector["authorization_digest_hex"]
        );
        assert_eq!(
            common["transcript_digest_hex"],
            provenance_vector["transcript_digest_hex"]
        );
        assert_eq!(
            common["input_provenance_pair_digest_hex"],
            provenance_vector["pair_digest_sha256_hex"]
        );

        let _ = case_by_id(&semantic, string(sources, "semantic_lifecycle_case_id"));
        let _ = case_by_id(&output, string(sources, "output_party_view_case_id"));
    }
}

#[test]
fn activation_has_zero_work_empty_views_and_one_registration_origin() {
    let input = input_corpus();
    let output = parse(OUTPUT);
    let semantic = parse(SEMANTIC);
    let vector = &cases(&input)[1]["vector"];
    let counts = &vector["common_public"]["evaluation_plan"]["counts"];
    for key in [
        "yao_evaluations",
        "deriver_a_invocations",
        "deriver_b_invocations",
        "contribution_derivations",
        "ideal_output_share_samples",
    ] {
        assert_eq!(counts[key], 0);
    }
    assert_eq!(
        vector["host_only_ideal_function_randomness"]["kind"],
        "activation_no_ideal_function_randomness"
    );
    let extensions = object(&vector["role_extensions"]);
    assert_eq!(extensions.len(), 7);
    for extension in extensions.values() {
        assert_eq!(object(extension).len(), 1);
    }

    let sources = &vector["host_only_source_references"];
    assert_eq!(sources["activation_origin"], "registration");
    let output_case = case_by_id(&output, string(sources, "output_party_view_case_id"));
    let projection = &output_case["vector"]["common_public"]["origin_metadata_projections"][0];
    assert_eq!(projection["origin_kind"], "registration");
    assert_eq!(
        vector["common_public"]["public_request_context_digest_hex"],
        projection["activation_request_context_digest_hex"]
    );
    assert_eq!(
        vector["common_public"]["authorization_digest_hex"],
        projection["activation_authorization_digest_hex"]
    );
    assert_eq!(
        vector["common_public"]["transcript_digest_hex"],
        projection["activation_transcript_digest_hex"]
    );
    let semantic_case = case_by_id(&semantic, string(sources, "semantic_lifecycle_case_id"));
    let semantic_projection = &semantic_case["vector"]["metadata_consumed"][0];
    assert_eq!(
        projection["activation_request_context_digest_hex"],
        semantic_projection["persistence"]["projection"]["activation_request_context_digest_hex"]
    );
}

#[test]
fn recovery_preserves_inputs_and_refresh_applies_exact_opposite_server_delta() {
    let input = input_corpus();
    let cases = cases(&input);
    let registration = &cases[0]["vector"]["role_extensions"];
    let recovery = &cases[2]["vector"]["role_extensions"];
    let refresh = &cases[3]["vector"]["role_extensions"];
    assert_eq!(registration, recovery);

    for role in ["deriver_a", "deriver_b"] {
        assert_eq!(
            registration[role]["y_client_hex"],
            refresh[role]["y_client_hex"]
        );
        assert_eq!(
            registration[role]["tau_client_hex"],
            refresh[role]["tau_client_hex"]
        );
    }

    let a_y_delta = wrapping_sub_le_256(
        hex32(&refresh["deriver_a"]["y_server_hex"]),
        hex32(&registration["deriver_a"]["y_server_hex"]),
    );
    let b_y_delta = wrapping_sub_le_256(
        hex32(&refresh["deriver_b"]["y_server_hex"]),
        hex32(&registration["deriver_b"]["y_server_hex"]),
    );
    assert_eq!(wrapping_add_le_256(a_y_delta, b_y_delta), [0; 32]);

    let a_tau_delta = scalar(&refresh["deriver_a"]["tau_server_hex"])
        - scalar(&registration["deriver_a"]["tau_server_hex"]);
    let b_tau_delta = scalar(&refresh["deriver_b"]["tau_server_hex"])
        - scalar(&registration["deriver_b"]["tau_server_hex"]);
    assert_eq!(a_tau_delta + b_tau_delta, Scalar::ZERO);
    assert_ne!(a_tau_delta, Scalar::ZERO);
}

#[test]
fn activation_family_inputs_and_ideal_coins_reproduce_output_party_views() {
    let input = input_corpus();
    let output = parse(OUTPUT);
    for index in [0_usize, 2, 3] {
        let vector = &cases(&input)[index]["vector"];
        let role_inputs = &vector["role_extensions"];
        let y = joined_y(role_inputs);
        let mut prefix = [0_u8; 32];
        prefix.copy_from_slice(&Sha512::digest(y)[..32]);
        let a = Scalar::from_bytes_mod_order(clamp_rfc8032(prefix));
        let tau = scalar(&role_inputs["deriver_a"]["tau_client_hex"])
            + scalar(&role_inputs["deriver_a"]["tau_server_hex"])
            + scalar(&role_inputs["deriver_b"]["tau_client_hex"])
            + scalar(&role_inputs["deriver_b"]["tau_server_hex"]);
        let x_client = a + tau;
        let x_server = a + tau + tau;

        let sources = &vector["host_only_source_references"];
        let output_case = case_by_id(&output, string(sources, "output_party_view_case_id"));
        let output_vector = &output_case["vector"];
        let role_outputs = &output_vector["role_extensions"];
        let randomness = &vector["host_only_ideal_function_randomness"];
        let client_coin = scalar(&randomness["client_scalar_coin_hex"]);
        let worker_coin = scalar(&randomness["signing_worker_scalar_coin_hex"]);
        assert_eq!(
            scalar(&role_outputs["deriver_a"]["client_scalar_share_hex"]),
            client_coin
        );
        assert_eq!(
            scalar(&role_outputs["deriver_a"]["signing_worker_scalar_share_hex"]),
            worker_coin
        );
        assert_eq!(
            client_coin + scalar(&role_outputs["deriver_b"]["client_scalar_share_hex"]),
            x_client
        );
        assert_eq!(
            worker_coin + scalar(&role_outputs["deriver_b"]["signing_worker_scalar_share_hex"]),
            x_server
        );
        assert_eq!(role_outputs["client"]["kind"], "client_no_private_output");
        assert_eq!(
            output_vector["common_public"]["x_client_hex"],
            encode_hex((ED25519_BASEPOINT_POINT * x_client).compress().to_bytes())
        );
        assert_eq!(
            output_vector["common_public"]["x_server_hex"],
            encode_hex((ED25519_BASEPOINT_POINT * x_server).compress().to_bytes())
        );
    }
}

#[test]
fn export_is_y_only_and_ideal_coin_reproduces_seed_outputs() {
    let input = input_corpus();
    let output = parse(OUTPUT);
    let vector = &cases(&input)[4]["vector"];
    for role in ["deriver_a", "deriver_b"] {
        let extension = object(&vector["role_extensions"][role]);
        assert_eq!(extension.len(), 3);
        assert!(extension.contains_key("y_client_hex"));
        assert!(extension.contains_key("y_server_hex"));
        assert!(!extension.keys().any(|key| key.contains("tau")));
    }
    let seed = joined_y(&vector["role_extensions"]);
    let source = &vector["host_only_source_references"];
    let output_case = case_by_id(&output, string(source, "output_party_view_case_id"));
    let role_outputs = &output_case["vector"]["role_extensions"];
    let coin = hex32(&vector["host_only_ideal_function_randomness"]["seed_output_coin_hex"]);
    assert_eq!(hex32(&role_outputs["deriver_a"]["seed_share_hex"]), coin);
    assert_eq!(
        wrapping_add_le_256(coin, hex32(&role_outputs["deriver_b"]["seed_share_hex"])),
        seed
    );
    assert_eq!(hex32(&role_outputs["client"]["seed_hex"]), seed);
    assert_eq!(
        SigningKey::from_bytes(&seed).verifying_key().to_bytes(),
        hex32(&output_case["vector"]["common_public"]["registered_public_key_hex"])
    );
}

#[test]
fn static_observations_are_exact_role_copies_and_coins_stay_outside_views() {
    let input = input_corpus();
    for case in cases(&input) {
        let vector = &case["vector"];
        for role in ["deriver_a", "deriver_b"] {
            let observation = &vector["static_deriver_observations"][role];
            assert_eq!(observation["source_case_id"], vector["case_id"]);
            assert_eq!(observation["source_stage"], vector["stage"]);
            assert_eq!(observation["extension"], vector["role_extensions"][role]);
        }
        for role in [
            "client",
            "signing_worker",
            "router",
            "observer",
            "diagnostics_logs",
        ] {
            assert_eq!(object(&vector["role_extensions"][role]).len(), 1);
        }
        let views = serde_json::to_string(&serde_json::json!({
            "common_public": vector["common_public"].clone(),
            "role_extensions": vector["role_extensions"].clone(),
            "static_deriver_observations": vector["static_deriver_observations"].clone(),
        }))
        .expect("views serialize");
        for forbidden in [
            "client_scalar_coin_hex",
            "signing_worker_scalar_coin_hex",
            "seed_output_coin_hex",
            "host_only_ideal_function_randomness",
        ] {
            assert!(
                !views.contains(forbidden),
                "{forbidden} entered a party view"
            );
        }
    }
}

fn input_corpus() -> Value {
    parse(COMMITTED)
}

fn parse(bytes: &[u8]) -> Value {
    serde_json::from_slice(bytes).expect("committed corpus is valid JSON")
}

fn cases(corpus: &Value) -> &Vec<Value> {
    corpus["cases"].as_array().expect("cases array")
}

fn object(value: &Value) -> &Map<String, Value> {
    value.as_object().expect("object")
}

fn string<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key].as_str().expect("string field")
}

fn case_by_id<'a>(corpus: &'a Value, case_id: &str) -> &'a Value {
    cases(corpus)
        .iter()
        .find(|case| case["vector"]["case_id"] == case_id)
        .unwrap_or_else(|| panic!("missing case {case_id}"))
}

fn hex32(value: &Value) -> [u8; 32] {
    let encoded = value.as_str().expect("hex string");
    assert_eq!(encoded.len(), 64);
    let mut decoded = [0_u8; 32];
    for (index, byte) in decoded.iter_mut().enumerate() {
        let offset = index * 2;
        *byte = u8::from_str_radix(&encoded[offset..offset + 2], 16).expect("valid hex");
    }
    decoded
}

fn encode_hex(bytes: [u8; 32]) -> String {
    let mut encoded = String::with_capacity(64);
    for byte in bytes {
        use std::fmt::Write;
        write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}

fn scalar(value: &Value) -> Scalar {
    Option::<Scalar>::from(Scalar::from_canonical_bytes(hex32(value))).expect("canonical scalar")
}

fn joined_y(extensions: &Value) -> [u8; 32] {
    let a = wrapping_add_le_256(
        hex32(&extensions["deriver_a"]["y_client_hex"]),
        hex32(&extensions["deriver_a"]["y_server_hex"]),
    );
    let b = wrapping_add_le_256(
        hex32(&extensions["deriver_b"]["y_client_hex"]),
        hex32(&extensions["deriver_b"]["y_server_hex"]),
    );
    wrapping_add_le_256(a, b)
}

fn wrapping_add_le_256(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut output = [0_u8; 32];
    let mut carry = 0_u16;
    for index in 0..32 {
        let sum = u16::from(left[index]) + u16::from(right[index]) + carry;
        output[index] = sum as u8;
        carry = sum >> 8;
    }
    output
}

fn wrapping_sub_le_256(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut output = [0_u8; 32];
    let mut borrow = 0_i16;
    for index in 0..32 {
        let difference = i16::from(left[index]) - i16::from(right[index]) - borrow;
        output[index] = difference as u8;
        borrow = i16::from(difference < 0);
    }
    output
}
