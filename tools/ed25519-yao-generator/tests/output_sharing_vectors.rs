use std::collections::BTreeSet;

use curve25519_dalek::scalar::Scalar;
use ed25519_yao_generator::{
    canonical_output_sharing_vector_corpus_json_bytes_v1, canonical_vector_corpus_v1,
    parse_canonical_output_sharing_vector_corpus_json_v1, VectorCaseV1,
};
use serde_json::Value;

const COMMITTED_CORPUS: &[u8] = include_bytes!("../vectors/ed25519-yao-output-sharing-v1.json");
const SCHEMA_V1: &str = "seams:router-ab:ed25519-yao:output-sharing-vectors:v1";
const PROTOCOL_ID_V1: &str = "router_ab_ed25519_yao_v1";
const EVIDENCE_SCOPE_V1: &str = "host_only_deterministic_output_sharing_v1";
const SCALAR_ORDER_HEX: &str = "edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010";

#[test]
fn committed_corpus_matches_the_canonical_builder_byte_for_byte() {
    let parsed = parse_canonical_output_sharing_vector_corpus_json_v1(COMMITTED_CORPUS)
        .expect("committed output-sharing corpus is canonical");
    assert_eq!(parsed.schema(), SCHEMA_V1);
    assert_eq!(parsed.protocol_id(), PROTOCOL_ID_V1);
    assert_eq!(parsed.evidence_scope(), EVIDENCE_SCOPE_V1);
    assert_eq!(parsed.case_count(), 6);

    let canonical = canonical_output_sharing_vector_corpus_json_bytes_v1();
    assert_eq!(COMMITTED_CORPUS, canonical);
    assert!(parse_canonical_output_sharing_vector_corpus_json_v1(
        &COMMITTED_CORPUS[..COMMITTED_CORPUS.len() - 1]
    )
    .is_err());

    let mut crlf = COMMITTED_CORPUS[..COMMITTED_CORPUS.len() - 1].to_vec();
    crlf.extend_from_slice(b"\r\n");
    assert!(parse_canonical_output_sharing_vector_corpus_json_v1(&crlf).is_err());
}

#[test]
fn corpus_has_exact_scope_order_and_source_mapping() {
    let corpus = committed_value();
    assert_eq!(text(&corpus["schema"]), SCHEMA_V1);
    assert_eq!(text(&corpus["protocol_id"]), PROTOCOL_ID_V1);
    assert_eq!(text(&corpus["evidence_scope"]), EVIDENCE_SCOPE_V1);

    let expected = [
        (
            "activation",
            "registration_activation_shares_zero_coins_v1",
            "registration_rfc8032_vector_one_v1",
        ),
        (
            "activation",
            "recovery_activation_shares_small_coins_v1",
            "recovery_clear_arithmetic_v1",
        ),
        (
            "activation",
            "refresh_activation_shares_boundary_coins_v1",
            "refresh_clear_arithmetic_v1",
        ),
        (
            "export",
            "export_seed_shares_zero_coin_v1",
            "export_rfc8032_vector_two_v1",
        ),
        (
            "export",
            "export_seed_shares_one_coin_v1",
            "export_rfc8032_vector_two_v1",
        ),
        (
            "export",
            "export_seed_shares_max_coin_v1",
            "export_rfc8032_vector_two_v1",
        ),
    ];
    let actual: Vec<_> = cases(&corpus).iter().map(case_identity).collect();
    assert_eq!(actual, expected);
    let case_ids: BTreeSet<_> = actual.iter().map(|(_, case_id, _)| *case_id).collect();
    assert_eq!(case_ids.len(), actual.len());
}

#[test]
fn activation_cases_reconstruct_both_scalar_outputs() {
    let corpus = committed_value();
    for case in &cases(&corpus)[..3] {
        assert_eq!(text(&case["output_family"]), "activation");
        let vector = &case["vector"];
        let client_joined = scalar(text(
            &vector["host_only_joined_outputs"]["x_client_base_hex"],
        ));
        let signing_worker_joined = scalar(text(
            &vector["host_only_joined_outputs"]["x_server_base_hex"],
        ));
        let client_coin = scalar(text(
            &vector["host_only_reference_randomness"]["r_client_hex"],
        ));
        let signing_worker_coin = scalar(text(
            &vector["host_only_reference_randomness"]["r_signing_worker_hex"],
        ));
        let a_client = scalar(text(
            &vector["role_output_shares"]["deriver_a"]["client_scalar_share_hex"],
        ));
        let b_client = scalar(text(
            &vector["role_output_shares"]["deriver_b"]["client_scalar_share_hex"],
        ));
        let a_signing_worker = scalar(text(
            &vector["role_output_shares"]["deriver_a"]["signing_worker_scalar_share_hex"],
        ));
        let b_signing_worker = scalar(text(
            &vector["role_output_shares"]["deriver_b"]["signing_worker_scalar_share_hex"],
        ));

        assert_eq!(a_client, client_coin);
        assert_eq!(a_signing_worker, signing_worker_coin);
        assert_eq!(a_client + b_client, client_joined);
        assert_eq!(a_signing_worker + b_signing_worker, signing_worker_joined);
    }
}

#[test]
fn export_cases_reconstruct_the_seed_modulo_two_to_the_256() {
    let corpus = committed_value();
    for case in &cases(&corpus)[3..] {
        assert_eq!(text(&case["output_family"]), "export");
        let vector = &case["vector"];
        let joined = hex_32(text(&vector["host_only_joined_output"]["joined_seed_hex"]));
        let coin = hex_32(text(&vector["host_only_reference_randomness"]["u_hex"]));
        let a = hex_32(text(
            &vector["role_output_shares"]["deriver_a"]["seed_share_hex"],
        ));
        let b = hex_32(text(
            &vector["role_output_shares"]["deriver_b"]["seed_share_hex"],
        ));

        assert_eq!(a, coin);
        assert_eq!(wrapping_add_256(a, b), joined);
    }
}

#[test]
fn source_inputs_are_copied_from_the_named_fixed_arithmetic_cases() {
    let arithmetic = canonical_vector_corpus_v1();
    let sharing = committed_value();
    for sharing_case in cases(&sharing) {
        let (_, _, source_case_id) = case_identity(sharing_case);
        let source_inputs = &sharing_case["vector"]["host_only_source_reference"]["inputs"];
        let expected = arithmetic
            .cases
            .iter()
            .find_map(|case| arithmetic_source(case, source_case_id))
            .expect("named fixed source case exists");
        assert_eq!(
            source_inputs,
            &serde_json::to_value(expected).expect("source inputs serialize")
        );
    }
}

#[test]
fn request_and_output_families_have_closed_nonoverlapping_json_shapes() {
    let mut activation_seed = committed_value();
    activation_seed["cases"][0]["vector"]["role_output_shares"]["deriver_a"]["seed_share_hex"] =
        Value::String("00".repeat(32));
    assert_rejected_value(activation_seed);

    let mut export_scalar = committed_value();
    export_scalar["cases"][3]["vector"]["role_output_shares"]["deriver_a"]
        ["signing_worker_scalar_share_hex"] = Value::String("00".repeat(32));
    assert_rejected_value(export_scalar);

    let mut activation_continuation = committed_value();
    activation_continuation["cases"][0]["vector"]["request_kind"] =
        Value::String("activation".to_owned());
    assert_rejected_value(activation_continuation);

    let mut wrong_family = committed_value();
    wrong_family["cases"][0]["output_family"] = Value::String("export".to_owned());
    assert_rejected_value(wrong_family);
}

#[test]
fn strict_parser_rejects_malformed_headers_counts_fields_and_scalar_domains() {
    let mut mutations = Vec::new();

    let mut unknown = committed_value();
    unknown
        .as_object_mut()
        .expect("corpus is an object")
        .insert("wire_encoding_hex".to_owned(), Value::String(String::new()));
    mutations.push(unknown);

    let mut missing = committed_value();
    missing["cases"][0]["vector"]
        .as_object_mut()
        .expect("case vector is an object")
        .remove("host_only_reference_randomness");
    mutations.push(missing);

    let mut null = committed_value();
    null["cases"][0]["vector"]["host_only_reference_randomness"] = Value::Null;
    mutations.push(null);

    for (field, replacement) in [
        ("schema", "changed-schema"),
        ("protocol_id", "changed-protocol"),
        ("evidence_scope", "changed-scope"),
    ] {
        let mut wrong_header = committed_value();
        wrong_header[field] = Value::String(replacement.to_owned());
        mutations.push(wrong_header);
    }

    let mut wrong_count = committed_value();
    wrong_count["cases"]
        .as_array_mut()
        .expect("cases are an array")
        .pop();
    mutations.push(wrong_count);

    let mut uppercase = committed_value();
    let scalar =
        text(&uppercase["cases"][1]["vector"]["host_only_joined_outputs"]["x_client_base_hex"])
            .to_ascii_uppercase();
    uppercase["cases"][1]["vector"]["host_only_joined_outputs"]["x_client_base_hex"] =
        Value::String(scalar);
    mutations.push(uppercase);

    let mut short = committed_value();
    short["cases"][1]["vector"]["host_only_source_reference"]["inputs"]["y_client_a_hex"] =
        Value::String("00".to_owned());
    mutations.push(short);

    let mut long = committed_value();
    long["cases"][5]["vector"]["role_output_shares"]["deriver_b"]["seed_share_hex"] =
        Value::String("00".repeat(33));
    mutations.push(long);

    let mut noncanonical_scalar = committed_value();
    noncanonical_scalar["cases"][1]["vector"]["host_only_reference_randomness"]["r_client_hex"] =
        Value::String(SCALAR_ORDER_HEX.to_owned());
    mutations.push(noncanonical_scalar);

    for mutation in mutations {
        assert_rejected_value(mutation);
    }

    let canonical = std::str::from_utf8(COMMITTED_CORPUS).expect("canonical corpus is UTF-8");
    let original_prefix =
        format!("{{\n  \"schema\": \"{SCHEMA_V1}\",\n  \"protocol_id\": \"{PROTOCOL_ID_V1}\",\n");
    let reordered_prefix =
        format!("{{\n  \"protocol_id\": \"{PROTOCOL_ID_V1}\",\n  \"schema\": \"{SCHEMA_V1}\",\n");
    let reordered = canonical.replacen(&original_prefix, &reordered_prefix, 1);
    assert_ne!(reordered, canonical);
    assert!(parse_canonical_output_sharing_vector_corpus_json_v1(reordered.as_bytes()).is_err());

    let schema_line = format!("  \"schema\": \"{SCHEMA_V1}\",\n");
    let duplicate = canonical.replacen(&schema_line, &format!("{schema_line}{schema_line}"), 1);
    assert_ne!(duplicate, canonical);
    assert!(parse_canonical_output_sharing_vector_corpus_json_v1(duplicate.as_bytes()).is_err());
}

#[test]
fn request_kind_sequence_is_registration_recovery_refresh() {
    let corpus = committed_value();
    let actual: Vec<_> = cases(&corpus)[..3]
        .iter()
        .map(|case| text(&case["vector"]["request_kind"]))
        .collect();
    assert_eq!(actual, ["registration", "recovery", "refresh"]);

    let mut reordered = committed_value();
    reordered["cases"]
        .as_array_mut()
        .expect("cases are an array")
        .swap(0, 1);
    assert_rejected_value(reordered);
}

fn committed_value() -> Value {
    serde_json::from_slice(COMMITTED_CORPUS).expect("committed output-sharing corpus is JSON")
}

fn cases(corpus: &Value) -> &[Value] {
    corpus["cases"].as_array().expect("cases are an array")
}

fn text(value: &Value) -> &str {
    value.as_str().expect("value is a string")
}

fn case_identity(case: &Value) -> (&str, &str, &str) {
    (
        text(&case["output_family"]),
        text(&case["vector"]["case_id"]),
        text(&case["vector"]["host_only_source_reference"]["case_id"]),
    )
}

fn assert_rejected_value(value: Value) {
    let mut encoded = serde_json::to_vec_pretty(&value).expect("mutation serializes");
    encoded.push(b'\n');
    assert!(parse_canonical_output_sharing_vector_corpus_json_v1(&encoded).is_err());
}

fn arithmetic_source<'a>(
    case: &'a VectorCaseV1,
    expected_case_id: &str,
) -> Option<&'a ed25519_yao_generator::VectorInputsV1> {
    let reference = match case {
        VectorCaseV1::Registration(reference)
        | VectorCaseV1::Activation(reference)
        | VectorCaseV1::Recovery(reference)
        | VectorCaseV1::Refresh(reference) => reference,
        VectorCaseV1::Export(export) => &export.reference,
    };
    (reference.case_id == expected_case_id).then_some(&reference.inputs)
}

fn scalar(value: &str) -> Scalar {
    Option::<Scalar>::from(Scalar::from_canonical_bytes(hex_32(value)))
        .expect("fixture scalar is canonical")
}

fn hex_32(value: &str) -> [u8; 32] {
    assert_eq!(value.len(), 64);
    let mut bytes = [0; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        let offset = index * 2;
        *byte = u8::from_str_radix(&value[offset..offset + 2], 16).expect("fixture hex is valid");
    }
    bytes
}

fn wrapping_add_256(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut output = [0; 32];
    let mut carry = 0u16;
    for index in 0..32 {
        let sum = u16::from(left[index]) + u16::from(right[index]) + carry;
        output[index] = sum as u8;
        carry = sum >> 8;
    }
    output
}
