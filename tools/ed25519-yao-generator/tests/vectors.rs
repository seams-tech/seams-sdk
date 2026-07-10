use std::fs;
use std::path::Path;

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::{Signer, SigningKey, Verifier};
use ed25519_yao_generator::{
    canonical_vector_corpus_v1, LifecycleRequestKindV1, VectorCaseV1, VECTOR_CORPUS_SCHEMA_V1,
};

#[test]
fn corpus_has_one_case_per_request_kind_and_export_only_result() {
    let corpus = canonical_vector_corpus_v1();
    assert_eq!(corpus.schema, VECTOR_CORPUS_SCHEMA_V1);
    assert_eq!(corpus.cases.len(), 5);

    let request_kinds: Vec<_> = corpus
        .cases
        .iter()
        .map(VectorCaseV1::request_kind)
        .collect();
    assert_eq!(
        request_kinds,
        [
            LifecycleRequestKindV1::Registration,
            LifecycleRequestKindV1::Activation,
            LifecycleRequestKindV1::Recovery,
            LifecycleRequestKindV1::Refresh,
            LifecycleRequestKindV1::Export,
        ]
    );

    for case in &corpus.cases {
        if let VectorCaseV1::Export(export) = case {
            assert_eq!(
                export.authorized_seed_hex,
                export.reference.clear_reference_trace.joined_seed_hex
            );
        }
    }
}

#[test]
fn corpus_serialization_is_deterministic_and_strict() {
    let first = canonical_encoding();
    let second = canonical_encoding();
    assert_eq!(first, second);

    let with_unknown_field = first.replacen("\"schema\":", "\"unknown\": true,\n  \"schema\":", 1);
    assert!(
        serde_json::from_str::<ed25519_yao_generator::VectorCorpusV1>(&with_unknown_field).is_err()
    );

    let registration_with_export_result = first.replacen(
        "\"request_kind\": \"registration\"",
        "\"request_kind\": \"registration\",\n      \"authorized_seed_hex\": \"00\"",
        1,
    );
    assert!(
        serde_json::from_str::<ed25519_yao_generator::VectorCorpusV1>(
            &registration_with_export_result
        )
        .is_err()
    );
}

#[test]
fn committed_corpus_matches_the_builder_byte_for_byte() {
    let vector_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("vectors")
        .join("ed25519-yao-v1.json");
    let committed = fs::read_to_string(&vector_path).expect("committed vector corpus is readable");

    assert_eq!(committed, canonical_encoding());
}

#[test]
fn every_clear_trace_satisfies_the_approved_scalar_and_point_relations() {
    let corpus = canonical_vector_corpus_v1();
    for case in corpus.cases {
        let trace = case.clear_reference_trace();
        let signing_scalar = decode_scalar(&trace.signing_scalar_hex);
        let tau = decode_scalar(&trace.tau_hex);
        let x_client_base = decode_scalar(&trace.x_client_base_hex);
        let x_server_base = decode_scalar(&trace.x_server_base_hex);
        let x_client = decode_point(&trace.x_client_point_hex);
        let x_server = decode_point(&trace.x_server_point_hex);
        let public_key = decode_point(&trace.public_key_hex);

        assert_eq!(x_client_base, signing_scalar + tau);
        assert_eq!(x_server_base, signing_scalar + tau + tau);
        assert_eq!(
            x_client_base + x_client_base - x_server_base,
            signing_scalar
        );
        assert_eq!(x_client, ED25519_BASEPOINT_POINT * x_client_base);
        assert_eq!(x_server, ED25519_BASEPOINT_POINT * x_server_base);
        assert_eq!(x_client + x_client - x_server, public_key);
        assert_eq!(public_key, ED25519_BASEPOINT_POINT * signing_scalar);
    }
}

#[test]
fn authorized_export_seed_round_trips_through_standard_ed25519_signing() {
    let corpus = canonical_vector_corpus_v1();
    let export = corpus
        .cases
        .iter()
        .find_map(find_export_case)
        .expect("corpus contains an export case");
    let seed = decode_hex_32(&export.authorized_seed_hex);
    let expected_public_key = decode_hex_32(&export.reference.clear_reference_trace.public_key_hex);
    let signing_key = SigningKey::from_bytes(&seed);
    let message = b"seams Ed25519 Yao export parity v1";
    let signature = signing_key.sign(message);

    assert_eq!(signing_key.verifying_key().to_bytes(), expected_public_key);
    signing_key
        .verifying_key()
        .verify(message, &signature)
        .expect("standard Ed25519 signature verifies after seed export");
}

fn canonical_encoding() -> String {
    format!(
        "{}\n",
        serde_json::to_string_pretty(&canonical_vector_corpus_v1())
            .expect("canonical vector serialization")
    )
}

fn find_export_case(case: &VectorCaseV1) -> Option<&ed25519_yao_generator::VectorExportCaseV1> {
    match case {
        VectorCaseV1::Export(export) => Some(export),
        VectorCaseV1::Registration(_)
        | VectorCaseV1::Activation(_)
        | VectorCaseV1::Recovery(_)
        | VectorCaseV1::Refresh(_) => None,
    }
}

fn decode_scalar(value: &str) -> Scalar {
    Option::<Scalar>::from(Scalar::from_canonical_bytes(decode_hex_32(value)))
        .expect("vector scalar is canonical")
}

fn decode_point(value: &str) -> EdwardsPoint {
    CompressedEdwardsY(decode_hex_32(value))
        .decompress()
        .expect("vector point is canonical and on-curve")
}

fn decode_hex_32(value: &str) -> [u8; 32] {
    assert_eq!(value.len(), 64);
    let mut output = [0u8; 32];
    for (index, byte) in output.iter_mut().enumerate() {
        let offset = index * 2;
        *byte = u8::from_str_radix(&value[offset..offset + 2], 16).expect("valid hex byte");
    }
    output
}
