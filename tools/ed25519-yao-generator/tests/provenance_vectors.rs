use std::collections::BTreeSet;

use ed25519_yao_generator::provenance::{
    parse_canonical_provenance_pair_v1, parse_canonical_provenance_statement_v1,
    ProvenanceCircuitFamilyV1, ProvenanceRequestKindV1, ProvenanceRoleKindV1,
    PROVENANCE_ARTIFACT_DIGEST_DOMAIN_V1, PROVENANCE_CLIENT_ENVELOPE_SET_DIGEST_DOMAIN_V1,
    PROVENANCE_DERIVER_A_ROLE_TAG_V1, PROVENANCE_DERIVER_B_ROLE_TAG_V1,
};
use ed25519_yao_generator::{
    canonical_provenance_vector_corpus_v1, ProvenanceLifecycleVectorCaseV1,
    ProvenanceVectorCorpusV1, PROVENANCE_VECTOR_CORPUS_SCHEMA_V1,
    PROVENANCE_VECTOR_EVIDENCE_SCOPE_V1,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

const COMMITTED_CORPUS: &str = include_str!("../vectors/ed25519-yao-provenance-v1.json");

#[test]
fn committed_corpus_matches_the_canonical_builder_byte_for_byte() {
    let expected = canonical_provenance_vector_corpus_v1();
    let parsed: ProvenanceVectorCorpusV1 =
        serde_json::from_str(COMMITTED_CORPUS).expect("committed provenance corpus is valid JSON");
    let canonical = format!(
        "{}\n",
        serde_json::to_string_pretty(&expected).expect("provenance corpus serializes")
    );

    assert_eq!(parsed, expected);
    assert_eq!(COMMITTED_CORPUS, canonical);
}

#[test]
fn corpus_has_exact_scope_case_order_and_no_activation_statement() {
    let corpus = canonical_provenance_vector_corpus_v1();
    assert_eq!(corpus.schema, PROVENANCE_VECTOR_CORPUS_SCHEMA_V1);
    assert_eq!(corpus.protocol_id, "router_ab_ed25519_yao_v1");
    assert_eq!(corpus.evidence_scope, PROVENANCE_VECTOR_EVIDENCE_SCOPE_V1);
    assert_eq!(corpus.cases.len(), 4);

    let actual: Vec<_> = corpus.cases.iter().map(case_identity).collect();
    assert_eq!(
        actual,
        [
            ("registration", "registration_provenance_outer_v1"),
            ("recovery", "recovery_provenance_outer_v1"),
            ("refresh", "refresh_provenance_outer_v1"),
            ("export", "export_provenance_outer_v1"),
        ]
    );
    let case_ids: BTreeSet<_> = actual.iter().map(|(_, case_id)| *case_id).collect();
    assert_eq!(case_ids.len(), actual.len());
}

#[test]
fn artifact_wrapper_goldens_recompute_from_frozen_lp32_preimages() {
    let corpus = canonical_provenance_vector_corpus_v1();
    let expected = [
        ("role_root_binding", 1),
        ("client_input_binding", 2),
        ("server_input_binding", 3),
        ("combined_role_input_binding", 4),
        ("client_envelope_commitment", 5),
        ("registration_anti_bias_evidence", 6),
        ("recovery_same_root_continuity", 7),
        ("refresh_opposite_delta_transition", 8),
    ];
    assert_eq!(corpus.artifact_wrapper_goldens.len(), expected.len());

    for (golden, (expected_name, expected_tag)) in
        corpus.artifact_wrapper_goldens.iter().zip(expected)
    {
        assert_eq!(golden.kind, expected_name);
        assert_eq!(golden.kind_tag, expected_tag);
        let artifact = decode_hex(&golden.canonical_artifact_hex);
        let wrapper = lp32_sequence(&[
            PROVENANCE_ARTIFACT_DIGEST_DOMAIN_V1,
            &[golden.kind_tag],
            &artifact,
        ]);
        assert_eq!(decode_hex_32(&golden.digest_sha256_hex), sha256(&wrapper));
    }
}

#[test]
fn every_statement_and_pair_round_trips_through_the_strict_parsers() {
    let corpus = canonical_provenance_vector_corpus_v1();
    for case in &corpus.cases {
        let (request, vector) = case_parts(case);
        let expected_family = if request == ProvenanceRequestKindV1::Export {
            ProvenanceCircuitFamilyV1::Export
        } else {
            ProvenanceCircuitFamilyV1::Activation
        };

        let a_bytes = decode_hex(&vector.deriver_a.statement_encoding_hex);
        let b_bytes = decode_hex(&vector.deriver_b.statement_encoding_hex);
        let a = parse_canonical_provenance_statement_v1(&a_bytes)
            .expect("canonical A statement parses");
        let b = parse_canonical_provenance_statement_v1(&b_bytes)
            .expect("canonical B statement parses");
        assert_eq!(a.request_kind(), request);
        assert_eq!(b.request_kind(), request);
        assert_eq!(a.role(), ProvenanceRoleKindV1::DeriverA);
        assert_eq!(b.role(), ProvenanceRoleKindV1::DeriverB);
        assert_eq!(a.circuit_family(), expected_family);
        assert_eq!(b.circuit_family(), expected_family);
        assert_eq!(
            a.digest(),
            &decode_hex_32(&vector.deriver_a.statement_digest_sha256_hex)
        );
        assert_eq!(
            b.digest(),
            &decode_hex_32(&vector.deriver_b.statement_digest_sha256_hex)
        );

        let pair_bytes = decode_hex(&vector.pair_encoding_hex);
        let pair = parse_canonical_provenance_pair_v1(&pair_bytes)
            .expect("canonical statement pair parses");
        assert_eq!(pair.deriver_a_statement_digest(), a.digest());
        assert_eq!(pair.deriver_b_statement_digest(), b.digest());
        assert_eq!(
            pair.digest(),
            &decode_hex_32(&vector.pair_digest_sha256_hex)
        );
    }
}

#[test]
fn nested_vector_encodings_are_exact_statement_fields() {
    let corpus = canonical_provenance_vector_corpus_v1();
    for case in &corpus.cases {
        let (_, vector) = case_parts(case);
        for role in [&vector.deriver_a, &vector.deriver_b] {
            let statement = decode_hex(&role.statement_encoding_hex);
            let fields = lp32_fields(&statement);
            assert_eq!(fields.len(), 11);
            assert_eq!(fields[3], [role.role_tag]);
            assert_eq!(fields[6], decode_hex(&vector.final_circuit_digest_hex));
            assert_eq!(fields[7], decode_hex(&vector.input_schema_digest_hex));
            assert_eq!(fields[8], decode_hex(&role.stable_scope_encoding_hex));
            assert_eq!(fields[9], decode_hex(&role.ceremony_binding_encoding_hex));
            assert_eq!(fields[10], decode_hex(&role.branch_encoding_hex));

            let ceremony = lp32_fields(&fields[9]);
            assert_eq!(ceremony[1], fields[2]);
            assert_eq!(
                ceremony[2],
                decode_hex(&vector.public_request_context_digest_hex)
            );
            assert_eq!(ceremony[3], decode_hex(&vector.transcript_digest_hex));
            assert_eq!(ceremony[4], decode_hex(&vector.authorization_digest_hex));
            let expected_envelope = if role.role_tag == PROVENANCE_DERIVER_A_ROLE_TAG_V1 {
                &vector.client_envelope_a_artifact_digest_hex
            } else {
                &vector.client_envelope_b_artifact_digest_hex
            };
            assert_eq!(ceremony[5], decode_hex(expected_envelope));
            assert_eq!(
                ceremony[6],
                decode_hex(&vector.client_envelope_set_digest_hex)
            );

            let branch = lp32_fields(&fields[10]);
            let snapshot_fields = if role.snapshot_encodings_hex.len() == 2 {
                &branch[1..3]
            } else {
                &branch[1..2]
            };
            let listed_snapshots: Vec<_> = role
                .snapshot_encodings_hex
                .iter()
                .map(|hex| decode_hex(hex))
                .collect();
            assert_eq!(snapshot_fields, listed_snapshots.as_slice());
        }
    }
}

#[test]
fn envelope_set_and_role_epochs_are_fixed_order_and_role_scoped() {
    let corpus = canonical_provenance_vector_corpus_v1();
    for case in &corpus.cases {
        let (_, vector) = case_parts(case);
        let a = decode_hex(&vector.client_envelope_a_artifact_digest_hex);
        let b = decode_hex(&vector.client_envelope_b_artifact_digest_hex);
        let encoded = lp32_sequence(&[PROVENANCE_CLIENT_ENVELOPE_SET_DIGEST_DOMAIN_V1, &a, &b]);
        assert_eq!(
            decode_hex_32(&vector.client_envelope_set_digest_hex),
            sha256(&encoded)
        );
        assert_eq!(vector.deriver_a.role, "deriver_a");
        assert_eq!(vector.deriver_a.role_tag, PROVENANCE_DERIVER_A_ROLE_TAG_V1);
        assert_eq!(vector.deriver_b.role, "deriver_b");
        assert_eq!(vector.deriver_b.role_tag, PROVENANCE_DERIVER_B_ROLE_TAG_V1);

        let a_epochs = snapshot_epochs(&vector.deriver_a.snapshot_encodings_hex);
        let b_epochs = snapshot_epochs(&vector.deriver_b.snapshot_encodings_hex);
        assert_ne!(a_epochs[0], b_epochs[0]);
        if a_epochs.len() == 2 {
            assert_eq!(a_epochs[0].0, a_epochs[1].0);
            assert_eq!(b_epochs[0].0, b_epochs[1].0);
            assert!(a_epochs[1].1 > a_epochs[0].1);
            assert!(b_epochs[1].1 > b_epochs[0].1);
        }
    }
}

#[test]
fn strict_serde_rejects_unknown_missing_and_activation_shapes() {
    let canonical = canonical_provenance_vector_corpus_v1();
    let mut unknown = serde_json::to_value(&canonical).expect("corpus converts to JSON");
    unknown["cases"][0]["vector"]["deriver_a"]
        .as_object_mut()
        .expect("role vector is an object")
        .insert("proof_hex".to_owned(), Value::String("00".to_owned()));
    assert!(serde_json::from_value::<ProvenanceVectorCorpusV1>(unknown).is_err());

    let mut missing = serde_json::to_value(&canonical).expect("corpus converts to JSON");
    missing["cases"][0]["vector"]
        .as_object_mut()
        .expect("case vector is an object")
        .remove("pair_encoding_hex");
    assert!(serde_json::from_value::<ProvenanceVectorCorpusV1>(missing).is_err());

    let mut activation = serde_json::to_value(&canonical).expect("corpus converts to JSON");
    activation["cases"][0]["request_kind"] = Value::String("activation".to_owned());
    assert!(serde_json::from_value::<ProvenanceVectorCorpusV1>(activation).is_err());
}

#[test]
fn digest_and_branch_mutations_fail_recomputation_or_structural_parsing() {
    let corpus = canonical_provenance_vector_corpus_v1();
    let (_, vector) = case_parts(&corpus.cases[0]);
    let mut statement = decode_hex(&vector.deriver_a.statement_encoding_hex);
    let role_range = lp32_field_range(&statement, 3);
    statement[role_range.start] = PROVENANCE_DERIVER_B_ROLE_TAG_V1;
    let mutated = parse_canonical_provenance_statement_v1(&statement)
        .expect("a valid alternate role tag remains structurally parseable");
    assert_ne!(
        mutated.digest(),
        &decode_hex_32(&vector.deriver_a.statement_digest_sha256_hex)
    );

    let mut branch = decode_hex(&vector.deriver_a.branch_encoding_hex);
    branch.push(0);
    let branch_range = lp32_field_range(&decode_hex(&vector.deriver_a.statement_encoding_hex), 10);
    let mut malformed_statement = decode_hex(&vector.deriver_a.statement_encoding_hex);
    let old_len = branch_range.len();
    malformed_statement[branch_range.start - 4..branch_range.start].copy_from_slice(
        &u32::try_from(old_len + 1)
            .expect("small fixture")
            .to_be_bytes(),
    );
    malformed_statement.splice(branch_range, branch);
    assert!(parse_canonical_provenance_statement_v1(&malformed_statement).is_err());
}

fn case_identity(case: &ProvenanceLifecycleVectorCaseV1) -> (&'static str, &str) {
    match case {
        ProvenanceLifecycleVectorCaseV1::Registration(vector) => ("registration", &vector.case_id),
        ProvenanceLifecycleVectorCaseV1::Recovery(vector) => ("recovery", &vector.case_id),
        ProvenanceLifecycleVectorCaseV1::Refresh(vector) => ("refresh", &vector.case_id),
        ProvenanceLifecycleVectorCaseV1::Export(vector) => ("export", &vector.case_id),
    }
}

fn case_parts(
    case: &ProvenanceLifecycleVectorCaseV1,
) -> (
    ProvenanceRequestKindV1,
    &ed25519_yao_generator::ProvenanceCaseVectorV1,
) {
    match case {
        ProvenanceLifecycleVectorCaseV1::Registration(vector) => {
            (ProvenanceRequestKindV1::Registration, vector)
        }
        ProvenanceLifecycleVectorCaseV1::Recovery(vector) => {
            (ProvenanceRequestKindV1::Recovery, vector)
        }
        ProvenanceLifecycleVectorCaseV1::Refresh(vector) => {
            (ProvenanceRequestKindV1::Refresh, vector)
        }
        ProvenanceLifecycleVectorCaseV1::Export(vector) => {
            (ProvenanceRequestKindV1::Export, vector)
        }
    }
}

fn snapshot_epochs(encodings: &[String]) -> Vec<(u64, u64)> {
    encodings
        .iter()
        .map(|hex| {
            let encoding = decode_hex(hex);
            let fields = lp32_fields(&encoding);
            (
                u64::from_be_bytes(fields[3].as_slice().try_into().expect("root epoch is u64")),
                u64::from_be_bytes(fields[5].as_slice().try_into().expect("state epoch is u64")),
            )
        })
        .collect()
}

fn lp32_sequence(fields: &[&[u8]]) -> Vec<u8> {
    let mut output = Vec::new();
    for field in fields {
        output.extend_from_slice(
            &u32::try_from(field.len())
                .expect("fixture fits LP32")
                .to_be_bytes(),
        );
        output.extend_from_slice(field);
    }
    output
}

fn lp32_fields(bytes: &[u8]) -> Vec<Vec<u8>> {
    let mut fields = Vec::new();
    let mut offset = 0;
    while offset < bytes.len() {
        let length_end = offset + 4;
        let length = u32::from_be_bytes(
            bytes[offset..length_end]
                .try_into()
                .expect("complete LP32 length"),
        ) as usize;
        let end = length_end + length;
        fields.push(bytes[length_end..end].to_vec());
        offset = end;
    }
    assert_eq!(offset, bytes.len());
    fields
}

fn lp32_field_range(bytes: &[u8], index: usize) -> std::ops::Range<usize> {
    let mut offset = 0;
    for current in 0..=index {
        let length_end = offset + 4;
        let length =
            u32::from_be_bytes(bytes[offset..length_end].try_into().expect("LP32 length")) as usize;
        let range = length_end..length_end + length;
        if current == index {
            return range;
        }
        offset = range.end;
    }
    unreachable!("requested LP32 field exists")
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn decode_hex_32(value: &str) -> [u8; 32] {
    decode_hex(value)
        .try_into()
        .expect("value contains 32 bytes")
}

fn decode_hex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).expect("hex is ASCII");
            u8::from_str_radix(text, 16).expect("hex is valid")
        })
        .collect()
}
