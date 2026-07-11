use ed25519_yao_generator::{
    canonical_export_delivery_vector_corpus_json_bytes_v1,
    canonical_export_delivery_vector_corpus_v1,
    parse_canonical_export_delivery_vector_corpus_json_v1, EXPORT_DELIVERY_VECTOR_CORPUS_SCHEMA_V1,
    EXPORT_DELIVERY_VECTOR_EVIDENCE_SCOPE_V1,
};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

const COMMITTED: &[u8] = include_bytes!("../vectors/ed25519-yao-export-delivery-v1.json");

fn object(value: &Value) -> &Map<String, Value> {
    value.as_object().expect("expected JSON object")
}

fn field<'a>(value: &'a Value, name: &str) -> &'a Value {
    &object(value)[name]
}

fn string<'a>(value: &'a Value, name: &str) -> &'a str {
    field(value, name).as_str().expect("expected string field")
}

fn decode_hex(encoded: &str) -> Vec<u8> {
    assert_eq!(encoded.len() % 2, 0);
    (0..encoded.len())
        .step_by(2)
        .map(|offset| u8::from_str_radix(&encoded[offset..offset + 2], 16).expect("lowercase hex"))
        .collect()
}

fn lp32(bytes: &[u8]) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(bytes.len() + 4);
    encoded.extend_from_slice(
        &u32::try_from(bytes.len())
            .expect("fixture length")
            .to_be_bytes(),
    );
    encoded.extend_from_slice(bytes);
    encoded
}

fn lp32_fields(mut encoded: &[u8]) -> Vec<Vec<u8>> {
    let mut fields = Vec::new();
    while !encoded.is_empty() {
        assert!(encoded.len() >= 4);
        let length = u32::from_be_bytes(encoded[..4].try_into().expect("LP32 length")) as usize;
        encoded = &encoded[4..];
        assert!(encoded.len() >= length);
        fields.push(encoded[..length].to_vec());
        encoded = &encoded[length..];
    }
    fields
}

fn digest(domain: &[u8], encoding: &[u8]) -> Vec<u8> {
    let mut preimage = lp32(domain);
    preimage.extend_from_slice(&lp32(encoding));
    Sha256::digest(preimage).to_vec()
}

fn only_case() -> Value {
    let corpus: Value = serde_json::from_slice(COMMITTED).expect("committed JSON parses");
    field(&corpus, "cases").as_array().expect("cases array")[0].clone()
}

fn assert_zero_work(value: &Value) {
    assert!(object(value)
        .values()
        .all(|count| count.as_u64() == Some(0)));
}

#[test]
fn committed_corpus_is_exact_and_strictly_parseable() {
    assert_eq!(
        COMMITTED,
        canonical_export_delivery_vector_corpus_json_bytes_v1()
    );
    let parsed = parse_canonical_export_delivery_vector_corpus_json_v1(COMMITTED)
        .expect("committed corpus is canonical");
    assert_eq!(parsed.schema(), EXPORT_DELIVERY_VECTOR_CORPUS_SCHEMA_V1);
    assert_eq!(parsed.protocol_id(), "router_ab_ed25519_yao_v1");
    assert_eq!(
        parsed.evidence_scope(),
        EXPORT_DELIVERY_VECTOR_EVIDENCE_SCOPE_V1
    );
    assert_eq!(parsed.case_count(), 1);
    assert_eq!(canonical_export_delivery_vector_corpus_v1().case_count(), 1);
}

#[test]
fn receipts_bind_output_commit_release_and_authorization_order() {
    let case = only_case();
    let committed = field(&case, "output_committed");
    let released = field(&case, "released");
    assert_eq!(string(committed, "authorization_state"), "unconsumed");
    assert_eq!(string(released, "authorization_state"), "consumed");

    let committed_encoding = decode_hex(string(committed, "output_committed_receipt_encoding_hex"));
    let committed_fields = lp32_fields(&committed_encoding);
    assert_eq!(committed_fields.len(), 16);
    assert_eq!(
        committed_fields[0],
        b"seams/router-ab/ed25519-yao/semantic-receipt/export-output-committed/v1"
    );
    assert_eq!(committed_fields[1], [0x01]);
    assert_eq!(committed_fields[2], [0x01]);
    assert_eq!(
        decode_hex(string(committed, "output_committed_receipt_digest_hex")),
        digest(
            b"seams/router-ab/ed25519-yao/semantic-receipt/export-output-committed-digest/v1",
            &committed_encoding
        )
    );

    let released_encoding = decode_hex(string(released, "released_receipt_encoding_hex"));
    let released_fields = lp32_fields(&released_encoding);
    assert_eq!(released_fields.len(), 17);
    assert_eq!(
        released_fields[0],
        b"seams/router-ab/ed25519-yao/semantic-receipt/export-released/v1"
    );
    assert_eq!(released_fields[1], [0x02]);
    assert_eq!(released_fields[2], [0x02]);
    assert_eq!(
        released_fields[14],
        decode_hex(string(committed, "output_committed_receipt_digest_hex"))
    );
    assert_eq!(
        released_fields[15],
        decode_hex(string(released, "client_delivery_evidence_digest_hex"))
    );
    assert_eq!(
        released_fields[16],
        decode_hex(string(
            released,
            "consumed_authorization_evidence_digest_hex"
        ))
    );
    assert_eq!(
        decode_hex(string(released, "released_receipt_digest_hex")),
        digest(
            b"seams/router-ab/ed25519-yao/semantic-receipt/export-released-digest/v1",
            &released_encoding
        )
    );
}

#[test]
fn uncertainty_and_redelivery_are_exact_identity_self_loops_with_zero_private_work() {
    let case = only_case();
    let uncertain = field(&case, "delivery_uncertain");
    assert_eq!(
        string(uncertain, "before_package_set_digest_hex"),
        string(uncertain, "after_package_set_digest_hex")
    );
    assert_eq!(string(uncertain, "authorization_state"), "unconsumed");
    assert_zero_work(field(uncertain, "zero_private_evaluation_work"));

    let released = field(&case, "released");
    let redelivered = field(&case, "redelivered");
    assert_eq!(
        string(redelivered, "before_released_receipt_digest_hex"),
        string(redelivered, "after_released_receipt_digest_hex")
    );
    assert_eq!(
        string(redelivered, "before_released_receipt_digest_hex"),
        string(released, "released_receipt_digest_hex")
    );
    assert_eq!(
        string(redelivered, "client_seed_hex"),
        string(released, "client_seed_hex")
    );
    assert_zero_work(field(released, "zero_private_evaluation_work"));
    assert_zero_work(field(redelivered, "zero_private_evaluation_work"));
}

#[test]
fn parser_rejects_mutation_truncation_and_secret_control_fields() {
    let mut mutation = COMMITTED.to_vec();
    let index = mutation
        .iter()
        .position(|byte| *byte == b'a')
        .expect("fixture contains a mutable byte");
    mutation[index] = b'b';
    assert!(parse_canonical_export_delivery_vector_corpus_json_v1(&mutation).is_err());
    assert!(parse_canonical_export_delivery_vector_corpus_json_v1(
        &COMMITTED[..COMMITTED.len() - 1]
    )
    .is_err());

    let corpus = std::str::from_utf8(COMMITTED).expect("fixture is UTF-8");
    for forbidden in [
        "joined_seed_hex",
        "decryption_key_hex",
        "ciphertext_bytes_hex",
        "protocol_randomness_hex",
        "frame_bytes_hex",
    ] {
        assert!(!corpus.contains(forbidden));
    }
}
