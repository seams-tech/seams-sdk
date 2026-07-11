use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::scalar::Scalar;
use ed25519_yao_generator::{
    canonical_activation_delivery_vector_corpus_json_bytes_v1,
    canonical_activation_delivery_vector_corpus_v1,
    parse_canonical_activation_delivery_vector_corpus_json_v1,
    ACTIVATION_DELIVERY_VECTOR_CORPUS_SCHEMA_V1, ACTIVATION_DELIVERY_VECTOR_EVIDENCE_SCOPE_V1,
};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

const COMMITTED: &[u8] = include_bytes!("../vectors/ed25519-yao-activation-delivery-v1.json");

fn object(value: &Value) -> &Map<String, Value> {
    value.as_object().expect("expected JSON object")
}

fn field<'a>(value: &'a Value, name: &str) -> &'a Value {
    &object(value)[name]
}

fn string<'a>(value: &'a Value, name: &str) -> &'a str {
    field(value, name).as_str().expect("expected string field")
}

fn cases() -> Vec<Value> {
    let corpus: Value = serde_json::from_slice(COMMITTED).expect("committed JSON parses");
    field(&corpus, "cases")
        .as_array()
        .expect("cases array")
        .clone()
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

fn receipt_digest(encoding: &[u8]) -> Vec<u8> {
    let mut preimage =
        lp32(b"seams/router-ab/ed25519-yao/semantic-receipt/activation-output-committed-digest/v1");
    preimage.extend_from_slice(&lp32(encoding));
    Sha256::digest(preimage).to_vec()
}

fn scalar(encoded: &str) -> Scalar {
    let bytes: [u8; 32] = decode_hex(encoded).try_into().expect("32-byte scalar");
    Option::<Scalar>::from(Scalar::from_canonical_bytes(bytes)).expect("canonical scalar")
}

fn assert_zero_work(value: &Value) {
    assert!(object(value)
        .values()
        .all(|count| count.as_u64() == Some(0)));
}

#[test]
fn committed_corpus_is_exact_strict_and_has_three_ordered_origins() {
    assert_eq!(
        COMMITTED,
        canonical_activation_delivery_vector_corpus_json_bytes_v1()
    );
    let parsed = parse_canonical_activation_delivery_vector_corpus_json_v1(COMMITTED)
        .expect("committed corpus is canonical");
    assert_eq!(parsed.schema(), ACTIVATION_DELIVERY_VECTOR_CORPUS_SCHEMA_V1);
    assert_eq!(parsed.protocol_id(), "router_ab_ed25519_yao_v1");
    assert_eq!(
        parsed.evidence_scope(),
        ACTIVATION_DELIVERY_VECTOR_EVIDENCE_SCOPE_V1
    );
    assert_eq!(parsed.case_count(), 3);
    assert_eq!(
        canonical_activation_delivery_vector_corpus_v1().case_count(),
        3
    );
    let cases = cases();
    assert_eq!(
        cases
            .iter()
            .map(|case| string(case, "origin_request_kind"))
            .collect::<Vec<_>>(),
        ["registration", "recovery", "refresh"]
    );
}

#[test]
fn authorization_and_identity_are_monotonic_across_every_origin() {
    for case in cases() {
        let output = field(&case, "output_committed");
        let admitted = field(&case, "activation_control_admitted");
        let metadata = field(&case, "metadata_consumed");
        assert_eq!(
            string(output, "activation_authorization_state"),
            "not_issued"
        );
        assert_eq!(
            string(admitted, "activation_authorization_state"),
            "unconsumed"
        );
        assert_eq!(
            string(metadata, "activation_authorization_state"),
            "consumed"
        );
        for name in [
            "package_set_digest_hex",
            "output_committed_receipt_digest_hex",
        ] {
            assert_eq!(string(output, name), string(admitted, name));
            assert_eq!(string(output, name), string(metadata, name));
        }
        for name in [
            "request_context_digest_hex",
            "authorization_digest_hex",
            "transcript_digest_hex",
        ] {
            assert_eq!(string(admitted, name), string(metadata, name));
        }
        let encoding = decode_hex(string(output, "output_committed_receipt_encoding_hex"));
        assert_eq!(
            receipt_digest(&encoding),
            decode_hex(string(output, "output_committed_receipt_digest_hex"))
        );
        let released = field(&case, "recipients_released");
        let client = field(released, "client");
        let x_client = (ED25519_BASEPOINT_POINT * scalar(string(client, "x_client_base_hex")))
            .compress()
            .to_bytes();
        assert_eq!(
            x_client.as_slice(),
            decode_hex(string(output, "x_client_hex"))
        );
    }
}

#[test]
fn uncertainty_release_and_redelivery_preserve_capabilities_with_zero_work() {
    for case in cases() {
        let metadata = field(&case, "metadata_consumed");
        let uncertain = field(&case, "delivery_uncertain");
        let released = field(&case, "recipients_released");
        let redelivered = field(&case, "redelivered");
        let client = field(released, "client");
        let worker = field(released, "signing_worker");

        assert_eq!(
            string(uncertain, "before_package_set_digest_hex"),
            string(uncertain, "after_package_set_digest_hex")
        );
        assert_eq!(
            string(uncertain, "before_package_set_digest_hex"),
            string(metadata, "package_set_digest_hex")
        );
        for state in [uncertain, released, redelivered] {
            assert_eq!(string(state, "activation_authorization_state"), "consumed");
            assert_zero_work(field(state, "zero_private_evaluation_work"));
        }
        assert_eq!(
            string(client, "capability_kind"),
            "activation_client_scalar_release"
        );
        assert_eq!(
            string(worker, "capability_kind"),
            "signing_worker_activation_release_authority"
        );
        assert_eq!(
            string(client, "package_set_digest_hex"),
            string(released, "package_set_digest_hex")
        );
        assert_eq!(
            string(worker, "package_set_digest_hex"),
            string(released, "package_set_digest_hex")
        );
        assert!(decode_hex(string(client, "delivery_evidence_digest_hex"))
            .iter()
            .any(|byte| *byte != 0));
        assert!(decode_hex(string(worker, "delivery_evidence_digest_hex"))
            .iter()
            .any(|byte| *byte != 0));
        for (before, after) in [
            (
                "before_package_set_digest_hex",
                "after_package_set_digest_hex",
            ),
            ("before_client_scalar_hex", "after_client_scalar_hex"),
            (
                "before_client_delivery_evidence_digest_hex",
                "after_client_delivery_evidence_digest_hex",
            ),
            (
                "before_signing_worker_delivery_evidence_digest_hex",
                "after_signing_worker_delivery_evidence_digest_hex",
            ),
            (
                "before_signing_worker_authority_package_set_digest_hex",
                "after_signing_worker_authority_package_set_digest_hex",
            ),
        ] {
            assert_eq!(string(redelivered, before), string(redelivered, after));
        }
    }
}

#[test]
fn parser_rejects_mutation_truncation_and_forbidden_secret_fields() {
    let mut mutation = COMMITTED.to_vec();
    let index = mutation
        .iter()
        .position(|byte| *byte == b'a')
        .expect("fixture contains a mutable byte");
    mutation[index] = b'b';
    assert!(parse_canonical_activation_delivery_vector_corpus_json_v1(&mutation).is_err());
    assert!(parse_canonical_activation_delivery_vector_corpus_json_v1(
        &COMMITTED[..COMMITTED.len() - 1]
    )
    .is_err());

    let corpus = std::str::from_utf8(COMMITTED).expect("fixture is UTF-8");
    for forbidden in [
        "signing_worker_scalar_hex",
        "scalar_share_hex",
        "derivation_root_hex",
        "ciphertext_bytes_hex",
        "decryption_key_hex",
        "opener_state_hex",
        "frame_bytes_hex",
    ] {
        assert!(!corpus.contains(forbidden));
    }
}
