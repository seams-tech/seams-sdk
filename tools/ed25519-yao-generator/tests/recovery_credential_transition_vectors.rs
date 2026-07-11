use ed25519_dalek::{Signature, SigningKey};
use ed25519_yao_generator::{
    canonical_recovery_credential_transition_vector_corpus_json_bytes_v1,
    canonical_recovery_credential_transition_vector_corpus_v1,
    parse_canonical_recovery_credential_transition_vector_corpus_json_v1,
    RECOVERY_CREDENTIAL_TRANSITION_VECTOR_CORPUS_SCHEMA_V1,
    RECOVERY_CREDENTIAL_TRANSITION_VECTOR_EVIDENCE_SCOPE_V1,
};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

const COMMITTED: &[u8] =
    include_bytes!("../vectors/ed25519-yao-recovery-credential-transition-v1.json");

fn object(value: &Value) -> &Map<String, Value> {
    value.as_object().expect("expected object")
}

fn field<'a>(value: &'a Value, name: &str) -> &'a Value {
    &object(value)[name]
}

fn string<'a>(value: &'a Value, name: &str) -> &'a str {
    field(value, name).as_str().expect("expected string")
}

fn number(value: &Value, name: &str) -> u64 {
    field(value, name).as_u64().expect("expected u64")
}

fn decode_hex(encoded: &str) -> Vec<u8> {
    assert_eq!(encoded.len() % 2, 0);
    (0..encoded.len())
        .step_by(2)
        .map(|offset| u8::from_str_radix(&encoded[offset..offset + 2], 16).expect("hex"))
        .collect()
}

fn lp32(value: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    output.extend_from_slice(
        &u32::try_from(value.len())
            .expect("fixture length")
            .to_be_bytes(),
    );
    output.extend_from_slice(value);
    output
}

fn lp32_fields(mut encoded: &[u8]) -> Vec<Vec<u8>> {
    let mut fields = Vec::new();
    while !encoded.is_empty() {
        let length = u32::from_be_bytes(encoded[..4].try_into().expect("LP32")) as usize;
        encoded = &encoded[4..];
        fields.push(encoded[..length].to_vec());
        encoded = &encoded[length..];
    }
    fields
}

fn only_case() -> Value {
    let corpus: Value = serde_json::from_slice(COMMITTED).expect("corpus JSON");
    field(&corpus, "cases").as_array().expect("cases")[0].clone()
}

fn state_digest(state: &Value) -> Vec<u8> {
    let mut encoded = Vec::new();
    let values = [
        b"seams/router-ab/ed25519-yao/recovery-promotion-state-digest/v1".to_vec(),
        decode_hex(string(state, "registered_public_key_hex")),
        decode_hex(string(state, "active_credential_binding_digest_hex")),
        decode_hex(string(state, "stable_scope_encoding_hex")),
        number(state, "active_activation_epoch")
            .to_be_bytes()
            .to_vec(),
        decode_hex(string(state, "deriver_a_root_record_hex")),
        decode_hex(string(state, "deriver_a_root_binding_hex")),
        number(state, "deriver_a_root_epoch").to_be_bytes().to_vec(),
        decode_hex(string(state, "deriver_a_state_record_hex")),
        number(state, "deriver_a_input_state_epoch")
            .to_be_bytes()
            .to_vec(),
        decode_hex(string(state, "deriver_b_root_record_hex")),
        decode_hex(string(state, "deriver_b_root_binding_hex")),
        number(state, "deriver_b_root_epoch").to_be_bytes().to_vec(),
        decode_hex(string(state, "deriver_b_state_record_hex")),
        number(state, "deriver_b_input_state_epoch")
            .to_be_bytes()
            .to_vec(),
    ];
    for value in values {
        encoded.extend_from_slice(&lp32(&value));
    }
    Sha256::digest(encoded).to_vec()
}

#[test]
fn committed_corpus_is_exact_and_strictly_parseable() {
    assert_eq!(
        COMMITTED,
        canonical_recovery_credential_transition_vector_corpus_json_bytes_v1()
    );
    let parsed = parse_canonical_recovery_credential_transition_vector_corpus_json_v1(COMMITTED)
        .expect("canonical corpus");
    assert_eq!(
        parsed.schema(),
        RECOVERY_CREDENTIAL_TRANSITION_VECTOR_CORPUS_SCHEMA_V1
    );
    assert_eq!(parsed.protocol_id(), "router_ab_ed25519_yao_v1");
    assert_eq!(
        parsed.evidence_scope(),
        RECOVERY_CREDENTIAL_TRANSITION_VECTOR_EVIDENCE_SCOPE_V1
    );
    assert_eq!(parsed.case_count(), 1);
    assert_eq!(
        canonical_recovery_credential_transition_vector_corpus_v1().case_count(),
        1
    );
}

#[test]
fn promotion_receipt_has_exact_fields_digests_and_pinned_signature() {
    let case = only_case();
    let promoted = field(&case, "promoted");
    let encoding = decode_hex(string(promoted, "promotion_receipt_encoding_hex"));
    let fields = lp32_fields(&encoding);
    assert_eq!(fields.len(), 20);
    assert_eq!(
        fields[0],
        b"seams/router-ab/ed25519-yao/recovery-promotion/v1"
    );
    assert_eq!(fields[13], state_digest(field(promoted, "old_state")));
    assert_eq!(fields[14], state_digest(field(promoted, "next_state")));
    let mut digest_input =
        lp32(b"seams/router-ab/ed25519-yao/recovery-promotion-receipt-digest/v1");
    digest_input.extend_from_slice(&lp32(&encoding));
    assert_eq!(
        decode_hex(string(promoted, "promotion_receipt_digest_hex")),
        Sha256::digest(digest_input).as_slice()
    );
    let pinned = SigningKey::from_bytes(&[0x5a; 32]).verifying_key();
    let signature = Signature::from_slice(&decode_hex(string(
        promoted,
        "promotion_receipt_signature_hex",
    )))
    .expect("signature");
    pinned
        .verify_strict(&encoding, &signature)
        .expect("pinned authority signature");
}

#[test]
fn promotion_changes_only_credential_epoch_and_state_version() {
    let case = only_case();
    let promoted = field(&case, "promoted");
    let old = object(field(promoted, "old_state"));
    let next = object(field(promoted, "next_state"));
    for (name, value) in old {
        if matches!(
            name.as_str(),
            "active_state_version"
                | "active_credential_binding_digest_hex"
                | "active_activation_epoch"
        ) {
            assert_ne!(next[name], *value);
        } else {
            assert_eq!(next[name], *value, "{name} changed");
        }
    }
    assert_eq!(
        number(field(promoted, "next_state"), "active_state_version"),
        number(field(promoted, "old_state"), "active_state_version") + 1
    );
    assert_eq!(
        number(field(promoted, "next_state"), "active_activation_epoch"),
        number(field(&case, "worker_activated"), "activation_epoch")
    );
}

#[test]
fn suspension_tombstone_and_companion_references_are_exact() {
    let case = only_case();
    let suspended = field(&case, "suspended");
    let promoted = field(&case, "promoted");
    let tombstone = field(promoted, "tombstone");
    assert_eq!(string(suspended, "credential_state"), "suspended");
    assert_eq!(string(promoted, "credential_state"), "active");
    assert_eq!(string(tombstone, "credential_state"), "tombstoned");
    assert_eq!(
        string(tombstone, "credential_binding_digest_hex"),
        string(suspended, "old_credential_binding_digest_hex")
    );
    assert_eq!(
        number(tombstone, "retired_state_version"),
        number(suspended, "old_active_state_version")
    );
    let sources = field(&case, "source_references");
    assert_eq!(
        string(sources, "ceremony_context_case_id"),
        "ceremony-recovery-v1"
    );
    assert_eq!(
        string(sources, "activation_recipient_party_view_case_id"),
        "recovery_activation_recipient_party_views_v1"
    );
}

#[test]
fn parser_rejects_mutation_truncation_and_unknown_or_secret_fields() {
    let mut mutation = COMMITTED.to_vec();
    let midpoint = mutation.len() / 2;
    mutation[midpoint] ^= 1;
    assert!(
        parse_canonical_recovery_credential_transition_vector_corpus_json_v1(&mutation).is_err()
    );
    assert!(
        parse_canonical_recovery_credential_transition_vector_corpus_json_v1(
            &COMMITTED[..COMMITTED.len() - 1]
        )
        .is_err()
    );
    let mut value: Value = serde_json::from_slice(COMMITTED).expect("JSON");
    object(
        field(&value, "cases")
            .as_array()
            .expect("cases")
            .first()
            .expect("case"),
    );
    value.as_object_mut().expect("root").insert(
        "security_profile".to_owned(),
        Value::String("p2".to_owned()),
    );
    let encoded = serde_json::to_vec_pretty(&value).expect("mutation");
    assert!(
        parse_canonical_recovery_credential_transition_vector_corpus_json_v1(&encoded).is_err()
    );
}
