use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::{Signature, VerifyingKey};
use ed25519_yao_generator::{
    canonical_activation_recipient_party_view_vector_corpus_json_bytes_v1,
    canonical_activation_recipient_party_view_vector_corpus_v1,
    parse_canonical_activation_recipient_party_view_vector_corpus_json_v1,
    ACTIVATION_RECIPIENT_PARTY_VIEW_VECTOR_CORPUS_SCHEMA_V1,
    ACTIVATION_RECIPIENT_PARTY_VIEW_VECTOR_EVIDENCE_SCOPE_V1,
};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

const COMMITTED: &[u8] =
    include_bytes!("../vectors/ed25519-yao-activation-recipient-party-views-v1.json");
const ACTIVATION_DELIVERY: &[u8] =
    include_bytes!("../vectors/ed25519-yao-activation-delivery-v1.json");
const OUTPUT_PARTY_VIEWS: &[u8] =
    include_bytes!("../vectors/ed25519-yao-output-party-views-v1.json");

fn object(value: &Value) -> &Map<String, Value> {
    value.as_object().expect("expected object")
}

fn field<'a>(value: &'a Value, name: &str) -> &'a Value {
    &object(value)[name]
}

fn string<'a>(value: &'a Value, name: &str) -> &'a str {
    field(value, name).as_str().expect("expected string")
}

fn corpus(encoded: &[u8]) -> Value {
    serde_json::from_slice(encoded).expect("committed JSON")
}

fn cases(encoded: &[u8]) -> Vec<Value> {
    field(&corpus(encoded), "cases")
        .as_array()
        .expect("cases array")
        .clone()
}

fn decode_hex(encoded: &str) -> Vec<u8> {
    assert_eq!(encoded.len() % 2, 0);
    (0..encoded.len())
        .step_by(2)
        .map(|offset| u8::from_str_radix(&encoded[offset..offset + 2], 16).expect("hex"))
        .collect()
}

fn scalar(encoded: &str) -> Scalar {
    let bytes: [u8; 32] = decode_hex(encoded).try_into().expect("32-byte scalar");
    Option::<Scalar>::from(Scalar::from_canonical_bytes(bytes)).expect("canonical scalar")
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

#[test]
fn committed_corpus_is_exact_strict_and_has_three_ordered_origins() {
    assert_eq!(
        COMMITTED,
        canonical_activation_recipient_party_view_vector_corpus_json_bytes_v1()
    );
    let parsed = parse_canonical_activation_recipient_party_view_vector_corpus_json_v1(COMMITTED)
        .expect("canonical corpus");
    assert_eq!(
        parsed.schema(),
        ACTIVATION_RECIPIENT_PARTY_VIEW_VECTOR_CORPUS_SCHEMA_V1
    );
    assert_eq!(parsed.protocol_id(), "router_ab_ed25519_yao_v1");
    assert_eq!(
        parsed.evidence_scope(),
        ACTIVATION_RECIPIENT_PARTY_VIEW_VECTOR_EVIDENCE_SCOPE_V1
    );
    assert_eq!(parsed.case_count(), 3);
    assert_eq!(
        canonical_activation_recipient_party_view_vector_corpus_v1().case_count(),
        3
    );
    assert_eq!(
        cases(COMMITTED)
            .iter()
            .map(|case| string(case, "origin_request_kind"))
            .collect::<Vec<_>>(),
        ["registration", "recovery", "refresh"]
    );
}

#[test]
fn released_views_cross_link_activation_delivery_and_keep_five_roles_empty() {
    for (recipient_case, delivery_case) in cases(COMMITTED)
        .iter()
        .zip(cases(ACTIVATION_DELIVERY).iter())
    {
        assert_eq!(
            string(recipient_case, "activation_delivery_case_id"),
            string(delivery_case, "case_id")
        );
        let released = field(recipient_case, "recipients_released");
        let common = field(released, "common_public");
        let extensions = field(released, "role_extensions");
        let delivery = field(delivery_case, "recipients_released");
        for name in [
            "package_set_digest_hex",
            "output_committed_receipt_digest_hex",
            "activation_transcript_digest_hex",
        ] {
            assert_eq!(string(common, name), string(delivery, name));
        }
        assert_eq!(string(common, "stage"), "recipients_released");
        assert_eq!(string(common, "activation_authorization_state"), "consumed");
        assert!(object(field(common, "zero_private_evaluation_work"))
            .values()
            .all(|value| value.as_u64() == Some(0)));
        for role in [
            "deriver_a",
            "deriver_b",
            "router",
            "observer",
            "diagnostics",
        ] {
            assert!(object(field(extensions, role)).is_empty());
        }
        let client = field(extensions, "client");
        let delivery_client = field(delivery, "client");
        assert_eq!(
            string(client, "extension_kind"),
            string(delivery_client, "capability_kind")
        );
        for name in [
            "package_set_digest_hex",
            "delivery_evidence_digest_hex",
            "x_client_base_hex",
        ] {
            assert_eq!(string(client, name), string(delivery_client, name));
        }
        let worker = field(extensions, "signing_worker");
        let delivery_worker = field(delivery, "signing_worker");
        assert_eq!(
            string(worker, "extension_kind"),
            string(delivery_worker, "capability_kind")
        );
        for name in ["package_set_digest_hex", "delivery_evidence_digest_hex"] {
            assert_eq!(string(worker, name), string(delivery_worker, name));
        }
    }
}

#[test]
fn pre_release_views_are_empty_and_released_client_scalar_matches_committed_shares() {
    let output_cases = cases(OUTPUT_PARTY_VIEWS);
    for (index, recipient_case) in cases(COMMITTED).iter().enumerate() {
        let output_case = &output_cases[[0, 2, 3][index]];
        assert_eq!(
            string(recipient_case, "output_party_view_case_id"),
            string(field(output_case, "vector"), "case_id")
        );
        let output_extensions = field(field(output_case, "vector"), "role_extensions");
        assert_eq!(
            string(field(output_extensions, "client"), "kind"),
            "client_no_private_output"
        );
        assert_eq!(
            string(field(output_extensions, "signing_worker"), "kind"),
            "signing_worker_no_private_output"
        );
        let client_a = scalar(string(
            field(output_extensions, "deriver_a"),
            "client_scalar_share_hex",
        ));
        let client_b = scalar(string(
            field(output_extensions, "deriver_b"),
            "client_scalar_share_hex",
        ));
        let released_client = field(
            field(
                field(recipient_case, "recipients_released"),
                "role_extensions",
            ),
            "client",
        );
        assert_eq!(
            scalar(string(released_client, "x_client_base_hex")),
            client_a + client_b
        );
    }
}

#[test]
fn activated_views_retain_client_and_reconstruct_only_worker_scalar() {
    let output_cases = cases(OUTPUT_PARTY_VIEWS);
    for (index, recipient_case) in cases(COMMITTED).iter().enumerate() {
        let released_extensions = field(
            field(recipient_case, "recipients_released"),
            "role_extensions",
        );
        let activated = field(recipient_case, "signing_worker_activated");
        let common = field(activated, "common_public");
        let activated_extensions = field(activated, "role_extensions");
        assert_eq!(
            field(activated_extensions, "client"),
            field(released_extensions, "client")
        );
        for role in [
            "deriver_a",
            "deriver_b",
            "router",
            "observer",
            "diagnostics",
        ] {
            assert!(object(field(activated_extensions, role)).is_empty());
        }
        let output_extensions = field(
            field(&output_cases[[0, 2, 3][index]], "vector"),
            "role_extensions",
        );
        let server_a = scalar(string(
            field(output_extensions, "deriver_a"),
            "signing_worker_scalar_share_hex",
        ));
        let server_b = scalar(string(
            field(output_extensions, "deriver_b"),
            "signing_worker_scalar_share_hex",
        ));
        let worker = field(activated_extensions, "signing_worker");
        let server = scalar(string(worker, "x_server_base_hex"));
        assert_eq!(server, server_a + server_b);
        assert_eq!(
            (ED25519_BASEPOINT_POINT * server)
                .compress()
                .to_bytes()
                .as_slice(),
            decode_hex(string(common, "x_server_hex"))
        );
        let client = scalar(string(
            field(activated_extensions, "client"),
            "x_client_base_hex",
        ));
        assert_eq!(
            (ED25519_BASEPOINT_POINT * (client + client - server))
                .compress()
                .to_bytes()
                .as_slice(),
            decode_hex(string(common, "registered_public_key_hex"))
        );
    }
}

#[test]
fn activated_receipt_digest_key_binding_and_signature_are_exact() {
    const RECEIPT_DIGEST_DOMAIN: &[u8] =
        b"seams/router-ab/ed25519-yao/signing-worker-activation-receipt-digest/v1";
    const RECEIPT_KEY_DIGEST_DOMAIN: &[u8] =
        b"seams/router-ab/ed25519-yao/signing-worker-receipt-key-digest/v1";
    for case in cases(COMMITTED) {
        let common = field(field(&case, "signing_worker_activated"), "common_public");
        let receipt = decode_hex(string(common, "activation_receipt_encoding_hex"));
        let mut digest_preimage = lp32(RECEIPT_DIGEST_DOMAIN);
        digest_preimage.extend_from_slice(&lp32(&receipt));
        assert_eq!(
            Sha256::digest(digest_preimage).as_slice(),
            decode_hex(string(common, "activation_receipt_digest_hex"))
        );

        let verifying_key_bytes: [u8; 32] = decode_hex(string(common, "receipt_verifying_key_hex"))
            .try_into()
            .expect("verifying key");
        let mut key_preimage = lp32(RECEIPT_KEY_DIGEST_DOMAIN);
        key_preimage.extend_from_slice(&lp32(string(common, "signing_worker_id").as_bytes()));
        key_preimage.extend_from_slice(&lp32(
            &field(common, "signing_worker_recipient_key_epoch")
                .as_u64()
                .expect("worker epoch")
                .to_be_bytes(),
        ));
        key_preimage.extend_from_slice(&lp32(&verifying_key_bytes));
        assert_eq!(
            Sha256::digest(key_preimage).as_slice(),
            decode_hex(string(common, "receipt_key_digest_hex"))
        );
        let signature = Signature::from_slice(&decode_hex(string(
            common,
            "activation_receipt_signature_hex",
        )))
        .expect("signature");
        VerifyingKey::from_bytes(&verifying_key_bytes)
            .expect("verifying key")
            .verify_strict(&receipt, &signature)
            .expect("strict receipt signature");
    }
}

#[test]
fn parser_rejects_drift_and_corpus_excludes_frames_openers_and_durable_records() {
    let mut mutation = COMMITTED.to_vec();
    let index = mutation
        .iter()
        .position(|byte| *byte == b'a')
        .expect("mutable byte");
    mutation[index] = b'b';
    assert!(
        parse_canonical_activation_recipient_party_view_vector_corpus_json_v1(&mutation).is_err()
    );
    assert!(
        parse_canonical_activation_recipient_party_view_vector_corpus_json_v1(
            &COMMITTED[..COMMITTED.len() - 1]
        )
        .is_err()
    );
    let corpus = std::str::from_utf8(COMMITTED).expect("UTF-8 corpus");
    for forbidden in [
        "frame_bytes_hex",
        "sent_frames",
        "received_frames",
        "ciphertext_bytes_hex",
        "decryption_key_hex",
        "opener_state_hex",
        "durable_record",
        "database_transaction",
        "derivation_root_hex",
        "client_scalar_share_hex",
        "signing_worker_scalar_share_hex",
    ] {
        assert!(!corpus.contains(forbidden));
    }
}
