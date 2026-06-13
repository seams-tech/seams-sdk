use router_ab_core::{
    AccountScope, AuthenticatedSignerReceiptV1, DerivationContext, MinimumLevelCEvidenceV1,
    RootShareEpoch, SignerSetBinding, TranscriptBinding,
};
use serde_json::{json, Value};

fn digest_json(seed: u8) -> Value {
    json!({
        "bytes": vec![seed; 32]
    })
}

fn raw_context_json() -> Value {
    json!({
        "candidate_id": "mpc_threshold_prf_v1",
        "request_kind": "registration",
        "correctness_level": "minimum_level_c",
        "account_scope": {
            "network_id": "near-testnet",
            "account_id": "alice.testnet",
            "account_public_key": "ed25519:11111111111111111111111111111111"
        },
        "root_share_epoch": "epoch-1",
        "ceremony_id": "ceremony-1"
    })
}

fn raw_signer_set_json() -> Value {
    json!({
        "signer_set_id": "signer-set-v1",
        "quorum_policy": {
            "All": {
                "signer_count": 2
            }
        },
        "signers": [
            {
                "signer_index": 0,
                "role": "signer_a",
                "signer_id": "role:signer-a:local:sha256-a",
                "key_epoch": "key-epoch-a-1"
            },
            {
                "signer_index": 1,
                "role": "signer_b",
                "signer_id": "role:signer-b:local:sha256-b",
                "key_epoch": "key-epoch-b-1"
            }
        ]
    })
}

fn raw_transcript_json() -> Value {
    json!({
        "context": raw_context_json(),
        "router_id": "role:router:local:sha256-router",
        "signer_set": raw_signer_set_json(),
        "selected_relayer_id": "role:relayer:local:sha256-r",
        "selected_relayer_recipient_encryption_key": "x25519:1111111111111111111111111111111111111111111111111111111111111111",
        "client_id": "role:client:local:sha256-c",
        "client_ephemeral_public_key": "x25519:client-ephemeral-public-key"
    })
}

fn raw_signer_receipt_json() -> Value {
    json!({
        "receipt_version": "v1",
        "signer_role": "signer_a",
        "signer_identity": "role:signer-a:local:sha256-a",
        "accepted_transcript_digest": digest_json(0x11),
        "accepted_root_share_epoch": "epoch-1",
        "output_package_commitments": [
            digest_json(0xa1),
            digest_json(0xa2)
        ]
    })
}

fn raw_minimum_level_c_evidence_json() -> Value {
    json!({
        "evidence_version": "v1",
        "correctness_level": "minimum_level_c",
        "context_digest": digest_json(0x01),
        "transcript_digest": digest_json(0x02),
        "signer_a_receipt_digest": digest_json(0x03),
        "signer_b_receipt_digest": digest_json(0x04),
        "client_package_commitments": [
            digest_json(0xa1),
            digest_json(0xb1)
        ],
        "relayer_package_commitments": [
            digest_json(0xa2),
            digest_json(0xb2)
        ],
        "replay_cache_key": digest_json(0x99)
    })
}

#[test]
fn typed_context_deserialize_runs_constructor_validation() {
    let context: DerivationContext =
        serde_json::from_value(raw_context_json()).expect("context parses");

    assert_eq!(context.root_share_epoch().as_str(), "epoch-1");
    assert_eq!(context.ceremony_id(), "ceremony-1");
}

#[test]
fn typed_context_deserialize_rejects_empty_ceremony_id() {
    let mut raw = raw_context_json();
    raw["ceremony_id"] = json!("");

    let err = serde_json::from_value::<DerivationContext>(raw)
        .expect_err("empty ceremony id should fail");

    assert!(err.to_string().contains("ceremony_id is required"));
}

#[test]
fn typed_root_epoch_deserialize_rejects_empty_string() {
    let err = serde_json::from_value::<RootShareEpoch>(json!(""))
        .expect_err("empty root epoch should fail");

    assert!(err.to_string().contains("root_share_epoch is required"));
}

#[test]
fn typed_account_scope_deserialize_rejects_empty_public_key() {
    let err = serde_json::from_value::<AccountScope>(json!({
        "network_id": "near-testnet",
        "account_id": "alice.testnet",
        "account_public_key": ""
    }))
    .expect_err("empty account public key should fail");

    assert!(err.to_string().contains("account_public_key is required"));
}

#[test]
fn typed_signer_set_deserialize_rejects_non_all2_quorum() {
    let mut raw = raw_signer_set_json();
    raw["quorum_policy"] = json!({
        "All": {
            "signer_count": 3
        }
    });

    let err =
        serde_json::from_value::<SignerSetBinding>(raw).expect_err("all(3) quorum should fail");

    assert!(err.to_string().contains("v1 requires quorum policy all(2)"));
}

#[test]
fn typed_transcript_deserialize_rejects_empty_client_key() {
    let mut raw = raw_transcript_json();
    raw["client_ephemeral_public_key"] = json!("");

    let err =
        serde_json::from_value::<TranscriptBinding>(raw).expect_err("empty client key should fail");

    assert!(err
        .to_string()
        .contains("client_ephemeral_public_key is required"));
}

#[test]
fn typed_signer_receipt_deserialize_rejects_non_signer_role() {
    let mut raw = raw_signer_receipt_json();
    raw["signer_role"] = json!("router");

    let err = serde_json::from_value::<AuthenticatedSignerReceiptV1>(raw)
        .expect_err("router receipt role should fail");

    assert!(err
        .to_string()
        .contains("signer receipt role must be Signer A or Signer B"));
}

#[test]
fn typed_signer_receipt_deserialize_rejects_missing_commitment() {
    let mut raw = raw_signer_receipt_json();
    raw["output_package_commitments"] = json!([digest_json(0xa1)]);

    let err = serde_json::from_value::<AuthenticatedSignerReceiptV1>(raw)
        .expect_err("short receipt commitment set should fail");

    assert!(err
        .to_string()
        .contains("signer receipt requires exactly two output package commitments"));
}

#[test]
fn typed_minimum_level_c_evidence_deserialize_accepts_public_shape() {
    let evidence: MinimumLevelCEvidenceV1 =
        serde_json::from_value(raw_minimum_level_c_evidence_json()).expect("evidence parses");

    assert_eq!(evidence.client_package_commitments().len(), 2);
    assert_eq!(evidence.relayer_package_commitments().len(), 2);
}

#[test]
fn typed_minimum_level_c_evidence_deserialize_rejects_wrong_correctness() {
    let mut raw = raw_minimum_level_c_evidence_json();
    raw["correctness_level"] = json!("public_share_binding_v1");

    let err = serde_json::from_value::<MinimumLevelCEvidenceV1>(raw)
        .expect_err("wrong correctness should fail");

    assert!(err
        .to_string()
        .contains("Minimum Level C evidence requires minimum_level_c correctness"));
}

#[test]
fn typed_minimum_level_c_evidence_deserialize_rejects_missing_package_commitment() {
    let mut raw = raw_minimum_level_c_evidence_json();
    raw["client_package_commitments"] = json!([digest_json(0xa1)]);

    let err = serde_json::from_value::<MinimumLevelCEvidenceV1>(raw)
        .expect_err("short client commitment set should fail");

    assert!(err
        .to_string()
        .contains("Minimum Level C evidence requires exactly two client package commitments"));
}
