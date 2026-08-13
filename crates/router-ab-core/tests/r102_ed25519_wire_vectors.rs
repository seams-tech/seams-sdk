//! Rust half of the Refactor 102 Ed25519 job and product-receipt wire contract.
//!
//! Regenerate only after an intentional canonical wire change:
//! `UPDATE_R102_ED25519_WIRE_FIXTURES=1 cargo test -p router-ab-core --test r102_ed25519_wire_vectors`.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use base64ct::{Base64UrlUnpadded, Encoding};
use router_ab_core::protocol::{
    Ed25519YaoLaneAuthorizationV1, Ed25519YaoLaneJobV1, Ed25519YaoLaneProtocolCommittedV1,
    Ed25519YaoLaneRequestKindV1, Ed25519YaoLaneSourceKindV1, Ed25519YaoLaneSourceV1,
    Ed25519YaoLaneTargetHolderV1, Ed25519YaoLaneTargetSigningWorkerV1, Ed25519YaoLaneTargetV1,
    MpcMaterialActivationRefV1,
};
use serde_json::{json, Value};

const UPDATE_ENV: &str = "UPDATE_R102_ED25519_WIRE_FIXTURES";
const FIXTURE_VERSION: &str = "r102_ed25519_wire_vectors_v1";

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join("protocol")
        .join("r102")
        .join("ed25519-wire-vectors-v1.json")
}

fn b64(bytes: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(bytes)
}

fn digest(value: u8) -> String {
    b64(&[value; 32])
}

fn activation(id: &str) -> MpcMaterialActivationRefV1 {
    MpcMaterialActivationRefV1::new(
        id,
        "ed25519-capability:wallet-key-A",
        "wallet-A",
        "near-ed25519-key:A",
        "yao-lifecycle:A",
        "signing-worker:source",
    )
    .expect("valid activation")
}

fn job() -> Ed25519YaoLaneJobV1 {
    Ed25519YaoLaneJobV1::new(Ed25519YaoLaneJobV1 {
        kind: "ed25519_yao_lane_job_v1".to_owned(),
        key_family: "ed25519".to_owned(),
        yao_request_kind: Ed25519YaoLaneRequestKindV1::LaneProvisioning,
        operation_id: "lane-operation:ed25519:A".to_owned(),
        enrollment_id: "lane-enrollment:A".to_owned(),
        idempotency_key: "lane-idempotency:ed25519:A".to_owned(),
        wallet_id: "wallet-A".to_owned(),
        wallet_key_id: "wallet-key:ed25519:A".to_owned(),
        source: Ed25519YaoLaneSourceV1 {
            lane_id: "owner-lane:A".to_owned(),
            lane_kind: "owner_passkey".to_owned(),
            lane_share_epoch: "opaque/creation-epoch:A".to_owned(),
            revocation_epoch: 7,
            source_kind: Ed25519YaoLaneSourceKindV1::OwnerRegistration {
                owner_participant_continuity:
                    router_ab_core::protocol::OwnerLaneParticipantContinuityV1 {
                        kind: "owner_lane_participant_continuity_v1".to_owned(),
                        signer_id: "signer:owner".to_owned(),
                        participant_ids: [1, 2],
                        signing_worker_id: "signing-worker:source".to_owned(),
                        custody_key_manifest_digest_b64u: digest(18),
                        source_identity_digest_b64u: digest(19),
                    },
            },
            participant_binding_digest_b64u: digest(1),
            material_activation: activation("activation:source"),
        },
        target: Ed25519YaoLaneTargetV1::CreateLane {
            lane_id: "linked-device-lane:A".to_owned(),
            lane_kind: "linked_device".to_owned(),
            lane_share_epoch: "opaque/creation-epoch:A".to_owned(),
            expected_target_state: "absent".to_owned(),
        },
        authorization: Ed25519YaoLaneAuthorizationV1::LinkedDeviceEnrollment {
            authorized_operation_id: "authorized-operation:A".to_owned(),
            linked_device_enrollment_id: "linked-device-enrollment:A".to_owned(),
            linked_device_permission_digest_b64u: digest(2),
        },
        target_material_activation_id: "activation:target".to_owned(),
        target_holder: Ed25519YaoLaneTargetHolderV1 {
            participant_id: "holder:linked-device".to_owned(),
            participant_binding_digest_b64u: digest(3),
            custody_binding_id: "custody-binding:linked-device".to_owned(),
            custody_binding_digest_b64u: digest(4),
            hpke_public_key_b64u: digest(5),
            hpke_public_key_digest_b64u: digest(6),
        },
        target_signing_worker: Ed25519YaoLaneTargetSigningWorkerV1 {
            participant_id: "signing-worker:target".to_owned(),
            participant_binding_digest_b64u: digest(7),
            recipient_key_id: "recipient-key:target".to_owned(),
            hpke_public_key_b64u: digest(8),
            hpke_public_key_digest_b64u: digest(9),
        },
        protocol_version: "rotatable_signing_lane_protocol_v1".to_owned(),
        registered_public_key_b64u: digest(10),
        key_creation_signer_slot: 7,
        stable_context_binding_b64u: digest(11),
        near_ed25519_signing_key_id: "near-ed25519-key:A".to_owned(),
        yao_suite_id: "ed25519-yao-suite:A".to_owned(),
        circuit_digest_b64u: digest(12),
        expires_at_ms: 1_900_000_000_123,
    })
    .expect("valid Ed25519 lane job")
}

fn receipt(job: &Ed25519YaoLaneJobV1) -> Ed25519YaoLaneProtocolCommittedV1 {
    Ed25519YaoLaneProtocolCommittedV1::new(
        job.operation_id.clone(),
        job.enrollment_id.clone(),
        job.wallet_id.clone(),
        job.wallet_key_id.clone(),
        job.source.lane_id.clone(),
        job.source.lane_share_epoch.clone(),
        job.source.revocation_epoch,
        job.source.material_activation.clone(),
        job.target_lane_id().to_owned(),
        job.target_lane_share_epoch().to_owned(),
        job.target_material_activation_id.clone(),
        job.key_family.clone(),
        digest(13),
        digest(14),
        digest(15),
        digest(16),
        digest(17),
        job.target_holder.hpke_public_key_digest_b64u.clone(),
        job.target_signing_worker
            .hpke_public_key_digest_b64u
            .clone(),
        b64(&job.transcript_digest_v1().expect("job digest")),
        1_800_000_000_333,
    )
    .expect("valid product receipt")
}

fn job_substitutions(job: &Ed25519YaoLaneJobV1) -> BTreeMap<String, Value> {
    let baseline_digest = job.transcript_digest_v1().expect("baseline job digest");
    let mut substitutions = BTreeMap::new();
    let mut record = |name: &str, candidate: Ed25519YaoLaneJobV1| {
        candidate.validate().expect("valid substituted job");
        let candidate_digest = candidate
            .transcript_digest_v1()
            .expect("substituted job digest");
        assert_ne!(candidate_digest, baseline_digest);
        substitutions.insert(
            name.to_owned(),
            json!({
                "jobTranscriptDigestB64u": b64(&candidate_digest),
                "sessionDigestB64u": b64(&candidate.session_v1().expect("substituted session")),
            }),
        );
    };

    let mut candidate = job.clone();
    candidate.target_holder.custody_binding_id = "custody-binding:substituted".to_owned();
    record("targetCustodyBindingId", candidate);

    let mut candidate = job.clone();
    candidate.target_holder.participant_id = "holder:substituted".to_owned();
    record("holderParticipant", candidate);

    let mut candidate = job.clone();
    candidate.target_holder.participant_binding_digest_b64u = digest(20);
    record("holderParticipantBinding", candidate);

    let mut candidate = job.clone();
    candidate.target_holder.hpke_public_key_b64u = digest(21);
    record("holderRecipientKey", candidate);

    let mut candidate = job.clone();
    candidate.target_holder.hpke_public_key_digest_b64u = digest(22);
    record("holderRecipientKeyDigest", candidate);

    let mut candidate = job.clone();
    candidate.target_signing_worker.participant_id = "signing-worker:substituted".to_owned();
    record("workerParticipant", candidate);

    let mut candidate = job.clone();
    candidate
        .target_signing_worker
        .participant_binding_digest_b64u = digest(23);
    record("workerParticipantBinding", candidate);

    let mut candidate = job.clone();
    candidate.target_signing_worker.recipient_key_id = "recipient-key:substituted".to_owned();
    record("workerRecipientKeyId", candidate);

    let mut candidate = job.clone();
    candidate.target_signing_worker.hpke_public_key_b64u = digest(24);
    record("workerRecipientKey", candidate);

    let mut candidate = job.clone();
    candidate.target_signing_worker.hpke_public_key_digest_b64u = digest(25);
    record("workerRecipientKeyDigest", candidate);

    substitutions
}

fn receipt_substitutions(receipt: &Ed25519YaoLaneProtocolCommittedV1) -> BTreeMap<String, String> {
    let baseline = receipt.digest_v1().expect("baseline receipt digest");
    let mut substitutions = BTreeMap::new();
    let mut record = |name: &str, candidate: Ed25519YaoLaneProtocolCommittedV1| {
        candidate.validate().expect("valid substituted receipt");
        let candidate_digest = candidate.digest_v1().expect("substituted receipt digest");
        assert_ne!(candidate_digest, baseline);
        substitutions.insert(name.to_owned(), b64(&candidate_digest));
    };

    let mut candidate = receipt.clone();
    candidate.source_lane_share_epoch = "opaque/source-epoch:substituted".to_owned();
    record("sourceLaneShareEpoch", candidate);

    let mut candidate = receipt.clone();
    candidate.target_lane_share_epoch = "opaque/target-epoch:substituted".to_owned();
    record("targetLaneShareEpoch", candidate);

    let mut candidate = receipt.clone();
    candidate.holder_recipient_key_digest_b64u = digest(26);
    record("holderRecipientKeyDigest", candidate);

    let mut candidate = receipt.clone();
    candidate.server_recipient_key_digest_b64u = digest(27);
    record("serverRecipientKeyDigest", candidate);

    let mut candidate = receipt.clone();
    candidate.transcript_hash_b64u = digest(28);
    record("transcriptHash", candidate);

    substitutions
}

fn generated_fixture() -> Value {
    let job = job();
    let receipt = receipt(&job);
    let job_digest = job.transcript_digest_v1().expect("job digest");
    json!({
        "fixtureVersion": FIXTURE_VERSION,
        "job": job,
        "canonicalJobTranscriptB64u": b64(&job.canonical_transcript_bytes_v1().expect("job bytes")),
        "jobTranscriptDigestB64u": b64(&job_digest),
        "sessionDigestB64u": b64(&job.session_v1().expect("session digest")),
        "jobSubstitutions": job_substitutions(&job),
        "tamperedBindings": {
            "jobTranscriptDigestB64u": digest(29),
            "sessionDigestB64u": digest(30),
        },
        "protocolCommitReceipt": receipt,
        "canonicalProtocolCommitReceiptB64u": b64(&receipt.canonical_bytes_v1().expect("receipt bytes")),
        "protocolCommitReceiptDigestB64u": b64(&receipt.digest_v1().expect("receipt digest")),
        "receiptSubstitutionDigestsB64u": receipt_substitutions(&receipt),
    })
}

fn generated_fixture_json() -> String {
    let mut output = serde_json::to_string_pretty(&generated_fixture()).expect("serialize fixture");
    output.push('\n');
    output
}

fn update_fixture_if_requested() {
    if std::env::var_os(UPDATE_ENV).is_none() {
        return;
    }
    let path = fixture_path();
    fs::create_dir_all(path.parent().expect("fixture parent")).expect("create fixture directory");
    fs::write(path, generated_fixture_json()).expect("write fixture");
}

#[test]
fn committed_ed25519_wire_fixture_matches_production_encoders() {
    update_fixture_if_requested();
    let generated = generated_fixture_json();
    let path = fixture_path();
    let committed = fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!(
            "read {}: {error}; regenerate with {UPDATE_ENV}=1 cargo test -p router-ab-core --test r102_ed25519_wire_vectors",
            path.display()
        )
    });
    assert_eq!(committed, generated, "regenerate with {UPDATE_ENV}=1");
}

#[test]
fn frozen_ed25519_job_session_receipt_and_tamper_vectors_revalidate() {
    update_fixture_if_requested();
    let fixture: Value =
        serde_json::from_str(&fs::read_to_string(fixture_path()).expect("read fixture"))
            .expect("parse fixture");
    let frozen_job: Ed25519YaoLaneJobV1 =
        serde_json::from_value(fixture["job"].clone()).expect("parse job");
    let frozen_receipt: Ed25519YaoLaneProtocolCommittedV1 =
        serde_json::from_value(fixture["protocolCommitReceipt"].clone()).expect("parse receipt");

    assert_eq!(
        frozen_job.source.lane_share_epoch,
        frozen_job.target_lane_share_epoch()
    );
    assert_ne!(frozen_job.source.lane_id, frozen_job.target_lane_id());
    assert_eq!(
        fixture["jobSubstitutions"],
        serde_json::to_value(job_substitutions(&frozen_job)).expect("serialize substitutions")
    );
    assert_eq!(
        fixture["receiptSubstitutionDigestsB64u"],
        serde_json::to_value(receipt_substitutions(&frozen_receipt))
            .expect("serialize receipt substitutions")
    );
    assert_ne!(
        fixture["tamperedBindings"]["jobTranscriptDigestB64u"],
        fixture["jobTranscriptDigestB64u"]
    );
    assert_ne!(
        fixture["tamperedBindings"]["sessionDigestB64u"],
        fixture["sessionDigestB64u"]
    );
}
