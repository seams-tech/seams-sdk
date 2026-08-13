//! Rust half of the Refactor 102 ECDSA transcript wire contract.
//!
//! The committed fixture is generated only from production protocol records
//! and their canonical encoders. TypeScript consumes the same fixture through
//! its production parser and encoders.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use base64ct::{Base64UrlUnpadded, Encoding};
use router_ab_ecdsa_client_protocol::{
    complete_ecdsa_additive_lane_server_round_v1, prepare_ecdsa_additive_lane_holder_round_v1,
    verify_ecdsa_additive_lane_transcript_v1, ActiveEcdsaLaneProtocolSourceV1,
    EcdsaAdditiveLaneHolderRoundV1, EcdsaAdditiveLaneJobV1, EcdsaAdditiveLaneServerRoundV1,
    EcdsaAdditiveLaneTranscriptV1, EcdsaLaneAuthorizationBindingV1, EcdsaLaneChainTargetV1,
    EcdsaLaneSourceKindV1, EcdsaLaneTargetHolderV1, EcdsaLaneTargetOperationV1,
    EcdsaLaneTargetSigningWorkerV1, EcdsaMaterialActivationRefKindV1, EcdsaMaterialActivationRefV1,
    EcdsaSourceCapabilityBindingV1, EcdsaTargetCapabilityBindingV1,
    EcdsaTargetThresholdSessionBindingV1, OwnerLaneParticipantContinuityV1,
};
use serde_json::{json, Value};

const UPDATE_ENV: &str = "UPDATE_R102_ECDSA_WIRE_FIXTURES";
const FIXTURE_VERSION: &str = "r102_ecdsa_wire_vectors_v1";

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join("protocol")
        .join("r102")
        .join("ecdsa-wire-vectors-v1.json")
}

fn b64(bytes: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(bytes)
}

fn digest(value: u8) -> String {
    b64(&[value; 32])
}

fn compressed_generator() -> String {
    b64(
        &hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
            .expect("compressed secp256k1 generator"),
    )
}

fn activation(id: &str) -> EcdsaMaterialActivationRefV1 {
    EcdsaMaterialActivationRefV1 {
        kind: EcdsaMaterialActivationRefKindV1::MpcMaterialActivationRef,
        activation_id: id.to_owned(),
        capability: "ecdsa-capability:wallet-key-A".to_owned(),
        material_owner: "wallet-A".to_owned(),
        key_binding: "evm-family-key:A".to_owned(),
        lifecycle_binding: "lifecycle:A".to_owned(),
        signing_worker: "signing-worker:source".to_owned(),
    }
}

fn job() -> EcdsaAdditiveLaneJobV1 {
    EcdsaAdditiveLaneJobV1 {
        kind: "ecdsa_additive_lane_job_v1".to_owned(),
        operation_id: "lane-operation:A".to_owned(),
        enrollment_id: "lane-enrollment:A".to_owned(),
        idempotency_key: "lane-idempotency:A".to_owned(),
        wallet_id: "wallet-A".to_owned(),
        wallet_key_id: "wallet-key:evm-family:A".to_owned(),
        source: ActiveEcdsaLaneProtocolSourceV1 {
            lane_id: "owner-lane:A".to_owned(),
            lane_kind: "owner_passkey".to_owned(),
            lane_share_epoch: "opaque/source-epoch:A".to_owned(),
            revocation_epoch: 7,
            source_kind: EcdsaLaneSourceKindV1::OwnerRegistration {
                owner_participant_continuity: OwnerLaneParticipantContinuityV1 {
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
        target_holder: EcdsaLaneTargetHolderV1 {
            participant_id: "holder:linked-device".to_owned(),
            participant_binding_digest_b64u: digest(2),
            custody_binding_id: "custody-binding:linked-device".to_owned(),
            custody_binding_digest_b64u: digest(3),
            hpke_public_key_b64u: digest(4),
            hpke_public_key_digest_b64u: digest(5),
        },
        target_signing_worker: EcdsaLaneTargetSigningWorkerV1 {
            participant_id: "signing-worker:target".to_owned(),
            participant_binding_digest_b64u: digest(6),
            recipient_key_id: "recipient-key:target".to_owned(),
            hpke_public_key_b64u: digest(7),
            hpke_public_key_digest_b64u: digest(8),
        },
        target_material_activation_id: "activation:target".to_owned(),
        protocol_version: "rotatable_signing_lane_protocol_v1".to_owned(),
        expires_at_ms: 1_900_000_000_123,
        target: EcdsaLaneTargetOperationV1::CreateLane {
            lane_id: "linked-device-lane:A".to_owned(),
            lane_kind: "linked_device".to_owned(),
            lane_share_epoch: "opaque/source-epoch:A".to_owned(),
            expected_target_state: "absent".to_owned(),
        },
        authorization: EcdsaLaneAuthorizationBindingV1::LinkedDeviceEnrollment {
            authorized_operation_id: "authorized-operation:A".to_owned(),
            linked_device_enrollment_id: "linked-device-enrollment:A".to_owned(),
            linked_device_permission_digest_b64u: digest(9),
        },
        key_family: "ecdsa_secp256k1".to_owned(),
        evm_family_signing_key_slot_id: "wallet-key:evm-family:wallet-A:signing-root-A:version-1"
            .to_owned(),
        threshold_public_key33_b64u: compressed_generator(),
        evm_address: "0x00000000000000000000000000000000000000a1".to_owned(),
        source_capability: EcdsaSourceCapabilityBindingV1 {
            manifest_id: "ecdsa-manifest:source".to_owned(),
            manifest_revision: 4,
            server_generation: "server-generation:4".to_owned(),
            ecdsa_threshold_key_id: "ecdsa-threshold-key:A".to_owned(),
            relayer_key_id: "ecdsa-relayer-key:A".to_owned(),
        },
        target_capability: EcdsaTargetCapabilityBindingV1 {
            manifest_id: "ecdsa-manifest:target".to_owned(),
            manifest_revision: 5,
            ecdsa_threshold_key_id: "ecdsa-threshold-key:A".to_owned(),
            ordered_threshold_sessions: vec![
                EcdsaTargetThresholdSessionBindingV1 {
                    chain_target: EcdsaLaneChainTargetV1::Evm {
                        namespace: "eip155".to_owned(),
                        chain_id: 1,
                        network_slug: "ethereum-mainnet".to_owned(),
                    },
                    threshold_session_id: "threshold-session:ethereum".to_owned(),
                    participant_binding_digest_b64u: digest(10),
                },
                EcdsaTargetThresholdSessionBindingV1 {
                    chain_target: EcdsaLaneChainTargetV1::Tempo {
                        chain_id: 4217,
                        network_slug: "tempo-mainnet".to_owned(),
                    },
                    threshold_session_id: "threshold-session:tempo".to_owned(),
                    participant_binding_digest_b64u: digest(11),
                },
            ],
        },
        source_holder_verifying_share33_b64u: compressed_generator(),
        source_server_verifying_share33_b64u: compressed_generator(),
        reshare_channel_binding_digest_b64u: digest(12),
        transcript_encoding: "ecdsa_additive_lane_transcript_v1".to_owned(),
    }
}

fn rounds() -> (
    EcdsaAdditiveLaneJobV1,
    EcdsaAdditiveLaneHolderRoundV1,
    EcdsaAdditiveLaneServerRoundV1,
    EcdsaAdditiveLaneTranscriptV1,
) {
    let job = job();
    let holder = prepare_ecdsa_additive_lane_holder_round_v1(
        &job,
        compressed_generator(),
        digest(13),
        digest(14),
        b64(&[15; 16]),
        1_800_000_000_111,
    )
    .expect("holder round");
    let server = complete_ecdsa_additive_lane_server_round_v1(
        &job,
        &holder,
        compressed_generator(),
        digest(16),
        digest(17),
        digest(18),
        b64(&[19; 16]),
        1_800_000_000_222,
    )
    .expect("server round");
    let transcript = EcdsaAdditiveLaneTranscriptV1 {
        kind: "ecdsa_additive_lane_transcript_v1".to_owned(),
        preamble_hash_b64u: b64(&job.preamble_hash().expect("preamble hash")),
        holder_round_hash_b64u: b64(&holder.hash().expect("holder hash")),
        server_round_hash_b64u: b64(&server.hash().expect("server hash")),
    };
    verify_ecdsa_additive_lane_transcript_v1(&job, &holder, &server, &transcript)
        .expect("linked transcript");
    (job, holder, server, transcript)
}

fn substitutions(job: &EcdsaAdditiveLaneJobV1) -> BTreeMap<String, String> {
    let mut changed = BTreeMap::new();
    let mut record = |name: &str, candidate: EcdsaAdditiveLaneJobV1| {
        candidate.validate().expect("valid substituted job");
        let hash = candidate.preamble_hash().expect("substituted hash");
        assert_ne!(hash, job.preamble_hash().expect("baseline hash"));
        changed.insert(name.to_owned(), b64(&hash));
    };

    let mut candidate = job.clone();
    candidate.source.lane_share_epoch = "opaque/source-epoch:B".to_owned();
    record("sourceLaneShareEpoch", candidate);

    let mut candidate = job.clone();
    if let EcdsaLaneTargetOperationV1::CreateLane {
        lane_share_epoch, ..
    } = &mut candidate.target
    {
        *lane_share_epoch = "opaque/target-epoch:Y".to_owned();
    }
    record("targetLaneShareEpoch", candidate);

    let mut candidate = job.clone();
    candidate.target_holder.participant_id = "holder:substituted".to_owned();
    record("holderParticipant", candidate);

    let mut candidate = job.clone();
    candidate.target_holder.participant_binding_digest_b64u = digest(20);
    record("holderParticipantBinding", candidate);

    let mut candidate = job.clone();
    candidate.target_holder.custody_binding_id = "custody-binding:substituted".to_owned();
    record("custodyBindingId", candidate);

    let mut candidate = job.clone();
    candidate.target_holder.custody_binding_digest_b64u = digest(21);
    record("custodyBindingDigest", candidate);

    let mut candidate = job.clone();
    candidate.target_holder.hpke_public_key_b64u = digest(22);
    record("holderRecipientKey", candidate);

    let mut candidate = job.clone();
    candidate.target_holder.hpke_public_key_digest_b64u = digest(23);
    record("holderRecipientKeyDigest", candidate);

    let mut candidate = job.clone();
    candidate.target_signing_worker.participant_id = "signing-worker:substituted".to_owned();
    record("workerParticipant", candidate);

    let mut candidate = job.clone();
    candidate
        .target_signing_worker
        .participant_binding_digest_b64u = digest(24);
    record("workerParticipantBinding", candidate);

    let mut candidate = job.clone();
    candidate.target_signing_worker.recipient_key_id = "recipient-key:substituted".to_owned();
    record("workerRecipientKeyId", candidate);

    let mut candidate = job.clone();
    candidate.target_signing_worker.hpke_public_key_b64u = digest(25);
    record("workerRecipientKey", candidate);

    let mut candidate = job.clone();
    candidate.target_signing_worker.hpke_public_key_digest_b64u = digest(26);
    record("workerRecipientKeyDigest", candidate);

    let mut candidate = job.clone();
    if let EcdsaLaneAuthorizationBindingV1::LinkedDeviceEnrollment {
        linked_device_permission_digest_b64u,
        ..
    } = &mut candidate.authorization
    {
        *linked_device_permission_digest_b64u = digest(27);
    }
    record("authorizationDigest", candidate);

    let mut candidate = job.clone();
    candidate
        .target_capability
        .ordered_threshold_sessions
        .reverse();
    record("thresholdSessionOrder", candidate);

    changed
}

fn generated_fixture() -> Value {
    let (job, holder, server, transcript) = rounds();
    let mut tampered_server = server.clone();
    tampered_server.holder_round_hash_b64u = digest(31);
    json!({
        "fixtureVersion": FIXTURE_VERSION,
        "job": job,
        "canonicalPreambleB64u": b64(&job.canonical_preamble_bytes().expect("preamble bytes")),
        "preambleHashB64u": b64(&job.preamble_hash().expect("preamble hash")),
        "holderRound": holder,
        "canonicalHolderRoundB64u": b64(&holder.canonical_bytes().expect("holder bytes")),
        "holderRoundHashB64u": b64(&holder.hash().expect("holder hash")),
        "serverRound": server,
        "canonicalServerRoundB64u": b64(&server.canonical_bytes().expect("server bytes")),
        "serverRoundHashB64u": b64(&server.hash().expect("server hash")),
        "tamperedServerRound": tampered_server,
        "tamperedServerRoundHashB64u": b64(&tampered_server.hash().expect("tampered server hash")),
        "transcript": transcript,
        "canonicalTranscriptB64u": b64(&transcript.canonical_bytes().expect("transcript bytes")),
        "transcriptHashB64u": b64(&transcript.hash().expect("transcript hash")),
        "substitutionPreambleHashesB64u": substitutions(&job),
    })
}

fn generated_fixture_json() -> String {
    let mut json = serde_json::to_string_pretty(&generated_fixture()).expect("serialize fixture");
    json.push('\n');
    json
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
fn committed_r102_ecdsa_wire_fixture_matches_production_encoders() {
    let path = fixture_path();
    let generated = generated_fixture_json();
    update_fixture_if_requested();
    let committed = fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!(
            "read {}: {error}; regenerate with {UPDATE_ENV}=1 cargo test -p router-ab-core --test r102_ecdsa_wire_vectors",
            path.display()
        )
    });
    assert_eq!(committed, generated, "regenerate with {UPDATE_ENV}=1");
}

#[test]
fn frozen_fixture_rounds_and_tamper_hashes_revalidate() {
    update_fixture_if_requested();
    let fixture: Value =
        serde_json::from_str(&fs::read_to_string(fixture_path()).expect("read fixture"))
            .expect("parse fixture");
    let frozen_job: EcdsaAdditiveLaneJobV1 =
        serde_json::from_value(fixture["job"].clone()).expect("parse production job");
    let frozen_holder: EcdsaAdditiveLaneHolderRoundV1 =
        serde_json::from_value(fixture["holderRound"].clone()).expect("parse holder round");
    let frozen_server: EcdsaAdditiveLaneServerRoundV1 =
        serde_json::from_value(fixture["serverRound"].clone()).expect("parse server round");
    let tampered_server: EcdsaAdditiveLaneServerRoundV1 =
        serde_json::from_value(fixture["tamperedServerRound"].clone())
            .expect("parse tampered server round");
    let frozen_transcript: EcdsaAdditiveLaneTranscriptV1 =
        serde_json::from_value(fixture["transcript"].clone()).expect("parse transcript");
    verify_ecdsa_additive_lane_transcript_v1(
        &frozen_job,
        &frozen_holder,
        &frozen_server,
        &frozen_transcript,
    )
    .expect("frozen transcript revalidates");
    assert_eq!(
        fixture["tamperedServerRoundHashB64u"],
        Value::String(b64(&tampered_server.hash().expect("tampered server hash")))
    );
    assert!(verify_ecdsa_additive_lane_transcript_v1(
        &frozen_job,
        &frozen_holder,
        &tampered_server,
        &frozen_transcript,
    )
    .is_err());
    assert_eq!(
        fixture["substitutionPreambleHashesB64u"],
        serde_json::to_value(substitutions(&frozen_job)).expect("serialize substitutions")
    );
}
