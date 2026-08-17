use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use router_ab_cloudflare::{
    apply_cloudflare_signing_worker_lane_material_command_v1,
    project_cloudflare_signing_worker_lane_material_effect_v1,
    CloudflareSigningWorkerLaneArtifactKindV1, CloudflareSigningWorkerLaneArtifactV1,
    CloudflareSigningWorkerLaneCommittedArtifactsV1, CloudflareSigningWorkerLaneHolderDeliveryV1,
    CloudflareSigningWorkerLaneKeyFamilyV1, CloudflareSigningWorkerLaneMaterialCommandV1,
    CloudflareSigningWorkerLaneMaterialIdentityV1, CloudflareSigningWorkerLaneMaterialLifecycleV1,
    CloudflareSigningWorkerLaneRetirementReasonV1, CloudflareSigningWorkerLaneRetirementV1,
    CloudflareSigningWorkerLaneServerActivationV1,
    CloudflareSigningWorkerNormalSigningLaneMaterialLookupV1,
};
use router_ab_core::RouterAbProtocolErrorCode;

fn digest(byte: u8) -> String {
    URL_SAFE_NO_PAD.encode([byte; 32])
}

fn artifact(
    kind: CloudflareSigningWorkerLaneArtifactKindV1,
    label: &'static str,
) -> CloudflareSigningWorkerLaneArtifactV1 {
    CloudflareSigningWorkerLaneArtifactV1::from_bytes(kind, label.as_bytes()).unwrap()
}

fn identity() -> CloudflareSigningWorkerLaneMaterialIdentityV1 {
    CloudflareSigningWorkerLaneMaterialIdentityV1 {
        operation_id: "lane-op-1".to_owned(),
        enrollment_id: "enrollment-1".to_owned(),
        wallet_id: "wallet-1".to_owned(),
        wallet_key_id: "wallet-key-1".to_owned(),
        target_lane_id: "linked-device-1".to_owned(),
        target_lane_share_epoch: "epoch-1".to_owned(),
        target_material_activation_id: "activation-1".to_owned(),
        key_family: CloudflareSigningWorkerLaneKeyFamilyV1::EcdsaSecp256k1,
        holder_participant_binding_digest_b64u: digest(1),
        signing_worker_participant_binding_digest_b64u: digest(2),
        holder_recipient_key_digest_b64u: digest(3),
        server_recipient_key_digest_b64u: digest(4),
        transcript_hash_b64u: digest(5),
        protocol_commit_receipt_digest_b64u: digest(6),
    }
}

fn committed_artifacts() -> CloudflareSigningWorkerLaneCommittedArtifactsV1 {
    CloudflareSigningWorkerLaneCommittedArtifactsV1::EcdsaAdditive {
        holder_package: artifact(
            CloudflareSigningWorkerLaneArtifactKindV1::HolderPackage,
            "holder package",
        ),
        signing_worker_package: artifact(
            CloudflareSigningWorkerLaneArtifactKindV1::SigningWorkerPackage,
            "worker package",
        ),
        protocol_commit_receipt: artifact(
            CloudflareSigningWorkerLaneArtifactKindV1::ProtocolCommitReceipt,
            "protocol receipt",
        ),
        transcript: artifact(
            CloudflareSigningWorkerLaneArtifactKindV1::Transcript,
            "transcript",
        ),
    }
}

fn commit_command() -> CloudflareSigningWorkerLaneMaterialCommandV1 {
    CloudflareSigningWorkerLaneMaterialCommandV1::Commit {
        identity: identity(),
        committed_artifacts: committed_artifacts(),
        committed_at_ms: 1_000,
    }
}

fn holder_delivery() -> CloudflareSigningWorkerLaneHolderDeliveryV1 {
    CloudflareSigningWorkerLaneHolderDeliveryV1 {
        receipt: artifact(
            CloudflareSigningWorkerLaneArtifactKindV1::HolderDeliveryReceipt,
            "holder delivery receipt",
        ),
        acknowledged_at_ms: 1_100,
    }
}

fn activation() -> CloudflareSigningWorkerLaneServerActivationV1 {
    CloudflareSigningWorkerLaneServerActivationV1 {
        active_server_material: artifact(
            CloudflareSigningWorkerLaneArtifactKindV1::ActiveServerMaterial,
            "private active server material",
        ),
        receipt: artifact(
            CloudflareSigningWorkerLaneArtifactKindV1::ServerActivationReceipt,
            "server activation receipt",
        ),
        activated_at_ms: 1_200,
    }
}

fn retirement() -> CloudflareSigningWorkerLaneRetirementV1 {
    CloudflareSigningWorkerLaneRetirementV1 {
        revocation_epoch: 2,
        reason: CloudflareSigningWorkerLaneRetirementReasonV1::LaneRevoked,
        correlation_id: "retirement-1".to_owned(),
        request_digest_b64u: digest(9),
        receipt: artifact(
            CloudflareSigningWorkerLaneArtifactKindV1::RetirementReceipt,
            "retirement receipt",
        ),
        retired_at_ms: 1_300,
    }
}

#[test]
fn exact_commit_replays_after_lifecycle_progress() {
    let committed =
        apply_cloudflare_signing_worker_lane_material_command_v1(None, commit_command()).unwrap();
    assert!(committed.changed);
    let delivery = holder_delivery();
    let delivered = apply_cloudflare_signing_worker_lane_material_command_v1(
        Some(committed.record),
        CloudflareSigningWorkerLaneMaterialCommandV1::RecordHolderDelivery {
            identity: identity(),
            holder_delivery: delivery,
        },
    )
    .unwrap();
    let replayed = apply_cloudflare_signing_worker_lane_material_command_v1(
        Some(delivered.record),
        commit_command(),
    )
    .unwrap();
    assert!(!replayed.changed);
    assert!(matches!(
        replayed.record.lifecycle,
        CloudflareSigningWorkerLaneMaterialLifecycleV1::AwaitingServerActivation { .. }
    ));
}

#[test]
fn holder_delivery_fences_activation_and_substitution() {
    let committed =
        apply_cloudflare_signing_worker_lane_material_command_v1(None, commit_command()).unwrap();
    let early = apply_cloudflare_signing_worker_lane_material_command_v1(
        Some(committed.record.clone()),
        CloudflareSigningWorkerLaneMaterialCommandV1::ActivateServerMaterial {
            identity: identity(),
            expected_holder_delivery_receipt: holder_delivery().receipt,
            server_activation: activation(),
        },
    )
    .unwrap_err();
    assert_eq!(early.code(), RouterAbProtocolErrorCode::ConflictingPair);

    let delivered = apply_cloudflare_signing_worker_lane_material_command_v1(
        Some(committed.record),
        CloudflareSigningWorkerLaneMaterialCommandV1::RecordHolderDelivery {
            identity: identity(),
            holder_delivery: holder_delivery(),
        },
    )
    .unwrap();
    let substituted = apply_cloudflare_signing_worker_lane_material_command_v1(
        Some(delivered.record),
        CloudflareSigningWorkerLaneMaterialCommandV1::ActivateServerMaterial {
            identity: identity(),
            expected_holder_delivery_receipt: artifact(
                CloudflareSigningWorkerLaneArtifactKindV1::HolderDeliveryReceipt,
                "substituted receipt",
            ),
            server_activation: activation(),
        },
    )
    .unwrap_err();
    assert_eq!(
        substituted.code(),
        RouterAbProtocolErrorCode::ReplayedLocalRequest
    );
}

#[test]
fn activation_and_retirement_are_exactly_replayable() {
    let committed =
        apply_cloudflare_signing_worker_lane_material_command_v1(None, commit_command()).unwrap();
    let delivery = holder_delivery();
    let delivered = apply_cloudflare_signing_worker_lane_material_command_v1(
        Some(committed.record),
        CloudflareSigningWorkerLaneMaterialCommandV1::RecordHolderDelivery {
            identity: identity(),
            holder_delivery: delivery.clone(),
        },
    )
    .unwrap();
    let activate = CloudflareSigningWorkerLaneMaterialCommandV1::ActivateServerMaterial {
        identity: identity(),
        expected_holder_delivery_receipt: delivery.receipt,
        server_activation: activation(),
    };
    let active = apply_cloudflare_signing_worker_lane_material_command_v1(
        Some(delivered.record),
        activate.clone(),
    )
    .unwrap();
    assert!(active.changed);
    let activation_replay = apply_cloudflare_signing_worker_lane_material_command_v1(
        Some(active.record),
        activate.clone(),
    )
    .unwrap();
    assert!(!activation_replay.changed);

    let retire = CloudflareSigningWorkerLaneMaterialCommandV1::Retire {
        identity: identity(),
        retirement: retirement(),
    };
    let retired = apply_cloudflare_signing_worker_lane_material_command_v1(
        Some(activation_replay.record),
        retire.clone(),
    )
    .unwrap();
    assert!(retired.changed);
    let retirement_replay =
        apply_cloudflare_signing_worker_lane_material_command_v1(Some(retired.record), retire)
            .unwrap();
    assert!(!retirement_replay.changed);
    let activation_after_retirement = apply_cloudflare_signing_worker_lane_material_command_v1(
        Some(retirement_replay.record),
        activate,
    )
    .unwrap();
    assert!(!activation_after_retirement.changed);
}

#[test]
fn same_operation_rejects_different_identity_or_commitment() {
    let committed =
        apply_cloudflare_signing_worker_lane_material_command_v1(None, commit_command()).unwrap();
    let mut changed_identity = identity();
    changed_identity.target_material_activation_id = "activation-2".to_owned();
    let identity_error = apply_cloudflare_signing_worker_lane_material_command_v1(
        Some(committed.record.clone()),
        CloudflareSigningWorkerLaneMaterialCommandV1::Commit {
            identity: changed_identity,
            committed_artifacts: committed_artifacts(),
            committed_at_ms: 1_000,
        },
    )
    .unwrap_err();
    assert_eq!(
        identity_error.code(),
        RouterAbProtocolErrorCode::ReplayedLocalRequest
    );

    let commitment_error = apply_cloudflare_signing_worker_lane_material_command_v1(
        Some(committed.record),
        CloudflareSigningWorkerLaneMaterialCommandV1::Commit {
            identity: identity(),
            committed_artifacts: CloudflareSigningWorkerLaneCommittedArtifactsV1::EcdsaAdditive {
                holder_package: artifact(
                    CloudflareSigningWorkerLaneArtifactKindV1::HolderPackage,
                    "different holder package",
                ),
                signing_worker_package: artifact(
                    CloudflareSigningWorkerLaneArtifactKindV1::SigningWorkerPackage,
                    "worker package",
                ),
                protocol_commit_receipt: artifact(
                    CloudflareSigningWorkerLaneArtifactKindV1::ProtocolCommitReceipt,
                    "protocol receipt",
                ),
                transcript: artifact(
                    CloudflareSigningWorkerLaneArtifactKindV1::Transcript,
                    "transcript",
                ),
            },
            committed_at_ms: 1_000,
        },
    )
    .unwrap_err();
    assert_eq!(
        commitment_error.code(),
        RouterAbProtocolErrorCode::ReplayedLocalRequest
    );
}

#[test]
fn retirement_before_delivery_is_terminal() {
    let committed =
        apply_cloudflare_signing_worker_lane_material_command_v1(None, commit_command()).unwrap();
    let retired = apply_cloudflare_signing_worker_lane_material_command_v1(
        Some(committed.record),
        CloudflareSigningWorkerLaneMaterialCommandV1::Retire {
            identity: identity(),
            retirement: retirement(),
        },
    )
    .unwrap();
    let delivery_error = apply_cloudflare_signing_worker_lane_material_command_v1(
        Some(retired.record),
        CloudflareSigningWorkerLaneMaterialCommandV1::RecordHolderDelivery {
            identity: identity(),
            holder_delivery: holder_delivery(),
        },
    )
    .unwrap_err();
    assert_eq!(
        delivery_error.code(),
        RouterAbProtocolErrorCode::ConflictingPair
    );
}

#[test]
fn artifact_digest_tampering_is_rejected() {
    let mut tampered = artifact(
        CloudflareSigningWorkerLaneArtifactKindV1::Transcript,
        "transcript",
    );
    tampered.storage_digest_b64u = digest(42);
    let error = tampered
        .validate_kind(CloudflareSigningWorkerLaneArtifactKindV1::Transcript)
        .unwrap_err();
    assert_eq!(
        error.code(),
        RouterAbProtocolErrorCode::MalformedWirePayload
    );
}

#[test]
fn transport_projection_never_contains_active_server_material() {
    let committed =
        apply_cloudflare_signing_worker_lane_material_command_v1(None, commit_command()).unwrap();
    let delivery = holder_delivery();
    let delivered = apply_cloudflare_signing_worker_lane_material_command_v1(
        Some(committed.record),
        CloudflareSigningWorkerLaneMaterialCommandV1::RecordHolderDelivery {
            identity: identity(),
            holder_delivery: delivery.clone(),
        },
    )
    .unwrap();
    let command = CloudflareSigningWorkerLaneMaterialCommandV1::ActivateServerMaterial {
        identity: identity(),
        expected_holder_delivery_receipt: delivery.receipt,
        server_activation: activation(),
    };
    let active = apply_cloudflare_signing_worker_lane_material_command_v1(
        Some(delivered.record),
        command.clone(),
    )
    .unwrap();
    let effect =
        project_cloudflare_signing_worker_lane_material_effect_v1(&active, &command).unwrap();
    let encoded = serde_json::to_string(&effect).unwrap();
    assert!(!encoded.contains("private active server material"));
    assert!(!encoded.contains("activeServerMaterial"));
}

#[test]
fn retirement_fences_holder_redelivery_and_active_material() {
    let committed =
        apply_cloudflare_signing_worker_lane_material_command_v1(None, commit_command()).unwrap();
    assert!(committed.record.holder_redelivery().is_ok());
    assert_eq!(
        committed
            .record
            .active_server_material()
            .unwrap_err()
            .code(),
        RouterAbProtocolErrorCode::MissingLocalBinding
    );
    let retired = apply_cloudflare_signing_worker_lane_material_command_v1(
        Some(committed.record),
        CloudflareSigningWorkerLaneMaterialCommandV1::Retire {
            identity: identity(),
            retirement: retirement(),
        },
    )
    .unwrap();
    assert_eq!(
        retired.record.holder_redelivery().unwrap_err().code(),
        RouterAbProtocolErrorCode::MissingLocalBinding
    );
    assert_eq!(
        retired.record.active_server_material().unwrap_err().code(),
        RouterAbProtocolErrorCode::MissingLocalBinding
    );
}

#[test]
fn normal_signing_lookup_requires_the_exact_lane_identity_digest() {
    let exact_identity = identity();
    let exact = CloudflareSigningWorkerNormalSigningLaneMaterialLookupV1 {
        admitted_lane_identity_digest_b64u: exact_identity.digest_b64u().unwrap(),
        identity: exact_identity.clone(),
    };
    exact.validate().unwrap();

    let substituted = CloudflareSigningWorkerNormalSigningLaneMaterialLookupV1 {
        admitted_lane_identity_digest_b64u: digest(77),
        identity: exact_identity,
    };
    assert_eq!(
        substituted.validate().unwrap_err().code(),
        RouterAbProtocolErrorCode::ReplayedLocalRequest
    );
}
