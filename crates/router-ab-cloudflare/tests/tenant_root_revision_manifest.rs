use router_ab_cloudflare::{
    TenantRootDerivationProfileV1, TenantRootParticipantStorageRevisionV1,
    TenantRootProtocolVersionV1, TenantRootRevisionManifestV1,
    TenantRootRevisionParticipantInputV1, TenantRootRevisionParticipantRoleV1,
    TenantRootRevisionParticipantV1, TenantRootYaoArtifactDigestSetV1,
};

const GIT_COMMIT: &str = "1111111111111111111111111111111111111111";
const B4_B5_COMMIT: &str = "2222222222222222222222222222222222222222";

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn artifacts(seed: u8) -> TenantRootYaoArtifactDigestSetV1 {
    TenantRootYaoArtifactDigestSetV1::new(
        [seed; 32],
        [seed + 1; 32],
        [seed + 2; 32],
        [seed + 3; 32],
        [seed + 4; 32],
        [seed + 5; 32],
    )
    .expect("artifact digests")
}

fn participant(
    role: TenantRootRevisionParticipantRoleV1,
    release_id: &str,
    git_commit: &str,
    artifact_set: TenantRootYaoArtifactDigestSetV1,
) -> TenantRootRevisionParticipantV1 {
    participant_with_deployment(
        role,
        release_id,
        git_commit,
        artifact_set,
        &format!("seams-{}", role_name(role)),
        &format!("deployment-{}", role_name(role)),
    )
}

fn participant_with_deployment(
    role: TenantRootRevisionParticipantRoleV1,
    release_id: &str,
    git_commit: &str,
    artifact_set: TenantRootYaoArtifactDigestSetV1,
    deployed_script_identity: &str,
    deployment_id: &str,
) -> TenantRootRevisionParticipantV1 {
    participant_with_digests(
        role,
        release_id,
        git_commit,
        artifact_set,
        [0x31; 32],
        configuration_digest(role),
        deployed_script_identity,
        deployment_id,
        storage_for_role(role),
    )
    .expect("participant")
}

fn participant_with_digests(
    role: TenantRootRevisionParticipantRoleV1,
    release_id: &str,
    git_commit: &str,
    artifact_set: TenantRootYaoArtifactDigestSetV1,
    source_build_digest: [u8; 32],
    configuration_digest: [u8; 32],
    deployed_script_identity: &str,
    deployment_id: &str,
    storage: TenantRootParticipantStorageRevisionV1,
) -> Result<TenantRootRevisionParticipantV1, router_ab_core::RouterAbProtocolError> {
    TenantRootRevisionParticipantV1::new(TenantRootRevisionParticipantInputV1 {
        role,
        release_id: release_id.to_owned(),
        git_commit: git_commit.to_owned(),
        deployed_script_identity: deployed_script_identity.to_owned(),
        deployment_id: deployment_id.to_owned(),
        source_build_digest,
        configuration_digest,
        protocol_version: TenantRootProtocolVersionV1::R120V1,
        profile: TenantRootDerivationProfileV1::RoleTargetedThresholdPrfV1,
        yao_artifacts: artifact_set,
        storage,
    })
}

fn storage_for_role(
    role: TenantRootRevisionParticipantRoleV1,
) -> TenantRootParticipantStorageRevisionV1 {
    match role {
        TenantRootRevisionParticipantRoleV1::DeriverA
        | TenantRootRevisionParticipantRoleV1::DeriverB => {
            TenantRootParticipantStorageRevisionV1::RolePrivateD1 {
                migration_head: "0004_tenant_root_creation_admission".to_owned(),
            }
        }
        TenantRootRevisionParticipantRoleV1::WalletServer
        | TenantRootRevisionParticipantRoleV1::Router
        | TenantRootRevisionParticipantRoleV1::SigningWorker => {
            TenantRootParticipantStorageRevisionV1::Stateless
        }
    }
}

fn configuration_digest(role: TenantRootRevisionParticipantRoleV1) -> [u8; 32] {
    match role {
        TenantRootRevisionParticipantRoleV1::WalletServer => [0x32; 32],
        TenantRootRevisionParticipantRoleV1::Router => [0x33; 32],
        TenantRootRevisionParticipantRoleV1::DeriverA => [0x34; 32],
        TenantRootRevisionParticipantRoleV1::DeriverB => [0x35; 32],
        TenantRootRevisionParticipantRoleV1::SigningWorker => [0x36; 32],
    }
}

fn role_name(role: TenantRootRevisionParticipantRoleV1) -> &'static str {
    match role {
        TenantRootRevisionParticipantRoleV1::WalletServer => "wallet-server",
        TenantRootRevisionParticipantRoleV1::Router => "router",
        TenantRootRevisionParticipantRoleV1::DeriverA => "deriver-a",
        TenantRootRevisionParticipantRoleV1::DeriverB => "deriver-b",
        TenantRootRevisionParticipantRoleV1::SigningWorker => "signing-worker",
    }
}

fn manifest_with(
    wallet_server: TenantRootRevisionParticipantV1,
    router: TenantRootRevisionParticipantV1,
    deriver_a: TenantRootRevisionParticipantV1,
    deriver_b: TenantRootRevisionParticipantV1,
    signing_worker: TenantRootRevisionParticipantV1,
) -> Result<TenantRootRevisionManifestV1, router_ab_core::RouterAbProtocolError> {
    TenantRootRevisionManifestV1::new(
        B4_B5_COMMIT,
        [0x44; 32],
        wallet_server,
        router,
        deriver_a,
        deriver_b,
        signing_worker,
    )
}

fn participants(
    release_id: &str,
    artifact_set: TenantRootYaoArtifactDigestSetV1,
) -> [TenantRootRevisionParticipantV1; 5] {
    [
        participant(
            TenantRootRevisionParticipantRoleV1::WalletServer,
            release_id,
            GIT_COMMIT,
            artifact_set,
        ),
        participant(
            TenantRootRevisionParticipantRoleV1::Router,
            release_id,
            GIT_COMMIT,
            artifact_set,
        ),
        participant(
            TenantRootRevisionParticipantRoleV1::DeriverA,
            release_id,
            GIT_COMMIT,
            artifact_set,
        ),
        participant(
            TenantRootRevisionParticipantRoleV1::DeriverB,
            release_id,
            GIT_COMMIT,
            artifact_set,
        ),
        participant(
            TenantRootRevisionParticipantRoleV1::SigningWorker,
            release_id,
            GIT_COMMIT,
            artifact_set,
        ),
    ]
}

#[test]
fn exact_revision_set_has_frozen_canonical_digest_and_round_trips() {
    let [wallet_server, router, deriver_a, deriver_b, signing_worker] =
        participants("release-120-1", artifacts(0x10));
    let manifest = manifest_with(wallet_server, router, deriver_a, deriver_b, signing_worker)
        .expect("manifest");
    assert_eq!(
        encode_hex(manifest.digest().expect("digest").as_bytes()),
        "e7629215ff381a0a0ff5d5e15b0352d75e5703b56a6ca7189f398ee1f34946d6"
    );
    let json = serde_json::to_string(&manifest).expect("json");
    let decoded: TenantRootRevisionManifestV1 = serde_json::from_str(&json).expect("decode");
    assert_eq!(decoded, manifest);
}

#[test]
fn mixed_release_commit_profile_or_artifacts_fail_closed() {
    let common = artifacts(0x10);

    let [wallet_server, router, deriver_a, deriver_b, _] = participants("release-120-1", common);
    let mixed_release = participant(
        TenantRootRevisionParticipantRoleV1::SigningWorker,
        "release-120-2",
        GIT_COMMIT,
        common,
    );
    assert!(manifest_with(wallet_server, router, deriver_a, deriver_b, mixed_release).is_err());

    let [wallet_server, router, deriver_a, deriver_b, _] = participants("release-120-1", common);
    let mixed_commit = participant(
        TenantRootRevisionParticipantRoleV1::SigningWorker,
        "release-120-1",
        "3333333333333333333333333333333333333333",
        common,
    );
    assert!(manifest_with(wallet_server, router, deriver_a, deriver_b, mixed_commit).is_err());

    let [wallet_server, router, deriver_a, deriver_b, _] = participants("release-120-1", common);
    let mixed_artifacts = participant(
        TenantRootRevisionParticipantRoleV1::SigningWorker,
        "release-120-1",
        GIT_COMMIT,
        artifacts(0x20),
    );
    assert!(manifest_with(wallet_server, router, deriver_a, deriver_b, mixed_artifacts).is_err());

    // The production profile enum currently has one admitted variant. An
    // unsupported profile is therefore the wire-level mixed-profile negative.
    let [wallet_server, router, deriver_a, deriver_b, signing_worker] =
        participants("release-120-1", common);
    let manifest = manifest_with(wallet_server, router, deriver_a, deriver_b, signing_worker)
        .expect("manifest");
    let mut unsupported_profile = serde_json::to_value(manifest).expect("json");
    unsupported_profile["signingWorker"]["profile"] =
        serde_json::Value::String("legacy_profile_v0".to_owned());
    assert!(serde_json::from_value::<TenantRootRevisionManifestV1>(unsupported_profile).is_err());
}

#[test]
fn role_position_and_storage_shape_fail_closed() {
    let common = artifacts(0x10);
    let [wallet_server, router, deriver_a, deriver_b, signing_worker] =
        participants("release-120-1", common);
    assert!(manifest_with(router, wallet_server, deriver_a, deriver_b, signing_worker).is_err());

    assert!(
        TenantRootRevisionParticipantV1::new(TenantRootRevisionParticipantInputV1 {
            role: TenantRootRevisionParticipantRoleV1::DeriverA,
            release_id: "release-120-1".to_owned(),
            git_commit: GIT_COMMIT.to_owned(),
            deployed_script_identity: "seams-deriver-a".to_owned(),
            deployment_id: "deployment-deriver-a".to_owned(),
            source_build_digest: [0x31; 32],
            configuration_digest: [0x32; 32],
            protocol_version: TenantRootProtocolVersionV1::R120V1,
            profile: TenantRootDerivationProfileV1::RoleTargetedThresholdPrfV1,
            yao_artifacts: common,
            storage: TenantRootParticipantStorageRevisionV1::Stateless,
        })
        .is_err()
    );
}

#[test]
fn duplicate_or_missing_participant_roles_fail_closed() {
    let common = artifacts(0x10);
    let [wallet_server, router, deriver_a, deriver_b, signing_worker] =
        participants("release-120-1", common);
    assert!(manifest_with(
        wallet_server.clone(),
        router.clone(),
        deriver_a.clone(),
        router.clone(),
        signing_worker.clone(),
    )
    .is_err());

    let manifest = manifest_with(wallet_server, router, deriver_a, deriver_b, signing_worker)
        .expect("manifest");
    let mut duplicate_role = serde_json::to_value(&manifest).expect("json");
    duplicate_role["deriverB"]["role"] = serde_json::Value::String("router".to_owned());
    assert!(serde_json::from_value::<TenantRootRevisionManifestV1>(duplicate_role).is_err());

    let mut missing_role = serde_json::to_value(manifest).expect("json");
    assert!(missing_role
        .as_object_mut()
        .expect("manifest object")
        .remove("deriverB")
        .is_some());
    assert!(serde_json::from_value::<TenantRootRevisionManifestV1>(missing_role).is_err());
}

#[test]
fn duplicate_script_or_deployment_identity_fails_closed() {
    let common = artifacts(0x10);
    let [wallet_server, router, deriver_a, deriver_b, _] = participants("release-120-1", common);
    let duplicate_script = participant_with_deployment(
        TenantRootRevisionParticipantRoleV1::SigningWorker,
        "release-120-1",
        GIT_COMMIT,
        common,
        "seams-router",
        "deployment-signing-worker",
    );
    assert!(manifest_with(
        wallet_server,
        router,
        deriver_a,
        deriver_b,
        duplicate_script
    )
    .is_err());

    let [wallet_server, router, deriver_a, deriver_b, _] = participants("release-120-1", common);
    let duplicate_deployment = participant_with_deployment(
        TenantRootRevisionParticipantRoleV1::SigningWorker,
        "release-120-1",
        GIT_COMMIT,
        common,
        "seams-signing-worker",
        "deployment-router",
    );
    assert!(manifest_with(
        wallet_server,
        router,
        deriver_a,
        deriver_b,
        duplicate_deployment
    )
    .is_err());
}

#[test]
fn deriver_roles_require_distinct_private_configuration_digests() {
    let common = artifacts(0x10);
    let [wallet_server, router, deriver_a, _, signing_worker] =
        participants("release-120-1", common);
    let deriver_b = TenantRootRevisionParticipantV1::new(TenantRootRevisionParticipantInputV1 {
        role: TenantRootRevisionParticipantRoleV1::DeriverB,
        release_id: "release-120-1".to_owned(),
        git_commit: GIT_COMMIT.to_owned(),
        deployed_script_identity: "seams-deriver-b".to_owned(),
        deployment_id: "deployment-deriver-b".to_owned(),
        source_build_digest: [0x31; 32],
        configuration_digest: configuration_digest(TenantRootRevisionParticipantRoleV1::DeriverA),
        protocol_version: TenantRootProtocolVersionV1::R120V1,
        profile: TenantRootDerivationProfileV1::RoleTargetedThresholdPrfV1,
        yao_artifacts: common,
        storage: TenantRootParticipantStorageRevisionV1::RolePrivateD1 {
            migration_head: "0004_tenant_root_creation_admission".to_owned(),
        },
    })
    .expect("deriver B participant");
    assert!(manifest_with(wallet_server, router, deriver_a, deriver_b, signing_worker,).is_err());
}

#[test]
fn stale_deriver_migration_head_fails_closed() {
    let error = participant_with_digests(
        TenantRootRevisionParticipantRoleV1::DeriverA,
        "release-120-1",
        GIT_COMMIT,
        artifacts(0x10),
        [0x31; 32],
        [0x34; 32],
        "seams-deriver-a",
        "deployment-deriver-a",
        TenantRootParticipantStorageRevisionV1::RolePrivateD1 {
            migration_head: "0002_tenant_root_role_shares".to_owned(),
        },
    )
    .unwrap_err();
    assert_eq!(
        error.message(),
        "R120 Deriver migration head is unsupported"
    );
}

#[test]
fn source_and_configuration_digest_substitution_changes_manifest_digest() {
    let common = artifacts(0x10);
    let [wallet_server, router, deriver_a, deriver_b, signing_worker] =
        participants("release-120-1", common);
    let baseline = manifest_with(wallet_server, router, deriver_a, deriver_b, signing_worker)
        .expect("baseline manifest");

    let [wallet_server, router, deriver_a, deriver_b, _] = participants("release-120-1", common);
    let substituted_signing_worker = participant_with_digests(
        TenantRootRevisionParticipantRoleV1::SigningWorker,
        "release-120-1",
        GIT_COMMIT,
        common,
        [0x41; 32],
        [0x42; 32],
        "seams-signing-worker",
        "deployment-signing-worker",
        TenantRootParticipantStorageRevisionV1::Stateless,
    )
    .expect("substituted signing worker");
    let substituted = manifest_with(
        wallet_server,
        router,
        deriver_a,
        deriver_b,
        substituted_signing_worker,
    )
    .expect("substituted manifest");

    assert_ne!(
        baseline.digest().expect("baseline digest"),
        substituted.digest().expect("substituted digest")
    );
}

#[test]
fn noncanonical_commits_and_unknown_json_fields_fail_closed() {
    assert!(
        TenantRootRevisionParticipantV1::new(TenantRootRevisionParticipantInputV1 {
            role: TenantRootRevisionParticipantRoleV1::Router,
            release_id: "release-120-1".to_owned(),
            git_commit: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            deployed_script_identity: "seams-router".to_owned(),
            deployment_id: "deployment-router".to_owned(),
            source_build_digest: [0x31; 32],
            configuration_digest: [0x32; 32],
            protocol_version: TenantRootProtocolVersionV1::R120V1,
            profile: TenantRootDerivationProfileV1::RoleTargetedThresholdPrfV1,
            yao_artifacts: artifacts(0x10),
            storage: TenantRootParticipantStorageRevisionV1::Stateless,
        })
        .is_err()
    );

    let [wallet_server, router, deriver_a, deriver_b, signing_worker] =
        participants("release-120-1", artifacts(0x10));
    let manifest = manifest_with(wallet_server, router, deriver_a, deriver_b, signing_worker)
        .expect("manifest");
    let mut json = serde_json::to_value(manifest).expect("json");
    json.as_object_mut()
        .expect("object")
        .insert("unexpected".to_owned(), serde_json::Value::Bool(true));
    assert!(serde_json::from_value::<TenantRootRevisionManifestV1>(json).is_err());
}

#[test]
fn zero_evidence_digests_fail_closed() {
    assert!(TenantRootYaoArtifactDigestSetV1::new(
        [0; 32], [1; 32], [2; 32], [3; 32], [4; 32], [5; 32]
    )
    .is_err());

    let common = artifacts(0x10);
    assert!(
        TenantRootRevisionParticipantV1::new(TenantRootRevisionParticipantInputV1 {
            role: TenantRootRevisionParticipantRoleV1::Router,
            release_id: "release-120-1".to_owned(),
            git_commit: GIT_COMMIT.to_owned(),
            deployed_script_identity: "seams-router".to_owned(),
            deployment_id: "deployment-router".to_owned(),
            source_build_digest: [0; 32],
            configuration_digest: [0x32; 32],
            protocol_version: TenantRootProtocolVersionV1::R120V1,
            profile: TenantRootDerivationProfileV1::RoleTargetedThresholdPrfV1,
            yao_artifacts: common,
            storage: TenantRootParticipantStorageRevisionV1::Stateless,
        })
        .is_err()
    );
    assert!(
        TenantRootRevisionParticipantV1::new(TenantRootRevisionParticipantInputV1 {
            role: TenantRootRevisionParticipantRoleV1::Router,
            release_id: "release-120-1".to_owned(),
            git_commit: GIT_COMMIT.to_owned(),
            deployed_script_identity: "seams-router".to_owned(),
            deployment_id: "deployment-router".to_owned(),
            source_build_digest: [0x31; 32],
            configuration_digest: [0; 32],
            protocol_version: TenantRootProtocolVersionV1::R120V1,
            profile: TenantRootDerivationProfileV1::RoleTargetedThresholdPrfV1,
            yao_artifacts: common,
            storage: TenantRootParticipantStorageRevisionV1::Stateless,
        })
        .is_err()
    );

    let [wallet_server, router, deriver_a, deriver_b, signing_worker] =
        participants("release-120-1", common);
    assert!(TenantRootRevisionManifestV1::new(
        B4_B5_COMMIT,
        [0; 32],
        wallet_server,
        router,
        deriver_a,
        deriver_b,
        signing_worker,
    )
    .is_err());
}
