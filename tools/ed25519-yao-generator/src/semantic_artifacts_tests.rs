use crate::ceremony_context::{
    CeremonyAccountIdV1, CeremonyActivationEpochV1, CeremonyArtifactSuiteDigest32V1,
    CeremonyAuthorizationRecordDigest32V1, CeremonyAuthorizationV1, CeremonyChainTargetV1,
    CeremonyClientEphemeralPublicKey32V1, CeremonyCurrentDeriverAInputStateEpochV1,
    CeremonyCurrentDeriverBInputStateEpochV1, CeremonyDeriverABindingV1, CeremonyDeriverAIdV1,
    CeremonyDeriverAKeyEpochV1, CeremonyDeriverBBindingV1, CeremonyDeriverBIdV1,
    CeremonyDeriverBKeyEpochV1, CeremonyDeriverSetIdV1, CeremonyEnvironmentIdV1,
    CeremonyExportAuthorizationV1, CeremonyIdentityScopeV1, CeremonyInfrastructureV1,
    CeremonyNextDeriverAInputStateEpochV1, CeremonyNextDeriverBInputStateEpochV1,
    CeremonyOrganizationIdV1, CeremonyProjectIdV1, CeremonyPublicRequestContextV1,
    CeremonyRecoveryAuthorizationV1, CeremonyRefreshAuthorizationV1,
    CeremonyRegistrationAuthorizationV1, CeremonyRegistrationIntentDigest32V1,
    CeremonyReplacementCredentialBindingDigest32V1, CeremonyReplayNonce32V1,
    CeremonyRequestExpiryV1, CeremonyRequestIdV1, CeremonyRequestKindV1, CeremonyRootShareEpochV1,
    CeremonyRouterIdV1, CeremonySessionIdV1, CeremonySigningRootIdV1, CeremonySigningRootVersionV1,
    CeremonySigningWorkerBindingV1, CeremonySigningWorkerIdV1, CeremonySigningWorkerKeyEpochV1,
    CeremonyTranscriptNonce32V1, CeremonyTranscriptV1, CeremonyTransportBindingDigest32V1,
    CeremonyValidatedDagV1, CeremonyWalletIdV1,
};
use crate::kdf_fixtures::canonical_synthetic_kdf_material_v1;
use crate::provenance::{
    ActivationCircuitBindingV1, CeremonyProvenanceBindingV1, ClientEnvelopeArtifactDigest32V1,
    ClientEnvelopeSetDigest32V1, ClientInputArtifactDigest32V1, CombinedInputArtifactDigest32V1,
    ExportBranchV1, ExportCircuitBindingV1, ExportStatementCommonV1, ProvenanceRoleV1,
    RecoveryBranchV1, RecoveryContinuityArtifactDigest32V1, RecoveryStatementCommonV1,
    RefreshBranchV1, RefreshContinuityArtifactDigest32V1, RefreshStatementCommonV1,
    RegistrationAntiBiasArtifactDigest32V1, RegistrationBranchV1, RegistrationIntentDigest32V1,
    RegistrationStatementCommonV1, RoleInputProvenancePairV1, RoleInputProvenanceStatementV1,
    RoleInputSnapshotV1, RoleInputStateEpochV1, RoleInputStateRecordDigest32V1, RoleRootEpochV1,
    RoleRootRecordDigest32V1, RootBindingArtifactDigest32V1, ServerInputArtifactDigest32V1,
    StableKdfScopeV1,
};
use crate::semantic_artifacts::{
    CommittedActivationArtifactsV1, ExportSemanticArtifactContextV1, HostOnlyPackagedActivationV1,
    OneUseExecutionId32V1, OpaqueHostReferenceDeriverAReceiptEvidenceDigest32V1,
    OpaqueHostReferenceDeriverBReceiptEvidenceDigest32V1,
    OpaqueHostReferenceEvaluationEvidenceDigest32V1, OutputCommittedExportArtifactsV1,
    RecoveryActivationSemanticArtifactContextV1, RefreshActivationSemanticArtifactContextV1,
    RegistrationActivationSemanticArtifactContextV1, SemanticArtifactErrorV1,
    ACTIVATION_DERIVER_A_CLIENT_DESCRIPTOR_DOMAIN_V1,
    ACTIVATION_DERIVER_A_SIGNING_WORKER_DESCRIPTOR_DOMAIN_V1,
    ACTIVATION_DERIVER_B_CLIENT_DESCRIPTOR_DOMAIN_V1,
    ACTIVATION_DERIVER_B_SIGNING_WORKER_DESCRIPTOR_DOMAIN_V1,
    ACTIVATION_OUTPUT_COMMITTED_RECEIPT_DIGEST_DOMAIN_V1,
    ACTIVATION_OUTPUT_COMMITTED_RECEIPT_ENCODING_DOMAIN_V1,
    ACTIVATION_PACKAGE_SET_DIGEST_DOMAIN_V1, ACTIVATION_PACKAGE_SET_ENCODING_DOMAIN_V1,
    EXPORT_DERIVER_A_CLIENT_DESCRIPTOR_DOMAIN_V1, EXPORT_DERIVER_B_CLIENT_DESCRIPTOR_DOMAIN_V1,
    EXPORT_OUTPUT_COMMITTED_RECEIPT_DIGEST_DOMAIN_V1,
    EXPORT_OUTPUT_COMMITTED_RECEIPT_ENCODING_DOMAIN_V1, EXPORT_PACKAGE_SET_DIGEST_DOMAIN_V1,
    EXPORT_PACKAGE_SET_ENCODING_DOMAIN_V1,
};
use crate::semantic_fixture_material::{
    activation_bindings, activation_bindings_with_a_client, export_bindings, export_ideal_coin,
    export_inputs, recovery_ideal_coins, recovery_inputs, reference_fixture, refresh_ideal_coins,
    refresh_inputs, registration_ideal_coins, registration_inputs, ReferenceFixture,
};
use crate::{
    evaluate_host_only_export_output_sharing_v1, prepare_host_only_export_reference_v1,
    reconstruct_host_only_seed_export_v1, HostOnlyExportReferenceErrorV1,
    HostOnlyExportReferenceSuccessV1, HostOnlyRecoveryReferenceErrorV1,
    HostOnlyRecoveryReferenceInputsV1, RegisteredEd25519PublicKey32V1,
    SyntheticClientDerivationRootV1,
};
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use ed25519_yao::{CircuitDigest32, InputSchemaDigest32};
use sha2::{Digest, Sha256};

fn export_success(fixture: &ReferenceFixture) -> HostOnlyExportReferenceSuccessV1 {
    let prepared = prepare_host_only_export_reference_v1(
        export_inputs(fixture),
        &fixture.registered_public_key,
    )
    .expect("export key equality");
    evaluate_host_only_export_output_sharing_v1(prepared, export_ideal_coin())
}

fn request(kind: CeremonyRequestKindV1, suffix: &str) -> CeremonyPublicRequestContextV1 {
    CeremonyPublicRequestContextV1::new(
        kind,
        CeremonyRequestIdV1::parse(&format!("semantic-{suffix}")).expect("request id"),
        CeremonyReplayNonce32V1::new([0x11; 32]),
        CeremonyIdentityScopeV1::new(
            CeremonyAccountIdV1::parse("account").expect("account"),
            CeremonyWalletIdV1::parse("wallet").expect("wallet"),
            CeremonySessionIdV1::parse("session").expect("session"),
            CeremonyOrganizationIdV1::parse("organization").expect("organization"),
            CeremonyProjectIdV1::parse("project").expect("project"),
            CeremonyEnvironmentIdV1::parse("environment").expect("environment"),
            CeremonySigningRootIdV1::parse("project:environment").expect("root"),
            CeremonySigningRootVersionV1::new(1).expect("root version"),
            CeremonyChainTargetV1::parse("near:testnet").expect("chain"),
        ),
        CeremonyRootShareEpochV1::new(2).expect("root epoch"),
        CeremonyInfrastructureV1::new(
            CeremonyRouterIdV1::parse("router").expect("router"),
            CeremonyDeriverSetIdV1::parse("deriver-set").expect("deriver set"),
            CeremonyDeriverABindingV1::new(
                CeremonyDeriverAIdV1::parse("deriver-a").expect("A id"),
                CeremonyDeriverAKeyEpochV1::new(3).expect("A epoch"),
            ),
            CeremonyDeriverBBindingV1::new(
                CeremonyDeriverBIdV1::parse("deriver-b").expect("B id"),
                CeremonyDeriverBKeyEpochV1::new(4).expect("B epoch"),
            ),
            CeremonySigningWorkerBindingV1::new(
                CeremonySigningWorkerIdV1::parse("signing-worker").expect("worker id"),
                CeremonySigningWorkerKeyEpochV1::new(5).expect("worker epoch"),
            ),
        ),
        CeremonyClientEphemeralPublicKey32V1::new([0x22; 32]),
        CeremonyRequestExpiryV1::new(10_000).expect("expiry"),
    )
}

fn transcript(
    request: &CeremonyPublicRequestContextV1,
    authorization: &CeremonyAuthorizationV1,
) -> CeremonyTranscriptV1 {
    transcript_with_nonce(request, authorization, 0x31)
}

fn transcript_with_nonce(
    request: &CeremonyPublicRequestContextV1,
    authorization: &CeremonyAuthorizationV1,
    nonce: u8,
) -> CeremonyTranscriptV1 {
    CeremonyTranscriptV1::new(
        request,
        authorization,
        CeremonyTranscriptNonce32V1::new([nonce; 32]),
        CeremonyTransportBindingDigest32V1::new([0x41; 32]).expect("transport binding"),
        CeremonyArtifactSuiteDigest32V1::new([0x51; 32]).expect("artifact suite"),
    )
    .expect("ceremony DAG")
}

pub(crate) fn registration_ceremony(
    suffix: &str,
) -> (
    CeremonyPublicRequestContextV1,
    CeremonyRegistrationAuthorizationV1,
    CeremonyTranscriptV1,
) {
    let request = request(CeremonyRequestKindV1::Registration, suffix);
    let authorization = CeremonyRegistrationAuthorizationV1::new(
        &request,
        CeremonyAuthorizationRecordDigest32V1::new([0x61; 32]).expect("authorization record"),
        CeremonyRegistrationIntentDigest32V1::new([0x62; 32]).expect("registration intent"),
    )
    .expect("registration authorization");
    let transcript = transcript(&request, &authorization.into());
    (request, authorization, transcript)
}

pub(crate) fn recovery_ceremony() -> (
    CeremonyPublicRequestContextV1,
    CeremonyRecoveryAuthorizationV1,
    CeremonyTranscriptV1,
) {
    let request = request(CeremonyRequestKindV1::Recovery, "recovery");
    let authorization = CeremonyRecoveryAuthorizationV1::new(
        &request,
        CeremonyAuthorizationRecordDigest32V1::new([0x63; 32]).expect("authorization record"),
        CeremonyReplacementCredentialBindingDigest32V1::new([0x64; 32])
            .expect("replacement credential"),
    )
    .expect("recovery authorization");
    let transcript = transcript(&request, &authorization.into());
    (request, authorization, transcript)
}

pub(crate) fn refresh_ceremony() -> (
    CeremonyPublicRequestContextV1,
    CeremonyRefreshAuthorizationV1,
    CeremonyTranscriptV1,
) {
    let request = request(CeremonyRequestKindV1::Refresh, "refresh");
    let authorization = CeremonyRefreshAuthorizationV1::new(
        &request,
        CeremonyAuthorizationRecordDigest32V1::new([0x65; 32]).expect("authorization record"),
        CeremonyCurrentDeriverAInputStateEpochV1::new(11).expect("current A epoch"),
        CeremonyNextDeriverAInputStateEpochV1::new(12).expect("next A epoch"),
        CeremonyCurrentDeriverBInputStateEpochV1::new(41).expect("current B epoch"),
        CeremonyNextDeriverBInputStateEpochV1::new(43).expect("next B epoch"),
    )
    .expect("refresh authorization");
    let transcript = transcript(&request, &authorization.into());
    (request, authorization, transcript)
}

pub(crate) fn export_ceremony(
    registered_public_key: RegisteredEd25519PublicKey32V1,
) -> (
    CeremonyPublicRequestContextV1,
    CeremonyExportAuthorizationV1,
    CeremonyTranscriptV1,
) {
    let request = request(CeremonyRequestKindV1::Export, "export");
    let authorization = CeremonyExportAuthorizationV1::new(
        &request,
        CeremonyAuthorizationRecordDigest32V1::new([0x66; 32]).expect("authorization record"),
        registered_public_key,
    )
    .expect("export authorization");
    let transcript = transcript(&request, &authorization.into());
    (request, authorization, transcript)
}

pub(crate) fn validated_dag(
    request: &CeremonyPublicRequestContextV1,
    authorization: CeremonyAuthorizationV1,
    transcript: &CeremonyTranscriptV1,
) -> CeremonyValidatedDagV1 {
    CeremonyValidatedDagV1::from_components(request, &authorization, transcript)
        .expect("validated DAG")
}

fn snapshot<Role: ProvenanceRoleV1>(tag: u8, state_epoch: u64) -> RoleInputSnapshotV1<Role> {
    RoleInputSnapshotV1::from_synthetic_fixture(
        RoleRootRecordDigest32V1::from_synthetic_fixture_bytes([tag; 32]),
        RootBindingArtifactDigest32V1::from_synthetic_artifact_bytes(&[tag, 1])
            .expect("root binding"),
        RoleRootEpochV1::new(u64::from(tag) + 1).expect("root epoch"),
        RoleInputStateRecordDigest32V1::from_synthetic_fixture_bytes([tag.wrapping_add(1); 32]),
        RoleInputStateEpochV1::new(state_epoch).expect("state epoch"),
        ClientInputArtifactDigest32V1::from_synthetic_artifact_bytes(&[tag, 2])
            .expect("client input"),
        ServerInputArtifactDigest32V1::from_synthetic_artifact_bytes(&[tag, 3])
            .expect("server input"),
        CombinedInputArtifactDigest32V1::from_synthetic_artifact_bytes(&[tag, 4])
            .expect("combined input"),
    )
}

pub(crate) fn provenance_pair(
    ceremony: CeremonyValidatedDagV1,
    registered_public_key: Option<RegisteredEd25519PublicKey32V1>,
) -> RoleInputProvenancePairV1 {
    let stable_scope =
        StableKdfScopeV1::from_context(&canonical_synthetic_kdf_material_v1().context);
    let a_envelope = ClientEnvelopeArtifactDigest32V1::from_synthetic_artifact_bytes(&[
        ceremony.request_kind().tag(),
        1,
    ])
    .expect("A envelope");
    let b_envelope = ClientEnvelopeArtifactDigest32V1::from_synthetic_artifact_bytes(&[
        ceremony.request_kind().tag(),
        2,
    ])
    .expect("B envelope");
    let envelope_set =
        ClientEnvelopeSetDigest32V1::compute(&a_envelope, &b_envelope).expect("envelope set");
    let ceremony_a =
        CeremonyProvenanceBindingV1::from_validated_ceremony(ceremony, a_envelope, envelope_set)
            .expect("A provenance ceremony");
    let ceremony_b =
        CeremonyProvenanceBindingV1::from_validated_ceremony(ceremony, b_envelope, envelope_set)
            .expect("B provenance ceremony");
    let activation_binding = ActivationCircuitBindingV1::new(
        CircuitDigest32::new([0x71; 32]).expect("circuit digest"),
        InputSchemaDigest32::new([0x72; 32]).expect("schema digest"),
    );
    let export_binding = ExportCircuitBindingV1::new(
        CircuitDigest32::new([0x73; 32]).expect("circuit digest"),
        InputSchemaDigest32::new([0x74; 32]).expect("schema digest"),
    );
    let (a, b) = match ceremony.request_kind() {
        CeremonyRequestKindV1::Registration => {
            assert!(registered_public_key.is_none());
            let anti_bias = RegistrationAntiBiasArtifactDigest32V1::from_synthetic_artifact_bytes(
                b"registration-anti-bias",
            )
            .expect("anti-bias");
            (
                RoleInputProvenanceStatementV1::registration(
                    RegistrationStatementCommonV1::new(
                        stable_scope,
                        ceremony_a,
                        activation_binding,
                    )
                    .expect("A registration common"),
                    RegistrationBranchV1::new(
                        snapshot(0x11, 11),
                        RegistrationIntentDigest32V1::from_synthetic_fixture_bytes([0x62; 32]),
                        anti_bias,
                    ),
                ),
                RoleInputProvenanceStatementV1::registration(
                    RegistrationStatementCommonV1::new(
                        stable_scope,
                        ceremony_b,
                        activation_binding,
                    )
                    .expect("B registration common"),
                    RegistrationBranchV1::new(
                        snapshot(0x12, 41),
                        RegistrationIntentDigest32V1::from_synthetic_fixture_bytes([0x62; 32]),
                        anti_bias,
                    ),
                ),
            )
        }
        CeremonyRequestKindV1::Recovery => {
            let key = registered_public_key.expect("recovery key");
            let continuity = RecoveryContinuityArtifactDigest32V1::from_synthetic_artifact_bytes(
                b"same-root-recovery",
            )
            .expect("recovery continuity");
            (
                RoleInputProvenanceStatementV1::recovery(
                    RecoveryStatementCommonV1::new(stable_scope, ceremony_a, activation_binding)
                        .expect("A recovery common"),
                    RecoveryBranchV1::new(snapshot(0x11, 11), key, continuity),
                ),
                RoleInputProvenanceStatementV1::recovery(
                    RecoveryStatementCommonV1::new(stable_scope, ceremony_b, activation_binding)
                        .expect("B recovery common"),
                    RecoveryBranchV1::new(snapshot(0x12, 41), key, continuity),
                ),
            )
        }
        CeremonyRequestKindV1::Refresh => {
            let key = registered_public_key.expect("refresh key");
            let continuity = RefreshContinuityArtifactDigest32V1::from_synthetic_artifact_bytes(
                b"opposite-delta-refresh",
            )
            .expect("refresh continuity");
            (
                RoleInputProvenanceStatementV1::refresh(
                    RefreshStatementCommonV1::new(stable_scope, ceremony_a, activation_binding)
                        .expect("A refresh common"),
                    RefreshBranchV1::new(snapshot(0x11, 11), snapshot(0x11, 12), key, continuity)
                        .expect("A refresh epochs"),
                ),
                RoleInputProvenanceStatementV1::refresh(
                    RefreshStatementCommonV1::new(stable_scope, ceremony_b, activation_binding)
                        .expect("B refresh common"),
                    RefreshBranchV1::new(snapshot(0x12, 41), snapshot(0x12, 43), key, continuity)
                        .expect("B refresh epochs"),
                ),
            )
        }
        CeremonyRequestKindV1::Export => {
            let key = registered_public_key.expect("export key");
            (
                RoleInputProvenanceStatementV1::export(
                    ExportStatementCommonV1::new(stable_scope, ceremony_a, export_binding)
                        .expect("A export common"),
                    ExportBranchV1::new(snapshot(0x11, 11), key),
                ),
                RoleInputProvenanceStatementV1::export(
                    ExportStatementCommonV1::new(stable_scope, ceremony_b, export_binding)
                        .expect("B export common"),
                    ExportBranchV1::new(snapshot(0x12, 41), key),
                ),
            )
        }
        CeremonyRequestKindV1::Activation => panic!("activation has no provenance pair"),
    };
    RoleInputProvenancePairV1::new(a, b).expect("valid A/B provenance pair")
}

fn registration_context(suffix: &str) -> RegistrationActivationSemanticArtifactContextV1 {
    let (request, authorization, transcript) = registration_ceremony(suffix);
    let pair = provenance_pair(
        validated_dag(&request, authorization.into(), &transcript),
        None,
    );
    RegistrationActivationSemanticArtifactContextV1::new(
        &request,
        &authorization,
        &transcript,
        CeremonyActivationEpochV1::new(9).expect("activation epoch"),
        OneUseExecutionId32V1::new([0x70; 32]).expect("execution id"),
        &pair,
        OpaqueHostReferenceEvaluationEvidenceDigest32V1::new([0x72; 32])
            .expect("evaluation evidence"),
    )
    .expect("registration semantic context")
}

fn recovery_context(
    registered_public_key: RegisteredEd25519PublicKey32V1,
) -> RecoveryActivationSemanticArtifactContextV1 {
    let (request, authorization, transcript) = recovery_ceremony();
    let pair = provenance_pair(
        validated_dag(&request, authorization.into(), &transcript),
        Some(registered_public_key),
    );
    RecoveryActivationSemanticArtifactContextV1::new(
        &request,
        &authorization,
        &transcript,
        CeremonyActivationEpochV1::new(10).expect("activation epoch"),
        OneUseExecutionId32V1::new([0x73; 32]).expect("execution id"),
        &pair,
        OpaqueHostReferenceEvaluationEvidenceDigest32V1::new([0x74; 32])
            .expect("evaluation evidence"),
    )
    .expect("recovery semantic context")
}

fn refresh_context(
    registered_public_key: RegisteredEd25519PublicKey32V1,
) -> RefreshActivationSemanticArtifactContextV1 {
    let (request, authorization, transcript) = refresh_ceremony();
    let pair = provenance_pair(
        validated_dag(&request, authorization.into(), &transcript),
        Some(registered_public_key),
    );
    RefreshActivationSemanticArtifactContextV1::new(
        &request,
        &authorization,
        &transcript,
        CeremonyActivationEpochV1::new(11).expect("activation epoch"),
        OneUseExecutionId32V1::new([0x75; 32]).expect("execution id"),
        &pair,
        OpaqueHostReferenceEvaluationEvidenceDigest32V1::new([0x76; 32])
            .expect("evaluation evidence"),
    )
    .expect("refresh semantic context")
}

fn export_context(
    registered_public_key: RegisteredEd25519PublicKey32V1,
) -> ExportSemanticArtifactContextV1 {
    let (request, authorization, transcript) = export_ceremony(registered_public_key);
    let pair = provenance_pair(
        validated_dag(&request, authorization.into(), &transcript),
        Some(registered_public_key),
    );
    ExportSemanticArtifactContextV1::new(
        &request,
        &authorization,
        &transcript,
        OneUseExecutionId32V1::new([0x79; 32]).expect("execution id"),
        &pair,
        OpaqueHostReferenceEvaluationEvidenceDigest32V1::new([0x78; 32])
            .expect("evaluation evidence"),
    )
    .expect("export semantic context")
}

fn lp32_fields(mut bytes: &[u8]) -> Vec<&[u8]> {
    let mut fields = Vec::new();
    while !bytes.is_empty() {
        let length = u32::from_be_bytes(bytes[..4].try_into().expect("four-byte length")) as usize;
        bytes = &bytes[4..];
        fields.push(&bytes[..length]);
        bytes = &bytes[length..];
    }
    fields
}

fn independent_digest(domain: &[u8], encoding: &[u8]) -> [u8; 32] {
    let mut input = Vec::new();
    input.extend_from_slice(&(domain.len() as u32).to_be_bytes());
    input.extend_from_slice(domain);
    input.extend_from_slice(&(encoding.len() as u32).to_be_bytes());
    input.extend_from_slice(encoding);
    Sha256::digest(input).into()
}

#[test]
fn package_entrypoints_remain_ceremony_bound_and_success_free() {
    let source = include_str!("../src/semantic_artifacts.rs");
    for removed in [
        "pub fn from_registration_host_reference(",
        "pub fn from_recovery_host_reference(",
        "pub fn from_refresh_host_reference(",
        "pub fn from_host_reference_success(",
    ] {
        assert!(
            !source.contains(removed),
            "removed entrypoint returned: {removed}"
        );
    }
    assert_eq!(
        source
            .matches("pub fn evaluate_and_package_host_reference(")
            .count(),
        4
    );
    assert!(!source.contains("pub fn activation_binding("));
    let activation_receipt_impl = source
        .split("impl ActivationOutputCommittedReceiptBodyV1 {")
        .nth(1)
        .expect("activation receipt impl")
        .split("/// Public export output-committed receipt body.")
        .next()
        .expect("activation receipt impl body");
    assert!(!activation_receipt_impl.contains("pub fn new("));
    let export_receipt_impl = source
        .split("impl ExportOutputCommittedReceiptBodyV1 {")
        .nth(1)
        .expect("export receipt impl")
        .split("/// Move-owned export package set committed before client release.")
        .next()
        .expect("export receipt impl body");
    assert!(!export_receipt_impl.contains("pub fn new("));
}

fn committed_activation(packaged: HostOnlyPackagedActivationV1) -> CommittedActivationArtifactsV1 {
    let (packages, _shares) = packaged.into_parts();
    CommittedActivationArtifactsV1::new(
        packages,
        OpaqueHostReferenceDeriverAReceiptEvidenceDigest32V1::new([0xa1; 32]).expect("A evidence"),
        OpaqueHostReferenceDeriverBReceiptEvidenceDigest32V1::new([0xa2; 32]).expect("B evidence"),
    )
    .expect("committed activation artifacts")
}

#[test]
fn activation_set_has_four_role_and_recipient_typed_descriptors_in_fixed_order() {
    let fixture = reference_fixture();
    let packages = registration_context("registration")
        .evaluate_and_package_host_reference(
            registration_inputs(&fixture),
            registration_ideal_coins(3, 5),
            activation_bindings(),
        )
        .expect("registration packages");
    let set_encoding = packages.packages().encode();
    let set_fields = lp32_fields(&set_encoding);
    assert_eq!(set_fields.len(), 5);
    assert_eq!(set_fields[0], ACTIVATION_PACKAGE_SET_ENCODING_DOMAIN_V1);
    let expected = [
        (ACTIVATION_DERIVER_A_CLIENT_DESCRIPTOR_DOMAIN_V1, 1, 1, 1),
        (ACTIVATION_DERIVER_B_CLIENT_DESCRIPTOR_DOMAIN_V1, 2, 1, 1),
        (
            ACTIVATION_DERIVER_A_SIGNING_WORKER_DESCRIPTOR_DOMAIN_V1,
            1,
            2,
            2,
        ),
        (
            ACTIVATION_DERIVER_B_SIGNING_WORKER_DESCRIPTOR_DOMAIN_V1,
            2,
            2,
            2,
        ),
    ];
    for (encoded, (domain, role, recipient, output)) in set_fields[1..].iter().zip(expected) {
        let descriptor = lp32_fields(encoded);
        assert_eq!(descriptor.len(), 21);
        assert_eq!(descriptor[0], domain);
        assert_eq!(descriptor[1], [CeremonyRequestKindV1::Registration.tag()]);
        assert_eq!(descriptor[2], [role]);
        assert_eq!(descriptor[3], [recipient]);
        assert_eq!(descriptor[4], [output]);
        assert_eq!(descriptor[10], [0x70; 32]);
        assert_eq!(descriptor[13], 9_u64.to_be_bytes());
        assert_eq!(descriptor[14].len(), 32);
        assert_eq!(descriptor[15].len(), 32);
        assert_eq!(descriptor[18].len(), 8);
    }
    let client_a = lp32_fields(set_fields[1]);
    let client_b = lp32_fields(set_fields[2]);
    let worker_a = lp32_fields(set_fields[3]);
    let worker_b = lp32_fields(set_fields[4]);
    assert_eq!(client_a[14], client_b[14]);
    assert_eq!(worker_a[14], worker_b[14]);
    assert_ne!(client_a[14], worker_a[14]);
    assert_eq!(
        packages.packages().digest().as_bytes(),
        &independent_digest(
            ACTIVATION_PACKAGE_SET_DIGEST_DOMAIN_V1,
            &packages.packages().encode(),
        )
    );
}

#[test]
fn ciphertext_digest_and_be64_length_mutations_change_package_and_receipt_commitments() {
    let fixture = reference_fixture();
    let baseline = registration_context("mutation")
        .evaluate_and_package_host_reference(
            registration_inputs(&fixture),
            registration_ideal_coins(3, 5),
            activation_bindings_with_a_client(0x82, 193),
        )
        .expect("baseline");
    let changed_ciphertext = registration_context("mutation")
        .evaluate_and_package_host_reference(
            registration_inputs(&fixture),
            registration_ideal_coins(3, 5),
            activation_bindings_with_a_client(0x83, 193),
        )
        .expect("ciphertext mutation");
    let changed_length = registration_context("mutation")
        .evaluate_and_package_host_reference(
            registration_inputs(&fixture),
            registration_ideal_coins(3, 5),
            activation_bindings_with_a_client(0x82, 194),
        )
        .expect("length mutation");
    assert_ne!(
        baseline.packages().digest(),
        changed_ciphertext.packages().digest()
    );
    assert_ne!(
        baseline.packages().digest(),
        changed_length.packages().digest()
    );
    let baseline_encoding = baseline.packages().deriver_a_client().encode();
    let ciphertext_encoding = changed_ciphertext.packages().deriver_a_client().encode();
    let length_encoding = changed_length.packages().deriver_a_client().encode();
    let baseline_fields = lp32_fields(&baseline_encoding);
    let ciphertext_fields = lp32_fields(&ciphertext_encoding);
    let length_fields = lp32_fields(&length_encoding);
    assert_eq!(baseline_fields[17], [0x82; 32]);
    assert_eq!(ciphertext_fields[17], [0x83; 32]);
    assert_eq!(baseline_fields[18], 193_u64.to_be_bytes());
    assert_eq!(length_fields[18], 194_u64.to_be_bytes());
    let baseline_receipt = committed_activation(baseline).receipt().digest();
    let changed_ciphertext_receipt = committed_activation(changed_ciphertext).receipt().digest();
    let changed_length_receipt = committed_activation(changed_length).receipt().digest();
    assert_ne!(baseline_receipt, changed_ciphertext_receipt);
    assert_ne!(baseline_receipt, changed_length_receipt);
}

#[test]
fn registration_derives_receipt_identity_from_joined_points() {
    let fixture = reference_fixture();
    let packages = registration_context("candidate-key")
        .evaluate_and_package_host_reference(
            registration_inputs(&fixture),
            registration_ideal_coins(3, 5),
            activation_bindings(),
        )
        .expect("registration packages");
    let committed = committed_activation(packages);
    let receipt = committed.receipt();
    let receipt_encoding = receipt.encode();
    let fields = lp32_fields(&receipt_encoding);
    assert_eq!(fields.len(), 19);
    assert_eq!(
        fields[0],
        ACTIVATION_OUTPUT_COMMITTED_RECEIPT_ENCODING_DOMAIN_V1
    );
    assert_eq!(fields[2], [1]);
    assert_eq!(fields[13], receipt.package_set_digest().as_bytes());
    assert_eq!(fields[16], fixture.registered_public_key.as_bytes());
    assert_eq!(
        receipt.digest().as_bytes(),
        &independent_digest(
            ACTIVATION_OUTPUT_COMMITTED_RECEIPT_DIGEST_DOMAIN_V1,
            &receipt.encode(),
        )
    );
}

#[test]
fn zero_individual_additive_share_remains_valid() {
    let fixture = reference_fixture();
    let packages = registration_context("zero-share")
        .evaluate_and_package_host_reference(
            registration_inputs(&fixture),
            registration_ideal_coins(0, 5),
            activation_bindings(),
        )
        .expect("zero individual share must remain valid");
    let descriptor_encoding = packages.packages().deriver_a_client().encode();
    let descriptor = lp32_fields(&descriptor_encoding);
    assert_eq!(
        descriptor[15],
        [
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ]
    );
    committed_activation(packages);
}

#[test]
fn recovery_and_refresh_preserve_the_authoritative_registered_identity() {
    let fixture = reference_fixture();
    recovery_context(fixture.registered_public_key)
        .evaluate_and_package_host_reference(
            recovery_inputs(&fixture),
            recovery_ideal_coins(3, 5),
            activation_bindings(),
        )
        .expect("matching recovery identity");
    refresh_context(fixture.registered_public_key)
        .evaluate_and_package_host_reference(
            refresh_inputs(&fixture),
            refresh_ideal_coins(3, 5),
            activation_bindings(),
        )
        .expect("matching refresh identity");

    let wrong_key = RegisteredEd25519PublicKey32V1::parse(
        (ED25519_BASEPOINT_POINT + ED25519_BASEPOINT_POINT)
            .compress()
            .to_bytes(),
    )
    .expect("wrong key is valid");
    assert_ne!(wrong_key, fixture.registered_public_key);
    assert!(matches!(
        recovery_context(wrong_key).evaluate_and_package_host_reference(
            recovery_inputs(&fixture),
            recovery_ideal_coins(3, 5),
            activation_bindings(),
        ),
        Err(SemanticArtifactErrorV1::Ed25519OutputRelationMismatch)
    ));
}

#[test]
fn ceremony_bound_recovery_propagates_reference_input_failures() {
    let fixture = reference_fixture();
    let different_recovered_root = SyntheticClientDerivationRootV1::from_fixture_bytes([0x99; 32]);
    let inputs = HostOnlyRecoveryReferenceInputsV1::new(
        &fixture.client_root,
        &different_recovered_root,
        &fixture.context,
        &fixture.deriver_a,
        &fixture.deriver_b,
    );
    assert!(matches!(
        recovery_context(fixture.registered_public_key).evaluate_and_package_host_reference(
            inputs,
            recovery_ideal_coins(3, 5),
            activation_bindings(),
        ),
        Err(SemanticArtifactErrorV1::RecoveryReference(
            HostOnlyRecoveryReferenceErrorV1::RecoveredClientRootMismatch
        ))
    ));
}

#[test]
fn export_requires_key_equality_success_and_exposes_no_seed() {
    let fixture = reference_fixture();
    let success = export_success(&fixture);
    let a_share = success.output_shares().deriver_a().expose_fixture_bytes();
    let b_share = success.output_shares().deriver_b().expose_fixture_bytes();
    let joined_seed = reconstruct_host_only_seed_export_v1(
        success.output_shares().deriver_a(),
        success.output_shares().deriver_b(),
    )
    .expose_bytes();
    let packaged = export_context(fixture.registered_public_key)
        .evaluate_and_package_host_reference(
            export_inputs(&fixture),
            export_ideal_coin(),
            export_bindings(),
        )
        .expect("export packages");
    let packages = packaged.packages();
    let set_encoding = packages.encode();
    let set_fields = lp32_fields(&set_encoding);
    assert_eq!(set_fields.len(), 3);
    assert_eq!(set_fields[0], EXPORT_PACKAGE_SET_ENCODING_DOMAIN_V1);
    for (encoded, (domain, role)) in set_fields[1..].iter().zip([
        (EXPORT_DERIVER_A_CLIENT_DESCRIPTOR_DOMAIN_V1, 1),
        (EXPORT_DERIVER_B_CLIENT_DESCRIPTOR_DOMAIN_V1, 2),
    ]) {
        let descriptor = lp32_fields(encoded);
        assert_eq!(descriptor.len(), 19);
        assert_eq!(descriptor[0], domain);
        assert_eq!(descriptor[1], [CeremonyRequestKindV1::Export.tag()]);
        assert_eq!(descriptor[2], [role]);
        assert_eq!(descriptor[3], [1]);
        assert_eq!(descriptor[4], [3]);
        assert!(descriptor.iter().all(|field| *field != a_share));
        assert!(descriptor.iter().all(|field| *field != b_share));
        assert!(descriptor.iter().all(|field| *field != joined_seed));
    }
    assert_eq!(
        packages.digest().as_bytes(),
        &independent_digest(EXPORT_PACKAGE_SET_DIGEST_DOMAIN_V1, &packages.encode())
    );
    let (packages, retained_shares) = packaged.into_parts();
    assert_eq!(
        reconstruct_host_only_seed_export_v1(
            retained_shares.deriver_a(),
            retained_shares.deriver_b()
        )
        .expose_bytes(),
        joined_seed
    );
    let committed = OutputCommittedExportArtifactsV1::new(
        packages,
        OpaqueHostReferenceDeriverAReceiptEvidenceDigest32V1::new([0xb1; 32]).expect("A evidence"),
        OpaqueHostReferenceDeriverBReceiptEvidenceDigest32V1::new([0xb2; 32]).expect("B evidence"),
    );
    let receipt = committed.receipt();
    let receipt_encoding = receipt.encode();
    let fields = lp32_fields(&receipt_encoding);
    assert_eq!(fields.len(), 16);
    assert_eq!(
        fields[0],
        EXPORT_OUTPUT_COMMITTED_RECEIPT_ENCODING_DOMAIN_V1
    );
    assert_eq!(fields[13], fixture.registered_public_key.as_bytes());
    assert_eq!(
        receipt.digest().as_bytes(),
        &independent_digest(
            EXPORT_OUTPUT_COMMITTED_RECEIPT_DIGEST_DOMAIN_V1,
            &receipt.encode()
        )
    );

    let wrong_key = RegisteredEd25519PublicKey32V1::parse(
        (ED25519_BASEPOINT_POINT + ED25519_BASEPOINT_POINT)
            .compress()
            .to_bytes(),
    )
    .expect("wrong key");
    assert_ne!(wrong_key, fixture.registered_public_key);
    assert!(matches!(
        export_context(wrong_key).evaluate_and_package_host_reference(
            export_inputs(&fixture),
            export_ideal_coin(),
            export_bindings(),
        ),
        Err(SemanticArtifactErrorV1::ExportReference(
            HostOnlyExportReferenceErrorV1::RegisteredPublicKeyMismatch
        ))
    ));
}

#[test]
fn semantic_context_rejects_cross_ceremony_and_cross_branch_provenance() {
    let (first_request, first_authorization, first_transcript) = registration_ceremony("first");
    let first_pair = provenance_pair(
        validated_dag(
            &first_request,
            first_authorization.into(),
            &first_transcript,
        ),
        None,
    );
    let (second_request, second_authorization, second_transcript) = registration_ceremony("second");
    assert_eq!(
        RegistrationActivationSemanticArtifactContextV1::new(
            &second_request,
            &second_authorization,
            &second_transcript,
            CeremonyActivationEpochV1::new(9).expect("activation epoch"),
            OneUseExecutionId32V1::new([0xc0; 32]).expect("execution id"),
            &first_pair,
            OpaqueHostReferenceEvaluationEvidenceDigest32V1::new([0xc1; 32])
                .expect("evaluation evidence"),
        ),
        Err(SemanticArtifactErrorV1::InputProvenanceRequestContextMismatch)
    );

    let changed_authorization = CeremonyRegistrationAuthorizationV1::new(
        &first_request,
        CeremonyAuthorizationRecordDigest32V1::new([0xd1; 32])
            .expect("changed authorization record"),
        CeremonyRegistrationIntentDigest32V1::new([0x62; 32]).expect("registration intent"),
    )
    .expect("changed registration authorization");
    let changed_authorization_transcript =
        transcript(&first_request, &changed_authorization.into());
    assert_eq!(
        RegistrationActivationSemanticArtifactContextV1::new(
            &first_request,
            &changed_authorization,
            &changed_authorization_transcript,
            CeremonyActivationEpochV1::new(9).expect("activation epoch"),
            OneUseExecutionId32V1::new([0xd2; 32]).expect("execution id"),
            &first_pair,
            OpaqueHostReferenceEvaluationEvidenceDigest32V1::new([0xd3; 32])
                .expect("evaluation evidence"),
        ),
        Err(SemanticArtifactErrorV1::InputProvenanceAuthorizationMismatch)
    );

    let changed_transcript = transcript_with_nonce(
        &first_request,
        &CeremonyAuthorizationV1::from(first_authorization),
        0xd4,
    );
    assert_eq!(
        RegistrationActivationSemanticArtifactContextV1::new(
            &first_request,
            &first_authorization,
            &changed_transcript,
            CeremonyActivationEpochV1::new(9).expect("activation epoch"),
            OneUseExecutionId32V1::new([0xd5; 32]).expect("execution id"),
            &first_pair,
            OpaqueHostReferenceEvaluationEvidenceDigest32V1::new([0xd6; 32])
                .expect("evaluation evidence"),
        ),
        Err(SemanticArtifactErrorV1::InputProvenanceTranscriptMismatch)
    );

    let fixture = reference_fixture();
    let (export_request, export_authorization, export_transcript) =
        export_ceremony(fixture.registered_public_key);
    assert_eq!(
        ExportSemanticArtifactContextV1::new(
            &export_request,
            &export_authorization,
            &export_transcript,
            OneUseExecutionId32V1::new([0xc2; 32]).expect("execution id"),
            &first_pair,
            OpaqueHostReferenceEvaluationEvidenceDigest32V1::new([0xc3; 32])
                .expect("evaluation evidence"),
        ),
        Err(SemanticArtifactErrorV1::InputProvenanceRequestKindMismatch)
    );
}

#[test]
fn export_context_rejects_provenance_for_a_different_registered_key() {
    let fixture = reference_fixture();
    let (request, authorization, transcript) = export_ceremony(fixture.registered_public_key);
    let wrong_key = RegisteredEd25519PublicKey32V1::parse(
        (ED25519_BASEPOINT_POINT + ED25519_BASEPOINT_POINT)
            .compress()
            .to_bytes(),
    )
    .expect("wrong key");
    assert_ne!(wrong_key, fixture.registered_public_key);
    let pair = provenance_pair(
        validated_dag(&request, authorization.into(), &transcript),
        Some(wrong_key),
    );
    assert_eq!(
        ExportSemanticArtifactContextV1::new(
            &request,
            &authorization,
            &transcript,
            OneUseExecutionId32V1::new([0xc4; 32]).expect("execution id"),
            &pair,
            OpaqueHostReferenceEvaluationEvidenceDigest32V1::new([0xc5; 32])
                .expect("evaluation evidence"),
        ),
        Err(SemanticArtifactErrorV1::InputProvenanceRegisteredPublicKeyMismatch)
    );
}
