use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use ed25519_yao::{CircuitDigest32, InputSchemaDigest32};
use ed25519_yao_generator::provenance::{
    parse_canonical_provenance_pair_v1, parse_canonical_provenance_statement_v1,
    ActivationCircuitBindingV1, CeremonyProvenanceBindingV1, CeremonyProvenanceErrorV1,
    ClientEnvelopeArtifactDigest32V1, ClientEnvelopeSetDigest32V1, ClientInputArtifactDigest32V1,
    CombinedInputArtifactDigest32V1, ComputedProvenanceArtifactDigestV1, DeriverAProvenanceRoleV1,
    DeriverBProvenanceRoleV1, ExportBranchV1, ExportCircuitBindingV1, ExportStatementCommonV1,
    ProvenanceArtifactKindV1, ProvenanceCircuitFamilyV1, ProvenanceDecodingErrorV1,
    ProvenanceEpochErrorV1, ProvenancePairFieldV1, ProvenanceRequestKindV1, ProvenanceRoleV1,
    RecoveryBranchV1, RecoveryContinuityArtifactDigest32V1, RecoveryStatementCommonV1,
    RefreshBranchV1, RefreshContinuityArtifactDigest32V1, RefreshProvenanceErrorV1,
    RefreshStatementCommonV1, RegistrationAntiBiasArtifactDigest32V1, RegistrationBranchV1,
    RegistrationIntentDigest32V1, RegistrationStatementCommonV1, RoleInputProvenancePairV1,
    RoleInputProvenanceStatementV1, RoleInputSnapshotV1, RoleInputStateEpochV1,
    RoleInputStateRecordDigest32V1, RoleRootEpochV1, RoleRootRecordDigest32V1,
    RootBindingArtifactDigest32V1, ServerInputArtifactDigest32V1, StableKdfScopeV1,
    PROVENANCE_ACTIVATION_FAMILY_TAG_V1, PROVENANCE_ARTIFACT_DIGEST_DOMAIN_V1,
    PROVENANCE_CLIENT_ENVELOPE_SET_DIGEST_DOMAIN_V1, PROVENANCE_DERIVER_A_ROLE_TAG_V1,
    PROVENANCE_DERIVER_B_ROLE_TAG_V1, PROVENANCE_EXPORT_FAMILY_TAG_V1,
    PROVENANCE_PAIR_DIGEST_DOMAIN_V1, PROVENANCE_PAIR_ENCODING_DOMAIN_V1,
    PROVENANCE_REGISTRATION_REQUEST_TAG_V1, PROVENANCE_STABLE_SCOPE_ENCODING_DOMAIN_V1,
    PROVENANCE_STATEMENT_DIGEST_DOMAIN_V1, PROVENANCE_STATEMENT_ENCODING_DOMAIN_V1,
};
use ed25519_yao_generator::{
    canonical_ceremony_fixture_dag_v1, ceremony_context::CeremonyRequestKindV1,
    RegisteredEd25519PublicKey32V1, StableKeyDerivationContext,
};
use sha2::{Digest, Sha256};
use std::ops::Range;

fn lp32(value: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    output.extend_from_slice(&(value.len() as u32).to_be_bytes());
    output.extend_from_slice(value);
    output
}

fn lp32_field_range(bytes: &[u8], index: usize) -> Range<usize> {
    let mut offset = 0;
    for current in 0..=index {
        let length_end = offset + 4;
        let length = u32::from_be_bytes(
            bytes[offset..length_end]
                .try_into()
                .expect("test encoding has complete LP32 length"),
        ) as usize;
        let range = length_end..length_end + length;
        if current == index {
            return range;
        }
        offset = range.end;
    }
    unreachable!("requested LP32 field exists")
}

fn lp32_field_path_range(bytes: &[u8], path: &[usize]) -> Range<usize> {
    let mut absolute_start = 0;
    let mut current = bytes;
    for (depth, index) in path.iter().enumerate() {
        let relative = lp32_field_range(current, *index);
        absolute_start += relative.start;
        if depth + 1 == path.len() {
            return absolute_start..absolute_start + relative.len();
        }
        current = &current[relative.clone()];
    }
    unreachable!("field path is nonempty")
}

fn overwrite_lp32_path(bytes: &mut [u8], path: &[usize], replacement: &[u8]) {
    let range = lp32_field_path_range(bytes, path);
    assert_eq!(range.len(), replacement.len());
    bytes[range].copy_from_slice(replacement);
}

fn fixture_context(byte: u8) -> StableKeyDerivationContext {
    StableKeyDerivationContext::new([byte; 32], 2, 1).expect("valid fixture context")
}

fn activation_binding(byte: u8) -> ActivationCircuitBindingV1 {
    ActivationCircuitBindingV1::new(
        CircuitDigest32::new([byte; 32]).expect("nonzero circuit digest"),
        InputSchemaDigest32::new([byte.wrapping_add(1); 32]).expect("nonzero schema digest"),
    )
}

fn export_binding(byte: u8) -> ExportCircuitBindingV1 {
    ExportCircuitBindingV1::new(
        CircuitDigest32::new([byte; 32]).expect("nonzero circuit digest"),
        InputSchemaDigest32::new([byte.wrapping_add(1); 32]).expect("nonzero schema digest"),
    )
}

fn snapshot<Role: ProvenanceRoleV1>(
    root_record_tag: u8,
    root_epoch: u64,
    state_record_tag: u8,
    state_epoch: u64,
) -> RoleInputSnapshotV1<Role> {
    RoleInputSnapshotV1::from_synthetic_fixture(
        RoleRootRecordDigest32V1::from_synthetic_fixture_bytes([root_record_tag; 32]),
        RootBindingArtifactDigest32V1::from_synthetic_artifact_bytes(&[root_record_tag, 0x01])
            .expect("root artifact encodes"),
        RoleRootEpochV1::new(root_epoch).expect("root epoch is nonzero"),
        RoleInputStateRecordDigest32V1::from_synthetic_fixture_bytes([state_record_tag; 32]),
        RoleInputStateEpochV1::new(state_epoch).expect("state epoch is nonzero"),
        ClientInputArtifactDigest32V1::from_synthetic_artifact_bytes(&[state_record_tag, 0x02])
            .expect("client artifact encodes"),
        ServerInputArtifactDigest32V1::from_synthetic_artifact_bytes(&[state_record_tag, 0x03])
            .expect("server artifact encodes"),
        CombinedInputArtifactDigest32V1::from_synthetic_artifact_bytes(&[state_record_tag, 0x04])
            .expect("combined artifact encodes"),
    )
}

fn envelope_artifacts(
    request_tag: u8,
) -> (
    ClientEnvelopeArtifactDigest32V1<DeriverAProvenanceRoleV1>,
    ClientEnvelopeArtifactDigest32V1<DeriverBProvenanceRoleV1>,
    ClientEnvelopeSetDigest32V1,
) {
    let a = ClientEnvelopeArtifactDigest32V1::from_synthetic_artifact_bytes(&[
        request_tag,
        PROVENANCE_DERIVER_A_ROLE_TAG_V1,
    ])
    .expect("A envelope artifact encodes");
    let b = ClientEnvelopeArtifactDigest32V1::from_synthetic_artifact_bytes(&[
        request_tag,
        PROVENANCE_DERIVER_B_ROLE_TAG_V1,
    ])
    .expect("B envelope artifact encodes");
    let set = ClientEnvelopeSetDigest32V1::compute(&a, &b).expect("set digest encodes");
    (a, b, set)
}

fn ceremony<Role: ProvenanceRoleV1>(
    request_tag: u8,
    envelope: ClientEnvelopeArtifactDigest32V1<Role>,
    set: ClientEnvelopeSetDigest32V1,
) -> CeremonyProvenanceBindingV1<Role> {
    let ceremony = canonical_ceremony_fixture_dag_v1(ceremony_kind(request_tag));
    CeremonyProvenanceBindingV1::from_validated_ceremony(ceremony, envelope, set)
        .expect("fixture ceremony performs an evaluation")
}

fn ceremony_kind(request_tag: u8) -> CeremonyRequestKindV1 {
    match request_tag {
        0x01 => CeremonyRequestKindV1::Registration,
        0x03 => CeremonyRequestKindV1::Recovery,
        0x04 => CeremonyRequestKindV1::Refresh,
        0x05 => CeremonyRequestKindV1::Export,
        _ => panic!("unexpected provenance request tag {request_tag}"),
    }
}

fn public_key() -> RegisteredEd25519PublicKey32V1 {
    RegisteredEd25519PublicKey32V1::parse(ED25519_BASEPOINT_POINT.compress().to_bytes())
        .expect("basepoint is a valid public identity")
}

fn registration_statement<Role: ProvenanceRoleV1>(
    stable_scope: StableKdfScopeV1,
    ceremony: CeremonyProvenanceBindingV1<Role>,
    snapshot: RoleInputSnapshotV1<Role>,
    intent_tag: u8,
    anti_bias_bytes: &[u8],
) -> RoleInputProvenanceStatementV1<Role> {
    RoleInputProvenanceStatementV1::registration(
        RegistrationStatementCommonV1::new(stable_scope, ceremony, activation_binding(0x51))
            .expect("registration ceremony kind matches"),
        RegistrationBranchV1::new(
            snapshot,
            RegistrationIntentDigest32V1::from_synthetic_fixture_bytes([intent_tag; 32]),
            RegistrationAntiBiasArtifactDigest32V1::from_synthetic_artifact_bytes(anti_bias_bytes)
                .expect("anti-bias artifact encodes"),
        ),
    )
}

fn registration_statements() -> (
    RoleInputProvenanceStatementV1<DeriverAProvenanceRoleV1>,
    RoleInputProvenanceStatementV1<DeriverBProvenanceRoleV1>,
) {
    let stable_scope = StableKdfScopeV1::from_context(&fixture_context(0x42));
    let (a_envelope, b_envelope, set) = envelope_artifacts(PROVENANCE_REGISTRATION_REQUEST_TAG_V1);
    (
        registration_statement(
            stable_scope,
            ceremony(PROVENANCE_REGISTRATION_REQUEST_TAG_V1, a_envelope, set),
            snapshot(0x11, 3, 0x31, 11),
            0x81,
            b"registration-anti-bias-fixture",
        ),
        registration_statement(
            stable_scope,
            ceremony(PROVENANCE_REGISTRATION_REQUEST_TAG_V1, b_envelope, set),
            snapshot(0x12, 9, 0x32, 41),
            0x81,
            b"registration-anti-bias-fixture",
        ),
    )
}

fn recovery_statements() -> (
    RoleInputProvenanceStatementV1<DeriverAProvenanceRoleV1>,
    RoleInputProvenanceStatementV1<DeriverBProvenanceRoleV1>,
) {
    let stable_scope = StableKdfScopeV1::from_context(&fixture_context(0x42));
    let (a_envelope, b_envelope, set) = envelope_artifacts(0x03);
    let continuity = RecoveryContinuityArtifactDigest32V1::from_synthetic_artifact_bytes(
        b"recovery-same-root-fixture",
    )
    .expect("recovery artifact encodes");
    (
        RoleInputProvenanceStatementV1::recovery(
            RecoveryStatementCommonV1::new(
                stable_scope,
                ceremony(0x03, a_envelope, set),
                activation_binding(0x51),
            )
            .expect("recovery ceremony kind matches"),
            RecoveryBranchV1::new(snapshot(0x11, 3, 0x31, 11), public_key(), continuity),
        ),
        RoleInputProvenanceStatementV1::recovery(
            RecoveryStatementCommonV1::new(
                stable_scope,
                ceremony(0x03, b_envelope, set),
                activation_binding(0x51),
            )
            .expect("recovery ceremony kind matches"),
            RecoveryBranchV1::new(snapshot(0x12, 9, 0x32, 41), public_key(), continuity),
        ),
    )
}

fn refresh_statements() -> (
    RoleInputProvenanceStatementV1<DeriverAProvenanceRoleV1>,
    RoleInputProvenanceStatementV1<DeriverBProvenanceRoleV1>,
) {
    let stable_scope = StableKdfScopeV1::from_context(&fixture_context(0x42));
    let (a_envelope, b_envelope, set) = envelope_artifacts(0x04);
    let continuity = RefreshContinuityArtifactDigest32V1::from_synthetic_artifact_bytes(
        b"refresh-opposite-delta-fixture",
    )
    .expect("refresh artifact encodes");
    (
        RoleInputProvenanceStatementV1::refresh(
            RefreshStatementCommonV1::new(
                stable_scope,
                ceremony(0x04, a_envelope, set),
                activation_binding(0x51),
            )
            .expect("refresh ceremony kind matches"),
            RefreshBranchV1::new(
                snapshot(0x11, 3, 0x31, 11),
                snapshot(0x11, 3, 0x33, 12),
                public_key(),
                continuity,
            )
            .expect("A refresh epochs advance"),
        ),
        RoleInputProvenanceStatementV1::refresh(
            RefreshStatementCommonV1::new(
                stable_scope,
                ceremony(0x04, b_envelope, set),
                activation_binding(0x51),
            )
            .expect("refresh ceremony kind matches"),
            RefreshBranchV1::new(
                snapshot(0x12, 9, 0x32, 41),
                snapshot(0x12, 9, 0x34, 43),
                public_key(),
                continuity,
            )
            .expect("B refresh epochs advance"),
        ),
    )
}

fn export_statements() -> (
    RoleInputProvenanceStatementV1<DeriverAProvenanceRoleV1>,
    RoleInputProvenanceStatementV1<DeriverBProvenanceRoleV1>,
) {
    let stable_scope = StableKdfScopeV1::from_context(&fixture_context(0x42));
    let (a_envelope, b_envelope, set) = envelope_artifacts(0x05);
    (
        RoleInputProvenanceStatementV1::export(
            ExportStatementCommonV1::new(
                stable_scope,
                ceremony(0x05, a_envelope, set),
                export_binding(0x61),
            )
            .expect("export ceremony kind matches"),
            ExportBranchV1::new(snapshot(0x11, 3, 0x31, 11), public_key()),
        ),
        RoleInputProvenanceStatementV1::export(
            ExportStatementCommonV1::new(
                stable_scope,
                ceremony(0x05, b_envelope, set),
                export_binding(0x61),
            )
            .expect("export ceremony kind matches"),
            ExportBranchV1::new(snapshot(0x12, 9, 0x32, 41), public_key()),
        ),
    )
}

#[test]
fn ceremony_binding_rejects_activation_and_common_builders_reject_cross_branch_splicing() {
    let stable_scope = StableKdfScopeV1::from_context(&fixture_context(0x42));
    let (activation_envelope, _, activation_set) = envelope_artifacts(0x02);
    let activation_result = CeremonyProvenanceBindingV1::from_validated_ceremony(
        canonical_ceremony_fixture_dag_v1(CeremonyRequestKindV1::Activation),
        activation_envelope,
        activation_set,
    );
    assert_eq!(
        activation_result,
        Err(CeremonyProvenanceErrorV1::ActivationHasNoEvaluationProvenance)
    );

    let (export_envelope, _, export_set) = envelope_artifacts(0x05);
    let export_ceremony = CeremonyProvenanceBindingV1::from_validated_ceremony(
        canonical_ceremony_fixture_dag_v1(CeremonyRequestKindV1::Export),
        export_envelope,
        export_set,
    )
    .expect("export ceremony performs an evaluation");
    assert_eq!(
        RegistrationStatementCommonV1::new(stable_scope, export_ceremony, activation_binding(0x51),),
        Err(CeremonyProvenanceErrorV1::StatementRequestKindMismatch)
    );
}

#[test]
fn artifact_wrapper_domains_every_kind_and_role() {
    let mut digests = Vec::new();
    for kind in [
        ProvenanceArtifactKindV1::RoleRootBinding,
        ProvenanceArtifactKindV1::ClientInputBinding,
        ProvenanceArtifactKindV1::ServerInputBinding,
        ProvenanceArtifactKindV1::CombinedRoleInputBinding,
        ProvenanceArtifactKindV1::ClientEnvelopeCommitment,
        ProvenanceArtifactKindV1::RegistrationAntiBiasEvidence,
        ProvenanceArtifactKindV1::RecoverySameRootContinuity,
        ProvenanceArtifactKindV1::RefreshOppositeDeltaTransition,
    ] {
        let computed = ComputedProvenanceArtifactDigestV1::compute(kind, b"artifact-fixture")
            .expect("artifact encodes");
        let mut expected = Vec::new();
        expected.extend_from_slice(&lp32(PROVENANCE_ARTIFACT_DIGEST_DOMAIN_V1));
        expected.extend_from_slice(&lp32(&[kind.tag()]));
        expected.extend_from_slice(&lp32(b"artifact-fixture"));
        assert_eq!(
            computed.as_bytes(),
            &<[u8; 32]>::from(Sha256::digest(expected))
        );
        digests.push(*computed.as_bytes());
    }
    digests.sort_unstable();
    digests.dedup();
    assert_eq!(digests.len(), 8);
}

#[test]
fn stable_scope_is_recomputed_from_the_frozen_context() {
    let context = fixture_context(0x42);
    let scope = StableKdfScopeV1::from_context(&context);
    let mut expected = Vec::new();
    expected.extend_from_slice(&lp32(PROVENANCE_STABLE_SCOPE_ENCODING_DOMAIN_V1));
    expected.extend_from_slice(&lp32(context.application_binding_digest().as_bytes()));
    expected.extend_from_slice(&lp32(&1_u16.to_be_bytes()));
    expected.extend_from_slice(&lp32(&2_u16.to_be_bytes()));
    expected.extend_from_slice(&lp32(context.binding_digest().as_bytes()));

    assert_eq!(scope.participant_ids(), [1, 2]);
    assert_eq!(scope.encode().expect("scope encodes"), expected);
}

#[test]
fn statement_dispatch_and_digest_domains_are_fixed() {
    let (registration_a, _) = registration_statements();
    let (recovery_a, _) = recovery_statements();
    let (refresh_a, _) = refresh_statements();
    let (export_a, _) = export_statements();
    let cases = [
        (
            registration_a,
            ProvenanceRequestKindV1::Registration,
            ProvenanceCircuitFamilyV1::Activation,
        ),
        (
            recovery_a,
            ProvenanceRequestKindV1::Recovery,
            ProvenanceCircuitFamilyV1::Activation,
        ),
        (
            refresh_a,
            ProvenanceRequestKindV1::Refresh,
            ProvenanceCircuitFamilyV1::Activation,
        ),
        (
            export_a,
            ProvenanceRequestKindV1::Export,
            ProvenanceCircuitFamilyV1::Export,
        ),
    ];

    for (statement, request, family) in cases {
        assert_eq!(statement.request_kind(), request);
        assert_eq!(statement.circuit_family(), family);
        let encoding = statement.encode().expect("statement encodes");
        assert!(encoding.starts_with(&lp32(PROVENANCE_STATEMENT_ENCODING_DOMAIN_V1)));
        let mut digest_input = Vec::new();
        digest_input.extend_from_slice(&lp32(PROVENANCE_STATEMENT_DIGEST_DOMAIN_V1));
        digest_input.extend_from_slice(&lp32(&encoding));
        assert_eq!(
            statement.digest().expect("statement digest").as_bytes(),
            &<[u8; 32]>::from(Sha256::digest(digest_input))
        );
    }

    assert_eq!(PROVENANCE_ACTIVATION_FAMILY_TAG_V1, 0x01);
    assert_eq!(PROVENANCE_EXPORT_FAMILY_TAG_V1, 0x02);
}

#[test]
fn ordered_pairs_accept_all_four_evaluation_branches() {
    for (a, b) in [
        registration_statements(),
        recovery_statements(),
        refresh_statements(),
        export_statements(),
    ] {
        let pair = RoleInputProvenancePairV1::new(a, b).expect("matching pair");
        let encoding = pair.encode().expect("pair encodes");
        assert!(encoding.starts_with(&lp32(PROVENANCE_PAIR_ENCODING_DOMAIN_V1)));
        let mut digest_input = Vec::new();
        digest_input.extend_from_slice(&lp32(PROVENANCE_PAIR_DIGEST_DOMAIN_V1));
        digest_input.extend_from_slice(&lp32(&encoding));
        assert_eq!(
            pair.digest().expect("pair digest").as_bytes(),
            &<[u8; 32]>::from(Sha256::digest(digest_input))
        );
    }
}

#[test]
fn pair_rejects_lifecycle_stable_scope_envelope_and_joint_evidence_mismatches() {
    let (registration_a, registration_b) = registration_statements();
    let (_, recovery_b) = recovery_statements();
    assert_eq!(
        RoleInputProvenancePairV1::new(registration_a.clone(), recovery_b)
            .expect_err("request mismatch")
            .field(),
        ProvenancePairFieldV1::RequestKind
    );

    let (a_envelope, b_envelope, set) = envelope_artifacts(PROVENANCE_REGISTRATION_REQUEST_TAG_V1);
    let wrong_stable_b = registration_statement(
        StableKdfScopeV1::from_context(&fixture_context(0x43)),
        ceremony(PROVENANCE_REGISTRATION_REQUEST_TAG_V1, b_envelope, set),
        snapshot(0x12, 9, 0x32, 41),
        0x81,
        b"registration-anti-bias-fixture",
    );
    assert_eq!(
        RoleInputProvenancePairV1::new(registration_a.clone(), wrong_stable_b)
            .expect_err("stable mismatch")
            .field(),
        ProvenancePairFieldV1::StableScope
    );

    let (_, _, wrong_set) = envelope_artifacts(0x7f);
    let wrong_envelope_b = registration_statement(
        StableKdfScopeV1::from_context(&fixture_context(0x42)),
        ceremony(
            PROVENANCE_REGISTRATION_REQUEST_TAG_V1,
            b_envelope,
            wrong_set,
        ),
        snapshot(0x12, 9, 0x32, 41),
        0x81,
        b"registration-anti-bias-fixture",
    );
    assert_eq!(
        RoleInputProvenancePairV1::new(registration_a.clone(), wrong_envelope_b)
            .expect_err("envelope set mismatch")
            .field(),
        ProvenancePairFieldV1::ClientEnvelopeSetDigest
    );

    let wrong_intent_b = registration_statement(
        StableKdfScopeV1::from_context(&fixture_context(0x42)),
        ceremony(PROVENANCE_REGISTRATION_REQUEST_TAG_V1, b_envelope, set),
        snapshot(0x12, 9, 0x32, 41),
        0x82,
        b"registration-anti-bias-fixture",
    );
    assert_eq!(
        RoleInputProvenancePairV1::new(registration_a, wrong_intent_b)
            .expect_err("intent mismatch")
            .field(),
        ProvenancePairFieldV1::RegistrationIntentDigest
    );

    assert!(RoleInputProvenancePairV1::new(registration_statements().0, registration_b).is_ok());
    let _ = a_envelope;
}

#[test]
fn epochs_and_refresh_outer_continuity_fail_closed() {
    assert_eq!(
        RoleRootEpochV1::<DeriverAProvenanceRoleV1>::new(0),
        Err(ProvenanceEpochErrorV1::Zero)
    );
    assert_eq!(
        RoleInputStateEpochV1::<DeriverBProvenanceRoleV1>::new(0),
        Err(ProvenanceEpochErrorV1::Zero)
    );
    let continuity = RefreshContinuityArtifactDigest32V1::from_synthetic_artifact_bytes(
        b"refresh-opposite-delta-fixture",
    )
    .expect("refresh artifact encodes");
    assert_eq!(
        RefreshBranchV1::new(
            snapshot::<DeriverAProvenanceRoleV1>(0x11, 3, 0x31, 11),
            snapshot::<DeriverAProvenanceRoleV1>(0x12, 3, 0x33, 12),
            public_key(),
            continuity,
        ),
        Err(RefreshProvenanceErrorV1::RoleRootRecordChanged)
    );
    assert_eq!(
        RefreshBranchV1::new(
            snapshot::<DeriverAProvenanceRoleV1>(0x11, 3, 0x31, 11),
            snapshot::<DeriverAProvenanceRoleV1>(0x11, 4, 0x33, 12),
            public_key(),
            continuity,
        ),
        Err(RefreshProvenanceErrorV1::RoleRootEpochChanged)
    );
    assert_eq!(
        RefreshBranchV1::new(
            snapshot::<DeriverAProvenanceRoleV1>(0x11, 3, 0x31, 11),
            snapshot::<DeriverAProvenanceRoleV1>(0x11, 3, 0x33, 11),
            public_key(),
            continuity,
        ),
        Err(RefreshProvenanceErrorV1::InputStateEpoch(
            ProvenanceEpochErrorV1::DidNotStrictlyAdvance
        ))
    );
}

#[test]
fn registered_public_key_rejects_identity_invalid_and_torsion_points() {
    let mut identity = [0_u8; 32];
    identity[0] = 1;
    assert!(RegisteredEd25519PublicKey32V1::parse(identity).is_err());
    assert!(RegisteredEd25519PublicKey32V1::parse([0xff; 32]).is_err());
    assert!(RegisteredEd25519PublicKey32V1::parse([0; 32]).is_err());
    assert!(
        RegisteredEd25519PublicKey32V1::parse(ED25519_BASEPOINT_POINT.compress().to_bytes())
            .is_ok()
    );
}

#[test]
fn envelope_set_digest_is_fixed_a_then_b() {
    let (a, b, set) = envelope_artifacts(PROVENANCE_REGISTRATION_REQUEST_TAG_V1);
    let mut input = Vec::new();
    input.extend_from_slice(&lp32(PROVENANCE_CLIENT_ENVELOPE_SET_DIGEST_DOMAIN_V1));
    input.extend_from_slice(&lp32(a.as_bytes()));
    input.extend_from_slice(&lp32(b.as_bytes()));
    assert_eq!(set.as_bytes(), &<[u8; 32]>::from(Sha256::digest(input)));
}

#[test]
fn strict_parser_round_trips_all_statements_and_pairs() {
    for (a, b) in [
        registration_statements(),
        recovery_statements(),
        refresh_statements(),
        export_statements(),
    ] {
        for statement in [
            &a.encode().expect("A encodes"),
            &b.encode().expect("B encodes"),
        ] {
            let parsed = parse_canonical_provenance_statement_v1(statement)
                .expect("canonical statement parses");
            assert_eq!(parsed.encoding(), statement);
            let mut digest_input = Vec::new();
            digest_input.extend_from_slice(&lp32(PROVENANCE_STATEMENT_DIGEST_DOMAIN_V1));
            digest_input.extend_from_slice(&lp32(statement));
            assert_eq!(
                parsed.digest(),
                &<[u8; 32]>::from(Sha256::digest(digest_input))
            );
        }
        let pair = RoleInputProvenancePairV1::new(a, b).expect("pair validates");
        let pair_encoding = pair.encode().expect("pair encodes");
        let parsed_pair =
            parse_canonical_provenance_pair_v1(&pair_encoding).expect("canonical pair parses");
        assert_eq!(parsed_pair.encoding(), pair_encoding);
        assert_eq!(
            parsed_pair.deriver_a_statement_digest(),
            pair.deriver_a().digest().expect("A digest").as_bytes()
        );
        assert_eq!(
            parsed_pair.deriver_b_statement_digest(),
            pair.deriver_b().digest().expect("B digest").as_bytes()
        );
        assert_eq!(
            parsed_pair.digest(),
            pair.digest().expect("pair digest").as_bytes()
        );
    }
}

#[test]
fn parser_rejects_activation_family_digest_and_stable_scope_mutations() {
    let mut encoding = registration_statements()
        .0
        .encode()
        .expect("registration encodes");
    overwrite_lp32_path(&mut encoding, &[2], &[0x02]);
    assert_eq!(
        parse_canonical_provenance_statement_v1(&encoding),
        Err(ProvenanceDecodingErrorV1::UnexpectedValue {
            field: "statement.request_kind"
        })
    );

    let mut encoding = registration_statements()
        .0
        .encode()
        .expect("registration encodes");
    overwrite_lp32_path(&mut encoding, &[4], &[PROVENANCE_EXPORT_FAMILY_TAG_V1]);
    assert_eq!(
        parse_canonical_provenance_statement_v1(&encoding),
        Err(ProvenanceDecodingErrorV1::UnexpectedValue {
            field: "statement.circuit_family"
        })
    );

    let mut encoding = registration_statements()
        .0
        .encode()
        .expect("registration encodes");
    overwrite_lp32_path(&mut encoding, &[6], &[0; 32]);
    assert_eq!(
        parse_canonical_provenance_statement_v1(&encoding),
        Err(ProvenanceDecodingErrorV1::ZeroManifestDigest {
            field: "statement.circuit_digest"
        })
    );

    let mut encoding = registration_statements()
        .0
        .encode()
        .expect("registration encodes");
    overwrite_lp32_path(&mut encoding, &[8, 4], &[0x99; 32]);
    assert_eq!(
        parse_canonical_provenance_statement_v1(&encoding),
        Err(ProvenanceDecodingErrorV1::StableContextBindingMismatch)
    );
}

#[test]
fn parser_rejects_zero_epochs_invalid_points_and_refresh_regression() {
    let mut registration = registration_statements()
        .0
        .encode()
        .expect("registration encodes");
    overwrite_lp32_path(&mut registration, &[10, 1, 3], &[0; 8]);
    assert_eq!(
        parse_canonical_provenance_statement_v1(&registration),
        Err(ProvenanceDecodingErrorV1::ZeroEpoch {
            field: "snapshot.role_root_epoch"
        })
    );

    let mut recovery = recovery_statements().0.encode().expect("recovery encodes");
    let mut identity = [0_u8; 32];
    identity[0] = 1;
    overwrite_lp32_path(&mut recovery, &[10, 2], &identity);
    assert!(matches!(
        parse_canonical_provenance_statement_v1(&recovery),
        Err(ProvenanceDecodingErrorV1::InvalidRegisteredPublicKey(_))
    ));

    let mut refresh = refresh_statements().0.encode().expect("refresh encodes");
    overwrite_lp32_path(&mut refresh, &[10, 2, 5], &11_u64.to_be_bytes());
    assert_eq!(
        parse_canonical_provenance_statement_v1(&refresh),
        Err(ProvenanceDecodingErrorV1::InvalidRefresh(
            RefreshProvenanceErrorV1::InputStateEpoch(
                ProvenanceEpochErrorV1::DidNotStrictlyAdvance
            )
        ))
    );
}

#[test]
fn parser_rejects_truncation_and_trailing_bytes_at_each_outer_shape() {
    let statement = registration_statements()
        .0
        .encode()
        .expect("registration encodes");
    assert!(matches!(
        parse_canonical_provenance_statement_v1(&statement[..statement.len() - 1]),
        Err(ProvenanceDecodingErrorV1::Truncated { .. })
    ));
    let mut trailing_statement = statement;
    trailing_statement.push(0);
    assert_eq!(
        parse_canonical_provenance_statement_v1(&trailing_statement),
        Err(ProvenanceDecodingErrorV1::TrailingBytes { scope: "statement" })
    );

    let (a, b) = registration_statements();
    let pair = RoleInputProvenancePairV1::new(a, b).expect("pair validates");
    let pair_encoding = pair.encode().expect("pair encodes");
    assert!(matches!(
        parse_canonical_provenance_pair_v1(&pair_encoding[..pair_encoding.len() - 1]),
        Err(ProvenanceDecodingErrorV1::Truncated { .. })
    ));
    let mut trailing_pair = pair_encoding;
    trailing_pair.push(0);
    assert_eq!(
        parse_canonical_provenance_pair_v1(&trailing_pair),
        Err(ProvenanceDecodingErrorV1::TrailingBytes { scope: "pair" })
    );
}
