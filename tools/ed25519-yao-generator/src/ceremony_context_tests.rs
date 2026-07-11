use crate::ceremony_context::{
    validate_canonical_authorization_encoding_v1, validate_canonical_ceremony_bundle_v1,
    validate_canonical_public_request_context_encoding_v1,
    validate_canonical_transcript_encoding_v1, CeremonyAccountIdV1,
    CeremonyActivationAuthorizationV1, CeremonyActivationEpochV1, CeremonyArtifactSuiteDigest32V1,
    CeremonyAuthorizationRecordDigest32V1, CeremonyAuthorizationV1, CeremonyChainTargetV1,
    CeremonyClientEphemeralPublicKey32V1, CeremonyContextErrorV1,
    CeremonyCurrentDeriverAInputStateEpochV1, CeremonyCurrentDeriverBInputStateEpochV1,
    CeremonyDeriverABindingV1, CeremonyDeriverAIdV1, CeremonyDeriverAKeyEpochV1,
    CeremonyDeriverBBindingV1, CeremonyDeriverBIdV1, CeremonyDeriverBKeyEpochV1,
    CeremonyDeriverSetIdV1, CeremonyEnvironmentIdV1, CeremonyExportAuthorizationV1,
    CeremonyIdentityScopeV1, CeremonyInfrastructureV1, CeremonyNextDeriverAInputStateEpochV1,
    CeremonyNextDeriverBInputStateEpochV1, CeremonyNumericFieldV1, CeremonyOrganizationIdV1,
    CeremonyPackageSetDigest32V1, CeremonyProjectIdV1, CeremonyPublicRequestContextV1,
    CeremonyRecoveryAuthorizationV1, CeremonyRefreshAuthorizationV1,
    CeremonyRegistrationAuthorizationV1, CeremonyRegistrationIntentDigest32V1,
    CeremonyReplacementCredentialBindingDigest32V1, CeremonyReplayNonce32V1,
    CeremonyRequestExpiryV1, CeremonyRequestIdV1, CeremonyRequestKindV1, CeremonyRootShareEpochV1,
    CeremonyRouterIdV1, CeremonySessionIdV1, CeremonySigningRootIdV1, CeremonySigningRootVersionV1,
    CeremonySigningWorkerBindingV1, CeremonySigningWorkerIdV1, CeremonySigningWorkerKeyEpochV1,
    CeremonyTranscriptNonce32V1, CeremonyTranscriptV1, CeremonyTransportBindingDigest32V1,
    CeremonyValidatedDagV1, CeremonyWalletIdV1,
};
use crate::{
    canonical_ceremony_context_vector_corpus_v1, canonical_ceremony_fixture_dag_v1,
    CeremonyContextVectorCaseV1, RegisteredEd25519PublicKey32V1, RegisteredEd25519PublicKeyErrorV1,
};
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;

fn context(kind: CeremonyRequestKindV1, request_suffix: &str) -> CeremonyPublicRequestContextV1 {
    CeremonyPublicRequestContextV1::new(
        kind,
        CeremonyRequestIdV1::parse(&format!("request-{request_suffix}")).expect("request id"),
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
            CeremonyDeriverSetIdV1::parse("deriver-set").expect("set"),
            CeremonyDeriverABindingV1::new(
                CeremonyDeriverAIdV1::parse("deriver-a").expect("A"),
                CeremonyDeriverAKeyEpochV1::new(3).expect("A epoch"),
            ),
            CeremonyDeriverBBindingV1::new(
                CeremonyDeriverBIdV1::parse("deriver-b").expect("B"),
                CeremonyDeriverBKeyEpochV1::new(4).expect("B epoch"),
            ),
            CeremonySigningWorkerBindingV1::new(
                CeremonySigningWorkerIdV1::parse("signing-worker").expect("worker"),
                CeremonySigningWorkerKeyEpochV1::new(5).expect("worker epoch"),
            ),
        ),
        CeremonyClientEphemeralPublicKey32V1::new([0x22; 32]),
        CeremonyRequestExpiryV1::new(10_000).expect("expiry"),
    )
}

fn record(byte: u8) -> CeremonyAuthorizationRecordDigest32V1 {
    CeremonyAuthorizationRecordDigest32V1::new([byte; 32]).expect("record digest")
}

fn transcript(
    context: &CeremonyPublicRequestContextV1,
    authorization: &CeremonyAuthorizationV1,
) -> CeremonyTranscriptV1 {
    CeremonyTranscriptV1::new(
        context,
        authorization,
        CeremonyTranscriptNonce32V1::new([0x31; 32]),
        CeremonyTransportBindingDigest32V1::new([0x41; 32]).expect("transport"),
        CeremonyArtifactSuiteDigest32V1::new([0x51; 32]).expect("suite"),
    )
    .expect("valid transcript DAG")
}

fn decode_hex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            u8::from_str_radix(std::str::from_utf8(pair).expect("ASCII hex"), 16)
                .expect("valid fixture hex")
        })
        .collect()
}

#[test]
fn five_case_corpus_has_fixed_mapping_and_valid_dag() {
    let corpus = canonical_ceremony_context_vector_corpus_v1();
    assert_eq!(corpus.cases.len(), 5);
    for case in corpus.cases {
        let (kind, expected) = match case {
            CeremonyContextVectorCaseV1::Registration(vector) => {
                (CeremonyRequestKindV1::Registration, vector.expected)
            }
            CeremonyContextVectorCaseV1::Activation(vector) => {
                (CeremonyRequestKindV1::Activation, vector.expected)
            }
            CeremonyContextVectorCaseV1::Recovery(vector) => {
                (CeremonyRequestKindV1::Recovery, vector.expected)
            }
            CeremonyContextVectorCaseV1::Refresh(vector) => {
                (CeremonyRequestKindV1::Refresh, vector.expected)
            }
            CeremonyContextVectorCaseV1::Export(vector) => {
                (CeremonyRequestKindV1::Export, vector.expected)
            }
        };
        let request = decode_hex(&expected.public_request_context_encoding_hex);
        let authorization = decode_hex(&expected.authorization_encoding_hex);
        let transcript = decode_hex(&expected.transcript_encoding_hex);
        validate_canonical_ceremony_bundle_v1(&request, &authorization, &transcript)
            .expect("canonical bundle validates");
        assert_eq!(
            kind.circuit_id(),
            if kind == CeremonyRequestKindV1::Export {
                ed25519_yao::EXPORT_CIRCUIT_ID_STR
            } else {
                ed25519_yao::ACTIVATION_CIRCUIT_ID_STR
            }
        );
        assert_eq!(
            kind.has_evaluation_provenance(),
            kind != CeremonyRequestKindV1::Activation
        );
    }
}

#[test]
fn textual_identifiers_use_exact_visible_ascii_grammar() {
    assert!(matches!(
        CeremonyAccountIdV1::parse(""),
        Err(CeremonyContextErrorV1::EmptyIdentifier(_))
    ));
    assert!(matches!(
        CeremonyWalletIdV1::parse("wallet name"),
        Err(CeremonyContextErrorV1::InvalidIdentifierGrammar(_))
    ));
    assert!(matches!(
        CeremonySessionIdV1::parse("session\n"),
        Err(CeremonyContextErrorV1::InvalidIdentifierGrammar(_))
    ));
    assert!(CeremonyRequestIdV1::parse("request:ABC-123").is_ok());
}

#[test]
fn numeric_and_opaque_fields_reject_zero() {
    assert_eq!(
        CeremonySigningRootVersionV1::new(0),
        Err(CeremonyContextErrorV1::ZeroNumeric(
            CeremonyNumericFieldV1::SigningRootVersion
        ))
    );
    assert!(CeremonyAuthorizationRecordDigest32V1::new([0; 32]).is_err());
    assert!(CeremonyTransportBindingDigest32V1::new([0; 32]).is_err());
    assert!(CeremonyArtifactSuiteDigest32V1::new([0; 32]).is_err());
}

#[test]
fn authorization_constructors_reject_cross_branch_contexts() {
    let export = context(CeremonyRequestKindV1::Export, "export");
    let result = CeremonyRegistrationAuthorizationV1::new(
        &export,
        record(0x10),
        CeremonyRegistrationIntentDigest32V1::new([0x20; 32]).expect("intent"),
    );
    assert_eq!(
        result,
        Err(CeremonyContextErrorV1::AuthorizationRequestKindMismatch)
    );
}

#[test]
fn transcript_rejects_authorization_from_another_context() {
    let first = context(CeremonyRequestKindV1::Registration, "one");
    let second = context(CeremonyRequestKindV1::Registration, "two");
    let authorization = CeremonyRegistrationAuthorizationV1::new(
        &first,
        record(0x10),
        CeremonyRegistrationIntentDigest32V1::new([0x20; 32]).expect("intent"),
    )
    .expect("authorization")
    .into();
    let result = CeremonyTranscriptV1::new(
        &second,
        &authorization,
        CeremonyTranscriptNonce32V1::new([0x30; 32]),
        CeremonyTransportBindingDigest32V1::new([0x40; 32]).expect("transport"),
        CeremonyArtifactSuiteDigest32V1::new([0x50; 32]).expect("suite"),
    );
    assert_eq!(
        result,
        Err(CeremonyContextErrorV1::AuthorizationContextDigestMismatch)
    );
}

#[test]
fn refresh_requires_strict_advancement_for_both_roles() {
    let request = context(CeremonyRequestKindV1::Refresh, "refresh");
    let result = CeremonyRefreshAuthorizationV1::new(
        &request,
        record(0x10),
        CeremonyCurrentDeriverAInputStateEpochV1::new(7).expect("current A"),
        CeremonyNextDeriverAInputStateEpochV1::new(7).expect("next A"),
        CeremonyCurrentDeriverBInputStateEpochV1::new(9).expect("current B"),
        CeremonyNextDeriverBInputStateEpochV1::new(10).expect("next B"),
    );
    assert_eq!(
        result,
        Err(CeremonyContextErrorV1::RefreshEpochDidNotStrictlyAdvance(
            CeremonyNumericFieldV1::NextDeriverAInputStateEpoch
        ))
    );
}

#[test]
fn activation_binds_origin_and_stays_out_of_evaluation_provenance() {
    let origin = context(CeremonyRequestKindV1::Registration, "origin");
    let origin_authorization: CeremonyAuthorizationV1 = CeremonyRegistrationAuthorizationV1::new(
        &origin,
        record(0x10),
        CeremonyRegistrationIntentDigest32V1::new([0x20; 32]).expect("intent"),
    )
    .expect("origin authorization")
    .into();
    let origin_transcript = transcript(&origin, &origin_authorization);
    let origin_dag =
        CeremonyValidatedDagV1::from_components(&origin, &origin_authorization, &origin_transcript)
            .expect("origin DAG");
    let activation = context(CeremonyRequestKindV1::Activation, "activation");
    let authorization = CeremonyActivationAuthorizationV1::new(
        &activation,
        record(0x11),
        origin_dag.activation_origin().expect("registration origin"),
        CeremonyPackageSetDigest32V1::new([0x33; 32]).expect("package set"),
        CeremonyActivationEpochV1::new(4).expect("activation epoch"),
    )
    .expect("activation authorization");
    assert!(!CeremonyRequestKindV1::Activation.has_evaluation_provenance());
    assert!(CeremonyAuthorizationV1::from(authorization)
        .encode()
        .is_ok());
}

#[test]
fn activation_origin_accepts_registration_recovery_and_refresh_dags() {
    for kind in [
        CeremonyRequestKindV1::Registration,
        CeremonyRequestKindV1::Recovery,
        CeremonyRequestKindV1::Refresh,
    ] {
        let activation = context(CeremonyRequestKindV1::Activation, kind.as_str());
        let authorization: CeremonyAuthorizationV1 = CeremonyActivationAuthorizationV1::new(
            &activation,
            record(0x11),
            canonical_ceremony_fixture_dag_v1(kind)
                .activation_origin()
                .expect("evaluation ceremony is eligible as an activation origin"),
            CeremonyPackageSetDigest32V1::new([0x33; 32]).expect("package set"),
            CeremonyActivationEpochV1::new(4).expect("activation epoch"),
        )
        .expect("activation authorization accepts the coherent origin")
        .into();
        let activation_transcript = transcript(&activation, &authorization);
        CeremonyValidatedDagV1::from_components(
            &activation,
            &authorization,
            &activation_transcript,
        )
        .expect("activation DAG remains coherent");
    }
}

#[test]
fn activation_origin_rejects_activation_and_export_dags() {
    let export = context(CeremonyRequestKindV1::Export, "origin-export");
    let export_authorization: CeremonyAuthorizationV1 = CeremonyExportAuthorizationV1::new(
        &export,
        record(0x10),
        RegisteredEd25519PublicKey32V1::parse(ED25519_BASEPOINT_POINT.compress().to_bytes())
            .expect("public key"),
    )
    .expect("export authorization")
    .into();
    let export_transcript = transcript(&export, &export_authorization);
    let export_dag =
        CeremonyValidatedDagV1::from_components(&export, &export_authorization, &export_transcript)
            .expect("export DAG");
    assert_eq!(
        export_dag.activation_origin(),
        Err(CeremonyContextErrorV1::InvalidActivationOriginRequestKind)
    );

    let registration = context(CeremonyRequestKindV1::Registration, "origin-registration");
    let registration_authorization: CeremonyAuthorizationV1 =
        CeremonyRegistrationAuthorizationV1::new(
            &registration,
            record(0x11),
            CeremonyRegistrationIntentDigest32V1::new([0x21; 32]).expect("intent"),
        )
        .expect("registration authorization")
        .into();
    let registration_transcript = transcript(&registration, &registration_authorization);
    let registration_origin = CeremonyValidatedDagV1::from_components(
        &registration,
        &registration_authorization,
        &registration_transcript,
    )
    .expect("registration DAG")
    .activation_origin()
    .expect("registration origin");
    let activation = context(CeremonyRequestKindV1::Activation, "origin-activation");
    let activation_authorization: CeremonyAuthorizationV1 = CeremonyActivationAuthorizationV1::new(
        &activation,
        record(0x12),
        registration_origin,
        CeremonyPackageSetDigest32V1::new([0x32; 32]).expect("package set"),
        CeremonyActivationEpochV1::new(4).expect("activation epoch"),
    )
    .expect("activation authorization")
    .into();
    let activation_transcript = transcript(&activation, &activation_authorization);
    let activation_dag = CeremonyValidatedDagV1::from_components(
        &activation,
        &activation_authorization,
        &activation_transcript,
    )
    .expect("activation DAG");
    assert_eq!(
        activation_dag.activation_origin(),
        Err(CeremonyContextErrorV1::InvalidActivationOriginRequestKind)
    );
}

#[test]
fn export_authorization_requires_a_canonical_prime_subgroup_key() {
    assert_eq!(
        RegisteredEd25519PublicKey32V1::parse([
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0
        ]),
        Err(RegisteredEd25519PublicKeyErrorV1::Identity)
    );
    let key = RegisteredEd25519PublicKey32V1::parse(ED25519_BASEPOINT_POINT.compress().to_bytes())
        .expect("basepoint is valid");
    let request = context(CeremonyRequestKindV1::Export, "export");
    assert!(CeremonyExportAuthorizationV1::new(&request, record(0x10), key).is_ok());
}

#[test]
fn strict_decoders_reject_reordered_mutated_and_trailing_bytes() {
    let request = context(CeremonyRequestKindV1::Recovery, "recovery");
    let authorization: CeremonyAuthorizationV1 = CeremonyRecoveryAuthorizationV1::new(
        &request,
        record(0x10),
        CeremonyReplacementCredentialBindingDigest32V1::new([0x20; 32]).expect("replacement"),
    )
    .expect("authorization")
    .into();
    let transcript = transcript(&request, &authorization);
    let mut request_bytes = request.encode().expect("request encodes");
    let authorization_bytes = authorization.encode().expect("authorization encodes");
    let mut transcript_bytes = transcript.encode().expect("transcript encodes");
    validate_canonical_public_request_context_encoding_v1(&request_bytes)
        .expect("request validates");
    validate_canonical_authorization_encoding_v1(&authorization_bytes)
        .expect("authorization validates");
    validate_canonical_transcript_encoding_v1(&transcript_bytes).expect("transcript validates");
    let mut version_two = request_bytes.clone();
    let version_offset = version_two
        .windows(8)
        .position(|window| window == 1_u64.to_be_bytes())
        .expect("protocol version occurs in request context");
    version_two[version_offset..version_offset + 8].copy_from_slice(&2_u64.to_be_bytes());
    assert!(validate_canonical_public_request_context_encoding_v1(&version_two).is_err());
    request_bytes[4] ^= 1;
    assert!(validate_canonical_public_request_context_encoding_v1(&request_bytes).is_err());
    let mut authorization_trailing = authorization_bytes.clone();
    authorization_trailing.push(0);
    assert!(validate_canonical_authorization_encoding_v1(&authorization_trailing).is_err());
    transcript_bytes.push(0);
    assert!(validate_canonical_transcript_encoding_v1(&transcript_bytes).is_err());
}

#[test]
fn bundle_validator_detects_digest_edge_mutation() {
    let request = context(CeremonyRequestKindV1::Export, "export");
    let authorization: CeremonyAuthorizationV1 = CeremonyExportAuthorizationV1::new(
        &request,
        record(0x10),
        RegisteredEd25519PublicKey32V1::parse(ED25519_BASEPOINT_POINT.compress().to_bytes())
            .expect("public key"),
    )
    .expect("authorization")
    .into();
    let transcript = transcript(&request, &authorization);
    let request_bytes = request.encode().expect("request");
    let authorization_bytes = authorization.encode().expect("authorization");
    let mut transcript_bytes = transcript.encode().expect("transcript");
    let digest = request.digest().expect("digest");
    let offset = transcript_bytes
        .windows(32)
        .position(|window| window == digest.as_bytes())
        .expect("request digest occurs in transcript");
    transcript_bytes[offset] ^= 1;
    assert_eq!(
        validate_canonical_ceremony_bundle_v1(
            &request_bytes,
            &authorization_bytes,
            &transcript_bytes,
        ),
        Err(CeremonyContextErrorV1::TranscriptContextDigestMismatch)
    );
}
