use router_ab_core::{
    decode_ecdsa_threshold_prf_outer_request_v2, decode_ecdsa_threshold_prf_private_request_v2,
    evaluate_mpc_prf_stable_signer_partial_with_threshold_backend_v2,
    plan_mpc_prf_stable_purpose_binding_v2, EcdsaThresholdPrfOuterRequestV2,
    EcdsaThresholdPrfPrivateRequestV2, EcdsaThresholdPrfPurposeV2, EncryptedPayloadV1,
    MpcPrfShareCommitmentWireV1, MpcPrfSigningRootShareWireV1, MpcPrfStableThresholdSignerInputV2,
    Role, RoleEncryptedEnvelopeV1, StableTenantDerivationContextV2, TenantRootActiveRootPairV1,
    TenantRootCeremonyContextV1, TenantRootCeremonyEpochsV1, TenantRootCeremonyNonceV1,
    TenantRootCeremonySessionIdV1, TenantRootCustodyBindingV1, TenantRootDerivationNonceV1,
    TenantRootDerivationOperationIdV1, TenantRootDerivationSessionIdV1,
    TenantRootDeriverIdentitiesV1, TenantRootOnlineRoleShareBindingV1,
    TenantRootOnlineRoleShareSealRequestV1, TenantRootProtocolDigestV1, TenantRootShareEpoch,
    TenantRootSignedShareInstallationEvidenceV1,
};
use threshold_prf::{
    PrfPurpose, SigningRootShareCommitment, SigningRootShareWire, TwoPartyDeriverRole,
};

mod support;

fn private_request() -> EcdsaThresholdPrfPrivateRequestV2 {
    EcdsaThresholdPrfPrivateRequestV2::new(
        StableTenantDerivationContextV2::new([0x42; 32]),
        TenantRootProtocolDigestV1::from_bytes([0x43; 32]).unwrap(),
        EcdsaThresholdPrfPurposeV2::XClientBase,
    )
    .unwrap()
}

fn envelope(role: Role, seed: u8) -> RoleEncryptedEnvelopeV1 {
    RoleEncryptedEnvelopeV1::new(
        role,
        router_ab_core::PublicDigest32::new([seed; 32]),
        router_ab_core::PublicDigest32::new([seed + 1; 32]),
        EncryptedPayloadV1::new(vec![seed; 16]).unwrap(),
    )
    .unwrap()
}

fn outer_request() -> EcdsaThresholdPrfOuterRequestV2 {
    EcdsaThresholdPrfOuterRequestV2::new(
        TenantRootDerivationNonceV1::from_bytes([0x51; 32]).unwrap(),
        support::ISSUED_AT_MS,
        support::EXPIRES_AT_MS,
        private_request(),
        envelope(Role::SignerA, 0x61),
        envelope(Role::SignerB, 0x71),
    )
    .unwrap()
}

fn authenticated_deriver_a_share() -> (
    StableTenantDerivationContextV2,
    TenantRootCustodyBindingV1,
    TenantRootActiveRootPairV1,
    router_ab_core::VerifiedTenantRootOnlineRoleShareV1,
) {
    let identity = support::identity();
    let lineage = support::lineage();
    let ceremony_context = TenantRootCeremonyContextV1::new(
        identity.digest().unwrap(),
        lineage,
        TenantRootCeremonyEpochsV1::create(),
        TenantRootCeremonySessionIdV1::from_bytes([0x71; 16]).unwrap(),
        TenantRootCeremonyNonceV1::from_bytes([0x72; 32]).unwrap(),
        support::ISSUED_AT_MS,
        support::EXPIRES_AT_MS,
        "deriver-a-signing-key-7",
        "deriver-b-signing-key-9",
    )
    .unwrap();
    let share_a = support::fixed_share(TwoPartyDeriverRole::DeriverA, 12);
    let share_b = support::fixed_share(TwoPartyDeriverRole::DeriverB, 19);
    let fixture =
        support::initial_activation_evidence_fixture(ceremony_context, &share_a, &share_b, 21, 22);
    let activation = support::initial_activation_receipt(&fixture.bundle, 1_020_000);
    let (installation_a, _) = fixture.bundle.into_installation_evidence_bytes();
    let role_key = support::signing_key(TwoPartyDeriverRole::DeriverA);
    let installation_a =
        TenantRootSignedShareInstallationEvidenceV1::decode_and_verify_canonical_bytes(
            &installation_a,
            role_key.verifying_key().as_bytes(),
        )
        .unwrap();
    let stable_context = StableTenantDerivationContextV2::new([0x42; 32]);
    let custody_binding = TenantRootCustodyBindingV1::from_verified_activation_receipt(
        &activation,
        TenantRootDeriverIdentitiesV1::new("deriver-a-runtime-7", "deriver-b-runtime-9").unwrap(),
        TenantRootDerivationOperationIdV1::from_bytes([0x81; 16]).unwrap(),
        TenantRootDerivationSessionIdV1::from_bytes([0x82; 16]).unwrap(),
        TenantRootDerivationNonceV1::from_bytes([0x83; 32]).unwrap(),
        support::ISSUED_AT_MS,
        support::EXPIRES_AT_MS,
        &stable_context,
        TenantRootProtocolDigestV1::from_bytes([0x84; 32]).unwrap(),
    )
    .unwrap();
    let active_pair =
        TenantRootActiveRootPairV1::from_verified_activation_receipt(&activation).unwrap();
    let share_binding = TenantRootOnlineRoleShareBindingV1::new(
        identity.digest().unwrap(),
        lineage,
        TwoPartyDeriverRole::DeriverA,
        TenantRootShareEpoch::INITIAL,
        MpcPrfShareCommitmentWireV1::new(
            SigningRootShareCommitment::from_share(&share_a)
                .to_bytes()
                .to_vec(),
        )
        .unwrap(),
        "kms/tenant-root/deriver-a/epoch-1",
        &installation_a,
    )
    .unwrap();
    let sealed = TenantRootOnlineRoleShareSealRequestV1::new(
        share_binding,
        SigningRootShareWire::from_share(&share_a),
    )
    .unwrap()
    .complete(vec![0xa5; 96])
    .unwrap();
    let verified = sealed
        .verify_opened_share(SigningRootShareWire::from_share(&share_a))
        .unwrap();
    (stable_context, custody_binding, active_pair, verified)
}

#[test]
fn private_request_canonical_bytes_round_trip_strictly() {
    let request = private_request();
    let bytes = request.canonical_bytes();
    let decoded = decode_ecdsa_threshold_prf_private_request_v2(&bytes).unwrap();
    assert_eq!(decoded, request);
    assert_eq!(decoded.canonical_bytes(), bytes);

    let mut with_trailing_bytes = bytes;
    with_trailing_bytes.push(0);
    assert!(decode_ecdsa_threshold_prf_private_request_v2(&with_trailing_bytes).is_err());
}

#[test]
fn outer_request_canonical_bytes_round_trip_and_role_swaps_fail() {
    let request = outer_request();
    let bytes = request.canonical_bytes();
    let decoded = decode_ecdsa_threshold_prf_outer_request_v2(&bytes).unwrap();
    assert_eq!(decoded, request);
    assert_eq!(decoded.canonical_bytes(), bytes);
    assert!(EcdsaThresholdPrfOuterRequestV2::new(
        TenantRootDerivationNonceV1::from_bytes([0x51; 32]).unwrap(),
        support::ISSUED_AT_MS,
        support::EXPIRES_AT_MS,
        private_request(),
        envelope(Role::SignerB, 0x61),
        envelope(Role::SignerB, 0x71),
    )
    .is_err());
}

#[test]
fn private_request_requires_the_authenticated_custody_digest_and_context() {
    let (stable_context, custody_binding, _, _) = authenticated_deriver_a_share();
    let valid = EcdsaThresholdPrfPrivateRequestV2::new(
        stable_context.clone(),
        custody_binding.digest().unwrap(),
        EcdsaThresholdPrfPurposeV2::XClientBase,
    )
    .unwrap();
    valid
        .validate_for_custody(&custody_binding, support::ISSUED_AT_MS)
        .unwrap();

    let wrong_digest = EcdsaThresholdPrfPrivateRequestV2::new(
        stable_context.clone(),
        TenantRootProtocolDigestV1::from_bytes([0x85; 32]).unwrap(),
        EcdsaThresholdPrfPurposeV2::XClientBase,
    )
    .unwrap();
    assert!(wrong_digest
        .validate_for_custody(&custody_binding, support::ISSUED_AT_MS)
        .is_err());

    let wrong_context = EcdsaThresholdPrfPrivateRequestV2::new(
        StableTenantDerivationContextV2::new([0x86; 32]),
        custody_binding.digest().unwrap(),
        EcdsaThresholdPrfPurposeV2::XClientBase,
    )
    .unwrap();
    assert!(wrong_context
        .validate_for_custody(&custody_binding, support::ISSUED_AT_MS)
        .is_err());
}

#[test]
fn backend_input_derives_role_from_the_verified_online_share() {
    let (stable_context, custody_binding, active_pair, verified_share) =
        authenticated_deriver_a_share();
    let request = EcdsaThresholdPrfPrivateRequestV2::new(
        stable_context,
        custody_binding.digest().unwrap(),
        EcdsaThresholdPrfPurposeV2::XClientBase,
    )
    .unwrap();
    let input = MpcPrfStableThresholdSignerInputV2::from_private_request(
        &request,
        &custody_binding,
        &active_pair,
        verified_share,
        support::ISSUED_AT_MS,
    )
    .unwrap();
    let output = evaluate_mpc_prf_stable_signer_partial_with_threshold_backend_v2(
        input,
        &mut support::rng06(91),
    )
    .unwrap();
    assert_eq!(output.signer_role, Role::SignerA);
    assert_eq!(
        output.purpose_plan.purpose().as_bytes(),
        b"router-ab/x_client_base/v1"
    );
}

#[test]
fn tenant_root_share_backed_v2_matches_prior_stable_derivation_for_each_purpose() {
    for (purpose, proof_seed) in [
        (EcdsaThresholdPrfPurposeV2::XClientBase, 0x91),
        (EcdsaThresholdPrfPurposeV2::XServerBase, 0x92),
        (EcdsaThresholdPrfPurposeV2::YServer, 0x93),
    ] {
        let (stable_context, custody_binding, active_pair, verified_share) =
            authenticated_deriver_a_share();
        let purpose_plan = plan_mpc_prf_stable_purpose_binding_v2(
            &stable_context,
            &custody_binding,
            purpose.threshold_prf_purpose(),
        )
        .unwrap();
        let prior_input = MpcPrfStableThresholdSignerInputV2::new(
            purpose_plan.clone(),
            &custody_binding,
            &active_pair,
            Role::SignerA,
            MpcPrfSigningRootShareWireV1::new(
                SigningRootShareWire::from_share(&support::fixed_share(
                    TwoPartyDeriverRole::DeriverA,
                    12,
                ))
                .to_bytes()
                .to_vec(),
            )
            .unwrap(),
            support::ISSUED_AT_MS,
        )
        .unwrap();
        let share_backed_input =
            MpcPrfStableThresholdSignerInputV2::from_verified_online_role_share(
                purpose_plan,
                &custody_binding,
                &active_pair,
                verified_share,
                support::ISSUED_AT_MS,
            )
            .unwrap();

        let prior = evaluate_mpc_prf_stable_signer_partial_with_threshold_backend_v2(
            prior_input,
            &mut support::rng06(proof_seed),
        )
        .unwrap();
        let share_backed = evaluate_mpc_prf_stable_signer_partial_with_threshold_backend_v2(
            share_backed_input,
            &mut support::rng06(proof_seed),
        )
        .unwrap();

        assert_eq!(share_backed, prior, "purpose {purpose:?} changed");
    }
}

#[test]
fn one_verified_share_batch_matches_separate_v2_evaluations() {
    let (batch_context, batch_custody, batch_active_pair, batch_share) =
        authenticated_deriver_a_share();
    let mut batch_rng = support::rng06(0xa4);
    let (batch_client, batch_server) =
        MpcPrfStableThresholdSignerInputV2::evaluate_x_client_and_x_server_batch_with_threshold_backend_v2(
            &batch_context,
            &batch_custody,
            &batch_active_pair,
            batch_share,
            support::ISSUED_AT_MS,
            &mut batch_rng,
        )
        .unwrap();

    let (client_context, client_custody, client_active_pair, client_share) =
        authenticated_deriver_a_share();
    let client_plan = plan_mpc_prf_stable_purpose_binding_v2(
        &client_context,
        &client_custody,
        PrfPurpose::RouterAbXClientBaseV1,
    )
    .unwrap();
    let client_input = MpcPrfStableThresholdSignerInputV2::from_verified_online_role_share(
        client_plan,
        &client_custody,
        &client_active_pair,
        client_share,
        support::ISSUED_AT_MS,
    )
    .unwrap();

    let (server_context, server_custody, server_active_pair, server_share) =
        authenticated_deriver_a_share();
    let server_plan = plan_mpc_prf_stable_purpose_binding_v2(
        &server_context,
        &server_custody,
        PrfPurpose::RouterAbXServerBaseV1,
    )
    .unwrap();
    let server_input = MpcPrfStableThresholdSignerInputV2::from_verified_online_role_share(
        server_plan,
        &server_custody,
        &server_active_pair,
        server_share,
        support::ISSUED_AT_MS,
    )
    .unwrap();
    let mut separate_rng = support::rng06(0xa4);
    let separate_client = evaluate_mpc_prf_stable_signer_partial_with_threshold_backend_v2(
        client_input,
        &mut separate_rng,
    )
    .unwrap();
    let separate_server = evaluate_mpc_prf_stable_signer_partial_with_threshold_backend_v2(
        server_input,
        &mut separate_rng,
    )
    .unwrap();

    assert_eq!(batch_client, separate_client);
    assert_eq!(batch_server, separate_server);
    assert_eq!(
        batch_client.purpose_plan.purpose().as_bytes(),
        b"router-ab/x_client_base/v1"
    );
    assert_eq!(
        batch_server.purpose_plan.purpose().as_bytes(),
        b"router-ab/x_server_base/v1"
    );
}
