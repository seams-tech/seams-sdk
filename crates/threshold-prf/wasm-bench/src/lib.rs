#![forbid(unsafe_code)]

use std::hint::black_box;

use ed25519_dalek::SigningKey;
use rand_chacha::ChaCha20Rng;
use rand_chacha_09::ChaCha20Rng as HpkeRng;
use rand_core::SeedableRng;
use rand_core_09::SeedableRng as SeedableRng09;
use router_ab_core::{
    seal_tenant_root_refresh_contribution_v1, verify_tenant_root_creation_evidence_v1,
    verify_tenant_root_refresh_evidence_v1, RouterAbDerivationError, RouterAbDerivationErrorCode,
    StableTenantDerivationContextV2, TenantRootCeremonyContextV1, TenantRootCeremonyEpochsV1,
    TenantRootCeremonyNonceV1, TenantRootCeremonySessionIdV1, TenantRootCustodyLineageId,
    TenantRootIdentityV1, TenantRootRefreshCommitmentTranscriptV1,
    TenantRootRefreshContributionAadV1, TenantRootRefreshHpkeKeypairV1, TenantRootShareEpoch,
    TenantRootShareInstallationEvidenceV1, TenantRootShareInstallationTranscriptV1,
    TenantRootSignedRefreshCommitmentV1, TenantRootSignedRefreshContributionV1,
    TenantRootSignedShareInstallationEvidenceV1,
};
use threshold_prf::trusted::combine_partials;
use threshold_prf::{
    apply_two_party_root_share_refresh, combine_verified_partials,
    complete_ed25519_deriver_a_target_v1, complete_ed25519_deriver_b_target_v1, evaluate_partial,
    evaluate_partial_with_dleq_proof, generate_signing_root, generate_two_party_root_share,
    prepare_ed25519_deriver_a_target_v1, prepare_ed25519_deriver_b_target_v1,
    prove_root_share_knowledge, split_signing_root, verify_partial_dleq_proof,
    verify_root_share_knowledge, verify_two_party_root_share_refresh, RootShareRefreshCoefficient,
    SigningRootShare, SigningRootShareCommitment, ThresholdPolicy, ThresholdPrfError,
    TwoPartyDeriverRole, TwoPartyRootShareCommitments, ValidatedThresholdSet,
};
use threshold_prf::{PrfContext, PrfPurpose, SuiteId};
use wasm_bindgen::prelude::*;

const R120_STABLE_CONTEXT: &[u8] = b"ed25519-yao/stable-context/v1/wasm-vector";
const R120_EXPECTED_REFRESH_NEXT_A: [u8; 32] = [
    3, 156, 214, 26, 62, 101, 115, 59, 50, 207, 6, 70, 190, 82, 71, 26, 8, 155, 95, 197, 100, 129,
    102, 124, 210, 211, 204, 147, 240, 177, 188, 8,
];
const R120_EXPECTED_REFRESH_NEXT_B: [u8; 32] = [
    131, 145, 138, 179, 23, 134, 223, 217, 172, 196, 168, 105, 215, 204, 236, 84, 45, 100, 45, 16,
    215, 109, 75, 239, 178, 50, 56, 255, 28, 84, 12, 0,
];
const R120_EXPECTED_ECDSA_OUTPUTS: [[u8; 32]; 3] = [
    [
        138, 0, 240, 126, 116, 233, 86, 28, 186, 71, 145, 83, 120, 130, 162, 132, 164, 80, 68, 1,
        242, 172, 124, 43, 109, 77, 15, 143, 21, 169, 185, 10,
    ],
    [
        2, 185, 251, 222, 212, 224, 187, 149, 150, 77, 145, 249, 8, 186, 29, 79, 25, 15, 237, 99,
        4, 195, 107, 68, 96, 114, 157, 73, 133, 147, 186, 8,
    ],
    [
        67, 93, 244, 178, 100, 188, 81, 176, 178, 11, 6, 210, 92, 79, 144, 116, 17, 52, 171, 134,
        124, 116, 128, 11, 172, 41, 27, 19, 36, 144, 171, 30,
    ],
];
const R120_EXPECTED_ED25519_A_OUTPUT: [u8; 32] = [
    181, 120, 235, 133, 63, 204, 132, 158, 226, 80, 189, 102, 54, 82, 51, 155, 64, 5, 75, 44, 163,
    28, 194, 142, 125, 143, 184, 109, 238, 130, 26, 217,
];
const R120_EXPECTED_ED25519_B_OUTPUT: [u8; 32] = [
    172, 111, 76, 101, 250, 127, 71, 82, 134, 163, 4, 66, 231, 108, 72, 72, 216, 147, 86, 58, 217,
    127, 244, 97, 146, 205, 38, 11, 183, 199, 164, 249,
];

/// Executes the R120 refresh, continuity, and share-knowledge vector in WASM.
#[wasm_bindgen]
pub fn verify_r120_share_refresh_vector() -> bool {
    run_r120_share_refresh_vector().is_ok()
}

/// Executes the distributed tenant-root creation vector in WASM.
#[wasm_bindgen]
pub fn verify_r120_tenant_root_creation_vector() -> bool {
    run_r120_tenant_root_creation_vector().is_ok()
}

/// Executes the refresh-invariant ECDSA threshold-PRF vector in WASM.
#[wasm_bindgen]
pub fn verify_r120_ecdsa_refresh_invariance_vector() -> bool {
    run_r120_ecdsa_refresh_invariance_vector().is_ok()
}

/// Executes the fixed-direction Ed25519 A/B target vector in WASM.
#[wasm_bindgen]
pub fn verify_r120_ed25519_role_target_vector() -> bool {
    run_r120_ed25519_role_target_vector().is_ok()
}

/// Executes the exact signed and recipient-encrypted tenant-root refresh vector in WASM.
#[wasm_bindgen]
pub fn verify_r120_tenant_root_outer_protocol_vector() -> bool {
    run_r120_tenant_root_outer_protocol_vector().is_ok()
}

#[wasm_bindgen]
pub fn benchmark_one_runtime_2_of_3(iterations: u32) -> u8 {
    let (policy, shares, context) = fixture(2, 3);
    let mut checksum = 0u8;

    for _ in 0..iterations {
        let partials = ValidatedThresholdSet::from_partials(
            policy,
            vec![
                evaluate_partial(black_box(&shares[0]), black_box(&context))
                    .expect("benchmark context is valid"),
                evaluate_partial(black_box(&shares[2]), black_box(&context))
                    .expect("benchmark context is valid"),
            ],
        )
        .expect("benchmark partial set is valid");
        let output =
            combine_partials(black_box(&partials), black_box(&context)).expect("partials combine");
        checksum ^= output.as_bytes()[0];
    }

    checksum
}

#[wasm_bindgen]
pub fn benchmark_one_runtime_3_of_5(iterations: u32) -> u8 {
    let (policy, shares, context) = fixture(3, 5);
    let mut checksum = 0u8;

    for _ in 0..iterations {
        let partials = ValidatedThresholdSet::from_partials(
            policy,
            vec![
                evaluate_partial(black_box(&shares[0]), black_box(&context))
                    .expect("benchmark context is valid"),
                evaluate_partial(black_box(&shares[2]), black_box(&context))
                    .expect("benchmark context is valid"),
                evaluate_partial(black_box(&shares[4]), black_box(&context))
                    .expect("benchmark context is valid"),
            ],
        )
        .expect("benchmark partial set is valid");
        let output =
            combine_partials(black_box(&partials), black_box(&context)).expect("partials combine");
        checksum ^= output.as_bytes()[0];
    }

    checksum
}

#[wasm_bindgen]
pub fn benchmark_dleq_prove(iterations: u32) -> u8 {
    let (_, shares, context) = fixture(3, 5);
    let mut rng = seeded_rng(8);
    let mut checksum = 0u8;

    for _ in 0..iterations {
        let bundle = evaluate_partial_with_dleq_proof(
            black_box(&shares[0]),
            black_box(&context),
            black_box(&mut rng),
        )
        .expect("benchmark proof generation succeeds");
        checksum ^= bundle.proof.to_bytes()[0];
    }

    checksum
}

#[wasm_bindgen]
pub fn benchmark_dleq_combine_verified_3_of_5(iterations: u32) -> u8 {
    let (policy, shares, context) = fixture(3, 5);
    let proof_bundles = ValidatedThresholdSet::from_proof_bundles(
        policy,
        vec![
            evaluate_partial_with_dleq_proof(&shares[0], &context, &mut seeded_rng(9))
                .expect("benchmark proof fixture"),
            evaluate_partial_with_dleq_proof(&shares[2], &context, &mut seeded_rng(10))
                .expect("benchmark proof fixture"),
            evaluate_partial_with_dleq_proof(&shares[4], &context, &mut seeded_rng(11))
                .expect("benchmark proof fixture"),
        ],
    )
    .expect("benchmark proof set is valid");
    let mut checksum = 0u8;

    for _ in 0..iterations {
        let output = combine_verified_partials(black_box(&proof_bundles), black_box(&context))
            .expect("benchmark verified combine succeeds");
        checksum ^= output.as_bytes()[0];
    }

    checksum
}

#[wasm_bindgen]
pub fn benchmark_dleq_verify(iterations: u32) -> u8 {
    let (_, shares, context) = fixture(3, 5);
    let mut rng = seeded_rng(12);
    let bundle = evaluate_partial_with_dleq_proof(&shares[0], &context, &mut rng)
        .expect("benchmark proof fixture");
    let mut checksum = 0u8;

    for _ in 0..iterations {
        verify_partial_dleq_proof(
            black_box(&bundle.commitment),
            black_box(&bundle.partial),
            black_box(&context),
            black_box(&bundle.proof),
        )
        .expect("benchmark proof verifies");
        checksum ^= bundle.proof.challenge_bytes()[0];
    }

    checksum
}

fn fixture(
    threshold: u16,
    share_count: u16,
) -> (ThresholdPolicy, Vec<SigningRootShare>, PrfContext) {
    let mut rng = seeded_rng(42);
    let root = generate_signing_root(&mut rng);
    let policy =
        ThresholdPolicy::from_u16s(threshold, share_count).expect("benchmark policy is valid");
    let shares = split_signing_root(&root, policy, &mut rng).expect("benchmark split succeeds");
    let context = PrfContext::new(
        SuiteId::Ristretto255Sha512,
        PrfPurpose::RouterAbEcdsaDerivationYServer,
        b"project:alpha/wallet:0",
    );
    (policy, shares, context)
}

fn seeded_rng(seed: u8) -> ChaCha20Rng {
    ChaCha20Rng::from_seed([seed; 32])
}

fn hpke_rng(seed: u8) -> HpkeRng {
    HpkeRng::from_seed([seed; 32])
}

fn two_party_shares() -> (SigningRootShare, SigningRootShare) {
    let (_, mut shares, _) = fixture(2, 2);
    (shares.remove(0), shares.remove(0))
}

fn refresh_role_share(
    current: &SigningRootShare,
    recipient: TwoPartyDeriverRole,
    coefficient_a: &RootShareRefreshCoefficient,
    coefficient_b: &RootShareRefreshCoefficient,
) -> Result<SigningRootShare, ThresholdPrfError> {
    let contribution_a = coefficient_a
        .commitment()
        .verify_contribution(coefficient_a.contribution_for(recipient))?;
    let contribution_b = coefficient_b
        .commitment()
        .verify_contribution(coefficient_b.contribution_for(recipient))?;
    apply_two_party_root_share_refresh(current, contribution_a, contribution_b)
}

fn refreshed_two_party_shares(
    current_a: &SigningRootShare,
    current_b: &SigningRootShare,
) -> Result<(SigningRootShare, SigningRootShare), ThresholdPrfError> {
    let coefficient_a =
        RootShareRefreshCoefficient::random(TwoPartyDeriverRole::DeriverA, &mut seeded_rng(51));
    let coefficient_b =
        RootShareRefreshCoefficient::random(TwoPartyDeriverRole::DeriverB, &mut seeded_rng(52));
    let next_a = refresh_role_share(
        current_a,
        TwoPartyDeriverRole::DeriverA,
        &coefficient_a,
        &coefficient_b,
    )?;
    let next_b = refresh_role_share(
        current_b,
        TwoPartyDeriverRole::DeriverB,
        &coefficient_a,
        &coefficient_b,
    )?;
    Ok((next_a, next_b))
}

fn run_r120_share_refresh_vector() -> Result<(), ThresholdPrfError> {
    let (current_a, current_b) = two_party_shares();
    let current = TwoPartyRootShareCommitments::from_shares(&current_a, &current_b)?;
    let (next_a, next_b) = refreshed_two_party_shares(&current_a, &current_b)?;
    if next_a.to_bytes() != R120_EXPECTED_REFRESH_NEXT_A
        || next_b.to_bytes() != R120_EXPECTED_REFRESH_NEXT_B
    {
        return Err(ThresholdPrfError::RefreshContinuityMismatch);
    }
    let next = TwoPartyRootShareCommitments::from_shares(&next_a, &next_b)?;
    verify_two_party_root_share_refresh(&current, &next)?;
    let transcript = b"seams/r120/wasm-refresh-installation/v1";
    let proof_a = prove_root_share_knowledge(&next_a, transcript, &mut seeded_rng(53))?;
    let proof_b = prove_root_share_knowledge(&next_b, transcript, &mut seeded_rng(54))?;
    verify_root_share_knowledge(
        &SigningRootShareCommitment::from_share(&next_a),
        transcript,
        &proof_a,
    )?;
    verify_root_share_knowledge(
        &SigningRootShareCommitment::from_share(&next_b),
        transcript,
        &proof_b,
    )
}

fn run_r120_tenant_root_creation_vector() -> Result<(), RouterAbDerivationError> {
    let share_a = generate_two_party_root_share(TwoPartyDeriverRole::DeriverA, &mut seeded_rng(55));
    let share_b = generate_two_party_root_share(TwoPartyDeriverRole::DeriverB, &mut seeded_rng(56));
    let context = TenantRootCeremonyContextV1::new(
        TenantRootIdentityV1::new("org-1", "project-2", "production", "root-main", "v3")?
            .digest()?,
        TenantRootCustodyLineageId::from_bytes([0x31; 16])?,
        TenantRootCeremonyEpochsV1::create(),
        TenantRootCeremonySessionIdV1::from_bytes([0x20; 16])?,
        TenantRootCeremonyNonceV1::from_bytes([0x40; 32])?,
        1_000_000,
        1_030_000,
        "deriver-a-signing-key-7",
        "deriver-b-signing-key-9",
    )?;
    let evidence_a = r120_installation_evidence(
        context.clone(),
        TwoPartyDeriverRole::DeriverA,
        &share_a,
        &share_b,
        57,
    )?;
    let evidence_b = r120_installation_evidence(
        context,
        TwoPartyDeriverRole::DeriverB,
        &share_b,
        &share_a,
        58,
    )?;
    let signing_a = SigningKey::from_bytes(&[0x51; 32]);
    let signing_b = SigningKey::from_bytes(&[0x61; 32]);
    let signed_a =
        TenantRootSignedShareInstallationEvidenceV1::sign(evidence_a, &signing_a.to_bytes())?;
    let signed_b =
        TenantRootSignedShareInstallationEvidenceV1::sign(evidence_b, &signing_b.to_bytes())?;
    let verified_a = signed_a.verify(signing_a.verifying_key().as_bytes())?;
    let verified_b = signed_b.verify(signing_b.verifying_key().as_bytes())?;
    verify_tenant_root_creation_evidence_v1(&verified_a, &verified_b)?;
    Ok(())
}

fn ecdsa_threshold_prf_output(
    share_a: &SigningRootShare,
    share_b: &SigningRootShare,
    purpose: PrfPurpose,
    proof_seed: u8,
) -> Result<[u8; 32], ThresholdPrfError> {
    let context = PrfContext::new(
        SuiteId::Ristretto255Sha512,
        purpose,
        StableTenantDerivationContextV2::new([0x42; 32]).canonical_context_bytes(),
    );
    let bundles = ValidatedThresholdSet::from_proof_bundles(
        ThresholdPolicy::from_u16s(2, 2)?,
        vec![
            evaluate_partial_with_dleq_proof(share_a, &context, &mut seeded_rng(proof_seed))?,
            evaluate_partial_with_dleq_proof(
                share_b,
                &context,
                &mut seeded_rng(proof_seed.wrapping_add(1)),
            )?,
        ],
    )?;
    Ok(combine_verified_partials(&bundles, &context)?.into_bytes())
}

fn run_r120_ecdsa_refresh_invariance_vector() -> Result<(), ThresholdPrfError> {
    let (current_a, current_b) = two_party_shares();
    let (next_a, next_b) = refreshed_two_party_shares(&current_a, &current_b)?;
    for (index, purpose) in [
        PrfPurpose::RouterAbXClientBaseV1,
        PrfPurpose::RouterAbXServerBaseV1,
        PrfPurpose::RouterAbEcdsaDerivationYServer,
    ]
    .into_iter()
    .enumerate()
    {
        let current = ecdsa_threshold_prf_output(
            &current_a,
            &current_b,
            purpose.clone(),
            81 + index as u8 * 2,
        )?;
        if current != R120_EXPECTED_ECDSA_OUTPUTS[index] {
            return Err(ThresholdPrfError::RefreshContinuityMismatch);
        }
        let next = ecdsa_threshold_prf_output(&next_a, &next_b, purpose, 91 + index as u8 * 2)?;
        if current != next {
            return Err(ThresholdPrfError::RefreshContinuityMismatch);
        }
    }
    Ok(())
}

fn ed25519_role_target_outputs(
    share_a: &SigningRootShare,
    share_b: &SigningRootShare,
    seed: u8,
) -> Result<([u8; 32], [u8; 32]), ThresholdPrfError> {
    let (prepared_a, a_to_b) = prepare_ed25519_deriver_a_target_v1(
        share_a,
        SigningRootShareCommitment::from_share(share_b),
        R120_STABLE_CONTEXT,
        &mut seeded_rng(seed),
    )?;
    let (prepared_b, b_to_a) = prepare_ed25519_deriver_b_target_v1(
        share_b,
        SigningRootShareCommitment::from_share(share_a),
        R120_STABLE_CONTEXT,
        &mut seeded_rng(seed.wrapping_add(1)),
    )?;
    let output_a = complete_ed25519_deriver_a_target_v1(prepared_a, &b_to_a)?;
    let output_b = complete_ed25519_deriver_b_target_v1(prepared_b, &a_to_b)?;
    Ok((output_a.into_secret_bytes(), output_b.into_secret_bytes()))
}

fn run_r120_ed25519_role_target_vector() -> Result<(), ThresholdPrfError> {
    let (current_a, current_b) = two_party_shares();
    let current_outputs = ed25519_role_target_outputs(&current_a, &current_b, 61)?;
    if current_outputs
        != (
            R120_EXPECTED_ED25519_A_OUTPUT,
            R120_EXPECTED_ED25519_B_OUTPUT,
        )
    {
        return Err(ThresholdPrfError::RefreshContinuityMismatch);
    }
    let (next_a, next_b) = refreshed_two_party_shares(&current_a, &current_b)?;
    let next_outputs = ed25519_role_target_outputs(&next_a, &next_b, 63)?;
    if current_outputs != next_outputs || current_outputs.0 == current_outputs.1 {
        return Err(ThresholdPrfError::RefreshContinuityMismatch);
    }
    Ok(())
}

fn r120_outer_context() -> Result<TenantRootCeremonyContextV1, RouterAbDerivationError> {
    TenantRootCeremonyContextV1::new(
        TenantRootIdentityV1::new("org-1", "project-2", "production", "root-main", "v3")?
            .digest()?,
        TenantRootCustodyLineageId::from_bytes([0x31; 16])?,
        TenantRootCeremonyEpochsV1::refresh(
            TenantRootShareEpoch::new(7)?,
            TenantRootShareEpoch::new(8)?,
        )?,
        TenantRootCeremonySessionIdV1::from_bytes([0x21; 16])?,
        TenantRootCeremonyNonceV1::from_bytes([0x41; 32])?,
        1_000_000,
        1_030_000,
        "deriver-a-signing-key-7",
        "deriver-b-signing-key-9",
    )
}

fn r120_verified_refresh_commitment(
    context: TenantRootCeremonyContextV1,
    coefficient: &RootShareRefreshCoefficient,
    signing_key: &SigningKey,
) -> Result<router_ab_core::VerifiedTenantRootRefreshCommitmentV1, RouterAbDerivationError> {
    let transcript =
        TenantRootRefreshCommitmentTranscriptV1::new(context, coefficient.commitment())?;
    TenantRootSignedRefreshCommitmentV1::sign(transcript, &signing_key.to_bytes())?
        .verify(signing_key.verifying_key().as_bytes())
}

fn r120_installation_evidence(
    context: TenantRootCeremonyContextV1,
    role: TwoPartyDeriverRole,
    share: &SigningRootShare,
    peer: &SigningRootShare,
    proof_seed: u8,
) -> Result<TenantRootShareInstallationEvidenceV1, RouterAbDerivationError> {
    let transcript = TenantRootShareInstallationTranscriptV1::new(
        context,
        role,
        SigningRootShareCommitment::from_share(share),
        SigningRootShareCommitment::from_share(peer),
    )?;
    let proof = prove_root_share_knowledge(
        share,
        &transcript.canonical_bytes()?,
        &mut seeded_rng(proof_seed),
    )
    .map_err(map_threshold_error)?;
    TenantRootShareInstallationEvidenceV1::new(transcript, proof)
}

fn map_threshold_error(_: ThresholdPrfError) -> RouterAbDerivationError {
    RouterAbDerivationError::new(
        RouterAbDerivationErrorCode::OutputVerificationFailed,
        "R120 WASM threshold-PRF vector failed",
    )
}

fn run_r120_tenant_root_outer_protocol_vector() -> Result<(), RouterAbDerivationError> {
    let context = r120_outer_context()?;
    let signing_a = SigningKey::from_bytes(&[0x51; 32]);
    let signing_b = SigningKey::from_bytes(&[0x61; 32]);
    let hpke_a = TenantRootRefreshHpkeKeypairV1::derive_from_ikm([0xa1; 32])?;
    let hpke_b = TenantRootRefreshHpkeKeypairV1::derive_from_ikm([0xb1; 32])?;
    let coefficient_a =
        RootShareRefreshCoefficient::random(TwoPartyDeriverRole::DeriverA, &mut seeded_rng(71));
    let coefficient_b =
        RootShareRefreshCoefficient::random(TwoPartyDeriverRole::DeriverB, &mut seeded_rng(72));
    let commitment_a =
        r120_verified_refresh_commitment(context.clone(), &coefficient_a, &signing_a)?;
    let commitment_b =
        r120_verified_refresh_commitment(context.clone(), &coefficient_b, &signing_b)?;
    let aad_a_to_b = TenantRootRefreshContributionAadV1::new(
        commitment_a,
        "deriver-b-hpke-key-8",
        hpke_b.public_key(),
    )?;
    let aad_b_to_a = TenantRootRefreshContributionAadV1::new(
        commitment_b,
        "deriver-a-hpke-key-8",
        hpke_a.public_key(),
    )?;

    let contribution_a_for_b = coefficient_a.contribution_for(TwoPartyDeriverRole::DeriverB);
    let encrypted_a = seal_tenant_root_refresh_contribution_v1(
        &aad_a_to_b,
        &contribution_a_for_b,
        &mut hpke_rng(0x81),
    )?;
    let signed_a = TenantRootSignedRefreshContributionV1::sign(
        &aad_a_to_b,
        encrypted_a,
        &signing_a.to_bytes(),
    )?;
    let opened_a_for_b =
        signed_a.verify_and_open(&aad_a_to_b, signing_a.verifying_key().as_bytes(), &hpke_b)?;

    let contribution_b_for_a = coefficient_b.contribution_for(TwoPartyDeriverRole::DeriverA);
    let encrypted_b = seal_tenant_root_refresh_contribution_v1(
        &aad_b_to_a,
        &contribution_b_for_a,
        &mut hpke_rng(0x82),
    )?;
    let signed_b = TenantRootSignedRefreshContributionV1::sign(
        &aad_b_to_a,
        encrypted_b,
        &signing_b.to_bytes(),
    )?;
    let opened_b_for_a =
        signed_b.verify_and_open(&aad_b_to_a, signing_b.verifying_key().as_bytes(), &hpke_a)?;

    let (current_a, current_b) = two_party_shares();
    let current = TwoPartyRootShareCommitments::from_shares(&current_a, &current_b)
        .map_err(map_threshold_error)?;
    let verified_a_for_a = coefficient_a
        .commitment()
        .verify_contribution(coefficient_a.contribution_for(TwoPartyDeriverRole::DeriverA))
        .map_err(map_threshold_error)?;
    let verified_b_for_a = coefficient_b
        .commitment()
        .verify_contribution(opened_b_for_a)
        .map_err(map_threshold_error)?;
    let next_a = apply_two_party_root_share_refresh(&current_a, verified_a_for_a, verified_b_for_a)
        .map_err(map_threshold_error)?;
    let verified_a_for_b = coefficient_a
        .commitment()
        .verify_contribution(opened_a_for_b)
        .map_err(map_threshold_error)?;
    let verified_b_for_b = coefficient_b
        .commitment()
        .verify_contribution(coefficient_b.contribution_for(TwoPartyDeriverRole::DeriverB))
        .map_err(map_threshold_error)?;
    let next_b = apply_two_party_root_share_refresh(&current_b, verified_a_for_b, verified_b_for_b)
        .map_err(map_threshold_error)?;

    let evidence_a = r120_installation_evidence(
        context.clone(),
        TwoPartyDeriverRole::DeriverA,
        &next_a,
        &next_b,
        73,
    )?;
    let evidence_b =
        r120_installation_evidence(context, TwoPartyDeriverRole::DeriverB, &next_b, &next_a, 74)?;
    let signed_evidence_a =
        TenantRootSignedShareInstallationEvidenceV1::sign(evidence_a, &signing_a.to_bytes())?;
    let signed_evidence_b =
        TenantRootSignedShareInstallationEvidenceV1::sign(evidence_b, &signing_b.to_bytes())?;
    let verified_evidence_a = signed_evidence_a.verify(signing_a.verifying_key().as_bytes())?;
    let verified_evidence_b = signed_evidence_b.verify(signing_b.verifying_key().as_bytes())?;
    verify_tenant_root_refresh_evidence_v1(&current, &verified_evidence_a, &verified_evidence_b)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn r120_wasm_vectors_pass_natively() {
        assert!(verify_r120_share_refresh_vector());
        assert!(verify_r120_tenant_root_creation_vector());
        assert!(verify_r120_ecdsa_refresh_invariance_vector());
        assert!(verify_r120_ed25519_role_target_vector());
        assert!(verify_r120_tenant_root_outer_protocol_vector());
    }
}
