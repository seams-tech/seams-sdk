use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::SigningKey;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use router_ab_core::{
    MpcPrfShareCommitmentWireV1, RouterAbDerivationResult, TenantRootCeremonyContextV1,
    TenantRootCeremonyEpochsV1, TenantRootCeremonyNonceV1, TenantRootCeremonySessionIdV1,
    TenantRootCustodyLineageId, TenantRootIdentityV1, TenantRootOnlineRoleShareBindingV1,
    TenantRootOnlineRoleShareSealRequestV1, TenantRootSealedOnlineRoleShareV1,
    TenantRootShareEpoch, TenantRootShareInstallationEvidenceV1,
    TenantRootShareInstallationTranscriptV1, TenantRootSignedShareInstallationEvidenceV1,
};
use sha2::{Digest, Sha256};
use threshold_prf::{
    prove_root_share_knowledge, SigningRootShare, SigningRootShareCommitment, SigningRootShareWire,
    TwoPartyDeriverRole,
};

const ISSUED_AT_MS: u64 = 1_000_000;
const EXPIRES_AT_MS: u64 = 1_030_000;
const ONLINE_KEY_REF: &str = "online-key/tenant-7/epoch-1";

fn identity(root_id: &str) -> TenantRootIdentityV1 {
    TenantRootIdentityV1::new("org-1", "project-2", "production", root_id, "v3").unwrap()
}

fn context(
    identity: &TenantRootIdentityV1,
    lineage: TenantRootCustodyLineageId,
    epochs: TenantRootCeremonyEpochsV1,
    session_seed: u8,
) -> TenantRootCeremonyContextV1 {
    TenantRootCeremonyContextV1::new(
        identity.digest().unwrap(),
        lineage,
        epochs,
        TenantRootCeremonySessionIdV1::from_bytes([session_seed; 16]).unwrap(),
        TenantRootCeremonyNonceV1::from_bytes([0x41; 32]).unwrap(),
        ISSUED_AT_MS,
        EXPIRES_AT_MS,
        "deriver-a-signing-key-7",
        "deriver-b-signing-key-9",
    )
    .unwrap()
}

fn role_signing_key(role: TwoPartyDeriverRole) -> SigningKey {
    SigningKey::from_bytes(
        &[match role {
            TwoPartyDeriverRole::DeriverA => 0x51,
            TwoPartyDeriverRole::DeriverB => 0x61,
        }; 32],
    )
}

fn verified_evidence(
    context: TenantRootCeremonyContextV1,
    role: TwoPartyDeriverRole,
    share_scalar: u64,
    peer_scalar: u64,
    proof_seed: u8,
) -> (
    router_ab_core::VerifiedTenantRootSignedShareInstallationEvidenceWireV1,
    SigningRootShareWire,
    MpcPrfShareCommitmentWireV1,
) {
    let share = SigningRootShare::from_canonical_bytes(
        role.share_id(),
        Scalar::from(share_scalar).to_bytes(),
    )
    .unwrap();
    let peer = SigningRootShare::from_canonical_bytes(
        role.peer().share_id(),
        Scalar::from(peer_scalar).to_bytes(),
    )
    .unwrap();
    let commitment = SigningRootShareCommitment::from_share(&share);
    let peer_commitment = SigningRootShareCommitment::from_share(&peer);
    let transcript =
        TenantRootShareInstallationTranscriptV1::new(context, role, commitment, peer_commitment)
            .unwrap();
    let proof = prove_root_share_knowledge(
        &share,
        &transcript.canonical_bytes().unwrap(),
        &mut ChaCha20Rng::from_seed([proof_seed; 32]),
    )
    .unwrap();
    let evidence = TenantRootShareInstallationEvidenceV1::new(transcript, proof).unwrap();
    let signing_key = role_signing_key(role);
    let signed =
        TenantRootSignedShareInstallationEvidenceV1::sign(evidence, &signing_key.to_bytes())
            .unwrap();
    let wire = signed.canonical_bytes().unwrap();
    let verified = TenantRootSignedShareInstallationEvidenceV1::decode_and_verify_canonical_bytes(
        &wire,
        signing_key.verifying_key().as_bytes(),
    )
    .unwrap();
    (
        verified,
        SigningRootShareWire::from_share(&share),
        MpcPrfShareCommitmentWireV1::new(commitment.to_bytes().to_vec()).unwrap(),
    )
}

fn provider_fixture(
    binding: &TenantRootOnlineRoleShareBindingV1,
    aad: &[u8],
    share_wire: &SigningRootShareWire,
) -> RouterAbDerivationResult<Vec<u8>> {
    assert_eq!(aad, binding.canonical_bytes().unwrap());
    assert_eq!(
        share_wire.to_share().unwrap().id(),
        binding.role().share_id()
    );
    Ok(vec![0xa5; 96])
}

fn binding_for(
    evidence: &router_ab_core::VerifiedTenantRootSignedShareInstallationEvidenceWireV1,
    identity_digest: router_ab_core::TenantRootIdentityDigestV1,
    custody_lineage: TenantRootCustodyLineageId,
    role: TwoPartyDeriverRole,
    epoch: TenantRootShareEpoch,
    share_commitment: MpcPrfShareCommitmentWireV1,
) -> router_ab_core::RouterAbDerivationResult<TenantRootOnlineRoleShareBindingV1> {
    TenantRootOnlineRoleShareBindingV1::new(
        identity_digest,
        custody_lineage,
        role,
        epoch,
        share_commitment,
        ONLINE_KEY_REF,
        evidence,
    )
}

#[test]
fn online_sealing_request_holds_zeroizing_share_and_preserves_exact_binding() {
    let identity = identity("root-main");
    let lineage = TenantRootCustodyLineageId::from_bytes([0x31; 16]).unwrap();
    let (evidence, share_wire, commitment) = verified_evidence(
        context(
            &identity,
            lineage,
            TenantRootCeremonyEpochsV1::create(),
            0x21,
        ),
        TwoPartyDeriverRole::DeriverA,
        12,
        19,
        0x33,
    );
    let binding = binding_for(
        &evidence,
        identity.digest().unwrap(),
        lineage,
        TwoPartyDeriverRole::DeriverA,
        TenantRootShareEpoch::INITIAL,
        commitment,
    )
    .unwrap();
    assert_eq!(
        binding.installation_evidence_digest(),
        evidence.lifecycle_receipt_digest().unwrap()
    );
    assert_eq!(binding.epoch_wrapping_key_ref(), ONLINE_KEY_REF);

    let request = TenantRootOnlineRoleShareSealRequestV1::new(binding.clone(), share_wire).unwrap();
    assert!(format!("{request:?}").contains("[redacted]"));
    let aad = request.aad().unwrap();
    let ciphertext = provider_fixture(request.binding(), &aad, request.share_wire()).unwrap();
    let sealed = request.complete(ciphertext.clone()).unwrap();

    assert_eq!(sealed.binding(), &binding);
    assert_eq!(sealed.aad().unwrap(), aad);
    assert_eq!(sealed.ciphertext(), ciphertext);
    let expected_ciphertext_digest: [u8; 32] = Sha256::digest(&ciphertext).into();
    assert_eq!(sealed.ciphertext_digest(), &expected_ciphertext_digest);
    assert!(format!("{sealed:?}").contains("[redacted]"));

    let (_, opened_share, _) = verified_evidence(
        context(
            &identity,
            lineage,
            TenantRootCeremonyEpochsV1::create(),
            0x21,
        ),
        TwoPartyDeriverRole::DeriverA,
        12,
        19,
        0x33,
    );
    let verified = sealed.verify_opened_share(opened_share).unwrap();
    assert_eq!(verified.binding(), &binding);
    assert_eq!(verified.aad().unwrap(), aad);
    assert_eq!(verified.role(), binding.role());
    assert_eq!(verified.identity_digest(), binding.identity_digest());
    assert_eq!(verified.custody_lineage(), binding.custody_lineage());
    assert_eq!(verified.epoch(), binding.epoch());
    assert_eq!(verified.share_commitment(), binding.share_commitment());
    assert!(format!("{verified:?}").contains("[redacted]"));
    let (verified_binding, verified_share) = verified.into_parts();
    assert_eq!(verified_binding, binding);
    assert_eq!(
        verified_share.to_share().unwrap().id(),
        TwoPartyDeriverRole::DeriverA.share_id()
    );
}

#[test]
fn persisted_online_artifact_reconstructs_with_the_exact_provider_binding() {
    let identity = identity("root-main");
    let lineage = TenantRootCustodyLineageId::from_bytes([0x31; 16]).unwrap();
    let (evidence, share_wire, commitment) = verified_evidence(
        context(
            &identity,
            lineage,
            TenantRootCeremonyEpochsV1::create(),
            0x21,
        ),
        TwoPartyDeriverRole::DeriverA,
        12,
        19,
        0x33,
    );
    let binding = binding_for(
        &evidence,
        identity.digest().unwrap(),
        lineage,
        TwoPartyDeriverRole::DeriverA,
        TenantRootShareEpoch::INITIAL,
        commitment,
    )
    .unwrap();
    let persisted_binding = TenantRootOnlineRoleShareBindingV1::from_persisted(
        binding.identity_digest(),
        binding.custody_lineage(),
        binding.role(),
        binding.epoch(),
        binding.share_commitment().clone(),
        binding.epoch_wrapping_key_ref(),
        binding.installation_evidence_digest(),
    )
    .unwrap();
    assert_eq!(persisted_binding, binding);

    let ciphertext = vec![0xa5; 96];
    let sealed = TenantRootOnlineRoleShareSealRequestV1::new(binding, share_wire)
        .unwrap()
        .complete(ciphertext.clone())
        .unwrap();
    let persisted_sealed =
        TenantRootSealedOnlineRoleShareV1::from_persisted(persisted_binding, ciphertext).unwrap();
    assert_eq!(persisted_sealed.binding(), sealed.binding());
    assert_eq!(persisted_sealed.ciphertext(), sealed.ciphertext());
    assert_eq!(
        persisted_sealed.ciphertext_digest(),
        sealed.ciphertext_digest()
    );

    let (_, opened_share, _) = verified_evidence(
        context(
            &identity,
            lineage,
            TenantRootCeremonyEpochsV1::create(),
            0x21,
        ),
        TwoPartyDeriverRole::DeriverA,
        12,
        19,
        0x33,
    );
    let verified = persisted_sealed.verify_opened_share(opened_share).unwrap();
    assert_eq!(verified.binding(), sealed.binding());
    assert_eq!(
        verified.share_commitment(),
        sealed.binding().share_commitment()
    );
}

#[test]
fn online_sealing_rejects_identity_lineage_role_epoch_commitment_and_share_substitution() {
    let tenant_identity = identity("root-main");
    let other_identity = identity("root-other");
    let lineage = TenantRootCustodyLineageId::from_bytes([0x31; 16]).unwrap();
    let other_lineage = TenantRootCustodyLineageId::from_bytes([0x32; 16]).unwrap();
    let (evidence, share_wire, commitment) = verified_evidence(
        context(
            &tenant_identity,
            lineage,
            TenantRootCeremonyEpochsV1::create(),
            0x21,
        ),
        TwoPartyDeriverRole::DeriverA,
        12,
        19,
        0x33,
    );
    assert!(binding_for(
        &evidence,
        other_identity.digest().unwrap(),
        lineage,
        TwoPartyDeriverRole::DeriverA,
        TenantRootShareEpoch::INITIAL,
        commitment.clone(),
    )
    .is_err());
    assert!(binding_for(
        &evidence,
        tenant_identity.digest().unwrap(),
        other_lineage,
        TwoPartyDeriverRole::DeriverA,
        TenantRootShareEpoch::INITIAL,
        commitment.clone(),
    )
    .is_err());
    assert!(binding_for(
        &evidence,
        tenant_identity.digest().unwrap(),
        lineage,
        TwoPartyDeriverRole::DeriverB,
        TenantRootShareEpoch::INITIAL,
        commitment.clone(),
    )
    .is_err());
    assert!(binding_for(
        &evidence,
        tenant_identity.digest().unwrap(),
        lineage,
        TwoPartyDeriverRole::DeriverA,
        TenantRootShareEpoch::new(2).unwrap(),
        commitment.clone(),
    )
    .is_err());
    let (_, _, other_commitment) = verified_evidence(
        context(
            &tenant_identity,
            lineage,
            TenantRootCeremonyEpochsV1::create(),
            0x22,
        ),
        TwoPartyDeriverRole::DeriverA,
        13,
        19,
        0x34,
    );
    assert!(binding_for(
        &evidence,
        tenant_identity.digest().unwrap(),
        lineage,
        TwoPartyDeriverRole::DeriverA,
        TenantRootShareEpoch::INITIAL,
        other_commitment,
    )
    .is_err());

    let binding = binding_for(
        &evidence,
        tenant_identity.digest().unwrap(),
        lineage,
        TwoPartyDeriverRole::DeriverA,
        TenantRootShareEpoch::INITIAL,
        commitment.clone(),
    )
    .unwrap();
    let changed_key_binding = TenantRootOnlineRoleShareBindingV1::new(
        tenant_identity.digest().unwrap(),
        lineage,
        TwoPartyDeriverRole::DeriverA,
        TenantRootShareEpoch::INITIAL,
        commitment.clone(),
        "online-key/tenant-7/epoch-2",
        &evidence,
    )
    .unwrap();
    assert_ne!(
        binding.canonical_bytes().unwrap(),
        changed_key_binding.canonical_bytes().unwrap()
    );
    assert!(TenantRootOnlineRoleShareBindingV1::new(
        tenant_identity.digest().unwrap(),
        lineage,
        TwoPartyDeriverRole::DeriverA,
        TenantRootShareEpoch::INITIAL,
        commitment,
        "",
        &evidence,
    )
    .is_err());
    let (_, wrong_role_share, _) = verified_evidence(
        context(
            &tenant_identity,
            lineage,
            TenantRootCeremonyEpochsV1::create(),
            0x23,
        ),
        TwoPartyDeriverRole::DeriverB,
        19,
        12,
        0x35,
    );
    assert!(
        TenantRootOnlineRoleShareSealRequestV1::new(binding.clone(), wrong_role_share).is_err()
    );
    let (_, wrong_commitment_share, _) = verified_evidence(
        context(
            &tenant_identity,
            lineage,
            TenantRootCeremonyEpochsV1::create(),
            0x24,
        ),
        TwoPartyDeriverRole::DeriverA,
        13,
        19,
        0x36,
    );
    assert!(
        TenantRootOnlineRoleShareSealRequestV1::new(binding.clone(), wrong_commitment_share)
            .is_err()
    );
    assert!(
        TenantRootOnlineRoleShareSealRequestV1::new(binding, share_wire)
            .unwrap()
            .complete(Vec::new())
            .is_err()
    );
}

#[test]
fn online_open_rejects_provider_role_and_commitment_substitution() {
    let identity = identity("root-main");
    let lineage = TenantRootCustodyLineageId::from_bytes([0x31; 16]).unwrap();
    let (evidence, share_wire, commitment) = verified_evidence(
        context(
            &identity,
            lineage,
            TenantRootCeremonyEpochsV1::create(),
            0x21,
        ),
        TwoPartyDeriverRole::DeriverA,
        12,
        19,
        0x33,
    );
    let binding = binding_for(
        &evidence,
        identity.digest().unwrap(),
        lineage,
        TwoPartyDeriverRole::DeriverA,
        TenantRootShareEpoch::INITIAL,
        commitment,
    )
    .unwrap();
    let sealed = TenantRootOnlineRoleShareSealRequestV1::new(binding, share_wire)
        .unwrap()
        .complete(vec![0xa5; 96])
        .unwrap();

    let (_, wrong_role_share, _) = verified_evidence(
        context(
            &identity,
            lineage,
            TenantRootCeremonyEpochsV1::create(),
            0x23,
        ),
        TwoPartyDeriverRole::DeriverB,
        19,
        12,
        0x35,
    );
    assert!(sealed
        .clone()
        .verify_opened_share(wrong_role_share)
        .is_err());

    let (_, wrong_commitment_share, _) = verified_evidence(
        context(
            &identity,
            lineage,
            TenantRootCeremonyEpochsV1::create(),
            0x24,
        ),
        TwoPartyDeriverRole::DeriverA,
        13,
        19,
        0x36,
    );
    assert!(sealed.verify_opened_share(wrong_commitment_share).is_err());
}
