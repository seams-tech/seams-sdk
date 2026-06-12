use router_ab_core::{
    envelope_aad_v1, envelope_idempotency_key_v1, package_commitment_v1, CandidateId, ContentKind,
    CorrectnessLevel, DeliveryPackageV1, EnvelopeHeaderV1, EnvelopeKind, EnvelopeVersion,
    PublicDigest32, RequestKind, Role, RootShareEpoch, RouterAbDerivationErrorCode,
};

fn digest(seed: u8) -> PublicDigest32 {
    PublicDigest32::new([seed; 32])
}

fn sample_header() -> EnvelopeHeaderV1 {
    EnvelopeHeaderV1 {
        envelope_version: EnvelopeVersion::V1,
        envelope_kind: EnvelopeKind::SignerAToClient,
        candidate_id: CandidateId::SplitRootDerivationV1,
        request_kind: RequestKind::Registration,
        correctness_level: CorrectnessLevel::MinimumLevelC,
        ceremony_id: "ceremony-1".to_owned(),
        root_share_epoch: RootShareEpoch::new("epoch-1").expect("epoch"),
        transcript_digest: digest(0x11),
        sender_role: Role::SignerA,
        sender_identity: "role:signer-a:local:sha256-a".to_owned(),
        recipient_role: Role::Client,
        recipient_identity: "role:client:local:sha256-c".to_owned(),
        content_kind: ContentKind::ClientOutputShare,
        ciphertext_digest: digest(0x22),
        ciphertext_len: 128,
    }
}

#[test]
fn envelope_aad_is_stable() {
    let header = sample_header();

    assert_eq!(
        envelope_aad_v1(&header).expect("left"),
        envelope_aad_v1(&header).expect("right")
    );
}

#[test]
fn envelope_rejects_kind_role_mismatch() {
    let mut header = sample_header();
    header.recipient_role = Role::Relayer;

    let err = envelope_aad_v1(&header).expect_err("recipient mismatch should fail");

    assert_eq!(err.code(), RouterAbDerivationErrorCode::RecipientMismatch);
}

#[test]
fn package_commitment_changes_with_ciphertext_digest() {
    let header = sample_header();
    let package = DeliveryPackageV1 {
        header: header.clone(),
    };
    let first = package_commitment_v1(&package).expect("first commitment");

    let mut changed = header;
    changed.ciphertext_digest = digest(0x33);
    let second =
        package_commitment_v1(&DeliveryPackageV1 { header: changed }).expect("second commitment");

    assert_ne!(first, second);
}

#[test]
fn idempotency_key_is_stable_for_same_header() {
    let header = sample_header();

    assert_eq!(
        envelope_idempotency_key_v1(&header).expect("left"),
        envelope_idempotency_key_v1(&header).expect("right")
    );
}
