use router_ab_core::{
    envelope_aad_v1, envelope_idempotency_key_v1, package_commitment_v1, CandidateId, ContentKind,
    CorrectnessLevel, DeliveryPackageV1, EnvelopeHeaderV1, EnvelopeKind, EnvelopeVersion,
    PublicDigest32, RequestKind, Role, RootShareEpoch, RouterAbDerivationErrorCode,
};

fn digest(seed: u8) -> PublicDigest32 {
    PublicDigest32::new([seed; 32])
}

fn sample_header_with_ciphertext(ciphertext_seed: u8) -> EnvelopeHeaderV1 {
    EnvelopeHeaderV1::new(
        EnvelopeVersion::V1,
        EnvelopeKind::SignerAToClient,
        CandidateId::SplitRootDerivationV1,
        RequestKind::Registration,
        CorrectnessLevel::MinimumLevelC,
        "ceremony-1",
        RootShareEpoch::new("epoch-1").expect("epoch"),
        digest(0x11),
        Role::SignerA,
        "role:signer-a:local:sha256-a",
        Role::Client,
        "role:client:local:sha256-c",
        ContentKind::ClientOutputShare,
        digest(ciphertext_seed),
        128,
    )
    .expect("header")
}

fn sample_header() -> EnvelopeHeaderV1 {
    sample_header_with_ciphertext(0x22)
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
    let err = EnvelopeHeaderV1::new(
        EnvelopeVersion::V1,
        EnvelopeKind::SignerAToClient,
        CandidateId::SplitRootDerivationV1,
        RequestKind::Registration,
        CorrectnessLevel::MinimumLevelC,
        "ceremony-1",
        RootShareEpoch::new("epoch-1").expect("epoch"),
        digest(0x11),
        Role::SignerA,
        "role:signer-a:local:sha256-a",
        Role::Server,
        "role:server:local:sha256-r",
        ContentKind::ClientOutputShare,
        digest(0x22),
        128,
    )
    .expect_err("recipient mismatch should fail");

    assert_eq!(err.code(), RouterAbDerivationErrorCode::RecipientMismatch);
}

#[test]
fn package_commitment_changes_with_ciphertext_digest() {
    let header = sample_header();
    let package = DeliveryPackageV1::new(header).expect("package");
    let first = package_commitment_v1(&package).expect("first commitment");

    let changed = sample_header_with_ciphertext(0x33);
    let second = package_commitment_v1(&DeliveryPackageV1::new(changed).expect("changed package"))
        .expect("second commitment");

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
