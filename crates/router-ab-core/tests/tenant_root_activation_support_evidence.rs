use std::ops::Range;

use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::SigningKey;
use router_ab_core::{
    MpcPrfShareCommitmentWireV1, RouterAbDerivationErrorCode,
    TenantRootAcceptedPermanentLossAuthorizationBindingV1, TenantRootActivationReceiptTransitionV1,
    TenantRootCanaryCurveFamilyV1, TenantRootControlPlaneAuthorityIdV1, TenantRootCustodyLineageId,
    TenantRootEpochCommitmentsV1, TenantRootIdentityDigestV1, TenantRootLifecycleReceiptDigestV1,
    TenantRootProtocolDigestV1, TenantRootProviderCanaryReceiptBindingV1,
    TenantRootRoleInstallationReceiptsV1, TenantRootShareEpoch,
    TenantRootSignedAcceptedPermanentLossAuthorizationV1, TenantRootSignedProviderCanaryReceiptV1,
};
use sha2::{Digest, Sha256};
use threshold_prf::{SigningRootShare, SigningRootShareCommitment, TwoPartyDeriverRole};

const PROVIDER_SIGNING_KEY_BYTES: [u8; 32] = [0x41; 32];
const FIRST_AUTHORITY_KEY_BYTES: [u8; 32] = [0x41; 32];
const SECOND_AUTHORITY_KEY_BYTES: [u8; 32] = [0x42; 32];
const PROVIDER_CANARY_VECTOR_HEX: &str = "0000002c7365616d732f74656e616e742d726f6f742d70726f76696465722d63616e6172792d726563656970742f763100000010696e697469616c5f6372656174696f6e0000002011111111111111111111111111111111111111111111111111111111111111110000001022222222222222222222222222222222000000080000000000000001000000220001e4549ee16b9aa03099ca208c67adafcafa4c3f3e4e5303de6026e3ca8ff844600000002200024cf1b9deda93eb9fd515fcc99262aed1368b48f24a27afd2984da8fe7bb2341f00000020e882b131016b52c1d3337080187cf768423efccbb517bb495ab812c4160ff44e000000056563647361000000156b6d732f74656e616e742d31312f65706f63682d310000000800000000000f424a00000020717171717171717171717171717171717171717171717171717171717171717100000017636f6e74726f6c2d706c616e652d63616e6172792d76310000000800000000000f42400000000800000000000fb77000000040b518a896c1d67d1762e0cc3b5877f88d0fb306984a1d0c5a920cd884440fda08bacdcf942fd8d172b8fe4c741f7a502552d9ed9efe3b9aa346f67201b1eae306";
const PROVIDER_CANARY_VECTOR_DIGEST_HEX: &str =
    "7c4a1f4f186dd771d28c3e067bee830e625c0e7592cfb9f9d395b97f4f7548ec";

fn identity(seed: u8) -> TenantRootIdentityDigestV1 {
    TenantRootIdentityDigestV1::from_bytes([seed; 32])
}

fn lineage(seed: u8) -> TenantRootCustodyLineageId {
    TenantRootCustodyLineageId::from_bytes([seed; 16]).expect("lineage")
}

fn authority(seed: u8) -> TenantRootControlPlaneAuthorityIdV1 {
    TenantRootControlPlaneAuthorityIdV1::from_bytes([seed; 32])
}

fn epoch(value: u64) -> TenantRootShareEpoch {
    TenantRootShareEpoch::new(value).expect("epoch")
}

fn commitment(role: TwoPartyDeriverRole, scalar: u64) -> MpcPrfShareCommitmentWireV1 {
    let share =
        SigningRootShare::from_canonical_bytes(role.share_id(), Scalar::from(scalar).to_bytes())
            .expect("share");
    MpcPrfShareCommitmentWireV1::new(
        SigningRootShareCommitment::from_share(&share)
            .to_bytes()
            .to_vec(),
    )
    .expect("commitment")
}

fn commitments(a_scalar: u64, b_scalar: u64) -> TenantRootEpochCommitmentsV1 {
    TenantRootEpochCommitmentsV1::new(
        commitment(TwoPartyDeriverRole::DeriverA, a_scalar),
        commitment(TwoPartyDeriverRole::DeriverB, b_scalar),
    )
    .expect("commitments")
}

fn context_digest() -> TenantRootProtocolDigestV1 {
    TenantRootProtocolDigestV1::from_bytes([0x55; 32]).expect("context digest")
}

fn installation_receipts_with(
    deriver_a: u8,
    deriver_b: u8,
) -> TenantRootRoleInstallationReceiptsV1 {
    TenantRootRoleInstallationReceiptsV1::new(
        TenantRootLifecycleReceiptDigestV1::from_bytes([deriver_a; 32]).expect("receipt A"),
        TenantRootLifecycleReceiptDigestV1::from_bytes([deriver_b; 32]).expect("receipt B"),
    )
    .expect("installation receipts")
}

fn installation_receipts() -> TenantRootRoleInstallationReceiptsV1 {
    installation_receipts_with(0x81, 0x82)
}

fn provider_binding(
    transition: TenantRootActivationReceiptTransitionV1,
    target_epoch: TenantRootShareEpoch,
    curve_family: TenantRootCanaryCurveFamilyV1,
) -> TenantRootProviderCanaryReceiptBindingV1 {
    TenantRootProviderCanaryReceiptBindingV1::new(
        identity(0x11),
        lineage(0x22),
        transition,
        target_epoch,
        commitments(12, 19),
        curve_family,
        "kms/tenant-11/epoch-1",
        1_000_010,
        authority(0x71),
        "control-plane-canary-v1",
        1_000_000,
        1_030_000,
    )
    .expect("provider binding")
}

fn accepted_loss_binding_with(
    context_digest: TenantRootProtocolDigestV1,
    commitments: TenantRootEpochCommitmentsV1,
    installation_receipts: TenantRootRoleInstallationReceiptsV1,
    expected_control_plane_revision: u64,
    result_control_plane_revision: u64,
    issued_at_ms: u64,
    expires_at_ms: u64,
) -> TenantRootAcceptedPermanentLossAuthorizationBindingV1 {
    TenantRootAcceptedPermanentLossAuthorizationBindingV1::new(
        identity(0x11),
        lineage(0x22),
        TenantRootActivationReceiptTransitionV1::RefreshSwap,
        epoch(8),
        context_digest,
        commitments,
        installation_receipts,
        expected_control_plane_revision,
        result_control_plane_revision,
        "policy-accept-loss-001",
        "incident-2026-0001",
        "both managed backups are unavailable",
        issued_at_ms,
        expires_at_ms,
        authority(0x71),
        "operator-a-v1",
        authority(0x72),
        "operator-b-v1",
    )
    .expect("accepted-loss binding")
}

fn accepted_loss_binding() -> TenantRootAcceptedPermanentLossAuthorizationBindingV1 {
    accepted_loss_binding_with(
        context_digest(),
        commitments(12, 19),
        installation_receipts(),
        11,
        12,
        1_000_000,
        1_030_000,
    )
}

fn sign_accepted_loss(
    binding: TenantRootAcceptedPermanentLossAuthorizationBindingV1,
) -> TenantRootSignedAcceptedPermanentLossAuthorizationV1 {
    TenantRootSignedAcceptedPermanentLossAuthorizationV1::sign(
        binding,
        &FIRST_AUTHORITY_KEY_BYTES,
        &SECOND_AUTHORITY_KEY_BYTES,
    )
    .expect("signed accepted-loss authorization")
}

#[test]
fn provider_canary_is_canonical_signed_and_non_clone_verified() {
    let binding = provider_binding(
        TenantRootActivationReceiptTransitionV1::InitialCreation,
        TenantRootShareEpoch::INITIAL,
        TenantRootCanaryCurveFamilyV1::Ecdsa,
    );
    let signed =
        TenantRootSignedProviderCanaryReceiptV1::sign(binding.clone(), &PROVIDER_SIGNING_KEY_BYTES)
            .expect("signed provider receipt");
    let bytes = signed
        .canonical_bytes()
        .expect("canonical provider receipt");
    assert_eq!(hex::encode(&bytes), PROVIDER_CANARY_VECTOR_HEX);
    let decoded = TenantRootSignedProviderCanaryReceiptV1::decode_canonical_bytes(&bytes)
        .expect("decoded provider receipt");
    assert_eq!(decoded, signed);
    assert_eq!(
        decoded.binding().curve_family(),
        TenantRootCanaryCurveFamilyV1::Ecdsa
    );
    assert_eq!(
        decoded.binding().commitments().root_commitment(),
        binding.commitments().root_commitment()
    );
    let expected_digest: [u8; 32] = Sha256::digest(&bytes).into();
    assert_eq!(
        hex::encode(expected_digest),
        PROVIDER_CANARY_VECTOR_DIGEST_HEX
    );
    assert_eq!(
        decoded
            .digest()
            .expect("provider receipt digest")
            .as_bytes(),
        &expected_digest
    );

    let verifying_key = SigningKey::from_bytes(&PROVIDER_SIGNING_KEY_BYTES)
        .verifying_key()
        .to_bytes();
    let verified = decoded
        .verify(&binding, &verifying_key)
        .expect("verified provider receipt");
    assert_eq!(verified.canonical_bytes(), bytes.as_slice());
    assert_eq!(verified.digest().as_bytes(), &expected_digest);
    verified
        .require_fresh(1_000_010)
        .expect("fresh provider receipt");
    assert!(verified.require_fresh(1_030_001).is_err());
}

#[test]
fn provider_canary_binds_refresh_and_curve_family_substitutions() {
    let binding = provider_binding(
        TenantRootActivationReceiptTransitionV1::RefreshSwap,
        epoch(8),
        TenantRootCanaryCurveFamilyV1::Ed25519,
    );
    let signed =
        TenantRootSignedProviderCanaryReceiptV1::sign(binding.clone(), &PROVIDER_SIGNING_KEY_BYTES)
            .expect("signed provider receipt");
    let bytes = signed
        .canonical_bytes()
        .expect("canonical provider receipt");
    let decoded = TenantRootSignedProviderCanaryReceiptV1::decode_canonical_bytes(&bytes)
        .expect("decoded provider receipt");
    assert_eq!(
        decoded.binding().curve_family(),
        TenantRootCanaryCurveFamilyV1::Ed25519
    );
    assert_eq!(decoded.binding().target_epoch(), epoch(8));

    let wrong_curve = provider_binding(
        TenantRootActivationReceiptTransitionV1::RefreshSwap,
        epoch(8),
        TenantRootCanaryCurveFamilyV1::Ecdsa,
    );
    let key = SigningKey::from_bytes(&PROVIDER_SIGNING_KEY_BYTES)
        .verifying_key()
        .to_bytes();
    assert_eq!(
        decoded
            .verify(&wrong_curve, &key)
            .expect_err("curve substitution must fail")
            .code(),
        RouterAbDerivationErrorCode::ReplayMismatch
    );

    for range in field_ranges(&bytes) {
        let mut substituted = bytes.clone();
        substituted[range.start] ^= 1;
        let result = TenantRootSignedProviderCanaryReceiptV1::decode_canonical_bytes(&substituted);
        if let Ok(tampered) = result {
            assert!(
                tampered.verify(&binding, &key).is_err(),
                "field substitution must fail verification at {range:?}"
            );
        }
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(
        TenantRootSignedProviderCanaryReceiptV1::decode_canonical_bytes(&trailing).is_err(),
        "trailing bytes must fail"
    );
}

#[test]
fn accepted_loss_requires_two_distinct_control_plane_signatures() {
    let binding = accepted_loss_binding();
    let signed = TenantRootSignedAcceptedPermanentLossAuthorizationV1::sign(
        binding.clone(),
        &FIRST_AUTHORITY_KEY_BYTES,
        &SECOND_AUTHORITY_KEY_BYTES,
    )
    .expect("signed accepted-loss authorization");
    let bytes = signed.canonical_bytes().expect("canonical authorization");
    let decoded =
        TenantRootSignedAcceptedPermanentLossAuthorizationV1::decode_canonical_bytes(&bytes)
            .expect("decoded authorization");
    assert_eq!(decoded, signed);
    assert_eq!(
        decoded.binding().one_use_policy_id(),
        "policy-accept-loss-001"
    );
    assert_eq!(decoded.binding().incident_id(), "incident-2026-0001");
    assert_eq!(decoded.binding().target_epoch(), epoch(8));
    let expected_digest: [u8; 32] = Sha256::digest(&bytes).into();
    assert_eq!(
        decoded.digest().expect("authorization digest").as_bytes(),
        &expected_digest
    );

    let first_verifying_key = SigningKey::from_bytes(&FIRST_AUTHORITY_KEY_BYTES)
        .verifying_key()
        .to_bytes();
    let second_verifying_key = SigningKey::from_bytes(&SECOND_AUTHORITY_KEY_BYTES)
        .verifying_key()
        .to_bytes();
    let verified = decoded
        .verify(&binding, &first_verifying_key, &second_verifying_key)
        .expect("verified accepted-loss authorization");
    assert_eq!(verified.canonical_bytes(), bytes.as_slice());
    verified
        .require_fresh(1_000_000)
        .expect("fresh authorization");
    assert!(verified.require_fresh(1_030_001).is_err());
    assert_eq!(verified.into_canonical_bytes(), bytes);
}

#[test]
fn accepted_loss_rejects_substitutions_and_duplicate_approval_keys() {
    let binding = accepted_loss_binding();
    assert_eq!(
        TenantRootSignedAcceptedPermanentLossAuthorizationV1::sign(
            binding.clone(),
            &FIRST_AUTHORITY_KEY_BYTES,
            &FIRST_AUTHORITY_KEY_BYTES,
        )
        .expect_err("same approval key must fail")
        .code(),
        RouterAbDerivationErrorCode::MalformedInput
    );

    let signed = TenantRootSignedAcceptedPermanentLossAuthorizationV1::sign(
        binding.clone(),
        &FIRST_AUTHORITY_KEY_BYTES,
        &SECOND_AUTHORITY_KEY_BYTES,
    )
    .expect("signed accepted-loss authorization");
    let bytes = signed.canonical_bytes().expect("canonical authorization");
    let first_verifying_key = SigningKey::from_bytes(&FIRST_AUTHORITY_KEY_BYTES)
        .verifying_key()
        .to_bytes();
    let second_verifying_key = SigningKey::from_bytes(&SECOND_AUTHORITY_KEY_BYTES)
        .verifying_key()
        .to_bytes();
    for range in field_ranges(&bytes) {
        let mut substituted = bytes.clone();
        substituted[range.start] ^= 1;
        let result = TenantRootSignedAcceptedPermanentLossAuthorizationV1::decode_canonical_bytes(
            &substituted,
        );
        if let Ok(tampered) = result {
            assert!(
                tampered
                    .verify(&binding, &first_verifying_key, &second_verifying_key)
                    .is_err(),
                "field substitution must fail verification at {range:?}"
            );
        }
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(
        TenantRootSignedAcceptedPermanentLossAuthorizationV1::decode_canonical_bytes(&trailing)
            .is_err(),
        "trailing bytes must fail"
    );
}

#[test]
fn accepted_loss_authentication_rejects_exact_scope_replays() {
    let expected = accepted_loss_binding();
    let first_verifying_key = SigningKey::from_bytes(&FIRST_AUTHORITY_KEY_BYTES)
        .verifying_key()
        .to_bytes();
    let second_verifying_key = SigningKey::from_bytes(&SECOND_AUTHORITY_KEY_BYTES)
        .verifying_key()
        .to_bytes();
    let candidates = [
        (
            "context",
            accepted_loss_binding_with(
                TenantRootProtocolDigestV1::from_bytes([0x56; 32]).expect("context digest"),
                commitments(12, 19),
                installation_receipts(),
                11,
                12,
                1_000_000,
                1_030_000,
            ),
        ),
        (
            "deriver A commitment",
            accepted_loss_binding_with(
                context_digest(),
                commitments(13, 19),
                installation_receipts(),
                11,
                12,
                1_000_000,
                1_030_000,
            ),
        ),
        (
            "deriver B commitment",
            accepted_loss_binding_with(
                context_digest(),
                commitments(12, 23),
                installation_receipts(),
                11,
                12,
                1_000_000,
                1_030_000,
            ),
        ),
        (
            "deriver A installation receipt",
            accepted_loss_binding_with(
                context_digest(),
                commitments(12, 19),
                installation_receipts_with(0x91, 0x82),
                11,
                12,
                1_000_000,
                1_030_000,
            ),
        ),
        (
            "deriver B installation receipt",
            accepted_loss_binding_with(
                context_digest(),
                commitments(12, 19),
                installation_receipts_with(0x81, 0x92),
                11,
                12,
                1_000_000,
                1_030_000,
            ),
        ),
        (
            "lifecycle revisions",
            accepted_loss_binding_with(
                context_digest(),
                commitments(12, 19),
                installation_receipts(),
                12,
                13,
                1_000_000,
                1_030_000,
            ),
        ),
        (
            "issue time",
            accepted_loss_binding_with(
                context_digest(),
                commitments(12, 19),
                installation_receipts(),
                11,
                12,
                1_000_001,
                1_030_001,
            ),
        ),
        (
            "expiry time",
            accepted_loss_binding_with(
                context_digest(),
                commitments(12, 19),
                installation_receipts(),
                11,
                12,
                1_000_000,
                1_029_999,
            ),
        ),
    ];

    for (label, candidate) in candidates {
        let signed = sign_accepted_loss(candidate);
        assert_eq!(
            signed
                .verify(&expected, &first_verifying_key, &second_verifying_key)
                .expect_err(label)
                .code(),
            RouterAbDerivationErrorCode::ReplayMismatch,
            "{label} must remain bound to the original activation scope"
        );
    }

    let signed = sign_accepted_loss(expected.clone());
    let mut root_substitution = signed.canonical_bytes().expect("canonical authorization");
    let root_range = field_ranges(&root_substitution)[8].clone();
    root_substitution[root_range.start] ^= 1;
    assert!(
        TenantRootSignedAcceptedPermanentLossAuthorizationV1::decode_canonical_bytes(
            &root_substitution
        )
        .is_err(),
        "the joined root commitment must remain consistent with both role commitments"
    );
}

#[test]
fn accepted_loss_rejects_same_authority_with_different_keys() {
    let result = TenantRootAcceptedPermanentLossAuthorizationBindingV1::new(
        identity(0x11),
        lineage(0x22),
        TenantRootActivationReceiptTransitionV1::RefreshSwap,
        epoch(8),
        context_digest(),
        commitments(12, 19),
        installation_receipts(),
        11,
        12,
        "policy-accept-loss-001",
        "incident-2026-0001",
        "both managed backups are unavailable",
        1_000_000,
        1_030_000,
        authority(0x71),
        "operator-a-v1",
        authority(0x71),
        "operator-b-v1",
    );

    assert_eq!(
        result
            .expect_err("same authority must fail even with different key ids")
            .code(),
        RouterAbDerivationErrorCode::MalformedInput
    );
}

fn field_ranges(bytes: &[u8]) -> Vec<Range<usize>> {
    let mut offset = 0;
    let mut ranges = Vec::new();
    while offset < bytes.len() {
        let length_end = offset + 4;
        let length =
            u32::from_be_bytes(bytes[offset..length_end].try_into().expect("length")) as usize;
        let value_start = length_end;
        let value_end = value_start + length;
        ranges.push(value_start..value_end);
        offset = value_end;
    }
    assert_eq!(offset, bytes.len());
    ranges
}
