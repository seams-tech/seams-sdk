use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar, traits::Identity};
use router_ab_core::{
    resolve_active_tenant_root_pair_binding_v1, resolve_active_tenant_root_role_binding_v1,
    validate_tenant_root_active_role_share_commitment_v1, MpcPrfShareCommitmentWireV1,
    RouterAbDerivationErrorCode, TenantRootActivePairMismatchV1, TenantRootActivePairResolutionV1,
    TenantRootActiveRoleAmbiguityV1, TenantRootActiveRoleBindingV1,
    TenantRootActiveRoleResolutionV1, TenantRootActiveRoleRowKeyV1, TenantRootCustodyLineageId,
    TenantRootIdentityDigestV1, TenantRootLifecycleReceiptDigestV1, TenantRootManagedRestoreRoleV1,
    TenantRootShareEpoch,
};
use threshold_prf::{SigningRootShare, SigningRootShareCommitment, TwoPartyDeriverRole};

const IDENTITY: u8 = 0x11;
const OTHER_IDENTITY: u8 = 0x12;

fn identity(seed: u8) -> TenantRootIdentityDigestV1 {
    TenantRootIdentityDigestV1::from_bytes([seed; 32])
}

fn receipt(seed: u8) -> TenantRootLifecycleReceiptDigestV1 {
    TenantRootLifecycleReceiptDigestV1::from_bytes([seed; 32]).expect("receipt")
}

fn lineage(seed: u8) -> TenantRootCustodyLineageId {
    TenantRootCustodyLineageId::from_bytes([seed; 16]).expect("lineage")
}

fn epoch(value: u64) -> TenantRootShareEpoch {
    TenantRootShareEpoch::new(value).expect("epoch")
}

fn deriver_role(role: TenantRootManagedRestoreRoleV1) -> TwoPartyDeriverRole {
    match role {
        TenantRootManagedRestoreRoleV1::DeriverA => TwoPartyDeriverRole::DeriverA,
        TenantRootManagedRestoreRoleV1::DeriverB => TwoPartyDeriverRole::DeriverB,
    }
}

/// Commits to one fixed role-local share, exactly as a real installation would.
fn commitment(role: TenantRootManagedRestoreRoleV1, scalar: u64) -> MpcPrfShareCommitmentWireV1 {
    let share = SigningRootShare::from_canonical_bytes(
        deriver_role(role).share_id(),
        Scalar::from(scalar).to_bytes(),
    )
    .expect("share");
    MpcPrfShareCommitmentWireV1::new(
        SigningRootShareCommitment::from_share(&share)
            .to_bytes()
            .to_vec(),
    )
    .expect("commitment")
}

/// The share each role commits to unless a test needs a different one.
fn role_scalar(role: TenantRootManagedRestoreRoleV1) -> u64 {
    match role {
        TenantRootManagedRestoreRoleV1::DeriverA => 17,
        TenantRootManagedRestoreRoleV1::DeriverB => 29,
    }
}

fn row(
    identity_seed: u8,
    lineage_seed: u8,
    epoch_value: u64,
    role: TenantRootManagedRestoreRoleV1,
) -> TenantRootActiveRoleBindingV1 {
    binding(
        row_key(identity_seed, lineage_seed, epoch_value, role),
        commitment(role, role_scalar(role)),
    )
}

fn row_key(
    identity_seed: u8,
    lineage_seed: u8,
    epoch_value: u64,
    role: TenantRootManagedRestoreRoleV1,
) -> TenantRootActiveRoleRowKeyV1 {
    TenantRootActiveRoleRowKeyV1::new(
        identity(identity_seed),
        lineage(lineage_seed),
        epoch(epoch_value),
        role,
    )
}

fn binding(
    row: TenantRootActiveRoleRowKeyV1,
    share_commitment: MpcPrfShareCommitmentWireV1,
) -> TenantRootActiveRoleBindingV1 {
    binding_with_receipt(row, share_commitment, receipt(0x41))
}

fn binding_with_receipt(
    row: TenantRootActiveRoleRowKeyV1,
    share_commitment: MpcPrfShareCommitmentWireV1,
    activation_receipt_digest: TenantRootLifecycleReceiptDigestV1,
) -> TenantRootActiveRoleBindingV1 {
    TenantRootActiveRoleBindingV1::new(row, share_commitment, activation_receipt_digest)
        .expect("binding")
}

fn resolve(observed: &[TenantRootActiveRoleBindingV1]) -> TenantRootActiveRoleResolutionV1 {
    resolve_active_tenant_root_role_binding_v1(
        identity(IDENTITY),
        TenantRootManagedRestoreRoleV1::DeriverA,
        observed,
    )
    .expect("resolution")
}

#[test]
fn no_active_row_resolves_to_unprovisioned() {
    let resolution = resolve(&[]);
    assert_eq!(resolution, TenantRootActiveRoleResolutionV1::Unprovisioned);
    assert_eq!(
        resolution.require_active().unwrap_err().code(),
        RouterAbDerivationErrorCode::MissingActiveTenantRootBinding
    );
}

#[test]
fn one_active_row_resolves_to_its_exact_lineage_and_epoch() {
    let only = row(IDENTITY, 0x31, 7, TenantRootManagedRestoreRoleV1::DeriverA);
    let resolution = resolve(std::slice::from_ref(&only));
    assert_eq!(resolution, TenantRootActiveRoleResolutionV1::Active(only));

    // The resolved lineage and epoch come from the stored row, never from a caller.
    let binding = resolution.require_active().expect("active");
    assert_eq!(binding.custody_lineage(), lineage(0x31));
    assert_eq!(binding.epoch(), epoch(7));
    assert_eq!(binding.identity_digest(), identity(IDENTITY));
    assert_eq!(binding.role(), TenantRootManagedRestoreRoleV1::DeriverA);
}

#[test]
fn distinct_active_lineages_are_ambiguous_and_never_pick_a_winner() {
    let resolution = resolve(&[
        row(IDENTITY, 0x31, 7, TenantRootManagedRestoreRoleV1::DeriverA),
        row(IDENTITY, 0x32, 7, TenantRootManagedRestoreRoleV1::DeriverA),
    ]);
    assert_eq!(
        resolution,
        TenantRootActiveRoleResolutionV1::Ambiguous(
            TenantRootActiveRoleAmbiguityV1::DistinctLineages {
                custody_lineages: vec![lineage(0x31), lineage(0x32)],
            }
        )
    );
    assert_eq!(
        resolution.require_active().unwrap_err().code(),
        RouterAbDerivationErrorCode::AmbiguousActiveTenantRootBinding
    );
}

#[test]
fn duplicate_rows_in_one_lineage_are_ambiguous_and_never_choose_the_latest_epoch() {
    let resolution = resolve(&[
        row(IDENTITY, 0x31, 7, TenantRootManagedRestoreRoleV1::DeriverA),
        row(IDENTITY, 0x31, 9, TenantRootManagedRestoreRoleV1::DeriverA),
    ]);
    assert_eq!(
        resolution,
        TenantRootActiveRoleResolutionV1::Ambiguous(
            TenantRootActiveRoleAmbiguityV1::DuplicateLineageRows {
                custody_lineage: lineage(0x31),
                epochs: vec![epoch(7), epoch(9)],
            }
        )
    );
    assert!(resolution.require_active().is_err());

    // Two rows at the exact same epoch are equally ambiguous.
    assert!(matches!(
        resolve(&[
            row(IDENTITY, 0x31, 7, TenantRootManagedRestoreRoleV1::DeriverA),
            row(IDENTITY, 0x31, 7, TenantRootManagedRestoreRoleV1::DeriverA),
        ]),
        TenantRootActiveRoleResolutionV1::Ambiguous(
            TenantRootActiveRoleAmbiguityV1::DuplicateLineageRows { .. }
        )
    ));
}

#[test]
fn resolution_and_diagnostics_are_row_order_independent() {
    let a = row(IDENTITY, 0x31, 9, TenantRootManagedRestoreRoleV1::DeriverA);
    let b = row(IDENTITY, 0x32, 7, TenantRootManagedRestoreRoleV1::DeriverA);
    assert_eq!(resolve(&[a.clone(), b.clone()]), resolve(&[b, a]));

    let early = row(IDENTITY, 0x31, 7, TenantRootManagedRestoreRoleV1::DeriverA);
    let late = row(IDENTITY, 0x31, 9, TenantRootManagedRestoreRoleV1::DeriverA);
    assert_eq!(
        resolve(&[early.clone(), late.clone()]),
        resolve(&[late, early])
    );
}

#[test]
fn foreign_identity_or_role_rows_fail_closed_instead_of_reporting_ambiguity() {
    for foreign in [
        row(
            OTHER_IDENTITY,
            0x31,
            7,
            TenantRootManagedRestoreRoleV1::DeriverA,
        ),
        row(IDENTITY, 0x31, 7, TenantRootManagedRestoreRoleV1::DeriverB),
    ] {
        let error = resolve_active_tenant_root_role_binding_v1(
            identity(IDENTITY),
            TenantRootManagedRestoreRoleV1::DeriverA,
            &[foreign],
        )
        .unwrap_err();
        assert_eq!(error.code(), RouterAbDerivationErrorCode::MalformedInput);
    }
}

#[test]
fn each_role_resolves_only_its_own_active_row() {
    let deriver_b = row(IDENTITY, 0x31, 7, TenantRootManagedRestoreRoleV1::DeriverB);
    let resolution = resolve_active_tenant_root_role_binding_v1(
        identity(IDENTITY),
        TenantRootManagedRestoreRoleV1::DeriverB,
        &[deriver_b],
    )
    .expect("resolution");
    assert_eq!(
        resolution.require_active().expect("active").role(),
        TenantRootManagedRestoreRoleV1::DeriverB
    );
}

fn active(
    role: TenantRootManagedRestoreRoleV1,
    lineage_seed: u8,
    epoch_value: u64,
) -> TenantRootActiveRoleResolutionV1 {
    TenantRootActiveRoleResolutionV1::Active(row(IDENTITY, lineage_seed, epoch_value, role))
}

fn resolve_pair(
    deriver_a: &TenantRootActiveRoleResolutionV1,
    deriver_b: &TenantRootActiveRoleResolutionV1,
) -> TenantRootActivePairResolutionV1 {
    resolve_active_tenant_root_pair_binding_v1(identity(IDENTITY), deriver_a, deriver_b)
        .expect("pair resolution")
}

#[test]
fn one_active_row_per_role_resolves_to_one_physical_root_pair() {
    let resolution = resolve_pair(
        &active(TenantRootManagedRestoreRoleV1::DeriverA, 0x31, 7),
        &active(TenantRootManagedRestoreRoleV1::DeriverB, 0x31, 7),
    );

    let pair = resolution.require_active().expect("active pair");
    assert_eq!(pair.identity_digest(), identity(IDENTITY));
    assert_eq!(pair.custody_lineage(), lineage(0x31));
    assert_eq!(pair.epoch(), epoch(7));
    assert_eq!(
        pair.deriver_a().role(),
        TenantRootManagedRestoreRoleV1::DeriverA
    );
    assert_eq!(
        pair.deriver_b().role(),
        TenantRootManagedRestoreRoleV1::DeriverB
    );
}

#[test]
fn the_resolved_pair_preserves_both_stored_role_commitments() {
    let resolution = resolve_pair(
        &active(TenantRootManagedRestoreRoleV1::DeriverA, 0x31, 7),
        &active(TenantRootManagedRestoreRoleV1::DeriverB, 0x31, 7),
    );
    let pair = resolution.require_active().expect("active pair");

    // Each role's commitment survives resolution unchanged and stays on its own side.
    assert_eq!(
        pair.deriver_a().share_commitment(),
        &commitment(TenantRootManagedRestoreRoleV1::DeriverA, 17)
    );
    assert_eq!(
        pair.deriver_b().share_commitment(),
        &commitment(TenantRootManagedRestoreRoleV1::DeriverB, 29)
    );
    assert_eq!(
        pair.commitments().deriver_a(),
        pair.deriver_a().share_commitment()
    );
    assert_eq!(
        pair.commitments().deriver_b(),
        pair.deriver_b().share_commitment()
    );

    // The joined root commitment is the pair's stable public identity.
    let expected = router_ab_core::TenantRootEpochCommitmentsV1::new(
        commitment(TenantRootManagedRestoreRoleV1::DeriverA, 17),
        commitment(TenantRootManagedRestoreRoleV1::DeriverB, 29),
    )
    .expect("epoch commitments");
    assert_eq!(pair.root_commitment(), expected.root_commitment());
}

#[test]
fn a_commitment_can_only_be_bound_to_the_role_that_committed_it() {
    let error = TenantRootActiveRoleBindingV1::new(
        row_key(IDENTITY, 0x31, 7, TenantRootManagedRestoreRoleV1::DeriverA),
        commitment(TenantRootManagedRestoreRoleV1::DeriverB, 29),
        receipt(0x41),
    )
    .unwrap_err();
    assert_eq!(error.code(), RouterAbDerivationErrorCode::MalformedInput);
}

#[test]
fn malformed_commitment_wire_fails_closed_without_panicking() {
    let error = TenantRootActiveRoleBindingV1::new(
        row_key(IDENTITY, 0x31, 7, TenantRootManagedRestoreRoleV1::DeriverA),
        MpcPrfShareCommitmentWireV1 { bytes: Vec::new() },
        receipt(0x41),
    )
    .unwrap_err();
    assert_eq!(error.code(), RouterAbDerivationErrorCode::MalformedInput);
}

#[test]
fn generic_role_commitment_validation_does_not_require_an_active_receipt() {
    let role = TenantRootManagedRestoreRoleV1::DeriverA;
    let valid = commitment(role, role_scalar(role));
    assert!(validate_tenant_root_active_role_share_commitment_v1(role, &valid).is_ok());
    assert!(validate_tenant_root_active_role_share_commitment_v1(
        role,
        &commitment(TenantRootManagedRestoreRoleV1::DeriverB, 29),
    )
    .is_err());
}

#[test]
fn malformed_commitment_point_fails_at_role_binding_construction() {
    let mut bytes = commitment(TenantRootManagedRestoreRoleV1::DeriverB, 29)
        .as_bytes()
        .to_vec();
    bytes[2..].fill(0xff);
    let error = TenantRootActiveRoleBindingV1::new(
        row_key(IDENTITY, 0x31, 7, TenantRootManagedRestoreRoleV1::DeriverB),
        MpcPrfShareCommitmentWireV1::new(bytes).expect("commitment wire"),
        receipt(0x41),
    )
    .unwrap_err();
    assert_eq!(error.code(), RouterAbDerivationErrorCode::MalformedInput);
}

#[test]
fn identity_commitment_fails_at_role_binding_construction() {
    let mut bytes = vec![0_u8; 34];
    bytes[..2].copy_from_slice(&2_u16.to_be_bytes());
    bytes[2..].copy_from_slice(RistrettoPoint::identity().compress().as_bytes());
    let error = TenantRootActiveRoleBindingV1::new(
        row_key(IDENTITY, 0x31, 7, TenantRootManagedRestoreRoleV1::DeriverB),
        MpcPrfShareCommitmentWireV1::new(bytes).expect("commitment wire"),
        receipt(0x41),
    )
    .unwrap_err();
    assert_eq!(error.code(), RouterAbDerivationErrorCode::MalformedInput);
}

#[test]
fn neither_role_provisioned_resolves_to_unprovisioned() {
    let resolution = resolve_pair(
        &TenantRootActiveRoleResolutionV1::Unprovisioned,
        &TenantRootActiveRoleResolutionV1::Unprovisioned,
    );
    assert_eq!(resolution, TenantRootActivePairResolutionV1::Unprovisioned);
    assert_eq!(
        resolution.require_active().unwrap_err().code(),
        RouterAbDerivationErrorCode::MissingActiveTenantRootBinding
    );
}

#[test]
fn one_role_alone_is_a_partial_pair_and_never_derives() {
    for (present, deriver_a, deriver_b) in [
        (
            TenantRootManagedRestoreRoleV1::DeriverA,
            active(TenantRootManagedRestoreRoleV1::DeriverA, 0x31, 7),
            TenantRootActiveRoleResolutionV1::Unprovisioned,
        ),
        (
            TenantRootManagedRestoreRoleV1::DeriverB,
            TenantRootActiveRoleResolutionV1::Unprovisioned,
            active(TenantRootManagedRestoreRoleV1::DeriverB, 0x31, 7),
        ),
    ] {
        let resolution = resolve_pair(&deriver_a, &deriver_b);
        assert_eq!(
            resolution,
            TenantRootActivePairResolutionV1::Partial { present }
        );
        assert_eq!(
            resolution.require_active().unwrap_err().code(),
            RouterAbDerivationErrorCode::MissingActiveTenantRootBinding
        );
    }
}

#[test]
fn distinct_role_lineages_are_a_mismatch_and_never_pick_a_winner() {
    let resolution = resolve_pair(
        &active(TenantRootManagedRestoreRoleV1::DeriverA, 0x31, 7),
        &active(TenantRootManagedRestoreRoleV1::DeriverB, 0x32, 7),
    );
    assert_eq!(
        resolution,
        TenantRootActivePairResolutionV1::Mismatched(
            TenantRootActivePairMismatchV1::CustodyLineage {
                deriver_a: lineage(0x31),
                deriver_b: lineage(0x32),
            }
        )
    );
    assert_eq!(
        resolution.require_active().unwrap_err().code(),
        RouterAbDerivationErrorCode::MismatchedActiveTenantRootPair
    );
}

#[test]
fn distinct_role_epochs_are_a_mismatch_and_never_choose_the_latest() {
    let resolution = resolve_pair(
        &active(TenantRootManagedRestoreRoleV1::DeriverA, 0x31, 7),
        &active(TenantRootManagedRestoreRoleV1::DeriverB, 0x31, 9),
    );
    assert_eq!(
        resolution,
        TenantRootActivePairResolutionV1::Mismatched(TenantRootActivePairMismatchV1::Epoch {
            deriver_a: epoch(7),
            deriver_b: epoch(9),
        })
    );
    assert_eq!(
        resolution.require_active().unwrap_err().code(),
        RouterAbDerivationErrorCode::MismatchedActiveTenantRootPair
    );
}

#[test]
fn distinct_role_activation_receipts_are_a_mismatch_before_pair_construction() {
    let deriver_a = TenantRootActiveRoleResolutionV1::Active(binding_with_receipt(
        row_key(IDENTITY, 0x31, 7, TenantRootManagedRestoreRoleV1::DeriverA),
        commitment(TenantRootManagedRestoreRoleV1::DeriverA, 17),
        receipt(0x41),
    ));
    let deriver_b = TenantRootActiveRoleResolutionV1::Active(binding_with_receipt(
        row_key(IDENTITY, 0x31, 7, TenantRootManagedRestoreRoleV1::DeriverB),
        commitment(TenantRootManagedRestoreRoleV1::DeriverB, 29),
        receipt(0x42),
    ));

    let resolution = resolve_pair(&deriver_a, &deriver_b);
    assert_eq!(
        resolution,
        TenantRootActivePairResolutionV1::Mismatched(
            TenantRootActivePairMismatchV1::ActivationReceiptDigests {
                deriver_a: receipt(0x41),
                deriver_b: receipt(0x42),
            }
        )
    );
    assert_eq!(
        resolution.require_active().unwrap_err().code(),
        RouterAbDerivationErrorCode::MismatchedActiveTenantRootPair
    );
}

#[test]
fn a_role_commitment_that_joins_no_pair_is_a_commitment_mismatch() {
    // Correct, non-identity role commitments whose joined root is the identity.
    let identity_root = binding(
        row_key(IDENTITY, 0x31, 7, TenantRootManagedRestoreRoleV1::DeriverB),
        commitment(TenantRootManagedRestoreRoleV1::DeriverB, 34),
    );

    let resolution = resolve_pair(
        &active(TenantRootManagedRestoreRoleV1::DeriverA, 0x31, 7),
        &TenantRootActiveRoleResolutionV1::Active(identity_root),
    );
    assert_eq!(
        resolution,
        TenantRootActivePairResolutionV1::Mismatched(
            TenantRootActivePairMismatchV1::ShareCommitments
        )
    );
    assert_eq!(
        resolution.require_active().unwrap_err().code(),
        RouterAbDerivationErrorCode::MismatchedActiveTenantRootPair
    );
}

#[test]
fn equal_role_commitment_points_are_not_an_active_pair() {
    // Role ids differ, while the committed Ristretto point is identical.
    let deriver_a = active(TenantRootManagedRestoreRoleV1::DeriverA, 0x31, 7);
    let deriver_b = TenantRootActiveRoleResolutionV1::Active(binding(
        row_key(IDENTITY, 0x31, 7, TenantRootManagedRestoreRoleV1::DeriverB),
        commitment(TenantRootManagedRestoreRoleV1::DeriverB, 17),
    ));

    let resolution = resolve_pair(&deriver_a, &deriver_b);
    assert_eq!(
        resolution,
        TenantRootActivePairResolutionV1::Mismatched(
            TenantRootActivePairMismatchV1::ShareCommitments
        )
    );
}

#[test]
fn an_ambiguous_role_is_reported_by_role_and_never_derives() {
    let ambiguous = resolve(&[
        row(IDENTITY, 0x31, 7, TenantRootManagedRestoreRoleV1::DeriverA),
        row(IDENTITY, 0x32, 7, TenantRootManagedRestoreRoleV1::DeriverA),
    ]);
    let TenantRootActiveRoleResolutionV1::Ambiguous(expected) = ambiguous.clone() else {
        panic!("expected an ambiguous role resolution");
    };

    let resolution = resolve_pair(
        &ambiguous,
        &active(TenantRootManagedRestoreRoleV1::DeriverB, 0x31, 7),
    );
    assert_eq!(
        resolution,
        TenantRootActivePairResolutionV1::AmbiguousRole {
            role: TenantRootManagedRestoreRoleV1::DeriverA,
            ambiguity: expected,
        }
    );
    assert_eq!(
        resolution.require_active().unwrap_err().code(),
        RouterAbDerivationErrorCode::AmbiguousActiveTenantRootBinding
    );
}

#[test]
fn an_ambiguous_role_outranks_its_peers_missing_share() {
    let ambiguous = resolve(&[
        row(IDENTITY, 0x31, 7, TenantRootManagedRestoreRoleV1::DeriverA),
        row(IDENTITY, 0x31, 9, TenantRootManagedRestoreRoleV1::DeriverA),
    ]);
    assert!(matches!(
        resolve_pair(&ambiguous, &TenantRootActiveRoleResolutionV1::Unprovisioned),
        TenantRootActivePairResolutionV1::AmbiguousRole {
            role: TenantRootManagedRestoreRoleV1::DeriverA,
            ..
        }
    ));
}

#[test]
fn a_role_resolution_in_the_wrong_position_fails_closed() {
    // Deriver B's active row supplied as Deriver A's, and a foreign identity.
    for (deriver_a, deriver_b) in [
        (
            active(TenantRootManagedRestoreRoleV1::DeriverB, 0x31, 7),
            active(TenantRootManagedRestoreRoleV1::DeriverB, 0x31, 7),
        ),
        (
            TenantRootActiveRoleResolutionV1::Active(row(
                OTHER_IDENTITY,
                0x31,
                7,
                TenantRootManagedRestoreRoleV1::DeriverA,
            )),
            active(TenantRootManagedRestoreRoleV1::DeriverB, 0x31, 7),
        ),
    ] {
        let error =
            resolve_active_tenant_root_pair_binding_v1(identity(IDENTITY), &deriver_a, &deriver_b)
                .unwrap_err();
        assert_eq!(error.code(), RouterAbDerivationErrorCode::MalformedInput);
    }
}
