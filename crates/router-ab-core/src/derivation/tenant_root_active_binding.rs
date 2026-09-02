use curve25519_dalek::{ristretto::RistrettoPoint, traits::Identity};
use subtle::ConstantTimeEq;
use threshold_prf::{SigningRootShareCommitment, TwoPartyDeriverRole};

use super::{
    MpcPrfShareCommitmentWireV1, RouterAbDerivationError, RouterAbDerivationErrorCode,
    RouterAbDerivationResult, TenantRootCustodyBindingV1, TenantRootCustodyLineageId,
    TenantRootEpochCommitmentsV1, TenantRootIdentityDigestV1, TenantRootLifecycleReceiptDigestV1,
    TenantRootManagedRestoreRoleV1, TenantRootShareEpoch,
};

/// Public coordinates of one stored active role-share row.
///
/// Every component is an already-validated custody type. The row's sealed share,
/// commitment ciphertext, and wrapping-key reference are deliberately absent, so
/// no resolution or ambiguity value can carry secret material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TenantRootActiveRoleRowKeyV1 {
    identity_digest: TenantRootIdentityDigestV1,
    custody_lineage: TenantRootCustodyLineageId,
    epoch: TenantRootShareEpoch,
    role: TenantRootManagedRestoreRoleV1,
}

impl TenantRootActiveRoleRowKeyV1 {
    /// Creates one exact observed active-row key.
    pub const fn new(
        identity_digest: TenantRootIdentityDigestV1,
        custody_lineage: TenantRootCustodyLineageId,
        epoch: TenantRootShareEpoch,
        role: TenantRootManagedRestoreRoleV1,
    ) -> Self {
        Self {
            identity_digest,
            custody_lineage,
            epoch,
            role,
        }
    }

    /// Returns the server-resolved logical tenant-root identity digest.
    pub const fn identity_digest(&self) -> TenantRootIdentityDigestV1 {
        self.identity_digest
    }

    /// Returns the deployment-local custody lineage owning this row.
    pub const fn custody_lineage(&self) -> TenantRootCustodyLineageId {
        self.custody_lineage
    }

    /// Returns the active custody epoch.
    pub const fn epoch(&self) -> TenantRootShareEpoch {
        self.epoch
    }

    /// Returns the role whose private store holds this row.
    pub const fn role(&self) -> TenantRootManagedRestoreRoleV1 {
        self.role
    }
}

/// One observed active role row and the public share commitment stored with it.
///
/// The commitment is carried beside its own row so a pair can never be assembled
/// from one role's coordinates and another role's commitment. Construction pins
/// the commitment's embedded threshold share id to the row's role, so a row can
/// only ever present the commitment its own role is allowed to hold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantRootActiveRoleBindingV1 {
    row: TenantRootActiveRoleRowKeyV1,
    share_commitment: MpcPrfShareCommitmentWireV1,
    activation_receipt_digest: TenantRootLifecycleReceiptDigestV1,
}

impl TenantRootActiveRoleBindingV1 {
    /// Binds one active row to the share commitment its role must hold.
    pub fn new(
        row: TenantRootActiveRoleRowKeyV1,
        share_commitment: MpcPrfShareCommitmentWireV1,
        activation_receipt_digest: TenantRootLifecycleReceiptDigestV1,
    ) -> RouterAbDerivationResult<Self> {
        let share_commitment =
            MpcPrfShareCommitmentWireV1::new(share_commitment.as_bytes().to_vec())?;
        validate_share_commitment_for_role(row.role, &share_commitment)?;
        Ok(Self {
            row,
            share_commitment,
            activation_receipt_digest,
        })
    }

    /// Returns the public coordinates of the bound row.
    pub const fn row(&self) -> &TenantRootActiveRoleRowKeyV1 {
        &self.row
    }

    /// Returns the public share commitment stored with the bound row.
    pub const fn share_commitment(&self) -> &MpcPrfShareCommitmentWireV1 {
        &self.share_commitment
    }

    /// Returns the control-plane activation receipt retained by this role.
    pub const fn activation_receipt_digest(&self) -> TenantRootLifecycleReceiptDigestV1 {
        self.activation_receipt_digest
    }

    /// Returns the server-resolved logical tenant-root identity digest.
    pub const fn identity_digest(&self) -> TenantRootIdentityDigestV1 {
        self.row.identity_digest
    }

    /// Returns the deployment-local custody lineage owning this row.
    pub const fn custody_lineage(&self) -> TenantRootCustodyLineageId {
        self.row.custody_lineage
    }

    /// Returns the active custody epoch.
    pub const fn epoch(&self) -> TenantRootShareEpoch {
        self.row.epoch
    }

    /// Returns the role whose private store holds this row.
    pub const fn role(&self) -> TenantRootManagedRestoreRoleV1 {
        self.row.role
    }
}

/// Returns the protocol role that owns the given custody role's share.
const fn deriver_role(role: TenantRootManagedRestoreRoleV1) -> TwoPartyDeriverRole {
    match role {
        TenantRootManagedRestoreRoleV1::DeriverA => TwoPartyDeriverRole::DeriverA,
        TenantRootManagedRestoreRoleV1::DeriverB => TwoPartyDeriverRole::DeriverB,
    }
}

/// Returns the fixed threshold share id the given custody role must commit to.
///
/// The mapping is the protocol's own, so a custody role and its share id can
/// never drift apart here.
fn role_share_id(role: TenantRootManagedRestoreRoleV1) -> u16 {
    deriver_role(role).share_id().get().get()
}

/// Validates one persisted role commitment without requiring an active-row
/// activation receipt. Lifecycle adapters use this for pending and retired
/// records whose commitment still needs the same canonical boundary checks.
pub fn validate_tenant_root_active_role_share_commitment_v1(
    role: TenantRootManagedRestoreRoleV1,
    share_commitment: &MpcPrfShareCommitmentWireV1,
) -> RouterAbDerivationResult<()> {
    let share_commitment = MpcPrfShareCommitmentWireV1::new(share_commitment.as_bytes().to_vec())?;
    validate_share_commitment_for_role(role, &share_commitment)
}

fn validate_share_commitment_for_role(
    role: TenantRootManagedRestoreRoleV1,
    share_commitment: &MpcPrfShareCommitmentWireV1,
) -> RouterAbDerivationResult<()> {
    let bytes = share_commitment.as_bytes();
    let observed = u16::from_be_bytes([bytes[0], bytes[1]]);
    if observed != role_share_id(role) {
        return Err(RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::MalformedInput,
            "tenant-root active share commitment does not match its own Deriver role",
        ));
    }
    validate_share_commitment(share_commitment)
}

/// Validates that a persisted role commitment is exactly one canonical,
/// non-identity Ristretto point for its already-validated role id.
fn validate_share_commitment(
    share_commitment: &MpcPrfShareCommitmentWireV1,
) -> RouterAbDerivationResult<()> {
    let parsed =
        SigningRootShareCommitment::from_slice(share_commitment.as_bytes()).map_err(|_| {
            RouterAbDerivationError::new(
                RouterAbDerivationErrorCode::MalformedInput,
                "tenant-root active share commitment encoding is invalid",
            )
        })?;
    if parsed.to_bytes().as_ref() != share_commitment.as_bytes() {
        return Err(RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::MalformedInput,
            "tenant-root active share commitment is not canonically encoded",
        ));
    }
    if bool::from(
        parsed
            .to_compressed()
            .ct_eq(&RistrettoPoint::identity().compress().to_bytes()),
    ) {
        return Err(RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::MalformedInput,
            "tenant-root active share commitment must not be the identity point",
        ));
    }
    Ok(())
}

/// Why one authenticated identity and role has no single active binding.
///
/// Both branches carry only public custody metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TenantRootActiveRoleAmbiguityV1 {
    /// Active rows exist under more than one custody lineage.
    DistinctLineages {
        /// Every observed lineage, ordered by its canonical bytes.
        custody_lineages: Vec<TenantRootCustodyLineageId>,
    },
    /// One custody lineage holds more than one active row.
    DuplicateLineageRows {
        /// The lineage holding the conflicting rows.
        custody_lineage: TenantRootCustodyLineageId,
        /// Every observed active epoch in that lineage, ascending.
        epochs: Vec<TenantRootShareEpoch>,
    },
}

/// Exhaustive result of resolving one authenticated identity and role to its
/// active root binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TenantRootActiveRoleResolutionV1 {
    /// No active row exists for this identity and role.
    Unprovisioned,
    /// Exactly one active row exists.
    Active(TenantRootActiveRoleBindingV1),
    /// More than one active row exists; no automatic winner is selected.
    Ambiguous(TenantRootActiveRoleAmbiguityV1),
}

impl TenantRootActiveRoleResolutionV1 {
    /// Returns the one active binding, or fails closed.
    ///
    /// Derivation and runtime callers use this. Reconciliation matches the
    /// resolution directly so it can observe the ambiguous state without
    /// deriving from it.
    pub fn require_active(&self) -> RouterAbDerivationResult<&TenantRootActiveRoleBindingV1> {
        match self {
            Self::Active(binding) => Ok(binding),
            Self::Unprovisioned => Err(RouterAbDerivationError::new(
                RouterAbDerivationErrorCode::MissingActiveTenantRootBinding,
                "authenticated tenant root has no active role share",
            )),
            Self::Ambiguous(_) => Err(RouterAbDerivationError::new(
                RouterAbDerivationErrorCode::AmbiguousActiveTenantRootBinding,
                "authenticated tenant root resolves to more than one active role share",
            )),
        }
    }
}

/// Resolves every observed active row for one authenticated identity and role.
///
/// The caller supplies only the authenticated identity digest and its own role;
/// it never supplies a lineage or epoch, so no request can select one. Any row
/// carrying another identity or role is a store-boundary failure, not ambiguity.
pub fn resolve_active_tenant_root_role_binding_v1(
    identity_digest: TenantRootIdentityDigestV1,
    role: TenantRootManagedRestoreRoleV1,
    observed: &[TenantRootActiveRoleBindingV1],
) -> RouterAbDerivationResult<TenantRootActiveRoleResolutionV1> {
    for binding in observed {
        if binding.row.identity_digest != identity_digest || binding.row.role != role {
            return Err(RouterAbDerivationError::new(
                RouterAbDerivationErrorCode::MalformedInput,
                "tenant-root active row does not belong to the authenticated identity and role",
            ));
        }
    }

    let Some(first) = observed.first() else {
        return Ok(TenantRootActiveRoleResolutionV1::Unprovisioned);
    };
    if observed.len() == 1 {
        return Ok(TenantRootActiveRoleResolutionV1::Active(first.clone()));
    }

    let mut custody_lineages: Vec<TenantRootCustodyLineageId> = observed
        .iter()
        .map(|binding| binding.row.custody_lineage)
        .collect();
    custody_lineages.sort_by_key(|lineage| *lineage.as_bytes());
    custody_lineages.dedup();
    if custody_lineages.len() > 1 {
        return Ok(TenantRootActiveRoleResolutionV1::Ambiguous(
            TenantRootActiveRoleAmbiguityV1::DistinctLineages { custody_lineages },
        ));
    }

    let mut epochs: Vec<TenantRootShareEpoch> =
        observed.iter().map(|binding| binding.row.epoch).collect();
    epochs.sort_by_key(|epoch| epoch.get().get());
    Ok(TenantRootActiveRoleResolutionV1::Ambiguous(
        TenantRootActiveRoleAmbiguityV1::DuplicateLineageRows {
            custody_lineage: first.row.custody_lineage,
            epochs,
        },
    ))
}

/// The one active Deriver A/B physical root pair for an authenticated tenant.
///
/// Construction is the only way to obtain this type, so holding one is proof
/// that both roles agree on identity, custody lineage, and epoch, that the roles
/// are complementary, and that each role presents its own distinct commitment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantRootActiveRootPairV1 {
    deriver_a: TenantRootActiveRoleBindingV1,
    deriver_b: TenantRootActiveRoleBindingV1,
    commitments: TenantRootEpochCommitmentsV1,
}

impl TenantRootActiveRootPairV1 {
    /// Returns Deriver A's active role binding.
    pub const fn deriver_a(&self) -> &TenantRootActiveRoleBindingV1 {
        &self.deriver_a
    }

    /// Returns Deriver B's active role binding.
    pub const fn deriver_b(&self) -> &TenantRootActiveRoleBindingV1 {
        &self.deriver_b
    }

    /// Returns the authenticated identity digest both roles share.
    pub const fn identity_digest(&self) -> TenantRootIdentityDigestV1 {
        self.deriver_a.identity_digest()
    }

    /// Returns the custody lineage both roles share.
    pub const fn custody_lineage(&self) -> TenantRootCustodyLineageId {
        self.deriver_a.custody_lineage()
    }

    /// Returns the custody epoch both roles share.
    pub const fn epoch(&self) -> TenantRootShareEpoch {
        self.deriver_a.epoch()
    }

    /// Returns the exact A/B role commitments joined for this epoch.
    pub const fn commitments(&self) -> &TenantRootEpochCommitmentsV1 {
        &self.commitments
    }

    /// Returns the stable joined public root commitment of this pair.
    pub const fn root_commitment(&self) -> &[u8; 32] {
        self.commitments.root_commitment()
    }

    /// Returns the activation receipt shared by both roles in this pair.
    pub const fn activation_receipt_digest(&self) -> TenantRootLifecycleReceiptDigestV1 {
        self.deriver_a.activation_receipt_digest()
    }
}

/// Why two active role bindings do not form one physical root pair.
///
/// Every branch carries only public custody metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TenantRootActivePairMismatchV1 {
    /// The roles are active under different custody lineages.
    CustodyLineage {
        /// Deriver A's observed lineage.
        deriver_a: TenantRootCustodyLineageId,
        /// Deriver B's observed lineage.
        deriver_b: TenantRootCustodyLineageId,
    },
    /// The roles are active at different custody epochs.
    Epoch {
        /// Deriver A's observed epoch.
        deriver_a: TenantRootShareEpoch,
        /// Deriver B's observed epoch.
        deriver_b: TenantRootShareEpoch,
    },
    /// The two role commitments do not join into one epoch commitment pair.
    ///
    /// A pair commits to one share per role, so an identical or role-swapped
    /// commitment means one role's share was installed twice rather than a pair
    /// being created.
    ShareCommitments,
    /// Deriver A and Deriver B retained different activation receipt digests.
    ActivationReceiptDigests {
        /// The receipt retained by Deriver A.
        deriver_a: TenantRootLifecycleReceiptDigestV1,
        /// The receipt retained by Deriver B.
        deriver_b: TenantRootLifecycleReceiptDigestV1,
    },
    /// The observed pair does not match the authenticated custody binding.
    CustodyBinding,
    /// One or both roles retained an activation receipt different from the
    /// authenticated custody binding.
    ActivationReceiptDigest {
        /// The receipt selected by the authenticated custody binding.
        expected: TenantRootLifecycleReceiptDigestV1,
        /// The receipt retained by Deriver A.
        deriver_a: TenantRootLifecycleReceiptDigestV1,
        /// The receipt retained by Deriver B.
        deriver_b: TenantRootLifecycleReceiptDigestV1,
    },
}

/// Exhaustive result of resolving one authenticated tenant to its active pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TenantRootActivePairResolutionV1 {
    /// Neither role holds an active share.
    Unprovisioned,
    /// Exactly one active pair exists.
    Active(Box<TenantRootActiveRootPairV1>),
    /// Exactly one role holds an active share.
    Partial {
        /// The role that is active on its own.
        present: TenantRootManagedRestoreRoleV1,
    },
    /// One role does not resolve to a single active row.
    AmbiguousRole {
        /// The role whose own resolution is ambiguous.
        role: TenantRootManagedRestoreRoleV1,
        /// That role's observed ambiguity.
        ambiguity: TenantRootActiveRoleAmbiguityV1,
    },
    /// Both roles are active but do not belong to one pair.
    Mismatched(TenantRootActivePairMismatchV1),
}

impl TenantRootActivePairResolutionV1 {
    /// Returns the one active pair, or fails closed.
    ///
    /// Derivation and runtime callers use this. Reconciliation matches the
    /// resolution directly so it can observe an unsafe state without deriving
    /// from it.
    pub fn require_active(&self) -> RouterAbDerivationResult<&TenantRootActiveRootPairV1> {
        match self {
            Self::Active(pair) => Ok(pair),
            Self::Unprovisioned => Err(RouterAbDerivationError::new(
                RouterAbDerivationErrorCode::MissingActiveTenantRootBinding,
                "authenticated tenant root has no active root pair",
            )),
            Self::Partial { .. } => Err(RouterAbDerivationError::new(
                RouterAbDerivationErrorCode::MissingActiveTenantRootBinding,
                "authenticated tenant root has only one active Deriver role",
            )),
            Self::AmbiguousRole { .. } => Err(RouterAbDerivationError::new(
                RouterAbDerivationErrorCode::AmbiguousActiveTenantRootBinding,
                "authenticated tenant root resolves to more than one active role share",
            )),
            Self::Mismatched(_) => Err(RouterAbDerivationError::new(
                RouterAbDerivationErrorCode::MismatchedActiveTenantRootPair,
                "authenticated tenant root active roles do not form one physical root pair",
            )),
        }
    }
}

/// Resolves one authenticated tenant to its single active physical root pair.
///
/// Each role's resolution is produced independently by its own private store, so
/// this is the only place the two halves meet. The caller supplies the
/// authenticated identity digest and nothing else; a role resolution carrying
/// another identity, or a role that is not the one its position names, is a
/// store-boundary failure rather than a pair state.
pub fn resolve_active_tenant_root_pair_binding_v1(
    identity_digest: TenantRootIdentityDigestV1,
    deriver_a: &TenantRootActiveRoleResolutionV1,
    deriver_b: &TenantRootActiveRoleResolutionV1,
) -> RouterAbDerivationResult<TenantRootActivePairResolutionV1> {
    require_role_position(
        identity_digest,
        deriver_a,
        TenantRootManagedRestoreRoleV1::DeriverA,
    )?;
    require_role_position(
        identity_digest,
        deriver_b,
        TenantRootManagedRestoreRoleV1::DeriverB,
    )?;

    if let TenantRootActiveRoleResolutionV1::Ambiguous(ambiguity) = deriver_a {
        return Ok(TenantRootActivePairResolutionV1::AmbiguousRole {
            role: TenantRootManagedRestoreRoleV1::DeriverA,
            ambiguity: ambiguity.clone(),
        });
    }
    if let TenantRootActiveRoleResolutionV1::Ambiguous(ambiguity) = deriver_b {
        return Ok(TenantRootActivePairResolutionV1::AmbiguousRole {
            role: TenantRootManagedRestoreRoleV1::DeriverB,
            ambiguity: ambiguity.clone(),
        });
    }

    let (deriver_a, deriver_b) = match (deriver_a, deriver_b) {
        (
            TenantRootActiveRoleResolutionV1::Unprovisioned,
            TenantRootActiveRoleResolutionV1::Unprovisioned,
        ) => return Ok(TenantRootActivePairResolutionV1::Unprovisioned),
        (
            TenantRootActiveRoleResolutionV1::Active(_),
            TenantRootActiveRoleResolutionV1::Unprovisioned,
        ) => {
            return Ok(TenantRootActivePairResolutionV1::Partial {
                present: TenantRootManagedRestoreRoleV1::DeriverA,
            })
        }
        (
            TenantRootActiveRoleResolutionV1::Unprovisioned,
            TenantRootActiveRoleResolutionV1::Active(_),
        ) => {
            return Ok(TenantRootActivePairResolutionV1::Partial {
                present: TenantRootManagedRestoreRoleV1::DeriverB,
            })
        }
        (
            TenantRootActiveRoleResolutionV1::Active(deriver_a),
            TenantRootActiveRoleResolutionV1::Active(deriver_b),
        ) => (deriver_a, deriver_b),
        (TenantRootActiveRoleResolutionV1::Ambiguous(_), _)
        | (_, TenantRootActiveRoleResolutionV1::Ambiguous(_)) => {
            return Err(RouterAbDerivationError::new(
                RouterAbDerivationErrorCode::AmbiguousActiveTenantRootBinding,
                "tenant-root pair resolution reached an unreported ambiguous role",
            ))
        }
    };

    if deriver_a.custody_lineage() != deriver_b.custody_lineage() {
        return Ok(TenantRootActivePairResolutionV1::Mismatched(
            TenantRootActivePairMismatchV1::CustodyLineage {
                deriver_a: deriver_a.custody_lineage(),
                deriver_b: deriver_b.custody_lineage(),
            },
        ));
    }
    if deriver_a.epoch() != deriver_b.epoch() {
        return Ok(TenantRootActivePairResolutionV1::Mismatched(
            TenantRootActivePairMismatchV1::Epoch {
                deriver_a: deriver_a.epoch(),
                deriver_b: deriver_b.epoch(),
            },
        ));
    }
    let deriver_a_receipt = deriver_a.activation_receipt_digest();
    let deriver_b_receipt = deriver_b.activation_receipt_digest();
    if deriver_a_receipt != deriver_b_receipt {
        return Ok(TenantRootActivePairResolutionV1::Mismatched(
            TenantRootActivePairMismatchV1::ActivationReceiptDigests {
                deriver_a: deriver_a_receipt,
                deriver_b: deriver_b_receipt,
            },
        ));
    }
    let Ok(commitments) = TenantRootEpochCommitmentsV1::new(
        deriver_a.share_commitment().clone(),
        deriver_b.share_commitment().clone(),
    ) else {
        return Ok(TenantRootActivePairResolutionV1::Mismatched(
            TenantRootActivePairMismatchV1::ShareCommitments,
        ));
    };

    Ok(TenantRootActivePairResolutionV1::Active(Box::new(
        TenantRootActiveRootPairV1 {
            deriver_a: deriver_a.clone(),
            deriver_b: deriver_b.clone(),
            commitments,
        },
    )))
}

/// Resolves one active pair against the authenticated control-plane custody
/// binding. The pair result retains only stable public pair facts; operation,
/// session, nonce, and time fields remain in the custody binding.
pub fn resolve_authoritative_active_tenant_root_pair_binding_v1(
    identity_digest: TenantRootIdentityDigestV1,
    custody_binding: &TenantRootCustodyBindingV1,
    deriver_a: &TenantRootActiveRoleResolutionV1,
    deriver_b: &TenantRootActiveRoleResolutionV1,
) -> RouterAbDerivationResult<TenantRootActivePairResolutionV1> {
    custody_binding.validate()?;
    if custody_binding.identity_digest() != identity_digest {
        return Err(RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::MalformedInput,
            "tenant-root custody binding does not belong to the authenticated identity",
        ));
    }

    let expected_receipt = custody_binding.activation_receipt_digest();
    let resolution =
        resolve_active_tenant_root_pair_binding_v1(identity_digest, deriver_a, deriver_b)?;
    if let TenantRootActivePairResolutionV1::Mismatched(
        TenantRootActivePairMismatchV1::ActivationReceiptDigests {
            deriver_a,
            deriver_b,
        },
    ) = resolution
    {
        return Ok(TenantRootActivePairResolutionV1::Mismatched(
            TenantRootActivePairMismatchV1::ActivationReceiptDigest {
                expected: expected_receipt,
                deriver_a,
                deriver_b,
            },
        ));
    }
    let TenantRootActivePairResolutionV1::Active(pair) = resolution else {
        return Ok(resolution);
    };

    if pair.custody_lineage() != custody_binding.custody_lineage()
        || pair.epoch() != custody_binding.epoch()
        || pair.commitments() != custody_binding.commitments()
    {
        return Ok(TenantRootActivePairResolutionV1::Mismatched(
            TenantRootActivePairMismatchV1::CustodyBinding,
        ));
    }

    let deriver_a_receipt = pair.deriver_a().activation_receipt_digest();
    let deriver_b_receipt = pair.deriver_b().activation_receipt_digest();
    if deriver_a_receipt != expected_receipt || deriver_b_receipt != expected_receipt {
        return Ok(TenantRootActivePairResolutionV1::Mismatched(
            TenantRootActivePairMismatchV1::ActivationReceiptDigest {
                expected: expected_receipt,
                deriver_a: deriver_a_receipt,
                deriver_b: deriver_b_receipt,
            },
        ));
    }

    Ok(TenantRootActivePairResolutionV1::Active(pair))
}

/// Rejects a role resolution that does not belong to the authenticated tenant
/// and the role its argument position names.
fn require_role_position(
    identity_digest: TenantRootIdentityDigestV1,
    resolution: &TenantRootActiveRoleResolutionV1,
    role: TenantRootManagedRestoreRoleV1,
) -> RouterAbDerivationResult<()> {
    let TenantRootActiveRoleResolutionV1::Active(binding) = resolution else {
        return Ok(());
    };
    if binding.identity_digest() != identity_digest || binding.role() != role {
        return Err(RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::MalformedInput,
            "tenant-root active role resolution does not belong to the authenticated identity and role",
        ));
    }
    Ok(())
}
