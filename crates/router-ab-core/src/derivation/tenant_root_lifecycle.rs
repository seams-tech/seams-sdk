use serde::{de::Error as DeError, ser::SerializeStruct, Deserialize, Deserializer, Serialize};
use threshold_prf::{SigningRootShareCommitment, TwoPartyRootShareCommitments};

use super::{
    verify_tenant_root_creation_evidence_v1, verify_tenant_root_refresh_evidence_v1,
    MpcPrfShareCommitmentWireV1, RouterAbDerivationError, RouterAbDerivationErrorCode,
    RouterAbDerivationResult, TenantRootAcceptedPermanentLossAuthorizationDigestV1,
    TenantRootActivationReceiptAvailabilityV1, TenantRootActivationReceiptBindingV1,
    TenantRootActivationReceiptTransitionV1, TenantRootCeremonyContextV1,
    TenantRootCeremonyEpochsV1, TenantRootCustodyLineageId, TenantRootIdentityV1,
    TenantRootProtocolDigestV1, TenantRootShareEpoch,
    TenantRootSignedAcceptedPermanentLossAuthorizationV1,
    VerifiedTenantRootShareInstallationEvidenceV1, VerifiedTenantRootSignedActivationReceiptV1,
};

/// Public SHA-256 digest of a signed tenant-root lifecycle receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct TenantRootLifecycleReceiptDigestV1([u8; 32]);

impl TenantRootLifecycleReceiptDigestV1 {
    /// Parses a non-zero lifecycle receipt digest.
    pub fn from_bytes(bytes: [u8; 32]) -> RouterAbDerivationResult<Self> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(malformed(
                "tenant-root lifecycle receipt digest must be non-zero",
            ));
        }
        Ok(Self(bytes))
    }

    /// Returns the exact digest bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl<'de> Deserialize<'de> for TenantRootLifecycleReceiptDigestV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = <[u8; 32]>::deserialize(deserializer)?;
        Self::from_bytes(bytes).map_err(D::Error::custom)
    }
}

/// Exact public A/B commitments for one tenant-root epoch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantRootEpochCommitmentsV1 {
    deriver_a: MpcPrfShareCommitmentWireV1,
    deriver_b: MpcPrfShareCommitmentWireV1,
    root_commitment: [u8; 32],
}

impl TenantRootEpochCommitmentsV1 {
    /// Validates exact role commitment wires and computes their stable joined root.
    pub fn new(
        deriver_a: MpcPrfShareCommitmentWireV1,
        deriver_b: MpcPrfShareCommitmentWireV1,
    ) -> RouterAbDerivationResult<Self> {
        let deriver_a = MpcPrfShareCommitmentWireV1::new(deriver_a.as_bytes().to_vec())?;
        let deriver_b = MpcPrfShareCommitmentWireV1::new(deriver_b.as_bytes().to_vec())?;
        let deriver_a_point = parse_share_commitment(&deriver_a)?;
        let deriver_b_point = parse_share_commitment(&deriver_b)?;
        if deriver_a_point.to_compressed() == deriver_b_point.to_compressed() {
            return Err(malformed(
                "tenant-root epoch role commitments must commit to distinct points",
            ));
        }
        let pair = TwoPartyRootShareCommitments::new(deriver_a_point, deriver_b_point)
            .map_err(|_| malformed("tenant-root epoch commitment pair is invalid"))?;
        Ok(Self {
            deriver_a,
            deriver_b,
            root_commitment: pair.root().to_bytes(),
        })
    }

    /// Builds the lifecycle representation from an already verified A/B pair.
    pub fn from_verified(pair: TwoPartyRootShareCommitments) -> RouterAbDerivationResult<Self> {
        Self::new(
            MpcPrfShareCommitmentWireV1::new(pair.deriver_a().to_bytes().to_vec())?,
            MpcPrfShareCommitmentWireV1::new(pair.deriver_b().to_bytes().to_vec())?,
        )
    }

    /// Returns Deriver A's exact public share commitment.
    pub const fn deriver_a(&self) -> &MpcPrfShareCommitmentWireV1 {
        &self.deriver_a
    }

    /// Returns Deriver B's exact public share commitment.
    pub const fn deriver_b(&self) -> &MpcPrfShareCommitmentWireV1 {
        &self.deriver_b
    }

    /// Returns the stable joined public root commitment.
    pub const fn root_commitment(&self) -> &[u8; 32] {
        &self.root_commitment
    }

    /// Verifies a refreshed A/B evidence pair against this epoch's public root.
    pub fn verify_refresh_evidence(
        &self,
        deriver_a: &VerifiedTenantRootShareInstallationEvidenceV1,
        deriver_b: &VerifiedTenantRootShareInstallationEvidenceV1,
    ) -> RouterAbDerivationResult<Self> {
        let current = self.threshold_pair()?;
        let next = verify_tenant_root_refresh_evidence_v1(&current, deriver_a, deriver_b)?;
        Self::from_verified(next)
    }

    pub(crate) fn threshold_pair(&self) -> RouterAbDerivationResult<TwoPartyRootShareCommitments> {
        let pair = TwoPartyRootShareCommitments::new(
            parse_share_commitment(&self.deriver_a)?,
            parse_share_commitment(&self.deriver_b)?,
        )
        .map_err(|_| malformed("tenant-root epoch commitment pair is invalid"))?;
        if pair.root().to_bytes() != self.root_commitment {
            return Err(malformed(
                "tenant-root stored root commitment does not match its role commitments",
            ));
        }
        Ok(pair)
    }
}

/// Both role-signed pending-share installation receipts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantRootRoleInstallationReceiptsV1 {
    deriver_a: TenantRootLifecycleReceiptDigestV1,
    deriver_b: TenantRootLifecycleReceiptDigestV1,
}

impl TenantRootRoleInstallationReceiptsV1 {
    /// Creates the exact A/B receipt pair.
    pub fn new(
        deriver_a: TenantRootLifecycleReceiptDigestV1,
        deriver_b: TenantRootLifecycleReceiptDigestV1,
    ) -> RouterAbDerivationResult<Self> {
        require_distinct_role_receipts(deriver_a, deriver_b)?;
        Ok(Self {
            deriver_a,
            deriver_b,
        })
    }

    /// Returns Deriver A's receipt digest.
    pub const fn deriver_a(&self) -> TenantRootLifecycleReceiptDigestV1 {
        self.deriver_a
    }

    /// Returns Deriver B's receipt digest.
    pub const fn deriver_b(&self) -> TenantRootLifecycleReceiptDigestV1 {
        self.deriver_b
    }
}

/// Both role-local managed-backup receipts for one epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantRootRoleBackupReceiptsV1 {
    deriver_a: TenantRootLifecycleReceiptDigestV1,
    deriver_b: TenantRootLifecycleReceiptDigestV1,
}

impl TenantRootRoleBackupReceiptsV1 {
    /// Creates the exact A/B managed-backup receipt pair.
    pub fn new(
        deriver_a: TenantRootLifecycleReceiptDigestV1,
        deriver_b: TenantRootLifecycleReceiptDigestV1,
    ) -> RouterAbDerivationResult<Self> {
        require_distinct_role_receipts(deriver_a, deriver_b)?;
        Ok(Self {
            deriver_a,
            deriver_b,
        })
    }

    /// Returns Deriver A's managed-backup receipt digest.
    pub const fn deriver_a(&self) -> TenantRootLifecycleReceiptDigestV1 {
        self.deriver_a
    }

    /// Returns Deriver B's managed-backup receipt digest.
    pub const fn deriver_b(&self) -> TenantRootLifecycleReceiptDigestV1 {
        self.deriver_b
    }
}

/// Exact accepted-loss authorization retained from verified activation evidence.
///
/// The lifecycle never accepts a caller-built digest. The authorization bytes
/// and their typed digest are copied only from a verified support-evidence
/// token at the activation-evidence boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantRootAcceptedLossReceiptV1 {
    authorization_bytes: Vec<u8>,
    authorization_digest: TenantRootAcceptedPermanentLossAuthorizationDigestV1,
}

impl TenantRootAcceptedLossReceiptV1 {
    /// Retains the exact accepted-loss authorization from a verified token.
    pub fn from_verified(
        authorization: super::VerifiedTenantRootAcceptedPermanentLossAuthorizationV1,
    ) -> Self {
        let authorization_digest = authorization.digest();
        Self {
            authorization_bytes: authorization.into_canonical_bytes(),
            authorization_digest,
        }
    }

    /// Returns the exact signed authorization bytes.
    pub fn authorization_bytes(&self) -> &[u8] {
        &self.authorization_bytes
    }

    /// Returns the digest of the exact signed authorization bytes.
    pub const fn authorization_digest(
        &self,
    ) -> &TenantRootAcceptedPermanentLossAuthorizationDigestV1 {
        &self.authorization_digest
    }

    /// Returns the exact canonical signed authorization bytes.
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.authorization_bytes
    }

    /// Returns the digest of the exact canonical signed authorization bytes.
    pub const fn digest(&self) -> TenantRootAcceptedPermanentLossAuthorizationDigestV1 {
        self.authorization_digest
    }

    /// Requires the retained authorization to be inside its signed freshness window.
    pub fn require_fresh(&self, now_ms: u64) -> RouterAbDerivationResult<()> {
        let authorization =
            TenantRootSignedAcceptedPermanentLossAuthorizationV1::decode_canonical_bytes(
                &self.authorization_bytes,
            )?;
        if authorization.digest()? != self.authorization_digest {
            return Err(malformed(
                "tenant-root accepted-loss authorization digest does not match its bytes",
            ));
        }
        if now_ms < authorization.issued_at_ms() || now_ms > authorization.expires_at_ms() {
            return Err(replay_mismatch(
                "tenant-root accepted-loss authorization is outside its freshness window",
            ));
        }
        Ok(())
    }
}

impl Serialize for TenantRootAcceptedLossReceiptV1 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("TenantRootAcceptedLossReceiptV1", 2)?;
        state.serialize_field("authorizationBytes", &self.authorization_bytes)?;
        state.serialize_field("authorizationDigest", self.authorization_digest.as_bytes())?;
        state.end()
    }
}

/// Exact availability branch required before a tenant-root epoch can activate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", content = "evidence", rename_all = "snake_case")]
pub enum TenantRootBackupPolicyV1 {
    /// Both roles hold independently encrypted current-epoch managed backups.
    CurrentRoleBackups(TenantRootRoleBackupReceiptsV1),
    /// The deployment explicitly accepts permanent future-derivation loss.
    AcceptedPermanentDerivationLoss(TenantRootAcceptedLossReceiptV1),
}

/// Fixed ECDSA and Ed25519 continuity-canary receipts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantRootCanaryReceiptsV1 {
    ecdsa: TenantRootLifecycleReceiptDigestV1,
    ed25519: TenantRootLifecycleReceiptDigestV1,
}

impl TenantRootCanaryReceiptsV1 {
    /// Creates the required two-family canary pair.
    pub fn new(
        ecdsa: TenantRootLifecycleReceiptDigestV1,
        ed25519: TenantRootLifecycleReceiptDigestV1,
    ) -> RouterAbDerivationResult<Self> {
        if ecdsa == ed25519 {
            return Err(malformed(
                "tenant-root canary receipts must be family-specific",
            ));
        }
        Ok(Self { ecdsa, ed25519 })
    }

    /// Returns the ECDSA canary receipt digest.
    pub const fn ecdsa(&self) -> TenantRootLifecycleReceiptDigestV1 {
        self.ecdsa
    }

    /// Returns the Ed25519 canary receipt digest.
    pub const fn ed25519(&self) -> TenantRootLifecycleReceiptDigestV1 {
        self.ed25519
    }
}

/// Exact operation that allocated one pending tenant-root epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TenantRootEpochTransitionV1 {
    /// Epoch 1 in a fresh custody lineage.
    InitialCreation,
    /// One exact forward refresh from the previous active epoch.
    Refresh {
        /// Epoch that must remain active until this transition commits.
        previous_epoch: TenantRootShareEpoch,
    },
}

/// Public pending epoch allocated by one exact creation or refresh ceremony.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingTenantRootEpochV1 {
    transition: TenantRootEpochTransitionV1,
    epoch: TenantRootShareEpoch,
    ceremony_digest: TenantRootProtocolDigestV1,
    issued_at_ms: u64,
    expires_at_ms: u64,
}

impl PendingTenantRootEpochV1 {
    fn from_creation_context(
        context: &TenantRootCeremonyContextV1,
    ) -> RouterAbDerivationResult<Self> {
        context.validate()?;
        let TenantRootCeremonyEpochsV1::Create { next } = context.epochs() else {
            return Err(malformed(
                "tenant-root creation lifecycle requires a create ceremony",
            ));
        };
        if next != TenantRootShareEpoch::INITIAL {
            return Err(malformed("tenant-root creation lifecycle requires epoch 1"));
        }
        Ok(Self {
            transition: TenantRootEpochTransitionV1::InitialCreation,
            epoch: next,
            ceremony_digest: context.digest()?,
            issued_at_ms: context.issued_at_ms(),
            expires_at_ms: context.expires_at_ms(),
        })
    }

    fn from_refresh_context(
        context: &TenantRootCeremonyContextV1,
    ) -> RouterAbDerivationResult<Self> {
        context.validate()?;
        let TenantRootCeremonyEpochsV1::Refresh { current, next } = context.epochs() else {
            return Err(malformed(
                "tenant-root refresh lifecycle requires a refresh ceremony",
            ));
        };
        if current.next()? != next {
            return Err(malformed(
                "tenant-root refresh lifecycle must advance exactly one epoch",
            ));
        }
        Ok(Self {
            transition: TenantRootEpochTransitionV1::Refresh {
                previous_epoch: current,
            },
            epoch: next,
            ceremony_digest: context.digest()?,
            issued_at_ms: context.issued_at_ms(),
            expires_at_ms: context.expires_at_ms(),
        })
    }

    /// Returns the exact operation that allocated this epoch.
    pub const fn transition(&self) -> TenantRootEpochTransitionV1 {
        self.transition
    }

    /// Returns the pending custody epoch.
    pub const fn epoch(&self) -> TenantRootShareEpoch {
        self.epoch
    }

    /// Returns the exact creation-ceremony digest.
    pub const fn ceremony_digest(&self) -> TenantRootProtocolDigestV1 {
        self.ceremony_digest
    }

    /// Returns the ceremony issue time.
    pub const fn issued_at_ms(&self) -> u64 {
        self.issued_at_ms
    }

    /// Returns the ceremony expiry.
    pub const fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }
}

/// Public evidence for an epoch that passed installation, availability, and canaries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifiedTenantRootEpochV1 {
    pending: PendingTenantRootEpochV1,
    commitments: TenantRootEpochCommitmentsV1,
    installation_receipts: TenantRootRoleInstallationReceiptsV1,
    backup_policy: TenantRootBackupPolicyV1,
    canary_receipts: TenantRootCanaryReceiptsV1,
    verified_at_ms: u64,
}

impl VerifiedTenantRootEpochV1 {
    /// Returns the pending ceremony facts retained through activation.
    pub const fn pending(&self) -> &PendingTenantRootEpochV1 {
        &self.pending
    }

    /// Returns the exact A/B and stable root commitments.
    pub const fn commitments(&self) -> &TenantRootEpochCommitmentsV1 {
        &self.commitments
    }

    /// Returns both role installation receipts.
    pub const fn installation_receipts(&self) -> TenantRootRoleInstallationReceiptsV1 {
        self.installation_receipts
    }

    /// Returns the activation availability branch.
    pub fn backup_policy(&self) -> TenantRootBackupPolicyV1 {
        self.backup_policy.clone()
    }

    /// Returns both continuity-canary receipts.
    pub const fn canary_receipts(&self) -> TenantRootCanaryReceiptsV1 {
        self.canary_receipts
    }

    /// Returns the verification time.
    pub const fn verified_at_ms(&self) -> u64 {
        self.verified_at_ms
    }
}

/// Cloneable active-state projection of one verified activation receipt.
///
/// The verified token is consumed at activation. Active state retains only the
/// exact authenticated wire and the values derived from it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantRootActivationReceiptProjectionV1 {
    canonical_bytes: Vec<u8>,
    digest: TenantRootLifecycleReceiptDigestV1,
    activated_at_ms: u64,
}

impl TenantRootActivationReceiptProjectionV1 {
    fn from_verified(receipt: VerifiedTenantRootSignedActivationReceiptV1) -> Self {
        let digest = receipt.digest();
        let activated_at_ms = receipt.activated_at_ms();
        Self {
            canonical_bytes: receipt.into_canonical_bytes(),
            digest,
            activated_at_ms,
        }
    }

    /// Returns the exact canonical signed receipt bytes.
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    /// Returns the digest of the exact canonical signed receipt bytes.
    pub const fn digest(&self) -> TenantRootLifecycleReceiptDigestV1 {
        self.digest
    }

    /// Returns the activation time.
    pub const fn activated_at_ms(&self) -> u64 {
        self.activated_at_ms
    }
}

/// Initial tenant-root epoch selected for new derivation ceremonies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActiveTenantRootEpochV1 {
    verified: VerifiedTenantRootEpochV1,
    activation: TenantRootActivationReceiptProjectionV1,
}

impl ActiveTenantRootEpochV1 {
    /// Returns the active custody epoch.
    pub const fn epoch(&self) -> TenantRootShareEpoch {
        self.verified.pending.epoch
    }

    /// Returns the verified epoch evidence.
    pub const fn verified(&self) -> &VerifiedTenantRootEpochV1 {
        &self.verified
    }

    /// Returns the control-plane activation receipt.
    pub const fn activation(&self) -> &TenantRootActivationReceiptProjectionV1 {
        &self.activation
    }

    /// Returns the exact canonical signed activation receipt bytes.
    pub fn activation_receipt_bytes(&self) -> &[u8] {
        self.activation.canonical_bytes()
    }

    /// Returns the digest of the exact canonical signed activation receipt.
    pub const fn activation_receipt_digest(&self) -> TenantRootLifecycleReceiptDigestV1 {
        self.activation.digest()
    }

    /// Returns the authenticated activation time.
    pub const fn activation_time_ms(&self) -> u64 {
        self.activation.activated_at_ms()
    }
}

/// Signed pre-activation creation failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantRootCreationFailureV1 {
    digest: TenantRootLifecycleReceiptDigestV1,
    failed_at_ms: u64,
}

impl TenantRootCreationFailureV1 {
    /// Creates one non-zero-time failure receipt.
    pub fn new(
        digest: TenantRootLifecycleReceiptDigestV1,
        failed_at_ms: u64,
    ) -> RouterAbDerivationResult<Self> {
        require_timestamp("tenant-root creation failure timestamp", failed_at_ms)?;
        Ok(Self {
            digest,
            failed_at_ms,
        })
    }

    /// Returns the signed failure receipt digest.
    pub const fn digest(&self) -> TenantRootLifecycleReceiptDigestV1 {
        self.digest
    }

    /// Returns the failure time.
    pub const fn failed_at_ms(&self) -> u64 {
        self.failed_at_ms
    }
}

/// Both role receipts proving pending share and key cleanup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantRootPendingCleanupReceiptV1 {
    deriver_a: TenantRootLifecycleReceiptDigestV1,
    deriver_b: TenantRootLifecycleReceiptDigestV1,
    cleaned_at_ms: u64,
}

impl TenantRootPendingCleanupReceiptV1 {
    /// Creates an exact complete A/B cleanup receipt.
    pub fn new(
        deriver_a: TenantRootLifecycleReceiptDigestV1,
        deriver_b: TenantRootLifecycleReceiptDigestV1,
        cleaned_at_ms: u64,
    ) -> RouterAbDerivationResult<Self> {
        require_distinct_role_receipts(deriver_a, deriver_b)?;
        require_timestamp("tenant-root pending cleanup timestamp", cleaned_at_ms)?;
        Ok(Self {
            deriver_a,
            deriver_b,
            cleaned_at_ms,
        })
    }

    /// Returns the cleanup completion time.
    pub const fn cleaned_at_ms(&self) -> u64 {
        self.cleaned_at_ms
    }
}

/// Exact role branch that prevented complete pending cleanup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TenantRootPendingCleanupFailureV1 {
    /// Neither role produced a complete cleanup receipt.
    BothRolesIncomplete {
        /// Signed cleanup failure digest.
        failure_digest: TenantRootLifecycleReceiptDigestV1,
        /// Time at which incomplete cleanup was observed.
        observed_at_ms: u64,
    },
    /// Deriver A remains incomplete; Deriver B completed cleanup.
    DeriverAIncomplete {
        /// Deriver B's completed cleanup receipt.
        deriver_b_receipt: TenantRootLifecycleReceiptDigestV1,
        /// Signed cleanup failure digest.
        failure_digest: TenantRootLifecycleReceiptDigestV1,
        /// Time at which incomplete cleanup was observed.
        observed_at_ms: u64,
    },
    /// Deriver B remains incomplete; Deriver A completed cleanup.
    DeriverBIncomplete {
        /// Deriver A's completed cleanup receipt.
        deriver_a_receipt: TenantRootLifecycleReceiptDigestV1,
        /// Signed cleanup failure digest.
        failure_digest: TenantRootLifecycleReceiptDigestV1,
        /// Time at which incomplete cleanup was observed.
        observed_at_ms: u64,
    },
}

impl TenantRootPendingCleanupFailureV1 {
    /// Creates the branch where neither role completed cleanup.
    pub fn both_roles_incomplete(
        failure_digest: TenantRootLifecycleReceiptDigestV1,
        observed_at_ms: u64,
    ) -> RouterAbDerivationResult<Self> {
        require_timestamp("tenant-root cleanup failure timestamp", observed_at_ms)?;
        Ok(Self::BothRolesIncomplete {
            failure_digest,
            observed_at_ms,
        })
    }

    /// Creates the branch where Deriver A remains incomplete.
    pub fn deriver_a_incomplete(
        deriver_b_receipt: TenantRootLifecycleReceiptDigestV1,
        failure_digest: TenantRootLifecycleReceiptDigestV1,
        observed_at_ms: u64,
    ) -> RouterAbDerivationResult<Self> {
        require_distinct_role_receipts(deriver_b_receipt, failure_digest)?;
        require_timestamp("tenant-root cleanup failure timestamp", observed_at_ms)?;
        Ok(Self::DeriverAIncomplete {
            deriver_b_receipt,
            failure_digest,
            observed_at_ms,
        })
    }

    /// Creates the branch where Deriver B remains incomplete.
    pub fn deriver_b_incomplete(
        deriver_a_receipt: TenantRootLifecycleReceiptDigestV1,
        failure_digest: TenantRootLifecycleReceiptDigestV1,
        observed_at_ms: u64,
    ) -> RouterAbDerivationResult<Self> {
        require_distinct_role_receipts(deriver_a_receipt, failure_digest)?;
        require_timestamp("tenant-root cleanup failure timestamp", observed_at_ms)?;
        Ok(Self::DeriverBIncomplete {
            deriver_a_receipt,
            failure_digest,
            observed_at_ms,
        })
    }

    /// Returns the observation time for the incomplete cleanup.
    pub const fn observed_at_ms(self) -> u64 {
        match self {
            Self::BothRolesIncomplete { observed_at_ms, .. }
            | Self::DeriverAIncomplete { observed_at_ms, .. }
            | Self::DeriverBIncomplete { observed_at_ms, .. } => observed_at_ms,
        }
    }
}

/// Public creation attempt retained after a pre-activation failure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "stage", content = "epoch", rename_all = "snake_case")]
pub enum FailedTenantRootEpochV1 {
    /// Failure occurred before installation, backup, and canary evidence was complete.
    Preparing(PendingTenantRootEpochV1),
    /// Failure occurred after verification and before activation.
    Verified(Box<VerifiedTenantRootEpochV1>),
}

impl FailedTenantRootEpochV1 {
    fn pending(&self) -> &PendingTenantRootEpochV1 {
        match self {
            Self::Preparing(pending) => pending,
            Self::Verified(verified) => verified.pending(),
        }
    }
}

/// Empty creation branch for one allocated identity and fresh custody lineage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantRootEmptyCreationV1 {
    identity: TenantRootIdentityV1,
    custody_lineage: TenantRootCustodyLineageId,
    revision: u64,
}

impl TenantRootEmptyCreationV1 {
    /// Allocates an empty lineage at revision zero.
    pub fn new(
        identity: TenantRootIdentityV1,
        custody_lineage: TenantRootCustodyLineageId,
    ) -> Self {
        Self {
            identity,
            custody_lineage,
            revision: 0,
        }
    }

    /// Starts one exact initial-creation ceremony.
    pub fn start(
        self,
        context: &TenantRootCeremonyContextV1,
    ) -> RouterAbDerivationResult<TenantRootPreparingCreationV1> {
        if self.identity.digest()? != context.identity_digest()
            || self.custody_lineage != context.custody_lineage()
        {
            return Err(malformed(
                "tenant-root creation ceremony does not match its allocated identity and lineage",
            ));
        }
        Ok(TenantRootPreparingCreationV1 {
            identity: self.identity,
            custody_lineage: self.custody_lineage,
            next: PendingTenantRootEpochV1::from_creation_context(context)?,
            revision: next_revision(self.revision)?,
        })
    }
}

/// Creation branch with one pending epoch and no active root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantRootPreparingCreationV1 {
    identity: TenantRootIdentityV1,
    custody_lineage: TenantRootCustodyLineageId,
    next: PendingTenantRootEpochV1,
    revision: u64,
}

impl TenantRootPreparingCreationV1 {
    /// Verifies exact A/B installation evidence and every activation prerequisite.
    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        self,
        deriver_a: &VerifiedTenantRootShareInstallationEvidenceV1,
        deriver_b: &VerifiedTenantRootShareInstallationEvidenceV1,
        installation_receipts: TenantRootRoleInstallationReceiptsV1,
        backup_policy: TenantRootBackupPolicyV1,
        canary_receipts: TenantRootCanaryReceiptsV1,
        verified_at_ms: u64,
    ) -> RouterAbDerivationResult<TenantRootVerifiedCreationV1> {
        require_timestamp("tenant-root verification timestamp", verified_at_ms)?;
        if verified_at_ms < self.next.issued_at_ms || verified_at_ms > self.next.expires_at_ms {
            return Err(malformed(
                "tenant-root verification must occur within the creation ceremony lifetime",
            ));
        }
        let context = deriver_a.transcript().context();
        if context.digest()? != self.next.ceremony_digest {
            return Err(malformed(
                "tenant-root installation evidence belongs to another creation ceremony",
            ));
        }
        let commitments = TenantRootEpochCommitmentsV1::from_verified(
            verify_tenant_root_creation_evidence_v1(deriver_a, deriver_b)?,
        )?;
        let verified_revision = next_revision(self.revision)?;
        let activation_revision = next_revision(verified_revision)?;
        validate_backup_policy(
            &backup_policy,
            self.identity.digest()?,
            self.custody_lineage,
            TenantRootActivationReceiptTransitionV1::InitialCreation,
            self.next.epoch(),
            self.next.ceremony_digest(),
            &commitments,
            installation_receipts,
            verified_revision,
            activation_revision,
            self.next.issued_at_ms(),
            self.next.expires_at_ms(),
        )?;
        Ok(TenantRootVerifiedCreationV1 {
            identity: self.identity,
            custody_lineage: self.custody_lineage,
            next: VerifiedTenantRootEpochV1 {
                pending: self.next,
                commitments,
                installation_receipts,
                backup_policy,
                canary_receipts,
                verified_at_ms,
            },
            revision: verified_revision,
        })
    }

    /// Records a failed attempt after both roles prove pending cleanup.
    pub fn fail_with_cleanup(
        self,
        failure: TenantRootCreationFailureV1,
        cleanup: TenantRootPendingCleanupReceiptV1,
    ) -> RouterAbDerivationResult<TenantRootFailedBeforeActivationCreationV1> {
        require_failure_order(self.next.issued_at_ms(), failure, cleanup.cleaned_at_ms())?;
        Ok(TenantRootFailedBeforeActivationCreationV1 {
            identity: self.identity,
            custody_lineage: self.custody_lineage,
            next: FailedTenantRootEpochV1::Preparing(self.next),
            failure,
            cleanup,
            revision: next_revision(self.revision)?,
        })
    }

    /// Records a failed attempt whose pending cleanup remains incomplete.
    pub fn fail_with_incomplete_cleanup(
        self,
        failure: TenantRootCreationFailureV1,
        cleanup: TenantRootPendingCleanupFailureV1,
    ) -> RouterAbDerivationResult<TenantRootCleanupIncompleteCreationV1> {
        require_failure_order(self.next.issued_at_ms(), failure, cleanup.observed_at_ms())?;
        Ok(TenantRootCleanupIncompleteCreationV1 {
            identity: self.identity,
            custody_lineage: self.custody_lineage,
            next: FailedTenantRootEpochV1::Preparing(self.next),
            failure,
            cleanup,
            revision: next_revision(self.revision)?,
        })
    }
}

/// Creation branch whose epoch is ready for one forward activation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantRootVerifiedCreationV1 {
    identity: TenantRootIdentityV1,
    custody_lineage: TenantRootCustodyLineageId,
    next: VerifiedTenantRootEpochV1,
    revision: u64,
}

impl TenantRootVerifiedCreationV1 {
    /// Returns the allocated tenant-root identity.
    pub const fn identity(&self) -> &TenantRootIdentityV1 {
        &self.identity
    }

    /// Returns the custody lineage selected for creation.
    pub const fn custody_lineage(&self) -> TenantRootCustodyLineageId {
        self.custody_lineage
    }

    /// Returns the verified epoch awaiting activation.
    pub const fn next(&self) -> &VerifiedTenantRootEpochV1 {
        &self.next
    }

    /// Returns the current lifecycle revision.
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Activates epoch 1 using one issuer-verified control-plane receipt.
    pub fn activate(
        self,
        activation: VerifiedTenantRootSignedActivationReceiptV1,
    ) -> RouterAbDerivationResult<TenantRootActiveCreationV1> {
        let activation = project_initial_creation_activation(&self, activation)?;
        Ok(TenantRootActiveCreationV1 {
            identity: self.identity,
            custody_lineage: self.custody_lineage,
            current: ActiveTenantRootEpochV1 {
                verified: self.next,
                activation,
            },
            revision: next_revision(self.revision)?,
        })
    }

    /// Records a verified epoch that failed before activation and was fully cleaned.
    pub fn fail_with_cleanup(
        self,
        failure: TenantRootCreationFailureV1,
        cleanup: TenantRootPendingCleanupReceiptV1,
    ) -> RouterAbDerivationResult<TenantRootFailedBeforeActivationCreationV1> {
        require_failure_order(self.next.verified_at_ms(), failure, cleanup.cleaned_at_ms())?;
        Ok(TenantRootFailedBeforeActivationCreationV1 {
            identity: self.identity,
            custody_lineage: self.custody_lineage,
            next: FailedTenantRootEpochV1::Verified(Box::new(self.next)),
            failure,
            cleanup,
            revision: next_revision(self.revision)?,
        })
    }

    /// Records a verified epoch whose pending cleanup remains incomplete.
    pub fn fail_with_incomplete_cleanup(
        self,
        failure: TenantRootCreationFailureV1,
        cleanup: TenantRootPendingCleanupFailureV1,
    ) -> RouterAbDerivationResult<TenantRootCleanupIncompleteCreationV1> {
        require_failure_order(
            self.next.verified_at_ms(),
            failure,
            cleanup.observed_at_ms(),
        )?;
        Ok(TenantRootCleanupIncompleteCreationV1 {
            identity: self.identity,
            custody_lineage: self.custody_lineage,
            next: FailedTenantRootEpochV1::Verified(Box::new(self.next)),
            failure,
            cleanup,
            revision: next_revision(self.revision)?,
        })
    }
}

fn project_initial_creation_activation(
    state: &TenantRootVerifiedCreationV1,
    activation: VerifiedTenantRootSignedActivationReceiptV1,
) -> RouterAbDerivationResult<TenantRootActivationReceiptProjectionV1> {
    activation.require_fresh(activation.activated_at_ms())?;
    require_transition_time(
        &state.next.pending,
        activation.activated_at_ms(),
        "activation",
    )?;
    if activation.activated_at_ms() < state.next.verified_at_ms() {
        return Err(malformed("tenant-root activation must follow verification"));
    }
    let TenantRootActivationReceiptBindingV1::InitialCreation(binding) = activation.binding()
    else {
        return Err(replay_mismatch(
            "tenant-root initial activation receipt branch is invalid",
        ));
    };
    if binding.epoch() != TenantRootShareEpoch::INITIAL
        || binding.identity_digest() != state.identity.digest()?
        || binding.custody_lineage() != state.custody_lineage
        || binding.context_digest() != state.next.pending.ceremony_digest()
        || binding.expected_control_plane_revision() != state.revision
        || binding.result_control_plane_revision() != next_revision(state.revision)?
        || binding.commitments() != &state.next.commitments
        || binding.installation_receipts() != state.next.installation_receipts
        || binding.canary_receipts() != state.next.canary_receipts
        || binding.issued_at_ms() != state.next.pending.issued_at_ms()
        || binding.expires_at_ms() != state.next.pending.expires_at_ms()
    {
        return Err(replay_mismatch(
            "tenant-root initial activation receipt fields do not match its lifecycle state",
        ));
    }
    validate_activation_availability(&state.next.backup_policy, binding.availability())?;
    project_verified_activation(activation)
}

/// Terminal successful initial-creation branch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantRootActiveCreationV1 {
    identity: TenantRootIdentityV1,
    custody_lineage: TenantRootCustodyLineageId,
    current: ActiveTenantRootEpochV1,
    revision: u64,
}

impl TenantRootActiveCreationV1 {
    /// Returns the active epoch.
    pub const fn current(&self) -> &ActiveTenantRootEpochV1 {
        &self.current
    }

    /// Returns the final creation revision.
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Returns the exact active epoch projection.
    pub const fn current_epoch(&self) -> &ActiveTenantRootEpochV1 {
        &self.current
    }

    /// Returns the exact canonical signed activation receipt bytes.
    pub fn activation_receipt_bytes(&self) -> &[u8] {
        self.current.activation_receipt_bytes()
    }

    /// Returns the digest of the exact canonical signed activation receipt.
    pub const fn activation_receipt_digest(&self) -> TenantRootLifecycleReceiptDigestV1 {
        self.current.activation_receipt_digest()
    }

    /// Returns the authenticated activation time.
    pub const fn activation_time_ms(&self) -> u64 {
        self.current.activation_time_ms()
    }

    /// Moves the successfully created root into its steady-state refresh machine.
    pub fn into_refresh_state(self) -> TenantRootActiveRefreshV1 {
        TenantRootActiveRefreshV1 {
            identity: self.identity,
            custody_lineage: self.custody_lineage,
            current: self.current,
            revision: self.revision,
        }
    }
}

/// Terminal failed branch after complete pending cleanup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantRootFailedBeforeActivationCreationV1 {
    identity: TenantRootIdentityV1,
    custody_lineage: TenantRootCustodyLineageId,
    next: FailedTenantRootEpochV1,
    failure: TenantRootCreationFailureV1,
    cleanup: TenantRootPendingCleanupReceiptV1,
    revision: u64,
}

impl TenantRootFailedBeforeActivationCreationV1 {
    /// Starts a fresh creation ceremony after complete cleanup of the failed attempt.
    pub fn retry(
        self,
        context: &TenantRootCeremonyContextV1,
    ) -> RouterAbDerivationResult<TenantRootPreparingCreationV1> {
        if self.identity.digest()? != context.identity_digest()
            || self.custody_lineage != context.custody_lineage()
        {
            return Err(malformed(
                "tenant-root retry ceremony does not match its allocated identity and lineage",
            ));
        }
        let next = PendingTenantRootEpochV1::from_creation_context(context)?;
        if next.ceremony_digest() == self.next.pending().ceremony_digest() {
            return Err(malformed(
                "tenant-root retry requires a fresh creation ceremony",
            ));
        }
        Ok(TenantRootPreparingCreationV1 {
            identity: self.identity,
            custody_lineage: self.custody_lineage,
            next,
            revision: next_revision(self.revision)?,
        })
    }
}

/// Operationally blocked branch after incomplete pending cleanup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantRootCleanupIncompleteCreationV1 {
    identity: TenantRootIdentityV1,
    custody_lineage: TenantRootCustodyLineageId,
    next: FailedTenantRootEpochV1,
    failure: TenantRootCreationFailureV1,
    cleanup: TenantRootPendingCleanupFailureV1,
    revision: u64,
}

impl TenantRootCleanupIncompleteCreationV1 {
    /// Accepts the eventual complete cleanup proof and unblocks a fresh retry.
    pub fn complete_cleanup(
        self,
        cleanup: TenantRootPendingCleanupReceiptV1,
    ) -> RouterAbDerivationResult<TenantRootFailedBeforeActivationCreationV1> {
        if cleanup.cleaned_at_ms() < self.cleanup.observed_at_ms() {
            return Err(malformed(
                "tenant-root cleanup completion predates the incomplete-cleanup observation",
            ));
        }
        Ok(TenantRootFailedBeforeActivationCreationV1 {
            identity: self.identity,
            custody_lineage: self.custody_lineage,
            next: self.next,
            failure: self.failure,
            cleanup,
            revision: next_revision(self.revision)?,
        })
    }
}

/// Exhaustive public control-plane state for initial tenant-root creation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", content = "state", rename_all = "snake_case")]
pub enum TenantRootCreationStateV1 {
    /// The identity and lineage exist without role material.
    Empty(TenantRootEmptyCreationV1),
    /// Epoch 1 creation is in progress.
    Preparing(TenantRootPreparingCreationV1),
    /// Both role installations, availability evidence, and canaries passed.
    Verified(TenantRootVerifiedCreationV1),
    /// Epoch 1 is active.
    Active(TenantRootActiveCreationV1),
    /// Creation failed and both roles cleaned pending material.
    FailedBeforeActivation(TenantRootFailedBeforeActivationCreationV1),
    /// Creation failed and at least one role has not proved cleanup.
    CleanupIncomplete(TenantRootCleanupIncompleteCreationV1),
}

/// Exact recovery action after reloading a persisted creation lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TenantRootCreationRecoveryActionV1 {
    /// No role material exists; a fresh creation ceremony may start.
    StartFreshCeremony,
    /// Pending material must be removed before another ceremony may start.
    AbortPendingEpoch {
        /// Epoch whose role-local pending material must be removed.
        pending_epoch: TenantRootShareEpoch,
        /// Exact ceremony whose pending material is being removed.
        ceremony_digest: TenantRootProtocolDigestV1,
    },
    /// Cleanup was already completed; retry must use a fresh ceremony.
    StartFreshCeremonyAfterCleanup {
        /// Epoch from the failed attempt.
        failed_epoch: TenantRootShareEpoch,
        /// Exact failed ceremony that cannot be replayed.
        failed_ceremony_digest: TenantRootProtocolDigestV1,
    },
    /// At least one role still has pending material from the failed attempt.
    ResumePendingCleanup {
        /// Epoch whose cleanup remains incomplete.
        pending_epoch: TenantRootShareEpoch,
        /// Exact failed ceremony whose cleanup must finish.
        ceremony_digest: TenantRootProtocolDigestV1,
    },
    /// Creation completed and the active epoch remains authoritative.
    KeepActive {
        /// Active custody epoch.
        active_epoch: TenantRootShareEpoch,
        /// Signed activation receipt accepted by the control plane.
        activation_receipt_digest: TenantRootLifecycleReceiptDigestV1,
    },
}

/// Identity-bound recovery plan derived from one persisted creation state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantRootCreationRecoveryPlanV1 {
    identity_digest: super::TenantRootIdentityDigestV1,
    custody_lineage: TenantRootCustodyLineageId,
    revision: u64,
    action: TenantRootCreationRecoveryActionV1,
}

impl TenantRootCreationRecoveryPlanV1 {
    /// Returns the server-resolved tenant-root identity digest.
    pub const fn identity_digest(&self) -> super::TenantRootIdentityDigestV1 {
        self.identity_digest
    }

    /// Returns the physical custody lineage.
    pub const fn custody_lineage(&self) -> TenantRootCustodyLineageId {
        self.custody_lineage
    }

    /// Returns the exact persisted lifecycle revision.
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Returns the only permitted recovery action for the persisted branch.
    pub const fn action(&self) -> TenantRootCreationRecoveryActionV1 {
        self.action
    }
}

impl TenantRootCreationStateV1 {
    /// Returns the monotonic lifecycle revision.
    pub const fn revision(&self) -> u64 {
        match self {
            Self::Empty(state) => state.revision,
            Self::Preparing(state) => state.revision,
            Self::Verified(state) => state.revision,
            Self::Active(state) => state.revision,
            Self::FailedBeforeActivation(state) => state.revision,
            Self::CleanupIncomplete(state) => state.revision,
        }
    }

    /// Projects one deterministic crash-recovery action from the persisted branch.
    pub fn recovery_plan(&self) -> RouterAbDerivationResult<TenantRootCreationRecoveryPlanV1> {
        let (identity, custody_lineage, action) = match self {
            Self::Empty(state) => (
                &state.identity,
                state.custody_lineage,
                TenantRootCreationRecoveryActionV1::StartFreshCeremony,
            ),
            Self::Preparing(state) => (
                &state.identity,
                state.custody_lineage,
                TenantRootCreationRecoveryActionV1::AbortPendingEpoch {
                    pending_epoch: state.next.epoch(),
                    ceremony_digest: state.next.ceremony_digest(),
                },
            ),
            Self::Verified(state) => (
                &state.identity,
                state.custody_lineage,
                TenantRootCreationRecoveryActionV1::AbortPendingEpoch {
                    pending_epoch: state.next.pending().epoch(),
                    ceremony_digest: state.next.pending().ceremony_digest(),
                },
            ),
            Self::Active(state) => (
                &state.identity,
                state.custody_lineage,
                TenantRootCreationRecoveryActionV1::KeepActive {
                    active_epoch: state.current.epoch(),
                    activation_receipt_digest: state.current.activation_receipt_digest(),
                },
            ),
            Self::FailedBeforeActivation(state) => (
                &state.identity,
                state.custody_lineage,
                TenantRootCreationRecoveryActionV1::StartFreshCeremonyAfterCleanup {
                    failed_epoch: state.next.pending().epoch(),
                    failed_ceremony_digest: state.next.pending().ceremony_digest(),
                },
            ),
            Self::CleanupIncomplete(state) => (
                &state.identity,
                state.custody_lineage,
                TenantRootCreationRecoveryActionV1::ResumePendingCleanup {
                    pending_epoch: state.next.pending().epoch(),
                    ceremony_digest: state.next.pending().ceremony_digest(),
                },
            ),
        };
        Ok(TenantRootCreationRecoveryPlanV1 {
            identity_digest: identity.digest()?,
            custody_lineage,
            revision: self.revision(),
            action,
        })
    }
}

impl From<TenantRootEmptyCreationV1> for TenantRootCreationStateV1 {
    fn from(state: TenantRootEmptyCreationV1) -> Self {
        Self::Empty(state)
    }
}

impl From<TenantRootPreparingCreationV1> for TenantRootCreationStateV1 {
    fn from(state: TenantRootPreparingCreationV1) -> Self {
        Self::Preparing(state)
    }
}

impl From<TenantRootVerifiedCreationV1> for TenantRootCreationStateV1 {
    fn from(state: TenantRootVerifiedCreationV1) -> Self {
        Self::Verified(state)
    }
}

impl From<TenantRootActiveCreationV1> for TenantRootCreationStateV1 {
    fn from(state: TenantRootActiveCreationV1) -> Self {
        Self::Active(state)
    }
}

impl From<TenantRootFailedBeforeActivationCreationV1> for TenantRootCreationStateV1 {
    fn from(state: TenantRootFailedBeforeActivationCreationV1) -> Self {
        Self::FailedBeforeActivation(state)
    }
}

impl From<TenantRootCleanupIncompleteCreationV1> for TenantRootCreationStateV1 {
    fn from(state: TenantRootCleanupIncompleteCreationV1) -> Self {
        Self::CleanupIncomplete(state)
    }
}

/// Signed pre-activation refresh failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantRootRefreshFailureV1 {
    digest: TenantRootLifecycleReceiptDigestV1,
    failed_at_ms: u64,
}

impl TenantRootRefreshFailureV1 {
    /// Creates one non-zero-time refresh failure receipt.
    pub fn new(
        digest: TenantRootLifecycleReceiptDigestV1,
        failed_at_ms: u64,
    ) -> RouterAbDerivationResult<Self> {
        require_timestamp("tenant-root refresh failure timestamp", failed_at_ms)?;
        Ok(Self {
            digest,
            failed_at_ms,
        })
    }

    /// Returns the signed failure receipt digest.
    pub const fn digest(&self) -> TenantRootLifecycleReceiptDigestV1 {
        self.digest
    }

    /// Returns the failure time.
    pub const fn failed_at_ms(&self) -> u64 {
        self.failed_at_ms
    }
}

/// Both role receipts proving destruction of the retired epoch and backup keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantRootRoleRetirementReceiptsV1 {
    deriver_a: TenantRootLifecycleReceiptDigestV1,
    deriver_b: TenantRootLifecycleReceiptDigestV1,
    retired_at_ms: u64,
}

impl TenantRootRoleRetirementReceiptsV1 {
    /// Creates the exact A/B retirement receipt pair.
    pub fn new(
        deriver_a: TenantRootLifecycleReceiptDigestV1,
        deriver_b: TenantRootLifecycleReceiptDigestV1,
        retired_at_ms: u64,
    ) -> RouterAbDerivationResult<Self> {
        require_distinct_role_receipts(deriver_a, deriver_b)?;
        require_timestamp("tenant-root retirement timestamp", retired_at_ms)?;
        Ok(Self {
            deriver_a,
            deriver_b,
            retired_at_ms,
        })
    }

    /// Returns the time both role retirement receipts were accepted.
    pub const fn retired_at_ms(&self) -> u64 {
        self.retired_at_ms
    }
}

/// Previous active epoch awaiting destruction after a forward activation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RetiringTenantRootEpochV1 {
    active: ActiveTenantRootEpochV1,
    retirement_started_at_ms: u64,
}

impl RetiringTenantRootEpochV1 {
    /// Returns the previous active epoch.
    pub const fn active(&self) -> &ActiveTenantRootEpochV1 {
        &self.active
    }

    /// Returns the forward-activation time that began retirement.
    pub const fn retirement_started_at_ms(&self) -> u64 {
        self.retirement_started_at_ms
    }
}

/// Stable active branch between refresh operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantRootActiveRefreshV1 {
    identity: TenantRootIdentityV1,
    custody_lineage: TenantRootCustodyLineageId,
    current: ActiveTenantRootEpochV1,
    revision: u64,
}

impl TenantRootActiveRefreshV1 {
    /// Returns the server-resolved tenant-root identity.
    pub const fn identity(&self) -> &TenantRootIdentityV1 {
        &self.identity
    }

    /// Returns the custody lineage that owns the active epoch.
    pub const fn custody_lineage(&self) -> TenantRootCustodyLineageId {
        self.custody_lineage
    }

    /// Returns the currently active epoch.
    pub const fn current(&self) -> &ActiveTenantRootEpochV1 {
        &self.current
    }

    /// Returns the current lifecycle revision.
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Returns the exact canonical signed activation receipt bytes for the active epoch.
    pub fn activation_receipt_bytes(&self) -> &[u8] {
        self.current.activation_receipt_bytes()
    }

    /// Returns the digest of the exact canonical signed activation receipt.
    pub const fn activation_receipt_digest(&self) -> TenantRootLifecycleReceiptDigestV1 {
        self.current.activation_receipt_digest()
    }

    /// Returns the authenticated activation time for the active epoch.
    pub const fn activation_time_ms(&self) -> u64 {
        self.current.activation_time_ms()
    }

    /// Rebuilds the public active refresh state from one issuer-verified receipt.
    ///
    /// The receipt carries every public epoch fact retained by active state.
    /// The caller supplies the server-resolved identity because an identity
    /// digest cannot be expanded back into its canonical identity fields.
    pub fn from_verified_activation_receipt(
        identity: TenantRootIdentityV1,
        activation: VerifiedTenantRootSignedActivationReceiptV1,
        lifecycle_revision: u64,
    ) -> RouterAbDerivationResult<Self> {
        let identity_digest = identity.digest()?;
        if identity_digest != activation.identity_digest() {
            return Err(malformed(
                "tenant-root active identity does not match its activation receipt",
            ));
        }
        if lifecycle_revision == 0 {
            return Err(malformed(
                "tenant-root active lifecycle revision must be positive",
            ));
        }
        if lifecycle_revision < activation.result_control_plane_revision() {
            return Err(malformed(
                "tenant-root active lifecycle revision predates activation receipt",
            ));
        }

        let backup_receipts = activation
            .availability()
            .current_role_backup_receipts()
            .ok_or_else(|| {
                malformed(
                    "tenant-root managed restore requires current-role backups in the active receipt",
                )
            })?;
        let backup_policy = TenantRootBackupPolicyV1::CurrentRoleBackups(backup_receipts);
        let custody_lineage = activation.custody_lineage();
        let (transition, epoch, commitments, installation_receipts, canary_receipts) =
            match activation.binding() {
                TenantRootActivationReceiptBindingV1::InitialCreation(binding) => (
                    TenantRootEpochTransitionV1::InitialCreation,
                    binding.epoch(),
                    binding.commitments().clone(),
                    binding.installation_receipts(),
                    binding.canary_receipts(),
                ),
                TenantRootActivationReceiptBindingV1::RefreshSwap(binding) => (
                    TenantRootEpochTransitionV1::Refresh {
                        previous_epoch: binding.current_epoch(),
                    },
                    binding.next_epoch(),
                    binding.next_commitments().clone(),
                    binding.installation_receipts(),
                    binding.canary_receipts(),
                ),
            };
        let pending = PendingTenantRootEpochV1 {
            transition,
            epoch,
            ceremony_digest: activation.context_digest(),
            issued_at_ms: activation.issued_at_ms(),
            expires_at_ms: activation.expires_at_ms(),
        };
        let verified = VerifiedTenantRootEpochV1 {
            pending,
            commitments,
            installation_receipts,
            backup_policy,
            canary_receipts,
            verified_at_ms: activation.activated_at_ms(),
        };
        let current = ActiveTenantRootEpochV1 {
            verified,
            activation: TenantRootActivationReceiptProjectionV1::from_verified(activation),
        };
        Ok(Self {
            identity,
            custody_lineage,
            current,
            revision: lifecycle_revision,
        })
    }

    pub(crate) fn resume_at_revision(mut self, revision: u64) -> RouterAbDerivationResult<Self> {
        if revision < self.revision {
            return Err(malformed(
                "tenant-root lifecycle revision cannot move backwards",
            ));
        }
        self.revision = revision;
        Ok(self)
    }

    /// Starts one exact forward refresh from the current active epoch.
    pub fn start(
        self,
        context: &TenantRootCeremonyContextV1,
    ) -> RouterAbDerivationResult<TenantRootPreparingRefreshV1> {
        if self.identity.digest()? != context.identity_digest()
            || self.custody_lineage != context.custody_lineage()
        {
            return Err(malformed(
                "tenant-root refresh ceremony does not match its active identity and lineage",
            ));
        }
        let TenantRootCeremonyEpochsV1::Refresh { current, next } = context.epochs() else {
            return Err(malformed(
                "tenant-root active state requires a refresh ceremony",
            ));
        };
        if current != self.current.epoch() || current.next()? != next {
            return Err(malformed(
                "tenant-root refresh ceremony does not advance the active epoch exactly once",
            ));
        }
        Ok(TenantRootPreparingRefreshV1 {
            identity: self.identity,
            custody_lineage: self.custody_lineage,
            current: self.current,
            next: PendingTenantRootEpochV1::from_refresh_context(context)?,
            revision: next_revision(self.revision)?,
        })
    }
}

/// Refresh branch with the old epoch active and one next epoch pending.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantRootPreparingRefreshV1 {
    identity: TenantRootIdentityV1,
    custody_lineage: TenantRootCustodyLineageId,
    current: ActiveTenantRootEpochV1,
    next: PendingTenantRootEpochV1,
    revision: u64,
}

impl TenantRootPreparingRefreshV1 {
    /// Returns the current lifecycle revision.
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Verifies exact refreshed A/B evidence, root continuity, availability, and canaries.
    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        self,
        deriver_a: &VerifiedTenantRootShareInstallationEvidenceV1,
        deriver_b: &VerifiedTenantRootShareInstallationEvidenceV1,
        installation_receipts: TenantRootRoleInstallationReceiptsV1,
        backup_policy: TenantRootBackupPolicyV1,
        canary_receipts: TenantRootCanaryReceiptsV1,
        verified_at_ms: u64,
    ) -> RouterAbDerivationResult<TenantRootVerifiedRefreshV1> {
        require_transition_time(&self.next, verified_at_ms, "verification")?;
        if deriver_a.transcript().context().digest()? != self.next.ceremony_digest {
            return Err(malformed(
                "tenant-root installation evidence belongs to another refresh ceremony",
            ));
        }
        let next_commitments = self
            .current
            .verified
            .commitments
            .verify_refresh_evidence(deriver_a, deriver_b)?;
        let verified_revision = next_revision(self.revision)?;
        let activation_revision = next_revision(verified_revision)?;
        validate_backup_policy(
            &backup_policy,
            self.identity.digest()?,
            self.custody_lineage,
            TenantRootActivationReceiptTransitionV1::RefreshSwap,
            self.next.epoch(),
            self.next.ceremony_digest(),
            &next_commitments,
            installation_receipts,
            verified_revision,
            activation_revision,
            self.next.issued_at_ms(),
            self.next.expires_at_ms(),
        )?;
        Ok(TenantRootVerifiedRefreshV1 {
            identity: self.identity,
            custody_lineage: self.custody_lineage,
            current: self.current,
            next: VerifiedTenantRootEpochV1 {
                pending: self.next,
                commitments: next_commitments,
                installation_receipts,
                backup_policy,
                canary_receipts,
                verified_at_ms,
            },
            revision: verified_revision,
        })
    }

    /// Records a failed refresh after both roles prove pending cleanup.
    pub fn fail_with_cleanup(
        self,
        failure: TenantRootRefreshFailureV1,
        cleanup: TenantRootPendingCleanupReceiptV1,
    ) -> RouterAbDerivationResult<TenantRootFailedBeforeActivationRefreshV1> {
        require_event_order(
            self.next.issued_at_ms(),
            failure.failed_at_ms(),
            cleanup.cleaned_at_ms(),
        )?;
        Ok(TenantRootFailedBeforeActivationRefreshV1 {
            identity: self.identity,
            custody_lineage: self.custody_lineage,
            current: self.current,
            next: FailedTenantRootEpochV1::Preparing(self.next),
            failure,
            cleanup,
            revision: next_revision(self.revision)?,
        })
    }

    /// Records a failed refresh whose pending cleanup remains incomplete.
    pub fn fail_with_incomplete_cleanup(
        self,
        failure: TenantRootRefreshFailureV1,
        cleanup: TenantRootPendingCleanupFailureV1,
    ) -> RouterAbDerivationResult<TenantRootCleanupIncompleteRefreshV1> {
        require_event_order(
            self.next.issued_at_ms(),
            failure.failed_at_ms(),
            cleanup.observed_at_ms(),
        )?;
        Ok(TenantRootCleanupIncompleteRefreshV1 {
            identity: self.identity,
            custody_lineage: self.custody_lineage,
            current: self.current,
            next: FailedTenantRootEpochV1::Preparing(self.next),
            failure,
            cleanup,
            revision: next_revision(self.revision)?,
        })
    }
}

/// Refresh branch whose next epoch passed every pre-activation gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantRootVerifiedRefreshV1 {
    identity: TenantRootIdentityV1,
    custody_lineage: TenantRootCustodyLineageId,
    current: ActiveTenantRootEpochV1,
    next: VerifiedTenantRootEpochV1,
    revision: u64,
}

impl TenantRootVerifiedRefreshV1 {
    /// Returns the server-resolved tenant-root identity.
    pub const fn identity(&self) -> &TenantRootIdentityV1 {
        &self.identity
    }

    /// Returns the custody lineage selected for refresh.
    pub const fn custody_lineage(&self) -> TenantRootCustodyLineageId {
        self.custody_lineage
    }

    /// Returns the active epoch retained during the swap.
    pub const fn current(&self) -> &ActiveTenantRootEpochV1 {
        &self.current
    }

    /// Returns the verified epoch awaiting activation.
    pub const fn next(&self) -> &VerifiedTenantRootEpochV1 {
        &self.next
    }

    /// Returns the current lifecycle revision.
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Activates the verified next epoch with one issuer-verified receipt and enters forward-only retirement.
    pub fn activate(
        self,
        activation: VerifiedTenantRootSignedActivationReceiptV1,
    ) -> RouterAbDerivationResult<TenantRootRetiringRefreshV1> {
        let activation = project_refresh_activation(&self, activation)?;
        let previous = RetiringTenantRootEpochV1 {
            active: self.current,
            retirement_started_at_ms: activation.activated_at_ms(),
        };
        Ok(TenantRootRetiringRefreshV1 {
            identity: self.identity,
            custody_lineage: self.custody_lineage,
            current: ActiveTenantRootEpochV1 {
                verified: self.next,
                activation,
            },
            previous,
            revision: next_revision(self.revision)?,
        })
    }

    /// Records a verified next epoch that failed before activation and was fully cleaned.
    pub fn fail_with_cleanup(
        self,
        failure: TenantRootRefreshFailureV1,
        cleanup: TenantRootPendingCleanupReceiptV1,
    ) -> RouterAbDerivationResult<TenantRootFailedBeforeActivationRefreshV1> {
        require_event_order(
            self.next.verified_at_ms(),
            failure.failed_at_ms(),
            cleanup.cleaned_at_ms(),
        )?;
        Ok(TenantRootFailedBeforeActivationRefreshV1 {
            identity: self.identity,
            custody_lineage: self.custody_lineage,
            current: self.current,
            next: FailedTenantRootEpochV1::Verified(Box::new(self.next)),
            failure,
            cleanup,
            revision: next_revision(self.revision)?,
        })
    }

    /// Records a verified next epoch whose pending cleanup remains incomplete.
    pub fn fail_with_incomplete_cleanup(
        self,
        failure: TenantRootRefreshFailureV1,
        cleanup: TenantRootPendingCleanupFailureV1,
    ) -> RouterAbDerivationResult<TenantRootCleanupIncompleteRefreshV1> {
        require_event_order(
            self.next.verified_at_ms(),
            failure.failed_at_ms(),
            cleanup.observed_at_ms(),
        )?;
        Ok(TenantRootCleanupIncompleteRefreshV1 {
            identity: self.identity,
            custody_lineage: self.custody_lineage,
            current: self.current,
            next: FailedTenantRootEpochV1::Verified(Box::new(self.next)),
            failure,
            cleanup,
            revision: next_revision(self.revision)?,
        })
    }
}

fn project_refresh_activation(
    state: &TenantRootVerifiedRefreshV1,
    activation: VerifiedTenantRootSignedActivationReceiptV1,
) -> RouterAbDerivationResult<TenantRootActivationReceiptProjectionV1> {
    activation.require_fresh(activation.activated_at_ms())?;
    require_transition_time(
        &state.next.pending,
        activation.activated_at_ms(),
        "activation",
    )?;
    if activation.activated_at_ms() < state.next.verified_at_ms() {
        return Err(malformed(
            "tenant-root refresh activation must follow verification",
        ));
    }
    let TenantRootActivationReceiptBindingV1::RefreshSwap(binding) = activation.binding() else {
        return Err(replay_mismatch(
            "tenant-root refresh activation receipt branch is invalid",
        ));
    };
    if binding.identity_digest() != state.identity.digest()?
        || binding.custody_lineage() != state.custody_lineage
        || binding.current_epoch() != state.current.epoch()
        || binding.next_epoch() != state.next.pending.epoch()
        || binding.current_commitments() != &state.current.verified.commitments
        || binding.next_commitments() != &state.next.commitments
        || binding.context_digest() != state.next.pending.ceremony_digest()
        || binding.expected_control_plane_revision() != state.revision
        || binding.result_control_plane_revision() != next_revision(state.revision)?
        || binding.installation_receipts() != state.next.installation_receipts
        || binding.canary_receipts() != state.next.canary_receipts
        || binding.issued_at_ms() != state.next.pending.issued_at_ms()
        || binding.expires_at_ms() != state.next.pending.expires_at_ms()
    {
        return Err(replay_mismatch(
            "tenant-root refresh activation receipt fields do not match its lifecycle state",
        ));
    }
    validate_activation_availability(&state.next.backup_policy, binding.availability())?;
    project_verified_activation(activation)
}

fn validate_activation_availability(
    expected: &TenantRootBackupPolicyV1,
    actual: &TenantRootActivationReceiptAvailabilityV1,
) -> RouterAbDerivationResult<()> {
    match (expected, actual) {
        (
            TenantRootBackupPolicyV1::CurrentRoleBackups(expected),
            TenantRootActivationReceiptAvailabilityV1::CurrentRoleBackups { receipts: actual },
        ) if expected == actual => Ok(()),
        (
            TenantRootBackupPolicyV1::AcceptedPermanentDerivationLoss(expected),
            TenantRootActivationReceiptAvailabilityV1::AcceptedPermanentDerivationLoss {
                authorization_bytes,
                authorization_digest,
            },
        ) if expected.authorization_bytes() == authorization_bytes.as_slice()
            && expected.authorization_digest() == authorization_digest => Ok(()),
        _ => Err(replay_mismatch(
            "tenant-root activation receipt availability does not match verified lifecycle evidence",
        )),
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_backup_policy(
    policy: &TenantRootBackupPolicyV1,
    identity_digest: super::TenantRootIdentityDigestV1,
    custody_lineage: TenantRootCustodyLineageId,
    transition: TenantRootActivationReceiptTransitionV1,
    target_epoch: TenantRootShareEpoch,
    context_digest: TenantRootProtocolDigestV1,
    commitments: &TenantRootEpochCommitmentsV1,
    installation_receipts: TenantRootRoleInstallationReceiptsV1,
    expected_control_plane_revision: u64,
    result_control_plane_revision: u64,
    issued_at_ms: u64,
    expires_at_ms: u64,
) -> RouterAbDerivationResult<()> {
    let TenantRootBackupPolicyV1::AcceptedPermanentDerivationLoss(accepted) = policy else {
        return Ok(());
    };
    let authorization =
        TenantRootSignedAcceptedPermanentLossAuthorizationV1::decode_canonical_bytes(
            accepted.authorization_bytes(),
        )?;
    if authorization.digest()? != *accepted.authorization_digest()
        || authorization.identity_digest() != identity_digest
        || authorization.custody_lineage() != custody_lineage
        || authorization.transition() != transition
        || authorization.target_epoch() != target_epoch
        || authorization.context_digest() != context_digest
        || authorization.commitments() != commitments
        || authorization.installation_receipts() != installation_receipts
        || authorization.expected_control_plane_revision() != expected_control_plane_revision
        || authorization.result_control_plane_revision() != result_control_plane_revision
        || authorization.issued_at_ms() != issued_at_ms
        || authorization.expires_at_ms() != expires_at_ms
    {
        return Err(replay_mismatch(
            "tenant-root accepted-loss authorization does not match lifecycle scope",
        ));
    }
    Ok(())
}

fn project_verified_activation(
    activation: VerifiedTenantRootSignedActivationReceiptV1,
) -> RouterAbDerivationResult<TenantRootActivationReceiptProjectionV1> {
    Ok(TenantRootActivationReceiptProjectionV1::from_verified(
        activation,
    ))
}

/// Post-activation branch while the previous epoch is being destroyed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantRootRetiringRefreshV1 {
    identity: TenantRootIdentityV1,
    custody_lineage: TenantRootCustodyLineageId,
    current: ActiveTenantRootEpochV1,
    previous: RetiringTenantRootEpochV1,
    revision: u64,
}

impl TenantRootRetiringRefreshV1 {
    /// Returns the newly active epoch used by derivation ceremonies.
    pub const fn current(&self) -> &ActiveTenantRootEpochV1 {
        &self.current
    }

    /// Returns the previous epoch awaiting destruction.
    pub const fn previous(&self) -> &RetiringTenantRootEpochV1 {
        &self.previous
    }

    /// Returns the current lifecycle revision.
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Accepts both role retirement receipts and returns to the active branch.
    pub fn finish_retirement(
        self,
        receipts: TenantRootRoleRetirementReceiptsV1,
    ) -> RouterAbDerivationResult<TenantRootActiveRefreshV1> {
        if receipts.retired_at_ms() < self.current.activation_time_ms() {
            return Err(malformed(
                "tenant-root retirement cannot predate forward activation",
            ));
        }
        Ok(TenantRootActiveRefreshV1 {
            identity: self.identity,
            custody_lineage: self.custody_lineage,
            current: self.current,
            revision: next_revision(self.revision)?,
        })
    }
}

/// Failed refresh branch after complete pending cleanup; the old epoch stays active.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantRootFailedBeforeActivationRefreshV1 {
    identity: TenantRootIdentityV1,
    custody_lineage: TenantRootCustodyLineageId,
    current: ActiveTenantRootEpochV1,
    next: FailedTenantRootEpochV1,
    failure: TenantRootRefreshFailureV1,
    cleanup: TenantRootPendingCleanupReceiptV1,
    revision: u64,
}

impl TenantRootFailedBeforeActivationRefreshV1 {
    /// Returns the current lifecycle revision.
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Starts a fresh refresh ceremony after complete cleanup of the failed attempt.
    pub fn retry(
        self,
        context: &TenantRootCeremonyContextV1,
    ) -> RouterAbDerivationResult<TenantRootPreparingRefreshV1> {
        if self.identity.digest()? != context.identity_digest()
            || self.custody_lineage != context.custody_lineage()
        {
            return Err(malformed(
                "tenant-root refresh retry does not match its active identity and lineage",
            ));
        }
        let next = PendingTenantRootEpochV1::from_refresh_context(context)?;
        if next.ceremony_digest() == self.next.pending().ceremony_digest() {
            return Err(malformed(
                "tenant-root refresh retry requires a fresh ceremony",
            ));
        }
        let TenantRootEpochTransitionV1::Refresh { previous_epoch } = next.transition() else {
            return Err(malformed(
                "tenant-root refresh retry requires a refresh transition",
            ));
        };
        if previous_epoch != self.current.epoch() {
            return Err(malformed(
                "tenant-root refresh retry does not start from the active epoch",
            ));
        }
        Ok(TenantRootPreparingRefreshV1 {
            identity: self.identity,
            custody_lineage: self.custody_lineage,
            current: self.current,
            next,
            revision: next_revision(self.revision)?,
        })
    }
}

/// Blocked refresh branch after incomplete pending cleanup; the old epoch stays active.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantRootCleanupIncompleteRefreshV1 {
    identity: TenantRootIdentityV1,
    custody_lineage: TenantRootCustodyLineageId,
    current: ActiveTenantRootEpochV1,
    next: FailedTenantRootEpochV1,
    failure: TenantRootRefreshFailureV1,
    cleanup: TenantRootPendingCleanupFailureV1,
    revision: u64,
}

impl TenantRootCleanupIncompleteRefreshV1 {
    /// Returns the current lifecycle revision.
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Accepts eventual complete cleanup and unblocks a fresh refresh attempt.
    pub fn complete_cleanup(
        self,
        cleanup: TenantRootPendingCleanupReceiptV1,
    ) -> RouterAbDerivationResult<TenantRootFailedBeforeActivationRefreshV1> {
        if cleanup.cleaned_at_ms() < self.cleanup.observed_at_ms() {
            return Err(malformed(
                "tenant-root cleanup completion predates the incomplete-cleanup observation",
            ));
        }
        Ok(TenantRootFailedBeforeActivationRefreshV1 {
            identity: self.identity,
            custody_lineage: self.custody_lineage,
            current: self.current,
            next: self.next,
            failure: self.failure,
            cleanup,
            revision: next_revision(self.revision)?,
        })
    }
}

/// Exhaustive public control-plane state for proactive tenant-root refresh.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", content = "state", rename_all = "snake_case")]
pub enum TenantRootRefreshStateV1 {
    /// One current epoch and no mutation in progress.
    Active(TenantRootActiveRefreshV1),
    /// The old epoch is active while the next epoch is prepared.
    Preparing(TenantRootPreparingRefreshV1),
    /// The next epoch passed every pre-activation gate.
    Verified(TenantRootVerifiedRefreshV1),
    /// The next epoch is active while the previous epoch is destroyed.
    Retiring(TenantRootRetiringRefreshV1),
    /// Refresh failed, pending material was cleaned, and the old epoch remains active.
    FailedBeforeActivation(TenantRootFailedBeforeActivationRefreshV1),
    /// Refresh failed and incomplete pending cleanup blocks another mutation.
    CleanupIncomplete(TenantRootCleanupIncompleteRefreshV1),
}

/// Exact recovery action after reloading a persisted refresh lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TenantRootRefreshRecoveryActionV1 {
    /// The current epoch is stable and a new operation may be accepted.
    KeepActive {
        /// Active custody epoch.
        active_epoch: TenantRootShareEpoch,
    },
    /// A pre-activation next epoch must be deleted while the old epoch stays active.
    AbortPendingEpoch {
        /// Epoch that remains authoritative during cleanup.
        active_epoch: TenantRootShareEpoch,
        /// Pending epoch whose role-local material must be removed.
        pending_epoch: TenantRootShareEpoch,
        /// Exact ceremony whose pending material is being removed.
        ceremony_digest: TenantRootProtocolDigestV1,
    },
    /// Cleanup completed and the next attempt must use a fresh ceremony.
    StartFreshRefreshAfterCleanup {
        /// Epoch that remained active through the failed attempt.
        active_epoch: TenantRootShareEpoch,
        /// Failed pending epoch that cannot be replayed.
        failed_epoch: TenantRootShareEpoch,
        /// Exact failed ceremony that cannot be replayed.
        failed_ceremony_digest: TenantRootProtocolDigestV1,
    },
    /// At least one role still has pending material from the failed attempt.
    ResumePendingCleanup {
        /// Epoch that remains authoritative during cleanup.
        active_epoch: TenantRootShareEpoch,
        /// Pending epoch whose cleanup remains incomplete.
        pending_epoch: TenantRootShareEpoch,
        /// Exact failed ceremony whose cleanup must finish.
        ceremony_digest: TenantRootProtocolDigestV1,
    },
    /// Forward activation committed; destruction of the previous epoch must resume.
    ResumeRetirement {
        /// Newly active custody epoch.
        active_epoch: TenantRootShareEpoch,
        /// Previous epoch that must never become active again.
        retiring_epoch: TenantRootShareEpoch,
        /// Signed forward-activation receipt accepted by the control plane.
        activation_receipt_digest: TenantRootLifecycleReceiptDigestV1,
    },
}

/// Identity-bound recovery plan derived from one persisted refresh state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantRootRefreshRecoveryPlanV1 {
    identity_digest: super::TenantRootIdentityDigestV1,
    custody_lineage: TenantRootCustodyLineageId,
    revision: u64,
    action: TenantRootRefreshRecoveryActionV1,
}

impl TenantRootRefreshRecoveryPlanV1 {
    /// Returns the server-resolved tenant-root identity digest.
    pub const fn identity_digest(&self) -> super::TenantRootIdentityDigestV1 {
        self.identity_digest
    }

    /// Returns the physical custody lineage.
    pub const fn custody_lineage(&self) -> TenantRootCustodyLineageId {
        self.custody_lineage
    }

    /// Returns the exact persisted lifecycle revision.
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Returns the only permitted recovery action for the persisted branch.
    pub const fn action(&self) -> TenantRootRefreshRecoveryActionV1 {
        self.action
    }
}

impl TenantRootRefreshStateV1 {
    /// Returns the monotonic lifecycle revision.
    pub const fn revision(&self) -> u64 {
        match self {
            Self::Active(state) => state.revision,
            Self::Preparing(state) => state.revision,
            Self::Verified(state) => state.revision,
            Self::Retiring(state) => state.revision,
            Self::FailedBeforeActivation(state) => state.revision,
            Self::CleanupIncomplete(state) => state.revision,
        }
    }

    /// Projects one deterministic crash-recovery action from the persisted branch.
    pub fn recovery_plan(&self) -> RouterAbDerivationResult<TenantRootRefreshRecoveryPlanV1> {
        let (identity, custody_lineage, action) = match self {
            Self::Active(state) => (
                &state.identity,
                state.custody_lineage,
                TenantRootRefreshRecoveryActionV1::KeepActive {
                    active_epoch: state.current.epoch(),
                },
            ),
            Self::Preparing(state) => (
                &state.identity,
                state.custody_lineage,
                TenantRootRefreshRecoveryActionV1::AbortPendingEpoch {
                    active_epoch: state.current.epoch(),
                    pending_epoch: state.next.epoch(),
                    ceremony_digest: state.next.ceremony_digest(),
                },
            ),
            Self::Verified(state) => (
                &state.identity,
                state.custody_lineage,
                TenantRootRefreshRecoveryActionV1::AbortPendingEpoch {
                    active_epoch: state.current.epoch(),
                    pending_epoch: state.next.pending().epoch(),
                    ceremony_digest: state.next.pending().ceremony_digest(),
                },
            ),
            Self::Retiring(state) => (
                &state.identity,
                state.custody_lineage,
                TenantRootRefreshRecoveryActionV1::ResumeRetirement {
                    active_epoch: state.current.epoch(),
                    retiring_epoch: state.previous.active().epoch(),
                    activation_receipt_digest: state.current.activation_receipt_digest(),
                },
            ),
            Self::FailedBeforeActivation(state) => (
                &state.identity,
                state.custody_lineage,
                TenantRootRefreshRecoveryActionV1::StartFreshRefreshAfterCleanup {
                    active_epoch: state.current.epoch(),
                    failed_epoch: state.next.pending().epoch(),
                    failed_ceremony_digest: state.next.pending().ceremony_digest(),
                },
            ),
            Self::CleanupIncomplete(state) => (
                &state.identity,
                state.custody_lineage,
                TenantRootRefreshRecoveryActionV1::ResumePendingCleanup {
                    active_epoch: state.current.epoch(),
                    pending_epoch: state.next.pending().epoch(),
                    ceremony_digest: state.next.pending().ceremony_digest(),
                },
            ),
        };
        Ok(TenantRootRefreshRecoveryPlanV1 {
            identity_digest: identity.digest()?,
            custody_lineage,
            revision: self.revision(),
            action,
        })
    }
}

impl From<TenantRootActiveRefreshV1> for TenantRootRefreshStateV1 {
    fn from(state: TenantRootActiveRefreshV1) -> Self {
        Self::Active(state)
    }
}

impl From<TenantRootPreparingRefreshV1> for TenantRootRefreshStateV1 {
    fn from(state: TenantRootPreparingRefreshV1) -> Self {
        Self::Preparing(state)
    }
}

impl From<TenantRootVerifiedRefreshV1> for TenantRootRefreshStateV1 {
    fn from(state: TenantRootVerifiedRefreshV1) -> Self {
        Self::Verified(state)
    }
}

impl From<TenantRootRetiringRefreshV1> for TenantRootRefreshStateV1 {
    fn from(state: TenantRootRetiringRefreshV1) -> Self {
        Self::Retiring(state)
    }
}

impl From<TenantRootFailedBeforeActivationRefreshV1> for TenantRootRefreshStateV1 {
    fn from(state: TenantRootFailedBeforeActivationRefreshV1) -> Self {
        Self::FailedBeforeActivation(state)
    }
}

impl From<TenantRootCleanupIncompleteRefreshV1> for TenantRootRefreshStateV1 {
    fn from(state: TenantRootCleanupIncompleteRefreshV1) -> Self {
        Self::CleanupIncomplete(state)
    }
}

fn parse_share_commitment(
    wire: &MpcPrfShareCommitmentWireV1,
) -> RouterAbDerivationResult<SigningRootShareCommitment> {
    SigningRootShareCommitment::from_slice(wire.as_bytes())
        .map_err(|_| malformed("tenant-root share commitment encoding is invalid"))
}

fn require_distinct_role_receipts(
    deriver_a: TenantRootLifecycleReceiptDigestV1,
    deriver_b: TenantRootLifecycleReceiptDigestV1,
) -> RouterAbDerivationResult<()> {
    if deriver_a == deriver_b {
        Err(malformed("tenant-root role receipts must be distinct"))
    } else {
        Ok(())
    }
}

fn require_timestamp(field: &'static str, value: u64) -> RouterAbDerivationResult<()> {
    if value == 0 {
        Err(RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::MalformedInput,
            format!("{field} must be non-zero"),
        ))
    } else {
        Ok(())
    }
}

fn require_failure_order(
    earliest_failure_at_ms: u64,
    failure: TenantRootCreationFailureV1,
    cleanup_at_ms: u64,
) -> RouterAbDerivationResult<()> {
    require_event_order(earliest_failure_at_ms, failure.failed_at_ms, cleanup_at_ms)
}

fn require_event_order(
    earliest_event_at_ms: u64,
    event_at_ms: u64,
    completion_at_ms: u64,
) -> RouterAbDerivationResult<()> {
    if event_at_ms < earliest_event_at_ms || completion_at_ms < event_at_ms {
        return Err(malformed(
            "tenant-root failure and cleanup timestamps are inconsistent",
        ));
    }
    Ok(())
}

fn require_transition_time(
    pending: &PendingTenantRootEpochV1,
    event_at_ms: u64,
    event: &'static str,
) -> RouterAbDerivationResult<()> {
    require_timestamp("tenant-root transition timestamp", event_at_ms)?;
    if event_at_ms < pending.issued_at_ms || event_at_ms > pending.expires_at_ms {
        let message = match event {
            "verification" => "tenant-root verification must occur within the ceremony lifetime",
            "activation" => "tenant-root activation must occur within the ceremony lifetime",
            _ => "tenant-root transition must occur within the ceremony lifetime",
        };
        return Err(malformed(message));
    }
    Ok(())
}

fn next_revision(current: u64) -> RouterAbDerivationResult<u64> {
    current
        .checked_add(1)
        .ok_or_else(|| malformed("tenant-root lifecycle revision is exhausted"))
}

fn malformed(message: &'static str) -> RouterAbDerivationError {
    RouterAbDerivationError::new(RouterAbDerivationErrorCode::MalformedInput, message)
}

fn replay_mismatch(message: &'static str) -> RouterAbDerivationError {
    RouterAbDerivationError::new(RouterAbDerivationErrorCode::ReplayMismatch, message)
}
