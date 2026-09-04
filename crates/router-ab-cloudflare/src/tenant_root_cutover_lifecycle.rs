use router_ab_core::{RouterAbProtocolError, RouterAbProtocolErrorCode, RouterAbProtocolResult};
use serde::{de::Error as DeError, Deserialize, Deserializer, Serialize};

use crate::{TenantRootRevisionManifestDigestV1, TenantRootRevisionManifestV1};

const MAX_CUTOVER_TIMESTAMP_MS_V1: u64 = 4_102_444_800_000;

/// Public random identifier for one cutover attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct TenantRootCutoverAttemptIdV1([u8; 16]);

impl TenantRootCutoverAttemptIdV1 {
    /// Parses one non-zero attempt identifier.
    pub fn from_bytes(bytes: [u8; 16]) -> RouterAbProtocolResult<Self> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(invalid("R120 cutover attempt id must be non-zero"));
        }
        Ok(Self(bytes))
    }

    /// Returns the exact attempt bytes.
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl<'de> Deserialize<'de> for TenantRootCutoverAttemptIdV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::from_bytes(<[u8; 16]>::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

/// Public digest of one signed cutover receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct TenantRootCutoverReceiptDigestV1([u8; 32]);

impl TenantRootCutoverReceiptDigestV1 {
    /// Parses a non-zero signed receipt digest.
    pub fn from_bytes(bytes: [u8; 32]) -> RouterAbProtocolResult<Self> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(invalid("R120 cutover receipt digest must be non-zero"));
        }
        Ok(Self(bytes))
    }

    /// Returns the exact digest bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl<'de> Deserialize<'de> for TenantRootCutoverReceiptDigestV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::from_bytes(<[u8; 32]>::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

/// Signed prerequisites required before a derivation fence may close.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TenantRootCutoverPrerequisitesV1 {
    r103f_r5_closure: TenantRootCutoverReceiptDigestV1,
    committed_identity_inventory: TenantRootCutoverReceiptDigestV1,
    phase0_architecture_selection: TenantRootCutoverReceiptDigestV1,
    phase0_selection_record_digest: [u8; 32],
}

impl<'de> Deserialize<'de> for TenantRootCutoverPrerequisitesV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Wire {
            r103f_r5_closure: TenantRootCutoverReceiptDigestV1,
            committed_identity_inventory: TenantRootCutoverReceiptDigestV1,
            phase0_architecture_selection: TenantRootCutoverReceiptDigestV1,
            phase0_selection_record_digest: [u8; 32],
        }

        let wire = Wire::deserialize(deserializer)?;
        Self::new(
            wire.r103f_r5_closure,
            wire.committed_identity_inventory,
            wire.phase0_architecture_selection,
            wire.phase0_selection_record_digest,
        )
        .map_err(D::Error::custom)
    }
}

impl TenantRootCutoverPrerequisitesV1 {
    /// Creates one exact prerequisite set.
    ///
    /// `phase0_selection_record_digest` is the verifier-committed
    /// `approval_payload_sha256` that `phase0_architecture_selection` attests to.
    /// Both come from one offline architecture-selection verifier output; the
    /// receipt is never compared against the record digest, because they digest
    /// different bytes at different layers.
    pub fn new(
        r103f_r5_closure: TenantRootCutoverReceiptDigestV1,
        committed_identity_inventory: TenantRootCutoverReceiptDigestV1,
        phase0_architecture_selection: TenantRootCutoverReceiptDigestV1,
        phase0_selection_record_digest: [u8; 32],
    ) -> RouterAbProtocolResult<Self> {
        require_distinct_receipts(&[
            r103f_r5_closure,
            committed_identity_inventory,
            phase0_architecture_selection,
        ])?;
        if phase0_selection_record_digest.iter().all(|byte| *byte == 0) {
            return Err(invalid(
                "R120 Phase 0 selection-record digest must be non-zero",
            ));
        }
        Ok(Self {
            r103f_r5_closure,
            committed_identity_inventory,
            phase0_architecture_selection,
            phase0_selection_record_digest,
        })
    }

    /// Returns the verifier-committed Phase 0 `approval_payload_sha256`.
    pub const fn phase0_selection_record_digest(&self) -> &[u8; 32] {
        &self.phase0_selection_record_digest
    }
}

/// The two derivation families that must pass after profile activation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TenantRootCutoverCanaryCurveV1 {
    Ecdsa,
    Ed25519,
}

/// One admitted post-activation derivation canary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TenantRootCutoverCanaryReceiptV1 {
    attempt_id: TenantRootCutoverAttemptIdV1,
    curve: TenantRootCutoverCanaryCurveV1,
    receipt_digest: TenantRootCutoverReceiptDigestV1,
    completed_at_ms: u64,
}

impl TenantRootCutoverCanaryReceiptV1 {
    /// Creates one curve-specific successful canary receipt.
    pub fn new(
        attempt_id: TenantRootCutoverAttemptIdV1,
        curve: TenantRootCutoverCanaryCurveV1,
        receipt_digest: TenantRootCutoverReceiptDigestV1,
        completed_at_ms: u64,
    ) -> RouterAbProtocolResult<Self> {
        require_timestamp("R120 cutover canary completion", completed_at_ms)?;
        Ok(Self {
            attempt_id,
            curve,
            receipt_digest,
            completed_at_ms,
        })
    }

    /// Returns the canary's curve family.
    pub const fn curve(&self) -> TenantRootCutoverCanaryCurveV1 {
        self.curve
    }
}

/// Receipt proving the derivation-only fence is closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TenantRootCutoverFenceReceiptV1 {
    attempt_id: TenantRootCutoverAttemptIdV1,
    digest: TenantRootCutoverReceiptDigestV1,
    fenced_at_ms: u64,
}

impl TenantRootCutoverFenceReceiptV1 {
    /// Creates one fence receipt boundary value.
    pub fn new(
        attempt_id: TenantRootCutoverAttemptIdV1,
        digest: TenantRootCutoverReceiptDigestV1,
        fenced_at_ms: u64,
    ) -> RouterAbProtocolResult<Self> {
        require_timestamp("R120 derivation fence", fenced_at_ms)?;
        Ok(Self {
            attempt_id,
            digest,
            fenced_at_ms,
        })
    }
}

/// Receipt proving every prior derivation and delayed commit path is terminal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TenantRootCutoverDrainReceiptV1 {
    attempt_id: TenantRootCutoverAttemptIdV1,
    zero_in_flight: TenantRootCutoverReceiptDigestV1,
    delayed_commit_retirement: TenantRootCutoverReceiptDigestV1,
    drained_at_ms: u64,
}

impl TenantRootCutoverDrainReceiptV1 {
    /// Creates one exact drain receipt pair.
    pub fn new(
        attempt_id: TenantRootCutoverAttemptIdV1,
        zero_in_flight: TenantRootCutoverReceiptDigestV1,
        delayed_commit_retirement: TenantRootCutoverReceiptDigestV1,
        drained_at_ms: u64,
    ) -> RouterAbProtocolResult<Self> {
        require_timestamp("R120 cutover drain", drained_at_ms)?;
        require_distinct_receipts(&[zero_in_flight, delayed_commit_retirement])?;
        Ok(Self {
            attempt_id,
            zero_in_flight,
            delayed_commit_retirement,
            drained_at_ms,
        })
    }
}

/// Receipt proving one exact revision set and all pre-activation probes passed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TenantRootCutoverRevisionVerificationReceiptV1 {
    attempt_id: TenantRootCutoverAttemptIdV1,
    manifest_digest: TenantRootRevisionManifestDigestV1,
    phase0_selection_record_digest: [u8; 32],
    ecdsa_canary: TenantRootCutoverReceiptDigestV1,
    ed25519_canary: TenantRootCutoverReceiptDigestV1,
    mixed_revision_rejection: TenantRootCutoverReceiptDigestV1,
    verified_at_ms: u64,
}

impl TenantRootCutoverRevisionVerificationReceiptV1 {
    /// Creates one exact revision-verification receipt.
    pub fn new(
        attempt_id: TenantRootCutoverAttemptIdV1,
        manifest: &TenantRootRevisionManifestV1,
        ecdsa_canary: TenantRootCutoverReceiptDigestV1,
        ed25519_canary: TenantRootCutoverReceiptDigestV1,
        mixed_revision_rejection: TenantRootCutoverReceiptDigestV1,
        verified_at_ms: u64,
    ) -> RouterAbProtocolResult<Self> {
        Self::from_persisted(
            attempt_id,
            manifest.digest()?,
            *manifest.phase0_selection_record_digest(),
            ecdsa_canary,
            ed25519_canary,
            mixed_revision_rejection,
            verified_at_ms,
        )
    }

    fn from_persisted(
        attempt_id: TenantRootCutoverAttemptIdV1,
        manifest_digest: TenantRootRevisionManifestDigestV1,
        phase0_selection_record_digest: [u8; 32],
        ecdsa_canary: TenantRootCutoverReceiptDigestV1,
        ed25519_canary: TenantRootCutoverReceiptDigestV1,
        mixed_revision_rejection: TenantRootCutoverReceiptDigestV1,
        verified_at_ms: u64,
    ) -> RouterAbProtocolResult<Self> {
        require_timestamp("R120 revision verification", verified_at_ms)?;
        require_distinct_receipts(&[ecdsa_canary, ed25519_canary, mixed_revision_rejection])?;
        if phase0_selection_record_digest.iter().all(|byte| *byte == 0) {
            return Err(invalid(
                "R120 Phase 0 selection-record digest must be non-zero",
            ));
        }
        Ok(Self {
            attempt_id,
            manifest_digest,
            phase0_selection_record_digest,
            ecdsa_canary,
            ed25519_canary,
            mixed_revision_rejection,
            verified_at_ms,
        })
    }
}

/// Receipt selecting the one R120 profile while the fence remains closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TenantRootCutoverProfileActivationReceiptV1 {
    attempt_id: TenantRootCutoverAttemptIdV1,
    digest: TenantRootCutoverReceiptDigestV1,
    activated_at_ms: u64,
}

impl TenantRootCutoverProfileActivationReceiptV1 {
    /// Creates one profile-activation receipt.
    pub fn new(
        attempt_id: TenantRootCutoverAttemptIdV1,
        digest: TenantRootCutoverReceiptDigestV1,
        activated_at_ms: u64,
    ) -> RouterAbProtocolResult<Self> {
        require_timestamp("R120 profile activation", activated_at_ms)?;
        Ok(Self {
            attempt_id,
            digest,
            activated_at_ms,
        })
    }
}

/// Receipt authorizing a pre-commit rollback.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TenantRootCutoverRollbackReceiptV1 {
    attempt_id: TenantRootCutoverAttemptIdV1,
    digest: TenantRootCutoverReceiptDigestV1,
    rolled_back_at_ms: u64,
}

impl TenantRootCutoverRollbackReceiptV1 {
    /// Creates one rollback receipt.
    pub fn new(
        attempt_id: TenantRootCutoverAttemptIdV1,
        digest: TenantRootCutoverReceiptDigestV1,
        rolled_back_at_ms: u64,
    ) -> RouterAbProtocolResult<Self> {
        require_timestamp("R120 cutover rollback", rolled_back_at_ms)?;
        Ok(Self {
            attempt_id,
            digest,
            rolled_back_at_ms,
        })
    }
}

/// Receipt proving derivation reopened after both post-activation canaries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TenantRootCutoverUnfenceReceiptV1 {
    attempt_id: TenantRootCutoverAttemptIdV1,
    digest: TenantRootCutoverReceiptDigestV1,
    unfenced_at_ms: u64,
}

impl TenantRootCutoverUnfenceReceiptV1 {
    /// Creates one unfence receipt.
    pub fn new(
        attempt_id: TenantRootCutoverAttemptIdV1,
        digest: TenantRootCutoverReceiptDigestV1,
        unfenced_at_ms: u64,
    ) -> RouterAbProtocolResult<Self> {
        require_timestamp("R120 derivation unfence", unfenced_at_ms)?;
        Ok(Self {
            attempt_id,
            digest,
            unfenced_at_ms,
        })
    }
}

impl<'de> Deserialize<'de> for TenantRootCutoverCanaryReceiptV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Wire {
            attempt_id: TenantRootCutoverAttemptIdV1,
            curve: TenantRootCutoverCanaryCurveV1,
            receipt_digest: TenantRootCutoverReceiptDigestV1,
            completed_at_ms: u64,
        }
        let wire = Wire::deserialize(deserializer)?;
        Self::new(
            wire.attempt_id,
            wire.curve,
            wire.receipt_digest,
            wire.completed_at_ms,
        )
        .map_err(D::Error::custom)
    }
}

impl<'de> Deserialize<'de> for TenantRootCutoverFenceReceiptV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Wire {
            attempt_id: TenantRootCutoverAttemptIdV1,
            digest: TenantRootCutoverReceiptDigestV1,
            fenced_at_ms: u64,
        }
        let wire = Wire::deserialize(deserializer)?;
        Self::new(wire.attempt_id, wire.digest, wire.fenced_at_ms).map_err(D::Error::custom)
    }
}

impl<'de> Deserialize<'de> for TenantRootCutoverDrainReceiptV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Wire {
            attempt_id: TenantRootCutoverAttemptIdV1,
            zero_in_flight: TenantRootCutoverReceiptDigestV1,
            delayed_commit_retirement: TenantRootCutoverReceiptDigestV1,
            drained_at_ms: u64,
        }
        let wire = Wire::deserialize(deserializer)?;
        Self::new(
            wire.attempt_id,
            wire.zero_in_flight,
            wire.delayed_commit_retirement,
            wire.drained_at_ms,
        )
        .map_err(D::Error::custom)
    }
}

impl<'de> Deserialize<'de> for TenantRootCutoverRevisionVerificationReceiptV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Wire {
            attempt_id: TenantRootCutoverAttemptIdV1,
            manifest_digest: TenantRootRevisionManifestDigestV1,
            phase0_selection_record_digest: [u8; 32],
            ecdsa_canary: TenantRootCutoverReceiptDigestV1,
            ed25519_canary: TenantRootCutoverReceiptDigestV1,
            mixed_revision_rejection: TenantRootCutoverReceiptDigestV1,
            verified_at_ms: u64,
        }
        let wire = Wire::deserialize(deserializer)?;
        Self::from_persisted(
            wire.attempt_id,
            wire.manifest_digest,
            wire.phase0_selection_record_digest,
            wire.ecdsa_canary,
            wire.ed25519_canary,
            wire.mixed_revision_rejection,
            wire.verified_at_ms,
        )
        .map_err(D::Error::custom)
    }
}

impl<'de> Deserialize<'de> for TenantRootCutoverProfileActivationReceiptV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Wire {
            attempt_id: TenantRootCutoverAttemptIdV1,
            digest: TenantRootCutoverReceiptDigestV1,
            activated_at_ms: u64,
        }
        let wire = Wire::deserialize(deserializer)?;
        Self::new(wire.attempt_id, wire.digest, wire.activated_at_ms).map_err(D::Error::custom)
    }
}

impl<'de> Deserialize<'de> for TenantRootCutoverRollbackReceiptV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Wire {
            attempt_id: TenantRootCutoverAttemptIdV1,
            digest: TenantRootCutoverReceiptDigestV1,
            rolled_back_at_ms: u64,
        }
        let wire = Wire::deserialize(deserializer)?;
        Self::new(wire.attempt_id, wire.digest, wire.rolled_back_at_ms).map_err(D::Error::custom)
    }
}

impl<'de> Deserialize<'de> for TenantRootCutoverUnfenceReceiptV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Wire {
            attempt_id: TenantRootCutoverAttemptIdV1,
            digest: TenantRootCutoverReceiptDigestV1,
            unfenced_at_ms: u64,
        }
        let wire = Wire::deserialize(deserializer)?;
        Self::new(wire.attempt_id, wire.digest, wire.unfenced_at_ms).map_err(D::Error::custom)
    }
}

/// Initial state carrying fresh signed prerequisites.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TenantRootCutoverOpenV1 {
    attempt_id: TenantRootCutoverAttemptIdV1,
    prerequisites: TenantRootCutoverPrerequisitesV1,
}

impl TenantRootCutoverOpenV1 {
    /// Starts one new cutover attempt.
    pub const fn new(
        attempt_id: TenantRootCutoverAttemptIdV1,
        prerequisites: TenantRootCutoverPrerequisitesV1,
    ) -> Self {
        Self {
            attempt_id,
            prerequisites,
        }
    }

    /// Returns the attempt identifier that the runtime receipt verifier must bind.
    pub const fn attempt_id(&self) -> TenantRootCutoverAttemptIdV1 {
        self.attempt_id
    }

    /// Closes the derivation-only fence. Normal signing remains outside this state.
    pub fn fence(
        self,
        receipt: TenantRootCutoverFenceReceiptV1,
    ) -> RouterAbProtocolResult<TenantRootCutoverFencedV1> {
        require_attempt(self.attempt_id, receipt.attempt_id)?;
        Ok(TenantRootCutoverFencedV1 {
            attempt_id: self.attempt_id,
            prerequisites: self.prerequisites,
            receipt,
        })
    }
}

/// New derivation is fenced while existing sessions drain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TenantRootCutoverFencedV1 {
    attempt_id: TenantRootCutoverAttemptIdV1,
    prerequisites: TenantRootCutoverPrerequisitesV1,
    receipt: TenantRootCutoverFenceReceiptV1,
}

impl TenantRootCutoverFencedV1 {
    /// Records zero in-flight derivations and retired delayed commit paths.
    pub fn drain(
        self,
        receipt: TenantRootCutoverDrainReceiptV1,
    ) -> RouterAbProtocolResult<TenantRootCutoverDrainedV1> {
        require_attempt(self.attempt_id, receipt.attempt_id)?;
        require_later(
            "R120 cutover drain",
            self.receipt.fenced_at_ms,
            receipt.drained_at_ms,
        )?;
        Ok(TenantRootCutoverDrainedV1 {
            fenced: self,
            receipt,
        })
    }

    /// Rolls back before any R120-profile derivation can be admitted.
    pub fn rollback(
        self,
        receipt: TenantRootCutoverRollbackReceiptV1,
    ) -> RouterAbProtocolResult<TenantRootCutoverRolledBackV1> {
        rollback_from(self.attempt_id, 1, self.receipt.fenced_at_ms, receipt)
    }
}

/// Every pre-cutover derivation path is terminal while the fence remains closed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TenantRootCutoverDrainedV1 {
    fenced: TenantRootCutoverFencedV1,
    receipt: TenantRootCutoverDrainReceiptV1,
}

impl TenantRootCutoverDrainedV1 {
    /// Binds the complete deployed revision set and pre-activation canaries.
    pub fn verify_revisions(
        self,
        receipt: TenantRootCutoverRevisionVerificationReceiptV1,
    ) -> RouterAbProtocolResult<TenantRootCutoverRevisionsVerifiedV1> {
        require_attempt(self.fenced.attempt_id, receipt.attempt_id)?;
        require_phase0_selection_record(
            self.fenced.prerequisites.phase0_selection_record_digest(),
            &receipt.phase0_selection_record_digest,
        )?;
        require_later(
            "R120 revision verification",
            self.receipt.drained_at_ms,
            receipt.verified_at_ms,
        )?;
        Ok(TenantRootCutoverRevisionsVerifiedV1 {
            drained: self,
            receipt,
        })
    }

    /// Rolls back while no R120 profile is active.
    pub fn rollback(
        self,
        receipt: TenantRootCutoverRollbackReceiptV1,
    ) -> RouterAbProtocolResult<TenantRootCutoverRolledBackV1> {
        rollback_from(
            self.fenced.attempt_id,
            2,
            self.receipt.drained_at_ms,
            receipt,
        )
    }
}

/// Every participant reports one exact revision set and both curves passed canaries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TenantRootCutoverRevisionsVerifiedV1 {
    drained: TenantRootCutoverDrainedV1,
    receipt: TenantRootCutoverRevisionVerificationReceiptV1,
}

impl TenantRootCutoverRevisionsVerifiedV1 {
    /// Activates the one selected R120 profile while derivation remains fenced.
    pub fn activate_profile(
        self,
        receipt: TenantRootCutoverProfileActivationReceiptV1,
    ) -> RouterAbProtocolResult<TenantRootCutoverProfileActivatedV1> {
        require_attempt(self.drained.fenced.attempt_id, receipt.attempt_id)?;
        require_later(
            "R120 profile activation",
            self.receipt.verified_at_ms,
            receipt.activated_at_ms,
        )?;
        Ok(TenantRootCutoverProfileActivatedV1 {
            revisions: self,
            receipt,
        })
    }

    /// Rolls back before the selected profile is active.
    pub fn rollback(
        self,
        receipt: TenantRootCutoverRollbackReceiptV1,
    ) -> RouterAbProtocolResult<TenantRootCutoverRolledBackV1> {
        rollback_from(
            self.drained.fenced.attempt_id,
            3,
            self.receipt.verified_at_ms,
            receipt,
        )
    }
}

/// The R120 profile is selected, but no R120-profile derivation was admitted yet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TenantRootCutoverProfileActivatedV1 {
    revisions: TenantRootCutoverRevisionsVerifiedV1,
    receipt: TenantRootCutoverProfileActivationReceiptV1,
}

impl TenantRootCutoverProfileActivatedV1 {
    /// Admits the first post-activation derivation and crosses the rollback boundary.
    pub fn admit_first_derivation(
        self,
        canary: TenantRootCutoverCanaryReceiptV1,
    ) -> RouterAbProtocolResult<TenantRootCutoverProfileCommittedV1> {
        require_attempt(self.revisions.drained.fenced.attempt_id, canary.attempt_id)?;
        require_fresh_post_activation_canary(&self.revisions.receipt, canary.receipt_digest)?;
        require_later(
            "R120 first profile derivation",
            self.receipt.activated_at_ms,
            canary.completed_at_ms,
        )?;
        Ok(TenantRootCutoverProfileCommittedV1 {
            activated: self,
            first_canary: canary,
        })
    }

    /// Rolls back while no R120-profile derivation has been admitted.
    pub fn rollback(
        self,
        receipt: TenantRootCutoverRollbackReceiptV1,
    ) -> RouterAbProtocolResult<TenantRootCutoverRolledBackV1> {
        rollback_from(
            self.revisions.drained.fenced.attempt_id,
            4,
            self.receipt.activated_at_ms,
            receipt,
        )
    }
}

/// The first R120-profile derivation was admitted; recovery is forward-only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TenantRootCutoverProfileCommittedV1 {
    activated: TenantRootCutoverProfileActivatedV1,
    first_canary: TenantRootCutoverCanaryReceiptV1,
}

impl TenantRootCutoverProfileCommittedV1 {
    /// Completes the other curve's post-activation proof.
    pub fn complete_other_curve(
        self,
        canary: TenantRootCutoverCanaryReceiptV1,
    ) -> RouterAbProtocolResult<TenantRootCutoverReadyToUnfenceV1> {
        require_attempt(
            self.activated.revisions.drained.fenced.attempt_id,
            canary.attempt_id,
        )?;
        require_fresh_post_activation_canary(
            &self.activated.revisions.receipt,
            canary.receipt_digest,
        )?;
        require_later(
            "R120 second profile derivation",
            self.first_canary.completed_at_ms,
            canary.completed_at_ms,
        )?;
        if canary.curve == self.first_canary.curve {
            return Err(invalid(
                "R120 cutover requires one post-activation canary for each curve",
            ));
        }
        if canary.receipt_digest == self.first_canary.receipt_digest {
            return Err(invalid("R120 cutover canary receipts must be distinct"));
        }
        Ok(TenantRootCutoverReadyToUnfenceV1 {
            committed: self,
            second_canary: canary,
        })
    }
}

/// Both post-activation curve proofs passed and the cutover may unfence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TenantRootCutoverReadyToUnfenceV1 {
    committed: TenantRootCutoverProfileCommittedV1,
    second_canary: TenantRootCutoverCanaryReceiptV1,
}

impl TenantRootCutoverReadyToUnfenceV1 {
    /// Opens new derivation after recording the final cutover receipt.
    pub fn unfence(
        self,
        receipt: TenantRootCutoverUnfenceReceiptV1,
    ) -> RouterAbProtocolResult<TenantRootCutoverCompleteV1> {
        require_attempt(
            self.committed.activated.revisions.drained.fenced.attempt_id,
            receipt.attempt_id,
        )?;
        require_later(
            "R120 derivation unfence",
            self.second_canary.completed_at_ms,
            receipt.unfenced_at_ms,
        )?;
        Ok(TenantRootCutoverCompleteV1 {
            ready: self,
            receipt,
        })
    }
}

/// Terminal successful cutover state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TenantRootCutoverCompleteV1 {
    ready: TenantRootCutoverReadyToUnfenceV1,
    receipt: TenantRootCutoverUnfenceReceiptV1,
}

/// Terminal pre-commit rollback state. A retry starts from fresh prerequisites.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TenantRootCutoverRolledBackV1 {
    attempt_id: TenantRootCutoverAttemptIdV1,
    rolled_back_from_revision: u64,
    receipt: TenantRootCutoverRollbackReceiptV1,
}

impl TenantRootCutoverRolledBackV1 {
    /// Returns the attempt identifier retained by the terminal rollback.
    pub const fn attempt_id(&self) -> TenantRootCutoverAttemptIdV1 {
        self.attempt_id
    }
}

impl<'de> Deserialize<'de> for TenantRootCutoverFencedV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Wire {
            attempt_id: TenantRootCutoverAttemptIdV1,
            prerequisites: TenantRootCutoverPrerequisitesV1,
            receipt: TenantRootCutoverFenceReceiptV1,
        }
        let wire = Wire::deserialize(deserializer)?;
        TenantRootCutoverOpenV1::new(wire.attempt_id, wire.prerequisites)
            .fence(wire.receipt)
            .map_err(D::Error::custom)
    }
}

impl<'de> Deserialize<'de> for TenantRootCutoverDrainedV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Wire {
            fenced: TenantRootCutoverFencedV1,
            receipt: TenantRootCutoverDrainReceiptV1,
        }
        let wire = Wire::deserialize(deserializer)?;
        wire.fenced.drain(wire.receipt).map_err(D::Error::custom)
    }
}

impl<'de> Deserialize<'de> for TenantRootCutoverRevisionsVerifiedV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Wire {
            drained: TenantRootCutoverDrainedV1,
            receipt: TenantRootCutoverRevisionVerificationReceiptV1,
        }
        let wire = Wire::deserialize(deserializer)?;
        wire.drained
            .verify_revisions(wire.receipt)
            .map_err(D::Error::custom)
    }
}

impl<'de> Deserialize<'de> for TenantRootCutoverProfileActivatedV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Wire {
            revisions: TenantRootCutoverRevisionsVerifiedV1,
            receipt: TenantRootCutoverProfileActivationReceiptV1,
        }
        let wire = Wire::deserialize(deserializer)?;
        wire.revisions
            .activate_profile(wire.receipt)
            .map_err(D::Error::custom)
    }
}

impl<'de> Deserialize<'de> for TenantRootCutoverProfileCommittedV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Wire {
            activated: TenantRootCutoverProfileActivatedV1,
            first_canary: TenantRootCutoverCanaryReceiptV1,
        }
        let wire = Wire::deserialize(deserializer)?;
        wire.activated
            .admit_first_derivation(wire.first_canary)
            .map_err(D::Error::custom)
    }
}

impl<'de> Deserialize<'de> for TenantRootCutoverReadyToUnfenceV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Wire {
            committed: TenantRootCutoverProfileCommittedV1,
            second_canary: TenantRootCutoverCanaryReceiptV1,
        }
        let wire = Wire::deserialize(deserializer)?;
        wire.committed
            .complete_other_curve(wire.second_canary)
            .map_err(D::Error::custom)
    }
}

impl<'de> Deserialize<'de> for TenantRootCutoverCompleteV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Wire {
            ready: TenantRootCutoverReadyToUnfenceV1,
            receipt: TenantRootCutoverUnfenceReceiptV1,
        }
        let wire = Wire::deserialize(deserializer)?;
        wire.ready.unfence(wire.receipt).map_err(D::Error::custom)
    }
}

impl<'de> Deserialize<'de> for TenantRootCutoverRolledBackV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Wire {
            attempt_id: TenantRootCutoverAttemptIdV1,
            rolled_back_from_revision: u64,
            receipt: TenantRootCutoverRollbackReceiptV1,
        }
        let wire = Wire::deserialize(deserializer)?;
        if !(1..=4).contains(&wire.rolled_back_from_revision) {
            return Err(D::Error::custom(
                "R120 cutover rollback revision must be between 1 and 4",
            ));
        }
        require_attempt(wire.attempt_id, wire.receipt.attempt_id).map_err(D::Error::custom)?;
        Ok(Self {
            attempt_id: wire.attempt_id,
            rolled_back_from_revision: wire.rolled_back_from_revision,
            receipt: wire.receipt,
        })
    }
}

/// Exhaustive persisted cutover state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "state",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum TenantRootCutoverStateV1 {
    Open(TenantRootCutoverOpenV1),
    Fenced(TenantRootCutoverFencedV1),
    Drained(TenantRootCutoverDrainedV1),
    RevisionsVerified(TenantRootCutoverRevisionsVerifiedV1),
    ProfileActivated(TenantRootCutoverProfileActivatedV1),
    ProfileCommitted(TenantRootCutoverProfileCommittedV1),
    ReadyToUnfence(TenantRootCutoverReadyToUnfenceV1),
    Complete(TenantRootCutoverCompleteV1),
    RolledBack(TenantRootCutoverRolledBackV1),
}

/// One exhaustive restart action for every persisted cutover state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TenantRootCutoverRecoveryActionV1 {
    CloseFence,
    ResumeDrainOrRollback,
    ResumeRevisionVerificationOrRollback,
    ResumeProfileActivationOrRollback,
    ResumeFirstDerivationOrRollback,
    ResumeForwardOnlyOtherCurve,
    ResumeUnfence,
    Complete,
    StartFreshAttempt,
}

/// The exact derivation admission rule recovered from durable cutover state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TenantRootCutoverDerivationGateV1 {
    LegacyProfileOpen,
    FencedRollbackAvailable,
    FencedForwardOnly,
    R120ProfileOpen,
    RolledBackLegacyProfileOpen,
}

const TENANT_ROOT_CUTOVER_RECORD_SCHEMA_V1: &str = "tenant_root_cutover_record_v1";

/// Strict durable-storage envelope for one cutover lifecycle checkpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantRootCutoverRecordV1 {
    schema: &'static str,
    revision: u64,
    state: TenantRootCutoverStateV1,
}

/// Result of comparing one proposed durable checkpoint with the current record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TenantRootCutoverRecordUpdateV1 {
    ExactReplay,
    Advanced,
}

impl TenantRootCutoverRecordV1 {
    /// Creates one revision-bound durable record.
    pub fn new(state: TenantRootCutoverStateV1) -> Self {
        Self {
            schema: TENANT_ROOT_CUTOVER_RECORD_SCHEMA_V1,
            revision: state.revision(),
            state,
        }
    }

    /// Returns the persisted monotonic revision.
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Returns the restart-safe derivation gate.
    pub const fn derivation_gate(&self) -> TenantRootCutoverDerivationGateV1 {
        self.state.derivation_gate()
    }

    /// Returns the validated state for the next transition.
    pub fn into_state(self) -> TenantRootCutoverStateV1 {
        self.state
    }

    /// Validates one exact replay or one legal adjacent lifecycle transition.
    pub fn classify_update_after(
        &self,
        current: &Self,
    ) -> RouterAbProtocolResult<TenantRootCutoverRecordUpdateV1> {
        if self == current {
            return Ok(TenantRootCutoverRecordUpdateV1::ExactReplay);
        }
        let valid = match (&current.state, &self.state) {
            (TenantRootCutoverStateV1::Open(previous), TenantRootCutoverStateV1::Fenced(next)) => {
                previous.clone().fence(next.receipt.clone())? == *next
            }
            (
                TenantRootCutoverStateV1::Fenced(previous),
                TenantRootCutoverStateV1::Drained(next),
            ) => previous.clone().drain(next.receipt)? == *next,
            (
                TenantRootCutoverStateV1::Drained(previous),
                TenantRootCutoverStateV1::RevisionsVerified(next),
            ) => previous.clone().verify_revisions(next.receipt)? == *next,
            (
                TenantRootCutoverStateV1::RevisionsVerified(previous),
                TenantRootCutoverStateV1::ProfileActivated(next),
            ) => previous.clone().activate_profile(next.receipt)? == *next,
            (
                TenantRootCutoverStateV1::ProfileActivated(previous),
                TenantRootCutoverStateV1::ProfileCommitted(next),
            ) => previous.clone().admit_first_derivation(next.first_canary)? == *next,
            (
                TenantRootCutoverStateV1::ProfileCommitted(previous),
                TenantRootCutoverStateV1::ReadyToUnfence(next),
            ) => previous.clone().complete_other_curve(next.second_canary)? == *next,
            (
                TenantRootCutoverStateV1::ReadyToUnfence(previous),
                TenantRootCutoverStateV1::Complete(next),
            ) => previous.clone().unfence(next.receipt)? == *next,
            (
                TenantRootCutoverStateV1::Fenced(previous),
                TenantRootCutoverStateV1::RolledBack(next),
            ) => previous.clone().rollback(next.receipt)? == *next,
            (
                TenantRootCutoverStateV1::Drained(previous),
                TenantRootCutoverStateV1::RolledBack(next),
            ) => previous.clone().rollback(next.receipt)? == *next,
            (
                TenantRootCutoverStateV1::RevisionsVerified(previous),
                TenantRootCutoverStateV1::RolledBack(next),
            ) => previous.clone().rollback(next.receipt)? == *next,
            (
                TenantRootCutoverStateV1::ProfileActivated(previous),
                TenantRootCutoverStateV1::RolledBack(next),
            ) => previous.clone().rollback(next.receipt)? == *next,
            _ => false,
        };
        if !valid {
            return Err(invalid(
                "R120 cutover durable update is not an adjacent lifecycle transition",
            ));
        }
        Ok(TenantRootCutoverRecordUpdateV1::Advanced)
    }
}

impl<'de> Deserialize<'de> for TenantRootCutoverRecordV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Wire {
            schema: String,
            revision: u64,
            state: TenantRootCutoverStateV1,
        }

        let wire = Wire::deserialize(deserializer)?;
        if wire.schema != TENANT_ROOT_CUTOVER_RECORD_SCHEMA_V1 {
            return Err(D::Error::custom("unsupported R120 cutover record schema"));
        }
        if wire.revision != wire.state.revision() {
            return Err(D::Error::custom(
                "R120 cutover record revision does not match its state",
            ));
        }
        Ok(Self::new(wire.state))
    }
}

impl TenantRootCutoverStateV1 {
    /// Returns the monotonic revision represented by each state.
    pub const fn revision(&self) -> u64 {
        match self {
            Self::Open(_) => 0,
            Self::Fenced(_) => 1,
            Self::Drained(_) => 2,
            Self::RevisionsVerified(_) => 3,
            Self::ProfileActivated(_) => 4,
            Self::ProfileCommitted(_) => 5,
            Self::ReadyToUnfence(_) => 6,
            Self::Complete(_) => 7,
            Self::RolledBack(state) => 8 + state.rolled_back_from_revision,
        }
    }

    /// Returns the only supported recovery branch after restart.
    pub const fn recovery_action(&self) -> TenantRootCutoverRecoveryActionV1 {
        match self {
            Self::Open(_) => TenantRootCutoverRecoveryActionV1::CloseFence,
            Self::Fenced(_) => TenantRootCutoverRecoveryActionV1::ResumeDrainOrRollback,
            Self::Drained(_) => {
                TenantRootCutoverRecoveryActionV1::ResumeRevisionVerificationOrRollback
            }
            Self::RevisionsVerified(_) => {
                TenantRootCutoverRecoveryActionV1::ResumeProfileActivationOrRollback
            }
            Self::ProfileActivated(_) => {
                TenantRootCutoverRecoveryActionV1::ResumeFirstDerivationOrRollback
            }
            Self::ProfileCommitted(_) => {
                TenantRootCutoverRecoveryActionV1::ResumeForwardOnlyOtherCurve
            }
            Self::ReadyToUnfence(_) => TenantRootCutoverRecoveryActionV1::ResumeUnfence,
            Self::Complete(_) => TenantRootCutoverRecoveryActionV1::Complete,
            Self::RolledBack(_) => TenantRootCutoverRecoveryActionV1::StartFreshAttempt,
        }
    }

    /// Returns the derivation admission rule that survives a runtime restart.
    pub const fn derivation_gate(&self) -> TenantRootCutoverDerivationGateV1 {
        match self {
            Self::Open(_) => TenantRootCutoverDerivationGateV1::LegacyProfileOpen,
            Self::Fenced(_)
            | Self::Drained(_)
            | Self::RevisionsVerified(_)
            | Self::ProfileActivated(_) => {
                TenantRootCutoverDerivationGateV1::FencedRollbackAvailable
            }
            Self::ProfileCommitted(_) | Self::ReadyToUnfence(_) => {
                TenantRootCutoverDerivationGateV1::FencedForwardOnly
            }
            Self::Complete(_) => TenantRootCutoverDerivationGateV1::R120ProfileOpen,
            Self::RolledBack(_) => TenantRootCutoverDerivationGateV1::RolledBackLegacyProfileOpen,
        }
    }
}

impl From<TenantRootCutoverOpenV1> for TenantRootCutoverStateV1 {
    fn from(state: TenantRootCutoverOpenV1) -> Self {
        Self::Open(state)
    }
}

macro_rules! cutover_state_from {
    ($state:ty, $variant:ident) => {
        impl From<$state> for TenantRootCutoverStateV1 {
            fn from(state: $state) -> Self {
                Self::$variant(state)
            }
        }
    };
}

cutover_state_from!(TenantRootCutoverFencedV1, Fenced);
cutover_state_from!(TenantRootCutoverDrainedV1, Drained);
cutover_state_from!(TenantRootCutoverRevisionsVerifiedV1, RevisionsVerified);
cutover_state_from!(TenantRootCutoverProfileActivatedV1, ProfileActivated);
cutover_state_from!(TenantRootCutoverProfileCommittedV1, ProfileCommitted);
cutover_state_from!(TenantRootCutoverReadyToUnfenceV1, ReadyToUnfence);
cutover_state_from!(TenantRootCutoverCompleteV1, Complete);
cutover_state_from!(TenantRootCutoverRolledBackV1, RolledBack);

fn rollback_from(
    attempt_id: TenantRootCutoverAttemptIdV1,
    revision: u64,
    previous_at_ms: u64,
    receipt: TenantRootCutoverRollbackReceiptV1,
) -> RouterAbProtocolResult<TenantRootCutoverRolledBackV1> {
    require_attempt(attempt_id, receipt.attempt_id)?;
    require_later(
        "R120 cutover rollback",
        previous_at_ms,
        receipt.rolled_back_at_ms,
    )?;
    Ok(TenantRootCutoverRolledBackV1 {
        attempt_id,
        rolled_back_from_revision: revision,
        receipt,
    })
}

fn require_attempt(
    expected: TenantRootCutoverAttemptIdV1,
    actual: TenantRootCutoverAttemptIdV1,
) -> RouterAbProtocolResult<()> {
    if actual != expected {
        return Err(invalid("R120 cutover receipt belongs to another attempt"));
    }
    Ok(())
}

fn require_fresh_post_activation_canary(
    revision_receipt: &TenantRootCutoverRevisionVerificationReceiptV1,
    canary_receipt: TenantRootCutoverReceiptDigestV1,
) -> RouterAbProtocolResult<()> {
    if [
        revision_receipt.ecdsa_canary,
        revision_receipt.ed25519_canary,
        revision_receipt.mixed_revision_rejection,
    ]
    .contains(&canary_receipt)
    {
        return Err(invalid(
            "R120 post-activation canary must not reuse a pre-activation probe receipt",
        ));
    }
    Ok(())
}

/// Binds the fenced Phase 0 approval to the deployed revision manifest.
///
/// Only the two `approval_payload_sha256` record digests are compared. The
/// signed-selection receipt digest is never compared against a record digest.
fn require_phase0_selection_record(
    fenced: &[u8; 32],
    manifest: &[u8; 32],
) -> RouterAbProtocolResult<()> {
    if fenced != manifest {
        return Err(invalid(
            "R120 revision manifest names another Phase 0 selection record",
        ));
    }
    Ok(())
}

fn require_distinct_receipts(
    receipts: &[TenantRootCutoverReceiptDigestV1],
) -> RouterAbProtocolResult<()> {
    for (index, receipt) in receipts.iter().enumerate() {
        if receipts[index + 1..].contains(receipt) {
            return Err(invalid("R120 cutover receipt digests must be distinct"));
        }
    }
    Ok(())
}

fn require_timestamp(label: &'static str, timestamp_ms: u64) -> RouterAbProtocolResult<()> {
    if timestamp_ms == 0 || timestamp_ms > MAX_CUTOVER_TIMESTAMP_MS_V1 {
        return Err(invalid(format!(
            "{label} timestamp must be positive and no later than 2100-01-01"
        )));
    }
    Ok(())
}

fn require_later(
    label: &'static str,
    previous_ms: u64,
    next_ms: u64,
) -> RouterAbProtocolResult<()> {
    require_timestamp(label, next_ms)?;
    if next_ms <= previous_ms {
        return Err(invalid(format!("{label} must advance time")));
    }
    Ok(())
}

fn invalid(message: impl Into<String>) -> RouterAbProtocolError {
    RouterAbProtocolError::new(RouterAbProtocolErrorCode::InvalidLifecycleState, message)
}
