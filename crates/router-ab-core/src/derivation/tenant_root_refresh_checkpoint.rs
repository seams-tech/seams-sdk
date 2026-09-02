use core::num::NonZeroU64;

use threshold_prf::{derive_two_party_root_share_refresh_commitments, TwoPartyDeriverRole};

use super::{
    verify_tenant_root_refresh_evidence_v1, MpcPrfShareCommitmentWireV1, RouterAbDerivationError,
    RouterAbDerivationErrorCode, RouterAbDerivationResult, TenantRootActivationReceiptBindingV1,
    TenantRootActiveRootPairV1, TenantRootCeremonyContextV1, TenantRootCeremonyEpochsV1,
    TenantRootControlPlaneAuthorityIdV1, TenantRootCustodyLineageId, TenantRootEpochCommitmentsV1,
    TenantRootIdentityDigestV1, TenantRootLifecycleReceiptDigestV1, TenantRootProtocolDigestV1,
    TenantRootShareEpoch, TenantRootSignedRefreshCommitmentV1,
    VerifiedTenantRootRefreshCommitmentPairV1, VerifiedTenantRootRefreshCommitmentV1,
    VerifiedTenantRootRoleRefreshCommandV1, VerifiedTenantRootSignedActivationReceiptV1,
    VerifiedTenantRootSignedShareInstallationEvidenceWireV1,
};

const TENANT_ROOT_REFRESH_COMMITMENT_CHECKPOINT_DOMAIN_V1: &[u8] =
    b"tenant_root_refresh_commitment_checkpoint_v1";
const TENANT_ROOT_REFRESH_COMMITMENT_CHECKPOINT_SCOPE_DOMAIN_V1: &[u8] =
    b"tenant_root_refresh_commitment_checkpoint_scope_v1";
const TENANT_ROOT_REFRESH_COMMITMENT_CHECKPOINT_ONE_ROLE_TAG_V1: &[u8] = b"one_role_committed";
const TENANT_ROOT_REFRESH_COMMITMENT_CHECKPOINT_BOTH_ROLES_TAG_V1: &[u8] = b"both_roles_committed";
/// Maximum canonical wire size for one public refresh commitment checkpoint.
pub const TENANT_ROOT_REFRESH_COMMITMENT_CHECKPOINT_MAX_BYTES_V1: usize = 16 * 1024;

/// Authoritative public active state required to admit a refresh checkpoint.
///
/// Construction consumes an issuer-verified activation receipt and checks it
/// against the exact active pair resolved from the identity/lineage stores.
/// The caller supplies the validated persisted lifecycle revision; the receipt
/// remains part of the immutable provenance. This token is deliberately
/// neither cloneable nor copyable.
#[derive(Debug)]
pub struct TenantRootRefreshCommitmentCheckpointActiveBindingV1 {
    active_pair: TenantRootActiveRootPairV1,
    activation_receipt: VerifiedTenantRootSignedActivationReceiptV1,
    expected_control_plane_revision: NonZeroU64,
}

impl TenantRootRefreshCommitmentCheckpointActiveBindingV1 {
    /// Binds one resolved active A/B pair to its issuer-authenticated activation.
    pub fn from_verified_activation_receipt(
        activation_receipt: VerifiedTenantRootSignedActivationReceiptV1,
        active_pair: &TenantRootActiveRootPairV1,
        expected_control_plane_revision: u64,
    ) -> RouterAbDerivationResult<Self> {
        let expected_control_plane_revision = NonZeroU64::new(expected_control_plane_revision)
            .ok_or_else(|| {
                malformed("tenant-root refresh checkpoint lifecycle revision must be positive")
            })?;
        validate_active_pair_provenance(
            &activation_receipt,
            active_pair,
            expected_control_plane_revision,
        )?;
        Ok(Self {
            active_pair: active_pair.clone(),
            activation_receipt,
            expected_control_plane_revision,
        })
    }

    /// Returns the resolved public active A/B pair.
    pub const fn active_pair(&self) -> &TenantRootActiveRootPairV1 {
        &self.active_pair
    }

    /// Returns the authoritative lifecycle revision.
    pub const fn expected_control_plane_revision(&self) -> u64 {
        self.expected_control_plane_revision.get()
    }

    /// Returns the active identity digest.
    pub const fn identity_digest(&self) -> TenantRootIdentityDigestV1 {
        self.active_pair.identity_digest()
    }

    /// Returns the active custody lineage.
    pub const fn custody_lineage(&self) -> TenantRootCustodyLineageId {
        self.active_pair.custody_lineage()
    }

    /// Returns the active epoch.
    pub const fn current_epoch(&self) -> TenantRootShareEpoch {
        self.active_pair.epoch()
    }

    /// Returns the exact active A/B commitment pair.
    pub const fn commitments(&self) -> &TenantRootEpochCommitmentsV1 {
        self.active_pair.commitments()
    }

    /// Returns the active stable root commitment.
    pub const fn active_root_commitment(&self) -> &[u8; 32] {
        self.active_pair.root_commitment()
    }

    /// Returns the active activation receipt digest.
    pub const fn active_activation_receipt_digest(&self) -> TenantRootLifecycleReceiptDigestV1 {
        self.activation_receipt.digest()
    }
}

fn validate_active_pair_provenance(
    activation_receipt: &VerifiedTenantRootSignedActivationReceiptV1,
    active_pair: &TenantRootActiveRootPairV1,
    active_revision: NonZeroU64,
) -> RouterAbDerivationResult<NonZeroU64> {
    if activation_receipt.identity_digest() != active_pair.identity_digest() {
        return Err(replay_mismatch(
            "tenant-root refresh checkpoint active pair identity does not match its activation receipt",
        ));
    }
    if active_pair.custody_lineage() != activation_receipt.custody_lineage() {
        return Err(replay_mismatch(
            "tenant-root refresh checkpoint active pair lineage does not match its activation receipt",
        ));
    }

    let (expected_epoch, expected_commitments) = match activation_receipt.binding() {
        TenantRootActivationReceiptBindingV1::InitialCreation(binding) => {
            (TenantRootShareEpoch::INITIAL, binding.commitments())
        }
        TenantRootActivationReceiptBindingV1::RefreshSwap(binding) => {
            (binding.next_epoch(), binding.next_commitments())
        }
    };
    if active_pair.epoch() != expected_epoch {
        return Err(replay_mismatch(
            "tenant-root refresh checkpoint active pair epoch does not match its activation receipt",
        ));
    }
    if active_pair.commitments() != expected_commitments
        || active_pair.root_commitment() != expected_commitments.root_commitment()
    {
        return Err(replay_mismatch(
            "tenant-root refresh checkpoint active pair commitments do not match its activation receipt",
        ));
    }

    let activation_receipt_digest = activation_receipt.digest();
    if active_pair.deriver_a().activation_receipt_digest() != activation_receipt_digest
        || active_pair.deriver_b().activation_receipt_digest() != activation_receipt_digest
    {
        return Err(replay_mismatch(
            "tenant-root refresh checkpoint active pair role receipt does not match its activation receipt",
        ));
    }

    let activation_result_revision =
        NonZeroU64::new(activation_receipt.result_control_plane_revision()).ok_or_else(|| {
            malformed("tenant-root refresh checkpoint activation result revision must be positive")
        })?;
    if active_revision < activation_result_revision {
        return Err(replay_mismatch(
            "tenant-root refresh checkpoint active lifecycle revision predates its activation receipt",
        ));
    }
    Ok(active_revision)
}

/// Public scope shared by both role commands in one refresh checkpoint.
///
/// The scope is built from a verified issuer command, the exact ceremony
/// context, and the authoritative active public binding. It carries no role
/// share, coefficient, or other secret material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantRootRefreshCommitmentCheckpointScopeV1 {
    identity_digest: TenantRootIdentityDigestV1,
    custody_lineage: TenantRootCustodyLineageId,
    authority_id: TenantRootControlPlaneAuthorityIdV1,
    ceremony_context_digest: TenantRootProtocolDigestV1,
    current_epoch: TenantRootShareEpoch,
    next_epoch: TenantRootShareEpoch,
    expected_control_plane_revision: u64,
    active_root_commitment: [u8; 32],
    active_activation_receipt_digest: TenantRootLifecycleReceiptDigestV1,
    deriver_a_share_commitment: MpcPrfShareCommitmentWireV1,
    deriver_b_share_commitment: MpcPrfShareCommitmentWireV1,
}

impl TenantRootRefreshCommitmentCheckpointScopeV1 {
    /// Builds the exact public scope from a verified role refresh command.
    pub fn from_verified_command(
        command: &VerifiedTenantRootRoleRefreshCommandV1,
        active_binding: &TenantRootRefreshCommitmentCheckpointActiveBindingV1,
        context: &TenantRootCeremonyContextV1,
        expected_authority_id: TenantRootControlPlaneAuthorityIdV1,
    ) -> RouterAbDerivationResult<Self> {
        context.validate()?;
        let TenantRootCeremonyEpochsV1::Refresh { current, next } = context.epochs() else {
            return Err(malformed(
                "tenant-root refresh checkpoint requires a refresh ceremony context",
            ));
        };
        if command.authority_id() != expected_authority_id {
            return Err(replay_mismatch(
                "tenant-root refresh checkpoint command authority does not match its Durable Object",
            ));
        }
        if command.refresh_context_digest() != context.digest()?
            || command.identity_digest() != context.identity_digest()
            || command.custody_lineage() != context.custody_lineage()
            || command.current_epoch() != current
            || command.next_epoch() != next
            || command.session_id() != context.session_id()
            || command.nonce() != context.nonce()
        {
            return Err(replay_mismatch(
                "tenant-root refresh checkpoint command does not match its ceremony context",
            ));
        }
        if command.identity_digest() != active_binding.identity_digest()
            || command.custody_lineage() != active_binding.custody_lineage()
            || command.current_epoch() != active_binding.current_epoch()
            || command.expected_control_plane_revision()
                != active_binding.expected_control_plane_revision()
            || command.deriver_a_share_commitment() != active_binding.commitments().deriver_a()
            || command.deriver_b_share_commitment() != active_binding.commitments().deriver_b()
            || command.active_root_commitment() != active_binding.active_root_commitment()
            || command.active_activation_receipt_digest()
                != active_binding.active_activation_receipt_digest()
        {
            return Err(replay_mismatch(
                "tenant-root refresh checkpoint command does not match the authoritative active state",
            ));
        }
        Ok(Self {
            identity_digest: command.identity_digest(),
            custody_lineage: command.custody_lineage(),
            authority_id: command.authority_id(),
            ceremony_context_digest: command.refresh_context_digest(),
            current_epoch: current,
            next_epoch: next,
            expected_control_plane_revision: active_binding.expected_control_plane_revision(),
            active_root_commitment: *active_binding.active_root_commitment(),
            active_activation_receipt_digest: active_binding.active_activation_receipt_digest(),
            deriver_a_share_commitment: active_binding.commitments().deriver_a().clone(),
            deriver_b_share_commitment: active_binding.commitments().deriver_b().clone(),
        })
    }

    /// Returns the server-resolved tenant-root identity digest.
    pub const fn identity_digest(&self) -> TenantRootIdentityDigestV1 {
        self.identity_digest
    }

    /// Returns the deployment-local custody lineage.
    pub const fn custody_lineage(&self) -> TenantRootCustodyLineageId {
        self.custody_lineage
    }

    /// Returns the Durable Object authority bound by the issuer command.
    pub const fn authority_id(&self) -> TenantRootControlPlaneAuthorityIdV1 {
        self.authority_id
    }

    /// Returns the exact refresh ceremony context digest.
    pub const fn ceremony_context_digest(&self) -> TenantRootProtocolDigestV1 {
        self.ceremony_context_digest
    }

    /// Returns the active epoch selected by the command.
    pub const fn current_epoch(&self) -> TenantRootShareEpoch {
        self.current_epoch
    }

    /// Returns the exact pending epoch selected by the command.
    pub const fn next_epoch(&self) -> TenantRootShareEpoch {
        self.next_epoch
    }

    /// Returns the expected control-plane lifecycle revision.
    pub const fn expected_control_plane_revision(&self) -> u64 {
        self.expected_control_plane_revision
    }

    /// Returns the stable public root commitment for the active epoch.
    pub const fn active_root_commitment(&self) -> &[u8; 32] {
        &self.active_root_commitment
    }

    /// Returns the active control-plane activation receipt digest.
    pub const fn active_activation_receipt_digest(&self) -> TenantRootLifecycleReceiptDigestV1 {
        self.active_activation_receipt_digest
    }

    /// Returns Deriver A's active share commitment wire.
    pub const fn deriver_a_share_commitment(&self) -> &MpcPrfShareCommitmentWireV1 {
        &self.deriver_a_share_commitment
    }

    /// Returns Deriver B's active share commitment wire.
    pub const fn deriver_b_share_commitment(&self) -> &MpcPrfShareCommitmentWireV1 {
        &self.deriver_b_share_commitment
    }

    /// Returns the exact canonical public scope bytes.
    pub fn canonical_bytes(&self) -> RouterAbDerivationResult<Vec<u8>> {
        self.validate()?;
        let mut bytes = Vec::new();
        push_field(
            &mut bytes,
            TENANT_ROOT_REFRESH_COMMITMENT_CHECKPOINT_SCOPE_DOMAIN_V1,
        )?;
        push_field(&mut bytes, self.identity_digest.as_bytes())?;
        push_field(&mut bytes, self.custody_lineage.as_bytes())?;
        push_field(&mut bytes, self.authority_id.as_bytes())?;
        push_field(&mut bytes, self.ceremony_context_digest.as_bytes())?;
        push_field(&mut bytes, &self.current_epoch.get().get().to_be_bytes())?;
        push_field(&mut bytes, &self.next_epoch.get().get().to_be_bytes())?;
        push_field(
            &mut bytes,
            &self.expected_control_plane_revision.to_be_bytes(),
        )?;
        push_field(&mut bytes, &self.active_root_commitment)?;
        push_field(&mut bytes, self.active_activation_receipt_digest.as_bytes())?;
        push_field(&mut bytes, self.deriver_a_share_commitment.as_bytes())?;
        push_field(&mut bytes, self.deriver_b_share_commitment.as_bytes())?;
        Ok(bytes)
    }

    fn decode_canonical_bytes(bytes: &[u8]) -> RouterAbDerivationResult<Self> {
        let mut decoder = CheckpointWireDecoderV1::new(bytes)?;
        decoder.require_field(TENANT_ROOT_REFRESH_COMMITMENT_CHECKPOINT_SCOPE_DOMAIN_V1)?;
        let identity_digest = TenantRootIdentityDigestV1::from_bytes(
            decoder.fixed_field::<32>("tenant-root refresh checkpoint identity digest")?,
        );
        let custody_lineage = TenantRootCustodyLineageId::from_bytes(
            decoder.fixed_field::<16>("tenant-root refresh checkpoint custody lineage")?,
        )?;
        let authority_id = TenantRootControlPlaneAuthorityIdV1::from_bytes(
            decoder.fixed_field::<32>("tenant-root refresh checkpoint authority id")?,
        );
        let ceremony_context_digest = TenantRootProtocolDigestV1::from_bytes(
            decoder.fixed_field::<32>("tenant-root refresh checkpoint context digest")?,
        )?;
        let current_epoch = TenantRootShareEpoch::new(
            decoder.u64_field("tenant-root refresh checkpoint current epoch")?,
        )?;
        let next_epoch = TenantRootShareEpoch::new(
            decoder.u64_field("tenant-root refresh checkpoint next epoch")?,
        )?;
        let expected_control_plane_revision =
            decoder.u64_field("tenant-root refresh checkpoint expected control-plane revision")?;
        let active_root_commitment =
            decoder.fixed_field::<32>("tenant-root refresh checkpoint active root commitment")?;
        let active_activation_receipt_digest =
            TenantRootLifecycleReceiptDigestV1::from_bytes(decoder.fixed_field::<32>(
                "tenant-root refresh checkpoint active activation receipt digest",
            )?)?;
        let deriver_a_share_commitment = MpcPrfShareCommitmentWireV1::new(
            decoder
                .field("tenant-root refresh checkpoint Deriver A share commitment")?
                .to_vec(),
        )?;
        let deriver_b_share_commitment = MpcPrfShareCommitmentWireV1::new(
            decoder
                .field("tenant-root refresh checkpoint Deriver B share commitment")?
                .to_vec(),
        )?;
        decoder.finish()?;
        let scope = Self {
            identity_digest,
            custody_lineage,
            authority_id,
            ceremony_context_digest,
            current_epoch,
            next_epoch,
            expected_control_plane_revision,
            active_root_commitment,
            active_activation_receipt_digest,
            deriver_a_share_commitment,
            deriver_b_share_commitment,
        };
        scope.validate()?;
        if scope.canonical_bytes()? != bytes {
            return Err(malformed(
                "tenant-root refresh checkpoint scope wire is not canonical",
            ));
        }
        Ok(scope)
    }

    fn validate(&self) -> RouterAbDerivationResult<()> {
        if self.current_epoch.next()? != self.next_epoch {
            return Err(malformed(
                "tenant-root refresh checkpoint epochs must advance exactly one",
            ));
        }
        if self.expected_control_plane_revision == 0 {
            return Err(malformed(
                "tenant-root refresh checkpoint expected revision must be positive",
            ));
        }
        let commitments = TenantRootEpochCommitmentsV1::new(
            self.deriver_a_share_commitment.clone(),
            self.deriver_b_share_commitment.clone(),
        )?;
        if commitments.root_commitment() != &self.active_root_commitment {
            return Err(malformed(
                "tenant-root refresh checkpoint active root commitment does not match its shares",
            ));
        }
        Ok(())
    }
}

/// Public non-secret refresh checkpoint state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TenantRootRefreshCommitmentCheckpointStateV1 {
    /// Exactly one role's signed commitment has been accepted.
    OneRoleCommitted {
        /// Role whose commitment arrived first.
        role: TwoPartyDeriverRole,
        /// Digest of that role's exact verified issuer command.
        command_digest: TenantRootProtocolDigestV1,
        /// Exact canonical signed commitment wire bytes.
        signed_commitment: Vec<u8>,
    },
    /// Both exact role commitments have been accepted.
    BothRolesCommitted {
        /// Digest of Deriver A's exact verified issuer command.
        deriver_a_command_digest: TenantRootProtocolDigestV1,
        /// Digest of Deriver B's exact verified issuer command.
        deriver_b_command_digest: TenantRootProtocolDigestV1,
        /// Exact canonical Deriver A signed commitment wire bytes.
        deriver_a_signed_commitment: Vec<u8>,
        /// Exact canonical Deriver B signed commitment wire bytes.
        deriver_b_signed_commitment: Vec<u8>,
    },
}

impl TenantRootRefreshCommitmentCheckpointStateV1 {
    /// Returns the first role for a one-role state.
    pub const fn role(&self) -> Option<TwoPartyDeriverRole> {
        match self {
            Self::OneRoleCommitted { role, .. } => Some(*role),
            Self::BothRolesCommitted { .. } => None,
        }
    }

    /// Returns the exact first-role command digest for one-role state.
    pub const fn command_digest(&self) -> Option<TenantRootProtocolDigestV1> {
        match self {
            Self::OneRoleCommitted { command_digest, .. } => Some(*command_digest),
            Self::BothRolesCommitted { .. } => None,
        }
    }

    /// Returns the exact first-role commitment wire for one-role state.
    pub fn signed_commitment(&self) -> Option<&[u8]> {
        match self {
            Self::OneRoleCommitted {
                signed_commitment, ..
            } => Some(signed_commitment),
            Self::BothRolesCommitted { .. } => None,
        }
    }

    /// Returns Deriver A's exact commitment wire when both roles are present.
    pub fn deriver_a_signed_commitment(&self) -> Option<&[u8]> {
        match self {
            Self::OneRoleCommitted { .. } => None,
            Self::BothRolesCommitted {
                deriver_a_signed_commitment,
                ..
            } => Some(deriver_a_signed_commitment),
        }
    }

    /// Returns Deriver B's exact commitment wire when both roles are present.
    pub fn deriver_b_signed_commitment(&self) -> Option<&[u8]> {
        match self {
            Self::OneRoleCommitted { .. } => None,
            Self::BothRolesCommitted {
                deriver_b_signed_commitment,
                ..
            } => Some(deriver_b_signed_commitment),
        }
    }

    fn canonical_bytes(&self) -> RouterAbDerivationResult<Vec<u8>> {
        let mut bytes = Vec::new();
        match self {
            Self::OneRoleCommitted {
                role,
                command_digest,
                signed_commitment,
            } => {
                push_field(
                    &mut bytes,
                    TENANT_ROOT_REFRESH_COMMITMENT_CHECKPOINT_ONE_ROLE_TAG_V1,
                )?;
                push_role(&mut bytes, *role)?;
                push_field(&mut bytes, command_digest.as_bytes())?;
                push_commitment_wire(&mut bytes, signed_commitment)?;
            }
            Self::BothRolesCommitted {
                deriver_a_command_digest,
                deriver_b_command_digest,
                deriver_a_signed_commitment,
                deriver_b_signed_commitment,
            } => {
                push_field(
                    &mut bytes,
                    TENANT_ROOT_REFRESH_COMMITMENT_CHECKPOINT_BOTH_ROLES_TAG_V1,
                )?;
                push_field(&mut bytes, deriver_a_command_digest.as_bytes())?;
                push_field(&mut bytes, deriver_b_command_digest.as_bytes())?;
                push_commitment_wire(&mut bytes, deriver_a_signed_commitment)?;
                push_commitment_wire(&mut bytes, deriver_b_signed_commitment)?;
            }
        }
        Ok(bytes)
    }

    fn decode_canonical_bytes(
        decoder: &mut CheckpointWireDecoderV1<'_>,
    ) -> RouterAbDerivationResult<Self> {
        let tag = decoder.field("tenant-root refresh checkpoint state tag")?;
        let state = if tag == TENANT_ROOT_REFRESH_COMMITMENT_CHECKPOINT_ONE_ROLE_TAG_V1 {
            let role = decoder.role()?;
            let command_digest = TenantRootProtocolDigestV1::from_bytes(
                decoder.fixed_field::<32>("tenant-root refresh checkpoint command digest")?,
            )?;
            let signed_commitment = decoder
                .field("tenant-root refresh checkpoint signed commitment")?
                .to_vec();
            let signed =
                TenantRootSignedRefreshCommitmentV1::decode_canonical_bytes(&signed_commitment)?;
            if signed.role() != role {
                return Err(malformed(
                    "tenant-root refresh checkpoint one-role state role does not match its commitment",
                ));
            }
            Self::OneRoleCommitted {
                role,
                command_digest,
                signed_commitment,
            }
        } else if tag == TENANT_ROOT_REFRESH_COMMITMENT_CHECKPOINT_BOTH_ROLES_TAG_V1 {
            let deriver_a_command_digest = TenantRootProtocolDigestV1::from_bytes(
                decoder
                    .fixed_field::<32>("tenant-root refresh checkpoint Deriver A command digest")?,
            )?;
            let deriver_b_command_digest = TenantRootProtocolDigestV1::from_bytes(
                decoder
                    .fixed_field::<32>("tenant-root refresh checkpoint Deriver B command digest")?,
            )?;
            let deriver_a_signed_commitment = decoder
                .field("tenant-root refresh checkpoint Deriver A signed commitment")?
                .to_vec();
            let deriver_b_signed_commitment = decoder
                .field("tenant-root refresh checkpoint Deriver B signed commitment")?
                .to_vec();
            let deriver_a = TenantRootSignedRefreshCommitmentV1::decode_canonical_bytes(
                &deriver_a_signed_commitment,
            )?;
            let deriver_b = TenantRootSignedRefreshCommitmentV1::decode_canonical_bytes(
                &deriver_b_signed_commitment,
            )?;
            if deriver_a.role() != TwoPartyDeriverRole::DeriverA
                || deriver_b.role() != TwoPartyDeriverRole::DeriverB
            {
                return Err(malformed(
                    "tenant-root refresh checkpoint pair roles are invalid",
                ));
            }
            Self::BothRolesCommitted {
                deriver_a_command_digest,
                deriver_b_command_digest,
                deriver_a_signed_commitment,
                deriver_b_signed_commitment,
            }
        } else {
            return Err(malformed(
                "tenant-root refresh checkpoint state tag is invalid",
            ));
        };
        Ok(state)
    }
}

/// Canonical public checkpoint retained by the identity/lineage Durable Object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantRootRefreshCommitmentCheckpointV1 {
    scope: TenantRootRefreshCommitmentCheckpointScopeV1,
    state: TenantRootRefreshCommitmentCheckpointStateV1,
}

impl TenantRootRefreshCommitmentCheckpointV1 {
    /// Returns the exact public scope bound to this checkpoint.
    pub const fn scope(&self) -> &TenantRootRefreshCommitmentCheckpointScopeV1 {
        &self.scope
    }

    /// Returns the exact non-secret checkpoint state.
    pub const fn state(&self) -> &TenantRootRefreshCommitmentCheckpointStateV1 {
        &self.state
    }

    /// Encodes the exact canonical checkpoint wire.
    pub fn canonical_bytes(&self) -> RouterAbDerivationResult<Vec<u8>> {
        let scope = self.scope.canonical_bytes()?;
        let state = self.state.canonical_bytes()?;
        let mut bytes = Vec::new();
        push_field(
            &mut bytes,
            TENANT_ROOT_REFRESH_COMMITMENT_CHECKPOINT_DOMAIN_V1,
        )?;
        push_field(&mut bytes, &scope)?;
        push_field(&mut bytes, &state)?;
        if bytes.len() > TENANT_ROOT_REFRESH_COMMITMENT_CHECKPOINT_MAX_BYTES_V1 {
            return Err(malformed("tenant-root refresh checkpoint wire is too long"));
        }
        Ok(bytes)
    }

    /// Parses exactly one canonical public checkpoint wire.
    pub fn decode_canonical_bytes(bytes: &[u8]) -> RouterAbDerivationResult<Self> {
        if bytes.is_empty() || bytes.len() > TENANT_ROOT_REFRESH_COMMITMENT_CHECKPOINT_MAX_BYTES_V1
        {
            return Err(malformed(
                "tenant-root refresh checkpoint wire length is invalid",
            ));
        }
        let mut decoder = CheckpointWireDecoderV1::new(bytes)?;
        decoder.require_field(TENANT_ROOT_REFRESH_COMMITMENT_CHECKPOINT_DOMAIN_V1)?;
        let scope_bytes = decoder.field("tenant-root refresh checkpoint scope")?;
        let scope =
            TenantRootRefreshCommitmentCheckpointScopeV1::decode_canonical_bytes(scope_bytes)?;
        let state_bytes = decoder.field("tenant-root refresh checkpoint state")?;
        let mut state_decoder = CheckpointWireDecoderV1::new(state_bytes)?;
        let state = TenantRootRefreshCommitmentCheckpointStateV1::decode_canonical_bytes(
            &mut state_decoder,
        )?;
        state_decoder.finish()?;
        decoder.finish()?;
        let checkpoint = Self { scope, state };
        if checkpoint.canonical_bytes()? != bytes {
            return Err(malformed(
                "tenant-root refresh checkpoint wire is not canonical",
            ));
        }
        Ok(checkpoint)
    }

    fn new(
        scope: TenantRootRefreshCommitmentCheckpointScopeV1,
        state: TenantRootRefreshCommitmentCheckpointStateV1,
    ) -> RouterAbDerivationResult<Self> {
        scope.validate()?;
        validate_state_wires(&state)?;
        let checkpoint = Self { scope, state };
        checkpoint.canonical_bytes()?;
        Ok(checkpoint)
    }
}

/// Verifies one exact public refresh transition from accepted coefficients.
///
/// The installation evidence is checked as a complete A/B pair before its
/// commitments are compared with the next pair predicted from the active
/// commitments and the accepted coefficient commitments.
pub fn verify_tenant_root_refresh_installation_transition_v1(
    active_commitments: &TenantRootEpochCommitmentsV1,
    accepted_refresh_commitments: &VerifiedTenantRootRefreshCommitmentPairV1,
    deriver_a_installation: &VerifiedTenantRootSignedShareInstallationEvidenceWireV1,
    deriver_b_installation: &VerifiedTenantRootSignedShareInstallationEvidenceWireV1,
) -> RouterAbDerivationResult<TenantRootEpochCommitmentsV1> {
    let context = accepted_refresh_commitments.context();
    if !matches!(context.epochs(), TenantRootCeremonyEpochsV1::Refresh { .. }) {
        return Err(malformed(
            "tenant-root refresh installation transition requires a refresh context",
        ));
    }
    if deriver_a_installation.evidence().transcript().context() != context
        || deriver_b_installation.evidence().transcript().context() != context
    {
        return Err(replay_mismatch(
            "tenant-root refresh installation evidence does not match its accepted coefficients",
        ));
    }

    let current = active_commitments.threshold_pair()?;
    let expected_next = derive_two_party_root_share_refresh_commitments(
        &current,
        accepted_refresh_commitments
            .deriver_a()
            .transcript()
            .commitment(),
        accepted_refresh_commitments
            .deriver_b()
            .transcript()
            .commitment(),
    )
    .map_err(|_| {
        RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::OutputVerificationFailed,
            "tenant-root refresh next commitments could not be derived",
        )
    })?;
    let evidenced_next = verify_tenant_root_refresh_evidence_v1(
        &current,
        deriver_a_installation.evidence(),
        deriver_b_installation.evidence(),
    )?;
    if evidenced_next != expected_next {
        return Err(RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::OutputVerificationFailed,
            "tenant-root refresh installation commitments do not match the accepted transition",
        ));
    }
    TenantRootEpochCommitmentsV1::from_verified(expected_next)
}

/// Result of applying one verified refresh commitment to the checkpoint.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum TenantRootRefreshCommitmentCheckpointEvaluationV1 {
    /// The Durable Object must persist the returned checkpoint atomically.
    Commit {
        /// New canonical public checkpoint state.
        checkpoint: TenantRootRefreshCommitmentCheckpointV1,
        /// Public rendezvous result for the caller.
        outcome: TenantRootRefreshCommitmentCheckpointOutcomeV1,
    },
    /// The candidate exactly repeats an accepted public commitment.
    Replay(TenantRootRefreshCommitmentCheckpointOutcomeV1),
}

/// Public result of one refresh commitment checkpoint evaluation.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum TenantRootRefreshCommitmentCheckpointOutcomeV1 {
    /// One role is committed and the peer is still required.
    WaitingForPeer {
        /// Role whose commitment is retained.
        role: TwoPartyDeriverRole,
    },
    /// Both role commitments are accepted and ready for contribution sealing.
    BothRolesCommitted {
        /// Verified A/B commitment pair for the exact refresh context.
        pair: VerifiedTenantRootRefreshCommitmentPairV1,
    },
}

/// Evaluates one verified refresh commitment against the durable public checkpoint.
///
/// The first commitment and a new peer commitment require a fresh command. An
/// exact role, command-digest, and wire retry replays after expiry. Any changed
/// command or commitment conflicts with the accepted checkpoint. The only
/// retained values are public scope metadata, command digests, and signed
/// commitment wires.
#[allow(clippy::too_many_arguments)]
pub fn evaluate_tenant_root_refresh_commitment_checkpoint_v1(
    existing: Option<TenantRootRefreshCommitmentCheckpointV1>,
    candidate: VerifiedTenantRootRefreshCommitmentV1,
    command: &VerifiedTenantRootRoleRefreshCommandV1,
    active_binding: &TenantRootRefreshCommitmentCheckpointActiveBindingV1,
    context: &TenantRootCeremonyContextV1,
    expected_authority_id: TenantRootControlPlaneAuthorityIdV1,
    deriver_a_verifying_key_bytes: &[u8; 32],
    deriver_b_verifying_key_bytes: &[u8; 32],
    now_ms: u64,
) -> RouterAbDerivationResult<TenantRootRefreshCommitmentCheckpointEvaluationV1> {
    let expected_scope = TenantRootRefreshCommitmentCheckpointScopeV1::from_verified_command(
        command,
        active_binding,
        context,
        expected_authority_id,
    )?;
    let candidate = verify_candidate(
        candidate,
        context,
        deriver_a_verifying_key_bytes,
        deriver_b_verifying_key_bytes,
    )?;
    if candidate.role() != command.role() {
        return Err(replay_mismatch(
            "tenant-root refresh checkpoint commitment role does not match its command",
        ));
    }
    let candidate_role = candidate.role();
    let candidate_command_digest = command.digest();
    let candidate_bytes = candidate.canonical_bytes().to_vec();

    let Some(existing) = existing else {
        require_fresh_refresh_command(command, context, now_ms)?;
        let state = TenantRootRefreshCommitmentCheckpointStateV1::OneRoleCommitted {
            role: candidate_role,
            command_digest: candidate_command_digest,
            signed_commitment: candidate_bytes,
        };
        let checkpoint = TenantRootRefreshCommitmentCheckpointV1::new(expected_scope, state)?;
        return Ok(TenantRootRefreshCommitmentCheckpointEvaluationV1::Commit {
            checkpoint,
            outcome: TenantRootRefreshCommitmentCheckpointOutcomeV1::WaitingForPeer {
                role: candidate_role,
            },
        });
    };

    if existing.scope() != &expected_scope {
        return Err(replay_mismatch(
            "tenant-root refresh checkpoint scope does not match the verified command",
        ));
    }
    let existing_state = validate_existing_state(
        existing.state(),
        context,
        deriver_a_verifying_key_bytes,
        deriver_b_verifying_key_bytes,
    )?;
    match existing_state {
        ExistingCheckpointStateV1::OneRole {
            role,
            command_digest,
            commitment,
        } => {
            if role == candidate_role {
                if command_digest != candidate_command_digest
                    || commitment.canonical_bytes() != candidate_bytes
                {
                    return Err(replay_mismatch(
                        "tenant-root refresh checkpoint role retry does not match its accepted command and commitment",
                    ));
                }
                return Ok(TenantRootRefreshCommitmentCheckpointEvaluationV1::Replay(
                    TenantRootRefreshCommitmentCheckpointOutcomeV1::WaitingForPeer { role },
                ));
            }
            require_fresh_refresh_command(command, context, now_ms)?;
            let (deriver_a, deriver_b) = match candidate_role {
                TwoPartyDeriverRole::DeriverA => (candidate, commitment),
                TwoPartyDeriverRole::DeriverB => (commitment, candidate),
            };
            let pair = VerifiedTenantRootRefreshCommitmentPairV1::new(deriver_a, deriver_b)?;
            let state = both_roles_state(
                &pair,
                command_digest,
                candidate_role,
                candidate_command_digest,
            )?;
            let checkpoint = TenantRootRefreshCommitmentCheckpointV1::new(expected_scope, state)?;
            Ok(TenantRootRefreshCommitmentCheckpointEvaluationV1::Commit {
                checkpoint,
                outcome: TenantRootRefreshCommitmentCheckpointOutcomeV1::BothRolesCommitted {
                    pair,
                },
            })
        }
        ExistingCheckpointStateV1::BothRoles {
            deriver_a_command_digest,
            deriver_b_command_digest,
            pair,
        } => {
            let accepted_command_digest = match candidate_role {
                TwoPartyDeriverRole::DeriverA => deriver_a_command_digest,
                TwoPartyDeriverRole::DeriverB => deriver_b_command_digest,
            };
            let accepted_commitment = match candidate_role {
                TwoPartyDeriverRole::DeriverA => pair.deriver_a(),
                TwoPartyDeriverRole::DeriverB => pair.deriver_b(),
            };
            if accepted_command_digest != candidate_command_digest
                || accepted_commitment.canonical_bytes() != candidate_bytes
            {
                return Err(replay_mismatch(
                    "tenant-root refresh checkpoint pair retry does not match its accepted command and commitment",
                ));
            }
            Ok(TenantRootRefreshCommitmentCheckpointEvaluationV1::Replay(
                TenantRootRefreshCommitmentCheckpointOutcomeV1::BothRolesCommitted { pair },
            ))
        }
    }
}

#[allow(clippy::large_enum_variant)]
enum ExistingCheckpointStateV1 {
    OneRole {
        role: TwoPartyDeriverRole,
        command_digest: TenantRootProtocolDigestV1,
        commitment: VerifiedTenantRootRefreshCommitmentV1,
    },
    BothRoles {
        deriver_a_command_digest: TenantRootProtocolDigestV1,
        deriver_b_command_digest: TenantRootProtocolDigestV1,
        pair: VerifiedTenantRootRefreshCommitmentPairV1,
    },
}

fn verify_candidate(
    candidate: VerifiedTenantRootRefreshCommitmentV1,
    context: &TenantRootCeremonyContextV1,
    deriver_a_verifying_key_bytes: &[u8; 32],
    deriver_b_verifying_key_bytes: &[u8; 32],
) -> RouterAbDerivationResult<VerifiedTenantRootRefreshCommitmentV1> {
    let bytes = candidate.into_canonical_bytes();
    verify_commitment_wire(
        &bytes,
        context,
        deriver_a_verifying_key_bytes,
        deriver_b_verifying_key_bytes,
    )
}

fn require_fresh_refresh_command(
    command: &VerifiedTenantRootRoleRefreshCommandV1,
    context: &TenantRootCeremonyContextV1,
    now_ms: u64,
) -> RouterAbDerivationResult<()> {
    // The command window remains strict; context validation documents and
    // enforces the shared clock-skew policy at the freshness boundary.
    command.require_fresh(now_ms)?;
    context.validate_at(now_ms)
}

fn verify_commitment_wire(
    bytes: &[u8],
    context: &TenantRootCeremonyContextV1,
    deriver_a_verifying_key_bytes: &[u8; 32],
    deriver_b_verifying_key_bytes: &[u8; 32],
) -> RouterAbDerivationResult<VerifiedTenantRootRefreshCommitmentV1> {
    let signed = TenantRootSignedRefreshCommitmentV1::decode_canonical_bytes(bytes)?;
    let role = signed.role();
    let verifying_key_bytes = match role {
        TwoPartyDeriverRole::DeriverA => deriver_a_verifying_key_bytes,
        TwoPartyDeriverRole::DeriverB => deriver_b_verifying_key_bytes,
    };
    signed.verify_strict(
        context,
        role,
        context.signing_key_id(role),
        verifying_key_bytes,
    )
}

fn validate_existing_state(
    state: &TenantRootRefreshCommitmentCheckpointStateV1,
    context: &TenantRootCeremonyContextV1,
    deriver_a_verifying_key_bytes: &[u8; 32],
    deriver_b_verifying_key_bytes: &[u8; 32],
) -> RouterAbDerivationResult<ExistingCheckpointStateV1> {
    match state {
        TenantRootRefreshCommitmentCheckpointStateV1::OneRoleCommitted {
            role,
            command_digest,
            signed_commitment,
        } => {
            let commitment = verify_commitment_wire(
                signed_commitment,
                context,
                deriver_a_verifying_key_bytes,
                deriver_b_verifying_key_bytes,
            )?;
            if commitment.role() != *role {
                return Err(malformed(
                    "tenant-root refresh checkpoint stored role does not match its commitment",
                ));
            }
            Ok(ExistingCheckpointStateV1::OneRole {
                role: *role,
                command_digest: *command_digest,
                commitment,
            })
        }
        TenantRootRefreshCommitmentCheckpointStateV1::BothRolesCommitted {
            deriver_a_command_digest,
            deriver_b_command_digest,
            deriver_a_signed_commitment,
            deriver_b_signed_commitment,
        } => {
            let deriver_a = verify_commitment_wire(
                deriver_a_signed_commitment,
                context,
                deriver_a_verifying_key_bytes,
                deriver_b_verifying_key_bytes,
            )?;
            let deriver_b = verify_commitment_wire(
                deriver_b_signed_commitment,
                context,
                deriver_a_verifying_key_bytes,
                deriver_b_verifying_key_bytes,
            )?;
            let pair = VerifiedTenantRootRefreshCommitmentPairV1::new(deriver_a, deriver_b)?;
            Ok(ExistingCheckpointStateV1::BothRoles {
                deriver_a_command_digest: *deriver_a_command_digest,
                deriver_b_command_digest: *deriver_b_command_digest,
                pair,
            })
        }
    }
}

fn both_roles_state(
    pair: &VerifiedTenantRootRefreshCommitmentPairV1,
    existing_command_digest: TenantRootProtocolDigestV1,
    candidate_role: TwoPartyDeriverRole,
    candidate_command_digest: TenantRootProtocolDigestV1,
) -> RouterAbDerivationResult<TenantRootRefreshCommitmentCheckpointStateV1> {
    let (deriver_a_command_digest, deriver_b_command_digest) = match candidate_role {
        TwoPartyDeriverRole::DeriverA => (candidate_command_digest, existing_command_digest),
        TwoPartyDeriverRole::DeriverB => (existing_command_digest, candidate_command_digest),
    };
    Ok(
        TenantRootRefreshCommitmentCheckpointStateV1::BothRolesCommitted {
            deriver_a_command_digest,
            deriver_b_command_digest,
            deriver_a_signed_commitment: pair.deriver_a().canonical_bytes().to_vec(),
            deriver_b_signed_commitment: pair.deriver_b().canonical_bytes().to_vec(),
        },
    )
}

fn validate_state_wires(
    state: &TenantRootRefreshCommitmentCheckpointStateV1,
) -> RouterAbDerivationResult<()> {
    match state {
        TenantRootRefreshCommitmentCheckpointStateV1::OneRoleCommitted {
            role,
            signed_commitment,
            ..
        } => {
            let signed =
                TenantRootSignedRefreshCommitmentV1::decode_canonical_bytes(signed_commitment)?;
            if signed.role() != *role {
                return Err(malformed(
                    "tenant-root refresh checkpoint one-role commitment role is invalid",
                ));
            }
        }
        TenantRootRefreshCommitmentCheckpointStateV1::BothRolesCommitted {
            deriver_a_signed_commitment,
            deriver_b_signed_commitment,
            ..
        } => {
            let deriver_a = TenantRootSignedRefreshCommitmentV1::decode_canonical_bytes(
                deriver_a_signed_commitment,
            )?;
            let deriver_b = TenantRootSignedRefreshCommitmentV1::decode_canonical_bytes(
                deriver_b_signed_commitment,
            )?;
            if deriver_a.role() != TwoPartyDeriverRole::DeriverA
                || deriver_b.role() != TwoPartyDeriverRole::DeriverB
            {
                return Err(malformed(
                    "tenant-root refresh checkpoint pair commitment roles are invalid",
                ));
            }
        }
    }
    Ok(())
}

fn push_commitment_wire(bytes: &mut Vec<u8>, commitment: &[u8]) -> RouterAbDerivationResult<()> {
    let signed = TenantRootSignedRefreshCommitmentV1::decode_canonical_bytes(commitment)?;
    if signed.canonical_bytes()? != commitment {
        return Err(malformed(
            "tenant-root refresh checkpoint commitment wire is not canonical",
        ));
    }
    push_field(bytes, commitment)
}

fn push_role(bytes: &mut Vec<u8>, role: TwoPartyDeriverRole) -> RouterAbDerivationResult<()> {
    push_field(bytes, role.as_str().as_bytes())?;
    push_field(bytes, &role.share_id().get().get().to_be_bytes())
}

fn push_field(bytes: &mut Vec<u8>, value: &[u8]) -> RouterAbDerivationResult<()> {
    if value.is_empty() {
        return Err(RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::EmptyField,
            "tenant-root refresh checkpoint field is required",
        ));
    }
    let length = u32::try_from(value.len())
        .map_err(|_| malformed("tenant-root refresh checkpoint field is too long"))?;
    let new_len = bytes
        .len()
        .checked_add(4)
        .and_then(|length| length.checked_add(value.len()))
        .ok_or_else(|| malformed("tenant-root refresh checkpoint wire length overflows"))?;
    if new_len > TENANT_ROOT_REFRESH_COMMITMENT_CHECKPOINT_MAX_BYTES_V1 {
        return Err(malformed("tenant-root refresh checkpoint wire is too long"));
    }
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(value);
    Ok(())
}

fn malformed(message: impl Into<String>) -> RouterAbDerivationError {
    RouterAbDerivationError::new(RouterAbDerivationErrorCode::MalformedInput, message)
}

fn replay_mismatch(message: &'static str) -> RouterAbDerivationError {
    RouterAbDerivationError::new(RouterAbDerivationErrorCode::ReplayMismatch, message)
}

struct CheckpointWireDecoderV1<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> CheckpointWireDecoderV1<'a> {
    fn new(bytes: &'a [u8]) -> RouterAbDerivationResult<Self> {
        if bytes.is_empty() || bytes.len() > TENANT_ROOT_REFRESH_COMMITMENT_CHECKPOINT_MAX_BYTES_V1
        {
            return Err(malformed(
                "tenant-root refresh checkpoint nested wire length is invalid",
            ));
        }
        Ok(Self { bytes, offset: 0 })
    }

    fn field(&mut self, name: &'static str) -> RouterAbDerivationResult<&'a [u8]> {
        let length_end = self
            .offset
            .checked_add(4)
            .ok_or_else(|| malformed("tenant-root refresh checkpoint wire offset overflows"))?;
        let length_bytes = self
            .bytes
            .get(self.offset..length_end)
            .ok_or_else(|| malformed(format!("{name} length is truncated")))?;
        let length = u32::from_be_bytes(
            length_bytes
                .try_into()
                .expect("fixed four-byte refresh checkpoint field length"),
        ) as usize;
        let value_end = length_end
            .checked_add(length)
            .ok_or_else(|| malformed(format!("{name} length overflows")))?;
        let value = self
            .bytes
            .get(length_end..value_end)
            .ok_or_else(|| malformed(format!("{name} is truncated")))?;
        self.offset = value_end;
        if value.is_empty() {
            return Err(RouterAbDerivationError::new(
                RouterAbDerivationErrorCode::EmptyField,
                format!("{name} is required"),
            ));
        }
        Ok(value)
    }

    fn require_field(&mut self, expected: &[u8]) -> RouterAbDerivationResult<()> {
        if self.field("tenant-root refresh checkpoint domain")? != expected {
            return Err(malformed(
                "tenant-root refresh checkpoint domain is invalid",
            ));
        }
        Ok(())
    }

    fn fixed_field<const N: usize>(
        &mut self,
        name: &'static str,
    ) -> RouterAbDerivationResult<[u8; N]> {
        self.field(name)?
            .try_into()
            .map_err(|_| malformed("tenant-root refresh checkpoint fixed field length is invalid"))
    }

    fn u64_field(&mut self, name: &'static str) -> RouterAbDerivationResult<u64> {
        Ok(u64::from_be_bytes(self.fixed_field::<8>(name)?))
    }

    fn role(&mut self) -> RouterAbDerivationResult<TwoPartyDeriverRole> {
        let label = self.field("tenant-root refresh checkpoint role")?;
        let share_id = self.fixed_field::<2>("tenant-root refresh checkpoint role share id")?;
        match (label, u16::from_be_bytes(share_id)) {
            (b"deriver_a", 1) => Ok(TwoPartyDeriverRole::DeriverA),
            (b"deriver_b", 2) => Ok(TwoPartyDeriverRole::DeriverB),
            _ => Err(malformed(
                "tenant-root refresh checkpoint role encoding is invalid",
            )),
        }
    }

    fn finish(self) -> RouterAbDerivationResult<()> {
        if self.offset != self.bytes.len() {
            return Err(malformed(
                "tenant-root refresh checkpoint wire has trailing bytes",
            ));
        }
        Ok(())
    }
}
