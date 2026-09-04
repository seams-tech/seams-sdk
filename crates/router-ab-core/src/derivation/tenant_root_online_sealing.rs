use core::fmt;

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use threshold_prf::{SigningRootShareCommitment, SigningRootShareWire, TwoPartyDeriverRole};

use super::{
    require_tenant_root_identifier, validate_tenant_root_active_role_share_commitment_v1,
    MpcPrfShareCommitmentWireV1, RouterAbDerivationError, RouterAbDerivationErrorCode,
    RouterAbDerivationResult, TenantRootCeremonyEpochsV1, TenantRootCustodyLineageId,
    TenantRootIdentityDigestV1, TenantRootLifecycleReceiptDigestV1, TenantRootShareEpoch,
    VerifiedTenantRootSignedShareInstallationEvidenceWireV1,
};

const TENANT_ROOT_ONLINE_ROLE_SHARE_BINDING_DOMAIN_V1: &[u8] =
    b"seams/tenant-root-online-role-share-binding/v1";
const TENANT_ROOT_ONLINE_ROLE_SHARE_MAX_CIPHERTEXT_BYTES_V1: usize = 64 * 1024;

/// Public coordinates authenticated by one online role-share provider call.
///
/// Construction requires the exact verified installation evidence that produced
/// the role share. The evidence supplies the role, epoch, commitment, and digest;
/// caller-supplied identity and lineage are checked against its ceremony context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantRootOnlineRoleShareBindingV1 {
    identity_digest: TenantRootIdentityDigestV1,
    custody_lineage: TenantRootCustodyLineageId,
    role: TwoPartyDeriverRole,
    epoch: TenantRootShareEpoch,
    share_commitment: MpcPrfShareCommitmentWireV1,
    epoch_wrapping_key_ref: String,
    installation_evidence_digest: TenantRootLifecycleReceiptDigestV1,
}

impl TenantRootOnlineRoleShareBindingV1 {
    /// Creates one exact online binding from the verified installation evidence.
    pub fn new(
        identity_digest: TenantRootIdentityDigestV1,
        custody_lineage: TenantRootCustodyLineageId,
        role: TwoPartyDeriverRole,
        epoch: TenantRootShareEpoch,
        share_commitment: MpcPrfShareCommitmentWireV1,
        epoch_wrapping_key_ref: impl Into<String>,
        evidence: &VerifiedTenantRootSignedShareInstallationEvidenceWireV1,
    ) -> RouterAbDerivationResult<Self> {
        let transcript = evidence.evidence().transcript();
        let context = transcript.context();
        let evidence_epoch = installation_epoch(context.epochs());
        let evidence_commitment =
            MpcPrfShareCommitmentWireV1::new(transcript.commitment().to_bytes().to_vec())?;
        let installation_evidence_digest = evidence.lifecycle_receipt_digest()?;
        let epoch_wrapping_key_ref = epoch_wrapping_key_ref.into();

        if is_zero_digest(identity_digest.as_bytes()) {
            return Err(malformed(
                "tenant-root online share identity digest must be non-zero",
            ));
        }
        if context.identity_digest() != identity_digest
            || context.custody_lineage() != custody_lineage
        {
            return Err(malformed(
                "tenant-root online share binding does not match installation evidence identity",
            ));
        }
        if role != transcript.role() {
            return Err(malformed(
                "tenant-root online share binding role does not match installation evidence",
            ));
        }
        if epoch != evidence_epoch {
            return Err(malformed(
                "tenant-root online share binding epoch does not match installation evidence",
            ));
        }
        if share_commitment != evidence_commitment {
            return Err(malformed(
                "tenant-root online share binding commitment does not match installation evidence",
            ));
        }
        require_tenant_root_identifier(
            "tenant-root online share epoch wrapping-key reference",
            &epoch_wrapping_key_ref,
        )?;

        Self::from_persisted(
            identity_digest,
            custody_lineage,
            role,
            epoch,
            share_commitment,
            epoch_wrapping_key_ref,
            installation_evidence_digest,
        )
    }

    /// Reconstructs one binding from its fully validated persisted coordinates.
    ///
    /// Installation evidence is retained as its authenticated digest in the
    /// active role record. The provider ciphertext remains outside this type.
    pub fn from_persisted(
        identity_digest: TenantRootIdentityDigestV1,
        custody_lineage: TenantRootCustodyLineageId,
        role: TwoPartyDeriverRole,
        epoch: TenantRootShareEpoch,
        share_commitment: MpcPrfShareCommitmentWireV1,
        epoch_wrapping_key_ref: impl Into<String>,
        installation_evidence_digest: TenantRootLifecycleReceiptDigestV1,
    ) -> RouterAbDerivationResult<Self> {
        let binding = Self {
            identity_digest,
            custody_lineage,
            role,
            epoch,
            share_commitment,
            epoch_wrapping_key_ref: epoch_wrapping_key_ref.into(),
            installation_evidence_digest,
        };
        binding.validate()?;
        Ok(binding)
    }

    /// Returns the exact provider authenticated-data bytes.
    pub fn canonical_bytes(&self) -> RouterAbDerivationResult<Vec<u8>> {
        self.validate()?;
        let mut bytes = Vec::new();
        push_len32(&mut bytes, TENANT_ROOT_ONLINE_ROLE_SHARE_BINDING_DOMAIN_V1)?;
        push_len32(&mut bytes, self.identity_digest.as_bytes())?;
        push_len32(&mut bytes, self.custody_lineage.as_bytes())?;
        push_role(&mut bytes, self.role)?;
        push_len32(&mut bytes, &self.epoch.get().get().to_be_bytes())?;
        push_len32(&mut bytes, self.share_commitment.as_bytes())?;
        push_len32(&mut bytes, self.installation_evidence_digest.as_bytes())?;
        push_len32(&mut bytes, self.epoch_wrapping_key_ref.as_bytes())?;
        Ok(bytes)
    }

    /// Returns a public digest of the exact provider authenticated data.
    pub fn digest(&self) -> RouterAbDerivationResult<TenantRootOnlineRoleShareBindingDigestV1> {
        Ok(TenantRootOnlineRoleShareBindingDigestV1(
            Sha256::digest(self.canonical_bytes()?).into(),
        ))
    }

    /// Returns the server-resolved logical tenant-root identity digest.
    pub const fn identity_digest(&self) -> TenantRootIdentityDigestV1 {
        self.identity_digest
    }

    /// Returns the deployment-local custody lineage.
    pub const fn custody_lineage(&self) -> TenantRootCustodyLineageId {
        self.custody_lineage
    }

    /// Returns the exact Deriver role owning this share.
    pub const fn role(&self) -> TwoPartyDeriverRole {
        self.role
    }

    /// Returns the exact custody epoch owning this share.
    pub const fn epoch(&self) -> TenantRootShareEpoch {
        self.epoch
    }

    /// Returns the public commitment to this role's share.
    pub const fn share_commitment(&self) -> &MpcPrfShareCommitmentWireV1 {
        &self.share_commitment
    }

    /// Returns the opaque provider key-version reference for this epoch.
    pub fn epoch_wrapping_key_ref(&self) -> &str {
        &self.epoch_wrapping_key_ref
    }

    /// Returns the digest of the exact verified installation-evidence wire.
    pub const fn installation_evidence_digest(&self) -> TenantRootLifecycleReceiptDigestV1 {
        self.installation_evidence_digest
    }

    fn validate(&self) -> RouterAbDerivationResult<()> {
        if is_zero_digest(self.identity_digest.as_bytes()) {
            return Err(malformed(
                "tenant-root online share identity digest must be non-zero",
            ));
        }
        require_tenant_root_identifier(
            "tenant-root online share epoch wrapping-key reference",
            &self.epoch_wrapping_key_ref,
        )?;
        validate_tenant_root_active_role_share_commitment_v1(
            managed_restore_role(self.role),
            &self.share_commitment,
        )
    }
}

/// Public SHA-256 digest of online role-share provider authenticated data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TenantRootOnlineRoleShareBindingDigestV1([u8; 32]);

impl TenantRootOnlineRoleShareBindingDigestV1 {
    /// Returns the exact digest bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// One linear provider request holding a zeroizing signing-root share wire.
///
/// The request is intentionally non-cloneable. Calling `complete` consumes it,
/// so the share is dropped and zeroized immediately after provider sealing.
pub struct TenantRootOnlineRoleShareSealRequestV1 {
    binding: TenantRootOnlineRoleShareBindingV1,
    share_wire: SigningRootShareWire,
}

impl TenantRootOnlineRoleShareSealRequestV1 {
    /// Creates a request after checking the share role and commitment.
    pub fn new(
        binding: TenantRootOnlineRoleShareBindingV1,
        share_wire: SigningRootShareWire,
    ) -> RouterAbDerivationResult<Self> {
        verify_share_matches_binding(&binding, &share_wire)?;
        Ok(Self {
            binding,
            share_wire,
        })
    }

    /// Returns the exact provider authenticated-data bytes.
    pub fn aad(&self) -> RouterAbDerivationResult<Vec<u8>> {
        self.binding.canonical_bytes()
    }

    /// Returns the zeroizing share wire for one local provider call.
    pub fn share_wire(&self) -> &SigningRootShareWire {
        &self.share_wire
    }

    /// Returns the validated public binding.
    pub const fn binding(&self) -> &TenantRootOnlineRoleShareBindingV1 {
        &self.binding
    }

    /// Completes the request with provider ciphertext while preserving its exact binding.
    ///
    /// This method performs no encryption and interprets no provider-specific
    /// bytes. D1 or another store may add its own outer encryption afterward.
    pub fn complete(
        self,
        ciphertext: Vec<u8>,
    ) -> RouterAbDerivationResult<TenantRootSealedOnlineRoleShareV1> {
        let Self {
            binding,
            share_wire,
        } = self;
        let sealed = TenantRootSealedOnlineRoleShareV1::from_provider(binding, ciphertext)?;
        drop(share_wire);
        Ok(sealed)
    }
}

impl fmt::Debug for TenantRootOnlineRoleShareSealRequestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TenantRootOnlineRoleShareSealRequestV1")
            .field("binding", &self.binding)
            .field("share_wire", &"[redacted]")
            .finish()
    }
}

/// Opaque ciphertext returned by one online role-share provider.
///
/// The core retains the exact provider bytes and their digest. It never opens,
/// interprets, or persists those bytes as a D1 record.
#[derive(Clone, PartialEq, Eq)]
pub struct TenantRootSealedOnlineRoleShareV1 {
    binding: TenantRootOnlineRoleShareBindingV1,
    ciphertext: Vec<u8>,
    ciphertext_digest: [u8; 32],
}

impl TenantRootSealedOnlineRoleShareV1 {
    /// Returns the provider binding authenticated during sealing.
    pub const fn binding(&self) -> &TenantRootOnlineRoleShareBindingV1 {
        &self.binding
    }

    /// Returns the exact provider authenticated-data bytes.
    pub fn aad(&self) -> RouterAbDerivationResult<Vec<u8>> {
        self.binding.canonical_bytes()
    }

    /// Returns the provider ciphertext without interpreting its format.
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// Returns the public digest of the exact provider ciphertext.
    pub const fn ciphertext_digest(&self) -> &[u8; 32] {
        &self.ciphertext_digest
    }

    fn from_provider(
        binding: TenantRootOnlineRoleShareBindingV1,
        ciphertext: Vec<u8>,
    ) -> RouterAbDerivationResult<Self> {
        binding.validate()?;
        require_ciphertext(&ciphertext)?;
        Ok(Self {
            binding,
            ciphertext_digest: Sha256::digest(&ciphertext).into(),
            ciphertext,
        })
    }

    /// Reconstructs one opaque provider artifact from persisted binding fields.
    ///
    /// The caller validates any persistence envelope and its ciphertext digest
    /// before supplying these exact bytes. This boundary only validates the
    /// binding and ciphertext length, then recomputes the core digest.
    pub fn from_persisted(
        binding: TenantRootOnlineRoleShareBindingV1,
        ciphertext: Vec<u8>,
    ) -> RouterAbDerivationResult<Self> {
        Self::from_provider(binding, ciphertext)
    }

    /// Accepts provider plaintext only when it reproduces the bound role share.
    pub fn verify_opened_share(
        self,
        opened_share: SigningRootShareWire,
    ) -> RouterAbDerivationResult<VerifiedTenantRootOnlineRoleShareV1> {
        let Self { binding, .. } = self;
        verify_share_matches_binding(&binding, &opened_share)?;
        Ok(VerifiedTenantRootOnlineRoleShareV1 {
            binding,
            share_wire: opened_share,
        })
    }
}

impl fmt::Debug for TenantRootSealedOnlineRoleShareV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TenantRootSealedOnlineRoleShareV1")
            .field("binding", &self.binding)
            .field("ciphertext", &"[redacted]")
            .field("ciphertext_digest", &hex::encode(self.ciphertext_digest))
            .finish()
    }
}

/// Role-local share opened by a provider and verified against one exact online binding.
///
/// The token is deliberately non-cloneable. Consuming it yields the binding and
/// zeroizing share wire for one role-attempt boundary.
pub struct VerifiedTenantRootOnlineRoleShareV1 {
    binding: TenantRootOnlineRoleShareBindingV1,
    share_wire: SigningRootShareWire,
}

impl fmt::Debug for VerifiedTenantRootOnlineRoleShareV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedTenantRootOnlineRoleShareV1")
            .field("binding", &self.binding)
            .field("share_wire", &"[redacted]")
            .finish()
    }
}

impl VerifiedTenantRootOnlineRoleShareV1 {
    /// Returns the exact binding authenticated during online sealing.
    pub const fn binding(&self) -> &TenantRootOnlineRoleShareBindingV1 {
        &self.binding
    }

    /// Returns the exact provider authenticated-data bytes retained by the token.
    pub fn aad(&self) -> RouterAbDerivationResult<Vec<u8>> {
        self.binding.canonical_bytes()
    }

    /// Returns the exact role owning the opened share.
    pub const fn role(&self) -> TwoPartyDeriverRole {
        self.binding.role()
    }

    /// Returns the exact tenant-root identity digest bound to the opened share.
    pub const fn identity_digest(&self) -> TenantRootIdentityDigestV1 {
        self.binding.identity_digest()
    }

    /// Returns the exact custody lineage bound to the opened share.
    pub const fn custody_lineage(&self) -> TenantRootCustodyLineageId {
        self.binding.custody_lineage()
    }

    /// Returns the exact custody epoch bound to the opened share.
    pub const fn epoch(&self) -> TenantRootShareEpoch {
        self.binding.epoch()
    }

    /// Returns the exact public commitment reproduced by the opened share.
    pub const fn share_commitment(&self) -> &MpcPrfShareCommitmentWireV1 {
        self.binding.share_commitment()
    }

    /// Consumes the token into the exact binding and zeroizing share wire.
    pub fn into_parts(self) -> (TenantRootOnlineRoleShareBindingV1, SigningRootShareWire) {
        (self.binding, self.share_wire)
    }
}

fn verify_share_matches_binding(
    binding: &TenantRootOnlineRoleShareBindingV1,
    share_wire: &SigningRootShareWire,
) -> RouterAbDerivationResult<()> {
    binding.validate()?;
    let share = share_wire
        .to_share()
        .map_err(|_| malformed("tenant-root online role share wire is invalid"))?;
    if TwoPartyDeriverRole::from_share_id(share.id())
        .map_err(|_| malformed("tenant-root online role share id is invalid"))?
        != binding.role
    {
        return Err(verification_failed(
            "tenant-root online role share does not match its binding role",
        ));
    }
    let commitment = SigningRootShareCommitment::from_share(&share);
    if !bool::from(
        commitment
            .to_bytes()
            .as_ref()
            .ct_eq(binding.share_commitment.as_bytes()),
    ) {
        return Err(verification_failed(
            "tenant-root online role share does not match its binding commitment",
        ));
    }
    Ok(())
}

fn installation_epoch(epochs: TenantRootCeremonyEpochsV1) -> TenantRootShareEpoch {
    match epochs {
        TenantRootCeremonyEpochsV1::Create { next }
        | TenantRootCeremonyEpochsV1::Refresh { next, .. } => next,
    }
}

const fn managed_restore_role(role: TwoPartyDeriverRole) -> super::TenantRootManagedRestoreRoleV1 {
    match role {
        TwoPartyDeriverRole::DeriverA => super::TenantRootManagedRestoreRoleV1::DeriverA,
        TwoPartyDeriverRole::DeriverB => super::TenantRootManagedRestoreRoleV1::DeriverB,
    }
}

fn push_role(bytes: &mut Vec<u8>, role: TwoPartyDeriverRole) -> RouterAbDerivationResult<()> {
    push_len32(bytes, role.as_str().as_bytes())?;
    push_len32(bytes, &role.share_id().get().get().to_be_bytes())
}

fn push_len32(bytes: &mut Vec<u8>, value: &[u8]) -> RouterAbDerivationResult<()> {
    let length = u32::try_from(value.len())
        .map_err(|_| malformed("tenant-root online role share binding field is too long"))?;
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(value);
    Ok(())
}

fn require_ciphertext(ciphertext: &[u8]) -> RouterAbDerivationResult<()> {
    if ciphertext.is_empty()
        || ciphertext.len() > TENANT_ROOT_ONLINE_ROLE_SHARE_MAX_CIPHERTEXT_BYTES_V1
    {
        return Err(malformed(
            "tenant-root online role share ciphertext has an invalid length",
        ));
    }
    Ok(())
}

fn is_zero_digest(digest: &[u8; 32]) -> bool {
    digest.iter().all(|byte| *byte == 0)
}

fn malformed(message: impl Into<String>) -> RouterAbDerivationError {
    RouterAbDerivationError::new(RouterAbDerivationErrorCode::MalformedInput, message)
}

fn verification_failed(message: impl Into<String>) -> RouterAbDerivationError {
    RouterAbDerivationError::new(
        RouterAbDerivationErrorCode::OutputVerificationFailed,
        message,
    )
}
