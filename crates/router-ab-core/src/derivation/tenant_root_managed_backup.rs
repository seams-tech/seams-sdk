use core::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use threshold_prf::{SigningRootShareCommitment, SigningRootShareWire, TwoPartyDeriverRole};

use super::tenant_root_protocol::TenantRootWireDecoderV1;
use super::{
    require_tenant_root_identifier, MpcPrfShareCommitmentWireV1, MpcPrfSigningRootShareWireV1,
    RouterAbDerivationError, RouterAbDerivationErrorCode, RouterAbDerivationResult,
    TenantRootCeremonyEpochsV1, TenantRootCustodyLineageId, TenantRootIdentityDigestV1,
    TenantRootLifecycleReceiptDigestV1, TenantRootManagedRestoreRoleV1, TenantRootShareEpoch,
    VerifiedTenantRootSignedShareInstallationEvidenceWireV1,
};

const MANAGED_BACKUP_BINDING_DOMAIN_V1: &[u8] = b"tenant_root_managed_backup_binding_v1";
const MANAGED_BACKUP_ARTIFACT_DOMAIN_V1: &[u8] = b"tenant_root_signed_managed_backup_v1";
const MANAGED_BACKUP_RECEIPT_DOMAIN_V1: &[u8] = b"tenant_root_managed_backup_receipt_v1";
const MANAGED_BACKUP_MAX_CIPHERTEXT_BYTES: usize = 64 * 1024;
const MANAGED_BACKUP_MAX_WIRE_BYTES: usize = MANAGED_BACKUP_MAX_CIPHERTEXT_BYTES + 8 * 1024;

/// Exact public AAD for one role-local current-epoch managed backup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantRootManagedBackupBindingV1 {
    identity_digest: TenantRootIdentityDigestV1,
    custody_lineage: TenantRootCustodyLineageId,
    role: TenantRootManagedRestoreRoleV1,
    epoch: TenantRootShareEpoch,
    share_commitment: MpcPrfShareCommitmentWireV1,
    installation_receipt_digest: TenantRootLifecycleReceiptDigestV1,
    backup_provider_id: String,
    backup_key_version: String,
    role_signing_key_id: String,
    created_at_ms: u64,
}

impl TenantRootManagedBackupBindingV1 {
    /// Creates the provider AAD from exact verified share-installation evidence.
    pub fn from_verified_installation_evidence(
        evidence: &VerifiedTenantRootSignedShareInstallationEvidenceWireV1,
        backup_provider_id: impl Into<String>,
        backup_key_version: impl Into<String>,
        role_signing_key_id: impl Into<String>,
        created_at_ms: u64,
    ) -> RouterAbDerivationResult<Self> {
        let transcript = evidence.evidence().transcript();
        let context = transcript.context();
        let binding = Self {
            identity_digest: context.identity_digest(),
            custody_lineage: context.custody_lineage(),
            role: managed_restore_role(transcript.role()),
            epoch: installation_epoch(context.epochs()),
            share_commitment: MpcPrfShareCommitmentWireV1::new(
                transcript.commitment().to_bytes().to_vec(),
            )?,
            installation_receipt_digest: evidence.lifecycle_receipt_digest()?,
            backup_provider_id: backup_provider_id.into(),
            backup_key_version: backup_key_version.into(),
            role_signing_key_id: role_signing_key_id.into(),
            created_at_ms,
        };
        binding.validate()?;
        Ok(binding)
    }

    /// Returns the exact bytes an external role provider must authenticate as AAD.
    pub fn canonical_bytes(&self) -> RouterAbDerivationResult<Vec<u8>> {
        self.validate()?;
        let mut bytes = Vec::new();
        push_len32(&mut bytes, MANAGED_BACKUP_BINDING_DOMAIN_V1)?;
        push_len32(&mut bytes, self.identity_digest.as_bytes())?;
        push_len32(&mut bytes, self.custody_lineage.as_bytes())?;
        push_role(&mut bytes, self.role)?;
        push_len32(&mut bytes, &self.epoch.get().get().to_be_bytes())?;
        push_len32(&mut bytes, self.share_commitment.as_bytes())?;
        push_len32(&mut bytes, self.installation_receipt_digest.as_bytes())?;
        push_len32(&mut bytes, self.backup_provider_id.as_bytes())?;
        push_len32(&mut bytes, self.backup_key_version.as_bytes())?;
        push_len32(&mut bytes, self.role_signing_key_id.as_bytes())?;
        push_len32(&mut bytes, &self.created_at_ms.to_be_bytes())?;
        Ok(bytes)
    }

    /// Returns a public digest of the exact provider AAD.
    pub fn digest(&self) -> RouterAbDerivationResult<TenantRootManagedBackupBindingDigestV1> {
        Ok(TenantRootManagedBackupBindingDigestV1(
            Sha256::digest(self.canonical_bytes()?).into(),
        ))
    }

    /// Returns the owning role.
    pub const fn role(&self) -> TenantRootManagedRestoreRoleV1 {
        self.role
    }

    /// Returns the exact logical tenant-root identity digest.
    pub const fn identity_digest(&self) -> TenantRootIdentityDigestV1 {
        self.identity_digest
    }

    /// Returns the exact custody lineage.
    pub const fn custody_lineage(&self) -> TenantRootCustodyLineageId {
        self.custody_lineage
    }

    /// Returns the exact custody epoch.
    pub const fn epoch(&self) -> TenantRootShareEpoch {
        self.epoch
    }

    /// Returns the role-local public share commitment.
    pub const fn share_commitment(&self) -> &MpcPrfShareCommitmentWireV1 {
        &self.share_commitment
    }

    /// Returns the provider identity authenticated by the backup binding.
    pub fn backup_provider_id(&self) -> &str {
        &self.backup_provider_id
    }

    /// Returns the role-local backup key version.
    pub fn backup_key_version(&self) -> &str {
        &self.backup_key_version
    }

    /// Returns the role signing-key identifier used for the backup receipt.
    pub fn role_signing_key_id(&self) -> &str {
        &self.role_signing_key_id
    }

    /// Returns the provider binding creation time.
    pub const fn created_at_ms(&self) -> u64 {
        self.created_at_ms
    }

    /// Returns the exact verified installation-evidence receipt digest.
    pub const fn installation_receipt_digest(&self) -> TenantRootLifecycleReceiptDigestV1 {
        self.installation_receipt_digest
    }

    fn validate(&self) -> RouterAbDerivationResult<()> {
        require_tenant_root_identifier(
            "tenant-root managed-backup provider id",
            &self.backup_provider_id,
        )?;
        require_tenant_root_identifier(
            "tenant-root managed-backup key version",
            &self.backup_key_version,
        )?;
        require_tenant_root_identifier(
            "tenant-root managed-backup role signing key id",
            &self.role_signing_key_id,
        )?;
        if self.created_at_ms == 0 {
            return Err(malformed(
                "tenant-root managed-backup creation timestamp must be positive",
            ));
        }
        let share_id = u16::from_be_bytes([
            self.share_commitment.as_bytes()[0],
            self.share_commitment.as_bytes()[1],
        ]);
        if share_id != role_share_id(self.role) {
            return Err(malformed(
                "tenant-root managed-backup commitment does not match its role",
            ));
        }
        Ok(())
    }
}

/// Public SHA-256 digest of managed-backup provider AAD.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TenantRootManagedBackupBindingDigestV1([u8; 32]);

impl TenantRootManagedBackupBindingDigestV1 {
    /// Returns the exact digest bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Provider sealing input whose share is already verified against the public binding.
pub struct TenantRootManagedBackupSealRequestV1 {
    binding: TenantRootManagedBackupBindingV1,
    share: MpcPrfSigningRootShareWireV1,
}

impl TenantRootManagedBackupSealRequestV1 {
    /// Creates an exact role-local seal request after checking the share commitment.
    pub fn new(
        binding: TenantRootManagedBackupBindingV1,
        share: MpcPrfSigningRootShareWireV1,
    ) -> RouterAbDerivationResult<Self> {
        verify_share_matches_binding(&binding, &share)?;
        Ok(Self { binding, share })
    }

    /// Returns the exact public AAD for the provider encryption call.
    pub fn aad(&self) -> RouterAbDerivationResult<Vec<u8>> {
        self.binding.canonical_bytes()
    }

    /// Returns the secret share bytes only to the role-local provider adapter.
    pub fn plaintext_share(&self) -> &[u8] {
        self.share.as_bytes()
    }

    /// Returns the validated public backup binding.
    pub const fn binding(&self) -> &TenantRootManagedBackupBindingV1 {
        &self.binding
    }
}

impl fmt::Debug for TenantRootManagedBackupSealRequestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TenantRootManagedBackupSealRequestV1")
            .field("binding", &self.binding)
            .field("share", &"[redacted]")
            .finish()
    }
}

/// Opaque provider ciphertext plus the owning role's signature over its exact digest.
#[derive(Clone, PartialEq, Eq)]
pub struct TenantRootSignedManagedBackupV1 {
    binding: TenantRootManagedBackupBindingV1,
    ciphertext: Vec<u8>,
    ciphertext_digest: [u8; 32],
    signature: [u8; 64],
}

impl TenantRootSignedManagedBackupV1 {
    /// Signs the provider ciphertext after the provider seals the validated request.
    pub fn sign(
        request: TenantRootManagedBackupSealRequestV1,
        ciphertext: Vec<u8>,
        role_signing_key_bytes: &[u8; 32],
    ) -> RouterAbDerivationResult<Self> {
        require_ciphertext(&ciphertext)?;
        let ciphertext_digest = Sha256::digest(&ciphertext).into();
        let signature = SigningKey::from_bytes(role_signing_key_bytes)
            .sign(&receipt_signature_input(
                &request.binding,
                &ciphertext_digest,
            )?)
            .to_bytes();
        let artifact = Self {
            binding: request.binding,
            ciphertext,
            ciphertext_digest,
            signature,
        };
        artifact.canonical_bytes()?;
        Ok(artifact)
    }

    /// Decodes exactly one canonical signed managed-backup artifact.
    pub fn decode_canonical_bytes(bytes: &[u8]) -> RouterAbDerivationResult<Self> {
        if bytes.is_empty() || bytes.len() > MANAGED_BACKUP_MAX_WIRE_BYTES {
            return Err(malformed(
                "tenant-root signed managed-backup wire length is invalid",
            ));
        }
        let mut decoder = TenantRootWireDecoderV1::new(bytes);
        decoder.require_field(MANAGED_BACKUP_ARTIFACT_DOMAIN_V1)?;
        let binding =
            decode_binding_canonical_bytes(decoder.field("tenant-root managed-backup binding")?)?;
        let ciphertext = decoder
            .field("tenant-root managed-backup ciphertext")?
            .to_vec();
        let ciphertext_digest =
            decoder.fixed_field::<32>("tenant-root managed-backup ciphertext digest")?;
        let signature = decoder.fixed_field::<64>("tenant-root managed-backup signature")?;
        decoder.finish()?;
        let artifact = Self {
            binding,
            ciphertext,
            ciphertext_digest,
            signature,
        };
        artifact.validate()?;
        if artifact.canonical_bytes()? != bytes {
            return Err(malformed(
                "tenant-root signed managed-backup wire is not canonical",
            ));
        }
        Ok(artifact)
    }

    /// Returns the exact public binding authenticated by this signed artifact.
    pub const fn binding(&self) -> &TenantRootManagedBackupBindingV1 {
        &self.binding
    }

    /// Decodes and verifies one canonical signed managed-backup artifact.
    pub fn decode_and_verify_canonical_bytes(
        bytes: &[u8],
        expected_binding: &TenantRootManagedBackupBindingV1,
        trusted_role_verifying_key: &[u8; 32],
    ) -> RouterAbDerivationResult<VerifiedTenantRootManagedBackupV1> {
        Self::decode_canonical_bytes(bytes)?.verify(expected_binding, trusted_role_verifying_key)
    }

    /// Verifies binding equality, ciphertext integrity, and the owning role's signature.
    pub fn verify(
        &self,
        expected_binding: &TenantRootManagedBackupBindingV1,
        trusted_role_verifying_key: &[u8; 32],
    ) -> RouterAbDerivationResult<VerifiedTenantRootManagedBackupV1> {
        self.validate()?;
        expected_binding.validate()?;
        if &self.binding != expected_binding {
            return Err(malformed(
                "tenant-root managed backup does not match its expected binding",
            ));
        }
        let verifying_key = VerifyingKey::from_bytes(trusted_role_verifying_key)
            .map_err(|_| malformed("tenant-root managed-backup verifying key is invalid"))?;
        verifying_key
            .verify_strict(
                &receipt_signature_input(&self.binding, &self.ciphertext_digest)?,
                &Signature::from_bytes(&self.signature),
            )
            .map_err(|_| verification_failed("tenant-root managed-backup signature is invalid"))?;
        let canonical_bytes = self.canonical_bytes()?;
        Ok(VerifiedTenantRootManagedBackupV1 {
            binding: self.binding.clone(),
            ciphertext: self.ciphertext.clone(),
            receipt_digest: self.lifecycle_receipt_digest()?,
            canonical_bytes,
        })
    }

    /// Returns the digest recorded by the tenant-root activation lifecycle.
    pub fn lifecycle_receipt_digest(
        &self,
    ) -> RouterAbDerivationResult<TenantRootLifecycleReceiptDigestV1> {
        let mut bytes = receipt_signature_input(&self.binding, &self.ciphertext_digest)?;
        push_len32(&mut bytes, &self.signature)?;
        TenantRootLifecycleReceiptDigestV1::from_bytes(Sha256::digest(bytes).into())
    }

    /// Returns the public ciphertext digest.
    pub const fn ciphertext_digest(&self) -> &[u8; 32] {
        &self.ciphertext_digest
    }

    /// Returns the exact canonical signed artifact bytes.
    pub fn canonical_bytes(&self) -> RouterAbDerivationResult<Vec<u8>> {
        self.validate()?;
        let mut bytes = Vec::new();
        push_len32(&mut bytes, MANAGED_BACKUP_ARTIFACT_DOMAIN_V1)?;
        push_len32(&mut bytes, &self.binding.canonical_bytes()?)?;
        push_len32(&mut bytes, &self.ciphertext)?;
        push_len32(&mut bytes, &self.ciphertext_digest)?;
        push_len32(&mut bytes, &self.signature)?;
        if bytes.len() > MANAGED_BACKUP_MAX_WIRE_BYTES {
            return Err(malformed(
                "tenant-root signed managed-backup wire is too long",
            ));
        }
        Ok(bytes)
    }

    fn validate(&self) -> RouterAbDerivationResult<()> {
        self.binding.validate()?;
        require_ciphertext(&self.ciphertext)?;
        if !bool::from(
            self.ciphertext_digest
                .ct_eq(Sha256::digest(&self.ciphertext).as_ref()),
        ) {
            return Err(malformed(
                "tenant-root managed-backup ciphertext digest does not match ciphertext",
            ));
        }
        if self.signature.iter().all(|byte| *byte == 0) {
            return Err(malformed(
                "tenant-root managed-backup signature must be nonzero",
            ));
        }
        Ok(())
    }
}

impl fmt::Debug for TenantRootSignedManagedBackupV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TenantRootSignedManagedBackupV1")
            .field("binding", &self.binding)
            .field("ciphertext", &"[redacted]")
            .field("ciphertext_digest", &hex::encode(self.ciphertext_digest))
            .field("signature", &"[redacted]")
            .finish()
    }
}

/// Signature-verified provider artifact accepted by one role's restore adapter.
pub struct VerifiedTenantRootManagedBackupV1 {
    binding: TenantRootManagedBackupBindingV1,
    ciphertext: Vec<u8>,
    receipt_digest: TenantRootLifecycleReceiptDigestV1,
    canonical_bytes: Vec<u8>,
}

impl VerifiedTenantRootManagedBackupV1 {
    /// Returns the signature-verified backup binding.
    pub const fn binding(&self) -> &TenantRootManagedBackupBindingV1 {
        &self.binding
    }

    /// Returns the exact verified installation-evidence receipt digest.
    pub const fn installation_receipt_digest(&self) -> TenantRootLifecycleReceiptDigestV1 {
        self.binding.installation_receipt_digest()
    }

    /// Returns the role owning the signature-verified backup.
    pub const fn role(&self) -> TenantRootManagedRestoreRoleV1 {
        self.binding.role()
    }

    /// Returns the exact tenant-root identity bound to the backup.
    pub const fn identity_digest(&self) -> TenantRootIdentityDigestV1 {
        self.binding.identity_digest()
    }

    /// Returns the exact custody lineage bound to the backup.
    pub const fn custody_lineage(&self) -> TenantRootCustodyLineageId {
        self.binding.custody_lineage()
    }

    /// Returns the exact custody epoch bound to the backup.
    pub const fn epoch(&self) -> TenantRootShareEpoch {
        self.binding.epoch()
    }

    /// Returns the public commitment bound to the backup.
    pub const fn share_commitment(&self) -> &MpcPrfShareCommitmentWireV1 {
        self.binding.share_commitment()
    }

    /// Returns the exact canonical signed artifact bytes accepted by verification.
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    /// Consumes the token into the exact canonical signed artifact bytes.
    pub fn into_canonical_bytes(self) -> Vec<u8> {
        self.canonical_bytes
    }

    /// Returns the exact AAD the provider must authenticate while decrypting.
    pub fn aad(&self) -> RouterAbDerivationResult<Vec<u8>> {
        self.binding.canonical_bytes()
    }

    /// Returns the opaque ciphertext to the owning role provider only.
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// Returns the signed lifecycle receipt digest.
    pub const fn receipt_digest(&self) -> TenantRootLifecycleReceiptDigestV1 {
        self.receipt_digest
    }

    /// Accepts provider plaintext only when it reproduces the bound role commitment.
    pub fn verify_opened_share(
        self,
        opened_share: MpcPrfSigningRootShareWireV1,
    ) -> RouterAbDerivationResult<VerifiedTenantRootManagedBackupShareV1> {
        verify_share_matches_binding(&self.binding, &opened_share)?;
        Ok(VerifiedTenantRootManagedBackupShareV1 {
            binding: self.binding,
            share: opened_share,
            receipt_digest: self.receipt_digest,
        })
    }
}

impl fmt::Debug for VerifiedTenantRootManagedBackupV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedTenantRootManagedBackupV1")
            .field("binding", &self.binding)
            .field("ciphertext", &"[redacted]")
            .field("receipt_digest", &self.receipt_digest)
            .finish()
    }
}

/// Role-local restored share proved against one signed current-epoch backup.
pub struct VerifiedTenantRootManagedBackupShareV1 {
    binding: TenantRootManagedBackupBindingV1,
    share: MpcPrfSigningRootShareWireV1,
    receipt_digest: TenantRootLifecycleReceiptDigestV1,
}

impl VerifiedTenantRootManagedBackupShareV1 {
    /// Returns the exact binding retained through provider open.
    pub const fn binding(&self) -> &TenantRootManagedBackupBindingV1 {
        &self.binding
    }

    /// Returns the exact role owning the opened share.
    pub const fn role(&self) -> TenantRootManagedRestoreRoleV1 {
        self.binding.role()
    }

    /// Returns the exact tenant-root identity bound to the opened share.
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

    /// Returns the public commitment reproduced by the opened share.
    pub const fn share_commitment(&self) -> &MpcPrfShareCommitmentWireV1 {
        self.binding.share_commitment()
    }

    /// Returns the signer-local share for immediate installation and forward refresh.
    pub fn share(&self) -> &MpcPrfSigningRootShareWireV1 {
        &self.share
    }

    /// Returns the signed backup receipt digest.
    pub const fn receipt_digest(&self) -> TenantRootLifecycleReceiptDigestV1 {
        self.receipt_digest
    }

    /// Returns the exact verified installation-evidence receipt digest.
    pub const fn installation_receipt_digest(&self) -> TenantRootLifecycleReceiptDigestV1 {
        self.binding.installation_receipt_digest()
    }
}

impl fmt::Debug for VerifiedTenantRootManagedBackupShareV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedTenantRootManagedBackupShareV1")
            .field("binding", &self.binding)
            .field("share", &"[redacted]")
            .field("receipt_digest", &self.receipt_digest)
            .finish()
    }
}

fn verify_share_matches_binding(
    binding: &TenantRootManagedBackupBindingV1,
    share: &MpcPrfSigningRootShareWireV1,
) -> RouterAbDerivationResult<()> {
    binding.validate()?;
    let share = SigningRootShareWire::decode_slice(share.as_bytes())
        .and_then(|wire| wire.to_share())
        .map_err(|_| malformed("tenant-root managed-backup share is invalid"))?;
    let commitment = SigningRootShareCommitment::from_share(&share).to_bytes();
    if share.id().get().get() != role_share_id(binding.role)
        || !bool::from(commitment.ct_eq(binding.share_commitment.as_bytes()))
    {
        return Err(verification_failed(
            "tenant-root managed-backup share does not match its commitment",
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

fn decode_binding_canonical_bytes(
    bytes: &[u8],
) -> RouterAbDerivationResult<TenantRootManagedBackupBindingV1> {
    let mut decoder = TenantRootWireDecoderV1::new(bytes);
    decoder.require_field(MANAGED_BACKUP_BINDING_DOMAIN_V1)?;
    let identity_digest = TenantRootIdentityDigestV1::from_bytes(
        decoder.fixed_field::<32>("tenant-root managed-backup identity digest")?,
    );
    let custody_lineage = TenantRootCustodyLineageId::from_bytes(
        decoder.fixed_field::<16>("tenant-root managed-backup custody lineage")?,
    )?;
    let role = managed_restore_role(decoder.role()?);
    let epoch = TenantRootShareEpoch::new(decoder.u64_field("tenant-root managed-backup epoch")?)?;
    let share_commitment = MpcPrfShareCommitmentWireV1::new(
        decoder
            .field("tenant-root managed-backup share commitment")?
            .to_vec(),
    )?;
    let installation_receipt_digest = TenantRootLifecycleReceiptDigestV1::from_bytes(
        decoder.fixed_field::<32>("tenant-root managed-backup installation receipt digest")?,
    )?;
    let backup_provider_id = decoder.text_field(
        "tenant-root managed-backup provider id",
        MANAGED_BACKUP_MAX_WIRE_BYTES,
    )?;
    let backup_key_version = decoder.text_field(
        "tenant-root managed-backup key version",
        MANAGED_BACKUP_MAX_WIRE_BYTES,
    )?;
    let role_signing_key_id = decoder.text_field(
        "tenant-root managed-backup role signing key id",
        MANAGED_BACKUP_MAX_WIRE_BYTES,
    )?;
    let created_at_ms = decoder.u64_field("tenant-root managed-backup creation timestamp")?;
    decoder.finish()?;
    let binding = TenantRootManagedBackupBindingV1 {
        identity_digest,
        custody_lineage,
        role,
        epoch,
        share_commitment,
        installation_receipt_digest,
        backup_provider_id,
        backup_key_version,
        role_signing_key_id,
        created_at_ms,
    };
    binding.validate()?;
    if binding.canonical_bytes()? != bytes {
        return Err(malformed(
            "tenant-root managed-backup binding is not canonical",
        ));
    }
    Ok(binding)
}

const fn managed_restore_role(role: TwoPartyDeriverRole) -> TenantRootManagedRestoreRoleV1 {
    match role {
        TwoPartyDeriverRole::DeriverA => TenantRootManagedRestoreRoleV1::DeriverA,
        TwoPartyDeriverRole::DeriverB => TenantRootManagedRestoreRoleV1::DeriverB,
    }
}

fn receipt_signature_input(
    binding: &TenantRootManagedBackupBindingV1,
    ciphertext_digest: &[u8; 32],
) -> RouterAbDerivationResult<Vec<u8>> {
    let mut bytes = Vec::new();
    push_len32(&mut bytes, MANAGED_BACKUP_RECEIPT_DOMAIN_V1)?;
    push_len32(&mut bytes, &binding.canonical_bytes()?)?;
    push_len32(&mut bytes, ciphertext_digest)?;
    Ok(bytes)
}

fn push_role(
    out: &mut Vec<u8>,
    role: TenantRootManagedRestoreRoleV1,
) -> RouterAbDerivationResult<()> {
    let role_name = match role {
        TenantRootManagedRestoreRoleV1::DeriverA => "deriver_a",
        TenantRootManagedRestoreRoleV1::DeriverB => "deriver_b",
    };
    push_len32(out, role_name.as_bytes())?;
    push_len32(out, &role_share_id(role).to_be_bytes())
}

const fn role_share_id(role: TenantRootManagedRestoreRoleV1) -> u16 {
    match role {
        TenantRootManagedRestoreRoleV1::DeriverA => 1,
        TenantRootManagedRestoreRoleV1::DeriverB => 2,
    }
}

fn push_len32(out: &mut Vec<u8>, value: &[u8]) -> RouterAbDerivationResult<()> {
    let length = u32::try_from(value.len())
        .map_err(|_| malformed("tenant-root managed-backup field is too long"))?;
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(value);
    Ok(())
}

fn require_ciphertext(ciphertext: &[u8]) -> RouterAbDerivationResult<()> {
    if ciphertext.is_empty() || ciphertext.len() > MANAGED_BACKUP_MAX_CIPHERTEXT_BYTES {
        return Err(malformed(
            "tenant-root managed-backup ciphertext has an invalid length",
        ));
    }
    Ok(())
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
