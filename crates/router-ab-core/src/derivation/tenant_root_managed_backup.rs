use core::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use threshold_prf::{SigningRootShareCommitment, SigningRootShareWire};

use super::{
    MpcPrfShareCommitmentWireV1, MpcPrfSigningRootShareWireV1, RouterAbDerivationError,
    RouterAbDerivationErrorCode, RouterAbDerivationResult, TenantRootCustodyLineageId,
    TenantRootIdentityDigestV1, TenantRootLifecycleReceiptDigestV1, TenantRootManagedRestoreRoleV1,
    TenantRootShareEpoch,
};

const MANAGED_BACKUP_BINDING_DOMAIN_V1: &[u8] = b"tenant_root_managed_backup_binding_v1";
const MANAGED_BACKUP_RECEIPT_DOMAIN_V1: &[u8] = b"tenant_root_managed_backup_receipt_v1";
const MANAGED_BACKUP_MAX_CIPHERTEXT_BYTES: usize = 64 * 1024;

/// Exact public AAD for one role-local current-epoch managed backup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantRootManagedBackupBindingV1 {
    identity_digest: TenantRootIdentityDigestV1,
    custody_lineage: TenantRootCustodyLineageId,
    role: TenantRootManagedRestoreRoleV1,
    epoch: TenantRootShareEpoch,
    share_commitment: MpcPrfShareCommitmentWireV1,
    installation_receipt_digest: TenantRootLifecycleReceiptDigestV1,
    backup_key_version: String,
    role_signing_key_id: String,
    created_at_ms: u64,
}

impl TenantRootManagedBackupBindingV1 {
    /// Creates the provider AAD for one exact role, epoch, and installed share.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        identity_digest: TenantRootIdentityDigestV1,
        custody_lineage: TenantRootCustodyLineageId,
        role: TenantRootManagedRestoreRoleV1,
        epoch: TenantRootShareEpoch,
        share_commitment: MpcPrfShareCommitmentWireV1,
        installation_receipt_digest: TenantRootLifecycleReceiptDigestV1,
        backup_key_version: impl Into<String>,
        role_signing_key_id: impl Into<String>,
        created_at_ms: u64,
    ) -> RouterAbDerivationResult<Self> {
        let binding = Self {
            identity_digest,
            custody_lineage,
            role,
            epoch,
            share_commitment,
            installation_receipt_digest,
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

    /// Returns the role-local backup key version.
    pub fn backup_key_version(&self) -> &str {
        &self.backup_key_version
    }

    fn validate(&self) -> RouterAbDerivationResult<()> {
        require_nonempty(
            "tenant-root managed-backup key version",
            &self.backup_key_version,
        )?;
        require_nonempty(
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
        Ok(Self {
            binding: request.binding,
            ciphertext,
            ciphertext_digest,
            signature,
        })
    }

    /// Verifies binding equality, ciphertext integrity, and the owning role's signature.
    pub fn verify(
        &self,
        expected_binding: &TenantRootManagedBackupBindingV1,
        trusted_role_verifying_key: &[u8; 32],
    ) -> RouterAbDerivationResult<VerifiedTenantRootManagedBackupV1> {
        self.binding.validate()?;
        require_ciphertext(&self.ciphertext)?;
        if &self.binding != expected_binding
            || !bool::from(
                self.ciphertext_digest
                    .ct_eq(Sha256::digest(&self.ciphertext).as_ref()),
            )
        {
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
        Ok(VerifiedTenantRootManagedBackupV1 {
            binding: self.binding.clone(),
            ciphertext: self.ciphertext.clone(),
            receipt_digest: self.lifecycle_receipt_digest()?,
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
}

impl VerifiedTenantRootManagedBackupV1 {
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
    /// Returns the restored role.
    pub const fn role(&self) -> TenantRootManagedRestoreRoleV1 {
        self.binding.role
    }

    /// Returns the signer-local share for immediate installation and forward refresh.
    pub fn share(&self) -> &MpcPrfSigningRootShareWireV1 {
        &self.share
    }

    /// Returns the signed backup receipt digest.
    pub const fn receipt_digest(&self) -> TenantRootLifecycleReceiptDigestV1 {
        self.receipt_digest
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

fn require_nonempty(field: &'static str, value: &str) -> RouterAbDerivationResult<()> {
    if value.is_empty() {
        return Err(RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::EmptyField,
            format!("{field} is required"),
        ));
    }
    u32::try_from(value.len())
        .map_err(|_| malformed("tenant-root managed-backup identifier is too long"))?;
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
