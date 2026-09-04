//! Canonical issuer-authenticated public state for managed restore.
//!
//! The package is a public reconstruction input. It carries the exact active
//! activation receipt, role-unavailability observation, lifecycle revision,
//! and cleanup fence. No role share or provider ciphertext crosses this
//! boundary.

use core::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

use super::tenant_root_protocol::TenantRootWireDecoderV1;
use super::{
    require_tenant_root_identifier, RouterAbDerivationError, RouterAbDerivationErrorCode,
    RouterAbDerivationResult, TenantRootActiveRefreshV1, TenantRootIdentityV1,
    TenantRootLifecycleReceiptDigestV1, TenantRootManagedRestoreCapabilityV1,
    TenantRootManagedRestoreCleanupReceiptV1, TenantRootManagedRestoreFailureV1,
    TenantRootManagedRestoreInstallationReceiptV1, TenantRootManagedRestoreInstallingV1,
    TenantRootManagedRestorePriorAttemptCleanupFenceV1, TenantRootManagedRestorePriorAttemptV1,
    TenantRootManagedRestoreRoleUnavailableV1, TenantRootManagedRestoreRoleV1,
    TenantRootProtocolDigestV1, TenantRootRoleUnavailableReceiptV1, TenantRootShareEpoch,
    TenantRootSignedActivationReceiptV1, VerifiedTenantRootManagedRestoreCapabilityV1,
};

const TENANT_ROOT_MANAGED_RESTORE_PUBLIC_STATE_DOMAIN_V1: &[u8] =
    b"tenant_root_managed_restore_public_state_v1";
const TENANT_ROOT_MANAGED_RESTORE_PUBLIC_STATE_AUTH_DOMAIN_V1: &[u8] =
    b"tenant_root_managed_restore_public_state_authentication_v1";
const TENANT_ROOT_MANAGED_RESTORE_PUBLIC_STATE_OPERATION_BYTES_V1: &[u8] =
    b"managed_restore_role_unavailable";
const TENANT_ROOT_MANAGED_RESTORE_PUBLIC_STATE_ISSUER_KEY_ID_MAX_BYTES_V1: usize = 256;
const TENANT_ROOT_MANAGED_RESTORE_PUBLIC_STATE_MAX_BYTES_V1: usize = 48 * 1024;
const TENANT_ROOT_MANAGED_RESTORE_PUBLIC_STATE_CLEANED_TAG_V1: &[u8] = b"cleaned";
const TENANT_ROOT_MANAGED_RESTORE_PUBLIC_STATE_INSTALLING_TAG_V1: &[u8] = b"installing";
const TENANT_ROOT_MANAGED_RESTORE_PUBLIC_STATE_INSTALLED_TAG_V1: &[u8] = b"installed";

/// Exact operation authenticated by a managed-restore public-state package.
pub const TENANT_ROOT_MANAGED_RESTORE_PUBLIC_STATE_OPERATION_V1: &str =
    "managed_restore_role_unavailable";

/// Maximum canonical wire size accepted for one managed-restore public state.
pub const TENANT_ROOT_MANAGED_RESTORE_PUBLIC_STATE_MAX_BYTES: usize =
    TENANT_ROOT_MANAGED_RESTORE_PUBLIC_STATE_MAX_BYTES_V1;

#[derive(Clone, PartialEq, Eq)]
struct TenantRootManagedRestorePublicStateDataV1 {
    identity: TenantRootIdentityV1,
    activation_receipt: TenantRootSignedActivationReceiptV1,
    unavailable: TenantRootRoleUnavailableReceiptV1,
    cleanup_fence: TenantRootManagedRestorePriorAttemptCleanupFenceV1,
    lifecycle_revision: u64,
    issuer_key_id: String,
    signature: [u8; 64],
}

impl fmt::Debug for TenantRootManagedRestorePublicStateDataV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TenantRootManagedRestorePublicStateDataV1")
            .field("identity", &self.identity)
            .field("activation_receipt", &self.activation_receipt)
            .field("unavailable", &self.unavailable)
            .field("cleanup_fence", &self.cleanup_fence)
            .field("lifecycle_revision", &self.lifecycle_revision)
            .field("issuer_key_id", &self.issuer_key_id)
            .field("signature", &"[redacted]")
            .finish()
    }
}

/// Issuer-signed managed-restore public state before outer signature verification.
#[derive(Clone, PartialEq, Eq)]
pub struct TenantRootSignedManagedRestoreRoleUnavailableV1 {
    data: TenantRootManagedRestorePublicStateDataV1,
}

impl fmt::Debug for TenantRootSignedManagedRestoreRoleUnavailableV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TenantRootSignedManagedRestoreRoleUnavailableV1")
            .field("data", &self.data)
            .finish()
    }
}

impl TenantRootSignedManagedRestoreRoleUnavailableV1 {
    /// Signs the exact public unavailable state retained by the lifecycle.
    pub fn sign(
        state: &TenantRootManagedRestoreRoleUnavailableV1,
        issuer_key_id: impl Into<String>,
        issuer_signing_key_bytes: &[u8; 32],
    ) -> RouterAbDerivationResult<Self> {
        let activation_receipt = TenantRootSignedActivationReceiptV1::decode_canonical_bytes(
            state.active().activation_receipt_bytes(),
        )?;
        let data = TenantRootManagedRestorePublicStateDataV1 {
            identity: state.active().identity().clone(),
            activation_receipt,
            unavailable: state.unavailable_receipt(),
            cleanup_fence: state.prior_attempt_cleanup_fence(),
            lifecycle_revision: state.revision(),
            issuer_key_id: issuer_key_id.into(),
            signature: [0; 64],
        };
        validate_unsigned_data(&data)?;
        let unsigned = unsigned_canonical_bytes(&data)?;
        let signature = SigningKey::from_bytes(issuer_signing_key_bytes)
            .sign(&authentication_input(&data.issuer_key_id, &unsigned)?)
            .to_bytes();
        let signed = Self {
            data: TenantRootManagedRestorePublicStateDataV1 { signature, ..data },
        };
        signed.canonical_bytes()?;
        Ok(signed)
    }

    /// Decodes exactly one canonical managed-restore public-state wire.
    pub fn decode_canonical_bytes(bytes: &[u8]) -> RouterAbDerivationResult<Self> {
        if bytes.is_empty() || bytes.len() > TENANT_ROOT_MANAGED_RESTORE_PUBLIC_STATE_MAX_BYTES_V1 {
            return Err(malformed(
                "tenant-root managed-restore public-state wire length is invalid",
            ));
        }
        let mut decoder = TenantRootWireDecoderV1::new(bytes);
        decoder.require_field(TENANT_ROOT_MANAGED_RESTORE_PUBLIC_STATE_DOMAIN_V1)?;
        if decoder.field("tenant-root managed-restore public-state operation")?
            != TENANT_ROOT_MANAGED_RESTORE_PUBLIC_STATE_OPERATION_BYTES_V1
        {
            return Err(malformed(
                "tenant-root managed-restore public-state operation is invalid",
            ));
        }
        let identity = TenantRootIdentityV1::decode_canonical_bytes(
            decoder.field("tenant-root managed-restore public-state identity")?,
        )?;
        let activation_receipt = TenantRootSignedActivationReceiptV1::decode_canonical_bytes(
            decoder.field("tenant-root managed-restore public-state activation receipt")?,
        )?;
        let unavailable = decode_unavailable_receipt(&mut decoder)?;
        let cleanup_fence = decode_cleanup_fence(&mut decoder)?;
        let lifecycle_revision =
            decoder.u64_field("tenant-root managed-restore public-state lifecycle revision")?;
        let issuer_key_id = decoder.text_field(
            "tenant-root managed-restore public-state issuer key id",
            TENANT_ROOT_MANAGED_RESTORE_PUBLIC_STATE_ISSUER_KEY_ID_MAX_BYTES_V1,
        )?;
        require_tenant_root_identifier(
            "tenant-root managed-restore public-state issuer key id",
            &issuer_key_id,
        )?;
        let signature =
            decoder.fixed_field::<64>("tenant-root managed-restore public-state signature")?;
        if signature.iter().all(|byte| *byte == 0) {
            return Err(malformed(
                "tenant-root managed-restore public-state signature must be nonzero",
            ));
        }
        decoder.finish()?;
        let signed = Self {
            data: TenantRootManagedRestorePublicStateDataV1 {
                identity,
                activation_receipt,
                unavailable,
                cleanup_fence,
                lifecycle_revision,
                issuer_key_id,
                signature,
            },
        };
        validate_data(&signed.data)?;
        if signed.canonical_bytes()? != bytes {
            return Err(malformed(
                "tenant-root managed-restore public-state wire is not canonical",
            ));
        }
        Ok(signed)
    }

    /// Decodes and verifies one issuer-signed canonical public-state package.
    pub fn decode_and_verify_canonical_bytes(
        bytes: &[u8],
        expected_issuer_key_id: &str,
        trusted_issuer_verifying_key: &[u8; 32],
    ) -> RouterAbDerivationResult<VerifiedTenantRootManagedRestoreRoleUnavailableV1> {
        Self::decode_canonical_bytes(bytes)?
            .verify(expected_issuer_key_id, trusted_issuer_verifying_key)
    }

    /// Returns the exact operation authenticated by this package.
    pub const fn operation(&self) -> &'static str {
        TENANT_ROOT_MANAGED_RESTORE_PUBLIC_STATE_OPERATION_V1
    }

    /// Returns the server-resolved identity carried by this package.
    pub const fn identity(&self) -> &TenantRootIdentityV1 {
        &self.data.identity
    }

    /// Returns the exact role-unavailability observation carried by this package.
    pub const fn unavailable_receipt(&self) -> TenantRootRoleUnavailableReceiptV1 {
        self.data.unavailable
    }

    /// Returns the prior-attempt cleanup fence carried by this package.
    pub fn cleanup_fence(&self) -> TenantRootManagedRestorePriorAttemptCleanupFenceV1 {
        self.data.cleanup_fence.clone()
    }

    /// Returns the lifecycle revision carried by this package.
    pub const fn lifecycle_revision(&self) -> u64 {
        self.data.lifecycle_revision
    }

    /// Returns the issuer key identifier carried by this package.
    pub fn issuer_key_id(&self) -> &str {
        &self.data.issuer_key_id
    }

    /// Returns the exact canonical signed public-state wire.
    pub fn canonical_bytes(&self) -> RouterAbDerivationResult<Vec<u8>> {
        let unsigned = unsigned_canonical_bytes(&self.data)?;
        canonical_bytes_from_unsigned(unsigned, &self.data.signature)
    }

    /// Returns the digest of the exact canonical signed public-state wire.
    pub fn digest(&self) -> RouterAbDerivationResult<TenantRootProtocolDigestV1> {
        TenantRootProtocolDigestV1::from_bytes(Sha256::digest(self.canonical_bytes()?).into())
    }

    /// Verifies this package and reconstructs the exact unavailable lifecycle state.
    pub fn verify(
        &self,
        expected_issuer_key_id: &str,
        trusted_issuer_verifying_key: &[u8; 32],
    ) -> RouterAbDerivationResult<VerifiedTenantRootManagedRestoreRoleUnavailableV1> {
        validate_data(&self.data)?;
        require_tenant_root_identifier(
            "tenant-root managed-restore public-state expected issuer key id",
            expected_issuer_key_id,
        )?;
        if self.data.issuer_key_id != expected_issuer_key_id {
            return Err(replay_mismatch(
                "tenant-root managed-restore public-state issuer key id does not match its expected issuer",
            ));
        }
        let verifying_key =
            VerifyingKey::from_bytes(trusted_issuer_verifying_key).map_err(|_| {
                verification_failed(
                    "tenant-root managed-restore public-state issuer key is invalid",
                )
            })?;
        let unsigned = unsigned_canonical_bytes(&self.data)?;
        verifying_key
            .verify_strict(
                &authentication_input(&self.data.issuer_key_id, &unsigned)?,
                &Signature::from_bytes(&self.data.signature),
            )
            .map_err(|_| {
                verification_failed("tenant-root managed-restore public-state signature is invalid")
            })?;

        let activation = self
            .data
            .activation_receipt
            .clone()
            .verify_issuer_signature(trusted_issuer_verifying_key)?;
        let active = TenantRootActiveRefreshV1::from_verified_activation_receipt(
            self.data.identity.clone(),
            activation,
            self.data.activation_receipt.result_control_plane_revision(),
        )?;
        let state = TenantRootManagedRestoreRoleUnavailableV1::from_public_projection(
            active,
            self.data.unavailable,
            self.data.cleanup_fence.clone(),
            self.data.lifecycle_revision,
        )?;
        let canonical_bytes = canonical_bytes_from_unsigned(unsigned, &self.data.signature)?;
        let digest =
            TenantRootProtocolDigestV1::from_bytes(Sha256::digest(&canonical_bytes).into())?;
        Ok(VerifiedTenantRootManagedRestoreRoleUnavailableV1 {
            state,
            issuer_key_id: self.data.issuer_key_id.clone(),
            canonical_bytes,
            digest,
        })
    }
}

/// Signature-verified managed-restore unavailable-state binding.
///
/// This token intentionally has no public constructor and does not implement
/// `Clone` or `Serialize`. Consuming it is the only way to enter role-local
/// restore from the reconstructed state.
pub struct VerifiedTenantRootManagedRestoreRoleUnavailableV1 {
    state: TenantRootManagedRestoreRoleUnavailableV1,
    issuer_key_id: String,
    canonical_bytes: Vec<u8>,
    digest: TenantRootProtocolDigestV1,
}

impl fmt::Debug for VerifiedTenantRootManagedRestoreRoleUnavailableV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedTenantRootManagedRestoreRoleUnavailableV1")
            .field("state", &self.state)
            .field("issuer_key_id", &self.issuer_key_id)
            .field("digest", &self.digest)
            .field("canonical_bytes", &"[public bytes]")
            .finish()
    }
}

impl VerifiedTenantRootManagedRestoreRoleUnavailableV1 {
    /// Returns the exact operation authenticated by this token.
    pub const fn operation(&self) -> &'static str {
        TENANT_ROOT_MANAGED_RESTORE_PUBLIC_STATE_OPERATION_V1
    }

    /// Returns the reconstructed role-unavailable lifecycle state.
    pub const fn state(&self) -> &TenantRootManagedRestoreRoleUnavailableV1 {
        &self.state
    }

    /// Returns the only role eligible for managed recovery.
    pub fn unavailable_role(&self) -> TenantRootManagedRestoreRoleV1 {
        self.state.unavailable_role()
    }

    /// Returns the authoritative lifecycle revision.
    pub const fn lifecycle_revision(&self) -> u64 {
        self.state.revision()
    }

    /// Returns the verified issuer key identifier.
    pub fn issuer_key_id(&self) -> &str {
        &self.issuer_key_id
    }

    /// Returns the exact canonical signed public-state wire accepted by verification.
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    /// Returns the digest of the exact canonical signed public-state wire.
    pub const fn digest(&self) -> TenantRootProtocolDigestV1 {
        self.digest
    }

    /// Starts role-local restore while consuming this verified state binding.
    pub fn start_restore(
        self,
        capability: VerifiedTenantRootManagedRestoreCapabilityV1,
        started_at_ms: u64,
    ) -> RouterAbDerivationResult<TenantRootManagedRestoreInstallingV1> {
        self.state
            .start_restore(capability.into_capability(), started_at_ms)
    }

    /// Consumes verification into the reconstructed lifecycle state.
    pub fn into_state(self) -> TenantRootManagedRestoreRoleUnavailableV1 {
        self.state
    }

    /// Consumes verification into the exact canonical signed wire bytes.
    pub fn into_canonical_bytes(self) -> Vec<u8> {
        self.canonical_bytes
    }
}

fn validate_data(data: &TenantRootManagedRestorePublicStateDataV1) -> RouterAbDerivationResult<()> {
    validate_unsigned_data(data)?;
    if data.signature.iter().all(|byte| *byte == 0) {
        return Err(malformed(
            "tenant-root managed-restore public-state signature must be nonzero",
        ));
    }
    Ok(())
}

fn validate_unsigned_data(
    data: &TenantRootManagedRestorePublicStateDataV1,
) -> RouterAbDerivationResult<()> {
    if data.identity.digest()? != data.activation_receipt.identity_digest() {
        return Err(replay_mismatch(
            "tenant-root managed-restore public-state identity does not match its activation receipt",
        ));
    }
    if data.activation_receipt.issuer_key_id() != data.issuer_key_id {
        return Err(replay_mismatch(
            "tenant-root managed-restore public-state issuer does not match its activation receipt",
        ));
    }
    if data.lifecycle_revision == 0
        || data.lifecycle_revision <= data.activation_receipt.result_control_plane_revision()
    {
        return Err(malformed(
            "tenant-root managed-restore public-state lifecycle revision must follow activation",
        ));
    }
    require_tenant_root_identifier(
        "tenant-root managed-restore public-state issuer key id",
        &data.issuer_key_id,
    )?;
    if data.issuer_key_id.len()
        > TENANT_ROOT_MANAGED_RESTORE_PUBLIC_STATE_ISSUER_KEY_ID_MAX_BYTES_V1
    {
        return Err(malformed(
            "tenant-root managed-restore public-state issuer key id is too long",
        ));
    }
    data.identity.canonical_bytes()?;
    data.activation_receipt.canonical_bytes()?;
    validate_unavailable_receipt(&data.unavailable)?;
    validate_cleanup_fence(&data.cleanup_fence)?;
    Ok(())
}

fn validate_unavailable_receipt(
    receipt: &TenantRootRoleUnavailableReceiptV1,
) -> RouterAbDerivationResult<()> {
    TenantRootRoleUnavailableReceiptV1::new(
        receipt.digest(),
        receipt.role(),
        receipt.unavailable_at_ms(),
    )?;
    Ok(())
}

fn validate_cleanup_fence(
    fence: &TenantRootManagedRestorePriorAttemptCleanupFenceV1,
) -> RouterAbDerivationResult<()> {
    match fence {
        TenantRootManagedRestorePriorAttemptCleanupFenceV1::None => Ok(()),
        TenantRootManagedRestorePriorAttemptCleanupFenceV1::Cleaned {
            attempt,
            failure,
            cleanup,
        } => {
            match attempt {
                TenantRootManagedRestorePriorAttemptV1::Installing {
                    capability,
                    started_at_ms,
                } => {
                    TenantRootManagedRestoreCapabilityV1::new(
                        capability.digest(),
                        capability.identity_digest(),
                        capability.custody_lineage(),
                        capability.role(),
                        capability.epoch(),
                        capability.activation_receipt_digest(),
                        capability.issued_at_ms(),
                        capability.expires_at_ms(),
                    )?;
                    if *started_at_ms < capability.issued_at_ms() {
                        return Err(malformed(
                            "tenant-root managed-restore cleanup-fence start predates capability",
                        ));
                    }
                }
                TenantRootManagedRestorePriorAttemptV1::Installed {
                    capability,
                    installation,
                } => {
                    TenantRootManagedRestoreCapabilityV1::new(
                        capability.digest(),
                        capability.identity_digest(),
                        capability.custody_lineage(),
                        capability.role(),
                        capability.epoch(),
                        capability.activation_receipt_digest(),
                        capability.issued_at_ms(),
                        capability.expires_at_ms(),
                    )?;
                    validate_installation_receipt_shape(installation)?;
                }
            }
            TenantRootManagedRestoreFailureV1::new(failure.digest(), failure.failed_at_ms())?;
            TenantRootManagedRestoreCleanupReceiptV1::new(
                cleanup.digest(),
                cleanup.role(),
                cleanup.cleaned_at_ms(),
            )?;
            Ok(())
        }
    }
}

fn validate_installation_receipt_shape(
    installation: &TenantRootManagedRestoreInstallationReceiptV1,
) -> RouterAbDerivationResult<()> {
    TenantRootManagedRestoreInstallationReceiptV1::new(
        installation.digest(),
        installation.capability_digest(),
        installation.identity_digest(),
        installation.custody_lineage(),
        installation.role(),
        installation.epoch(),
        installation.activation_receipt_digest(),
        installation.share_commitment().clone(),
        installation.installed_at_ms(),
    )?;
    Ok(())
}

fn unsigned_canonical_bytes(
    data: &TenantRootManagedRestorePublicStateDataV1,
) -> RouterAbDerivationResult<Vec<u8>> {
    validate_unsigned_data(data)?;
    let mut bytes = Vec::new();
    push_field(
        &mut bytes,
        TENANT_ROOT_MANAGED_RESTORE_PUBLIC_STATE_DOMAIN_V1,
    )?;
    push_field(
        &mut bytes,
        TENANT_ROOT_MANAGED_RESTORE_PUBLIC_STATE_OPERATION_BYTES_V1,
    )?;
    push_field(&mut bytes, &data.identity.canonical_bytes()?)?;
    push_field(&mut bytes, &data.activation_receipt.canonical_bytes()?)?;
    push_unavailable_receipt(&mut bytes, &data.unavailable)?;
    push_cleanup_fence(&mut bytes, &data.cleanup_fence)?;
    push_field(&mut bytes, &data.lifecycle_revision.to_be_bytes())?;
    push_field(&mut bytes, data.issuer_key_id.as_bytes())?;
    Ok(bytes)
}

fn canonical_bytes_from_unsigned(
    mut unsigned: Vec<u8>,
    signature: &[u8; 64],
) -> RouterAbDerivationResult<Vec<u8>> {
    push_field(&mut unsigned, signature)?;
    Ok(unsigned)
}

fn authentication_input(issuer_key_id: &str, unsigned: &[u8]) -> RouterAbDerivationResult<Vec<u8>> {
    require_tenant_root_identifier(
        "tenant-root managed-restore public-state issuer key id",
        issuer_key_id,
    )?;
    let mut bytes = Vec::new();
    push_field(
        &mut bytes,
        TENANT_ROOT_MANAGED_RESTORE_PUBLIC_STATE_AUTH_DOMAIN_V1,
    )?;
    push_field(&mut bytes, issuer_key_id.as_bytes())?;
    push_field(&mut bytes, unsigned)?;
    Ok(bytes)
}

fn push_unavailable_receipt(
    bytes: &mut Vec<u8>,
    receipt: &TenantRootRoleUnavailableReceiptV1,
) -> RouterAbDerivationResult<()> {
    push_field(bytes, receipt.digest().as_bytes())?;
    push_role(bytes, receipt.role())?;
    push_field(bytes, &receipt.unavailable_at_ms().to_be_bytes())
}

fn decode_unavailable_receipt(
    decoder: &mut TenantRootWireDecoderV1<'_>,
) -> RouterAbDerivationResult<TenantRootRoleUnavailableReceiptV1> {
    let digest = TenantRootLifecycleReceiptDigestV1::from_bytes(
        decoder.fixed_field::<32>("tenant-root managed-restore public-state unavailable digest")?,
    )?;
    let role = managed_restore_role(decoder.role()?);
    let unavailable_at_ms =
        decoder.u64_field("tenant-root managed-restore public-state unavailable time")?;
    TenantRootRoleUnavailableReceiptV1::new(digest, role, unavailable_at_ms)
}

fn push_cleanup_fence(
    bytes: &mut Vec<u8>,
    fence: &TenantRootManagedRestorePriorAttemptCleanupFenceV1,
) -> RouterAbDerivationResult<()> {
    match fence {
        TenantRootManagedRestorePriorAttemptCleanupFenceV1::None => {
            push_field(bytes, b"none")?;
        }
        TenantRootManagedRestorePriorAttemptCleanupFenceV1::Cleaned {
            attempt,
            failure,
            cleanup,
        } => {
            push_field(
                bytes,
                TENANT_ROOT_MANAGED_RESTORE_PUBLIC_STATE_CLEANED_TAG_V1,
            )?;
            push_prior_attempt(bytes, attempt)?;
            push_field(bytes, failure.digest().as_bytes())?;
            push_field(bytes, &failure.failed_at_ms().to_be_bytes())?;
            push_field(bytes, cleanup.digest().as_bytes())?;
            push_role(bytes, cleanup.role())?;
            push_field(bytes, &cleanup.cleaned_at_ms().to_be_bytes())?;
        }
    }
    Ok(())
}

fn decode_cleanup_fence(
    decoder: &mut TenantRootWireDecoderV1<'_>,
) -> RouterAbDerivationResult<TenantRootManagedRestorePriorAttemptCleanupFenceV1> {
    match decoder.field("tenant-root managed-restore public-state cleanup fence")? {
        b"none" => Ok(TenantRootManagedRestorePriorAttemptCleanupFenceV1::None),
        TENANT_ROOT_MANAGED_RESTORE_PUBLIC_STATE_CLEANED_TAG_V1 => {
            let attempt = decode_prior_attempt(decoder)?;
            let failure_digest =
                TenantRootLifecycleReceiptDigestV1::from_bytes(decoder.fixed_field::<32>(
                    "tenant-root managed-restore public-state cleanup failure digest",
                )?)?;
            let failed_at_ms = decoder
                .u64_field("tenant-root managed-restore public-state cleanup failure time")?;
            let cleanup_digest =
                TenantRootLifecycleReceiptDigestV1::from_bytes(decoder.fixed_field::<32>(
                    "tenant-root managed-restore public-state cleanup receipt digest",
                )?)?;
            let cleanup_role = managed_restore_role(decoder.role()?);
            let cleaned_at_ms = decoder
                .u64_field("tenant-root managed-restore public-state cleanup completion time")?;
            Ok(
                TenantRootManagedRestorePriorAttemptCleanupFenceV1::Cleaned {
                    attempt,
                    failure: TenantRootManagedRestoreFailureV1::new(failure_digest, failed_at_ms)?,
                    cleanup: TenantRootManagedRestoreCleanupReceiptV1::new(
                        cleanup_digest,
                        cleanup_role,
                        cleaned_at_ms,
                    )?,
                },
            )
        }
        _ => Err(malformed(
            "tenant-root managed-restore public-state cleanup fence is invalid",
        )),
    }
}

fn push_prior_attempt(
    bytes: &mut Vec<u8>,
    attempt: &TenantRootManagedRestorePriorAttemptV1,
) -> RouterAbDerivationResult<()> {
    match attempt {
        TenantRootManagedRestorePriorAttemptV1::Installing {
            capability,
            started_at_ms,
        } => {
            push_field(
                bytes,
                TENANT_ROOT_MANAGED_RESTORE_PUBLIC_STATE_INSTALLING_TAG_V1,
            )?;
            push_capability(bytes, capability)?;
            push_field(bytes, &started_at_ms.to_be_bytes())?;
        }
        TenantRootManagedRestorePriorAttemptV1::Installed {
            capability,
            installation,
        } => {
            push_field(
                bytes,
                TENANT_ROOT_MANAGED_RESTORE_PUBLIC_STATE_INSTALLED_TAG_V1,
            )?;
            push_capability(bytes, capability)?;
            push_installation(bytes, installation)?;
        }
    }
    Ok(())
}

fn decode_prior_attempt(
    decoder: &mut TenantRootWireDecoderV1<'_>,
) -> RouterAbDerivationResult<TenantRootManagedRestorePriorAttemptV1> {
    let kind = decoder.field("tenant-root managed-restore public-state prior attempt")?;
    let capability = decode_capability(decoder)?;
    match kind {
        TENANT_ROOT_MANAGED_RESTORE_PUBLIC_STATE_INSTALLING_TAG_V1 => {
            Ok(TenantRootManagedRestorePriorAttemptV1::Installing {
                capability,
                started_at_ms: decoder
                    .u64_field("tenant-root managed-restore public-state restore start time")?,
            })
        }
        TENANT_ROOT_MANAGED_RESTORE_PUBLIC_STATE_INSTALLED_TAG_V1 => {
            Ok(TenantRootManagedRestorePriorAttemptV1::Installed {
                capability,
                installation: decode_installation(decoder)?,
            })
        }
        _ => Err(malformed(
            "tenant-root managed-restore public-state prior attempt is invalid",
        )),
    }
}

fn push_capability(
    bytes: &mut Vec<u8>,
    capability: &TenantRootManagedRestoreCapabilityV1,
) -> RouterAbDerivationResult<()> {
    push_field(bytes, capability.digest().as_bytes())?;
    push_field(bytes, capability.identity_digest().as_bytes())?;
    push_field(bytes, capability.custody_lineage().as_bytes())?;
    push_role(bytes, capability.role())?;
    push_field(bytes, &capability.epoch().get().get().to_be_bytes())?;
    push_field(bytes, capability.activation_receipt_digest().as_bytes())?;
    push_field(bytes, &capability.issued_at_ms().to_be_bytes())?;
    push_field(bytes, &capability.expires_at_ms().to_be_bytes())
}

fn decode_capability(
    decoder: &mut TenantRootWireDecoderV1<'_>,
) -> RouterAbDerivationResult<TenantRootManagedRestoreCapabilityV1> {
    TenantRootManagedRestoreCapabilityV1::new(
        TenantRootLifecycleReceiptDigestV1::from_bytes(
            decoder
                .fixed_field::<32>("tenant-root managed-restore public-state capability digest")?,
        )?,
        super::TenantRootIdentityDigestV1::from_bytes(decoder.fixed_field::<32>(
            "tenant-root managed-restore public-state capability identity digest",
        )?),
        super::TenantRootCustodyLineageId::from_bytes(decoder.fixed_field::<16>(
            "tenant-root managed-restore public-state capability custody lineage",
        )?)?,
        managed_restore_role(decoder.role()?),
        TenantRootShareEpoch::new(
            decoder.u64_field("tenant-root managed-restore public-state capability epoch")?,
        )?,
        TenantRootLifecycleReceiptDigestV1::from_bytes(decoder.fixed_field::<32>(
            "tenant-root managed-restore public-state capability activation receipt digest",
        )?)?,
        decoder.u64_field("tenant-root managed-restore public-state capability issue time")?,
        decoder.u64_field("tenant-root managed-restore public-state capability expiry")?,
    )
}

fn push_installation(
    bytes: &mut Vec<u8>,
    installation: &TenantRootManagedRestoreInstallationReceiptV1,
) -> RouterAbDerivationResult<()> {
    push_field(bytes, installation.digest().as_bytes())?;
    push_field(bytes, installation.capability_digest().as_bytes())?;
    push_field(bytes, installation.identity_digest().as_bytes())?;
    push_field(bytes, installation.custody_lineage().as_bytes())?;
    push_role(bytes, installation.role())?;
    push_field(bytes, &installation.epoch().get().get().to_be_bytes())?;
    push_field(bytes, installation.activation_receipt_digest().as_bytes())?;
    push_field(bytes, installation.share_commitment().as_bytes())?;
    push_field(bytes, &installation.installed_at_ms().to_be_bytes())
}

fn decode_installation(
    decoder: &mut TenantRootWireDecoderV1<'_>,
) -> RouterAbDerivationResult<TenantRootManagedRestoreInstallationReceiptV1> {
    TenantRootManagedRestoreInstallationReceiptV1::new(
        TenantRootLifecycleReceiptDigestV1::from_bytes(
            decoder.fixed_field::<32>(
                "tenant-root managed-restore public-state installation digest",
            )?,
        )?,
        TenantRootLifecycleReceiptDigestV1::from_bytes(decoder.fixed_field::<32>(
            "tenant-root managed-restore public-state installation capability digest",
        )?)?,
        super::TenantRootIdentityDigestV1::from_bytes(decoder.fixed_field::<32>(
            "tenant-root managed-restore public-state installation identity digest",
        )?),
        super::TenantRootCustodyLineageId::from_bytes(decoder.fixed_field::<16>(
            "tenant-root managed-restore public-state installation custody lineage",
        )?)?,
        managed_restore_role(decoder.role()?),
        TenantRootShareEpoch::new(
            decoder.u64_field("tenant-root managed-restore public-state installation epoch")?,
        )?,
        TenantRootLifecycleReceiptDigestV1::from_bytes(decoder.fixed_field::<32>(
            "tenant-root managed-restore public-state installation activation receipt digest",
        )?)?,
        super::MpcPrfShareCommitmentWireV1::new(
            decoder
                .field("tenant-root managed-restore public-state installation commitment")?
                .to_vec(),
        )?,
        decoder.u64_field("tenant-root managed-restore public-state installation time")?,
    )
}

fn push_role(
    bytes: &mut Vec<u8>,
    role: TenantRootManagedRestoreRoleV1,
) -> RouterAbDerivationResult<()> {
    let (name, share_id) = match role {
        TenantRootManagedRestoreRoleV1::DeriverA => (b"deriver_a".as_slice(), 1_u16),
        TenantRootManagedRestoreRoleV1::DeriverB => (b"deriver_b".as_slice(), 2_u16),
    };
    push_field(bytes, name)?;
    push_field(bytes, &share_id.to_be_bytes())
}

fn managed_restore_role(
    role: threshold_prf::TwoPartyDeriverRole,
) -> TenantRootManagedRestoreRoleV1 {
    match role {
        threshold_prf::TwoPartyDeriverRole::DeriverA => TenantRootManagedRestoreRoleV1::DeriverA,
        threshold_prf::TwoPartyDeriverRole::DeriverB => TenantRootManagedRestoreRoleV1::DeriverB,
    }
}

fn push_field(out: &mut Vec<u8>, value: &[u8]) -> RouterAbDerivationResult<()> {
    if value.is_empty() {
        return Err(RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::EmptyField,
            "tenant-root managed-restore public-state field is required",
        ));
    }
    let length = u32::try_from(value.len())
        .map_err(|_| malformed("tenant-root managed-restore public-state field is too long"))?;
    let new_len = out
        .len()
        .checked_add(4)
        .and_then(|length| length.checked_add(value.len()))
        .ok_or_else(|| {
            malformed("tenant-root managed-restore public-state wire length overflows")
        })?;
    if new_len > TENANT_ROOT_MANAGED_RESTORE_PUBLIC_STATE_MAX_BYTES_V1 {
        return Err(malformed(
            "tenant-root managed-restore public-state wire is too long",
        ));
    }
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(value);
    Ok(())
}

fn malformed(message: impl Into<String>) -> RouterAbDerivationError {
    RouterAbDerivationError::new(RouterAbDerivationErrorCode::MalformedInput, message)
}

fn replay_mismatch(message: &'static str) -> RouterAbDerivationError {
    RouterAbDerivationError::new(RouterAbDerivationErrorCode::ReplayMismatch, message)
}

fn verification_failed(message: &'static str) -> RouterAbDerivationError {
    RouterAbDerivationError::new(
        RouterAbDerivationErrorCode::OutputVerificationFailed,
        message,
    )
}
