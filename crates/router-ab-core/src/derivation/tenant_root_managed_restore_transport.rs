//! Canonical control-plane authorization for one managed role restore.
//!
//! The lifecycle capability describes the state that may be restored. This
//! transport type adds the issuer signature and is the only wire boundary for
//! accepting that authorization.

use core::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use threshold_prf::TwoPartyDeriverRole;

use super::tenant_root_protocol::TenantRootWireDecoderV1;
use super::{
    require_tenant_root_identifier, RouterAbDerivationError, RouterAbDerivationErrorCode,
    RouterAbDerivationResult, TenantRootCustodyLineageId, TenantRootIdentityDigestV1,
    TenantRootLifecycleReceiptDigestV1, TenantRootManagedRestoreCapabilityV1,
    TenantRootManagedRestoreRoleUnavailableV1, TenantRootManagedRestoreRoleV1,
    TenantRootProtocolDigestV1, TenantRootShareEpoch, TENANT_ROOT_MAX_LIFETIME_MS_V1,
};

const TENANT_ROOT_MANAGED_RESTORE_CAPABILITY_DOMAIN_V1: &[u8] =
    b"tenant_root_managed_restore_capability_v1";
const TENANT_ROOT_MANAGED_RESTORE_CAPABILITY_AUTH_DOMAIN_V1: &[u8] =
    b"tenant_root_managed_restore_capability_authentication_v1";
const TENANT_ROOT_MANAGED_RESTORE_OPERATION_V1: &[u8] = b"restore_role_share";
const TENANT_ROOT_MANAGED_RESTORE_ISSUER_KEY_ID_MAX_BYTES_V1: usize = 256;

/// Exact operation authenticated by one managed role-restore capability.
pub const TENANT_ROOT_MANAGED_RESTORE_CAPABILITY_OPERATION_V1: &str = "restore_role_share";

/// Maximum canonical wire size accepted for one managed role-restore capability.
pub const TENANT_ROOT_MANAGED_RESTORE_CAPABILITY_MAX_BYTES_V1: usize = 16 * 1024;

#[derive(Clone, PartialEq, Eq)]
struct TenantRootManagedRestoreCapabilityDataV1 {
    capability: TenantRootManagedRestoreCapabilityV1,
    issuer_key_id: String,
    signature: [u8; 64],
}

impl fmt::Debug for TenantRootManagedRestoreCapabilityDataV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TenantRootManagedRestoreCapabilityDataV1")
            .field("capability", &self.capability)
            .field("issuer_key_id", &self.issuer_key_id)
            .field("signature", &"[redacted]")
            .finish()
    }
}

/// Issuer-signed managed role-restore capability before signature verification.
#[derive(Clone, PartialEq, Eq)]
pub struct TenantRootSignedManagedRestoreCapabilityV1 {
    data: TenantRootManagedRestoreCapabilityDataV1,
}

impl fmt::Debug for TenantRootSignedManagedRestoreCapabilityV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TenantRootSignedManagedRestoreCapabilityV1")
            .field("data", &self.data)
            .finish()
    }
}

impl TenantRootSignedManagedRestoreCapabilityV1 {
    /// Signs one exact lifecycle capability with the control-plane issuer key.
    pub fn sign(
        capability: TenantRootManagedRestoreCapabilityV1,
        issuer_key_id: impl Into<String>,
        issuer_signing_key_bytes: &[u8; 32],
    ) -> RouterAbDerivationResult<Self> {
        let mut data = TenantRootManagedRestoreCapabilityDataV1 {
            capability,
            issuer_key_id: issuer_key_id.into(),
            signature: [0; 64],
        };
        validate_unsigned_data(&data)?;
        let unsigned = unsigned_canonical_bytes(&data)?;
        data.signature = SigningKey::from_bytes(issuer_signing_key_bytes)
            .sign(&authentication_input(&data.issuer_key_id, &unsigned)?)
            .to_bytes();
        validate_data(&data)?;
        let signed = Self { data };
        signed.canonical_bytes()?;
        Ok(signed)
    }

    /// Decodes exactly one canonical signed managed role-restore capability wire.
    pub fn decode_canonical_bytes(bytes: &[u8]) -> RouterAbDerivationResult<Self> {
        if bytes.is_empty() || bytes.len() > TENANT_ROOT_MANAGED_RESTORE_CAPABILITY_MAX_BYTES_V1 {
            return Err(malformed(
                "tenant-root managed-restore capability wire length is invalid",
            ));
        }
        let mut decoder = TenantRootWireDecoderV1::new(bytes);
        decoder.require_field(TENANT_ROOT_MANAGED_RESTORE_CAPABILITY_DOMAIN_V1)?;
        if decoder.field("tenant-root managed-restore capability operation")?
            != TENANT_ROOT_MANAGED_RESTORE_OPERATION_V1
        {
            return Err(malformed(
                "tenant-root managed-restore capability operation is invalid",
            ));
        }
        let capability_digest = TenantRootLifecycleReceiptDigestV1::from_bytes(
            decoder.fixed_field::<32>("tenant-root managed-restore capability digest")?,
        )?;
        let identity_digest = TenantRootIdentityDigestV1::from_bytes(
            decoder.fixed_field::<32>("tenant-root managed-restore capability identity digest")?,
        );
        let custody_lineage = TenantRootCustodyLineageId::from_bytes(
            decoder.fixed_field::<16>("tenant-root managed-restore capability custody lineage")?,
        )?;
        let role = managed_restore_role(decoder.role()?);
        let epoch = TenantRootShareEpoch::new(
            decoder.u64_field("tenant-root managed-restore capability epoch")?,
        )?;
        let activation_receipt_digest =
            TenantRootLifecycleReceiptDigestV1::from_bytes(decoder.fixed_field::<32>(
                "tenant-root managed-restore capability activation receipt digest",
            )?)?;
        let issued_at_ms =
            decoder.u64_field("tenant-root managed-restore capability issue time")?;
        let expires_at_ms = decoder.u64_field("tenant-root managed-restore capability expiry")?;
        let issuer_key_id = decoder.text_field(
            "tenant-root managed-restore capability issuer key id",
            TENANT_ROOT_MANAGED_RESTORE_ISSUER_KEY_ID_MAX_BYTES_V1,
        )?;
        require_tenant_root_identifier(
            "tenant-root managed-restore capability issuer key id",
            &issuer_key_id,
        )?;
        let signature =
            decoder.fixed_field::<64>("tenant-root managed-restore capability signature")?;
        if signature.iter().all(|byte| *byte == 0) {
            return Err(malformed(
                "tenant-root managed-restore capability signature must be nonzero",
            ));
        }
        decoder.finish()?;

        let capability = TenantRootManagedRestoreCapabilityV1::new(
            capability_digest,
            identity_digest,
            custody_lineage,
            role,
            epoch,
            activation_receipt_digest,
            issued_at_ms,
            expires_at_ms,
        )?;
        let signed = Self {
            data: TenantRootManagedRestoreCapabilityDataV1 {
                capability,
                issuer_key_id,
                signature,
            },
        };
        validate_data(&signed.data)?;
        if signed.canonical_bytes()? != bytes {
            return Err(malformed(
                "tenant-root managed-restore capability wire is not canonical",
            ));
        }
        Ok(signed)
    }

    /// Decodes and verifies one canonical managed role-restore capability wire.
    pub fn decode_and_verify_canonical_bytes(
        bytes: &[u8],
        expected_state: &TenantRootManagedRestoreRoleUnavailableV1,
        expected_issuer_key_id: &str,
        trusted_issuer_verifying_key: &[u8; 32],
    ) -> RouterAbDerivationResult<VerifiedTenantRootManagedRestoreCapabilityV1> {
        Self::decode_canonical_bytes(bytes)?.verify(
            expected_state,
            expected_issuer_key_id,
            trusted_issuer_verifying_key,
        )
    }

    /// Returns the exact operation authenticated by this capability.
    pub const fn operation(&self) -> &'static str {
        TENANT_ROOT_MANAGED_RESTORE_CAPABILITY_OPERATION_V1
    }

    /// Returns the lifecycle capability carried by this signed transport.
    pub const fn capability(&self) -> &TenantRootManagedRestoreCapabilityV1 {
        &self.data.capability
    }

    /// Returns the one-use lifecycle capability digest.
    pub const fn capability_digest(&self) -> TenantRootLifecycleReceiptDigestV1 {
        self.data.capability.digest()
    }

    /// Returns the issuer signing-key identifier.
    pub fn issuer_key_id(&self) -> &str {
        &self.data.issuer_key_id
    }

    /// Returns the exact canonical signed wire bytes.
    pub fn canonical_bytes(&self) -> RouterAbDerivationResult<Vec<u8>> {
        let unsigned = unsigned_canonical_bytes(&self.data)?;
        canonical_bytes_from_unsigned(unsigned, &self.data.signature)
    }

    /// Returns the digest of the exact canonical signed wire bytes.
    pub fn digest(&self) -> RouterAbDerivationResult<TenantRootProtocolDigestV1> {
        TenantRootProtocolDigestV1::from_bytes(Sha256::digest(self.canonical_bytes()?).into())
    }

    /// Verifies issuer signature and exact current managed-restore lifecycle binding.
    pub fn verify(
        &self,
        expected_state: &TenantRootManagedRestoreRoleUnavailableV1,
        expected_issuer_key_id: &str,
        trusted_issuer_verifying_key: &[u8; 32],
    ) -> RouterAbDerivationResult<VerifiedTenantRootManagedRestoreCapabilityV1> {
        validate_data(&self.data)?;
        require_tenant_root_identifier(
            "tenant-root managed-restore expected issuer key id",
            expected_issuer_key_id,
        )?;
        if self.data.issuer_key_id != expected_issuer_key_id {
            return Err(replay_mismatch(
                "tenant-root managed-restore capability issuer key id does not match its expected issuer",
            ));
        }
        expected_state.validate_capability_for_transport(&self.data.capability)?;

        let verifying_key =
            VerifyingKey::from_bytes(trusted_issuer_verifying_key).map_err(|_| {
                verification_failed("tenant-root managed-restore issuer key is invalid")
            })?;
        let unsigned = unsigned_canonical_bytes(&self.data)?;
        verifying_key
            .verify_strict(
                &authentication_input(&self.data.issuer_key_id, &unsigned)?,
                &Signature::from_bytes(&self.data.signature),
            )
            .map_err(|_| {
                verification_failed("tenant-root managed-restore capability signature is invalid")
            })?;
        let canonical_bytes = canonical_bytes_from_unsigned(unsigned, &self.data.signature)?;
        let digest =
            TenantRootProtocolDigestV1::from_bytes(Sha256::digest(&canonical_bytes).into())?;
        Ok(VerifiedTenantRootManagedRestoreCapabilityV1 {
            capability: self.data.capability.clone(),
            issuer_key_id: self.data.issuer_key_id.clone(),
            canonical_bytes,
            digest,
        })
    }
}

/// Signature-verified managed role-restore capability.
///
/// This token is intentionally neither cloneable nor serializable. A caller
/// must hold the result of issuer verification while beginning the restore.
pub struct VerifiedTenantRootManagedRestoreCapabilityV1 {
    capability: TenantRootManagedRestoreCapabilityV1,
    issuer_key_id: String,
    canonical_bytes: Vec<u8>,
    digest: TenantRootProtocolDigestV1,
}

impl fmt::Debug for VerifiedTenantRootManagedRestoreCapabilityV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedTenantRootManagedRestoreCapabilityV1")
            .field("capability", &self.capability)
            .field("issuer_key_id", &self.issuer_key_id)
            .field("digest", &self.digest)
            .field("canonical_bytes", &"[public bytes]")
            .finish()
    }
}

impl VerifiedTenantRootManagedRestoreCapabilityV1 {
    /// Returns the exact operation authenticated by this token.
    pub const fn operation(&self) -> &'static str {
        TENANT_ROOT_MANAGED_RESTORE_CAPABILITY_OPERATION_V1
    }

    /// Returns the verified lifecycle capability.
    pub const fn capability(&self) -> &TenantRootManagedRestoreCapabilityV1 {
        &self.capability
    }

    /// Returns the verified one-use lifecycle capability digest.
    pub const fn capability_digest(&self) -> TenantRootLifecycleReceiptDigestV1 {
        self.capability.digest()
    }

    /// Returns the verified tenant-root identity digest.
    pub const fn identity_digest(&self) -> TenantRootIdentityDigestV1 {
        self.capability.identity_digest()
    }

    /// Returns the verified custody lineage.
    pub const fn custody_lineage(&self) -> TenantRootCustodyLineageId {
        self.capability.custody_lineage()
    }

    /// Returns the verified restore role.
    pub const fn role(&self) -> TenantRootManagedRestoreRoleV1 {
        self.capability.role()
    }

    /// Returns the verified active epoch.
    pub const fn epoch(&self) -> TenantRootShareEpoch {
        self.capability.epoch()
    }

    /// Returns the verified active activation receipt digest.
    pub const fn activation_receipt_digest(&self) -> TenantRootLifecycleReceiptDigestV1 {
        self.capability.activation_receipt_digest()
    }

    /// Returns the verified issue timestamp.
    pub const fn issued_at_ms(&self) -> u64 {
        self.capability.issued_at_ms()
    }

    /// Returns the verified expiry timestamp.
    pub const fn expires_at_ms(&self) -> u64 {
        self.capability.expires_at_ms()
    }

    /// Returns the verified issuer signing-key identifier.
    pub fn issuer_key_id(&self) -> &str {
        &self.issuer_key_id
    }

    /// Returns the exact canonical signed wire accepted by verification.
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    /// Returns the digest of the exact canonical signed wire accepted by verification.
    pub const fn digest(&self) -> TenantRootProtocolDigestV1 {
        self.digest
    }

    /// Requires `now_ms` to be within the inclusive issue-to-expiry window.
    pub fn require_fresh(&self, now_ms: u64) -> RouterAbDerivationResult<()> {
        if now_ms < self.issued_at_ms() || now_ms > self.expires_at_ms() {
            return Err(replay_mismatch(
                "tenant-root managed-restore capability is outside its freshness window",
            ));
        }
        Ok(())
    }

    /// Consumes verification and returns the exact lifecycle capability.
    pub fn into_capability(self) -> TenantRootManagedRestoreCapabilityV1 {
        self.capability
    }

    /// Consumes verification and returns the exact canonical signed wire bytes.
    pub fn into_canonical_bytes(self) -> Vec<u8> {
        self.canonical_bytes
    }
}

fn validate_data(data: &TenantRootManagedRestoreCapabilityDataV1) -> RouterAbDerivationResult<()> {
    validate_unsigned_data(data)?;
    if data.signature.iter().all(|byte| *byte == 0) {
        return Err(malformed(
            "tenant-root managed-restore capability signature must be nonzero",
        ));
    }
    Ok(())
}

fn validate_unsigned_data(
    data: &TenantRootManagedRestoreCapabilityDataV1,
) -> RouterAbDerivationResult<()> {
    let capability = &data.capability;
    if capability
        .identity_digest()
        .as_bytes()
        .iter()
        .all(|byte| *byte == 0)
    {
        return Err(malformed(
            "tenant-root managed-restore capability identity digest must be nonzero",
        ));
    }
    if capability.expires_at_ms() - capability.issued_at_ms() > TENANT_ROOT_MAX_LIFETIME_MS_V1 {
        return Err(malformed(
            "tenant-root managed-restore capability lifetime exceeds the frozen maximum window",
        ));
    }
    require_tenant_root_identifier(
        "tenant-root managed-restore capability issuer key id",
        &data.issuer_key_id,
    )?;
    if data.issuer_key_id.len() > TENANT_ROOT_MANAGED_RESTORE_ISSUER_KEY_ID_MAX_BYTES_V1 {
        return Err(malformed(
            "tenant-root managed-restore capability issuer key id is too long",
        ));
    }
    Ok(())
}

fn unsigned_canonical_bytes(
    data: &TenantRootManagedRestoreCapabilityDataV1,
) -> RouterAbDerivationResult<Vec<u8>> {
    validate_unsigned_data(data)?;
    let capability = &data.capability;
    let mut bytes = Vec::new();
    push_field(&mut bytes, TENANT_ROOT_MANAGED_RESTORE_CAPABILITY_DOMAIN_V1)?;
    push_field(&mut bytes, TENANT_ROOT_MANAGED_RESTORE_OPERATION_V1)?;
    push_field(&mut bytes, capability.digest().as_bytes())?;
    push_field(&mut bytes, capability.identity_digest().as_bytes())?;
    push_field(&mut bytes, capability.custody_lineage().as_bytes())?;
    push_role(&mut bytes, capability.role())?;
    push_field(&mut bytes, &capability.epoch().get().get().to_be_bytes())?;
    push_field(
        &mut bytes,
        capability.activation_receipt_digest().as_bytes(),
    )?;
    push_field(&mut bytes, &capability.issued_at_ms().to_be_bytes())?;
    push_field(&mut bytes, &capability.expires_at_ms().to_be_bytes())?;
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
        "tenant-root managed-restore capability issuer key id",
        issuer_key_id,
    )?;
    let mut bytes = Vec::new();
    push_field(
        &mut bytes,
        TENANT_ROOT_MANAGED_RESTORE_CAPABILITY_AUTH_DOMAIN_V1,
    )?;
    push_field(&mut bytes, issuer_key_id.as_bytes())?;
    push_field(&mut bytes, unsigned)?;
    Ok(bytes)
}

fn push_role(
    bytes: &mut Vec<u8>,
    role: TenantRootManagedRestoreRoleV1,
) -> RouterAbDerivationResult<()> {
    let (label, share_id): (&[u8], u16) = match role {
        TenantRootManagedRestoreRoleV1::DeriverA => (b"deriver_a", 1),
        TenantRootManagedRestoreRoleV1::DeriverB => (b"deriver_b", 2),
    };
    push_field(bytes, label)?;
    push_field(bytes, &share_id.to_be_bytes())
}

fn managed_restore_role(role: TwoPartyDeriverRole) -> TenantRootManagedRestoreRoleV1 {
    match role {
        TwoPartyDeriverRole::DeriverA => TenantRootManagedRestoreRoleV1::DeriverA,
        TwoPartyDeriverRole::DeriverB => TenantRootManagedRestoreRoleV1::DeriverB,
    }
}

fn push_field(out: &mut Vec<u8>, value: &[u8]) -> RouterAbDerivationResult<()> {
    if value.is_empty() {
        return Err(RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::EmptyField,
            "tenant-root managed-restore capability field is required",
        ));
    }
    let length = u32::try_from(value.len())
        .map_err(|_| malformed("tenant-root managed-restore capability field is too long"))?;
    let new_len = out
        .len()
        .checked_add(4)
        .and_then(|length| length.checked_add(value.len()))
        .ok_or_else(|| malformed("tenant-root managed-restore capability wire length overflows"))?;
    if new_len > TENANT_ROOT_MANAGED_RESTORE_CAPABILITY_MAX_BYTES_V1 {
        return Err(malformed(
            "tenant-root managed-restore capability wire is too long",
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
