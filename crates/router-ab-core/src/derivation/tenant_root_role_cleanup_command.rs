//! Issuer-authorized cleanup of one tenant-root role share.
//!
//! Cleanup is a one-use authorization for one exact row state. Pending cleanup
//! names the ceremony that produced the stranded row. Retired cleanup names
//! the retired row and the exact active successor that must still be present.
//! The operation discriminator is part of the signed canonical wire, so a
//! command for one lifecycle state cannot authorize the other.

use core::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use threshold_prf::TwoPartyDeriverRole;

use super::{
    require_tenant_root_identifier, RouterAbDerivationError, RouterAbDerivationErrorCode,
    RouterAbDerivationResult, TenantRootCeremonyNonceV1, TenantRootCeremonySessionIdV1,
    TenantRootControlPlaneAuthorityIdV1, TenantRootCustodyLineageId, TenantRootIdentityDigestV1,
    TenantRootProtocolDigestV1, TenantRootShareEpoch, TENANT_ROOT_MAX_LIFETIME_MS_V1,
};

const TENANT_ROOT_ROLE_CLEANUP_COMMAND_DOMAIN_V1: &[u8] = b"tenant_root_role_cleanup_command_v1";
const TENANT_ROOT_ROLE_CLEANUP_COMMAND_AUTH_DOMAIN_V1: &[u8] =
    b"tenant_root_role_cleanup_command_authentication_v1";
const TENANT_ROOT_ROLE_CLEANUP_PENDING_OPERATION_V1: &[u8] = b"cleanup_pending_share";
const TENANT_ROOT_ROLE_CLEANUP_RETIRED_OPERATION_V1: &[u8] = b"cleanup_retired_share";
const TENANT_ROOT_ROLE_CLEANUP_ISSUER_KEY_ID_MAX_BYTES_V1: usize = 256;

/// Exact pending-cleanup operation authenticated by a cleanup command.
pub const TENANT_ROOT_ROLE_CLEANUP_COMMAND_OPERATION_V1: &str = "cleanup_pending_share";

/// Exact retired-cleanup operation authenticated by a cleanup command.
pub const TENANT_ROOT_ROLE_CLEANUP_RETIRED_COMMAND_OPERATION_V1: &str = "cleanup_retired_share";

/// Maximum canonical wire size accepted for one cleanup command.
pub const TENANT_ROOT_ROLE_CLEANUP_COMMAND_MAX_BYTES_V1: usize = 16 * 1024;

/// Exact row state authorized for cleanup.
///
/// The variants deliberately carry different fields. Pending cleanup is tied
/// to its ceremony evidence; retired cleanup is tied to both sides of the
/// active/retired row transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TenantRootRoleCleanupTargetV1 {
    /// A stranded row that never activated.
    Pending {
        identity_digest: TenantRootIdentityDigestV1,
        custody_lineage: TenantRootCustodyLineageId,
        role: TwoPartyDeriverRole,
        epoch: TenantRootShareEpoch,
        expected_row_revision: i64,
        session_id: TenantRootCeremonySessionIdV1,
        ceremony_nonce: TenantRootCeremonyNonceV1,
        installation_evidence_digest: TenantRootProtocolDigestV1,
    },
    /// A retired row whose exact active successor is still expected.
    Retired {
        identity_digest: TenantRootIdentityDigestV1,
        custody_lineage: TenantRootCustodyLineageId,
        role: TwoPartyDeriverRole,
        retired_epoch: TenantRootShareEpoch,
        expected_retired_revision: i64,
        expected_active_epoch: TenantRootShareEpoch,
        expected_active_revision: i64,
    },
}

impl TenantRootRoleCleanupTargetV1 {
    /// Returns the role whose row is named by this target.
    pub const fn role(&self) -> TwoPartyDeriverRole {
        match self {
            Self::Pending { role, .. } | Self::Retired { role, .. } => *role,
        }
    }

    /// Returns the tenant identity digest named by this target.
    pub const fn identity_digest(&self) -> TenantRootIdentityDigestV1 {
        match self {
            Self::Pending {
                identity_digest, ..
            }
            | Self::Retired {
                identity_digest, ..
            } => *identity_digest,
        }
    }

    /// Returns the custody lineage named by this target.
    pub const fn custody_lineage(&self) -> TenantRootCustodyLineageId {
        match self {
            Self::Pending {
                custody_lineage, ..
            }
            | Self::Retired {
                custody_lineage, ..
            } => *custody_lineage,
        }
    }

    /// Returns the row epoch named by this target.
    pub const fn epoch(&self) -> TenantRootShareEpoch {
        match self {
            Self::Pending { epoch, .. } => *epoch,
            Self::Retired { retired_epoch, .. } => *retired_epoch,
        }
    }

    /// Returns the exact revision of the row that may be deleted.
    pub const fn expected_row_revision(&self) -> i64 {
        match self {
            Self::Pending {
                expected_row_revision,
                ..
            } => *expected_row_revision,
            Self::Retired {
                expected_retired_revision,
                ..
            } => *expected_retired_revision,
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
struct TenantRootRoleCleanupCommandDataV1 {
    target: TenantRootRoleCleanupTargetV1,
    authority_id: TenantRootControlPlaneAuthorityIdV1,
    nonce: TenantRootCeremonyNonceV1,
    issued_at_ms: u64,
    expires_at_ms: u64,
    issuer_key_id: String,
    signature: [u8; 64],
}

impl fmt::Debug for TenantRootRoleCleanupCommandDataV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TenantRootRoleCleanupCommandDataV1")
            .field("target", &self.target)
            .field("authority_id", &self.authority_id)
            .field("nonce", &self.nonce)
            .field("issued_at_ms", &self.issued_at_ms)
            .field("expires_at_ms", &self.expires_at_ms)
            .field("issuer_key_id", &self.issuer_key_id)
            .field("signature", &"[redacted]")
            .finish()
    }
}

/// Issuer-signed cleanup command before signature verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantRootRoleCleanupCommandV1 {
    data: TenantRootRoleCleanupCommandDataV1,
}

impl TenantRootRoleCleanupCommandV1 {
    /// Signs one exact pending or retired cleanup authorization.
    pub fn sign(
        target: &TenantRootRoleCleanupTargetV1,
        authority_id: TenantRootControlPlaneAuthorityIdV1,
        nonce: TenantRootCeremonyNonceV1,
        issued_at_ms: u64,
        expires_at_ms: u64,
        issuer_key_id: impl Into<String>,
        issuer_signing_key_bytes: &[u8; 32],
    ) -> RouterAbDerivationResult<Self> {
        let mut data = TenantRootRoleCleanupCommandDataV1 {
            target: target.clone(),
            authority_id,
            nonce,
            issued_at_ms,
            expires_at_ms,
            issuer_key_id: issuer_key_id.into(),
            signature: [0; 64],
        };
        validate_unsigned_data(&data)?;
        let unsigned = unsigned_canonical_bytes(&data)?;
        data.signature = SigningKey::from_bytes(issuer_signing_key_bytes)
            .sign(&authentication_input(&data.issuer_key_id, &unsigned)?)
            .to_bytes();
        validate_data(&data)?;
        let command = Self { data };
        command.canonical_bytes()?;
        Ok(command)
    }

    /// Decodes exactly one canonical signed cleanup command wire.
    pub fn decode_canonical_bytes(bytes: &[u8]) -> RouterAbDerivationResult<Self> {
        if bytes.is_empty() || bytes.len() > TENANT_ROOT_ROLE_CLEANUP_COMMAND_MAX_BYTES_V1 {
            return Err(malformed(
                "tenant-root role cleanup command wire length is invalid",
            ));
        }
        let mut decoder = CleanupCommandWireDecoderV1::new(bytes);
        decoder.require_field(TENANT_ROOT_ROLE_CLEANUP_COMMAND_DOMAIN_V1)?;
        let operation = decoder.field("tenant-root role cleanup command operation")?;
        let identity_digest = TenantRootIdentityDigestV1::from_bytes(
            decoder.fixed_field::<32>("tenant-root role cleanup command identity digest")?,
        );
        let custody_lineage = TenantRootCustodyLineageId::from_bytes(
            decoder.fixed_field::<16>("tenant-root role cleanup command custody lineage")?,
        )?;
        let role = decoder.role()?;
        let target = match operation {
            TENANT_ROOT_ROLE_CLEANUP_PENDING_OPERATION_V1 => {
                let epoch = TenantRootShareEpoch::new(
                    decoder.u64_field("tenant-root role cleanup command epoch")?,
                )?;
                let expected_row_revision =
                    decoder.revision_field("tenant-root role cleanup command row revision")?;
                let session_id = TenantRootCeremonySessionIdV1::from_bytes(
                    decoder.fixed_field::<16>("tenant-root role cleanup command session id")?,
                )?;
                let ceremony_nonce = TenantRootCeremonyNonceV1::from_bytes(
                    decoder.fixed_field::<32>("tenant-root role cleanup command ceremony nonce")?,
                )?;
                let installation_evidence_digest = TenantRootProtocolDigestV1::from_bytes(
                    decoder
                        .fixed_field::<32>("tenant-root role cleanup command evidence digest")?,
                )?;
                TenantRootRoleCleanupTargetV1::Pending {
                    identity_digest,
                    custody_lineage,
                    role,
                    epoch,
                    expected_row_revision,
                    session_id,
                    ceremony_nonce,
                    installation_evidence_digest,
                }
            }
            TENANT_ROOT_ROLE_CLEANUP_RETIRED_OPERATION_V1 => {
                let retired_epoch = TenantRootShareEpoch::new(
                    decoder.u64_field("tenant-root role cleanup command retired epoch")?,
                )?;
                let expected_retired_revision = decoder
                    .revision_field("tenant-root role cleanup command retired row revision")?;
                let expected_active_epoch = TenantRootShareEpoch::new(
                    decoder.u64_field("tenant-root role cleanup command active successor epoch")?,
                )?;
                let expected_active_revision = decoder
                    .revision_field("tenant-root role cleanup command active successor revision")?;
                TenantRootRoleCleanupTargetV1::Retired {
                    identity_digest,
                    custody_lineage,
                    role,
                    retired_epoch,
                    expected_retired_revision,
                    expected_active_epoch,
                    expected_active_revision,
                }
            }
            _ => {
                return Err(malformed(
                    "tenant-root role cleanup command operation is invalid",
                ));
            }
        };
        let authority_id = TenantRootControlPlaneAuthorityIdV1::from_bytes(
            decoder.fixed_field::<32>("tenant-root role cleanup command authority id")?,
        );
        let nonce = TenantRootCeremonyNonceV1::from_bytes(
            decoder.fixed_field::<32>("tenant-root role cleanup command nonce")?,
        )?;
        let issued_at_ms = decoder.u64_field("tenant-root role cleanup command issue time")?;
        let expires_at_ms = decoder.u64_field("tenant-root role cleanup command expiry")?;
        let issuer_key_id = decoder.text_field(
            "tenant-root role cleanup command issuer key id",
            TENANT_ROOT_ROLE_CLEANUP_ISSUER_KEY_ID_MAX_BYTES_V1,
        )?;
        let signature = decoder.fixed_field::<64>("tenant-root role cleanup command signature")?;
        decoder.finish()?;
        let data = TenantRootRoleCleanupCommandDataV1 {
            target,
            authority_id,
            nonce,
            issued_at_ms,
            expires_at_ms,
            issuer_key_id,
            signature,
        };
        validate_data(&data)?;
        let command = Self { data };
        if command.canonical_bytes()? != bytes {
            return Err(malformed(
                "tenant-root role cleanup command wire is not canonical",
            ));
        }
        Ok(command)
    }

    /// Returns the target row state claimed by this command.
    ///
    /// This projection is untrusted until [`Self::verify`] succeeds. Use it
    /// only to locate the candidate local row before verification; it grants
    /// no authorization to clean that row.
    pub fn claimed_target(&self) -> TenantRootRoleCleanupTargetV1 {
        self.data.target.clone()
    }

    /// Returns the operation discriminator authenticated by this command.
    pub fn operation(&self) -> &'static str {
        operation_for_target(&self.data.target)
    }

    /// Returns the issuer key id this command names.
    pub fn issuer_key_id(&self) -> &str {
        &self.data.issuer_key_id
    }

    /// Returns the exact canonical signed command bytes.
    pub fn canonical_bytes(&self) -> RouterAbDerivationResult<Vec<u8>> {
        let unsigned = unsigned_canonical_bytes(&self.data)?;
        canonical_bytes_from_unsigned(unsigned, &self.data.signature)
    }

    /// Returns the digest of the exact canonical signed command bytes.
    pub fn digest(&self) -> RouterAbDerivationResult<TenantRootProtocolDigestV1> {
        TenantRootProtocolDigestV1::from_bytes(Sha256::digest(self.canonical_bytes()?).into())
    }

    /// Verifies this command against the exact row state a role actually holds.
    ///
    /// `expected_role` and `expected_authority_id` are the verifier's own,
    /// never the command's. The complete discriminated target is compared
    /// before the issuer signature is accepted as a cleanup capability.
    pub fn verify(
        &self,
        expected_target: &TenantRootRoleCleanupTargetV1,
        expected_role: TwoPartyDeriverRole,
        expected_authority_id: TenantRootControlPlaneAuthorityIdV1,
        expected_issuer_key_id: &str,
        trusted_issuer_verifying_key: &[u8; 32],
    ) -> RouterAbDerivationResult<VerifiedTenantRootRoleCleanupCommandV1> {
        validate_data(&self.data)?;
        require_tenant_root_identifier(
            "tenant-root role cleanup command expected issuer key id",
            expected_issuer_key_id,
        )?;
        if self.data.target.role() != expected_role {
            return Err(replay_mismatch(
                "tenant-root role cleanup command names a different role",
            ));
        }
        if self.data.authority_id != expected_authority_id {
            return Err(replay_mismatch(
                "tenant-root role cleanup command names a different control-plane authority",
            ));
        }
        if self.data.target != *expected_target {
            return Err(replay_mismatch(
                "tenant-root role cleanup command does not name the expected row state",
            ));
        }
        if self.data.issuer_key_id != expected_issuer_key_id {
            return Err(replay_mismatch(
                "tenant-root role cleanup command issuer key id does not match its expected issuer",
            ));
        }
        let verifying_key = VerifyingKey::from_bytes(trusted_issuer_verifying_key)
            .map_err(|_| verification_failed("tenant-root role cleanup issuer key is invalid"))?;
        let unsigned = unsigned_canonical_bytes(&self.data)?;
        verifying_key
            .verify_strict(
                &authentication_input(&self.data.issuer_key_id, &unsigned)?,
                &Signature::from_bytes(&self.data.signature),
            )
            .map_err(|_| {
                verification_failed("tenant-root role cleanup command signature is invalid")
            })?;
        Ok(VerifiedTenantRootRoleCleanupCommandV1 {
            data: self.data.clone(),
        })
    }
}

/// An authenticated cleanup authorization.
///
/// Deliberately neither cloneable nor serializable: it authorizes destroying a
/// share, so it is a capability held briefly, not a record to pass around.
pub struct VerifiedTenantRootRoleCleanupCommandV1 {
    data: TenantRootRoleCleanupCommandDataV1,
}

impl fmt::Debug for VerifiedTenantRootRoleCleanupCommandV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedTenantRootRoleCleanupCommandV1")
            .field("data", &self.data)
            .finish()
    }
}

impl VerifiedTenantRootRoleCleanupCommandV1 {
    /// Returns the exact discriminated target authorized for cleanup.
    pub fn target(&self) -> &TenantRootRoleCleanupTargetV1 {
        &self.data.target
    }

    /// Returns the operation discriminator authenticated by this command.
    pub fn operation(&self) -> &'static str {
        operation_for_target(&self.data.target)
    }

    /// Returns the role authorized to clean.
    pub const fn role(&self) -> TwoPartyDeriverRole {
        self.data.target.role()
    }

    /// Returns the epoch of the row this authorizes cleaning.
    pub const fn epoch(&self) -> TenantRootShareEpoch {
        self.data.target.epoch()
    }

    /// Returns the exact revision of the row this authorizes cleaning.
    pub const fn expected_row_revision(&self) -> i64 {
        self.data.target.expected_row_revision()
    }

    /// Returns the tenant identity digest.
    pub const fn identity_digest(&self) -> TenantRootIdentityDigestV1 {
        self.data.target.identity_digest()
    }

    /// Returns the custody lineage.
    pub const fn custody_lineage(&self) -> TenantRootCustodyLineageId {
        self.data.target.custody_lineage()
    }

    /// Returns the one-use nonce.
    pub const fn nonce(&self) -> TenantRootCeremonyNonceV1 {
        self.data.nonce
    }

    /// Returns the pending target's installation-evidence digest.
    pub fn pending_installation_evidence_digest(
        &self,
    ) -> RouterAbDerivationResult<TenantRootProtocolDigestV1> {
        match &self.data.target {
            TenantRootRoleCleanupTargetV1::Pending {
                installation_evidence_digest,
                ..
            } => Ok(*installation_evidence_digest),
            TenantRootRoleCleanupTargetV1::Retired { .. } => Err(replay_mismatch(
                "retired cleanup authorization has no pending installation evidence",
            )),
        }
    }

    /// Returns the authenticated issue timestamp.
    pub const fn issued_at_ms(&self) -> u64 {
        self.data.issued_at_ms
    }

    /// Returns the exact canonical signed command bytes.
    pub fn canonical_bytes(&self) -> RouterAbDerivationResult<Vec<u8>> {
        let unsigned = unsigned_canonical_bytes(&self.data)?;
        canonical_bytes_from_unsigned(unsigned, &self.data.signature)
    }

    /// Returns the digest of the exact verified signed authorization bytes.
    pub fn digest(&self) -> RouterAbDerivationResult<TenantRootProtocolDigestV1> {
        TenantRootProtocolDigestV1::from_bytes(Sha256::digest(self.canonical_bytes()?).into())
    }

    /// Requires `now_ms` to fall inside the authorized window.
    pub fn require_fresh(&self, now_ms: u64) -> RouterAbDerivationResult<()> {
        if now_ms <= self.data.issued_at_ms || now_ms >= self.data.expires_at_ms {
            return Err(malformed(
                "tenant-root role cleanup command is outside its freshness window",
            ));
        }
        Ok(())
    }
}

fn operation_for_target(target: &TenantRootRoleCleanupTargetV1) -> &'static str {
    match target {
        TenantRootRoleCleanupTargetV1::Pending { .. } => {
            TENANT_ROOT_ROLE_CLEANUP_COMMAND_OPERATION_V1
        }
        TenantRootRoleCleanupTargetV1::Retired { .. } => {
            TENANT_ROOT_ROLE_CLEANUP_RETIRED_COMMAND_OPERATION_V1
        }
    }
}

fn operation_bytes_for_target(target: &TenantRootRoleCleanupTargetV1) -> &'static [u8] {
    match target {
        TenantRootRoleCleanupTargetV1::Pending { .. } => {
            TENANT_ROOT_ROLE_CLEANUP_PENDING_OPERATION_V1
        }
        TenantRootRoleCleanupTargetV1::Retired { .. } => {
            TENANT_ROOT_ROLE_CLEANUP_RETIRED_OPERATION_V1
        }
    }
}

fn validate_data(data: &TenantRootRoleCleanupCommandDataV1) -> RouterAbDerivationResult<()> {
    validate_unsigned_data(data)?;
    if data.signature.iter().all(|byte| *byte == 0) {
        return Err(malformed(
            "tenant-root role cleanup command signature must be nonzero",
        ));
    }
    Ok(())
}

fn validate_unsigned_data(
    data: &TenantRootRoleCleanupCommandDataV1,
) -> RouterAbDerivationResult<()> {
    if data.issued_at_ms == 0 || data.expires_at_ms <= data.issued_at_ms {
        return Err(malformed(
            "tenant-root role cleanup command expiry must follow a non-zero issue time",
        ));
    }
    if data.expires_at_ms - data.issued_at_ms > TENANT_ROOT_MAX_LIFETIME_MS_V1 {
        return Err(malformed(
            "tenant-root role cleanup command lifetime exceeds the frozen maximum window",
        ));
    }
    match &data.target {
        TenantRootRoleCleanupTargetV1::Pending {
            expected_row_revision,
            ..
        } => {
            require_positive_revision(*expected_row_revision, "pending row revision")?;
        }
        TenantRootRoleCleanupTargetV1::Retired {
            retired_epoch,
            expected_retired_revision,
            expected_active_epoch,
            expected_active_revision,
            ..
        } => {
            require_positive_revision(*expected_retired_revision, "retired row revision")?;
            require_positive_revision(*expected_active_revision, "active successor revision")?;
            if retired_epoch.next()? != *expected_active_epoch {
                return Err(malformed(
                    "tenant-root role cleanup command retired and active epochs must be adjacent",
                ));
            }
        }
    }
    require_tenant_root_identifier(
        "tenant-root role cleanup command issuer key id",
        &data.issuer_key_id,
    )?;
    if data.issuer_key_id.len() > TENANT_ROOT_ROLE_CLEANUP_ISSUER_KEY_ID_MAX_BYTES_V1 {
        return Err(malformed(
            "tenant-root role cleanup command issuer key id is too long",
        ));
    }
    Ok(())
}

fn require_positive_revision(
    revision: i64,
    row_kind: &'static str,
) -> RouterAbDerivationResult<()> {
    if revision <= 0 {
        return Err(malformed(format!(
            "tenant-root role cleanup command {row_kind} must be positive",
        )));
    }
    Ok(())
}

fn unsigned_canonical_bytes(
    data: &TenantRootRoleCleanupCommandDataV1,
) -> RouterAbDerivationResult<Vec<u8>> {
    let mut bytes = Vec::new();
    push_field(&mut bytes, TENANT_ROOT_ROLE_CLEANUP_COMMAND_DOMAIN_V1)?;
    push_field(&mut bytes, operation_bytes_for_target(&data.target))?;
    push_field(&mut bytes, data.target.identity_digest().as_bytes())?;
    push_field(&mut bytes, data.target.custody_lineage().as_bytes())?;
    push_role(&mut bytes, data.target.role())?;
    match &data.target {
        TenantRootRoleCleanupTargetV1::Pending {
            epoch,
            expected_row_revision,
            session_id,
            ceremony_nonce,
            installation_evidence_digest,
            ..
        } => {
            push_field(&mut bytes, &epoch.get().get().to_be_bytes())?;
            push_revision(&mut bytes, *expected_row_revision)?;
            push_field(&mut bytes, session_id.as_bytes())?;
            push_field(&mut bytes, ceremony_nonce.as_bytes())?;
            push_field(&mut bytes, installation_evidence_digest.as_bytes())?;
        }
        TenantRootRoleCleanupTargetV1::Retired {
            retired_epoch,
            expected_retired_revision,
            expected_active_epoch,
            expected_active_revision,
            ..
        } => {
            push_field(&mut bytes, &retired_epoch.get().get().to_be_bytes())?;
            push_revision(&mut bytes, *expected_retired_revision)?;
            push_field(&mut bytes, &expected_active_epoch.get().get().to_be_bytes())?;
            push_revision(&mut bytes, *expected_active_revision)?;
        }
    }
    push_field(&mut bytes, data.authority_id.as_bytes())?;
    push_field(&mut bytes, data.nonce.as_bytes())?;
    push_field(&mut bytes, &data.issued_at_ms.to_be_bytes())?;
    push_field(&mut bytes, &data.expires_at_ms.to_be_bytes())?;
    push_field(&mut bytes, data.issuer_key_id.as_bytes())?;
    Ok(bytes)
}

fn push_revision(out: &mut Vec<u8>, revision: i64) -> RouterAbDerivationResult<()> {
    let revision = u64::try_from(revision)
        .map_err(|_| malformed("tenant-root role cleanup command row revision is invalid"))?;
    push_field(out, &revision.to_be_bytes())
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
        "tenant-root role cleanup command issuer key id",
        issuer_key_id,
    )?;
    let mut bytes = Vec::new();
    push_field(&mut bytes, TENANT_ROOT_ROLE_CLEANUP_COMMAND_AUTH_DOMAIN_V1)?;
    push_field(&mut bytes, issuer_key_id.as_bytes())?;
    push_field(&mut bytes, unsigned)?;
    Ok(bytes)
}

fn push_role(bytes: &mut Vec<u8>, role: TwoPartyDeriverRole) -> RouterAbDerivationResult<()> {
    let (label, share_id): (&[u8], u16) = match role {
        TwoPartyDeriverRole::DeriverA => (b"deriver_a", 1),
        TwoPartyDeriverRole::DeriverB => (b"deriver_b", 2),
    };
    push_field(bytes, label)?;
    push_field(bytes, &share_id.to_be_bytes())
}

fn push_field(out: &mut Vec<u8>, value: &[u8]) -> RouterAbDerivationResult<()> {
    if value.is_empty() {
        return Err(RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::EmptyField,
            "tenant-root role cleanup command field is required",
        ));
    }
    let length = u32::try_from(value.len())
        .map_err(|_| malformed("tenant-root role cleanup command field is too long"))?;
    let new_len = out
        .len()
        .checked_add(4)
        .and_then(|length| length.checked_add(value.len()))
        .ok_or_else(|| malformed("tenant-root role cleanup command wire length overflows"))?;
    if new_len > TENANT_ROOT_ROLE_CLEANUP_COMMAND_MAX_BYTES_V1 {
        return Err(malformed(
            "tenant-root role cleanup command wire is too long",
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

struct CleanupCommandWireDecoderV1<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> CleanupCommandWireDecoderV1<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn field(&mut self, name: &'static str) -> RouterAbDerivationResult<&'a [u8]> {
        let length_end = self
            .offset
            .checked_add(4)
            .ok_or_else(|| malformed("tenant-root role cleanup wire offset overflows"))?;
        let length_bytes = self
            .bytes
            .get(self.offset..length_end)
            .ok_or_else(|| malformed("tenant-root role cleanup field length is truncated"))?;
        let length = u32::from_be_bytes(
            length_bytes
                .try_into()
                .expect("fixed four-byte cleanup field length"),
        ) as usize;
        let value_end = length_end
            .checked_add(length)
            .ok_or_else(|| malformed("tenant-root role cleanup field length overflows"))?;
        let value = self
            .bytes
            .get(length_end..value_end)
            .ok_or_else(|| malformed("tenant-root role cleanup field is truncated"))?;
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
        if self.field("tenant-root role cleanup command domain")? != expected {
            return Err(malformed(
                "tenant-root role cleanup command domain is invalid",
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
            .map_err(|_| malformed("tenant-root role cleanup fixed field length is invalid"))
    }

    fn u64_field(&mut self, name: &'static str) -> RouterAbDerivationResult<u64> {
        Ok(u64::from_be_bytes(self.fixed_field::<8>(name)?))
    }

    fn revision_field(&mut self, name: &'static str) -> RouterAbDerivationResult<i64> {
        i64::try_from(self.u64_field(name)?)
            .map_err(|_| malformed("tenant-root role cleanup command row revision is out of range"))
    }

    fn text_field(
        &mut self,
        name: &'static str,
        max_bytes: usize,
    ) -> RouterAbDerivationResult<String> {
        let bytes = self.field(name)?;
        if bytes.len() > max_bytes {
            return Err(malformed("tenant-root role cleanup text field is too long"));
        }
        core::str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|_| malformed("tenant-root role cleanup text field is invalid UTF-8"))
    }

    fn role(&mut self) -> RouterAbDerivationResult<TwoPartyDeriverRole> {
        let label = self.field("tenant-root role cleanup command role")?;
        let share_id = self.fixed_field::<2>("tenant-root role cleanup command role share id")?;
        match (label, u16::from_be_bytes(share_id)) {
            (b"deriver_a", 1) => Ok(TwoPartyDeriverRole::DeriverA),
            (b"deriver_b", 2) => Ok(TwoPartyDeriverRole::DeriverB),
            _ => Err(malformed(
                "tenant-root role cleanup command role encoding is invalid",
            )),
        }
    }

    fn finish(self) -> RouterAbDerivationResult<()> {
        if self.offset != self.bytes.len() {
            return Err(malformed(
                "tenant-root role cleanup command wire has trailing bytes",
            ));
        }
        Ok(())
    }
}
