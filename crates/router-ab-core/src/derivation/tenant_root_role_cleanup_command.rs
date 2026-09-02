//! Authorized cleanup of one role's pending share.
//!
//! A pending share can be stranded: the peer role completed its insertion and
//! the initiating role then lost the response, so a durable pending row exists
//! for a ceremony that will never finish. Clearing it must be an authorized,
//! one-use act, not an age heuristic — a row that merely looks old may belong
//! to a ceremony still in flight.
//!
//! This command is the authorization. The control plane issues it against one
//! exact row: the role that owns it, the tenant and lineage it belongs to, its
//! epoch, its exact revision, the ceremony that created it, and the digest of
//! the installation evidence it carries. A command naming any other row, or a
//! row that has since moved, cannot clean it.
//!
//! It is deliberately a distinct type from the creation command. Reusing a
//! creation command to authorize deletion would let a replayed creation
//! authorization destroy the share it originally created.

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
const TENANT_ROOT_ROLE_CLEANUP_OPERATION_V1: &[u8] = b"cleanup_pending_share";
const TENANT_ROOT_ROLE_CLEANUP_ISSUER_KEY_ID_MAX_BYTES_V1: usize = 256;

/// Exact operation authenticated by a cleanup command.
pub const TENANT_ROOT_ROLE_CLEANUP_COMMAND_OPERATION_V1: &str = "cleanup_pending_share";

/// Maximum canonical wire size accepted for one cleanup command.
pub const TENANT_ROOT_ROLE_CLEANUP_COMMAND_MAX_BYTES_V1: usize = 16 * 1024;

#[derive(Clone, PartialEq, Eq)]
struct TenantRootRoleCleanupCommandDataV1 {
    identity_digest: TenantRootIdentityDigestV1,
    custody_lineage: TenantRootCustodyLineageId,
    role: TwoPartyDeriverRole,
    epoch: TenantRootShareEpoch,
    /// The exact row revision this command may clean. A row that moved on is a
    /// different row, and this command no longer applies to it.
    expected_row_revision: i64,
    session_id: TenantRootCeremonySessionIdV1,
    ceremony_nonce: TenantRootCeremonyNonceV1,
    /// Digest of the installation evidence the stranded row carries.
    installation_evidence_digest: TenantRootProtocolDigestV1,
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
            .field("identity_digest", &self.identity_digest)
            .field("custody_lineage", &self.custody_lineage)
            .field("role", &self.role)
            .field("epoch", &self.epoch)
            .field("expected_row_revision", &self.expected_row_revision)
            .field("session_id", &self.session_id)
            .field("ceremony_nonce", &self.ceremony_nonce)
            .field(
                "installation_evidence_digest",
                &self.installation_evidence_digest,
            )
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

/// Everything the issuer must know to authorize one cleanup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantRootRoleCleanupTargetV1 {
    /// Tenant whose pending row is stranded.
    pub identity_digest: TenantRootIdentityDigestV1,
    /// Custody lineage of the stranded row.
    pub custody_lineage: TenantRootCustodyLineageId,
    /// Role that owns the row. Only that role may act on this command.
    pub role: TwoPartyDeriverRole,
    /// Epoch of the stranded row.
    pub epoch: TenantRootShareEpoch,
    /// Exact row revision at the time of authorization.
    pub expected_row_revision: i64,
    /// Session of the ceremony that created the row.
    pub session_id: TenantRootCeremonySessionIdV1,
    /// Nonce of that ceremony.
    pub ceremony_nonce: TenantRootCeremonyNonceV1,
    /// Digest of the installation evidence the row carries.
    pub installation_evidence_digest: TenantRootProtocolDigestV1,
}

impl TenantRootRoleCleanupCommandV1 {
    /// Signs one exact cleanup authorization.
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
            identity_digest: target.identity_digest,
            custody_lineage: target.custody_lineage,
            role: target.role,
            epoch: target.epoch,
            expected_row_revision: target.expected_row_revision,
            session_id: target.session_id,
            ceremony_nonce: target.ceremony_nonce,
            installation_evidence_digest: target.installation_evidence_digest,
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
        if decoder.field("tenant-root role cleanup command operation")?
            != TENANT_ROOT_ROLE_CLEANUP_OPERATION_V1
        {
            return Err(malformed(
                "tenant-root role cleanup command operation is invalid",
            ));
        }
        let identity_digest = TenantRootIdentityDigestV1::from_bytes(
            decoder.fixed_field::<32>("tenant-root role cleanup command identity digest")?,
        );
        let custody_lineage = TenantRootCustodyLineageId::from_bytes(
            decoder.fixed_field::<16>("tenant-root role cleanup command custody lineage")?,
        )?;
        let role = decoder.role()?;
        let epoch = TenantRootShareEpoch::new(
            decoder.u64_field("tenant-root role cleanup command epoch")?,
        )?;
        let expected_row_revision =
            decoder.u64_field("tenant-root role cleanup command row revision")? as i64;
        let session_id = TenantRootCeremonySessionIdV1::from_bytes(
            decoder.fixed_field::<16>("tenant-root role cleanup command session id")?,
        )?;
        let ceremony_nonce = TenantRootCeremonyNonceV1::from_bytes(
            decoder.fixed_field::<32>("tenant-root role cleanup command ceremony nonce")?,
        )?;
        let installation_evidence_digest = TenantRootProtocolDigestV1::from_bytes(
            decoder.fixed_field::<32>("tenant-root role cleanup command evidence digest")?,
        )?;
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
            identity_digest,
            custody_lineage,
            role,
            epoch,
            expected_row_revision,
            session_id,
            ceremony_nonce,
            installation_evidence_digest,
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

    /// Verifies this command against the row a role actually holds.
    ///
    /// `expected_role` and `expected_authority_id` are the verifier's own, never
    /// the command's: a role that read its expected role from the command it is
    /// checking could be made to clean on another role's behalf.
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
        if self.data.role != expected_role || expected_target.role != expected_role {
            return Err(replay_mismatch(
                "tenant-root role cleanup command names a different role",
            ));
        }
        if self.data.authority_id != expected_authority_id {
            return Err(replay_mismatch(
                "tenant-root role cleanup command names a different control-plane authority",
            ));
        }
        if self.data.identity_digest != expected_target.identity_digest
            || self.data.custody_lineage != expected_target.custody_lineage
            || self.data.epoch != expected_target.epoch
            || self.data.session_id != expected_target.session_id
            || self.data.ceremony_nonce != expected_target.ceremony_nonce
            || self.data.installation_evidence_digest
                != expected_target.installation_evidence_digest
        {
            return Err(replay_mismatch(
                "tenant-root role cleanup command does not name this pending row",
            ));
        }
        // The exact revision is what makes this one-use against one row state.
        if self.data.expected_row_revision != expected_target.expected_row_revision {
            return Err(replay_mismatch(
                "tenant-root role cleanup command was authorized for a different row revision",
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
    /// Returns the role authorized to clean.
    pub const fn role(&self) -> TwoPartyDeriverRole {
        self.data.role
    }

    /// Returns the epoch of the row this authorizes cleaning.
    pub const fn epoch(&self) -> TenantRootShareEpoch {
        self.data.epoch
    }

    /// Returns the exact row revision this authorizes cleaning.
    pub const fn expected_row_revision(&self) -> i64 {
        self.data.expected_row_revision
    }

    /// Returns the tenant identity digest.
    pub const fn identity_digest(&self) -> TenantRootIdentityDigestV1 {
        self.data.identity_digest
    }

    /// Returns the custody lineage.
    pub const fn custody_lineage(&self) -> TenantRootCustodyLineageId {
        self.data.custody_lineage
    }

    /// Returns the one-use nonce.
    pub const fn nonce(&self) -> TenantRootCeremonyNonceV1 {
        self.data.nonce
    }

    /// Returns the installation-evidence digest of the exact pending row.
    pub const fn installation_evidence_digest(&self) -> TenantRootProtocolDigestV1 {
        self.data.installation_evidence_digest
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
    if data.expected_row_revision <= 0 {
        return Err(malformed(
            "tenant-root role cleanup command row revision must be positive",
        ));
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

fn unsigned_canonical_bytes(
    data: &TenantRootRoleCleanupCommandDataV1,
) -> RouterAbDerivationResult<Vec<u8>> {
    let mut bytes = Vec::new();
    push_field(&mut bytes, TENANT_ROOT_ROLE_CLEANUP_COMMAND_DOMAIN_V1)?;
    push_field(&mut bytes, TENANT_ROOT_ROLE_CLEANUP_OPERATION_V1)?;
    push_field(&mut bytes, data.identity_digest.as_bytes())?;
    push_field(&mut bytes, data.custody_lineage.as_bytes())?;
    push_role(&mut bytes, data.role)?;
    push_field(&mut bytes, &data.epoch.get().get().to_be_bytes())?;
    push_field(
        &mut bytes,
        &(data.expected_row_revision as u64).to_be_bytes(),
    )?;
    push_field(&mut bytes, data.session_id.as_bytes())?;
    push_field(&mut bytes, data.ceremony_nonce.as_bytes())?;
    push_field(&mut bytes, data.installation_evidence_digest.as_bytes())?;
    push_field(&mut bytes, data.authority_id.as_bytes())?;
    push_field(&mut bytes, data.nonce.as_bytes())?;
    push_field(&mut bytes, &data.issued_at_ms.to_be_bytes())?;
    push_field(&mut bytes, &data.expires_at_ms.to_be_bytes())?;
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
