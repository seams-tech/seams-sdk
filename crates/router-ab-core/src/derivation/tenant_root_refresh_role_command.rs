use core::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use threshold_prf::TwoPartyDeriverRole;

use super::{
    require_tenant_root_identifier, validate_tenant_root_active_role_share_commitment_v1,
    MpcPrfShareCommitmentWireV1, RouterAbDerivationError, RouterAbDerivationErrorCode,
    RouterAbDerivationResult, TenantRootActiveRootPairV1, TenantRootCeremonyContextV1,
    TenantRootCeremonyEpochsV1, TenantRootCeremonyNonceV1, TenantRootCeremonySessionIdV1,
    TenantRootCommandReplayKeyV1, TenantRootCommandScopeV1, TenantRootControlPlaneAuthorityIdV1,
    TenantRootCustodyLineageId, TenantRootEpochCommitmentsV1, TenantRootIdentityDigestV1,
    TenantRootLifecycleReceiptDigestV1, TenantRootProtocolDigestV1, TenantRootShareEpoch,
    TENANT_ROOT_MAX_CLOCK_SKEW_MS_V1, TENANT_ROOT_MAX_LIFETIME_MS_V1,
};

const TENANT_ROOT_ROLE_REFRESH_COMMAND_DOMAIN_V1: &[u8] = b"tenant_root_role_refresh_command_v1";
const TENANT_ROOT_ROLE_REFRESH_COMMAND_AUTH_DOMAIN_V1: &[u8] =
    b"tenant_root_role_refresh_command_authentication_v1";
const TENANT_ROOT_ROLE_REFRESH_AUTHORIZATION_PAYLOAD_DOMAIN_V1: &[u8] =
    b"tenant_root_role_refresh_authorization_payload_v1";
const TENANT_ROOT_ROLE_REFRESH_OPERATION_V1: &[u8] = b"refresh_pending_share";
const TENANT_ROOT_ROLE_REFRESH_ISSUER_KEY_ID_MAX_BYTES_V1: usize = 256;

/// Exact operation authenticated by a tenant-root refresh role command.
pub const TENANT_ROOT_ROLE_REFRESH_COMMAND_OPERATION_V1: &str = "refresh_pending_share";

/// Maximum canonical wire size accepted for one role refresh command.
pub const TENANT_ROOT_ROLE_REFRESH_COMMAND_MAX_BYTES_V1: usize = 16 * 1024;

#[derive(Clone, PartialEq, Eq)]
struct TenantRootRoleRefreshCommandDataV1 {
    identity_digest: TenantRootIdentityDigestV1,
    custody_lineage: TenantRootCustodyLineageId,
    deriver_a_share_commitment: MpcPrfShareCommitmentWireV1,
    deriver_b_share_commitment: MpcPrfShareCommitmentWireV1,
    active_root_commitment: [u8; 32],
    active_activation_receipt_digest: TenantRootLifecycleReceiptDigestV1,
    refresh_context_digest: TenantRootProtocolDigestV1,
    role: TwoPartyDeriverRole,
    current_epoch: TenantRootShareEpoch,
    next_epoch: TenantRootShareEpoch,
    expected_control_plane_revision: u64,
    session_id: TenantRootCeremonySessionIdV1,
    nonce: TenantRootCeremonyNonceV1,
    authority_id: TenantRootControlPlaneAuthorityIdV1,
    issued_at_ms: u64,
    expires_at_ms: u64,
    authorization_payload_digest: TenantRootProtocolDigestV1,
    issuer_key_id: String,
    signature: [u8; 64],
}

impl fmt::Debug for TenantRootRoleRefreshCommandDataV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TenantRootRoleRefreshCommandDataV1")
            .field("identity_digest", &self.identity_digest)
            .field("custody_lineage", &self.custody_lineage)
            .field(
                "deriver_a_share_commitment",
                &self.deriver_a_share_commitment,
            )
            .field(
                "deriver_b_share_commitment",
                &self.deriver_b_share_commitment,
            )
            .field(
                "active_root_commitment",
                &hex::encode(self.active_root_commitment),
            )
            .field(
                "active_activation_receipt_digest",
                &self.active_activation_receipt_digest,
            )
            .field("refresh_context_digest", &self.refresh_context_digest)
            .field("role", &self.role)
            .field("current_epoch", &self.current_epoch)
            .field("next_epoch", &self.next_epoch)
            .field(
                "expected_control_plane_revision",
                &self.expected_control_plane_revision,
            )
            .field("session_id", &self.session_id)
            .field("nonce", &self.nonce)
            .field("authority_id", &self.authority_id)
            .field("issued_at_ms", &self.issued_at_ms)
            .field("expires_at_ms", &self.expires_at_ms)
            .field(
                "authorization_payload_digest",
                &self.authorization_payload_digest,
            )
            .field("issuer_key_id", &self.issuer_key_id)
            .field("signature", &"[redacted]")
            .finish()
    }
}

/// Issuer-signed tenant-root refresh role command before signature verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantRootRoleRefreshCommandV1 {
    data: TenantRootRoleRefreshCommandDataV1,
}

impl TenantRootRoleRefreshCommandV1 {
    /// Signs one exact tenant-root refresh role command.
    #[allow(clippy::too_many_arguments)]
    pub fn sign(
        active_pair: &TenantRootActiveRootPairV1,
        refresh_context: &TenantRootCeremonyContextV1,
        role: TwoPartyDeriverRole,
        expected_control_plane_revision: u64,
        authority_id: TenantRootControlPlaneAuthorityIdV1,
        issued_at_ms: u64,
        expires_at_ms: u64,
        issuer_key_id: impl Into<String>,
        issuer_signing_key_bytes: &[u8; 32],
    ) -> RouterAbDerivationResult<Self> {
        let bindings = CommandBindingsV1::from_sources(
            active_pair,
            refresh_context,
            role,
            expected_control_plane_revision,
            authority_id,
            issued_at_ms,
            expires_at_ms,
            issuer_key_id.into(),
        )?;
        let mut data = TenantRootRoleRefreshCommandDataV1 {
            identity_digest: bindings.identity_digest,
            custody_lineage: bindings.custody_lineage,
            deriver_a_share_commitment: bindings.deriver_a_share_commitment,
            deriver_b_share_commitment: bindings.deriver_b_share_commitment,
            active_root_commitment: bindings.active_root_commitment,
            active_activation_receipt_digest: bindings.active_activation_receipt_digest,
            refresh_context_digest: bindings.refresh_context_digest,
            role: bindings.role,
            current_epoch: bindings.current_epoch,
            next_epoch: bindings.next_epoch,
            expected_control_plane_revision: bindings.expected_control_plane_revision,
            session_id: bindings.session_id,
            nonce: bindings.nonce,
            authority_id: bindings.authority_id,
            issued_at_ms: bindings.issued_at_ms,
            expires_at_ms: bindings.expires_at_ms,
            authorization_payload_digest: TenantRootProtocolDigestV1::from_bytes([1; 32])?,
            issuer_key_id: bindings.issuer_key_id,
            signature: [0; 64],
        };
        data.authorization_payload_digest = authorization_payload_digest(&data)?;
        let unsigned = unsigned_canonical_bytes(&data)?;
        data.signature = SigningKey::from_bytes(issuer_signing_key_bytes)
            .sign(&authentication_input(&data.issuer_key_id, &unsigned)?)
            .to_bytes();
        validate_data(&data)?;
        let command = Self { data };
        command.canonical_bytes()?;
        Ok(command)
    }

    /// Decodes exactly one canonical signed tenant-root refresh role command wire.
    pub fn decode_canonical_bytes(bytes: &[u8]) -> RouterAbDerivationResult<Self> {
        if bytes.is_empty() || bytes.len() > TENANT_ROOT_ROLE_REFRESH_COMMAND_MAX_BYTES_V1 {
            return Err(malformed(
                "tenant-root role refresh command wire length is invalid",
            ));
        }
        let mut decoder = RoleRefreshCommandWireDecoderV1::new(bytes);
        decoder.require_field(TENANT_ROOT_ROLE_REFRESH_COMMAND_DOMAIN_V1)?;
        if decoder.field("tenant-root role refresh command operation")?
            != TENANT_ROOT_ROLE_REFRESH_OPERATION_V1
        {
            return Err(malformed(
                "tenant-root role refresh command operation is invalid",
            ));
        }
        let identity_digest = TenantRootIdentityDigestV1::from_bytes(
            decoder.fixed_field::<32>("tenant-root role refresh command identity digest")?,
        );
        let custody_lineage = TenantRootCustodyLineageId::from_bytes(
            decoder.fixed_field::<16>("tenant-root role refresh command custody lineage")?,
        )?;
        let deriver_a_share_commitment = MpcPrfShareCommitmentWireV1::new(
            decoder
                .field("tenant-root role refresh command Deriver A share commitment")?
                .to_vec(),
        )?;
        let deriver_b_share_commitment = MpcPrfShareCommitmentWireV1::new(
            decoder
                .field("tenant-root role refresh command Deriver B share commitment")?
                .to_vec(),
        )?;
        let active_root_commitment =
            decoder.fixed_field::<32>("tenant-root role refresh command active root commitment")?;
        let active_activation_receipt_digest =
            TenantRootLifecycleReceiptDigestV1::from_bytes(decoder.fixed_field::<32>(
                "tenant-root role refresh command active activation receipt digest",
            )?)?;
        let refresh_context_digest = TenantRootProtocolDigestV1::from_bytes(
            decoder.fixed_field::<32>("tenant-root role refresh command refresh context digest")?,
        )?;
        let role = decoder.role()?;
        let current_epoch = TenantRootShareEpoch::new(
            decoder.u64_field("tenant-root role refresh command current epoch")?,
        )?;
        let next_epoch = TenantRootShareEpoch::new(
            decoder.u64_field("tenant-root role refresh command next epoch")?,
        )?;
        if current_epoch.next()? != next_epoch {
            return Err(malformed(
                "tenant-root role refresh command epochs must advance exactly one",
            ));
        }
        let expected_control_plane_revision =
            decoder.u64_field("tenant-root role refresh command expected revision")?;
        if expected_control_plane_revision == 0 {
            return Err(malformed(
                "tenant-root role refresh command expected revision must be positive",
            ));
        }
        let session_id = TenantRootCeremonySessionIdV1::from_bytes(
            decoder.fixed_field::<16>("tenant-root role refresh command session id")?,
        )?;
        let nonce = TenantRootCeremonyNonceV1::from_bytes(
            decoder.fixed_field::<32>("tenant-root role refresh command nonce")?,
        )?;
        let authority_id = TenantRootControlPlaneAuthorityIdV1::from_bytes(
            decoder.fixed_field::<32>("tenant-root role refresh command authority id")?,
        );
        let issued_at_ms = decoder.u64_field("tenant-root role refresh command issue time")?;
        let expires_at_ms = decoder.u64_field("tenant-root role refresh command expiry")?;
        let encoded_authorization_payload_digest =
            TenantRootProtocolDigestV1::from_bytes(decoder.fixed_field::<32>(
                "tenant-root role refresh command authorization payload digest",
            )?)?;
        let issuer_key_id = decoder.text_field(
            "tenant-root role refresh command issuer key id",
            TENANT_ROOT_ROLE_REFRESH_ISSUER_KEY_ID_MAX_BYTES_V1,
        )?;
        require_tenant_root_identifier(
            "tenant-root role refresh command issuer key id",
            &issuer_key_id,
        )?;
        let signature = decoder.fixed_field::<64>("tenant-root role refresh command signature")?;
        if signature.iter().all(|byte| *byte == 0) {
            return Err(malformed(
                "tenant-root role refresh command signature must be nonzero",
            ));
        }
        decoder.finish()?;

        let command = Self {
            data: TenantRootRoleRefreshCommandDataV1 {
                identity_digest,
                custody_lineage,
                deriver_a_share_commitment,
                deriver_b_share_commitment,
                active_root_commitment,
                active_activation_receipt_digest,
                refresh_context_digest,
                role,
                current_epoch,
                next_epoch,
                expected_control_plane_revision,
                session_id,
                nonce,
                authority_id,
                issued_at_ms,
                expires_at_ms,
                authorization_payload_digest: encoded_authorization_payload_digest,
                issuer_key_id,
                signature,
            },
        };
        validate_data(&command.data)?;
        if authorization_payload_digest(&command.data)? != command.data.authorization_payload_digest
        {
            return Err(malformed(
                "tenant-root role refresh command authorization payload digest does not match its fields",
            ));
        }
        if command.canonical_bytes()? != bytes {
            return Err(malformed(
                "tenant-root role refresh command wire is not canonical",
            ));
        }
        Ok(command)
    }

    /// Returns the fixed operation authenticated by this command.
    pub const fn operation(&self) -> &'static str {
        TENANT_ROOT_ROLE_REFRESH_COMMAND_OPERATION_V1
    }

    /// Returns the server-resolved tenant-root identity digest.
    pub const fn identity_digest(&self) -> TenantRootIdentityDigestV1 {
        self.data.identity_digest
    }

    /// Returns the deployment-local custody lineage.
    pub const fn custody_lineage(&self) -> TenantRootCustodyLineageId {
        self.data.custody_lineage
    }

    /// Returns Deriver A's exact active share commitment wire.
    pub const fn deriver_a_share_commitment(&self) -> &MpcPrfShareCommitmentWireV1 {
        &self.data.deriver_a_share_commitment
    }

    /// Returns Deriver B's exact active share commitment wire.
    pub const fn deriver_b_share_commitment(&self) -> &MpcPrfShareCommitmentWireV1 {
        &self.data.deriver_b_share_commitment
    }

    /// Returns the exact public stable root commitment.
    pub const fn active_root_commitment(&self) -> &[u8; 32] {
        &self.data.active_root_commitment
    }

    /// Returns the exact shared active activation-receipt digest.
    pub const fn active_activation_receipt_digest(&self) -> TenantRootLifecycleReceiptDigestV1 {
        self.data.active_activation_receipt_digest
    }

    /// Returns the refresh ceremony context digest.
    pub const fn refresh_context_digest(&self) -> TenantRootProtocolDigestV1 {
        self.data.refresh_context_digest
    }

    /// Returns the exact role authenticated by this command.
    pub const fn role(&self) -> TwoPartyDeriverRole {
        self.data.role
    }

    /// Returns the currently active custody epoch.
    pub const fn current_epoch(&self) -> TenantRootShareEpoch {
        self.data.current_epoch
    }

    /// Returns the pending refresh custody epoch.
    pub const fn next_epoch(&self) -> TenantRootShareEpoch {
        self.data.next_epoch
    }

    /// Returns the exact control-plane revision authenticated by this command.
    pub const fn expected_control_plane_revision(&self) -> u64 {
        self.data.expected_control_plane_revision
    }

    /// Returns the one-use ceremony session identifier.
    pub const fn session_id(&self) -> TenantRootCeremonySessionIdV1 {
        self.data.session_id
    }

    /// Returns the one-use ceremony nonce.
    pub const fn nonce(&self) -> TenantRootCeremonyNonceV1 {
        self.data.nonce
    }

    /// Returns the tenant-root control-plane authority identifier.
    pub const fn authority_id(&self) -> TenantRootControlPlaneAuthorityIdV1 {
        self.data.authority_id
    }

    /// Returns the command issue timestamp.
    pub const fn issued_at_ms(&self) -> u64 {
        self.data.issued_at_ms
    }

    /// Returns the command expiry timestamp.
    pub const fn expires_at_ms(&self) -> u64 {
        self.data.expires_at_ms
    }

    /// Returns the derived issuer authorization payload digest.
    pub const fn authorization_payload_digest(&self) -> TenantRootProtocolDigestV1 {
        self.data.authorization_payload_digest
    }

    /// Returns the issuer key identifier authenticated by the signature.
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

    /// Verifies this command against the exact active pair and refresh context.
    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        &self,
        expected_active_pair: &TenantRootActiveRootPairV1,
        expected_refresh_context: &TenantRootCeremonyContextV1,
        expected_role: TwoPartyDeriverRole,
        expected_control_plane_revision: u64,
        expected_authority_id: TenantRootControlPlaneAuthorityIdV1,
        expected_issuer_key_id: &str,
        trusted_issuer_verifying_key: &[u8; 32],
    ) -> RouterAbDerivationResult<VerifiedTenantRootRoleRefreshCommandV1> {
        let expected = CommandBindingsV1::from_sources(
            expected_active_pair,
            expected_refresh_context,
            expected_role,
            expected_control_plane_revision,
            expected_authority_id,
            self.data.issued_at_ms,
            self.data.expires_at_ms,
            expected_issuer_key_id.to_owned(),
        )?;
        validate_data(&self.data)?;
        require_tenant_root_identifier(
            "tenant-root role refresh command expected issuer key id",
            expected_issuer_key_id,
        )?;
        if self.data.identity_digest != expected.identity_digest {
            return Err(replay_mismatch(
                "tenant-root role refresh command identity digest does not match its active pair",
            ));
        }
        if self.data.custody_lineage != expected.custody_lineage {
            return Err(replay_mismatch(
                "tenant-root role refresh command custody lineage does not match its active pair",
            ));
        }
        if self.data.deriver_a_share_commitment != expected.deriver_a_share_commitment {
            return Err(replay_mismatch(
                "tenant-root role refresh command Deriver A share commitment does not match its active pair",
            ));
        }
        if self.data.deriver_b_share_commitment != expected.deriver_b_share_commitment {
            return Err(replay_mismatch(
                "tenant-root role refresh command Deriver B share commitment does not match its active pair",
            ));
        }
        if self.data.active_root_commitment != expected.active_root_commitment {
            return Err(replay_mismatch(
                "tenant-root role refresh command active root commitment does not match its active pair",
            ));
        }
        if self.data.active_activation_receipt_digest != expected.active_activation_receipt_digest {
            return Err(replay_mismatch(
                "tenant-root role refresh command activation receipt does not match its active pair",
            ));
        }
        if self.data.refresh_context_digest != expected.refresh_context_digest {
            return Err(replay_mismatch(
                "tenant-root role refresh command context digest does not match its expected context",
            ));
        }
        if self.data.role != expected.role {
            return Err(replay_mismatch(
                "tenant-root role refresh command role does not match its expected role",
            ));
        }
        if self.data.current_epoch != expected.current_epoch {
            return Err(replay_mismatch(
                "tenant-root role refresh command current epoch does not match its active pair",
            ));
        }
        if self.data.next_epoch != expected.next_epoch {
            return Err(replay_mismatch(
                "tenant-root role refresh command next epoch does not match its expected context",
            ));
        }
        if self.data.expected_control_plane_revision != expected.expected_control_plane_revision {
            return Err(replay_mismatch(
                "tenant-root role refresh command revision does not match its expected revision",
            ));
        }
        if self.data.session_id != expected.session_id {
            return Err(replay_mismatch(
                "tenant-root role refresh command session id does not match its expected context",
            ));
        }
        if self.data.nonce != expected.nonce {
            return Err(replay_mismatch(
                "tenant-root role refresh command nonce does not match its expected context",
            ));
        }
        if self.data.authority_id != expected.authority_id {
            return Err(replay_mismatch(
                "tenant-root role refresh command authority does not match its expected authority",
            ));
        }
        if self.data.issued_at_ms != expected.issued_at_ms
            || self.data.expires_at_ms != expected.expires_at_ms
        {
            return Err(replay_mismatch(
                "tenant-root role refresh command time window does not match its expected command",
            ));
        }
        if self.data.issuer_key_id != expected.issuer_key_id {
            return Err(replay_mismatch(
                "tenant-root role refresh command issuer key id does not match its expected issuer",
            ));
        }
        if authorization_payload_digest(&self.data)? != self.data.authorization_payload_digest {
            return Err(replay_mismatch(
                "tenant-root role refresh command authorization payload digest does not match its fields",
            ));
        }

        let unsigned = unsigned_canonical_bytes(&self.data)?;
        let verifying_key = VerifyingKey::from_bytes(trusted_issuer_verifying_key)
            .map_err(|_| malformed("tenant-root role refresh command verifying key is invalid"))?;
        verifying_key
            .verify_strict(
                &authentication_input(&self.data.issuer_key_id, &unsigned)?,
                &Signature::from_bytes(&self.data.signature),
            )
            .map_err(|_| {
                verification_failed("tenant-root role refresh command signature is invalid")
            })?;
        let canonical_bytes = canonical_bytes_from_unsigned(unsigned, &self.data.signature)?;
        let digest =
            TenantRootProtocolDigestV1::from_bytes(Sha256::digest(&canonical_bytes).into())?;
        Ok(VerifiedTenantRootRoleRefreshCommandV1 {
            command: self.clone(),
            canonical_bytes,
            digest,
        })
    }
}

/// Strictly verified issuer-authenticated tenant-root refresh role command.
///
/// This token has no public constructor and is intentionally neither
/// cloneable nor copyable. Its exact bytes and digest can be retained for
/// durable replay.
pub struct VerifiedTenantRootRoleRefreshCommandV1 {
    command: TenantRootRoleRefreshCommandV1,
    canonical_bytes: Vec<u8>,
    digest: TenantRootProtocolDigestV1,
}

impl fmt::Debug for VerifiedTenantRootRoleRefreshCommandV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedTenantRootRoleRefreshCommandV1")
            .field("digest", &self.digest)
            .field("canonical_bytes", &"[public bytes]")
            .finish()
    }
}

impl VerifiedTenantRootRoleRefreshCommandV1 {
    /// Returns the exact role authenticated by this command.
    pub const fn role(&self) -> TwoPartyDeriverRole {
        self.command.role()
    }

    /// Returns the fixed operation label authenticated by this command.
    pub const fn operation(&self) -> &'static str {
        self.command.operation()
    }

    /// Projects this authorization into the existing role-command scope.
    pub fn scope(&self) -> TenantRootCommandScopeV1 {
        TenantRootCommandScopeV1::new(
            TenantRootCommandReplayKeyV1::new(
                self.identity_digest(),
                self.custody_lineage(),
                self.session_id(),
                self.nonce(),
                self.role(),
            ),
            self.next_epoch(),
            self.expected_control_plane_revision(),
        )
        .expect("verified tenant-root role refresh command has a valid scope")
    }

    /// Returns the server-resolved tenant-root identity digest.
    pub const fn identity_digest(&self) -> TenantRootIdentityDigestV1 {
        self.command.identity_digest()
    }

    /// Returns the deployment-local custody lineage.
    pub const fn custody_lineage(&self) -> TenantRootCustodyLineageId {
        self.command.custody_lineage()
    }

    /// Returns Deriver A's exact active share commitment wire.
    pub const fn deriver_a_share_commitment(&self) -> &MpcPrfShareCommitmentWireV1 {
        self.command.deriver_a_share_commitment()
    }

    /// Returns Deriver B's exact active share commitment wire.
    pub const fn deriver_b_share_commitment(&self) -> &MpcPrfShareCommitmentWireV1 {
        self.command.deriver_b_share_commitment()
    }

    /// Returns the exact public stable root commitment.
    pub const fn active_root_commitment(&self) -> &[u8; 32] {
        self.command.active_root_commitment()
    }

    /// Returns the exact shared active activation-receipt digest.
    pub const fn active_activation_receipt_digest(&self) -> TenantRootLifecycleReceiptDigestV1 {
        self.command.active_activation_receipt_digest()
    }

    /// Returns the refresh ceremony context digest.
    pub const fn refresh_context_digest(&self) -> TenantRootProtocolDigestV1 {
        self.command.refresh_context_digest()
    }

    /// Returns the currently active custody epoch.
    pub const fn current_epoch(&self) -> TenantRootShareEpoch {
        self.command.current_epoch()
    }

    /// Returns the pending refresh custody epoch.
    pub const fn next_epoch(&self) -> TenantRootShareEpoch {
        self.command.next_epoch()
    }

    /// Returns the expected control-plane revision.
    pub const fn expected_control_plane_revision(&self) -> u64 {
        self.command.expected_control_plane_revision()
    }

    /// Returns the one-use ceremony session identifier.
    pub const fn session_id(&self) -> TenantRootCeremonySessionIdV1 {
        self.command.session_id()
    }

    /// Returns the one-use ceremony nonce.
    pub const fn nonce(&self) -> TenantRootCeremonyNonceV1 {
        self.command.nonce()
    }

    /// Returns the tenant-root control-plane authority identifier.
    pub const fn authority_id(&self) -> TenantRootControlPlaneAuthorityIdV1 {
        self.command.authority_id()
    }

    /// Returns the authenticated issue timestamp.
    pub const fn issued_at_ms(&self) -> u64 {
        self.command.issued_at_ms()
    }

    /// Returns the authenticated expiry timestamp.
    pub const fn expires_at_ms(&self) -> u64 {
        self.command.expires_at_ms()
    }

    /// Returns the derived issuer authorization payload digest.
    pub const fn authorization_payload_digest(&self) -> TenantRootProtocolDigestV1 {
        self.command.authorization_payload_digest()
    }

    /// Returns the issuer key identifier authenticated by this command.
    pub fn issuer_key_id(&self) -> &str {
        self.command.issuer_key_id()
    }

    /// Returns the exact canonical signed command bytes accepted by verification.
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    /// Returns the digest of the exact canonical signed command bytes.
    pub const fn digest(&self) -> TenantRootProtocolDigestV1 {
        self.digest
    }

    /// Consumes this token into the exact canonical signed command bytes.
    pub fn into_canonical_bytes(self) -> Vec<u8> {
        self.canonical_bytes
    }

    /// Requires the command to be within its issue-to-expiry window plus peer clock skew.
    pub fn require_fresh(&self, now_ms: u64) -> RouterAbDerivationResult<()> {
        let earliest_acceptable_now = self
            .issued_at_ms()
            .saturating_sub(TENANT_ROOT_MAX_CLOCK_SKEW_MS_V1);
        let latest_acceptable_now = self
            .expires_at_ms()
            .saturating_add(TENANT_ROOT_MAX_CLOCK_SKEW_MS_V1);
        if now_ms < earliest_acceptable_now || now_ms > latest_acceptable_now {
            return Err(replay_mismatch(
                "tenant-root role refresh command is outside its freshness window",
            ));
        }
        Ok(())
    }
}

struct CommandBindingsV1 {
    identity_digest: TenantRootIdentityDigestV1,
    custody_lineage: TenantRootCustodyLineageId,
    deriver_a_share_commitment: MpcPrfShareCommitmentWireV1,
    deriver_b_share_commitment: MpcPrfShareCommitmentWireV1,
    active_root_commitment: [u8; 32],
    active_activation_receipt_digest: TenantRootLifecycleReceiptDigestV1,
    refresh_context_digest: TenantRootProtocolDigestV1,
    role: TwoPartyDeriverRole,
    current_epoch: TenantRootShareEpoch,
    next_epoch: TenantRootShareEpoch,
    expected_control_plane_revision: u64,
    session_id: TenantRootCeremonySessionIdV1,
    nonce: TenantRootCeremonyNonceV1,
    authority_id: TenantRootControlPlaneAuthorityIdV1,
    issued_at_ms: u64,
    expires_at_ms: u64,
    issuer_key_id: String,
}

impl CommandBindingsV1 {
    #[allow(clippy::too_many_arguments)]
    fn from_sources(
        active_pair: &TenantRootActiveRootPairV1,
        refresh_context: &TenantRootCeremonyContextV1,
        role: TwoPartyDeriverRole,
        expected_control_plane_revision: u64,
        authority_id: TenantRootControlPlaneAuthorityIdV1,
        issued_at_ms: u64,
        expires_at_ms: u64,
        issuer_key_id: String,
    ) -> RouterAbDerivationResult<Self> {
        refresh_context.validate()?;
        let TenantRootCeremonyEpochsV1::Refresh { current, next } = refresh_context.epochs() else {
            return Err(malformed(
                "tenant-root role refresh command requires a refresh ceremony context",
            ));
        };
        if active_pair.identity_digest() != refresh_context.identity_digest() {
            return Err(malformed(
                "tenant-root role refresh command active pair identity does not match its refresh context",
            ));
        }
        if active_pair.custody_lineage() != refresh_context.custody_lineage() {
            return Err(malformed(
                "tenant-root role refresh command active pair lineage does not match its refresh context",
            ));
        }
        if active_pair.epoch() != current {
            return Err(malformed(
                "tenant-root role refresh command active pair epoch does not match its refresh context",
            ));
        }
        if current.next()? != next {
            return Err(malformed(
                "tenant-root role refresh command refresh epochs must advance exactly one",
            ));
        }
        let commitments = active_pair_commitments(active_pair)?;
        let active_activation_receipt_digest = active_pair.activation_receipt_digest();
        if active_pair.deriver_a().activation_receipt_digest()
            != active_pair.deriver_b().activation_receipt_digest()
        {
            return Err(malformed(
                "tenant-root role refresh command active pair receipts must be shared",
            ));
        }
        let refresh_context_digest = refresh_context.digest()?;
        if issued_at_ms < refresh_context.issued_at_ms()
            || expires_at_ms > refresh_context.expires_at_ms()
        {
            return Err(malformed(
                "tenant-root role refresh command time window must be inside its ceremony window",
            ));
        }
        if expected_control_plane_revision == 0 {
            return Err(malformed(
                "tenant-root role refresh command expected revision must be positive",
            ));
        }
        require_command_times(issued_at_ms, expires_at_ms)?;
        require_tenant_root_identifier(
            "tenant-root role refresh command issuer key id",
            &issuer_key_id,
        )?;
        if issuer_key_id.len() > TENANT_ROOT_ROLE_REFRESH_ISSUER_KEY_ID_MAX_BYTES_V1 {
            return Err(malformed(
                "tenant-root role refresh command issuer key id is too long",
            ));
        }
        Ok(Self {
            identity_digest: active_pair.identity_digest(),
            custody_lineage: active_pair.custody_lineage(),
            deriver_a_share_commitment: commitments.deriver_a().clone(),
            deriver_b_share_commitment: commitments.deriver_b().clone(),
            active_root_commitment: *commitments.root_commitment(),
            active_activation_receipt_digest,
            refresh_context_digest,
            role,
            current_epoch: current,
            next_epoch: next,
            expected_control_plane_revision,
            session_id: refresh_context.session_id(),
            nonce: refresh_context.nonce(),
            authority_id,
            issued_at_ms,
            expires_at_ms,
            issuer_key_id,
        })
    }
}

fn active_pair_commitments(
    active_pair: &TenantRootActiveRootPairV1,
) -> RouterAbDerivationResult<TenantRootEpochCommitmentsV1> {
    validate_tenant_root_active_role_share_commitment_v1(
        super::TenantRootManagedRestoreRoleV1::DeriverA,
        active_pair.deriver_a().share_commitment(),
    )?;
    validate_tenant_root_active_role_share_commitment_v1(
        super::TenantRootManagedRestoreRoleV1::DeriverB,
        active_pair.deriver_b().share_commitment(),
    )?;
    let commitments = TenantRootEpochCommitmentsV1::new(
        active_pair.deriver_a().share_commitment().clone(),
        active_pair.deriver_b().share_commitment().clone(),
    )?;
    if commitments != *active_pair.commitments() {
        return Err(malformed(
            "tenant-root role refresh command active pair commitments are inconsistent",
        ));
    }
    Ok(commitments)
}

fn validate_data(data: &TenantRootRoleRefreshCommandDataV1) -> RouterAbDerivationResult<()> {
    validate_unsigned_data(data)?;
    if data.signature.iter().all(|byte| *byte == 0) {
        return Err(malformed(
            "tenant-root role refresh command signature must be nonzero",
        ));
    }
    Ok(())
}

fn validate_unsigned_data(
    data: &TenantRootRoleRefreshCommandDataV1,
) -> RouterAbDerivationResult<()> {
    validate_tenant_root_active_role_share_commitment_v1(
        super::TenantRootManagedRestoreRoleV1::DeriverA,
        &data.deriver_a_share_commitment,
    )?;
    validate_tenant_root_active_role_share_commitment_v1(
        super::TenantRootManagedRestoreRoleV1::DeriverB,
        &data.deriver_b_share_commitment,
    )?;
    let commitments = TenantRootEpochCommitmentsV1::new(
        data.deriver_a_share_commitment.clone(),
        data.deriver_b_share_commitment.clone(),
    )?;
    if commitments.root_commitment() != &data.active_root_commitment {
        return Err(malformed(
            "tenant-root role refresh command active root commitment does not match its share commitments",
        ));
    }
    if data.current_epoch.next()? != data.next_epoch {
        return Err(malformed(
            "tenant-root role refresh command epochs must advance exactly one",
        ));
    }
    if data.expected_control_plane_revision == 0 {
        return Err(malformed(
            "tenant-root role refresh command expected revision must be positive",
        ));
    }
    require_command_times(data.issued_at_ms, data.expires_at_ms)?;
    require_tenant_root_identifier(
        "tenant-root role refresh command issuer key id",
        &data.issuer_key_id,
    )?;
    if data.issuer_key_id.len() > TENANT_ROOT_ROLE_REFRESH_ISSUER_KEY_ID_MAX_BYTES_V1 {
        return Err(malformed(
            "tenant-root role refresh command issuer key id is too long",
        ));
    }
    Ok(())
}

fn require_command_times(issued_at_ms: u64, expires_at_ms: u64) -> RouterAbDerivationResult<()> {
    if issued_at_ms == 0 || expires_at_ms <= issued_at_ms {
        return Err(malformed(
            "tenant-root role refresh command expiry must follow a non-zero issue time",
        ));
    }
    if expires_at_ms - issued_at_ms > TENANT_ROOT_MAX_LIFETIME_MS_V1 {
        return Err(malformed(
            "tenant-root role refresh command lifetime exceeds the frozen maximum window",
        ));
    }
    Ok(())
}

fn authorization_payload_digest(
    data: &TenantRootRoleRefreshCommandDataV1,
) -> RouterAbDerivationResult<TenantRootProtocolDigestV1> {
    let mut bytes = Vec::new();
    push_field(
        &mut bytes,
        TENANT_ROOT_ROLE_REFRESH_AUTHORIZATION_PAYLOAD_DOMAIN_V1,
    )?;
    push_authorization_fields(&mut bytes, data)?;
    push_field(&mut bytes, data.issuer_key_id.as_bytes())?;
    TenantRootProtocolDigestV1::from_bytes(Sha256::digest(bytes).into())
}

fn push_authorization_fields(
    bytes: &mut Vec<u8>,
    data: &TenantRootRoleRefreshCommandDataV1,
) -> RouterAbDerivationResult<()> {
    push_field(bytes, TENANT_ROOT_ROLE_REFRESH_OPERATION_V1)?;
    push_field(bytes, data.identity_digest.as_bytes())?;
    push_field(bytes, data.custody_lineage.as_bytes())?;
    push_field(bytes, data.deriver_a_share_commitment.as_bytes())?;
    push_field(bytes, data.deriver_b_share_commitment.as_bytes())?;
    push_field(bytes, &data.active_root_commitment)?;
    push_field(bytes, data.active_activation_receipt_digest.as_bytes())?;
    push_field(bytes, data.refresh_context_digest.as_bytes())?;
    push_role(bytes, data.role)?;
    push_field(bytes, &data.current_epoch.get().get().to_be_bytes())?;
    push_field(bytes, &data.next_epoch.get().get().to_be_bytes())?;
    push_field(bytes, &data.expected_control_plane_revision.to_be_bytes())?;
    push_field(bytes, data.session_id.as_bytes())?;
    push_field(bytes, data.nonce.as_bytes())?;
    push_field(bytes, data.authority_id.as_bytes())?;
    push_field(bytes, &data.issued_at_ms.to_be_bytes())?;
    push_field(bytes, &data.expires_at_ms.to_be_bytes())?;
    Ok(())
}

fn unsigned_canonical_bytes(
    data: &TenantRootRoleRefreshCommandDataV1,
) -> RouterAbDerivationResult<Vec<u8>> {
    validate_unsigned_data(data)?;
    let mut bytes = Vec::new();
    push_field(&mut bytes, TENANT_ROOT_ROLE_REFRESH_COMMAND_DOMAIN_V1)?;
    push_authorization_fields(&mut bytes, data)?;
    push_field(&mut bytes, data.authorization_payload_digest.as_bytes())?;
    push_field(&mut bytes, data.issuer_key_id.as_bytes())?;
    Ok(bytes)
}

fn canonical_bytes_from_unsigned(
    unsigned: Vec<u8>,
    signature: &[u8; 64],
) -> RouterAbDerivationResult<Vec<u8>> {
    if signature.iter().all(|byte| *byte == 0) {
        return Err(malformed(
            "tenant-root role refresh command signature must be nonzero",
        ));
    }
    let mut bytes = unsigned;
    push_field(&mut bytes, signature)?;
    Ok(bytes)
}

fn authentication_input(issuer_key_id: &str, unsigned: &[u8]) -> RouterAbDerivationResult<Vec<u8>> {
    require_tenant_root_identifier(
        "tenant-root role refresh command issuer key id",
        issuer_key_id,
    )?;
    let mut bytes = Vec::new();
    push_field(&mut bytes, TENANT_ROOT_ROLE_REFRESH_COMMAND_AUTH_DOMAIN_V1)?;
    push_field(&mut bytes, issuer_key_id.as_bytes())?;
    push_field(&mut bytes, unsigned)?;
    Ok(bytes)
}

fn push_role(bytes: &mut Vec<u8>, role: TwoPartyDeriverRole) -> RouterAbDerivationResult<()> {
    push_field(bytes, role.as_str().as_bytes())?;
    push_field(bytes, &role.share_id().get().get().to_be_bytes())
}

fn push_field(bytes: &mut Vec<u8>, value: &[u8]) -> RouterAbDerivationResult<()> {
    if value.is_empty() {
        return Err(RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::EmptyField,
            "tenant-root role refresh command field is required",
        ));
    }
    let length = u32::try_from(value.len())
        .map_err(|_| malformed("tenant-root role refresh command field is too long"))?;
    let new_len = bytes
        .len()
        .checked_add(4)
        .and_then(|length| length.checked_add(value.len()))
        .ok_or_else(|| malformed("tenant-root role refresh command wire length overflows"))?;
    if new_len > TENANT_ROOT_ROLE_REFRESH_COMMAND_MAX_BYTES_V1 {
        return Err(malformed(
            "tenant-root role refresh command wire is too long",
        ));
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

fn verification_failed(message: &'static str) -> RouterAbDerivationError {
    RouterAbDerivationError::new(
        RouterAbDerivationErrorCode::OutputVerificationFailed,
        message,
    )
}

struct RoleRefreshCommandWireDecoderV1<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> RoleRefreshCommandWireDecoderV1<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn field(&mut self, name: &'static str) -> RouterAbDerivationResult<&'a [u8]> {
        let length_end = self
            .offset
            .checked_add(4)
            .ok_or_else(|| malformed("tenant-root role refresh command wire offset overflows"))?;
        let length_bytes = self.bytes.get(self.offset..length_end).ok_or_else(|| {
            malformed("tenant-root role refresh command field length is truncated")
        })?;
        let length = u32::from_be_bytes(
            length_bytes
                .try_into()
                .expect("fixed four-byte role refresh command field length"),
        ) as usize;
        let value_end = length_end
            .checked_add(length)
            .ok_or_else(|| malformed("tenant-root role refresh command field length overflows"))?;
        let value = self
            .bytes
            .get(length_end..value_end)
            .ok_or_else(|| malformed("tenant-root role refresh command field is truncated"))?;
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
        if self.field("tenant-root role refresh command domain")? != expected {
            return Err(malformed(
                "tenant-root role refresh command domain is invalid",
            ));
        }
        Ok(())
    }

    fn fixed_field<const N: usize>(
        &mut self,
        name: &'static str,
    ) -> RouterAbDerivationResult<[u8; N]> {
        self.field(name)?.try_into().map_err(|_| {
            malformed("tenant-root role refresh command fixed field length is invalid")
        })
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
            return Err(malformed(
                "tenant-root role refresh command text field is too long",
            ));
        }
        core::str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|_| malformed("tenant-root role refresh command text field is invalid UTF-8"))
    }

    fn role(&mut self) -> RouterAbDerivationResult<TwoPartyDeriverRole> {
        let label = self.field("tenant-root role refresh command role")?;
        let share_id = self.fixed_field::<2>("tenant-root role refresh command role share id")?;
        match (label, u16::from_be_bytes(share_id)) {
            (b"deriver_a", 1) => Ok(TwoPartyDeriverRole::DeriverA),
            (b"deriver_b", 2) => Ok(TwoPartyDeriverRole::DeriverB),
            _ => Err(malformed(
                "tenant-root role refresh command role encoding is invalid",
            )),
        }
    }

    fn finish(self) -> RouterAbDerivationResult<()> {
        if self.offset != self.bytes.len() {
            return Err(malformed(
                "tenant-root role refresh command wire has trailing bytes",
            ));
        }
        Ok(())
    }
}
