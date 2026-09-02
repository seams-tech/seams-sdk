use core::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use threshold_prf::TwoPartyDeriverRole;

use super::{
    require_tenant_root_identifier, RouterAbDerivationError, RouterAbDerivationErrorCode,
    RouterAbDerivationResult, TenantRootCeremonyContextV1, TenantRootCeremonyNonceV1,
    TenantRootCeremonySessionIdV1, TenantRootCommandReplayKeyV1, TenantRootCommandScopeV1,
    TenantRootControlPlaneAuthorityIdV1, TenantRootCreationJournalV1, TenantRootCustodyLineageId,
    TenantRootIdentityDigestV1, TenantRootProtocolDigestV1, TenantRootShareEpoch,
    TENANT_ROOT_MAX_LIFETIME_MS_V1,
};

const TENANT_ROOT_ROLE_CREATION_COMMAND_DOMAIN_V1: &[u8] = b"tenant_root_role_creation_command_v1";
const TENANT_ROOT_ROLE_CREATION_COMMAND_AUTH_DOMAIN_V1: &[u8] =
    b"tenant_root_role_creation_command_authentication_v1";
const TENANT_ROOT_ROLE_CREATION_AUTHORIZATION_PAYLOAD_DOMAIN_V1: &[u8] =
    b"tenant_root_role_creation_authorization_payload_v1";
const TENANT_ROOT_ROLE_CREATION_OPERATION_V1: &[u8] = b"create_pending_share";
const TENANT_ROOT_ROLE_CREATION_ISSUER_KEY_ID_MAX_BYTES_V1: usize = 256;

/// Exact operation authenticated by an initial tenant-root role command.
///
/// The operation covers one role's generate, commit, prove, seal, and insert
/// sequence. Role D1 authenticates its final `insert_pending` mutation with a
/// separate post-sealing digest.
pub const TENANT_ROOT_ROLE_CREATION_COMMAND_OPERATION_V1: &str = "create_pending_share";

/// Exact epoch authenticated by an initial tenant-root role command.
pub const TENANT_ROOT_ROLE_CREATION_COMMAND_EPOCH_V1: u64 = 1;

/// Exact control-plane revision authenticated by an initial role creation.
pub const TENANT_ROOT_ROLE_CREATION_COMMAND_EXPECTED_REVISION_V1: u64 = 1;

/// Maximum canonical wire size accepted for one role creation command.
pub const TENANT_ROOT_ROLE_CREATION_COMMAND_MAX_BYTES_V1: usize = 16 * 1024;

#[derive(Clone, PartialEq, Eq)]
struct TenantRootRoleCreationCommandDataV1 {
    identity_digest: TenantRootIdentityDigestV1,
    custody_lineage: TenantRootCustodyLineageId,
    started_journal_digest: TenantRootProtocolDigestV1,
    creation_context_digest: TenantRootProtocolDigestV1,
    role: TwoPartyDeriverRole,
    epoch: TenantRootShareEpoch,
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

impl fmt::Debug for TenantRootRoleCreationCommandDataV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TenantRootRoleCreationCommandDataV1")
            .field("identity_digest", &self.identity_digest)
            .field("custody_lineage", &self.custody_lineage)
            .field("started_journal_digest", &self.started_journal_digest)
            .field("creation_context_digest", &self.creation_context_digest)
            .field("role", &self.role)
            .field("epoch", &self.epoch)
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

/// Issuer-signed initial role creation command before signature verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantRootRoleCreationCommandV1 {
    data: TenantRootRoleCreationCommandDataV1,
}

impl TenantRootRoleCreationCommandV1 {
    /// Signs one exact initial role creation command.
    #[allow(clippy::too_many_arguments)]
    pub fn sign(
        started_journal: &TenantRootCreationJournalV1,
        creation_context: &TenantRootCeremonyContextV1,
        role: TwoPartyDeriverRole,
        authority_id: TenantRootControlPlaneAuthorityIdV1,
        issued_at_ms: u64,
        expires_at_ms: u64,
        issuer_key_id: impl Into<String>,
        issuer_signing_key_bytes: &[u8; 32],
    ) -> RouterAbDerivationResult<Self> {
        let bindings = CommandBindingsV1::from_sources(
            started_journal,
            creation_context,
            role,
            authority_id,
            issued_at_ms,
            expires_at_ms,
            issuer_key_id.into(),
        )?;
        let mut data = TenantRootRoleCreationCommandDataV1 {
            identity_digest: bindings.identity_digest,
            custody_lineage: bindings.custody_lineage,
            started_journal_digest: bindings.started_journal_digest,
            creation_context_digest: bindings.creation_context_digest,
            role: bindings.role,
            epoch: bindings.epoch,
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

    /// Decodes exactly one canonical signed role creation command wire.
    pub fn decode_canonical_bytes(bytes: &[u8]) -> RouterAbDerivationResult<Self> {
        if bytes.is_empty() || bytes.len() > TENANT_ROOT_ROLE_CREATION_COMMAND_MAX_BYTES_V1 {
            return Err(malformed(
                "tenant-root role creation command wire length is invalid",
            ));
        }
        let mut decoder = RoleCreationCommandWireDecoderV1::new(bytes);
        decoder.require_field(TENANT_ROOT_ROLE_CREATION_COMMAND_DOMAIN_V1)?;
        if decoder.field("tenant-root role creation command operation")?
            != TENANT_ROOT_ROLE_CREATION_OPERATION_V1
        {
            return Err(malformed(
                "tenant-root role creation command operation is invalid",
            ));
        }
        let identity_digest = TenantRootIdentityDigestV1::from_bytes(
            decoder.fixed_field::<32>("tenant-root role creation command identity digest")?,
        );
        let custody_lineage = TenantRootCustodyLineageId::from_bytes(
            decoder.fixed_field::<16>("tenant-root role creation command custody lineage")?,
        )?;
        let started_journal_digest = TenantRootProtocolDigestV1::from_bytes(
            decoder
                .fixed_field::<32>("tenant-root role creation command Started journal digest")?,
        )?;
        let creation_context_digest = TenantRootProtocolDigestV1::from_bytes(
            decoder
                .fixed_field::<32>("tenant-root role creation command creation context digest")?,
        )?;
        let role = decoder.role()?;
        let epoch = TenantRootShareEpoch::new(
            decoder.u64_field("tenant-root role creation command epoch")?,
        )?;
        if epoch != TenantRootShareEpoch::INITIAL {
            return Err(malformed(
                "tenant-root role creation command epoch is not initial",
            ));
        }
        let expected_control_plane_revision =
            decoder.u64_field("tenant-root role creation command expected revision")?;
        if expected_control_plane_revision != TENANT_ROOT_ROLE_CREATION_COMMAND_EXPECTED_REVISION_V1
        {
            return Err(malformed(
                "tenant-root role creation command expected revision is invalid",
            ));
        }
        let session_id = TenantRootCeremonySessionIdV1::from_bytes(
            decoder.fixed_field::<16>("tenant-root role creation command session id")?,
        )?;
        let nonce = TenantRootCeremonyNonceV1::from_bytes(
            decoder.fixed_field::<32>("tenant-root role creation command nonce")?,
        )?;
        let authority_id = TenantRootControlPlaneAuthorityIdV1::from_bytes(
            decoder.fixed_field::<32>("tenant-root role creation command authority id")?,
        );
        let issued_at_ms = decoder.u64_field("tenant-root role creation command issue time")?;
        let expires_at_ms = decoder.u64_field("tenant-root role creation command expiry")?;
        let encoded_authorization_payload_digest =
            TenantRootProtocolDigestV1::from_bytes(decoder.fixed_field::<32>(
                "tenant-root role creation command authorization payload digest",
            )?)?;
        let issuer_key_id = decoder.text_field(
            "tenant-root role creation command issuer key id",
            TENANT_ROOT_ROLE_CREATION_ISSUER_KEY_ID_MAX_BYTES_V1,
        )?;
        require_tenant_root_identifier(
            "tenant-root role creation command issuer key id",
            &issuer_key_id,
        )?;
        let signature = decoder.fixed_field::<64>("tenant-root role creation command signature")?;
        if signature.iter().all(|byte| *byte == 0) {
            return Err(malformed(
                "tenant-root role creation command signature must be nonzero",
            ));
        }
        decoder.finish()?;

        let command = Self {
            data: TenantRootRoleCreationCommandDataV1 {
                identity_digest,
                custody_lineage,
                started_journal_digest,
                creation_context_digest,
                role,
                epoch,
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
                "tenant-root role creation command authorization payload digest does not match its fields",
            ));
        }
        if command.canonical_bytes()? != bytes {
            return Err(malformed(
                "tenant-root role creation command wire is not canonical",
            ));
        }
        Ok(command)
    }

    /// Returns the fixed operation authenticated by this command.
    pub const fn operation(&self) -> &'static str {
        TENANT_ROOT_ROLE_CREATION_COMMAND_OPERATION_V1
    }

    /// Returns the server-resolved tenant-root identity digest.
    pub const fn identity_digest(&self) -> TenantRootIdentityDigestV1 {
        self.data.identity_digest
    }

    /// Returns the deployment-local custody lineage.
    pub const fn custody_lineage(&self) -> TenantRootCustodyLineageId {
        self.data.custody_lineage
    }

    /// Returns the Started journal digest authenticated by this command.
    pub const fn started_journal_digest(&self) -> TenantRootProtocolDigestV1 {
        self.data.started_journal_digest
    }

    /// Returns the creation ceremony context digest authenticated by this command.
    pub const fn creation_context_digest(&self) -> TenantRootProtocolDigestV1 {
        self.data.creation_context_digest
    }

    /// Returns the exact role authenticated by this command.
    pub const fn role(&self) -> TwoPartyDeriverRole {
        self.data.role
    }

    /// Returns the exact initial epoch authenticated by this command.
    pub const fn epoch(&self) -> TenantRootShareEpoch {
        self.data.epoch
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

    /// Verifies this command against the exact Started journal and ceremony context.
    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        &self,
        expected_started_journal: &TenantRootCreationJournalV1,
        expected_creation_context: &TenantRootCeremonyContextV1,
        expected_role: TwoPartyDeriverRole,
        expected_authority_id: TenantRootControlPlaneAuthorityIdV1,
        expected_issuer_key_id: &str,
        trusted_issuer_verifying_key: &[u8; 32],
    ) -> RouterAbDerivationResult<VerifiedTenantRootRoleCreationCommandV1> {
        let expected = CommandBindingsV1::from_sources(
            expected_started_journal,
            expected_creation_context,
            expected_role,
            expected_authority_id,
            self.data.issued_at_ms,
            self.data.expires_at_ms,
            expected_issuer_key_id.to_owned(),
        )?;
        validate_data(&self.data)?;
        require_tenant_root_identifier(
            "tenant-root role creation command expected issuer key id",
            expected_issuer_key_id,
        )?;
        if self.data.identity_digest != expected.identity_digest {
            return Err(replay_mismatch(
                "tenant-root role creation command identity digest does not match its Started journal",
            ));
        }
        if self.data.custody_lineage != expected.custody_lineage {
            return Err(replay_mismatch(
                "tenant-root role creation command custody lineage does not match its Started journal",
            ));
        }
        if self.data.started_journal_digest != expected.started_journal_digest {
            return Err(replay_mismatch(
                "tenant-root role creation command Started journal digest does not match its expected journal",
            ));
        }
        if self.data.creation_context_digest != expected.creation_context_digest {
            return Err(replay_mismatch(
                "tenant-root role creation command context digest does not match its expected context",
            ));
        }
        if self.data.role != expected.role {
            return Err(replay_mismatch(
                "tenant-root role creation command role does not match its expected role",
            ));
        }
        if self.data.epoch != expected.epoch {
            return Err(replay_mismatch(
                "tenant-root role creation command epoch does not match its expected epoch",
            ));
        }
        if self.data.expected_control_plane_revision != expected.expected_control_plane_revision {
            return Err(replay_mismatch(
                "tenant-root role creation command revision does not match its expected revision",
            ));
        }
        if self.data.session_id != expected.session_id {
            return Err(replay_mismatch(
                "tenant-root role creation command session id does not match its expected context",
            ));
        }
        if self.data.nonce != expected.nonce {
            return Err(replay_mismatch(
                "tenant-root role creation command nonce does not match its expected context",
            ));
        }
        if self.data.authority_id != expected.authority_id {
            return Err(replay_mismatch(
                "tenant-root role creation command authority does not match its expected authority",
            ));
        }
        if self.data.issued_at_ms != expected.issued_at_ms
            || self.data.expires_at_ms != expected.expires_at_ms
        {
            return Err(replay_mismatch(
                "tenant-root role creation command time window does not match its expected command",
            ));
        }
        if self.data.issuer_key_id != expected.issuer_key_id {
            return Err(replay_mismatch(
                "tenant-root role creation command issuer key id does not match its expected issuer",
            ));
        }
        if authorization_payload_digest(&self.data)? != self.data.authorization_payload_digest {
            return Err(replay_mismatch(
                "tenant-root role creation command authorization payload digest does not match its fields",
            ));
        }

        let unsigned = unsigned_canonical_bytes(&self.data)?;
        let verifying_key = VerifyingKey::from_bytes(trusted_issuer_verifying_key)
            .map_err(|_| malformed("tenant-root role creation command verifying key is invalid"))?;
        verifying_key
            .verify_strict(
                &authentication_input(&self.data.issuer_key_id, &unsigned)?,
                &Signature::from_bytes(&self.data.signature),
            )
            .map_err(|_| {
                verification_failed("tenant-root role creation command signature is invalid")
            })?;
        let canonical_bytes = canonical_bytes_from_unsigned(unsigned, &self.data.signature)?;
        let digest =
            TenantRootProtocolDigestV1::from_bytes(Sha256::digest(&canonical_bytes).into())?;
        Ok(VerifiedTenantRootRoleCreationCommandV1 {
            command: self.clone(),
            canonical_bytes,
            digest,
        })
    }
}

/// Strictly verified issuer-authenticated initial role creation command.
///
/// This token has no public constructor and is intentionally neither
/// cloneable nor copyable. Its exact bytes and digest can be retained for
/// durable replay.
pub struct VerifiedTenantRootRoleCreationCommandV1 {
    command: TenantRootRoleCreationCommandV1,
    canonical_bytes: Vec<u8>,
    digest: TenantRootProtocolDigestV1,
}

impl fmt::Debug for VerifiedTenantRootRoleCreationCommandV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedTenantRootRoleCreationCommandV1")
            .field("digest", &self.digest)
            .field("canonical_bytes", &"[public bytes]")
            .finish()
    }
}

impl VerifiedTenantRootRoleCreationCommandV1 {
    /// Returns the exact role authenticated by this command.
    pub const fn role(&self) -> TwoPartyDeriverRole {
        self.command.role()
    }

    /// Returns the fixed operation label authenticated by this command.
    pub const fn operation(&self) -> &'static str {
        self.command.operation()
    }

    /// Projects this authorization into the existing role-command scope.
    ///
    /// The role-store adapter computes its D1 mutation payload and replay
    /// command digests after sealing the role row.
    pub fn scope(&self) -> TenantRootCommandScopeV1 {
        TenantRootCommandScopeV1::new(
            TenantRootCommandReplayKeyV1::new(
                self.identity_digest(),
                self.custody_lineage(),
                self.session_id(),
                self.nonce(),
                self.role(),
            ),
            self.epoch(),
            self.expected_control_plane_revision(),
        )
        .expect("verified initial role creation command has a valid scope")
    }

    /// Returns the server-resolved tenant-root identity digest.
    pub const fn identity_digest(&self) -> TenantRootIdentityDigestV1 {
        self.command.identity_digest()
    }

    /// Returns the deployment-local custody lineage.
    pub const fn custody_lineage(&self) -> TenantRootCustodyLineageId {
        self.command.custody_lineage()
    }

    /// Returns the authenticated Started journal digest.
    pub const fn started_journal_digest(&self) -> TenantRootProtocolDigestV1 {
        self.command.started_journal_digest()
    }

    /// Returns the authenticated creation context digest.
    pub const fn creation_context_digest(&self) -> TenantRootProtocolDigestV1 {
        self.command.creation_context_digest()
    }

    /// Returns the exact initial custody epoch.
    pub const fn epoch(&self) -> TenantRootShareEpoch {
        self.command.epoch()
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

    /// Requires the command to be within its inclusive issue-to-expiry window.
    pub fn require_fresh(&self, now_ms: u64) -> RouterAbDerivationResult<()> {
        if now_ms < self.issued_at_ms() || now_ms > self.expires_at_ms() {
            return Err(replay_mismatch(
                "tenant-root role creation command is outside its freshness window",
            ));
        }
        Ok(())
    }
}

struct CommandBindingsV1 {
    identity_digest: TenantRootIdentityDigestV1,
    custody_lineage: TenantRootCustodyLineageId,
    started_journal_digest: TenantRootProtocolDigestV1,
    creation_context_digest: TenantRootProtocolDigestV1,
    role: TwoPartyDeriverRole,
    epoch: TenantRootShareEpoch,
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
        started_journal: &TenantRootCreationJournalV1,
        creation_context: &TenantRootCeremonyContextV1,
        role: TwoPartyDeriverRole,
        authority_id: TenantRootControlPlaneAuthorityIdV1,
        issued_at_ms: u64,
        expires_at_ms: u64,
        issuer_key_id: String,
    ) -> RouterAbDerivationResult<Self> {
        let started_journal_digest = started_journal.digest()?;
        let creation_context_bytes = creation_context.canonical_bytes()?;
        match started_journal {
            TenantRootCreationJournalV1::Started(started_event)
                if started_event.ceremony_context_canonical_bytes() != creation_context_bytes =>
            {
                return Err(malformed(
                    "tenant-root role creation command context bytes do not match its Started journal",
                ));
            }
            TenantRootCreationJournalV1::Started(_) => {}
        }
        let creation_context_digest = creation_context.digest()?;
        let identity_digest = started_journal.identity_digest();
        let custody_lineage = started_journal.custody_lineage();
        if creation_context.identity_digest() != identity_digest {
            return Err(malformed(
                "tenant-root role creation command context identity does not match its Started journal",
            ));
        }
        if creation_context.custody_lineage() != custody_lineage {
            return Err(malformed(
                "tenant-root role creation command context lineage does not match its Started journal",
            ));
        }
        if !matches!(
            creation_context.epochs(),
            super::TenantRootCeremonyEpochsV1::Create { .. }
        ) {
            return Err(malformed(
                "tenant-root role creation command requires a creation ceremony context",
            ));
        }
        if issued_at_ms < creation_context.issued_at_ms()
            || expires_at_ms > creation_context.expires_at_ms()
        {
            return Err(malformed(
                "tenant-root role creation command time window must be inside its ceremony window",
            ));
        }
        require_command_times(issued_at_ms, expires_at_ms)?;
        require_tenant_root_identifier(
            "tenant-root role creation command issuer key id",
            &issuer_key_id,
        )?;
        if issuer_key_id.len() > TENANT_ROOT_ROLE_CREATION_ISSUER_KEY_ID_MAX_BYTES_V1 {
            return Err(malformed(
                "tenant-root role creation command issuer key id is too long",
            ));
        }
        Ok(Self {
            identity_digest,
            custody_lineage,
            started_journal_digest,
            creation_context_digest,
            role,
            epoch: TenantRootShareEpoch::INITIAL,
            expected_control_plane_revision: TENANT_ROOT_ROLE_CREATION_COMMAND_EXPECTED_REVISION_V1,
            session_id: creation_context.session_id(),
            nonce: creation_context.nonce(),
            authority_id,
            issued_at_ms,
            expires_at_ms,
            issuer_key_id,
        })
    }
}

fn validate_data(data: &TenantRootRoleCreationCommandDataV1) -> RouterAbDerivationResult<()> {
    validate_unsigned_data(data)?;
    if data.signature.iter().all(|byte| *byte == 0) {
        return Err(malformed(
            "tenant-root role creation command signature must be nonzero",
        ));
    }
    Ok(())
}

fn validate_unsigned_data(
    data: &TenantRootRoleCreationCommandDataV1,
) -> RouterAbDerivationResult<()> {
    if data.epoch != TenantRootShareEpoch::INITIAL {
        return Err(malformed(
            "tenant-root role creation command epoch must be initial",
        ));
    }
    if data.expected_control_plane_revision
        != TENANT_ROOT_ROLE_CREATION_COMMAND_EXPECTED_REVISION_V1
    {
        return Err(malformed(
            "tenant-root role creation command expected revision must be one",
        ));
    }
    require_command_times(data.issued_at_ms, data.expires_at_ms)?;
    require_tenant_root_identifier(
        "tenant-root role creation command issuer key id",
        &data.issuer_key_id,
    )?;
    if data.issuer_key_id.len() > TENANT_ROOT_ROLE_CREATION_ISSUER_KEY_ID_MAX_BYTES_V1 {
        return Err(malformed(
            "tenant-root role creation command issuer key id is too long",
        ));
    }
    Ok(())
}

fn require_command_times(issued_at_ms: u64, expires_at_ms: u64) -> RouterAbDerivationResult<()> {
    if issued_at_ms == 0 || expires_at_ms <= issued_at_ms {
        return Err(malformed(
            "tenant-root role creation command expiry must follow a non-zero issue time",
        ));
    }
    if expires_at_ms - issued_at_ms > TENANT_ROOT_MAX_LIFETIME_MS_V1 {
        return Err(malformed(
            "tenant-root role creation command lifetime exceeds the frozen maximum window",
        ));
    }
    Ok(())
}

fn authorization_payload_digest(
    data: &TenantRootRoleCreationCommandDataV1,
) -> RouterAbDerivationResult<TenantRootProtocolDigestV1> {
    let mut bytes = Vec::new();
    push_field(
        &mut bytes,
        TENANT_ROOT_ROLE_CREATION_AUTHORIZATION_PAYLOAD_DOMAIN_V1,
    )?;
    push_authorization_fields(&mut bytes, data)?;
    push_field(&mut bytes, data.issuer_key_id.as_bytes())?;
    TenantRootProtocolDigestV1::from_bytes(Sha256::digest(bytes).into())
}

fn push_authorization_fields(
    bytes: &mut Vec<u8>,
    data: &TenantRootRoleCreationCommandDataV1,
) -> RouterAbDerivationResult<()> {
    push_field(bytes, TENANT_ROOT_ROLE_CREATION_OPERATION_V1)?;
    push_field(bytes, data.identity_digest.as_bytes())?;
    push_field(bytes, data.custody_lineage.as_bytes())?;
    push_field(bytes, data.started_journal_digest.as_bytes())?;
    push_field(bytes, data.creation_context_digest.as_bytes())?;
    push_role(bytes, data.role)?;
    push_field(bytes, &data.epoch.get().get().to_be_bytes())?;
    push_field(bytes, &data.expected_control_plane_revision.to_be_bytes())?;
    push_field(bytes, data.session_id.as_bytes())?;
    push_field(bytes, data.nonce.as_bytes())?;
    push_field(bytes, data.authority_id.as_bytes())?;
    push_field(bytes, &data.issued_at_ms.to_be_bytes())?;
    push_field(bytes, &data.expires_at_ms.to_be_bytes())?;
    Ok(())
}

fn unsigned_canonical_bytes(
    data: &TenantRootRoleCreationCommandDataV1,
) -> RouterAbDerivationResult<Vec<u8>> {
    validate_unsigned_data(data)?;
    let mut bytes = Vec::new();
    push_field(&mut bytes, TENANT_ROOT_ROLE_CREATION_COMMAND_DOMAIN_V1)?;
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
            "tenant-root role creation command signature must be nonzero",
        ));
    }
    let mut bytes = unsigned;
    push_field(&mut bytes, signature)?;
    Ok(bytes)
}

fn authentication_input(issuer_key_id: &str, unsigned: &[u8]) -> RouterAbDerivationResult<Vec<u8>> {
    require_tenant_root_identifier(
        "tenant-root role creation command issuer key id",
        issuer_key_id,
    )?;
    let mut bytes = Vec::new();
    push_field(&mut bytes, TENANT_ROOT_ROLE_CREATION_COMMAND_AUTH_DOMAIN_V1)?;
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
            "tenant-root role creation command field is required",
        ));
    }
    let length = u32::try_from(value.len())
        .map_err(|_| malformed("tenant-root role creation command field is too long"))?;
    let new_len = bytes
        .len()
        .checked_add(4)
        .and_then(|length| length.checked_add(value.len()))
        .ok_or_else(|| malformed("tenant-root role creation command wire length overflows"))?;
    if new_len > TENANT_ROOT_ROLE_CREATION_COMMAND_MAX_BYTES_V1 {
        return Err(malformed(
            "tenant-root role creation command wire is too long",
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

struct RoleCreationCommandWireDecoderV1<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> RoleCreationCommandWireDecoderV1<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn field(&mut self, name: &'static str) -> RouterAbDerivationResult<&'a [u8]> {
        let length_end = self
            .offset
            .checked_add(4)
            .ok_or_else(|| malformed("tenant-root role creation command wire offset overflows"))?;
        let length_bytes = self.bytes.get(self.offset..length_end).ok_or_else(|| {
            malformed("tenant-root role creation command field length is truncated")
        })?;
        let length = u32::from_be_bytes(
            length_bytes
                .try_into()
                .expect("fixed four-byte role creation command field length"),
        ) as usize;
        let value_end = length_end
            .checked_add(length)
            .ok_or_else(|| malformed("tenant-root role creation command field length overflows"))?;
        let value = self
            .bytes
            .get(length_end..value_end)
            .ok_or_else(|| malformed("tenant-root role creation command field is truncated"))?;
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
        if self.field("tenant-root role creation command domain")? != expected {
            return Err(malformed(
                "tenant-root role creation command domain is invalid",
            ));
        }
        Ok(())
    }

    fn fixed_field<const N: usize>(
        &mut self,
        name: &'static str,
    ) -> RouterAbDerivationResult<[u8; N]> {
        self.field(name)?.try_into().map_err(|_| {
            malformed("tenant-root role creation command fixed field length is invalid")
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
                "tenant-root role creation command text field is too long",
            ));
        }
        core::str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|_| malformed("tenant-root role creation command text field is invalid UTF-8"))
    }

    fn role(&mut self) -> RouterAbDerivationResult<TwoPartyDeriverRole> {
        let label = self.field("tenant-root role creation command role")?;
        let share_id = self.fixed_field::<2>("tenant-root role creation command role share id")?;
        match (label, u16::from_be_bytes(share_id)) {
            (b"deriver_a", 1) => Ok(TwoPartyDeriverRole::DeriverA),
            (b"deriver_b", 2) => Ok(TwoPartyDeriverRole::DeriverB),
            _ => Err(malformed(
                "tenant-root role creation command role encoding is invalid",
            )),
        }
    }

    fn finish(self) -> RouterAbDerivationResult<()> {
        if self.offset != self.bytes.len() {
            return Err(malformed(
                "tenant-root role creation command wire has trailing bytes",
            ));
        }
        Ok(())
    }
}
