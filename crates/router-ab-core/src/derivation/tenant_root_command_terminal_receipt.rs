use core::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use threshold_prf::TwoPartyDeriverRole;

use super::{
    require_tenant_root_identifier, ExecutedTenantRootCommandV1, ReservedTenantRootCommandV1,
    RouterAbDerivationError, RouterAbDerivationErrorCode, RouterAbDerivationResult,
    TenantRootCeremonyNonceV1, TenantRootCeremonySessionIdV1, TenantRootCommandReplayKeyV1,
    TenantRootCustodyLineageId, TenantRootIdentityDigestV1, TenantRootProtocolDigestV1,
};

const TENANT_ROOT_COMMAND_TERMINAL_RECEIPT_DOMAIN_V1: &[u8] =
    b"tenant_root_command_terminal_receipt_v1";
const TENANT_ROOT_COMMAND_TERMINAL_RECEIPT_AUTH_DOMAIN_V1: &[u8] =
    b"tenant_root_command_terminal_receipt_authentication_v1";
const MAX_ROLE_SIGNING_KEY_ID_BYTES_V1: usize = 256;
const MAX_TERMINAL_PAYLOAD_BYTES_V1: usize = 64 * 1024;

/// Maximum canonical wire size accepted for one terminal command receipt.
pub const TENANT_ROOT_COMMAND_TERMINAL_RECEIPT_MAX_BYTES_V1: usize = 64 * 1024;

/// Exhaustive terminal outcome carried by one role command receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TenantRootCommandTerminalOutcomeV1 {
    /// The command mutation completed successfully.
    Success,
    /// The command terminated without applying its mutation.
    Failure,
}

impl TenantRootCommandTerminalOutcomeV1 {
    const fn as_bytes(self) -> &'static [u8] {
        match self {
            Self::Success => b"success",
            Self::Failure => b"failure",
        }
    }
}

/// Public fields shared by the two branch-specific signed receipt types.
#[derive(Clone, PartialEq, Eq)]
struct TenantRootCommandTerminalReceiptDataV1 {
    key: TenantRootCommandReplayKeyV1,
    command_digest: TenantRootProtocolDigestV1,
    payload: Vec<u8>,
    payload_digest: TenantRootProtocolDigestV1,
    terminal_at_ms: u64,
    role_signing_key_id: String,
    signature: [u8; 64],
}

impl fmt::Debug for TenantRootCommandTerminalReceiptDataV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TenantRootCommandTerminalReceiptDataV1")
            .field("key", &self.key)
            .field("command_digest", &self.command_digest)
            .field("payload", &"[public bytes]")
            .field("payload_digest", &self.payload_digest)
            .field("terminal_at_ms", &self.terminal_at_ms)
            .field("role_signing_key_id", &self.role_signing_key_id)
            .field("signature", &"[redacted]")
            .finish()
    }
}

/// Role-signed successful terminal receipt before signature verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantRootCommandSuccessReceiptV1 {
    data: TenantRootCommandTerminalReceiptDataV1,
}

/// Role-signed failed terminal receipt before signature verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantRootCommandFailureReceiptV1 {
    data: TenantRootCommandTerminalReceiptDataV1,
}

/// Strict decoded wire form of a signed terminal command receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TenantRootCommandTerminalReceiptV1 {
    /// A receipt for a mutation that was applied successfully.
    Success(TenantRootCommandSuccessReceiptV1),
    /// A receipt for a mutation that failed before its mutation checkpoint.
    Failure(TenantRootCommandFailureReceiptV1),
}

impl TenantRootCommandSuccessReceiptV1 {
    /// Signs one exact public payload as a successful command terminal receipt.
    pub fn sign(
        key: TenantRootCommandReplayKeyV1,
        command_digest: TenantRootProtocolDigestV1,
        payload: Vec<u8>,
        terminal_at_ms: u64,
        role_signing_key_id: impl Into<String>,
        role_signing_key_bytes: &[u8; 32],
    ) -> RouterAbDerivationResult<Self> {
        sign_receipt(
            TenantRootCommandTerminalOutcomeV1::Success,
            key,
            command_digest,
            payload,
            terminal_at_ms,
            role_signing_key_id.into(),
            role_signing_key_bytes,
        )
        .map(|data| Self { data })
    }

    /// Returns the exact role-local replay key bound by this receipt.
    pub const fn key(&self) -> &TenantRootCommandReplayKeyV1 {
        &self.data.key
    }

    /// Returns the exact command digest bound by this receipt.
    pub const fn command_digest(&self) -> TenantRootProtocolDigestV1 {
        self.data.command_digest
    }

    /// Returns the exact public payload bytes.
    pub fn payload_bytes(&self) -> &[u8] {
        &self.data.payload
    }

    /// Returns the digest of the exact public payload bytes.
    pub const fn payload_digest(&self) -> TenantRootProtocolDigestV1 {
        self.data.payload_digest
    }

    /// Returns the terminal timestamp authenticated by the role signature.
    pub const fn terminal_at_ms(&self) -> u64 {
        self.data.terminal_at_ms
    }

    /// Returns the role signing-key identifier authenticated by the signature.
    pub fn role_signing_key_id(&self) -> &str {
        &self.data.role_signing_key_id
    }

    /// Returns the exact canonical signed receipt bytes.
    pub fn canonical_bytes(&self) -> RouterAbDerivationResult<Vec<u8>> {
        canonical_bytes(TenantRootCommandTerminalOutcomeV1::Success, &self.data)
    }

    /// Returns the digest of the exact canonical signed receipt bytes.
    pub fn digest(&self) -> RouterAbDerivationResult<TenantRootProtocolDigestV1> {
        receipt_digest(self.canonical_bytes()?)
    }

    /// Verifies this successful receipt against the exact executed replay token.
    /// Verifies a success receipt from a remote role using public expectations.
    ///
    /// A peer role cannot reconstruct the signer's executed-command token: the
    /// insert-pending payload digest covers the signer's sealed record, whose
    /// ciphertext is role-private. So this checks everything a remote verifier
    /// CAN derive independently -- the role signature, the expected signing key
    /// id, the replay key, the payload, and the earliest legitimate terminal
    /// time -- and deliberately does not assert the command digest, which is
    /// only meaningful to the signer.
    ///
    /// The payload binding is what makes this useful: the caller supplies the
    /// exact bytes the receipt must attest, so a receipt for a different
    /// operation by the same role in the same ceremony does not satisfy it.
    ///
    /// Use [`Self::verify`] wherever the executed-command token is available;
    /// it is strictly stronger.
    pub fn verify_remote_public(
        &self,
        expected_key: &TenantRootCommandReplayKeyV1,
        expected_payload: &[u8],
        earliest_terminal_at_ms: u64,
        expected_role_signing_key_id: &str,
        trusted_role_verifying_key: &[u8; 32],
    ) -> RouterAbDerivationResult<()> {
        validate_data(&self.data)?;
        require_tenant_root_identifier(
            "tenant-root command role signing key id",
            expected_role_signing_key_id,
        )?;
        if self.data.key != *expected_key {
            return Err(replay_mismatch(
                "tenant-root command receipt replay key does not match its ceremony",
            ));
        }
        if self.data.payload != expected_payload {
            return Err(replay_mismatch(
                "tenant-root command receipt payload does not match its expected attestation",
            ));
        }
        if self.data.terminal_at_ms < earliest_terminal_at_ms {
            return Err(replay_mismatch(
                "tenant-root command receipt predates its ceremony",
            ));
        }
        if self.data.role_signing_key_id != expected_role_signing_key_id {
            return Err(replay_mismatch(
                "tenant-root command receipt signing key id does not match its expected role",
            ));
        }
        verify_receipt_signature(
            TenantRootCommandTerminalOutcomeV1::Success,
            &self.data,
            trusted_role_verifying_key,
        )
    }

    pub fn verify(
        &self,
        executed: &ExecutedTenantRootCommandV1,
        expected_role_signing_key_id: &str,
        trusted_role_verifying_key: &[u8; 32],
    ) -> RouterAbDerivationResult<VerifiedTenantRootCommandSuccessReceiptV1> {
        let (data, canonical_bytes, digest) = verify_receipt(
            TenantRootCommandTerminalOutcomeV1::Success,
            &self.data,
            executed.key(),
            executed.command_digest(),
            executed.executed_at_ms(),
            expected_role_signing_key_id,
            trusted_role_verifying_key,
        )?;
        Ok(VerifiedTenantRootCommandSuccessReceiptV1 {
            receipt: Self { data },
            canonical_bytes,
            digest,
        })
    }
}

impl TenantRootCommandFailureReceiptV1 {
    /// Signs one exact public payload as a failed command terminal receipt.
    pub fn sign(
        key: TenantRootCommandReplayKeyV1,
        command_digest: TenantRootProtocolDigestV1,
        payload: Vec<u8>,
        terminal_at_ms: u64,
        role_signing_key_id: impl Into<String>,
        role_signing_key_bytes: &[u8; 32],
    ) -> RouterAbDerivationResult<Self> {
        sign_receipt(
            TenantRootCommandTerminalOutcomeV1::Failure,
            key,
            command_digest,
            payload,
            terminal_at_ms,
            role_signing_key_id.into(),
            role_signing_key_bytes,
        )
        .map(|data| Self { data })
    }

    /// Returns the exact role-local replay key bound by this receipt.
    pub const fn key(&self) -> &TenantRootCommandReplayKeyV1 {
        &self.data.key
    }

    /// Returns the exact command digest bound by this receipt.
    pub const fn command_digest(&self) -> TenantRootProtocolDigestV1 {
        self.data.command_digest
    }

    /// Returns the exact public payload bytes.
    pub fn payload_bytes(&self) -> &[u8] {
        &self.data.payload
    }

    /// Returns the digest of the exact public payload bytes.
    pub const fn payload_digest(&self) -> TenantRootProtocolDigestV1 {
        self.data.payload_digest
    }

    /// Returns the terminal timestamp authenticated by the role signature.
    pub const fn terminal_at_ms(&self) -> u64 {
        self.data.terminal_at_ms
    }

    /// Returns the role signing-key identifier authenticated by the signature.
    pub fn role_signing_key_id(&self) -> &str {
        &self.data.role_signing_key_id
    }

    /// Returns the exact canonical signed receipt bytes.
    pub fn canonical_bytes(&self) -> RouterAbDerivationResult<Vec<u8>> {
        canonical_bytes(TenantRootCommandTerminalOutcomeV1::Failure, &self.data)
    }

    /// Returns the digest of the exact canonical signed receipt bytes.
    pub fn digest(&self) -> RouterAbDerivationResult<TenantRootProtocolDigestV1> {
        receipt_digest(self.canonical_bytes()?)
    }

    /// Verifies this failed receipt against the exact reserved replay token.
    pub fn verify(
        &self,
        reserved: &ReservedTenantRootCommandV1,
        expected_role_signing_key_id: &str,
        trusted_role_verifying_key: &[u8; 32],
    ) -> RouterAbDerivationResult<VerifiedTenantRootCommandFailureReceiptV1> {
        let (data, canonical_bytes, digest) = verify_receipt(
            TenantRootCommandTerminalOutcomeV1::Failure,
            &self.data,
            reserved.key(),
            reserved.command_digest(),
            reserved.reserved_at_ms(),
            expected_role_signing_key_id,
            trusted_role_verifying_key,
        )?;
        Ok(VerifiedTenantRootCommandFailureReceiptV1 {
            receipt: Self { data },
            canonical_bytes,
            digest,
        })
    }
}

impl TenantRootCommandTerminalReceiptV1 {
    /// Signs one exact public payload as a successful command terminal receipt.
    pub fn sign_success(
        key: TenantRootCommandReplayKeyV1,
        command_digest: TenantRootProtocolDigestV1,
        payload: Vec<u8>,
        terminal_at_ms: u64,
        role_signing_key_id: impl Into<String>,
        role_signing_key_bytes: &[u8; 32],
    ) -> RouterAbDerivationResult<Self> {
        TenantRootCommandSuccessReceiptV1::sign(
            key,
            command_digest,
            payload,
            terminal_at_ms,
            role_signing_key_id,
            role_signing_key_bytes,
        )
        .map(Self::Success)
    }

    /// Signs one exact public payload as a failed command terminal receipt.
    pub fn sign_failure(
        key: TenantRootCommandReplayKeyV1,
        command_digest: TenantRootProtocolDigestV1,
        payload: Vec<u8>,
        terminal_at_ms: u64,
        role_signing_key_id: impl Into<String>,
        role_signing_key_bytes: &[u8; 32],
    ) -> RouterAbDerivationResult<Self> {
        TenantRootCommandFailureReceiptV1::sign(
            key,
            command_digest,
            payload,
            terminal_at_ms,
            role_signing_key_id,
            role_signing_key_bytes,
        )
        .map(Self::Failure)
    }

    /// Decodes exactly one canonical signed terminal receipt wire.
    pub fn decode_canonical_bytes(bytes: &[u8]) -> RouterAbDerivationResult<Self> {
        if bytes.is_empty() || bytes.len() > TENANT_ROOT_COMMAND_TERMINAL_RECEIPT_MAX_BYTES_V1 {
            return Err(malformed(
                "tenant-root command terminal receipt wire length is invalid",
            ));
        }
        let mut decoder = TerminalReceiptWireDecoderV1::new(bytes);
        decoder.require_field(TENANT_ROOT_COMMAND_TERMINAL_RECEIPT_DOMAIN_V1)?;
        let outcome = decoder.outcome()?;
        let data = decode_data(&mut decoder)?;
        decoder.finish()?;
        validate_data(&data)?;
        match outcome {
            TenantRootCommandTerminalOutcomeV1::Success => {
                Ok(Self::Success(TenantRootCommandSuccessReceiptV1 { data }))
            }
            TenantRootCommandTerminalOutcomeV1::Failure => {
                Ok(Self::Failure(TenantRootCommandFailureReceiptV1 { data }))
            }
        }
    }

    /// Returns the terminal outcome represented by this decoded receipt.
    pub const fn outcome(&self) -> TenantRootCommandTerminalOutcomeV1 {
        match self {
            Self::Success(_) => TenantRootCommandTerminalOutcomeV1::Success,
            Self::Failure(_) => TenantRootCommandTerminalOutcomeV1::Failure,
        }
    }

    /// Returns the exact role-local replay key bound by this receipt.
    pub const fn key(&self) -> &TenantRootCommandReplayKeyV1 {
        match self {
            Self::Success(receipt) => receipt.key(),
            Self::Failure(receipt) => receipt.key(),
        }
    }

    /// Returns the exact command digest bound by this receipt.
    pub const fn command_digest(&self) -> TenantRootProtocolDigestV1 {
        match self {
            Self::Success(receipt) => receipt.command_digest(),
            Self::Failure(receipt) => receipt.command_digest(),
        }
    }

    /// Returns the exact public payload bytes.
    pub fn payload_bytes(&self) -> &[u8] {
        match self {
            Self::Success(receipt) => receipt.payload_bytes(),
            Self::Failure(receipt) => receipt.payload_bytes(),
        }
    }

    /// Returns the digest of the exact public payload bytes.
    pub const fn payload_digest(&self) -> TenantRootProtocolDigestV1 {
        match self {
            Self::Success(receipt) => receipt.payload_digest(),
            Self::Failure(receipt) => receipt.payload_digest(),
        }
    }

    /// Returns the authenticated terminal timestamp.
    pub const fn terminal_at_ms(&self) -> u64 {
        match self {
            Self::Success(receipt) => receipt.terminal_at_ms(),
            Self::Failure(receipt) => receipt.terminal_at_ms(),
        }
    }

    /// Returns the authenticated role signing-key identifier.
    pub fn role_signing_key_id(&self) -> &str {
        match self {
            Self::Success(receipt) => receipt.role_signing_key_id(),
            Self::Failure(receipt) => receipt.role_signing_key_id(),
        }
    }

    /// Returns the exact canonical signed receipt bytes.
    pub fn canonical_bytes(&self) -> RouterAbDerivationResult<Vec<u8>> {
        match self {
            Self::Success(receipt) => receipt.canonical_bytes(),
            Self::Failure(receipt) => receipt.canonical_bytes(),
        }
    }

    /// Returns the digest of the exact canonical signed receipt bytes.
    pub fn digest(&self) -> RouterAbDerivationResult<TenantRootProtocolDigestV1> {
        receipt_digest(self.canonical_bytes()?)
    }

    /// Verifies only a successful receipt against an executed replay token.
    pub fn verify_success(
        &self,
        executed: &ExecutedTenantRootCommandV1,
        expected_role_signing_key_id: &str,
        trusted_role_verifying_key: &[u8; 32],
    ) -> RouterAbDerivationResult<VerifiedTenantRootCommandSuccessReceiptV1> {
        match self {
            Self::Success(receipt) => receipt.verify(
                executed,
                expected_role_signing_key_id,
                trusted_role_verifying_key,
            ),
            Self::Failure(_) => Err(replay_mismatch(
                "tenant-root command failure receipt cannot verify as success",
            )),
        }
    }

    /// Verifies only a failed receipt against a reserved replay token.
    pub fn verify_failure(
        &self,
        reserved: &ReservedTenantRootCommandV1,
        expected_role_signing_key_id: &str,
        trusted_role_verifying_key: &[u8; 32],
    ) -> RouterAbDerivationResult<VerifiedTenantRootCommandFailureReceiptV1> {
        match self {
            Self::Failure(receipt) => receipt.verify(
                reserved,
                expected_role_signing_key_id,
                trusted_role_verifying_key,
            ),
            Self::Success(_) => Err(replay_mismatch(
                "tenant-root command success receipt cannot verify as failure",
            )),
        }
    }
}

/// Signature-verified successful terminal receipt.
///
/// This token has no public constructor and cannot be cloned or copied. Its
/// canonical bytes are the only bytes accepted for durable replay.
pub struct VerifiedTenantRootCommandSuccessReceiptV1 {
    receipt: TenantRootCommandSuccessReceiptV1,
    canonical_bytes: Vec<u8>,
    digest: TenantRootProtocolDigestV1,
}

impl fmt::Debug for VerifiedTenantRootCommandSuccessReceiptV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedTenantRootCommandSuccessReceiptV1")
            .field("digest", &self.digest)
            .field("canonical_bytes", &"[public bytes]")
            .finish()
    }
}

impl VerifiedTenantRootCommandSuccessReceiptV1 {
    /// Returns the exact canonical signed receipt bytes accepted by verification.
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    /// Returns the digest of the exact canonical signed receipt bytes.
    pub const fn digest(&self) -> TenantRootProtocolDigestV1 {
        self.digest
    }

    /// Returns the exact role-local replay key.
    pub const fn key(&self) -> &TenantRootCommandReplayKeyV1 {
        self.receipt.key()
    }

    /// Returns the exact command digest.
    pub const fn command_digest(&self) -> TenantRootProtocolDigestV1 {
        self.receipt.command_digest()
    }

    /// Returns the exact public payload bytes.
    pub fn payload_bytes(&self) -> &[u8] {
        self.receipt.payload_bytes()
    }

    /// Returns the exact public payload digest.
    pub const fn payload_digest(&self) -> TenantRootProtocolDigestV1 {
        self.receipt.payload_digest()
    }

    /// Returns the authenticated terminal timestamp.
    pub const fn terminal_at_ms(&self) -> u64 {
        self.receipt.terminal_at_ms()
    }

    /// Returns the authenticated role signing-key identifier.
    pub fn role_signing_key_id(&self) -> &str {
        self.receipt.role_signing_key_id()
    }

    /// Consumes this token into the exact canonical signed receipt bytes.
    pub fn into_canonical_bytes(self) -> Vec<u8> {
        self.canonical_bytes
    }
}

/// Signature-verified failed terminal receipt.
///
/// This token has no public constructor and cannot be cloned or copied. Its
/// canonical bytes are the only bytes accepted for durable replay.
pub struct VerifiedTenantRootCommandFailureReceiptV1 {
    receipt: TenantRootCommandFailureReceiptV1,
    canonical_bytes: Vec<u8>,
    digest: TenantRootProtocolDigestV1,
}

impl fmt::Debug for VerifiedTenantRootCommandFailureReceiptV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedTenantRootCommandFailureReceiptV1")
            .field("digest", &self.digest)
            .field("canonical_bytes", &"[public bytes]")
            .finish()
    }
}

impl VerifiedTenantRootCommandFailureReceiptV1 {
    /// Returns the exact canonical signed receipt bytes accepted by verification.
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    /// Returns the digest of the exact canonical signed receipt bytes.
    pub const fn digest(&self) -> TenantRootProtocolDigestV1 {
        self.digest
    }

    /// Returns the exact role-local replay key.
    pub const fn key(&self) -> &TenantRootCommandReplayKeyV1 {
        self.receipt.key()
    }

    /// Returns the exact command digest.
    pub const fn command_digest(&self) -> TenantRootProtocolDigestV1 {
        self.receipt.command_digest()
    }

    /// Returns the exact public payload bytes.
    pub fn payload_bytes(&self) -> &[u8] {
        self.receipt.payload_bytes()
    }

    /// Returns the exact public payload digest.
    pub const fn payload_digest(&self) -> TenantRootProtocolDigestV1 {
        self.receipt.payload_digest()
    }

    /// Returns the authenticated terminal timestamp.
    pub const fn terminal_at_ms(&self) -> u64 {
        self.receipt.terminal_at_ms()
    }

    /// Returns the authenticated role signing-key identifier.
    pub fn role_signing_key_id(&self) -> &str {
        self.receipt.role_signing_key_id()
    }

    /// Consumes this token into the exact canonical signed receipt bytes.
    pub fn into_canonical_bytes(self) -> Vec<u8> {
        self.canonical_bytes
    }
}

fn sign_receipt(
    outcome: TenantRootCommandTerminalOutcomeV1,
    key: TenantRootCommandReplayKeyV1,
    command_digest: TenantRootProtocolDigestV1,
    payload: Vec<u8>,
    terminal_at_ms: u64,
    role_signing_key_id: String,
    role_signing_key_bytes: &[u8; 32],
) -> RouterAbDerivationResult<TenantRootCommandTerminalReceiptDataV1> {
    let payload_digest = payload_digest(&payload)?;
    let unsigned = unsigned_canonical_bytes(
        outcome,
        &key,
        command_digest,
        &payload,
        payload_digest,
        terminal_at_ms,
        &role_signing_key_id,
    )?;
    let signature = SigningKey::from_bytes(role_signing_key_bytes)
        .sign(&role_authentication_input(
            key.role(),
            &role_signing_key_id,
            &unsigned,
        )?)
        .to_bytes();
    let data = TenantRootCommandTerminalReceiptDataV1 {
        key,
        command_digest,
        payload,
        payload_digest,
        terminal_at_ms,
        role_signing_key_id,
        signature,
    };
    validate_data(&data)?;
    canonical_bytes_from_unsigned(unsigned, &data.signature)?;
    Ok(data)
}

fn verify_receipt(
    outcome: TenantRootCommandTerminalOutcomeV1,
    data: &TenantRootCommandTerminalReceiptDataV1,
    expected_key: &TenantRootCommandReplayKeyV1,
    expected_command_digest: TenantRootProtocolDigestV1,
    earliest_terminal_at_ms: u64,
    expected_role_signing_key_id: &str,
    trusted_role_verifying_key: &[u8; 32],
) -> RouterAbDerivationResult<(
    TenantRootCommandTerminalReceiptDataV1,
    Vec<u8>,
    TenantRootProtocolDigestV1,
)> {
    validate_data(data)?;
    require_tenant_root_identifier(
        "tenant-root command role signing key id",
        expected_role_signing_key_id,
    )?;
    if data.key != *expected_key {
        return Err(replay_mismatch(
            "tenant-root command receipt replay key does not match its replay token",
        ));
    }
    if data.command_digest != expected_command_digest {
        return Err(replay_mismatch(
            "tenant-root command receipt command digest does not match its replay token",
        ));
    }
    if data.role_signing_key_id != expected_role_signing_key_id {
        return Err(replay_mismatch(
            "tenant-root command receipt role signing key id does not match its trusted key",
        ));
    }
    if data.terminal_at_ms < earliest_terminal_at_ms {
        return Err(replay_mismatch(
            "tenant-root command receipt terminal time precedes its replay checkpoint",
        ));
    }
    let unsigned = unsigned_canonical_bytes(
        outcome,
        &data.key,
        data.command_digest,
        &data.payload,
        data.payload_digest,
        data.terminal_at_ms,
        &data.role_signing_key_id,
    )?;
    let verifying_key = VerifyingKey::from_bytes(trusted_role_verifying_key)
        .map_err(|_| malformed("tenant-root command role verifying key is invalid"))?;
    verifying_key
        .verify_strict(
            &role_authentication_input(data.key.role(), &data.role_signing_key_id, &unsigned)?,
            &Signature::from_bytes(&data.signature),
        )
        .map_err(|_| verification_failed("tenant-root command role signature is invalid"))?;
    let canonical_bytes = canonical_bytes_from_unsigned(unsigned, &data.signature)?;
    let digest = receipt_digest(canonical_bytes.clone())?;
    Ok((data.clone(), canonical_bytes, digest))
}

/// Verifies only the role signature over a receipt's canonical bytes.
fn verify_receipt_signature(
    outcome: TenantRootCommandTerminalOutcomeV1,
    data: &TenantRootCommandTerminalReceiptDataV1,
    trusted_role_verifying_key: &[u8; 32],
) -> RouterAbDerivationResult<()> {
    let unsigned = unsigned_canonical_bytes(
        outcome,
        &data.key,
        data.command_digest,
        &data.payload,
        data.payload_digest,
        data.terminal_at_ms,
        &data.role_signing_key_id,
    )?;
    let verifying_key = VerifyingKey::from_bytes(trusted_role_verifying_key)
        .map_err(|_| malformed("tenant-root command role verifying key is invalid"))?;
    verifying_key
        .verify_strict(
            &role_authentication_input(data.key.role(), &data.role_signing_key_id, &unsigned)?,
            &Signature::from_bytes(&data.signature),
        )
        .map_err(|_| verification_failed("tenant-root command role signature is invalid"))
}

fn decode_data(
    decoder: &mut TerminalReceiptWireDecoderV1<'_>,
) -> RouterAbDerivationResult<TenantRootCommandTerminalReceiptDataV1> {
    let identity_digest = TenantRootIdentityDigestV1::from_bytes(
        decoder.fixed_field::<32>("tenant-root command receipt identity digest")?,
    );
    let custody_lineage = TenantRootCustodyLineageId::from_bytes(
        decoder.fixed_field::<16>("tenant-root command receipt custody lineage")?,
    )?;
    let role = decoder.role()?;
    let session_id = TenantRootCeremonySessionIdV1::from_bytes(
        decoder.fixed_field::<16>("tenant-root command receipt session id")?,
    )?;
    let nonce = TenantRootCeremonyNonceV1::from_bytes(
        decoder.fixed_field::<32>("tenant-root command receipt nonce")?,
    )?;
    let command_digest = TenantRootProtocolDigestV1::from_bytes(
        decoder.fixed_field::<32>("tenant-root command receipt command digest")?,
    )?;
    let payload_digest = TenantRootProtocolDigestV1::from_bytes(
        decoder.fixed_field::<32>("tenant-root command receipt payload digest")?,
    )?;
    let payload = decoder.payload()?;
    let terminal_at_ms = u64::from_be_bytes(
        decoder.fixed_field::<8>("tenant-root command receipt terminal timestamp")?,
    );
    let role_signing_key_id = decoder.text_field(
        "tenant-root command receipt role signing key id",
        MAX_ROLE_SIGNING_KEY_ID_BYTES_V1,
    )?;
    require_tenant_root_identifier(
        "tenant-root command receipt role signing key id",
        &role_signing_key_id,
    )?;
    let signature = decoder.fixed_field::<64>("tenant-root command receipt role signature")?;
    if signature.iter().all(|byte| *byte == 0) {
        return Err(malformed(
            "tenant-root command receipt role signature must be nonzero",
        ));
    }
    Ok(TenantRootCommandTerminalReceiptDataV1 {
        key: TenantRootCommandReplayKeyV1::new(
            identity_digest,
            custody_lineage,
            session_id,
            nonce,
            role,
        ),
        command_digest,
        payload,
        payload_digest,
        terminal_at_ms,
        role_signing_key_id,
        signature,
    })
}

fn validate_data(data: &TenantRootCommandTerminalReceiptDataV1) -> RouterAbDerivationResult<()> {
    require_tenant_root_identifier(
        "tenant-root command receipt role signing key id",
        &data.role_signing_key_id,
    )?;
    if data.role_signing_key_id.len() > MAX_ROLE_SIGNING_KEY_ID_BYTES_V1 {
        return Err(malformed(
            "tenant-root command receipt role signing key id is too long",
        ));
    }
    if data.payload.is_empty() || data.payload.len() > MAX_TERMINAL_PAYLOAD_BYTES_V1 {
        return Err(malformed(
            "tenant-root command receipt payload length is invalid",
        ));
    }
    if data.terminal_at_ms == 0 {
        return Err(malformed(
            "tenant-root command receipt terminal timestamp must be positive",
        ));
    }
    let actual_payload_digest = Sha256::digest(&data.payload);
    if data.payload_digest.as_bytes() != &actual_payload_digest[..] {
        return Err(malformed(
            "tenant-root command receipt payload digest does not match its bytes",
        ));
    }
    if data.signature.iter().all(|byte| *byte == 0) {
        return Err(malformed(
            "tenant-root command receipt role signature must be nonzero",
        ));
    }
    Ok(())
}

fn unsigned_canonical_bytes(
    outcome: TenantRootCommandTerminalOutcomeV1,
    key: &TenantRootCommandReplayKeyV1,
    command_digest: TenantRootProtocolDigestV1,
    payload: &[u8],
    payload_digest: TenantRootProtocolDigestV1,
    terminal_at_ms: u64,
    role_signing_key_id: &str,
) -> RouterAbDerivationResult<Vec<u8>> {
    require_tenant_root_identifier(
        "tenant-root command receipt role signing key id",
        role_signing_key_id,
    )?;
    if role_signing_key_id.len() > MAX_ROLE_SIGNING_KEY_ID_BYTES_V1 {
        return Err(malformed(
            "tenant-root command receipt role signing key id is too long",
        ));
    }
    if terminal_at_ms == 0 {
        return Err(malformed(
            "tenant-root command receipt terminal timestamp must be positive",
        ));
    }
    if payload.is_empty() || payload.len() > MAX_TERMINAL_PAYLOAD_BYTES_V1 {
        return Err(malformed(
            "tenant-root command receipt payload length is invalid",
        ));
    }
    let mut bytes = Vec::new();
    push_field(&mut bytes, TENANT_ROOT_COMMAND_TERMINAL_RECEIPT_DOMAIN_V1)?;
    push_field(&mut bytes, outcome.as_bytes())?;
    push_field(&mut bytes, key.identity_digest().as_bytes())?;
    push_field(&mut bytes, key.custody_lineage().as_bytes())?;
    push_role(&mut bytes, key.role())?;
    push_field(&mut bytes, key.session_id().as_bytes())?;
    push_field(&mut bytes, key.nonce().as_bytes())?;
    push_field(&mut bytes, command_digest.as_bytes())?;
    push_field(&mut bytes, payload_digest.as_bytes())?;
    push_field(&mut bytes, payload)?;
    push_field(&mut bytes, &terminal_at_ms.to_be_bytes())?;
    push_field(&mut bytes, role_signing_key_id.as_bytes())?;
    Ok(bytes)
}

fn canonical_bytes(
    outcome: TenantRootCommandTerminalOutcomeV1,
    data: &TenantRootCommandTerminalReceiptDataV1,
) -> RouterAbDerivationResult<Vec<u8>> {
    let unsigned = unsigned_canonical_bytes(
        outcome,
        &data.key,
        data.command_digest,
        &data.payload,
        data.payload_digest,
        data.terminal_at_ms,
        &data.role_signing_key_id,
    )?;
    canonical_bytes_from_unsigned(unsigned, &data.signature)
}

fn canonical_bytes_from_unsigned(
    unsigned: Vec<u8>,
    signature: &[u8; 64],
) -> RouterAbDerivationResult<Vec<u8>> {
    let mut bytes = unsigned;
    push_field(&mut bytes, signature)?;
    if bytes.len() > TENANT_ROOT_COMMAND_TERMINAL_RECEIPT_MAX_BYTES_V1 {
        return Err(malformed(
            "tenant-root command terminal receipt wire is too long",
        ));
    }
    Ok(bytes)
}

fn role_authentication_input(
    role: TwoPartyDeriverRole,
    role_signing_key_id: &str,
    unsigned: &[u8],
) -> RouterAbDerivationResult<Vec<u8>> {
    require_tenant_root_identifier(
        "tenant-root command receipt role signing key id",
        role_signing_key_id,
    )?;
    let mut bytes = Vec::new();
    push_field(
        &mut bytes,
        TENANT_ROOT_COMMAND_TERMINAL_RECEIPT_AUTH_DOMAIN_V1,
    )?;
    push_role(&mut bytes, role)?;
    push_field(&mut bytes, role_signing_key_id.as_bytes())?;
    push_field(&mut bytes, unsigned)?;
    Ok(bytes)
}

fn receipt_digest(
    canonical_bytes: Vec<u8>,
) -> RouterAbDerivationResult<TenantRootProtocolDigestV1> {
    TenantRootProtocolDigestV1::from_bytes(Sha256::digest(canonical_bytes).into())
}

fn payload_digest(payload: &[u8]) -> RouterAbDerivationResult<TenantRootProtocolDigestV1> {
    TenantRootProtocolDigestV1::from_bytes(Sha256::digest(payload).into())
}

fn push_role(out: &mut Vec<u8>, role: TwoPartyDeriverRole) -> RouterAbDerivationResult<()> {
    push_field(out, role.as_str().as_bytes())?;
    push_field(out, &role.share_id().get().get().to_be_bytes())
}

fn push_field(out: &mut Vec<u8>, value: &[u8]) -> RouterAbDerivationResult<()> {
    let length = u32::try_from(value.len())
        .map_err(|_| malformed("tenant-root command receipt field is too long"))?;
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

struct TerminalReceiptWireDecoderV1<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> TerminalReceiptWireDecoderV1<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn field(&mut self, name: &'static str) -> RouterAbDerivationResult<&'a [u8]> {
        let length_end = self
            .offset
            .checked_add(4)
            .ok_or_else(|| malformed("tenant-root command receipt wire offset overflow"))?;
        let length_bytes = self
            .bytes
            .get(self.offset..length_end)
            .ok_or_else(|| malformed("tenant-root command receipt field length is truncated"))?;
        let length = u32::from_be_bytes(
            length_bytes
                .try_into()
                .expect("fixed four-byte command receipt field length"),
        ) as usize;
        let value_end = length_end
            .checked_add(length)
            .ok_or_else(|| malformed("tenant-root command receipt field length overflows"))?;
        let value = self
            .bytes
            .get(length_end..value_end)
            .ok_or_else(|| malformed("tenant-root command receipt field is truncated"))?;
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
        if self.field("tenant-root command receipt wire domain")? != expected {
            return Err(malformed(
                "tenant-root command receipt wire domain is invalid",
            ));
        }
        Ok(())
    }

    fn outcome(&mut self) -> RouterAbDerivationResult<TenantRootCommandTerminalOutcomeV1> {
        match self.field("tenant-root command receipt outcome")? {
            b"success" => Ok(TenantRootCommandTerminalOutcomeV1::Success),
            b"failure" => Ok(TenantRootCommandTerminalOutcomeV1::Failure),
            _ => Err(malformed("tenant-root command receipt outcome is invalid")),
        }
    }

    fn role(&mut self) -> RouterAbDerivationResult<TwoPartyDeriverRole> {
        let label = self.field("tenant-root command receipt role")?;
        let share_id = self.fixed_field::<2>("tenant-root command receipt role share id")?;
        match (label, u16::from_be_bytes(share_id)) {
            (b"deriver_a", 1) => Ok(TwoPartyDeriverRole::DeriverA),
            (b"deriver_b", 2) => Ok(TwoPartyDeriverRole::DeriverB),
            _ => Err(malformed(
                "tenant-root command receipt role encoding is invalid",
            )),
        }
    }

    fn payload(&mut self) -> RouterAbDerivationResult<Vec<u8>> {
        let payload = self.field("tenant-root command receipt payload")?;
        if payload.len() > MAX_TERMINAL_PAYLOAD_BYTES_V1 {
            return Err(malformed("tenant-root command receipt payload is too long"));
        }
        Ok(payload.to_vec())
    }

    fn fixed_field<const N: usize>(
        &mut self,
        name: &'static str,
    ) -> RouterAbDerivationResult<[u8; N]> {
        self.field(name)?
            .try_into()
            .map_err(|_| malformed("tenant-root command receipt fixed field length is invalid"))
    }

    fn text_field(
        &mut self,
        name: &'static str,
        max_bytes: usize,
    ) -> RouterAbDerivationResult<String> {
        let bytes = self.field(name)?;
        if bytes.len() > max_bytes {
            return Err(malformed(
                "tenant-root command receipt text field is too long",
            ));
        }
        core::str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|_| malformed("tenant-root command receipt text field is invalid UTF-8"))
    }

    fn finish(self) -> RouterAbDerivationResult<()> {
        if self.offset != self.bytes.len() {
            return Err(malformed(
                "tenant-root command receipt wire has trailing bytes",
            ));
        }
        Ok(())
    }
}
