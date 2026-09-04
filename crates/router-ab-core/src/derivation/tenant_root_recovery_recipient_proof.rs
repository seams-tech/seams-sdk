use core::{fmt, num::NonZeroU64};

use hmac::{Hmac, Mac};
use hpke_ng::{Aes256Gcm, DhKemX25519HkdfSha256, HkdfSha256, Hpke, Kem};
use rand_core_09::{CryptoRng, RngCore};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use threshold_prf::{ThresholdShareId, TwoPartyDeriverRole};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::x25519_canonical::is_canonical_nonzero_x25519_encoding;
use super::{
    RouterAbDerivationError, RouterAbDerivationErrorCode, RouterAbDerivationResult,
    TenantRootCustodyLineageId, TenantRootIdentityDigestV1,
    TenantRootRecoveryRecipientFingerprintV1, TenantRootRecoveryRecipientKeypairV1,
    TenantRootRecoveryRecipientPublicKeyV1,
};

const RECOVERY_RECIPIENT_PROOF_AAD_DOMAIN_V1: &[u8] =
    b"seams/tenant-root-recovery-recipient-proof/aad/v1";
const RECOVERY_RECIPIENT_PROOF_CONFIRMATION_DOMAIN_V1: &[u8] =
    b"seams/tenant-root-recovery-recipient-proof/confirmation/v1";
const RECOVERY_RECIPIENT_PROOF_HPKE_INFO_V1: &[u8] =
    b"seams/tenant-root-recovery-recipient-proof/hpke-x25519-hkdf-sha256-aes256gcm/v1";
const RECOVERY_RECIPIENT_PROOF_ENVELOPE_MAGIC: &[u8; 8] = b"SEAMRCP1";
const RECOVERY_RECIPIENT_PROOF_KEY_BYTES: usize = 32;
const RECOVERY_RECIPIENT_PROOF_CHALLENGE_ID_BYTES: usize = 16;
const RECOVERY_RECIPIENT_PROOF_FINGERPRINT_BYTES: usize = 32;
const RECOVERY_RECIPIENT_PROOF_HMAC_BYTES: usize = 32;
const RECOVERY_RECIPIENT_PROOF_HPKE_TAG_BYTES: usize = 16;
const RECOVERY_RECIPIENT_PROOF_CIPHERTEXT_BYTES: usize =
    RECOVERY_RECIPIENT_PROOF_KEY_BYTES + RECOVERY_RECIPIENT_PROOF_HPKE_TAG_BYTES;
const RECOVERY_RECIPIENT_PROOF_MAX_BYTES_V1: usize = 16 * 1024;

type TenantRootRecoveryRecipientProofHpkeV1 = Hpke<DhKemX25519HkdfSha256, HkdfSha256, Aes256Gcm>;
type HmacSha256 = Hmac<Sha256>;

/// Maximum encoded size of one recovery-recipient proof envelope.
pub const TENANT_ROOT_RECOVERY_RECIPIENT_PROOF_MAX_BYTES: usize =
    RECOVERY_RECIPIENT_PROOF_MAX_BYTES_V1;

/// One exact public binding for a recovery-recipient control challenge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantRootRecoveryRecipientProofBindingV1 {
    challenge_id: [u8; RECOVERY_RECIPIENT_PROOF_CHALLENGE_ID_BYTES],
    tenant_identity_digest: TenantRootIdentityDigestV1,
    custody_lineage: TenantRootCustodyLineageId,
    role: TwoPartyDeriverRole,
    share_id: ThresholdShareId,
    recipient_fingerprint: TenantRootRecoveryRecipientFingerprintV1,
    actor_id: String,
    lifecycle_revision: NonZeroU64,
    issued_at_ms: u64,
    expires_at_ms: u64,
}

impl TenantRootRecoveryRecipientProofBindingV1 {
    /// Creates and validates one exact challenge binding.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        challenge_id: [u8; RECOVERY_RECIPIENT_PROOF_CHALLENGE_ID_BYTES],
        tenant_identity_digest: TenantRootIdentityDigestV1,
        custody_lineage: TenantRootCustodyLineageId,
        role: TwoPartyDeriverRole,
        share_id: ThresholdShareId,
        recipient_fingerprint: TenantRootRecoveryRecipientFingerprintV1,
        actor_id: impl Into<String>,
        lifecycle_revision: u64,
        issued_at_ms: u64,
        expires_at_ms: u64,
    ) -> RouterAbDerivationResult<Self> {
        let binding = Self {
            challenge_id,
            tenant_identity_digest,
            custody_lineage,
            role,
            share_id,
            recipient_fingerprint,
            actor_id: actor_id.into(),
            lifecycle_revision: NonZeroU64::new(lifecycle_revision).ok_or_else(|| {
                malformed(
                    "tenant-root recovery recipient proof lifecycle revision must be positive",
                )
            })?,
            issued_at_ms,
            expires_at_ms,
        };
        binding.validate()?;
        Ok(binding)
    }

    /// Validates all fields and role/share identity constraints.
    pub fn validate(&self) -> RouterAbDerivationResult<()> {
        if bool::from(
            self.challenge_id
                .ct_eq(&[0_u8; RECOVERY_RECIPIENT_PROOF_CHALLENGE_ID_BYTES]),
        ) {
            return Err(malformed(
                "tenant-root recovery recipient proof challenge id must be non-zero",
            ));
        }
        if self.role.share_id() != self.share_id {
            return Err(malformed(
                "tenant-root recovery recipient proof role and share id do not match",
            ));
        }
        if self.actor_id.is_empty() {
            return Err(RouterAbDerivationError::new(
                RouterAbDerivationErrorCode::EmptyField,
                "tenant-root recovery recipient proof actor id is required",
            ));
        }
        u32::try_from(self.actor_id.len())
            .map_err(|_| malformed("tenant-root recovery recipient proof actor id is too long"))?;
        if self.issued_at_ms == 0 || self.expires_at_ms <= self.issued_at_ms {
            return Err(malformed(
                "tenant-root recovery recipient proof expiry must follow a non-zero issue time",
            ));
        }
        Ok(())
    }

    /// Returns the challenge identifier.
    pub const fn challenge_id(&self) -> &[u8; RECOVERY_RECIPIENT_PROOF_CHALLENGE_ID_BYTES] {
        &self.challenge_id
    }

    /// Returns the tenant identity digest.
    pub const fn tenant_identity_digest(&self) -> TenantRootIdentityDigestV1 {
        self.tenant_identity_digest
    }

    /// Returns the deployment custody lineage.
    pub const fn custody_lineage(&self) -> TenantRootCustodyLineageId {
        self.custody_lineage
    }

    /// Returns the fixed Deriver role.
    pub const fn role(&self) -> TwoPartyDeriverRole {
        self.role
    }

    /// Returns the role's fixed share identifier.
    pub const fn share_id(&self) -> ThresholdShareId {
        self.share_id
    }

    /// Returns the bound recipient public-key fingerprint.
    pub const fn recipient_fingerprint(&self) -> TenantRootRecoveryRecipientFingerprintV1 {
        self.recipient_fingerprint
    }

    /// Returns the exact actor identifier.
    pub fn actor_id(&self) -> &str {
        &self.actor_id
    }

    /// Returns the positive lifecycle revision.
    pub const fn lifecycle_revision(&self) -> NonZeroU64 {
        self.lifecycle_revision
    }

    /// Returns the issue timestamp in milliseconds.
    pub const fn issued_at_ms(&self) -> u64 {
        self.issued_at_ms
    }

    /// Returns the expiry timestamp in milliseconds.
    pub const fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }

    /// Returns the exact LP32 canonical authenticated-data bytes.
    pub fn canonical_aad_bytes(&self) -> RouterAbDerivationResult<Vec<u8>> {
        self.validate()?;
        let mut bytes = Vec::new();
        append_binding_domain_and_fields(&mut bytes, RECOVERY_RECIPIENT_PROOF_AAD_DOMAIN_V1, self)?;
        Ok(bytes)
    }

    /// Returns the exact canonical bytes used as HPKE authenticated data.
    pub fn canonical_bytes(&self) -> RouterAbDerivationResult<Vec<u8>> {
        self.canonical_aad_bytes()
    }

    /// Returns the separately domain-separated confirmation transcript bytes.
    pub fn canonical_confirmation_bytes(&self) -> RouterAbDerivationResult<Vec<u8>> {
        self.validate()?;
        let mut bytes = Vec::new();
        append_binding_domain_and_fields(
            &mut bytes,
            RECOVERY_RECIPIENT_PROOF_CONFIRMATION_DOMAIN_V1,
            self,
        )?;
        Ok(bytes)
    }
}

/// A fixed-width HMAC-SHA-256 confirmation returned by the controlled recipient.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TenantRootRecoveryRecipientProofConfirmationV1(
    [u8; RECOVERY_RECIPIENT_PROOF_HMAC_BYTES],
);

impl fmt::Debug for TenantRootRecoveryRecipientProofConfirmationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TenantRootRecoveryRecipientProofConfirmationV1([redacted])")
    }
}

impl TenantRootRecoveryRecipientProofConfirmationV1 {
    /// Parses one exact HMAC-SHA-256 confirmation.
    pub const fn from_bytes(bytes: [u8; RECOVERY_RECIPIENT_PROOF_HMAC_BYTES]) -> Self {
        Self(bytes)
    }

    /// Returns the exact confirmation bytes.
    pub const fn as_bytes(&self) -> &[u8; RECOVERY_RECIPIENT_PROOF_HMAC_BYTES] {
        &self.0
    }

    /// Returns a copy of the exact confirmation bytes.
    pub const fn into_bytes(self) -> [u8; RECOVERY_RECIPIENT_PROOF_HMAC_BYTES] {
        self.0
    }
}

/// A zeroizing 32-byte challenge secret opened from a proof envelope.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct TenantRootRecoveryRecipientProofSecretV1([u8; RECOVERY_RECIPIENT_PROOF_KEY_BYTES]);

impl fmt::Debug for TenantRootRecoveryRecipientProofSecretV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TenantRootRecoveryRecipientProofSecretV1([redacted])")
    }
}

impl TenantRootRecoveryRecipientProofSecretV1 {
    /// Constructs one non-zero challenge secret from exact bytes.
    pub fn from_bytes(
        bytes: [u8; RECOVERY_RECIPIENT_PROOF_KEY_BYTES],
    ) -> RouterAbDerivationResult<Self> {
        if bool::from(bytes.ct_eq(&[0_u8; RECOVERY_RECIPIENT_PROOF_KEY_BYTES])) {
            return Err(malformed(
                "tenant-root recovery recipient proof challenge secret must be non-zero",
            ));
        }
        Ok(Self(bytes))
    }

    /// Returns a borrowed view of the secret bytes for the HMAC boundary.
    pub const fn as_bytes(&self) -> &[u8; RECOVERY_RECIPIENT_PROOF_KEY_BYTES] {
        &self.0
    }
}

/// Fixed-shape encrypted recovery-recipient proof challenge.
#[derive(Clone, PartialEq, Eq)]
pub struct TenantRootRecoveryRecipientProofEnvelopeV1 {
    binding: TenantRootRecoveryRecipientProofBindingV1,
    encapsulated_key: [u8; RECOVERY_RECIPIENT_PROOF_KEY_BYTES],
    ciphertext: [u8; RECOVERY_RECIPIENT_PROOF_CIPHERTEXT_BYTES],
}

impl fmt::Debug for TenantRootRecoveryRecipientProofEnvelopeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TenantRootRecoveryRecipientProofEnvelopeV1")
            .field("binding", &self.binding)
            .field("encapsulated_key", &hex::encode(self.encapsulated_key))
            .field("ciphertext", &"[redacted]")
            .finish()
    }
}

impl TenantRootRecoveryRecipientProofEnvelopeV1 {
    /// Encrypts exactly one 32-byte non-zero challenge secret to one recipient.
    pub fn seal<R>(
        binding: TenantRootRecoveryRecipientProofBindingV1,
        recipient: TenantRootRecoveryRecipientPublicKeyV1,
        challenge_secret: [u8; RECOVERY_RECIPIENT_PROOF_KEY_BYTES],
        rng: &mut R,
    ) -> RouterAbDerivationResult<Self>
    where
        R: RngCore + CryptoRng,
    {
        binding.validate()?;
        require_recipient_fingerprint(&binding, &recipient)?;
        let recipient_key = DhKemX25519HkdfSha256::pk_from_bytes(recipient.as_bytes())
            .map_err(|_| malformed("tenant-root recovery recipient proof public key is invalid"))?;
        let mut challenge_secret = Zeroizing::new(challenge_secret);
        TenantRootRecoveryRecipientProofSecretV1::from_bytes(*challenge_secret)?;
        let aad = binding.canonical_aad_bytes()?;
        let plaintext = Zeroizing::new(*challenge_secret);
        let (encapsulated_key, ciphertext) = TenantRootRecoveryRecipientProofHpkeV1::seal_base(
            rng,
            &recipient_key,
            RECOVERY_RECIPIENT_PROOF_HPKE_INFO_V1,
            &aad,
            plaintext.as_ref(),
        )
        .map_err(|_| {
            verification_failed("tenant-root recovery recipient proof encryption failed")
        })?;
        challenge_secret.zeroize();
        let encapsulated_key: [u8; RECOVERY_RECIPIENT_PROOF_KEY_BYTES] =
            encapsulated_key.as_ref().try_into().map_err(|_| {
                malformed("tenant-root recovery recipient proof encapsulated key length is invalid")
            })?;
        let ciphertext: [u8; RECOVERY_RECIPIENT_PROOF_CIPHERTEXT_BYTES] =
            ciphertext.try_into().map_err(|_| {
                malformed("tenant-root recovery recipient proof ciphertext length is invalid")
            })?;
        validate_encapsulated_key(&encapsulated_key)?;
        let envelope = Self {
            binding,
            encapsulated_key,
            ciphertext,
        };
        envelope.validate_encoded_size()?;
        Ok(envelope)
    }

    /// Returns the exact public challenge binding.
    pub const fn binding(&self) -> &TenantRootRecoveryRecipientProofBindingV1 {
        &self.binding
    }

    /// Returns the exact HPKE encapsulated key.
    pub const fn encapsulated_key(&self) -> &[u8; RECOVERY_RECIPIENT_PROOF_KEY_BYTES] {
        &self.encapsulated_key
    }

    /// Returns the fixed ciphertext bytes without exposing decrypted material.
    pub const fn ciphertext(&self) -> &[u8; RECOVERY_RECIPIENT_PROOF_CIPHERTEXT_BYTES] {
        &self.ciphertext
    }

    /// Returns the exact canonical envelope bytes.
    pub fn canonical_bytes(&self) -> RouterAbDerivationResult<Vec<u8>> {
        self.to_bytes()
    }

    /// Encodes the complete fixed-capped binary envelope.
    pub fn to_bytes(&self) -> RouterAbDerivationResult<Vec<u8>> {
        self.binding.validate()?;
        self.validate_encoded_size()?;
        let binding = self.binding.canonical_aad_bytes()?;
        let binding_len = u32::try_from(binding.len())
            .map_err(|_| malformed("tenant-root recovery recipient proof binding is too long"))?;
        let ciphertext_len = u32::try_from(self.ciphertext.len()).map_err(|_| {
            malformed("tenant-root recovery recipient proof ciphertext is too long")
        })?;
        let capacity = RECOVERY_RECIPIENT_PROOF_ENVELOPE_MAGIC.len()
            + 4
            + binding.len()
            + RECOVERY_RECIPIENT_PROOF_KEY_BYTES
            + 4
            + self.ciphertext.len();
        let mut bytes = Vec::with_capacity(capacity);
        bytes.extend_from_slice(RECOVERY_RECIPIENT_PROOF_ENVELOPE_MAGIC);
        bytes.extend_from_slice(&binding_len.to_be_bytes());
        bytes.extend_from_slice(&binding);
        bytes.extend_from_slice(&self.encapsulated_key);
        bytes.extend_from_slice(&ciphertext_len.to_be_bytes());
        bytes.extend_from_slice(&self.ciphertext);
        Ok(bytes)
    }

    /// Decodes one exact capped envelope and rejects non-canonical bytes.
    pub fn decode(bytes: &[u8]) -> RouterAbDerivationResult<Self> {
        if bytes.len() > RECOVERY_RECIPIENT_PROOF_MAX_BYTES_V1 {
            return Err(malformed(
                "tenant-root recovery recipient proof envelope exceeds size cap",
            ));
        }
        let mut cursor = 0_usize;
        let magic = take_bytes(
            bytes,
            &mut cursor,
            RECOVERY_RECIPIENT_PROOF_ENVELOPE_MAGIC.len(),
        )?;
        if magic != RECOVERY_RECIPIENT_PROOF_ENVELOPE_MAGIC {
            return Err(malformed(
                "tenant-root recovery recipient proof envelope magic is invalid",
            ));
        }
        let binding_len = usize::try_from(read_u32_be(bytes, &mut cursor)?).map_err(|_| {
            malformed("tenant-root recovery recipient proof binding length is invalid")
        })?;
        if binding_len > RECOVERY_RECIPIENT_PROOF_MAX_BYTES_V1 {
            return Err(malformed(
                "tenant-root recovery recipient proof binding exceeds size cap",
            ));
        }
        let binding_bytes = take_bytes(bytes, &mut cursor, binding_len)?;
        let binding = decode_binding(binding_bytes)?;
        let encapsulated_key =
            take_fixed_bytes::<RECOVERY_RECIPIENT_PROOF_KEY_BYTES>(bytes, &mut cursor)?;
        validate_encapsulated_key(&encapsulated_key)?;
        let ciphertext_len = usize::try_from(read_u32_be(bytes, &mut cursor)?).map_err(|_| {
            malformed("tenant-root recovery recipient proof ciphertext length is invalid")
        })?;
        if ciphertext_len != RECOVERY_RECIPIENT_PROOF_CIPHERTEXT_BYTES {
            return Err(malformed(
                "tenant-root recovery recipient proof ciphertext length is invalid",
            ));
        }
        let ciphertext =
            take_fixed_bytes::<RECOVERY_RECIPIENT_PROOF_CIPHERTEXT_BYTES>(bytes, &mut cursor)?;
        if cursor != bytes.len() {
            return Err(malformed(
                "tenant-root recovery recipient proof envelope has trailing bytes",
            ));
        }
        let envelope = Self {
            binding,
            encapsulated_key,
            ciphertext,
        };
        envelope.validate_encoded_size()?;
        Ok(envelope)
    }

    /// Opens one exact envelope with the matching recipient private key.
    pub fn open(
        &self,
        recipient: &TenantRootRecoveryRecipientKeypairV1,
    ) -> RouterAbDerivationResult<TenantRootRecoveryRecipientProofSecretV1> {
        self.binding.validate()?;
        let recipient_public_key = recipient.public_key();
        require_recipient_fingerprint(&self.binding, &recipient_public_key)?;
        validate_encapsulated_key(&self.encapsulated_key)?;
        let private_key = DhKemX25519HkdfSha256::sk_from_bytes(recipient.private_key_bytes())
            .map_err(|_| {
                malformed("tenant-root recovery recipient proof private key is invalid")
            })?;
        let encapsulated_key = DhKemX25519HkdfSha256::enc_from_bytes(&self.encapsulated_key)
            .map_err(|_| {
                malformed("tenant-root recovery recipient proof encapsulated key is invalid")
            })?;
        let aad = self.binding.canonical_aad_bytes()?;
        let plaintext = Zeroizing::new(
            TenantRootRecoveryRecipientProofHpkeV1::open_base(
                &encapsulated_key,
                &private_key,
                RECOVERY_RECIPIENT_PROOF_HPKE_INFO_V1,
                &aad,
                &self.ciphertext,
            )
            .map_err(|_| {
                verification_failed("tenant-root recovery recipient proof decryption failed")
            })?,
        );
        if plaintext.len() != RECOVERY_RECIPIENT_PROOF_KEY_BYTES {
            return Err(malformed(
                "tenant-root recovery recipient proof plaintext length is invalid",
            ));
        }
        let mut secret = [0_u8; RECOVERY_RECIPIENT_PROOF_KEY_BYTES];
        secret.copy_from_slice(&plaintext);
        TenantRootRecoveryRecipientProofSecretV1::from_bytes(secret)
    }

    fn validate_encoded_size(&self) -> RouterAbDerivationResult<()> {
        if self.ciphertext.len() != RECOVERY_RECIPIENT_PROOF_CIPHERTEXT_BYTES {
            return Err(malformed(
                "tenant-root recovery recipient proof ciphertext length is invalid",
            ));
        }
        let binding_len = self.binding.canonical_aad_bytes()?.len();
        let total = RECOVERY_RECIPIENT_PROOF_ENVELOPE_MAGIC
            .len()
            .checked_add(4)
            .and_then(|value| value.checked_add(binding_len))
            .and_then(|value| value.checked_add(RECOVERY_RECIPIENT_PROOF_KEY_BYTES))
            .and_then(|value| value.checked_add(4))
            .and_then(|value| value.checked_add(self.ciphertext.len()))
            .ok_or_else(|| {
                malformed("tenant-root recovery recipient proof envelope length overflows")
            })?;
        if total > RECOVERY_RECIPIENT_PROOF_MAX_BYTES_V1 {
            return Err(malformed(
                "tenant-root recovery recipient proof envelope exceeds size cap",
            ));
        }
        Ok(())
    }
}

/// Computes the recipient confirmation for one opened challenge secret.
pub fn confirm_tenant_root_recovery_recipient_proof_v1(
    binding: &TenantRootRecoveryRecipientProofBindingV1,
    challenge_secret: &[u8; RECOVERY_RECIPIENT_PROOF_KEY_BYTES],
) -> RouterAbDerivationResult<TenantRootRecoveryRecipientProofConfirmationV1> {
    binding.validate()?;
    let challenge_secret = Zeroizing::new(*challenge_secret);
    TenantRootRecoveryRecipientProofSecretV1::from_bytes(*challenge_secret)?;
    let transcript = binding.canonical_confirmation_bytes()?;
    Ok(TenantRootRecoveryRecipientProofConfirmationV1(hmac_sha256(
        &challenge_secret,
        &transcript,
    )))
}

/// Verifies one confirmation in constant time against the exact binding.
pub fn verify_tenant_root_recovery_recipient_proof_v1(
    binding: &TenantRootRecoveryRecipientProofBindingV1,
    challenge_secret: &[u8; RECOVERY_RECIPIENT_PROOF_KEY_BYTES],
    confirmation: &TenantRootRecoveryRecipientProofConfirmationV1,
) -> RouterAbDerivationResult<()> {
    let expected = confirm_tenant_root_recovery_recipient_proof_v1(binding, challenge_secret)?;
    if bool::from(expected.as_bytes().ct_eq(confirmation.as_bytes())) {
        Ok(())
    } else {
        Err(verification_failed(
            "tenant-root recovery recipient proof confirmation is invalid",
        ))
    }
}

/// Decodes one binary recovery-recipient proof envelope.
pub fn decode_tenant_root_recovery_recipient_proof_v1(
    bytes: &[u8],
) -> RouterAbDerivationResult<TenantRootRecoveryRecipientProofEnvelopeV1> {
    TenantRootRecoveryRecipientProofEnvelopeV1::decode(bytes)
}

/// Encrypts one recovery-recipient proof challenge envelope.
pub fn seal_tenant_root_recovery_recipient_proof_v1<R>(
    binding: TenantRootRecoveryRecipientProofBindingV1,
    recipient: TenantRootRecoveryRecipientPublicKeyV1,
    challenge_secret: [u8; RECOVERY_RECIPIENT_PROOF_KEY_BYTES],
    rng: &mut R,
) -> RouterAbDerivationResult<TenantRootRecoveryRecipientProofEnvelopeV1>
where
    R: RngCore + CryptoRng,
{
    TenantRootRecoveryRecipientProofEnvelopeV1::seal(binding, recipient, challenge_secret, rng)
}

/// Opens one recovery-recipient proof envelope with its private key.
pub fn open_tenant_root_recovery_recipient_proof_v1(
    envelope: &TenantRootRecoveryRecipientProofEnvelopeV1,
    recipient: &TenantRootRecoveryRecipientKeypairV1,
) -> RouterAbDerivationResult<TenantRootRecoveryRecipientProofSecretV1> {
    envelope.open(recipient)
}

fn append_binding_domain_and_fields(
    out: &mut Vec<u8>,
    domain: &[u8],
    binding: &TenantRootRecoveryRecipientProofBindingV1,
) -> RouterAbDerivationResult<()> {
    push_lp32(out, domain)?;
    push_lp32(out, &binding.challenge_id)?;
    push_lp32(out, binding.tenant_identity_digest.as_bytes())?;
    push_lp32(out, binding.custody_lineage.as_bytes())?;
    push_lp32(out, binding.role.as_str().as_bytes())?;
    push_lp32(out, &binding.share_id.get().get().to_be_bytes())?;
    push_lp32(out, binding.recipient_fingerprint.as_bytes())?;
    push_lp32(out, binding.actor_id.as_bytes())?;
    push_lp32(out, &binding.lifecycle_revision.get().to_be_bytes())?;
    push_lp32(out, &binding.issued_at_ms.to_be_bytes())?;
    push_lp32(out, &binding.expires_at_ms.to_be_bytes())?;
    Ok(())
}

fn decode_binding(
    bytes: &[u8],
) -> RouterAbDerivationResult<TenantRootRecoveryRecipientProofBindingV1> {
    let mut cursor = 0_usize;
    let domain = take_lp32(bytes, &mut cursor)?;
    if domain != RECOVERY_RECIPIENT_PROOF_AAD_DOMAIN_V1 {
        return Err(malformed(
            "tenant-root recovery recipient proof authenticated-data domain is invalid",
        ));
    }
    let challenge_id =
        take_fixed_lp32::<RECOVERY_RECIPIENT_PROOF_CHALLENGE_ID_BYTES>(bytes, &mut cursor)?;
    let tenant_identity_digest = TenantRootIdentityDigestV1::from_bytes(take_fixed_lp32::<
        RECOVERY_RECIPIENT_PROOF_KEY_BYTES,
    >(bytes, &mut cursor)?);
    let custody_lineage = TenantRootCustodyLineageId::from_bytes(take_fixed_lp32::<
        RECOVERY_RECIPIENT_PROOF_CHALLENGE_ID_BYTES,
    >(bytes, &mut cursor)?)?;
    let role = parse_role(take_lp32(bytes, &mut cursor)?)?;
    let share_id = ThresholdShareId::from_u16(u16::from_be_bytes(take_fixed_lp32::<2>(
        bytes,
        &mut cursor,
    )?))
    .map_err(|_| malformed("tenant-root recovery recipient proof share id is invalid"))?;
    let recipient_fingerprint =
        TenantRootRecoveryRecipientFingerprintV1::from_bytes(take_fixed_lp32::<
            RECOVERY_RECIPIENT_PROOF_FINGERPRINT_BYTES,
        >(bytes, &mut cursor)?);
    let actor_id = String::from_utf8(take_lp32(bytes, &mut cursor)?.to_vec())
        .map_err(|_| malformed("tenant-root recovery recipient proof actor id is invalid UTF-8"))?;
    let lifecycle_revision = u64::from_be_bytes(take_fixed_lp32::<8>(bytes, &mut cursor)?);
    let issued_at_ms = u64::from_be_bytes(take_fixed_lp32::<8>(bytes, &mut cursor)?);
    let expires_at_ms = u64::from_be_bytes(take_fixed_lp32::<8>(bytes, &mut cursor)?);
    if cursor != bytes.len() {
        return Err(malformed(
            "tenant-root recovery recipient proof binding has trailing bytes",
        ));
    }
    let binding = TenantRootRecoveryRecipientProofBindingV1::new(
        challenge_id,
        tenant_identity_digest,
        custody_lineage,
        role,
        share_id,
        recipient_fingerprint,
        actor_id,
        lifecycle_revision,
        issued_at_ms,
        expires_at_ms,
    )?;
    if binding.canonical_aad_bytes()?.as_slice() != bytes {
        return Err(malformed(
            "tenant-root recovery recipient proof binding is not canonical",
        ));
    }
    Ok(binding)
}

fn parse_role(bytes: &[u8]) -> RouterAbDerivationResult<TwoPartyDeriverRole> {
    match bytes {
        b"deriver_a" => Ok(TwoPartyDeriverRole::DeriverA),
        b"deriver_b" => Ok(TwoPartyDeriverRole::DeriverB),
        _ => Err(malformed(
            "tenant-root recovery recipient proof role is invalid",
        )),
    }
}

fn require_recipient_fingerprint(
    binding: &TenantRootRecoveryRecipientProofBindingV1,
    recipient: &TenantRootRecoveryRecipientPublicKeyV1,
) -> RouterAbDerivationResult<()> {
    if bool::from(
        binding
            .recipient_fingerprint
            .as_bytes()
            .ct_eq(recipient.fingerprint().as_bytes()),
    ) {
        Ok(())
    } else {
        Err(RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::RecipientMismatch,
            "tenant-root recovery recipient proof public key does not match its binding",
        ))
    }
}

fn validate_encapsulated_key(
    bytes: &[u8; RECOVERY_RECIPIENT_PROOF_KEY_BYTES],
) -> RouterAbDerivationResult<()> {
    if !is_canonical_nonzero_x25519_encoding(bytes) {
        return Err(malformed(
            "tenant-root recovery recipient proof encapsulated key is not canonical",
        ));
    }
    let decoded = DhKemX25519HkdfSha256::enc_from_bytes(bytes).map_err(|_| {
        malformed("tenant-root recovery recipient proof encapsulated key is invalid")
    })?;
    if decoded.as_ref() != bytes {
        return Err(malformed(
            "tenant-root recovery recipient proof encapsulated key is not canonical",
        ));
    }
    Ok(())
}

fn hmac_sha256(key: &[u8; RECOVERY_RECIPIENT_PROOF_KEY_BYTES], message: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC-SHA-256 accepts a 32-byte key");
    mac.update(message);
    mac.finalize().into_bytes().into()
}

fn push_lp32(out: &mut Vec<u8>, value: &[u8]) -> RouterAbDerivationResult<()> {
    let length = u32::try_from(value.len())
        .map_err(|_| malformed("tenant-root recovery recipient proof field is too long"))?;
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(value);
    Ok(())
}

fn take_lp32<'a>(bytes: &'a [u8], cursor: &mut usize) -> RouterAbDerivationResult<&'a [u8]> {
    let length = usize::try_from(read_u32_be(bytes, cursor)?)
        .map_err(|_| malformed("tenant-root recovery recipient proof field length is invalid"))?;
    take_bytes(bytes, cursor, length)
}

fn take_fixed_lp32<const N: usize>(
    bytes: &[u8],
    cursor: &mut usize,
) -> RouterAbDerivationResult<[u8; N]> {
    let value = take_lp32(bytes, cursor)?;
    value.try_into().map_err(|_| {
        malformed("tenant-root recovery recipient proof fixed field length is invalid")
    })
}

fn take_fixed_bytes<const N: usize>(
    bytes: &[u8],
    cursor: &mut usize,
) -> RouterAbDerivationResult<[u8; N]> {
    take_bytes(bytes, cursor, N)?
        .try_into()
        .map_err(|_| malformed("tenant-root recovery recipient proof fixed field is truncated"))
}

fn take_bytes<'a>(
    bytes: &'a [u8],
    cursor: &mut usize,
    length: usize,
) -> RouterAbDerivationResult<&'a [u8]> {
    let end = cursor
        .checked_add(length)
        .ok_or_else(|| malformed("tenant-root recovery recipient proof length overflows"))?;
    if end > bytes.len() {
        return Err(malformed(
            "tenant-root recovery recipient proof envelope is truncated",
        ));
    }
    let value = &bytes[*cursor..end];
    *cursor = end;
    Ok(value)
}

fn read_u32_be(bytes: &[u8], cursor: &mut usize) -> RouterAbDerivationResult<u32> {
    Ok(u32::from_be_bytes(take_fixed_bytes::<4>(bytes, cursor)?))
}

fn malformed(message: &'static str) -> RouterAbDerivationError {
    RouterAbDerivationError::new(RouterAbDerivationErrorCode::MalformedInput, message)
}

fn verification_failed(message: &'static str) -> RouterAbDerivationError {
    RouterAbDerivationError::new(
        RouterAbDerivationErrorCode::OutputVerificationFailed,
        message,
    )
}
