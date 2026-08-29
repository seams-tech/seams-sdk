use core::fmt;

use hpke_ng::{Aes256Gcm, DhKemX25519HkdfSha256, HkdfSha256, Hpke, Kem};
use rand_core_09::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use threshold_prf::{
    SigningRootShareCommitment, SigningRootShareWire, ThresholdShareId, TwoPartyDeriverRole,
    TwoPartyRootCommitment,
};
use zeroize::{Zeroize, Zeroizing};

use super::x25519_canonical::is_canonical_nonzero_x25519_encoding;
use super::{
    RouterAbDerivationError, RouterAbDerivationErrorCode, RouterAbDerivationResult,
    TenantRootCustodyLineageId, TenantRootIdentityDigestV1, TenantRootRecoveryPackageDigestV1,
    TenantRootRecoverySetId, VerifiedTenantRootRecoveryRoleShareV1,
};

const RESTORE_IMPORT_DOMAIN_V1: &[u8] = b"seams/tenant-root-restore-import/v1";
const RESTORE_IMPORT_HPKE_INFO_V1: &[u8] =
    b"seams/tenant-root-restore-import/hpke-x25519-hkdf-sha256-aes256gcm/v1";
const RESTORE_IMPORT_MAGIC_V1: &[u8; 8] = b"SEAMSRI1";
const RESTORE_IMPORT_KEY_BYTES: usize = 32;
const RESTORE_IMPORT_ID_BYTES: usize = 16;
const RESTORE_IMPORT_CIPHERTEXT_BYTES: usize = SigningRootShareWire::LEN + 16;
const RESTORE_IMPORT_MAX_BYTES_V1: usize = 16 * 1024;

type TenantRootRestoreImportHpkeV1 = Hpke<DhKemX25519HkdfSha256, HkdfSha256, Aes256Gcm>;

/// Maximum encoded size of one destination role import envelope.
pub const TENANT_ROOT_RESTORE_IMPORT_MAX_BYTES: usize = RESTORE_IMPORT_MAX_BYTES_V1;

/// Public fingerprint of one empty destination deployment.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TenantRootRestoreDestinationFingerprintV1([u8; RESTORE_IMPORT_KEY_BYTES]);

impl TenantRootRestoreDestinationFingerprintV1 {
    pub fn from_bytes(bytes: [u8; RESTORE_IMPORT_KEY_BYTES]) -> RouterAbDerivationResult<Self> {
        require_nonzero(
            &bytes,
            "destination deployment fingerprint must be non-zero",
        )?;
        Ok(Self(bytes))
    }

    pub const fn as_bytes(&self) -> &[u8; RESTORE_IMPORT_KEY_BYTES] {
        &self.0
    }
}

impl fmt::Debug for TenantRootRestoreDestinationFingerprintV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("TenantRootRestoreDestinationFingerprintV1")
            .field(&hex::encode(self.0))
            .finish()
    }
}

/// Public identifier for one destination restore session.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TenantRootRestoreSessionIdV1([u8; RESTORE_IMPORT_ID_BYTES]);

impl TenantRootRestoreSessionIdV1 {
    pub fn from_bytes(bytes: [u8; RESTORE_IMPORT_ID_BYTES]) -> RouterAbDerivationResult<Self> {
        require_nonzero(&bytes, "tenant-root restore session id must be non-zero")?;
        Ok(Self(bytes))
    }

    pub const fn as_bytes(&self) -> &[u8; RESTORE_IMPORT_ID_BYTES] {
        &self.0
    }
}

impl fmt::Debug for TenantRootRestoreSessionIdV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("TenantRootRestoreSessionIdV1")
            .field(&hex::encode(self.0))
            .finish()
    }
}

/// Canonical destination role import public key.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TenantRootRestoreImportPublicKeyV1([u8; RESTORE_IMPORT_KEY_BYTES]);

impl TenantRootRestoreImportPublicKeyV1 {
    pub fn from_bytes(bytes: [u8; RESTORE_IMPORT_KEY_BYTES]) -> RouterAbDerivationResult<Self> {
        validate_x25519_public_key(&bytes, "tenant-root restore import public key")?;
        Ok(Self(bytes))
    }

    pub const fn as_bytes(&self) -> &[u8; RESTORE_IMPORT_KEY_BYTES] {
        &self.0
    }

    pub fn digest(&self) -> [u8; 32] {
        Sha256::digest(self.0).into()
    }
}

impl fmt::Debug for TenantRootRestoreImportPublicKeyV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("TenantRootRestoreImportPublicKeyV1")
            .field(&hex::encode(self.0))
            .finish()
    }
}

/// One-use role-local import keypair created inside the destination Deriver.
pub struct TenantRootRestoreImportKeypairV1 {
    private_key: Zeroizing<[u8; RESTORE_IMPORT_KEY_BYTES]>,
    public_key: TenantRootRestoreImportPublicKeyV1,
}

impl TenantRootRestoreImportKeypairV1 {
    pub fn derive_from_ikm(ikm: [u8; RESTORE_IMPORT_KEY_BYTES]) -> RouterAbDerivationResult<Self> {
        let mut ikm = Zeroizing::new(ikm);
        require_nonzero(
            ikm.as_ref(),
            "tenant-root restore import IKM must be non-zero",
        )?;
        let (private_key, public_key) = DhKemX25519HkdfSha256::derive_key_pair(ikm.as_ref())
            .map_err(|_| malformed("tenant-root restore import key derivation failed"))?;
        let private_key: [u8; RESTORE_IMPORT_KEY_BYTES] =
            DhKemX25519HkdfSha256::sk_to_bytes(&private_key)
                .as_slice()
                .try_into()
                .map_err(|_| malformed("tenant-root restore import private key is invalid"))?;
        let public_key: [u8; RESTORE_IMPORT_KEY_BYTES] =
            DhKemX25519HkdfSha256::pk_to_bytes(&public_key)
                .as_slice()
                .try_into()
                .map_err(|_| malformed("tenant-root restore import public key is invalid"))?;
        ikm.zeroize();
        Ok(Self {
            private_key: Zeroizing::new(private_key),
            public_key: TenantRootRestoreImportPublicKeyV1::from_bytes(public_key)?,
        })
    }

    pub const fn public_key(&self) -> TenantRootRestoreImportPublicKeyV1 {
        self.public_key
    }
}

impl fmt::Debug for TenantRootRestoreImportKeypairV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TenantRootRestoreImportKeypairV1")
            .field("private_key", &"[redacted]")
            .field("public_key", &self.public_key)
            .finish()
    }
}

/// Exact source and destination metadata authenticated by one role import envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantRootRestoreImportBindingV1 {
    destination_fingerprint: TenantRootRestoreDestinationFingerprintV1,
    destination_lineage: TenantRootCustodyLineageId,
    restore_session_id: TenantRootRestoreSessionIdV1,
    identity_digest: TenantRootIdentityDigestV1,
    recovery_set_id: TenantRootRecoverySetId,
    manifest_digest: [u8; 32],
    source_package_digest: TenantRootRecoveryPackageDigestV1,
    stable_root_commitment: TwoPartyRootCommitment,
    recovery_share_commitment: SigningRootShareCommitment,
    role: TwoPartyDeriverRole,
    share_id: ThresholdShareId,
    import_key_id: String,
    import_public_key_digest: [u8; 32],
    issued_at_ms: u64,
    expires_at_ms: u64,
}

impl TenantRootRestoreImportBindingV1 {
    #[allow(clippy::too_many_arguments)]
    fn new(
        source: &VerifiedTenantRootRecoveryRoleShareV1,
        destination_fingerprint: TenantRootRestoreDestinationFingerprintV1,
        destination_lineage: TenantRootCustodyLineageId,
        restore_session_id: TenantRootRestoreSessionIdV1,
        import_key_id: impl Into<String>,
        import_public_key: TenantRootRestoreImportPublicKeyV1,
        issued_at_ms: u64,
        expires_at_ms: u64,
    ) -> RouterAbDerivationResult<Self> {
        let binding = Self {
            destination_fingerprint,
            destination_lineage,
            restore_session_id,
            identity_digest: source.tenant_root_identity_digest(),
            recovery_set_id: source.recovery_set_id(),
            manifest_digest: *source.manifest_digest(),
            source_package_digest: source.package_digest(),
            stable_root_commitment: source.stable_root_commitment(),
            recovery_share_commitment: source.recovery_share_commitment(),
            role: source.role(),
            share_id: source.role().share_id(),
            import_key_id: import_key_id.into(),
            import_public_key_digest: import_public_key.digest(),
            issued_at_ms,
            expires_at_ms,
        };
        binding.validate()?;
        Ok(binding)
    }

    pub const fn role(&self) -> TwoPartyDeriverRole {
        self.role
    }

    pub const fn recovery_share_commitment(&self) -> SigningRootShareCommitment {
        self.recovery_share_commitment
    }

    pub const fn destination_lineage(&self) -> TenantRootCustodyLineageId {
        self.destination_lineage
    }

    pub fn canonical_aad_bytes(&self) -> RouterAbDerivationResult<Vec<u8>> {
        self.validate()?;
        let mut bytes = Vec::with_capacity(512);
        push_lp32(&mut bytes, RESTORE_IMPORT_DOMAIN_V1)?;
        push_lp32(&mut bytes, self.destination_fingerprint.as_bytes())?;
        push_lp32(&mut bytes, self.destination_lineage.as_bytes())?;
        push_lp32(&mut bytes, self.restore_session_id.as_bytes())?;
        push_lp32(&mut bytes, self.identity_digest.as_bytes())?;
        push_lp32(&mut bytes, self.recovery_set_id.as_bytes())?;
        push_lp32(&mut bytes, &self.manifest_digest)?;
        push_lp32(&mut bytes, self.source_package_digest.as_bytes())?;
        push_lp32(&mut bytes, &self.stable_root_commitment.to_bytes())?;
        push_lp32(&mut bytes, &self.recovery_share_commitment.to_bytes())?;
        push_lp32(&mut bytes, self.role.as_str().as_bytes())?;
        push_lp32(&mut bytes, &self.share_id.get().get().to_be_bytes())?;
        push_lp32(&mut bytes, self.import_key_id.as_bytes())?;
        push_lp32(&mut bytes, &self.import_public_key_digest)?;
        push_lp32(&mut bytes, &self.issued_at_ms.to_be_bytes())?;
        push_lp32(&mut bytes, &self.expires_at_ms.to_be_bytes())?;
        Ok(bytes)
    }

    fn validate(&self) -> RouterAbDerivationResult<()> {
        if self.share_id != self.role.share_id()
            || self.recovery_share_commitment.id() != self.share_id
        {
            return Err(malformed(
                "tenant-root restore import role binding is invalid",
            ));
        }
        validate_key_id(&self.import_key_id)?;
        require_nonzero(
            &self.import_public_key_digest,
            "tenant-root restore import public-key digest must be non-zero",
        )?;
        if self.issued_at_ms == 0 || self.expires_at_ms <= self.issued_at_ms {
            return Err(malformed(
                "tenant-root restore import time window is invalid",
            ));
        }
        Ok(())
    }
}

/// Authoritative destination expectation required before an import envelope can be opened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedTenantRootRestoreImportV1 {
    binding: TenantRootRestoreImportBindingV1,
    import_public_key: TenantRootRestoreImportPublicKeyV1,
}

impl ExpectedTenantRootRestoreImportV1 {
    /// Creates an import expectation from a manifest-verified source role and one destination session.
    #[allow(clippy::too_many_arguments)]
    pub fn from_verified_source(
        source: &VerifiedTenantRootRecoveryRoleShareV1,
        destination_fingerprint: TenantRootRestoreDestinationFingerprintV1,
        destination_lineage: TenantRootCustodyLineageId,
        restore_session_id: TenantRootRestoreSessionIdV1,
        import_key_id: impl Into<String>,
        import_public_key: TenantRootRestoreImportPublicKeyV1,
        issued_at_ms: u64,
        expires_at_ms: u64,
    ) -> RouterAbDerivationResult<Self> {
        Ok(Self {
            binding: TenantRootRestoreImportBindingV1::new(
                source,
                destination_fingerprint,
                destination_lineage,
                restore_session_id,
                import_key_id,
                import_public_key,
                issued_at_ms,
                expires_at_ms,
            )?,
            import_public_key,
        })
    }

    /// Returns the exact source and destination metadata authorized for this import.
    pub const fn binding(&self) -> &TenantRootRestoreImportBindingV1 {
        &self.binding
    }

    fn validate(&self) -> RouterAbDerivationResult<()> {
        self.binding.validate()?;
        if !bool::from(
            self.binding
                .import_public_key_digest
                .ct_eq(&self.import_public_key.digest()),
        ) {
            return Err(malformed(
                "tenant-root restore import expectation key does not match binding",
            ));
        }
        Ok(())
    }
}

/// Recipient-encrypted role share ready for one destination import key.
#[derive(Clone, PartialEq, Eq)]
pub struct TenantRootRestoreImportEnvelopeV1 {
    binding: TenantRootRestoreImportBindingV1,
    encapsulated_key: [u8; RESTORE_IMPORT_KEY_BYTES],
    ciphertext: Vec<u8>,
}

impl fmt::Debug for TenantRootRestoreImportEnvelopeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TenantRootRestoreImportEnvelopeV1")
            .field("binding", &self.binding)
            .field("encapsulated_key", &hex::encode(self.encapsulated_key))
            .field("ciphertext", &"[redacted]")
            .finish()
    }
}

impl TenantRootRestoreImportEnvelopeV1 {
    pub fn seal<R>(
        source: &VerifiedTenantRootRecoveryRoleShareV1,
        expected: &ExpectedTenantRootRestoreImportV1,
        rng: &mut R,
    ) -> RouterAbDerivationResult<Self>
    where
        R: RngCore + CryptoRng,
    {
        expected.validate()?;
        validate_binding_against_source(&expected.binding, source, &expected.import_public_key)?;
        let recipient = DhKemX25519HkdfSha256::pk_from_bytes(expected.import_public_key.as_bytes())
            .map_err(|_| malformed("tenant-root restore import public key is invalid"))?;
        let plaintext = Zeroizing::new(source.share_wire().to_bytes());
        let aad = expected.binding.canonical_aad_bytes()?;
        let (encapsulated_key, ciphertext) = TenantRootRestoreImportHpkeV1::seal_base(
            rng,
            &recipient,
            RESTORE_IMPORT_HPKE_INFO_V1,
            &aad,
            plaintext.as_ref(),
        )
        .map_err(|_| verification_failed("tenant-root restore import encryption failed"))?;
        if ciphertext.len() != RESTORE_IMPORT_CIPHERTEXT_BYTES {
            return Err(malformed(
                "tenant-root restore import ciphertext length is invalid",
            ));
        }
        let encapsulated_key: [u8; RESTORE_IMPORT_KEY_BYTES] = encapsulated_key
            .as_ref()
            .try_into()
            .map_err(|_| malformed("tenant-root restore encapsulated key length is invalid"))?;
        validate_x25519_encapsulation(&encapsulated_key)?;
        Ok(Self {
            binding: expected.binding.clone(),
            encapsulated_key,
            ciphertext,
        })
    }

    pub const fn binding(&self) -> &TenantRootRestoreImportBindingV1 {
        &self.binding
    }

    pub fn digest(&self) -> RouterAbDerivationResult<[u8; 32]> {
        Ok(Sha256::digest(self.to_bytes()?).into())
    }

    pub fn to_bytes(&self) -> RouterAbDerivationResult<Vec<u8>> {
        self.validate_shape()?;
        let binding = self.binding.canonical_aad_bytes()?;
        let mut bytes = Vec::with_capacity(
            RESTORE_IMPORT_MAGIC_V1.len() + 4 + binding.len() + 32 + 4 + self.ciphertext.len(),
        );
        bytes.extend_from_slice(RESTORE_IMPORT_MAGIC_V1);
        push_u32(&mut bytes, binding.len())?;
        bytes.extend_from_slice(&binding);
        bytes.extend_from_slice(&self.encapsulated_key);
        push_u32(&mut bytes, self.ciphertext.len())?;
        bytes.extend_from_slice(&self.ciphertext);
        if bytes.len() > RESTORE_IMPORT_MAX_BYTES_V1 {
            return Err(malformed(
                "tenant-root restore import envelope exceeds size cap",
            ));
        }
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> RouterAbDerivationResult<Self> {
        if bytes.len() > RESTORE_IMPORT_MAX_BYTES_V1 {
            return Err(malformed(
                "tenant-root restore import envelope exceeds size cap",
            ));
        }
        let mut cursor = 0;
        if take(bytes, &mut cursor, RESTORE_IMPORT_MAGIC_V1.len())? != RESTORE_IMPORT_MAGIC_V1 {
            return Err(malformed("tenant-root restore import magic is invalid"));
        }
        let binding_len = read_u32(bytes, &mut cursor)?;
        let binding_bytes = take(bytes, &mut cursor, binding_len)?;
        let binding = decode_binding(binding_bytes)?;
        let encapsulated_key = take_fixed::<RESTORE_IMPORT_KEY_BYTES>(bytes, &mut cursor)?;
        validate_x25519_encapsulation(&encapsulated_key)?;
        let ciphertext_len = read_u32(bytes, &mut cursor)?;
        if ciphertext_len != RESTORE_IMPORT_CIPHERTEXT_BYTES {
            return Err(malformed(
                "tenant-root restore import ciphertext length is invalid",
            ));
        }
        let ciphertext = take(bytes, &mut cursor, ciphertext_len)?.to_vec();
        if cursor != bytes.len() {
            return Err(malformed(
                "tenant-root restore import envelope has trailing bytes",
            ));
        }
        let envelope = Self {
            binding,
            encapsulated_key,
            ciphertext,
        };
        envelope.validate_shape()?;
        Ok(envelope)
    }

    pub fn open(
        &self,
        expected: &ExpectedTenantRootRestoreImportV1,
        import_keypair: &TenantRootRestoreImportKeypairV1,
    ) -> RouterAbDerivationResult<ImportedTenantRootRecoveryRoleShareV1> {
        self.validate_shape()?;
        expected.validate()?;
        if self.binding != expected.binding {
            return Err(RouterAbDerivationError::new(
                RouterAbDerivationErrorCode::ReplayMismatch,
                "tenant-root restore import envelope does not match the authorized session",
            ));
        }
        if !bool::from(
            import_keypair
                .public_key
                .digest()
                .ct_eq(&expected.import_public_key.digest()),
        ) {
            return Err(RouterAbDerivationError::new(
                RouterAbDerivationErrorCode::RecipientMismatch,
                "tenant-root restore import key does not match binding",
            ));
        }
        let private_key = DhKemX25519HkdfSha256::sk_from_bytes(import_keypair.private_key.as_ref())
            .map_err(|_| malformed("tenant-root restore import private key is invalid"))?;
        let encapsulated_key = DhKemX25519HkdfSha256::enc_from_bytes(&self.encapsulated_key)
            .map_err(|_| malformed("tenant-root restore encapsulated key is invalid"))?;
        let plaintext = Zeroizing::new(
            TenantRootRestoreImportHpkeV1::open_base(
                &encapsulated_key,
                &private_key,
                RESTORE_IMPORT_HPKE_INFO_V1,
                &self.binding.canonical_aad_bytes()?,
                &self.ciphertext,
            )
            .map_err(|_| verification_failed("tenant-root restore import decryption failed"))?,
        );
        let share_wire = SigningRootShareWire::decode_slice(&plaintext)
            .map_err(|_| verification_failed("tenant-root restore import share is invalid"))?;
        let share = share_wire
            .to_share()
            .map_err(|_| verification_failed("tenant-root restore import share is invalid"))?;
        if bool::from(share.to_bytes().ct_eq(&[0_u8; 32]))
            || share.id() != self.binding.role.share_id()
            || SigningRootShareCommitment::from_share(&share)
                != self.binding.recovery_share_commitment
        {
            return Err(verification_failed(
                "tenant-root restore import share does not match binding",
            ));
        }
        Ok(ImportedTenantRootRecoveryRoleShareV1 {
            binding: self.binding.clone(),
            share_wire,
        })
    }

    fn validate_shape(&self) -> RouterAbDerivationResult<()> {
        self.binding.validate()?;
        validate_x25519_encapsulation(&self.encapsulated_key)?;
        if self.ciphertext.len() != RESTORE_IMPORT_CIPHERTEXT_BYTES {
            return Err(malformed(
                "tenant-root restore import ciphertext length is invalid",
            ));
        }
        Ok(())
    }
}

/// Decrypted role share that remains bound to its verified destination import metadata.
pub struct ImportedTenantRootRecoveryRoleShareV1 {
    binding: TenantRootRestoreImportBindingV1,
    share_wire: SigningRootShareWire,
}

impl ImportedTenantRootRecoveryRoleShareV1 {
    pub const fn binding(&self) -> &TenantRootRestoreImportBindingV1 {
        &self.binding
    }

    /// Consumes the verified import capability and returns its role-local share wire.
    pub fn into_share_wire(self) -> SigningRootShareWire {
        self.share_wire
    }
}

impl fmt::Debug for ImportedTenantRootRecoveryRoleShareV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ImportedTenantRootRecoveryRoleShareV1")
            .field("binding", &self.binding)
            .field("share_wire", &"[redacted]")
            .finish()
    }
}

fn validate_binding_against_source(
    binding: &TenantRootRestoreImportBindingV1,
    source: &VerifiedTenantRootRecoveryRoleShareV1,
    import_public_key: &TenantRootRestoreImportPublicKeyV1,
) -> RouterAbDerivationResult<()> {
    binding.validate()?;
    if binding.role != source.role()
        || binding.identity_digest != source.tenant_root_identity_digest()
        || binding.recovery_set_id != source.recovery_set_id()
        || !bool::from(binding.manifest_digest.ct_eq(source.manifest_digest()))
        || binding.source_package_digest != source.package_digest()
        || binding.stable_root_commitment != source.stable_root_commitment()
        || binding.recovery_share_commitment != source.recovery_share_commitment()
        || !bool::from(
            binding
                .import_public_key_digest
                .ct_eq(&import_public_key.digest()),
        )
    {
        return Err(verification_failed(
            "tenant-root restore import binding does not match verified source share",
        ));
    }
    Ok(())
}

fn decode_binding(bytes: &[u8]) -> RouterAbDerivationResult<TenantRootRestoreImportBindingV1> {
    let mut cursor = 0;
    if take_lp32(bytes, &mut cursor)? != RESTORE_IMPORT_DOMAIN_V1 {
        return Err(malformed("tenant-root restore import domain is invalid"));
    }
    let destination_fingerprint = TenantRootRestoreDestinationFingerprintV1::from_bytes(
        take_fixed_lp32(bytes, &mut cursor)?,
    )?;
    let destination_lineage =
        TenantRootCustodyLineageId::from_bytes(take_fixed_lp32(bytes, &mut cursor)?)?;
    let restore_session_id =
        TenantRootRestoreSessionIdV1::from_bytes(take_fixed_lp32(bytes, &mut cursor)?)?;
    let identity_digest =
        TenantRootIdentityDigestV1::from_bytes(take_fixed_lp32(bytes, &mut cursor)?);
    let recovery_set_id =
        TenantRootRecoverySetId::from_bytes(take_fixed_lp32(bytes, &mut cursor)?)?;
    let manifest_digest = take_fixed_lp32(bytes, &mut cursor)?;
    let source_package_digest =
        TenantRootRecoveryPackageDigestV1::from_bytes(take_fixed_lp32(bytes, &mut cursor)?);
    let stable_root_commitment =
        TwoPartyRootCommitment::from_bytes(take_fixed_lp32(bytes, &mut cursor)?)
            .map_err(|_| malformed("tenant-root restore stable root commitment is invalid"))?;
    let recovery_share_commitment =
        SigningRootShareCommitment::from_bytes(take_fixed_lp32(bytes, &mut cursor)?)
            .map_err(|_| malformed("tenant-root restore share commitment is invalid"))?;
    let role = parse_role(take_lp32(bytes, &mut cursor)?)?;
    let share_id =
        ThresholdShareId::from_u16(u16::from_be_bytes(take_fixed_lp32(bytes, &mut cursor)?))
            .map_err(|_| malformed("tenant-root restore share id is invalid"))?;
    let import_key_id = String::from_utf8(take_lp32(bytes, &mut cursor)?.to_vec())
        .map_err(|_| malformed("tenant-root restore import key id is invalid UTF-8"))?;
    let import_public_key_digest = take_fixed_lp32(bytes, &mut cursor)?;
    let issued_at_ms = u64::from_be_bytes(take_fixed_lp32(bytes, &mut cursor)?);
    let expires_at_ms = u64::from_be_bytes(take_fixed_lp32(bytes, &mut cursor)?);
    if cursor != bytes.len() {
        return Err(malformed(
            "tenant-root restore import binding has trailing bytes",
        ));
    }
    let binding = TenantRootRestoreImportBindingV1 {
        destination_fingerprint,
        destination_lineage,
        restore_session_id,
        identity_digest,
        recovery_set_id,
        manifest_digest,
        source_package_digest,
        stable_root_commitment,
        recovery_share_commitment,
        role,
        share_id,
        import_key_id,
        import_public_key_digest,
        issued_at_ms,
        expires_at_ms,
    };
    binding.validate()?;
    if binding.canonical_aad_bytes()?.as_slice() != bytes {
        return Err(malformed(
            "tenant-root restore import binding is not canonical",
        ));
    }
    Ok(binding)
}

fn validate_x25519_public_key(
    bytes: &[u8; 32],
    label: &'static str,
) -> RouterAbDerivationResult<()> {
    if !is_canonical_nonzero_x25519_encoding(bytes) {
        return Err(malformed(label));
    }
    let key = DhKemX25519HkdfSha256::pk_from_bytes(bytes).map_err(|_| malformed(label))?;
    if DhKemX25519HkdfSha256::pk_to_bytes(&key).as_slice() != bytes {
        return Err(malformed(label));
    }
    Ok(())
}

fn validate_x25519_encapsulation(bytes: &[u8; 32]) -> RouterAbDerivationResult<()> {
    if !is_canonical_nonzero_x25519_encoding(bytes) {
        return Err(malformed("tenant-root restore encapsulated key is invalid"));
    }
    DhKemX25519HkdfSha256::enc_from_bytes(bytes)
        .map_err(|_| malformed("tenant-root restore encapsulated key is invalid"))?;
    Ok(())
}

fn validate_key_id(value: &str) -> RouterAbDerivationResult<()> {
    if value.is_empty()
        || value.len() > 128
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b' ')
    {
        return Err(malformed("tenant-root restore import key id is invalid"));
    }
    Ok(())
}

fn parse_role(bytes: &[u8]) -> RouterAbDerivationResult<TwoPartyDeriverRole> {
    match bytes {
        b"deriver_a" => Ok(TwoPartyDeriverRole::DeriverA),
        b"deriver_b" => Ok(TwoPartyDeriverRole::DeriverB),
        _ => Err(malformed("tenant-root restore import role is invalid")),
    }
}

fn push_lp32(out: &mut Vec<u8>, value: &[u8]) -> RouterAbDerivationResult<()> {
    push_u32(out, value.len())?;
    out.extend_from_slice(value);
    Ok(())
}

fn push_u32(out: &mut Vec<u8>, length: usize) -> RouterAbDerivationResult<()> {
    let length = u32::try_from(length)
        .map_err(|_| malformed("tenant-root restore import field is too long"))?;
    out.extend_from_slice(&length.to_be_bytes());
    Ok(())
}

fn read_u32(bytes: &[u8], cursor: &mut usize) -> RouterAbDerivationResult<usize> {
    Ok(u32::from_be_bytes(take_fixed(bytes, cursor)?) as usize)
}

fn take_lp32<'a>(bytes: &'a [u8], cursor: &mut usize) -> RouterAbDerivationResult<&'a [u8]> {
    let length = read_u32(bytes, cursor)?;
    take(bytes, cursor, length)
}

fn take_fixed_lp32<const N: usize>(
    bytes: &[u8],
    cursor: &mut usize,
) -> RouterAbDerivationResult<[u8; N]> {
    let value = take_lp32(bytes, cursor)?;
    value
        .try_into()
        .map_err(|_| malformed("tenant-root restore import fixed field length is invalid"))
}

fn take_fixed<const N: usize>(
    bytes: &[u8],
    cursor: &mut usize,
) -> RouterAbDerivationResult<[u8; N]> {
    take(bytes, cursor, N)?
        .try_into()
        .map_err(|_| malformed("tenant-root restore import fixed field length is invalid"))
}

fn take<'a>(
    bytes: &'a [u8],
    cursor: &mut usize,
    length: usize,
) -> RouterAbDerivationResult<&'a [u8]> {
    let end = cursor
        .checked_add(length)
        .ok_or_else(|| malformed("tenant-root restore import length overflows"))?;
    let value = bytes
        .get(*cursor..end)
        .ok_or_else(|| malformed("tenant-root restore import is truncated"))?;
    *cursor = end;
    Ok(value)
}

fn require_nonzero(bytes: &[u8], message: &'static str) -> RouterAbDerivationResult<()> {
    let aggregate = bytes.iter().fold(0_u8, |value, byte| value | byte);
    if aggregate == 0 {
        Err(malformed(message))
    } else {
        Ok(())
    }
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
