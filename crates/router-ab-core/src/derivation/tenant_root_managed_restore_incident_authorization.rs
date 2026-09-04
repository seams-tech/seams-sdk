//! Canonical dual-approval authorization for one managed role restore.
//!
//! The authorization is scoped to one incident, tenant-root custody lineage,
//! active epoch, and outage observation. The operations and unavailable-role
//! custody authorities sign the same canonical binding bytes. The resulting
//! verified token is the only constructible proof accepted by a restore adapter.

use core::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use threshold_prf::TwoPartyDeriverRole;

use super::tenant_root_protocol::TenantRootWireDecoderV1;
use super::{
    require_tenant_root_identifier, RouterAbDerivationError, RouterAbDerivationErrorCode,
    RouterAbDerivationResult, TenantRootControlPlaneAuthorityIdV1, TenantRootCustodyLineageId,
    TenantRootIdentityDigestV1, TenantRootLifecycleReceiptDigestV1, TenantRootManagedRestoreRoleV1,
    TenantRootProtocolDigestV1, TenantRootShareEpoch, TENANT_ROOT_MAX_LIFETIME_MS_V1,
};

const TENANT_ROOT_MANAGED_RESTORE_INCIDENT_AUTHORIZATION_DOMAIN_V1: &[u8] =
    b"tenant_root_managed_restore_incident_authorization_v1";
const TENANT_ROOT_MANAGED_RESTORE_INCIDENT_AUTHORIZATION_AUTH_DOMAIN_V1: &[u8] =
    b"tenant_root_managed_restore_incident_authorization_authentication_v1";
const TENANT_ROOT_MANAGED_RESTORE_INCIDENT_OPERATIONS_OPERATION_BYTES_V1: &[u8] =
    b"operations_incident";
const TENANT_ROOT_MANAGED_RESTORE_INCIDENT_CUSTODY_OPERATION_BYTES_V1: &[u8] = b"role_custody";
const TENANT_ROOT_MANAGED_RESTORE_INCIDENT_NONCE_LEN_V1: usize = 32;
const TENANT_ROOT_MANAGED_RESTORE_INCIDENT_MAX_IDENTIFIER_BYTES_V1: usize = 256;

/// Exact operation signed by the incident operations authority.
pub const TENANT_ROOT_MANAGED_RESTORE_INCIDENT_OPERATIONS_OPERATION_V1: &str =
    "operations_incident";

/// Exact operation signed by the unavailable role's custody authority.
pub const TENANT_ROOT_MANAGED_RESTORE_INCIDENT_CUSTODY_OPERATION_V1: &str = "role_custody";

/// Maximum canonical wire size accepted for one incident authorization.
pub const TENANT_ROOT_MANAGED_RESTORE_INCIDENT_AUTHORIZATION_MAX_BYTES_V1: usize = 16 * 1024;

/// Non-zero one-use nonce for one managed-restore incident authorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TenantRootManagedRestoreIncidentNonceV1(
    [u8; TENANT_ROOT_MANAGED_RESTORE_INCIDENT_NONCE_LEN_V1],
);

impl TenantRootManagedRestoreIncidentNonceV1 {
    /// Parses one exact non-zero incident nonce.
    pub fn from_bytes(
        bytes: [u8; TENANT_ROOT_MANAGED_RESTORE_INCIDENT_NONCE_LEN_V1],
    ) -> RouterAbDerivationResult<Self> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(malformed(
                "tenant-root managed-restore incident nonce must be non-zero",
            ));
        }
        Ok(Self(bytes))
    }

    /// Samples one fresh non-zero incident nonce.
    pub fn random<R>(rng: &mut R) -> Self
    where
        R: RngCore + CryptoRng,
    {
        loop {
            let mut bytes = [0_u8; TENANT_ROOT_MANAGED_RESTORE_INCIDENT_NONCE_LEN_V1];
            rng.fill_bytes(&mut bytes);
            if let Ok(nonce) = Self::from_bytes(bytes) {
                return nonce;
            }
        }
    }

    /// Returns the exact nonce bytes.
    pub const fn as_bytes(&self) -> &[u8; TENANT_ROOT_MANAGED_RESTORE_INCIDENT_NONCE_LEN_V1] {
        &self.0
    }

    /// Consumes the nonce and returns its exact bytes.
    pub const fn into_bytes(self) -> [u8; TENANT_ROOT_MANAGED_RESTORE_INCIDENT_NONCE_LEN_V1] {
        self.0
    }
}

/// Exact public binding approved by the operations and unavailable-role
/// custody authorities.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantRootManagedRestoreIncidentAuthorizationBindingV1 {
    incident_id: String,
    identity_digest: TenantRootIdentityDigestV1,
    custody_lineage: TenantRootCustodyLineageId,
    unavailable_role: TenantRootManagedRestoreRoleV1,
    current_epoch: TenantRootShareEpoch,
    activation_receipt_digest: TenantRootLifecycleReceiptDigestV1,
    outage_observation_digest: TenantRootLifecycleReceiptDigestV1,
    issued_at_ms: u64,
    expires_at_ms: u64,
    nonce: TenantRootManagedRestoreIncidentNonceV1,
    operations_authority_id: TenantRootControlPlaneAuthorityIdV1,
    operations_key_id: String,
    custody_authority_id: TenantRootControlPlaneAuthorityIdV1,
    custody_key_id: String,
}

impl TenantRootManagedRestoreIncidentAuthorizationBindingV1 {
    /// Creates one exact dual-approval incident binding.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        incident_id: impl Into<String>,
        identity_digest: TenantRootIdentityDigestV1,
        custody_lineage: TenantRootCustodyLineageId,
        unavailable_role: TenantRootManagedRestoreRoleV1,
        current_epoch: TenantRootShareEpoch,
        activation_receipt_digest: TenantRootLifecycleReceiptDigestV1,
        outage_observation_digest: TenantRootLifecycleReceiptDigestV1,
        issued_at_ms: u64,
        expires_at_ms: u64,
        nonce: TenantRootManagedRestoreIncidentNonceV1,
        operations_authority_id: TenantRootControlPlaneAuthorityIdV1,
        operations_key_id: impl Into<String>,
        custody_authority_id: TenantRootControlPlaneAuthorityIdV1,
        custody_key_id: impl Into<String>,
    ) -> RouterAbDerivationResult<Self> {
        let binding = Self {
            incident_id: incident_id.into(),
            identity_digest,
            custody_lineage,
            unavailable_role,
            current_epoch,
            activation_receipt_digest,
            outage_observation_digest,
            issued_at_ms,
            expires_at_ms,
            nonce,
            operations_authority_id,
            operations_key_id: operations_key_id.into(),
            custody_authority_id,
            custody_key_id: custody_key_id.into(),
        };
        binding.validate()?;
        Ok(binding)
    }

    /// Returns the incident identifier.
    pub fn incident_id(&self) -> &str {
        &self.incident_id
    }

    /// Returns the logical tenant-root identity digest.
    pub const fn identity_digest(&self) -> TenantRootIdentityDigestV1 {
        self.identity_digest
    }

    /// Returns the physical custody lineage.
    pub const fn custody_lineage(&self) -> TenantRootCustodyLineageId {
        self.custody_lineage
    }

    /// Returns the role whose current share is unavailable.
    pub const fn unavailable_role(&self) -> TenantRootManagedRestoreRoleV1 {
        self.unavailable_role
    }

    /// Returns the current active custody epoch.
    pub const fn current_epoch(&self) -> TenantRootShareEpoch {
        self.current_epoch
    }

    /// Returns the active activation receipt digest.
    pub const fn activation_receipt_digest(&self) -> TenantRootLifecycleReceiptDigestV1 {
        self.activation_receipt_digest
    }

    /// Returns the outage observation digest.
    pub const fn outage_observation_digest(&self) -> TenantRootLifecycleReceiptDigestV1 {
        self.outage_observation_digest
    }

    /// Returns the issue timestamp.
    pub const fn issued_at_ms(&self) -> u64 {
        self.issued_at_ms
    }

    /// Returns the expiry timestamp.
    pub const fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }

    /// Returns the one-use incident nonce.
    pub const fn nonce(&self) -> TenantRootManagedRestoreIncidentNonceV1 {
        self.nonce
    }

    /// Returns the incident-operations authority identifier.
    pub const fn operations_authority_id(&self) -> TenantRootControlPlaneAuthorityIdV1 {
        self.operations_authority_id
    }

    /// Returns the incident-operations signing-key identifier.
    pub fn operations_key_id(&self) -> &str {
        &self.operations_key_id
    }

    /// Returns the unavailable role's custody authority identifier.
    pub const fn custody_authority_id(&self) -> TenantRootControlPlaneAuthorityIdV1 {
        self.custody_authority_id
    }

    /// Returns the unavailable role's custody signing-key identifier.
    pub fn custody_key_id(&self) -> &str {
        &self.custody_key_id
    }

    /// Returns the exact unsigned canonical bytes signed by both authorities.
    pub fn canonical_bytes(&self) -> RouterAbDerivationResult<Vec<u8>> {
        self.validate()?;
        let mut bytes = Vec::new();
        push_field(
            &mut bytes,
            TENANT_ROOT_MANAGED_RESTORE_INCIDENT_AUTHORIZATION_DOMAIN_V1,
        )?;
        push_field(&mut bytes, self.incident_id.as_bytes())?;
        push_field(&mut bytes, self.identity_digest.as_bytes())?;
        push_field(&mut bytes, self.custody_lineage.as_bytes())?;
        push_role(&mut bytes, self.unavailable_role)?;
        push_field(&mut bytes, &self.current_epoch.get().get().to_be_bytes())?;
        push_field(&mut bytes, self.activation_receipt_digest.as_bytes())?;
        push_field(&mut bytes, self.outage_observation_digest.as_bytes())?;
        push_field(&mut bytes, &self.issued_at_ms.to_be_bytes())?;
        push_field(&mut bytes, &self.expires_at_ms.to_be_bytes())?;
        push_field(&mut bytes, self.nonce.as_bytes())?;
        push_field(
            &mut bytes,
            TENANT_ROOT_MANAGED_RESTORE_INCIDENT_OPERATIONS_OPERATION_BYTES_V1,
        )?;
        push_field(&mut bytes, self.operations_authority_id.as_bytes())?;
        push_field(&mut bytes, self.operations_key_id.as_bytes())?;
        push_field(
            &mut bytes,
            TENANT_ROOT_MANAGED_RESTORE_INCIDENT_CUSTODY_OPERATION_BYTES_V1,
        )?;
        push_field(&mut bytes, self.custody_authority_id.as_bytes())?;
        push_field(&mut bytes, self.custody_key_id.as_bytes())?;
        Ok(bytes)
    }

    fn validate(&self) -> RouterAbDerivationResult<()> {
        require_tenant_root_identifier(
            "tenant-root managed-restore incident id",
            &self.incident_id,
        )?;
        if self.incident_id.len() > TENANT_ROOT_MANAGED_RESTORE_INCIDENT_MAX_IDENTIFIER_BYTES_V1 {
            return Err(malformed(
                "tenant-root managed-restore incident id is too long",
            ));
        }
        if self.issued_at_ms == 0 || self.expires_at_ms <= self.issued_at_ms {
            return Err(malformed(
                "tenant-root managed-restore incident expiry must follow a non-zero issue time",
            ));
        }
        if self.expires_at_ms - self.issued_at_ms > TENANT_ROOT_MAX_LIFETIME_MS_V1 {
            return Err(malformed(
                "tenant-root managed-restore incident lifetime exceeds the frozen maximum window",
            ));
        }
        require_tenant_root_identifier(
            "tenant-root managed-restore incident operations key id",
            &self.operations_key_id,
        )?;
        require_tenant_root_identifier(
            "tenant-root managed-restore incident custody key id",
            &self.custody_key_id,
        )?;
        if self.operations_key_id.len()
            > TENANT_ROOT_MANAGED_RESTORE_INCIDENT_MAX_IDENTIFIER_BYTES_V1
            || self.custody_key_id.len()
                > TENANT_ROOT_MANAGED_RESTORE_INCIDENT_MAX_IDENTIFIER_BYTES_V1
        {
            return Err(malformed(
                "tenant-root managed-restore incident signing key id is too long",
            ));
        }
        if self.operations_authority_id == self.custody_authority_id {
            return Err(malformed(
                "tenant-root managed-restore incident authorities must be distinct",
            ));
        }
        if self
            .operations_authority_id
            .as_bytes()
            .iter()
            .all(|byte| *byte == 0)
            || self
                .custody_authority_id
                .as_bytes()
                .iter()
                .all(|byte| *byte == 0)
        {
            return Err(malformed(
                "tenant-root managed-restore incident authorities must be non-zero",
            ));
        }
        if self.operations_key_id == self.custody_key_id {
            return Err(malformed(
                "tenant-root managed-restore incident signing key ids must be distinct",
            ));
        }
        Ok(())
    }
}

/// Dual-signed managed-restore incident authorization before verification.
#[derive(Debug, PartialEq, Eq)]
pub struct TenantRootSignedManagedRestoreIncidentAuthorizationV1 {
    binding: TenantRootManagedRestoreIncidentAuthorizationBindingV1,
    operations_signature: [u8; 64],
    custody_signature: [u8; 64],
}

impl TenantRootSignedManagedRestoreIncidentAuthorizationV1 {
    /// Signs one binding with distinct operations and custody signing keys.
    pub fn sign(
        binding: TenantRootManagedRestoreIncidentAuthorizationBindingV1,
        operations_signing_key_bytes: &[u8; 32],
        custody_signing_key_bytes: &[u8; 32],
    ) -> RouterAbDerivationResult<Self> {
        binding.validate()?;
        let operations_key = SigningKey::from_bytes(operations_signing_key_bytes);
        let custody_key = SigningKey::from_bytes(custody_signing_key_bytes);
        if operations_key.verifying_key() == custody_key.verifying_key() {
            return Err(malformed(
                "tenant-root managed-restore incident signing keys must be distinct",
            ));
        }
        let unsigned = binding.canonical_bytes()?;
        let input = authentication_input(&unsigned)?;
        let authorization = Self {
            binding,
            operations_signature: operations_key.sign(&input).to_bytes(),
            custody_signature: custody_key.sign(&input).to_bytes(),
        };
        authorization.canonical_bytes()?;
        Ok(authorization)
    }

    /// Decodes exactly one canonical dual-signed incident authorization.
    pub fn decode_canonical_bytes(bytes: &[u8]) -> RouterAbDerivationResult<Self> {
        if bytes.is_empty()
            || bytes.len() > TENANT_ROOT_MANAGED_RESTORE_INCIDENT_AUTHORIZATION_MAX_BYTES_V1
        {
            return Err(malformed(
                "tenant-root managed-restore incident authorization wire length is invalid",
            ));
        }
        let mut decoder = TenantRootWireDecoderV1::new(bytes);
        decoder.require_field(TENANT_ROOT_MANAGED_RESTORE_INCIDENT_AUTHORIZATION_DOMAIN_V1)?;
        let incident_id = decoder.text_field(
            "tenant-root managed-restore incident authorization incident id",
            TENANT_ROOT_MANAGED_RESTORE_INCIDENT_MAX_IDENTIFIER_BYTES_V1,
        )?;
        let identity_digest = TenantRootIdentityDigestV1::from_bytes(decoder.fixed_field::<32>(
            "tenant-root managed-restore incident authorization identity digest",
        )?);
        let custody_lineage = TenantRootCustodyLineageId::from_bytes(decoder.fixed_field::<16>(
            "tenant-root managed-restore incident authorization custody lineage",
        )?)?;
        let unavailable_role = managed_restore_role(decoder.role()?);
        let current_epoch = TenantRootShareEpoch::new(
            decoder
                .u64_field("tenant-root managed-restore incident authorization current epoch")?,
        )?;
        let activation_receipt_digest =
            TenantRootLifecycleReceiptDigestV1::from_bytes(decoder.fixed_field::<32>(
                "tenant-root managed-restore incident authorization activation receipt digest",
            )?)?;
        let outage_observation_digest =
            TenantRootLifecycleReceiptDigestV1::from_bytes(decoder.fixed_field::<32>(
                "tenant-root managed-restore incident authorization outage observation digest",
            )?)?;
        let issued_at_ms =
            decoder.u64_field("tenant-root managed-restore incident authorization issue time")?;
        let expires_at_ms =
            decoder.u64_field("tenant-root managed-restore incident authorization expiry")?;
        let nonce = TenantRootManagedRestoreIncidentNonceV1::from_bytes(
            decoder
                .fixed_field::<32>("tenant-root managed-restore incident authorization nonce")?,
        )?;
        if decoder.field("tenant-root managed-restore incident operations operation")?
            != TENANT_ROOT_MANAGED_RESTORE_INCIDENT_OPERATIONS_OPERATION_BYTES_V1
        {
            return Err(malformed(
                "tenant-root managed-restore incident operations operation is invalid",
            ));
        }
        let operations_authority_id = TenantRootControlPlaneAuthorityIdV1::from_bytes(
            decoder
                .fixed_field::<32>("tenant-root managed-restore incident operations authority")?,
        );
        let operations_key_id = decoder.text_field(
            "tenant-root managed-restore incident operations key id",
            TENANT_ROOT_MANAGED_RESTORE_INCIDENT_MAX_IDENTIFIER_BYTES_V1,
        )?;
        if decoder.field("tenant-root managed-restore incident custody operation")?
            != TENANT_ROOT_MANAGED_RESTORE_INCIDENT_CUSTODY_OPERATION_BYTES_V1
        {
            return Err(malformed(
                "tenant-root managed-restore incident custody operation is invalid",
            ));
        }
        let custody_authority_id = TenantRootControlPlaneAuthorityIdV1::from_bytes(
            decoder.fixed_field::<32>("tenant-root managed-restore incident custody authority")?,
        );
        let custody_key_id = decoder.text_field(
            "tenant-root managed-restore incident custody key id",
            TENANT_ROOT_MANAGED_RESTORE_INCIDENT_MAX_IDENTIFIER_BYTES_V1,
        )?;
        let operations_signature = decoder.fixed_field::<64>(
            "tenant-root managed-restore incident authorization operations signature",
        )?;
        let custody_signature = decoder.fixed_field::<64>(
            "tenant-root managed-restore incident authorization custody signature",
        )?;
        decoder.finish()?;
        if operations_signature.iter().all(|byte| *byte == 0)
            || custody_signature.iter().all(|byte| *byte == 0)
        {
            return Err(malformed(
                "tenant-root managed-restore incident authorization signatures must be nonzero",
            ));
        }
        let authorization = Self {
            binding: TenantRootManagedRestoreIncidentAuthorizationBindingV1::new(
                incident_id,
                identity_digest,
                custody_lineage,
                unavailable_role,
                current_epoch,
                activation_receipt_digest,
                outage_observation_digest,
                issued_at_ms,
                expires_at_ms,
                nonce,
                operations_authority_id,
                operations_key_id,
                custody_authority_id,
                custody_key_id,
            )?,
            operations_signature,
            custody_signature,
        };
        if authorization.canonical_bytes()? != bytes {
            return Err(malformed(
                "tenant-root managed-restore incident authorization wire is not canonical",
            ));
        }
        Ok(authorization)
    }

    /// Decodes and verifies one exact incident authorization wire.
    pub fn decode_and_verify_canonical_bytes(
        bytes: &[u8],
        expected: &TenantRootManagedRestoreIncidentAuthorizationBindingV1,
        operations_trusted_verifying_key: &[u8; 32],
        custody_trusted_verifying_key: &[u8; 32],
    ) -> RouterAbDerivationResult<VerifiedTenantRootManagedRestoreIncidentAuthorizationV1> {
        Self::decode_canonical_bytes(bytes)?.verify(
            expected,
            operations_trusted_verifying_key,
            custody_trusted_verifying_key,
        )
    }

    /// Returns the exact binding carried by this authorization.
    pub const fn binding(&self) -> &TenantRootManagedRestoreIncidentAuthorizationBindingV1 {
        &self.binding
    }

    /// Returns the operations authority signature.
    pub const fn operations_signature(&self) -> &[u8; 64] {
        &self.operations_signature
    }

    /// Returns the unavailable-role custody signature.
    pub const fn custody_signature(&self) -> &[u8; 64] {
        &self.custody_signature
    }

    /// Returns the exact canonical signed authorization bytes.
    pub fn canonical_bytes(&self) -> RouterAbDerivationResult<Vec<u8>> {
        let mut bytes = self.binding.canonical_bytes()?;
        push_field(&mut bytes, &self.operations_signature)?;
        push_field(&mut bytes, &self.custody_signature)?;
        Ok(bytes)
    }

    /// Returns the digest of the exact canonical signed authorization bytes.
    pub fn digest(&self) -> RouterAbDerivationResult<TenantRootProtocolDigestV1> {
        TenantRootProtocolDigestV1::from_bytes(Sha256::digest(self.canonical_bytes()?).into())
    }

    /// Verifies both signatures against one exact expected binding.
    ///
    /// Signature verification does not check wall-clock freshness. Call
    /// `require_fresh` on the returned token before accepting an unseen wire.
    pub fn verify(
        self,
        expected: &TenantRootManagedRestoreIncidentAuthorizationBindingV1,
        operations_trusted_verifying_key: &[u8; 32],
        custody_trusted_verifying_key: &[u8; 32],
    ) -> RouterAbDerivationResult<VerifiedTenantRootManagedRestoreIncidentAuthorizationV1> {
        self.binding.validate()?;
        expected.validate()?;
        if self.binding != *expected {
            return Err(replay_mismatch(
                "tenant-root managed-restore incident authorization does not match its expected binding",
            ));
        }
        if operations_trusted_verifying_key == custody_trusted_verifying_key {
            return Err(verification_failed(
                "tenant-root managed-restore incident trusted keys must be distinct",
            ));
        }
        let unsigned = self.binding.canonical_bytes()?;
        let input = authentication_input(&unsigned)?;
        verify_signature(
            &input,
            &self.operations_signature,
            operations_trusted_verifying_key,
            "tenant-root managed-restore incident operations signature is invalid",
        )?;
        verify_signature(
            &input,
            &self.custody_signature,
            custody_trusted_verifying_key,
            "tenant-root managed-restore incident custody signature is invalid",
        )?;
        let canonical_bytes = self.canonical_bytes()?;
        let digest =
            TenantRootProtocolDigestV1::from_bytes(Sha256::digest(&canonical_bytes).into())?;
        Ok(VerifiedTenantRootManagedRestoreIncidentAuthorizationV1 {
            authorization: self,
            canonical_bytes,
            digest,
        })
    }
}

/// Dual-signature incident authorization after exact verification.
pub struct VerifiedTenantRootManagedRestoreIncidentAuthorizationV1 {
    authorization: TenantRootSignedManagedRestoreIncidentAuthorizationV1,
    canonical_bytes: Vec<u8>,
    digest: TenantRootProtocolDigestV1,
}

impl fmt::Debug for VerifiedTenantRootManagedRestoreIncidentAuthorizationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedTenantRootManagedRestoreIncidentAuthorizationV1")
            .field("binding", &self.authorization.binding)
            .field("digest", &self.digest)
            .field("canonical_bytes", &"[public authenticated bytes]")
            .finish()
    }
}

impl VerifiedTenantRootManagedRestoreIncidentAuthorizationV1 {
    /// Returns the exact binding authenticated by this token.
    pub const fn binding(&self) -> &TenantRootManagedRestoreIncidentAuthorizationBindingV1 {
        self.authorization.binding()
    }

    /// Returns the incident identifier authenticated by this token.
    pub fn incident_id(&self) -> &str {
        self.binding().incident_id()
    }

    /// Returns the tenant identity authenticated by this token.
    pub const fn identity_digest(&self) -> TenantRootIdentityDigestV1 {
        self.binding().identity_digest()
    }

    /// Returns the custody lineage authenticated by this token.
    pub const fn custody_lineage(&self) -> TenantRootCustodyLineageId {
        self.binding().custody_lineage()
    }

    /// Returns the unavailable role authenticated by this token.
    pub const fn unavailable_role(&self) -> TenantRootManagedRestoreRoleV1 {
        self.binding().unavailable_role()
    }

    /// Returns the current epoch authenticated by this token.
    pub const fn current_epoch(&self) -> TenantRootShareEpoch {
        self.binding().current_epoch()
    }

    /// Returns the activation receipt digest authenticated by this token.
    pub const fn activation_receipt_digest(&self) -> TenantRootLifecycleReceiptDigestV1 {
        self.binding().activation_receipt_digest()
    }

    /// Returns the outage observation digest authenticated by this token.
    pub const fn outage_observation_digest(&self) -> TenantRootLifecycleReceiptDigestV1 {
        self.binding().outage_observation_digest()
    }

    /// Returns the issue timestamp authenticated by this token.
    pub const fn issued_at_ms(&self) -> u64 {
        self.binding().issued_at_ms()
    }

    /// Returns the expiry timestamp authenticated by this token.
    pub const fn expires_at_ms(&self) -> u64 {
        self.binding().expires_at_ms()
    }

    /// Returns the one-use nonce authenticated by this token.
    pub const fn nonce(&self) -> TenantRootManagedRestoreIncidentNonceV1 {
        self.binding().nonce()
    }

    /// Returns the incident-operations authority authenticated by this token.
    pub const fn operations_authority_id(&self) -> TenantRootControlPlaneAuthorityIdV1 {
        self.binding().operations_authority_id()
    }

    /// Returns the incident-operations signing-key identifier authenticated by this token.
    pub fn operations_key_id(&self) -> &str {
        self.binding().operations_key_id()
    }

    /// Returns the unavailable role's custody authority authenticated by this token.
    pub const fn custody_authority_id(&self) -> TenantRootControlPlaneAuthorityIdV1 {
        self.binding().custody_authority_id()
    }

    /// Returns the unavailable role's custody signing-key identifier authenticated by this token.
    pub fn custody_key_id(&self) -> &str {
        self.binding().custody_key_id()
    }

    /// Returns the exact canonical signed bytes accepted by verification.
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    /// Returns the digest of the exact canonical signed bytes accepted by verification.
    pub const fn digest(&self) -> TenantRootProtocolDigestV1 {
        self.digest
    }

    /// Requires `now_ms` to be inside the inclusive issue-to-expiry window.
    pub fn require_fresh(&self, now_ms: u64) -> RouterAbDerivationResult<()> {
        if now_ms < self.issued_at_ms() || now_ms > self.expires_at_ms() {
            return Err(replay_mismatch(
                "tenant-root managed-restore incident authorization is outside its freshness window",
            ));
        }
        Ok(())
    }

    /// Consumes this token into the exact canonical signed bytes.
    pub fn into_canonical_bytes(self) -> Vec<u8> {
        self.canonical_bytes
    }
}

fn managed_restore_role(role: TwoPartyDeriverRole) -> TenantRootManagedRestoreRoleV1 {
    match role {
        TwoPartyDeriverRole::DeriverA => TenantRootManagedRestoreRoleV1::DeriverA,
        TwoPartyDeriverRole::DeriverB => TenantRootManagedRestoreRoleV1::DeriverB,
    }
}

fn push_role(
    bytes: &mut Vec<u8>,
    role: TenantRootManagedRestoreRoleV1,
) -> RouterAbDerivationResult<()> {
    let (label, share_id) = match role {
        TenantRootManagedRestoreRoleV1::DeriverA => (b"deriver_a".as_slice(), 1_u16),
        TenantRootManagedRestoreRoleV1::DeriverB => (b"deriver_b".as_slice(), 2_u16),
    };
    push_field(bytes, label)?;
    push_field(bytes, &share_id.to_be_bytes())
}

fn authentication_input(unsigned: &[u8]) -> RouterAbDerivationResult<Vec<u8>> {
    let mut bytes = Vec::new();
    push_field(
        &mut bytes,
        TENANT_ROOT_MANAGED_RESTORE_INCIDENT_AUTHORIZATION_AUTH_DOMAIN_V1,
    )?;
    push_field(&mut bytes, unsigned)?;
    Ok(bytes)
}

fn verify_signature(
    input: &[u8],
    signature: &[u8; 64],
    trusted_verifying_key: &[u8; 32],
    message: &'static str,
) -> RouterAbDerivationResult<()> {
    let verifying_key = VerifyingKey::from_bytes(trusted_verifying_key).map_err(|_| {
        verification_failed("tenant-root managed-restore incident trusted key is invalid")
    })?;
    verifying_key
        .verify_strict(input, &Signature::from_bytes(signature))
        .map_err(|_| verification_failed(message))
}

fn push_field(out: &mut Vec<u8>, value: &[u8]) -> RouterAbDerivationResult<()> {
    if value.is_empty() {
        return Err(RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::EmptyField,
            "tenant-root managed-restore incident authorization field is required",
        ));
    }
    let length = u32::try_from(value.len()).map_err(|_| {
        malformed("tenant-root managed-restore incident authorization field is too long")
    })?;
    let new_len = out
        .len()
        .checked_add(4)
        .and_then(|length| length.checked_add(value.len()))
        .ok_or_else(|| {
            malformed("tenant-root managed-restore incident authorization wire length overflows")
        })?;
    if new_len > TENANT_ROOT_MANAGED_RESTORE_INCIDENT_AUTHORIZATION_MAX_BYTES_V1 {
        return Err(malformed(
            "tenant-root managed-restore incident authorization wire is too long",
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
