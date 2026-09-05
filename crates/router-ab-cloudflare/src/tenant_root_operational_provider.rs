#![allow(dead_code)]

use hpke_ng::{ChaCha20Poly1305, DhKemX25519HkdfSha256, HkdfSha256, Hpke, Kem};
use router_ab_core::{
    MpcPrfSigningRootShareWireV1, RouterAbDerivationError, RouterAbDerivationErrorCode,
    RouterAbDerivationResult, TenantRootManagedBackupSealRequestV1, TenantRootManagedRestoreRoleV1,
    TenantRootOnlineRoleShareSealRequestV1, TenantRootSealedOnlineRoleShareV1,
    VerifiedTenantRootManagedBackupShareV1, VerifiedTenantRootManagedBackupV1,
    VerifiedTenantRootOnlineRoleShareV1,
};
use subtle::ConstantTimeEq;
use threshold_prf::SigningRootShareWire;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::hpke::CloudflareHpkeGetrandomRngV1;
#[cfg(feature = "workers-rs")]
use crate::tenant_root_google_kms::CloudflareTenantRootGoogleKmsBackupProviderV1;
use crate::tenant_root_role_runtime::{
    TenantRootManagedBackupProviderV1, TenantRootOnlineRoleShareProviderV1,
};

type OperationalHpkeSuiteV1 = Hpke<DhKemX25519HkdfSha256, HkdfSha256, ChaCha20Poly1305>;
type OperationalHpkeKemV1 = DhKemX25519HkdfSha256;
type OperationalHpkePublicKeyV1 = <OperationalHpkeKemV1 as Kem>::PublicKey;
type OperationalHpkePrivateKeyV1 = <OperationalHpkeKemV1 as Kem>::PrivateKey;
type OperationalHpkeEncappedKeyV1 = <OperationalHpkeKemV1 as Kem>::EncappedKey;

const ONLINE_INFO_V1: &[u8] =
    b"seams/tenant-root/operational-rotation/online/hpke-x25519-hkdf-sha256-chacha20poly1305/v1";
const BACKUP_INFO_V1: &[u8] =
    b"seams/tenant-root/operational-rotation/managed-backup/hpke-x25519-hkdf-sha256-chacha20poly1305/v1";
const ENCAPSULATED_KEY_BYTES_V1: usize = 32;
const AEAD_TAG_BYTES_V1: usize = 16;
const MAX_CIPHERTEXT_BYTES_V1: usize = 64 * 1024;

#[derive(Zeroize, ZeroizeOnDrop)]
struct OperationalHpkeSecretKeyV1 {
    key: OperationalHpkePrivateKeyV1,
}

/// Owned, request-local inputs for a role-local operational provider.
///
/// The private key bytes remain zeroizing until the provider has validated and
/// parsed both key pairs.
pub(crate) struct CloudflareTenantRootOperationalRotationProviderInputsV1 {
    role: threshold_prf::TwoPartyDeriverRole,
    online_epoch_wrapping_key_ref: String,
    online_public_key_bytes: [u8; 32],
    online_secret_bytes: Zeroizing<Vec<u8>>,
    managed_backup: CloudflareTenantRootManagedBackupProviderInputsV1,
}

pub(crate) enum CloudflareTenantRootManagedBackupProviderInputsV1 {
    CloudflareHpke {
        provider_id: String,
        key_version: String,
        public_key_bytes: [u8; 32],
        secret_bytes: Zeroizing<Vec<u8>>,
    },
    #[cfg(feature = "workers-rs")]
    GoogleCloudKms {
        provider_id: String,
        key_version: String,
        credentials_json: Zeroizing<Vec<u8>>,
    },
}

impl core::fmt::Debug for CloudflareTenantRootOperationalRotationProviderInputsV1 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CloudflareTenantRootOperationalRotationProviderInputsV1")
            .field("role", &self.role)
            .field(
                "online_epoch_wrapping_key_ref",
                &self.online_epoch_wrapping_key_ref,
            )
            .field("online_public_key_bytes", &"[redacted]")
            .field("online_secret_bytes", &"[redacted]")
            .field("managed_backup", &"[configured]")
            .finish()
    }
}

impl CloudflareTenantRootOperationalRotationProviderInputsV1 {
    /// Creates owned provider inputs; `from_inputs` performs full validation.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        role: threshold_prf::TwoPartyDeriverRole,
        online_epoch_wrapping_key_ref: impl Into<String>,
        online_public_key_bytes: [u8; 32],
        online_secret_bytes: Zeroizing<Vec<u8>>,
        backup_provider_id: impl Into<String>,
        backup_key_version: impl Into<String>,
        backup_public_key_bytes: [u8; 32],
        backup_secret_bytes: Zeroizing<Vec<u8>>,
    ) -> Self {
        Self {
            role,
            online_epoch_wrapping_key_ref: online_epoch_wrapping_key_ref.into(),
            online_public_key_bytes,
            online_secret_bytes,
            managed_backup: CloudflareTenantRootManagedBackupProviderInputsV1::CloudflareHpke {
                provider_id: backup_provider_id.into(),
                key_version: backup_key_version.into(),
                public_key_bytes: backup_public_key_bytes,
                secret_bytes: backup_secret_bytes,
            },
        }
    }

    pub(crate) fn new_with_managed_backup(
        role: threshold_prf::TwoPartyDeriverRole,
        online_epoch_wrapping_key_ref: impl Into<String>,
        online_public_key_bytes: [u8; 32],
        online_secret_bytes: Zeroizing<Vec<u8>>,
        managed_backup: CloudflareTenantRootManagedBackupProviderInputsV1,
    ) -> Self {
        Self {
            role,
            online_epoch_wrapping_key_ref: online_epoch_wrapping_key_ref.into(),
            online_public_key_bytes,
            online_secret_bytes,
            managed_backup,
        }
    }
}

/// One role-local provider for the online and managed-backup rotation slots.
pub(crate) struct CloudflareTenantRootOperationalRotationProviderV1 {
    role: threshold_prf::TwoPartyDeriverRole,
    online_epoch_wrapping_key_ref: String,
    backup_provider_id: String,
    backup_key_version: String,
    online_public_key: OperationalHpkePublicKeyV1,
    online_private_key: OperationalHpkeSecretKeyV1,
    managed_backup: TenantRootManagedBackupProviderStateV1,
}

enum TenantRootManagedBackupProviderStateV1 {
    CloudflareHpke {
        public_key: OperationalHpkePublicKeyV1,
        private_key: OperationalHpkeSecretKeyV1,
    },
    #[cfg(feature = "workers-rs")]
    GoogleCloudKms(CloudflareTenantRootGoogleKmsBackupProviderV1),
}

impl CloudflareTenantRootOperationalRotationProviderV1 {
    /// Builds a provider from owned, zeroizing environment/Secret inputs.
    pub(crate) fn from_inputs(
        inputs: CloudflareTenantRootOperationalRotationProviderInputsV1,
    ) -> RouterAbDerivationResult<Self> {
        let CloudflareTenantRootOperationalRotationProviderInputsV1 {
            role,
            online_epoch_wrapping_key_ref,
            online_public_key_bytes,
            online_secret_bytes,
            managed_backup,
        } = inputs;
        let online_epoch_wrapping_key_ref = online_epoch_wrapping_key_ref;
        let online_public_key = parse_public_key(&online_public_key_bytes)?;
        let online_private_key = parse_secret_key(online_secret_bytes)?;
        verify_key_pair(&online_public_key, &online_private_key)?;
        let (backup_provider_id, backup_key_version, managed_backup) = match managed_backup {
            CloudflareTenantRootManagedBackupProviderInputsV1::CloudflareHpke {
                provider_id,
                key_version,
                public_key_bytes,
                secret_bytes,
            } => {
                let public_key = parse_public_key(&public_key_bytes)?;
                let private_key = parse_secret_key(secret_bytes)?;
                verify_key_pair(&public_key, &private_key)?;
                if online_public_key_bytes == public_key_bytes {
                    return Err(malformed(
                        "tenant-root operational provider key material must be distinct",
                    ));
                }
                (
                    provider_id,
                    key_version,
                    TenantRootManagedBackupProviderStateV1::CloudflareHpke {
                        public_key,
                        private_key,
                    },
                )
            }
            #[cfg(feature = "workers-rs")]
            CloudflareTenantRootManagedBackupProviderInputsV1::GoogleCloudKms {
                provider_id,
                key_version,
                credentials_json,
            } => (
                provider_id.clone(),
                key_version.clone(),
                TenantRootManagedBackupProviderStateV1::GoogleCloudKms(
                    CloudflareTenantRootGoogleKmsBackupProviderV1::new(
                        role,
                        provider_id,
                        key_version,
                        credentials_json,
                    )?,
                ),
            ),
        };
        require_descriptor(
            "tenant-root online epoch wrapping-key reference",
            &online_epoch_wrapping_key_ref,
        )?;
        require_descriptor(
            "tenant-root managed-backup provider id",
            &backup_provider_id,
        )?;
        require_descriptor(
            "tenant-root managed-backup key version",
            &backup_key_version,
        )?;
        if online_epoch_wrapping_key_ref == backup_provider_id
            || online_epoch_wrapping_key_ref == backup_key_version
            || backup_provider_id == backup_key_version
        {
            return Err(malformed(
                "tenant-root operational provider key descriptors must be distinct",
            ));
        }
        Ok(Self {
            role,
            online_epoch_wrapping_key_ref,
            backup_provider_id,
            backup_key_version,
            online_public_key,
            online_private_key,
            managed_backup,
        })
    }

    /// Creates a role-local provider after validating both HPKE key pairs.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        role: threshold_prf::TwoPartyDeriverRole,
        online_epoch_wrapping_key_ref: impl Into<String>,
        online_public_key_bytes: impl AsRef<[u8]>,
        online_secret_bytes: Zeroizing<Vec<u8>>,
        backup_provider_id: impl Into<String>,
        backup_key_version: impl Into<String>,
        backup_public_key_bytes: impl AsRef<[u8]>,
        backup_secret_bytes: Zeroizing<Vec<u8>>,
    ) -> RouterAbDerivationResult<Self> {
        Self::from_inputs(
            CloudflareTenantRootOperationalRotationProviderInputsV1::new(
                role,
                online_epoch_wrapping_key_ref,
                online_public_key_bytes.as_ref().try_into().map_err(|_| {
                    malformed("tenant-root operational provider public key must be 32 bytes")
                })?,
                online_secret_bytes,
                backup_provider_id,
                backup_key_version,
                backup_public_key_bytes.as_ref().try_into().map_err(|_| {
                    malformed("tenant-root operational provider public key must be 32 bytes")
                })?,
                backup_secret_bytes,
            ),
        )
    }
}

impl TenantRootOnlineRoleShareProviderV1 for CloudflareTenantRootOperationalRotationProviderV1 {
    fn seal_online_role_share(
        &mut self,
        request: &TenantRootOnlineRoleShareSealRequestV1,
    ) -> RouterAbDerivationResult<Vec<u8>> {
        require_online_request(self, request)?;
        let aad = request.aad()?;
        let plaintext = Zeroizing::new(request.share_wire().to_bytes());
        seal_payload(
            &self.online_public_key,
            ONLINE_INFO_V1,
            &aad,
            plaintext.as_ref(),
        )
    }

    fn open_online_role_share(
        &mut self,
        sealed: TenantRootSealedOnlineRoleShareV1,
    ) -> RouterAbDerivationResult<VerifiedTenantRootOnlineRoleShareV1> {
        require_online_artifact(self, &sealed)?;
        let aad = sealed.aad()?;
        let (encapped_key, ciphertext) = split_ciphertext(sealed.ciphertext())?;
        let plaintext = Zeroizing::new(
            OperationalHpkeSuiteV1::open_base(
                &encapped_key,
                &self.online_private_key.key,
                ONLINE_INFO_V1,
                &aad,
                ciphertext,
            )
            .map_err(|_| malformed("tenant-root online role-share HPKE opening failed"))?,
        );
        let share = SigningRootShareWire::decode_slice(plaintext.as_slice())
            .map_err(|_| malformed("tenant-root online role-share plaintext is invalid"))?;
        sealed.verify_opened_share(share)
    }
}

impl TenantRootManagedBackupProviderV1 for CloudflareTenantRootOperationalRotationProviderV1 {
    async fn seal_managed_backup(
        &mut self,
        request: &TenantRootManagedBackupSealRequestV1,
    ) -> RouterAbDerivationResult<Vec<u8>> {
        require_backup_request(self, request)?;
        let aad = request.aad()?;
        let plaintext = Zeroizing::new(request.plaintext_share().to_vec());
        match &mut self.managed_backup {
            TenantRootManagedBackupProviderStateV1::CloudflareHpke { public_key, .. } => {
                seal_payload(public_key, BACKUP_INFO_V1, &aad, plaintext.as_slice())
            }
            #[cfg(feature = "workers-rs")]
            TenantRootManagedBackupProviderStateV1::GoogleCloudKms(provider) => {
                provider.seal(&aad, plaintext.as_slice()).await
            }
        }
    }

    async fn open_managed_backup(
        &mut self,
        backup: VerifiedTenantRootManagedBackupV1,
    ) -> RouterAbDerivationResult<VerifiedTenantRootManagedBackupShareV1> {
        require_backup_artifact(self, &backup)?;
        let aad = backup.aad()?;
        let plaintext = match &mut self.managed_backup {
            TenantRootManagedBackupProviderStateV1::CloudflareHpke { private_key, .. } => {
                let (encapped_key, ciphertext) = split_ciphertext(backup.ciphertext())?;
                Zeroizing::new(
                    OperationalHpkeSuiteV1::open_base(
                        &encapped_key,
                        &private_key.key,
                        BACKUP_INFO_V1,
                        &aad,
                        ciphertext,
                    )
                    .map_err(|_| malformed("tenant-root managed-backup HPKE opening failed"))?,
                )
            }
            #[cfg(feature = "workers-rs")]
            TenantRootManagedBackupProviderStateV1::GoogleCloudKms(provider) => {
                provider.open(&aad, backup.ciphertext()).await?
            }
        };
        let share = MpcPrfSigningRootShareWireV1::new(plaintext.to_vec())?;
        backup.verify_opened_share(share)
    }
}

fn parse_public_key(bytes: &[u8]) -> RouterAbDerivationResult<OperationalHpkePublicKeyV1> {
    if bytes.len() != OperationalHpkeKemV1::PUBLIC_KEY_LEN {
        return Err(malformed(
            "tenant-root operational provider public key must be 32 bytes",
        ));
    }
    let public_key = OperationalHpkeKemV1::pk_from_bytes(bytes)
        .map_err(|_| malformed("tenant-root operational provider public key is invalid"))?;
    if OperationalHpkeKemV1::pk_to_bytes(&public_key) != bytes {
        return Err(malformed(
            "tenant-root operational provider public key is not canonical",
        ));
    }
    Ok(public_key)
}

fn parse_secret_key(
    bytes: Zeroizing<Vec<u8>>,
) -> RouterAbDerivationResult<OperationalHpkeSecretKeyV1> {
    if bytes.len() != OperationalHpkeKemV1::PRIVATE_KEY_LEN {
        return Err(malformed(
            "tenant-root operational provider secret key must be 32 bytes",
        ));
    }
    let key = OperationalHpkeKemV1::sk_from_bytes(bytes.as_slice())
        .map_err(|_| malformed("tenant-root operational provider secret key is invalid"))?;
    Ok(OperationalHpkeSecretKeyV1 { key })
}

fn verify_key_pair(
    public_key: &OperationalHpkePublicKeyV1,
    private_key: &OperationalHpkeSecretKeyV1,
) -> RouterAbDerivationResult<()> {
    let mut rng = CloudflareHpkeGetrandomRngV1;
    let (encapped_shared_secret, encapped_key) = OperationalHpkeKemV1::encap(&mut rng, public_key)
        .map_err(|_| malformed("tenant-root operational provider public key is invalid"))?;
    let decapped_shared_secret = OperationalHpkeKemV1::decap(&encapped_key, &private_key.key)
        .map_err(|_| malformed("tenant-root operational provider secret key is invalid"))?;
    if !bool::from(
        encapped_shared_secret
            .as_ref()
            .ct_eq(decapped_shared_secret.as_ref()),
    ) {
        return Err(malformed(
            "tenant-root operational provider public/private key pair does not match",
        ));
    }
    Ok(())
}

fn seal_payload(
    public_key: &OperationalHpkePublicKeyV1,
    info: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> RouterAbDerivationResult<Vec<u8>> {
    let mut rng = CloudflareHpkeGetrandomRngV1;
    let (encapped_key, ciphertext) =
        OperationalHpkeSuiteV1::seal_base(&mut rng, public_key, info, aad, plaintext)
            .map_err(|_| malformed("tenant-root operational provider HPKE sealing failed"))?;
    let total_len = encapped_key
        .as_ref()
        .len()
        .checked_add(ciphertext.len())
        .ok_or_else(|| malformed("tenant-root operational provider ciphertext is too long"))?;
    if total_len > MAX_CIPHERTEXT_BYTES_V1 {
        return Err(malformed(
            "tenant-root operational provider ciphertext is too long",
        ));
    }
    let mut payload = Vec::with_capacity(total_len);
    payload.extend_from_slice(encapped_key.as_ref());
    payload.extend_from_slice(&ciphertext);
    Ok(payload)
}

fn split_ciphertext(
    payload: &[u8],
) -> RouterAbDerivationResult<(OperationalHpkeEncappedKeyV1, &[u8])> {
    let minimum = ENCAPSULATED_KEY_BYTES_V1 + AEAD_TAG_BYTES_V1;
    if payload.len() < minimum || payload.len() > MAX_CIPHERTEXT_BYTES_V1 {
        return Err(malformed(
            "tenant-root operational provider ciphertext has an invalid length",
        ));
    }
    let (encapped_bytes, ciphertext) = payload.split_at(ENCAPSULATED_KEY_BYTES_V1);
    let canonical_public_key = OperationalHpkeKemV1::pk_from_bytes(encapped_bytes)
        .map_err(|_| malformed("tenant-root operational provider encapsulated key is invalid"))?;
    if OperationalHpkeKemV1::pk_to_bytes(&canonical_public_key) != encapped_bytes {
        return Err(malformed(
            "tenant-root operational provider encapsulated key is not canonical",
        ));
    }
    let encapped_key = OperationalHpkeKemV1::enc_from_bytes(encapped_bytes)
        .map_err(|_| malformed("tenant-root operational provider encapsulated key is invalid"))?;
    Ok((encapped_key, ciphertext))
}

fn require_online_request(
    provider: &CloudflareTenantRootOperationalRotationProviderV1,
    request: &TenantRootOnlineRoleShareSealRequestV1,
) -> RouterAbDerivationResult<()> {
    if request.binding().role() != provider.role
        || request.binding().epoch_wrapping_key_ref() != provider.online_epoch_wrapping_key_ref
    {
        return Err(malformed(
            "tenant-root online role-share request does not match this provider",
        ));
    }
    Ok(())
}

fn require_online_artifact(
    provider: &CloudflareTenantRootOperationalRotationProviderV1,
    sealed: &TenantRootSealedOnlineRoleShareV1,
) -> RouterAbDerivationResult<()> {
    if sealed.binding().role() != provider.role
        || sealed.binding().epoch_wrapping_key_ref() != provider.online_epoch_wrapping_key_ref
    {
        return Err(malformed(
            "tenant-root online role-share artifact does not match this provider",
        ));
    }
    Ok(())
}

fn require_backup_request(
    provider: &CloudflareTenantRootOperationalRotationProviderV1,
    request: &TenantRootManagedBackupSealRequestV1,
) -> RouterAbDerivationResult<()> {
    if request.binding().role() != managed_role(provider.role)
        || request.binding().backup_provider_id() != provider.backup_provider_id
        || request.binding().backup_key_version() != provider.backup_key_version
    {
        return Err(malformed(
            "tenant-root managed-backup request does not match this provider",
        ));
    }
    Ok(())
}

fn require_backup_artifact(
    provider: &CloudflareTenantRootOperationalRotationProviderV1,
    backup: &VerifiedTenantRootManagedBackupV1,
) -> RouterAbDerivationResult<()> {
    if backup.role() != managed_role(provider.role)
        || backup.binding().backup_provider_id() != provider.backup_provider_id
        || backup.binding().backup_key_version() != provider.backup_key_version
    {
        return Err(malformed(
            "tenant-root managed-backup artifact does not match this provider",
        ));
    }
    Ok(())
}

const fn managed_role(role: threshold_prf::TwoPartyDeriverRole) -> TenantRootManagedRestoreRoleV1 {
    match role {
        threshold_prf::TwoPartyDeriverRole::DeriverA => TenantRootManagedRestoreRoleV1::DeriverA,
        threshold_prf::TwoPartyDeriverRole::DeriverB => TenantRootManagedRestoreRoleV1::DeriverB,
    }
}

fn require_descriptor(field: &'static str, value: &str) -> RouterAbDerivationResult<()> {
    if value.is_empty()
        || value.len() > 256
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(malformed(field));
    }
    Ok(())
}

fn malformed(message: &'static str) -> RouterAbDerivationError {
    RouterAbDerivationError::new(RouterAbDerivationErrorCode::MalformedInput, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keypair(seed: u8) -> ([u8; 32], [u8; 32]) {
        let (private_key, public_key) =
            DhKemX25519HkdfSha256::derive_key_pair(&[seed; 32]).expect("operational key pair");
        let private_key_bytes = DhKemX25519HkdfSha256::sk_to_bytes(&private_key);
        let public_key_bytes = DhKemX25519HkdfSha256::pk_to_bytes(&public_key);
        let mut private_key_out = [0_u8; 32];
        let mut public_key_out = [0_u8; 32];
        private_key_out.copy_from_slice(&private_key_bytes);
        public_key_out.copy_from_slice(&public_key_bytes);
        (private_key_out, public_key_out)
    }

    fn inputs(
        online_seed: u8,
        backup_seed: u8,
    ) -> CloudflareTenantRootOperationalRotationProviderInputsV1 {
        let (online_secret, online_public) = keypair(online_seed);
        let (backup_secret, backup_public) = keypair(backup_seed);
        CloudflareTenantRootOperationalRotationProviderInputsV1::new(
            threshold_prf::TwoPartyDeriverRole::DeriverA,
            "online-epoch-1",
            online_public,
            Zeroizing::new(online_secret.to_vec()),
            "cloudflare-operational",
            "backup-epoch-1",
            backup_public,
            Zeroizing::new(backup_secret.to_vec()),
        )
    }

    #[test]
    fn owned_inputs_construct_only_matching_distinct_key_pairs() {
        CloudflareTenantRootOperationalRotationProviderV1::from_inputs(inputs(0x11, 0x22))
            .expect("matching operational key pairs");

        let (online_secret, online_public) = keypair(0x31);
        let (_, backup_public) = keypair(0x32);
        let mismatched = CloudflareTenantRootOperationalRotationProviderInputsV1::new(
            threshold_prf::TwoPartyDeriverRole::DeriverB,
            "online-epoch-2",
            backup_public,
            Zeroizing::new(online_secret.to_vec()),
            "cloudflare-operational-b",
            "backup-epoch-2",
            online_public,
            Zeroizing::new(online_secret.to_vec()),
        );
        assert!(
            CloudflareTenantRootOperationalRotationProviderV1::from_inputs(mismatched).is_err()
        );
    }

    #[test]
    fn owned_input_debug_redacts_private_material() {
        let input = inputs(0x41, 0x42);
        let debug = format!("{input:?}");
        assert!(debug.contains("[redacted]"));
        assert!(!debug.contains("41".repeat(32).as_str()));
    }
}
