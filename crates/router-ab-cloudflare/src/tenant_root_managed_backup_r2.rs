#[cfg(feature = "workers-rs")]
use sha2::{Digest, Sha256};

#[cfg(feature = "workers-rs")]
use std::collections::HashMap;

use router_ab_core::{
    TenantRootCustodyLineageId, TenantRootIdentityDigestV1, TenantRootManagedBackupBindingV1,
    TenantRootManagedRestoreRoleV1, TenantRootOperationalErasureClaimV1, TenantRootShareEpoch,
};
#[cfg(feature = "workers-rs")]
use router_ab_core::{
    TenantRootProviderCanaryReceiptBindingV1, TenantRootSignedManagedBackupV1,
    TenantRootSignedProviderCanaryReceiptV1, VerifiedTenantRootManagedBackupV1,
    VerifiedTenantRootProviderCanaryReceiptV1,
};

#[cfg(feature = "workers-rs")]
use worker::{Bucket, Conditional, Env};

pub(crate) const TENANT_ROOT_MANAGED_BACKUP_BUCKET_BINDING: &str =
    "TENANT_ROOT_MANAGED_BACKUP_BUCKET";

const TENANT_ROOT_MANAGED_BACKUP_OBJECT_PREFIX_V1: &str = "tenant-root-managed-backup/v1";
const TENANT_ROOT_PROVIDER_CANARY_OBJECT_SUFFIX_V1: &str = ".provider-canary.bin";
const TENANT_ROOT_MANAGED_BACKUP_CANONICAL_DIGEST_METADATA_V1: &str =
    "tenant-root-canonical-digest-v1";
const TENANT_ROOT_MANAGED_BACKUP_WRAPPING_KEY_GENERATION_METADATA_V1: &str =
    "tenant-root-wrapping-key-generation-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TenantRootManagedBackupObjectCoordinatesV1 {
    identity_digest: TenantRootIdentityDigestV1,
    custody_lineage: TenantRootCustodyLineageId,
    role: TenantRootManagedRestoreRoleV1,
    epoch: TenantRootShareEpoch,
}

impl TenantRootManagedBackupObjectCoordinatesV1 {
    pub(crate) const fn new(
        identity_digest: TenantRootIdentityDigestV1,
        custody_lineage: TenantRootCustodyLineageId,
        role: TenantRootManagedRestoreRoleV1,
        epoch: TenantRootShareEpoch,
    ) -> Self {
        Self {
            identity_digest,
            custody_lineage,
            role,
            epoch,
        }
    }

    pub(crate) const fn from_binding(binding: &TenantRootManagedBackupBindingV1) -> Self {
        Self::new(
            binding.identity_digest(),
            binding.custody_lineage(),
            binding.role(),
            binding.epoch(),
        )
    }

    pub(crate) fn object_key(self) -> String {
        format!(
            "{TENANT_ROOT_MANAGED_BACKUP_OBJECT_PREFIX_V1}/{}/{}/{}/{}.bin",
            role_name(self.role),
            encode_hex(self.identity_digest.as_bytes()),
            self.custody_lineage.to_base64url(),
            self.epoch.get().get(),
        )
    }

    pub(crate) fn provider_canary_object_key(self) -> String {
        format!(
            "{TENANT_ROOT_MANAGED_BACKUP_OBJECT_PREFIX_V1}/{}/{}/{}/{}{}",
            role_name(self.role),
            encode_hex(self.identity_digest.as_bytes()),
            self.custody_lineage.to_base64url(),
            self.epoch.get().get(),
            TENANT_ROOT_PROVIDER_CANARY_OBJECT_SUFFIX_V1,
        )
    }
}

/// Exact public metadata retained with one immutable managed-backup object.
///
/// The canonical digest and wrapping-key generation reference are authenticated
/// by the signed artifact before this value is constructed. The object
/// generation comes from R2's immutable object metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TenantRootManagedBackupObjectMetadataV1 {
    object_key: String,
    canonical_digest: [u8; 32],
    object_generation: String,
    wrapping_key_generation_ref: String,
}

impl TenantRootManagedBackupObjectMetadataV1 {
    fn new(
        object_key: String,
        canonical_digest: [u8; 32],
        object_generation: String,
        wrapping_key_generation_ref: String,
    ) -> Result<Self, &'static str> {
        if object_key.is_empty() {
            return Err("managed-backup object key is empty");
        }
        if object_generation.is_empty() {
            return Err("managed-backup object generation is empty");
        }
        if wrapping_key_generation_ref.is_empty() {
            return Err("managed-backup wrapping-key generation reference is empty");
        }
        Ok(Self {
            object_key,
            canonical_digest,
            object_generation,
            wrapping_key_generation_ref,
        })
    }

    pub(crate) fn object_key(&self) -> &str {
        &self.object_key
    }

    pub(crate) const fn canonical_digest(&self) -> &[u8; 32] {
        &self.canonical_digest
    }

    pub(crate) fn object_generation(&self) -> &str {
        &self.object_generation
    }

    pub(crate) fn wrapping_key_generation_ref(&self) -> &str {
        &self.wrapping_key_generation_ref
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CloudflareTenantRootManagedBackupPutOutcomeV1 {
    Stored {
        metadata: TenantRootManagedBackupObjectMetadataV1,
    },
    Replay {
        metadata: TenantRootManagedBackupObjectMetadataV1,
    },
}

impl CloudflareTenantRootManagedBackupPutOutcomeV1 {
    pub(crate) const fn metadata(&self) -> &TenantRootManagedBackupObjectMetadataV1 {
        match self {
            Self::Stored { metadata } | Self::Replay { metadata } => metadata,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CloudflareTenantRootManagedBackupObjectDeletionStatusV1 {
    /// The object was present before deletion and absent in the verified read after it.
    Removed,
    /// The object was already absent before deletion and absent in the verified read after it.
    AlreadyAbsent,
}

/// R2 object-removal evidence with the required limitation on key erasure.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CloudflareTenantRootManagedBackupDeletionReceiptV1 {
    managed_backup_object_key: String,
    provider_canary_object_key: String,
    managed_backup: CloudflareTenantRootManagedBackupObjectDeletionStatusV1,
    provider_canary: CloudflareTenantRootManagedBackupObjectDeletionStatusV1,
    #[serde(deserialize_with = "deserialize_operational_erasure_claim")]
    cryptographic_erasure: TenantRootOperationalErasureClaimV1,
}

impl CloudflareTenantRootManagedBackupDeletionReceiptV1 {
    fn new(
        coordinates: TenantRootManagedBackupObjectCoordinatesV1,
        managed_backup: CloudflareTenantRootManagedBackupObjectDeletionStatusV1,
        provider_canary: CloudflareTenantRootManagedBackupObjectDeletionStatusV1,
    ) -> Self {
        Self {
            managed_backup_object_key: coordinates.object_key(),
            provider_canary_object_key: coordinates.provider_canary_object_key(),
            managed_backup,
            provider_canary,
            cryptographic_erasure:
                TenantRootOperationalErasureClaimV1::CryptographicErasureUnverified,
        }
    }

    pub(crate) fn managed_backup_object_key(&self) -> &str {
        &self.managed_backup_object_key
    }

    pub(crate) fn provider_canary_object_key(&self) -> &str {
        &self.provider_canary_object_key
    }

    pub(crate) const fn managed_backup(
        &self,
    ) -> CloudflareTenantRootManagedBackupObjectDeletionStatusV1 {
        self.managed_backup
    }

    pub(crate) const fn provider_canary(
        &self,
    ) -> CloudflareTenantRootManagedBackupObjectDeletionStatusV1 {
        self.provider_canary
    }

    pub(crate) const fn cryptographic_erasure(&self) -> TenantRootOperationalErasureClaimV1 {
        self.cryptographic_erasure
    }
}

fn deserialize_operational_erasure_claim<'de, D>(
    deserializer: D,
) -> Result<TenantRootOperationalErasureClaimV1, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = <String as serde::Deserialize>::deserialize(deserializer)?;
    match value.as_str() {
        "cryptographic_erasure_unverified" => {
            Ok(TenantRootOperationalErasureClaimV1::CryptographicErasureUnverified)
        }
        _ => Err(serde::de::Error::custom(
            "unsupported tenant-root operational erasure claim",
        )),
    }
}

#[cfg(feature = "workers-rs")]
#[derive(Clone)]
pub(crate) struct CloudflareTenantRootManagedBackupStoreV1 {
    bucket: Bucket,
    role: TenantRootManagedRestoreRoleV1,
}

#[cfg(feature = "workers-rs")]
impl CloudflareTenantRootManagedBackupStoreV1 {
    pub(crate) fn from_env(
        env: &Env,
        role: TenantRootManagedRestoreRoleV1,
    ) -> worker::Result<Self> {
        Ok(Self {
            bucket: env.bucket(TENANT_ROOT_MANAGED_BACKUP_BUCKET_BINDING)?,
            role,
        })
    }

    pub(crate) async fn put_verified(
        &self,
        backup: &VerifiedTenantRootManagedBackupV1,
    ) -> worker::Result<CloudflareTenantRootManagedBackupPutOutcomeV1> {
        self.require_role(backup.role())?;
        let canonical_bytes = backup.canonical_bytes();
        let canonical_digest: [u8; 32] = Sha256::digest(canonical_bytes).into();
        let object_key =
            TenantRootManagedBackupObjectCoordinatesV1::from_binding(backup.binding()).object_key();
        let wrapping_key_generation_ref = backup.binding().backup_key_version();
        let created = self
            .bucket
            .put(object_key.clone(), canonical_bytes.to_vec())
            .sha256(canonical_digest)
            .custom_metadata(object_custom_metadata(
                &canonical_digest,
                wrapping_key_generation_ref,
            ))
            .only_if(Conditional {
                etag_does_not_match: Some("*".to_owned()),
                ..Conditional::default()
            })
            .execute()
            .await?;
        if let Some(created) = created {
            let metadata = metadata_from_object(
                &created,
                &object_key,
                &canonical_digest,
                wrapping_key_generation_ref,
            )?;
            return Ok(CloudflareTenantRootManagedBackupPutOutcomeV1::Stored { metadata });
        }

        let existing = self
            .bucket
            .get(object_key.clone())
            .execute()
            .await?
            .ok_or_else(|| backup_store_error("managed-backup write conflict disappeared"))?;
        let existing_bytes = existing
            .body()
            .ok_or_else(|| backup_store_error("managed-backup replay returned no object body"))?
            .bytes()
            .await?;
        if existing_bytes != canonical_bytes {
            return Err(backup_store_error(
                "managed-backup object key already contains different canonical bytes",
            ));
        }
        let metadata = metadata_from_object(
            &existing,
            &object_key,
            &canonical_digest,
            wrapping_key_generation_ref,
        )?;
        Ok(CloudflareTenantRootManagedBackupPutOutcomeV1::Replay { metadata })
    }

    pub(crate) async fn get_verified(
        &self,
        coordinates: TenantRootManagedBackupObjectCoordinatesV1,
        trusted_role_verifying_key: &[u8; 32],
    ) -> worker::Result<VerifiedTenantRootManagedBackupV1> {
        let (verified, _) = self
            .get_verified_with_metadata(coordinates, trusted_role_verifying_key)
            .await?;
        Ok(verified)
    }

    pub(crate) async fn get_verified_with_metadata(
        &self,
        coordinates: TenantRootManagedBackupObjectCoordinatesV1,
        trusted_role_verifying_key: &[u8; 32],
    ) -> worker::Result<(
        VerifiedTenantRootManagedBackupV1,
        TenantRootManagedBackupObjectMetadataV1,
    )> {
        self.require_role(coordinates.role)?;
        let object_key = coordinates.object_key();
        let object = self
            .bucket
            .get(object_key.clone())
            .execute()
            .await?
            .ok_or_else(|| backup_store_error("managed-backup object does not exist"))?;
        let bytes = object
            .body()
            .ok_or_else(|| backup_store_error("managed-backup object has no body"))?
            .bytes()
            .await?;
        let signed = TenantRootSignedManagedBackupV1::decode_canonical_bytes(&bytes)
            .map_err(|error| backup_store_error(error.message()))?;
        if TenantRootManagedBackupObjectCoordinatesV1::from_binding(signed.binding()) != coordinates
        {
            return Err(backup_store_error(
                "managed-backup artifact does not match its object coordinates",
            ));
        }
        let verified = signed
            .verify(signed.binding(), trusted_role_verifying_key)
            .map_err(|error| backup_store_error(error.message()))?;
        let canonical_digest: [u8; 32] = Sha256::digest(&bytes).into();
        let metadata = metadata_from_object(
            &object,
            &object_key,
            &canonical_digest,
            verified.binding().backup_key_version(),
        )?;
        Ok((verified, metadata))
    }

    pub(crate) async fn put_verified_provider_canary(
        &self,
        coordinates: TenantRootManagedBackupObjectCoordinatesV1,
        canary_bytes: &[u8],
        expected_binding: &TenantRootProviderCanaryReceiptBindingV1,
        trusted_role_verifying_key: &[u8; 32],
    ) -> worker::Result<CloudflareTenantRootManagedBackupPutOutcomeV1> {
        self.require_role(coordinates.role)?;
        let verified = verify_provider_canary_object_bytes_v1(
            coordinates,
            Some(canary_bytes),
            expected_binding,
            trusted_role_verifying_key,
        )?;
        let canonical_bytes = verified.canonical_bytes();
        let canonical_digest: [u8; 32] = Sha256::digest(canonical_bytes).into();
        let object_key = coordinates.provider_canary_object_key();
        let wrapping_key_generation_ref = verified.provider_key_version_ref();
        let created = self
            .bucket
            .put(object_key.clone(), canonical_bytes.to_vec())
            .sha256(canonical_digest)
            .custom_metadata(object_custom_metadata(
                &canonical_digest,
                wrapping_key_generation_ref,
            ))
            .only_if(Conditional {
                etag_does_not_match: Some("*".to_owned()),
                ..Conditional::default()
            })
            .execute()
            .await?;
        if let Some(created) = created {
            let metadata = metadata_from_object(
                &created,
                &object_key,
                &canonical_digest,
                wrapping_key_generation_ref,
            )?;
            return Ok(CloudflareTenantRootManagedBackupPutOutcomeV1::Stored { metadata });
        }

        let existing = self
            .bucket
            .get(object_key.clone())
            .execute()
            .await?
            .ok_or_else(|| backup_store_error("provider canary write conflict disappeared"))?;
        let existing_bytes = existing
            .body()
            .ok_or_else(|| backup_store_error("provider canary replay returned no object body"))?
            .bytes()
            .await?;
        if existing_bytes != canonical_bytes {
            return Err(backup_store_error(
                "provider canary object key already contains different canonical bytes",
            ));
        }
        let metadata = metadata_from_object(
            &existing,
            &object_key,
            &canonical_digest,
            wrapping_key_generation_ref,
        )?;
        Ok(CloudflareTenantRootManagedBackupPutOutcomeV1::Replay { metadata })
    }

    pub(crate) async fn get_verified_provider_canary(
        &self,
        coordinates: TenantRootManagedBackupObjectCoordinatesV1,
        expected_binding: &TenantRootProviderCanaryReceiptBindingV1,
        trusted_role_verifying_key: &[u8; 32],
    ) -> worker::Result<VerifiedTenantRootProviderCanaryReceiptV1> {
        let (verified, _) = self
            .get_verified_provider_canary_with_metadata(
                coordinates,
                expected_binding,
                trusted_role_verifying_key,
            )
            .await?;
        Ok(verified)
    }

    pub(crate) async fn get_verified_provider_canary_with_metadata(
        &self,
        coordinates: TenantRootManagedBackupObjectCoordinatesV1,
        expected_binding: &TenantRootProviderCanaryReceiptBindingV1,
        trusted_role_verifying_key: &[u8; 32],
    ) -> worker::Result<(
        VerifiedTenantRootProviderCanaryReceiptV1,
        TenantRootManagedBackupObjectMetadataV1,
    )> {
        self.require_role(coordinates.role)?;
        let object_key = coordinates.provider_canary_object_key();
        let object = self
            .bucket
            .get(object_key.clone())
            .execute()
            .await?
            .ok_or_else(|| backup_store_error("provider canary object does not exist"))?;
        let bytes = object.body().map(|body| body.bytes());
        let bytes = match bytes {
            Some(bytes) => bytes.await?,
            None => return Err(backup_store_error("provider canary object has no body")),
        };
        let verified = verify_provider_canary_object_bytes_v1(
            coordinates,
            Some(&bytes),
            expected_binding,
            trusted_role_verifying_key,
        )?;
        let canonical_digest: [u8; 32] = Sha256::digest(&bytes).into();
        let metadata = metadata_from_object(
            &object,
            &object_key,
            &canonical_digest,
            verified.provider_key_version_ref(),
        )?;
        Ok((verified, metadata))
    }

    /// Deletes one role-local backup object and verifies both R2 keys are absent.
    pub(crate) async fn delete_coordinates(
        &self,
        coordinates: TenantRootManagedBackupObjectCoordinatesV1,
    ) -> worker::Result<CloudflareTenantRootManagedBackupDeletionReceiptV1> {
        self.require_role(coordinates.role)?;
        let provider_canary_key = coordinates.provider_canary_object_key();
        let managed_backup_key = coordinates.object_key();
        let provider_canary_was_present = self
            .bucket
            .head(provider_canary_key.clone())
            .await?
            .is_some();
        let managed_backup_was_present = self
            .bucket
            .head(managed_backup_key.clone())
            .await?
            .is_some();

        self.bucket.delete(provider_canary_key.clone()).await?;
        self.bucket.delete(managed_backup_key.clone()).await?;
        require_r2_object_absent(&self.bucket, &provider_canary_key, "provider canary").await?;
        require_r2_object_absent(&self.bucket, &managed_backup_key, "managed-backup").await?;

        Ok(CloudflareTenantRootManagedBackupDeletionReceiptV1::new(
            coordinates,
            object_deletion_status(managed_backup_was_present),
            object_deletion_status(provider_canary_was_present),
        ))
    }

    fn require_role(&self, role: TenantRootManagedRestoreRoleV1) -> worker::Result<()> {
        if role != self.role {
            return Err(backup_store_error(
                "managed-backup object belongs to the other Deriver",
            ));
        }
        Ok(())
    }
}

#[cfg(feature = "workers-rs")]
fn object_deletion_status(
    was_present: bool,
) -> CloudflareTenantRootManagedBackupObjectDeletionStatusV1 {
    if was_present {
        CloudflareTenantRootManagedBackupObjectDeletionStatusV1::Removed
    } else {
        CloudflareTenantRootManagedBackupObjectDeletionStatusV1::AlreadyAbsent
    }
}

#[cfg(feature = "workers-rs")]
async fn require_r2_object_absent(
    bucket: &Bucket,
    object_key: &str,
    object_kind: &str,
) -> worker::Result<()> {
    if bucket.head(object_key.to_owned()).await?.is_some() {
        return Err(backup_store_error(format!(
            "{object_kind} managed-backup object remained after deletion"
        )));
    }
    Ok(())
}

#[cfg(feature = "workers-rs")]
fn verify_provider_canary_object_bytes_v1(
    coordinates: TenantRootManagedBackupObjectCoordinatesV1,
    object_bytes: Option<&[u8]>,
    expected_binding: &TenantRootProviderCanaryReceiptBindingV1,
    trusted_role_verifying_key: &[u8; 32],
) -> worker::Result<VerifiedTenantRootProviderCanaryReceiptV1> {
    let bytes =
        object_bytes.ok_or_else(|| backup_store_error("provider canary object has no body"))?;
    let signed = TenantRootSignedProviderCanaryReceiptV1::decode_canonical_bytes(bytes)
        .map_err(|error| backup_store_error(error.message()))?;
    if signed.identity_digest() != coordinates.identity_digest
        || signed.custody_lineage() != coordinates.custody_lineage
        || signed.target_epoch() != coordinates.epoch
    {
        return Err(backup_store_error(
            "provider canary artifact does not match its object coordinates",
        ));
    }
    let verified = signed
        .verify(expected_binding, trusted_role_verifying_key)
        .map_err(|error| backup_store_error(error.message()))?;
    if verified.canonical_bytes() != bytes {
        return Err(backup_store_error(
            "provider canary artifact bytes are not canonical",
        ));
    }
    Ok(verified)
}

#[cfg(feature = "workers-rs")]
fn object_custom_metadata(
    canonical_digest: &[u8; 32],
    wrapping_key_generation_ref: &str,
) -> HashMap<String, String> {
    HashMap::from([
        (
            TENANT_ROOT_MANAGED_BACKUP_CANONICAL_DIGEST_METADATA_V1.to_owned(),
            encode_hex(canonical_digest),
        ),
        (
            TENANT_ROOT_MANAGED_BACKUP_WRAPPING_KEY_GENERATION_METADATA_V1.to_owned(),
            wrapping_key_generation_ref.to_owned(),
        ),
    ])
}

#[cfg(feature = "workers-rs")]
fn metadata_from_object(
    object: &worker::Object,
    expected_object_key: &str,
    expected_canonical_digest: &[u8; 32],
    expected_wrapping_key_generation_ref: &str,
) -> worker::Result<TenantRootManagedBackupObjectMetadataV1> {
    let object_key = object.key();
    if object_key != expected_object_key {
        return Err(backup_store_error(
            "managed-backup object metadata key does not match its coordinates",
        ));
    }
    let object_generation = object.version();
    let custom_metadata = object.custom_metadata()?;
    let stored_digest = custom_metadata
        .get(TENANT_ROOT_MANAGED_BACKUP_CANONICAL_DIGEST_METADATA_V1)
        .and_then(|value| decode_hex_digest(value))
        .ok_or_else(|| {
            backup_store_error("managed-backup object metadata has no canonical digest")
        })?;
    if &stored_digest != expected_canonical_digest {
        return Err(backup_store_error(
            "managed-backup object metadata canonical digest does not match its bytes",
        ));
    }
    let stored_wrapping_key_generation_ref = custom_metadata
        .get(TENANT_ROOT_MANAGED_BACKUP_WRAPPING_KEY_GENERATION_METADATA_V1)
        .ok_or_else(|| {
            backup_store_error("managed-backup object metadata has no wrapping-key generation")
        })?;
    if stored_wrapping_key_generation_ref != expected_wrapping_key_generation_ref {
        return Err(backup_store_error(
            "managed-backup object metadata wrapping-key generation does not match its binding",
        ));
    }
    TenantRootManagedBackupObjectMetadataV1::new(
        object_key,
        stored_digest,
        object_generation,
        stored_wrapping_key_generation_ref.to_owned(),
    )
    .map_err(backup_store_error)
}

fn decode_hex_digest(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 {
        return None;
    }
    let mut digest = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = decode_hex_nibble(pair[0])?;
        let low = decode_hex_nibble(pair[1])?;
        digest[index] = (high << 4) | low;
    }
    (encode_hex(&digest) == value).then_some(digest)
}

fn decode_hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

fn role_name(role: TenantRootManagedRestoreRoleV1) -> &'static str {
    match role {
        TenantRootManagedRestoreRoleV1::DeriverA => "deriver-a",
        TenantRootManagedRestoreRoleV1::DeriverB => "deriver-b",
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(feature = "workers-rs")]
fn backup_store_error(message: impl Into<String>) -> worker::Error {
    worker::Error::RustError(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "workers-rs")]
    use curve25519_dalek::scalar::Scalar;
    #[cfg(feature = "workers-rs")]
    use router_ab_core::{
        TenantRootActivationReceiptTransitionV1, TenantRootCanaryCurveFamilyV1,
        TenantRootControlPlaneAuthorityIdV1, TenantRootEpochCommitmentsV1,
        TenantRootSignedProviderCanaryReceiptV1,
    };
    #[cfg(feature = "workers-rs")]
    use threshold_prf::{SigningRootShare, SigningRootShareCommitment, ThresholdShareId};

    fn coordinates(
        role: TenantRootManagedRestoreRoleV1,
    ) -> TenantRootManagedBackupObjectCoordinatesV1 {
        TenantRootManagedBackupObjectCoordinatesV1::new(
            TenantRootIdentityDigestV1::from_bytes([0x11; 32]),
            TenantRootCustodyLineageId::from_bytes([0x22; 16]).expect("lineage"),
            role,
            TenantRootShareEpoch::new(7).expect("epoch"),
        )
    }

    #[test]
    fn object_keys_are_stable_role_private_and_coordinate_bound() {
        let a = coordinates(TenantRootManagedRestoreRoleV1::DeriverA).object_key();
        let b = coordinates(TenantRootManagedRestoreRoleV1::DeriverB).object_key();
        assert_eq!(
            a,
            "tenant-root-managed-backup/v1/deriver-a/1111111111111111111111111111111111111111111111111111111111111111/IiIiIiIiIiIiIiIiIiIiIg/7.bin"
        );
        assert_ne!(a, b);

        let changed_epoch = TenantRootManagedBackupObjectCoordinatesV1::new(
            TenantRootIdentityDigestV1::from_bytes([0x11; 32]),
            TenantRootCustodyLineageId::from_bytes([0x22; 16]).expect("lineage"),
            TenantRootManagedRestoreRoleV1::DeriverA,
            TenantRootShareEpoch::new(8).expect("epoch"),
        )
        .object_key();
        assert_ne!(a, changed_epoch);

        assert_eq!(
            coordinates(TenantRootManagedRestoreRoleV1::DeriverA).provider_canary_object_key(),
            "tenant-root-managed-backup/v1/deriver-a/1111111111111111111111111111111111111111111111111111111111111111/IiIiIiIiIiIiIiIiIiIiIg/7.provider-canary.bin"
        );
    }

    #[test]
    fn object_metadata_retains_exact_digest_generation_and_key_reference() {
        let digest = [0xabu8; 32];
        let metadata = TenantRootManagedBackupObjectMetadataV1::new(
            "tenant-root-managed-backup/v1/deriver-a/object.bin".to_owned(),
            digest,
            "r2-generation-17".to_owned(),
            "backup-key/tenant-7/epoch-1".to_owned(),
        )
        .expect("valid object metadata");

        assert_eq!(
            metadata.object_key(),
            "tenant-root-managed-backup/v1/deriver-a/object.bin"
        );
        assert_eq!(metadata.canonical_digest(), &digest);
        assert_eq!(metadata.object_generation(), "r2-generation-17");
        assert_eq!(
            metadata.wrapping_key_generation_ref(),
            "backup-key/tenant-7/epoch-1"
        );
    }

    #[test]
    fn object_metadata_rejects_missing_immutable_fields() {
        let digest = [0xabu8; 32];
        assert!(TenantRootManagedBackupObjectMetadataV1::new(
            String::new(),
            digest,
            "generation".to_owned(),
            "key-version".to_owned(),
        )
        .is_err());
        assert!(TenantRootManagedBackupObjectMetadataV1::new(
            "object".to_owned(),
            digest,
            String::new(),
            "key-version".to_owned(),
        )
        .is_err());
        assert!(TenantRootManagedBackupObjectMetadataV1::new(
            "object".to_owned(),
            digest,
            "generation".to_owned(),
            String::new(),
        )
        .is_err());
    }

    #[test]
    fn canonical_digest_metadata_is_lowercase_fixed_width_hex() {
        let digest = [0xabu8; 32];
        let encoded = encode_hex(&digest);
        assert_eq!(decode_hex_digest(&encoded), Some(digest));
        assert!(decode_hex_digest(&encoded.to_uppercase()).is_none());
        assert!(decode_hex_digest("00").is_none());
        assert!(decode_hex_digest(&encoded[..63]).is_none());
    }

    #[cfg(feature = "workers-rs")]
    #[test]
    fn deletion_receipt_keeps_r2_states_and_unverified_erasure_explicit() {
        let coordinates = coordinates(TenantRootManagedRestoreRoleV1::DeriverA);
        let receipt = CloudflareTenantRootManagedBackupDeletionReceiptV1::new(
            coordinates,
            CloudflareTenantRootManagedBackupObjectDeletionStatusV1::Removed,
            CloudflareTenantRootManagedBackupObjectDeletionStatusV1::AlreadyAbsent,
        );

        assert_eq!(
            receipt.managed_backup_object_key(),
            coordinates.object_key()
        );
        assert_eq!(
            receipt.provider_canary_object_key(),
            coordinates.provider_canary_object_key()
        );
        assert_eq!(
            receipt.managed_backup(),
            CloudflareTenantRootManagedBackupObjectDeletionStatusV1::Removed
        );
        assert_eq!(
            receipt.provider_canary(),
            CloudflareTenantRootManagedBackupObjectDeletionStatusV1::AlreadyAbsent
        );
        assert_eq!(
            receipt.cryptographic_erasure(),
            TenantRootOperationalErasureClaimV1::CryptographicErasureUnverified
        );
        let encoded = serde_json::to_value(&receipt).expect("deletion receipt json");
        let decoded: CloudflareTenantRootManagedBackupDeletionReceiptV1 =
            serde_json::from_value(encoded).expect("deletion receipt roundtrip");
        assert_eq!(decoded, receipt);
    }

    #[cfg(feature = "workers-rs")]
    fn provider_canary_fixture() -> (
        TenantRootManagedBackupObjectCoordinatesV1,
        TenantRootProviderCanaryReceiptBindingV1,
        Vec<u8>,
        [u8; 32],
    ) {
        let coordinates = coordinates(TenantRootManagedRestoreRoleV1::DeriverA);
        let commitment = |share_id: u8| {
            let share = SigningRootShare::from_canonical_bytes(
                ThresholdShareId::from_u16(u16::from(share_id)).expect("share id"),
                Scalar::from(u64::from(share_id) + 1).to_bytes(),
            )
            .expect("share");
            router_ab_core::MpcPrfShareCommitmentWireV1::new(
                SigningRootShareCommitment::from_share(&share)
                    .to_bytes()
                    .to_vec(),
            )
            .expect("share commitment")
        };
        let commitments = TenantRootEpochCommitmentsV1::new(commitment(1), commitment(2))
            .expect("epoch commitments");
        let signing_key = [0x44; 32];
        let binding = TenantRootProviderCanaryReceiptBindingV1::new(
            coordinates.identity_digest,
            coordinates.custody_lineage,
            TenantRootActivationReceiptTransitionV1::RefreshSwap,
            coordinates.epoch,
            commitments,
            TenantRootCanaryCurveFamilyV1::Ecdsa,
            "online-key/tenant-7/epoch-1",
            2,
            TenantRootControlPlaneAuthorityIdV1::from_bytes([0x55; 32]),
            "test-role-key",
            1,
            3,
        )
        .expect("canary binding");
        let canary = TenantRootSignedProviderCanaryReceiptV1::sign(binding.clone(), &signing_key)
            .expect("canary receipt");
        let bytes = canary.canonical_bytes().expect("canary bytes");
        (coordinates, binding, bytes, signing_key)
    }

    #[cfg(feature = "workers-rs")]
    #[test]
    fn provider_canary_object_verification_rejects_missing_and_tampered_bytes() {
        let (coordinates, binding, bytes, signing_key) = provider_canary_fixture();
        assert!(
            verify_provider_canary_object_bytes_v1(coordinates, None, &binding, &signing_key,)
                .is_err()
        );

        let mut tampered = bytes;
        let last = tampered.last_mut().expect("signature byte");
        *last ^= 1;
        assert!(verify_provider_canary_object_bytes_v1(
            coordinates,
            Some(&tampered),
            &binding,
            &signing_key,
        )
        .is_err());
    }
}
