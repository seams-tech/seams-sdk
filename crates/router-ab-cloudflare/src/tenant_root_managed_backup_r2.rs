use sha2::{Digest, Sha256};

use router_ab_core::{
    TenantRootCustodyLineageId, TenantRootIdentityDigestV1, TenantRootManagedBackupBindingV1,
    TenantRootManagedRestoreRoleV1, TenantRootShareEpoch, TenantRootSignedManagedBackupV1,
    VerifiedTenantRootManagedBackupV1,
};

#[cfg(feature = "workers-rs")]
use worker::{Bucket, Conditional, Env};

pub(crate) const TENANT_ROOT_MANAGED_BACKUP_BUCKET_BINDING: &str =
    "TENANT_ROOT_MANAGED_BACKUP_BUCKET";

const TENANT_ROOT_MANAGED_BACKUP_OBJECT_PREFIX_V1: &str = "tenant-root-managed-backup/v1";

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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CloudflareTenantRootManagedBackupPutOutcomeV1 {
    Stored {
        object_key: String,
        artifact_digest: [u8; 32],
    },
    Replay {
        object_key: String,
        artifact_digest: [u8; 32],
    },
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
        let artifact_digest: [u8; 32] = Sha256::digest(canonical_bytes).into();
        let object_key =
            TenantRootManagedBackupObjectCoordinatesV1::from_binding(backup.binding()).object_key();
        let created = self
            .bucket
            .put(object_key.clone(), canonical_bytes.to_vec())
            .sha256(artifact_digest)
            .only_if(Conditional {
                etag_does_not_match: Some("*".to_owned()),
                ..Conditional::default()
            })
            .execute()
            .await?;
        if created.is_some() {
            return Ok(CloudflareTenantRootManagedBackupPutOutcomeV1::Stored {
                object_key,
                artifact_digest,
            });
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
        Ok(CloudflareTenantRootManagedBackupPutOutcomeV1::Replay {
            object_key,
            artifact_digest,
        })
    }

    pub(crate) async fn get_verified(
        &self,
        coordinates: TenantRootManagedBackupObjectCoordinatesV1,
        trusted_role_verifying_key: &[u8; 32],
    ) -> worker::Result<VerifiedTenantRootManagedBackupV1> {
        self.require_role(coordinates.role)?;
        let object = self
            .bucket
            .get(coordinates.object_key())
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
        signed
            .verify(signed.binding(), trusted_role_verifying_key)
            .map_err(|error| backup_store_error(error.message()))
    }

    /// Deletes one role-local backup object by its complete object coordinates.
    pub(crate) async fn delete_coordinates(
        &self,
        coordinates: TenantRootManagedBackupObjectCoordinatesV1,
    ) -> worker::Result<()> {
        self.require_role(coordinates.role)?;
        self.bucket.delete(coordinates.object_key()).await
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
    }
}
