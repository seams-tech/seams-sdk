use core::fmt;

#[cfg(debug_assertions)]
use ed25519_dalek::SigningKey;
use hpke_ng::Kem;
use router_ab_core::{
    reserve_tenant_root_command_v1, resolve_active_tenant_root_pair_binding_v1,
    resolve_active_tenant_root_role_binding_v1,
    resolve_authoritative_active_tenant_root_pair_binding_v1,
    validate_tenant_root_active_role_share_commitment_v1, ExecutedTenantRootCommandV1,
    MpcPrfShareCommitmentWireV1, ReservedTenantRootCommandV1,
    TenantRootAcceptedPermanentLossAuthorizationDigestV1,
    TenantRootActivationReceiptAvailabilityV1, TenantRootActivationReceiptBindingV1,
    TenantRootActivationReceiptTransitionV1, TenantRootActivePairResolutionV1,
    TenantRootActiveRoleAmbiguityV1, TenantRootActiveRoleBindingV1,
    TenantRootActiveRoleResolutionV1, TenantRootActiveRoleRowKeyV1, TenantRootActiveRootPairV1,
    TenantRootCeremonyEpochsV1, TenantRootCeremonyNonceV1, TenantRootCeremonySessionIdV1,
    TenantRootCommandOperationV1, TenantRootCommandReplayDecisionV1, TenantRootCommandReplayKeyV1,
    TenantRootCommandReplayRecordV1, TenantRootCommandScopeV1, TenantRootCommandTerminalOutcomeV1,
    TenantRootCommandTerminalReceiptV1, TenantRootCustodyBindingV1, TenantRootCustodyLineageId,
    TenantRootEpochCommitmentsV1, TenantRootIdentityDigestV1, TenantRootIdentityV1,
    TenantRootLifecycleReceiptDigestV1, TenantRootManagedRestoreRoleV1,
    TenantRootOnlineRoleShareBindingV1, TenantRootProtocolDigestV1,
    TenantRootRoleInstallationReceiptsV1, TenantRootSealedOnlineRoleShareV1, TenantRootShareEpoch,
    TenantRootSignedAcceptedPermanentLossAuthorizationV1, TenantRootSignedActivationReceiptV1,
    TwoPartyDeriverRole, VerifiedTenantRootCommandFailureReceiptV1,
    VerifiedTenantRootCommandSuccessReceiptV1, VerifiedTenantRootManagedBackupV1,
    VerifiedTenantRootRoleCleanupCommandV1, VerifiedTenantRootRoleCreationCommandV1,
    VerifiedTenantRootRoleRefreshCommandV1, VerifiedTenantRootSignedActivationReceiptV1,
    VerifiedTenantRootSignedShareInstallationEvidenceWireV1,
    TENANT_ROOT_ACTIVATION_RECEIPT_MAX_BYTES_V1, TENANT_ROOT_COMMAND_TERMINAL_RECEIPT_MAX_BYTES_V1,
};
use serde::{ser::SerializeStruct, Deserialize, Serialize, Serializer};
use sha2::{Digest, Sha256};
use worker::{D1DatabaseSession, D1SessionConstraint, D1Type, Env};
use zeroize::Zeroize;

use crate::{
    encoding::{decode_base64url_bytes_v1, encode_base64url_bytes_v1},
    env::CloudflareTenantRootCreationRoleSignerV1,
    hpke::{
        parse_cloudflare_hpke_x25519_public_key_v1, CloudflareHpkeGetrandomRngV1,
        CloudflareHpkeKemV1, CloudflareHpkeSuiteV1,
    },
};

const ROLE_PRIVATE_D1_BINDING: &str = "DERIVER_ROLE_PRIVATE_DB";
const ROLE_PRIVATE_D1_KEK_BINDING_ENV: &str = "DERIVER_ROLE_PRIVATE_D1_KEK_BINDING";
const ROLE_PRIVATE_D1_KEK_VERSION_ENV: &str = "DERIVER_ROLE_PRIVATE_D1_KEK_VERSION";
const ROLE_PRIVATE_D1_KEK_PUBLIC_KEY_ENV: &str = "DERIVER_ROLE_PRIVATE_D1_KEK_PUBLIC_KEY";
const ROLE_PRIVATE_D1_ENVIRONMENT_ENV: &str = "DERIVER_ROLE_PRIVATE_D1_ENVIRONMENT";
const ROLE_PRIVATE_D1_ROLE_ENV: &str = "DERIVER_ROLE_PRIVATE_D1_ROLE";
const ROLE_PRIVATE_D1_KEK_SECRET_PREFIX: &str = "hpke-x25519-role-private-d1-private-v1:";
const TENANT_ROOT_ROLE_D1_HPKE_INFO: &[u8] = b"seams/tenant-root/role-private-d1/hpke/v1";
const TENANT_ROOT_ROLE_D1_SCHEMA: &str = "tenant-root-role-private-d1/v2";
const TENANT_ROOT_ROLE_D1_PURPOSE: &str = "tenant-root-role-share";
const MAX_SEALED_ROLE_SHARE_BYTES: usize = 64 * 1024;
const INTEGRATION_EPOCH_ONE_DERIVER_A_POINT_V1: [u8; 32] = [
    0xe4, 0x54, 0x9e, 0xe1, 0x6b, 0x9a, 0xa0, 0x30, 0x99, 0xca, 0x20, 0x8c, 0x67, 0xad, 0xaf, 0xca,
    0xfa, 0x4c, 0x3f, 0x3e, 0x4e, 0x53, 0x03, 0xde, 0x60, 0x26, 0xe3, 0xca, 0x8f, 0xf8, 0x44, 0x60,
];
const INTEGRATION_EPOCH_ONE_DERIVER_B_POINT_V1: [u8; 32] = [
    0x4c, 0xf1, 0xb9, 0xde, 0xda, 0x93, 0xeb, 0x9f, 0xd5, 0x15, 0xfc, 0xc9, 0x92, 0x62, 0xae, 0xd1,
    0x36, 0x8b, 0x48, 0xf2, 0x4a, 0x27, 0xaf, 0xd2, 0x98, 0x4d, 0xa8, 0xfe, 0x7b, 0xb2, 0x34, 0x1f,
];
const INTEGRATION_EPOCH_TWO_DERIVER_A_POINT_V1: [u8; 32] = [
    0x68, 0x28, 0x02, 0xb3, 0xc9, 0x01, 0x12, 0xe0, 0xf4, 0xe7, 0xd9, 0x85, 0xe4, 0x23, 0xcd, 0x2b,
    0x16, 0xc5, 0xbf, 0xa6, 0x3d, 0x9c, 0x96, 0x7c, 0x52, 0xbb, 0x6c, 0xb7, 0xfe, 0xa7, 0xea, 0x7e,
];
const INTEGRATION_EPOCH_TWO_DERIVER_B_POINT_V1: [u8; 32] = [
    0x28, 0x09, 0xbe, 0x5a, 0x1c, 0x38, 0x8c, 0x4c, 0x00, 0x70, 0xa5, 0xc6, 0x6a, 0xce, 0x50, 0x7f,
    0xea, 0xde, 0x48, 0x82, 0x85, 0x90, 0x31, 0x46, 0x74, 0xcb, 0x0a, 0x6f, 0xd9, 0x71, 0xe9, 0x03,
];

const LOAD_EPOCH_SQL: &str = "SELECT tenant_identity_digest_hex, custody_lineage_b64u, \
    tenant_root_share_epoch, role, lifecycle, ciphertext_json, revision, created_at_ms, \
    updated_at_ms FROM tenant_root_role_shares WHERE tenant_identity_digest_hex = ?1 \
    AND custody_lineage_b64u = ?2 AND tenant_root_share_epoch = ?3 AND role = ?4";
const LOAD_ACTIVE_SQL: &str = "SELECT tenant_identity_digest_hex, custody_lineage_b64u, \
    tenant_root_share_epoch, role, lifecycle, ciphertext_json, revision, created_at_ms, \
    updated_at_ms FROM tenant_root_role_shares WHERE tenant_identity_digest_hex = ?1 \
    AND lifecycle = 'active'";
const INSERT_SQL: &str = "INSERT INTO tenant_root_role_shares \
    (tenant_identity_digest_hex, custody_lineage_b64u, tenant_root_share_epoch, role, \
    lifecycle, ciphertext_json, revision, created_at_ms, updated_at_ms) \
    VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1, ?7, ?8) \
    ON CONFLICT(tenant_identity_digest_hex, custody_lineage_b64u, \
    tenant_root_share_epoch, role) DO NOTHING";
const ACTIVATE_INITIAL_PENDING_SQL: &str = "UPDATE tenant_root_role_shares SET \
    lifecycle = 'active', ciphertext_json = ?1, revision = revision + 1, updated_at_ms = ?2 \
    WHERE tenant_identity_digest_hex = ?3 AND custody_lineage_b64u = ?4 \
    AND tenant_root_share_epoch = ?5 AND CAST(?5 AS INTEGER) = 1 \
    AND role = ?6 AND lifecycle = 'pending' \
    AND revision = ?7 AND NOT EXISTS (SELECT 1 FROM tenant_root_role_shares \
    WHERE tenant_identity_digest_hex = ?3 AND role = ?6 AND lifecycle = 'active')";
const SWAP_ACTIVE_EPOCH_SQL: &str = "UPDATE tenant_root_role_shares SET \
    lifecycle = CASE WHEN tenant_root_share_epoch = ?3 THEN 'retired' ELSE 'active' END, \
    ciphertext_json = CASE WHEN tenant_root_share_epoch = ?3 THEN ?8 ELSE ?9 END, \
    revision = revision + 1, updated_at_ms = ?10 \
    WHERE tenant_identity_digest_hex = ?1 AND custody_lineage_b64u = ?2 AND role = ?4 \
    AND CAST(?6 AS INTEGER) = CAST(?3 AS INTEGER) + 1 \
    AND ((tenant_root_share_epoch = ?3 AND lifecycle = 'active' AND revision = ?5 \
    AND EXISTS (SELECT 1 FROM tenant_root_role_shares \
    WHERE tenant_identity_digest_hex = ?1 AND custody_lineage_b64u = ?2 \
    AND tenant_root_share_epoch = ?6 AND role = ?4 AND lifecycle = 'pending' \
    AND revision = ?7)) OR (tenant_root_share_epoch = ?6 AND lifecycle = 'pending' \
    AND revision = ?7 AND EXISTS (SELECT 1 FROM tenant_root_role_shares \
    WHERE tenant_identity_digest_hex = ?1 AND custody_lineage_b64u = ?2 \
    AND tenant_root_share_epoch = ?3 AND role = ?4 AND lifecycle = 'active' \
    AND revision = ?5)))";
const CLEANUP_PENDING_SQL: &str = "DELETE FROM tenant_root_role_shares \
    WHERE tenant_identity_digest_hex = ?1 AND custody_lineage_b64u = ?2 \
    AND tenant_root_share_epoch = ?3 AND role = ?4 AND lifecycle = 'pending' \
    AND revision = ?5";
const LOAD_COMMAND_REPLAY_SQL: &str = "SELECT replay_key_digest_hex, \
    tenant_identity_digest_hex, custody_lineage_b64u, session_id_hex, nonce_hex, role, \
    command_digest_hex, admission_digest_hex, status, receipt_b64u, \
    receipt_digest_hex, reserved_at_ms, executed_at_ms, terminal_at_ms \
    FROM tenant_root_command_replays WHERE replay_key_digest_hex = ?1 \
    AND role = ?2";
const INSERT_COMMAND_RESERVATION_SQL: &str = "INSERT INTO tenant_root_command_replays \
    (replay_key_digest_hex, tenant_identity_digest_hex, custody_lineage_b64u, \
    session_id_hex, nonce_hex, role, command_digest_hex, admission_digest_hex, \
    status, reserved_at_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'reserved', ?9) \
    ON CONFLICT(replay_key_digest_hex) DO NOTHING";
const MARK_COMMAND_EXECUTED_SQL: &str = "UPDATE tenant_root_command_replays SET \
    status = 'executed', executed_at_ms = ?9 \
    WHERE replay_key_digest_hex = ?1 AND tenant_identity_digest_hex = ?2 \
    AND custody_lineage_b64u = ?3 AND session_id_hex = ?4 AND nonce_hex = ?5 \
    AND role = ?6 AND command_digest_hex = ?7 AND reserved_at_ms = ?8 \
    AND status = 'reserved'";
const CAS_COUNT_GUARD_SQL: &str = "INSERT INTO tenant_root_command_cas_guard (guard_id) \
    SELECT 1 WHERE changes() <> CAST(?1 AS INTEGER)";
const COMMIT_COMMAND_TERMINAL_SQL: &str = "UPDATE tenant_root_command_replays SET \
    status = ?1, receipt_b64u = ?2, receipt_digest_hex = ?3, terminal_at_ms = ?4 \
    WHERE replay_key_digest_hex = ?5 AND tenant_identity_digest_hex = ?6 \
    AND custody_lineage_b64u = ?7 AND session_id_hex = ?8 AND nonce_hex = ?9 \
    AND role = ?10 AND command_digest_hex = ?11 AND reserved_at_ms = ?12 \
    AND status = ?13 AND (status = 'reserved' OR executed_at_ms = ?14)";

/// Exact role owning one private tenant-root share store.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CloudflareTenantRootDeriverRoleV1 {
    /// Deriver A owns threshold share identifier one.
    DeriverA,
    /// Deriver B owns threshold share identifier two.
    DeriverB,
}

impl CloudflareTenantRootDeriverRoleV1 {
    fn parse(value: &str) -> worker::Result<Self> {
        match value {
            "deriver_a" => Ok(Self::DeriverA),
            "deriver_b" => Ok(Self::DeriverB),
            _ => Err(store_error(
                "DERIVER_ROLE_PRIVATE_D1_ROLE must be deriver_a or deriver_b",
            )),
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::DeriverA => "deriver_a",
            Self::DeriverB => "deriver_b",
        }
    }

    const fn share_id(self) -> u16 {
        match self {
            Self::DeriverA => 1,
            Self::DeriverB => 2,
        }
    }

    const fn managed_restore_role(self) -> TenantRootManagedRestoreRoleV1 {
        match self {
            Self::DeriverA => TenantRootManagedRestoreRoleV1::DeriverA,
            Self::DeriverB => TenantRootManagedRestoreRoleV1::DeriverB,
        }
    }
}

/// Ciphertext returned by the role's epoch wrapping-key provider.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareTenantRootSealedRoleShareV1 {
    ciphertext_b64u: String,
    ciphertext_digest_hex: String,
}

impl CloudflareTenantRootSealedRoleShareV1 {
    /// Normalizes one non-empty bounded ciphertext and commits its exact bytes.
    pub fn new(ciphertext: &[u8]) -> worker::Result<Self> {
        if ciphertext.is_empty() || ciphertext.len() > MAX_SEALED_ROLE_SHARE_BYTES {
            return Err(store_error(
                "tenant-root sealed role share has an invalid ciphertext length",
            ));
        }
        Ok(Self {
            ciphertext_b64u: encode_base64url_bytes_v1(ciphertext),
            ciphertext_digest_hex: encode_hex(Sha256::digest(ciphertext).as_ref()),
        })
    }

    /// Returns the canonical unpadded base64url ciphertext.
    pub fn ciphertext_b64u(&self) -> &str {
        &self.ciphertext_b64u
    }

    /// Returns the public digest of the exact sealed ciphertext.
    pub fn ciphertext_digest_hex(&self) -> &str {
        &self.ciphertext_digest_hex
    }

    fn validate(&self) -> worker::Result<()> {
        let ciphertext =
            decode_base64url_bytes_v1("tenant-root sealed role share", &self.ciphertext_b64u)
                .map_err(|error| store_error(error.message()))?;
        if ciphertext.is_empty()
            || ciphertext.len() > MAX_SEALED_ROLE_SHARE_BYTES
            || encode_base64url_bytes_v1(&ciphertext) != self.ciphertext_b64u
            || encode_hex(Sha256::digest(&ciphertext).as_ref()) != self.ciphertext_digest_hex
        {
            return Err(store_error("tenant-root sealed role share is malformed"));
        }
        require_digest_hex(
            "tenant-root sealed role share digest",
            &self.ciphertext_digest_hex,
        )
    }
}

impl fmt::Debug for CloudflareTenantRootSealedRoleShareV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CloudflareTenantRootSealedRoleShareV1")
            .field("ciphertext", &"[redacted]")
            .field("ciphertext_digest_hex", &self.ciphertext_digest_hex)
            .finish()
    }
}

/// Pending role-local tenant-root installation evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareTenantRootPendingShareV1 {
    installation_evidence_digest: TenantRootLifecycleReceiptDigestV1,
    staged_at_ms: u64,
}

impl CloudflareTenantRootPendingShareV1 {
    /// Creates one pending branch from exact verified installation evidence bytes.
    pub fn from_verified_installation_evidence(
        evidence: &VerifiedTenantRootSignedShareInstallationEvidenceWireV1,
        staged_at_ms: u64,
    ) -> worker::Result<Self> {
        let installation_evidence_digest = evidence
            .lifecycle_receipt_digest()
            .map_err(|error| store_error(error.message()))?;
        Self::from_stored_digest(installation_evidence_digest, staged_at_ms)
    }

    fn from_stored_digest(
        installation_evidence_digest: TenantRootLifecycleReceiptDigestV1,
        staged_at_ms: u64,
    ) -> worker::Result<Self> {
        let pending = Self {
            installation_evidence_digest,
            staged_at_ms,
        };
        pending.validate()?;
        Ok(pending)
    }

    fn validate(&self) -> worker::Result<()> {
        require_timestamp("tenant-root staged timestamp", self.staged_at_ms)
    }

    pub const fn installation_evidence_digest(&self) -> TenantRootLifecycleReceiptDigestV1 {
        self.installation_evidence_digest
    }
}

/// Exact availability evidence accepted before a role share may activate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CloudflareTenantRootAvailabilityEvidenceV1 {
    /// The owning role durably stored its independently encrypted current backup.
    CurrentRoleBackup {
        /// Digest of the role-signed backup receipt.
        role_backup_receipt_digest: TenantRootLifecycleReceiptDigestV1,
        /// Logical root bound by the signature-verified backup.
        identity_digest: TenantRootIdentityDigestV1,
        /// Custody lineage bound by the signature-verified backup.
        custody_lineage: TenantRootCustodyLineageId,
        /// Owning role bound by the signature-verified backup.
        role: TenantRootManagedRestoreRoleV1,
        /// Custody epoch bound by the signature-verified backup.
        epoch: TenantRootShareEpoch,
        /// Public role-share commitment bound by the signature-verified backup.
        share_commitment: MpcPrfShareCommitmentWireV1,
    },
    /// The deployment accepted permanent derivation loss with a verified
    /// dual-authority authorization retained by the activation receipt.
    AcceptedPermanentDerivationLoss {
        /// Digest of the exact signed accepted-loss authorization bytes.
        authorization_digest: TenantRootAcceptedPermanentLossAuthorizationDigestV1,
        /// Logical root bound by the signed activation receipt.
        identity_digest: TenantRootIdentityDigestV1,
        /// Custody lineage bound by the signed activation receipt.
        custody_lineage: TenantRootCustodyLineageId,
        /// Owning role bound by the signed activation receipt.
        role: TenantRootManagedRestoreRoleV1,
        /// Custody epoch bound by the signed activation receipt.
        epoch: TenantRootShareEpoch,
        /// Public role-share commitment bound by the signed activation receipt.
        share_commitment: MpcPrfShareCommitmentWireV1,
    },
}

impl Serialize for CloudflareTenantRootAvailabilityEvidenceV1 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::CurrentRoleBackup {
                role_backup_receipt_digest,
                identity_digest,
                custody_lineage,
                role,
                epoch,
                share_commitment,
            } => {
                let mut state =
                    serializer.serialize_struct("CloudflareTenantRootAvailabilityEvidenceV1", 7)?;
                state.serialize_field("kind", "current_role_backup")?;
                state.serialize_field("role_backup_receipt_digest", role_backup_receipt_digest)?;
                state.serialize_field("identity_digest", identity_digest)?;
                state.serialize_field("custody_lineage", custody_lineage)?;
                state.serialize_field("role", role)?;
                state.serialize_field("epoch", epoch)?;
                state.serialize_field("share_commitment", share_commitment)?;
                state.end()
            }
            Self::AcceptedPermanentDerivationLoss {
                authorization_digest,
                identity_digest,
                custody_lineage,
                role,
                epoch,
                share_commitment,
            } => {
                let mut state =
                    serializer.serialize_struct("CloudflareTenantRootAvailabilityEvidenceV1", 7)?;
                state.serialize_field("kind", "accepted_permanent_derivation_loss")?;
                state.serialize_field("authorization_digest", authorization_digest.as_bytes())?;
                state.serialize_field("identity_digest", identity_digest)?;
                state.serialize_field("custody_lineage", custody_lineage)?;
                state.serialize_field("role", role)?;
                state.serialize_field("epoch", epoch)?;
                state.serialize_field("share_commitment", share_commitment)?;
                state.end()
            }
        }
    }
}

impl CloudflareTenantRootAvailabilityEvidenceV1 {
    fn validate(&self) -> worker::Result<()> {
        match self {
            Self::CurrentRoleBackup { .. } => Ok(()),
            Self::AcceptedPermanentDerivationLoss {
                authorization_digest,
                ..
            } => {
                if authorization_digest
                    .as_bytes()
                    .iter()
                    .all(|byte| *byte == 0)
                {
                    return Err(store_error(
                        "tenant-root accepted-loss authorization digest must be non-zero",
                    ));
                }
                Ok(())
            }
        }
    }
}

/// Evidence required to activate one pending role-local share.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareTenantRootActivationV1 {
    availability: CloudflareTenantRootAvailabilityEvidenceV1,
    #[serde(
        rename = "activation_receipt_b64u",
        serialize_with = "serialize_activation_receipt_bytes"
    )]
    activation_receipt_bytes: Vec<u8>,
    #[serde(skip)]
    activation_receipt_digest: TenantRootLifecycleReceiptDigestV1,
    #[serde(skip)]
    activated_at_ms: u64,
}

impl CloudflareTenantRootActivationV1 {
    /// Creates one activation backed by the role's current managed backup.
    pub fn with_current_role_backup(
        record: &CloudflareTenantRootRoleShareRecordV1,
        verified_backup: &VerifiedTenantRootManagedBackupV1,
        activation_receipt: VerifiedTenantRootSignedActivationReceiptV1,
    ) -> worker::Result<Self> {
        record.validate()?;
        if !matches!(
            record.lifecycle(),
            CloudflareTenantRootRoleShareLifecycleV1::Pending(_)
        ) {
            return Err(store_error(
                "tenant-root activation requires a pending role-share record",
            ));
        }
        let binding = verified_backup.binding();
        validate_activation_receipt_against_backup(&activation_receipt, verified_backup)?;
        let availability = CloudflareTenantRootAvailabilityEvidenceV1::CurrentRoleBackup {
            role_backup_receipt_digest: verified_backup.receipt_digest(),
            identity_digest: binding.identity_digest(),
            custody_lineage: binding.custody_lineage(),
            role: binding.role(),
            epoch: binding.epoch(),
            share_commitment: binding.share_commitment().clone(),
        };
        validate_activation_receipt_against_record(
            activation_receipt.canonical_bytes(),
            record,
            &availability,
        )?;
        Self::from_verified_receipt(availability, activation_receipt)
    }

    /// Creates one activation backed by a verified dual-authority loss authorization.
    pub fn with_accepted_permanent_derivation_loss(
        record: &CloudflareTenantRootRoleShareRecordV1,
        activation_receipt: VerifiedTenantRootSignedActivationReceiptV1,
    ) -> worker::Result<Self> {
        record.validate()?;
        if !matches!(
            record.lifecycle(),
            CloudflareTenantRootRoleShareLifecycleV1::Pending(_)
        ) {
            return Err(store_error(
                "tenant-root activation requires a pending role-share record",
            ));
        }
        let availability = accepted_loss_availability_from_verified_receipt(
            &activation_receipt,
            record.role.managed_restore_role(),
        )?;
        validate_activation_receipt_against_record(
            activation_receipt.canonical_bytes(),
            record,
            &availability,
        )?;
        Self::from_verified_receipt(availability, activation_receipt)
    }

    fn from_verified_receipt(
        availability: CloudflareTenantRootAvailabilityEvidenceV1,
        activation_receipt: VerifiedTenantRootSignedActivationReceiptV1,
    ) -> worker::Result<Self> {
        let activation_receipt_digest = activation_receipt.digest();
        let activated_at_ms = activation_receipt.activated_at_ms();
        let activation_receipt_bytes = activation_receipt.into_canonical_bytes();
        let activation = Self {
            availability,
            activation_receipt_bytes,
            activation_receipt_digest,
            activated_at_ms,
        };
        activation.validate()?;
        Ok(activation)
    }

    fn from_stored_receipt_bytes(
        availability: CloudflareTenantRootAvailabilityEvidenceV1,
        activation_receipt_bytes: Vec<u8>,
    ) -> worker::Result<Self> {
        let receipt = decode_activation_receipt_bytes(&activation_receipt_bytes)?;
        let activation_receipt_digest = receipt
            .digest()
            .map_err(|error| store_error(error.message()))?;
        let activated_at_ms = receipt.activated_at_ms();
        let activation = Self {
            availability,
            activation_receipt_bytes,
            activation_receipt_digest,
            activated_at_ms,
        };
        activation.validate()?;
        Ok(activation)
    }

    /// Returns the exact canonical signed activation receipt bytes.
    pub fn activation_receipt_bytes(&self) -> &[u8] {
        &self.activation_receipt_bytes
    }

    /// Returns the digest derived from the exact canonical activation bytes.
    pub const fn activation_receipt_digest(&self) -> TenantRootLifecycleReceiptDigestV1 {
        self.activation_receipt_digest
    }

    /// Returns the activation time derived from the signed receipt.
    pub const fn activated_at_ms(&self) -> u64 {
        self.activated_at_ms
    }

    fn validate(&self) -> worker::Result<()> {
        self.availability.validate()?;
        let receipt = decode_activation_receipt_bytes(&self.activation_receipt_bytes)?;
        let digest = receipt
            .digest()
            .map_err(|error| store_error(error.message()))?;
        if digest != self.activation_receipt_digest
            || receipt.activated_at_ms() != self.activated_at_ms
        {
            return Err(store_error(
                "tenant-root activation receipt projection does not match its exact bytes",
            ));
        }
        require_timestamp("tenant-root activation timestamp", self.activated_at_ms)
    }

    fn validate_for_record(
        &self,
        record: &CloudflareTenantRootRoleShareRecordV1,
    ) -> worker::Result<()> {
        self.validate()?;
        let record_identity = record
            .identity
            .digest()
            .map_err(|error| store_error(error.message()))?;
        match &self.availability {
            CloudflareTenantRootAvailabilityEvidenceV1::CurrentRoleBackup {
                identity_digest,
                custody_lineage,
                role,
                epoch,
                share_commitment,
                ..
            } => {
                if *identity_digest != record_identity
                    || *custody_lineage != record.custody_lineage
                    || *role != record.role.managed_restore_role()
                    || *epoch != record.epoch
                    || share_commitment != &record.share_commitment
                {
                    return Err(store_error(
                        "tenant-root managed-backup binding does not match the pending role share",
                    ));
                }
            }
            CloudflareTenantRootAvailabilityEvidenceV1::AcceptedPermanentDerivationLoss {
                identity_digest,
                custody_lineage,
                role,
                epoch,
                share_commitment,
                ..
            } => {
                if *identity_digest != record_identity
                    || *custody_lineage != record.custody_lineage
                    || *role != record.role.managed_restore_role()
                    || *epoch != record.epoch
                    || share_commitment != &record.share_commitment
                {
                    return Err(store_error(
                        "tenant-root accepted-loss binding does not match the pending role share",
                    ));
                }
            }
        }
        validate_activation_receipt_against_record(
            &self.activation_receipt_bytes,
            record,
            &self.availability,
        )?;
        Ok(())
    }
}

/// Active role-local tenant-root share retaining the exact activation receipt bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareTenantRootActiveShareV1 {
    pending: CloudflareTenantRootPendingShareV1,
    activation: CloudflareTenantRootActivationV1,
}

impl CloudflareTenantRootActiveShareV1 {
    fn from_pending(
        pending: CloudflareTenantRootPendingShareV1,
        activation: CloudflareTenantRootActivationV1,
    ) -> worker::Result<Self> {
        let active = Self {
            pending,
            activation,
        };
        active.validate()?;
        Ok(active)
    }

    fn validate(&self) -> worker::Result<()> {
        self.pending.validate()?;
        self.activation.validate()?;
        if self.activation.activated_at_ms < self.pending.staged_at_ms {
            return Err(store_error(
                "tenant-root activation predates role-share installation",
            ));
        }
        Ok(())
    }
}

/// Evidence required to retire one active role-local share.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareTenantRootRetirementV1 {
    retirement_receipt_digest: TenantRootLifecycleReceiptDigestV1,
    retired_at_ms: u64,
}

impl CloudflareTenantRootRetirementV1 {
    /// Creates one signed forward-only retirement transition.
    pub fn new(
        retirement_receipt_digest: TenantRootLifecycleReceiptDigestV1,
        retired_at_ms: u64,
    ) -> worker::Result<Self> {
        let retirement = Self {
            retirement_receipt_digest,
            retired_at_ms,
        };
        retirement.validate()?;
        Ok(retirement)
    }

    fn validate(&self) -> worker::Result<()> {
        require_timestamp("tenant-root retirement timestamp", self.retired_at_ms)
    }
}

/// Retired role-local tenant-root share awaiting provider destruction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareTenantRootRetiredShareV1 {
    active: CloudflareTenantRootActiveShareV1,
    retirement: CloudflareTenantRootRetirementV1,
}

impl CloudflareTenantRootRetiredShareV1 {
    fn from_active(
        active: CloudflareTenantRootActiveShareV1,
        retirement: CloudflareTenantRootRetirementV1,
    ) -> worker::Result<Self> {
        let retired = Self { active, retirement };
        retired.validate()?;
        Ok(retired)
    }

    fn validate(&self) -> worker::Result<()> {
        self.active.validate()?;
        self.retirement.validate()?;
        if self.retirement.retired_at_ms < self.active.activation.activated_at_ms {
            return Err(store_error(
                "tenant-root retirement predates role-share activation",
            ));
        }
        Ok(())
    }
}

/// Exhaustive lifecycle for one persisted role-local share epoch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", content = "state", rename_all = "snake_case")]
pub enum CloudflareTenantRootRoleShareLifecycleV1 {
    /// Installed and verified locally, with activation still pending.
    Pending(CloudflareTenantRootPendingShareV1),
    /// Selected as the one current epoch for this role and tenant.
    Active(CloudflareTenantRootActiveShareV1),
    /// Replaced by a newer active epoch and awaiting destruction.
    Retired(CloudflareTenantRootRetiredShareV1),
}

impl CloudflareTenantRootRoleShareLifecycleV1 {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Pending(_) => "pending",
            Self::Active(_) => "active",
            Self::Retired(_) => "retired",
        }
    }

    fn event_at_ms(&self) -> u64 {
        match self {
            Self::Pending(state) => state.staged_at_ms,
            Self::Active(state) => state.activation.activated_at_ms,
            Self::Retired(state) => state.retirement.retired_at_ms,
        }
    }

    fn validate(&self) -> worker::Result<()> {
        match self {
            Self::Pending(state) => state.validate(),
            Self::Active(state) => state.validate(),
            Self::Retired(state) => state.validate(),
        }
    }
}

/// Required fields for one role-private tenant-root share record.
pub struct CloudflareTenantRootRoleShareRecordInputV1 {
    /// Server-resolved logical root identity.
    pub identity: TenantRootIdentityV1,
    /// Random custody lineage for this physical share pair.
    pub custody_lineage: TenantRootCustodyLineageId,
    /// Monotonic role-share custody epoch.
    pub epoch: TenantRootShareEpoch,
    /// Exact Deriver role owning the record.
    pub role: CloudflareTenantRootDeriverRoleV1,
    /// Epoch-provider ciphertext containing one canonical role share.
    pub sealed_share: CloudflareTenantRootSealedRoleShareV1,
    /// Public commitment to the sealed role share.
    pub share_commitment: MpcPrfShareCommitmentWireV1,
    /// Opaque external key-version reference needed to open the sealed share.
    pub epoch_wrapping_key_ref: String,
    /// Current lifecycle branch.
    pub lifecycle: CloudflareTenantRootRoleShareLifecycleV1,
    /// Initial durable creation time.
    pub created_at_ms: u64,
    /// Last successful lifecycle update time.
    pub updated_at_ms: u64,
}

/// Encrypted-at-rest record for one role's tenant-root share epoch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareTenantRootRoleShareRecordV1 {
    identity: TenantRootIdentityV1,
    custody_lineage: TenantRootCustodyLineageId,
    epoch: TenantRootShareEpoch,
    role: CloudflareTenantRootDeriverRoleV1,
    sealed_share: CloudflareTenantRootSealedRoleShareV1,
    share_commitment: MpcPrfShareCommitmentWireV1,
    epoch_wrapping_key_ref: String,
    lifecycle: CloudflareTenantRootRoleShareLifecycleV1,
    created_at_ms: u64,
    updated_at_ms: u64,
}

impl CloudflareTenantRootRoleShareRecordV1 {
    /// Validates and normalizes one role-private share record.
    pub fn new(input: CloudflareTenantRootRoleShareRecordInputV1) -> worker::Result<Self> {
        let record = Self {
            identity: input.identity,
            custody_lineage: input.custody_lineage,
            epoch: input.epoch,
            role: input.role,
            sealed_share: input.sealed_share,
            share_commitment: input.share_commitment,
            epoch_wrapping_key_ref: input.epoch_wrapping_key_ref,
            lifecycle: input.lifecycle,
            created_at_ms: input.created_at_ms,
            updated_at_ms: input.updated_at_ms,
        };
        record.validate()?;
        Ok(record)
    }

    /// Returns the server-resolved logical root identity.
    pub fn identity(&self) -> &TenantRootIdentityV1 {
        &self.identity
    }

    /// Returns the physical custody lineage.
    pub const fn custody_lineage(&self) -> TenantRootCustodyLineageId {
        self.custody_lineage
    }

    /// Returns the role-share custody epoch.
    pub const fn epoch(&self) -> TenantRootShareEpoch {
        self.epoch
    }

    /// Returns the exact owning Deriver role.
    pub const fn role(&self) -> CloudflareTenantRootDeriverRoleV1 {
        self.role
    }

    /// Returns the epoch-provider sealed share ciphertext.
    pub const fn sealed_share(&self) -> &CloudflareTenantRootSealedRoleShareV1 {
        &self.sealed_share
    }

    /// Returns the public share commitment.
    pub const fn share_commitment(&self) -> &MpcPrfShareCommitmentWireV1 {
        &self.share_commitment
    }

    /// Returns the opaque epoch wrapping-key reference.
    pub fn epoch_wrapping_key_ref(&self) -> &str {
        &self.epoch_wrapping_key_ref
    }

    /// Returns the exhaustive lifecycle branch.
    pub const fn lifecycle(&self) -> &CloudflareTenantRootRoleShareLifecycleV1 {
        &self.lifecycle
    }

    /// Returns the last timestamp durably written with this row.
    pub(crate) const fn updated_at_ms(&self) -> u64 {
        self.updated_at_ms
    }

    fn into_online_role_share_artifact(self) -> worker::Result<TenantRootSealedOnlineRoleShareV1> {
        let installation_evidence_digest = match &self.lifecycle {
            CloudflareTenantRootRoleShareLifecycleV1::Active(active) => {
                active.pending.installation_evidence_digest()
            }
            _ => {
                return Err(store_error(
                    "tenant-root online role-share artifact requires an active record",
                ));
            }
        };
        self.validate()?;
        validate_record_activation_binding(&self)?;
        let identity_digest = self
            .identity
            .digest()
            .map_err(|error| store_error(error.message()))?;
        let ciphertext = decode_base64url_bytes_v1(
            "tenant-root sealed role share",
            self.sealed_share.ciphertext_b64u(),
        )
        .map_err(|error| store_error(error.message()))?;
        let binding = TenantRootOnlineRoleShareBindingV1::from_persisted(
            identity_digest,
            self.custody_lineage,
            protocol_role_for_cloudflare(self.role),
            self.epoch,
            self.share_commitment,
            self.epoch_wrapping_key_ref,
            installation_evidence_digest,
        )
        .map_err(|error| store_error(error.message()))?;
        TenantRootSealedOnlineRoleShareV1::from_persisted(binding, ciphertext)
            .map_err(|error| store_error(error.message()))
    }

    fn identity_digest_hex(&self) -> worker::Result<String> {
        self.identity
            .digest()
            .map(|digest| encode_hex(digest.as_bytes()))
            .map_err(|error| store_error(error.message()))
    }

    fn validate(&self) -> worker::Result<()> {
        self.sealed_share.validate()?;
        self.lifecycle.validate()?;
        require_identifier(
            "tenant-root epoch wrapping-key reference",
            &self.epoch_wrapping_key_ref,
        )?;
        require_timestamp("tenant-root record creation timestamp", self.created_at_ms)?;
        require_timestamp("tenant-root record update timestamp", self.updated_at_ms)?;
        if self.updated_at_ms < self.created_at_ms
            || self.lifecycle.event_at_ms() < self.created_at_ms
            || self.lifecycle.event_at_ms() > self.updated_at_ms
        {
            return Err(store_error(
                "tenant-root role-share lifecycle timestamps are inconsistent",
            ));
        }
        validate_tenant_root_active_role_share_commitment_v1(
            self.role.managed_restore_role(),
            &self.share_commitment,
        )
        .map_err(|error| store_error(error.message()))?;
        epoch_i64(self.epoch)?;
        timestamp_i64(self.created_at_ms)?;
        timestamp_i64(self.updated_at_ms)?;
        Ok(())
    }

    fn into_active(
        mut self,
        activation: CloudflareTenantRootActivationV1,
        updated_at_ms: u64,
    ) -> worker::Result<Self> {
        activation.validate_for_record(&self)?;
        require_lifecycle_progression(
            "tenant-root activation",
            self.updated_at_ms,
            activation.activated_at_ms,
            updated_at_ms,
        )?;
        let CloudflareTenantRootRoleShareLifecycleV1::Pending(pending) = self.lifecycle else {
            return Err(store_error(
                "only a pending tenant-root role share can become active",
            ));
        };
        let active = CloudflareTenantRootActiveShareV1::from_pending(pending, activation)?;
        self.lifecycle = CloudflareTenantRootRoleShareLifecycleV1::Active(active);
        self.updated_at_ms = updated_at_ms;
        self.validate()?;
        Ok(self)
    }

    fn into_retired(
        mut self,
        retirement: CloudflareTenantRootRetirementV1,
        updated_at_ms: u64,
    ) -> worker::Result<Self> {
        require_lifecycle_progression(
            "tenant-root retirement",
            self.updated_at_ms,
            retirement.retired_at_ms,
            updated_at_ms,
        )?;
        let CloudflareTenantRootRoleShareLifecycleV1::Active(active) = self.lifecycle else {
            return Err(store_error(
                "only an active tenant-root role share can become retired",
            ));
        };
        let retired = CloudflareTenantRootRetiredShareV1::from_active(active, retirement)?;
        self.lifecycle = CloudflareTenantRootRoleShareLifecycleV1::Retired(retired);
        self.updated_at_ms = updated_at_ms;
        self.validate()?;
        Ok(self)
    }
}

/// One versioned record read from the primary role-private D1 session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudflareStoredTenantRootRoleShareV1 {
    record: CloudflareTenantRootRoleShareRecordV1,
    revision: i64,
}

impl CloudflareStoredTenantRootRoleShareV1 {
    /// Returns the validated encrypted-record plaintext.
    pub const fn record(&self) -> &CloudflareTenantRootRoleShareRecordV1 {
        &self.record
    }

    /// Returns the positive compare-and-set revision.
    pub const fn revision(&self) -> i64 {
        self.revision
    }

    /// Returns the validated public binding for this active role share.
    pub(crate) fn active_binding(&self) -> worker::Result<TenantRootActiveRoleBindingV1> {
        active_binding_from_stored(self)
    }

    /// Returns the exact activation receipt retained by an active row.
    pub(crate) fn active_activation_receipt_bytes(&self) -> worker::Result<&[u8]> {
        let CloudflareTenantRootRoleShareLifecycleV1::Active(active) = &self.record.lifecycle
        else {
            return Err(store_error(
                "tenant-root initial activation retry requires an active record",
            ));
        };
        Ok(active.activation.activation_receipt_bytes())
    }

    /// Reconstructs the exact pending revision consumed by initial activation.
    pub(crate) fn initial_activation_retry_pending(&self) -> worker::Result<Self> {
        self.record.validate()?;
        if self.record.epoch != TenantRootShareEpoch::INITIAL {
            return Err(store_error(
                "tenant-root initial activation retry requires epoch 1",
            ));
        }
        let CloudflareTenantRootRoleShareLifecycleV1::Active(active) = &self.record.lifecycle
        else {
            return Err(store_error(
                "tenant-root initial activation retry requires an active record",
            ));
        };
        let revision = self
            .revision
            .checked_sub(1)
            .filter(|revision| *revision > 0)
            .ok_or_else(|| {
                store_error("tenant-root initial activation retry has no prior pending revision")
            })?;
        let mut record = self.record.clone();
        record.lifecycle =
            CloudflareTenantRootRoleShareLifecycleV1::Pending(active.pending.clone());
        record.updated_at_ms = active.pending.staged_at_ms;
        record.validate()?;
        Ok(Self { record, revision })
    }

    /// Reconstructs the opaque provider artifact from one validated active D1 record.
    pub fn into_online_role_share_artifact(
        self,
    ) -> worker::Result<TenantRootSealedOnlineRoleShareV1> {
        validate_active_stored_record_shape(&self)?;
        self.record.into_online_role_share_artifact()
    }
}

/// Exhaustive role-private active-share resolution for one authenticated tenant.
#[derive(Debug)]
pub enum CloudflareTenantRootActiveRoleShareV1 {
    /// This role holds no active share for the authenticated tenant root.
    Unprovisioned,
    /// Exactly one active share exists.
    Active(Box<CloudflareStoredTenantRootRoleShareV1>),
    /// More than one active share exists; reconciliation may observe this.
    Ambiguous(TenantRootActiveRoleAmbiguityV1),
}

impl CloudflareTenantRootActiveRoleShareV1 {
    fn from_stored(stored: CloudflareStoredTenantRootRoleShareV1) -> worker::Result<Self> {
        active_binding_from_stored(&stored)?;
        Ok(Self::Active(Box::new(stored)))
    }

    /// Returns the one active share, or fails closed.
    ///
    /// Derivation and runtime callers use this; reconciliation matches the
    /// variants directly so it can observe ambiguity without deriving from it.
    pub fn require_active(self) -> worker::Result<CloudflareStoredTenantRootRoleShareV1> {
        match self {
            Self::Active(stored) => {
                validate_active_stored_record_shape(stored.as_ref())?;
                Ok(*stored)
            }
            Self::Unprovisioned => Err(store_error(
                "authenticated tenant root has no active role share",
            )),
            Self::Ambiguous(_) => Err(store_error(
                "authenticated tenant root resolves to more than one active role share",
            )),
        }
    }
}

impl CloudflareTenantRootActiveRoleShareV1 {
    /// Returns this role's public resolution, leaving every sealed value behind.
    ///
    /// Pair resolution consumes only this. A Deriver never receives its peer's
    /// opened record, so assembling a pair cannot move sealed share material
    /// across the role boundary.
    pub fn public_resolution(&self) -> worker::Result<TenantRootActiveRoleResolutionV1> {
        match self {
            Self::Unprovisioned => Ok(TenantRootActiveRoleResolutionV1::Unprovisioned),
            Self::Active(stored) => Ok(TenantRootActiveRoleResolutionV1::Active(
                active_binding_from_stored(stored.as_ref())?,
            )),
            Self::Ambiguous(ambiguity) => Ok(TenantRootActiveRoleResolutionV1::Ambiguous(
                ambiguity.clone(),
            )),
        }
    }
}

/// Observes one authenticated tenant's active Deriver A/B root pair.
///
/// Each role's private store answers for itself, so this is where the two
/// halves meet for reconciliation. This intentionally does not authorize
/// derivation; callers that need a usable pair must supply the authority-derived
/// custody binding through `cloudflare_resolve_active_tenant_root_pair_v1`.
pub fn cloudflare_observe_active_tenant_root_pair_v1(
    identity: &TenantRootIdentityV1,
    deriver_a: &CloudflareTenantRootActiveRoleShareV1,
    deriver_b: &CloudflareTenantRootActiveRoleShareV1,
) -> worker::Result<TenantRootActivePairResolutionV1> {
    let identity_digest = identity
        .digest()
        .map_err(|error| store_error(error.message()))?;
    let deriver_a = deriver_a.public_resolution()?;
    let deriver_b = deriver_b.public_resolution()?;
    resolve_active_tenant_root_pair_binding_v1(identity_digest, &deriver_a, &deriver_b)
        .map_err(|error| store_error(error.message()))
}

/// Resolves one active root pair against the authority-derived custody binding.
///
/// The custody binding supplies the authenticated identity, lineage, epoch,
/// commitments, root commitment, and activation receipt expected from both
/// private stores. An observed pair is never sufficient for derivation.
pub fn cloudflare_resolve_active_tenant_root_pair_v1(
    custody_binding: &TenantRootCustodyBindingV1,
    deriver_a: &CloudflareTenantRootActiveRoleShareV1,
    deriver_b: &CloudflareTenantRootActiveRoleShareV1,
) -> worker::Result<TenantRootActivePairResolutionV1> {
    let identity_digest = custody_binding.identity_digest();
    let deriver_a = deriver_a.public_resolution()?;
    let deriver_b = deriver_b.public_resolution()?;
    resolve_authoritative_active_tenant_root_pair_binding_v1(
        identity_digest,
        custody_binding,
        &deriver_a,
        &deriver_b,
    )
    .map_err(|error| store_error(error.message()))
}

/// Returns the one authority-matching active root pair, or fails closed.
///
/// Reconciliation calls `cloudflare_observe_active_tenant_root_pair_v1` instead
/// so it can observe an unsafe state without deriving from it.
pub fn cloudflare_require_active_tenant_root_pair_v1(
    custody_binding: &TenantRootCustodyBindingV1,
    deriver_a: &CloudflareTenantRootActiveRoleShareV1,
    deriver_b: &CloudflareTenantRootActiveRoleShareV1,
) -> worker::Result<TenantRootActiveRootPairV1> {
    let resolution =
        cloudflare_resolve_active_tenant_root_pair_v1(custody_binding, deriver_a, deriver_b)?;
    let pair = resolution
        .require_active()
        .map_err(|error| store_error(error.message()))?;
    Ok(pair.clone())
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct TenantRootRoleD1AadV1<'a> {
    environment: &'a str,
    worker_role: CloudflareTenantRootDeriverRoleV1,
    tenant_identity_digest_hex: &'a str,
    custody_lineage_b64u: &'a str,
    tenant_root_share_epoch: u64,
    record_role: CloudflareTenantRootDeriverRoleV1,
    lifecycle: &'a str,
    revision: i64,
    purpose: &'static str,
    schema: &'static str,
    record_key: &'a str,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TenantRootRoleD1CiphertextV1 {
    key_version: String,
    tenant_identity_digest_hex: String,
    custody_lineage_b64u: String,
    tenant_root_share_epoch: u64,
    role: CloudflareTenantRootDeriverRoleV1,
    lifecycle: String,
    ciphertext_b64u: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TenantRootRoleD1RecordWireV1 {
    identity: TenantRootIdentityV1,
    custody_lineage: TenantRootCustodyLineageId,
    epoch: TenantRootShareEpoch,
    role: CloudflareTenantRootDeriverRoleV1,
    sealed_share: CloudflareTenantRootSealedRoleShareV1,
    share_commitment: MpcPrfShareCommitmentWireV1,
    epoch_wrapping_key_ref: String,
    lifecycle: TenantRootRoleD1LifecycleWireV1,
    created_at_ms: u64,
    updated_at_ms: u64,
}

#[derive(Debug, Deserialize)]
#[serde(
    tag = "kind",
    content = "state",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum TenantRootRoleD1LifecycleWireV1 {
    Pending(TenantRootRoleD1PendingWireV1),
    Active(TenantRootRoleD1ActiveWireV1),
    Retired(TenantRootRoleD1RetiredWireV1),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TenantRootRoleD1PendingWireV1 {
    installation_evidence_digest: TenantRootLifecycleReceiptDigestV1,
    staged_at_ms: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TenantRootRoleD1ActiveWireV1 {
    pending: TenantRootRoleD1PendingWireV1,
    activation: TenantRootRoleD1ActivationWireV1,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TenantRootRoleD1RetiredWireV1 {
    active: TenantRootRoleD1ActiveWireV1,
    retirement: TenantRootRoleD1RetirementWireV1,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TenantRootRoleD1ActivationWireV1 {
    availability: TenantRootRoleD1AvailabilityWireV1,
    activation_receipt_b64u: String,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum TenantRootRoleD1AvailabilityWireV1 {
    CurrentRoleBackup {
        role_backup_receipt_digest: TenantRootLifecycleReceiptDigestV1,
        identity_digest: TenantRootIdentityDigestV1,
        custody_lineage: TenantRootCustodyLineageId,
        role: TenantRootManagedRestoreRoleV1,
        epoch: TenantRootShareEpoch,
        share_commitment: MpcPrfShareCommitmentWireV1,
    },
    AcceptedPermanentDerivationLoss {
        authorization_digest: [u8; 32],
        identity_digest: TenantRootIdentityDigestV1,
        custody_lineage: TenantRootCustodyLineageId,
        role: TenantRootManagedRestoreRoleV1,
        epoch: TenantRootShareEpoch,
        share_commitment: MpcPrfShareCommitmentWireV1,
    },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TenantRootRoleD1RetirementWireV1 {
    retirement_receipt_digest: TenantRootLifecycleReceiptDigestV1,
    retired_at_ms: u64,
}

impl TenantRootRoleD1RecordWireV1 {
    fn into_record(self) -> worker::Result<CloudflareTenantRootRoleShareRecordV1> {
        CloudflareTenantRootRoleShareRecordV1::new(CloudflareTenantRootRoleShareRecordInputV1 {
            identity: self.identity,
            custody_lineage: self.custody_lineage,
            epoch: self.epoch,
            role: self.role,
            sealed_share: self.sealed_share,
            share_commitment: self.share_commitment,
            epoch_wrapping_key_ref: self.epoch_wrapping_key_ref,
            lifecycle: self.lifecycle.into_lifecycle()?,
            created_at_ms: self.created_at_ms,
            updated_at_ms: self.updated_at_ms,
        })
    }
}

impl TenantRootRoleD1LifecycleWireV1 {
    fn into_lifecycle(self) -> worker::Result<CloudflareTenantRootRoleShareLifecycleV1> {
        match self {
            Self::Pending(pending) => Ok(CloudflareTenantRootRoleShareLifecycleV1::Pending(
                pending.into_pending()?,
            )),
            Self::Active(active) => Ok(CloudflareTenantRootRoleShareLifecycleV1::Active(
                active.into_active()?,
            )),
            Self::Retired(retired) => Ok(CloudflareTenantRootRoleShareLifecycleV1::Retired(
                retired.into_retired()?,
            )),
        }
    }
}

impl TenantRootRoleD1PendingWireV1 {
    fn into_pending(self) -> worker::Result<CloudflareTenantRootPendingShareV1> {
        CloudflareTenantRootPendingShareV1::from_stored_digest(
            self.installation_evidence_digest,
            self.staged_at_ms,
        )
    }
}

impl TenantRootRoleD1ActiveWireV1 {
    fn into_active(self) -> worker::Result<CloudflareTenantRootActiveShareV1> {
        CloudflareTenantRootActiveShareV1::from_pending(
            self.pending.into_pending()?,
            self.activation.into_activation()?,
        )
    }
}

impl TenantRootRoleD1RetiredWireV1 {
    fn into_retired(self) -> worker::Result<CloudflareTenantRootRetiredShareV1> {
        CloudflareTenantRootRetiredShareV1::from_active(
            self.active.into_active()?,
            self.retirement.into_retirement()?,
        )
    }
}

impl TenantRootRoleD1ActivationWireV1 {
    fn into_activation(self) -> worker::Result<CloudflareTenantRootActivationV1> {
        let receipt_bytes = decode_base64url_bytes_v1(
            "tenant-root activation receipt",
            &self.activation_receipt_b64u,
        )
        .map_err(|error| store_error(error.message()))?;
        if encode_base64url_bytes_v1(&receipt_bytes) != self.activation_receipt_b64u {
            return Err(store_error(
                "tenant-root activation receipt bytes are not canonical base64url",
            ));
        }
        let receipt = decode_activation_receipt_bytes(&receipt_bytes)?;
        CloudflareTenantRootActivationV1::from_stored_receipt_bytes(
            self.availability
                .into_availability(receipt.availability())?,
            receipt_bytes,
        )
    }
}

impl TenantRootRoleD1AvailabilityWireV1 {
    fn into_availability(
        self,
        receipt_availability: &TenantRootActivationReceiptAvailabilityV1,
    ) -> worker::Result<CloudflareTenantRootAvailabilityEvidenceV1> {
        Ok(match self {
            Self::CurrentRoleBackup {
                role_backup_receipt_digest,
                identity_digest,
                custody_lineage,
                role,
                epoch,
                share_commitment,
            } => {
                let TenantRootActivationReceiptAvailabilityV1::CurrentRoleBackups { receipts } =
                    receipt_availability
                else {
                    return Err(store_error(
                        "tenant-root current-backup availability does not match activation receipt",
                    ));
                };
                let receipt_digest = match role {
                    TenantRootManagedRestoreRoleV1::DeriverA => receipts.deriver_a(),
                    TenantRootManagedRestoreRoleV1::DeriverB => receipts.deriver_b(),
                };
                if receipt_digest != role_backup_receipt_digest {
                    return Err(store_error(
                        "tenant-root current-backup receipt digest does not match activation receipt",
                    ));
                }
                CloudflareTenantRootAvailabilityEvidenceV1::CurrentRoleBackup {
                    role_backup_receipt_digest,
                    identity_digest,
                    custody_lineage,
                    role,
                    epoch,
                    share_commitment,
                }
            }
            Self::AcceptedPermanentDerivationLoss {
                authorization_digest,
                identity_digest,
                custody_lineage,
                role,
                epoch,
                share_commitment,
            } => {
                let TenantRootActivationReceiptAvailabilityV1::AcceptedPermanentDerivationLoss {
                    authorization_digest: receipt_digest,
                    ..
                } = receipt_availability
                else {
                    return Err(store_error(
                        "tenant-root accepted-loss availability does not match activation receipt",
                    ));
                };
                if receipt_digest.as_bytes() != &authorization_digest {
                    return Err(store_error(
                        "tenant-root accepted-loss authorization digest does not match activation receipt",
                    ));
                }
                CloudflareTenantRootAvailabilityEvidenceV1::AcceptedPermanentDerivationLoss {
                    authorization_digest: *receipt_digest,
                    identity_digest,
                    custody_lineage,
                    role,
                    epoch,
                    share_commitment,
                }
            }
        })
    }
}

impl TenantRootRoleD1RetirementWireV1 {
    fn into_retirement(self) -> worker::Result<CloudflareTenantRootRetirementV1> {
        CloudflareTenantRootRetirementV1::new(self.retirement_receipt_digest, self.retired_at_ms)
    }
}

struct TenantRootRoleD1CipherV1 {
    environment: String,
    role: CloudflareTenantRootDeriverRoleV1,
    key_version: String,
    public_key: <CloudflareHpkeKemV1 as Kem>::PublicKey,
    private_key: <CloudflareHpkeKemV1 as Kem>::PrivateKey,
}

impl TenantRootRoleD1CipherV1 {
    fn from_env(env: &Env) -> worker::Result<Self> {
        let environment = required_env_var(env, ROLE_PRIVATE_D1_ENVIRONMENT_ENV)?;
        let role = CloudflareTenantRootDeriverRoleV1::parse(&required_env_var(
            env,
            ROLE_PRIVATE_D1_ROLE_ENV,
        )?)?;
        let key_version = required_env_var(env, ROLE_PRIVATE_D1_KEK_VERSION_ENV)?;
        let public_key = parse_cloudflare_hpke_x25519_public_key_v1(&required_env_var(
            env,
            ROLE_PRIVATE_D1_KEK_PUBLIC_KEY_ENV,
        )?)
        .map_err(|error| store_error(error.message()))?;
        let secret_binding = required_env_var(env, ROLE_PRIVATE_D1_KEK_BINDING_ENV)?;
        let secret = env.secret(&secret_binding).map_err(|error| {
            store_error(format!(
                "role-private D1 KEK Secret binding {secret_binding} is unavailable: {error}"
            ))
        })?;
        let mut encoded_private_key = secret.to_string();
        let mut private_key_bytes = decode_private_key(&encoded_private_key)?;
        encoded_private_key.zeroize();
        let private_key = CloudflareHpkeKemV1::sk_from_bytes(&private_key_bytes)
            .map_err(|error| store_error(format!("role-private D1 KEK is invalid: {error}")))?;
        private_key_bytes.zeroize();
        validate_role_private_d1_kek_key_pair(&public_key, &private_key)?;
        Ok(Self {
            environment,
            role,
            key_version,
            public_key,
            private_key,
        })
    }

    fn seal(
        &self,
        record: &CloudflareTenantRootRoleShareRecordV1,
        revision: i64,
    ) -> worker::Result<String> {
        if revision <= 0 {
            return Err(store_error(
                "tenant-root role-private row has an invalid revision",
            ));
        }
        record.validate()?;
        self.require_role(record.role)?;
        let metadata = record_metadata(record)?;
        let aad = self.aad(&metadata, revision)?;
        let plaintext = serde_json::to_vec(record).map_err(|error| {
            store_error(format!(
                "tenant-root role-private record encoding failed: {error}"
            ))
        })?;
        let mut rng = CloudflareHpkeGetrandomRngV1;
        let (encapped_key, ciphertext) = CloudflareHpkeSuiteV1::seal_base(
            &mut rng,
            &self.public_key,
            TENANT_ROOT_ROLE_D1_HPKE_INFO,
            &aad,
            &plaintext,
        )
        .map_err(|error| {
            store_error(format!(
                "tenant-root role-private D1 encryption failed: {error}"
            ))
        })?;
        let mut payload = Vec::with_capacity(encapped_key.as_ref().len() + ciphertext.len());
        payload.extend_from_slice(encapped_key.as_ref());
        payload.extend_from_slice(&ciphertext);
        serde_json::to_string(&TenantRootRoleD1CiphertextV1 {
            key_version: self.key_version.clone(),
            tenant_identity_digest_hex: metadata.identity_digest_hex,
            custody_lineage_b64u: metadata.custody_lineage_b64u,
            tenant_root_share_epoch: metadata.epoch,
            role: metadata.role,
            lifecycle: metadata.lifecycle,
            ciphertext_b64u: encode_base64url_bytes_v1(&payload),
        })
        .map_err(|error| {
            store_error(format!(
                "tenant-root role-private ciphertext encoding failed: {error}"
            ))
        })
    }

    fn open(
        &self,
        row: &TenantRootRoleD1RowV1,
    ) -> worker::Result<CloudflareTenantRootRoleShareRecordV1> {
        let envelope: TenantRootRoleD1CiphertextV1 = serde_json::from_str(&row.ciphertext_json)
            .map_err(|error| {
                store_error(format!(
                    "tenant-root role-private ciphertext decoding failed: {error}"
                ))
            })?;
        if envelope.key_version != self.key_version
            || envelope.tenant_identity_digest_hex != row.tenant_identity_digest_hex
            || envelope.custody_lineage_b64u != row.custody_lineage_b64u
            || epoch_i64_value(envelope.tenant_root_share_epoch)? != row.tenant_root_share_epoch
            || envelope.role.as_str() != row.role
            || envelope.lifecycle != row.lifecycle
        {
            return Err(store_error(
                "tenant-root role-private ciphertext metadata does not match its row",
            ));
        }
        self.require_role(envelope.role)?;
        let metadata = TenantRootRoleD1MetadataV1 {
            identity_digest_hex: envelope.tenant_identity_digest_hex,
            custody_lineage_b64u: envelope.custody_lineage_b64u,
            epoch: envelope.tenant_root_share_epoch,
            role: envelope.role,
            lifecycle: envelope.lifecycle,
        };
        let aad = self.aad(&metadata, row.revision)?;
        let payload = decode_base64url_bytes_v1(
            "tenant-root role-private ciphertext",
            &envelope.ciphertext_b64u,
        )
        .map_err(|error| store_error(error.message()))?;
        if encode_base64url_bytes_v1(&payload) != envelope.ciphertext_b64u
            || payload.len() <= CloudflareHpkeKemV1::ENCAPPED_KEY_LEN
        {
            return Err(store_error(
                "tenant-root role-private ciphertext is malformed",
            ));
        }
        let (encapped_key, ciphertext) = payload.split_at(CloudflareHpkeKemV1::ENCAPPED_KEY_LEN);
        let encapped_key = CloudflareHpkeKemV1::enc_from_bytes(encapped_key).map_err(|error| {
            store_error(format!(
                "tenant-root role-private encapsulated key is invalid: {error}"
            ))
        })?;
        let plaintext = CloudflareHpkeSuiteV1::open_base(
            &encapped_key,
            &self.private_key,
            TENANT_ROOT_ROLE_D1_HPKE_INFO,
            &aad,
            ciphertext,
        )
        .map_err(|error| {
            store_error(format!(
                "tenant-root role-private D1 decryption failed: {error}"
            ))
        })?;
        let record: CloudflareTenantRootRoleShareRecordV1 =
            serde_json::from_slice::<TenantRootRoleD1RecordWireV1>(&plaintext)
                .map_err(|error| {
                    store_error(format!(
                        "tenant-root role-private record decoding failed: {error}"
                    ))
                })?
                .into_record()?;
        record.validate()?;
        validate_record_activation_binding(&record)?;
        let actual = record_metadata(&record)?;
        if actual != metadata
            || timestamp_i64(record.created_at_ms)? != row.created_at_ms
            || timestamp_i64(record.updated_at_ms)? != row.updated_at_ms
        {
            return Err(store_error(
                "tenant-root role-private record does not match its authenticated row",
            ));
        }
        Ok(record)
    }

    fn aad(&self, metadata: &TenantRootRoleD1MetadataV1, revision: i64) -> worker::Result<Vec<u8>> {
        if revision <= 0 {
            return Err(store_error(
                "tenant-root role-private row has an invalid revision",
            ));
        }
        let record_key = metadata.record_key();
        serde_json::to_vec(&TenantRootRoleD1AadV1 {
            environment: &self.environment,
            worker_role: self.role,
            tenant_identity_digest_hex: &metadata.identity_digest_hex,
            custody_lineage_b64u: &metadata.custody_lineage_b64u,
            tenant_root_share_epoch: metadata.epoch,
            record_role: metadata.role,
            lifecycle: &metadata.lifecycle,
            revision,
            purpose: TENANT_ROOT_ROLE_D1_PURPOSE,
            schema: TENANT_ROOT_ROLE_D1_SCHEMA,
            record_key: &record_key,
        })
        .map_err(|error| {
            store_error(format!(
                "tenant-root role-private AAD encoding failed: {error}"
            ))
        })
    }

    fn require_role(&self, role: CloudflareTenantRootDeriverRoleV1) -> worker::Result<()> {
        if role != self.role {
            return Err(store_error(
                "tenant-root role-private record belongs to the other Deriver",
            ));
        }
        Ok(())
    }
}

fn validate_role_private_d1_kek_key_pair(
    public_key: &<CloudflareHpkeKemV1 as Kem>::PublicKey,
    private_key: &<CloudflareHpkeKemV1 as Kem>::PrivateKey,
) -> worker::Result<()> {
    let mut rng = CloudflareHpkeGetrandomRngV1;
    let (encapped_shared_secret, encapped_key) =
        match CloudflareHpkeKemV1::encap(&mut rng, public_key) {
            Ok(pair) => pair,
            Err(error) => {
                return Err(store_error(format!(
                    "role-private D1 KEK public key validation failed: {error}"
                )));
            }
        };
    let decapped_shared_secret =
        CloudflareHpkeKemV1::decap(&encapped_key, private_key).map_err(|error| {
            store_error(format!(
                "role-private D1 KEK private key validation failed: {error}"
            ))
        })?;
    if !constant_time_bytes_equal(
        encapped_shared_secret.as_ref(),
        decapped_shared_secret.as_ref(),
    ) {
        return Err(store_error(
            "role-private D1 KEK public key does not match private key",
        ));
    }
    Ok(())
}

fn constant_time_bytes_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0_u8;
    for (left, right) in left.iter().zip(right) {
        difference |= left ^ right;
    }
    difference == 0
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TenantRootRoleD1MetadataV1 {
    identity_digest_hex: String,
    custody_lineage_b64u: String,
    epoch: u64,
    role: CloudflareTenantRootDeriverRoleV1,
    lifecycle: String,
}

impl TenantRootRoleD1MetadataV1 {
    fn record_key(&self) -> String {
        format!(
            "{}/{}/{}/{}",
            self.identity_digest_hex,
            self.custody_lineage_b64u,
            self.epoch,
            self.role.as_str()
        )
    }
}

#[derive(Debug, Deserialize)]
struct TenantRootRoleD1RowV1 {
    tenant_identity_digest_hex: String,
    custody_lineage_b64u: String,
    tenant_root_share_epoch: i64,
    role: String,
    lifecycle: String,
    ciphertext_json: String,
    revision: i64,
    created_at_ms: i64,
    updated_at_ms: i64,
}

#[derive(Debug, Deserialize)]
struct TenantRootCommandReplayD1RowV1 {
    replay_key_digest_hex: String,
    tenant_identity_digest_hex: String,
    custody_lineage_b64u: String,
    session_id_hex: String,
    nonce_hex: String,
    role: String,
    command_digest_hex: String,
    admission_digest_hex: Option<String>,
    status: String,
    receipt_b64u: Option<String>,
    receipt_digest_hex: Option<String>,
    reserved_at_ms: i64,
    executed_at_ms: Option<i64>,
    terminal_at_ms: Option<i64>,
}

struct StoredTenantRootCommandReplayV1 {
    record: TenantRootCommandReplayRecordV1,
    admission_digest: Option<TenantRootProtocolDigestV1>,
    receipt_bytes: Option<Vec<u8>>,
    reserved_at_ms: u64,
    executed_at_ms: Option<u64>,
}

#[derive(Clone, Copy)]
enum TenantRootCommandAdmissionV1 {
    InitialCreation(TenantRootProtocolDigestV1),
    AuthorizedCleanup(TenantRootProtocolDigestV1),
}

impl TenantRootCommandAdmissionV1 {
    const fn digest(self) -> TenantRootProtocolDigestV1 {
        match self {
            Self::InitialCreation(digest) | Self::AuthorizedCleanup(digest) => digest,
        }
    }
}

/// Durable role-local decision for one exact tenant-root command retry.
#[derive(Debug, PartialEq, Eq)]
pub enum CloudflareTenantRootCommandReplayDecisionV1 {
    /// The caller owns the newly persisted reservation and may execute once.
    Execute {
        /// Exact reservation required to commit a terminal receipt.
        reservation: ReservedTenantRootCommandV1,
    },
    /// An identical command already owns this role-local session.
    InProgress,
    /// The reservation is durable and execution may be resumed.
    ResumeExecution {
        /// Exact token reconstructed from the validated reserved replay row.
        reservation: ReservedTenantRootCommandV1,
    },
    /// The lifecycle mutation is durably checkpointed and may be terminalized.
    ResumeCompletion {
        /// Exact token reconstructed from the validated executed replay row.
        executed: ExecutedTenantRootCommandV1,
    },
    /// Return the exact previously committed successful receipt bytes.
    ReplayCompleted {
        /// Previously committed signed public receipt bytes.
        receipt_bytes: Vec<u8>,
    },
    /// Return the exact previously committed failure receipt bytes.
    ReplayFailed {
        /// Previously committed signed public failure-receipt bytes.
        failure_receipt_bytes: Vec<u8>,
    },
}

/// Executable insert-pending command issued by the role's control plane.
///
/// Fields remain private so a caller cannot forge the reserved operation or
/// substitute a different local row after reservation.
#[derive(Debug, PartialEq, Eq)]
pub struct CloudflareTenantRootInsertPendingCommandV1 {
    scope: TenantRootCommandScopeV1,
    reservation: ReservedTenantRootCommandV1,
    record: CloudflareTenantRootRoleShareRecordV1,
    expected_revision: i64,
    operation_payload_digest: TenantRootProtocolDigestV1,
}

/// Local inputs for one issuer-authorized initial role creation.
///
/// The role store derives the pending lifecycle branch from the exact verified
/// installation-evidence wire. Callers provide only the server-resolved
/// identity and the locally sealed share material.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CloudflareTenantRootInitialCreationShareInputV1 {
    identity: TenantRootIdentityV1,
    sealed_online_share: TenantRootSealedOnlineRoleShareV1,
    staged_at_ms: u64,
}

#[allow(dead_code)]
impl CloudflareTenantRootInitialCreationShareInputV1 {
    /// Creates the local sealed-share inputs for one initial role installation.
    pub(crate) fn new(
        identity: TenantRootIdentityV1,
        sealed_online_share: TenantRootSealedOnlineRoleShareV1,
        staged_at_ms: u64,
    ) -> Self {
        Self {
            identity,
            sealed_online_share,
            staged_at_ms,
        }
    }
}

/// Creation-only input bundle coupling one verified issuer command to one exact
/// role-signed installation-evidence wire and its local sealed share material.
///
/// The bundle is intentionally non-cloneable. Its evidence token is carried
/// through reservation, execution, and successful terminalization so a caller
/// cannot substitute receipt payload bytes at a later lifecycle stage.
#[allow(dead_code)]
pub(crate) struct CloudflareTenantRootInitialCreationInputV1 {
    command: VerifiedTenantRootRoleCreationCommandV1,
    evidence: VerifiedTenantRootSignedShareInstallationEvidenceWireV1,
    record: CloudflareTenantRootRoleShareRecordV1,
}

#[allow(dead_code)]
impl fmt::Debug for CloudflareTenantRootInitialCreationInputV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CloudflareTenantRootInitialCreationInputV1")
            .field("command", &self.command)
            .field("evidence", &self.evidence)
            .field("record", &self.record)
            .finish()
    }
}

#[allow(dead_code)]
impl CloudflareTenantRootInitialCreationInputV1 {
    /// Returns the sealed share ciphertext, for leak tests only.
    #[cfg(test)]
    pub(crate) fn sealed_share_ciphertext_for_test(&self) -> Vec<u8> {
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(self.record.sealed_share().ciphertext_b64u())
            .expect("sealed share ciphertext is canonical base64url")
    }

    /// Returns the exact signed installation evidence wire bytes.
    ///
    /// Public evidence: it is what the Router-owned object verifies, and it
    /// carries no share material.
    pub(crate) fn installation_evidence_bytes(&self) -> &[u8] {
        self.evidence.canonical_bytes()
    }

    /// Builds one exact pending record from verified evidence and local share inputs.
    pub(crate) fn new(
        command: VerifiedTenantRootRoleCreationCommandV1,
        evidence: VerifiedTenantRootSignedShareInstallationEvidenceWireV1,
        share: CloudflareTenantRootInitialCreationShareInputV1,
    ) -> worker::Result<Self> {
        let sealed_binding = share.sealed_online_share.binding();
        let identity_digest = share
            .identity
            .digest()
            .map_err(|error| store_error(error.message()))?;
        let evidence_digest = evidence
            .lifecycle_receipt_digest()
            .map_err(|error| store_error(error.message()))?;
        if sealed_binding.identity_digest() != identity_digest {
            return Err(store_error(
                "tenant-root initial creation sealed share identity does not match its local identity",
            ));
        }
        if sealed_binding.installation_evidence_digest() != evidence_digest {
            return Err(store_error(
                "tenant-root initial creation sealed share evidence does not match its exact wire",
            ));
        }
        let role = cloudflare_role_for_protocol(sealed_binding.role())?;
        let installation_evidence =
            CloudflareTenantRootPendingShareV1::from_verified_installation_evidence(
                &evidence,
                share.staged_at_ms,
            )?;
        let sealed_share =
            CloudflareTenantRootSealedRoleShareV1::new(share.sealed_online_share.ciphertext())?;
        let record = CloudflareTenantRootRoleShareRecordV1::new(
            CloudflareTenantRootRoleShareRecordInputV1 {
                identity: share.identity,
                custody_lineage: sealed_binding.custody_lineage(),
                epoch: sealed_binding.epoch(),
                role,
                sealed_share,
                share_commitment: sealed_binding.share_commitment().clone(),
                epoch_wrapping_key_ref: sealed_binding.epoch_wrapping_key_ref().to_owned(),
                lifecycle: CloudflareTenantRootRoleShareLifecycleV1::Pending(installation_evidence),
                created_at_ms: share.staged_at_ms,
                updated_at_ms: share.staged_at_ms,
            },
        )?;
        validate_initial_creation_binding(&command, &evidence, &record)?;
        Ok(Self {
            command,
            evidence,
            record,
        })
    }
}

/// Executable initial-creation insertion command retaining its exact evidence token.
#[allow(dead_code)]
pub(crate) struct CloudflareTenantRootInitialCreationPendingCommandV1 {
    command: CloudflareTenantRootInsertPendingCommandV1,
    evidence: VerifiedTenantRootSignedShareInstallationEvidenceWireV1,
}

impl fmt::Debug for CloudflareTenantRootInitialCreationPendingCommandV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CloudflareTenantRootInitialCreationPendingCommandV1")
            .field("command", &self.command)
            .field("evidence", &self.evidence)
            .finish()
    }
}

/// Executed initial-creation command retaining the evidence needed for its
/// exact successful terminal receipt payload.
#[allow(dead_code)]
pub(crate) struct CloudflareTenantRootInitialCreationExecutedCommandV1 {
    executed: ExecutedTenantRootCommandV1,
    evidence: VerifiedTenantRootSignedShareInstallationEvidenceWireV1,
}

impl CloudflareTenantRootInitialCreationExecutedCommandV1 {
    /// Returns the executed command this insertion must be terminalized under.
    ///
    /// The caller signs its terminal receipt against this token and verifies
    /// the result with it, which is what binds the receipt to the exact
    /// insertion rather than to the role generally.
    pub(crate) const fn executed(&self) -> &ExecutedTenantRootCommandV1 {
        &self.executed
    }

    /// Returns the installation evidence this insertion attests.
    pub(crate) fn evidence_bytes(&self) -> &[u8] {
        self.evidence.canonical_bytes()
    }
}

impl fmt::Debug for CloudflareTenantRootInitialCreationExecutedCommandV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CloudflareTenantRootInitialCreationExecutedCommandV1")
            .field("executed", &self.executed)
            .field("evidence", &self.evidence)
            .finish()
    }
}

/// Local inputs for one issuer-authorized refresh role installation.
///
/// The sealed provider result retains the exact binding that authenticated the
/// refresh evidence, role, epoch, commitment, and wrapping-key reference.
#[allow(dead_code)]
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct CloudflareTenantRootRefreshShareInputV1 {
    /// Server-resolved logical root identity.
    identity: TenantRootIdentityV1,
    /// Provider ciphertext containing the newly sealed role share.
    sealed_online_share: TenantRootSealedOnlineRoleShareV1,
    /// Initial durable staging time for the pending row.
    staged_at_ms: u64,
}

#[allow(dead_code)]
impl CloudflareTenantRootRefreshShareInputV1 {
    /// Creates the local sealed-share inputs for one refresh installation.
    pub(crate) fn new(
        identity: TenantRootIdentityV1,
        sealed_online_share: TenantRootSealedOnlineRoleShareV1,
        staged_at_ms: u64,
    ) -> Self {
        Self {
            identity,
            sealed_online_share,
            staged_at_ms,
        }
    }
}

/// Refresh-only input bundle coupling one verified issuer command to one exact
/// role-signed installation-evidence wire and its local sealed share material.
///
/// The bundle is intentionally non-cloneable. Its evidence token is carried
/// through reservation, execution, and successful terminalization so receipt
/// payload bytes cannot be substituted after the provider call.
#[allow(dead_code)]
pub(crate) struct CloudflareTenantRootRefreshInputV1 {
    command: VerifiedTenantRootRoleRefreshCommandV1,
    evidence: VerifiedTenantRootSignedShareInstallationEvidenceWireV1,
    record: CloudflareTenantRootRoleShareRecordV1,
}

#[allow(dead_code)]
impl fmt::Debug for CloudflareTenantRootRefreshInputV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CloudflareTenantRootRefreshInputV1")
            .field("command", &self.command)
            .field("evidence", &self.evidence)
            .field("record", &self.record)
            .finish()
    }
}

#[allow(dead_code)]
impl CloudflareTenantRootRefreshInputV1 {
    /// Returns the exact signed installation evidence wire bytes.
    pub(crate) fn installation_evidence_bytes(&self) -> &[u8] {
        self.evidence.canonical_bytes()
    }

    /// Builds one exact pending record from verified refresh evidence and local
    /// provider-sealed share inputs.
    pub(crate) fn new(
        command: VerifiedTenantRootRoleRefreshCommandV1,
        evidence: VerifiedTenantRootSignedShareInstallationEvidenceWireV1,
        share: CloudflareTenantRootRefreshShareInputV1,
    ) -> worker::Result<Self> {
        let sealed_binding = share.sealed_online_share.binding();
        let evidence_digest = validate_refresh_command_evidence(&command, &evidence)?;
        let identity_digest = share
            .identity
            .digest()
            .map_err(|error| store_error(error.message()))?;
        validate_refresh_sealed_binding(
            &command,
            &evidence,
            sealed_binding,
            identity_digest,
            evidence_digest,
        )?;
        let role = cloudflare_role_for_protocol(sealed_binding.role())?;
        let pending = CloudflareTenantRootPendingShareV1::from_verified_installation_evidence(
            &evidence,
            share.staged_at_ms,
        )?;
        let sealed_share =
            CloudflareTenantRootSealedRoleShareV1::new(share.sealed_online_share.ciphertext())?;
        let record = CloudflareTenantRootRoleShareRecordV1::new(
            CloudflareTenantRootRoleShareRecordInputV1 {
                identity: share.identity,
                custody_lineage: sealed_binding.custody_lineage(),
                epoch: sealed_binding.epoch(),
                role,
                sealed_share,
                share_commitment: sealed_binding.share_commitment().clone(),
                epoch_wrapping_key_ref: sealed_binding.epoch_wrapping_key_ref().to_owned(),
                lifecycle: CloudflareTenantRootRoleShareLifecycleV1::Pending(pending),
                created_at_ms: share.staged_at_ms,
                updated_at_ms: share.staged_at_ms,
            },
        )?;
        validate_refresh_record_sealed_binding(&record, sealed_binding)?;
        validate_refresh_record_binding(&command, &evidence, &record)?;
        Ok(Self {
            command,
            evidence,
            record,
        })
    }
}

fn validate_refresh_record_sealed_binding(
    record: &CloudflareTenantRootRoleShareRecordV1,
    sealed_binding: &TenantRootOnlineRoleShareBindingV1,
) -> worker::Result<()> {
    let record_identity = record
        .identity
        .digest()
        .map_err(|error| store_error(error.message()))?;
    let record_role = cloudflare_role_for_protocol(sealed_binding.role())?;
    if record_identity != sealed_binding.identity_digest()
        || record.custody_lineage != sealed_binding.custody_lineage()
        || record.epoch != sealed_binding.epoch()
        || record.role != record_role
        || record.share_commitment != *sealed_binding.share_commitment()
        || record.epoch_wrapping_key_ref != sealed_binding.epoch_wrapping_key_ref()
    {
        return Err(store_error(
            "tenant-root refresh role-share record does not match its sealed binding",
        ));
    }
    Ok(())
}

/// Executable refresh pending-row insertion retaining its exact evidence token.
#[allow(dead_code)]
pub(crate) struct CloudflareTenantRootRefreshPendingCommandV1 {
    command: CloudflareTenantRootInsertPendingCommandV1,
    evidence: VerifiedTenantRootSignedShareInstallationEvidenceWireV1,
}

impl fmt::Debug for CloudflareTenantRootRefreshPendingCommandV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CloudflareTenantRootRefreshPendingCommandV1")
            .field("command", &self.command)
            .field("evidence", &self.evidence)
            .finish()
    }
}

/// Executed refresh insertion retaining the exact evidence needed to produce
/// its successful terminal receipt payload.
#[allow(dead_code)]
pub(crate) struct CloudflareTenantRootRefreshExecutedCommandV1 {
    executed: ExecutedTenantRootCommandV1,
    evidence: VerifiedTenantRootSignedShareInstallationEvidenceWireV1,
}

impl CloudflareTenantRootRefreshExecutedCommandV1 {
    /// Returns the executed command this insertion must be terminalized under.
    pub(crate) const fn executed(&self) -> &ExecutedTenantRootCommandV1 {
        &self.executed
    }

    /// Returns the installation evidence this insertion attests.
    pub(crate) fn evidence_bytes(&self) -> &[u8] {
        self.evidence.canonical_bytes()
    }
}

impl fmt::Debug for CloudflareTenantRootRefreshExecutedCommandV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CloudflareTenantRootRefreshExecutedCommandV1")
            .field("executed", &self.executed)
            .field("evidence", &self.evidence)
            .finish()
    }
}

/// Durable decision for one refresh-only pending-row reservation.
#[allow(dead_code)]
#[derive(Debug)]
pub(crate) enum CloudflareTenantRootRefreshDecisionV1 {
    /// The caller owns the newly reserved command and may execute it once.
    Execute {
        command: CloudflareTenantRootRefreshPendingCommandV1,
    },
    /// An identical command already owns this role-local session.
    InProgress,
    /// The reservation is durable and execution may be resumed.
    ResumeExecution {
        command: CloudflareTenantRootRefreshPendingCommandV1,
    },
    /// The lifecycle mutation is durably checkpointed and may be terminalized.
    ResumeCompletion {
        executed: CloudflareTenantRootRefreshExecutedCommandV1,
    },
    /// Return the exact prior successful receipt bytes.
    ReplayCompleted { receipt_bytes: Vec<u8> },
    /// Return the exact prior failure receipt bytes.
    ReplayFailed { failure_receipt_bytes: Vec<u8> },
}

/// Durable decision for one creation-only pending-row reservation.
#[allow(dead_code)]
#[derive(Debug)]
pub(crate) enum CloudflareTenantRootInitialCreationDecisionV1 {
    /// The caller owns the newly reserved command and may execute it once.
    Execute {
        command: CloudflareTenantRootInitialCreationPendingCommandV1,
    },
    /// An identical command already owns this role-local session.
    InProgress,
    /// The reservation is durable and execution may be resumed.
    ResumeExecution {
        command: CloudflareTenantRootInitialCreationPendingCommandV1,
    },
    /// The lifecycle mutation is durably checkpointed and may be terminalized.
    ResumeCompletion {
        executed: CloudflareTenantRootInitialCreationExecutedCommandV1,
    },
    /// Return the exact prior successful receipt bytes.
    ReplayCompleted { receipt_bytes: Vec<u8> },
    /// Return the exact prior failure receipt bytes.
    ReplayFailed { failure_receipt_bytes: Vec<u8> },
}

/// Read-only admission decision before a creation attempt draws a role share.
///
/// A completed retry returns its exact public receipt here. Reserved or
/// executed retries remain in progress because their random scalar cannot be
/// regenerated after the original request ends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CloudflareTenantRootInitialCreationPreflightV1 {
    Fresh,
    InProgress,
    ReplayCompleted { receipt_bytes: Vec<u8> },
    ReplayFailed { failure_receipt_bytes: Vec<u8> },
}

/// Result of one role-local initial-creation persistence attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CloudflareTenantRootInitialCreationPersistenceOutcomeV1 {
    /// This call persisted the successful terminal receipt.
    Committed { receipt_bytes: Vec<u8> },
    /// A reservation or execution checkpoint already owns this command.
    InProgress,
    /// An identical command already committed the exact successful receipt.
    ReplayCompleted { receipt_bytes: Vec<u8> },
    /// An identical command already committed the exact failure receipt.
    ReplayFailed { failure_receipt_bytes: Vec<u8> },
}

/// Result of persisting one refresh-only tenant-root share.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CloudflareTenantRootRefreshPersistenceOutcomeV1 {
    /// This call persisted the successful terminal receipt.
    Committed { receipt_bytes: Vec<u8> },
    /// A reservation or execution checkpoint already owns this command.
    InProgress,
    /// An identical command already committed the exact successful receipt.
    ReplayCompleted { receipt_bytes: Vec<u8> },
    /// An identical command already committed the exact failure receipt.
    ReplayFailed { failure_receipt_bytes: Vec<u8> },
}

/// Executable initial-activation command issued by the role's control plane.
#[derive(Debug, PartialEq, Eq)]
pub struct CloudflareTenantRootActivateInitialPendingCommandV1 {
    scope: TenantRootCommandScopeV1,
    reservation: ReservedTenantRootCommandV1,
    pending: CloudflareStoredTenantRootRoleShareV1,
    activation: CloudflareTenantRootActivationV1,
    updated_at_ms: u64,
    expected_revision: i64,
}

/// Executable active-epoch-swap command issued by the role's control plane.
#[derive(Debug, PartialEq, Eq)]
pub struct CloudflareTenantRootSwapActiveEpochCommandV1 {
    scope: TenantRootCommandScopeV1,
    reservation: ReservedTenantRootCommandV1,
    active: CloudflareStoredTenantRootRoleShareV1,
    pending: CloudflareStoredTenantRootRoleShareV1,
    activation: CloudflareTenantRootActivationV1,
    retirement: CloudflareTenantRootRetirementV1,
    updated_at_ms: u64,
    expected_active_revision: i64,
    expected_pending_revision: i64,
}

/// Executable pending-cleanup command issued by the role's control plane.
#[derive(Debug, PartialEq, Eq)]
pub struct CloudflareTenantRootCleanupPendingCommandV1 {
    scope: TenantRootCommandScopeV1,
    reservation: ReservedTenantRootCommandV1,
    pending: CloudflareStoredTenantRootRoleShareV1,
    expected_revision: i64,
    operation_payload_digest: TenantRootProtocolDigestV1,
}

pub(crate) struct CloudflareTenantRootAuthorizedCleanupPendingCommandV1 {
    command: CloudflareTenantRootCleanupPendingCommandV1,
    authorization: VerifiedTenantRootRoleCleanupCommandV1,
}

pub(crate) struct CloudflareTenantRootAuthorizedCleanupExecutedCommandV1 {
    executed: ExecutedTenantRootCommandV1,
    authorization: VerifiedTenantRootRoleCleanupCommandV1,
}

/// Durable decision for one insert-pending command reservation.
#[derive(Debug, PartialEq, Eq)]
pub enum CloudflareTenantRootInsertPendingDecisionV1 {
    /// The caller owns the newly reserved command and may execute it once.
    Execute {
        command: CloudflareTenantRootInsertPendingCommandV1,
    },
    /// An identical command already owns this role-local session.
    InProgress,
    /// The reservation is durable and execution may be resumed.
    ResumeExecution {
        /// Exact command rebuilt from the request payload and durable reservation.
        command: CloudflareTenantRootInsertPendingCommandV1,
    },
    /// The lifecycle mutation is durably checkpointed and may be terminalized.
    ResumeCompletion {
        /// Exact token reconstructed from the validated executed replay row.
        executed: ExecutedTenantRootCommandV1,
    },
    /// Return the exact prior successful receipt bytes.
    ReplayCompleted { receipt_bytes: Vec<u8> },
    /// Return the exact prior failure receipt bytes.
    ReplayFailed { failure_receipt_bytes: Vec<u8> },
}

/// Durable decision for one initial-activation command reservation.
#[derive(Debug, PartialEq, Eq)]
pub enum CloudflareTenantRootActivateInitialPendingDecisionV1 {
    /// The caller owns the newly reserved command and may execute it once.
    Execute {
        command: CloudflareTenantRootActivateInitialPendingCommandV1,
    },
    /// An identical command already owns this role-local session.
    InProgress,
    /// The reservation is durable and execution may be resumed.
    ResumeExecution {
        /// Exact command rebuilt from the request payload and durable reservation.
        command: CloudflareTenantRootActivateInitialPendingCommandV1,
    },
    /// The lifecycle mutation is durably checkpointed and may be terminalized.
    ResumeCompletion {
        /// Exact token reconstructed from the validated executed replay row.
        executed: ExecutedTenantRootCommandV1,
    },
    /// Return the exact prior successful receipt bytes.
    ReplayCompleted { receipt_bytes: Vec<u8> },
    /// Return the exact prior failure receipt bytes.
    ReplayFailed { failure_receipt_bytes: Vec<u8> },
}

/// Durable decision for one active-epoch-swap command reservation.
#[derive(Debug, PartialEq, Eq)]
pub enum CloudflareTenantRootSwapActiveEpochDecisionV1 {
    /// The caller owns the newly reserved command and may execute it once.
    Execute {
        command: CloudflareTenantRootSwapActiveEpochCommandV1,
    },
    /// An identical command already owns this role-local session.
    InProgress,
    /// The reservation is durable and execution may be resumed.
    ResumeExecution {
        /// Exact command rebuilt from the request payload and durable reservation.
        command: CloudflareTenantRootSwapActiveEpochCommandV1,
    },
    /// The lifecycle mutation is durably checkpointed and may be terminalized.
    ResumeCompletion {
        /// Exact token reconstructed from the validated executed replay row.
        executed: ExecutedTenantRootCommandV1,
    },
    /// Return the exact prior successful receipt bytes.
    ReplayCompleted { receipt_bytes: Vec<u8> },
    /// Return the exact prior failure receipt bytes.
    ReplayFailed { failure_receipt_bytes: Vec<u8> },
}

/// Durable decision for one pending-cleanup command reservation.
#[derive(Debug, PartialEq, Eq)]
pub enum CloudflareTenantRootCleanupPendingDecisionV1 {
    /// The caller owns the newly reserved command and may execute it once.
    Execute {
        command: CloudflareTenantRootCleanupPendingCommandV1,
    },
    /// An identical command already owns this role-local session.
    InProgress,
    /// The reservation is durable and execution may be resumed.
    ResumeExecution {
        /// Exact command rebuilt from the request payload and durable reservation.
        command: CloudflareTenantRootCleanupPendingCommandV1,
    },
    /// The lifecycle mutation is durably checkpointed and may be terminalized.
    ResumeCompletion {
        /// Exact token reconstructed from the validated executed replay row.
        executed: ExecutedTenantRootCommandV1,
    },
    /// Return the exact prior successful receipt bytes.
    ReplayCompleted { receipt_bytes: Vec<u8> },
    /// Return the exact prior failure receipt bytes.
    ReplayFailed { failure_receipt_bytes: Vec<u8> },
}

pub(crate) enum CloudflareTenantRootAuthorizedCleanupDecisionV1 {
    Execute {
        command: CloudflareTenantRootAuthorizedCleanupPendingCommandV1,
    },
    InProgress,
    ResumeExecution {
        command: CloudflareTenantRootAuthorizedCleanupPendingCommandV1,
    },
    ResumeCompletion {
        executed: CloudflareTenantRootAuthorizedCleanupExecutedCommandV1,
    },
    ReplayCompleted {
        receipt_bytes: Vec<u8>,
    },
    ReplayFailed {
        failure_receipt_bytes: Vec<u8>,
    },
}

/// Result of persisting one terminal tenant-root command receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CloudflareTenantRootCommandTerminalCommitV1 {
    /// This call committed the terminal receipt.
    Committed {
        /// Exact committed signed public receipt bytes.
        receipt_bytes: Vec<u8>,
    },
    /// Another identical call already committed these exact receipt bytes.
    Replay {
        /// Exact previously committed signed public receipt bytes.
        receipt_bytes: Vec<u8>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TenantRootCommandTerminalKindV1 {
    Completed,
    Failed,
}

enum TenantRootCommandTerminalInputV1 {
    Completed {
        executed: ExecutedTenantRootCommandV1,
        receipt: VerifiedTenantRootCommandSuccessReceiptV1,
    },
    Failed {
        reservation: ReservedTenantRootCommandV1,
        receipt: VerifiedTenantRootCommandFailureReceiptV1,
    },
}

struct TenantRootCommandTerminalCommitDataV1 {
    key: TenantRootCommandReplayKeyV1,
    command_digest: TenantRootProtocolDigestV1,
    reserved_at_ms: u64,
    executed_at_ms: Option<u64>,
    receipt_bytes: Vec<u8>,
    receipt_digest: TenantRootProtocolDigestV1,
    terminal_at_ms: u64,
    terminal_kind: TenantRootCommandTerminalKindV1,
}

struct DecodedTenantRootCommandTerminalReceiptV1 {
    receipt_bytes: Vec<u8>,
    receipt_digest: TenantRootProtocolDigestV1,
    terminal_at_ms: u64,
}

impl TenantRootCommandTerminalInputV1 {
    fn into_commit_data(self) -> worker::Result<TenantRootCommandTerminalCommitDataV1> {
        match self {
            Self::Completed { executed, receipt } => {
                if receipt.key() != executed.key()
                    || receipt.command_digest() != executed.command_digest()
                {
                    return Err(store_error(
                        "tenant-root successful receipt does not match its executed command",
                    ));
                }
                let key = *executed.key();
                let command_digest = executed.command_digest();
                let reserved_at_ms = executed.reserved_at_ms();
                let executed_at_ms = executed.executed_at_ms();
                let receipt_digest = receipt.digest();
                let terminal_at_ms = receipt.terminal_at_ms();
                executed
                    .complete(receipt_digest, terminal_at_ms)
                    .map_err(|error| store_error(error.message()))?;
                Ok(TenantRootCommandTerminalCommitDataV1 {
                    key,
                    command_digest,
                    reserved_at_ms,
                    executed_at_ms: Some(executed_at_ms),
                    receipt_bytes: receipt.into_canonical_bytes(),
                    receipt_digest,
                    terminal_at_ms,
                    terminal_kind: TenantRootCommandTerminalKindV1::Completed,
                })
            }
            Self::Failed {
                reservation,
                receipt,
            } => {
                if receipt.key() != reservation.key()
                    || receipt.command_digest() != reservation.command_digest()
                {
                    return Err(store_error(
                        "tenant-root failure receipt does not match its reserved command",
                    ));
                }
                let key = *reservation.key();
                let command_digest = reservation.command_digest();
                let reserved_at_ms = reservation.reserved_at_ms();
                let receipt_digest = receipt.digest();
                let terminal_at_ms = receipt.terminal_at_ms();
                reservation
                    .fail(receipt_digest, terminal_at_ms)
                    .map_err(|error| store_error(error.message()))?;
                Ok(TenantRootCommandTerminalCommitDataV1 {
                    key,
                    command_digest,
                    reserved_at_ms,
                    executed_at_ms: None,
                    receipt_bytes: receipt.into_canonical_bytes(),
                    receipt_digest,
                    terminal_at_ms,
                    terminal_kind: TenantRootCommandTerminalKindV1::Failed,
                })
            }
        }
    }
}

impl TenantRootCommandTerminalKindV1 {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Failed => "failed",
        }
    }

    const fn expected_status(self) -> &'static str {
        match self {
            Self::Completed => "executed",
            Self::Failed => "reserved",
        }
    }

    const fn expected_outcome(self) -> TenantRootCommandTerminalOutcomeV1 {
        match self {
            Self::Completed => TenantRootCommandTerminalOutcomeV1::Success,
            Self::Failed => TenantRootCommandTerminalOutcomeV1::Failure,
        }
    }
}

/// Primary-consistent access to one Deriver's encrypted tenant-root share rows.
pub struct CloudflareTenantRootRoleShareStoreV1 {
    session: D1DatabaseSession,
    cipher: TenantRootRoleD1CipherV1,
}

#[cfg(debug_assertions)]
pub const CLOUDFLARE_TENANT_ROOT_ROLE_D1_INTEGRATION_PATH: &str =
    "/router-ab/deriver/tenant-root-role-d1/integration";

#[cfg(debug_assertions)]
const TENANT_ROOT_ROLE_D1_INTEGRATION_ENV: &str = "ROUTER_AB_TENANT_ROOT_ROLE_D1_INTEGRATION";

/// Exact request accepted by the debug-only role-store workerd probe.
#[cfg(debug_assertions)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CloudflareTenantRootRoleD1IntegrationRequestV1 {
    /// Runs the complete pending-to-active-to-retired lifecycle through the Rust store.
    RunLifecycle,
    /// Runs the creation-specific reserve, insert, terminalize, and replay path.
    ///
    /// Exercises the creation wrappers the generic lifecycle probe never
    /// reaches, driving a real ceremony so the terminal receipt comes from the
    /// production sequence rather than fixture bytes.
    RunInitialCreation,
}

/// Receipt proving that the real Rust role-store adapter completed its lifecycle probe.
#[cfg(debug_assertions)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudflareTenantRootRoleD1IntegrationReceiptV1 {
    role: CloudflareTenantRootDeriverRoleV1,
    retired_epoch: u64,
    retired_revision: i64,
    active_epoch: u64,
    active_revision: i64,
    cleanup_epoch: u64,
    command_receipt_digest_hex: String,
}

/// Returns whether the explicit workerd-only integration binding is enabled.
#[cfg(debug_assertions)]
pub fn cloudflare_tenant_root_role_d1_integration_enabled_v1(env: &Env) -> bool {
    env.var(TENANT_ROOT_ROLE_D1_INTEGRATION_ENV)
        .map(|value| value.to_string() == "enabled")
        .unwrap_or(false)
}

/// Exercises the production Rust store against a real role-private D1 binding.
#[cfg(debug_assertions)]
pub async fn run_cloudflare_tenant_root_role_d1_integration_v1(
    env: &Env,
    request: CloudflareTenantRootRoleD1IntegrationRequestV1,
) -> worker::Result<CloudflareTenantRootRoleD1IntegrationReceiptV1> {
    match request {
        CloudflareTenantRootRoleD1IntegrationRequestV1::RunLifecycle => {
            run_cloudflare_tenant_root_role_d1_lifecycle_integration_v1(env).await
        }
        CloudflareTenantRootRoleD1IntegrationRequestV1::RunInitialCreation => {
            run_cloudflare_tenant_root_initial_creation_integration_v1(env).await
        }
    }
}

impl CloudflareTenantRootRoleShareStoreV1 {
    /// Resolves the private D1 binding and role-local record cipher per request.
    pub fn from_env(env: &Env) -> worker::Result<Self> {
        let database = env.d1(ROLE_PRIVATE_D1_BINDING).map_err(|error| {
            store_error(format!(
                "role-private D1 binding {ROLE_PRIVATE_D1_BINDING} is unavailable: {error}"
            ))
        })?;
        let session = database
            .with_session_constraint(D1SessionConstraint::FirstPrimary)
            .map_err(|error| {
                store_error(format!(
                    "tenant-root role-private primary session could not be created: {error}"
                ))
            })?;
        Ok(Self {
            session,
            cipher: TenantRootRoleD1CipherV1::from_env(env)?,
        })
    }

    /// Reserves one exact pending-row insertion command.
    async fn reserve_insert_pending(
        &self,
        scope: TenantRootCommandScopeV1,
        record: CloudflareTenantRootRoleShareRecordV1,
        reserved_at_ms: u64,
    ) -> worker::Result<CloudflareTenantRootInsertPendingDecisionV1> {
        let operation_payload_digest = insert_pending_payload_digest(&record, 1)?;
        self.reserve_insert_pending_with_payload_digest(
            scope,
            record,
            reserved_at_ms,
            operation_payload_digest,
            None,
        )
        .await
    }

    async fn reserve_insert_pending_with_payload_digest(
        &self,
        scope: TenantRootCommandScopeV1,
        record: CloudflareTenantRootRoleShareRecordV1,
        reserved_at_ms: u64,
        operation_payload_digest: TenantRootProtocolDigestV1,
        creation_admission_digest: Option<TenantRootProtocolDigestV1>,
    ) -> worker::Result<CloudflareTenantRootInsertPendingDecisionV1> {
        record.validate()?;
        self.cipher.require_role(record.role)?;
        if !matches!(
            record.lifecycle,
            CloudflareTenantRootRoleShareLifecycleV1::Pending(_)
        ) {
            return Err(store_error(
                "tenant-root role-private insertion requires a pending record",
            ));
        }
        let expected_revision = 1;
        validate_command_scope_for_record(
            &scope,
            &record,
            expected_revision,
            "tenant-root pending insertion",
        )?;
        let operation = TenantRootCommandOperationV1::insert_pending(operation_payload_digest);
        match self
            .reserve_scoped_command_with_admission_digest(
                scope,
                operation,
                reserved_at_ms,
                creation_admission_digest.map(TenantRootCommandAdmissionV1::InitialCreation),
            )
            .await?
        {
            CloudflareTenantRootCommandReplayDecisionV1::Execute { reservation } => {
                Ok(CloudflareTenantRootInsertPendingDecisionV1::Execute {
                    command: CloudflareTenantRootInsertPendingCommandV1 {
                        scope,
                        reservation,
                        record,
                        expected_revision,
                        operation_payload_digest,
                    },
                })
            }
            CloudflareTenantRootCommandReplayDecisionV1::InProgress => {
                Ok(CloudflareTenantRootInsertPendingDecisionV1::InProgress)
            }
            CloudflareTenantRootCommandReplayDecisionV1::ResumeExecution { reservation } => Ok(
                CloudflareTenantRootInsertPendingDecisionV1::ResumeExecution {
                    command: CloudflareTenantRootInsertPendingCommandV1 {
                        scope,
                        reservation,
                        record,
                        expected_revision,
                        operation_payload_digest,
                    },
                },
            ),
            CloudflareTenantRootCommandReplayDecisionV1::ResumeCompletion { executed } => {
                Ok(CloudflareTenantRootInsertPendingDecisionV1::ResumeCompletion { executed })
            }
            CloudflareTenantRootCommandReplayDecisionV1::ReplayCompleted { receipt_bytes } => {
                Ok(CloudflareTenantRootInsertPendingDecisionV1::ReplayCompleted { receipt_bytes })
            }
            CloudflareTenantRootCommandReplayDecisionV1::ReplayFailed {
                failure_receipt_bytes,
            } => Ok(CloudflareTenantRootInsertPendingDecisionV1::ReplayFailed {
                failure_receipt_bytes,
            }),
        }
    }

    /// Reserves one refresh-only pending-row insertion with exact evidence.
    ///
    /// Freshness is required only for the first durable reservation. Once the
    /// replay row exists, reconciliation may resume or replay it after expiry.
    #[allow(dead_code)]
    pub(crate) async fn reserve_refresh_pending(
        &self,
        refresh: CloudflareTenantRootRefreshInputV1,
        reserved_at_ms: u64,
    ) -> worker::Result<CloudflareTenantRootRefreshDecisionV1> {
        let CloudflareTenantRootRefreshInputV1 {
            command,
            evidence,
            record,
        } = refresh;
        validate_refresh_command_evidence(&command, &evidence)?;
        validate_refresh_record_binding(&command, &evidence, &record)?;
        let scope = command.scope();
        validate_command_scope_for_record(
            &scope,
            &record,
            1,
            "tenant-root refresh pending insertion",
        )?;
        let operation_payload_digest = refresh_insert_pending_payload_digest(&command, &record, 1)?;
        // Freshness applies only before the first durable reservation. An exact
        // retry must still reconcile after the issuer command has expired.
        if self.load_command_replay(scope.key()).await?.is_none() {
            command
                .require_fresh(reserved_at_ms)
                .map_err(|error| store_error(error.message()))?;
        }
        match self
            .reserve_insert_pending_with_payload_digest(
                scope,
                record,
                reserved_at_ms,
                operation_payload_digest,
                None,
            )
            .await?
        {
            CloudflareTenantRootInsertPendingDecisionV1::Execute { command } => {
                Ok(CloudflareTenantRootRefreshDecisionV1::Execute {
                    command: CloudflareTenantRootRefreshPendingCommandV1 { command, evidence },
                })
            }
            CloudflareTenantRootInsertPendingDecisionV1::InProgress => {
                Ok(CloudflareTenantRootRefreshDecisionV1::InProgress)
            }
            CloudflareTenantRootInsertPendingDecisionV1::ResumeExecution { command } => {
                Ok(CloudflareTenantRootRefreshDecisionV1::ResumeExecution {
                    command: CloudflareTenantRootRefreshPendingCommandV1 { command, evidence },
                })
            }
            CloudflareTenantRootInsertPendingDecisionV1::ResumeCompletion { executed } => {
                Ok(CloudflareTenantRootRefreshDecisionV1::ResumeCompletion {
                    executed: CloudflareTenantRootRefreshExecutedCommandV1 { executed, evidence },
                })
            }
            CloudflareTenantRootInsertPendingDecisionV1::ReplayCompleted { receipt_bytes } => {
                Ok(CloudflareTenantRootRefreshDecisionV1::ReplayCompleted { receipt_bytes })
            }
            CloudflareTenantRootInsertPendingDecisionV1::ReplayFailed {
                failure_receipt_bytes,
            } => Ok(CloudflareTenantRootRefreshDecisionV1::ReplayFailed {
                failure_receipt_bytes,
            }),
        }
    }

    /// Inserts one refresh-only pending row and retains evidence for
    /// successful terminalization.
    #[allow(dead_code)]
    pub(crate) async fn insert_refresh_pending(
        &self,
        command: CloudflareTenantRootRefreshPendingCommandV1,
        executed_at_ms: u64,
    ) -> worker::Result<(
        CloudflareStoredTenantRootRoleShareV1,
        CloudflareTenantRootRefreshExecutedCommandV1,
    )> {
        let CloudflareTenantRootRefreshPendingCommandV1 { command, evidence } = command;
        let (stored, executed) = self.insert_pending(command, executed_at_ms).await?;
        Ok((
            stored,
            CloudflareTenantRootRefreshExecutedCommandV1 { executed, evidence },
        ))
    }

    /// Persists one refresh-only tenant-root share through its complete
    /// reserve, execution-checkpoint, and successful terminal-receipt path.
    pub(crate) async fn persist_refresh(
        &self,
        refresh: CloudflareTenantRootRefreshInputV1,
        role_signer: &CloudflareTenantRootCreationRoleSignerV1,
        reserved_at_ms: u64,
        executed_at_ms: u64,
        terminal_at_ms: u64,
    ) -> worker::Result<CloudflareTenantRootRefreshPersistenceOutcomeV1> {
        validate_refresh_role_signer(&refresh, role_signer)?;
        let reservation = self
            .reserve_refresh_pending(refresh, reserved_at_ms)
            .await?;
        let executed = match reservation {
            CloudflareTenantRootRefreshDecisionV1::Execute { command }
            | CloudflareTenantRootRefreshDecisionV1::ResumeExecution { command } => {
                let (_, executed) = self.insert_refresh_pending(command, executed_at_ms).await?;
                executed
            }
            CloudflareTenantRootRefreshDecisionV1::ResumeCompletion { executed } => executed,
            CloudflareTenantRootRefreshDecisionV1::InProgress => {
                return Ok(CloudflareTenantRootRefreshPersistenceOutcomeV1::InProgress);
            }
            CloudflareTenantRootRefreshDecisionV1::ReplayCompleted { receipt_bytes } => {
                return Ok(
                    CloudflareTenantRootRefreshPersistenceOutcomeV1::ReplayCompleted {
                        receipt_bytes,
                    },
                );
            }
            CloudflareTenantRootRefreshDecisionV1::ReplayFailed {
                failure_receipt_bytes,
            } => {
                return Ok(
                    CloudflareTenantRootRefreshPersistenceOutcomeV1::ReplayFailed {
                        failure_receipt_bytes,
                    },
                );
            }
        };
        let receipt = role_signer
            .sign_verified_success_terminal_receipt(
                executed.executed(),
                executed.evidence_bytes(),
                terminal_at_ms,
            )
            .map_err(|error| store_error(error.message()))?;
        match self.complete_refresh(executed, receipt).await? {
            CloudflareTenantRootCommandTerminalCommitV1::Committed { receipt_bytes } => {
                Ok(CloudflareTenantRootRefreshPersistenceOutcomeV1::Committed { receipt_bytes })
            }
            CloudflareTenantRootCommandTerminalCommitV1::Replay { receipt_bytes } => Ok(
                CloudflareTenantRootRefreshPersistenceOutcomeV1::ReplayCompleted { receipt_bytes },
            ),
        }
    }

    /// Reserves initial creation with one exact verified evidence wire.
    ///
    /// The generic replay reservation remains below this creation-only boundary;
    /// this method is the only initial-creation entry point and carries evidence
    /// into every executable branch.
    pub(crate) async fn preflight_initial_creation(
        &self,
        command: &VerifiedTenantRootRoleCreationCommandV1,
        now_ms: u64,
    ) -> worker::Result<CloudflareTenantRootInitialCreationPreflightV1> {
        let scope = command.scope();
        self.require_command_role(scope.key())?;
        let Some(stored) = self.load_command_replay(scope.key()).await? else {
            command
                .require_fresh(now_ms)
                .map_err(|error| store_error(error.message()))?;
            return Ok(CloudflareTenantRootInitialCreationPreflightV1::Fresh);
        };
        match self.reconcile_initial_creation_retry(&stored, *scope.key(), command.digest())? {
            CloudflareTenantRootCommandReplayDecisionV1::InProgress
            | CloudflareTenantRootCommandReplayDecisionV1::ResumeExecution { .. }
            | CloudflareTenantRootCommandReplayDecisionV1::ResumeCompletion { .. } => {
                Ok(CloudflareTenantRootInitialCreationPreflightV1::InProgress)
            }
            CloudflareTenantRootCommandReplayDecisionV1::ReplayCompleted { receipt_bytes } => Ok(
                CloudflareTenantRootInitialCreationPreflightV1::ReplayCompleted { receipt_bytes },
            ),
            CloudflareTenantRootCommandReplayDecisionV1::ReplayFailed {
                failure_receipt_bytes,
            } => Ok(
                CloudflareTenantRootInitialCreationPreflightV1::ReplayFailed {
                    failure_receipt_bytes,
                },
            ),
            CloudflareTenantRootCommandReplayDecisionV1::Execute { .. } => Err(store_error(
                "durable initial creation replay returned a fresh execution",
            )),
        }
    }

    /// Persists one role's initial tenant-root share through its complete
    /// reserve, execution-checkpoint, and successful terminal-receipt path.
    pub(crate) async fn persist_initial_creation(
        &self,
        creation: CloudflareTenantRootInitialCreationInputV1,
        role_signer: &CloudflareTenantRootCreationRoleSignerV1,
        reserved_at_ms: u64,
        executed_at_ms: u64,
        terminal_at_ms: u64,
    ) -> worker::Result<CloudflareTenantRootInitialCreationPersistenceOutcomeV1> {
        validate_initial_creation_role_signer(&creation, role_signer)?;
        match self
            .preflight_initial_creation(&creation.command, reserved_at_ms)
            .await?
        {
            CloudflareTenantRootInitialCreationPreflightV1::Fresh => {}
            CloudflareTenantRootInitialCreationPreflightV1::InProgress => {
                return Ok(CloudflareTenantRootInitialCreationPersistenceOutcomeV1::InProgress);
            }
            CloudflareTenantRootInitialCreationPreflightV1::ReplayCompleted { receipt_bytes } => {
                return Ok(
                    CloudflareTenantRootInitialCreationPersistenceOutcomeV1::ReplayCompleted {
                        receipt_bytes,
                    },
                );
            }
            CloudflareTenantRootInitialCreationPreflightV1::ReplayFailed {
                failure_receipt_bytes,
            } => {
                return Ok(
                    CloudflareTenantRootInitialCreationPersistenceOutcomeV1::ReplayFailed {
                        failure_receipt_bytes,
                    },
                );
            }
        }

        let reservation = self
            .reserve_initial_creation_pending(creation, reserved_at_ms)
            .await?;
        let pending = match reservation {
            CloudflareTenantRootInitialCreationDecisionV1::Execute { command } => command,
            CloudflareTenantRootInitialCreationDecisionV1::InProgress
            | CloudflareTenantRootInitialCreationDecisionV1::ResumeExecution { .. }
            | CloudflareTenantRootInitialCreationDecisionV1::ResumeCompletion { .. } => {
                return Ok(CloudflareTenantRootInitialCreationPersistenceOutcomeV1::InProgress);
            }
            CloudflareTenantRootInitialCreationDecisionV1::ReplayCompleted { receipt_bytes } => {
                return Ok(
                    CloudflareTenantRootInitialCreationPersistenceOutcomeV1::ReplayCompleted {
                        receipt_bytes,
                    },
                );
            }
            CloudflareTenantRootInitialCreationDecisionV1::ReplayFailed {
                failure_receipt_bytes,
            } => {
                return Ok(
                    CloudflareTenantRootInitialCreationPersistenceOutcomeV1::ReplayFailed {
                        failure_receipt_bytes,
                    },
                );
            }
        };
        let (_, executed) = self
            .insert_initial_creation_pending(pending, executed_at_ms)
            .await?;
        let receipt = role_signer
            .sign_verified_success_terminal_receipt(
                executed.executed(),
                executed.evidence_bytes(),
                terminal_at_ms,
            )
            .map_err(|error| store_error(error.message()))?;
        match self.complete_initial_creation(executed, receipt).await? {
            CloudflareTenantRootCommandTerminalCommitV1::Committed { receipt_bytes } => Ok(
                CloudflareTenantRootInitialCreationPersistenceOutcomeV1::Committed {
                    receipt_bytes,
                },
            ),
            CloudflareTenantRootCommandTerminalCommitV1::Replay { receipt_bytes } => Ok(
                CloudflareTenantRootInitialCreationPersistenceOutcomeV1::ReplayCompleted {
                    receipt_bytes,
                },
            ),
        }
    }

    #[allow(dead_code)]
    pub(crate) async fn reserve_initial_creation_pending(
        &self,
        creation: CloudflareTenantRootInitialCreationInputV1,
        reserved_at_ms: u64,
    ) -> worker::Result<CloudflareTenantRootInitialCreationDecisionV1> {
        let CloudflareTenantRootInitialCreationInputV1 {
            command,
            evidence,
            record,
        } = creation;
        validate_initial_creation_binding(&command, &evidence, &record)?;
        let scope = initial_creation_scope_without_freshness(&command, &record)?;
        let creation_admission_digest = command.digest();
        // Freshness applies only before the first durable reservation. An exact
        // retry must still reconcile after the issuer command has expired.
        if self.load_command_replay(scope.key()).await?.is_none() {
            command
                .require_fresh(reserved_at_ms)
                .map_err(|error| store_error(error.message()))?;
        }
        let operation_payload_digest = insert_pending_payload_digest(&record, 1)?;
        match self
            .reserve_insert_pending_with_payload_digest(
                scope,
                record,
                reserved_at_ms,
                operation_payload_digest,
                Some(creation_admission_digest),
            )
            .await?
        {
            CloudflareTenantRootInsertPendingDecisionV1::Execute { command } => {
                Ok(CloudflareTenantRootInitialCreationDecisionV1::Execute {
                    command: CloudflareTenantRootInitialCreationPendingCommandV1 {
                        command,
                        evidence,
                    },
                })
            }
            CloudflareTenantRootInsertPendingDecisionV1::InProgress => {
                Ok(CloudflareTenantRootInitialCreationDecisionV1::InProgress)
            }
            CloudflareTenantRootInsertPendingDecisionV1::ResumeExecution { command } => Ok(
                CloudflareTenantRootInitialCreationDecisionV1::ResumeExecution {
                    command: CloudflareTenantRootInitialCreationPendingCommandV1 {
                        command,
                        evidence,
                    },
                },
            ),
            CloudflareTenantRootInsertPendingDecisionV1::ResumeCompletion { executed } => Ok(
                CloudflareTenantRootInitialCreationDecisionV1::ResumeCompletion {
                    executed: CloudflareTenantRootInitialCreationExecutedCommandV1 {
                        executed,
                        evidence,
                    },
                },
            ),
            CloudflareTenantRootInsertPendingDecisionV1::ReplayCompleted { receipt_bytes } => Ok(
                CloudflareTenantRootInitialCreationDecisionV1::ReplayCompleted { receipt_bytes },
            ),
            CloudflareTenantRootInsertPendingDecisionV1::ReplayFailed {
                failure_receipt_bytes,
            } => Ok(
                CloudflareTenantRootInitialCreationDecisionV1::ReplayFailed {
                    failure_receipt_bytes,
                },
            ),
        }
    }

    /// Inserts one creation-only pending row and retains evidence for terminalization.
    #[allow(dead_code)]
    pub(crate) async fn insert_initial_creation_pending(
        &self,
        command: CloudflareTenantRootInitialCreationPendingCommandV1,
        executed_at_ms: u64,
    ) -> worker::Result<(
        CloudflareStoredTenantRootRoleShareV1,
        CloudflareTenantRootInitialCreationExecutedCommandV1,
    )> {
        let CloudflareTenantRootInitialCreationPendingCommandV1 { command, evidence } = command;
        let (stored, executed) = self.insert_pending(command, executed_at_ms).await?;
        Ok((
            stored,
            CloudflareTenantRootInitialCreationExecutedCommandV1 { executed, evidence },
        ))
    }

    /// Inserts a verified pending epoch exactly once using its reserved command.
    async fn insert_pending(
        &self,
        command: CloudflareTenantRootInsertPendingCommandV1,
        executed_at_ms: u64,
    ) -> worker::Result<(
        CloudflareStoredTenantRootRoleShareV1,
        ExecutedTenantRootCommandV1,
    )> {
        let CloudflareTenantRootInsertPendingCommandV1 {
            scope,
            record,
            reservation,
            expected_revision,
            operation_payload_digest,
        } = command;
        record.validate()?;
        self.cipher.require_role(record.role)?;
        if !matches!(
            record.lifecycle,
            CloudflareTenantRootRoleShareLifecycleV1::Pending(_)
        ) {
            return Err(store_error(
                "tenant-root role-private insertion requires a pending record",
            ));
        }
        validate_command_scope_for_record(
            &scope,
            &record,
            expected_revision,
            "tenant-root pending insertion",
        )?;
        if expected_revision != 1 {
            return Err(store_error(
                "tenant-root pending insertion has an invalid initial revision",
            ));
        }
        let operation = TenantRootCommandOperationV1::insert_pending(operation_payload_digest);
        validate_reserved_command(
            &scope,
            &reservation,
            operation,
            "tenant-root pending insertion",
        )?;
        let metadata = record_metadata(&record)?;
        let ciphertext_json = self.cipher.seal(&record, expected_revision)?;
        let epoch = metadata.epoch.to_string();
        let created_at_ms = record.created_at_ms.to_string();
        let updated_at_ms = record.updated_at_ms.to_string();
        let lifecycle_statement = self.session.prepare(INSERT_SQL).bind_refs(
            [
                D1Type::Text(metadata.identity_digest_hex.as_str()),
                D1Type::Text(metadata.custody_lineage_b64u.as_str()),
                D1Type::Text(epoch.as_str()),
                D1Type::Text(metadata.role.as_str()),
                D1Type::Text(metadata.lifecycle.as_str()),
                D1Type::Text(ciphertext_json.as_str()),
                D1Type::Text(created_at_ms.as_str()),
                D1Type::Text(updated_at_ms.as_str()),
            ]
            .iter(),
        )?;
        let checkpoint_statement =
            self.command_execution_checkpoint_statement(&reservation, executed_at_ms)?;
        let executed = self
            .run_lifecycle_checkpoint(
                lifecycle_statement,
                1,
                checkpoint_statement,
                reservation,
                executed_at_ms,
            )
            .await?;
        Ok((
            CloudflareStoredTenantRootRoleShareV1 {
                record,
                revision: expected_revision,
            },
            executed,
        ))
    }

    /// Loads the one active role share authorized by the control-plane binding.
    ///
    /// The store's configured role supplies the role selector. Identity, lineage,
    /// epoch, commitment, and activation receipt all come from the authenticated
    /// custody binding; no caller can choose them independently.
    pub(crate) async fn load_active(
        &self,
        custody_binding: &TenantRootCustodyBindingV1,
    ) -> worker::Result<CloudflareStoredTenantRootRoleShareV1> {
        custody_binding
            .validate()
            .map_err(|error| store_error(error.message()))?;
        let active = self
            .load_active_resolution(custody_binding.identity_digest())
            .await?
            .require_active()?;
        let observed = active_binding_from_stored(&active)?;
        let expected_role = self.cipher.role.managed_restore_role();
        let expected_commitment = match expected_role {
            TenantRootManagedRestoreRoleV1::DeriverA => custody_binding.commitments().deriver_a(),
            TenantRootManagedRestoreRoleV1::DeriverB => custody_binding.commitments().deriver_b(),
        };
        if observed.identity_digest() != custody_binding.identity_digest()
            || observed.custody_lineage() != custody_binding.custody_lineage()
            || observed.epoch() != custody_binding.epoch()
            || observed.role() != expected_role
            || observed.share_commitment() != expected_commitment
            || observed.activation_receipt_digest() != custody_binding.activation_receipt_digest()
        {
            return Err(store_error(
                "tenant-root active role share does not match authenticated custody binding",
            ));
        }
        Ok(active)
    }

    /// Observes all active rows for the debug lifecycle probe.
    async fn observe_active(
        &self,
        identity: &TenantRootIdentityV1,
    ) -> worker::Result<CloudflareTenantRootActiveRoleShareV1> {
        let identity_digest = identity
            .digest()
            .map_err(|error| store_error(error.message()))?;
        self.load_active_resolution(identity_digest).await
    }

    async fn load_active_resolution(
        &self,
        identity_digest: TenantRootIdentityDigestV1,
    ) -> worker::Result<CloudflareTenantRootActiveRoleShareV1> {
        let identity_digest_hex = encode_hex(identity_digest.as_bytes());
        let rows = self
            .session
            .prepare(LOAD_ACTIVE_SQL)
            .bind_refs([D1Type::Text(identity_digest_hex.as_str())].iter())?
            .all()
            .await?
            .results::<TenantRootRoleD1RowV1>()?;
        let mut stored = Vec::with_capacity(rows.len());
        for row in rows {
            let opened = self
                .open_row(Some(row))?
                .ok_or_else(|| store_error("tenant-root role-private active row is missing"))?;
            stored.push(opened);
        }
        let mut observed = Vec::with_capacity(stored.len());
        for entry in &stored {
            observed.push(active_binding_from_stored(entry)?);
        }
        let resolution = resolve_active_tenant_root_role_binding_v1(
            identity_digest,
            self.cipher.role.managed_restore_role(),
            &observed,
        )
        .map_err(|error| store_error(error.message()))?;
        Ok(match resolution {
            TenantRootActiveRoleResolutionV1::Unprovisioned => {
                CloudflareTenantRootActiveRoleShareV1::Unprovisioned
            }
            TenantRootActiveRoleResolutionV1::Active(binding) => {
                let [stored] = stored
                    .try_into()
                    .map_err(|_| store_error("tenant-root active resolution lost its exact row"))?;
                let expected = active_binding_from_stored(&stored)?;
                if expected != binding {
                    return Err(store_error(
                        "tenant-root active resolution changed its stored commitment",
                    ));
                }
                CloudflareTenantRootActiveRoleShareV1::from_stored(stored)?
            }
            TenantRootActiveRoleResolutionV1::Ambiguous(ambiguity) => {
                CloudflareTenantRootActiveRoleShareV1::Ambiguous(ambiguity)
            }
        })
    }

    /// Loads one exact lineage and epoch for reconciliation or lifecycle work.
    pub async fn load_epoch(
        &self,
        identity: &TenantRootIdentityV1,
        custody_lineage: TenantRootCustodyLineageId,
        epoch: TenantRootShareEpoch,
    ) -> worker::Result<Option<CloudflareStoredTenantRootRoleShareV1>> {
        let identity_digest_hex = identity_digest_hex(identity)?;
        let custody_lineage_b64u = custody_lineage.to_base64url();
        let epoch = epoch_i64(epoch)?.to_string();
        let row = self
            .session
            .prepare(LOAD_EPOCH_SQL)
            .bind_refs(
                [
                    D1Type::Text(identity_digest_hex.as_str()),
                    D1Type::Text(custody_lineage_b64u.as_str()),
                    D1Type::Text(epoch.as_str()),
                    D1Type::Text(self.cipher.role.as_str()),
                ]
                .iter(),
            )?
            .first::<TenantRootRoleD1RowV1>(None)
            .await?;
        self.open_row(row)
    }

    pub(crate) async fn load_epoch_by_identity_digest(
        &self,
        identity_digest: TenantRootIdentityDigestV1,
        custody_lineage: TenantRootCustodyLineageId,
        epoch: TenantRootShareEpoch,
    ) -> worker::Result<Option<CloudflareStoredTenantRootRoleShareV1>> {
        let identity_digest_hex = encode_hex(identity_digest.as_bytes());
        let custody_lineage_b64u = custody_lineage.to_base64url();
        let epoch = epoch_i64(epoch)?.to_string();
        let row = self
            .session
            .prepare(LOAD_EPOCH_SQL)
            .bind_refs(
                [
                    D1Type::Text(identity_digest_hex.as_str()),
                    D1Type::Text(custody_lineage_b64u.as_str()),
                    D1Type::Text(epoch.as_str()),
                    D1Type::Text(self.cipher.role.as_str()),
                ]
                .iter(),
            )?
            .first::<TenantRootRoleD1RowV1>(None)
            .await?;
        self.open_row(row)
    }

    pub(crate) async fn load_initial_pending_for_activation(
        &self,
        identity_digest: TenantRootIdentityDigestV1,
        custody_lineage: TenantRootCustodyLineageId,
    ) -> worker::Result<CloudflareStoredTenantRootRoleShareV1> {
        let stored = self
            .load_epoch_by_identity_digest(
                identity_digest,
                custody_lineage,
                TenantRootShareEpoch::INITIAL,
            )
            .await?
            .ok_or_else(|| store_error("tenant-root initial pending role share does not exist"))?;
        if !matches!(
            stored.record.lifecycle(),
            CloudflareTenantRootRoleShareLifecycleV1::Pending(_)
                | CloudflareTenantRootRoleShareLifecycleV1::Active(_)
        ) {
            return Err(store_error(
                "tenant-root initial activation requires a pending or active role share",
            ));
        }
        Ok(stored)
    }

    /// Returns whether one exact activation command already has a
    /// durable replay row. Freshness is enforced only when this is false.
    pub(crate) async fn activation_replay_exists(
        &self,
        scope: &TenantRootCommandScopeV1,
    ) -> worker::Result<bool> {
        self.require_command_role(scope.key())?;
        Ok(self.load_command_replay(scope.key()).await?.is_some())
    }

    /// Reserves one exact initial-activation command.
    pub(crate) async fn reserve_activate_initial_pending(
        &self,
        scope: TenantRootCommandScopeV1,
        pending: CloudflareStoredTenantRootRoleShareV1,
        activation: CloudflareTenantRootActivationV1,
        updated_at_ms: u64,
        reserved_at_ms: u64,
    ) -> worker::Result<CloudflareTenantRootActivateInitialPendingDecisionV1> {
        validate_pending_stored_record(&self.cipher, &pending)?;
        if pending.record.epoch != TenantRootShareEpoch::INITIAL {
            return Err(store_error(
                "tenant-root initial activation requires epoch 1",
            ));
        }
        let expected_revision = pending.revision;
        validate_command_scope_for_record(
            &scope,
            &pending.record,
            expected_revision,
            "tenant-root initial activation",
        )?;
        pending
            .record
            .clone()
            .into_active(activation.clone(), updated_at_ms)?;
        let operation =
            TenantRootCommandOperationV1::activate_initial(activate_initial_payload_digest(
                &pending,
                &activation,
                updated_at_ms,
                expected_revision,
            )?);
        match self
            .reserve_scoped_command(scope, operation, reserved_at_ms)
            .await?
        {
            CloudflareTenantRootCommandReplayDecisionV1::Execute { reservation } => Ok(
                CloudflareTenantRootActivateInitialPendingDecisionV1::Execute {
                    command: CloudflareTenantRootActivateInitialPendingCommandV1 {
                        scope,
                        reservation,
                        pending,
                        activation,
                        updated_at_ms,
                        expected_revision,
                    },
                },
            ),
            CloudflareTenantRootCommandReplayDecisionV1::InProgress => {
                Ok(CloudflareTenantRootActivateInitialPendingDecisionV1::InProgress)
            }
            CloudflareTenantRootCommandReplayDecisionV1::ResumeExecution { reservation } => Ok(
                CloudflareTenantRootActivateInitialPendingDecisionV1::ResumeExecution {
                    command: CloudflareTenantRootActivateInitialPendingCommandV1 {
                        scope,
                        reservation,
                        pending,
                        activation,
                        updated_at_ms,
                        expected_revision,
                    },
                },
            ),
            CloudflareTenantRootCommandReplayDecisionV1::ResumeCompletion { executed } => Ok(
                CloudflareTenantRootActivateInitialPendingDecisionV1::ResumeCompletion { executed },
            ),
            CloudflareTenantRootCommandReplayDecisionV1::ReplayCompleted { receipt_bytes } => Ok(
                CloudflareTenantRootActivateInitialPendingDecisionV1::ReplayCompleted {
                    receipt_bytes,
                },
            ),
            CloudflareTenantRootCommandReplayDecisionV1::ReplayFailed {
                failure_receipt_bytes,
            } => Ok(
                CloudflareTenantRootActivateInitialPendingDecisionV1::ReplayFailed {
                    failure_receipt_bytes,
                },
            ),
        }
    }

    /// Reserves one exact active-epoch-swap command.
    pub(crate) async fn reserve_swap_active_epoch(
        &self,
        scope: TenantRootCommandScopeV1,
        active: CloudflareStoredTenantRootRoleShareV1,
        pending: CloudflareStoredTenantRootRoleShareV1,
        activation: CloudflareTenantRootActivationV1,
        retirement: CloudflareTenantRootRetirementV1,
        updated_at_ms: u64,
        reserved_at_ms: u64,
    ) -> worker::Result<CloudflareTenantRootSwapActiveEpochDecisionV1> {
        validate_active_stored_record(&self.cipher, &active)?;
        validate_pending_stored_record(&self.cipher, &pending)?;
        validate_epoch_swap_inputs(&active, &pending)?;
        validate_activation_receipt_against_swap_records(&activation, &active, &pending)?;
        let expected_active_revision = active.revision;
        let expected_pending_revision = pending.revision;
        validate_command_scope_for_record(
            &scope,
            &pending.record,
            expected_pending_revision,
            "tenant-root epoch swap",
        )?;
        active
            .record
            .clone()
            .into_retired(retirement.clone(), updated_at_ms)?;
        pending
            .record
            .clone()
            .into_active(activation.clone(), updated_at_ms)?;
        let operation =
            TenantRootCommandOperationV1::swap_active_epoch(swap_active_epoch_payload_digest(
                &active,
                &pending,
                &activation,
                &retirement,
                updated_at_ms,
                expected_active_revision,
                expected_pending_revision,
            )?);
        match self
            .reserve_scoped_command(scope, operation, reserved_at_ms)
            .await?
        {
            CloudflareTenantRootCommandReplayDecisionV1::Execute { reservation } => {
                Ok(CloudflareTenantRootSwapActiveEpochDecisionV1::Execute {
                    command: CloudflareTenantRootSwapActiveEpochCommandV1 {
                        scope,
                        reservation,
                        active,
                        pending,
                        activation,
                        retirement,
                        updated_at_ms,
                        expected_active_revision,
                        expected_pending_revision,
                    },
                })
            }
            CloudflareTenantRootCommandReplayDecisionV1::InProgress => {
                Ok(CloudflareTenantRootSwapActiveEpochDecisionV1::InProgress)
            }
            CloudflareTenantRootCommandReplayDecisionV1::ResumeExecution { reservation } => Ok(
                CloudflareTenantRootSwapActiveEpochDecisionV1::ResumeExecution {
                    command: CloudflareTenantRootSwapActiveEpochCommandV1 {
                        scope,
                        reservation,
                        active,
                        pending,
                        activation,
                        retirement,
                        updated_at_ms,
                        expected_active_revision,
                        expected_pending_revision,
                    },
                },
            ),
            CloudflareTenantRootCommandReplayDecisionV1::ResumeCompletion { executed } => {
                Ok(CloudflareTenantRootSwapActiveEpochDecisionV1::ResumeCompletion { executed })
            }
            CloudflareTenantRootCommandReplayDecisionV1::ReplayCompleted { receipt_bytes } => Ok(
                CloudflareTenantRootSwapActiveEpochDecisionV1::ReplayCompleted { receipt_bytes },
            ),
            CloudflareTenantRootCommandReplayDecisionV1::ReplayFailed {
                failure_receipt_bytes,
            } => Ok(
                CloudflareTenantRootSwapActiveEpochDecisionV1::ReplayFailed {
                    failure_receipt_bytes,
                },
            ),
        }
    }

    /// Reserves one exact pending-cleanup command.
    /// Reserves a cleanup that a control-plane authorization permits.
    ///
    /// This is the authorized path. The raw `reserve_cleanup_pending` below
    /// takes a caller-supplied scope and asks no one's permission, so it can
    /// only be reached from inside this store; every external cleanup must
    /// present a signed command naming the exact row.
    ///
    /// The scope is derived from the command's own nonce, not the ceremony's,
    /// so a cleanup is a distinct one-use command from the creation it undoes.
    /// A replayed creation command therefore cannot authorize deleting the
    /// share it created.
    pub(crate) async fn reserve_authorized_cleanup(
        &self,
        authorization: VerifiedTenantRootRoleCleanupCommandV1,
        reserved_at_ms: u64,
    ) -> worker::Result<CloudflareTenantRootAuthorizedCleanupDecisionV1> {
        let record_role = authorization.role();
        if record_role.as_str() != self.cipher.role.as_str() {
            return Err(store_error(
                "tenant-root cleanup authorization names another role",
            ));
        }
        let key = TenantRootCommandReplayKeyV1::new(
            authorization.identity_digest(),
            authorization.custody_lineage(),
            // The cleanup's own session coordinate is its nonce, which makes
            // its replay key disjoint from the creation command's.
            router_ab_core::TenantRootCeremonySessionIdV1::from_bytes(
                authorization.nonce().as_bytes()[..16]
                    .try_into()
                    .expect("sixteen nonce bytes"),
            )
            .map_err(|error| store_error(error.message()))?,
            authorization.nonce(),
            record_role,
        );
        let scope = TenantRootCommandScopeV1::new(
            key,
            authorization.epoch(),
            TENANT_ROOT_AUTHORIZED_CLEANUP_CONTROL_PLANE_REVISION_V1,
        )
        .map_err(|error| store_error(error.message()))?;
        let authorization_digest = authorization
            .digest()
            .map_err(|error| store_error(error.message()))?;
        let replay = self.load_command_replay(scope.key()).await?;
        if let Some(stored) = replay.as_ref() {
            match &stored.record {
                TenantRootCommandReplayRecordV1::Executed(_)
                | TenantRootCommandReplayRecordV1::Completed(_)
                | TenantRootCommandReplayRecordV1::Failed(_) => {
                    return match self.reconcile_authorized_cleanup_retry(
                        stored,
                        key,
                        authorization_digest,
                        None,
                    )? {
                        CloudflareTenantRootCommandReplayDecisionV1::ResumeCompletion {
                            executed,
                        } => Ok(
                            CloudflareTenantRootAuthorizedCleanupDecisionV1::ResumeCompletion {
                                executed: CloudflareTenantRootAuthorizedCleanupExecutedCommandV1 {
                                    executed,
                                    authorization,
                                },
                            },
                        ),
                        CloudflareTenantRootCommandReplayDecisionV1::ReplayCompleted {
                            receipt_bytes,
                        } => Ok(
                            CloudflareTenantRootAuthorizedCleanupDecisionV1::ReplayCompleted {
                                receipt_bytes,
                            },
                        ),
                        CloudflareTenantRootCommandReplayDecisionV1::ReplayFailed {
                            failure_receipt_bytes,
                        } => Ok(
                            CloudflareTenantRootAuthorizedCleanupDecisionV1::ReplayFailed {
                                failure_receipt_bytes,
                            },
                        ),
                        _ => Err(store_error(
                            "durable tenant-root cleanup replay returned an invalid decision",
                        )),
                    };
                }
                TenantRootCommandReplayRecordV1::Reserved(_) => {}
            }
        } else {
            authorization
                .require_fresh(reserved_at_ms)
                .map_err(|error| store_error(error.message()))?;
        }

        let pending = self
            .load_epoch_by_identity_digest(
                authorization.identity_digest(),
                authorization.custody_lineage(),
                authorization.epoch(),
            )
            .await?
            .ok_or_else(|| store_error("tenant-root cleanup pending row does not exist"))?;
        validate_authorized_cleanup_pending(&self.cipher, &authorization, &pending)?;
        let operation_payload_digest =
            authorized_cleanup_pending_payload_digest(&authorization, &pending, pending.revision)?;
        match self
            .reserve_cleanup_pending_with_payload_digest(
                scope,
                pending,
                reserved_at_ms,
                operation_payload_digest,
                Some(TenantRootCommandAdmissionV1::AuthorizedCleanup(
                    authorization_digest,
                )),
            )
            .await?
        {
            CloudflareTenantRootCleanupPendingDecisionV1::Execute { command } => {
                Ok(CloudflareTenantRootAuthorizedCleanupDecisionV1::Execute {
                    command: CloudflareTenantRootAuthorizedCleanupPendingCommandV1 {
                        command,
                        authorization,
                    },
                })
            }
            CloudflareTenantRootCleanupPendingDecisionV1::InProgress => {
                Ok(CloudflareTenantRootAuthorizedCleanupDecisionV1::InProgress)
            }
            CloudflareTenantRootCleanupPendingDecisionV1::ResumeExecution { command } => Ok(
                CloudflareTenantRootAuthorizedCleanupDecisionV1::ResumeExecution {
                    command: CloudflareTenantRootAuthorizedCleanupPendingCommandV1 {
                        command,
                        authorization,
                    },
                },
            ),
            CloudflareTenantRootCleanupPendingDecisionV1::ResumeCompletion { executed } => Ok(
                CloudflareTenantRootAuthorizedCleanupDecisionV1::ResumeCompletion {
                    executed: CloudflareTenantRootAuthorizedCleanupExecutedCommandV1 {
                        executed,
                        authorization,
                    },
                },
            ),
            CloudflareTenantRootCleanupPendingDecisionV1::ReplayCompleted { receipt_bytes } => Ok(
                CloudflareTenantRootAuthorizedCleanupDecisionV1::ReplayCompleted { receipt_bytes },
            ),
            CloudflareTenantRootCleanupPendingDecisionV1::ReplayFailed {
                failure_receipt_bytes,
            } => Ok(
                CloudflareTenantRootAuthorizedCleanupDecisionV1::ReplayFailed {
                    failure_receipt_bytes,
                },
            ),
        }
    }

    /// Executes one authorized cleanup and returns its exact terminal receipt bytes.
    pub(crate) async fn persist_authorized_cleanup(
        &self,
        authorization: VerifiedTenantRootRoleCleanupCommandV1,
        role_signer: &CloudflareTenantRootCreationRoleSignerV1,
        reserved_at_ms: u64,
        executed_at_ms: u64,
        terminal_at_ms: u64,
    ) -> worker::Result<Vec<u8>> {
        if role_signer.role() != authorization.role() {
            return Err(store_error(
                "tenant-root cleanup receipt signer does not match the authorized role",
            ));
        }
        let authorization_bytes = authorization
            .canonical_bytes()
            .map_err(|error| store_error(error.message()))?;
        let decision = self
            .reserve_authorized_cleanup(authorization, reserved_at_ms)
            .await?;
        let executed = match decision {
            CloudflareTenantRootAuthorizedCleanupDecisionV1::Execute { command }
            | CloudflareTenantRootAuthorizedCleanupDecisionV1::ResumeExecution { command } => {
                self.execute_authorized_cleanup(command, executed_at_ms)
                    .await?
            }
            CloudflareTenantRootAuthorizedCleanupDecisionV1::ResumeCompletion { executed } => {
                executed
            }
            CloudflareTenantRootAuthorizedCleanupDecisionV1::ReplayCompleted { receipt_bytes } => {
                return Ok(receipt_bytes);
            }
            CloudflareTenantRootAuthorizedCleanupDecisionV1::InProgress => {
                return Err(store_error(
                    "tenant-root authorized cleanup is already in progress",
                ));
            }
            CloudflareTenantRootAuthorizedCleanupDecisionV1::ReplayFailed { .. } => {
                return Err(store_error(
                    "tenant-root authorized cleanup previously failed",
                ));
            }
        };
        let receipt = role_signer
            .sign_verified_success_terminal_receipt(
                &executed.executed,
                &authorization_bytes,
                terminal_at_ms,
            )
            .map_err(|error| store_error(error.message()))?;
        match self.complete_authorized_cleanup(executed, receipt).await? {
            CloudflareTenantRootCommandTerminalCommitV1::Committed { receipt_bytes }
            | CloudflareTenantRootCommandTerminalCommitV1::Replay { receipt_bytes } => {
                Ok(receipt_bytes)
            }
        }
    }

    async fn reserve_cleanup_pending(
        &self,
        scope: TenantRootCommandScopeV1,
        pending: CloudflareStoredTenantRootRoleShareV1,
        reserved_at_ms: u64,
    ) -> worker::Result<CloudflareTenantRootCleanupPendingDecisionV1> {
        let operation_payload_digest = cleanup_pending_payload_digest(&pending, pending.revision)?;
        self.reserve_cleanup_pending_with_payload_digest(
            scope,
            pending,
            reserved_at_ms,
            operation_payload_digest,
            None,
        )
        .await
    }

    async fn reserve_cleanup_pending_with_payload_digest(
        &self,
        scope: TenantRootCommandScopeV1,
        pending: CloudflareStoredTenantRootRoleShareV1,
        reserved_at_ms: u64,
        operation_payload_digest: TenantRootProtocolDigestV1,
        admission: Option<TenantRootCommandAdmissionV1>,
    ) -> worker::Result<CloudflareTenantRootCleanupPendingDecisionV1> {
        validate_pending_stored_record(&self.cipher, &pending)?;
        let expected_revision = pending.revision;
        validate_command_scope_for_record(
            &scope,
            &pending.record,
            expected_revision,
            "tenant-root pending cleanup",
        )?;
        let operation = TenantRootCommandOperationV1::cleanup_pending(operation_payload_digest);
        match self
            .reserve_scoped_command_with_admission_digest(
                scope,
                operation,
                reserved_at_ms,
                admission,
            )
            .await?
        {
            CloudflareTenantRootCommandReplayDecisionV1::Execute { reservation } => {
                Ok(CloudflareTenantRootCleanupPendingDecisionV1::Execute {
                    command: CloudflareTenantRootCleanupPendingCommandV1 {
                        scope,
                        reservation,
                        pending,
                        expected_revision,
                        operation_payload_digest,
                    },
                })
            }
            CloudflareTenantRootCommandReplayDecisionV1::InProgress => {
                Ok(CloudflareTenantRootCleanupPendingDecisionV1::InProgress)
            }
            CloudflareTenantRootCommandReplayDecisionV1::ResumeExecution { reservation } => Ok(
                CloudflareTenantRootCleanupPendingDecisionV1::ResumeExecution {
                    command: CloudflareTenantRootCleanupPendingCommandV1 {
                        scope,
                        reservation,
                        pending,
                        expected_revision,
                        operation_payload_digest,
                    },
                },
            ),
            CloudflareTenantRootCommandReplayDecisionV1::ResumeCompletion { executed } => {
                Ok(CloudflareTenantRootCleanupPendingDecisionV1::ResumeCompletion { executed })
            }
            CloudflareTenantRootCommandReplayDecisionV1::ReplayCompleted { receipt_bytes } => {
                Ok(CloudflareTenantRootCleanupPendingDecisionV1::ReplayCompleted { receipt_bytes })
            }
            CloudflareTenantRootCommandReplayDecisionV1::ReplayFailed {
                failure_receipt_bytes,
            } => Ok(CloudflareTenantRootCleanupPendingDecisionV1::ReplayFailed {
                failure_receipt_bytes,
            }),
        }
    }

    async fn reserve_scoped_command(
        &self,
        scope: TenantRootCommandScopeV1,
        operation: TenantRootCommandOperationV1,
        reserved_at_ms: u64,
    ) -> worker::Result<CloudflareTenantRootCommandReplayDecisionV1> {
        self.reserve_scoped_command_with_admission_digest(scope, operation, reserved_at_ms, None)
            .await
    }

    async fn reserve_scoped_command_with_admission_digest(
        &self,
        scope: TenantRootCommandScopeV1,
        operation: TenantRootCommandOperationV1,
        reserved_at_ms: u64,
        admission: Option<TenantRootCommandAdmissionV1>,
    ) -> worker::Result<CloudflareTenantRootCommandReplayDecisionV1> {
        // Reservation commits before an executable command leaves this adapter.
        // Atomic reservation-plus-lifecycle mutation needs a D1 transaction path.
        let key = *scope.key();
        self.require_command_role(&key)?;
        let command_digest = scope
            .command_digest(operation)
            .map_err(|error| store_error(error.message()))?;
        let reservation =
            match reserve_tenant_root_command_v1(None, key, command_digest, reserved_at_ms)
                .map_err(|error| store_error(error.message()))?
            {
                TenantRootCommandReplayDecisionV1::Execute(reservation) => reservation,
                _ => {
                    return Err(store_error(
                        "fresh tenant-root command reservation returned an invalid decision",
                    ));
                }
            };
        let replay_key_digest_hex = encode_hex(
            key.storage_key_digest()
                .map_err(|error| store_error(error.message()))?
                .as_bytes(),
        );
        let identity_digest_hex = encode_hex(key.identity_digest().as_bytes());
        let custody_lineage_b64u = key.custody_lineage().to_base64url();
        let session_id_hex = encode_hex(key.session_id().as_bytes());
        let nonce_hex = encode_hex(key.nonce().as_bytes());
        let command_digest_hex = encode_hex(command_digest.as_bytes());
        let admission_digest_hex = admission.map(|value| encode_hex(value.digest().as_bytes()));
        let reserved_at_ms_text = timestamp_i64(reserved_at_ms)?.to_string();
        let admission_digest_value = admission_digest_hex
            .as_deref()
            .map_or(D1Type::Null, D1Type::Text);
        let result = self
            .session
            .prepare(INSERT_COMMAND_RESERVATION_SQL)
            .bind_refs(
                [
                    D1Type::Text(replay_key_digest_hex.as_str()),
                    D1Type::Text(identity_digest_hex.as_str()),
                    D1Type::Text(custody_lineage_b64u.as_str()),
                    D1Type::Text(session_id_hex.as_str()),
                    D1Type::Text(nonce_hex.as_str()),
                    D1Type::Text(self.cipher.role.as_str()),
                    D1Type::Text(command_digest_hex.as_str()),
                    admission_digest_value,
                    D1Type::Text(reserved_at_ms_text.as_str()),
                ]
                .iter(),
            )?
            .run()
            .await?;
        match result_changes(&result)? {
            1 => Ok(CloudflareTenantRootCommandReplayDecisionV1::Execute { reservation }),
            0 => {
                let stored = self
                    .load_command_replay(&key)
                    .await?
                    .ok_or_else(|| {
                        store_error(
                            "tenant-root command reservation conflict disappeared before reconciliation",
                        )
                    })?;
                match admission {
                    Some(TenantRootCommandAdmissionV1::InitialCreation(admission_digest)) => {
                        self.reconcile_initial_creation_retry(&stored, key, admission_digest)
                    }
                    Some(TenantRootCommandAdmissionV1::AuthorizedCleanup(admission_digest)) => self
                        .reconcile_authorized_cleanup_retry(
                            &stored,
                            key,
                            admission_digest,
                            Some(command_digest),
                        ),
                    None => self.reconcile_command_retry(&stored, key, command_digest),
                }
            }
            _ => Err(store_error(
                "tenant-root command reservation returned an invalid change count",
            )),
        }
    }

    /// Commits one exact successful signed public receipt for an executed command.
    async fn complete_command(
        &self,
        executed: ExecutedTenantRootCommandV1,
        receipt: VerifiedTenantRootCommandSuccessReceiptV1,
    ) -> worker::Result<CloudflareTenantRootCommandTerminalCommitV1> {
        self.commit_command_terminal(TenantRootCommandTerminalInputV1::Completed {
            executed,
            receipt,
        })
        .await
    }

    /// Commits the initial-creation receipt whose payload is the exact evidence wire.
    #[allow(dead_code)]
    pub(crate) async fn complete_initial_creation(
        &self,
        executed: CloudflareTenantRootInitialCreationExecutedCommandV1,
        receipt: VerifiedTenantRootCommandSuccessReceiptV1,
    ) -> worker::Result<CloudflareTenantRootCommandTerminalCommitV1> {
        let CloudflareTenantRootInitialCreationExecutedCommandV1 { executed, evidence } = executed;
        validate_initial_creation_success_receipt_payload(&evidence, &receipt)?;
        self.complete_command(executed, receipt).await
    }

    /// Commits an activation receipt whose payload is the exact issuer-signed
    /// activation receipt consumed by the lifecycle transition.
    pub(crate) async fn complete_activation(
        &self,
        executed: ExecutedTenantRootCommandV1,
        activation: &CloudflareTenantRootActivationV1,
        receipt: VerifiedTenantRootCommandSuccessReceiptV1,
    ) -> worker::Result<CloudflareTenantRootCommandTerminalCommitV1> {
        if receipt.payload_bytes() != activation.activation_receipt_bytes() {
            return Err(store_error(
                "tenant-root activation receipt payload does not match its exact activation receipt",
            ));
        }
        self.complete_command(executed, receipt).await
    }

    /// Commits the refresh receipt whose payload is the exact evidence wire.
    #[allow(dead_code)]
    pub(crate) async fn complete_refresh(
        &self,
        executed: CloudflareTenantRootRefreshExecutedCommandV1,
        receipt: VerifiedTenantRootCommandSuccessReceiptV1,
    ) -> worker::Result<CloudflareTenantRootCommandTerminalCommitV1> {
        let CloudflareTenantRootRefreshExecutedCommandV1 { executed, evidence } = executed;
        validate_refresh_success_receipt_payload(&evidence, &receipt)?;
        self.complete_command(executed, receipt).await
    }

    /// Commits one exact signed public failure receipt for a reserved command.
    async fn fail_command(
        &self,
        reservation: ReservedTenantRootCommandV1,
        receipt: VerifiedTenantRootCommandFailureReceiptV1,
    ) -> worker::Result<CloudflareTenantRootCommandTerminalCommitV1> {
        self.commit_command_terminal(TenantRootCommandTerminalInputV1::Failed {
            reservation,
            receipt,
        })
        .await
    }

    /// Activates epoch 1 only when this role has no active epoch for the root.
    pub(crate) async fn activate_initial_pending(
        &self,
        command: CloudflareTenantRootActivateInitialPendingCommandV1,
        executed_at_ms: u64,
    ) -> worker::Result<(
        CloudflareStoredTenantRootRoleShareV1,
        ExecutedTenantRootCommandV1,
    )> {
        let CloudflareTenantRootActivateInitialPendingCommandV1 {
            scope,
            pending,
            reservation,
            activation,
            updated_at_ms,
            expected_revision,
        } = command;
        validate_pending_stored_record(&self.cipher, &pending)?;
        if pending.record.epoch != TenantRootShareEpoch::INITIAL {
            return Err(store_error(
                "tenant-root initial activation requires epoch 1",
            ));
        }
        if expected_revision != pending.revision {
            return Err(store_error(
                "tenant-root initial activation command revision changed",
            ));
        }
        validate_command_scope_for_record(
            &scope,
            &pending.record,
            expected_revision,
            "tenant-root initial activation",
        )?;
        let operation =
            TenantRootCommandOperationV1::activate_initial(activate_initial_payload_digest(
                &pending,
                &activation,
                updated_at_ms,
                expected_revision,
            )?);
        validate_reserved_command(
            &scope,
            &reservation,
            operation,
            "tenant-root initial activation",
        )?;
        let revision = next_revision(expected_revision)?;
        let record = pending.record.into_active(activation, updated_at_ms)?;
        let metadata = record_metadata(&record)?;
        let ciphertext_json = self.cipher.seal(&record, revision)?;
        let epoch = metadata.epoch.to_string();
        let updated_at_ms = record.updated_at_ms.to_string();
        let expected_revision_text = expected_revision.to_string();
        let lifecycle_statement = self
            .session
            .prepare(ACTIVATE_INITIAL_PENDING_SQL)
            .bind_refs(
                [
                    D1Type::Text(ciphertext_json.as_str()),
                    D1Type::Text(updated_at_ms.as_str()),
                    D1Type::Text(metadata.identity_digest_hex.as_str()),
                    D1Type::Text(metadata.custody_lineage_b64u.as_str()),
                    D1Type::Text(epoch.as_str()),
                    D1Type::Text(metadata.role.as_str()),
                    D1Type::Text(expected_revision_text.as_str()),
                ]
                .iter(),
            )?;
        let checkpoint_statement =
            self.command_execution_checkpoint_statement(&reservation, executed_at_ms)?;
        let executed = self
            .run_lifecycle_checkpoint(
                lifecycle_statement,
                1,
                checkpoint_statement,
                reservation,
                executed_at_ms,
            )
            .await?;
        Ok((
            CloudflareStoredTenantRootRoleShareV1 { record, revision },
            executed,
        ))
    }

    /// Atomically retires one active epoch and activates its exact next pending epoch.
    ///
    /// The returned pair contains the retired row first and the newly active row second.
    pub(crate) async fn swap_active_epoch(
        &self,
        command: CloudflareTenantRootSwapActiveEpochCommandV1,
        executed_at_ms: u64,
    ) -> worker::Result<(
        (
            CloudflareStoredTenantRootRoleShareV1,
            CloudflareStoredTenantRootRoleShareV1,
        ),
        ExecutedTenantRootCommandV1,
    )> {
        let CloudflareTenantRootSwapActiveEpochCommandV1 {
            scope,
            reservation,
            active,
            pending,
            activation,
            retirement,
            updated_at_ms,
            expected_active_revision,
            expected_pending_revision,
        } = command;
        validate_active_stored_record(&self.cipher, &active)?;
        validate_pending_stored_record(&self.cipher, &pending)?;
        validate_epoch_swap_inputs(&active, &pending)?;
        validate_activation_receipt_against_swap_records(&activation, &active, &pending)?;
        if expected_active_revision != active.revision
            || expected_pending_revision != pending.revision
        {
            return Err(store_error(
                "tenant-root epoch-swap command revision changed",
            ));
        }
        validate_command_scope_for_record(
            &scope,
            &pending.record,
            expected_pending_revision,
            "tenant-root epoch swap",
        )?;
        let operation =
            TenantRootCommandOperationV1::swap_active_epoch(swap_active_epoch_payload_digest(
                &active,
                &pending,
                &activation,
                &retirement,
                updated_at_ms,
                expected_active_revision,
                expected_pending_revision,
            )?);
        validate_reserved_command(&scope, &reservation, operation, "tenant-root epoch swap")?;
        let retired_revision = next_revision(expected_active_revision)?;
        let activated_revision = next_revision(expected_pending_revision)?;
        let retired_record = active.record.into_retired(retirement, updated_at_ms)?;
        let activated_record = pending.record.into_active(activation, updated_at_ms)?;
        let retired_metadata = record_metadata(&retired_record)?;
        let activated_metadata = record_metadata(&activated_record)?;
        if retired_metadata.identity_digest_hex != activated_metadata.identity_digest_hex
            || retired_metadata.custody_lineage_b64u != activated_metadata.custody_lineage_b64u
            || retired_metadata.role != activated_metadata.role
        {
            return Err(store_error(
                "tenant-root epoch swap metadata changed during transition",
            ));
        }
        let current_epoch = retired_metadata.epoch.to_string();
        let next_epoch = activated_metadata.epoch.to_string();
        let current_revision = active.revision.to_string();
        let next_revision = pending.revision.to_string();
        let updated_at_ms = timestamp_i64(updated_at_ms)?.to_string();
        let retired_ciphertext_json = self.cipher.seal(&retired_record, retired_revision)?;
        let activated_ciphertext_json = self.cipher.seal(&activated_record, activated_revision)?;
        // The WHERE clause requires both CAS rows before this single UPDATE can match either.
        let lifecycle_statement = self.session.prepare(SWAP_ACTIVE_EPOCH_SQL).bind_refs(
            [
                D1Type::Text(retired_metadata.identity_digest_hex.as_str()),
                D1Type::Text(retired_metadata.custody_lineage_b64u.as_str()),
                D1Type::Text(current_epoch.as_str()),
                D1Type::Text(retired_metadata.role.as_str()),
                D1Type::Text(current_revision.as_str()),
                D1Type::Text(next_epoch.as_str()),
                D1Type::Text(next_revision.as_str()),
                D1Type::Text(retired_ciphertext_json.as_str()),
                D1Type::Text(activated_ciphertext_json.as_str()),
                D1Type::Text(updated_at_ms.as_str()),
            ]
            .iter(),
        )?;
        let checkpoint_statement =
            self.command_execution_checkpoint_statement(&reservation, executed_at_ms)?;
        let executed = self
            .run_lifecycle_checkpoint(
                lifecycle_statement,
                2,
                checkpoint_statement,
                reservation,
                executed_at_ms,
            )
            .await?;
        Ok((
            (
                CloudflareStoredTenantRootRoleShareV1 {
                    record: retired_record,
                    revision: retired_revision,
                },
                CloudflareStoredTenantRootRoleShareV1 {
                    record: activated_record,
                    revision: activated_revision,
                },
            ),
            executed,
        ))
    }

    /// Removes one exact pending revision after a failed pre-activation attempt.
    pub(crate) async fn cleanup_pending(
        &self,
        command: CloudflareTenantRootCleanupPendingCommandV1,
        executed_at_ms: u64,
    ) -> worker::Result<ExecutedTenantRootCommandV1> {
        let CloudflareTenantRootCleanupPendingCommandV1 {
            scope,
            reservation,
            pending,
            expected_revision,
            operation_payload_digest,
        } = command;
        validate_pending_stored_record(&self.cipher, &pending)?;
        if expected_revision != pending.revision {
            return Err(store_error(
                "tenant-root pending-cleanup command revision changed",
            ));
        }
        validate_command_scope_for_record(
            &scope,
            &pending.record,
            expected_revision,
            "tenant-root pending cleanup",
        )?;
        let operation = TenantRootCommandOperationV1::cleanup_pending(operation_payload_digest);
        validate_reserved_command(
            &scope,
            &reservation,
            operation,
            "tenant-root pending cleanup",
        )?;
        let metadata = record_metadata(&pending.record)?;
        let epoch = metadata.epoch.to_string();
        let revision = expected_revision.to_string();
        let lifecycle_statement = self.session.prepare(CLEANUP_PENDING_SQL).bind_refs(
            [
                D1Type::Text(metadata.identity_digest_hex.as_str()),
                D1Type::Text(metadata.custody_lineage_b64u.as_str()),
                D1Type::Text(epoch.as_str()),
                D1Type::Text(metadata.role.as_str()),
                D1Type::Text(revision.as_str()),
            ]
            .iter(),
        )?;
        let checkpoint_statement =
            self.command_execution_checkpoint_statement(&reservation, executed_at_ms)?;
        self.run_lifecycle_checkpoint(
            lifecycle_statement,
            1,
            checkpoint_statement,
            reservation,
            executed_at_ms,
        )
        .await
    }

    pub(crate) async fn execute_authorized_cleanup(
        &self,
        command: CloudflareTenantRootAuthorizedCleanupPendingCommandV1,
        executed_at_ms: u64,
    ) -> worker::Result<CloudflareTenantRootAuthorizedCleanupExecutedCommandV1> {
        let CloudflareTenantRootAuthorizedCleanupPendingCommandV1 {
            command,
            authorization,
        } = command;
        let executed = self.cleanup_pending(command, executed_at_ms).await?;
        Ok(CloudflareTenantRootAuthorizedCleanupExecutedCommandV1 {
            executed,
            authorization,
        })
    }

    pub(crate) async fn complete_authorized_cleanup(
        &self,
        executed: CloudflareTenantRootAuthorizedCleanupExecutedCommandV1,
        receipt: VerifiedTenantRootCommandSuccessReceiptV1,
    ) -> worker::Result<CloudflareTenantRootCommandTerminalCommitV1> {
        let CloudflareTenantRootAuthorizedCleanupExecutedCommandV1 {
            executed,
            authorization,
        } = executed;
        let authorization_bytes = authorization
            .canonical_bytes()
            .map_err(|error| store_error(error.message()))?;
        if receipt.payload_bytes() != authorization_bytes {
            return Err(store_error(
                "tenant-root cleanup receipt payload does not match its exact authorization",
            ));
        }
        self.complete_command(executed, receipt).await
    }

    fn command_execution_checkpoint_statement(
        &self,
        reservation: &ReservedTenantRootCommandV1,
        executed_at_ms: u64,
    ) -> worker::Result<worker::D1PreparedStatement> {
        self.require_command_role(reservation.key())?;
        let key = reservation.key();
        let replay_key_digest_hex = encode_hex(
            key.storage_key_digest()
                .map_err(|error| store_error(error.message()))?
                .as_bytes(),
        );
        let identity_digest_hex = encode_hex(key.identity_digest().as_bytes());
        let custody_lineage_b64u = key.custody_lineage().to_base64url();
        let session_id_hex = encode_hex(key.session_id().as_bytes());
        let nonce_hex = encode_hex(key.nonce().as_bytes());
        let command_digest_hex = encode_hex(reservation.command_digest().as_bytes());
        let reserved_at_ms = timestamp_i64(reservation.reserved_at_ms())?.to_string();
        let executed_at_ms = timestamp_i64(executed_at_ms)?.to_string();
        self.session.prepare(MARK_COMMAND_EXECUTED_SQL).bind_refs(
            [
                D1Type::Text(replay_key_digest_hex.as_str()),
                D1Type::Text(identity_digest_hex.as_str()),
                D1Type::Text(custody_lineage_b64u.as_str()),
                D1Type::Text(session_id_hex.as_str()),
                D1Type::Text(nonce_hex.as_str()),
                D1Type::Text(key.role().as_str()),
                D1Type::Text(command_digest_hex.as_str()),
                D1Type::Text(reserved_at_ms.as_str()),
                D1Type::Text(executed_at_ms.as_str()),
            ]
            .iter(),
        )
    }

    fn command_cas_count_guard_statement(
        &self,
        expected_changes: usize,
    ) -> worker::Result<worker::D1PreparedStatement> {
        let expected_changes = expected_changes.to_string();
        self.session
            .prepare(CAS_COUNT_GUARD_SQL)
            .bind_refs([D1Type::Text(expected_changes.as_str())].iter())
    }

    async fn run_lifecycle_checkpoint(
        &self,
        lifecycle_statement: worker::D1PreparedStatement,
        expected_lifecycle_changes: usize,
        checkpoint_statement: worker::D1PreparedStatement,
        reservation: ReservedTenantRootCommandV1,
        executed_at_ms: u64,
    ) -> worker::Result<ExecutedTenantRootCommandV1> {
        if executed_at_ms < reservation.reserved_at_ms() {
            return Err(store_error(
                "tenant-root command execution checkpoint precedes its reservation",
            ));
        }
        let lifecycle_guard = self.command_cas_count_guard_statement(expected_lifecycle_changes)?;
        let checkpoint_guard = self.command_cas_count_guard_statement(1)?;
        let results = self
            .session
            .batch(vec![
                lifecycle_statement,
                lifecycle_guard,
                checkpoint_statement,
                checkpoint_guard,
            ])
            .await?;
        if results.len() != 4 {
            return Err(store_error(
                "tenant-root lifecycle checkpoint returned an invalid result count",
            ));
        }
        for result in &results {
            if !result.success() {
                return Err(store_error(format!(
                    "tenant-root lifecycle checkpoint statement failed: {}",
                    result
                        .error()
                        .unwrap_or_else(|| "unknown D1 error".to_owned())
                )));
            }
        }
        require_changes(
            &results[0],
            expected_lifecycle_changes,
            "tenant-root lifecycle changed concurrently",
        )?;
        require_changes(
            &results[1],
            0,
            "tenant-root lifecycle count guard returned an invalid change count",
        )?;
        require_one_change(
            &results[2],
            "tenant-root command execution checkpoint changed concurrently",
        )?;
        require_changes(
            &results[3],
            0,
            "tenant-root command checkpoint count guard returned an invalid change count",
        )?;
        reservation
            .checkpoint_executed(executed_at_ms)
            .map_err(|error| store_error(error.message()))
    }

    fn open_row(
        &self,
        row: Option<TenantRootRoleD1RowV1>,
    ) -> worker::Result<Option<CloudflareStoredTenantRootRoleShareV1>> {
        row.map(|row| {
            if row.revision <= 0 {
                return Err(store_error(
                    "tenant-root role-private row has an invalid revision",
                ));
            }
            let revision = row.revision;
            let record = self.cipher.open(&row)?;
            Ok(CloudflareStoredTenantRootRoleShareV1 { record, revision })
        })
        .transpose()
    }

    async fn commit_command_terminal(
        &self,
        input: TenantRootCommandTerminalInputV1,
    ) -> worker::Result<CloudflareTenantRootCommandTerminalCommitV1> {
        let TenantRootCommandTerminalCommitDataV1 {
            key,
            command_digest,
            reserved_at_ms,
            executed_at_ms,
            receipt_bytes,
            receipt_digest,
            terminal_at_ms,
            terminal_kind,
        } = input.into_commit_data()?;
        self.require_command_role(&key)?;
        let replay_key_digest_hex = encode_hex(
            key.storage_key_digest()
                .map_err(|error| store_error(error.message()))?
                .as_bytes(),
        );
        let identity_digest_hex = encode_hex(key.identity_digest().as_bytes());
        let custody_lineage_b64u = key.custody_lineage().to_base64url();
        let session_id_hex = encode_hex(key.session_id().as_bytes());
        let nonce_hex = encode_hex(key.nonce().as_bytes());
        let command_digest_hex = encode_hex(command_digest.as_bytes());
        let receipt_b64u = encode_base64url_bytes_v1(&receipt_bytes);
        let receipt_digest_hex = encode_hex(receipt_digest.as_bytes());
        let terminal_at_ms_text = timestamp_i64(terminal_at_ms)?.to_string();
        let reserved_at_ms_text = timestamp_i64(reserved_at_ms)?.to_string();
        let executed_at_ms_text = timestamp_i64(executed_at_ms.unwrap_or_default())?.to_string();
        let result = self
            .session
            .prepare(COMMIT_COMMAND_TERMINAL_SQL)
            .bind_refs(
                [
                    D1Type::Text(terminal_kind.as_str()),
                    D1Type::Text(receipt_b64u.as_str()),
                    D1Type::Text(receipt_digest_hex.as_str()),
                    D1Type::Text(terminal_at_ms_text.as_str()),
                    D1Type::Text(replay_key_digest_hex.as_str()),
                    D1Type::Text(identity_digest_hex.as_str()),
                    D1Type::Text(custody_lineage_b64u.as_str()),
                    D1Type::Text(session_id_hex.as_str()),
                    D1Type::Text(nonce_hex.as_str()),
                    D1Type::Text(self.cipher.role.as_str()),
                    D1Type::Text(command_digest_hex.as_str()),
                    D1Type::Text(reserved_at_ms_text.as_str()),
                    D1Type::Text(terminal_kind.expected_status()),
                    D1Type::Text(executed_at_ms_text.as_str()),
                ]
                .iter(),
            )?
            .run()
            .await?;
        match result_changes(&result)? {
            1 => Ok(CloudflareTenantRootCommandTerminalCommitV1::Committed { receipt_bytes }),
            0 => {
                let stored = self.load_command_replay(&key).await?.ok_or_else(|| {
                    store_error(
                        "tenant-root terminal command conflict has no durable replay record",
                    )
                })?;
                let decision = reserve_tenant_root_command_v1(
                    Some(&stored.record),
                    key,
                    command_digest,
                    reserved_at_ms,
                )
                .map_err(|error| store_error(error.message()))?;
                let matches_terminal_kind = matches!(
                    (terminal_kind, decision),
                    (
                        TenantRootCommandTerminalKindV1::Completed,
                        TenantRootCommandReplayDecisionV1::ReplayCompleted { .. }
                    ) | (
                        TenantRootCommandTerminalKindV1::Failed,
                        TenantRootCommandReplayDecisionV1::ReplayFailed { .. }
                    )
                );
                let stored_receipt = stored.receipt_bytes.ok_or_else(|| {
                    store_error("tenant-root terminal replay omitted its exact receipt bytes")
                })?;
                if !matches_terminal_kind || stored_receipt != receipt_bytes {
                    return Err(store_error(
                        "tenant-root command terminal receipt conflicts with durable state",
                    ));
                }
                Ok(CloudflareTenantRootCommandTerminalCommitV1::Replay {
                    receipt_bytes: stored_receipt,
                })
            }
            _ => Err(store_error(
                "tenant-root command terminal commit returned an invalid change count",
            )),
        }
    }

    async fn load_command_replay(
        &self,
        key: &TenantRootCommandReplayKeyV1,
    ) -> worker::Result<Option<StoredTenantRootCommandReplayV1>> {
        self.require_command_role(key)?;
        let replay_key_digest_hex = encode_hex(
            key.storage_key_digest()
                .map_err(|error| store_error(error.message()))?
                .as_bytes(),
        );
        let row = self
            .session
            .prepare(LOAD_COMMAND_REPLAY_SQL)
            .bind_refs(
                [
                    D1Type::Text(replay_key_digest_hex.as_str()),
                    D1Type::Text(self.cipher.role.as_str()),
                ]
                .iter(),
            )?
            .first::<TenantRootCommandReplayD1RowV1>(None)
            .await?;
        row.map(|row| self.open_command_replay_row(row)).transpose()
    }

    fn open_command_replay_row(
        &self,
        row: TenantRootCommandReplayD1RowV1,
    ) -> worker::Result<StoredTenantRootCommandReplayV1> {
        if row.role != self.cipher.role.as_str() {
            return Err(store_error(
                "tenant-root command replay row belongs to the other Deriver",
            ));
        }
        let identity_digest = TenantRootIdentityDigestV1::from_bytes(decode_lower_hex_fixed::<32>(
            "tenant-root command identity digest",
            &row.tenant_identity_digest_hex,
        )?);
        let custody_lineage = TenantRootCustodyLineageId::from_base64url(&row.custody_lineage_b64u)
            .map_err(|error| store_error(error.message()))?;
        let session_id = TenantRootCeremonySessionIdV1::from_bytes(decode_lower_hex_fixed::<16>(
            "tenant-root command session id",
            &row.session_id_hex,
        )?)
        .map_err(|error| store_error(error.message()))?;
        let nonce = TenantRootCeremonyNonceV1::from_bytes(decode_lower_hex_fixed::<32>(
            "tenant-root command nonce",
            &row.nonce_hex,
        )?)
        .map_err(|error| store_error(error.message()))?;
        let key = match self.cipher.role {
            CloudflareTenantRootDeriverRoleV1::DeriverA => TenantRootCommandReplayKeyV1::deriver_a(
                identity_digest,
                custody_lineage,
                session_id,
                nonce,
            ),
            CloudflareTenantRootDeriverRoleV1::DeriverB => TenantRootCommandReplayKeyV1::deriver_b(
                identity_digest,
                custody_lineage,
                session_id,
                nonce,
            ),
        };
        if encode_hex(
            key.storage_key_digest()
                .map_err(|error| store_error(error.message()))?
                .as_bytes(),
        ) != row.replay_key_digest_hex
        {
            return Err(store_error(
                "tenant-root command replay lookup digest does not match its row",
            ));
        }
        let command_digest = TenantRootProtocolDigestV1::from_bytes(decode_lower_hex_fixed::<32>(
            "tenant-root command payload digest",
            &row.command_digest_hex,
        )?)
        .map_err(|error| store_error(error.message()))?;
        let admission_digest = row
            .admission_digest_hex
            .as_deref()
            .map(|value| {
                TenantRootProtocolDigestV1::from_bytes(decode_lower_hex_fixed::<32>(
                    "tenant-root command admission digest",
                    value,
                )?)
                .map_err(|error| store_error(error.message()))
            })
            .transpose()?;
        let reserved_at_ms = positive_u64_from_i64(
            "tenant-root command reservation timestamp",
            row.reserved_at_ms,
        )?;
        let reservation =
            match reserve_tenant_root_command_v1(None, key, command_digest, reserved_at_ms)
                .map_err(|error| store_error(error.message()))?
            {
                TenantRootCommandReplayDecisionV1::Execute(reservation) => reservation,
                _ => {
                    return Err(store_error(
                        "persisted tenant-root command could not reconstruct its reservation",
                    ));
                }
            };
        let (record, receipt_bytes, executed_at_ms) = match row.status.as_str() {
            "reserved"
                if row.receipt_b64u.is_none()
                    && row.receipt_digest_hex.is_none()
                    && row.executed_at_ms.is_none()
                    && row.terminal_at_ms.is_none() =>
            {
                (
                    TenantRootCommandReplayRecordV1::Reserved(reservation),
                    None,
                    None,
                )
            }
            "executed"
                if row.receipt_b64u.is_none()
                    && row.receipt_digest_hex.is_none()
                    && row.terminal_at_ms.is_none() =>
            {
                let executed_at_ms = positive_u64_from_i64(
                    "tenant-root command execution timestamp",
                    row.executed_at_ms.ok_or_else(|| {
                        store_error("executed tenant-root command row omitted execution timestamp")
                    })?,
                )?;
                let executed = reservation
                    .checkpoint_executed(executed_at_ms)
                    .map_err(|error| store_error(error.message()))?;
                (
                    TenantRootCommandReplayRecordV1::Executed(executed),
                    None,
                    Some(executed_at_ms),
                )
            }
            "completed" => {
                let terminal_receipt = decode_stored_terminal_receipt(
                    TenantRootCommandTerminalKindV1::Completed,
                    row.receipt_b64u.as_deref(),
                    row.receipt_digest_hex.as_deref(),
                    row.terminal_at_ms,
                    key,
                    command_digest,
                )?;
                let executed_at_ms = positive_u64_from_i64(
                    "tenant-root command execution timestamp",
                    row.executed_at_ms.ok_or_else(|| {
                        store_error("completed tenant-root command row omitted execution timestamp")
                    })?,
                )?;
                let executed = reservation
                    .checkpoint_executed(executed_at_ms)
                    .map_err(|error| store_error(error.message()))?;
                let record = executed
                    .complete(
                        terminal_receipt.receipt_digest,
                        terminal_receipt.terminal_at_ms,
                    )
                    .map_err(|error| store_error(error.message()))?;
                (
                    record,
                    Some(terminal_receipt.receipt_bytes),
                    Some(executed_at_ms),
                )
            }
            "failed" if row.executed_at_ms.is_none() => {
                let terminal_receipt = decode_stored_terminal_receipt(
                    TenantRootCommandTerminalKindV1::Failed,
                    row.receipt_b64u.as_deref(),
                    row.receipt_digest_hex.as_deref(),
                    row.terminal_at_ms,
                    key,
                    command_digest,
                )?;
                let record = reservation
                    .fail(
                        terminal_receipt.receipt_digest,
                        terminal_receipt.terminal_at_ms,
                    )
                    .map_err(|error| store_error(error.message()))?;
                (record, Some(terminal_receipt.receipt_bytes), None)
            }
            _ => {
                return Err(store_error(
                    "tenant-root command replay row has an invalid lifecycle shape",
                ));
            }
        };
        Ok(StoredTenantRootCommandReplayV1 {
            record,
            admission_digest,
            receipt_bytes,
            reserved_at_ms,
            executed_at_ms,
        })
    }

    fn reconcile_command_retry(
        &self,
        stored: &StoredTenantRootCommandReplayV1,
        key: TenantRootCommandReplayKeyV1,
        command_digest: TenantRootProtocolDigestV1,
    ) -> worker::Result<CloudflareTenantRootCommandReplayDecisionV1> {
        match reserve_tenant_root_command_v1(
            Some(&stored.record),
            key,
            command_digest,
            stored.reserved_at_ms,
        )
        .map_err(|error| store_error(error.message()))?
        {
            TenantRootCommandReplayDecisionV1::Execute(_) => Err(store_error(
                "durable tenant-root command replay returned a fresh execution",
            )),
            TenantRootCommandReplayDecisionV1::InProgress => match &stored.record {
                TenantRootCommandReplayRecordV1::Reserved(_) => Ok(
                    CloudflareTenantRootCommandReplayDecisionV1::ResumeExecution {
                        reservation: replay_reservation_from_stored(stored)?,
                    },
                ),
                TenantRootCommandReplayRecordV1::Executed(_) => Ok(
                    CloudflareTenantRootCommandReplayDecisionV1::ResumeCompletion {
                        executed: replay_executed_from_stored(stored)?,
                    },
                ),
                _ => Err(store_error(
                    "tenant-root command replay reported in-progress for a terminal row",
                )),
            },
            TenantRootCommandReplayDecisionV1::ReplayCompleted { receipt_digest } => {
                let receipt_bytes = stored.receipt_bytes.clone().ok_or_else(|| {
                    store_error("completed tenant-root command omitted prior receipt bytes")
                })?;
                require_receipt_digest(&receipt_bytes, receipt_digest)?;
                Ok(CloudflareTenantRootCommandReplayDecisionV1::ReplayCompleted { receipt_bytes })
            }
            TenantRootCommandReplayDecisionV1::ReplayFailed {
                failure_receipt_digest,
            } => {
                let failure_receipt_bytes = stored.receipt_bytes.clone().ok_or_else(|| {
                    store_error("failed tenant-root command omitted prior receipt bytes")
                })?;
                require_receipt_digest(&failure_receipt_bytes, failure_receipt_digest)?;
                Ok(CloudflareTenantRootCommandReplayDecisionV1::ReplayFailed {
                    failure_receipt_bytes,
                })
            }
        }
    }

    fn reconcile_initial_creation_retry(
        &self,
        stored: &StoredTenantRootCommandReplayV1,
        key: TenantRootCommandReplayKeyV1,
        creation_admission_digest: TenantRootProtocolDigestV1,
    ) -> worker::Result<CloudflareTenantRootCommandReplayDecisionV1> {
        if stored.admission_digest != Some(creation_admission_digest) {
            return Err(store_error(
                "tenant-root creation session was reused with different issuer-authorized bytes",
            ));
        }
        match self.reconcile_command_retry(stored, key, stored.record.command_digest())? {
            CloudflareTenantRootCommandReplayDecisionV1::ResumeExecution { .. }
            | CloudflareTenantRootCommandReplayDecisionV1::ResumeCompletion { .. } => {
                Ok(CloudflareTenantRootCommandReplayDecisionV1::InProgress)
            }
            decision => Ok(decision),
        }
    }

    fn reconcile_authorized_cleanup_retry(
        &self,
        stored: &StoredTenantRootCommandReplayV1,
        key: TenantRootCommandReplayKeyV1,
        authorization_digest: TenantRootProtocolDigestV1,
        expected_command_digest: Option<TenantRootProtocolDigestV1>,
    ) -> worker::Result<CloudflareTenantRootCommandReplayDecisionV1> {
        if stored.admission_digest != Some(authorization_digest) {
            return Err(store_error(
                "tenant-root cleanup session was reused with different authorization bytes",
            ));
        }
        if expected_command_digest
            .is_some_and(|expected| stored.record.command_digest() != expected)
        {
            return Err(store_error(
                "tenant-root cleanup session was reused after the pending row changed",
            ));
        }
        self.reconcile_command_retry(stored, key, stored.record.command_digest())
    }

    fn require_command_role(&self, key: &TenantRootCommandReplayKeyV1) -> worker::Result<()> {
        if key.role().as_str() != self.cipher.role.as_str() {
            return Err(store_error(
                "tenant-root command replay key belongs to the other Deriver",
            ));
        }
        Ok(())
    }
}

#[cfg(debug_assertions)]
async fn run_cloudflare_tenant_root_role_d1_lifecycle_integration_v1(
    env: &Env,
) -> worker::Result<CloudflareTenantRootRoleD1IntegrationReceiptV1> {
    let store = CloudflareTenantRootRoleShareStoreV1::from_env(env)?;
    let role = store.cipher.role;
    let other_role = match role {
        CloudflareTenantRootDeriverRoleV1::DeriverA => CloudflareTenantRootDeriverRoleV1::DeriverB,
        CloudflareTenantRootDeriverRoleV1::DeriverB => CloudflareTenantRootDeriverRoleV1::DeriverA,
    };

    let wrong_role = tenant_root_role_d1_integration_pending_record(other_role, 8, 8, 10)?;
    let wrong_role_scope = tenant_root_role_d1_integration_scope(&wrong_role, 0x01, 0x01, 1)?;
    require_integration_failure(
        store
            .reserve_insert_pending(wrong_role_scope, wrong_role, 10)
            .await,
        "role-private D1 accepted the other Deriver's share",
    )?;

    let non_initial_record = tenant_root_role_d1_integration_pending_record(role, 2, 2, 10)?;
    let non_initial_scope =
        tenant_root_role_d1_integration_scope(&non_initial_record, 0x02, 0x02, 1)?;
    let non_initial_command = match store
        .reserve_insert_pending(non_initial_scope, non_initial_record, 11)
        .await?
    {
        CloudflareTenantRootInsertPendingDecisionV1::Execute { command } => command,
        _ => {
            return Err(store_error(
                "fresh non-initial insertion did not return an executable command",
            ));
        }
    };
    let (non_initial, _) = store.insert_pending(non_initial_command, 11).await?;
    require_integration_failure(
        store
            .reserve_activate_initial_pending(
                tenant_root_role_d1_integration_scope(&non_initial.record, 0x03, 0x03, 1)?,
                non_initial.clone(),
                tenant_root_role_d1_integration_activation(&non_initial.record, 20)?,
                20,
                12,
            )
            .await,
        "role-private D1 reserved a non-initial epoch as epoch one",
    )?;
    let non_initial_cleanup_scope =
        tenant_root_role_d1_integration_scope(&non_initial.record, 0x04, 0x04, 1)?;
    let non_initial_cleanup = match store
        .reserve_cleanup_pending(non_initial_cleanup_scope, non_initial, 13)
        .await?
    {
        CloudflareTenantRootCleanupPendingDecisionV1::Execute { command } => command,
        _ => {
            return Err(store_error(
                "fresh non-initial cleanup did not return an executable command",
            ));
        }
    };
    let _ = store.cleanup_pending(non_initial_cleanup, 13).await?;

    let initial_record = tenant_root_role_d1_integration_pending_record(role, 1, 1, 10)?;
    let initial_scope = tenant_root_role_d1_integration_scope(&initial_record, 0x05, 0x05, 1)?;
    let initial_command = match store
        .reserve_insert_pending(initial_scope, initial_record.clone(), 60)
        .await?
    {
        CloudflareTenantRootInsertPendingDecisionV1::Execute { command } => command,
        _ => {
            return Err(store_error(
                "fresh initial insertion did not return an executable command",
            ));
        }
    };
    let (initial, _) = store.insert_pending(initial_command, 60).await?;
    let resumed_initial = match store
        .reserve_insert_pending(initial_scope, initial_record.clone(), 61)
        .await?
    {
        CloudflareTenantRootInsertPendingDecisionV1::ResumeCompletion { executed } => executed,
        _ => {
            return Err(store_error(
                "identical executed pending insertion did not return a completion token",
            ));
        }
    };
    if resumed_initial.executed_at_ms() != 60 {
        return Err(store_error(
            "executed pending insertion changed its durable checkpoint timestamp",
        ));
    }
    let initial_receipt = tenant_root_role_d1_integration_success_receipt(
        role,
        &resumed_initial,
        br#"{"kind":"r120_pending_inserted"}"#,
        62,
    )?;
    let initial_receipt_bytes = initial_receipt.canonical_bytes().to_vec();
    store
        .complete_command(resumed_initial, initial_receipt)
        .await?;
    if !matches!(
        store
            .reserve_insert_pending(initial_scope, initial_record.clone(), 63)
            .await?,
        CloudflareTenantRootInsertPendingDecisionV1::ReplayCompleted { receipt_bytes }
            if receipt_bytes == initial_receipt_bytes
    ) {
        return Err(store_error(
            "completed pending insertion did not replay after an arrival-time change",
        ));
    }
    let conflicting = tenant_root_role_d1_integration_pending_record(role, 1, 9, 10)?;
    require_integration_failure(
        store
            .reserve_insert_pending(initial_scope, conflicting, 60)
            .await,
        "role-private D1 accepted conflicting pending share bytes",
    )?;

    let initial_activation = tenant_root_role_d1_integration_activation(&initial.record, 20)?;
    let initial_activation_scope =
        tenant_root_role_d1_integration_scope(&initial.record, 0x06, 0x06, 1)?;
    let initial_activation_command = match store
        .reserve_activate_initial_pending(
            initial_activation_scope,
            initial.clone(),
            initial_activation.clone(),
            20,
            61,
        )
        .await?
    {
        CloudflareTenantRootActivateInitialPendingDecisionV1::Execute { command } => command,
        _ => {
            return Err(store_error(
                "fresh initial activation did not return an executable command",
            ));
        }
    };
    let (active, _) = store
        .activate_initial_pending(initial_activation_command, 61)
        .await?;
    let stale_activation_scope =
        tenant_root_role_d1_integration_scope(&initial.record, 0x07, 0x07, 1)?;
    let stale_activation_command = match store
        .reserve_activate_initial_pending(
            stale_activation_scope,
            initial,
            initial_activation,
            20,
            62,
        )
        .await?
    {
        CloudflareTenantRootActivateInitialPendingDecisionV1::Execute { command } => command,
        _ => {
            return Err(store_error(
                "fresh stale activation did not return an executable command",
            ));
        }
    };
    require_integration_failure(
        store
            .activate_initial_pending(stale_activation_command, 62)
            .await,
        "role-private D1 accepted a stale initial-activation revision",
    )?;

    let next_record = tenant_root_role_d1_integration_pending_record(role, 2, 2, 30)?;
    let missing_scope = tenant_root_role_d1_integration_scope(&next_record, 0x08, 0x08, 2)?;
    let missing_command = match store
        .reserve_insert_pending(missing_scope, next_record.clone(), 63)
        .await?
    {
        CloudflareTenantRootInsertPendingDecisionV1::Execute { command } => command,
        _ => {
            return Err(store_error(
                "fresh successor insertion did not return an executable command",
            ));
        }
    };
    let (missing_pending, _) = store.insert_pending(missing_command, 63).await?;
    let missing_cleanup_scope =
        tenant_root_role_d1_integration_scope(&missing_pending.record, 0x09, 0x09, 2)?;
    let missing_cleanup_command = match store
        .reserve_cleanup_pending(missing_cleanup_scope, missing_pending.clone(), 64)
        .await?
    {
        CloudflareTenantRootCleanupPendingDecisionV1::Execute { command } => command,
        _ => {
            return Err(store_error(
                "fresh missing-successor cleanup did not return an executable command",
            ));
        }
    };
    let _ = store.cleanup_pending(missing_cleanup_command, 64).await?;
    let missing_swap_scope =
        tenant_root_role_d1_integration_scope(&missing_pending.record, 0x0a, 0x0a, 2)?;
    let missing_swap_command = match store
        .reserve_swap_active_epoch(
            missing_swap_scope,
            active.clone(),
            missing_pending,
            tenant_root_role_d1_integration_activation(&next_record, 40)?,
            CloudflareTenantRootRetirementV1::new(lifecycle_receipt(0x45)?, 40)?,
            40,
            65,
        )
        .await?
    {
        CloudflareTenantRootSwapActiveEpochDecisionV1::Execute { command } => command,
        _ => {
            return Err(store_error(
                "fresh missing-successor swap did not return an executable command",
            ));
        }
    };
    require_integration_failure(
        store.swap_active_epoch(missing_swap_command, 65).await,
        "role-private D1 retired an active epoch without its pending successor",
    )?;

    let pending_scope = tenant_root_role_d1_integration_scope(&next_record, 0x0b, 0x0b, 2)?;
    let pending_command = match store
        .reserve_insert_pending(pending_scope, next_record, 66)
        .await?
    {
        CloudflareTenantRootInsertPendingDecisionV1::Execute { command } => command,
        _ => {
            return Err(store_error(
                "fresh successor insertion did not return an executable command",
            ));
        }
    };
    let (pending, _) = store.insert_pending(pending_command, 66).await?;
    let swap_activation = tenant_root_role_d1_integration_activation(&pending.record, 40)?;
    let swap_retirement = CloudflareTenantRootRetirementV1::new(lifecycle_receipt(0x45)?, 40)?;
    let swap_scope = tenant_root_role_d1_integration_scope(&pending.record, 0x0c, 0x0c, 2)?;
    let swap_command = match store
        .reserve_swap_active_epoch(
            swap_scope,
            active.clone(),
            pending.clone(),
            swap_activation.clone(),
            swap_retirement.clone(),
            40,
            67,
        )
        .await?
    {
        CloudflareTenantRootSwapActiveEpochDecisionV1::Execute { command } => command,
        _ => {
            return Err(store_error(
                "fresh epoch swap did not return an executable command",
            ));
        }
    };
    let ((retired, activated), _) = store.swap_active_epoch(swap_command, 67).await?;
    let stale_swap_scope = tenant_root_role_d1_integration_scope(&pending.record, 0x0d, 0x0d, 2)?;
    let stale_swap_command = match store
        .reserve_swap_active_epoch(
            stale_swap_scope,
            active,
            pending,
            swap_activation,
            swap_retirement,
            40,
            68,
        )
        .await?
    {
        CloudflareTenantRootSwapActiveEpochDecisionV1::Execute { command } => command,
        _ => {
            return Err(store_error(
                "fresh stale epoch swap did not return an executable command",
            ));
        }
    };
    require_integration_failure(
        store.swap_active_epoch(stale_swap_command, 68).await,
        "role-private D1 accepted a stale epoch-swap revision",
    )?;

    let loaded_active = store
        .observe_active(activated.record().identity())
        .await?
        .require_active()?;
    if loaded_active != activated {
        return Err(store_error(
            "role-private D1 active load did not return the activated epoch",
        ));
    }

    let cleanup_record = tenant_root_role_d1_integration_pending_record(role, 3, 3, 50)?;
    let cleanup_insert_scope =
        tenant_root_role_d1_integration_scope(&cleanup_record, 0x0e, 0x0e, 3)?;
    let cleanup_insert_command = match store
        .reserve_insert_pending(cleanup_insert_scope, cleanup_record, 69)
        .await?
    {
        CloudflareTenantRootInsertPendingDecisionV1::Execute { command } => command,
        _ => {
            return Err(store_error(
                "fresh cleanup-row insertion did not return an executable command",
            ));
        }
    };
    let (cleanup, _) = store.insert_pending(cleanup_insert_command, 69).await?;
    let cleanup_scope = tenant_root_role_d1_integration_scope(&cleanup.record, 0x0f, 0x0f, 3)?;
    let cleanup_command = match store
        .reserve_cleanup_pending(cleanup_scope, cleanup.clone(), 70)
        .await?
    {
        CloudflareTenantRootCleanupPendingDecisionV1::Execute { command } => command,
        _ => {
            return Err(store_error(
                "fresh pending cleanup did not return an executable command",
            ));
        }
    };
    let _ = store.cleanup_pending(cleanup_command, 70).await?;
    let stale_cleanup_scope =
        tenant_root_role_d1_integration_scope(&cleanup.record, 0x10, 0x10, 3)?;
    let stale_cleanup_command = match store
        .reserve_cleanup_pending(stale_cleanup_scope, cleanup, 71)
        .await?
    {
        CloudflareTenantRootCleanupPendingDecisionV1::Execute { command } => command,
        _ => {
            return Err(store_error(
                "fresh stale pending cleanup did not return an executable command",
            ));
        }
    };
    require_integration_failure(
        store.cleanup_pending(stale_cleanup_command, 71).await,
        "role-private D1 accepted a stale pending-cleanup revision",
    )?;

    let command_identity = activated
        .record
        .identity
        .digest()
        .map_err(|error| store_error(error.message()))?;
    let command_session = TenantRootCeremonySessionIdV1::from_bytes([0x71; 16])
        .map_err(|error| store_error(error.message()))?;
    let command_nonce = TenantRootCeremonyNonceV1::from_bytes([0x72; 32])
        .map_err(|error| store_error(error.message()))?;
    let mut command_payload = command_payload_start("integration_terminal_probe")?;
    push_command_field(&mut command_payload, b"r120-role-command")?;
    let command_payload_digest = finish_command_payload(command_payload)?;
    let command_scope = TenantRootCommandScopeV1::new(
        match role {
            CloudflareTenantRootDeriverRoleV1::DeriverA => TenantRootCommandReplayKeyV1::deriver_a(
                command_identity,
                activated.record.custody_lineage,
                command_session,
                command_nonce,
            ),
            CloudflareTenantRootDeriverRoleV1::DeriverB => TenantRootCommandReplayKeyV1::deriver_b(
                command_identity,
                activated.record.custody_lineage,
                command_session,
                command_nonce,
            ),
        },
        activated.record.epoch,
        2,
    )
    .map_err(|error| store_error(error.message()))?;
    let command_operation = TenantRootCommandOperationV1::cleanup_pending(command_payload_digest);
    let _fresh_reservation = match store
        .reserve_scoped_command(command_scope, command_operation, 60)
        .await?
    {
        CloudflareTenantRootCommandReplayDecisionV1::Execute { reservation } => reservation,
        _ => {
            return Err(store_error(
                "fresh role-private command did not return an execution reservation",
            ));
        }
    };
    let resumed_reservation = match store
        .reserve_scoped_command(command_scope, command_operation, 61)
        .await?
    {
        CloudflareTenantRootCommandReplayDecisionV1::ResumeExecution { reservation } => reservation,
        _ => {
            return Err(store_error(
                "identical reserved role-private command did not return a resumable reservation",
            ));
        }
    };
    let command_receipt = tenant_root_role_d1_integration_failure_receipt(
        role,
        &resumed_reservation,
        br#"{"kind":"r120_role_command_failed"}"#,
        70,
    )?;
    let command_receipt_bytes = command_receipt.canonical_bytes().to_vec();
    let command_receipt_digest_hex = encode_hex(command_receipt.digest().as_bytes());
    let committed = store
        .fail_command(resumed_reservation, command_receipt)
        .await?;
    if !matches!(
        committed,
        CloudflareTenantRootCommandTerminalCommitV1::Committed { receipt_bytes }
            if receipt_bytes == command_receipt_bytes
    ) {
        return Err(store_error(
            "role-private command did not commit its exact receipt bytes",
        ));
    }
    if !matches!(
        store
            .reserve_scoped_command(command_scope, command_operation, 63)
            .await?,
        CloudflareTenantRootCommandReplayDecisionV1::ReplayFailed { failure_receipt_bytes }
            if failure_receipt_bytes == command_receipt_bytes
    ) {
        return Err(store_error(
            "failed role-private command did not replay exact receipt bytes",
        ));
    }
    let substituted_nonce = TenantRootCeremonyNonceV1::from_bytes([0x74; 32])
        .map_err(|error| store_error(error.message()))?;
    let substituted_scope = TenantRootCommandScopeV1::new(
        match role {
            CloudflareTenantRootDeriverRoleV1::DeriverA => TenantRootCommandReplayKeyV1::deriver_a(
                command_identity,
                activated.record.custody_lineage,
                command_session,
                substituted_nonce,
            ),
            CloudflareTenantRootDeriverRoleV1::DeriverB => TenantRootCommandReplayKeyV1::deriver_b(
                command_identity,
                activated.record.custody_lineage,
                command_session,
                substituted_nonce,
            ),
        },
        activated.record.epoch,
        2,
    )
    .map_err(|error| store_error(error.message()))?;
    require_integration_failure(
        store
            .reserve_scoped_command(substituted_scope, command_operation, 60)
            .await,
        "role-private command replay accepted nonce substitution",
    )?;

    let failed_session = TenantRootCeremonySessionIdV1::from_bytes([0x75; 16])
        .map_err(|error| store_error(error.message()))?;
    let failed_nonce = TenantRootCeremonyNonceV1::from_bytes([0x76; 32])
        .map_err(|error| store_error(error.message()))?;
    let failed_scope = TenantRootCommandScopeV1::new(
        match role {
            CloudflareTenantRootDeriverRoleV1::DeriverA => TenantRootCommandReplayKeyV1::deriver_a(
                command_identity,
                activated.record.custody_lineage,
                failed_session,
                failed_nonce,
            ),
            CloudflareTenantRootDeriverRoleV1::DeriverB => TenantRootCommandReplayKeyV1::deriver_b(
                command_identity,
                activated.record.custody_lineage,
                failed_session,
                failed_nonce,
            ),
        },
        activated.record.epoch,
        2,
    )
    .map_err(|error| store_error(error.message()))?;
    let failed_reservation = match store
        .reserve_scoped_command(failed_scope, command_operation, 80)
        .await?
    {
        CloudflareTenantRootCommandReplayDecisionV1::Execute { reservation } => reservation,
        _ => {
            return Err(store_error(
                "fresh failing role-private command did not return an execution reservation",
            ));
        }
    };
    let failure_receipt = tenant_root_role_d1_integration_failure_receipt(
        role,
        &failed_reservation,
        br#"{"kind":"r120_role_command_failed"}"#,
        90,
    )?;
    let failed_receipt_bytes = failure_receipt.canonical_bytes().to_vec();
    store
        .fail_command(failed_reservation, failure_receipt)
        .await?;
    if !matches!(
        store
            .reserve_scoped_command(failed_scope, command_operation, 81)
            .await?,
        CloudflareTenantRootCommandReplayDecisionV1::ReplayFailed {
            failure_receipt_bytes: stored_receipt_bytes
        } if stored_receipt_bytes == failed_receipt_bytes
    ) {
        return Err(store_error(
            "failed role-private command did not replay exact failure-receipt bytes",
        ));
    }

    Ok(CloudflareTenantRootRoleD1IntegrationReceiptV1 {
        role,
        retired_epoch: retired.record.epoch.get().get(),
        retired_revision: retired.revision,
        active_epoch: activated.record.epoch.get().get(),
        active_revision: activated.revision,
        cleanup_epoch: 3,
        command_receipt_digest_hex,
    })
}

/// One probe ceremony's sealed creation input plus the public bytes A needs.
#[cfg(debug_assertions)]
struct TenantRootCreationProbeCeremonyV1 {
    input: CloudflareTenantRootInitialCreationInputV1,
    managed_backup: VerifiedTenantRootManagedBackupV1,
    own_package: Vec<u8>,
    evidence: Vec<u8>,
    context: router_ab_core::TenantRootCeremonyContextV1,
    authority_id: router_ab_core::TenantRootControlPlaneAuthorityIdV1,
}

#[cfg(debug_assertions)]
struct TenantRootCreationProbeAuthorizationV1 {
    own_package: Vec<u8>,
    peer_package: Vec<u8>,
    context: router_ab_core::TenantRootCeremonyContextV1,
    authority_id: router_ab_core::TenantRootControlPlaneAuthorityIdV1,
}

#[cfg(debug_assertions)]
fn tenant_root_creation_probe_authorization(
    role: CloudflareTenantRootDeriverRoleV1,
    session_seed: u8,
) -> worker::Result<TenantRootCreationProbeAuthorizationV1> {
    let protocol_role = tenant_root_creation_probe_protocol_role(role);
    let identity = tenant_root_creation_probe_identity()?;
    let context = tenant_root_creation_probe_context(session_seed)?;
    let journal = router_ab_core::TenantRootCreationJournalV1::started(
        identity,
        context.custody_lineage(),
        context.clone(),
    )
    .map_err(|error| store_error(error.message()))?;
    let authority_id = router_ab_core::TenantRootControlPlaneAuthorityIdV1::from_bytes([0x56; 32]);
    let package_for = |package_role: TwoPartyDeriverRole| -> worker::Result<Vec<u8>> {
        let signed = tenant_root_creation_probe_signed_command(
            package_role,
            &journal,
            &context,
            authority_id,
        )?;
        router_ab_core::TenantRootRoleCreationCommandPackageV1::new(journal.clone(), signed)
            .and_then(|package| package.canonical_bytes())
            .map_err(|error| store_error(error.message()))
    };
    Ok(TenantRootCreationProbeAuthorizationV1 {
        own_package: package_for(protocol_role)?,
        peer_package: package_for(protocol_role.peer())?,
        context,
        authority_id,
    })
}

#[cfg(debug_assertions)]
fn tenant_root_creation_probe_verified_package(
    authorization: &TenantRootCreationProbeAuthorizationV1,
    role: CloudflareTenantRootDeriverRoleV1,
) -> worker::Result<router_ab_core::VerifiedTenantRootRoleCreationCommandPackageV1> {
    let protocol_role = tenant_root_creation_probe_protocol_role(role);
    let signer = crate::env::cloudflare_tenant_root_creation_role_signer_for_probe_v1(
        protocol_role,
        tenant_root_role_d1_integration_role_signing_key_id(role),
        tenant_root_role_d1_integration_role_signing_key(role),
    );
    crate::tenant_root_role_runtime::verify_tenant_root_role_creation_package_v1(
        &authorization.own_package,
        protocol_role,
        authorization.authority_id,
        &tenant_root_creation_probe_issuer_keys()?,
        &signer,
    )
    .map_err(|error| store_error(error.message()))
}

/// Builds one complete ceremony through the production entry point.
///
/// The peer leg runs first only to produce a real peer commitment; its share is
/// dropped and never persisted. This role's leg then runs through
/// `execute_tenant_root_role_creation_v1`, the same function a live Deriver
/// calls, so the probe exercises production admission, finalization, and
/// sealing rather than a parallel fixture path.
#[cfg(debug_assertions)]
fn tenant_root_creation_probe_ceremony(
    env: &Env,
    role: CloudflareTenantRootDeriverRoleV1,
    authorization: TenantRootCreationProbeAuthorizationV1,
    now_ms: u64,
) -> worker::Result<TenantRootCreationProbeCeremonyV1> {
    let protocol_role = tenant_root_creation_probe_protocol_role(role);
    let peer_protocol_role = protocol_role.peer();
    let peer_role_id = match role {
        CloudflareTenantRootDeriverRoleV1::DeriverA => CloudflareTenantRootDeriverRoleV1::DeriverB,
        CloudflareTenantRootDeriverRoleV1::DeriverB => CloudflareTenantRootDeriverRoleV1::DeriverA,
    };

    let TenantRootCreationProbeAuthorizationV1 {
        own_package,
        peer_package,
        context,
        authority_id,
    } = authorization;

    let role_keys = tenant_root_creation_probe_role_keys()?;
    let trusted_issuer = tenant_root_creation_probe_issuer_keys()?;
    let worker_role = match role {
        CloudflareTenantRootDeriverRoleV1::DeriverA => crate::CloudflareWorkerRoleV1::DeriverA,
        CloudflareTenantRootDeriverRoleV1::DeriverB => crate::CloudflareWorkerRoleV1::DeriverB,
    };
    let provider_config = tenant_root_creation_probe_provider_config(env, worker_role)?;
    let mut rng = crate::CloudflareSignerProofGetrandomRngV1;

    // Peer leg: commit only. Its share dies with this scope.
    let mut peer_online =
        crate::env::load_cloudflare_tenant_root_operational_rotation_provider_v1(env, worker_role)
            .map_err(|error| store_error(error.message()))?;
    let mut peer_backup =
        crate::env::load_cloudflare_tenant_root_operational_rotation_provider_v1(env, worker_role)
            .map_err(|error| store_error(error.message()))?;
    let peer_signer = crate::env::cloudflare_tenant_root_creation_role_signer_for_probe_v1(
        peer_protocol_role,
        tenant_root_role_d1_integration_role_signing_key_id(peer_role_id),
        tenant_root_role_d1_integration_role_signing_key(peer_role_id),
    );
    let peer_progress = crate::tenant_root_role_runtime::execute_tenant_root_role_creation_v1(
        &peer_package,
        None,
        peer_protocol_role,
        authority_id,
        &trusted_issuer,
        &role_keys,
        &peer_signer,
        &provider_config,
        &mut peer_online,
        &mut peer_backup,
        now_ms,
        &mut rng,
    )
    .map_err(|error| store_error(error.message()))?;
    let peer_commitment = match peer_progress {
        crate::tenant_root_role_runtime::TenantRootRoleCreationProgressV1::Committed {
            pending,
        } => pending.commitment_bytes().to_vec(),
        _ => {
            return Err(store_error(
                "peer probe leg sealed without a peer commitment",
            ))
        }
    };

    // This role's leg: admit, finalize, seal, through the production entry point.
    let mut online =
        crate::env::load_cloudflare_tenant_root_operational_rotation_provider_v1(env, worker_role)
            .map_err(|error| store_error(error.message()))?;
    let mut backup =
        crate::env::load_cloudflare_tenant_root_operational_rotation_provider_v1(env, worker_role)
            .map_err(|error| store_error(error.message()))?;
    let signer = crate::env::cloudflare_tenant_root_creation_role_signer_for_probe_v1(
        protocol_role,
        tenant_root_role_d1_integration_role_signing_key_id(role),
        tenant_root_role_d1_integration_role_signing_key(role),
    );
    let progress = crate::tenant_root_role_runtime::execute_tenant_root_role_creation_v1(
        &own_package,
        Some(&peer_commitment),
        protocol_role,
        authority_id,
        &trusted_issuer,
        &role_keys,
        &signer,
        &provider_config,
        &mut online,
        &mut backup,
        now_ms,
        &mut rng,
    )
    .map_err(|error| store_error(error.message()))?;
    match progress {
        crate::tenant_root_role_runtime::TenantRootRoleCreationProgressV1::Sealed {
            signed_installation_evidence,
            input,
            managed_backup,
            ..
        } => Ok(TenantRootCreationProbeCeremonyV1 {
            input: *input,
            managed_backup: *managed_backup,
            own_package,
            evidence: signed_installation_evidence,
            context,
            authority_id,
        }),
        _ => Err(store_error(
            "own probe leg did not seal against the peer commitment",
        )),
    }
}

/// Exercises the creation-specific store path against a real role-private D1.
///
/// The receipt comes through the production sequence -- reserve, insert, sign
/// against the executed command, verify locally with that same token, complete
/// -- so nothing here fabricates a receipt. Run this probe in each Deriver to
/// prove both roles' wrappers; a single Worker only owns its own store.
#[cfg(debug_assertions)]
async fn run_cloudflare_tenant_root_initial_creation_integration_v1(
    env: &Env,
) -> worker::Result<CloudflareTenantRootRoleD1IntegrationReceiptV1> {
    let store = CloudflareTenantRootRoleShareStoreV1::from_env(env)?;
    let role = store.cipher.role;
    let reserved_at_ms = TENANT_ROOT_CREATION_PROBE_ISSUED_AT_MS_V1 + 4;

    // 1. The full happy path: reserve, insert, terminalize.
    let completed_authorization = tenant_root_creation_probe_authorization(role, 0x54)?;
    let completed_package =
        tenant_root_creation_probe_verified_package(&completed_authorization, role)?;
    if !matches!(
        store
            .preflight_initial_creation(completed_package.command(), reserved_at_ms)
            .await?,
        CloudflareTenantRootInitialCreationPreflightV1::Fresh
    ) {
        return Err(store_error(
            "fresh initial creation preflight did not admit generation",
        ));
    }
    let completed = tenant_root_creation_probe_ceremony(
        env,
        role,
        completed_authorization,
        reserved_at_ms - 2,
    )?;
    let role_signer = crate::env::cloudflare_tenant_root_creation_role_signer_for_probe_v1(
        tenant_root_creation_probe_protocol_role(role),
        tenant_root_role_d1_integration_role_signing_key_id(role),
        tenant_root_role_d1_integration_role_signing_key(role),
    );
    let backup_store =
        crate::tenant_root_managed_backup_r2::CloudflareTenantRootManagedBackupStoreV1::from_env(
            env,
            role.managed_restore_role(),
        )?;
    if !matches!(
        backup_store.put_verified(&completed.managed_backup).await?,
        crate::tenant_root_managed_backup_r2::CloudflareTenantRootManagedBackupPutOutcomeV1::Stored { .. }
    ) {
        return Err(store_error(
            "a first managed-backup write reported a replay",
        ));
    }
    let completed_epoch = completed.input.record.epoch.get().get();
    let committed_bytes = match store
        .persist_initial_creation(
            completed.input,
            &role_signer,
            reserved_at_ms,
            reserved_at_ms,
            reserved_at_ms + 1,
        )
        .await?
    {
        CloudflareTenantRootInitialCreationPersistenceOutcomeV1::Committed { receipt_bytes } => {
            receipt_bytes
        }
        CloudflareTenantRootInitialCreationPersistenceOutcomeV1::ReplayCompleted { .. } => {
            return Err(store_error(
                "a first initial-creation persistence reported a replay",
            ));
        }
        CloudflareTenantRootInitialCreationPersistenceOutcomeV1::InProgress => {
            return Err(store_error(
                "a first initial-creation persistence reported in progress",
            ));
        }
        CloudflareTenantRootInitialCreationPersistenceOutcomeV1::ReplayFailed { .. } => {
            return Err(store_error(
                "a first initial-creation persistence replayed a failure",
            ));
        }
    };

    // 2. Exact replay returns the identical receipt.
    let replay_authorization = tenant_root_creation_probe_authorization(role, 0x54)?;
    let replay_package = tenant_root_creation_probe_verified_package(&replay_authorization, role)?;
    match store
        .preflight_initial_creation(replay_package.command(), reserved_at_ms + 2)
        .await?
    {
        CloudflareTenantRootInitialCreationPreflightV1::ReplayCompleted { receipt_bytes } => {
            if receipt_bytes != committed_bytes {
                return Err(store_error(
                    "exact initial-creation replay returned different receipt bytes",
                ));
            }
        }
        _ => {
            return Err(store_error(
                "exact initial-creation replay was not recognised",
            ))
        }
    }

    if !matches!(
        backup_store.put_verified(&completed.managed_backup).await?,
        crate::tenant_root_managed_backup_r2::CloudflareTenantRootManagedBackupPutOutcomeV1::Replay { .. }
    ) {
        return Err(store_error(
            "an exact managed-backup retry did not report a replay",
        ));
    }

    // 3. Exact replay AFTER the issuer command expired still reconciles.
    //    Freshness gates only the first durable reservation.
    let expired_authorization = tenant_root_creation_probe_authorization(role, 0x54)?;
    let expired_package =
        tenant_root_creation_probe_verified_package(&expired_authorization, role)?;
    match store
        .preflight_initial_creation(
            expired_package.command(),
            TENANT_ROOT_CREATION_PROBE_EXPIRES_AT_MS_V1 + 60_000,
        )
        .await?
    {
        CloudflareTenantRootInitialCreationPreflightV1::ReplayCompleted { receipt_bytes } => {
            if receipt_bytes != committed_bytes {
                return Err(store_error(
                    "post-expiry initial-creation replay returned different receipt bytes",
                ));
            }
        }
        _ => {
            return Err(store_error(
                "post-expiry exact initial-creation replay was not recognised",
            ));
        }
    }

    // 4. A different ceremony for the same tenant is a different command and
    //    must not reconcile against the completed one.
    let changed_authorization = tenant_root_creation_probe_authorization(role, 0x64)?;
    let changed_package =
        tenant_root_creation_probe_verified_package(&changed_authorization, role)?;
    if !matches!(
        store
            .preflight_initial_creation(changed_package.command(), reserved_at_ms + 3)
            .await?,
        CloudflareTenantRootInitialCreationPreflightV1::Fresh
    ) {
        return Err(store_error(
            "a changed creation package reconciled against another ceremony",
        ));
    }
    let changed =
        tenant_root_creation_probe_ceremony(env, role, changed_authorization, reserved_at_ms - 2)?;
    match store
        .reserve_initial_creation_pending(changed.input, reserved_at_ms + 3)
        .await
    {
        Ok(CloudflareTenantRootInitialCreationDecisionV1::ReplayCompleted { .. }) => {
            return Err(store_error(
                "a changed creation package replayed the prior receipt",
            ));
        }
        Ok(CloudflareTenantRootInitialCreationDecisionV1::Execute { .. }) | Err(_) => {}
        Ok(_) => {
            return Err(store_error(
                "a changed creation package produced an unexpected decision",
            ));
        }
    }

    // 5. Execution-checkpoint resume: reserve, do not insert, reserve again.
    let resume_authorization = tenant_root_creation_probe_authorization(role, 0x74)?;
    let resume_package = tenant_root_creation_probe_verified_package(&resume_authorization, role)?;
    if !matches!(
        store
            .preflight_initial_creation(resume_package.command(), reserved_at_ms + 4)
            .await?,
        CloudflareTenantRootInitialCreationPreflightV1::Fresh
    ) {
        return Err(store_error("a fresh resume preflight was not executable"));
    }
    let resume =
        tenant_root_creation_probe_ceremony(env, role, resume_authorization, reserved_at_ms - 2)?;
    match store
        .reserve_initial_creation_pending(resume.input, reserved_at_ms + 4)
        .await?
    {
        CloudflareTenantRootInitialCreationDecisionV1::Execute { .. } => {}
        _ => return Err(store_error("a fresh resume ceremony was not executable")),
    }
    let resume_again_authorization = tenant_root_creation_probe_authorization(role, 0x74)?;
    let resume_again_package =
        tenant_root_creation_probe_verified_package(&resume_again_authorization, role)?;
    match store
        .preflight_initial_creation(resume_again_package.command(), reserved_at_ms + 5)
        .await?
    {
        CloudflareTenantRootInitialCreationPreflightV1::InProgress => {}
        _ => {
            return Err(store_error(
                "an unexecuted reservation did not offer resume or report in progress",
            ));
        }
    }

    // 6. The receipt A would receive verifies under the remote attestation path.
    crate::tenant_root_role_runtime::verify_tenant_root_peer_persistence_v1(
        &committed_bytes,
        &completed.own_package,
        &completed.evidence,
        tenant_root_creation_probe_protocol_role(role),
        completed.authority_id,
        &tenant_root_creation_probe_issuer_keys()?,
        &tenant_root_creation_probe_role_keys()?,
        &completed.context,
    )
    .map_err(|error| store_error(error.message()))?;

    // 7. Cleanup requires a distinct issuer authorization, deletes the exact
    // pending revision, terminalizes under that authorization, and replays its
    // exact receipt without resurrecting the row.
    let cleanup_record = tenant_root_role_d1_integration_pending_record(role, 2, 0x85, 50)?;
    let cleanup_identity = cleanup_record.identity().clone();
    let cleanup_lineage = cleanup_record.custody_lineage();
    let cleanup_epoch = cleanup_record.epoch();
    let cleanup_insert_scope =
        tenant_root_role_d1_integration_scope(&cleanup_record, 0x81, 0x82, 1)?;
    let cleanup_insert = match store
        .reserve_insert_pending(cleanup_insert_scope, cleanup_record, reserved_at_ms + 6)
        .await?
    {
        CloudflareTenantRootInsertPendingDecisionV1::Execute { command } => command,
        _ => return Err(store_error("fresh cleanup fixture was not executable")),
    };
    let (cleanup_pending, _) = store
        .insert_pending(cleanup_insert, reserved_at_ms + 6)
        .await?;
    let cleanup_session = TenantRootCeremonySessionIdV1::from_bytes([0x83; 16])
        .map_err(|error| store_error(error.message()))?;
    let cleanup_ceremony_nonce = TenantRootCeremonyNonceV1::from_bytes([0x84; 32])
        .map_err(|error| store_error(error.message()))?;

    let wrong_role = tenant_root_creation_probe_cleanup_authorization(
        &cleanup_pending,
        tenant_root_creation_probe_protocol_role(role).peer(),
        cleanup_pending.revision,
        cleanup_session,
        cleanup_ceremony_nonce,
        0x85,
    )?;
    require_integration_failure(
        store
            .reserve_authorized_cleanup(wrong_role, reserved_at_ms + 7)
            .await,
        "role-private D1 accepted a cleanup authorization for the peer role",
    )?;
    let wrong_revision = tenant_root_creation_probe_cleanup_authorization(
        &cleanup_pending,
        tenant_root_creation_probe_protocol_role(role),
        cleanup_pending.revision + 1,
        cleanup_session,
        cleanup_ceremony_nonce,
        0x86,
    )?;
    require_integration_failure(
        store
            .reserve_authorized_cleanup(wrong_revision, reserved_at_ms + 7)
            .await,
        "role-private D1 accepted a cleanup authorization for another revision",
    )?;

    let cleanup_authorization = tenant_root_creation_probe_cleanup_authorization(
        &cleanup_pending,
        tenant_root_creation_probe_protocol_role(role),
        cleanup_pending.revision,
        cleanup_session,
        cleanup_ceremony_nonce,
        0x87,
    )?;
    let cleanup_authorization_bytes = cleanup_authorization
        .canonical_bytes()
        .map_err(|error| store_error(error.message()))?;
    let cleanup_command = match store
        .reserve_authorized_cleanup(cleanup_authorization, reserved_at_ms + 7)
        .await?
    {
        CloudflareTenantRootAuthorizedCleanupDecisionV1::Execute { command } => command,
        _ => return Err(store_error("fresh authorized cleanup was not executable")),
    };
    let cleanup_executed = store
        .execute_authorized_cleanup(cleanup_command, reserved_at_ms + 7)
        .await?;
    let cleanup_receipt = tenant_root_role_d1_integration_success_receipt(
        role,
        &cleanup_executed.executed,
        &cleanup_authorization_bytes,
        reserved_at_ms + 8,
    )?;
    let cleanup_receipt_bytes = match store
        .complete_authorized_cleanup(cleanup_executed, cleanup_receipt)
        .await?
    {
        CloudflareTenantRootCommandTerminalCommitV1::Committed { receipt_bytes } => receipt_bytes,
        CloudflareTenantRootCommandTerminalCommitV1::Replay { .. } => {
            return Err(store_error("fresh authorized cleanup reported a replay"));
        }
    };
    let replay_cleanup_authorization = tenant_root_creation_probe_cleanup_authorization(
        &cleanup_pending,
        tenant_root_creation_probe_protocol_role(role),
        cleanup_pending.revision,
        cleanup_session,
        cleanup_ceremony_nonce,
        0x87,
    )?;
    match store
        .reserve_authorized_cleanup(
            replay_cleanup_authorization,
            TENANT_ROOT_CREATION_PROBE_EXPIRES_AT_MS_V1 + 60_000,
        )
        .await?
    {
        CloudflareTenantRootAuthorizedCleanupDecisionV1::ReplayCompleted { receipt_bytes }
            if receipt_bytes == cleanup_receipt_bytes => {}
        _ => {
            return Err(store_error(
                "authorized cleanup did not replay its exact terminal receipt",
            ));
        }
    }
    let conflicting_replay_cleanup = tenant_root_creation_probe_cleanup_authorization(
        &cleanup_pending,
        tenant_root_creation_probe_protocol_role(role),
        cleanup_pending.revision + 1,
        cleanup_session,
        cleanup_ceremony_nonce,
        0x87,
    )?;
    require_integration_failure(
        store
            .reserve_authorized_cleanup(
                conflicting_replay_cleanup,
                TENANT_ROOT_CREATION_PROBE_EXPIRES_AT_MS_V1 + 60_000,
            )
            .await,
        "authorized cleanup accepted changed command bytes under a completed replay key",
    )?;
    if store
        .load_epoch(&cleanup_identity, cleanup_lineage, cleanup_epoch)
        .await?
        .is_some()
    {
        return Err(store_error(
            "authorized cleanup left its pending role share durable",
        ));
    }

    Ok(CloudflareTenantRootRoleD1IntegrationReceiptV1 {
        role,
        retired_epoch: 0,
        retired_revision: 0,
        active_epoch: completed_epoch,
        active_revision: 1,
        cleanup_epoch: cleanup_epoch.get().get(),
        command_receipt_digest_hex: encode_hex(&Sha256::digest(&committed_bytes)),
    })
}

/// The probe's published issuer keyset.
#[cfg(debug_assertions)]
fn tenant_root_creation_probe_issuer_keys(
) -> worker::Result<crate::env::CloudflareTenantRootControlPlaneIssuerVerifyingKeysV1> {
    crate::env::CloudflareTenantRootControlPlaneIssuerVerifyingKeysV1::decode(&format!(
        "{{\"keys\":[{{\"issuer_key_id\":\"{TENANT_ROOT_CREATION_PROBE_ISSUER_KEY_ID_V1}\",\"verifying_key_hex\":\"{}\"}}]}}",
        encode_hex(
            SigningKey::from_bytes(&TENANT_ROOT_CREATION_PROBE_ISSUER_KEY_V1)
                .verifying_key()
                .as_bytes()
        )
    ))
    .map_err(|error| store_error(error.message()))
}

/// The probe's sealing provider descriptors, read from this Worker's own Env.
///
/// These must describe the provider that actually performs the seal, not a
/// fixture's idea of one: a seal request whose declared provider disagrees with
/// the loaded provider is refused, and that check is one of the things this
/// probe exists to exercise.
#[cfg(debug_assertions)]
fn tenant_root_creation_probe_provider_config(
    env: &Env,
    worker_role: crate::CloudflareWorkerRoleV1,
) -> worker::Result<crate::tenant_root_role_runtime::TenantRootRoleRuntimeProviderConfigV1> {
    let reader = crate::CloudflareWorkerEnvReaderV1::new(env);
    let config = crate::env::parse_cloudflare_tenant_root_operational_rotation_provider_config_v1(
        worker_role,
        &reader,
    )
    .map_err(|error| store_error(error.message()))?;
    crate::tenant_root_role_runtime::TenantRootRoleRuntimeProviderConfigV1::new(
        config.online_epoch_wrapping_key_ref(),
        config.backup_provider_id(),
        config.backup_key_version(),
    )
    .map_err(|error| store_error(error.message()))
}

/// The probe's published role keyset, matching the ceremony's key IDs.
#[cfg(debug_assertions)]
fn tenant_root_creation_probe_role_keys(
) -> worker::Result<crate::env::TenantRootCreationRoleVerifyingKeysV1> {
    let entry = |role: CloudflareTenantRootDeriverRoleV1, label: &str| {
        format!(
            "{{\"role\":\"{label}\",\"signing_key_id\":\"{}\",\"verifying_key_hex\":\"{}\"}}",
            tenant_root_role_d1_integration_role_signing_key_id(role),
            encode_hex(
                tenant_root_role_d1_integration_role_signing_key(role)
                    .verifying_key()
                    .as_bytes()
            )
        )
    };
    crate::env::decode_role_verifying_keys(&format!(
        "{{\"keys\":[{},{}]}}",
        entry(CloudflareTenantRootDeriverRoleV1::DeriverA, "deriver_a"),
        entry(CloudflareTenantRootDeriverRoleV1::DeriverB, "deriver_b"),
    ))
    .map_err(|error| store_error(error.message()))
}

/// Control-plane revision an authorized cleanup executes under.
///
/// Cleanup undoes an initial insertion, so it acts at the same control-plane
/// revision that authorized the creation it is clearing.
const TENANT_ROOT_AUTHORIZED_CLEANUP_CONTROL_PLANE_REVISION_V1: u64 = 1;

/// Maps a stored record's role to its protocol role.
fn tenant_root_protocol_role_of(role: CloudflareTenantRootDeriverRoleV1) -> TwoPartyDeriverRole {
    match role {
        CloudflareTenantRootDeriverRoleV1::DeriverA => TwoPartyDeriverRole::DeriverA,
        CloudflareTenantRootDeriverRoleV1::DeriverB => TwoPartyDeriverRole::DeriverB,
    }
}

/// Issuer key used only by the workerd-gated creation probe.
///
/// The probe must produce a genuinely issuer-signed command so the production
/// verification path runs. This key exists only in a debug build behind the
/// integration env flag.
#[cfg(debug_assertions)]
const TENANT_ROOT_CREATION_PROBE_ISSUER_KEY_V1: [u8; 32] = [0x4d; 32];
#[cfg(debug_assertions)]
const TENANT_ROOT_CREATION_PROBE_ISSUER_KEY_ID_V1: &str = "tenant-root-creation-probe-issuer-v1";
#[cfg(debug_assertions)]
const TENANT_ROOT_CREATION_PROBE_ISSUED_AT_MS_V1: u64 = 1_000_000;
#[cfg(debug_assertions)]
const TENANT_ROOT_CREATION_PROBE_EXPIRES_AT_MS_V1: u64 = 1_030_000;

/// Builds the probe's ceremony context, shared by both roles.
#[cfg(debug_assertions)]
fn tenant_root_creation_probe_context(
    session_seed: u8,
) -> worker::Result<router_ab_core::TenantRootCeremonyContextV1> {
    let identity = tenant_root_creation_probe_identity()?;
    router_ab_core::TenantRootCeremonyContextV1::new(
        identity
            .digest()
            .map_err(|error| store_error(error.message()))?,
        TenantRootCustodyLineageId::from_bytes([0x53; 16])
            .map_err(|error| store_error(error.message()))?,
        router_ab_core::TenantRootCeremonyEpochsV1::create(),
        router_ab_core::TenantRootCeremonySessionIdV1::from_bytes([session_seed; 16])
            .map_err(|error| store_error(error.message()))?,
        router_ab_core::TenantRootCeremonyNonceV1::from_bytes([session_seed ^ 0x0f; 32])
            .map_err(|error| store_error(error.message()))?,
        TENANT_ROOT_CREATION_PROBE_ISSUED_AT_MS_V1,
        TENANT_ROOT_CREATION_PROBE_EXPIRES_AT_MS_V1,
        tenant_root_role_d1_integration_role_signing_key_id(
            CloudflareTenantRootDeriverRoleV1::DeriverA,
        ),
        tenant_root_role_d1_integration_role_signing_key_id(
            CloudflareTenantRootDeriverRoleV1::DeriverB,
        ),
    )
    .map_err(|error| store_error(error.message()))
}

#[cfg(debug_assertions)]
fn tenant_root_creation_probe_identity() -> worker::Result<TenantRootIdentityV1> {
    TenantRootIdentityV1::new(
        "r120-creation-probe-org",
        "r120-creation-probe-project",
        "workerd",
        "r120-creation-probe-root",
        "v1",
    )
    .map_err(|error| store_error(error.message()))
}

/// Signs and verifies one role's creation command, as the issuer would.
#[cfg(debug_assertions)]
fn tenant_root_creation_probe_signed_command(
    role: TwoPartyDeriverRole,
    journal: &router_ab_core::TenantRootCreationJournalV1,
    context: &router_ab_core::TenantRootCeremonyContextV1,
    authority_id: router_ab_core::TenantRootControlPlaneAuthorityIdV1,
) -> worker::Result<router_ab_core::TenantRootRoleCreationCommandV1> {
    router_ab_core::TenantRootRoleCreationCommandV1::sign(
        journal,
        context,
        role,
        authority_id,
        TENANT_ROOT_CREATION_PROBE_ISSUED_AT_MS_V1 + 1,
        TENANT_ROOT_CREATION_PROBE_EXPIRES_AT_MS_V1 - 1,
        TENANT_ROOT_CREATION_PROBE_ISSUER_KEY_ID_V1,
        &TENANT_ROOT_CREATION_PROBE_ISSUER_KEY_V1,
    )
    .map_err(|error| store_error(error.message()))
}

#[cfg(debug_assertions)]
fn tenant_root_creation_probe_cleanup_authorization(
    pending: &CloudflareStoredTenantRootRoleShareV1,
    authorized_role: TwoPartyDeriverRole,
    expected_revision: i64,
    session_id: TenantRootCeremonySessionIdV1,
    ceremony_nonce: TenantRootCeremonyNonceV1,
    cleanup_nonce_seed: u8,
) -> worker::Result<VerifiedTenantRootRoleCleanupCommandV1> {
    let installation_evidence_digest = TenantRootProtocolDigestV1::from_bytes(
        *record_installation_evidence_digest(&pending.record)?.as_bytes(),
    )
    .map_err(|error| store_error(error.message()))?;
    let target = router_ab_core::TenantRootRoleCleanupTargetV1 {
        identity_digest: pending
            .record
            .identity()
            .digest()
            .map_err(|error| store_error(error.message()))?,
        custody_lineage: pending.record.custody_lineage(),
        role: authorized_role,
        epoch: pending.record.epoch(),
        expected_row_revision: expected_revision,
        session_id,
        ceremony_nonce,
        installation_evidence_digest,
    };
    let cleanup_nonce = TenantRootCeremonyNonceV1::from_bytes([cleanup_nonce_seed; 32])
        .map_err(|error| store_error(error.message()))?;
    let issuer_signing_key = SigningKey::from_bytes(&TENANT_ROOT_CREATION_PROBE_ISSUER_KEY_V1);
    let signed = router_ab_core::TenantRootRoleCleanupCommandV1::sign(
        &target,
        router_ab_core::TenantRootControlPlaneAuthorityIdV1::from_bytes([0x56; 32]),
        cleanup_nonce,
        TENANT_ROOT_CREATION_PROBE_ISSUED_AT_MS_V1 + 1,
        TENANT_ROOT_CREATION_PROBE_EXPIRES_AT_MS_V1 - 1,
        TENANT_ROOT_CREATION_PROBE_ISSUER_KEY_ID_V1,
        issuer_signing_key.as_bytes(),
    )
    .map_err(|error| store_error(error.message()))?;
    signed
        .verify(
            &target,
            authorized_role,
            router_ab_core::TenantRootControlPlaneAuthorityIdV1::from_bytes([0x56; 32]),
            TENANT_ROOT_CREATION_PROBE_ISSUER_KEY_ID_V1,
            issuer_signing_key.verifying_key().as_bytes(),
        )
        .map_err(|error| store_error(error.message()))
}

#[cfg(debug_assertions)]
fn tenant_root_creation_probe_protocol_role(
    role: CloudflareTenantRootDeriverRoleV1,
) -> TwoPartyDeriverRole {
    match role {
        CloudflareTenantRootDeriverRoleV1::DeriverA => TwoPartyDeriverRole::DeriverA,
        CloudflareTenantRootDeriverRoleV1::DeriverB => TwoPartyDeriverRole::DeriverB,
    }
}

#[cfg(debug_assertions)]
fn tenant_root_role_d1_integration_role_signing_key(
    role: CloudflareTenantRootDeriverRoleV1,
) -> SigningKey {
    let seed = match role {
        CloudflareTenantRootDeriverRoleV1::DeriverA => 0xa7,
        CloudflareTenantRootDeriverRoleV1::DeriverB => 0xb7,
    };
    SigningKey::from_bytes(&[seed; 32])
}

#[cfg(debug_assertions)]
const fn tenant_root_role_d1_integration_role_signing_key_id(
    role: CloudflareTenantRootDeriverRoleV1,
) -> &'static str {
    match role {
        CloudflareTenantRootDeriverRoleV1::DeriverA => "r120-integration-deriver-a-command-key-v1",
        CloudflareTenantRootDeriverRoleV1::DeriverB => "r120-integration-deriver-b-command-key-v1",
    }
}

#[cfg(debug_assertions)]
fn tenant_root_role_d1_integration_success_receipt(
    role: CloudflareTenantRootDeriverRoleV1,
    executed: &ExecutedTenantRootCommandV1,
    payload: &[u8],
    terminal_at_ms: u64,
) -> worker::Result<VerifiedTenantRootCommandSuccessReceiptV1> {
    let signing_key = tenant_root_role_d1_integration_role_signing_key(role);
    let role_signing_key_id = tenant_root_role_d1_integration_role_signing_key_id(role);
    let signed = TenantRootCommandTerminalReceiptV1::sign_success(
        *executed.key(),
        executed.command_digest(),
        payload.to_vec(),
        terminal_at_ms,
        role_signing_key_id,
        signing_key.as_bytes(),
    )
    .map_err(|error| store_error(error.message()))?;
    let canonical_bytes = signed
        .canonical_bytes()
        .map_err(|error| store_error(error.message()))?;
    let decoded = TenantRootCommandTerminalReceiptV1::decode_canonical_bytes(&canonical_bytes)
        .map_err(|error| store_error(error.message()))?;
    decoded
        .verify_success(
            executed,
            role_signing_key_id,
            signing_key.verifying_key().as_bytes(),
        )
        .map_err(|error| store_error(error.message()))
}

#[cfg(debug_assertions)]
fn tenant_root_role_d1_integration_failure_receipt(
    role: CloudflareTenantRootDeriverRoleV1,
    reservation: &ReservedTenantRootCommandV1,
    payload: &[u8],
    terminal_at_ms: u64,
) -> worker::Result<VerifiedTenantRootCommandFailureReceiptV1> {
    let signing_key = tenant_root_role_d1_integration_role_signing_key(role);
    let role_signing_key_id = tenant_root_role_d1_integration_role_signing_key_id(role);
    let signed = TenantRootCommandTerminalReceiptV1::sign_failure(
        *reservation.key(),
        reservation.command_digest(),
        payload.to_vec(),
        terminal_at_ms,
        role_signing_key_id,
        signing_key.as_bytes(),
    )
    .map_err(|error| store_error(error.message()))?;
    let canonical_bytes = signed
        .canonical_bytes()
        .map_err(|error| store_error(error.message()))?;
    let decoded = TenantRootCommandTerminalReceiptV1::decode_canonical_bytes(&canonical_bytes)
        .map_err(|error| store_error(error.message()))?;
    decoded
        .verify_failure(
            reservation,
            role_signing_key_id,
            signing_key.verifying_key().as_bytes(),
        )
        .map_err(|error| store_error(error.message()))
}

#[cfg(debug_assertions)]
fn tenant_root_role_d1_integration_pending_record(
    role: CloudflareTenantRootDeriverRoleV1,
    epoch: u64,
    marker: u8,
    at_ms: u64,
) -> worker::Result<CloudflareTenantRootRoleShareRecordV1> {
    let identity = TenantRootIdentityV1::new(
        "r120-integration-org",
        "r120-integration-project",
        "workerd",
        "r120-integration-root",
        "v1",
    )
    .map_err(|error| store_error(error.message()))?;
    let custody_lineage = TenantRootCustodyLineageId::from_bytes([0x52; 16])
        .map_err(|error| store_error(error.message()))?;
    let epoch = TenantRootShareEpoch::new(epoch).map_err(|error| store_error(error.message()))?;
    let share_commitment = tenant_root_role_d1_integration_commitment(role, epoch)?;
    CloudflareTenantRootRoleShareRecordV1::new(CloudflareTenantRootRoleShareRecordInputV1 {
        identity,
        custody_lineage,
        epoch,
        role,
        sealed_share: CloudflareTenantRootSealedRoleShareV1::new(&[marker; 96])?,
        share_commitment,
        epoch_wrapping_key_ref: format!("workerd://tenant-root/{}", epoch.get()),
        lifecycle: CloudflareTenantRootRoleShareLifecycleV1::Pending(
            CloudflareTenantRootPendingShareV1::from_stored_digest(
                lifecycle_receipt(marker)?,
                at_ms,
            )?,
        ),
        created_at_ms: at_ms,
        updated_at_ms: at_ms,
    })
}

#[cfg(debug_assertions)]
fn tenant_root_role_d1_integration_commitment(
    role: CloudflareTenantRootDeriverRoleV1,
    epoch: TenantRootShareEpoch,
) -> worker::Result<MpcPrfShareCommitmentWireV1> {
    let point = match (epoch, role) {
        (TenantRootShareEpoch::INITIAL, CloudflareTenantRootDeriverRoleV1::DeriverA) => {
            INTEGRATION_EPOCH_ONE_DERIVER_A_POINT_V1
        }
        (TenantRootShareEpoch::INITIAL, CloudflareTenantRootDeriverRoleV1::DeriverB) => {
            INTEGRATION_EPOCH_ONE_DERIVER_B_POINT_V1
        }
        (_, CloudflareTenantRootDeriverRoleV1::DeriverA) => {
            INTEGRATION_EPOCH_TWO_DERIVER_A_POINT_V1
        }
        (_, CloudflareTenantRootDeriverRoleV1::DeriverB) => {
            INTEGRATION_EPOCH_TWO_DERIVER_B_POINT_V1
        }
    };
    let mut bytes = Vec::with_capacity(34);
    bytes.extend_from_slice(&role.share_id().to_be_bytes());
    bytes.extend_from_slice(&point);
    MpcPrfShareCommitmentWireV1::new(bytes).map_err(|error| store_error(error.message()))
}

#[cfg(debug_assertions)]
fn tenant_root_role_d1_integration_scope(
    record: &CloudflareTenantRootRoleShareRecordV1,
    session_seed: u8,
    nonce_seed: u8,
    expected_control_plane_revision: u64,
) -> worker::Result<TenantRootCommandScopeV1> {
    let identity_digest = record
        .identity
        .digest()
        .map_err(|error| store_error(error.message()))?;
    let session_id = TenantRootCeremonySessionIdV1::from_bytes([session_seed; 16])
        .map_err(|error| store_error(error.message()))?;
    let nonce = TenantRootCeremonyNonceV1::from_bytes([nonce_seed; 32])
        .map_err(|error| store_error(error.message()))?;
    let key = match record.role {
        CloudflareTenantRootDeriverRoleV1::DeriverA => TenantRootCommandReplayKeyV1::deriver_a(
            identity_digest,
            record.custody_lineage,
            session_id,
            nonce,
        ),
        CloudflareTenantRootDeriverRoleV1::DeriverB => TenantRootCommandReplayKeyV1::deriver_b(
            identity_digest,
            record.custody_lineage,
            session_id,
            nonce,
        ),
    };
    TenantRootCommandScopeV1::new(key, record.epoch, expected_control_plane_revision)
        .map_err(|error| store_error(error.message()))
}

#[cfg(debug_assertions)]
fn tenant_root_role_d1_integration_activation(
    record: &CloudflareTenantRootRoleShareRecordV1,
    at_ms: u64,
) -> worker::Result<CloudflareTenantRootActivationV1> {
    let _ = (record, at_ms);
    Err(store_error(
        "tenant-root role-private D1 integration requires a verified activation evidence bundle",
    ))
}

#[cfg(debug_assertions)]
fn require_integration_failure<T>(
    result: worker::Result<T>,
    message: &'static str,
) -> worker::Result<()> {
    if result.is_ok() {
        return Err(store_error(message));
    }
    Ok(())
}

fn record_metadata(
    record: &CloudflareTenantRootRoleShareRecordV1,
) -> worker::Result<TenantRootRoleD1MetadataV1> {
    Ok(TenantRootRoleD1MetadataV1 {
        identity_digest_hex: record.identity_digest_hex()?,
        custody_lineage_b64u: record.custody_lineage.to_base64url(),
        epoch: record.epoch.get().get(),
        role: record.role,
        lifecycle: record.lifecycle.as_str().to_owned(),
    })
}

fn serialize_activation_receipt_bytes<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&encode_base64url_bytes_v1(bytes))
}

fn decode_activation_receipt_bytes(
    bytes: &[u8],
) -> worker::Result<TenantRootSignedActivationReceiptV1> {
    if bytes.is_empty() || bytes.len() > TENANT_ROOT_ACTIVATION_RECEIPT_MAX_BYTES_V1 {
        return Err(store_error(
            "tenant-root activation receipt bytes have an invalid length",
        ));
    }
    let receipt = TenantRootSignedActivationReceiptV1::decode_canonical_bytes(bytes)
        .map_err(|error| store_error(error.message()))?;
    let canonical_bytes = receipt
        .canonical_bytes()
        .map_err(|error| store_error(error.message()))?;
    if canonical_bytes != bytes {
        return Err(store_error(
            "tenant-root activation receipt bytes are not canonical",
        ));
    }
    Ok(receipt)
}

fn accepted_loss_availability_from_verified_receipt(
    activation: &VerifiedTenantRootSignedActivationReceiptV1,
    role: TenantRootManagedRestoreRoleV1,
) -> worker::Result<CloudflareTenantRootAvailabilityEvidenceV1> {
    let (authorization, authorization_digest) =
        accepted_loss_authorization_from_binding(activation.binding())?;
    validate_accepted_loss_authorization_against_activation(activation.binding(), &authorization)?;
    Ok(
        CloudflareTenantRootAvailabilityEvidenceV1::AcceptedPermanentDerivationLoss {
            authorization_digest,
            identity_digest: activation.identity_digest(),
            custody_lineage: activation.custody_lineage(),
            role,
            epoch: activation_target_epoch(activation.binding()),
            share_commitment: activation_target_commitment(activation.binding(), role).clone(),
        },
    )
}

fn accepted_loss_authorization_from_binding(
    binding: &TenantRootActivationReceiptBindingV1,
) -> worker::Result<(
    TenantRootSignedAcceptedPermanentLossAuthorizationV1,
    TenantRootAcceptedPermanentLossAuthorizationDigestV1,
)> {
    let TenantRootActivationReceiptAvailabilityV1::AcceptedPermanentDerivationLoss {
        authorization_bytes,
        authorization_digest,
    } = binding.availability()
    else {
        return Err(store_error(
            "tenant-root activation receipt does not carry accepted-loss authorization",
        ));
    };
    let authorization =
        TenantRootSignedAcceptedPermanentLossAuthorizationV1::decode_canonical_bytes(
            authorization_bytes,
        )
        .map_err(|error| store_error(error.message()))?;
    if authorization
        .digest()
        .map_err(|error| store_error(error.message()))?
        != *authorization_digest
    {
        return Err(store_error(
            "tenant-root accepted-loss authorization digest does not match its bytes",
        ));
    }
    Ok((authorization, *authorization_digest))
}

fn validate_accepted_loss_authorization_against_activation(
    binding: &TenantRootActivationReceiptBindingV1,
    authorization: &TenantRootSignedAcceptedPermanentLossAuthorizationV1,
) -> worker::Result<()> {
    if authorization.identity_digest() != binding.identity_digest()
        || authorization.custody_lineage() != binding.custody_lineage()
        || authorization.transition() != binding.transition()
        || authorization.target_epoch() != activation_target_epoch(binding)
        || authorization.context_digest() != binding.context_digest()
        || authorization.commitments() != activation_target_commitments(binding)
        || authorization.installation_receipts() != activation_installation_receipts(binding)
        || authorization.expected_control_plane_revision()
            != binding.expected_control_plane_revision()
        || authorization.result_control_plane_revision() != binding.result_control_plane_revision()
        || authorization.issued_at_ms() != binding.issued_at_ms()
        || authorization.expires_at_ms() != binding.expires_at_ms()
    {
        return Err(store_error(
            "tenant-root accepted-loss authorization does not match activation receipt binding",
        ));
    }
    Ok(())
}

fn validate_activation_receipt_against_backup(
    activation: &VerifiedTenantRootSignedActivationReceiptV1,
    backup: &VerifiedTenantRootManagedBackupV1,
) -> worker::Result<()> {
    let binding = activation.binding();
    if binding.identity_digest() != backup.identity_digest()
        || binding.custody_lineage() != backup.custody_lineage()
    {
        return Err(store_error(
            "tenant-root activation receipt identity binding does not match managed backup",
        ));
    }
    if activation_target_epoch(binding) != backup.epoch()
        || activation_target_commitment(binding, backup.role()) != backup.share_commitment()
        || activation_installation_receipt(binding, backup.role())
            != backup.installation_receipt_digest()
        || activation_backup_receipt(binding, backup.role())? != backup.receipt_digest()
    {
        return Err(store_error(
            "tenant-root activation receipt binding does not match managed backup",
        ));
    }
    Ok(())
}

fn validate_activation_receipt_against_record(
    activation_receipt_bytes: &[u8],
    record: &CloudflareTenantRootRoleShareRecordV1,
    availability: &CloudflareTenantRootAvailabilityEvidenceV1,
) -> worker::Result<()> {
    let receipt = decode_activation_receipt_bytes(activation_receipt_bytes)?;
    let binding = receipt.binding();
    let role = record.role.managed_restore_role();
    let record_identity = record
        .identity
        .digest()
        .map_err(|error| store_error(error.message()))?;
    let expected_transition = if record.epoch == TenantRootShareEpoch::INITIAL {
        TenantRootActivationReceiptTransitionV1::InitialCreation
    } else {
        TenantRootActivationReceiptTransitionV1::RefreshSwap
    };
    if binding.identity_digest() != record_identity
        || binding.custody_lineage() != record.custody_lineage
        || binding.transition() != expected_transition
        || activation_target_epoch(binding) != record.epoch
        || activation_target_commitment(binding, role) != &record.share_commitment
        || activation_installation_receipt(binding, role)
            != record_installation_evidence_digest(record)?
    {
        return Err(store_error(
            "tenant-root activation receipt binding does not match the role-share record",
        ));
    }
    match availability {
        CloudflareTenantRootAvailabilityEvidenceV1::CurrentRoleBackup {
            role_backup_receipt_digest,
            identity_digest,
            custody_lineage,
            role: availability_role,
            epoch,
            share_commitment,
        } => {
            if *identity_digest != record_identity
                || *custody_lineage != record.custody_lineage
                || *availability_role != role
                || *epoch != record.epoch
                || share_commitment != &record.share_commitment
                || activation_backup_receipt(binding, role)? != *role_backup_receipt_digest
            {
                return Err(store_error(
                    "tenant-root activation backup evidence does not match the role-share record",
                ));
            }
        }
        CloudflareTenantRootAvailabilityEvidenceV1::AcceptedPermanentDerivationLoss {
            authorization_digest,
            identity_digest,
            custody_lineage,
            role: availability_role,
            epoch,
            share_commitment,
        } => {
            if *identity_digest != record_identity
                || *custody_lineage != record.custody_lineage
                || *availability_role != role
                || *epoch != record.epoch
                || share_commitment != &record.share_commitment
            {
                return Err(store_error(
                    "tenant-root accepted-loss evidence does not match the role-share record",
                ));
            }
            let (authorization, receipt_digest) =
                accepted_loss_authorization_from_binding(binding)?;
            if receipt_digest != *authorization_digest {
                return Err(store_error(
                    "tenant-root accepted-loss authorization digest does not match its projection",
                ));
            }
            validate_accepted_loss_authorization_against_activation(binding, &authorization)?;
        }
    }
    Ok(())
}

fn validate_activation_receipt_against_swap_records(
    activation: &CloudflareTenantRootActivationV1,
    active: &CloudflareStoredTenantRootRoleShareV1,
    pending: &CloudflareStoredTenantRootRoleShareV1,
) -> worker::Result<()> {
    let receipt = decode_activation_receipt_bytes(&activation.activation_receipt_bytes)?;
    let TenantRootActivationReceiptBindingV1::RefreshSwap(binding) = receipt.binding() else {
        return Err(store_error(
            "tenant-root epoch swap requires a refresh activation receipt",
        ));
    };
    let active_identity = active
        .record
        .identity
        .digest()
        .map_err(|error| store_error(error.message()))?;
    let pending_identity = pending
        .record
        .identity
        .digest()
        .map_err(|error| store_error(error.message()))?;
    let active_role = active.record.role.managed_restore_role();
    let pending_role = pending.record.role.managed_restore_role();
    if active_identity != pending_identity
        || binding.identity_digest() != pending_identity
        || binding.custody_lineage() != pending.record.custody_lineage
        || binding.current_epoch() != active.record.epoch
        || binding.next_epoch() != pending.record.epoch
        || active_role != pending_role
        || activation_role_commitment(binding.current_commitments(), active_role)
            != &active.record.share_commitment
        || activation_role_commitment(binding.next_commitments(), pending_role)
            != &pending.record.share_commitment
    {
        return Err(store_error(
            "tenant-root refresh activation receipt does not match the epoch swap records",
        ));
    }
    Ok(())
}

fn activation_target_epoch(binding: &TenantRootActivationReceiptBindingV1) -> TenantRootShareEpoch {
    match binding {
        TenantRootActivationReceiptBindingV1::InitialCreation(_) => TenantRootShareEpoch::INITIAL,
        TenantRootActivationReceiptBindingV1::RefreshSwap(binding) => binding.next_epoch(),
    }
}

fn activation_target_commitment(
    binding: &TenantRootActivationReceiptBindingV1,
    role: TenantRootManagedRestoreRoleV1,
) -> &MpcPrfShareCommitmentWireV1 {
    activation_role_commitment(activation_target_commitments(binding), role)
}

fn activation_target_commitments(
    binding: &TenantRootActivationReceiptBindingV1,
) -> &TenantRootEpochCommitmentsV1 {
    match binding {
        TenantRootActivationReceiptBindingV1::InitialCreation(binding) => binding.commitments(),
        TenantRootActivationReceiptBindingV1::RefreshSwap(binding) => binding.next_commitments(),
    }
}

fn activation_role_commitment(
    commitments: &TenantRootEpochCommitmentsV1,
    role: TenantRootManagedRestoreRoleV1,
) -> &MpcPrfShareCommitmentWireV1 {
    match role {
        TenantRootManagedRestoreRoleV1::DeriverA => commitments.deriver_a(),
        TenantRootManagedRestoreRoleV1::DeriverB => commitments.deriver_b(),
    }
}

fn activation_installation_receipt(
    binding: &TenantRootActivationReceiptBindingV1,
    role: TenantRootManagedRestoreRoleV1,
) -> TenantRootLifecycleReceiptDigestV1 {
    let receipts = activation_installation_receipts(binding);
    match role {
        TenantRootManagedRestoreRoleV1::DeriverA => receipts.deriver_a(),
        TenantRootManagedRestoreRoleV1::DeriverB => receipts.deriver_b(),
    }
}

fn activation_installation_receipts(
    binding: &TenantRootActivationReceiptBindingV1,
) -> TenantRootRoleInstallationReceiptsV1 {
    match binding {
        TenantRootActivationReceiptBindingV1::InitialCreation(binding) => {
            binding.installation_receipts()
        }
        TenantRootActivationReceiptBindingV1::RefreshSwap(binding) => {
            binding.installation_receipts()
        }
    }
}

fn activation_backup_receipt(
    binding: &TenantRootActivationReceiptBindingV1,
    role: TenantRootManagedRestoreRoleV1,
) -> worker::Result<TenantRootLifecycleReceiptDigestV1> {
    let availability = match binding {
        TenantRootActivationReceiptBindingV1::InitialCreation(binding) => binding.availability(),
        TenantRootActivationReceiptBindingV1::RefreshSwap(binding) => binding.availability(),
    };
    let receipts = match availability {
        TenantRootActivationReceiptAvailabilityV1::CurrentRoleBackups { receipts, .. } => *receipts,
        TenantRootActivationReceiptAvailabilityV1::AcceptedPermanentDerivationLoss { .. } => {
            return Err(store_error(
                "tenant-root activation receipt does not carry current-backup evidence",
            ));
        }
    };
    Ok(match role {
        TenantRootManagedRestoreRoleV1::DeriverA => receipts.deriver_a(),
        TenantRootManagedRestoreRoleV1::DeriverB => receipts.deriver_b(),
    })
}

fn record_installation_evidence_digest(
    record: &CloudflareTenantRootRoleShareRecordV1,
) -> worker::Result<TenantRootLifecycleReceiptDigestV1> {
    match &record.lifecycle {
        CloudflareTenantRootRoleShareLifecycleV1::Pending(pending) => {
            Ok(pending.installation_evidence_digest)
        }
        CloudflareTenantRootRoleShareLifecycleV1::Active(active) => {
            Ok(active.pending.installation_evidence_digest)
        }
        CloudflareTenantRootRoleShareLifecycleV1::Retired(retired) => {
            Ok(retired.active.pending.installation_evidence_digest)
        }
    }
}

const TENANT_ROOT_ROLE_COMMAND_PAYLOAD_DOMAIN_V1: &[u8] =
    b"seams/tenant-root-role-command-payload/v1";
const TENANT_ROOT_REFRESH_INSERT_PENDING_PAYLOAD_DOMAIN_V1: &[u8] =
    b"seams/tenant-root-refresh-insert-pending-payload/v1";
const TENANT_ROOT_AUTHORIZED_CLEANUP_PAYLOAD_DOMAIN_V1: &[u8] =
    b"seams/tenant-root-authorized-cleanup-payload/v1";

fn validate_command_scope_for_record(
    scope: &TenantRootCommandScopeV1,
    record: &CloudflareTenantRootRoleShareRecordV1,
    expected_revision: i64,
    operation: &'static str,
) -> worker::Result<()> {
    let identity_digest = record
        .identity
        .digest()
        .map_err(|error| store_error(error.message()))?;
    if scope.key().identity_digest() != identity_digest
        || scope.key().custody_lineage() != record.custody_lineage
        || scope.key().role().as_str() != record.role.as_str()
        || scope.epoch() != record.epoch
    {
        return Err(store_error(format!(
            "{operation} command scope does not match its role-share record"
        )));
    }
    if expected_revision <= 0 {
        return Err(store_error(format!(
            "{operation} command has an invalid local row revision"
        )));
    }
    // Authority must be established by the caller before this module-private
    // helper accepts the scope; a raw scope does not establish issuer authority.
    let _ = scope.expected_control_plane_revision();
    Ok(())
}

#[allow(dead_code)]
fn initial_creation_scope_for_record(
    command: &VerifiedTenantRootRoleCreationCommandV1,
    record: &CloudflareTenantRootRoleShareRecordV1,
    reserved_at_ms: u64,
) -> worker::Result<TenantRootCommandScopeV1> {
    command
        .require_fresh(reserved_at_ms)
        .map_err(|error| store_error(error.message()))?;
    initial_creation_scope_without_freshness(command, record)
}

#[allow(dead_code)]
fn initial_creation_scope_without_freshness(
    command: &VerifiedTenantRootRoleCreationCommandV1,
    record: &CloudflareTenantRootRoleShareRecordV1,
) -> worker::Result<TenantRootCommandScopeV1> {
    let scope = command.scope();
    validate_command_scope_for_record(&scope, record, 1, "tenant-root initial role creation")?;
    Ok(scope)
}

#[allow(dead_code)]
fn cloudflare_role_for_protocol(
    role: TwoPartyDeriverRole,
) -> worker::Result<CloudflareTenantRootDeriverRoleV1> {
    Ok(match role {
        TwoPartyDeriverRole::DeriverA => CloudflareTenantRootDeriverRoleV1::DeriverA,
        TwoPartyDeriverRole::DeriverB => CloudflareTenantRootDeriverRoleV1::DeriverB,
    })
}

fn protocol_role_for_cloudflare(role: CloudflareTenantRootDeriverRoleV1) -> TwoPartyDeriverRole {
    match role {
        CloudflareTenantRootDeriverRoleV1::DeriverA => TwoPartyDeriverRole::DeriverA,
        CloudflareTenantRootDeriverRoleV1::DeriverB => TwoPartyDeriverRole::DeriverB,
    }
}

fn validate_initial_creation_role_signer(
    creation: &CloudflareTenantRootInitialCreationInputV1,
    role_signer: &CloudflareTenantRootCreationRoleSignerV1,
) -> worker::Result<()> {
    let role = creation.command.role();
    if role_signer.role() != role {
        return Err(store_error(
            "tenant-root initial creation receipt signer role does not match its command",
        ));
    }
    if role_signer.signing_key_id()
        != creation
            .evidence
            .evidence()
            .transcript()
            .context()
            .signing_key_id(role)
    {
        return Err(store_error(
            "tenant-root initial creation receipt signer key does not match its evidence",
        ));
    }
    Ok(())
}

fn validate_refresh_role_signer(
    refresh: &CloudflareTenantRootRefreshInputV1,
    role_signer: &CloudflareTenantRootCreationRoleSignerV1,
) -> worker::Result<()> {
    let role = refresh.command.role();
    if role_signer.role() != role {
        return Err(store_error(
            "tenant-root refresh receipt signer role does not match its command",
        ));
    }
    if role_signer.signing_key_id()
        != refresh
            .evidence
            .evidence()
            .transcript()
            .context()
            .signing_key_id(role)
    {
        return Err(store_error(
            "tenant-root refresh receipt signer key does not match its evidence",
        ));
    }
    Ok(())
}

#[allow(dead_code)]
fn validate_initial_creation_binding(
    command: &VerifiedTenantRootRoleCreationCommandV1,
    evidence: &VerifiedTenantRootSignedShareInstallationEvidenceWireV1,
    record: &CloudflareTenantRootRoleShareRecordV1,
) -> worker::Result<()> {
    record.validate()?;
    let transcript = evidence.evidence().transcript();
    let context = transcript.context();
    let record_identity = record
        .identity
        .digest()
        .map_err(|error| store_error(error.message()))?;
    let evidence_context_digest = context
        .digest()
        .map_err(|error| store_error(error.message()))?;
    if command.role() != transcript.role() {
        return Err(store_error(
            "tenant-root initial creation evidence role does not match its command",
        ));
    }
    if record.role != cloudflare_role_for_protocol(transcript.role())? {
        return Err(store_error(
            "tenant-root initial creation share role does not match its evidence",
        ));
    }
    if command.identity_digest() != record_identity
        || command.identity_digest() != context.identity_digest()
        || command.custody_lineage() != record.custody_lineage
        || command.custody_lineage() != context.custody_lineage()
        || command.creation_context_digest() != evidence_context_digest
        || command.epoch() != TenantRootShareEpoch::INITIAL
        || record.epoch != TenantRootShareEpoch::INITIAL
    {
        return Err(store_error(
            "tenant-root initial creation command, evidence, and share identity do not match",
        ));
    }
    let evidence_commitment =
        MpcPrfShareCommitmentWireV1::new(transcript.commitment().to_bytes().to_vec())
            .map_err(|error| store_error(error.message()))?;
    if record.share_commitment != evidence_commitment {
        return Err(store_error(
            "tenant-root initial creation share commitment does not match its evidence",
        ));
    }
    let CloudflareTenantRootRoleShareLifecycleV1::Pending(pending) = &record.lifecycle else {
        return Err(store_error(
            "tenant-root initial creation requires a pending role share",
        ));
    };
    let evidence_digest = evidence
        .lifecycle_receipt_digest()
        .map_err(|error| store_error(error.message()))?;
    if pending.installation_evidence_digest != evidence_digest {
        return Err(store_error(
            "tenant-root pending installation evidence digest does not match its exact wire",
        ));
    }
    Ok(())
}

#[allow(dead_code)]
fn validate_initial_creation_success_receipt_payload(
    evidence: &VerifiedTenantRootSignedShareInstallationEvidenceWireV1,
    receipt: &VerifiedTenantRootCommandSuccessReceiptV1,
) -> worker::Result<()> {
    if receipt.payload_bytes() != evidence.canonical_bytes() {
        return Err(store_error(
            "tenant-root initial creation receipt payload does not match its exact evidence wire",
        ));
    }
    Ok(())
}

fn validate_refresh_command_evidence(
    command: &VerifiedTenantRootRoleRefreshCommandV1,
    evidence: &VerifiedTenantRootSignedShareInstallationEvidenceWireV1,
) -> worker::Result<TenantRootLifecycleReceiptDigestV1> {
    let transcript = evidence.evidence().transcript();
    let context = transcript.context();
    let TenantRootCeremonyEpochsV1::Refresh { current, next } = context.epochs() else {
        return Err(store_error(
            "tenant-root refresh installation requires a refresh ceremony context",
        ));
    };
    let context_digest = context
        .digest()
        .map_err(|error| store_error(error.message()))?;
    if command.identity_digest() != context.identity_digest()
        || command.custody_lineage() != context.custody_lineage()
        || command.refresh_context_digest() != context_digest
        || command.current_epoch() != current
        || command.next_epoch() != next
        || command.session_id() != context.session_id()
        || command.nonce() != context.nonce()
        || command.role() != transcript.role()
    {
        return Err(store_error(
            "tenant-root refresh command and installation evidence do not match",
        ));
    }
    evidence
        .lifecycle_receipt_digest()
        .map_err(|error| store_error(error.message()))
}

fn validate_refresh_sealed_binding(
    command: &VerifiedTenantRootRoleRefreshCommandV1,
    evidence: &VerifiedTenantRootSignedShareInstallationEvidenceWireV1,
    sealed_binding: &TenantRootOnlineRoleShareBindingV1,
    share_identity_digest: TenantRootIdentityDigestV1,
    evidence_digest: TenantRootLifecycleReceiptDigestV1,
) -> worker::Result<()> {
    let transcript = evidence.evidence().transcript();
    let evidence_commitment =
        MpcPrfShareCommitmentWireV1::new(transcript.commitment().to_bytes().to_vec())
            .map_err(|error| store_error(error.message()))?;
    if share_identity_digest != command.identity_digest()
        || sealed_binding.identity_digest() != share_identity_digest
        || sealed_binding.custody_lineage() != command.custody_lineage()
        || sealed_binding.role() != command.role()
        || sealed_binding.epoch() != command.next_epoch()
        || sealed_binding.share_commitment() != &evidence_commitment
        || sealed_binding.installation_evidence_digest() != evidence_digest
    {
        return Err(store_error(
            "tenant-root refresh sealed share does not match its command and evidence",
        ));
    }
    Ok(())
}

fn validate_refresh_record_binding(
    command: &VerifiedTenantRootRoleRefreshCommandV1,
    evidence: &VerifiedTenantRootSignedShareInstallationEvidenceWireV1,
    record: &CloudflareTenantRootRoleShareRecordV1,
) -> worker::Result<()> {
    let evidence_digest = validate_refresh_command_evidence(command, evidence)?;
    let transcript = evidence.evidence().transcript();
    let evidence_commitment =
        MpcPrfShareCommitmentWireV1::new(transcript.commitment().to_bytes().to_vec())
            .map_err(|error| store_error(error.message()))?;
    let identity_digest = record
        .identity
        .digest()
        .map_err(|error| store_error(error.message()))?;
    let expected_role = cloudflare_role_for_protocol(command.role())?;
    let CloudflareTenantRootRoleShareLifecycleV1::Pending(pending) = &record.lifecycle else {
        return Err(store_error(
            "tenant-root refresh insertion requires a pending role share",
        ));
    };
    if identity_digest != command.identity_digest()
        || record.custody_lineage != command.custody_lineage()
        || record.epoch != command.next_epoch()
        || record.role != expected_role
        || record.share_commitment != evidence_commitment
        || pending.installation_evidence_digest() != evidence_digest
    {
        return Err(store_error(
            "tenant-root refresh role-share record does not match its command and evidence",
        ));
    }
    record.validate()
}

fn validate_refresh_success_receipt_payload(
    evidence: &VerifiedTenantRootSignedShareInstallationEvidenceWireV1,
    receipt: &VerifiedTenantRootCommandSuccessReceiptV1,
) -> worker::Result<()> {
    if receipt.payload_bytes() != evidence.canonical_bytes() {
        return Err(store_error(
            "tenant-root refresh receipt payload does not match its exact evidence wire",
        ));
    }
    Ok(())
}

fn validate_reserved_command(
    scope: &TenantRootCommandScopeV1,
    reservation: &ReservedTenantRootCommandV1,
    operation: TenantRootCommandOperationV1,
    operation_name: &'static str,
) -> worker::Result<()> {
    let command_digest = scope
        .command_digest(operation)
        .map_err(|error| store_error(error.message()))?;
    if reservation.key() != scope.key() || reservation.command_digest() != command_digest {
        return Err(store_error(format!(
            "{operation_name} command does not match its authority reservation"
        )));
    }
    Ok(())
}

fn decode_stored_terminal_receipt(
    terminal_kind: TenantRootCommandTerminalKindV1,
    receipt_b64u: Option<&str>,
    receipt_digest_hex: Option<&str>,
    terminal_at_ms: Option<i64>,
    key: TenantRootCommandReplayKeyV1,
    command_digest: TenantRootProtocolDigestV1,
) -> worker::Result<DecodedTenantRootCommandTerminalReceiptV1> {
    let receipt_b64u = receipt_b64u
        .ok_or_else(|| store_error("terminal tenant-root command row omitted receipt bytes"))?;
    let receipt_bytes = decode_base64url_bytes_v1("tenant-root command receipt", receipt_b64u)
        .map_err(|error| store_error(error.message()))?;
    if receipt_bytes.is_empty()
        || receipt_bytes.len() > TENANT_ROOT_COMMAND_TERMINAL_RECEIPT_MAX_BYTES_V1
        || encode_base64url_bytes_v1(&receipt_bytes) != receipt_b64u
    {
        return Err(store_error(
            "terminal tenant-root command receipt bytes are malformed",
        ));
    }

    // D1 stores the signed bytes without a role verifier. The receipt consumer
    // verifies Ed25519 with the retained role key after this canonical binding.
    let receipt = TenantRootCommandTerminalReceiptV1::decode_canonical_bytes(&receipt_bytes)
        .map_err(|error| store_error(error.message()))?;
    let canonical_bytes = receipt
        .canonical_bytes()
        .map_err(|error| store_error(error.message()))?;
    if canonical_bytes != receipt_bytes {
        return Err(store_error(
            "terminal tenant-root command receipt bytes are not canonical",
        ));
    }
    if receipt.outcome() != terminal_kind.expected_outcome() {
        return Err(store_error(
            "terminal tenant-root command receipt outcome conflicts with durable status",
        ));
    }
    if receipt.key() != &key {
        return Err(store_error(
            "terminal tenant-root command receipt replay key conflicts with durable state",
        ));
    }
    if receipt.command_digest() != command_digest {
        return Err(store_error(
            "terminal tenant-root command receipt command digest conflicts with durable state",
        ));
    }
    let receipt_digest = TenantRootProtocolDigestV1::from_bytes(decode_lower_hex_fixed::<32>(
        "tenant-root command receipt digest",
        receipt_digest_hex.ok_or_else(|| {
            store_error("terminal tenant-root command row omitted receipt digest")
        })?,
    )?)
    .map_err(|error| store_error(error.message()))?;
    let decoded_receipt_digest = receipt
        .digest()
        .map_err(|error| store_error(error.message()))?;
    if decoded_receipt_digest != receipt_digest {
        return Err(store_error(
            "terminal tenant-root command receipt digest conflicts with durable state",
        ));
    }
    let terminal_at_ms = positive_u64_from_i64(
        "tenant-root command terminal timestamp",
        terminal_at_ms.ok_or_else(|| {
            store_error("terminal tenant-root command row omitted terminal timestamp")
        })?,
    )?;
    if receipt.terminal_at_ms() != terminal_at_ms {
        return Err(store_error(
            "terminal tenant-root command receipt timestamp conflicts with durable state",
        ));
    }

    Ok(DecodedTenantRootCommandTerminalReceiptV1 {
        receipt_bytes,
        receipt_digest,
        terminal_at_ms,
    })
}

fn replay_reservation_from_stored(
    stored: &StoredTenantRootCommandReplayV1,
) -> worker::Result<ReservedTenantRootCommandV1> {
    if !matches!(&stored.record, TenantRootCommandReplayRecordV1::Reserved(_)) {
        return Err(store_error(
            "tenant-root replay row is not resumable as a reservation",
        ));
    }
    fresh_reservation_from_stored(stored)
}

fn replay_executed_from_stored(
    stored: &StoredTenantRootCommandReplayV1,
) -> worker::Result<ExecutedTenantRootCommandV1> {
    if !matches!(&stored.record, TenantRootCommandReplayRecordV1::Executed(_)) {
        return Err(store_error(
            "tenant-root replay row is not resumable as an executed command",
        ));
    }
    let executed_at_ms = stored.executed_at_ms.ok_or_else(|| {
        store_error("executed tenant-root replay row omitted execution timestamp")
    })?;
    fresh_reservation_from_stored(stored)?
        .checkpoint_executed(executed_at_ms)
        .map_err(|error| store_error(error.message()))
}

fn fresh_reservation_from_stored(
    stored: &StoredTenantRootCommandReplayV1,
) -> worker::Result<ReservedTenantRootCommandV1> {
    let key = *stored.record.key();
    let command_digest = stored.record.command_digest();
    match reserve_tenant_root_command_v1(None, key, command_digest, stored.reserved_at_ms)
        .map_err(|error| store_error(error.message()))?
    {
        TenantRootCommandReplayDecisionV1::Execute(reservation) => Ok(reservation),
        _ => Err(store_error(
            "tenant-root replay row could not reconstruct its reservation",
        )),
    }
}

fn insert_pending_payload_digest(
    record: &CloudflareTenantRootRoleShareRecordV1,
    expected_revision: i64,
) -> worker::Result<TenantRootProtocolDigestV1> {
    let mut bytes = command_payload_start("insert_pending")?;
    push_record_public_payload(&mut bytes, record)?;
    push_command_i64(&mut bytes, expected_revision)?;
    finish_command_payload(bytes)
}

fn refresh_insert_pending_payload_digest(
    command: &VerifiedTenantRootRoleRefreshCommandV1,
    record: &CloudflareTenantRootRoleShareRecordV1,
    expected_revision: i64,
) -> worker::Result<TenantRootProtocolDigestV1> {
    let row_payload_digest = insert_pending_payload_digest(record, expected_revision)?;
    let mut bytes = Vec::new();
    push_command_field(
        &mut bytes,
        TENANT_ROOT_REFRESH_INSERT_PENDING_PAYLOAD_DOMAIN_V1,
    )?;
    push_command_field(&mut bytes, command.digest().as_bytes())?;
    push_command_field(&mut bytes, row_payload_digest.as_bytes())?;
    finish_command_payload(bytes)
}

fn activate_initial_payload_digest(
    pending: &CloudflareStoredTenantRootRoleShareV1,
    activation: &CloudflareTenantRootActivationV1,
    updated_at_ms: u64,
    expected_revision: i64,
) -> worker::Result<TenantRootProtocolDigestV1> {
    let mut bytes = command_payload_start("activate_initial")?;
    push_record_public_payload(&mut bytes, &pending.record)?;
    push_command_i64(&mut bytes, expected_revision)?;
    push_activation_payload(&mut bytes, activation)?;
    push_command_u64(&mut bytes, updated_at_ms)?;
    finish_command_payload(bytes)
}

#[allow(clippy::too_many_arguments)]
fn swap_active_epoch_payload_digest(
    active: &CloudflareStoredTenantRootRoleShareV1,
    pending: &CloudflareStoredTenantRootRoleShareV1,
    activation: &CloudflareTenantRootActivationV1,
    retirement: &CloudflareTenantRootRetirementV1,
    updated_at_ms: u64,
    expected_active_revision: i64,
    expected_pending_revision: i64,
) -> worker::Result<TenantRootProtocolDigestV1> {
    let mut bytes = command_payload_start("swap_active_epoch")?;
    push_record_public_payload(&mut bytes, &active.record)?;
    push_command_i64(&mut bytes, expected_active_revision)?;
    push_record_public_payload(&mut bytes, &pending.record)?;
    push_command_i64(&mut bytes, expected_pending_revision)?;
    push_activation_payload(&mut bytes, activation)?;
    push_retirement_payload(&mut bytes, retirement)?;
    push_command_u64(&mut bytes, updated_at_ms)?;
    finish_command_payload(bytes)
}

fn cleanup_pending_payload_digest(
    pending: &CloudflareStoredTenantRootRoleShareV1,
    expected_revision: i64,
) -> worker::Result<TenantRootProtocolDigestV1> {
    let mut bytes = command_payload_start("cleanup_pending")?;
    push_record_public_payload(&mut bytes, &pending.record)?;
    push_command_i64(&mut bytes, expected_revision)?;
    finish_command_payload(bytes)
}

fn authorized_cleanup_pending_payload_digest(
    authorization: &VerifiedTenantRootRoleCleanupCommandV1,
    pending: &CloudflareStoredTenantRootRoleShareV1,
    expected_revision: i64,
) -> worker::Result<TenantRootProtocolDigestV1> {
    let row_payload_digest = cleanup_pending_payload_digest(pending, expected_revision)?;
    let authorization_digest = authorization
        .digest()
        .map_err(|error| store_error(error.message()))?;
    let mut bytes = Vec::new();
    push_command_field(&mut bytes, TENANT_ROOT_AUTHORIZED_CLEANUP_PAYLOAD_DOMAIN_V1)?;
    push_command_field(&mut bytes, authorization_digest.as_bytes())?;
    push_command_field(&mut bytes, row_payload_digest.as_bytes())?;
    finish_command_payload(bytes)
}

fn validate_authorized_cleanup_pending(
    cipher: &TenantRootRoleD1CipherV1,
    authorization: &VerifiedTenantRootRoleCleanupCommandV1,
    pending: &CloudflareStoredTenantRootRoleShareV1,
) -> worker::Result<()> {
    validate_pending_stored_record(cipher, pending)?;
    let record_role = tenant_root_protocol_role_of(pending.record.role);
    let identity_digest = pending
        .record
        .identity()
        .digest()
        .map_err(|error| store_error(error.message()))?;
    let evidence_digest = record_installation_evidence_digest(&pending.record)?;
    if authorization.role() != record_role
        || authorization.identity_digest() != identity_digest
        || authorization.custody_lineage() != pending.record.custody_lineage
        || authorization.epoch() != pending.record.epoch
        || authorization.expected_row_revision() != pending.revision
        || authorization.installation_evidence_digest().as_bytes() != evidence_digest.as_bytes()
    {
        return Err(store_error(
            "tenant-root cleanup authorization does not name the authoritative pending row",
        ));
    }
    Ok(())
}

fn command_payload_start(operation: &'static str) -> worker::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    push_command_field(&mut bytes, TENANT_ROOT_ROLE_COMMAND_PAYLOAD_DOMAIN_V1)?;
    push_command_field(&mut bytes, operation.as_bytes())?;
    Ok(bytes)
}

fn finish_command_payload(bytes: Vec<u8>) -> worker::Result<TenantRootProtocolDigestV1> {
    TenantRootProtocolDigestV1::from_bytes(Sha256::digest(bytes).into())
        .map_err(|error| store_error(error.message()))
}

fn push_record_public_payload(
    bytes: &mut Vec<u8>,
    record: &CloudflareTenantRootRoleShareRecordV1,
) -> worker::Result<()> {
    record.validate()?;
    let identity_digest = record
        .identity
        .digest()
        .map_err(|error| store_error(error.message()))?;
    push_command_field(bytes, identity_digest.as_bytes())?;
    push_command_field(bytes, record.custody_lineage.as_bytes())?;
    push_command_u64(bytes, record.epoch.get().get())?;
    push_command_field(bytes, record.role.as_str().as_bytes())?;
    push_command_field(
        bytes,
        record.sealed_share.ciphertext_digest_hex().as_bytes(),
    )?;
    push_command_field(bytes, record.share_commitment.as_bytes())?;
    push_command_field(bytes, record.epoch_wrapping_key_ref.as_bytes())?;
    push_lifecycle_public_payload(bytes, &record.lifecycle)?;
    push_command_u64(bytes, record.created_at_ms)?;
    push_command_u64(bytes, record.updated_at_ms)?;
    Ok(())
}

fn push_lifecycle_public_payload(
    bytes: &mut Vec<u8>,
    lifecycle: &CloudflareTenantRootRoleShareLifecycleV1,
) -> worker::Result<()> {
    match lifecycle {
        CloudflareTenantRootRoleShareLifecycleV1::Pending(pending) => {
            push_command_field(bytes, b"pending")?;
            push_pending_public_payload(bytes, pending)?;
        }
        CloudflareTenantRootRoleShareLifecycleV1::Active(active) => {
            push_command_field(bytes, b"active")?;
            push_active_public_payload(bytes, active)?;
        }
        CloudflareTenantRootRoleShareLifecycleV1::Retired(retired) => {
            push_command_field(bytes, b"retired")?;
            push_retired_public_payload(bytes, retired)?;
        }
    }
    Ok(())
}

fn push_pending_public_payload(
    bytes: &mut Vec<u8>,
    pending: &CloudflareTenantRootPendingShareV1,
) -> worker::Result<()> {
    push_command_field(bytes, pending.installation_evidence_digest.as_bytes())?;
    push_command_u64(bytes, pending.staged_at_ms)
}

fn push_active_public_payload(
    bytes: &mut Vec<u8>,
    active: &CloudflareTenantRootActiveShareV1,
) -> worker::Result<()> {
    push_pending_public_payload(bytes, &active.pending)?;
    push_activation_payload(bytes, &active.activation)
}

fn push_retired_public_payload(
    bytes: &mut Vec<u8>,
    retired: &CloudflareTenantRootRetiredShareV1,
) -> worker::Result<()> {
    push_active_public_payload(bytes, &retired.active)?;
    push_retirement_payload(bytes, &retired.retirement)
}

fn push_activation_payload(
    bytes: &mut Vec<u8>,
    activation: &CloudflareTenantRootActivationV1,
) -> worker::Result<()> {
    activation.validate()?;
    match &activation.availability {
        CloudflareTenantRootAvailabilityEvidenceV1::CurrentRoleBackup {
            role_backup_receipt_digest,
            identity_digest,
            custody_lineage,
            role,
            epoch,
            share_commitment,
        } => {
            push_command_field(bytes, b"current_role_backup")?;
            push_command_field(bytes, role_backup_receipt_digest.as_bytes())?;
            push_command_field(bytes, identity_digest.as_bytes())?;
            push_command_field(bytes, custody_lineage.as_bytes())?;
            push_command_field(bytes, managed_restore_role_str(*role).as_bytes())?;
            push_command_u64(bytes, epoch.get().get())?;
            push_command_field(bytes, share_commitment.as_bytes())?;
        }
        CloudflareTenantRootAvailabilityEvidenceV1::AcceptedPermanentDerivationLoss {
            authorization_digest,
            identity_digest,
            custody_lineage,
            role,
            epoch,
            share_commitment,
        } => {
            push_command_field(bytes, b"accepted_permanent_derivation_loss")?;
            push_command_field(bytes, authorization_digest.as_bytes())?;
            push_command_field(bytes, identity_digest.as_bytes())?;
            push_command_field(bytes, custody_lineage.as_bytes())?;
            push_command_field(bytes, managed_restore_role_str(*role).as_bytes())?;
            push_command_u64(bytes, epoch.get().get())?;
            push_command_field(bytes, share_commitment.as_bytes())?;
        }
    }
    push_command_field(bytes, &activation.activation_receipt_bytes)?;
    push_command_u64(bytes, activation.activated_at_ms)
}

const fn managed_restore_role_str(role: TenantRootManagedRestoreRoleV1) -> &'static str {
    match role {
        TenantRootManagedRestoreRoleV1::DeriverA => "deriver_a",
        TenantRootManagedRestoreRoleV1::DeriverB => "deriver_b",
    }
}

fn push_retirement_payload(
    bytes: &mut Vec<u8>,
    retirement: &CloudflareTenantRootRetirementV1,
) -> worker::Result<()> {
    push_command_field(bytes, retirement.retirement_receipt_digest.as_bytes())?;
    push_command_u64(bytes, retirement.retired_at_ms)
}

fn push_command_u64(bytes: &mut Vec<u8>, value: u64) -> worker::Result<()> {
    push_command_field(bytes, &value.to_be_bytes())
}

fn push_command_i64(bytes: &mut Vec<u8>, value: i64) -> worker::Result<()> {
    let value = u64::try_from(value)
        .map_err(|_| store_error("tenant-root command local revision is invalid"))?;
    push_command_u64(bytes, value)
}

fn push_command_field(bytes: &mut Vec<u8>, value: &[u8]) -> worker::Result<()> {
    let length = u32::try_from(value.len())
        .map_err(|_| store_error("tenant-root command payload field is too long"))?;
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(value);
    Ok(())
}

fn identity_digest_hex(identity: &TenantRootIdentityV1) -> worker::Result<String> {
    identity
        .digest()
        .map(|digest| encode_hex(digest.as_bytes()))
        .map_err(|error| store_error(error.message()))
}

fn active_binding_from_stored(
    stored: &CloudflareStoredTenantRootRoleShareV1,
) -> worker::Result<TenantRootActiveRoleBindingV1> {
    validate_active_stored_record_shape(stored)?;
    let record = stored.record();
    let CloudflareTenantRootRoleShareLifecycleV1::Active(active) = record.lifecycle() else {
        return Err(store_error(
            "tenant-root active binding requires an active record",
        ));
    };
    let identity_digest = record
        .identity()
        .digest()
        .map_err(|error| store_error(error.message()))?;
    let row = TenantRootActiveRoleRowKeyV1::new(
        identity_digest,
        record.custody_lineage(),
        record.epoch(),
        record.role().managed_restore_role(),
    );
    TenantRootActiveRoleBindingV1::new(
        row,
        record.share_commitment().clone(),
        active.activation.activation_receipt_digest,
    )
    .map_err(|error| store_error(error.message()))
}

fn required_env_var(env: &Env, name: &'static str) -> worker::Result<String> {
    let value = env
        .var(name)
        .map_err(|error| store_error(format!("required env {name} is unavailable: {error}")))?
        .to_string();
    require_identifier(name, &value)?;
    Ok(value)
}

fn require_identifier(field: &str, value: &str) -> worker::Result<()> {
    if value.is_empty()
        || value.trim() != value
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(store_error(format!("{field} is malformed")));
    }
    Ok(())
}

fn require_digest_hex(field: &str, value: &str) -> worker::Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(store_error(format!(
            "{field} must be 32-byte lowercase hex"
        )));
    }
    Ok(())
}

fn require_timestamp(field: &str, value: u64) -> worker::Result<()> {
    if value == 0 {
        return Err(store_error(format!("{field} must be positive")));
    }
    timestamp_i64(value).map(|_| ())
}

fn timestamp_i64(value: u64) -> worker::Result<i64> {
    i64::try_from(value).map_err(|_| store_error("tenant-root timestamp exceeds D1 INTEGER"))
}

fn epoch_i64(epoch: TenantRootShareEpoch) -> worker::Result<i64> {
    epoch_i64_value(epoch.get().get())
}

fn epoch_i64_value(epoch: u64) -> worker::Result<i64> {
    i64::try_from(epoch).map_err(|_| store_error("tenant-root share epoch exceeds D1 INTEGER"))
}

fn decode_private_key(encoded: &str) -> worker::Result<[u8; 32]> {
    let hex = encoded
        .trim()
        .strip_prefix(ROLE_PRIVATE_D1_KEK_SECRET_PREFIX)
        .ok_or_else(|| {
            store_error("role-private D1 KEK Secret has an unsupported encoding prefix")
        })?;
    if hex.len() != 64 {
        return Err(store_error(
            "role-private D1 KEK Secret must contain 32 bytes",
        ));
    }
    let mut bytes = [0_u8; 32];
    for (index, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
        let high = decode_hex_nibble(chunk[0])
            .ok_or_else(|| store_error("role-private D1 KEK Secret must use lowercase hex"))?;
        let low = decode_hex_nibble(chunk[1])
            .ok_or_else(|| store_error("role-private D1 KEK Secret must use lowercase hex"))?;
        bytes[index] = (high << 4) | low;
    }
    Ok(bytes)
}

const fn decode_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

#[cfg(any(debug_assertions, test))]
fn lifecycle_receipt(seed: u8) -> worker::Result<TenantRootLifecycleReceiptDigestV1> {
    TenantRootLifecycleReceiptDigestV1::from_bytes([seed; 32])
        .map_err(|error| store_error(error.message()))
}

fn decode_lower_hex_fixed<const N: usize>(field: &str, value: &str) -> worker::Result<[u8; N]> {
    if value.len() != N * 2 {
        return Err(store_error(format!(
            "{field} must contain exactly {N} bytes of lowercase hex"
        )));
    }
    let mut bytes = [0_u8; N];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = decode_hex_nibble(chunk[0])
            .ok_or_else(|| store_error(format!("{field} must use lowercase hex")))?;
        let low = decode_hex_nibble(chunk[1])
            .ok_or_else(|| store_error(format!("{field} must use lowercase hex")))?;
        bytes[index] = (high << 4) | low;
    }
    Ok(bytes)
}

fn positive_u64_from_i64(field: &str, value: i64) -> worker::Result<u64> {
    let value = u64::try_from(value).map_err(|_| store_error(format!("{field} is invalid")))?;
    if value == 0 {
        return Err(store_error(format!("{field} must be positive")));
    }
    Ok(value)
}

fn require_receipt_digest(
    receipt_bytes: &[u8],
    expected: TenantRootProtocolDigestV1,
) -> worker::Result<()> {
    let actual: [u8; 32] = Sha256::digest(receipt_bytes).into();
    if &actual != expected.as_bytes() {
        return Err(store_error(
            "tenant-root command replay receipt digest does not match its bytes",
        ));
    }
    Ok(())
}

fn validate_active_stored_record_shape(
    stored: &CloudflareStoredTenantRootRoleShareV1,
) -> worker::Result<()> {
    stored.record.validate()?;
    let CloudflareTenantRootRoleShareLifecycleV1::Active(_) = &stored.record.lifecycle else {
        return Err(store_error(
            "tenant-root role-private operation requires an active record",
        ));
    };
    validate_record_activation_binding(&stored.record)?;
    if stored.revision <= 0 {
        return Err(store_error(
            "tenant-root role-private revision must be positive",
        ));
    }
    Ok(())
}

fn validate_record_activation_binding(
    record: &CloudflareTenantRootRoleShareRecordV1,
) -> worker::Result<()> {
    match &record.lifecycle {
        CloudflareTenantRootRoleShareLifecycleV1::Pending(_) => Ok(()),
        CloudflareTenantRootRoleShareLifecycleV1::Active(active) => {
            active.activation.validate_for_record(record)
        }
        CloudflareTenantRootRoleShareLifecycleV1::Retired(retired) => {
            retired.active.activation.validate_for_record(record)
        }
    }
}

fn validate_pending_stored_record(
    cipher: &TenantRootRoleD1CipherV1,
    stored: &CloudflareStoredTenantRootRoleShareV1,
) -> worker::Result<()> {
    stored.record.validate()?;
    cipher.require_role(stored.record.role)?;
    if !matches!(
        stored.record.lifecycle,
        CloudflareTenantRootRoleShareLifecycleV1::Pending(_)
    ) {
        return Err(store_error(
            "tenant-root role-private operation requires a pending record",
        ));
    }
    if stored.revision <= 0 {
        return Err(store_error(
            "tenant-root role-private revision must be positive",
        ));
    }
    Ok(())
}

fn validate_active_stored_record(
    cipher: &TenantRootRoleD1CipherV1,
    stored: &CloudflareStoredTenantRootRoleShareV1,
) -> worker::Result<()> {
    validate_active_stored_record_shape(stored)?;
    cipher.require_role(stored.record.role)?;
    Ok(())
}

fn require_lifecycle_progression(
    operation: &'static str,
    existing_updated_at_ms: u64,
    event_at_ms: u64,
    updated_at_ms: u64,
) -> worker::Result<()> {
    if event_at_ms < existing_updated_at_ms || updated_at_ms < existing_updated_at_ms {
        return Err(store_error(format!(
            "{operation} timestamps regress the existing tenant-root record"
        )));
    }
    if event_at_ms > updated_at_ms {
        return Err(store_error(format!(
            "{operation} timestamp exceeds the tenant-root record update timestamp"
        )));
    }
    Ok(())
}

fn validate_epoch_swap_inputs(
    active: &CloudflareStoredTenantRootRoleShareV1,
    pending: &CloudflareStoredTenantRootRoleShareV1,
) -> worker::Result<()> {
    if active.record.identity != pending.record.identity {
        return Err(store_error(
            "tenant-root epoch swap requires one tenant-root identity",
        ));
    }
    if active.record.custody_lineage != pending.record.custody_lineage {
        return Err(store_error(
            "tenant-root epoch swap requires one custody lineage",
        ));
    }
    if active.record.role != pending.record.role {
        return Err(store_error(
            "tenant-root epoch swap requires one Deriver role",
        ));
    }
    if active
        .record
        .epoch
        .next()
        .map_err(|error| store_error(error.message()))?
        != pending.record.epoch
    {
        return Err(store_error(
            "tenant-root epoch swap must advance exactly one epoch",
        ));
    }
    Ok(())
}

fn next_revision(revision: i64) -> worker::Result<i64> {
    if revision <= 0 {
        return Err(store_error(
            "tenant-root role-private revision must be positive",
        ));
    }
    revision
        .checked_add(1)
        .ok_or_else(|| store_error("tenant-root role-private revision is exhausted"))
}

fn result_changes(result: &worker::D1Result) -> worker::Result<usize> {
    Ok(result
        .meta()?
        .and_then(|metadata| metadata.changes)
        .unwrap_or_default())
}

fn require_changes(
    result: &worker::D1Result,
    expected: usize,
    message: &'static str,
) -> worker::Result<()> {
    if result_changes(result)? != expected {
        return Err(store_error(message));
    }
    Ok(())
}

fn require_one_change(result: &worker::D1Result, message: &'static str) -> worker::Result<()> {
    require_changes(result, 1, message)
}

fn store_error(message: impl Into<String>) -> worker::Error {
    worker::Error::RustError(message.into())
}

#[cfg(test)]
mod tests {
    use curve25519_dalek::{
        ristretto::{CompressedRistretto, RistrettoPoint},
        scalar::Scalar,
        traits::Identity,
    };
    use ed25519_dalek::SigningKey;
    use rand_chacha::ChaCha20Rng;
    use rand_core_06::SeedableRng;
    use router_ab_core::{
        resolve_active_tenant_root_pair_binding_v1, MpcPrfSigningRootShareWireV1,
        RouterAbDerivationError, StableTenantDerivationContextV2,
        TenantRootAcceptedPermanentLossAuthorizationBindingV1,
        TenantRootActivationReceiptTransitionV1, TenantRootActiveRoleBindingV1,
        TenantRootActiveRoleResolutionV1, TenantRootActiveRoleRowKeyV1, TenantRootBackupPolicyV1,
        TenantRootCanaryCurveFamilyV1, TenantRootCanaryReceiptsV1, TenantRootCeremonyContextV1,
        TenantRootCeremonyEpochsV1, TenantRootControlPlaneAuthorityIdV1,
        TenantRootCreationJournalV1, TenantRootDerivationNonceV1,
        TenantRootDerivationOperationIdV1, TenantRootDerivationSessionIdV1,
        TenantRootDeriverIdentitiesV1, TenantRootEmptyCreationV1, TenantRootManagedBackupBindingV1,
        TenantRootManagedBackupSealRequestV1, TenantRootOnlineRoleShareBindingV1,
        TenantRootOnlineRoleShareSealRequestV1, TenantRootProviderCanaryReceiptBindingV1,
        TenantRootRoleBackupReceiptsV1, TenantRootRoleCreationCommandV1,
        TenantRootRoleInstallationReceiptsV1, TenantRootRoleRefreshCommandV1,
        TenantRootSealedOnlineRoleShareV1, TenantRootShareInstallationEvidenceV1,
        TenantRootShareInstallationTranscriptV1,
        TenantRootSignedAcceptedPermanentLossAuthorizationV1, TenantRootSignedActivationReceiptV1,
        TenantRootSignedManagedBackupV1, TenantRootSignedProviderCanaryReceiptV1,
        TenantRootSignedShareInstallationEvidenceV1,
        VerifiedTenantRootInitialCreationActivationEvidenceBundleV1,
        VerifiedTenantRootProviderCanaryReceiptV1,
        VerifiedTenantRootRefreshSwapActivationEvidenceBundleV1,
    };
    use threshold_prf::{
        prove_root_share_knowledge, SigningRootShare, SigningRootShareCommitment,
        SigningRootShareWire, TwoPartyDeriverRole,
    };

    use super::*;
    use crate::tenant_root_role_runtime::{
        open_tenant_root_online_role_share_v1, TenantRootOnlineRoleShareProviderV1,
    };

    struct PersistedOnlineShareProvider {
        opened_share: Option<SigningRootShareWire>,
    }

    impl TenantRootOnlineRoleShareProviderV1 for PersistedOnlineShareProvider {
        fn seal_online_role_share(
            &mut self,
            _request: &TenantRootOnlineRoleShareSealRequestV1,
        ) -> router_ab_core::RouterAbDerivationResult<Vec<u8>> {
            Err(RouterAbDerivationError::new(
                router_ab_core::RouterAbDerivationErrorCode::MalformedInput,
                "persisted-artifact test provider does not seal shares",
            ))
        }

        fn open_online_role_share(
            &mut self,
            sealed: TenantRootSealedOnlineRoleShareV1,
        ) -> router_ab_core::RouterAbDerivationResult<
            router_ab_core::VerifiedTenantRootOnlineRoleShareV1,
        > {
            let opened_share = self.opened_share.take().ok_or_else(|| {
                RouterAbDerivationError::new(
                    router_ab_core::RouterAbDerivationErrorCode::MalformedInput,
                    "persisted-artifact test provider has no opened share",
                )
            })?;
            sealed.verify_opened_share(opened_share)
        }
    }

    fn test_cipher(role: CloudflareTenantRootDeriverRoleV1, seed: u8) -> TenantRootRoleD1CipherV1 {
        let (private_key, public_key) = CloudflareHpkeKemV1::derive_key_pair(&[seed; 32])
            .expect("test role-private D1 keypair derives");
        TenantRootRoleD1CipherV1 {
            environment: "test".to_owned(),
            role,
            key_version: "outer-kek-1".to_owned(),
            public_key,
            private_key,
        }
    }

    fn test_identity() -> TenantRootIdentityV1 {
        TenantRootIdentityV1::new(
            "org-1",
            "project-1",
            "env-1",
            "project-1:env-1",
            "root-version-1",
        )
        .expect("identity")
    }

    fn test_creation_context() -> TenantRootCeremonyContextV1 {
        test_creation_context_for_identity(test_identity())
    }

    fn test_creation_context_for_identity(
        identity: TenantRootIdentityV1,
    ) -> TenantRootCeremonyContextV1 {
        let custody_lineage = TenantRootCustodyLineageId::from_bytes([0x44; 16]).expect("lineage");
        TenantRootCeremonyContextV1::new(
            identity.digest().expect("identity digest"),
            custody_lineage,
            TenantRootCeremonyEpochsV1::create(),
            TenantRootCeremonySessionIdV1::from_bytes([0x45; 16]).expect("session"),
            TenantRootCeremonyNonceV1::from_bytes([0x46; 32]).expect("nonce"),
            10,
            100,
            "deriver-a-signing-key-7",
            "deriver-b-signing-key-9",
        )
        .expect("creation context")
    }

    fn test_refresh_context() -> TenantRootCeremonyContextV1 {
        test_refresh_context_with_identity(test_identity(), 0x44, 1, 2, 0x45, 0x46)
    }

    fn test_refresh_context_with_identity(
        identity: TenantRootIdentityV1,
        lineage_seed: u8,
        current_epoch: u64,
        next_epoch: u64,
        session_seed: u8,
        nonce_seed: u8,
    ) -> TenantRootCeremonyContextV1 {
        let custody_lineage =
            TenantRootCustodyLineageId::from_bytes([lineage_seed; 16]).expect("lineage");
        TenantRootCeremonyContextV1::new(
            identity.digest().expect("identity digest"),
            custody_lineage,
            TenantRootCeremonyEpochsV1::refresh(epoch(current_epoch), epoch(next_epoch))
                .expect("refresh epochs"),
            TenantRootCeremonySessionIdV1::from_bytes([session_seed; 16]).expect("session"),
            TenantRootCeremonyNonceV1::from_bytes([nonce_seed; 32]).expect("nonce"),
            10,
            100,
            "deriver-a-signing-key-7",
            "deriver-b-signing-key-9",
        )
        .expect("refresh context")
    }

    fn test_refresh_active_pair() -> TenantRootActiveRootPairV1 {
        let identity_digest = test_identity().digest().expect("identity digest");
        let custody_lineage = TenantRootCustodyLineageId::from_bytes([0x44; 16]).expect("lineage");
        let epoch = epoch(1);
        let receipt = lifecycle_receipt(0x89).expect("activation receipt");
        let deriver_a = TenantRootActiveRoleBindingV1::new(
            TenantRootActiveRoleRowKeyV1::new(
                identity_digest,
                custody_lineage,
                epoch,
                TenantRootManagedRestoreRoleV1::DeriverA,
            ),
            pair_commitment(CloudflareTenantRootDeriverRoleV1::DeriverA, 7),
            receipt,
        )
        .expect("Deriver A active binding");
        let deriver_b = TenantRootActiveRoleBindingV1::new(
            TenantRootActiveRoleRowKeyV1::new(
                identity_digest,
                custody_lineage,
                epoch,
                TenantRootManagedRestoreRoleV1::DeriverB,
            ),
            pair_commitment(CloudflareTenantRootDeriverRoleV1::DeriverB, 8),
            receipt,
        )
        .expect("Deriver B active binding");
        resolve_active_tenant_root_pair_binding_v1(
            identity_digest,
            &TenantRootActiveRoleResolutionV1::Active(deriver_a),
            &TenantRootActiveRoleResolutionV1::Active(deriver_b),
        )
        .expect("active pair resolution")
        .require_active()
        .expect("active pair")
        .clone()
    }

    fn test_verified_refresh_command(
        role: TwoPartyDeriverRole,
        expected_control_plane_revision: u64,
    ) -> VerifiedTenantRootRoleRefreshCommandV1 {
        test_verified_refresh_command_with_window(role, expected_control_plane_revision, 20, 40)
    }

    fn test_verified_refresh_command_with_window(
        role: TwoPartyDeriverRole,
        expected_control_plane_revision: u64,
        issued_at_ms: u64,
        expires_at_ms: u64,
    ) -> VerifiedTenantRootRoleRefreshCommandV1 {
        let active_pair = test_refresh_active_pair();
        let context = test_refresh_context();
        let signing_key = SigningKey::from_bytes(&[0x47; 32]);
        TenantRootRoleRefreshCommandV1::sign(
            &active_pair,
            &context,
            role,
            expected_control_plane_revision,
            TenantRootControlPlaneAuthorityIdV1::from_bytes([0x48; 32]),
            issued_at_ms,
            expires_at_ms,
            "test-issuer-v1",
            signing_key.as_bytes(),
        )
        .expect("signed refresh command")
        .verify(
            &active_pair,
            &context,
            role,
            expected_control_plane_revision,
            TenantRootControlPlaneAuthorityIdV1::from_bytes([0x48; 32]),
            "test-issuer-v1",
            signing_key.verifying_key().as_bytes(),
        )
        .expect("verified refresh command")
    }

    fn test_refresh_evidence(
        context: &router_ab_core::TenantRootCeremonyContextV1,
        role: TwoPartyDeriverRole,
    ) -> VerifiedTenantRootSignedShareInstallationEvidenceWireV1 {
        let (signing_seed, proof_seed) = match role {
            TwoPartyDeriverRole::DeriverA => (0x57, 0x67),
            TwoPartyDeriverRole::DeriverB => (0x58, 0x68),
        };
        test_refresh_evidence_with_seeds(context, role, signing_seed, proof_seed)
    }

    fn test_refresh_evidence_with_seeds(
        context: &router_ab_core::TenantRootCeremonyContextV1,
        role: TwoPartyDeriverRole,
        signing_seed: u8,
        proof_seed: u8,
    ) -> VerifiedTenantRootSignedShareInstallationEvidenceWireV1 {
        let share_a = SigningRootShare::from_canonical_bytes(
            TwoPartyDeriverRole::DeriverA.share_id(),
            Scalar::from(17_u64).to_bytes(),
        )
        .expect("Deriver A share");
        let share_b = SigningRootShare::from_canonical_bytes(
            TwoPartyDeriverRole::DeriverB.share_id(),
            Scalar::from(29_u64).to_bytes(),
        )
        .expect("Deriver B share");
        match role {
            TwoPartyDeriverRole::DeriverA => signed_installation_evidence_wire(
                context,
                role,
                &share_a,
                &share_b,
                signing_seed,
                proof_seed,
            ),
            TwoPartyDeriverRole::DeriverB => signed_installation_evidence_wire(
                context,
                role,
                &share_b,
                &share_a,
                signing_seed,
                proof_seed,
            ),
        }
    }

    fn refresh_input_with_sealed_evidence(
        command: VerifiedTenantRootRoleRefreshCommandV1,
        evidence: VerifiedTenantRootSignedShareInstallationEvidenceWireV1,
        identity: TenantRootIdentityV1,
        sealed_context: &router_ab_core::TenantRootCeremonyContextV1,
        sealed_evidence: &VerifiedTenantRootSignedShareInstallationEvidenceWireV1,
        sealed_role: TwoPartyDeriverRole,
    ) -> worker::Result<CloudflareTenantRootRefreshInputV1> {
        let sealed_online_share =
            test_sealed_online_share(sealed_context, sealed_evidence, sealed_role);
        CloudflareTenantRootRefreshInputV1::new(
            command,
            evidence,
            CloudflareTenantRootRefreshShareInputV1::new(identity, sealed_online_share, 30),
        )
    }

    fn test_verified_initial_creation_command(
        role: TwoPartyDeriverRole,
        issued_at_ms: u64,
        expires_at_ms: u64,
    ) -> VerifiedTenantRootRoleCreationCommandV1 {
        let identity = test_identity();
        let custody_lineage = TenantRootCustodyLineageId::from_bytes([0x44; 16]).expect("lineage");
        let context = test_creation_context();
        let journal =
            TenantRootCreationJournalV1::started(identity, custody_lineage, context.clone())
                .expect("Started journal");
        let signing_key = SigningKey::from_bytes(&[0x47; 32]);
        TenantRootRoleCreationCommandV1::sign(
            &journal,
            &context,
            role,
            TenantRootControlPlaneAuthorityIdV1::from_bytes([0x48; 32]),
            issued_at_ms,
            expires_at_ms,
            "test-issuer-v1",
            signing_key.as_bytes(),
        )
        .expect("signed command")
        .verify(
            &journal,
            &context,
            role,
            TenantRootControlPlaneAuthorityIdV1::from_bytes([0x48; 32]),
            "test-issuer-v1",
            signing_key.verifying_key().as_bytes(),
        )
        .expect("verified command")
    }

    fn test_commitment(role: CloudflareTenantRootDeriverRoleV1) -> MpcPrfShareCommitmentWireV1 {
        pair_commitment(
            role,
            match role {
                CloudflareTenantRootDeriverRoleV1::DeriverA => 17,
                CloudflareTenantRootDeriverRoleV1::DeriverB => 29,
            },
        )
    }

    fn core_role(role: CloudflareTenantRootDeriverRoleV1) -> TwoPartyDeriverRole {
        match role {
            CloudflareTenantRootDeriverRoleV1::DeriverA => TwoPartyDeriverRole::DeriverA,
            CloudflareTenantRootDeriverRoleV1::DeriverB => TwoPartyDeriverRole::DeriverB,
        }
    }

    fn scalar_for_commitment(
        role: CloudflareTenantRootDeriverRoleV1,
        commitment: &MpcPrfShareCommitmentWireV1,
    ) -> u64 {
        (1..=1024)
            .find(|scalar| pair_commitment(role, *scalar) == *commitment)
            .expect("test commitment has a small discrete-log fixture")
    }

    fn test_context_for_record(
        identity: &TenantRootIdentityV1,
        custody_lineage: TenantRootCustodyLineageId,
        target_epoch: TenantRootShareEpoch,
    ) -> TenantRootCeremonyContextV1 {
        let epochs = if target_epoch == TenantRootShareEpoch::INITIAL {
            TenantRootCeremonyEpochsV1::create()
        } else {
            TenantRootCeremonyEpochsV1::refresh(epoch(target_epoch.get().get() - 1), target_epoch)
                .expect("refresh epochs")
        };
        TenantRootCeremonyContextV1::new(
            identity.digest().expect("identity digest"),
            custody_lineage,
            epochs,
            TenantRootCeremonySessionIdV1::from_bytes([0x45; 16]).expect("session"),
            TenantRootCeremonyNonceV1::from_bytes([0x46; 32]).expect("nonce"),
            10,
            100,
            "deriver-a-signing-key-7",
            "deriver-b-signing-key-9",
        )
        .expect("test context")
    }

    fn test_target_commitments(
        role: CloudflareTenantRootDeriverRoleV1,
        share_commitment: &MpcPrfShareCommitmentWireV1,
    ) -> (TenantRootEpochCommitmentsV1, u64, u64) {
        let (deriver_a, scalar_a, deriver_b, scalar_b) = match role {
            CloudflareTenantRootDeriverRoleV1::DeriverA => (
                share_commitment.clone(),
                scalar_for_commitment(role, share_commitment),
                pair_commitment(CloudflareTenantRootDeriverRoleV1::DeriverB, 29),
                29,
            ),
            CloudflareTenantRootDeriverRoleV1::DeriverB => (
                pair_commitment(CloudflareTenantRootDeriverRoleV1::DeriverA, 17),
                17,
                share_commitment.clone(),
                scalar_for_commitment(role, share_commitment),
            ),
        };
        (
            TenantRootEpochCommitmentsV1::new(deriver_a, deriver_b)
                .expect("test target commitments"),
            scalar_a,
            scalar_b,
        )
    }

    fn test_refresh_current_commitments(
        target: &TenantRootEpochCommitmentsV1,
    ) -> TenantRootEpochCommitmentsV1 {
        let current_a = commitment_point(&pair_commitment(
            CloudflareTenantRootDeriverRoleV1::DeriverA,
            6,
        ));
        let target_root = CompressedRistretto(
            (*target.root_commitment())
                .try_into()
                .expect("target root commitment point"),
        )
        .decompress()
        .expect("target root commitment point");
        let current_b = (Scalar::from(2_u64) * current_a) - target_root;
        TenantRootEpochCommitmentsV1::new(
            pair_commitment(CloudflareTenantRootDeriverRoleV1::DeriverA, 6),
            commitment_wire_from_point(CloudflareTenantRootDeriverRoleV1::DeriverB, current_b),
        )
        .expect("test refresh current commitments")
    }

    fn commitment_point(commitment: &MpcPrfShareCommitmentWireV1) -> RistrettoPoint {
        CompressedRistretto(
            commitment.as_bytes()[2..]
                .try_into()
                .expect("commitment point"),
        )
        .decompress()
        .expect("commitment point decodes")
    }

    fn commitment_wire_from_point(
        role: CloudflareTenantRootDeriverRoleV1,
        point: RistrettoPoint,
    ) -> MpcPrfShareCommitmentWireV1 {
        let mut bytes = Vec::with_capacity(34);
        bytes.extend_from_slice(&role.share_id().to_be_bytes());
        bytes.extend_from_slice(point.compress().as_bytes());
        MpcPrfShareCommitmentWireV1::new(bytes).expect("commitment wire")
    }

    fn test_signed_installation_evidence(
        context: &router_ab_core::TenantRootCeremonyContextV1,
        role: TwoPartyDeriverRole,
        scalar_a: u64,
        scalar_b: u64,
    ) -> VerifiedTenantRootSignedShareInstallationEvidenceWireV1 {
        let share_a = SigningRootShare::from_canonical_bytes(
            TwoPartyDeriverRole::DeriverA.share_id(),
            Scalar::from(scalar_a).to_bytes(),
        )
        .expect("Deriver A share");
        let share_b = SigningRootShare::from_canonical_bytes(
            TwoPartyDeriverRole::DeriverB.share_id(),
            Scalar::from(scalar_b).to_bytes(),
        )
        .expect("Deriver B share");
        let (share, peer, signing_seed, proof_seed) = match role {
            TwoPartyDeriverRole::DeriverA => (&share_a, &share_b, 0x57, 0x67),
            TwoPartyDeriverRole::DeriverB => (&share_b, &share_a, 0x58, 0x68),
        };
        signed_installation_evidence_wire(context, role, share, peer, signing_seed, proof_seed)
    }

    fn test_verified_managed_backup(
        context: &router_ab_core::TenantRootCeremonyContextV1,
        role: TwoPartyDeriverRole,
        scalar: u64,
        backup_seed: u8,
        evidence: &VerifiedTenantRootSignedShareInstallationEvidenceWireV1,
    ) -> VerifiedTenantRootManagedBackupV1 {
        let managed_role = match role {
            TwoPartyDeriverRole::DeriverA => CloudflareTenantRootDeriverRoleV1::DeriverA,
            TwoPartyDeriverRole::DeriverB => CloudflareTenantRootDeriverRoleV1::DeriverB,
        };
        let (backup_provider_id, backup_key_version) = match role {
            TwoPartyDeriverRole::DeriverA => ("backup-provider-a-v1", "backup-key-a-v1"),
            TwoPartyDeriverRole::DeriverB => ("backup-provider-b-v1", "backup-key-b-v1"),
        };
        let binding = TenantRootManagedBackupBindingV1::from_verified_installation_evidence(
            evidence,
            backup_provider_id,
            backup_key_version,
            context.signing_key_id(role),
            11,
        )
        .expect("managed-backup binding");
        assert_eq!(binding.role(), managed_role.managed_restore_role());
        assert_eq!(binding.custody_lineage(), context.custody_lineage());
        let share = SigningRootShare::from_canonical_bytes(
            role.share_id(),
            Scalar::from(scalar).to_bytes(),
        )
        .expect("managed-backup share");
        let share_wire = MpcPrfSigningRootShareWireV1::new(
            SigningRootShareWire::from_share(&share).to_bytes().to_vec(),
        )
        .expect("managed-backup share wire");
        let request = TenantRootManagedBackupSealRequestV1::new(binding.clone(), share_wire)
            .expect("managed-backup request");
        let signing_key = SigningKey::from_bytes(&[backup_seed; 32]);
        TenantRootSignedManagedBackupV1::sign(
            request,
            vec![backup_seed; 96],
            signing_key.as_bytes(),
        )
        .expect("signed managed backup")
        .verify(&binding, signing_key.verifying_key().as_bytes())
        .expect("verified managed backup")
    }

    fn test_verified_provider_canary(
        context: &router_ab_core::TenantRootCeremonyContextV1,
        transition: TenantRootActivationReceiptTransitionV1,
        target_epoch: TenantRootShareEpoch,
        commitments: &TenantRootEpochCommitmentsV1,
        curve_family: TenantRootCanaryCurveFamilyV1,
        signing_seed: u8,
    ) -> VerifiedTenantRootProviderCanaryReceiptV1 {
        let binding = TenantRootProviderCanaryReceiptBindingV1::new(
            context.identity_digest(),
            context.custody_lineage(),
            transition,
            target_epoch,
            commitments.clone(),
            curve_family,
            "canary-provider-key-v1",
            20,
            TenantRootControlPlaneAuthorityIdV1::from_bytes([0x48; 32]),
            "canary-signing-key-v1",
            10,
            100,
        )
        .expect("provider canary binding");
        let signing_key = SigningKey::from_bytes(&[signing_seed; 32]);
        TenantRootSignedProviderCanaryReceiptV1::sign(binding.clone(), signing_key.as_bytes())
            .expect("signed provider canary")
            .verify(&binding, signing_key.verifying_key().as_bytes())
            .expect("verified provider canary")
    }

    fn record_for_identity_epoch(
        identity: TenantRootIdentityV1,
        role: CloudflareTenantRootDeriverRoleV1,
        lineage_seed: u8,
        target_epoch: TenantRootShareEpoch,
        share_commitment: MpcPrfShareCommitmentWireV1,
    ) -> CloudflareTenantRootRoleShareRecordV1 {
        let custody_lineage =
            TenantRootCustodyLineageId::from_bytes([lineage_seed; 16]).expect("lineage");
        let context = test_context_for_record(&identity, custody_lineage, target_epoch);
        let (target_commitments, scalar_a, scalar_b) =
            test_target_commitments(role, &share_commitment);
        let evidence =
            test_signed_installation_evidence(&context, core_role(role), scalar_a, scalar_b);
        debug_assert_eq!(
            share_commitment,
            match role {
                CloudflareTenantRootDeriverRoleV1::DeriverA =>
                    target_commitments.deriver_a().clone(),
                CloudflareTenantRootDeriverRoleV1::DeriverB =>
                    target_commitments.deriver_b().clone(),
            }
        );
        CloudflareTenantRootRoleShareRecordV1::new(CloudflareTenantRootRoleShareRecordInputV1 {
            identity,
            custody_lineage,
            epoch: target_epoch,
            role,
            sealed_share: CloudflareTenantRootSealedRoleShareV1::new(&[0x66; 96])
                .expect("sealed share"),
            share_commitment,
            epoch_wrapping_key_ref: format!("kms://deriver/tenant/epoch-{}", target_epoch.get()),
            lifecycle: CloudflareTenantRootRoleShareLifecycleV1::Pending(
                CloudflareTenantRootPendingShareV1::from_verified_installation_evidence(
                    &evidence, 10,
                )
                .expect("pending"),
            ),
            created_at_ms: 10,
            updated_at_ms: 10,
        })
        .expect("record")
    }

    fn record(role: CloudflareTenantRootDeriverRoleV1) -> CloudflareTenantRootRoleShareRecordV1 {
        record_for_identity_epoch(
            test_identity(),
            role,
            0x44,
            TenantRootShareEpoch::INITIAL,
            test_commitment(role),
        )
    }

    fn current_backup_activation(
        role: CloudflareTenantRootDeriverRoleV1,
        backup_seed: u8,
        activation_seed: u8,
        activated_at_ms: u64,
    ) -> CloudflareTenantRootActivationV1 {
        current_backup_activation_for_record(
            &record(role),
            backup_seed,
            activation_seed,
            activated_at_ms,
        )
    }

    fn deriver_b_share_activation_digest() -> TenantRootLifecycleReceiptDigestV1 {
        current_backup_activation(CloudflareTenantRootDeriverRoleV1::DeriverB, 0x88, 0x89, 20)
            .activation_receipt_digest()
    }

    fn test_activation_target(
        record: &CloudflareTenantRootRoleShareRecordV1,
    ) -> (
        TenantRootEpochCommitmentsV1,
        u64,
        u64,
        TenantRootCeremonyContextV1,
    ) {
        let target_commitments = test_target_commitments(record.role(), record.share_commitment());
        let context =
            test_context_for_record(record.identity(), record.custody_lineage(), record.epoch());
        (
            target_commitments.0,
            target_commitments.1,
            target_commitments.2,
            context,
        )
    }

    fn test_initial_activation_bundle(
        record: &CloudflareTenantRootRoleShareRecordV1,
        backup_seed: u8,
        canary_seed: u8,
    ) -> VerifiedTenantRootInitialCreationActivationEvidenceBundleV1 {
        let (target_commitments, scalar_a, scalar_b, context) = test_activation_target(record);
        let evidence_a = test_signed_installation_evidence(
            &context,
            TwoPartyDeriverRole::DeriverA,
            scalar_a,
            scalar_b,
        );
        let evidence_b = test_signed_installation_evidence(
            &context,
            TwoPartyDeriverRole::DeriverB,
            scalar_a,
            scalar_b,
        );
        let backup_a = test_verified_managed_backup(
            &context,
            TwoPartyDeriverRole::DeriverA,
            scalar_a,
            backup_seed,
            &evidence_a,
        );
        let backup_b = test_verified_managed_backup(
            &context,
            TwoPartyDeriverRole::DeriverB,
            scalar_b,
            backup_seed.wrapping_add(1),
            &evidence_b,
        );
        let canary_ecdsa = test_verified_provider_canary(
            &context,
            TenantRootActivationReceiptTransitionV1::InitialCreation,
            TenantRootShareEpoch::INITIAL,
            &target_commitments,
            TenantRootCanaryCurveFamilyV1::Ecdsa,
            canary_seed,
        );
        let canary_ed25519 = test_verified_provider_canary(
            &context,
            TenantRootActivationReceiptTransitionV1::InitialCreation,
            TenantRootShareEpoch::INITIAL,
            &target_commitments,
            TenantRootCanaryCurveFamilyV1::Ed25519,
            canary_seed.wrapping_add(1),
        );
        VerifiedTenantRootInitialCreationActivationEvidenceBundleV1::from_verified_managed_backups(
            evidence_a,
            evidence_b,
            backup_a,
            backup_b,
            canary_ecdsa,
            canary_ed25519,
            2,
            3,
        )
        .expect("initial activation evidence")
    }

    fn test_refresh_activation_bundle(
        record: &CloudflareTenantRootRoleShareRecordV1,
        backup_seed: u8,
        canary_seed: u8,
    ) -> VerifiedTenantRootRefreshSwapActivationEvidenceBundleV1 {
        let (target_commitments, scalar_a, scalar_b, context) = test_activation_target(record);
        let evidence_a = test_signed_installation_evidence(
            &context,
            TwoPartyDeriverRole::DeriverA,
            scalar_a,
            scalar_b,
        );
        let evidence_b = test_signed_installation_evidence(
            &context,
            TwoPartyDeriverRole::DeriverB,
            scalar_a,
            scalar_b,
        );
        let backup_a = test_verified_managed_backup(
            &context,
            TwoPartyDeriverRole::DeriverA,
            scalar_a,
            backup_seed,
            &evidence_a,
        );
        let backup_b = test_verified_managed_backup(
            &context,
            TwoPartyDeriverRole::DeriverB,
            scalar_b,
            backup_seed.wrapping_add(1),
            &evidence_b,
        );
        let canary_ecdsa = test_verified_provider_canary(
            &context,
            TenantRootActivationReceiptTransitionV1::RefreshSwap,
            record.epoch(),
            &target_commitments,
            TenantRootCanaryCurveFamilyV1::Ecdsa,
            canary_seed,
        );
        let canary_ed25519 = test_verified_provider_canary(
            &context,
            TenantRootActivationReceiptTransitionV1::RefreshSwap,
            record.epoch(),
            &target_commitments,
            TenantRootCanaryCurveFamilyV1::Ed25519,
            canary_seed.wrapping_add(1),
        );
        VerifiedTenantRootRefreshSwapActivationEvidenceBundleV1::from_verified_managed_backups(
            &test_refresh_current_commitments(&target_commitments),
            evidence_a,
            evidence_b,
            backup_a,
            backup_b,
            canary_ecdsa,
            canary_ed25519,
            2,
            3,
        )
        .expect("refresh activation evidence")
    }

    fn test_verified_accepted_loss_authorization(
        context: &router_ab_core::TenantRootCeremonyContextV1,
        target_commitments: &TenantRootEpochCommitmentsV1,
        installation_receipts: TenantRootRoleInstallationReceiptsV1,
        variant: u8,
    ) -> router_ab_core::VerifiedTenantRootAcceptedPermanentLossAuthorizationV1 {
        let (transition, target_epoch) = match context.epochs() {
            TenantRootCeremonyEpochsV1::Create { next } => (
                TenantRootActivationReceiptTransitionV1::InitialCreation,
                next,
            ),
            TenantRootCeremonyEpochsV1::Refresh { next, .. } => {
                (TenantRootActivationReceiptTransitionV1::RefreshSwap, next)
            }
        };
        let binding = TenantRootAcceptedPermanentLossAuthorizationBindingV1::new(
            context.identity_digest(),
            context.custody_lineage(),
            transition,
            target_epoch,
            context.digest().expect("context digest"),
            target_commitments.clone(),
            installation_receipts,
            2,
            3,
            format!("policy-accept-loss-{variant:02x}"),
            format!("incident-2026-{variant:04x}"),
            "both managed backups are unavailable",
            context.issued_at_ms(),
            context.expires_at_ms(),
            TenantRootControlPlaneAuthorityIdV1::from_bytes([0x71; 32]),
            "operator-a-v1",
            TenantRootControlPlaneAuthorityIdV1::from_bytes([0x72; 32]),
            "operator-b-v1",
        )
        .expect("accepted-loss binding");
        let first_key = SigningKey::from_bytes(&[0x61; 32]);
        let second_key = SigningKey::from_bytes(&[0x62; 32]);
        TenantRootSignedAcceptedPermanentLossAuthorizationV1::sign(
            binding.clone(),
            first_key.as_bytes(),
            second_key.as_bytes(),
        )
        .expect("signed accepted-loss authorization")
        .verify(
            &binding,
            first_key.verifying_key().as_bytes(),
            second_key.verifying_key().as_bytes(),
        )
        .expect("verified accepted-loss authorization")
    }

    fn test_initial_accepted_loss_bundle(
        record: &CloudflareTenantRootRoleShareRecordV1,
        authorization_variant: u8,
        canary_seed: u8,
    ) -> VerifiedTenantRootInitialCreationActivationEvidenceBundleV1 {
        let (target_commitments, scalar_a, scalar_b, context) = test_activation_target(record);
        let evidence_a = test_signed_installation_evidence(
            &context,
            TwoPartyDeriverRole::DeriverA,
            scalar_a,
            scalar_b,
        );
        let evidence_b = test_signed_installation_evidence(
            &context,
            TwoPartyDeriverRole::DeriverB,
            scalar_a,
            scalar_b,
        );
        let installation_receipts = TenantRootRoleInstallationReceiptsV1::new(
            evidence_a
                .lifecycle_receipt_digest()
                .expect("Deriver A installation receipt"),
            evidence_b
                .lifecycle_receipt_digest()
                .expect("Deriver B installation receipt"),
        )
        .expect("installation receipts");
        let authorization = test_verified_accepted_loss_authorization(
            &context,
            &target_commitments,
            installation_receipts,
            authorization_variant,
        );
        let canary_ecdsa = test_verified_provider_canary(
            &context,
            TenantRootActivationReceiptTransitionV1::InitialCreation,
            TenantRootShareEpoch::INITIAL,
            &target_commitments,
            TenantRootCanaryCurveFamilyV1::Ecdsa,
            canary_seed,
        );
        let canary_ed25519 = test_verified_provider_canary(
            &context,
            TenantRootActivationReceiptTransitionV1::InitialCreation,
            TenantRootShareEpoch::INITIAL,
            &target_commitments,
            TenantRootCanaryCurveFamilyV1::Ed25519,
            canary_seed.wrapping_add(1),
        );
        VerifiedTenantRootInitialCreationActivationEvidenceBundleV1::from_verified_accepted_loss(
            evidence_a,
            evidence_b,
            authorization,
            canary_ecdsa,
            canary_ed25519,
            2,
            3,
        )
        .expect("initial accepted-loss activation evidence")
    }

    fn test_refresh_accepted_loss_bundle(
        record: &CloudflareTenantRootRoleShareRecordV1,
        authorization_variant: u8,
        canary_seed: u8,
    ) -> VerifiedTenantRootRefreshSwapActivationEvidenceBundleV1 {
        let (target_commitments, scalar_a, scalar_b, context) = test_activation_target(record);
        let evidence_a = test_signed_installation_evidence(
            &context,
            TwoPartyDeriverRole::DeriverA,
            scalar_a,
            scalar_b,
        );
        let evidence_b = test_signed_installation_evidence(
            &context,
            TwoPartyDeriverRole::DeriverB,
            scalar_a,
            scalar_b,
        );
        let installation_receipts = TenantRootRoleInstallationReceiptsV1::new(
            evidence_a
                .lifecycle_receipt_digest()
                .expect("Deriver A installation receipt"),
            evidence_b
                .lifecycle_receipt_digest()
                .expect("Deriver B installation receipt"),
        )
        .expect("installation receipts");
        let authorization = test_verified_accepted_loss_authorization(
            &context,
            &target_commitments,
            installation_receipts,
            authorization_variant,
        );
        let canary_ecdsa = test_verified_provider_canary(
            &context,
            TenantRootActivationReceiptTransitionV1::RefreshSwap,
            record.epoch(),
            &target_commitments,
            TenantRootCanaryCurveFamilyV1::Ecdsa,
            canary_seed,
        );
        let canary_ed25519 = test_verified_provider_canary(
            &context,
            TenantRootActivationReceiptTransitionV1::RefreshSwap,
            record.epoch(),
            &target_commitments,
            TenantRootCanaryCurveFamilyV1::Ed25519,
            canary_seed.wrapping_add(1),
        );
        VerifiedTenantRootRefreshSwapActivationEvidenceBundleV1::from_verified_accepted_loss(
            &test_refresh_current_commitments(&target_commitments),
            evidence_a,
            evidence_b,
            authorization,
            canary_ecdsa,
            canary_ed25519,
            2,
            3,
        )
        .expect("refresh accepted-loss activation evidence")
    }

    fn accepted_loss_activation_for_record(
        record: &CloudflareTenantRootRoleShareRecordV1,
        authorization_variant: u8,
        activation_seed: u8,
        activated_at_ms: u64,
    ) -> CloudflareTenantRootActivationV1 {
        let authority_id = TenantRootControlPlaneAuthorityIdV1::from_bytes([0x48; 32]);
        let signing_key = SigningKey::from_bytes(&[activation_seed; 32]);
        let canary_seed = activation_seed.wrapping_add(1);
        match record.epoch() {
            TenantRootShareEpoch::INITIAL => {
                let signed = TenantRootSignedActivationReceiptV1::sign_initial_creation(
                    &test_initial_accepted_loss_bundle(record, authorization_variant, canary_seed),
                    activated_at_ms,
                    authority_id,
                    "test-accepted-loss-activation-issuer-v1",
                    signing_key.as_bytes(),
                )
                .expect("signed initial accepted-loss activation");
                let verified = signed
                    .verify_initial_creation(
                        &test_initial_accepted_loss_bundle(
                            record,
                            authorization_variant,
                            canary_seed,
                        ),
                        activated_at_ms,
                        authority_id,
                        "test-accepted-loss-activation-issuer-v1",
                        signing_key.verifying_key().as_bytes(),
                    )
                    .expect("verified initial accepted-loss activation");
                CloudflareTenantRootActivationV1::with_accepted_permanent_derivation_loss(
                    record, verified,
                )
                .expect("accepted-loss activation")
            }
            _ => {
                let signed = TenantRootSignedActivationReceiptV1::sign_refresh_swap(
                    &test_refresh_accepted_loss_bundle(record, authorization_variant, canary_seed),
                    activated_at_ms,
                    authority_id,
                    "test-accepted-loss-activation-issuer-v1",
                    signing_key.as_bytes(),
                )
                .expect("signed refresh accepted-loss activation");
                let verified = signed
                    .verify_refresh_swap(
                        &test_refresh_accepted_loss_bundle(
                            record,
                            authorization_variant,
                            canary_seed,
                        ),
                        activated_at_ms,
                        authority_id,
                        "test-accepted-loss-activation-issuer-v1",
                        signing_key.verifying_key().as_bytes(),
                    )
                    .expect("verified refresh accepted-loss activation");
                CloudflareTenantRootActivationV1::with_accepted_permanent_derivation_loss(
                    record, verified,
                )
                .expect("accepted-loss activation")
            }
        }
    }

    fn current_backup_activation_for_record(
        record: &CloudflareTenantRootRoleShareRecordV1,
        backup_seed: u8,
        activation_seed: u8,
        activated_at_ms: u64,
    ) -> CloudflareTenantRootActivationV1 {
        let (_target_commitments, scalar_a, scalar_b, context) = test_activation_target(record);
        let evidence_a = test_signed_installation_evidence(
            &context,
            TwoPartyDeriverRole::DeriverA,
            scalar_a,
            scalar_b,
        );
        let evidence_b = test_signed_installation_evidence(
            &context,
            TwoPartyDeriverRole::DeriverB,
            scalar_a,
            scalar_b,
        );
        let verified_backup = match record.role() {
            CloudflareTenantRootDeriverRoleV1::DeriverA => test_verified_managed_backup(
                &context,
                TwoPartyDeriverRole::DeriverA,
                scalar_a,
                backup_seed,
                &evidence_a,
            ),
            CloudflareTenantRootDeriverRoleV1::DeriverB => test_verified_managed_backup(
                &context,
                TwoPartyDeriverRole::DeriverB,
                scalar_b,
                backup_seed.wrapping_add(1),
                &evidence_b,
            ),
        };
        let signing_key = SigningKey::from_bytes(&[activation_seed; 32]);
        let authority_id = TenantRootControlPlaneAuthorityIdV1::from_bytes([0x48; 32]);
        match record.epoch() {
            TenantRootShareEpoch::INITIAL => {
                let signed = TenantRootSignedActivationReceiptV1::sign_initial_creation(
                    &test_initial_activation_bundle(
                        record,
                        backup_seed,
                        activation_seed.wrapping_add(1),
                    ),
                    activated_at_ms,
                    authority_id,
                    "test-activation-issuer-v1",
                    signing_key.as_bytes(),
                )
                .expect("signed initial activation");
                let verified = signed
                    .verify_initial_creation(
                        &test_initial_activation_bundle(
                            record,
                            backup_seed,
                            activation_seed.wrapping_add(1),
                        ),
                        activated_at_ms,
                        authority_id,
                        "test-activation-issuer-v1",
                        signing_key.verifying_key().as_bytes(),
                    )
                    .expect("verified initial activation");
                CloudflareTenantRootActivationV1::with_current_role_backup(
                    record,
                    &verified_backup,
                    verified,
                )
                .expect("activation")
            }
            _ => {
                let signed = TenantRootSignedActivationReceiptV1::sign_refresh_swap(
                    &test_refresh_activation_bundle(
                        record,
                        backup_seed,
                        activation_seed.wrapping_add(1),
                    ),
                    activated_at_ms,
                    authority_id,
                    "test-activation-issuer-v1",
                    signing_key.as_bytes(),
                )
                .expect("signed refresh activation");
                let verified = signed
                    .verify_refresh_swap(
                        &test_refresh_activation_bundle(
                            record,
                            backup_seed,
                            activation_seed.wrapping_add(1),
                        ),
                        activated_at_ms,
                        authority_id,
                        "test-activation-issuer-v1",
                        signing_key.verifying_key().as_bytes(),
                    )
                    .expect("verified refresh activation");
                CloudflareTenantRootActivationV1::with_current_role_backup(
                    record,
                    &verified_backup,
                    verified,
                )
                .expect("activation")
            }
        }
    }

    /// Builds one role's public active resolution the way `load_active` does.
    fn active_role_share(
        role: CloudflareTenantRootDeriverRoleV1,
        lineage_seed: u8,
        epoch: TenantRootShareEpoch,
        share_commitment: MpcPrfShareCommitmentWireV1,
    ) -> CloudflareTenantRootActiveRoleShareV1 {
        active_role_share_for_identity(test_identity(), role, lineage_seed, epoch, share_commitment)
    }

    fn active_role_share_for_identity(
        identity: TenantRootIdentityV1,
        role: CloudflareTenantRootDeriverRoleV1,
        lineage_seed: u8,
        epoch: TenantRootShareEpoch,
        share_commitment: MpcPrfShareCommitmentWireV1,
    ) -> CloudflareTenantRootActiveRoleShareV1 {
        let record =
            record_for_identity_epoch(identity, role, lineage_seed, epoch, share_commitment);
        let activation = current_backup_activation_for_record(&record, 0x88, 0x89, 20);
        let record = record.into_active(activation, 20).expect("active record");
        CloudflareTenantRootActiveRoleShareV1::Active(Box::new(
            CloudflareStoredTenantRootRoleShareV1 {
                record,
                revision: 1,
            },
        ))
    }

    fn direct_active_role_resolution(
        role: TenantRootManagedRestoreRoleV1,
        lineage_seed: u8,
        epoch: TenantRootShareEpoch,
        share_commitment: MpcPrfShareCommitmentWireV1,
        activation_receipt_digest: TenantRootLifecycleReceiptDigestV1,
    ) -> TenantRootActiveRoleResolutionV1 {
        let identity_digest = test_identity().digest().expect("identity digest");
        let custody_lineage =
            TenantRootCustodyLineageId::from_bytes([lineage_seed; 16]).expect("lineage");
        TenantRootActiveRoleResolutionV1::Active(
            TenantRootActiveRoleBindingV1::new(
                TenantRootActiveRoleRowKeyV1::new(identity_digest, custody_lineage, epoch, role),
                share_commitment,
                activation_receipt_digest,
            )
            .expect("active role binding"),
        )
    }

    /// Commits to one fixed role-local share, as a real installation would.
    fn pair_commitment(
        role: CloudflareTenantRootDeriverRoleV1,
        scalar: u64,
    ) -> MpcPrfShareCommitmentWireV1 {
        let deriver = match role {
            CloudflareTenantRootDeriverRoleV1::DeriverA => TwoPartyDeriverRole::DeriverA,
            CloudflareTenantRootDeriverRoleV1::DeriverB => TwoPartyDeriverRole::DeriverB,
        };
        let share = SigningRootShare::from_canonical_bytes(
            deriver.share_id(),
            Scalar::from(scalar).to_bytes(),
        )
        .expect("share");
        MpcPrfShareCommitmentWireV1::new(
            SigningRootShareCommitment::from_share(&share)
                .to_bytes()
                .to_vec(),
        )
        .expect("commitment")
    }

    fn deriver_a_share(
        lineage_seed: u8,
        epoch: TenantRootShareEpoch,
    ) -> CloudflareTenantRootActiveRoleShareV1 {
        active_role_share(
            CloudflareTenantRootDeriverRoleV1::DeriverA,
            lineage_seed,
            epoch,
            pair_commitment(CloudflareTenantRootDeriverRoleV1::DeriverA, 17),
        )
    }

    fn deriver_b_share(
        lineage_seed: u8,
        epoch: TenantRootShareEpoch,
    ) -> CloudflareTenantRootActiveRoleShareV1 {
        active_role_share(
            CloudflareTenantRootDeriverRoleV1::DeriverB,
            lineage_seed,
            epoch,
            pair_commitment(CloudflareTenantRootDeriverRoleV1::DeriverB, 29),
        )
    }

    fn epoch(value: u64) -> TenantRootShareEpoch {
        TenantRootShareEpoch::new(value).expect("epoch")
    }

    fn test_custody_binding() -> TenantRootCustodyBindingV1 {
        let identity = test_identity();
        let custody_lineage = TenantRootCustodyLineageId::from_bytes([0x44; 16]).expect("lineage");
        let context =
            test_context_for_record(&identity, custody_lineage, TenantRootShareEpoch::INITIAL);
        let evidence_a_wire =
            test_signed_installation_evidence(&context, TwoPartyDeriverRole::DeriverA, 17, 29);
        let evidence_b_wire =
            test_signed_installation_evidence(&context, TwoPartyDeriverRole::DeriverB, 17, 29);
        let target_commitments = TenantRootEpochCommitmentsV1::new(
            pair_commitment(CloudflareTenantRootDeriverRoleV1::DeriverA, 17),
            pair_commitment(CloudflareTenantRootDeriverRoleV1::DeriverB, 29),
        )
        .expect("target commitments");
        let backup_a = test_verified_managed_backup(
            &context,
            TwoPartyDeriverRole::DeriverA,
            17,
            0x88,
            &evidence_a_wire,
        );
        let backup_b = test_verified_managed_backup(
            &context,
            TwoPartyDeriverRole::DeriverB,
            29,
            0x89,
            &evidence_b_wire,
        );
        let canary_ecdsa = test_verified_provider_canary(
            &context,
            TenantRootActivationReceiptTransitionV1::InitialCreation,
            TenantRootShareEpoch::INITIAL,
            &target_commitments,
            TenantRootCanaryCurveFamilyV1::Ecdsa,
            0x8a,
        );
        let canary_ed25519 = test_verified_provider_canary(
            &context,
            TenantRootActivationReceiptTransitionV1::InitialCreation,
            TenantRootShareEpoch::INITIAL,
            &target_commitments,
            TenantRootCanaryCurveFamilyV1::Ed25519,
            0x8b,
        );
        let installation_receipts = TenantRootRoleInstallationReceiptsV1::new(
            evidence_a_wire
                .lifecycle_receipt_digest()
                .expect("installation receipt"),
            evidence_b_wire
                .lifecycle_receipt_digest()
                .expect("installation receipt"),
        )
        .expect("installation receipts");
        let backup_receipts = TenantRootRoleBackupReceiptsV1::new(
            backup_a.receipt_digest(),
            backup_b.receipt_digest(),
        )
        .expect("backup receipts");
        let canary_receipts = TenantRootCanaryReceiptsV1::new(
            TenantRootLifecycleReceiptDigestV1::from_bytes(*canary_ecdsa.digest().as_bytes())
                .expect("canary receipt"),
            TenantRootLifecycleReceiptDigestV1::from_bytes(*canary_ed25519.digest().as_bytes())
                .expect("canary receipt"),
        )
        .expect("canary receipts");
        let verified_creation = TenantRootEmptyCreationV1::new(identity, custody_lineage)
            .start(&context)
            .expect("start ceremony")
            .verify(
                evidence_a_wire.evidence(),
                evidence_b_wire.evidence(),
                installation_receipts,
                TenantRootBackupPolicyV1::CurrentRoleBackups(backup_receipts),
                canary_receipts,
                20,
            )
            .expect("verify ceremony");
        let activation_key = SigningKey::from_bytes(&[0x89; 32]);
        let activation = TenantRootSignedActivationReceiptV1::sign_initial_creation(
            &VerifiedTenantRootInitialCreationActivationEvidenceBundleV1::from_verified_managed_backups(
                evidence_a_wire,
                evidence_b_wire,
                backup_a,
                backup_b,
                canary_ecdsa,
                canary_ed25519,
                2,
                3,
            )
            .expect("activation evidence"),
            20,
            TenantRootControlPlaneAuthorityIdV1::from_bytes([0x48; 32]),
            "test-activation-issuer-v1",
            activation_key.as_bytes(),
        )
        .expect("signed activation")
        .verify_initial_creation(
            &test_initial_activation_bundle(
                &record_for_identity_epoch(
                    test_identity(),
                    CloudflareTenantRootDeriverRoleV1::DeriverA,
                    0x44,
                    TenantRootShareEpoch::INITIAL,
                    pair_commitment(CloudflareTenantRootDeriverRoleV1::DeriverA, 17),
                ),
                0x88,
                0x8a,
            ),
            20,
            TenantRootControlPlaneAuthorityIdV1::from_bytes([0x48; 32]),
            "test-activation-issuer-v1",
            activation_key.verifying_key().as_bytes(),
        )
        .expect("verified activation");
        let active = verified_creation
            .activate(activation)
            .expect("activate ceremony")
            .into_refresh_state();
        let stable_context = StableTenantDerivationContextV2::new([0x85; 32]);
        TenantRootCustodyBindingV1::from_active(
            &active,
            TenantRootDeriverIdentitiesV1::new("deriver-a-runtime-7", "deriver-b-runtime-9")
                .expect("Deriver identities"),
            TenantRootDerivationOperationIdV1::from_bytes([0x81; 16]).expect("operation id"),
            TenantRootDerivationSessionIdV1::from_bytes([0x82; 16]).expect("session id"),
            TenantRootDerivationNonceV1::from_bytes([0x83; 32]).expect("derivation nonce"),
            40,
            70,
            &stable_context,
            TenantRootProtocolDigestV1::from_bytes([0x84; 32]).expect("transcript digest"),
        )
        .expect("custody binding")
    }

    fn test_initial_creation_evidence(
        context: &router_ab_core::TenantRootCeremonyContextV1,
        role: TwoPartyDeriverRole,
    ) -> VerifiedTenantRootSignedShareInstallationEvidenceWireV1 {
        let share_a = SigningRootShare::from_canonical_bytes(
            TwoPartyDeriverRole::DeriverA.share_id(),
            Scalar::from(17_u64).to_bytes(),
        )
        .expect("Deriver A share");
        let share_b = SigningRootShare::from_canonical_bytes(
            TwoPartyDeriverRole::DeriverB.share_id(),
            Scalar::from(29_u64).to_bytes(),
        )
        .expect("Deriver B share");
        match role {
            TwoPartyDeriverRole::DeriverA => {
                signed_installation_evidence_wire(context, role, &share_a, &share_b, 0x57, 0x67)
            }
            TwoPartyDeriverRole::DeriverB => {
                signed_installation_evidence_wire(context, role, &share_b, &share_a, 0x58, 0x68)
            }
        }
    }

    fn signed_installation_evidence_wire(
        context: &router_ab_core::TenantRootCeremonyContextV1,
        role: TwoPartyDeriverRole,
        share: &SigningRootShare,
        peer: &SigningRootShare,
        signing_seed: u8,
        proof_seed: u8,
    ) -> VerifiedTenantRootSignedShareInstallationEvidenceWireV1 {
        let transcript = TenantRootShareInstallationTranscriptV1::new(
            context.clone(),
            role,
            SigningRootShareCommitment::from_share(share),
            SigningRootShareCommitment::from_share(peer),
        )
        .expect("installation transcript");
        let proof = prove_root_share_knowledge(
            share,
            &transcript.canonical_bytes().expect("transcript bytes"),
            &mut ChaCha20Rng::from_seed([proof_seed; 32]),
        )
        .expect("share proof");
        let evidence = TenantRootShareInstallationEvidenceV1::new(transcript, proof)
            .expect("installation evidence");
        let signing_key = SigningKey::from_bytes(&[signing_seed; 32]);
        let signed =
            TenantRootSignedShareInstallationEvidenceV1::sign(evidence, &signing_key.to_bytes())
                .expect("signed installation evidence");
        let bytes = signed.canonical_bytes().expect("signed evidence bytes");
        TenantRootSignedShareInstallationEvidenceV1::decode_and_verify_canonical_bytes(
            &bytes,
            signing_key.verifying_key().as_bytes(),
        )
        .expect("verified installation evidence wire")
    }

    fn test_sealed_online_share(
        context: &router_ab_core::TenantRootCeremonyContextV1,
        evidence: &VerifiedTenantRootSignedShareInstallationEvidenceWireV1,
        role: TwoPartyDeriverRole,
    ) -> TenantRootSealedOnlineRoleShareV1 {
        let (share, commitment) = match role {
            TwoPartyDeriverRole::DeriverA => {
                let share = SigningRootShare::from_canonical_bytes(
                    TwoPartyDeriverRole::DeriverA.share_id(),
                    Scalar::from(17_u64).to_bytes(),
                )
                .expect("Deriver A share");
                let commitment = MpcPrfShareCommitmentWireV1::new(
                    SigningRootShareCommitment::from_share(&share)
                        .to_bytes()
                        .to_vec(),
                )
                .expect("Deriver A commitment");
                (share, commitment)
            }
            TwoPartyDeriverRole::DeriverB => {
                let share = SigningRootShare::from_canonical_bytes(
                    TwoPartyDeriverRole::DeriverB.share_id(),
                    Scalar::from(29_u64).to_bytes(),
                )
                .expect("Deriver B share");
                let commitment = MpcPrfShareCommitmentWireV1::new(
                    SigningRootShareCommitment::from_share(&share)
                        .to_bytes()
                        .to_vec(),
                )
                .expect("Deriver B commitment");
                (share, commitment)
            }
        };
        let binding = TenantRootOnlineRoleShareBindingV1::new(
            context.identity_digest(),
            context.custody_lineage(),
            role,
            match context.epochs() {
                TenantRootCeremonyEpochsV1::Create { next }
                | TenantRootCeremonyEpochsV1::Refresh { next, .. } => next,
            },
            commitment,
            "kms://deriver/tenant/epoch-1",
            evidence,
        )
        .expect("online share binding");
        TenantRootOnlineRoleShareSealRequestV1::new(
            binding,
            SigningRootShareWire::from_share(&share),
        )
        .expect("online share seal request")
        .complete(vec![0x66; 96])
        .expect("sealed online share")
    }

    #[test]
    fn active_pair_resolution_preserves_both_stored_role_commitments() {
        let custody_binding = test_custody_binding();
        let pair = cloudflare_require_active_tenant_root_pair_v1(
            &custody_binding,
            &deriver_a_share(0x44, epoch(1)),
            &deriver_b_share(0x44, epoch(1)),
        )
        .expect("one active root pair");

        assert_eq!(
            pair.identity_digest(),
            test_identity().digest().expect("identity digest")
        );
        assert_eq!(
            pair.custody_lineage(),
            TenantRootCustodyLineageId::from_bytes([0x44; 16]).expect("lineage")
        );
        assert_eq!(pair.epoch(), epoch(1));
        assert_eq!(
            pair.deriver_a().share_commitment(),
            &pair_commitment(CloudflareTenantRootDeriverRoleV1::DeriverA, 17)
        );
        assert_eq!(
            pair.deriver_b().share_commitment(),
            &pair_commitment(CloudflareTenantRootDeriverRoleV1::DeriverB, 29)
        );
        assert_eq!(pair.root_commitment(), pair.commitments().root_commitment());
        assert_eq!(
            pair.activation_receipt_digest(),
            custody_binding.activation_receipt_digest()
        );
    }

    #[test]
    fn authoritative_pair_resolution_rejects_stale_pair_receipt_and_commitment() {
        let custody_binding = test_custody_binding();

        let stale_lineage = cloudflare_resolve_active_tenant_root_pair_v1(
            &custody_binding,
            &deriver_a_share(0x45, epoch(1)),
            &deriver_b_share(0x45, epoch(1)),
        )
        .expect("stale lineage is observed");
        assert_eq!(
            stale_lineage,
            TenantRootActivePairResolutionV1::Mismatched(
                router_ab_core::TenantRootActivePairMismatchV1::CustodyBinding
            )
        );

        let stale_epoch = cloudflare_resolve_active_tenant_root_pair_v1(
            &custody_binding,
            &deriver_a_share(0x44, epoch(2)),
            &deriver_b_share(0x44, epoch(2)),
        )
        .expect("stale epoch is observed");
        assert_eq!(
            stale_epoch,
            TenantRootActivePairResolutionV1::Mismatched(
                router_ab_core::TenantRootActivePairMismatchV1::CustodyBinding
            )
        );

        let TenantRootActiveRoleResolutionV1::Active(deriver_a) = deriver_a_share(0x44, epoch(1))
            .public_resolution()
            .expect("Deriver A public resolution")
        else {
            panic!("expected an active Deriver A resolution");
        };
        let mismatched_commitment = direct_active_role_resolution(
            TenantRootManagedRestoreRoleV1::DeriverB,
            0x44,
            epoch(1),
            pair_commitment(CloudflareTenantRootDeriverRoleV1::DeriverB, 34),
            deriver_a.activation_receipt_digest(),
        );
        let commitment_mismatch = resolve_authoritative_active_tenant_root_pair_binding_v1(
            custody_binding.identity_digest(),
            &custody_binding,
            &TenantRootActiveRoleResolutionV1::Active(deriver_a),
            &mismatched_commitment,
        )
        .expect("commitment mismatch is observed");
        assert_eq!(
            commitment_mismatch,
            TenantRootActivePairResolutionV1::Mismatched(
                router_ab_core::TenantRootActivePairMismatchV1::ShareCommitments
            )
        );

        let mut stale_receipt = match deriver_a_share(0x44, epoch(1)) {
            CloudflareTenantRootActiveRoleShareV1::Active(stored) => *stored,
            _ => panic!("expected active role share"),
        };
        let CloudflareTenantRootRoleShareLifecycleV1::Active(active) =
            &mut stale_receipt.record.lifecycle
        else {
            panic!("expected active lifecycle");
        };
        let replacement =
            current_backup_activation(CloudflareTenantRootDeriverRoleV1::DeriverA, 0x88, 0x90, 20);
        active.activation.activation_receipt_bytes = replacement.activation_receipt_bytes.clone();
        active.activation.activation_receipt_digest = replacement.activation_receipt_digest;
        active.activation.activated_at_ms = replacement.activated_at_ms;
        let stale_receipt = CloudflareTenantRootActiveRoleShareV1::Active(Box::new(stale_receipt));
        let stale_receipt = cloudflare_resolve_active_tenant_root_pair_v1(
            &custody_binding,
            &stale_receipt,
            &deriver_b_share(0x44, epoch(1)),
        )
        .expect("stale receipt is observed");
        assert_eq!(
            stale_receipt,
            TenantRootActivePairResolutionV1::Mismatched(
                router_ab_core::TenantRootActivePairMismatchV1::ActivationReceiptDigest {
                    expected: custody_binding.activation_receipt_digest(),
                    deriver_a: replacement.activation_receipt_digest,
                    deriver_b: deriver_b_share_activation_digest(),
                }
            )
        );
        assert!(commitment_mismatch.require_active().is_err());
    }

    #[test]
    fn pair_resolution_never_moves_a_peers_sealed_share_across_the_role_boundary() {
        let deriver_a = deriver_a_share(0x44, epoch(7));
        let TenantRootActiveRoleResolutionV1::Active(binding) =
            deriver_a.public_resolution().expect("public resolution")
        else {
            panic!("expected an active public resolution");
        };
        // The public half carries coordinates and a commitment, and nothing sealed.
        assert_eq!(binding.role(), TenantRootManagedRestoreRoleV1::DeriverA);
        assert_eq!(binding.epoch(), epoch(7));
        assert_eq!(
            binding.share_commitment(),
            &pair_commitment(CloudflareTenantRootDeriverRoleV1::DeriverA, 17)
        );
    }

    #[test]
    fn public_resolution_rejects_a_non_active_stored_record() {
        let pending = CloudflareTenantRootActiveRoleShareV1::Active(Box::new(
            CloudflareStoredTenantRootRoleShareV1 {
                record: record(CloudflareTenantRootDeriverRoleV1::DeriverA),
                revision: 1,
            },
        ));

        assert!(pending.public_resolution().is_err());
        assert!(pending.require_active().is_err());
    }

    #[test]
    fn persisted_active_record_reconstructs_online_artifact_for_role_local_provider() {
        let role = CloudflareTenantRootDeriverRoleV1::DeriverA;
        let pending = record(role);
        let expected_identity_digest = pending.identity().digest().expect("identity digest");
        let expected_lineage = pending.custody_lineage();
        let expected_epoch = pending.epoch();
        let expected_commitment = pending.share_commitment().clone();
        let expected_key_ref = pending.epoch_wrapping_key_ref().to_owned();
        let expected_evidence_digest =
            record_installation_evidence_digest(&pending).expect("installation evidence digest");
        assert!(CloudflareStoredTenantRootRoleShareV1 {
            record: pending.clone(),
            revision: 1,
        }
        .into_online_role_share_artifact()
        .is_err());
        let share = SigningRootShare::from_canonical_bytes(
            TwoPartyDeriverRole::DeriverA.share_id(),
            Scalar::from(17_u64).to_bytes(),
        )
        .expect("Deriver A share");
        let activation = current_backup_activation_for_record(&pending, 0x88, 0x89, 20);
        let active = pending
            .into_active(activation, 20)
            .expect("active role share");
        let stored = CloudflareStoredTenantRootRoleShareV1 {
            record: active,
            revision: 1,
        };
        let artifact = stored
            .into_online_role_share_artifact()
            .expect("persisted online role-share artifact");
        let mut provider = PersistedOnlineShareProvider {
            opened_share: Some(SigningRootShareWire::from_share(&share)),
        };

        let opened = open_tenant_root_online_role_share_v1(artifact, &mut provider)
            .expect("provider-opened online role share");

        assert_eq!(opened.role(), TwoPartyDeriverRole::DeriverA);
        assert_eq!(opened.identity_digest(), expected_identity_digest);
        assert_eq!(opened.custody_lineage(), expected_lineage);
        assert_eq!(opened.epoch(), expected_epoch);
        assert_eq!(opened.share_commitment(), &expected_commitment);
        assert_eq!(opened.binding().epoch_wrapping_key_ref(), expected_key_ref);
        assert_eq!(
            opened.binding().installation_evidence_digest(),
            expected_evidence_digest
        );
    }

    #[test]
    fn empty_active_load_is_publicly_unprovisioned_and_fails_closed() {
        let empty = CloudflareTenantRootActiveRoleShareV1::Unprovisioned;
        assert_eq!(
            empty.public_resolution().expect("empty public resolution"),
            TenantRootActiveRoleResolutionV1::Unprovisioned
        );
        assert!(empty.require_active().is_err());
    }

    #[test]
    fn active_projection_rejects_invalid_commitments_and_activation_evidence() {
        let mut invalid_commitment = match deriver_a_share(0x44, epoch(7)) {
            CloudflareTenantRootActiveRoleShareV1::Active(stored) => *stored,
            _ => panic!("expected active role share"),
        };
        let mut identity_commitment = vec![0_u8; 34];
        identity_commitment[..2].copy_from_slice(&1_u16.to_be_bytes());
        identity_commitment[2..].copy_from_slice(RistrettoPoint::identity().compress().as_bytes());
        invalid_commitment.record.share_commitment =
            MpcPrfShareCommitmentWireV1::new(identity_commitment).expect("identity commitment");
        let invalid_commitment =
            CloudflareTenantRootActiveRoleShareV1::Active(Box::new(invalid_commitment));
        assert!(invalid_commitment.public_resolution().is_err());
        assert!(invalid_commitment.require_active().is_err());

        let mut tampered_evidence = match deriver_a_share(0x44, epoch(7)) {
            CloudflareTenantRootActiveRoleShareV1::Active(stored) => *stored,
            _ => panic!("expected active role share"),
        };
        let CloudflareTenantRootRoleShareLifecycleV1::Active(active) =
            &mut tampered_evidence.record.lifecycle
        else {
            panic!("expected active lifecycle");
        };
        let CloudflareTenantRootAvailabilityEvidenceV1::CurrentRoleBackup {
            identity_digest, ..
        } = &mut active.activation.availability
        else {
            panic!("expected current-backup availability");
        };
        *identity_digest = TenantRootIdentityDigestV1::from_bytes([0x91; 32]);
        let tampered_evidence =
            CloudflareTenantRootActiveRoleShareV1::Active(Box::new(tampered_evidence));
        assert!(tampered_evidence.public_resolution().is_err());
        assert!(tampered_evidence.require_active().is_err());
    }

    #[test]
    fn pair_resolution_reports_exact_fail_closed_classifications() {
        let unprovisioned = CloudflareTenantRootActiveRoleShareV1::Unprovisioned;
        let ambiguous = CloudflareTenantRootActiveRoleShareV1::Ambiguous(
            TenantRootActiveRoleAmbiguityV1::DistinctLineages {
                custody_lineages: vec![
                    TenantRootCustodyLineageId::from_bytes([0x44; 16]).expect("lineage"),
                    TenantRootCustodyLineageId::from_bytes([0x45; 16]).expect("lineage"),
                ],
            },
        );
        let cases = [
            (
                &unprovisioned,
                &unprovisioned,
                TenantRootActivePairResolutionV1::Unprovisioned,
            ),
            (
                &deriver_a_share(0x44, epoch(7)),
                &unprovisioned,
                TenantRootActivePairResolutionV1::Partial {
                    present: TenantRootManagedRestoreRoleV1::DeriverA,
                },
            ),
            (
                &unprovisioned,
                &deriver_b_share(0x44, epoch(7)),
                TenantRootActivePairResolutionV1::Partial {
                    present: TenantRootManagedRestoreRoleV1::DeriverB,
                },
            ),
            (
                &ambiguous,
                &deriver_b_share(0x44, epoch(7)),
                TenantRootActivePairResolutionV1::AmbiguousRole {
                    role: TenantRootManagedRestoreRoleV1::DeriverA,
                    ambiguity: match &ambiguous {
                        CloudflareTenantRootActiveRoleShareV1::Ambiguous(ambiguity) => {
                            ambiguity.clone()
                        }
                        _ => unreachable!(),
                    },
                },
            ),
            (
                &deriver_a_share(0x44, epoch(7)),
                &ambiguous,
                TenantRootActivePairResolutionV1::AmbiguousRole {
                    role: TenantRootManagedRestoreRoleV1::DeriverB,
                    ambiguity: match &ambiguous {
                        CloudflareTenantRootActiveRoleShareV1::Ambiguous(ambiguity) => {
                            ambiguity.clone()
                        }
                        _ => unreachable!(),
                    },
                },
            ),
            (
                &deriver_a_share(0x44, epoch(7)),
                &deriver_b_share(0x45, epoch(7)),
                TenantRootActivePairResolutionV1::Mismatched(
                    router_ab_core::TenantRootActivePairMismatchV1::CustodyLineage {
                        deriver_a: TenantRootCustodyLineageId::from_bytes([0x44; 16])
                            .expect("lineage"),
                        deriver_b: TenantRootCustodyLineageId::from_bytes([0x45; 16])
                            .expect("lineage"),
                    },
                ),
            ),
            (
                &deriver_a_share(0x44, epoch(7)),
                &deriver_b_share(0x44, epoch(9)),
                TenantRootActivePairResolutionV1::Mismatched(
                    router_ab_core::TenantRootActivePairMismatchV1::Epoch {
                        deriver_a: epoch(7),
                        deriver_b: epoch(9),
                    },
                ),
            ),
        ];

        for (deriver_a, deriver_b, expected) in cases {
            let actual = cloudflare_observe_active_tenant_root_pair_v1(
                &test_identity(),
                deriver_a,
                deriver_b,
            )
            .expect("reconciliation observes the public state");
            assert_eq!(actual, expected);
            assert!(cloudflare_require_active_tenant_root_pair_v1(
                &test_custody_binding(),
                deriver_a,
                deriver_b,
            )
            .is_err());
        }

        let TenantRootActiveRoleResolutionV1::Active(deriver_a) = deriver_a_share(0x44, epoch(7))
            .public_resolution()
            .expect("Deriver A public resolution")
        else {
            panic!("expected an active Deriver A resolution");
        };
        let mismatched_commitment = direct_active_role_resolution(
            TenantRootManagedRestoreRoleV1::DeriverB,
            0x44,
            epoch(7),
            pair_commitment(CloudflareTenantRootDeriverRoleV1::DeriverB, 34),
            deriver_a.activation_receipt_digest(),
        );
        assert_eq!(
            resolve_active_tenant_root_pair_binding_v1(
                test_identity().digest().expect("identity digest"),
                &TenantRootActiveRoleResolutionV1::Active(deriver_a),
                &mismatched_commitment,
            )
            .expect("reconciliation observes invalid pair commitments"),
            TenantRootActivePairResolutionV1::Mismatched(
                router_ab_core::TenantRootActivePairMismatchV1::ShareCommitments,
            )
        );
    }

    #[test]
    fn every_unsafe_pair_state_fails_closed_at_the_boundary() {
        let unprovisioned = CloudflareTenantRootActiveRoleShareV1::Unprovisioned;
        let ambiguous = CloudflareTenantRootActiveRoleShareV1::Ambiguous(
            TenantRootActiveRoleAmbiguityV1::DistinctLineages {
                custody_lineages: vec![
                    TenantRootCustodyLineageId::from_bytes([0x44; 16]).expect("lineage"),
                    TenantRootCustodyLineageId::from_bytes([0x45; 16]).expect("lineage"),
                ],
            },
        );
        // Unprovisioned, partial both ways, ambiguous either role, lineage, and
        // epoch mismatch: none of them yields a pair.
        for (deriver_a, deriver_b) in [
            (&unprovisioned, &unprovisioned),
            (&deriver_a_share(0x44, epoch(7)), &unprovisioned),
            (&unprovisioned, &deriver_b_share(0x44, epoch(7))),
            (&ambiguous, &deriver_b_share(0x44, epoch(7))),
            (&deriver_a_share(0x44, epoch(7)), &ambiguous),
            (
                &deriver_a_share(0x44, epoch(7)),
                &deriver_b_share(0x45, epoch(7)),
            ),
            (
                &deriver_a_share(0x44, epoch(7)),
                &deriver_b_share(0x44, epoch(9)),
            ),
        ] {
            assert!(
                cloudflare_require_active_tenant_root_pair_v1(
                    &test_custody_binding(),
                    deriver_a,
                    deriver_b
                )
                .is_err(),
                "unsafe tenant-root pair state resolved to a usable pair"
            );
            // Reconciliation still observes the state without deriving from it.
            cloudflare_observe_active_tenant_root_pair_v1(&test_identity(), deriver_a, deriver_b)
                .expect("reconciliation observes the unsafe state");
        }
    }

    #[test]
    fn a_role_share_in_the_wrong_pair_position_fails_closed() {
        assert!(cloudflare_observe_active_tenant_root_pair_v1(
            &test_identity(),
            &deriver_b_share(0x44, epoch(7)),
            &deriver_b_share(0x44, epoch(7)),
        )
        .is_err());
        assert!(cloudflare_observe_active_tenant_root_pair_v1(
            &test_identity(),
            &deriver_a_share(0x44, epoch(7)),
            &deriver_a_share(0x44, epoch(7)),
        )
        .is_err());
    }

    #[test]
    fn a_role_share_for_a_foreign_identity_fails_closed() {
        let foreign_identity = TenantRootIdentityV1::new(
            "org-2",
            "project-1",
            "env-1",
            "project-1:env-1",
            "root-version-1",
        )
        .expect("foreign identity");
        assert!(cloudflare_observe_active_tenant_root_pair_v1(
            &test_identity(),
            &active_role_share_for_identity(
                foreign_identity.clone(),
                CloudflareTenantRootDeriverRoleV1::DeriverA,
                0x44,
                epoch(7),
                pair_commitment(CloudflareTenantRootDeriverRoleV1::DeriverA, 17),
            ),
            &deriver_b_share(0x44, epoch(7)),
        )
        .is_err());
        assert!(cloudflare_observe_active_tenant_root_pair_v1(
            &test_identity(),
            &deriver_a_share(0x44, epoch(7)),
            &active_role_share_for_identity(
                foreign_identity,
                CloudflareTenantRootDeriverRoleV1::DeriverB,
                0x44,
                epoch(7),
                pair_commitment(CloudflareTenantRootDeriverRoleV1::DeriverB, 29),
            ),
        )
        .is_err());
    }

    #[test]
    fn role_private_d1_kek_matching_public_private_pair_is_accepted() {
        let cipher = test_cipher(CloudflareTenantRootDeriverRoleV1::DeriverA, 0x41);
        validate_role_private_d1_kek_key_pair(&cipher.public_key, &cipher.private_key)
            .expect("matching role-private D1 KEK pair is accepted");
    }

    #[test]
    fn role_private_d1_kek_mismatched_public_private_pair_is_rejected() {
        let public_key = test_cipher(CloudflareTenantRootDeriverRoleV1::DeriverA, 0x41).public_key;
        let private_key =
            test_cipher(CloudflareTenantRootDeriverRoleV1::DeriverA, 0x42).private_key;
        assert!(validate_role_private_d1_kek_key_pair(&public_key, &private_key).is_err());
    }

    fn row_from_record(
        cipher: &TenantRootRoleD1CipherV1,
        record: &CloudflareTenantRootRoleShareRecordV1,
    ) -> TenantRootRoleD1RowV1 {
        let metadata = record_metadata(record).expect("metadata");
        TenantRootRoleD1RowV1 {
            tenant_identity_digest_hex: metadata.identity_digest_hex,
            custody_lineage_b64u: metadata.custody_lineage_b64u,
            tenant_root_share_epoch: epoch_i64_value(metadata.epoch).expect("epoch"),
            role: metadata.role.as_str().to_owned(),
            lifecycle: metadata.lifecycle,
            ciphertext_json: cipher.seal(record, 1).expect("ciphertext"),
            revision: 1,
            created_at_ms: timestamp_i64(record.created_at_ms).expect("created"),
            updated_at_ms: timestamp_i64(record.updated_at_ms).expect("updated"),
        }
    }

    fn row_from_record_with_schema(
        cipher: &TenantRootRoleD1CipherV1,
        record: &CloudflareTenantRootRoleShareRecordV1,
        schema: &'static str,
    ) -> TenantRootRoleD1RowV1 {
        let metadata = record_metadata(record).expect("metadata");
        let revision = 1;
        let record_key = metadata.record_key();
        let aad = serde_json::to_vec(&TenantRootRoleD1AadV1 {
            environment: &cipher.environment,
            worker_role: cipher.role,
            tenant_identity_digest_hex: &metadata.identity_digest_hex,
            custody_lineage_b64u: &metadata.custody_lineage_b64u,
            tenant_root_share_epoch: metadata.epoch,
            record_role: metadata.role,
            lifecycle: &metadata.lifecycle,
            revision,
            purpose: TENANT_ROOT_ROLE_D1_PURPOSE,
            schema,
            record_key: &record_key,
        })
        .expect("old-schema AAD");
        let plaintext = serde_json::to_vec(record).expect("record JSON");
        let mut rng = CloudflareHpkeGetrandomRngV1;
        let (encapped_key, ciphertext) = CloudflareHpkeSuiteV1::seal_base(
            &mut rng,
            &cipher.public_key,
            TENANT_ROOT_ROLE_D1_HPKE_INFO,
            &aad,
            &plaintext,
        )
        .expect("old-schema ciphertext");
        let mut payload = Vec::with_capacity(encapped_key.as_ref().len() + ciphertext.len());
        payload.extend_from_slice(encapped_key.as_ref());
        payload.extend_from_slice(&ciphertext);
        let ciphertext_json = serde_json::to_string(&TenantRootRoleD1CiphertextV1 {
            key_version: cipher.key_version.clone(),
            tenant_identity_digest_hex: metadata.identity_digest_hex.clone(),
            custody_lineage_b64u: metadata.custody_lineage_b64u.clone(),
            tenant_root_share_epoch: metadata.epoch,
            role: metadata.role,
            lifecycle: metadata.lifecycle.clone(),
            ciphertext_b64u: encode_base64url_bytes_v1(&payload),
        })
        .expect("old-schema envelope");
        TenantRootRoleD1RowV1 {
            tenant_identity_digest_hex: metadata.identity_digest_hex,
            custody_lineage_b64u: metadata.custody_lineage_b64u,
            tenant_root_share_epoch: epoch_i64_value(metadata.epoch).expect("epoch"),
            role: metadata.role.as_str().to_owned(),
            lifecycle: metadata.lifecycle,
            ciphertext_json,
            revision,
            created_at_ms: timestamp_i64(record.created_at_ms).expect("created"),
            updated_at_ms: timestamp_i64(record.updated_at_ms).expect("updated"),
        }
    }

    #[test]
    fn role_private_cipher_binds_tenant_lineage_epoch_role_and_lifecycle() {
        let cipher = test_cipher(CloudflareTenantRootDeriverRoleV1::DeriverA, 0x41);
        let record = record(CloudflareTenantRootDeriverRoleV1::DeriverA);
        let row = row_from_record(&cipher, &record);
        assert_eq!(cipher.open(&row).expect("record opens"), record);

        let mut wrong_revision = row_from_record(&cipher, &record);
        wrong_revision.revision = 2;
        assert!(cipher.open(&wrong_revision).is_err());

        let wrong_role = test_cipher(CloudflareTenantRootDeriverRoleV1::DeriverB, 0x41);
        assert!(wrong_role.open(&row).is_err());

        let wrong_key = test_cipher(CloudflareTenantRootDeriverRoleV1::DeriverA, 0x42);
        assert!(wrong_key.open(&row).is_err());

        let mut wrong_epoch = row_from_record(&cipher, &record);
        wrong_epoch.tenant_root_share_epoch = 2;
        assert!(cipher.open(&wrong_epoch).is_err());

        let mut wrong_lifecycle = row_from_record(&cipher, &record);
        wrong_lifecycle.lifecycle = "active".to_owned();
        assert!(cipher.open(&wrong_lifecycle).is_err());
    }

    #[test]
    fn old_schema_ciphertext_is_rejected_without_a_compatibility_parser() {
        let cipher = test_cipher(CloudflareTenantRootDeriverRoleV1::DeriverA, 0x41);
        let record = record(CloudflareTenantRootDeriverRoleV1::DeriverA);
        let old_row =
            row_from_record_with_schema(&cipher, &record, "tenant-root-role-private-d1/v1");
        assert!(cipher.open(&old_row).is_err());
    }

    #[test]
    fn activation_wire_round_trip_rederives_projection_from_exact_bytes() {
        let activation =
            current_backup_activation(CloudflareTenantRootDeriverRoleV1::DeriverA, 0x88, 0x89, 20);
        let wire_value = serde_json::json!({
            "availability": serde_json::to_value(&activation.availability)
                .expect("availability JSON"),
            "activation_receipt_b64u": encode_base64url_bytes_v1(
                activation.activation_receipt_bytes()
            ),
        });
        let decoded = serde_json::from_value::<TenantRootRoleD1ActivationWireV1>(wire_value)
            .expect("activation wire");
        let round_tripped = decoded.into_activation().expect("round-tripped activation");
        assert_eq!(
            round_tripped.activation_receipt_bytes(),
            activation.activation_receipt_bytes()
        );
        assert_eq!(
            round_tripped.activation_receipt_digest(),
            activation.activation_receipt_digest()
        );
        assert_eq!(
            round_tripped.activated_at_ms(),
            activation.activated_at_ms()
        );
        let serialized = serde_json::to_value(&round_tripped).expect("activation JSON");
        assert_eq!(
            serialized["activation_receipt_b64u"],
            serde_json::json!(encode_base64url_bytes_v1(
                activation.activation_receipt_bytes()
            ))
        );
        assert!(serialized.get("activation_receipt_digest").is_none());
        assert!(serialized.get("activated_at_ms").is_none());
    }

    #[test]
    fn accepted_loss_activation_wire_round_trip_retains_exact_authorization_digest() {
        let record = record(CloudflareTenantRootDeriverRoleV1::DeriverA);
        let activation = accepted_loss_activation_for_record(&record, 0x61, 0x89, 20);
        let receipt = decode_activation_receipt_bytes(activation.activation_receipt_bytes())
            .expect("accepted-loss activation receipt");
        let (authorization_bytes, authorization_digest) = match receipt.availability() {
            TenantRootActivationReceiptAvailabilityV1::AcceptedPermanentDerivationLoss {
                authorization_bytes,
                authorization_digest,
            } => (authorization_bytes.clone(), *authorization_digest),
            TenantRootActivationReceiptAvailabilityV1::CurrentRoleBackups { .. } => {
                panic!("expected accepted-loss availability")
            }
        };
        let wire_value = serde_json::json!({
            "availability": serde_json::to_value(&activation.availability)
                .expect("accepted-loss availability JSON"),
            "activation_receipt_b64u": encode_base64url_bytes_v1(
                activation.activation_receipt_bytes()
            ),
        });
        let decoded = serde_json::from_value::<TenantRootRoleD1ActivationWireV1>(wire_value)
            .expect("accepted-loss activation wire");
        let round_tripped = decoded
            .into_activation()
            .expect("round-tripped accepted-loss activation");
        assert_eq!(
            round_tripped.activation_receipt_bytes(),
            activation.activation_receipt_bytes()
        );
        assert_eq!(
            round_tripped.activation_receipt_digest(),
            activation.activation_receipt_digest()
        );
        assert_eq!(
            round_tripped.activated_at_ms(),
            activation.activated_at_ms()
        );
        let CloudflareTenantRootAvailabilityEvidenceV1::AcceptedPermanentDerivationLoss {
            authorization_digest: round_tripped_digest,
            ..
        } = &round_tripped.availability
        else {
            panic!("expected accepted-loss availability");
        };
        assert_eq!(*round_tripped_digest, authorization_digest);
        assert!(!authorization_bytes.is_empty());
        let serialized = serde_json::to_value(&round_tripped).expect("activation JSON");
        assert_eq!(
            serialized["availability"]["kind"],
            serde_json::json!("accepted_permanent_derivation_loss")
        );
        assert_eq!(
            serialized["availability"]["authorization_digest"],
            serde_json::json!(authorization_digest.as_bytes())
        );
        assert_eq!(
            serialized["activation_receipt_b64u"],
            serde_json::json!(encode_base64url_bytes_v1(
                activation.activation_receipt_bytes()
            ))
        );
        assert!(serialized.get("activation_receipt_digest").is_none());
        assert!(serialized.get("activated_at_ms").is_none());
    }

    #[test]
    fn accepted_loss_refresh_activation_round_trip_retains_exact_receipt_bytes() {
        let pending = record_for_identity_epoch(
            test_identity(),
            CloudflareTenantRootDeriverRoleV1::DeriverA,
            0x44,
            epoch(2),
            pair_commitment(CloudflareTenantRootDeriverRoleV1::DeriverA, 18),
        );
        let activation = accepted_loss_activation_for_record(&pending, 0x63, 0x89, 40);
        let wire_value = serde_json::json!({
            "availability": serde_json::to_value(&activation.availability)
                .expect("accepted-loss availability JSON"),
            "activation_receipt_b64u": encode_base64url_bytes_v1(
                activation.activation_receipt_bytes()
            ),
        });
        let decoded = serde_json::from_value::<TenantRootRoleD1ActivationWireV1>(wire_value)
            .expect("accepted-loss refresh activation wire");
        let round_tripped = decoded
            .into_activation()
            .expect("round-tripped accepted-loss refresh activation");
        assert_eq!(
            round_tripped.activation_receipt_bytes(),
            activation.activation_receipt_bytes()
        );
        assert_eq!(
            round_tripped.activation_receipt_digest(),
            activation.activation_receipt_digest()
        );
        assert_eq!(
            round_tripped.activated_at_ms(),
            activation.activated_at_ms()
        );
        pending
            .into_active(round_tripped, 40)
            .expect("accepted-loss refresh activation binds pending role");
    }

    #[test]
    fn accepted_loss_activation_rejects_authorization_projection_substitution() {
        let pending = record(CloudflareTenantRootDeriverRoleV1::DeriverA);
        let original = accepted_loss_activation_for_record(&pending, 0x61, 0x89, 20);
        let replacement = accepted_loss_activation_for_record(&pending, 0x62, 0x90, 20);
        let active = pending
            .clone()
            .into_active(original.clone(), 20)
            .expect("active record");
        let mut stored = CloudflareStoredTenantRootRoleShareV1 {
            record: active,
            revision: 1,
        };
        {
            let CloudflareTenantRootRoleShareLifecycleV1::Active(active) =
                &mut stored.record.lifecycle
            else {
                panic!("active lifecycle");
            };
            active.activation.activation_receipt_bytes =
                replacement.activation_receipt_bytes.clone();
        }
        assert!(validate_active_stored_record_shape(&stored).is_err());
        {
            let CloudflareTenantRootRoleShareLifecycleV1::Active(active) =
                &mut stored.record.lifecycle
            else {
                panic!("active lifecycle");
            };
            active.activation.activation_receipt_digest = replacement.activation_receipt_digest;
            active.activation.activated_at_ms = replacement.activated_at_ms;
        }
        assert!(validate_active_stored_record_shape(&stored).is_err());
        let original_payload = activate_initial_payload_digest(
            &CloudflareStoredTenantRootRoleShareV1 {
                record: pending,
                revision: 1,
            },
            &original,
            20,
            1,
        )
        .expect("original activation payload");
        let replacement_payload = activate_initial_payload_digest(
            &CloudflareStoredTenantRootRoleShareV1 {
                record: record(CloudflareTenantRootDeriverRoleV1::DeriverA),
                revision: 1,
            },
            &replacement,
            20,
            1,
        )
        .expect("replacement activation payload");
        assert_ne!(original_payload, replacement_payload);
    }

    #[test]
    fn accepted_loss_activation_replay_is_idempotent_and_rejects_authorization_substitution() {
        let pending = record(CloudflareTenantRootDeriverRoleV1::DeriverA);
        let pending_stored = CloudflareStoredTenantRootRoleShareV1 {
            record: pending.clone(),
            revision: 1,
        };
        let original = accepted_loss_activation_for_record(&pending, 0x61, 0x89, 20);
        let original_payload = activate_initial_payload_digest(&pending_stored, &original, 20, 1)
            .expect("accepted-loss activation payload");
        let identity = pending.identity().digest().expect("identity digest");
        let key = TenantRootCommandReplayKeyV1::deriver_a(
            identity,
            pending.custody_lineage(),
            TenantRootCeremonySessionIdV1::from_bytes([0x21; 16]).expect("session"),
            TenantRootCeremonyNonceV1::from_bytes([0x22; 32]).expect("nonce"),
        );
        let scope = TenantRootCommandScopeV1::new(key, pending.epoch(), 1).expect("scope");
        let command_digest = scope
            .command_digest(TenantRootCommandOperationV1::activate_initial(
                original_payload,
            ))
            .expect("command digest");
        let reservation = match reserve_tenant_root_command_v1(None, key, command_digest, 61)
            .expect("fresh accepted-loss reservation")
        {
            TenantRootCommandReplayDecisionV1::Execute(reservation) => reservation,
            _ => panic!("fresh accepted-loss command must be executable"),
        };
        let stored = TenantRootCommandReplayRecordV1::Reserved(reservation);
        assert!(matches!(
            reserve_tenant_root_command_v1(Some(&stored), key, command_digest, 62)
                .expect("identical accepted-loss replay"),
            TenantRootCommandReplayDecisionV1::InProgress
        ));

        let replacement = accepted_loss_activation_for_record(&pending, 0x62, 0x89, 20);
        let replacement_payload =
            activate_initial_payload_digest(&pending_stored, &replacement, 20, 1)
                .expect("replacement accepted-loss activation payload");
        let replacement_digest = scope
            .command_digest(TenantRootCommandOperationV1::activate_initial(
                replacement_payload,
            ))
            .expect("replacement command digest");
        assert_ne!(command_digest, replacement_digest);
        assert!(
            reserve_tenant_root_command_v1(Some(&stored), key, replacement_digest, 62).is_err()
        );
    }

    #[test]
    fn encrypted_active_record_round_trip_retains_exact_activation_receipt_bytes() {
        let cipher = test_cipher(CloudflareTenantRootDeriverRoleV1::DeriverA, 0x41);
        let activation =
            current_backup_activation(CloudflareTenantRootDeriverRoleV1::DeriverA, 0x88, 0x89, 20);
        let record = record(CloudflareTenantRootDeriverRoleV1::DeriverA)
            .into_active(activation.clone(), 20)
            .expect("active record");
        let row = row_from_record(&cipher, &record);
        let opened = cipher.open(&row).expect("opened active record");
        let CloudflareTenantRootRoleShareLifecycleV1::Active(active) = opened.lifecycle else {
            panic!("active lifecycle");
        };
        assert_eq!(
            active.activation.activation_receipt_bytes,
            activation.activation_receipt_bytes
        );
        assert_eq!(
            active.activation.activation_receipt_digest,
            activation.activation_receipt_digest
        );
        assert_eq!(
            active.activation.activated_at_ms,
            activation.activated_at_ms
        );

        let mut tampered = record;
        let CloudflareTenantRootRoleShareLifecycleV1::Active(active) = &mut tampered.lifecycle
        else {
            panic!("active lifecycle");
        };
        let CloudflareTenantRootAvailabilityEvidenceV1::CurrentRoleBackup {
            identity_digest, ..
        } = &mut active.activation.availability
        else {
            panic!("expected current-backup availability");
        };
        *identity_digest = TenantRootIdentityDigestV1::from_bytes([0x91; 32]);
        assert!(cipher.open(&row_from_record(&cipher, &tampered)).is_err());
    }

    #[test]
    fn active_initial_activation_retry_reuses_exact_receipt_and_pending_command_revision() {
        let pending = record(CloudflareTenantRootDeriverRoleV1::DeriverA);
        let pending_stored = CloudflareStoredTenantRootRoleShareV1 {
            record: pending.clone(),
            revision: 1,
        };
        let activation =
            current_backup_activation(CloudflareTenantRootDeriverRoleV1::DeriverA, 0x88, 0x89, 20);
        let active_record = pending
            .clone()
            .into_active(activation.clone(), 20)
            .expect("active record");
        let active_stored = CloudflareStoredTenantRootRoleShareV1 {
            record: active_record,
            revision: 2,
        };

        assert_eq!(
            active_stored
                .active_activation_receipt_bytes()
                .expect("stored activation receipt"),
            activation.activation_receipt_bytes()
        );
        let retry_pending = active_stored
            .initial_activation_retry_pending()
            .expect("retry pending record");
        assert_eq!(retry_pending.revision(), pending_stored.revision());
        assert!(matches!(
            retry_pending.record().lifecycle(),
            CloudflareTenantRootRoleShareLifecycleV1::Pending(_)
        ));
        assert_eq!(
            retry_pending.record().updated_at_ms(),
            pending_stored.record().updated_at_ms()
        );
        assert_eq!(
            activate_initial_payload_digest(&pending_stored, &activation, 20, 1)
                .expect("original activation payload"),
            activate_initial_payload_digest(&retry_pending, &activation, 20, 1)
                .expect("retry activation payload")
        );
    }

    #[test]
    fn old_digest_only_activation_wire_is_rejected() {
        let activation =
            current_backup_activation(CloudflareTenantRootDeriverRoleV1::DeriverA, 0x88, 0x89, 20);
        let old_shape = serde_json::json!({
            "availability": serde_json::to_value(&activation.availability)
                .expect("availability JSON"),
            "activation_receipt_digest_hex": encode_hex(
                activation.activation_receipt_digest().as_bytes()
            ),
            "activated_at_ms": activation.activated_at_ms(),
        });
        assert!(serde_json::from_value::<TenantRootRoleD1ActivationWireV1>(old_shape).is_err());
    }

    #[test]
    fn activation_replay_substitution_retains_only_the_replacement_exact_bytes() {
        let pending = record(CloudflareTenantRootDeriverRoleV1::DeriverA);
        let original =
            current_backup_activation(CloudflareTenantRootDeriverRoleV1::DeriverA, 0x88, 0x89, 20);
        let replacement =
            current_backup_activation(CloudflareTenantRootDeriverRoleV1::DeriverA, 0x88, 0x90, 20);
        assert_ne!(
            original.activation_receipt_bytes(),
            replacement.activation_receipt_bytes()
        );
        let original_digest = original.activation_receipt_digest();
        let active = pending.into_active(original, 20).expect("active record");
        let mut stored = CloudflareStoredTenantRootRoleShareV1 {
            record: active,
            revision: 1,
        };
        {
            let CloudflareTenantRootRoleShareLifecycleV1::Active(active) =
                &mut stored.record.lifecycle
            else {
                panic!("active lifecycle");
            };
            active.activation.activation_receipt_bytes =
                replacement.activation_receipt_bytes.clone();
        }
        assert!(validate_active_stored_record_shape(&stored).is_err());
        {
            let CloudflareTenantRootRoleShareLifecycleV1::Active(active) =
                &mut stored.record.lifecycle
            else {
                panic!("active lifecycle");
            };
            active.activation.activation_receipt_digest = replacement.activation_receipt_digest;
            active.activation.activated_at_ms = replacement.activated_at_ms;
        }
        validate_active_stored_record_shape(&stored).expect("replacement remains self-consistent");
        let replacement_binding = active_binding_from_stored(&stored).expect("active binding");
        assert_eq!(
            replacement_binding.activation_receipt_digest(),
            replacement.activation_receipt_digest()
        );
        assert_ne!(
            replacement_binding.activation_receipt_digest(),
            original_digest
        );
    }

    #[test]
    fn lifecycle_is_forward_only_and_retains_activation_evidence() {
        let pending = record(CloudflareTenantRootDeriverRoleV1::DeriverA);
        let activation =
            current_backup_activation(CloudflareTenantRootDeriverRoleV1::DeriverA, 0x88, 0x89, 20);
        let installation_digest = match pending.lifecycle() {
            CloudflareTenantRootRoleShareLifecycleV1::Pending(pending) => {
                pending.installation_evidence_digest()
            }
            _ => unreachable!(),
        };
        let activation_digest = activation.activation_receipt_digest();
        let backup_digest = match &activation.availability {
            CloudflareTenantRootAvailabilityEvidenceV1::CurrentRoleBackup {
                role_backup_receipt_digest,
                ..
            } => *role_backup_receipt_digest,
            CloudflareTenantRootAvailabilityEvidenceV1::AcceptedPermanentDerivationLoss {
                ..
            } => {
                panic!("expected current-backup availability")
            }
        };
        let active = pending
            .into_active(activation, 20)
            .expect("pending activates");
        assert_eq!(active.lifecycle.as_str(), "active");
        let CloudflareTenantRootRoleShareLifecycleV1::Active(active_evidence) = &active.lifecycle
        else {
            panic!("active lifecycle");
        };
        assert_eq!(
            active_evidence.pending.installation_evidence_digest,
            installation_digest
        );
        assert!(matches!(
            &active_evidence.activation.availability,
            CloudflareTenantRootAvailabilityEvidenceV1::CurrentRoleBackup {
                role_backup_receipt_digest,
                ..
            } if *role_backup_receipt_digest == backup_digest
        ));
        assert_eq!(
            active_evidence.activation.activation_receipt_digest,
            activation_digest
        );
        let retired = active
            .into_retired(
                CloudflareTenantRootRetirementV1::new(
                    lifecycle_receipt(0x90).expect("retirement receipt"),
                    30,
                )
                .expect("retirement"),
                30,
            )
            .expect("active retires");
        assert_eq!(retired.lifecycle.as_str(), "retired");
        let CloudflareTenantRootRoleShareLifecycleV1::Retired(retired_evidence) =
            &retired.lifecycle
        else {
            panic!("retired lifecycle");
        };
        assert_eq!(
            retired_evidence.active.pending.installation_evidence_digest,
            installation_digest
        );
        assert_eq!(
            retired_evidence.active.activation.activation_receipt_digest,
            activation_digest
        );
        assert_eq!(
            retired_evidence.retirement.retirement_receipt_digest,
            lifecycle_receipt(0x90).expect("retirement receipt")
        );
        let cipher = test_cipher(CloudflareTenantRootDeriverRoleV1::DeriverA, 0x43);
        let row = row_from_record(&cipher, &retired);
        assert_eq!(cipher.open(&row).expect("retired record opens"), retired);
        assert!(retired
            .clone()
            .into_active(
                current_backup_activation(
                    CloudflareTenantRootDeriverRoleV1::DeriverA,
                    0x99,
                    0x9a,
                    40
                ),
                40,
            )
            .is_err());
        assert!(TenantRootLifecycleReceiptDigestV1::from_bytes([0; 32]).is_err());
    }

    #[test]
    fn lifecycle_rejects_out_of_order_evidence() {
        let mut activation =
            current_backup_activation(CloudflareTenantRootDeriverRoleV1::DeriverA, 0x88, 0x89, 20);
        activation.activated_at_ms = 9;
        assert!(record(CloudflareTenantRootDeriverRoleV1::DeriverA)
            .into_active(activation, 10)
            .is_err());

        let active = record(CloudflareTenantRootDeriverRoleV1::DeriverA)
            .into_active(
                current_backup_activation(
                    CloudflareTenantRootDeriverRoleV1::DeriverA,
                    0x88,
                    0x89,
                    20,
                ),
                20,
            )
            .expect("active");
        assert!(active
            .into_retired(
                CloudflareTenantRootRetirementV1::new(
                    lifecycle_receipt(0x90).expect("retirement receipt"),
                    19,
                )
                .expect("retirement shape"),
                30,
            )
            .is_err());

        let active = record(CloudflareTenantRootDeriverRoleV1::DeriverA)
            .into_active(
                current_backup_activation(
                    CloudflareTenantRootDeriverRoleV1::DeriverA,
                    0x88,
                    0x89,
                    20,
                ),
                20,
            )
            .expect("active");
        assert!(active
            .into_retired(
                CloudflareTenantRootRetirementV1::new(
                    lifecycle_receipt(0x90).expect("retirement receipt"),
                    30,
                )
                .expect("retirement shape"),
                19,
            )
            .is_err());

        assert!(record(CloudflareTenantRootDeriverRoleV1::DeriverA)
            .into_active(
                current_backup_activation(
                    CloudflareTenantRootDeriverRoleV1::DeriverA,
                    0x88,
                    0x89,
                    20,
                ),
                19,
            )
            .is_err());
    }

    fn assert_payload_digest_changes(
        cases: &[(&str, TenantRootProtocolDigestV1, TenantRootProtocolDigestV1)],
    ) {
        for (label, original, changed) in cases {
            assert_ne!(
                original, changed,
                "{label} did not change its payload digest"
            );
        }
    }

    #[test]
    fn branch_commands_preserve_linear_reservation_for_terminalization() {
        let pending = record(CloudflareTenantRootDeriverRoleV1::DeriverA);
        let identity = pending.identity().digest().expect("identity digest");
        let lineage = pending.custody_lineage();
        let key = TenantRootCommandReplayKeyV1::deriver_a(
            identity,
            lineage,
            TenantRootCeremonySessionIdV1::from_bytes([0x21; 16]).expect("session"),
            TenantRootCeremonyNonceV1::from_bytes([0x22; 32]).expect("nonce"),
        );
        let scope = TenantRootCommandScopeV1::new(key, pending.epoch(), 1).expect("scope");
        let command_digest =
            TenantRootProtocolDigestV1::from_bytes([0x23; 32]).expect("command digest");
        let reservation = match reserve_tenant_root_command_v1(None, key, command_digest, 1)
            .expect("reservation")
        {
            TenantRootCommandReplayDecisionV1::Execute(reservation) => reservation,
            _ => panic!("fresh reservation must be executable"),
        };
        let command = CloudflareTenantRootInsertPendingCommandV1 {
            scope,
            reservation,
            record: pending,
            expected_revision: 1,
            operation_payload_digest: command_digest,
        };
        let CloudflareTenantRootInsertPendingCommandV1 { reservation, .. } = command;
        let terminal = reservation
            .checkpoint_executed(2)
            .expect("reservation checkpoints")
            .complete(
                TenantRootProtocolDigestV1::from_bytes([0x24; 32]).expect("receipt digest"),
                3,
            )
            .expect("executed reservation terminalizes");
        assert_eq!(terminal.key(), &key);
        assert_eq!(terminal.command_digest(), command_digest);
    }

    #[test]
    fn persisted_command_checkpoints_reconstruct_only_the_exact_resume_token() {
        let identity = test_identity().digest().expect("identity digest");
        let lineage = TenantRootCustodyLineageId::from_bytes([0x31; 16]).expect("lineage");
        let session = TenantRootCeremonySessionIdV1::from_bytes([0x32; 16]).expect("session");
        let nonce = TenantRootCeremonyNonceV1::from_bytes([0x33; 32]).expect("nonce");
        let key = TenantRootCommandReplayKeyV1::deriver_a(identity, lineage, session, nonce);
        let command_digest = TenantRootProtocolDigestV1::from_bytes([0x34; 32]).expect("digest");
        let reservation = match reserve_tenant_root_command_v1(None, key, command_digest, 40)
            .expect("reservation")
        {
            TenantRootCommandReplayDecisionV1::Execute(reservation) => reservation,
            _ => panic!("fresh reservation must be executable"),
        };
        let executed = reservation.checkpoint_executed(41).expect("checkpoint");
        let stored = StoredTenantRootCommandReplayV1 {
            record: TenantRootCommandReplayRecordV1::Executed(executed),
            receipt_bytes: None,
            admission_digest: None,
            reserved_at_ms: 40,
            executed_at_ms: Some(41),
        };
        let resumed = replay_executed_from_stored(&stored).expect("resume token");
        assert_eq!(resumed.key(), &key);
        assert_eq!(resumed.command_digest(), command_digest);
        assert_eq!(resumed.reserved_at_ms(), 40);
        assert_eq!(resumed.executed_at_ms(), 41);
        assert!(replay_reservation_from_stored(&stored).is_err());
    }

    #[test]
    fn d1_terminal_receipt_reload_rejects_untrusted_bytes_and_row_substitutions() {
        let identity = test_identity().digest().expect("identity digest");
        let lineage = TenantRootCustodyLineageId::from_bytes([0x41; 16]).expect("lineage");
        let session = TenantRootCeremonySessionIdV1::from_bytes([0x42; 16]).expect("session");
        let nonce = TenantRootCeremonyNonceV1::from_bytes([0x43; 32]).expect("nonce");
        let key = TenantRootCommandReplayKeyV1::deriver_a(identity, lineage, session, nonce);
        let command_digest = TenantRootProtocolDigestV1::from_bytes([0x44; 32]).expect("digest");
        let signing_key = SigningKey::from_bytes(&[0x45; 32]);
        let signed = TenantRootCommandTerminalReceiptV1::sign_success(
            key,
            command_digest,
            b"terminal payload".to_vec(),
            20,
            "r120-test-command-key-v1",
            signing_key.as_bytes(),
        )
        .expect("signed receipt");
        let receipt_bytes = signed.canonical_bytes().expect("receipt bytes");
        let receipt_b64u = encode_base64url_bytes_v1(&receipt_bytes);
        let receipt_digest = signed.digest().expect("receipt digest");
        let receipt_digest_hex = encode_hex(receipt_digest.as_bytes());

        let arbitrary_bytes = encode_base64url_bytes_v1(b"arbitrary bytes");
        let arbitrary_digest = encode_hex(Sha256::digest(b"arbitrary bytes").as_ref());
        assert!(decode_stored_terminal_receipt(
            TenantRootCommandTerminalKindV1::Completed,
            Some(arbitrary_bytes.as_str()),
            Some(arbitrary_digest.as_str()),
            Some(20),
            key,
            command_digest,
        )
        .is_err());

        assert!(decode_stored_terminal_receipt(
            TenantRootCommandTerminalKindV1::Failed,
            Some(receipt_b64u.as_str()),
            Some(receipt_digest_hex.as_str()),
            Some(20),
            key,
            command_digest,
        )
        .is_err());

        let wrong_session = TenantRootCeremonySessionIdV1::from_bytes([0x46; 16]).expect("session");
        let wrong_key =
            TenantRootCommandReplayKeyV1::deriver_a(identity, lineage, wrong_session, nonce);
        assert!(decode_stored_terminal_receipt(
            TenantRootCommandTerminalKindV1::Completed,
            Some(receipt_b64u.as_str()),
            Some(receipt_digest_hex.as_str()),
            Some(20),
            wrong_key,
            command_digest,
        )
        .is_err());

        let wrong_command_digest =
            TenantRootProtocolDigestV1::from_bytes([0x47; 32]).expect("digest");
        assert!(decode_stored_terminal_receipt(
            TenantRootCommandTerminalKindV1::Completed,
            Some(receipt_b64u.as_str()),
            Some(receipt_digest_hex.as_str()),
            Some(20),
            key,
            wrong_command_digest,
        )
        .is_err());

        let wrong_receipt_digest = encode_hex([0x48; 32].as_ref());
        assert!(decode_stored_terminal_receipt(
            TenantRootCommandTerminalKindV1::Completed,
            Some(receipt_b64u.as_str()),
            Some(wrong_receipt_digest.as_str()),
            Some(20),
            key,
            command_digest,
        )
        .is_err());

        assert!(decode_stored_terminal_receipt(
            TenantRootCommandTerminalKindV1::Completed,
            Some(receipt_b64u.as_str()),
            Some(receipt_digest_hex.as_str()),
            Some(21),
            key,
            command_digest,
        )
        .is_err());
    }

    #[test]
    fn d1_terminal_receipt_reload_returns_exact_canonical_success_and_failure_bytes() {
        let identity = test_identity().digest().expect("identity digest");
        let lineage = TenantRootCustodyLineageId::from_bytes([0x51; 16]).expect("lineage");
        let session = TenantRootCeremonySessionIdV1::from_bytes([0x52; 16]).expect("session");
        let nonce = TenantRootCeremonyNonceV1::from_bytes([0x53; 32]).expect("nonce");
        let key = TenantRootCommandReplayKeyV1::deriver_a(identity, lineage, session, nonce);
        let command_digest = TenantRootProtocolDigestV1::from_bytes([0x54; 32]).expect("digest");
        let signing_key = SigningKey::from_bytes(&[0x55; 32]);

        let success = TenantRootCommandTerminalReceiptV1::sign_success(
            key,
            command_digest,
            b"success payload".to_vec(),
            20,
            "r120-test-command-key-v1",
            signing_key.as_bytes(),
        )
        .expect("success receipt");
        let success_bytes = success.canonical_bytes().expect("success bytes");
        let success_b64u = encode_base64url_bytes_v1(&success_bytes);
        let success_digest = success.digest().expect("success digest");
        let success_digest_hex = encode_hex(success_digest.as_bytes());
        let opened_success = decode_stored_terminal_receipt(
            TenantRootCommandTerminalKindV1::Completed,
            Some(success_b64u.as_str()),
            Some(success_digest_hex.as_str()),
            Some(20),
            key,
            command_digest,
        )
        .expect("exact success receipt reload");
        assert_eq!(opened_success.receipt_bytes, success_bytes);
        assert_eq!(opened_success.receipt_digest, success_digest);
        assert_eq!(opened_success.terminal_at_ms, 20);

        let failure = TenantRootCommandTerminalReceiptV1::sign_failure(
            key,
            command_digest,
            b"failure payload".to_vec(),
            21,
            "r120-test-command-key-v1",
            signing_key.as_bytes(),
        )
        .expect("failure receipt");
        let failure_bytes = failure.canonical_bytes().expect("failure bytes");
        let failure_b64u = encode_base64url_bytes_v1(&failure_bytes);
        let failure_digest = failure.digest().expect("failure digest");
        let failure_digest_hex = encode_hex(failure_digest.as_bytes());
        let opened_failure = decode_stored_terminal_receipt(
            TenantRootCommandTerminalKindV1::Failed,
            Some(failure_b64u.as_str()),
            Some(failure_digest_hex.as_str()),
            Some(21),
            key,
            command_digest,
        )
        .expect("exact failure receipt reload");
        assert_eq!(opened_failure.receipt_bytes, failure_bytes);
        assert_eq!(opened_failure.receipt_digest, failure_digest);
        assert_eq!(opened_failure.terminal_at_ms, 21);
    }

    #[test]
    fn command_payload_digest_binds_each_operation_and_substitution() {
        let pending = record(CloudflareTenantRootDeriverRoleV1::DeriverA);
        let pending_stored = CloudflareStoredTenantRootRoleShareV1 {
            record: pending.clone(),
            revision: 1,
        };
        let initial_activation = current_backup_activation_for_record(&pending, 0x88, 0x89, 20);
        let initial_active_record = pending
            .clone()
            .into_active(initial_activation.clone(), 20)
            .expect("active record");
        let active_stored = CloudflareStoredTenantRootRoleShareV1 {
            record: initial_active_record,
            revision: 2,
        };

        let successor = record_for_identity_epoch(
            test_identity(),
            CloudflareTenantRootDeriverRoleV1::DeriverA,
            0x44,
            epoch(2),
            pair_commitment(CloudflareTenantRootDeriverRoleV1::DeriverA, 18),
        );
        let successor_stored = CloudflareStoredTenantRootRoleShareV1 {
            record: successor.clone(),
            revision: 1,
        };
        let successor_activation = current_backup_activation_for_record(&successor, 0x90, 0x91, 40);
        let retirement = CloudflareTenantRootRetirementV1::new(
            lifecycle_receipt(0x92).expect("retirement receipt"),
            40,
        )
        .expect("retirement");

        let insert = insert_pending_payload_digest(&pending, 1).expect("insert digest");
        let activate = activate_initial_payload_digest(&pending_stored, &initial_activation, 20, 1)
            .expect("activation digest");
        let swap = swap_active_epoch_payload_digest(
            &active_stored,
            &successor_stored,
            &successor_activation,
            &retirement,
            40,
            2,
            1,
        )
        .expect("swap digest");
        let cleanup = cleanup_pending_payload_digest(&successor_stored, 1).expect("cleanup digest");

        let mut changed_insert_record = pending.clone();
        changed_insert_record.sealed_share =
            CloudflareTenantRootSealedRoleShareV1::new(&[0x68; 96]).expect("sealed share");
        let changed_insert =
            insert_pending_payload_digest(&changed_insert_record, 1).expect("insert substitution");

        let mut changed_pending = pending.clone();
        changed_pending.updated_at_ms = 11;
        let changed_activate_record = CloudflareStoredTenantRootRoleShareV1 {
            record: changed_pending,
            revision: 1,
        };
        let changed_activate_record_digest =
            activate_initial_payload_digest(&changed_activate_record, &initial_activation, 20, 1)
                .expect("activation record substitution");
        let mut changed_activation = initial_activation.clone();
        let replacement_activation = current_backup_activation_for_record(&pending, 0x88, 0x93, 20);
        changed_activation.activation_receipt_bytes =
            replacement_activation.activation_receipt_bytes.clone();
        changed_activation.activation_receipt_digest =
            replacement_activation.activation_receipt_digest;
        changed_activation.activated_at_ms = replacement_activation.activated_at_ms;
        let changed_activate_evidence =
            activate_initial_payload_digest(&pending_stored, &changed_activation, 20, 1)
                .expect("activation evidence substitution");
        let changed_activate_timestamp =
            activate_initial_payload_digest(&pending_stored, &initial_activation, 21, 1)
                .expect("activation timestamp substitution");
        let changed_activate_revision =
            activate_initial_payload_digest(&pending_stored, &initial_activation, 20, 2)
                .expect("activation revision substitution");

        let mut changed_active = active_stored.clone();
        changed_active.record.sealed_share =
            CloudflareTenantRootSealedRoleShareV1::new(&[0x69; 96]).expect("sealed share");
        let changed_swap_active = swap_active_epoch_payload_digest(
            &changed_active,
            &successor_stored,
            &successor_activation,
            &retirement,
            40,
            2,
            1,
        )
        .expect("swap active-row substitution");
        let mut changed_successor = successor_stored.clone();
        changed_successor.record.sealed_share =
            CloudflareTenantRootSealedRoleShareV1::new(&[0x6a; 96]).expect("sealed share");
        let changed_swap_pending = swap_active_epoch_payload_digest(
            &active_stored,
            &changed_successor,
            &successor_activation,
            &retirement,
            40,
            2,
            1,
        )
        .expect("swap pending-row substitution");
        let mut changed_successor_activation = successor_activation.clone();
        let replacement_successor_activation =
            current_backup_activation_for_record(&successor, 0x90, 0x94, 40);
        changed_successor_activation.activation_receipt_bytes = replacement_successor_activation
            .activation_receipt_bytes
            .clone();
        changed_successor_activation.activation_receipt_digest =
            replacement_successor_activation.activation_receipt_digest;
        changed_successor_activation.activated_at_ms =
            replacement_successor_activation.activated_at_ms;
        let changed_swap_evidence = swap_active_epoch_payload_digest(
            &active_stored,
            &successor_stored,
            &changed_successor_activation,
            &retirement,
            40,
            2,
            1,
        )
        .expect("swap evidence substitution");
        let mut changed_retirement = retirement.clone();
        changed_retirement.retirement_receipt_digest =
            lifecycle_receipt(0x95).expect("retirement receipt");
        let changed_swap_retirement = swap_active_epoch_payload_digest(
            &active_stored,
            &successor_stored,
            &successor_activation,
            &changed_retirement,
            40,
            2,
            1,
        )
        .expect("swap retirement substitution");
        let changed_swap_timestamp = swap_active_epoch_payload_digest(
            &active_stored,
            &successor_stored,
            &successor_activation,
            &retirement,
            41,
            2,
            1,
        )
        .expect("swap timestamp substitution");
        let changed_swap_active_revision = swap_active_epoch_payload_digest(
            &active_stored,
            &successor_stored,
            &successor_activation,
            &retirement,
            40,
            3,
            1,
        )
        .expect("swap active revision substitution");
        let changed_swap_pending_revision = swap_active_epoch_payload_digest(
            &active_stored,
            &successor_stored,
            &successor_activation,
            &retirement,
            40,
            2,
            2,
        )
        .expect("swap pending revision substitution");

        let changed_cleanup_record = cleanup_pending_payload_digest(&changed_successor, 1)
            .expect("cleanup record substitution");
        let changed_cleanup_revision =
            cleanup_pending_payload_digest(&successor_stored, 2).expect("cleanup revision");

        assert_payload_digest_changes(&[
            ("insert record", insert, changed_insert),
            ("activate record", activate, changed_activate_record_digest),
            ("activate evidence", activate, changed_activate_evidence),
            ("activate timestamp", activate, changed_activate_timestamp),
            (
                "activate local revision",
                activate,
                changed_activate_revision,
            ),
            ("swap active record", swap, changed_swap_active),
            ("swap pending record", swap, changed_swap_pending),
            ("swap activation evidence", swap, changed_swap_evidence),
            ("swap retirement evidence", swap, changed_swap_retirement),
            ("swap timestamp", swap, changed_swap_timestamp),
            (
                "swap active local revision",
                swap,
                changed_swap_active_revision,
            ),
            (
                "swap pending local revision",
                swap,
                changed_swap_pending_revision,
            ),
            ("cleanup record", cleanup, changed_cleanup_record),
            ("cleanup local revision", cleanup, changed_cleanup_revision),
        ]);

        let identity = pending.identity().digest().expect("identity digest");
        let key = TenantRootCommandReplayKeyV1::deriver_a(
            identity,
            pending.custody_lineage(),
            TenantRootCeremonySessionIdV1::from_bytes([0x21; 16]).expect("session"),
            TenantRootCeremonyNonceV1::from_bytes([0x22; 32]).expect("nonce"),
        );
        let scope = TenantRootCommandScopeV1::new(key, pending.epoch(), 1).expect("scope");
        let operation = TenantRootCommandOperationV1::activate_initial(activate);
        let digest = scope.command_digest(operation).expect("command digest");
        let changed_scope =
            TenantRootCommandScopeV1::new(key, pending.epoch(), 2).expect("changed scope");
        assert_ne!(
            digest,
            changed_scope
                .command_digest(operation)
                .expect("changed command digest")
        );
    }

    #[test]
    fn current_backup_activation_rejects_record_binding_substitution() {
        let pending = record(CloudflareTenantRootDeriverRoleV1::DeriverA);
        let activation =
            current_backup_activation(CloudflareTenantRootDeriverRoleV1::DeriverA, 0x88, 0x89, 20);

        let mut wrong_identity = activation.clone();
        let CloudflareTenantRootAvailabilityEvidenceV1::CurrentRoleBackup {
            identity_digest, ..
        } = &mut wrong_identity.availability
        else {
            panic!("expected current-backup availability");
        };
        *identity_digest = TenantRootIdentityDigestV1::from_bytes([0x91; 32]);
        assert!(pending.clone().into_active(wrong_identity, 20).is_err());

        let mut wrong_lineage = activation.clone();
        let CloudflareTenantRootAvailabilityEvidenceV1::CurrentRoleBackup {
            custody_lineage, ..
        } = &mut wrong_lineage.availability
        else {
            panic!("expected current-backup availability");
        };
        *custody_lineage = TenantRootCustodyLineageId::from_bytes([0x45; 16]).expect("lineage");
        assert!(pending.clone().into_active(wrong_lineage, 20).is_err());

        let mut wrong_role = activation.clone();
        let CloudflareTenantRootAvailabilityEvidenceV1::CurrentRoleBackup { role, .. } =
            &mut wrong_role.availability
        else {
            panic!("expected current-backup availability");
        };
        *role = TenantRootManagedRestoreRoleV1::DeriverB;
        assert!(pending.clone().into_active(wrong_role, 20).is_err());

        let mut wrong_epoch = activation.clone();
        let CloudflareTenantRootAvailabilityEvidenceV1::CurrentRoleBackup { epoch, .. } =
            &mut wrong_epoch.availability
        else {
            panic!("expected current-backup availability");
        };
        *epoch = TenantRootShareEpoch::new(2).expect("epoch");
        assert!(pending.clone().into_active(wrong_epoch, 20).is_err());

        let mut wrong_commitment = activation;
        let CloudflareTenantRootAvailabilityEvidenceV1::CurrentRoleBackup {
            share_commitment, ..
        } = &mut wrong_commitment.availability
        else {
            panic!("expected current-backup availability");
        };
        *share_commitment = test_commitment(CloudflareTenantRootDeriverRoleV1::DeriverB);
        assert!(pending.into_active(wrong_commitment, 20).is_err());
    }

    #[test]
    fn initial_creation_reservation_requires_fresh_command_and_exact_record_binding() {
        let command = test_verified_initial_creation_command(TwoPartyDeriverRole::DeriverA, 20, 40);
        let pending = record(CloudflareTenantRootDeriverRoleV1::DeriverA);

        let scope = initial_creation_scope_for_record(&command, &pending, 25)
            .expect("fresh verified command matches pending record");
        assert_eq!(scope.key().role(), TwoPartyDeriverRole::DeriverA);
        assert_eq!(scope.epoch(), TenantRootShareEpoch::INITIAL);
        assert_eq!(scope.expected_control_plane_revision(), 1);

        assert!(initial_creation_scope_for_record(&command, &pending, 41).is_err());
        assert!(initial_creation_scope_for_record(
            &command,
            &record(CloudflareTenantRootDeriverRoleV1::DeriverB),
            25,
        )
        .is_err());

        let mut substituted_identity = pending;
        substituted_identity.identity = TenantRootIdentityV1::new(
            "org-2",
            "project-1",
            "env-1",
            "project-1:env-1",
            "root-version-1",
        )
        .expect("substituted identity");
        assert!(initial_creation_scope_for_record(&command, &substituted_identity, 25).is_err());
    }

    #[test]
    fn initial_creation_input_derives_the_pending_digest_from_exact_evidence_bytes() {
        let command = test_verified_initial_creation_command(TwoPartyDeriverRole::DeriverA, 20, 40);
        let context = test_creation_context();
        let evidence = test_initial_creation_evidence(&context, TwoPartyDeriverRole::DeriverA);
        let expected_digest = evidence
            .lifecycle_receipt_digest()
            .expect("evidence digest");
        let share = CloudflareTenantRootInitialCreationShareInputV1::new(
            test_identity(),
            test_sealed_online_share(&context, &evidence, TwoPartyDeriverRole::DeriverA),
            10,
        );
        let creation = CloudflareTenantRootInitialCreationInputV1::new(command, evidence, share)
            .expect("initial creation input");
        let CloudflareTenantRootRoleShareLifecycleV1::Pending(pending) =
            creation.record.lifecycle()
        else {
            panic!("initial creation must produce a pending record");
        };
        assert_eq!(pending.installation_evidence_digest(), expected_digest);
    }

    #[test]
    fn initial_creation_input_rejects_evidence_role_and_identity_substitution() {
        let command = test_verified_initial_creation_command(TwoPartyDeriverRole::DeriverA, 20, 40);
        let context = test_creation_context();
        let wrong_role_evidence =
            test_initial_creation_evidence(&context, TwoPartyDeriverRole::DeriverB);
        let wrong_role_share = CloudflareTenantRootInitialCreationShareInputV1::new(
            test_identity(),
            test_sealed_online_share(
                &context,
                &wrong_role_evidence,
                TwoPartyDeriverRole::DeriverB,
            ),
            10,
        );
        assert!(CloudflareTenantRootInitialCreationInputV1::new(
            command,
            wrong_role_evidence,
            wrong_role_share,
        )
        .is_err());

        let command = test_verified_initial_creation_command(TwoPartyDeriverRole::DeriverA, 20, 40);
        let foreign_identity = TenantRootIdentityV1::new(
            "org-2",
            "project-1",
            "env-1",
            "project-1:env-1",
            "root-version-1",
        )
        .expect("foreign identity");
        let foreign_context = test_creation_context_for_identity(foreign_identity.clone());
        let foreign_evidence =
            test_initial_creation_evidence(&foreign_context, TwoPartyDeriverRole::DeriverA);
        let foreign_share = CloudflareTenantRootInitialCreationShareInputV1::new(
            foreign_identity,
            test_sealed_online_share(
                &foreign_context,
                &foreign_evidence,
                TwoPartyDeriverRole::DeriverA,
            ),
            10,
        );
        assert!(CloudflareTenantRootInitialCreationInputV1::new(
            command,
            foreign_evidence,
            foreign_share,
        )
        .is_err());
    }

    #[test]
    fn initial_creation_input_rejects_sealed_share_evidence_substitution() {
        let command = test_verified_initial_creation_command(TwoPartyDeriverRole::DeriverA, 20, 40);
        let context = test_creation_context();
        let sealed_evidence =
            test_initial_creation_evidence(&context, TwoPartyDeriverRole::DeriverA);
        let share_a = SigningRootShare::from_canonical_bytes(
            TwoPartyDeriverRole::DeriverA.share_id(),
            Scalar::from(17_u64).to_bytes(),
        )
        .expect("Deriver A share");
        let share_b = SigningRootShare::from_canonical_bytes(
            TwoPartyDeriverRole::DeriverB.share_id(),
            Scalar::from(29_u64).to_bytes(),
        )
        .expect("Deriver B share");
        let substituted_evidence = signed_installation_evidence_wire(
            &context,
            TwoPartyDeriverRole::DeriverA,
            &share_a,
            &share_b,
            0x59,
            0x69,
        );
        assert_ne!(
            sealed_evidence.canonical_bytes(),
            substituted_evidence.canonical_bytes()
        );
        let share = CloudflareTenantRootInitialCreationShareInputV1::new(
            test_identity(),
            test_sealed_online_share(&context, &sealed_evidence, TwoPartyDeriverRole::DeriverA),
            10,
        );
        assert!(CloudflareTenantRootInitialCreationInputV1::new(
            command,
            substituted_evidence,
            share,
        )
        .is_err());
    }

    #[test]
    fn initial_creation_success_receipt_requires_the_exact_evidence_payload() {
        let context = test_creation_context();
        let evidence = test_initial_creation_evidence(&context, TwoPartyDeriverRole::DeriverA);
        let expected_payload = evidence.canonical_bytes().to_vec();
        let identity = test_identity().digest().expect("identity digest");
        let lineage = TenantRootCustodyLineageId::from_bytes([0x44; 16]).expect("lineage");
        let key = TenantRootCommandReplayKeyV1::deriver_a(
            identity,
            lineage,
            TenantRootCeremonySessionIdV1::from_bytes([0x71; 16]).expect("session"),
            TenantRootCeremonyNonceV1::from_bytes([0x72; 32]).expect("nonce"),
        );
        let command_digest = TenantRootProtocolDigestV1::from_bytes([0x73; 32]).expect("digest");
        let reservation = match reserve_tenant_root_command_v1(None, key, command_digest, 20)
            .expect("reservation")
        {
            TenantRootCommandReplayDecisionV1::Execute(reservation) => reservation,
            _ => panic!("fresh reservation must be executable"),
        };
        let executed = reservation.checkpoint_executed(21).expect("executed");
        let signing_key = SigningKey::from_bytes(&[0x74; 32]);
        let signed = TenantRootCommandTerminalReceiptV1::sign_success(
            key,
            command_digest,
            expected_payload,
            22,
            "r120-initial-creation-command-key-v1",
            signing_key.as_bytes(),
        )
        .expect("signed receipt");
        let receipt_bytes = signed.canonical_bytes().expect("receipt bytes");
        let receipt = TenantRootCommandTerminalReceiptV1::decode_canonical_bytes(&receipt_bytes)
            .expect("decoded receipt")
            .verify_success(
                &executed,
                "r120-initial-creation-command-key-v1",
                signing_key.verifying_key().as_bytes(),
            )
            .expect("verified receipt");
        assert!(validate_initial_creation_success_receipt_payload(&evidence, &receipt).is_ok());

        let signed = TenantRootCommandTerminalReceiptV1::sign_success(
            key,
            command_digest,
            b"substituted evidence bytes".to_vec(),
            22,
            "r120-initial-creation-command-key-v1",
            signing_key.as_bytes(),
        )
        .expect("signed substituted receipt");
        let receipt_bytes = signed.canonical_bytes().expect("receipt bytes");
        let receipt = TenantRootCommandTerminalReceiptV1::decode_canonical_bytes(&receipt_bytes)
            .expect("decoded substituted receipt")
            .verify_success(
                &executed,
                "r120-initial-creation-command-key-v1",
                signing_key.verifying_key().as_bytes(),
            )
            .expect("verified substituted receipt");
        assert!(validate_initial_creation_success_receipt_payload(&evidence, &receipt).is_err());
    }

    #[test]
    fn refresh_input_derives_pending_digest_from_exact_evidence_and_keeps_scope_revision() {
        let context = test_refresh_context();
        let evidence = test_refresh_evidence(&context, TwoPartyDeriverRole::DeriverA);
        let expected_digest = evidence
            .lifecycle_receipt_digest()
            .expect("refresh evidence digest");
        let command = test_verified_refresh_command(TwoPartyDeriverRole::DeriverA, 4);
        let input = refresh_input_with_sealed_evidence(
            command,
            evidence,
            test_identity(),
            &context,
            &test_refresh_evidence(&context, TwoPartyDeriverRole::DeriverA),
            TwoPartyDeriverRole::DeriverA,
        )
        .expect("refresh input");
        let CloudflareTenantRootRoleShareLifecycleV1::Pending(pending) = input.record.lifecycle()
        else {
            panic!("refresh insertion must produce a pending record");
        };
        assert_eq!(pending.installation_evidence_digest(), expected_digest);
        assert_eq!(input.record.epoch(), epoch(2));
        assert_eq!(input.command.scope().expected_control_plane_revision(), 4);
        assert_eq!(input.record.created_at_ms, 30);
        assert_eq!(input.record.updated_at_ms, 30);
    }

    #[test]
    fn refresh_replay_digest_binds_the_exact_signed_command() {
        let context = test_refresh_context();
        let command =
            test_verified_refresh_command_with_window(TwoPartyDeriverRole::DeriverA, 4, 20, 40);
        let changed_command =
            test_verified_refresh_command_with_window(TwoPartyDeriverRole::DeriverA, 4, 21, 39);
        let input = refresh_input_with_sealed_evidence(
            command,
            test_refresh_evidence(&context, TwoPartyDeriverRole::DeriverA),
            test_identity(),
            &context,
            &test_refresh_evidence(&context, TwoPartyDeriverRole::DeriverA),
            TwoPartyDeriverRole::DeriverA,
        )
        .expect("refresh input");
        let original_digest =
            refresh_insert_pending_payload_digest(&input.command, &input.record, 1)
                .expect("original operation payload digest");
        let changed_digest =
            refresh_insert_pending_payload_digest(&changed_command, &input.record, 1)
                .expect("changed operation payload digest");
        assert_ne!(input.command.digest(), changed_command.digest());
        assert_ne!(original_digest, changed_digest);

        let scope = input.command.scope();
        let key = *scope.key();
        let reserved = match reserve_tenant_root_command_v1(None, key, original_digest, 40)
            .expect("fresh reservation")
        {
            TenantRootCommandReplayDecisionV1::Execute(reservation) => reservation,
            _ => panic!("fresh reservation must be executable"),
        };
        let reserved_record = TenantRootCommandReplayRecordV1::Reserved(reserved);
        assert!(
            reserve_tenant_root_command_v1(Some(&reserved_record), key, changed_digest, 400,)
                .is_err()
        );
        assert!(matches!(
            reserve_tenant_root_command_v1(Some(&reserved_record), key, original_digest, 400)
                .expect("exact reserved retry"),
            TenantRootCommandReplayDecisionV1::InProgress
        ));

        let completed_reservation =
            match reserve_tenant_root_command_v1(None, key, original_digest, 40)
                .expect("fresh completion reservation")
            {
                TenantRootCommandReplayDecisionV1::Execute(reservation) => reservation,
                _ => panic!("fresh completion reservation must be executable"),
            };
        let completed = completed_reservation
            .checkpoint_executed(41)
            .expect("executed checkpoint")
            .complete(
                TenantRootProtocolDigestV1::from_bytes([0x79; 32]).expect("receipt digest"),
                42,
            )
            .expect("completed command");
        assert!(matches!(
            reserve_tenant_root_command_v1(Some(&completed), key, original_digest, 400)
                .expect("exact completed retry"),
            TenantRootCommandReplayDecisionV1::ReplayCompleted { .. }
        ));
        assert!(
            reserve_tenant_root_command_v1(Some(&completed), key, changed_digest, 400).is_err()
        );
    }

    #[test]
    fn refresh_input_rejects_context_identity_lineage_role_epoch_commitment_and_evidence_substitution(
    ) {
        let identity = test_identity();
        let context = test_refresh_context();

        let foreign_identity = TenantRootIdentityV1::new(
            "org-2",
            "project-1",
            "env-1",
            "project-1:env-1",
            "root-version-1",
        )
        .expect("foreign identity");
        let foreign_context =
            test_refresh_context_with_identity(foreign_identity.clone(), 0x44, 1, 2, 0x45, 0x46);
        let foreign_evidence =
            test_refresh_evidence(&foreign_context, TwoPartyDeriverRole::DeriverA);
        assert!(refresh_input_with_sealed_evidence(
            test_verified_refresh_command(TwoPartyDeriverRole::DeriverA, 4),
            foreign_evidence,
            foreign_identity,
            &foreign_context,
            &test_refresh_evidence(&foreign_context, TwoPartyDeriverRole::DeriverA),
            TwoPartyDeriverRole::DeriverA,
        )
        .is_err());

        let foreign_lineage_context =
            test_refresh_context_with_identity(identity.clone(), 0x45, 1, 2, 0x45, 0x46);
        let foreign_lineage_evidence =
            test_refresh_evidence(&foreign_lineage_context, TwoPartyDeriverRole::DeriverA);
        assert!(refresh_input_with_sealed_evidence(
            test_verified_refresh_command(TwoPartyDeriverRole::DeriverA, 4),
            foreign_lineage_evidence,
            identity.clone(),
            &foreign_lineage_context,
            &test_refresh_evidence(&foreign_lineage_context, TwoPartyDeriverRole::DeriverA),
            TwoPartyDeriverRole::DeriverA,
        )
        .is_err());

        let role_evidence = test_refresh_evidence(&context, TwoPartyDeriverRole::DeriverA);
        assert!(refresh_input_with_sealed_evidence(
            test_verified_refresh_command(TwoPartyDeriverRole::DeriverB, 4),
            role_evidence,
            identity.clone(),
            &context,
            &test_refresh_evidence(&context, TwoPartyDeriverRole::DeriverA),
            TwoPartyDeriverRole::DeriverA,
        )
        .is_err());

        let foreign_epoch_context =
            test_refresh_context_with_identity(identity.clone(), 0x44, 2, 3, 0x45, 0x46);
        let foreign_epoch_evidence =
            test_refresh_evidence(&foreign_epoch_context, TwoPartyDeriverRole::DeriverA);
        assert!(refresh_input_with_sealed_evidence(
            test_verified_refresh_command(TwoPartyDeriverRole::DeriverA, 4),
            foreign_epoch_evidence,
            identity.clone(),
            &foreign_epoch_context,
            &test_refresh_evidence(&foreign_epoch_context, TwoPartyDeriverRole::DeriverA),
            TwoPartyDeriverRole::DeriverA,
        )
        .is_err());

        let commitment_evidence = test_refresh_evidence(&context, TwoPartyDeriverRole::DeriverB);
        assert!(refresh_input_with_sealed_evidence(
            test_verified_refresh_command(TwoPartyDeriverRole::DeriverA, 4),
            test_refresh_evidence(&context, TwoPartyDeriverRole::DeriverA),
            identity.clone(),
            &context,
            &commitment_evidence,
            TwoPartyDeriverRole::DeriverB,
        )
        .is_err());

        let sealed_evidence =
            test_refresh_evidence_with_seeds(&context, TwoPartyDeriverRole::DeriverA, 0x59, 0x69);
        let arrival_evidence = test_refresh_evidence(&context, TwoPartyDeriverRole::DeriverA);
        assert_ne!(
            sealed_evidence.canonical_bytes(),
            arrival_evidence.canonical_bytes()
        );
        assert!(refresh_input_with_sealed_evidence(
            test_verified_refresh_command(TwoPartyDeriverRole::DeriverA, 4),
            arrival_evidence,
            identity,
            &context,
            &sealed_evidence,
            TwoPartyDeriverRole::DeriverA,
        )
        .is_err());
    }

    #[test]
    fn refresh_success_receipt_requires_exact_evidence_payload() {
        let context = test_refresh_context();
        let evidence = test_refresh_evidence(&context, TwoPartyDeriverRole::DeriverA);
        let expected_payload = evidence.canonical_bytes().to_vec();
        let key = TenantRootCommandReplayKeyV1::deriver_a(
            test_identity().digest().expect("identity digest"),
            TenantRootCustodyLineageId::from_bytes([0x44; 16]).expect("lineage"),
            TenantRootCeremonySessionIdV1::from_bytes([0x71; 16]).expect("session"),
            TenantRootCeremonyNonceV1::from_bytes([0x72; 32]).expect("nonce"),
        );
        let command_digest = TenantRootProtocolDigestV1::from_bytes([0x73; 32]).expect("digest");
        let reservation = match reserve_tenant_root_command_v1(None, key, command_digest, 20)
            .expect("reservation")
        {
            TenantRootCommandReplayDecisionV1::Execute(reservation) => reservation,
            _ => panic!("fresh reservation must be executable"),
        };
        let executed = reservation.checkpoint_executed(21).expect("executed");
        let signing_key = SigningKey::from_bytes(&[0x74; 32]);
        let signed = TenantRootCommandTerminalReceiptV1::sign_success(
            key,
            command_digest,
            expected_payload,
            22,
            "r120-refresh-command-key-v1",
            signing_key.as_bytes(),
        )
        .expect("signed receipt");
        let receipt_bytes = signed.canonical_bytes().expect("receipt bytes");
        let receipt = TenantRootCommandTerminalReceiptV1::decode_canonical_bytes(&receipt_bytes)
            .expect("decoded receipt")
            .verify_success(
                &executed,
                "r120-refresh-command-key-v1",
                signing_key.verifying_key().as_bytes(),
            )
            .expect("verified receipt");
        assert!(validate_refresh_success_receipt_payload(&evidence, &receipt).is_ok());

        let signed = TenantRootCommandTerminalReceiptV1::sign_success(
            key,
            command_digest,
            b"changed arrival bytes".to_vec(),
            22,
            "r120-refresh-command-key-v1",
            signing_key.as_bytes(),
        )
        .expect("signed changed receipt");
        let receipt_bytes = signed.canonical_bytes().expect("changed receipt bytes");
        let receipt = TenantRootCommandTerminalReceiptV1::decode_canonical_bytes(&receipt_bytes)
            .expect("decoded changed receipt")
            .verify_success(
                &executed,
                "r120-refresh-command-key-v1",
                signing_key.verifying_key().as_bytes(),
            )
            .expect("verified changed receipt");
        assert!(validate_refresh_success_receipt_payload(&evidence, &receipt).is_err());
    }

    #[test]
    fn refresh_executed_retry_retains_checkpoint_time_and_terminal_bytes() {
        let identity = test_identity().digest().expect("identity digest");
        let lineage = TenantRootCustodyLineageId::from_bytes([0x44; 16]).expect("lineage");
        let key = TenantRootCommandReplayKeyV1::deriver_a(
            identity,
            lineage,
            TenantRootCeremonySessionIdV1::from_bytes([0x71; 16]).expect("session"),
            TenantRootCeremonyNonceV1::from_bytes([0x72; 32]).expect("nonce"),
        );
        let command_digest = TenantRootProtocolDigestV1::from_bytes([0x73; 32]).expect("digest");
        let reservation = match reserve_tenant_root_command_v1(None, key, command_digest, 40)
            .expect("reservation")
        {
            TenantRootCommandReplayDecisionV1::Execute(reservation) => reservation,
            _ => panic!("fresh reservation must be executable"),
        };
        let executed = reservation.checkpoint_executed(41).expect("checkpoint");
        let stored = StoredTenantRootCommandReplayV1 {
            record: TenantRootCommandReplayRecordV1::Executed(executed),
            receipt_bytes: None,
            admission_digest: None,
            reserved_at_ms: 40,
            executed_at_ms: Some(41),
        };
        let resumed = replay_executed_from_stored(&stored).expect("resume token");
        assert_eq!(resumed.executed_at_ms(), 41);
        assert_eq!(resumed.reserved_at_ms(), 40);

        let context = test_refresh_context();
        let evidence = test_refresh_evidence(&context, TwoPartyDeriverRole::DeriverA);
        let evidence_bytes = evidence.canonical_bytes().to_vec();
        let decision = CloudflareTenantRootRefreshDecisionV1::ResumeCompletion {
            executed: CloudflareTenantRootRefreshExecutedCommandV1 {
                executed: resumed,
                evidence,
            },
        };
        let CloudflareTenantRootRefreshDecisionV1::ResumeCompletion { executed } = decision else {
            panic!("executed refresh retry must resume completion");
        };
        assert_eq!(executed.executed.executed_at_ms(), 41);
        assert_eq!(
            executed.evidence.canonical_bytes(),
            evidence_bytes.as_slice()
        );

        let signing_key = SigningKey::from_bytes(&[0x74; 32]);
        let committed_receipt = TenantRootCommandTerminalReceiptV1::sign_success(
            key,
            command_digest,
            b"exact terminal payload".to_vec(),
            50,
            "r120-refresh-command-key-v1",
            signing_key.as_bytes(),
        )
        .expect("committed receipt");
        let committed_bytes = committed_receipt
            .canonical_bytes()
            .expect("committed receipt bytes");
        let changed_receipt = TenantRootCommandTerminalReceiptV1::sign_success(
            key,
            command_digest,
            b"changed arrival payload".to_vec(),
            50,
            "r120-refresh-command-key-v1",
            signing_key.as_bytes(),
        )
        .expect("changed receipt");
        let changed_bytes = changed_receipt
            .canonical_bytes()
            .expect("changed receipt bytes");
        assert_ne!(committed_bytes, changed_bytes);
        let replay = CloudflareTenantRootRefreshDecisionV1::ReplayCompleted {
            receipt_bytes: committed_bytes.clone(),
        };
        let CloudflareTenantRootRefreshDecisionV1::ReplayCompleted { receipt_bytes } = replay
        else {
            panic!("terminal retry must replay completion");
        };
        assert_eq!(receipt_bytes, committed_bytes);
        assert_ne!(receipt_bytes, changed_bytes);
    }

    #[test]
    fn refresh_control_plane_revision_is_distinct_from_new_row_revision() {
        let context = test_refresh_context();
        let evidence = test_refresh_evidence(&context, TwoPartyDeriverRole::DeriverA);
        let command = test_verified_refresh_command(TwoPartyDeriverRole::DeriverA, 4);
        let input = refresh_input_with_sealed_evidence(
            command,
            evidence,
            test_identity(),
            &context,
            &test_refresh_evidence(&context, TwoPartyDeriverRole::DeriverA),
            TwoPartyDeriverRole::DeriverA,
        )
        .expect("refresh input");
        let scope = input.command.scope();
        let stored = CloudflareStoredTenantRootRoleShareV1 {
            record: input.record,
            revision: 1,
        };
        assert_eq!(scope.expected_control_plane_revision(), 4);
        assert_eq!(stored.revision(), 1);
        assert_ne!(
            scope.expected_control_plane_revision() as i64,
            stored.revision()
        );
    }

    #[test]
    fn record_rejects_commitment_for_the_other_role() {
        let mut record = record(CloudflareTenantRootDeriverRoleV1::DeriverA);
        let mut commitment = record.share_commitment.as_bytes().to_vec();
        commitment[..2].copy_from_slice(&2_u16.to_be_bytes());
        record.share_commitment =
            MpcPrfShareCommitmentWireV1::new(commitment).expect("B commitment");
        assert!(record.validate().is_err());
    }

    #[test]
    fn epoch_swap_requires_exact_identity_lineage_role_and_next_epoch() {
        let active_record = record(CloudflareTenantRootDeriverRoleV1::DeriverA)
            .into_active(
                current_backup_activation(
                    CloudflareTenantRootDeriverRoleV1::DeriverA,
                    0x88,
                    0x89,
                    20,
                ),
                20,
            )
            .expect("active");
        let pending_record = record_for_identity_epoch(
            test_identity(),
            CloudflareTenantRootDeriverRoleV1::DeriverA,
            0x44,
            TenantRootShareEpoch::new(2).expect("epoch 2"),
            pair_commitment(CloudflareTenantRootDeriverRoleV1::DeriverA, 18),
        );
        let active = CloudflareStoredTenantRootRoleShareV1 {
            record: active_record,
            revision: 2,
        };
        let pending = CloudflareStoredTenantRootRoleShareV1 {
            record: pending_record.clone(),
            revision: 1,
        };
        assert!(validate_epoch_swap_inputs(&active, &pending).is_ok());

        let mut wrong_identity = pending_record.clone();
        wrong_identity.identity = TenantRootIdentityV1::new(
            "org-2",
            "project-1",
            "env-1",
            "project-1:env-1",
            "root-version-1",
        )
        .expect("identity");
        assert!(validate_epoch_swap_inputs(
            &active,
            &CloudflareStoredTenantRootRoleShareV1 {
                record: wrong_identity,
                revision: 1,
            }
        )
        .is_err());

        let mut wrong_lineage = pending_record.clone();
        wrong_lineage.custody_lineage =
            TenantRootCustodyLineageId::from_bytes([0x45; 16]).expect("lineage");
        assert!(validate_epoch_swap_inputs(
            &active,
            &CloudflareStoredTenantRootRoleShareV1 {
                record: wrong_lineage,
                revision: 1,
            }
        )
        .is_err());

        let mut wrong_next_epoch = pending_record;
        wrong_next_epoch.epoch = TenantRootShareEpoch::new(3).expect("epoch 3");
        assert!(validate_epoch_swap_inputs(
            &active,
            &CloudflareStoredTenantRootRoleShareV1 {
                record: wrong_next_epoch,
                revision: 1,
            }
        )
        .is_err());

        let wrong_role = CloudflareStoredTenantRootRoleShareV1 {
            record: record(CloudflareTenantRootDeriverRoleV1::DeriverB),
            revision: 1,
        };
        assert!(validate_epoch_swap_inputs(&active, &wrong_role).is_err());
    }
}
