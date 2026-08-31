use core::fmt;

use hpke_ng::Kem;
use router_ab_core::{
    reserve_tenant_root_command_v1, MpcPrfShareCommitmentWireV1, ReservedTenantRootCommandV1,
    TenantRootCeremonyNonceV1, TenantRootCeremonySessionIdV1, TenantRootCommandReplayDecisionV1,
    TenantRootCommandReplayKeyV1, TenantRootCommandReplayRecordV1, TenantRootCustodyLineageId,
    TenantRootIdentityDigestV1, TenantRootIdentityV1, TenantRootProtocolDigestV1,
    TenantRootShareEpoch,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use worker::{D1DatabaseSession, D1SessionConstraint, D1Type, Env};
use zeroize::Zeroize;

use crate::{
    encoding::{decode_base64url_bytes_v1, encode_base64url_bytes_v1},
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
const TENANT_ROOT_ROLE_D1_SCHEMA: &str = "tenant-root-role-private-d1/v1";
const TENANT_ROOT_ROLE_D1_PURPOSE: &str = "tenant-root-role-share";
const MAX_SEALED_ROLE_SHARE_BYTES: usize = 64 * 1024;
const MAX_TENANT_ROOT_COMMAND_RECEIPT_BYTES: usize = 64 * 1024;

const LOAD_EPOCH_SQL: &str = "SELECT tenant_identity_digest_hex, custody_lineage_b64u, \
    tenant_root_share_epoch, role, lifecycle, ciphertext_json, revision, created_at_ms, \
    updated_at_ms FROM tenant_root_role_shares WHERE tenant_identity_digest_hex = ?1 \
    AND custody_lineage_b64u = ?2 AND tenant_root_share_epoch = ?3 AND role = ?4";
const LOAD_ACTIVE_SQL: &str = "SELECT tenant_identity_digest_hex, custody_lineage_b64u, \
    tenant_root_share_epoch, role, lifecycle, ciphertext_json, revision, created_at_ms, \
    updated_at_ms FROM tenant_root_role_shares WHERE tenant_identity_digest_hex = ?1 \
    AND role = ?2 AND lifecycle = 'active'";
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
    command_digest_hex, status, receipt_b64u, receipt_digest_hex, reserved_at_ms, \
    terminal_at_ms FROM tenant_root_command_replays WHERE replay_key_digest_hex = ?1 \
    AND role = ?2";
const INSERT_COMMAND_RESERVATION_SQL: &str = "INSERT INTO tenant_root_command_replays \
    (replay_key_digest_hex, tenant_identity_digest_hex, custody_lineage_b64u, \
    session_id_hex, nonce_hex, role, command_digest_hex, status, reserved_at_ms) \
    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'reserved', ?8) \
    ON CONFLICT(replay_key_digest_hex) DO NOTHING";
const COMMIT_COMMAND_TERMINAL_SQL: &str = "UPDATE tenant_root_command_replays SET \
    status = ?1, receipt_b64u = ?2, receipt_digest_hex = ?3, terminal_at_ms = ?4 \
    WHERE replay_key_digest_hex = ?5 AND tenant_identity_digest_hex = ?6 \
    AND custody_lineage_b64u = ?7 AND session_id_hex = ?8 AND nonce_hex = ?9 \
    AND role = ?10 AND command_digest_hex = ?11 AND reserved_at_ms = ?12 \
    AND status = 'reserved'";

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
    installation_evidence_digest_hex: String,
    staged_at_ms: u64,
}

impl CloudflareTenantRootPendingShareV1 {
    /// Creates one pending branch bound to verified installation evidence.
    pub fn new(
        installation_evidence_digest_hex: impl Into<String>,
        staged_at_ms: u64,
    ) -> worker::Result<Self> {
        let pending = Self {
            installation_evidence_digest_hex: installation_evidence_digest_hex.into(),
            staged_at_ms,
        };
        pending.validate()?;
        Ok(pending)
    }

    fn validate(&self) -> worker::Result<()> {
        require_digest_hex(
            "tenant-root installation evidence digest",
            &self.installation_evidence_digest_hex,
        )?;
        require_timestamp("tenant-root staged timestamp", self.staged_at_ms)
    }
}

/// Exact availability evidence accepted before a role share may activate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CloudflareTenantRootAvailabilityEvidenceV1 {
    /// The owning role durably stored its independently encrypted current backup.
    CurrentRoleBackup {
        /// Digest of the role-signed backup receipt.
        role_backup_receipt_digest_hex: String,
    },
    /// The deployment explicitly accepts permanent future-derivation loss.
    AcceptedPermanentDerivationLoss {
        /// Digest of the signed deployment-policy decision.
        policy_receipt_digest_hex: String,
    },
}

impl CloudflareTenantRootAvailabilityEvidenceV1 {
    fn validate(&self) -> worker::Result<()> {
        match self {
            Self::CurrentRoleBackup {
                role_backup_receipt_digest_hex,
            } => require_digest_hex(
                "tenant-root role-backup receipt digest",
                role_backup_receipt_digest_hex,
            ),
            Self::AcceptedPermanentDerivationLoss {
                policy_receipt_digest_hex,
            } => require_digest_hex(
                "tenant-root accepted-loss policy receipt digest",
                policy_receipt_digest_hex,
            ),
        }
    }
}

/// Evidence required to activate one pending role-local share.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareTenantRootActivationV1 {
    availability: CloudflareTenantRootAvailabilityEvidenceV1,
    activation_receipt_digest_hex: String,
    activated_at_ms: u64,
}

impl CloudflareTenantRootActivationV1 {
    /// Creates one activation backed by the role's current managed backup.
    pub fn with_current_role_backup(
        role_backup_receipt_digest_hex: impl Into<String>,
        activation_receipt_digest_hex: impl Into<String>,
        activated_at_ms: u64,
    ) -> worker::Result<Self> {
        Self::new(
            CloudflareTenantRootAvailabilityEvidenceV1::CurrentRoleBackup {
                role_backup_receipt_digest_hex: role_backup_receipt_digest_hex.into(),
            },
            activation_receipt_digest_hex,
            activated_at_ms,
        )
    }

    /// Creates one activation under an explicit permanent-loss policy decision.
    pub fn with_accepted_permanent_derivation_loss(
        policy_receipt_digest_hex: impl Into<String>,
        activation_receipt_digest_hex: impl Into<String>,
        activated_at_ms: u64,
    ) -> worker::Result<Self> {
        Self::new(
            CloudflareTenantRootAvailabilityEvidenceV1::AcceptedPermanentDerivationLoss {
                policy_receipt_digest_hex: policy_receipt_digest_hex.into(),
            },
            activation_receipt_digest_hex,
            activated_at_ms,
        )
    }

    fn new(
        availability: CloudflareTenantRootAvailabilityEvidenceV1,
        activation_receipt_digest_hex: impl Into<String>,
        activated_at_ms: u64,
    ) -> worker::Result<Self> {
        let activation = Self {
            availability,
            activation_receipt_digest_hex: activation_receipt_digest_hex.into(),
            activated_at_ms,
        };
        activation.validate()?;
        Ok(activation)
    }

    fn validate(&self) -> worker::Result<()> {
        self.availability.validate()?;
        require_digest_hex(
            "tenant-root activation receipt digest",
            &self.activation_receipt_digest_hex,
        )?;
        require_timestamp("tenant-root activation timestamp", self.activated_at_ms)
    }
}

/// Active role-local tenant-root share retaining every accepted receipt digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareTenantRootRetirementV1 {
    retirement_receipt_digest_hex: String,
    retired_at_ms: u64,
}

impl CloudflareTenantRootRetirementV1 {
    /// Creates one signed forward-only retirement transition.
    pub fn new(
        retirement_receipt_digest_hex: impl Into<String>,
        retired_at_ms: u64,
    ) -> worker::Result<Self> {
        let retirement = Self {
            retirement_receipt_digest_hex: retirement_receipt_digest_hex.into(),
            retired_at_ms,
        };
        retirement.validate()?;
        Ok(retirement)
    }

    fn validate(&self) -> worker::Result<()> {
        require_digest_hex(
            "tenant-root retirement receipt digest",
            &self.retirement_receipt_digest_hex,
        )?;
        require_timestamp("tenant-root retirement timestamp", self.retired_at_ms)
    }
}

/// Retired role-local tenant-root share awaiting provider destruction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

    fn identity_digest_hex(&self) -> worker::Result<String> {
        self.identity
            .digest()
            .map(|digest| encode_hex(digest.as_bytes()))
            .map_err(|error| store_error(error.message()))
    }

    fn validate(&self) -> worker::Result<()> {
        self.identity_digest_hex()?;
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
        let commitment =
            MpcPrfShareCommitmentWireV1::new(self.share_commitment.as_bytes().to_vec())
                .map_err(|error| store_error(error.message()))?;
        let bytes = commitment.as_bytes();
        let share_id = u16::from_be_bytes([bytes[0], bytes[1]]);
        if share_id != self.role.share_id() {
            return Err(store_error(
                "tenant-root share commitment does not match the Deriver role",
            ));
        }
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

    fn seal(&self, record: &CloudflareTenantRootRoleShareRecordV1) -> worker::Result<String> {
        record.validate()?;
        self.require_role(record.role)?;
        let metadata = record_metadata(record)?;
        let aad = self.aad(&metadata)?;
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
        let aad = self.aad(&metadata)?;
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
        let record: CloudflareTenantRootRoleShareRecordV1 = serde_json::from_slice(&plaintext)
            .map_err(|error| {
                store_error(format!(
                    "tenant-root role-private record decoding failed: {error}"
                ))
            })?;
        record.validate()?;
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

    fn aad(&self, metadata: &TenantRootRoleD1MetadataV1) -> worker::Result<Vec<u8>> {
        let record_key = metadata.record_key();
        serde_json::to_vec(&TenantRootRoleD1AadV1 {
            environment: &self.environment,
            worker_role: self.role,
            tenant_identity_digest_hex: &metadata.identity_digest_hex,
            custody_lineage_b64u: &metadata.custody_lineage_b64u,
            tenant_root_share_epoch: metadata.epoch,
            record_role: metadata.role,
            lifecycle: &metadata.lifecycle,
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
    status: String,
    receipt_b64u: Option<String>,
    receipt_digest_hex: Option<String>,
    reserved_at_ms: i64,
    terminal_at_ms: Option<i64>,
}

struct StoredTenantRootCommandReplayV1 {
    record: TenantRootCommandReplayRecordV1,
    receipt_bytes: Option<Vec<u8>>,
}

/// Durable role-local decision for one exact tenant-root command retry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CloudflareTenantRootCommandReplayDecisionV1 {
    /// The caller owns the newly persisted reservation and may execute once.
    Execute {
        /// Exact reservation required to commit a terminal receipt.
        reservation: ReservedTenantRootCommandV1,
    },
    /// An identical command already owns this role-local session.
    InProgress,
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

impl TenantRootCommandTerminalKindV1 {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Failed => "failed",
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

    /// Inserts a verified pending epoch exactly once.
    pub async fn insert_pending(
        &self,
        record: CloudflareTenantRootRoleShareRecordV1,
    ) -> worker::Result<CloudflareStoredTenantRootRoleShareV1> {
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
        let metadata = record_metadata(&record)?;
        let ciphertext_json = self.cipher.seal(&record)?;
        let epoch = metadata.epoch.to_string();
        let created_at_ms = record.created_at_ms.to_string();
        let updated_at_ms = record.updated_at_ms.to_string();
        let result = self
            .session
            .prepare(INSERT_SQL)
            .bind_refs(
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
            )?
            .run()
            .await?;
        match result_changes(&result)? {
            1 => Ok(CloudflareStoredTenantRootRoleShareV1 {
                record,
                revision: 1,
            }),
            0 => {
                let existing = self
                    .load_epoch(record.identity(), record.custody_lineage(), record.epoch())
                    .await?
                    .ok_or_else(|| {
                        store_error(
                            "tenant-root pending share conflict disappeared before reconciliation",
                        )
                    })?;
                if existing.revision == 1
                    && matches!(
                        existing.record.lifecycle,
                        CloudflareTenantRootRoleShareLifecycleV1::Pending(_)
                    )
                    && existing.record == record
                {
                    Ok(existing)
                } else {
                    Err(store_error(
                        "tenant-root pending share conflicts with existing record",
                    ))
                }
            }
            _ => Err(store_error(
                "tenant-root pending share insertion returned an invalid change count",
            )),
        }
    }

    /// Loads the one current active epoch for this role and logical tenant root.
    pub async fn load_active(
        &self,
        identity: &TenantRootIdentityV1,
    ) -> worker::Result<Option<CloudflareStoredTenantRootRoleShareV1>> {
        let identity_digest_hex = identity_digest_hex(identity)?;
        let row = self
            .session
            .prepare(LOAD_ACTIVE_SQL)
            .bind_refs(
                [
                    D1Type::Text(identity_digest_hex.as_str()),
                    D1Type::Text(self.cipher.role.as_str()),
                ]
                .iter(),
            )?
            .first::<TenantRootRoleD1RowV1>(None)
            .await?;
        self.open_row(row)
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

    /// Atomically reserves one role-local tenant-root command or reconciles its exact retry.
    pub async fn reserve_command(
        &self,
        key: TenantRootCommandReplayKeyV1,
        command_digest: TenantRootProtocolDigestV1,
        reserved_at_ms: u64,
    ) -> worker::Result<CloudflareTenantRootCommandReplayDecisionV1> {
        self.require_command_role(&key)?;
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
        let replay_key_digest_hex = encode_hex(key.storage_key_digest().as_bytes());
        let identity_digest_hex = encode_hex(key.identity_digest().as_bytes());
        let custody_lineage_b64u = key.custody_lineage().to_base64url();
        let session_id_hex = encode_hex(key.session_id().as_bytes());
        let nonce_hex = encode_hex(key.nonce().as_bytes());
        let command_digest_hex = encode_hex(command_digest.as_bytes());
        let reserved_at_ms_text = timestamp_i64(reserved_at_ms)?.to_string();
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
                self.reconcile_command_retry(&stored, key, command_digest, reserved_at_ms)
            }
            _ => Err(store_error(
                "tenant-root command reservation returned an invalid change count",
            )),
        }
    }

    /// Commits one exact successful signed public receipt for a reserved command.
    pub async fn complete_command(
        &self,
        reservation: ReservedTenantRootCommandV1,
        receipt_bytes: &[u8],
        completed_at_ms: u64,
    ) -> worker::Result<CloudflareTenantRootCommandTerminalCommitV1> {
        self.commit_command_terminal(
            reservation,
            receipt_bytes,
            completed_at_ms,
            TenantRootCommandTerminalKindV1::Completed,
        )
        .await
    }

    /// Commits one exact signed public failure receipt for a reserved command.
    pub async fn fail_command(
        &self,
        reservation: ReservedTenantRootCommandV1,
        failure_receipt_bytes: &[u8],
        failed_at_ms: u64,
    ) -> worker::Result<CloudflareTenantRootCommandTerminalCommitV1> {
        self.commit_command_terminal(
            reservation,
            failure_receipt_bytes,
            failed_at_ms,
            TenantRootCommandTerminalKindV1::Failed,
        )
        .await
    }

    /// Activates epoch 1 only when this role has no active epoch for the root.
    pub async fn activate_initial_pending(
        &self,
        pending: CloudflareStoredTenantRootRoleShareV1,
        activation: CloudflareTenantRootActivationV1,
        updated_at_ms: u64,
    ) -> worker::Result<CloudflareStoredTenantRootRoleShareV1> {
        validate_pending_stored_record(&self.cipher, &pending)?;
        if pending.record.epoch != TenantRootShareEpoch::INITIAL {
            return Err(store_error(
                "tenant-root initial activation requires epoch 1",
            ));
        }
        let revision = next_revision(pending.revision)?;
        let record = pending.record.into_active(activation, updated_at_ms)?;
        let metadata = record_metadata(&record)?;
        let ciphertext_json = self.cipher.seal(&record)?;
        let epoch = metadata.epoch.to_string();
        let updated_at_ms = record.updated_at_ms.to_string();
        let expected_revision = pending.revision.to_string();
        let result = self
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
                    D1Type::Text(expected_revision.as_str()),
                ]
                .iter(),
            )?
            .run()
            .await?;
        require_one_change(
            &result,
            "tenant-root initial activation changed concurrently or an active epoch exists",
        )?;
        Ok(CloudflareStoredTenantRootRoleShareV1 { record, revision })
    }

    /// Atomically retires one active epoch and activates its exact next pending epoch.
    ///
    /// The returned pair contains the retired row first and the newly active row second.
    pub async fn swap_active_epoch(
        &self,
        active: CloudflareStoredTenantRootRoleShareV1,
        pending: CloudflareStoredTenantRootRoleShareV1,
        activation: CloudflareTenantRootActivationV1,
        retirement: CloudflareTenantRootRetirementV1,
        updated_at_ms: u64,
    ) -> worker::Result<(
        CloudflareStoredTenantRootRoleShareV1,
        CloudflareStoredTenantRootRoleShareV1,
    )> {
        validate_active_stored_record(&self.cipher, &active)?;
        validate_pending_stored_record(&self.cipher, &pending)?;
        validate_epoch_swap_inputs(&active, &pending)?;
        let retired_revision = next_revision(active.revision)?;
        let activated_revision = next_revision(pending.revision)?;
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
        let retired_ciphertext_json = self.cipher.seal(&retired_record)?;
        let activated_ciphertext_json = self.cipher.seal(&activated_record)?;
        // The WHERE clause requires both CAS rows before this single UPDATE can match either.
        let result = self
            .session
            .prepare(SWAP_ACTIVE_EPOCH_SQL)
            .bind_refs(
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
            )?
            .run()
            .await?;
        require_changes(&result, 2, "tenant-root epoch swap changed concurrently")?;
        Ok((
            CloudflareStoredTenantRootRoleShareV1 {
                record: retired_record,
                revision: retired_revision,
            },
            CloudflareStoredTenantRootRoleShareV1 {
                record: activated_record,
                revision: activated_revision,
            },
        ))
    }

    /// Removes one exact pending revision after a failed pre-activation attempt.
    pub async fn cleanup_pending(
        &self,
        pending: CloudflareStoredTenantRootRoleShareV1,
    ) -> worker::Result<()> {
        validate_pending_stored_record(&self.cipher, &pending)?;
        let metadata = record_metadata(&pending.record)?;
        let epoch = metadata.epoch.to_string();
        let revision = pending.revision.to_string();
        let result = self
            .session
            .prepare(CLEANUP_PENDING_SQL)
            .bind_refs(
                [
                    D1Type::Text(metadata.identity_digest_hex.as_str()),
                    D1Type::Text(metadata.custody_lineage_b64u.as_str()),
                    D1Type::Text(epoch.as_str()),
                    D1Type::Text(metadata.role.as_str()),
                    D1Type::Text(revision.as_str()),
                ]
                .iter(),
            )?
            .run()
            .await?;
        require_one_change(&result, "tenant-root pending cleanup changed concurrently")
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
        reservation: ReservedTenantRootCommandV1,
        receipt_bytes: &[u8],
        terminal_at_ms: u64,
        terminal_kind: TenantRootCommandTerminalKindV1,
    ) -> worker::Result<CloudflareTenantRootCommandTerminalCommitV1> {
        if receipt_bytes.is_empty() || receipt_bytes.len() > MAX_TENANT_ROOT_COMMAND_RECEIPT_BYTES {
            return Err(store_error(
                "tenant-root command receipt has an invalid byte length",
            ));
        }
        self.require_command_role(reservation.key())?;
        let receipt_digest =
            TenantRootProtocolDigestV1::from_bytes(Sha256::digest(receipt_bytes).into());
        match terminal_kind {
            TenantRootCommandTerminalKindV1::Completed => reservation
                .complete(receipt_digest, terminal_at_ms)
                .map_err(|error| store_error(error.message()))?,
            TenantRootCommandTerminalKindV1::Failed => reservation
                .fail(receipt_digest, terminal_at_ms)
                .map_err(|error| store_error(error.message()))?,
        };

        let key = reservation.key();
        let replay_key_digest_hex = encode_hex(key.storage_key_digest().as_bytes());
        let identity_digest_hex = encode_hex(key.identity_digest().as_bytes());
        let custody_lineage_b64u = key.custody_lineage().to_base64url();
        let session_id_hex = encode_hex(key.session_id().as_bytes());
        let nonce_hex = encode_hex(key.nonce().as_bytes());
        let command_digest_hex = encode_hex(reservation.command_digest().as_bytes());
        let receipt_b64u = encode_base64url_bytes_v1(receipt_bytes);
        let receipt_digest_hex = encode_hex(receipt_digest.as_bytes());
        let terminal_at_ms_text = timestamp_i64(terminal_at_ms)?.to_string();
        let reserved_at_ms_text = timestamp_i64(reservation.reserved_at_ms())?.to_string();
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
                ]
                .iter(),
            )?
            .run()
            .await?;
        match result_changes(&result)? {
            1 => Ok(CloudflareTenantRootCommandTerminalCommitV1::Committed {
                receipt_bytes: receipt_bytes.to_vec(),
            }),
            0 => {
                let stored = self.load_command_replay(key).await?.ok_or_else(|| {
                    store_error(
                        "tenant-root terminal command conflict has no durable replay record",
                    )
                })?;
                let decision = reserve_tenant_root_command_v1(
                    Some(&stored.record),
                    *key,
                    reservation.command_digest(),
                    reservation.reserved_at_ms(),
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
        let replay_key_digest_hex = encode_hex(key.storage_key_digest().as_bytes());
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
        if encode_hex(key.storage_key_digest().as_bytes()) != row.replay_key_digest_hex {
            return Err(store_error(
                "tenant-root command replay lookup digest does not match its row",
            ));
        }
        let command_digest = TenantRootProtocolDigestV1::from_bytes(decode_lower_hex_fixed::<32>(
            "tenant-root command payload digest",
            &row.command_digest_hex,
        )?);
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
        let (record, receipt_bytes) = match row.status.as_str() {
            "reserved"
                if row.receipt_b64u.is_none()
                    && row.receipt_digest_hex.is_none()
                    && row.terminal_at_ms.is_none() =>
            {
                (TenantRootCommandReplayRecordV1::Reserved(reservation), None)
            }
            "completed" | "failed" => {
                let receipt_b64u = row.receipt_b64u.ok_or_else(|| {
                    store_error("terminal tenant-root command row omitted receipt bytes")
                })?;
                let receipt_bytes =
                    decode_base64url_bytes_v1("tenant-root command receipt", &receipt_b64u)
                        .map_err(|error| store_error(error.message()))?;
                if receipt_bytes.is_empty()
                    || receipt_bytes.len() > MAX_TENANT_ROOT_COMMAND_RECEIPT_BYTES
                    || encode_base64url_bytes_v1(&receipt_bytes) != receipt_b64u
                {
                    return Err(store_error(
                        "terminal tenant-root command receipt bytes are malformed",
                    ));
                }
                let receipt_digest =
                    TenantRootProtocolDigestV1::from_bytes(decode_lower_hex_fixed::<32>(
                        "tenant-root command receipt digest",
                        &row.receipt_digest_hex.ok_or_else(|| {
                            store_error("terminal tenant-root command row omitted receipt digest")
                        })?,
                    )?);
                require_receipt_digest(&receipt_bytes, receipt_digest)?;
                let terminal_at_ms = positive_u64_from_i64(
                    "tenant-root command terminal timestamp",
                    row.terminal_at_ms.ok_or_else(|| {
                        store_error("terminal tenant-root command row omitted terminal timestamp")
                    })?,
                )?;
                let record = if row.status == "completed" {
                    reservation
                        .complete(receipt_digest, terminal_at_ms)
                        .map_err(|error| store_error(error.message()))?
                } else {
                    reservation
                        .fail(receipt_digest, terminal_at_ms)
                        .map_err(|error| store_error(error.message()))?
                };
                (record, Some(receipt_bytes))
            }
            _ => {
                return Err(store_error(
                    "tenant-root command replay row has an invalid lifecycle shape",
                ));
            }
        };
        Ok(StoredTenantRootCommandReplayV1 {
            record,
            receipt_bytes,
        })
    }

    fn reconcile_command_retry(
        &self,
        stored: &StoredTenantRootCommandReplayV1,
        key: TenantRootCommandReplayKeyV1,
        command_digest: TenantRootProtocolDigestV1,
        reserved_at_ms: u64,
    ) -> worker::Result<CloudflareTenantRootCommandReplayDecisionV1> {
        match reserve_tenant_root_command_v1(
            Some(&stored.record),
            key,
            command_digest,
            reserved_at_ms,
        )
        .map_err(|error| store_error(error.message()))?
        {
            TenantRootCommandReplayDecisionV1::Execute(_) => Err(store_error(
                "durable tenant-root command replay returned a fresh execution",
            )),
            TenantRootCommandReplayDecisionV1::InProgress => {
                Ok(CloudflareTenantRootCommandReplayDecisionV1::InProgress)
            }
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
    require_integration_failure(
        store.insert_pending(wrong_role).await,
        "role-private D1 accepted the other Deriver's share",
    )?;

    let non_initial = tenant_root_role_d1_integration_pending_record(role, 2, 2, 10)?;
    let non_initial = store.insert_pending(non_initial).await?;
    require_integration_failure(
        store
            .activate_initial_pending(
                non_initial.clone(),
                tenant_root_role_d1_integration_activation(20)?,
                20,
            )
            .await,
        "role-private D1 activated a non-initial epoch as epoch one",
    )?;
    store.cleanup_pending(non_initial).await?;

    let initial_record = tenant_root_role_d1_integration_pending_record(role, 1, 1, 10)?;
    let initial = store.insert_pending(initial_record.clone()).await?;
    let identical_retry = store.insert_pending(initial_record).await?;
    if identical_retry != initial {
        return Err(store_error(
            "role-private D1 changed an identical pending insertion retry",
        ));
    }
    let conflicting = tenant_root_role_d1_integration_pending_record(role, 1, 9, 10)?;
    require_integration_failure(
        store.insert_pending(conflicting).await,
        "role-private D1 accepted conflicting pending share bytes",
    )?;

    let active = store
        .activate_initial_pending(
            initial.clone(),
            tenant_root_role_d1_integration_activation(20)?,
            20,
        )
        .await?;
    require_integration_failure(
        store
            .activate_initial_pending(initial, tenant_root_role_d1_integration_activation(20)?, 20)
            .await,
        "role-private D1 accepted a stale initial-activation revision",
    )?;

    let next_record = tenant_root_role_d1_integration_pending_record(role, 2, 2, 30)?;
    let missing_pending = store.insert_pending(next_record.clone()).await?;
    store.cleanup_pending(missing_pending.clone()).await?;
    require_integration_failure(
        store
            .swap_active_epoch(
                active.clone(),
                missing_pending,
                tenant_root_role_d1_integration_activation(40)?,
                CloudflareTenantRootRetirementV1::new(encode_hex(&[0x45; 32]), 40)?,
                40,
            )
            .await,
        "role-private D1 retired an active epoch without its pending successor",
    )?;

    let pending = store.insert_pending(next_record).await?;
    let (retired, activated) = store
        .swap_active_epoch(
            active.clone(),
            pending.clone(),
            tenant_root_role_d1_integration_activation(40)?,
            CloudflareTenantRootRetirementV1::new(encode_hex(&[0x45; 32]), 40)?,
            40,
        )
        .await?;
    require_integration_failure(
        store
            .swap_active_epoch(
                active,
                pending,
                tenant_root_role_d1_integration_activation(40)?,
                CloudflareTenantRootRetirementV1::new(encode_hex(&[0x45; 32]), 40)?,
                40,
            )
            .await,
        "role-private D1 accepted a stale epoch-swap revision",
    )?;

    let loaded_active = store.load_active(activated.record().identity()).await?;
    if loaded_active.as_ref() != Some(&activated) {
        return Err(store_error(
            "role-private D1 active load did not return the activated epoch",
        ));
    }

    let cleanup = store
        .insert_pending(tenant_root_role_d1_integration_pending_record(
            role, 3, 3, 50,
        )?)
        .await?;
    store.cleanup_pending(cleanup.clone()).await?;
    require_integration_failure(
        store.cleanup_pending(cleanup).await,
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
    let command_key = match role {
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
    };
    let command_digest = TenantRootProtocolDigestV1::from_bytes([0x73; 32]);
    let reservation = match store
        .reserve_command(command_key, command_digest, 60)
        .await?
    {
        CloudflareTenantRootCommandReplayDecisionV1::Execute { reservation } => reservation,
        _ => {
            return Err(store_error(
                "fresh role-private command did not return an execution reservation",
            ));
        }
    };
    if !matches!(
        store
            .reserve_command(command_key, command_digest, 60)
            .await?,
        CloudflareTenantRootCommandReplayDecisionV1::InProgress
    ) {
        return Err(store_error(
            "identical reserved role-private command did not report in-progress",
        ));
    }
    let command_receipt = br#"{"kind":"r120_role_command_completed"}"#;
    let committed = store
        .complete_command(reservation, command_receipt, 70)
        .await?;
    if !matches!(
        committed,
        CloudflareTenantRootCommandTerminalCommitV1::Committed { receipt_bytes }
            if receipt_bytes == command_receipt
    ) {
        return Err(store_error(
            "role-private command did not commit its exact receipt bytes",
        ));
    }
    let terminal_retry = store
        .complete_command(reservation, command_receipt, 70)
        .await?;
    if !matches!(
        terminal_retry,
        CloudflareTenantRootCommandTerminalCommitV1::Replay { receipt_bytes }
            if receipt_bytes == command_receipt
    ) {
        return Err(store_error(
            "role-private command terminal retry did not replay exact receipt bytes",
        ));
    }
    if !matches!(
        store
            .reserve_command(command_key, command_digest, 60)
            .await?,
        CloudflareTenantRootCommandReplayDecisionV1::ReplayCompleted { receipt_bytes }
            if receipt_bytes == command_receipt
    ) {
        return Err(store_error(
            "completed role-private command did not replay exact receipt bytes",
        ));
    }
    let substituted_nonce = TenantRootCeremonyNonceV1::from_bytes([0x74; 32])
        .map_err(|error| store_error(error.message()))?;
    let substituted_key = match role {
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
    };
    require_integration_failure(
        store
            .reserve_command(substituted_key, command_digest, 60)
            .await,
        "role-private command replay accepted nonce substitution",
    )?;
    require_integration_failure(
        store
            .fail_command(reservation, br#"{"kind":"late_failure"}"#, 71)
            .await,
        "completed role-private command transitioned to failed",
    )?;

    let failed_session = TenantRootCeremonySessionIdV1::from_bytes([0x75; 16])
        .map_err(|error| store_error(error.message()))?;
    let failed_nonce = TenantRootCeremonyNonceV1::from_bytes([0x76; 32])
        .map_err(|error| store_error(error.message()))?;
    let failed_key = match role {
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
    };
    let failed_digest = TenantRootProtocolDigestV1::from_bytes([0x77; 32]);
    let failed_reservation = match store.reserve_command(failed_key, failed_digest, 80).await? {
        CloudflareTenantRootCommandReplayDecisionV1::Execute { reservation } => reservation,
        _ => {
            return Err(store_error(
                "fresh failing role-private command did not return an execution reservation",
            ));
        }
    };
    let failure_receipt = br#"{"kind":"r120_role_command_failed"}"#;
    store
        .fail_command(failed_reservation, failure_receipt, 90)
        .await?;
    if !matches!(
        store.reserve_command(failed_key, failed_digest, 80).await?,
        CloudflareTenantRootCommandReplayDecisionV1::ReplayFailed {
            failure_receipt_bytes
        } if failure_receipt_bytes == failure_receipt
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
        command_receipt_digest_hex: encode_hex(Sha256::digest(command_receipt).as_ref()),
    })
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
    let mut commitment = vec![marker; 34];
    commitment[..2].copy_from_slice(&role.share_id().to_be_bytes());
    CloudflareTenantRootRoleShareRecordV1::new(CloudflareTenantRootRoleShareRecordInputV1 {
        identity,
        custody_lineage,
        epoch,
        role,
        sealed_share: CloudflareTenantRootSealedRoleShareV1::new(&[marker; 96])?,
        share_commitment: MpcPrfShareCommitmentWireV1::new(commitment)
            .map_err(|error| store_error(error.message()))?,
        epoch_wrapping_key_ref: format!("workerd://tenant-root/{}", epoch.get()),
        lifecycle: CloudflareTenantRootRoleShareLifecycleV1::Pending(
            CloudflareTenantRootPendingShareV1::new(encode_hex(&[marker; 32]), at_ms)?,
        ),
        created_at_ms: at_ms,
        updated_at_ms: at_ms,
    })
}

#[cfg(debug_assertions)]
fn tenant_root_role_d1_integration_activation(
    at_ms: u64,
) -> worker::Result<CloudflareTenantRootActivationV1> {
    CloudflareTenantRootActivationV1::with_current_role_backup(
        encode_hex(&[0x43; 32]),
        encode_hex(&[0x44; 32]),
        at_ms,
    )
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

fn identity_digest_hex(identity: &TenantRootIdentityV1) -> worker::Result<String> {
    identity
        .digest()
        .map(|digest| encode_hex(digest.as_bytes()))
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
    stored.record.validate()?;
    cipher.require_role(stored.record.role)?;
    if !matches!(
        stored.record.lifecycle,
        CloudflareTenantRootRoleShareLifecycleV1::Active(_)
    ) {
        return Err(store_error(
            "tenant-root role-private operation requires an active record",
        ));
    }
    if stored.revision <= 0 {
        return Err(store_error(
            "tenant-root role-private revision must be positive",
        ));
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
    use super::*;

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

    fn record(role: CloudflareTenantRootDeriverRoleV1) -> CloudflareTenantRootRoleShareRecordV1 {
        let identity = TenantRootIdentityV1::new(
            "org-1",
            "project-1",
            "env-1",
            "project-1:env-1",
            "root-version-1",
        )
        .expect("identity");
        let lineage = TenantRootCustodyLineageId::from_bytes([0x44; 16]).expect("lineage");
        let mut commitment = vec![0x55; 34];
        commitment[..2].copy_from_slice(&role.share_id().to_be_bytes());
        CloudflareTenantRootRoleShareRecordV1::new(CloudflareTenantRootRoleShareRecordInputV1 {
            identity,
            custody_lineage: lineage,
            epoch: TenantRootShareEpoch::INITIAL,
            role,
            sealed_share: CloudflareTenantRootSealedRoleShareV1::new(&[0x66; 96])
                .expect("sealed share"),
            share_commitment: MpcPrfShareCommitmentWireV1::new(commitment).expect("commitment"),
            epoch_wrapping_key_ref: "kms://deriver/tenant/epoch-1".to_owned(),
            lifecycle: CloudflareTenantRootRoleShareLifecycleV1::Pending(
                CloudflareTenantRootPendingShareV1::new(encode_hex(&[0x77; 32]), 10)
                    .expect("pending"),
            ),
            created_at_ms: 10,
            updated_at_ms: 10,
        })
        .expect("record")
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
            ciphertext_json: cipher.seal(record).expect("ciphertext"),
            revision: 1,
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
    fn lifecycle_is_forward_only_and_retains_activation_evidence() {
        let pending = record(CloudflareTenantRootDeriverRoleV1::DeriverA);
        let active = pending
            .into_active(
                CloudflareTenantRootActivationV1::with_current_role_backup(
                    encode_hex(&[0x88; 32]),
                    encode_hex(&[0x89; 32]),
                    20,
                )
                .expect("activation"),
                20,
            )
            .expect("pending activates");
        assert_eq!(active.lifecycle.as_str(), "active");
        let CloudflareTenantRootRoleShareLifecycleV1::Active(active_evidence) = &active.lifecycle
        else {
            panic!("active lifecycle");
        };
        assert_eq!(
            active_evidence.pending.installation_evidence_digest_hex,
            encode_hex(&[0x77; 32])
        );
        assert_eq!(
            active_evidence.activation.availability,
            CloudflareTenantRootAvailabilityEvidenceV1::CurrentRoleBackup {
                role_backup_receipt_digest_hex: encode_hex(&[0x88; 32])
            }
        );
        assert_eq!(
            active_evidence.activation.activation_receipt_digest_hex,
            encode_hex(&[0x89; 32])
        );
        let retired = active
            .into_retired(
                CloudflareTenantRootRetirementV1::new(encode_hex(&[0x90; 32]), 30)
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
            retired_evidence
                .active
                .pending
                .installation_evidence_digest_hex,
            encode_hex(&[0x77; 32])
        );
        assert_eq!(
            retired_evidence
                .active
                .activation
                .activation_receipt_digest_hex,
            encode_hex(&[0x89; 32])
        );
        assert_eq!(
            retired_evidence.retirement.retirement_receipt_digest_hex,
            encode_hex(&[0x90; 32])
        );
        let cipher = test_cipher(CloudflareTenantRootDeriverRoleV1::DeriverA, 0x43);
        let row = row_from_record(&cipher, &retired);
        assert_eq!(cipher.open(&row).expect("retired record opens"), retired);
        assert!(retired
            .clone()
            .into_active(
                CloudflareTenantRootActivationV1::with_current_role_backup(
                    encode_hex(&[0x99; 32]),
                    encode_hex(&[0x9a; 32]),
                    40,
                )
                .expect("activation"),
                40,
            )
            .is_err());
        assert!(CloudflareTenantRootActivationV1::with_current_role_backup(
            "",
            encode_hex(&[0x9a; 32]),
            20
        )
        .is_err());
        assert!(CloudflareTenantRootActivationV1::with_current_role_backup(
            encode_hex(&[0x99; 32]),
            "",
            20
        )
        .is_err());

        let accepted_loss = record(CloudflareTenantRootDeriverRoleV1::DeriverA)
            .into_active(
                CloudflareTenantRootActivationV1::with_accepted_permanent_derivation_loss(
                    encode_hex(&[0xa1; 32]),
                    encode_hex(&[0xa2; 32]),
                    20,
                )
                .expect("accepted-loss activation"),
                20,
            )
            .expect("accepted-loss branch activates");
        let CloudflareTenantRootRoleShareLifecycleV1::Active(accepted_loss_evidence) =
            accepted_loss.lifecycle
        else {
            panic!("accepted-loss active lifecycle");
        };
        assert_eq!(
            accepted_loss_evidence.activation.availability,
            CloudflareTenantRootAvailabilityEvidenceV1::AcceptedPermanentDerivationLoss {
                policy_receipt_digest_hex: encode_hex(&[0xa1; 32])
            }
        );
    }

    #[test]
    fn lifecycle_rejects_out_of_order_evidence() {
        assert!(record(CloudflareTenantRootDeriverRoleV1::DeriverA)
            .into_active(
                CloudflareTenantRootActivationV1::with_current_role_backup(
                    encode_hex(&[0x88; 32]),
                    encode_hex(&[0x89; 32]),
                    9,
                )
                .expect("activation shape"),
                10,
            )
            .is_err());

        let active = record(CloudflareTenantRootDeriverRoleV1::DeriverA)
            .into_active(
                CloudflareTenantRootActivationV1::with_current_role_backup(
                    encode_hex(&[0x88; 32]),
                    encode_hex(&[0x89; 32]),
                    20,
                )
                .expect("activation"),
                20,
            )
            .expect("active");
        assert!(active
            .into_retired(
                CloudflareTenantRootRetirementV1::new(encode_hex(&[0x90; 32]), 19)
                    .expect("retirement shape"),
                30,
            )
            .is_err());
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
                CloudflareTenantRootActivationV1::with_current_role_backup(
                    encode_hex(&[0x88; 32]),
                    encode_hex(&[0x89; 32]),
                    20,
                )
                .expect("activation"),
                20,
            )
            .expect("active");
        let mut pending_record = record(CloudflareTenantRootDeriverRoleV1::DeriverA);
        pending_record.epoch = TenantRootShareEpoch::new(2).expect("epoch 2");
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
