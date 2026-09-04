use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use router_ab_core::{
    ActiveSigningWorkerStateV1, Ed25519YaoCeremonyBindingV1,
    NormalSigningEd25519TwoPartyFrostCommitmentsV1, NormalSigningScopeV1, PublicDigest32, Role,
    RootShareEpoch, RouterAbEcdsaDerivationNormalSigningScopeV1,
};
use router_ab_core::{RouterAbProtocolError, RouterAbProtocolErrorCode, RouterAbProtocolResult};
use router_ab_ed25519_yao::Ed25519YaoSigningWorkerActivationReceiptV1;
use serde::{Deserialize, Serialize};
#[cfg(feature = "workers-rs")]
use wasm_bindgen as _;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    cloudflare_signing_worker_recipient_proof_bundle_activation_digest_v1, require_non_empty,
    require_positive_ms, CloudflareServerOutputMaterialRecordV1,
    CloudflareSigningWorkerEcdsaPoolCommandV1, CloudflareSigningWorkerEcdsaPoolMutationOutcomeV1,
    CloudflareSigningWorkerRecipientProofBundleActivationRequestV1,
};
#[cfg(feature = "workers-rs")]
mod ecdsa_presign_live_session;
#[cfg(any(feature = "workers-rs", test))]
pub(crate) mod tenant_root_creation;
#[cfg(any(feature = "workers-rs", test))]
#[cfg(feature = "workers-rs")]
mod worker_storage;
#[cfg(feature = "workers-rs")]
use ecdsa_presign_live_session::{
    handle_cloudflare_signing_worker_ecdsa_presign_session_do_fetch_v1,
    handle_cloudflare_signing_worker_linked_ecdsa_presign_session_do_fetch_v1,
    CloudflareSigningWorkerEcdsaPresignLiveSessionsV1,
    CloudflareSigningWorkerLinkedDeviceEcdsaCompletedPresignatureRecordsV1,
    CloudflareSigningWorkerLinkedDeviceEcdsaPresignLiveSessionsV1,
};
#[cfg(feature = "workers-rs")]
pub(crate) use ecdsa_presign_live_session::{
    CloudflareSigningWorkerEcdsaPresignSessionDoInitRequestV1,
    CloudflareSigningWorkerEcdsaPresignSessionDoProgressV1,
    CloudflareSigningWorkerLinkedDeviceEcdsaPresignSessionDoInitRequestV1,
    CloudflareSigningWorkerLinkedDeviceEcdsaPresignSessionDoProgressV1,
    CloudflareSigningWorkerLinkedDeviceEcdsaPresignatureDoConsumeRequestV1,
    CloudflareSigningWorkerLinkedDeviceEcdsaPresignatureDoConsumeResponseV1,
};
#[cfg(feature = "workers-rs")]
#[allow(unused_imports)]
pub(crate) use tenant_root_creation::RouterAbTenantRootCreationDurableObject;
#[cfg(feature = "workers-rs")]
#[allow(unused_imports)]
pub(crate) use tenant_root_creation::{
    execute_cloudflare_router_tenant_root_creation_commitment_call_v1,
    execute_cloudflare_router_tenant_root_creation_installation_call_v1,
    execute_cloudflare_router_tenant_root_creation_journal_call_v1,
};
#[allow(unused_imports)]
#[cfg(any(feature = "workers-rs", test))]
pub(crate) use tenant_root_creation::{
    tenant_root_creation_object_name_v1, CloudflareTenantRootCreationCommitmentOutcomeV1,
    CloudflareTenantRootCreationInstallationOutcomeV1,
    CloudflareTenantRootCreationInstallationRoleV1, CloudflareTenantRootCreationJournalOutcomeV1,
    CloudflareTenantRootCreationJournalRecordV1, CloudflareTenantRootCreationJournalRequestV1,
    CloudflareTenantRootCreationJournalResponseV1,
    CLOUDFLARE_TENANT_ROOT_CREATION_COMMITMENT_RENDEZVOUS_PATH,
    CLOUDFLARE_TENANT_ROOT_CREATION_INSTALLATION_CHECKPOINT_PATH,
    CLOUDFLARE_TENANT_ROOT_CREATION_JOURNAL_PATH,
    TENANT_ROOT_CREATION_INSTALLATION_CHECKPOINT_STORAGE_KEY_V1,
    TENANT_ROOT_CREATION_JOURNAL_STORAGE_KEY_V1,
};
#[cfg(feature = "workers-rs")]
pub(crate) use worker_storage::execute_cloudflare_durable_object_custom_json_call_v1;

/// SigningWorker ECDSA presign rendezvous with durable terminal records.
#[cfg(feature = "workers-rs")]
#[worker::durable_object(fetch)]
pub struct RouterAbSigningWorkerPresignSessionDurableObject {
    storage: worker::Storage,
    ecdsa_presign_sessions: CloudflareSigningWorkerEcdsaPresignLiveSessionsV1,
    linked_ecdsa_presign_sessions: CloudflareSigningWorkerLinkedDeviceEcdsaPresignLiveSessionsV1,
    linked_ecdsa_presignature_records:
        CloudflareSigningWorkerLinkedDeviceEcdsaCompletedPresignatureRecordsV1,
}

#[cfg(feature = "workers-rs")]
impl worker::DurableObject for RouterAbSigningWorkerPresignSessionDurableObject {
    fn new(state: worker::State, _env: worker::Env) -> Self {
        Self {
            storage: state.storage(),
            ecdsa_presign_sessions: Default::default(),
            linked_ecdsa_presign_sessions: Default::default(),
            linked_ecdsa_presignature_records: Default::default(),
        }
    }

    async fn fetch(&self, request: worker::Request) -> worker::Result<worker::Response> {
        let path = request.path();
        if path.starts_with("/router-ab/internal/signing-worker/linked-ecdsa-presign-session/")
            || path == crate::CLOUDFLARE_SIGNING_WORKER_LINKED_ECDSA_PRESIGNATURE_DO_CONSUME_PATH
        {
            return handle_cloudflare_signing_worker_linked_ecdsa_presign_session_do_fetch_v1(
                request,
                &self.linked_ecdsa_presign_sessions,
                &self.linked_ecdsa_presignature_records,
                &self.storage,
            )
            .await;
        }
        handle_cloudflare_signing_worker_ecdsa_presign_session_do_fetch_v1(
            request,
            &self.ecdsa_presign_sessions,
        )
        .await
    }
}

/// Request body for an explicit expired-state cleanup pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareExpiredStateCleanupRequestV1 {
    /// Current Worker time in Unix milliseconds.
    pub now_unix_ms: u64,
}

impl CloudflareExpiredStateCleanupRequestV1 {
    /// Creates a validated expired-state cleanup request.
    pub fn new(now_unix_ms: u64) -> RouterAbProtocolResult<Self> {
        let request = Self { now_unix_ms };
        request.validate()?;
        Ok(request)
    }

    /// Validates cleanup time.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_positive_ms("cleanup now_unix_ms", self.now_unix_ms)
    }
}

/// Summary returned after one expired-state cleanup pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareExpiredStateCleanupReportV1 {
    /// Current Worker time used for expiry comparisons.
    pub now_unix_ms: u64,
    /// Primary storage records removed.
    pub records_removed: u64,
    /// Secondary index records removed.
    pub index_records_removed: u64,
}

impl CloudflareExpiredStateCleanupReportV1 {
    /// Creates a validated cleanup report.
    pub fn new(
        now_unix_ms: u64,
        records_removed: u64,
        index_records_removed: u64,
    ) -> RouterAbProtocolResult<Self> {
        let report = Self {
            now_unix_ms,
            records_removed,
            index_records_removed,
        };
        report.validate()?;
        Ok(report)
    }

    /// Validates cleanup report fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_positive_ms("cleanup report now_unix_ms", self.now_unix_ms)
    }
}

/// Metadata returned by `root_share.startup_metadata`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareRootShareStartupMetadataV1 {
    /// Signer set id.
    pub signer_set_id: String,
    /// Signer role stored with the root share.
    pub signer_role: Role,
    /// Signer id stored with the root share.
    pub signer_id: String,
    /// Signer key epoch stored with the root share.
    pub signer_key_epoch: String,
    /// Root-share epoch.
    pub root_share_epoch: RootShareEpoch,
    /// Storage key for the sealed root-share blob.
    pub sealed_share_storage_key: String,
}

impl CloudflareRootShareStartupMetadataV1 {
    /// Creates validated root-share startup metadata.
    pub fn new(
        signer_set_id: impl Into<String>,
        signer_role: Role,
        signer_id: impl Into<String>,
        signer_key_epoch: impl Into<String>,
        root_share_epoch: RootShareEpoch,
        sealed_share_storage_key: impl Into<String>,
    ) -> RouterAbProtocolResult<Self> {
        let metadata = Self {
            signer_set_id: signer_set_id.into(),
            signer_role,
            signer_id: signer_id.into(),
            signer_key_epoch: signer_key_epoch.into(),
            root_share_epoch,
            sealed_share_storage_key: sealed_share_storage_key.into(),
        };
        metadata.validate()?;
        Ok(metadata)
    }

    /// Validates startup metadata identity and storage key.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("signer_set_id", &self.signer_set_id)?;
        require_signer_role(self.signer_role)?;
        require_non_empty("signer_id", &self.signer_id)?;
        require_non_empty("signer_key_epoch", &self.signer_key_epoch)?;
        require_non_empty("root_share_epoch", self.root_share_epoch.as_str())?;
        require_non_empty("sealed_share_storage_key", &self.sealed_share_storage_key)
    }
}

/// SigningWorker-output activation receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareSigningWorkerOutputActivationReceiptV1 {
    /// Lifecycle id activated by the SigningWorker.
    pub lifecycle_id: String,
    /// SigningWorker id that accepted activation.
    pub signing_worker_id: String,
    /// Public transcript digest.
    pub transcript_digest: PublicDigest32,
    /// Active SigningWorker state descriptor for normal signing.
    pub active_signing_worker_state: ActiveSigningWorkerStateV1,
    /// Whether the exact activation is durably stored.
    pub activated: bool,
}

impl CloudflareSigningWorkerOutputActivationReceiptV1 {
    /// Creates a validated SigningWorker-output activation receipt.
    pub fn new(
        lifecycle_id: impl Into<String>,
        signing_worker_id: impl Into<String>,
        transcript_digest: PublicDigest32,
        active_signing_worker_state: ActiveSigningWorkerStateV1,
        activated: bool,
    ) -> RouterAbProtocolResult<Self> {
        let receipt = Self {
            lifecycle_id: lifecycle_id.into(),
            signing_worker_id: signing_worker_id.into(),
            transcript_digest,
            active_signing_worker_state,
            activated,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    /// Validates SigningWorker-output activation receipt fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("lifecycle_id", &self.lifecycle_id)?;
        require_non_empty("signing_worker_id", &self.signing_worker_id)?;
        self.active_signing_worker_state.validate()?;
        if self.active_signing_worker_state.signing_worker.server_id != self.signing_worker_id
            || self
                .active_signing_worker_state
                .activation_transcript_digest
                != self.transcript_digest
        {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "SigningWorker activation receipt active state does not match receipt identity",
            ));
        }
        Ok(())
    }
}

/// Stored SigningWorker activation record inside SigningWorker-private D1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "protocol", rename_all = "snake_case")]
pub enum CloudflareSigningWorkerOutputActivationRecordV1 {
    /// Recipient-encrypted proof-bundle activation.
    RecipientProofBundle {
        /// Encrypted SigningWorker proof-bundle activation request.
        activation: CloudflareSigningWorkerRecipientProofBundleActivationRequestV1,
        /// Active SigningWorker state descriptor indexed for normal signing.
        active_signing_worker_state: ActiveSigningWorkerStateV1,
        /// SigningWorker-local opened output material.
        material: CloudflareServerOutputMaterialRecordV1,
    },
    /// P0 Half-Gates Ed25519 Yao activation.
    Ed25519Yao {
        /// Exact registration or recovery ceremony binding.
        binding: Ed25519YaoCeremonyBindingV1,
        /// Public receipt derived from the joined Yao outputs.
        receipt: Ed25519YaoSigningWorkerActivationReceiptV1,
        /// Active SigningWorker state descriptor indexed for normal signing.
        active_signing_worker_state: ActiveSigningWorkerStateV1,
        /// SigningWorker-local Yao-derived scalar material.
        material: CloudflareServerOutputMaterialRecordV1,
    },
}

impl CloudflareSigningWorkerOutputActivationRecordV1 {
    /// Creates a validated proof-bundle SigningWorker activation record.
    pub fn new(
        activation: CloudflareSigningWorkerRecipientProofBundleActivationRequestV1,
        active_signing_worker_state: ActiveSigningWorkerStateV1,
        material: CloudflareServerOutputMaterialRecordV1,
    ) -> RouterAbProtocolResult<Self> {
        let record = Self::RecipientProofBundle {
            activation,
            active_signing_worker_state,
            material,
        };
        record.validate()?;
        Ok(record)
    }

    /// Creates a validated Ed25519 Yao SigningWorker activation record.
    pub fn ed25519_yao(
        binding: Ed25519YaoCeremonyBindingV1,
        receipt: Ed25519YaoSigningWorkerActivationReceiptV1,
        active_signing_worker_state: ActiveSigningWorkerStateV1,
        material: CloudflareServerOutputMaterialRecordV1,
    ) -> RouterAbProtocolResult<Self> {
        let record = Self::Ed25519Yao {
            binding,
            receipt,
            active_signing_worker_state,
            material,
        };
        record.validate()?;
        Ok(record)
    }

    /// Returns the indexed active SigningWorker state.
    pub fn active_signing_worker_state(&self) -> &ActiveSigningWorkerStateV1 {
        match self {
            Self::RecipientProofBundle {
                active_signing_worker_state,
                ..
            }
            | Self::Ed25519Yao {
                active_signing_worker_state,
                ..
            } => active_signing_worker_state,
        }
    }

    /// Returns SigningWorker-local signing material.
    pub fn material(&self) -> &CloudflareServerOutputMaterialRecordV1 {
        match self {
            Self::RecipientProofBundle { material, .. } | Self::Ed25519Yao { material, .. } => {
                material
            }
        }
    }

    /// Compares the immutable activation input and role-local material, excluding commit time.
    pub fn matches_activation_and_material(&self, other: &Self) -> bool {
        match (self, other) {
            (
                Self::RecipientProofBundle {
                    activation: left_activation,
                    material: left_material,
                    ..
                },
                Self::RecipientProofBundle {
                    activation: right_activation,
                    material: right_material,
                    ..
                },
            ) => left_activation == right_activation && left_material == right_material,
            (
                Self::Ed25519Yao {
                    binding: left_binding,
                    receipt: left_receipt,
                    material: left_material,
                    ..
                },
                Self::Ed25519Yao {
                    binding: right_binding,
                    receipt: right_receipt,
                    material: right_material,
                    ..
                },
            ) => {
                left_binding == right_binding
                    && left_receipt == right_receipt
                    && left_material == right_material
            }
            _ => false,
        }
    }

    /// Consumes the activation record and returns SigningWorker-local material.
    pub fn into_material(self) -> CloudflareServerOutputMaterialRecordV1 {
        match self {
            Self::RecipientProofBundle { material, .. } | Self::Ed25519Yao { material, .. } => {
                material
            }
        }
    }

    /// Validates the active SigningWorker descriptor against the stored activation.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        match self {
            Self::RecipientProofBundle {
                activation,
                active_signing_worker_state,
                material,
            } => {
                activation.validate()?;
                active_signing_worker_state.validate()?;
                material.validate_for_activation_request(activation)?;
                let activation_context = &activation.activation_context;
                let lifecycle = activation_context.lifecycle();
                let selected_server = &activation_context.signer_set().selected_server;
                if active_signing_worker_state.account_id != lifecycle.account_id
                    || active_signing_worker_state.material_activation
                        != activation.material_activation
                    || active_signing_worker_state.signing_worker != *selected_server
                    || active_signing_worker_state.activation_transcript_digest
                        != activation_context.transcript_digest()
                    || active_signing_worker_state.activation_digest
                        != cloudflare_signing_worker_recipient_proof_bundle_activation_digest_v1(
                            &activation.activation,
                        )?
                    || material.transcript_digest
                        != active_signing_worker_state.activation_transcript_digest
                    || material.recipient_identity
                        != active_signing_worker_state.signing_worker.server_id
                {
                    return Err(invalid_signing_worker_activation_record(
                        "SigningWorker proof-bundle activation record does not match active state",
                    ));
                }
            }
            Self::Ed25519Yao {
                binding,
                receipt,
                active_signing_worker_state,
                material,
            } => {
                binding.validate()?;
                active_signing_worker_state.validate()?;
                material.validate()?;
                if receipt.session != binding.session_id.into_bytes()
                    || &receipt.transcript != material.transcript_digest.as_bytes()
                    || receipt.registered_public_key
                        != *active_signing_worker_state.activation_digest.as_bytes()
                    || receipt.signing_worker_verifying_share
                        != receipt.joined_signing_worker_commitment
                    || active_signing_worker_state.account_id != binding.lifecycle.account_id
                    || active_signing_worker_state.material_activation
                        != *binding.material_activation()
                    || active_signing_worker_state.signing_worker.server_id
                        != binding.lifecycle.selected_server_id
                    || active_signing_worker_state.activation_transcript_digest
                        != material.transcript_digest
                    || material.recipient_identity
                        != active_signing_worker_state.signing_worker.server_id
                {
                    return Err(invalid_signing_worker_activation_record(
                        "SigningWorker Ed25519 Yao activation record does not match active state",
                    ));
                }
            }
        }
        Ok(())
    }
}

fn invalid_signing_worker_activation_record(message: &'static str) -> RouterAbProtocolError {
    RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
        message,
    )
}

/// Account/material-activation/SigningWorker lookup for active SigningWorker state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareActiveSigningWorkerStateLookupV1 {
    /// Canonical account or wallet id.
    pub account_id: String,
    /// Exact activated MPC material identity.
    pub material_activation_id: String,
    /// Active SigningWorker id.
    pub signing_worker_id: String,
}

impl CloudflareActiveSigningWorkerStateLookupV1 {
    /// Creates a validated active SigningWorker lookup.
    pub fn new(
        account_id: impl Into<String>,
        material_activation_id: impl Into<String>,
        signing_worker_id: impl Into<String>,
    ) -> RouterAbProtocolResult<Self> {
        let lookup = Self {
            account_id: account_id.into(),
            material_activation_id: material_activation_id.into(),
            signing_worker_id: signing_worker_id.into(),
        };
        lookup.validate()?;
        Ok(lookup)
    }

    /// Creates a lookup from a normal-signing scope.
    pub fn from_normal_signing_scope(scope: &NormalSigningScopeV1) -> RouterAbProtocolResult<Self> {
        scope.validate()?;
        Self::new(
            scope.account_id.clone(),
            scope.material_activation.activation_id.clone(),
            scope.signing_worker_id.clone(),
        )
    }

    /// Creates a lookup from a Router A/B ECDSA derivation normal-signing scope.
    pub fn from_router_ab_ecdsa_derivation_normal_signing_scope(
        scope: &RouterAbEcdsaDerivationNormalSigningScopeV1,
    ) -> RouterAbProtocolResult<Self> {
        scope.validate()?;
        Self::new(
            scope.wallet_id.clone(),
            scope.material_activation_id()?,
            scope.signing_worker.server_id.clone(),
        )
    }

    /// Validates lookup identity fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("active signing worker lookup account_id", &self.account_id)?;
        require_non_empty(
            "active signing worker lookup material_activation_id",
            &self.material_activation_id,
        )?;
        require_non_empty(
            "active signing worker lookup signing_worker_id",
            &self.signing_worker_id,
        )
    }

    /// Validates returned active state matches this lookup.
    pub fn validate_active_state(
        &self,
        active_signing_worker_state: &ActiveSigningWorkerStateV1,
    ) -> RouterAbProtocolResult<()> {
        self.validate()?;
        active_signing_worker_state.validate()?;
        if active_signing_worker_state.account_id == self.account_id
            && active_signing_worker_state
                .material_activation
                .activation_id
                == self.material_activation_id
            && active_signing_worker_state.signing_worker.server_id == self.signing_worker_id
        {
            return Ok(());
        }
        Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "active SigningWorker state does not match lookup",
        ))
    }
}

/// Lookup for active SigningWorker material by active-state descriptor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareSigningWorkerOutputMaterialLookupV1 {
    /// Active SigningWorker descriptor returned by the state index.
    pub active_signing_worker_state: ActiveSigningWorkerStateV1,
}

impl CloudflareSigningWorkerOutputMaterialLookupV1 {
    /// Creates a validated material lookup.
    pub fn new(
        active_signing_worker_state: ActiveSigningWorkerStateV1,
    ) -> RouterAbProtocolResult<Self> {
        let lookup = Self {
            active_signing_worker_state,
        };
        lookup.validate()?;
        Ok(lookup)
    }

    /// Validates the material lookup descriptor.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.active_signing_worker_state.validate()
    }

    /// Validates returned material matches the active state used for lookup.
    pub fn validate_material(
        &self,
        material: &CloudflareServerOutputMaterialRecordV1,
    ) -> RouterAbProtocolResult<()> {
        self.validate()?;
        material.validate()?;
        if material.transcript_digest
            == self
                .active_signing_worker_state
                .activation_transcript_digest
            && material.recipient_identity
                == self.active_signing_worker_state.signing_worker.server_id
        {
            return Ok(());
        }
        Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "SigningWorker material does not match active SigningWorker state",
        ))
    }
}

/// Persisted standard FROST round-one state produced from a Yao-derived scalar share.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct CloudflareEd25519Round1StateV1 {
    signing_nonces: Vec<u8>,
    #[zeroize(skip)]
    pub commitments: NormalSigningEd25519TwoPartyFrostCommitmentsV1,
}

impl core::fmt::Debug for CloudflareEd25519Round1StateV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("CloudflareEd25519Round1StateV1")
            .field("signing_nonces", &"[REDACTED]")
            .field("commitments", &self.commitments)
            .finish()
    }
}

impl CloudflareEd25519Round1StateV1 {
    /// Creates persisted state from freshly generated one-use FROST nonces.
    pub fn new(
        signing_nonces: frost_ed25519::round1::SigningNonces,
        commitments: frost_ed25519::round1::SigningCommitments,
    ) -> RouterAbProtocolResult<Self> {
        let signing_nonces = signing_nonces.serialize().map_err(|error| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                format!("failed to serialize SigningWorker FROST nonces: {error}"),
            )
        })?;
        let commitments = NormalSigningEd25519TwoPartyFrostCommitmentsV1::new(
            URL_SAFE_NO_PAD.encode(commitments.hiding().serialize().map_err(|error| {
                RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::MalformedWirePayload,
                    format!("failed to serialize hiding commitment: {error}"),
                )
            })?),
            URL_SAFE_NO_PAD.encode(commitments.binding().serialize().map_err(|error| {
                RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::MalformedWirePayload,
                    format!("failed to serialize binding commitment: {error}"),
                )
            })?),
        )?;
        let state = Self {
            signing_nonces,
            commitments,
        };
        state.validate()?;
        Ok(state)
    }

    pub(crate) fn signing_nonces(
        &self,
    ) -> RouterAbProtocolResult<frost_ed25519::round1::SigningNonces> {
        frost_ed25519::round1::SigningNonces::deserialize(&self.signing_nonces).map_err(|error| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                format!("invalid persisted SigningWorker FROST nonces: {error}"),
            )
        })
    }

    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.commitments.validate()?;
        let nonces = self.signing_nonces()?;
        let expected = NormalSigningEd25519TwoPartyFrostCommitmentsV1::new(
            URL_SAFE_NO_PAD.encode(nonces.commitments().hiding().serialize().map_err(|error| {
                RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::MalformedWirePayload,
                    format!("failed to validate hiding commitment: {error}"),
                )
            })?),
            URL_SAFE_NO_PAD.encode(nonces.commitments().binding().serialize().map_err(
                |error| {
                    RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::MalformedWirePayload,
                        format!("failed to validate binding commitment: {error}"),
                    )
                },
            )?),
        )?;
        if expected == self.commitments {
            return Ok(());
        }
        Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "persisted SigningWorker FROST nonces do not match commitments",
        ))
    }
}

/// Stored SigningWorker round-1 nonce material for one normal-signing request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareSigningWorkerRound1RecordV1 {
    /// Active SigningWorker descriptor that owns this nonce material.
    pub active_signing_worker_state: ActiveSigningWorkerStateV1,
    /// SigningWorker-local nonce handle returned to the client.
    pub server_round1_handle: String,
    /// Digest binding this nonce material to the exact normal-signing context.
    pub round1_binding_digest: PublicDigest32,
    /// Router-admitted intent digest persisted during prepare.
    pub intent_digest: PublicDigest32,
    /// Router-admitted signing-payload digest persisted during prepare.
    pub signing_payload_digest: PublicDigest32,
    /// Router-admitted digest that this nonce material may sign.
    pub admitted_signing_digest: PublicDigest32,
    /// Persisted round-1 nonce material and public commitments.
    pub round1_state: CloudflareEd25519Round1StateV1,
    /// Creation timestamp in Unix milliseconds.
    pub created_at_ms: u64,
    /// Expiry timestamp in Unix milliseconds.
    pub expires_at_ms: u64,
}

impl CloudflareSigningWorkerRound1RecordV1 {
    /// Creates a validated round-1 record.
    pub fn new(
        active_signing_worker_state: ActiveSigningWorkerStateV1,
        server_round1_handle: impl Into<String>,
        round1_binding_digest: PublicDigest32,
        intent_digest: PublicDigest32,
        signing_payload_digest: PublicDigest32,
        admitted_signing_digest: PublicDigest32,
        round1_state: CloudflareEd25519Round1StateV1,
        created_at_ms: u64,
        expires_at_ms: u64,
    ) -> RouterAbProtocolResult<Self> {
        let record = Self {
            active_signing_worker_state,
            server_round1_handle: server_round1_handle.into(),
            round1_binding_digest,
            intent_digest,
            signing_payload_digest,
            admitted_signing_digest,
            round1_state,
            created_at_ms,
            expires_at_ms,
        };
        record.validate()?;
        Ok(record)
    }

    /// Validates persisted round-1 state and lifecycle timing.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.active_signing_worker_state.validate()?;
        require_non_empty("server_round1_handle", &self.server_round1_handle)?;
        self.round1_state.validate().map_err(|err| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                format!("SigningWorker round-1 state is invalid: {err}"),
            )
        })?;
        require_positive_ms("SigningWorker round-1 created_at_ms", self.created_at_ms)?;
        require_positive_ms("SigningWorker round-1 expires_at_ms", self.expires_at_ms)?;
        if self.expires_at_ms > self.created_at_ms {
            return Ok(());
        }
        Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidTimeRange,
            "SigningWorker round-1 expiry must be after creation",
        ))
    }

    /// Validates this record is live and matches the lookup used to load it.
    pub fn validate_for_lookup(
        &self,
        lookup: &CloudflareSigningWorkerRound1LookupV1,
    ) -> RouterAbProtocolResult<()> {
        self.validate()?;
        lookup.validate()?;
        if lookup.now_unix_ms >= self.expires_at_ms {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ExpiredLocalRequest,
                "SigningWorker round-1 nonce material expired",
            ));
        }
        if self.server_round1_handle == lookup.server_round1_handle
            && self.round1_binding_digest == lookup.round1_binding_digest
            && self.active_signing_worker_state == lookup.active_signing_worker_state
        {
            return Ok(());
        }
        Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "SigningWorker round-1 record does not match lookup",
        ))
    }
}

/// Lookup for one stored SigningWorker round-1 nonce record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareSigningWorkerRound1LookupV1 {
    /// Active SigningWorker descriptor that owns this nonce material.
    pub active_signing_worker_state: ActiveSigningWorkerStateV1,
    /// SigningWorker-local nonce handle returned to the client.
    pub server_round1_handle: String,
    /// Expected digest binding this nonce material to the normal-signing context.
    pub round1_binding_digest: PublicDigest32,
    /// Current time for expiry enforcement.
    pub now_unix_ms: u64,
}

impl CloudflareSigningWorkerRound1LookupV1 {
    /// Creates a validated round-1 lookup.
    pub fn new(
        active_signing_worker_state: ActiveSigningWorkerStateV1,
        server_round1_handle: impl Into<String>,
        round1_binding_digest: PublicDigest32,
        now_unix_ms: u64,
    ) -> RouterAbProtocolResult<Self> {
        let lookup = Self {
            active_signing_worker_state,
            server_round1_handle: server_round1_handle.into(),
            round1_binding_digest,
            now_unix_ms,
        };
        lookup.validate()?;
        Ok(lookup)
    }

    /// Validates lookup fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.active_signing_worker_state.validate()?;
        require_non_empty("server_round1_handle", &self.server_round1_handle)?;
        require_positive_ms("SigningWorker round-1 lookup now_unix_ms", self.now_unix_ms)
    }
}

/// Receipt for a stored SigningWorker round-1 nonce record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareSigningWorkerRound1PutReceiptV1 {
    /// Active SigningWorker descriptor that owns this nonce material.
    pub active_signing_worker_state: ActiveSigningWorkerStateV1,
    /// SigningWorker-local nonce handle returned to the client.
    pub server_round1_handle: String,
    /// Digest binding this nonce material to the exact normal-signing context.
    pub round1_binding_digest: PublicDigest32,
    /// Server public round-1 commitments.
    pub server_commitments: NormalSigningEd25519TwoPartyFrostCommitmentsV1,
    /// Whether storage changed.
    pub stored: bool,
}

impl CloudflareSigningWorkerRound1PutReceiptV1 {
    /// Creates a validated round-1 put receipt from the stored record.
    pub fn from_record(
        record: &CloudflareSigningWorkerRound1RecordV1,
        stored: bool,
    ) -> RouterAbProtocolResult<Self> {
        record.validate()?;
        let receipt = Self {
            active_signing_worker_state: record.active_signing_worker_state.clone(),
            server_round1_handle: record.server_round1_handle.clone(),
            round1_binding_digest: record.round1_binding_digest,
            server_commitments: record.round1_state.commitments.clone(),
            stored,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    /// Validates receipt fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.active_signing_worker_state.validate()?;
        require_non_empty("server_round1_handle", &self.server_round1_handle)?;
        self.server_commitments.validate()
    }

    /// Validates receipt identity against the record that created it.
    pub fn validate_for_record(
        &self,
        record: &CloudflareSigningWorkerRound1RecordV1,
    ) -> RouterAbProtocolResult<()> {
        self.validate()?;
        record.validate()?;
        if self.active_signing_worker_state == record.active_signing_worker_state
            && self.server_round1_handle == record.server_round1_handle
            && self.round1_binding_digest == record.round1_binding_digest
            && self.server_commitments == record.round1_state.commitments
        {
            return Ok(());
        }
        Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "SigningWorker round-1 put receipt does not match record",
        ))
    }
}

/// Stored SigningWorker ECDSA presignature material for one Router A/B ECDSA derivation signing request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareSigningWorkerEcdsaPresignatureRecordV1 {
    /// Active SigningWorker descriptor that owns this presignature.
    pub active_signing_worker_state: ActiveSigningWorkerStateV1,
    /// SigningWorker-local presignature id returned by the signer backend.
    pub server_presignature_id: String,
    /// Canonical Router-admitted Router A/B ECDSA derivation signing request digest.
    pub request_digest: PublicDigest32,
    /// Router-admitted 32-byte EVM digest this presignature may sign.
    pub admitted_signing_digest: PublicDigest32,
    /// Compressed secp256k1 presignature R point encoded as unpadded base64url.
    pub server_big_r33_b64u: String,
    /// SigningWorker contribution revealed after the Client commitment.
    pub signing_worker_rerandomization_contribution32_b64u: String,
    /// SigningWorker-local ECDSA presignature k share encoded as unpadded base64url.
    pub server_k_share32_b64u: String,
    /// SigningWorker-local ECDSA presignature sigma share encoded as unpadded base64url.
    pub server_sigma_share32_b64u: String,
    /// Creation timestamp in Unix milliseconds.
    pub created_at_ms: u64,
    /// Expiry timestamp in Unix milliseconds.
    pub expires_at_ms: u64,
}

impl CloudflareSigningWorkerEcdsaPresignatureRecordV1 {
    /// Creates a validated ECDSA presignature record.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        active_signing_worker_state: ActiveSigningWorkerStateV1,
        server_presignature_id: impl Into<String>,
        request_digest: PublicDigest32,
        admitted_signing_digest: PublicDigest32,
        server_big_r33_b64u: impl Into<String>,
        signing_worker_rerandomization_contribution32_b64u: impl Into<String>,
        server_k_share32_b64u: impl Into<String>,
        server_sigma_share32_b64u: impl Into<String>,
        created_at_ms: u64,
        expires_at_ms: u64,
    ) -> RouterAbProtocolResult<Self> {
        let record = Self {
            active_signing_worker_state,
            server_presignature_id: server_presignature_id.into(),
            request_digest,
            admitted_signing_digest,
            server_big_r33_b64u: server_big_r33_b64u.into(),
            signing_worker_rerandomization_contribution32_b64u:
                signing_worker_rerandomization_contribution32_b64u.into(),
            server_k_share32_b64u: server_k_share32_b64u.into(),
            server_sigma_share32_b64u: server_sigma_share32_b64u.into(),
            created_at_ms,
            expires_at_ms,
        };
        record.validate()?;
        Ok(record)
    }

    /// Validates persisted ECDSA presignature state and lifecycle timing.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.active_signing_worker_state.validate()?;
        require_non_empty("server_presignature_id", &self.server_presignature_id)?;
        validate_compressed_secp256k1_point_b64u_v1(
            "server_big_r33_b64u",
            &self.server_big_r33_b64u,
        )?;
        validate_base64url_fixed_len_v1(
            "signing_worker_rerandomization_contribution32_b64u",
            &self.signing_worker_rerandomization_contribution32_b64u,
            32,
        )?;
        validate_base64url_fixed_len_v1("server_k_share32_b64u", &self.server_k_share32_b64u, 32)?;
        validate_base64url_fixed_len_v1(
            "server_sigma_share32_b64u",
            &self.server_sigma_share32_b64u,
            32,
        )?;
        require_positive_ms(
            "SigningWorker ECDSA presignature created_at_ms",
            self.created_at_ms,
        )?;
        require_positive_ms(
            "SigningWorker ECDSA presignature expires_at_ms",
            self.expires_at_ms,
        )?;
        if self.expires_at_ms > self.created_at_ms {
            return Ok(());
        }
        Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidTimeRange,
            "SigningWorker ECDSA presignature expiry must be after creation",
        ))
    }

    /// Validates this record is live and matches one exact finalization request.
    pub fn validate_for_request(
        &self,
        active_signing_worker_state: &ActiveSigningWorkerStateV1,
        server_presignature_id: &str,
        request_digest: PublicDigest32,
        admitted_signing_digest: PublicDigest32,
        now_unix_ms: u64,
    ) -> RouterAbProtocolResult<()> {
        self.validate()?;
        active_signing_worker_state.validate()?;
        require_non_empty("server_presignature_id", server_presignature_id)?;
        require_positive_ms("SigningWorker ECDSA finalize now_unix_ms", now_unix_ms)?;
        if now_unix_ms >= self.expires_at_ms {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ExpiredLocalRequest,
                "SigningWorker ECDSA presignature expired",
            ));
        }
        let recorded_active = &self.active_signing_worker_state;
        if recorded_active.account_id != active_signing_worker_state.account_id
            || recorded_active.material_activation
                != active_signing_worker_state.material_activation
            || recorded_active.account_public_key != active_signing_worker_state.account_public_key
            || recorded_active.signing_worker != active_signing_worker_state.signing_worker
            || recorded_active.activation_transcript_digest
                != active_signing_worker_state.activation_transcript_digest
            || recorded_active.activation_digest != active_signing_worker_state.activation_digest
            || recorded_active.signing_worker_material_handle
                != active_signing_worker_state.signing_worker_material_handle
        {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "SigningWorker ECDSA presignature active material does not match finalization request",
            ));
        }
        if self.server_presignature_id != server_presignature_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "SigningWorker ECDSA presignature id does not match finalization request",
            ));
        }
        if self.request_digest != request_digest {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "SigningWorker ECDSA presignature request digest does not match finalization request",
            ));
        }
        if self.admitted_signing_digest != admitted_signing_digest {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "SigningWorker ECDSA presignature signing digest does not match finalization request",
            ));
        }
        Ok(())
    }
}

/// Stored unbound SigningWorker ECDSA presignature material for a later prepare request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareSigningWorkerEcdsaPresignaturePoolRecordV1 {
    /// Complete authenticated normal-signing scope that admitted this pair.
    pub scope: RouterAbEcdsaDerivationNormalSigningScopeV1,
    /// Active SigningWorker descriptor that owns this presignature.
    pub active_signing_worker_state: ActiveSigningWorkerStateV1,
    /// Client-selected presignature id shared by the client and SigningWorker.
    pub server_presignature_id: String,
    /// Compressed secp256k1 presignature R point encoded as unpadded base64url.
    pub server_big_r33_b64u: String,
    /// SigningWorker-local ECDSA presignature k share encoded as unpadded base64url.
    pub server_k_share32_b64u: String,
    /// SigningWorker-local ECDSA presignature sigma share encoded as unpadded base64url.
    pub server_sigma_share32_b64u: String,
    /// Creation timestamp in Unix milliseconds.
    pub created_at_ms: u64,
    /// Expiry timestamp in Unix milliseconds.
    pub expires_at_ms: u64,
}

impl CloudflareSigningWorkerEcdsaPresignaturePoolRecordV1 {
    /// Creates a validated unbound ECDSA presignature pool record.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope: RouterAbEcdsaDerivationNormalSigningScopeV1,
        active_signing_worker_state: ActiveSigningWorkerStateV1,
        server_presignature_id: impl Into<String>,
        server_big_r33_b64u: impl Into<String>,
        server_k_share32_b64u: impl Into<String>,
        server_sigma_share32_b64u: impl Into<String>,
        created_at_ms: u64,
        expires_at_ms: u64,
    ) -> RouterAbProtocolResult<Self> {
        let record = Self {
            scope,
            active_signing_worker_state,
            server_presignature_id: server_presignature_id.into(),
            server_big_r33_b64u: server_big_r33_b64u.into(),
            server_k_share32_b64u: server_k_share32_b64u.into(),
            server_sigma_share32_b64u: server_sigma_share32_b64u.into(),
            created_at_ms,
            expires_at_ms,
        };
        record.validate()?;
        Ok(record)
    }

    /// Validates persisted unbound ECDSA presignature state and lifecycle timing.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.scope.validate()?;
        self.active_signing_worker_state.validate()?;
        CloudflareActiveSigningWorkerStateLookupV1::from_router_ab_ecdsa_derivation_normal_signing_scope(
            &self.scope,
        )?
        .validate_active_state(&self.active_signing_worker_state)?;
        require_non_empty("server_presignature_id", &self.server_presignature_id)?;
        validate_compressed_secp256k1_point_b64u_v1(
            "server_big_r33_b64u",
            &self.server_big_r33_b64u,
        )?;
        validate_base64url_fixed_len_v1("server_k_share32_b64u", &self.server_k_share32_b64u, 32)?;
        validate_base64url_fixed_len_v1(
            "server_sigma_share32_b64u",
            &self.server_sigma_share32_b64u,
            32,
        )?;
        require_positive_ms(
            "SigningWorker ECDSA presignature pool created_at_ms",
            self.created_at_ms,
        )?;
        require_positive_ms(
            "SigningWorker ECDSA presignature pool expires_at_ms",
            self.expires_at_ms,
        )?;
        if self.expires_at_ms > self.created_at_ms {
            return Ok(());
        }
        Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidTimeRange,
            "SigningWorker ECDSA presignature pool expiry must be after creation",
        ))
    }

    /// Converts this unbound record into a request-bound one-use presignature record.
    pub fn to_request_bound_record(
        &self,
        request_digest: PublicDigest32,
        admitted_signing_digest: PublicDigest32,
        signing_worker_rerandomization_contribution32_b64u: impl Into<String>,
        created_at_ms: u64,
        expires_at_ms: u64,
    ) -> RouterAbProtocolResult<CloudflareSigningWorkerEcdsaPresignatureRecordV1> {
        self.validate()?;
        if created_at_ms >= self.expires_at_ms {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ExpiredLocalRequest,
                "SigningWorker ECDSA presignature pool record expired before binding",
            ));
        }
        if expires_at_ms > self.expires_at_ms {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidTimeRange,
                "SigningWorker ECDSA presignature pool record expires before prepare request",
            ));
        }
        CloudflareSigningWorkerEcdsaPresignatureRecordV1::new(
            self.active_signing_worker_state.clone(),
            self.server_presignature_id.clone(),
            request_digest,
            admitted_signing_digest,
            self.server_big_r33_b64u.clone(),
            signing_worker_rerandomization_contribution32_b64u,
            self.server_k_share32_b64u.clone(),
            self.server_sigma_share32_b64u.clone(),
            created_at_ms,
            expires_at_ms,
        )
    }
}

/// Public receipt for authenticated SigningWorker ECDSA pool admission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareSigningWorkerEcdsaPoolAdmissionReceiptV1 {
    /// Active SigningWorker descriptor that owns this presignature.
    pub active_signing_worker_state: ActiveSigningWorkerStateV1,
    /// Client-selected presignature id shared by the client and SigningWorker.
    pub server_presignature_id: String,
    /// Compressed secp256k1 presignature R point encoded as unpadded base64url.
    pub server_big_r33_b64u: String,
    /// Whether storage changed.
    pub stored: bool,
}

impl CloudflareSigningWorkerEcdsaPoolAdmissionReceiptV1 {
    /// Creates a validated ECDSA pool admission receipt from the stored record.
    pub fn from_record(
        record: &CloudflareSigningWorkerEcdsaPresignaturePoolRecordV1,
        stored: bool,
    ) -> RouterAbProtocolResult<Self> {
        record.validate()?;
        let receipt = Self {
            active_signing_worker_state: record.active_signing_worker_state.clone(),
            server_presignature_id: record.server_presignature_id.clone(),
            server_big_r33_b64u: record.server_big_r33_b64u.clone(),
            stored,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    /// Validates receipt fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.active_signing_worker_state.validate()?;
        require_non_empty("server_presignature_id", &self.server_presignature_id)?;
        validate_compressed_secp256k1_point_b64u_v1(
            "server_big_r33_b64u",
            &self.server_big_r33_b64u,
        )
    }

    /// Validates receipt identity against the record that created it.
    pub fn validate_for_record(
        &self,
        record: &CloudflareSigningWorkerEcdsaPresignaturePoolRecordV1,
    ) -> RouterAbProtocolResult<()> {
        self.validate()?;
        record.validate()?;
        if self.active_signing_worker_state == record.active_signing_worker_state
            && self.server_presignature_id == record.server_presignature_id
            && self.server_big_r33_b64u == record.server_big_r33_b64u
        {
            return Ok(());
        }
        Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "SigningWorker ECDSA pool admission receipt does not match record",
        ))
    }
}

/// One transactionally executed operation against SigningWorker-private D1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CloudflareSigningWorkerPrivateD1RequestV1 {
    OutputActivate {
        activation: CloudflareSigningWorkerRecipientProofBundleActivationRequestV1,
        material: CloudflareServerOutputMaterialRecordV1,
        activated_at_ms: u64,
    },
    ActiveStateGet {
        lookup: CloudflareActiveSigningWorkerStateLookupV1,
    },
    OutputMaterialGet {
        lookup: CloudflareSigningWorkerOutputMaterialLookupV1,
    },
    Round1Put {
        record: CloudflareSigningWorkerRound1RecordV1,
    },
    Round1Take {
        lookup: CloudflareSigningWorkerRound1LookupV1,
    },
    Round1CleanupExpired {
        cleanup: CloudflareExpiredStateCleanupRequestV1,
    },
    EcdsaPoolMutate {
        command: CloudflareSigningWorkerEcdsaPoolCommandV1,
    },
}

impl CloudflareSigningWorkerPrivateD1RequestV1 {
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        match self {
            Self::OutputActivate {
                activation,
                material,
                activated_at_ms,
            } => {
                activation.validate()?;
                material.validate()?;
                require_positive_ms("SigningWorker activation timestamp", *activated_at_ms)
            }
            Self::ActiveStateGet { lookup } => lookup.validate(),
            Self::OutputMaterialGet { lookup } => lookup.validate(),
            Self::Round1Put { record } => record.validate(),
            Self::Round1Take { lookup } => lookup.validate(),
            Self::Round1CleanupExpired { cleanup } => cleanup.validate(),
            Self::EcdsaPoolMutate { command } => command.validate(),
        }
    }

    pub fn storage_key(&self) -> String {
        match self {
            Self::OutputActivate { activation, .. } => format!(
                "signing-worker-output/{}/{}",
                activation.activation_context.lifecycle().lifecycle_id,
                digest_hex(activation.activation_context.transcript_digest())
            ),
            Self::ActiveStateGet { lookup } => format!(
                "active-signing-worker/{}/{}/{}",
                lookup.account_id, lookup.material_activation_id, lookup.signing_worker_id
            ),
            Self::OutputMaterialGet { lookup } => lookup
                .active_signing_worker_state
                .signing_worker_material_handle
                .clone(),
            Self::Round1Put { record } => format!(
                "signing-worker-round1/{}/{}/{}/{}",
                record.active_signing_worker_state.account_id,
                record
                    .active_signing_worker_state
                    .material_activation
                    .activation_id,
                record.active_signing_worker_state.signing_worker.server_id,
                record.server_round1_handle
            ),
            Self::Round1Take { lookup } => format!(
                "signing-worker-round1/{}/{}/{}/{}",
                lookup.active_signing_worker_state.account_id,
                lookup
                    .active_signing_worker_state
                    .material_activation
                    .activation_id,
                lookup.active_signing_worker_state.signing_worker.server_id,
                lookup.server_round1_handle
            ),
            Self::Round1CleanupExpired { .. } => "signing-worker-round1/".to_owned(),
            Self::EcdsaPoolMutate { command } => {
                let scope = command.scope();
                format!(
                    "signing-worker-ecdsa-pool/{}/{}/{}/{}",
                    scope.wallet_id,
                    scope
                        .material_activation_id()
                        .expect("validated ECDSA pool command has material activation id"),
                    scope.signing_worker.server_id,
                    command.server_presignature_id()
                )
            }
        }
    }

    pub fn active_state_index_key(&self) -> RouterAbProtocolResult<String> {
        self.validate()?;
        match self {
            Self::OutputActivate { activation, .. } => Ok(format!(
                "active-signing-worker/{}/{}/{}",
                activation.material_activation.material_owner,
                activation.material_activation.activation_id,
                activation.material_activation.signing_worker
            )),
            Self::ActiveStateGet { lookup } => Ok(format!(
                "active-signing-worker/{}/{}/{}",
                lookup.account_id, lookup.material_activation_id, lookup.signing_worker_id
            )),
            Self::OutputMaterialGet { lookup } => Ok(lookup
                .active_signing_worker_state
                .signing_worker_material_handle
                .clone()),
            _ => Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "active SigningWorker state index requires an output operation",
            )),
        }
    }
}

/// Result of one SigningWorker-private D1 operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CloudflareSigningWorkerPrivateD1ResponseV1 {
    OutputActivated {
        receipt: CloudflareSigningWorkerOutputActivationReceiptV1,
    },
    ActiveState {
        active_state: ActiveSigningWorkerStateV1,
    },
    OutputMaterial {
        material: CloudflareServerOutputMaterialRecordV1,
    },
    Round1Stored {
        receipt: CloudflareSigningWorkerRound1PutReceiptV1,
    },
    Round1Taken {
        record: CloudflareSigningWorkerRound1RecordV1,
    },
    Round1ExpiredCleaned {
        report: CloudflareExpiredStateCleanupReportV1,
    },
    EcdsaPoolMutated {
        outcome: CloudflareSigningWorkerEcdsaPoolMutationOutcomeV1,
    },
}

impl CloudflareSigningWorkerPrivateD1ResponseV1 {
    pub fn validate_for_request(
        &self,
        request: &CloudflareSigningWorkerPrivateD1RequestV1,
    ) -> RouterAbProtocolResult<()> {
        request.validate()?;
        let matches = matches!(
            (request, self),
            (
                CloudflareSigningWorkerPrivateD1RequestV1::OutputActivate { .. },
                Self::OutputActivated { .. }
            ) | (
                CloudflareSigningWorkerPrivateD1RequestV1::ActiveStateGet { .. },
                Self::ActiveState { .. }
            ) | (
                CloudflareSigningWorkerPrivateD1RequestV1::OutputMaterialGet { .. },
                Self::OutputMaterial { .. }
            ) | (
                CloudflareSigningWorkerPrivateD1RequestV1::Round1Put { .. },
                Self::Round1Stored { .. }
            ) | (
                CloudflareSigningWorkerPrivateD1RequestV1::Round1Take { .. },
                Self::Round1Taken { .. }
            ) | (
                CloudflareSigningWorkerPrivateD1RequestV1::Round1CleanupExpired { .. },
                Self::Round1ExpiredCleaned { .. }
            ) | (
                CloudflareSigningWorkerPrivateD1RequestV1::EcdsaPoolMutate { .. },
                Self::EcdsaPoolMutated { .. }
            )
        );
        if matches {
            return Ok(());
        }
        Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "SigningWorker private D1 returned the wrong response branch",
        ))
    }
}

#[cfg(feature = "workers-rs")]
fn durable_object_error_status(code: RouterAbProtocolErrorCode) -> u16 {
    crate::cloudflare_router_error_status(code)
}

fn validate_compressed_secp256k1_point_b64u_v1(
    field_name: &str,
    value: &str,
) -> RouterAbProtocolResult<()> {
    let bytes = validate_base64url_fixed_len_v1(field_name, value, 33)?;
    if matches!(bytes[0], 0x02 | 0x03) {
        return Ok(());
    }
    Err(RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::MalformedWirePayload,
        format!("{field_name} must use a compressed secp256k1 point prefix"),
    ))
}

fn validate_base64url_fixed_len_v1(
    field_name: &str,
    value: &str,
    expected_len: usize,
) -> RouterAbProtocolResult<Vec<u8>> {
    require_non_empty(field_name, value)?;
    let bytes = URL_SAFE_NO_PAD.decode(value).map_err(|err| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("{field_name} must be unpadded base64url: {err}"),
        )
    })?;
    if bytes.len() == expected_len {
        return Ok(bytes);
    }
    Err(RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::MalformedWirePayload,
        format!("{field_name} must decode to {expected_len} bytes"),
    ))
}

fn digest_hex(digest: PublicDigest32) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for byte in digest.as_bytes() {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn require_signer_role(role: Role) -> RouterAbProtocolResult<()> {
    match role {
        Role::SignerA | Role::SignerB => Ok(()),
        _ => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidRole,
            format!(
                "Cloudflare root-share metadata requires signer role, received {}",
                role.as_str()
            ),
        )),
    }
}
