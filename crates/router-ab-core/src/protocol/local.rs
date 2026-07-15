use crate::derivation::{
    MpcPrfOutputRequestV1, MpcPrfSigningRootShareWireV1, MpcPrfThresholdSignerBatchOutputV1,
    OpenedShareKind, PublicDigest32, Role, RootShareEpoch, RouterAbDerivationError,
    SignerInputPlaintextV1, SignerInputQuorumPolicyV1,
};
use rand_core::{CryptoRng, Error as RandError, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::protocol::engine::{DeriverAEngine, DeriverBEngine};
use crate::protocol::envelope::EncryptedPayloadV1;
use crate::protocol::error::{
    RouterAbProtocolError, RouterAbProtocolErrorCode, RouterAbProtocolResult,
};
use crate::protocol::identity::{ServerIdentityV1, SignerIdentityV1};
use crate::protocol::normal_signing::ActiveSigningWorkerStateV1;
use crate::protocol::output::{
    decode_recipient_proof_bundle_ciphertext_v1,
    recipient_proof_bundle_wire_message_from_ab_proof_batch_v1,
    verify_recipient_proof_bundle_ciphertext_payload_v1, RecipientOutputEncryptionAlgorithmV1,
    RecipientProofBundleCiphertextV1, RecipientProofBundleEncryptionRequestV1,
    RecipientProofBundleEncryptorV1,
};
use crate::protocol::payload::{
    decode_ab_peer_message_payload_v1,
    decode_and_validate_ecdsa_threshold_prf_proof_batch_peer_payload_v1,
    decode_recipient_proof_bundle_payload_v1, decode_router_to_signer_payload_v1,
    sign_ecdsa_threshold_prf_proof_batch_peer_payload_v1,
    validate_signer_input_plaintext_binding_v1, EcdsaThresholdPrfProofBatchPayloadV1,
    RouterToSignerPayloadV1, SigningWorkerActivationContextV1,
};
use crate::protocol::signer_input::build_mpc_prf_threshold_signer_batch_input_v1;
use crate::protocol::wire::{CanonicalWireBytesV1, WireMessageKindV1, WireMessageV1};

const LOCAL_DEV_OUTPUT_LABEL_V1: &[u8] = b"router-ab-protocol/local-dev-output/v1";
const LOCAL_DEV_MPC_PROOF_RNG_LABEL_V1: &[u8] = b"mpc-proof-rng";
const LOCAL_DEV_PROOF_BUNDLE_TAG_LEN_V1: usize = 32;
const LOCAL_DEV_ROUTER_REQUEST_DIGEST_LABEL_V1: &[u8] =
    b"router-ab-protocol/local-router-request-digest/v1";
const LOCAL_DEV_SIGNING_WORKER_ACTIVATED_AT_MS_V1: u64 = 1;
const LOCAL_DEV_ROOT_SHARE_EPOCH_V1: &str = "epoch-1";
const ROUTER_FORBIDDEN_KEYS: &[&str] = &[
    "DERIVER_A_ENVELOPE_HPKE_PRIVATE_KEY",
    "DERIVER_B_ENVELOPE_HPKE_PRIVATE_KEY",
    "SIGNING_ROOT_SHARE_A_KEK",
    "SIGNING_ROOT_SHARE_B_KEK",
    "SERVER_OUTPUT_AEAD_KEY",
    "SERVER_OUTPUT_STORAGE",
];
const DERIVER_A_REQUIRED_KEYS: &[&str] = &[
    "DERIVER_A_ENVELOPE_HPKE_PRIVATE_KEY",
    "SIGNING_ROOT_SHARE_A_KEK",
    "DERIVER_B_URL",
];
const DERIVER_A_FORBIDDEN_KEYS: &[&str] = &[
    "DERIVER_B_ENVELOPE_HPKE_PRIVATE_KEY",
    "SIGNING_ROOT_SHARE_B_KEK",
    "SERVER_OUTPUT_AEAD_KEY",
    "SERVER_OUTPUT_STORAGE",
];
const DERIVER_B_REQUIRED_KEYS: &[&str] = &[
    "DERIVER_B_ENVELOPE_HPKE_PRIVATE_KEY",
    "SIGNING_ROOT_SHARE_B_KEK",
    "DERIVER_A_URL",
];
const DERIVER_B_FORBIDDEN_KEYS: &[&str] = &[
    "DERIVER_A_ENVELOPE_HPKE_PRIVATE_KEY",
    "SIGNING_ROOT_SHARE_A_KEK",
    "SERVER_OUTPUT_AEAD_KEY",
    "SERVER_OUTPUT_STORAGE",
];
const SIGNING_WORKER_REQUIRED_KEYS: &[&str] = &["SERVER_OUTPUT_STORAGE"];
const SIGNING_WORKER_FORBIDDEN_KEYS: &[&str] = &[
    "DERIVER_A_ENVELOPE_HPKE_PRIVATE_KEY",
    "DERIVER_B_ENVELOPE_HPKE_PRIVATE_KEY",
    "SIGNING_ROOT_SHARE_A_KEK",
    "SIGNING_ROOT_SHARE_B_KEK",
];

/// Local simulation service role.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalServiceRoleV1 {
    /// Public Router endpoint.
    Router,
    /// Deriver A private endpoint.
    DeriverA,
    /// Deriver B private endpoint.
    DeriverB,
    /// Dedicated SigningWorker endpoint.
    SigningWorker,
}

impl LocalServiceRoleV1 {
    /// Returns the stable role label.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Router => "router",
            Self::DeriverA => "deriver_a",
            Self::DeriverB => "deriver_b",
            Self::SigningWorker => "signing_worker",
        }
    }
}

/// Public Router entrypoint for local boundary simulation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalRouterEndpointV1 {
    /// Public URL clients use in local simulation.
    pub public_url: String,
    /// Private Deriver A URL.
    pub deriver_a_url: String,
    /// Private Deriver B URL.
    pub deriver_b_url: String,
    /// Private SigningWorker URL.
    pub signing_worker_url: String,
}

impl LocalRouterEndpointV1 {
    /// Creates a validated local Router entrypoint.
    pub fn new(
        public_url: impl Into<String>,
        deriver_a_url: impl Into<String>,
        deriver_b_url: impl Into<String>,
        signing_worker_url: impl Into<String>,
    ) -> RouterAbProtocolResult<Self> {
        let endpoint = Self {
            public_url: public_url.into(),
            deriver_a_url: deriver_a_url.into(),
            deriver_b_url: deriver_b_url.into(),
            signing_worker_url: signing_worker_url.into(),
        };
        endpoint.validate()?;
        Ok(endpoint)
    }

    /// Validates required endpoint fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("public_url", &self.public_url)?;
        require_non_empty("deriver_a_url", &self.deriver_a_url)?;
        require_non_empty("deriver_b_url", &self.deriver_b_url)?;
        require_non_empty("signing_worker_url", &self.signing_worker_url)
    }
}

/// Deriver A entrypoint for local boundary simulation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalDeriverAEndpointV1 {
    /// Private Deriver A URL.
    pub private_url: String,
    /// Private Deriver B URL used for A/B coordination.
    pub deriver_b_url: String,
}

impl LocalDeriverAEndpointV1 {
    /// Creates a validated local Deriver A entrypoint.
    pub fn new(
        private_url: impl Into<String>,
        deriver_b_url: impl Into<String>,
    ) -> RouterAbProtocolResult<Self> {
        let endpoint = Self {
            private_url: private_url.into(),
            deriver_b_url: deriver_b_url.into(),
        };
        endpoint.validate()?;
        Ok(endpoint)
    }

    /// Validates required endpoint fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("private_url", &self.private_url)?;
        require_non_empty("deriver_b_url", &self.deriver_b_url)
    }
}

/// Deriver B entrypoint for local boundary simulation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalDeriverBEndpointV1 {
    /// Private Deriver B URL.
    pub private_url: String,
    /// Private Deriver A URL used for A/B coordination.
    pub deriver_a_url: String,
}

impl LocalDeriverBEndpointV1 {
    /// Creates a validated local Deriver B entrypoint.
    pub fn new(
        private_url: impl Into<String>,
        deriver_a_url: impl Into<String>,
    ) -> RouterAbProtocolResult<Self> {
        let endpoint = Self {
            private_url: private_url.into(),
            deriver_a_url: deriver_a_url.into(),
        };
        endpoint.validate()?;
        Ok(endpoint)
    }

    /// Validates required endpoint fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("private_url", &self.private_url)?;
        require_non_empty("deriver_a_url", &self.deriver_a_url)
    }
}

/// SigningWorker entrypoint for local boundary simulation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalSigningWorkerEndpointV1 {
    /// Private SigningWorker URL.
    pub private_url: String,
    /// Local storage binding name for server output activation.
    pub server_output_storage: String,
}

impl LocalSigningWorkerEndpointV1 {
    /// Creates a validated local SigningWorker entrypoint.
    pub fn new(
        private_url: impl Into<String>,
        server_output_storage: impl Into<String>,
    ) -> RouterAbProtocolResult<Self> {
        let endpoint = Self {
            private_url: private_url.into(),
            server_output_storage: server_output_storage.into(),
        };
        endpoint.validate()?;
        Ok(endpoint)
    }

    /// Validates required endpoint fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("private_url", &self.private_url)?;
        require_non_empty("server_output_storage", &self.server_output_storage)
    }
}

/// Role-specific local endpoint descriptor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "role", rename_all = "snake_case")]
pub enum LocalServiceEndpointV1 {
    /// Public Router endpoint.
    Router {
        /// Router endpoint data.
        endpoint: LocalRouterEndpointV1,
    },
    /// Deriver A endpoint.
    DeriverA {
        /// Deriver A endpoint data.
        endpoint: LocalDeriverAEndpointV1,
    },
    /// Deriver B endpoint.
    DeriverB {
        /// Deriver B endpoint data.
        endpoint: LocalDeriverBEndpointV1,
    },
    /// SigningWorker endpoint.
    SigningWorker {
        /// SigningWorker endpoint data.
        endpoint: LocalSigningWorkerEndpointV1,
    },
}

impl LocalServiceEndpointV1 {
    /// Creates a local Router service descriptor.
    pub fn router(endpoint: LocalRouterEndpointV1) -> RouterAbProtocolResult<Self> {
        endpoint.validate()?;
        Ok(Self::Router { endpoint })
    }

    /// Creates a local Deriver A service descriptor.
    pub fn deriver_a(endpoint: LocalDeriverAEndpointV1) -> RouterAbProtocolResult<Self> {
        endpoint.validate()?;
        Ok(Self::DeriverA { endpoint })
    }

    /// Creates a local Deriver B service descriptor.
    pub fn deriver_b(endpoint: LocalDeriverBEndpointV1) -> RouterAbProtocolResult<Self> {
        endpoint.validate()?;
        Ok(Self::DeriverB { endpoint })
    }

    /// Creates a local SigningWorker service descriptor.
    pub fn signing_worker(endpoint: LocalSigningWorkerEndpointV1) -> RouterAbProtocolResult<Self> {
        endpoint.validate()?;
        Ok(Self::SigningWorker { endpoint })
    }

    /// Returns the service role.
    pub fn role(&self) -> LocalServiceRoleV1 {
        match self {
            Self::Router { .. } => LocalServiceRoleV1::Router,
            Self::DeriverA { .. } => LocalServiceRoleV1::DeriverA,
            Self::DeriverB { .. } => LocalServiceRoleV1::DeriverB,
            Self::SigningWorker { .. } => LocalServiceRoleV1::SigningWorker,
        }
    }
}

/// Validates local binding names for a service role.
pub fn validate_local_env_keys_v1(
    role: LocalServiceRoleV1,
    keys: &[&str],
) -> RouterAbProtocolResult<()> {
    match role {
        LocalServiceRoleV1::Router => {
            reject_forbidden_keys(role, keys, ROUTER_FORBIDDEN_KEYS)?;
        }
        LocalServiceRoleV1::DeriverA => {
            require_keys(role, keys, DERIVER_A_REQUIRED_KEYS)?;
            reject_forbidden_keys(role, keys, DERIVER_A_FORBIDDEN_KEYS)?;
        }
        LocalServiceRoleV1::DeriverB => {
            require_keys(role, keys, DERIVER_B_REQUIRED_KEYS)?;
            reject_forbidden_keys(role, keys, DERIVER_B_FORBIDDEN_KEYS)?;
        }
        LocalServiceRoleV1::SigningWorker => {
            require_keys(role, keys, SIGNING_WORKER_REQUIRED_KEYS)?;
            reject_forbidden_keys(role, keys, SIGNING_WORKER_FORBIDDEN_KEYS)?;
        }
    }
    Ok(())
}

/// Transport-neutral local env snapshot containing binding names only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalEnvSnapshotV1 {
    /// Service role the bindings belong to.
    pub role: LocalServiceRoleV1,
    /// Binding names visible to the service.
    pub binding_keys: Vec<String>,
}

impl LocalEnvSnapshotV1 {
    /// Creates a validated local env snapshot.
    pub fn new(
        role: LocalServiceRoleV1,
        binding_keys: Vec<String>,
    ) -> RouterAbProtocolResult<Self> {
        let snapshot = Self { role, binding_keys };
        snapshot.validate()?;
        Ok(snapshot)
    }

    /// Validates binding names and role-specific binding policy.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        for key in &self.binding_keys {
            require_non_empty("binding_key", key)?;
        }
        let keys = self
            .binding_keys
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        validate_local_env_keys_v1(self.role, &keys)
    }
}

/// Local signing-root metadata row used to seed dev persistence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalSigningRootMetadataV1 {
    /// Signer set that owns this root-share epoch.
    pub signer_set_id: String,
    /// Logical signing-root version.
    pub signing_root_version: String,
    /// Root-share epoch.
    pub root_share_epoch: RootShareEpoch,
    /// Account or wallet id bound to this local root.
    pub account_id: String,
}

impl LocalSigningRootMetadataV1 {
    /// Creates validated local signing-root metadata.
    pub fn new(
        signer_set_id: impl Into<String>,
        signing_root_version: impl Into<String>,
        root_share_epoch: RootShareEpoch,
        account_id: impl Into<String>,
    ) -> RouterAbProtocolResult<Self> {
        let metadata = Self {
            signer_set_id: signer_set_id.into(),
            signing_root_version: signing_root_version.into(),
            root_share_epoch,
            account_id: account_id.into(),
        };
        metadata.validate()?;
        Ok(metadata)
    }

    /// Validates local signing-root metadata fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("signer_set_id", &self.signer_set_id)?;
        require_non_empty("signing_root_version", &self.signing_root_version)?;
        require_non_empty("root_share_epoch", self.root_share_epoch.as_str())?;
        require_non_empty("account_id", &self.account_id)
    }
}

/// Role-specific sealed signing-root-share row used to seed dev persistence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalSealedRootShareRecordV1 {
    /// Signer set that owns this sealed share.
    pub signer_set_id: String,
    /// Signer identity for the sealed share.
    pub signer: SignerIdentityV1,
    /// Root-share epoch.
    pub root_share_epoch: RootShareEpoch,
    /// Local storage key for the sealed share blob.
    pub sealed_share_storage_key: String,
    /// Public commitment digest to the sealed share blob.
    pub sealed_share_commitment: PublicDigest32,
    /// Sealed share blob length.
    pub sealed_share_len: u32,
}

impl LocalSealedRootShareRecordV1 {
    /// Creates a validated role-specific sealed-share record.
    pub fn new(
        signer_set_id: impl Into<String>,
        signer: SignerIdentityV1,
        root_share_epoch: RootShareEpoch,
        sealed_share_storage_key: impl Into<String>,
        sealed_share_commitment: PublicDigest32,
        sealed_share_len: u32,
    ) -> RouterAbProtocolResult<Self> {
        let record = Self {
            signer_set_id: signer_set_id.into(),
            signer,
            root_share_epoch,
            sealed_share_storage_key: sealed_share_storage_key.into(),
            sealed_share_commitment,
            sealed_share_len,
        };
        record.validate()?;
        Ok(record)
    }

    /// Validates sealed-share record fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("signer_set_id", &self.signer_set_id)?;
        self.signer.validate()?;
        require_non_empty("root_share_epoch", self.root_share_epoch.as_str())?;
        require_non_empty("sealed_share_storage_key", &self.sealed_share_storage_key)?;
        if self.sealed_share_len == 0 {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "sealed_share_len must be greater than zero",
            ));
        }
        Ok(())
    }
}

/// Transport-neutral local persistence seed for signing-root metadata and shares.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalPersistenceSeedV1 {
    /// Root metadata row.
    pub root_metadata: LocalSigningRootMetadataV1,
    /// Signer A sealed-share row.
    pub deriver_a_share: LocalSealedRootShareRecordV1,
    /// Signer B sealed-share row.
    pub deriver_b_share: LocalSealedRootShareRecordV1,
}

impl LocalPersistenceSeedV1 {
    /// Creates a validated local persistence seed.
    pub fn new(
        root_metadata: LocalSigningRootMetadataV1,
        deriver_a_share: LocalSealedRootShareRecordV1,
        deriver_b_share: LocalSealedRootShareRecordV1,
    ) -> RouterAbProtocolResult<Self> {
        let seed = Self {
            root_metadata,
            deriver_a_share,
            deriver_b_share,
        };
        seed.validate()?;
        Ok(seed)
    }

    /// Validates that sealed-share rows match root metadata and v1 A/B roles.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.root_metadata.validate()?;
        self.deriver_a_share.validate()?;
        self.deriver_b_share.validate()?;
        require_seed_share(&self.root_metadata, &self.deriver_a_share, Role::SignerA)?;
        require_seed_share(&self.root_metadata, &self.deriver_b_share, Role::SignerB)?;
        if self.deriver_a_share.signer.signer_id == self.deriver_b_share.signer.signer_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidSignerIdentity,
                "local persistence seed requires distinct signer ids",
            ));
        }
        Ok(())
    }
}

/// Bound value for a local persistence SQL statement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum LocalPersistenceSqlValueV1 {
    /// Text bind value.
    Text(String),
    /// Unsigned 32-bit integer bind value.
    U32(u32),
}

impl LocalPersistenceSqlValueV1 {
    /// Creates a text bind value.
    pub fn text(value: impl Into<String>) -> Self {
        Self::Text(value.into())
    }

    /// Creates an unsigned 32-bit integer bind value.
    pub fn u32(value: u32) -> Self {
        Self::U32(value)
    }
}

/// Parameterized SQL statement for local persistence seeding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalPersistenceSqlStatementV1 {
    /// Parameterized SQL text.
    pub sql: String,
    /// Bound values in placeholder order.
    pub values: Vec<LocalPersistenceSqlValueV1>,
}

impl LocalPersistenceSqlStatementV1 {
    /// Creates a validated SQL statement plan.
    pub fn new(
        sql: impl Into<String>,
        values: Vec<LocalPersistenceSqlValueV1>,
    ) -> RouterAbProtocolResult<Self> {
        let statement = Self {
            sql: sql.into(),
            values,
        };
        statement.validate()?;
        Ok(statement)
    }

    /// Validates statement SQL and bind values.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("sql", &self.sql)?;
        if self.values.is_empty() {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "local persistence SQL statement requires bind values",
            ));
        }
        Ok(())
    }
}

/// Parameterized SQL statements for local persistence seeding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalPersistenceSqlSeedPlanV1 {
    /// Ordered SQL statements to execute.
    pub statements: Vec<LocalPersistenceSqlStatementV1>,
}

impl LocalPersistenceSqlSeedPlanV1 {
    /// Creates a validated SQL seed plan.
    pub fn new(statements: Vec<LocalPersistenceSqlStatementV1>) -> RouterAbProtocolResult<Self> {
        let plan = Self { statements };
        plan.validate()?;
        Ok(plan)
    }

    /// Validates seed-plan statements.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        if self.statements.len() != 3 {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "local persistence SQL seed plan requires root, signer A share, and signer B share statements",
            ));
        }
        for statement in &self.statements {
            statement.validate()?;
        }
        Ok(())
    }
}

/// Receipt for local SQL seed-plan execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalPersistenceSqlExecutionReceiptV1 {
    /// Number of statements executed.
    pub executed_statement_count: u32,
}

impl LocalPersistenceSqlExecutionReceiptV1 {
    /// Creates a validated SQL seed execution receipt.
    pub fn new(executed_statement_count: u32) -> RouterAbProtocolResult<Self> {
        if executed_statement_count == 0 {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "local persistence SQL execution receipt requires executed statements",
            ));
        }
        Ok(Self {
            executed_statement_count,
        })
    }
}

/// Adapter hook for executing local SQL seed statements.
pub trait LocalPersistenceSqlSeedExecutorV1 {
    /// Executes one validated seed statement with its bound values.
    fn execute_local_persistence_sql_statement_v1(
        &mut self,
        statement_index: u32,
        statement: &LocalPersistenceSqlStatementV1,
    ) -> RouterAbProtocolResult<()>;
}

/// Builds SQLite SQL for local signing-root metadata and sealed-share seeds.
pub fn local_persistence_seed_sql_plan_v1(
    seed: &LocalPersistenceSeedV1,
) -> RouterAbProtocolResult<LocalPersistenceSqlSeedPlanV1> {
    seed.validate()?;
    LocalPersistenceSqlSeedPlanV1::new(vec![
        local_signing_root_metadata_sql_statement(&seed.root_metadata)?,
        local_sealed_root_share_sql_statement(&seed.deriver_a_share)?,
        local_sealed_root_share_sql_statement(&seed.deriver_b_share)?,
    ])
}

/// Executes a validated local persistence SQL seed plan through an adapter.
pub fn execute_local_persistence_sql_seed_plan_v1(
    plan: &LocalPersistenceSqlSeedPlanV1,
    executor: &mut impl LocalPersistenceSqlSeedExecutorV1,
) -> RouterAbProtocolResult<LocalPersistenceSqlExecutionReceiptV1> {
    plan.validate()?;
    for (index, statement) in plan.statements.iter().enumerate() {
        statement.validate()?;
        executor.execute_local_persistence_sql_statement_v1(index as u32, statement)?;
    }
    LocalPersistenceSqlExecutionReceiptV1::new(plan.statements.len() as u32)
}

/// Local Router handler over checked transport envelopes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalRouterServiceV1 {
    /// Local Router endpoint descriptor.
    pub endpoint: LocalRouterEndpointV1,
}

impl LocalRouterServiceV1 {
    /// Creates a local Router handler.
    pub fn new(endpoint: LocalRouterEndpointV1) -> RouterAbProtocolResult<Self> {
        endpoint.validate()?;
        Ok(Self { endpoint })
    }

    /// Wraps Router-to-signer wire messages in checked local transport routes.
    pub fn dispatch_signer_requests(
        &self,
        deriver_a_request: WireMessageV1,
        deriver_b_request: WireMessageV1,
    ) -> RouterAbProtocolResult<LocalRouterDispatchV1> {
        let to_deriver_a = LocalTransportEnvelopeV1::new(
            LocalTransportRouteV1::RouterToSignerA,
            deriver_a_request,
        )?;
        let to_deriver_b = LocalTransportEnvelopeV1::new(
            LocalTransportRouteV1::RouterToSignerB,
            deriver_b_request,
        )?;
        require_matching_transcripts(&to_deriver_a.message, &to_deriver_b.message)?;
        Ok(LocalRouterDispatchV1 {
            to_deriver_a,
            to_deriver_b,
        })
    }
}

/// Router-dispatched local signer requests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalRouterDispatchV1 {
    /// Request routed to Signer A.
    pub to_deriver_a: LocalTransportEnvelopeV1,
    /// Request routed to Signer B.
    pub to_deriver_b: LocalTransportEnvelopeV1,
}

/// Local signer response carrying opaque client and server proof bundles.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalSignerRecipientProofBundleResponseV1 {
    /// Producing signer role.
    pub signer_role: Role,
    /// Opaque client-delivery proof bundle for `x_client_base`.
    pub client_bundle: WireMessageV1,
    /// Opaque server-delivery proof bundle for `x_server_base`.
    pub server_bundle: WireMessageV1,
}

impl LocalSignerRecipientProofBundleResponseV1 {
    /// Creates a validated local signer proof-bundle response.
    pub fn new(
        signer_role: Role,
        client_bundle: WireMessageV1,
        server_bundle: WireMessageV1,
    ) -> RouterAbProtocolResult<Self> {
        let response = Self {
            signer_role,
            client_bundle,
            server_bundle,
        };
        response.validate()?;
        Ok(response)
    }

    /// Validates role, recipient class, and transcript agreement.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_signer_role_value(self.signer_role)?;
        let client = decode_local_recipient_proof_bundle_wire_v1(
            "client_bundle",
            &self.client_bundle,
            self.signer_role,
            Role::Client,
            OpenedShareKind::XClientBase,
        )?;
        let server = decode_local_recipient_proof_bundle_wire_v1(
            "server_bundle",
            &self.server_bundle,
            self.signer_role,
            Role::Server,
            OpenedShareKind::XServerBase,
        )?;
        if client.signer != server.signer {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidSignerIdentity,
                "local proof-bundle response signer identities must match",
            ));
        }
        require_matching_transcripts(&self.client_bundle, &self.server_bundle)
    }

    /// Validates this signer response against the Router payload that produced it.
    pub fn validate_for_router_payload(
        &self,
        router_payload: &RouterToSignerPayloadV1,
    ) -> RouterAbProtocolResult<()> {
        self.validate()?;
        router_payload.validate()?;
        let client = decode_local_recipient_proof_bundle_wire_v1(
            "client_bundle",
            &self.client_bundle,
            self.signer_role,
            Role::Client,
            OpenedShareKind::XClientBase,
        )?;
        let server = decode_local_recipient_proof_bundle_wire_v1(
            "server_bundle",
            &self.server_bundle,
            self.signer_role,
            Role::Server,
            OpenedShareKind::XServerBase,
        )?;
        let expected_signer =
            expected_local_signer_identity_for_role_v1(router_payload, self.signer_role)?;
        validate_local_recipient_proof_bundle_envelope_for_router_payload_v1(
            "client_bundle",
            &client,
            router_payload,
            expected_signer,
        )?;
        validate_local_recipient_proof_bundle_envelope_for_router_payload_v1(
            "server_bundle",
            &server,
            router_payload,
            expected_signer,
        )
    }
}

/// Local Router response carrying only opaque client proof bundles.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalRouterRecipientProofBundleResponseV1 {
    /// Signer A opaque client proof bundle.
    pub deriver_a_client_bundle: WireMessageV1,
    /// Signer B opaque client proof bundle.
    pub deriver_b_client_bundle: WireMessageV1,
}

impl LocalRouterRecipientProofBundleResponseV1 {
    /// Creates a validated local Router proof-bundle response.
    pub fn new(
        deriver_a_client_bundle: WireMessageV1,
        deriver_b_client_bundle: WireMessageV1,
    ) -> RouterAbProtocolResult<Self> {
        let response = Self {
            deriver_a_client_bundle,
            deriver_b_client_bundle,
        };
        response.validate()?;
        Ok(response)
    }

    /// Validates opaque client bundle shape and transcript agreement.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        let deriver_a = decode_local_recipient_proof_bundle_wire_v1(
            "deriver_a_client_bundle",
            &self.deriver_a_client_bundle,
            Role::SignerA,
            Role::Client,
            OpenedShareKind::XClientBase,
        )?;
        let deriver_b = decode_local_recipient_proof_bundle_wire_v1(
            "deriver_b_client_bundle",
            &self.deriver_b_client_bundle,
            Role::SignerB,
            Role::Client,
            OpenedShareKind::XClientBase,
        )?;
        if deriver_a.transcript_digest != deriver_b.transcript_digest {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "local Router proof-bundle response transcripts must match",
            ));
        }
        Ok(())
    }

    /// Validates opaque client bundles against the Router payload that produced them.
    pub fn validate_for_router_payload(
        &self,
        router_payload: &RouterToSignerPayloadV1,
    ) -> RouterAbProtocolResult<()> {
        self.validate()?;
        router_payload.validate()?;
        let deriver_a = decode_local_recipient_proof_bundle_wire_v1(
            "deriver_a_client_bundle",
            &self.deriver_a_client_bundle,
            Role::SignerA,
            Role::Client,
            OpenedShareKind::XClientBase,
        )?;
        let deriver_b = decode_local_recipient_proof_bundle_wire_v1(
            "deriver_b_client_bundle",
            &self.deriver_b_client_bundle,
            Role::SignerB,
            Role::Client,
            OpenedShareKind::XClientBase,
        )?;
        validate_local_recipient_proof_bundle_envelope_for_router_payload_v1(
            "deriver_a_client_bundle",
            &deriver_a,
            router_payload,
            &router_payload.signer_set().signer_a,
        )?;
        validate_local_recipient_proof_bundle_envelope_for_router_payload_v1(
            "deriver_b_client_bundle",
            &deriver_b,
            router_payload,
            &router_payload.signer_set().signer_b,
        )
    }
}

/// Local SigningWorker activation package carrying opaque `x_server_base` proof bundles.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalSigningWorkerRecipientProofBundleActivationV1 {
    /// Signer A opaque SigningWorker proof bundle.
    pub deriver_a_signing_worker_bundle: WireMessageV1,
    /// Signer B opaque SigningWorker proof bundle.
    pub deriver_b_signing_worker_bundle: WireMessageV1,
}

impl LocalSigningWorkerRecipientProofBundleActivationV1 {
    /// Creates a validated local SigningWorker proof-bundle activation.
    pub fn new(
        deriver_a_signing_worker_bundle: WireMessageV1,
        deriver_b_signing_worker_bundle: WireMessageV1,
    ) -> RouterAbProtocolResult<Self> {
        let activation = Self {
            deriver_a_signing_worker_bundle,
            deriver_b_signing_worker_bundle,
        };
        activation.validate()?;
        Ok(activation)
    }

    /// Validates opaque SigningWorker bundle shape and transcript agreement.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        let deriver_a = decode_local_recipient_proof_bundle_wire_v1(
            "deriver_a_signing_worker_bundle",
            &self.deriver_a_signing_worker_bundle,
            Role::SignerA,
            Role::Server,
            OpenedShareKind::XServerBase,
        )?;
        let deriver_b = decode_local_recipient_proof_bundle_wire_v1(
            "deriver_b_signing_worker_bundle",
            &self.deriver_b_signing_worker_bundle,
            Role::SignerB,
            Role::Server,
            OpenedShareKind::XServerBase,
        )?;
        if deriver_a.transcript_digest != deriver_b.transcript_digest {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "local SigningWorker proof-bundle activation transcripts must match",
            ));
        }
        Ok(())
    }

    /// Validates opaque SigningWorker bundles against public activation context.
    pub fn validate_for_activation_context(
        &self,
        activation_context: &SigningWorkerActivationContextV1,
    ) -> RouterAbProtocolResult<()> {
        self.validate()?;
        activation_context.validate()?;
        let deriver_a = decode_local_recipient_proof_bundle_wire_v1(
            "deriver_a_signing_worker_bundle",
            &self.deriver_a_signing_worker_bundle,
            Role::SignerA,
            Role::Server,
            OpenedShareKind::XServerBase,
        )?;
        let deriver_b = decode_local_recipient_proof_bundle_wire_v1(
            "deriver_b_signing_worker_bundle",
            &self.deriver_b_signing_worker_bundle,
            Role::SignerB,
            Role::Server,
            OpenedShareKind::XServerBase,
        )?;
        validate_local_recipient_proof_bundle_envelope_for_activation_context_v1(
            "deriver_a_signing_worker_bundle",
            &deriver_a,
            activation_context,
            &activation_context.signer_set().signer_a,
        )?;
        validate_local_recipient_proof_bundle_envelope_for_activation_context_v1(
            "deriver_b_signing_worker_bundle",
            &deriver_b,
            activation_context,
            &activation_context.signer_set().signer_b,
        )
    }
}

/// Shared context for deterministic local signer handlers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalSignerHandlerContextV1 {
    /// Lifecycle id bound into signer responses.
    pub lifecycle_id: String,
    /// Public Router request digest expected inside decrypted signer input.
    pub router_request_digest: PublicDigest32,
    /// Root-share epoch the local signer host has loaded.
    pub root_share_epoch: RootShareEpoch,
    /// Peer signer identity for the A/B coordination message.
    pub peer_signer: SignerIdentityV1,
    /// Selected server identity.
    pub selected_server: ServerIdentityV1,
}

impl LocalSignerHandlerContextV1 {
    /// Creates a validated local signer handler context.
    pub fn new(
        lifecycle_id: impl Into<String>,
        router_request_digest: PublicDigest32,
        root_share_epoch: RootShareEpoch,
        peer_signer: SignerIdentityV1,
        selected_server: ServerIdentityV1,
    ) -> RouterAbProtocolResult<Self> {
        let context = Self {
            lifecycle_id: lifecycle_id.into(),
            router_request_digest,
            root_share_epoch,
            peer_signer,
            selected_server,
        };
        context.validate()?;
        Ok(context)
    }

    /// Validates the shared signer handler context.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("lifecycle_id", &self.lifecycle_id)?;
        require_non_empty("root_share_epoch", self.root_share_epoch.as_str())?;
        self.peer_signer.validate()?;
        self.selected_server.validate()
    }
}

/// Adapter boundary for local signer-envelope decryption.
pub trait LocalSignerEnvelopeDecryptorV1 {
    /// Returns typed signer input after role-specific envelope decryption.
    fn decrypt_signer_input_plaintext(
        &self,
        context: &LocalSignerHandlerContextV1,
        payload: &RouterToSignerPayloadV1,
    ) -> RouterAbProtocolResult<SignerInputPlaintextV1>;
}

/// Deterministic local decryptor used before real envelope encryption lands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalDeterministicSignerEnvelopeDecryptorV1;

impl LocalSignerEnvelopeDecryptorV1 for LocalDeterministicSignerEnvelopeDecryptorV1 {
    fn decrypt_signer_input_plaintext(
        &self,
        context: &LocalSignerHandlerContextV1,
        payload: &RouterToSignerPayloadV1,
    ) -> RouterAbProtocolResult<SignerInputPlaintextV1> {
        context.validate()?;
        let assignment = payload.assignment();
        let signer_set = payload.signer_set();
        SignerInputPlaintextV1::new(
            payload.lifecycle().primitive_request_kind,
            payload.lifecycle().lifecycle_id.clone(),
            signer_set.signer_set_id.clone(),
            SignerInputQuorumPolicyV1::All2,
            assignment.signer.role,
            assignment.signer.signer_id.clone(),
            assignment.signer.key_epoch.clone(),
            context.root_share_epoch.clone(),
            signer_set.selected_server.server_id.clone(),
            signer_set.selected_server.key_epoch.clone(),
            payload.transcript_digest(),
            context.router_request_digest,
            assignment.envelope.aad_digest,
            vec![
                local_mpc_prf_output_request(OpenedShareKind::XClientBase, Role::Client, "client")?,
                local_mpc_prf_output_request(
                    OpenedShareKind::XServerBase,
                    Role::Server,
                    signer_set.selected_server.server_id.clone(),
                )?,
            ],
        )
        .map_err(map_derivation_to_protocol_error)
    }
}

fn local_mpc_prf_output_request(
    opened_share_kind: OpenedShareKind,
    recipient_role: Role,
    recipient_identity: impl Into<String>,
) -> RouterAbProtocolResult<MpcPrfOutputRequestV1> {
    MpcPrfOutputRequestV1::new(opened_share_kind, recipient_role, recipient_identity)
        .map_err(map_derivation_to_protocol_error)
}

fn map_derivation_to_protocol_error(error: RouterAbDerivationError) -> RouterAbProtocolError {
    RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::MalformedWirePayload,
        format!(
            "local signer plaintext boundary rejected input: {:?}",
            error.code()
        ),
    )
}

/// Local Deriver A handler.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalDeriverAServiceV1 {
    /// Local Deriver A endpoint descriptor.
    pub endpoint: LocalDeriverAEndpointV1,
    /// Deriver A identity.
    pub signer: SignerIdentityV1,
}

impl LocalDeriverAServiceV1 {
    /// Creates a local Deriver A handler.
    pub fn new(
        endpoint: LocalDeriverAEndpointV1,
        signer: SignerIdentityV1,
    ) -> RouterAbProtocolResult<Self> {
        endpoint.validate()?;
        require_signer_role(&signer, Role::SignerA)?;
        Ok(Self { endpoint, signer })
    }

    /// Handles a Router-to-Deriver-A local request.
    pub fn handle_router_request(
        &self,
        context: LocalSignerHandlerContextV1,
        request: LocalTransportEnvelopeV1,
    ) -> RouterAbProtocolResult<LocalSignerHandlerOutputV1> {
        require_route(&request, LocalTransportRouteV1::RouterToSignerA)?;
        require_signer_role(&context.peer_signer, Role::SignerB)?;
        let payload =
            require_local_router_to_signer_payload(&request.message, Role::SignerA, &self.signer)?;
        let plaintext = LocalDeterministicSignerEnvelopeDecryptorV1
            .decrypt_signer_input_plaintext(&context, &payload)?;
        validate_signer_input_plaintext_binding_v1(
            &payload,
            &plaintext,
            context.router_request_digest,
            &context.root_share_epoch,
        )?;
        let peer_message = local_peer_message(
            LocalTransportRouteV1::SignerAToSignerB,
            self.signer.clone(),
            context.peer_signer,
            &payload,
            &plaintext,
        )?;
        Ok(LocalSignerHandlerOutputV1::SignerA { peer_message })
    }
}

/// Local SigningWorker handler.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalSigningWorkerServiceV1 {
    /// Local SigningWorker endpoint descriptor.
    pub endpoint: LocalSigningWorkerEndpointV1,
    /// Selected server identity hosted by the SigningWorker.
    pub server: ServerIdentityV1,
}

impl LocalSigningWorkerServiceV1 {
    /// Creates a local SigningWorker handler.
    pub fn new(
        endpoint: LocalSigningWorkerEndpointV1,
        server: ServerIdentityV1,
    ) -> RouterAbProtocolResult<Self> {
        endpoint.validate()?;
        server.validate()?;
        Ok(Self { endpoint, server })
    }

    /// Accepts recipient-scoped SigningWorker proof bundles routed to the local SigningWorker role.
    pub fn accept_recipient_proof_bundle_activation(
        &self,
        activation_context: &SigningWorkerActivationContextV1,
        activation: LocalSigningWorkerRecipientProofBundleActivationV1,
        activated_at_ms: u64,
    ) -> RouterAbProtocolResult<LocalSigningWorkerActivationReceiptV1> {
        activation.validate_for_activation_context(activation_context)?;
        let deriver_a = decode_local_recipient_proof_bundle_wire_v1(
            "deriver_a_signing_worker_bundle",
            &activation.deriver_a_signing_worker_bundle,
            Role::SignerA,
            Role::Server,
            OpenedShareKind::XServerBase,
        )?;
        let deriver_b = decode_local_recipient_proof_bundle_wire_v1(
            "deriver_b_signing_worker_bundle",
            &activation.deriver_b_signing_worker_bundle,
            Role::SignerB,
            Role::Server,
            OpenedShareKind::XServerBase,
        )?;
        if deriver_a.recipient_identity != self.server.server_id
            || deriver_b.recipient_identity != self.server.server_id
            || deriver_a.recipient_encryption_key != self.server.recipient_encryption_key
            || deriver_b.recipient_encryption_key != self.server.recipient_encryption_key
        {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "local SigningWorker proof-bundle activation recipient does not match selected worker",
            ));
        }
        let router_server = &activation_context.signer_set().selected_server;
        if router_server != &self.server
            || activation_context.lifecycle().selected_server_id != self.server.server_id
        {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "local SigningWorker proof-bundle activation does not match selected Router worker",
            ));
        }
        local_open_recipient_proof_bundle_payload_v1(
            &deriver_a,
            &self.server.recipient_encryption_key,
        )?;
        local_open_recipient_proof_bundle_payload_v1(
            &deriver_b,
            &self.server.recipient_encryption_key,
        )?;
        let mut hasher = Sha256::new();
        push_hash_field(&mut hasher, LOCAL_DEV_OUTPUT_LABEL_V1);
        push_hash_field(&mut hasher, b"server-proof-bundle-activation");
        push_hash_field(
            &mut hasher,
            activation
                .deriver_a_signing_worker_bundle
                .digest()
                .as_bytes(),
        );
        push_hash_field(
            &mut hasher,
            activation
                .deriver_b_signing_worker_bundle
                .digest()
                .as_bytes(),
        );
        let activation_digest = PublicDigest32::new(hasher.finalize().into());
        let signing_worker_material_handle = local_signing_worker_material_handle_v1(
            &self.endpoint.server_output_storage,
            &self.server,
            activation_digest,
        );
        let lifecycle = activation_context.lifecycle();
        let active_signing_worker_state = ActiveSigningWorkerStateV1::new(
            lifecycle.account_id.clone(),
            lifecycle.session_id.clone(),
            activation_context
                .transcript_metadata
                .account_public_key
                .clone(),
            self.server.clone(),
            activation.deriver_a_signing_worker_bundle.transcript_digest,
            activation_digest,
            signing_worker_material_handle,
            activated_at_ms,
        )?;
        Ok(LocalSigningWorkerActivationReceiptV1 {
            signing_worker: self.server.clone(),
            transcript_digest: activation.deriver_a_signing_worker_bundle.transcript_digest,
            activation_digest,
            active_signing_worker_state,
        })
    }
}

/// Local Deriver B handler.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalDeriverBServiceV1 {
    /// Local Deriver B endpoint descriptor.
    pub endpoint: LocalDeriverBEndpointV1,
    /// Deriver B identity.
    pub signer: SignerIdentityV1,
}

impl LocalDeriverBServiceV1 {
    /// Creates a local Deriver B handler.
    pub fn new(
        endpoint: LocalDeriverBEndpointV1,
        signer: SignerIdentityV1,
    ) -> RouterAbProtocolResult<Self> {
        endpoint.validate()?;
        require_signer_role(&signer, Role::SignerB)?;
        Ok(Self { endpoint, signer })
    }

    /// Handles a Router-to-Deriver-B local request.
    pub fn handle_router_request(
        &self,
        context: LocalSignerHandlerContextV1,
        request: LocalTransportEnvelopeV1,
    ) -> RouterAbProtocolResult<LocalSignerHandlerOutputV1> {
        require_route(&request, LocalTransportRouteV1::RouterToSignerB)?;
        require_signer_role(&context.peer_signer, Role::SignerA)?;
        let payload =
            require_local_router_to_signer_payload(&request.message, Role::SignerB, &self.signer)?;
        let plaintext = LocalDeterministicSignerEnvelopeDecryptorV1
            .decrypt_signer_input_plaintext(&context, &payload)?;
        validate_signer_input_plaintext_binding_v1(
            &payload,
            &plaintext,
            context.router_request_digest,
            &context.root_share_epoch,
        )?;
        let peer_message = local_peer_message(
            LocalTransportRouteV1::SignerBToSignerA,
            self.signer.clone(),
            context.peer_signer,
            &payload,
            &plaintext,
        )?;
        Ok(LocalSignerHandlerOutputV1::SignerB { peer_message })
    }
}

/// Branch-specific local signer handler output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "signer", rename_all = "snake_case")]
pub enum LocalSignerHandlerOutputV1 {
    /// Signer A proof-batch coordination message.
    SignerA {
        /// A-to-B coordination message.
        peer_message: LocalTransportEnvelopeV1,
    },
    /// Signer B proof-batch coordination message.
    SignerB {
        /// B-to-A coordination message.
        peer_message: LocalTransportEnvelopeV1,
    },
}

impl LocalSignerHandlerOutputV1 {
    /// Returns the peer coordination message.
    pub fn peer_message(&self) -> &LocalTransportEnvelopeV1 {
        match self {
            Self::SignerA { peer_message, .. } | Self::SignerB { peer_message, .. } => peer_message,
        }
    }
}

/// Receipt for local SigningWorker activation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalSigningWorkerActivationReceiptV1 {
    /// SigningWorker identity that accepted the activation.
    pub signing_worker: ServerIdentityV1,
    /// Transcript digest of the activation message.
    pub transcript_digest: PublicDigest32,
    /// Digest of the activation wire message.
    pub activation_digest: PublicDigest32,
    /// Active SigningWorker state descriptor used by normal signing.
    pub active_signing_worker_state: ActiveSigningWorkerStateV1,
}

/// Local service startup config with validated role-specific env bindings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LocalServiceStartupV1 {
    /// Router startup config.
    Router {
        /// Router handler.
        service: LocalRouterServiceV1,
        /// Router env snapshot.
        env: LocalEnvSnapshotV1,
    },
    /// Deriver A startup config.
    DeriverA {
        /// Deriver A handler.
        service: LocalDeriverAServiceV1,
        /// Deriver A env snapshot.
        env: LocalEnvSnapshotV1,
    },
    /// Deriver B startup config.
    DeriverB {
        /// Deriver B handler.
        service: LocalDeriverBServiceV1,
        /// Deriver B env snapshot.
        env: LocalEnvSnapshotV1,
    },
    /// SigningWorker startup config.
    SigningWorker {
        /// SigningWorker handler.
        service: LocalSigningWorkerServiceV1,
        /// SigningWorker env snapshot.
        env: LocalEnvSnapshotV1,
    },
}

impl LocalServiceStartupV1 {
    /// Creates a validated Router startup config.
    pub fn router(
        endpoint: LocalRouterEndpointV1,
        env: LocalEnvSnapshotV1,
    ) -> RouterAbProtocolResult<Self> {
        require_env_role(&env, LocalServiceRoleV1::Router)?;
        Ok(Self::Router {
            service: LocalRouterServiceV1::new(endpoint)?,
            env,
        })
    }

    /// Creates a validated Deriver A startup config.
    pub fn deriver_a(
        endpoint: LocalDeriverAEndpointV1,
        signer: SignerIdentityV1,
        env: LocalEnvSnapshotV1,
    ) -> RouterAbProtocolResult<Self> {
        require_env_role(&env, LocalServiceRoleV1::DeriverA)?;
        Ok(Self::DeriverA {
            service: LocalDeriverAServiceV1::new(endpoint, signer)?,
            env,
        })
    }

    /// Creates a validated Deriver B startup config.
    pub fn deriver_b(
        endpoint: LocalDeriverBEndpointV1,
        signer: SignerIdentityV1,
        env: LocalEnvSnapshotV1,
    ) -> RouterAbProtocolResult<Self> {
        require_env_role(&env, LocalServiceRoleV1::DeriverB)?;
        Ok(Self::DeriverB {
            service: LocalDeriverBServiceV1::new(endpoint, signer)?,
            env,
        })
    }

    /// Creates a validated SigningWorker startup config.
    pub fn signing_worker(
        endpoint: LocalSigningWorkerEndpointV1,
        server: ServerIdentityV1,
        env: LocalEnvSnapshotV1,
    ) -> RouterAbProtocolResult<Self> {
        require_env_role(&env, LocalServiceRoleV1::SigningWorker)?;
        Ok(Self::SigningWorker {
            service: LocalSigningWorkerServiceV1::new(endpoint, server)?,
            env,
        })
    }

    /// Returns the startup service role.
    pub fn role(&self) -> LocalServiceRoleV1 {
        match self {
            Self::Router { .. } => LocalServiceRoleV1::Router,
            Self::DeriverA { .. } => LocalServiceRoleV1::DeriverA,
            Self::DeriverB { .. } => LocalServiceRoleV1::DeriverB,
            Self::SigningWorker { .. } => LocalServiceRoleV1::SigningWorker,
        }
    }
}

/// In-process local service stack assembled from validated startup configs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalServiceStackV1 {
    /// Router handler.
    pub router: LocalRouterServiceV1,
    /// Router env snapshot.
    pub router_env: LocalEnvSnapshotV1,
    /// Deriver A handler.
    pub deriver_a: LocalDeriverAServiceV1,
    /// Deriver A env snapshot.
    pub deriver_a_env: LocalEnvSnapshotV1,
    /// Deriver B handler.
    pub deriver_b: LocalDeriverBServiceV1,
    /// Deriver B env snapshot.
    pub deriver_b_env: LocalEnvSnapshotV1,
    /// SigningWorker handler.
    pub signing_worker: LocalSigningWorkerServiceV1,
    /// SigningWorker env snapshot.
    pub signing_worker_env: LocalEnvSnapshotV1,
}

impl LocalServiceStackV1 {
    /// Creates a validated in-process service stack.
    pub fn new(
        router: LocalServiceStartupV1,
        deriver_a: LocalServiceStartupV1,
        deriver_b: LocalServiceStartupV1,
        signing_worker: LocalServiceStartupV1,
    ) -> RouterAbProtocolResult<Self> {
        let (router, router_env) = require_router_startup(router)?;
        let (deriver_a, deriver_a_env) = require_deriver_a_startup(deriver_a)?;
        let (deriver_b, deriver_b_env) = require_deriver_b_startup(deriver_b)?;
        let (signing_worker, signing_worker_env) = require_signing_worker_startup(signing_worker)?;
        Ok(Self {
            router,
            router_env,
            deriver_a,
            deriver_a_env,
            deriver_b,
            deriver_b_env,
            signing_worker,
            signing_worker_env,
        })
    }

    /// Runs the deterministic in-process local derivation ceremony.
    pub fn run_deterministic_ceremony(
        &self,
        lifecycle_id: impl Into<String>,
        deriver_a_request: WireMessageV1,
        deriver_b_request: WireMessageV1,
    ) -> RouterAbProtocolResult<LocalInProcessCeremonyResultV1> {
        let lifecycle_id = lifecycle_id.into();
        require_non_empty("lifecycle_id", &lifecycle_id)?;
        let dispatch = self
            .router
            .dispatch_signer_requests(deriver_a_request, deriver_b_request)?;
        let router_request_digest = local_router_request_digest_v1(
            &lifecycle_id,
            &dispatch.to_deriver_a.message,
            &dispatch.to_deriver_b.message,
        );
        let root_share_epoch = local_dev_root_share_epoch_v1()?;
        let deriver_a_context = LocalSignerHandlerContextV1::new(
            lifecycle_id.clone(),
            router_request_digest,
            root_share_epoch.clone(),
            self.deriver_b.signer.clone(),
            self.signing_worker.server.clone(),
        )?;
        let deriver_b_context = LocalSignerHandlerContextV1::new(
            lifecycle_id.clone(),
            router_request_digest,
            root_share_epoch,
            self.deriver_a.signer.clone(),
            self.signing_worker.server.clone(),
        )?;
        let deriver_a_output = self
            .deriver_a
            .handle_router_request(deriver_a_context, dispatch.to_deriver_a.clone())?;
        let deriver_b_output = self
            .deriver_b
            .handle_router_request(deriver_b_context, dispatch.to_deriver_b.clone())?;
        let deriver_a_peer_message = require_deriver_a_output(deriver_a_output)?;
        let deriver_b_peer_message = require_deriver_b_output(deriver_b_output)?;
        let (deriver_a_response, deriver_b_response) =
            local_recipient_proof_bundle_responses_from_peer_messages(
                &dispatch.to_deriver_a.message,
                &deriver_a_peer_message,
                &deriver_b_peer_message,
            )?;
        let router_response = LocalRouterRecipientProofBundleResponseV1::new(
            deriver_a_response.client_bundle.clone(),
            deriver_b_response.client_bundle.clone(),
        )?;
        let router_payload =
            decode_router_to_signer_payload_v1(dispatch.to_deriver_a.message.payload.as_bytes())?;
        router_response.validate_for_router_payload(&router_payload)?;
        let signing_worker_activation = LocalSigningWorkerRecipientProofBundleActivationV1::new(
            deriver_a_response.server_bundle.clone(),
            deriver_b_response.server_bundle.clone(),
        )?;
        let signing_worker_activation_context =
            SigningWorkerActivationContextV1::from_router_payload(&router_payload)?;
        signing_worker_activation
            .validate_for_activation_context(&signing_worker_activation_context)?;
        let signing_worker_activation_receipt = self
            .signing_worker
            .accept_recipient_proof_bundle_activation(
                &signing_worker_activation_context,
                signing_worker_activation.clone(),
                LOCAL_DEV_SIGNING_WORKER_ACTIVATED_AT_MS_V1,
            )?;
        Ok(LocalInProcessCeremonyResultV1 {
            router_response,
            deriver_a_peer_message,
            deriver_b_peer_message,
            signing_worker_activation,
            signing_worker_activation_receipt,
        })
    }

    /// Runs the deterministic local ceremony through typed local HTTP requests.
    pub fn run_deterministic_http_ceremony(
        &self,
        lifecycle_id: impl Into<String>,
        deriver_a_request: LocalHttpRequestV1,
        deriver_b_request: LocalHttpRequestV1,
    ) -> RouterAbProtocolResult<LocalHttpCeremonyResultV1> {
        require_http_path(&deriver_a_request, LocalHttpPathV1::RouterToSignerA)?;
        require_http_path(&deriver_b_request, LocalHttpPathV1::RouterToSignerB)?;
        let result = self.run_deterministic_ceremony(
            lifecycle_id,
            deriver_a_request.envelope.message,
            deriver_b_request.envelope.message,
        )?;
        Ok(LocalHttpCeremonyResultV1 {
            router_response: result.router_response,
            deriver_a_peer_request: LocalHttpRequestV1::new(
                LocalHttpMethodV1::Post,
                LocalHttpPathV1::SignerAToSignerB,
                result.deriver_a_peer_message,
            )?,
            deriver_b_peer_request: LocalHttpRequestV1::new(
                LocalHttpMethodV1::Post,
                LocalHttpPathV1::SignerBToSignerA,
                result.deriver_b_peer_message,
            )?,
            signing_worker_activation: result.signing_worker_activation,
            signing_worker_activation_receipt: result.signing_worker_activation_receipt,
        })
    }

    /// Handles one local client request submitted to Router.
    pub fn handle_local_client_request(
        &self,
        now_unix_ms: u64,
        request: LocalClientRouterRequestV1,
    ) -> RouterAbProtocolResult<LocalHttpCeremonyResultV1> {
        request.validate_at(now_unix_ms)?;
        self.run_deterministic_http_ceremony(
            request.lifecycle_id,
            request.deriver_a_request,
            request.deriver_b_request,
        )
    }

    /// Handles one local client request with replay detection.
    pub fn handle_local_client_request_with_replay_cache(
        &self,
        now_unix_ms: u64,
        replay_cache: &mut LocalReplayCacheV1,
        request: LocalClientRouterRequestV1,
    ) -> RouterAbProtocolResult<LocalHttpCeremonyResultV1> {
        request.validate_at(now_unix_ms)?;
        replay_cache.check_and_record(&request)?;
        self.run_deterministic_http_ceremony(
            request.lifecycle_id,
            request.deriver_a_request,
            request.deriver_b_request,
        )
    }
}

/// Result of the deterministic in-process local ceremony.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalInProcessCeremonyResultV1 {
    /// Router response carrying opaque client proof bundles.
    pub router_response: LocalRouterRecipientProofBundleResponseV1,
    /// A-to-B coordination message.
    pub deriver_a_peer_message: LocalTransportEnvelopeV1,
    /// B-to-A coordination message.
    pub deriver_b_peer_message: LocalTransportEnvelopeV1,
    /// SigningWorker activation carrying opaque x_server_base proof bundles.
    pub signing_worker_activation: LocalSigningWorkerRecipientProofBundleActivationV1,
    /// Receipt from the local SigningWorker role.
    pub signing_worker_activation_receipt: LocalSigningWorkerActivationReceiptV1,
}

/// Local HTTP method accepted by the boundary simulator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalHttpMethodV1 {
    /// HTTP GET.
    Get,
    /// HTTP POST.
    Post,
}

impl LocalHttpMethodV1 {
    /// Returns the stable HTTP method label.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
        }
    }
}

/// Local HTTP path for a checked transport envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalHttpPathV1 {
    /// Router forwards Signer A's request.
    RouterToSignerA,
    /// Router forwards Signer B's request.
    RouterToSignerB,
    /// Signer A sends a peer message to Signer B.
    SignerAToSignerB,
    /// Signer B sends a peer message to Signer A.
    SignerBToSignerA,
}

impl LocalHttpPathV1 {
    /// Returns the stable local HTTP path.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RouterToSignerA => "/local/router/signer-a",
            Self::RouterToSignerB => "/local/router/signer-b",
            Self::SignerAToSignerB => "/local/signer-a/signer-b",
            Self::SignerBToSignerA => "/local/signer-b/signer-a",
        }
    }

    /// Returns the required local transport route.
    pub fn expected_route(self) -> LocalTransportRouteV1 {
        match self {
            Self::RouterToSignerA => LocalTransportRouteV1::RouterToSignerA,
            Self::RouterToSignerB => LocalTransportRouteV1::RouterToSignerB,
            Self::SignerAToSignerB => LocalTransportRouteV1::SignerAToSignerB,
            Self::SignerBToSignerA => LocalTransportRouteV1::SignerBToSignerA,
        }
    }
}

/// Local HTTP request carrying a checked transport envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalHttpRequestV1 {
    /// HTTP method.
    pub method: LocalHttpMethodV1,
    /// Local HTTP path.
    pub path: LocalHttpPathV1,
    /// Checked transport envelope.
    pub envelope: LocalTransportEnvelopeV1,
}

impl LocalHttpRequestV1 {
    /// Creates a validated local HTTP request.
    pub fn new(
        method: LocalHttpMethodV1,
        path: LocalHttpPathV1,
        envelope: LocalTransportEnvelopeV1,
    ) -> RouterAbProtocolResult<Self> {
        let request = Self {
            method,
            path,
            envelope,
        };
        request.validate()?;
        Ok(request)
    }

    /// Validates method, path, and route agreement.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        if self.method != LocalHttpMethodV1::Post {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalHttpRequest,
                format!(
                    "local HTTP request requires POST, received {}",
                    self.method.as_str()
                ),
            ));
        }
        self.envelope.validate()?;
        if self.envelope.route != self.path.expected_route() {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalHttpRequest,
                format!(
                    "local HTTP path {} does not match route {:?}",
                    self.path.as_str(),
                    self.envelope.route
                ),
            ));
        }
        Ok(())
    }
}

/// Result of the deterministic local ceremony over the typed HTTP boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalHttpCeremonyResultV1 {
    /// Router response carrying opaque client proof bundles.
    pub router_response: LocalRouterRecipientProofBundleResponseV1,
    /// A-to-B local HTTP peer request.
    pub deriver_a_peer_request: LocalHttpRequestV1,
    /// B-to-A local HTTP peer request.
    pub deriver_b_peer_request: LocalHttpRequestV1,
    /// SigningWorker activation carrying opaque x_server_base proof bundles.
    pub signing_worker_activation: LocalSigningWorkerRecipientProofBundleActivationV1,
    /// Receipt from the local SigningWorker role.
    pub signing_worker_activation_receipt: LocalSigningWorkerActivationReceiptV1,
}

/// Single local client request submitted to Router for the split ceremony.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalClientRouterRequestV1 {
    /// Lifecycle id assigned for the local ceremony.
    pub lifecycle_id: String,
    /// Client request nonce used by local replay checks.
    pub request_nonce: String,
    /// Expiry timestamp in Unix milliseconds.
    pub expires_at_ms: u64,
    /// Local HTTP request carrying the Signer A envelope.
    pub deriver_a_request: LocalHttpRequestV1,
    /// Local HTTP request carrying the Signer B envelope.
    pub deriver_b_request: LocalHttpRequestV1,
}

impl LocalClientRouterRequestV1 {
    /// Creates a validated local client-to-Router request.
    pub fn new(
        lifecycle_id: impl Into<String>,
        request_nonce: impl Into<String>,
        expires_at_ms: u64,
        deriver_a_request: LocalHttpRequestV1,
        deriver_b_request: LocalHttpRequestV1,
    ) -> RouterAbProtocolResult<Self> {
        let request = Self {
            lifecycle_id: lifecycle_id.into(),
            request_nonce: request_nonce.into(),
            expires_at_ms,
            deriver_a_request,
            deriver_b_request,
        };
        request.validate()?;
        Ok(request)
    }

    /// Validates local client request shape and transcript agreement.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("lifecycle_id", &self.lifecycle_id)?;
        require_non_empty("request_nonce", &self.request_nonce)?;
        if self.expires_at_ms == 0 {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidTimeRange,
                "local client request expires_at_ms must be greater than zero",
            ));
        }
        require_http_path(&self.deriver_a_request, LocalHttpPathV1::RouterToSignerA)?;
        require_http_path(&self.deriver_b_request, LocalHttpPathV1::RouterToSignerB)?;
        require_matching_transcripts(
            &self.deriver_a_request.envelope.message,
            &self.deriver_b_request.envelope.message,
        )
    }

    /// Validates local client request shape, transcript agreement, and expiry.
    pub fn validate_at(&self, now_unix_ms: u64) -> RouterAbProtocolResult<()> {
        self.validate()?;
        if now_unix_ms >= self.expires_at_ms {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ExpiredLocalRequest,
                "local client request expired",
            ));
        }
        Ok(())
    }
}

/// Local replay cache for client-to-Router request nonces.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalReplayCacheV1 {
    /// Request nonces already accepted by the local Router.
    pub seen_request_nonces: Vec<String>,
}

impl LocalReplayCacheV1 {
    /// Creates an empty replay cache.
    pub fn new() -> Self {
        Self {
            seen_request_nonces: Vec::new(),
        }
    }

    /// Records a request nonce once and rejects repeats.
    pub fn check_and_record(
        &mut self,
        request: &LocalClientRouterRequestV1,
    ) -> RouterAbProtocolResult<()> {
        request.validate()?;
        if self
            .seen_request_nonces
            .iter()
            .any(|nonce| nonce == &request.request_nonce)
        {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ReplayedLocalRequest,
                "local client request nonce was already used",
            ));
        }
        self.seen_request_nonces.push(request.request_nonce.clone());
        Ok(())
    }
}

impl Default for LocalReplayCacheV1 {
    fn default() -> Self {
        Self::new()
    }
}

/// Local transport route used by in-process and local HTTP simulations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalTransportRouteV1 {
    /// Router forwards Signer A's role-specific request.
    RouterToSignerA,
    /// Router forwards Signer B's role-specific request.
    RouterToSignerB,
    /// Signer A sends an A/B protocol message to Signer B.
    SignerAToSignerB,
    /// Signer B sends an A/B protocol message to Signer A.
    SignerBToSignerA,
}

impl LocalTransportRouteV1 {
    /// Returns the source local service role.
    pub fn source(self) -> LocalServiceRoleV1 {
        match self {
            Self::RouterToSignerA | Self::RouterToSignerB => LocalServiceRoleV1::Router,
            Self::SignerAToSignerB => LocalServiceRoleV1::DeriverA,
            Self::SignerBToSignerA => LocalServiceRoleV1::DeriverB,
        }
    }

    /// Returns the destination local service role.
    pub fn destination(self) -> LocalServiceRoleV1 {
        match self {
            Self::RouterToSignerA | Self::SignerBToSignerA => LocalServiceRoleV1::DeriverA,
            Self::RouterToSignerB | Self::SignerAToSignerB => LocalServiceRoleV1::DeriverB,
        }
    }

    /// Returns the required canonical wire-message kind for the route.
    pub fn expected_wire_kind(self) -> WireMessageKindV1 {
        match self {
            Self::RouterToSignerA => WireMessageKindV1::RouterToSignerA,
            Self::RouterToSignerB => WireMessageKindV1::RouterToSignerB,
            Self::SignerAToSignerB => WireMessageKindV1::SignerAToSignerB,
            Self::SignerBToSignerA => WireMessageKindV1::SignerBToSignerA,
        }
    }
}

/// Local transport envelope with route and wire-kind agreement checked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalTransportEnvelopeV1 {
    /// Route used by the local simulation.
    pub route: LocalTransportRouteV1,
    /// Canonical wire message carried by the route.
    pub message: WireMessageV1,
}

impl LocalTransportEnvelopeV1 {
    /// Creates a validated local transport envelope.
    pub fn new(
        route: LocalTransportRouteV1,
        message: WireMessageV1,
    ) -> RouterAbProtocolResult<Self> {
        let envelope = Self { route, message };
        envelope.validate()?;
        Ok(envelope)
    }

    /// Validates route and wire-message kind agreement.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        let expected = self.route.expected_wire_kind();
        if self.message.kind != expected {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalRoute,
                format!(
                    "local route expected {} message, received {}",
                    expected.as_str(),
                    self.message.kind.as_str()
                ),
            ));
        }
        Ok(())
    }
}

fn local_router_request_digest_v1(
    lifecycle_id: &str,
    deriver_a_request: &WireMessageV1,
    deriver_b_request: &WireMessageV1,
) -> PublicDigest32 {
    let mut hasher = Sha256::new();
    push_hash_field(&mut hasher, LOCAL_DEV_ROUTER_REQUEST_DIGEST_LABEL_V1);
    push_hash_field(&mut hasher, lifecycle_id.as_bytes());
    push_hash_field(&mut hasher, deriver_a_request.digest().as_bytes());
    push_hash_field(&mut hasher, deriver_b_request.digest().as_bytes());
    PublicDigest32::new(hasher.finalize().into())
}

fn local_dev_root_share_epoch_v1() -> RouterAbProtocolResult<RootShareEpoch> {
    RootShareEpoch::new(LOCAL_DEV_ROOT_SHARE_EPOCH_V1).map_err(map_derivation_to_protocol_error)
}

fn require_keys(
    role: LocalServiceRoleV1,
    keys: &[&str],
    required: &[&str],
) -> RouterAbProtocolResult<()> {
    for required_key in required {
        if !keys.contains(required_key) {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MissingLocalBinding,
                format!(
                    "{} local service is missing required binding {required_key}",
                    role.as_str()
                ),
            ));
        }
    }
    Ok(())
}

fn require_seed_share(
    metadata: &LocalSigningRootMetadataV1,
    share: &LocalSealedRootShareRecordV1,
    expected_role: Role,
) -> RouterAbProtocolResult<()> {
    if share.signer_set_id != metadata.signer_set_id {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "local sealed-share signer_set_id does not match metadata",
        ));
    }
    if share.root_share_epoch != metadata.root_share_epoch {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "local sealed-share root_share_epoch does not match metadata",
        ));
    }
    if share.signer.role != expected_role {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidSignerIdentity,
            format!(
                "local persistence seed expected {} share, received {}",
                expected_role.as_str(),
                share.signer.role.as_str()
            ),
        ));
    }
    Ok(())
}

fn local_signing_root_metadata_sql_statement(
    metadata: &LocalSigningRootMetadataV1,
) -> RouterAbProtocolResult<LocalPersistenceSqlStatementV1> {
    metadata.validate()?;
    let placeholders = sqlite_placeholders(4);
    LocalPersistenceSqlStatementV1::new(
        format!(
            "INSERT INTO local_signing_roots \
             (signer_set_id, signing_root_version, root_share_epoch, account_id) \
             VALUES ({}, {}, {}, {}) \
             ON CONFLICT (signer_set_id, root_share_epoch) DO UPDATE SET \
             signing_root_version = excluded.signing_root_version, \
             account_id = excluded.account_id",
            placeholders[0], placeholders[1], placeholders[2], placeholders[3]
        ),
        vec![
            LocalPersistenceSqlValueV1::text(metadata.signer_set_id.clone()),
            LocalPersistenceSqlValueV1::text(metadata.signing_root_version.clone()),
            LocalPersistenceSqlValueV1::text(metadata.root_share_epoch.as_str()),
            LocalPersistenceSqlValueV1::text(metadata.account_id.clone()),
        ],
    )
}

fn local_sealed_root_share_sql_statement(
    share: &LocalSealedRootShareRecordV1,
) -> RouterAbProtocolResult<LocalPersistenceSqlStatementV1> {
    share.validate()?;
    let placeholders = sqlite_placeholders(8);
    LocalPersistenceSqlStatementV1::new(
        format!(
            "INSERT INTO local_sealed_root_shares \
             (signer_set_id, signer_role, signer_id, signer_key_epoch, root_share_epoch, \
             sealed_share_storage_key, sealed_share_commitment_hex, sealed_share_len) \
             VALUES ({}, {}, {}, {}, {}, {}, {}, {}) \
             ON CONFLICT (signer_set_id, signer_role, root_share_epoch) DO UPDATE SET \
             signer_id = excluded.signer_id, \
             signer_key_epoch = excluded.signer_key_epoch, \
             sealed_share_storage_key = excluded.sealed_share_storage_key, \
             sealed_share_commitment_hex = excluded.sealed_share_commitment_hex, \
             sealed_share_len = excluded.sealed_share_len",
            placeholders[0],
            placeholders[1],
            placeholders[2],
            placeholders[3],
            placeholders[4],
            placeholders[5],
            placeholders[6],
            placeholders[7]
        ),
        vec![
            LocalPersistenceSqlValueV1::text(share.signer_set_id.clone()),
            LocalPersistenceSqlValueV1::text(share.signer.role.as_str()),
            LocalPersistenceSqlValueV1::text(share.signer.signer_id.clone()),
            LocalPersistenceSqlValueV1::text(share.signer.key_epoch.clone()),
            LocalPersistenceSqlValueV1::text(share.root_share_epoch.as_str()),
            LocalPersistenceSqlValueV1::text(share.sealed_share_storage_key.clone()),
            LocalPersistenceSqlValueV1::text(hex::encode(share.sealed_share_commitment.as_bytes())),
            LocalPersistenceSqlValueV1::u32(share.sealed_share_len),
        ],
    )
}

fn sqlite_placeholders(count: usize) -> Vec<String> {
    (1..=count).map(|index| format!("?{index}")).collect()
}

fn reject_forbidden_keys(
    role: LocalServiceRoleV1,
    keys: &[&str],
    forbidden: &[&str],
) -> RouterAbProtocolResult<()> {
    for forbidden_key in forbidden {
        if keys.contains(forbidden_key) {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ForbiddenLocalBinding,
                format!(
                    "{} local service must not receive binding {forbidden_key}",
                    role.as_str()
                ),
            ));
        }
    }
    Ok(())
}

fn require_local_router_to_signer_payload(
    message: &WireMessageV1,
    expected_role: Role,
    local_signer: &SignerIdentityV1,
) -> RouterAbProtocolResult<RouterToSignerPayloadV1> {
    let payload = decode_router_to_signer_payload_v1(message.payload.as_bytes())?;
    if payload.transcript_digest() != message.transcript_digest {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "local signer request payload transcript digest does not match wire message",
        ));
    }
    let assignment = payload.require_recipient_role(expected_role)?;
    if assignment.signer != *local_signer {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidSignerIdentity,
            "local signer request assignment identity does not match local signer",
        ));
    }
    Ok(payload)
}

fn local_peer_message(
    route: LocalTransportRouteV1,
    from: SignerIdentityV1,
    to: SignerIdentityV1,
    payload: &RouterToSignerPayloadV1,
    plaintext: &SignerInputPlaintextV1,
) -> RouterAbProtocolResult<LocalTransportEnvelopeV1> {
    let batch_output = local_mpc_prf_batch_output(&from, payload, plaintext)?;
    let peer_payload = sign_ecdsa_threshold_prf_proof_batch_peer_payload_v1(
        &local_dev_peer_signing_key_bytes(&from),
        from,
        to,
        batch_output,
    )?;
    let message = WireMessageV1::new(
        route.expected_wire_kind(),
        peer_payload.transcript_digest,
        CanonicalWireBytesV1::new(peer_payload.canonical_bytes())?,
    )?;
    LocalTransportEnvelopeV1::new(route, message)
}

fn local_recipient_proof_bundle_responses_from_peer_messages(
    deriver_a_request: &WireMessageV1,
    deriver_a_peer_message: &LocalTransportEnvelopeV1,
    deriver_b_peer_message: &LocalTransportEnvelopeV1,
) -> RouterAbProtocolResult<(
    LocalSignerRecipientProofBundleResponseV1,
    LocalSignerRecipientProofBundleResponseV1,
)> {
    let router_payload = decode_router_to_signer_payload_v1(deriver_a_request.payload.as_bytes())?;
    if router_payload.transcript_digest() != deriver_a_request.transcript_digest {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "local proof-bundle response payload transcript does not match wire message",
        ));
    }
    let proof_batch_a = local_decode_peer_proof_batch(
        deriver_a_peer_message,
        LocalTransportRouteV1::SignerAToSignerB,
    )?;
    let proof_batch_b = local_decode_peer_proof_batch(
        deriver_b_peer_message,
        LocalTransportRouteV1::SignerBToSignerA,
    )?;
    if proof_batch_a.transcript_digest != deriver_a_request.transcript_digest
        || proof_batch_b.transcript_digest != deriver_a_request.transcript_digest
    {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "local proof-bundle response proof transcript mismatch",
        ));
    }
    if proof_batch_a.root_share_epoch != proof_batch_b.root_share_epoch {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "local proof-bundle response root-share epoch mismatch",
        ));
    }
    let mut encryptor = LocalDeterministicRecipientProofBundleEncryptorV1;
    let deriver_a_response = local_recipient_proof_bundle_response_from_ab_proof_batch_v1(
        &router_payload,
        proof_batch_a,
        &mut encryptor,
    )?;
    let deriver_b_response = local_recipient_proof_bundle_response_from_ab_proof_batch_v1(
        &router_payload,
        proof_batch_b,
        &mut encryptor,
    )?;
    Ok((deriver_a_response, deriver_b_response))
}

fn local_recipient_proof_bundle_response_from_ab_proof_batch_v1(
    router_payload: &RouterToSignerPayloadV1,
    proof_batch: EcdsaThresholdPrfProofBatchPayloadV1,
    encryptor: &mut impl RecipientProofBundleEncryptorV1,
) -> RouterAbProtocolResult<LocalSignerRecipientProofBundleResponseV1> {
    router_payload.validate()?;
    proof_batch.validate()?;
    let signer_role = proof_batch.from.role;
    require_signer_role_value(signer_role)?;
    let client_bundle = recipient_proof_bundle_wire_message_from_ab_proof_batch_v1(
        &router_payload.lifecycle().lifecycle_id,
        proof_batch.clone(),
        OpenedShareKind::XClientBase,
        Role::Client,
        &router_payload.transcript_metadata().client_id,
        &router_payload
            .transcript_metadata()
            .client_ephemeral_public_key,
        encryptor,
    )?;
    let server_bundle = recipient_proof_bundle_wire_message_from_ab_proof_batch_v1(
        &router_payload.lifecycle().lifecycle_id,
        proof_batch,
        OpenedShareKind::XServerBase,
        Role::Server,
        &router_payload.signer_set().selected_server.server_id,
        &router_payload
            .signer_set()
            .selected_server
            .recipient_encryption_key,
        encryptor,
    )?;
    let response =
        LocalSignerRecipientProofBundleResponseV1::new(signer_role, client_bundle, server_bundle)?;
    response.validate_for_router_payload(router_payload)?;
    Ok(response)
}

fn local_decode_peer_proof_batch(
    envelope: &LocalTransportEnvelopeV1,
    expected_route: LocalTransportRouteV1,
) -> RouterAbProtocolResult<EcdsaThresholdPrfProofBatchPayloadV1> {
    require_route(envelope, expected_route)?;
    let peer_payload = decode_ab_peer_message_payload_v1(envelope.message.payload.as_bytes())?;
    if peer_payload.transcript_digest != envelope.message.transcript_digest {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "local A/B proof-batch peer payload transcript does not match wire message",
        ));
    }
    decode_and_validate_ecdsa_threshold_prf_proof_batch_peer_payload_v1(&peer_payload)
}

fn decode_local_recipient_proof_bundle_wire_v1(
    field: &str,
    message: &WireMessageV1,
    expected_signer_role: Role,
    expected_recipient_role: Role,
    expected_opened_share_kind: OpenedShareKind,
) -> RouterAbProtocolResult<RecipientProofBundleCiphertextV1> {
    require_signer_role_value(expected_signer_role)?;
    if message.kind != WireMessageKindV1::RecipientProofBundle {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            format!("{field} must be a recipient_proof_bundle wire message"),
        ));
    }
    let envelope = decode_recipient_proof_bundle_ciphertext_v1(message.payload.as_bytes())?;
    if envelope.transcript_digest != message.transcript_digest {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            format!("{field} transcript digest does not match ciphertext envelope"),
        ));
    }
    if envelope.signer.role != expected_signer_role {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidSignerIdentity,
            format!("{field} proof-bundle signer role is not expected"),
        ));
    }
    if envelope.recipient_role != expected_recipient_role
        || envelope.opened_share_kind != expected_opened_share_kind
    {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            format!("{field} proof-bundle recipient binding is invalid"),
        ));
    }
    Ok(envelope)
}

fn expected_local_signer_identity_for_role_v1(
    router_payload: &RouterToSignerPayloadV1,
    role: Role,
) -> RouterAbProtocolResult<&SignerIdentityV1> {
    require_signer_role_value(role)?;
    match role {
        Role::SignerA => Ok(&router_payload.signer_set().signer_a),
        Role::SignerB => Ok(&router_payload.signer_set().signer_b),
        _ => unreachable!("require_signer_role_value accepted only signer roles"),
    }
}

fn validate_local_recipient_proof_bundle_envelope_for_router_payload_v1(
    field: &str,
    envelope: &RecipientProofBundleCiphertextV1,
    router_payload: &RouterToSignerPayloadV1,
    expected_signer: &SignerIdentityV1,
) -> RouterAbProtocolResult<()> {
    envelope.validate()?;
    router_payload.validate()?;
    expected_signer.validate()?;
    if envelope.signer != *expected_signer {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidSignerIdentity,
            format!("{field} signer identity does not match signer set"),
        ));
    }
    if envelope.transcript_digest != router_payload.transcript_digest() {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            format!("{field} transcript digest does not match Router payload"),
        ));
    }
    match (envelope.recipient_role, envelope.opened_share_kind) {
        (Role::Client, OpenedShareKind::XClientBase) => {
            let metadata = router_payload.transcript_metadata();
            if envelope.recipient_identity != metadata.client_id
                || envelope.recipient_encryption_key != metadata.client_ephemeral_public_key
            {
                return Err(RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                    format!("{field} client recipient binding does not match Router payload"),
                ));
            }
        }
        (Role::Server, OpenedShareKind::XServerBase) => {
            let server = &router_payload.signer_set().selected_server;
            if envelope.recipient_identity != server.server_id
                || envelope.recipient_encryption_key != server.recipient_encryption_key
            {
                return Err(RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                    format!("{field} server recipient binding does not match Router payload"),
                ));
            }
        }
        _ => {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                format!("{field} recipient proof-bundle binding is invalid"),
            ));
        }
    }
    Ok(())
}

fn validate_local_recipient_proof_bundle_envelope_for_activation_context_v1(
    field: &str,
    envelope: &RecipientProofBundleCiphertextV1,
    activation_context: &SigningWorkerActivationContextV1,
    expected_signer: &SignerIdentityV1,
) -> RouterAbProtocolResult<()> {
    envelope.validate()?;
    activation_context.validate()?;
    expected_signer.validate()?;
    if envelope.signer != *expected_signer {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidSignerIdentity,
            format!("{field} signer identity does not match signer set"),
        ));
    }
    if envelope.transcript_digest != activation_context.transcript_digest() {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            format!("{field} transcript digest does not match activation context"),
        ));
    }
    if envelope.recipient_role != Role::Server
        || envelope.opened_share_kind != OpenedShareKind::XServerBase
    {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            format!("{field} SigningWorker activation bundle has invalid output binding"),
        ));
    }
    let server = &activation_context.signer_set().selected_server;
    if envelope.recipient_identity != server.server_id
        || envelope.recipient_encryption_key != server.recipient_encryption_key
    {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            format!("{field} recipient binding does not match activation context"),
        ));
    }
    Ok(())
}

struct LocalDeterministicRecipientProofBundleEncryptorV1;

impl RecipientProofBundleEncryptorV1 for LocalDeterministicRecipientProofBundleEncryptorV1 {
    fn encrypt_recipient_proof_bundle_v1(
        &mut self,
        request: RecipientProofBundleEncryptionRequestV1,
    ) -> RouterAbProtocolResult<RecipientProofBundleCiphertextV1> {
        request.validate()?;
        let nonce = local_dev_recipient_proof_bundle_nonce_v1(&request);
        let mut ciphertext_and_tag = local_dev_recipient_proof_bundle_xor_v1(
            request.plaintext(),
            request.signer(),
            request.recipient_role(),
            request.opened_share_kind(),
            request.recipient_identity(),
            request.recipient_encryption_key(),
            &request.transcript_digest(),
            &request.payload_digest(),
            &nonce,
        );
        let tag = local_dev_recipient_proof_bundle_tag_v1(
            request.signer(),
            request.recipient_role(),
            request.opened_share_kind(),
            request.recipient_identity(),
            request.recipient_encryption_key(),
            &request.transcript_digest(),
            &request.payload_digest(),
            &nonce,
            &ciphertext_and_tag,
        );
        ciphertext_and_tag.extend_from_slice(&tag);

        RecipientProofBundleCiphertextV1::new(
            RecipientOutputEncryptionAlgorithmV1::LocalDeterministicSha256V1,
            request.signer().clone(),
            request.recipient_role(),
            request.opened_share_kind(),
            request.recipient_identity(),
            request.recipient_encryption_key(),
            request.transcript_digest(),
            request.payload_digest(),
            nonce,
            EncryptedPayloadV1::new(ciphertext_and_tag)?,
        )
    }
}

fn local_open_recipient_proof_bundle_payload_v1(
    envelope: &RecipientProofBundleCiphertextV1,
    recipient_encryption_key: &str,
) -> RouterAbProtocolResult<()> {
    envelope.validate()?;
    if envelope.algorithm != RecipientOutputEncryptionAlgorithmV1::LocalDeterministicSha256V1 {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "local proof-bundle opener requires local deterministic algorithm",
        ));
    }
    if envelope.recipient_encryption_key != recipient_encryption_key {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "local proof-bundle recipient key does not match opener key",
        ));
    }
    let ciphertext_and_tag = envelope.ciphertext_and_tag().as_bytes();
    if ciphertext_and_tag.len() <= LOCAL_DEV_PROOF_BUNDLE_TAG_LEN_V1 {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "local proof-bundle ciphertext is too short",
        ));
    }
    let ciphertext_len = ciphertext_and_tag.len() - LOCAL_DEV_PROOF_BUNDLE_TAG_LEN_V1;
    let (ciphertext, tag) = ciphertext_and_tag.split_at(ciphertext_len);
    let expected_tag = local_dev_recipient_proof_bundle_tag_v1(
        &envelope.signer,
        envelope.recipient_role,
        envelope.opened_share_kind,
        &envelope.recipient_identity,
        &envelope.recipient_encryption_key,
        &envelope.transcript_digest,
        &envelope.payload_digest,
        envelope.nonce(),
        ciphertext,
    );
    if expected_tag.as_slice() != tag {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "local proof-bundle ciphertext tag is invalid",
        ));
    }
    let plaintext = local_dev_recipient_proof_bundle_xor_v1(
        ciphertext,
        &envelope.signer,
        envelope.recipient_role,
        envelope.opened_share_kind,
        &envelope.recipient_identity,
        recipient_encryption_key,
        &envelope.transcript_digest,
        &envelope.payload_digest,
        envelope.nonce(),
    );
    let payload = decode_recipient_proof_bundle_payload_v1(&plaintext)?;
    verify_recipient_proof_bundle_ciphertext_payload_v1(envelope, &payload)
}

fn local_dev_recipient_proof_bundle_nonce_v1(
    request: &RecipientProofBundleEncryptionRequestV1,
) -> [u8; 12] {
    let mut hasher = Sha256::new();
    push_hash_field(&mut hasher, LOCAL_DEV_OUTPUT_LABEL_V1);
    push_hash_field(&mut hasher, b"recipient-proof-bundle");
    push_hash_field(&mut hasher, b"nonce");
    push_hash_field(&mut hasher, request.signer().role.as_str().as_bytes());
    push_hash_field(&mut hasher, request.signer().signer_id.as_bytes());
    push_hash_field(&mut hasher, request.signer().key_epoch.as_bytes());
    push_hash_field(&mut hasher, request.recipient_role().as_str().as_bytes());
    push_hash_field(&mut hasher, request.opened_share_kind().as_str().as_bytes());
    push_hash_field(&mut hasher, request.transcript_digest().as_bytes());
    push_hash_field(&mut hasher, request.payload_digest().as_bytes());
    push_hash_field(&mut hasher, request.recipient_identity().as_bytes());
    push_hash_field(&mut hasher, request.recipient_encryption_key().as_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&digest[..12]);
    nonce
}

#[allow(clippy::too_many_arguments)]
fn local_dev_recipient_proof_bundle_xor_v1(
    input: &[u8],
    signer: &SignerIdentityV1,
    recipient_role: Role,
    opened_share_kind: OpenedShareKind,
    recipient_identity: &str,
    recipient_encryption_key: &str,
    transcript_digest: &PublicDigest32,
    payload_digest: &PublicDigest32,
    nonce: &[u8; 12],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut counter = 0u64;
    while out.len() < input.len() {
        let mut hasher = Sha256::new();
        push_hash_field(&mut hasher, LOCAL_DEV_OUTPUT_LABEL_V1);
        push_hash_field(&mut hasher, b"recipient-proof-bundle");
        push_hash_field(&mut hasher, b"stream");
        push_local_recipient_proof_bundle_fields_v1(
            &mut hasher,
            signer,
            recipient_role,
            opened_share_kind,
            recipient_identity,
            recipient_encryption_key,
            transcript_digest,
            payload_digest,
            nonce,
        );
        push_hash_field(&mut hasher, &counter.to_be_bytes());
        let block: [u8; 32] = hasher.finalize().into();
        for byte in block {
            if out.len() == input.len() {
                break;
            }
            out.push(input[out.len()] ^ byte);
        }
        counter = counter.wrapping_add(1);
    }
    out
}

#[allow(clippy::too_many_arguments)]
fn local_dev_recipient_proof_bundle_tag_v1(
    signer: &SignerIdentityV1,
    recipient_role: Role,
    opened_share_kind: OpenedShareKind,
    recipient_identity: &str,
    recipient_encryption_key: &str,
    transcript_digest: &PublicDigest32,
    payload_digest: &PublicDigest32,
    nonce: &[u8; 12],
    ciphertext: &[u8],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    push_hash_field(&mut hasher, LOCAL_DEV_OUTPUT_LABEL_V1);
    push_hash_field(&mut hasher, b"recipient-proof-bundle");
    push_hash_field(&mut hasher, b"tag");
    push_local_recipient_proof_bundle_fields_v1(
        &mut hasher,
        signer,
        recipient_role,
        opened_share_kind,
        recipient_identity,
        recipient_encryption_key,
        transcript_digest,
        payload_digest,
        nonce,
    );
    push_hash_field(&mut hasher, ciphertext);
    hasher.finalize().into()
}

#[allow(clippy::too_many_arguments)]
fn push_local_recipient_proof_bundle_fields_v1(
    hasher: &mut Sha256,
    signer: &SignerIdentityV1,
    recipient_role: Role,
    opened_share_kind: OpenedShareKind,
    recipient_identity: &str,
    recipient_encryption_key: &str,
    transcript_digest: &PublicDigest32,
    payload_digest: &PublicDigest32,
    nonce: &[u8; 12],
) {
    push_hash_field(hasher, signer.role.as_str().as_bytes());
    push_hash_field(hasher, signer.signer_id.as_bytes());
    push_hash_field(hasher, signer.key_epoch.as_bytes());
    push_hash_field(hasher, recipient_role.as_str().as_bytes());
    push_hash_field(hasher, opened_share_kind.as_str().as_bytes());
    push_hash_field(hasher, recipient_identity.as_bytes());
    push_hash_field(hasher, recipient_encryption_key.as_bytes());
    push_hash_field(hasher, transcript_digest.as_bytes());
    push_hash_field(hasher, payload_digest.as_bytes());
    push_hash_field(hasher, nonce);
}

fn local_mpc_prf_batch_output(
    signer: &SignerIdentityV1,
    payload: &RouterToSignerPayloadV1,
    plaintext: &SignerInputPlaintextV1,
) -> RouterAbProtocolResult<MpcPrfThresholdSignerBatchOutputV1> {
    let signing_root_share_wire = local_dev_mpc_signing_root_share_wire_v1(signer.role)
        .map_err(map_derivation_to_protocol_error)?;
    let input =
        build_mpc_prf_threshold_signer_batch_input_v1(payload, plaintext, signing_root_share_wire)?;
    let mut proof_rng = LocalDevProofRngV1::new(signer, payload, plaintext);
    match signer.role {
        Role::SignerA => DeriverAEngine::new().evaluate_mpc_prf_output_batch(input, &mut proof_rng),
        Role::SignerB => DeriverBEngine::new().evaluate_mpc_prf_output_batch(input, &mut proof_rng),
        _ => Err(RouterAbDerivationError::new(
            crate::derivation::RouterAbDerivationErrorCode::SignerIdentityMismatch,
            "local MPC PRF batch output requires signer role",
        )),
    }
    .map_err(map_derivation_to_protocol_error)
}

fn local_dev_mpc_signing_root_share_wire_v1(
    signer_role: Role,
) -> crate::derivation::RouterAbDerivationResult<MpcPrfSigningRootShareWireV1> {
    let (share_id, scalar_byte) = match signer_role {
        Role::SignerA => (1u16, 11u8),
        Role::SignerB => (2u16, 29u8),
        _ => {
            return Err(RouterAbDerivationError::new(
                crate::derivation::RouterAbDerivationErrorCode::SignerIdentityMismatch,
                "local MPC PRF dev share requires signer role",
            ));
        }
    };
    // ECDSA threshold-PRF envelopes carry share wires: u16 share id + scalar.
    let mut bytes = vec![0u8; 34];
    bytes[0..2].copy_from_slice(&share_id.to_be_bytes());
    bytes[2] = scalar_byte;
    MpcPrfSigningRootShareWireV1::new(bytes)
}

struct LocalDevProofRngV1 {
    seed: [u8; 32],
    counter: u64,
    buffer: [u8; 32],
    offset: usize,
}

impl LocalDevProofRngV1 {
    fn new(
        signer: &SignerIdentityV1,
        payload: &RouterToSignerPayloadV1,
        plaintext: &SignerInputPlaintextV1,
    ) -> Self {
        let mut hasher = Sha256::new();
        push_hash_field(&mut hasher, LOCAL_DEV_OUTPUT_LABEL_V1);
        push_hash_field(&mut hasher, LOCAL_DEV_MPC_PROOF_RNG_LABEL_V1);
        push_hash_field(&mut hasher, signer.role.as_str().as_bytes());
        push_hash_field(&mut hasher, signer.signer_id.as_bytes());
        push_hash_field(&mut hasher, signer.key_epoch.as_bytes());
        push_hash_field(&mut hasher, payload.lifecycle().lifecycle_id.as_bytes());
        push_hash_field(&mut hasher, payload.signer_set().signer_set_id.as_bytes());
        push_hash_field(&mut hasher, plaintext.root_share_epoch.as_str().as_bytes());
        push_hash_field(&mut hasher, plaintext.router_request_digest.as_bytes());
        let seed = hasher.finalize().into();
        Self {
            seed,
            counter: 0,
            buffer: [0u8; 32],
            offset: 32,
        }
    }

    fn refill(&mut self) {
        let mut hasher = Sha256::new();
        push_hash_field(&mut hasher, LOCAL_DEV_OUTPUT_LABEL_V1);
        push_hash_field(&mut hasher, LOCAL_DEV_MPC_PROOF_RNG_LABEL_V1);
        push_hash_field(&mut hasher, &self.seed);
        push_hash_field(&mut hasher, &self.counter.to_be_bytes());
        self.buffer = hasher.finalize().into();
        self.counter = self.counter.wrapping_add(1);
        self.offset = 0;
    }
}

impl RngCore for LocalDevProofRngV1 {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0u8; 4];
        self.fill_bytes(&mut bytes);
        u32::from_be_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0u8; 8];
        self.fill_bytes(&mut bytes);
        u64::from_be_bytes(bytes)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for byte in dest {
            if self.offset == self.buffer.len() {
                self.refill();
            }
            *byte = self.buffer[self.offset];
            self.offset += 1;
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), RandError> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for LocalDevProofRngV1 {}

fn require_route(
    envelope: &LocalTransportEnvelopeV1,
    route: LocalTransportRouteV1,
) -> RouterAbProtocolResult<()> {
    envelope.validate()?;
    if envelope.route != route {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalRoute,
            format!(
                "local handler expected {:?} route, received {:?}",
                route, envelope.route
            ),
        ));
    }
    Ok(())
}

fn require_matching_transcripts(
    left: &WireMessageV1,
    right: &WireMessageV1,
) -> RouterAbProtocolResult<()> {
    if left.transcript_digest != right.transcript_digest {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "local messages must share one transcript digest",
        ));
    }
    Ok(())
}

fn require_http_path(
    request: &LocalHttpRequestV1,
    expected: LocalHttpPathV1,
) -> RouterAbProtocolResult<()> {
    request.validate()?;
    if request.path != expected {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalHttpRequest,
            format!(
                "local HTTP handler expected {} path, received {}",
                expected.as_str(),
                request.path.as_str()
            ),
        ));
    }
    Ok(())
}

fn require_signer_role(signer: &SignerIdentityV1, expected: Role) -> RouterAbProtocolResult<()> {
    signer.validate()?;
    if signer.role != expected {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidRole,
            format!(
                "local signer handler expected {} identity, received {}",
                expected.as_str(),
                signer.role.as_str()
            ),
        ));
    }
    Ok(())
}

fn require_signer_role_value(role: Role) -> RouterAbProtocolResult<()> {
    match role {
        Role::SignerA | Role::SignerB => Ok(()),
        _ => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidRole,
            "local proof-bundle delivery requires Signer A or Signer B role",
        )),
    }
}

fn require_router_startup(
    startup: LocalServiceStartupV1,
) -> RouterAbProtocolResult<(LocalRouterServiceV1, LocalEnvSnapshotV1)> {
    match startup {
        LocalServiceStartupV1::Router { service, env } => Ok((service, env)),
        other => Err(invalid_startup_branch(
            LocalServiceRoleV1::Router,
            other.role(),
        )),
    }
}

fn require_deriver_a_startup(
    startup: LocalServiceStartupV1,
) -> RouterAbProtocolResult<(LocalDeriverAServiceV1, LocalEnvSnapshotV1)> {
    match startup {
        LocalServiceStartupV1::DeriverA { service, env } => Ok((service, env)),
        other => Err(invalid_startup_branch(
            LocalServiceRoleV1::DeriverA,
            other.role(),
        )),
    }
}

fn require_deriver_b_startup(
    startup: LocalServiceStartupV1,
) -> RouterAbProtocolResult<(LocalDeriverBServiceV1, LocalEnvSnapshotV1)> {
    match startup {
        LocalServiceStartupV1::DeriverB { service, env } => Ok((service, env)),
        other => Err(invalid_startup_branch(
            LocalServiceRoleV1::DeriverB,
            other.role(),
        )),
    }
}

fn require_signing_worker_startup(
    startup: LocalServiceStartupV1,
) -> RouterAbProtocolResult<(LocalSigningWorkerServiceV1, LocalEnvSnapshotV1)> {
    match startup {
        LocalServiceStartupV1::SigningWorker { service, env } => Ok((service, env)),
        other => Err(invalid_startup_branch(
            LocalServiceRoleV1::SigningWorker,
            other.role(),
        )),
    }
}

fn require_deriver_a_output(
    output: LocalSignerHandlerOutputV1,
) -> RouterAbProtocolResult<LocalTransportEnvelopeV1> {
    match output {
        LocalSignerHandlerOutputV1::SignerA { peer_message } => Ok(peer_message),
        other => Err(invalid_signer_output_branch(
            LocalServiceRoleV1::DeriverA,
            other,
        )),
    }
}

fn require_deriver_b_output(
    output: LocalSignerHandlerOutputV1,
) -> RouterAbProtocolResult<LocalTransportEnvelopeV1> {
    match output {
        LocalSignerHandlerOutputV1::SignerB { peer_message } => Ok(peer_message),
        other => Err(invalid_signer_output_branch(
            LocalServiceRoleV1::DeriverB,
            other,
        )),
    }
}

fn invalid_startup_branch(
    expected: LocalServiceRoleV1,
    actual: LocalServiceRoleV1,
) -> RouterAbProtocolError {
    RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
        format!(
            "local stack expected {} startup config, received {}",
            expected.as_str(),
            actual.as_str()
        ),
    )
}

fn invalid_signer_output_branch(
    expected: LocalServiceRoleV1,
    actual: LocalSignerHandlerOutputV1,
) -> RouterAbProtocolError {
    RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
        format!(
            "local stack expected {} signer output, received {:?}",
            expected.as_str(),
            actual
        ),
    )
}

fn require_env_role(
    env: &LocalEnvSnapshotV1,
    expected: LocalServiceRoleV1,
) -> RouterAbProtocolResult<()> {
    env.validate()?;
    if env.role != expected {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            format!(
                "local startup expected {} env snapshot, received {}",
                expected.as_str(),
                env.role.as_str()
            ),
        ));
    }
    Ok(())
}

fn local_dev_peer_signing_key_bytes(signer: &SignerIdentityV1) -> [u8; 32] {
    match signer.role {
        Role::SignerA => [0xa1; 32],
        Role::SignerB => [0xb1; 32],
        _ => unreachable!("local dev peer signer role"),
    }
}

fn push_hash_field(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u32).to_be_bytes());
    hasher.update(bytes);
}

fn local_signing_worker_material_handle_v1(
    storage_binding: &str,
    server: &ServerIdentityV1,
    activation_digest: PublicDigest32,
) -> String {
    format!(
        "{}/{}/{}",
        storage_binding,
        server.server_id,
        hex::encode(activation_digest.as_bytes())
    )
}

fn require_non_empty(field: &'static str, value: &str) -> RouterAbProtocolResult<()> {
    if value.is_empty() {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::EmptyField,
            format!("{field} is required"),
        ));
    }
    Ok(())
}
