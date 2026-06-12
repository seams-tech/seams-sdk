use crate::derivation::{
    CandidateId, MpcPrfOutputRequestV1, MpcPrfSigningRootShareWireV1, MpcPrfSuiteId,
    MpcPrfThresholdSignerBatchOutputV1, OpenedShareKind, PublicDigest32, Role, RootShareEpoch,
    RouterAbDerivationError, SignerInputPlaintextV1, SignerInputQuorumPolicyV1,
};
use rand_core::{CryptoRng, Error as RandError, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::protocol::engine::{SignerAEngine, SignerBEngine};
use crate::protocol::envelope::EncryptedPayloadV1;
use crate::protocol::error::{
    RouterAbProtocolError, RouterAbProtocolErrorCode, RouterAbProtocolResult,
};
use crate::protocol::identity::{RelayerIdentityV1, SignerIdentityV1};
use crate::protocol::output::{
    combine_mpc_prf_output_packages_from_ab_proof_batches_v1, mpc_prf_output_label_v1,
    signer_response_wire_message_from_mpc_prf_packages_v1, MpcPrfOutputPackagesV1,
    RecipientOutputCiphertextV1, RecipientOutputEncryptionAlgorithmV1,
    RecipientOutputEncryptionRequestV1, RecipientOutputEncryptorV1, RelayerOutputPackageV1,
    THRESHOLD_PRF_OUTPUT_PACKAGE_LABEL_V1,
};
use crate::protocol::payload::{
    decode_ab_peer_message_payload_v1,
    decode_and_validate_ab_derivation_proof_batch_peer_payload_v1,
    decode_router_to_signer_payload_v1, sign_ab_derivation_proof_batch_peer_payload_v1,
    validate_signer_input_plaintext_binding_v1, AbDerivationProofBatchPayloadV1,
    RelayerActivationPayloadV1, RouterToSignerPayloadV1,
};
use crate::protocol::signer_input::build_mpc_prf_threshold_signer_batch_input_v1;
use crate::protocol::wire::{CanonicalWireBytesV1, WireMessageKindV1, WireMessageV1};

const LOCAL_DEV_OUTPUT_LABEL_V1: &[u8] = b"router-ab-protocol/local-dev-output/v1";
const LOCAL_DEV_MPC_PROOF_RNG_LABEL_V1: &[u8] = b"mpc-proof-rng";
const LOCAL_DEV_ROUTER_REQUEST_DIGEST_LABEL_V1: &[u8] =
    b"router-ab-protocol/local-router-request-digest/v1";
const LOCAL_DEV_ROOT_SHARE_EPOCH_V1: &str = "epoch-1";
const ROUTER_FORBIDDEN_KEYS: &[&str] = &[
    "SIGNER_A_ENVELOPE_AEAD_KEY",
    "SIGNER_B_ENVELOPE_AEAD_KEY",
    "SIGNING_ROOT_SHARE_A_KEK",
    "SIGNING_ROOT_SHARE_B_KEK",
    "RELAYER_OUTPUT_AEAD_KEY",
    "RELAYER_OUTPUT_STORAGE",
];
const SIGNER_A_RELAYER_REQUIRED_KEYS: &[&str] = &[
    "SIGNER_A_ENVELOPE_AEAD_KEY",
    "SIGNING_ROOT_SHARE_A_KEK",
    "RELAYER_OUTPUT_STORAGE",
];
const SIGNER_A_RELAYER_FORBIDDEN_KEYS: &[&str] =
    &["SIGNER_B_ENVELOPE_AEAD_KEY", "SIGNING_ROOT_SHARE_B_KEK"];
const SIGNER_B_REQUIRED_KEYS: &[&str] = &["SIGNER_B_ENVELOPE_AEAD_KEY", "SIGNING_ROOT_SHARE_B_KEK"];
const SIGNER_B_FORBIDDEN_KEYS: &[&str] = &[
    "SIGNER_A_ENVELOPE_AEAD_KEY",
    "SIGNING_ROOT_SHARE_A_KEK",
    "RELAYER_OUTPUT_AEAD_KEY",
    "RELAYER_OUTPUT_STORAGE",
];

/// Local simulation service role.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalServiceRoleV1 {
    /// Public Router endpoint.
    Router,
    /// Signer A plus initial relayer role.
    SignerARelayer,
    /// Signer B private endpoint.
    SignerB,
}

impl LocalServiceRoleV1 {
    /// Returns the stable role label.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Router => "router",
            Self::SignerARelayer => "signer_a_relayer",
            Self::SignerB => "signer_b",
        }
    }
}

/// Public Router entrypoint for local boundary simulation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalRouterEndpointV1 {
    /// Public URL clients use in local simulation.
    pub public_url: String,
    /// Private Signer A/Relayer URL.
    pub signer_a_relayer_url: String,
    /// Private Signer B URL.
    pub signer_b_url: String,
}

impl LocalRouterEndpointV1 {
    /// Creates a validated local Router entrypoint.
    pub fn new(
        public_url: impl Into<String>,
        signer_a_relayer_url: impl Into<String>,
        signer_b_url: impl Into<String>,
    ) -> RouterAbProtocolResult<Self> {
        let endpoint = Self {
            public_url: public_url.into(),
            signer_a_relayer_url: signer_a_relayer_url.into(),
            signer_b_url: signer_b_url.into(),
        };
        endpoint.validate()?;
        Ok(endpoint)
    }

    /// Validates required endpoint fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("public_url", &self.public_url)?;
        require_non_empty("signer_a_relayer_url", &self.signer_a_relayer_url)?;
        require_non_empty("signer_b_url", &self.signer_b_url)
    }
}

/// Signer A plus relayer entrypoint for local boundary simulation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalSignerARelayerEndpointV1 {
    /// Private Signer A/Relayer URL.
    pub private_url: String,
    /// Private Signer B URL used for A/B coordination.
    pub signer_b_url: String,
    /// Local storage binding name for relayer output activation.
    pub relayer_output_storage: String,
}

impl LocalSignerARelayerEndpointV1 {
    /// Creates a validated local Signer A/Relayer entrypoint.
    pub fn new(
        private_url: impl Into<String>,
        signer_b_url: impl Into<String>,
        relayer_output_storage: impl Into<String>,
    ) -> RouterAbProtocolResult<Self> {
        let endpoint = Self {
            private_url: private_url.into(),
            signer_b_url: signer_b_url.into(),
            relayer_output_storage: relayer_output_storage.into(),
        };
        endpoint.validate()?;
        Ok(endpoint)
    }

    /// Validates required endpoint fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("private_url", &self.private_url)?;
        require_non_empty("signer_b_url", &self.signer_b_url)?;
        require_non_empty("relayer_output_storage", &self.relayer_output_storage)
    }
}

/// Signer B entrypoint for local boundary simulation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalSignerBEndpointV1 {
    /// Private Signer B URL.
    pub private_url: String,
    /// Private Signer A/Relayer URL used for A/B coordination.
    pub signer_a_relayer_url: String,
}

impl LocalSignerBEndpointV1 {
    /// Creates a validated local Signer B entrypoint.
    pub fn new(
        private_url: impl Into<String>,
        signer_a_relayer_url: impl Into<String>,
    ) -> RouterAbProtocolResult<Self> {
        let endpoint = Self {
            private_url: private_url.into(),
            signer_a_relayer_url: signer_a_relayer_url.into(),
        };
        endpoint.validate()?;
        Ok(endpoint)
    }

    /// Validates required endpoint fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("private_url", &self.private_url)?;
        require_non_empty("signer_a_relayer_url", &self.signer_a_relayer_url)
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
    /// Signer A plus relayer endpoint.
    SignerARelayer {
        /// Signer A/Relayer endpoint data.
        endpoint: LocalSignerARelayerEndpointV1,
    },
    /// Signer B endpoint.
    SignerB {
        /// Signer B endpoint data.
        endpoint: LocalSignerBEndpointV1,
    },
}

impl LocalServiceEndpointV1 {
    /// Creates a local Router service descriptor.
    pub fn router(endpoint: LocalRouterEndpointV1) -> RouterAbProtocolResult<Self> {
        endpoint.validate()?;
        Ok(Self::Router { endpoint })
    }

    /// Creates a local Signer A/Relayer service descriptor.
    pub fn signer_a_relayer(
        endpoint: LocalSignerARelayerEndpointV1,
    ) -> RouterAbProtocolResult<Self> {
        endpoint.validate()?;
        Ok(Self::SignerARelayer { endpoint })
    }

    /// Creates a local Signer B service descriptor.
    pub fn signer_b(endpoint: LocalSignerBEndpointV1) -> RouterAbProtocolResult<Self> {
        endpoint.validate()?;
        Ok(Self::SignerB { endpoint })
    }

    /// Returns the service role.
    pub fn role(&self) -> LocalServiceRoleV1 {
        match self {
            Self::Router { .. } => LocalServiceRoleV1::Router,
            Self::SignerARelayer { .. } => LocalServiceRoleV1::SignerARelayer,
            Self::SignerB { .. } => LocalServiceRoleV1::SignerB,
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
        LocalServiceRoleV1::SignerARelayer => {
            require_keys(role, keys, SIGNER_A_RELAYER_REQUIRED_KEYS)?;
            reject_forbidden_keys(role, keys, SIGNER_A_RELAYER_FORBIDDEN_KEYS)?;
        }
        LocalServiceRoleV1::SignerB => {
            require_keys(role, keys, SIGNER_B_REQUIRED_KEYS)?;
            reject_forbidden_keys(role, keys, SIGNER_B_FORBIDDEN_KEYS)?;
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
    pub signer_a_share: LocalSealedRootShareRecordV1,
    /// Signer B sealed-share row.
    pub signer_b_share: LocalSealedRootShareRecordV1,
}

impl LocalPersistenceSeedV1 {
    /// Creates a validated local persistence seed.
    pub fn new(
        root_metadata: LocalSigningRootMetadataV1,
        signer_a_share: LocalSealedRootShareRecordV1,
        signer_b_share: LocalSealedRootShareRecordV1,
    ) -> RouterAbProtocolResult<Self> {
        let seed = Self {
            root_metadata,
            signer_a_share,
            signer_b_share,
        };
        seed.validate()?;
        Ok(seed)
    }

    /// Validates that sealed-share rows match root metadata and v1 A/B roles.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.root_metadata.validate()?;
        self.signer_a_share.validate()?;
        self.signer_b_share.validate()?;
        require_seed_share(&self.root_metadata, &self.signer_a_share, Role::SignerA)?;
        require_seed_share(&self.root_metadata, &self.signer_b_share, Role::SignerB)?;
        if self.signer_a_share.signer.signer_id == self.signer_b_share.signer.signer_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidSignerIdentity,
                "local persistence seed requires distinct signer ids",
            ));
        }
        Ok(())
    }
}

/// SQL dialect for local persistence seed plans.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalPersistenceSqlDialectV1 {
    /// PostgreSQL parameter placeholders.
    Postgres,
    /// SQLite parameter placeholders.
    Sqlite,
}

impl LocalPersistenceSqlDialectV1 {
    /// Returns the stable dialect label.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Postgres => "postgres",
            Self::Sqlite => "sqlite",
        }
    }

    fn placeholder(self, index: usize) -> String {
        debug_assert!(index > 0);
        match self {
            Self::Postgres => format!("${index}"),
            Self::Sqlite => format!("?{index}"),
        }
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
    /// SQL dialect used by the statements.
    pub dialect: LocalPersistenceSqlDialectV1,
    /// Ordered SQL statements to execute.
    pub statements: Vec<LocalPersistenceSqlStatementV1>,
}

impl LocalPersistenceSqlSeedPlanV1 {
    /// Creates a validated SQL seed plan.
    pub fn new(
        dialect: LocalPersistenceSqlDialectV1,
        statements: Vec<LocalPersistenceSqlStatementV1>,
    ) -> RouterAbProtocolResult<Self> {
        let plan = Self {
            dialect,
            statements,
        };
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
    /// SQL dialect used for execution.
    pub dialect: LocalPersistenceSqlDialectV1,
    /// Number of statements executed.
    pub executed_statement_count: u32,
}

impl LocalPersistenceSqlExecutionReceiptV1 {
    /// Creates a validated SQL seed execution receipt.
    pub fn new(
        dialect: LocalPersistenceSqlDialectV1,
        executed_statement_count: u32,
    ) -> RouterAbProtocolResult<Self> {
        if executed_statement_count == 0 {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "local persistence SQL execution receipt requires executed statements",
            ));
        }
        Ok(Self {
            dialect,
            executed_statement_count,
        })
    }
}

/// Adapter hook for executing local SQL seed statements.
pub trait LocalPersistenceSqlSeedExecutorV1 {
    /// Executes one validated seed statement with its bound values.
    fn execute_local_persistence_sql_statement_v1(
        &mut self,
        dialect: LocalPersistenceSqlDialectV1,
        statement_index: u32,
        statement: &LocalPersistenceSqlStatementV1,
    ) -> RouterAbProtocolResult<()>;
}

/// Builds parameterized SQL for local signing-root metadata and sealed-share seeds.
pub fn local_persistence_seed_sql_plan_v1(
    seed: &LocalPersistenceSeedV1,
    dialect: LocalPersistenceSqlDialectV1,
) -> RouterAbProtocolResult<LocalPersistenceSqlSeedPlanV1> {
    seed.validate()?;
    LocalPersistenceSqlSeedPlanV1::new(
        dialect,
        vec![
            local_signing_root_metadata_sql_statement(&seed.root_metadata, dialect)?,
            local_sealed_root_share_sql_statement(&seed.signer_a_share, dialect)?,
            local_sealed_root_share_sql_statement(&seed.signer_b_share, dialect)?,
        ],
    )
}

/// Executes a validated local persistence SQL seed plan through an adapter.
pub fn execute_local_persistence_sql_seed_plan_v1(
    plan: &LocalPersistenceSqlSeedPlanV1,
    executor: &mut impl LocalPersistenceSqlSeedExecutorV1,
) -> RouterAbProtocolResult<LocalPersistenceSqlExecutionReceiptV1> {
    plan.validate()?;
    for (index, statement) in plan.statements.iter().enumerate() {
        statement.validate()?;
        executor.execute_local_persistence_sql_statement_v1(
            plan.dialect,
            index as u32,
            statement,
        )?;
    }
    LocalPersistenceSqlExecutionReceiptV1::new(plan.dialect, plan.statements.len() as u32)
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
        signer_a_request: WireMessageV1,
        signer_b_request: WireMessageV1,
    ) -> RouterAbProtocolResult<LocalRouterDispatchV1> {
        let to_signer_a = LocalTransportEnvelopeV1::new(
            LocalTransportRouteV1::RouterToSignerA,
            signer_a_request,
        )?;
        let to_signer_b = LocalTransportEnvelopeV1::new(
            LocalTransportRouteV1::RouterToSignerB,
            signer_b_request,
        )?;
        require_matching_transcripts(&to_signer_a.message, &to_signer_b.message)?;
        Ok(LocalRouterDispatchV1 {
            to_signer_a,
            to_signer_b,
        })
    }

    /// Collects checked signer responses for return to the local client.
    pub fn collect_signer_responses(
        &self,
        signer_a_response: LocalTransportEnvelopeV1,
        signer_b_response: LocalTransportEnvelopeV1,
    ) -> RouterAbProtocolResult<LocalRouterCollectedResponsesV1> {
        require_route(&signer_a_response, LocalTransportRouteV1::SignerAToRouter)?;
        require_route(&signer_b_response, LocalTransportRouteV1::SignerBToRouter)?;
        require_matching_transcripts(&signer_a_response.message, &signer_b_response.message)?;
        Ok(LocalRouterCollectedResponsesV1 {
            signer_a_response,
            signer_b_response,
        })
    }
}

/// Router-dispatched local signer requests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalRouterDispatchV1 {
    /// Request routed to Signer A.
    pub to_signer_a: LocalTransportEnvelopeV1,
    /// Request routed to Signer B.
    pub to_signer_b: LocalTransportEnvelopeV1,
}

/// Router-collected local signer responses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalRouterCollectedResponsesV1 {
    /// Signer A response.
    pub signer_a_response: LocalTransportEnvelopeV1,
    /// Signer B response.
    pub signer_b_response: LocalTransportEnvelopeV1,
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
    /// Selected relayer identity.
    pub selected_relayer: RelayerIdentityV1,
}

impl LocalSignerHandlerContextV1 {
    /// Creates a validated local signer handler context.
    pub fn new(
        lifecycle_id: impl Into<String>,
        router_request_digest: PublicDigest32,
        root_share_epoch: RootShareEpoch,
        peer_signer: SignerIdentityV1,
        selected_relayer: RelayerIdentityV1,
    ) -> RouterAbProtocolResult<Self> {
        let context = Self {
            lifecycle_id: lifecycle_id.into(),
            router_request_digest,
            root_share_epoch,
            peer_signer,
            selected_relayer,
        };
        context.validate()?;
        Ok(context)
    }

    /// Validates the shared signer handler context.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("lifecycle_id", &self.lifecycle_id)?;
        require_non_empty("root_share_epoch", self.root_share_epoch.as_str())?;
        self.peer_signer.validate()?;
        self.selected_relayer.validate()
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
            CandidateId::MpcThresholdPrfV1,
            MpcPrfSuiteId::ThresholdPrfRistretto255Sha512V1,
            payload.lifecycle().primitive_request_kind,
            payload.lifecycle().lifecycle_id.clone(),
            signer_set.signer_set_id.clone(),
            SignerInputQuorumPolicyV1::All2,
            assignment.signer.role,
            assignment.signer.signer_id.clone(),
            assignment.signer.key_epoch.clone(),
            context.root_share_epoch.clone(),
            signer_set.selected_relayer.relayer_id.clone(),
            signer_set.selected_relayer.key_epoch.clone(),
            payload.transcript_digest(),
            context.router_request_digest,
            assignment.envelope.aad_digest,
            vec![
                local_mpc_prf_output_request(OpenedShareKind::XClientBase, Role::Client, "client")?,
                local_mpc_prf_output_request(
                    OpenedShareKind::XRelayerBase,
                    Role::Relayer,
                    signer_set.selected_relayer.relayer_id.clone(),
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

/// Local Signer A plus relayer handler.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalSignerARelayerServiceV1 {
    /// Local Signer A/Relayer endpoint descriptor.
    pub endpoint: LocalSignerARelayerEndpointV1,
    /// Signer A identity.
    pub signer: SignerIdentityV1,
    /// Selected relayer identity hosted by Signer A.
    pub relayer: RelayerIdentityV1,
}

impl LocalSignerARelayerServiceV1 {
    /// Creates a local Signer A/Relayer handler.
    pub fn new(
        endpoint: LocalSignerARelayerEndpointV1,
        signer: SignerIdentityV1,
        relayer: RelayerIdentityV1,
    ) -> RouterAbProtocolResult<Self> {
        endpoint.validate()?;
        require_signer_role(&signer, Role::SignerA)?;
        relayer.validate()?;
        Ok(Self {
            endpoint,
            signer,
            relayer,
        })
    }

    /// Handles a Router-to-Signer-A local request.
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

    /// Accepts a relayer activation message routed to Signer A's relayer role.
    pub fn accept_relayer_activation(
        &self,
        activation: LocalTransportEnvelopeV1,
    ) -> RouterAbProtocolResult<LocalRelayerActivationReceiptV1> {
        require_route(&activation, LocalTransportRouteV1::SignerBToSignerARelayer)?;
        Ok(LocalRelayerActivationReceiptV1 {
            relayer: self.relayer.clone(),
            transcript_digest: activation.message.transcript_digest,
            activation_digest: activation.message.digest(),
        })
    }
}

/// Local Signer B handler.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalSignerBServiceV1 {
    /// Local Signer B endpoint descriptor.
    pub endpoint: LocalSignerBEndpointV1,
    /// Signer B identity.
    pub signer: SignerIdentityV1,
}

impl LocalSignerBServiceV1 {
    /// Creates a local Signer B handler.
    pub fn new(
        endpoint: LocalSignerBEndpointV1,
        signer: SignerIdentityV1,
    ) -> RouterAbProtocolResult<Self> {
        endpoint.validate()?;
        require_signer_role(&signer, Role::SignerB)?;
        Ok(Self { endpoint, signer })
    }

    /// Handles a Router-to-Signer-B local request.
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

/// Receipt for relayer activation consumed by Signer A's local relayer role.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalRelayerActivationReceiptV1 {
    /// Relayer identity that accepted the activation.
    pub relayer: RelayerIdentityV1,
    /// Transcript digest of the activation message.
    pub transcript_digest: PublicDigest32,
    /// Digest of the activation wire message.
    pub activation_digest: PublicDigest32,
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
    /// Signer A/Relayer startup config.
    SignerARelayer {
        /// Signer A/Relayer handler.
        service: LocalSignerARelayerServiceV1,
        /// Signer A/Relayer env snapshot.
        env: LocalEnvSnapshotV1,
    },
    /// Signer B startup config.
    SignerB {
        /// Signer B handler.
        service: LocalSignerBServiceV1,
        /// Signer B env snapshot.
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

    /// Creates a validated Signer A/Relayer startup config.
    pub fn signer_a_relayer(
        endpoint: LocalSignerARelayerEndpointV1,
        signer: SignerIdentityV1,
        relayer: RelayerIdentityV1,
        env: LocalEnvSnapshotV1,
    ) -> RouterAbProtocolResult<Self> {
        require_env_role(&env, LocalServiceRoleV1::SignerARelayer)?;
        Ok(Self::SignerARelayer {
            service: LocalSignerARelayerServiceV1::new(endpoint, signer, relayer)?,
            env,
        })
    }

    /// Creates a validated Signer B startup config.
    pub fn signer_b(
        endpoint: LocalSignerBEndpointV1,
        signer: SignerIdentityV1,
        env: LocalEnvSnapshotV1,
    ) -> RouterAbProtocolResult<Self> {
        require_env_role(&env, LocalServiceRoleV1::SignerB)?;
        Ok(Self::SignerB {
            service: LocalSignerBServiceV1::new(endpoint, signer)?,
            env,
        })
    }

    /// Returns the startup service role.
    pub fn role(&self) -> LocalServiceRoleV1 {
        match self {
            Self::Router { .. } => LocalServiceRoleV1::Router,
            Self::SignerARelayer { .. } => LocalServiceRoleV1::SignerARelayer,
            Self::SignerB { .. } => LocalServiceRoleV1::SignerB,
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
    /// Signer A/Relayer handler.
    pub signer_a_relayer: LocalSignerARelayerServiceV1,
    /// Signer A/Relayer env snapshot.
    pub signer_a_relayer_env: LocalEnvSnapshotV1,
    /// Signer B handler.
    pub signer_b: LocalSignerBServiceV1,
    /// Signer B env snapshot.
    pub signer_b_env: LocalEnvSnapshotV1,
}

impl LocalServiceStackV1 {
    /// Creates a validated in-process service stack.
    pub fn new(
        router: LocalServiceStartupV1,
        signer_a_relayer: LocalServiceStartupV1,
        signer_b: LocalServiceStartupV1,
    ) -> RouterAbProtocolResult<Self> {
        let (router, router_env) = require_router_startup(router)?;
        let (signer_a_relayer, signer_a_relayer_env) =
            require_signer_a_relayer_startup(signer_a_relayer)?;
        let (signer_b, signer_b_env) = require_signer_b_startup(signer_b)?;
        Ok(Self {
            router,
            router_env,
            signer_a_relayer,
            signer_a_relayer_env,
            signer_b,
            signer_b_env,
        })
    }

    /// Runs the deterministic in-process local derivation ceremony.
    pub fn run_deterministic_ceremony(
        &self,
        lifecycle_id: impl Into<String>,
        signer_a_request: WireMessageV1,
        signer_b_request: WireMessageV1,
    ) -> RouterAbProtocolResult<LocalInProcessCeremonyResultV1> {
        let lifecycle_id = lifecycle_id.into();
        require_non_empty("lifecycle_id", &lifecycle_id)?;
        let dispatch = self
            .router
            .dispatch_signer_requests(signer_a_request, signer_b_request)?;
        let router_request_digest = local_router_request_digest_v1(
            &lifecycle_id,
            &dispatch.to_signer_a.message,
            &dispatch.to_signer_b.message,
        );
        let root_share_epoch = local_dev_root_share_epoch_v1()?;
        let signer_a_context = LocalSignerHandlerContextV1::new(
            lifecycle_id.clone(),
            router_request_digest,
            root_share_epoch.clone(),
            self.signer_b.signer.clone(),
            self.signer_a_relayer.relayer.clone(),
        )?;
        let signer_b_context = LocalSignerHandlerContextV1::new(
            lifecycle_id.clone(),
            router_request_digest,
            root_share_epoch,
            self.signer_a_relayer.signer.clone(),
            self.signer_a_relayer.relayer.clone(),
        )?;
        let signer_a_output = self
            .signer_a_relayer
            .handle_router_request(signer_a_context, dispatch.to_signer_a.clone())?;
        let signer_b_output = self
            .signer_b
            .handle_router_request(signer_b_context, dispatch.to_signer_b.clone())?;
        let signer_a_peer_message = require_signer_a_output(signer_a_output)?;
        let signer_b_peer_message = require_signer_b_output(signer_b_output)?;
        let output_packages = local_threshold_prf_output_packages_from_peer_messages(
            &dispatch.to_signer_a.message,
            &signer_a_peer_message,
            &signer_b_peer_message,
        )?;
        let signer_a_response = local_signer_response_from_packages(
            &lifecycle_id,
            self.signer_a_relayer.signer.clone(),
            &output_packages,
        )?;
        let signer_b_response = local_signer_response_from_packages(
            &lifecycle_id,
            self.signer_b.signer.clone(),
            &output_packages,
        )?;
        let relayer_activation = local_relayer_activation_from_package(
            &lifecycle_id,
            self.signer_a_relayer.relayer.clone(),
            output_packages.relayer_output.clone(),
        )?;
        let relayer_activation_receipt = self
            .signer_a_relayer
            .accept_relayer_activation(relayer_activation.clone())?;
        let collected_responses = self
            .router
            .collect_signer_responses(signer_a_response, signer_b_response)?;
        Ok(LocalInProcessCeremonyResultV1 {
            collected_responses,
            signer_a_peer_message,
            signer_b_peer_message,
            relayer_activation,
            relayer_activation_receipt,
        })
    }

    /// Runs the deterministic local ceremony through typed local HTTP requests.
    pub fn run_deterministic_http_ceremony(
        &self,
        lifecycle_id: impl Into<String>,
        signer_a_request: LocalHttpRequestV1,
        signer_b_request: LocalHttpRequestV1,
    ) -> RouterAbProtocolResult<LocalHttpCeremonyResultV1> {
        require_http_path(&signer_a_request, LocalHttpPathV1::RouterToSignerA)?;
        require_http_path(&signer_b_request, LocalHttpPathV1::RouterToSignerB)?;
        let result = self.run_deterministic_ceremony(
            lifecycle_id,
            signer_a_request.envelope.message,
            signer_b_request.envelope.message,
        )?;
        Ok(LocalHttpCeremonyResultV1 {
            signer_a_response: LocalHttpResponseV1::ok(
                result.collected_responses.signer_a_response,
            )?,
            signer_b_response: LocalHttpResponseV1::ok(
                result.collected_responses.signer_b_response,
            )?,
            signer_a_peer_request: LocalHttpRequestV1::new(
                LocalHttpMethodV1::Post,
                LocalHttpPathV1::SignerAToSignerB,
                result.signer_a_peer_message,
            )?,
            signer_b_peer_request: LocalHttpRequestV1::new(
                LocalHttpMethodV1::Post,
                LocalHttpPathV1::SignerBToSignerA,
                result.signer_b_peer_message,
            )?,
            relayer_activation_request: LocalHttpRequestV1::new(
                LocalHttpMethodV1::Post,
                LocalHttpPathV1::SignerBToSignerARelayer,
                result.relayer_activation,
            )?,
            relayer_activation_receipt: result.relayer_activation_receipt,
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
            request.signer_a_request,
            request.signer_b_request,
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
            request.signer_a_request,
            request.signer_b_request,
        )
    }
}

/// Result of the deterministic in-process local ceremony.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalInProcessCeremonyResultV1 {
    /// Router-collected signer responses.
    pub collected_responses: LocalRouterCollectedResponsesV1,
    /// A-to-B coordination message.
    pub signer_a_peer_message: LocalTransportEnvelopeV1,
    /// B-to-A coordination message.
    pub signer_b_peer_message: LocalTransportEnvelopeV1,
    /// Relayer activation message routed to Signer A.
    pub relayer_activation: LocalTransportEnvelopeV1,
    /// Receipt from Signer A's relayer role.
    pub relayer_activation_receipt: LocalRelayerActivationReceiptV1,
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
    /// Signer A sends a response to Router.
    SignerAToRouter,
    /// Signer B sends a response to Router.
    SignerBToRouter,
    /// Signer A sends a peer message to Signer B.
    SignerAToSignerB,
    /// Signer B sends a peer message to Signer A.
    SignerBToSignerA,
    /// Signer B sends relayer activation material to Signer A.
    SignerBToSignerARelayer,
}

impl LocalHttpPathV1 {
    /// Returns the stable local HTTP path.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RouterToSignerA => "/local/router/signer-a",
            Self::RouterToSignerB => "/local/router/signer-b",
            Self::SignerAToRouter => "/local/signer-a/router",
            Self::SignerBToRouter => "/local/signer-b/router",
            Self::SignerAToSignerB => "/local/signer-a/signer-b",
            Self::SignerBToSignerA => "/local/signer-b/signer-a",
            Self::SignerBToSignerARelayer => "/local/signer-b/signer-a/relayer",
        }
    }

    /// Returns the required local transport route.
    pub fn expected_route(self) -> LocalTransportRouteV1 {
        match self {
            Self::RouterToSignerA => LocalTransportRouteV1::RouterToSignerA,
            Self::RouterToSignerB => LocalTransportRouteV1::RouterToSignerB,
            Self::SignerAToRouter => LocalTransportRouteV1::SignerAToRouter,
            Self::SignerBToRouter => LocalTransportRouteV1::SignerBToRouter,
            Self::SignerAToSignerB => LocalTransportRouteV1::SignerAToSignerB,
            Self::SignerBToSignerA => LocalTransportRouteV1::SignerBToSignerA,
            Self::SignerBToSignerARelayer => LocalTransportRouteV1::SignerBToSignerARelayer,
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

/// Local HTTP response status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalHttpStatusV1 {
    /// HTTP 200 OK.
    Ok,
}

impl LocalHttpStatusV1 {
    /// Returns the numeric HTTP status code.
    pub fn status_code(self) -> u16 {
        match self {
            Self::Ok => 200,
        }
    }
}

/// Local HTTP response carrying a checked transport envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalHttpResponseV1 {
    /// Response status.
    pub status: LocalHttpStatusV1,
    /// Checked transport envelope response body.
    pub envelope: LocalTransportEnvelopeV1,
}

impl LocalHttpResponseV1 {
    /// Creates a 200 OK local HTTP response.
    pub fn ok(envelope: LocalTransportEnvelopeV1) -> RouterAbProtocolResult<Self> {
        envelope.validate()?;
        Ok(Self {
            status: LocalHttpStatusV1::Ok,
            envelope,
        })
    }
}

/// Result of the deterministic local ceremony over the typed HTTP boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalHttpCeremonyResultV1 {
    /// Signer A response to Router.
    pub signer_a_response: LocalHttpResponseV1,
    /// Signer B response to Router.
    pub signer_b_response: LocalHttpResponseV1,
    /// A-to-B local HTTP peer request.
    pub signer_a_peer_request: LocalHttpRequestV1,
    /// B-to-A local HTTP peer request.
    pub signer_b_peer_request: LocalHttpRequestV1,
    /// Relayer activation local HTTP request.
    pub relayer_activation_request: LocalHttpRequestV1,
    /// Receipt from Signer A's relayer role.
    pub relayer_activation_receipt: LocalRelayerActivationReceiptV1,
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
    pub signer_a_request: LocalHttpRequestV1,
    /// Local HTTP request carrying the Signer B envelope.
    pub signer_b_request: LocalHttpRequestV1,
}

impl LocalClientRouterRequestV1 {
    /// Creates a validated local client-to-Router request.
    pub fn new(
        lifecycle_id: impl Into<String>,
        request_nonce: impl Into<String>,
        expires_at_ms: u64,
        signer_a_request: LocalHttpRequestV1,
        signer_b_request: LocalHttpRequestV1,
    ) -> RouterAbProtocolResult<Self> {
        let request = Self {
            lifecycle_id: lifecycle_id.into(),
            request_nonce: request_nonce.into(),
            expires_at_ms,
            signer_a_request,
            signer_b_request,
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
        require_http_path(&self.signer_a_request, LocalHttpPathV1::RouterToSignerA)?;
        require_http_path(&self.signer_b_request, LocalHttpPathV1::RouterToSignerB)?;
        require_matching_transcripts(
            &self.signer_a_request.envelope.message,
            &self.signer_b_request.envelope.message,
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
    /// Signer A returns a signer response to Router.
    SignerAToRouter,
    /// Signer B returns a signer response to Router.
    SignerBToRouter,
    /// Signer A sends an A/B protocol message to Signer B.
    SignerAToSignerB,
    /// Signer B sends an A/B protocol message to Signer A.
    SignerBToSignerA,
    /// Signer B delivers relayer activation material to Signer A's relayer role.
    SignerBToSignerARelayer,
}

impl LocalTransportRouteV1 {
    /// Returns the source local service role.
    pub fn source(self) -> LocalServiceRoleV1 {
        match self {
            Self::RouterToSignerA | Self::RouterToSignerB => LocalServiceRoleV1::Router,
            Self::SignerAToRouter | Self::SignerAToSignerB => LocalServiceRoleV1::SignerARelayer,
            Self::SignerBToRouter | Self::SignerBToSignerA | Self::SignerBToSignerARelayer => {
                LocalServiceRoleV1::SignerB
            }
        }
    }

    /// Returns the destination local service role.
    pub fn destination(self) -> LocalServiceRoleV1 {
        match self {
            Self::RouterToSignerA | Self::SignerBToSignerA | Self::SignerBToSignerARelayer => {
                LocalServiceRoleV1::SignerARelayer
            }
            Self::RouterToSignerB | Self::SignerAToSignerB => LocalServiceRoleV1::SignerB,
            Self::SignerAToRouter | Self::SignerBToRouter => LocalServiceRoleV1::Router,
        }
    }

    /// Returns the required canonical wire-message kind for the route.
    pub fn expected_wire_kind(self) -> WireMessageKindV1 {
        match self {
            Self::RouterToSignerA => WireMessageKindV1::RouterToSignerA,
            Self::RouterToSignerB => WireMessageKindV1::RouterToSignerB,
            Self::SignerAToRouter | Self::SignerBToRouter => WireMessageKindV1::SignerResponse,
            Self::SignerAToSignerB => WireMessageKindV1::SignerAToSignerB,
            Self::SignerBToSignerA => WireMessageKindV1::SignerBToSignerA,
            Self::SignerBToSignerARelayer => WireMessageKindV1::RelayerActivation,
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
    signer_a_request: &WireMessageV1,
    signer_b_request: &WireMessageV1,
) -> PublicDigest32 {
    let mut hasher = Sha256::new();
    push_hash_field(&mut hasher, LOCAL_DEV_ROUTER_REQUEST_DIGEST_LABEL_V1);
    push_hash_field(&mut hasher, lifecycle_id.as_bytes());
    push_hash_field(&mut hasher, signer_a_request.digest().as_bytes());
    push_hash_field(&mut hasher, signer_b_request.digest().as_bytes());
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
    dialect: LocalPersistenceSqlDialectV1,
) -> RouterAbProtocolResult<LocalPersistenceSqlStatementV1> {
    metadata.validate()?;
    let placeholders = sql_placeholders(dialect, 4);
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
    dialect: LocalPersistenceSqlDialectV1,
) -> RouterAbProtocolResult<LocalPersistenceSqlStatementV1> {
    share.validate()?;
    let placeholders = sql_placeholders(dialect, 8);
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

fn sql_placeholders(dialect: LocalPersistenceSqlDialectV1, count: usize) -> Vec<String> {
    (1..=count)
        .map(|index| dialect.placeholder(index))
        .collect()
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

fn local_signer_response_from_packages(
    lifecycle_id: &str,
    signer: SignerIdentityV1,
    packages: &MpcPrfOutputPackagesV1,
) -> RouterAbProtocolResult<LocalTransportEnvelopeV1> {
    let route = match signer.role {
        Role::SignerA => LocalTransportRouteV1::SignerAToRouter,
        Role::SignerB => LocalTransportRouteV1::SignerBToRouter,
        _ => {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidRole,
                "local threshold signer response requires a signer role",
            ));
        }
    };
    let message =
        signer_response_wire_message_from_mpc_prf_packages_v1(lifecycle_id, signer, packages)?;
    LocalTransportEnvelopeV1::new(route, message)
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
    let peer_payload = sign_ab_derivation_proof_batch_peer_payload_v1(
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

fn local_threshold_prf_output_packages_from_peer_messages(
    signer_a_request: &WireMessageV1,
    signer_a_peer_message: &LocalTransportEnvelopeV1,
    signer_b_peer_message: &LocalTransportEnvelopeV1,
) -> RouterAbProtocolResult<MpcPrfOutputPackagesV1> {
    let router_payload = decode_router_to_signer_payload_v1(signer_a_request.payload.as_bytes())?;
    if router_payload.transcript_digest() != signer_a_request.transcript_digest {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "local threshold output combine payload transcript does not match wire message",
        ));
    }
    let proof_batch_a = local_decode_peer_proof_batch(
        signer_a_peer_message,
        LocalTransportRouteV1::SignerAToSignerB,
    )?;
    let proof_batch_b = local_decode_peer_proof_batch(
        signer_b_peer_message,
        LocalTransportRouteV1::SignerBToSignerA,
    )?;
    if proof_batch_a.transcript_digest != signer_a_request.transcript_digest
        || proof_batch_b.transcript_digest != signer_a_request.transcript_digest
    {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "local threshold output combine proof transcript mismatch",
        ));
    }
    if proof_batch_a.root_share_epoch != proof_batch_b.root_share_epoch {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "local threshold output combine root-share epoch mismatch",
        ));
    }
    let mut encryptor = LocalDeterministicRecipientOutputEncryptorV1;
    combine_mpc_prf_output_packages_from_ab_proof_batches_v1(
        &router_payload,
        proof_batch_a,
        proof_batch_b,
        &mut encryptor,
    )
}

fn local_decode_peer_proof_batch(
    envelope: &LocalTransportEnvelopeV1,
    expected_route: LocalTransportRouteV1,
) -> RouterAbProtocolResult<AbDerivationProofBatchPayloadV1> {
    require_route(envelope, expected_route)?;
    let peer_payload = decode_ab_peer_message_payload_v1(envelope.message.payload.as_bytes())?;
    if peer_payload.transcript_digest != envelope.message.transcript_digest {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "local A/B proof-batch peer payload transcript does not match wire message",
        ));
    }
    decode_and_validate_ab_derivation_proof_batch_peer_payload_v1(&peer_payload)
}

struct LocalDeterministicRecipientOutputEncryptorV1;

impl RecipientOutputEncryptorV1 for LocalDeterministicRecipientOutputEncryptorV1 {
    fn encrypt_recipient_output_v1(
        &mut self,
        request: RecipientOutputEncryptionRequestV1<'_>,
    ) -> RouterAbProtocolResult<RecipientOutputCiphertextV1> {
        request.validate()?;
        let label = mpc_prf_output_label_v1(request.recipient_role(), request.opened_share_kind())?;
        let material = request.plaintext();
        let mut material_digest_hasher = Sha256::new();
        push_hash_field(
            &mut material_digest_hasher,
            THRESHOLD_PRF_OUTPUT_PACKAGE_LABEL_V1,
        );
        push_hash_field(&mut material_digest_hasher, b"ciphertext");
        push_hash_field(&mut material_digest_hasher, label);
        push_hash_field(&mut material_digest_hasher, material.as_bytes());
        let material_digest: [u8; 32] = material_digest_hasher.finalize().into();

        let mut nonce_hasher = Sha256::new();
        push_hash_field(&mut nonce_hasher, THRESHOLD_PRF_OUTPUT_PACKAGE_LABEL_V1);
        push_hash_field(&mut nonce_hasher, b"nonce");
        push_hash_field(&mut nonce_hasher, label);
        push_hash_field(&mut nonce_hasher, request.transcript_digest().as_bytes());
        push_hash_field(&mut nonce_hasher, request.package_commitment().as_bytes());
        push_hash_field(&mut nonce_hasher, request.recipient_identity().as_bytes());
        push_hash_field(
            &mut nonce_hasher,
            request.recipient_encryption_key().as_bytes(),
        );
        let nonce_digest: [u8; 32] = nonce_hasher.finalize().into();
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&nonce_digest[..12]);

        let mut ciphertext_and_tag = Vec::new();
        push_len32(
            &mut ciphertext_and_tag,
            THRESHOLD_PRF_OUTPUT_PACKAGE_LABEL_V1,
        );
        push_len32(&mut ciphertext_and_tag, label);
        push_len32(
            &mut ciphertext_and_tag,
            request.recipient_identity().as_bytes(),
        );
        push_len32(
            &mut ciphertext_and_tag,
            request.recipient_encryption_key().as_bytes(),
        );
        push_len32(
            &mut ciphertext_and_tag,
            request.package_commitment().as_bytes(),
        );
        push_len32(&mut ciphertext_and_tag, &material_digest);

        RecipientOutputCiphertextV1::new(
            RecipientOutputEncryptionAlgorithmV1::LocalDeterministicSha256V1,
            request.recipient_role(),
            request.opened_share_kind(),
            request.recipient_identity(),
            request.recipient_encryption_key(),
            request.transcript_digest(),
            request.package_commitment(),
            nonce,
            EncryptedPayloadV1::new(ciphertext_and_tag)?,
        )
    }
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
        Role::SignerA => {
            SignerAEngine::new(()).evaluate_mpc_prf_output_batch(input, &mut proof_rng)
        }
        Role::SignerB => {
            SignerBEngine::new(()).evaluate_mpc_prf_output_batch(input, &mut proof_rng)
        }
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
        Role::SignerA => (1u8, 11u8),
        Role::SignerB => (3u8, 29u8),
        _ => {
            return Err(RouterAbDerivationError::new(
                crate::derivation::RouterAbDerivationErrorCode::SignerIdentityMismatch,
                "local MPC PRF dev share requires signer role",
            ));
        }
    };
    let mut bytes = vec![0u8; 33];
    bytes[0] = share_id;
    bytes[1] = scalar_byte;
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

fn local_relayer_activation_from_package(
    lifecycle_id: &str,
    relayer: RelayerIdentityV1,
    relayer_output: RelayerOutputPackageV1,
) -> RouterAbProtocolResult<LocalTransportEnvelopeV1> {
    let transcript_digest = relayer_output.transcript_digest();
    let payload =
        RelayerActivationPayloadV1::new(lifecycle_id, relayer, transcript_digest, relayer_output)?;
    let message = WireMessageV1::new(
        WireMessageKindV1::RelayerActivation,
        transcript_digest,
        CanonicalWireBytesV1::new(payload.canonical_bytes())?,
    )?;
    LocalTransportEnvelopeV1::new(LocalTransportRouteV1::SignerBToSignerARelayer, message)
}

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

fn require_signer_a_relayer_startup(
    startup: LocalServiceStartupV1,
) -> RouterAbProtocolResult<(LocalSignerARelayerServiceV1, LocalEnvSnapshotV1)> {
    match startup {
        LocalServiceStartupV1::SignerARelayer { service, env } => Ok((service, env)),
        other => Err(invalid_startup_branch(
            LocalServiceRoleV1::SignerARelayer,
            other.role(),
        )),
    }
}

fn require_signer_b_startup(
    startup: LocalServiceStartupV1,
) -> RouterAbProtocolResult<(LocalSignerBServiceV1, LocalEnvSnapshotV1)> {
    match startup {
        LocalServiceStartupV1::SignerB { service, env } => Ok((service, env)),
        other => Err(invalid_startup_branch(
            LocalServiceRoleV1::SignerB,
            other.role(),
        )),
    }
}

fn require_signer_a_output(
    output: LocalSignerHandlerOutputV1,
) -> RouterAbProtocolResult<LocalTransportEnvelopeV1> {
    match output {
        LocalSignerHandlerOutputV1::SignerA { peer_message } => Ok(peer_message),
        other => Err(invalid_signer_output_branch(
            LocalServiceRoleV1::SignerARelayer,
            other,
        )),
    }
}

fn require_signer_b_output(
    output: LocalSignerHandlerOutputV1,
) -> RouterAbProtocolResult<LocalTransportEnvelopeV1> {
    match output {
        LocalSignerHandlerOutputV1::SignerB { peer_message } => Ok(peer_message),
        other => Err(invalid_signer_output_branch(
            LocalServiceRoleV1::SignerB,
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

fn push_len32(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn push_hash_field(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u32).to_be_bytes());
    hasher.update(bytes);
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
