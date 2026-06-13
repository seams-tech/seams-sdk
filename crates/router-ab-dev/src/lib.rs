#![forbid(unsafe_code)]
//! Local development adapters for Router/A/B signing.
//!
//! This crate may use local database drivers and filesystem-facing binaries.
//! The protocol crate remains transport-neutral and wasm-safe by default.

use curve25519_dalek::scalar::Scalar;
use ed25519_hss::fixtures::{committed_fixture_corpus, FExpandFixture};
use ed25519_hss::shared::{
    add_le_bytes_mod_2_256, eval_f_expand, public_key_from_base_shares, FExpandOutput,
};
use router_ab_core::{
    execute_local_persistence_sql_seed_plan_v1, local_persistence_seed_sql_plan_v1,
    router_transcript_digest_v1, CandidateId, CorrectnessLevel, EncryptedPayloadV1,
    ExpensiveWorkKindV1, LifecycleScopeV1, LocalDeriverAEndpointV1, LocalDeriverBEndpointV1,
    LocalEnvSnapshotV1, LocalInProcessCeremonyResultV1, LocalPersistenceSeedV1,
    LocalPersistenceSqlDialectV1, LocalPersistenceSqlExecutionReceiptV1,
    LocalPersistenceSqlSeedExecutorV1, LocalPersistenceSqlStatementV1, LocalPersistenceSqlValueV1,
    LocalRouterEndpointV1, LocalSealedRootShareRecordV1, LocalServiceRoleV1, LocalServiceStackV1,
    LocalServiceStartupV1, LocalSigningRootMetadataV1, LocalSigningWorkerEndpointV1,
    PublicRouterRequestV1, RelayerIdentityV1, RoleEncryptedEnvelopeV1, RouterAbProtocolError,
    RouterAbProtocolErrorCode, RouterAbProtocolResult, RouterTranscriptMetadataV1,
    SignerIdentityV1, SignerSetV1, SigningRootShareStore,
};
use router_ab_core::{OpenedShareKind, PublicDigest32, Role, RootShareEpoch};
use rusqlite::{params, params_from_iter, types::Value, Connection};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fmt;

const LOCAL_ED25519_HSS_SPLIT_RELAYER_LABEL_V1: &[u8] =
    b"router-ab-dev/ed25519-hss/split-relayer/v1";
const LOCAL_ED25519_HSS_DEFAULT_SPLIT_EPOCH_V1: &str = "split-epoch-1";

/// Summary read back from local SQLite after seeding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LocalSqliteSeedSummaryV1 {
    /// Number of signing-root metadata rows.
    pub signing_root_count: u32,
    /// Number of sealed root-share rows.
    pub sealed_share_count: u32,
    /// Signer roles present in sealed-share storage.
    pub signer_roles: Vec<String>,
}

/// Successful signer startup check against local SQLite share storage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LocalSqliteSignerStartupCheckV1 {
    /// Signer set that owns the checked root share.
    pub signer_set_id: String,
    /// Signer role checked at startup.
    pub role: Role,
    /// Root-share epoch checked at startup.
    pub root_share_epoch: RootShareEpoch,
    /// Signer id stored with the sealed share.
    pub signer_id: String,
    /// Signer key epoch stored with the sealed share.
    pub signer_key_epoch: String,
    /// Storage key for the sealed share blob.
    pub sealed_share_storage_key: String,
}

/// Public commitment to one role's local HSS relayer-input shares.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LocalEd25519HssSplitRelayerRoleCommitmentV1 {
    /// Deriver role that owns this split input share.
    pub role: Role,
    /// SHA-256 commitment to this role's `y_relayer` share.
    pub y_relayer_share_commitment_hex: String,
    /// SHA-256 commitment to this role's `tau_relayer` share.
    pub tau_relayer_share_commitment_hex: String,
}

/// Public parity evidence from the local HSS split-relayer dev adapter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LocalEd25519HssSplitRelayerParityReportV1 {
    /// Committed `ed25519-hss` fixture name.
    pub fixture_name: String,
    /// Local split epoch used to derive role-specific relayer-input shares.
    pub split_epoch: String,
    /// Fixture HSS context binding.
    pub context_binding_hex: String,
    /// Public key derived from recipient-opened base shares.
    pub public_key_hex: String,
    /// Product-facing NEAR Ed25519 public key representation.
    pub near_public_key: String,
    /// Commitment to the client-side base share opened by the client role.
    pub x_client_base_commitment_hex: String,
    /// Commitment to the SigningWorker-side base share opened by the worker role.
    pub x_relayer_base_commitment_hex: String,
    /// Deriver A split relayer-input commitments.
    pub deriver_a: LocalEd25519HssSplitRelayerRoleCommitmentV1,
    /// Deriver B split relayer-input commitments.
    pub deriver_b: LocalEd25519HssSplitRelayerRoleCommitmentV1,
}

/// Public commitment to one recipient-opened HSS base share.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LocalEd25519HssRecipientBaseShareCommitmentV1 {
    /// Recipient role allowed to open this base share.
    pub recipient_role: Role,
    /// Opened share kind.
    pub opened_share_kind: OpenedShareKind,
    /// SHA-256 commitment to the recipient-opened base share.
    pub base_share_commitment_hex: String,
}

/// Recipient-scoped local HSS base share output.
#[derive(Clone, PartialEq, Eq)]
pub struct LocalEd25519HssRecipientBaseShareV1 {
    recipient_role: Role,
    opened_share_kind: OpenedShareKind,
    base_share: [u8; 32],
}

impl LocalEd25519HssRecipientBaseShareV1 {
    /// Creates a recipient-scoped local HSS base share.
    pub fn new(
        recipient_role: Role,
        opened_share_kind: OpenedShareKind,
        base_share: [u8; 32],
    ) -> RouterAbProtocolResult<Self> {
        let share = Self {
            recipient_role,
            opened_share_kind,
            base_share,
        };
        share.validate()?;
        Ok(share)
    }

    /// Validates the recipient/output-kind binding.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        match (self.recipient_role, self.opened_share_kind) {
            (Role::Client, OpenedShareKind::XClientBase)
            | (Role::Relayer, OpenedShareKind::XRelayerBase) => Ok(()),
            _ => Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "local HSS recipient base share has invalid recipient binding",
            )),
        }
    }

    /// Returns the recipient role.
    pub fn recipient_role(&self) -> Role {
        self.recipient_role
    }

    /// Returns the opened share kind.
    pub fn opened_share_kind(&self) -> OpenedShareKind {
        self.opened_share_kind
    }

    /// Returns public commitment evidence for this recipient output.
    pub fn commitment(&self) -> LocalEd25519HssRecipientBaseShareCommitmentV1 {
        let label = match self.opened_share_kind {
            OpenedShareKind::XClientBase => b"x_client_base".as_slice(),
            OpenedShareKind::XRelayerBase => b"x_relayer_base".as_slice(),
        };
        LocalEd25519HssRecipientBaseShareCommitmentV1 {
            recipient_role: self.recipient_role,
            opened_share_kind: self.opened_share_kind,
            base_share_commitment_hex: commitment_hex_v1(label, &self.base_share),
        }
    }
}

impl fmt::Debug for LocalEd25519HssRecipientBaseShareV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalEd25519HssRecipientBaseShareV1")
            .field("recipient_role", &self.recipient_role)
            .field("opened_share_kind", &self.opened_share_kind)
            .field("base_share", &"[redacted]")
            .finish()
    }
}

/// Dev-only output of one role-scoped local HSS derivation.
#[derive(Clone, PartialEq, Eq)]
pub struct LocalEd25519HssRoleScopedDerivationOutputV1 {
    /// Committed `ed25519-hss` fixture name.
    pub fixture_name: String,
    /// Local split epoch used for Deriver A/B relayer-input shares.
    pub split_epoch: String,
    /// Client-scoped `x_client_base` output.
    pub client_output: LocalEd25519HssRecipientBaseShareV1,
    /// SigningWorker-scoped `x_relayer_base` output.
    pub signing_worker_output: LocalEd25519HssRecipientBaseShareV1,
    /// Public key derived from the recipient-opened base shares.
    pub public_key_hex: String,
    /// Product-facing NEAR Ed25519 public key representation.
    pub near_public_key: String,
}

impl fmt::Debug for LocalEd25519HssRoleScopedDerivationOutputV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalEd25519HssRoleScopedDerivationOutputV1")
            .field("fixture_name", &self.fixture_name)
            .field("split_epoch", &self.split_epoch)
            .field("client_output", &self.client_output)
            .field("signing_worker_output", &self.signing_worker_output)
            .field("public_key_hex", &self.public_key_hex)
            .field("near_public_key", &self.near_public_key)
            .finish()
    }
}

/// Combined dev harness output for core local Router/A/B and HSS parity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalRouterAbHssDevCeremonyResultV1 {
    /// Public Router request used for the core local ceremony.
    pub router_request: PublicRouterRequestV1,
    /// Result of the core local Router/Deriver/SigningWorker ceremony.
    pub core_ceremony: LocalInProcessCeremonyResultV1,
    /// HSS recipient-scoped output evidence for the same account public key.
    pub hss_derivation: LocalEd25519HssRoleScopedDerivationOutputV1,
    /// Public HSS parity report for Deriver A/B split relayer shares.
    pub hss_parity: LocalEd25519HssSplitRelayerParityReportV1,
}

/// Role-scoped local HSS relayer-input share held by one Deriver.
#[derive(Clone, PartialEq, Eq)]
pub struct LocalEd25519HssRelayerInputShareV1 {
    role: Role,
    split_epoch: String,
    y_relayer_share: [u8; 32],
    tau_relayer_share: [u8; 32],
}

impl LocalEd25519HssRelayerInputShareV1 {
    /// Creates a role-scoped relayer-input share for the local HSS dev adapter.
    pub fn new(
        role: Role,
        split_epoch: impl Into<String>,
        y_relayer_share: [u8; 32],
        tau_relayer_share: [u8; 32],
    ) -> RouterAbProtocolResult<Self> {
        let share = Self {
            role,
            split_epoch: split_epoch.into(),
            y_relayer_share,
            tau_relayer_share,
        };
        share.validate()?;
        Ok(share)
    }

    /// Validates role and scalar shape.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_sqlite_signer_role(self.role)?;
        require_non_empty("split_epoch", &self.split_epoch)?;
        canonical_scalar_v1("tau_relayer share", self.tau_relayer_share)?;
        Ok(())
    }

    /// Returns the Deriver role that owns this share.
    pub fn role(&self) -> Role {
        self.role
    }

    /// Returns the local split epoch.
    pub fn split_epoch(&self) -> &str {
        &self.split_epoch
    }

    /// Returns public commitments for this role-scoped share.
    pub fn commitment(&self) -> LocalEd25519HssSplitRelayerRoleCommitmentV1 {
        let role_label = match self.role {
            Role::SignerA => b"deriver-a".as_slice(),
            Role::SignerB => b"deriver-b".as_slice(),
            _ => b"invalid-role".as_slice(),
        };
        LocalEd25519HssSplitRelayerRoleCommitmentV1 {
            role: self.role,
            y_relayer_share_commitment_hex: commitment_hex_v1(
                &[role_label, b"/y_relayer"].concat(),
                &self.y_relayer_share,
            ),
            tau_relayer_share_commitment_hex: commitment_hex_v1(
                &[role_label, b"/tau_relayer"].concat(),
                &self.tau_relayer_share,
            ),
        }
    }
}

impl fmt::Debug for LocalEd25519HssRelayerInputShareV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalEd25519HssRelayerInputShareV1")
            .field("role", &self.role)
            .field("split_epoch", &self.split_epoch)
            .field("y_relayer_share", &"[redacted]")
            .field("tau_relayer_share", &"[redacted]")
            .finish()
    }
}

struct LocalEd25519HssSplitRelayerInputsV1 {
    deriver_a: LocalEd25519HssRelayerInputShareV1,
    deriver_b: LocalEd25519HssRelayerInputShareV1,
}

/// SQLite executor for protocol-generated local seed statements.
pub struct LocalSqliteSeedExecutorV1<'conn> {
    connection: &'conn Connection,
}

impl<'conn> LocalSqliteSeedExecutorV1<'conn> {
    /// Creates a SQLite seed executor for an existing connection.
    pub fn new(connection: &'conn Connection) -> Self {
        Self { connection }
    }
}

impl LocalPersistenceSqlSeedExecutorV1 for LocalSqliteSeedExecutorV1<'_> {
    fn execute_local_persistence_sql_statement_v1(
        &mut self,
        dialect: LocalPersistenceSqlDialectV1,
        _statement_index: u32,
        statement: &LocalPersistenceSqlStatementV1,
    ) -> RouterAbProtocolResult<()> {
        if dialect != LocalPersistenceSqlDialectV1::Sqlite {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "local SQLite seed executor requires sqlite dialect statements",
            ));
        }
        statement.validate()?;
        let values = statement
            .values
            .iter()
            .map(sqlite_value)
            .collect::<Vec<_>>();
        self.connection
            .execute(&statement.sql, params_from_iter(values.iter()))
            .map_err(map_sqlite_error)?;
        Ok(())
    }
}

/// SQLite-backed local signing-root share store.
pub struct LocalSqliteSigningRootShareStoreV1<'conn> {
    connection: &'conn Connection,
    signer_set_id: String,
}

impl<'conn> LocalSqliteSigningRootShareStoreV1<'conn> {
    /// Creates a local SQLite root-share store for one signer set.
    pub fn new(
        connection: &'conn Connection,
        signer_set_id: impl Into<String>,
    ) -> RouterAbProtocolResult<Self> {
        let store = Self {
            connection,
            signer_set_id: signer_set_id.into(),
        };
        require_non_empty("signer_set_id", &store.signer_set_id)?;
        Ok(store)
    }

    /// Reads the startup metadata required for a role-specific local signer.
    pub fn require_startup_share(
        &self,
        role: Role,
        root_share_epoch: &RootShareEpoch,
    ) -> RouterAbProtocolResult<LocalSqliteSignerStartupCheckV1> {
        require_sqlite_signer_role(role)?;
        let mut statement = self
            .connection
            .prepare(
                "SELECT signer_id, signer_key_epoch, sealed_share_storage_key \
                 FROM local_sealed_root_shares \
                 WHERE signer_set_id = ?1 AND signer_role = ?2 AND root_share_epoch = ?3",
            )
            .map_err(map_sqlite_error)?;
        let row = statement
            .query_row(
                params![
                    self.signer_set_id.as_str(),
                    role.as_str(),
                    root_share_epoch.as_str()
                ],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .map_err(|error| map_sqlite_missing_share(error, role, root_share_epoch))?;
        Ok(LocalSqliteSignerStartupCheckV1 {
            signer_set_id: self.signer_set_id.clone(),
            role,
            root_share_epoch: root_share_epoch.clone(),
            signer_id: row.0,
            signer_key_epoch: row.1,
            sealed_share_storage_key: row.2,
        })
    }
}

impl SigningRootShareStore for LocalSqliteSigningRootShareStoreV1<'_> {
    fn has_root_share(&self, role: Role, epoch: &RootShareEpoch) -> RouterAbProtocolResult<bool> {
        require_sqlite_signer_role(role)?;
        let count = self
            .connection
            .query_row(
                "SELECT COUNT(*) FROM local_sealed_root_shares \
                 WHERE signer_set_id = ?1 AND signer_role = ?2 AND root_share_epoch = ?3",
                params![self.signer_set_id.as_str(), role.as_str(), epoch.as_str()],
                |row| row.get::<_, i64>(0),
            )
            .map_err(map_sqlite_error)?;
        Ok(count > 0)
    }
}

/// Verifies every committed `ed25519-hss` fixture through the local split-relayer adapter.
pub fn verify_committed_ed25519_hss_split_relayer_fixtures_v1(
) -> RouterAbProtocolResult<Vec<LocalEd25519HssSplitRelayerParityReportV1>> {
    let fixtures = committed_fixture_corpus().map_err(map_hss_error)?;
    fixtures
        .iter()
        .map(|fixture| {
            verify_ed25519_hss_split_relayer_fixture_v1(
                fixture,
                LOCAL_ED25519_HSS_DEFAULT_SPLIT_EPOCH_V1,
            )
        })
        .collect()
}

/// Verifies one committed `ed25519-hss` fixture through split `y_relayer` and `tau_relayer` shares.
pub fn verify_committed_ed25519_hss_split_relayer_fixture_v1(
    fixture_name: &str,
) -> RouterAbProtocolResult<LocalEd25519HssSplitRelayerParityReportV1> {
    verify_committed_ed25519_hss_split_relayer_fixture_at_epoch_v1(
        fixture_name,
        LOCAL_ED25519_HSS_DEFAULT_SPLIT_EPOCH_V1,
    )
}

/// Verifies one committed `ed25519-hss` fixture through one local split epoch.
pub fn verify_committed_ed25519_hss_split_relayer_fixture_at_epoch_v1(
    fixture_name: &str,
    split_epoch: &str,
) -> RouterAbProtocolResult<LocalEd25519HssSplitRelayerParityReportV1> {
    require_non_empty("fixture_name", fixture_name)?;
    require_non_empty("split_epoch", split_epoch)?;
    let fixtures = committed_fixture_corpus().map_err(map_hss_error)?;
    let fixture = fixtures
        .iter()
        .find(|fixture| fixture.name == fixture_name)
        .ok_or_else(|| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                format!("unknown committed ed25519-hss fixture {fixture_name}"),
            )
        })?;
    let shares = split_ed25519_hss_relayer_inputs_v1(fixture, split_epoch)?;
    verify_committed_ed25519_hss_split_relayer_role_shares_v1(
        fixture_name,
        shares.deriver_a,
        shares.deriver_b,
    )
}

/// Derives deterministic role-scoped relayer-input shares for one committed HSS fixture.
pub fn derive_committed_ed25519_hss_split_relayer_role_shares_v1(
    fixture_name: &str,
    split_epoch: &str,
) -> RouterAbProtocolResult<(
    LocalEd25519HssRelayerInputShareV1,
    LocalEd25519HssRelayerInputShareV1,
)> {
    require_non_empty("fixture_name", fixture_name)?;
    require_non_empty("split_epoch", split_epoch)?;
    let fixtures = committed_fixture_corpus().map_err(map_hss_error)?;
    let fixture = fixtures
        .iter()
        .find(|fixture| fixture.name == fixture_name)
        .ok_or_else(|| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                format!("unknown committed ed25519-hss fixture {fixture_name}"),
            )
        })?;
    let split = split_ed25519_hss_relayer_inputs_v1(fixture, split_epoch)?;
    Ok((split.deriver_a, split.deriver_b))
}

/// Verifies one committed HSS fixture from explicit Deriver A/B role-scoped shares.
pub fn verify_committed_ed25519_hss_split_relayer_role_shares_v1(
    fixture_name: &str,
    deriver_a: LocalEd25519HssRelayerInputShareV1,
    deriver_b: LocalEd25519HssRelayerInputShareV1,
) -> RouterAbProtocolResult<LocalEd25519HssSplitRelayerParityReportV1> {
    require_non_empty("fixture_name", fixture_name)?;
    validate_ed25519_hss_role_share_pair_v1(&deriver_a, &deriver_b)?;
    let fixtures = committed_fixture_corpus().map_err(map_hss_error)?;
    let fixture = fixtures
        .iter()
        .find(|fixture| fixture.name == fixture_name)
        .ok_or_else(|| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                format!("unknown committed ed25519-hss fixture {fixture_name}"),
            )
        })?;
    verify_ed25519_hss_split_relayer_fixture_with_role_shares_v1(fixture, deriver_a, deriver_b)
}

/// Runs the dev-only role-scoped HSS derivation and returns recipient-scoped outputs.
pub fn evaluate_committed_ed25519_hss_role_scoped_derivation_v1(
    fixture_name: &str,
    deriver_a: LocalEd25519HssRelayerInputShareV1,
    deriver_b: LocalEd25519HssRelayerInputShareV1,
) -> RouterAbProtocolResult<LocalEd25519HssRoleScopedDerivationOutputV1> {
    require_non_empty("fixture_name", fixture_name)?;
    validate_ed25519_hss_role_share_pair_v1(&deriver_a, &deriver_b)?;
    let fixtures = committed_fixture_corpus().map_err(map_hss_error)?;
    let fixture = fixtures
        .iter()
        .find(|fixture| fixture.name == fixture_name)
        .ok_or_else(|| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                format!("unknown committed ed25519-hss fixture {fixture_name}"),
            )
        })?;
    let expanded = evaluate_ed25519_hss_split_relayer_fixture_with_role_shares_v1(
        fixture, &deriver_a, &deriver_b,
    )?;
    Ok(LocalEd25519HssRoleScopedDerivationOutputV1 {
        fixture_name: fixture.name.clone(),
        split_epoch: deriver_a.split_epoch().to_owned(),
        client_output: LocalEd25519HssRecipientBaseShareV1::new(
            Role::Client,
            OpenedShareKind::XClientBase,
            expanded.output.x_client_base,
        )?,
        signing_worker_output: LocalEd25519HssRecipientBaseShareV1::new(
            Role::Relayer,
            OpenedShareKind::XRelayerBase,
            expanded.output.x_relayer_base,
        )?,
        public_key_hex: hex::encode(expanded.public_key),
        near_public_key: encode_near_ed25519_public_key_v1(expanded.public_key),
    })
}

/// Runs the local Router/Deriver/SigningWorker ceremony and HSS role-scoped parity side by side.
pub fn run_example_local_router_ab_hss_dev_ceremony_v1(
    fixture_name: &str,
    split_epoch: &str,
) -> RouterAbProtocolResult<LocalRouterAbHssDevCeremonyResultV1> {
    require_non_empty("fixture_name", fixture_name)?;
    require_non_empty("split_epoch", split_epoch)?;
    let fixture = committed_ed25519_hss_fixture_v1(fixture_name)?;
    let (deriver_a, deriver_b) =
        derive_committed_ed25519_hss_split_relayer_role_shares_v1(fixture_name, split_epoch)?;
    let hss_derivation = evaluate_committed_ed25519_hss_role_scoped_derivation_v1(
        fixture_name,
        deriver_a.clone(),
        deriver_b.clone(),
    )?;
    let hss_parity = verify_committed_ed25519_hss_split_relayer_role_shares_v1(
        fixture_name,
        deriver_a,
        deriver_b,
    )?;
    let router_request = local_router_request_for_hss_fixture_v1(&fixture, &hss_derivation)?;
    let (signer_a_request, signer_b_request) = router_request.to_signer_wire_messages()?;
    let core_ceremony = local_service_stack_v1()?.run_deterministic_ceremony(
        router_request.lifecycle.lifecycle_id.clone(),
        signer_a_request,
        signer_b_request,
    )?;
    Ok(LocalRouterAbHssDevCeremonyResultV1 {
        router_request,
        core_ceremony,
        hss_derivation,
        hss_parity,
    })
}

fn verify_ed25519_hss_split_relayer_fixture_v1(
    fixture: &FExpandFixture,
    split_epoch: &str,
) -> RouterAbProtocolResult<LocalEd25519HssSplitRelayerParityReportV1> {
    let split = split_ed25519_hss_relayer_inputs_v1(fixture, split_epoch)?;
    verify_ed25519_hss_split_relayer_fixture_with_role_shares_v1(
        fixture,
        split.deriver_a,
        split.deriver_b,
    )
}

fn verify_ed25519_hss_split_relayer_fixture_with_role_shares_v1(
    fixture: &FExpandFixture,
    deriver_a: LocalEd25519HssRelayerInputShareV1,
    deriver_b: LocalEd25519HssRelayerInputShareV1,
) -> RouterAbProtocolResult<LocalEd25519HssSplitRelayerParityReportV1> {
    let expanded = evaluate_ed25519_hss_split_relayer_fixture_with_role_shares_v1(
        fixture, &deriver_a, &deriver_b,
    )?;
    let split_epoch = deriver_a.split_epoch().to_owned();
    Ok(LocalEd25519HssSplitRelayerParityReportV1 {
        fixture_name: fixture.name.clone(),
        split_epoch,
        context_binding_hex: hex::encode(fixture.output.context_binding),
        public_key_hex: hex::encode(expanded.public_key),
        near_public_key: encode_near_ed25519_public_key_v1(expanded.public_key),
        x_client_base_commitment_hex: commitment_hex_v1(
            b"x_client_base",
            &expanded.output.x_client_base,
        ),
        x_relayer_base_commitment_hex: commitment_hex_v1(
            b"x_relayer_base",
            &expanded.output.x_relayer_base,
        ),
        deriver_a: deriver_a.commitment(),
        deriver_b: deriver_b.commitment(),
    })
}

fn committed_ed25519_hss_fixture_v1(fixture_name: &str) -> RouterAbProtocolResult<FExpandFixture> {
    require_non_empty("fixture_name", fixture_name)?;
    committed_fixture_corpus()
        .map_err(map_hss_error)?
        .into_iter()
        .find(|fixture| fixture.name == fixture_name)
        .ok_or_else(|| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                format!("unknown committed ed25519-hss fixture {fixture_name}"),
            )
        })
}

struct LocalEd25519HssExpandedFixtureV1 {
    output: FExpandOutput,
    public_key: [u8; 32],
}

fn evaluate_ed25519_hss_split_relayer_fixture_with_role_shares_v1(
    fixture: &FExpandFixture,
    deriver_a: &LocalEd25519HssRelayerInputShareV1,
    deriver_b: &LocalEd25519HssRelayerInputShareV1,
) -> RouterAbProtocolResult<LocalEd25519HssExpandedFixtureV1> {
    validate_ed25519_hss_role_share_pair_v1(deriver_a, deriver_b)?;
    let y_relayer = add_le_bytes_mod_2_256(deriver_a.y_relayer_share, deriver_b.y_relayer_share);
    let tau_relayer = add_scalar_mod_l(deriver_a.tau_relayer_share, deriver_b.tau_relayer_share)?;
    if y_relayer != fixture.input.y_relayer || tau_relayer != fixture.input.tau_relayer {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "local split HSS relayer inputs failed to reconstruct fixture inputs",
        ));
    }
    let output = eval_f_expand(&ed25519_hss::shared::FExpandInput {
        context: fixture.input.context.clone(),
        y_client: fixture.input.y_client,
        y_relayer,
        tau_client: fixture.input.tau_client,
        tau_relayer,
    })
    .map_err(map_hss_error)?;
    if output != fixture.output {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "local split HSS relayer expansion did not match committed fixture output",
        ));
    }
    let public_key = public_key_from_base_shares(output.x_client_base, output.x_relayer_base)
        .map_err(map_hss_error)?;
    if public_key != fixture.output.public_key {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "local split HSS base-share public key did not match committed fixture",
        ));
    }
    Ok(LocalEd25519HssExpandedFixtureV1 { output, public_key })
}

/// Encodes a NEAR Ed25519 public key string from raw 32-byte public key material.
pub fn encode_near_ed25519_public_key_v1(public_key: [u8; 32]) -> String {
    format!("ed25519:{}", bs58::encode(public_key).into_string())
}

/// Ensures local SQLite tables used by Router/A/B seed tests exist.
pub fn ensure_local_sqlite_schema_v1(connection: &Connection) -> RouterAbProtocolResult<()> {
    connection
        .execute_batch(
            "
            PRAGMA foreign_keys = ON;

            CREATE TABLE IF NOT EXISTS local_signing_roots (
                signer_set_id TEXT NOT NULL,
                signing_root_version TEXT NOT NULL,
                root_share_epoch TEXT NOT NULL,
                account_id TEXT NOT NULL,
                PRIMARY KEY (signer_set_id, root_share_epoch)
            );

            CREATE TABLE IF NOT EXISTS local_sealed_root_shares (
                signer_set_id TEXT NOT NULL,
                signer_role TEXT NOT NULL CHECK (signer_role IN ('signer_a', 'signer_b')),
                signer_id TEXT NOT NULL,
                signer_key_epoch TEXT NOT NULL,
                root_share_epoch TEXT NOT NULL,
                sealed_share_storage_key TEXT NOT NULL,
                sealed_share_commitment_hex TEXT NOT NULL CHECK (length(sealed_share_commitment_hex) = 64),
                sealed_share_len INTEGER NOT NULL CHECK (sealed_share_len > 0),
                PRIMARY KEY (signer_set_id, signer_role, root_share_epoch),
                FOREIGN KEY (signer_set_id, root_share_epoch)
                    REFERENCES local_signing_roots (signer_set_id, root_share_epoch)
            );
            ",
        )
        .map_err(map_sqlite_error)
}

/// Seeds local SQLite with a validated Router/A/B persistence seed.
pub fn seed_local_sqlite_v1(
    connection: &Connection,
    seed: &LocalPersistenceSeedV1,
) -> RouterAbProtocolResult<LocalPersistenceSqlExecutionReceiptV1> {
    ensure_local_sqlite_schema_v1(connection)?;
    let plan = local_persistence_seed_sql_plan_v1(seed, LocalPersistenceSqlDialectV1::Sqlite)?;
    let mut executor = LocalSqliteSeedExecutorV1::new(connection);
    execute_local_persistence_sql_seed_plan_v1(&plan, &mut executor)
}

/// Reads a small verification summary from local SQLite.
pub fn read_local_sqlite_seed_summary_v1(
    connection: &Connection,
) -> RouterAbProtocolResult<LocalSqliteSeedSummaryV1> {
    let signing_root_count =
        query_u32_count(connection, "SELECT COUNT(*) FROM local_signing_roots")?;
    let sealed_share_count =
        query_u32_count(connection, "SELECT COUNT(*) FROM local_sealed_root_shares")?;
    let signer_roles = query_signer_roles(connection)?;
    Ok(LocalSqliteSeedSummaryV1 {
        signing_root_count,
        sealed_share_count,
        signer_roles,
    })
}

/// Creates the deterministic local dev persistence seed used by smoke tests.
pub fn example_local_persistence_seed_v1() -> RouterAbProtocolResult<LocalPersistenceSeedV1> {
    LocalPersistenceSeedV1::new(
        LocalSigningRootMetadataV1::new(
            "signer-set-v1",
            "signing-root-v1",
            root_epoch()?,
            "alice.testnet",
        )?,
        sealed_share_record(Role::SignerA)?,
        sealed_share_record(Role::SignerB)?,
    )
}

/// Seeds local SQLite with the deterministic dev seed.
pub fn seed_example_local_sqlite_v1(
    connection: &Connection,
) -> RouterAbProtocolResult<LocalPersistenceSqlExecutionReceiptV1> {
    seed_local_sqlite_v1(connection, &example_local_persistence_seed_v1()?)
}

/// Checks that a local signer can see its role-specific sealed root share.
pub fn require_example_local_sqlite_signer_startup_v1(
    connection: &Connection,
    role: Role,
) -> RouterAbProtocolResult<LocalSqliteSignerStartupCheckV1> {
    let seed = example_local_persistence_seed_v1()?;
    let store = LocalSqliteSigningRootShareStoreV1::new(
        connection,
        seed.root_metadata.signer_set_id.clone(),
    )?;
    store.require_startup_share(role, &seed.root_metadata.root_share_epoch)
}

fn query_u32_count(connection: &Connection, sql: &str) -> RouterAbProtocolResult<u32> {
    let count = connection
        .query_row(sql, [], |row| row.get::<_, i64>(0))
        .map_err(map_sqlite_error)?;
    u32::try_from(count).map_err(|_| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "local SQLite count did not fit u32",
        )
    })
}

fn query_signer_roles(connection: &Connection) -> RouterAbProtocolResult<Vec<String>> {
    let mut statement = connection
        .prepare("SELECT signer_role FROM local_sealed_root_shares ORDER BY signer_role")
        .map_err(map_sqlite_error)?;
    let rows = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(map_sqlite_error)?;
    let mut roles = Vec::new();
    for row in rows {
        roles.push(row.map_err(map_sqlite_error)?);
    }
    Ok(roles)
}

fn sealed_share_record(role: Role) -> RouterAbProtocolResult<LocalSealedRootShareRecordV1> {
    let (signer, storage_key, commitment_seed) = match role {
        Role::SignerA => (signer_identity(Role::SignerA)?, "sealed/share/a", 0xa1),
        Role::SignerB => (signer_identity(Role::SignerB)?, "sealed/share/b", 0xb1),
        _ => {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidRole,
                "local dev seed requires signer role",
            ));
        }
    };
    LocalSealedRootShareRecordV1::new(
        "signer-set-v1",
        signer,
        root_epoch()?,
        storage_key,
        digest(commitment_seed),
        33,
    )
}

fn local_router_request_for_hss_fixture_v1(
    fixture: &FExpandFixture,
    hss_derivation: &LocalEd25519HssRoleScopedDerivationOutputV1,
) -> RouterAbProtocolResult<PublicRouterRequestV1> {
    let account_id = fixture.input.context.account_id.clone();
    let account_public_key = hss_derivation.near_public_key.clone();
    let lifecycle = local_lifecycle_scope_v1(&account_id)?;
    let signer_set = signer_set_v1()?;
    let metadata = RouterTranscriptMetadataV1::new(
        "near-testnet",
        account_public_key.clone(),
        "local-router",
        "client",
        "x25519:local-dev-client-ephemeral-public-key",
    )?;
    let transcript_digest = router_transcript_digest_v1(
        &lifecycle,
        &signer_set,
        &metadata,
        CandidateId::MpcThresholdPrfV1,
        CorrectnessLevel::MinimumLevelC,
        root_epoch()?,
    )?;
    PublicRouterRequestV1::new(
        "request-nonce-1",
        2_000,
        lifecycle,
        CandidateId::MpcThresholdPrfV1,
        signer_set,
        metadata.network_id,
        account_public_key,
        metadata.router_id,
        metadata.client_id,
        metadata.client_ephemeral_public_key,
        transcript_digest,
        role_envelope_v1(Role::SignerA, 0xa0)?,
        role_envelope_v1(Role::SignerB, 0xb0)?,
    )
}

fn local_lifecycle_scope_v1(account_id: &str) -> RouterAbProtocolResult<LifecycleScopeV1> {
    LifecycleScopeV1::new(
        "lifecycle-1",
        ExpensiveWorkKindV1::RegistrationPrepare,
        root_epoch()?,
        account_id,
        "session-1",
        "signer-set-v1",
        "relayer-a",
    )
}

fn signer_set_v1() -> RouterAbProtocolResult<SignerSetV1> {
    SignerSetV1::v1_all2(
        "signer-set-v1",
        signer_identity(Role::SignerA)?,
        signer_identity(Role::SignerB)?,
        relayer_identity_v1()?,
    )
}

fn relayer_identity_v1() -> RouterAbProtocolResult<RelayerIdentityV1> {
    RelayerIdentityV1::new(
        "relayer-a",
        "relayer-epoch",
        "x25519:1111111111111111111111111111111111111111111111111111111111111111",
    )
}

fn role_envelope_v1(role: Role, seed: u8) -> RouterAbProtocolResult<RoleEncryptedEnvelopeV1> {
    RoleEncryptedEnvelopeV1::new(
        role,
        digest(seed),
        digest(seed.wrapping_add(1)),
        EncryptedPayloadV1::new(vec![seed, seed.wrapping_add(2)])?,
    )
}

fn local_service_stack_v1() -> RouterAbProtocolResult<LocalServiceStackV1> {
    LocalServiceStackV1::new(
        LocalServiceStartupV1::router(router_endpoint_v1()?, router_env_snapshot_v1()?)?,
        LocalServiceStartupV1::deriver_a(
            deriver_a_endpoint_v1()?,
            signer_identity(Role::SignerA)?,
            deriver_a_env_snapshot_v1()?,
        )?,
        LocalServiceStartupV1::deriver_b(
            deriver_b_endpoint_v1()?,
            signer_identity(Role::SignerB)?,
            deriver_b_env_snapshot_v1()?,
        )?,
        LocalServiceStartupV1::signing_worker(
            signing_worker_endpoint_v1()?,
            relayer_identity_v1()?,
            signing_worker_env_snapshot_v1()?,
        )?,
    )
}

fn router_endpoint_v1() -> RouterAbProtocolResult<LocalRouterEndpointV1> {
    LocalRouterEndpointV1::new(
        "http://127.0.0.1:8787",
        "http://127.0.0.1:8788",
        "http://127.0.0.1:8789",
        "http://127.0.0.1:8790",
    )
}

fn deriver_a_endpoint_v1() -> RouterAbProtocolResult<LocalDeriverAEndpointV1> {
    LocalDeriverAEndpointV1::new("http://127.0.0.1:8788", "http://127.0.0.1:8789")
}

fn deriver_b_endpoint_v1() -> RouterAbProtocolResult<LocalDeriverBEndpointV1> {
    LocalDeriverBEndpointV1::new("http://127.0.0.1:8789", "http://127.0.0.1:8788")
}

fn signing_worker_endpoint_v1() -> RouterAbProtocolResult<LocalSigningWorkerEndpointV1> {
    LocalSigningWorkerEndpointV1::new("http://127.0.0.1:8790", "local-relayer-output")
}

fn router_env_snapshot_v1() -> RouterAbProtocolResult<LocalEnvSnapshotV1> {
    LocalEnvSnapshotV1::new(
        LocalServiceRoleV1::Router,
        vec![
            "ROUTER_PUBLIC_URL".to_owned(),
            "DERIVER_A_URL".to_owned(),
            "DERIVER_B_URL".to_owned(),
            "SIGNING_WORKER_URL".to_owned(),
        ],
    )
}

fn deriver_a_env_snapshot_v1() -> RouterAbProtocolResult<LocalEnvSnapshotV1> {
    LocalEnvSnapshotV1::new(
        LocalServiceRoleV1::DeriverA,
        vec![
            "DERIVER_A_ENVELOPE_HPKE_PRIVATE_KEY".to_owned(),
            "SIGNING_ROOT_SHARE_A_KEK".to_owned(),
            "DERIVER_B_URL".to_owned(),
        ],
    )
}

fn deriver_b_env_snapshot_v1() -> RouterAbProtocolResult<LocalEnvSnapshotV1> {
    LocalEnvSnapshotV1::new(
        LocalServiceRoleV1::DeriverB,
        vec![
            "DERIVER_B_ENVELOPE_HPKE_PRIVATE_KEY".to_owned(),
            "SIGNING_ROOT_SHARE_B_KEK".to_owned(),
            "DERIVER_A_URL".to_owned(),
        ],
    )
}

fn signing_worker_env_snapshot_v1() -> RouterAbProtocolResult<LocalEnvSnapshotV1> {
    LocalEnvSnapshotV1::new(
        LocalServiceRoleV1::SigningWorker,
        vec!["RELAYER_OUTPUT_STORAGE".to_owned()],
    )
}

fn split_ed25519_hss_relayer_inputs_v1(
    fixture: &FExpandFixture,
    split_epoch: &str,
) -> RouterAbProtocolResult<LocalEd25519HssSplitRelayerInputsV1> {
    let y_relayer_a = deterministic_hss_share_v1(
        b"deriver-a/y_relayer",
        &fixture.name,
        split_epoch,
        fixture.output.context_binding,
    );
    let y_relayer_b = sub_le_bytes_mod_2_256(fixture.input.y_relayer, y_relayer_a);
    let tau_relayer_a = Scalar::from_bytes_mod_order(deterministic_hss_share_v1(
        b"deriver-a/tau_relayer",
        &fixture.name,
        split_epoch,
        fixture.output.context_binding,
    ))
    .to_bytes();
    let tau_relayer_b = sub_scalar_mod_l(fixture.input.tau_relayer, tau_relayer_a)?;
    Ok(LocalEd25519HssSplitRelayerInputsV1 {
        deriver_a: LocalEd25519HssRelayerInputShareV1::new(
            Role::SignerA,
            split_epoch,
            y_relayer_a,
            tau_relayer_a,
        )?,
        deriver_b: LocalEd25519HssRelayerInputShareV1::new(
            Role::SignerB,
            split_epoch,
            y_relayer_b,
            tau_relayer_b,
        )?,
    })
}

fn validate_ed25519_hss_role_share_pair_v1(
    deriver_a: &LocalEd25519HssRelayerInputShareV1,
    deriver_b: &LocalEd25519HssRelayerInputShareV1,
) -> RouterAbProtocolResult<()> {
    deriver_a.validate()?;
    deriver_b.validate()?;
    if deriver_a.role() != Role::SignerA || deriver_b.role() != Role::SignerB {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidRole,
            "local HSS role-scoped shares require Deriver A then Deriver B",
        ));
    }
    if deriver_a.split_epoch() != deriver_b.split_epoch() {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "local HSS role-scoped shares must use one split epoch",
        ));
    }
    Ok(())
}

fn deterministic_hss_share_v1(
    label: &[u8],
    fixture_name: &str,
    split_epoch: &str,
    context_binding: [u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    push_hash_field_v1(&mut hasher, LOCAL_ED25519_HSS_SPLIT_RELAYER_LABEL_V1);
    push_hash_field_v1(&mut hasher, label);
    push_hash_field_v1(&mut hasher, fixture_name.as_bytes());
    push_hash_field_v1(&mut hasher, split_epoch.as_bytes());
    push_hash_field_v1(&mut hasher, &context_binding);
    hasher.finalize().into()
}

fn sub_le_bytes_mod_2_256(total: [u8; 32], left: [u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut borrow = 0i16;
    for index in 0..32 {
        let difference = total[index] as i16 - left[index] as i16 - borrow;
        if difference < 0 {
            out[index] = (difference + 256) as u8;
            borrow = 1;
        } else {
            out[index] = difference as u8;
            borrow = 0;
        }
    }
    out
}

fn sub_scalar_mod_l(total: [u8; 32], left: [u8; 32]) -> RouterAbProtocolResult<[u8; 32]> {
    let total = canonical_scalar_v1("tau_relayer", total)?;
    let left = Scalar::from_bytes_mod_order(left);
    Ok((total - left).to_bytes())
}

fn add_scalar_mod_l(left: [u8; 32], right: [u8; 32]) -> RouterAbProtocolResult<[u8; 32]> {
    let left = canonical_scalar_v1("tau_relayer left share", left)?;
    let right = canonical_scalar_v1("tau_relayer right share", right)?;
    Ok((left + right).to_bytes())
}

fn canonical_scalar_v1(field: &str, bytes: [u8; 32]) -> RouterAbProtocolResult<Scalar> {
    Scalar::from_canonical_bytes(bytes)
        .into_option()
        .ok_or_else(|| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                format!("{field} must be canonical modulo ed25519 l"),
            )
        })
}

fn commitment_hex_v1(label: &[u8], material: &[u8]) -> String {
    let mut hasher = Sha256::new();
    push_hash_field_v1(&mut hasher, LOCAL_ED25519_HSS_SPLIT_RELAYER_LABEL_V1);
    push_hash_field_v1(&mut hasher, b"commitment");
    push_hash_field_v1(&mut hasher, label);
    push_hash_field_v1(&mut hasher, material);
    hex::encode(hasher.finalize())
}

fn signer_identity(role: Role) -> RouterAbProtocolResult<SignerIdentityV1> {
    match role {
        Role::SignerA => SignerIdentityV1::new(Role::SignerA, "signer-a", "epoch-a"),
        Role::SignerB => SignerIdentityV1::new(Role::SignerB, "signer-b", "epoch-b"),
        _ => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidRole,
            "local dev seed requires signer identity",
        )),
    }
}

fn root_epoch() -> RouterAbProtocolResult<RootShareEpoch> {
    RootShareEpoch::new("epoch-1").map_err(|error| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            error.to_string(),
        )
    })
}

fn require_non_empty(field: &str, value: &str) -> RouterAbProtocolResult<()> {
    if value.is_empty() {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::EmptyField,
            format!("{field} must not be empty"),
        ));
    }
    Ok(())
}

fn require_sqlite_signer_role(role: Role) -> RouterAbProtocolResult<()> {
    match role {
        Role::SignerA | Role::SignerB => Ok(()),
        _ => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidRole,
            format!(
                "local SQLite root-share store requires signer role, received {}",
                role.as_str()
            ),
        )),
    }
}

fn digest(seed: u8) -> PublicDigest32 {
    PublicDigest32::new([seed; 32])
}

fn push_hash_field_v1(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u32).to_be_bytes());
    hasher.update(bytes);
}

fn sqlite_value(value: &LocalPersistenceSqlValueV1) -> Value {
    match value {
        LocalPersistenceSqlValueV1::Text(value) => Value::Text(value.clone()),
        LocalPersistenceSqlValueV1::U32(value) => Value::Integer(i64::from(*value)),
    }
}

fn map_sqlite_error(error: rusqlite::Error) -> RouterAbProtocolError {
    RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
        format!("local SQLite seed failed: {error}"),
    )
}

fn map_hss_error(error: ed25519_hss::shared::ProtoError) -> RouterAbProtocolError {
    RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
        format!("local ed25519-hss parity failed: {error}"),
    )
}

fn map_sqlite_missing_share(
    error: rusqlite::Error,
    role: Role,
    epoch: &RootShareEpoch,
) -> RouterAbProtocolError {
    match error {
        rusqlite::Error::QueryReturnedNoRows => RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            format!(
                "local SQLite signer startup missing {} root share for epoch {}",
                role.as_str(),
                epoch.as_str()
            ),
        ),
        other => map_sqlite_error(other),
    }
}
