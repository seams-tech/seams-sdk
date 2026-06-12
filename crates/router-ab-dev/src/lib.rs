#![forbid(unsafe_code)]
//! Local development adapters for Router/A/B signing.
//!
//! This crate may use local database drivers and filesystem-facing binaries.
//! The protocol crate remains transport-neutral and wasm-safe by default.

use router_ab_core::{
    execute_local_persistence_sql_seed_plan_v1, local_persistence_seed_sql_plan_v1,
    LocalPersistenceSeedV1, LocalPersistenceSqlDialectV1, LocalPersistenceSqlExecutionReceiptV1,
    LocalPersistenceSqlSeedExecutorV1, LocalPersistenceSqlStatementV1, LocalPersistenceSqlValueV1,
    LocalSealedRootShareRecordV1, LocalSigningRootMetadataV1, RouterAbProtocolError,
    RouterAbProtocolErrorCode, RouterAbProtocolResult, SignerIdentityV1, SigningRootShareStore,
};
use router_ab_core::{PublicDigest32, Role, RootShareEpoch};
use rusqlite::{params, params_from_iter, types::Value, Connection};
use serde::Serialize;

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
