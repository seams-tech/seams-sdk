use router_ab_core::{Role, RootShareEpoch};
use router_ab_core::{RouterAbProtocolErrorCode, SigningRootShareStore};
use router_ab_dev::{
    ensure_local_sqlite_schema_v1, example_local_persistence_seed_v1,
    read_local_sqlite_seed_summary_v1, require_example_local_sqlite_signer_startup_v1,
    seed_example_local_sqlite_v1, LocalSqliteSigningRootShareStoreV1,
};
use rusqlite::Connection;

#[test]
fn sqlite_seed_inserts_signing_root_and_role_shares() -> Result<(), Box<dyn std::error::Error>> {
    let connection = Connection::open_in_memory()?;

    let receipt = seed_example_local_sqlite_v1(&connection)?;
    let summary = read_local_sqlite_seed_summary_v1(&connection)?;

    assert_eq!(receipt.executed_statement_count, 3);
    assert_eq!(summary.signing_root_count, 1);
    assert_eq!(summary.sealed_share_count, 2);
    assert_eq!(summary.signer_roles, vec!["signer_a", "signer_b"]);

    let account_id: String = connection.query_row(
        "SELECT account_id FROM local_signing_roots WHERE signer_set_id = 'signer-set-v1'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(account_id, "alice.testnet");

    let signer_a_storage_key: String = connection.query_row(
        "SELECT sealed_share_storage_key FROM local_sealed_root_shares WHERE signer_role = 'signer_a'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(signer_a_storage_key, "sealed/share/a");

    Ok(())
}

#[test]
fn sqlite_seed_is_idempotent() -> Result<(), Box<dyn std::error::Error>> {
    let connection = Connection::open_in_memory()?;

    seed_example_local_sqlite_v1(&connection)?;
    seed_example_local_sqlite_v1(&connection)?;
    let summary = read_local_sqlite_seed_summary_v1(&connection)?;

    assert_eq!(summary.signing_root_count, 1);
    assert_eq!(summary.sealed_share_count, 2);
    Ok(())
}

#[test]
fn sqlite_signing_root_share_store_finds_seeded_role_shares(
) -> Result<(), Box<dyn std::error::Error>> {
    let connection = Connection::open_in_memory()?;
    seed_example_local_sqlite_v1(&connection)?;
    let seed = example_local_persistence_seed_v1()?;
    let store = LocalSqliteSigningRootShareStoreV1::new(
        &connection,
        seed.root_metadata.signer_set_id.clone(),
    )?;

    assert!(store.has_root_share(Role::SignerA, &seed.root_metadata.root_share_epoch)?);
    assert!(store.has_root_share(Role::SignerB, &seed.root_metadata.root_share_epoch)?);

    let missing_epoch = RootShareEpoch::new("epoch-missing")?;
    assert!(!store.has_root_share(Role::SignerA, &missing_epoch)?);
    Ok(())
}

#[test]
fn sqlite_signer_startup_check_returns_role_metadata() -> Result<(), Box<dyn std::error::Error>> {
    let connection = Connection::open_in_memory()?;
    seed_example_local_sqlite_v1(&connection)?;

    let signer_a = require_example_local_sqlite_signer_startup_v1(&connection, Role::SignerA)?;
    let signer_b = require_example_local_sqlite_signer_startup_v1(&connection, Role::SignerB)?;

    assert_eq!(signer_a.role, Role::SignerA);
    assert_eq!(signer_a.signer_id, "signer-a");
    assert_eq!(signer_a.signer_key_epoch, "epoch-a");
    assert_eq!(signer_a.sealed_share_storage_key, "sealed/share/a");
    assert_eq!(signer_b.role, Role::SignerB);
    assert_eq!(signer_b.signer_id, "signer-b");
    assert_eq!(signer_b.sealed_share_storage_key, "sealed/share/b");
    Ok(())
}

#[test]
fn sqlite_signer_startup_check_fails_when_role_share_is_missing(
) -> Result<(), Box<dyn std::error::Error>> {
    let connection = Connection::open_in_memory()?;
    seed_example_local_sqlite_v1(&connection)?;
    connection.execute(
        "DELETE FROM local_sealed_root_shares WHERE signer_role = 'signer_b'",
        [],
    )?;

    let err = require_example_local_sqlite_signer_startup_v1(&connection, Role::SignerB)
        .expect_err("missing signer b share must fail startup");

    assert_eq!(
        err.code(),
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig
    );
    Ok(())
}

#[test]
fn sqlite_signing_root_share_store_rejects_non_signer_roles(
) -> Result<(), Box<dyn std::error::Error>> {
    let connection = Connection::open_in_memory()?;
    ensure_local_sqlite_schema_v1(&connection)?;
    let seed = example_local_persistence_seed_v1()?;
    let store = LocalSqliteSigningRootShareStoreV1::new(
        &connection,
        seed.root_metadata.signer_set_id.clone(),
    )?;

    let err = store
        .has_root_share(Role::Router, &seed.root_metadata.root_share_epoch)
        .expect_err("router role must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidRole);
    Ok(())
}
