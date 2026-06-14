use router_ab_core::{LocalServiceRoleV1, RouterAbProtocolErrorCode};
use router_ab_dev::{
    example_local_durable_object_seed_plan_v1, read_local_sqlite_seed_summary_v1,
    seed_example_local_durable_object_sqlite_v1, seed_example_local_storage_parity_v1,
    LocalDurableObjectScopeV1, LocalDurableObjectSqliteStorageV1,
};
use rusqlite::Connection;
use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

#[test]
fn local_durable_sqlite_storage_persists_across_reopened_connections(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = temp_sqlite_path("persist");
    {
        let connection = Connection::open(&path)?;
        let store = LocalDurableObjectSqliteStorageV1::new(
            &connection,
            LocalDurableObjectScopeV1::RouterReplay,
        )?;
        store.put_bytes("request/id/1", b"reservation-1")?;
        assert_eq!(
            store.get_bytes("request/id/1")?,
            Some(b"reservation-1".to_vec())
        );
    }

    {
        let connection = Connection::open(&path)?;
        let store = LocalDurableObjectSqliteStorageV1::new(
            &connection,
            LocalDurableObjectScopeV1::RouterReplay,
        )?;
        assert_eq!(
            store.get_bytes("request/id/1")?,
            Some(b"reservation-1".to_vec())
        );
        assert!(store.delete_key("request/id/1")?);
        assert_eq!(store.get_bytes("request/id/1")?, None);
    }
    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn local_durable_sqlite_storage_is_scope_isolated() -> Result<(), Box<dyn std::error::Error>> {
    let connection = Connection::open_in_memory()?;
    let router = LocalDurableObjectSqliteStorageV1::new(
        &connection,
        LocalDurableObjectScopeV1::RouterReplay,
    )?;
    let signing_worker = LocalDurableObjectSqliteStorageV1::new(
        &connection,
        LocalDurableObjectScopeV1::SigningWorkerRelayerOutput,
    )?;

    router.put_bytes("same-key", b"router-value")?;
    signing_worker.put_bytes("same-key", b"signing-worker-value")?;

    assert_eq!(
        router.get_bytes("same-key")?,
        Some(b"router-value".to_vec())
    );
    assert_eq!(
        signing_worker.get_bytes("same-key")?,
        Some(b"signing-worker-value".to_vec())
    );
    assert_eq!(router.list_keys()?, vec!["same-key"]);
    assert_eq!(signing_worker.list_keys()?, vec!["same-key"]);
    assert_eq!(router.owner(), LocalServiceRoleV1::Router);
    assert_eq!(signing_worker.owner(), LocalServiceRoleV1::SigningWorker);
    Ok(())
}

#[test]
fn local_durable_sqlite_storage_rejects_empty_keys_and_values(
) -> Result<(), Box<dyn std::error::Error>> {
    let connection = Connection::open_in_memory()?;
    let store = LocalDurableObjectSqliteStorageV1::new(
        &connection,
        LocalDurableObjectScopeV1::DeriverARootShare,
    )?;

    let err = store
        .put_bytes("", b"value")
        .expect_err("empty key must fail");
    assert_eq!(err.code(), RouterAbProtocolErrorCode::EmptyField);

    let err = store
        .put_bytes("key", b"")
        .expect_err("empty value must fail");
    assert_eq!(err.code(), RouterAbProtocolErrorCode::EmptyField);
    assert_eq!(store.owner(), LocalServiceRoleV1::DeriverA);
    Ok(())
}

#[test]
fn local_durable_sqlite_seed_writes_role_owned_smoke_state(
) -> Result<(), Box<dyn std::error::Error>> {
    let connection = Connection::open_in_memory()?;
    let receipt = seed_example_local_durable_object_sqlite_v1(&connection)?;

    assert_eq!(receipt.written_entry_count, 9);
    assert!(receipt.scope_labels.contains(&"router_replay".to_owned()));
    assert!(receipt
        .scope_labels
        .contains(&"deriver_a_root_share".to_owned()));
    assert!(receipt
        .scope_labels
        .contains(&"signing_worker_relayer_output".to_owned()));

    let router_replay = LocalDurableObjectSqliteStorageV1::new(
        &connection,
        LocalDurableObjectScopeV1::RouterReplay,
    )?;
    let deriver_a = LocalDurableObjectSqliteStorageV1::new(
        &connection,
        LocalDurableObjectScopeV1::DeriverARootShare,
    )?;
    let deriver_b = LocalDurableObjectSqliteStorageV1::new(
        &connection,
        LocalDurableObjectScopeV1::DeriverBRootShare,
    )?;
    let signing_worker = LocalDurableObjectSqliteStorageV1::new(
        &connection,
        LocalDurableObjectScopeV1::SigningWorkerRelayerOutput,
    )?;

    assert_eq!(
        router_replay.get_bytes("replay/request/dev")?,
        Some(br#"{"state":"available"}"#.to_vec())
    );
    assert_eq!(
        deriver_a.get_bytes("sealed/share/a")?,
        Some(b"local-dev-sealed-root-share-a".to_vec())
    );
    assert_eq!(
        deriver_b.get_bytes("sealed/share/b")?,
        Some(b"local-dev-sealed-root-share-b".to_vec())
    );
    assert_eq!(
        signing_worker.get_bytes("activation/dev")?,
        Some(br#"{"state":"activated"}"#.to_vec())
    );
    assert_eq!(
        signing_worker.get_bytes("active-state/dev")?,
        Some(br#"{"state":"active"}"#.to_vec())
    );
    Ok(())
}

#[test]
fn local_storage_parity_seed_includes_signing_root_metadata_and_durable_state(
) -> Result<(), Box<dyn std::error::Error>> {
    let connection = Connection::open_in_memory()?;
    let receipt = seed_example_local_storage_parity_v1(&connection)?;

    assert_eq!(receipt.signing_root_metadata.executed_statement_count, 3);
    assert_eq!(receipt.durable_objects.written_entry_count, 9);
    let summary = read_local_sqlite_seed_summary_v1(&connection)?;
    assert_eq!(summary.signing_root_count, 1);
    assert_eq!(summary.sealed_share_count, 2);

    let signing_worker = LocalDurableObjectSqliteStorageV1::new(
        &connection,
        LocalDurableObjectScopeV1::SigningWorkerRelayerOutput,
    )?;
    assert_eq!(
        signing_worker.list_keys()?,
        vec!["activation/dev", "active-state/dev"]
    );
    Ok(())
}

#[test]
fn local_storage_parity_seed_survives_reopened_connection() -> Result<(), Box<dyn std::error::Error>>
{
    let path = temp_sqlite_path("storage-parity");
    {
        let connection = Connection::open(&path)?;
        seed_example_local_storage_parity_v1(&connection)?;
    }

    {
        let connection = Connection::open(&path)?;
        let summary = read_local_sqlite_seed_summary_v1(&connection)?;
        assert_eq!(summary.signing_root_count, 1);
        assert_eq!(summary.sealed_share_count, 2);

        let deriver_a = LocalDurableObjectSqliteStorageV1::new(
            &connection,
            LocalDurableObjectScopeV1::DeriverARootShare,
        )?;
        let signing_worker = LocalDurableObjectSqliteStorageV1::new(
            &connection,
            LocalDurableObjectScopeV1::SigningWorkerRelayerOutput,
        )?;
        assert_eq!(
            deriver_a.get_bytes("sealed/share/a")?,
            Some(b"local-dev-sealed-root-share-a".to_vec())
        );
        assert_eq!(
            signing_worker.get_bytes("active-state/dev")?,
            Some(br#"{"state":"active"}"#.to_vec())
        );
    }

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn local_durable_seed_debug_redacts_seed_values() -> Result<(), Box<dyn std::error::Error>> {
    let plan = example_local_durable_object_seed_plan_v1()?;
    let debug = format!("{plan:?}");

    assert!(debug.contains("[redacted]"));
    assert!(!debug.contains("local-dev-sealed-root-share-a"));
    assert!(!debug.contains("activated"));
    Ok(())
}

fn temp_sqlite_path(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "router-ab-local-durable-{label}-{}-{nanos}.sqlite",
        std::process::id()
    ))
}
