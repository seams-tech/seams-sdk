use router_ab_dev::LocalRolePrivateSqliteStorageV1;
use rusqlite::Connection;
use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

#[test]
fn role_private_sqlite_state_survives_reopen() -> Result<(), Box<dyn std::error::Error>> {
    let path = temp_sqlite_path("persist");
    {
        let connection = Connection::open(&path)?;
        let store = LocalRolePrivateSqliteStorageV1::new(&connection)?;
        store.put_bytes("ed25519-yao/worker-state-v1", b"role-private-state")?;
    }
    {
        let connection = Connection::open(&path)?;
        let store = LocalRolePrivateSqliteStorageV1::new(&connection)?;
        assert_eq!(
            store.get_bytes("ed25519-yao/worker-state-v1")?,
            Some(b"role-private-state".to_vec())
        );
    }
    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn role_private_sqlite_files_are_isolated() -> Result<(), Box<dyn std::error::Error>> {
    let deriver_path = temp_sqlite_path("deriver");
    let signing_worker_path = temp_sqlite_path("signing-worker");
    {
        let deriver_connection = Connection::open(&deriver_path)?;
        let signing_worker_connection = Connection::open(&signing_worker_path)?;
        let deriver = LocalRolePrivateSqliteStorageV1::new(&deriver_connection)?;
        let signing_worker = LocalRolePrivateSqliteStorageV1::new(&signing_worker_connection)?;
        deriver.put_bytes("same-key", b"deriver-state")?;
        signing_worker.put_bytes("same-key", b"signing-worker-state")?;
        assert_eq!(
            deriver.get_bytes("same-key")?,
            Some(b"deriver-state".to_vec())
        );
        assert_eq!(
            signing_worker.get_bytes("same-key")?,
            Some(b"signing-worker-state".to_vec())
        );
    }
    let _ = fs::remove_file(deriver_path);
    let _ = fs::remove_file(signing_worker_path);
    Ok(())
}

fn temp_sqlite_path(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "router-ab-role-private-{label}-{}-{nanos}.sqlite",
        std::process::id()
    ))
}
