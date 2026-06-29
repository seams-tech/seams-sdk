use router_ab_core::Role;
use router_ab_dev::{
    read_local_sqlite_seed_summary_v1, require_example_local_sqlite_signer_startup_v1,
    seed_example_local_sqlite_v1, LocalSqliteSeedSummaryV1,
};
use rusqlite::Connection;
use serde::Serialize;

#[derive(Serialize)]
struct DevSqliteSeedSummary {
    database: String,
    executed_statement_count: u32,
    signing_root_count: u32,
    sealed_share_count: u32,
    signer_roles: Vec<String>,
    signer_startup_checks: Vec<DevSignerStartupCheck>,
}

#[derive(Serialize)]
struct DevSignerStartupCheck {
    role: &'static str,
    signer_id: String,
    signer_key_epoch: String,
    sealed_share_storage_key: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let database = std::env::args()
        .nth(1)
        .unwrap_or_else(|| ":memory:".to_owned());
    let connection = if database == ":memory:" {
        Connection::open_in_memory()?
    } else {
        Connection::open(&database)?
    };
    let receipt = seed_example_local_sqlite_v1(&connection)?;
    let summary = read_local_sqlite_seed_summary_v1(&connection)?;
    let signer_a_check =
        require_example_local_sqlite_signer_startup_v1(&connection, Role::SignerA)?;
    let signer_b_check =
        require_example_local_sqlite_signer_startup_v1(&connection, Role::SignerB)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&dev_summary(
            database,
            receipt.executed_statement_count,
            summary,
            vec![
                DevSignerStartupCheck {
                    role: "signer_a",
                    signer_id: signer_a_check.signer_id,
                    signer_key_epoch: signer_a_check.signer_key_epoch,
                    sealed_share_storage_key: signer_a_check.sealed_share_storage_key,
                },
                DevSignerStartupCheck {
                    role: "signer_b",
                    signer_id: signer_b_check.signer_id,
                    signer_key_epoch: signer_b_check.signer_key_epoch,
                    sealed_share_storage_key: signer_b_check.sealed_share_storage_key,
                },
            ],
        ))?
    );
    Ok(())
}

fn dev_summary(
    database: String,
    executed_statement_count: u32,
    summary: LocalSqliteSeedSummaryV1,
    signer_startup_checks: Vec<DevSignerStartupCheck>,
) -> DevSqliteSeedSummary {
    DevSqliteSeedSummary {
        database,
        executed_statement_count,
        signing_root_count: summary.signing_root_count,
        sealed_share_count: summary.sealed_share_count,
        signer_roles: summary.signer_roles,
        signer_startup_checks,
    }
}
