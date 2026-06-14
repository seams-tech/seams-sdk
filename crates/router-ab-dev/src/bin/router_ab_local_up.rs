#[path = "local_dev_process/mod.rs"]
mod local_dev_process;

use local_dev_process::{
    assert_worker_binary_bindable, normalize_root, read_pid, resolve_worker_binary,
    wait_for_managed_health, write_pid, LocalWorkerSpawnReceipt, ManagedChild,
    LOCAL_WORKER_PROCESS_SPECS,
};
use serde::Serialize;
use std::{env, path::PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
struct UpOptions {
    root: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct UpSummary {
    root: String,
    worker_binary: String,
    processes: Vec<LocalWorkerSpawnReceipt>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let options = parse_args(env::args().skip(1))?;
    let root = normalize_root(options.root)?;
    let worker_binary = resolve_worker_binary()?;

    for spec in LOCAL_WORKER_PROCESS_SPECS {
        if read_pid(&root, *spec)?.is_some() {
            return Err(format!(
                "{} already exists; run pnpm router-ab:local:down first",
                local_dev_process::pid_path(&root, *spec).display()
            )
            .into());
        }
        assert_worker_binary_bindable(&root, *spec)?;
    }

    let mut children: Vec<(ManagedChild, LocalWorkerSpawnReceipt)> = Vec::new();
    for spec in LOCAL_WORKER_PROCESS_SPECS {
        let (mut child, receipt) = ManagedChild::spawn(&worker_binary, &root, *spec)?;
        wait_for_managed_health(&receipt.url, child.child_mut())?;
        write_pid(&root, *spec, receipt.pid)?;
        children.push((child, receipt));
    }

    let summary = UpSummary {
        root: root.display().to_string(),
        worker_binary: worker_binary.display().to_string(),
        processes: children
            .iter()
            .map(|(_, receipt)| receipt.clone())
            .collect(),
    };
    for (child, _) in children {
        child.disarm();
    }
    println!("{}", serde_json::to_string_pretty(&summary)?);
    Ok(())
}

fn parse_args(args: impl IntoIterator<Item = String>) -> Result<UpOptions, String> {
    let mut root = PathBuf::from(".");
    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--" => {}
            "--root" => {
                let Some(value) = iter.next() else {
                    return Err("--root requires a path".to_owned());
                };
                root = PathBuf::from(value);
            }
            "--help" | "-h" => {
                return Err(usage());
            }
            _ => {
                return Err(format!("unknown argument {arg}\n{}", usage()));
            }
        }
    }
    Ok(UpOptions { root })
}

fn usage() -> String {
    "usage: router_ab_local_up [--root <path>]".to_owned()
}
