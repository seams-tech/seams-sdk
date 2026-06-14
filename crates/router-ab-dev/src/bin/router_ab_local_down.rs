#[path = "local_dev_process/mod.rs"]
mod local_dev_process;

use local_dev_process::{
    normalize_root, read_pid, remove_pid, terminate_pid, LOCAL_WORKER_PROCESS_SPECS,
};
use router_ab_core::LocalServiceRoleV1;
use serde::Serialize;
use std::{env, path::PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
struct DownOptions {
    root: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct DownSummary {
    root: String,
    stopped: Vec<StoppedProcess>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct StoppedProcess {
    role: LocalServiceRoleV1,
    role_label: &'static str,
    pid: u32,
    status: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let options = parse_args(env::args().skip(1))?;
    let root = normalize_root(options.root)?;
    let mut stopped = Vec::new();

    for spec in LOCAL_WORKER_PROCESS_SPECS {
        let Some(pid) = read_pid(&root, *spec)? else {
            continue;
        };
        let status = match terminate_pid(pid) {
            Ok(()) => "terminated".to_owned(),
            Err(error) => format!("terminate_failed: {error}"),
        };
        remove_pid(&root, *spec)?;
        stopped.push(StoppedProcess {
            role: spec.role,
            role_label: spec.role_label,
            pid,
            status,
        });
    }

    println!(
        "{}",
        serde_json::to_string_pretty(&DownSummary {
            root: root.display().to_string(),
            stopped,
        })?
    );
    Ok(())
}

fn parse_args(args: impl IntoIterator<Item = String>) -> Result<DownOptions, String> {
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
    Ok(DownOptions { root })
}

fn usage() -> String {
    "usage: router_ab_local_down [--root <path>]".to_owned()
}
