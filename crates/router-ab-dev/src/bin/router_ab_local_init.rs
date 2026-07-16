#[path = "local_dev_process/mod.rs"]
mod local_dev_process;

use local_dev_process::{free_port_url, LocalWorkerUrls};
use router_ab_dev::{local_env_materialization_plan_v1, LocalEnvMaterializationPlanV1};
use serde::Serialize;
use std::{
    env, fs,
    path::{Path, PathBuf},
};

#[derive(Debug, Clone, PartialEq, Eq)]
struct InitOptions {
    root: PathBuf,
    force: bool,
    ephemeral_ports: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct InitSummary {
    root: String,
    directories: Vec<String>,
    files: Vec<String>,
    urls: Option<LocalWorkerUrls>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let options = parse_args(env::args().skip(1))?;
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed)?;
    let urls = if options.ephemeral_ports {
        Some(LocalWorkerUrls {
            router: free_port_url()?,
            deriver_a: free_port_url()?,
            deriver_b: free_port_url()?,
            signing_worker: free_port_url()?,
        })
    } else {
        None
    };
    let mut plan = local_env_materialization_plan_v1(&seed)?;
    if let Some(urls) = &urls {
        replace_default_urls(&mut plan, urls);
        plan.validate()?;
    }

    for directory in &plan.directories {
        fs::create_dir_all(options.root.join(directory))?;
    }

    for file in &plan.files {
        let path = options.root.join(&file.path);
        if path.exists() && !options.force {
            return Err(format!(
                "{} already exists; pass --force to regenerate local env files",
                path.display()
            )
            .into());
        }
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        fs::write(path, &file.contents)?;
    }
    let build_environment_path = options.root.join(&plan.build_environment.path);
    if build_environment_path.exists() && !options.force {
        return Err(format!(
            "{} already exists; pass --force to regenerate local env files",
            build_environment_path.display()
        )
        .into());
    }
    fs::write(&build_environment_path, &plan.build_environment.contents)?;

    let summary = InitSummary {
        root: options.root.display().to_string(),
        directories: plan.directories,
        files: plan
            .files
            .into_iter()
            .map(|file| file.path)
            .chain(std::iter::once(plan.build_environment.path))
            .collect(),
        urls,
    };
    println!("{}", serde_json::to_string_pretty(&summary)?);
    Ok(())
}

fn replace_default_urls(plan: &mut LocalEnvMaterializationPlanV1, urls: &LocalWorkerUrls) {
    for file in &mut plan.files {
        file.contents = file
            .contents
            .replace("http://127.0.0.1:9090", &urls.router)
            .replace("http://127.0.0.1:9091", &urls.deriver_a)
            .replace("http://127.0.0.1:9092", &urls.deriver_b)
            .replace("http://127.0.0.1:9093", &urls.signing_worker);
    }
}

fn parse_args(args: impl IntoIterator<Item = String>) -> Result<InitOptions, String> {
    let mut root = PathBuf::from(".");
    let mut force = false;
    let mut ephemeral_ports = false;
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
            "--force" => {
                force = true;
            }
            "--ephemeral-ports" => {
                ephemeral_ports = true;
            }
            "--help" | "-h" => {
                return Err(usage());
            }
            _ => {
                return Err(format!("unknown argument {arg}\n{}", usage()));
            }
        }
    }
    require_relative_or_absolute_path(&root)?;
    Ok(InitOptions {
        root,
        force,
        ephemeral_ports,
    })
}

fn require_relative_or_absolute_path(path: &Path) -> Result<(), String> {
    if path.as_os_str().is_empty() {
        return Err("--root must not be empty".to_owned());
    }
    Ok(())
}

fn usage() -> String {
    "usage: router_ab_local_init [--root <path>] [--force] [--ephemeral-ports]".to_owned()
}
