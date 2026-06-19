use router_ab_core::LocalServiceRoleV1;
use router_ab_dev::{
    local_dev_http_handle_request_v1, local_worker_bind_addr_v1, parse_local_env_file_contents_v1,
    parse_local_service_role_label_v1, parse_local_worker_role_config_for_role_v1,
    read_local_dev_http_request_v1 as read_http_request,
    write_local_dev_http_response_v1 as write_response, LocalDevHttpTopologyV1,
    LocalWorkerRoleConfigV1,
};
use serde::Serialize;
use std::{
    env, fs,
    net::{TcpListener, TcpStream},
    path::PathBuf,
    sync::Arc,
};

#[derive(Debug, Clone, PartialEq, Eq)]
struct WorkerOptions {
    role: LocalServiceRoleV1,
    env_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct WorkerStartupSummary {
    role: LocalServiceRoleV1,
    role_label: String,
    bind_addr: String,
    env_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct WorkerRequestErrorSummary {
    role: LocalServiceRoleV1,
    role_label: String,
    event: &'static str,
    error: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let options = parse_args(env::args().skip(1))?;
    let env_contents = fs::read_to_string(&options.env_path)?;
    let config = Arc::new(parse_local_worker_role_config_for_role_v1(
        options.role,
        parse_local_env_file_contents_v1(&env_contents)?,
    )?);
    let bind_addr = local_worker_bind_addr_v1(&config)?;
    let listener = TcpListener::bind(&bind_addr)?;

    let summary = WorkerStartupSummary {
        role: config.role(),
        role_label: config.role().as_str().to_owned(),
        bind_addr: bind_addr.clone(),
        env_path: options.env_path.display().to_string(),
    };
    eprintln!("{}", serde_json::to_string(&summary)?);

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                if let Err(error) = handle_connection(stream, &config) {
                    log_worker_request_error(&config, error.as_ref());
                }
            }
            Err(error) => {
                log_worker_request_error(&config, &error);
            }
        }
    }
    Ok(())
}

fn handle_connection(
    mut stream: TcpStream,
    config: &LocalWorkerRoleConfigV1,
) -> Result<(), Box<dyn std::error::Error>> {
    let request = read_http_request(&mut stream)?;
    let (status, body) =
        local_dev_http_handle_request_v1(LocalDevHttpTopologyV1::FourWorker(config), &request)?;
    write_response(&mut stream, status, &body)?;
    Ok(())
}

fn log_worker_request_error(config: &LocalWorkerRoleConfigV1, error: &dyn std::error::Error) {
    let summary = WorkerRequestErrorSummary {
        role: config.role(),
        role_label: config.role().as_str().to_owned(),
        event: "request_error",
        error: error.to_string(),
    };
    match serde_json::to_string(&summary) {
        Ok(json) => eprintln!("{json}"),
        Err(_) => eprintln!("local worker request error: {}", error),
    }
}

fn parse_args(args: impl IntoIterator<Item = String>) -> Result<WorkerOptions, String> {
    let mut role = None;
    let mut env_path = None;
    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--role" => {
                let Some(value) = iter.next() else {
                    return Err("--role requires a value".to_owned());
                };
                let parsed =
                    parse_local_service_role_label_v1(&value).map_err(|e| e.to_string())?;
                if parsed == LocalServiceRoleV1::Router {
                    return Err("router_ab_local_worker no longer exposes a public router role; use the SDK Router server".to_owned());
                }
                role = Some(parsed);
            }
            "--env" => {
                let Some(value) = iter.next() else {
                    return Err("--env requires a path".to_owned());
                };
                env_path = Some(PathBuf::from(value));
            }
            "--help" | "-h" => {
                return Err(usage());
            }
            _ => {
                return Err(format!("unknown argument {arg}\n{}", usage()));
            }
        }
    }
    let Some(role) = role else {
        return Err(format!("missing --role\n{}", usage()));
    };
    let Some(env_path) = env_path else {
        return Err(format!("missing --env\n{}", usage()));
    };
    Ok(WorkerOptions { role, env_path })
}

fn usage() -> String {
    "usage: router_ab_local_worker --role <deriver-a|deriver-b|signing-worker> --env <path>"
        .to_owned()
}
