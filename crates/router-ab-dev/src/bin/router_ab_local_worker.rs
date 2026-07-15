use router_ab_core::LocalServiceRoleV1;
use router_ab_dev::{
    dispatch_local_ed25519_yao_connection_v1, local_dev_http_handle_request_v1,
    local_worker_bind_addr_v1, parse_local_env_file_contents_v1, parse_local_service_role_label_v1,
    parse_local_worker_role_config_for_role_v1, read_local_dev_http_request_v1,
    write_local_dev_http_response_v1, LocalDevHttpTopologyV1, LocalDurableObjectScopeV1,
    LocalDurableObjectSqliteStorageV1, LocalEd25519YaoConnectionDispatchV1,
    LocalEd25519YaoWorkerStateV1, LocalWorkerRoleConfigV1,
};
use rusqlite::Connection;
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

const LOCAL_ED25519_YAO_DURABLE_STATE_KEY_V1: &str = "ed25519-yao/worker-state-v1";

struct LocalEd25519YaoStateStoreV1 {
    connection: Connection,
    scope: LocalDurableObjectScopeV1,
}

impl LocalEd25519YaoStateStoreV1 {
    fn open(config: &LocalWorkerRoleConfigV1) -> Result<Self, Box<dyn std::error::Error>> {
        let (path, scope) = match config {
            LocalWorkerRoleConfigV1::DeriverA(config) => (
                config.root_share_storage_path.as_str(),
                LocalDurableObjectScopeV1::DeriverARootShare,
            ),
            LocalWorkerRoleConfigV1::DeriverB(config) => (
                config.root_share_storage_path.as_str(),
                LocalDurableObjectScopeV1::DeriverBRootShare,
            ),
            LocalWorkerRoleConfigV1::SigningWorker(config) => (
                config.server_output_storage_path.as_str(),
                LocalDurableObjectScopeV1::SigningWorkerServerOutput,
            ),
            LocalWorkerRoleConfigV1::Router(_) => {
                return Err("Router does not own local Ed25519 Yao secret state".into());
            }
        };
        let path = PathBuf::from(path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        Ok(Self {
            connection: Connection::open(path)?,
            scope,
        })
    }

    fn load(
        &self,
        role: LocalServiceRoleV1,
    ) -> Result<LocalEd25519YaoWorkerStateV1, Box<dyn std::error::Error>> {
        let storage = LocalDurableObjectSqliteStorageV1::new(&self.connection, self.scope)?;
        let Some(bytes) = storage.get_bytes(LOCAL_ED25519_YAO_DURABLE_STATE_KEY_V1)? else {
            return Ok(LocalEd25519YaoWorkerStateV1::default());
        };
        Ok(LocalEd25519YaoWorkerStateV1::decode_durable_state_for_role_v1(role, &bytes)?)
    }

    fn persist(
        &self,
        role: LocalServiceRoleV1,
        state: &LocalEd25519YaoWorkerStateV1,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let bytes = state.encode_durable_state_for_role_v1(role)?;
        let storage = LocalDurableObjectSqliteStorageV1::new(&self.connection, self.scope)?;
        storage.put_bytes(LOCAL_ED25519_YAO_DURABLE_STATE_KEY_V1, &bytes)?;
        Ok(())
    }
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
    let state_store = LocalEd25519YaoStateStoreV1::open(&config)?;

    let summary = WorkerStartupSummary {
        role: config.role(),
        role_label: config.role().as_str().to_owned(),
        bind_addr: bind_addr.clone(),
        env_path: options.env_path.display().to_string(),
    };
    eprintln!("{}", serde_json::to_string(&summary)?);

    let mut yao_state = state_store.load(config.role())?;
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => match handle_connection(stream, &config, &mut yao_state) {
                Ok(LocalWorkerConnectionResultV1::YaoHandled) => {
                    state_store.persist(config.role(), &yao_state)?;
                }
                Ok(LocalWorkerConnectionResultV1::OtherHandled) => {}
                Err(error) => log_worker_request_error(&config, error.as_ref()),
            },
            Err(error) => log_worker_request_error(&config, &error),
        }
    }
    Ok(())
}

enum LocalWorkerConnectionResultV1 {
    YaoHandled,
    OtherHandled,
}

fn handle_connection(
    stream: TcpStream,
    config: &LocalWorkerRoleConfigV1,
    yao_state: &mut LocalEd25519YaoWorkerStateV1,
) -> Result<LocalWorkerConnectionResultV1, Box<dyn std::error::Error>> {
    let mut stream = match dispatch_local_ed25519_yao_connection_v1(stream, config, yao_state)? {
        LocalEd25519YaoConnectionDispatchV1::Handled => {
            return Ok(LocalWorkerConnectionResultV1::YaoHandled);
        }
        LocalEd25519YaoConnectionDispatchV1::Unhandled(stream) => stream,
    };
    let request = read_local_dev_http_request_v1(&mut stream)?;
    let (status, body) =
        local_dev_http_handle_request_v1(LocalDevHttpTopologyV1::FourWorker(config), &request)?;
    write_local_dev_http_response_v1(&mut stream, status, &body)?;
    Ok(LocalWorkerConnectionResultV1::OtherHandled)
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
            "--help" | "-h" => return Err(usage()),
            _ => return Err(format!("unknown argument {arg}\n{}", usage())),
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
