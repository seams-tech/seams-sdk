use router_ab_core::LocalServiceRoleV1;
use router_ab_dev::{
    handle_local_deriver_peer_message_json_v1,
    handle_local_router_normal_signing_smoke_request_json_v1,
    handle_local_router_setup_smoke_request_json_v1,
    handle_local_signing_worker_activation_json_v1,
    handle_local_signing_worker_normal_signing_smoke_json_v1, local_worker_bind_addr_v1,
    local_worker_health_response_json_v1, local_worker_owns_path_v1,
    parse_local_env_file_contents_v1, parse_local_service_role_label_v1,
    parse_local_worker_role_config_for_role_v1, LocalWorkerRoleConfigV1,
    LOCAL_DERIVER_A_PEER_PATH_V1, LOCAL_DERIVER_B_PEER_PATH_V1,
    LOCAL_ROUTER_NORMAL_SIGNING_PATH_V1, LOCAL_ROUTER_SPLIT_DERIVATION_PATH_V1,
    LOCAL_SIGNING_WORKER_ACTIVATION_PATH_V1, LOCAL_SIGNING_WORKER_NORMAL_SIGNING_PATH_V1,
    LOCAL_WORKER_HEALTH_PATH_V1, LOCAL_WORKER_READY_PATH_V1,
};
use serde::Serialize;
use std::{
    env, fs,
    io::{Read, Write},
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
struct LocalHttpErrorBody {
    role: LocalServiceRoleV1,
    path: String,
    status: u16,
    error: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LocalHttpRequestParts {
    method: String,
    path: String,
    body: Vec<u8>,
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
        let stream = stream?;
        handle_connection(stream, &config)?;
    }
    Ok(())
}

fn handle_connection(
    mut stream: TcpStream,
    config: &LocalWorkerRoleConfigV1,
) -> Result<(), Box<dyn std::error::Error>> {
    let request = read_http_request(&mut stream)?;
    let method = request.method.as_str();
    let path = request.path.as_str();

    let (status, body) = if path == LOCAL_WORKER_HEALTH_PATH_V1
        || path == LOCAL_WORKER_READY_PATH_V1
    {
        if method == "GET" {
            (200, local_worker_health_response_json_v1(config)?)
        } else {
            error_body(config.role(), path, 405, "method not allowed")?
        }
    } else if config.role() == LocalServiceRoleV1::Router
        && path == LOCAL_ROUTER_SPLIT_DERIVATION_PATH_V1
    {
        if method == "POST" {
            match handle_local_router_setup_smoke_request_json_v1(&request.body) {
                Ok(response) => (200, response),
                Err(error) => error_body(
                    config.role(),
                    path,
                    400,
                    &format!("{:?}: {}", error.code(), error.message()),
                )?,
            }
        } else {
            error_body(config.role(), path, 405, "method not allowed")?
        }
    } else if matches!(config, LocalWorkerRoleConfigV1::Router(_))
        && path == LOCAL_ROUTER_NORMAL_SIGNING_PATH_V1
    {
        if method == "POST" {
            let LocalWorkerRoleConfigV1::Router(router_config) = config else {
                unreachable!("matches! checked Router branch");
            };
            match handle_local_router_normal_signing_smoke_request_json_v1(
                &router_config.signing_worker_url,
                &request.body,
            ) {
                Ok(response) => (200, response),
                Err(error) => error_body(
                    config.role(),
                    path,
                    400,
                    &format!("{:?}: {}", error.code(), error.message()),
                )?,
            }
        } else {
            error_body(config.role(), path, 405, "method not allowed")?
        }
    } else if matches!(
        (config.role(), path),
        (LocalServiceRoleV1::DeriverA, LOCAL_DERIVER_A_PEER_PATH_V1)
            | (LocalServiceRoleV1::DeriverB, LOCAL_DERIVER_B_PEER_PATH_V1)
    ) {
        if method == "POST" {
            match handle_local_deriver_peer_message_json_v1(config.role(), path, &request.body) {
                Ok(response) => (200, response),
                Err(error) => error_body(
                    config.role(),
                    path,
                    400,
                    &format!("{:?}: {}", error.code(), error.message()),
                )?,
            }
        } else {
            error_body(config.role(), path, 405, "method not allowed")?
        }
    } else if config.role() == LocalServiceRoleV1::SigningWorker
        && path == LOCAL_SIGNING_WORKER_ACTIVATION_PATH_V1
    {
        if method == "POST" {
            match handle_local_signing_worker_activation_json_v1(config.role(), path, &request.body)
            {
                Ok(response) => (200, response),
                Err(error) => error_body(
                    config.role(),
                    path,
                    400,
                    &format!("{:?}: {}", error.code(), error.message()),
                )?,
            }
        } else {
            error_body(config.role(), path, 405, "method not allowed")?
        }
    } else if config.role() == LocalServiceRoleV1::SigningWorker
        && path == LOCAL_SIGNING_WORKER_NORMAL_SIGNING_PATH_V1
    {
        if method == "POST" {
            match handle_local_signing_worker_normal_signing_smoke_json_v1(
                config.role(),
                path,
                &request.body,
            ) {
                Ok(response) => (200, response),
                Err(error) => error_body(
                    config.role(),
                    path,
                    400,
                    &format!("{:?}: {}", error.code(), error.message()),
                )?,
            }
        } else {
            error_body(config.role(), path, 405, "method not allowed")?
        }
    } else if local_worker_owns_path_v1(config.role(), path) {
        if method == "POST" {
            error_body(
                config.role(),
                path,
                501,
                "local protocol route is not implemented yet",
            )?
        } else {
            error_body(config.role(), path, 405, "method not allowed")?
        }
    } else {
        error_body(config.role(), path, 404, "path is not owned by this worker")?
    };

    write_response(&mut stream, status, &body)?;
    Ok(())
}

fn read_http_request(
    stream: &mut TcpStream,
) -> Result<LocalHttpRequestParts, Box<dyn std::error::Error>> {
    let mut request = Vec::new();
    let mut buffer = [0u8; 8192];
    let header_end = loop {
        let bytes_read = stream.read(&mut buffer)?;
        if bytes_read == 0 {
            break request.windows(4).position(|window| window == b"\r\n\r\n");
        }
        request.extend_from_slice(&buffer[..bytes_read]);
        if let Some(header_end) = request.windows(4).position(|window| window == b"\r\n\r\n") {
            break Some(header_end);
        }
    };
    let Some(header_end) = header_end else {
        return Err("HTTP request missing header terminator".into());
    };
    let headers = std::str::from_utf8(&request[..header_end])?;
    let request_line = headers.lines().next().unwrap_or_default();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_owned();
    let path = parts.next().unwrap_or_default().to_owned();
    let content_length = content_length(headers)?;
    let body_start = header_end + 4;
    while request.len() < body_start + content_length {
        let bytes_read = stream.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        request.extend_from_slice(&buffer[..bytes_read]);
    }
    if request.len() < body_start + content_length {
        return Err("HTTP request body ended before content-length".into());
    }
    Ok(LocalHttpRequestParts {
        method,
        path,
        body: request[body_start..body_start + content_length].to_vec(),
    })
}

fn content_length(headers: &str) -> Result<usize, Box<dyn std::error::Error>> {
    for line in headers.lines().skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("content-length") {
            return Ok(value.trim().parse::<usize>()?);
        }
    }
    Ok(0)
}

fn write_response(
    stream: &mut TcpStream,
    status: u16,
    body: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        501 => "Not Implemented",
        _ => "Error",
    };
    write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        body.len(),
        body
    )?;
    Ok(())
}

fn error_body(
    role: LocalServiceRoleV1,
    path: &str,
    status: u16,
    error: &str,
) -> Result<(u16, String), Box<dyn std::error::Error>> {
    Ok((
        status,
        serde_json::to_string(&LocalHttpErrorBody {
            role,
            path: path.to_owned(),
            status,
            error: error.to_owned(),
        })?,
    ))
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
                role = Some(parse_local_service_role_label_v1(&value).map_err(|e| e.to_string())?);
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
    "usage: router_ab_local_worker --role <router|deriver-a|deriver-b|signing-worker> --env <path>"
        .to_owned()
}
