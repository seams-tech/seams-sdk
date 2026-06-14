use router_ab_core::{LocalServiceRoleV1, RouterAbProtocolError, RouterAbProtocolErrorCode};
use router_ab_dev::{
    handle_local_deriver_peer_message_json_v1, handle_local_router_setup_smoke_request_json_v1,
    handle_local_signing_worker_activation_json_v1,
    handle_local_signing_worker_normal_signing_smoke_json_v1, local_worker_owns_path_v1,
    parse_local_env_file_contents_v1, parse_local_worker_role_config_for_role_v1,
    LocalRouterNormalSigningSmokeResponseV1, LocalSigningWorkerNormalSigningSmokeResponseV1,
    LocalWorkerHealthResponseV1, LOCAL_DERIVER_A_PEER_PATH_V1, LOCAL_DERIVER_B_PEER_PATH_V1,
    LOCAL_ROUTER_ENV_FILE_V1, LOCAL_ROUTER_NORMAL_SIGNING_PATH_V1,
    LOCAL_ROUTER_SPLIT_DERIVATION_PATH_V1, LOCAL_SIGNING_WORKER_ACTIVATION_PATH_V1,
    LOCAL_SIGNING_WORKER_NORMAL_SIGNING_PATH_V1, LOCAL_WORKER_HEALTH_PATH_V1,
    LOCAL_WORKER_READY_PATH_V1,
};
use serde::Serialize;
use std::{
    env, fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::PathBuf,
};

#[derive(Debug, Clone, PartialEq, Eq)]
struct BundledOptions {
    root: PathBuf,
    url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct BundledStartupSummary {
    mode: &'static str,
    bind_addr: String,
    public_url: String,
    router_env_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct BundledHttpErrorBody {
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
    let options = match parse_args(env::args().skip(1)) {
        Ok(options) => options,
        Err(message) if message == usage() => {
            println!("{message}");
            return Ok(());
        }
        Err(message) => return Err(message.into()),
    };
    let router_env_path = normalize_root(options.root)?.join(LOCAL_ROUTER_ENV_FILE_V1);
    let router_env = fs::read_to_string(&router_env_path)?;
    let router_config = parse_local_worker_role_config_for_role_v1(
        LocalServiceRoleV1::Router,
        parse_local_env_file_contents_v1(&router_env)?,
    )?;
    let public_url = options
        .url
        .unwrap_or_else(|| router_config.bind_url().to_owned());
    let bind_addr = http_bind_addr(&public_url)?;
    let listener = TcpListener::bind(&bind_addr)?;
    eprintln!(
        "{}",
        serde_json::to_string(&BundledStartupSummary {
            mode: "bundled_single_server",
            bind_addr: bind_addr.clone(),
            public_url,
            router_env_path: router_env_path.display().to_string(),
        })?
    );

    for stream in listener.incoming() {
        let stream = stream?;
        handle_connection(stream)?;
    }
    Ok(())
}

fn handle_connection(mut stream: TcpStream) -> Result<(), Box<dyn std::error::Error>> {
    let request = read_http_request(&mut stream)?;
    let method = request.method.as_str();
    let path = request.path.as_str();

    let (status, body) =
        if path == LOCAL_WORKER_HEALTH_PATH_V1 || path == LOCAL_WORKER_READY_PATH_V1 {
            if method == "GET" {
                (
                    200,
                    serde_json::to_string(&LocalWorkerHealthResponseV1 {
                        role: LocalServiceRoleV1::Router,
                        role_label: "bundled".to_owned(),
                        bind_url: "bundled".to_owned(),
                        status: "ready".to_owned(),
                        startup_epoch: "local-dev".to_owned(),
                        config_branch: "bundled_single_server".to_owned(),
                    })?,
                )
            } else {
                error_body(LocalServiceRoleV1::Router, path, 405, "method not allowed")?
            }
        } else if path == LOCAL_ROUTER_SPLIT_DERIVATION_PATH_V1 {
            if method == "POST" {
                match handle_local_router_setup_smoke_request_json_v1(&request.body) {
                    Ok(response) => (200, response),
                    Err(error) => route_error(LocalServiceRoleV1::Router, path, error)?,
                }
            } else {
                error_body(LocalServiceRoleV1::Router, path, 405, "method not allowed")?
            }
        } else if path == LOCAL_ROUTER_NORMAL_SIGNING_PATH_V1 {
            if method == "POST" {
                match handle_bundled_router_normal_signing_json_v1(&request.body) {
                    Ok(response) => (200, response),
                    Err(error) => route_error(LocalServiceRoleV1::Router, path, error)?,
                }
            } else {
                error_body(LocalServiceRoleV1::Router, path, 405, "method not allowed")?
            }
        } else if path == LOCAL_DERIVER_A_PEER_PATH_V1 {
            if method == "POST" {
                match handle_local_deriver_peer_message_json_v1(
                    LocalServiceRoleV1::DeriverA,
                    path,
                    &request.body,
                ) {
                    Ok(response) => (200, response),
                    Err(error) => route_error(LocalServiceRoleV1::DeriverA, path, error)?,
                }
            } else {
                error_body(
                    LocalServiceRoleV1::DeriverA,
                    path,
                    405,
                    "method not allowed",
                )?
            }
        } else if path == LOCAL_DERIVER_B_PEER_PATH_V1 {
            if method == "POST" {
                match handle_local_deriver_peer_message_json_v1(
                    LocalServiceRoleV1::DeriverB,
                    path,
                    &request.body,
                ) {
                    Ok(response) => (200, response),
                    Err(error) => route_error(LocalServiceRoleV1::DeriverB, path, error)?,
                }
            } else {
                error_body(
                    LocalServiceRoleV1::DeriverB,
                    path,
                    405,
                    "method not allowed",
                )?
            }
        } else if path == LOCAL_SIGNING_WORKER_ACTIVATION_PATH_V1 {
            if method == "POST" {
                match handle_local_signing_worker_activation_json_v1(
                    LocalServiceRoleV1::SigningWorker,
                    path,
                    &request.body,
                ) {
                    Ok(response) => (200, response),
                    Err(error) => route_error(LocalServiceRoleV1::SigningWorker, path, error)?,
                }
            } else {
                error_body(
                    LocalServiceRoleV1::SigningWorker,
                    path,
                    405,
                    "method not allowed",
                )?
            }
        } else if path == LOCAL_SIGNING_WORKER_NORMAL_SIGNING_PATH_V1 {
            if method == "POST" {
                match handle_local_signing_worker_normal_signing_smoke_json_v1(
                    LocalServiceRoleV1::SigningWorker,
                    path,
                    &request.body,
                ) {
                    Ok(response) => (200, response),
                    Err(error) => route_error(LocalServiceRoleV1::SigningWorker, path, error)?,
                }
            } else {
                error_body(
                    LocalServiceRoleV1::SigningWorker,
                    path,
                    405,
                    "method not allowed",
                )?
            }
        } else if local_worker_owns_path_v1(LocalServiceRoleV1::Router, path) {
            error_body(
                LocalServiceRoleV1::Router,
                path,
                501,
                "local protocol route is not implemented yet",
            )?
        } else {
            error_body(
                LocalServiceRoleV1::Router,
                path,
                404,
                "path is not owned by bundled server",
            )?
        };

    write_response(&mut stream, status, &body)?;
    Ok(())
}

fn handle_bundled_router_normal_signing_json_v1(
    body: &[u8],
) -> Result<String, RouterAbProtocolError> {
    let signing_worker_json = handle_local_signing_worker_normal_signing_smoke_json_v1(
        LocalServiceRoleV1::SigningWorker,
        LOCAL_SIGNING_WORKER_NORMAL_SIGNING_PATH_V1,
        body,
    )?;
    let signing_worker = serde_json::from_str::<LocalSigningWorkerNormalSigningSmokeResponseV1>(
        &signing_worker_json,
    )
    .map_err(|error| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("bundled SigningWorker normal-signing response JSON parse failed: {error}"),
        )
    })?;
    serde_json::to_string(&LocalRouterNormalSigningSmokeResponseV1 {
        status: "signed".to_owned(),
        forwarded_to_role: LocalServiceRoleV1::SigningWorker,
        signing_worker_status: signing_worker.status,
        signature_scheme: signing_worker.signature_scheme,
        signing_payload_digest_hex: signing_worker.signing_payload_digest_hex,
        signature_hex: signing_worker.signature_hex,
        verifying_key_hex: signing_worker.verifying_key_hex,
        deriver_a_request_count: 0,
        deriver_b_request_count: 0,
    })
    .map_err(|error| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("bundled Router normal-signing response JSON serialization failed: {error}"),
        )
    })
}

fn route_error(
    role: LocalServiceRoleV1,
    path: &str,
    error: RouterAbProtocolError,
) -> Result<(u16, String), Box<dyn std::error::Error>> {
    error_body(
        role,
        path,
        400,
        &format!("{:?}: {}", error.code(), error.message()),
    )
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
        serde_json::to_string(&BundledHttpErrorBody {
            role,
            path: path.to_owned(),
            status,
            error: error.to_owned(),
        })?,
    ))
}

fn normalize_root(root: PathBuf) -> Result<PathBuf, Box<dyn std::error::Error>> {
    if root.as_os_str().is_empty() {
        return Err("local root must not be empty".into());
    }
    if root.is_absolute() {
        Ok(root)
    } else {
        Ok(std::env::current_dir()?.join(root))
    }
}

fn http_bind_addr(url: &str) -> Result<String, Box<dyn std::error::Error>> {
    let authority = url
        .strip_prefix("http://")
        .ok_or("bundled Router A/B URL must use http://")?
        .trim_end_matches('/');
    if authority.is_empty() || authority.contains('/') {
        return Err("bundled Router A/B URL must contain only host and port".into());
    }
    Ok(authority.to_owned())
}

fn parse_args(args: impl IntoIterator<Item = String>) -> Result<BundledOptions, String> {
    let mut root = PathBuf::from(".");
    let mut url = None;
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
            "--url" => {
                let Some(value) = iter.next() else {
                    return Err("--url requires an http://host:port value".to_owned());
                };
                url = Some(value);
            }
            "--help" | "-h" => {
                return Err(usage());
            }
            _ => {
                return Err(format!("unknown argument {arg}\n{}", usage()));
            }
        }
    }
    Ok(BundledOptions { root, url })
}

fn usage() -> String {
    "usage: router_ab_local_bundled [--root <path>] [--url http://127.0.0.1:<port>]".to_owned()
}
