use router_ab_core::{LocalServiceRoleV1, RouterAbProtocolError, RouterAbProtocolResult};
use serde::Serialize;
use std::{
    io::{Read, Write},
    net::TcpStream,
};

use super::{
    handle_local_deriver_peer_message_json_v1,
    handle_local_router_ecdsa_hss_finalize_request_in_process_json_v1,
    handle_local_router_ecdsa_hss_finalize_request_json_v1,
    handle_local_router_ecdsa_hss_prepare_request_in_process_json_v1,
    handle_local_router_ecdsa_hss_prepare_request_json_v1,
    handle_local_router_normal_signing_request_in_process_json_v1,
    handle_local_router_normal_signing_request_json_v1,
    handle_local_router_normal_signing_round1_prepare_request_in_process_json_v1,
    handle_local_router_normal_signing_round1_prepare_request_json_v1,
    handle_local_signing_worker_activation_json_v1,
    handle_local_signing_worker_ecdsa_hss_finalize_json_v1,
    handle_local_signing_worker_ecdsa_hss_prepare_json_v1,
    handle_local_signing_worker_ecdsa_hss_presignature_pool_put_json_v1,
    handle_local_signing_worker_normal_signing_json_v1,
    handle_local_signing_worker_normal_signing_presign_pool_hit_json_v1,
    handle_local_signing_worker_normal_signing_presign_pool_prepare_json_v1,
    handle_local_signing_worker_normal_signing_round1_prepare_json_v1,
    local_worker_health_response_json_v1, local_worker_owns_path_v1, LocalSigningWorkerConfigV1,
    LocalWorkerHealthResponseV1, LocalWorkerRoleConfigV1, LOCAL_DERIVER_A_PEER_PATH_V1,
    LOCAL_DERIVER_B_PEER_PATH_V1, LOCAL_ROUTER_ECDSA_HSS_SIGNING_PATH_V1,
    LOCAL_ROUTER_ECDSA_HSS_SIGNING_PREPARE_PATH_V1, LOCAL_ROUTER_NORMAL_SIGNING_PATH_V2,
    LOCAL_ROUTER_NORMAL_SIGNING_PREPARE_PATH_V2, LOCAL_SIGNING_WORKER_ACTIVATION_PATH_V1,
    LOCAL_SIGNING_WORKER_ECDSA_HSS_PRESIGNATURE_POOL_PUT_PATH_V1,
    LOCAL_SIGNING_WORKER_ECDSA_HSS_SIGNING_PATH_V1,
    LOCAL_SIGNING_WORKER_ECDSA_HSS_SIGNING_PREPARE_PATH_V1,
    LOCAL_SIGNING_WORKER_NORMAL_SIGNING_PATH_V1,
    LOCAL_SIGNING_WORKER_NORMAL_SIGNING_PREPARE_PATH_V1,
    LOCAL_SIGNING_WORKER_NORMAL_SIGNING_PRESIGN_POOL_PATH_V1,
    LOCAL_SIGNING_WORKER_NORMAL_SIGNING_PRESIGN_POOL_PREPARE_PATH_V1, LOCAL_WORKER_HEALTH_PATH_V1,
    LOCAL_WORKER_READY_PATH_V1,
};

#[derive(Debug, Clone, Copy)]
pub enum LocalDevHttpTopologyV1<'a> {
    FourWorker(&'a LocalWorkerRoleConfigV1),
    Bundled {
        signing_worker: &'a LocalSigningWorkerConfigV1,
    },
}

pub fn local_dev_http_handle_request_v1(
    topology: LocalDevHttpTopologyV1<'_>,
    request: &LocalDevHttpRequestPartsV1,
) -> Result<(u16, String), Box<dyn std::error::Error>> {
    let method = request.method.as_str();
    let path = request.path.as_str();

    if path == LOCAL_WORKER_HEALTH_PATH_V1 || path == LOCAL_WORKER_READY_PATH_V1 {
        let role = topology.local_http_error_role();
        if method == "GET" {
            return match topology {
                LocalDevHttpTopologyV1::FourWorker(config) => {
                    Ok((200, local_worker_health_response_json_v1(config)?))
                }
                LocalDevHttpTopologyV1::Bundled { .. } => Ok((
                    200,
                    serde_json::to_string(&LocalWorkerHealthResponseV1 {
                        role: LocalServiceRoleV1::Router,
                        role_label: "bundled".to_owned(),
                        bind_url: "bundled".to_owned(),
                        status: "ready".to_owned(),
                        startup_epoch: "local-dev".to_owned(),
                        config_branch: "bundled_single_server".to_owned(),
                    })?,
                )),
            };
        }
        return local_dev_http_error_body_v1(role, path, 405, "method not allowed");
    }

    if path == LOCAL_ROUTER_NORMAL_SIGNING_PREPARE_PATH_V2 {
        return local_dev_router_public_signing_route_v1(
            topology,
            request,
            |router| match router {
                LocalDevRouterTargetV1::FourWorker { signing_worker_url } => {
                    handle_local_router_normal_signing_round1_prepare_request_json_v1(
                        signing_worker_url,
                        &request.body,
                    )
                }
                LocalDevRouterTargetV1::Bundled { signing_worker } => {
                    handle_local_router_normal_signing_round1_prepare_request_in_process_json_v1(
                        signing_worker,
                        &request.body,
                    )
                }
            },
        );
    }

    if path == LOCAL_ROUTER_NORMAL_SIGNING_PATH_V2 {
        return local_dev_router_public_signing_route_v1(
            topology,
            request,
            |router| match router {
                LocalDevRouterTargetV1::FourWorker { signing_worker_url } => {
                    handle_local_router_normal_signing_request_json_v1(
                        signing_worker_url,
                        &request.body,
                    )
                }
                LocalDevRouterTargetV1::Bundled { signing_worker } => {
                    handle_local_router_normal_signing_request_in_process_json_v1(
                        signing_worker,
                        &request.body,
                    )
                }
            },
        );
    }

    if path == LOCAL_ROUTER_ECDSA_HSS_SIGNING_PREPARE_PATH_V1 {
        return local_dev_router_public_signing_route_v1(
            topology,
            request,
            |router| match router {
                LocalDevRouterTargetV1::FourWorker { signing_worker_url } => {
                    handle_local_router_ecdsa_hss_prepare_request_json_v1(
                        signing_worker_url,
                        &request.body,
                    )
                }
                LocalDevRouterTargetV1::Bundled { signing_worker } => {
                    handle_local_router_ecdsa_hss_prepare_request_in_process_json_v1(
                        signing_worker,
                        &request.body,
                    )
                }
            },
        );
    }

    if path == LOCAL_ROUTER_ECDSA_HSS_SIGNING_PATH_V1 {
        return local_dev_router_public_signing_route_v1(
            topology,
            request,
            |router| match router {
                LocalDevRouterTargetV1::FourWorker { signing_worker_url } => {
                    handle_local_router_ecdsa_hss_finalize_request_json_v1(
                        signing_worker_url,
                        &request.body,
                    )
                }
                LocalDevRouterTargetV1::Bundled { signing_worker } => {
                    handle_local_router_ecdsa_hss_finalize_request_in_process_json_v1(
                        signing_worker,
                        &request.body,
                    )
                }
            },
        );
    }

    if path == LOCAL_DERIVER_A_PEER_PATH_V1 {
        return local_dev_deriver_peer_route_v1(topology, request, LocalServiceRoleV1::DeriverA);
    }

    if path == LOCAL_DERIVER_B_PEER_PATH_V1 {
        return local_dev_deriver_peer_route_v1(topology, request, LocalServiceRoleV1::DeriverB);
    }

    if path == LOCAL_SIGNING_WORKER_ACTIVATION_PATH_V1 {
        return local_dev_signing_worker_activation_route_v1(topology, request);
    }

    if path == LOCAL_SIGNING_WORKER_NORMAL_SIGNING_PREPARE_PATH_V1 {
        return local_dev_signing_worker_private_route_v1(topology, request, |signing_worker| {
            handle_local_signing_worker_normal_signing_round1_prepare_json_v1(
                signing_worker,
                LocalServiceRoleV1::SigningWorker,
                path,
                &request.body,
            )
        });
    }

    if path == LOCAL_SIGNING_WORKER_NORMAL_SIGNING_PRESIGN_POOL_PREPARE_PATH_V1 {
        return local_dev_signing_worker_private_route_v1(topology, request, |signing_worker| {
            handle_local_signing_worker_normal_signing_presign_pool_prepare_json_v1(
                signing_worker,
                LocalServiceRoleV1::SigningWorker,
                path,
                &request.body,
            )
        });
    }

    if path == LOCAL_SIGNING_WORKER_NORMAL_SIGNING_PRESIGN_POOL_PATH_V1 {
        return local_dev_signing_worker_private_route_v1(topology, request, |signing_worker| {
            handle_local_signing_worker_normal_signing_presign_pool_hit_json_v1(
                signing_worker,
                LocalServiceRoleV1::SigningWorker,
                path,
                &request.body,
            )
        });
    }

    if path == LOCAL_SIGNING_WORKER_NORMAL_SIGNING_PATH_V1 {
        return local_dev_signing_worker_private_route_v1(topology, request, |signing_worker| {
            handle_local_signing_worker_normal_signing_json_v1(
                signing_worker,
                LocalServiceRoleV1::SigningWorker,
                path,
                &request.body,
            )
        });
    }

    if path == LOCAL_SIGNING_WORKER_ECDSA_HSS_PRESIGNATURE_POOL_PUT_PATH_V1 {
        return local_dev_signing_worker_private_route_v1(topology, request, |signing_worker| {
            handle_local_signing_worker_ecdsa_hss_presignature_pool_put_json_v1(
                signing_worker,
                LocalServiceRoleV1::SigningWorker,
                path,
                &request.body,
            )
        });
    }

    if path == LOCAL_SIGNING_WORKER_ECDSA_HSS_SIGNING_PREPARE_PATH_V1 {
        return local_dev_signing_worker_private_route_v1(topology, request, |signing_worker| {
            handle_local_signing_worker_ecdsa_hss_prepare_json_v1(
                signing_worker,
                LocalServiceRoleV1::SigningWorker,
                path,
                &request.body,
            )
        });
    }

    if path == LOCAL_SIGNING_WORKER_ECDSA_HSS_SIGNING_PATH_V1 {
        return local_dev_signing_worker_private_route_v1(topology, request, |signing_worker| {
            handle_local_signing_worker_ecdsa_hss_finalize_json_v1(
                signing_worker,
                LocalServiceRoleV1::SigningWorker,
                path,
                &request.body,
            )
        });
    }

    match topology {
        LocalDevHttpTopologyV1::FourWorker(config) => {
            if local_worker_owns_path_v1(config.role(), path) {
                if method == "POST" {
                    local_dev_http_error_body_v1(
                        config.role(),
                        path,
                        501,
                        "local protocol route is not implemented yet",
                    )
                } else {
                    local_dev_http_error_body_v1(config.role(), path, 405, "method not allowed")
                }
            } else {
                local_dev_http_error_body_v1(
                    config.role(),
                    path,
                    404,
                    "path is not owned by this worker",
                )
            }
        }
        LocalDevHttpTopologyV1::Bundled { .. } => {
            if local_worker_owns_path_v1(LocalServiceRoleV1::Router, path) {
                local_dev_http_error_body_v1(
                    LocalServiceRoleV1::Router,
                    path,
                    501,
                    "local protocol route is not implemented yet",
                )
            } else {
                local_dev_http_error_body_v1(
                    LocalServiceRoleV1::Router,
                    path,
                    404,
                    "path is not owned by bundled server",
                )
            }
        }
    }
}

impl LocalDevHttpTopologyV1<'_> {
    fn local_http_error_role(self) -> LocalServiceRoleV1 {
        match self {
            LocalDevHttpTopologyV1::FourWorker(config) => config.role(),
            LocalDevHttpTopologyV1::Bundled { .. } => LocalServiceRoleV1::Router,
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum LocalDevRouterTargetV1<'a> {
    FourWorker {
        signing_worker_url: &'a str,
    },
    Bundled {
        signing_worker: &'a LocalSigningWorkerConfigV1,
    },
}

fn local_dev_router_target_v1(
    topology: LocalDevHttpTopologyV1<'_>,
) -> Option<LocalDevRouterTargetV1<'_>> {
    match topology {
        LocalDevHttpTopologyV1::FourWorker(LocalWorkerRoleConfigV1::Router(router_config)) => {
            Some(LocalDevRouterTargetV1::FourWorker {
                signing_worker_url: &router_config.signing_worker_url,
            })
        }
        LocalDevHttpTopologyV1::FourWorker(_) => None,
        LocalDevHttpTopologyV1::Bundled { signing_worker } => {
            Some(LocalDevRouterTargetV1::Bundled { signing_worker })
        }
    }
}

fn local_dev_signing_worker_config_v1(
    topology: LocalDevHttpTopologyV1<'_>,
) -> Option<&LocalSigningWorkerConfigV1> {
    match topology {
        LocalDevHttpTopologyV1::FourWorker(LocalWorkerRoleConfigV1::SigningWorker(config)) => {
            Some(config)
        }
        LocalDevHttpTopologyV1::FourWorker(_) => None,
        LocalDevHttpTopologyV1::Bundled { signing_worker } => Some(signing_worker),
    }
}

fn local_dev_router_public_signing_route_v1(
    topology: LocalDevHttpTopologyV1<'_>,
    request: &LocalDevHttpRequestPartsV1,
    handler: impl FnOnce(LocalDevRouterTargetV1<'_>) -> RouterAbProtocolResult<String>,
) -> Result<(u16, String), Box<dyn std::error::Error>> {
    let role = topology.local_http_error_role();
    let path = request.path.as_str();
    if request.method != "POST" {
        return local_dev_http_error_body_v1(role, path, 405, "method not allowed");
    }
    let Some(router) = local_dev_router_target_v1(topology) else {
        return local_dev_http_error_body_v1(role, path, 404, "path is not owned by this worker");
    };
    if let Err(message) = require_local_dev_normal_signing_wallet_session_v2(request) {
        return local_dev_http_error_body_v1(role, path, 401, message);
    }
    local_dev_protocol_response_v1(role, path, handler(router))
}

fn local_dev_deriver_peer_route_v1(
    topology: LocalDevHttpTopologyV1<'_>,
    request: &LocalDevHttpRequestPartsV1,
    route_role: LocalServiceRoleV1,
) -> Result<(u16, String), Box<dyn std::error::Error>> {
    let path = request.path.as_str();
    if request.method != "POST" {
        return local_dev_http_error_body_v1(route_role, path, 405, "method not allowed");
    }
    let owned = match topology {
        LocalDevHttpTopologyV1::FourWorker(config) => config.role() == route_role,
        LocalDevHttpTopologyV1::Bundled { .. } => true,
    };
    if !owned {
        return local_dev_http_error_body_v1(
            topology.local_http_error_role(),
            path,
            404,
            "path is not owned by this worker",
        );
    }
    local_dev_protocol_response_v1(
        route_role,
        path,
        handle_local_deriver_peer_message_json_v1(route_role, path, &request.body),
    )
}

fn local_dev_signing_worker_activation_route_v1(
    topology: LocalDevHttpTopologyV1<'_>,
    request: &LocalDevHttpRequestPartsV1,
) -> Result<(u16, String), Box<dyn std::error::Error>> {
    let path = request.path.as_str();
    if request.method != "POST" {
        return local_dev_http_error_body_v1(
            LocalServiceRoleV1::SigningWorker,
            path,
            405,
            "method not allowed",
        );
    }
    if local_dev_signing_worker_config_v1(topology).is_none() {
        return local_dev_http_error_body_v1(
            topology.local_http_error_role(),
            path,
            404,
            "path is not owned by this worker",
        );
    }
    local_dev_protocol_response_v1(
        LocalServiceRoleV1::SigningWorker,
        path,
        handle_local_signing_worker_activation_json_v1(
            LocalServiceRoleV1::SigningWorker,
            path,
            &request.body,
        ),
    )
}

fn local_dev_signing_worker_private_route_v1(
    topology: LocalDevHttpTopologyV1<'_>,
    request: &LocalDevHttpRequestPartsV1,
    handler: impl FnOnce(&LocalSigningWorkerConfigV1) -> RouterAbProtocolResult<String>,
) -> Result<(u16, String), Box<dyn std::error::Error>> {
    let path = request.path.as_str();
    if request.method != "POST" {
        return local_dev_http_error_body_v1(
            LocalServiceRoleV1::SigningWorker,
            path,
            405,
            "method not allowed",
        );
    }
    let Some(signing_worker) = local_dev_signing_worker_config_v1(topology) else {
        return local_dev_http_error_body_v1(
            topology.local_http_error_role(),
            path,
            404,
            "path is not owned by this worker",
        );
    };
    if let Err(message) = require_local_dev_internal_service_auth_v1(request) {
        return local_dev_http_error_body_v1(LocalServiceRoleV1::SigningWorker, path, 401, message);
    }
    local_dev_protocol_response_v1(
        LocalServiceRoleV1::SigningWorker,
        path,
        handler(signing_worker),
    )
}

fn local_dev_protocol_response_v1(
    role: LocalServiceRoleV1,
    path: &str,
    result: RouterAbProtocolResult<String>,
) -> Result<(u16, String), Box<dyn std::error::Error>> {
    match result {
        Ok(response) => Ok((200, response)),
        Err(error) => local_dev_http_route_error_v1(role, path, error),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalDevHttpRequestPartsV1 {
    pub method: String,
    pub path: String,
    pub authorization: Option<String>,
    pub internal_service_auth: Option<String>,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LocalDevHttpErrorBodyV1 {
    pub role: LocalServiceRoleV1,
    pub path: String,
    pub status: u16,
    pub error: String,
}

pub fn read_local_dev_http_request_v1(
    stream: &mut TcpStream,
) -> Result<LocalDevHttpRequestPartsV1, Box<dyn std::error::Error>> {
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
    let authorization = local_dev_http_named_header_v1(headers, "authorization");
    let internal_service_auth = local_dev_http_named_header_v1(
        headers,
        super::LOCAL_ROUTER_AB_INTERNAL_SERVICE_AUTH_HEADER_V1,
    );
    let content_length = local_dev_http_content_length_v1(headers)?;
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
    Ok(LocalDevHttpRequestPartsV1 {
        method,
        path,
        authorization,
        internal_service_auth,
        body: request[body_start..body_start + content_length].to_vec(),
    })
}

pub fn require_local_dev_normal_signing_wallet_session_v2(
    request: &LocalDevHttpRequestPartsV1,
) -> Result<(), &'static str> {
    super::validate_local_router_wallet_session_authorization_header_v2(
        request.authorization.as_deref(),
    )
}

pub fn require_local_dev_internal_service_auth_v1(
    request: &LocalDevHttpRequestPartsV1,
) -> Result<(), &'static str> {
    let expected = super::local_router_ab_internal_service_auth_secret_v1();
    match request.internal_service_auth.as_deref() {
        Some(actual) if actual == expected => Ok(()),
        Some(_) => Err("local Router A/B internal service-auth header is invalid"),
        None => Err("local Router A/B internal service-auth header is missing"),
    }
}

pub fn write_local_dev_http_response_v1(
    stream: &mut TcpStream,
    status: u16,
    body: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
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

pub fn local_dev_http_error_body_v1(
    role: LocalServiceRoleV1,
    path: &str,
    status: u16,
    error: &str,
) -> Result<(u16, String), Box<dyn std::error::Error>> {
    Ok((
        status,
        serde_json::to_string(&LocalDevHttpErrorBodyV1 {
            role,
            path: path.to_owned(),
            status,
            error: error.to_owned(),
        })?,
    ))
}

pub fn local_dev_http_route_error_v1(
    role: LocalServiceRoleV1,
    path: &str,
    error: RouterAbProtocolError,
) -> Result<(u16, String), Box<dyn std::error::Error>> {
    local_dev_http_error_body_v1(
        role,
        path,
        400,
        &format!("{:?}: {}", error.code(), error.message()),
    )
}

fn local_dev_http_named_header_v1(headers: &str, target_name: &str) -> Option<String> {
    for line in headers.lines().skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case(target_name) {
            return Some(value.trim().to_owned());
        }
    }
    None
}

fn local_dev_http_content_length_v1(headers: &str) -> Result<usize, Box<dyn std::error::Error>> {
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
