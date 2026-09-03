use router_ab_core::{LocalServiceRoleV1, RouterAbProtocolError, RouterAbProtocolResult};
use serde::Serialize;
use std::{
    io::{Read, Write},
    net::TcpStream,
};

use super::{
    handle_local_deriver_peer_message_json_v1,
    handle_local_signing_worker_router_ab_ecdsa_derivation_finalize_json_v1,
    handle_local_signing_worker_router_ab_ecdsa_derivation_prepare_json_v1,
    handle_local_signing_worker_router_ab_ecdsa_derivation_presignature_pool_put_json_v1,
    local_worker_health_response_json_v1, local_worker_owns_path_v1, LocalRouterWorkerConfigV1,
    LocalSigningWorkerConfigV1, LocalWorkerRoleConfigV1, LOCAL_DERIVER_A_PEER_PATH,
    LOCAL_DERIVER_B_PEER_PATH, LOCAL_ROUTER_ED25519_YAO_EXECUTE_PATH,
    LOCAL_ROUTER_ED25519_YAO_RECOVERY_PROMOTE_PATH,
    LOCAL_SIGNING_WORKER_ROUTER_AB_ECDSA_DERIVATION_PRESIGNATURE_POOL_PUT_PATH,
    LOCAL_SIGNING_WORKER_ROUTER_AB_ECDSA_DERIVATION_SIGNING_PATH,
    LOCAL_SIGNING_WORKER_ROUTER_AB_ECDSA_DERIVATION_SIGNING_PREPARE_PATH, LOCAL_WORKER_HEALTH_PATH,
    LOCAL_WORKER_READY_PATH,
};

#[derive(Debug, Clone, Copy)]
pub enum LocalDevHttpTopologyV1<'a> {
    /// Rust local Router process. The executable installs the native
    /// coordinator after constructing this authenticated boundary.
    Router(&'a LocalRouterWorkerConfigV1),
    /// Private role worker process.
    FourWorker(&'a LocalWorkerRoleConfigV1),
}

/// Native Router request handler seam.
///
/// The optional dispatcher installs Router-owned Yao routes without changing
/// HTTP authentication, ownership, or role-secret boundaries. Calls for
/// routes it does not implement retain the explicit unsupported response.
pub trait LocalRouterRequestDispatcherV1 {
    /// Handles one authenticated Router-owned request.
    ///
    /// Returning `None` preserves the explicit unsupported response for a
    /// route the installed coordinator does not serve.
    fn dispatch(
        &self,
        config: &LocalRouterWorkerConfigV1,
        request: &LocalDevHttpRequestPartsV1,
    ) -> Result<Option<(u16, String)>, Box<dyn std::error::Error>>;
}

pub fn local_dev_http_handle_request_v1(
    topology: LocalDevHttpTopologyV1<'_>,
    request: &LocalDevHttpRequestPartsV1,
) -> Result<(u16, String), Box<dyn std::error::Error>> {
    local_dev_http_handle_request_with_dispatcher_v1(topology, request, None)
}

/// Handles one local request with an optional native Router coordinator.
pub fn local_dev_http_handle_request_with_dispatcher_v1(
    topology: LocalDevHttpTopologyV1<'_>,
    request: &LocalDevHttpRequestPartsV1,
    dispatcher: Option<&dyn LocalRouterRequestDispatcherV1>,
) -> Result<(u16, String), Box<dyn std::error::Error>> {
    let method = request.method.as_str();
    let path = request.path.as_str();

    if path == LOCAL_WORKER_HEALTH_PATH || path == LOCAL_WORKER_READY_PATH {
        let role = topology.local_http_error_role();
        if method == "GET" {
            return Ok((
                200,
                local_worker_health_response_json_v1(&topology.as_role_config())?,
            ));
        }
        return local_dev_http_error_body_v1(role, path, 405, "method not allowed");
    }

    if let LocalDevHttpTopologyV1::Router(config) = topology {
        if local_worker_owns_path_v1(LocalServiceRoleV1::Router, path) {
            return local_dev_router_request_v1(config, request, dispatcher);
        }
        return local_dev_http_error_body_v1(
            LocalServiceRoleV1::Router,
            path,
            404,
            "path is not owned by the local Router",
        );
    }

    if path == LOCAL_DERIVER_A_PEER_PATH {
        return local_dev_deriver_peer_route_v1(topology, request, LocalServiceRoleV1::DeriverA);
    }

    if path == LOCAL_DERIVER_B_PEER_PATH {
        return local_dev_deriver_peer_route_v1(topology, request, LocalServiceRoleV1::DeriverB);
    }

    if path == LOCAL_SIGNING_WORKER_ROUTER_AB_ECDSA_DERIVATION_PRESIGNATURE_POOL_PUT_PATH {
        return local_dev_signing_worker_private_route_v1(topology, request, |signing_worker| {
            handle_local_signing_worker_router_ab_ecdsa_derivation_presignature_pool_put_json_v1(
                signing_worker,
                LocalServiceRoleV1::SigningWorker,
                path,
                &request.body,
            )
        });
    }

    if path == LOCAL_SIGNING_WORKER_ROUTER_AB_ECDSA_DERIVATION_SIGNING_PREPARE_PATH {
        return local_dev_signing_worker_private_route_v1(topology, request, |signing_worker| {
            handle_local_signing_worker_router_ab_ecdsa_derivation_prepare_json_v1(
                signing_worker,
                LocalServiceRoleV1::SigningWorker,
                path,
                &request.body,
            )
        });
    }

    if path == LOCAL_SIGNING_WORKER_ROUTER_AB_ECDSA_DERIVATION_SIGNING_PATH {
        return local_dev_signing_worker_private_route_v1(topology, request, |signing_worker| {
            handle_local_signing_worker_router_ab_ecdsa_derivation_finalize_json_v1(
                signing_worker,
                LocalServiceRoleV1::SigningWorker,
                path,
                &request.body,
            )
        });
    }

    let LocalDevHttpTopologyV1::FourWorker(config) = topology else {
        unreachable!("Router topology is handled before role dispatch")
    };
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
        local_dev_http_error_body_v1(config.role(), path, 404, "path is not owned by this worker")
    }
}

impl LocalDevHttpTopologyV1<'_> {
    fn local_http_error_role(self) -> LocalServiceRoleV1 {
        match self {
            Self::Router(_) => LocalServiceRoleV1::Router,
            Self::FourWorker(config) => config.role(),
        }
    }

    fn as_role_config(&self) -> LocalWorkerRoleConfigV1 {
        match self {
            Self::Router(config) => LocalWorkerRoleConfigV1::Router((*config).clone()),
            Self::FourWorker(config) => (*config).clone(),
        }
    }
}

/// Dispatches one Router-owned request through an optional native coordinator.
pub fn local_dev_router_request_with_dispatcher_v1(
    config: &LocalRouterWorkerConfigV1,
    request: &LocalDevHttpRequestPartsV1,
    dispatcher: &dyn LocalRouterRequestDispatcherV1,
) -> Result<(u16, String), Box<dyn std::error::Error>> {
    local_dev_router_request_v1(config, request, Some(dispatcher))
}

fn local_dev_router_request_v1(
    config: &LocalRouterWorkerConfigV1,
    request: &LocalDevHttpRequestPartsV1,
    dispatcher: Option<&dyn LocalRouterRequestDispatcherV1>,
) -> Result<(u16, String), Box<dyn std::error::Error>> {
    if request.method != "POST" {
        return local_dev_http_error_body_v1(
            LocalServiceRoleV1::Router,
            &request.path,
            405,
            "method not allowed",
        );
    }
    if let Err(message) = require_local_dev_router_internal_service_auth_v1(config, request) {
        return local_dev_http_error_body_v1(
            LocalServiceRoleV1::Router,
            &request.path,
            401,
            message,
        );
    }
    if let Some(dispatcher) = dispatcher {
        if let Some(response) = dispatcher.dispatch(config, request)? {
            return Ok(response);
        }
    }
    let error = match request.path.as_str() {
        LOCAL_ROUTER_ED25519_YAO_EXECUTE_PATH => {
            "Rust local Router Yao execution is not served; use strict Wrangler local mode"
        }
        LOCAL_ROUTER_ED25519_YAO_RECOVERY_PROMOTE_PATH => {
            "Rust local Router recovery promotion is not served; use strict Wrangler local mode"
        }
        _ => "Rust local Router route is not served; use strict Wrangler local mode",
    };
    local_dev_http_error_body_v1(LocalServiceRoleV1::Router, &request.path, 501, error)
}

fn require_local_dev_router_internal_service_auth_v1(
    config: &LocalRouterWorkerConfigV1,
    request: &LocalDevHttpRequestPartsV1,
) -> Result<(), &'static str> {
    match request.internal_service_auth.as_deref() {
        Some(actual)
            if super::local_router_ab_internal_service_auth_matches_v1(
                actual,
                &config.internal_service_auth,
            ) =>
        {
            Ok(())
        }
        Some(_) => Err("local Router internal service-auth header is invalid"),
        None => Err("local Router internal service-auth header is missing"),
    }
}

fn local_dev_signing_worker_config_v1(
    topology: LocalDevHttpTopologyV1<'_>,
) -> Option<&LocalSigningWorkerConfigV1> {
    let LocalDevHttpTopologyV1::FourWorker(config) = topology else {
        return None;
    };
    match config {
        LocalWorkerRoleConfigV1::SigningWorker(config) => Some(config),
        _ => None,
    }
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
    let LocalDevHttpTopologyV1::FourWorker(config) = topology else {
        unreachable!("Router topology is handled before role dispatch")
    };
    let owned = config.role() == route_role;
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

pub fn require_local_dev_internal_service_auth_v1(
    request: &LocalDevHttpRequestPartsV1,
) -> Result<(), &'static str> {
    let expected = super::local_router_ab_internal_service_auth_secret_v1();
    match request.internal_service_auth.as_deref() {
        Some(actual)
            if super::local_router_ab_internal_service_auth_matches_v1(actual, &expected) =>
        {
            Ok(())
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    struct RecordingDispatcher {
        calls: Cell<u32>,
    }

    impl LocalRouterRequestDispatcherV1 for RecordingDispatcher {
        fn dispatch(
            &self,
            _config: &LocalRouterWorkerConfigV1,
            _request: &LocalDevHttpRequestPartsV1,
        ) -> Result<Option<(u16, String)>, Box<dyn std::error::Error>> {
            self.calls.set(self.calls.get() + 1);
            Ok(Some((200, "{\"status\":\"handled\"}".to_owned())))
        }
    }

    struct EmptyDispatcher;

    impl LocalRouterRequestDispatcherV1 for EmptyDispatcher {
        fn dispatch(
            &self,
            _config: &LocalRouterWorkerConfigV1,
            _request: &LocalDevHttpRequestPartsV1,
        ) -> Result<Option<(u16, String)>, Box<dyn std::error::Error>> {
            Ok(None)
        }
    }

    fn router_config() -> LocalRouterWorkerConfigV1 {
        LocalRouterWorkerConfigV1 {
            public_url: "http://127.0.0.1:4102".to_owned(),
            deriver_a_url: "http://127.0.0.1:4103".to_owned(),
            deriver_b_url: "http://127.0.0.1:4104".to_owned(),
            signing_worker_url: "http://127.0.0.1:4105".to_owned(),
            deriver_a_ed25519_yao_input_public_key: "x25519:a".to_owned(),
            deriver_b_ed25519_yao_input_public_key: "x25519:b".to_owned(),
            signing_worker_ed25519_yao_recipient_public_key: "x25519:c".to_owned(),
            signing_worker_id: "local-signing-worker".to_owned(),
            internal_service_auth: "local-test-auth".to_owned(),
            tenant_root_resolver: Default::default(),
        }
    }

    fn router_request(config: &LocalRouterWorkerConfigV1) -> LocalDevHttpRequestPartsV1 {
        LocalDevHttpRequestPartsV1 {
            method: "POST".to_owned(),
            path: LOCAL_ROUTER_ED25519_YAO_EXECUTE_PATH.to_owned(),
            authorization: None,
            internal_service_auth: Some(config.internal_service_auth.clone()),
            body: Vec::new(),
        }
    }

    #[test]
    fn router_dispatcher_runs_only_after_internal_authentication() {
        let config = router_config();
        let dispatcher = RecordingDispatcher {
            calls: Cell::new(0),
        };
        let request = router_request(&config);
        let response = local_dev_router_request_with_dispatcher_v1(&config, &request, &dispatcher)
            .expect("authenticated request should dispatch");
        assert_eq!(response, (200, "{\"status\":\"handled\"}".to_owned()));
        assert_eq!(dispatcher.calls.get(), 1);

        let unauthorized = LocalDevHttpRequestPartsV1 {
            internal_service_auth: Some("wrong".to_owned()),
            ..request
        };
        let (status, _) =
            local_dev_router_request_with_dispatcher_v1(&config, &unauthorized, &dispatcher)
                .expect("unauthorized request should return a typed HTTP error");
        assert_eq!(status, 401);
        assert_eq!(dispatcher.calls.get(), 1);
    }

    #[test]
    fn dispatcher_can_leave_route_explicitly_unsupported() {
        let config = router_config();
        let request = router_request(&config);
        let fallback =
            local_dev_router_request_with_dispatcher_v1(&config, &request, &EmptyDispatcher)
                .expect("empty dispatcher should preserve fallback");
        assert_eq!(fallback.0, 501);
        assert!(fallback.1.contains("strict Wrangler local mode"));
    }
}
