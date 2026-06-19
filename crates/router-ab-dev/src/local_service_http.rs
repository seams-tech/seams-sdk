use router_ab_core::{
    CanonicalWireBytesV1, LocalHttpPathV1, LocalServiceRoleV1, RouterAbProtocolError,
    RouterAbProtocolErrorCode, RouterAbProtocolResult,
};
use serde::{de::DeserializeOwned, Serialize};
use std::{
    io::{Read, Write},
    net::{Shutdown, TcpStream},
    time::Duration,
};

/// Parsed local HTTP service-binding endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalHttpServiceBindingEndpointV1 {
    /// Role that owns the target path.
    pub owner: LocalServiceRoleV1,
    /// Full URL requested by the local transport.
    pub url: String,
    /// Host header value.
    pub host_header: String,
    /// Host:port address used by `TcpStream`.
    pub bind_addr: String,
    /// Production-style request path.
    pub path: String,
}

/// Blocking local HTTP client for service-binding parity tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalHttpServiceBindingClientV1 {
    timeout: Duration,
}

impl LocalHttpServiceBindingClientV1 {
    /// Creates a local HTTP service-binding client with a non-zero timeout.
    pub fn new(timeout: Duration) -> RouterAbProtocolResult<Self> {
        if timeout.is_zero() {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "local HTTP service-binding timeout must be non-zero",
            ));
        }
        Ok(Self { timeout })
    }

    /// Posts canonical wire bytes to one checked local service-binding path.
    pub fn post_canonical_wire_bytes_v1(
        &self,
        base_url: &str,
        path: LocalHttpPathV1,
        body: &CanonicalWireBytesV1,
    ) -> RouterAbProtocolResult<CanonicalWireBytesV1> {
        let endpoint = local_http_service_binding_endpoint_v1(base_url, path)?;
        let response_body = self.post_bytes_to_endpoint_v1(
            &endpoint,
            super::LOCAL_HTTP_CANONICAL_WIRE_CONTENT_TYPE_V1,
            body.as_bytes(),
        )?;
        CanonicalWireBytesV1::new(response_body)
    }

    /// Posts JSON to one checked local service-binding path and parses JSON response.
    pub fn post_json_v1<Request, Response>(
        &self,
        base_url: &str,
        path: LocalHttpPathV1,
        body: &Request,
    ) -> RouterAbProtocolResult<Response>
    where
        Request: Serialize,
        Response: DeserializeOwned,
    {
        let endpoint = local_http_service_binding_endpoint_v1(base_url, path)?;
        let request_body = serde_json::to_vec(body).map_err(|error| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                format!("local HTTP service-binding JSON request serialization failed: {error}"),
            )
        })?;
        let response_body = self.post_bytes_to_endpoint_v1(
            &endpoint,
            super::LOCAL_HTTP_JSON_CONTENT_TYPE_V1,
            &request_body,
        )?;
        serde_json::from_slice(&response_body).map_err(|error| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                format!("local HTTP service-binding JSON response parse failed: {error}"),
            )
        })
    }

    fn post_bytes_to_endpoint_v1(
        &self,
        endpoint: &LocalHttpServiceBindingEndpointV1,
        content_type: &str,
        body: &[u8],
    ) -> RouterAbProtocolResult<Vec<u8>> {
        let mut stream = TcpStream::connect(&endpoint.bind_addr).map_err(|error| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalHttpRequest,
                format!(
                    "local HTTP service-binding connect to {} failed: {error}",
                    endpoint.bind_addr
                ),
            )
        })?;
        stream
            .set_read_timeout(Some(self.timeout))
            .map_err(super::map_local_http_io_error_v1)?;
        stream
            .set_write_timeout(Some(self.timeout))
            .map_err(super::map_local_http_io_error_v1)?;

        write!(
            stream,
            "POST {} HTTP/1.1\r\nhost: {}\r\ncontent-type: {}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
            endpoint.path,
            endpoint.host_header,
            content_type,
            body.len()
        )
        .map_err(super::map_local_http_io_error_v1)?;
        stream
            .write_all(body)
            .map_err(super::map_local_http_io_error_v1)?;
        stream.flush().map_err(super::map_local_http_io_error_v1)?;
        stream
            .shutdown(Shutdown::Write)
            .map_err(super::map_local_http_io_error_v1)?;

        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .map_err(super::map_local_http_io_error_v1)?;
        let (status, response_body) = super::split_local_http_response_v1(&response)?;
        if !(200..=299).contains(&status) {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalHttpRequest,
                format!("local HTTP service-binding request failed with status {status}"),
            ));
        }
        Ok(response_body)
    }
}

impl Default for LocalHttpServiceBindingClientV1 {
    fn default() -> Self {
        Self {
            timeout: Duration::from_millis(super::LOCAL_HTTP_SERVICE_BINDING_TIMEOUT_MS_V1),
        }
    }
}

/// Returns the production-style path for a checked local transport path.
pub fn local_http_service_binding_path_v1(path: LocalHttpPathV1) -> &'static str {
    match path {
        LocalHttpPathV1::RouterToSignerA => super::LOCAL_DERIVER_A_PRIVATE_PATH_V1,
        LocalHttpPathV1::RouterToSignerB => super::LOCAL_DERIVER_B_PRIVATE_PATH_V1,
        LocalHttpPathV1::SignerAToSignerB => super::LOCAL_DERIVER_B_PEER_PATH_V1,
        LocalHttpPathV1::SignerBToSignerA => super::LOCAL_DERIVER_A_PEER_PATH_V1,
    }
}

/// Returns the destination role that owns a checked local transport path.
pub fn local_http_service_binding_owner_v1(path: LocalHttpPathV1) -> LocalServiceRoleV1 {
    match path {
        LocalHttpPathV1::RouterToSignerA | LocalHttpPathV1::SignerBToSignerA => {
            LocalServiceRoleV1::DeriverA
        }
        LocalHttpPathV1::RouterToSignerB | LocalHttpPathV1::SignerAToSignerB => {
            LocalServiceRoleV1::DeriverB
        }
    }
}

/// Builds the full production-style local service-binding URL for a base URL.
pub fn local_http_service_binding_url_v1(
    base_url: &str,
    path: LocalHttpPathV1,
) -> RouterAbProtocolResult<String> {
    super::require_non_empty("local HTTP service-binding base URL", base_url)?;
    let route_path = local_http_service_binding_path_v1(path);
    let base = base_url.trim_end_matches('/');
    Ok(format!("{base}{route_path}"))
}

/// Builds the parsed endpoint used by the blocking local HTTP transport.
pub fn local_http_service_binding_endpoint_v1(
    base_url: &str,
    path: LocalHttpPathV1,
) -> RouterAbProtocolResult<LocalHttpServiceBindingEndpointV1> {
    let url = local_http_service_binding_url_v1(base_url, path)?;
    let parts = super::parse_http_url_parts_v1(&url)?;
    let owner = local_http_service_binding_owner_v1(path);
    if !super::local_worker_owns_path_v1(owner, &parts.path) {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalHttpRequest,
            format!(
                "local HTTP service-binding path {} is not owned by {}",
                parts.path,
                owner.as_str()
            ),
        ));
    }
    Ok(LocalHttpServiceBindingEndpointV1 {
        owner,
        url,
        host_header: parts.authority.clone(),
        bind_addr: parts.authority,
        path: parts.path,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LocalHttpPostResponseV1 {
    status: u16,
    body: Vec<u8>,
}

pub(crate) fn local_http_post_signing_worker_private_json_v1<TReq, TResp>(
    signing_worker_url: &str,
    path: &str,
    request: &TReq,
    label: &str,
) -> RouterAbProtocolResult<TResp>
where
    TReq: Serialize,
    TResp: DeserializeOwned,
{
    super::require_non_empty("local SigningWorker private request label", label)?;
    let url = format!("{}{}", signing_worker_url.trim_end_matches('/'), path);
    let service_auth = super::local_router_ab_internal_service_auth_secret_v1();
    let response = local_http_post_json_url_with_headers_v1(
        &url,
        request,
        &[(
            super::LOCAL_ROUTER_AB_INTERNAL_SERVICE_AUTH_HEADER_V1,
            service_auth.as_str(),
        )],
        Duration::from_millis(super::LOCAL_HTTP_SERVICE_BINDING_TIMEOUT_MS_V1),
    )?;
    if response.status != 200 {
        let body = String::from_utf8_lossy(&response.body);
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalHttpRequest,
            format!(
                "{label} expected SigningWorker status 200, received {}: {}",
                response.status, body
            ),
        ));
    }
    serde_json::from_slice::<TResp>(&response.body).map_err(|error| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("{label} response JSON parse failed: {error}"),
        )
    })
}

fn local_http_post_json_url_with_headers_v1<T: Serialize>(
    url: &str,
    body: &T,
    headers: &[(&str, &str)],
    timeout: Duration,
) -> RouterAbProtocolResult<LocalHttpPostResponseV1> {
    if timeout.is_zero() {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "local HTTP POST timeout must be non-zero",
        ));
    }
    let parts = super::parse_http_url_parts_v1(url)?;
    for (name, value) in headers {
        super::require_non_empty("local HTTP header name", name)?;
        super::require_no_ascii_whitespace_v1("local HTTP header name", name)?;
        super::require_no_ascii_whitespace_v1("local HTTP header value", value)?;
    }
    let request_body = serde_json::to_vec(body).map_err(|error| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("local HTTP POST JSON request serialization failed: {error}"),
        )
    })?;
    let mut stream =
        TcpStream::connect(&parts.authority).map_err(super::map_local_http_io_error_v1)?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(super::map_local_http_io_error_v1)?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(super::map_local_http_io_error_v1)?;
    write!(
        stream,
        "POST {} HTTP/1.1\r\nhost: {}\r\ncontent-type: {}\r\n",
        parts.path,
        parts.authority,
        super::LOCAL_HTTP_JSON_CONTENT_TYPE_V1,
    )
    .map_err(super::map_local_http_io_error_v1)?;
    for (name, value) in headers {
        write!(stream, "{name}: {value}\r\n").map_err(super::map_local_http_io_error_v1)?;
    }
    write!(
        stream,
        "content-length: {}\r\nconnection: close\r\n\r\n",
        request_body.len()
    )
    .map_err(super::map_local_http_io_error_v1)?;
    stream
        .write_all(&request_body)
        .map_err(super::map_local_http_io_error_v1)?;
    stream.flush().map_err(super::map_local_http_io_error_v1)?;
    stream
        .shutdown(Shutdown::Write)
        .map_err(super::map_local_http_io_error_v1)?;
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .map_err(super::map_local_http_io_error_v1)?;
    let (status, body) = super::split_local_http_response_v1(&response)?;
    Ok(LocalHttpPostResponseV1 { status, body })
}
