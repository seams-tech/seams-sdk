#[cfg(feature = "workers-rs")]
use crate::{
    cloudflare_router_error_status, worker_binding_error, worker_binding_error_code,
    ROUTER_AB_INTERNAL_SERVICE_AUTH_HEADER_V1, ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET_BINDING_ENV,
};
use crate::{require_non_empty, CloudflareRouterEd25519JwkV1};
use ed25519_dalek::{Signature as Ed25519Signature, VerifyingKey as Ed25519VerifyingKey};
use router_ab_core::{RouterAbProtocolError, RouterAbProtocolErrorCode, RouterAbProtocolResult};
#[cfg(feature = "workers-rs")]
use sha2::{Digest as Sha2Digest, Sha256};
#[cfg(feature = "workers-rs")]
use zeroize::Zeroize;

#[cfg(feature = "workers-rs")]
fn load_cloudflare_internal_service_auth_token_v1(
    env: &worker::Env,
) -> RouterAbProtocolResult<String> {
    let binding_name = env
        .var(ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET_BINDING_ENV)
        .map_err(|err| {
            worker_binding_error(
                worker_binding_error_code(&err, ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET_BINDING_ENV),
                ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET_BINDING_ENV,
                "text Env",
                err,
            )
        })?
        .to_string();
    let binding_name = binding_name.trim().to_owned();
    require_non_empty(
        ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET_BINDING_ENV,
        &binding_name,
    )?;
    let secret = env.secret(&binding_name).map_err(|err| {
        worker_binding_error(
            worker_binding_error_code(&err, &binding_name),
            &binding_name,
            "secret",
            err,
        )
    })?;
    let mut secret_value = secret.to_string();
    let token = secret_value.trim().to_owned();
    secret_value.zeroize();
    require_non_empty("Router A/B internal service-auth token", &token)?;
    Ok(token)
}

#[cfg(feature = "workers-rs")]
pub fn set_cloudflare_internal_service_auth_header_v1(
    env: &worker::Env,
    headers: &worker::Headers,
    request_kind: &str,
) -> RouterAbProtocolResult<()> {
    require_non_empty("Cloudflare service-auth request kind", request_kind)?;
    let mut token = load_cloudflare_internal_service_auth_token_v1(env)?;
    let result = headers
        .set(ROUTER_AB_INTERNAL_SERVICE_AUTH_HEADER_V1, &token)
        .map_err(|err| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                format!("{request_kind} service-auth header construction failed: {err}"),
            )
        });
    token.zeroize();
    result
}

#[cfg(feature = "workers-rs")]
pub fn require_cloudflare_internal_service_auth_request_v1(
    request: &worker::Request,
    env: &worker::Env,
) -> RouterAbProtocolResult<()> {
    let mut expected = load_cloudflare_internal_service_auth_token_v1(env)?;
    let presented = request
        .headers()
        .get(ROUTER_AB_INTERNAL_SERVICE_AUTH_HEADER_V1)
        .map_err(|err| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalHttpRequest,
                format!("Router A/B internal service-auth header read failed: {err}"),
            )
        })?
        .unwrap_or_default();
    let authorized = constant_time_text_eq_v1(&expected, &presented);
    expected.zeroize();
    if authorized {
        return Ok(());
    }
    Err(RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::InvalidLocalHttpRequest,
        "Router A/B private Worker request is missing valid service auth",
    ))
}

#[cfg(feature = "workers-rs")]
pub fn cloudflare_private_service_auth_error_response_v1(
    err: RouterAbProtocolError,
) -> worker::Result<worker::Response> {
    let status = match err.code() {
        RouterAbProtocolErrorCode::InvalidLocalHttpRequest => 403,
        code => cloudflare_router_error_status(code),
    };
    worker::Response::error(format!("{:?}: {}", err.code(), err.message()), status)
}

#[cfg(feature = "workers-rs")]
fn constant_time_text_eq_v1(a: &str, b: &str) -> bool {
    let a = a.as_bytes();
    let b = b.as_bytes();
    let mut diff = a.len() ^ b.len();
    let max_len = core::cmp::max(a.len(), b.len());
    for index in 0..max_len {
        let left = a.get(index).copied().unwrap_or_default();
        let right = b.get(index).copied().unwrap_or_default();
        diff |= (left ^ right) as usize;
    }
    diff == 0
}

pub(crate) fn verify_router_ed25519_jwt_signature_v1(
    signing_input: &str,
    signature: &[u8; 64],
    key: &CloudflareRouterEd25519JwkV1,
) -> RouterAbProtocolResult<()> {
    key.validate()?;
    let verifying_key = Ed25519VerifyingKey::from_bytes(&key.public_key).map_err(|_| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "Router JWT Ed25519 JWK public key bytes are invalid",
        )
    })?;
    let signature = Ed25519Signature::from_bytes(signature);
    verifying_key
        .verify_strict(signing_input.as_bytes(), &signature)
        .map_err(|_| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "Router JWT Ed25519 signature verification failed",
            )
        })
}

pub(crate) fn select_router_jwt_session_id_v1(
    sid: Option<String>,
    session_id: Option<String>,
) -> RouterAbProtocolResult<String> {
    match (sid, session_id) {
        (Some(sid), Some(session_id)) if sid == session_id => Ok(sid),
        (Some(_), Some(_)) => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "Router JWT sid and session_id claims differ",
        )),
        (Some(sid), None) => {
            require_non_empty("jwt sid", &sid)?;
            Ok(sid)
        }
        (None, Some(session_id)) => {
            require_non_empty("jwt session_id", &session_id)?;
            Ok(session_id)
        }
        (None, None) => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "Router JWT must include sid or session_id",
        )),
    }
}

pub(crate) fn unix_seconds_to_millis_v1(field: &str, seconds: u64) -> RouterAbProtocolResult<u64> {
    seconds.checked_mul(1_000).ok_or_else(|| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidTimeRange,
            format!("{field} seconds overflow milliseconds"),
        )
    })
}

pub(crate) fn router_jwt_segment_error() -> RouterAbProtocolError {
    RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::MalformedWirePayload,
        "Router JWT must use compact three-segment serialization",
    )
}

#[cfg(feature = "workers-rs")]
pub(crate) fn hash_optional_header_v1(hasher: &mut Sha256, name: &[u8], value: Option<&str>) {
    hasher.update((name.len() as u64).to_be_bytes());
    hasher.update(name);
    match value {
        Some(value) => {
            let bytes = value.as_bytes();
            hasher.update((bytes.len() as u64).to_be_bytes());
            hasher.update(bytes);
        }
        None => hasher.update(0u64.to_be_bytes()),
    }
}
