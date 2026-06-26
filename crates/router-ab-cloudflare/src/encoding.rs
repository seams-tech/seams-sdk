use crate::{require_no_ascii_whitespace, require_non_empty};
use base64::Engine;
use router_ab_core::{RouterAbProtocolError, RouterAbProtocolErrorCode, RouterAbProtocolResult};

pub(crate) fn decode_base64url_json_v1<T>(field: &str, encoded: &str) -> RouterAbProtocolResult<T>
where
    T: serde::de::DeserializeOwned,
{
    let bytes = decode_base64url_bytes_v1(field, encoded)?;
    serde_json::from_slice(&bytes).map_err(|err| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("{field} JSON parse failed: {err}"),
        )
    })
}

pub(crate) fn decode_base64url_fixed_32_v1(
    field: &str,
    encoded: &str,
) -> RouterAbProtocolResult<[u8; 32]> {
    decode_base64url_fixed_v1(field, encoded)
}

pub(crate) fn decode_base64url_fixed_33_v1(
    field: &str,
    encoded: &str,
) -> RouterAbProtocolResult<[u8; 33]> {
    decode_base64url_fixed_v1(field, encoded)
}

pub(crate) fn decode_base64url_fixed_64_v1(
    field: &str,
    encoded: &str,
) -> RouterAbProtocolResult<[u8; 64]> {
    decode_base64url_fixed_v1(field, encoded)
}

fn decode_base64url_fixed_v1<const N: usize>(
    field: &str,
    encoded: &str,
) -> RouterAbProtocolResult<[u8; N]> {
    let bytes = decode_base64url_bytes_v1(field, encoded)?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("{field} must decode to {N} bytes, received {}", bytes.len()),
        )
    })
}

pub(crate) fn encode_base64url_bytes_v1(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn decode_base64url_bytes_v1(field: &str, encoded: &str) -> RouterAbProtocolResult<Vec<u8>> {
    require_non_empty(field, encoded)?;
    require_no_ascii_whitespace(field, encoded)?;
    if encoded.contains('=') {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("{field} must be unpadded base64url"),
        ));
    }
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded.as_bytes())
        .map_err(|err| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                format!("{field} base64url decode failed: {err}"),
            )
        })
}
