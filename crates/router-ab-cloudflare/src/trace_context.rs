use router_ab_core::{RouterAbProtocolError, RouterAbProtocolErrorCode, RouterAbProtocolResult};

#[cfg(feature = "workers-rs")]
pub const CLOUDFLARE_TRACE_ID_HEADER_V1: &str = "x-seams-trace-id";
const CLOUDFLARE_TRACE_ID_HEX_LENGTH: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CloudflareTraceIdV1([u8; 16]);

impl CloudflareTraceIdV1 {
    pub fn parse(value: &str) -> RouterAbProtocolResult<Self> {
        if value.len() != CLOUDFLARE_TRACE_ID_HEX_LENGTH {
            return Err(invalid_trace_id(
                "trace ID must contain exactly 32 characters",
            ));
        }
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(invalid_trace_id(
                "trace ID must contain only lowercase hexadecimal characters",
            ));
        }
        let mut bytes = [0_u8; 16];
        for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
            bytes[index] = (hex_nibble(chunk[0]) << 4) | hex_nibble(chunk[1]);
        }
        Ok(Self(bytes))
    }

    pub fn as_hex(self) -> String {
        let mut value = String::with_capacity(CLOUDFLARE_TRACE_ID_HEX_LENGTH);
        for byte in self.0 {
            value.push(hex_digit(byte >> 4));
            value.push(hex_digit(byte & 0x0f));
        }
        value
    }
}

#[cfg(feature = "workers-rs")]
pub fn parse_cloudflare_trace_id_from_request_v1(
    request: &worker::Request,
) -> RouterAbProtocolResult<Option<CloudflareTraceIdV1>> {
    let value = request
        .headers()
        .get(CLOUDFLARE_TRACE_ID_HEADER_V1)
        .map_err(|error| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalHttpRequest,
                format!("trace ID header read failed: {error}"),
            )
        })?;
    match value {
        Some(value) => CloudflareTraceIdV1::parse(&value).map(Some),
        None => Ok(None),
    }
}

#[cfg(feature = "workers-rs")]
pub fn set_cloudflare_trace_id_header_v1(
    headers: &worker::Headers,
    trace_id: CloudflareTraceIdV1,
) -> RouterAbProtocolResult<()> {
    headers
        .set(CLOUDFLARE_TRACE_ID_HEADER_V1, &trace_id.as_hex())
        .map_err(|error| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                format!("trace ID header write failed: {error}"),
            )
        })
}

fn invalid_trace_id(message: &str) -> RouterAbProtocolError {
    RouterAbProtocolError::new(RouterAbProtocolErrorCode::InvalidLocalHttpRequest, message)
}

fn hex_nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        _ => unreachable!("trace ID validation rejects non-hex characters"),
    }
}

fn hex_digit(value: u8) -> char {
    match value {
        0..=9 => (b'0' + value) as char,
        10..=15 => (b'a' + value - 10) as char,
        _ => unreachable!("trace ID nibble is always four bits"),
    }
}

#[cfg(test)]
mod tests {
    use super::CloudflareTraceIdV1;

    #[test]
    fn parses_and_round_trips_lowercase_hex() {
        let trace_id = CloudflareTraceIdV1::parse("0123456789abcdef0123456789abcdef")
            .expect("trace ID should parse");
        assert_eq!(trace_id.as_hex(), "0123456789abcdef0123456789abcdef");
    }

    #[test]
    fn rejects_wrong_length_and_uppercase_values() {
        assert!(CloudflareTraceIdV1::parse("0123").is_err());
        assert!(CloudflareTraceIdV1::parse("0123456789ABCDEF0123456789abcdef").is_err());
    }
}
