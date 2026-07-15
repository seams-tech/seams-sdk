use base64ct::{Base64UrlUnpadded, Encoding};

pub fn base64_url_decode(input: &str) -> Result<Vec<u8>, String> {
    Base64UrlUnpadded::decode_vec(input).map_err(|e| format!("Base64 decode error: {e}"))
}

pub fn base64_url_encode(data: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(data)
}
