use hmac::{Hmac, Mac};
use sha2::Sha256;
use wasm_bindgen::prelude::*;
use zeroize::Zeroize;

type HmacSha256 = Hmac<Sha256>;

const HKDF_SHA256_LENGTH: usize = 32;
const EMAIL_OTP_THRESHOLD_ROOT_SALT_V1: &str = "tatchi/email-otp/root/v1";
const EMAIL_OTP_ECDSA_CLIENT_SHARE_SALT_V1: &str =
    "tatchi/email-otp/threshold-client-share/v1";
const EMAIL_OTP_UNLOCK_AUTH_SALT_V1: &str = "tatchi/email-otp/unlock-auth/v1";
const EMAIL_OTP_ECDSA_DERIVATION_PATH_V1: &str = "evm-signing";

fn js_error(message: impl Into<String>) -> JsValue {
    JsValue::from_str(&message.into())
}

fn require_secret32(secret: &[u8]) -> Result<(), JsValue> {
    if secret.len() != HKDF_SHA256_LENGTH {
        return Err(js_error("Email OTP client secret must be 32 bytes"));
    }
    Ok(())
}

fn encode_u16_be(value: usize) -> Result<[u8; 2], JsValue> {
    if value > 0xffff {
        return Err(js_error("Email OTP tuple field length must fit in u16"));
    }
    Ok([((value >> 8) & 0xff) as u8, (value & 0xff) as u8])
}

fn encode_email_otp_tuple(fields: &[&[u8]]) -> Result<Vec<u8>, JsValue> {
    let mut total_len = 0usize;
    for field in fields {
        total_len = total_len
            .checked_add(2)
            .and_then(|value| value.checked_add(field.len()))
            .ok_or_else(|| js_error("Email OTP tuple length overflow"))?;
    }
    let mut out = Vec::with_capacity(total_len);
    for field in fields {
        let len = encode_u16_be(field.len())?;
        out.extend_from_slice(&len);
        out.extend_from_slice(field);
    }
    Ok(out)
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<[u8; HKDF_SHA256_LENGTH], JsValue> {
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|_| js_error("Failed to initialize HMAC-SHA-256"))?;
    mac.update(data);
    let bytes = mac.finalize().into_bytes();
    let mut out = [0u8; HKDF_SHA256_LENGTH];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8]) -> Result<Vec<u8>, JsValue> {
    let zero_salt = [0u8; HKDF_SHA256_LENGTH];
    let salt = if salt.is_empty() { &zero_salt[..] } else { salt };
    let mut prk = hmac_sha256(salt, ikm)?;
    let mut previous = [0u8; HKDF_SHA256_LENGTH];
    let mut block_input = Vec::with_capacity(info.len() + 1);
    let mut out = vec![0u8; HKDF_SHA256_LENGTH];
    let result = (|| -> Result<(), JsValue> {
        block_input.extend_from_slice(info);
        block_input.push(1);
        previous = hmac_sha256(&prk, &block_input)?;
        out.copy_from_slice(&previous);
        Ok(())
    })();
    block_input.zeroize();
    previous.zeroize();
    prk.zeroize();
    result.map(|_| out)
}

fn derive_threshold_root_from_secret32(
    client_secret32: &[u8],
    wallet_id: &str,
) -> Result<Vec<u8>, JsValue> {
    require_secret32(client_secret32)?;
    let wallet_id = wallet_id.trim();
    let mut info = encode_email_otp_tuple(&[wallet_id.as_bytes()])?;
    let result = hkdf_sha256(
        client_secret32,
        EMAIL_OTP_THRESHOLD_ROOT_SALT_V1.as_bytes(),
        &info,
    );
    info.zeroize();
    result
}

#[wasm_bindgen]
pub fn init_email_otp_runtime() {
    // Reserved for future logger/metrics initialization.
}

#[wasm_bindgen]
pub fn derive_email_otp_threshold_root_from_secret32(
    mut client_secret32: Vec<u8>,
    wallet_id: String,
) -> Result<Vec<u8>, JsValue> {
    let result = derive_threshold_root_from_secret32(&client_secret32, &wallet_id);
    client_secret32.zeroize();
    result
}

#[wasm_bindgen]
pub fn derive_email_otp_ecdsa_client_root_share32_from_secret32(
    mut client_secret32: Vec<u8>,
    wallet_id: String,
    user_id: String,
    derivation_path: Option<String>,
) -> Result<Vec<u8>, JsValue> {
    require_secret32(&client_secret32)?;
    let mut threshold_root = derive_threshold_root_from_secret32(&client_secret32, &wallet_id)?;
    client_secret32.zeroize();
    let user_id = user_id.trim();
    let derivation_path = derivation_path
        .as_deref()
        .unwrap_or(EMAIL_OTP_ECDSA_DERIVATION_PATH_V1)
        .trim();
    let mut info = encode_email_otp_tuple(&[user_id.as_bytes(), derivation_path.as_bytes()])?;
    let result = hkdf_sha256(
        &threshold_root,
        EMAIL_OTP_ECDSA_CLIENT_SHARE_SALT_V1.as_bytes(),
        &info,
    );
    info.zeroize();
    threshold_root.zeroize();
    result
}

#[wasm_bindgen]
pub fn derive_email_otp_unlock_auth_seed_from_secret32(
    mut client_secret32: Vec<u8>,
    wallet_id: String,
) -> Result<Vec<u8>, JsValue> {
    require_secret32(&client_secret32)?;
    let mut threshold_root = derive_threshold_root_from_secret32(&client_secret32, &wallet_id)?;
    client_secret32.zeroize();
    let wallet_id = wallet_id.trim();
    let mut info = encode_email_otp_tuple(&[wallet_id.as_bytes()])?;
    let result = hkdf_sha256(
        &threshold_root,
        EMAIL_OTP_UNLOCK_AUTH_SALT_V1.as_bytes(),
        &info,
    );
    info.zeroize();
    threshold_root.zeroize();
    result
}
