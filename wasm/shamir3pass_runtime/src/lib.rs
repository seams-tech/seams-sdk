use serde::Serialize;
use shamir_3_pass::{decode_biguint_b64u, encode_biguint_b64u, Shamir3Pass};
use wasm_bindgen::prelude::*;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ClientLockKeypairPayload {
    shamir_prime_b64u: String,
    client_encrypt_exponent_b64u: String,
    client_decrypt_exponent_b64u: String,
}

fn js_error(message: impl Into<String>) -> JsValue {
    JsValue::from_str(&message.into())
}

fn parse_protocol(shamir_prime_b64u: &str) -> Result<Shamir3Pass, JsValue> {
    Shamir3Pass::new(shamir_prime_b64u)
        .map_err(|error| js_error(format!("Invalid shamirPrimeB64u: {error}")))
}

fn decode_positive_operand(input: &str, label: &str) -> Result<num_bigint::BigUint, JsValue> {
    let value = decode_biguint_b64u(input)
        .map_err(|error| js_error(format!("Invalid {label}: {error}")))?;
    if value == 0u8.into() {
        return Err(js_error(format!("{label} must decode to integer > 0")));
    }
    Ok(value)
}

#[wasm_bindgen]
pub fn init_shamir3pass_runtime() {
    // Reserved for future logger/metrics initialization.
}

#[wasm_bindgen]
pub fn shamir3pass_generate_client_lock_keys(
    shamir_prime_b64u: String,
) -> Result<JsValue, JsValue> {
    let protocol = parse_protocol(&shamir_prime_b64u)?;
    let keys = protocol
        .generate_lock_keys()
        .map_err(|error| js_error(format!("Failed to generate lock keys: {error}")))?;
    let payload = ClientLockKeypairPayload {
        shamir_prime_b64u,
        client_encrypt_exponent_b64u: encode_biguint_b64u(&keys.e),
        client_decrypt_exponent_b64u: encode_biguint_b64u(&keys.d),
    };
    serde_wasm_bindgen::to_value(&payload)
        .map_err(|error| js_error(format!("Failed to serialize lock keys: {error}")))
}

#[wasm_bindgen]
pub fn shamir3pass_add_lock(
    ciphertext_b64u: String,
    exponent_b64u: String,
    shamir_prime_b64u: String,
) -> Result<String, JsValue> {
    let protocol = parse_protocol(&shamir_prime_b64u)?;
    let ciphertext = decode_positive_operand(&ciphertext_b64u, "ciphertextB64u")?;
    if &ciphertext >= protocol.p() {
        return Err(js_error(
            "ciphertextB64u must decode to integer in range (0, p)",
        ));
    }
    let exponent = decode_positive_operand(&exponent_b64u, "exponentB64u")?;
    let output = protocol.add_lock(&ciphertext, &exponent);
    Ok(encode_biguint_b64u(&output))
}

#[wasm_bindgen]
pub fn shamir3pass_remove_lock(
    ciphertext_b64u: String,
    exponent_b64u: String,
    shamir_prime_b64u: String,
) -> Result<String, JsValue> {
    let protocol = parse_protocol(&shamir_prime_b64u)?;
    let ciphertext = decode_positive_operand(&ciphertext_b64u, "ciphertextB64u")?;
    if &ciphertext >= protocol.p() {
        return Err(js_error(
            "ciphertextB64u must decode to integer in range (0, p)",
        ));
    }
    let exponent = decode_positive_operand(&exponent_b64u, "exponentB64u")?;
    let output = protocol.remove_lock(&ciphertext, &exponent);
    Ok(encode_biguint_b64u(&output))
}
