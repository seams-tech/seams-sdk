use getrandom::getrandom;
use num_bigint::{BigInt, BigUint, ToBigInt};
use num_traits::{One, Zero};
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

fn decode_positive_operand_bytes(mut input: Vec<u8>, label: &str) -> Result<BigUint, JsValue> {
    if input.is_empty() {
        return Err(js_error(format!("{label} must decode to integer > 0")));
    }
    let value = BigUint::from_bytes_be(&input);
    input.fill(0);
    if value == 0u8.into() {
        return Err(js_error(format!("{label} must decode to integer > 0")));
    }
    Ok(value)
}

fn gcd(mut a: BigUint, mut b: BigUint) -> BigUint {
    while b != BigUint::zero() {
        let remainder = &a % &b;
        a = b;
        b = remainder;
    }
    a
}

fn mod_inverse(a: &BigUint, modulus: &BigUint) -> Result<BigUint, JsValue> {
    let mut t = BigInt::zero();
    let mut next_t = BigInt::one();
    let mut r = modulus
        .to_bigint()
        .ok_or_else(|| js_error("Failed to convert modulus to BigInt"))?;
    let mut next_r = (a % modulus)
        .to_bigint()
        .ok_or_else(|| js_error("Failed to convert exponent to BigInt"))?;

    while next_r != BigInt::zero() {
        let q = &r / &next_r;
        let temp_t = &t - &q * &next_t;
        t = next_t;
        next_t = temp_t;
        let temp_r = &r - &q * &next_r;
        r = next_r;
        next_r = temp_r;
    }

    if r != BigInt::one() {
        return Err(js_error(
            "Failed to generate lock keys: client exponent is not invertible mod (p-1)",
        ));
    }

    if t < BigInt::zero() {
        t += modulus
            .to_bigint()
            .ok_or_else(|| js_error("Failed to convert modulus to BigInt"))?;
    }

    t.to_biguint()
        .ok_or_else(|| js_error("Failed to convert modular inverse to BigUint"))
}

fn random_biguint_below(limit: &BigUint) -> Result<BigUint, JsValue> {
    if *limit <= BigUint::one() {
        return Ok(BigUint::zero());
    }
    let bit_length = limit.bits();
    let byte_length = ((bit_length + 7) / 8) as usize;

    loop {
        let mut bytes = vec![0u8; byte_length];
        getrandom(&mut bytes)
            .map_err(|error| js_error(format!("Failed to gather random bytes: {error}")))?;
        let candidate = BigUint::from_bytes_be(&bytes);
        if &candidate < limit {
            return Ok(candidate);
        }
    }
}

fn pick_client_encrypt_exponent(phi: &BigUint) -> Result<BigUint, JsValue> {
    let preferred = BigUint::from(65_537u32);
    if &preferred < phi && gcd(preferred.clone(), phi.clone()) == BigUint::one() {
        return Ok(preferred);
    }

    let min = BigUint::from(3u8);
    if phi <= &min {
        return Err(js_error("Invalid shamirPrimeB64u: prime too small"));
    }

    let span = phi - &min;
    loop {
        let mut candidate = &min + random_biguint_below(&span)?;
        if !candidate.bit(0) {
            candidate += BigUint::one();
        }
        if &candidate >= phi {
            continue;
        }
        if gcd(candidate.clone(), phi.clone()) == BigUint::one() {
            return Ok(candidate);
        }
    }
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
    let mut phi = protocol.p().clone();
    phi -= BigUint::one();
    let client_encrypt_exponent = pick_client_encrypt_exponent(&phi)?;
    let client_decrypt_exponent = mod_inverse(&client_encrypt_exponent, &phi)?;
    let payload = ClientLockKeypairPayload {
        shamir_prime_b64u,
        client_encrypt_exponent_b64u: encode_biguint_b64u(&client_encrypt_exponent),
        client_decrypt_exponent_b64u: encode_biguint_b64u(&client_decrypt_exponent),
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
pub fn shamir3pass_add_lock_bytes(
    ciphertext: Vec<u8>,
    exponent_b64u: String,
    shamir_prime_b64u: String,
) -> Result<String, JsValue> {
    let protocol = parse_protocol(&shamir_prime_b64u)?;
    let ciphertext = decode_positive_operand_bytes(ciphertext, "ciphertext")?;
    if &ciphertext >= protocol.p() {
        return Err(js_error(
            "ciphertext must decode to integer in range (0, p)",
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

#[wasm_bindgen]
pub fn shamir3pass_remove_lock_to_bytes(
    ciphertext_b64u: String,
    exponent_b64u: String,
    shamir_prime_b64u: String,
) -> Result<Vec<u8>, JsValue> {
    let protocol = parse_protocol(&shamir_prime_b64u)?;
    let ciphertext = decode_positive_operand(&ciphertext_b64u, "ciphertextB64u")?;
    if &ciphertext >= protocol.p() {
        return Err(js_error(
            "ciphertextB64u must decode to integer in range (0, p)",
        ));
    }
    let exponent = decode_positive_operand(&exponent_b64u, "exponentB64u")?;
    let output = protocol.remove_lock(&ciphertext, &exponent);
    Ok(output.to_bytes_be())
}
