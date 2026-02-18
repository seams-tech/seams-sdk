use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use wasm_bindgen::prelude::*;
use x25519_dalek::{x25519, X25519_BASEPOINT_BYTES};

fn require_len<const N: usize>(label: &str, input: &[u8]) -> Result<[u8; N], JsValue> {
    if input.len() != N {
        return Err(JsValue::from_str(&format!(
            "{label} must be {N} bytes, got {}",
            input.len()
        )));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(input);
    Ok(out)
}

#[wasm_bindgen]
pub fn email_recovery_x25519_public_key_from_secret(
    secret_key32: Vec<u8>,
) -> Result<Vec<u8>, JsValue> {
    let sk = require_len::<32>("secretKey32", secret_key32.as_slice())?;
    Ok(x25519(sk, X25519_BASEPOINT_BYTES).to_vec())
}

#[wasm_bindgen]
pub fn email_recovery_x25519_shared_secret(
    secret_key32: Vec<u8>,
    peer_public_key32: Vec<u8>,
) -> Result<Vec<u8>, JsValue> {
    let sk = require_len::<32>("secretKey32", secret_key32.as_slice())?;
    let pk = require_len::<32>("peerPublicKey32", peer_public_key32.as_slice())?;
    Ok(x25519(sk, pk).to_vec())
}

#[wasm_bindgen]
pub fn email_recovery_hkdf_sha256_32(ikm: Vec<u8>, info: Vec<u8>) -> Result<Vec<u8>, JsValue> {
    let hk = Hkdf::<Sha256>::new(None, ikm.as_slice());
    let mut out = [0u8; 32];
    hk.expand(info.as_slice(), &mut out)
        .map_err(|_| JsValue::from_str("HKDF expand failed"))?;
    Ok(out.to_vec())
}

#[wasm_bindgen]
pub fn email_recovery_chacha20poly1305_encrypt(
    key32: Vec<u8>,
    nonce12: Vec<u8>,
    aad: Vec<u8>,
    plaintext: Vec<u8>,
) -> Result<Vec<u8>, JsValue> {
    let key = require_len::<32>("key32", key32.as_slice())?;
    let nonce = require_len::<12>("nonce12", nonce12.as_slice())?;
    let cipher = ChaCha20Poly1305::new_from_slice(&key)
        .map_err(|_| JsValue::from_str("Invalid ChaCha20-Poly1305 key"))?;
    cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext.as_slice(),
                aad: aad.as_slice(),
            },
        )
        .map_err(|_| JsValue::from_str("ChaCha20-Poly1305 encrypt failed"))
}

#[wasm_bindgen]
pub fn email_recovery_chacha20poly1305_decrypt(
    key32: Vec<u8>,
    nonce12: Vec<u8>,
    aad: Vec<u8>,
    ciphertext: Vec<u8>,
) -> Result<Vec<u8>, JsValue> {
    let key = require_len::<32>("key32", key32.as_slice())?;
    let nonce = require_len::<12>("nonce12", nonce12.as_slice())?;
    let cipher = ChaCha20Poly1305::new_from_slice(&key)
        .map_err(|_| JsValue::from_str("Invalid ChaCha20-Poly1305 key"))?;
    cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: ciphertext.as_slice(),
                aad: aad.as_slice(),
            },
        )
        .map_err(|_| JsValue::from_str("ChaCha20-Poly1305 decrypt failed"))
}

#[wasm_bindgen]
pub fn email_recovery_sha256(input: Vec<u8>) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(input.as_slice());
    hasher.finalize().to_vec()
}
