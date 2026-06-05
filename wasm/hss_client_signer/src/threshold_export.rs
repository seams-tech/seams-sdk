use crate::js::{get_required_string, object, set_string};
use base64ct::{Base64UrlUnpadded, Encoding};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn threshold_ed25519_seed_export_artifact_from_seed(args: JsValue) -> Result<JsValue, JsValue> {
    let seed_b64u = get_required_string(&args, "seedB64u")?;
    let expected_public_key = get_required_string(&args, "expectedPublicKey")?;
    let seed = Base64UrlUnpadded::decode_vec(seed_b64u.as_str())
        .map_err(|e| JsValue::from_str(&format!("Invalid seedB64u: {e}")))?;
    if seed.len() != 32 {
        return Err(JsValue::from_str(&format!(
            "seedB64u must decode to 32 bytes, got {}",
            seed.len()
        )));
    }
    let mut seed32 = [0u8; 32];
    seed32.copy_from_slice(seed.as_slice());
    let artifact =
        signer_wasm_core::near_ed25519_recovery::build_near_ed25519_seed_export_artifact_v1(
            seed32,
            expected_public_key.as_str(),
        )
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let out = object();
    set_string(&out, "artifactKind", &artifact.artifact_kind)?;
    set_string(&out, "seedB64u", &artifact.seed_b64u)?;
    set_string(&out, "publicKey", &artifact.public_key)?;
    set_string(&out, "privateKey", &artifact.private_key)?;
    Ok(out.into())
}
