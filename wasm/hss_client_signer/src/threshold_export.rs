use base64ct::{Base64UrlUnpadded, Encoding};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ThresholdEd25519SeedExportArtifactFromSeedArgs {
    seed_b64u: String,
    expected_public_key: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ThresholdEd25519SeedExportArtifactFromSeedOutput {
    artifact_kind: String,
    seed_b64u: String,
    public_key: String,
    private_key: String,
}

#[wasm_bindgen]
pub fn threshold_ed25519_seed_export_artifact_from_seed(args: JsValue) -> Result<JsValue, JsValue> {
    let args: ThresholdEd25519SeedExportArtifactFromSeedArgs = serde_wasm_bindgen::from_value(args)
        .map_err(|e| JsValue::from_str(&format!("Invalid args: {e}")))?;
    let output = build_threshold_ed25519_seed_export_artifact_from_seed(args)
        .map_err(|e| JsValue::from_str(&e))?;
    serde_wasm_bindgen::to_value(&output)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize seed export artifact: {e}")))
}

fn build_threshold_ed25519_seed_export_artifact_from_seed(
    args: ThresholdEd25519SeedExportArtifactFromSeedArgs,
) -> Result<ThresholdEd25519SeedExportArtifactFromSeedOutput, String> {
    let seed = Base64UrlUnpadded::decode_vec(args.seed_b64u.as_str())
        .map_err(|e| format!("Invalid seedB64u: {e}"))?;
    if seed.len() != 32 {
        return Err(format!(
            "seedB64u must decode to 32 bytes, got {}",
            seed.len()
        ));
    }
    let mut seed32 = [0u8; 32];
    seed32.copy_from_slice(seed.as_slice());
    let artifact =
        signer_platform_web::near_ed25519_recovery::build_near_ed25519_seed_export_artifact_v1(
            seed32,
            args.expected_public_key.as_str(),
        )
        .map_err(|e| e.to_string())?;

    Ok(ThresholdEd25519SeedExportArtifactFromSeedOutput {
        artifact_kind: artifact.artifact_kind,
        seed_b64u: artifact.seed_b64u,
        public_key: artifact.public_key,
        private_key: artifact.private_key,
    })
}
