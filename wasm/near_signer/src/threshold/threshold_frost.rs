use crate::encoders::{base64_url_decode, base64_url_encode};
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use std::collections::BTreeMap;
use wasm_bindgen::prelude::*;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg(feature = "hss-server-exports")]
struct ThresholdEd25519RecoveryKeypairFromSeedArgs {
    seed_b64u: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg(feature = "hss-server-exports")]
struct ThresholdEd25519RecoveryKeypairFromSeedOutput {
    public_key: String,
    private_key: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg(feature = "hss-client-exports")]
pub(crate) struct ThresholdEd25519SeedExportArtifactFromSeedArgs {
    seed_b64u: String,
    expected_public_key: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg(feature = "hss-client-exports")]
pub(crate) struct ThresholdEd25519SeedExportArtifactFromSeedOutput {
    artifact_kind: String,
    seed_b64u: String,
    public_key: String,
    private_key: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg(feature = "hss-server-exports")]
struct ThresholdEd25519HssServerInputsArgs {
    master_secret_b64u: String,
    org_id: String,
    near_account_id: String,
    key_purpose: String,
    key_version: String,
    participant_ids: Vec<u16>,
    derivation_version: u32,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg(feature = "hss-server-exports")]
struct ThresholdEd25519HssServerInputsOutput {
    org_id: String,
    near_account_id: String,
    key_purpose: String,
    key_version: String,
    participant_ids: Vec<u16>,
    derivation_version: u32,
    context_binding_b64u: String,
    y_relayer_b64u: String,
    tau_relayer_b64u: String,
}

#[wasm_bindgen]
#[cfg(feature = "hss-server-exports")]
pub fn threshold_ed25519_recovery_keypair_from_seed(args: JsValue) -> Result<JsValue, JsValue> {
    let args: ThresholdEd25519RecoveryKeypairFromSeedArgs = serde_wasm_bindgen::from_value(args)
        .map_err(|e| JsValue::from_str(&format!("Invalid args: {e}")))?;
    let seed = base64_url_decode(&args.seed_b64u)
        .map_err(|e| JsValue::from_str(&format!("Invalid seedB64u: {e}")))?;
    if seed.len() != 32 {
        return Err(JsValue::from_str(&format!(
            "seedB64u must decode to 32 bytes, got {}",
            seed.len()
        )));
    }
    let mut seed32 = [0u8; 32];
    seed32.copy_from_slice(seed.as_slice());
    serde_wasm_bindgen::to_value(&ThresholdEd25519RecoveryKeypairFromSeedOutput {
        public_key:
            signer_platform_web::near_ed25519_recovery::encode_near_ed25519_public_key_from_seed(
                seed32,
            ),
        private_key:
            signer_platform_web::near_ed25519_recovery::encode_near_ed25519_private_key_from_seed(
                seed32,
            ),
    })
    .map_err(|e| JsValue::from_str(&format!("Failed to serialize recovery keypair: {e}")))
}

#[wasm_bindgen]
#[cfg(feature = "hss-client-exports")]
pub fn threshold_ed25519_seed_export_artifact_from_seed(args: JsValue) -> Result<JsValue, JsValue> {
    let args: ThresholdEd25519SeedExportArtifactFromSeedArgs = serde_wasm_bindgen::from_value(args)
        .map_err(|e| JsValue::from_str(&format!("Invalid args: {e}")))?;
    let output = build_threshold_ed25519_seed_export_artifact_from_seed(args)
        .map_err(|e| JsValue::from_str(&e))?;
    serde_wasm_bindgen::to_value(&output)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize seed export artifact: {e}")))
}

#[wasm_bindgen]
#[cfg(feature = "hss-server-exports")]
pub fn threshold_ed25519_hss_server_inputs(args: JsValue) -> Result<JsValue, JsValue> {
    let args: ThresholdEd25519HssServerInputsArgs = serde_wasm_bindgen::from_value(args)
        .map_err(|e| JsValue::from_str(&format!("Invalid args: {e}")))?;
    let master_secret = base64_url_decode(&args.master_secret_b64u)
        .map_err(|e| JsValue::from_str(&format!("Invalid masterSecretB64u: {e}")))?;
    let out = signer_platform_web::near_ed25519_recovery::derive_ed25519_hss_server_inputs_v1(
        master_secret.as_slice(),
        &signer_platform_web::near_ed25519_recovery::Ed25519HssCanonicalContextV1 {
            org_id: args.org_id.clone(),
            account_id: args.near_account_id.clone(),
            key_purpose: args.key_purpose.clone(),
            key_version: args.key_version.clone(),
            participant_ids: args.participant_ids,
            derivation_version: args.derivation_version,
        },
    )
    .map_err(|e| JsValue::from_str(&e.to_string()))?;

    serde_wasm_bindgen::to_value(&ThresholdEd25519HssServerInputsOutput {
        org_id: out.context.org_id,
        near_account_id: out.context.account_id,
        key_purpose: out.context.key_purpose,
        key_version: out.context.key_version,
        participant_ids: out.context.participant_ids,
        derivation_version: out.context.derivation_version,
        context_binding_b64u: base64_url_encode(&out.context_binding),
        y_relayer_b64u: base64_url_encode(&out.y_relayer),
        tau_relayer_b64u: base64_url_encode(&out.tau_relayer),
    })
    .map_err(|e| JsValue::from_str(&format!("Failed to serialize HSS server inputs: {e}")))
}

#[wasm_bindgen]
pub fn threshold_ed25519_round1_commit(
    relayer_signing_share_b64u: String,
) -> Result<JsValue, JsValue> {
    let out = signer_platform_web::near_threshold_frost::threshold_ed25519_round1_commit(
        relayer_signing_share_b64u.as_str(),
    )
    .map_err(|e| JsValue::from_str(&e.to_string()))?;
    serde_wasm_bindgen::to_value(&out)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize round1 output: {e}")))
}

#[wasm_bindgen]
pub fn threshold_ed25519_round2_sign(args: JsValue) -> Result<JsValue, JsValue> {
    let args: signer_platform_web::near_threshold_frost::ThresholdEd25519Round2SignArgs =
        serde_wasm_bindgen::from_value(args)
            .map_err(|e| JsValue::from_str(&format!("Invalid round2 args: {e}")))?;
    let out = signer_platform_web::near_threshold_frost::threshold_ed25519_round2_sign(args)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    serde_wasm_bindgen::to_value(&out)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize round2 output: {e}")))
}

#[wasm_bindgen]
pub fn threshold_ed25519_round2_sign_cosigner(args: JsValue) -> Result<JsValue, JsValue> {
    let args: signer_platform_web::near_threshold_frost::ThresholdEd25519Round2SignArgs =
        serde_wasm_bindgen::from_value(args)
            .map_err(|e| JsValue::from_str(&format!("Invalid round2 args: {e}")))?;
    let out =
        signer_platform_web::near_threshold_frost::threshold_ed25519_round2_sign_cosigner(args)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
    serde_wasm_bindgen::to_value(&out)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize round2 output: {e}")))
}

const COSIGNER_POLY_PREFIX_V1: &[u8] = b"w3a/threshold-ed25519/cosigner-poly_v1";

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AddPointsInput {
    points_b64u: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeriveRelayerCosignerSharesInput {
    relayer_signing_share_b64u: String,
    cosigner_ids: Vec<u32>,
    cosigner_threshold: u32,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DeriveRelayerCosignerSharesOutput {
    shares_by_cosigner_id: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LagrangeCoefficientInput {
    cosigner_id: u32,
    cosigner_ids: Vec<u32>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MultiplyScalarInput {
    scalar_b64u: String,
    factor_bytes_le32: Vec<u8>,
}

fn decode_fixed_32(input_b64u: &str, label: &str) -> Result<[u8; 32], JsValue> {
    let decoded = base64_url_decode(input_b64u)
        .map_err(|e| JsValue::from_str(&format!("Invalid {label}: {e}")))?;
    if decoded.len() != 32 {
        return Err(JsValue::from_str(&format!(
            "{label} must be 32 bytes, got {}",
            decoded.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(decoded.as_slice());
    Ok(out)
}

#[cfg(feature = "hss-client-exports")]
pub(crate) fn build_threshold_ed25519_seed_export_artifact_from_seed(
    args: ThresholdEd25519SeedExportArtifactFromSeedArgs,
) -> Result<ThresholdEd25519SeedExportArtifactFromSeedOutput, String> {
    let seed = base64_url_decode(&args.seed_b64u).map_err(|e| format!("Invalid seedB64u: {e}"))?;
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

fn decode_ed25519_point_32(input_b64u: &str, label: &str) -> Result<EdwardsPoint, JsValue> {
    let point_bytes = decode_fixed_32(input_b64u, label)?;
    CompressedEdwardsY(point_bytes)
        .decompress()
        .ok_or_else(|| JsValue::from_str(&format!("{label} is not a valid Ed25519 point")))
}

fn normalize_cosigner_ids(ids: &[u32]) -> Result<Vec<u16>, JsValue> {
    if ids.is_empty() {
        return Err(JsValue::from_str(
            "cosignerIds must be a non-empty list of u16 ids",
        ));
    }
    let mut out = Vec::<u16>::with_capacity(ids.len());
    for id in ids {
        if *id == 0 || *id > u16::MAX as u32 {
            return Err(JsValue::from_str(
                "cosignerIds must be a non-empty list of u16 ids",
            ));
        }
        out.push(*id as u16);
    }
    out.sort_unstable();
    out.dedup();
    if out.is_empty() {
        return Err(JsValue::from_str(
            "cosignerIds must be a non-empty list of u16 ids",
        ));
    }
    Ok(out)
}

#[wasm_bindgen]
pub fn threshold_ed25519_add_points_b64u(args: JsValue) -> Result<String, JsValue> {
    let input: AddPointsInput = serde_wasm_bindgen::from_value(args)
        .map_err(|e| JsValue::from_str(&format!("Invalid add-point args: {e}")))?;
    if input.points_b64u.is_empty() {
        return Err(JsValue::from_str("pointsB64u must be a non-empty array"));
    }

    let mut acc = EdwardsPoint::identity();
    for (idx, item) in input.points_b64u.iter().enumerate() {
        let label = format!("pointsB64u[{idx}]");
        let point = decode_ed25519_point_32(item, label.as_str())?;
        acc += point;
    }
    Ok(base64_url_encode(acc.compress().as_bytes()))
}

#[wasm_bindgen]
pub fn threshold_ed25519_derive_relayer_cosigner_shares(args: JsValue) -> Result<JsValue, JsValue> {
    let input: DeriveRelayerCosignerSharesInput = serde_wasm_bindgen::from_value(args)
        .map_err(|e| JsValue::from_str(&format!("Invalid cosigner-share args: {e}")))?;
    let relayer_signing_share = decode_fixed_32(
        input.relayer_signing_share_b64u.as_str(),
        "relayerSigningShareB64u",
    )?;
    let cosigner_ids = normalize_cosigner_ids(input.cosigner_ids.as_slice())?;
    let t = input.cosigner_threshold as usize;
    if t < 1 {
        return Err(JsValue::from_str(
            "cosignerThreshold must be an integer >= 1",
        ));
    }
    if t > cosigner_ids.len() {
        return Err(JsValue::from_str(&format!(
            "cosignerThreshold must be <= cosignerIds.length (got t={}, n={})",
            t,
            cosigner_ids.len()
        )));
    }

    let a0 = Scalar::from_bytes_mod_order(relayer_signing_share);
    if a0 == Scalar::ZERO {
        return Err(JsValue::from_str("relayer signing share must be non-zero"));
    }

    let mut coeffs: Vec<Scalar> = vec![a0];
    if t > 1 {
        let t_bytes = (t as u32).to_le_bytes();
        for i in 1..t {
            let mut hasher = Sha512::new();
            hasher.update(COSIGNER_POLY_PREFIX_V1);
            hasher.update(t_bytes);
            hasher.update(relayer_signing_share);
            hasher.update((i as u32).to_le_bytes());
            let digest = hasher.finalize();
            let mut wide = [0u8; 64];
            wide.copy_from_slice(digest.as_slice());
            coeffs.push(Scalar::from_bytes_mod_order_wide(&wide));
        }
    }

    let mut shares_by_cosigner_id = BTreeMap::<String, String>::new();
    for id in cosigner_ids {
        let x = Scalar::from(id as u64);
        let mut x_pow = x;
        let mut y = coeffs[0];
        for coeff in coeffs.iter().skip(1) {
            y += *coeff * x_pow;
            x_pow *= x;
        }
        if y == Scalar::ZERO {
            return Err(JsValue::from_str(&format!(
                "Derived cosigner share is zero for cosignerId={id}",
            )));
        }
        shares_by_cosigner_id.insert(id.to_string(), base64_url_encode(&y.to_bytes()));
    }

    let out = DeriveRelayerCosignerSharesOutput {
        shares_by_cosigner_id,
    };
    serde_wasm_bindgen::to_value(&out)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize cosigner shares: {e}")))
}

#[wasm_bindgen]
pub fn threshold_ed25519_lagrange_coefficient_at_zero(args: JsValue) -> Result<Vec<u8>, JsValue> {
    let input: LagrangeCoefficientInput = serde_wasm_bindgen::from_value(args)
        .map_err(|e| JsValue::from_str(&format!("Invalid lagrange args: {e}")))?;
    let cosigner_ids = normalize_cosigner_ids(input.cosigner_ids.as_slice())?;
    let cosigner_id_u16 = if input.cosigner_id == 0 || input.cosigner_id > u16::MAX as u32 {
        return Err(JsValue::from_str(
            "cosignerId must be an integer in [1,65535]",
        ));
    } else {
        input.cosigner_id as u16
    };
    if !cosigner_ids.contains(&cosigner_id_u16) {
        return Err(JsValue::from_str("cosignerIds must include cosignerId"));
    }

    let x_i = Scalar::from(cosigner_id_u16 as u64);
    let mut num = Scalar::ONE;
    let mut den = Scalar::ONE;
    for id in cosigner_ids {
        if id == cosigner_id_u16 {
            continue;
        }
        let x_j = Scalar::from(id as u64);
        num *= x_j;
        den *= x_j - x_i;
    }
    if den == Scalar::ZERO {
        return Err(JsValue::from_str("duplicated cosignerId in cosignerIds"));
    }
    let lambda = num * den.invert();
    Ok(lambda.to_bytes().to_vec())
}

#[wasm_bindgen]
pub fn threshold_ed25519_multiply_scalar_b64u_by_scalar_le32(
    args: JsValue,
) -> Result<String, JsValue> {
    let input: MultiplyScalarInput = serde_wasm_bindgen::from_value(args)
        .map_err(|e| JsValue::from_str(&format!("Invalid scalar multiply args: {e}")))?;
    let scalar_bytes = decode_fixed_32(input.scalar_b64u.as_str(), "scalarB64u")?;
    if input.factor_bytes_le32.len() != 32 {
        return Err(JsValue::from_str(&format!(
            "factorBytesLE32 must be 32 bytes, got {}",
            input.factor_bytes_le32.len()
        )));
    }
    let mut factor_bytes = [0u8; 32];
    factor_bytes.copy_from_slice(input.factor_bytes_le32.as_slice());

    let scalar = Scalar::from_bytes_mod_order(scalar_bytes);
    let factor = Scalar::from_bytes_mod_order(factor_bytes);
    let out = scalar * factor;
    if out == Scalar::ZERO {
        return Err(JsValue::from_str("Derived scalar is zero"));
    }
    Ok(base64_url_encode(&out.to_bytes()))
}
