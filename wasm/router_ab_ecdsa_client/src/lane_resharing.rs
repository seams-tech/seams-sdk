use base64ct::{Base64UrlUnpadded, Encoding};
use router_ab_ecdsa_client_protocol::{
    prepare_ecdsa_additive_lane_holder_round_v1, seal_ecdsa_lane_payload_v1,
    EcdsaAdditiveLaneHolderRoundV1, EcdsaAdditiveLaneJobV1, EcdsaClientProtocolError,
    EcdsaLaneEncryptedPayloadV1,
};
use router_ab_ecdsa_derivation::shared::secp256k1::add_secp256k1_public_keys_33;
use router_ab_ecdsa_derivation::{
    derive_ecdsa_lane_delta_from_source_share32_v1, ecdsa_lane_client_public_key_from_share32_v1,
    sample_ecdsa_lane_client_share_v1, EcdsaLaneClientShare,
};
use serde::{Deserialize, Serialize};
use signer_core::ecdsa_role_local_client::command::{
    extract_client_signing_share32_from_ready_state_blob, EcdsaRoleLocalReadyStateBlob,
};
use wasm_bindgen::prelude::*;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const HOLDER_PREPARATION_KIND_V1: &str = "ecdsa_additive_lane_holder_preparation_v1";
const HOLDER_PACKAGE_KIND_V1: &str = "ecdsa_additive_lane_holder_package_v1";
const HOLDER_ROUND_KIND_V1: &str = "ecdsa_additive_lane_holder_round_v1";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct HolderPreparationInputV1 {
    job: EcdsaAdditiveLaneJobV1,
    holder_committed_at_ms: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HolderRoundWireV1<'a> {
    kind: &'static str,
    #[serde(flatten)]
    round: &'a EcdsaAdditiveLaneHolderRoundV1,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HolderPackageWireV1 {
    kind: &'static str,
    ecdsa_encrypted_material_envelope_json: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HolderPreparationOutputV1<'a> {
    kind: &'static str,
    holder_round: HolderRoundWireV1<'a>,
    holder_package: HolderPackageWireV1,
    encrypted_delta_package_json: String,
}

/// One-use holder-side ECDSA lane session. The source client scalar remains
/// inside this Rust/WASM object and is consumed by the first preparation.
#[wasm_bindgen]
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct EcdsaLaneHolderSessionV1 {
    ready_state_blob: Option<EcdsaRoleLocalReadyStateBlob>,
}

impl EcdsaLaneHolderSessionV1 {
    fn take_ready_state_blob(&mut self) -> Option<EcdsaRoleLocalReadyStateBlob> {
        self.ready_state_blob.take()
    }
}

#[wasm_bindgen]
impl EcdsaLaneHolderSessionV1 {
    /// Opens one exact role-local ready-state envelope inside Rust/WASM.
    #[wasm_bindgen(constructor)]
    pub fn new(mut state_blob_b64u: String) -> Result<EcdsaLaneHolderSessionV1, JsValue> {
        let decoded = Base64UrlUnpadded::decode_vec(state_blob_b64u.trim())
            .map_err(|error| js_error(format!("stateBlobB64u is invalid: {error}")));
        state_blob_b64u.zeroize();
        Ok(Self {
            ready_state_blob: Some(EcdsaRoleLocalReadyStateBlob {
                state_blob: decoded?,
            }),
        })
    }

    /// Samples and seals one target holder share, and encrypts the transient
    /// additive delta directly to the admitted SigningWorker recipient.
    pub fn prepare(&mut self, input_json: &str) -> Result<String, JsValue> {
        let input: HolderPreparationInputV1 = serde_json::from_str(input_json)
            .map_err(|error| js_error(format!("lane holder input is invalid: {error}")))?;
        input.job.validate().map_err(protocol_error)?;
        let ready_state_blob = self
            .take_ready_state_blob()
            .ok_or_else(|| js_error("ECDSA lane holder session was already consumed"))?;
        prepare_holder_artifact(ready_state_blob, input)
    }
}

fn prepare_holder_artifact(
    ready_state_blob: EcdsaRoleLocalReadyStateBlob,
    input: HolderPreparationInputV1,
) -> Result<String, JsValue> {
    let source_share32 = Zeroizing::new(
        extract_client_signing_share32_from_ready_state_blob(&ready_state_blob)
            .map_err(|error| js_error(error.to_string()))?,
    );
    let source_public_key33 =
        ecdsa_lane_client_public_key_from_share32_v1(*source_share32).map_err(derivation_error)?;
    let admitted_source_key33 = decode_fixed::<33>(
        &input.job.source_holder_verifying_share33_b64u,
        "job.sourceHolderVerifyingShare33B64u",
    )?;
    if source_public_key33 != admitted_source_key33 {
        return Err(js_error(
            "ready-state client share does not match the admitted source lane",
        ));
    }
    let admitted_server_key33 = decode_fixed::<33>(
        &input.job.source_server_verifying_share33_b64u,
        "job.sourceServerVerifyingShare33B64u",
    )?;
    let admitted_threshold_key33 = decode_fixed::<33>(
        &input.job.threshold_public_key33_b64u,
        "job.thresholdPublicKey33B64u",
    )?;
    let reconstructed_threshold_key33 =
        add_secp256k1_public_keys_33(&source_public_key33, &admitted_server_key33)
            .map_err(derivation_error)?;
    if reconstructed_threshold_key33.as_slice() != admitted_threshold_key33 {
        return Err(js_error(
            "admitted source shares do not reconstruct the lane threshold public key",
        ));
    }

    let target_share = sample_target_share()?;
    let delta = derive_ecdsa_lane_delta_from_source_share32_v1(*source_share32, &target_share)
        .map_err(derivation_error)?;
    let preamble_hash = input.job.preamble_hash().map_err(protocol_error)?;
    let holder_seed = random32()?;
    let delta_seed = random32()?;
    let holder_package = seal_ecdsa_lane_payload_v1(
        &input.job.target_holder.hpke_public_key_b64u,
        &preamble_hash,
        target_share.secret_bytes(),
        *holder_seed,
    )
    .map_err(protocol_error)?;
    let encrypted_delta = seal_ecdsa_lane_payload_v1(
        &input.job.target_signing_worker.hpke_public_key_b64u,
        &preamble_hash,
        delta.as_bytes(),
        *delta_seed,
    )
    .map_err(protocol_error)?;
    let holder_package_digest = holder_package.digest().map_err(protocol_error)?;
    let encrypted_delta_digest = encrypted_delta.digest().map_err(protocol_error)?;
    let holder_round = prepare_ecdsa_additive_lane_holder_round_v1(
        &input.job,
        Base64UrlUnpadded::encode_string(target_share.public_key33()),
        Base64UrlUnpadded::encode_string(&encrypted_delta_digest),
        Base64UrlUnpadded::encode_string(&holder_package_digest),
        Base64UrlUnpadded::encode_string(&preamble_hash),
        input.holder_committed_at_ms,
    )
    .map_err(protocol_error)?;
    serialize_output(&holder_round, holder_package, encrypted_delta)
}

fn sample_target_share() -> Result<EcdsaLaneClientShare, JsValue> {
    for _ in 0..128 {
        let randomness = random32()?;
        if let Ok(share) = sample_ecdsa_lane_client_share_v1(*randomness) {
            return Ok(share);
        }
    }
    Err(js_error(
        "worker CSPRNG did not produce a canonical ECDSA lane scalar",
    ))
}

fn random32() -> Result<Zeroizing<[u8; 32]>, JsValue> {
    let mut value = Zeroizing::new([0_u8; 32]);
    getrandom::getrandom(value.as_mut())
        .map_err(|error| js_error(format!("worker CSPRNG failed: {error}")))?;
    Ok(value)
}

fn serialize_output(
    holder_round: &EcdsaAdditiveLaneHolderRoundV1,
    holder_package: EcdsaLaneEncryptedPayloadV1,
    encrypted_delta: EcdsaLaneEncryptedPayloadV1,
) -> Result<String, JsValue> {
    let holder_package_json =
        serde_json::to_string(&holder_package).map_err(|error| js_error(error.to_string()))?;
    let encrypted_delta_package_json =
        serde_json::to_string(&encrypted_delta).map_err(|error| js_error(error.to_string()))?;
    serde_json::to_string(&HolderPreparationOutputV1 {
        kind: HOLDER_PREPARATION_KIND_V1,
        holder_round: HolderRoundWireV1 {
            kind: HOLDER_ROUND_KIND_V1,
            round: holder_round,
        },
        holder_package: HolderPackageWireV1 {
            kind: HOLDER_PACKAGE_KIND_V1,
            ecdsa_encrypted_material_envelope_json: holder_package_json,
        },
        encrypted_delta_package_json,
    })
    .map_err(|error| js_error(error.to_string()))
}

fn decode_fixed<const N: usize>(value: &str, label: &str) -> Result<[u8; N], JsValue> {
    let decoded = Base64UrlUnpadded::decode_vec(value)
        .map_err(|error| js_error(format!("{label} is invalid: {error}")))?;
    decoded
        .try_into()
        .map_err(|_| js_error(format!("{label} must decode to {N} bytes")))
}

fn js_error(message: impl Into<String>) -> JsValue {
    JsValue::from_str(&message.into())
}

fn protocol_error(error: EcdsaClientProtocolError) -> JsValue {
    js_error(format!("ECDSA lane protocol failed: {error:?}"))
}

fn derivation_error(error: impl core::fmt::Display) -> JsValue {
    js_error(format!("ECDSA lane derivation failed: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

    #[test]
    fn holder_session_consumes_and_zeroizes_its_ready_state() {
        assert_zeroize_on_drop::<EcdsaLaneHolderSessionV1>();
        let mut session = EcdsaLaneHolderSessionV1 {
            ready_state_blob: Some(EcdsaRoleLocalReadyStateBlob {
                state_blob: vec![7_u8; 32],
            }),
        };
        assert!(session.take_ready_state_blob().is_some());
        assert!(session.take_ready_state_blob().is_none());
    }
}
