use base64ct::{Base64UrlUnpadded, Encoding};
use router_ab_ecdsa_client_protocol::{
    seal_linked_device_ecdsa_source_contribution_v1, EcdsaClientProtocolError,
    LinkedDeviceEcdsaSourceContributionPackageV1, LinkedDeviceEcdsaSourceContributionPreparationV1,
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

const SOURCE_CONTRIBUTION_PREPARATION_INPUT_KIND_V1: &str =
    "linked_device_ecdsa_source_contribution_preparation_input_v1";
const SOURCE_CONTRIBUTION_PREPARATION_OUTPUT_KIND_V1: &str =
    "linked_device_ecdsa_source_contribution_package_v1";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SourceContributionPreparationInputV1 {
    kind: String,
    preparation: LinkedDeviceEcdsaSourceContributionPreparationV1,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SourceContributionPreparationOutputV1<'a> {
    kind: &'static str,
    package: &'a LinkedDeviceEcdsaSourceContributionPackageV1,
}

/// One-use Device 1 ECDSA source-contribution session.
///
/// The source client scalar is opened and consumed inside this WASM object.
/// The sampled target scalar is sealed directly to Device 2, while only the
/// additive source-client-minus-target-client delta is sealed to the target
/// SigningWorker.
#[wasm_bindgen]
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct LinkedDeviceEcdsaSourceContributionSessionV1 {
    ready_state_blob: Option<EcdsaRoleLocalReadyStateBlob>,
}

impl LinkedDeviceEcdsaSourceContributionSessionV1 {
    fn take_ready_state_blob(&mut self) -> Option<EcdsaRoleLocalReadyStateBlob> {
        self.ready_state_blob.take()
    }
}

#[wasm_bindgen]
impl LinkedDeviceEcdsaSourceContributionSessionV1 {
    /// Opens one exact role-local ready-state envelope inside Rust/WASM.
    #[wasm_bindgen(constructor)]
    pub fn new(
        mut state_blob_b64u: String,
    ) -> Result<LinkedDeviceEcdsaSourceContributionSessionV1, JsValue> {
        let decoded = Base64UrlUnpadded::decode_vec(state_blob_b64u.trim())
            .map_err(|error| js_error(format!("stateBlobB64u is invalid: {error}")));
        state_blob_b64u.zeroize();
        Ok(Self {
            ready_state_blob: Some(EcdsaRoleLocalReadyStateBlob {
                state_blob: decoded?,
            }),
        })
    }

    /// Samples Device 2's client share and returns the two recipient-bound
    /// ciphertexts as one source-contribution package.
    pub fn prepare(&mut self, input_json: &str) -> Result<String, JsValue> {
        let input: SourceContributionPreparationInputV1 = serde_json::from_str(input_json)
            .map_err(|error| {
                js_error(format!(
                    "linked-device source contribution input is invalid: {error}"
                ))
            })?;
        if input.kind != SOURCE_CONTRIBUTION_PREPARATION_INPUT_KIND_V1 {
            return Err(js_error(
                "linked-device source contribution input kind is invalid",
            ));
        }
        input.preparation.validate().map_err(protocol_error)?;
        let ready_state_blob = self.take_ready_state_blob().ok_or_else(|| {
            js_error("linked-device source contribution session was already consumed")
        })?;
        prepare_source_contribution(ready_state_blob, input.preparation)
    }
}

fn prepare_source_contribution(
    ready_state_blob: EcdsaRoleLocalReadyStateBlob,
    preparation: LinkedDeviceEcdsaSourceContributionPreparationV1,
) -> Result<String, JsValue> {
    let source_share32 = Zeroizing::new(
        extract_client_signing_share32_from_ready_state_blob(&ready_state_blob)
            .map_err(|error| js_error(error.to_string()))?,
    );
    let source_client_public_key33 =
        ecdsa_lane_client_public_key_from_share32_v1(*source_share32).map_err(derivation_error)?;
    let admitted_source_client_public_key33 = decode_fixed::<33>(
        &preparation.source.client_public_key33_b64u,
        "preparation.source.clientPublicKey33B64u",
    )?;
    if source_client_public_key33 != admitted_source_client_public_key33 {
        return Err(js_error(
            "ready-state client share does not match the admitted source signer",
        ));
    }
    let admitted_source_relayer_public_key33 = decode_fixed::<33>(
        &preparation.source.relayer_public_key33_b64u,
        "preparation.source.relayerPublicKey33B64u",
    )?;
    let admitted_source_threshold_public_key33 = decode_fixed::<33>(
        &preparation.source.threshold_public_key33_b64u,
        "preparation.source.thresholdPublicKey33B64u",
    )?;
    let reconstructed_threshold_public_key33 = add_secp256k1_public_keys_33(
        &source_client_public_key33,
        &admitted_source_relayer_public_key33,
    )
    .map_err(derivation_error)?;
    if reconstructed_threshold_public_key33.as_slice() != admitted_source_threshold_public_key33 {
        return Err(js_error(
            "admitted source shares do not reconstruct the source threshold public key",
        ));
    }

    let target_client_share = sample_target_client_share()?;
    let target_client_public_key33 = *target_client_share.public_key33();
    let target_client_public_key33_b64u =
        Base64UrlUnpadded::encode_string(&target_client_public_key33);
    let binding = preparation
        .bind_target_client_public_key(target_client_public_key33_b64u)
        .map_err(protocol_error)?;
    let binding_digest = binding.digest().map_err(protocol_error)?;
    let delta =
        derive_ecdsa_lane_delta_from_source_share32_v1(*source_share32, &target_client_share)
            .map_err(derivation_error)?;
    let encrypted_delta = seal_linked_device_ecdsa_source_contribution_v1(
        &binding.target.signing_worker_recipient_public_key_b64u,
        &binding_digest,
        delta.as_bytes(),
        *random32()?,
    )
    .map_err(protocol_error)?;
    let encrypted_target_client_share = seal_linked_device_ecdsa_source_contribution_v1(
        &binding.target.client_recipient_public_key_b64u,
        &binding_digest,
        target_client_share.secret_bytes(),
        *random32()?,
    )
    .map_err(protocol_error)?;
    let package = LinkedDeviceEcdsaSourceContributionPackageV1 {
        binding,
        encrypted_delta,
        encrypted_target_client_share,
    };
    package.validate().map_err(protocol_error)?;
    serde_json::to_string(&SourceContributionPreparationOutputV1 {
        kind: SOURCE_CONTRIBUTION_PREPARATION_OUTPUT_KIND_V1,
        package: &package,
    })
    .map_err(|error| js_error(error.to_string()))
}

fn sample_target_client_share() -> Result<EcdsaLaneClientShare, JsValue> {
    for _ in 0..128 {
        let randomness = random32()?;
        if let Ok(share) = sample_ecdsa_lane_client_share_v1(*randomness) {
            return Ok(share);
        }
    }
    Err(js_error(
        "linked-device source contribution CSPRNG did not produce a canonical ECDSA scalar",
    ))
}

fn random32() -> Result<Zeroizing<[u8; 32]>, JsValue> {
    let mut value = Zeroizing::new([0_u8; 32]);
    getrandom::getrandom(value.as_mut()).map_err(|error| {
        js_error(format!(
            "linked-device source contribution CSPRNG failed: {error}"
        ))
    })?;
    Ok(value)
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
    js_error(format!(
        "linked-device source contribution protocol failed: {error:?}"
    ))
}

fn derivation_error(error: impl core::fmt::Display) -> JsValue {
    js_error(format!(
        "linked-device source contribution derivation failed: {error}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

    #[test]
    fn source_contribution_session_consumes_its_ready_state() {
        assert_zeroize_on_drop::<LinkedDeviceEcdsaSourceContributionSessionV1>();
        let mut session = LinkedDeviceEcdsaSourceContributionSessionV1 {
            ready_state_blob: Some(EcdsaRoleLocalReadyStateBlob {
                state_blob: vec![7_u8; 32],
            }),
        };
        assert!(session.take_ready_state_blob().is_some());
        assert!(session.take_ready_state_blob().is_none());
    }
}
