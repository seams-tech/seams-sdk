use base64ct::{Base64UrlUnpadded, Encoding};
use router_ab_ecdsa_client_protocol::{
    open_linked_device_ecdsa_source_contribution_v1,
    seal_linked_device_ecdsa_source_contribution_v1, EcdsaClientProtocolError,
    LinkedDeviceEcdsaSourceContributionPackageV1,
};
use router_ab_ecdsa_derivation::{
    rebind_ecdsa_lane_relayer_share_bytes_v1, EcdsaLaneDelta, EcdsaLanePublicIdentityBindingV1,
    RouterAbEcdsaDerivationError,
};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const SOURCE_CONTRIBUTION_WORKER_INPUT_KIND_V1: &str =
    "linked_device_ecdsa_source_contribution_worker_input_v1";
const SOURCE_CONTRIBUTION_WORKER_OUTPUT_KIND_V1: &str =
    "linked_device_ecdsa_source_contribution_inactive_material_v1";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SourceContributionWorkerInputV1 {
    kind: String,
    package: LinkedDeviceEcdsaSourceContributionPackageV1,
    target_server_material_recipient_public_key_b64u: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SourceContributionWorkerOutputV1<'a> {
    kind: &'static str,
    state: &'static str,
    reservation_id: String,
    binding: &'a router_ab_ecdsa_client_protocol::LinkedDeviceEcdsaSourceContributionBindingV1,
    binding_digest_b64u: String,
    target_relayer_public_key33_b64u: String,
    threshold_public_key33_b64u: String,
    threshold_ethereum_address20_b64u: String,
    encrypted_target_client_share:
        router_ab_ecdsa_client_protocol::LinkedDeviceEcdsaEncryptedSourceContributionV1,
    encrypted_target_server_share:
        router_ab_ecdsa_client_protocol::LinkedDeviceEcdsaEncryptedSourceContributionV1,
}

/// One-use SigningWorker source-contribution consumer.
///
/// The source relayer scalar and the delta-recipient private key are consumed
/// before any target material is returned. The returned inactive server share
/// is encrypted to the exact target material recipient and carries the same
/// binding digest used for reservation idempotency.
#[wasm_bindgen]
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct LinkedDeviceEcdsaSourceContributionWorkerSessionV1 {
    source_relayer_share32: Option<Zeroizing<[u8; 32]>>,
    delta_recipient_private_key32: Option<Zeroizing<[u8; 32]>>,
}

#[wasm_bindgen]
impl LinkedDeviceEcdsaSourceContributionWorkerSessionV1 {
    /// Loads source material and the one-use delta recipient key.
    #[wasm_bindgen(constructor)]
    pub fn new(
        mut source_relayer_share32_b64u: String,
        mut delta_recipient_private_key32_b64u: String,
    ) -> Result<LinkedDeviceEcdsaSourceContributionWorkerSessionV1, JsValue> {
        let source = decode_fixed::<32>(&source_relayer_share32_b64u, "sourceRelayerShare32B64u");
        let recipient = decode_fixed::<32>(
            &delta_recipient_private_key32_b64u,
            "deltaRecipientPrivateKey32B64u",
        );
        source_relayer_share32_b64u.zeroize();
        delta_recipient_private_key32_b64u.zeroize();
        Ok(Self {
            source_relayer_share32: Some(Zeroizing::new(source?)),
            delta_recipient_private_key32: Some(Zeroizing::new(recipient?)),
        })
    }

    /// Opens and consumes one source contribution, rebinds the source
    /// relayer share, and seals Device 2's inactive server material.
    pub fn complete(&mut self, input_json: &str) -> Result<String, JsValue> {
        let input: SourceContributionWorkerInputV1 =
            serde_json::from_str(input_json).map_err(|error| {
                js_error(format!(
                    "linked-device source contribution worker input is invalid: {error}"
                ))
            })?;
        if input.kind != SOURCE_CONTRIBUTION_WORKER_INPUT_KIND_V1 {
            return Err(js_error(
                "linked-device source contribution worker input kind is invalid",
            ));
        }
        input.package.validate().map_err(protocol_error)?;
        let source_relayer_share32 = self.source_relayer_share32.take().ok_or_else(|| {
            js_error("linked-device source contribution worker was already consumed")
        })?;
        let delta_recipient_private_key32 =
            self.delta_recipient_private_key32.take().ok_or_else(|| {
                js_error("linked-device source contribution recipient was already consumed")
            })?;
        complete_source_contribution(input, source_relayer_share32, delta_recipient_private_key32)
    }
}

fn complete_source_contribution(
    input: SourceContributionWorkerInputV1,
    source_relayer_share32: Zeroizing<[u8; 32]>,
    delta_recipient_private_key32: Zeroizing<[u8; 32]>,
) -> Result<String, JsValue> {
    let binding = &input.package.binding;
    if input.target_server_material_recipient_public_key_b64u
        != binding.target.signing_worker_recipient_public_key_b64u
    {
        return Err(js_error(
            "target server material recipient differs from the bound SigningWorker recipient",
        ));
    }
    let binding_digest = binding.digest().map_err(protocol_error)?;
    let opened_delta = Zeroizing::new(
        open_linked_device_ecdsa_source_contribution_v1(
            &input.package.encrypted_delta,
            &delta_recipient_private_key32,
            &binding_digest,
        )
        .map_err(protocol_error)?,
    );
    let delta32: [u8; 32] = opened_delta
        .as_slice()
        .try_into()
        .map_err(|_| js_error("source contribution delta must open to exactly 32 bytes"))?;
    let delta = EcdsaLaneDelta::from_bytes(delta32).map_err(derivation_error)?;
    let source_identity = EcdsaLanePublicIdentityBindingV1 {
        source_client_public_key33: decode_fixed::<33>(
            &binding.source.client_public_key33_b64u,
            "binding.source.clientPublicKey33B64u",
        )?,
        source_relayer_public_key33: decode_fixed::<33>(
            &binding.source.relayer_public_key33_b64u,
            "binding.source.relayerPublicKey33B64u",
        )?,
        threshold_public_key33: decode_fixed::<33>(
            &binding.source.threshold_public_key33_b64u,
            "binding.source.thresholdPublicKey33B64u",
        )?,
        threshold_ethereum_address20: decode_fixed::<20>(
            &binding.source.threshold_ethereum_address20_b64u,
            "binding.source.thresholdEthereumAddress20B64u",
        )?,
    };
    let target_client_public_key33 = decode_fixed::<33>(
        &binding.target_client_public_key33_b64u,
        "binding.targetClientPublicKey33B64u",
    )?;
    let rebound = rebind_ecdsa_lane_relayer_share_bytes_v1(
        *source_relayer_share32,
        &source_identity,
        &delta,
        target_client_public_key33,
    )
    .map_err(derivation_error)?;
    let target_relayer_public_key33 = rebound.target_relayer_public_key33;
    let threshold_public_key33 = rebound.target_threshold_public_key33;
    let threshold_ethereum_address20 = rebound.target_ethereum_address20;
    let target_relayer_share32 = Zeroizing::new(rebound.into_target_relayer_share32());
    let encrypted_target_server_share = seal_linked_device_ecdsa_source_contribution_v1(
        &input.target_server_material_recipient_public_key_b64u,
        &binding_digest,
        target_relayer_share32.as_ref(),
        *random32()?,
    )
    .map_err(protocol_error)?;
    let output = SourceContributionWorkerOutputV1 {
        kind: SOURCE_CONTRIBUTION_WORKER_OUTPUT_KIND_V1,
        state: "inactive",
        reservation_id: source_contribution_reservation_id(&binding_digest),
        binding,
        binding_digest_b64u: Base64UrlUnpadded::encode_string(&binding_digest),
        target_relayer_public_key33_b64u: Base64UrlUnpadded::encode_string(
            &target_relayer_public_key33,
        ),
        threshold_public_key33_b64u: Base64UrlUnpadded::encode_string(&threshold_public_key33),
        threshold_ethereum_address20_b64u: Base64UrlUnpadded::encode_string(
            &threshold_ethereum_address20,
        ),
        encrypted_target_client_share: input.package.encrypted_target_client_share.clone(),
        encrypted_target_server_share,
    };
    serde_json::to_string(&output).map_err(|error| js_error(error.to_string()))
}

fn source_contribution_reservation_id(binding_digest: &[u8; 32]) -> String {
    format!(
        "linked-device-ecdsa-source-contribution-inactive-v1:{}",
        Base64UrlUnpadded::encode_string(binding_digest)
    )
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

fn derivation_error(error: RouterAbEcdsaDerivationError) -> JsValue {
    js_error(format!(
        "linked-device source contribution derivation failed: {error}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

    #[test]
    fn worker_session_consumes_source_material_and_recipient() {
        assert_zeroize_on_drop::<LinkedDeviceEcdsaSourceContributionWorkerSessionV1>();
        let mut session = LinkedDeviceEcdsaSourceContributionWorkerSessionV1 {
            source_relayer_share32: Some(Zeroizing::new([7_u8; 32])),
            delta_recipient_private_key32: Some(Zeroizing::new([8_u8; 32])),
        };
        assert!(session.source_relayer_share32.take().is_some());
        assert!(session.delta_recipient_private_key32.take().is_some());
        assert!(session.source_relayer_share32.is_none());
        assert!(session.delta_recipient_private_key32.is_none());
    }
}
