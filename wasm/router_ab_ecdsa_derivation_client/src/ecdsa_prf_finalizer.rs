use crate::encoders::{base64_url_decode, base64_url_encode};
use router_ab_ecdsa_client_protocol::{
    decode_ecdsa_client_proof_bundle_envelope_v1, finalize_ecdsa_prf_two_party_output_v1,
    open_ecdsa_client_proof_bundle_v1, pair_ecdsa_opened_client_proof_bundles_v1,
    EcdsaClientProofBundleDeliveryKindV1, EcdsaClientProofBundleDeliveryV1,
    EcdsaClientProofBundlePairDeliveryV1,
};
use serde::{Deserialize, Serialize};

pub(crate) fn finalize_encrypted_client_proof_bundles_v1(
    input_json: &str,
    private_key: &[u8; 32],
) -> Result<String, String> {
    serialize_final_output(finalize_encrypted_client_proof_output_v1(
        input_json,
        private_key,
    )?)
}

pub(crate) fn finalize_encrypted_client_proof_output_v1(
    input_json: &str,
    private_key: &[u8; 32],
) -> Result<[u8; 32], String> {
    let input: FinalizeEncryptedClientProofBundlesInputV1 =
        serde_json::from_str(input_json).map_err(|error| error.to_string())?;
    finalize_encrypted_client_proof_input_v1(input, private_key)
}

pub(crate) fn finalize_encrypted_client_proof_input_v1(
    input: FinalizeEncryptedClientProofBundlesInputV1,
    private_key: &[u8; 32],
) -> Result<[u8; 32], String> {
    match input.kind {
        FinalizeEncryptedClientProofBundlesKindV1::FinalizeEncryptedClientProofBundlesV1 => {}
    }
    let signer_a = open_client_wire_bundle(input.bundles.signer_a, private_key)?;
    let signer_b = open_client_wire_bundle(input.bundles.signer_b, private_key)?;
    let pair =
        pair_ecdsa_opened_client_proof_bundles_v1(signer_a, signer_b).map_err(protocol_error)?;
    let context = pair.prf_context().map_err(protocol_error)?;
    finalize_ecdsa_prf_two_party_output_v1(
        &context,
        &pair.signer_a().role_bound_proof,
        &pair.signer_b().role_bound_proof,
    )
    .map_err(protocol_error)
}

fn open_client_wire_bundle(
    input: EcdsaClientProofBundleDeliveryV1,
    private_key: &[u8; 32],
) -> Result<router_ab_ecdsa_client_protocol::EcdsaOpenedClientProofBundleV1, String> {
    match input.kind {
        EcdsaClientProofBundleDeliveryKindV1::RecipientProofBundle => {}
    }
    let wire_transcript_digest =
        decode_fixed_base64::<32>(&input.transcript_digest_b64u, "bundle.transcriptDigestB64u")?;
    let payload = decode_nonempty_base64(&input.payload_b64u, "bundle.payloadB64u")?;
    let envelope =
        decode_ecdsa_client_proof_bundle_envelope_v1(&payload).map_err(protocol_error)?;
    if envelope.transcript_digest != wire_transcript_digest {
        return Err("recipient proof-bundle WireMessage transcript digest mismatch".to_owned());
    }
    open_ecdsa_client_proof_bundle_v1(&envelope, private_key).map_err(protocol_error)
}

fn serialize_final_output(output: [u8; 32]) -> Result<String, String> {
    serde_json::to_string(&FinalizeEcdsaPrfOutputResultV1 {
        kind: FinalizeEcdsaPrfOutputResultKindV1::RouterAbEcdsaPrfOutputV1,
        output32_b64u: base64_url_encode(&output),
    })
    .map_err(|error| error.to_string())
}

fn decode_fixed_base64<const N: usize>(value: &str, field: &str) -> Result<[u8; N], String> {
    let decoded = base64_url_decode(value).map_err(|error| format!("{field}: {error}"))?;
    decoded
        .try_into()
        .map_err(|_| format!("{field} must decode to {N} bytes"))
}

fn decode_nonempty_base64(value: &str, field: &str) -> Result<Vec<u8>, String> {
    let decoded = base64_url_decode(value).map_err(|error| format!("{field}: {error}"))?;
    if decoded.is_empty() {
        return Err(format!("{field} must be non-empty"));
    }
    Ok(decoded)
}

fn protocol_error(error: router_ab_ecdsa_client_protocol::EcdsaClientProtocolError) -> String {
    format!("Router A/B ECDSA PRF finalization failed: {error:?}")
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct FinalizeEncryptedClientProofBundlesInputV1 {
    kind: FinalizeEncryptedClientProofBundlesKindV1,
    bundles: EcdsaClientProofBundlePairDeliveryV1,
}

#[derive(Debug, Deserialize)]
enum FinalizeEncryptedClientProofBundlesKindV1 {
    #[serde(rename = "finalize_encrypted_client_proof_bundles_v1")]
    FinalizeEncryptedClientProofBundlesV1,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct FinalizeEcdsaPrfOutputResultV1 {
    kind: FinalizeEcdsaPrfOutputResultKindV1,
    output32_b64u: String,
}

#[derive(Debug, Serialize)]
enum FinalizeEcdsaPrfOutputResultKindV1 {
    #[serde(rename = "router_ab_ecdsa_prf_output_v1")]
    RouterAbEcdsaPrfOutputV1,
}
