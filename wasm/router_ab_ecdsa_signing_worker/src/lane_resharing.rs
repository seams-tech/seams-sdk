use base64ct::{Base64UrlUnpadded, Encoding};
use router_ab_ecdsa_client_protocol::{
    complete_ecdsa_additive_lane_server_round_v1, ecdsa_lane_public_identity_relation_digest_v1,
    open_ecdsa_lane_payload_v1, seal_ecdsa_lane_payload_v1,
    verify_ecdsa_additive_lane_transcript_v1, EcdsaAdditiveLaneHolderRoundV1,
    EcdsaAdditiveLaneJobV1, EcdsaAdditiveLaneServerRoundV1, EcdsaAdditiveLaneTranscriptV1,
    EcdsaClientProtocolError, EcdsaLaneEncryptedPayloadV1,
};
use router_ab_ecdsa_derivation::{
    rebind_ecdsa_lane_relayer_share_bytes_v1, EcdsaLaneDelta, EcdsaLanePublicIdentityBindingV1,
    RouterAbEcdsaDerivationError,
};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;
use zeroize::{Zeroize, Zeroizing};

const SERVER_COMPLETION_KIND_V1: &str = "ecdsa_additive_lane_server_completion_v1";
const SERVER_ROUND_KIND_V1: &str = "ecdsa_additive_lane_server_round_v1";
const TRANSCRIPT_KIND_V1: &str = "ecdsa_additive_lane_transcript_v1";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct HolderRoundWireV1 {
    kind: String,
    #[serde(flatten)]
    round: EcdsaAdditiveLaneHolderRoundV1,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ServerCompletionInputV1 {
    job: EcdsaAdditiveLaneJobV1,
    holder_round: HolderRoundWireV1,
    encrypted_delta_package_json: String,
    server_committed_at_ms: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ServerRoundWireV1<'a> {
    kind: &'static str,
    #[serde(flatten)]
    round: &'a EcdsaAdditiveLaneServerRoundV1,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TranscriptWireV1<'a> {
    kind: &'static str,
    #[serde(flatten)]
    transcript: &'a EcdsaAdditiveLaneTranscriptV1,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ServerCompletionOutputV1<'a> {
    kind: &'static str,
    server_round: ServerRoundWireV1<'a>,
    transcript: TranscriptWireV1<'a>,
    sealed_server_material_json: String,
}

/// One-use SigningWorker ECDSA lane session. Source material and the delta
/// recipient private key never leave the Rust/WASM object after construction.
#[wasm_bindgen]
pub struct EcdsaLaneSigningWorkerSessionV1 {
    source_relayer_share32: Option<Zeroizing<[u8; 32]>>,
    delta_recipient_private_key32: Option<Zeroizing<[u8; 32]>>,
}

#[wasm_bindgen]
impl EcdsaLaneSigningWorkerSessionV1 {
    /// Loads the exact active server share and operation recipient key into a
    /// one-use private worker session.
    #[wasm_bindgen(constructor)]
    pub fn new(
        mut source_relayer_share32_b64u: String,
        mut delta_recipient_private_key32_b64u: String,
    ) -> Result<EcdsaLaneSigningWorkerSessionV1, JsValue> {
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

    /// Opens the transient delta, verifies the source and target public
    /// relations, and seals the target server share to its admitted recipient.
    pub fn complete(&mut self, input_json: &str) -> Result<String, JsValue> {
        let input: ServerCompletionInputV1 = serde_json::from_str(input_json)
            .map_err(|error| js_error(format!("lane server input is invalid: {error}")))?;
        input.job.validate().map_err(protocol_error)?;
        if input.holder_round.kind != "ecdsa_additive_lane_holder_round_v1" {
            return Err(js_error("holder round kind is invalid"));
        }
        let source_relayer_share32 = self
            .source_relayer_share32
            .take()
            .ok_or_else(|| js_error("ECDSA lane SigningWorker session was already consumed"))?;
        let delta_recipient_private_key32 = self
            .delta_recipient_private_key32
            .take()
            .ok_or_else(|| js_error("ECDSA lane SigningWorker recipient was already consumed"))?;
        complete_server_artifact(input, source_relayer_share32, delta_recipient_private_key32)
    }
}

fn complete_server_artifact(
    input: ServerCompletionInputV1,
    source_relayer_share32: Zeroizing<[u8; 32]>,
    delta_recipient_private_key32: Zeroizing<[u8; 32]>,
) -> Result<String, JsValue> {
    let preamble_hash = input.job.preamble_hash().map_err(protocol_error)?;
    if input.holder_round.round.preamble_hash_b64u
        != Base64UrlUnpadded::encode_string(&preamble_hash)
    {
        return Err(js_error("holder round is bound to a different lane job"));
    }
    let encrypted_delta: EcdsaLaneEncryptedPayloadV1 =
        serde_json::from_str(&input.encrypted_delta_package_json)
            .map_err(|error| js_error(format!("encrypted delta package is invalid: {error}")))?;
    if encrypted_delta.recipient_public_key_b64u
        != input.job.target_signing_worker.hpke_public_key_b64u
    {
        return Err(js_error(
            "encrypted delta recipient differs from the admitted SigningWorker",
        ));
    }
    let opened_delta = Zeroizing::new(
        open_ecdsa_lane_payload_v1(
            &encrypted_delta,
            &delta_recipient_private_key32,
            &preamble_hash,
        )
        .map_err(protocol_error)?,
    );
    let delta32: [u8; 32] = opened_delta
        .as_slice()
        .try_into()
        .map_err(|_| js_error("encrypted delta must open to exactly 32 bytes"))?;
    let delta = EcdsaLaneDelta::from_bytes(delta32).map_err(derivation_error)?;
    let source_identity = EcdsaLanePublicIdentityBindingV1 {
        source_client_public_key33: decode_fixed(
            &input.job.source_holder_verifying_share33_b64u,
            "job.sourceHolderVerifyingShare33B64u",
        )?,
        source_relayer_public_key33: decode_fixed(
            &input.job.source_server_verifying_share33_b64u,
            "job.sourceServerVerifyingShare33B64u",
        )?,
        threshold_public_key33: decode_fixed(
            &input.job.threshold_public_key33_b64u,
            "job.thresholdPublicKey33B64u",
        )?,
        threshold_ethereum_address20: decode_evm_address20(&input.job.evm_address)?,
    };
    let target_holder_public_key33 = decode_fixed(
        &input
            .holder_round
            .round
            .target_holder_public_commitment33_b64u,
        "holderRound.targetHolderPublicCommitment33B64u",
    )?;
    let rebound = rebind_ecdsa_lane_relayer_share_bytes_v1(
        *source_relayer_share32,
        &source_identity,
        &delta,
        target_holder_public_key33,
    )
    .map_err(derivation_error)?;
    let target_server_public_key33 = rebound.target_relayer_public_key33;
    let target_threshold_public_key33 = rebound.target_threshold_public_key33;
    let target_ethereum_address20 = rebound.target_ethereum_address20;
    let target_server_share32 = Zeroizing::new(rebound.into_target_relayer_share32());
    let seal_seed = random32()?;
    let sealed_server_material = seal_ecdsa_lane_payload_v1(
        &input.job.target_signing_worker.hpke_public_key_b64u,
        &preamble_hash,
        target_server_share32.as_ref(),
        *seal_seed,
    )
    .map_err(protocol_error)?;
    let sealed_server_digest = sealed_server_material.digest().map_err(protocol_error)?;
    let target_session_digest = input
        .job
        .target_threshold_session_set_digest()
        .map_err(protocol_error)?;
    let relation_digest = ecdsa_lane_public_identity_relation_digest_v1(
        &target_holder_public_key33,
        &target_server_public_key33,
        &target_threshold_public_key33,
        &target_ethereum_address20,
    )
    .map_err(protocol_error)?;
    let holder_hash = input.holder_round.round.hash().map_err(protocol_error)?;
    let server_round = complete_ecdsa_additive_lane_server_round_v1(
        &input.job,
        &input.holder_round.round,
        Base64UrlUnpadded::encode_string(&target_server_public_key33),
        Base64UrlUnpadded::encode_string(&sealed_server_digest),
        Base64UrlUnpadded::encode_string(&target_session_digest),
        Base64UrlUnpadded::encode_string(&relation_digest),
        Base64UrlUnpadded::encode_string(&holder_hash),
        input.server_committed_at_ms,
    )
    .map_err(protocol_error)?;
    let transcript = EcdsaAdditiveLaneTranscriptV1 {
        kind: "ecdsa_additive_lane_transcript_v1".to_owned(),
        preamble_hash_b64u: Base64UrlUnpadded::encode_string(&preamble_hash),
        holder_round_hash_b64u: Base64UrlUnpadded::encode_string(&holder_hash),
        server_round_hash_b64u: Base64UrlUnpadded::encode_string(
            &server_round.hash().map_err(protocol_error)?,
        ),
    };
    verify_ecdsa_additive_lane_transcript_v1(
        &input.job,
        &input.holder_round.round,
        &server_round,
        &transcript,
    )
    .map_err(protocol_error)?;
    serialize_output(&server_round, &transcript, sealed_server_material)
}

fn serialize_output(
    server_round: &EcdsaAdditiveLaneServerRoundV1,
    transcript: &EcdsaAdditiveLaneTranscriptV1,
    sealed_server_material: EcdsaLaneEncryptedPayloadV1,
) -> Result<String, JsValue> {
    let sealed_server_material_json = serde_json::to_string(&sealed_server_material)
        .map_err(|error| js_error(error.to_string()))?;
    serde_json::to_string(&ServerCompletionOutputV1 {
        kind: SERVER_COMPLETION_KIND_V1,
        server_round: ServerRoundWireV1 {
            kind: SERVER_ROUND_KIND_V1,
            round: server_round,
        },
        transcript: TranscriptWireV1 {
            kind: TRANSCRIPT_KIND_V1,
            transcript,
        },
        sealed_server_material_json,
    })
    .map_err(|error| js_error(error.to_string()))
}

fn random32() -> Result<Zeroizing<[u8; 32]>, JsValue> {
    let mut value = Zeroizing::new([0_u8; 32]);
    getrandom::getrandom(value.as_mut())
        .map_err(|error| js_error(format!("worker CSPRNG failed: {error}")))?;
    Ok(value)
}

fn decode_fixed<const N: usize>(value: &str, label: &str) -> Result<[u8; N], JsValue> {
    let decoded = Base64UrlUnpadded::decode_vec(value)
        .map_err(|error| js_error(format!("{label} is invalid: {error}")))?;
    decoded
        .try_into()
        .map_err(|_| js_error(format!("{label} must decode to {N} bytes")))
}

fn decode_evm_address20(value: &str) -> Result<[u8; 20], JsValue> {
    let hex = value
        .strip_prefix("0x")
        .ok_or_else(|| js_error("job.evmAddress must use a 0x prefix"))?;
    if hex.len() != 40 {
        return Err(js_error("job.evmAddress must contain exactly 20 bytes"));
    }
    let mut output = [0_u8; 20];
    for (index, byte) in output.iter_mut().enumerate() {
        let offset = index * 2;
        *byte = u8::from_str_radix(&hex[offset..offset + 2], 16)
            .map_err(|_| js_error("job.evmAddress contains invalid hex"))?;
    }
    Ok(output)
}

fn js_error(message: impl Into<String>) -> JsValue {
    JsValue::from_str(&message.into())
}

fn protocol_error(error: EcdsaClientProtocolError) -> JsValue {
    js_error(format!("ECDSA lane protocol failed: {error:?}"))
}

fn derivation_error(error: RouterAbEcdsaDerivationError) -> JsValue {
    js_error(format!("ECDSA lane derivation failed: {error}"))
}
