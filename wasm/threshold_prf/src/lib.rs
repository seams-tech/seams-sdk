#![forbid(unsafe_code)]

use js_sys::{Object, Reflect, Uint8Array};
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use threshold_prf::trusted::combine_partials;
use threshold_prf::{
    combine_verified_partials, evaluate_partial, evaluate_partial_with_dleq_proof, PrfDleqProof,
    PrfPartialProofBundle, PrfPartialWire, SigningRootShare, SigningRootShareCommitment,
    SigningRootShareWire, ThresholdPolicy, ValidatedThresholdSet,
};
use threshold_prf::{PrfContext, PrfPurpose, SuiteId};
use wasm_bindgen::prelude::*;
use zeroize::Zeroize;

const PROOF_BUNDLE_WIRE_LEN: usize =
    PrfPartialWire::LEN + SigningRootShareCommitment::LEN + PrfDleqProof::LEN;

fn js_error(message: impl Into<String>) -> JsValue {
    JsValue::from_str(&message.into())
}

fn js_threshold_error(error: impl core::fmt::Display) -> JsValue {
    js_error(format!("threshold-prf error: {error}"))
}

fn validate_ascii_field<'a>(label: &str, value: &'a str) -> Result<&'a str, JsValue> {
    if value.is_empty() {
        return Err(js_error(format!("{label} must be non-empty")));
    }
    if !value.is_ascii() {
        return Err(js_error(format!("{label} must be ASCII-only")));
    }
    if value.len() > usize::from(u16::MAX) {
        return Err(js_error(format!("{label} exceeds u16 length encoding")));
    }
    Ok(value)
}

fn parse_prf_purpose(purpose: &str) -> Result<PrfPurpose, JsValue> {
    match purpose {
        "ecdsa-hss/y_server" => Ok(PrfPurpose::EcdsaHssYServer),
        "ed25519-hss/y_server" => Ok(PrfPurpose::Ed25519HssYServer),
        "ed25519-hss/tau_server" => Ok(PrfPurpose::Ed25519HssTauServer),
        "router-ab/x_client_base/v1" => Ok(PrfPurpose::RouterAbXClientBaseV1),
        "router-ab/x_server_base/v1" => Ok(PrfPurpose::RouterAbXServerBaseV1),
        _ => Err(js_error("unknown threshold-prf purpose")),
    }
}

fn prf_context(purpose: &str, context_bytes: Vec<u8>) -> Result<PrfContext, JsValue> {
    Ok(PrfContext::new(
        SuiteId::Ristretto255Sha512,
        parse_prf_purpose(purpose)?,
        context_bytes,
    ))
}

fn push_len16(out: &mut Vec<u8>, label: &str, value: &str) -> Result<(), JsValue> {
    let value = validate_ascii_field(label, value)?;
    out.extend_from_slice(&(value.len() as u16).to_be_bytes());
    out.extend_from_slice(value.as_bytes());
    Ok(())
}

fn encode_ecdsa_hss_context_with_participants(
    application_binding_digest: &[u8],
    participant_ids: &[u16],
) -> Result<Vec<u8>, JsValue> {
    if application_binding_digest.len() != 32 {
        return Err(js_error("application_binding_digest must be 32 bytes"));
    }
    let participant_count = u8::try_from(participant_ids.len())
        .map_err(|_| js_error("participant count exceeds ecdsa-hss context capacity"))?;
    if participant_count == 0 {
        return Err(js_error("participant_ids must be non-empty"));
    }

    let mut out = Vec::new();
    out.extend_from_slice(b"ecdsa-hss:context:v4");
    push_len16(&mut out, "scheme_id", "ecdsa-hss-v4")?;
    push_len16(&mut out, "curve", "secp256k1")?;
    out.extend_from_slice(application_binding_digest);
    out.push(participant_count);
    for participant_id in participant_ids {
        out.extend_from_slice(&participant_id.to_be_bytes());
    }
    Ok(out)
}

const ED25519_HSS_CONTEXT_VERSION: &str = "v2";
const ED25519_HSS_SCHEME_ID: &str = "ed25519-hss-v2";
const ED25519_HSS_CURVE: &str = "ed25519";
const ED25519_HSS_CONTEXT_BINDING_DOMAIN_V2: &[u8] =
    b"succinct-garbling-proto/ed25519-hss/context-binding/v2";

fn update_len32(hasher: &mut Sha256, value: &str) {
    hasher.update((value.len() as u32).to_be_bytes());
    hasher.update(value.as_bytes());
}

fn ed25519_hss_context_binding_v2_with_min_participants(
    application_binding_digest: &[u8],
    mut participant_ids: Vec<u16>,
    min_participants: usize,
) -> Result<[u8; 32], JsValue> {
    if application_binding_digest.len() != 32 {
        return Err(js_error("application_binding_digest must be 32 bytes"));
    }

    participant_ids.retain(|value| *value > 0);
    participant_ids.sort_unstable();
    participant_ids.dedup();
    if participant_ids.len() < min_participants {
        return Err(js_error(
            "participant_ids must contain the required non-zero identifiers",
        ));
    }

    let mut hasher = Sha256::new();
    hasher.update(ED25519_HSS_CONTEXT_BINDING_DOMAIN_V2);
    update_len32(&mut hasher, ED25519_HSS_CONTEXT_VERSION);
    update_len32(&mut hasher, ED25519_HSS_SCHEME_ID);
    update_len32(&mut hasher, ED25519_HSS_CURVE);
    hasher.update(application_binding_digest);
    hasher.update((participant_ids.len() as u32).to_be_bytes());
    for participant_id in participant_ids {
        hasher.update(participant_id.to_be_bytes());
    }

    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Ok(out)
}

fn decode_policy(threshold: u32, share_count: u32) -> Result<ThresholdPolicy, JsValue> {
    let threshold = u16::try_from(threshold).map_err(|_| js_error("threshold must fit in u16"))?;
    let share_count =
        u16::try_from(share_count).map_err(|_| js_error("share_count must fit in u16"))?;
    ThresholdPolicy::from_u16s(threshold, share_count).map_err(js_threshold_error)
}

fn decode_signing_root_share_set(
    threshold: u32,
    share_count: u32,
    mut share_wire_bytes: Vec<u8>,
) -> Result<ValidatedThresholdSet<SigningRootShare>, JsValue> {
    let policy = match decode_policy(threshold, share_count) {
        Ok(policy) => policy,
        Err(error) => {
            share_wire_bytes.zeroize();
            return Err(error);
        }
    };
    let expected_len = usize::from(policy.threshold().get()) * SigningRootShareWire::LEN;
    if share_wire_bytes.len() != expected_len {
        share_wire_bytes.zeroize();
        return Err(js_error(format!(
            "share_wires must contain exactly {} share wires",
            policy.threshold()
        )));
    }

    let shares = share_wire_bytes
        .chunks_exact(SigningRootShareWire::LEN)
        .map(|chunk| {
            SigningRootShareWire::decode_slice(chunk)
                .and_then(|wire| wire.to_share())
                .map_err(js_threshold_error)
        })
        .collect::<Result<Vec<_>, _>>();
    share_wire_bytes.zeroize();
    ValidatedThresholdSet::from_signing_root_shares(policy, shares?).map_err(js_threshold_error)
}

fn decode_single_signing_root_share(
    mut share_wire_bytes: Vec<u8>,
) -> Result<SigningRootShare, JsValue> {
    if share_wire_bytes.len() != SigningRootShareWire::LEN {
        share_wire_bytes.zeroize();
        return Err(js_error(format!(
            "share_wire must be exactly {} bytes",
            SigningRootShareWire::LEN
        )));
    }
    let share = SigningRootShareWire::decode_slice(&share_wire_bytes)
        .and_then(|wire| wire.to_share())
        .map_err(js_threshold_error);
    share_wire_bytes.zeroize();
    share
}

fn decode_proof_bundle_set(
    threshold: u32,
    share_count: u32,
    mut proof_bundle_bytes: Vec<u8>,
) -> Result<ValidatedThresholdSet<PrfPartialProofBundle>, JsValue> {
    let policy = match decode_policy(threshold, share_count) {
        Ok(policy) => policy,
        Err(error) => {
            proof_bundle_bytes.zeroize();
            return Err(error);
        }
    };
    let expected_len = usize::from(policy.threshold().get()) * PROOF_BUNDLE_WIRE_LEN;
    if proof_bundle_bytes.len() != expected_len {
        proof_bundle_bytes.zeroize();
        return Err(js_error(format!(
            "proof_bundle_wires must contain exactly {} proof bundles",
            policy.threshold()
        )));
    }

    let bundles = proof_bundle_bytes
        .chunks_exact(PROOF_BUNDLE_WIRE_LEN)
        .map(decode_proof_bundle)
        .collect::<Result<Vec<_>, _>>();
    proof_bundle_bytes.zeroize();
    ValidatedThresholdSet::from_proof_bundles(policy, bundles?).map_err(js_threshold_error)
}

fn decode_proof_bundle(chunk: &[u8]) -> Result<PrfPartialProofBundle, JsValue> {
    let commitment_start = PrfPartialWire::LEN;
    let proof_start = commitment_start + SigningRootShareCommitment::LEN;
    let proof_end = proof_start + PrfDleqProof::LEN;

    let partial = PrfPartialWire::decode_slice(&chunk[..commitment_start])
        .and_then(|wire| wire.to_partial())
        .map_err(js_threshold_error)?;
    let commitment = SigningRootShareCommitment::from_slice(&chunk[commitment_start..proof_start])
        .map_err(js_threshold_error)?;
    let proof =
        PrfDleqProof::from_slice(&chunk[proof_start..proof_end]).map_err(js_threshold_error)?;

    Ok(PrfPartialProofBundle {
        partial,
        commitment,
        proof,
    })
}

fn encode_proof_bundle(bundle: PrfPartialProofBundle) -> Vec<u8> {
    let mut out = Vec::with_capacity(PROOF_BUNDLE_WIRE_LEN);
    out.extend_from_slice(&PrfPartialWire::from_partial(&bundle.partial).to_bytes());
    out.extend_from_slice(&bundle.commitment.to_bytes());
    out.extend_from_slice(&bundle.proof.to_bytes());
    out
}

fn derive_hss_output_from_shares(
    shares: &ValidatedThresholdSet<SigningRootShare>,
    purpose: PrfPurpose,
    context_bytes: Vec<u8>,
) -> Result<Vec<u8>, JsValue> {
    let context = PrfContext::new(SuiteId::Ristretto255Sha512, purpose, context_bytes);
    let partials = shares
        .values()
        .iter()
        .map(|share| evaluate_partial(share, &context).map_err(js_threshold_error))
        .collect::<Result<Vec<_>, _>>()?;
    let partial_set = ValidatedThresholdSet::from_partials(*shares.policy(), partials)
        .map_err(js_threshold_error)?;
    let output = combine_partials(&partial_set, &context).map_err(js_threshold_error)?;
    Ok(output.as_bytes().to_vec())
}

fn combine_proof_bundles(
    threshold: u32,
    share_count: u32,
    proof_bundle_wires: Vec<u8>,
    purpose: String,
    context_bytes: Vec<u8>,
) -> Result<Vec<u8>, JsValue> {
    let bundles = decode_proof_bundle_set(threshold, share_count, proof_bundle_wires)?;
    let context = prf_context(&purpose, context_bytes)?;
    let output = combine_verified_partials(&bundles, &context).map_err(js_threshold_error)?;
    Ok(output.as_bytes().to_vec())
}

fn sorted_share_ids(shares: &ValidatedThresholdSet<SigningRootShare>) -> Vec<u16> {
    let mut ids = shares
        .values()
        .iter()
        .map(|share| share.id().get().get())
        .collect::<Vec<_>>();
    ids.sort_unstable();
    ids
}

fn set_bytes_field(object: &Object, name: &str, bytes: &[u8]) -> Result<(), JsValue> {
    Reflect::set(
        object,
        &JsValue::from_str(name),
        &Uint8Array::from(bytes).into(),
    )
    .map(|_| ())
    .map_err(|_| js_error(format!("failed to serialize ed25519-hss field: {name}")))
}

fn ed25519_hss_server_inputs_output(
    binding: &[u8; 32],
    y_relayer: &[u8],
    tau_relayer: &[u8],
) -> Result<JsValue, JsValue> {
    let object = Object::new();
    set_bytes_field(&object, "contextBinding", binding)?;
    set_bytes_field(&object, "yRelayer", y_relayer)?;
    set_bytes_field(&object, "tauRelayer", tau_relayer)?;
    Ok(object.into())
}

#[wasm_bindgen]
pub fn init_threshold_prf() {
    // Reserved for future logger/metrics initialization.
}

#[wasm_bindgen]
pub fn threshold_prf_derive_ecdsa_hss_y_relayer(
    threshold: u32,
    share_count: u32,
    share_wires: Vec<u8>,
    application_binding_digest: Vec<u8>,
) -> Result<Vec<u8>, JsValue> {
    let shares = decode_signing_root_share_set(threshold, share_count, share_wires)?;
    let participant_ids = sorted_share_ids(&shares);
    let context_bytes =
        encode_ecdsa_hss_context_with_participants(&application_binding_digest, &participant_ids)?;
    derive_hss_output_from_shares(&shares, PrfPurpose::EcdsaHssYServer, context_bytes)
}

#[wasm_bindgen]
pub fn threshold_prf_combine_verified_partials(
    threshold: u32,
    share_count: u32,
    proof_bundle_wires: Vec<u8>,
    purpose: String,
    context_bytes: Vec<u8>,
) -> Result<Vec<u8>, JsValue> {
    combine_proof_bundles(
        threshold,
        share_count,
        proof_bundle_wires,
        purpose,
        context_bytes,
    )
}

#[wasm_bindgen]
pub fn threshold_prf_evaluate_partial_with_dleq_proof(
    share_wire: Vec<u8>,
    purpose: String,
    context_bytes: Vec<u8>,
) -> Result<Vec<u8>, JsValue> {
    let share = decode_single_signing_root_share(share_wire)?;
    let context = prf_context(&purpose, context_bytes)?;
    let mut rng = OsRng;
    let bundle =
        evaluate_partial_with_dleq_proof(&share, &context, &mut rng).map_err(js_threshold_error)?;
    Ok(encode_proof_bundle(bundle))
}

#[wasm_bindgen]
pub fn threshold_prf_derive_ed25519_hss_server_inputs(
    threshold: u32,
    share_count: u32,
    share_wires: Vec<u8>,
    application_binding_digest: Vec<u8>,
) -> Result<JsValue, JsValue> {
    let shares = decode_signing_root_share_set(threshold, share_count, share_wires)?;
    let participant_ids = sorted_share_ids(&shares);
    let binding = ed25519_hss_context_binding_v2_with_min_participants(
        &application_binding_digest,
        participant_ids,
        usize::from(shares.policy().threshold().get()),
    )?;
    let y_relayer =
        derive_hss_output_from_shares(&shares, PrfPurpose::Ed25519HssYServer, binding.to_vec())?;
    let tau_relayer =
        derive_hss_output_from_shares(&shares, PrfPurpose::Ed25519HssTauServer, binding.to_vec())?;

    ed25519_hss_server_inputs_output(&binding, &y_relayer, &tau_relayer)
}

#[cfg(all(test, target_arch = "wasm32"))]
mod tests {
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;
    use threshold_prf::{
        combine_verified_partials as core_combine_verified_partials,
        evaluate_partial_with_dleq_proof as core_evaluate_partial_with_dleq_proof,
        generate_signing_root, split_signing_root,
    };
    use wasm_bindgen_test::wasm_bindgen_test;

    use super::*;

    const ROUTER_CLIENT_PURPOSE: &str = "router-ab/x_client_base/v1";

    fn seeded_rng(seed: u8) -> ChaCha20Rng {
        ChaCha20Rng::from_seed([seed; 32])
    }

    fn router_context(bytes: &'static [u8]) -> PrfContext {
        PrfContext::new(
            SuiteId::Ristretto255Sha512,
            PrfPurpose::RouterAbXClientBaseV1,
            bytes,
        )
    }

    #[wasm_bindgen_test]
    fn combine_verified_partials_export_matches_core_api() {
        let policy = ThresholdPolicy::from_u16s(3, 5).unwrap();
        let mut root_rng = seeded_rng(21);
        let root = generate_signing_root(&mut root_rng);
        let shares = split_signing_root(&root, policy, &mut root_rng).unwrap();
        let context = router_context(b"wasm:proof-bundles");
        let bundles = vec![
            core_evaluate_partial_with_dleq_proof(&shares[0], &context, &mut seeded_rng(22))
                .unwrap(),
            core_evaluate_partial_with_dleq_proof(&shares[2], &context, &mut seeded_rng(23))
                .unwrap(),
            core_evaluate_partial_with_dleq_proof(&shares[4], &context, &mut seeded_rng(24))
                .unwrap(),
        ];
        let bundle_set =
            ValidatedThresholdSet::from_proof_bundles(policy, bundles.clone()).unwrap();
        let expected = core_combine_verified_partials(&bundle_set, &context)
            .unwrap()
            .as_bytes()
            .to_vec();
        let bundle_wires = bundles
            .iter()
            .flat_map(|bundle| {
                let mut bytes = Vec::with_capacity(PROOF_BUNDLE_WIRE_LEN);
                bytes.extend_from_slice(&PrfPartialWire::from_partial(&bundle.partial).to_bytes());
                bytes.extend_from_slice(&bundle.commitment.to_bytes());
                bytes.extend_from_slice(&bundle.proof.to_bytes());
                bytes
            })
            .collect();

        let actual = threshold_prf_combine_verified_partials(
            3,
            5,
            bundle_wires,
            ROUTER_CLIENT_PURPOSE.to_owned(),
            b"wasm:proof-bundles".to_vec(),
        )
        .unwrap();

        assert_eq!(actual, expected);
    }

    #[wasm_bindgen_test]
    fn combine_verified_partials_export_rejects_malformed_bundle_bytes() {
        let mut malformed = vec![0u8; PROOF_BUNDLE_WIRE_LEN - 1];
        assert!(threshold_prf_combine_verified_partials(
            1,
            1,
            malformed.clone(),
            ROUTER_CLIENT_PURPOSE.to_owned(),
            b"wasm:malformed-bundle".to_vec(),
        )
        .is_err());

        malformed.resize(PROOF_BUNDLE_WIRE_LEN, 0);
        assert!(threshold_prf_combine_verified_partials(
            1,
            1,
            malformed,
            ROUTER_CLIENT_PURPOSE.to_owned(),
            b"wasm:malformed-bundle".to_vec(),
        )
        .is_err());
    }

    #[wasm_bindgen_test]
    fn proof_bundle_wire_length_matches_public_component_widths() {
        assert_eq!(
            PROOF_BUNDLE_WIRE_LEN,
            PrfPartialWire::LEN + SigningRootShareCommitment::LEN + PrfDleqProof::LEN
        );
    }
}
