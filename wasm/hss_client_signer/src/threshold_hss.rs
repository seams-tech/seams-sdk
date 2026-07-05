use crate::encoders::{base64_url_decode, base64_url_encode};
use crate::js::{
    get_optional_string, get_required_string, get_required_u16_vec, object, set_f64, set_string,
    set_u16_vec, set_u32,
};
use ecdsa_hss::EcdsaHssStableKeyContext;
use ed25519_hss::{
    client::{
        output_mask::{
            derive_client_output_mask, ClientOutputMaskContext, ClientOutputMaskOperation,
        },
        ClientDriverState, ClientOtState, ClientSession,
    },
    protocol::prepare_prime_order_succinct_hss_client,
    role_signing::{
        create_role_separated_ed25519_client_signature_share_v1,
        prepare_role_separated_ed25519_round1_v1, role_separated_ed25519_client_verifying_share_v1,
        RoleSeparatedEd25519ClientShareRequestV1, RoleSeparatedEd25519CommitmentsV1,
    },
    runtime::SharedRuntime,
    shared::CanonicalContext,
    wire::{RoleSeparatedServerInputDeliveryPacket, WireMessage},
};
use js_sys::{Date, Reflect};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use signer_core::commands::{
    Base64UrlEncodingV1, EcdsaClientBootstrapAlgorithmV1, EcdsaClientBootstrapContextV1,
    EcdsaClientBootstrapFactsV1, EcdsaClientBootstrapParticipantsV1, EcdsaPreparePublicFactsV1,
    EcdsaRoleLocalPendingStateBlobV1, PendingStateBlobKindV1, PrepareEcdsaClientBootstrapOutputV1,
    Secp256k1CurveNameV1, SignerCoreProducerV1,
};
use signer_core::error::{CoreResult, SignerCoreError, SignerCoreErrorCode};
use signer_core::threshold_ecdsa_hss::{
    extract_client_signing_share32_from_ready_state_blob, finalize_ecdsa_client_bootstrap,
    prepare_ecdsa_client_bootstrap, EcdsaRoleLocalReadyStateBlob,
    FinalizeEcdsaClientBootstrapCommand, PrepareEcdsaClientBootstrapCommand,
    RelayerPublicIdentityInput,
};
use std::{cell::RefCell, collections::HashMap};
use wasm_bindgen::prelude::*;

const HSS_CLIENT_SESSION_HANDLE_PREFIX: &str = "ed25519-hss-client-session";
const HSS_CLIENT_SESSION_HANDLE_LIMIT: usize = 32;
const HSS_CLIENT_SESSION_HANDLE_TTL_MS: f64 = 5.0 * 60.0 * 1000.0;

struct HssClientSessionHandleEntry {
    issued_id: u64,
    issued_at_ms: f64,
    context_binding: [u8; 32],
    driver_state: ClientDriverState,
    materialized: Option<(SharedRuntime, ClientSession)>,
}

#[derive(Default)]
struct HssClientSessionHandleStore {
    next_id: u64,
    entries: HashMap<String, HssClientSessionHandleEntry>,
}

thread_local! {
    static HSS_CLIENT_SESSION_HANDLES: RefCell<HssClientSessionHandleStore> =
        RefCell::new(HssClientSessionHandleStore::default());
}

enum HssClientSessionSource {
    WorkerHandle(String),
    SerializedState(ClientDriverState),
}

fn elapsed_ms(started_at: f64) -> f64 {
    (Date::now() - started_at).max(0.0)
}

fn ns_to_ms(value: u128) -> f64 {
    value as f64 / 1_000_000.0
}

fn insert_hss_client_session_handle(
    driver_state: ClientDriverState,
    materialized: Option<(SharedRuntime, ClientSession)>,
) -> String {
    HSS_CLIENT_SESSION_HANDLES.with(|store_cell| {
        let mut store = store_cell.borrow_mut();
        let now_ms = Date::now();
        prune_expired_hss_client_session_handles(&mut store, now_ms);
        store.next_id = store.next_id.saturating_add(1);
        let issued_id = store.next_id;
        let handle = format!("{HSS_CLIENT_SESSION_HANDLE_PREFIX}-{issued_id}");
        if store.entries.len() >= HSS_CLIENT_SESSION_HANDLE_LIMIT {
            if let Some(oldest_handle) = store
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.issued_id)
                .map(|(handle, _)| handle.clone())
            {
                store.entries.remove(&oldest_handle);
            }
        }
        store.entries.insert(
            handle.clone(),
            HssClientSessionHandleEntry {
                issued_id,
                issued_at_ms: now_ms,
                context_binding: driver_state.evaluator_session.context_binding,
                driver_state,
                materialized,
            },
        );
        handle
    })
}

fn prune_expired_hss_client_session_handles(store: &mut HssClientSessionHandleStore, now_ms: f64) {
    store
        .entries
        .retain(|_, entry| now_ms - entry.issued_at_ms <= HSS_CLIENT_SESSION_HANDLE_TTL_MS);
}

fn remove_hss_client_session_handle(handle: &str) {
    HSS_CLIENT_SESSION_HANDLES.with(|store_cell| {
        store_cell.borrow_mut().entries.remove(handle);
    });
}

fn hss_client_session_source_from_js(args: &JsValue) -> Result<HssClientSessionSource, JsValue> {
    match get_optional_string(args, "sessionSource")?.as_deref() {
        Some("worker_handle") => Ok(HssClientSessionSource::WorkerHandle(get_required_string(
            args,
            "workerSessionHandle",
        )?)),
        Some("serialized_state") | None => {
            let evaluator_driver_state_b64u =
                get_required_string(args, "evaluatorDriverStateB64u")?;
            Ok(HssClientSessionSource::SerializedState(decode_state_blob(
                &evaluator_driver_state_b64u,
                "evaluatorDriverStateB64u",
            )?))
        }
        Some(other) => Err(JsValue::from_str(&format!(
            "Invalid args: unsupported sessionSource {other}"
        ))),
    }
}

fn serialized_hss_client_driver_state_from_js(
    args: &JsValue,
) -> Result<ClientDriverState, JsValue> {
    match get_optional_string(args, "sessionSource")?.as_deref() {
        Some("worker_handle") => Err(JsValue::from_str(
            "Invalid args: workerSessionHandle is only supported for staged artifact build",
        )),
        Some("serialized_state") | None => {
            let evaluator_driver_state_b64u =
                get_required_string(args, "evaluatorDriverStateB64u")?;
            decode_state_blob(&evaluator_driver_state_b64u, "evaluatorDriverStateB64u")
        }
        Some(other) => Err(JsValue::from_str(&format!(
            "Invalid args: unsupported sessionSource {other}"
        ))),
    }
}

fn with_serialized_hss_client_session_handle<T>(
    driver_state: ClientDriverState,
    f: impl FnOnce([u8; 32], &SharedRuntime, &ClientSession) -> Result<T, JsValue>,
) -> Result<(T, String), JsValue> {
    let context_binding = driver_state.evaluator_session.context_binding;
    let (runtime, evaluator_session) = driver_state
        .materialize()
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let out = f(context_binding, &runtime, &evaluator_session)?;
    let handle = insert_hss_client_session_handle(driver_state, Some((runtime, evaluator_session)));
    Ok((out, handle))
}

fn with_serialized_hss_client_session<T>(
    driver_state: ClientDriverState,
    f: impl FnOnce([u8; 32], &SharedRuntime, &ClientSession) -> Result<T, JsValue>,
) -> Result<T, JsValue> {
    let context_binding = driver_state.evaluator_session.context_binding;
    let (runtime, evaluator_session) = driver_state
        .materialize()
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    f(context_binding, &runtime, &evaluator_session)
}

fn with_materialized_hss_client_session_timed<T>(
    source: HssClientSessionSource,
    f: impl FnOnce([u8; 32], &SharedRuntime, &ClientSession) -> Result<T, JsValue>,
) -> Result<(T, f64), JsValue> {
    match source {
        HssClientSessionSource::SerializedState(driver_state) => {
            let context_binding = driver_state.evaluator_session.context_binding;
            let materialize_started_at = Date::now();
            let (runtime, evaluator_session) = driver_state
                .materialize()
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            let materialize_ms = elapsed_ms(materialize_started_at);
            f(context_binding, &runtime, &evaluator_session).map(|out| (out, materialize_ms))
        }
        HssClientSessionSource::WorkerHandle(handle) => {
            HSS_CLIENT_SESSION_HANDLES.with(|store_cell| {
                let mut store = store_cell.borrow_mut();
                prune_expired_hss_client_session_handles(&mut store, Date::now());
                let entry = store.entries.get_mut(&handle).ok_or_else(|| {
                    JsValue::from_str("Invalid args: unknown workerSessionHandle")
                })?;
                let materialize_started_at = Date::now();
                if entry.materialized.is_none() {
                    entry.materialized = Some(
                        entry
                            .driver_state
                            .materialize()
                            .map_err(|e| JsValue::from_str(&e.to_string()))?,
                    );
                }
                let materialize_ms = elapsed_ms(materialize_started_at);
                let (runtime, evaluator_session) =
                    entry.materialized.as_ref().ok_or_else(|| {
                        JsValue::from_str("Invalid args: workerSessionHandle is not materialized")
                    })?;
                f(entry.context_binding, runtime, evaluator_session)
                    .map(|out| (out, materialize_ms))
            })
        }
    }
}

#[wasm_bindgen]
pub fn threshold_ed25519_hss_prepare_session(args: JsValue) -> Result<JsValue, JsValue> {
    let context = canonical_context_from_js(&args)?;
    let evaluator_driver_state = prepare_prime_order_succinct_hss_client(&context)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let context_binding = evaluator_driver_state.evaluator_session.context_binding;
    let evaluator_driver_state_b64u = encode_state_blob(&evaluator_driver_state, "evaluator state")
        .map_err(|e| JsValue::from_str(&e))?;

    let out = object();
    set_string(
        &out,
        "applicationBindingDigestB64u",
        &base64_url_encode(&context.application_binding_digest),
    )?;
    set_u16_vec(&out, "participantIds", &context.participant_ids)?;
    set_string(
        &out,
        "contextBindingB64u",
        &base64_url_encode(&context_binding),
    )?;
    set_string(
        &out,
        "evaluatorDriverStateB64u",
        &evaluator_driver_state_b64u,
    )?;
    Ok(out.into())
}

#[wasm_bindgen]
pub fn threshold_ed25519_hss_derive_client_output_mask(args: JsValue) -> Result<JsValue, JsValue> {
    let client_recoverable_secret = decode_fixed_32(
        &get_required_string(&args, "clientRecoverableSecretB64u")?,
        "clientRecoverableSecretB64u",
    )?;
    let context = ClientOutputMaskContext {
        canonical_context: canonical_context_from_js(&args)?,
        context_binding: decode_fixed_32(
            &get_required_string(&args, "contextBindingB64u")?,
            "contextBindingB64u",
        )?,
        operation: get_required_string(&args, "operation")?
            .parse::<ClientOutputMaskOperation>()
            .map_err(|e| JsValue::from_str(&e.to_string()))?,
        server_key_id: get_required_string(&args, "relayerKeyId")?,
    };
    let client_output_mask = derive_client_output_mask(client_recoverable_secret, &context)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let out = object();
    set_string(
        &out,
        "clientOutputMaskB64u",
        &base64_url_encode(&client_output_mask),
    )?;
    Ok(out.into())
}

#[wasm_bindgen]
pub fn threshold_ed25519_hss_prepare_client_request(args: JsValue) -> Result<JsValue, JsValue> {
    let evaluator_state = serialized_hss_client_driver_state_from_js(&args)?;
    let client_ot_offer_message_b64u = get_required_string(&args, "clientOtOfferMessageB64u")?;
    let y_client_b64u = get_required_string(&args, "yClientB64u")?;
    let tau_client_b64u = get_required_string(&args, "tauClientB64u")?;

    let offer_message =
        decode_wire_message(&client_ot_offer_message_b64u, "clientOtOfferMessageB64u")?;
    let y_client = decode_fixed_32(&y_client_b64u, "yClientB64u")?;
    let tau_client = decode_fixed_32(&tau_client_b64u, "tauClientB64u")?;
    let ((client_request_message, evaluator_ot_state), worker_session_handle) =
        with_serialized_hss_client_session_handle(
            evaluator_state,
            |_context_binding, _runtime, evaluator_session| {
                evaluator_session
                    .prepare_client_ot_request_from_offer_message(
                        &offer_message,
                        y_client,
                        tau_client,
                    )
                    .map_err(|e| JsValue::from_str(&e.to_string()))
            },
        )?;

    let out = object();
    set_string(
        &out,
        "clientRequestMessageB64u",
        &encode_wire_message(&client_request_message),
    )?;
    set_string(
        &out,
        "evaluatorOtStateB64u",
        &encode_state_blob(&evaluator_ot_state, "evaluator OT state")
            .map_err(|e| JsValue::from_str(&e))?,
    )?;
    set_string(&out, "workerSessionHandle", &worker_session_handle)?;
    Ok(out.into())
}

#[wasm_bindgen]
pub fn threshold_ed25519_hss_prepare_add_stage_request_message(
    args: JsValue,
) -> Result<JsValue, JsValue> {
    let client_request_message_b64u = get_required_string(&args, "clientRequestMessageB64u")?;
    let evaluator_ot_state_b64u = get_required_string(&args, "evaluatorOtStateB64u")?;
    let server_input_delivery_b64u = get_required_string(&args, "serverInputDeliveryB64u")?;

    let decode_evaluator_ot_state_started_at = Date::now();
    let evaluator_ot_state: ClientOtState =
        decode_state_blob(&evaluator_ot_state_b64u, "evaluatorOtStateB64u")?;
    let decode_evaluator_ot_state_ms = elapsed_ms(decode_evaluator_ot_state_started_at);

    let decode_server_input_delivery_started_at = Date::now();
    let server_input_delivery: RoleSeparatedServerInputDeliveryPacket =
        decode_state_blob(&server_input_delivery_b64u, "serverInputDeliveryB64u")?;
    let decode_server_input_delivery_ms = elapsed_ms(decode_server_input_delivery_started_at);

    let decode_client_request_message_started_at = Date::now();
    let client_request_message =
        decode_wire_message(&client_request_message_b64u, "clientRequestMessageB64u")?;
    let decode_client_request_message_ms = elapsed_ms(decode_client_request_message_started_at);

    let decode_evaluator_driver_state_started_at = Date::now();
    let session_source = hss_client_session_source_from_js(&args)?;
    let decode_evaluator_driver_state_ms = elapsed_ms(decode_evaluator_driver_state_started_at);

    let (
        (context_binding, add_stage_request_message, prepare_add_stage_request_ms),
        materialize_session_ms,
    ) = with_materialized_hss_client_session_timed(
        session_source,
        |context_binding, _runtime, evaluator_session| {
            let prepare_add_stage_request_started_at = Date::now();
            let add_stage_request_message = evaluator_session
                .prepare_add_stage_request_message_from_role_separated_delivery(
                    &client_request_message,
                    &evaluator_ot_state,
                    &server_input_delivery,
                )
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            Ok((
                context_binding,
                add_stage_request_message,
                elapsed_ms(prepare_add_stage_request_started_at),
            ))
        },
    )?;

    let encode_add_stage_request_started_at = Date::now();
    let add_stage_request_message_b64u = encode_wire_message(&add_stage_request_message);
    let encode_add_stage_request_ms = elapsed_ms(encode_add_stage_request_started_at);

    let timings = object();
    set_f64(
        &timings,
        "decodeEvaluatorDriverStateMs",
        decode_evaluator_driver_state_ms,
    )?;
    set_f64(
        &timings,
        "decodeEvaluatorOtStateMs",
        decode_evaluator_ot_state_ms,
    )?;
    set_f64(
        &timings,
        "decodeServerInputDeliveryMs",
        decode_server_input_delivery_ms,
    )?;
    set_f64(
        &timings,
        "decodeClientRequestMessageMs",
        decode_client_request_message_ms,
    )?;
    set_f64(&timings, "materializeSessionMs", materialize_session_ms)?;
    set_f64(
        &timings,
        "prepareAddStageRequestMs",
        prepare_add_stage_request_ms,
    )?;
    set_f64(
        &timings,
        "encodeAddStageRequestMs",
        encode_add_stage_request_ms,
    )?;

    let out = object();
    set_string(
        &out,
        "contextBindingB64u",
        &base64_url_encode(&context_binding),
    )?;
    set_string(
        &out,
        "addStageRequestMessageB64u",
        &add_stage_request_message_b64u,
    )?;
    Reflect::set(&out, &JsValue::from_str("timings"), &timings)
        .map_err(|_| JsValue::from_str("Failed to serialize field timings"))?;
    Ok(out.into())
}

#[wasm_bindgen]
pub fn threshold_ed25519_hss_build_client_owned_staged_evaluator_artifact(
    args: JsValue,
) -> Result<JsValue, JsValue> {
    let client_request_message_b64u = get_required_string(&args, "clientRequestMessageB64u")?;
    let evaluator_ot_state_b64u = get_required_string(&args, "evaluatorOtStateB64u")?;
    let server_input_delivery_b64u = get_required_string(&args, "serverInputDeliveryB64u")?;
    let decode_client_output_mask_started_at = Date::now();
    let client_output_mask = decode_fixed_32(
        &get_required_string(&args, "clientOutputMaskB64u")?,
        "clientOutputMaskB64u",
    )?;
    let decode_client_output_mask_ms = elapsed_ms(decode_client_output_mask_started_at);

    let decode_evaluator_ot_state_started_at = Date::now();
    let evaluator_ot_state: ClientOtState =
        decode_state_blob(&evaluator_ot_state_b64u, "evaluatorOtStateB64u")?;
    let decode_evaluator_ot_state_ms = elapsed_ms(decode_evaluator_ot_state_started_at);

    let decode_server_input_delivery_started_at = Date::now();
    let server_input_delivery: RoleSeparatedServerInputDeliveryPacket =
        decode_state_blob(&server_input_delivery_b64u, "serverInputDeliveryB64u")?;
    let decode_server_input_delivery_ms = elapsed_ms(decode_server_input_delivery_started_at);

    let decode_client_request_message_started_at = Date::now();
    let client_request_message =
        decode_wire_message(&client_request_message_b64u, "clientRequestMessageB64u")?;
    let decode_client_request_message_ms = elapsed_ms(decode_client_request_message_started_at);
    let expected_add_stage_request_message =
        match get_optional_string(&args, "expectedAddStageRequestMessageB64u")? {
            Some(value) => Some(decode_wire_message(
                &value,
                "expectedAddStageRequestMessageB64u",
            )?),
            None => None,
        };

    let decode_evaluator_driver_state_started_at = Date::now();
    let session_source = hss_client_session_source_from_js(&args)?;
    let release_handle = match &session_source {
        HssClientSessionSource::WorkerHandle(handle) => Some(handle.clone()),
        HssClientSessionSource::SerializedState(_) => None,
    };
    let decode_evaluator_driver_state_ms = elapsed_ms(decode_evaluator_driver_state_started_at);

    let built = with_materialized_hss_client_session_timed(
        session_source,
        |context_binding, runtime, evaluator_session| {
            let build_artifact_started_at = Date::now();
            let add_stage_request_message =
                if let Some(expected) = expected_add_stage_request_message.as_ref() {
                    expected.clone()
                } else {
                    evaluator_session
                        .prepare_add_stage_request_message_from_role_separated_delivery(
                            &client_request_message,
                            &evaluator_ot_state,
                            &server_input_delivery,
                        )
                        .map_err(|e| JsValue::from_str(&e.to_string()))?
                };
            let (artifact, _server_output, stage_profile) = evaluator_session
                .build_client_owned_staged_evaluator_artifact_and_server_finalize_output_from_role_separated_delivery_message_profiled(
                    runtime,
                    &client_request_message,
                    &evaluator_ot_state,
                    &server_input_delivery,
                    client_output_mask,
                )
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            if let Some(expected) = expected_add_stage_request_message.as_ref() {
                evaluator_session
                    .validate_add_stage_request_message_from_role_separated_delivery_for_commitment(
                        &client_request_message,
                        &evaluator_ot_state,
                        &server_input_delivery,
                        expected,
                        artifact.bindings.client_input_commitment,
                    )
                    .map_err(|e| JsValue::from_str(&e.to_string()))?;
            }
            Ok((
                context_binding,
                artifact,
                add_stage_request_message,
                stage_profile,
                elapsed_ms(build_artifact_started_at),
            ))
        },
    );
    if let Some(handle) = release_handle.as_deref() {
        remove_hss_client_session_handle(handle);
    }
    let (
        (context_binding, artifact, add_stage_request_message, stage_profile, build_artifact_ms),
        materialize_session_ms,
    ) = built?;

    let encode_artifact_started_at = Date::now();
    let staged_evaluator_artifact_b64u = encode_state_blob(&artifact, "staged evaluator artifact")
        .map_err(|e| JsValue::from_str(&e))?;
    let add_stage_request_message_b64u = encode_wire_message(&add_stage_request_message);
    let encode_artifact_ms = elapsed_ms(encode_artifact_started_at);

    let timings = object();
    set_f64(
        &timings,
        "decodeClientOutputMaskMs",
        decode_client_output_mask_ms,
    )?;
    set_f64(
        &timings,
        "decodeEvaluatorDriverStateMs",
        decode_evaluator_driver_state_ms,
    )?;
    set_f64(
        &timings,
        "decodeEvaluatorOtStateMs",
        decode_evaluator_ot_state_ms,
    )?;
    set_f64(
        &timings,
        "decodeServerInputDeliveryMs",
        decode_server_input_delivery_ms,
    )?;
    set_f64(
        &timings,
        "decodeClientRequestMessageMs",
        decode_client_request_message_ms,
    )?;
    set_f64(&timings, "materializeSessionMs", materialize_session_ms)?;
    set_f64(&timings, "buildArtifactMs", build_artifact_ms)?;
    set_f64(&timings, "encodeArtifactMs", encode_artifact_ms)?;
    set_f64(
        &timings,
        "hiddenEvalInputSharingMs",
        ns_to_ms(stage_profile.input_sharing_duration_ns),
    )?;
    set_f64(
        &timings,
        "hiddenEvalAddStageMs",
        ns_to_ms(stage_profile.add_stage_duration_ns),
    )?;
    set_f64(
        &timings,
        "hiddenEvalMessageScheduleMs",
        ns_to_ms(stage_profile.message_schedule_duration_ns),
    )?;
    set_f64(
        &timings,
        "hiddenEvalMessageScheduleAccumulationMs",
        ns_to_ms(stage_profile.message_schedule_accumulation_duration_ns),
    )?;
    set_f64(
        &timings,
        "hiddenEvalMessageScheduleAccumulationXorAbMs",
        ns_to_ms(stage_profile.message_schedule_accumulation_xor_ab_duration_ns),
    )?;
    set_f64(
        &timings,
        "hiddenEvalMessageScheduleAccumulationSumMs",
        ns_to_ms(stage_profile.message_schedule_accumulation_sum_duration_ns),
    )?;
    set_f64(
        &timings,
        "hiddenEvalMessageScheduleAccumulationAXorCarryMs",
        ns_to_ms(stage_profile.message_schedule_accumulation_a_xor_carry_duration_ns),
    )?;
    set_f64(
        &timings,
        "hiddenEvalMessageScheduleAccumulationCarryGateMs",
        ns_to_ms(stage_profile.message_schedule_accumulation_carry_gate_duration_ns),
    )?;
    set_f64(
        &timings,
        "hiddenEvalMessageScheduleAccumulationNextCarryMs",
        ns_to_ms(stage_profile.message_schedule_accumulation_next_carry_duration_ns),
    )?;
    set_f64(
        &timings,
        "hiddenEvalRoundCoreMs",
        ns_to_ms(stage_profile.round_core_duration_ns),
    )?;
    set_f64(
        &timings,
        "hiddenEvalRoundSigma0Ms",
        ns_to_ms(stage_profile.round_sigma0_duration_ns),
    )?;
    set_f64(
        &timings,
        "hiddenEvalRoundSigma1Ms",
        ns_to_ms(stage_profile.round_sigma1_duration_ns),
    )?;
    set_f64(
        &timings,
        "hiddenEvalRoundChMs",
        ns_to_ms(stage_profile.round_ch_duration_ns),
    )?;
    set_f64(
        &timings,
        "hiddenEvalRoundMajMs",
        ns_to_ms(stage_profile.round_maj_duration_ns),
    )?;
    set_f64(
        &timings,
        "hiddenEvalRoundState3Ms",
        ns_to_ms(stage_profile.round_state3_duration_ns),
    )?;
    set_f64(
        &timings,
        "hiddenEvalRoundTemp1Ms",
        ns_to_ms(stage_profile.round_temp1_duration_ns),
    )?;
    set_f64(
        &timings,
        "hiddenEvalRoundTemp1XorAbMs",
        ns_to_ms(stage_profile.round_temp1_xor_ab_duration_ns),
    )?;
    set_f64(
        &timings,
        "hiddenEvalRoundTemp1SumMs",
        ns_to_ms(stage_profile.round_temp1_sum_duration_ns),
    )?;
    set_f64(
        &timings,
        "hiddenEvalRoundTemp1AXorCarryMs",
        ns_to_ms(stage_profile.round_temp1_a_xor_carry_duration_ns),
    )?;
    set_f64(
        &timings,
        "hiddenEvalRoundTemp1CarryGateMs",
        ns_to_ms(stage_profile.round_temp1_carry_gate_duration_ns),
    )?;
    set_f64(
        &timings,
        "hiddenEvalRoundTemp1NextCarryMs",
        ns_to_ms(stage_profile.round_temp1_next_carry_duration_ns),
    )?;
    set_f64(
        &timings,
        "hiddenEvalRoundTemp2Ms",
        ns_to_ms(stage_profile.round_temp2_duration_ns),
    )?;
    set_f64(
        &timings,
        "hiddenEvalRoundNewABitsMs",
        ns_to_ms(stage_profile.round_new_a_bits_duration_ns),
    )?;
    set_f64(
        &timings,
        "hiddenEvalRoundNewEBitsMs",
        ns_to_ms(stage_profile.round_new_e_bits_duration_ns),
    )?;
    set_f64(
        &timings,
        "hiddenEvalOutputProjectorMs",
        ns_to_ms(stage_profile.output_projector_duration_ns),
    )?;
    set_f64(
        &timings,
        "hiddenEvalOutputProjectorCoreMs",
        ns_to_ms(stage_profile.output_projector_core_duration_ns),
    )?;
    set_f64(
        &timings,
        "hiddenEvalOutputProjectorClampAMs",
        ns_to_ms(stage_profile.output_projector_clamp_a_duration_ns),
    )?;
    set_f64(
        &timings,
        "hiddenEvalOutputProjectorReduceAMs",
        ns_to_ms(stage_profile.output_projector_reduce_a_duration_ns),
    )?;
    set_f64(
        &timings,
        "hiddenEvalOutputProjectorTauMs",
        ns_to_ms(stage_profile.output_projector_tau_duration_ns),
    )?;
    set_f64(
        &timings,
        "hiddenEvalOutputProjectorMaskShareMs",
        ns_to_ms(stage_profile.output_projector_mask_share_duration_ns),
    )?;
    set_f64(
        &timings,
        "hiddenEvalOutputProjectorMaskAddMs",
        ns_to_ms(stage_profile.output_projector_mask_add_duration_ns),
    )?;
    set_f64(
        &timings,
        "hiddenEvalOutputProjectorClientBaseMs",
        ns_to_ms(stage_profile.output_projector_client_base_duration_ns),
    )?;
    set_f64(
        &timings,
        "hiddenEvalOutputProjectorClientOutputMs",
        ns_to_ms(stage_profile.output_projector_client_output_duration_ns),
    )?;
    set_f64(
        &timings,
        "hiddenEvalOutputProjectorTauDoubleMs",
        ns_to_ms(stage_profile.output_projector_tau_double_duration_ns),
    )?;
    set_f64(
        &timings,
        "hiddenEvalOutputProjectorServerOutputMs",
        ns_to_ms(stage_profile.output_projector_server_output_duration_ns),
    )?;
    set_f64(
        &timings,
        "hiddenEvalOutputProjectorBundleBuildMs",
        ns_to_ms(stage_profile.output_projector_bundle_build_duration_ns),
    )?;
    set_f64(
        &timings,
        "hiddenEvalOutputProjectorLocalWordMaterializations",
        stage_profile.output_projector_local_word_materializations as f64,
    )?;
    set_f64(
        &timings,
        "hiddenEvalTotalMs",
        ns_to_ms(stage_profile.total_duration_ns),
    )?;
    let operation_counts = stage_profile.operation_counts;
    set_f64(
        &timings,
        "hiddenEvalLogicalLocalWordMaterializations",
        operation_counts.logical_local_word_materializations as f64,
    )?;
    set_f64(
        &timings,
        "hiddenEvalLogicalSharedWordMaterializations",
        operation_counts.logical_shared_word_materializations as f64,
    )?;
    set_f64(
        &timings,
        "hiddenEvalLogicalTransportWordMaterializations",
        operation_counts.logical_transport_word_materializations as f64,
    )?;
    set_f64(
        &timings,
        "hiddenEvalLogicalCommitmentMaterializations",
        operation_counts.logical_commitment_materializations as f64,
    )?;
    set_f64(
        &timings,
        "hiddenEvalLogicalProvenanceDigestMaterializations",
        operation_counts.logical_provenance_digest_materializations as f64,
    )?;
    set_f64(
        &timings,
        "hiddenEvalLogicalCommitmentDerivations",
        operation_counts.logical_commitment_derivations as f64,
    )?;
    set_f64(
        &timings,
        "hiddenEvalLogicalProvenanceDigestDerivations",
        operation_counts.logical_provenance_digest_derivations as f64,
    )?;
    set_f64(
        &timings,
        "hiddenEvalLogicalLabelWrites",
        operation_counts.logical_label_writes as f64,
    )?;
    set_f64(
        &timings,
        "hiddenEvalLogicalLabelFormatAllocations",
        operation_counts.logical_label_format_allocations as f64,
    )?;
    if operation_counts.physical_keyed_digest_derivations > 0 {
        set_f64(
            &timings,
            "hiddenEvalPhysicalKeyedDigestDerivations",
            operation_counts.physical_keyed_digest_derivations as f64,
        )?;
    }
    if operation_counts.physical_keyed_digest_eval_xor_local_word > 0 {
        set_f64(
            &timings,
            "hiddenEvalPhysicalKeyedDigestEvalXorLocalWord",
            operation_counts.physical_keyed_digest_eval_xor_local_word as f64,
        )?;
    }
    if operation_counts.physical_keyed_digest_eval_add_local > 0 {
        set_f64(
            &timings,
            "hiddenEvalPhysicalKeyedDigestEvalAddLocal",
            operation_counts.physical_keyed_digest_eval_add_local as f64,
        )?;
    }
    if operation_counts.physical_keyed_digest_eval_mul_local_material > 0 {
        set_f64(
            &timings,
            "hiddenEvalPhysicalKeyedDigestEvalMulLocalMaterial",
            operation_counts.physical_keyed_digest_eval_mul_local_material as f64,
        )?;
    }
    if operation_counts.physical_keyed_digest_eval_mul_local > 0 {
        set_f64(
            &timings,
            "hiddenEvalPhysicalKeyedDigestEvalMulLocal",
            operation_counts.physical_keyed_digest_eval_mul_local as f64,
        )?;
    }
    if operation_counts.physical_keyed_digest_phase_a_arith_share_to_bool > 0 {
        set_f64(
            &timings,
            "hiddenEvalPhysicalKeyedDigestPhaseAArithShareToBool",
            operation_counts.physical_keyed_digest_phase_a_arith_share_to_bool as f64,
        )?;
    }
    if operation_counts.physical_keyed_digest_phase_a_bool_to_arith_base > 0 {
        set_f64(
            &timings,
            "hiddenEvalPhysicalKeyedDigestPhaseABoolToArithBase",
            operation_counts.physical_keyed_digest_phase_a_bool_to_arith_base as f64,
        )?;
    }
    if operation_counts.physical_keyed_digest_phase_a_arith_to_bool_zero > 0 {
        set_f64(
            &timings,
            "hiddenEvalPhysicalKeyedDigestPhaseAArithToBoolZero",
            operation_counts.physical_keyed_digest_phase_a_arith_to_bool_zero as f64,
        )?;
    }
    if operation_counts.physical_keyed_digest_compose_word_from_share_bits > 0 {
        set_f64(
            &timings,
            "hiddenEvalPhysicalKeyedDigestComposeWordFromShareBits",
            operation_counts.physical_keyed_digest_compose_word_from_share_bits as f64,
        )?;
    }
    if operation_counts.physical_keyed_digest_share_word > 0 {
        set_f64(
            &timings,
            "hiddenEvalPhysicalKeyedDigestShareWord",
            operation_counts.physical_keyed_digest_share_word as f64,
        )?;
    }
    if operation_counts.physical_keyed_digest_other > 0 {
        set_f64(
            &timings,
            "hiddenEvalPhysicalKeyedDigestOther",
            operation_counts.physical_keyed_digest_other as f64,
        )?;
    }
    if operation_counts.physical_derived_commitment_hashes > 0 {
        set_f64(
            &timings,
            "hiddenEvalPhysicalDerivedCommitmentHashes",
            operation_counts.physical_derived_commitment_hashes as f64,
        )?;
    }
    if operation_counts.physical_derived_commitment_eval_xor_local_word > 0 {
        set_f64(
            &timings,
            "hiddenEvalPhysicalDerivedCommitmentEvalXorLocalWord",
            operation_counts.physical_derived_commitment_eval_xor_local_word as f64,
        )?;
    }
    if operation_counts.physical_derived_commitment_eval_add_local > 0 {
        set_f64(
            &timings,
            "hiddenEvalPhysicalDerivedCommitmentEvalAddLocal",
            operation_counts.physical_derived_commitment_eval_add_local as f64,
        )?;
    }
    if operation_counts.physical_derived_commitment_eval_mul_local_material > 0 {
        set_f64(
            &timings,
            "hiddenEvalPhysicalDerivedCommitmentEvalMulLocalMaterial",
            operation_counts.physical_derived_commitment_eval_mul_local_material as f64,
        )?;
    }
    if operation_counts.physical_derived_commitment_eval_mul_local > 0 {
        set_f64(
            &timings,
            "hiddenEvalPhysicalDerivedCommitmentEvalMulLocal",
            operation_counts.physical_derived_commitment_eval_mul_local as f64,
        )?;
    }
    if operation_counts.physical_derived_commitment_phase_a_arith_share_to_bool > 0 {
        set_f64(
            &timings,
            "hiddenEvalPhysicalDerivedCommitmentPhaseAArithShareToBool",
            operation_counts.physical_derived_commitment_phase_a_arith_share_to_bool as f64,
        )?;
    }
    if operation_counts.physical_derived_commitment_phase_a_bool_to_arith_base > 0 {
        set_f64(
            &timings,
            "hiddenEvalPhysicalDerivedCommitmentPhaseABoolToArithBase",
            operation_counts.physical_derived_commitment_phase_a_bool_to_arith_base as f64,
        )?;
    }
    if operation_counts.physical_derived_commitment_phase_a_arith_to_bool_zero > 0 {
        set_f64(
            &timings,
            "hiddenEvalPhysicalDerivedCommitmentPhaseAArithToBoolZero",
            operation_counts.physical_derived_commitment_phase_a_arith_to_bool_zero as f64,
        )?;
    }
    if operation_counts.physical_derived_commitment_compose_word_from_share_bits > 0 {
        set_f64(
            &timings,
            "hiddenEvalPhysicalDerivedCommitmentComposeWordFromShareBits",
            operation_counts.physical_derived_commitment_compose_word_from_share_bits as f64,
        )?;
    }
    if operation_counts.physical_derived_commitment_share_word > 0 {
        set_f64(
            &timings,
            "hiddenEvalPhysicalDerivedCommitmentShareWord",
            operation_counts.physical_derived_commitment_share_word as f64,
        )?;
    }
    if operation_counts.physical_derived_commitment_other > 0 {
        set_f64(
            &timings,
            "hiddenEvalPhysicalDerivedCommitmentOther",
            operation_counts.physical_derived_commitment_other as f64,
        )?;
    }
    if operation_counts.physical_add_bit_hashes > 0 {
        set_f64(
            &timings,
            "hiddenEvalPhysicalAddBitHashes",
            operation_counts.physical_add_bit_hashes as f64,
        )?;
    }
    if operation_counts.physical_mul_material_hashes > 0 {
        set_f64(
            &timings,
            "hiddenEvalPhysicalMulMaterialHashes",
            operation_counts.physical_mul_material_hashes as f64,
        )?;
    }
    if operation_counts.physical_mul_output_seed_hashes > 0 {
        set_f64(
            &timings,
            "hiddenEvalPhysicalMulOutputSeedHashes",
            operation_counts.physical_mul_output_seed_hashes as f64,
        )?;
    }

    let out = object();
    set_string(
        &out,
        "contextBindingB64u",
        &base64_url_encode(&context_binding),
    )?;
    set_string(
        &out,
        "stagedEvaluatorArtifactB64u",
        &staged_evaluator_artifact_b64u,
    )?;
    set_string(
        &out,
        "addStageRequestMessageB64u",
        &add_stage_request_message_b64u,
    )?;
    Reflect::set(&out, &JsValue::from_str("timings"), &timings)
        .map_err(|_| JsValue::from_str("Failed to serialize field timings"))?;
    Ok(out.into())
}

#[wasm_bindgen]
pub fn threshold_ed25519_hss_open_client_output(args: JsValue) -> Result<JsValue, JsValue> {
    let evaluator_state = serialized_hss_client_driver_state_from_js(&args)?;
    let client_output_message_b64u = get_required_string(&args, "clientOutputMessageB64u")?;
    let client_output_mask = decode_fixed_32(
        &get_required_string(&args, "clientOutputMaskB64u")?,
        "clientOutputMaskB64u",
    )?;
    let client_output_message =
        decode_wire_message(&client_output_message_b64u, "clientOutputMessageB64u")?;
    let (context_binding, x_client_base) = with_serialized_hss_client_session(
        evaluator_state,
        |context_binding, _runtime, evaluator_session| {
            let opener = evaluator_session.client_output_opener();
            let x_client_base = opener
                .open_masked(&client_output_message, client_output_mask)
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            Ok((context_binding, x_client_base))
        },
    )?;

    let out = object();
    set_string(
        &out,
        "contextBindingB64u",
        &base64_url_encode(&context_binding),
    )?;
    set_string(&out, "xClientBaseB64u", &base64_url_encode(&x_client_base))?;
    Ok(out.into())
}

#[wasm_bindgen]
pub fn threshold_ed25519_hss_open_seed_output(args: JsValue) -> Result<JsValue, JsValue> {
    let evaluator_state = serialized_hss_client_driver_state_from_js(&args)?;
    let seed_output_message_b64u = get_required_string(&args, "seedOutputMessageB64u")?;
    let seed_output_message =
        decode_wire_message(&seed_output_message_b64u, "seedOutputMessageB64u")?;
    let (context_binding, canonical_seed) = with_serialized_hss_client_session(
        evaluator_state,
        |context_binding, _runtime, evaluator_session| {
            let canonical_seed = evaluator_session
                .seed_output_opener()
                .open(&seed_output_message)
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            Ok((context_binding, canonical_seed))
        },
    )?;

    let out = object();
    set_string(
        &out,
        "contextBindingB64u",
        &base64_url_encode(&context_binding),
    )?;
    set_string(
        &out,
        "canonicalSeedB64u",
        &base64_url_encode(&canonical_seed),
    )?;
    Ok(out.into())
}

#[wasm_bindgen]
pub fn threshold_ed25519_role_separated_client_verifying_share_from_base_share(
    args: JsValue,
) -> Result<JsValue, JsValue> {
    let x_client_base = decode_fixed_32(
        &get_required_string(&args, "xClientBaseB64u")?,
        "xClientBaseB64u",
    )?;
    let client_verifying_share = role_separated_ed25519_client_verifying_share_v1(x_client_base)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let out = object();
    set_string(
        &out,
        "clientVerifyingShareB64u",
        &base64_url_encode(&client_verifying_share),
    )?;
    Ok(out.into())
}

#[wasm_bindgen]
pub fn threshold_ed25519_role_separated_normal_signing_create_client_share(
    args: JsValue,
) -> Result<JsValue, JsValue> {
    let x_client_base = decode_fixed_32(
        &get_required_string(&args, "xClientBaseB64u")?,
        "xClientBaseB64u",
    )?;
    let group_public_key = decode_fixed_32(
        &get_required_string(&args, "groupPublicKeyB64u")?,
        "groupPublicKeyB64u",
    )?;
    let server_verifying_share = decode_fixed_32(
        &get_required_string(&args, "serverVerifyingShareB64u")?,
        "serverVerifyingShareB64u",
    )?;
    let server_commitments = decode_role_separated_commitments_from_js(&args, "serverCommitments")?;
    let signing_payload = decode_non_empty_bytes(
        &get_required_string(&args, "signingPayloadB64u")?,
        "signingPayloadB64u",
    )?;

    let mut rng = OsRng;
    let client_round1 = prepare_role_separated_ed25519_round1_v1(&mut rng)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let client_verifying_share = role_separated_ed25519_client_verifying_share_v1(x_client_base)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let client_signature_share = create_role_separated_ed25519_client_signature_share_v1(
        RoleSeparatedEd25519ClientShareRequestV1 {
            x_client_base,
            client_round1: &client_round1,
            group_public_key,
            client_verifying_share,
            server_verifying_share,
            server_commitments,
            signing_payload: &signing_payload,
        },
    )
    .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let out = object();
    set_role_separated_commitments(&out, "clientCommitments", client_round1.commitments)?;
    set_string(
        &out,
        "clientVerifyingShareB64u",
        &base64_url_encode(&client_verifying_share),
    )?;
    set_string(
        &out,
        "clientSignatureShareB64u",
        &base64_url_encode(&client_signature_share),
    )?;
    Ok(out.into())
}

#[wasm_bindgen]
pub fn prepare_ecdsa_client_bootstrap_v1(input_json: &str) -> Result<String, JsValue> {
    let command: signer_core::commands::PrepareEcdsaClientBootstrapCommandV1 =
        serde_json::from_str(input_json).map_err(js_command_invalid_input_err)?;
    let output = signer_core::commands::prepare_ecdsa_client_bootstrap_command_v1(command)
        .map_err(js_signer_core_err)?;
    serde_json::to_string(&output).map_err(js_command_invalid_input_err)
}

#[wasm_bindgen]
pub fn prepare_ecdsa_client_bootstrap_from_resolved_email_otp_root_v1(
    input_json: &str,
) -> Result<String, JsValue> {
    let command: PrepareResolvedEmailOtpRootCommandV1 =
        serde_json::from_str(input_json).map_err(js_command_invalid_input_err)?;
    let output = prepare_resolved_email_otp_root_command_v1(command).map_err(js_signer_core_err)?;
    serde_json::to_string(&output).map_err(js_command_invalid_input_err)
}

#[wasm_bindgen]
pub fn finalize_ecdsa_client_bootstrap_v1(input_json: &str) -> Result<String, JsValue> {
    let command: signer_core::commands::FinalizeEcdsaClientBootstrapCommandV1 =
        serde_json::from_str(input_json).map_err(js_command_invalid_input_err)?;
    let output = signer_core::commands::finalize_ecdsa_client_bootstrap_command_v1(command)
        .map_err(js_signer_core_err)?;
    serde_json::to_string(&output).map_err(js_command_invalid_input_err)
}

#[wasm_bindgen]
pub fn build_ecdsa_role_local_export_artifact_v1(input_json: &str) -> Result<String, JsValue> {
    let command: signer_core::commands::BuildEcdsaRoleLocalExportArtifactCommandV1 =
        serde_json::from_str(input_json).map_err(js_command_invalid_input_err)?;
    let output = signer_core::commands::build_ecdsa_role_local_export_artifact_command_v1(command)
        .map_err(js_signer_core_err)?;
    serde_json::to_string(&output).map_err(js_command_invalid_input_err)
}

#[wasm_bindgen]
pub fn threshold_ecdsa_hss_role_local_finalize_client_bootstrap(
    args: JsValue,
) -> Result<JsValue, JsValue> {
    let pending_state_blob = signer_core::threshold_ecdsa_hss::EcdsaRoleLocalPendingStateBlob {
        state_blob: base64_url_decode(&get_required_string(&args, "pendingStateBlobB64u")?)
            .map_err(|e| JsValue::from_str(&format!("Invalid pendingStateBlobB64u: {e}")))?,
    };
    let finalized = finalize_ecdsa_client_bootstrap(FinalizeEcdsaClientBootstrapCommand {
        pending_state_blob,
        relayer_public_identity: RelayerPublicIdentityInput {
            relayer_key_id: get_required_string(&args, "relayerKeyId")?,
            relayer_public_key33: decode_fixed_33(
                &get_required_string(&args, "relayerPublicKey33B64u")?,
                "relayerPublicKey33B64u",
            )?,
            group_public_key33: decode_fixed_33(
                &get_required_string(&args, "groupPublicKey33B64u")?,
                "groupPublicKey33B64u",
            )?,
            ethereum_address20: decode_ethereum_address20(&get_required_string(
                &args,
                "ethereumAddress",
            )?)?,
            relayer_share_retry_counter: get_optional_u32(&args, "relayerShareRetryCounter")?
                .unwrap_or(0),
        },
    })
    .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let out = object();
    set_string(
        &out,
        "stateBlobB64u",
        &base64_url_encode(&finalized.ready_state_blob.state_blob),
    )?;
    set_string(
        &out,
        "contextBinding32B64u",
        &base64_url_encode(&finalized.public_facts.context_binding32),
    )?;
    set_string(
        &out,
        "hssClientSharePublicKey33B64u",
        &base64_url_encode(&finalized.public_facts.hss_client_share_public_key33),
    )?;
    set_string(
        &out,
        "clientVerifyingShareB64u",
        &base64_url_encode(&finalized.public_facts.client_verifying_share33),
    )?;
    set_string(
        &out,
        "relayerPublicKey33B64u",
        &base64_url_encode(&finalized.public_facts.relayer_public_key33),
    )?;
    set_string(
        &out,
        "groupPublicKey33B64u",
        &base64_url_encode(&finalized.public_facts.group_public_key33),
    )?;
    set_string(
        &out,
        "ethereumAddress",
        &hex_prefixed(&finalized.public_facts.ethereum_address20),
    )?;
    set_u32(
        &out,
        "clientShareRetryCounter",
        finalized.public_facts.client_share_retry_counter,
    )?;
    set_u32(
        &out,
        "relayerShareRetryCounter",
        finalized.public_facts.relayer_share_retry_counter,
    )?;
    Ok(out.into())
}

#[wasm_bindgen]
pub fn open_ecdsa_role_local_signing_share_v1(args: JsValue) -> Result<JsValue, JsValue> {
    let ready_state_blob = EcdsaRoleLocalReadyStateBlob {
        state_blob: base64_url_decode(&get_required_string(&args, "stateBlobB64u")?)
            .map_err(|e| JsValue::from_str(&format!("Invalid stateBlobB64u: {e}")))?,
    };
    let signing_share32 = extract_client_signing_share32_from_ready_state_blob(&ready_state_blob)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let out = object();
    set_string(
        &out,
        "signingShare32B64u",
        &base64_url_encode(&signing_share32),
    )?;
    Ok(out.into())
}

fn canonical_context_from_js(args: &JsValue) -> Result<CanonicalContext, JsValue> {
    Ok(CanonicalContext {
        application_binding_digest: decode_fixed_32(
            &get_required_string(args, "applicationBindingDigestB64u")?,
            "applicationBindingDigestB64u",
        )?,
        participant_ids: get_required_u16_vec(args, "participantIds")?,
    })
}

fn decode_state_blob<T: for<'de> Deserialize<'de>>(
    value: &str,
    field_name: &str,
) -> Result<T, JsValue> {
    let bytes = base64_url_decode(value)
        .map_err(|e| JsValue::from_str(&format!("Invalid {field_name}: {e}")))?;
    bincode::deserialize::<T>(&bytes)
        .map_err(|e| JsValue::from_str(&format!("Invalid {field_name}: {e}")))
}

fn encode_state_blob<T: Serialize>(value: &T, field_name: &str) -> Result<String, String> {
    let bytes =
        bincode::serialize(value).map_err(|e| format!("Failed to serialize {field_name}: {e}"))?;
    Ok(base64_url_encode(&bytes))
}

fn decode_fixed_32(value: &str, field_name: &str) -> Result<[u8; 32], JsValue> {
    let decoded = base64_url_decode(value)
        .map_err(|e| JsValue::from_str(&format!("Invalid {field_name}: {e}")))?;
    decoded
        .as_slice()
        .try_into()
        .map_err(|_| JsValue::from_str(&format!("{field_name} must decode to 32 bytes")))
}

fn decode_non_empty_bytes(value: &str, field_name: &str) -> Result<Vec<u8>, JsValue> {
    let decoded = base64_url_decode(value)
        .map_err(|e| JsValue::from_str(&format!("Invalid {field_name}: {e}")))?;
    if decoded.is_empty() {
        return Err(JsValue::from_str(&format!(
            "{field_name} must decode to non-empty bytes"
        )));
    }
    Ok(decoded)
}

fn decode_role_separated_commitments_from_js(
    args: &JsValue,
    field_name: &str,
) -> Result<RoleSeparatedEd25519CommitmentsV1, JsValue> {
    let value = Reflect::get(args, &JsValue::from_str(field_name))
        .map_err(|_| JsValue::from_str(&format!("Invalid args: missing {field_name}")))?;
    if !value.is_object() || js_sys::Array::is_array(&value) {
        return Err(JsValue::from_str(&format!(
            "Invalid args: {field_name} must be an object"
        )));
    }
    let hiding = decode_fixed_32(
        &get_required_string(&value, "hidingB64u")?,
        &format!("{field_name}.hidingB64u"),
    )?;
    let binding = decode_fixed_32(
        &get_required_string(&value, "bindingB64u")?,
        &format!("{field_name}.bindingB64u"),
    )?;
    RoleSeparatedEd25519CommitmentsV1::new(hiding, binding)
        .map_err(|e| JsValue::from_str(&e.to_string()))
}

fn set_role_separated_commitments(
    target: &js_sys::Object,
    field_name: &str,
    commitments: RoleSeparatedEd25519CommitmentsV1,
) -> Result<(), JsValue> {
    let value = object();
    set_string(
        &value,
        "hidingB64u",
        &base64_url_encode(&commitments.hiding),
    )?;
    set_string(
        &value,
        "bindingB64u",
        &base64_url_encode(&commitments.binding),
    )?;
    Reflect::set(target, &JsValue::from_str(field_name), &value)
        .map_err(|_| JsValue::from_str(&format!("Failed to serialize field {field_name}")))?;
    Ok(())
}

fn decode_fixed_33(value: &str, field_name: &str) -> Result<[u8; 33], JsValue> {
    let decoded = base64_url_decode(value)
        .map_err(|e| JsValue::from_str(&format!("Invalid {field_name}: {e}")))?;
    decoded
        .as_slice()
        .try_into()
        .map_err(|_| JsValue::from_str(&format!("{field_name} must decode to 33 bytes")))
}

fn decode_ethereum_address20(value: &str) -> Result<[u8; 20], JsValue> {
    let text = value.trim().strip_prefix("0x").unwrap_or(value.trim());
    if text.len() != 40 {
        return Err(JsValue::from_str("ethereumAddress must be 20 bytes hex"));
    }
    let mut out = [0u8; 20];
    for (i, byte) in out.iter_mut().enumerate() {
        let start = i * 2;
        *byte = u8::from_str_radix(&text[start..start + 2], 16)
            .map_err(|_| JsValue::from_str("ethereumAddress must be hex"))?;
    }
    Ok(out)
}

fn get_optional_u32(args: &JsValue, field_name: &str) -> Result<Option<u32>, JsValue> {
    let value = Reflect::get(args, &JsValue::from_str(field_name))
        .map_err(|_| JsValue::from_str(&format!("Invalid args: missing {field_name}")))?;
    if value.is_undefined() || value.is_null() {
        return Ok(None);
    }
    let number = value
        .as_f64()
        .ok_or_else(|| JsValue::from_str(&format!("{field_name} must be a number")))?;
    if !number.is_finite() || number < 0.0 || number.fract() != 0.0 || number > u32::MAX as f64 {
        return Err(JsValue::from_str(&format!(
            "{field_name} must be a u32 integer"
        )));
    }
    Ok(Some(number as u32))
}

fn hex_prefixed(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(2 + bytes.len() * 2);
    out.push_str("0x");
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PrepareResolvedEmailOtpRootCommandV1 {
    kind: PrepareResolvedEmailOtpRootCommandKindV1,
    algorithm: EcdsaClientBootstrapAlgorithmV1,
    context: EcdsaClientBootstrapContextV1,
    participants: EcdsaClientBootstrapParticipantsV1,
    resolved_email_otp_root_share32_b64u: String,
}

#[derive(Debug, Deserialize)]
enum PrepareResolvedEmailOtpRootCommandKindV1 {
    #[serde(rename = "prepare_ecdsa_client_bootstrap_from_resolved_email_otp_root_v1")]
    PrepareEcdsaClientBootstrapFromResolvedEmailOtpRootV1,
}

fn prepare_resolved_email_otp_root_command_v1(
    command: PrepareResolvedEmailOtpRootCommandV1,
) -> CoreResult<PrepareEcdsaClientBootstrapOutputV1> {
    match command.kind {
        PrepareResolvedEmailOtpRootCommandKindV1::PrepareEcdsaClientBootstrapFromResolvedEmailOtpRootV1 => {}
    }
    match command.algorithm {
        EcdsaClientBootstrapAlgorithmV1::EcdsaHssSecp256k1RoleLocalV1 => {}
    }
    validate_resolved_email_otp_root_participants(&command.participants)?;

    let context = EcdsaHssStableKeyContext::new(decode_fixed_32_core(
        &command.context.application_binding_digest_b64u,
        "context.applicationBindingDigestB64u",
    )?);
    context
        .validate()
        .map_err(|error| SignerCoreError::invalid_input(error.to_string()))?;

    let mut client_root_share32 = decode_fixed_32_core(
        &command.resolved_email_otp_root_share32_b64u,
        "resolvedEmailOtpRootShare32B64u",
    )?;
    let prepared_result = prepare_ecdsa_client_bootstrap(PrepareEcdsaClientBootstrapCommand {
        context,
        client_root_share32,
    });
    client_root_share32.fill(0);
    let prepared = prepared_result?;

    Ok(PrepareEcdsaClientBootstrapOutputV1 {
        pending_state_blob: EcdsaRoleLocalPendingStateBlobV1 {
            kind: PendingStateBlobKindV1::EcdsaRoleLocalPendingStateBlobV1,
            curve: Secp256k1CurveNameV1::Secp256k1,
            encoding: Base64UrlEncodingV1::Base64url,
            producer: SignerCoreProducerV1::SignerCore,
            state_blob_b64u: base64_url_encode(&prepared.pending_state_blob.state_blob),
        },
        client_bootstrap: EcdsaClientBootstrapFactsV1 {
            context_binding32_b64u: base64_url_encode(&prepared.client_bootstrap.context_binding32),
            hss_client_share_public_key33_b64u: base64_url_encode(
                &prepared.client_bootstrap.hss_client_share_public_key33,
            ),
            client_share_retry_counter: prepared.client_bootstrap.client_share_retry_counter,
            participant_id: prepared.client_bootstrap.participant_id,
        },
        public_facts: EcdsaPreparePublicFactsV1 {
            hss_client_share_public_key33_b64u: base64_url_encode(
                &prepared.public_facts.hss_client_share_public_key33,
            ),
            client_verifying_share_b64u: base64_url_encode(
                &prepared.public_facts.client_verifying_share33,
            ),
        },
    })
}

fn validate_resolved_email_otp_root_participants(
    participants: &EcdsaClientBootstrapParticipantsV1,
) -> CoreResult<()> {
    if participants.client_participant_id != 1 {
        return Err(SignerCoreError::invalid_input(
            "participants.clientParticipantId must be 1",
        ));
    }
    if participants.relayer_participant_id != 2 {
        return Err(SignerCoreError::invalid_input(
            "participants.relayerParticipantId must be 2",
        ));
    }
    if participants.participant_ids != [1, 2] {
        return Err(SignerCoreError::invalid_input(
            "participants.participantIds must be [1, 2]",
        ));
    }
    Ok(())
}

fn decode_fixed_32_core(value: &str, field_name: &str) -> CoreResult<[u8; 32]> {
    let mut decoded = base64_url_decode(value)
        .map_err(|error| SignerCoreError::decode_error(format!("{field_name}: {error}")))?;
    if decoded.len() != 32 {
        let len = decoded.len();
        decoded.fill(0);
        return Err(SignerCoreError::invalid_length(format!(
            "{field_name} must decode to 32 bytes (got {len})"
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&decoded);
    decoded.fill(0);
    Ok(out)
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct SignerWorkerErrorWire {
    code: String,
    core_code: String,
    message: String,
}

fn command_core_code_name(code: SignerCoreErrorCode) -> &'static str {
    match code {
        SignerCoreErrorCode::InvalidInput => "InvalidInput",
        SignerCoreErrorCode::InvalidLength => "InvalidLength",
        SignerCoreErrorCode::DecodeError => "DecodeError",
        SignerCoreErrorCode::EncodeError => "EncodeError",
        SignerCoreErrorCode::HkdfError => "HkdfError",
        SignerCoreErrorCode::CryptoError => "CryptoError",
        SignerCoreErrorCode::Utf8Error => "Utf8Error",
        SignerCoreErrorCode::Unsupported => "Unsupported",
        SignerCoreErrorCode::Internal => "Internal",
    }
}

fn command_host_code(code: SignerCoreErrorCode) -> &'static str {
    match code {
        SignerCoreErrorCode::InvalidInput => "SIGNER_INVALID_INPUT",
        SignerCoreErrorCode::InvalidLength => "SIGNER_INVALID_LENGTH",
        SignerCoreErrorCode::DecodeError => "SIGNER_DECODE_ERROR",
        SignerCoreErrorCode::EncodeError => "SIGNER_ENCODE_ERROR",
        SignerCoreErrorCode::HkdfError => "SIGNER_KDF_ERROR",
        SignerCoreErrorCode::CryptoError => "SIGNER_CRYPTO_ERROR",
        SignerCoreErrorCode::Utf8Error => "SIGNER_UTF8_ERROR",
        SignerCoreErrorCode::Unsupported => "SIGNER_UNSUPPORTED",
        SignerCoreErrorCode::Internal => "SIGNER_INTERNAL",
    }
}

fn js_command_error_with_codes(code: &str, core_code: &str, message: String) -> JsValue {
    serde_wasm_bindgen::to_value(&SignerWorkerErrorWire {
        code: code.to_owned(),
        core_code: core_code.to_owned(),
        message,
    })
    .unwrap_or_else(|_| JsValue::from_str("SIGNER_INTERNAL: failed to serialize error"))
}

fn js_signer_core_err(error: SignerCoreError) -> JsValue {
    js_command_error_with_codes(
        command_host_code(error.code),
        command_core_code_name(error.code),
        error.message,
    )
}

fn js_command_invalid_input_err(error: impl core::fmt::Display) -> JsValue {
    js_command_error_with_codes("SIGNER_INVALID_INPUT", "InvalidInput", error.to_string())
}

fn decode_wire_message(value: &str, field_name: &str) -> Result<WireMessage, JsValue> {
    Ok(WireMessage {
        bytes: base64_url_decode(value)
            .map_err(|e| JsValue::from_str(&format!("Invalid {field_name}: {e}")))?,
    })
}

fn encode_wire_message(value: &WireMessage) -> String {
    base64_url_encode(&value.bytes)
}
