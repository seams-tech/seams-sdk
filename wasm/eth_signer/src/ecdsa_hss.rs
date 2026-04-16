use base64ct::{Base64UrlUnpadded, Encoding};
use ecdsa_hss::{
    bootstrap_evm_threshold_v1, complete_presign_roundtrip_v1, derive_additive_shares_v1,
    derive_canonical_secret_v1, encode_context_v1, export_evm_threshold_v1, EcdsaHssContextV1,
    EvmThresholdBootstrapRequestV1, EvmThresholdExportRequestV1, EvmThresholdSigningOperationV1,
    RootShareInputsV1, ServerEvalOperationV1,
};
use js_sys::Date;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use wasm_bindgen::prelude::JsValue;

use crate::errors::{js_core_err, js_invalid_input_err};

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EcdsaHssBenchmarkInputJs {
    pub near_account_id: String,
    pub key_purpose: String,
    pub key_version: String,
    pub y_client32_le: Vec<u8>,
    pub y_relayer32_le: Vec<u8>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EcdsaHssSignBenchmarkInputJs {
    #[serde(flatten)]
    pub root: EcdsaHssBenchmarkInputJs,
    pub digest32: Vec<u8>,
    pub entropy32: Vec<u8>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CanonicalSecretBenchmarkResultJs {
    pub x32: Vec<u8>,
    pub public_key33: Vec<u8>,
    pub ethereum_address20: Vec<u8>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdditiveSharesBenchmarkResultJs {
    pub retry_counter: u32,
    pub x_client32: Vec<u8>,
    pub x_relayer32: Vec<u8>,
    pub threshold_public_key33: Vec<u8>,
    pub threshold_ethereum_address20: Vec<u8>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BootstrapBenchmarkResultJs {
    pub group_public_key33: Vec<u8>,
    pub ethereum_address20: Vec<u8>,
    pub client_threshold_private_share32: Vec<u8>,
    pub relayer_threshold_private_share32: Vec<u8>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BootstrapFullResultJs {
    pub group_public_key33: Vec<u8>,
    pub ethereum_address20: Vec<u8>,
    pub client_additive_share32: Vec<u8>,
    pub client_public_key33: Vec<u8>,
    pub relayer_additive_share32: Vec<u8>,
    pub relayer_public_key33: Vec<u8>,
    pub client_threshold_private_share32: Vec<u8>,
    pub relayer_threshold_private_share32: Vec<u8>,
    pub retry_counter: u32,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportBenchmarkResultJs {
    pub canonical_x32: Vec<u8>,
    pub canonical_public_key33: Vec<u8>,
    pub canonical_ethereum_address20: Vec<u8>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignBenchmarkProfileResultJs {
    pub signature65: Vec<u8>,
    pub parse_input_ms: f64,
    pub prepare_session_ms: f64,
    pub presign_roundtrip_ms: f64,
    pub client_signature_share_ms: f64,
    pub finalize_signature_ms: f64,
    pub total_core_ms: f64,
}

fn parse_context_and_roots(
    payload: JsValue,
) -> Result<(EcdsaHssContextV1, [u8; 32], [u8; 32]), JsValue> {
    let parsed: EcdsaHssBenchmarkInputJs =
        serde_wasm_bindgen::from_value(payload).map_err(|err| js_invalid_input_err(err))?;
    let context = EcdsaHssContextV1::new(
        parsed.near_account_id,
        parsed.key_purpose,
        parsed.key_version,
    );
    let y_client32_le = vec_to_fixed_32(parsed.y_client32_le, "yClient32Le")?;
    let y_relayer32_le = vec_to_fixed_32(parsed.y_relayer32_le, "yRelayer32Le")?;
    Ok((context, y_client32_le, y_relayer32_le))
}

pub fn ecdsa_hss_derive_canonical_secret(payload: JsValue) -> Result<JsValue, JsValue> {
    let (context, y_client32_le, y_relayer32_le) = parse_context_and_roots(payload)?;
    let out = derive_canonical_secret_v1(
        &RootShareInputsV1::new(y_client32_le, y_relayer32_le),
        &context,
    )
    .map_err(js_core_err)?;
    serde_wasm_bindgen::to_value(&CanonicalSecretBenchmarkResultJs {
        x32: out.x32.to_vec(),
        public_key33: out.public_key33.to_vec(),
        ethereum_address20: out.ethereum_address20.to_vec(),
    })
    .map_err(|err| js_invalid_input_err(err))
}

pub fn ecdsa_hss_derive_additive_shares(payload: JsValue) -> Result<JsValue, JsValue> {
    let (context, y_client32_le, y_relayer32_le) = parse_context_and_roots(payload)?;
    let canonical = derive_canonical_secret_v1(
        &RootShareInputsV1::new(y_client32_le, y_relayer32_le),
        &context,
    )
    .map_err(js_core_err)?;
    let out = derive_additive_shares_v1(&canonical.x32, &context).map_err(js_core_err)?;
    serde_wasm_bindgen::to_value(&AdditiveSharesBenchmarkResultJs {
        retry_counter: out.retry_counter,
        x_client32: out.x_client32.to_vec(),
        x_relayer32: out.x_relayer32.to_vec(),
        threshold_public_key33: out.threshold_public_key33.to_vec(),
        threshold_ethereum_address20: out.threshold_ethereum_address20.to_vec(),
    })
    .map_err(|err| js_invalid_input_err(err))
}

pub fn ecdsa_hss_bootstrap_non_export_sign(payload: JsValue) -> Result<JsValue, JsValue> {
    let (context, y_client32_le, y_relayer32_le) = parse_context_and_roots(payload)?;
    let out = bootstrap_evm_threshold_v1(EvmThresholdBootstrapRequestV1 {
        operation: ServerEvalOperationV1::NonExportSign,
        context,
        y_client32_le,
        y_relayer32_le,
    })
    .map_err(js_core_err)?;
    serde_wasm_bindgen::to_value(&BootstrapBenchmarkResultJs {
        group_public_key33: out.adapter.identity.group_public_key33.to_vec(),
        ethereum_address20: out.adapter.identity.ethereum_address20.to_vec(),
        client_threshold_private_share32: out.adapter.client.threshold_private_share32.to_vec(),
        relayer_threshold_private_share32: out.adapter.relayer.threshold_private_share32.to_vec(),
    })
    .map_err(|err| js_invalid_input_err(err))
}

pub fn ecdsa_hss_bootstrap_non_export_sign_full(payload: JsValue) -> Result<JsValue, JsValue> {
    let (context, y_client32_le, y_relayer32_le) = parse_context_and_roots(payload)?;
    let out = bootstrap_evm_threshold_v1(EvmThresholdBootstrapRequestV1 {
        operation: ServerEvalOperationV1::NonExportSign,
        context,
        y_client32_le,
        y_relayer32_le,
    })
    .map_err(js_core_err)?;
    serde_wasm_bindgen::to_value(&BootstrapFullResultJs {
        group_public_key33: out.adapter.identity.group_public_key33.to_vec(),
        ethereum_address20: out.adapter.identity.ethereum_address20.to_vec(),
        client_additive_share32: out.adapter.client.additive_share32.to_vec(),
        client_public_key33: out.adapter.identity.client_verifying_share33.to_vec(),
        relayer_additive_share32: out.adapter.relayer.additive_share32.to_vec(),
        relayer_public_key33: out.adapter.identity.relayer_verifying_share33.to_vec(),
        client_threshold_private_share32: out.adapter.client.threshold_private_share32.to_vec(),
        relayer_threshold_private_share32: out.adapter.relayer.threshold_private_share32.to_vec(),
        retry_counter: out.adapter.identity.retry_counter,
    })
    .map_err(|err| js_invalid_input_err(err))
}

pub fn ecdsa_hss_sign_non_export(payload: JsValue) -> Result<Vec<u8>, JsValue> {
    run_sign_non_export(payload).map(|result| result.signature65)
}

pub fn ecdsa_hss_sign_non_export_profiled(payload: JsValue) -> Result<JsValue, JsValue> {
    let result = run_sign_non_export(payload)?;
    serde_wasm_bindgen::to_value(&result).map_err(|err| js_invalid_input_err(err))
}

pub fn ecdsa_hss_explicit_export(payload: JsValue) -> Result<JsValue, JsValue> {
    let (context, y_client32_le, y_relayer32_le) = parse_context_and_roots(payload)?;
    let out = export_evm_threshold_v1(EvmThresholdExportRequestV1 {
        context,
        y_client32_le,
        y_relayer32_le,
    })
    .map_err(js_core_err)?;
    serde_wasm_bindgen::to_value(&ExportBenchmarkResultJs {
        canonical_x32: out.exported.canonical_x32.to_vec(),
        canonical_public_key33: out.exported.canonical_public_key33.to_vec(),
        canonical_ethereum_address20: out.exported.canonical_ethereum_address20.to_vec(),
    })
    .map_err(|err| js_invalid_input_err(err))
}

pub fn threshold_ecdsa_hss_prepare_server_session(_payload: JsValue) -> Result<JsValue, JsValue> {
    let parsed: EcdsaHssPrepareServerSessionInputJs =
        serde_wasm_bindgen::from_value(_payload).map_err(|err| js_invalid_input_err(err))?;
    let context = EcdsaHssContextV1::new(
        parsed.near_account_id,
        parsed.key_purpose,
        parsed.key_version,
    );
    let operation = parse_server_eval_operation(&parsed.operation)?;
    let context_binding = compute_ecdsa_context_binding(&context).map_err(js_core_err)?;
    let y_relayer32_le = vec_to_fixed_32(parsed.y_relayer32_le, "yRelayer32Le")?;
    let session = ThresholdEcdsaHssPreparedServerSessionWire {
        operation: server_eval_operation_code(operation),
        near_account_id: context.near_account_id,
        key_purpose: context.key_purpose,
        key_version: context.key_version,
        context_binding,
        y_relayer32_le,
    };
    serde_wasm_bindgen::to_value(&ThresholdEcdsaHssPrepareServerSessionResultJs {
        prepared_server_session_b64u: encode_state_blob(
            &session,
            "threshold ecdsa hss prepared server session",
        )
        .map_err(js_invalid_input_err)?,
        server_assist_init_message_b64u: encode_state_blob(
            &ThresholdEcdsaHssServerAssistInitWire { context_binding },
            "threshold ecdsa hss server assist init",
        )
        .map_err(js_invalid_input_err)?,
    })
    .map_err(js_invalid_input_err)
}

pub fn threshold_ecdsa_hss_prepare_server_ceremony(payload: JsValue) -> Result<JsValue, JsValue> {
    let parsed: EcdsaHssPrepareServerCeremonyInputJs =
        serde_wasm_bindgen::from_value(payload).map_err(|err| js_invalid_input_err(err))?;
    let session: ThresholdEcdsaHssPreparedServerSessionWire = decode_state_blob(
        &parsed.prepared_server_session_b64u,
        "preparedServerSessionB64u",
    )?;
    let assist: ThresholdEcdsaHssServerAssistInitWire =
        decode_state_blob(&parsed.server_assist_init_b64u, "serverAssistInitB64u")?;
    let client_request: ThresholdEcdsaHssClientEvalRequestWire =
        decode_state_blob(&parsed.client_eval_request_b64u, "clientEvalRequestB64u")?;
    if assist.context_binding != session.context_binding {
        return Err(js_invalid_input_err(
            "serverAssistInitB64u did not match preparedServerSessionB64u",
        ));
    }
    if client_request.context_binding != session.context_binding {
        return Err(js_invalid_input_err(
            "clientEvalRequestB64u did not match preparedServerSessionB64u",
        ));
    }
    serde_wasm_bindgen::to_value(&ThresholdEcdsaHssPrepareServerCeremonyResultJs {
        server_eval_response_b64u: encode_state_blob(
            &ThresholdEcdsaHssServerEvalResponseWire {
                context_binding: session.context_binding,
            },
            "threshold ecdsa hss server eval response",
        )
        .map_err(js_invalid_input_err)?,
    })
    .map_err(js_invalid_input_err)
}

pub fn threshold_ecdsa_hss_finalize_server_report(payload: JsValue) -> Result<JsValue, JsValue> {
    let parsed: EcdsaHssFinalizeServerReportInputJs =
        serde_wasm_bindgen::from_value(payload).map_err(|err| js_invalid_input_err(err))?;
    let session: ThresholdEcdsaHssPreparedServerSessionWire = decode_state_blob(
        &parsed.prepared_server_session_b64u,
        "preparedServerSessionB64u",
    )?;
    let client_request: ThresholdEcdsaHssClientEvalRequestWire =
        decode_state_blob(&parsed.client_eval_request_b64u, "clientEvalRequestB64u")?;
    let server_eval_response: ThresholdEcdsaHssServerEvalResponseWire =
        decode_state_blob(&parsed.server_eval_response_b64u, "serverEvalResponseB64u")?;
    let client_finalize: ThresholdEcdsaHssClientFinalizeWire =
        decode_state_blob(&parsed.client_eval_finalize_b64u, "clientEvalFinalizeB64u")?;
    if client_request.context_binding != session.context_binding {
        return Err(js_invalid_input_err(
            "clientEvalRequestB64u did not match preparedServerSessionB64u",
        ));
    }
    if server_eval_response.context_binding != session.context_binding {
        return Err(js_invalid_input_err(
            "serverEvalResponseB64u did not match preparedServerSessionB64u",
        ));
    }
    if client_finalize.context_binding != session.context_binding {
        return Err(js_invalid_input_err(
            "clientEvalFinalizeB64u did not match preparedServerSessionB64u",
        ));
    }
    serde_wasm_bindgen::to_value(&ThresholdEcdsaHssFinalizeServerReportResultJs {
        server_output_message_b64u: encode_state_blob(
            &ThresholdEcdsaHssServerOutputWire {
                context_binding: session.context_binding,
                y_client32_le: client_request.y_client32_le,
            },
            "threshold ecdsa hss server output",
        )
        .map_err(js_invalid_input_err)?,
    })
    .map_err(js_invalid_input_err)
}

pub fn threshold_ecdsa_hss_open_server_output(payload: JsValue) -> Result<JsValue, JsValue> {
    let parsed: EcdsaHssOpenServerOutputInputJs =
        serde_wasm_bindgen::from_value(payload).map_err(|err| js_invalid_input_err(err))?;
    let session: ThresholdEcdsaHssPreparedServerSessionWire = decode_state_blob(
        &parsed.prepared_server_session_b64u,
        "preparedServerSessionB64u",
    )?;
    let output: ThresholdEcdsaHssServerOutputWire = decode_state_blob(
        &parsed.server_output_message_b64u,
        "serverOutputMessageB64u",
    )?;
    if output.context_binding != session.context_binding {
        return Err(js_invalid_input_err(
            "serverOutputMessageB64u did not match preparedServerSessionB64u",
        ));
    }
    serde_wasm_bindgen::to_value(&ThresholdEcdsaHssOpenServerOutputResultJs {
        context_binding_b64u: base64_url_encode(&output.context_binding),
        y_client32_le_b64u: base64_url_encode(&output.y_client32_le),
    })
    .map_err(js_invalid_input_err)
}

fn vec_to_fixed_32(bytes: Vec<u8>, field_name: &str) -> Result<[u8; 32], JsValue> {
    if bytes.len() != 32 {
        return Err(js_invalid_input_err(format!(
            "{field_name} must be 32 bytes (got {})",
            bytes.len()
        )));
    }
    bytes
        .try_into()
        .map_err(|_| js_invalid_input_err(format!("{field_name} must be exactly 32 bytes")))
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EcdsaHssPrepareServerSessionInputJs {
    pub near_account_id: String,
    pub key_purpose: String,
    pub key_version: String,
    pub operation: String,
    pub y_relayer32_le: Vec<u8>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ThresholdEcdsaHssPrepareServerSessionResultJs {
    pub prepared_server_session_b64u: String,
    pub server_assist_init_message_b64u: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EcdsaHssPrepareServerCeremonyInputJs {
    pub prepared_server_session_b64u: String,
    pub client_eval_request_b64u: String,
    pub server_assist_init_b64u: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ThresholdEcdsaHssPrepareServerCeremonyResultJs {
    pub server_eval_response_b64u: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EcdsaHssFinalizeServerReportInputJs {
    pub prepared_server_session_b64u: String,
    pub client_eval_request_b64u: String,
    pub client_eval_finalize_b64u: String,
    pub server_eval_response_b64u: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ThresholdEcdsaHssFinalizeServerReportResultJs {
    pub server_output_message_b64u: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EcdsaHssOpenServerOutputInputJs {
    pub prepared_server_session_b64u: String,
    pub server_output_message_b64u: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ThresholdEcdsaHssOpenServerOutputResultJs {
    pub context_binding_b64u: String,
    pub y_client32_le_b64u: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ThresholdEcdsaHssPreparedServerSessionWire {
    operation: u8,
    near_account_id: String,
    key_purpose: String,
    key_version: String,
    context_binding: [u8; 32],
    y_relayer32_le: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ThresholdEcdsaHssServerAssistInitWire {
    context_binding: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ThresholdEcdsaHssClientEvalRequestWire {
    context_binding: [u8; 32],
    y_client32_le: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ThresholdEcdsaHssServerEvalResponseWire {
    context_binding: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ThresholdEcdsaHssClientFinalizeWire {
    context_binding: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ThresholdEcdsaHssServerOutputWire {
    context_binding: [u8; 32],
    y_client32_le: [u8; 32],
}

fn parse_server_eval_operation(value: &str) -> Result<ServerEvalOperationV1, JsValue> {
    match value.trim() {
        "registration_bootstrap" => Ok(ServerEvalOperationV1::RegistrationBootstrap),
        "session_bootstrap" => Ok(ServerEvalOperationV1::SessionBootstrap),
        "non_export_sign" => Ok(ServerEvalOperationV1::NonExportSign),
        "explicit_key_export" => Ok(ServerEvalOperationV1::ExplicitKeyExport),
        _ => Err(js_invalid_input_err("operation is invalid")),
    }
}

fn server_eval_operation_code(value: ServerEvalOperationV1) -> u8 {
    match value {
        ServerEvalOperationV1::RegistrationBootstrap => 1,
        ServerEvalOperationV1::SessionBootstrap => 2,
        ServerEvalOperationV1::NonExportSign => 3,
        ServerEvalOperationV1::ExplicitKeyExport => 4,
    }
}

fn compute_ecdsa_context_binding(
    context: &EcdsaHssContextV1,
) -> signer_platform_web::error::CoreResult<[u8; 32]> {
    Ok(Sha256::digest(encode_context_v1(context)?).into())
}

fn decode_state_blob<T: for<'de> Deserialize<'de>>(
    value: &str,
    field_name: &str,
) -> Result<T, JsValue> {
    let bytes = base64_url_decode(value)
        .map_err(|e| js_invalid_input_err(format!("Invalid {field_name}: {e}")))?;
    bincode::deserialize::<T>(&bytes)
        .map_err(|e| js_invalid_input_err(format!("Invalid {field_name}: {e}")))
}

fn encode_state_blob<T: Serialize>(value: &T, field_name: &str) -> Result<String, String> {
    let bytes =
        bincode::serialize(value).map_err(|e| format!("Failed to serialize {field_name}: {e}"))?;
    Ok(base64_url_encode(&bytes))
}

fn base64_url_decode(value: &str) -> Result<Vec<u8>, String> {
    Base64UrlUnpadded::decode_vec(value).map_err(|e| e.to_string())
}

fn base64_url_encode(value: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(value)
}

fn run_sign_non_export(payload: JsValue) -> Result<SignBenchmarkProfileResultJs, JsValue> {
    let parse_started = Date::now();
    let parsed: EcdsaHssSignBenchmarkInputJs =
        serde_wasm_bindgen::from_value(payload).map_err(|err| js_invalid_input_err(err))?;
    let context = EcdsaHssContextV1::new(
        parsed.root.near_account_id,
        parsed.root.key_purpose,
        parsed.root.key_version,
    );
    let y_client32_le = vec_to_fixed_32(parsed.root.y_client32_le, "yClient32Le")?;
    let y_relayer32_le = vec_to_fixed_32(parsed.root.y_relayer32_le, "yRelayer32Le")?;
    let digest32 = vec_to_fixed_32(parsed.digest32, "digest32")?;
    let entropy32 = vec_to_fixed_32(parsed.entropy32, "entropy32")?;
    let parse_input_ms = elapsed_ms(parse_started);

    let prepare_started = Date::now();
    let session = ecdsa_hss::prepare_signing_session_v1(
        EvmThresholdSigningOperationV1::NonExportSign,
        context,
        y_client32_le,
        y_relayer32_le,
    )
    .map_err(js_core_err)?;
    let prepare_session_ms = elapsed_ms(prepare_started);

    let presign_started = Date::now();
    let adapter = &session.bootstrap.adapter;
    let (client_presignature, relayer_presignature) =
        complete_presign_roundtrip_v1(adapter).map_err(js_core_err)?;
    let presign_roundtrip_ms = elapsed_ms(presign_started);

    let client_share_started = Date::now();
    let client_signature_share32 = ecdsa_hss::compute_client_signature_share_v1(
        adapter,
        &client_presignature,
        &digest32,
        &entropy32,
    )
    .map_err(js_core_err)?;
    let client_signature_share_ms = elapsed_ms(client_share_started);

    let finalize_started = Date::now();
    let signature65 = ecdsa_hss::finalize_signature_v1(
        adapter,
        &relayer_presignature,
        &digest32,
        &entropy32,
        &client_signature_share32,
    )
    .map_err(js_core_err)?;
    let finalize_signature_ms = elapsed_ms(finalize_started);

    Ok(SignBenchmarkProfileResultJs {
        signature65: signature65.to_vec(),
        parse_input_ms,
        prepare_session_ms,
        presign_roundtrip_ms,
        client_signature_share_ms,
        finalize_signature_ms,
        total_core_ms: prepare_session_ms
            + presign_roundtrip_ms
            + client_signature_share_ms
            + finalize_signature_ms,
    })
}

fn elapsed_ms(started: f64) -> f64 {
    (Date::now() - started).max(0.0)
}
