use std::env;
use std::fs;
use std::io::{self, Read, Write};
use std::path::Path;

use ed25519_hss::{
    client::ClientDriverState,
    protocol::prepare_prime_order_succinct_hss,
    server::{ServerDriverState, ServerEvalOperation},
    shared::{CanonicalContext, ProtoError, ProtoResult},
    wire::WireMessage,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ServerCeremonyJsonInput {
    prepared_server_session: PreparedServerSessionJson,
    client_request: ClientRequestJson,
    server_inputs: ServerInputsJson,
    operation: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PreparedServerSessionJson {
    evaluator_driver_state_b64u: String,
    garbler_driver_state_b64u: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ClientRequestJson {
    client_request_message_b64u: String,
    evaluator_ot_state_b64u: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ServerInputsJson {
    y_server_b64u: String,
    tau_server_b64u: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ServerCeremonyJsonOutput {
    context_binding_b64u: String,
    staged_evaluator_artifact_b64u: String,
    server_eval_finalize_output_b64u: String,
}

fn main() {
    if let Err(err) = run() {
        eprintln!("{err}");
        std::process::exit(1);
    }
}

fn run() -> ProtoResult<()> {
    let mut args = env::args().skip(1);
    let Some(command) = args.next() else {
        return Err(ProtoError::InvalidInput("missing subcommand".to_string()));
    };
    let rest: Vec<String> = args.collect();
    match command.as_str() {
        "prepare" => cmd_prepare(&rest),
        "garbler-offer" => cmd_garbler_offer(&rest),
        "evaluator-request" => cmd_evaluator_request(&rest),
        "server-assist-init" => cmd_server_assist_init(&rest),
        "server-ceremony-json" => cmd_server_ceremony_json(),
        _ => Err(ProtoError::InvalidInput(format!(
            "unknown subcommand {command}"
        ))),
    }
}

fn cmd_prepare(args: &[String]) -> ProtoResult<()> {
    let context_in = required_arg(args, "--context-in")?;
    let garbler_state_out = required_arg(args, "--garbler-state-out")?;
    let evaluator_state_out = required_arg(args, "--evaluator-state-out")?;
    let context: CanonicalContext = read_json_file(context_in)?;
    let prepared = prepare_prime_order_succinct_hss(&context)?;
    write_json_file(garbler_state_out, &prepared.garbler_driver_state())?;
    write_json_file(evaluator_state_out, &prepared.evaluator_driver_state())?;
    Ok(())
}

fn cmd_garbler_offer(args: &[String]) -> ProtoResult<()> {
    let garbler_state_in = required_arg(args, "--garbler-state-in")?;
    let offer_out = required_arg(args, "--offer-out")?;
    let garbler_state: ServerDriverState = read_json_file(garbler_state_in)?;
    let (_runtime, garbler_session) = garbler_state.materialize()?;
    let offer_message = garbler_session.client_ot_offer_message()?;
    write_json_file(offer_out, &offer_message)?;
    Ok(())
}

fn cmd_evaluator_request(args: &[String]) -> ProtoResult<()> {
    let evaluator_state_in = required_arg(args, "--evaluator-state-in")?;
    let offer_in = required_arg(args, "--offer-in")?;
    let y_client_hex = required_arg(args, "--y-client-hex")?;
    let tau_client_hex = required_arg(args, "--tau-client-hex")?;
    let request_out = required_arg(args, "--request-out")?;
    let ot_state_out = required_arg(args, "--ot-state-out")?;
    let evaluator_state: ClientDriverState = read_json_file(evaluator_state_in)?;
    let (_runtime, evaluator_session) = evaluator_state.materialize()?;
    let offer_message: WireMessage = read_json_file(offer_in)?;
    let y_client = parse_hex_array32(y_client_hex)?;
    let tau_client = parse_hex_array32(tau_client_hex)?;
    let (request_message, ot_state) = evaluator_session
        .prepare_client_ot_request_from_offer_message(&offer_message, y_client, tau_client)?;
    write_json_file(request_out, &request_message)?;
    write_json_file(ot_state_out, &ot_state)?;
    Ok(())
}

fn cmd_server_assist_init(args: &[String]) -> ProtoResult<()> {
    let garbler_state_in = required_arg(args, "--garbler-state-in")?;
    let request_in = required_arg(args, "--request-in")?;
    let y_server_hex = required_arg(args, "--y-server-hex")?;
    let tau_server_hex = required_arg(args, "--tau-server-hex")?;
    let server_assist_init_out = required_arg(args, "--server-assist-init-out")?;
    let garbler_state: ServerDriverState = read_json_file(garbler_state_in)?;
    let (_runtime, garbler_session) = garbler_state.materialize()?;
    let request_message: WireMessage = read_json_file(request_in)?;
    let y_server = parse_hex_array32(y_server_hex)?;
    let tau_server = parse_hex_array32(tau_server_hex)?;
    let (server_assist_init_message, _server_eval_state) = garbler_session
        .prepare_server_assist_init_message(
            &request_message,
            y_server,
            tau_server,
            ServerEvalOperation::Registration,
        )?;
    write_json_file(server_assist_init_out, &server_assist_init_message)?;
    Ok(())
}

fn cmd_server_ceremony_json() -> ProtoResult<()> {
    let input: ServerCeremonyJsonInput = read_json_stdin()?;
    let evaluator_driver_state: ClientDriverState = decode_b64u_state_blob_named(
        "preparedServerSession.evaluatorDriverStateB64u",
        &input.prepared_server_session.evaluator_driver_state_b64u,
    )?;
    let garbler_driver_state: ServerDriverState = decode_b64u_state_blob_named(
        "preparedServerSession.garblerDriverStateB64u",
        &input.prepared_server_session.garbler_driver_state_b64u,
    )?;
    let client_request_message = decode_b64u_wire_message_named(
        "clientRequest.clientRequestMessageB64u",
        &input.client_request.client_request_message_b64u,
    )?;
    let evaluator_ot_state = decode_b64u_state_blob_named(
        "clientRequest.evaluatorOtStateB64u",
        &input.client_request.evaluator_ot_state_b64u,
    )?;
    let y_server = decode_b64u_array32_named(
        "serverInputs.yServerB64u",
        &input.server_inputs.y_server_b64u,
    )?;
    let tau_server = decode_b64u_array32_named(
        "serverInputs.tauServerB64u",
        &input.server_inputs.tau_server_b64u,
    )?;
    let operation = parse_operation(&input.operation)?;

    if evaluator_driver_state.runtime != garbler_driver_state.runtime {
        return Err(ProtoError::InvalidInput(
            "evaluator and garbler driver states do not share the same prepared runtime"
                .to_string(),
        ));
    }
    let runtime = evaluator_driver_state.runtime.materialize()?;
    let evaluator_session = evaluator_driver_state.evaluator_session.materialize()?;
    let garbler_session = garbler_driver_state.garbler_session.materialize()?;
    let (_server_assist_init, artifact, server_output) = garbler_session
        .prepare_server_ceremony_from_transport_messages(
            &runtime,
            &evaluator_session,
            &evaluator_ot_state,
            &client_request_message,
            y_server,
            tau_server,
            operation,
        )?;

    let output = ServerCeremonyJsonOutput {
        context_binding_b64u: base64_url_encode(
            &evaluator_driver_state.evaluator_session.context_binding,
        ),
        staged_evaluator_artifact_b64u: encode_state_blob_b64u(&artifact)?,
        server_eval_finalize_output_b64u: encode_state_blob_b64u(&server_output)?,
    };
    write_json_stdout(&output)
}

fn required_arg<'a>(args: &'a [String], flag: &str) -> ProtoResult<&'a str> {
    let Some(index) = args.iter().position(|value| value == flag) else {
        return Err(ProtoError::InvalidInput(format!(
            "missing required flag {flag}"
        )));
    };
    args.get(index + 1)
        .map(String::as_str)
        .ok_or_else(|| ProtoError::InvalidInput(format!("missing value for flag {flag}")))
}

fn read_json_file<T: serde::de::DeserializeOwned>(path: &str) -> ProtoResult<T> {
    let bytes = fs::read(path).map_err(|err| {
        ProtoError::Decode(format!("failed to read {}: {err}", display_path(path)))
    })?;
    serde_json::from_slice(&bytes).map_err(|err| {
        ProtoError::Decode(format!(
            "failed to decode JSON from {}: {err}",
            display_path(path)
        ))
    })
}

fn read_json_stdin<T: serde::de::DeserializeOwned>() -> ProtoResult<T> {
    let mut bytes = Vec::new();
    io::stdin()
        .read_to_end(&mut bytes)
        .map_err(|err| ProtoError::Decode(format!("failed to read stdin: {err}")))?;
    serde_json::from_slice(&bytes)
        .map_err(|err| ProtoError::Decode(format!("failed to decode JSON from stdin: {err}")))
}

fn write_json_file<T: serde::Serialize>(path: &str, value: &T) -> ProtoResult<()> {
    let bytes = serde_json::to_vec_pretty(value).map_err(|err| {
        ProtoError::Decode(format!(
            "failed to encode JSON for {}: {err}",
            display_path(path)
        ))
    })?;
    fs::write(path, bytes)
        .map_err(|err| ProtoError::Decode(format!("failed to write {}: {err}", display_path(path))))
}

fn write_json_stdout<T: serde::Serialize>(value: &T) -> ProtoResult<()> {
    let bytes = serde_json::to_vec(value)
        .map_err(|err| ProtoError::Decode(format!("failed to encode stdout JSON: {err}")))?;
    io::stdout()
        .write_all(&bytes)
        .map_err(|err| ProtoError::Decode(format!("failed to write stdout: {err}")))
}

fn parse_hex_array32(value: &str) -> ProtoResult<[u8; 32]> {
    let decoded = hex::decode(value)
        .map_err(|err| ProtoError::InvalidInput(format!("failed to decode hex input: {err}")))?;
    decoded.try_into().map_err(|decoded: Vec<u8>| {
        ProtoError::InvalidInput(format!(
            "expected 32-byte hex input, got {} bytes",
            decoded.len()
        ))
    })
}

fn parse_operation(value: &str) -> ProtoResult<ServerEvalOperation> {
    match value.trim().to_ascii_lowercase().as_str() {
        "registration" => Ok(ServerEvalOperation::Registration),
        "txsigning" | "tx_signing" | "sign" => Ok(ServerEvalOperation::TxSigning),
        "linkdevice" | "link_device" => Ok(ServerEvalOperation::LinkDevice),
        "emailrecovery" | "email_recovery" => Ok(ServerEvalOperation::EmailRecovery),
        "warmsessionreconstruction" | "warm_session_reconstruction" => {
            Ok(ServerEvalOperation::WarmSessionReconstruction)
        }
        "export" | "explicitkeyexport" | "explicit_key_export" => {
            Ok(ServerEvalOperation::ExplicitKeyExport)
        }
        other => Err(ProtoError::InvalidInput(format!(
            "unknown server ceremony operation {other}"
        ))),
    }
}

fn decode_b64u_state_blob_named<T: serde::de::DeserializeOwned>(
    label: &str,
    value: &str,
) -> ProtoResult<T> {
    let decoded = base64_url_decode(value)?;
    bincode::deserialize(&decoded).map_err(|err| {
        ProtoError::Decode(format!(
            "failed to decode base64url state blob {label}: {err}"
        ))
    })
}

fn decode_b64u_array32_named(label: &str, value: &str) -> ProtoResult<[u8; 32]> {
    let decoded = base64_url_decode(value)?;
    decoded.try_into().map_err(|decoded: Vec<u8>| {
        ProtoError::InvalidInput(format!(
            "expected 32-byte base64url payload for {label}, got {} bytes",
            decoded.len()
        ))
    })
}

fn decode_b64u_wire_message_named(label: &str, value: &str) -> ProtoResult<WireMessage> {
    Ok(WireMessage {
        bytes: base64_url_decode(value).map_err(|err| {
            ProtoError::Decode(format!(
                "failed to decode base64url wire message {label}: {err}"
            ))
        })?,
    })
}

fn encode_state_blob_b64u<T: serde::Serialize>(value: &T) -> ProtoResult<String> {
    let bytes = bincode::serialize(value)
        .map_err(|err| ProtoError::Decode(format!("failed to encode state blob: {err}")))?;
    Ok(base64_url_encode(&bytes))
}

fn base64_url_encode(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn base64_url_decode(value: &str) -> ProtoResult<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|err| ProtoError::Decode(format!("failed to decode base64url payload: {err}")))
}

fn display_path(path: &str) -> String {
    Path::new(path).display().to_string()
}
