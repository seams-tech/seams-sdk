use std::env;
use std::fs;
use std::path::Path;

use ed25519_hss::{
    prepare_prime_order_succinct_hss, CanonicalContext, PrimeOrderSuccinctHssEvaluatorDriverState,
    PrimeOrderSuccinctHssEvaluatorOtState, PrimeOrderSuccinctHssGarblerDriverState,
    PrimeOrderSuccinctHssWireMessage, ProtoError, ProtoResult,
};

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
        "garbler-respond" => cmd_garbler_respond(&rest),
        "evaluator-evaluate" => cmd_evaluator_evaluate(&rest),
        "garbler-finalize" => cmd_garbler_finalize(&rest),
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
    let garbler_state: PrimeOrderSuccinctHssGarblerDriverState = read_json_file(garbler_state_in)?;
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
    let evaluator_state: PrimeOrderSuccinctHssEvaluatorDriverState =
        read_json_file(evaluator_state_in)?;
    let (_runtime, evaluator_session) = evaluator_state.materialize()?;
    let offer_message: PrimeOrderSuccinctHssWireMessage = read_json_file(offer_in)?;
    let y_client = parse_hex_array32(y_client_hex)?;
    let tau_client = parse_hex_array32(tau_client_hex)?;
    let (request_message, ot_state) = evaluator_session
        .prepare_client_ot_request_from_offer_message(&offer_message, y_client, tau_client)?;
    write_json_file(request_out, &request_message)?;
    write_json_file(ot_state_out, &ot_state)?;
    Ok(())
}

fn cmd_garbler_respond(args: &[String]) -> ProtoResult<()> {
    let garbler_state_in = required_arg(args, "--garbler-state-in")?;
    let request_in = required_arg(args, "--request-in")?;
    let y_relayer_hex = required_arg(args, "--y-relayer-hex")?;
    let tau_relayer_hex = required_arg(args, "--tau-relayer-hex")?;
    let server_out = required_arg(args, "--server-out")?;
    let garbler_state: PrimeOrderSuccinctHssGarblerDriverState = read_json_file(garbler_state_in)?;
    let (_runtime, garbler_session) = garbler_state.materialize()?;
    let request_message: PrimeOrderSuccinctHssWireMessage = read_json_file(request_in)?;
    let y_relayer = parse_hex_array32(y_relayer_hex)?;
    let tau_relayer = parse_hex_array32(tau_relayer_hex)?;
    let server_message =
        garbler_session.prepare_server_message(&request_message, y_relayer, tau_relayer)?;
    write_json_file(server_out, &server_message)?;
    Ok(())
}

fn cmd_evaluator_evaluate(args: &[String]) -> ProtoResult<()> {
    let evaluator_state_in = required_arg(args, "--evaluator-state-in")?;
    let request_in = required_arg(args, "--request-in")?;
    let ot_state_in = required_arg(args, "--ot-state-in")?;
    let server_in = required_arg(args, "--server-in")?;
    let evaluation_result_out = required_arg(args, "--evaluation-result-out")?;
    let evaluator_state: PrimeOrderSuccinctHssEvaluatorDriverState =
        read_json_file(evaluator_state_in)?;
    let (runtime, evaluator_session) = evaluator_state.materialize()?;
    let request_message: PrimeOrderSuccinctHssWireMessage = read_json_file(request_in)?;
    let ot_state: PrimeOrderSuccinctHssEvaluatorOtState = read_json_file(ot_state_in)?;
    let server_message: PrimeOrderSuccinctHssWireMessage = read_json_file(server_in)?;
    let evaluation_result_message = evaluator_session
        .evaluate_result_message_from_transport_messages(
            &runtime,
            &request_message,
            &ot_state,
            &server_message,
        )?;
    write_json_file(evaluation_result_out, &evaluation_result_message)?;
    Ok(())
}

fn cmd_garbler_finalize(args: &[String]) -> ProtoResult<()> {
    let garbler_state_in = required_arg(args, "--garbler-state-in")?;
    let evaluation_result_in = required_arg(args, "--evaluation-result-in")?;
    let report_out = required_arg(args, "--report-out")?;
    let garbler_state: PrimeOrderSuccinctHssGarblerDriverState = read_json_file(garbler_state_in)?;
    let (runtime, garbler_session) = garbler_state.materialize()?;
    let evaluation_result_message: PrimeOrderSuccinctHssWireMessage =
        read_json_file(evaluation_result_in)?;
    let report = garbler_session
        .finalize_report_from_evaluation_result_message(&runtime, &evaluation_result_message)?;
    write_json_file(report_out, &report)?;
    Ok(())
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

fn display_path(path: &str) -> String {
    Path::new(path).display().to_string()
}
