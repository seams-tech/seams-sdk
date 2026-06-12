use std::fs;
use std::path::{Path, PathBuf};

#[test]
fn production_adapter_source_does_not_reference_joined_state_material() {
    let forbidden_patterns = [
        "joined d",
        "joined_d",
        "joined a",
        "joined_a",
        "joined x_client_base",
        "joined_x_client_base",
        "joined y_relayer",
        "joined_y_relayer",
        "joined tau_relayer",
        "joined_tau_relayer",
        "DdhHssSharedWord",
        "DdhHiddenEvalProjectorInputs",
    ];

    for path in rust_source_files() {
        let source = fs::read_to_string(&path).expect("source file should read");
        let lower = source.to_lowercase();
        for forbidden in forbidden_patterns {
            assert!(
                !lower.contains(&forbidden.to_lowercase()),
                "{} contains forbidden joined-state marker `{forbidden}`",
                path.display()
            );
        }
    }
}

#[test]
fn production_adapter_source_does_not_combine_recipient_outputs() {
    let forbidden_patterns = [
        "combine_mpc_prf_batch_outputs_with_threshold_backend_v1",
        "MpcPrfThresholdBatchCombinedOutputV1",
        "MpcPrfThresholdCombinedOutputV1",
    ];

    for path in rust_source_files() {
        let source = fs::read_to_string(&path).expect("source file should read");
        for forbidden in forbidden_patterns {
            assert!(
                !source.contains(forbidden),
                "{} imports or calls recipient-side combine path `{forbidden}`",
                path.display()
            );
        }
    }
}

#[test]
fn cloudflare_route_boundaries_do_not_decode_signer_plaintext() {
    let lib_rs = read_src_file("lib.rs");
    for function_name in [
        "execute_cloudflare_router_public_admission_plan_v1",
        "handle_cloudflare_router_public_request_v1",
        "handle_cloudflare_router_public_fetch_v1",
        "validate_cloudflare_signer_private_request_v1",
        "decode_and_validate_cloudflare_signer_envelope_aead_payload_v1",
        "handle_cloudflare_signer_private_fetch_v1",
        "handle_cloudflare_signer_private_request_v1",
        "validate_cloudflare_signer_peer_request_v1",
        "handle_cloudflare_signer_peer_fetch_v1",
        "handle_cloudflare_signer_peer_request_v1",
    ] {
        let body = extract_function_body(&lib_rs, function_name);
        for forbidden in [
            "SignerInputPlaintextV1",
            "decode_signer_input_plaintext_v1",
            "decode_and_validate_cloudflare_signer_input_plaintext_v1",
            "validate_cloudflare_signer_private_request_plaintext_v1",
            "decrypt_and_validate_cloudflare_signer_input_plaintext_v1",
            "decrypt_cloudflare_validated_signer_private_request_v1",
            "decrypt_and_handle_cloudflare_validated_signer_private_request_v1",
        ] {
            assert!(
                !body.contains(forbidden),
                "{function_name} crosses signer plaintext boundary through `{forbidden}`"
            );
        }
    }
}

fn read_src_file(file_name: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join(file_name);
    fs::read_to_string(path).expect("source file should read")
}

fn rust_source_files() -> Vec<PathBuf> {
    let mut out = Vec::new();
    collect_rust_files(&Path::new(env!("CARGO_MANIFEST_DIR")).join("src"), &mut out);
    out
}

fn collect_rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).expect("source directory should read") {
        let entry = entry.expect("source entry should read");
        let path = entry.path();
        if path.is_dir() {
            collect_rust_files(&path, out);
        } else if path.extension().and_then(|ext| ext.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

fn extract_function_body(source: &str, function_name: &str) -> String {
    let marker = format!("fn {function_name}");
    let start = source
        .find(&marker)
        .unwrap_or_else(|| panic!("function marker `{marker}` should exist"));
    let body_start = source[start..]
        .find('{')
        .map(|offset| start + offset)
        .unwrap_or_else(|| panic!("function `{function_name}` should have a body"));
    let mut depth = 0usize;
    for (offset, ch) in source[body_start..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth = depth
                    .checked_sub(1)
                    .expect("function body braces should stay balanced");
                if depth == 0 {
                    return source[body_start..=body_start + offset].to_owned();
                }
            }
            _ => {}
        }
    }
    panic!("function `{function_name}` body should end");
}
