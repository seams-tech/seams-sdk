use std::fs;

mod support;

use support::{extract_function_body, read_src_file, rust_source_files};

#[test]
fn production_adapter_source_does_not_reference_joined_state_material() {
    let forbidden_patterns = [
        "joined d",
        "joined_d",
        "joined a",
        "joined_a",
        "joined x_client_base",
        "joined_x_client_base",
        "joined y_server",
        "joined_y_server",
        "joined tau_server",
        "joined_tau_server",
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
        "validate_cloudflare_signer_private_request_v1",
        "decode_and_validate_cloudflare_signer_envelope_hpke_payload_v1",
        "handle_cloudflare_signer_recipient_proof_bundle_private_fetch_v1",
        "handle_cloudflare_signer_recipient_proof_bundle_private_request_v1",
        "validate_cloudflare_deriver_peer_request_v1",
        "handle_cloudflare_deriver_peer_fetch_v1",
        "handle_cloudflare_deriver_peer_request_v1",
    ] {
        let body = extract_function_body(&lib_rs, function_name);
        for forbidden in [
            "SignerInputPlaintextV1",
            "decode_signer_input_plaintext_v1",
            "decode_and_validate_cloudflare_signer_input_plaintext_v1",
            "validate_cloudflare_signer_private_request_plaintext_v1",
            "decrypt_and_validate_cloudflare_signer_input_plaintext_v1",
            "decrypt_cloudflare_validated_signer_private_request_v1",
        ] {
            assert!(
                !body.contains(forbidden),
                "{function_name} crosses signer plaintext boundary through `{forbidden}`"
            );
        }
    }
}

/// The creation probe's deterministic issuer key must be unreachable in a
/// release build.
///
/// It is a real Ed25519 signing key that mints valid tenant-root creation
/// commands. A release binary that could reference it would accept probe-issued
/// commands as production authorization, so every definition and every use must
/// sit behind `#[cfg(debug_assertions)]`.
#[test]
fn the_creation_probe_issuer_key_cannot_be_referenced_in_release_builds() {
    let source = read_src_file("tenant_root_role_d1.rs");
    let marker = "TENANT_ROOT_CREATION_PROBE_ISSUER_KEY_V1";
    let mut sites = 0_usize;
    for (index, line) in source.lines().enumerate() {
        if !line.contains(marker) {
            continue;
        }
        sites += 1;
        // Walk back to the nearest attribute or item boundary and require a
        // debug_assertions gate to cover this line.
        let preceding: Vec<&str> = source.lines().take(index + 1).collect();
        let gated = preceding
            .iter()
            .rev()
            .take(40)
            .any(|prior| prior.contains("#[cfg(debug_assertions)]"));
        assert!(
            gated,
            "line {} references {marker} without a debug_assertions gate: {line}",
            index + 1
        );
    }
    assert!(
        sites > 0,
        "the guard found no references to {marker}; it has been renamed and this test is stale"
    );

    // The key must never be named by production configuration paths.
    //
    // Read these files directly: read_src_file("lib.rs") aggregates every .rs
    // under src/, so asking it whether "lib.rs" contains the marker always says
    // yes and proves nothing.
    let src_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    for forbidden in ["env.rs", "lib.rs", "tenant_root_role_runtime.rs"] {
        let contents =
            std::fs::read_to_string(src_dir.join(forbidden)).expect("source file should read");
        assert!(
            !contents.contains(marker),
            "{forbidden} references the probe issuer key"
        );
    }
}
