use std::fs;
use std::path::{Path, PathBuf};

use router_ab_core::SecretMaterial32;

#[test]
fn secret_material_debug_is_redacted() {
    let secret = SecretMaterial32::new([7u8; 32]);
    let debug = format!("{secret:?}");

    assert!(debug.contains("[redacted]"));
    assert!(!debug.contains("7, 7, 7"));
}

#[test]
fn secret_material_does_not_derive_serialization() {
    let material_rs = read_src_file("material.rs");
    let secret_block = extract_struct_block(&material_rs, "SecretMaterial32");

    assert!(!secret_block.contains("Serialize"));
    assert!(!secret_block.contains("Deserialize"));
}

#[test]
fn mpc_prf_plaintext_partial_wire_does_not_derive_serialization() {
    let candidate_rs = read_src_file("candidate_mpc_prf.rs");
    for struct_name in [
        "MpcPrfPartialWireV1",
        "MpcPrfSignerPartialV1",
        "MpcPrfPartialProofBundleV1",
        "MpcPrfVerifiedPartialV1",
    ] {
        let block = extract_struct_block(&candidate_rs, struct_name);
        assert!(!block.contains("Serialize"), "{struct_name}");
        assert!(!block.contains("Deserialize"), "{struct_name}");
    }
}

#[test]
fn mpc_prf_threshold_backend_secret_types_do_not_derive_serialization() {
    let backend_rs = read_src_file("candidate_mpc_prf_threshold_backend.rs");
    for struct_name in [
        "MpcPrfSigningRootShareWireV1",
        "MpcPrfThresholdSignerInputV1",
        "MpcPrfThresholdSignerBatchInputV1",
        "MpcPrfThresholdSignerBatchOutputV1",
        "MpcPrfThresholdBatchCombineInputV1",
        "MpcPrfThresholdBatchCombinedOutputV1",
        "MpcPrfThresholdCombineInputV1",
        "MpcPrfThresholdCombinedOutputV1",
    ] {
        let block = extract_struct_block(&backend_rs, struct_name);
        assert!(!block.contains("Serialize"), "{struct_name}");
        assert!(!block.contains("Deserialize"), "{struct_name}");
    }
}

#[test]
fn recipient_output_encryption_request_does_not_derive_serialization() {
    let output_rs = read_manifest_file("src/protocol/output.rs");
    let block = extract_struct_block(&output_rs, "RecipientOutputEncryptionRequestV1");

    assert!(!block.contains("Serialize"));
    assert!(!block.contains("Deserialize"));
}

#[test]
fn split_root_plaintext_share_types_do_not_derive_serialization() {
    let candidate_rs = read_src_file("candidate_split_root.rs");
    for struct_name in [
        "SplitRootSecretShareV1",
        "SplitRootOutputShareWireV1",
        "SplitRootSignerOutputShareV1",
        "SplitRootVerifiedOutputShareV1",
        "SplitRootCombinedOutputV1",
    ] {
        let block = extract_struct_block(&candidate_rs, struct_name);
        assert!(!block.contains("Serialize"), "{struct_name}");
        assert!(!block.contains("Deserialize"), "{struct_name}");
    }
}

#[test]
fn library_code_does_not_log_or_debug_print() {
    for path in rust_source_files() {
        if is_allowed_logging_file(&path) {
            continue;
        }

        let source = fs::read_to_string(&path).expect("source file should read");
        for forbidden in ["println!", "eprintln!", "dbg!"] {
            assert!(
                !source.contains(forbidden),
                "{} contains forbidden logging macro `{forbidden}`",
                path.display()
            );
        }
    }
}

#[test]
fn forbidden_joined_state_names_stay_in_allowlisted_modules() {
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
    ];

    for path in rust_source_files() {
        if is_allowed_invariant_model_file(&path) {
            continue;
        }

        let source = fs::read_to_string(&path).expect("source file should read");
        let lower = source.to_lowercase();
        for forbidden in forbidden_patterns {
            assert!(
                !lower.contains(forbidden),
                "{} contains forbidden joined-state phrase `{forbidden}` outside invariant models",
                path.display()
            );
        }
    }
}

#[test]
fn router_boundary_does_not_import_signer_plaintext_decoder() {
    for relative_path in [
        "src/protocol/engine/router.rs",
        "src/protocol/public_request.rs",
    ] {
        let source = read_manifest_file(relative_path);
        for forbidden in [
            "SignerInputPlaintextV1",
            "decode_signer_input_plaintext_v1",
            "validate_signer_input_plaintext_binding_v1",
        ] {
            assert!(
                !source.contains(forbidden),
                "{relative_path} imports signer plaintext boundary `{forbidden}`"
            );
        }
    }
}

#[test]
fn ab_peer_payloads_do_not_carry_combined_or_root_secret_material() {
    let payload_rs = read_manifest_file("src/protocol/payload.rs");
    for forbidden in [
        "SecretMaterial32",
        "MpcPrfSigningRootShareWireV1",
        "MpcPrfThresholdSignerInputV1",
        "MpcPrfThresholdSignerBatchInputV1",
        "MpcPrfThresholdCombineInputV1",
        "MpcPrfThresholdCombinedOutputV1",
        "SplitRootSecretShareV1",
        "SplitRootCombinedOutputV1",
    ] {
        assert!(
            !payload_rs.contains(forbidden),
            "A/B peer payload module imports forbidden secret-bearing type `{forbidden}`"
        );
    }
}

fn read_src_file(file_name: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("derivation")
        .join(file_name);
    fs::read_to_string(path).expect("source file should read")
}

fn read_manifest_file(relative_path: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(relative_path);
    fs::read_to_string(path).expect("source file should read")
}

fn extract_struct_block(source: &str, struct_name: &str) -> String {
    let marker = format!("pub struct {struct_name}");
    let start = source.find(&marker).expect("struct marker should exist");
    let before = source[..start].rfind("#[").unwrap_or(start);
    let after = source[start..]
        .find("}")
        .map(|offset| start + offset + 1)
        .expect("struct block should end");
    source[before..after].to_owned()
}

fn rust_source_files() -> Vec<PathBuf> {
    let mut out = Vec::new();
    collect_rust_files(
        &Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("derivation"),
        &mut out,
    );
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

fn is_allowed_logging_file(path: &Path) -> bool {
    path.ends_with(Path::new("src/bin/emit_contract_vectors.rs"))
}

fn is_allowed_invariant_model_file(path: &Path) -> bool {
    path.ends_with(Path::new("src/derivation/leakage.rs"))
        || path.ends_with(Path::new("src/derivation/material.rs"))
}
