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
fn typed_envelope_and_verifier_inputs_do_not_deserialize_from_raw_boundaries() {
    let envelope_rs = read_src_file("envelope.rs");
    for struct_name in ["EnvelopeHeaderV1", "DeliveryPackageV1"] {
        let block = extract_struct_block(&envelope_rs, struct_name);
        assert!(!block.contains("Deserialize"), "{struct_name}");
    }

    let evidence_rs = read_src_file("evidence.rs");
    let verification_input_block =
        extract_struct_block(&evidence_rs, "MinimumLevelCVerificationInputV1");
    assert!(!verification_input_block.contains("Deserialize"));
    for struct_name in [
        "AuthenticatedSignerReceiptV1",
        "MinimumLevelCEvidenceV1",
        "VerifiedMinimumLevelCEvidenceV1",
    ] {
        let block = extract_struct_block(&evidence_rs, struct_name);
        assert!(!block.contains("Deserialize"), "{struct_name}");
        assert!(
            !block.contains("\n    pub "),
            "{struct_name} must stay constructor/accessor-only"
        );
    }
    for impl_name in ["AuthenticatedSignerReceiptV1", "MinimumLevelCEvidenceV1"] {
        assert!(
            evidence_rs.contains(&format!("impl<'de> Deserialize<'de> for {impl_name}")),
            "{impl_name} must deserialize through its validating constructor"
        );
        assert!(
            evidence_rs.contains(&format!("impl {impl_name} {{"))
                && evidence_rs.contains("pub fn new("),
            "{impl_name} must expose a validating constructor"
        );
    }
    assert!(evidence_rs.contains("impl VerifiedMinimumLevelCEvidenceV1 {"));
    assert!(evidence_rs.contains("pub fn evidence(&self) -> &MinimumLevelCEvidenceV1"));

    let state_machine_rs = read_src_file("state_machine.rs");
    for struct_name in ["CreateRoleEnvelopesInput", "RoleEnvelopesCreated"] {
        let block = extract_struct_block(&state_machine_rs, struct_name);
        assert!(!block.contains("Deserialize"), "{struct_name}");
    }
}

#[test]
fn typed_context_and_transcript_use_validating_deserialize_impls() {
    let context_rs = read_src_file("context.rs");
    for struct_name in ["AccountScope", "DerivationContext"] {
        let block = extract_struct_block(&context_rs, struct_name);
        assert!(!block.contains("Deserialize"), "{struct_name}");
        assert!(
            !block.contains("\n    pub "),
            "{struct_name} must stay constructor/accessor-only"
        );
    }
    for impl_name in ["RootShareEpoch", "AccountScope", "DerivationContext"] {
        assert!(
            context_rs.contains(&format!("impl<'de> Deserialize<'de> for {impl_name}")),
            "{impl_name} must deserialize through its validating constructor"
        );
    }

    let transcript_rs = read_src_file("transcript.rs");
    for struct_name in [
        "IndexedSignerBinding",
        "SignerSetBinding",
        "TranscriptBinding",
    ] {
        let block = extract_struct_block(&transcript_rs, struct_name);
        assert!(!block.contains("Deserialize"), "{struct_name}");
        assert!(
            !block.contains("\n    pub "),
            "{struct_name} must stay constructor/accessor-only"
        );
    }
    for impl_name in [
        "IndexedSignerBinding",
        "SignerSetBinding",
        "TranscriptBinding",
    ] {
        assert!(
            transcript_rs.contains(&format!("impl<'de> Deserialize<'de> for {impl_name}")),
            "{impl_name} must deserialize through its validating constructor"
        );
    }
}

#[test]
fn router_ab_core_keeps_ed25519_hss_behind_dev_adapter_boundary() {
    let cargo_toml = read_manifest_file("Cargo.toml");
    for forbidden in ["ed25519-hss", "ed25519_hss"] {
        assert!(
            !cargo_toml.contains(forbidden),
            "router-ab-core must not depend on `{forbidden}`; use router-ab-dev for HSS parity"
        );
    }

    for relative_path in [
        "src/lib.rs",
        "src/protocol/local.rs",
        "src/protocol/output.rs",
    ] {
        let source = read_manifest_file(relative_path);
        assert!(
            !source.contains("ed25519_hss"),
            "{relative_path} must not import ed25519_hss"
        );
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
        "joined y_server",
        "joined_y_server",
        "joined tau_server",
        "joined_tau_server",
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
    for relative_path in ["src/protocol/public_request.rs"] {
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

#[test]
fn stale_mpc_candidate_placeholder_is_not_public_api() {
    let derivation_mod_rs = read_manifest_file("src/derivation/mod.rs");
    let public_candidate_export_block =
        extract_pub_use_block(&derivation_mod_rs, "candidate_mpc_prf");
    let candidate_mpc_prf_rs = read_src_file("candidate_mpc_prf.rs");

    assert!(!public_candidate_export_block.contains("evaluate_mpc_threshold_prf_candidate"));
    assert!(!public_candidate_export_block.contains("MpcPrfCandidateInput"));
    assert!(!public_candidate_export_block.contains("MpcPrfCandidateOutput"));
    assert!(!candidate_mpc_prf_rs.contains("pub fn evaluate_mpc_threshold_prf_candidate"));
    assert!(!candidate_mpc_prf_rs.contains("pub struct MpcPrfCandidateInput"));
    assert!(!candidate_mpc_prf_rs.contains("pub struct MpcPrfCandidateOutput"));
}

#[test]
fn split_root_candidate_api_is_removed_from_compiled_core() {
    let derivation_mod_rs = read_manifest_file("src/derivation/mod.rs");
    let split_root_module_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("derivation")
        .join("candidate_split_root.rs");

    assert!(!split_root_module_path.exists());
    assert!(!derivation_mod_rs.contains("mod candidate_split_root"));
    assert!(!derivation_mod_rs.contains("pub use self::candidate_split_root"));
    for forbidden in [
        "evaluate_split_root_candidate",
        "derive_split_root_output_share_v1",
        "combine_split_root_verified_output_shares_v1",
        "SplitRootCandidateInput",
        "SplitRootCandidateOutput",
        "SplitRootSecretShareV1",
        "SplitRootCombinedOutputV1",
    ] {
        assert!(
            !derivation_mod_rs.contains(forbidden),
            "split-root prototype API `{forbidden}` must stay out of public exports"
        );
    }
}

#[test]
fn local_simulation_does_not_open_joined_recipient_outputs_server_side() {
    let local_rs = read_manifest_file("src/protocol/local.rs");
    for forbidden in [
        "combine_mpc_prf_recipient_output_from_ab_proof_batches_v1",
        "combine_mpc_prf_recipient_output_from_proof_bundle_payloads_v1",
        "combine_mpc_prf_proof_bundles_with_threshold_backend_v1",
        "combine_mpc_prf_batch_outputs_with_threshold_backend_v1",
        "MpcPrfThresholdCombineInputV1",
        "MpcPrfThresholdCombinedOutputV1",
        "MpcPrfThresholdBatchCombineInputV1",
        "MpcPrfThresholdBatchCombinedOutputV1",
        "SplitRootCombinerInputV1",
        "SplitRootCombinedOutputV1",
        "SecretMaterial32",
        "output_material",
    ] {
        assert!(
            !local_rs.contains(forbidden),
            "local simulation must not open joined recipient output through `{forbidden}`"
        );
    }
}

#[test]
fn local_deriver_and_signing_worker_state_stay_role_separated() {
    let local_rs = read_manifest_file("src/protocol/local.rs");

    for struct_name in [
        "LocalDeriverAEndpointV1",
        "LocalDeriverAServiceV1",
        "LocalDeriverBEndpointV1",
        "LocalDeriverBServiceV1",
    ] {
        let block = extract_struct_block(&local_rs, struct_name);
        for forbidden in ["server_output_storage", "server: ServerIdentityV1"] {
            assert!(
                !block.contains(forbidden),
                "{struct_name} must not own SigningWorker state through `{forbidden}`"
            );
        }
    }

    let signing_worker_block = extract_struct_block(&local_rs, "LocalSigningWorkerServiceV1");
    for forbidden in [
        "signer: SignerIdentityV1",
        "MpcPrfSigningRootShareWireV1",
        "SIGNING_ROOT_SHARE_A_KEK",
        "SIGNING_ROOT_SHARE_B_KEK",
    ] {
        assert!(
            !signing_worker_block.contains(forbidden),
            "LocalSigningWorkerServiceV1 must not own deriver state through `{forbidden}`"
        );
    }
}

#[test]
fn local_signing_worker_activation_uses_public_activation_context() {
    let local_rs = read_manifest_file("src/protocol/local.rs");
    let activation_impl = extract_impl_block(
        &local_rs,
        "LocalSigningWorkerRecipientProofBundleActivationV1",
    );
    let signing_worker_activation_signature =
        extract_function_signature(&local_rs, "pub fn accept_recipient_proof_bundle_activation");

    assert!(activation_impl.contains("validate_for_activation_context"));
    assert!(!activation_impl.contains("validate_for_router_payload"));
    assert!(signing_worker_activation_signature.contains("SigningWorkerActivationContextV1"));
    assert!(!signing_worker_activation_signature.contains("RouterToSignerPayloadV1"));
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

fn extract_impl_block(source: &str, type_name: &str) -> String {
    let marker = format!("impl {type_name} {{");
    let start = source.find(&marker).expect("impl marker should exist");
    let mut depth = 0usize;
    let mut saw_open = false;

    for (offset, ch) in source[start..].char_indices() {
        match ch {
            '{' => {
                depth += 1;
                saw_open = true;
            }
            '}' => {
                depth = depth.checked_sub(1).expect("impl block depth underflow");
                if saw_open && depth == 0 {
                    return source[start..start + offset + ch.len_utf8()].to_owned();
                }
            }
            _ => {}
        }
    }
    panic!("impl block should end");
}

fn extract_function_signature(source: &str, function_name: &str) -> String {
    let start = source
        .find(function_name)
        .expect("function marker should exist");
    let end = source[start..]
        .find('{')
        .map(|offset| start + offset)
        .expect("function signature should end");
    source[start..end].to_owned()
}

fn extract_pub_use_block(source: &str, module_name: &str) -> String {
    let marker = format!("pub use self::{module_name}::{{");
    let start = source
        .find(&marker)
        .expect("pub use block marker should exist");
    let end = source[start..]
        .find("};")
        .map(|offset| start + offset + 2)
        .expect("pub use block should end");
    source[start..end].to_owned()
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
