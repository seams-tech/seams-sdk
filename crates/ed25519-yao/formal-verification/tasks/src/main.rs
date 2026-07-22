use std::collections::HashSet;
use std::env;
use std::fs;
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Output};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Deserialize;
use sha2::{Digest, Sha256};

mod phase2b_exit_evidence;
mod phase2b_protected_inputs;
mod phase2b_review_subject;

type DynError = Box<dyn std::error::Error>;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VerificationBaseline {
    verus: VerusPin,
    aeneas: SourcePin,
    charon: SourcePin,
    lean: LeanPin,
    python: PythonPin,
    constant_time: ConstantTimePin,
    extraction: ExtractionBaseline,
    evidence: EvidenceCounts,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConstantTimePin {
    repo: String,
    rev: String,
    uv_version: String,
    analyzer_sha256: String,
    uv_lock_sha256: String,
}

#[derive(Deserialize)]
struct ConstantTimeReport {
    total_functions: usize,
    total_instructions: usize,
    error_count: usize,
    warning_count: usize,
    passed: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VerusPin {
    release: String,
    vstd: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SourcePin {
    repo: String,
    rev: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanPin {
    toolchain: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PythonPin {
    minimum_major: usize,
    minimum_minor: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExtractionBaseline {
    #[serde(rename = "crate")]
    crate_path: String,
    functions: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceCounts {
    reference_spec_documents: usize,
    vector_cases: usize,
    kdf_vector_cases: usize,
    ceremony_context_vector_cases: usize,
    lifecycle_continuity_vector_cases: usize,
    provenance_vector_cases: usize,
    output_sharing_vector_cases: usize,
    semantic_lifecycle_vector_cases: usize,
    output_party_view_vector_cases: usize,
    activation_delivery_vector_cases: usize,
    activation_recipient_party_view_vector_cases: usize,
    evaluation_input_party_view_vector_cases: usize,
    uniform_abort_vector_cases: usize,
    evaluator_abort_view_vector_cases: usize,
    export_delivery_vector_cases: usize,
    recovery_credential_transition_vector_cases: usize,
    export_evaluator_authorization_vector_cases: usize,
    registration_evaluator_admission_vector_cases: usize,
    recovery_evaluator_admission_vector_cases: usize,
    refresh_evaluator_admission_vector_cases: usize,
    semantic_frame_party_view_vector_cases: usize,
    phase2b_reconciliation_vector_cases: usize,
    differential_vector_cases: usize,
    independent_verifier_tests: usize,
    ceremony_context_python_tests: usize,
    output_sharing_python_tests: usize,
    semantic_lifecycle_python_tests: usize,
    output_party_view_python_tests: usize,
    activation_delivery_python_tests: usize,
    activation_recipient_party_view_python_tests: usize,
    evaluation_input_party_view_python_tests: usize,
    uniform_abort_python_tests: usize,
    evaluator_abort_view_python_tests: usize,
    export_delivery_python_tests: usize,
    recovery_credential_transition_python_tests: usize,
    export_evaluator_authorization_python_tests: usize,
    registration_evaluator_admission_python_tests: usize,
    recovery_evaluator_admission_python_tests: usize,
    refresh_evaluator_admission_python_tests: usize,
    semantic_frame_party_view_python_tests: usize,
    phase2b_reconciliation_python_tests: usize,
    artifact_python_tests: usize,
    artifact_vector_cases: usize,
    production_rust_tests: usize,
    generator_rust_tests: usize,
    circuit_rust_tests: usize,
    artifact_bundle_rust_tests: usize,
    artifact_filesystem_policy_rust_tests: usize,
    joint_refresh_delta_rust_tests: usize,
    registration_reference_rust_tests: usize,
    recovery_reference_rust_tests: usize,
    refresh_reference_rust_tests: usize,
    export_reference_rust_tests: usize,
    output_sharing_core_rust_tests: usize,
    output_sharing_vector_rust_tests: usize,
    semantic_lifecycle_vector_rust_tests: usize,
    output_party_view_core_rust_tests: usize,
    output_party_view_guard_rust_tests: usize,
    output_party_view_vector_rust_tests: usize,
    activation_delivery_vector_rust_tests: usize,
    activation_recipient_party_view_core_rust_tests: usize,
    activation_recipient_party_view_guard_rust_tests: usize,
    activation_recipient_party_view_vector_rust_tests: usize,
    evaluation_input_party_view_core_rust_tests: usize,
    evaluation_input_party_view_guard_rust_tests: usize,
    evaluation_input_party_view_vector_rust_tests: usize,
    uniform_abort_vector_rust_tests: usize,
    evaluator_abort_view_vector_rust_tests: usize,
    export_delivery_core_rust_tests: usize,
    export_delivery_vector_rust_tests: usize,
    activation_delivery_core_rust_tests: usize,
    authenticated_store_rust_tests: usize,
    signing_worker_activation_rust_tests: usize,
    refresh_promotion_rust_tests: usize,
    recovery_credential_transition_rust_tests: usize,
    recovery_credential_transition_vector_rust_tests: usize,
    export_evaluator_authorization_rust_tests: usize,
    export_evaluator_authorization_vector_rust_tests: usize,
    registration_evaluator_admission_rust_tests: usize,
    registration_evaluator_admission_vector_rust_tests: usize,
    recovery_evaluator_admission_rust_tests: usize,
    recovery_evaluator_admission_vector_rust_tests: usize,
    refresh_evaluator_admission_rust_tests: usize,
    refresh_evaluator_admission_vector_rust_tests: usize,
    semantic_frame_core_rust_tests: usize,
    semantic_trace_boundary_rust_tests: usize,
    semantic_frame_party_view_vector_rust_tests: usize,
    phase2b_reconciliation_rust_tests: usize,
    phase2b_exit_evidence_rust_tests: usize,
    phase2b_review_subject_rust_tests: usize,
    phase2b_protected_inputs_rust_tests: usize,
    phase2b_exit_evidence_spec_sha256: String,
    benchmark_manifest_rust_tests: usize,
    benchmark_manifest_bytes: usize,
    benchmark_manifest_digest: String,
    benchmark_bundle_index_bytes: usize,
    benchmark_bundle_index_digest: String,
    anti_drift_tests: usize,
    verus_obligations: usize,
    lean_model_theorems: usize,
    aeneas_extracted_functions: usize,
}

struct ArtifactSnapshot {
    path: PathBuf,
    bytes: Vec<u8>,
}

struct TemporaryDirectory {
    path: PathBuf,
}

impl TemporaryDirectory {
    fn create(label: &str) -> Result<Self, DynError> {
        let temporary = Self::reserve(label)?;
        fs::create_dir(&temporary.path)?;
        #[cfg(unix)]
        fs::set_permissions(&temporary.path, fs::Permissions::from_mode(0o700))?;
        Ok(temporary)
    }

    fn reserve(label: &str) -> Result<Self, DynError> {
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let parent = repository_root().join("tools/ed25519-yao-generator/target");
        fs::create_dir_all(&parent)?;
        reject_symlink_path_components(&repository_root(), &parent)?;
        let canonical_root = fs::canonicalize(repository_root())?;
        let canonical_parent = fs::canonicalize(&parent)?;
        if !canonical_parent.starts_with(&canonical_root) {
            return Err("formal-verification temporary parent escapes the repository".into());
        }
        let path = parent.join(format!(
            "ed25519-yao-{label}-{}-{timestamp}",
            std::process::id()
        ));
        Ok(Self { path })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

fn reject_symlink_path_components(root: &Path, path: &Path) -> Result<(), DynError> {
    let relative = path.strip_prefix(root)?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        current.push(component);
        if fs::symlink_metadata(&current)?.file_type().is_symlink() {
            return Err(format!(
                "formal-verification temporary path contains symlink `{}`",
                current.display()
            )
            .into());
        }
    }
    Ok(())
}

impl Drop for TemporaryDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("Ed25519 Yao formal-verification task failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), DynError> {
    let task = env::args().nth(1).unwrap_or_else(|| "all".to_owned());
    match task.as_str() {
        "all" | "check" => run_all(),
        "reference-spec-check" => run_reference_spec_check(),
        "vectors-check" => run_vectors_check(),
        "cross-language-check" => run_cross_language_check(),
        "parity" => run_parity(),
        "anti-drift" => run_anti_drift(),
        "lean-check" => run_lean_check(),
        "aeneas-check" => run_aeneas_check(),
        "verus-check" => run_verus_check(),
        "constant-time-qualification" => run_constant_time_qualification(),
        "benchmark-manifest-reproducibility" => run_benchmark_manifest_reproducibility(),
        "phase2b-reconciliation-check" => run_phase2b_reconciliation_check(),
        "phase2b-exit-evidence-readiness-check" => {
            run_phase2b_exit_evidence_readiness_check()
        }
        "phase2b-review-subject-check" => run_phase2b_review_subject_check(),
        "phase2b-protected-inputs-check" => {
            println!("{}", phase2b_protected_inputs::run_protected_inputs_check()?);
            Ok(())
        }
        "phase2b-independent-host-prepare" => run_phase2b_independent_host_prepare(),
        "phase2b-independent-host-finalize" => run_phase2b_independent_host_finalize(),
        "phase2b-independent-host-record-check" => run_phase2b_independent_host_record_check(),
        "phase2b-review-approval-check" => run_phase2b_review_approval_check(),
        "__phase2b-review-subject-material-v1" => run_internal_phase2b_review_subject_material(),
        phase2b_review_subject::INTERNAL_REPRODUCTION_MATERIAL_COMMAND => {
            run_internal_phase2b_reproduction_material()
        }
        "help" | "--help" | "-h" => {
            print_help();
            Ok(())
        }
        unknown => Err(format!(
            "unknown task `{unknown}`; expected all, check, reference-spec-check, vectors-check, cross-language-check, parity, anti-drift, lean-check, aeneas-check, verus-check, constant-time-qualification, benchmark-manifest-reproducibility, phase2b-reconciliation-check, phase2b-exit-evidence-readiness-check, phase2b-review-subject-check, phase2b-protected-inputs-check, phase2b-independent-host-prepare, phase2b-independent-host-finalize, phase2b-independent-host-record-check, or phase2b-review-approval-check"
        )
        .into()),
    }
}

fn run_all() -> Result<(), DynError> {
    run_reference_spec_check()?;
    run_vectors_check()?;
    run_cross_language_check()?;
    run_phase2b_reconciliation_check()?;
    run_phase2b_exit_evidence_readiness_check()?;
    run_phase2b_review_subject_check()?;
    run_benchmark_manifest_reproducibility()?;
    run_parity()?;
    run_anti_drift()?;
    run_aeneas_check()?;
    run_lean_check()?;
    run_verus_check()?;
    println!("all ok: 12 nonempty Ed25519 Yao verification tracks executed");
    Ok(())
}

fn print_help() {
    println!(
        "usage: cargo yao-fv [all|check|reference-spec-check|vectors-check|cross-language-check|parity|anti-drift|lean-check|aeneas-check|verus-check|constant-time-qualification|benchmark-manifest-reproducibility|phase2b-reconciliation-check|phase2b-exit-evidence-readiness-check|phase2b-review-subject-check|phase2b-protected-inputs-check|phase2b-independent-host-prepare|phase2b-independent-host-finalize|phase2b-independent-host-record-check|phase2b-review-approval-check]"
    );
}

fn run_reference_spec_check() -> Result<(), DynError> {
    let baseline = load_baseline()?;
    let reference_specs = [
        generator_dir(&baseline).join("docs/fixed-reference-v1.md"),
        generator_dir(&baseline).join("docs/output-sharing-v1.md"),
        generator_dir(&baseline).join("docs/circuit-ir-v1.md"),
        generator_dir(&baseline).join("docs/ceremony-context-v1.md"),
        generator_dir(&baseline).join("docs/input-provenance-v1.md"),
        generator_dir(&baseline).join("docs/semantic-artifact-lifecycle-v1.md"),
        generator_dir(&baseline).join("docs/output-party-views-v1.md"),
        generator_dir(&baseline).join("docs/evaluation-input-party-views-v1.md"),
        generator_dir(&baseline).join("docs/uniform-abort-envelope-v1.md"),
        generator_dir(&baseline).join("docs/evaluator-abort-state-party-views-v1.md"),
        generator_dir(&baseline).join("docs/authenticated-store-resolution-v1.md"),
        generator_dir(&baseline).join("docs/signing-worker-activation-v1.md"),
        generator_dir(&baseline).join("docs/refresh-promotion-v1.md"),
        generator_dir(&baseline).join("docs/benchmark-manifest-v1.md"),
        generator_dir(&baseline).join("docs/artifact-filesystem-policy-v1.md"),
        generator_dir(&baseline).join("docs/joint-refresh-delta-v1.md"),
        generator_dir(&baseline).join("docs/export-delivery-lifecycle-v1.md"),
        generator_dir(&baseline).join("docs/activation-delivery-lifecycle-v1.md"),
        generator_dir(&baseline).join("docs/activation-recipient-party-views-v1.md"),
        generator_dir(&baseline).join("docs/recovery-credential-transition-v1.md"),
        generator_dir(&baseline).join("docs/export-evaluator-authorization-v1.md"),
        generator_dir(&baseline).join("docs/registration-evaluator-admission-v1.md"),
        generator_dir(&baseline).join("docs/recovery-evaluator-admission-v1.md"),
        generator_dir(&baseline).join("docs/refresh-evaluator-admission-v1.md"),
        generator_dir(&baseline).join("docs/semantic-frame-party-views-v1.md"),
        generator_dir(&baseline).join("docs/phase2b-core-reconciliation-v1.md"),
        formal_verification_dir().join("docs/phase2b-exit-evidence-v1.md"),
    ];
    require_exact_count(
        "fixed-reference specification document",
        reference_specs.len(),
        baseline.evidence.reference_spec_documents,
    )?;
    let reference_spec = &reference_specs[0];
    require_file(
        reference_spec,
        "versioned Ed25519 Yao fixed-reference specification",
    )?;
    require_file(
        &reference_specs[1],
        "versioned Ed25519 Yao output-sharing specification",
    )?;
    require_file(
        &reference_specs[2],
        "versioned Ed25519 Yao circuit-IR specification",
    )?;
    require_file(
        &reference_specs[3],
        "versioned Ed25519 Yao ceremony-context specification",
    )?;
    require_file(
        &reference_specs[4],
        "versioned Ed25519 Yao input-provenance specification",
    )?;
    require_file(
        &reference_specs[5],
        "versioned Ed25519 Yao semantic-artifact lifecycle specification",
    )?;
    require_file(
        &reference_specs[6],
        "versioned Ed25519 Yao output-party-view specification",
    )?;
    require_file(
        &reference_specs[7],
        "versioned Ed25519 Yao evaluation-input party-view specification",
    )?;
    require_file(
        &reference_specs[8],
        "versioned Ed25519 Yao uniform-abort envelope specification",
    )?;
    require_file(
        &reference_specs[9],
        "versioned Ed25519 Yao evaluator-abort state and party-view specification",
    )?;
    require_file(
        &reference_specs[10],
        "versioned Ed25519 Yao authenticated-store resolution specification",
    )?;
    require_file(
        &reference_specs[11],
        "versioned Ed25519 Yao SigningWorker activation specification",
    )?;
    require_file(
        &reference_specs[12],
        "versioned Ed25519 Yao authenticated refresh-promotion specification",
    )?;
    require_file(
        &reference_specs[13],
        "versioned Ed25519 Yao provisional benchmark-manifest specification",
    )?;
    require_file(
        &reference_specs[14],
        "versioned Ed25519 Yao artifact-filesystem policy specification",
    )?;
    require_file(
        &reference_specs[15],
        "versioned Ed25519 Yao ideal joint refresh-delta specification",
    )?;
    require_file(
        &reference_specs[16],
        "versioned Ed25519 Yao export-delivery lifecycle specification",
    )?;
    require_file(
        &reference_specs[17],
        "versioned Ed25519 Yao activation-delivery lifecycle specification",
    )?;
    require_file(
        &reference_specs[18],
        "versioned Ed25519 Yao activation-recipient party-view specification",
    )?;
    require_file(
        &reference_specs[19],
        "versioned Ed25519 Yao recovery credential-transition specification",
    )?;
    require_file(
        &reference_specs[20],
        "versioned Ed25519 Yao export evaluator-authorization specification",
    )?;
    require_file(
        &reference_specs[21],
        "versioned Ed25519 Yao registration evaluator-admission specification",
    )?;
    require_file(
        &reference_specs[22],
        "versioned Ed25519 Yao recovery evaluator-admission specification",
    )?;
    require_file(
        &reference_specs[23],
        "versioned Ed25519 Yao refresh evaluator-admission specification",
    )?;
    require_file(
        &reference_specs[24],
        "versioned Ed25519 Yao semantic-frame party-view specification",
    )?;
    require_file(
        &reference_specs[25],
        "versioned Ed25519 Yao Phase 2B core-reconciliation specification",
    )?;
    require_file(
        &reference_specs[26],
        "versioned Ed25519 Yao Phase 2B exit-evidence specification",
    )?;
    verify_sha256(
        &reference_specs[26],
        &baseline.evidence.phase2b_exit_evidence_spec_sha256,
        "Phase 2B exit-evidence specification",
    )?;

    let generator_manifest = generator_manifest(&baseline);
    let generator_manifest_string = path_string(&generator_manifest)?;
    let reference_spec_string = path_string(reference_spec)?;
    run_cargo_capture(
        &[
            "run",
            "--locked",
            "--manifest-path",
            generator_manifest_string,
            "--bin",
            "ed25519-yao-spec-goldens",
            "--",
            "check",
            "--input",
            reference_spec_string,
        ],
        "reference-spec-check generated golden drift",
    )?;

    let checked_paths = reference_specs
        .iter()
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    println!(
        "reference-spec-check ok: {} versioned reference specifications checked in {checked_paths}",
        reference_specs.len()
    );
    Ok(())
}

fn run_vectors_check() -> Result<(), DynError> {
    let baseline = load_baseline()?;
    let vector_file = generator_dir(&baseline).join("vectors/ed25519-yao-v1.json");
    let kdf_file = generator_dir(&baseline).join("vectors/ed25519-yao-kdf-v1.json");
    let ceremony_context_file =
        generator_dir(&baseline).join("vectors/ed25519-yao-ceremony-context-v1.json");
    let lifecycle_file =
        generator_dir(&baseline).join("vectors/ed25519-yao-lifecycle-continuity-v1.json");
    let provenance_file = generator_dir(&baseline).join("vectors/ed25519-yao-provenance-v1.json");
    let output_sharing_file =
        generator_dir(&baseline).join("vectors/ed25519-yao-output-sharing-v1.json");
    let semantic_lifecycle_file =
        generator_dir(&baseline).join("vectors/ed25519-yao-semantic-lifecycle-v1.json");
    let output_party_view_file =
        generator_dir(&baseline).join("vectors/ed25519-yao-output-party-views-v1.json");
    let activation_delivery_file =
        generator_dir(&baseline).join("vectors/ed25519-yao-activation-delivery-v1.json");
    let activation_recipient_party_view_file = generator_dir(&baseline)
        .join("vectors/ed25519-yao-activation-recipient-party-views-v1.json");
    let evaluation_input_party_view_file =
        generator_dir(&baseline).join("vectors/ed25519-yao-evaluation-input-party-views-v1.json");
    let uniform_abort_file =
        generator_dir(&baseline).join("vectors/ed25519-yao-uniform-abort-envelope-v1.json");
    let evaluator_abort_view_file = generator_dir(&baseline)
        .join("vectors/ed25519-yao-evaluator-abort-state-party-views-v1.json");
    let export_delivery_file =
        generator_dir(&baseline).join("vectors/ed25519-yao-export-delivery-v1.json");
    let recovery_credential_transition_file =
        generator_dir(&baseline).join("vectors/ed25519-yao-recovery-credential-transition-v1.json");
    let export_evaluator_authorization_file =
        generator_dir(&baseline).join("vectors/ed25519-yao-export-evaluator-authorization-v1.json");
    let registration_evaluator_admission_file = generator_dir(&baseline)
        .join("vectors/ed25519-yao-registration-evaluator-admission-v1.json");
    let recovery_evaluator_admission_file =
        generator_dir(&baseline).join("vectors/ed25519-yao-recovery-evaluator-admission-v1.json");
    let refresh_evaluator_admission_file =
        generator_dir(&baseline).join("vectors/ed25519-yao-refresh-evaluator-admission-v1.json");
    let semantic_frame_party_view_file =
        generator_dir(&baseline).join("vectors/ed25519-yao-semantic-frame-party-views-v1.json");
    let phase2b_reconciliation_file =
        generator_dir(&baseline).join("vectors/ed25519-yao-phase2b-core-reconciliation-v1.json");
    let generator_manifest = generator_manifest(&baseline);
    require_file(&vector_file, "committed Ed25519 Yao vector corpus")?;
    require_file(&kdf_file, "committed Ed25519 Yao KDF-continuity corpus")?;
    require_file(
        &ceremony_context_file,
        "committed Ed25519 Yao ceremony-context corpus",
    )?;
    require_file(
        &lifecycle_file,
        "committed Ed25519 Yao lifecycle-continuity corpus",
    )?;
    require_file(
        &provenance_file,
        "committed Ed25519 Yao provenance outer-contract corpus",
    )?;
    require_file(
        &output_sharing_file,
        "committed Ed25519 Yao output-sharing corpus",
    )?;
    require_file(
        &semantic_lifecycle_file,
        "committed Ed25519 Yao semantic-lifecycle corpus",
    )?;
    require_file(
        &output_party_view_file,
        "committed Ed25519 Yao output-party-view corpus",
    )?;
    require_file(
        &activation_delivery_file,
        "committed Ed25519 Yao activation-delivery corpus",
    )?;
    require_file(
        &activation_recipient_party_view_file,
        "committed Ed25519 Yao activation-recipient party-view corpus",
    )?;
    require_file(
        &evaluation_input_party_view_file,
        "committed Ed25519 Yao evaluation-input party-view corpus",
    )?;
    require_file(
        &uniform_abort_file,
        "committed Ed25519 Yao uniform-abort corpus",
    )?;
    require_file(
        &evaluator_abort_view_file,
        "committed Ed25519 Yao evaluator-abort state/party-view corpus",
    )?;
    require_file(
        &export_delivery_file,
        "committed Ed25519 Yao export-delivery corpus",
    )?;
    require_file(
        &recovery_credential_transition_file,
        "committed Ed25519 Yao recovery credential-transition corpus",
    )?;
    require_file(
        &export_evaluator_authorization_file,
        "committed Ed25519 Yao export evaluator-authorization corpus",
    )?;
    require_file(
        &registration_evaluator_admission_file,
        "committed Ed25519 Yao registration evaluator-admission corpus",
    )?;
    require_file(
        &recovery_evaluator_admission_file,
        "committed Ed25519 Yao recovery evaluator-admission corpus",
    )?;
    require_file(
        &refresh_evaluator_admission_file,
        "committed Ed25519 Yao refresh evaluator-admission corpus",
    )?;
    require_file(
        &semantic_frame_party_view_file,
        "committed Ed25519 Yao semantic-frame party-view corpus",
    )?;
    require_file(
        &phase2b_reconciliation_file,
        "committed Ed25519 Yao Phase 2B core-reconciliation corpus",
    )?;
    let generator_manifest_string = path_string(&generator_manifest)?;
    let vector_file_string = path_string(&vector_file)?;
    let output = run_cargo_capture(
        &[
            "run",
            "--locked",
            "--manifest-path",
            generator_manifest_string,
            "--bin",
            "ed25519-yao-vectors",
            "--",
            "check",
            "--input",
            vector_file_string,
        ],
        "vectors-check canonical corpus",
    )?;
    let expected_summary = format!("checked {} canonical cases", baseline.evidence.vector_cases);
    if !output.contains(&expected_summary) {
        return Err(format!(
            "vector command did not report expected nonzero case count `{expected_summary}`"
        )
        .into());
    }
    let kdf_file_string = path_string(&kdf_file)?;
    let kdf_output = run_cargo_capture(
        &[
            "run",
            "--locked",
            "--manifest-path",
            generator_manifest_string,
            "--bin",
            "ed25519-yao-vectors",
            "--",
            "check-kdf",
            "--input",
            kdf_file_string,
        ],
        "vectors-check KDF-continuity corpus",
    )?;
    let kdf_summary = format!(
        "checked {} KDF-continuity cases",
        baseline.evidence.kdf_vector_cases
    );
    if !kdf_output.contains(&kdf_summary) {
        return Err(format!(
            "KDF command did not report expected nonzero case count `{kdf_summary}`"
        )
        .into());
    }
    let ceremony_context_file_string = path_string(&ceremony_context_file)?;
    let ceremony_context_output = run_cargo_capture(
        &[
            "run",
            "--locked",
            "--manifest-path",
            generator_manifest_string,
            "--bin",
            "ed25519-yao-vectors",
            "--",
            "check-ceremony-context",
            "--input",
            ceremony_context_file_string,
        ],
        "vectors-check ceremony-context corpus",
    )?;
    let ceremony_context_summary = format!(
        "checked {} ceremony-context cases",
        baseline.evidence.ceremony_context_vector_cases
    );
    if !ceremony_context_output.contains(&ceremony_context_summary) {
        return Err(format!(
            "ceremony-context command did not report expected nonzero case count `{ceremony_context_summary}`"
        )
        .into());
    }
    let lifecycle_file_string = path_string(&lifecycle_file)?;
    let lifecycle_output = run_cargo_capture(
        &[
            "run",
            "--locked",
            "--manifest-path",
            generator_manifest_string,
            "--bin",
            "ed25519-yao-vectors",
            "--",
            "check-lifecycle-continuity",
            "--input",
            lifecycle_file_string,
        ],
        "vectors-check lifecycle-continuity corpus",
    )?;
    let lifecycle_summary = format!(
        "checked {} lifecycle-continuity cases",
        baseline.evidence.lifecycle_continuity_vector_cases
    );
    if !lifecycle_output.contains(&lifecycle_summary) {
        return Err(format!(
            "lifecycle command did not report expected nonzero case count `{lifecycle_summary}`"
        )
        .into());
    }
    let provenance_file_string = path_string(&provenance_file)?;
    let provenance_output = run_cargo_capture(
        &[
            "run",
            "--locked",
            "--manifest-path",
            generator_manifest_string,
            "--bin",
            "ed25519-yao-vectors",
            "--",
            "check-provenance",
            "--input",
            provenance_file_string,
        ],
        "vectors-check provenance outer-contract corpus",
    )?;
    let provenance_summary = format!(
        "checked {} provenance outer-contract cases",
        baseline.evidence.provenance_vector_cases
    );
    if !provenance_output.contains(&provenance_summary) {
        return Err(format!(
            "provenance command did not report expected nonzero case count `{provenance_summary}`"
        )
        .into());
    }
    let output_sharing_file_string = path_string(&output_sharing_file)?;
    let output_sharing_output = run_cargo_capture(
        &[
            "run",
            "--locked",
            "--manifest-path",
            generator_manifest_string,
            "--bin",
            "ed25519-yao-vectors",
            "--",
            "check-output-sharing",
            "--input",
            output_sharing_file_string,
        ],
        "vectors-check output-sharing corpus",
    )?;
    let output_sharing_summary = format!(
        "checked {} output-sharing cases",
        baseline.evidence.output_sharing_vector_cases
    );
    if !output_sharing_output.contains(&output_sharing_summary) {
        return Err(format!(
            "output-sharing command did not report expected nonzero case count `{output_sharing_summary}`"
        )
        .into());
    }
    let semantic_lifecycle_file_string = path_string(&semantic_lifecycle_file)?;
    let semantic_lifecycle_output = run_cargo_capture(
        &[
            "run",
            "--locked",
            "--manifest-path",
            generator_manifest_string,
            "--bin",
            "ed25519-yao-vectors",
            "--",
            "check-semantic-lifecycle",
            "--input",
            semantic_lifecycle_file_string,
        ],
        "vectors-check semantic-lifecycle corpus",
    )?;
    let semantic_lifecycle_summary = format!(
        "checked {} semantic-lifecycle cases",
        baseline.evidence.semantic_lifecycle_vector_cases
    );
    if !semantic_lifecycle_output.contains(&semantic_lifecycle_summary) {
        return Err(format!(
            "semantic-lifecycle command did not report expected nonzero case count `{semantic_lifecycle_summary}`"
        )
        .into());
    }
    let output_party_view_file_string = path_string(&output_party_view_file)?;
    let output_party_view_output = run_cargo_capture(
        &[
            "run",
            "--locked",
            "--manifest-path",
            generator_manifest_string,
            "--bin",
            "ed25519-yao-vectors",
            "--",
            "check-output-party-views",
            "--input",
            output_party_view_file_string,
        ],
        "vectors-check output-party-view corpus",
    )?;
    let output_party_view_summary = format!(
        "checked {} output-party-view cases",
        baseline.evidence.output_party_view_vector_cases
    );
    if !output_party_view_output.contains(&output_party_view_summary) {
        return Err(format!(
            "output-party-view command did not report expected nonzero case count `{output_party_view_summary}`"
        )
        .into());
    }
    let activation_delivery_file_string = path_string(&activation_delivery_file)?;
    let activation_delivery_output = run_cargo_capture(
        &[
            "run",
            "--locked",
            "--manifest-path",
            generator_manifest_string,
            "--bin",
            "ed25519-yao-vectors",
            "--",
            "check-activation-delivery",
            "--input",
            activation_delivery_file_string,
        ],
        "vectors-check activation-delivery corpus",
    )?;
    let activation_delivery_summary = format!(
        "checked {} activation-delivery cases",
        baseline.evidence.activation_delivery_vector_cases
    );
    if !activation_delivery_output.contains(&activation_delivery_summary) {
        return Err(format!(
            "activation-delivery command did not report expected nonzero case count `{activation_delivery_summary}`"
        )
        .into());
    }
    let activation_recipient_party_view_file_string =
        path_string(&activation_recipient_party_view_file)?;
    let activation_recipient_party_view_output = run_cargo_capture(
        &[
            "run",
            "--locked",
            "--manifest-path",
            generator_manifest_string,
            "--bin",
            "ed25519-yao-vectors",
            "--",
            "check-activation-recipient-party-views",
            "--input",
            activation_recipient_party_view_file_string,
        ],
        "vectors-check activation-recipient party-view corpus",
    )?;
    let activation_recipient_party_view_summary = format!(
        "checked {} activation recipient-party-view cases",
        baseline
            .evidence
            .activation_recipient_party_view_vector_cases
    );
    if !activation_recipient_party_view_output.contains(&activation_recipient_party_view_summary) {
        return Err(format!(
            "activation-recipient party-view command did not report expected nonzero case count `{activation_recipient_party_view_summary}`"
        )
        .into());
    }
    let evaluation_input_party_view_file_string = path_string(&evaluation_input_party_view_file)?;
    let evaluation_input_party_view_output = run_cargo_capture(
        &[
            "run",
            "--locked",
            "--manifest-path",
            generator_manifest_string,
            "--bin",
            "ed25519-yao-vectors",
            "--",
            "check-evaluation-input-party-views",
            "--input",
            evaluation_input_party_view_file_string,
        ],
        "vectors-check evaluation-input party-view corpus",
    )?;
    let evaluation_input_party_view_summary = format!(
        "checked {} evaluation-input party-view cases",
        baseline.evidence.evaluation_input_party_view_vector_cases
    );
    if !evaluation_input_party_view_output.contains(&evaluation_input_party_view_summary) {
        return Err(format!(
            "evaluation-input party-view command did not report expected nonzero case count `{evaluation_input_party_view_summary}`"
        )
        .into());
    }
    let uniform_abort_file_string = path_string(&uniform_abort_file)?;
    let uniform_abort_output = run_cargo_capture(
        &[
            "run",
            "--locked",
            "--manifest-path",
            generator_manifest_string,
            "--bin",
            "ed25519-yao-vectors",
            "--",
            "check-uniform-abort",
            "--input",
            uniform_abort_file_string,
        ],
        "vectors-check uniform-abort corpus",
    )?;
    let uniform_abort_summary = format!(
        "checked {} uniform-abort cases",
        baseline.evidence.uniform_abort_vector_cases
    );
    if !uniform_abort_output.contains(&uniform_abort_summary) {
        return Err(format!(
            "uniform-abort command did not report expected nonzero case count `{uniform_abort_summary}`"
        )
        .into());
    }
    let evaluator_abort_view_file_string = path_string(&evaluator_abort_view_file)?;
    let evaluator_abort_view_output = run_cargo_capture(
        &[
            "run",
            "--locked",
            "--manifest-path",
            generator_manifest_string,
            "--bin",
            "ed25519-yao-vectors",
            "--",
            "check-evaluator-abort-views",
            "--input",
            evaluator_abort_view_file_string,
        ],
        "vectors-check evaluator-abort state/party-view corpus",
    )?;
    let evaluator_abort_view_summary = format!(
        "checked {} evaluator-abort state/party-view cases",
        baseline.evidence.evaluator_abort_view_vector_cases
    );
    if !evaluator_abort_view_output.contains(&evaluator_abort_view_summary) {
        return Err(format!(
            "evaluator-abort-view command did not report expected nonzero case count `{evaluator_abort_view_summary}`"
        )
        .into());
    }
    let export_delivery_file_string = path_string(&export_delivery_file)?;
    let export_delivery_output = run_cargo_capture(
        &[
            "run",
            "--locked",
            "--manifest-path",
            generator_manifest_string,
            "--bin",
            "ed25519-yao-vectors",
            "--",
            "check-export-delivery",
            "--input",
            export_delivery_file_string,
        ],
        "vectors-check export-delivery corpus",
    )?;
    let export_delivery_summary = format!(
        "checked {} export-delivery cases",
        baseline.evidence.export_delivery_vector_cases
    );
    if !export_delivery_output.contains(&export_delivery_summary) {
        return Err(format!(
            "export-delivery command did not report expected nonzero case count `{export_delivery_summary}`"
        )
        .into());
    }
    let recovery_credential_transition_file_string =
        path_string(&recovery_credential_transition_file)?;
    let recovery_credential_transition_output = run_cargo_capture(
        &[
            "run",
            "--locked",
            "--manifest-path",
            generator_manifest_string,
            "--bin",
            "ed25519-yao-vectors",
            "--",
            "check-recovery-credential-transition",
            "--input",
            recovery_credential_transition_file_string,
        ],
        "vectors-check recovery credential-transition corpus",
    )?;
    let recovery_credential_transition_summary = format!(
        "checked {} recovery credential-transition cases",
        baseline
            .evidence
            .recovery_credential_transition_vector_cases
    );
    if !recovery_credential_transition_output.contains(&recovery_credential_transition_summary) {
        return Err(format!(
            "recovery credential-transition command did not report expected nonzero case count `{recovery_credential_transition_summary}`"
        )
        .into());
    }
    let export_evaluator_authorization_file_string =
        path_string(&export_evaluator_authorization_file)?;
    let export_evaluator_authorization_output = run_cargo_capture(
        &[
            "run",
            "--locked",
            "--manifest-path",
            generator_manifest_string,
            "--bin",
            "ed25519-yao-vectors",
            "--",
            "check-export-evaluator-authorization",
            "--input",
            export_evaluator_authorization_file_string,
        ],
        "vectors-check export evaluator-authorization corpus",
    )?;
    let export_evaluator_authorization_summary = format!(
        "checked {} export evaluator-authorization cases",
        baseline
            .evidence
            .export_evaluator_authorization_vector_cases
    );
    if !export_evaluator_authorization_output.contains(&export_evaluator_authorization_summary) {
        return Err(format!(
            "export evaluator-authorization command did not report expected nonzero case count `{export_evaluator_authorization_summary}`"
        )
        .into());
    }
    let registration_evaluator_admission_file_string =
        path_string(&registration_evaluator_admission_file)?;
    let registration_evaluator_admission_output = run_cargo_capture(
        &[
            "run",
            "--locked",
            "--manifest-path",
            generator_manifest_string,
            "--bin",
            "ed25519-yao-vectors",
            "--",
            "check-registration-evaluator-admission",
            "--input",
            registration_evaluator_admission_file_string,
        ],
        "vectors-check registration evaluator-admission corpus",
    )?;
    let registration_evaluator_admission_summary = format!(
        "checked {} registration evaluator-admission cases",
        baseline
            .evidence
            .registration_evaluator_admission_vector_cases
    );
    if !registration_evaluator_admission_output.contains(&registration_evaluator_admission_summary)
    {
        return Err(format!(
            "registration evaluator-admission command did not report expected nonzero case count `{registration_evaluator_admission_summary}`"
        )
        .into());
    }
    let recovery_evaluator_admission_file_string = path_string(&recovery_evaluator_admission_file)?;
    let recovery_evaluator_admission_output = run_cargo_capture(
        &[
            "run",
            "--locked",
            "--manifest-path",
            generator_manifest_string,
            "--bin",
            "ed25519-yao-vectors",
            "--",
            "check-recovery-evaluator-admission",
            "--input",
            recovery_evaluator_admission_file_string,
        ],
        "vectors-check recovery evaluator-admission corpus",
    )?;
    let recovery_evaluator_admission_summary = format!(
        "checked {} recovery evaluator-admission cases",
        baseline.evidence.recovery_evaluator_admission_vector_cases
    );
    if !recovery_evaluator_admission_output.contains(&recovery_evaluator_admission_summary) {
        return Err(format!(
            "recovery evaluator-admission command did not report expected nonzero case count `{recovery_evaluator_admission_summary}`"
        )
        .into());
    }
    let refresh_evaluator_admission_file_string = path_string(&refresh_evaluator_admission_file)?;
    let refresh_evaluator_admission_output = run_cargo_capture(
        &[
            "run",
            "--locked",
            "--manifest-path",
            generator_manifest_string,
            "--bin",
            "ed25519-yao-vectors",
            "--",
            "check-refresh-evaluator-admission",
            "--input",
            refresh_evaluator_admission_file_string,
        ],
        "vectors-check refresh evaluator-admission corpus",
    )?;
    let refresh_evaluator_admission_summary = format!(
        "checked {} refresh evaluator-admission cases",
        baseline.evidence.refresh_evaluator_admission_vector_cases
    );
    if !refresh_evaluator_admission_output.contains(&refresh_evaluator_admission_summary) {
        return Err(format!(
            "refresh evaluator-admission command did not report expected nonzero case count `{refresh_evaluator_admission_summary}`"
        )
        .into());
    }
    let semantic_frame_party_view_file_string = path_string(&semantic_frame_party_view_file)?;
    let semantic_frame_party_view_output = run_cargo_capture(
        &[
            "run",
            "--locked",
            "--manifest-path",
            generator_manifest_string,
            "--bin",
            "ed25519-yao-vectors",
            "--",
            "check-semantic-frame-party-views",
            "--input",
            semantic_frame_party_view_file_string,
        ],
        "vectors-check semantic-frame party-view corpus",
    )?;
    let semantic_frame_party_view_summary = format!(
        "checked {} semantic-frame party-view cases",
        baseline.evidence.semantic_frame_party_view_vector_cases
    );
    if !semantic_frame_party_view_output.contains(&semantic_frame_party_view_summary) {
        return Err(format!(
            "semantic-frame party-view command did not report expected nonzero case count `{semantic_frame_party_view_summary}`"
        )
        .into());
    }
    let phase2b_reconciliation_file_string = path_string(&phase2b_reconciliation_file)?;
    let phase2b_reconciliation_output = run_cargo_capture(
        &[
            "run",
            "--locked",
            "--manifest-path",
            generator_manifest_string,
            "--bin",
            "ed25519-yao-vectors",
            "--",
            "check-phase2b-core-reconciliation",
            "--input",
            phase2b_reconciliation_file_string,
        ],
        "vectors-check Phase 2B core-reconciliation corpus",
    )?;
    let phase2b_reconciliation_summary = format!(
        "checked {} Phase 2B core-reconciliation cases",
        baseline.evidence.phase2b_reconciliation_vector_cases
    );
    if !phase2b_reconciliation_output.contains(&phase2b_reconciliation_summary) {
        return Err(format!(
            "Phase 2B core-reconciliation command did not report expected nonzero case count `{phase2b_reconciliation_summary}`"
        )
        .into());
    }
    println!(
        "vectors-check ok: {} canonical cases in {}; {} KDF-continuity cases in {}; {} ceremony-context cases in {}; {} lifecycle-continuity cases in {}; {} provenance outer-contract cases in {}; {} output-sharing cases in {}; {} semantic-lifecycle cases in {}; {} output-party-view cases in {}; {} activation-delivery cases in {}; {} activation-recipient party-view cases in {}; {} evaluation-input party-view cases in {}; {} uniform-abort cases in {}; {} evaluator-abort state/party-view cases in {}; {} export-delivery cases in {}; {} recovery credential-transition cases in {}",
        baseline.evidence.vector_cases,
        vector_file.display(),
        baseline.evidence.kdf_vector_cases,
        kdf_file.display(),
        baseline.evidence.ceremony_context_vector_cases,
        ceremony_context_file.display(),
        baseline.evidence.lifecycle_continuity_vector_cases,
        lifecycle_file.display(),
        baseline.evidence.provenance_vector_cases,
        provenance_file.display(),
        baseline.evidence.output_sharing_vector_cases,
        output_sharing_file.display(),
        baseline.evidence.semantic_lifecycle_vector_cases,
        semantic_lifecycle_file.display(),
        baseline.evidence.output_party_view_vector_cases,
        output_party_view_file.display(),
        baseline.evidence.activation_delivery_vector_cases,
        activation_delivery_file.display(),
        baseline
            .evidence
            .activation_recipient_party_view_vector_cases,
        activation_recipient_party_view_file.display(),
        baseline.evidence.evaluation_input_party_view_vector_cases,
        evaluation_input_party_view_file.display(),
        baseline.evidence.uniform_abort_vector_cases,
        uniform_abort_file.display(),
        baseline.evidence.evaluator_abort_view_vector_cases,
        evaluator_abort_view_file.display(),
        baseline.evidence.export_delivery_vector_cases,
        export_delivery_file.display(),
        baseline
            .evidence
            .recovery_credential_transition_vector_cases,
        recovery_credential_transition_file.display()
    );
    println!(
        "vectors-check export evaluator-authorization: {} cases in {}",
        baseline
            .evidence
            .export_evaluator_authorization_vector_cases,
        export_evaluator_authorization_file.display()
    );
    println!(
        "vectors-check registration evaluator-admission: {} cases in {}",
        baseline
            .evidence
            .registration_evaluator_admission_vector_cases,
        registration_evaluator_admission_file.display()
    );
    println!(
        "vectors-check recovery evaluator-admission: {} cases in {}",
        baseline.evidence.recovery_evaluator_admission_vector_cases,
        recovery_evaluator_admission_file.display()
    );
    println!(
        "vectors-check refresh evaluator-admission: {} cases in {}",
        baseline.evidence.refresh_evaluator_admission_vector_cases,
        refresh_evaluator_admission_file.display()
    );
    println!(
        "vectors-check semantic-frame party views: {} cases in {}",
        baseline.evidence.semantic_frame_party_view_vector_cases,
        semantic_frame_party_view_file.display()
    );
    println!(
        "vectors-check Phase 2B core reconciliation: {} cases in {}",
        baseline.evidence.phase2b_reconciliation_vector_cases,
        phase2b_reconciliation_file.display()
    );
    Ok(())
}

fn run_cross_language_check() -> Result<(), DynError> {
    const DIFFERENTIAL_SEED_HEX: &str =
        "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a";

    let baseline = load_baseline()?;
    let python = resolve_program("python3", "install the pinned minimum Python version")?;
    verify_python_version(&python, &baseline.python)?;

    let verifier_dir = independent_verifier_dir();
    let verifier = verifier_dir.join("verify_vectors.py");
    let verifier_tests = verifier_dir.join("test_verify_vectors.py");
    let artifact_verifier = verifier_dir.join("verify_artifacts.py");
    let artifact_verifier_tests = verifier_dir.join("test_verify_artifacts.py");
    let committed_corpus = generator_dir(&baseline).join("vectors/ed25519-yao-v1.json");
    let kdf_corpus = generator_dir(&baseline).join("vectors/ed25519-yao-kdf-v1.json");
    let ceremony_context_corpus =
        generator_dir(&baseline).join("vectors/ed25519-yao-ceremony-context-v1.json");
    let lifecycle_corpus =
        generator_dir(&baseline).join("vectors/ed25519-yao-lifecycle-continuity-v1.json");
    let provenance_corpus = generator_dir(&baseline).join("vectors/ed25519-yao-provenance-v1.json");
    let output_sharing_corpus =
        generator_dir(&baseline).join("vectors/ed25519-yao-output-sharing-v1.json");
    let semantic_lifecycle_corpus =
        generator_dir(&baseline).join("vectors/ed25519-yao-semantic-lifecycle-v1.json");
    let output_party_view_corpus =
        generator_dir(&baseline).join("vectors/ed25519-yao-output-party-views-v1.json");
    let activation_delivery_corpus =
        generator_dir(&baseline).join("vectors/ed25519-yao-activation-delivery-v1.json");
    let activation_recipient_party_view_corpus = generator_dir(&baseline)
        .join("vectors/ed25519-yao-activation-recipient-party-views-v1.json");
    let evaluation_input_party_view_corpus =
        generator_dir(&baseline).join("vectors/ed25519-yao-evaluation-input-party-views-v1.json");
    let uniform_abort_corpus =
        generator_dir(&baseline).join("vectors/ed25519-yao-uniform-abort-envelope-v1.json");
    let evaluator_abort_view_corpus = generator_dir(&baseline)
        .join("vectors/ed25519-yao-evaluator-abort-state-party-views-v1.json");
    let export_delivery_corpus =
        generator_dir(&baseline).join("vectors/ed25519-yao-export-delivery-v1.json");
    let recovery_credential_transition_corpus =
        generator_dir(&baseline).join("vectors/ed25519-yao-recovery-credential-transition-v1.json");
    let export_evaluator_authorization_corpus =
        generator_dir(&baseline).join("vectors/ed25519-yao-export-evaluator-authorization-v1.json");
    let registration_evaluator_admission_corpus = generator_dir(&baseline)
        .join("vectors/ed25519-yao-registration-evaluator-admission-v1.json");
    let recovery_evaluator_admission_corpus =
        generator_dir(&baseline).join("vectors/ed25519-yao-recovery-evaluator-admission-v1.json");
    let refresh_evaluator_admission_corpus =
        generator_dir(&baseline).join("vectors/ed25519-yao-refresh-evaluator-admission-v1.json");
    let semantic_frame_party_view_corpus =
        generator_dir(&baseline).join("vectors/ed25519-yao-semantic-frame-party-views-v1.json");
    require_file(&verifier, "independent Python vector verifier")?;
    require_file(&verifier_tests, "independent Python vector verifier tests")?;
    require_file(&artifact_verifier, "independent Python artifact verifier")?;
    require_file(
        &artifact_verifier_tests,
        "independent Python artifact verifier tests",
    )?;
    require_file(&committed_corpus, "committed Ed25519 Yao vector corpus")?;
    require_file(&kdf_corpus, "committed Ed25519 Yao KDF continuity corpus")?;
    require_file(
        &ceremony_context_corpus,
        "committed Ed25519 Yao ceremony-context corpus",
    )?;
    require_file(
        &lifecycle_corpus,
        "committed Ed25519 Yao lifecycle-continuity corpus",
    )?;
    require_file(
        &provenance_corpus,
        "committed Ed25519 Yao provenance outer-contract corpus",
    )?;
    require_file(
        &output_sharing_corpus,
        "committed Ed25519 Yao output-sharing corpus",
    )?;
    require_file(
        &semantic_lifecycle_corpus,
        "committed Ed25519 Yao semantic-lifecycle corpus",
    )?;
    require_file(
        &output_party_view_corpus,
        "committed Ed25519 Yao output-party-view corpus",
    )?;
    require_file(
        &activation_delivery_corpus,
        "committed Ed25519 Yao activation-delivery corpus",
    )?;
    require_file(
        &activation_recipient_party_view_corpus,
        "committed Ed25519 Yao activation-recipient party-view corpus",
    )?;
    require_file(
        &evaluation_input_party_view_corpus,
        "committed Ed25519 Yao evaluation-input party-view corpus",
    )?;
    require_file(
        &uniform_abort_corpus,
        "committed Ed25519 Yao uniform-abort corpus",
    )?;
    require_file(
        &evaluator_abort_view_corpus,
        "committed Ed25519 Yao evaluator-abort state/party-view corpus",
    )?;
    require_file(
        &export_delivery_corpus,
        "committed Ed25519 Yao export-delivery corpus",
    )?;
    require_file(
        &recovery_credential_transition_corpus,
        "committed Ed25519 Yao recovery credential-transition corpus",
    )?;
    require_file(
        &export_evaluator_authorization_corpus,
        "committed Ed25519 Yao export evaluator-authorization corpus",
    )?;
    require_file(
        &registration_evaluator_admission_corpus,
        "committed Ed25519 Yao registration evaluator-admission corpus",
    )?;
    require_file(
        &recovery_evaluator_admission_corpus,
        "committed Ed25519 Yao recovery evaluator-admission corpus",
    )?;
    require_file(
        &refresh_evaluator_admission_corpus,
        "committed Ed25519 Yao refresh evaluator-admission corpus",
    )?;
    require_file(
        &semantic_frame_party_view_corpus,
        "committed Ed25519 Yao semantic-frame party-view corpus",
    )?;

    let generator_manifest = generator_manifest(&baseline);
    let generator_manifest_string = path_string(&generator_manifest)?;
    let artifact_temporary = TemporaryDirectory::reserve("phase2a-artifacts")?;
    let artifact_directory_string = path_string(artifact_temporary.path())?;
    run_cargo_capture(
        &[
            "run",
            "--locked",
            "--manifest-path",
            generator_manifest_string,
            "--bin",
            "ed25519-yao-circuit-artifacts",
            "--",
            "emit",
            "--output-dir",
            artifact_directory_string,
        ],
        "cross-language-check Phase 2A artifact generation",
    )?;

    let mut unit_command = Command::new(&python);
    unit_command
        .args(["-m", "unittest", "discover", "-s"])
        .arg(&verifier_dir)
        .args(["-p", "test_*.py"])
        .env("ED25519_YAO_ARTIFACT_DIR", artifact_temporary.path());
    let unit_output = capture_command(
        &mut unit_command,
        "cross-language-check Python mutation suite",
        true,
    )?;
    let verifier_test_count = parse_python_test_count(&unit_output)?;
    require_exact_count(
        "independent verifier test",
        verifier_test_count,
        baseline.evidence.independent_verifier_tests,
    )?;
    let output_sharing_python_test_count =
        count_prefixed_python_tests(&verifier_tests, "def test_output_sharing_")?;
    require_exact_count(
        "output-sharing independent verifier test",
        output_sharing_python_test_count,
        baseline.evidence.output_sharing_python_tests,
    )?;
    let ceremony_context_python_test_count =
        count_prefixed_python_tests(&verifier_tests, "def test_ceremony_context_")?;
    require_exact_count(
        "ceremony-context independent verifier test",
        ceremony_context_python_test_count,
        baseline.evidence.ceremony_context_python_tests,
    )?;
    let semantic_lifecycle_python_test_count =
        count_prefixed_python_tests(&verifier_tests, "def test_semantic_lifecycle_")?;
    require_exact_count(
        "semantic-lifecycle independent verifier test",
        semantic_lifecycle_python_test_count,
        baseline.evidence.semantic_lifecycle_python_tests,
    )?;
    let output_party_view_python_test_count =
        count_prefixed_python_tests(&verifier_tests, "def test_output_party_views_")?;
    require_exact_count(
        "output-party-view independent verifier test",
        output_party_view_python_test_count,
        baseline.evidence.output_party_view_python_tests,
    )?;
    let activation_delivery_python_test_count =
        count_prefixed_python_tests(&verifier_tests, "def test_activation_delivery_")?;
    require_exact_count(
        "activation-delivery independent verifier test",
        activation_delivery_python_test_count,
        baseline.evidence.activation_delivery_python_tests,
    )?;
    let activation_recipient_party_view_python_test_count = count_prefixed_python_tests(
        &verifier_tests,
        "def test_activation_recipient_party_views_",
    )?;
    require_exact_count(
        "activation-recipient party-view independent verifier test",
        activation_recipient_party_view_python_test_count,
        baseline
            .evidence
            .activation_recipient_party_view_python_tests,
    )?;
    let evaluation_input_party_view_python_test_count =
        count_prefixed_python_tests(&verifier_tests, "def test_evaluation_input_party_views_")?;
    require_exact_count(
        "evaluation-input party-view independent verifier test",
        evaluation_input_party_view_python_test_count,
        baseline.evidence.evaluation_input_party_view_python_tests,
    )?;
    let uniform_abort_python_test_count =
        count_prefixed_python_tests(&verifier_tests, "def test_uniform_abort_")?;
    require_exact_count(
        "uniform-abort independent verifier test",
        uniform_abort_python_test_count,
        baseline.evidence.uniform_abort_python_tests,
    )?;
    let evaluator_abort_view_python_test_count =
        count_prefixed_python_tests(&verifier_tests, "def test_evaluator_abort_views_")?;
    require_exact_count(
        "evaluator-abort-view independent verifier test",
        evaluator_abort_view_python_test_count,
        baseline.evidence.evaluator_abort_view_python_tests,
    )?;
    let export_delivery_python_test_count =
        count_prefixed_python_tests(&verifier_tests, "def test_export_delivery_")?;
    require_exact_count(
        "export-delivery independent verifier test",
        export_delivery_python_test_count,
        baseline.evidence.export_delivery_python_tests,
    )?;
    let recovery_credential_transition_python_test_count =
        count_prefixed_python_tests(&verifier_tests, "def test_recovery_transition_")?;
    require_exact_count(
        "recovery credential-transition independent verifier test",
        recovery_credential_transition_python_test_count,
        baseline
            .evidence
            .recovery_credential_transition_python_tests,
    )?;
    let export_evaluator_authorization_python_test_count =
        count_prefixed_python_tests(&verifier_tests, "def test_export_evaluator_authorization_")?;
    require_exact_count(
        "export evaluator-authorization independent verifier test",
        export_evaluator_authorization_python_test_count,
        baseline
            .evidence
            .export_evaluator_authorization_python_tests,
    )?;
    let registration_evaluator_admission_python_test_count = count_prefixed_python_tests(
        &verifier_tests,
        "def test_registration_evaluator_admission_",
    )?;
    require_exact_count(
        "registration evaluator-admission independent verifier test",
        registration_evaluator_admission_python_test_count,
        baseline
            .evidence
            .registration_evaluator_admission_python_tests,
    )?;
    let recovery_evaluator_admission_python_test_count =
        count_prefixed_python_tests(&verifier_tests, "def test_recovery_evaluator_admission_")?;
    require_exact_count(
        "recovery evaluator-admission independent verifier test",
        recovery_evaluator_admission_python_test_count,
        baseline.evidence.recovery_evaluator_admission_python_tests,
    )?;
    let refresh_evaluator_admission_python_test_count =
        count_prefixed_python_tests(&verifier_tests, "def test_refresh_evaluator_admission_")?;
    require_exact_count(
        "refresh evaluator-admission independent verifier test",
        refresh_evaluator_admission_python_test_count,
        baseline.evidence.refresh_evaluator_admission_python_tests,
    )?;
    let semantic_frame_party_view_python_test_count =
        count_prefixed_python_tests(&verifier_tests, "def test_semantic_frame_party_views_")?;
    require_exact_count(
        "semantic-frame party-view independent verifier test",
        semantic_frame_party_view_python_test_count,
        baseline.evidence.semantic_frame_party_view_python_tests,
    )?;
    let phase2b_reconciliation_python_test_count = count_prefixed_python_tests(
        &artifact_verifier_tests,
        "def test_artifact_phase2b_reconciliation_",
    )?;
    require_exact_count(
        "Phase 2B reconciliation independent verifier test",
        phase2b_reconciliation_python_test_count,
        baseline.evidence.phase2b_reconciliation_python_tests,
    )?;
    let artifact_python_test_count =
        count_prefixed_python_tests(&artifact_verifier_tests, "def test_artifact_")?;
    require_exact_count(
        "artifact independent verifier test",
        artifact_python_test_count,
        baseline.evidence.artifact_python_tests,
    )?;

    let artifact_output = capture_command(
        Command::new(&python)
            .arg(&artifact_verifier)
            .arg(artifact_temporary.path())
            .arg(&committed_corpus),
        "cross-language-check Phase 2A artifacts",
        true,
    )?;
    let artifact_summary = format!(
        "verified {} independent Phase 2A artifact vector cases",
        baseline.evidence.artifact_vector_cases
    );
    if !artifact_output.contains(&artifact_summary) {
        return Err(
            format!("artifact verifier output did not contain `{artifact_summary}`").into(),
        );
    }

    let committed_output = capture_command(
        Command::new(&python).arg(&verifier).arg(&committed_corpus),
        "cross-language-check committed corpus",
        true,
    )?;
    require_reported_case_count(
        &committed_output,
        baseline.evidence.vector_cases,
        "committed independent vector",
    )?;

    let kdf_output = capture_command(
        Command::new(&python).arg(&verifier).arg(&kdf_corpus),
        "cross-language-check KDF continuity corpus",
        true,
    )?;
    require_reported_case_count(
        &kdf_output,
        baseline.evidence.kdf_vector_cases,
        "KDF continuity vector",
    )?;

    let ceremony_context_output = capture_command(
        Command::new(&python)
            .arg(&verifier)
            .arg(&ceremony_context_corpus),
        "cross-language-check ceremony-context corpus",
        true,
    )?;
    require_reported_case_count(
        &ceremony_context_output,
        baseline.evidence.ceremony_context_vector_cases,
        "ceremony-context vector",
    )?;

    let lifecycle_output = capture_command(
        Command::new(&python).arg(&verifier).arg(&lifecycle_corpus),
        "cross-language-check lifecycle-continuity corpus",
        true,
    )?;
    require_reported_case_count(
        &lifecycle_output,
        baseline.evidence.lifecycle_continuity_vector_cases,
        "lifecycle-continuity vector",
    )?;

    let provenance_output = capture_command(
        Command::new(&python)
            .arg(&verifier)
            .arg(&provenance_corpus)
            .arg("--ceremony-context-corpus")
            .arg(&ceremony_context_corpus),
        "cross-language-check provenance outer-contract corpus",
        true,
    )?;
    require_reported_case_count(
        &provenance_output,
        baseline.evidence.provenance_vector_cases,
        "provenance outer-contract vector",
    )?;

    let output_sharing_output = capture_command(
        Command::new(&python)
            .arg(&verifier)
            .arg(&output_sharing_corpus),
        "cross-language-check output-sharing corpus",
        true,
    )?;
    require_reported_case_count(
        &output_sharing_output,
        baseline.evidence.output_sharing_vector_cases,
        "output-sharing vector",
    )?;

    let semantic_lifecycle_output = capture_command(
        Command::new(&python)
            .arg(&verifier)
            .arg(&semantic_lifecycle_corpus)
            .arg("--ceremony-context-corpus")
            .arg(&ceremony_context_corpus)
            .arg("--provenance-corpus")
            .arg(&provenance_corpus),
        "cross-language-check semantic-lifecycle corpus",
        true,
    )?;
    require_reported_case_count(
        &semantic_lifecycle_output,
        baseline.evidence.semantic_lifecycle_vector_cases,
        "semantic-lifecycle vector",
    )?;

    let output_party_view_output = capture_command(
        Command::new(&python)
            .arg(&verifier)
            .arg(&output_party_view_corpus)
            .arg("--semantic-lifecycle-corpus")
            .arg(&semantic_lifecycle_corpus)
            .arg("--ceremony-context-corpus")
            .arg(&ceremony_context_corpus)
            .arg("--provenance-corpus")
            .arg(&provenance_corpus),
        "cross-language-check output-party-view corpus",
        true,
    )?;
    require_reported_case_count(
        &output_party_view_output,
        baseline.evidence.output_party_view_vector_cases,
        "output-party-view vector",
    )?;

    let activation_delivery_output = capture_command(
        Command::new(&python)
            .arg(&verifier)
            .arg(&activation_delivery_corpus)
            .arg("--ceremony-context-corpus")
            .arg(&ceremony_context_corpus)
            .arg("--provenance-corpus")
            .arg(&provenance_corpus)
            .arg("--semantic-lifecycle-corpus")
            .arg(&semantic_lifecycle_corpus)
            .arg("--output-party-view-corpus")
            .arg(&output_party_view_corpus),
        "cross-language-check activation-delivery corpus",
        true,
    )?;
    require_reported_case_count(
        &activation_delivery_output,
        baseline.evidence.activation_delivery_vector_cases,
        "activation-delivery vector",
    )?;

    let activation_recipient_party_view_output = capture_command(
        Command::new(&python)
            .arg(&verifier)
            .arg(&activation_recipient_party_view_corpus)
            .arg("--ceremony-context-corpus")
            .arg(&ceremony_context_corpus)
            .arg("--provenance-corpus")
            .arg(&provenance_corpus)
            .arg("--semantic-lifecycle-corpus")
            .arg(&semantic_lifecycle_corpus)
            .arg("--output-party-view-corpus")
            .arg(&output_party_view_corpus)
            .arg("--activation-delivery-corpus")
            .arg(&activation_delivery_corpus),
        "cross-language-check activation-recipient party-view corpus",
        true,
    )?;
    require_reported_case_count(
        &activation_recipient_party_view_output,
        baseline
            .evidence
            .activation_recipient_party_view_vector_cases,
        "activation-recipient party-view vector",
    )?;

    let evaluation_input_party_view_output = capture_command(
        Command::new(&python)
            .arg(&verifier)
            .arg(&evaluation_input_party_view_corpus)
            .arg("--ceremony-context-corpus")
            .arg(&ceremony_context_corpus)
            .arg("--provenance-corpus")
            .arg(&provenance_corpus)
            .arg("--semantic-lifecycle-corpus")
            .arg(&semantic_lifecycle_corpus)
            .arg("--output-party-view-corpus")
            .arg(&output_party_view_corpus),
        "cross-language-check evaluation-input party-view corpus",
        true,
    )?;
    require_reported_case_count(
        &evaluation_input_party_view_output,
        baseline.evidence.evaluation_input_party_view_vector_cases,
        "evaluation-input party-view vector",
    )?;

    let uniform_abort_output = capture_command(
        Command::new(&python)
            .arg(&verifier)
            .arg(&uniform_abort_corpus)
            .arg("--ceremony-context-corpus")
            .arg(&ceremony_context_corpus),
        "cross-language-check uniform-abort corpus",
        true,
    )?;
    require_reported_case_count(
        &uniform_abort_output,
        baseline.evidence.uniform_abort_vector_cases,
        "uniform-abort vector",
    )?;

    let evaluator_abort_view_output = capture_command(
        Command::new(&python)
            .arg(&verifier)
            .arg(&evaluator_abort_view_corpus)
            .arg("--ceremony-context-corpus")
            .arg(&ceremony_context_corpus),
        "cross-language-check evaluator-abort state/party-view corpus",
        true,
    )?;
    require_reported_case_count(
        &evaluator_abort_view_output,
        baseline.evidence.evaluator_abort_view_vector_cases,
        "evaluator-abort state/party-view vector",
    )?;

    let export_delivery_output = capture_command(
        Command::new(&python)
            .arg(&verifier)
            .arg(&export_delivery_corpus),
        "cross-language-check export-delivery corpus",
        true,
    )?;
    require_reported_case_count(
        &export_delivery_output,
        baseline.evidence.export_delivery_vector_cases,
        "export-delivery vector",
    )?;

    let recovery_credential_transition_output = capture_command(
        Command::new(&python)
            .arg(&verifier)
            .arg(&recovery_credential_transition_corpus)
            .arg("--ceremony-context-corpus")
            .arg(&ceremony_context_corpus)
            .arg("--provenance-corpus")
            .arg(&provenance_corpus)
            .arg("--semantic-lifecycle-corpus")
            .arg(&semantic_lifecycle_corpus)
            .arg("--output-party-view-corpus")
            .arg(&output_party_view_corpus)
            .arg("--activation-delivery-corpus")
            .arg(&activation_delivery_corpus)
            .arg("--activation-recipient-party-view-corpus")
            .arg(&activation_recipient_party_view_corpus),
        "cross-language-check recovery credential-transition corpus",
        true,
    )?;
    require_reported_case_count(
        &recovery_credential_transition_output,
        baseline
            .evidence
            .recovery_credential_transition_vector_cases,
        "recovery credential-transition vector",
    )?;
    let export_evaluator_authorization_output = capture_command(
        Command::new(&python)
            .arg(&verifier)
            .arg(&export_evaluator_authorization_corpus),
        "cross-language-check export evaluator-authorization corpus",
        true,
    )?;
    require_reported_case_count(
        &export_evaluator_authorization_output,
        baseline
            .evidence
            .export_evaluator_authorization_vector_cases,
        "export evaluator-authorization vector",
    )?;
    let registration_evaluator_admission_output = capture_command(
        Command::new(&python)
            .arg(&verifier)
            .arg(&registration_evaluator_admission_corpus),
        "cross-language-check registration evaluator-admission corpus",
        true,
    )?;
    require_reported_case_count(
        &registration_evaluator_admission_output,
        baseline
            .evidence
            .registration_evaluator_admission_vector_cases,
        "registration evaluator-admission vector",
    )?;
    let recovery_evaluator_admission_output = capture_command(
        Command::new(&python)
            .arg(&verifier)
            .arg(&recovery_evaluator_admission_corpus),
        "cross-language-check recovery evaluator-admission corpus",
        true,
    )?;
    require_reported_case_count(
        &recovery_evaluator_admission_output,
        baseline.evidence.recovery_evaluator_admission_vector_cases,
        "recovery evaluator-admission vector",
    )?;
    let refresh_evaluator_admission_output = capture_command(
        Command::new(&python)
            .arg(&verifier)
            .arg(&refresh_evaluator_admission_corpus),
        "cross-language-check refresh evaluator-admission corpus",
        true,
    )?;
    require_reported_case_count(
        &refresh_evaluator_admission_output,
        baseline.evidence.refresh_evaluator_admission_vector_cases,
        "refresh evaluator-admission vector",
    )?;
    let semantic_frame_party_view_output = capture_command(
        Command::new(&python)
            .arg(&verifier)
            .arg(&semantic_frame_party_view_corpus)
            .arg("--source-vector-directory")
            .arg(generator_dir(&baseline).join("vectors")),
        "cross-language-check semantic-frame party-view corpus",
        true,
    )?;
    require_reported_case_count(
        &semantic_frame_party_view_output,
        baseline.evidence.semantic_frame_party_view_vector_cases,
        "semantic-frame party-view vector",
    )?;

    let temporary = TemporaryDirectory::create("differential")?;
    let differential_corpus = temporary.path().join("ed25519-yao-differential-v1.json");
    let differential_corpus_string = path_string(&differential_corpus)?;
    let differential_count = baseline.evidence.differential_vector_cases.to_string();
    run_cargo_capture(
        &[
            "run",
            "--locked",
            "--manifest-path",
            generator_manifest_string,
            "--bin",
            "ed25519-yao-vectors",
            "--",
            "emit-differential",
            "--seed-hex",
            DIFFERENTIAL_SEED_HEX,
            "--cases",
            &differential_count,
            "--output",
            differential_corpus_string,
        ],
        "cross-language-check deterministic corpus generation",
    )?;
    let differential_output = capture_command(
        Command::new(&python)
            .arg(&verifier)
            .arg(&differential_corpus)
            .args(["--differential-seed-hex", DIFFERENTIAL_SEED_HEX]),
        "cross-language-check deterministic differential corpus",
        true,
    )?;
    require_reported_case_count(
        &differential_output,
        baseline.evidence.differential_vector_cases,
        "deterministic differential vector",
    )?;

    println!(
        "cross-language-check ok: {verifier_test_count} verifier tests, including {artifact_python_test_count} artifact tests, {ceremony_context_python_test_count} ceremony-context tests, {semantic_lifecycle_python_test_count} semantic-lifecycle tests, {output_party_view_python_test_count} output-party-view tests, {activation_delivery_python_test_count} activation-delivery tests, {activation_recipient_party_view_python_test_count} activation-recipient party-view tests, {evaluation_input_party_view_python_test_count} evaluation-input party-view tests, {uniform_abort_python_test_count} uniform-abort tests, {evaluator_abort_view_python_test_count} evaluator-abort-view tests, {export_delivery_python_test_count} export-delivery tests, {recovery_credential_transition_python_test_count} recovery credential-transition tests, {export_evaluator_authorization_python_test_count} export evaluator-authorization tests, {registration_evaluator_admission_python_test_count} registration evaluator-admission tests, {recovery_evaluator_admission_python_test_count} recovery evaluator-admission tests, {refresh_evaluator_admission_python_test_count} refresh evaluator-admission tests, and {semantic_frame_party_view_python_test_count} semantic-frame party-view tests; Phase 2A artifact cases: {}; committed arithmetic cases: {}; KDF continuity cases: {}; ceremony-context cases: {}; lifecycle-continuity cases: {}; provenance outer-contract cases: {}; output-sharing cases: {}; semantic-lifecycle cases: {}; output-party-view cases: {}; activation-delivery cases: {}; activation-recipient party-view cases: {}; evaluation-input party-view cases: {}; uniform-abort cases: {}; evaluator-abort state/party-view cases: {}; export-delivery cases: {}; recovery credential-transition cases: {}; export evaluator-authorization cases: {}; registration evaluator-admission cases: {}; recovery evaluator-admission cases: {}; refresh evaluator-admission cases: {}; semantic-frame party-view cases: {}; independently regenerated differential cases: {}",
        baseline.evidence.artifact_vector_cases,
        baseline.evidence.vector_cases,
        baseline.evidence.kdf_vector_cases,
        baseline.evidence.ceremony_context_vector_cases,
        baseline.evidence.lifecycle_continuity_vector_cases,
        baseline.evidence.provenance_vector_cases,
        baseline.evidence.output_sharing_vector_cases,
        baseline.evidence.semantic_lifecycle_vector_cases,
        baseline.evidence.output_party_view_vector_cases,
        baseline.evidence.activation_delivery_vector_cases,
        baseline
            .evidence
            .activation_recipient_party_view_vector_cases,
        baseline.evidence.evaluation_input_party_view_vector_cases,
        baseline.evidence.uniform_abort_vector_cases,
        baseline.evidence.evaluator_abort_view_vector_cases,
        baseline.evidence.export_delivery_vector_cases,
        baseline
            .evidence
            .recovery_credential_transition_vector_cases,
        baseline
            .evidence
            .export_evaluator_authorization_vector_cases,
        baseline
            .evidence
            .registration_evaluator_admission_vector_cases,
        baseline.evidence.recovery_evaluator_admission_vector_cases,
        baseline.evidence.refresh_evaluator_admission_vector_cases,
        baseline.evidence.semantic_frame_party_view_vector_cases,
        baseline.evidence.differential_vector_cases
    );
    Ok(())
}

fn run_parity() -> Result<(), DynError> {
    let baseline = load_baseline()?;
    let generator_manifest = generator_manifest(&baseline);
    let artifact_filesystem_policy_manifest = artifact_filesystem_policy_manifest(&baseline);
    let circuit_count = count_cargo_tests(&generator_manifest, &["--lib", "circuit::"])?;
    require_exact_count(
        "Phase 2A circuit Rust test",
        circuit_count,
        baseline.evidence.circuit_rust_tests,
    )?;
    let artifact_bundle_count =
        count_cargo_tests(&generator_manifest, &["--lib", "artifact_bundle::"])?;
    require_exact_count(
        "Phase 2A artifact-bundle Rust test",
        artifact_bundle_count,
        baseline.evidence.artifact_bundle_rust_tests,
    )?;
    let authenticated_store_count =
        count_cargo_tests(&generator_manifest, &["--lib", "authenticated_store::"])?;
    require_exact_count(
        "authenticated-store Rust test",
        authenticated_store_count,
        baseline.evidence.authenticated_store_rust_tests,
    )?;
    let signing_worker_activation_count = count_cargo_tests(
        &generator_manifest,
        &["--lib", "signing_worker_activation::tests::"],
    )?;
    require_exact_count(
        "SigningWorker-activation Rust test",
        signing_worker_activation_count,
        baseline.evidence.signing_worker_activation_rust_tests,
    )?;
    let refresh_promotion_count = count_cargo_tests(
        &generator_manifest,
        &["--lib", "refresh_promotion::tests::"],
    )?;
    require_exact_count(
        "refresh-promotion Rust test",
        refresh_promotion_count,
        baseline.evidence.refresh_promotion_rust_tests,
    )?;
    let recovery_credential_transition_count = count_cargo_tests(
        &generator_manifest,
        &["--lib", "recovery_credential_transition::tests::"],
    )?;
    require_exact_count(
        "recovery-credential-transition Rust test",
        recovery_credential_transition_count,
        baseline.evidence.recovery_credential_transition_rust_tests,
    )?;
    let recovery_credential_transition_vector_count = count_cargo_tests(
        &generator_manifest,
        &["--test", "recovery_credential_transition_vectors"],
    )?;
    require_exact_count(
        "recovery credential-transition vector Rust test",
        recovery_credential_transition_vector_count,
        baseline
            .evidence
            .recovery_credential_transition_vector_rust_tests,
    )?;
    let export_evaluator_authorization_count = count_cargo_tests(
        &generator_manifest,
        &["--lib", "export_evaluation_acceptance::tests::"],
    )?;
    require_exact_count(
        "export evaluator-authorization Rust test",
        export_evaluator_authorization_count,
        baseline.evidence.export_evaluator_authorization_rust_tests,
    )?;
    let export_evaluator_authorization_vector_count = count_cargo_tests(
        &generator_manifest,
        &["--test", "export_evaluator_authorization_vectors"],
    )?;
    require_exact_count(
        "export evaluator-authorization vector Rust test",
        export_evaluator_authorization_vector_count,
        baseline
            .evidence
            .export_evaluator_authorization_vector_rust_tests,
    )?;
    let registration_evaluator_admission_count = count_cargo_tests(
        &generator_manifest,
        &["--lib", "registration_evaluation_admission::tests::"],
    )?;
    require_exact_count(
        "registration evaluator-admission Rust test",
        registration_evaluator_admission_count,
        baseline
            .evidence
            .registration_evaluator_admission_rust_tests,
    )?;
    let registration_evaluator_admission_vector_count = count_cargo_tests(
        &generator_manifest,
        &["--test", "registration_evaluator_admission_vectors"],
    )?;
    require_exact_count(
        "registration evaluator-admission vector Rust test",
        registration_evaluator_admission_vector_count,
        baseline
            .evidence
            .registration_evaluator_admission_vector_rust_tests,
    )?;
    let recovery_evaluator_admission_count = count_cargo_tests(
        &generator_manifest,
        &["--lib", "recovery_evaluation_admission::tests::"],
    )?;
    require_exact_count(
        "recovery evaluator-admission Rust test",
        recovery_evaluator_admission_count,
        baseline.evidence.recovery_evaluator_admission_rust_tests,
    )?;
    let recovery_evaluator_admission_vector_count = count_cargo_tests(
        &generator_manifest,
        &["--test", "recovery_evaluator_admission_vectors"],
    )?;
    require_exact_count(
        "recovery evaluator-admission vector Rust test",
        recovery_evaluator_admission_vector_count,
        baseline
            .evidence
            .recovery_evaluator_admission_vector_rust_tests,
    )?;
    let refresh_evaluator_admission_count = count_cargo_tests(
        &generator_manifest,
        &["--lib", "refresh_evaluation_admission::tests::"],
    )?;
    require_exact_count(
        "refresh evaluator-admission Rust test",
        refresh_evaluator_admission_count,
        baseline.evidence.refresh_evaluator_admission_rust_tests,
    )?;
    let refresh_evaluator_admission_vector_count = count_cargo_tests(
        &generator_manifest,
        &["--test", "refresh_evaluator_admission_vectors"],
    )?;
    require_exact_count(
        "refresh evaluator-admission vector Rust test",
        refresh_evaluator_admission_vector_count,
        baseline
            .evidence
            .refresh_evaluator_admission_vector_rust_tests,
    )?;
    let benchmark_manifest_count = count_cargo_tests(
        &generator_manifest,
        &["--lib", "benchmark_manifest::tests::"],
    )?;
    require_exact_count(
        "benchmark-manifest Rust test",
        benchmark_manifest_count,
        baseline.evidence.benchmark_manifest_rust_tests,
    )?;
    let joint_refresh_delta_count = count_cargo_tests(
        &generator_manifest,
        &["--lib", "joint_refresh_delta::tests::"],
    )?;
    require_exact_count(
        "joint-refresh-delta Rust test",
        joint_refresh_delta_count,
        baseline.evidence.joint_refresh_delta_rust_tests,
    )?;
    let registration_reference_count =
        count_cargo_tests(&generator_manifest, &["--test", "registration_reference"])?;
    require_exact_count(
        "registration-reference Rust test",
        registration_reference_count,
        baseline.evidence.registration_reference_rust_tests,
    )?;
    let recovery_reference_count =
        count_cargo_tests(&generator_manifest, &["--test", "recovery_reference"])?;
    require_exact_count(
        "recovery-reference Rust test",
        recovery_reference_count,
        baseline.evidence.recovery_reference_rust_tests,
    )?;
    let refresh_reference_count =
        count_cargo_tests(&generator_manifest, &["--test", "refresh_reference"])?;
    require_exact_count(
        "refresh-reference Rust test",
        refresh_reference_count,
        baseline.evidence.refresh_reference_rust_tests,
    )?;
    let export_reference_count =
        count_cargo_tests(&generator_manifest, &["--test", "export_reference"])?;
    require_exact_count(
        "export-reference Rust test",
        export_reference_count,
        baseline.evidence.export_reference_rust_tests,
    )?;
    let output_sharing_core_count =
        count_cargo_tests(&generator_manifest, &["--test", "output_sharing"])?;
    require_exact_count(
        "output-sharing core Rust test",
        output_sharing_core_count,
        baseline.evidence.output_sharing_core_rust_tests,
    )?;
    let output_sharing_vector_count =
        count_cargo_tests(&generator_manifest, &["--test", "output_sharing_vectors"])?;
    require_exact_count(
        "output-sharing vector Rust test",
        output_sharing_vector_count,
        baseline.evidence.output_sharing_vector_rust_tests,
    )?;
    let semantic_lifecycle_vector_count = count_cargo_tests(
        &generator_manifest,
        &["--test", "semantic_lifecycle_vectors"],
    )?;
    require_exact_count(
        "semantic-lifecycle vector Rust test",
        semantic_lifecycle_vector_count,
        baseline.evidence.semantic_lifecycle_vector_rust_tests,
    )?;
    let output_party_view_core_count =
        count_cargo_tests(&generator_manifest, &["--lib", "output_party_views::"])?;
    require_exact_count(
        "output-party-view core Rust test",
        output_party_view_core_count,
        baseline.evidence.output_party_view_core_rust_tests,
    )?;
    let output_party_view_guard_count =
        count_cargo_tests(&generator_manifest, &["--test", "output_party_views"])?;
    require_exact_count(
        "output-party-view API/static-guard Rust test",
        output_party_view_guard_count,
        baseline.evidence.output_party_view_guard_rust_tests,
    )?;
    let output_party_view_vector_count = count_cargo_tests(
        &generator_manifest,
        &["--test", "output_party_view_vectors"],
    )?;
    require_exact_count(
        "output-party-view vector Rust test",
        output_party_view_vector_count,
        baseline.evidence.output_party_view_vector_rust_tests,
    )?;
    let evaluation_input_party_view_core_count =
        count_cargo_tests(&generator_manifest, &["--lib", "evaluation_input_views::"])?;
    require_exact_count(
        "evaluation-input party-view core Rust test",
        evaluation_input_party_view_core_count,
        baseline
            .evidence
            .evaluation_input_party_view_core_rust_tests,
    )?;
    let evaluation_input_party_view_guard_count =
        count_cargo_tests(&generator_manifest, &["--test", "evaluation_input_views"])?;
    require_exact_count(
        "evaluation-input party-view API/static-guard Rust test",
        evaluation_input_party_view_guard_count,
        baseline
            .evidence
            .evaluation_input_party_view_guard_rust_tests,
    )?;
    let evaluation_input_party_view_vector_count = count_cargo_tests(
        &generator_manifest,
        &["--test", "evaluation_input_view_vectors"],
    )?;
    require_exact_count(
        "evaluation-input party-view vector Rust test",
        evaluation_input_party_view_vector_count,
        baseline
            .evidence
            .evaluation_input_party_view_vector_rust_tests,
    )?;
    let uniform_abort_vector_count =
        count_cargo_tests(&generator_manifest, &["--test", "uniform_abort_vectors"])?;
    require_exact_count(
        "uniform-abort vector Rust test",
        uniform_abort_vector_count,
        baseline.evidence.uniform_abort_vector_rust_tests,
    )?;
    let evaluator_abort_view_vector_count = count_cargo_tests(
        &generator_manifest,
        &["--test", "evaluator_abort_view_vectors"],
    )?;
    require_exact_count(
        "evaluator-abort-view vector Rust test",
        evaluator_abort_view_vector_count,
        baseline.evidence.evaluator_abort_view_vector_rust_tests,
    )?;
    let export_delivery_vector_count =
        count_cargo_tests(&generator_manifest, &["--test", "export_delivery_vectors"])?;
    let export_delivery_core_count =
        count_cargo_tests(&generator_manifest, &["--lib", "export_delivery::tests::"])?;
    require_exact_count(
        "export-delivery core Rust test",
        export_delivery_core_count,
        baseline.evidence.export_delivery_core_rust_tests,
    )?;
    require_exact_count(
        "export-delivery vector Rust test",
        export_delivery_vector_count,
        baseline.evidence.export_delivery_vector_rust_tests,
    )?;
    let activation_delivery_core_count = count_cargo_tests(
        &generator_manifest,
        &["--lib", "activation_delivery::tests::"],
    )?;
    require_exact_count(
        "activation-delivery core Rust test",
        activation_delivery_core_count,
        baseline.evidence.activation_delivery_core_rust_tests,
    )?;
    let activation_delivery_vector_count = count_cargo_tests(
        &generator_manifest,
        &["--test", "activation_delivery_vectors"],
    )?;
    require_exact_count(
        "activation-delivery vector Rust test",
        activation_delivery_vector_count,
        baseline.evidence.activation_delivery_vector_rust_tests,
    )?;
    let activation_recipient_party_view_core_count = count_cargo_tests(
        &generator_manifest,
        &["--lib", "activation_recipient_party_views::tests::"],
    )?;
    require_exact_count(
        "activation-recipient party-view core Rust test",
        activation_recipient_party_view_core_count,
        baseline
            .evidence
            .activation_recipient_party_view_core_rust_tests,
    )?;
    let activation_recipient_party_view_guard_count = count_cargo_tests(
        &generator_manifest,
        &["--test", "activation_recipient_party_views"],
    )?;
    require_exact_count(
        "activation-recipient party-view API/static-guard Rust test",
        activation_recipient_party_view_guard_count,
        baseline
            .evidence
            .activation_recipient_party_view_guard_rust_tests,
    )?;
    let activation_recipient_party_view_vector_count = count_cargo_tests(
        &generator_manifest,
        &["--test", "activation_recipient_party_view_vectors"],
    )?;
    require_exact_count(
        "activation-recipient party-view vector Rust test",
        activation_recipient_party_view_vector_count,
        baseline
            .evidence
            .activation_recipient_party_view_vector_rust_tests,
    )?;
    let semantic_delivery_view_count = count_cargo_tests(
        &generator_manifest,
        &["--lib", "semantic_delivery_views::tests::"],
    )?;
    let semantic_frame_class_count = count_cargo_tests(
        &generator_manifest,
        &["--lib", "semantic_frame_classes::tests::"],
    )?;
    let corruption_interface_count = count_cargo_tests(
        &generator_manifest,
        &["--lib", "corruption_game_interfaces::tests::"],
    )?;
    let semantic_frame_core_count = semantic_delivery_view_count
        .checked_add(semantic_frame_class_count)
        .and_then(|count| count.checked_add(corruption_interface_count))
        .ok_or("semantic-frame core Rust test count overflow")?;
    require_exact_count(
        "semantic-frame core Rust test",
        semantic_frame_core_count,
        baseline.evidence.semantic_frame_core_rust_tests,
    )?;
    let semantic_trace_boundary_count = count_cargo_tests(
        &generator_manifest,
        &["--test", "semantic_trace_boundaries"],
    )?;
    require_exact_count(
        "semantic-trace boundary Rust test",
        semantic_trace_boundary_count,
        baseline.evidence.semantic_trace_boundary_rust_tests,
    )?;
    let semantic_frame_party_view_vector_count = count_cargo_tests(
        &generator_manifest,
        &["--test", "semantic_frame_party_view_vectors"],
    )?;
    require_exact_count(
        "semantic-frame party-view vector Rust test",
        semantic_frame_party_view_vector_count,
        baseline
            .evidence
            .semantic_frame_party_view_vector_rust_tests,
    )?;
    let phase2b_reconciliation_count = count_cargo_tests(
        &generator_manifest,
        &["--lib", "phase2b_core_reconciliation::tests::"],
    )?;
    require_exact_count(
        "Phase 2B reconciliation Rust test",
        phase2b_reconciliation_count,
        baseline.evidence.phase2b_reconciliation_rust_tests,
    )?;
    let production_count = run_cargo_test_suite(
        &production_manifest(),
        &[],
        baseline.evidence.production_rust_tests,
        "production manifest crate",
    )?;
    let generator_count = run_cargo_test_suite(
        &generator_manifest,
        &[],
        baseline.evidence.generator_rust_tests,
        "clear generator crate",
    )?;
    let artifact_filesystem_policy_count = run_cargo_test_suite(
        &artifact_filesystem_policy_manifest,
        &[],
        baseline.evidence.artifact_filesystem_policy_rust_tests,
        "artifact filesystem policy crate",
    )?;
    println!(
        "parity ok: {production_count} production, {generator_count} generator, and {artifact_filesystem_policy_count} artifact-filesystem-policy tests, including {circuit_count} Phase 2A circuit, {artifact_bundle_count} artifact-bundle, {benchmark_manifest_count} benchmark-manifest, {joint_refresh_delta_count} joint-refresh-delta, {authenticated_store_count} authenticated-store, {signing_worker_activation_count} SigningWorker-activation, {refresh_promotion_count} refresh-promotion, {recovery_credential_transition_count} recovery credential-transition core, {recovery_credential_transition_vector_count} recovery credential-transition vector, {registration_reference_count} registration-reference, {recovery_reference_count} recovery-reference, {refresh_reference_count} refresh-reference, {export_reference_count} export-reference, {output_sharing_core_count} output-sharing core, {output_sharing_vector_count} output-sharing vector, {semantic_lifecycle_vector_count} semantic-lifecycle vector, {output_party_view_core_count} output-party-view core, {output_party_view_guard_count} output-party-view API/static-guard, {output_party_view_vector_count} output-party-view vector, {evaluation_input_party_view_core_count} evaluation-input party-view core, {evaluation_input_party_view_guard_count} evaluation-input party-view API/static-guard, {evaluation_input_party_view_vector_count} evaluation-input party-view vector, {uniform_abort_vector_count} uniform-abort vector, {evaluator_abort_view_vector_count} evaluator-abort-view vector, {export_delivery_core_count} export-delivery core, {export_delivery_vector_count} export-delivery vector, {activation_delivery_core_count} activation-delivery core, {activation_delivery_vector_count} activation-delivery vector, {activation_recipient_party_view_core_count} activation-recipient party-view core, {activation_recipient_party_view_guard_count} activation-recipient party-view API/static-guard, {activation_recipient_party_view_vector_count} activation-recipient party-view vector, {semantic_frame_core_count} semantic-frame core, {semantic_trace_boundary_count} semantic-trace boundary, {semantic_frame_party_view_vector_count} semantic-frame corpus, and {phase2b_reconciliation_count} Phase 2B reconciliation tests"
    );
    Ok(())
}

fn run_anti_drift() -> Result<(), DynError> {
    let baseline = load_baseline()?;
    let count = run_cargo_test_suite(
        &verus_manifest(),
        &["--test", "anti_drift"],
        baseline.evidence.anti_drift_tests,
        "production-to-mirror anti-drift",
    )?;
    println!("anti-drift ok: {count} production, generator, and mirror comparisons");
    Ok(())
}

fn run_lean_check() -> Result<(), DynError> {
    let baseline = load_baseline()?;
    reject_forbidden_lean_declarations()?;
    verify_lean_toolchain(&baseline, &lean_model_dir())?;

    let manifest_model = lean_model_dir().join("Ed25519YaoModel/Manifest.lean");
    let party_views_model = lean_model_dir().join("Ed25519YaoModel/PartyViews.lean");
    let evaluation_inputs_model = lean_model_dir().join("Ed25519YaoModel/EvaluationInputs.lean");
    let evaluation_input_theorem_count = count_lean_theorems(&evaluation_inputs_model)?;
    let uniform_abort_model = lean_model_dir().join("Ed25519YaoModel/UniformAbort.lean");
    let uniform_abort_theorem_count = count_lean_theorems(&uniform_abort_model)?;
    let evaluator_abort_views_model =
        lean_model_dir().join("Ed25519YaoModel/EvaluatorAbortViews.lean");
    let evaluator_abort_views_theorem_count = count_lean_theorems(&evaluator_abort_views_model)?;
    let export_delivery_model = lean_model_dir().join("Ed25519YaoModel/ExportDelivery.lean");
    let export_delivery_theorem_count = count_lean_theorems(&export_delivery_model)?;
    let activation_delivery_model =
        lean_model_dir().join("Ed25519YaoModel/ActivationDelivery.lean");
    let activation_delivery_theorem_count = count_lean_theorems(&activation_delivery_model)?;
    let activation_recipient_party_views_model =
        lean_model_dir().join("Ed25519YaoModel/ActivationRecipientPartyViews.lean");
    let activation_recipient_party_views_theorem_count =
        count_lean_theorems(&activation_recipient_party_views_model)?;
    let recovery_credential_transition_model =
        lean_model_dir().join("Ed25519YaoModel/RecoveryCredentialTransition.lean");
    let recovery_credential_transition_theorem_count =
        count_lean_theorems(&recovery_credential_transition_model)?;
    let export_evaluator_authorization_model =
        lean_model_dir().join("Ed25519YaoModel/ExportEvaluatorAuthorization.lean");
    let export_evaluator_authorization_theorem_count =
        count_lean_theorems(&export_evaluator_authorization_model)?;
    let registration_evaluator_admission_model =
        lean_model_dir().join("Ed25519YaoModel/RegistrationEvaluatorAdmission.lean");
    let registration_evaluator_admission_theorem_count =
        count_lean_theorems(&registration_evaluator_admission_model)?;
    let recovery_evaluator_admission_model =
        lean_model_dir().join("Ed25519YaoModel/RecoveryEvaluatorAdmission.lean");
    let recovery_evaluator_admission_theorem_count =
        count_lean_theorems(&recovery_evaluator_admission_model)?;
    let refresh_evaluator_admission_model =
        lean_model_dir().join("Ed25519YaoModel/RefreshEvaluatorAdmission.lean");
    let refresh_evaluator_admission_theorem_count =
        count_lean_theorems(&refresh_evaluator_admission_model)?;
    let semantic_frame_party_views_model =
        lean_model_dir().join("Ed25519YaoModel/SemanticFramePartyViews.lean");
    let semantic_frame_party_views_theorem_count =
        count_lean_theorems(&semantic_frame_party_views_model)?;
    let theorem_count = count_lean_theorems(&manifest_model)?
        .checked_add(count_lean_theorems(&party_views_model)?)
        .and_then(|count| count.checked_add(evaluation_input_theorem_count))
        .and_then(|count| count.checked_add(uniform_abort_theorem_count))
        .and_then(|count| count.checked_add(evaluator_abort_views_theorem_count))
        .and_then(|count| count.checked_add(export_delivery_theorem_count))
        .and_then(|count| count.checked_add(activation_delivery_theorem_count))
        .and_then(|count| count.checked_add(activation_recipient_party_views_theorem_count))
        .and_then(|count| count.checked_add(recovery_credential_transition_theorem_count))
        .and_then(|count| count.checked_add(export_evaluator_authorization_theorem_count))
        .and_then(|count| count.checked_add(registration_evaluator_admission_theorem_count))
        .and_then(|count| count.checked_add(recovery_evaluator_admission_theorem_count))
        .and_then(|count| count.checked_add(refresh_evaluator_admission_theorem_count))
        .and_then(|count| count.checked_add(semantic_frame_party_views_theorem_count))
        .ok_or("Lean model theorem count overflow")?;
    require_exact_count(
        "Lean model theorem",
        theorem_count,
        baseline.evidence.lean_model_theorems,
    )?;

    let lake = resolve_program("lake", "install Lean through elan")?;
    run_command(
        Command::new(lake)
            .arg("build")
            .arg("Ed25519YaoModel")
            .current_dir(lean_model_dir()),
        "lean-check named Ed25519YaoModel target",
    )?;
    require_file(
        &lean_model_dir().join(".lake/build/lib/lean/Ed25519YaoModel.olean"),
        "named Lean model output",
    )?;
    println!("lean-check ok: {theorem_count} theorems and Ed25519YaoModel.olean produced");
    Ok(())
}

fn run_aeneas_check() -> Result<(), DynError> {
    let baseline = load_baseline()?;
    reject_forbidden_lean_declarations()?;
    verify_lean_toolchain(&baseline, &lean_boundary_dir())?;

    let aeneas_dir = lean_boundary_dir().join("tools/aeneas");
    let charon_dir = lean_boundary_dir().join("tools/charon");
    verify_git_checkout(&aeneas_dir, &baseline.aeneas, "Aeneas")?;
    verify_git_checkout(&charon_dir, &baseline.charon, "Charon")?;
    verify_tool_binary(&aeneas_dir.join("bin/aeneas"), &aeneas_dir, "Aeneas")?;
    verify_tool_binary(&charon_dir.join("bin/charon"), &charon_dir, "Charon")?;

    let artifact_paths = aeneas_artifact_paths();
    let snapshots = snapshot_artifacts(&artifact_paths)?;
    let extraction = lean_boundary_dir().join("scripts/extract-reference-boundary.sh");
    require_file(&extraction, "Aeneas reference-boundary extractor")?;
    run_command(
        &mut Command::new(extraction),
        "aeneas-check reference-boundary extraction",
    )?;
    assert_artifacts_unchanged(&snapshots)?;
    reject_forbidden_lean_declarations()?;
    verify_generated_extraction_scope(&baseline)?;

    let lake = resolve_program("lake", "install Lean through elan")?;
    run_command(
        Command::new(lake)
            .arg("build")
            .arg("Ed25519Yao")
            .arg("Ed25519YaoBoundary")
            .current_dir(lean_boundary_dir()),
        "aeneas-check named Lean boundary targets",
    )?;
    require_file(
        &lean_boundary_dir().join(".lake/build/lib/lean/Ed25519Yao.olean"),
        "named generated Lean output",
    )?;
    require_file(
        &lean_boundary_dir().join(".lake/build/lib/lean/Ed25519YaoBoundary.olean"),
        "named Lean boundary output",
    )?;
    println!(
        "aeneas-check ok: {} generated functions, 2 stable Lean artifacts, and 2 named Lean targets checked",
        baseline.evidence.aeneas_extracted_functions
    );
    Ok(())
}

fn run_verus_check() -> Result<(), DynError> {
    let baseline = load_baseline()?;
    reject_forbidden_verus_declarations()?;
    verify_vstd_pin(&baseline)?;

    let verus = resolve_program("verus", "install the pinned repository Verus release")?;
    let cargo_verus = resolve_program(
        "cargo-verus",
        "install cargo-verus from the same pinned Verus release",
    )?;
    verify_same_tool_bundle(&verus, &cargo_verus)?;

    let version_output = capture_command(
        Command::new(&verus).arg("--version"),
        "verus --version",
        true,
    )?;
    if !version_output.contains(&format!("Version: {}", baseline.verus.release)) {
        return Err(format!(
            "Verus release mismatch: expected {}; received `{}`",
            baseline.verus.release,
            version_output.trim().replace('\n', " | ")
        )
        .into());
    }

    let manifest = verus_manifest();
    let output = capture_command(
        Command::new(cargo_verus)
            .arg("verify")
            .arg("--locked")
            .arg("--manifest-path")
            .arg(manifest),
        "verus-check pinned cargo-verus driver",
        true,
    )?;
    let verified = parse_verus_verified_count(&output)?;
    require_exact_count(
        "Verus obligation",
        verified,
        baseline.evidence.verus_obligations,
    )?;
    println!(
        "verus-check ok: {verified} obligations verified by release {}",
        baseline.verus.release
    );
    Ok(())
}

fn run_benchmark_manifest_reproducibility() -> Result<(), DynError> {
    let baseline = load_baseline()?;
    let generator_manifest = generator_manifest(&baseline);
    require_file(&generator_manifest, "benchmark-manifest generator manifest")?;
    let temporary = TemporaryDirectory::create("benchmark-manifest-reproducibility")?;
    let expected = format!(
        "bytes={} digest={} bundle_index_bytes={} bundle_index_digest={}",
        baseline.evidence.benchmark_manifest_bytes,
        baseline.evidence.benchmark_manifest_digest,
        baseline.evidence.benchmark_bundle_index_bytes,
        baseline.evidence.benchmark_bundle_index_digest,
    );
    let cargo = env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let mut summaries = Vec::new();
    for build in ["first", "second"] {
        let target = temporary.path().join(build);
        let summary = capture_command(
            Command::new(&cargo)
                .args(["run", "--locked", "--quiet", "--manifest-path"])
                .arg(&generator_manifest)
                .args(["--bin", "ed25519-yao-benchmark-manifest", "--", "summary"])
                .env("CARGO_TARGET_DIR", target),
            "clean-build benchmark-manifest regeneration",
            false,
        )?;
        let summary = summary.trim();
        if summary != expected {
            return Err(format!(
                "{build} clean build produced unexpected benchmark manifest: expected `{expected}`, received `{summary}`"
            )
            .into());
        }
        summaries.push(summary.to_owned());
    }
    if summaries[0] != summaries[1] {
        return Err("independent clean builds produced different benchmark manifests".into());
    }
    println!(
        "benchmark-manifest-reproducibility ok: 2 isolated clean builds reproduced {expected}"
    );
    Ok(())
}

fn run_phase2b_reconciliation_check() -> Result<(), DynError> {
    let baseline = load_baseline()?;
    let generator_manifest = generator_manifest(&baseline);
    let generator_manifest_string = path_string(&generator_manifest)?;
    let generator = generator_dir(&baseline);
    let certificate = generator.join("vectors/ed25519-yao-phase2b-core-reconciliation-v1.json");
    let source_vector_dir = generator.join("vectors");
    let verifier_dir = independent_verifier_dir();
    let artifact_verifier = verifier_dir.join("verify_artifacts.py");
    let artifact_verifier_tests = verifier_dir.join("test_verify_artifacts.py");
    require_file(
        &certificate,
        "committed Phase 2B reconciliation certificate",
    )?;
    require_file(&artifact_verifier, "independent Python artifact verifier")?;
    require_file(
        &artifact_verifier_tests,
        "independent Python artifact verifier tests",
    )?;

    let certificate_string = path_string(&certificate)?;
    run_cargo_capture(
        &[
            "run",
            "--locked",
            "--manifest-path",
            generator_manifest_string,
            "--bin",
            "ed25519-yao-vectors",
            "--",
            "check-phase2b-core-reconciliation",
            "--input",
            certificate_string,
        ],
        "Phase 2B committed-certificate check",
    )?;

    let rust_test_count = run_cargo_test_suite(
        &generator_manifest,
        &["--lib", "phase2b_core_reconciliation::tests::"],
        baseline.evidence.phase2b_reconciliation_rust_tests,
        "Phase 2B reconciliation Rust suite",
    )?;
    let python_test_count = count_prefixed_python_tests(
        &artifact_verifier_tests,
        "def test_artifact_phase2b_reconciliation_",
    )?;
    require_exact_count(
        "Phase 2B reconciliation independent verifier test",
        python_test_count,
        baseline.evidence.phase2b_reconciliation_python_tests,
    )?;

    let temporary = TemporaryDirectory::create("phase2b-reconciliation")?;
    let artifact_directory = temporary.path().join("bundle");
    let artifact_directory_string = path_string(&artifact_directory)?;
    run_cargo_capture(
        &[
            "run",
            "--locked",
            "--manifest-path",
            generator_manifest_string,
            "--bin",
            "ed25519-yao-circuit-artifacts",
            "--",
            "emit",
            "--output-dir",
            artifact_directory_string,
        ],
        "Phase 2B fresh artifact generation",
    )?;
    let cargo = env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let manifest_hex = capture_command(
        Command::new(cargo)
            .args(["run", "--locked", "--quiet", "--manifest-path"])
            .arg(&generator_manifest)
            .args(["--bin", "ed25519-yao-benchmark-manifest", "--", "hex"]),
        "Phase 2B candidate benchmark-manifest regeneration",
        false,
    )?;
    let manifest_hex_path = temporary.path().join("benchmark-manifest-v1.hex");
    fs::write(&manifest_hex_path, manifest_hex.trim())?;

    let python = resolve_program("python3", "install the pinned minimum Python version")?;
    verify_python_version(&python, &baseline.python)?;
    let unit_output = capture_command(
        Command::new(&python)
            .args(["-m", "unittest", "test_verify_artifacts.py"])
            .current_dir(&verifier_dir)
            .env("ED25519_YAO_ARTIFACT_DIR", &artifact_directory),
        "Phase 2B independent Python mutation suite",
        true,
    )?;
    let artifact_test_count = parse_python_test_count(&unit_output)?;
    require_exact_count(
        "artifact independent verifier test",
        artifact_test_count,
        baseline.evidence.artifact_python_tests,
    )?;

    const PYTHON_RECONCILIATION_DRIVER: &str = r#"
import sys
from pathlib import Path
from verify_artifacts import verify_bundle_directory, verify_phase2b_core_reconciliation

certificate = Path(sys.argv[1])
artifact_dir = Path(sys.argv[2])
manifest = bytes.fromhex(Path(sys.argv[3]).read_text(encoding="ascii"))
source_vector_dir = Path(sys.argv[4])
bundle = verify_bundle_directory(artifact_dir)
count = verify_phase2b_core_reconciliation(
    certificate,
    bundle,
    manifest,
    source_vector_dir,
)
print(f"verified {count} Phase 2B reconciliation cases")
"#;
    let reconciliation_output = capture_command(
        Command::new(&python)
            .args(["-c", PYTHON_RECONCILIATION_DRIVER])
            .arg(&certificate)
            .arg(&artifact_directory)
            .arg(&manifest_hex_path)
            .arg(&source_vector_dir)
            .current_dir(&verifier_dir),
        "Phase 2B independent cross-corpus reconciliation",
        true,
    )?;
    let expected_summary = format!(
        "verified {} Phase 2B reconciliation cases",
        baseline.evidence.phase2b_reconciliation_vector_cases
    );
    if !reconciliation_output.contains(&expected_summary) {
        return Err(format!(
            "Phase 2B verifier did not report expected nonzero case count `{expected_summary}`"
        )
        .into());
    }

    println!(
        "phase2b-reconciliation-check ok: {} cases, {rust_test_count} Rust tests, {python_test_count} focused Python tests, and {artifact_test_count} total artifact-verifier tests",
        baseline.evidence.phase2b_reconciliation_vector_cases,
    );
    Ok(())
}

fn run_phase2b_exit_evidence_readiness_check() -> Result<(), DynError> {
    let baseline = load_baseline()?;
    let specification = formal_verification_dir().join("docs/phase2b-exit-evidence-v1.md");
    require_file(
        &specification,
        "normative Phase 2B external exit-evidence specification",
    )?;
    verify_sha256(
        &specification,
        &baseline.evidence.phase2b_exit_evidence_spec_sha256,
        "Phase 2B exit-evidence specification",
    )?;

    let tasks_manifest = formal_verification_dir().join("tasks/Cargo.toml");
    let test_count = run_cargo_test_suite(
        &tasks_manifest,
        &[
            "--bin",
            "ed25519-yao-formal-verification-tasks",
            "phase2b_exit_evidence::tests::",
        ],
        baseline.evidence.phase2b_exit_evidence_rust_tests,
        "Phase 2B exit-evidence readiness suite",
    )?;
    let protected_test_count = run_cargo_test_suite(
        &tasks_manifest,
        &[
            "--bin",
            "ed25519-yao-formal-verification-tasks",
            "phase2b_protected_inputs::tests::",
        ],
        baseline.evidence.phase2b_protected_inputs_rust_tests,
        "Phase 2B protected-input readiness suite",
    )?;

    let mut authority_forbidden_sources = Vec::new();
    collect_source_files(
        &repository_root().join("crates/ed25519-yao/src"),
        "rs",
        &["target"],
        &mut authority_forbidden_sources,
    )?;
    collect_source_files(
        &generator_dir(&baseline).join("src"),
        "rs",
        &["target"],
        &mut authority_forbidden_sources,
    )?;
    reject_tokens(
        &authority_forbidden_sources,
        &[
            "Phase2bReviewApprovalV1",
            "Phase2bIndependentHostReproductionV1",
            "phase2b_review_approval",
            "phase2b_independent_host_reproduction",
            "reviewer_signature",
            "operator_signature",
        ],
        "Phase 2B generator/production authority",
    )?;

    println!(
        "phase2b-exit-evidence-readiness-check ok: {test_count} signed-record boundary tests, {protected_test_count} protected-input tests, pinned normative specification, and generator/production authority exclusion"
    );
    Ok(())
}

fn run_phase2b_review_subject_check() -> Result<(), DynError> {
    let baseline = load_baseline()?;
    let tasks_manifest = formal_verification_dir().join("tasks/Cargo.toml");
    let test_count = run_cargo_test_suite(
        &tasks_manifest,
        &[
            "--bin",
            "ed25519-yao-formal-verification-tasks",
            "phase2b_review_subject::tests::",
        ],
        baseline.evidence.phase2b_review_subject_rust_tests,
        "Phase 2B review-subject builder suite",
    )?;
    println!(
        "{}; {test_count} builder tests passed",
        phase2b_review_subject::run_review_subject_check()?
    );
    Ok(())
}

fn run_internal_phase2b_review_subject_material() -> Result<(), DynError> {
    require_no_task_arguments()?;
    let material = phase2b_review_subject::run_review_subject_material()?;
    std::io::stdout().lock().write_all(&material)?;
    Ok(())
}

fn run_phase2b_independent_host_prepare() -> Result<(), DynError> {
    require_no_task_arguments()?;
    let prepared = phase2b_exit_evidence::prepare_independent_host_reproduction()?;
    std::io::stdout().lock().write_all(&prepared)?;
    Ok(())
}

fn run_phase2b_independent_host_finalize() -> Result<(), DynError> {
    require_no_task_arguments()?;
    let request = read_bounded_stdin(phase2b_exit_evidence::MAX_FINALIZE_REQUEST_BYTES)?;
    let finalized = phase2b_exit_evidence::finalize_independent_host_reproduction(&request)?;
    std::io::stdout().lock().write_all(&finalized)?;
    Ok(())
}

fn run_phase2b_independent_host_record_check() -> Result<(), DynError> {
    require_no_task_arguments()?;
    println!(
        "{}",
        phase2b_exit_evidence::run_independent_host_record_check()?
    );
    Ok(())
}

fn run_phase2b_review_approval_check() -> Result<(), DynError> {
    require_no_task_arguments()?;
    println!("{}", phase2b_exit_evidence::run_review_approval_check()?);
    Ok(())
}

fn read_bounded_stdin(maximum_bytes: usize) -> Result<Vec<u8>, DynError> {
    let limit = u64::try_from(maximum_bytes)? + 1;
    let mut input = Vec::new();
    std::io::stdin()
        .lock()
        .take(limit)
        .read_to_end(&mut input)?;
    if input.len() > maximum_bytes {
        return Err(Box::new(
            phase2b_exit_evidence::ExitEvidenceErrorV1::InputTooLarge,
        ));
    }
    Ok(input)
}

fn run_internal_phase2b_reproduction_material() -> Result<(), DynError> {
    require_no_task_arguments()?;
    let current_executable = env::current_exe()?;
    let reconciliation = capture_command(
        Command::new(current_executable).arg("phase2b-reconciliation-check"),
        "isolated independent-host Phase 2B reconciliation",
        false,
    )?;
    const EXPECTED_SUMMARY: &str = "phase2b-reconciliation-check ok: 5 cases, 6 Rust tests, 4 focused Python tests, and 24 total artifact-verifier tests";
    if reconciliation
        .lines()
        .filter(|line| *line == EXPECTED_SUMMARY)
        .count()
        != 1
    {
        return Err(
            "isolated independent-host reconciliation returned an unexpected summary".into(),
        );
    }
    let material = phase2b_review_subject::run_review_subject_material()?;
    std::io::stdout().lock().write_all(&material)?;
    Ok(())
}

fn require_no_task_arguments() -> Result<(), DynError> {
    if env::args_os().nth(2).is_some() {
        Err("this task accepts no arguments".into())
    } else {
        Ok(())
    }
}

fn run_constant_time_qualification() -> Result<(), DynError> {
    let baseline = load_baseline()?;
    let analyzer = resolve_constant_time_analyzer()?;
    let analyzer_root = analyzer
        .parent()
        .and_then(Path::parent)
        .ok_or("constant-time analyzer must be under a ct_analyzer directory")?;
    let uv_lock = analyzer_root.join("uv.lock");
    require_file(&uv_lock, "constant-time analyzer uv.lock")?;
    verify_sha256(
        &analyzer,
        &baseline.constant_time.analyzer_sha256,
        "constant-time analyzer",
    )?;
    verify_sha256(
        &uv_lock,
        &baseline.constant_time.uv_lock_sha256,
        "constant-time analyzer uv.lock",
    )?;

    let architecture = match env::consts::ARCH {
        "aarch64" => "arm64",
        "x86_64" => "x86_64",
        architecture => {
            return Err(format!(
                "constant-time qualification does not support host architecture `{architecture}`"
            )
            .into())
        }
    };
    let cargo = env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let uv = resolve_program("uv", "install uv for the pinned constant-time analyzer")?;
    let uv_version = capture_command(Command::new(&uv).arg("--version"), "uv --version", false)?;
    if uv_version.split_whitespace().nth(1) != Some(baseline.constant_time.uv_version.as_str()) {
        return Err(format!(
            "uv version mismatch: expected {}, received `{}`",
            baseline.constant_time.uv_version,
            uv_version.trim()
        )
        .into());
    }
    let fixture_manifest = constant_time_fixture_dir().join("Cargo.toml");
    require_file(
        &fixture_manifest,
        "constant-time qualification fixture manifest",
    )?;
    let temporary = TemporaryDirectory::create("constant-time-qualification")?;

    for optimization in ["0", "3"] {
        let target_dir = temporary.path().join(format!("o{optimization}"));
        run_command(
            Command::new(&cargo)
                .arg("rustc")
                .arg("--locked")
                .arg("--manifest-path")
                .arg(&fixture_manifest)
                .arg("--release")
                .arg("--lib")
                .env("CARGO_TARGET_DIR", &target_dir)
                .args(["--", "-C"])
                .arg(format!("opt-level={optimization}"))
                .arg("--emit=asm"),
            &format!("compile constant-time qualification fixtures at O{optimization}"),
        )?;
        let assembly = prepare_fixture_assembly(&find_fixture_assembly(&target_dir)?)?;
        let safe = analyze_constant_time_fixture(
            &uv,
            analyzer_root,
            &analyzer,
            architecture,
            &assembly,
            "ct_fixture_select",
        )?;
        if !safe.passed
            || safe.total_functions == 0
            || safe.total_instructions == 0
            || safe.error_count != 0
            || safe.warning_count != 0
        {
            return Err(format!(
                "branchless fixture failed constant-time qualification at O{optimization}: {} functions, {} instructions, {} errors, {} warnings",
                safe.total_functions, safe.total_instructions, safe.error_count, safe.warning_count
            )
            .into());
        }

        let vulnerable = analyze_constant_time_fixture(
            &uv,
            analyzer_root,
            &analyzer,
            architecture,
            &assembly,
            "ct_fixture_secret_divide",
        )?;
        if vulnerable.passed
            || vulnerable.total_functions == 0
            || vulnerable.total_instructions == 0
            || vulnerable.error_count == 0
        {
            return Err(format!(
                "variable-time fixture was not rejected at O{optimization}: {} functions, {} instructions, {} errors",
                vulnerable.total_functions, vulnerable.total_instructions, vulnerable.error_count
            )
            .into());
        }
    }

    println!(
        "constant-time-qualification ok: pinned analyzer distinguished safe and vulnerable {architecture} fixtures at O0 and O3"
    );
    Ok(())
}

fn resolve_constant_time_analyzer() -> Result<PathBuf, DynError> {
    let configured = if let Some(path) = env::var_os("CT_ANALYZER") {
        PathBuf::from(path)
    } else {
        let codex_home = env::var_os("CODEX_HOME")
            .map(PathBuf::from)
            .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".codex")))
            .ok_or("set CT_ANALYZER or CODEX_HOME to locate the constant-time analyzer")?;
        codex_home.join("skills/constant-time-analysis/ct_analyzer/analyzer.py")
    };
    require_file(&configured, "constant-time analyzer")?;
    Ok(configured.canonicalize()?)
}

fn find_fixture_assembly(target_dir: &Path) -> Result<PathBuf, DynError> {
    let deps = target_dir.join("release/deps");
    let mut matches = fs::read_dir(&deps)?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension().and_then(|extension| extension.to_str()) == Some("s")
                && path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with("ed25519_yao_constant_time_fixtures-"))
        })
        .collect::<Vec<_>>();
    matches.sort();
    match matches.as_slice() {
        [assembly] => Ok(assembly.clone()),
        _ => Err(format!(
            "expected one constant-time fixture assembly file under {}, found {}",
            deps.display(),
            matches.len()
        )
        .into()),
    }
}

fn prepare_fixture_assembly(assembly: &Path) -> Result<PathBuf, DynError> {
    if env::consts::OS != "macos" {
        return Ok(assembly.to_path_buf());
    }

    let source = fs::read_to_string(assembly)?;
    let normalized = source
        .lines()
        .filter(|line| {
            let trimmed = line.trim();
            !(trimmed.starts_with('L') && trimmed.ends_with(':'))
        })
        .collect::<Vec<_>>()
        .join("\n");
    let output = assembly.with_extension("normalized.s");
    fs::write(&output, normalized)?;
    Ok(output)
}

fn analyze_constant_time_fixture(
    uv: &Path,
    analyzer_root: &Path,
    analyzer: &Path,
    architecture: &str,
    assembly: &Path,
    function: &str,
) -> Result<ConstantTimeReport, DynError> {
    let output = Command::new(uv)
        .arg("run")
        .arg("--project")
        .arg(analyzer_root)
        .arg(analyzer)
        .args(["--assembly", "--arch", architecture, "--warnings", "--func"])
        .arg(format!("^{function}$|^_{function}$"))
        .arg("--json")
        .arg(assembly)
        .output()?;
    let stdout = std::str::from_utf8(&output.stdout)?;
    serde_json::from_str(stdout).map_err(|error| {
        format!(
            "constant-time analyzer returned invalid JSON for `{function}`: {error}; stdout `{}`; stderr `{}`",
            stdout.trim(),
            String::from_utf8_lossy(&output.stderr).trim()
        )
        .into()
    })
}

fn verify_sha256(path: &Path, expected: &str, label: &str) -> Result<(), DynError> {
    let digest = Sha256::digest(fs::read(path)?);
    let actual = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    if actual == expected {
        Ok(())
    } else {
        Err(format!("{label} digest mismatch: expected {expected}, received {actual}").into())
    }
}

fn run_cargo_test_suite(
    manifest: &Path,
    selectors: &[&str],
    expected_count: usize,
    label: &str,
) -> Result<usize, DynError> {
    let actual_count = count_cargo_tests(manifest, selectors)?;
    require_exact_count(label, actual_count, expected_count)?;

    let cargo = env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let mut command = Command::new(cargo);
    command
        .arg("test")
        .arg("--locked")
        .arg("--manifest-path")
        .arg(manifest)
        .args(selectors);
    run_command(&mut command, label)?;
    Ok(actual_count)
}

fn count_cargo_tests(manifest: &Path, selectors: &[&str]) -> Result<usize, DynError> {
    let cargo = env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let mut command = Command::new(cargo);
    command
        .arg("test")
        .arg("--locked")
        .arg("--manifest-path")
        .arg(manifest)
        .args(selectors)
        .args(["--", "--list", "--format", "terse"]);
    let output = capture_command(&mut command, "list Rust tests", false)?;
    Ok(output
        .lines()
        .filter(|line| line.trim_end().ends_with(": test"))
        .count())
}

fn count_prefixed_python_tests(path: &Path, prefix: &str) -> Result<usize, DynError> {
    let source = fs::read_to_string(path)?;
    Ok(source
        .lines()
        .filter(|line| line.trim_start().starts_with(prefix))
        .count())
}

fn run_cargo_capture(args: &[&str], context: &str) -> Result<String, DynError> {
    let cargo = env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    capture_command(Command::new(cargo).args(args), context, true)
}

fn run_command(command: &mut Command, context: &str) -> Result<(), DynError> {
    let status = command.status()?;
    ensure_success(context, status)
}

fn capture_command(command: &mut Command, context: &str, relay: bool) -> Result<String, DynError> {
    let output = command.output()?;
    if !output.status.success() {
        let diagnostics = combined_output(&output)?;
        return Err(format!(
            "{context} exited with status {}:\n{}",
            output.status,
            diagnostics.trim()
        )
        .into());
    }
    if relay {
        relay_output(&output)?;
    }
    combined_output(&output)
}

fn relay_output(output: &Output) -> Result<(), DynError> {
    let stdout = std::str::from_utf8(&output.stdout)?;
    let stderr = std::str::from_utf8(&output.stderr)?;
    print!("{stdout}");
    eprint!("{stderr}");
    Ok(())
}

fn combined_output(output: &Output) -> Result<String, DynError> {
    let stdout = std::str::from_utf8(&output.stdout)?;
    let stderr = std::str::from_utf8(&output.stderr)?;
    Ok(format!("{stdout}\n{stderr}"))
}

fn ensure_success(context: &str, status: ExitStatus) -> Result<(), DynError> {
    if status.success() {
        Ok(())
    } else {
        Err(format!("{context} exited with status {status}").into())
    }
}

fn require_exact_count(label: &str, actual: usize, expected: usize) -> Result<(), DynError> {
    if actual == expected && actual > 0 {
        Ok(())
    } else {
        Err(
            format!("{label} count mismatch: expected nonzero {expected}, received {actual}")
                .into(),
        )
    }
}

fn resolve_program(program: &str, remediation: &str) -> Result<PathBuf, DynError> {
    for directory in env::var_os("PATH")
        .into_iter()
        .flat_map(|paths| env::split_paths(&paths).collect::<Vec<_>>())
    {
        let candidate = directory.join(program);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    Err(format!("required program `{program}` is unavailable; {remediation}").into())
}

fn require_file(path: &Path, description: &str) -> Result<(), DynError> {
    if path.is_file() {
        Ok(())
    } else {
        Err(format!("missing {description} at {}", path.display()).into())
    }
}

fn verify_git_checkout(directory: &Path, pin: &SourcePin, tool: &str) -> Result<(), DynError> {
    if !directory.join(".git").exists() {
        return Err(format!(
            "missing pinned {tool} checkout at {}; run lean-boundary/scripts/setup-aeneas.sh",
            directory.display()
        )
        .into());
    }
    let revision = capture_command(
        Command::new("git")
            .arg("-C")
            .arg(directory)
            .args(["rev-parse", "HEAD"]),
        &format!("read {tool} revision"),
        false,
    )?;
    if revision.trim() != pin.rev {
        return Err(format!(
            "{tool} revision mismatch: expected {}, received {}",
            pin.rev,
            revision.trim()
        )
        .into());
    }
    let remote = capture_command(
        Command::new("git")
            .arg("-C")
            .arg(directory)
            .args(["remote", "get-url", "origin"]),
        &format!("read {tool} origin"),
        false,
    )?;
    if remote.trim() != pin.repo {
        return Err(format!(
            "{tool} origin mismatch: expected {}, received {}",
            pin.repo,
            remote.trim()
        )
        .into());
    }
    let status = capture_command(
        Command::new("git").arg("-C").arg(directory).args([
            "status",
            "--porcelain",
            "--untracked-files=no",
        ]),
        &format!("read {tool} checkout status"),
        false,
    )?;
    if !status.trim().is_empty() {
        return Err(format!("{tool} source checkout contains tracked modifications").into());
    }
    Ok(())
}

fn verify_tool_binary(binary: &Path, source: &Path, tool: &str) -> Result<(), DynError> {
    require_file(binary, &format!("{tool} binary"))?;
    let canonical_binary = binary.canonicalize()?;
    let canonical_source = source.canonicalize()?;
    if !canonical_binary.starts_with(&canonical_source) {
        return Err(format!(
            "{tool} binary {} is outside pinned source checkout {}",
            canonical_binary.display(),
            canonical_source.display()
        )
        .into());
    }
    Ok(())
}

fn verify_same_tool_bundle(verus: &Path, cargo_verus: &Path) -> Result<(), DynError> {
    let canonical_verus = verus.canonicalize()?;
    let canonical_cargo_verus = cargo_verus.canonicalize()?;
    if canonical_verus.parent() != canonical_cargo_verus.parent() {
        return Err(format!(
            "verus and cargo-verus must come from one release bundle: {} vs {}",
            canonical_verus.display(),
            canonical_cargo_verus.display()
        )
        .into());
    }
    Ok(())
}

fn verify_vstd_pin(baseline: &VerificationBaseline) -> Result<(), DynError> {
    let cargo_toml = fs::read_to_string(verus_manifest())?;
    let expected = format!("vstd = \"={}\"", baseline.verus.vstd);
    if !cargo_toml.lines().any(|line| line.trim() == expected) {
        return Err(format!("Verus manifest must contain exact pin `{expected}`").into());
    }
    Ok(())
}

fn verify_lean_toolchain(
    baseline: &VerificationBaseline,
    directory: &Path,
) -> Result<(), DynError> {
    let configured = fs::read_to_string(directory.join("lean-toolchain"))?;
    if configured.trim() != baseline.lean.toolchain {
        return Err(format!(
            "Lean toolchain mismatch in {}: expected {}, received {}",
            directory.display(),
            baseline.lean.toolchain,
            configured.trim()
        )
        .into());
    }
    let lake = resolve_program("lake", "install Lean through elan")?;
    let version = capture_command(
        Command::new(lake).arg("--version").current_dir(directory),
        "lake --version",
        false,
    )?;
    let expected_version = baseline
        .lean
        .toolchain
        .rsplit(':')
        .next()
        .ok_or("Lean toolchain has no version component")?;
    if !version.contains(expected_version.trim_start_matches('v')) {
        return Err(format!(
            "Lake did not select Lean {expected_version}; received `{}`",
            version.trim()
        )
        .into());
    }
    Ok(())
}

fn load_baseline() -> Result<VerificationBaseline, DynError> {
    let source = fs::read_to_string(baseline_path())?;
    let baseline: VerificationBaseline = toml::from_str(&source)?;
    validate_baseline(&baseline)?;
    Ok(baseline)
}

fn validate_baseline(baseline: &VerificationBaseline) -> Result<(), DynError> {
    validate_source_pin(&baseline.aeneas, "Aeneas")?;
    validate_source_pin(&baseline.charon, "Charon")?;
    validate_source_coordinates(
        &baseline.constant_time.repo,
        &baseline.constant_time.rev,
        "constant-time analyzer",
    )?;
    if baseline.verus.release.is_empty()
        || baseline.verus.vstd.is_empty()
        || baseline.lean.toolchain.is_empty()
        || baseline.extraction.crate_path.is_empty()
        || baseline.python.minimum_major == 0
        || baseline.constant_time.uv_version.is_empty()
        || !is_sha256_hex(&baseline.constant_time.analyzer_sha256)
        || !is_sha256_hex(&baseline.constant_time.uv_lock_sha256)
        || !is_sha256_hex(&baseline.evidence.phase2b_exit_evidence_spec_sha256)
        || !is_sha256_hex(&baseline.evidence.benchmark_manifest_digest)
        || !is_sha256_hex(&baseline.evidence.benchmark_bundle_index_digest)
    {
        return Err("verification baseline contains an empty tool or crate pin".into());
    }
    let mut unique_functions = HashSet::new();
    for function in &baseline.extraction.functions {
        if function.is_empty() || !unique_functions.insert(function) {
            return Err("Aeneas extraction scope contains an empty or duplicate function".into());
        }
    }
    require_exact_count(
        "Aeneas extraction scope",
        baseline.extraction.functions.len(),
        baseline.evidence.aeneas_extracted_functions,
    )?;
    let counts = [
        baseline.evidence.reference_spec_documents,
        baseline.evidence.vector_cases,
        baseline.evidence.kdf_vector_cases,
        baseline.evidence.ceremony_context_vector_cases,
        baseline.evidence.lifecycle_continuity_vector_cases,
        baseline.evidence.provenance_vector_cases,
        baseline.evidence.output_sharing_vector_cases,
        baseline.evidence.semantic_lifecycle_vector_cases,
        baseline.evidence.output_party_view_vector_cases,
        baseline.evidence.activation_delivery_vector_cases,
        baseline
            .evidence
            .activation_recipient_party_view_vector_cases,
        baseline.evidence.evaluation_input_party_view_vector_cases,
        baseline.evidence.uniform_abort_vector_cases,
        baseline.evidence.evaluator_abort_view_vector_cases,
        baseline.evidence.export_delivery_vector_cases,
        baseline
            .evidence
            .recovery_credential_transition_vector_cases,
        baseline
            .evidence
            .export_evaluator_authorization_vector_cases,
        baseline
            .evidence
            .registration_evaluator_admission_vector_cases,
        baseline.evidence.recovery_evaluator_admission_vector_cases,
        baseline.evidence.refresh_evaluator_admission_vector_cases,
        baseline.evidence.semantic_frame_party_view_vector_cases,
        baseline.evidence.differential_vector_cases,
        baseline.evidence.independent_verifier_tests,
        baseline.evidence.ceremony_context_python_tests,
        baseline.evidence.output_sharing_python_tests,
        baseline.evidence.semantic_lifecycle_python_tests,
        baseline.evidence.output_party_view_python_tests,
        baseline.evidence.activation_delivery_python_tests,
        baseline
            .evidence
            .activation_recipient_party_view_python_tests,
        baseline.evidence.evaluation_input_party_view_python_tests,
        baseline.evidence.uniform_abort_python_tests,
        baseline.evidence.evaluator_abort_view_python_tests,
        baseline.evidence.export_delivery_python_tests,
        baseline
            .evidence
            .recovery_credential_transition_python_tests,
        baseline
            .evidence
            .export_evaluator_authorization_python_tests,
        baseline
            .evidence
            .registration_evaluator_admission_python_tests,
        baseline.evidence.recovery_evaluator_admission_python_tests,
        baseline.evidence.refresh_evaluator_admission_python_tests,
        baseline.evidence.semantic_frame_party_view_python_tests,
        baseline.evidence.phase2b_reconciliation_python_tests,
        baseline.evidence.artifact_python_tests,
        baseline.evidence.artifact_vector_cases,
        baseline.evidence.production_rust_tests,
        baseline.evidence.generator_rust_tests,
        baseline.evidence.circuit_rust_tests,
        baseline.evidence.artifact_bundle_rust_tests,
        baseline.evidence.artifact_filesystem_policy_rust_tests,
        baseline.evidence.joint_refresh_delta_rust_tests,
        baseline.evidence.registration_reference_rust_tests,
        baseline.evidence.recovery_reference_rust_tests,
        baseline.evidence.refresh_reference_rust_tests,
        baseline.evidence.export_reference_rust_tests,
        baseline.evidence.output_sharing_core_rust_tests,
        baseline.evidence.output_sharing_vector_rust_tests,
        baseline.evidence.semantic_lifecycle_vector_rust_tests,
        baseline.evidence.output_party_view_core_rust_tests,
        baseline.evidence.output_party_view_guard_rust_tests,
        baseline.evidence.output_party_view_vector_rust_tests,
        baseline.evidence.activation_delivery_vector_rust_tests,
        baseline
            .evidence
            .activation_recipient_party_view_core_rust_tests,
        baseline
            .evidence
            .activation_recipient_party_view_guard_rust_tests,
        baseline
            .evidence
            .activation_recipient_party_view_vector_rust_tests,
        baseline
            .evidence
            .evaluation_input_party_view_core_rust_tests,
        baseline
            .evidence
            .evaluation_input_party_view_guard_rust_tests,
        baseline
            .evidence
            .evaluation_input_party_view_vector_rust_tests,
        baseline.evidence.uniform_abort_vector_rust_tests,
        baseline.evidence.evaluator_abort_view_vector_rust_tests,
        baseline.evidence.export_delivery_core_rust_tests,
        baseline.evidence.export_delivery_vector_rust_tests,
        baseline.evidence.activation_delivery_core_rust_tests,
        baseline.evidence.authenticated_store_rust_tests,
        baseline.evidence.signing_worker_activation_rust_tests,
        baseline.evidence.refresh_promotion_rust_tests,
        baseline.evidence.recovery_credential_transition_rust_tests,
        baseline
            .evidence
            .recovery_credential_transition_vector_rust_tests,
        baseline.evidence.export_evaluator_authorization_rust_tests,
        baseline
            .evidence
            .export_evaluator_authorization_vector_rust_tests,
        baseline
            .evidence
            .registration_evaluator_admission_rust_tests,
        baseline
            .evidence
            .registration_evaluator_admission_vector_rust_tests,
        baseline.evidence.recovery_evaluator_admission_rust_tests,
        baseline
            .evidence
            .recovery_evaluator_admission_vector_rust_tests,
        baseline.evidence.refresh_evaluator_admission_rust_tests,
        baseline
            .evidence
            .refresh_evaluator_admission_vector_rust_tests,
        baseline.evidence.semantic_frame_core_rust_tests,
        baseline.evidence.semantic_trace_boundary_rust_tests,
        baseline
            .evidence
            .semantic_frame_party_view_vector_rust_tests,
        baseline.evidence.phase2b_reconciliation_rust_tests,
        baseline.evidence.phase2b_exit_evidence_rust_tests,
        baseline.evidence.phase2b_review_subject_rust_tests,
        baseline.evidence.phase2b_protected_inputs_rust_tests,
        baseline.evidence.benchmark_manifest_rust_tests,
        baseline.evidence.benchmark_manifest_bytes,
        baseline.evidence.benchmark_bundle_index_bytes,
        baseline.evidence.anti_drift_tests,
        baseline.evidence.verus_obligations,
        baseline.evidence.lean_model_theorems,
    ];
    if counts.contains(&0) {
        return Err("verification baseline contains a zero evidence count".into());
    }
    require_file(
        &repository_root()
            .join(&baseline.extraction.crate_path)
            .join("Cargo.toml"),
        "configured Aeneas extraction crate manifest",
    )?;
    Ok(())
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn validate_source_pin(pin: &SourcePin, tool: &str) -> Result<(), DynError> {
    validate_source_coordinates(&pin.repo, &pin.rev, tool)
}

fn validate_source_coordinates(repo: &str, rev: &str, tool: &str) -> Result<(), DynError> {
    if !repo.starts_with("https://github.com/") {
        return Err(format!("{tool} repository pin must use an HTTPS GitHub URL").into());
    }
    if rev.len() != 40 || !rev.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!("{tool} revision must be a full 40-character Git hash").into());
    }
    Ok(())
}

fn aeneas_artifact_paths() -> [PathBuf; 2] {
    [
        lean_boundary_dir().join("Ed25519Yao/Types.lean"),
        lean_boundary_dir().join("Ed25519Yao/Funs.lean"),
    ]
}

fn snapshot_artifacts(paths: &[PathBuf]) -> Result<Vec<ArtifactSnapshot>, DynError> {
    paths
        .iter()
        .map(|path| {
            require_file(path, "checked-in Aeneas artifact")?;
            Ok(ArtifactSnapshot {
                path: path.clone(),
                bytes: fs::read(path)?,
            })
        })
        .collect()
}

fn assert_artifacts_unchanged(snapshots: &[ArtifactSnapshot]) -> Result<(), DynError> {
    for snapshot in snapshots {
        let regenerated = fs::read(&snapshot.path)?;
        if regenerated != snapshot.bytes {
            return Err(format!(
                "Aeneas artifact drifted after regeneration: {}",
                snapshot.path.display()
            )
            .into());
        }
    }
    Ok(())
}

fn verify_generated_extraction_scope(baseline: &VerificationBaseline) -> Result<(), DynError> {
    let generated = fs::read_to_string(lean_boundary_dir().join("Ed25519Yao/Funs.lean"))?;
    let boundary = fs::read_to_string(lean_boundary_dir().join("Ed25519YaoBoundary/Scope.lean"))?;
    for function in &baseline.extraction.functions {
        let function_name = function
            .rsplit("::")
            .next()
            .ok_or("extraction function has no Rust item name")?;
        let generated_declaration = format!("def {function_name}\n");
        if !generated.contains(&generated_declaration) {
            return Err(
                format!("generated Lean is missing scoped function `{function_name}`").into(),
            );
        }
        let lean_name = function.replace("::", ".");
        if !boundary.contains(&lean_name) {
            return Err(format!(
                "Lean boundary does not reference generated function `{lean_name}`"
            )
            .into());
        }
    }
    Ok(())
}

fn count_lean_theorems(path: &Path) -> Result<usize, DynError> {
    let source = fs::read_to_string(path)?;
    Ok(source
        .lines()
        .filter(|line| line.trim_start().starts_with("theorem "))
        .count())
}

fn parse_verus_verified_count(output: &str) -> Result<usize, DynError> {
    let result_line = output
        .lines()
        .find(|line| line.contains("verification results::"))
        .ok_or("Verus output did not contain a verification result count")?;
    if !result_line.contains(", 0 errors") {
        return Err(format!("Verus reported a nonzero error count: {result_line}").into());
    }
    let count = result_line
        .split("verification results::")
        .nth(1)
        .and_then(|result| result.split_whitespace().next())
        .ok_or("Verus result line did not contain a verified count")?
        .parse()?;
    Ok(count)
}

fn verify_python_version(python: &Path, pin: &PythonPin) -> Result<(), DynError> {
    let output = capture_command(
        Command::new(python).arg("--version"),
        "python3 --version",
        false,
    )?;
    let version = output
        .split_whitespace()
        .find(|value| {
            value
                .chars()
                .next()
                .is_some_and(|first| first.is_ascii_digit())
        })
        .ok_or("python3 --version did not report a version number")?;
    let mut components = version.split('.');
    let major: usize = components
        .next()
        .ok_or("Python version is missing its major component")?
        .parse()?;
    let minor: usize = components
        .next()
        .ok_or("Python version is missing its minor component")?
        .parse()?;
    if (major, minor) < (pin.minimum_major, pin.minimum_minor) {
        return Err(format!(
            "Python version mismatch: require at least {}.{}, received {major}.{minor}",
            pin.minimum_major, pin.minimum_minor
        )
        .into());
    }
    Ok(())
}

fn parse_python_test_count(output: &str) -> Result<usize, DynError> {
    let result_line = output
        .lines()
        .find(|line| line.trim_start().starts_with("Ran "))
        .ok_or("Python unittest output did not report a test count")?;
    let count = result_line
        .split_whitespace()
        .nth(1)
        .ok_or("Python unittest result is missing its test count")?
        .parse()?;
    Ok(count)
}

fn require_reported_case_count(output: &str, expected: usize, label: &str) -> Result<(), DynError> {
    let expected_summary = format!("verified {expected} independent Ed25519 Yao vector cases");
    if expected > 0 && output.contains(&expected_summary) {
        Ok(())
    } else {
        Err(format!("{label} output did not contain `{expected_summary}`").into())
    }
}

fn reject_forbidden_lean_declarations() -> Result<(), DynError> {
    let mut lean_files = Vec::new();
    collect_source_files(
        &formal_verification_dir(),
        "lean",
        &[".lake", "tools"],
        &mut lean_files,
    )?;
    reject_tokens(&lean_files, &["sorry", "admit", "axiom"], "Lean")?;
    println!(
        "Lean source guard ok: {} project-owned files contain no sorry, admit, or axiom token",
        lean_files.len()
    );
    Ok(())
}

fn reject_forbidden_verus_declarations() -> Result<(), DynError> {
    let mut rust_files = Vec::new();
    collect_source_files(&verus_dir(), "rs", &["target"], &mut rust_files)?;
    reject_tokens(
        &rust_files,
        &[
            "assume",
            "assume_specification",
            "external_body",
            "admit",
            "axiom",
        ],
        "Verus",
    )?;
    println!(
        "Verus source guard ok: {} mirror files contain no unchecked-declaration token",
        rust_files.len()
    );
    Ok(())
}

fn collect_source_files(
    directory: &Path,
    extension: &str,
    skipped_directories: &[&str],
    files: &mut Vec<PathBuf>,
) -> Result<(), DynError> {
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        if path.is_dir() {
            let skipped = path.file_name().is_some_and(|name| {
                skipped_directories
                    .iter()
                    .any(|skipped_name| name == *skipped_name)
            });
            if !skipped {
                collect_source_files(&path, extension, skipped_directories, files)?;
            }
        } else if path
            .extension()
            .is_some_and(|candidate| candidate == extension)
        {
            files.push(path);
        }
    }
    Ok(())
}

fn reject_tokens(files: &[PathBuf], forbidden: &[&str], owner: &str) -> Result<(), DynError> {
    if files.is_empty() {
        return Err(format!("no project-owned {owner} source files were found").into());
    }
    for file in files {
        let source = fs::read_to_string(file)?;
        for token in
            source.split(|character: char| !character.is_alphanumeric() && character != '_')
        {
            if forbidden.contains(&token) {
                return Err(format!(
                    "forbidden {owner} declaration token `{token}` in {}",
                    file.display()
                )
                .into());
            }
        }
    }
    Ok(())
}

fn path_string(path: &Path) -> Result<&str, DynError> {
    path.to_str()
        .ok_or_else(|| format!("path is not valid UTF-8: {}", path.display()).into())
}

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../..")
        .canonicalize()
        .expect("repository root must be readable")
}

fn production_manifest() -> PathBuf {
    repository_root().join("crates/ed25519-yao/Cargo.toml")
}

fn generator_dir(baseline: &VerificationBaseline) -> PathBuf {
    repository_root().join(&baseline.extraction.crate_path)
}

fn generator_manifest(baseline: &VerificationBaseline) -> PathBuf {
    generator_dir(baseline).join("Cargo.toml")
}

fn artifact_filesystem_policy_manifest(baseline: &VerificationBaseline) -> PathBuf {
    generator_dir(baseline).join("artifact-fs-policy/Cargo.toml")
}

fn independent_verifier_dir() -> PathBuf {
    repository_root().join("tools/ed25519-yao-verifier")
}

fn formal_verification_dir() -> PathBuf {
    repository_root().join("crates/ed25519-yao/formal-verification")
}

fn constant_time_fixture_dir() -> PathBuf {
    formal_verification_dir().join("constant-time-fixtures")
}

fn baseline_path() -> PathBuf {
    formal_verification_dir().join("toolchain.toml")
}

fn verus_dir() -> PathBuf {
    formal_verification_dir().join("verus")
}

fn verus_manifest() -> PathBuf {
    verus_dir().join("Cargo.toml")
}

fn lean_model_dir() -> PathBuf {
    formal_verification_dir().join("lean-model")
}

fn lean_boundary_dir() -> PathBuf {
    formal_verification_dir().join("lean-boundary")
}
