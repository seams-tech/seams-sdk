//! Deterministic construction of the host-only Phase 2B review subject.

use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

use ed25519_yao_generator::{
    build_provisional_artifact_bundle_v1, build_provisional_benchmark_manifest_v1,
    canonical_phase2b_core_reconciliation_corpus_json_bytes_v1,
    parse_canonical_phase2b_core_reconciliation_corpus_json_v1,
    ProvisionalBenchmarkManifestComponentV1, FIXED_SHA512_32_BIT_ORDER_V1,
    PROVISIONAL_ARTIFACT_BUNDLE_INDEX_FILE_V1, PROVISIONAL_BENCHMARK_COMPILER_CONTRACT_V1,
    PROVISIONAL_BENCHMARK_MANIFEST_CANONICAL_BYTES_V1,
    PROVISIONAL_BENCHMARK_MANIFEST_CANONICAL_DIGEST_V1, PROVISIONAL_BENCHMARK_MANIFEST_MAGIC_V1,
    PROVISIONAL_BENCHMARK_WIRE_ORDER_V1,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::phase2b_protected_inputs::{CHALLENGE_ENV, POLICY_DIGEST_ENV, POLICY_JSON_ENV};
use crate::{repository_root, TemporaryDirectory};

const SUBJECT_SCHEMA: &str = "seams:router-ab:ed25519-yao:phase2b-review-subject:v1";
const PROTOCOL_ID: &str = "router_ab_ed25519_yao_v1";
const SUBJECT_SCOPE: &str = "benchmark_only_phase2b_deterministic_core_review_subject_v1";
const SUBJECT_DIGEST_DOMAIN: &[u8] =
    b"seams/router-ab/ed25519-yao/phase2b-review-subject-digest/v1";
const MATERIAL_SCHEMA: &str = "seams:router-ab:ed25519-yao:phase2b-review-subject-material:v1";
const INTERNAL_MATERIAL_COMMAND: &str = "__phase2b-review-subject-material-v1";
pub(crate) const INTERNAL_REPRODUCTION_MATERIAL_COMMAND: &str =
    "__phase2b-independent-host-material-v1";
const CHECKOUT_STATE: &str = "clean_exact_commit";
const RECONCILIATION_PATH: &str =
    "tools/ed25519-yao-generator/vectors/ed25519-yao-phase2b-core-reconciliation-v1.json";
const RECONCILIATION_SCHEMA: &str = "seams:router-ab:ed25519-yao:phase2b-core-reconciliation:v1";
const RECONCILIATION_SCOPE: &str = "benchmark_only_phase2b_core_cross_corpus_reconciliation_v1";
const BUNDLE_INDEX_DIGEST: [u8; 32] = [
    0xaa, 0x62, 0xb8, 0x3b, 0x38, 0x16, 0x3b, 0xf8, 0x98, 0xc9, 0x00, 0x84, 0xf2, 0xeb, 0x25, 0xdf,
    0x1c, 0x95, 0xba, 0x41, 0x27, 0x4d, 0x0f, 0x78, 0x26, 0x25, 0x0f, 0x91, 0x68, 0xb8, 0x0d, 0xb1,
];

const AUTHORITATIVE_SPECIFICATIONS: [&str; 11] = [
    "tools/ed25519-yao-generator/docs/fixed-reference-v1.md",
    "tools/ed25519-yao-generator/docs/circuit-ir-v1.md",
    "tools/ed25519-yao-generator/docs/benchmark-manifest-v1.md",
    "tools/ed25519-yao-generator/docs/evaluation-input-party-views-v1.md",
    "tools/ed25519-yao-generator/docs/output-party-views-v1.md",
    "tools/ed25519-yao-generator/docs/semantic-frame-party-views-v1.md",
    "tools/ed25519-yao-generator/docs/registration-evaluator-admission-v1.md",
    "tools/ed25519-yao-generator/docs/recovery-evaluator-admission-v1.md",
    "tools/ed25519-yao-generator/docs/refresh-evaluator-admission-v1.md",
    "tools/ed25519-yao-generator/docs/export-evaluator-authorization-v1.md",
    "tools/ed25519-yao-generator/docs/phase2b-core-reconciliation-v1.md",
];

const EXPLICIT_NONCLAIMS: [&str; 10] = [
    "production_artifact_authority_absent",
    "selected_security_profile_absent",
    "garbling_and_ot_unimplemented",
    "randomized_output_protection_unimplemented",
    "simulator_and_security_experiment_unimplemented",
    "runtime_frame_and_transport_encoding_absent",
    "durable_lifecycle_and_replay_semantics_absent",
    "production_constant_time_and_erasure_unclaimed",
    "independent_operator_reproducibility_unclaimed",
    "reviewer_approval_absent",
];

#[derive(Debug)]
pub(crate) enum ReviewSubjectErrorV1 {
    DirtyCheckout,
    Command(&'static str),
    InvalidUtf8(&'static str),
    InvalidHex(&'static str),
    InvalidRepositoryIdentity,
    ChangedCheckout,
    InvalidMaterialSource,
    InvalidMaterialSubject,
    NonCanonicalMaterial,
    InvalidCertificate,
    InvalidCorpusCommitment,
    InvalidArtifactObservation,
    Io(std::io::Error),
    Json(serde_json::Error),
    Artifact(String),
}

impl fmt::Display for ReviewSubjectErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DirtyCheckout => {
                formatter.write_str("Phase 2B review subject requires a clean checkout")
            }
            Self::Command(command) => write!(
                formatter,
                "Phase 2B review-subject command failed: {command}"
            ),
            Self::InvalidUtf8(field) => write!(
                formatter,
                "Phase 2B review-subject field is not UTF-8: {field}"
            ),
            Self::InvalidHex(field) => write!(
                formatter,
                "Phase 2B review-subject field is not canonical lowercase hex: {field}"
            ),
            Self::InvalidRepositoryIdentity => {
                formatter.write_str("Phase 2B repository identity is invalid")
            }
            Self::ChangedCheckout => {
                formatter.write_str("Phase 2B invoking checkout changed during construction")
            }
            Self::InvalidMaterialSource => {
                formatter.write_str("isolated Phase 2B material source does not match candidate")
            }
            Self::InvalidMaterialSubject => {
                formatter.write_str("isolated Phase 2B material subject is invalid")
            }
            Self::NonCanonicalMaterial => {
                formatter.write_str("isolated Phase 2B material is not canonical JSON")
            }
            Self::InvalidCertificate => {
                formatter.write_str("Phase 2B reconciliation certificate is invalid")
            }
            Self::InvalidCorpusCommitment => {
                formatter.write_str("Phase 2B corpus commitment does not match fixed bytes")
            }
            Self::InvalidArtifactObservation => formatter
                .write_str("Phase 2B artifact observation does not match the checked bundle"),
            Self::Io(error) => write!(formatter, "Phase 2B review-subject I/O failed: {error}"),
            Self::Json(error) => write!(formatter, "Phase 2B review-subject JSON failed: {error}"),
            Self::Artifact(error) => {
                write!(formatter, "Phase 2B artifact construction failed: {error}")
            }
        }
    }
}

impl std::error::Error for ReviewSubjectErrorV1 {}

impl From<std::io::Error> for ReviewSubjectErrorV1 {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<serde_json::Error> for ReviewSubjectErrorV1 {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReviewSubjectPayloadV1 {
    schema: String,
    protocol_id: String,
    evidence_scope: String,
    source: ReviewSubjectSourceV1,
    toolchain_commitments: ToolchainCommitmentsV1,
    authoritative_specifications: Vec<FileCommitmentV1>,
    benchmark_manifest_binding: BenchmarkManifestBindingV1,
    reconciliation_certificate_binding: ReconciliationCertificateBindingV1,
    phase1_corpus_commitments: Vec<Phase1CorpusCommitmentV1>,
    explicit_nonclaims: Vec<String>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReviewSubjectV1 {
    schema: String,
    protocol_id: String,
    evidence_scope: String,
    source: ReviewSubjectSourceV1,
    toolchain_commitments: ToolchainCommitmentsV1,
    authoritative_specifications: Vec<FileCommitmentV1>,
    benchmark_manifest_binding: BenchmarkManifestBindingV1,
    reconciliation_certificate_binding: ReconciliationCertificateBindingV1,
    phase1_corpus_commitments: Vec<Phase1CorpusCommitmentV1>,
    explicit_nonclaims: Vec<String>,
    subject_digest_hex: String,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ReviewSubjectSourceV1 {
    repository_commit_hex: String,
    repository_tree_hex: String,
    source_archive_sha256_hex: String,
    checkout_state: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ToolchainCommitmentsV1 {
    generator_cargo_lock_sha256_hex: String,
    task_runner_cargo_lock_sha256_hex: String,
    formal_toolchain_sha256_hex: String,
    rustc_version_verbose_sha256_hex: String,
    cargo_version_sha256_hex: String,
    python_version_sha256_hex: String,
    git_version_sha256_hex: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileCommitmentV1 {
    path: String,
    canonical_bytes: u64,
    sha256_hex: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BenchmarkManifestBindingV1 {
    manifest_magic: String,
    manifest_canonical_bytes: u64,
    manifest_digest_hex: String,
    compiler_contract: String,
    bit_order: String,
    wire_order: String,
    bundle_index_file: String,
    bundle_index_canonical_bytes: u64,
    bundle_index_digest_hex: String,
    components: Vec<BenchmarkComponentBindingV1>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BenchmarkComponentBindingV1 {
    component_kind: String,
    component_tag: u8,
    ir_file: String,
    schedule_file: String,
    input_schema: String,
    output_schema: String,
    ir_digest_hex: String,
    schedule_digest_hex: String,
    circuit_metrics: CircuitMetricsV1,
    schedule_metrics: ScheduleMetricsV1,
    passive_half_gates_table_bytes: u64,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CircuitMetricsV1 {
    input_wire_count: u64,
    output_wire_count: u64,
    wire_count: u64,
    and_gate_count: u64,
    xor_gate_count: u64,
    inversion_gate_count: u64,
    total_gate_count: u64,
    circuit_depth: u64,
    and_depth: u64,
    canonical_ir_bytes: u64,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScheduleMetricsV1 {
    input_wire_count: u64,
    output_wire_count: u64,
    scheduled_gate_count: u64,
    reusable_slot_count: u64,
    slot_width_bytes: u8,
    gate_record_width_bytes: u8,
    canonical_schedule_bytes: u64,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReconciliationCertificateBindingV1 {
    path: String,
    canonical_bytes: u64,
    sha256_hex: String,
    case_count: u64,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Phase1CorpusCommitmentV1 {
    path: String,
    schema: String,
    case_count: u64,
    canonical_bytes: u64,
    sha256_hex: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReconciliationProjectionV1 {
    schema: String,
    protocol_id: String,
    evidence_scope: String,
    benchmark_manifest_binding: serde_json::Value,
    phase1_corpus_commitments: Vec<Phase1CorpusCommitmentV1>,
    mapping_contracts: serde_json::Value,
    cases: Vec<serde_json::Value>,
    explicit_nonclaims: Vec<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReviewSubjectMaterialEnvelopeV1 {
    schema: String,
    subject: ReviewSubjectV1,
    observations: MaterialObservationsV1,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MaterialObservationsV1 {
    manifest_canonical_bytes: u64,
    manifest_digest_hex: String,
    bundle_index_canonical_bytes: u64,
    bundle_index_digest_hex: String,
    artifact_entries: Vec<MaterialArtifactEntryV1>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MaterialArtifactEntryV1 {
    tag: u8,
    filename: String,
    canonical_bytes: u64,
    sha256_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FreshArtifactObservationsV1 {
    pub(crate) manifest_canonical_bytes: u64,
    pub(crate) manifest_digest: [u8; 32],
    pub(crate) bundle_index_canonical_bytes: u64,
    pub(crate) bundle_index_digest: [u8; 32],
    pub(crate) artifact_entries: Vec<FreshArtifactEntryV1>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FreshArtifactEntryV1 {
    pub(crate) tag: u8,
    pub(crate) filename: String,
    pub(crate) canonical_bytes: u64,
    pub(crate) sha256: [u8; 32],
}

pub(crate) struct TrustedReviewSubjectV1 {
    canonical_json: Vec<u8>,
    digest: [u8; 32],
    source_commit: [u8; 20],
    source_tree: [u8; 20],
    observations: FreshArtifactObservationsV1,
}

impl TrustedReviewSubjectV1 {
    pub(crate) fn canonical_json(&self) -> &[u8] {
        &self.canonical_json
    }

    pub(crate) const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    pub(crate) const fn source_commit(&self) -> &[u8; 20] {
        &self.source_commit
    }

    pub(crate) const fn source_tree(&self) -> &[u8; 20] {
        &self.source_tree
    }

    pub(crate) const fn observations(&self) -> &FreshArtifactObservationsV1 {
        &self.observations
    }

    pub(crate) fn document(&self) -> Result<ReviewSubjectV1, ReviewSubjectErrorV1> {
        parse_canonical(&self.canonical_json)
    }

    pub(crate) fn explicit_nonclaims(&self) -> Result<Vec<String>, ReviewSubjectErrorV1> {
        Ok(self.document()?.explicit_nonclaims)
    }

    #[cfg(test)]
    pub(crate) fn synthetic(
        digest: [u8; 32],
        source_commit: [u8; 20],
        source_tree: [u8; 20],
        observations: FreshArtifactObservationsV1,
    ) -> Self {
        let document = ReviewSubjectV1 {
            schema: SUBJECT_SCHEMA.to_owned(),
            protocol_id: PROTOCOL_ID.to_owned(),
            evidence_scope: SUBJECT_SCOPE.to_owned(),
            source: ReviewSubjectSourceV1 {
                repository_commit_hex: encode_hex(&source_commit),
                repository_tree_hex: encode_hex(&source_tree),
                source_archive_sha256_hex: "88".repeat(32),
                checkout_state: CHECKOUT_STATE.to_owned(),
            },
            toolchain_commitments: ToolchainCommitmentsV1 {
                generator_cargo_lock_sha256_hex: "01".repeat(32),
                task_runner_cargo_lock_sha256_hex: "02".repeat(32),
                formal_toolchain_sha256_hex: "03".repeat(32),
                rustc_version_verbose_sha256_hex: "04".repeat(32),
                cargo_version_sha256_hex: "05".repeat(32),
                python_version_sha256_hex: "06".repeat(32),
                git_version_sha256_hex: "07".repeat(32),
            },
            authoritative_specifications: Vec::new(),
            benchmark_manifest_binding: benchmark_manifest_binding(
                &build_provisional_benchmark_manifest_v1(),
            ),
            reconciliation_certificate_binding: ReconciliationCertificateBindingV1 {
                path: RECONCILIATION_PATH.to_owned(),
                canonical_bytes: 1,
                sha256_hex: "09".repeat(32),
                case_count: 5,
            },
            phase1_corpus_commitments: Vec::new(),
            explicit_nonclaims: EXPLICIT_NONCLAIMS
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
            subject_digest_hex: encode_hex(&digest),
        };
        Self {
            canonical_json: canonical_json(&document).expect("synthetic subject serializes"),
            digest,
            source_commit,
            source_tree,
            observations,
        }
    }
}

pub(crate) fn run_review_subject_check() -> Result<String, ReviewSubjectErrorV1> {
    let subject = build_trusted_review_subject()?;
    Ok(format!(
        "phase2b-review-subject-check ok: canonical_bytes={} subject_digest={} source_commit={} source_tree={} artifacts={}",
        subject.canonical_json().len(),
        encode_hex(subject.digest()),
        encode_hex(subject.source_commit()),
        encode_hex(subject.source_tree()),
        subject.observations().artifact_entries.len()
    ))
}

pub(crate) fn build_trusted_review_subject() -> Result<TrustedReviewSubjectV1, ReviewSubjectErrorV1>
{
    build_review_subject_isolated(INTERNAL_MATERIAL_COMMAND)
}

pub(crate) fn build_trusted_reproduced_subject(
) -> Result<TrustedReviewSubjectV1, ReviewSubjectErrorV1> {
    build_review_subject_isolated(INTERNAL_REPRODUCTION_MATERIAL_COMMAND)
}

pub(crate) fn candidate_commit_from_subject_bytes(
    subject_bytes: &[u8],
) -> Result<[u8; 20], ReviewSubjectErrorV1> {
    let subject: ReviewSubjectV1 = parse_canonical(subject_bytes)?;
    decode_hex::<20>(
        &subject.source.repository_commit_hex,
        "repository_commit_hex",
    )
}

pub(crate) fn build_trusted_review_subject_for_candidate(
    candidate_commit: &[u8; 20],
) -> Result<TrustedReviewSubjectV1, ReviewSubjectErrorV1> {
    let root = repository_root();
    let outer_head = git_text(&root, &["rev-parse", "--verify", "HEAD"])?;
    require_clean_checkout(&root)?;
    build_review_subject_isolated_candidate(
        &root,
        &encode_hex(candidate_commit),
        &outer_head,
        INTERNAL_MATERIAL_COMMAND,
    )
}

pub(crate) fn require_subject_checkout_current(
    subject: &TrustedReviewSubjectV1,
) -> Result<(), ReviewSubjectErrorV1> {
    let root = repository_root();
    require_clean_checkout(&root)?;
    let head = git_text(&root, &["rev-parse", "--verify", "HEAD"])?;
    if decode_hex::<20>(&head, "repository_commit_hex")? == *subject.source_commit() {
        Ok(())
    } else {
        Err(ReviewSubjectErrorV1::ChangedCheckout)
    }
}

pub(crate) fn run_review_subject_material() -> Result<Vec<u8>, ReviewSubjectErrorV1> {
    let subject = build_review_subject_current_checkout()?;
    let parsed_subject: ReviewSubjectV1 = parse_canonical(subject.canonical_json())?;
    let envelope = ReviewSubjectMaterialEnvelopeV1 {
        schema: MATERIAL_SCHEMA.to_owned(),
        subject: parsed_subject,
        observations: material_observations(subject.observations()),
    };
    canonical_json(&envelope)
}

fn build_review_subject_isolated(
    internal_command: &'static str,
) -> Result<TrustedReviewSubjectV1, ReviewSubjectErrorV1> {
    let root = repository_root();
    let captured_commit = git_text(&root, &["rev-parse", "--verify", "HEAD"])?;
    require_clean_checkout(&root)?;
    build_review_subject_isolated_candidate(
        &root,
        &captured_commit,
        &captured_commit,
        internal_command,
    )
}

fn build_review_subject_isolated_candidate(
    root: &Path,
    candidate_commit: &str,
    expected_outer_head: &str,
    internal_command: &'static str,
) -> Result<TrustedReviewSubjectV1, ReviewSubjectErrorV1> {
    validate_candidate_tree(root, candidate_commit)?;
    let expected_source = build_source(root, candidate_commit)?;
    let temporary = TemporaryDirectory::create("phase2b-review-isolated-source")
        .map_err(|error| ReviewSubjectErrorV1::Artifact(error.to_string()))?;
    let clone = temporary.path().join("candidate");
    clone_candidate(root, &clone, candidate_commit)?;
    let material = run_isolated_material_builder(&clone, temporary.path(), internal_command)?;
    let envelope: ReviewSubjectMaterialEnvelopeV1 = parse_canonical(&material)?;
    let subject = validate_material_envelope(envelope, &expected_source)?;
    require_unchanged_checkout(root, expected_outer_head)?;
    Ok(subject)
}

fn build_review_subject_current_checkout() -> Result<TrustedReviewSubjectV1, ReviewSubjectErrorV1> {
    let root = repository_root();
    let captured_commit = git_text(&root, &["rev-parse", "--verify", "HEAD"])?;
    require_clean_checkout(&root)?;
    let source = build_source(&root, &captured_commit)?;
    let source_commit = decode_hex::<20>(&source.repository_commit_hex, "repository_commit_hex")?;
    let source_tree = decode_hex::<20>(&source.repository_tree_hex, "repository_tree_hex")?;
    let toolchain_commitments = build_toolchain_commitments(&root)?;
    let authoritative_specifications = AUTHORITATIVE_SPECIFICATIONS
        .iter()
        .map(|path| file_commitment(&root, path))
        .collect::<Result<Vec<_>, _>>()?;
    let manifest = build_provisional_benchmark_manifest_v1();
    let benchmark_manifest_binding = benchmark_manifest_binding(&manifest);
    let observations = build_fresh_artifact_observations(&manifest)?;
    let (reconciliation_certificate_binding, phase1_corpus_commitments) =
        build_reconciliation_binding(&root, &benchmark_manifest_binding)?;
    let payload = ReviewSubjectPayloadV1 {
        schema: SUBJECT_SCHEMA.to_owned(),
        protocol_id: PROTOCOL_ID.to_owned(),
        evidence_scope: SUBJECT_SCOPE.to_owned(),
        source,
        toolchain_commitments,
        authoritative_specifications,
        benchmark_manifest_binding,
        reconciliation_certificate_binding,
        phase1_corpus_commitments,
        explicit_nonclaims: EXPLICIT_NONCLAIMS
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
    };
    let payload_json = canonical_json(&payload)?;
    let digest = domain_digest(SUBJECT_DIGEST_DOMAIN, &payload_json);
    let subject = ReviewSubjectV1 {
        schema: payload.schema,
        protocol_id: payload.protocol_id,
        evidence_scope: payload.evidence_scope,
        source: payload.source,
        toolchain_commitments: payload.toolchain_commitments,
        authoritative_specifications: payload.authoritative_specifications,
        benchmark_manifest_binding: payload.benchmark_manifest_binding,
        reconciliation_certificate_binding: payload.reconciliation_certificate_binding,
        phase1_corpus_commitments: payload.phase1_corpus_commitments,
        explicit_nonclaims: payload.explicit_nonclaims,
        subject_digest_hex: encode_hex(&digest),
    };
    let canonical_json = canonical_json(&subject)?;
    require_unchanged_checkout(&root, &captured_commit)?;
    Ok(TrustedReviewSubjectV1 {
        canonical_json,
        digest,
        source_commit,
        source_tree,
        observations,
    })
}

fn clone_candidate(
    root: &Path,
    clone: &Path,
    captured_commit: &str,
) -> Result<(), ReviewSubjectErrorV1> {
    let mut clone_command = Command::new("git");
    hardened_git_environment(&mut clone_command);
    clone_command
        .args(["clone", "--quiet", "--no-checkout", "--no-hardlinks"])
        .arg(root)
        .arg(clone);
    command_bytes(&mut clone_command, "git clone captured candidate")?;

    let mut checkout_command = Command::new("git");
    hardened_git_environment(&mut checkout_command);
    checkout_command.arg("-C").arg(clone).args([
        "-c",
        "core.autocrlf=false",
        "-c",
        "core.eol=lf",
        "checkout",
        "--quiet",
        "--detach",
        captured_commit,
    ]);
    command_bytes(&mut checkout_command, "git checkout captured candidate")?;
    if git_text(clone, &["rev-parse", "--verify", "HEAD"])? != captured_commit {
        return Err(ReviewSubjectErrorV1::InvalidRepositoryIdentity);
    }
    require_clean_checkout(clone)
}

fn run_isolated_material_builder(
    clone: &Path,
    temporary_root: &Path,
    internal_command: &'static str,
) -> Result<Vec<u8>, ReviewSubjectErrorV1> {
    let manifest = clone.join("crates/ed25519-yao/formal-verification/tasks/Cargo.toml");
    let target = temporary_root.join("isolated-target");
    let mut command = Command::new("cargo");
    command
        .args(["run", "--locked", "--offline", "--quiet", "--manifest-path"])
        .arg(manifest)
        .args([
            "--bin",
            "ed25519-yao-formal-verification-tasks",
            "--",
            internal_command,
        ])
        .current_dir(clone);
    configure_isolated_environment(&mut command, &target);
    command
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_ATTR_NOSYSTEM", "1");
    command_bytes(
        &mut command,
        "isolated Phase 2B review-subject material build",
    )
}

fn configure_isolated_environment(command: &mut Command, target: &Path) {
    command
        .env("CARGO_TARGET_DIR", target)
        .env_remove("RUSTC_WRAPPER")
        .env_remove("RUSTC_WORKSPACE_WRAPPER")
        .env_remove("RUSTFLAGS")
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .env_remove("RUSTDOCFLAGS")
        .env_remove("CARGO")
        .env_remove("RUSTC")
        .env_remove("RUSTDOC")
        .env_remove("CARGO_BUILD_RUSTC")
        .env_remove("RUSTUP_TOOLCHAIN")
        .env_remove(POLICY_JSON_ENV)
        .env_remove(POLICY_DIGEST_ENV)
        .env_remove(CHALLENGE_ENV);
}

fn validate_candidate_tree(root: &Path, captured_commit: &str) -> Result<(), ReviewSubjectErrorV1> {
    let mut command = Command::new("git");
    hardened_git_environment(&mut command);
    command
        .args(["ls-tree", "-r", "--full-tree", captured_commit])
        .current_dir(root);
    let bytes = command_bytes(&mut command, "git ls-tree captured candidate")?;
    let source = std::str::from_utf8(&bytes)
        .map_err(|_| ReviewSubjectErrorV1::InvalidUtf8("git ls-tree"))?;
    let mut entries = Vec::new();
    for line in source.lines() {
        let (metadata, path) = line
            .split_once('\t')
            .ok_or(ReviewSubjectErrorV1::InvalidRepositoryIdentity)?;
        let mode = metadata
            .split_ascii_whitespace()
            .next()
            .ok_or(ReviewSubjectErrorV1::InvalidRepositoryIdentity)?;
        if mode == "160000"
            || Path::new(path).file_name().and_then(|value| value.to_str())
                == Some(".gitattributes")
        {
            return Err(ReviewSubjectErrorV1::InvalidRepositoryIdentity);
        }
        entries.push((mode, path));
    }
    for (mode, path) in &entries {
        if *mode != "120000" {
            continue;
        }
        let object = format!("{captured_commit}:{path}");
        let target = command_bytes(
            Command::new("git")
                .args(["show", &object])
                .current_dir(root),
            "git show candidate symlink",
        )?;
        let target = std::str::from_utf8(&target)
            .map_err(|_| ReviewSubjectErrorV1::InvalidRepositoryIdentity)?;
        let resolved = resolve_internal_symlink(path, target)?;
        let prefix = format!("{resolved}/");
        let exact = entries.iter().find(|(_, candidate)| *candidate == resolved);
        if resolved == *path
            || exact.is_some_and(|(target_mode, _)| *target_mode == "120000")
            || (exact.is_none()
                && !entries
                    .iter()
                    .any(|(_, candidate)| candidate.starts_with(&prefix)))
        {
            return Err(ReviewSubjectErrorV1::InvalidRepositoryIdentity);
        }
    }
    Ok(())
}

fn resolve_internal_symlink(link_path: &str, target: &str) -> Result<String, ReviewSubjectErrorV1> {
    let target = Path::new(target);
    if target.as_os_str().is_empty() || target.is_absolute() {
        return Err(ReviewSubjectErrorV1::InvalidRepositoryIdentity);
    }
    let mut components = Vec::<OsString>::new();
    let joined = Path::new(link_path)
        .parent()
        .unwrap_or_else(|| Path::new(""))
        .join(target);
    for component in joined.components() {
        match component {
            Component::Normal(value) => components.push(value.to_owned()),
            Component::CurDir => {}
            Component::ParentDir => {
                components
                    .pop()
                    .ok_or(ReviewSubjectErrorV1::InvalidRepositoryIdentity)?;
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(ReviewSubjectErrorV1::InvalidRepositoryIdentity);
            }
        }
    }
    let resolved = components.iter().collect::<PathBuf>();
    resolved
        .to_str()
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or(ReviewSubjectErrorV1::InvalidRepositoryIdentity)
}

fn hardened_git_environment(command: &mut Command) {
    command
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_ATTR_NOSYSTEM", "1");
}

fn material_observations(value: &FreshArtifactObservationsV1) -> MaterialObservationsV1 {
    MaterialObservationsV1 {
        manifest_canonical_bytes: value.manifest_canonical_bytes,
        manifest_digest_hex: encode_hex(&value.manifest_digest),
        bundle_index_canonical_bytes: value.bundle_index_canonical_bytes,
        bundle_index_digest_hex: encode_hex(&value.bundle_index_digest),
        artifact_entries: value
            .artifact_entries
            .iter()
            .map(|entry| MaterialArtifactEntryV1 {
                tag: entry.tag,
                filename: entry.filename.clone(),
                canonical_bytes: entry.canonical_bytes,
                sha256_hex: encode_hex(&entry.sha256),
            })
            .collect(),
    }
}

fn validate_material_envelope(
    envelope: ReviewSubjectMaterialEnvelopeV1,
    expected_source: &ReviewSubjectSourceV1,
) -> Result<TrustedReviewSubjectV1, ReviewSubjectErrorV1> {
    if envelope.schema != MATERIAL_SCHEMA || &envelope.subject.source != expected_source {
        return Err(ReviewSubjectErrorV1::InvalidMaterialSource);
    }
    let subject = envelope.subject;
    let payload = ReviewSubjectPayloadV1 {
        schema: subject.schema.clone(),
        protocol_id: subject.protocol_id.clone(),
        evidence_scope: subject.evidence_scope.clone(),
        source: subject.source.clone(),
        toolchain_commitments: subject.toolchain_commitments.clone(),
        authoritative_specifications: subject.authoritative_specifications.clone(),
        benchmark_manifest_binding: subject.benchmark_manifest_binding.clone(),
        reconciliation_certificate_binding: subject.reconciliation_certificate_binding.clone(),
        phase1_corpus_commitments: subject.phase1_corpus_commitments.clone(),
        explicit_nonclaims: subject.explicit_nonclaims.clone(),
    };
    let expected_digest = domain_digest(SUBJECT_DIGEST_DOMAIN, &canonical_json(&payload)?);
    if subject.schema != SUBJECT_SCHEMA
        || subject.protocol_id != PROTOCOL_ID
        || subject.evidence_scope != SUBJECT_SCOPE
        || subject.subject_digest_hex != encode_hex(&expected_digest)
    {
        return Err(ReviewSubjectErrorV1::InvalidMaterialSubject);
    }
    let observations =
        parse_material_observations(envelope.observations, &subject.benchmark_manifest_binding)?;
    let canonical_json = canonical_json(&subject)?;
    Ok(TrustedReviewSubjectV1 {
        canonical_json,
        digest: expected_digest,
        source_commit: decode_hex::<20>(
            &subject.source.repository_commit_hex,
            "repository_commit_hex",
        )?,
        source_tree: decode_hex::<20>(&subject.source.repository_tree_hex, "repository_tree_hex")?,
        observations,
    })
}

fn parse_material_observations(
    value: MaterialObservationsV1,
    manifest: &BenchmarkManifestBindingV1,
) -> Result<FreshArtifactObservationsV1, ReviewSubjectErrorV1> {
    if value.manifest_canonical_bytes != manifest.manifest_canonical_bytes
        || value.manifest_digest_hex != manifest.manifest_digest_hex
        || value.bundle_index_canonical_bytes != manifest.bundle_index_canonical_bytes
        || value.bundle_index_digest_hex != manifest.bundle_index_digest_hex
        || value.artifact_entries.len() != 6
        || manifest.components.len() != 3
    {
        return Err(ReviewSubjectErrorV1::InvalidArtifactObservation);
    }
    let expected_files = manifest
        .components
        .iter()
        .flat_map(|component| {
            [
                (
                    component.ir_file.as_str(),
                    component.circuit_metrics.canonical_ir_bytes,
                    component.ir_digest_hex.as_str(),
                ),
                (
                    component.schedule_file.as_str(),
                    component.schedule_metrics.canonical_schedule_bytes,
                    component.schedule_digest_hex.as_str(),
                ),
            ]
        })
        .collect::<Vec<_>>();
    let mut artifact_entries = Vec::new();
    for (index, (entry, (filename, canonical_bytes, sha256_hex))) in value
        .artifact_entries
        .into_iter()
        .zip(expected_files)
        .enumerate()
    {
        if entry.tag != u8::try_from(index + 1).expect("six fixed artifact tags")
            || entry.filename != filename
            || entry.canonical_bytes != canonical_bytes
            || entry.sha256_hex != sha256_hex
        {
            return Err(ReviewSubjectErrorV1::InvalidArtifactObservation);
        }
        artifact_entries.push(FreshArtifactEntryV1 {
            tag: entry.tag,
            filename: entry.filename,
            canonical_bytes: entry.canonical_bytes,
            sha256: decode_hex::<32>(&entry.sha256_hex, "artifact.sha256_hex")?,
        });
    }
    Ok(FreshArtifactObservationsV1 {
        manifest_canonical_bytes: value.manifest_canonical_bytes,
        manifest_digest: decode_hex::<32>(&value.manifest_digest_hex, "manifest_digest_hex")?,
        bundle_index_canonical_bytes: value.bundle_index_canonical_bytes,
        bundle_index_digest: decode_hex::<32>(
            &value.bundle_index_digest_hex,
            "bundle_index_digest_hex",
        )?,
        artifact_entries,
    })
}

fn build_source(
    root: &Path,
    captured_commit: &str,
) -> Result<ReviewSubjectSourceV1, ReviewSubjectErrorV1> {
    let tree_revision = format!("{captured_commit}^{{tree}}");
    let repository_commit_hex = captured_commit.to_owned();
    let repository_tree_hex = git_text(root, &["rev-parse", "--verify", tree_revision.as_str()])?;
    decode_hex::<20>(&repository_commit_hex, "repository_commit_hex")?;
    decode_hex::<20>(&repository_tree_hex, "repository_tree_hex")?;
    let archive = command_bytes(
        Command::new("git")
            .args(["archive", "--format=tar", &repository_commit_hex])
            .current_dir(root),
        "git archive",
    )?;
    Ok(ReviewSubjectSourceV1 {
        repository_commit_hex,
        repository_tree_hex,
        source_archive_sha256_hex: encode_hex(&Sha256::digest(archive)),
        checkout_state: CHECKOUT_STATE.to_owned(),
    })
}

fn build_toolchain_commitments(
    root: &Path,
) -> Result<ToolchainCommitmentsV1, ReviewSubjectErrorV1> {
    Ok(ToolchainCommitmentsV1 {
        generator_cargo_lock_sha256_hex: hash_file(
            &root.join("tools/ed25519-yao-generator/Cargo.lock"),
        )?,
        task_runner_cargo_lock_sha256_hex: hash_file(
            &root.join("crates/ed25519-yao/formal-verification/tasks/Cargo.lock"),
        )?,
        formal_toolchain_sha256_hex: hash_file(
            &root.join("crates/ed25519-yao/formal-verification/toolchain.toml"),
        )?,
        rustc_version_verbose_sha256_hex: hash_command_stdout(
            Command::new("rustc").args(["--version", "--verbose"]),
            "rustc --version --verbose",
        )?,
        cargo_version_sha256_hex: hash_command_stdout(
            Command::new("cargo").arg("--version"),
            "cargo --version",
        )?,
        python_version_sha256_hex: hash_command_stdout(
            Command::new("python3").arg("--version"),
            "python3 --version",
        )?,
        git_version_sha256_hex: hash_command_stdout(
            Command::new("git").arg("--version"),
            "git --version",
        )?,
    })
}

fn build_reconciliation_binding(
    root: &Path,
    benchmark_manifest: &BenchmarkManifestBindingV1,
) -> Result<
    (
        ReconciliationCertificateBindingV1,
        Vec<Phase1CorpusCommitmentV1>,
    ),
    ReviewSubjectErrorV1,
> {
    let path = root.join(RECONCILIATION_PATH);
    let bytes = fs::read(&path)?;
    if bytes != canonical_phase2b_core_reconciliation_corpus_json_bytes_v1()
        || parse_canonical_phase2b_core_reconciliation_corpus_json_v1(&bytes).is_err()
    {
        return Err(ReviewSubjectErrorV1::InvalidCertificate);
    }
    let projection: ReconciliationProjectionV1 = serde_json::from_slice(&bytes)?;
    if projection.schema != RECONCILIATION_SCHEMA
        || projection.protocol_id != PROTOCOL_ID
        || projection.evidence_scope != RECONCILIATION_SCOPE
        || projection.cases.len() != 5
        || projection.explicit_nonclaims
            != EXPLICIT_NONCLAIMS
                .iter()
                .map(|value| (*value).to_owned())
                .collect::<Vec<_>>()
        || projection.benchmark_manifest_binding
            != reconciliation_manifest_projection(benchmark_manifest)?
        || !projection.mapping_contracts.is_object()
    {
        return Err(ReviewSubjectErrorV1::InvalidCertificate);
    }
    if projection.phase1_corpus_commitments.len() != 20 {
        return Err(ReviewSubjectErrorV1::InvalidCorpusCommitment);
    }
    let generator = root.join("tools/ed25519-yao-generator");
    for commitment in &projection.phase1_corpus_commitments {
        validate_corpus_path(&commitment.path)?;
        let bytes = fs::read(generator.join(&commitment.path))?;
        if u64::try_from(bytes.len()).ok() != Some(commitment.canonical_bytes)
            || encode_hex(&Sha256::digest(&bytes)) != commitment.sha256_hex
        {
            return Err(ReviewSubjectErrorV1::InvalidCorpusCommitment);
        }
    }
    Ok((
        ReconciliationCertificateBindingV1 {
            path: RECONCILIATION_PATH.to_owned(),
            canonical_bytes: u64::try_from(bytes.len())
                .map_err(|_| ReviewSubjectErrorV1::InvalidCertificate)?,
            sha256_hex: encode_hex(&Sha256::digest(&bytes)),
            case_count: 5,
        },
        projection.phase1_corpus_commitments,
    ))
}

fn reconciliation_manifest_projection(
    manifest: &BenchmarkManifestBindingV1,
) -> Result<serde_json::Value, ReviewSubjectErrorV1> {
    #[derive(Serialize)]
    struct Component<'a> {
        component_kind: &'a str,
        component_tag: u8,
        ir_file: &'a str,
        schedule_file: &'a str,
        input_schema: &'a str,
        output_schema: &'a str,
        ir_digest_hex: &'a str,
        schedule_digest_hex: &'a str,
    }
    #[derive(Serialize)]
    struct Projection<'a> {
        manifest_magic: &'a str,
        manifest_canonical_bytes: u64,
        manifest_digest_hex: &'a str,
        compiler_contract: &'a str,
        bit_order: &'a str,
        wire_order: &'a str,
        bundle_index_file: &'a str,
        bundle_index_canonical_bytes: u64,
        bundle_index_digest_hex: &'a str,
        components: Vec<Component<'a>>,
    }
    let components = manifest
        .components
        .iter()
        .map(|component| Component {
            component_kind: &component.component_kind,
            component_tag: component.component_tag,
            ir_file: &component.ir_file,
            schedule_file: &component.schedule_file,
            input_schema: &component.input_schema,
            output_schema: &component.output_schema,
            ir_digest_hex: &component.ir_digest_hex,
            schedule_digest_hex: &component.schedule_digest_hex,
        })
        .collect();
    Ok(serde_json::to_value(Projection {
        manifest_magic: &manifest.manifest_magic,
        manifest_canonical_bytes: manifest.manifest_canonical_bytes,
        manifest_digest_hex: &manifest.manifest_digest_hex,
        compiler_contract: &manifest.compiler_contract,
        bit_order: &manifest.bit_order,
        wire_order: &manifest.wire_order,
        bundle_index_file: &manifest.bundle_index_file,
        bundle_index_canonical_bytes: manifest.bundle_index_canonical_bytes,
        bundle_index_digest_hex: &manifest.bundle_index_digest_hex,
        components,
    })?)
}

fn benchmark_manifest_binding(
    manifest: &ed25519_yao_generator::ProvisionalBenchmarkManifestV1,
) -> BenchmarkManifestBindingV1 {
    let kinds = ["fixed_sha512_32", "activation", "export"];
    let components = manifest
        .components()
        .zip(kinds)
        .map(|(component, component_kind)| benchmark_component(component, component_kind))
        .collect();
    BenchmarkManifestBindingV1 {
        manifest_magic: std::str::from_utf8(PROVISIONAL_BENCHMARK_MANIFEST_MAGIC_V1)
            .expect("fixed manifest magic is ASCII")
            .to_owned(),
        manifest_canonical_bytes: u64::try_from(manifest.canonical_encoding().len())
            .expect("fixed manifest length fits u64"),
        manifest_digest_hex: encode_hex(manifest.digest().as_bytes()),
        compiler_contract: PROVISIONAL_BENCHMARK_COMPILER_CONTRACT_V1.to_owned(),
        bit_order: FIXED_SHA512_32_BIT_ORDER_V1.to_owned(),
        wire_order: PROVISIONAL_BENCHMARK_WIRE_ORDER_V1.to_owned(),
        bundle_index_file: PROVISIONAL_ARTIFACT_BUNDLE_INDEX_FILE_V1.to_owned(),
        bundle_index_canonical_bytes: manifest.bundle_index_bytes(),
        bundle_index_digest_hex: encode_hex(manifest.bundle_index_digest()),
        components,
    }
}

fn benchmark_component(
    component: &ProvisionalBenchmarkManifestComponentV1,
    component_kind: &str,
) -> BenchmarkComponentBindingV1 {
    let circuit = component.circuit_metrics();
    let schedule = component.schedule_metrics();
    BenchmarkComponentBindingV1 {
        component_kind: component_kind.to_owned(),
        component_tag: component.component_tag(),
        ir_file: component.ir_filename().to_owned(),
        schedule_file: component.schedule_filename().to_owned(),
        input_schema: component.input_schema().to_owned(),
        output_schema: component.output_schema().to_owned(),
        ir_digest_hex: encode_hex(component.ir_digest()),
        schedule_digest_hex: encode_hex(component.schedule_digest()),
        circuit_metrics: CircuitMetricsV1 {
            input_wire_count: circuit.input_wire_count(),
            output_wire_count: circuit.output_wire_count(),
            wire_count: circuit.wire_count(),
            and_gate_count: circuit.and_gate_count(),
            xor_gate_count: circuit.xor_gate_count(),
            inversion_gate_count: circuit.inversion_gate_count(),
            total_gate_count: circuit.total_gate_count(),
            circuit_depth: circuit.circuit_depth(),
            and_depth: circuit.and_depth(),
            canonical_ir_bytes: circuit.canonical_encoding_bytes(),
        },
        schedule_metrics: ScheduleMetricsV1 {
            input_wire_count: schedule.input_wire_count(),
            output_wire_count: schedule.output_wire_count(),
            scheduled_gate_count: schedule.scheduled_gate_count(),
            reusable_slot_count: schedule.reusable_slot_count(),
            slot_width_bytes: schedule.slot_width_bytes(),
            gate_record_width_bytes: schedule.gate_record_width_bytes(),
            canonical_schedule_bytes: schedule.encoded_schedule_bytes(),
        },
        passive_half_gates_table_bytes: component.passive_half_gates_table_bytes(),
    }
}

fn build_fresh_artifact_observations(
    manifest: &ed25519_yao_generator::ProvisionalBenchmarkManifestV1,
) -> Result<FreshArtifactObservationsV1, ReviewSubjectErrorV1> {
    if manifest.canonical_encoding().len() != PROVISIONAL_BENCHMARK_MANIFEST_CANONICAL_BYTES_V1
        || manifest.digest().as_bytes() != &PROVISIONAL_BENCHMARK_MANIFEST_CANONICAL_DIGEST_V1
    {
        return Err(ReviewSubjectErrorV1::InvalidArtifactObservation);
    }
    let bundle = build_provisional_artifact_bundle_v1();
    let temporary = TemporaryDirectory::create("phase2b-review-subject-artifacts")
        .map_err(|error| ReviewSubjectErrorV1::Artifact(error.to_string()))?;
    let output = temporary.path().join("bundle");
    bundle
        .emit_to(&output)
        .map_err(|error| ReviewSubjectErrorV1::Artifact(error.to_string()))?;
    bundle
        .check_directory(&output)
        .map_err(|error| ReviewSubjectErrorV1::Artifact(error.to_string()))?;
    let index = fs::read(output.join(PROVISIONAL_ARTIFACT_BUNDLE_INDEX_FILE_V1))?;
    let index_digest: [u8; 32] = Sha256::digest(&index).into();
    if index != bundle.canonical_index()
        || index_digest != BUNDLE_INDEX_DIGEST
        || index_digest != bundle.digest().expose_public_bytes()
        || u64::try_from(index.len()).ok() != Some(manifest.bundle_index_bytes())
    {
        return Err(ReviewSubjectErrorV1::InvalidArtifactObservation);
    }
    let decoded_entries = decode_bundle_index(&index)?;
    let mut artifact_entries = Vec::new();
    for (entry, decoded) in bundle.entries().zip(decoded_entries) {
        let bytes = fs::read(output.join(entry.filename()))?;
        let digest: [u8; 32] = Sha256::digest(&bytes).into();
        if bytes != entry.bytes()
            || digest != entry.digest().expose_public_bytes()
            || decoded.tag != entry.tag()
            || decoded.filename != entry.filename()
            || decoded.canonical_bytes != u64::try_from(bytes.len()).unwrap_or(u64::MAX)
            || decoded.sha256 != digest
        {
            return Err(ReviewSubjectErrorV1::InvalidArtifactObservation);
        }
        artifact_entries.push(decoded);
    }
    if artifact_entries.len() != 6 {
        return Err(ReviewSubjectErrorV1::InvalidArtifactObservation);
    }
    Ok(FreshArtifactObservationsV1 {
        manifest_canonical_bytes: u64::try_from(manifest.canonical_encoding().len())
            .map_err(|_| ReviewSubjectErrorV1::InvalidArtifactObservation)?,
        manifest_digest: *manifest.digest().as_bytes(),
        bundle_index_canonical_bytes: u64::try_from(index.len())
            .map_err(|_| ReviewSubjectErrorV1::InvalidArtifactObservation)?,
        bundle_index_digest: index_digest,
        artifact_entries,
    })
}

fn decode_bundle_index(index: &[u8]) -> Result<Vec<FreshArtifactEntryV1>, ReviewSubjectErrorV1> {
    let mut reader = IndexReaderV1::new(index);
    if reader.take(8)? != b"EYAOBA01" || reader.integer(1)? != 6 {
        return Err(ReviewSubjectErrorV1::InvalidArtifactObservation);
    }
    let mut entries = Vec::new();
    for expected_tag in 1..=6 {
        let tag = u8::try_from(reader.integer(1)?)
            .map_err(|_| ReviewSubjectErrorV1::InvalidArtifactObservation)?;
        let filename_length = usize::try_from(reader.integer(2)?)
            .map_err(|_| ReviewSubjectErrorV1::InvalidArtifactObservation)?;
        let filename_bytes = reader.take(filename_length)?;
        let filename = std::str::from_utf8(filename_bytes)
            .map_err(|_| ReviewSubjectErrorV1::InvalidArtifactObservation)?
            .to_owned();
        let canonical_bytes = reader.integer(8)?;
        let sha256: [u8; 32] = reader
            .take(32)?
            .try_into()
            .map_err(|_| ReviewSubjectErrorV1::InvalidArtifactObservation)?;
        if tag != expected_tag
            || filename.is_empty()
            || filename.contains('/')
            || canonical_bytes == 0
        {
            return Err(ReviewSubjectErrorV1::InvalidArtifactObservation);
        }
        entries.push(FreshArtifactEntryV1 {
            tag,
            filename,
            canonical_bytes,
            sha256,
        });
    }
    if !reader.finished() {
        return Err(ReviewSubjectErrorV1::InvalidArtifactObservation);
    }
    Ok(entries)
}

struct IndexReaderV1<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> IndexReaderV1<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], ReviewSubjectErrorV1> {
        let end = self
            .offset
            .checked_add(count)
            .ok_or(ReviewSubjectErrorV1::InvalidArtifactObservation)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(ReviewSubjectErrorV1::InvalidArtifactObservation)?;
        self.offset = end;
        Ok(value)
    }

    fn integer(&mut self, count: usize) -> Result<u64, ReviewSubjectErrorV1> {
        let bytes = self.take(count)?;
        let mut value = 0u64;
        for byte in bytes {
            value = value
                .checked_mul(256)
                .and_then(|current| current.checked_add(u64::from(*byte)))
                .ok_or(ReviewSubjectErrorV1::InvalidArtifactObservation)?;
        }
        Ok(value)
    }

    const fn finished(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

fn file_commitment(root: &Path, relative: &str) -> Result<FileCommitmentV1, ReviewSubjectErrorV1> {
    let bytes = fs::read(root.join(relative))?;
    Ok(FileCommitmentV1 {
        path: relative.to_owned(),
        canonical_bytes: u64::try_from(bytes.len())
            .map_err(|_| ReviewSubjectErrorV1::InvalidRepositoryIdentity)?,
        sha256_hex: encode_hex(&Sha256::digest(bytes)),
    })
}

fn validate_corpus_path(path: &str) -> Result<(), ReviewSubjectErrorV1> {
    let parsed = Path::new(path);
    if !path.starts_with("vectors/")
        || parsed.is_absolute()
        || parsed
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
        || parsed.extension().and_then(|value| value.to_str()) != Some("json")
    {
        return Err(ReviewSubjectErrorV1::InvalidCorpusCommitment);
    }
    Ok(())
}

fn require_clean_checkout(root: &Path) -> Result<(), ReviewSubjectErrorV1> {
    let output = command_bytes(
        Command::new("git")
            .args(["status", "--porcelain=v1", "--untracked-files=all"])
            .current_dir(root),
        "git status",
    )?;
    if output.is_empty() {
        Ok(())
    } else {
        Err(ReviewSubjectErrorV1::DirtyCheckout)
    }
}

fn require_unchanged_checkout(
    root: &Path,
    captured_commit: &str,
) -> Result<(), ReviewSubjectErrorV1> {
    require_clean_checkout(root)?;
    if git_text(root, &["rev-parse", "--verify", "HEAD"])? == captured_commit {
        Ok(())
    } else {
        Err(ReviewSubjectErrorV1::ChangedCheckout)
    }
}

fn git_text(root: &Path, arguments: &[&str]) -> Result<String, ReviewSubjectErrorV1> {
    let bytes = command_bytes(Command::new("git").args(arguments).current_dir(root), "git")?;
    let text =
        String::from_utf8(bytes).map_err(|_| ReviewSubjectErrorV1::InvalidUtf8("git output"))?;
    let value = text
        .strip_suffix('\n')
        .ok_or(ReviewSubjectErrorV1::InvalidRepositoryIdentity)?;
    if value.contains('\n') || value.contains('\r') {
        return Err(ReviewSubjectErrorV1::InvalidRepositoryIdentity);
    }
    Ok(value.to_owned())
}

fn hash_file(path: &Path) -> Result<String, ReviewSubjectErrorV1> {
    Ok(encode_hex(&Sha256::digest(fs::read(path)?)))
}

fn hash_command_stdout(
    command: &mut Command,
    label: &'static str,
) -> Result<String, ReviewSubjectErrorV1> {
    let bytes = command_bytes(command, label)?;
    if bytes.is_empty() || !bytes.ends_with(b"\n") || bytes.contains(&b'\r') {
        return Err(ReviewSubjectErrorV1::Command(label));
    }
    Ok(encode_hex(&Sha256::digest(bytes)))
}

fn command_bytes(
    command: &mut Command,
    label: &'static str,
) -> Result<Vec<u8>, ReviewSubjectErrorV1> {
    let output = command
        .output()
        .map_err(|_| ReviewSubjectErrorV1::Command(label))?;
    if !output.status.success() || !output.stderr.is_empty() {
        return Err(ReviewSubjectErrorV1::Command(label));
    }
    Ok(output.stdout)
}

fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, ReviewSubjectErrorV1> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn parse_canonical<T>(bytes: &[u8]) -> Result<T, ReviewSubjectErrorV1>
where
    T: DeserializeOwned + Serialize,
{
    let value: T = serde_json::from_slice(bytes)?;
    if canonical_json(&value)? != bytes {
        return Err(ReviewSubjectErrorV1::NonCanonicalMaterial);
    }
    Ok(value)
}

fn domain_digest(domain: &[u8], value: &[u8]) -> [u8; 32] {
    let mut preimage = Vec::new();
    push_lp32(&mut preimage, domain);
    push_lp32(&mut preimage, value);
    Sha256::digest(preimage).into()
}

fn push_lp32(output: &mut Vec<u8>, value: &[u8]) {
    let length = u32::try_from(value.len()).expect("fixed review-subject field fits LP32");
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
}

fn decode_hex<const N: usize>(
    value: &str,
    field: &'static str,
) -> Result<[u8; N], ReviewSubjectErrorV1> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ReviewSubjectErrorV1::InvalidHex(field));
    }
    let mut output = [0u8; N];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| ReviewSubjectErrorV1::InvalidHex(field))?;
    }
    Ok(output)
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;

    #[test]
    fn fresh_observations_come_from_one_checked_emitted_bundle() {
        let manifest = build_provisional_benchmark_manifest_v1();
        let observations = build_fresh_artifact_observations(&manifest).expect("fresh bundle");
        assert_eq!(observations.artifact_entries.len(), 6);
        assert_eq!(observations.bundle_index_digest, BUNDLE_INDEX_DIGEST);
        assert_eq!(
            observations.manifest_digest,
            PROVISIONAL_BENCHMARK_MANIFEST_CANONICAL_DIGEST_V1
        );
        assert!(observations
            .artifact_entries
            .iter()
            .all(|entry| entry.canonical_bytes > 0 && entry.sha256 != [0; 32]));
    }

    #[test]
    fn manifest_projection_contains_complete_metrics() {
        let manifest = build_provisional_benchmark_manifest_v1();
        let binding = benchmark_manifest_binding(&manifest);
        assert_eq!(binding.components.len(), 3);
        for component in binding.components {
            assert_eq!(
                component.circuit_metrics.total_gate_count,
                component.schedule_metrics.scheduled_gate_count
            );
            assert_eq!(
                component.passive_half_gates_table_bytes,
                component.circuit_metrics.and_gate_count * 32
            );
        }
    }

    #[test]
    fn committed_certificate_and_twenty_corpora_match_fixed_bytes() {
        let root = repository_root();
        let manifest = benchmark_manifest_binding(&build_provisional_benchmark_manifest_v1());
        let (certificate, corpora) =
            build_reconciliation_binding(&root, &manifest).expect("fixed reconciliation");
        assert_eq!(certificate.case_count, 5);
        assert_eq!(corpora.len(), 20);
    }

    #[test]
    fn subject_digest_hashes_complete_unsigned_object() {
        let payload = ReviewSubjectPayloadV1 {
            schema: SUBJECT_SCHEMA.to_owned(),
            protocol_id: PROTOCOL_ID.to_owned(),
            evidence_scope: SUBJECT_SCOPE.to_owned(),
            source: ReviewSubjectSourceV1 {
                repository_commit_hex: "11".repeat(20),
                repository_tree_hex: "22".repeat(20),
                source_archive_sha256_hex: "33".repeat(32),
                checkout_state: CHECKOUT_STATE.to_owned(),
            },
            toolchain_commitments: ToolchainCommitmentsV1 {
                generator_cargo_lock_sha256_hex: "44".repeat(32),
                task_runner_cargo_lock_sha256_hex: "55".repeat(32),
                formal_toolchain_sha256_hex: "66".repeat(32),
                rustc_version_verbose_sha256_hex: "77".repeat(32),
                cargo_version_sha256_hex: "88".repeat(32),
                python_version_sha256_hex: "99".repeat(32),
                git_version_sha256_hex: "aa".repeat(32),
            },
            authoritative_specifications: Vec::new(),
            benchmark_manifest_binding: benchmark_manifest_binding(
                &build_provisional_benchmark_manifest_v1(),
            ),
            reconciliation_certificate_binding: ReconciliationCertificateBindingV1 {
                path: RECONCILIATION_PATH.to_owned(),
                canonical_bytes: 1,
                sha256_hex: "aa".repeat(32),
                case_count: 5,
            },
            phase1_corpus_commitments: Vec::new(),
            explicit_nonclaims: EXPLICIT_NONCLAIMS
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
        };
        let bytes = canonical_json(&payload).expect("canonical payload");
        let digest = domain_digest(SUBJECT_DIGEST_DOMAIN, &bytes);
        let mut mutation = payload.clone();
        mutation.evidence_scope.push_str("-changed");
        assert_ne!(
            digest,
            domain_digest(
                SUBJECT_DIGEST_DOMAIN,
                &canonical_json(&mutation).expect("canonical mutation")
            )
        );
    }

    #[test]
    fn corpus_paths_reject_traversal_and_non_json_inputs() {
        assert!(validate_corpus_path("vectors/valid.json").is_ok());
        assert!(validate_corpus_path("../vectors/valid.json").is_err());
        assert!(validate_corpus_path("vectors/../secret.json").is_err());
        assert!(validate_corpus_path("vectors/valid.txt").is_err());
    }

    #[test]
    fn hex_decoder_rejects_uppercase_and_wrong_width() {
        assert!(decode_hex::<20>(&"AA".repeat(20), "hex").is_err());
        assert!(decode_hex::<20>(&"aa".repeat(19), "hex").is_err());
        assert!(decode_hex::<20>(&"aa".repeat(20), "hex").is_ok());
    }

    #[test]
    fn bundle_index_decoder_rejects_mutation_and_trailing_bytes() {
        let bundle = build_provisional_artifact_bundle_v1();
        assert_eq!(
            decode_bundle_index(bundle.canonical_index())
                .expect("canonical index")
                .len(),
            6
        );
        let mut mutation = bundle.canonical_index().to_vec();
        mutation[8] = 5;
        assert!(decode_bundle_index(&mutation).is_err());
        let mut trailing = bundle.canonical_index().to_vec();
        trailing.push(0);
        assert!(decode_bundle_index(&trailing).is_err());
    }

    #[test]
    fn canonical_json_and_lp32_digest_match_independent_golden() {
        #[derive(Serialize)]
        struct Golden<'a> {
            schema: &'a str,
            count: u64,
        }

        let bytes = canonical_json(&Golden {
            schema: "phase2b-subject-golden-v1",
            count: 7,
        })
        .expect("golden serializes");
        assert_eq!(
            bytes,
            b"{\n  \"schema\": \"phase2b-subject-golden-v1\",\n  \"count\": 7\n}\n"
        );
        assert_eq!(
            encode_hex(&domain_digest(SUBJECT_DIGEST_DOMAIN, &bytes)),
            "9786e4f5d4ba9b85ddd1ad9c2cb84d6749951c4ea7a550b535c33a9d454dc019"
        );
    }

    #[test]
    fn material_observations_reject_manifest_and_artifact_substitution() {
        let manifest = build_provisional_benchmark_manifest_v1();
        let binding = benchmark_manifest_binding(&manifest);
        let observations =
            build_fresh_artifact_observations(&manifest).expect("fresh observations");
        let mut material = material_observations(&observations);
        material.manifest_digest_hex = "00".repeat(32);
        assert!(parse_material_observations(material, &binding).is_err());

        let mut material = material_observations(&observations);
        material.artifact_entries[0].sha256_hex = "11".repeat(32);
        assert!(parse_material_observations(material, &binding).is_err());
    }

    #[test]
    fn isolated_candidate_environment_strips_governance_and_tool_overrides() {
        let target = Path::new("/private/process-owned-target");
        let mut command = Command::new("cargo");
        configure_isolated_environment(&mut command, target);
        let environment = command.get_envs().collect::<Vec<_>>();

        assert!(environment.iter().any(|(name, value)| {
            *name == OsStr::new("CARGO_TARGET_DIR") && *value == Some(target.as_os_str())
        }));
        for name in [
            POLICY_JSON_ENV,
            POLICY_DIGEST_ENV,
            CHALLENGE_ENV,
            "CARGO",
            "RUSTC",
            "RUSTDOC",
            "CARGO_BUILD_RUSTC",
            "RUSTUP_TOOLCHAIN",
            "RUSTC_WRAPPER",
            "RUSTC_WORKSPACE_WRAPPER",
            "RUSTFLAGS",
            "CARGO_ENCODED_RUSTFLAGS",
            "RUSTDOCFLAGS",
        ] {
            assert!(environment
                .iter()
                .any(|(actual, value)| { *actual == OsStr::new(name) && value.is_none() }));
        }
    }

    #[test]
    fn candidate_tree_accepts_only_tracked_internal_symlink_targets() {
        let root = repository_root();
        let commit =
            git_text(&root, &["rev-parse", "--verify", "HEAD"]).expect("repository commit");
        validate_candidate_tree(&root, &commit).expect("captured tree is internally closed");
        assert_eq!(
            resolve_internal_symlink("packages/wasm", "../crates/threshold-prf-wasm")
                .expect("tracked internal target"),
            "crates/threshold-prf-wasm"
        );
        assert!(resolve_internal_symlink("packages/wasm", "../../outside").is_err());
        assert!(resolve_internal_symlink("packages/wasm", "/private/outside").is_err());
    }
}
