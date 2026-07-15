//! Host-only verification of externally owned Phase 2B exit evidence.

use core::fmt;
use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature, VerifyingKey};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[cfg(test)]
use crate::phase2b_protected_inputs::{
    authority_digest, validate_policy, ReviewAuthorityPolicyV1, ReviewAuthorityV1, POLICY_SCHEMA,
    POLICY_SCOPE, REPRODUCER_ROLE, REVIEWER_ROLE,
};
use crate::phase2b_protected_inputs::{
    load_protected_inputs, ProjectChallengeV1, ValidatedAuthorityPolicyV1, PROTOCOL_ID,
};
use crate::phase2b_review_subject::{
    build_trusted_reproduced_subject, build_trusted_review_subject,
    build_trusted_review_subject_for_candidate, candidate_commit_from_subject_bytes,
    require_subject_checkout_current, FreshArtifactObservationsV1, ReviewSubjectV1,
    TrustedReviewSubjectV1,
};
use crate::repository_root;

const PREPARE_SCHEMA: &str = "seams:router-ab:ed25519-yao:phase2b-independent-host-prepare:v1";
const FINALIZE_REQUEST_SCHEMA: &str =
    "seams:router-ab:ed25519-yao:phase2b-independent-host-finalize-request:v1";
pub(crate) const MAX_FINALIZE_REQUEST_BYTES: usize = 65_536;
const MAX_GIT_COMMIT_BYTES: usize = 1_048_576;
const MAX_GIT_DIFF_BYTES: usize = 1_048_576;
const MAX_GIT_STDERR_BYTES: usize = 65_536;
const REPRODUCTION_SCHEMA: &str =
    "seams:router-ab:ed25519-yao:phase2b-independent-host-reproduction:v1";
const REPRODUCTION_SCOPE: &str = "benchmark_only_phase2b_independent_host_reproduction_v1";
const APPROVAL_SCHEMA: &str = "seams:router-ab:ed25519-yao:phase2b-review-approval:v1";
const APPROVAL_SCOPE: &str = "benchmark_only_phase2b_deterministic_core_exit_v1";

const REPRODUCTION_SIGNATURE_DOMAIN: &[u8] =
    b"seams/router-ab/ed25519-yao/phase2b-independent-host-reproduction-attestation/v1";
const APPROVAL_SIGNATURE_DOMAIN: &[u8] =
    b"seams/router-ab/ed25519-yao/phase2b-review-approval-attestation/v1";
const REVIEW_REPORT_PATH: &str =
    "crates/ed25519-yao/formal-verification/review/phase2b-cryptographic-review-v1.md";
const REVIEW_SUBJECT_PATH: &str =
    "crates/ed25519-yao/formal-verification/review/phase2b-review-subject-v1.json";
const REPRODUCTION_RECORD_PATH: &str =
    "crates/ed25519-yao/formal-verification/review/phase2b-independent-host-reproduction-v1.json";
const REVIEW_APPROVAL_PATH: &str =
    "crates/ed25519-yao/formal-verification/review/phase2b-review-approval-v1.json";

const EVIDENCE_BLOBS: [(&str, usize); 4] = [
    (REVIEW_REPORT_PATH, 262_144),
    (REPRODUCTION_RECORD_PATH, 16_384),
    (REVIEW_APPROVAL_PATH, 16_384),
    (REVIEW_SUBJECT_PATH, 32_768),
];

const MANIFEST_DIGEST_HEX: &str =
    "c9c969fd23998509ae07f04fdc9982e2f3b5b21aa92aac9cf62db5ed2f0cce81";
const BUNDLE_INDEX_DIGEST_HEX: &str =
    "aa62b83b38163bf898c90084f2eb25df1c95ba41274d0f7826250f9168b80db1";

const REPRODUCTION_NONCLAIMS: [&str; 6] = [
    "operator_independence_policy_is_external",
    "reviewer_approval_not_conveyed_by_this_record",
    "production_artifact_authority_absent",
    "selected_security_profile_absent",
    "protocol_security_unclaimed",
    "runtime_and_deployment_authority_absent",
];

const REVIEWED_SURFACES: [&str; 8] = [
    "compiler_contract",
    "boolean_core_semantics",
    "input_and_output_schemas",
    "field_byte_bit_and_wire_order",
    "clear_ir_and_schedule_evaluator_equivalence",
    "component_bundle_and_manifest_digests",
    "schedule_gate_metric_and_passive_table_counts",
    "phase1_input_and_party_output_reconciliation",
];

const ARTIFACTS: [(u8, &str); 6] = [
    (1, "sha512-fixed32.ir.bin"),
    (2, "sha512-fixed32.schedule.bin"),
    (3, "activation.ir.bin"),
    (4, "activation.schedule.bin"),
    (5, "export.ir.bin"),
    (6, "export.schedule.bin"),
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ExitEvidenceErrorV1 {
    Json,
    NonCanonicalJson,
    InvalidField(&'static str),
    InvalidHex(&'static str),
    ProtectedPolicyDigestMismatch,
    InvalidSignature,
    SubjectMismatch,
    ChallengeMismatch,
    ReportDigestMismatch,
    ReproductionRecordMismatch,
    StaleApproval,
    SubjectConstruction,
    ProtectedInputs,
    HostEnvironment,
    Clock,
    EmptyInput,
    InputTooLarge,
    GitCommand,
    InvalidEvidenceCommit,
    InvalidEvidenceBlob(&'static str),
    EvidenceTooLarge,
}

impl fmt::Display for ExitEvidenceErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json => formatter.write_str("Phase 2B exit evidence is invalid JSON"),
            Self::NonCanonicalJson => {
                formatter.write_str("Phase 2B exit evidence is not canonical JSON")
            }
            Self::InvalidField(field) => write!(formatter, "invalid Phase 2B field `{field}`"),
            Self::InvalidHex(field) => write!(formatter, "invalid lowercase hex field `{field}`"),
            Self::ProtectedPolicyDigestMismatch => {
                formatter.write_str("protected authority-policy digest mismatch")
            }
            Self::InvalidSignature => formatter.write_str("invalid strict Ed25519 signature"),
            Self::SubjectMismatch => formatter.write_str("review subject digest mismatch"),
            Self::ChallengeMismatch => formatter.write_str("reproduction challenge mismatch"),
            Self::ReportDigestMismatch => formatter.write_str("review report digest mismatch"),
            Self::ReproductionRecordMismatch => {
                formatter.write_str("approval reproduction-record digest mismatch")
            }
            Self::StaleApproval => formatter.write_str("approval sequence is below policy floor"),
            Self::SubjectConstruction => {
                formatter.write_str("Phase 2B review-subject construction failed")
            }
            Self::ProtectedInputs => formatter.write_str("Phase 2B protected-input loading failed"),
            Self::HostEnvironment => {
                formatter.write_str("Phase 2B host-environment measurement failed")
            }
            Self::Clock => formatter.write_str("Phase 2B system-clock measurement failed"),
            Self::EmptyInput => formatter.write_str("Phase 2B finalize input is empty"),
            Self::InputTooLarge => {
                formatter.write_str("Phase 2B finalize input exceeds 65536 bytes")
            }
            Self::GitCommand => formatter.write_str("Phase 2B hardened Git command failed"),
            Self::InvalidEvidenceCommit => {
                formatter.write_str("Phase 2B evidence commit shape is invalid")
            }
            Self::InvalidEvidenceBlob(path) => {
                write!(formatter, "invalid Phase 2B evidence blob `{path}`")
            }
            Self::EvidenceTooLarge => {
                formatter.write_str("Phase 2B Git evidence exceeds its fixed bound")
            }
        }
    }
}

impl std::error::Error for ExitEvidenceErrorV1 {}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedReproductionRecordV1 {
    payload: ReproductionPayloadV1,
    signature_algorithm: String,
    signature_hex: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReproductionPayloadV1 {
    schema: String,
    protocol_id: String,
    evidence_scope: String,
    authority_policy_sha256_hex: String,
    subject_digest_hex: String,
    source_commit_hex: String,
    source_tree_hex: String,
    operator_assertion: OperatorAssertionV1,
    host_environment: HostEnvironmentV1,
    execution: ReproductionExecutionV1,
    observations: ReproductionObservationsV1,
    explicit_nonclaims: Vec<String>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct IndependentHostPrepareEnvelopeV1 {
    schema: String,
    review_subject: ReviewSubjectV1,
    unsigned_reproduction_payload: ReproductionPayloadV1,
    signing_digest_hex: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct IndependentHostFinalizeRequestV1 {
    schema: String,
    prepare_envelope: IndependentHostPrepareEnvelopeV1,
    signature_hex: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OperatorAssertionV1 {
    operator_id: String,
    operator_key_epoch: u64,
    operator_authority_key_digest_hex: String,
    challenge_hex: String,
    independence_claim: String,
    started_at_unix_seconds: u64,
    completed_at_unix_seconds: u64,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HostEnvironmentV1 {
    operating_system: String,
    architecture: String,
    kernel_release: String,
    artifact_filesystem_policy: String,
    checkout_state: String,
    cargo_target_state: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReproductionExecutionV1 {
    runner_contract: String,
    locked_dependencies: bool,
    committed_certificate_check: String,
    phase2b_reconciliation_cases: u64,
    phase2b_reconciliation_rust_tests: u64,
    phase2b_reconciliation_python_tests: u64,
    artifact_python_tests: u64,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReproductionObservationsV1 {
    manifest_canonical_bytes: u64,
    manifest_digest_hex: String,
    bundle_index_canonical_bytes: u64,
    bundle_index_digest_hex: String,
    artifact_entries: Vec<ArtifactEntryV1>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactEntryV1 {
    tag: u8,
    filename: String,
    canonical_bytes: u64,
    sha256_hex: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedReviewApprovalV1 {
    payload: ReviewApprovalPayloadV1,
    signature_algorithm: String,
    signature_hex: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReviewApprovalPayloadV1 {
    schema: String,
    protocol_id: String,
    approval_scope: String,
    decision: String,
    approval_sequence: u64,
    authority_policy_sha256_hex: String,
    subject_digest_hex: String,
    independent_reproduction_record_sha256_hex: String,
    review_report_path: String,
    review_report_sha256_hex: String,
    reviewed_at_unix_seconds: u64,
    reviewer_authority_id: String,
    reviewer_key_epoch: u64,
    reviewer_authority_key_digest_hex: String,
    reviewed_surfaces: Vec<String>,
    explicit_nonclaims: Vec<String>,
}

struct TrustedReviewReportV1 {
    sha256: [u8; 32],
}

/// Private capability proving both externally owned statements verified.
#[derive(Debug)]
pub(crate) struct VerifiedPhase2bReviewApprovalV1 {
    evidence_commit: [u8; 20],
    candidate_commit: [u8; 20],
    subject_digest: [u8; 32],
    authority_policy_digest: [u8; 32],
    reproduction_record_digest: [u8; 32],
    approval_record_digest: [u8; 32],
    approval_sequence: u64,
}

impl VerifiedPhase2bReviewApprovalV1 {
    pub(crate) const fn evidence_commit(&self) -> &[u8; 20] {
        &self.evidence_commit
    }

    pub(crate) const fn candidate_commit(&self) -> &[u8; 20] {
        &self.candidate_commit
    }

    pub(crate) const fn subject_digest(&self) -> &[u8; 32] {
        &self.subject_digest
    }

    pub(crate) const fn authority_policy_digest(&self) -> &[u8; 32] {
        &self.authority_policy_digest
    }

    pub(crate) const fn reproduction_record_digest(&self) -> &[u8; 32] {
        &self.reproduction_record_digest
    }

    pub(crate) const fn approval_record_digest(&self) -> &[u8; 32] {
        &self.approval_record_digest
    }

    pub(crate) const fn approval_sequence(&self) -> u64 {
        self.approval_sequence
    }
}

struct EvidenceBlobEntryV1 {
    path: String,
    oid: [u8; 20],
}

struct FixedEvidenceCommitV1 {
    evidence_commit: [u8; 20],
    candidate_commit: [u8; 20],
    subject_bytes: Vec<u8>,
    reproduction_record_bytes: Vec<u8>,
    review_report_bytes: Vec<u8>,
    approval_record_bytes: Vec<u8>,
}

/// Private capability proving the fixed evidence commit and reproduction record verified.
pub(crate) struct VerifiedPhase2bIndependentHostReproductionV1 {
    evidence_commit: [u8; 20],
    candidate_commit: [u8; 20],
    subject: TrustedReviewSubjectV1,
    policy: ValidatedAuthorityPolicyV1,
    reproduction_record_bytes: Vec<u8>,
    review_report_bytes: Vec<u8>,
    approval_record_bytes: Vec<u8>,
}

impl VerifiedPhase2bIndependentHostReproductionV1 {
    pub(crate) const fn evidence_commit(&self) -> &[u8; 20] {
        &self.evidence_commit
    }

    pub(crate) const fn candidate_commit(&self) -> &[u8; 20] {
        &self.candidate_commit
    }

    pub(crate) const fn subject_digest(&self) -> &[u8; 32] {
        self.subject.digest()
    }

    pub(crate) fn reproduction_record_digest(&self) -> [u8; 32] {
        Sha256::digest(&self.reproduction_record_bytes).into()
    }
}

pub(crate) fn prepare_independent_host_reproduction() -> Result<Vec<u8>, ExitEvidenceErrorV1> {
    let started_at_unix_seconds = unix_time()?;
    let protected = load_protected_inputs().map_err(|_| ExitEvidenceErrorV1::ProtectedInputs)?;
    let subject =
        build_trusted_reproduced_subject().map_err(|_| ExitEvidenceErrorV1::SubjectConstruction)?;
    let host_environment = measure_host_environment()?;
    let completed_at_unix_seconds = unix_time()?;
    let payload = build_reproduction_payload(
        &subject,
        &protected.policy,
        &protected.challenge,
        started_at_unix_seconds,
        completed_at_unix_seconds,
        host_environment,
    )?;
    let signing_digest_hex = encode_hex(&signing_digest(REPRODUCTION_SIGNATURE_DOMAIN, &payload));
    let output = canonical_json(&IndependentHostPrepareEnvelopeV1 {
        schema: PREPARE_SCHEMA.to_owned(),
        review_subject: subject
            .document()
            .map_err(|_| ExitEvidenceErrorV1::SubjectConstruction)?,
        unsigned_reproduction_payload: payload,
        signing_digest_hex,
    });
    require_subject_checkout_current(&subject)
        .map_err(|_| ExitEvidenceErrorV1::SubjectConstruction)?;
    Ok(output)
}

pub(crate) fn finalize_independent_host_reproduction(
    request_bytes: &[u8],
) -> Result<Vec<u8>, ExitEvidenceErrorV1> {
    let request = parse_finalize_request(request_bytes)?;
    let protected = load_protected_inputs().map_err(|_| ExitEvidenceErrorV1::ProtectedInputs)?;
    authenticate_finalize_request(&request, &protected.policy)?;
    let subject =
        build_trusted_review_subject().map_err(|_| ExitEvidenceErrorV1::SubjectConstruction)?;
    let output =
        finalize_authenticated_request(request, &subject, &protected.policy, &protected.challenge)?;
    require_subject_checkout_current(&subject)
        .map_err(|_| ExitEvidenceErrorV1::SubjectConstruction)?;
    Ok(output)
}

#[cfg(test)]
fn parse_and_authenticate_finalize_request(
    request_bytes: &[u8],
    policy: &ValidatedAuthorityPolicyV1,
) -> Result<IndependentHostFinalizeRequestV1, ExitEvidenceErrorV1> {
    let request = parse_finalize_request(request_bytes)?;
    authenticate_finalize_request(&request, policy)?;
    Ok(request)
}

fn parse_finalize_request(
    request_bytes: &[u8],
) -> Result<IndependentHostFinalizeRequestV1, ExitEvidenceErrorV1> {
    if request_bytes.is_empty() {
        return Err(ExitEvidenceErrorV1::EmptyInput);
    }
    if request_bytes.len() > MAX_FINALIZE_REQUEST_BYTES {
        return Err(ExitEvidenceErrorV1::InputTooLarge);
    }
    let request: IndependentHostFinalizeRequestV1 = parse_canonical(request_bytes)?;
    require_equal(
        &request.schema,
        FINALIZE_REQUEST_SCHEMA,
        "finalize_request.schema",
    )?;
    require_equal(
        &request.prepare_envelope.schema,
        PREPARE_SCHEMA,
        "prepare_envelope.schema",
    )?;
    let payload = &request.prepare_envelope.unsigned_reproduction_payload;
    let expected_signing_digest = signing_digest(REPRODUCTION_SIGNATURE_DOMAIN, payload);
    if decode_hex::<32>(
        &request.prepare_envelope.signing_digest_hex,
        "signing_digest_hex",
    )? != expected_signing_digest
    {
        return Err(ExitEvidenceErrorV1::InvalidField("signing_digest_hex"));
    }
    decode_hex::<64>(&request.signature_hex, "signature_hex")?;
    Ok(request)
}

fn authenticate_finalize_request(
    request: &IndependentHostFinalizeRequestV1,
    policy: &ValidatedAuthorityPolicyV1,
) -> Result<(), ExitEvidenceErrorV1> {
    let payload = &request.prepare_envelope.unsigned_reproduction_payload;
    verify_signature(
        &policy.reproducer_key,
        REPRODUCTION_SIGNATURE_DOMAIN,
        payload,
        "ed25519",
        &request.signature_hex,
    )
}

fn finalize_authenticated_request(
    request: IndependentHostFinalizeRequestV1,
    subject: &TrustedReviewSubjectV1,
    policy: &ValidatedAuthorityPolicyV1,
    challenge: &ProjectChallengeV1,
) -> Result<Vec<u8>, ExitEvidenceErrorV1> {
    if canonical_json(&request.prepare_envelope.review_subject) != subject.canonical_json() {
        return Err(ExitEvidenceErrorV1::SubjectMismatch);
    }
    validate_reproduction_payload(
        &request.prepare_envelope.unsigned_reproduction_payload,
        policy,
        subject,
        challenge,
    )?;
    let record = SignedReproductionRecordV1 {
        payload: request.prepare_envelope.unsigned_reproduction_payload,
        signature_algorithm: "ed25519".to_owned(),
        signature_hex: request.signature_hex,
    };
    Ok(canonical_json(&record))
}

pub(crate) fn run_independent_host_record_check() -> Result<String, ExitEvidenceErrorV1> {
    let verified = verify_fixed_independent_host_reproduction()?;
    Ok(format!(
        "phase2b-independent-host-record-check ok: candidate_commit={} evidence_commit={} subject_digest={} reproduction_record_sha256={}",
        encode_hex(verified.candidate_commit()),
        encode_hex(verified.evidence_commit()),
        encode_hex(verified.subject_digest()),
        encode_hex(&verified.reproduction_record_digest()),
    ))
}

pub(crate) fn run_review_approval_check() -> Result<String, ExitEvidenceErrorV1> {
    let verified_reproduction = verify_fixed_independent_host_reproduction()?;
    let evidence_commit = *verified_reproduction.evidence_commit();
    let verified = verify_review_approval_from_reproduction(verified_reproduction)?;
    require_clean_checkout_at(&repository_root(), &evidence_commit)?;
    Ok(format!(
        "phase2b-review-approval-check ok: candidate_commit={} evidence_commit={} subject_digest={} authority_policy_sha256={} reproduction_record_sha256={} approval_record_sha256={} approval_sequence={}",
        encode_hex(verified.candidate_commit()),
        encode_hex(verified.evidence_commit()),
        encode_hex(verified.subject_digest()),
        encode_hex(verified.authority_policy_digest()),
        encode_hex(verified.reproduction_record_digest()),
        encode_hex(verified.approval_record_digest()),
        verified.approval_sequence(),
    ))
}

fn verify_review_approval_from_reproduction(
    verified: VerifiedPhase2bIndependentHostReproductionV1,
) -> Result<VerifiedPhase2bReviewApprovalV1, ExitEvidenceErrorV1> {
    let review_report = TrustedReviewReportV1 {
        sha256: Sha256::digest(&verified.review_report_bytes).into(),
    };
    let approval: SignedReviewApprovalV1 = parse_canonical(&verified.approval_record_bytes)?;
    validate_approval(
        &approval,
        &verified.policy,
        &verified.subject,
        &verified.reproduction_record_bytes,
        &review_report,
    )?;
    Ok(VerifiedPhase2bReviewApprovalV1 {
        evidence_commit: verified.evidence_commit,
        candidate_commit: verified.candidate_commit,
        subject_digest: *verified.subject.digest(),
        authority_policy_digest: verified.policy.canonical_sha256,
        reproduction_record_digest: Sha256::digest(&verified.reproduction_record_bytes).into(),
        approval_record_digest: Sha256::digest(&verified.approval_record_bytes).into(),
        approval_sequence: approval.payload.approval_sequence,
    })
}

fn verify_fixed_independent_host_reproduction(
) -> Result<VerifiedPhase2bIndependentHostReproductionV1, ExitEvidenceErrorV1> {
    let fixed = load_fixed_evidence_commit()?;
    let reproduction: SignedReproductionRecordV1 =
        parse_canonical(&fixed.reproduction_record_bytes)?;
    let protected = load_protected_inputs().map_err(|_| ExitEvidenceErrorV1::ProtectedInputs)?;
    verify_signature(
        &protected.policy.reproducer_key,
        REPRODUCTION_SIGNATURE_DOMAIN,
        &reproduction.payload,
        &reproduction.signature_algorithm,
        &reproduction.signature_hex,
    )?;
    let subject = build_trusted_review_subject_for_candidate(&fixed.candidate_commit)
        .map_err(|_| ExitEvidenceErrorV1::SubjectConstruction)?;
    if subject.canonical_json() != fixed.subject_bytes {
        return Err(ExitEvidenceErrorV1::SubjectMismatch);
    }
    validate_reproduction_payload(
        &reproduction.payload,
        &protected.policy,
        &subject,
        &protected.challenge,
    )?;
    require_clean_checkout_at(&repository_root(), &fixed.evidence_commit)?;
    Ok(VerifiedPhase2bIndependentHostReproductionV1 {
        evidence_commit: fixed.evidence_commit,
        candidate_commit: fixed.candidate_commit,
        subject,
        policy: protected.policy,
        reproduction_record_bytes: fixed.reproduction_record_bytes,
        review_report_bytes: fixed.review_report_bytes,
        approval_record_bytes: fixed.approval_record_bytes,
    })
}

fn load_fixed_evidence_commit() -> Result<FixedEvidenceCommitV1, ExitEvidenceErrorV1> {
    let root = repository_root();
    let evidence_commit = capture_clean_head(&root)?;
    let commit_oid = encode_hex(&evidence_commit);
    let commit_bytes = read_git_object(&root, &commit_oid, "commit", MAX_GIT_COMMIT_BYTES, None)?;
    let candidate_commit = parse_single_parent_commit(&commit_bytes)?;
    let candidate_oid = encode_hex(&candidate_commit);
    let diff = git_output_bounded(
        git_command(
            &root,
            &[
                "diff-tree",
                "--no-commit-id",
                "--raw",
                "-z",
                "-r",
                "--no-renames",
                "--full-index",
                &candidate_oid,
                &commit_oid,
                "--",
            ],
        ),
        MAX_GIT_DIFF_BYTES,
    )?;
    let entries = parse_fixed_evidence_diff(&diff)?;
    let mut blobs = Vec::new();
    for ((path, maximum_bytes), entry) in EVIDENCE_BLOBS.iter().zip(&entries) {
        if entry.path != *path {
            return Err(ExitEvidenceErrorV1::InvalidEvidenceCommit);
        }
        blobs.push(read_git_object(
            &root,
            &encode_hex(&entry.oid),
            "blob",
            *maximum_bytes,
            Some(path),
        )?);
    }
    let review_report_bytes = blobs.remove(0);
    let reproduction_record_bytes = blobs.remove(0);
    let approval_record_bytes = blobs.remove(0);
    let subject_bytes = blobs.remove(0);
    let claimed_candidate = candidate_commit_from_subject_bytes(&subject_bytes)
        .map_err(|_| ExitEvidenceErrorV1::SubjectMismatch)?;
    if claimed_candidate != candidate_commit {
        return Err(ExitEvidenceErrorV1::SubjectMismatch);
    }
    require_clean_checkout_at(&root, &evidence_commit)?;
    Ok(FixedEvidenceCommitV1 {
        evidence_commit,
        candidate_commit,
        subject_bytes,
        reproduction_record_bytes,
        review_report_bytes,
        approval_record_bytes,
    })
}

fn capture_clean_head(root: &Path) -> Result<[u8; 20], ExitEvidenceErrorV1> {
    let status = git_output_bounded(
        git_command(
            root,
            &[
                "status",
                "--porcelain=v1",
                "--untracked-files=all",
                "--ignore-submodules=none",
            ],
        ),
        MAX_GIT_DIFF_BYTES,
    )?;
    if !status.is_empty() {
        return Err(ExitEvidenceErrorV1::InvalidEvidenceCommit);
    }
    let head = git_line(root, &["rev-parse", "--verify", "HEAD"])?;
    decode_hex::<20>(&head, "evidence_commit")
}

fn require_clean_checkout_at(
    root: &Path,
    expected_head: &[u8; 20],
) -> Result<(), ExitEvidenceErrorV1> {
    if capture_clean_head(root)? == *expected_head {
        Ok(())
    } else {
        Err(ExitEvidenceErrorV1::InvalidEvidenceCommit)
    }
}

fn parse_single_parent_commit(bytes: &[u8]) -> Result<[u8; 20], ExitEvidenceErrorV1> {
    if bytes.contains(&b'\r') {
        return Err(ExitEvidenceErrorV1::InvalidEvidenceCommit);
    }
    let header_end = bytes
        .windows(2)
        .position(|window| window == b"\n\n")
        .ok_or(ExitEvidenceErrorV1::InvalidEvidenceCommit)?;
    let header = std::str::from_utf8(&bytes[..header_end])
        .map_err(|_| ExitEvidenceErrorV1::InvalidEvidenceCommit)?;
    let mut tree_count = 0;
    let mut parents = Vec::new();
    for line in header.lines() {
        if let Some(tree) = line.strip_prefix("tree ") {
            tree_count += 1;
            decode_hex::<20>(tree, "commit_tree")?;
        } else if let Some(parent) = line.strip_prefix("parent ") {
            parents.push(decode_hex::<20>(parent, "commit_parent")?);
        }
    }
    if tree_count == 1 && parents.len() == 1 {
        Ok(parents[0])
    } else {
        Err(ExitEvidenceErrorV1::InvalidEvidenceCommit)
    }
}

fn parse_fixed_evidence_diff(
    bytes: &[u8],
) -> Result<Vec<EvidenceBlobEntryV1>, ExitEvidenceErrorV1> {
    let mut offset = 0;
    let mut entries = Vec::new();
    while offset < bytes.len() {
        let header = take_nul_field(bytes, &mut offset)?;
        let path = take_nul_field(bytes, &mut offset)?;
        let header =
            std::str::from_utf8(header).map_err(|_| ExitEvidenceErrorV1::InvalidEvidenceCommit)?;
        let path =
            std::str::from_utf8(path).map_err(|_| ExitEvidenceErrorV1::InvalidEvidenceCommit)?;
        let fields = header.split_ascii_whitespace().collect::<Vec<_>>();
        if fields.len() != 5
            || fields[0] != ":000000"
            || fields[1] != "100644"
            || fields[2] != "0000000000000000000000000000000000000000"
            || fields[4] != "A"
            || path.is_empty()
        {
            return Err(ExitEvidenceErrorV1::InvalidEvidenceCommit);
        }
        entries.push(EvidenceBlobEntryV1 {
            path: path.to_owned(),
            oid: decode_hex::<20>(fields[3], "evidence_blob_oid")?,
        });
    }
    if entries.len() == EVIDENCE_BLOBS.len() {
        Ok(entries)
    } else {
        Err(ExitEvidenceErrorV1::InvalidEvidenceCommit)
    }
}

fn take_nul_field<'a>(
    bytes: &'a [u8],
    offset: &mut usize,
) -> Result<&'a [u8], ExitEvidenceErrorV1> {
    let remaining = bytes
        .get(*offset..)
        .ok_or(ExitEvidenceErrorV1::InvalidEvidenceCommit)?;
    let length = remaining
        .iter()
        .position(|byte| *byte == 0)
        .ok_or(ExitEvidenceErrorV1::InvalidEvidenceCommit)?;
    let value = &remaining[..length];
    *offset = offset
        .checked_add(length + 1)
        .ok_or(ExitEvidenceErrorV1::InvalidEvidenceCommit)?;
    Ok(value)
}

fn read_git_object(
    root: &Path,
    oid: &str,
    expected_type: &str,
    maximum_bytes: usize,
    evidence_path: Option<&'static str>,
) -> Result<Vec<u8>, ExitEvidenceErrorV1> {
    let object_type = git_line(root, &["cat-file", "-t", oid])?;
    if object_type != expected_type {
        return Err(evidence_path.map_or(
            ExitEvidenceErrorV1::InvalidEvidenceCommit,
            ExitEvidenceErrorV1::InvalidEvidenceBlob,
        ));
    }
    let size = git_line(root, &["cat-file", "-s", oid])?
        .parse::<usize>()
        .map_err(|_| ExitEvidenceErrorV1::InvalidEvidenceCommit)?;
    if size == 0 || size > maximum_bytes {
        return Err(ExitEvidenceErrorV1::EvidenceTooLarge);
    }
    let bytes = git_output_bounded(
        git_command(root, &["cat-file", expected_type, oid]),
        maximum_bytes,
    )?;
    if bytes.len() == size {
        Ok(bytes)
    } else {
        Err(ExitEvidenceErrorV1::GitCommand)
    }
}

fn git_line(root: &Path, arguments: &[&str]) -> Result<String, ExitEvidenceErrorV1> {
    let bytes = git_output_bounded(git_command(root, arguments), 4096)?;
    let source = std::str::from_utf8(&bytes).map_err(|_| ExitEvidenceErrorV1::GitCommand)?;
    let value = source
        .strip_suffix('\n')
        .ok_or(ExitEvidenceErrorV1::GitCommand)?;
    if value.is_empty() || value.contains('\n') || value.contains('\r') {
        Err(ExitEvidenceErrorV1::GitCommand)
    } else {
        Ok(value.to_owned())
    }
}

fn git_command(root: &Path, arguments: &[&str]) -> Command {
    let path = std::env::var_os("PATH");
    let temporary = std::env::var_os("TMPDIR");
    let mut command = Command::new("git");
    command.env_clear();
    if let Some(path) = path {
        command.env("PATH", path);
    }
    if let Some(temporary) = temporary {
        command.env("TMPDIR", temporary);
    }
    command
        .env("LC_ALL", "C")
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_ATTR_NOSYSTEM", "1")
        .env("GIT_CONFIG_COUNT", "0")
        .env("GIT_LITERAL_PATHSPECS", "1")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .current_dir(root)
        .args([
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.untrackedCache=false",
        ])
        .args(arguments);
    command
}

fn git_output_bounded(
    mut command: Command,
    maximum_stdout_bytes: usize,
) -> Result<Vec<u8>, ExitEvidenceErrorV1> {
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| ExitEvidenceErrorV1::GitCommand)?;
    let stdout = child.stdout.take().ok_or(ExitEvidenceErrorV1::GitCommand)?;
    let stderr = child.stderr.take().ok_or(ExitEvidenceErrorV1::GitCommand)?;
    let stdout_thread = thread::spawn(move || read_stream_bounded(stdout, maximum_stdout_bytes));
    let stderr_thread = thread::spawn(move || read_stream_bounded(stderr, MAX_GIT_STDERR_BYTES));
    let status = child.wait().map_err(|_| ExitEvidenceErrorV1::GitCommand)?;
    let stdout = stdout_thread
        .join()
        .map_err(|_| ExitEvidenceErrorV1::GitCommand)??;
    let stderr = stderr_thread
        .join()
        .map_err(|_| ExitEvidenceErrorV1::GitCommand)??;
    if status.success() && stderr.is_empty() {
        Ok(stdout)
    } else {
        Err(ExitEvidenceErrorV1::GitCommand)
    }
}

fn read_stream_bounded(
    reader: impl Read,
    maximum_bytes: usize,
) -> Result<Vec<u8>, ExitEvidenceErrorV1> {
    let limit =
        u64::try_from(maximum_bytes).map_err(|_| ExitEvidenceErrorV1::EvidenceTooLarge)? + 1;
    let mut bytes = Vec::new();
    reader
        .take(limit)
        .read_to_end(&mut bytes)
        .map_err(|_| ExitEvidenceErrorV1::GitCommand)?;
    if bytes.len() > maximum_bytes {
        Err(ExitEvidenceErrorV1::EvidenceTooLarge)
    } else {
        Ok(bytes)
    }
}

fn unix_time() -> Result<u64, ExitEvidenceErrorV1> {
    let value = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ExitEvidenceErrorV1::Clock)?
        .as_secs();
    require_nonzero(value, "unix_time")?;
    Ok(value)
}

fn build_reproduction_payload(
    subject: &TrustedReviewSubjectV1,
    policy: &ValidatedAuthorityPolicyV1,
    challenge: &ProjectChallengeV1,
    started_at_unix_seconds: u64,
    completed_at_unix_seconds: u64,
    host_environment: HostEnvironmentV1,
) -> Result<ReproductionPayloadV1, ExitEvidenceErrorV1> {
    require_nonzero(started_at_unix_seconds, "started_at_unix_seconds")?;
    if completed_at_unix_seconds < started_at_unix_seconds {
        return Err(ExitEvidenceErrorV1::InvalidField(
            "completed_at_unix_seconds",
        ));
    }
    validate_host_environment(&host_environment)?;
    let authority = &policy.policy.independent_reproducer;
    let payload = ReproductionPayloadV1 {
        schema: REPRODUCTION_SCHEMA.to_owned(),
        protocol_id: PROTOCOL_ID.to_owned(),
        evidence_scope: REPRODUCTION_SCOPE.to_owned(),
        authority_policy_sha256_hex: encode_hex(&policy.canonical_sha256),
        subject_digest_hex: encode_hex(subject.digest()),
        source_commit_hex: encode_hex(subject.source_commit()),
        source_tree_hex: encode_hex(subject.source_tree()),
        operator_assertion: OperatorAssertionV1 {
            operator_id: authority.authority_id.clone(),
            operator_key_epoch: authority.key_epoch,
            operator_authority_key_digest_hex: authority.authority_key_digest_hex.clone(),
            challenge_hex: encode_hex(challenge.bytes()),
            independence_claim:
                "operator_and_execution_host_are_independent_of_primary_implementation_environment"
                    .to_owned(),
            started_at_unix_seconds,
            completed_at_unix_seconds,
        },
        host_environment,
        execution: ReproductionExecutionV1 {
            runner_contract: "cargo_yao_fv_phase2b_independent_host_reproduce_v1".to_owned(),
            locked_dependencies: true,
            committed_certificate_check: "passed".to_owned(),
            phase2b_reconciliation_cases: 5,
            phase2b_reconciliation_rust_tests: 6,
            phase2b_reconciliation_python_tests: 4,
            artifact_python_tests: 24,
        },
        observations: reproduction_observations(subject.observations()),
        explicit_nonclaims: REPRODUCTION_NONCLAIMS
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
    };
    Ok(payload)
}

fn reproduction_observations(value: &FreshArtifactObservationsV1) -> ReproductionObservationsV1 {
    ReproductionObservationsV1 {
        manifest_canonical_bytes: value.manifest_canonical_bytes,
        manifest_digest_hex: encode_hex(&value.manifest_digest),
        bundle_index_canonical_bytes: value.bundle_index_canonical_bytes,
        bundle_index_digest_hex: encode_hex(&value.bundle_index_digest),
        artifact_entries: value
            .artifact_entries
            .iter()
            .map(|entry| ArtifactEntryV1 {
                tag: entry.tag,
                filename: entry.filename.clone(),
                canonical_bytes: entry.canonical_bytes,
                sha256_hex: encode_hex(&entry.sha256),
            })
            .collect(),
    }
}

fn measure_host_environment() -> Result<HostEnvironmentV1, ExitEvidenceErrorV1> {
    Ok(HostEnvironmentV1 {
        operating_system: std::env::consts::OS.to_owned(),
        architecture: std::env::consts::ARCH.to_owned(),
        kernel_release: kernel_release()?,
        artifact_filesystem_policy: "accepted_local_filesystem".to_owned(),
        checkout_state: "clean_exact_commit".to_owned(),
        cargo_target_state: "fresh_process_owned_directory".to_owned(),
    })
}

fn kernel_release() -> Result<String, ExitEvidenceErrorV1> {
    let output = Command::new("uname")
        .arg("-r")
        .output()
        .map_err(|_| ExitEvidenceErrorV1::HostEnvironment)?;
    if !output.status.success() || !output.stderr.is_empty() {
        return Err(ExitEvidenceErrorV1::HostEnvironment);
    }
    let source =
        String::from_utf8(output.stdout).map_err(|_| ExitEvidenceErrorV1::HostEnvironment)?;
    let value = source
        .strip_suffix('\n')
        .ok_or(ExitEvidenceErrorV1::HostEnvironment)?;
    require_visible_ascii(value, "kernel_release")?;
    Ok(value.to_owned())
}

#[cfg(test)]
fn verify_phase2b_exit_evidence_v1(
    subject: &TrustedReviewSubjectV1,
    policy: &ValidatedAuthorityPolicyV1,
    challenge: &ProjectChallengeV1,
    review_report: &TrustedReviewReportV1,
    reproduction_record_bytes: &[u8],
    approval_record_bytes: &[u8],
) -> Result<VerifiedPhase2bReviewApprovalV1, ExitEvidenceErrorV1> {
    let reproduction: SignedReproductionRecordV1 = parse_canonical(reproduction_record_bytes)?;
    validate_reproduction(&reproduction, policy, subject, challenge)?;
    let approval: SignedReviewApprovalV1 = parse_canonical(approval_record_bytes)?;
    validate_approval(
        &approval,
        policy,
        subject,
        reproduction_record_bytes,
        review_report,
    )?;
    Ok(VerifiedPhase2bReviewApprovalV1 {
        evidence_commit: [0x88; 20],
        candidate_commit: *subject.source_commit(),
        subject_digest: *subject.digest(),
        authority_policy_digest: policy.canonical_sha256,
        reproduction_record_digest: Sha256::digest(reproduction_record_bytes).into(),
        approval_record_digest: Sha256::digest(approval_record_bytes).into(),
        approval_sequence: approval.payload.approval_sequence,
    })
}

#[cfg(test)]
fn validate_reproduction(
    record: &SignedReproductionRecordV1,
    policy: &ValidatedAuthorityPolicyV1,
    subject: &TrustedReviewSubjectV1,
    challenge: &ProjectChallengeV1,
) -> Result<(), ExitEvidenceErrorV1> {
    let payload = &record.payload;
    validate_reproduction_payload(payload, policy, subject, challenge)?;
    verify_signature(
        &policy.reproducer_key,
        REPRODUCTION_SIGNATURE_DOMAIN,
        payload,
        &record.signature_algorithm,
        &record.signature_hex,
    )
}

fn validate_reproduction_payload(
    payload: &ReproductionPayloadV1,
    policy: &ValidatedAuthorityPolicyV1,
    subject: &TrustedReviewSubjectV1,
    challenge: &ProjectChallengeV1,
) -> Result<(), ExitEvidenceErrorV1> {
    require_equal(&payload.schema, REPRODUCTION_SCHEMA, "reproduction.schema")?;
    require_equal(
        &payload.protocol_id,
        PROTOCOL_ID,
        "reproduction.protocol_id",
    )?;
    require_equal(
        &payload.evidence_scope,
        REPRODUCTION_SCOPE,
        "reproduction.evidence_scope",
    )?;
    if decode_hex::<32>(
        &payload.authority_policy_sha256_hex,
        "authority_policy_sha256_hex",
    )? != policy.canonical_sha256
    {
        return Err(ExitEvidenceErrorV1::ProtectedPolicyDigestMismatch);
    }
    if decode_hex::<32>(&payload.subject_digest_hex, "subject_digest_hex")? != *subject.digest() {
        return Err(ExitEvidenceErrorV1::SubjectMismatch);
    }
    if decode_hex::<20>(&payload.source_commit_hex, "source_commit_hex")?
        != *subject.source_commit()
        || decode_hex::<20>(&payload.source_tree_hex, "source_tree_hex")? != *subject.source_tree()
    {
        return Err(ExitEvidenceErrorV1::SubjectMismatch);
    }
    let assertion = &payload.operator_assertion;
    let authority = &policy.policy.independent_reproducer;
    require_equal(
        &assertion.operator_id,
        &authority.authority_id,
        "operator_id",
    )?;
    if assertion.operator_key_epoch != authority.key_epoch {
        return Err(ExitEvidenceErrorV1::InvalidField("operator_key_epoch"));
    }
    require_equal(
        &assertion.operator_authority_key_digest_hex,
        &authority.authority_key_digest_hex,
        "operator_authority_key_digest_hex",
    )?;
    if decode_hex::<32>(&assertion.challenge_hex, "challenge_hex")? != *challenge.bytes() {
        return Err(ExitEvidenceErrorV1::ChallengeMismatch);
    }
    require_equal(
        &assertion.independence_claim,
        "operator_and_execution_host_are_independent_of_primary_implementation_environment",
        "independence_claim",
    )?;
    require_nonzero(assertion.started_at_unix_seconds, "started_at_unix_seconds")?;
    if assertion.completed_at_unix_seconds < assertion.started_at_unix_seconds {
        return Err(ExitEvidenceErrorV1::InvalidField(
            "completed_at_unix_seconds",
        ));
    }
    validate_host_environment(&payload.host_environment)?;
    validate_execution(&payload.execution)?;
    validate_observations(&payload.observations, subject.observations())?;
    require_string_list(
        &payload.explicit_nonclaims,
        &REPRODUCTION_NONCLAIMS,
        "reproduction.explicit_nonclaims",
    )
}

fn validate_host_environment(value: &HostEnvironmentV1) -> Result<(), ExitEvidenceErrorV1> {
    require_visible_ascii(&value.operating_system, "operating_system")?;
    require_visible_ascii(&value.architecture, "architecture")?;
    require_visible_ascii(&value.kernel_release, "kernel_release")?;
    require_equal(
        &value.artifact_filesystem_policy,
        "accepted_local_filesystem",
        "artifact_filesystem_policy",
    )?;
    require_equal(
        &value.checkout_state,
        "clean_exact_commit",
        "checkout_state",
    )?;
    require_equal(
        &value.cargo_target_state,
        "fresh_process_owned_directory",
        "cargo_target_state",
    )
}

fn validate_execution(value: &ReproductionExecutionV1) -> Result<(), ExitEvidenceErrorV1> {
    require_equal(
        &value.runner_contract,
        "cargo_yao_fv_phase2b_independent_host_reproduce_v1",
        "runner_contract",
    )?;
    if !value.locked_dependencies {
        return Err(ExitEvidenceErrorV1::InvalidField("locked_dependencies"));
    }
    require_equal(
        &value.committed_certificate_check,
        "passed",
        "committed_certificate_check",
    )?;
    for (actual, expected, field) in [
        (
            value.phase2b_reconciliation_cases,
            5,
            "phase2b_reconciliation_cases",
        ),
        (
            value.phase2b_reconciliation_rust_tests,
            6,
            "phase2b_reconciliation_rust_tests",
        ),
        (
            value.phase2b_reconciliation_python_tests,
            4,
            "phase2b_reconciliation_python_tests",
        ),
        (value.artifact_python_tests, 24, "artifact_python_tests"),
    ] {
        if actual != expected {
            return Err(ExitEvidenceErrorV1::InvalidField(field));
        }
    }
    Ok(())
}

fn validate_observations(
    value: &ReproductionObservationsV1,
    expected: &FreshArtifactObservationsV1,
) -> Result<(), ExitEvidenceErrorV1> {
    if value.manifest_canonical_bytes != 1973
        || value.bundle_index_canonical_bytes != 387
        || value.manifest_digest_hex != MANIFEST_DIGEST_HEX
        || value.bundle_index_digest_hex != BUNDLE_INDEX_DIGEST_HEX
        || value.artifact_entries.len() != ARTIFACTS.len()
        || value.manifest_canonical_bytes != expected.manifest_canonical_bytes
        || value.manifest_digest_hex != encode_hex(&expected.manifest_digest)
        || value.bundle_index_canonical_bytes != expected.bundle_index_canonical_bytes
        || value.bundle_index_digest_hex != encode_hex(&expected.bundle_index_digest)
        || value.artifact_entries.len() != expected.artifact_entries.len()
    {
        return Err(ExitEvidenceErrorV1::InvalidField("observations"));
    }
    for ((entry, expected_entry), (tag, filename)) in value
        .artifact_entries
        .iter()
        .zip(&expected.artifact_entries)
        .zip(ARTIFACTS)
    {
        if entry.tag != tag
            || entry.filename != filename
            || entry.canonical_bytes == 0
            || entry.tag != expected_entry.tag
            || entry.filename != expected_entry.filename
            || entry.canonical_bytes != expected_entry.canonical_bytes
            || entry.sha256_hex != encode_hex(&expected_entry.sha256)
        {
            return Err(ExitEvidenceErrorV1::InvalidField("artifact_entries"));
        }
        decode_hex::<32>(&entry.sha256_hex, "artifact.sha256_hex")?;
    }
    Ok(())
}

fn validate_approval(
    record: &SignedReviewApprovalV1,
    policy: &ValidatedAuthorityPolicyV1,
    subject: &TrustedReviewSubjectV1,
    reproduction_record_bytes: &[u8],
    review_report: &TrustedReviewReportV1,
) -> Result<(), ExitEvidenceErrorV1> {
    let payload = &record.payload;
    require_equal(&payload.schema, APPROVAL_SCHEMA, "approval.schema")?;
    require_equal(&payload.protocol_id, PROTOCOL_ID, "approval.protocol_id")?;
    require_equal(
        &payload.approval_scope,
        APPROVAL_SCOPE,
        "approval.approval_scope",
    )?;
    require_equal(
        &payload.decision,
        "approve_exact_subject",
        "approval.decision",
    )?;
    if payload.approval_sequence < policy.policy.minimum_approval_sequence {
        return Err(ExitEvidenceErrorV1::StaleApproval);
    }
    if decode_hex::<32>(
        &payload.authority_policy_sha256_hex,
        "authority_policy_sha256_hex",
    )? != policy.canonical_sha256
    {
        return Err(ExitEvidenceErrorV1::ProtectedPolicyDigestMismatch);
    }
    if decode_hex::<32>(&payload.subject_digest_hex, "subject_digest_hex")? != *subject.digest() {
        return Err(ExitEvidenceErrorV1::SubjectMismatch);
    }
    if decode_hex::<32>(
        &payload.independent_reproduction_record_sha256_hex,
        "independent_reproduction_record_sha256_hex",
    )? != Sha256::digest(reproduction_record_bytes).as_slice()
    {
        return Err(ExitEvidenceErrorV1::ReproductionRecordMismatch);
    }
    require_equal(
        &payload.review_report_path,
        REVIEW_REPORT_PATH,
        "review_report_path",
    )?;
    if decode_hex::<32>(
        &payload.review_report_sha256_hex,
        "review_report_sha256_hex",
    )? != review_report.sha256
    {
        return Err(ExitEvidenceErrorV1::ReportDigestMismatch);
    }
    require_nonzero(payload.reviewed_at_unix_seconds, "reviewed_at_unix_seconds")?;
    let authority = &policy.policy.cryptographic_reviewer;
    require_equal(
        &payload.reviewer_authority_id,
        &authority.authority_id,
        "reviewer_authority_id",
    )?;
    if payload.reviewer_key_epoch != authority.key_epoch {
        return Err(ExitEvidenceErrorV1::InvalidField("reviewer_key_epoch"));
    }
    require_equal(
        &payload.reviewer_authority_key_digest_hex,
        &authority.authority_key_digest_hex,
        "reviewer_authority_key_digest_hex",
    )?;
    require_string_list(
        &payload.reviewed_surfaces,
        &REVIEWED_SURFACES,
        "reviewed_surfaces",
    )?;
    let subject_nonclaims = subject
        .explicit_nonclaims()
        .map_err(|_| ExitEvidenceErrorV1::SubjectConstruction)?;
    if payload.explicit_nonclaims != subject_nonclaims {
        return Err(ExitEvidenceErrorV1::InvalidField(
            "approval.explicit_nonclaims",
        ));
    }
    verify_signature(
        &policy.reviewer_key,
        APPROVAL_SIGNATURE_DOMAIN,
        payload,
        &record.signature_algorithm,
        &record.signature_hex,
    )
}

fn verify_signature<T: Serialize>(
    key: &VerifyingKey,
    domain: &[u8],
    payload: &T,
    algorithm: &str,
    signature_hex: &str,
) -> Result<(), ExitEvidenceErrorV1> {
    require_equal(algorithm, "ed25519", "signature_algorithm")?;
    let signature = decode_hex::<64>(signature_hex, "signature_hex")?;
    let digest = signing_digest(domain, payload);
    key.verify_strict(&digest, &Signature::from_bytes(&signature))
        .map_err(|_| ExitEvidenceErrorV1::InvalidSignature)
}

fn signing_digest<T: Serialize>(domain: &[u8], payload: &T) -> [u8; 32] {
    let bytes = canonical_json(payload);
    let mut preimage = Vec::new();
    push_lp32(&mut preimage, domain);
    push_lp32(&mut preimage, &bytes);
    Sha256::digest(preimage).into()
}

fn parse_canonical<T>(bytes: &[u8]) -> Result<T, ExitEvidenceErrorV1>
where
    T: DeserializeOwned + Serialize,
{
    let value: T = serde_json::from_slice(bytes).map_err(|_| ExitEvidenceErrorV1::Json)?;
    if canonical_json(&value) != bytes {
        return Err(ExitEvidenceErrorV1::NonCanonicalJson);
    }
    Ok(value)
}

fn canonical_json<T: Serialize>(value: &T) -> Vec<u8> {
    let mut bytes = serde_json::to_vec_pretty(value).expect("fixed evidence structure serializes");
    bytes.push(b'\n');
    bytes
}

fn decode_hex<const N: usize>(
    value: &str,
    field: &'static str,
) -> Result<[u8; N], ExitEvidenceErrorV1> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ExitEvidenceErrorV1::InvalidHex(field));
    }
    let mut output = [0u8; N];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| ExitEvidenceErrorV1::InvalidHex(field))?;
    }
    Ok(output)
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn push_lp32(output: &mut Vec<u8>, value: &[u8]) {
    let length = u32::try_from(value.len()).expect("host evidence field fits LP32");
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
}

fn require_equal(
    actual: &str,
    expected: &str,
    field: &'static str,
) -> Result<(), ExitEvidenceErrorV1> {
    if actual == expected {
        Ok(())
    } else {
        Err(ExitEvidenceErrorV1::InvalidField(field))
    }
}

fn require_nonzero(value: u64, field: &'static str) -> Result<(), ExitEvidenceErrorV1> {
    if value == 0 {
        Err(ExitEvidenceErrorV1::InvalidField(field))
    } else {
        Ok(())
    }
}

fn require_visible_ascii(value: &str, field: &'static str) -> Result<(), ExitEvidenceErrorV1> {
    if value.is_empty()
        || value.trim() != value
        || !value
            .bytes()
            .all(|byte| byte.is_ascii() && !byte.is_ascii_control())
    {
        Err(ExitEvidenceErrorV1::InvalidField(field))
    } else {
        Ok(())
    }
}

fn require_string_list(
    actual: &[String],
    expected: &[&str],
    field: &'static str,
) -> Result<(), ExitEvidenceErrorV1> {
    if actual
        .iter()
        .map(String::as_str)
        .eq(expected.iter().copied())
    {
        Ok(())
    } else {
        Err(ExitEvidenceErrorV1::InvalidField(field))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    const SUBJECT: [u8; 32] = [0x44; 32];
    const CHALLENGE: [u8; 32] = [0x55; 32];
    const REVIEW_REPORT: &[u8] = b"independent Phase 2B review report\n";

    struct Fixture {
        policy: ReviewAuthorityPolicyV1,
        subject: TrustedReviewSubjectV1,
        reproducer: SigningKey,
        reviewer: SigningKey,
        reproduction: SignedReproductionRecordV1,
        approval: SignedReviewApprovalV1,
    }

    fn build_fixture() -> Fixture {
        let reproducer = SigningKey::from_bytes(&[0x11; 32]);
        let reviewer = SigningKey::from_bytes(&[0x22; 32]);
        let reproducer_authority = authority(REPRODUCER_ROLE, "operator-a", 3, &reproducer);
        let reviewer_authority = authority(REVIEWER_ROLE, "reviewer-b", 7, &reviewer);
        let policy = ReviewAuthorityPolicyV1 {
            schema: POLICY_SCHEMA.to_owned(),
            protocol_id: PROTOCOL_ID.to_owned(),
            policy_scope: POLICY_SCOPE.to_owned(),
            policy_version: 1,
            minimum_approval_sequence: 9,
            independent_reproducer: reproducer_authority.clone(),
            cryptographic_reviewer: reviewer_authority.clone(),
            required_distinct_authorities: true,
        };
        let policy_digest: [u8; 32] = Sha256::digest(canonical_json(&policy)).into();
        let reproduction_payload = reproduction_payload(&reproducer_authority, policy_digest);
        let subject = TrustedReviewSubjectV1::synthetic(
            SUBJECT,
            [0x66; 20],
            [0x77; 20],
            FreshArtifactObservationsV1 {
                manifest_canonical_bytes: reproduction_payload
                    .observations
                    .manifest_canonical_bytes,
                manifest_digest: decode_hex::<32>(
                    &reproduction_payload.observations.manifest_digest_hex,
                    "manifest_digest_hex",
                )
                .expect("fixed manifest digest"),
                bundle_index_canonical_bytes: reproduction_payload
                    .observations
                    .bundle_index_canonical_bytes,
                bundle_index_digest: decode_hex::<32>(
                    &reproduction_payload.observations.bundle_index_digest_hex,
                    "bundle_index_digest_hex",
                )
                .expect("fixed bundle-index digest"),
                artifact_entries: reproduction_payload
                    .observations
                    .artifact_entries
                    .iter()
                    .map(
                        |entry| crate::phase2b_review_subject::FreshArtifactEntryV1 {
                            tag: entry.tag,
                            filename: entry.filename.clone(),
                            canonical_bytes: entry.canonical_bytes,
                            sha256: decode_hex::<32>(&entry.sha256_hex, "artifact.sha256_hex")
                                .expect("fixed artifact digest"),
                        },
                    )
                    .collect(),
            },
        );
        let reproduction = sign_reproduction(reproduction_payload, &reproducer);
        let reproduction_bytes = canonical_json(&reproduction);
        let approval_payload = ReviewApprovalPayloadV1 {
            schema: APPROVAL_SCHEMA.to_owned(),
            protocol_id: PROTOCOL_ID.to_owned(),
            approval_scope: APPROVAL_SCOPE.to_owned(),
            decision: "approve_exact_subject".to_owned(),
            approval_sequence: 9,
            authority_policy_sha256_hex: encode_hex(&policy_digest),
            subject_digest_hex: encode_hex(&SUBJECT),
            independent_reproduction_record_sha256_hex: encode_hex(&Sha256::digest(
                &reproduction_bytes,
            )),
            review_report_path: REVIEW_REPORT_PATH.to_owned(),
            review_report_sha256_hex: encode_hex(&Sha256::digest(REVIEW_REPORT)),
            reviewed_at_unix_seconds: 1_700_000_300,
            reviewer_authority_id: reviewer_authority.authority_id.clone(),
            reviewer_key_epoch: reviewer_authority.key_epoch,
            reviewer_authority_key_digest_hex: reviewer_authority.authority_key_digest_hex.clone(),
            reviewed_surfaces: REVIEWED_SURFACES
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
            explicit_nonclaims: subject
                .explicit_nonclaims()
                .expect("synthetic subject nonclaims"),
        };
        let approval = sign_approval(approval_payload, &reviewer);
        Fixture {
            policy,
            subject,
            reproducer,
            reviewer,
            reproduction,
            approval,
        }
    }

    fn authority(role: &str, id: &str, epoch: u64, key: &SigningKey) -> ReviewAuthorityV1 {
        let verifying = key.verifying_key().to_bytes();
        ReviewAuthorityV1 {
            role: role.to_owned(),
            authority_id: id.to_owned(),
            key_epoch: epoch,
            verifying_key_hex: encode_hex(&verifying),
            authority_key_digest_hex: encode_hex(&authority_digest(role, id, epoch, &verifying)),
        }
    }

    fn reproduction_payload(
        authority: &ReviewAuthorityV1,
        policy_digest: [u8; 32],
    ) -> ReproductionPayloadV1 {
        ReproductionPayloadV1 {
            schema: REPRODUCTION_SCHEMA.to_owned(),
            protocol_id: PROTOCOL_ID.to_owned(),
            evidence_scope: REPRODUCTION_SCOPE.to_owned(),
            authority_policy_sha256_hex: encode_hex(&policy_digest),
            subject_digest_hex: encode_hex(&SUBJECT),
            source_commit_hex: encode_hex(&[0x66; 20]),
            source_tree_hex: encode_hex(&[0x77; 20]),
            operator_assertion: OperatorAssertionV1 {
                operator_id: authority.authority_id.clone(),
                operator_key_epoch: authority.key_epoch,
                operator_authority_key_digest_hex: authority.authority_key_digest_hex.clone(),
                challenge_hex: encode_hex(&CHALLENGE),
                independence_claim: "operator_and_execution_host_are_independent_of_primary_implementation_environment".to_owned(),
                started_at_unix_seconds: 1_700_000_000,
                completed_at_unix_seconds: 1_700_000_100,
            },
            host_environment: HostEnvironmentV1 {
                operating_system: "linux".to_owned(),
                architecture: "x86_64".to_owned(),
                kernel_release: "6.12".to_owned(),
                artifact_filesystem_policy: "accepted_local_filesystem".to_owned(),
                checkout_state: "clean_exact_commit".to_owned(),
                cargo_target_state: "fresh_process_owned_directory".to_owned(),
            },
            execution: ReproductionExecutionV1 {
                runner_contract: "cargo_yao_fv_phase2b_independent_host_reproduce_v1".to_owned(),
                locked_dependencies: true,
                committed_certificate_check: "passed".to_owned(),
                phase2b_reconciliation_cases: 5,
                phase2b_reconciliation_rust_tests: 6,
                phase2b_reconciliation_python_tests: 4,
                artifact_python_tests: 24,
            },
            observations: ReproductionObservationsV1 {
                manifest_canonical_bytes: 1973,
                manifest_digest_hex: MANIFEST_DIGEST_HEX.to_owned(),
                bundle_index_canonical_bytes: 387,
                bundle_index_digest_hex: BUNDLE_INDEX_DIGEST_HEX.to_owned(),
                artifact_entries: ARTIFACTS
                    .iter()
                    .enumerate()
                    .map(|(index, (tag, filename))| ArtifactEntryV1 {
                        tag: *tag,
                        filename: (*filename).to_owned(),
                        canonical_bytes: 100 + index as u64,
                        sha256_hex: encode_hex(&[0x80 + index as u8; 32]),
                    })
                    .collect(),
            },
            explicit_nonclaims: REPRODUCTION_NONCLAIMS
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
        }
    }

    fn sign_reproduction(
        payload: ReproductionPayloadV1,
        key: &SigningKey,
    ) -> SignedReproductionRecordV1 {
        let digest = signing_digest(REPRODUCTION_SIGNATURE_DOMAIN, &payload);
        SignedReproductionRecordV1 {
            payload,
            signature_algorithm: "ed25519".to_owned(),
            signature_hex: encode_hex(&key.sign(&digest).to_bytes()),
        }
    }

    fn sign_approval(payload: ReviewApprovalPayloadV1, key: &SigningKey) -> SignedReviewApprovalV1 {
        let digest = signing_digest(APPROVAL_SIGNATURE_DOMAIN, &payload);
        SignedReviewApprovalV1 {
            payload,
            signature_algorithm: "ed25519".to_owned(),
            signature_hex: encode_hex(&key.sign(&digest).to_bytes()),
        }
    }

    fn verify(fixture: &Fixture) -> Result<VerifiedPhase2bReviewApprovalV1, ExitEvidenceErrorV1> {
        let policy_bytes = canonical_json(&fixture.policy);
        let policy_digest: [u8; 32] = Sha256::digest(&policy_bytes).into();
        let policy = validate_policy(&policy_bytes, policy_digest).expect("valid test policy");
        let challenge = ProjectChallengeV1::synthetic(CHALLENGE);
        let review_report = TrustedReviewReportV1 {
            sha256: Sha256::digest(REVIEW_REPORT).into(),
        };
        verify_phase2b_exit_evidence_v1(
            &fixture.subject,
            &policy,
            &challenge,
            &review_report,
            &canonical_json(&fixture.reproduction),
            &canonical_json(&fixture.approval),
        )
    }

    fn rebuild_approval(fixture: &mut Fixture) {
        let bytes = canonical_json(&fixture.reproduction);
        fixture
            .approval
            .payload
            .independent_reproduction_record_sha256_hex = encode_hex(&Sha256::digest(bytes));
        fixture.approval = sign_approval(fixture.approval.payload.clone(), &fixture.reviewer);
    }

    fn validated_fixture_policy(fixture: &Fixture) -> ValidatedAuthorityPolicyV1 {
        let bytes = canonical_json(&fixture.policy);
        let digest = Sha256::digest(&bytes).into();
        validate_policy(&bytes, digest).expect("valid test policy")
    }

    fn fixture_host_environment() -> HostEnvironmentV1 {
        HostEnvironmentV1 {
            operating_system: "linux".to_owned(),
            architecture: "x86_64".to_owned(),
            kernel_release: "6.12".to_owned(),
            artifact_filesystem_policy: "accepted_local_filesystem".to_owned(),
            checkout_state: "clean_exact_commit".to_owned(),
            cargo_target_state: "fresh_process_owned_directory".to_owned(),
        }
    }

    fn build_finalize_request(fixture: &Fixture) -> IndependentHostFinalizeRequestV1 {
        let payload = fixture.reproduction.payload.clone();
        IndependentHostFinalizeRequestV1 {
            schema: FINALIZE_REQUEST_SCHEMA.to_owned(),
            prepare_envelope: IndependentHostPrepareEnvelopeV1 {
                schema: PREPARE_SCHEMA.to_owned(),
                review_subject: fixture
                    .subject
                    .document()
                    .expect("synthetic subject document"),
                signing_digest_hex: encode_hex(&signing_digest(
                    REPRODUCTION_SIGNATURE_DOMAIN,
                    &payload,
                )),
                unsigned_reproduction_payload: payload,
            },
            signature_hex: fixture.reproduction.signature_hex.clone(),
        }
    }

    fn finalize_fixture_request(
        fixture: &Fixture,
        request_bytes: &[u8],
        challenge: [u8; 32],
    ) -> Result<Vec<u8>, ExitEvidenceErrorV1> {
        let policy = validated_fixture_policy(fixture);
        let request = parse_and_authenticate_finalize_request(request_bytes, &policy)?;
        finalize_authenticated_request(
            request,
            &fixture.subject,
            &policy,
            &ProjectChallengeV1::synthetic(challenge),
        )
    }

    fn resign_finalize_request(request: &mut IndependentHostFinalizeRequestV1, key: &SigningKey) {
        let payload = &request.prepare_envelope.unsigned_reproduction_payload;
        let digest = signing_digest(REPRODUCTION_SIGNATURE_DOMAIN, payload);
        request.prepare_envelope.signing_digest_hex = encode_hex(&digest);
        request.signature_hex = encode_hex(&key.sign(&digest).to_bytes());
    }

    fn canonical_evidence_diff() -> Vec<u8> {
        let mut bytes = Vec::new();
        for (index, (path, _)) in EVIDENCE_BLOBS.iter().enumerate() {
            let oid = encode_hex(&[0x10 + index as u8; 20]);
            bytes.extend_from_slice(
                format!(":000000 100644 0000000000000000000000000000000000000000 {oid} A")
                    .as_bytes(),
            );
            bytes.push(0);
            bytes.extend_from_slice(path.as_bytes());
            bytes.push(0);
        }
        bytes
    }

    fn build_fixture_prepare_payload(
        fixture: &Fixture,
        policy: &ValidatedAuthorityPolicyV1,
        started_at_unix_seconds: u64,
        completed_at_unix_seconds: u64,
        host_environment: HostEnvironmentV1,
    ) -> Result<ReproductionPayloadV1, ExitEvidenceErrorV1> {
        build_reproduction_payload(
            &fixture.subject,
            policy,
            &ProjectChallengeV1::synthetic(CHALLENGE),
            started_at_unix_seconds,
            completed_at_unix_seconds,
            host_environment,
        )
    }

    #[test]
    fn prepare_payload_binds_the_validated_policy_subject_challenge_and_host() {
        let fixture = build_fixture();
        let policy = validated_fixture_policy(&fixture);
        let payload = build_fixture_prepare_payload(
            &fixture,
            &policy,
            1_700_000_000,
            1_700_000_100,
            fixture_host_environment(),
        )
        .expect("valid prepare payload");

        assert_eq!(
            canonical_json(&payload),
            canonical_json(&fixture.reproduction.payload)
        );
        assert_eq!(
            encode_hex(&signing_digest(REPRODUCTION_SIGNATURE_DOMAIN, &payload)),
            "b7b66c76d7dce22e83d11176ab61120d6828e28062e68531d15e6feec2414a55"
        );
    }

    #[test]
    fn prepare_payload_rejects_invalid_timestamps_and_host_measurements() {
        let fixture = build_fixture();
        let policy = validated_fixture_policy(&fixture);
        assert_eq!(
            build_fixture_prepare_payload(&fixture, &policy, 0, 1, fixture_host_environment())
                .err()
                .expect("zero start time must fail"),
            ExitEvidenceErrorV1::InvalidField("started_at_unix_seconds")
        );
        assert_eq!(
            build_fixture_prepare_payload(&fixture, &policy, 2, 1, fixture_host_environment())
                .err()
                .expect("reversed times must fail"),
            ExitEvidenceErrorV1::InvalidField("completed_at_unix_seconds")
        );

        for (field, mutation) in [
            ("operating_system", 0_u8),
            ("architecture", 1),
            ("kernel_release", 2),
            ("artifact_filesystem_policy", 3),
            ("checkout_state", 4),
            ("cargo_target_state", 5),
        ] {
            let mut host = fixture_host_environment();
            match mutation {
                0 => host.operating_system = "linux\nforged".to_owned(),
                1 => host.architecture = "x86_64\nforged".to_owned(),
                2 => host.kernel_release = "6.12\nforged".to_owned(),
                3 => host.artifact_filesystem_policy = "ambient_target".to_owned(),
                4 => host.checkout_state = "dirty_checkout".to_owned(),
                5 => host.cargo_target_state = "ambient_target".to_owned(),
                _ => unreachable!("fixed host mutation"),
            }
            assert_eq!(
                build_fixture_prepare_payload(&fixture, &policy, 1, 2, host)
                    .err()
                    .expect("invalid host claim must fail"),
                ExitEvidenceErrorV1::InvalidField(field)
            );
        }
    }

    #[test]
    fn finalize_accepts_one_exact_canonical_request_and_emits_the_signed_record() {
        let fixture = build_fixture();
        let request = canonical_json(&build_finalize_request(&fixture));
        let finalized = finalize_fixture_request(&fixture, &request, CHALLENGE)
            .expect("valid finalize request");

        assert_eq!(finalized, canonical_json(&fixture.reproduction));
        let record: SignedReproductionRecordV1 =
            parse_canonical(&finalized).expect("canonical signed record");
        assert_eq!(record.signature_algorithm, "ed25519");
        assert_eq!(record.signature_hex, fixture.reproduction.signature_hex);
        let source = String::from_utf8(finalized).expect("signed record is UTF-8");
        assert!(!source.contains("prepare_envelope"));
        assert!(!source.contains("signing_digest_hex"));
        assert!(!source.contains("private_key"));
        assert!(source.ends_with("\n"));
        assert!(!source.contains('\r'));
    }

    #[test]
    fn finalize_rejects_noncanonical_bounded_input_and_bad_signatures() {
        let fixture = build_fixture();
        let policy = validated_fixture_policy(&fixture);
        assert_eq!(
            parse_and_authenticate_finalize_request(&[], &policy)
                .err()
                .expect("empty input must fail"),
            ExitEvidenceErrorV1::EmptyInput
        );
        assert_eq!(
            parse_and_authenticate_finalize_request(
                &vec![b' '; MAX_FINALIZE_REQUEST_BYTES + 1],
                &policy,
            )
            .err()
            .expect("oversized input must fail"),
            ExitEvidenceErrorV1::InputTooLarge
        );

        let request = canonical_json(&build_finalize_request(&fixture));
        let source = String::from_utf8(request.clone()).expect("request is UTF-8");
        let crlf = source.replace('\n', "\r\n");
        assert!(matches!(
            parse_and_authenticate_finalize_request(crlf.as_bytes(), &policy),
            Err(ExitEvidenceErrorV1::NonCanonicalJson)
        ));
        let mut trailing = request;
        trailing.extend_from_slice(b" \n");
        assert!(parse_and_authenticate_finalize_request(&trailing, &policy).is_err());

        let mut uppercase = build_finalize_request(&fixture);
        uppercase.signature_hex.make_ascii_uppercase();
        assert_eq!(
            parse_and_authenticate_finalize_request(&canonical_json(&uppercase), &policy)
                .err()
                .expect("uppercase signature must fail"),
            ExitEvidenceErrorV1::InvalidHex("signature_hex")
        );
        let mut invalid = build_finalize_request(&fixture);
        invalid.signature_hex = "00".repeat(64);
        assert_eq!(
            parse_and_authenticate_finalize_request(&canonical_json(&invalid), &policy)
                .err()
                .expect("invalid signature must fail"),
            ExitEvidenceErrorV1::InvalidSignature
        );
        let mut wrong_digest = build_finalize_request(&fixture);
        wrong_digest.prepare_envelope.signing_digest_hex = "00".repeat(32);
        assert_eq!(
            parse_and_authenticate_finalize_request(&canonical_json(&wrong_digest), &policy)
                .err()
                .expect("wrong displayed digest must fail"),
            ExitEvidenceErrorV1::InvalidField("signing_digest_hex")
        );
    }

    #[test]
    fn finalize_rejects_authenticated_subject_challenge_and_policy_mutations() {
        let fixture = build_fixture();
        let policy = validated_fixture_policy(&fixture);
        let mut wrong_subject = canonical_json(&build_finalize_request(&fixture));
        let subject_digest = encode_hex(&SUBJECT);
        let replacement = encode_hex(&[0x45; 32]);
        let position = wrong_subject
            .windows(subject_digest.len())
            .position(|window| window == subject_digest.as_bytes())
            .expect("embedded subject digest");
        wrong_subject[position..position + subject_digest.len()]
            .copy_from_slice(replacement.as_bytes());
        let request = parse_and_authenticate_finalize_request(&wrong_subject, &policy)
            .expect("subject-only mutation keeps payload signature valid");
        assert_eq!(
            finalize_authenticated_request(
                request,
                &fixture.subject,
                &policy,
                &ProjectChallengeV1::synthetic(CHALLENGE),
            ),
            Err(ExitEvidenceErrorV1::SubjectMismatch)
        );

        let mut wrong_challenge = build_finalize_request(&fixture);
        wrong_challenge
            .prepare_envelope
            .unsigned_reproduction_payload
            .operator_assertion
            .challenge_hex = encode_hex(&[0x99; 32]);
        resign_finalize_request(&mut wrong_challenge, &fixture.reproducer);
        assert_eq!(
            finalize_fixture_request(&fixture, &canonical_json(&wrong_challenge), CHALLENGE),
            Err(ExitEvidenceErrorV1::ChallengeMismatch)
        );

        let mut wrong_policy = build_finalize_request(&fixture);
        wrong_policy
            .prepare_envelope
            .unsigned_reproduction_payload
            .authority_policy_sha256_hex = "00".repeat(32);
        resign_finalize_request(&mut wrong_policy, &fixture.reproducer);
        assert_eq!(
            finalize_fixture_request(&fixture, &canonical_json(&wrong_policy), CHALLENGE),
            Err(ExitEvidenceErrorV1::ProtectedPolicyDigestMismatch)
        );
    }

    #[test]
    fn evidence_commit_parser_requires_one_exact_parent() {
        let tree = "11".repeat(20);
        let parent = "22".repeat(20);
        let commit = format!(
            "tree {tree}\nparent {parent}\nauthor Reviewer <review@example.invalid> 1 +0000\ncommitter Reviewer <review@example.invalid> 1 +0000\n\nreview evidence\n"
        );
        assert_eq!(
            parse_single_parent_commit(commit.as_bytes()).expect("single parent"),
            [0x22; 20]
        );

        let root = commit.replace(&format!("parent {parent}\n"), "");
        assert_eq!(
            parse_single_parent_commit(root.as_bytes()),
            Err(ExitEvidenceErrorV1::InvalidEvidenceCommit)
        );
        let merge = commit.replace(
            &format!("parent {parent}\n"),
            &format!("parent {parent}\nparent {}\n", "33".repeat(20)),
        );
        assert_eq!(
            parse_single_parent_commit(merge.as_bytes()),
            Err(ExitEvidenceErrorV1::InvalidEvidenceCommit)
        );
        assert_eq!(
            parse_single_parent_commit(commit.replace('\n', "\r\n").as_bytes()),
            Err(ExitEvidenceErrorV1::InvalidEvidenceCommit)
        );
    }

    #[test]
    fn evidence_diff_parser_requires_four_added_regular_blobs_at_fixed_paths() {
        let canonical = canonical_evidence_diff();
        let entries = parse_fixed_evidence_diff(&canonical).expect("fixed four-blob diff");
        assert_eq!(entries.len(), 4);
        for ((entry, (path, _)), index) in entries.iter().zip(EVIDENCE_BLOBS).zip(0_u8..) {
            assert_eq!(entry.path, path);
            assert_eq!(entry.oid, [0x10 + index; 20]);
        }

        let mut executable = canonical.clone();
        let mode = executable
            .windows(6)
            .position(|window| window == b"100644")
            .expect("regular mode");
        executable[mode..mode + 6].copy_from_slice(b"100755");
        assert_eq!(
            parse_fixed_evidence_diff(&executable).err(),
            Some(ExitEvidenceErrorV1::InvalidEvidenceCommit)
        );

        let mut modified = canonical.clone();
        let status = modified
            .windows(2)
            .position(|window| window == b"A\0")
            .expect("addition status");
        modified[status] = b'M';
        assert_eq!(
            parse_fixed_evidence_diff(&modified).err(),
            Some(ExitEvidenceErrorV1::InvalidEvidenceCommit)
        );

        let mut extra = canonical.clone();
        extra.extend_from_slice(&canonical[..canonical.len() / 4]);
        assert_eq!(
            parse_fixed_evidence_diff(&extra).err(),
            Some(ExitEvidenceErrorV1::InvalidEvidenceCommit)
        );
        assert_eq!(
            parse_fixed_evidence_diff(&canonical[..canonical.len() - 1]).err(),
            Some(ExitEvidenceErrorV1::InvalidEvidenceCommit)
        );
    }

    #[test]
    fn canonical_policy_has_distinct_valid_authorities() {
        let fixture = build_fixture();
        let bytes = canonical_json(&fixture.policy);
        assert!(validate_policy(&bytes, Sha256::digest(&bytes).into()).is_ok());
    }

    #[test]
    fn valid_records_issue_one_private_verified_capability() {
        let fixture = build_fixture();
        let verified = verify(&fixture).expect("valid external evidence");
        assert_eq!(verified.subject_digest(), &SUBJECT);
        assert_eq!(verified.approval_sequence(), 9);
    }

    #[test]
    fn reviewer_approval_consumes_the_verified_reproduction_capability() {
        let fixture = build_fixture();
        let policy = validated_fixture_policy(&fixture);
        let expected_policy_digest = policy.canonical_sha256;
        let reproduction_record_bytes = canonical_json(&fixture.reproduction);
        let approval_record_bytes = canonical_json(&fixture.approval);
        let expected_reproduction_digest: [u8; 32] =
            Sha256::digest(&reproduction_record_bytes).into();
        let expected_approval_digest: [u8; 32] = Sha256::digest(&approval_record_bytes).into();
        let verified_reproduction = VerifiedPhase2bIndependentHostReproductionV1 {
            evidence_commit: [0x88; 20],
            candidate_commit: [0x66; 20],
            subject: fixture.subject,
            policy,
            reproduction_record_bytes,
            review_report_bytes: REVIEW_REPORT.to_vec(),
            approval_record_bytes,
        };

        let verified = verify_review_approval_from_reproduction(verified_reproduction)
            .expect("valid reviewer approval");
        assert_eq!(verified.evidence_commit(), &[0x88; 20]);
        assert_eq!(verified.candidate_commit(), &[0x66; 20]);
        assert_eq!(verified.subject_digest(), &SUBJECT);
        assert_eq!(verified.authority_policy_digest(), &expected_policy_digest);
        assert_eq!(
            verified.reproduction_record_digest(),
            &expected_reproduction_digest
        );
        assert_eq!(verified.approval_record_digest(), &expected_approval_digest);
        assert_eq!(verified.approval_sequence(), 9);
    }

    #[test]
    fn protected_policy_digest_is_mandatory_and_exact() {
        let mut fixture = build_fixture();
        let policy = canonical_json(&fixture.policy);
        assert!(validate_policy(&policy, [0; 32]).is_err());
        fixture.policy.policy_version += 1;
        assert!(verify(&fixture).is_err());
    }

    #[test]
    fn weak_or_shared_authorities_fail_closed() {
        let mut fixture = build_fixture();
        fixture.policy.cryptographic_reviewer = fixture.policy.independent_reproducer.clone();
        fixture.policy.cryptographic_reviewer.role = REVIEWER_ROLE.to_owned();
        let bytes = canonical_json(&fixture.policy);
        assert!(validate_policy(&bytes, Sha256::digest(&bytes).into()).is_err());

        fixture = build_fixture();
        fixture.policy.independent_reproducer.verifying_key_hex = encode_hex(&[0; 32]);
        let bytes = canonical_json(&fixture.policy);
        assert!(validate_policy(&bytes, Sha256::digest(&bytes).into()).is_err());
    }

    #[test]
    fn canonical_parser_rejects_unknown_reordered_crlf_and_trailing_bytes() {
        let fixture = build_fixture();
        let bytes = canonical_json(&fixture.reproduction);
        let source = String::from_utf8(bytes.clone()).expect("JSON is UTF-8");
        let unknown = source.replacen("{\n", "{\n  \"unknown\": true,\n", 1);
        assert!(parse_canonical::<SignedReproductionRecordV1>(unknown.as_bytes()).is_err());
        let reordered = source.replacen(
            "  \"payload\"",
            "  \"signature_algorithm_copy\": \"ed25519\",\n  \"payload\"",
            1,
        );
        assert!(parse_canonical::<SignedReproductionRecordV1>(reordered.as_bytes()).is_err());
        let crlf = source.replace('\n', "\r\n");
        assert!(parse_canonical::<SignedReproductionRecordV1>(crlf.as_bytes()).is_err());
        let mut trailing = bytes;
        trailing.extend_from_slice(b" \n");
        assert!(parse_canonical::<SignedReproductionRecordV1>(&trailing).is_err());

        let approval_bytes = canonical_json(&fixture.approval);
        let approval_source = String::from_utf8(approval_bytes).expect("approval JSON is UTF-8");
        let approval_unknown = approval_source.replacen("{\n", "{\n  \"unknown\": true,\n", 1);
        assert!(parse_canonical::<SignedReviewApprovalV1>(approval_unknown.as_bytes()).is_err());
        let approval_duplicate = approval_source.replacen(
            "  \"signature_algorithm\":",
            "  \"signature_algorithm\": \"ed25519\",\n  \"signature_algorithm\":",
            1,
        );
        assert!(parse_canonical::<SignedReviewApprovalV1>(approval_duplicate.as_bytes()).is_err());
        let approval_reordered = approval_source.replacen(
            "    \"schema\": \"seams:router-ab:ed25519-yao:phase2b-review-approval:v1\",\n    \"protocol_id\": \"router_ab_ed25519_yao_v1\",",
            "    \"protocol_id\": \"router_ab_ed25519_yao_v1\",\n    \"schema\": \"seams:router-ab:ed25519-yao:phase2b-review-approval:v1\",",
            1,
        );
        assert_ne!(approval_reordered, approval_source);
        assert!(parse_canonical::<SignedReviewApprovalV1>(approval_reordered.as_bytes()).is_err());
    }

    #[test]
    fn reproduction_rejects_wrong_challenge_key_signature_and_payload() {
        let mut fixture = build_fixture();
        let policy_bytes = canonical_json(&fixture.policy);
        let policy = validate_policy(&policy_bytes, Sha256::digest(&policy_bytes).into())
            .expect("valid test policy");
        let wrong_challenge = ProjectChallengeV1::synthetic([0x99; 32]);
        let review_report = TrustedReviewReportV1 {
            sha256: Sha256::digest(REVIEW_REPORT).into(),
        };
        assert!(verify_phase2b_exit_evidence_v1(
            &fixture.subject,
            &policy,
            &wrong_challenge,
            &review_report,
            &canonical_json(&fixture.reproduction),
            &canonical_json(&fixture.approval),
        )
        .is_err());
        fixture.reproduction.signature_hex = encode_hex(&[0; 64]);
        rebuild_approval(&mut fixture);
        assert!(verify(&fixture).is_err());
        fixture = build_fixture();
        fixture.reproduction.payload.source_commit_hex = encode_hex(&[0x88; 20]);
        fixture.reproduction =
            sign_reproduction(fixture.reproduction.payload.clone(), &fixture.reproducer);
        rebuild_approval(&mut fixture);
        assert!(verify(&fixture).is_err());
    }

    #[test]
    fn reproduction_rejects_count_artifact_and_nonclaim_mutations() {
        let mut fixture = build_fixture();
        fixture.reproduction.payload.execution.artifact_python_tests = 23;
        fixture.reproduction =
            sign_reproduction(fixture.reproduction.payload.clone(), &fixture.reproducer);
        rebuild_approval(&mut fixture);
        assert!(verify(&fixture).is_err());
        fixture = build_fixture();
        fixture
            .reproduction
            .payload
            .observations
            .artifact_entries
            .swap(0, 1);
        fixture.reproduction =
            sign_reproduction(fixture.reproduction.payload.clone(), &fixture.reproducer);
        rebuild_approval(&mut fixture);
        assert!(verify(&fixture).is_err());
        fixture = build_fixture();
        fixture.reproduction.payload.observations.artifact_entries[0].sha256_hex =
            encode_hex(&[0x42; 32]);
        fixture.reproduction =
            sign_reproduction(fixture.reproduction.payload.clone(), &fixture.reproducer);
        rebuild_approval(&mut fixture);
        assert!(verify(&fixture).is_err());
        fixture = build_fixture();
        fixture.reproduction.payload.explicit_nonclaims.pop();
        fixture.reproduction =
            sign_reproduction(fixture.reproduction.payload.clone(), &fixture.reproducer);
        rebuild_approval(&mut fixture);
        assert!(verify(&fixture).is_err());
    }

    #[test]
    fn approval_rejects_wrong_signature_reproduction_and_report_binding() {
        let mut fixture = build_fixture();
        fixture.approval.signature_hex = encode_hex(&[0; 64]);
        assert!(verify(&fixture).is_err());
        fixture = build_fixture();
        fixture
            .approval
            .payload
            .independent_reproduction_record_sha256_hex = encode_hex(&[0; 32]);
        fixture.approval = sign_approval(fixture.approval.payload.clone(), &fixture.reviewer);
        assert!(verify(&fixture).is_err());
        fixture = build_fixture();
        fixture.approval.payload.review_report_sha256_hex = encode_hex(&[0; 32]);
        fixture.approval = sign_approval(fixture.approval.payload.clone(), &fixture.reviewer);
        assert!(verify(&fixture).is_err());
        fixture = build_fixture();
        fixture.approval.payload.authority_policy_sha256_hex = encode_hex(&[0; 32]);
        fixture.approval = sign_approval(fixture.approval.payload.clone(), &fixture.reviewer);
        assert!(verify(&fixture).is_err());
        fixture = build_fixture();
        fixture.approval.payload.subject_digest_hex = encode_hex(&[0; 32]);
        fixture.approval = sign_approval(fixture.approval.payload.clone(), &fixture.reviewer);
        assert!(verify(&fixture).is_err());
        fixture = build_fixture();
        fixture.approval.payload.review_report_path = "review.md".to_owned();
        fixture.approval = sign_approval(fixture.approval.payload.clone(), &fixture.reviewer);
        assert!(verify(&fixture).is_err());
        fixture = build_fixture();
        fixture.approval.signature_algorithm = "Ed25519".to_owned();
        assert!(verify(&fixture).is_err());
        fixture = build_fixture();
        fixture.approval = sign_approval(fixture.approval.payload.clone(), &fixture.reproducer);
        assert!(verify(&fixture).is_err());
        fixture = build_fixture();
        fixture.approval.signature_hex.truncate(126);
        assert!(verify(&fixture).is_err());
        fixture = build_fixture();
        let mut malleated = decode_hex::<64>(&fixture.approval.signature_hex, "signature_hex")
            .expect("valid fixture signature");
        malleated[0] ^= 1;
        fixture.approval.signature_hex = encode_hex(&malleated);
        assert!(verify(&fixture).is_err());
    }

    #[test]
    fn approval_requires_complete_surfaces_scope_and_nonclaims() {
        let mut fixture = build_fixture();
        fixture.approval.payload.reviewed_surfaces.pop();
        fixture.approval = sign_approval(fixture.approval.payload.clone(), &fixture.reviewer);
        assert!(verify(&fixture).is_err());
        fixture = build_fixture();
        fixture.approval.payload.approval_scope = "production".to_owned();
        fixture.approval = sign_approval(fixture.approval.payload.clone(), &fixture.reviewer);
        assert!(verify(&fixture).is_err());
        fixture = build_fixture();
        fixture.approval.payload.explicit_nonclaims.swap(0, 1);
        fixture.approval = sign_approval(fixture.approval.payload.clone(), &fixture.reviewer);
        assert!(verify(&fixture).is_err());
        fixture = build_fixture();
        fixture.approval.payload.reviewed_surfaces.swap(0, 1);
        fixture.approval = sign_approval(fixture.approval.payload.clone(), &fixture.reviewer);
        assert!(verify(&fixture).is_err());
        fixture = build_fixture();
        fixture.approval.payload.schema = "approval-v2".to_owned();
        fixture.approval = sign_approval(fixture.approval.payload.clone(), &fixture.reviewer);
        assert!(verify(&fixture).is_err());
        fixture = build_fixture();
        fixture.approval.payload.protocol_id = "another-protocol".to_owned();
        fixture.approval = sign_approval(fixture.approval.payload.clone(), &fixture.reviewer);
        assert!(verify(&fixture).is_err());
        fixture = build_fixture();
        fixture.approval.payload.decision = "reject".to_owned();
        fixture.approval = sign_approval(fixture.approval.payload.clone(), &fixture.reviewer);
        assert!(verify(&fixture).is_err());
    }

    #[test]
    fn zero_and_stale_epochs_timestamps_and_sequences_fail_closed() {
        let mut fixture = build_fixture();
        fixture.approval.payload.approval_sequence = 8;
        fixture.approval = sign_approval(fixture.approval.payload.clone(), &fixture.reviewer);
        assert_eq!(
            verify(&fixture).unwrap_err(),
            ExitEvidenceErrorV1::StaleApproval
        );
        fixture = build_fixture();
        fixture.approval.payload.reviewed_at_unix_seconds = 0;
        fixture.approval = sign_approval(fixture.approval.payload.clone(), &fixture.reviewer);
        assert!(verify(&fixture).is_err());
        fixture = build_fixture();
        fixture.approval.payload.reviewer_authority_id = "another-reviewer".to_owned();
        fixture.approval = sign_approval(fixture.approval.payload.clone(), &fixture.reviewer);
        assert!(verify(&fixture).is_err());
        fixture = build_fixture();
        fixture.approval.payload.reviewer_key_epoch += 1;
        fixture.approval = sign_approval(fixture.approval.payload.clone(), &fixture.reviewer);
        assert!(verify(&fixture).is_err());
        fixture = build_fixture();
        fixture.approval.payload.reviewer_authority_key_digest_hex = encode_hex(&[0; 32]);
        fixture.approval = sign_approval(fixture.approval.payload.clone(), &fixture.reviewer);
        assert!(verify(&fixture).is_err());
        fixture = build_fixture();
        fixture
            .reproduction
            .payload
            .operator_assertion
            .started_at_unix_seconds = 0;
        fixture.reproduction =
            sign_reproduction(fixture.reproduction.payload.clone(), &fixture.reproducer);
        rebuild_approval(&mut fixture);
        assert!(verify(&fixture).is_err());
        fixture = build_fixture();
        fixture.policy.cryptographic_reviewer.key_epoch = 0;
        let bytes = canonical_json(&fixture.policy);
        assert!(validate_policy(&bytes, Sha256::digest(&bytes).into()).is_err());
    }

    #[test]
    fn uppercase_short_long_and_nonhex_fields_are_rejected() {
        assert!(decode_hex::<32>(&"AA".repeat(32), "hex").is_err());
        assert!(decode_hex::<32>(&"a".repeat(62), "hex").is_err());
        assert!(decode_hex::<32>(&"a".repeat(66), "hex").is_err());
        assert!(decode_hex::<32>(&"gg".repeat(32), "hex").is_err());
    }

    #[test]
    fn signing_surface_is_test_only_and_capability_is_not_serializable() {
        let source = include_str!("phase2b_exit_evidence.rs");
        let production = source
            .split_once("#[cfg(test)]\nmod tests {")
            .expect("test module boundary")
            .0;
        assert!(!production.contains("SigningKey"));
        assert!(!production.contains(".sign("));
        assert!(!production.contains("impl Serialize for VerifiedPhase2bReviewApprovalV1"));
        assert!(!production.contains("impl Clone for VerifiedPhase2bReviewApprovalV1"));
        let capability_attributes = production
            .split_once("pub(crate) struct VerifiedPhase2bReviewApprovalV1")
            .expect("approval capability declaration")
            .0
            .rsplit_once("\n\n")
            .expect("approval capability attributes")
            .1;
        assert!(!capability_attributes.contains("Clone"));
        assert!(!capability_attributes.contains("Serialize"));
        assert!(!capability_attributes.contains("Deserialize"));
    }
}
