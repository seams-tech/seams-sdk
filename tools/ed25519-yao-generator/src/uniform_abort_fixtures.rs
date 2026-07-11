//! Strict synthetic corpus for the construction-independent uniform abort envelope.

use core::fmt;

use serde::Serialize;

use crate::canonical_ceremony_fixture_dag_v1;
use crate::ceremony_context::CeremonyRequestKindV1;
use crate::lifecycle_domain::{
    AbortedTerminalStateV1, RedactedFailureCodeV1, UniformLifecycleAbortV1,
};

/// Schema identifier for the strict uniform-abort corpus.
pub const UNIFORM_ABORT_VECTOR_CORPUS_SCHEMA_V1: &str =
    "seams:router-ab:ed25519-yao:uniform-abort-envelope-vectors:v1";

/// Scope separating host-reference envelope shape from protocol-security evidence.
pub const UNIFORM_ABORT_VECTOR_EVIDENCE_SCOPE_V1: &str =
    "host_only_synthetic_uniform_abort_envelope_v1";

/// Strict five-case uniform-abort envelope corpus.
#[derive(Serialize)]
pub struct UniformAbortVectorCorpusV1 {
    schema: String,
    protocol_id: String,
    evidence_scope: String,
    cases: Vec<UniformAbortVectorCaseV1>,
}

impl UniformAbortVectorCorpusV1 {
    /// Returns the fixed corpus schema.
    pub fn schema(&self) -> &str {
        &self.schema
    }

    /// Returns the fixed protocol identifier.
    pub fn protocol_id(&self) -> &str {
        &self.protocol_id
    }

    /// Returns the narrow host-only evidence scope.
    pub fn evidence_scope(&self) -> &str {
        &self.evidence_scope
    }

    /// Returns the exact case count.
    pub fn case_count(&self) -> usize {
        self.cases.len()
    }
}

#[derive(Serialize)]
struct UniformAbortVectorCaseV1 {
    request_kind: AbortRequestKindVectorV1,
    source_ceremony_case_id: &'static str,
    envelope: UniformAbortEnvelopeVectorV1,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum AbortRequestKindVectorV1 {
    Registration,
    Activation,
    Recovery,
    Refresh,
    Export,
}

#[derive(Serialize)]
struct UniformAbortEnvelopeVectorV1 {
    request_kind: AbortRequestKindVectorV1,
    public_transcript_digest_hex: String,
    public_failure_code: RedactedFailureCodeVectorV1,
    terminal: AbortedTerminalStateVectorV1,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum RedactedFailureCodeVectorV1 {
    Rejected,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum AbortedTerminalStateVectorV1 {
    Aborted,
}

/// Failure returned for any noncanonical corpus bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UniformAbortVectorCorpusParseErrorV1;

impl fmt::Display for UniformAbortVectorCorpusParseErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(
            "uniform-abort corpus must equal the exact canonical LF-terminated JSON bytes",
        )
    }
}

impl std::error::Error for UniformAbortVectorCorpusParseErrorV1 {}

/// Builds the canonical five-case synthetic uniform-abort corpus.
pub fn canonical_uniform_abort_vector_corpus_v1() -> UniformAbortVectorCorpusV1 {
    UniformAbortVectorCorpusV1 {
        schema: UNIFORM_ABORT_VECTOR_CORPUS_SCHEMA_V1.to_owned(),
        protocol_id: ed25519_yao::PROTOCOL_ID_STR.to_owned(),
        evidence_scope: UNIFORM_ABORT_VECTOR_EVIDENCE_SCOPE_V1.to_owned(),
        cases: vec![
            abort_case(
                CeremonyRequestKindV1::Registration,
                AbortRequestKindVectorV1::Registration,
                "ceremony-registration-v1",
            ),
            abort_case(
                CeremonyRequestKindV1::Activation,
                AbortRequestKindVectorV1::Activation,
                "ceremony-activation-v1",
            ),
            abort_case(
                CeremonyRequestKindV1::Recovery,
                AbortRequestKindVectorV1::Recovery,
                "ceremony-recovery-v1",
            ),
            abort_case(
                CeremonyRequestKindV1::Refresh,
                AbortRequestKindVectorV1::Refresh,
                "ceremony-refresh-v1",
            ),
            abort_case(
                CeremonyRequestKindV1::Export,
                AbortRequestKindVectorV1::Export,
                "ceremony-export-v1",
            ),
        ],
    }
}

/// Encodes the exact canonical corpus with one trailing LF.
pub fn canonical_uniform_abort_vector_corpus_json_bytes_v1() -> Vec<u8> {
    let mut encoded = serde_json::to_vec_pretty(&canonical_uniform_abort_vector_corpus_v1())
        .expect("fixed uniform-abort corpus serializes");
    encoded.push(b'\n');
    encoded
}

/// Parses only the exact canonical LF-terminated corpus bytes.
pub fn parse_canonical_uniform_abort_vector_corpus_json_v1(
    encoded: &[u8],
) -> Result<UniformAbortVectorCorpusV1, UniformAbortVectorCorpusParseErrorV1> {
    if encoded != canonical_uniform_abort_vector_corpus_json_bytes_v1() {
        return Err(UniformAbortVectorCorpusParseErrorV1);
    }
    Ok(canonical_uniform_abort_vector_corpus_v1())
}

fn abort_case(
    request_kind: CeremonyRequestKindV1,
    vector_kind: AbortRequestKindVectorV1,
    source_ceremony_case_id: &'static str,
) -> UniformAbortVectorCaseV1 {
    let dag = canonical_ceremony_fixture_dag_v1(request_kind);
    let abort = UniformLifecycleAbortV1::rejected(&dag);
    let public_failure_code = match abort.public_failure_code() {
        RedactedFailureCodeV1::Rejected => RedactedFailureCodeVectorV1::Rejected,
    };
    let terminal = match abort.terminal() {
        AbortedTerminalStateV1::Aborted => AbortedTerminalStateVectorV1::Aborted,
    };
    UniformAbortVectorCaseV1 {
        request_kind: vector_kind,
        source_ceremony_case_id,
        envelope: UniformAbortEnvelopeVectorV1 {
            request_kind: vector_kind,
            public_transcript_digest_hex: encode_hex(abort.public_transcript_digest().as_bytes()),
            public_failure_code,
            terminal,
        },
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}
