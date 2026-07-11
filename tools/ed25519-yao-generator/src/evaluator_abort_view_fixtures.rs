//! Strict host-only corpus for admitted evaluator-abort state and party views.

use core::fmt;

use serde::Serialize;

use crate::canonical_ceremony_fixture_dag_v1;
use crate::ceremony_context::CeremonyRequestKindV1;
use crate::lifecycle_domain::{
    AbortedTerminalStateV1, RedactedFailureCodeV1, UniformLifecycleAbortV1,
};

/// Schema identifier for the evaluator-abort state/party-view corpus.
pub const EVALUATOR_ABORT_VIEW_VECTOR_CORPUS_SCHEMA_V1: &str =
    "seams:router-ab:ed25519-yao:evaluator-abort-state-party-views:v1";

/// Scope separating host-only structural evidence from runtime protocol claims.
pub const EVALUATOR_ABORT_VIEW_VECTOR_EVIDENCE_SCOPE_V1: &str =
    "host_only_synthetic_evaluator_abort_state_party_views_v1";

/// Strict four-case evaluator-abort state and party-view corpus.
#[derive(Serialize)]
pub struct EvaluatorAbortViewVectorCorpusV1 {
    schema: String,
    protocol_id: String,
    evidence_scope: String,
    cases: Vec<EvaluatorAbortViewVectorCaseV1>,
}

impl EvaluatorAbortViewVectorCorpusV1 {
    /// Returns the fixed schema.
    pub fn schema(&self) -> &str {
        &self.schema
    }

    /// Returns the fixed protocol identifier.
    pub fn protocol_id(&self) -> &str {
        &self.protocol_id
    }

    /// Returns the host-only evidence scope.
    pub fn evidence_scope(&self) -> &str {
        &self.evidence_scope
    }

    /// Returns the exact case count.
    pub fn case_count(&self) -> usize {
        self.cases.len()
    }
}

#[derive(Serialize)]
struct EvaluatorAbortViewVectorCaseV1 {
    request_kind: EvaluatorRequestKindVectorV1,
    source_ceremony_case_id: &'static str,
    persistence: EvaluatorAbortPersistenceVectorV1,
    party_views: EvaluatorAbortPartyViewsVectorV1,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum EvaluatorRequestKindVectorV1 {
    Registration,
    Recovery,
    Refresh,
    Export,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum EvaluatorAbortPreStateClassVectorV1 {
    Unregistered,
    CredentialSuspended,
    Registered,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum EvaluatorAbortTransitionVectorV1 {
    SelfLoop,
}

#[derive(Serialize)]
struct EvaluatorAbortPersistenceVectorV1 {
    pre_state_class: EvaluatorAbortPreStateClassVectorV1,
    transition: EvaluatorAbortTransitionVectorV1,
    burned_attempt: BurnedAttemptVectorV1,
    public_abort: EvaluatorAbortEnvelopeVectorV1,
}

#[derive(Serialize)]
struct BurnedAttemptVectorV1 {
    request_kind: EvaluatorRequestKindVectorV1,
    request_context_digest_hex: String,
    authorization_digest_hex: String,
    transcript_digest_hex: String,
    one_use_execution_id_hex: String,
}

#[derive(Clone, Serialize)]
struct EvaluatorAbortEnvelopeVectorV1 {
    request_kind: EvaluatorRequestKindVectorV1,
    public_transcript_digest_hex: String,
    public_failure_code: EvaluatorAbortFailureCodeVectorV1,
    terminal: EvaluatorAbortTerminalVectorV1,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "snake_case")]
enum EvaluatorAbortFailureCodeVectorV1 {
    Rejected,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "snake_case")]
enum EvaluatorAbortTerminalVectorV1 {
    Aborted,
}

#[derive(Serialize)]
struct EvaluatorAbortPartyViewsVectorV1 {
    deriver_a: EvaluatorAbortEnvelopeVectorV1,
    deriver_b: EvaluatorAbortEnvelopeVectorV1,
    client: EvaluatorAbortEnvelopeVectorV1,
    signing_worker: EvaluatorAbortEnvelopeVectorV1,
    router: EvaluatorAbortEnvelopeVectorV1,
    observer: EvaluatorAbortEnvelopeVectorV1,
    diagnostics: EvaluatorAbortEnvelopeVectorV1,
}

/// Failure returned for any noncanonical corpus bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EvaluatorAbortViewVectorCorpusParseErrorV1;

impl fmt::Display for EvaluatorAbortViewVectorCorpusParseErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(
            "evaluator-abort state/party-view corpus must equal the exact canonical LF-terminated JSON bytes",
        )
    }
}

impl std::error::Error for EvaluatorAbortViewVectorCorpusParseErrorV1 {}

/// Builds the canonical four-case synthetic evaluator-abort corpus.
pub fn canonical_evaluator_abort_view_vector_corpus_v1() -> EvaluatorAbortViewVectorCorpusV1 {
    EvaluatorAbortViewVectorCorpusV1 {
        schema: EVALUATOR_ABORT_VIEW_VECTOR_CORPUS_SCHEMA_V1.to_owned(),
        protocol_id: ed25519_yao::PROTOCOL_ID_STR.to_owned(),
        evidence_scope: EVALUATOR_ABORT_VIEW_VECTOR_EVIDENCE_SCOPE_V1.to_owned(),
        cases: vec![
            evaluator_abort_case(
                CeremonyRequestKindV1::Registration,
                EvaluatorRequestKindVectorV1::Registration,
                EvaluatorAbortPreStateClassVectorV1::Unregistered,
                "ceremony-registration-v1",
                0xa1,
            ),
            evaluator_abort_case(
                CeremonyRequestKindV1::Recovery,
                EvaluatorRequestKindVectorV1::Recovery,
                EvaluatorAbortPreStateClassVectorV1::CredentialSuspended,
                "ceremony-recovery-v1",
                0xa2,
            ),
            evaluator_abort_case(
                CeremonyRequestKindV1::Refresh,
                EvaluatorRequestKindVectorV1::Refresh,
                EvaluatorAbortPreStateClassVectorV1::Registered,
                "ceremony-refresh-v1",
                0xa3,
            ),
            evaluator_abort_case(
                CeremonyRequestKindV1::Export,
                EvaluatorRequestKindVectorV1::Export,
                EvaluatorAbortPreStateClassVectorV1::Registered,
                "ceremony-export-v1",
                0xa4,
            ),
        ],
    }
}

/// Encodes the exact canonical corpus with one trailing LF.
pub fn canonical_evaluator_abort_view_vector_corpus_json_bytes_v1() -> Vec<u8> {
    let mut encoded = serde_json::to_vec_pretty(&canonical_evaluator_abort_view_vector_corpus_v1())
        .expect("fixed evaluator-abort corpus serializes");
    encoded.push(b'\n');
    encoded
}

/// Parses only the exact canonical LF-terminated corpus bytes.
pub fn parse_canonical_evaluator_abort_view_vector_corpus_json_v1(
    encoded: &[u8],
) -> Result<EvaluatorAbortViewVectorCorpusV1, EvaluatorAbortViewVectorCorpusParseErrorV1> {
    if encoded != canonical_evaluator_abort_view_vector_corpus_json_bytes_v1() {
        return Err(EvaluatorAbortViewVectorCorpusParseErrorV1);
    }
    Ok(canonical_evaluator_abort_view_vector_corpus_v1())
}

fn evaluator_abort_case(
    request_kind: CeremonyRequestKindV1,
    vector_kind: EvaluatorRequestKindVectorV1,
    pre_state_class: EvaluatorAbortPreStateClassVectorV1,
    source_ceremony_case_id: &'static str,
    execution_byte: u8,
) -> EvaluatorAbortViewVectorCaseV1 {
    let dag = canonical_ceremony_fixture_dag_v1(request_kind);
    let abort = abort_envelope(UniformLifecycleAbortV1::rejected(&dag), vector_kind);
    let party_views = EvaluatorAbortPartyViewsVectorV1 {
        deriver_a: abort.clone(),
        deriver_b: abort.clone(),
        client: abort.clone(),
        signing_worker: abort.clone(),
        router: abort.clone(),
        observer: abort.clone(),
        diagnostics: abort.clone(),
    };
    EvaluatorAbortViewVectorCaseV1 {
        request_kind: vector_kind,
        source_ceremony_case_id,
        persistence: EvaluatorAbortPersistenceVectorV1 {
            pre_state_class,
            transition: EvaluatorAbortTransitionVectorV1::SelfLoop,
            burned_attempt: BurnedAttemptVectorV1 {
                request_kind: vector_kind,
                request_context_digest_hex: encode_hex(dag.request_context_digest().as_bytes()),
                authorization_digest_hex: encode_hex(dag.authorization_digest().as_bytes()),
                transcript_digest_hex: encode_hex(dag.transcript_digest().as_bytes()),
                one_use_execution_id_hex: encode_hex(&[execution_byte; 32]),
            },
            public_abort: abort,
        },
        party_views,
    }
}

fn abort_envelope(
    abort: UniformLifecycleAbortV1,
    vector_kind: EvaluatorRequestKindVectorV1,
) -> EvaluatorAbortEnvelopeVectorV1 {
    let public_failure_code = match abort.public_failure_code() {
        RedactedFailureCodeV1::Rejected => EvaluatorAbortFailureCodeVectorV1::Rejected,
    };
    let terminal = match abort.terminal() {
        AbortedTerminalStateV1::Aborted => EvaluatorAbortTerminalVectorV1::Aborted,
    };
    EvaluatorAbortEnvelopeVectorV1 {
        request_kind: vector_kind,
        public_transcript_digest_hex: encode_hex(abort.public_transcript_digest().as_bytes()),
        public_failure_code,
        terminal,
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
