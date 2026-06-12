use serde::{Deserialize, Serialize};

use crate::derivation::context::CandidateId;

/// Candidate-selection measurement gate report version.
pub const CANDIDATE_MEASUREMENT_GATES_VERSION_V1: &str = "router_ab_candidate_measurement_gates_v1";

/// One benchmark measurement for a derivation candidate.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CandidateBenchmarkMeasurement {
    /// Candidate family measured.
    pub candidate_id: CandidateId,
    /// Operation label, such as `registration` or `refresh`.
    pub operation: String,
    /// Median latency in microseconds.
    pub median_micros: f64,
    /// p95 latency in microseconds.
    pub p95_micros: f64,
    /// Number of protocol round trips.
    pub round_trips: u32,
}

/// Benchmark report for the candidate decision gate.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CandidateBenchmarkReport {
    /// Report format version.
    pub report_version: String,
    /// Measurements in this report.
    pub measurements: Vec<CandidateBenchmarkMeasurement>,
}

/// Adapter round-trip profile for one candidate and ceremony kind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidateRoundTripProfileV1 {
    /// Candidate family.
    pub candidate_id: CandidateId,
    /// Operation label, such as `registration`, `export`, or `refresh`.
    pub operation: String,
    /// Client-visible Router requests.
    pub router_facing_client_requests: u32,
    /// Router worker invocations.
    pub router_invocations: u32,
    /// Signer A worker invocations.
    pub signer_a_invocations: u32,
    /// Signer B worker invocations.
    pub signer_b_invocations: u32,
    /// Direct A/B coordination round trips.
    pub direct_ab_coordination_round_trips: u32,
    /// Output packages emitted by A/B for client and relayer recipients.
    pub signer_output_packages: u32,
}

/// Candidate-selection measurement gate status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateMeasurementGateStatus {
    /// Gate has enough evidence for the current adapter phase.
    Complete,
    /// Gate is blocked on missing production implementation or deployment data.
    Blocked,
}

/// One measurement gate required before production candidate selection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidateMeasurementGateV1 {
    /// Stable gate identifier.
    pub gate_id: String,
    /// Gate status.
    pub status: CandidateMeasurementGateStatus,
    /// Evidence summary.
    pub evidence_summary: String,
    /// Remaining blocking requirement, or an empty string when complete.
    pub blocking_requirement: String,
}

/// Full Phase 6 measurement-gate snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidateMeasurementGateReportV1 {
    /// Report version.
    pub report_version: String,
    /// Adapter round-trip profiles.
    pub round_trip_profiles: Vec<CandidateRoundTripProfileV1>,
    /// Measurement gates.
    pub gates: Vec<CandidateMeasurementGateV1>,
}

/// Returns the current adapter round-trip profiles for both candidates.
pub fn candidate_round_trip_profiles_v1() -> Vec<CandidateRoundTripProfileV1> {
    let mut profiles = Vec::new();
    for candidate_id in [
        CandidateId::MpcThresholdPrfV1,
        CandidateId::SplitRootDerivationV1,
    ] {
        for operation in ["registration", "export", "refresh"] {
            profiles.push(CandidateRoundTripProfileV1 {
                candidate_id,
                operation: operation.to_owned(),
                router_facing_client_requests: 1,
                router_invocations: 1,
                signer_a_invocations: 1,
                signer_b_invocations: 1,
                direct_ab_coordination_round_trips: 0,
                signer_output_packages: 4,
            });
        }
    }
    profiles
}

/// Returns the current Phase 6 measurement-gate report.
pub fn candidate_measurement_gate_report_v1() -> CandidateMeasurementGateReportV1 {
    CandidateMeasurementGateReportV1 {
        report_version: CANDIDATE_MEASUREMENT_GATES_VERSION_V1.to_owned(),
        round_trip_profiles: candidate_round_trip_profiles_v1(),
        gates: vec![
            CandidateMeasurementGateV1 {
                gate_id: "native_adapter_latency_baseline".to_owned(),
                status: CandidateMeasurementGateStatus::Complete,
                evidence_summary: "Criterion adapter benchmarks captured on aarch64-apple-darwin"
                    .to_owned(),
                blocking_requirement: String::new(),
            },
            CandidateMeasurementGateV1 {
                gate_id: "adapter_round_trip_shape".to_owned(),
                status: CandidateMeasurementGateStatus::Complete,
                evidence_summary: "Both candidates use one Router-facing client request, one Router invocation, one Signer A invocation, one Signer B invocation, and zero direct A/B coordination round trips per ceremony".to_owned(),
                blocking_requirement: String::new(),
            },
            CandidateMeasurementGateV1 {
                gate_id: "wasm32_library_build".to_owned(),
                status: CandidateMeasurementGateStatus::Complete,
                evidence_summary:
                    "wasm32-unknown-unknown and wasm32-wasip1 release library builds pass"
                        .to_owned(),
                blocking_requirement: String::new(),
            },
            CandidateMeasurementGateV1 {
                gate_id: "candidate_a_cryptographic_path_native_latency".to_owned(),
                status: CandidateMeasurementGateStatus::Complete,
                evidence_summary: "Candidate A threshold-prf path captured natively: DLEQ prove ~102 us, DLEQ verify ~123 us, verified combine ~263 us, two proofs plus combine ~467 us".to_owned(),
                blocking_requirement: String::new(),
            },
            CandidateMeasurementGateV1 {
                gate_id: "candidate_b_cryptographic_path_native_latency".to_owned(),
                status: CandidateMeasurementGateStatus::Complete,
                evidence_summary: "Candidate B split-root path captured natively: derive output share ~2.46 us, combine output shares ~6.58 us".to_owned(),
                blocking_requirement: String::new(),
            },
            CandidateMeasurementGateV1 {
                gate_id: "cryptographic_path_native_latency".to_owned(),
                status: CandidateMeasurementGateStatus::Complete,
                evidence_summary: "Both Candidate A and Candidate B native cryptographic paths are measured on aarch64-apple-darwin".to_owned(),
                blocking_requirement: String::new(),
            },
            CandidateMeasurementGateV1 {
                gate_id: "deployable_wasm_or_worker_bundle_size".to_owned(),
                status: CandidateMeasurementGateStatus::Blocked,
                evidence_summary:
                    "Protocol crate currently builds as rlib; no deployable Worker or cdylib artifact exists"
                        .to_owned(),
                blocking_requirement:
                    "Add Worker adapter or cdylib target and record optimized bundle size"
                        .to_owned(),
            },
            CandidateMeasurementGateV1 {
                gate_id: "cloudflare_worker_runtime_latency".to_owned(),
                status: CandidateMeasurementGateStatus::Blocked,
                evidence_summary: "No Worker adapter or deployed Worker benchmark target exists".to_owned(),
                blocking_requirement:
                    "Deploy Worker adapter benchmark and capture runtime p50/p95 latency"
                        .to_owned(),
            },
        ],
    }
}
