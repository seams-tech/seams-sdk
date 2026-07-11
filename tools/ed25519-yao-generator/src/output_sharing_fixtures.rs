//! Strict portable vectors for host-only randomized-output sharing arithmetic.

use core::fmt;

use serde::Serialize;

use crate::ceremony_context::CeremonyRequestKindV1;
use crate::{
    canonical_vector_corpus_v1, evaluate_activation, evaluate_full_clear_reference_export_v1,
    share_host_only_activation_outputs_v1, share_host_only_export_seed_v1, DeriverAContribution,
    DeriverBContribution, HostOnlyActivationOutputCoinsV1, HostOnlyClientScalarOutputCoinV1,
    HostOnlySeedOutputCoinV1, HostOnlySigningWorkerScalarOutputCoinV1, RawDeriverAContribution,
    RawDeriverBContribution, VectorCaseV1, VectorInputsV1, VectorReferenceCaseV1,
};

/// Schema identifier for the version-one host-only output-sharing corpus.
const OUTPUT_SHARING_VECTOR_CORPUS_SCHEMA_V1: &str =
    "seams:router-ab:ed25519-yao:output-sharing-vectors:v1";

/// Exact claim boundary for deterministic output-sharing vector evidence.
const OUTPUT_SHARING_VECTOR_EVIDENCE_SCOPE_V1: &str = "host_only_deterministic_output_sharing_v1";

/// Registration boundary case identifier.
const REGISTRATION_OUTPUT_SHARING_CASE_ID_V1: &str = "registration_activation_shares_zero_coins_v1";

/// Recovery small-coin case identifier.
const RECOVERY_OUTPUT_SHARING_CASE_ID_V1: &str = "recovery_activation_shares_small_coins_v1";

/// Refresh scalar-boundary case identifier.
const REFRESH_OUTPUT_SHARING_CASE_ID_V1: &str = "refresh_activation_shares_boundary_coins_v1";

/// Export zero-coin case identifier.
const EXPORT_ZERO_OUTPUT_SHARING_CASE_ID_V1: &str = "export_seed_shares_zero_coin_v1";

/// Export one-coin case identifier.
const EXPORT_ONE_OUTPUT_SHARING_CASE_ID_V1: &str = "export_seed_shares_one_coin_v1";

/// Export maximum-coin case identifier.
const EXPORT_MAX_OUTPUT_SHARING_CASE_ID_V1: &str = "export_seed_shares_max_coin_v1";

const ZERO_BYTES: [u8; 32] = [0; 32];
const ONE_BYTES: [u8; 32] = scalar_u64_bytes(1);
const TWO_BYTES: [u8; 32] = scalar_u64_bytes(2);
const SCALAR_L_MINUS_ONE_BYTES: [u8; 32] = [
    0xec, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];
const SCALAR_L_MINUS_TWO_BYTES: [u8; 32] = [
    0xeb, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

/// Strict portable corpus for deterministic host-only output-sharing evidence.
#[derive(Serialize)]
pub struct OutputSharingVectorCorpusV1 {
    schema: String,
    protocol_id: String,
    evidence_scope: String,
    cases: Vec<OutputSharingVectorCaseV1>,
}

impl OutputSharingVectorCorpusV1 {
    /// Returns the fixed corpus schema identifier.
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

    /// Returns the exact number of canonical cases.
    pub fn case_count(&self) -> usize {
        self.cases.len()
    }
}

/// Failure returned for any noncanonical output-sharing corpus bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutputSharingVectorCorpusParseErrorV1;

impl fmt::Display for OutputSharingVectorCorpusParseErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(
            "output-sharing corpus must equal the exact canonical LF-terminated JSON bytes",
        )
    }
}

impl std::error::Error for OutputSharingVectorCorpusParseErrorV1 {}

#[derive(Serialize)]
#[serde(tag = "output_family", content = "vector", rename_all = "snake_case")]
pub(crate) enum OutputSharingVectorCaseV1 {
    Activation(ActivationOutputSharingVectorV1),
    Export(ExportOutputSharingVectorV1),
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ActivationOutputSharingRequestKindV1 {
    Registration,
    Recovery,
    Refresh,
}

#[derive(Serialize)]
pub(crate) struct HostOnlyOutputSharingSourceReferenceV1 {
    case_id: String,
    inputs: VectorInputsV1,
}

#[derive(Serialize)]
pub(crate) struct ActivationOutputSharingVectorV1 {
    case_id: String,
    request_kind: ActivationOutputSharingRequestKindV1,
    host_only_source_reference: HostOnlyOutputSharingSourceReferenceV1,
    host_only_joined_outputs: HostOnlyJoinedActivationOutputsV1,
    host_only_reference_randomness: HostOnlyActivationReferenceRandomnessV1,
    role_output_shares: HostOnlyActivationRoleOutputSharesV1,
}

#[derive(Serialize)]
pub(crate) struct HostOnlyJoinedActivationOutputsV1 {
    x_client_base_hex: String,
    x_server_base_hex: String,
}

#[derive(Serialize)]
pub(crate) struct HostOnlyActivationReferenceRandomnessV1 {
    r_client_hex: String,
    r_signing_worker_hex: String,
}

#[derive(Serialize)]
pub(crate) struct HostOnlyActivationRoleOutputSharesV1 {
    deriver_a: HostOnlyActivationRoleSharesV1,
    deriver_b: HostOnlyActivationRoleSharesV1,
}

#[derive(Serialize)]
pub(crate) struct HostOnlyActivationRoleSharesV1 {
    client_scalar_share_hex: String,
    signing_worker_scalar_share_hex: String,
}

#[derive(Serialize)]
pub(crate) struct ExportOutputSharingVectorV1 {
    case_id: String,
    host_only_source_reference: HostOnlyOutputSharingSourceReferenceV1,
    host_only_joined_output: HostOnlyJoinedExportOutputV1,
    host_only_reference_randomness: HostOnlyExportReferenceRandomnessV1,
    role_output_shares: HostOnlyExportRoleOutputSharesV1,
}

#[derive(Serialize)]
pub(crate) struct HostOnlyJoinedExportOutputV1 {
    joined_seed_hex: String,
}

#[derive(Serialize)]
pub(crate) struct HostOnlyExportReferenceRandomnessV1 {
    u_hex: String,
}

#[derive(Serialize)]
pub(crate) struct HostOnlyExportRoleOutputSharesV1 {
    deriver_a: HostOnlySeedRoleShareV1,
    deriver_b: HostOnlySeedRoleShareV1,
}

#[derive(Serialize)]
pub(crate) struct HostOnlySeedRoleShareV1 {
    seed_share_hex: String,
}

/// Parses only the exact canonical LF-terminated output-sharing JSON bytes.
pub fn parse_canonical_output_sharing_vector_corpus_json_v1(
    encoded: &[u8],
) -> Result<OutputSharingVectorCorpusV1, OutputSharingVectorCorpusParseErrorV1> {
    let corpus = canonical_output_sharing_vector_corpus_v1();
    if encoded != canonical_output_sharing_vector_corpus_json_bytes_v1() {
        return Err(OutputSharingVectorCorpusParseErrorV1);
    }
    Ok(corpus)
}

/// Encodes the exact canonical output-sharing corpus with one trailing LF.
pub fn canonical_output_sharing_vector_corpus_json_bytes_v1() -> Vec<u8> {
    canonical_json_bytes(&canonical_output_sharing_vector_corpus_v1())
}

/// Builds the canonical six-case host-only output-sharing corpus.
pub fn canonical_output_sharing_vector_corpus_v1() -> OutputSharingVectorCorpusV1 {
    OutputSharingVectorCorpusV1 {
        schema: OUTPUT_SHARING_VECTOR_CORPUS_SCHEMA_V1.to_owned(),
        protocol_id: ed25519_yao::PROTOCOL_ID_STR.to_owned(),
        evidence_scope: OUTPUT_SHARING_VECTOR_EVIDENCE_SCOPE_V1.to_owned(),
        cases: vec![
            activation_case(
                REGISTRATION_OUTPUT_SHARING_CASE_ID_V1,
                ActivationOutputSharingRequestKindV1::Registration,
                CeremonyRequestKindV1::Registration,
                ZERO_BYTES,
                ZERO_BYTES,
            ),
            activation_case(
                RECOVERY_OUTPUT_SHARING_CASE_ID_V1,
                ActivationOutputSharingRequestKindV1::Recovery,
                CeremonyRequestKindV1::Recovery,
                ONE_BYTES,
                TWO_BYTES,
            ),
            activation_case(
                REFRESH_OUTPUT_SHARING_CASE_ID_V1,
                ActivationOutputSharingRequestKindV1::Refresh,
                CeremonyRequestKindV1::Refresh,
                SCALAR_L_MINUS_ONE_BYTES,
                SCALAR_L_MINUS_TWO_BYTES,
            ),
            export_case(EXPORT_ZERO_OUTPUT_SHARING_CASE_ID_V1, ZERO_BYTES),
            export_case(EXPORT_ONE_OUTPUT_SHARING_CASE_ID_V1, ONE_BYTES),
            export_case(EXPORT_MAX_OUTPUT_SHARING_CASE_ID_V1, [0xff; 32]),
        ],
    }
}

fn canonical_json_bytes(corpus: &OutputSharingVectorCorpusV1) -> Vec<u8> {
    let mut encoded =
        serde_json::to_vec_pretty(corpus).expect("fixed output-sharing corpus must serialize");
    encoded.push(b'\n');
    encoded
}

fn activation_case(
    case_id: &str,
    request_kind: ActivationOutputSharingRequestKindV1,
    source_kind: CeremonyRequestKindV1,
    client_coin_bytes: [u8; 32],
    signing_worker_coin_bytes: [u8; 32],
) -> OutputSharingVectorCaseV1 {
    let (source, deriver_a, deriver_b) = source_reference(source_kind);
    let output = evaluate_activation(&deriver_a, &deriver_b);
    let coins = HostOnlyActivationOutputCoinsV1::new(
        HostOnlyClientScalarOutputCoinV1::from_canonical_fixture_bytes(client_coin_bytes)
            .expect("fixed client output coin is canonical"),
        HostOnlySigningWorkerScalarOutputCoinV1::from_canonical_fixture_bytes(
            signing_worker_coin_bytes,
        )
        .expect("fixed SigningWorker output coin is canonical"),
    );
    let shares = share_host_only_activation_outputs_v1(&output, coins);

    OutputSharingVectorCaseV1::Activation(ActivationOutputSharingVectorV1 {
        case_id: case_id.to_owned(),
        request_kind,
        host_only_source_reference: source,
        host_only_joined_outputs: HostOnlyJoinedActivationOutputsV1 {
            x_client_base_hex: encode_hex(&output.material().x_client_base().expose_bytes()),
            x_server_base_hex: encode_hex(&output.material().x_server_base().expose_bytes()),
        },
        host_only_reference_randomness: HostOnlyActivationReferenceRandomnessV1 {
            r_client_hex: encode_hex(&client_coin_bytes),
            r_signing_worker_hex: encode_hex(&signing_worker_coin_bytes),
        },
        role_output_shares: HostOnlyActivationRoleOutputSharesV1 {
            deriver_a: HostOnlyActivationRoleSharesV1 {
                client_scalar_share_hex: encode_hex(
                    &shares.deriver_a().client().expose_fixture_bytes(),
                ),
                signing_worker_scalar_share_hex: encode_hex(
                    &shares.deriver_a().signing_worker().expose_fixture_bytes(),
                ),
            },
            deriver_b: HostOnlyActivationRoleSharesV1 {
                client_scalar_share_hex: encode_hex(
                    &shares.deriver_b().client().expose_fixture_bytes(),
                ),
                signing_worker_scalar_share_hex: encode_hex(
                    &shares.deriver_b().signing_worker().expose_fixture_bytes(),
                ),
            },
        },
    })
}

fn export_case(case_id: &str, coin_bytes: [u8; 32]) -> OutputSharingVectorCaseV1 {
    let (source, deriver_a, deriver_b) = source_reference(CeremonyRequestKindV1::Export);
    let output = evaluate_full_clear_reference_export_v1(&deriver_a, &deriver_b);
    let coin = HostOnlySeedOutputCoinV1::from_fixture_bytes(coin_bytes);
    let shares = share_host_only_export_seed_v1(&output, coin);

    OutputSharingVectorCaseV1::Export(ExportOutputSharingVectorV1 {
        case_id: case_id.to_owned(),
        host_only_source_reference: source,
        host_only_joined_output: HostOnlyJoinedExportOutputV1 {
            joined_seed_hex: encode_hex(&output.seed().expose_bytes()),
        },
        host_only_reference_randomness: HostOnlyExportReferenceRandomnessV1 {
            u_hex: encode_hex(&coin_bytes),
        },
        role_output_shares: HostOnlyExportRoleOutputSharesV1 {
            deriver_a: HostOnlySeedRoleShareV1 {
                seed_share_hex: encode_hex(&shares.deriver_a().expose_fixture_bytes()),
            },
            deriver_b: HostOnlySeedRoleShareV1 {
                seed_share_hex: encode_hex(&shares.deriver_b().expose_fixture_bytes()),
            },
        },
    })
}

fn source_reference(
    request_kind: CeremonyRequestKindV1,
) -> (
    HostOnlyOutputSharingSourceReferenceV1,
    DeriverAContribution,
    DeriverBContribution,
) {
    let reference = canonical_vector_corpus_v1()
        .cases
        .into_iter()
        .find_map(|case| source_case(case, request_kind))
        .expect("fixed clear-arithmetic source case exists");
    let (deriver_a, deriver_b) = contributions(&reference.inputs);
    (
        HostOnlyOutputSharingSourceReferenceV1 {
            case_id: reference.case_id,
            inputs: reference.inputs,
        },
        deriver_a,
        deriver_b,
    )
}

fn source_case(
    case: VectorCaseV1,
    request_kind: CeremonyRequestKindV1,
) -> Option<VectorReferenceCaseV1> {
    match (request_kind, case) {
        (CeremonyRequestKindV1::Registration, VectorCaseV1::Registration(reference))
        | (CeremonyRequestKindV1::Recovery, VectorCaseV1::Recovery(reference))
        | (CeremonyRequestKindV1::Refresh, VectorCaseV1::Refresh(reference)) => Some(reference),
        (CeremonyRequestKindV1::Export, VectorCaseV1::Export(export)) => Some(export.reference),
        _ => None,
    }
}

fn contributions(inputs: &VectorInputsV1) -> (DeriverAContribution, DeriverBContribution) {
    let deriver_a = DeriverAContribution::try_from(RawDeriverAContribution {
        y_client: decode_hex_32(&inputs.y_client_a_hex),
        y_server: decode_hex_32(&inputs.y_server_a_hex),
        tau_client: decode_hex_32(&inputs.tau_client_a_hex),
        tau_server: decode_hex_32(&inputs.tau_server_a_hex),
    })
    .expect("fixed A source inputs are canonical");
    let deriver_b = DeriverBContribution::try_from(RawDeriverBContribution {
        y_client: decode_hex_32(&inputs.y_client_b_hex),
        y_server: decode_hex_32(&inputs.y_server_b_hex),
        tau_client: decode_hex_32(&inputs.tau_client_b_hex),
        tau_server: decode_hex_32(&inputs.tau_server_b_hex),
    })
    .expect("fixed B source inputs are canonical");
    (deriver_a, deriver_b)
}

const fn scalar_u64_bytes(value: u64) -> [u8; 32] {
    let mut bytes = [0; 32];
    let encoded = value.to_le_bytes();
    let mut index = 0;
    while index < encoded.len() {
        bytes[index] = encoded[index];
        index += 1;
    }
    bytes
}

fn decode_hex_32(value: &str) -> [u8; 32] {
    assert_eq!(value.len(), 64, "fixed source input is 32-byte hex");
    let mut bytes = [0; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        let offset = index * 2;
        *byte = u8::from_str_radix(&value[offset..offset + 2], 16)
            .expect("fixed source input uses lowercase hex");
    }
    bytes
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
