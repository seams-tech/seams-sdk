use core::fmt;

use curve25519_dalek::scalar::Scalar;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};

use crate::{
    evaluate_activation, evaluate_export, wrapping_add_le_256, DeriverAContribution,
    DeriverBContribution, OracleMaterial, RawDeriverAContribution, RawDeriverBContribution,
    StableKeyDerivationContext,
};

/// Schema identifier for the first portable Ed25519 Yao vector corpus.
pub const VECTOR_CORPUS_SCHEMA_V1: &str = "seams:router-ab:ed25519-yao:vectors:v1";

/// Domain separating deterministic differential inputs from protocol KDFs.
pub const DIFFERENTIAL_INPUT_DOMAIN_V1: &[u8] =
    b"seams/router-ab/ed25519-yao/differential-input/v1";

/// Largest differential corpus accepted by the host-only generator.
pub const MAX_DIFFERENTIAL_VECTOR_CASES_V1: usize = 4_096;

/// Invalid deterministic differential-corpus request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DifferentialVectorError {
    /// A differential corpus must contain at least one case.
    EmptyCorpus,
    /// The requested corpus exceeds the bounded host-only test workload.
    TooManyCases {
        /// Caller-provided number of cases.
        requested: usize,
        /// Fixed version-one upper bound.
        maximum: usize,
    },
}

impl fmt::Display for DifferentialVectorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyCorpus => formatter.write_str("differential corpus must be nonempty"),
            Self::TooManyCases { requested, maximum } => write!(
                formatter,
                "differential corpus requested {requested} cases; maximum is {maximum}"
            ),
        }
    }
}

impl std::error::Error for DifferentialVectorError {}

const RFC8032_VECTOR_ONE_SEED: [u8; 32] = [
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
];

const RFC8032_VECTOR_TWO_SEED: [u8; 32] = [
    0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda, 0x9d, 0xb6, 0xc3, 0x46, 0xec, 0x11, 0x4e, 0x0f,
    0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0x24, 0xda, 0x8c, 0xf6, 0xed, 0x4f, 0xb8, 0xa6, 0xfb,
];

/// Canonical request kind associated with a clear-arithmetic vector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleRequestKindV1 {
    /// Registration request shape.
    Registration,
    /// SigningWorker activation request shape.
    Activation,
    /// Recovery request shape.
    Recovery,
    /// Role-local refresh request shape.
    Refresh,
    /// Explicitly authorized export request shape.
    Export,
}

/// Versioned, deterministic portable vector corpus.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VectorCorpusV1 {
    /// Fixed schema identifier.
    pub schema: String,
    /// Fixed protocol identifier.
    pub protocol_id: String,
    /// Clear-arithmetic cases tagged with each canonical request kind.
    pub cases: Vec<VectorCaseV1>,
}

/// Request-kind-tagged clear-arithmetic vector.
///
/// The variants prevent an export-only seed result from appearing in any
/// non-export request shape. Lifecycle state transitions remain outside this
/// Phase 1 arithmetic corpus.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "request_kind",
    content = "vector",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum VectorCaseV1 {
    /// Registration-labelled arithmetic case.
    Registration(VectorReferenceCaseV1),
    /// Activation-labelled arithmetic case.
    Activation(VectorReferenceCaseV1),
    /// Recovery-labelled arithmetic case.
    Recovery(VectorReferenceCaseV1),
    /// Refresh-labelled arithmetic case.
    Refresh(VectorReferenceCaseV1),
    /// Export-labelled arithmetic case with a required authorized result.
    Export(VectorExportCaseV1),
}

impl VectorCaseV1 {
    /// Returns the canonical request kind encoded by this variant.
    pub const fn request_kind(&self) -> LifecycleRequestKindV1 {
        match self {
            Self::Registration(_) => LifecycleRequestKindV1::Registration,
            Self::Activation(_) => LifecycleRequestKindV1::Activation,
            Self::Recovery(_) => LifecycleRequestKindV1::Recovery,
            Self::Refresh(_) => LifecycleRequestKindV1::Refresh,
            Self::Export(_) => LifecycleRequestKindV1::Export,
        }
    }

    /// Returns the synthetic joined reference trace for this case.
    pub const fn clear_reference_trace(&self) -> &VectorClearReferenceTraceV1 {
        match self {
            Self::Registration(case)
            | Self::Activation(case)
            | Self::Recovery(case)
            | Self::Refresh(case) => &case.clear_reference_trace,
            Self::Export(case) => &case.reference.clear_reference_trace,
        }
    }
}

/// Common context, inputs, and joined trace for one synthetic vector.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VectorReferenceCaseV1 {
    /// Stable case identifier.
    pub case_id: String,
    /// Frozen stable key context recorded alongside the synthetic inputs.
    pub context: VectorContextV1,
    /// All four `y` and four `tau` role contributions.
    pub inputs: VectorInputsV1,
    /// Joined host-only oracle values unavailable to protocol parties.
    pub clear_reference_trace: VectorClearReferenceTraceV1,
}

/// Export vector with a required authorized seed result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VectorExportCaseV1 {
    /// Common synthetic clear-reference case.
    pub reference: VectorReferenceCaseV1,
    /// Seed returned only by the explicitly authorized export branch.
    pub authorized_seed_hex: String,
}

/// Portable stable-context evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VectorContextV1 {
    /// SDK-owned immutable application binding digest.
    pub application_binding_digest_hex: String,
    /// Exactly two canonical participant identifiers.
    pub participant_ids: [u16; 2],
    /// Exact stable-context encoding.
    pub encoded_hex: String,
    /// SHA-256 binding of the domain-separated context encoding.
    pub binding_sha256_hex: String,
}

/// Portable role-local input encodings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VectorInputsV1 {
    /// A's client-labelled seed contribution.
    pub y_client_a_hex: String,
    /// A's server-labelled seed contribution.
    pub y_server_a_hex: String,
    /// B's client-labelled seed contribution.
    pub y_client_b_hex: String,
    /// B's server-labelled seed contribution.
    pub y_server_b_hex: String,
    /// A's client-labelled canonical scalar contribution.
    pub tau_client_a_hex: String,
    /// A's server-labelled canonical scalar contribution.
    pub tau_server_a_hex: String,
    /// B's client-labelled canonical scalar contribution.
    pub tau_client_b_hex: String,
    /// B's server-labelled canonical scalar contribution.
    pub tau_server_b_hex: String,
}

/// Complete host-only joined trace for differential implementations.
///
/// These values are synthetic oracle evidence. They do not describe values
/// revealed to a Deriver, Router, client, or SigningWorker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VectorClearReferenceTraceV1 {
    /// A's joined `y` contribution modulo `2^256`.
    pub y_a_hex: String,
    /// B's joined `y` contribution modulo `2^256`.
    pub y_b_hex: String,
    /// Joined RFC 8032 seed `d` modulo `2^256`.
    pub joined_seed_hex: String,
    /// Full SHA-512 digest of the joined seed.
    pub sha512_digest_hex: String,
    /// RFC 8032-clamped lower digest half before scalar reduction.
    pub clamped_scalar_bytes_hex: String,
    /// Canonical reduced Ed25519 signing scalar.
    pub signing_scalar_hex: String,
    /// A's joined `tau` contribution modulo `l`.
    pub tau_a_hex: String,
    /// B's joined `tau` contribution modulo `l`.
    pub tau_b_hex: String,
    /// Canonical joined `tau` scalar.
    pub tau_hex: String,
    /// Canonical `a + tau mod l` scalar.
    pub x_client_base_hex: String,
    /// Canonical `a + 2*tau mod l` scalar.
    pub x_server_base_hex: String,
    /// Compressed `[x_client_base]B` point.
    pub x_client_point_hex: String,
    /// Compressed `[x_server_base]B` point.
    pub x_server_point_hex: String,
    /// Standard RFC 8032 public key derived from the seed.
    pub public_key_hex: String,
}

#[derive(Clone, Copy)]
struct SyntheticInputs {
    y_client_a: [u8; 32],
    y_server_a: [u8; 32],
    y_client_b: [u8; 32],
    y_server_b: [u8; 32],
    tau_client_a: Scalar,
    tau_server_a: Scalar,
    tau_client_b: Scalar,
    tau_server_b: Scalar,
}

impl SyntheticInputs {
    fn for_request_kind(request_kind: LifecycleRequestKindV1) -> Self {
        match request_kind {
            LifecycleRequestKindV1::Registration => Self::rfc8032_vector_one(),
            LifecycleRequestKindV1::Activation => Self::wrapping_boundaries(),
            LifecycleRequestKindV1::Recovery => Self::patterned(0x13, 0x29, 3),
            LifecycleRequestKindV1::Refresh => Self::patterned(0x71, 0x1d, 19),
            LifecycleRequestKindV1::Export => Self::rfc8032_vector_two(),
        }
    }

    fn rfc8032_vector_one() -> Self {
        Self {
            y_client_a: RFC8032_VECTOR_ONE_SEED,
            y_server_a: [0u8; 32],
            y_client_b: [0u8; 32],
            y_server_b: [0u8; 32],
            tau_client_a: Scalar::ZERO,
            tau_server_a: Scalar::ZERO,
            tau_client_b: Scalar::ZERO,
            tau_server_b: Scalar::ZERO,
        }
    }

    fn wrapping_boundaries() -> Self {
        let mut one = [0u8; 32];
        one[0] = 1;
        Self {
            y_client_a: [0xff; 32],
            y_server_a: one,
            y_client_b: [0u8; 32],
            y_server_b: [0u8; 32],
            tau_client_a: -Scalar::ONE,
            tau_server_a: Scalar::from(2u64),
            tau_client_b: -Scalar::ONE,
            tau_server_b: Scalar::ZERO,
        }
    }

    fn patterned(first_start: u8, second_start: u8, scalar_start: u64) -> Self {
        Self {
            y_client_a: patterned_bytes(first_start, 0x07),
            y_server_a: patterned_bytes(second_start, 0x11),
            y_client_b: patterned_bytes(first_start.wrapping_add(0x83), 0x19),
            y_server_b: patterned_bytes(second_start.wrapping_add(0x47), 0x23),
            tau_client_a: Scalar::from(scalar_start),
            tau_server_a: Scalar::from(scalar_start + 2),
            tau_client_b: Scalar::from(scalar_start + 6),
            tau_server_b: Scalar::from(scalar_start + 12),
        }
    }

    fn rfc8032_vector_two() -> Self {
        Self {
            y_client_a: RFC8032_VECTOR_TWO_SEED,
            y_server_a: [0u8; 32],
            y_client_b: [0u8; 32],
            y_server_b: [0u8; 32],
            tau_client_a: Scalar::from(5u64),
            tau_server_a: Scalar::from(7u64),
            tau_client_b: Scalar::from(11u64),
            tau_server_b: Scalar::from(13u64),
        }
    }

    fn validate(self) -> (DeriverAContribution, DeriverBContribution) {
        let deriver_a = DeriverAContribution::try_from(RawDeriverAContribution {
            y_client: self.y_client_a,
            y_server: self.y_server_a,
            tau_client: self.tau_client_a.to_bytes(),
            tau_server: self.tau_server_a.to_bytes(),
        })
        .expect("fixed A vector contributions are canonical");
        let deriver_b = DeriverBContribution::try_from(RawDeriverBContribution {
            y_client: self.y_client_b,
            y_server: self.y_server_b,
            tau_client: self.tau_client_b.to_bytes(),
            tau_server: self.tau_server_b.to_bytes(),
        })
        .expect("fixed B vector contributions are canonical");
        (deriver_a, deriver_b)
    }
}

/// Builds the canonical deterministic version-one corpus.
pub fn canonical_vector_corpus_v1() -> VectorCorpusV1 {
    let request_kinds = [
        LifecycleRequestKindV1::Registration,
        LifecycleRequestKindV1::Activation,
        LifecycleRequestKindV1::Recovery,
        LifecycleRequestKindV1::Refresh,
        LifecycleRequestKindV1::Export,
    ];
    let cases = request_kinds
        .into_iter()
        .enumerate()
        .map(build_vector_case)
        .collect();

    VectorCorpusV1 {
        schema: VECTOR_CORPUS_SCHEMA_V1.to_owned(),
        protocol_id: ed25519_yao::PROTOCOL_ID_STR.to_owned(),
        cases,
    }
}

/// Builds a deterministic differential corpus from a public 32-byte test seed.
///
/// This generator never consumes operating-system randomness. The seed and all
/// derived values are public test material and must never be used as wallet
/// roots or protocol contributions.
pub fn differential_vector_corpus_v1(
    public_test_seed: [u8; 32],
    case_count: usize,
) -> Result<VectorCorpusV1, DifferentialVectorError> {
    if case_count == 0 {
        return Err(DifferentialVectorError::EmptyCorpus);
    }
    if case_count > MAX_DIFFERENTIAL_VECTOR_CASES_V1 {
        return Err(DifferentialVectorError::TooManyCases {
            requested: case_count,
            maximum: MAX_DIFFERENTIAL_VECTOR_CASES_V1,
        });
    }

    let cases = (0..case_count)
        .map(|index| build_differential_vector_case(public_test_seed, index))
        .collect();

    Ok(VectorCorpusV1 {
        schema: VECTOR_CORPUS_SCHEMA_V1.to_owned(),
        protocol_id: ed25519_yao::PROTOCOL_ID_STR.to_owned(),
        cases,
    })
}

fn build_vector_case((index, request_kind): (usize, LifecycleRequestKindV1)) -> VectorCaseV1 {
    let index = u8::try_from(index).expect("five vector cases fit in u8");
    let inputs = SyntheticInputs::for_request_kind(request_kind);
    let context = StableKeyDerivationContext::new([0x40u8 + index; 32], 2, 1)
        .expect("fixed context is valid");
    build_vector_case_from_inputs(
        case_id(request_kind).to_owned(),
        request_kind,
        inputs,
        context,
    )
}

fn build_differential_vector_case(public_test_seed: [u8; 32], index: usize) -> VectorCaseV1 {
    let request_kind = differential_request_kind(index);
    let index_u32 = u32::try_from(index).expect("bounded vector index fits in u32");
    let inputs = SyntheticInputs {
        y_client_a: derive_differential_y(public_test_seed, index_u32, 0x01),
        y_server_a: derive_differential_y(public_test_seed, index_u32, 0x02),
        y_client_b: derive_differential_y(public_test_seed, index_u32, 0x03),
        y_server_b: derive_differential_y(public_test_seed, index_u32, 0x04),
        tau_client_a: derive_differential_tau(public_test_seed, index_u32, 0x05),
        tau_server_a: derive_differential_tau(public_test_seed, index_u32, 0x06),
        tau_client_b: derive_differential_tau(public_test_seed, index_u32, 0x07),
        tau_server_b: derive_differential_tau(public_test_seed, index_u32, 0x08),
    };
    let context_digest = derive_differential_y(public_test_seed, index_u32, 0x09);
    let participant_low =
        u16::try_from(index % 32_767).expect("participant remainder fits in u16") + 1;
    let participant_high = participant_low + 32_768;
    let context =
        StableKeyDerivationContext::new(context_digest, participant_high, participant_low)
            .expect("derived participant identifiers are distinct and nonzero");
    let case_id = format!(
        "differential_{index:04}_{}_v1",
        request_kind_label(request_kind)
    );
    build_vector_case_from_inputs(case_id, request_kind, inputs, context)
}

fn build_vector_case_from_inputs(
    case_id: String,
    request_kind: LifecycleRequestKindV1,
    inputs: SyntheticInputs,
    context: StableKeyDerivationContext,
) -> VectorCaseV1 {
    let (deriver_a, deriver_b) = inputs.validate();
    let activation = evaluate_activation(&deriver_a, &deriver_b);
    let reference = VectorReferenceCaseV1 {
        case_id,
        context: context_fixture(&context),
        inputs: inputs_fixture(inputs),
        clear_reference_trace: trace_fixture(inputs, activation.material()),
    };

    match request_kind {
        LifecycleRequestKindV1::Registration => VectorCaseV1::Registration(reference),
        LifecycleRequestKindV1::Activation => VectorCaseV1::Activation(reference),
        LifecycleRequestKindV1::Recovery => VectorCaseV1::Recovery(reference),
        LifecycleRequestKindV1::Refresh => VectorCaseV1::Refresh(reference),
        LifecycleRequestKindV1::Export => {
            let export = evaluate_export(&deriver_a, &deriver_b);
            assert_eq!(
                reference.clear_reference_trace.joined_seed_hex,
                encode_hex(&export.seed().expose_bytes()),
                "export result must equal the joined clear trace"
            );
            VectorCaseV1::Export(VectorExportCaseV1 {
                reference,
                authorized_seed_hex: encode_hex(&export.seed().expose_bytes()),
            })
        }
    }
}

fn differential_request_kind(index: usize) -> LifecycleRequestKindV1 {
    match index % 5 {
        0 => LifecycleRequestKindV1::Registration,
        1 => LifecycleRequestKindV1::Activation,
        2 => LifecycleRequestKindV1::Recovery,
        3 => LifecycleRequestKindV1::Refresh,
        4 => LifecycleRequestKindV1::Export,
        _ => unreachable!("remainder modulo five is in range"),
    }
}

fn request_kind_label(request_kind: LifecycleRequestKindV1) -> &'static str {
    match request_kind {
        LifecycleRequestKindV1::Registration => "registration",
        LifecycleRequestKindV1::Activation => "activation",
        LifecycleRequestKindV1::Recovery => "recovery",
        LifecycleRequestKindV1::Refresh => "refresh",
        LifecycleRequestKindV1::Export => "export",
    }
}

fn derive_differential_y(public_test_seed: [u8; 32], case_index: u32, field_tag: u8) -> [u8; 32] {
    let wide = derive_differential_wide(public_test_seed, case_index, field_tag);
    wide[..32]
        .try_into()
        .expect("SHA-512 prefix has the requested length")
}

fn derive_differential_tau(public_test_seed: [u8; 32], case_index: u32, field_tag: u8) -> Scalar {
    Scalar::from_bytes_mod_order_wide(&derive_differential_wide(
        public_test_seed,
        case_index,
        field_tag,
    ))
}

fn derive_differential_wide(
    public_test_seed: [u8; 32],
    case_index: u32,
    field_tag: u8,
) -> [u8; 64] {
    let mut hasher = Sha512::new();
    hasher.update(DIFFERENTIAL_INPUT_DOMAIN_V1);
    hasher.update([0u8]);
    hasher.update(public_test_seed);
    hasher.update(case_index.to_be_bytes());
    hasher.update([field_tag]);
    hasher.finalize().into()
}

fn case_id(request_kind: LifecycleRequestKindV1) -> &'static str {
    match request_kind {
        LifecycleRequestKindV1::Registration => "registration_rfc8032_vector_one_v1",
        LifecycleRequestKindV1::Activation => "activation_wrapping_boundaries_v1",
        LifecycleRequestKindV1::Recovery => "recovery_clear_arithmetic_v1",
        LifecycleRequestKindV1::Refresh => "refresh_clear_arithmetic_v1",
        LifecycleRequestKindV1::Export => "export_rfc8032_vector_two_v1",
    }
}

fn context_fixture(context: &StableKeyDerivationContext) -> VectorContextV1 {
    VectorContextV1 {
        application_binding_digest_hex: encode_hex(context.application_binding_digest().as_bytes()),
        participant_ids: context.participant_ids().as_array(),
        encoded_hex: encode_hex(context.encode().as_bytes()),
        binding_sha256_hex: encode_hex(context.binding_digest().as_bytes()),
    }
}

fn inputs_fixture(inputs: SyntheticInputs) -> VectorInputsV1 {
    VectorInputsV1 {
        y_client_a_hex: encode_hex(&inputs.y_client_a),
        y_server_a_hex: encode_hex(&inputs.y_server_a),
        y_client_b_hex: encode_hex(&inputs.y_client_b),
        y_server_b_hex: encode_hex(&inputs.y_server_b),
        tau_client_a_hex: encode_hex(&inputs.tau_client_a.to_bytes()),
        tau_server_a_hex: encode_hex(&inputs.tau_server_a.to_bytes()),
        tau_client_b_hex: encode_hex(&inputs.tau_client_b.to_bytes()),
        tau_server_b_hex: encode_hex(&inputs.tau_server_b.to_bytes()),
    }
}

fn trace_fixture(
    inputs: SyntheticInputs,
    material: &OracleMaterial,
) -> VectorClearReferenceTraceV1 {
    let y_a = wrapping_add_le_256(inputs.y_client_a, inputs.y_server_a);
    let y_b = wrapping_add_le_256(inputs.y_client_b, inputs.y_server_b);
    let joined_seed = wrapping_add_le_256(y_a, y_b);
    let tau_a = inputs.tau_client_a + inputs.tau_server_a;
    let tau_b = inputs.tau_client_b + inputs.tau_server_b;
    let joined_tau = tau_a + tau_b;

    assert_eq!(joined_tau.to_bytes(), material.tau().expose_bytes());

    VectorClearReferenceTraceV1 {
        y_a_hex: encode_hex(&y_a),
        y_b_hex: encode_hex(&y_b),
        joined_seed_hex: encode_hex(&joined_seed),
        sha512_digest_hex: encode_hex(&material.sha512_digest().expose_bytes()),
        clamped_scalar_bytes_hex: encode_hex(&material.clamped_scalar_bytes().expose_bytes()),
        signing_scalar_hex: encode_hex(&material.signing_scalar().expose_bytes()),
        tau_a_hex: encode_hex(&tau_a.to_bytes()),
        tau_b_hex: encode_hex(&tau_b.to_bytes()),
        tau_hex: encode_hex(&material.tau().expose_bytes()),
        x_client_base_hex: encode_hex(&material.x_client_base().expose_bytes()),
        x_server_base_hex: encode_hex(&material.x_server_base().expose_bytes()),
        x_client_point_hex: encode_hex(&material.x_client().expose_bytes()),
        x_server_point_hex: encode_hex(&material.x_server().expose_bytes()),
        public_key_hex: encode_hex(&material.public_key().expose_bytes()),
    }
}

fn patterned_bytes(start: u8, step: u8) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        let offset = step.wrapping_mul(u8::try_from(index).expect("32-byte index fits u8"));
        *byte = start.wrapping_add(offset);
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
