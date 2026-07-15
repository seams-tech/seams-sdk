use curve25519_dalek::scalar::Scalar;

use super::add256::wrapping_add_le_256_bits;
use super::clamp::clamp_rfc8032_bits;
use super::ir::{BuilderBit, CanonicalBooleanCircuitV1, CircuitBuilder};
use super::scalar::{add_mod_l_bits, reduce_clamped_mod_l_bits};
use super::schedule::{CanonicalLivenessScheduleV1, ProvisionalScheduleMetricsV1};
use super::sha512::sha512_fixed_32_bits;
use super::BooleanCircuitMetricsV1;

/// Canonical provisional activation-core input schema bytes.
pub const PROVISIONAL_ACTIVATION_CORE_INPUT_SCHEMA_V1: &str =
    "seams/router-ab/ed25519-yao/provisional-benchmark/activation/input/v1:a.y_client[32],a.y_server[32],a.tau_client[32]:canonical-l,a.tau_server[32]:canonical-l,b.y_client[32],b.y_server[32],b.tau_client[32]:canonical-l,b.tau_server[32]:canonical-l:field-byte-bit-lsb0";
/// Canonical provisional activation-core output schema bytes.
pub const PROVISIONAL_ACTIVATION_CORE_OUTPUT_SCHEMA_V1: &str =
    "seams/router-ab/ed25519-yao/provisional-benchmark/activation/output/v1:x_client_base[32]:canonical-l,x_server_base[32]:canonical-l:field-byte-bit-lsb0:no-seed";
/// Canonical provisional export-core input schema bytes.
pub const PROVISIONAL_EXPORT_CORE_INPUT_SCHEMA_V1: &str =
    "seams/router-ab/ed25519-yao/provisional-benchmark/export/input/v1:a.y_client[32],a.y_server[32],b.y_client[32],b.y_server[32]:field-byte-bit-lsb0:no-tau";
/// Canonical provisional export-core output schema bytes.
pub const PROVISIONAL_EXPORT_CORE_OUTPUT_SCHEMA_V1: &str =
    "seams/router-ab/ed25519-yao/provisional-benchmark/export/output/v1:seed[32]:field-byte-bit-lsb0:no-scalar";

const FIELD_BIT_WIDTH: usize = 256;
const ACTIVATION_INPUT_BIT_WIDTH: u32 = 8 * FIELD_BIT_WIDTH as u32;
const EXPORT_INPUT_BIT_WIDTH: u32 = 4 * FIELD_BIT_WIDTH as u32;
const ACTIVATION_OUTPUT_BIT_WIDTH: usize = 2 * FIELD_BIT_WIDTH;

/// Canonical scalar field rejected at the public-synthetic harness boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicSyntheticTauFieldV1 {
    /// Deriver A client contribution.
    DeriverAClient,
    /// Deriver A server contribution.
    DeriverAServer,
    /// Deriver B client contribution.
    DeriverBClient,
    /// Deriver B server contribution.
    DeriverBServer,
}

/// Boundary error for a noncanonical public-synthetic scalar contribution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicSyntheticActivationInputErrorV1 {
    field: PublicSyntheticTauFieldV1,
}

impl PublicSyntheticActivationInputErrorV1 {
    /// Returns the exact malformed scalar field.
    pub const fn field(self) -> PublicSyntheticTauFieldV1 {
        self.field
    }
}

struct PublicSyntheticRoleActivationInputsV1 {
    y_client: [u8; 32],
    y_server: [u8; 32],
    tau_client: [u8; 32],
    tau_server: [u8; 32],
}

/// Validated public-synthetic Deriver A activation-core inputs.
pub struct PublicSyntheticDeriverAActivationInputsV1(PublicSyntheticRoleActivationInputsV1);

impl PublicSyntheticDeriverAActivationInputsV1 {
    /// Validates both canonical scalar inputs once at the harness boundary.
    pub fn new(
        y_client: [u8; 32],
        y_server: [u8; 32],
        tau_client: [u8; 32],
        tau_server: [u8; 32],
    ) -> Result<Self, PublicSyntheticActivationInputErrorV1> {
        validate_canonical_tau(tau_client, PublicSyntheticTauFieldV1::DeriverAClient)?;
        validate_canonical_tau(tau_server, PublicSyntheticTauFieldV1::DeriverAServer)?;
        Ok(Self(PublicSyntheticRoleActivationInputsV1 {
            y_client,
            y_server,
            tau_client,
            tau_server,
        }))
    }

    pub(super) fn append_canonical_fields_v1(&self, bytes: &mut Vec<u8>) {
        append_activation_role_fields(&self.0, bytes);
    }
}

/// Validated public-synthetic Deriver B activation-core inputs.
pub struct PublicSyntheticDeriverBActivationInputsV1(PublicSyntheticRoleActivationInputsV1);

impl PublicSyntheticDeriverBActivationInputsV1 {
    /// Validates both canonical scalar inputs once at the harness boundary.
    pub fn new(
        y_client: [u8; 32],
        y_server: [u8; 32],
        tau_client: [u8; 32],
        tau_server: [u8; 32],
    ) -> Result<Self, PublicSyntheticActivationInputErrorV1> {
        validate_canonical_tau(tau_client, PublicSyntheticTauFieldV1::DeriverBClient)?;
        validate_canonical_tau(tau_server, PublicSyntheticTauFieldV1::DeriverBServer)?;
        Ok(Self(PublicSyntheticRoleActivationInputsV1 {
            y_client,
            y_server,
            tau_client,
            tau_server,
        }))
    }

    pub(super) fn append_canonical_fields_v1(&self, bytes: &mut Vec<u8>) {
        append_activation_role_fields(&self.0, bytes);
    }
}

/// Complete validated public-synthetic activation-core input tuple.
pub struct PublicSyntheticActivationCoreInputsV1 {
    deriver_a: PublicSyntheticDeriverAActivationInputsV1,
    deriver_b: PublicSyntheticDeriverBActivationInputsV1,
}

impl PublicSyntheticActivationCoreInputsV1 {
    /// Joins role-typed inputs without changing their fixed wire order.
    pub const fn new(
        deriver_a: PublicSyntheticDeriverAActivationInputsV1,
        deriver_b: PublicSyntheticDeriverBActivationInputsV1,
    ) -> Self {
        Self {
            deriver_a,
            deriver_b,
        }
    }

    pub(crate) fn canonical_input_bytes_v1(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(ACTIVATION_INPUT_BIT_WIDTH as usize / 8);
        self.deriver_a.append_canonical_fields_v1(&mut bytes);
        self.deriver_b.append_canonical_fields_v1(&mut bytes);
        bytes
    }
}

fn append_activation_role_fields(
    inputs: &PublicSyntheticRoleActivationInputsV1,
    bytes: &mut Vec<u8>,
) {
    bytes.extend_from_slice(&inputs.y_client);
    bytes.extend_from_slice(&inputs.y_server);
    bytes.extend_from_slice(&inputs.tau_client);
    bytes.extend_from_slice(&inputs.tau_server);
}

struct PublicSyntheticRoleExportInputsV1 {
    y_client: [u8; 32],
    y_server: [u8; 32],
}

/// Public-synthetic Deriver A export-core seed inputs.
pub struct PublicSyntheticDeriverAExportInputsV1(PublicSyntheticRoleExportInputsV1);

impl PublicSyntheticDeriverAExportInputsV1 {
    /// Constructs the fixed two-field Deriver A export input.
    pub const fn new(y_client: [u8; 32], y_server: [u8; 32]) -> Self {
        Self(PublicSyntheticRoleExportInputsV1 { y_client, y_server })
    }

    pub(super) fn append_canonical_fields_v1(&self, bytes: &mut Vec<u8>) {
        append_export_role_fields(&self.0, bytes);
    }
}

/// Public-synthetic Deriver B export-core seed inputs.
pub struct PublicSyntheticDeriverBExportInputsV1(PublicSyntheticRoleExportInputsV1);

impl PublicSyntheticDeriverBExportInputsV1 {
    /// Constructs the fixed two-field Deriver B export input.
    pub const fn new(y_client: [u8; 32], y_server: [u8; 32]) -> Self {
        Self(PublicSyntheticRoleExportInputsV1 { y_client, y_server })
    }

    pub(super) fn append_canonical_fields_v1(&self, bytes: &mut Vec<u8>) {
        append_export_role_fields(&self.0, bytes);
    }
}

/// Complete public-synthetic export-core input tuple with no scalar fields.
pub struct PublicSyntheticExportCoreInputsV1 {
    deriver_a: PublicSyntheticDeriverAExportInputsV1,
    deriver_b: PublicSyntheticDeriverBExportInputsV1,
}

impl PublicSyntheticExportCoreInputsV1 {
    /// Joins role-typed inputs without changing their fixed wire order.
    pub const fn new(
        deriver_a: PublicSyntheticDeriverAExportInputsV1,
        deriver_b: PublicSyntheticDeriverBExportInputsV1,
    ) -> Self {
        Self {
            deriver_a,
            deriver_b,
        }
    }

    pub(crate) fn canonical_input_bytes_v1(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(EXPORT_INPUT_BIT_WIDTH as usize / 8);
        self.deriver_a.append_canonical_fields_v1(&mut bytes);
        self.deriver_b.append_canonical_fields_v1(&mut bytes);
        bytes
    }
}

fn append_export_role_fields(inputs: &PublicSyntheticRoleExportInputsV1, bytes: &mut Vec<u8>) {
    bytes.extend_from_slice(&inputs.y_client);
    bytes.extend_from_slice(&inputs.y_server);
}

/// Seed-free mathematical outputs of the provisional activation core.
#[derive(PartialEq, Eq)]
pub struct PublicSyntheticActivationCoreOutputsV1 {
    x_client_base: [u8; 32],
    x_server_base: [u8; 32],
}

impl PublicSyntheticActivationCoreOutputsV1 {
    /// Returns the canonical client scalar output.
    pub const fn x_client_base(&self) -> [u8; 32] {
        self.x_client_base
    }

    /// Returns the canonical SigningWorker scalar output.
    pub const fn x_server_base(&self) -> [u8; 32] {
        self.x_server_base
    }
}

/// Seed-only mathematical output of the provisional export core.
#[derive(PartialEq, Eq)]
pub struct PublicSyntheticExportCoreOutputV1 {
    seed: [u8; 32],
}

/// Provisional activation-core digest with no production conversion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProvisionalActivationCoreDigest32V1([u8; 32]);

impl ProvisionalActivationCoreDigest32V1 {
    /// Exposes public digest bytes for benchmark reproducibility.
    pub const fn expose_public_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// Provisional export-core digest with no production conversion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProvisionalExportCoreDigest32V1([u8; 32]);

impl ProvisionalExportCoreDigest32V1 {
    /// Exposes public digest bytes for benchmark reproducibility.
    pub const fn expose_public_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// Provisional activation-core schedule digest with no production conversion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProvisionalActivationScheduleDigest32V1([u8; 32]);

impl ProvisionalActivationScheduleDigest32V1 {
    /// Exposes public digest bytes for benchmark reproducibility.
    pub const fn expose_public_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// Provisional export-core schedule digest with no production conversion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProvisionalExportScheduleDigest32V1([u8; 32]);

impl ProvisionalExportScheduleDigest32V1 {
    /// Exposes public digest bytes for benchmark reproducibility.
    pub const fn expose_public_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl PublicSyntheticExportCoreOutputV1 {
    /// Returns the public-synthetic seed projection.
    pub const fn seed(&self) -> [u8; 32] {
        self.seed
    }
}

/// Opaque provisional activation-family benchmark core.
pub struct ProvisionalActivationCoreV1 {
    circuit: CanonicalBooleanCircuitV1,
    schedule: CanonicalLivenessScheduleV1,
}

impl ProvisionalActivationCoreV1 {
    /// Evaluates joined mathematical outputs over public synthetic inputs.
    pub fn evaluate_public_synthetic(
        &self,
        inputs: &PublicSyntheticActivationCoreInputsV1,
    ) -> PublicSyntheticActivationCoreOutputsV1 {
        let bits = activation_input_bits(inputs);
        let outputs = self
            .schedule
            .evaluate(&bits)
            .expect("typed activation input has the fixed width");
        PublicSyntheticActivationCoreOutputsV1 {
            x_client_base: lsb0_bits_to_32_bytes(&outputs[..FIELD_BIT_WIDTH]),
            x_server_base: lsb0_bits_to_32_bytes(&outputs[FIELD_BIT_WIDTH..]),
        }
    }

    pub(crate) fn evaluate_ir_public_synthetic_bytes_v1(
        &self,
        inputs: &PublicSyntheticActivationCoreInputsV1,
    ) -> Vec<u8> {
        let outputs = self
            .circuit
            .evaluate(&activation_input_bits(inputs))
            .expect("typed activation input has the fixed width");
        lsb0_bits_to_bytes(&outputs)
    }

    pub(crate) fn evaluate_schedule_public_synthetic_bytes_v1(
        &self,
        inputs: &PublicSyntheticActivationCoreInputsV1,
    ) -> Vec<u8> {
        let outputs = self
            .schedule
            .evaluate(&activation_input_bits(inputs))
            .expect("typed activation input has the fixed width");
        lsb0_bits_to_bytes(&outputs)
    }

    /// Returns metrics derived from the provisional activation core.
    pub const fn metrics(&self) -> BooleanCircuitMetricsV1 {
        self.circuit.metrics()
    }

    /// Returns the provisional activation-core identity.
    pub const fn benchmark_component_digest(&self) -> ProvisionalActivationCoreDigest32V1 {
        ProvisionalActivationCoreDigest32V1(self.circuit.digest())
    }

    /// Returns the exact provisional activation-core bytes.
    pub fn canonical_encoding(&self) -> &[u8] {
        self.circuit.canonical_encoding()
    }

    /// Returns metrics derived from the canonical activation schedule.
    pub const fn schedule_metrics(&self) -> ProvisionalScheduleMetricsV1 {
        self.schedule.metrics()
    }

    /// Returns the provisional activation-schedule identity.
    pub const fn benchmark_schedule_digest(&self) -> ProvisionalActivationScheduleDigest32V1 {
        ProvisionalActivationScheduleDigest32V1(self.schedule.digest())
    }

    /// Returns the exact canonical activation-schedule bytes.
    pub fn canonical_schedule_encoding(&self) -> &[u8] {
        self.schedule.canonical_encoding()
    }
}

/// Opaque provisional export-family benchmark core.
pub struct ProvisionalExportCoreV1 {
    circuit: CanonicalBooleanCircuitV1,
    schedule: CanonicalLivenessScheduleV1,
}

impl ProvisionalExportCoreV1 {
    /// Evaluates the seed projection over public synthetic inputs.
    pub fn evaluate_public_synthetic(
        &self,
        inputs: &PublicSyntheticExportCoreInputsV1,
    ) -> PublicSyntheticExportCoreOutputV1 {
        let bits = export_input_bits(inputs);
        let outputs = self
            .schedule
            .evaluate(&bits)
            .expect("typed export input has the fixed width");
        PublicSyntheticExportCoreOutputV1 {
            seed: lsb0_bits_to_32_bytes(&outputs),
        }
    }

    pub(crate) fn evaluate_ir_public_synthetic_bytes_v1(
        &self,
        inputs: &PublicSyntheticExportCoreInputsV1,
    ) -> Vec<u8> {
        let outputs = self
            .circuit
            .evaluate(&export_input_bits(inputs))
            .expect("typed export input has the fixed width");
        lsb0_bits_to_bytes(&outputs)
    }

    pub(crate) fn evaluate_schedule_public_synthetic_bytes_v1(
        &self,
        inputs: &PublicSyntheticExportCoreInputsV1,
    ) -> Vec<u8> {
        let outputs = self
            .schedule
            .evaluate(&export_input_bits(inputs))
            .expect("typed export input has the fixed width");
        lsb0_bits_to_bytes(&outputs)
    }

    /// Returns metrics derived from the provisional export core.
    pub const fn metrics(&self) -> BooleanCircuitMetricsV1 {
        self.circuit.metrics()
    }

    /// Returns the provisional export-core identity.
    pub const fn benchmark_component_digest(&self) -> ProvisionalExportCoreDigest32V1 {
        ProvisionalExportCoreDigest32V1(self.circuit.digest())
    }

    /// Returns the exact provisional export-core bytes.
    pub fn canonical_encoding(&self) -> &[u8] {
        self.circuit.canonical_encoding()
    }

    /// Returns metrics derived from the canonical export schedule.
    pub const fn schedule_metrics(&self) -> ProvisionalScheduleMetricsV1 {
        self.schedule.metrics()
    }

    /// Returns the provisional export-schedule identity.
    pub const fn benchmark_schedule_digest(&self) -> ProvisionalExportScheduleDigest32V1 {
        ProvisionalExportScheduleDigest32V1(self.schedule.digest())
    }

    /// Returns the exact canonical export-schedule bytes.
    pub fn canonical_schedule_encoding(&self) -> &[u8] {
        self.schedule.canonical_encoding()
    }
}

#[derive(Clone, Copy)]
pub(super) struct ActivationRoleInputBitsV1 {
    pub(super) y_client: [BuilderBit; FIELD_BIT_WIDTH],
    pub(super) y_server: [BuilderBit; FIELD_BIT_WIDTH],
    pub(super) tau_client: [BuilderBit; FIELD_BIT_WIDTH],
    pub(super) tau_server: [BuilderBit; FIELD_BIT_WIDTH],
}

#[derive(Clone, Copy)]
pub(super) struct ExportRoleInputBitsV1 {
    pub(super) y_client: [BuilderBit; FIELD_BIT_WIDTH],
    pub(super) y_server: [BuilderBit; FIELD_BIT_WIDTH],
}

pub(super) fn activation_base_output_bits(
    builder: &mut CircuitBuilder,
    deriver_a: ActivationRoleInputBitsV1,
    deriver_b: ActivationRoleInputBitsV1,
) -> ([BuilderBit; FIELD_BIT_WIDTH], [BuilderBit; FIELD_BIT_WIDTH]) {
    let seed = export_seed_bits(
        builder,
        ExportRoleInputBitsV1 {
            y_client: deriver_a.y_client,
            y_server: deriver_a.y_server,
        },
        ExportRoleInputBitsV1 {
            y_client: deriver_b.y_client,
            y_server: deriver_b.y_server,
        },
    );
    let digest = sha512_fixed_32_bits(builder, seed);
    let digest_prefix: [BuilderBit; FIELD_BIT_WIDTH] = digest[..FIELD_BIT_WIDTH]
        .try_into()
        .expect("SHA-512 prefix has 256 bits");
    let clamped = clamp_rfc8032_bits(digest_prefix);
    let signing_scalar = reduce_clamped_mod_l_bits(builder, clamped);

    let tau_a = add_mod_l_bits(builder, deriver_a.tau_client, deriver_a.tau_server);
    let tau_b = add_mod_l_bits(builder, deriver_b.tau_client, deriver_b.tau_server);
    let tau = add_mod_l_bits(builder, tau_a, tau_b);
    let x_client_base = add_mod_l_bits(builder, signing_scalar, tau);
    let x_server_base = add_mod_l_bits(builder, x_client_base, tau);
    (x_client_base, x_server_base)
}

pub(super) fn export_seed_bits(
    builder: &mut CircuitBuilder,
    deriver_a: ExportRoleInputBitsV1,
    deriver_b: ExportRoleInputBitsV1,
) -> [BuilderBit; FIELD_BIT_WIDTH] {
    let y_a = wrapping_add_le_256_bits(builder, deriver_a.y_client, deriver_a.y_server);
    let y_b = wrapping_add_le_256_bits(builder, deriver_b.y_client, deriver_b.y_server);
    wrapping_add_le_256_bits(builder, y_a, y_b)
}

/// Compiles the deterministic provisional activation-family benchmark core.
pub fn compile_provisional_activation_core_v1() -> ProvisionalActivationCoreV1 {
    let mut builder = CircuitBuilder::new(ACTIVATION_INPUT_BIT_WIDTH)
        .expect("activation core has fixed nonzero inputs");
    let inputs = builder.input_bits();
    let deriver_a = ActivationRoleInputBitsV1 {
        y_client: field_bits(&inputs, 0),
        y_server: field_bits(&inputs, 1),
        tau_client: field_bits(&inputs, 2),
        tau_server: field_bits(&inputs, 3),
    };
    let deriver_b = ActivationRoleInputBitsV1 {
        y_client: field_bits(&inputs, 4),
        y_server: field_bits(&inputs, 5),
        tau_client: field_bits(&inputs, 6),
        tau_server: field_bits(&inputs, 7),
    };
    let (x_client_base, x_server_base) =
        activation_base_output_bits(&mut builder, deriver_a, deriver_b);

    let mut outputs = Vec::with_capacity(ACTIVATION_OUTPUT_BIT_WIDTH);
    outputs.extend_from_slice(&x_client_base);
    outputs.extend_from_slice(&x_server_base);
    let circuit = builder
        .finish_provisional_activation_core(outputs)
        .expect("activation core topology and schema are fixed");
    let schedule = CanonicalLivenessScheduleV1::derive(&circuit);
    ProvisionalActivationCoreV1 { circuit, schedule }
}

/// Compiles the deterministic provisional export-family benchmark core.
pub fn compile_provisional_export_core_v1() -> ProvisionalExportCoreV1 {
    let mut builder =
        CircuitBuilder::new(EXPORT_INPUT_BIT_WIDTH).expect("export core has fixed nonzero inputs");
    let inputs = builder.input_bits();
    let deriver_a = ExportRoleInputBitsV1 {
        y_client: field_bits(&inputs, 0),
        y_server: field_bits(&inputs, 1),
    };
    let deriver_b = ExportRoleInputBitsV1 {
        y_client: field_bits(&inputs, 2),
        y_server: field_bits(&inputs, 3),
    };
    let seed = export_seed_bits(&mut builder, deriver_a, deriver_b);
    let circuit = builder
        .finish_provisional_export_core(seed.to_vec())
        .expect("export core topology and schema are fixed");
    let schedule = CanonicalLivenessScheduleV1::derive(&circuit);
    ProvisionalExportCoreV1 { circuit, schedule }
}

fn validate_canonical_tau(
    bytes: [u8; 32],
    field: PublicSyntheticTauFieldV1,
) -> Result<(), PublicSyntheticActivationInputErrorV1> {
    if Option::<Scalar>::from(Scalar::from_canonical_bytes(bytes)).is_none() {
        return Err(PublicSyntheticActivationInputErrorV1 { field });
    }
    Ok(())
}

pub(super) fn field_bits(
    inputs: &[BuilderBit],
    field_index: usize,
) -> [BuilderBit; FIELD_BIT_WIDTH] {
    let start = field_index * FIELD_BIT_WIDTH;
    inputs[start..start + FIELD_BIT_WIDTH]
        .try_into()
        .expect("fixed field has 256 bits")
}

pub(crate) fn activation_input_bits(inputs: &PublicSyntheticActivationCoreInputsV1) -> Vec<bool> {
    input_bytes_to_lsb0_bits(&inputs.canonical_input_bytes_v1())
}

pub(crate) fn export_input_bits(inputs: &PublicSyntheticExportCoreInputsV1) -> Vec<bool> {
    input_bytes_to_lsb0_bits(&inputs.canonical_input_bytes_v1())
}

pub(super) fn input_bytes_to_lsb0_bits(bytes: &[u8]) -> Vec<bool> {
    let mut bits = Vec::with_capacity(bytes.len() * 8);
    for byte in bytes {
        for bit_index in 0..8 {
            bits.push(((byte >> bit_index) & 1) == 1);
        }
    }
    bits
}

pub(super) fn lsb0_bits_to_32_bytes(bits: &[bool]) -> [u8; 32] {
    assert_eq!(
        bits.len(),
        FIELD_BIT_WIDTH,
        "scalar/seed output has 256 bits"
    );
    let mut bytes = [0u8; 32];
    for (bit_index, bit) in bits.iter().copied().enumerate() {
        if bit {
            bytes[bit_index / 8] |= 1 << (bit_index % 8);
        }
    }
    bytes
}

pub(super) fn lsb0_bits_to_bytes(bits: &[bool]) -> Vec<u8> {
    assert_eq!(bits.len() % 8, 0, "output bits form complete bytes");
    let mut bytes = vec![0u8; bits.len() / 8];
    for (bit_index, bit) in bits.iter().copied().enumerate() {
        if bit {
            bytes[bit_index / 8] |= 1 << (bit_index % 8);
        }
    }
    bytes
}
