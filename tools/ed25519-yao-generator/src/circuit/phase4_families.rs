use curve25519_dalek::scalar::Scalar;

use super::add256::wrapping_subtract_le_256_bits;
#[cfg(test)]
use super::families::lsb0_bits_to_bytes;
use super::families::{
    activation_base_output_bits, export_seed_bits, field_bits, input_bytes_to_lsb0_bits,
    lsb0_bits_to_32_bytes, ActivationRoleInputBitsV1, ExportRoleInputBitsV1,
    PublicSyntheticDeriverAActivationInputsV1, PublicSyntheticDeriverAExportInputsV1,
    PublicSyntheticDeriverBActivationInputsV1, PublicSyntheticDeriverBExportInputsV1,
};
use super::ir::{CanonicalBooleanCircuitV1, CircuitBuilder};
use super::scalar::{add_mod_l_bits, subtract_mod_l_bits};
use super::schedule::{CanonicalLivenessScheduleV1, ProvisionalScheduleMetricsV1};
use super::BooleanCircuitMetricsV1;

/// Canonical Phase 4 activation input schema for the joint-coin private-output benchmark.
pub const PHASE4_PRIVATE_OUTPUT_ACTIVATION_INPUT_SCHEMA_V1: &str =
    "seams/router-ab/ed25519-yao/phase4-p0-private-output-benchmark/activation/input/v1:a.y_client[32],a.y_server[32],a.tau_client[32]:canonical-l,a.tau_server[32]:canonical-l,a.r_client[32]:canonical-l,a.r_signing_worker[32]:canonical-l,b.y_client[32],b.y_server[32],b.tau_client[32]:canonical-l,b.tau_server[32]:canonical-l,b.r_client[32]:canonical-l,b.r_signing_worker[32]:canonical-l:field-byte-bit-lsb0:joint-coins";
/// Canonical Phase 4 activation output schema in fixed Deriver A then Deriver B order.
pub const PHASE4_PRIVATE_OUTPUT_ACTIVATION_OUTPUT_SCHEMA_V1: &str =
    "seams/router-ab/ed25519-yao/phase4-p0-private-output-benchmark/activation/output/v1:a.x_client_share[32]:canonical-l,a.x_signing_worker_share[32]:canonical-l,b.x_client_share[32]:canonical-l,b.x_signing_worker_share[32]:canonical-l:field-byte-bit-lsb0:role-separated";
/// Canonical Phase 4 export input schema for the joint-coin private-output benchmark.
pub const PHASE4_PRIVATE_OUTPUT_EXPORT_INPUT_SCHEMA_V1: &str =
    "seams/router-ab/ed25519-yao/phase4-p0-private-output-benchmark/export/input/v1:a.y_client[32],a.y_server[32],a.u[32],b.y_client[32],b.y_server[32],b.u[32]:field-byte-bit-lsb0:joint-coins:no-tau";
/// Canonical Phase 4 export output schema in fixed Deriver A then Deriver B order.
pub const PHASE4_PRIVATE_OUTPUT_EXPORT_OUTPUT_SCHEMA_V1: &str =
    "seams/router-ab/ed25519-yao/phase4-p0-private-output-benchmark/export/output/v1:a.seed_share[32],b.seed_share[32]:field-byte-bit-lsb0:role-separated:no-scalar";

const FIELD_BYTES: usize = 32;
const FIELD_BITS: usize = FIELD_BYTES * 8;
const ACTIVATION_INPUT_BITS: u32 = 12 * FIELD_BITS as u32;
const ACTIVATION_OUTPUT_BITS: usize = 4 * FIELD_BITS;
const EXPORT_INPUT_BITS: u32 = 6 * FIELD_BITS as u32;
const EXPORT_OUTPUT_BITS: usize = 2 * FIELD_BITS;

/// Boundary error for a noncanonical Phase 4 scalar coin contribution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicSyntheticPhase4ScalarCoinErrorV1;

/// Canonical Deriver A client-share mask contribution.
pub struct PublicSyntheticPhase4DeriverAClientScalarCoinV1([u8; FIELD_BYTES]);

impl PublicSyntheticPhase4DeriverAClientScalarCoinV1 {
    /// Validates a canonical scalar contribution.
    pub fn new(bytes: [u8; FIELD_BYTES]) -> Result<Self, PublicSyntheticPhase4ScalarCoinErrorV1> {
        validate_scalar_coin(bytes).map(Self)
    }
}

/// Canonical Deriver A SigningWorker-share mask contribution.
pub struct PublicSyntheticPhase4DeriverASigningWorkerScalarCoinV1([u8; FIELD_BYTES]);

impl PublicSyntheticPhase4DeriverASigningWorkerScalarCoinV1 {
    /// Validates a canonical scalar contribution.
    pub fn new(bytes: [u8; FIELD_BYTES]) -> Result<Self, PublicSyntheticPhase4ScalarCoinErrorV1> {
        validate_scalar_coin(bytes).map(Self)
    }
}

/// Canonical Deriver B client-share mask contribution.
pub struct PublicSyntheticPhase4DeriverBClientScalarCoinV1([u8; FIELD_BYTES]);

impl PublicSyntheticPhase4DeriverBClientScalarCoinV1 {
    /// Validates a canonical scalar contribution.
    pub fn new(bytes: [u8; FIELD_BYTES]) -> Result<Self, PublicSyntheticPhase4ScalarCoinErrorV1> {
        validate_scalar_coin(bytes).map(Self)
    }
}

/// Canonical Deriver B SigningWorker-share mask contribution.
pub struct PublicSyntheticPhase4DeriverBSigningWorkerScalarCoinV1([u8; FIELD_BYTES]);

impl PublicSyntheticPhase4DeriverBSigningWorkerScalarCoinV1 {
    /// Validates a canonical scalar contribution.
    pub fn new(bytes: [u8; FIELD_BYTES]) -> Result<Self, PublicSyntheticPhase4ScalarCoinErrorV1> {
        validate_scalar_coin(bytes).map(Self)
    }
}

/// Deriver A's unrestricted 256-bit export-mask contribution.
pub struct PublicSyntheticPhase4DeriverAExportSeedCoinV1([u8; FIELD_BYTES]);

impl PublicSyntheticPhase4DeriverAExportSeedCoinV1 {
    /// Constructs the fixed-width contribution.
    pub const fn new(bytes: [u8; FIELD_BYTES]) -> Self {
        Self(bytes)
    }
}

/// Deriver B's unrestricted 256-bit export-mask contribution.
pub struct PublicSyntheticPhase4DeriverBExportSeedCoinV1([u8; FIELD_BYTES]);

impl PublicSyntheticPhase4DeriverBExportSeedCoinV1 {
    /// Constructs the fixed-width contribution.
    pub const fn new(bytes: [u8; FIELD_BYTES]) -> Self {
        Self(bytes)
    }
}

/// Complete role-typed Phase 4 activation benchmark inputs.
pub struct PublicSyntheticPhase4ActivationInputsV1 {
    deriver_a: PublicSyntheticDeriverAActivationInputsV1,
    deriver_a_client_coin: PublicSyntheticPhase4DeriverAClientScalarCoinV1,
    deriver_a_signing_worker_coin: PublicSyntheticPhase4DeriverASigningWorkerScalarCoinV1,
    deriver_b: PublicSyntheticDeriverBActivationInputsV1,
    deriver_b_client_coin: PublicSyntheticPhase4DeriverBClientScalarCoinV1,
    deriver_b_signing_worker_coin: PublicSyntheticPhase4DeriverBSigningWorkerScalarCoinV1,
}

impl PublicSyntheticPhase4ActivationInputsV1 {
    /// Joins validated role inputs and independently typed joint-coin contributions.
    pub const fn new(
        deriver_a: PublicSyntheticDeriverAActivationInputsV1,
        deriver_a_client_coin: PublicSyntheticPhase4DeriverAClientScalarCoinV1,
        deriver_a_signing_worker_coin: PublicSyntheticPhase4DeriverASigningWorkerScalarCoinV1,
        deriver_b: PublicSyntheticDeriverBActivationInputsV1,
        deriver_b_client_coin: PublicSyntheticPhase4DeriverBClientScalarCoinV1,
        deriver_b_signing_worker_coin: PublicSyntheticPhase4DeriverBSigningWorkerScalarCoinV1,
    ) -> Self {
        Self {
            deriver_a,
            deriver_a_client_coin,
            deriver_a_signing_worker_coin,
            deriver_b,
            deriver_b_client_coin,
            deriver_b_signing_worker_coin,
        }
    }

    pub(crate) fn canonical_input_bytes_v1(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(ACTIVATION_INPUT_BITS as usize / 8);
        self.deriver_a.append_canonical_fields_v1(&mut bytes);
        bytes.extend_from_slice(&self.deriver_a_client_coin.0);
        bytes.extend_from_slice(&self.deriver_a_signing_worker_coin.0);
        self.deriver_b.append_canonical_fields_v1(&mut bytes);
        bytes.extend_from_slice(&self.deriver_b_client_coin.0);
        bytes.extend_from_slice(&self.deriver_b_signing_worker_coin.0);
        bytes
    }
}

/// Complete role-typed Phase 4 export benchmark inputs.
pub struct PublicSyntheticPhase4ExportInputsV1 {
    deriver_a: PublicSyntheticDeriverAExportInputsV1,
    deriver_a_coin: PublicSyntheticPhase4DeriverAExportSeedCoinV1,
    deriver_b: PublicSyntheticDeriverBExportInputsV1,
    deriver_b_coin: PublicSyntheticPhase4DeriverBExportSeedCoinV1,
}

impl PublicSyntheticPhase4ExportInputsV1 {
    /// Joins fixed role inputs and both 256-bit joint-coin contributions.
    pub const fn new(
        deriver_a: PublicSyntheticDeriverAExportInputsV1,
        deriver_a_coin: PublicSyntheticPhase4DeriverAExportSeedCoinV1,
        deriver_b: PublicSyntheticDeriverBExportInputsV1,
        deriver_b_coin: PublicSyntheticPhase4DeriverBExportSeedCoinV1,
    ) -> Self {
        Self {
            deriver_a,
            deriver_a_coin,
            deriver_b,
            deriver_b_coin,
        }
    }

    pub(crate) fn canonical_input_bytes_v1(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(EXPORT_INPUT_BITS as usize / 8);
        self.deriver_a.append_canonical_fields_v1(&mut bytes);
        bytes.extend_from_slice(&self.deriver_a_coin.0);
        self.deriver_b.append_canonical_fields_v1(&mut bytes);
        bytes.extend_from_slice(&self.deriver_b_coin.0);
        bytes
    }
}

/// Deriver A's two canonical activation shares.
#[derive(PartialEq, Eq)]
pub struct PublicSyntheticPhase4DeriverAActivationSharesV1 {
    x_client_share: [u8; FIELD_BYTES],
    x_signing_worker_share: [u8; FIELD_BYTES],
}

impl PublicSyntheticPhase4DeriverAActivationSharesV1 {
    /// Returns Deriver A's client scalar share.
    pub const fn x_client_share(&self) -> [u8; FIELD_BYTES] {
        self.x_client_share
    }

    /// Returns Deriver A's SigningWorker scalar share.
    pub const fn x_signing_worker_share(&self) -> [u8; FIELD_BYTES] {
        self.x_signing_worker_share
    }
}

/// Deriver B's two canonical activation shares.
#[derive(PartialEq, Eq)]
pub struct PublicSyntheticPhase4DeriverBActivationSharesV1 {
    x_client_share: [u8; FIELD_BYTES],
    x_signing_worker_share: [u8; FIELD_BYTES],
}

impl PublicSyntheticPhase4DeriverBActivationSharesV1 {
    /// Returns Deriver B's client scalar share.
    pub const fn x_client_share(&self) -> [u8; FIELD_BYTES] {
        self.x_client_share
    }

    /// Returns Deriver B's SigningWorker scalar share.
    pub const fn x_signing_worker_share(&self) -> [u8; FIELD_BYTES] {
        self.x_signing_worker_share
    }
}

/// Role-separated Phase 4 activation benchmark outputs.
#[derive(PartialEq, Eq)]
pub struct PublicSyntheticPhase4ActivationOutputsV1 {
    deriver_a: PublicSyntheticPhase4DeriverAActivationSharesV1,
    deriver_b: PublicSyntheticPhase4DeriverBActivationSharesV1,
}

impl PublicSyntheticPhase4ActivationOutputsV1 {
    /// Returns only Deriver A's output view.
    pub const fn deriver_a(&self) -> &PublicSyntheticPhase4DeriverAActivationSharesV1 {
        &self.deriver_a
    }

    /// Returns only Deriver B's output view.
    pub const fn deriver_b(&self) -> &PublicSyntheticPhase4DeriverBActivationSharesV1 {
        &self.deriver_b
    }
}

/// Deriver A's 256-bit export share.
#[derive(PartialEq, Eq)]
pub struct PublicSyntheticPhase4DeriverAExportShareV1([u8; FIELD_BYTES]);

impl PublicSyntheticPhase4DeriverAExportShareV1 {
    /// Returns Deriver A's export share.
    pub const fn seed_share(&self) -> [u8; FIELD_BYTES] {
        self.0
    }
}

/// Deriver B's 256-bit export share.
#[derive(PartialEq, Eq)]
pub struct PublicSyntheticPhase4DeriverBExportShareV1([u8; FIELD_BYTES]);

impl PublicSyntheticPhase4DeriverBExportShareV1 {
    /// Returns Deriver B's export share.
    pub const fn seed_share(&self) -> [u8; FIELD_BYTES] {
        self.0
    }
}

/// Role-separated Phase 4 export benchmark outputs.
#[derive(PartialEq, Eq)]
pub struct PublicSyntheticPhase4ExportOutputsV1 {
    deriver_a: PublicSyntheticPhase4DeriverAExportShareV1,
    deriver_b: PublicSyntheticPhase4DeriverBExportShareV1,
}

impl PublicSyntheticPhase4ExportOutputsV1 {
    /// Returns only Deriver A's output view.
    pub const fn deriver_a(&self) -> &PublicSyntheticPhase4DeriverAExportShareV1 {
        &self.deriver_a
    }

    /// Returns only Deriver B's output view.
    pub const fn deriver_b(&self) -> &PublicSyntheticPhase4DeriverBExportShareV1 {
        &self.deriver_b
    }
}

/// Phase 4 private-output activation IR digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Phase4PrivateOutputActivationCoreDigest32V1([u8; FIELD_BYTES]);

impl Phase4PrivateOutputActivationCoreDigest32V1 {
    /// Exposes public digest bytes for benchmark reproducibility.
    pub const fn expose_public_bytes(self) -> [u8; FIELD_BYTES] {
        self.0
    }
}

/// Phase 4 private-output activation schedule digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Phase4PrivateOutputActivationScheduleDigest32V1([u8; FIELD_BYTES]);

impl Phase4PrivateOutputActivationScheduleDigest32V1 {
    /// Exposes public digest bytes for benchmark reproducibility.
    pub const fn expose_public_bytes(self) -> [u8; FIELD_BYTES] {
        self.0
    }
}

/// Phase 4 private-output export IR digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Phase4PrivateOutputExportCoreDigest32V1([u8; FIELD_BYTES]);

impl Phase4PrivateOutputExportCoreDigest32V1 {
    /// Exposes public digest bytes for benchmark reproducibility.
    pub const fn expose_public_bytes(self) -> [u8; FIELD_BYTES] {
        self.0
    }
}

/// Phase 4 private-output export schedule digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Phase4PrivateOutputExportScheduleDigest32V1([u8; FIELD_BYTES]);

impl Phase4PrivateOutputExportScheduleDigest32V1 {
    /// Exposes public digest bytes for benchmark reproducibility.
    pub const fn expose_public_bytes(self) -> [u8; FIELD_BYTES] {
        self.0
    }
}

/// Opaque joint-coin Phase 4 activation benchmark circuit.
pub struct Phase4PrivateOutputActivationCoreV1 {
    circuit: CanonicalBooleanCircuitV1,
    schedule: CanonicalLivenessScheduleV1,
}

impl Phase4PrivateOutputActivationCoreV1 {
    /// Evaluates role-separated shares over public synthetic inputs.
    pub fn evaluate_public_synthetic(
        &self,
        inputs: &PublicSyntheticPhase4ActivationInputsV1,
    ) -> PublicSyntheticPhase4ActivationOutputsV1 {
        let outputs = self
            .schedule
            .evaluate(&phase4_activation_input_bits(inputs))
            .expect("typed Phase 4 activation input has the fixed width");
        PublicSyntheticPhase4ActivationOutputsV1 {
            deriver_a: PublicSyntheticPhase4DeriverAActivationSharesV1 {
                x_client_share: lsb0_bits_to_32_bytes(&outputs[..FIELD_BITS]),
                x_signing_worker_share: lsb0_bits_to_32_bytes(&outputs[FIELD_BITS..2 * FIELD_BITS]),
            },
            deriver_b: PublicSyntheticPhase4DeriverBActivationSharesV1 {
                x_client_share: lsb0_bits_to_32_bytes(&outputs[2 * FIELD_BITS..3 * FIELD_BITS]),
                x_signing_worker_share: lsb0_bits_to_32_bytes(&outputs[3 * FIELD_BITS..]),
            },
        }
    }

    #[cfg(test)]
    pub(crate) fn evaluate_ir_public_synthetic_bytes_v1(
        &self,
        inputs: &PublicSyntheticPhase4ActivationInputsV1,
    ) -> Vec<u8> {
        let outputs = self
            .circuit
            .evaluate(&phase4_activation_input_bits(inputs))
            .expect("typed Phase 4 activation input has the fixed width");
        lsb0_bits_to_bytes(&outputs)
    }

    #[cfg(test)]
    pub(crate) fn evaluate_schedule_public_synthetic_bytes_v1(
        &self,
        inputs: &PublicSyntheticPhase4ActivationInputsV1,
    ) -> Vec<u8> {
        let outputs = self
            .schedule
            .evaluate(&phase4_activation_input_bits(inputs))
            .expect("typed Phase 4 activation input has the fixed width");
        lsb0_bits_to_bytes(&outputs)
    }

    /// Returns metrics derived from the finalized IR.
    pub const fn metrics(&self) -> BooleanCircuitMetricsV1 {
        self.circuit.metrics()
    }

    /// Returns the Phase 4 activation IR identity.
    pub const fn benchmark_component_digest(&self) -> Phase4PrivateOutputActivationCoreDigest32V1 {
        Phase4PrivateOutputActivationCoreDigest32V1(self.circuit.digest())
    }

    /// Returns exact canonical IR bytes.
    pub fn canonical_encoding(&self) -> &[u8] {
        self.circuit.canonical_encoding()
    }

    /// Returns metrics derived from the canonical schedule.
    pub const fn schedule_metrics(&self) -> ProvisionalScheduleMetricsV1 {
        self.schedule.metrics()
    }

    /// Returns the Phase 4 activation schedule identity.
    pub const fn benchmark_schedule_digest(
        &self,
    ) -> Phase4PrivateOutputActivationScheduleDigest32V1 {
        Phase4PrivateOutputActivationScheduleDigest32V1(self.schedule.digest())
    }

    /// Returns exact canonical schedule bytes.
    pub fn canonical_schedule_encoding(&self) -> &[u8] {
        self.schedule.canonical_encoding()
    }
}

/// Opaque joint-coin Phase 4 export benchmark circuit.
pub struct Phase4PrivateOutputExportCoreV1 {
    circuit: CanonicalBooleanCircuitV1,
    schedule: CanonicalLivenessScheduleV1,
}

impl Phase4PrivateOutputExportCoreV1 {
    /// Evaluates role-separated shares over public synthetic inputs.
    pub fn evaluate_public_synthetic(
        &self,
        inputs: &PublicSyntheticPhase4ExportInputsV1,
    ) -> PublicSyntheticPhase4ExportOutputsV1 {
        let outputs = self
            .schedule
            .evaluate(&phase4_export_input_bits(inputs))
            .expect("typed Phase 4 export input has the fixed width");
        PublicSyntheticPhase4ExportOutputsV1 {
            deriver_a: PublicSyntheticPhase4DeriverAExportShareV1(lsb0_bits_to_32_bytes(
                &outputs[..FIELD_BITS],
            )),
            deriver_b: PublicSyntheticPhase4DeriverBExportShareV1(lsb0_bits_to_32_bytes(
                &outputs[FIELD_BITS..],
            )),
        }
    }

    #[cfg(test)]
    pub(crate) fn evaluate_ir_public_synthetic_bytes_v1(
        &self,
        inputs: &PublicSyntheticPhase4ExportInputsV1,
    ) -> Vec<u8> {
        let outputs = self
            .circuit
            .evaluate(&phase4_export_input_bits(inputs))
            .expect("typed Phase 4 export input has the fixed width");
        lsb0_bits_to_bytes(&outputs)
    }

    #[cfg(test)]
    pub(crate) fn evaluate_schedule_public_synthetic_bytes_v1(
        &self,
        inputs: &PublicSyntheticPhase4ExportInputsV1,
    ) -> Vec<u8> {
        let outputs = self
            .schedule
            .evaluate(&phase4_export_input_bits(inputs))
            .expect("typed Phase 4 export input has the fixed width");
        lsb0_bits_to_bytes(&outputs)
    }

    /// Returns metrics derived from the finalized IR.
    pub const fn metrics(&self) -> BooleanCircuitMetricsV1 {
        self.circuit.metrics()
    }

    /// Returns the Phase 4 export IR identity.
    pub const fn benchmark_component_digest(&self) -> Phase4PrivateOutputExportCoreDigest32V1 {
        Phase4PrivateOutputExportCoreDigest32V1(self.circuit.digest())
    }

    /// Returns exact canonical IR bytes.
    pub fn canonical_encoding(&self) -> &[u8] {
        self.circuit.canonical_encoding()
    }

    /// Returns metrics derived from the canonical schedule.
    pub const fn schedule_metrics(&self) -> ProvisionalScheduleMetricsV1 {
        self.schedule.metrics()
    }

    /// Returns the Phase 4 export schedule identity.
    pub const fn benchmark_schedule_digest(&self) -> Phase4PrivateOutputExportScheduleDigest32V1 {
        Phase4PrivateOutputExportScheduleDigest32V1(self.schedule.digest())
    }

    /// Returns exact canonical schedule bytes.
    pub fn canonical_schedule_encoding(&self) -> &[u8] {
        self.schedule.canonical_encoding()
    }
}

/// Compiles the joint-coin Phase 4 activation private-output benchmark circuit.
pub fn compile_phase4_private_output_activation_core_v1() -> Phase4PrivateOutputActivationCoreV1 {
    let mut builder = CircuitBuilder::new(ACTIVATION_INPUT_BITS)
        .expect("Phase 4 activation circuit has fixed nonzero inputs");
    let inputs = builder.input_bits();
    let deriver_a = ActivationRoleInputBitsV1 {
        y_client: field_bits(&inputs, 0),
        y_server: field_bits(&inputs, 1),
        tau_client: field_bits(&inputs, 2),
        tau_server: field_bits(&inputs, 3),
    };
    let deriver_a_client_coin = field_bits(&inputs, 4);
    let deriver_a_signing_worker_coin = field_bits(&inputs, 5);
    let deriver_b = ActivationRoleInputBitsV1 {
        y_client: field_bits(&inputs, 6),
        y_server: field_bits(&inputs, 7),
        tau_client: field_bits(&inputs, 8),
        tau_server: field_bits(&inputs, 9),
    };
    let deriver_b_client_coin = field_bits(&inputs, 10);
    let deriver_b_signing_worker_coin = field_bits(&inputs, 11);

    let (x_client_base, x_signing_worker_base) =
        activation_base_output_bits(&mut builder, deriver_a, deriver_b);
    let client_mask = add_mod_l_bits(&mut builder, deriver_a_client_coin, deriver_b_client_coin);
    let signing_worker_mask = add_mod_l_bits(
        &mut builder,
        deriver_a_signing_worker_coin,
        deriver_b_signing_worker_coin,
    );
    let deriver_b_client_share = subtract_mod_l_bits(&mut builder, x_client_base, client_mask);
    let deriver_b_signing_worker_share =
        subtract_mod_l_bits(&mut builder, x_signing_worker_base, signing_worker_mask);

    let mut outputs = Vec::with_capacity(ACTIVATION_OUTPUT_BITS);
    outputs.extend_from_slice(&client_mask);
    outputs.extend_from_slice(&signing_worker_mask);
    outputs.extend_from_slice(&deriver_b_client_share);
    outputs.extend_from_slice(&deriver_b_signing_worker_share);
    let circuit = builder
        .finish_phase4_private_output_activation_core(outputs)
        .expect("Phase 4 activation topology and schemas are fixed");
    let schedule = CanonicalLivenessScheduleV1::derive(&circuit);
    Phase4PrivateOutputActivationCoreV1 { circuit, schedule }
}

/// Compiles the joint-coin Phase 4 export private-output benchmark circuit.
pub fn compile_phase4_private_output_export_core_v1() -> Phase4PrivateOutputExportCoreV1 {
    let mut builder = CircuitBuilder::new(EXPORT_INPUT_BITS)
        .expect("Phase 4 export circuit has fixed nonzero inputs");
    let inputs = builder.input_bits();
    let deriver_a = ExportRoleInputBitsV1 {
        y_client: field_bits(&inputs, 0),
        y_server: field_bits(&inputs, 1),
    };
    let deriver_a_coin = field_bits(&inputs, 2);
    let deriver_b = ExportRoleInputBitsV1 {
        y_client: field_bits(&inputs, 3),
        y_server: field_bits(&inputs, 4),
    };
    let deriver_b_coin = field_bits(&inputs, 5);

    let seed = export_seed_bits(&mut builder, deriver_a, deriver_b);
    let mask =
        super::add256::wrapping_add_le_256_bits(&mut builder, deriver_a_coin, deriver_b_coin);
    let deriver_b_share = wrapping_subtract_le_256_bits(&mut builder, seed, mask);

    let mut outputs = Vec::with_capacity(EXPORT_OUTPUT_BITS);
    outputs.extend_from_slice(&mask);
    outputs.extend_from_slice(&deriver_b_share);
    let circuit = builder
        .finish_phase4_private_output_export_core(outputs)
        .expect("Phase 4 export topology and schemas are fixed");
    let schedule = CanonicalLivenessScheduleV1::derive(&circuit);
    Phase4PrivateOutputExportCoreV1 { circuit, schedule }
}

pub(crate) fn phase4_activation_input_bits(
    inputs: &PublicSyntheticPhase4ActivationInputsV1,
) -> Vec<bool> {
    input_bytes_to_lsb0_bits(&inputs.canonical_input_bytes_v1())
}

pub(crate) fn phase4_export_input_bits(inputs: &PublicSyntheticPhase4ExportInputsV1) -> Vec<bool> {
    input_bytes_to_lsb0_bits(&inputs.canonical_input_bytes_v1())
}

fn validate_scalar_coin(
    bytes: [u8; FIELD_BYTES],
) -> Result<[u8; FIELD_BYTES], PublicSyntheticPhase4ScalarCoinErrorV1> {
    if Option::<Scalar>::from(Scalar::from_canonical_bytes(bytes)).is_none() {
        return Err(PublicSyntheticPhase4ScalarCoinErrorV1);
    }
    Ok(bytes)
}
