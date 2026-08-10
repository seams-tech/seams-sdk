//! Distinct Ed25519 lane-materialization circuit family.
//!
//! Each Deriver supplies only its role-local source shares and a
//! Yao-produced offset share.  Outputs remain role-separated holder and
//! SigningWorker shares; no seed, root, or combined scalar is represented.

#[cfg(test)]
use curve25519_dalek::scalar::Scalar;

use super::families::field_bits;
#[cfg(test)]
use super::families::{input_bytes_to_lsb0_bits, lsb0_bits_to_32_bytes};
use super::ir::{CanonicalBooleanCircuitV1, CircuitBuilder};
use super::scalar::add_mod_l_bits;
use super::schedule::{CanonicalLivenessScheduleV1, ProvisionalScheduleMetricsV1};
use super::BooleanCircuitMetricsV1;

/// Lane-materialization input schema.  Offset shares are sampled by the
/// circuit's Yao functionality and are never supplied by a client request.
pub const LANE_MATERIALIZATION_INPUT_SCHEMA_V1: &str =
    "seams/router-ab/ed25519-yao/lane_materialization/input/v1:a.source_holder_share[32]:canonical-l,a.source_signing_worker_share[32]:canonical-l,a.offset_share[32]:canonical-l,b.source_holder_share[32]:canonical-l,b.source_signing_worker_share[32]:canonical-l,b.offset_share[32]:canonical-l:field-byte-bit-lsb0:role-local-offset";
/// Lane-materialization output schema in fixed Deriver A then Deriver B order.
pub const LANE_MATERIALIZATION_OUTPUT_SCHEMA_V1: &str =
    "seams/router-ab/ed25519-yao/lane_materialization/output/v1:a.target_holder_share[32]:canonical-l,a.target_signing_worker_share[32]:canonical-l,b.target_holder_share[32]:canonical-l,b.target_signing_worker_share[32]:canonical-l:field-byte-bit-lsb0:role-separated:no-seed:no-root:no-base";

const FIELD_BITS: usize = 256;
const INPUT_BITS: u32 = 6 * FIELD_BITS as u32;
const OUTPUT_BITS: usize = 4 * FIELD_BITS;

/// Role-local canonical lane input tuple for the test-only synthetic oracle.
#[cfg(test)]
#[derive(Debug, Clone, Copy)]
pub struct PublicSyntheticLaneMaterializationInputsV1 {
    /// Deriver A source holder share.
    pub a_source_holder_share: [u8; 32],
    /// Deriver A source SigningWorker share.
    pub a_source_signing_worker_share: [u8; 32],
    /// Deriver A offset share.
    pub a_offset_share: [u8; 32],
    /// Deriver B source holder share.
    pub b_source_holder_share: [u8; 32],
    /// Deriver B source SigningWorker share.
    pub b_source_signing_worker_share: [u8; 32],
    /// Deriver B offset share.
    pub b_offset_share: [u8; 32],
}

#[cfg(test)]
impl PublicSyntheticLaneMaterializationInputsV1 {
    /// Validates all role-local scalar fields once at the harness boundary.
    pub fn new(
        a_source_holder_share: [u8; 32],
        a_source_signing_worker_share: [u8; 32],
        a_offset_share: [u8; 32],
        b_source_holder_share: [u8; 32],
        b_source_signing_worker_share: [u8; 32],
        b_offset_share: [u8; 32],
    ) -> Result<Self, LaneMaterializationInputErrorV1> {
        for value in [
            a_source_holder_share,
            a_source_signing_worker_share,
            a_offset_share,
            b_source_holder_share,
            b_source_signing_worker_share,
            b_offset_share,
        ] {
            if Option::<Scalar>::from(Scalar::from_canonical_bytes(value)).is_none() {
                return Err(LaneMaterializationInputErrorV1);
            }
        }
        Ok(Self {
            a_source_holder_share,
            a_source_signing_worker_share,
            a_offset_share,
            b_source_holder_share,
            b_source_signing_worker_share,
            b_offset_share,
        })
    }

    fn canonical_input_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(INPUT_BITS as usize / 8);
        for value in [
            self.a_source_holder_share,
            self.a_source_signing_worker_share,
            self.a_offset_share,
            self.b_source_holder_share,
            self.b_source_signing_worker_share,
            self.b_offset_share,
        ] {
            bytes.extend_from_slice(&value);
        }
        bytes
    }
}

/// Invalid canonical scalar at the test-only synthetic boundary.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LaneMaterializationInputErrorV1;

/// Role-separated target shares from one synthetic circuit evaluation.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicSyntheticLaneMaterializationOutputsV1 {
    /// Deriver A target holder share.
    pub a_target_holder_share: [u8; 32],
    /// Deriver A target SigningWorker share.
    pub a_target_signing_worker_share: [u8; 32],
    /// Deriver B target holder share.
    pub b_target_holder_share: [u8; 32],
    /// Deriver B target SigningWorker share.
    pub b_target_signing_worker_share: [u8; 32],
}

/// Distinct lane-materialization circuit IR digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LaneMaterializationCoreDigest32V1([u8; 32]);

impl LaneMaterializationCoreDigest32V1 {
    /// Exposes public digest bytes for fixture generation.
    pub const fn expose_public_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// Distinct lane-materialization liveness schedule digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LaneMaterializationScheduleDigest32V1([u8; 32]);

impl LaneMaterializationScheduleDigest32V1 {
    /// Exposes public digest bytes for fixture generation.
    pub const fn expose_public_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// Compiled lane-materialization circuit and its canonical schedule.
pub struct LaneMaterializationCoreV1 {
    circuit: CanonicalBooleanCircuitV1,
    schedule: CanonicalLivenessScheduleV1,
}

impl LaneMaterializationCoreV1 {
    /// Evaluates role-separated outputs over test-only synthetic shares.
    #[cfg(test)]
    pub fn evaluate_public_synthetic(
        &self,
        inputs: &PublicSyntheticLaneMaterializationInputsV1,
    ) -> PublicSyntheticLaneMaterializationOutputsV1 {
        let outputs = self
            .schedule
            .evaluate(&input_bits(inputs))
            .expect("typed lane input has fixed width");
        PublicSyntheticLaneMaterializationOutputsV1 {
            a_target_holder_share: lsb0_bits_to_32_bytes(&outputs[..FIELD_BITS]),
            a_target_signing_worker_share: lsb0_bits_to_32_bytes(
                &outputs[FIELD_BITS..2 * FIELD_BITS],
            ),
            b_target_holder_share: lsb0_bits_to_32_bytes(&outputs[2 * FIELD_BITS..3 * FIELD_BITS]),
            b_target_signing_worker_share: lsb0_bits_to_32_bytes(&outputs[3 * FIELD_BITS..]),
        }
    }

    /// Returns circuit metrics.
    pub const fn metrics(&self) -> BooleanCircuitMetricsV1 {
        self.circuit.metrics()
    }

    /// Returns the canonical lane-materialization IR digest.
    pub const fn benchmark_component_digest(&self) -> LaneMaterializationCoreDigest32V1 {
        LaneMaterializationCoreDigest32V1(self.circuit.digest())
    }

    /// Returns canonical circuit bytes.
    pub fn canonical_encoding(&self) -> &[u8] {
        self.circuit.canonical_encoding()
    }

    /// Returns liveness schedule metrics.
    pub const fn schedule_metrics(&self) -> ProvisionalScheduleMetricsV1 {
        self.schedule.metrics()
    }

    /// Returns the canonical lane schedule digest.
    pub const fn benchmark_schedule_digest(&self) -> LaneMaterializationScheduleDigest32V1 {
        LaneMaterializationScheduleDigest32V1(self.schedule.digest())
    }

    /// Returns canonical schedule bytes.
    pub fn canonical_schedule_encoding(&self) -> &[u8] {
        self.schedule.canonical_encoding()
    }
}

/// Compiles the separate `lane_materialization` circuit family.
pub fn compile_lane_materialization_v1() -> LaneMaterializationCoreV1 {
    let mut builder = CircuitBuilder::new(INPUT_BITS).expect("lane input width is fixed");
    let inputs = builder.input_bits();
    let a_holder = field_bits(&inputs, 0);
    let a_worker = field_bits(&inputs, 1);
    let a_offset = field_bits(&inputs, 2);
    let b_holder = field_bits(&inputs, 3);
    let b_worker = field_bits(&inputs, 4);
    let b_offset = field_bits(&inputs, 5);
    let a_target_holder = add_mod_l_bits(&mut builder, a_holder, a_offset);
    let a_target_worker_offset = add_mod_l_bits(&mut builder, a_offset, a_offset);
    let a_target_worker = add_mod_l_bits(&mut builder, a_worker, a_target_worker_offset);
    let b_target_holder = add_mod_l_bits(&mut builder, b_holder, b_offset);
    let b_target_worker_offset = add_mod_l_bits(&mut builder, b_offset, b_offset);
    let b_target_worker = add_mod_l_bits(&mut builder, b_worker, b_target_worker_offset);
    let mut outputs = Vec::with_capacity(OUTPUT_BITS);
    outputs.extend_from_slice(&a_target_holder);
    outputs.extend_from_slice(&a_target_worker);
    outputs.extend_from_slice(&b_target_holder);
    outputs.extend_from_slice(&b_target_worker);
    let circuit = builder
        .finish_lane_materialization_core(outputs)
        .expect("lane circuit topology and schemas are fixed");
    let schedule = CanonicalLivenessScheduleV1::derive(&circuit);
    LaneMaterializationCoreV1 { circuit, schedule }
}

#[cfg(test)]
fn input_bits(inputs: &PublicSyntheticLaneMaterializationInputsV1) -> Vec<bool> {
    input_bytes_to_lsb0_bits(&inputs.canonical_input_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lane_outputs_preserve_additive_relation_without_combining_inputs_in_circuit() {
        let inputs = PublicSyntheticLaneMaterializationInputsV1::new(
            Scalar::from(11_u64).to_bytes(),
            Scalar::from(15_u64).to_bytes(),
            Scalar::from(2_u64).to_bytes(),
            Scalar::from(3_u64).to_bytes(),
            Scalar::from(7_u64).to_bytes(),
            Scalar::from(5_u64).to_bytes(),
        )
        .expect("canonical lane inputs");
        let circuit = compile_lane_materialization_v1();
        let outputs = circuit.evaluate_public_synthetic(&inputs);
        let holder = Scalar::from_canonical_bytes(outputs.a_target_holder_share)
            .expect("A holder share")
            + Scalar::from_canonical_bytes(outputs.b_target_holder_share).expect("B holder share");
        let worker = Scalar::from_canonical_bytes(outputs.a_target_signing_worker_share)
            .expect("A worker share")
            + Scalar::from_canonical_bytes(outputs.b_target_signing_worker_share)
                .expect("B worker share");
        assert_eq!(holder + holder - worker, Scalar::from(6_u64));
        println!(
            "lane_circuit_digest={:02x?} lane_schedule_digest={:02x?}",
            circuit.benchmark_component_digest().expose_public_bytes(),
            circuit.benchmark_schedule_digest().expose_public_bytes()
        );
    }
}
