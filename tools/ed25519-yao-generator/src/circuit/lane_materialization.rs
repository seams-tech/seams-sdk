//! Distinct Ed25519 lane-materialization circuit family.
//!
//! Each Deriver supplies only its role-local source shares and a
//! Yao-produced offset share.  Outputs remain role-separated holder and
//! SigningWorker shares; no seed, root, or combined scalar is represented.

#[cfg(test)]
use curve25519_dalek::scalar::Scalar;

use super::families::{activation_base_output_bits, field_bits, ActivationRoleInputBitsV1};
#[cfg(test)]
use super::families::{input_bytes_to_lsb0_bits, lsb0_bits_to_32_bytes};
use super::ir::{CanonicalBooleanCircuitV1, CircuitBuilder};
use super::scalar::add_mod_l_bits;
use super::schedule::{CanonicalLivenessScheduleV1, ProvisionalScheduleMetricsV1};
use super::BooleanCircuitMetricsV1;

/// Lane-materialization input schema.  Offset shares are sampled by the
/// circuit's Yao functionality and are never supplied by a client request.
pub const LANE_MATERIALIZATION_INPUT_SCHEMA_V1: &str =
    "seams/router-ab/ed25519-yao/lane_materialization/input/v1:a.y_client[32],a.y_server[32],a.tau_client[32]:canonical-l,a.tau_server[32]:canonical-l,a.holder_coin[32]:canonical-l,a.signing_worker_coin[32]:canonical-l,a.offset_share[32]:canonical-l,b.y_client[32],b.y_server[32],b.tau_client[32]:canonical-l,b.tau_server[32]:canonical-l,b.holder_coin[32]:canonical-l,b.signing_worker_coin[32]:canonical-l,b.offset_share[32]:canonical-l:field-byte-bit-lsb0:activation-base:role-local-offset";
/// Lane-materialization output schema in fixed Deriver A then Deriver B order.
pub const LANE_MATERIALIZATION_OUTPUT_SCHEMA_V1: &str =
    "seams/router-ab/ed25519-yao/lane_materialization/output/v1:a.target_holder_share[32]:canonical-l,a.target_signing_worker_share[32]:canonical-l,b.target_holder_share[32]:canonical-l,b.target_signing_worker_share[32]:canonical-l:field-byte-bit-lsb0:role-separated:no-seed:no-root:no-base";

const FIELD_BITS: usize = 256;
const INPUT_BITS: u32 = 14 * FIELD_BITS as u32;
const OUTPUT_BITS: usize = 4 * FIELD_BITS;

/// Role-local canonical lane input tuple for the test-only synthetic oracle.
#[cfg(test)]
#[derive(Debug, Clone, Copy)]
pub struct PublicSyntheticLaneMaterializationInputsV1 {
    pub a_y_client: [u8; 32],
    pub a_y_server: [u8; 32],
    pub a_tau_client: [u8; 32],
    pub a_tau_server: [u8; 32],
    pub a_holder_coin: [u8; 32],
    pub a_signing_worker_coin: [u8; 32],
    /// Deriver A offset share.
    pub a_offset_share: [u8; 32],
    pub b_y_client: [u8; 32],
    pub b_y_server: [u8; 32],
    pub b_tau_client: [u8; 32],
    pub b_tau_server: [u8; 32],
    pub b_holder_coin: [u8; 32],
    pub b_signing_worker_coin: [u8; 32],
    /// Deriver B offset share.
    pub b_offset_share: [u8; 32],
}

#[cfg(test)]
impl PublicSyntheticLaneMaterializationInputsV1 {
    /// Validates all role-local scalar fields once at the harness boundary.
    pub fn new(
        a_y_client: [u8; 32],
        a_y_server: [u8; 32],
        a_tau_client: [u8; 32],
        a_tau_server: [u8; 32],
        a_holder_coin: [u8; 32],
        a_signing_worker_coin: [u8; 32],
        a_offset_share: [u8; 32],
        b_y_client: [u8; 32],
        b_y_server: [u8; 32],
        b_tau_client: [u8; 32],
        b_tau_server: [u8; 32],
        b_holder_coin: [u8; 32],
        b_signing_worker_coin: [u8; 32],
        b_offset_share: [u8; 32],
    ) -> Result<Self, LaneMaterializationInputErrorV1> {
        for value in [
            a_tau_client,
            a_tau_server,
            a_holder_coin,
            a_signing_worker_coin,
            a_offset_share,
            b_tau_client,
            b_tau_server,
            b_holder_coin,
            b_signing_worker_coin,
            b_offset_share,
        ] {
            if Option::<Scalar>::from(Scalar::from_canonical_bytes(value)).is_none() {
                return Err(LaneMaterializationInputErrorV1);
            }
        }
        Ok(Self {
            a_y_client,
            a_y_server,
            a_tau_client,
            a_tau_server,
            a_holder_coin,
            a_signing_worker_coin,
            a_offset_share,
            b_y_client,
            b_y_server,
            b_tau_client,
            b_tau_server,
            b_holder_coin,
            b_signing_worker_coin,
            b_offset_share,
        })
    }

    fn canonical_input_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(INPUT_BITS as usize / 8);
        for value in [
            self.a_y_client,
            self.a_y_server,
            self.a_tau_client,
            self.a_tau_server,
            self.a_holder_coin,
            self.a_signing_worker_coin,
            self.a_offset_share,
            self.b_y_client,
            self.b_y_server,
            self.b_tau_client,
            self.b_tau_server,
            self.b_holder_coin,
            self.b_signing_worker_coin,
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
    let deriver_a = ActivationRoleInputBitsV1 {
        y_client: field_bits(&inputs, 0),
        y_server: field_bits(&inputs, 1),
        tau_client: field_bits(&inputs, 2),
        tau_server: field_bits(&inputs, 3),
    };
    let a_holder_coin = field_bits(&inputs, 4);
    let a_worker_coin = field_bits(&inputs, 5);
    let a_offset = field_bits(&inputs, 6);
    let deriver_b = ActivationRoleInputBitsV1 {
        y_client: field_bits(&inputs, 7),
        y_server: field_bits(&inputs, 8),
        tau_client: field_bits(&inputs, 9),
        tau_server: field_bits(&inputs, 10),
    };
    let b_holder_coin = field_bits(&inputs, 11);
    let b_worker_coin = field_bits(&inputs, 12);
    let b_offset = field_bits(&inputs, 13);
    let (holder_base, worker_base) =
        activation_base_output_bits(&mut builder, deriver_a, deriver_b);
    let holder_mask = add_mod_l_bits(&mut builder, a_holder_coin, b_holder_coin);
    let worker_mask = add_mod_l_bits(&mut builder, a_worker_coin, b_worker_coin);
    let b_holder_base = super::scalar::subtract_mod_l_bits(&mut builder, holder_base, holder_mask);
    let b_worker_base = super::scalar::subtract_mod_l_bits(&mut builder, worker_base, worker_mask);
    let a_holder = holder_mask;
    let a_worker = worker_mask;
    let a_target_holder = add_mod_l_bits(&mut builder, a_holder, a_offset);
    let a_target_worker_offset = add_mod_l_bits(&mut builder, a_offset, a_offset);
    let a_target_worker = add_mod_l_bits(&mut builder, a_worker, a_target_worker_offset);
    let b_target_holder = add_mod_l_bits(&mut builder, b_holder_base, b_offset);
    let b_target_worker_offset = add_mod_l_bits(&mut builder, b_offset, b_offset);
    let b_target_worker = add_mod_l_bits(&mut builder, b_worker_base, b_target_worker_offset);
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
    use sha2::{Digest, Sha512};

    #[test]
    fn lane_outputs_recompute_the_activation_base_and_preserve_its_relation() {
        let y = [0x42_u8; 32];
        let inputs = PublicSyntheticLaneMaterializationInputsV1::new(
            y,
            [0_u8; 32],
            Scalar::from(2_u64).to_bytes(),
            Scalar::from(3_u64).to_bytes(),
            Scalar::from(11_u64).to_bytes(),
            Scalar::from(13_u64).to_bytes(),
            Scalar::from(17_u64).to_bytes(),
            [0_u8; 32],
            [0_u8; 32],
            Scalar::from(5_u64).to_bytes(),
            Scalar::from(7_u64).to_bytes(),
            Scalar::from(19_u64).to_bytes(),
            Scalar::from(23_u64).to_bytes(),
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
        let digest = Sha512::digest(y);
        let mut clamped = [0_u8; 32];
        clamped.copy_from_slice(&digest[..32]);
        clamped[0] &= 248;
        clamped[31] &= 63;
        clamped[31] |= 64;
        assert_eq!(
            holder + holder - worker,
            Scalar::from_bytes_mod_order(clamped)
        );
        println!(
            "lane_circuit_digest={:02x?} lane_schedule_digest={:02x?}",
            circuit.benchmark_component_digest().expose_public_bytes(),
            circuit.benchmark_schedule_digest().expose_public_bytes()
        );
    }
}
