//! Role-separated Phase 4 passive ceremony composition.

use core::fmt;

use sha2::{Digest, Sha256};
#[cfg(any(
    test,
    feature = "passive-benchmark",
    feature = "phase9-role-benchmark",
    feature = "local-protocol"
))]
use zeroize::Zeroize;
use zeroize::Zeroizing;

use super::ot::OtError;
#[cfg(any(
    test,
    feature = "passive-benchmark",
    feature = "phase9-role-benchmark",
    feature = "local-protocol"
))]
use super::ot::OtSessionId;
use super::roles::{
    ActivationSessionBinding, ExportSessionBinding, RoleBoundaryError, TranscriptDigest32,
};
use super::runtime::CircuitRunError;
use super::{EvaluatorWire, Garbler, GarblerWire, SessionDomain, WireValue, LABEL_BYTES};

const ACTIVATION_FAMILY_TAG: u8 = 0x93;
const EXPORT_FAMILY_TAG: u8 = 0x94;
const TRANSCRIPT_START_DOMAIN: &[u8] = b"seams:ed25519-yao:phase4:transcript-start:v1";
#[cfg(any(
    test,
    feature = "passive-benchmark",
    feature = "phase9-role-benchmark",
    feature = "local-protocol"
))]
const TRANSCRIPT_STEP_DOMAIN: &[u8] = b"seams:ed25519-yao:phase4:transcript-step:v1";
#[cfg(any(
    test,
    feature = "passive-benchmark",
    feature = "phase9-role-benchmark",
    feature = "local-protocol"
))]
const OT_DOMAIN: &[u8] = b"seams:ed25519-yao:phase4:ot-domain:v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Phase4CeremonyError {
    Randomness,
    GateDomain,
    Ot(OtError),
    Role(RoleBoundaryError),
    Circuit(CircuitRunError),
}

impl fmt::Display for Phase4CeremonyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Phase 4 passive ceremony failed")
    }
}

impl From<OtError> for Phase4CeremonyError {
    fn from(error: OtError) -> Self {
        Self::Ot(error)
    }
}

impl From<RoleBoundaryError> for Phase4CeremonyError {
    fn from(error: RoleBoundaryError) -> Self {
        Self::Role(error)
    }
}

impl From<CircuitRunError> for Phase4CeremonyError {
    fn from(error: CircuitRunError) -> Self {
        Self::Circuit(error)
    }
}

impl From<getrandom::Error> for Phase4CeremonyError {
    fn from(_: getrandom::Error) -> Self {
        Self::Randomness
    }
}

pub(super) struct PreparedLabels {
    pub(super) garbler_inputs: Vec<GarblerWire>,
    pub(super) direct_labels: Zeroizing<Vec<u8>>,
    pub(super) ot_pairs: Vec<([u8; LABEL_BYTES], [u8; LABEL_BYTES])>,
}

pub(super) fn prepare_labels(
    garbler: &Garbler,
    a_input_bytes: &[u8],
    input_bits_per_role: usize,
) -> Result<PreparedLabels, Phase4CeremonyError> {
    if a_input_bytes.len() * 8 != input_bits_per_role {
        return Err(Phase4CeremonyError::Circuit(CircuitRunError::InputCount));
    }
    let total_inputs = input_bits_per_role
        .checked_mul(2)
        .ok_or(Phase4CeremonyError::Circuit(CircuitRunError::InputCount))?;
    let garbler_inputs = GarblerWire::random_batch(total_inputs)?;
    let mut direct_labels = Zeroizing::new(Vec::with_capacity(input_bits_per_role * LABEL_BYTES));
    let mut index = 0_usize;
    while index < input_bits_per_role {
        garbler
            .encode(
                &garbler_inputs[index],
                packed_wire_value(a_input_bytes, index),
            )
            .append_secret_bytes(&mut direct_labels);
        index += 1;
    }
    let mut ot_pairs = Vec::with_capacity(input_bits_per_role);
    while index < total_inputs {
        ot_pairs.push(garbler.encoded_pair(&garbler_inputs[index]));
        index += 1;
    }
    Ok(PreparedLabels {
        garbler_inputs,
        direct_labels,
        ot_pairs,
    })
}

pub(super) fn evaluator_inputs(
    direct_labels: &[u8],
    selected_labels: &[[u8; LABEL_BYTES]],
    input_bits_per_role: usize,
) -> Result<Vec<EvaluatorWire>, Phase4CeremonyError> {
    if direct_labels.len() != input_bits_per_role * LABEL_BYTES
        || selected_labels.len() != input_bits_per_role
    {
        return Err(Phase4CeremonyError::Circuit(CircuitRunError::InputCount));
    }
    let mut inputs = Vec::with_capacity(input_bits_per_role * 2);
    for bytes in direct_labels.chunks_exact(LABEL_BYTES) {
        let active = bytes
            .try_into()
            .map_err(|_| Phase4CeremonyError::Circuit(CircuitRunError::InputCount))?;
        inputs.push(EvaluatorWire::from_secret_bytes(active));
    }
    for active in selected_labels {
        inputs.push(EvaluatorWire::from_secret_bytes(*active));
    }
    Ok(inputs)
}

fn packed_wire_value(bytes: &[u8], index: usize) -> WireValue {
    WireValue::from_secret_bit(bytes[index / 8] >> (index % 8))
}

pub(super) fn protocol_domain(value: u64) -> Result<SessionDomain, Phase4CeremonyError> {
    SessionDomain::from_protocol_value(value).ok_or(Phase4CeremonyError::GateDomain)
}

pub(super) fn activation_transcript_start(
    binding: ActivationSessionBinding,
) -> Result<TranscriptDigest32, Phase4CeremonyError> {
    transcript_start(
        ACTIVATION_FAMILY_TAG,
        binding.session_bytes(),
        binding.circuit_digest().as_bytes(),
        binding.schedule_digest().as_bytes(),
    )
}

pub(super) fn export_transcript_start(
    binding: ExportSessionBinding,
) -> Result<TranscriptDigest32, Phase4CeremonyError> {
    transcript_start(
        EXPORT_FAMILY_TAG,
        binding.session_bytes(),
        binding.circuit_digest().as_bytes(),
        binding.schedule_digest().as_bytes(),
    )
}

fn transcript_start(
    family: u8,
    session: &[u8; 32],
    circuit: &[u8; 32],
    schedule: &[u8; 32],
) -> Result<TranscriptDigest32, Phase4CeremonyError> {
    let digest: [u8; 32] = Sha256::new()
        .chain_update(TRANSCRIPT_START_DOMAIN)
        .chain_update([family])
        .chain_update(session)
        .chain_update(circuit)
        .chain_update(schedule)
        .finalize()
        .into();
    TranscriptDigest32::new(digest).map_err(Into::into)
}

#[cfg(any(
    test,
    feature = "passive-benchmark",
    feature = "phase9-role-benchmark",
    feature = "local-protocol"
))]
pub(super) fn advance_transcript(
    predecessor: TranscriptDigest32,
    message: &[u8],
) -> Result<TranscriptDigest32, Phase4CeremonyError> {
    let digest: [u8; 32] = Sha256::new()
        .chain_update(TRANSCRIPT_STEP_DOMAIN)
        .chain_update(predecessor.as_bytes())
        .chain_update((message.len() as u64).to_be_bytes())
        .chain_update(message)
        .finalize()
        .into();
    TranscriptDigest32::new(digest).map_err(Into::into)
}

#[cfg(any(
    test,
    feature = "passive-benchmark",
    feature = "phase9-role-benchmark",
    feature = "local-protocol"
))]
pub(super) fn activation_ot_session(
    binding: ActivationSessionBinding,
) -> Result<OtSessionId, Phase4CeremonyError> {
    ot_session(
        ACTIVATION_FAMILY_TAG,
        binding.session_bytes(),
        binding.circuit_digest().as_bytes(),
        binding.schedule_digest().as_bytes(),
    )
}

#[cfg(any(
    test,
    feature = "passive-benchmark",
    feature = "phase9-role-benchmark",
    feature = "local-protocol"
))]
pub(super) fn export_ot_session(
    binding: ExportSessionBinding,
) -> Result<OtSessionId, Phase4CeremonyError> {
    ot_session(
        EXPORT_FAMILY_TAG,
        binding.session_bytes(),
        binding.circuit_digest().as_bytes(),
        binding.schedule_digest().as_bytes(),
    )
}

#[cfg(any(
    test,
    feature = "passive-benchmark",
    feature = "phase9-role-benchmark",
    feature = "local-protocol"
))]
fn ot_session(
    family: u8,
    session: &[u8; 32],
    circuit: &[u8; 32],
    schedule: &[u8; 32],
) -> Result<OtSessionId, Phase4CeremonyError> {
    let mut digest: [u8; 32] = Sha256::new()
        .chain_update(OT_DOMAIN)
        .chain_update([family])
        .chain_update(session)
        .chain_update(circuit)
        .chain_update(schedule)
        .finalize()
        .into();
    let result = OtSessionId::new(digest).map_err(Into::into);
    digest.zeroize();
    result
}
