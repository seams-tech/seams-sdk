use core::fmt;
use std::sync::OnceLock;

use sha2::{Digest, Sha256};

use super::GateOrdinal;

const SCHEDULE_MAGIC: &[u8; 8] = b"EYAOSC01";
const HEADER_BYTES: usize = 58;
const SLOT_WIDTH: usize = 2;
const RECORD_BYTES: usize = 1 + 3 * SLOT_WIDTH;
const XOR_OPCODE: u8 = 1;
const AND_OPCODE: u8 = 2;
const INV_OPCODE: u8 = 3;
const MAX_SLOT_COUNT: usize = 6_785;

#[cfg(test)]
const ACTIVATION_SCHEDULE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/artifacts/passive-benchmark-v1/activation.schedule.bin"
));
#[cfg(test)]
const EXPORT_SCHEDULE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/artifacts/passive-benchmark-v1/export.schedule.bin"
));
const PHASE4_ACTIVATION_SCHEDULE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/artifacts/passive-benchmark-v1/activation-private-output.schedule.bin"
));
const PHASE4_EXPORT_SCHEDULE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/artifacts/passive-benchmark-v1/export-private-output.schedule.bin"
));

#[cfg(test)]
static ACTIVATION_VALIDATION: OnceLock<Result<ValidatedSchedule<'static>, ScheduleError>> =
    OnceLock::new();
#[cfg(test)]
static EXPORT_VALIDATION: OnceLock<Result<ValidatedSchedule<'static>, ScheduleError>> =
    OnceLock::new();
static PHASE4_ACTIVATION_VALIDATION: OnceLock<Result<ValidatedSchedule<'static>, ScheduleError>> =
    OnceLock::new();
static PHASE4_EXPORT_VALIDATION: OnceLock<Result<ValidatedSchedule<'static>, ScheduleError>> =
    OnceLock::new();

#[cfg(test)]
const ACTIVATION_SPEC: FixedScheduleSpec = FixedScheduleSpec {
    component: 0x91,
    ir_digest: [
        0x74, 0x7f, 0xa6, 0xf1, 0x81, 0x5e, 0x3a, 0x0c, 0x70, 0xf0, 0x07, 0x7f, 0xfc, 0x10, 0x50,
        0x88, 0x82, 0xf3, 0x21, 0xad, 0x6e, 0x7b, 0xb4, 0x22, 0xf4, 0xee, 0xf6, 0x95, 0xa8, 0x53,
        0xb5, 0xa5,
    ],
    schedule_digest: [
        0xe0, 0xf9, 0xdf, 0xb3, 0xf3, 0xb8, 0x5e, 0xab, 0x28, 0xfb, 0xab, 0x81, 0x78, 0x8e, 0x0e,
        0xfe, 0xa2, 0x5d, 0xac, 0x7c, 0x8d, 0xe2, 0x07, 0xaf, 0x8c, 0xe9, 0xe5, 0x75, 0x67, 0xc6,
        0xad, 0x25,
    ],
    input_count: 2_048,
    gate_count: 367_240,
    output_count: 512,
    slot_count: 5_761,
    xor_count: 294_021,
    and_count: 62_716,
    inv_count: 10_503,
};

#[cfg(test)]
const EXPORT_SPEC: FixedScheduleSpec = FixedScheduleSpec {
    component: 0x92,
    ir_digest: [
        0x3c, 0xc9, 0x56, 0x94, 0xe0, 0x19, 0x66, 0x64, 0x2d, 0xb7, 0xea, 0xed, 0x9d, 0x68, 0xa4,
        0x11, 0x6c, 0x66, 0xbc, 0x4d, 0x72, 0xf1, 0x49, 0x08, 0xd0, 0xd3, 0xb5, 0xe2, 0x5e, 0xe7,
        0x98, 0x38,
    ],
    schedule_digest: [
        0xbb, 0x4b, 0x0b, 0x1d, 0xe8, 0x7b, 0xaa, 0x1b, 0xf7, 0xb1, 0x90, 0xc8, 0xc5, 0x75, 0x38,
        0xa6, 0x73, 0x67, 0x09, 0x14, 0x83, 0xa4, 0xcb, 0x08, 0xab, 0xc1, 0xa2, 0x39, 0x2f, 0x55,
        0xb0, 0x71,
    ],
    input_count: 1_024,
    gate_count: 4_584,
    output_count: 256,
    slot_count: 1_025,
    xor_count: 3_819,
    and_count: 765,
    inv_count: 0,
};

const PHASE4_ACTIVATION_SPEC: FixedScheduleSpec = FixedScheduleSpec {
    component: 0x93,
    ir_digest: [
        0x65, 0xb0, 0x01, 0xc2, 0xf9, 0x4d, 0xe2, 0x7e, 0xe8, 0xcb, 0x9f, 0x0c, 0x07, 0x73, 0xfb,
        0xe5, 0x42, 0x58, 0xce, 0xab, 0x43, 0xd1, 0x83, 0x17, 0x4b, 0xee, 0x71, 0x0e, 0xe8, 0xaa,
        0x54, 0x6d,
    ],
    schedule_digest: [
        0xfb, 0x04, 0xa1, 0x39, 0xde, 0xc1, 0x5e, 0x9d, 0x52, 0xe4, 0x96, 0xdc, 0x4f, 0xc0, 0x11,
        0xcf, 0x88, 0x5c, 0x8f, 0x3f, 0x6f, 0x2d, 0x18, 0xbf, 0x38, 0x60, 0xe4, 0x60, 0x71, 0xf0,
        0xe6, 0x9a,
    ],
    input_count: 3_072,
    gate_count: 382_050,
    output_count: 1_024,
    slot_count: 6_785,
    xor_count: 304_223,
    and_count: 65_780,
    inv_count: 12_047,
};

const PHASE4_EXPORT_SPEC: FixedScheduleSpec = FixedScheduleSpec {
    component: 0x94,
    ir_digest: [
        0x31, 0xb0, 0x3d, 0x13, 0xe4, 0x1a, 0x72, 0x83, 0x42, 0xae, 0xdc, 0xe7, 0xaf, 0x40, 0xf5,
        0x40, 0x5d, 0xc5, 0x98, 0xd2, 0x8e, 0x78, 0x4d, 0xe4, 0x4d, 0x80, 0x44, 0xdb, 0x9c, 0x60,
        0x1a, 0x0c,
    ],
    schedule_digest: [
        0x66, 0xdd, 0xc2, 0x0f, 0x84, 0x07, 0xe3, 0x69, 0xb7, 0x4f, 0x2a, 0x21, 0x02, 0x87, 0xd2,
        0x13, 0x1e, 0x78, 0xc7, 0x52, 0x5f, 0x47, 0xfc, 0x82, 0x9c, 0x57, 0xf6, 0x41, 0x8b, 0x0d,
        0x97, 0xd0,
    ],
    input_count: 1_536,
    gate_count: 7_900,
    output_count: 512,
    slot_count: 1_537,
    xor_count: 6_365,
    and_count: 1_275,
    inv_count: 260,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FixedScheduleSpec {
    component: u8,
    ir_digest: [u8; 32],
    schedule_digest: [u8; 32],
    input_count: u32,
    gate_count: u32,
    output_count: u32,
    slot_count: u32,
    xor_count: u32,
    and_count: u32,
    inv_count: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ScheduleError {
    Length,
    Magic,
    Component,
    SlotWidth,
    IrDigest,
    InputCount,
    GateCount,
    OutputCount,
    SlotCount,
    Opcode,
    SlotBound,
    InversionOperands,
    GateClassCounts,
    DuplicateOutput,
    Digest,
}

impl fmt::Display for ScheduleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid passive benchmark schedule: {self:?}")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum GateRecord {
    Xor {
        left: usize,
        right: usize,
        output: usize,
    },
    And {
        ordinal: GateOrdinal,
        left: usize,
        right: usize,
        output: usize,
    },
    Invert {
        input: usize,
        output: usize,
    },
}

#[derive(Debug)]
pub(super) struct ValidatedSchedule<'a> {
    spec: FixedScheduleSpec,
    records: &'a [u8],
    outputs: &'a [u8],
}

impl ValidatedSchedule<'_> {
    pub(super) const fn input_count(&self) -> usize {
        self.spec.input_count as usize
    }

    pub(super) const fn gate_count(&self) -> usize {
        self.spec.gate_count as usize
    }

    pub(super) const fn output_count(&self) -> usize {
        self.spec.output_count as usize
    }

    pub(super) const fn slot_count(&self) -> usize {
        self.spec.slot_count as usize
    }

    pub(super) const fn and_count(&self) -> usize {
        self.spec.and_count as usize
    }

    #[cfg(test)]
    pub(super) fn gates(&self) -> GateRecords<'_> {
        GateRecords {
            bytes: self.records,
            next: 0,
            total: self.gate_count(),
        }
    }

    pub(super) fn gate(&self, index: usize) -> Option<GateRecord> {
        if index >= self.gate_count() {
            return None;
        }
        Some(decode_gate_record(self.records, index))
    }

    pub(super) fn output_slots(&self) -> OutputSlots<'_> {
        OutputSlots {
            bytes: self.outputs,
            next: 0,
            total: self.output_count(),
        }
    }
}

#[cfg(test)]
pub(super) struct GateRecords<'a> {
    bytes: &'a [u8],
    next: usize,
    total: usize,
}

#[cfg(test)]
impl Iterator for GateRecords<'_> {
    type Item = GateRecord;

    fn next(&mut self) -> Option<Self::Item> {
        if self.next == self.total {
            return None;
        }
        let record = decode_gate_record(self.bytes, self.next);
        self.next += 1;
        Some(record)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.total - self.next;
        (remaining, Some(remaining))
    }
}

#[cfg(test)]
impl ExactSizeIterator for GateRecords<'_> {}

fn decode_gate_record(records: &[u8], index: usize) -> GateRecord {
    let offset = index * RECORD_BYTES;
    let bytes = &records[offset..offset + RECORD_BYTES];
    let ordinal = GateOrdinal::from_schedule_index(index as u64)
        .expect("validated schedule gate count fits the tweak domain");
    let left = read_slot(&bytes[1..3]);
    let right = read_slot(&bytes[3..5]);
    let output = read_slot(&bytes[5..7]);
    match bytes[0] {
        XOR_OPCODE => GateRecord::Xor {
            left,
            right,
            output,
        },
        AND_OPCODE => GateRecord::And {
            ordinal,
            left,
            right,
            output,
        },
        INV_OPCODE => GateRecord::Invert {
            input: left,
            output,
        },
        _ => unreachable!("validated schedule contains only known opcodes"),
    }
}

pub(super) struct OutputSlots<'a> {
    bytes: &'a [u8],
    next: usize,
    total: usize,
}

impl Iterator for OutputSlots<'_> {
    type Item = usize;

    fn next(&mut self) -> Option<Self::Item> {
        if self.next == self.total {
            return None;
        }
        let offset = self.next * SLOT_WIDTH;
        self.next += 1;
        Some(read_slot(&self.bytes[offset..offset + SLOT_WIDTH]))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.total - self.next;
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for OutputSlots<'_> {}

#[cfg(test)]
pub(super) fn activation() -> Result<&'static ValidatedSchedule<'static>, ScheduleError> {
    cached_validation(&ACTIVATION_VALIDATION, ACTIVATION_SCHEDULE, ACTIVATION_SPEC)
}

#[cfg(test)]
pub(super) fn export() -> Result<&'static ValidatedSchedule<'static>, ScheduleError> {
    cached_validation(&EXPORT_VALIDATION, EXPORT_SCHEDULE, EXPORT_SPEC)
}

pub(super) fn phase4_activation() -> Result<&'static ValidatedSchedule<'static>, ScheduleError> {
    cached_validation(
        &PHASE4_ACTIVATION_VALIDATION,
        PHASE4_ACTIVATION_SCHEDULE,
        PHASE4_ACTIVATION_SPEC,
    )
}

pub(super) fn phase4_export() -> Result<&'static ValidatedSchedule<'static>, ScheduleError> {
    cached_validation(
        &PHASE4_EXPORT_VALIDATION,
        PHASE4_EXPORT_SCHEDULE,
        PHASE4_EXPORT_SPEC,
    )
}

fn cached_validation(
    cache: &'static OnceLock<Result<ValidatedSchedule<'static>, ScheduleError>>,
    bytes: &'static [u8],
    spec: FixedScheduleSpec,
) -> Result<&'static ValidatedSchedule<'static>, ScheduleError> {
    match cache.get_or_init(|| parse(bytes, spec)) {
        Ok(schedule) => Ok(schedule),
        Err(error) => Err(*error),
    }
}

fn parse(bytes: &[u8], spec: FixedScheduleSpec) -> Result<ValidatedSchedule<'_>, ScheduleError> {
    let gate_bytes = checked_encoded_length(spec)?;
    if bytes.len() != gate_bytes {
        return Err(ScheduleError::Length);
    }
    if &bytes[..8] != SCHEDULE_MAGIC {
        return Err(ScheduleError::Magic);
    }
    if bytes[8] != spec.component {
        return Err(ScheduleError::Component);
    }
    if usize::from(bytes[9]) != SLOT_WIDTH
        || spec.slot_count <= 256
        || spec.slot_count as usize > MAX_SLOT_COUNT
    {
        return Err(ScheduleError::SlotWidth);
    }
    if bytes[10..42] != spec.ir_digest {
        return Err(ScheduleError::IrDigest);
    }
    validate_header_count(&bytes[42..46], spec.input_count, ScheduleError::InputCount)?;
    validate_header_count(&bytes[46..50], spec.gate_count, ScheduleError::GateCount)?;
    validate_header_count(
        &bytes[50..54],
        spec.output_count,
        ScheduleError::OutputCount,
    )?;
    validate_header_count(&bytes[54..58], spec.slot_count, ScheduleError::SlotCount)?;

    let records_end = HEADER_BYTES + spec.gate_count as usize * RECORD_BYTES;
    let records = &bytes[HEADER_BYTES..records_end];
    let outputs = &bytes[records_end..];
    validate_records(records, spec)?;
    validate_outputs(outputs, spec)?;
    let actual_digest: [u8; 32] = Sha256::digest(bytes).into();
    if actual_digest != spec.schedule_digest {
        return Err(ScheduleError::Digest);
    }
    Ok(ValidatedSchedule {
        spec,
        records,
        outputs,
    })
}

fn checked_encoded_length(spec: FixedScheduleSpec) -> Result<usize, ScheduleError> {
    let records = (spec.gate_count as usize)
        .checked_mul(RECORD_BYTES)
        .ok_or(ScheduleError::Length)?;
    let outputs = (spec.output_count as usize)
        .checked_mul(SLOT_WIDTH)
        .ok_or(ScheduleError::Length)?;
    HEADER_BYTES
        .checked_add(records)
        .and_then(|value| value.checked_add(outputs))
        .ok_or(ScheduleError::Length)
}

fn validate_header_count(
    bytes: &[u8],
    expected: u32,
    error: ScheduleError,
) -> Result<(), ScheduleError> {
    let actual = u32::from_be_bytes(
        bytes
            .try_into()
            .expect("header parser passes exactly four bytes"),
    );
    if actual == expected {
        Ok(())
    } else {
        Err(error)
    }
}

fn validate_records(records: &[u8], spec: FixedScheduleSpec) -> Result<(), ScheduleError> {
    let mut xor_count = 0_u32;
    let mut and_count = 0_u32;
    let mut inv_count = 0_u32;
    for record in records.chunks_exact(RECORD_BYTES) {
        let left = read_slot(&record[1..3]);
        let right = read_slot(&record[3..5]);
        let output = read_slot(&record[5..7]);
        if left >= spec.slot_count as usize
            || right >= spec.slot_count as usize
            || output >= spec.slot_count as usize
        {
            return Err(ScheduleError::SlotBound);
        }
        match record[0] {
            XOR_OPCODE => xor_count += 1,
            AND_OPCODE => and_count += 1,
            INV_OPCODE => {
                if left != right {
                    return Err(ScheduleError::InversionOperands);
                }
                inv_count += 1;
            }
            _ => return Err(ScheduleError::Opcode),
        }
    }
    if xor_count != spec.xor_count || and_count != spec.and_count || inv_count != spec.inv_count {
        return Err(ScheduleError::GateClassCounts);
    }
    Ok(())
}

fn validate_outputs(outputs: &[u8], spec: FixedScheduleSpec) -> Result<(), ScheduleError> {
    let mut seen = [false; MAX_SLOT_COUNT];
    for bytes in outputs.chunks_exact(SLOT_WIDTH) {
        let slot = read_slot(bytes);
        if slot >= spec.slot_count as usize {
            return Err(ScheduleError::SlotBound);
        }
        if seen[slot] {
            return Err(ScheduleError::DuplicateOutput);
        }
        seen[slot] = true;
    }
    Ok(())
}

fn read_slot(bytes: &[u8]) -> usize {
    usize::from(u16::from_be_bytes(
        bytes
            .try_into()
            .expect("fixed schedule slot width is two bytes"),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_activation_and_export_schedules_validate_and_iterate() {
        let activation = activation().expect("activation schedule");
        assert_eq!(activation.input_count(), 2_048);
        assert_eq!(activation.gate_count(), 367_240);
        assert_eq!(activation.output_count(), 512);
        assert_eq!(activation.slot_count(), 5_761);
        assert_eq!(activation.and_count(), 62_716);
        assert_eq!(activation.gates().len(), 367_240);
        assert_eq!(activation.output_slots().len(), 512);

        let export = export().expect("export schedule");
        assert_eq!(export.input_count(), 1_024);
        assert_eq!(export.gate_count(), 4_584);
        assert_eq!(export.output_count(), 256);
        assert_eq!(export.slot_count(), 1_025);
        assert_eq!(export.and_count(), 765);
        assert_eq!(export.gates().len(), 4_584);
        assert_eq!(export.output_slots().len(), 256);
    }

    #[test]
    fn phase4_private_output_schedules_validate_and_iterate() {
        let activation = phase4_activation().expect("Phase 4 activation schedule");
        assert_eq!(activation.input_count(), 3_072);
        assert_eq!(activation.gate_count(), 382_050);
        assert_eq!(activation.output_count(), 1_024);
        assert_eq!(activation.slot_count(), 6_785);
        assert_eq!(activation.and_count(), 65_780);
        assert_eq!(activation.gates().len(), 382_050);
        assert_eq!(activation.output_slots().len(), 1_024);

        let export = phase4_export().expect("Phase 4 export schedule");
        assert_eq!(export.input_count(), 1_536);
        assert_eq!(export.gate_count(), 7_900);
        assert_eq!(export.output_count(), 512);
        assert_eq!(export.slot_count(), 1_537);
        assert_eq!(export.and_count(), 1_275);
        assert_eq!(export.gates().len(), 7_900);
        assert_eq!(export.output_slots().len(), 512);
    }

    #[test]
    fn phase4_schedule_cannot_parse_under_a_phase3_identity() {
        assert_eq!(
            parse(PHASE4_EXPORT_SCHEDULE, EXPORT_SPEC).unwrap_err(),
            ScheduleError::Length
        );
        let mut bytes = PHASE4_EXPORT_SCHEDULE.to_vec();
        bytes[8] = EXPORT_SPEC.component;
        assert_eq!(
            parse(&bytes, PHASE4_EXPORT_SPEC).unwrap_err(),
            ScheduleError::Component
        );
    }

    #[test]
    fn strict_parser_rejects_header_and_record_mutations() {
        let mut bytes = EXPORT_SCHEDULE.to_vec();
        bytes[0] ^= 1;
        assert_eq!(
            parse(&bytes, EXPORT_SPEC).unwrap_err(),
            ScheduleError::Magic
        );

        let mut bytes = EXPORT_SCHEDULE.to_vec();
        bytes[8] = 0x91;
        assert_eq!(
            parse(&bytes, EXPORT_SPEC).unwrap_err(),
            ScheduleError::Component
        );

        let mut bytes = EXPORT_SCHEDULE.to_vec();
        bytes[9] = 1;
        assert_eq!(
            parse(&bytes, EXPORT_SPEC).unwrap_err(),
            ScheduleError::SlotWidth
        );

        let mut bytes = EXPORT_SCHEDULE.to_vec();
        bytes[HEADER_BYTES] = 0xff;
        assert_eq!(
            parse(&bytes, EXPORT_SPEC).unwrap_err(),
            ScheduleError::Opcode
        );

        let mut bytes = EXPORT_SCHEDULE.to_vec();
        bytes[HEADER_BYTES + 1..HEADER_BYTES + 3].copy_from_slice(&u16::MAX.to_be_bytes());
        assert_eq!(
            parse(&bytes, EXPORT_SPEC).unwrap_err(),
            ScheduleError::SlotBound
        );
    }

    #[test]
    fn strict_parser_rejects_length_output_and_digest_mutations() {
        assert_eq!(
            parse(&EXPORT_SCHEDULE[..EXPORT_SCHEDULE.len() - 1], EXPORT_SPEC).unwrap_err(),
            ScheduleError::Length
        );

        let mut bytes = EXPORT_SCHEDULE.to_vec();
        let output_offset = HEADER_BYTES + EXPORT_SPEC.gate_count as usize * RECORD_BYTES;
        bytes[output_offset..output_offset + 2].copy_from_slice(&u16::MAX.to_be_bytes());
        assert_eq!(
            parse(&bytes, EXPORT_SPEC).unwrap_err(),
            ScheduleError::SlotBound
        );

        let mut bytes = EXPORT_SCHEDULE.to_vec();
        let record_offset = HEADER_BYTES + RECORD_BYTES;
        bytes[record_offset + 5] ^= 1;
        assert_eq!(
            parse(&bytes, EXPORT_SPEC).unwrap_err(),
            ScheduleError::Digest
        );
    }
}
