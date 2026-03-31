use crate::artifact::prime_order_encoder::{prime_order_section_layout, PrimeOrderSectionKind};
use crate::error::{ProtoError, ProtoResult};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrimeOrderDecodedArtifact {
    pub total_bytes: u64,
    pub header: PrimeOrderDecodedHeader,
    pub windows: PrimeOrderGroupedWindowsSection,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrimeOrderDecodedHeader {
    pub artifact_version: u16,
    pub section_count: u16,
    pub backend_family_id: u16,
    pub expected_total_bytes: u64,
    pub template_descriptor_bytes: u64,
    pub public_data_bytes: u64,
    pub cpu_target_latency_ms: u32,
    pub accelerator_target_latency_ms: u32,
    pub context_binding: [u8; 32],
    pub candidate_digest: [u8; 32],
    pub round_template_digest: [u8; 32],
    pub fixed_function_id: String,
    pub encoder_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrimeOrderGroupedWindowsSection {
    pub backend_family_id: u16,
    pub section_version: u16,
    pub record_bytes: u16,
    pub total_records: u16,
    pub class_count: u16,
    pub add_lane_count: u16,
    pub schedule_derived_count: u16,
    pub round_constant_count: u16,
    pub round_state_count: u16,
    pub output_projector_count: u16,
    pub participant_count: u16,
    pub participant_id_count: u16,
    pub records: Vec<PrimeOrderWindowRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrimeOrderWindowRecord {
    pub index: u16,
    pub class: PrimeOrderWindowRecordClass,
    pub source_kind: PrimeOrderSectionKind,
    pub source_offset: u32,
    pub logical_span: u16,
    pub window_bits: u16,
    pub digit_count: u16,
    pub bucket_count: u16,
    pub class_value: u16,
    pub dependency_left: Option<u16>,
    pub dependency_right: Option<u16>,
    pub reuse_scope: u16,
    pub class_slot: u16,
    pub digest: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrimeOrderWindowRecordClass {
    AddLane,
    ScheduleDerivedWord,
    RoundConstant,
    RoundState,
    OutputProjector,
    ContextParticipant,
}

pub fn decode_prime_order_size_optimized_artifact(
    bytes: &[u8],
) -> ProtoResult<PrimeOrderDecodedArtifact> {
    let total_bytes = u64::try_from(bytes.len())
        .map_err(|_| ProtoError::Decode("artifact length does not fit into u64".to_string()))?;
    let layout = prime_order_section_layout(total_bytes)?;
    let header = decode_header(section_slice(
        bytes,
        &layout,
        PrimeOrderSectionKind::Header,
    )?)?;
    if header.expected_total_bytes != total_bytes {
        return Err(ProtoError::Decode(format!(
            "header expected_total_bytes {} does not match actual {}",
            header.expected_total_bytes, total_bytes
        )));
    }

    let windows = decode_grouped_windows(section_slice(
        bytes,
        &layout,
        PrimeOrderSectionKind::GroupPublicDataWindows,
    )?)?;

    Ok(PrimeOrderDecodedArtifact {
        total_bytes,
        header,
        windows,
    })
}

fn decode_header(bytes: &[u8]) -> ProtoResult<PrimeOrderDecodedHeader> {
    if bytes.len() < 144 {
        return Err(ProtoError::Decode(format!(
            "header section too short: {} bytes",
            bytes.len()
        )));
    }
    if &bytes[..8] != b"SGPPRM01" {
        return Err(ProtoError::Decode(
            "unexpected prime-order header magic".to_string(),
        ));
    }

    let mut cursor = 8usize;
    let artifact_version = read_u16(bytes, &mut cursor)?;
    let section_count = read_u16(bytes, &mut cursor)?;
    let backend_family_id = read_u16(bytes, &mut cursor)?;
    let _reserved = read_u16(bytes, &mut cursor)?;
    let expected_total_bytes = read_u64(bytes, &mut cursor)?;
    let template_descriptor_bytes = read_u64(bytes, &mut cursor)?;
    let public_data_bytes = read_u64(bytes, &mut cursor)?;
    let cpu_target_latency_ms = read_u32(bytes, &mut cursor)?;
    let accelerator_target_latency_ms = read_u32(bytes, &mut cursor)?;
    let context_binding = read_array_32(bytes, &mut cursor)?;
    let candidate_digest = read_array_32(bytes, &mut cursor)?;
    let round_template_digest = read_array_32(bytes, &mut cursor)?;
    let fixed_function_id = read_len_prefixed_string(bytes, &mut cursor)?;
    let encoder_version = read_len_prefixed_string(bytes, &mut cursor)?;

    Ok(PrimeOrderDecodedHeader {
        artifact_version,
        section_count,
        backend_family_id,
        expected_total_bytes,
        template_descriptor_bytes,
        public_data_bytes,
        cpu_target_latency_ms,
        accelerator_target_latency_ms,
        context_binding,
        candidate_digest,
        round_template_digest,
        fixed_function_id,
        encoder_version,
    })
}

fn decode_grouped_windows(bytes: &[u8]) -> ProtoResult<PrimeOrderGroupedWindowsSection> {
    if bytes.len() < 32 {
        return Err(ProtoError::Decode(format!(
            "grouped windows section too short: {} bytes",
            bytes.len()
        )));
    }
    if &bytes[..8] != b"GRPWNDW2" {
        return Err(ProtoError::Decode(
            "unexpected grouped windows section magic".to_string(),
        ));
    }

    let mut cursor = 8usize;
    let backend_family_id = read_u16(bytes, &mut cursor)?;
    let section_version = read_u16(bytes, &mut cursor)?;
    let record_bytes = read_u16(bytes, &mut cursor)?;
    let total_records = read_u16(bytes, &mut cursor)?;
    let class_count = read_u16(bytes, &mut cursor)?;
    let add_lane_count = read_u16(bytes, &mut cursor)?;
    let schedule_derived_count = read_u16(bytes, &mut cursor)?;
    let round_constant_count = read_u16(bytes, &mut cursor)?;
    let round_state_count = read_u16(bytes, &mut cursor)?;
    let output_projector_count = read_u16(bytes, &mut cursor)?;
    let participant_count = read_u16(bytes, &mut cursor)?;
    let participant_id_count = read_u16(bytes, &mut cursor)?;

    let record_bytes_usize = usize::from(record_bytes);
    let expected_record_end = cursor + usize::from(total_records) * record_bytes_usize;
    if expected_record_end > bytes.len() {
        return Err(ProtoError::Decode(format!(
            "grouped windows records exceed section length: need {}, have {}",
            expected_record_end,
            bytes.len()
        )));
    }

    let mut records = Vec::with_capacity(usize::from(total_records));
    for _ in 0..total_records {
        let record_start = cursor;
        records.push(decode_window_record(bytes, &mut cursor)?);
        if cursor - record_start != record_bytes_usize {
            return Err(ProtoError::Decode(format!(
                "window record width mismatch: expected {}, decoded {}",
                record_bytes,
                cursor - record_start
            )));
        }
    }

    Ok(PrimeOrderGroupedWindowsSection {
        backend_family_id,
        section_version,
        record_bytes,
        total_records,
        class_count,
        add_lane_count,
        schedule_derived_count,
        round_constant_count,
        round_state_count,
        output_projector_count,
        participant_count,
        participant_id_count,
        records,
    })
}

fn decode_window_record(bytes: &[u8], cursor: &mut usize) -> ProtoResult<PrimeOrderWindowRecord> {
    let index = read_u16(bytes, cursor)?;
    let class = PrimeOrderWindowRecordClass::from_u8(read_u8(bytes, cursor)?)?;
    let source_kind = prime_order_section_kind_from_id(read_u8(bytes, cursor)?)?;
    let source_offset = read_u32(bytes, cursor)?;
    let logical_span = read_u16(bytes, cursor)?;
    let window_bits = read_u16(bytes, cursor)?;
    let digit_count = read_u16(bytes, cursor)?;
    let bucket_count = read_u16(bytes, cursor)?;
    let class_value = read_u16(bytes, cursor)?;
    let dependency_left = decode_optional_u16(read_u16(bytes, cursor)?);
    let dependency_right = decode_optional_u16(read_u16(bytes, cursor)?);
    let reuse_scope = read_u16(bytes, cursor)?;
    let class_slot = read_u16(bytes, cursor)?;
    let _reserved_short = read_u16(bytes, cursor)?;
    let _reserved_word = read_u32(bytes, cursor)?;
    let digest = read_array_32(bytes, cursor)?;

    Ok(PrimeOrderWindowRecord {
        index,
        class,
        source_kind,
        source_offset,
        logical_span,
        window_bits,
        digit_count,
        bucket_count,
        class_value,
        dependency_left,
        dependency_right,
        reuse_scope,
        class_slot,
        digest,
    })
}

fn decode_optional_u16(value: u16) -> Option<u16> {
    if value == u16::MAX {
        None
    } else {
        Some(value)
    }
}

fn section_slice<'a>(
    bytes: &'a [u8],
    layout: &[(PrimeOrderSectionKind, u64)],
    kind: PrimeOrderSectionKind,
) -> ProtoResult<&'a [u8]> {
    let mut offset = 0usize;
    for (section_kind, length) in layout {
        let length_usize = usize::try_from(*length).map_err(|_| {
            ProtoError::Decode(format!(
                "section length for {} does not fit into usize",
                section_kind.as_str()
            ))
        })?;
        if *section_kind == kind {
            let end = offset + length_usize;
            return bytes.get(offset..end).ok_or_else(|| {
                ProtoError::Decode(format!(
                    "section {} outside artifact bounds",
                    section_kind.as_str()
                ))
            });
        }
        offset += length_usize;
    }

    Err(ProtoError::Decode(format!(
        "missing section {} in fixed prime-order layout",
        kind.as_str()
    )))
}

fn prime_order_section_kind_from_id(value: u8) -> ProtoResult<PrimeOrderSectionKind> {
    match value {
        1 => Ok(PrimeOrderSectionKind::Header),
        2 => Ok(PrimeOrderSectionKind::ContextDescriptor),
        3 => Ok(PrimeOrderSectionKind::AddMod2Pow256Template),
        4 => Ok(PrimeOrderSectionKind::MessageScheduleTemplate),
        5 => Ok(PrimeOrderSectionKind::RoundConstants),
        6 => Ok(PrimeOrderSectionKind::RoundTemplates00To19),
        7 => Ok(PrimeOrderSectionKind::RoundTemplates20To39),
        8 => Ok(PrimeOrderSectionKind::RoundTemplates40To59),
        9 => Ok(PrimeOrderSectionKind::RoundTemplates60To79),
        10 => Ok(PrimeOrderSectionKind::ClampReduceTemplate),
        11 => Ok(PrimeOrderSectionKind::OutputProjectorTemplate),
        12 => Ok(PrimeOrderSectionKind::GroupPublicDataWindows),
        _ => Err(ProtoError::Decode(format!(
            "unexpected prime-order section id: {value}"
        ))),
    }
}

impl PrimeOrderWindowRecordClass {
    fn from_u8(value: u8) -> ProtoResult<Self> {
        match value {
            1 => Ok(Self::AddLane),
            2 => Ok(Self::ScheduleDerivedWord),
            3 => Ok(Self::RoundConstant),
            4 => Ok(Self::RoundState),
            5 => Ok(Self::OutputProjector),
            6 => Ok(Self::ContextParticipant),
            _ => Err(ProtoError::Decode(format!(
                "unexpected prime-order window record class: {value}"
            ))),
        }
    }
}

fn read_u8(bytes: &[u8], cursor: &mut usize) -> ProtoResult<u8> {
    let value = *bytes
        .get(*cursor)
        .ok_or_else(|| ProtoError::Decode("unexpected end of section".to_string()))?;
    *cursor += 1;
    Ok(value)
}

fn read_u16(bytes: &[u8], cursor: &mut usize) -> ProtoResult<u16> {
    let slice = bytes
        .get(*cursor..*cursor + 2)
        .ok_or_else(|| ProtoError::Decode("unexpected end of section".to_string()))?;
    *cursor += 2;
    Ok(u16::from_le_bytes([slice[0], slice[1]]))
}

fn read_u32(bytes: &[u8], cursor: &mut usize) -> ProtoResult<u32> {
    let slice = bytes
        .get(*cursor..*cursor + 4)
        .ok_or_else(|| ProtoError::Decode("unexpected end of section".to_string()))?;
    *cursor += 4;
    Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn read_u64(bytes: &[u8], cursor: &mut usize) -> ProtoResult<u64> {
    let slice = bytes
        .get(*cursor..*cursor + 8)
        .ok_or_else(|| ProtoError::Decode("unexpected end of section".to_string()))?;
    *cursor += 8;
    Ok(u64::from_le_bytes([
        slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
    ]))
}

fn read_array_32(bytes: &[u8], cursor: &mut usize) -> ProtoResult<[u8; 32]> {
    let slice = bytes
        .get(*cursor..*cursor + 32)
        .ok_or_else(|| ProtoError::Decode("unexpected end of section".to_string()))?;
    *cursor += 32;
    let mut out = [0u8; 32];
    out.copy_from_slice(slice);
    Ok(out)
}

fn read_len_prefixed_string(bytes: &[u8], cursor: &mut usize) -> ProtoResult<String> {
    let length = usize::from(read_u16(bytes, cursor)?);
    let slice = bytes
        .get(*cursor..*cursor + length)
        .ok_or_else(|| ProtoError::Decode("unexpected end of string field".to_string()))?;
    *cursor += length;
    String::from_utf8(slice.to_vec())
        .map_err(|err| ProtoError::Decode(format!("invalid utf-8 in header field: {err}")))
}
