use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::candidate::{CandidateBackendFamily, FixedHiddenCoreCandidate};
use crate::error::{ProtoError, ProtoResult};

pub const PRIME_ORDER_ENCODER_VERSION: &str = "prime_order_encoder_v1";

const SHA512_SMALL_SIGMA0: [u8; 3] = [1, 8, 7];
const SHA512_SMALL_SIGMA1: [u8; 3] = [19, 61, 6];
const SHA512_BIG_SIGMA0: [u8; 3] = [28, 34, 39];
const SHA512_BIG_SIGMA1: [u8; 3] = [14, 18, 41];
const GROUP_WINDOW_RECORD_BYTES: usize = 64;
const GROUP_WINDOW_ADD_LANE_COUNT: usize = 32;
const GROUP_WINDOW_SCHEDULE_DERIVED_COUNT: usize = 64;
const GROUP_WINDOW_ROUND_CONSTANT_COUNT: usize = 80;
const GROUP_WINDOW_ROUND_STATE_COUNT: usize = 80;
const GROUP_WINDOW_PROJECTOR_COUNT: usize = 4;
const ED25519_BASEPOINT_ORDER_BYTES: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];
const SHA512_ROUND_CONSTANTS: [u64; 80] = [
    0x428a2f98d728ae22,
    0x7137449123ef65cd,
    0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc,
    0x3956c25bf348b538,
    0x59f111f1b605d019,
    0x923f82a4af194f9b,
    0xab1c5ed5da6d8118,
    0xd807aa98a3030242,
    0x12835b0145706fbe,
    0x243185be4ee4b28c,
    0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f,
    0x80deb1fe3b1696b1,
    0x9bdc06a725c71235,
    0xc19bf174cf692694,
    0xe49b69c19ef14ad2,
    0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5,
    0x240ca1cc77ac9c65,
    0x2de92c6f592b0275,
    0x4a7484aa6ea6e483,
    0x5cb0a9dcbd41fbd4,
    0x76f988da831153b5,
    0x983e5152ee66dfab,
    0xa831c66d2db43210,
    0xb00327c898fb213f,
    0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2,
    0xd5a79147930aa725,
    0x06ca6351e003826f,
    0x142929670a0e6e70,
    0x27b70a8546d22ffc,
    0x2e1b21385c26c926,
    0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df,
    0x650a73548baf63de,
    0x766a0abb3c77b2a8,
    0x81c2c92e47edaee6,
    0x92722c851482353b,
    0xa2bfe8a14cf10364,
    0xa81a664bbc423001,
    0xc24b8b70d0f89791,
    0xc76c51a30654be30,
    0xd192e819d6ef5218,
    0xd69906245565a910,
    0xf40e35855771202a,
    0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8,
    0x1e376c085141ab53,
    0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63,
    0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc,
    0x78a5636f43172f60,
    0x84c87814a1f0ab72,
    0x8cc702081a6439ec,
    0x90befffa23631e28,
    0xa4506cebde82bde9,
    0xbef9a3f7b2c67915,
    0xc67178f2e372532b,
    0xca273eceea26619c,
    0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e,
    0xf57d4f7fee6ed178,
    0x06f067aa72176fba,
    0x0a637dc5a2c898a6,
    0x113f9804bef90dae,
    0x1b710b35131c471b,
    0x28db77f523047d84,
    0x32caab7b40c72493,
    0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6,
    0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec,
    0x6c44198c4a475817,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrimeOrderSectionKind {
    Header,
    ContextDescriptor,
    AddMod2Pow256Template,
    MessageScheduleTemplate,
    RoundConstants,
    RoundTemplates00To19,
    RoundTemplates20To39,
    RoundTemplates40To59,
    RoundTemplates60To79,
    ClampReduceTemplate,
    OutputProjectorTemplate,
    GroupPublicDataWindows,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PrimeOrderWindowRecordClass {
    AddLane,
    ScheduleDerivedWord,
    RoundConstant,
    RoundState,
    OutputProjector,
    ContextParticipant,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrimeOrderArtifactSection {
    pub kind: PrimeOrderSectionKind,
    pub offset_bytes: u64,
    pub length_bytes: u64,
    pub digest: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrimeOrderEncodedArtifact {
    pub encoder_version: String,
    pub candidate_digest: [u8; 32],
    pub context_binding: [u8; 32],
    pub total_bytes: u64,
    pub artifact_digest: [u8; 32],
    pub sections: Vec<PrimeOrderArtifactSection>,
}

pub fn build_prime_order_size_optimized_artifact(
    candidate: &FixedHiddenCoreCandidate,
) -> ProtoResult<PrimeOrderEncodedArtifact> {
    if candidate.backend.family != CandidateBackendFamily::PrimeOrderSizeOptimized {
        return Err(ProtoError::InvalidInput(format!(
            "prime-order encoder requires prime_order_size_optimized backend, got {}",
            candidate.backend.family.as_str()
        )));
    }

    let bytes = materialize_prime_order_size_optimized_bytes(candidate)?;
    let sections = build_section_manifest(candidate, bytes.len() as u64)?;
    let artifact_digest = sha256_bytes(&bytes);

    Ok(PrimeOrderEncodedArtifact {
        encoder_version: PRIME_ORDER_ENCODER_VERSION.to_string(),
        candidate_digest: candidate.template.candidate_digest,
        context_binding: candidate.context_binding,
        total_bytes: bytes.len() as u64,
        artifact_digest,
        sections,
    })
}

pub fn materialize_prime_order_size_optimized_bytes(
    candidate: &FixedHiddenCoreCandidate,
) -> ProtoResult<Vec<u8>> {
    let sections = prime_order_section_layout(candidate.backend.public_data_bytes)?;
    let mut out = Vec::with_capacity(candidate.backend.public_data_bytes as usize);

    for (kind, length_bytes) in sections {
        let section_bytes = build_section_payload(candidate, kind, length_bytes as usize)?;
        out.extend_from_slice(&section_bytes);
    }

    Ok(out)
}

impl PrimeOrderEncodedArtifact {
    pub fn summary_lines(&self) -> Vec<String> {
        vec![
            format!(
                "prime_order_artifact: total={}B sections={} digest={}",
                self.total_bytes,
                self.sections.len(),
                hex::encode(self.artifact_digest),
            ),
            format!(
                "candidate_digest={} context_binding={}",
                hex::encode(self.candidate_digest),
                hex::encode(self.context_binding),
            ),
        ]
    }
}

fn build_section_manifest(
    candidate: &FixedHiddenCoreCandidate,
    expected_total_bytes: u64,
) -> ProtoResult<Vec<PrimeOrderArtifactSection>> {
    let layout = prime_order_section_layout(expected_total_bytes)?;
    let mut offset = 0u64;
    let mut sections = Vec::with_capacity(layout.len());

    for (kind, length_bytes) in layout {
        let payload = build_section_payload(candidate, kind, length_bytes as usize)?;
        sections.push(PrimeOrderArtifactSection {
            kind,
            offset_bytes: offset,
            length_bytes,
            digest: sha256_bytes(&payload),
        });
        offset += length_bytes;
    }

    Ok(sections)
}

pub(crate) fn prime_order_section_layout(
    total_bytes: u64,
) -> ProtoResult<Vec<(PrimeOrderSectionKind, u64)>> {
    let mut layout = vec![
        (PrimeOrderSectionKind::Header, 256),
        (PrimeOrderSectionKind::ContextDescriptor, 512),
        (PrimeOrderSectionKind::AddMod2Pow256Template, 2_048),
        (PrimeOrderSectionKind::MessageScheduleTemplate, 12_288),
        (PrimeOrderSectionKind::RoundConstants, 1_024),
        (PrimeOrderSectionKind::RoundTemplates00To19, 24_576),
        (PrimeOrderSectionKind::RoundTemplates20To39, 24_576),
        (PrimeOrderSectionKind::RoundTemplates40To59, 24_576),
        (PrimeOrderSectionKind::RoundTemplates60To79, 24_576),
        (PrimeOrderSectionKind::ClampReduceTemplate, 4_096),
        (PrimeOrderSectionKind::OutputProjectorTemplate, 2_048),
    ];

    let allocated = layout.iter().map(|(_, bytes)| *bytes).sum::<u64>();
    if total_bytes <= allocated {
        return Err(ProtoError::InvalidInput(format!(
            "prime-order artifact size {} too small for fixed section layout {}",
            total_bytes, allocated
        )));
    }

    layout.push((
        PrimeOrderSectionKind::GroupPublicDataWindows,
        total_bytes - allocated,
    ));
    Ok(layout)
}

fn build_section_payload(
    candidate: &FixedHiddenCoreCandidate,
    kind: PrimeOrderSectionKind,
    length_bytes: usize,
) -> ProtoResult<Vec<u8>> {
    let mut out = Vec::new();

    match kind {
        PrimeOrderSectionKind::Header => encode_header_section(candidate, length_bytes, &mut out)?,
        PrimeOrderSectionKind::ContextDescriptor => {
            encode_context_descriptor_section(candidate, &mut out);
        }
        PrimeOrderSectionKind::AddMod2Pow256Template => encode_add_template_section(&mut out),
        PrimeOrderSectionKind::MessageScheduleTemplate => {
            encode_message_schedule_section(&mut out);
        }
        PrimeOrderSectionKind::RoundConstants => encode_round_constants_section(&mut out),
        PrimeOrderSectionKind::RoundTemplates00To19 => {
            encode_round_template_section(0, 19, &mut out);
        }
        PrimeOrderSectionKind::RoundTemplates20To39 => {
            encode_round_template_section(20, 39, &mut out);
        }
        PrimeOrderSectionKind::RoundTemplates40To59 => {
            encode_round_template_section(40, 59, &mut out);
        }
        PrimeOrderSectionKind::RoundTemplates60To79 => {
            encode_round_template_section(60, 79, &mut out);
        }
        PrimeOrderSectionKind::ClampReduceTemplate => encode_clamp_reduce_section(&mut out),
        PrimeOrderSectionKind::OutputProjectorTemplate => {
            encode_output_projector_section(&mut out);
        }
        PrimeOrderSectionKind::GroupPublicDataWindows => {
            encode_group_public_data_windows_section(candidate, length_bytes, &mut out);
        }
    }

    finalize_section(candidate, kind, length_bytes, out)
}

fn encode_header_section(
    candidate: &FixedHiddenCoreCandidate,
    _section_length_bytes: usize,
    out: &mut Vec<u8>,
) -> ProtoResult<()> {
    let section_count = prime_order_section_layout(candidate.backend.public_data_bytes)?.len();

    out.extend_from_slice(b"SGPPRM01");
    push_u16(out, 1);
    push_u16(
        out,
        u16::try_from(section_count).map_err(|_| {
            ProtoError::InvalidInput("section count does not fit into u16".to_string())
        })?,
    );
    push_u16(out, backend_family_id(candidate.backend.family));
    push_u16(out, 0);
    push_u64(out, candidate.backend.public_data_bytes);
    push_u64(out, candidate.template.template_descriptor_bytes);
    push_u64(out, candidate.backend.public_data_bytes);
    push_u32(
        out,
        candidate
            .evaluator_plan
            .cpu_fallback
            .target_latency_ms
            .unwrap_or_default() as u32,
    );
    push_u32(
        out,
        candidate
            .evaluator_plan
            .accelerator_path
            .target_latency_ms
            .unwrap_or_default() as u32,
    );
    out.extend_from_slice(&candidate.context_binding);
    out.extend_from_slice(&candidate.template.candidate_digest);
    out.extend_from_slice(&candidate.template.round_template_digest);
    push_len_prefixed_str(out, &candidate.fixed_function_id)?;
    push_len_prefixed_str(out, PRIME_ORDER_ENCODER_VERSION)?;
    Ok(())
}

fn encode_context_descriptor_section(candidate: &FixedHiddenCoreCandidate, out: &mut Vec<u8>) {
    out.extend_from_slice(b"CTXDESC1");
    out.extend_from_slice(&candidate.context_binding);
    push_u64(out, candidate.template.template_descriptor_bytes);
    push_u32(out, candidate.context_descriptor.derivation_version);
    push_u16(
        out,
        candidate.context_descriptor.participant_ids.len() as u16,
    );
    for participant_id in &candidate.context_descriptor.participant_ids {
        push_u16(out, *participant_id);
    }
    push_len_prefixed_str_infallible(out, &candidate.context_descriptor.org_id);
    push_len_prefixed_str_infallible(out, &candidate.context_descriptor.account_id);
    push_len_prefixed_str_infallible(out, &candidate.context_descriptor.key_purpose);
    push_len_prefixed_str_infallible(out, &candidate.context_descriptor.key_version);
    push_len_prefixed_str_infallible(out, candidate.backend.family.as_str());
}

fn encode_add_template_section(out: &mut Vec<u8>) {
    out.extend_from_slice(b"ADD256V1");
    push_u16(out, 32);
    push_u16(out, 8);
    push_u16(out, 32);
    push_u16(out, 1);
    for idx in 0u8..32u8 {
        push_u8(out, idx);
        push_u8(out, 0);
        push_u8(out, 1);
        push_u8(out, if idx == 0 { u8::MAX } else { idx - 1 });
        push_u8(out, if idx == 31 { u8::MAX } else { idx + 1 });
        push_u8(out, u8::from(idx == 31));
        push_u16(out, 8);
    }
}

fn encode_message_schedule_section(out: &mut Vec<u8>) {
    out.extend_from_slice(b"MSGSCHD1");
    push_u32(out, 1_024);
    push_u16(out, 64);
    push_u16(out, 80);
    push_u16(out, 32);
    push_u16(out, 16);
    push_u16(out, 64);
    push_u16(out, 4);
    push_u16(out, 15);
    push_u64(out, 256);
    for value in SHA512_SMALL_SIGMA0 {
        push_u8(out, value);
    }
    for value in SHA512_SMALL_SIGMA1 {
        push_u8(out, value);
    }

    for word_idx in 0u8..16u8 {
        push_u8(out, word_idx);
        match word_idx {
            0..=3 => {
                push_u8(out, 0);
                push_u16(out, u16::from(word_idx) * 8);
                push_u16(out, 8);
                push_u16(out, 0);
            }
            4 => {
                push_u8(out, 1);
                push_u16(out, 32);
                push_u16(out, 1);
                push_u16(out, 7);
            }
            5..=13 => {
                push_u8(out, 2);
                push_u16(out, 0);
                push_u16(out, 8);
                push_u16(out, 0);
            }
            14 => {
                push_u8(out, 3);
                push_u16(out, 0);
                push_u16(out, 8);
                push_u16(out, 0);
            }
            15 => {
                push_u8(out, 4);
                push_u16(out, 256);
                push_u16(out, 8);
                push_u16(out, 0);
            }
            _ => unreachable!(),
        }
    }

    for word_idx in 16u8..80u8 {
        push_u8(out, word_idx);
        push_u8(out, word_idx - 2);
        push_u8(out, word_idx - 7);
        push_u8(out, word_idx - 15);
        push_u8(out, word_idx - 16);
        push_u8(out, SHA512_SMALL_SIGMA0[0]);
        push_u8(out, SHA512_SMALL_SIGMA0[1]);
        push_u8(out, SHA512_SMALL_SIGMA0[2]);
        push_u8(out, SHA512_SMALL_SIGMA1[0]);
        push_u8(out, SHA512_SMALL_SIGMA1[1]);
        push_u8(out, SHA512_SMALL_SIGMA1[2]);
        push_u8(out, 4);
    }
}

fn encode_round_constants_section(out: &mut Vec<u8>) {
    out.extend_from_slice(b"RNDCNST1");
    push_u16(out, SHA512_ROUND_CONSTANTS.len() as u16);
    for value in SHA512_BIG_SIGMA0 {
        push_u8(out, value);
    }
    for value in SHA512_BIG_SIGMA1 {
        push_u8(out, value);
    }
    push_u8(out, 3);
    push_u8(out, 3);
    for constant in SHA512_ROUND_CONSTANTS {
        out.extend_from_slice(&constant.to_be_bytes());
    }
}

fn encode_round_template_section(start_round: u8, end_round: u8, out: &mut Vec<u8>) {
    out.extend_from_slice(b"RNDTPLT1");
    push_u8(out, start_round);
    push_u8(out, end_round);
    push_u8(out, end_round - start_round + 1);
    push_u8(out, 8);

    for round in start_round..=end_round {
        push_u8(out, round);
        push_u8(out, round);
        push_u8(out, round);
        push_u8(out, 4);
        push_u8(out, 5);
        push_u8(out, 6);
        push_u8(out, 0);
        push_u8(out, 1);
        push_u8(out, 2);
        push_u8(out, SHA512_BIG_SIGMA1[0]);
        push_u8(out, SHA512_BIG_SIGMA1[1]);
        push_u8(out, SHA512_BIG_SIGMA1[2]);
        push_u8(out, SHA512_BIG_SIGMA0[0]);
        push_u8(out, SHA512_BIG_SIGMA0[1]);
        push_u8(out, SHA512_BIG_SIGMA0[2]);
        push_u8(out, 5);
        push_u8(out, 2);
        push_u8(out, 0);
        push_u8(out, 3);
        push_u8(out, 4);
        push_u8(out, 0);
        push_u8(out, 1);
        push_u8(out, 2);
        push_u8(out, 4);
        push_u8(out, 5);
        push_u8(out, 6);
        push_u8(out, 7);
        push_u8(out, 0);
        push_u8(out, 1);
        push_u8(out, 2);
        push_u8(out, 3);
    }
}

fn encode_clamp_reduce_section(out: &mut Vec<u8>) {
    out.extend_from_slice(b"CLMPRED1");
    push_u16(out, 0);
    push_u16(out, 32);
    push_u8(out, 0);
    push_u8(out, 248);
    push_u8(out, 31);
    push_u8(out, 63);
    push_u8(out, 31);
    push_u8(out, 64);
    push_u16(out, 252);
    push_u16(out, 32);
    push_u8(out, 1);
    push_u8(out, 0);
    out.extend_from_slice(&ED25519_BASEPOINT_ORDER_BYTES);
}

fn encode_output_projector_section(out: &mut Vec<u8>) {
    out.extend_from_slice(b"OUTPROJ1");
    push_u8(out, 4);
    push_u8(out, 3);
    push_u8(out, 2);
    push_u8(out, 1);
    push_u16(out, 32);
    push_u16(out, 32);
    push_u16(out, 32);
    push_u16(out, 32);
    push_u8(out, 1);
    push_u8(out, 1);
    push_u8(out, 1);
    push_u8(out, 2);
    out.extend_from_slice(&ED25519_BASEPOINT_POINT.compress().to_bytes());
    push_len_prefixed_str_infallible(out, "tau = tau_client + tau_relayer");
    push_len_prefixed_str_infallible(out, "x_client_base = a + tau");
    push_len_prefixed_str_infallible(out, "x_relayer_base = a + 2*tau");
    push_len_prefixed_str_infallible(out, "public_key = [a]B");
}

fn encode_group_public_data_windows_section(
    candidate: &FixedHiddenCoreCandidate,
    length_bytes: usize,
    out: &mut Vec<u8>,
) {
    let participant_count = candidate.context_descriptor.participant_ids.len();
    let total_records = GROUP_WINDOW_ADD_LANE_COUNT
        + GROUP_WINDOW_SCHEDULE_DERIVED_COUNT
        + GROUP_WINDOW_ROUND_CONSTANT_COUNT
        + GROUP_WINDOW_ROUND_STATE_COUNT
        + GROUP_WINDOW_PROJECTOR_COUNT
        + participant_count;

    out.extend_from_slice(b"GRPWNDW2");
    push_u16(out, backend_family_id(candidate.backend.family));
    push_u16(out, 2);
    push_u16(out, GROUP_WINDOW_RECORD_BYTES as u16);
    push_u16(out, total_records as u16);
    push_u16(out, 6);
    push_u16(out, GROUP_WINDOW_ADD_LANE_COUNT as u16);
    push_u16(out, GROUP_WINDOW_SCHEDULE_DERIVED_COUNT as u16);
    push_u16(out, GROUP_WINDOW_ROUND_CONSTANT_COUNT as u16);
    push_u16(out, GROUP_WINDOW_ROUND_STATE_COUNT as u16);
    push_u16(out, GROUP_WINDOW_PROJECTOR_COUNT as u16);
    push_u16(out, participant_count as u16);
    push_u16(
        out,
        candidate.context_descriptor.participant_ids.len() as u16,
    );

    let mut record_index = 0u16;

    for lane_idx in 0..GROUP_WINDOW_ADD_LANE_COUNT {
        encode_window_record(
            out,
            candidate,
            record_index,
            PrimeOrderWindowRecordClass::AddLane,
            PrimeOrderSectionKind::AddMod2Pow256Template,
            16 + (lane_idx as u32) * 8,
            8,
            8,
            4,
            16,
            lane_idx as u16,
            u16::MAX,
            u16::MAX,
            2,
            lane_idx as u16,
        );
        record_index += 1;
    }

    for word_idx in 16..80usize {
        let derived_idx = word_idx - 16;
        encode_window_record(
            out,
            candidate,
            record_index,
            PrimeOrderWindowRecordClass::ScheduleDerivedWord,
            PrimeOrderSectionKind::MessageScheduleTemplate,
            166 + (derived_idx as u32) * 12,
            8,
            16,
            4,
            16,
            word_idx as u16,
            (word_idx - 15) as u16,
            (word_idx - 2) as u16,
            2,
            derived_idx as u16,
        );
        record_index += 1;
    }

    for round_idx in 0..GROUP_WINDOW_ROUND_CONSTANT_COUNT {
        encode_window_record(
            out,
            candidate,
            record_index,
            PrimeOrderWindowRecordClass::RoundConstant,
            PrimeOrderSectionKind::RoundConstants,
            18 + (round_idx as u32) * 8,
            8,
            8,
            4,
            16,
            round_idx as u16,
            u16::MAX,
            u16::MAX,
            1,
            round_idx as u16,
        );
        record_index += 1;
    }

    for round_idx in 0..GROUP_WINDOW_ROUND_STATE_COUNT {
        let source_kind = round_section_kind(round_idx as u8);
        let local_round = round_idx % 20;
        encode_window_record(
            out,
            candidate,
            record_index,
            PrimeOrderWindowRecordClass::RoundState,
            source_kind,
            12 + (local_round as u32) * 32,
            32,
            20,
            5,
            32,
            round_idx as u16,
            round_idx.saturating_sub(1) as u16,
            round_idx as u16,
            2,
            local_round as u16,
        );
        record_index += 1;
    }

    for projector_idx in 0..GROUP_WINDOW_PROJECTOR_COUNT {
        let (source_offset, class_slot) = match projector_idx {
            0 => (56, 0),
            1 => (85, 1),
            2 => (110, 2),
            3 => (139, 3),
            _ => unreachable!(),
        };
        encode_window_record(
            out,
            candidate,
            record_index,
            PrimeOrderWindowRecordClass::OutputProjector,
            PrimeOrderSectionKind::OutputProjectorTemplate,
            source_offset,
            32,
            16,
            4,
            16,
            projector_idx as u16,
            u16::MAX,
            u16::MAX,
            1,
            class_slot,
        );
        record_index += 1;
    }

    for (participant_slot, participant_id) in candidate
        .context_descriptor
        .participant_ids
        .iter()
        .enumerate()
    {
        encode_window_record(
            out,
            candidate,
            record_index,
            PrimeOrderWindowRecordClass::ContextParticipant,
            PrimeOrderSectionKind::ContextDescriptor,
            54 + (participant_slot as u32) * 2,
            2,
            4,
            2,
            4,
            *participant_id,
            u16::MAX,
            u16::MAX,
            1,
            participant_slot as u16,
        );
        record_index += 1;
    }

    let header_and_records_bytes = 32 + total_records * GROUP_WINDOW_RECORD_BYTES;
    debug_assert!(out.len() <= length_bytes);
    debug_assert_eq!(header_and_records_bytes, out.len());
}

#[allow(clippy::too_many_arguments)]
fn encode_window_record(
    out: &mut Vec<u8>,
    candidate: &FixedHiddenCoreCandidate,
    record_index: u16,
    class: PrimeOrderWindowRecordClass,
    source_kind: PrimeOrderSectionKind,
    source_offset: u32,
    logical_span: u16,
    window_bits: u16,
    digit_count: u16,
    bucket_count: u16,
    class_value: u16,
    dependency_left: u16,
    dependency_right: u16,
    reuse_scope: u16,
    class_slot: u16,
) {
    let digest = sha256_concat(&[
        b"succinct-garbling-proto/group-window-record/v2",
        &candidate.context_binding,
        &candidate.template.candidate_digest,
        &[class.as_u8()],
        source_kind.as_str().as_bytes(),
        &record_index.to_le_bytes(),
        &source_offset.to_le_bytes(),
        &class_value.to_le_bytes(),
        &class_slot.to_le_bytes(),
    ]);

    push_u16(out, record_index);
    push_u8(out, class.as_u8());
    push_u8(out, section_kind_id(source_kind));
    push_u32(out, source_offset);
    push_u16(out, logical_span);
    push_u16(out, window_bits);
    push_u16(out, digit_count);
    push_u16(out, bucket_count);
    push_u16(out, class_value);
    push_u16(out, dependency_left);
    push_u16(out, dependency_right);
    push_u16(out, reuse_scope);
    push_u16(out, class_slot);
    push_u16(out, 0);
    push_u32(out, 0);
    out.extend_from_slice(&digest);
}

fn finalize_section(
    candidate: &FixedHiddenCoreCandidate,
    kind: PrimeOrderSectionKind,
    length_bytes: usize,
    mut out: Vec<u8>,
) -> ProtoResult<Vec<u8>> {
    if out.len() > length_bytes {
        return Err(ProtoError::InvalidInput(format!(
            "section {} produced {} bytes, exceeds allocated {} bytes",
            kind.as_str(),
            out.len(),
            length_bytes
        )));
    }

    if out.len() < length_bytes {
        let section_seed = section_seed(candidate, kind);
        let content_digest = sha256_bytes(&out);
        let mut counter = 0u64;

        while out.len() < length_bytes {
            let block = sha256_concat(&[
                b"succinct-garbling-proto/prime-order-section-padding/v1",
                &section_seed,
                &content_digest,
                &counter.to_be_bytes(),
            ]);
            let remaining = length_bytes - out.len();
            let take = remaining.min(block.len());
            out.extend_from_slice(&block[..take]);
            counter += 1;
        }
    }

    Ok(out)
}

fn section_seed(candidate: &FixedHiddenCoreCandidate, kind: PrimeOrderSectionKind) -> [u8; 32] {
    sha256_concat(&[
        b"succinct-garbling-proto/prime-order-section-seed/v1",
        &candidate.context_binding,
        &candidate.template.candidate_digest,
        &candidate.template.round_template_digest,
        kind.as_str().as_bytes(),
    ])
}

fn backend_family_id(family: CandidateBackendFamily) -> u16 {
    match family {
        CandidateBackendFamily::PrimeOrderSizeOptimized => 1,
        CandidateBackendFamily::PrimeOrderComputeOptimized => 2,
        CandidateBackendFamily::PaillierCompressed => 3,
        CandidateBackendFamily::LatticeRlwe => 4,
    }
}

fn section_kind_id(kind: PrimeOrderSectionKind) -> u8 {
    match kind {
        PrimeOrderSectionKind::Header => 1,
        PrimeOrderSectionKind::ContextDescriptor => 2,
        PrimeOrderSectionKind::AddMod2Pow256Template => 3,
        PrimeOrderSectionKind::MessageScheduleTemplate => 4,
        PrimeOrderSectionKind::RoundConstants => 5,
        PrimeOrderSectionKind::RoundTemplates00To19 => 6,
        PrimeOrderSectionKind::RoundTemplates20To39 => 7,
        PrimeOrderSectionKind::RoundTemplates40To59 => 8,
        PrimeOrderSectionKind::RoundTemplates60To79 => 9,
        PrimeOrderSectionKind::ClampReduceTemplate => 10,
        PrimeOrderSectionKind::OutputProjectorTemplate => 11,
        PrimeOrderSectionKind::GroupPublicDataWindows => 12,
    }
}

fn round_section_kind(round: u8) -> PrimeOrderSectionKind {
    match round {
        0..=19 => PrimeOrderSectionKind::RoundTemplates00To19,
        20..=39 => PrimeOrderSectionKind::RoundTemplates20To39,
        40..=59 => PrimeOrderSectionKind::RoundTemplates40To59,
        _ => PrimeOrderSectionKind::RoundTemplates60To79,
    }
}

impl PrimeOrderSectionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Header => "header",
            Self::ContextDescriptor => "context_descriptor",
            Self::AddMod2Pow256Template => "add_mod_2pow256_template",
            Self::MessageScheduleTemplate => "message_schedule_template",
            Self::RoundConstants => "round_constants",
            Self::RoundTemplates00To19 => "round_templates_00_to_19",
            Self::RoundTemplates20To39 => "round_templates_20_to_39",
            Self::RoundTemplates40To59 => "round_templates_40_to_59",
            Self::RoundTemplates60To79 => "round_templates_60_to_79",
            Self::ClampReduceTemplate => "clamp_reduce_template",
            Self::OutputProjectorTemplate => "output_projector_template",
            Self::GroupPublicDataWindows => "group_public_data_windows",
        }
    }
}

impl PrimeOrderWindowRecordClass {
    fn as_u8(self) -> u8 {
        match self {
            Self::AddLane => 1,
            Self::ScheduleDerivedWord => 2,
            Self::RoundConstant => 3,
            Self::RoundState => 4,
            Self::OutputProjector => 5,
            Self::ContextParticipant => 6,
        }
    }
}

fn push_len_prefixed_str(out: &mut Vec<u8>, value: &str) -> ProtoResult<()> {
    let length = u16::try_from(value.len()).map_err(|_| {
        ProtoError::InvalidInput(format!(
            "string too long for encoder section record: {} bytes",
            value.len()
        ))
    })?;
    push_u16(out, length);
    out.extend_from_slice(value.as_bytes());
    Ok(())
}

fn push_len_prefixed_str_infallible(out: &mut Vec<u8>, value: &str) {
    push_u16(out, value.len() as u16);
    out.extend_from_slice(value.as_bytes());
}

fn push_u8(out: &mut Vec<u8>, value: u8) {
    out.push(value);
}

fn push_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn sha256_bytes(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn sha256_concat(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update((part.len() as u32).to_be_bytes());
        hasher.update(part);
    }
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}
