use sha2::{Digest, Sha256};

use super::phase4::{activation_transcript_start, advance_transcript, export_transcript_start};
use super::roles::{
    ActivationASelectedOutputLabels, ActivationBOutputDecodeBits, ActivationSessionBinding,
    ExportASelectedOutputLabels, ExportBOutputDecodeBits, ExportSessionBinding, SessionId,
    TranscriptDigest32,
};
use super::stream::{
    ActivationStream, Chunk256KiB, Chunk64KiB, ExportStream, FixedChunkProfile, FixedStreamFamily,
    PassiveStreamManifest, TABLE_FRAME_HEADER_BYTES,
};

const VECTOR_JSON: &[u8] =
    include_bytes!("../../artifacts/passive-benchmark-v1/phase5-stream-wire-kats-v1.json");
const VECTOR_BINARY: &[u8] =
    include_bytes!("../../artifacts/passive-benchmark-v1/phase5-stream-wire-kats-v1.bin");
const BINARY_MAGIC: &[u8; 8] = b"EY5KAT01";
const BINARY_VERSION: u16 = 1;
const ACTIVATION_TAG: u8 = 0x93;
const EXPORT_TAG: u8 = 0x94;
const MANIFEST_BYTES: usize = 248;
const DIGEST_BYTES: usize = 32;
const FRAME_DIGEST_DOMAIN: &[u8] = b"seams:ed25519-yao:stream-frame-digest:v1";

#[derive(Debug)]
struct WireKat<'a> {
    family_tag: u8,
    chunk_profile_tag: u8,
    payload_multiplier: u8,
    payload_addend: u8,
    session: [u8; 32],
    gate_domain: u64,
    circuit_digest: [u8; 32],
    schedule_digest: [u8; 32],
    transcript_start: [u8; 32],
    pre_stream_control_message: &'a [u8],
    pre_stream_transcript: [u8; 32],
    manifest: [u8; MANIFEST_BYTES],
    manifest_digest: [u8; 32],
    chain_start: [u8; 32],
    first_header: [u8; TABLE_FRAME_HEADER_BYTES],
    first_payload_digest: [u8; 32],
    first_frame_digest: [u8; 32],
    final_header: [u8; TABLE_FRAME_HEADER_BYTES],
    final_payload_digest: [u8; 32],
    final_frame_digest: [u8; 32],
    stream_final_transcript: [u8; 32],
    translation_message: &'a [u8],
    post_translation_transcript: [u8; 32],
    returned_label_message: &'a [u8],
    terminal_transcript: [u8; 32],
}

struct Cursor<'a> {
    encoded: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    const fn new(encoded: &'a [u8]) -> Self {
        Self { encoded, offset: 0 }
    }

    fn take(&mut self, length: usize) -> &'a [u8] {
        let end = self
            .offset
            .checked_add(length)
            .expect("vector cursor overflow");
        let value = self
            .encoded
            .get(self.offset..end)
            .expect("truncated Phase 5 wire KAT");
        self.offset = end;
        value
    }

    fn array<const N: usize>(&mut self) -> [u8; N] {
        self.take(N)
            .try_into()
            .expect("KAT parser supplies the exact array width")
    }

    fn u8(&mut self) -> u8 {
        self.array::<1>()[0]
    }

    fn u16(&mut self) -> u16 {
        u16::from_be_bytes(self.array())
    }

    fn u32(&mut self) -> u32 {
        u32::from_be_bytes(self.array())
    }

    fn u64(&mut self) -> u64 {
        u64::from_be_bytes(self.array())
    }

    fn length_prefixed(&mut self) -> &'a [u8] {
        let length = usize::try_from(self.u32()).expect("u32 fits usize");
        self.take(length)
    }

    fn finish(self) {
        assert_eq!(self.offset, self.encoded.len(), "trailing KAT bytes");
    }
}

fn parse_record(encoded: &[u8]) -> WireKat<'_> {
    let mut cursor = Cursor::new(encoded);
    let kat = WireKat {
        family_tag: cursor.u8(),
        chunk_profile_tag: cursor.u8(),
        payload_multiplier: cursor.u8(),
        payload_addend: cursor.u8(),
        session: cursor.array(),
        gate_domain: cursor.u64(),
        circuit_digest: cursor.array(),
        schedule_digest: cursor.array(),
        transcript_start: cursor.array(),
        pre_stream_control_message: cursor.length_prefixed(),
        pre_stream_transcript: cursor.array(),
        manifest: cursor.array(),
        manifest_digest: cursor.array(),
        chain_start: cursor.array(),
        first_header: cursor.array(),
        first_payload_digest: cursor.array(),
        first_frame_digest: cursor.array(),
        final_header: cursor.array(),
        final_payload_digest: cursor.array(),
        final_frame_digest: cursor.array(),
        stream_final_transcript: cursor.array(),
        translation_message: cursor.length_prefixed(),
        post_translation_transcript: cursor.array(),
        returned_label_message: cursor.length_prefixed(),
        terminal_transcript: cursor.array(),
    };
    cursor.finish();
    kat
}

fn parse_vectors() -> Vec<WireKat<'static>> {
    let mut cursor = Cursor::new(VECTOR_BINARY);
    assert_eq!(cursor.take(BINARY_MAGIC.len()), BINARY_MAGIC);
    assert_eq!(cursor.u16(), BINARY_VERSION);
    let record_count = usize::from(cursor.u16());
    let expected_json_digest: [u8; DIGEST_BYTES] = Sha256::digest(VECTOR_JSON).into();
    assert_eq!(cursor.array::<DIGEST_BYTES>(), expected_json_digest);
    let mut records = Vec::with_capacity(record_count);
    for _ in 0..record_count {
        records.push(parse_record(cursor.length_prefixed()));
    }
    cursor.finish();
    records
}

fn patterned_payload(kat: &WireKat<'_>, offset: usize, length: usize) -> Vec<u8> {
    let multiplier = usize::from(kat.payload_multiplier);
    let addend = usize::from(kat.payload_addend);
    (offset..offset + length)
        .map(|index| (index.wrapping_mul(multiplier).wrapping_add(addend)) as u8)
        .collect()
}

fn frame_digest(
    manifest_digest: &[u8; 32],
    header: &[u8; TABLE_FRAME_HEADER_BYTES],
    payload: &[u8],
) -> [u8; 32] {
    Sha256::new()
        .chain_update(FRAME_DIGEST_DOMAIN)
        .chain_update(manifest_digest)
        .chain_update(header)
        .chain_update(payload)
        .finalize()
        .into()
}

fn verify_stream<F, C>(
    kat: &WireKat<'_>,
    binding: F::Binding,
    pre_stream_transcript: TranscriptDigest32,
) -> TranscriptDigest32
where
    F: FixedStreamFamily,
    C: FixedChunkProfile,
{
    let manifest = PassiveStreamManifest::<F, C>::new(binding, pre_stream_transcript);
    assert_eq!(manifest.encode(), kat.manifest);
    assert_eq!(manifest.manifest_digest(), &kat.manifest_digest);
    let decoded =
        PassiveStreamManifest::<F, C>::decode(binding, pre_stream_transcript, &kat.manifest)
            .expect("Python-generated manifest must pass the production decoder");

    let mut encoder = manifest.encoder();
    let mut decoder = decoded.decoder();
    let mut offset = 0_usize;
    let mut sequence = 0_u32;
    while offset < manifest.table_payload_bytes() {
        let length = core::cmp::min(
            manifest.maximum_frame_payload_bytes(),
            manifest.table_payload_bytes() - offset,
        );
        let payload = patterned_payload(kat, offset, length);
        let header = encoder
            .encode_next_header(&payload)
            .expect("fixed payload must encode");
        let encoded_header = *header.as_bytes();
        let digest = frame_digest(&kat.manifest_digest, &encoded_header, &payload);

        if sequence == 0 {
            assert_eq!(encoded_header, kat.first_header);
            assert_eq!(&encoded_header[28..60], &kat.chain_start);
            assert_eq!(&encoded_header[60..92], &kat.first_payload_digest);
            assert_eq!(digest, kat.first_frame_digest);
        }
        if offset + length == manifest.table_payload_bytes() {
            assert_eq!(encoded_header, kat.final_header);
            assert_eq!(&encoded_header[60..92], &kat.final_payload_digest);
            assert_eq!(digest, kat.final_frame_digest);
        }

        let pending = decoder
            .accept_header(&encoded_header)
            .expect("fixed header must decode");
        assert_eq!(pending.expected_payload_bytes(), length);
        let (next, validated) = pending
            .accept_payload(&payload)
            .expect("fixed payload digest must decode");
        assert_eq!(validated.payload(), payload);
        decoder = next;
        offset += length;
        sequence += 1;
    }

    assert_eq!(sequence, manifest.frame_count());
    let encoder_receipt = encoder
        .complete()
        .expect("complete encoded stream")
        .confirm_body_closed();
    let decoder_receipt = decoder
        .finish_after_exact_eof()
        .expect("complete decoded stream");
    assert_eq!(encoder_receipt, decoder_receipt);
    assert_eq!(
        encoder_receipt.final_transcript().as_bytes(),
        &kat.stream_final_transcript
    );
    encoder_receipt.final_transcript()
}

fn assert_binding(
    kat: &WireKat<'_>,
    gate_domain: u64,
    circuit_digest: &[u8; 32],
    schedule_digest: &[u8; 32],
) {
    assert_eq!(gate_domain, kat.gate_domain);
    assert_eq!(circuit_digest, &kat.circuit_digest);
    assert_eq!(schedule_digest, &kat.schedule_digest);
    assert_eq!(kat.payload_multiplier, 17);
    assert_eq!(kat.payload_addend, kat.family_tag);
}

fn verify_activation(kat: &WireKat<'_>) {
    assert_eq!(kat.family_tag, ACTIVATION_TAG);
    assert_eq!(kat.chunk_profile_tag, 1);
    let binding = ActivationSessionBinding::new(SessionId::new(kat.session).expect("session"));
    assert_binding(
        kat,
        binding.gate_domain(),
        binding.circuit_digest().as_bytes(),
        binding.schedule_digest().as_bytes(),
    );
    let start = activation_transcript_start(binding).expect("transcript start");
    assert_eq!(start.as_bytes(), &kat.transcript_start);
    let pre_stream = advance_transcript(start, kat.pre_stream_control_message)
        .expect("pre-stream control transcript");
    assert_eq!(pre_stream.as_bytes(), &kat.pre_stream_transcript);
    let stream_final = verify_stream::<ActivationStream, Chunk64KiB>(kat, binding, pre_stream);

    let translation = ActivationBOutputDecodeBits::decode(
        binding.bind_transcript(stream_final),
        kat.translation_message,
    )
    .expect("canonical activation translation message");
    assert_eq!(translation.encode().as_slice(), kat.translation_message);
    let post_translation =
        advance_transcript(stream_final, kat.translation_message).expect("translation transcript");
    assert_eq!(
        post_translation.as_bytes(),
        &kat.post_translation_transcript
    );

    let returned = ActivationASelectedOutputLabels::decode(
        binding.bind_transcript(post_translation),
        kat.returned_label_message,
    )
    .expect("canonical activation returned-label message");
    assert_eq!(returned.encode().as_slice(), kat.returned_label_message);
    let terminal = advance_transcript(post_translation, kat.returned_label_message)
        .expect("returned-label transcript");
    assert_eq!(terminal.as_bytes(), &kat.terminal_transcript);
}

fn verify_export(kat: &WireKat<'_>) {
    assert_eq!(kat.family_tag, EXPORT_TAG);
    assert_eq!(kat.chunk_profile_tag, 3);
    let binding = ExportSessionBinding::new(SessionId::new(kat.session).expect("session"));
    assert_binding(
        kat,
        binding.gate_domain(),
        binding.circuit_digest().as_bytes(),
        binding.schedule_digest().as_bytes(),
    );
    let start = export_transcript_start(binding).expect("transcript start");
    assert_eq!(start.as_bytes(), &kat.transcript_start);
    let pre_stream = advance_transcript(start, kat.pre_stream_control_message)
        .expect("pre-stream control transcript");
    assert_eq!(pre_stream.as_bytes(), &kat.pre_stream_transcript);
    let stream_final = verify_stream::<ExportStream, Chunk256KiB>(kat, binding, pre_stream);

    let translation = ExportBOutputDecodeBits::decode(
        binding.bind_transcript(stream_final),
        kat.translation_message,
    )
    .expect("canonical export translation message");
    assert_eq!(translation.encode().as_slice(), kat.translation_message);
    let post_translation =
        advance_transcript(stream_final, kat.translation_message).expect("translation transcript");
    assert_eq!(
        post_translation.as_bytes(),
        &kat.post_translation_transcript
    );

    let returned = ExportASelectedOutputLabels::decode(
        binding.bind_transcript(post_translation),
        kat.returned_label_message,
    )
    .expect("canonical export returned-label message");
    assert_eq!(returned.encode().as_slice(), kat.returned_label_message);
    let terminal = advance_transcript(post_translation, kat.returned_label_message)
        .expect("returned-label transcript");
    assert_eq!(terminal.as_bytes(), &kat.terminal_transcript);
}

#[test]
fn independent_phase5_stream_and_control_wire_kats_match_production_codecs() {
    let vectors = parse_vectors();
    assert_eq!(vectors.len(), 2);
    verify_activation(&vectors[0]);
    verify_export(&vectors[1]);
}
