use super::roles::{ExportSessionBinding, SessionId, TranscriptDigest32};
use super::stream::{
    Chunk64KiB, ExportStreamManifest, FixedChunkProfile, FixedStreamFamily, PassiveStreamManifest,
    StreamWireError,
};

const RANDOM_CASES: usize = 512;
const RANDOM_PAYLOAD_MUTATIONS: usize = 128;

struct DeterministicGenerator(u64);

impl DeterministicGenerator {
    const fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next_u64(&mut self) -> u64 {
        let mut value = self.0;
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        self.0 = value;
        value
    }

    fn fill(&mut self, output: &mut [u8]) {
        for byte in output {
            *byte = self.next_u64() as u8;
        }
    }
}

fn binding() -> ExportSessionBinding {
    ExportSessionBinding::new(SessionId::new([0x51; 32]).expect("session"))
}

fn predecessor() -> TranscriptDigest32 {
    TranscriptDigest32::new([0x62; 32]).expect("transcript")
}

fn canonical_export_frame() -> (
    PassiveStreamManifest<super::stream::ExportStream, Chunk64KiB>,
    Vec<u8>,
    Vec<u8>,
) {
    let manifest = ExportStreamManifest::<Chunk64KiB>::new(binding(), predecessor());
    let payload = (0..manifest.table_payload_bytes())
        .map(|index| (index as u8).wrapping_mul(29).wrapping_add(7))
        .collect::<Vec<_>>();
    let mut encoder = manifest.encoder();
    let header = encoder
        .encode_next_header(&payload)
        .expect("canonical export header")
        .as_bytes()
        .to_vec();
    (manifest, header, payload)
}

fn exercise_header_candidate<F, C>(
    manifest: PassiveStreamManifest<F, C>,
    header: &[u8],
    canonical_payload: &[u8],
) where
    F: FixedStreamFamily,
    C: FixedChunkProfile,
{
    if let Ok(pending) = manifest.decoder().accept_header(header) {
        assert!(
            pending.accept_payload(canonical_payload).is_err(),
            "a mutated header and canonical payload must not validate"
        );
    }
}

#[test]
fn deterministic_untrusted_stream_parser_fuzz_smoke() {
    let (manifest, canonical_header, canonical_payload) = canonical_export_frame();
    let canonical_manifest = manifest.encode();

    for offset in 0..canonical_manifest.len() {
        let mut mutated = canonical_manifest;
        mutated[offset] ^= 1_u8 << (offset % 8);
        assert!(
            ExportStreamManifest::<Chunk64KiB>::decode(binding(), predecessor(), &mutated,)
                .is_err()
        );
    }

    for offset in 0..canonical_header.len() {
        let mut mutated = canonical_header.clone();
        mutated[offset] ^= 1_u8 << (offset % 8);
        exercise_header_candidate(manifest, &mutated, &canonical_payload);
    }

    for malformed_length in [0, 1, 31, 32, 91, 93, 247, 249, 512] {
        let bytes = vec![0xa5; malformed_length];
        assert!(
            ExportStreamManifest::<Chunk64KiB>::decode(binding(), predecessor(), &bytes,).is_err()
        );
        assert!(manifest.decoder().accept_header(&bytes).is_err());
    }

    for malformed_length in [
        0,
        1,
        canonical_payload.len() - 1,
        canonical_payload.len() + 1,
    ] {
        let pending = manifest
            .decoder()
            .accept_header(&canonical_header)
            .expect("canonical header");
        assert!(pending
            .accept_payload(&vec![0x3c; malformed_length])
            .is_err());
    }

    let mut generator = DeterministicGenerator::new(0x6a09_e667_f3bc_c909);
    let mut mutation_offsets = vec![
        0,
        1,
        31,
        32,
        canonical_payload.len() / 2,
        canonical_payload.len() - 2,
        canonical_payload.len() - 1,
    ];
    for _ in 0..RANDOM_PAYLOAD_MUTATIONS {
        mutation_offsets.push(generator.next_u64() as usize % canonical_payload.len());
    }
    mutation_offsets.sort_unstable();
    mutation_offsets.dedup();
    for offset in mutation_offsets {
        let mut mutated = canonical_payload.clone();
        mutated[offset] ^= 1_u8 << (offset % 8);
        let pending = manifest
            .decoder()
            .accept_header(&canonical_header)
            .expect("canonical header");
        assert_eq!(
            pending.accept_payload(&mutated).unwrap_err(),
            StreamWireError::PayloadDigest
        );
    }

    for _ in 0..RANDOM_CASES {
        let length = generator.next_u64() as usize % 513;
        let mut bytes = vec![0_u8; length];
        generator.fill(&mut bytes);
        let _ = ExportStreamManifest::<Chunk64KiB>::decode(binding(), predecessor(), &bytes);
        exercise_header_candidate(manifest, &bytes, &canonical_payload);
    }
}
