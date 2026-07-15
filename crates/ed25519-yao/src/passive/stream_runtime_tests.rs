use super::roles::{ActivationSessionBinding, ExportSessionBinding, SessionId, TranscriptDigest32};
use super::stream::{
    ActivationStream, Chunk128KiB, Chunk256KiB, Chunk64KiB, ExactTableStreamReceipt, ExportStream,
    FixedChunkProfile, FixedStreamFamily, PassiveStreamManifest,
};
use super::stream_runtime::{
    activation_evaluator_machine, activation_garbler_machine, export_evaluator_machine,
    export_garbler_machine, EvaluatorAdvance, EvaluatorBodyComplete, GarblerAdvance,
    GarblerBodyComplete,
};
use super::{
    Evaluator, EvaluatorWire, Garbler, GarblerWire, GlobalDelta, SessionDomain, WireLabel,
    WireValue,
};

fn next_u64(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

fn deterministic_inputs(
    garbler: &Garbler,
    count: usize,
    seed: u64,
) -> (Vec<GarblerWire>, Vec<EvaluatorWire>) {
    let mut state = seed;
    let mut garbler_inputs = Vec::with_capacity(count);
    let mut evaluator_inputs = Vec::with_capacity(count);
    for _ in 0..count {
        let mut bytes = [0_u8; 16];
        bytes[..8].copy_from_slice(&next_u64(&mut state).to_be_bytes());
        bytes[8..].copy_from_slice(&next_u64(&mut state).to_be_bytes());
        let wire = GarblerWire::from_zero_label(WireLabel::from_test_bytes(bytes));
        let value = WireValue::from_secret_bit(next_u64(&mut state) as u8);
        evaluator_inputs.push(garbler.encode(&wire, value));
        garbler_inputs.push(wire);
    }
    (garbler_inputs, evaluator_inputs)
}

fn collect_garbler<F, C>(
    mut advance: GarblerAdvance<F, C>,
) -> (Vec<Vec<u8>>, GarblerBodyComplete<F, C>)
where
    F: FixedStreamFamily,
    C: FixedChunkProfile,
{
    let mut chunks = Vec::new();
    loop {
        match advance {
            GarblerAdvance::ChunkReady(chunk) => {
                chunks.push(chunk.payload().to_vec());
                advance = chunk.resume().advance().expect("resume garbler");
            }
            GarblerAdvance::BodyComplete(body) => return (chunks, body),
        }
    }
}

fn evaluate_frames<F, C>(
    manifest: PassiveStreamManifest<F, C>,
    chunks: &[Vec<u8>],
    mut advance: EvaluatorAdvance<F, C>,
) -> (
    ExactTableStreamReceipt<F, C>,
    ExactTableStreamReceipt<F, C>,
    EvaluatorBodyComplete<F, C>,
)
where
    F: FixedStreamFamily,
    C: FixedChunkProfile,
{
    let mut encoder = manifest.encoder();
    let mut decoder = manifest.decoder();
    for chunk in chunks {
        let waiting = match advance {
            EvaluatorAdvance::NeedsFrame(waiting) => waiting,
            EvaluatorAdvance::AwaitingExactEof(_) => panic!("evaluator completed early"),
        };
        let header = encoder.encode_next_header(chunk).expect("encode frame");
        let pending = decoder
            .accept_header(header.as_bytes())
            .expect("decode header");
        let (next_decoder, frame) = pending.accept_payload(chunk).expect("decode payload");
        decoder = next_decoder;
        advance = waiting
            .accept_frame(frame)
            .expect("evaluate frame")
            .advance()
            .expect("advance evaluator");
    }
    let body = match advance {
        EvaluatorAdvance::AwaitingExactEof(body) => body,
        EvaluatorAdvance::NeedsFrame(_) => panic!("evaluator requested a trailing frame"),
    };
    let sender = encoder
        .complete()
        .expect("complete encoder")
        .confirm_body_closed();
    let receiver = decoder.finish_after_exact_eof().expect("complete decoder");
    (sender, receiver, body)
}

fn exercise_activation<C: FixedChunkProfile>() {
    let domain = SessionDomain::from_test_value(0x1020_3040_5060_7080).expect("domain");
    let delta = [0xa5_u8; 16];
    let whole_garbler = Garbler::new(GlobalDelta::from_test_bytes(delta), domain);
    let streamed_garbler = Garbler::new(GlobalDelta::from_test_bytes(delta), domain);
    let (whole_inputs, whole_evaluator_inputs) =
        deterministic_inputs(&whole_garbler, 3_072, 0x1122_3344_5566_7788);
    let (streamed_inputs, streamed_evaluator_inputs) =
        deterministic_inputs(&streamed_garbler, 3_072, 0x1122_3344_5566_7788);
    let whole = whole_garbler
        .garble_phase4_activation(whole_inputs)
        .expect("whole garble");
    let (chunks, body) = collect_garbler(
        activation_garbler_machine::<C>(streamed_garbler, streamed_inputs, 512)
            .expect("garbler machine")
            .advance()
            .expect("garbler advance"),
    );
    assert_eq!(chunks.concat(), whole.tables);

    let manifest = PassiveStreamManifest::<ActivationStream, C>::new(
        ActivationSessionBinding::new(SessionId::new([0x31; 32]).expect("session")),
        TranscriptDigest32::new([0x32; 32]).expect("transcript"),
    );
    let (sender_receipt, receiver_receipt, evaluator_body) = evaluate_frames(
        manifest,
        &chunks,
        activation_evaluator_machine::<C>(Evaluator::new(domain), streamed_evaluator_inputs, 512)
            .expect("evaluator machine")
            .advance()
            .expect("evaluator advance"),
    );
    assert_eq!(sender_receipt, receiver_receipt);
    let streamed_garbled = body.finalize(sender_receipt).expect("garbler EOF gate");
    let streamed_evaluated = evaluator_body
        .finalize(receiver_receipt)
        .expect("evaluator EOF gate");
    assert_eq!(streamed_garbled.table_bytes, whole.tables.len());
    assert_eq!(
        streamed_garbled.table_buffer_write_bytes,
        whole.tables.len()
    );
    assert_eq!(streamed_garbled.host_boundary_copy_bytes, 0);
    assert_eq!(streamed_evaluated.and_records_decoded, 65_780);
    assert_eq!(streamed_evaluated.host_boundary_copy_bytes, 0);
    assert_eq!(
        streamed_garbled.frame_calls,
        u32::try_from(whole.tables.len().div_ceil(C::MAX_PAYLOAD_BYTES)).expect("frames")
    );

    let whole_evaluated = Evaluator::new(domain)
        .evaluate_phase4_activation(whole_evaluator_inputs, &whole.tables)
        .expect("whole evaluate")
        .into_private_outputs(512)
        .expect("whole private outputs");
    let whole_garbled = whole.into_private_outputs(512).expect("whole outputs");
    let whole_a = whole_garbled
        .returned_decoder
        .decode(whole_evaluated.returned_labels)
        .expect("whole A output");
    let whole_b = whole_garbled
        .evaluator_translation
        .decode(whole_evaluated.evaluator_labels)
        .expect("whole B output");
    let streamed_a = streamed_garbled
        .returned_decoder
        .decode(streamed_evaluated.returned_labels)
        .expect("streamed A output");
    let streamed_b = streamed_garbled
        .evaluator_translation
        .decode(streamed_evaluated.evaluator_labels)
        .expect("streamed B output");
    assert_eq!(streamed_a, whole_a);
    assert_eq!(streamed_b, whole_b);
}

fn exercise_export<C: FixedChunkProfile>() {
    let domain = SessionDomain::from_test_value(0x8877_6655_4433_2211).expect("domain");
    let delta = [0x3c_u8; 16];
    let whole_garbler = Garbler::new(GlobalDelta::from_test_bytes(delta), domain);
    let streamed_garbler = Garbler::new(GlobalDelta::from_test_bytes(delta), domain);
    let (whole_inputs, whole_evaluator_inputs) =
        deterministic_inputs(&whole_garbler, 1_536, 0x0123_4567_89ab_cdef);
    let (streamed_inputs, streamed_evaluator_inputs) =
        deterministic_inputs(&streamed_garbler, 1_536, 0x0123_4567_89ab_cdef);
    let whole = whole_garbler
        .garble_phase4_export(whole_inputs)
        .expect("whole garble");
    let (chunks, body) = collect_garbler(
        export_garbler_machine::<C>(streamed_garbler, streamed_inputs, 256)
            .expect("garbler machine")
            .advance()
            .expect("garbler advance"),
    );
    assert_eq!(chunks.concat(), whole.tables);

    let manifest = PassiveStreamManifest::<ExportStream, C>::new(
        ExportSessionBinding::new(SessionId::new([0x41; 32]).expect("session")),
        TranscriptDigest32::new([0x42; 32]).expect("transcript"),
    );
    let (sender_receipt, receiver_receipt, evaluator_body) = evaluate_frames(
        manifest,
        &chunks,
        export_evaluator_machine::<C>(Evaluator::new(domain), streamed_evaluator_inputs, 256)
            .expect("evaluator machine")
            .advance()
            .expect("evaluator advance"),
    );
    assert_eq!(sender_receipt, receiver_receipt);
    let streamed_garbled = body.finalize(sender_receipt).expect("garbler EOF gate");
    let streamed_evaluated = evaluator_body
        .finalize(receiver_receipt)
        .expect("evaluator EOF gate");
    assert_eq!(
        streamed_garbled.table_buffer_write_bytes,
        whole.tables.len()
    );
    assert_eq!(streamed_evaluated.and_records_decoded, 1_275);

    let whole_evaluated = Evaluator::new(domain)
        .evaluate_phase4_export(whole_evaluator_inputs, &whole.tables)
        .expect("whole evaluate")
        .into_private_outputs(256)
        .expect("whole private outputs");
    let whole_garbled = whole.into_private_outputs(256).expect("whole outputs");
    let whole_a = whole_garbled
        .returned_decoder
        .decode(whole_evaluated.returned_labels)
        .expect("whole A output");
    let whole_b = whole_garbled
        .evaluator_translation
        .decode(whole_evaluated.evaluator_labels)
        .expect("whole B output");
    let streamed_a = streamed_garbled
        .returned_decoder
        .decode(streamed_evaluated.returned_labels)
        .expect("streamed A output");
    let streamed_b = streamed_garbled
        .evaluator_translation
        .decode(streamed_evaluated.evaluator_labels)
        .expect("streamed B output");
    assert_eq!(streamed_a, whole_a);
    assert_eq!(streamed_b, whole_b);
}

#[test]
fn all_chunk_profiles_match_the_whole_buffer_activation_oracle() {
    exercise_activation::<Chunk64KiB>();
    exercise_activation::<Chunk128KiB>();
    exercise_activation::<Chunk256KiB>();
}

#[test]
fn all_chunk_profiles_match_the_whole_buffer_export_oracle() {
    exercise_export::<Chunk64KiB>();
    exercise_export::<Chunk128KiB>();
    exercise_export::<Chunk256KiB>();
}

#[test]
fn runtime_source_has_no_callback_or_per_record_transport_api() {
    let source = include_str!("stream_runtime.rs")
        .split("#[cfg(test)]")
        .next()
        .expect("production runtime prefix");
    for forbidden in [
        "FnMut",
        "ValidatedAndTableRecord",
        "next_and_table_record",
        "impl Fn",
    ] {
        assert!(
            !source.contains(forbidden),
            "legacy runtime path: {forbidden}"
        );
    }
    assert!(source.contains("ValidatedTableFrame<'_, F, C>"));
    assert!(source.contains("AwaitingExactEof"));
}
