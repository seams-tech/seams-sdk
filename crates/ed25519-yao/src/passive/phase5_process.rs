//! Benchmark-only separate-role process runners for the bounded Phase 5 stream.
//!
//! The table reader and writer must be opposite ends of a dedicated channel.
//! No writer clone may survive A's table-stream completion because B treats the
//! resulting exact EOF as the release gate for every decoded output.

#![allow(dead_code)]

use core::fmt;
use std::io::{Read, Write};

use zeroize::Zeroize;

use super::ot::{
    ActivationOtFamily, BaseChoices, BaseOffer, ExportOtFamily, ExtensionMatrix, MaskedPayloads,
    OtError, ReceiverChoices, ReceiverStart, SenderPayloads, SenderStart,
};
use super::phase4::{
    activation_ot_session, activation_transcript_start, advance_transcript, evaluator_inputs,
    export_ot_session, export_transcript_start, prepare_labels, protocol_domain,
    Phase4CeremonyError, PreparedLabels,
};
use super::phase5_transport::{sealed, EofBodyWriter};
use super::process_support::{
    complete_activation_deriver_a, complete_activation_deriver_b, complete_export_deriver_a,
    complete_export_deriver_b, read_exact_frame, require_eof, write_exact_frame,
    CompletedDeriverAActivation, CompletedDeriverAExport, CompletedDeriverBActivation,
    CompletedDeriverBExport, ProcessSupportError, ACTIVATION_DIRECT_MESSAGE_BYTES,
    ACTIVATION_RETURNED_MESSAGE_BYTES, ACTIVATION_TRANSLATION_MESSAGE_BYTES,
    EXPORT_DIRECT_MESSAGE_BYTES, EXPORT_RETURNED_MESSAGE_BYTES, EXPORT_TRANSLATION_MESSAGE_BYTES,
};
use super::roles::{
    ActivationADirectInputLabels, ActivationASelectedOutputLabels, ActivationBOutputDecodeBits,
    ActivationDeriverAStart, ActivationDeriverBStart, DecodedDeriverAActivationShares,
    DecodedDeriverAExportSeedShare, DecodedDeriverBActivationShares,
    DecodedDeriverBExportSeedShare, ExportADirectInputLabels, ExportASelectedOutputLabels,
    ExportBOutputDecodeBits, ExportDeriverAStart, ExportDeriverBStart, RoleBoundaryError,
    ACTIVATION_INPUT_BITS_PER_ROLE, ACTIVATION_OUTPUT_BITS_PER_ROLE, EXPORT_INPUT_BITS_PER_ROLE,
    EXPORT_OUTPUT_BITS_PER_ROLE,
};
use super::runtime::{CircuitRunError, EvaluatorOutputTranslation, ReturnedOutputLabels};
use super::stream::{
    ActivationStream, ExportStream, FixedChunkProfile, FixedStreamFamily, PassiveStreamManifest,
};
use super::stream_io::{
    ExactTableStreamReceipt, StreamIoError, TableStreamSink, TableStreamSource,
};
use super::stream_runtime::{
    activation_evaluator_machine, activation_garbler_machine, export_evaluator_machine,
    export_garbler_machine, EvaluatorAdvance, GarblerAdvance, StreamRuntimeError,
    StreamedPrivateEvaluatorOutputs, StreamedPrivateGarblerOutputs,
};
use super::{Evaluator, Garbler, GlobalDelta};

#[derive(Debug)]
pub(super) enum Phase5ProcessError {
    Control(ProcessSupportError),
    Stream(StreamIoError),
    Runtime(StreamRuntimeError),
    MetricMismatch,
}

impl fmt::Display for Phase5ProcessError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Phase 5 passive process harness failed")
    }
}

impl From<ProcessSupportError> for Phase5ProcessError {
    fn from(error: ProcessSupportError) -> Self {
        Self::Control(error)
    }
}

impl From<Phase4CeremonyError> for Phase5ProcessError {
    fn from(error: Phase4CeremonyError) -> Self {
        Self::Control(error.into())
    }
}

impl From<OtError> for Phase5ProcessError {
    fn from(error: OtError) -> Self {
        Self::Control(error.into())
    }
}

impl From<RoleBoundaryError> for Phase5ProcessError {
    fn from(error: RoleBoundaryError) -> Self {
        Self::Control(error.into())
    }
}

impl From<CircuitRunError> for Phase5ProcessError {
    fn from(error: CircuitRunError) -> Self {
        Self::Control(error.into())
    }
}

impl From<getrandom::Error> for Phase5ProcessError {
    fn from(error: getrandom::Error) -> Self {
        Self::Control(error.into())
    }
}

impl From<StreamIoError> for Phase5ProcessError {
    fn from(error: StreamIoError) -> Self {
        Self::Stream(error)
    }
}

impl From<StreamRuntimeError> for Phase5ProcessError {
    fn from(error: StreamRuntimeError) -> Self {
        Self::Runtime(error)
    }
}

struct AbortOnDropBody<W: EofBodyWriter> {
    writer: Option<W>,
    terminated: bool,
}

impl<W: EofBodyWriter> AbortOnDropBody<W> {
    fn new(writer: W) -> Self {
        Self {
            writer: Some(writer),
            terminated: false,
        }
    }

    fn writer(&mut self) -> std::io::Result<&mut W> {
        if self.terminated {
            return Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "body writer already terminated",
            ));
        }
        self.writer.as_mut().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::BrokenPipe, "body writer unavailable")
        })
    }
}

impl<W: EofBodyWriter> Write for AbortOnDropBody<W> {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.writer()?.write(buffer)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.writer()?.flush()
    }
}

impl<W: EofBodyWriter> sealed::Sealed for AbortOnDropBody<W> {}

impl<W: EofBodyWriter> EofBodyWriter for AbortOnDropBody<W> {
    type Completion = W::Completion;

    fn finish_body(mut self) -> std::io::Result<Self::Completion> {
        let writer = self.writer.take().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::BrokenPipe, "body writer unavailable")
        })?;
        self.terminated = true;
        writer.finish_body()
    }

    fn abort_body(&mut self) -> std::io::Result<()> {
        let result = self.writer()?.abort_body();
        if result.is_ok() {
            self.terminated = true;
        }
        result
    }
}

impl<W: EofBodyWriter> Drop for AbortOnDropBody<W> {
    fn drop(&mut self) {
        if !self.terminated {
            if let Some(writer) = self.writer.as_mut() {
                let _ = writer.abort_body();
            }
            self.terminated = true;
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Phase5StreamMetrics {
    table_payload_bytes: usize,
    body_bytes: u64,
    frame_count: u32,
    peak_table_buffer_bytes: usize,
    peak_arena_bytes: usize,
}

impl Phase5StreamMetrics {
    fn new<F: FixedStreamFamily, C: FixedChunkProfile>(
        table_payload_bytes: usize,
        peak_table_buffer_bytes: usize,
        peak_arena_bytes: usize,
        frame_calls: u32,
        host_boundary_copy_bytes: usize,
        receipt: &ExactTableStreamReceipt<F, C>,
    ) -> Result<Self, Phase5ProcessError> {
        let expected_peak = core::cmp::min(F::TABLE_PAYLOAD_BYTES, C::MAX_PAYLOAD_BYTES);
        if table_payload_bytes != F::TABLE_PAYLOAD_BYTES
            || peak_table_buffer_bytes != expected_peak
            || frame_calls != receipt.frame_count()
            || host_boundary_copy_bytes != 0
        {
            return Err(Phase5ProcessError::MetricMismatch);
        }
        Ok(Self {
            table_payload_bytes,
            body_bytes: receipt.body_bytes(),
            frame_count: receipt.frame_count(),
            peak_table_buffer_bytes,
            peak_arena_bytes,
        })
    }

    pub(super) const fn table_payload_bytes(self) -> usize {
        self.table_payload_bytes
    }

    pub(super) const fn body_bytes(self) -> u64 {
        self.body_bytes
    }

    pub(super) const fn frame_count(self) -> u32 {
        self.frame_count
    }

    pub(super) const fn peak_table_buffer_bytes(self) -> usize {
        self.peak_table_buffer_bytes
    }

    pub(super) const fn peak_arena_bytes(self) -> usize {
        self.peak_arena_bytes
    }
}

macro_rules! define_completed_streamed_role {
    ($name:ident, $inner:ty, $($encode:ident),+ $(,)?) => {
        pub(super) struct $name {
            inner: $inner,
            metrics: Phase5StreamMetrics,
        }

        impl $name {
            fn new(inner: $inner, metrics: Phase5StreamMetrics) -> Self {
                Self { inner, metrics }
            }

            pub(super) const fn stream_metrics(&self) -> Phase5StreamMetrics {
                self.metrics
            }

            $(
                pub(super) fn $encode(&self) -> super::packages::EncodedRecipientPackage {
                    self.inner.$encode()
                }
            )+
        }
    };
}

define_completed_streamed_role!(
    CompletedPhase5DeriverAActivation,
    CompletedDeriverAActivation,
    encode_client_package,
    encode_signing_worker_package,
);
define_completed_streamed_role!(
    CompletedPhase5DeriverBActivation,
    CompletedDeriverBActivation,
    encode_client_package,
    encode_signing_worker_package,
);
define_completed_streamed_role!(
    CompletedPhase5DeriverAExport,
    CompletedDeriverAExport,
    encode_package,
);
define_completed_streamed_role!(
    CompletedPhase5DeriverBExport,
    CompletedDeriverBExport,
    encode_package,
);

macro_rules! define_streamed_family_runners {
    (
        $run_a:ident,
        $run_b:ident,
        $a_start:ty,
        $b_start:ty,
        $a_share:ty,
        $b_share:ty,
        $a_completed:ty,
        $b_completed:ty,
        $a_inner_completed:ty,
        $b_inner_completed:ty,
        $complete_a:ident,
        $complete_b:ident,
        $ot_family:ty,
        $stream_family:ty,
        $direct_message:ty,
        $translation_message:ty,
        $returned_message:ty,
        $transcript_start:ident,
        $ot_session:ident,
        $garbler_machine:ident,
        $evaluator_machine:ident,
        $input_bits:expr,
        $output_bits:expr,
        $direct_bytes:expr,
        $translation_bytes:expr,
        $returned_bytes:expr
    ) => {
        pub(super) fn $run_a<
            C: FixedChunkProfile,
            CR: Read,
            CW: EofBodyWriter,
            TW: EofBodyWriter,
        >(
            start: $a_start,
            mut control_reader: CR,
            control_writer: CW,
            table_writer: TW,
        ) -> Result<$a_completed, Phase5ProcessError> {
            let mut control_writer = AbortOnDropBody::new(control_writer);
            let table_writer = AbortOnDropBody::new(table_writer);
            let a_input = start.into_garbler_input();
            let binding = a_input.binding();
            let mut control_transcript = $transcript_start(binding)?;

            let mut offer_bytes = read_exact_frame(
                &mut control_reader,
                BaseOffer::<$ot_family>::wire_bytes(),
                BaseOffer::<$ot_family>::wire_bytes(),
            )?;
            let offer =
                BaseOffer::<$ot_family>::decode_for_session(&offer_bytes, $ot_session(binding)?)?;
            control_transcript = advance_transcript(control_transcript, &offer_bytes)?;
            offer_bytes.zeroize();

            let garbler = Garbler::new(
                GlobalDelta::random()?,
                protocol_domain(binding.gate_domain())?,
            );
            let PreparedLabels {
                garbler_inputs,
                mut direct_labels,
                ot_pairs,
            } = prepare_labels(&garbler, a_input.bitpacked_lsb0(), $input_bits)?;
            drop(a_input);
            let sender_payloads = SenderPayloads::<$ot_family>::new(ot_pairs)?;
            let (sender_extension, base_choices) =
                SenderStart::<$ot_family>::new().begin_os(offer, sender_payloads)?;

            let mut base_choice_bytes = base_choices.encode();
            write_exact_frame(
                &mut control_writer,
                &base_choice_bytes,
                BaseChoices::<$ot_family>::wire_bytes(),
                BaseChoices::<$ot_family>::wire_bytes(),
            )?;
            control_transcript = advance_transcript(control_transcript, &base_choice_bytes)?;
            base_choice_bytes.zeroize();

            let direct_context = binding.bind_transcript(control_transcript);
            let direct_message =
                <$direct_message>::from_secret_payload(direct_context, &direct_labels)?;
            direct_labels.zeroize();
            let direct_encoded = direct_message.encode();
            write_exact_frame(
                &mut control_writer,
                direct_encoded.as_slice(),
                $direct_bytes,
                $direct_bytes,
            )?;
            control_transcript = advance_transcript(control_transcript, direct_encoded.as_slice())?;
            drop(direct_encoded);
            drop(direct_message);
            control_writer.flush().map_err(ProcessSupportError::from)?;

            let mut extension_bytes = read_exact_frame(
                &mut control_reader,
                ExtensionMatrix::<$ot_family>::wire_bytes(),
                ExtensionMatrix::<$ot_family>::wire_bytes(),
            )?;
            let extension = ExtensionMatrix::<$ot_family>::decode(&extension_bytes)?;
            control_transcript = advance_transcript(control_transcript, &extension_bytes)?;
            extension_bytes.zeroize();

            let masked = sender_extension.accept(extension)?;
            let mut masked_bytes = masked.encode();
            write_exact_frame(
                &mut control_writer,
                &masked_bytes,
                MaskedPayloads::<$ot_family>::wire_bytes(),
                MaskedPayloads::<$ot_family>::wire_bytes(),
            )?;
            control_transcript = advance_transcript(control_transcript, &masked_bytes)?;
            masked_bytes.zeroize();
            control_writer.flush().map_err(ProcessSupportError::from)?;

            let manifest =
                PassiveStreamManifest::<$stream_family, C>::new(binding, control_transcript);
            let mut table_sink = TableStreamSink::new(table_writer, manifest)?;
            let mut garbler_advance =
                $garbler_machine::<C>(garbler, garbler_inputs, $output_bits)?.advance()?;
            let garbler_body = loop {
                match garbler_advance {
                    GarblerAdvance::ChunkReady(chunk) => {
                        table_sink.write_chunk(chunk.payload())?;
                        garbler_advance = chunk.resume().advance()?;
                    }
                    GarblerAdvance::BodyComplete(body) => break body,
                }
            };
            let (_table_completion, exact_receipt) = table_sink.finish()?;
            let StreamedPrivateGarblerOutputs {
                returned_decoder,
                evaluator_translation,
                receipt: stream_receipt,
                peak_arena_bytes,
                peak_table_buffer_bytes,
                table_bytes,
                frame_calls,
                host_boundary_copy_bytes,
                table_buffer_write_bytes,
            } = garbler_body.finalize(exact_receipt)?;
            if table_buffer_write_bytes != table_bytes {
                return Err(Phase5ProcessError::MetricMismatch);
            }
            let metrics = Phase5StreamMetrics::new::<$stream_family, C>(
                table_bytes,
                peak_table_buffer_bytes,
                peak_arena_bytes,
                frame_calls,
                host_boundary_copy_bytes,
                &stream_receipt,
            )?;

            let translation_context = binding.bind_transcript(stream_receipt.final_transcript());
            let translation_message = <$translation_message>::from_secret_payload(
                translation_context,
                evaluator_translation.encoded_bits(),
            )?;
            let translation_encoded = translation_message.encode();
            write_exact_frame(
                &mut control_writer,
                translation_encoded.as_slice(),
                $translation_bytes,
                $translation_bytes,
            )?;
            let mut terminal_transcript = advance_transcript(
                stream_receipt.final_transcript(),
                translation_encoded.as_slice(),
            )?;
            drop(translation_encoded);
            drop(translation_message);
            control_writer.flush().map_err(ProcessSupportError::from)?;
            let _control_completion = control_writer
                .finish_body()
                .map_err(ProcessSupportError::from)?;

            let mut returned_bytes =
                read_exact_frame(&mut control_reader, $returned_bytes, $returned_bytes)?;
            let returned_context = binding.bind_transcript(terminal_transcript);
            let returned_message = <$returned_message>::decode(returned_context, &returned_bytes)?;
            terminal_transcript = advance_transcript(terminal_transcript, &returned_bytes)?;
            returned_bytes.zeroize();
            require_eof(&mut control_reader)?;
            let returned_payload = returned_message.into_secret_payload();
            let returned_labels =
                ReturnedOutputLabels::decode(returned_payload.as_slice(), $output_bits)?;
            drop(returned_payload);
            let mut decoded = returned_decoder.decode(returned_labels)?;
            let parsed = <$a_share>::from_decoded_output(&decoded);
            decoded.zeroize();
            let inner: $a_inner_completed = $complete_a(binding, terminal_transcript, parsed?)?;
            Ok(<$a_completed>::new(inner, metrics))
        }

        pub(super) fn $run_b<C: FixedChunkProfile, CR: Read, CW: EofBodyWriter, TR: Read>(
            start: $b_start,
            mut control_reader: CR,
            control_writer: CW,
            table_reader: TR,
        ) -> Result<$b_completed, Phase5ProcessError> {
            let mut control_writer = AbortOnDropBody::new(control_writer);
            let b_choices = start.into_ot_choices();
            let binding = b_choices.binding();
            let mut control_transcript = $transcript_start(binding)?;
            let ot_session = $ot_session(binding)?;
            let choices = ReceiverChoices::<$ot_family>::from_packed_bytes(
                b_choices.bitpacked_lsb0().to_vec(),
            )?;
            drop(b_choices);
            let (receiver_base, offer) =
                ReceiverStart::<$ot_family>::new().begin_os(ot_session, choices)?;
            let mut offer_bytes = offer.encode();
            write_exact_frame(
                &mut control_writer,
                &offer_bytes,
                BaseOffer::<$ot_family>::wire_bytes(),
                BaseOffer::<$ot_family>::wire_bytes(),
            )?;
            control_transcript = advance_transcript(control_transcript, &offer_bytes)?;
            offer_bytes.zeroize();
            control_writer.flush().map_err(ProcessSupportError::from)?;

            let mut base_choice_bytes = read_exact_frame(
                &mut control_reader,
                BaseChoices::<$ot_family>::wire_bytes(),
                BaseChoices::<$ot_family>::wire_bytes(),
            )?;
            let base_choices = BaseChoices::<$ot_family>::decode(&base_choice_bytes)?;
            control_transcript = advance_transcript(control_transcript, &base_choice_bytes)?;
            base_choice_bytes.zeroize();

            let direct_context = binding.bind_transcript(control_transcript);
            let mut direct_bytes =
                read_exact_frame(&mut control_reader, $direct_bytes, $direct_bytes)?;
            let direct_message = <$direct_message>::decode(direct_context, &direct_bytes)?;
            control_transcript = advance_transcript(control_transcript, &direct_bytes)?;
            direct_bytes.zeroize();

            let (receiver_masked, extension) = receiver_base.accept(base_choices)?;
            let mut extension_bytes = extension.encode();
            write_exact_frame(
                &mut control_writer,
                &extension_bytes,
                ExtensionMatrix::<$ot_family>::wire_bytes(),
                ExtensionMatrix::<$ot_family>::wire_bytes(),
            )?;
            control_transcript = advance_transcript(control_transcript, &extension_bytes)?;
            extension_bytes.zeroize();
            control_writer.flush().map_err(ProcessSupportError::from)?;

            let mut masked_bytes = read_exact_frame(
                &mut control_reader,
                MaskedPayloads::<$ot_family>::wire_bytes(),
                MaskedPayloads::<$ot_family>::wire_bytes(),
            )?;
            let masked = MaskedPayloads::<$ot_family>::decode(&masked_bytes)?;
            control_transcript = advance_transcript(control_transcript, &masked_bytes)?;
            masked_bytes.zeroize();
            let selected = receiver_masked.accept(masked)?;

            let direct_payload = direct_message.into_secret_payload();
            let inputs =
                evaluator_inputs(direct_payload.as_slice(), selected.as_slice(), $input_bits)?;
            drop(direct_payload);
            drop(selected);

            let mut table_source = TableStreamSource::<_, $stream_family, C>::new(
                table_reader,
                binding,
                control_transcript,
            )?;
            let mut evaluator_advance = $evaluator_machine::<C>(
                Evaluator::new(protocol_domain(binding.gate_domain())?),
                inputs,
                $output_bits,
            )?
            .advance()?;
            let evaluator_body = loop {
                match evaluator_advance {
                    EvaluatorAdvance::NeedsFrame(waiting) => {
                        let accepted = table_source
                            .with_next_frame(|frame| waiting.accept_frame(frame))?
                            .ok_or(StreamRuntimeError::UnexpectedEndOfTables)??;
                        evaluator_advance = accepted.advance()?;
                    }
                    EvaluatorAdvance::AwaitingExactEof(body) => break body,
                }
            };
            let (table_reader, exact_receipt) = table_source.finish()?;
            drop(table_reader);
            let StreamedPrivateEvaluatorOutputs {
                returned_labels,
                evaluator_labels,
                receipt: stream_receipt,
                peak_arena_bytes,
                peak_table_buffer_bytes,
                table_bytes,
                frame_calls,
                host_boundary_copy_bytes,
                and_records_decoded,
            } = evaluator_body.finalize(exact_receipt)?;
            if and_records_decoded != <$stream_family as FixedStreamFamily>::AND_GATE_COUNT as usize
            {
                return Err(Phase5ProcessError::MetricMismatch);
            }
            let metrics = Phase5StreamMetrics::new::<$stream_family, C>(
                table_bytes,
                peak_table_buffer_bytes,
                peak_arena_bytes,
                frame_calls,
                host_boundary_copy_bytes,
                &stream_receipt,
            )?;

            let translation_context = binding.bind_transcript(stream_receipt.final_transcript());
            let mut translation_bytes =
                read_exact_frame(&mut control_reader, $translation_bytes, $translation_bytes)?;
            let translation_message =
                <$translation_message>::decode(translation_context, &translation_bytes)?;
            let mut terminal_transcript =
                advance_transcript(stream_receipt.final_transcript(), &translation_bytes)?;
            translation_bytes.zeroize();
            require_eof(&mut control_reader)?;

            let translation_payload = translation_message.into_secret_payload();
            let translation = EvaluatorOutputTranslation::from_encoded_bits(
                translation_payload.as_slice().to_vec(),
                $output_bits,
            )?;
            drop(translation_payload);
            let mut decoded = translation.decode(evaluator_labels)?;
            let parsed = <$b_share>::from_decoded_output(&decoded);
            decoded.zeroize();
            let share = parsed?;

            let returned_context = binding.bind_transcript(terminal_transcript);
            let mut returned_payload = returned_labels.encode();
            let returned_message =
                <$returned_message>::from_secret_payload(returned_context, &returned_payload)?;
            returned_payload.zeroize();
            let returned_encoded = returned_message.encode();
            write_exact_frame(
                &mut control_writer,
                returned_encoded.as_slice(),
                $returned_bytes,
                $returned_bytes,
            )?;
            terminal_transcript =
                advance_transcript(terminal_transcript, returned_encoded.as_slice())?;
            control_writer.flush().map_err(ProcessSupportError::from)?;
            drop(returned_encoded);
            drop(returned_message);
            let _control_completion = control_writer
                .finish_body()
                .map_err(ProcessSupportError::from)?;
            let inner: $b_inner_completed = $complete_b(binding, terminal_transcript, share)?;
            Ok(<$b_completed>::new(inner, metrics))
        }
    };
}

define_streamed_family_runners!(
    run_phase5_activation_deriver_a,
    run_phase5_activation_deriver_b,
    ActivationDeriverAStart,
    ActivationDeriverBStart,
    DecodedDeriverAActivationShares,
    DecodedDeriverBActivationShares,
    CompletedPhase5DeriverAActivation,
    CompletedPhase5DeriverBActivation,
    CompletedDeriverAActivation,
    CompletedDeriverBActivation,
    complete_activation_deriver_a,
    complete_activation_deriver_b,
    ActivationOtFamily,
    ActivationStream,
    ActivationADirectInputLabels,
    ActivationBOutputDecodeBits,
    ActivationASelectedOutputLabels,
    activation_transcript_start,
    activation_ot_session,
    activation_garbler_machine,
    activation_evaluator_machine,
    ACTIVATION_INPUT_BITS_PER_ROLE,
    ACTIVATION_OUTPUT_BITS_PER_ROLE,
    ACTIVATION_DIRECT_MESSAGE_BYTES,
    ACTIVATION_TRANSLATION_MESSAGE_BYTES,
    ACTIVATION_RETURNED_MESSAGE_BYTES
);

define_streamed_family_runners!(
    run_phase5_export_deriver_a,
    run_phase5_export_deriver_b,
    ExportDeriverAStart,
    ExportDeriverBStart,
    DecodedDeriverAExportSeedShare,
    DecodedDeriverBExportSeedShare,
    CompletedPhase5DeriverAExport,
    CompletedPhase5DeriverBExport,
    CompletedDeriverAExport,
    CompletedDeriverBExport,
    complete_export_deriver_a,
    complete_export_deriver_b,
    ExportOtFamily,
    ExportStream,
    ExportADirectInputLabels,
    ExportBOutputDecodeBits,
    ExportASelectedOutputLabels,
    export_transcript_start,
    export_ot_session,
    export_garbler_machine,
    export_evaluator_machine,
    EXPORT_INPUT_BITS_PER_ROLE,
    EXPORT_OUTPUT_BITS_PER_ROLE,
    EXPORT_DIRECT_MESSAGE_BYTES,
    EXPORT_TRANSLATION_MESSAGE_BYTES,
    EXPORT_RETURNED_MESSAGE_BYTES
);

#[cfg(all(test, unix))]
mod tests {
    use std::cell::Cell;
    use std::io::{Result as IoResult, Write};
    use std::os::unix::net::UnixStream;
    use std::rc::Rc;
    use std::thread;
    use std::time::Duration;

    use curve25519_dalek::scalar::Scalar;

    use super::*;
    use crate::passive::phase5_transport::UnixEofBodyWriter;
    use crate::passive::roles::{
        ActivationDeriverAInputs, ActivationDeriverBInputs, ActivationSessionBinding,
        DeriverAClientScalarOutputCoin, DeriverAClientTau, DeriverAClientY, DeriverASeedOutputCoin,
        DeriverAServerTau, DeriverAServerY, DeriverASigningWorkerScalarOutputCoin,
        DeriverBClientScalarOutputCoin, DeriverBClientTau, DeriverBClientY, DeriverBSeedOutputCoin,
        DeriverBServerTau, DeriverBServerY, DeriverBSigningWorkerScalarOutputCoin,
        ExportDeriverAInputs, ExportDeriverBInputs, ExportSessionBinding, SessionId,
    };
    use crate::passive::stream::Chunk64KiB;

    const PACKAGE_TRANSCRIPT_RANGE: core::ops::Range<usize> = 112..144;
    const PACKAGE_SHARE_RANGE: core::ops::Range<usize> = 152..184;

    struct ObservedBodyWriter {
        finish_calls: Rc<Cell<usize>>,
        abort_calls: Rc<Cell<usize>>,
    }

    impl Write for ObservedBodyWriter {
        fn write(&mut self, buffer: &[u8]) -> IoResult<usize> {
            Ok(buffer.len())
        }

        fn flush(&mut self) -> IoResult<()> {
            Ok(())
        }
    }

    impl sealed::Sealed for ObservedBodyWriter {}

    impl EofBodyWriter for ObservedBodyWriter {
        type Completion = ();

        fn finish_body(self) -> IoResult<Self::Completion> {
            self.finish_calls.set(self.finish_calls.get() + 1);
            Ok(())
        }

        fn abort_body(&mut self) -> IoResult<()> {
            self.abort_calls.set(self.abort_calls.get() + 1);
            Ok(())
        }
    }

    #[test]
    fn control_body_has_distinct_success_and_abort_termination() {
        let finish_calls = Rc::new(Cell::new(0));
        let abort_calls = Rc::new(Cell::new(0));
        AbortOnDropBody::new(ObservedBodyWriter {
            finish_calls: Rc::clone(&finish_calls),
            abort_calls: Rc::clone(&abort_calls),
        })
        .finish_body()
        .expect("explicit control EOF");
        assert_eq!(finish_calls.get(), 1);
        assert_eq!(abort_calls.get(), 0);

        drop(AbortOnDropBody::new(ObservedBodyWriter {
            finish_calls: Rc::clone(&finish_calls),
            abort_calls: Rc::clone(&abort_calls),
        }));
        assert_eq!(finish_calls.get(), 1);
        assert_eq!(abort_calls.get(), 1);
    }

    #[test]
    fn process_source_forbids_whole_tables_and_freezes_stream_before_translation() {
        const SOURCE: &str = include_str!("phase5_process.rs");
        let production = SOURCE
            .split_once("#[cfg(all(test, unix))]")
            .expect("tests follow the process runtime")
            .0;

        for forbidden in [
            "Vec<",
            "Vec::",
            "ACTIVATION_TABLE_BYTES",
            "EXPORT_TABLE_BYTES",
            "garble_phase4_activation(",
            "garble_phase4_export(",
            "evaluate_phase4_activation(",
            "evaluate_phase4_export(",
            "garble_phase4_activation_streamed",
            "garble_phase4_export_streamed",
            "evaluate_phase4_activation_streamed",
            "evaluate_phase4_export_streamed",
            "next_and_table_record",
            "TableBodyWriter",
            "finish_table_body",
            "drop(table_writer)",
            "drop(control_writer)",
        ] {
            assert!(
                !production.contains(forbidden),
                "Phase 5 process source contains forbidden whole-table path: {forbidden}"
            );
        }

        let manifest = source_position(
            production,
            "PassiveStreamManifest::<$stream_family, C>::new",
        );
        let streamed_garble = source_position(production, "$garbler_machine::<C>");
        let chunk_write = source_position(production, "table_sink.write_chunk(chunk.payload())?");
        let table_eof = source_position(production, "table_sink.finish()?");
        let garbler_release = source_position(production, "garbler_body.finalize(exact_receipt)?");
        let translations: Vec<usize> = production
            .match_indices("let translation_context")
            .map(|(index, _)| index)
            .collect();
        assert_eq!(translations.len(), 2);
        assert!(manifest < streamed_garble);
        assert!(streamed_garble < chunk_write);
        assert!(chunk_write < table_eof);
        assert!(table_eof < garbler_release);
        assert!(garbler_release < translations[0]);

        let source = source_position(production, "let mut table_source");
        let streamed_evaluate = source_position(production, "$evaluator_machine::<C>");
        let frame_accept = source_position(production, "waiting.accept_frame(frame)");
        let exact_eof = source_position(production, "table_source.finish()?");
        let evaluator_release =
            source_position(production, "evaluator_body.finalize(exact_receipt)?");
        assert!(source < streamed_evaluate);
        assert!(streamed_evaluate < frame_accept);
        assert!(frame_accept < exact_eof);
        assert!(exact_eof < evaluator_release);
        assert!(evaluator_release < translations[1]);
    }

    fn source_position(source: &str, needle: &str) -> usize {
        source
            .find(needle)
            .unwrap_or_else(|| panic!("missing process source marker: {needle}"))
    }

    #[test]
    fn activation_streams_between_separate_roles_with_exact_64k_bounds() {
        let session = SessionId::new([0x61; 32]).expect("session");
        let zero = Scalar::ZERO.to_bytes();
        let a_start = ActivationDeriverAStart::new(
            ActivationSessionBinding::new(session),
            ActivationDeriverAInputs::new(
                DeriverAClientY::from_secret_bytes([7; 32]),
                DeriverAServerY::from_secret_bytes([0; 32]),
                DeriverAClientTau::from_canonical_secret_bytes(zero).expect("A client tau"),
                DeriverAServerTau::from_canonical_secret_bytes(zero).expect("A server tau"),
                DeriverAClientScalarOutputCoin::from_canonical_secret_bytes(
                    Scalar::from(1_u64).to_bytes(),
                )
                .expect("A client coin"),
                DeriverASigningWorkerScalarOutputCoin::from_canonical_secret_bytes(
                    Scalar::from(2_u64).to_bytes(),
                )
                .expect("A worker coin"),
            ),
        );
        let b_start = ActivationDeriverBStart::new(
            ActivationSessionBinding::new(session),
            ActivationDeriverBInputs::new(
                DeriverBClientY::from_secret_bytes([0; 32]),
                DeriverBServerY::from_secret_bytes([0; 32]),
                DeriverBClientTau::from_canonical_secret_bytes(zero).expect("B client tau"),
                DeriverBServerTau::from_canonical_secret_bytes(zero).expect("B server tau"),
                DeriverBClientScalarOutputCoin::from_canonical_secret_bytes(
                    Scalar::from(3_u64).to_bytes(),
                )
                .expect("B client coin"),
                DeriverBSigningWorkerScalarOutputCoin::from_canonical_secret_bytes(
                    Scalar::from(4_u64).to_bytes(),
                )
                .expect("B worker coin"),
            ),
        );

        let (a, b) = run_activation_roles(a_start, b_start);
        assert_stream_metrics(a.stream_metrics(), 2_104_960, 2_107_996, 33, 65_536);
        assert_stream_metrics(b.stream_metrics(), 2_104_960, 2_107_996, 33, 65_536);

        let a_client = a.encode_client_package();
        let a_worker = a.encode_signing_worker_package();
        let b_client = b.encode_client_package();
        let b_worker = b.encode_signing_worker_package();
        let client = parse_scalar(package_share(a_client.as_slice()))
            + parse_scalar(package_share(b_client.as_slice()));
        let worker = parse_scalar(package_share(a_worker.as_slice()))
            + parse_scalar(package_share(b_worker.as_slice()));
        assert_eq!(client, worker);
        assert_ne!(client, Scalar::ZERO);
        assert_matching_transcripts(&[
            a_client.as_slice(),
            a_worker.as_slice(),
            b_client.as_slice(),
            b_worker.as_slice(),
        ]);
    }

    #[test]
    fn export_streams_between_separate_roles_with_exact_64k_bounds() {
        let session = SessionId::new([0x62; 32]).expect("session");
        let expected_seed = [7_u8; 32];
        let a_start = ExportDeriverAStart::new(
            ExportSessionBinding::new(session),
            ExportDeriverAInputs::new(
                DeriverAClientY::from_secret_bytes(expected_seed),
                DeriverAServerY::from_secret_bytes([0; 32]),
                DeriverASeedOutputCoin::from_secret_bytes([1; 32]),
            ),
        );
        let b_start = ExportDeriverBStart::new(
            ExportSessionBinding::new(session),
            ExportDeriverBInputs::new(
                DeriverBClientY::from_secret_bytes([0; 32]),
                DeriverBServerY::from_secret_bytes([0; 32]),
                DeriverBSeedOutputCoin::from_secret_bytes([2; 32]),
            ),
        );

        let (a, b) = run_export_roles(a_start, b_start);
        assert_stream_metrics(a.stream_metrics(), 40_800, 40_892, 1, 40_800);
        assert_stream_metrics(b.stream_metrics(), 40_800, 40_892, 1, 40_800);
        let a_package = a.encode_package();
        let b_package = b.encode_package();
        assert_eq!(
            wrapping_add(
                package_share(a_package.as_slice()),
                package_share(b_package.as_slice())
            ),
            expected_seed
        );
        assert_matching_transcripts(&[a_package.as_slice(), b_package.as_slice()]);
    }

    fn run_activation_roles(
        a_start: ActivationDeriverAStart,
        b_start: ActivationDeriverBStart,
    ) -> (
        CompletedPhase5DeriverAActivation,
        CompletedPhase5DeriverBActivation,
    ) {
        let (a_control, b_control) = UnixStream::pair().expect("control channel");
        let (a_table, b_table) = UnixStream::pair().expect("dedicated table channel");
        configure(&[&a_control, &b_control, &a_table, &b_table]);
        let a_reader = a_control.try_clone().expect("A control reader");
        let b_reader = b_control.try_clone().expect("B control reader");
        let a = thread::spawn(move || {
            run_phase5_activation_deriver_a::<Chunk64KiB, _, _, _>(
                a_start,
                a_reader,
                UnixEofBodyWriter::new(a_control),
                UnixEofBodyWriter::new(a_table),
            )
        });
        let b = thread::spawn(move || {
            run_phase5_activation_deriver_b::<Chunk64KiB, _, _, _>(
                b_start,
                b_reader,
                UnixEofBodyWriter::new(b_control),
                b_table,
            )
        });
        (
            a.join().expect("A thread").expect("A role"),
            b.join().expect("B thread").expect("B role"),
        )
    }

    fn run_export_roles(
        a_start: ExportDeriverAStart,
        b_start: ExportDeriverBStart,
    ) -> (CompletedPhase5DeriverAExport, CompletedPhase5DeriverBExport) {
        let (a_control, b_control) = UnixStream::pair().expect("control channel");
        let (a_table, b_table) = UnixStream::pair().expect("dedicated table channel");
        configure(&[&a_control, &b_control, &a_table, &b_table]);
        let a_reader = a_control.try_clone().expect("A control reader");
        let b_reader = b_control.try_clone().expect("B control reader");
        let a = thread::spawn(move || {
            run_phase5_export_deriver_a::<Chunk64KiB, _, _, _>(
                a_start,
                a_reader,
                UnixEofBodyWriter::new(a_control),
                UnixEofBodyWriter::new(a_table),
            )
        });
        let b = thread::spawn(move || {
            run_phase5_export_deriver_b::<Chunk64KiB, _, _, _>(
                b_start,
                b_reader,
                UnixEofBodyWriter::new(b_control),
                b_table,
            )
        });
        (
            a.join().expect("A thread").expect("A role"),
            b.join().expect("B thread").expect("B role"),
        )
    }

    fn configure(streams: &[&UnixStream]) {
        for stream in streams {
            stream
                .set_read_timeout(Some(Duration::from_secs(20)))
                .expect("read timeout");
            stream
                .set_write_timeout(Some(Duration::from_secs(20)))
                .expect("write timeout");
        }
    }

    fn assert_stream_metrics(
        metrics: Phase5StreamMetrics,
        table_payload_bytes: usize,
        body_bytes: u64,
        frame_count: u32,
        peak_table_buffer_bytes: usize,
    ) {
        assert_eq!(metrics.table_payload_bytes(), table_payload_bytes);
        assert_eq!(metrics.body_bytes(), body_bytes);
        assert_eq!(metrics.frame_count(), frame_count);
        assert_eq!(metrics.peak_table_buffer_bytes(), peak_table_buffer_bytes);
        assert_ne!(metrics.peak_arena_bytes(), 0);
    }

    fn package_share(encoded: &[u8]) -> &[u8; 32] {
        encoded[PACKAGE_SHARE_RANGE]
            .try_into()
            .expect("package share")
    }

    fn parse_scalar(bytes: &[u8; 32]) -> Scalar {
        Option::<Scalar>::from(Scalar::from_canonical_bytes(*bytes)).expect("canonical share")
    }

    fn wrapping_add(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        let mut output = [0_u8; 32];
        let mut carry = 0_u16;
        let mut index = 0_usize;
        while index < output.len() {
            let sum = left[index] as u16 + right[index] as u16 + carry;
            output[index] = sum as u8;
            carry = sum >> 8;
            index += 1;
        }
        output
    }

    fn assert_matching_transcripts(packages: &[&[u8]]) {
        let expected = &packages[0][PACKAGE_TRANSCRIPT_RANGE];
        for package in &packages[1..] {
            assert_eq!(&package[PACKAGE_TRANSCRIPT_RANGE], expected);
        }
    }
}
