//! Bounded blocking-I/O adapters for the passive benchmark table stream.

#![allow(dead_code)]

use core::fmt;
use std::io::{self, Read};

use zeroize::{Zeroize, Zeroizing};

use super::phase5_transport::EofBodyWriter;
pub(super) use super::stream::ExactTableStreamReceipt;
use super::stream::{
    FixedChunkProfile, FixedStreamFamily, PassiveStreamManifest, StreamWireError,
    TableFrameDecoder, TableFrameEncoder, ValidatedTableFrame, STREAM_MANIFEST_BYTES,
    TABLE_BYTES_PER_AND_GATE, TABLE_FRAME_HEADER_BYTES,
};

#[derive(Debug)]
pub(super) enum StreamIoError {
    Io(io::Error),
    Wire(StreamWireError),
    Aborted,
}

impl fmt::Display for StreamIoError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "passive table stream transport failed: {error}"),
            Self::Wire(error) => write!(formatter, "{error}"),
            Self::Aborted => formatter.write_str("passive table stream adapter already aborted"),
        }
    }
}

impl std::error::Error for StreamIoError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Wire(_) | Self::Aborted => None,
        }
    }
}

impl From<io::Error> for StreamIoError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<StreamWireError> for StreamIoError {
    fn from(error: StreamWireError) -> Self {
        Self::Wire(error)
    }
}

pub(super) struct TableStreamSink<W, F, C>
where
    W: EofBodyWriter,
    F: FixedStreamFamily,
    C: FixedChunkProfile,
{
    writer: Option<W>,
    manifest: PassiveStreamManifest<F, C>,
    encoder: Option<TableFrameEncoder<F, C>>,
    payload_bytes_sent: usize,
    aborted: bool,
    body_terminated: bool,
}

impl<W, F, C> fmt::Debug for TableStreamSink<W, F, C>
where
    W: EofBodyWriter,
    F: FixedStreamFamily,
    C: FixedChunkProfile,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TableStreamSink")
            .field("manifest", &self.manifest)
            .field("payload_bytes_sent", &self.payload_bytes_sent)
            .field("aborted", &self.aborted)
            .field("body_terminated", &self.body_terminated)
            .finish_non_exhaustive()
    }
}

impl<W, F, C> TableStreamSink<W, F, C>
where
    W: EofBodyWriter,
    F: FixedStreamFamily,
    C: FixedChunkProfile,
{
    pub(super) fn new(
        mut writer: W,
        manifest: PassiveStreamManifest<F, C>,
    ) -> Result<Self, StreamIoError> {
        if let Err(error) = writer.write_all(&manifest.encode()) {
            let original = StreamIoError::Io(error);
            return match writer.abort_body() {
                Ok(()) => Err(original),
                Err(abort_error) => Err(StreamIoError::Io(abort_error)),
            };
        }
        Ok(Self {
            writer: Some(writer),
            manifest,
            encoder: Some(manifest.encoder()),
            payload_bytes_sent: 0,
            aborted: false,
            body_terminated: false,
        })
    }

    pub(super) const fn body_bytes(&self) -> u64 {
        self.manifest.body_bytes()
    }

    pub(super) const fn frame_count(&self) -> u32 {
        self.manifest.frame_count()
    }

    pub(super) const fn maximum_frame_payload_bytes(&self) -> usize {
        C::MAX_PAYLOAD_BYTES
    }

    /// Writes one runtime-owned fixed chunk without allocating or copying it.
    pub(super) fn write_chunk(&mut self, payload: &[u8]) -> Result<(), StreamIoError> {
        if self.aborted {
            return Err(self.fail(StreamIoError::Aborted));
        }
        let result = (|| {
            let remaining = self
                .manifest
                .table_payload_bytes()
                .checked_sub(self.payload_bytes_sent)
                .ok_or(StreamWireError::TablePayloadBytes)?;
            if remaining == 0 {
                return Err(StreamIoError::Wire(StreamWireError::TrailingBytes));
            }
            let expected = core::cmp::min(remaining, C::MAX_PAYLOAD_BYTES);
            if payload.len() != expected {
                return Err(StreamIoError::Wire(StreamWireError::PayloadLength));
            }
            write_borrowed_chunk(self, payload)
        })();
        match result {
            Ok(()) => Ok(()),
            Err(error) => Err(self.fail(error)),
        }
    }

    pub(super) fn finish(
        mut self,
    ) -> Result<(W::Completion, ExactTableStreamReceipt<F, C>), StreamIoError> {
        if self.aborted {
            return Err(self.fail(StreamIoError::Aborted));
        }
        if self.payload_bytes_sent != self.manifest.table_payload_bytes() {
            let error = StreamIoError::Wire(StreamWireError::IncompleteStream);
            return Err(self.fail(error));
        }
        let encoder = match self.encoder.take() {
            Some(encoder) => encoder,
            None => return Err(self.fail(StreamIoError::Aborted)),
        };
        let completed_encoder = match encoder.complete() {
            Ok(completed) => completed,
            Err(error) => return Err(self.fail(error.into())),
        };
        let writer = match self.writer.take() {
            Some(writer) => writer,
            None => return Err(self.fail(StreamIoError::Aborted)),
        };
        self.body_terminated = true;
        let completion = writer.finish_body()?;
        let receipt = completed_encoder.confirm_body_closed();
        Ok((completion, receipt))
    }

    fn fail(&mut self, original: StreamIoError) -> StreamIoError {
        self.aborted = true;
        if self.body_terminated {
            return original;
        }
        let abort_result = self
            .writer
            .as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "table writer unavailable"))
            .and_then(EofBodyWriter::abort_body);
        match abort_result {
            Ok(()) => {
                self.body_terminated = true;
                original
            }
            Err(error) => StreamIoError::Io(error),
        }
    }
}

impl<W, F, C> Drop for TableStreamSink<W, F, C>
where
    W: EofBodyWriter,
    F: FixedStreamFamily,
    C: FixedChunkProfile,
{
    fn drop(&mut self) {
        if !self.body_terminated {
            self.aborted = true;
            if let Some(writer) = self.writer.as_mut() {
                if writer.abort_body().is_ok() {
                    self.body_terminated = true;
                }
            }
        }
    }
}

fn write_borrowed_chunk<W, F, C>(
    sink: &mut TableStreamSink<W, F, C>,
    payload: &[u8],
) -> Result<(), StreamIoError>
where
    W: EofBodyWriter,
    F: FixedStreamFamily,
    C: FixedChunkProfile,
{
    let encoder = sink.encoder.as_mut().ok_or(StreamIoError::Aborted)?;
    let header = encoder.encode_next_header(payload)?;
    let writer = sink.writer.as_mut().ok_or(StreamIoError::Aborted)?;
    writer.write_all(header.as_bytes())?;
    writer.write_all(payload)?;
    sink.payload_bytes_sent = sink
        .payload_bytes_sent
        .checked_add(payload.len())
        .ok_or(StreamWireError::TablePayloadBytes)?;
    Ok(())
}

pub(super) struct TableStreamSource<R, F, C>
where
    R: Read,
    F: FixedStreamFamily,
    C: FixedChunkProfile,
{
    reader: R,
    manifest: PassiveStreamManifest<F, C>,
    decoder: Option<TableFrameDecoder<F, C>>,
    header_buffer: [u8; TABLE_FRAME_HEADER_BYTES],
    payload_buffer: Zeroizing<Vec<u8>>,
    frames_read: u32,
    next_and_table_ordinal: u32,
    aborted: bool,
}

impl<R, F, C> fmt::Debug for TableStreamSource<R, F, C>
where
    R: Read,
    F: FixedStreamFamily,
    C: FixedChunkProfile,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TableStreamSource")
            .field("manifest", &self.manifest)
            .field("frames_read", &self.frames_read)
            .field("next_and_table_ordinal", &self.next_and_table_ordinal)
            .field("maximum_buffer_bytes", &self.payload_buffer.len())
            .field("aborted", &self.aborted)
            .finish_non_exhaustive()
    }
}

impl<R, F, C> TableStreamSource<R, F, C>
where
    R: Read,
    F: FixedStreamFamily,
    C: FixedChunkProfile,
{
    pub(super) fn new(
        mut reader: R,
        binding: F::Binding,
        pre_stream_transcript: super::roles::TranscriptDigest32,
    ) -> Result<Self, StreamIoError> {
        let mut encoded_manifest = [0_u8; STREAM_MANIFEST_BYTES];
        read_stream_exact(&mut reader, &mut encoded_manifest)?;
        let manifest = PassiveStreamManifest::<F, C>::decode(
            binding,
            pre_stream_transcript,
            &encoded_manifest,
        )?;
        encoded_manifest.zeroize();
        let payload_buffer_bytes = core::cmp::min(F::TABLE_PAYLOAD_BYTES, C::MAX_PAYLOAD_BYTES);
        Ok(Self {
            reader,
            manifest,
            decoder: Some(manifest.decoder()),
            header_buffer: [0_u8; TABLE_FRAME_HEADER_BYTES],
            payload_buffer: Zeroizing::new(vec![0_u8; payload_buffer_bytes]),
            frames_read: 0,
            next_and_table_ordinal: 0,
            aborted: false,
        })
    }

    pub(super) fn with_next_frame<T>(
        &mut self,
        consume: impl for<'frame> FnOnce(ValidatedTableFrame<'frame, F, C>) -> T,
    ) -> Result<Option<T>, StreamIoError> {
        if self.aborted {
            return Err(StreamIoError::Aborted);
        }
        if self.frames_read == self.manifest.frame_count() {
            if self.next_and_table_ordinal != F::AND_GATE_COUNT {
                self.abort();
                return Err(StreamWireError::AndTableRecordCount.into());
            }
            return Ok(None);
        }
        self.header_buffer.zeroize();
        self.payload_buffer.as_mut_slice().zeroize();
        if let Err(error) = read_stream_exact(&mut self.reader, &mut self.header_buffer) {
            self.abort();
            return Err(error);
        }

        let decoder = self.decoder.take().ok_or(StreamIoError::Aborted)?;
        let pending = match decoder.accept_header(&self.header_buffer) {
            Ok(pending) => pending,
            Err(error) => {
                self.abort();
                return Err(error.into());
            }
        };
        let payload_bytes = pending.expected_payload_bytes();
        if let Err(error) =
            read_stream_exact(&mut self.reader, &mut self.payload_buffer[..payload_bytes])
        {
            self.abort();
            return Err(error);
        }
        let expected_and_table_ordinal = self.next_and_table_ordinal;
        self.aborted = true;
        let frame_result = {
            let payload = PayloadBufferWiper::new(&mut self.payload_buffer[..payload_bytes]);
            match pending.accept_payload(payload.as_slice()) {
                Ok((decoder, validated)) => {
                    let and_table_ordinal_start = validated.and_table_ordinal_start();
                    let and_table_record_count = validated.and_table_record_count();
                    let declared_payload_bytes =
                        (and_table_record_count as usize).checked_mul(TABLE_BYTES_PER_AND_GATE);
                    let next_and_table_ordinal =
                        and_table_ordinal_start.checked_add(and_table_record_count);
                    if and_table_ordinal_start != expected_and_table_ordinal
                        || declared_payload_bytes != Some(payload_bytes)
                    {
                        Err(StreamWireError::AndTableRecordCount)
                    } else if let Some(next_and_table_ordinal) = next_and_table_ordinal {
                        let output = consume(validated);
                        Ok((decoder, next_and_table_ordinal, output))
                    } else {
                        Err(StreamWireError::AndTableRecordCount)
                    }
                }
                Err(error) => Err(error),
            }
        };
        let (decoder, next_and_table_ordinal, output) = match frame_result {
            Ok(accepted) => accepted,
            Err(error) => {
                self.abort();
                return Err(error.into());
            }
        };
        self.decoder = Some(decoder);
        self.frames_read = match self.frames_read.checked_add(1) {
            Some(frames_read) => frames_read,
            None => {
                self.abort();
                return Err(StreamWireError::FrameCount.into());
            }
        };
        self.next_and_table_ordinal = next_and_table_ordinal;
        self.aborted = false;
        self.header_buffer.zeroize();
        Ok(Some(output))
    }

    pub(super) const fn body_bytes(&self) -> u64 {
        self.manifest.body_bytes()
    }

    pub(super) const fn frame_count(&self) -> u32 {
        self.manifest.frame_count()
    }

    pub(super) const fn maximum_frame_payload_bytes(&self) -> usize {
        C::MAX_PAYLOAD_BYTES
    }

    pub(super) fn finish(mut self) -> Result<(R, ExactTableStreamReceipt<F, C>), StreamIoError> {
        self.header_buffer.zeroize();
        self.payload_buffer.as_mut_slice().zeroize();
        if self.aborted {
            return Err(StreamIoError::Aborted);
        }
        if self.frames_read != self.manifest.frame_count() {
            return Err(StreamWireError::UnexpectedEof.into());
        }
        if self.next_and_table_ordinal != F::AND_GATE_COUNT {
            return Err(StreamWireError::IncompleteStream.into());
        }
        require_exact_eof(&mut self.reader)?;
        let decoder = self.decoder.take().ok_or(StreamIoError::Aborted)?;
        let receipt = decoder.finish_after_exact_eof()?;
        Ok((self.reader, receipt))
    }

    fn abort(&mut self) {
        self.aborted = true;
        self.header_buffer.zeroize();
        self.payload_buffer.as_mut_slice().zeroize();
    }
}

struct PayloadBufferWiper<'a> {
    payload: &'a mut [u8],
}

impl<'a> PayloadBufferWiper<'a> {
    fn new(payload: &'a mut [u8]) -> Self {
        Self { payload }
    }

    fn as_slice(&self) -> &[u8] {
        self.payload
    }
}

impl Drop for PayloadBufferWiper<'_> {
    fn drop(&mut self) {
        self.payload.zeroize();
    }
}

fn read_stream_exact(reader: &mut impl Read, bytes: &mut [u8]) -> Result<(), StreamIoError> {
    match reader.read_exact(bytes) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
            Err(StreamWireError::UnexpectedEof.into())
        }
        Err(error) => Err(error.into()),
    }
}

fn require_exact_eof(reader: &mut impl Read) -> Result<(), StreamIoError> {
    let mut trailing = [0_u8; 1];
    loop {
        match reader.read(&mut trailing) {
            Ok(0) => return Ok(()),
            Ok(_) => {
                trailing.zeroize();
                return Err(StreamWireError::TrailingBytes.into());
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::io::Cursor;
    use std::io::Write;
    use std::rc::Rc;

    use super::*;
    use crate::passive::phase5_transport::sealed;
    use crate::passive::roles::{
        ActivationSessionBinding, ExportSessionBinding, SessionId, TranscriptDigest32,
    };
    use crate::passive::stream::{
        ActivationStream, ActivationStreamManifest, Chunk64KiB, ExportStream, ExportStreamManifest,
    };

    fn activation_binding() -> ActivationSessionBinding {
        ActivationSessionBinding::new(SessionId::new([0x41; 32]).expect("session"))
    }

    fn export_binding() -> ExportSessionBinding {
        ExportSessionBinding::new(SessionId::new([0x45; 32]).expect("session"))
    }

    fn transcript() -> TranscriptDigest32 {
        TranscriptDigest32::new([0x54; 32]).expect("transcript")
    }

    fn fill_pattern(bytes: &mut [u8], seed: u8) {
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = (index as u8).wrapping_mul(29).wrapping_add(seed);
        }
    }

    #[derive(Debug)]
    struct ShortWriter {
        bytes: Vec<u8>,
        maximum_write: usize,
        calls: usize,
        finished: bool,
    }

    impl ShortWriter {
        fn new(maximum_write: usize) -> Self {
            Self {
                bytes: Vec::new(),
                maximum_write,
                calls: 0,
                finished: false,
            }
        }
    }

    impl Write for ShortWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.calls += 1;
            let accepted = core::cmp::min(bytes.len(), self.maximum_write);
            self.bytes.extend_from_slice(&bytes[..accepted]);
            Ok(accepted)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl sealed::Sealed for ShortWriter {}

    impl EofBodyWriter for ShortWriter {
        type Completion = Self;

        fn finish_body(mut self) -> io::Result<Self::Completion> {
            self.flush()?;
            self.finished = true;
            Ok(self)
        }

        fn abort_body(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[derive(Debug)]
    struct ShortReader<R> {
        inner: R,
        maximum_read: usize,
        calls: usize,
    }

    impl<R> ShortReader<R> {
        fn new(inner: R, maximum_read: usize) -> Self {
            Self {
                inner,
                maximum_read,
                calls: 0,
            }
        }
    }

    impl<R: Read> Read for ShortReader<R> {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            self.calls += 1;
            let allowed = core::cmp::min(bytes.len(), self.maximum_read);
            self.inner.read(&mut bytes[..allowed])
        }
    }

    #[derive(Debug)]
    struct DisconnectWriter {
        accepted: usize,
        disconnect_after: usize,
        abort_calls: usize,
    }

    struct InjectedWriteError {
        accepted: usize,
        fail_after: usize,
        error_kind: io::ErrorKind,
        abort_calls: Rc<Cell<usize>>,
    }

    impl Write for InjectedWriteError {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.accepted == self.fail_after {
                return Err(io::Error::new(self.error_kind, "injected write failure"));
            }
            let remaining = self.fail_after - self.accepted;
            let accepted = core::cmp::min(bytes.len(), remaining);
            self.accepted += accepted;
            Ok(accepted)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl sealed::Sealed for InjectedWriteError {}

    impl EofBodyWriter for InjectedWriteError {
        type Completion = ();

        fn finish_body(self) -> io::Result<Self::Completion> {
            Ok(())
        }

        fn abort_body(&mut self) -> io::Result<()> {
            self.abort_calls.set(self.abort_calls.get() + 1);
            Ok(())
        }
    }

    struct InjectedReadError<R> {
        inner: R,
        accepted: usize,
        fail_after: usize,
        error_kind: io::ErrorKind,
    }

    impl<R: Read> Read for InjectedReadError<R> {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            if self.accepted == self.fail_after {
                return Err(io::Error::new(self.error_kind, "injected read failure"));
            }
            let remaining = self.fail_after - self.accepted;
            let accepted = core::cmp::min(bytes.len(), remaining);
            let read = self.inner.read(&mut bytes[..accepted])?;
            self.accepted += read;
            Ok(read)
        }
    }

    impl Write for DisconnectWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.accepted == self.disconnect_after {
                return Err(io::Error::new(io::ErrorKind::BrokenPipe, "disconnected"));
            }
            let remaining = self.disconnect_after - self.accepted;
            let accepted = core::cmp::min(bytes.len(), remaining);
            self.accepted += accepted;
            Ok(accepted)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl sealed::Sealed for DisconnectWriter {}

    impl EofBodyWriter for DisconnectWriter {
        type Completion = Self;

        fn finish_body(self) -> io::Result<Self::Completion> {
            Ok(self)
        }

        fn abort_body(&mut self) -> io::Result<()> {
            self.abort_calls += 1;
            Ok(())
        }
    }

    #[derive(Debug, Default)]
    struct FinishFailWriter {
        bytes: usize,
    }

    impl Write for FinishFailWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.bytes += bytes.len();
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl sealed::Sealed for FinishFailWriter {}

    impl EofBodyWriter for FinishFailWriter {
        type Completion = ();

        fn finish_body(self) -> io::Result<Self::Completion> {
            Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "table close failed",
            ))
        }

        fn abort_body(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[derive(Debug, Default)]
    struct CountingWriter {
        bytes: usize,
        largest_request: usize,
        abort_calls: usize,
    }

    impl Write for CountingWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.bytes += bytes.len();
            self.largest_request = core::cmp::max(self.largest_request, bytes.len());
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl sealed::Sealed for CountingWriter {}

    impl EofBodyWriter for CountingWriter {
        type Completion = Self;

        fn finish_body(mut self) -> io::Result<Self::Completion> {
            self.flush()?;
            Ok(self)
        }

        fn abort_body(&mut self) -> io::Result<()> {
            self.abort_calls += 1;
            Ok(())
        }
    }

    struct AbortObserverWriter {
        abort_calls: Rc<Cell<usize>>,
    }

    impl Write for AbortObserverWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl sealed::Sealed for AbortObserverWriter {}

    impl EofBodyWriter for AbortObserverWriter {
        type Completion = ();

        fn finish_body(self) -> io::Result<Self::Completion> {
            Ok(())
        }

        fn abort_body(&mut self) -> io::Result<()> {
            self.abort_calls.set(self.abort_calls.get() + 1);
            Ok(())
        }
    }

    type EncodedExport = (
        Vec<u8>,
        ExactTableStreamReceipt<ExportStream, Chunk64KiB>,
        usize,
    );

    fn encoded_export(maximum_write: usize) -> EncodedExport {
        let manifest = ExportStreamManifest::<Chunk64KiB>::new(export_binding(), transcript());
        let mut sink = TableStreamSink::new(ShortWriter::new(maximum_write), manifest)
            .expect("manifest write");
        let mut payload = Zeroizing::new(vec![0_u8; manifest.table_payload_bytes()]);
        fill_pattern(&mut payload, 7);
        sink.write_chunk(&payload).expect("frame write");
        payload.zeroize();
        let (writer, receipt) = sink.finish().expect("sink finish");
        assert!(writer.finished);
        (writer.bytes, receipt, writer.calls)
    }

    #[test]
    fn one_byte_short_reads_and_writes_round_trip_with_exact_eof() {
        let (encoded, sender_receipt, write_calls) = encoded_export(1);
        assert!(write_calls > 40_000);
        let reader = ShortReader::new(Cursor::new(encoded), 1);
        let mut source = TableStreamSource::<_, ExportStream, Chunk64KiB>::new(
            reader,
            export_binding(),
            transcript(),
        )
        .expect("manifest read");
        assert_eq!(
            source.payload_buffer.len(),
            ExportStream::TABLE_PAYLOAD_BYTES
        );
        assert_eq!(
            source.payload_buffer.capacity(),
            ExportStream::TABLE_PAYLOAD_BYTES
        );

        let source_buffer_address = source.payload_buffer.as_ptr();
        source
            .with_next_frame(|frame| {
                assert_eq!(frame.and_table_ordinal_start(), 0);
                assert_eq!(frame.and_table_record_count(), ExportStream::AND_GATE_COUNT);
                assert_eq!(frame.payload().len(), ExportStream::TABLE_PAYLOAD_BYTES);
                assert_eq!(frame.payload().as_ptr(), source_buffer_address);
                for (index, byte) in frame.payload().iter().enumerate() {
                    assert_eq!(*byte, (index as u8).wrapping_mul(29).wrapping_add(7));
                }
            })
            .expect("validated frame")
            .expect("frame");
        assert!(source.payload_buffer.iter().all(|byte| *byte == 0));
        assert!(source
            .with_next_frame(|_| ())
            .expect("complete stream")
            .is_none());
        let (reader, receiver_receipt) = source.finish().expect("exact EOF");
        assert_eq!(sender_receipt, receiver_receipt);
        assert!(reader.calls > 40_000);
    }

    #[test]
    fn activation_sink_uses_only_the_runtime_owned_64kib_buffer() {
        let manifest =
            ActivationStreamManifest::<Chunk64KiB>::new(activation_binding(), transcript());
        let mut sink = TableStreamSink::new(CountingWriter::default(), manifest).expect("sink");
        assert_eq!(sink.body_bytes(), manifest.body_bytes());
        assert_eq!(sink.frame_count(), manifest.frame_count());
        assert_eq!(sink.maximum_frame_payload_bytes(), 64 * 1_024);

        let mut runtime_chunk = Zeroizing::new(vec![0_u8; Chunk64KiB::MAX_PAYLOAD_BYTES]);
        let address = runtime_chunk.as_ptr();
        let mut remaining = manifest.table_payload_bytes();
        let mut sequence = 0_u8;
        while remaining != 0 {
            let chunk_bytes = core::cmp::min(remaining, Chunk64KiB::MAX_PAYLOAD_BYTES);
            for byte in runtime_chunk[..chunk_bytes].chunks_mut(1) {
                byte[0] = sequence.wrapping_add(1);
            }
            sink.write_chunk(&runtime_chunk[..chunk_bytes])
                .expect("bounded write");
            runtime_chunk.as_mut_slice().zeroize();
            assert_eq!(runtime_chunk.as_ptr(), address);
            assert!(runtime_chunk.iter().all(|byte| *byte == 0));
            remaining -= chunk_bytes;
            sequence = sequence.wrapping_add(1);
        }
        let (writer, receipt) = sink.finish().expect("finish");
        assert_eq!(receipt.frame_count(), manifest.frame_count());
        assert_eq!(
            writer.bytes,
            STREAM_MANIFEST_BYTES + manifest.body_bytes() as usize
        );
        assert!(writer.largest_request <= Chunk64KiB::MAX_PAYLOAD_BYTES);
    }

    #[test]
    fn activation_source_reuses_one_frame_buffer_without_record_copies() {
        let manifest =
            ActivationStreamManifest::<Chunk64KiB>::new(activation_binding(), transcript());
        let mut encoder = manifest.encoder();
        let mut encoded = manifest.encode().to_vec();
        let mut payload = Zeroizing::new(vec![0x31_u8; Chunk64KiB::MAX_PAYLOAD_BYTES]);
        for sequence in 0..2_u8 {
            payload.fill(sequence.wrapping_add(0x31));
            let header = encoder
                .encode_next_header(&payload)
                .expect("full activation frame");
            encoded.extend_from_slice(header.as_bytes());
            encoded.extend_from_slice(&payload);
        }
        payload.zeroize();

        let mut source = TableStreamSource::<_, ActivationStream, Chunk64KiB>::new(
            Cursor::new(encoded),
            activation_binding(),
            transcript(),
        )
        .expect("activation source");
        let buffer_address = source.payload_buffer.as_ptr();
        for sequence in 0..2_u32 {
            source
                .with_next_frame(|frame| {
                    assert_eq!(frame.payload().as_ptr(), buffer_address);
                    assert_eq!(frame.and_table_ordinal_start(), sequence * 2_048);
                    assert_eq!(frame.and_table_record_count(), 2_048);
                    assert_eq!(frame.payload().len(), Chunk64KiB::MAX_PAYLOAD_BYTES);
                })
                .expect("frame")
                .expect("present frame");
            assert!(source.payload_buffer.iter().all(|byte| *byte == 0));
        }
        assert!(matches!(
            source.with_next_frame(|_| ()),
            Err(StreamIoError::Wire(StreamWireError::UnexpectedEof))
        ));
        assert!(matches!(
            source.with_next_frame(|_| ()),
            Err(StreamIoError::Aborted)
        ));
    }

    #[test]
    fn header_and_payload_truncation_abort_and_zeroize_the_source() {
        let (encoded, _, _) = encoded_export(usize::MAX);
        let header_end = STREAM_MANIFEST_BYTES + TABLE_FRAME_HEADER_BYTES - 1;
        let mut source = TableStreamSource::<_, ExportStream, Chunk64KiB>::new(
            Cursor::new(&encoded[..header_end]),
            export_binding(),
            transcript(),
        )
        .expect("manifest");
        assert!(matches!(
            source.with_next_frame(|_| ()),
            Err(StreamIoError::Wire(StreamWireError::UnexpectedEof))
        ));
        assert!(source.header_buffer.iter().all(|byte| *byte == 0));
        assert!(matches!(
            source.with_next_frame(|_| ()),
            Err(StreamIoError::Aborted)
        ));

        let mut source = TableStreamSource::<_, ExportStream, Chunk64KiB>::new(
            Cursor::new(&encoded[..encoded.len() - 1]),
            export_binding(),
            transcript(),
        )
        .expect("manifest");
        assert!(matches!(
            source.with_next_frame(|_| ()),
            Err(StreamIoError::Wire(StreamWireError::UnexpectedEof))
        ));
        assert!(source.payload_buffer.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn panicking_frame_consumer_zeroizes_and_poisons_the_source() {
        let (encoded, _, _) = encoded_export(usize::MAX);
        let mut source = TableStreamSource::<_, ExportStream, Chunk64KiB>::new(
            Cursor::new(encoded),
            export_binding(),
            transcript(),
        )
        .expect("manifest");
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = source.with_next_frame::<()>(|_| panic!("consumer failed"));
        }));
        assert!(panic.is_err());
        assert!(source.payload_buffer.iter().all(|byte| *byte == 0));
        assert!(matches!(
            source.with_next_frame(|_| ()),
            Err(StreamIoError::Aborted)
        ));
    }

    #[test]
    fn exact_eof_rejects_a_trailing_byte_after_all_frames() {
        let (mut encoded, _, _) = encoded_export(usize::MAX);
        encoded.push(1);
        let mut source = TableStreamSource::<_, ExportStream, Chunk64KiB>::new(
            Cursor::new(encoded),
            export_binding(),
            transcript(),
        )
        .expect("manifest");
        source
            .with_next_frame(|_| ())
            .expect("frame")
            .expect("one frame");
        assert!(source
            .with_next_frame(|_| ())
            .expect("complete stream")
            .is_none());
        assert!(matches!(
            source.finish(),
            Err(StreamIoError::Wire(StreamWireError::TrailingBytes))
        ));
    }

    #[test]
    fn sink_disconnect_is_terminal() {
        let writer = DisconnectWriter {
            accepted: 0,
            disconnect_after: STREAM_MANIFEST_BYTES + TABLE_FRAME_HEADER_BYTES + 17,
            abort_calls: 0,
        };
        let manifest = ExportStreamManifest::<Chunk64KiB>::new(export_binding(), transcript());
        let mut sink = TableStreamSink::new(writer, manifest).expect("manifest");
        let mut runtime_chunk = Zeroizing::new(vec![0xA5; manifest.table_payload_bytes()]);
        let error = sink.write_chunk(&runtime_chunk).expect_err("disconnect");
        runtime_chunk.as_mut_slice().zeroize();
        assert!(matches!(
            error,
            StreamIoError::Io(ref io_error) if io_error.kind() == io::ErrorKind::BrokenPipe
        ));
        assert_eq!(
            sink.writer
                .as_ref()
                .expect("aborted writer retained")
                .abort_calls,
            1
        );
        assert!(matches!(
            sink.write_chunk(&runtime_chunk),
            Err(StreamIoError::Aborted)
        ));

        let manifest = ExportStreamManifest::<Chunk64KiB>::new(export_binding(), transcript());
        let mut sink = TableStreamSink::new(CountingWriter::default(), manifest).expect("sink");
        let payload = Zeroizing::new(vec![0_u8; manifest.table_payload_bytes()]);
        assert!(matches!(
            sink.write_chunk(&payload[..payload.len() - TABLE_BYTES_PER_AND_GATE]),
            Err(StreamIoError::Wire(StreamWireError::PayloadLength))
        ));
        assert_eq!(
            sink.writer
                .as_ref()
                .expect("aborted writer retained")
                .abort_calls,
            1
        );
        assert!(matches!(
            sink.write_chunk(&payload),
            Err(StreamIoError::Aborted)
        ));

        let mut sink =
            TableStreamSink::new(FinishFailWriter::default(), manifest).expect("manifest write");
        sink.write_chunk(&payload).expect("complete table write");
        assert!(matches!(
            sink.finish(),
            Err(StreamIoError::Io(ref error)) if error.kind() == io::ErrorKind::BrokenPipe
        ));
    }

    #[test]
    fn timed_out_and_would_block_writes_abort_and_cannot_mint_a_receipt() {
        for error_kind in [io::ErrorKind::TimedOut, io::ErrorKind::WouldBlock] {
            let abort_calls = Rc::new(Cell::new(0));
            let writer = InjectedWriteError {
                accepted: 0,
                fail_after: STREAM_MANIFEST_BYTES + TABLE_FRAME_HEADER_BYTES + 17,
                error_kind,
                abort_calls: Rc::clone(&abort_calls),
            };
            let manifest = ExportStreamManifest::<Chunk64KiB>::new(export_binding(), transcript());
            let mut sink = TableStreamSink::new(writer, manifest).expect("manifest");
            let mut runtime_chunk = Zeroizing::new(vec![0xA5; manifest.table_payload_bytes()]);

            let error = sink
                .write_chunk(&runtime_chunk)
                .expect_err("transient write error is terminal");
            assert!(matches!(
                error,
                StreamIoError::Io(ref error) if error.kind() == error_kind
            ));
            assert_eq!(abort_calls.get(), 1);
            runtime_chunk.as_mut_slice().zeroize();
            assert!(runtime_chunk.iter().all(|byte| *byte == 0));
            assert!(matches!(
                sink.write_chunk(&runtime_chunk),
                Err(StreamIoError::Aborted)
            ));
            assert!(matches!(sink.finish(), Err(StreamIoError::Aborted)));
            assert_eq!(abort_calls.get(), 1);
        }
    }

    #[test]
    fn timed_out_and_would_block_reads_poison_zeroize_and_cannot_mint_a_receipt() {
        let (encoded, _, _) = encoded_export(usize::MAX);
        for error_kind in [io::ErrorKind::TimedOut, io::ErrorKind::WouldBlock] {
            let reader = InjectedReadError {
                inner: Cursor::new(encoded.as_slice()),
                accepted: 0,
                fail_after: STREAM_MANIFEST_BYTES + TABLE_FRAME_HEADER_BYTES + 17,
                error_kind,
            };
            let mut source = TableStreamSource::<_, ExportStream, Chunk64KiB>::new(
                reader,
                export_binding(),
                transcript(),
            )
            .expect("manifest");

            let error = source
                .with_next_frame(|_| ())
                .expect_err("transient read error is terminal");
            assert!(matches!(
                error,
                StreamIoError::Io(ref error) if error.kind() == error_kind
            ));
            assert!(source.header_buffer.iter().all(|byte| *byte == 0));
            assert!(source.payload_buffer.iter().all(|byte| *byte == 0));
            assert!(matches!(
                source.with_next_frame(|_| ()),
                Err(StreamIoError::Aborted)
            ));
            assert!(matches!(source.finish(), Err(StreamIoError::Aborted)));
        }
    }

    #[test]
    fn timed_out_and_would_block_are_never_accepted_as_exact_eof() {
        let (encoded, _, _) = encoded_export(usize::MAX);
        for error_kind in [io::ErrorKind::TimedOut, io::ErrorKind::WouldBlock] {
            let reader = InjectedReadError {
                inner: Cursor::new(encoded.as_slice()),
                accepted: 0,
                fail_after: encoded.len(),
                error_kind,
            };
            let mut source = TableStreamSource::<_, ExportStream, Chunk64KiB>::new(
                reader,
                export_binding(),
                transcript(),
            )
            .expect("manifest");
            source
                .with_next_frame(|_| ())
                .expect("frame")
                .expect("present frame");
            assert!(source.payload_buffer.iter().all(|byte| *byte == 0));

            assert!(matches!(
                source.finish(),
                Err(StreamIoError::Io(ref error)) if error.kind() == error_kind
            ));
        }
    }

    #[test]
    fn dropping_an_unfinished_sink_aborts_the_table_body_once() {
        let abort_calls = Rc::new(Cell::new(0));
        let writer = AbortObserverWriter {
            abort_calls: Rc::clone(&abort_calls),
        };
        let manifest = ExportStreamManifest::<Chunk64KiB>::new(export_binding(), transcript());
        {
            let _sink = TableStreamSink::new(writer, manifest).expect("manifest write");
        }
        assert_eq!(abort_calls.get(), 1);
    }

    #[test]
    fn implementation_excludes_text_transports_and_whole_table_allocation() {
        let source = include_str!("stream_io.rs");
        let implementation = source
            .split("#[cfg(test)]")
            .next()
            .expect("implementation prefix");
        let forbidden_text = [
            ["JS", "ON"].concat(),
            ["base", "64"].concat(),
            ["array", "Buffer"].concat(),
            ["Router", " relay"].concat(),
            ["post_service", "_json"].concat(),
        ];
        for needle in forbidden_text {
            assert!(!implementation.contains(&needle), "forbidden path {needle}");
        }

        let sink_source = implementation
            .split("pub(super) struct TableStreamSource")
            .next()
            .expect("sink prefix");
        assert!(!sink_source.contains("Vec<"));
        assert!(!sink_source.contains("vec!["));
        let whole_table_allocations = [
            ["vec![0_u8; ", "F::TABLE_PAYLOAD_BYTES]"].concat(),
            ["Vec::with_capacity(", "F::TABLE_PAYLOAD_BYTES)"].concat(),
            ["Vec::with_capacity(", "manifest.table_payload_bytes())"].concat(),
        ];
        for needle in whole_table_allocations {
            assert!(
                !implementation.contains(&needle),
                "forbidden whole-body allocation {needle}"
            );
        }
        assert!(
            implementation.contains("core::cmp::min(F::TABLE_PAYLOAD_BYTES, C::MAX_PAYLOAD_BYTES)")
        );
        assert!(implementation.contains("vec![0_u8; payload_buffer_bytes]"));
        let legacy_record_api = ["next_and_table_", "record"].concat();
        let legacy_record_type = ["ValidatedAndTable", "Record"].concat();
        let io_specific_frame_type = ["ValidatedTable", "StreamFrame"].concat();
        let direct_frame_api = ["pub(super) fn next_", "frame"].concat();
        assert!(!implementation.contains(&legacy_record_api));
        assert!(!implementation.contains(&legacy_record_type));
        assert!(!implementation.contains(&io_specific_frame_type));
        assert!(!implementation.contains(&direct_frame_api));
        assert!(!implementation.contains("copy_from_slice"));
        assert!(implementation.contains("ValidatedTableFrame<'frame, F, C>"));
    }
}
