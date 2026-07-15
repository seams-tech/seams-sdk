//! Shared control-frame and recipient-package support for the Phase 5 process harness.

use core::fmt;
use std::io::{ErrorKind, Read, Write};

use zeroize::Zeroize;

use super::ot::OtError;
use super::packages::RecipientPackageError;
use super::phase4::Phase4CeremonyError;
use super::roles::RoleBoundaryError;
use super::runtime::CircuitRunError;

pub(super) use super::role_protocol_support::{
    CompletedDeriverAActivation, CompletedDeriverAExport, CompletedDeriverBActivation,
    CompletedDeriverBExport, ACTIVATION_DIRECT_MESSAGE_BYTES, ACTIVATION_RETURNED_MESSAGE_BYTES,
    ACTIVATION_TRANSLATION_MESSAGE_BYTES, EXPORT_DIRECT_MESSAGE_BYTES,
    EXPORT_RETURNED_MESSAGE_BYTES, EXPORT_TRANSLATION_MESSAGE_BYTES,
};

const FRAME_PREFIX_BYTES: usize = 4;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ProcessSupportError {
    Io(ErrorKind),
    FrameTooLarge,
    FrameLength,
    TrailingBytes,
    Ceremony(Phase4CeremonyError),
    Package(RecipientPackageError),
}

impl fmt::Display for ProcessSupportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("passive process support failed")
    }
}

impl From<std::io::Error> for ProcessSupportError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error.kind())
    }
}

impl From<Phase4CeremonyError> for ProcessSupportError {
    fn from(error: Phase4CeremonyError) -> Self {
        Self::Ceremony(error)
    }
}

impl From<OtError> for ProcessSupportError {
    fn from(error: OtError) -> Self {
        Self::Ceremony(error.into())
    }
}

impl From<RoleBoundaryError> for ProcessSupportError {
    fn from(error: RoleBoundaryError) -> Self {
        Self::Ceremony(error.into())
    }
}

impl From<CircuitRunError> for ProcessSupportError {
    fn from(error: CircuitRunError) -> Self {
        Self::Ceremony(error.into())
    }
}

impl From<RecipientPackageError> for ProcessSupportError {
    fn from(error: RecipientPackageError) -> Self {
        Self::Package(error)
    }
}

impl From<getrandom::Error> for ProcessSupportError {
    fn from(error: getrandom::Error) -> Self {
        Self::Ceremony(error.into())
    }
}

pub(super) fn write_exact_frame(
    writer: &mut impl Write,
    payload: &[u8],
    maximum: usize,
    expected: usize,
) -> Result<(), ProcessSupportError> {
    if payload.len() > maximum {
        return Err(ProcessSupportError::FrameTooLarge);
    }
    if payload.len() != expected {
        return Err(ProcessSupportError::FrameLength);
    }
    let encoded_length = u32::try_from(payload.len())
        .map_err(|_| ProcessSupportError::FrameTooLarge)?
        .to_be_bytes();
    writer.write_all(&encoded_length)?;
    writer.write_all(payload)?;
    Ok(())
}

pub(super) fn read_exact_frame(
    reader: &mut impl Read,
    maximum: usize,
    expected: usize,
) -> Result<Vec<u8>, ProcessSupportError> {
    let mut encoded_length = [0_u8; FRAME_PREFIX_BYTES];
    reader.read_exact(&mut encoded_length)?;
    let payload_length = u32::from_be_bytes(encoded_length) as usize;
    if payload_length > maximum {
        return Err(ProcessSupportError::FrameTooLarge);
    }
    if payload_length != expected {
        return Err(ProcessSupportError::FrameLength);
    }
    let mut payload = vec![0_u8; payload_length];
    if let Err(error) = reader.read_exact(&mut payload) {
        payload.zeroize();
        return Err(error.into());
    }
    Ok(payload)
}

pub(super) fn require_eof(reader: &mut impl Read) -> Result<(), ProcessSupportError> {
    let mut trailing = [0_u8; 1];
    let read = reader.read(&mut trailing)?;
    trailing.zeroize();
    if read == 0 {
        Ok(())
    } else {
        Err(ProcessSupportError::TrailingBytes)
    }
}

pub(super) fn complete_activation_deriver_a(
    binding: super::roles::ActivationSessionBinding,
    final_transcript: super::roles::TranscriptDigest32,
    shares: super::roles::DecodedDeriverAActivationShares,
) -> Result<CompletedDeriverAActivation, ProcessSupportError> {
    Ok(super::role_protocol_support::complete_activation_deriver_a(
        binding,
        final_transcript,
        shares,
    )?)
}

pub(super) fn complete_activation_deriver_b(
    binding: super::roles::ActivationSessionBinding,
    final_transcript: super::roles::TranscriptDigest32,
    shares: super::roles::DecodedDeriverBActivationShares,
) -> Result<CompletedDeriverBActivation, ProcessSupportError> {
    Ok(super::role_protocol_support::complete_activation_deriver_b(
        binding,
        final_transcript,
        shares,
    )?)
}

pub(super) fn complete_export_deriver_a(
    binding: super::roles::ExportSessionBinding,
    final_transcript: super::roles::TranscriptDigest32,
    share: super::roles::DecodedDeriverAExportSeedShare,
) -> Result<CompletedDeriverAExport, ProcessSupportError> {
    Ok(super::role_protocol_support::complete_export_deriver_a(
        binding,
        final_transcript,
        share,
    ))
}

pub(super) fn complete_export_deriver_b(
    binding: super::roles::ExportSessionBinding,
    final_transcript: super::roles::TranscriptDigest32,
    share: super::roles::DecodedDeriverBExportSeedShare,
) -> Result<CompletedDeriverBExport, ProcessSupportError> {
    Ok(super::role_protocol_support::complete_export_deriver_b(
        binding,
        final_transcript,
        share,
    ))
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn fixed_frame_codec_rejects_oversize_wrong_length_and_trailing_bytes() {
        let payload = [0x5a_u8; 8];
        let mut encoded = Vec::new();
        write_exact_frame(&mut encoded, &payload, 8, 8).expect("fixed frame");
        let mut reader = Cursor::new(encoded);
        assert_eq!(
            read_exact_frame(&mut reader, 8, 8).expect("fixed frame"),
            payload
        );
        assert!(require_eof(&mut reader).is_ok());

        let mut oversize = Cursor::new([0_u8, 0, 0, 9]);
        assert_eq!(
            read_exact_frame(&mut oversize, 8, 8).err(),
            Some(ProcessSupportError::FrameTooLarge)
        );
        let mut short = Cursor::new([0_u8, 0, 0, 7]);
        assert_eq!(
            read_exact_frame(&mut short, 8, 8).err(),
            Some(ProcessSupportError::FrameLength)
        );
        assert_eq!(
            require_eof(&mut Cursor::new([1_u8])).err(),
            Some(ProcessSupportError::TrailingBytes)
        );
    }
}
