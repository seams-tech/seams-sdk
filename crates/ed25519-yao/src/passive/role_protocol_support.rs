//! Transport-neutral recipient completion shared by benchmark role runners.

#![allow(dead_code)]

use super::packages::{
    DeriverAClientScalarPackage, DeriverAExportSeedPackage, DeriverASigningWorkerScalarPackage,
    DeriverBClientScalarPackage, DeriverBExportSeedPackage, DeriverBSigningWorkerScalarPackage,
    EncodedRecipientPackage, RecipientPackageError,
};
use super::roles::{
    ActivationDeriverAInputs, ActivationDeriverAStart, ActivationDeriverBInputs,
    ActivationDeriverBStart, ActivationSessionBinding, DecodedDeriverAActivationShares,
    DecodedDeriverAExportSeedShare, DecodedDeriverBActivationShares,
    DecodedDeriverBExportSeedShare, DeriverAClientScalarOutputCoin, DeriverAClientTau,
    DeriverAClientY, DeriverASeedOutputCoin, DeriverAServerTau, DeriverAServerY,
    DeriverASigningWorkerScalarOutputCoin, DeriverBClientScalarOutputCoin, DeriverBClientTau,
    DeriverBClientY, DeriverBSeedOutputCoin, DeriverBServerTau, DeriverBServerY,
    DeriverBSigningWorkerScalarOutputCoin, ExportDeriverAInputs, ExportDeriverAStart,
    ExportDeriverBInputs, ExportDeriverBStart, ExportSessionBinding, RoleBoundaryError, SessionId,
    TranscriptDigest32, ACTIVATION_INPUT_BITS_PER_ROLE, ACTIVATION_OUTPUT_BITS_PER_ROLE,
    EXPORT_INPUT_BITS_PER_ROLE, EXPORT_OUTPUT_BITS_PER_ROLE,
};

const ZERO: [u8; 32] = [0_u8; 32];
pub(super) const FIXTURE_SEED: [u8; 32] = [
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
];

const ROLE_MESSAGE_HEADER_BYTES: usize = 156;
const LABEL_BYTES: usize = 16;

pub(super) const ACTIVATION_DIRECT_MESSAGE_BYTES: usize =
    ROLE_MESSAGE_HEADER_BYTES + ACTIVATION_INPUT_BITS_PER_ROLE * LABEL_BYTES;
pub(super) const EXPORT_DIRECT_MESSAGE_BYTES: usize =
    ROLE_MESSAGE_HEADER_BYTES + EXPORT_INPUT_BITS_PER_ROLE * LABEL_BYTES;
pub(super) const ACTIVATION_TRANSLATION_MESSAGE_BYTES: usize =
    ROLE_MESSAGE_HEADER_BYTES + ACTIVATION_OUTPUT_BITS_PER_ROLE / 8;
pub(super) const EXPORT_TRANSLATION_MESSAGE_BYTES: usize =
    ROLE_MESSAGE_HEADER_BYTES + EXPORT_OUTPUT_BITS_PER_ROLE / 8;
pub(super) const ACTIVATION_RETURNED_MESSAGE_BYTES: usize =
    ROLE_MESSAGE_HEADER_BYTES + ACTIVATION_OUTPUT_BITS_PER_ROLE * LABEL_BYTES;
pub(super) const EXPORT_RETURNED_MESSAGE_BYTES: usize =
    ROLE_MESSAGE_HEADER_BYTES + EXPORT_OUTPUT_BITS_PER_ROLE * LABEL_BYTES;

pub(super) fn activation_deriver_a_fixture_start(
    session: [u8; 32],
) -> Result<ActivationDeriverAStart, RoleBoundaryError> {
    let binding = ActivationSessionBinding::new(SessionId::new(session)?);
    Ok(ActivationDeriverAStart::new(
        binding,
        ActivationDeriverAInputs::new(
            DeriverAClientY::from_secret_bytes(FIXTURE_SEED),
            DeriverAServerY::from_secret_bytes(ZERO),
            DeriverAClientTau::from_canonical_secret_bytes(ZERO)?,
            DeriverAServerTau::from_canonical_secret_bytes(ZERO)?,
            DeriverAClientScalarOutputCoin::random_os()?,
            DeriverASigningWorkerScalarOutputCoin::random_os()?,
        ),
    ))
}

pub(super) fn activation_deriver_b_fixture_start(
    session: [u8; 32],
) -> Result<ActivationDeriverBStart, RoleBoundaryError> {
    let binding = ActivationSessionBinding::new(SessionId::new(session)?);
    Ok(ActivationDeriverBStart::new(
        binding,
        ActivationDeriverBInputs::new(
            DeriverBClientY::from_secret_bytes(ZERO),
            DeriverBServerY::from_secret_bytes(ZERO),
            DeriverBClientTau::from_canonical_secret_bytes(ZERO)?,
            DeriverBServerTau::from_canonical_secret_bytes(ZERO)?,
            DeriverBClientScalarOutputCoin::random_os()?,
            DeriverBSigningWorkerScalarOutputCoin::random_os()?,
        ),
    ))
}

pub(super) fn export_deriver_a_fixture_start(
    session: [u8; 32],
) -> Result<ExportDeriverAStart, RoleBoundaryError> {
    let binding = ExportSessionBinding::new(SessionId::new(session)?);
    Ok(ExportDeriverAStart::new(
        binding,
        ExportDeriverAInputs::new(
            DeriverAClientY::from_secret_bytes(FIXTURE_SEED),
            DeriverAServerY::from_secret_bytes(ZERO),
            DeriverASeedOutputCoin::random_os()?,
        ),
    ))
}

pub(super) fn export_deriver_b_fixture_start(
    session: [u8; 32],
) -> Result<ExportDeriverBStart, RoleBoundaryError> {
    let binding = ExportSessionBinding::new(SessionId::new(session)?);
    Ok(ExportDeriverBStart::new(
        binding,
        ExportDeriverBInputs::new(
            DeriverBClientY::from_secret_bytes(ZERO),
            DeriverBServerY::from_secret_bytes(ZERO),
            DeriverBSeedOutputCoin::random_os()?,
        ),
    ))
}

pub(super) struct CompletedDeriverAActivation {
    client_package: DeriverAClientScalarPackage,
    signing_worker_package: DeriverASigningWorkerScalarPackage,
}

impl CompletedDeriverAActivation {
    pub(super) fn client_commitment(&self) -> [u8; 32] {
        *self.client_package.commitment().as_bytes()
    }

    pub(super) fn signing_worker_commitment(&self) -> [u8; 32] {
        *self.signing_worker_package.commitment().as_bytes()
    }

    pub(super) fn encode_client_package(&self) -> EncodedRecipientPackage {
        self.client_package.encode()
    }

    pub(super) fn encode_signing_worker_package(&self) -> EncodedRecipientPackage {
        self.signing_worker_package.encode()
    }
}

pub(super) struct CompletedDeriverBActivation {
    client_package: DeriverBClientScalarPackage,
    signing_worker_package: DeriverBSigningWorkerScalarPackage,
}

impl CompletedDeriverBActivation {
    pub(super) fn client_commitment(&self) -> [u8; 32] {
        *self.client_package.commitment().as_bytes()
    }

    pub(super) fn signing_worker_commitment(&self) -> [u8; 32] {
        *self.signing_worker_package.commitment().as_bytes()
    }

    pub(super) fn encode_client_package(&self) -> EncodedRecipientPackage {
        self.client_package.encode()
    }

    pub(super) fn encode_signing_worker_package(&self) -> EncodedRecipientPackage {
        self.signing_worker_package.encode()
    }
}

pub(super) struct CompletedDeriverAExport {
    package: DeriverAExportSeedPackage,
}

impl CompletedDeriverAExport {
    pub(super) fn encode_package(&self) -> EncodedRecipientPackage {
        self.package.encode()
    }
}

pub(super) struct CompletedDeriverBExport {
    package: DeriverBExportSeedPackage,
}

impl CompletedDeriverBExport {
    pub(super) fn encode_package(&self) -> EncodedRecipientPackage {
        self.package.encode()
    }
}

pub(super) fn complete_activation_deriver_a(
    binding: ActivationSessionBinding,
    final_transcript: TranscriptDigest32,
    shares: DecodedDeriverAActivationShares,
) -> Result<CompletedDeriverAActivation, RecipientPackageError> {
    Ok(CompletedDeriverAActivation {
        client_package: DeriverAClientScalarPackage::new(binding, final_transcript, &shares)?,
        signing_worker_package: DeriverASigningWorkerScalarPackage::new(
            binding,
            final_transcript,
            &shares,
        )?,
    })
}

pub(super) fn complete_activation_deriver_b(
    binding: ActivationSessionBinding,
    final_transcript: TranscriptDigest32,
    shares: DecodedDeriverBActivationShares,
) -> Result<CompletedDeriverBActivation, RecipientPackageError> {
    Ok(CompletedDeriverBActivation {
        client_package: DeriverBClientScalarPackage::new(binding, final_transcript, &shares)?,
        signing_worker_package: DeriverBSigningWorkerScalarPackage::new(
            binding,
            final_transcript,
            &shares,
        )?,
    })
}

pub(super) fn complete_export_deriver_a(
    binding: ExportSessionBinding,
    final_transcript: TranscriptDigest32,
    share: DecodedDeriverAExportSeedShare,
) -> CompletedDeriverAExport {
    CompletedDeriverAExport {
        package: DeriverAExportSeedPackage::new(binding, final_transcript, &share),
    }
}

pub(super) fn complete_export_deriver_b(
    binding: ExportSessionBinding,
    final_transcript: TranscriptDigest32,
    share: DecodedDeriverBExportSeedShare,
) -> CompletedDeriverBExport {
    CompletedDeriverBExport {
        package: DeriverBExportSeedPackage::new(binding, final_transcript, &share),
    }
}
