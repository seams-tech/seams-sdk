#![allow(dead_code)]

use core::fmt;

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::IsIdentity;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::roles::{
    ActivationSessionBinding, DecodedDeriverAActivationShares, DecodedDeriverAExportSeedShare,
    DecodedDeriverBActivationShares, DecodedDeriverBExportSeedShare, ExportSessionBinding,
    TranscriptDigest32,
};

// Recipient encryption is intentionally deferred to Phase 6B.
const PACKAGE_MAGIC: &[u8; 8] = b"EYAOPKG1";
const PACKAGE_VERSION: u8 = 1;
const PACKAGE_HEADER_BYTES: usize = 152;
pub(super) const ACTIVATION_PACKAGE_BYTES: usize = PACKAGE_HEADER_BYTES + 64;
pub(super) const EXPORT_PACKAGE_BYTES: usize = PACKAGE_HEADER_BYTES + 32;
const ACTIVATION_FAMILY_TAG: u8 = 0x93;
const EXPORT_FAMILY_TAG: u8 = 0x94;
const DERIVER_A_ROLE_TAG: u8 = 0xa1;
const DERIVER_B_ROLE_TAG: u8 = 0xb2;
const CLIENT_RECIPIENT_TAG: u8 = 0x01;
const SIGNING_WORKER_RECIPIENT_TAG: u8 = 0x02;
const EXPORT_RECIPIENT_TAG: u8 = 0x03;
const CLIENT_SCALAR_SHARE_OUTPUT_KIND: u8 = 0x21;
const SIGNING_WORKER_SCALAR_SHARE_OUTPUT_KIND: u8 = 0x22;
const EXPORT_SEED_SHARE_OUTPUT_KIND: u8 = 0x23;
const PACKAGE_ITEM_COUNT: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RecipientPackageError {
    MessageLength,
    Magic,
    Version,
    Family,
    Role,
    Recipient,
    OutputKind,
    Reserved,
    Session,
    CircuitDigest,
    ScheduleDigest,
    Transcript,
    ItemCount,
    PayloadLength,
    NonCanonicalScalar,
    InvalidPointEncoding,
    NonCanonicalPoint,
    TorsionPoint,
    NonPrimeSubgroupPoint,
    IdentityPoint,
    ShareCommitmentMismatch,
    PublicKeyRelation,
}

impl fmt::Display for RecipientPackageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid Phase 4 recipient package")
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub(super) struct EncodedRecipientPackage(Vec<u8>);

impl EncodedRecipientPackage {
    pub(super) fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for EncodedRecipientPackage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EncodedRecipientPackage([REDACTED])")
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct SecretShare32([u8; 32]);

impl SecretShare32 {
    fn copy_from(bytes: &[u8]) -> Self {
        let mut share = [0_u8; 32];
        share.copy_from_slice(bytes);
        let output = Self(share);
        share.zeroize();
        output
    }

    const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for SecretShare32 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretShare32([REDACTED])")
    }
}

trait RecipientPackageBinding: Copy {
    const FAMILY_TAG: u8;

    fn session_bytes(self) -> [u8; 32];
    fn circuit_digest_bytes(self) -> [u8; 32];
    fn schedule_digest_bytes(self) -> [u8; 32];
}

impl RecipientPackageBinding for ActivationSessionBinding {
    const FAMILY_TAG: u8 = ACTIVATION_FAMILY_TAG;

    fn session_bytes(self) -> [u8; 32] {
        *ActivationSessionBinding::session_bytes(&self)
    }

    fn circuit_digest_bytes(self) -> [u8; 32] {
        *ActivationSessionBinding::circuit_digest(&self).as_bytes()
    }

    fn schedule_digest_bytes(self) -> [u8; 32] {
        *ActivationSessionBinding::schedule_digest(&self).as_bytes()
    }
}

impl RecipientPackageBinding for ExportSessionBinding {
    const FAMILY_TAG: u8 = EXPORT_FAMILY_TAG;

    fn session_bytes(self) -> [u8; 32] {
        *ExportSessionBinding::session_bytes(&self)
    }

    fn circuit_digest_bytes(self) -> [u8; 32] {
        *ExportSessionBinding::circuit_digest(&self).as_bytes()
    }

    fn schedule_digest_bytes(self) -> [u8; 32] {
        *ExportSessionBinding::schedule_digest(&self).as_bytes()
    }
}

#[derive(Clone, Copy)]
struct PackageIdentity<B> {
    binding: B,
    final_transcript: TranscriptDigest32,
    role_tag: u8,
    recipient_tag: u8,
    output_kind: u8,
    payload_bytes: usize,
}

impl<B: RecipientPackageBinding> PackageIdentity<B> {
    const fn new(
        binding: B,
        final_transcript: TranscriptDigest32,
        role_tag: u8,
        recipient_tag: u8,
        output_kind: u8,
        payload_bytes: usize,
    ) -> Self {
        Self {
            binding,
            final_transcript,
            role_tag,
            recipient_tag,
            output_kind,
            payload_bytes,
        }
    }

    fn encoded_length(self) -> Result<usize, RecipientPackageError> {
        PACKAGE_HEADER_BYTES
            .checked_add(self.payload_bytes)
            .ok_or(RecipientPackageError::MessageLength)
    }
}

fn encode_package<B: RecipientPackageBinding>(
    identity: PackageIdentity<B>,
    payload: &[u8],
) -> EncodedRecipientPackage {
    debug_assert_eq!(payload.len(), identity.payload_bytes);
    let mut encoded = vec![0_u8; PACKAGE_HEADER_BYTES + payload.len()];
    encoded[..8].copy_from_slice(PACKAGE_MAGIC);
    encoded[8] = PACKAGE_VERSION;
    encoded[9] = B::FAMILY_TAG;
    encoded[10] = identity.role_tag;
    encoded[11] = identity.recipient_tag;
    encoded[12] = identity.output_kind;
    encoded[16..48].copy_from_slice(&identity.binding.session_bytes());
    encoded[48..80].copy_from_slice(&identity.binding.circuit_digest_bytes());
    encoded[80..112].copy_from_slice(&identity.binding.schedule_digest_bytes());
    encoded[112..144].copy_from_slice(identity.final_transcript.as_bytes());
    encoded[144..148].copy_from_slice(&PACKAGE_ITEM_COUNT.to_be_bytes());
    encoded[148..152].copy_from_slice(&(payload.len() as u32).to_be_bytes());
    encoded[PACKAGE_HEADER_BYTES..].copy_from_slice(payload);
    EncodedRecipientPackage(encoded)
}

fn decode_package<B: RecipientPackageBinding>(
    identity: PackageIdentity<B>,
    encoded: &[u8],
) -> Result<&[u8], RecipientPackageError> {
    if encoded.len() != identity.encoded_length()? {
        return Err(RecipientPackageError::MessageLength);
    }
    if &encoded[..8] != PACKAGE_MAGIC {
        return Err(RecipientPackageError::Magic);
    }
    if encoded[8] != PACKAGE_VERSION {
        return Err(RecipientPackageError::Version);
    }
    if encoded[9] != B::FAMILY_TAG {
        return Err(RecipientPackageError::Family);
    }
    if encoded[10] != identity.role_tag {
        return Err(RecipientPackageError::Role);
    }
    if encoded[11] != identity.recipient_tag {
        return Err(RecipientPackageError::Recipient);
    }
    if encoded[12] != identity.output_kind {
        return Err(RecipientPackageError::OutputKind);
    }
    if encoded[13..16] != [0_u8; 3] {
        return Err(RecipientPackageError::Reserved);
    }
    if encoded[16..48] != identity.binding.session_bytes() {
        return Err(RecipientPackageError::Session);
    }
    if encoded[48..80] != identity.binding.circuit_digest_bytes() {
        return Err(RecipientPackageError::CircuitDigest);
    }
    if encoded[80..112] != identity.binding.schedule_digest_bytes() {
        return Err(RecipientPackageError::ScheduleDigest);
    }
    if encoded[112..144] != *identity.final_transcript.as_bytes() {
        return Err(RecipientPackageError::Transcript);
    }
    let item_count = u32::from_be_bytes(
        encoded[144..148]
            .try_into()
            .expect("fixed package header has a four-byte item count"),
    );
    if item_count != PACKAGE_ITEM_COUNT {
        return Err(RecipientPackageError::ItemCount);
    }
    let payload_bytes = u32::from_be_bytes(
        encoded[148..152]
            .try_into()
            .expect("fixed package header has a four-byte payload length"),
    ) as usize;
    if payload_bytes != identity.payload_bytes {
        return Err(RecipientPackageError::PayloadLength);
    }
    Ok(&encoded[PACKAGE_HEADER_BYTES..])
}

fn scalar_and_commitment(
    share_bytes: &[u8; 32],
) -> Result<(SecretShare32, [u8; 32]), RecipientPackageError> {
    let mut scalar = Scalar::from_canonical_bytes(*share_bytes)
        .into_option()
        .ok_or(RecipientPackageError::NonCanonicalScalar)?;
    let commitment = (ED25519_BASEPOINT_POINT * scalar).compress().to_bytes();
    scalar.zeroize();
    Ok((SecretShare32::copy_from(share_bytes), commitment))
}

fn decode_activation_payload(
    payload: &[u8],
) -> Result<(SecretShare32, [u8; 32]), RecipientPackageError> {
    debug_assert_eq!(payload.len(), 64);
    let mut share_bytes = [0_u8; 32];
    share_bytes.copy_from_slice(&payload[..32]);
    let parsed = scalar_and_commitment(&share_bytes);
    share_bytes.zeroize();
    let (share, expected_commitment) = parsed?;

    let mut encoded_commitment = [0_u8; 32];
    encoded_commitment.copy_from_slice(&payload[32..]);
    let commitment_point = decode_canonical_edwards(encoded_commitment, true)?;
    if !bool::from(expected_commitment.ct_eq(commitment_point.compress().as_bytes())) {
        return Err(RecipientPackageError::ShareCommitmentMismatch);
    }
    Ok((share, encoded_commitment))
}

macro_rules! define_share_commitment {
    ($name:ident) => {
        #[derive(Clone, Copy, PartialEq, Eq)]
        pub(super) struct $name([u8; 32]);

        impl $name {
            pub(super) const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($name), "([public commitment])"))
            }
        }
    };
}

define_share_commitment!(DeriverAClientShareCommitment);
define_share_commitment!(DeriverBClientShareCommitment);
define_share_commitment!(DeriverASigningWorkerShareCommitment);
define_share_commitment!(DeriverBSigningWorkerShareCommitment);

macro_rules! define_activation_package {
    (
        $name:ident,
        $binding:ident,
        $shares:ident,
        $share_getter:ident,
        $commitment:ident,
        $role_tag:expr,
        $recipient_tag:expr,
        $output_kind:expr
    ) => {
        pub(super) struct $name {
            identity: PackageIdentity<$binding>,
            share: SecretShare32,
            commitment: $commitment,
        }

        impl $name {
            pub(super) fn new(
                binding: $binding,
                final_transcript: TranscriptDigest32,
                shares: &$shares,
            ) -> Result<Self, RecipientPackageError> {
                let identity = PackageIdentity::new(
                    binding,
                    final_transcript,
                    $role_tag,
                    $recipient_tag,
                    $output_kind,
                    64,
                );
                let (share, commitment) = scalar_and_commitment(shares.$share_getter())?;
                Ok(Self {
                    identity,
                    share,
                    commitment: $commitment(commitment),
                })
            }

            pub(super) fn decode(
                binding: $binding,
                final_transcript: TranscriptDigest32,
                encoded: &[u8],
            ) -> Result<Self, RecipientPackageError> {
                let identity = PackageIdentity::new(
                    binding,
                    final_transcript,
                    $role_tag,
                    $recipient_tag,
                    $output_kind,
                    64,
                );
                let payload = decode_package(identity, encoded)?;
                let (share, commitment) = decode_activation_payload(payload)?;
                Ok(Self {
                    identity,
                    share,
                    commitment: $commitment(commitment),
                })
            }

            pub(super) fn encode(&self) -> EncodedRecipientPackage {
                let mut payload = [0_u8; 64];
                payload[..32].copy_from_slice(self.share.as_bytes());
                payload[32..].copy_from_slice(self.commitment.as_bytes());
                let encoded = encode_package(self.identity, &payload);
                payload.zeroize();
                encoded
            }

            pub(super) const fn share_bytes(&self) -> &[u8; 32] {
                self.share.as_bytes()
            }

            pub(super) const fn commitment(&self) -> $commitment {
                self.commitment
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($name), "([REDACTED])"))
            }
        }
    };
}

define_activation_package!(
    DeriverAClientScalarPackage,
    ActivationSessionBinding,
    DecodedDeriverAActivationShares,
    client_share_bytes,
    DeriverAClientShareCommitment,
    DERIVER_A_ROLE_TAG,
    CLIENT_RECIPIENT_TAG,
    CLIENT_SCALAR_SHARE_OUTPUT_KIND
);
define_activation_package!(
    DeriverBClientScalarPackage,
    ActivationSessionBinding,
    DecodedDeriverBActivationShares,
    client_share_bytes,
    DeriverBClientShareCommitment,
    DERIVER_B_ROLE_TAG,
    CLIENT_RECIPIENT_TAG,
    CLIENT_SCALAR_SHARE_OUTPUT_KIND
);
define_activation_package!(
    DeriverASigningWorkerScalarPackage,
    ActivationSessionBinding,
    DecodedDeriverAActivationShares,
    signing_worker_share_bytes,
    DeriverASigningWorkerShareCommitment,
    DERIVER_A_ROLE_TAG,
    SIGNING_WORKER_RECIPIENT_TAG,
    SIGNING_WORKER_SCALAR_SHARE_OUTPUT_KIND
);
define_activation_package!(
    DeriverBSigningWorkerScalarPackage,
    ActivationSessionBinding,
    DecodedDeriverBActivationShares,
    signing_worker_share_bytes,
    DeriverBSigningWorkerShareCommitment,
    DERIVER_B_ROLE_TAG,
    SIGNING_WORKER_RECIPIENT_TAG,
    SIGNING_WORKER_SCALAR_SHARE_OUTPUT_KIND
);

macro_rules! define_export_package {
    ($name:ident, $binding:ident, $shares:ident, $role_tag:expr) => {
        pub(super) struct $name {
            identity: PackageIdentity<$binding>,
            share: SecretShare32,
        }

        impl $name {
            pub(super) fn new(
                binding: $binding,
                final_transcript: TranscriptDigest32,
                share: &$shares,
            ) -> Self {
                Self {
                    identity: PackageIdentity::new(
                        binding,
                        final_transcript,
                        $role_tag,
                        EXPORT_RECIPIENT_TAG,
                        EXPORT_SEED_SHARE_OUTPUT_KIND,
                        32,
                    ),
                    share: SecretShare32::copy_from(share.share_bytes()),
                }
            }

            pub(super) fn decode(
                binding: $binding,
                final_transcript: TranscriptDigest32,
                encoded: &[u8],
            ) -> Result<Self, RecipientPackageError> {
                let identity = PackageIdentity::new(
                    binding,
                    final_transcript,
                    $role_tag,
                    EXPORT_RECIPIENT_TAG,
                    EXPORT_SEED_SHARE_OUTPUT_KIND,
                    32,
                );
                let payload = decode_package(identity, encoded)?;
                Ok(Self {
                    identity,
                    share: SecretShare32::copy_from(payload),
                })
            }

            pub(super) fn encode(&self) -> EncodedRecipientPackage {
                encode_package(self.identity, self.share.as_bytes())
            }

            pub(super) const fn share_bytes(&self) -> &[u8; 32] {
                self.share.as_bytes()
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($name), "([REDACTED])"))
            }
        }
    };
}

define_export_package!(
    DeriverAExportSeedPackage,
    ExportSessionBinding,
    DecodedDeriverAExportSeedShare,
    DERIVER_A_ROLE_TAG
);
define_export_package!(
    DeriverBExportSeedPackage,
    ExportSessionBinding,
    DecodedDeriverBExportSeedShare,
    DERIVER_B_ROLE_TAG
);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct VerifiedActivationReceipt {
    registered_public_key: [u8; 32],
    joined_client_commitment: [u8; 32],
    joined_signing_worker_commitment: [u8; 32],
}

impl VerifiedActivationReceipt {
    pub(super) const fn registered_public_key(&self) -> &[u8; 32] {
        &self.registered_public_key
    }

    pub(super) const fn joined_client_commitment(&self) -> &[u8; 32] {
        &self.joined_client_commitment
    }

    pub(super) const fn joined_signing_worker_commitment(&self) -> &[u8; 32] {
        &self.joined_signing_worker_commitment
    }
}

pub(super) fn verify_public_activation_receipt(
    registered_public_key: [u8; 32],
    a_client: DeriverAClientShareCommitment,
    b_client: DeriverBClientShareCommitment,
    a_signing_worker: DeriverASigningWorkerShareCommitment,
    b_signing_worker: DeriverBSigningWorkerShareCommitment,
) -> Result<VerifiedActivationReceipt, RecipientPackageError> {
    verify_public_activation_receipt_bytes(
        registered_public_key,
        *a_client.as_bytes(),
        *b_client.as_bytes(),
        *a_signing_worker.as_bytes(),
        *b_signing_worker.as_bytes(),
    )
}

pub(super) fn derive_public_activation_receipt(
    a_client: DeriverAClientShareCommitment,
    b_client: DeriverBClientShareCommitment,
    a_signing_worker: DeriverASigningWorkerShareCommitment,
    b_signing_worker: DeriverBSigningWorkerShareCommitment,
) -> Result<VerifiedActivationReceipt, RecipientPackageError> {
    derive_public_activation_receipt_bytes(
        *a_client.as_bytes(),
        *b_client.as_bytes(),
        *a_signing_worker.as_bytes(),
        *b_signing_worker.as_bytes(),
    )
}

pub(super) fn derive_public_activation_receipt_bytes(
    a_client: [u8; 32],
    b_client: [u8; 32],
    a_signing_worker: [u8; 32],
    b_signing_worker: [u8; 32],
) -> Result<VerifiedActivationReceipt, RecipientPackageError> {
    let a_client_point = decode_canonical_edwards(a_client, true)?;
    let b_client_point = decode_canonical_edwards(b_client, true)?;
    let a_signing_worker_point = decode_canonical_edwards(a_signing_worker, true)?;
    let b_signing_worker_point = decode_canonical_edwards(b_signing_worker, true)?;
    let joined_client = a_client_point + b_client_point;
    validate_joined_point(&joined_client)?;
    let joined_signing_worker = a_signing_worker_point + b_signing_worker_point;
    validate_joined_point(&joined_signing_worker)?;
    let registered_public_key = (joined_client + joined_client - joined_signing_worker)
        .compress()
        .to_bytes();
    verify_public_activation_receipt_bytes(
        registered_public_key,
        a_client,
        b_client,
        a_signing_worker,
        b_signing_worker,
    )
}

pub(super) fn verify_public_activation_receipt_bytes(
    registered_public_key: [u8; 32],
    a_client: [u8; 32],
    b_client: [u8; 32],
    a_signing_worker: [u8; 32],
    b_signing_worker: [u8; 32],
) -> Result<VerifiedActivationReceipt, RecipientPackageError> {
    let registered_point = decode_canonical_edwards(registered_public_key, false)?;
    let a_client_point = decode_canonical_edwards(a_client, true)?;
    let b_client_point = decode_canonical_edwards(b_client, true)?;
    let a_signing_worker_point = decode_canonical_edwards(a_signing_worker, true)?;
    let b_signing_worker_point = decode_canonical_edwards(b_signing_worker, true)?;

    let joined_client = a_client_point + b_client_point;
    validate_joined_point(&joined_client)?;
    let joined_signing_worker = a_signing_worker_point + b_signing_worker_point;
    validate_joined_point(&joined_signing_worker)?;

    let relation_point = joined_client + joined_client - joined_signing_worker;
    let relation_bytes = relation_point.compress();
    let registered_bytes = registered_point.compress();
    if !bool::from(relation_bytes.as_bytes().ct_eq(registered_bytes.as_bytes())) {
        return Err(RecipientPackageError::PublicKeyRelation);
    }

    Ok(VerifiedActivationReceipt {
        registered_public_key,
        joined_client_commitment: joined_client.compress().to_bytes(),
        joined_signing_worker_commitment: joined_signing_worker.compress().to_bytes(),
    })
}

fn decode_canonical_edwards(
    bytes: [u8; 32],
    allow_identity: bool,
) -> Result<EdwardsPoint, RecipientPackageError> {
    let point = CompressedEdwardsY(bytes)
        .decompress()
        .ok_or(RecipientPackageError::InvalidPointEncoding)?;
    if !bool::from(point.compress().as_bytes().ct_eq(&bytes)) {
        return Err(RecipientPackageError::NonCanonicalPoint);
    }
    if point.is_identity() {
        if allow_identity {
            return Ok(point);
        }
        return Err(RecipientPackageError::IdentityPoint);
    }
    if point.is_small_order() {
        return Err(RecipientPackageError::TorsionPoint);
    }
    if !point.is_torsion_free() {
        return Err(RecipientPackageError::NonPrimeSubgroupPoint);
    }
    Ok(point)
}

fn validate_joined_point(point: &EdwardsPoint) -> Result<(), RecipientPackageError> {
    if point.is_identity() {
        return Err(RecipientPackageError::IdentityPoint);
    }
    if point.is_small_order() {
        return Err(RecipientPackageError::TorsionPoint);
    }
    if !point.is_torsion_free() {
        return Err(RecipientPackageError::NonPrimeSubgroupPoint);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use curve25519_dalek::constants::{ED25519_BASEPOINT_POINT, EIGHT_TORSION};
    use curve25519_dalek::traits::Identity;

    use super::*;
    use crate::passive::roles::SessionId;

    fn session(byte: u8) -> SessionId {
        SessionId::new([byte; 32]).expect("nonzero session")
    }

    fn transcript(byte: u8) -> TranscriptDigest32 {
        TranscriptDigest32::new([byte; 32]).expect("nonzero transcript")
    }

    fn scalar(value: u64) -> [u8; 32] {
        Scalar::from(value).to_bytes()
    }

    fn activation_shares(
        client: u64,
        signing_worker: u64,
    ) -> (
        DecodedDeriverAActivationShares,
        DecodedDeriverBActivationShares,
    ) {
        let mut bytes = [0_u8; 64];
        bytes[..32].copy_from_slice(&scalar(client));
        bytes[32..].copy_from_slice(&scalar(signing_worker));
        (
            DecodedDeriverAActivationShares::from_decoded_output(&bytes).expect("A shares"),
            DecodedDeriverBActivationShares::from_decoded_output(&bytes).expect("B shares"),
        )
    }

    fn export_shares(
        byte: u8,
    ) -> (
        DecodedDeriverAExportSeedShare,
        DecodedDeriverBExportSeedShare,
    ) {
        let bytes = [byte; 32];
        (
            DecodedDeriverAExportSeedShare::from_decoded_output(&bytes).expect("A export share"),
            DecodedDeriverBExportSeedShare::from_decoded_output(&bytes).expect("B export share"),
        )
    }

    #[test]
    fn activation_packages_round_trip_one_share_and_commitment() {
        let binding = ActivationSessionBinding::new(session(1));
        let final_transcript = transcript(2);
        let (a_shares, b_shares) = activation_shares(3, 5);
        let a_client = DeriverAClientScalarPackage::new(binding, final_transcript, &a_shares)
            .expect("A client package");
        let encoded = a_client.encode();
        assert_eq!(encoded.as_slice().len(), ACTIVATION_PACKAGE_BYTES);
        let decoded =
            DeriverAClientScalarPackage::decode(binding, final_transcript, encoded.as_slice())
                .expect("strict round trip");
        assert_eq!(decoded.share_bytes(), &scalar(3));
        assert_eq!(
            decoded.commitment().as_bytes(),
            &(ED25519_BASEPOINT_POINT * Scalar::from(3_u64))
                .compress()
                .to_bytes()
        );

        let b_worker =
            DeriverBSigningWorkerScalarPackage::new(binding, final_transcript, &b_shares)
                .expect("B worker package");
        let encoded = b_worker.encode();
        let decoded = DeriverBSigningWorkerScalarPackage::decode(
            binding,
            final_transcript,
            encoded.as_slice(),
        )
        .expect("strict B worker round trip");
        assert_eq!(decoded.share_bytes(), &scalar(5));
    }

    #[test]
    fn export_packages_round_trip_exactly_one_seed_share() {
        let binding = ExportSessionBinding::new(session(3));
        let final_transcript = transcript(4);
        let (a_share, b_share) = export_shares(0x5a);
        let a_package = DeriverAExportSeedPackage::new(binding, final_transcript, &a_share);
        let encoded = a_package.encode();
        assert_eq!(encoded.as_slice().len(), EXPORT_PACKAGE_BYTES);
        let decoded =
            DeriverAExportSeedPackage::decode(binding, final_transcript, encoded.as_slice())
                .expect("strict export round trip");
        assert_eq!(decoded.share_bytes(), &[0x5a; 32]);

        let b_package = DeriverBExportSeedPackage::new(binding, final_transcript, &b_share);
        let encoded = b_package.encode();
        let decoded =
            DeriverBExportSeedPackage::decode(binding, final_transcript, encoded.as_slice())
                .expect("strict B export round trip");
        assert_eq!(decoded.share_bytes(), &[0x5a; 32]);
    }

    #[test]
    fn role_recipient_family_and_output_kind_swaps_fail_closed() {
        let binding = ActivationSessionBinding::new(session(5));
        let final_transcript = transcript(6);
        let (a_shares, _) = activation_shares(7, 11);
        let package = DeriverAClientScalarPackage::new(binding, final_transcript, &a_shares)
            .expect("A client package");
        let encoded = package.encode();

        assert_eq!(
            DeriverBClientScalarPackage::decode(binding, final_transcript, encoded.as_slice())
                .err(),
            Some(RecipientPackageError::Role)
        );
        assert_eq!(
            DeriverASigningWorkerScalarPackage::decode(
                binding,
                final_transcript,
                encoded.as_slice()
            )
            .err(),
            Some(RecipientPackageError::Recipient)
        );

        let mut mutated = encoded.as_slice().to_vec();
        mutated[9] = EXPORT_FAMILY_TAG;
        assert_eq!(
            DeriverAClientScalarPackage::decode(binding, final_transcript, &mutated).err(),
            Some(RecipientPackageError::Family)
        );
        mutated[9] = ACTIVATION_FAMILY_TAG;
        mutated[12] = SIGNING_WORKER_SCALAR_SHARE_OUTPUT_KIND;
        assert_eq!(
            DeriverAClientScalarPackage::decode(binding, final_transcript, &mutated).err(),
            Some(RecipientPackageError::OutputKind)
        );
    }

    #[test]
    fn export_package_cannot_parse_as_activation() {
        let export_binding = ExportSessionBinding::new(session(7));
        let activation_binding = ActivationSessionBinding::new(session(7));
        let final_transcript = transcript(8);
        let (share, _) = export_shares(0x42);
        let package = DeriverAExportSeedPackage::new(export_binding, final_transcript, &share);
        let encoded = package.encode();
        assert_eq!(
            DeriverAClientScalarPackage::decode(
                activation_binding,
                final_transcript,
                encoded.as_slice()
            )
            .err(),
            Some(RecipientPackageError::MessageLength)
        );
    }

    #[test]
    fn exact_length_reserved_count_and_binding_checks_fail_closed() {
        let binding = ActivationSessionBinding::new(session(9));
        let final_transcript = transcript(10);
        let (shares, _) = activation_shares(13, 17);
        let package = DeriverAClientScalarPackage::new(binding, final_transcript, &shares)
            .expect("A client package");
        let encoded = package.encode();

        let mut trailing = encoded.as_slice().to_vec();
        trailing.push(0);
        assert_eq!(
            DeriverAClientScalarPackage::decode(binding, final_transcript, &trailing).err(),
            Some(RecipientPackageError::MessageLength)
        );

        let mut reserved = encoded.as_slice().to_vec();
        reserved[14] = 1;
        assert_eq!(
            DeriverAClientScalarPackage::decode(binding, final_transcript, &reserved).err(),
            Some(RecipientPackageError::Reserved)
        );

        let mut count = encoded.as_slice().to_vec();
        count[144..148].copy_from_slice(&2_u32.to_be_bytes());
        assert_eq!(
            DeriverAClientScalarPackage::decode(binding, final_transcript, &count).err(),
            Some(RecipientPackageError::ItemCount)
        );

        assert_eq!(
            DeriverAClientScalarPackage::decode(
                ActivationSessionBinding::new(session(11)),
                final_transcript,
                encoded.as_slice()
            )
            .err(),
            Some(RecipientPackageError::Session)
        );
        assert_eq!(
            DeriverAClientScalarPackage::decode(binding, transcript(12), encoded.as_slice()).err(),
            Some(RecipientPackageError::Transcript)
        );
    }

    #[test]
    fn activation_decode_rejects_noncanonical_scalar_and_malformed_point() {
        let binding = ActivationSessionBinding::new(session(13));
        let final_transcript = transcript(14);
        let (shares, _) = activation_shares(19, 23);
        let package = DeriverAClientScalarPackage::new(binding, final_transcript, &shares)
            .expect("A client package");
        let encoded = package.encode();

        let scalar_order = [
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
            0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x10,
        ];
        let mut noncanonical_scalar = encoded.as_slice().to_vec();
        noncanonical_scalar[PACKAGE_HEADER_BYTES..PACKAGE_HEADER_BYTES + 32]
            .copy_from_slice(&scalar_order);
        assert_eq!(
            DeriverAClientScalarPackage::decode(binding, final_transcript, &noncanonical_scalar)
                .err(),
            Some(RecipientPackageError::NonCanonicalScalar)
        );

        let mut malformed_point = encoded.as_slice().to_vec();
        malformed_point[PACKAGE_HEADER_BYTES + 32..].fill(0xff);
        assert_eq!(
            DeriverAClientScalarPackage::decode(binding, final_transcript, &malformed_point).err(),
            Some(RecipientPackageError::NonCanonicalPoint)
        );
    }

    #[test]
    fn activation_decode_rejects_commitment_mismatch() {
        let binding = ActivationSessionBinding::new(session(15));
        let final_transcript = transcript(16);
        let (shares, _) = activation_shares(29, 31);
        let package = DeriverAClientScalarPackage::new(binding, final_transcript, &shares)
            .expect("A client package");
        let encoded = package.encode();
        let mut mismatched = encoded.as_slice().to_vec();
        mismatched[PACKAGE_HEADER_BYTES + 32..].copy_from_slice(
            (ED25519_BASEPOINT_POINT * Scalar::from(30_u64))
                .compress()
                .as_bytes(),
        );
        assert_eq!(
            DeriverAClientScalarPackage::decode(binding, final_transcript, &mismatched).err(),
            Some(RecipientPackageError::ShareCommitmentMismatch)
        );
    }

    #[test]
    fn public_receipt_relation_passes_and_fails_using_commitments() {
        let binding = ActivationSessionBinding::new(session(17));
        let final_transcript = transcript(18);
        let (a_shares, _) = activation_shares(3, 5);
        let (_, b_shares) = activation_shares(4, 6);
        let a_client = DeriverAClientScalarPackage::new(binding, final_transcript, &a_shares)
            .expect("A client");
        let b_client = DeriverBClientScalarPackage::new(binding, final_transcript, &b_shares)
            .expect("B client");
        let a_worker =
            DeriverASigningWorkerScalarPackage::new(binding, final_transcript, &a_shares)
                .expect("A worker");
        let b_worker =
            DeriverBSigningWorkerScalarPackage::new(binding, final_transcript, &b_shares)
                .expect("B worker");
        let public_key = (ED25519_BASEPOINT_POINT * Scalar::from(3_u64))
            .compress()
            .to_bytes();
        let receipt = verify_public_activation_receipt(
            public_key,
            a_client.commitment(),
            b_client.commitment(),
            a_worker.commitment(),
            b_worker.commitment(),
        )
        .expect("2 * 7 - 11 = 3");
        assert_eq!(receipt.registered_public_key(), &public_key);
        assert_eq!(
            receipt.joined_client_commitment(),
            (ED25519_BASEPOINT_POINT * Scalar::from(7_u64))
                .compress()
                .as_bytes()
        );
        assert_eq!(
            receipt.joined_signing_worker_commitment(),
            (ED25519_BASEPOINT_POINT * Scalar::from(11_u64))
                .compress()
                .as_bytes()
        );

        let wrong_public_key = (ED25519_BASEPOINT_POINT * Scalar::from(4_u64))
            .compress()
            .to_bytes();
        assert_eq!(
            verify_public_activation_receipt(
                wrong_public_key,
                a_client.commitment(),
                b_client.commitment(),
                a_worker.commitment(),
                b_worker.commitment(),
            )
            .err(),
            Some(RecipientPackageError::PublicKeyRelation)
        );
    }

    #[test]
    fn public_receipt_rejects_invalid_registered_and_joined_points() {
        let basepoint = ED25519_BASEPOINT_POINT.compress().to_bytes();
        let identity = EdwardsPoint::identity().compress().to_bytes();
        let torsion = EIGHT_TORSION[1].compress().to_bytes();
        let mixed = (ED25519_BASEPOINT_POINT + EIGHT_TORSION[1])
            .compress()
            .to_bytes();

        assert_eq!(
            verify_public_activation_receipt_bytes(
                [0xff; 32], basepoint, basepoint, basepoint, basepoint
            )
            .err(),
            Some(RecipientPackageError::NonCanonicalPoint)
        );
        assert_eq!(
            verify_public_activation_receipt_bytes(
                identity, basepoint, basepoint, basepoint, basepoint
            )
            .err(),
            Some(RecipientPackageError::IdentityPoint)
        );
        assert_eq!(
            verify_public_activation_receipt_bytes(
                torsion, basepoint, basepoint, basepoint, basepoint
            )
            .err(),
            Some(RecipientPackageError::TorsionPoint)
        );
        assert_eq!(
            verify_public_activation_receipt_bytes(
                mixed, basepoint, basepoint, basepoint, basepoint
            )
            .err(),
            Some(RecipientPackageError::NonPrimeSubgroupPoint)
        );

        assert_eq!(
            verify_public_activation_receipt_bytes(
                basepoint, identity, identity, basepoint, basepoint
            )
            .err(),
            Some(RecipientPackageError::IdentityPoint)
        );
        assert_eq!(
            verify_public_activation_receipt_bytes(
                basepoint, torsion, identity, basepoint, basepoint
            )
            .err(),
            Some(RecipientPackageError::TorsionPoint)
        );
        assert_eq!(
            verify_public_activation_receipt_bytes(
                basepoint, mixed, identity, basepoint, basepoint
            )
            .err(),
            Some(RecipientPackageError::NonPrimeSubgroupPoint)
        );
    }
}
