use core::fmt;

use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT, edwards::CompressedEdwardsY, scalar::Scalar,
    traits::IsIdentity,
};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const PACKAGE_MAGIC: &[u8; 8] = b"EYAOPKG1";
const PACKAGE_VERSION: u8 = 1;
const PACKAGE_HEADER_BYTES: usize = 152;
const ACTIVATION_PACKAGE_BYTES: usize = PACKAGE_HEADER_BYTES + 64;
const EXPORT_PACKAGE_BYTES: usize = PACKAGE_HEADER_BYTES + 32;
const ACTIVATION_FAMILY_TAG: u8 = 0x93;
const EXPORT_FAMILY_TAG: u8 = 0x94;
const DERIVER_A_ROLE_TAG: u8 = 0xa1;
const DERIVER_B_ROLE_TAG: u8 = 0xb2;
const CLIENT_RECIPIENT_TAG: u8 = 0x01;
const EXPORT_RECIPIENT_TAG: u8 = 0x03;
const CLIENT_SCALAR_SHARE_OUTPUT_KIND: u8 = 0x21;
const EXPORT_SEED_SHARE_OUTPUT_KIND: u8 = 0x23;
const PACKAGE_ITEM_COUNT: u32 = 1;

const ACTIVATION_CIRCUIT_DIGEST: [u8; 32] = [
    0x65, 0xb0, 0x01, 0xc2, 0xf9, 0x4d, 0xe2, 0x7e, 0xe8, 0xcb, 0x9f, 0x0c, 0x07, 0x73, 0xfb, 0xe5,
    0x42, 0x58, 0xce, 0xab, 0x43, 0xd1, 0x83, 0x17, 0x4b, 0xee, 0x71, 0x0e, 0xe8, 0xaa, 0x54, 0x6d,
];
const ACTIVATION_SCHEDULE_DIGEST: [u8; 32] = [
    0xfb, 0x04, 0xa1, 0x39, 0xde, 0xc1, 0x5e, 0x9d, 0x52, 0xe4, 0x96, 0xdc, 0x4f, 0xc0, 0x11, 0xcf,
    0x88, 0x5c, 0x8f, 0x3f, 0x6f, 0x2d, 0x18, 0xbf, 0x38, 0x60, 0xe4, 0x60, 0x71, 0xf0, 0xe6, 0x9a,
];
const EXPORT_CIRCUIT_DIGEST: [u8; 32] = [
    0x31, 0xb0, 0x3d, 0x13, 0xe4, 0x1a, 0x72, 0x83, 0x42, 0xae, 0xdc, 0xe7, 0xaf, 0x40, 0xf5, 0x40,
    0x5d, 0xc5, 0x98, 0xd2, 0x8e, 0x78, 0x4d, 0xe4, 0x4d, 0x80, 0x44, 0xdb, 0x9c, 0x60, 0x1a, 0x0c,
];
const EXPORT_SCHEDULE_DIGEST: [u8; 32] = [
    0x66, 0xdd, 0xc2, 0x0f, 0x84, 0x07, 0xe3, 0x69, 0xb7, 0x4f, 0x2a, 0x21, 0x02, 0x87, 0xd2, 0x13,
    0x1e, 0x78, 0xc7, 0x52, 0x5f, 0x47, 0xfc, 0x82, 0x9c, 0x57, 0xf6, 0x41, 0x8b, 0x0d, 0x97, 0xd0,
];

/// Recipient-output decoding or combination failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecipientPackageError {
    /// The package length differs from its fixed family length.
    MessageLength,
    /// A fixed header field, binding, role, recipient, or transcript was invalid.
    Binding,
    /// The activation share was not a canonical scalar.
    NonCanonicalScalar,
    /// The activation share commitment was malformed or inconsistent.
    ShareCommitment,
}

impl fmt::Display for RecipientPackageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid Ed25519 Yao recipient package")
    }
}

impl std::error::Error for RecipientPackageError {}

macro_rules! define_recipient_package {
    ($name:ident, $expected_bytes:expr) => {
        #[doc = "A fixed-width, zeroizing recipient package from one Deriver."]
        pub struct $name(Zeroizing<Vec<u8>>);

        impl $name {
            /// Validates the fixed family length and takes ownership of the bytes.
            pub fn from_bytes(mut bytes: Vec<u8>) -> Result<Self, RecipientPackageError> {
                if bytes.len() != $expected_bytes {
                    bytes.zeroize();
                    return Err(RecipientPackageError::MessageLength);
                }
                Ok(Self(Zeroizing::new(bytes)))
            }

            fn as_bytes(&self) -> &[u8] {
                self.0.as_slice()
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($name), "([REDACTED])"))
            }
        }
    };
}

define_recipient_package!(ActivationDeriverAClientPackage, ACTIVATION_PACKAGE_BYTES);
define_recipient_package!(ActivationDeriverBClientPackage, ACTIVATION_PACKAGE_BYTES);
define_recipient_package!(ExportDeriverAClientPackage, EXPORT_PACKAGE_BYTES);
define_recipient_package!(ExportDeriverBClientPackage, EXPORT_PACKAGE_BYTES);

/// Canonical Client scalar obtained after combining both activation outputs.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ClientBaseScalar([u8; 32]);

impl ClientBaseScalar {
    /// Consumes the scalar into its canonical bytes.
    pub fn into_bytes(mut self) -> [u8; 32] {
        core::mem::take(&mut self.0)
    }
}

impl fmt::Debug for ClientBaseScalar {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ClientBaseScalar([REDACTED])")
    }
}

/// Exact Ed25519 seed obtained after combining both export outputs.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ExportedSeed32([u8; 32]);

impl ExportedSeed32 {
    /// Consumes the seed into its fixed-width bytes.
    pub fn into_bytes(mut self) -> [u8; 32] {
        core::mem::take(&mut self.0)
    }
}

impl fmt::Debug for ExportedSeed32 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ExportedSeed32([REDACTED])")
    }
}

#[derive(Clone, Copy)]
struct ExpectedPackage {
    total_bytes: usize,
    family_tag: u8,
    role_tag: u8,
    recipient_tag: u8,
    output_kind: u8,
    circuit_digest: [u8; 32],
    schedule_digest: [u8; 32],
    payload_bytes: usize,
}

fn decode_payload(
    encoded: &[u8],
    session: [u8; 32],
    transcript: [u8; 32],
    expected: ExpectedPackage,
) -> Result<&[u8], RecipientPackageError> {
    if encoded.len() != expected.total_bytes {
        return Err(RecipientPackageError::MessageLength);
    }
    if session.iter().all(|byte| *byte == 0) || transcript.iter().all(|byte| *byte == 0) {
        return Err(RecipientPackageError::Binding);
    }
    let item_count = u32::from_be_bytes(
        encoded[144..148]
            .try_into()
            .map_err(|_| RecipientPackageError::Binding)?,
    );
    let payload_bytes = u32::from_be_bytes(
        encoded[148..152]
            .try_into()
            .map_err(|_| RecipientPackageError::Binding)?,
    ) as usize;
    let fixed_header_matches = &encoded[..8] == PACKAGE_MAGIC
        && encoded[8] == PACKAGE_VERSION
        && encoded[9] == expected.family_tag
        && encoded[10] == expected.role_tag
        && encoded[11] == expected.recipient_tag
        && encoded[12] == expected.output_kind
        && encoded[13..16] == [0_u8; 3]
        && encoded[16..48] == session
        && encoded[48..80] == expected.circuit_digest
        && encoded[80..112] == expected.schedule_digest
        && encoded[112..144] == transcript
        && item_count == PACKAGE_ITEM_COUNT
        && payload_bytes == expected.payload_bytes;
    if !fixed_header_matches {
        return Err(RecipientPackageError::Binding);
    }
    Ok(&encoded[PACKAGE_HEADER_BYTES..])
}

fn activation_expected(role_tag: u8) -> ExpectedPackage {
    ExpectedPackage {
        total_bytes: ACTIVATION_PACKAGE_BYTES,
        family_tag: ACTIVATION_FAMILY_TAG,
        role_tag,
        recipient_tag: CLIENT_RECIPIENT_TAG,
        output_kind: CLIENT_SCALAR_SHARE_OUTPUT_KIND,
        circuit_digest: ACTIVATION_CIRCUIT_DIGEST,
        schedule_digest: ACTIVATION_SCHEDULE_DIGEST,
        payload_bytes: 64,
    }
}

fn export_expected(role_tag: u8) -> ExpectedPackage {
    ExpectedPackage {
        total_bytes: EXPORT_PACKAGE_BYTES,
        family_tag: EXPORT_FAMILY_TAG,
        role_tag,
        recipient_tag: EXPORT_RECIPIENT_TAG,
        output_kind: EXPORT_SEED_SHARE_OUTPUT_KIND,
        circuit_digest: EXPORT_CIRCUIT_DIGEST,
        schedule_digest: EXPORT_SCHEDULE_DIGEST,
        payload_bytes: 32,
    }
}

fn decode_activation_share(
    encoded: &[u8],
    session: [u8; 32],
    transcript: [u8; 32],
    role_tag: u8,
) -> Result<Zeroizing<[u8; 32]>, RecipientPackageError> {
    let payload = decode_payload(encoded, session, transcript, activation_expected(role_tag))?;
    let mut share = Zeroizing::new([0_u8; 32]);
    share.copy_from_slice(&payload[..32]);
    let scalar_option = Scalar::from_canonical_bytes(*share);
    let mut scalar = scalar_option.unwrap_or(Scalar::ZERO);
    if !bool::from(scalar_option.is_some()) {
        scalar.zeroize();
        return Err(RecipientPackageError::NonCanonicalScalar);
    }
    let expected_commitment = (ED25519_BASEPOINT_POINT * scalar).compress().to_bytes();
    scalar.zeroize();
    let mut commitment_bytes = [0_u8; 32];
    commitment_bytes.copy_from_slice(&payload[32..]);
    let commitment = CompressedEdwardsY(commitment_bytes)
        .decompress()
        .ok_or(RecipientPackageError::ShareCommitment)?;
    let canonical = commitment.compress().to_bytes();
    let valid_point = bool::from(canonical.ct_eq(&commitment_bytes))
        && (commitment.is_identity()
            || (!commitment.is_small_order() && commitment.is_torsion_free()));
    if !valid_point || !bool::from(expected_commitment.ct_eq(&commitment_bytes)) {
        return Err(RecipientPackageError::ShareCommitment);
    }
    Ok(share)
}

fn decode_export_share(
    encoded: &[u8],
    session: [u8; 32],
    transcript: [u8; 32],
    role_tag: u8,
) -> Result<Zeroizing<[u8; 32]>, RecipientPackageError> {
    let payload = decode_payload(encoded, session, transcript, export_expected(role_tag))?;
    let mut share = Zeroizing::new([0_u8; 32]);
    share.copy_from_slice(payload);
    Ok(share)
}

/// Combines the two transcript-bound Client activation shares.
pub fn combine_client_activation_packages(
    session: [u8; 32],
    final_transcript: [u8; 32],
    deriver_a: ActivationDeriverAClientPackage,
    deriver_b: ActivationDeriverBClientPackage,
) -> Result<ClientBaseScalar, RecipientPackageError> {
    let mut left = decode_activation_share(
        deriver_a.as_bytes(),
        session,
        final_transcript,
        DERIVER_A_ROLE_TAG,
    )?;
    let mut right = decode_activation_share(
        deriver_b.as_bytes(),
        session,
        final_transcript,
        DERIVER_B_ROLE_TAG,
    )?;
    let left_option = Scalar::from_canonical_bytes(*left);
    let right_option = Scalar::from_canonical_bytes(*right);
    let valid = left_option.is_some() & right_option.is_some();
    let mut left_scalar = left_option.unwrap_or(Scalar::ZERO);
    let mut right_scalar = right_option.unwrap_or(Scalar::ZERO);
    let output = (left_scalar + right_scalar).to_bytes();
    left_scalar.zeroize();
    right_scalar.zeroize();
    left.zeroize();
    right.zeroize();
    if !bool::from(valid) {
        return Err(RecipientPackageError::NonCanonicalScalar);
    }
    Ok(ClientBaseScalar(output))
}

/// Combines the two transcript-bound export seed shares using little-endian addition.
pub fn combine_export_packages(
    session: [u8; 32],
    final_transcript: [u8; 32],
    deriver_a: ExportDeriverAClientPackage,
    deriver_b: ExportDeriverBClientPackage,
) -> Result<ExportedSeed32, RecipientPackageError> {
    let mut left = decode_export_share(
        deriver_a.as_bytes(),
        session,
        final_transcript,
        DERIVER_A_ROLE_TAG,
    )?;
    let mut right = decode_export_share(
        deriver_b.as_bytes(),
        session,
        final_transcript,
        DERIVER_B_ROLE_TAG,
    )?;
    let mut output = [0_u8; 32];
    let mut carry = 0_u16;
    for (index, output_byte) in output.iter_mut().enumerate() {
        let sum = left[index] as u16 + right[index] as u16 + carry;
        *output_byte = sum as u8;
        carry = sum >> 8;
    }
    left.zeroize();
    right.zeroize();
    Ok(ExportedSeed32(output))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SESSION: [u8; 32] = [0x31; 32];
    const TRANSCRIPT: [u8; 32] = [0x42; 32];

    fn encode_test_package(expected: ExpectedPackage, payload: &[u8]) -> Vec<u8> {
        let mut encoded = vec![0_u8; expected.total_bytes];
        encoded[..8].copy_from_slice(PACKAGE_MAGIC);
        encoded[8] = PACKAGE_VERSION;
        encoded[9] = expected.family_tag;
        encoded[10] = expected.role_tag;
        encoded[11] = expected.recipient_tag;
        encoded[12] = expected.output_kind;
        encoded[16..48].copy_from_slice(&SESSION);
        encoded[48..80].copy_from_slice(&expected.circuit_digest);
        encoded[80..112].copy_from_slice(&expected.schedule_digest);
        encoded[112..144].copy_from_slice(&TRANSCRIPT);
        encoded[144..148].copy_from_slice(&PACKAGE_ITEM_COUNT.to_be_bytes());
        encoded[148..152].copy_from_slice(&(expected.payload_bytes as u32).to_be_bytes());
        encoded[152..].copy_from_slice(payload);
        encoded
    }

    fn activation_package(role_tag: u8, scalar: Scalar) -> Vec<u8> {
        let mut payload = [0_u8; 64];
        payload[..32].copy_from_slice(&scalar.to_bytes());
        payload[32..].copy_from_slice((ED25519_BASEPOINT_POINT * scalar).compress().as_bytes());
        encode_test_package(activation_expected(role_tag), &payload)
    }

    fn export_package(role_tag: u8, share: [u8; 32]) -> Vec<u8> {
        encode_test_package(export_expected(role_tag), &share)
    }

    #[test]
    fn activation_combination_accepts_exact_role_bound_packages() {
        let a = ActivationDeriverAClientPackage::from_bytes(activation_package(
            DERIVER_A_ROLE_TAG,
            Scalar::from(2_u64),
        ))
        .expect("Deriver A package");
        let b = ActivationDeriverBClientPackage::from_bytes(activation_package(
            DERIVER_B_ROLE_TAG,
            Scalar::from(3_u64),
        ))
        .expect("Deriver B package");
        let combined = combine_client_activation_packages(SESSION, TRANSCRIPT, a, b)
            .expect("combined Client scalar")
            .into_bytes();
        assert_eq!(combined, Scalar::from(5_u64).to_bytes());
    }

    #[test]
    fn activation_combination_rejects_role_swap_transcript_swap_and_truncation() {
        let a_bytes = activation_package(DERIVER_A_ROLE_TAG, Scalar::from(2_u64));
        let b_bytes = activation_package(DERIVER_B_ROLE_TAG, Scalar::from(3_u64));
        let swapped_a = ActivationDeriverAClientPackage::from_bytes(b_bytes.clone())
            .expect("fixed-width package");
        let b = ActivationDeriverBClientPackage::from_bytes(b_bytes).expect("Deriver B package");
        assert!(matches!(
            combine_client_activation_packages(SESSION, TRANSCRIPT, swapped_a, b),
            Err(RecipientPackageError::Binding)
        ));

        let a = ActivationDeriverAClientPackage::from_bytes(a_bytes.clone())
            .expect("Deriver A package");
        let b = ActivationDeriverBClientPackage::from_bytes(activation_package(
            DERIVER_B_ROLE_TAG,
            Scalar::from(3_u64),
        ))
        .expect("Deriver B package");
        let mut other_transcript = TRANSCRIPT;
        other_transcript[0] ^= 1;
        assert!(matches!(
            combine_client_activation_packages(SESSION, other_transcript, a, b),
            Err(RecipientPackageError::Binding)
        ));

        assert!(matches!(
            ActivationDeriverAClientPackage::from_bytes(a_bytes[..a_bytes.len() - 1].to_vec()),
            Err(RecipientPackageError::MessageLength)
        ));
    }

    #[test]
    fn activation_combination_rejects_commitment_substitution() {
        let mut a_bytes = activation_package(DERIVER_A_ROLE_TAG, Scalar::from(2_u64));
        a_bytes[184] ^= 1;
        let a = ActivationDeriverAClientPackage::from_bytes(a_bytes).expect("fixed-width package");
        let b = ActivationDeriverBClientPackage::from_bytes(activation_package(
            DERIVER_B_ROLE_TAG,
            Scalar::from(3_u64),
        ))
        .expect("Deriver B package");
        assert!(matches!(
            combine_client_activation_packages(SESSION, TRANSCRIPT, a, b),
            Err(RecipientPackageError::ShareCommitment)
        ));
    }

    #[test]
    fn export_combination_preserves_little_endian_seed_addition() {
        let mut a_share = [0_u8; 32];
        a_share[0] = 0xff;
        let mut b_share = [0_u8; 32];
        b_share[0] = 2;
        let a =
            ExportDeriverAClientPackage::from_bytes(export_package(DERIVER_A_ROLE_TAG, a_share))
                .expect("Deriver A package");
        let b =
            ExportDeriverBClientPackage::from_bytes(export_package(DERIVER_B_ROLE_TAG, b_share))
                .expect("Deriver B package");
        let output = combine_export_packages(SESSION, TRANSCRIPT, a, b)
            .expect("combined seed")
            .into_bytes();
        assert_eq!(output[0], 1);
        assert_eq!(output[1], 1);
        assert!(output[2..].iter().all(|byte| *byte == 0));
    }
}

#[cfg(test)]
#[path = "recipient_fuzz_tests.rs"]
mod recipient_fuzz_tests;
