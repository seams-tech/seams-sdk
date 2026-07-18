//! Fixed-role online ECDSA signing over one-use presign material.
//!
//! Client and SigningWorker inputs are distinct types and cannot cross roles.
//!
//! ```compile_fail
//! use router_ab_ecdsa_online::{ClientPresignMaterial, SigningWorkerOnlineInput};
//! fn cross_role(material: ClientPresignMaterial, input: SigningWorkerOnlineInput) {
//!     let _ = material.reserve().commit(input);
//! }
//! ```
//!
//! ```compile_fail
//! use router_ab_ecdsa_online::ClientPresignMaterial;
//! fn require_clone<T: Clone>() {}
//! fn duplicate_secret() {
//!     require_clone::<ClientPresignMaterial>();
//! }
//! ```
//!
//! ```compile_fail
//! use router_ab_ecdsa_online::ClientPresignMaterial;
//! fn expose_secret(material: &ClientPresignMaterial) {
//!     let _ = format!("{material:?}");
//! }
//! ```

#![forbid(unsafe_code)]

use core::fmt;

use hkdf::Hkdf;
use k256::{
    ecdsa::{signature::hazmat::PrehashVerifier, RecoveryId, Signature, VerifyingKey},
    elliptic_curve::{
        bigint::U256,
        group::prime::PrimeCurveAffine,
        ops::Reduce,
        point::AffineCoordinates,
        scalar::IsHigh,
        sec1::{FromEncodedPoint, ToEncodedPoint},
        PrimeField,
    },
    AffinePoint, EncodedPoint, FieldBytes, ProjectivePoint, Scalar,
};
use sha3::Sha3_256;
use subtle::{ConditionallySelectable, ConstantTimeEq};
use zeroize::{Zeroize, ZeroizeOnDrop};

const CLIENT_LAGRANGE_COEFFICIENT: u64 = 3;
const SIGNING_WORKER_LAGRANGE_MAGNITUDE: u64 = 2;
const FIXED_PARTICIPANT_IDS: [u32; 2] = [1, 2];
const RERANDOMIZATION_SALT: [u8; 32] = [
    0x32, 0x8a, 0x47, 0xc2, 0xb8, 0x79, 0x44, 0x45, 0x25, 0x5c, 0x16, 0x47, 0x60, 0x8d, 0xf5, 0xdb,
    0x85, 0xc6, 0x8b, 0xb0, 0xe7, 0x17, 0x0a, 0xbe, 0xc5, 0x34, 0xdf, 0x27, 0x64, 0xa4, 0x58, 0x31,
];

/// Combines contributions after the Client has committed and the SigningWorker has revealed.
/// If either contribution is uniformly random and hidden from the other role when selected,
/// the resulting entropy is uniformly random.
pub fn combine_rerandomization_contributions(
    client_contribution32: [u8; 32],
    signing_worker_contribution32: [u8; 32],
) -> [u8; 32] {
    let mut entropy32 = client_contribution32;
    for (left, right) in entropy32.iter_mut().zip(signing_worker_contribution32) {
        *left ^= right;
    }
    entropy32
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OnlineError {
    InvalidPoint,
    IdentityPoint,
    NonCanonicalScalar,
    ZeroScalar,
    PresignCommitmentMismatch,
    RandomnessDerivation,
    SignatureVerification,
    RecoveryId,
}

impl fmt::Display for OnlineError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidPoint => "invalid compressed secp256k1 point",
            Self::IdentityPoint => "identity secp256k1 point is forbidden",
            Self::NonCanonicalScalar => "non-canonical secp256k1 scalar",
            Self::ZeroScalar => "zero secp256k1 scalar is forbidden",
            Self::PresignCommitmentMismatch => "presignature commitment mismatch",
            Self::RandomnessDerivation => "ECDSA rerandomization derivation failed",
            Self::SignatureVerification => "final ECDSA signature failed verification",
            Self::RecoveryId => "failed to recover the registered ECDSA public key",
        })
    }
}

impl std::error::Error for OnlineError {}

#[derive(Zeroize, ZeroizeOnDrop)]
struct PresignMaterial {
    #[zeroize(skip)]
    big_r: AffinePoint,
    k: Scalar,
    sigma: Scalar,
}

pub struct ClientPresignMaterial(PresignMaterial);
pub struct SigningWorkerPresignMaterial(PresignMaterial);
pub struct ReservedClientPresignMaterial(PresignMaterial);
pub struct ReservedSigningWorkerPresignMaterial(PresignMaterial);

pub struct CommittedClientOnlineSigning {
    material: PresignMaterial,
    input: OnlineInput,
}

pub struct CommittedSigningWorkerOnlineSigning {
    material: PresignMaterial,
    input: OnlineInput,
}

impl ClientPresignMaterial {
    pub fn from_bytes(
        big_r33: [u8; 33],
        k_share32: [u8; 32],
        sigma_share32: [u8; 32],
    ) -> Result<Self, OnlineError> {
        parse_presign_material(big_r33, k_share32, sigma_share32).map(Self)
    }

    /// Reserves this one-use material and consumes the available state.
    ///
    /// ```compile_fail
    /// use router_ab_ecdsa_online::{OnlineClientInput, ReservedClientPresignMaterial};
    /// fn reuse(
    ///     reserved: ReservedClientPresignMaterial,
    ///     first: OnlineClientInput,
    ///     second: OnlineClientInput,
    /// ) {
    ///     let _ = reserved.commit(first);
    ///     let _ = reserved.commit(second);
    /// }
    /// ```
    pub fn reserve(self) -> ReservedClientPresignMaterial {
        ReservedClientPresignMaterial(self.0)
    }
}

impl SigningWorkerPresignMaterial {
    pub fn from_bytes(
        big_r33: [u8; 33],
        k_share32: [u8; 32],
        sigma_share32: [u8; 32],
    ) -> Result<Self, OnlineError> {
        parse_presign_material(big_r33, k_share32, sigma_share32).map(Self)
    }

    pub fn reserve(self) -> ReservedSigningWorkerPresignMaterial {
        ReservedSigningWorkerPresignMaterial(self.0)
    }
}

fn parse_presign_material(
    big_r33: [u8; 33],
    k_share32: [u8; 32],
    sigma_share32: [u8; 32],
) -> Result<PresignMaterial, OnlineError> {
    Ok(PresignMaterial {
        big_r: parse_nonidentity_point(&big_r33)?,
        k: parse_nonzero_scalar(k_share32)?,
        sigma: parse_scalar(sigma_share32)?,
    })
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct OnlineInput {
    #[zeroize(skip)]
    group_public_key: AffinePoint,
    #[zeroize(skip)]
    expected_big_r: AffinePoint,
    digest32: [u8; 32],
    entropy32: [u8; 32],
}

pub struct OnlineClientInput(OnlineInput);
pub struct SigningWorkerOnlineInput(OnlineInput);

impl OnlineClientInput {
    pub fn new(
        group_public_key33: [u8; 33],
        expected_big_r33: [u8; 33],
        digest32: [u8; 32],
        entropy32: [u8; 32],
    ) -> Result<Self, OnlineError> {
        parse_online_input(group_public_key33, expected_big_r33, digest32, entropy32).map(Self)
    }
}

impl SigningWorkerOnlineInput {
    pub fn new(
        group_public_key33: [u8; 33],
        expected_big_r33: [u8; 33],
        digest32: [u8; 32],
        entropy32: [u8; 32],
    ) -> Result<Self, OnlineError> {
        parse_online_input(group_public_key33, expected_big_r33, digest32, entropy32).map(Self)
    }
}

fn parse_online_input(
    group_public_key33: [u8; 33],
    expected_big_r33: [u8; 33],
    digest32: [u8; 32],
    entropy32: [u8; 32],
) -> Result<OnlineInput, OnlineError> {
    Ok(OnlineInput {
        group_public_key: parse_nonidentity_point(&group_public_key33)?,
        expected_big_r: parse_nonidentity_point(&expected_big_r33)?,
        digest32,
        entropy32,
    })
}

impl ReservedClientPresignMaterial {
    pub fn commit(
        self,
        input: OnlineClientInput,
    ) -> Result<CommittedClientOnlineSigning, OnlineError> {
        let (material, input) = bind_material(self.0, input.0)?;
        Ok(CommittedClientOnlineSigning { material, input })
    }
}

impl ReservedSigningWorkerPresignMaterial {
    pub fn commit(
        self,
        input: SigningWorkerOnlineInput,
    ) -> Result<CommittedSigningWorkerOnlineSigning, OnlineError> {
        let (material, input) = bind_material(self.0, input.0)?;
        Ok(CommittedSigningWorkerOnlineSigning { material, input })
    }
}

fn bind_material(
    material: PresignMaterial,
    input: OnlineInput,
) -> Result<(PresignMaterial, OnlineInput), OnlineError> {
    if !bool::from(point_bytes(material.big_r).ct_eq(&point_bytes(input.expected_big_r))) {
        return Err(OnlineError::PresignCommitmentMismatch);
    }
    Ok((material, input))
}

/// Emits a Client share only from material already reserved and committed.
///
/// ```compile_fail
/// use router_ab_ecdsa_online::{compute_client_signature_share, ClientPresignMaterial};
/// fn sign_available(material: ClientPresignMaterial) {
///     let _ = compute_client_signature_share(material);
/// }
/// ```
pub fn compute_client_signature_share(
    committed: CommittedClientOnlineSigning,
) -> Result<[u8; 32], OnlineError> {
    let CommittedClientOnlineSigning { material, input } = committed;

    let delta = derive_rerandomization_delta(&input)?;
    let inverse: Option<Scalar> = delta.invert().into();
    let inverse = inverse.ok_or(OnlineError::ZeroScalar)?;
    let rerandomized_big_r = AffinePoint::from(ProjectivePoint::from(material.big_r) * delta);
    let rerandomized_k = material.k * inverse;
    let rerandomized_sigma = material.sigma * inverse;
    let lambda = Scalar::from(CLIENT_LAGRANGE_COEFFICIENT);
    let h = <Scalar as Reduce<U256>>::reduce_bytes(&FieldBytes::from(input.digest32));
    let r = <Scalar as Reduce<U256>>::reduce_bytes(&rerandomized_big_r.x());
    let signature_share = h * (lambda * rerandomized_k) + r * (lambda * rerandomized_sigma);
    Ok(signature_share.to_bytes().into())
}

pub fn finalize_signing_worker_signature(
    committed: CommittedSigningWorkerOnlineSigning,
    client_signature_share32: [u8; 32],
) -> Result<[u8; 65], OnlineError> {
    let CommittedSigningWorkerOnlineSigning { material, input } = committed;
    let client_share = parse_scalar(client_signature_share32)?;
    let delta = derive_rerandomization_delta(&input)?;
    let inverse: Option<Scalar> = delta.invert().into();
    let inverse = inverse.ok_or(OnlineError::ZeroScalar)?;
    let rerandomized_big_r = AffinePoint::from(ProjectivePoint::from(material.big_r) * delta);
    let lambda = -Scalar::from(SIGNING_WORKER_LAGRANGE_MAGNITUDE);
    let h = <Scalar as Reduce<U256>>::reduce_bytes(&FieldBytes::from(input.digest32));
    let r = <Scalar as Reduce<U256>>::reduce_bytes(&rerandomized_big_r.x());
    let worker_share =
        h * (lambda * material.k * inverse) + r * (lambda * material.sigma * inverse);
    let s = client_share + worker_share;
    let s = Scalar::conditional_select(&s, &-s, s.is_high());

    let signature = Signature::from_scalars(r.to_bytes(), s.to_bytes())
        .map_err(|_| OnlineError::SignatureVerification)?;
    let verifying_key =
        VerifyingKey::from_affine(input.group_public_key).map_err(|_| OnlineError::InvalidPoint)?;
    verifying_key
        .verify_prehash(&input.digest32, &signature)
        .map_err(|_| OnlineError::SignatureVerification)?;
    let recovery_id = recovery_id(&verifying_key, &input.digest32, &signature)?;

    let mut output = [0u8; 65];
    output[..32].copy_from_slice(signature.r().to_bytes().as_ref());
    output[32..64].copy_from_slice(signature.s().to_bytes().as_ref());
    output[64] = recovery_id;
    Ok(output)
}

fn recovery_id(
    expected: &VerifyingKey,
    digest32: &[u8; 32],
    signature: &Signature,
) -> Result<u8, OnlineError> {
    for value in 0u8..=3 {
        let Some(id) = RecoveryId::from_byte(value) else {
            continue;
        };
        let Ok(recovered) = VerifyingKey::recover_from_prehash(digest32, signature, id) else {
            continue;
        };
        if bool::from(
            recovered
                .to_encoded_point(true)
                .as_bytes()
                .ct_eq(expected.to_encoded_point(true).as_bytes()),
        ) {
            return Ok(value);
        }
    }
    Err(OnlineError::RecoveryId)
}

fn derive_rerandomization_delta(input: &OnlineInput) -> Result<Scalar, OnlineError> {
    let mut info = Vec::with_capacity(2 + 33 + 32 + 32 + 33 + 8);
    info.extend_from_slice(&[0, 1]);
    info.extend_from_slice(input.group_public_key.to_encoded_point(true).as_bytes());
    info.extend_from_slice(&[0u8; 32]);
    info.extend_from_slice(&input.digest32);
    info.extend_from_slice(input.expected_big_r.to_encoded_point(true).as_bytes());
    for participant_id in FIXED_PARTICIPANT_IDS {
        info.extend_from_slice(&participant_id.to_le_bytes());
    }

    let hkdf = Hkdf::<Sha3_256>::new(Some(&RERANDOMIZATION_SALT), &input.entropy32);
    loop {
        let mut candidate = [0u8; 32];
        hkdf.expand(&info, &mut candidate)
            .map_err(|_| OnlineError::RandomnessDerivation)?;
        let scalar = Option::<Scalar>::from(Scalar::from_repr(candidate.into()));
        candidate.zeroize();
        if let Some(scalar) = scalar {
            if !bool::from(scalar.is_zero()) {
                info.zeroize();
                return Ok(scalar);
            }
        }
        let counter = info.first_mut().ok_or(OnlineError::RandomnessDerivation)?;
        *counter = counter
            .checked_add(1)
            .ok_or(OnlineError::RandomnessDerivation)?;
    }
}

fn parse_nonidentity_point(bytes: &[u8; 33]) -> Result<AffinePoint, OnlineError> {
    let encoded = EncodedPoint::from_bytes(bytes).map_err(|_| OnlineError::InvalidPoint)?;
    let point = Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&encoded))
        .ok_or(OnlineError::InvalidPoint)?;
    if bool::from(point.is_identity()) {
        return Err(OnlineError::IdentityPoint);
    }
    Ok(point)
}

fn parse_scalar(bytes: [u8; 32]) -> Result<Scalar, OnlineError> {
    Option::<Scalar>::from(Scalar::from_repr(bytes.into())).ok_or(OnlineError::NonCanonicalScalar)
}

fn parse_nonzero_scalar(bytes: [u8; 32]) -> Result<Scalar, OnlineError> {
    let scalar = parse_scalar(bytes)?;
    if bool::from(scalar.is_zero()) {
        return Err(OnlineError::ZeroScalar);
    }
    Ok(scalar)
}

fn point_bytes(point: AffinePoint) -> [u8; 33] {
    let encoded = point.to_encoded_point(true);
    let mut out = [0u8; 33];
    out.copy_from_slice(encoded.as_bytes());
    out
}

#[cfg(test)]
mod tests {
    use k256::elliptic_curve::PrimeField;
    use k256::Scalar;

    use super::{
        combine_rerandomization_contributions, compute_client_signature_share,
        finalize_signing_worker_signature, ClientPresignMaterial, OnlineClientInput, OnlineError,
        SigningWorkerOnlineInput, SigningWorkerPresignMaterial,
    };

    #[test]
    fn public_coin_requires_both_role_contributions() {
        let client = [0x60; 32];
        let worker = [0x01; 32];
        assert_eq!(
            combine_rerandomization_contributions(client, worker),
            [0x61; 32]
        );
        assert_ne!(
            combine_rerandomization_contributions([0x62; 32], worker),
            combine_rerandomization_contributions(client, worker)
        );
        assert_ne!(
            combine_rerandomization_contributions(client, [0x02; 32]),
            combine_rerandomization_contributions(client, worker)
        );
    }

    #[test]
    fn generated_presign_fixture_matches_oracle_finalization() {
        let group_public_key33 = [
            2, 254, 141, 30, 177, 188, 179, 67, 43, 29, 181, 131, 63, 245, 242, 34, 109, 156, 181,
            230, 92, 238, 67, 5, 88, 193, 142, 211, 163, 200, 108, 225, 175,
        ];
        let big_r33 = [
            3, 237, 150, 72, 69, 132, 153, 242, 148, 195, 128, 215, 84, 235, 17, 17, 182, 76, 107,
            254, 74, 146, 36, 62, 241, 41, 198, 185, 22, 109, 37, 77, 101,
        ];
        let client_k = [
            197, 87, 37, 100, 201, 71, 119, 15, 251, 24, 175, 179, 76, 165, 241, 88, 226, 144, 113,
            32, 42, 139, 246, 79, 67, 44, 131, 217, 172, 59, 26, 168,
        ];
        let client_sigma = [
            41, 80, 108, 245, 183, 251, 136, 226, 31, 123, 65, 156, 75, 13, 173, 79, 47, 134, 41,
            97, 244, 228, 59, 120, 19, 22, 222, 236, 92, 19, 78, 7,
        ];
        let worker_k = [
            25, 44, 47, 163, 99, 81, 14, 235, 214, 85, 18, 72, 234, 132, 84, 147, 108, 236, 231,
            46, 206, 85, 187, 156, 14, 32, 147, 195, 90, 217, 117, 188,
        ];
        let worker_sigma = [
            78, 198, 64, 113, 86, 175, 115, 21, 142, 26, 165, 65, 13, 115, 255, 14, 88, 0, 186,
            239, 201, 21, 93, 175, 190, 23, 137, 88, 64, 173, 14, 87,
        ];
        let digest32 = [0x42; 32];
        let entropy32 = [0x24; 32];

        let client_committed = ClientPresignMaterial::from_bytes(big_r33, client_k, client_sigma)
            .unwrap()
            .reserve()
            .commit(
                OnlineClientInput::new(group_public_key33, big_r33, digest32, entropy32).unwrap(),
            )
            .unwrap();
        let client_share = compute_client_signature_share(client_committed).unwrap();
        assert_eq!(
            client_share,
            [
                8, 46, 156, 40, 245, 90, 89, 122, 17, 195, 125, 69, 237, 224, 21, 99, 97, 131, 12,
                51, 124, 227, 87, 88, 198, 192, 41, 38, 207, 186, 26, 74,
            ]
        );

        let worker_committed =
            SigningWorkerPresignMaterial::from_bytes(big_r33, worker_k, worker_sigma)
                .unwrap()
                .reserve()
                .commit(
                    SigningWorkerOnlineInput::new(group_public_key33, big_r33, digest32, entropy32)
                        .unwrap(),
                )
                .unwrap();
        let signature = finalize_signing_worker_signature(worker_committed, client_share).unwrap();
        assert_eq!(
            signature,
            [
                194, 198, 128, 183, 98, 145, 10, 127, 191, 70, 33, 14, 150, 127, 179, 126, 216,
                238, 197, 63, 123, 123, 8, 115, 253, 92, 93, 141, 245, 191, 76, 31, 111, 24, 87,
                46, 67, 101, 139, 50, 54, 227, 82, 3, 166, 64, 143, 16, 66, 242, 134, 90, 126, 102,
                115, 130, 87, 45, 50, 39, 183, 123, 152, 98, 0,
            ]
        );

        let altered_share =
            Option::<Scalar>::from(Scalar::from_repr(client_share.into())).unwrap() + Scalar::ONE;
        let altered_worker_committed =
            SigningWorkerPresignMaterial::from_bytes(big_r33, worker_k, worker_sigma)
                .unwrap()
                .reserve()
                .commit(
                    SigningWorkerOnlineInput::new(group_public_key33, big_r33, digest32, entropy32)
                        .unwrap(),
                )
                .unwrap();
        let result = finalize_signing_worker_signature(
            altered_worker_committed,
            altered_share.to_bytes().into(),
        );
        assert!(matches!(result, Err(OnlineError::SignatureVerification)));

        let mismatched_commitment =
            ClientPresignMaterial::from_bytes(big_r33, client_k, client_sigma)
                .unwrap()
                .reserve()
                .commit(
                    OnlineClientInput::new(
                        group_public_key33,
                        group_public_key33,
                        digest32,
                        entropy32,
                    )
                    .unwrap(),
                );
        assert!(matches!(
            mismatched_commitment,
            Err(OnlineError::PresignCommitmentMismatch)
        ));

        let wrong_key_committed =
            SigningWorkerPresignMaterial::from_bytes(big_r33, worker_k, worker_sigma)
                .unwrap()
                .reserve()
                .commit(
                    SigningWorkerOnlineInput::new(big_r33, big_r33, digest32, entropy32).unwrap(),
                )
                .unwrap();
        let result = finalize_signing_worker_signature(wrong_key_committed, client_share);
        assert!(matches!(result, Err(OnlineError::SignatureVerification)));
    }
}
