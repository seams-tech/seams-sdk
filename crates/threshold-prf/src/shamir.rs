use core::fmt;

use curve25519_dalek::scalar::Scalar;
use rand_core::{CryptoRng, RngCore};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{ThresholdPrfError, ThresholdPrfResult};

const SIGNING_ROOT_SHARE_WIRE_V1_LEN: usize = 33;

/// Project-root scalar `k_org` in the PRF suite field.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SigningRootScalar(pub(crate) Scalar);

impl fmt::Debug for SigningRootScalar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SigningRootScalar([redacted])")
    }
}

impl SigningRootScalar {
    /// Parses canonical scalar bytes.
    pub fn from_canonical_bytes(bytes: [u8; 32]) -> ThresholdPrfResult<Self> {
        let scalar = Option::<Scalar>::from(Scalar::from_canonical_bytes(bytes))
            .ok_or(ThresholdPrfError::InvalidScalarEncoding)?;
        Self::from_scalar(scalar)
    }

    /// Returns canonical scalar bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    pub(crate) fn from_scalar(scalar: Scalar) -> ThresholdPrfResult<Self> {
        reject_zero_scalar(&scalar)?;
        Ok(Self(scalar))
    }
}

/// Project-root share identifier for the fixed 2-of-3 prototype.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SigningRootShareId(u8);

impl SigningRootShareId {
    /// Creates a share id. The prototype supports only ids 1, 2, and 3.
    pub fn new(value: u8) -> ThresholdPrfResult<Self> {
        if (1..=3).contains(&value) {
            Ok(Self(value))
        } else {
            Err(ThresholdPrfError::InvalidShareId)
        }
    }

    /// Returns the integer share id.
    pub fn get(self) -> u8 {
        self.0
    }

    pub(crate) fn scalar(self) -> Scalar {
        Scalar::from(u64::from(self.0))
    }
}

/// One Shamir signing-root share.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SigningRootShare {
    #[zeroize(skip)]
    id: SigningRootShareId,
    pub(crate) value: Scalar,
}

/// Fixed-width v1 secret signing-root share encoding.
///
/// This encoding is for decrypted share material at the server SDK boundary.
/// It is not a public transport format.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SigningRootShareWireV1 {
    bytes: [u8; SIGNING_ROOT_SHARE_WIRE_V1_LEN],
}

impl fmt::Debug for SigningRootShare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SigningRootShare")
            .field("id", &self.id)
            .field("value", &"[redacted]")
            .finish()
    }
}

impl fmt::Debug for SigningRootShareWireV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SigningRootShareWireV1([redacted])")
    }
}

impl SigningRootShare {
    /// Creates a signing-root share from a validated id and canonical scalar bytes.
    pub fn from_canonical_bytes(
        id: SigningRootShareId,
        bytes: [u8; 32],
    ) -> ThresholdPrfResult<Self> {
        let value = Option::<Scalar>::from(Scalar::from_canonical_bytes(bytes))
            .ok_or(ThresholdPrfError::InvalidScalarEncoding)?;
        Ok(Self { id, value })
    }

    /// Returns the share id.
    pub fn id(&self) -> SigningRootShareId {
        self.id
    }

    /// Returns canonical share scalar bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.value.to_bytes()
    }

    pub(crate) fn new_unchecked(id: SigningRootShareId, value: Scalar) -> Self {
        Self { id, value }
    }
}

impl SigningRootShareWireV1 {
    /// Serialized signing-root share length: one share-id byte and 32-byte scalar.
    pub const LEN: usize = SIGNING_ROOT_SHARE_WIRE_V1_LEN;

    /// Decodes and validates fixed-width secret share bytes.
    pub fn decode(bytes: [u8; Self::LEN]) -> ThresholdPrfResult<Self> {
        let wire = Self { bytes };
        wire.to_share()?;
        Ok(wire)
    }

    /// Decodes and validates a fixed-width secret share byte slice.
    pub fn decode_slice(bytes: &[u8]) -> ThresholdPrfResult<Self> {
        let bytes: [u8; Self::LEN] = bytes
            .try_into()
            .map_err(|_| ThresholdPrfError::InvalidShareEncoding)?;
        Self::decode(bytes)
    }

    /// Creates a fixed-width secret share wire value from a signing-root share.
    pub fn from_share(share: &SigningRootShare) -> Self {
        let mut bytes = [0u8; Self::LEN];
        bytes[0] = share.id().get();
        bytes[1..].copy_from_slice(&share.to_bytes());
        Self { bytes }
    }

    /// Decodes the validated wire value into a signing-root share.
    pub fn to_share(&self) -> ThresholdPrfResult<SigningRootShare> {
        let id = SigningRootShareId::new(self.bytes[0])?;
        let scalar_bytes = self.bytes[1..]
            .try_into()
            .expect("fixed-width signing-root share scalar slice");
        SigningRootShare::from_canonical_bytes(id, scalar_bytes)
    }

    /// Returns the fixed-width secret share bytes.
    pub fn to_bytes(&self) -> [u8; Self::LEN] {
        self.bytes
    }
}

/// Generates a non-zero signing-root scalar.
pub fn generate_signing_root<R>(rng: &mut R) -> SigningRootScalar
where
    R: RngCore + CryptoRng,
{
    loop {
        let scalar = Scalar::random(&mut *rng);
        if !bool::from(scalar.ct_eq(&Scalar::ZERO)) {
            return SigningRootScalar(scalar);
        }
    }
}

/// Splits a signing root into fixed 2-of-3 Shamir shares.
pub fn split_signing_root_2_of_3<R>(root: &SigningRootScalar, rng: &mut R) -> [SigningRootShare; 3]
where
    R: RngCore + CryptoRng,
{
    let slope = random_nonzero_scalar(rng);

    [
        eval_share(
            root.0,
            slope,
            SigningRootShareId::new(1).expect("static share id"),
        ),
        eval_share(
            root.0,
            slope,
            SigningRootShareId::new(2).expect("static share id"),
        ),
        eval_share(
            root.0,
            slope,
            SigningRootShareId::new(3).expect("static share id"),
        ),
    ]
}

/// Reconstructs the signing root from exactly two distinct 2-of-3 shares.
pub fn reconstruct_signing_root_2_of_3(
    shares: &[SigningRootShare],
) -> ThresholdPrfResult<SigningRootScalar> {
    let pair = exactly_two_shares(shares)?;
    let (lambda_left, lambda_right) = lagrange_coefficients_2_of_3(pair.left.id, pair.right.id)?;
    SigningRootScalar::from_scalar(
        (lambda_left * pair.left.value) + (lambda_right * pair.right.value),
    )
}

/// Refreshes a 2-of-3 sharing of the same signing root.
///
/// This prototype reconstructs the root before splitting again. A future
/// distributed refresh can preserve the same public API while changing the
/// implementation.
pub fn refresh_signing_root_shares_2_of_3<R>(
    shares: &[SigningRootShare],
    rng: &mut R,
) -> ThresholdPrfResult<[SigningRootShare; 3]>
where
    R: RngCore + CryptoRng,
{
    let root = reconstruct_signing_root_2_of_3(shares)?;
    Ok(split_signing_root_2_of_3(&root, rng))
}

pub(crate) fn lagrange_coefficients_2_of_3(
    left: SigningRootShareId,
    right: SigningRootShareId,
) -> ThresholdPrfResult<(Scalar, Scalar)> {
    if left == right {
        return Err(ThresholdPrfError::DuplicateShareId);
    }

    let x_left = left.scalar();
    let x_right = right.scalar();
    let lambda_left = x_right * (x_right - x_left).invert();
    let lambda_right = x_left * (x_left - x_right).invert();
    Ok((lambda_left, lambda_right))
}

/// Validated fixed v1 pair of distinct signing-root shares.
#[derive(Debug, Clone, Copy)]
pub(crate) struct SigningRootSharePair<'a> {
    pub(crate) left: &'a SigningRootShare,
    pub(crate) right: &'a SigningRootShare,
}

pub(crate) fn exactly_two_shares(
    shares: &[SigningRootShare],
) -> ThresholdPrfResult<SigningRootSharePair<'_>> {
    if shares.len() != 2 {
        return Err(ThresholdPrfError::InvalidThresholdSubset);
    }
    if shares[0].id == shares[1].id {
        return Err(ThresholdPrfError::DuplicateShareId);
    }
    Ok(SigningRootSharePair {
        left: &shares[0],
        right: &shares[1],
    })
}

fn eval_share(root: Scalar, slope: Scalar, id: SigningRootShareId) -> SigningRootShare {
    SigningRootShare::new_unchecked(id, root + (slope * id.scalar()))
}

fn random_nonzero_scalar<R>(rng: &mut R) -> Scalar
where
    R: RngCore + CryptoRng,
{
    loop {
        let candidate = Scalar::random(&mut *rng);
        if !is_zero_scalar(&candidate) {
            return candidate;
        }
    }
}

fn reject_zero_scalar(scalar: &Scalar) -> ThresholdPrfResult<()> {
    if is_zero_scalar(scalar) {
        Err(ThresholdPrfError::ZeroScalar)
    } else {
        Ok(())
    }
}

fn is_zero_scalar(scalar: &Scalar) -> bool {
    bool::from(scalar.ct_eq(&Scalar::ZERO))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lagrange_coefficients_cover_every_ordered_v1_pair() {
        let root = Scalar::from(9u64);
        let slope = Scalar::from(13u64);

        for (left_id, right_id) in [(1, 2), (2, 1), (1, 3), (3, 1), (2, 3), (3, 2)] {
            let left_id = SigningRootShareId::new(left_id).expect("valid share id");
            let right_id = SigningRootShareId::new(right_id).expect("valid share id");
            let left = eval_share(root, slope, left_id);
            let right = eval_share(root, slope, right_id);
            let (lambda_left, lambda_right) =
                lagrange_coefficients_2_of_3(left_id, right_id).expect("distinct share ids");

            assert_eq!(
                (lambda_left * left.value) + (lambda_right * right.value),
                root
            );
        }
    }

    #[test]
    fn duplicate_share_ids_fail_before_lagrange_use() {
        let share_id = SigningRootShareId::new(1).expect("valid share id");
        assert_eq!(
            lagrange_coefficients_2_of_3(share_id, share_id).unwrap_err(),
            ThresholdPrfError::DuplicateShareId
        );

        let share = SigningRootShare::new_unchecked(share_id, Scalar::from(7u64));
        assert_eq!(
            exactly_two_shares(&[share.clone(), share]).unwrap_err(),
            ThresholdPrfError::DuplicateShareId
        );
    }
}
