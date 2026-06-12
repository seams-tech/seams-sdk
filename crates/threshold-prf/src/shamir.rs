use core::fmt;

use curve25519_dalek::scalar::Scalar;
use rand_core::{CryptoRng, RngCore};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{ThresholdPrfError, ThresholdPrfResult};

const SIGNING_ROOT_SHARE_WIRE_V1_LEN: usize = 33;
const V1_2_OF_3_POLICY: ThresholdPolicy = ThresholdPolicy {
    threshold: 2,
    share_count: 3,
};

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

    pub(crate) fn threshold_id(self) -> u16 {
        u16::from(self.0)
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
    let [lambda_left, lambda_right] = lagrange_coefficients_for_v1_subset([left, right])?;
    Ok((lambda_left, lambda_right))
}

pub(crate) fn lagrange_coefficients_for_v1_subset<const T: usize>(
    ids: [SigningRootShareId; T],
) -> ThresholdPrfResult<[Scalar; T]> {
    let subset = validate_v1_threshold_subset(ids)?;
    Ok(lagrange_coefficients_at_zero(subset))
}

pub(crate) fn validate_v1_threshold_subset_ids<const T: usize>(
    ids: [SigningRootShareId; T],
) -> ThresholdPrfResult<()> {
    validate_v1_threshold_subset(ids).map(|_| ())
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
    validate_v1_threshold_subset_ids([shares[0].id, shares[1].id])?;
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ThresholdPolicy {
    threshold: usize,
    share_count: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ValidatedThresholdSubset<const T: usize> {
    policy: ThresholdPolicy,
    ids: [u16; T],
}

fn validate_v1_threshold_subset<const T: usize>(
    ids: [SigningRootShareId; T],
) -> ThresholdPrfResult<ValidatedThresholdSubset<T>> {
    let mut threshold_ids = [0u16; T];
    for (output, id) in threshold_ids.iter_mut().zip(ids) {
        *output = id.threshold_id();
    }
    V1_2_OF_3_POLICY.validate_subset_ids(threshold_ids)
}

impl ThresholdPolicy {
    fn validate_subset_ids<const T: usize>(
        self,
        ids: [u16; T],
    ) -> ThresholdPrfResult<ValidatedThresholdSubset<T>> {
        if T != self.threshold {
            return Err(ThresholdPrfError::InvalidThresholdSubset);
        }

        for (index, id) in ids.iter().copied().enumerate() {
            if id == 0 || usize::from(id) > self.share_count {
                return Err(ThresholdPrfError::InvalidShareId);
            }
            if ids[..index].contains(&id) {
                return Err(ThresholdPrfError::DuplicateShareId);
            }
        }

        Ok(ValidatedThresholdSubset { policy: self, ids })
    }
}

fn lagrange_coefficients_at_zero<const T: usize>(
    subset: ValidatedThresholdSubset<T>,
) -> [Scalar; T] {
    let mut coefficients = [Scalar::ZERO; T];

    for (coefficient_index, coefficient) in coefficients.iter_mut().enumerate() {
        let x_i = Scalar::from(u64::from(subset.ids[coefficient_index]));
        let mut numerator = Scalar::ONE;
        let mut denominator = Scalar::ONE;

        for (other_index, other_id) in subset.ids.iter().copied().enumerate() {
            if coefficient_index == other_index {
                continue;
            }
            let x_j = Scalar::from(u64::from(other_id));
            numerator *= x_j;
            denominator *= x_j - x_i;
        }

        *coefficient = numerator * denominator.invert();
    }

    coefficients
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
    use curve25519_dalek::ristretto::RistrettoPoint;
    use curve25519_dalek::traits::Identity;
    use std::time::Instant;

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

    #[test]
    fn private_generic_lagrange_reconstructs_three_of_five_subsets() {
        let policy = ThresholdPolicy {
            threshold: 3,
            share_count: 5,
        };
        let root = Scalar::from(11u64);
        let linear = Scalar::from(17u64);
        let quadratic = Scalar::from(23u64);
        let shares = [
            (1u16, eval_quadratic_share(root, linear, quadratic, 1)),
            (2u16, eval_quadratic_share(root, linear, quadratic, 2)),
            (3u16, eval_quadratic_share(root, linear, quadratic, 3)),
            (4u16, eval_quadratic_share(root, linear, quadratic, 4)),
            (5u16, eval_quadratic_share(root, linear, quadratic, 5)),
        ];

        for ids in [
            [1u16, 2, 3],
            [1, 2, 4],
            [1, 2, 5],
            [1, 3, 4],
            [1, 3, 5],
            [1, 4, 5],
            [2, 3, 4],
            [2, 3, 5],
            [2, 4, 5],
            [3, 4, 5],
        ] {
            assert_eq!(
                reconstruct_scalar_with_private_generic(policy, ids, &shares),
                root
            );
            assert_eq!(
                reconstruct_scalar_with_private_generic(policy, [ids[2], ids[1], ids[0]], &shares),
                root
            );
        }
    }

    #[test]
    fn private_generic_lagrange_reconstructs_five_of_seven_scalar_and_point_subsets() {
        let policy = ThresholdPolicy {
            threshold: 5,
            share_count: 7,
        };
        let root = Scalar::from(29u64);
        let coefficients = [
            Scalar::from(31u64),
            Scalar::from(37u64),
            Scalar::from(41u64),
            Scalar::from(43u64),
        ];
        let shares = [
            (1u16, eval_polynomial_share(root, &coefficients, 1)),
            (2u16, eval_polynomial_share(root, &coefficients, 2)),
            (3u16, eval_polynomial_share(root, &coefficients, 3)),
            (4u16, eval_polynomial_share(root, &coefficients, 4)),
            (5u16, eval_polynomial_share(root, &coefficients, 5)),
            (6u16, eval_polynomial_share(root, &coefficients, 6)),
            (7u16, eval_polynomial_share(root, &coefficients, 7)),
        ];
        let input_point = Scalar::from(101u64) * RISTRETTO_BASEPOINT_POINT;
        let points = shares.map(|(id, share)| (id, share * input_point));

        for ids in [
            [1u16, 2, 3, 4, 5],
            [1, 2, 3, 4, 7],
            [1, 3, 4, 6, 7],
            [2, 3, 5, 6, 7],
            [1, 2, 4, 6, 7],
        ] {
            assert_eq!(
                reconstruct_scalar_with_private_generic(policy, ids, &shares),
                root
            );
            assert_eq!(
                reconstruct_scalar_with_private_generic(
                    policy,
                    [ids[4], ids[3], ids[2], ids[1], ids[0]],
                    &shares
                ),
                root
            );
            assert_eq!(
                reconstruct_point_with_private_generic(policy, ids, &points).compress(),
                (root * input_point).compress()
            );
        }
    }

    #[test]
    fn private_threshold_policy_rejects_invalid_subsets() {
        let policy = ThresholdPolicy {
            threshold: 3,
            share_count: 5,
        };

        assert_eq!(
            policy.validate_subset_ids([1u16, 2]).unwrap_err(),
            ThresholdPrfError::InvalidThresholdSubset
        );
        assert_eq!(
            policy.validate_subset_ids([1u16, 2, 3, 4]).unwrap_err(),
            ThresholdPrfError::InvalidThresholdSubset
        );
        assert_eq!(
            policy.validate_subset_ids([1u16, 1, 2]).unwrap_err(),
            ThresholdPrfError::DuplicateShareId
        );
        assert_eq!(
            policy.validate_subset_ids([0u16, 1, 2]).unwrap_err(),
            ThresholdPrfError::InvalidShareId
        );
        assert_eq!(
            policy.validate_subset_ids([1u16, 2, 6]).unwrap_err(),
            ThresholdPrfError::InvalidShareId
        );
    }

    #[test]
    fn private_v1_subset_validator_keeps_current_policy_shape() {
        let id_1 = SigningRootShareId::new(1).expect("valid share id");
        let id_2 = SigningRootShareId::new(2).expect("valid share id");
        let id_3 = SigningRootShareId::new(3).expect("valid share id");

        assert!(validate_v1_threshold_subset_ids([id_1, id_2]).is_ok());
        assert!(validate_v1_threshold_subset_ids([id_3, id_1]).is_ok());
        assert_eq!(
            validate_v1_threshold_subset_ids([id_1]).unwrap_err(),
            ThresholdPrfError::InvalidThresholdSubset
        );
        assert_eq!(
            validate_v1_threshold_subset_ids([id_1, id_2, id_3]).unwrap_err(),
            ThresholdPrfError::InvalidThresholdSubset
        );
        assert_eq!(
            validate_v1_threshold_subset_ids([id_2, id_2]).unwrap_err(),
            ThresholdPrfError::DuplicateShareId
        );
    }

    fn eval_quadratic_share(root: Scalar, linear: Scalar, quadratic: Scalar, id: u16) -> Scalar {
        eval_polynomial_share(root, &[linear, quadratic], id)
    }

    fn eval_polynomial_share(root: Scalar, coefficients: &[Scalar], id: u16) -> Scalar {
        let x = Scalar::from(u64::from(id));
        let mut value = root;
        let mut x_power = x;
        for coefficient in coefficients {
            value += *coefficient * x_power;
            x_power *= x;
        }
        value
    }

    fn reconstruct_scalar_with_private_generic<const T: usize, const N: usize>(
        policy: ThresholdPolicy,
        ids: [u16; T],
        shares: &[(u16, Scalar); N],
    ) -> Scalar {
        let subset = policy
            .validate_subset_ids(ids)
            .expect("valid threshold subset");
        let coefficients = lagrange_coefficients_at_zero(subset);
        let mut reconstructed = Scalar::ZERO;

        for (coefficient, id) in coefficients.into_iter().zip(ids) {
            let share = shares
                .iter()
                .find(|(share_id, _)| *share_id == id)
                .expect("share id exists in fixture")
                .1;
            reconstructed += coefficient * share;
        }

        reconstructed
    }

    fn reconstruct_point_with_private_generic<const T: usize, const N: usize>(
        policy: ThresholdPolicy,
        ids: [u16; T],
        points: &[(u16, RistrettoPoint); N],
    ) -> RistrettoPoint {
        let subset = policy
            .validate_subset_ids(ids)
            .expect("valid threshold subset");
        let coefficients = lagrange_coefficients_at_zero(subset);
        let mut reconstructed = RistrettoPoint::identity();

        for (coefficient, id) in coefficients.into_iter().zip(ids) {
            let point = points
                .iter()
                .find(|(share_id, _)| *share_id == id)
                .expect("point id exists in fixture")
                .1;
            reconstructed += coefficient * point;
        }

        reconstructed
    }

    #[test]
    #[ignore = "local timing harness; run `just threshold-prf-t-of-n-prep-bench`"]
    fn benchmark_private_generic_lagrange_prep() {
        let iterations = 1_000;
        measure_lagrange_case(
            "lagrange_at_zero_t2_n3",
            ThresholdPolicy {
                threshold: 2,
                share_count: 3,
            },
            [1u16, 3],
            iterations,
        );
        measure_point_interpolation_case(
            "point_interpolation_at_zero_t2_n3",
            ThresholdPolicy {
                threshold: 2,
                share_count: 3,
            },
            [1u16, 3],
            iterations,
        );
        measure_lagrange_case(
            "lagrange_at_zero_t3_n5",
            ThresholdPolicy {
                threshold: 3,
                share_count: 5,
            },
            [1u16, 3, 5],
            iterations,
        );
        measure_point_interpolation_case(
            "point_interpolation_at_zero_t3_n5",
            ThresholdPolicy {
                threshold: 3,
                share_count: 5,
            },
            [1u16, 3, 5],
            iterations,
        );
        measure_lagrange_case(
            "lagrange_at_zero_t5_n7",
            ThresholdPolicy {
                threshold: 5,
                share_count: 7,
            },
            [1u16, 2, 4, 6, 7],
            iterations,
        );
        measure_point_interpolation_case(
            "point_interpolation_at_zero_t5_n7",
            ThresholdPolicy {
                threshold: 5,
                share_count: 7,
            },
            [1u16, 2, 4, 6, 7],
            iterations,
        );
    }

    fn measure_lagrange_case<const T: usize>(
        name: &str,
        policy: ThresholdPolicy,
        ids: [u16; T],
        iterations: u32,
    ) {
        let subset = policy
            .validate_subset_ids(ids)
            .expect("benchmark subset is valid");
        let started_at = Instant::now();
        let mut checksum = 0u8;

        for _ in 0..iterations {
            for coefficient in lagrange_coefficients_at_zero(subset) {
                checksum ^= coefficient.to_bytes()[0];
            }
        }

        let elapsed = started_at.elapsed();
        let ns_per_op = elapsed.as_nanos() as f64 / f64::from(iterations);
        println!("{name}: {ns_per_op:.3} ns/op over {iterations} iterations, checksum {checksum}");
    }

    fn measure_point_interpolation_case<const T: usize>(
        name: &str,
        policy: ThresholdPolicy,
        ids: [u16; T],
        iterations: u32,
    ) {
        let subset = policy
            .validate_subset_ids(ids)
            .expect("benchmark subset is valid");
        let coefficients = lagrange_coefficients_at_zero(subset);
        let points = ids.map(|id| Scalar::from(u64::from(id)) * RISTRETTO_BASEPOINT_POINT);
        let started_at = Instant::now();
        let mut checksum = 0u8;

        for _ in 0..iterations {
            let mut interpolated = RistrettoPoint::identity();
            for (coefficient, point) in coefficients.iter().zip(points.iter()) {
                interpolated += *coefficient * *point;
            }
            checksum ^= interpolated.compress().as_bytes()[0];
        }

        let elapsed = started_at.elapsed();
        let ns_per_op = elapsed.as_nanos() as f64 / f64::from(iterations);
        println!("{name}: {ns_per_op:.3} ns/op over {iterations} iterations, checksum {checksum}");
    }
}
