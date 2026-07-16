use core::fmt;

use k256::{elliptic_curve::Field, AffinePoint, ProjectivePoint, Scalar};
use rand_core::CryptoRngCore;
use router_ab_ecdsa_wire::{CompressedPointBytes, PresignPairContext, ScalarBytes};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::proofs::TripleIndex;
use crate::{parse_nonidentity_point, point_bytes, scalar_bytes};

pub mod base_rot;
pub mod finalize;

const OPENING_DOMAIN: &[u8] = b"seams/router-ab-ecdsa-presign/polynomial-opening/v1";
const SUITE: &[u8] = b"secp256k1+sha256";
const CLIENT_ROLE: u8 = 1;
const SIGNING_WORKER_ROLE: u8 = 2;
const CLIENT_COORDINATE: u64 = 2;
const SIGNING_WORKER_COORDINATE: u64 = 3;
const RANDOMIZER_SIZE: usize = 32;
const MAX_NONZERO_ATTEMPTS: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolynomialError {
    ContextMismatch,
    TripleIndexMismatch,
    InvalidPoint,
    IdentityPoint,
    NonCanonicalScalar,
    PolynomialGenerationFailed,
    CommitmentOpeningMismatch,
    PrivateShareMismatch,
}

impl fmt::Display for PolynomialError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ContextMismatch => "polynomial message context mismatch",
            Self::TripleIndexMismatch => "polynomial message triple index mismatch",
            Self::InvalidPoint => "invalid compressed secp256k1 point",
            Self::IdentityPoint => "identity polynomial coefficient is forbidden",
            Self::NonCanonicalScalar => "non-canonical secp256k1 scalar",
            Self::PolynomialGenerationFailed => "failed to generate an exact-degree polynomial",
            Self::CommitmentOpeningMismatch => "polynomial commitment opening mismatch",
            Self::PrivateShareMismatch => "private polynomial share does not match its commitment",
        })
    }
}

impl std::error::Error for PolynomialError {}

#[derive(Clone, Copy)]
struct LinearPolynomialCommitment {
    constant: AffinePoint,
    slope: AffinePoint,
}

impl LinearPolynomialCommitment {
    fn evaluate(self, coordinate: Scalar) -> ProjectivePoint {
        ProjectivePoint::from(self.constant) + ProjectivePoint::from(self.slope) * coordinate
    }
}

#[derive(Clone, Copy)]
struct PublicPolynomialSet {
    big_e: LinearPolynomialCommitment,
    big_f: LinearPolynomialCommitment,
    big_l_constant: AffinePoint,
}

impl PublicPolynomialSet {
    fn from_parts(
        big_e_constant: CompressedPointBytes,
        big_e_slope: CompressedPointBytes,
        big_f_constant: CompressedPointBytes,
        big_f_slope: CompressedPointBytes,
        big_l_constant: CompressedPointBytes,
    ) -> Result<Self, PolynomialError> {
        Ok(Self {
            big_e: LinearPolynomialCommitment {
                constant: parse_point(big_e_constant)?,
                slope: parse_point(big_e_slope)?,
            },
            big_f: LinearPolynomialCommitment {
                constant: parse_point(big_f_constant)?,
                slope: parse_point(big_f_slope)?,
            },
            big_l_constant: parse_point(big_l_constant)?,
        })
    }

    fn into_parts(self) -> [CompressedPointBytes; 5] {
        [
            point_bytes(self.big_e.constant),
            point_bytes(self.big_e.slope),
            point_bytes(self.big_f.constant),
            point_bytes(self.big_f.slope),
            point_bytes(self.big_l_constant),
        ]
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct LinearPolynomial {
    constant: Scalar,
    slope: Scalar,
}

impl LinearPolynomial {
    fn generate(rng: &mut impl CryptoRngCore) -> Result<Self, PolynomialError> {
        Ok(Self {
            constant: random_nonzero_scalar(rng)?,
            slope: random_nonzero_scalar(rng)?,
        })
    }

    fn commitment(&self) -> LinearPolynomialCommitment {
        LinearPolynomialCommitment {
            constant: (ProjectivePoint::GENERATOR * self.constant).to_affine(),
            slope: (ProjectivePoint::GENERATOR * self.slope).to_affine(),
        }
    }

    fn evaluate(&self, coordinate: Scalar) -> Scalar {
        self.constant + self.slope * coordinate
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct SecretPolynomialSet {
    e: LinearPolynomial,
    f: LinearPolynomial,
    l_constant: Scalar,
}

impl SecretPolynomialSet {
    fn generate(rng: &mut impl CryptoRngCore) -> Result<Self, PolynomialError> {
        Ok(Self {
            e: LinearPolynomial::generate(rng)?,
            f: LinearPolynomial::generate(rng)?,
            l_constant: random_nonzero_scalar(rng)?,
        })
    }

    fn commitment(&self) -> PublicPolynomialSet {
        PublicPolynomialSet {
            big_e: self.e.commitment(),
            big_f: self.f.commitment(),
            big_l_constant: (ProjectivePoint::GENERATOR * self.l_constant).to_affine(),
        }
    }

    fn private_share(&self, coordinate: Scalar) -> PrivatePolynomialShare {
        PrivatePolynomialShare {
            e: self.e.evaluate(coordinate),
            f: self.f.evaluate(coordinate),
        }
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct CommitmentRandomizer([u8; RANDOMIZER_SIZE]);

struct CommittedPolynomialState {
    context: PresignPairContext,
    triple_index: TripleIndex,
    secrets: SecretPolynomialSet,
    public: PublicPolynomialSet,
    randomizer: CommitmentRandomizer,
}

struct OpenedPolynomialState {
    context: PresignPairContext,
    triple_index: TripleIndex,
    secrets: SecretPolynomialSet,
}

pub struct ClientCommittedPolynomials(CommittedPolynomialState);
pub struct SigningWorkerCommittedPolynomials(CommittedPolynomialState);
pub struct ClientOpenedPolynomials(OpenedPolynomialState);
pub struct SigningWorkerOpenedPolynomials(OpenedPolynomialState);

struct PolynomialCommitmentMessage {
    context: PresignPairContext,
    triple_index: TripleIndex,
    digest: [u8; 32],
}

struct PolynomialOpeningMessage {
    context: PresignPairContext,
    triple_index: TripleIndex,
    public: PublicPolynomialSet,
    randomizer: [u8; RANDOMIZER_SIZE],
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct PrivatePolynomialShare {
    e: Scalar,
    f: Scalar,
}

struct PrivatePolynomialShareMessage {
    context: PresignPairContext,
    triple_index: TripleIndex,
    share: PrivatePolynomialShare,
}

macro_rules! define_commitment_message {
    ($name:ident) => {
        pub struct $name(PolynomialCommitmentMessage);

        impl $name {
            pub const fn from_parts(
                context: PresignPairContext,
                triple_index: TripleIndex,
                digest: [u8; 32],
            ) -> Self {
                Self(PolynomialCommitmentMessage {
                    context,
                    triple_index,
                    digest,
                })
            }

            pub fn into_parts(self) -> (PresignPairContext, TripleIndex, [u8; 32]) {
                (self.0.context, self.0.triple_index, self.0.digest)
            }
        }
    };
}

macro_rules! define_opening_message {
    ($name:ident) => {
        pub struct $name(PolynomialOpeningMessage);

        impl $name {
            #[allow(clippy::too_many_arguments)]
            pub fn from_parts(
                context: PresignPairContext,
                triple_index: TripleIndex,
                big_e_constant: CompressedPointBytes,
                big_e_slope: CompressedPointBytes,
                big_f_constant: CompressedPointBytes,
                big_f_slope: CompressedPointBytes,
                big_l_constant: CompressedPointBytes,
                randomizer: [u8; RANDOMIZER_SIZE],
            ) -> Result<Self, PolynomialError> {
                Ok(Self(PolynomialOpeningMessage {
                    context,
                    triple_index,
                    public: PublicPolynomialSet::from_parts(
                        big_e_constant,
                        big_e_slope,
                        big_f_constant,
                        big_f_slope,
                        big_l_constant,
                    )?,
                    randomizer,
                }))
            }

            #[allow(clippy::type_complexity)]
            pub fn into_parts(
                self,
            ) -> (
                PresignPairContext,
                TripleIndex,
                CompressedPointBytes,
                CompressedPointBytes,
                CompressedPointBytes,
                CompressedPointBytes,
                CompressedPointBytes,
                [u8; RANDOMIZER_SIZE],
            ) {
                let points = self.0.public.into_parts();
                (
                    self.0.context,
                    self.0.triple_index,
                    points[0],
                    points[1],
                    points[2],
                    points[3],
                    points[4],
                    self.0.randomizer,
                )
            }
        }
    };
}

macro_rules! define_private_share_message {
    ($name:ident) => {
        pub struct $name(PrivatePolynomialShareMessage);

        impl $name {
            pub fn from_parts(
                context: PresignPairContext,
                triple_index: TripleIndex,
                e: ScalarBytes,
                f: ScalarBytes,
            ) -> Result<Self, PolynomialError> {
                Ok(Self(PrivatePolynomialShareMessage {
                    context,
                    triple_index,
                    share: PrivatePolynomialShare {
                        e: parse_scalar(e)?,
                        f: parse_scalar(f)?,
                    },
                }))
            }

            pub fn into_parts(self) -> (PresignPairContext, TripleIndex, ScalarBytes, ScalarBytes) {
                (
                    self.0.context,
                    self.0.triple_index,
                    scalar_bytes(self.0.share.e),
                    scalar_bytes(self.0.share.f),
                )
            }
        }
    };
}

define_commitment_message!(ClientPolynomialCommitmentMessage);
define_commitment_message!(SigningWorkerPolynomialCommitmentMessage);
define_opening_message!(ClientPolynomialOpeningMessage);
define_opening_message!(SigningWorkerPolynomialOpeningMessage);
define_private_share_message!(ClientPolynomialShareMessage);
define_private_share_message!(SigningWorkerPolynomialShareMessage);

#[derive(Clone, Copy)]
struct VerifiedPolynomialCommitment {
    context: PresignPairContext,
    triple_index: TripleIndex,
    public: PublicPolynomialSet,
}

pub struct VerifiedClientPolynomialCommitment(VerifiedPolynomialCommitment);
pub struct VerifiedSigningWorkerPolynomialCommitment(VerifiedPolynomialCommitment);

#[derive(Zeroize, ZeroizeOnDrop)]
struct VerifiedPrivatePolynomialShare {
    #[zeroize(skip)]
    context: PresignPairContext,
    #[zeroize(skip)]
    triple_index: TripleIndex,
    #[zeroize(skip)]
    public: PublicPolynomialSet,
    share: PrivatePolynomialShare,
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct VerifiedClientPrivateShare(VerifiedPrivatePolynomialShare);
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct VerifiedSigningWorkerPrivateShare(VerifiedPrivatePolynomialShare);

impl VerifiedClientPrivateShare {
    fn into_finalization(self) -> VerifiedPrivatePolynomialShare {
        VerifiedPrivatePolynomialShare {
            context: self.0.context,
            triple_index: self.0.triple_index,
            public: self.0.public,
            share: PrivatePolynomialShare {
                e: self.0.share.e,
                f: self.0.share.f,
            },
        }
    }
}

impl VerifiedSigningWorkerPrivateShare {
    fn into_finalization(self) -> VerifiedPrivatePolynomialShare {
        VerifiedPrivatePolynomialShare {
            context: self.0.context,
            triple_index: self.0.triple_index,
            public: self.0.public,
            share: PrivatePolynomialShare {
                e: self.0.share.e,
                f: self.0.share.f,
            },
        }
    }
}

pub fn commit_client_polynomials(
    context: PresignPairContext,
    triple_index: TripleIndex,
    rng: &mut impl CryptoRngCore,
) -> Result<
    (
        ClientCommittedPolynomials,
        ClientPolynomialCommitmentMessage,
    ),
    PolynomialError,
> {
    let (state, message) = commit_polynomials(context, triple_index, CLIENT_ROLE, rng)?;
    Ok((
        ClientCommittedPolynomials(state),
        ClientPolynomialCommitmentMessage(message),
    ))
}

pub fn commit_signing_worker_polynomials(
    context: PresignPairContext,
    triple_index: TripleIndex,
    rng: &mut impl CryptoRngCore,
) -> Result<
    (
        SigningWorkerCommittedPolynomials,
        SigningWorkerPolynomialCommitmentMessage,
    ),
    PolynomialError,
> {
    let (state, message) = commit_polynomials(context, triple_index, SIGNING_WORKER_ROLE, rng)?;
    Ok((
        SigningWorkerCommittedPolynomials(state),
        SigningWorkerPolynomialCommitmentMessage(message),
    ))
}

impl ClientCommittedPolynomials {
    pub fn open(self) -> (ClientOpenedPolynomials, ClientPolynomialOpeningMessage) {
        let (state, message) = open_polynomials(self.0);
        (
            ClientOpenedPolynomials(state),
            ClientPolynomialOpeningMessage(message),
        )
    }
}

impl SigningWorkerCommittedPolynomials {
    pub fn open(
        self,
    ) -> (
        SigningWorkerOpenedPolynomials,
        SigningWorkerPolynomialOpeningMessage,
    ) {
        let (state, message) = open_polynomials(self.0);
        (
            SigningWorkerOpenedPolynomials(state),
            SigningWorkerPolynomialOpeningMessage(message),
        )
    }
}

impl ClientOpenedPolynomials {
    pub fn multiplication_operands(
        &self,
    ) -> base_rot::extension::mta::ClientMultiplicationOperands {
        base_rot::extension::mta::ClientMultiplicationOperands::from_scalars(
            self.0.context,
            self.0.triple_index,
            self.0.secrets.e.constant,
            self.0.secrets.f.constant,
        )
    }

    pub fn private_share_for_signing_worker(&self) -> ClientPolynomialShareMessage {
        ClientPolynomialShareMessage(private_share_message(
            &self.0,
            Scalar::from(SIGNING_WORKER_COORDINATE),
        ))
    }
}

impl SigningWorkerOpenedPolynomials {
    pub fn multiplication_operands(
        &self,
    ) -> base_rot::extension::mta::SigningWorkerMultiplicationOperands {
        base_rot::extension::mta::SigningWorkerMultiplicationOperands::from_scalars(
            self.0.context,
            self.0.triple_index,
            self.0.secrets.e.constant,
            self.0.secrets.f.constant,
        )
    }

    pub fn private_share_for_client(&self) -> SigningWorkerPolynomialShareMessage {
        SigningWorkerPolynomialShareMessage(private_share_message(
            &self.0,
            Scalar::from(CLIENT_COORDINATE),
        ))
    }
}

pub fn verify_client_polynomial_opening(
    expected_context: PresignPairContext,
    expected_triple_index: TripleIndex,
    commitment: ClientPolynomialCommitmentMessage,
    opening: ClientPolynomialOpeningMessage,
) -> Result<VerifiedClientPolynomialCommitment, PolynomialError> {
    verify_opening(
        expected_context,
        expected_triple_index,
        CLIENT_ROLE,
        commitment.0,
        opening.0,
    )
    .map(VerifiedClientPolynomialCommitment)
}

pub fn verify_signing_worker_polynomial_opening(
    expected_context: PresignPairContext,
    expected_triple_index: TripleIndex,
    commitment: SigningWorkerPolynomialCommitmentMessage,
    opening: SigningWorkerPolynomialOpeningMessage,
) -> Result<VerifiedSigningWorkerPolynomialCommitment, PolynomialError> {
    verify_opening(
        expected_context,
        expected_triple_index,
        SIGNING_WORKER_ROLE,
        commitment.0,
        opening.0,
    )
    .map(VerifiedSigningWorkerPolynomialCommitment)
}

pub fn verify_client_private_share_for_signing_worker(
    expected_context: PresignPairContext,
    expected_triple_index: TripleIndex,
    commitment: &VerifiedClientPolynomialCommitment,
    message: ClientPolynomialShareMessage,
) -> Result<VerifiedClientPrivateShare, PolynomialError> {
    verify_private_share(
        expected_context,
        expected_triple_index,
        Scalar::from(SIGNING_WORKER_COORDINATE),
        commitment.0,
        message.0,
    )
    .map(|share| {
        VerifiedClientPrivateShare(VerifiedPrivatePolynomialShare {
            context: expected_context,
            triple_index: expected_triple_index,
            public: commitment.0.public,
            share,
        })
    })
}

pub fn verify_signing_worker_private_share_for_client(
    expected_context: PresignPairContext,
    expected_triple_index: TripleIndex,
    commitment: &VerifiedSigningWorkerPolynomialCommitment,
    message: SigningWorkerPolynomialShareMessage,
) -> Result<VerifiedSigningWorkerPrivateShare, PolynomialError> {
    verify_private_share(
        expected_context,
        expected_triple_index,
        Scalar::from(CLIENT_COORDINATE),
        commitment.0,
        message.0,
    )
    .map(|share| {
        VerifiedSigningWorkerPrivateShare(VerifiedPrivatePolynomialShare {
            context: expected_context,
            triple_index: expected_triple_index,
            public: commitment.0.public,
            share,
        })
    })
}

fn commit_polynomials(
    context: PresignPairContext,
    triple_index: TripleIndex,
    role: u8,
    rng: &mut impl CryptoRngCore,
) -> Result<(CommittedPolynomialState, PolynomialCommitmentMessage), PolynomialError> {
    let secrets = SecretPolynomialSet::generate(rng)?;
    let public = secrets.commitment();
    let mut randomizer = [0u8; RANDOMIZER_SIZE];
    rng.fill_bytes(&mut randomizer);
    let digest = commitment_digest(context, triple_index, role, public, &randomizer);
    let state = CommittedPolynomialState {
        context,
        triple_index,
        secrets,
        public,
        randomizer: CommitmentRandomizer(randomizer),
    };
    let message = PolynomialCommitmentMessage {
        context,
        triple_index,
        digest,
    };
    Ok((state, message))
}

fn open_polynomials(
    state: CommittedPolynomialState,
) -> (OpenedPolynomialState, PolynomialOpeningMessage) {
    let message = PolynomialOpeningMessage {
        context: state.context,
        triple_index: state.triple_index,
        public: state.public,
        randomizer: state.randomizer.0,
    };
    let opened = OpenedPolynomialState {
        context: state.context,
        triple_index: state.triple_index,
        secrets: state.secrets,
    };
    (opened, message)
}

fn private_share_message(
    state: &OpenedPolynomialState,
    coordinate: Scalar,
) -> PrivatePolynomialShareMessage {
    PrivatePolynomialShareMessage {
        context: state.context,
        triple_index: state.triple_index,
        share: state.secrets.private_share(coordinate),
    }
}

fn verify_opening(
    expected_context: PresignPairContext,
    expected_triple_index: TripleIndex,
    role: u8,
    commitment: PolynomialCommitmentMessage,
    opening: PolynomialOpeningMessage,
) -> Result<VerifiedPolynomialCommitment, PolynomialError> {
    check_binding(
        expected_context,
        expected_triple_index,
        commitment.context,
        commitment.triple_index,
    )?;
    check_binding(
        expected_context,
        expected_triple_index,
        opening.context,
        opening.triple_index,
    )?;
    let actual = commitment_digest(
        opening.context,
        opening.triple_index,
        role,
        opening.public,
        &opening.randomizer,
    );
    if !bool::from(commitment.digest.ct_eq(&actual)) {
        return Err(PolynomialError::CommitmentOpeningMismatch);
    }
    Ok(VerifiedPolynomialCommitment {
        context: opening.context,
        triple_index: opening.triple_index,
        public: opening.public,
    })
}

fn verify_private_share(
    expected_context: PresignPairContext,
    expected_triple_index: TripleIndex,
    coordinate: Scalar,
    commitment: VerifiedPolynomialCommitment,
    message: PrivatePolynomialShareMessage,
) -> Result<PrivatePolynomialShare, PolynomialError> {
    check_binding(
        expected_context,
        expected_triple_index,
        commitment.context,
        commitment.triple_index,
    )?;
    check_binding(
        expected_context,
        expected_triple_index,
        message.context,
        message.triple_index,
    )?;
    let expected_e = commitment.public.big_e.evaluate(coordinate);
    let expected_f = commitment.public.big_f.evaluate(coordinate);
    let actual_e = ProjectivePoint::GENERATOR * message.share.e;
    let actual_f = ProjectivePoint::GENERATOR * message.share.f;
    if !bool::from(expected_e.ct_eq(&actual_e)) || !bool::from(expected_f.ct_eq(&actual_f)) {
        return Err(PolynomialError::PrivateShareMismatch);
    }
    Ok(message.share)
}

fn check_binding(
    expected_context: PresignPairContext,
    expected_triple_index: TripleIndex,
    actual_context: PresignPairContext,
    actual_triple_index: TripleIndex,
) -> Result<(), PolynomialError> {
    if actual_context != expected_context {
        return Err(PolynomialError::ContextMismatch);
    }
    if actual_triple_index != expected_triple_index {
        return Err(PolynomialError::TripleIndexMismatch);
    }
    Ok(())
}

fn random_nonzero_scalar(rng: &mut impl CryptoRngCore) -> Result<Scalar, PolynomialError> {
    for _ in 0..MAX_NONZERO_ATTEMPTS {
        let candidate = Scalar::random(&mut *rng);
        if !bool::from(candidate.is_zero()) {
            return Ok(candidate);
        }
    }
    Err(PolynomialError::PolynomialGenerationFailed)
}

fn commitment_digest(
    context: PresignPairContext,
    triple_index: TripleIndex,
    role: u8,
    public: PublicPolynomialSet,
    randomizer: &[u8; RANDOMIZER_SIZE],
) -> [u8; 32] {
    let points = public.into_parts();
    let mut hasher = Sha256::new();
    absorb_field(&mut hasher, 1, OPENING_DOMAIN);
    absorb_field(&mut hasher, 2, SUITE);
    absorb_field(&mut hasher, 3, context.signing_scope().as_bytes());
    absorb_field(&mut hasher, 4, context.pair().as_bytes());
    absorb_field(&mut hasher, 5, &[triple_index_byte(triple_index)]);
    absorb_field(&mut hasher, 6, &[role]);
    absorb_field(&mut hasher, 16, points[0].as_bytes());
    absorb_field(&mut hasher, 17, points[1].as_bytes());
    absorb_field(&mut hasher, 18, points[2].as_bytes());
    absorb_field(&mut hasher, 19, points[3].as_bytes());
    absorb_field(&mut hasher, 20, points[4].as_bytes());
    absorb_field(&mut hasher, 21, randomizer);
    hasher.finalize().into()
}

fn absorb_field(hasher: &mut Sha256, tag: u16, value: &[u8]) {
    hasher.update(tag.to_be_bytes());
    hasher.update((value.len() as u32).to_be_bytes());
    hasher.update(value);
}

fn triple_index_byte(index: TripleIndex) -> u8 {
    match index {
        TripleIndex::Zero => 0,
        TripleIndex::One => 1,
    }
}

fn parse_point(bytes: CompressedPointBytes) -> Result<AffinePoint, PolynomialError> {
    parse_nonidentity_point(bytes).map_err(|error| match error {
        crate::PresignError::IdentityPoint => PolynomialError::IdentityPoint,
        _ => PolynomialError::InvalidPoint,
    })
}

fn parse_scalar(bytes: ScalarBytes) -> Result<Scalar, PolynomialError> {
    use k256::elliptic_curve::ff::PrimeField;

    Option::<Scalar>::from(Scalar::from_repr(bytes.into_bytes().into()))
        .ok_or(PolynomialError::NonCanonicalScalar)
}

#[cfg(test)]
mod tests {
    use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
    use router_ab_ecdsa_wire::{PairContextDigest, SigningScopeDigest};

    use super::*;

    fn binding(scope: u8, pair: u8) -> PresignPairContext {
        PresignPairContext::new(
            SigningScopeDigest::new([scope; 32]),
            PairContextDigest::new([pair; 32]),
        )
    }

    #[test]
    fn fixed_roles_open_and_verify_private_shares() {
        let context = binding(0x24, 0x42);
        let mut client_rng = ChaCha20Rng::from_seed([1; 32]);
        let mut worker_rng = ChaCha20Rng::from_seed([2; 32]);
        let (client_state, client_commitment) =
            commit_client_polynomials(context, TripleIndex::Zero, &mut client_rng)
                .expect("client commitment");
        let (worker_state, worker_commitment) =
            commit_signing_worker_polynomials(context, TripleIndex::Zero, &mut worker_rng)
                .expect("worker commitment");
        let (client_opened, client_opening) = client_state.open();
        let (worker_opened, worker_opening) = worker_state.open();

        let verified_client = verify_client_polynomial_opening(
            context,
            TripleIndex::Zero,
            client_commitment,
            client_opening,
        )
        .expect("valid client opening");
        let verified_worker = verify_signing_worker_polynomial_opening(
            context,
            TripleIndex::Zero,
            worker_commitment,
            worker_opening,
        )
        .expect("valid worker opening");

        verify_client_private_share_for_signing_worker(
            context,
            TripleIndex::Zero,
            &verified_client,
            client_opened.private_share_for_signing_worker(),
        )
        .expect("valid client share");
        verify_signing_worker_private_share_for_client(
            context,
            TripleIndex::Zero,
            &verified_worker,
            worker_opened.private_share_for_client(),
        )
        .expect("valid worker share");
    }

    #[test]
    fn opening_context_substitution_aborts() {
        let context = binding(1, 2);
        let mut rng = ChaCha20Rng::from_seed([3; 32]);
        let (state, commitment) =
            commit_client_polynomials(context, TripleIndex::One, &mut rng).expect("commitment");
        let (_, opening) = state.open();
        let result =
            verify_client_polynomial_opening(binding(1, 9), TripleIndex::One, commitment, opening);
        assert!(matches!(result, Err(PolynomialError::ContextMismatch)));
    }

    #[test]
    fn opening_triple_index_substitution_aborts() {
        let context = binding(2, 3);
        let mut rng = ChaCha20Rng::from_seed([4; 32]);
        let (state, commitment) =
            commit_client_polynomials(context, TripleIndex::Zero, &mut rng).expect("commitment");
        let (_, opening) = state.open();
        let result =
            verify_client_polynomial_opening(context, TripleIndex::One, commitment, opening);
        assert!(matches!(result, Err(PolynomialError::TripleIndexMismatch)));
    }

    #[test]
    fn altered_randomizer_aborts() {
        let context = binding(4, 5);
        let mut rng = ChaCha20Rng::from_seed([6; 32]);
        let (state, commitment) =
            commit_client_polynomials(context, TripleIndex::Zero, &mut rng).expect("commitment");
        let (_, opening) = state.open();
        let (context, index, e0, e1, f0, f1, l0, mut randomizer) = opening.into_parts();
        randomizer[0] ^= 1;
        let altered = ClientPolynomialOpeningMessage::from_parts(
            context, index, e0, e1, f0, f1, l0, randomizer,
        )
        .expect("well-formed altered opening");

        let result =
            verify_client_polynomial_opening(context, TripleIndex::Zero, commitment, altered);
        assert!(matches!(
            result,
            Err(PolynomialError::CommitmentOpeningMismatch)
        ));
    }

    #[test]
    fn client_opening_cannot_be_reflected_as_worker_opening() {
        let context = binding(7, 8);
        let mut rng = ChaCha20Rng::from_seed([9; 32]);
        let (state, commitment) =
            commit_client_polynomials(context, TripleIndex::One, &mut rng).expect("commitment");
        let (_, opening) = state.open();
        let (commit_context, index, digest) = commitment.into_parts();
        let (open_context, _, e0, e1, f0, f1, l0, randomizer) = opening.into_parts();
        let reflected_commitment =
            SigningWorkerPolynomialCommitmentMessage::from_parts(commit_context, index, digest);
        let reflected_opening = SigningWorkerPolynomialOpeningMessage::from_parts(
            open_context,
            index,
            e0,
            e1,
            f0,
            f1,
            l0,
            randomizer,
        )
        .expect("well-formed reflected opening");

        let result = verify_signing_worker_polynomial_opening(
            context,
            TripleIndex::One,
            reflected_commitment,
            reflected_opening,
        );
        assert!(matches!(
            result,
            Err(PolynomialError::CommitmentOpeningMismatch)
        ));
    }

    #[test]
    fn altered_private_share_aborts() {
        let context = binding(10, 11);
        let mut rng = ChaCha20Rng::from_seed([12; 32]);
        let (state, commitment) =
            commit_client_polynomials(context, TripleIndex::Zero, &mut rng).expect("commitment");
        let (opened, opening) = state.open();
        let verified =
            verify_client_polynomial_opening(context, TripleIndex::Zero, commitment, opening)
                .expect("valid opening");
        let share = opened.private_share_for_signing_worker();
        let (share_context, index, e, f) = share.into_parts();
        let altered_e = parse_scalar(e).expect("canonical share") + Scalar::ONE;
        let altered = ClientPolynomialShareMessage::from_parts(
            share_context,
            index,
            scalar_bytes(altered_e),
            f,
        )
        .expect("canonical altered share");

        let result = verify_client_private_share_for_signing_worker(
            context,
            TripleIndex::Zero,
            &verified,
            altered,
        );
        assert!(matches!(result, Err(PolynomialError::PrivateShareMismatch)));
    }
}
