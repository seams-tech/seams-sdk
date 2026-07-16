use core::fmt;

use k256::{
    elliptic_curve::{
        bigint::U256,
        ff::PrimeField,
        group::prime::PrimeCurveAffine,
        ops::Reduce,
        sec1::{FromEncodedPoint, ToEncodedPoint},
        Field,
    },
    AffinePoint, EncodedPoint, FieldBytes, ProjectivePoint, Scalar,
};
use rand_core::CryptoRngCore;
use router_ab_ecdsa_wire::{CompressedPointBytes, PresignPairContext, ScalarBytes};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

const PROOF_DOMAIN: &[u8] = b"seams/router-ab-ecdsa-presign/proof/v1";
const SUITE: &[u8] = b"secp256k1+sha256";
const MAX_CHALLENGE_ATTEMPTS: u16 = 256;

const ROLE_CLIENT: u8 = 1;
const ROLE_SIGNING_WORKER: u8 = 2;
const PROOF_DLOG: u8 = 1;
const PROOF_DLOG_EQ: u8 = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TripleIndex {
    Zero,
    One,
}

impl TripleIndex {
    const fn as_byte(self) -> u8 {
        match self {
            Self::Zero => 0,
            Self::One => 1,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DLogProofKind {
    TripleA,
    TripleB,
    ProductShare,
}

impl DLogProofKind {
    const fn as_byte(self) -> u8 {
        match self {
            Self::TripleA => 1,
            Self::TripleB => 2,
            Self::ProductShare => 3,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProofError {
    InvalidPoint,
    IdentityPoint,
    NonCanonicalScalar,
    ZeroWitness,
    ZeroNonce,
    NonceGenerationFailed,
    StatementWitnessMismatch,
    InvalidProof,
    TranscriptFieldTooLarge,
    ChallengeDerivationFailed,
}

impl fmt::Display for ProofError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidPoint => "invalid compressed secp256k1 point",
            Self::IdentityPoint => "identity point is forbidden",
            Self::NonCanonicalScalar => "non-canonical secp256k1 scalar",
            Self::ZeroWitness => "zero proof witness is forbidden",
            Self::ZeroNonce => "zero proof nonce is forbidden",
            Self::NonceGenerationFailed => "failed to generate a non-zero proof nonce",
            Self::StatementWitnessMismatch => "proof witness does not satisfy its statement",
            Self::InvalidProof => "proof equation failed",
            Self::TranscriptFieldTooLarge => "proof transcript field exceeds its length bound",
            Self::ChallengeDerivationFailed => "failed to derive a non-zero proof challenge",
        })
    }
}

impl std::error::Error for ProofError {}

#[derive(Clone, Copy)]
struct ProofContext {
    binding: PresignPairContext,
    triple_index: TripleIndex,
    kind: u8,
}

macro_rules! define_dlog_context {
    ($name:ident) => {
        #[derive(Clone, Copy)]
        pub struct $name(ProofContext);

        impl $name {
            pub const fn new(
                binding: PresignPairContext,
                triple_index: TripleIndex,
                kind: DLogProofKind,
            ) -> Self {
                Self(ProofContext {
                    binding,
                    triple_index,
                    kind: kind.as_byte(),
                })
            }
        }
    };
}

macro_rules! define_dlog_eq_context {
    ($name:ident) => {
        #[derive(Clone, Copy)]
        pub struct $name(ProofContext);

        impl $name {
            pub const fn new(binding: PresignPairContext, triple_index: TripleIndex) -> Self {
                Self(ProofContext {
                    binding,
                    triple_index,
                    kind: 1,
                })
            }
        }
    };
}

define_dlog_context!(ClientDLogContext);
define_dlog_context!(SigningWorkerDLogContext);
define_dlog_eq_context!(ClientDLogEqContext);
define_dlog_eq_context!(SigningWorkerDLogEqContext);

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ProofWitness(Scalar);

impl ProofWitness {
    pub fn from_bytes(bytes: ScalarBytes) -> Result<Self, ProofError> {
        let scalar = parse_scalar(bytes.into_bytes())?;
        if bool::from(scalar.is_zero()) {
            return Err(ProofError::ZeroWitness);
        }
        Ok(Self(scalar))
    }
}

#[cfg(any(test, feature = "test-utils"))]
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ProofNonce(Scalar);

#[cfg(any(test, feature = "test-utils"))]
impl ProofNonce {
    pub fn from_bytes(bytes: ScalarBytes) -> Result<Self, ProofError> {
        let scalar = parse_scalar(bytes.into_bytes())?;
        if bool::from(scalar.is_zero()) {
            return Err(ProofError::ZeroNonce);
        }
        Ok(Self(scalar))
    }
}

#[derive(Clone, Copy)]
pub struct DLogStatement {
    public: AffinePoint,
}

impl DLogStatement {
    pub fn from_bytes(public: CompressedPointBytes) -> Result<Self, ProofError> {
        Ok(Self {
            public: parse_nonidentity_point(public)?,
        })
    }
}

#[derive(Clone, Copy)]
pub struct DLogEqStatement {
    public0: AffinePoint,
    generator1: AffinePoint,
    public1: AffinePoint,
}

impl DLogEqStatement {
    pub fn from_bytes(
        public0: CompressedPointBytes,
        generator1: CompressedPointBytes,
        public1: CompressedPointBytes,
    ) -> Result<Self, ProofError> {
        Ok(Self {
            public0: parse_nonidentity_point(public0)?,
            generator1: parse_nonidentity_point(generator1)?,
            public1: parse_nonidentity_point(public1)?,
        })
    }
}

pub struct DLogProof {
    commitment: AffinePoint,
    response: Scalar,
}

impl DLogProof {
    pub fn from_parts(
        commitment: CompressedPointBytes,
        response: ScalarBytes,
    ) -> Result<Self, ProofError> {
        Ok(Self {
            commitment: parse_nonidentity_point(commitment)?,
            response: parse_scalar(response.into_bytes())?,
        })
    }

    pub fn into_parts(self) -> (CompressedPointBytes, ScalarBytes) {
        (point_bytes(self.commitment), scalar_bytes(self.response))
    }
}

pub struct DLogEqProof {
    commitment0: AffinePoint,
    commitment1: AffinePoint,
    response: Scalar,
}

impl DLogEqProof {
    pub fn from_parts(
        commitment0: CompressedPointBytes,
        commitment1: CompressedPointBytes,
        response: ScalarBytes,
    ) -> Result<Self, ProofError> {
        Ok(Self {
            commitment0: parse_nonidentity_point(commitment0)?,
            commitment1: parse_nonidentity_point(commitment1)?,
            response: parse_scalar(response.into_bytes())?,
        })
    }

    pub fn into_parts(self) -> (CompressedPointBytes, CompressedPointBytes, ScalarBytes) {
        (
            point_bytes(self.commitment0),
            point_bytes(self.commitment1),
            scalar_bytes(self.response),
        )
    }
}

pub fn prove_client_dlog(
    context: ClientDLogContext,
    statement: DLogStatement,
    witness: ProofWitness,
    rng: &mut impl CryptoRngCore,
) -> Result<DLogProof, ProofError> {
    prove_dlog(
        ROLE_CLIENT,
        context.0,
        statement,
        witness,
        generate_nonce(rng)?,
    )
}

pub fn prove_signing_worker_dlog(
    context: SigningWorkerDLogContext,
    statement: DLogStatement,
    witness: ProofWitness,
    rng: &mut impl CryptoRngCore,
) -> Result<DLogProof, ProofError> {
    prove_dlog(
        ROLE_SIGNING_WORKER,
        context.0,
        statement,
        witness,
        generate_nonce(rng)?,
    )
}

pub fn verify_client_dlog(
    context: ClientDLogContext,
    statement: DLogStatement,
    proof: DLogProof,
) -> Result<(), ProofError> {
    verify_dlog(ROLE_CLIENT, context.0, statement, proof)
}

pub fn verify_signing_worker_dlog(
    context: SigningWorkerDLogContext,
    statement: DLogStatement,
    proof: DLogProof,
) -> Result<(), ProofError> {
    verify_dlog(ROLE_SIGNING_WORKER, context.0, statement, proof)
}

pub fn prove_client_dlog_eq(
    context: ClientDLogEqContext,
    statement: DLogEqStatement,
    witness: ProofWitness,
    rng: &mut impl CryptoRngCore,
) -> Result<DLogEqProof, ProofError> {
    prove_dlog_eq(
        ROLE_CLIENT,
        context.0,
        statement,
        witness,
        generate_nonce(rng)?,
    )
}

pub fn prove_signing_worker_dlog_eq(
    context: SigningWorkerDLogEqContext,
    statement: DLogEqStatement,
    witness: ProofWitness,
    rng: &mut impl CryptoRngCore,
) -> Result<DLogEqProof, ProofError> {
    prove_dlog_eq(
        ROLE_SIGNING_WORKER,
        context.0,
        statement,
        witness,
        generate_nonce(rng)?,
    )
}

pub fn verify_client_dlog_eq(
    context: ClientDLogEqContext,
    statement: DLogEqStatement,
    proof: DLogEqProof,
) -> Result<(), ProofError> {
    verify_dlog_eq(ROLE_CLIENT, context.0, statement, proof)
}

pub fn verify_signing_worker_dlog_eq(
    context: SigningWorkerDLogEqContext,
    statement: DLogEqStatement,
    proof: DLogEqProof,
) -> Result<(), ProofError> {
    verify_dlog_eq(ROLE_SIGNING_WORKER, context.0, statement, proof)
}

#[cfg(any(test, feature = "test-utils"))]
pub fn prove_client_dlog_with_nonce(
    context: ClientDLogContext,
    statement: DLogStatement,
    witness: ProofWitness,
    nonce: ProofNonce,
) -> Result<DLogProof, ProofError> {
    prove_dlog(ROLE_CLIENT, context.0, statement, witness, nonce.0)
}

#[cfg(any(test, feature = "test-utils"))]
pub fn prove_signing_worker_dlog_with_nonce(
    context: SigningWorkerDLogContext,
    statement: DLogStatement,
    witness: ProofWitness,
    nonce: ProofNonce,
) -> Result<DLogProof, ProofError> {
    prove_dlog(ROLE_SIGNING_WORKER, context.0, statement, witness, nonce.0)
}

#[cfg(any(test, feature = "test-utils"))]
pub fn prove_client_dlog_eq_with_nonce(
    context: ClientDLogEqContext,
    statement: DLogEqStatement,
    witness: ProofWitness,
    nonce: ProofNonce,
) -> Result<DLogEqProof, ProofError> {
    prove_dlog_eq(ROLE_CLIENT, context.0, statement, witness, nonce.0)
}

#[cfg(any(test, feature = "test-utils"))]
pub fn prove_signing_worker_dlog_eq_with_nonce(
    context: SigningWorkerDLogEqContext,
    statement: DLogEqStatement,
    witness: ProofWitness,
    nonce: ProofNonce,
) -> Result<DLogEqProof, ProofError> {
    prove_dlog_eq(ROLE_SIGNING_WORKER, context.0, statement, witness, nonce.0)
}

fn prove_dlog(
    role: u8,
    context: ProofContext,
    statement: DLogStatement,
    witness: ProofWitness,
    nonce: Scalar,
) -> Result<DLogProof, ProofError> {
    if ProjectivePoint::GENERATOR * witness.0 != ProjectivePoint::from(statement.public) {
        return Err(ProofError::StatementWitnessMismatch);
    }

    let commitment = (ProjectivePoint::GENERATOR * nonce).to_affine();
    let challenge = dlog_challenge(role, context, statement.public, commitment)?;
    let response = nonce + challenge * witness.0;

    Ok(DLogProof {
        commitment,
        response,
    })
}

fn verify_dlog(
    role: u8,
    context: ProofContext,
    statement: DLogStatement,
    proof: DLogProof,
) -> Result<(), ProofError> {
    let challenge = dlog_challenge(role, context, statement.public, proof.commitment)?;
    let lhs = ProjectivePoint::GENERATOR * proof.response;
    let rhs = ProjectivePoint::from(proof.commitment)
        + ProjectivePoint::from(statement.public) * challenge;

    if lhs != rhs {
        return Err(ProofError::InvalidProof);
    }
    Ok(())
}

fn prove_dlog_eq(
    role: u8,
    context: ProofContext,
    statement: DLogEqStatement,
    witness: ProofWitness,
    nonce: Scalar,
) -> Result<DLogEqProof, ProofError> {
    let witness_public0 = ProjectivePoint::GENERATOR * witness.0;
    let witness_public1 = ProjectivePoint::from(statement.generator1) * witness.0;
    if witness_public0 != ProjectivePoint::from(statement.public0)
        || witness_public1 != ProjectivePoint::from(statement.public1)
    {
        return Err(ProofError::StatementWitnessMismatch);
    }

    let commitment0 = (ProjectivePoint::GENERATOR * nonce).to_affine();
    let commitment1 = (ProjectivePoint::from(statement.generator1) * nonce).to_affine();
    let challenge = dlog_eq_challenge(role, context, statement, commitment0, commitment1)?;
    let response = nonce + challenge * witness.0;

    Ok(DLogEqProof {
        commitment0,
        commitment1,
        response,
    })
}

fn verify_dlog_eq(
    role: u8,
    context: ProofContext,
    statement: DLogEqStatement,
    proof: DLogEqProof,
) -> Result<(), ProofError> {
    let challenge = dlog_eq_challenge(
        role,
        context,
        statement,
        proof.commitment0,
        proof.commitment1,
    )?;
    let lhs0 = ProjectivePoint::GENERATOR * proof.response;
    let rhs0 = ProjectivePoint::from(proof.commitment0)
        + ProjectivePoint::from(statement.public0) * challenge;
    let lhs1 = ProjectivePoint::from(statement.generator1) * proof.response;
    let rhs1 = ProjectivePoint::from(proof.commitment1)
        + ProjectivePoint::from(statement.public1) * challenge;

    if lhs0 != rhs0 || lhs1 != rhs1 {
        return Err(ProofError::InvalidProof);
    }
    Ok(())
}

fn dlog_challenge(
    role: u8,
    context: ProofContext,
    public: AffinePoint,
    commitment: AffinePoint,
) -> Result<Scalar, ProofError> {
    let points = [point_array(public), point_array(commitment)];
    derive_challenge(role, context, PROOF_DLOG, &points)
}

fn dlog_eq_challenge(
    role: u8,
    context: ProofContext,
    statement: DLogEqStatement,
    commitment0: AffinePoint,
    commitment1: AffinePoint,
) -> Result<Scalar, ProofError> {
    let points = [
        point_array(statement.public0),
        point_array(statement.generator1),
        point_array(statement.public1),
        point_array(commitment0),
        point_array(commitment1),
    ];
    derive_challenge(role, context, PROOF_DLOG_EQ, &points)
}

fn derive_challenge<const N: usize>(
    role: u8,
    context: ProofContext,
    proof_type: u8,
    points: &[[u8; 33]; N],
) -> Result<Scalar, ProofError> {
    let mut base = Sha256::new();
    absorb(&mut base, 1, PROOF_DOMAIN)?;
    absorb(&mut base, 2, SUITE)?;
    absorb(&mut base, 3, context.binding.signing_scope().as_bytes())?;
    absorb(&mut base, 4, context.binding.pair().as_bytes())?;
    absorb(&mut base, 5, &[context.triple_index.as_byte()])?;
    absorb(&mut base, 6, &[role])?;
    absorb(&mut base, 7, &[proof_type])?;
    absorb(&mut base, 8, &[context.kind])?;
    for (index, point) in points.iter().enumerate() {
        let tag =
            16u16 + u16::try_from(index).map_err(|_| ProofError::ChallengeDerivationFailed)?;
        absorb(&mut base, tag, point)?;
    }

    for counter in 0..MAX_CHALLENGE_ATTEMPTS {
        let mut attempt = base.clone();
        absorb(&mut attempt, 255, &counter.to_be_bytes())?;
        let digest: FieldBytes = attempt.finalize();
        let challenge = <Scalar as Reduce<U256>>::reduce_bytes(&digest);
        if !bool::from(challenge.is_zero()) {
            return Ok(challenge);
        }
    }

    Err(ProofError::ChallengeDerivationFailed)
}

fn generate_nonce(rng: &mut impl CryptoRngCore) -> Result<Scalar, ProofError> {
    for _ in 0..MAX_CHALLENGE_ATTEMPTS {
        let nonce = Scalar::random(&mut *rng);
        if !bool::from(nonce.is_zero()) {
            return Ok(nonce);
        }
    }
    Err(ProofError::NonceGenerationFailed)
}

fn absorb(hasher: &mut Sha256, tag: u16, value: &[u8]) -> Result<(), ProofError> {
    let length = u32::try_from(value.len()).map_err(|_| ProofError::TranscriptFieldTooLarge)?;
    hasher.update(tag.to_be_bytes());
    hasher.update(length.to_be_bytes());
    hasher.update(value);
    Ok(())
}

fn parse_scalar(bytes: [u8; 32]) -> Result<Scalar, ProofError> {
    Option::<Scalar>::from(Scalar::from_repr(bytes.into())).ok_or(ProofError::NonCanonicalScalar)
}

fn parse_nonidentity_point(bytes: CompressedPointBytes) -> Result<AffinePoint, ProofError> {
    let encoded =
        EncodedPoint::from_bytes(bytes.as_bytes()).map_err(|_| ProofError::InvalidPoint)?;
    let point = Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&encoded))
        .ok_or(ProofError::InvalidPoint)?;
    if bool::from(point.is_identity()) {
        return Err(ProofError::IdentityPoint);
    }
    Ok(point)
}

fn scalar_bytes(scalar: Scalar) -> ScalarBytes {
    ScalarBytes::new(scalar.to_bytes().into())
}

fn point_array(point: AffinePoint) -> [u8; 33] {
    point
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .expect("compressed secp256k1 point has fixed width")
}

fn point_bytes(point: AffinePoint) -> CompressedPointBytes {
    CompressedPointBytes::new(point_array(point))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
    use router_ab_ecdsa_wire::{PairContextDigest, SigningScopeDigest};

    fn binding(scope: u8, pair: u8) -> PresignPairContext {
        PresignPairContext::new(
            SigningScopeDigest::new([scope; 32]),
            PairContextDigest::new([pair; 32]),
        )
    }

    fn scalar_input(value: u64) -> ScalarBytes {
        scalar_bytes(Scalar::from(value))
    }

    fn generator_multiple(value: u64) -> CompressedPointBytes {
        point_bytes((ProjectivePoint::GENERATOR * Scalar::from(value)).to_affine())
    }

    fn dlog_statement(value: u64) -> DLogStatement {
        DLogStatement::from_bytes(generator_multiple(value)).expect("valid statement")
    }

    fn dlog_eq_statement(witness: u64, alternate_generator: u64) -> DLogEqStatement {
        let witness = Scalar::from(witness);
        let generator1 = ProjectivePoint::GENERATOR * Scalar::from(alternate_generator);
        DLogEqStatement::from_bytes(
            point_bytes((ProjectivePoint::GENERATOR * witness).to_affine()),
            point_bytes(generator1.to_affine()),
            point_bytes((generator1 * witness).to_affine()),
        )
        .expect("valid equality statement")
    }

    fn witness(value: u64) -> ProofWitness {
        ProofWitness::from_bytes(scalar_input(value)).expect("valid witness")
    }

    fn nonce(value: u64) -> ProofNonce {
        ProofNonce::from_bytes(scalar_input(value)).expect("valid nonce")
    }

    fn expect_proof_error<T>(result: Result<T, ProofError>, expected: ProofError) {
        match result {
            Ok(_) => panic!("expected proof error"),
            Err(actual) => assert_eq!(actual, expected),
        }
    }

    #[test]
    fn client_dlog_proof_verifies_only_in_its_bound_context() {
        let context =
            ClientDLogContext::new(binding(1, 2), TripleIndex::Zero, DLogProofKind::TripleA);
        let proof = prove_client_dlog_with_nonce(context, dlog_statement(7), witness(7), nonce(11))
            .expect("valid proof");
        verify_client_dlog(context, dlog_statement(7), proof).expect("proof verifies");

        let proof = prove_client_dlog_with_nonce(context, dlog_statement(7), witness(7), nonce(11))
            .expect("valid proof");
        let wrong_context =
            ClientDLogContext::new(binding(1, 3), TripleIndex::Zero, DLogProofKind::TripleA);
        expect_proof_error(
            verify_client_dlog(wrong_context, dlog_statement(7), proof),
            ProofError::InvalidProof,
        );
    }

    #[test]
    fn dlog_proof_role_reflection_fails() {
        let binding = binding(1, 2);
        let client_context =
            ClientDLogContext::new(binding, TripleIndex::One, DLogProofKind::TripleB);
        let proof = prove_client_dlog_with_nonce(
            client_context,
            dlog_statement(13),
            witness(13),
            nonce(17),
        )
        .expect("valid client proof");
        let (_, response) = proof.into_parts();
        let commitment = generator_multiple(17);
        let reflected = DLogProof::from_parts(commitment, response).expect("valid proof encoding");
        let worker_context =
            SigningWorkerDLogContext::new(binding, TripleIndex::One, DLogProofKind::TripleB);

        expect_proof_error(
            verify_signing_worker_dlog(worker_context, dlog_statement(13), reflected),
            ProofError::InvalidProof,
        );
    }

    #[test]
    fn client_dlog_eq_proof_verifies_and_rejects_a_tampered_response() {
        let context = ClientDLogEqContext::new(binding(4, 5), TripleIndex::Zero);
        let proof = prove_client_dlog_eq_with_nonce(
            context,
            dlog_eq_statement(19, 23),
            witness(19),
            nonce(29),
        )
        .expect("valid equality proof");
        verify_client_dlog_eq(context, dlog_eq_statement(19, 23), proof)
            .expect("equality proof verifies");

        let proof = prove_client_dlog_eq_with_nonce(
            context,
            dlog_eq_statement(19, 23),
            witness(19),
            nonce(29),
        )
        .expect("valid equality proof");
        let (commitment0, commitment1, response) = proof.into_parts();
        let tampered_response =
            parse_scalar(response.into_bytes()).expect("canonical response") + Scalar::ONE;
        let tampered =
            DLogEqProof::from_parts(commitment0, commitment1, scalar_bytes(tampered_response))
                .expect("valid proof encoding");

        expect_proof_error(
            verify_client_dlog_eq(context, dlog_eq_statement(19, 23), tampered),
            ProofError::InvalidProof,
        );
    }

    #[test]
    fn mismatched_witness_and_zero_nonce_are_rejected_before_proof_emission() {
        let context = SigningWorkerDLogContext::new(
            binding(6, 7),
            TripleIndex::Zero,
            DLogProofKind::ProductShare,
        );
        expect_proof_error(
            prove_signing_worker_dlog_with_nonce(
                context,
                dlog_statement(31),
                witness(37),
                nonce(41),
            ),
            ProofError::StatementWitnessMismatch,
        );
        expect_proof_error(
            ProofNonce::from_bytes(ScalarBytes::new([0; 32])),
            ProofError::ZeroNonce,
        );
    }

    #[test]
    fn production_prover_generates_its_nonce_from_a_crypto_rng() {
        let context =
            SigningWorkerDLogContext::new(binding(8, 9), TripleIndex::One, DLogProofKind::TripleA);
        let mut rng = ChaCha20Rng::from_seed([0x55; 32]);
        let proof = prove_signing_worker_dlog(context, dlog_statement(43), witness(43), &mut rng)
            .expect("valid randomized proof");
        verify_signing_worker_dlog(context, dlog_statement(43), proof)
            .expect("randomized proof verifies");
    }
}
