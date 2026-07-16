use core::fmt;

use k256::{elliptic_curve::Group, AffinePoint, ProjectivePoint, Scalar};
use rand_core::CryptoRngCore;
use router_ab_ecdsa_wire::{CompressedPointBytes, PresignPairContext, ScalarBytes};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::proofs::{
    prove_client_dlog, prove_client_dlog_eq, prove_signing_worker_dlog,
    prove_signing_worker_dlog_eq, verify_client_dlog, verify_client_dlog_eq,
    verify_signing_worker_dlog, verify_signing_worker_dlog_eq, ClientDLogContext,
    ClientDLogEqContext, DLogEqProof, DLogEqStatement, DLogProof, DLogProofKind, DLogStatement,
    ProofError, ProofWitness, SigningWorkerDLogContext, SigningWorkerDLogEqContext, TripleIndex,
};
use crate::{
    parse_nonidentity_point, parse_scalar, point_bytes, scalar_bytes, PresignError, TriplePublic,
    TripleShare, ValidatedTriple,
};

use super::base_rot::extension::mta::{
    ClientTwoTripleMultiplicationShares, FinalizationMultiplicationShares,
    SigningWorkerTwoTripleMultiplicationShares,
};
use super::{
    ClientOpenedPolynomials, OpenedPolynomialState, SigningWorkerOpenedPolynomials,
    VerifiedClientPrivateShare, VerifiedPrivatePolynomialShare, VerifiedSigningWorkerPrivateShare,
    CLIENT_COORDINATE, CLIENT_ROLE, SIGNING_WORKER_COORDINATE, SIGNING_WORKER_ROLE,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TripleGenerationError {
    ContextMismatch,
    TripleIndexMismatch,
    RoleMismatch,
    DegenerateAggregate,
    DegenerateMultiplicationShare,
    PrivateShareMismatch,
    TerminalProductMismatch,
    Boundary(PresignError),
    Proof(ProofError),
}

impl fmt::Display for TripleGenerationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ContextMismatch => formatter.write_str("triple finalization context mismatch"),
            Self::TripleIndexMismatch => formatter.write_str("triple finalization index mismatch"),
            Self::RoleMismatch => formatter.write_str("triple finalization role mismatch"),
            Self::DegenerateAggregate => formatter.write_str("triple aggregate is the identity"),
            Self::DegenerateMultiplicationShare => {
                formatter.write_str("zero multiplication share cannot be committed")
            }
            Self::PrivateShareMismatch => {
                formatter.write_str("final private triple share does not match its commitment")
            }
            Self::TerminalProductMismatch => {
                formatter.write_str("terminal triple product equation failed")
            }
            Self::Boundary(error) => write!(formatter, "triple boundary error: {error}"),
            Self::Proof(error) => write!(formatter, "triple proof error: {error}"),
        }
    }
}

impl std::error::Error for TripleGenerationError {}

impl From<ProofError> for TripleGenerationError {
    fn from(error: ProofError) -> Self {
        Self::Proof(error)
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct SecretProductEvaluation(Scalar);

struct TripleContribution {
    e_proof: DLogProof,
    f_proof: DLogProof,
    big_c_contribution: AffinePoint,
    product_proof: DLogEqProof,
    multiplication_commitment: AffinePoint,
    multiplication_proof: DLogProof,
    private_product_evaluation: SecretProductEvaluation,
}

struct FinalizationMessage {
    context: PresignPairContext,
    contributions: [TripleContribution; 2],
}

pub struct ClientTripleFinalizationMessage(FinalizationMessage);
pub struct SigningWorkerTripleFinalizationMessage(FinalizationMessage);

pub struct TripleContributionParts {
    big_c_contribution: CompressedPointBytes,
    e_proof_commitment: CompressedPointBytes,
    e_proof_response: ScalarBytes,
    f_proof_commitment: CompressedPointBytes,
    f_proof_response: ScalarBytes,
    product_proof_commitment0: CompressedPointBytes,
    product_proof_commitment1: CompressedPointBytes,
    product_proof_response: ScalarBytes,
    multiplication_commitment: CompressedPointBytes,
    multiplication_proof_commitment: CompressedPointBytes,
    multiplication_proof_response: ScalarBytes,
    private_product_evaluation: ScalarBytes,
}

impl TripleContributionParts {
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        big_c_contribution: CompressedPointBytes,
        e_proof_commitment: CompressedPointBytes,
        e_proof_response: ScalarBytes,
        f_proof_commitment: CompressedPointBytes,
        f_proof_response: ScalarBytes,
        product_proof_commitment0: CompressedPointBytes,
        product_proof_commitment1: CompressedPointBytes,
        product_proof_response: ScalarBytes,
        multiplication_commitment: CompressedPointBytes,
        multiplication_proof_commitment: CompressedPointBytes,
        multiplication_proof_response: ScalarBytes,
        private_product_evaluation: ScalarBytes,
    ) -> Self {
        Self {
            big_c_contribution,
            e_proof_commitment,
            e_proof_response,
            f_proof_commitment,
            f_proof_response,
            product_proof_commitment0,
            product_proof_commitment1,
            product_proof_response,
            multiplication_commitment,
            multiplication_proof_commitment,
            multiplication_proof_response,
            private_product_evaluation,
        }
    }

    #[allow(clippy::type_complexity)]
    pub fn into_parts(
        self,
    ) -> (
        CompressedPointBytes,
        CompressedPointBytes,
        ScalarBytes,
        CompressedPointBytes,
        ScalarBytes,
        CompressedPointBytes,
        CompressedPointBytes,
        ScalarBytes,
        CompressedPointBytes,
        CompressedPointBytes,
        ScalarBytes,
        ScalarBytes,
    ) {
        (
            self.big_c_contribution,
            self.e_proof_commitment,
            self.e_proof_response,
            self.f_proof_commitment,
            self.f_proof_response,
            self.product_proof_commitment0,
            self.product_proof_commitment1,
            self.product_proof_response,
            self.multiplication_commitment,
            self.multiplication_proof_commitment,
            self.multiplication_proof_response,
            self.private_product_evaluation,
        )
    }
}

macro_rules! define_finalization_message {
    ($name:ident) => {
        impl $name {
            pub fn from_parts(
                context: PresignPairContext,
                contributions: [TripleContributionParts; 2],
            ) -> Result<Self, TripleGenerationError> {
                let [zero, one] = contributions;
                Ok(Self(FinalizationMessage {
                    context,
                    contributions: [parse_contribution(zero)?, parse_contribution(one)?],
                }))
            }

            pub fn into_parts(self) -> (PresignPairContext, [TripleContributionParts; 2]) {
                (
                    self.0.context,
                    self.0.contributions.map(contribution_into_parts),
                )
            }
        }
    };
}

define_finalization_message!(ClientTripleFinalizationMessage);
define_finalization_message!(SigningWorkerTripleFinalizationMessage);

#[derive(Zeroize, ZeroizeOnDrop)]
struct SecretPreparedTriple {
    a_share: Scalar,
    b_share: Scalar,
    own_product_evaluation: Scalar,
}

struct PreparedTriple {
    index: TripleIndex,
    big_a: AffinePoint,
    big_b: AffinePoint,
    peer_big_e_constant: AffinePoint,
    peer_big_f_constant: AffinePoint,
    own_big_c_contribution: AffinePoint,
    own_multiplication_commitment: AffinePoint,
    aggregate_l_slope: ProjectivePoint,
    secrets: SecretPreparedTriple,
}

struct FinalizationState {
    context: PresignPairContext,
    peer_role: u8,
    triples: [PreparedTriple; 2],
}

pub struct ClientTripleFinalizationState(FinalizationState);
pub struct SigningWorkerTripleFinalizationState(FinalizationState);

pub struct ClientGeneratedTriples([ValidatedTriple; 2]);
pub struct SigningWorkerGeneratedTriples([ValidatedTriple; 2]);

impl ClientGeneratedTriples {
    pub fn into_triples(self) -> (ValidatedTriple, ValidatedTriple) {
        let [zero, one] = self.0;
        (zero, one)
    }
}

impl SigningWorkerGeneratedTriples {
    pub fn into_triples(self) -> (ValidatedTriple, ValidatedTriple) {
        let [zero, one] = self.0;
        (zero, one)
    }
}

pub fn prepare_client_triple_finalization(
    opened: [ClientOpenedPolynomials; 2],
    peer_shares: [VerifiedSigningWorkerPrivateShare; 2],
    multiplication: ClientTwoTripleMultiplicationShares,
    rng: &mut impl CryptoRngCore,
) -> Result<
    (
        ClientTripleFinalizationState,
        ClientTripleFinalizationMessage,
    ),
    TripleGenerationError,
> {
    let [opened_zero, opened_one] = opened;
    let [peer_zero, peer_one] = peer_shares;
    let (state, message) = prepare(
        CLIENT_ROLE,
        [opened_zero.0, opened_one.0],
        [peer_zero.into_finalization(), peer_one.into_finalization()],
        multiplication.into_finalization(),
        rng,
    )?;
    Ok((
        ClientTripleFinalizationState(state),
        ClientTripleFinalizationMessage(message),
    ))
}

pub fn prepare_signing_worker_triple_finalization(
    opened: [SigningWorkerOpenedPolynomials; 2],
    peer_shares: [VerifiedClientPrivateShare; 2],
    multiplication: SigningWorkerTwoTripleMultiplicationShares,
    rng: &mut impl CryptoRngCore,
) -> Result<
    (
        SigningWorkerTripleFinalizationState,
        SigningWorkerTripleFinalizationMessage,
    ),
    TripleGenerationError,
> {
    let [opened_zero, opened_one] = opened;
    let [peer_zero, peer_one] = peer_shares;
    let (state, message) = prepare(
        SIGNING_WORKER_ROLE,
        [opened_zero.0, opened_one.0],
        [peer_zero.into_finalization(), peer_one.into_finalization()],
        multiplication.into_finalization(),
        rng,
    )?;
    Ok((
        SigningWorkerTripleFinalizationState(state),
        SigningWorkerTripleFinalizationMessage(message),
    ))
}

impl ClientTripleFinalizationState {
    pub fn receive(
        self,
        message: SigningWorkerTripleFinalizationMessage,
    ) -> Result<ClientGeneratedTriples, TripleGenerationError> {
        finalize(self.0, message.0).map(ClientGeneratedTriples)
    }
}

impl SigningWorkerTripleFinalizationState {
    pub fn receive(
        self,
        message: ClientTripleFinalizationMessage,
    ) -> Result<SigningWorkerGeneratedTriples, TripleGenerationError> {
        finalize(self.0, message.0).map(SigningWorkerGeneratedTriples)
    }
}

fn prepare(
    role: u8,
    opened: [OpenedPolynomialState; 2],
    peer_shares: [VerifiedPrivatePolynomialShare; 2],
    multiplication: FinalizationMultiplicationShares,
    rng: &mut impl CryptoRngCore,
) -> Result<(FinalizationState, FinalizationMessage), TripleGenerationError> {
    if multiplication.role != role {
        return Err(TripleGenerationError::RoleMismatch);
    }
    let [opened_zero, opened_one] = opened;
    let [peer_zero, peer_one] = peer_shares;
    let [multiplication_zero, multiplication_one] = multiplication.values;
    let (state_zero, contribution_zero) = prepare_one(
        role,
        multiplication.context,
        TripleIndex::Zero,
        opened_zero,
        peer_zero,
        multiplication_zero,
        rng,
    )?;
    let (state_one, contribution_one) = prepare_one(
        role,
        multiplication.context,
        TripleIndex::One,
        opened_one,
        peer_one,
        multiplication_one,
        rng,
    )?;
    Ok((
        FinalizationState {
            context: multiplication.context,
            peer_role: opposite_role(role),
            triples: [state_zero, state_one],
        },
        FinalizationMessage {
            context: multiplication.context,
            contributions: [contribution_zero, contribution_one],
        },
    ))
}

fn prepare_one(
    role: u8,
    context: PresignPairContext,
    index: TripleIndex,
    opened: OpenedPolynomialState,
    peer: VerifiedPrivatePolynomialShare,
    multiplication_share: Scalar,
    rng: &mut impl CryptoRngCore,
) -> Result<(PreparedTriple, TripleContribution), TripleGenerationError> {
    check_binding(context, index, opened.context, opened.triple_index)?;
    check_binding(context, index, peer.context, peer.triple_index)?;
    if bool::from(multiplication_share.is_zero()) {
        return Err(TripleGenerationError::DegenerateMultiplicationShare);
    }

    let own_public = opened.secrets.commitment();
    let big_a = nonidentity(
        ProjectivePoint::from(own_public.big_e.constant)
            + ProjectivePoint::from(peer.public.big_e.constant),
    )?;
    let big_b = nonidentity(
        ProjectivePoint::from(own_public.big_f.constant)
            + ProjectivePoint::from(peer.public.big_f.constant),
    )?;
    let big_c_contribution = nonidentity(ProjectivePoint::from(big_b) * opened.secrets.e.constant)?;
    let multiplication_commitment = nonidentity(ProjectivePoint::GENERATOR * multiplication_share)?;

    let coordinate = role_coordinate(role)?;
    let peer_coordinate = role_coordinate(opposite_role(role))?;
    let own_product_evaluation = multiplication_share + opened.secrets.l_constant * coordinate;
    let peer_product_evaluation =
        multiplication_share + opened.secrets.l_constant * peer_coordinate;
    let aggregate_l_slope = ProjectivePoint::from(own_public.big_l_constant)
        + ProjectivePoint::from(peer.public.big_l_constant);

    let e_proof = prove_dlog_for_role(
        role,
        context,
        index,
        DLogProofKind::TripleA,
        own_public.big_e.constant,
        opened.secrets.e.constant,
        rng,
    )?;
    let f_proof = prove_dlog_for_role(
        role,
        context,
        index,
        DLogProofKind::TripleB,
        own_public.big_f.constant,
        opened.secrets.f.constant,
        rng,
    )?;
    let product_proof = prove_dlog_eq_for_role(
        role,
        context,
        index,
        own_public.big_e.constant,
        big_b,
        big_c_contribution,
        opened.secrets.e.constant,
        rng,
    )?;
    let multiplication_proof = prove_dlog_for_role(
        role,
        context,
        index,
        DLogProofKind::ProductShare,
        multiplication_commitment,
        multiplication_share,
        rng,
    )?;

    let a_share = opened.secrets.e.evaluate(coordinate) + peer.share.e;
    let b_share = opened.secrets.f.evaluate(coordinate) + peer.share.f;
    let aggregate_e_at_coordinate =
        own_public.big_e.evaluate(coordinate) + peer.public.big_e.evaluate(coordinate);
    let aggregate_f_at_coordinate =
        own_public.big_f.evaluate(coordinate) + peer.public.big_f.evaluate(coordinate);
    if !bool::from(aggregate_e_at_coordinate.ct_eq(&(ProjectivePoint::GENERATOR * a_share)))
        || !bool::from(aggregate_f_at_coordinate.ct_eq(&(ProjectivePoint::GENERATOR * b_share)))
    {
        return Err(TripleGenerationError::PrivateShareMismatch);
    }

    Ok((
        PreparedTriple {
            index,
            big_a,
            big_b,
            peer_big_e_constant: peer.public.big_e.constant,
            peer_big_f_constant: peer.public.big_f.constant,
            own_big_c_contribution: big_c_contribution,
            own_multiplication_commitment: multiplication_commitment,
            aggregate_l_slope,
            secrets: SecretPreparedTriple {
                a_share,
                b_share,
                own_product_evaluation,
            },
        },
        TripleContribution {
            e_proof,
            f_proof,
            big_c_contribution,
            product_proof,
            multiplication_commitment,
            multiplication_proof,
            private_product_evaluation: SecretProductEvaluation(peer_product_evaluation),
        },
    ))
}

fn finalize(
    state: FinalizationState,
    message: FinalizationMessage,
) -> Result<[ValidatedTriple; 2], TripleGenerationError> {
    if message.context != state.context {
        return Err(TripleGenerationError::ContextMismatch);
    }
    let [state_zero, state_one] = state.triples;
    let [message_zero, message_one] = message.contributions;
    Ok([
        finalize_one(state.context, state.peer_role, state_zero, message_zero)?,
        finalize_one(state.context, state.peer_role, state_one, message_one)?,
    ])
}

fn finalize_one(
    context: PresignPairContext,
    peer_role: u8,
    state: PreparedTriple,
    message: TripleContribution,
) -> Result<ValidatedTriple, TripleGenerationError> {
    verify_dlog_for_role(
        peer_role,
        context,
        state.index,
        DLogProofKind::TripleA,
        state.peer_big_e_constant,
        message.e_proof,
    )?;
    verify_dlog_for_role(
        peer_role,
        context,
        state.index,
        DLogProofKind::TripleB,
        state.peer_big_f_constant,
        message.f_proof,
    )?;
    verify_dlog_eq_for_role(
        peer_role,
        context,
        state.index,
        state.peer_big_e_constant,
        state.big_b,
        message.big_c_contribution,
        message.product_proof,
    )?;
    verify_dlog_for_role(
        peer_role,
        context,
        state.index,
        DLogProofKind::ProductShare,
        message.multiplication_commitment,
        message.multiplication_proof,
    )?;

    let big_c = ProjectivePoint::from(state.own_big_c_contribution)
        + ProjectivePoint::from(message.big_c_contribution);
    let multiplication_product = ProjectivePoint::from(state.own_multiplication_commitment)
        + ProjectivePoint::from(message.multiplication_commitment);
    if bool::from(big_c.is_identity()) || !bool::from(big_c.ct_eq(&multiplication_product)) {
        return Err(TripleGenerationError::TerminalProductMismatch);
    }

    let coordinate = role_coordinate(opposite_role(peer_role))?;
    let c_share = state.secrets.own_product_evaluation + message.private_product_evaluation.0;
    let expected_c_share = big_c + state.aggregate_l_slope * coordinate;
    if !bool::from((ProjectivePoint::GENERATOR * c_share).ct_eq(&expected_c_share)) {
        return Err(TripleGenerationError::PrivateShareMismatch);
    }
    let big_c = big_c.to_affine();

    Ok(ValidatedTriple {
        share: TripleShare {
            a: state.secrets.a_share,
            b: state.secrets.b_share,
            c: c_share,
        },
        public: TriplePublic {
            context,
            big_a: state.big_a,
            big_b: state.big_b,
            big_c,
        },
    })
}

#[allow(clippy::too_many_arguments)]
fn prove_dlog_for_role(
    role: u8,
    context: PresignPairContext,
    index: TripleIndex,
    kind: DLogProofKind,
    public: AffinePoint,
    witness: Scalar,
    rng: &mut impl CryptoRngCore,
) -> Result<DLogProof, TripleGenerationError> {
    let statement = DLogStatement::from_bytes(point_bytes(public))?;
    let witness = ProofWitness::from_bytes(scalar_bytes(witness))?;
    match role {
        CLIENT_ROLE => Ok(prove_client_dlog(
            ClientDLogContext::new(context, index, kind),
            statement,
            witness,
            rng,
        )?),
        SIGNING_WORKER_ROLE => Ok(prove_signing_worker_dlog(
            SigningWorkerDLogContext::new(context, index, kind),
            statement,
            witness,
            rng,
        )?),
        _ => Err(TripleGenerationError::RoleMismatch),
    }
}

fn verify_dlog_for_role(
    role: u8,
    context: PresignPairContext,
    index: TripleIndex,
    kind: DLogProofKind,
    public: AffinePoint,
    proof: DLogProof,
) -> Result<(), TripleGenerationError> {
    let statement = DLogStatement::from_bytes(point_bytes(public))?;
    match role {
        CLIENT_ROLE => Ok(verify_client_dlog(
            ClientDLogContext::new(context, index, kind),
            statement,
            proof,
        )?),
        SIGNING_WORKER_ROLE => Ok(verify_signing_worker_dlog(
            SigningWorkerDLogContext::new(context, index, kind),
            statement,
            proof,
        )?),
        _ => Err(TripleGenerationError::RoleMismatch),
    }
}

#[allow(clippy::too_many_arguments)]
fn prove_dlog_eq_for_role(
    role: u8,
    context: PresignPairContext,
    index: TripleIndex,
    public0: AffinePoint,
    generator1: AffinePoint,
    public1: AffinePoint,
    witness: Scalar,
    rng: &mut impl CryptoRngCore,
) -> Result<DLogEqProof, TripleGenerationError> {
    let statement = DLogEqStatement::from_bytes(
        point_bytes(public0),
        point_bytes(generator1),
        point_bytes(public1),
    )?;
    let witness = ProofWitness::from_bytes(scalar_bytes(witness))?;
    match role {
        CLIENT_ROLE => Ok(prove_client_dlog_eq(
            ClientDLogEqContext::new(context, index),
            statement,
            witness,
            rng,
        )?),
        SIGNING_WORKER_ROLE => Ok(prove_signing_worker_dlog_eq(
            SigningWorkerDLogEqContext::new(context, index),
            statement,
            witness,
            rng,
        )?),
        _ => Err(TripleGenerationError::RoleMismatch),
    }
}

fn verify_dlog_eq_for_role(
    role: u8,
    context: PresignPairContext,
    index: TripleIndex,
    public0: AffinePoint,
    generator1: AffinePoint,
    public1: AffinePoint,
    proof: DLogEqProof,
) -> Result<(), TripleGenerationError> {
    let statement = DLogEqStatement::from_bytes(
        point_bytes(public0),
        point_bytes(generator1),
        point_bytes(public1),
    )?;
    match role {
        CLIENT_ROLE => Ok(verify_client_dlog_eq(
            ClientDLogEqContext::new(context, index),
            statement,
            proof,
        )?),
        SIGNING_WORKER_ROLE => Ok(verify_signing_worker_dlog_eq(
            SigningWorkerDLogEqContext::new(context, index),
            statement,
            proof,
        )?),
        _ => Err(TripleGenerationError::RoleMismatch),
    }
}

fn parse_contribution(
    parts: TripleContributionParts,
) -> Result<TripleContribution, TripleGenerationError> {
    Ok(TripleContribution {
        e_proof: DLogProof::from_parts(parts.e_proof_commitment, parts.e_proof_response)?,
        f_proof: DLogProof::from_parts(parts.f_proof_commitment, parts.f_proof_response)?,
        big_c_contribution: parse_nonidentity_point(parts.big_c_contribution)
            .map_err(TripleGenerationError::Boundary)?,
        product_proof: DLogEqProof::from_parts(
            parts.product_proof_commitment0,
            parts.product_proof_commitment1,
            parts.product_proof_response,
        )?,
        multiplication_commitment: parse_nonidentity_point(parts.multiplication_commitment)
            .map_err(TripleGenerationError::Boundary)?,
        multiplication_proof: DLogProof::from_parts(
            parts.multiplication_proof_commitment,
            parts.multiplication_proof_response,
        )?,
        private_product_evaluation: SecretProductEvaluation(
            parse_scalar(parts.private_product_evaluation.into_bytes())
                .map_err(TripleGenerationError::Boundary)?,
        ),
    })
}

fn contribution_into_parts(contribution: TripleContribution) -> TripleContributionParts {
    let (e_proof_commitment, e_proof_response) = contribution.e_proof.into_parts();
    let (f_proof_commitment, f_proof_response) = contribution.f_proof.into_parts();
    let (product_proof_commitment0, product_proof_commitment1, product_proof_response) =
        contribution.product_proof.into_parts();
    let (multiplication_proof_commitment, multiplication_proof_response) =
        contribution.multiplication_proof.into_parts();
    TripleContributionParts::new(
        point_bytes(contribution.big_c_contribution),
        e_proof_commitment,
        e_proof_response,
        f_proof_commitment,
        f_proof_response,
        product_proof_commitment0,
        product_proof_commitment1,
        product_proof_response,
        point_bytes(contribution.multiplication_commitment),
        multiplication_proof_commitment,
        multiplication_proof_response,
        scalar_bytes(contribution.private_product_evaluation.0),
    )
}

fn nonidentity(point: ProjectivePoint) -> Result<AffinePoint, TripleGenerationError> {
    if bool::from(point.is_identity()) {
        return Err(TripleGenerationError::DegenerateAggregate);
    }
    Ok(point.to_affine())
}

fn check_binding(
    expected_context: PresignPairContext,
    expected_index: TripleIndex,
    actual_context: PresignPairContext,
    actual_index: TripleIndex,
) -> Result<(), TripleGenerationError> {
    if actual_context != expected_context {
        return Err(TripleGenerationError::ContextMismatch);
    }
    if actual_index != expected_index {
        return Err(TripleGenerationError::TripleIndexMismatch);
    }
    Ok(())
}

fn opposite_role(role: u8) -> u8 {
    match role {
        CLIENT_ROLE => SIGNING_WORKER_ROLE,
        SIGNING_WORKER_ROLE => CLIENT_ROLE,
        _ => 0,
    }
}

fn role_coordinate(role: u8) -> Result<Scalar, TripleGenerationError> {
    match role {
        CLIENT_ROLE => Ok(Scalar::from(CLIENT_COORDINATE)),
        SIGNING_WORKER_ROLE => Ok(Scalar::from(SIGNING_WORKER_COORDINATE)),
        _ => Err(TripleGenerationError::RoleMismatch),
    }
}

#[cfg(test)]
mod tests {
    use k256::elliptic_curve::group::prime::PrimeCurveAffine;
    use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
    use router_ab_ecdsa_online::{
        compute_client_signature_share, finalize_signing_worker_signature, ClientPresignMaterial,
        OnlineClientInput, SigningWorkerOnlineInput, SigningWorkerPresignMaterial,
    };
    use router_ab_ecdsa_wire::{PairContextDigest, SigningScopeDigest};
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::triples::base_rot::extension::mta::{
        combine_client_multiplication_shares, combine_signing_worker_multiplication_shares,
        receive_client_mta_ciphertexts, receive_signing_worker_mta_ciphertexts,
        start_client_multiplication_sender, start_signing_worker_multiplication_sender,
        ClientMtaCiphertextMessage,
    };
    use crate::triples::base_rot::extension::{
        start_client_extension_receiver, start_client_extension_sender,
        start_signing_worker_extension_receiver, start_signing_worker_extension_sender,
        ClientRandomOtReceiverOutput, ClientRandomOtSenderOutput,
        SigningWorkerRandomOtReceiverOutput, SigningWorkerRandomOtSenderOutput,
    };
    use crate::triples::base_rot::{
        receive_client_base_rot_sender_hello, receive_signing_worker_base_rot_sender_hello,
        start_client_base_rot_sender, start_signing_worker_base_rot_sender,
    };
    use crate::triples::{
        commit_client_polynomials, commit_signing_worker_polynomials,
        verify_client_polynomial_opening, verify_client_private_share_for_signing_worker,
        verify_signing_worker_polynomial_opening, verify_signing_worker_private_share_for_client,
        VerifiedClientPrivateShare, VerifiedSigningWorkerPrivateShare,
    };
    use crate::{
        start_client, start_signing_worker, AdditiveKeyShare, ClientPresignInput,
        SigningWorkerPresignInput, CLIENT_LAGRANGE, SIGNING_WORKER_LAGRANGE_MAGNITUDE,
    };

    struct PolynomialRound {
        client: ClientOpenedPolynomials,
        worker: SigningWorkerOpenedPolynomials,
        client_peer: VerifiedSigningWorkerPrivateShare,
        worker_peer: VerifiedClientPrivateShare,
    }

    struct GenerationStates {
        client: ClientTripleFinalizationState,
        worker: SigningWorkerTripleFinalizationState,
        client_message: ClientTripleFinalizationMessage,
        worker_message: SigningWorkerTripleFinalizationMessage,
    }

    fn binding() -> PresignPairContext {
        PresignPairContext::new(
            SigningScopeDigest::new([0x24; 32]),
            PairContextDigest::new([0x42; 32]),
        )
    }

    fn polynomial_round(index: TripleIndex, seed: u8) -> PolynomialRound {
        let mut client_rng = ChaCha20Rng::from_seed([seed; 32]);
        let mut worker_rng = ChaCha20Rng::from_seed([seed + 1; 32]);
        let (client_state, client_commitment) =
            commit_client_polynomials(binding(), index, &mut client_rng).expect("client commit");
        let (worker_state, worker_commitment) =
            commit_signing_worker_polynomials(binding(), index, &mut worker_rng)
                .expect("worker commit");
        let (client, client_opening) = client_state.open();
        let (worker, worker_opening) = worker_state.open();
        let client_private = client.private_share_for_signing_worker();
        let worker_private = worker.private_share_for_client();
        let verified_client =
            verify_client_polynomial_opening(binding(), index, client_commitment, client_opening)
                .expect("client opening");
        let verified_worker = verify_signing_worker_polynomial_opening(
            binding(),
            index,
            worker_commitment,
            worker_opening,
        )
        .expect("worker opening");
        let client_peer = verify_signing_worker_private_share_for_client(
            binding(),
            index,
            &verified_worker,
            worker_private,
        )
        .expect("worker private share");
        let worker_peer = verify_client_private_share_for_signing_worker(
            binding(),
            index,
            &verified_client,
            client_private,
        )
        .expect("client private share");
        PolynomialRound {
            client,
            worker,
            client_peer,
            worker_peer,
        }
    }

    fn client_sender_random_ot(
        seed: u8,
    ) -> (
        ClientRandomOtSenderOutput,
        SigningWorkerRandomOtReceiverOutput,
    ) {
        let mut base_sender_rng = ChaCha20Rng::from_seed([seed; 32]);
        let mut base_receiver_rng = ChaCha20Rng::from_seed([seed + 1; 32]);
        let (worker_base_state, hello) = start_signing_worker_base_rot_sender(
            binding(),
            TripleIndex::Zero,
            &mut base_sender_rng,
        )
        .expect("worker base sender");
        let (client_base_output, response) = receive_signing_worker_base_rot_sender_hello(
            binding(),
            TripleIndex::Zero,
            hello,
            &mut base_receiver_rng,
        )
        .expect("client base receiver");
        let worker_base_output = worker_base_state
            .receive(response)
            .expect("worker base sender finish");
        let mut extension_receiver_rng = ChaCha20Rng::from_seed([seed + 2; 32]);
        let mut extension_sender_rng = ChaCha20Rng::from_seed([seed + 3; 32]);
        let (worker_state, correlation) = start_signing_worker_extension_receiver(
            worker_base_output,
            &mut extension_receiver_rng,
        )
        .expect("worker extension receiver");
        let (client_state, challenge) = start_client_extension_sender(
            binding(),
            TripleIndex::Zero,
            client_base_output,
            correlation,
            &mut extension_sender_rng,
        )
        .expect("client extension sender");
        let (worker_accept_state, proof) = worker_state.receive(challenge).expect("worker proof");
        let (client_output, acceptance) = client_state.receive(proof).expect("client accepts");
        let worker_output = worker_accept_state
            .receive(acceptance)
            .expect("worker releases output");
        (client_output, worker_output)
    }

    fn worker_sender_random_ot(
        seed: u8,
    ) -> (
        SigningWorkerRandomOtSenderOutput,
        ClientRandomOtReceiverOutput,
    ) {
        let mut base_sender_rng = ChaCha20Rng::from_seed([seed; 32]);
        let mut base_receiver_rng = ChaCha20Rng::from_seed([seed + 1; 32]);
        let (client_base_state, hello) =
            start_client_base_rot_sender(binding(), TripleIndex::One, &mut base_sender_rng)
                .expect("client base sender");
        let (worker_base_output, response) = receive_client_base_rot_sender_hello(
            binding(),
            TripleIndex::One,
            hello,
            &mut base_receiver_rng,
        )
        .expect("worker base receiver");
        let client_base_output = client_base_state
            .receive(response)
            .expect("client base sender finish");
        let mut extension_receiver_rng = ChaCha20Rng::from_seed([seed + 2; 32]);
        let mut extension_sender_rng = ChaCha20Rng::from_seed([seed + 3; 32]);
        let (client_state, correlation) =
            start_client_extension_receiver(client_base_output, &mut extension_receiver_rng)
                .expect("client extension receiver");
        let (worker_state, challenge) = start_signing_worker_extension_sender(
            binding(),
            TripleIndex::One,
            worker_base_output,
            correlation,
            &mut extension_sender_rng,
        )
        .expect("worker extension sender");
        let (client_accept_state, proof) = client_state.receive(challenge).expect("client proof");
        let (worker_output, acceptance) = worker_state.receive(proof).expect("worker accepts");
        let client_output = client_accept_state
            .receive(acceptance)
            .expect("client releases output");
        (worker_output, client_output)
    }

    fn tamper_ciphertexts(message: ClientMtaCiphertextMessage) -> ClientMtaCiphertextMessage {
        let (context, index, mut values) = message.into_parts();
        for branch in 0..2 {
            let value = parse_scalar(values[0][0][branch]).expect("canonical ciphertext");
            values[0][0][branch] = (value + Scalar::ONE).to_bytes().into();
        }
        ClientMtaCiphertextMessage::from_parts(context, index, values)
            .expect("tampered ciphertext remains canonical")
    }

    fn generation_states(corrupt_first_mta: bool) -> GenerationStates {
        let zero = polynomial_round(TripleIndex::Zero, 11);
        let one = polynomial_round(TripleIndex::One, 13);

        let (client_random_ot, worker_random_ot) = client_sender_random_ot(21);
        let mut zero_sender_rng = ChaCha20Rng::from_seed([25; 32]);
        let mut zero_receiver_rng = ChaCha20Rng::from_seed([26; 32]);
        let (client_zero_state, client_zero_ciphertexts) = start_client_multiplication_sender(
            client_random_ot,
            zero.client.multiplication_operands(),
            &mut zero_sender_rng,
        )
        .expect("client zero MTA sender");
        let client_zero_ciphertexts = if corrupt_first_mta {
            tamper_ciphertexts(client_zero_ciphertexts)
        } else {
            client_zero_ciphertexts
        };
        let (worker_zero_share, worker_zero_response) = receive_client_mta_ciphertexts(
            binding(),
            worker_random_ot,
            zero.worker.multiplication_operands(),
            client_zero_ciphertexts,
            &mut zero_receiver_rng,
        )
        .expect("worker zero MTA receiver");
        let client_zero_share = client_zero_state
            .receive(worker_zero_response)
            .expect("client zero MTA share");

        let (worker_random_ot, client_random_ot) = worker_sender_random_ot(31);
        let mut one_sender_rng = ChaCha20Rng::from_seed([35; 32]);
        let mut one_receiver_rng = ChaCha20Rng::from_seed([36; 32]);
        let (worker_one_state, worker_one_ciphertexts) =
            start_signing_worker_multiplication_sender(
                worker_random_ot,
                one.worker.multiplication_operands(),
                &mut one_sender_rng,
            )
            .expect("worker one MTA sender");
        let (client_one_share, client_one_response) = receive_signing_worker_mta_ciphertexts(
            binding(),
            client_random_ot,
            one.client.multiplication_operands(),
            worker_one_ciphertexts,
            &mut one_receiver_rng,
        )
        .expect("client one MTA receiver");
        let worker_one_share = worker_one_state
            .receive(client_one_response)
            .expect("worker one MTA share");

        let client_multiplication =
            combine_client_multiplication_shares(client_zero_share, client_one_share)
                .expect("client MTA bundle");
        let worker_multiplication =
            combine_signing_worker_multiplication_shares(worker_zero_share, worker_one_share)
                .expect("worker MTA bundle");
        let mut client_finalization_rng = ChaCha20Rng::from_seed([41; 32]);
        let mut worker_finalization_rng = ChaCha20Rng::from_seed([42; 32]);
        let (client, client_message) = prepare_client_triple_finalization(
            [zero.client, one.client],
            [zero.client_peer, one.client_peer],
            client_multiplication,
            &mut client_finalization_rng,
        )
        .expect("client finalization");
        let (worker, worker_message) = prepare_signing_worker_triple_finalization(
            [zero.worker, one.worker],
            [zero.worker_peer, one.worker_peer],
            worker_multiplication,
            &mut worker_finalization_rng,
        )
        .expect("worker finalization");
        GenerationStates {
            client,
            worker,
            client_message,
            worker_message,
        }
    }

    fn decoded_scalar(value: [u8; 32]) -> Scalar {
        parse_scalar(value).expect("canonical scalar")
    }

    fn assert_valid_pair(client: ValidatedTriple, worker: ValidatedTriple) -> [u8; 32] {
        let (client_context, client_shares, client_public) = client.into_test_parts();
        let (worker_context, worker_shares, worker_public) = worker.into_test_parts();
        assert_eq!(client_context, binding());
        assert_eq!(worker_context, binding());
        assert_eq!(client_public, worker_public);

        let client_share_bytes = client_shares.map(ScalarBytes::into_bytes);
        let worker_share_bytes = worker_shares.map(ScalarBytes::into_bytes);
        let [client_a, client_b, client_c] = client_share_bytes.map(decoded_scalar);
        let [worker_a, worker_b, worker_c] = worker_share_bytes.map(decoded_scalar);
        let a = Scalar::from(CLIENT_LAGRANGE) * client_a
            - Scalar::from(SIGNING_WORKER_LAGRANGE_MAGNITUDE) * worker_a;
        let b = Scalar::from(CLIENT_LAGRANGE) * client_b
            - Scalar::from(SIGNING_WORKER_LAGRANGE_MAGNITUDE) * worker_b;
        let c = Scalar::from(CLIENT_LAGRANGE) * client_c
            - Scalar::from(SIGNING_WORKER_LAGRANGE_MAGNITUDE) * worker_c;

        assert_ne!(client_c, worker_c);
        assert_eq!(c, a * b);
        for (scalar, point) in [a, b, c].into_iter().zip(client_public) {
            let expected = parse_nonidentity_point(point).expect("valid public point");
            assert_eq!(ProjectivePoint::GENERATOR * scalar, expected.to_curve());
        }

        let mut digest = Sha256::new();
        digest.update(b"seams/router-ab-ecdsa-presign/generated-triple-test/v1");
        for value in client_share_bytes.into_iter().chain(worker_share_bytes) {
            digest.update(value);
        }
        for point in client_public {
            digest.update(point.as_bytes());
        }
        digest.finalize().into()
    }

    #[test]
    fn fixed_protocol_generates_two_validated_multiplication_triples() {
        let states = generation_states(false);
        let client = states
            .client
            .receive(states.worker_message)
            .expect("client validates triples");
        let worker = states
            .worker
            .receive(states.client_message)
            .expect("worker validates triples");
        let (client_zero, client_one) = client.into_triples();
        let (worker_zero, worker_one) = worker.into_triples();
        let zero_digest = assert_valid_pair(client_zero, worker_zero);
        let one_digest = assert_valid_pair(client_one, worker_one);
        let session_digest: [u8; 32] = Sha256::new()
            .chain_update(zero_digest)
            .chain_update(one_digest)
            .finalize()
            .into();
        assert_eq!(
            session_digest,
            [
                0x96, 0x57, 0xd1, 0x35, 0xf2, 0x3d, 0xb8, 0xa2, 0x95, 0x42, 0x3d, 0x0d, 0x31, 0xa6,
                0xff, 0xf1, 0x78, 0xe0, 0x2a, 0x38, 0x00, 0xec, 0x7f, 0xb8, 0xc5, 0x0e, 0xf9, 0x21,
                0xbc, 0x29, 0x6f, 0x6d,
            ]
        );
    }

    #[test]
    fn corrupted_mta_output_fails_the_terminal_product_equation() {
        let states = generation_states(true);
        let client_result = states.client.receive(states.worker_message);
        let worker_result = states.worker.receive(states.client_message);
        assert!(matches!(
            client_result,
            Err(TripleGenerationError::TerminalProductMismatch)
        ));
        assert!(matches!(
            worker_result,
            Err(TripleGenerationError::TerminalProductMismatch)
        ));
    }

    #[test]
    fn generated_triples_complete_presign_and_online_signing() {
        let states = generation_states(false);
        let client_generated = states
            .client
            .receive(states.worker_message)
            .expect("client validates triples");
        let worker_generated = states
            .worker
            .receive(states.client_message)
            .expect("worker validates triples");
        let (client_zero, client_one) = client_generated.into_triples();
        let (worker_zero, worker_one) = worker_generated.into_triples();

        let client_key_share = Scalar::from(19u64);
        let worker_key_share = Scalar::from(23u64);
        let wallet_public = point_bytes(
            (ProjectivePoint::GENERATOR * (client_key_share + worker_key_share)).to_affine(),
        );
        let client_input = ClientPresignInput::new(
            AdditiveKeyShare::from_bytes(scalar_bytes(client_key_share)).expect("client key share"),
            wallet_public,
            client_zero,
            client_one,
        )
        .expect("client presign input");
        let worker_input = SigningWorkerPresignInput::new(
            AdditiveKeyShare::from_bytes(scalar_bytes(worker_key_share)).expect("worker key share"),
            wallet_public,
            worker_zero,
            worker_one,
        )
        .expect("worker presign input");
        let (client_e_state, client_e) = start_client(client_input).expect("client presign starts");
        let (worker_e_state, worker_e) =
            start_signing_worker(worker_input).expect("worker presign starts");
        let (client_ab_state, client_ab) =
            client_e_state.receive(worker_e).expect("client accepts e");
        let (worker_ab_state, worker_ab) =
            worker_e_state.receive(client_e).expect("worker accepts e");
        let client_presign = client_ab_state
            .receive(worker_ab)
            .expect("client completes presign");
        let worker_presign = worker_ab_state
            .receive(client_ab)
            .expect("worker completes presign");
        let (client_big_r, client_k, client_sigma) = client_presign.into_parts();
        let (worker_big_r, worker_k, worker_sigma) = worker_presign.into_parts();
        assert_eq!(client_big_r, worker_big_r);

        let wallet_public = *wallet_public.as_bytes();
        let big_r = *client_big_r.as_bytes();
        let client_k = client_k.into_bytes();
        let client_sigma = client_sigma.into_bytes();
        let worker_k = worker_k.into_bytes();
        let worker_sigma = worker_sigma.into_bytes();
        let digest = [0x42; 32];
        let entropy = [0x24; 32];
        let client_committed = ClientPresignMaterial::from_bytes(big_r, client_k, client_sigma)
            .expect("client online material")
            .reserve()
            .commit(
                OnlineClientInput::new(wallet_public, big_r, digest, entropy)
                    .expect("client online input"),
            )
            .expect("client commits presign use");
        let client_signature_share =
            compute_client_signature_share(client_committed).expect("client signature share");
        let worker_committed =
            SigningWorkerPresignMaterial::from_bytes(big_r, worker_k, worker_sigma)
                .expect("worker online material")
                .reserve()
                .commit(
                    SigningWorkerOnlineInput::new(wallet_public, big_r, digest, entropy)
                        .expect("worker online input"),
                )
                .expect("worker commits presign use");
        let signature = finalize_signing_worker_signature(worker_committed, client_signature_share)
            .expect("worker final signature");

        let signature_digest: [u8; 32] = Sha256::digest(signature).into();
        assert_eq!(
            signature_digest,
            [
                0x60, 0xad, 0xd2, 0x6f, 0xae, 0x8c, 0x12, 0x8e, 0x20, 0x04, 0x50, 0x0a, 0xb2, 0x2d,
                0x87, 0xee, 0x1f, 0x36, 0x3a, 0x71, 0xb7, 0xaa, 0x01, 0x76, 0xf3, 0xae, 0x44, 0x5b,
                0x16, 0x27, 0x6f, 0x1d,
            ]
        );
    }
}
