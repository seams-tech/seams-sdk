#![forbid(unsafe_code)]

pub mod proofs;
pub mod triples;

use core::fmt;

use k256::{
    elliptic_curve::{
        ff::PrimeField,
        group::prime::PrimeCurveAffine,
        sec1::{FromEncodedPoint, ToEncodedPoint},
    },
    AffinePoint, EncodedPoint, ProjectivePoint, Scalar,
};
use router_ab_ecdsa_wire::{
    ClientAlphaBetaMessage, ClientEShareMessage, CompressedPointBytes, PresignPairContext,
    ScalarBytes, SigningWorkerAlphaBetaMessage, SigningWorkerEShareMessage,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

const CLIENT_LAGRANGE: u64 = 3;
const SIGNING_WORKER_LAGRANGE_MAGNITUDE: u64 = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PresignError {
    ContextMismatch,
    IdentityPoint,
    InvalidPoint,
    NonCanonicalScalar,
    ZeroKeyShare,
    ZeroEShare,
    ECommitmentMismatch,
    AdditiveCommitmentMismatch,
    NonInvertibleE,
}

impl fmt::Display for PresignError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ContextMismatch => "presign pair context mismatch",
            Self::IdentityPoint => "identity point is forbidden",
            Self::InvalidPoint => "invalid compressed secp256k1 point",
            Self::NonCanonicalScalar => "non-canonical secp256k1 scalar",
            Self::ZeroKeyShare => "zero key share is forbidden",
            Self::ZeroEShare => "zero e share is forbidden",
            Self::ECommitmentMismatch => "reconstructed e does not match its commitment",
            Self::AdditiveCommitmentMismatch => {
                "reconstructed additive values do not match their commitments"
            }
            Self::NonInvertibleE => "reconstructed e is not invertible",
        })
    }
}

impl std::error::Error for PresignError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TriplePublic {
    context: PresignPairContext,
    big_a: AffinePoint,
    big_b: AffinePoint,
    big_c: AffinePoint,
}

impl TriplePublic {
    pub fn from_bytes(
        context: PresignPairContext,
        big_a: CompressedPointBytes,
        big_b: CompressedPointBytes,
        big_c: CompressedPointBytes,
    ) -> Result<Self, PresignError> {
        Ok(Self {
            context,
            big_a: parse_nonidentity_point(big_a)?,
            big_b: parse_nonidentity_point(big_b)?,
            big_c: parse_nonidentity_point(big_c)?,
        })
    }

    pub fn context(&self) -> PresignPairContext {
        self.context
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct TripleShare {
    a: Scalar,
    b: Scalar,
    c: Scalar,
}

#[cfg(any(test, feature = "test-utils"))]
impl TripleShare {
    fn from_bytes(a: ScalarBytes, b: ScalarBytes, c: ScalarBytes) -> Result<Self, PresignError> {
        Ok(Self {
            a: parse_scalar(a.into_bytes())?,
            b: parse_scalar(b.into_bytes())?,
            c: parse_scalar(c.into_bytes())?,
        })
    }
}

/// Opaque output of the checked triple-generation state machine.
///
/// ```compile_fail
/// use router_ab_ecdsa_presign::ValidatedTriple;
/// let _ = ValidatedTriple {};
/// ```
pub struct ValidatedTriple {
    share: TripleShare,
    public: TriplePublic,
}

#[cfg(any(test, feature = "test-utils"))]
impl ValidatedTriple {
    pub fn from_test_parts(
        a: ScalarBytes,
        b: ScalarBytes,
        c: ScalarBytes,
        public: TriplePublic,
    ) -> Result<Self, PresignError> {
        Ok(Self {
            share: TripleShare::from_bytes(a, b, c)?,
            public,
        })
    }

    pub fn into_test_parts(
        self,
    ) -> (
        PresignPairContext,
        [ScalarBytes; 3],
        [CompressedPointBytes; 3],
    ) {
        (
            self.public.context,
            [
                scalar_bytes(self.share.a),
                scalar_bytes(self.share.b),
                scalar_bytes(self.share.c),
            ],
            [
                point_bytes(self.public.big_a),
                point_bytes(self.public.big_b),
                point_bytes(self.public.big_c),
            ],
        )
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct AdditiveKeyShare(Scalar);

impl AdditiveKeyShare {
    pub fn from_bytes(bytes: ScalarBytes) -> Result<Self, PresignError> {
        let scalar = parse_scalar(bytes.into_bytes())?;
        if bool::from(scalar.is_zero()) {
            return Err(PresignError::ZeroKeyShare);
        }
        Ok(Self(scalar))
    }
}

pub struct ClientPresignInput(PresignInput);
pub struct SigningWorkerPresignInput(PresignInput);

macro_rules! impl_presign_input {
    ($name:ident) => {
        impl $name {
            pub fn new(
                key_share: AdditiveKeyShare,
                wallet_public_key: CompressedPointBytes,
                triple0: ValidatedTriple,
                triple1: ValidatedTriple,
            ) -> Result<Self, PresignError> {
                PresignInput::new(key_share, wallet_public_key, triple0, triple1).map(Self)
            }
        }
    };
}

impl_presign_input!(ClientPresignInput);
impl_presign_input!(SigningWorkerPresignInput);

#[derive(Zeroize, ZeroizeOnDrop)]
struct PresignInput {
    #[zeroize(skip)]
    context: PresignPairContext,
    additive_key_share: Scalar,
    #[zeroize(skip)]
    wallet_public_key: AffinePoint,
    triple0_share: TripleShare,
    #[zeroize(skip)]
    triple0_public: TriplePublic,
    triple1_share: TripleShare,
    #[zeroize(skip)]
    triple1_public: TriplePublic,
}

impl PresignInput {
    fn new(
        key_share: AdditiveKeyShare,
        wallet_public_key: CompressedPointBytes,
        triple0: ValidatedTriple,
        triple1: ValidatedTriple,
    ) -> Result<Self, PresignError> {
        if triple0.public.context != triple1.public.context {
            return Err(PresignError::ContextMismatch);
        }

        Ok(Self {
            context: triple0.public.context,
            additive_key_share: key_share.0,
            wallet_public_key: parse_nonidentity_point(wallet_public_key)?,
            triple0_share: triple0.share,
            triple0_public: triple0.public,
            triple1_share: triple1.share,
            triple1_public: triple1.public,
        })
    }
}

#[derive(Clone, Copy)]
enum FixedRole {
    Client,
    SigningWorker,
}

impl FixedRole {
    fn lagrange(self) -> Scalar {
        match self {
            Self::Client => Scalar::from(CLIENT_LAGRANGE),
            Self::SigningWorker => -Scalar::from(SIGNING_WORKER_LAGRANGE_MAGNITUDE),
        }
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct AwaitingPeerE {
    #[zeroize(skip)]
    role: FixedRole,
    #[zeroize(skip)]
    context: PresignPairContext,
    private_share: Scalar,
    #[zeroize(skip)]
    wallet_public_key: AffinePoint,
    triple0_share: TripleShare,
    #[zeroize(skip)]
    triple0_public: TriplePublic,
    triple1_share: TripleShare,
    #[zeroize(skip)]
    triple1_public: TriplePublic,
    own_e_prime: Scalar,
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct AwaitingPeerAlphaBeta {
    #[zeroize(skip)]
    context: PresignPairContext,
    private_share: Scalar,
    #[zeroize(skip)]
    wallet_public_key: AffinePoint,
    triple0_share: TripleShare,
    #[zeroize(skip)]
    triple0_public: TriplePublic,
    triple1_share: TripleShare,
    #[zeroize(skip)]
    triple1_public: TriplePublic,
    e: Scalar,
    own_alpha: Scalar,
    own_beta: Scalar,
}

pub struct ClientAwaitingPeerE(AwaitingPeerE);
pub struct SigningWorkerAwaitingPeerE(AwaitingPeerE);
pub struct ClientAwaitingPeerAlphaBeta(AwaitingPeerAlphaBeta);
pub struct SigningWorkerAwaitingPeerAlphaBeta(AwaitingPeerAlphaBeta);

pub struct PresignOutput {
    big_r: AffinePoint,
    k: Scalar,
    sigma: Scalar,
}

impl PresignOutput {
    pub fn into_parts(self) -> (CompressedPointBytes, ScalarBytes, ScalarBytes) {
        (
            point_bytes(self.big_r),
            scalar_bytes(self.k),
            scalar_bytes(self.sigma),
        )
    }
}

impl Drop for PresignOutput {
    fn drop(&mut self) {
        self.k.zeroize();
        self.sigma.zeroize();
    }
}

pub fn start_client(
    input: ClientPresignInput,
) -> Result<(ClientAwaitingPeerE, ClientEShareMessage), PresignError> {
    let (state, e_share) = start(FixedRole::Client, input.0)?;
    let message = ClientEShareMessage::new(state.context, scalar_bytes(e_share));
    Ok((ClientAwaitingPeerE(state), message))
}

pub fn start_signing_worker(
    input: SigningWorkerPresignInput,
) -> Result<(SigningWorkerAwaitingPeerE, SigningWorkerEShareMessage), PresignError> {
    let (state, e_share) = start(FixedRole::SigningWorker, input.0)?;
    let message = SigningWorkerEShareMessage::new(state.context, scalar_bytes(e_share));
    Ok((SigningWorkerAwaitingPeerE(state), message))
}

impl ClientAwaitingPeerE {
    pub fn receive(
        self,
        message: SigningWorkerEShareMessage,
    ) -> Result<(ClientAwaitingPeerAlphaBeta, ClientAlphaBetaMessage), PresignError> {
        let (state, alpha, beta) = receive_e(self.0, message.into_parts())?;
        let message =
            ClientAlphaBetaMessage::new(state.context, scalar_bytes(alpha), scalar_bytes(beta));
        Ok((ClientAwaitingPeerAlphaBeta(state), message))
    }
}

impl SigningWorkerAwaitingPeerE {
    pub fn receive(
        self,
        message: ClientEShareMessage,
    ) -> Result<
        (
            SigningWorkerAwaitingPeerAlphaBeta,
            SigningWorkerAlphaBetaMessage,
        ),
        PresignError,
    > {
        let (state, alpha, beta) = receive_e(self.0, message.into_parts())?;
        let message = SigningWorkerAlphaBetaMessage::new(
            state.context,
            scalar_bytes(alpha),
            scalar_bytes(beta),
        );
        Ok((SigningWorkerAwaitingPeerAlphaBeta(state), message))
    }
}

impl ClientAwaitingPeerAlphaBeta {
    pub fn receive(
        self,
        message: SigningWorkerAlphaBetaMessage,
    ) -> Result<PresignOutput, PresignError> {
        finish(self.0, message.into_parts())
    }
}

impl SigningWorkerAwaitingPeerAlphaBeta {
    pub fn receive(self, message: ClientAlphaBetaMessage) -> Result<PresignOutput, PresignError> {
        finish(self.0, message.into_parts())
    }
}

fn start(role: FixedRole, input: PresignInput) -> Result<(AwaitingPeerE, Scalar), PresignError> {
    let lagrange = role.lagrange();
    let own_e_prime = lagrange * input.triple0_share.c;
    if bool::from(own_e_prime.is_zero()) {
        return Err(PresignError::ZeroEShare);
    }

    let lagrange_inverse: Option<Scalar> = lagrange.invert().into();
    let private_share =
        lagrange_inverse.ok_or(PresignError::ZeroKeyShare)? * input.additive_key_share;

    Ok((
        AwaitingPeerE {
            role,
            context: input.context,
            private_share,
            wallet_public_key: input.wallet_public_key,
            triple0_share: copy_triple_share(&input.triple0_share),
            triple0_public: input.triple0_public.clone(),
            triple1_share: copy_triple_share(&input.triple1_share),
            triple1_public: input.triple1_public.clone(),
            own_e_prime,
        },
        own_e_prime,
    ))
}

fn receive_e(
    state: AwaitingPeerE,
    message: (PresignPairContext, [u8; 32]),
) -> Result<(AwaitingPeerAlphaBeta, Scalar, Scalar), PresignError> {
    if message.0 != state.context {
        return Err(PresignError::ContextMismatch);
    }
    let peer_e_prime = parse_scalar(message.1)?;
    if bool::from(peer_e_prime.is_zero()) {
        return Err(PresignError::ZeroEShare);
    }

    let e = state.own_e_prime + peer_e_prime;
    if ProjectivePoint::GENERATOR * e != ProjectivePoint::from(state.triple0_public.big_c) {
        return Err(PresignError::ECommitmentMismatch);
    }

    let lagrange = state.role.lagrange();
    let own_alpha = lagrange * (state.triple0_share.a + state.triple1_share.a);
    let own_beta = state.additive_key_share() + lagrange * state.triple1_share.b;

    Ok((
        AwaitingPeerAlphaBeta {
            context: state.context,
            private_share: state.private_share,
            wallet_public_key: state.wallet_public_key,
            triple0_share: copy_triple_share(&state.triple0_share),
            triple0_public: state.triple0_public.clone(),
            triple1_share: copy_triple_share(&state.triple1_share),
            triple1_public: state.triple1_public.clone(),
            e,
            own_alpha,
            own_beta,
        },
        own_alpha,
        own_beta,
    ))
}

impl AwaitingPeerE {
    fn additive_key_share(&self) -> Scalar {
        self.role.lagrange() * self.private_share
    }
}

fn finish(
    state: AwaitingPeerAlphaBeta,
    message: (PresignPairContext, [u8; 32], [u8; 32]),
) -> Result<PresignOutput, PresignError> {
    if message.0 != state.context {
        return Err(PresignError::ContextMismatch);
    }
    let peer_alpha = parse_scalar(message.1)?;
    let peer_beta = parse_scalar(message.2)?;
    let alpha = state.own_alpha + peer_alpha;
    let beta = state.own_beta + peer_beta;

    let alpha_commitment = ProjectivePoint::GENERATOR * alpha;
    let expected_alpha = ProjectivePoint::from(state.triple0_public.big_a)
        + ProjectivePoint::from(state.triple1_public.big_a);
    let beta_commitment = ProjectivePoint::GENERATOR * beta;
    let expected_beta = ProjectivePoint::from(state.wallet_public_key)
        + ProjectivePoint::from(state.triple1_public.big_b);

    if alpha_commitment != expected_alpha || beta_commitment != expected_beta {
        return Err(PresignError::AdditiveCommitmentMismatch);
    }

    let e_inverse: Option<Scalar> = state.e.invert().into();
    let e_inverse = e_inverse.ok_or(PresignError::NonInvertibleE)?;
    let big_r = (ProjectivePoint::from(state.triple0_public.big_b) * e_inverse).to_affine();
    let sigma = alpha * state.private_share - beta * state.triple1_share.a + state.triple1_share.c;

    Ok(PresignOutput {
        big_r,
        k: state.triple0_share.a,
        sigma,
    })
}

fn parse_scalar(bytes: [u8; 32]) -> Result<Scalar, PresignError> {
    Option::<Scalar>::from(Scalar::from_repr(bytes.into())).ok_or(PresignError::NonCanonicalScalar)
}

fn copy_triple_share(share: &TripleShare) -> TripleShare {
    TripleShare {
        a: share.a,
        b: share.b,
        c: share.c,
    }
}

fn parse_nonidentity_point(bytes: CompressedPointBytes) -> Result<AffinePoint, PresignError> {
    let encoded =
        EncodedPoint::from_bytes(bytes.as_bytes()).map_err(|_| PresignError::InvalidPoint)?;
    let point = Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&encoded))
        .ok_or(PresignError::InvalidPoint)?;
    if bool::from(point.is_identity()) {
        return Err(PresignError::IdentityPoint);
    }
    Ok(point)
}

fn scalar_bytes(scalar: Scalar) -> ScalarBytes {
    ScalarBytes::new(scalar.to_bytes().into())
}

fn point_bytes(point: AffinePoint) -> CompressedPointBytes {
    let encoded = point.to_encoded_point(true);
    let bytes: [u8; 33] = encoded
        .as_bytes()
        .try_into()
        .expect("compressed secp256k1 point has fixed width");
    CompressedPointBytes::new(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use router_ab_ecdsa_wire::{PairContextDigest, SigningScopeDigest};

    const CLIENT_COORDINATE: u64 = 2;
    const SIGNING_WORKER_COORDINATE: u64 = 3;

    struct Fixture {
        wallet_secret: Scalar,
        wallet_slope: Scalar,
        triple0_secrets: [Scalar; 3],
        triple0_slopes: [Scalar; 3],
        triple1_secrets: [Scalar; 3],
        triple1_slopes: [Scalar; 3],
        triple0_public: TriplePublic,
        triple1_public: TriplePublic,
    }

    impl Fixture {
        fn new() -> Self {
            let context = PresignPairContext::new(
                SigningScopeDigest::new([0x24; 32]),
                PairContextDigest::new([0x42; 32]),
            );
            let k = Scalar::from(7u64);
            let d = Scalar::from(11u64);
            let a = Scalar::from(13u64);
            let b = Scalar::from(17u64);
            let triple0_secrets = [k, d, k * d];
            let triple1_secrets = [a, b, a * b];

            Self {
                wallet_secret: Scalar::from(19u64),
                wallet_slope: Scalar::from(23u64),
                triple0_slopes: [Scalar::from(5u64), Scalar::from(29u64), Scalar::from(31u64)],
                triple1_slopes: [
                    Scalar::from(37u64),
                    Scalar::from(41u64),
                    Scalar::from(43u64),
                ],
                triple0_public: make_triple_public(context, triple0_secrets),
                triple1_public: make_triple_public(context, triple1_secrets),
                triple0_secrets,
                triple1_secrets,
            }
        }

        fn client_input(&self) -> ClientPresignInput {
            let coordinate = Scalar::from(CLIENT_COORDINATE);
            let key_evaluation = evaluate(self.wallet_secret, self.wallet_slope, coordinate);
            let additive_share = Scalar::from(CLIENT_LAGRANGE) * key_evaluation;

            ClientPresignInput::new(
                make_key_share(additive_share),
                generator_multiple(self.wallet_secret),
                make_validated_triple(
                    self.triple0_secrets,
                    self.triple0_slopes,
                    coordinate,
                    self.triple0_public.clone(),
                ),
                make_validated_triple(
                    self.triple1_secrets,
                    self.triple1_slopes,
                    coordinate,
                    self.triple1_public.clone(),
                ),
            )
            .expect("valid client fixture")
        }

        fn signing_worker_input(&self) -> SigningWorkerPresignInput {
            let coordinate = Scalar::from(SIGNING_WORKER_COORDINATE);
            let key_evaluation = evaluate(self.wallet_secret, self.wallet_slope, coordinate);
            let additive_share = -Scalar::from(SIGNING_WORKER_LAGRANGE_MAGNITUDE) * key_evaluation;

            SigningWorkerPresignInput::new(
                make_key_share(additive_share),
                generator_multiple(self.wallet_secret),
                make_validated_triple(
                    self.triple0_secrets,
                    self.triple0_slopes,
                    coordinate,
                    self.triple0_public.clone(),
                ),
                make_validated_triple(
                    self.triple1_secrets,
                    self.triple1_slopes,
                    coordinate,
                    self.triple1_public.clone(),
                ),
            )
            .expect("valid signing worker fixture")
        }
    }

    fn evaluate(secret: Scalar, slope: Scalar, coordinate: Scalar) -> Scalar {
        secret + slope * coordinate
    }

    fn make_validated_triple(
        secrets: [Scalar; 3],
        slopes: [Scalar; 3],
        coordinate: Scalar,
        public: TriplePublic,
    ) -> ValidatedTriple {
        ValidatedTriple::from_test_parts(
            scalar_bytes(evaluate(secrets[0], slopes[0], coordinate)),
            scalar_bytes(evaluate(secrets[1], slopes[1], coordinate)),
            scalar_bytes(evaluate(secrets[2], slopes[2], coordinate)),
            public,
        )
        .expect("valid test triple")
    }

    fn make_triple_public(context: PresignPairContext, secrets: [Scalar; 3]) -> TriplePublic {
        TriplePublic::from_bytes(
            context,
            generator_multiple(secrets[0]),
            generator_multiple(secrets[1]),
            generator_multiple(secrets[2]),
        )
        .expect("valid triple public values")
    }

    fn make_key_share(scalar: Scalar) -> AdditiveKeyShare {
        AdditiveKeyShare::from_bytes(scalar_bytes(scalar)).expect("valid additive key share")
    }

    fn generator_multiple(scalar: Scalar) -> CompressedPointBytes {
        point_bytes((ProjectivePoint::GENERATOR * scalar).to_affine())
    }

    fn scalar_from_output(bytes: [u8; 32]) -> Scalar {
        parse_scalar(bytes).expect("canonical output scalar")
    }

    fn expect_presign_error<T>(result: Result<T, PresignError>, expected: PresignError) {
        match result {
            Ok(_) => panic!("expected presign error"),
            Err(actual) => assert_eq!(actual, expected),
        }
    }

    #[test]
    fn fixed_roles_complete_near_compatible_presign_equations() {
        let fixture = Fixture::new();
        let (client_e_state, client_e) =
            start_client(fixture.client_input()).expect("client start");
        let (worker_e_state, worker_e) =
            start_signing_worker(fixture.signing_worker_input()).expect("worker start");

        let (client_alpha_state, client_alpha) =
            client_e_state.receive(worker_e).expect("client round two");
        let (worker_alpha_state, worker_alpha) =
            worker_e_state.receive(client_e).expect("worker round two");

        let client_output = client_alpha_state
            .receive(worker_alpha)
            .expect("client output");
        let worker_output = worker_alpha_state
            .receive(client_alpha)
            .expect("worker output");

        let (client_big_r, client_k, client_sigma) = client_output.into_parts();
        let (worker_big_r, worker_k, worker_sigma) = worker_output.into_parts();
        assert_eq!(client_big_r, worker_big_r);

        let client_lagrange = Scalar::from(CLIENT_LAGRANGE);
        let worker_lagrange = -Scalar::from(SIGNING_WORKER_LAGRANGE_MAGNITUDE);
        let reconstructed_k = client_lagrange * scalar_from_output(client_k.into_bytes())
            + worker_lagrange * scalar_from_output(worker_k.into_bytes());
        let reconstructed_sigma = client_lagrange * scalar_from_output(client_sigma.into_bytes())
            + worker_lagrange * scalar_from_output(worker_sigma.into_bytes());

        assert_eq!(reconstructed_k, fixture.triple0_secrets[0]);
        assert_eq!(reconstructed_sigma, reconstructed_k * fixture.wallet_secret);

        let k_inverse = Option::<Scalar>::from(reconstructed_k.invert()).expect("non-zero k");
        let expected_r = generator_multiple(k_inverse);
        assert_eq!(client_big_r, expected_r);
    }

    #[test]
    fn wrong_pair_context_aborts_before_peer_scalar_use() {
        let fixture = Fixture::new();
        let (client_e_state, _) = start_client(fixture.client_input()).expect("client start");
        let (_, worker_e) =
            start_signing_worker(fixture.signing_worker_input()).expect("worker start");
        let (_, worker_e_bytes) = worker_e.into_parts();
        let wrong_context_message = SigningWorkerEShareMessage::new(
            PresignPairContext::new(
                SigningScopeDigest::new([0x24; 32]),
                PairContextDigest::new([0x99; 32]),
            ),
            ScalarBytes::new(worker_e_bytes),
        );

        expect_presign_error(
            client_e_state.receive(wrong_context_message),
            PresignError::ContextMismatch,
        );
    }

    #[test]
    fn tampered_alpha_aborts_on_commitment_check() {
        let fixture = Fixture::new();
        let (client_e_state, client_e) =
            start_client(fixture.client_input()).expect("client start");
        let (worker_e_state, worker_e) =
            start_signing_worker(fixture.signing_worker_input()).expect("worker start");
        let (client_alpha_state, _) = client_e_state.receive(worker_e).expect("client round two");
        let (_, worker_alpha) = worker_e_state.receive(client_e).expect("worker round two");
        let (context, alpha_bytes, beta_bytes) = worker_alpha.into_parts();
        let tampered_alpha = parse_scalar(alpha_bytes).expect("canonical alpha") + Scalar::ONE;
        let tampered_message = SigningWorkerAlphaBetaMessage::new(
            context,
            scalar_bytes(tampered_alpha),
            ScalarBytes::new(beta_bytes),
        );

        expect_presign_error(
            client_alpha_state.receive(tampered_message),
            PresignError::AdditiveCommitmentMismatch,
        );
    }

    #[test]
    fn noncanonical_key_share_is_rejected_at_the_boundary() {
        expect_presign_error(
            AdditiveKeyShare::from_bytes(ScalarBytes::new([0xff; 32])),
            PresignError::NonCanonicalScalar,
        );
    }

    #[test]
    fn zero_peer_e_share_aborts_before_reconstruction() {
        let fixture = Fixture::new();
        let (client_e_state, _) = start_client(fixture.client_input()).expect("client start");
        let zero_message = SigningWorkerEShareMessage::new(
            fixture.triple0_public.context(),
            ScalarBytes::new([0; 32]),
        );

        expect_presign_error(
            client_e_state.receive(zero_message),
            PresignError::ZeroEShare,
        );
    }
}
