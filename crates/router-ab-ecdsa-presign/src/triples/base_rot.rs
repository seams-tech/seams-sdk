use core::fmt;

use k256::{
    elliptic_curve::{Field, Group},
    AffinePoint, ProjectivePoint, Scalar,
};
use rand_core::CryptoRngCore;
use router_ab_ecdsa_wire::{CompressedPointBytes, PresignPairContext};
use sha2::{Digest, Sha256};
use subtle::{ConditionallySelectable, ConstantTimeEq};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::proofs::TripleIndex;
use crate::{parse_nonidentity_point, point_bytes, PresignError};

pub const BASE_OT_COUNT: usize = 128;
pub const BASE_OT_KEY_SIZE: usize = 16;
pub mod extension;
const CHOICE_BYTES: usize = BASE_OT_COUNT / 8;
const MAX_RANDOM_ATTEMPTS: usize = 256;
const BASE_ROT_DOMAIN: &[u8] = b"seams/router-ab-ecdsa-presign/base-rot/v1";
const SUITE: &[u8] = b"secp256k1+sha256";
const CLIENT_ROLE: u8 = 1;
const SIGNING_WORKER_ROLE: u8 = 2;

type BaseOtKey = [u8; BASE_OT_KEY_SIZE];
type SenderKeys = [[BaseOtKey; 2]; BASE_OT_COUNT];
type ReceiverKeys = [BaseOtKey; BASE_OT_COUNT];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BaseRotError {
    ContextMismatch,
    TripleIndexMismatch,
    InvalidPoint,
    IdentityPoint,
    DegenerateChoicePoint,
    RandomnessExhausted,
}

impl fmt::Display for BaseRotError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ContextMismatch => "base ROT context mismatch",
            Self::TripleIndexMismatch => "base ROT triple index mismatch",
            Self::InvalidPoint => "invalid compressed secp256k1 point",
            Self::IdentityPoint => "identity base ROT point is forbidden",
            Self::DegenerateChoicePoint => "degenerate base ROT choice point",
            Self::RandomnessExhausted => "failed to generate base ROT randomness",
        })
    }
}

impl std::error::Error for BaseRotError {}

#[derive(Clone, Copy)]
struct SenderHello {
    context: PresignPairContext,
    triple_index: TripleIndex,
    public_y: AffinePoint,
}

#[derive(Clone, Copy)]
struct ReceiverChoices {
    context: PresignPairContext,
    triple_index: TripleIndex,
    public_x: [AffinePoint; BASE_OT_COUNT],
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct SenderState {
    #[zeroize(skip)]
    context: PresignPairContext,
    #[zeroize(skip)]
    triple_index: TripleIndex,
    #[zeroize(skip)]
    sender_role: u8,
    secret_y: Scalar,
    #[zeroize(skip)]
    public_y: AffinePoint,
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct SenderOutput {
    #[zeroize(skip)]
    context: PresignPairContext,
    #[zeroize(skip)]
    triple_index: TripleIndex,
    #[zeroize(skip)]
    sender_role: u8,
    keys: SenderKeys,
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct ReceiverOutput {
    #[zeroize(skip)]
    context: PresignPairContext,
    #[zeroize(skip)]
    triple_index: TripleIndex,
    #[zeroize(skip)]
    sender_role: u8,
    choices: [u8; CHOICE_BYTES],
    keys: ReceiverKeys,
}

pub struct ClientBaseRotSenderState(SenderState);
pub struct SigningWorkerBaseRotSenderState(SenderState);
pub struct ClientBaseRotSenderHello(SenderHello);
pub struct SigningWorkerBaseRotSenderHello(SenderHello);
pub struct ClientBaseRotReceiverChoices(ReceiverChoices);
pub struct SigningWorkerBaseRotReceiverChoices(ReceiverChoices);
// These sealed outputs are consumed by the pending OT-extension state.
#[allow(dead_code)]
pub struct ClientBaseRotSenderOutput(SenderOutput);
#[allow(dead_code)]
pub struct SigningWorkerBaseRotSenderOutput(SenderOutput);
#[allow(dead_code)]
pub struct ClientBaseRotReceiverOutput(ReceiverOutput);
#[allow(dead_code)]
pub struct SigningWorkerBaseRotReceiverOutput(ReceiverOutput);

macro_rules! define_hello {
    ($name:ident) => {
        impl $name {
            pub fn from_parts(
                context: PresignPairContext,
                triple_index: TripleIndex,
                public_y: CompressedPointBytes,
            ) -> Result<Self, BaseRotError> {
                Ok(Self(SenderHello {
                    context,
                    triple_index,
                    public_y: parse_point(public_y)?,
                }))
            }

            pub fn into_parts(self) -> (PresignPairContext, TripleIndex, CompressedPointBytes) {
                (
                    self.0.context,
                    self.0.triple_index,
                    point_bytes(self.0.public_y),
                )
            }
        }
    };
}

macro_rules! define_choices {
    ($name:ident) => {
        impl $name {
            pub fn from_parts(
                context: PresignPairContext,
                triple_index: TripleIndex,
                public_x: [CompressedPointBytes; BASE_OT_COUNT],
            ) -> Result<Self, BaseRotError> {
                let mut parsed = [AffinePoint::GENERATOR; BASE_OT_COUNT];
                for (target, encoded) in parsed.iter_mut().zip(public_x) {
                    *target = parse_point(encoded)?;
                }
                Ok(Self(ReceiverChoices {
                    context,
                    triple_index,
                    public_x: parsed,
                }))
            }

            pub fn into_parts(
                self,
            ) -> (
                PresignPairContext,
                TripleIndex,
                [CompressedPointBytes; BASE_OT_COUNT],
            ) {
                (
                    self.0.context,
                    self.0.triple_index,
                    self.0.public_x.map(point_bytes),
                )
            }
        }
    };
}

define_hello!(ClientBaseRotSenderHello);
define_hello!(SigningWorkerBaseRotSenderHello);
define_choices!(ClientBaseRotReceiverChoices);
define_choices!(SigningWorkerBaseRotReceiverChoices);

pub fn start_client_base_rot_sender(
    context: PresignPairContext,
    triple_index: TripleIndex,
    rng: &mut impl CryptoRngCore,
) -> Result<(ClientBaseRotSenderState, ClientBaseRotSenderHello), BaseRotError> {
    let (state, hello) = start_sender(context, triple_index, CLIENT_ROLE, rng)?;
    Ok((
        ClientBaseRotSenderState(state),
        ClientBaseRotSenderHello(hello),
    ))
}

pub fn start_signing_worker_base_rot_sender(
    context: PresignPairContext,
    triple_index: TripleIndex,
    rng: &mut impl CryptoRngCore,
) -> Result<
    (
        SigningWorkerBaseRotSenderState,
        SigningWorkerBaseRotSenderHello,
    ),
    BaseRotError,
> {
    let (state, hello) = start_sender(context, triple_index, SIGNING_WORKER_ROLE, rng)?;
    Ok((
        SigningWorkerBaseRotSenderState(state),
        SigningWorkerBaseRotSenderHello(hello),
    ))
}

pub fn receive_client_base_rot_sender_hello(
    expected_context: PresignPairContext,
    expected_triple_index: TripleIndex,
    hello: ClientBaseRotSenderHello,
    rng: &mut impl CryptoRngCore,
) -> Result<
    (
        SigningWorkerBaseRotReceiverOutput,
        SigningWorkerBaseRotReceiverChoices,
    ),
    BaseRotError,
> {
    let (output, choices) = receive_sender_hello(
        expected_context,
        expected_triple_index,
        CLIENT_ROLE,
        hello.0,
        rng,
    )?;
    Ok((
        SigningWorkerBaseRotReceiverOutput(output),
        SigningWorkerBaseRotReceiverChoices(choices),
    ))
}

pub fn receive_signing_worker_base_rot_sender_hello(
    expected_context: PresignPairContext,
    expected_triple_index: TripleIndex,
    hello: SigningWorkerBaseRotSenderHello,
    rng: &mut impl CryptoRngCore,
) -> Result<(ClientBaseRotReceiverOutput, ClientBaseRotReceiverChoices), BaseRotError> {
    let (output, choices) = receive_sender_hello(
        expected_context,
        expected_triple_index,
        SIGNING_WORKER_ROLE,
        hello.0,
        rng,
    )?;
    Ok((
        ClientBaseRotReceiverOutput(output),
        ClientBaseRotReceiverChoices(choices),
    ))
}

impl ClientBaseRotSenderState {
    pub fn receive(
        self,
        choices: SigningWorkerBaseRotReceiverChoices,
    ) -> Result<ClientBaseRotSenderOutput, BaseRotError> {
        finish_sender(self.0, choices.0).map(ClientBaseRotSenderOutput)
    }
}

impl SigningWorkerBaseRotSenderState {
    pub fn receive(
        self,
        choices: ClientBaseRotReceiverChoices,
    ) -> Result<SigningWorkerBaseRotSenderOutput, BaseRotError> {
        finish_sender(self.0, choices.0).map(SigningWorkerBaseRotSenderOutput)
    }
}

#[cfg(any(test, feature = "test-utils"))]
macro_rules! define_sender_test_parts {
    ($name:ident) => {
        impl $name {
            pub fn into_test_keys(self) -> SenderKeys {
                self.0.keys
            }
        }
    };
}

#[cfg(any(test, feature = "test-utils"))]
macro_rules! define_receiver_test_parts {
    ($name:ident) => {
        impl $name {
            pub fn into_test_parts(self) -> ([u8; CHOICE_BYTES], ReceiverKeys) {
                (self.0.choices, self.0.keys)
            }
        }
    };
}

#[cfg(any(test, feature = "test-utils"))]
define_sender_test_parts!(ClientBaseRotSenderOutput);
#[cfg(any(test, feature = "test-utils"))]
define_sender_test_parts!(SigningWorkerBaseRotSenderOutput);
#[cfg(any(test, feature = "test-utils"))]
define_receiver_test_parts!(ClientBaseRotReceiverOutput);
#[cfg(any(test, feature = "test-utils"))]
define_receiver_test_parts!(SigningWorkerBaseRotReceiverOutput);

fn start_sender(
    context: PresignPairContext,
    triple_index: TripleIndex,
    sender_role: u8,
    rng: &mut impl CryptoRngCore,
) -> Result<(SenderState, SenderHello), BaseRotError> {
    let secret_y = random_nonzero_scalar(rng)?;
    let public_y = (ProjectivePoint::GENERATOR * secret_y).to_affine();
    Ok((
        SenderState {
            context,
            triple_index,
            sender_role,
            secret_y,
            public_y,
        },
        SenderHello {
            context,
            triple_index,
            public_y,
        },
    ))
}

fn receive_sender_hello(
    expected_context: PresignPairContext,
    expected_triple_index: TripleIndex,
    sender_role: u8,
    hello: SenderHello,
    rng: &mut impl CryptoRngCore,
) -> Result<(ReceiverOutput, ReceiverChoices), BaseRotError> {
    check_binding(
        expected_context,
        expected_triple_index,
        hello.context,
        hello.triple_index,
    )?;
    let mut choice_bytes = [0u8; CHOICE_BYTES];
    rng.fill_bytes(&mut choice_bytes);
    let mut keys = [[0u8; BASE_OT_KEY_SIZE]; BASE_OT_COUNT];
    let mut public_x = [AffinePoint::GENERATOR; BASE_OT_COUNT];
    let public_y = ProjectivePoint::from(hello.public_y);
    let negative_y = -public_y;

    for index in 0..BASE_OT_COUNT {
        let secret_x = random_safe_receiver_scalar(public_y, negative_y, rng)?;
        let base_x = ProjectivePoint::GENERATOR * secret_x;
        let choice = choice_at(&choice_bytes, index);
        let selected_x = ProjectivePoint::conditional_select(&base_x, &(base_x + public_y), choice);
        public_x[index] = selected_x.to_affine();
        let shared = public_y * secret_x;
        keys[index] = derive_key(
            hello.context,
            hello.triple_index,
            sender_role,
            index,
            choice.unwrap_u8(),
            hello.public_y,
            public_x[index],
            shared.to_affine(),
        );
    }

    Ok((
        ReceiverOutput {
            context: hello.context,
            triple_index: hello.triple_index,
            sender_role,
            choices: choice_bytes,
            keys,
        },
        ReceiverChoices {
            context: hello.context,
            triple_index: hello.triple_index,
            public_x,
        },
    ))
}

fn finish_sender(
    state: SenderState,
    choices: ReceiverChoices,
) -> Result<SenderOutput, BaseRotError> {
    check_binding(
        state.context,
        state.triple_index,
        choices.context,
        choices.triple_index,
    )?;
    let public_y = ProjectivePoint::from(state.public_y);
    let mut keys = [[[0u8; BASE_OT_KEY_SIZE]; 2]; BASE_OT_COUNT];

    for (index, public_x_affine) in choices.public_x.into_iter().enumerate() {
        let public_x = ProjectivePoint::from(public_x_affine);
        let public_x_minus_y = public_x - public_y;
        if bool::from(public_x_minus_y.is_identity()) {
            return Err(BaseRotError::DegenerateChoicePoint);
        }
        let shared0 = public_x * state.secret_y;
        let shared1 = public_x_minus_y * state.secret_y;
        keys[index][0] = derive_key(
            state.context,
            state.triple_index,
            state.sender_role,
            index,
            0,
            state.public_y,
            public_x_affine,
            shared0.to_affine(),
        );
        keys[index][1] = derive_key(
            state.context,
            state.triple_index,
            state.sender_role,
            index,
            1,
            state.public_y,
            public_x_affine,
            shared1.to_affine(),
        );
    }
    Ok(SenderOutput {
        context: state.context,
        triple_index: state.triple_index,
        sender_role: state.sender_role,
        keys,
    })
}

fn random_safe_receiver_scalar(
    public_y: ProjectivePoint,
    negative_y: ProjectivePoint,
    rng: &mut impl CryptoRngCore,
) -> Result<Scalar, BaseRotError> {
    for _ in 0..MAX_RANDOM_ATTEMPTS {
        let candidate = random_nonzero_scalar(rng)?;
        let public_x = ProjectivePoint::GENERATOR * candidate;
        if !bool::from(public_x.ct_eq(&public_y)) && !bool::from(public_x.ct_eq(&negative_y)) {
            return Ok(candidate);
        }
    }
    Err(BaseRotError::RandomnessExhausted)
}

fn random_nonzero_scalar(rng: &mut impl CryptoRngCore) -> Result<Scalar, BaseRotError> {
    for _ in 0..MAX_RANDOM_ATTEMPTS {
        let candidate = Scalar::random(&mut *rng);
        if !bool::from(candidate.is_zero()) {
            return Ok(candidate);
        }
    }
    Err(BaseRotError::RandomnessExhausted)
}

fn choice_at(choices: &[u8; CHOICE_BYTES], index: usize) -> subtle::Choice {
    subtle::Choice::from((choices[index / 8] >> (index % 8)) & 1)
}

#[allow(clippy::too_many_arguments)]
fn derive_key(
    context: PresignPairContext,
    triple_index: TripleIndex,
    sender_role: u8,
    index: usize,
    branch: u8,
    public_y: AffinePoint,
    public_x: AffinePoint,
    shared: AffinePoint,
) -> BaseOtKey {
    let mut hasher = Sha256::new();
    absorb_field(&mut hasher, 1, BASE_ROT_DOMAIN);
    absorb_field(&mut hasher, 2, SUITE);
    absorb_field(&mut hasher, 3, context.signing_scope().as_bytes());
    absorb_field(&mut hasher, 4, context.pair().as_bytes());
    absorb_field(&mut hasher, 5, &[triple_index_byte(triple_index)]);
    absorb_field(&mut hasher, 6, &[sender_role]);
    absorb_field(&mut hasher, 7, &(index as u16).to_be_bytes());
    absorb_field(&mut hasher, 8, &[branch]);
    absorb_field(&mut hasher, 16, point_bytes(public_y).as_bytes());
    absorb_field(&mut hasher, 17, point_bytes(public_x).as_bytes());
    absorb_field(&mut hasher, 18, point_bytes(shared).as_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    let mut key = [0u8; BASE_OT_KEY_SIZE];
    key.copy_from_slice(&digest[..BASE_OT_KEY_SIZE]);
    key
}

fn absorb_field(hasher: &mut Sha256, tag: u16, value: &[u8]) {
    hasher.update(tag.to_be_bytes());
    hasher.update((value.len() as u32).to_be_bytes());
    hasher.update(value);
}

fn check_binding(
    expected_context: PresignPairContext,
    expected_triple_index: TripleIndex,
    actual_context: PresignPairContext,
    actual_triple_index: TripleIndex,
) -> Result<(), BaseRotError> {
    if actual_context != expected_context {
        return Err(BaseRotError::ContextMismatch);
    }
    if actual_triple_index != expected_triple_index {
        return Err(BaseRotError::TripleIndexMismatch);
    }
    Ok(())
}

fn triple_index_byte(index: TripleIndex) -> u8 {
    match index {
        TripleIndex::Zero => 0,
        TripleIndex::One => 1,
    }
}

fn parse_point(bytes: CompressedPointBytes) -> Result<AffinePoint, BaseRotError> {
    parse_nonidentity_point(bytes).map_err(|error| match error {
        PresignError::IdentityPoint => BaseRotError::IdentityPoint,
        _ => BaseRotError::InvalidPoint,
    })
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

    fn assert_correlated(sender: SenderKeys, choices: [u8; CHOICE_BYTES], receiver: ReceiverKeys) {
        for index in 0..BASE_OT_COUNT {
            let branch = usize::from(choice_at(&choices, index).unwrap_u8());
            assert_eq!(receiver[index], sender[index][branch]);
            assert_ne!(sender[index][0], sender[index][1]);
        }
    }

    #[test]
    fn client_sender_and_worker_receiver_complete_fixed_base_rot() {
        let context = binding(0x24, 0x42);
        let mut sender_rng = ChaCha20Rng::from_seed([1; 32]);
        let mut receiver_rng = ChaCha20Rng::from_seed([2; 32]);
        let (sender_state, hello) =
            start_client_base_rot_sender(context, TripleIndex::Zero, &mut sender_rng)
                .expect("sender starts");
        let (receiver_output, choices) = receive_client_base_rot_sender_hello(
            context,
            TripleIndex::Zero,
            hello,
            &mut receiver_rng,
        )
        .expect("receiver responds");
        let sender_output = sender_state.receive(choices).expect("sender finishes");
        let (choices, receiver_keys) = receiver_output.into_test_parts();
        assert_correlated(sender_output.into_test_keys(), choices, receiver_keys);
    }

    #[test]
    fn worker_sender_and_client_receiver_complete_fixed_base_rot() {
        let context = binding(3, 4);
        let mut sender_rng = ChaCha20Rng::from_seed([5; 32]);
        let mut receiver_rng = ChaCha20Rng::from_seed([6; 32]);
        let (sender_state, hello) =
            start_signing_worker_base_rot_sender(context, TripleIndex::One, &mut sender_rng)
                .expect("sender starts");
        let (receiver_output, choices) = receive_signing_worker_base_rot_sender_hello(
            context,
            TripleIndex::One,
            hello,
            &mut receiver_rng,
        )
        .expect("receiver responds");
        let sender_output = sender_state.receive(choices).expect("sender finishes");
        let (choices, receiver_keys) = receiver_output.into_test_parts();
        assert_correlated(sender_output.into_test_keys(), choices, receiver_keys);
    }

    #[test]
    fn context_substitution_aborts_before_receiver_randomness() {
        let context = binding(7, 8);
        let mut sender_rng = ChaCha20Rng::from_seed([9; 32]);
        let mut receiver_rng = ChaCha20Rng::from_seed([10; 32]);
        let (_, hello) = start_client_base_rot_sender(context, TripleIndex::Zero, &mut sender_rng)
            .expect("sender starts");
        let result = receive_client_base_rot_sender_hello(
            binding(7, 11),
            TripleIndex::Zero,
            hello,
            &mut receiver_rng,
        );
        assert!(matches!(result, Err(BaseRotError::ContextMismatch)));
    }

    #[test]
    fn degenerate_choice_point_aborts() {
        let context = binding(12, 13);
        let mut sender_rng = ChaCha20Rng::from_seed([14; 32]);
        let (sender_state, hello) =
            start_client_base_rot_sender(context, TripleIndex::One, &mut sender_rng)
                .expect("sender starts");
        let (_, _, public_y) = hello.into_parts();
        let reflected = [public_y; BASE_OT_COUNT];
        let choices =
            SigningWorkerBaseRotReceiverChoices::from_parts(context, TripleIndex::One, reflected)
                .expect("non-identity points");
        let result = sender_state.receive(choices);
        assert!(matches!(result, Err(BaseRotError::DegenerateChoicePoint)));
    }

    #[test]
    fn reflected_sender_role_cannot_produce_correlated_keys() {
        let context = binding(15, 16);
        let mut sender_rng = ChaCha20Rng::from_seed([17; 32]);
        let mut receiver_rng = ChaCha20Rng::from_seed([18; 32]);
        let (client_sender_state, client_hello) =
            start_client_base_rot_sender(context, TripleIndex::Zero, &mut sender_rng)
                .expect("sender starts");
        let (hello_context, index, public_y) = client_hello.into_parts();
        let reflected_hello =
            SigningWorkerBaseRotSenderHello::from_parts(hello_context, index, public_y)
                .expect("well-formed reflection");
        let (reflected_receiver_output, reflected_choices) =
            receive_signing_worker_base_rot_sender_hello(
                context,
                TripleIndex::Zero,
                reflected_hello,
                &mut receiver_rng,
            )
            .expect("reflected receiver responds");
        let (choice_context, _, public_x) = reflected_choices.into_parts();
        let choices_for_client_sender =
            SigningWorkerBaseRotReceiverChoices::from_parts(choice_context, index, public_x)
                .expect("well-formed reflected choices");
        let client_sender_output = client_sender_state
            .receive(choices_for_client_sender)
            .expect("original sender finishes");
        let sender_keys = client_sender_output.into_test_keys();
        let (choices, receiver_keys) = reflected_receiver_output.into_test_parts();

        for ot_index in 0..BASE_OT_COUNT {
            let branch = usize::from(choice_at(&choices, ot_index).unwrap_u8());
            assert_ne!(receiver_keys[ot_index], sender_keys[ot_index][branch]);
        }
    }
}
