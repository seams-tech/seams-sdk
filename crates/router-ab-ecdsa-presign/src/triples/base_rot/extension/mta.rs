use core::fmt;

use k256::{
    elliptic_curve::{bigint::U512, ff::PrimeField, ops::Reduce, Field},
    Scalar, WideBytes,
};
use rand_core::CryptoRngCore;
use router_ab_ecdsa_wire::PresignPairContext;
#[cfg(any(test, feature = "test-utils"))]
use router_ab_ecdsa_wire::ScalarBytes;
use sha2::{Digest, Sha512};
use subtle::{Choice, ConditionallySelectable};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::proofs::TripleIndex;

use super::{
    ClientRandomOtSenderOutput, ExtensionReceiverOutput, ExtensionSenderOutput,
    SigningWorkerRandomOtReceiverOutput, EXTENDED_OT_COUNT,
};

pub const MTA_INSTANCE_COUNT: usize = 2;
pub const MTA_OT_COUNT: usize = 384;
const MTA_TAIL_COUNT: usize = MTA_OT_COUNT - 1;
const CLIENT_ROLE: u8 = 1;
const SIGNING_WORKER_ROLE: u8 = 2;
const MTA_CHI_DOMAIN: &[u8] = b"seams/router-ab-ecdsa-presign/mta-chi/v1";
const MTA_SUITE: &[u8] = b"secp256k1+sha512";

type CiphertextScalars = Box<[[[Scalar; 2]; MTA_OT_COUNT]; MTA_INSTANCE_COUNT]>;
type CiphertextBytes = Box<[[[[u8; 32]; 2]; MTA_OT_COUNT]; MTA_INSTANCE_COUNT]>;
type Masks = Box<[[Scalar; MTA_OT_COUNT]; MTA_INSTANCE_COUNT]>;
type ChiTail = Box<[[Scalar; MTA_TAIL_COUNT]; MTA_INSTANCE_COUNT]>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MtaError {
    ContextMismatch,
    TripleIndexMismatch,
    RoleMismatch,
    NonCanonicalScalar,
}

impl fmt::Display for MtaError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ContextMismatch => "MTA context mismatch",
            Self::TripleIndexMismatch => "MTA triple index mismatch",
            Self::RoleMismatch => "MTA role mismatch",
            Self::NonCanonicalScalar => "non-canonical MTA scalar",
        })
    }
}

impl std::error::Error for MtaError {}

#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct FinalizationMultiplicationShares {
    #[zeroize(skip)]
    pub(crate) context: PresignPairContext,
    #[zeroize(skip)]
    pub(crate) role: u8,
    pub(crate) values: [Scalar; 2],
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct MultiplicationOperands {
    #[zeroize(skip)]
    context: PresignPairContext,
    #[zeroize(skip)]
    triple_index: TripleIndex,
    a: Scalar,
    b: Scalar,
}

pub struct ClientMultiplicationOperands(MultiplicationOperands);
pub struct SigningWorkerMultiplicationOperands(MultiplicationOperands);

macro_rules! define_operands {
    ($name:ident) => {
        impl $name {
            #[cfg(any(test, feature = "test-utils"))]
            pub fn from_parts(
                context: PresignPairContext,
                triple_index: TripleIndex,
                a: ScalarBytes,
                b: ScalarBytes,
            ) -> Result<Self, MtaError> {
                Ok(Self(MultiplicationOperands {
                    context,
                    triple_index,
                    a: parse_scalar(a.into_bytes())?,
                    b: parse_scalar(b.into_bytes())?,
                }))
            }
        }
    };
}

define_operands!(ClientMultiplicationOperands);
define_operands!(SigningWorkerMultiplicationOperands);

impl ClientMultiplicationOperands {
    pub(crate) fn from_scalars(
        context: PresignPairContext,
        triple_index: TripleIndex,
        a: Scalar,
        b: Scalar,
    ) -> Self {
        Self(MultiplicationOperands {
            context,
            triple_index,
            a,
            b,
        })
    }
}

impl SigningWorkerMultiplicationOperands {
    pub(crate) fn from_scalars(
        context: PresignPairContext,
        triple_index: TripleIndex,
        a: Scalar,
        b: Scalar,
    ) -> Self {
        Self(MultiplicationOperands {
            context,
            triple_index,
            a,
            b,
        })
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct CiphertextMessage {
    #[zeroize(skip)]
    context: PresignPairContext,
    #[zeroize(skip)]
    triple_index: TripleIndex,
    values: CiphertextScalars,
}

pub struct ClientMtaCiphertextMessage(CiphertextMessage);
pub struct SigningWorkerMtaCiphertextMessage(CiphertextMessage);

macro_rules! define_ciphertext_message {
    ($name:ident) => {
        impl $name {
            pub fn from_parts(
                context: PresignPairContext,
                triple_index: TripleIndex,
                values: CiphertextBytes,
            ) -> Result<Self, MtaError> {
                let mut parsed = Box::new([[[Scalar::ZERO; 2]; MTA_OT_COUNT]; MTA_INSTANCE_COUNT]);
                for (parsed_instance, encoded_instance) in parsed.iter_mut().zip(values.iter()) {
                    for (parsed_pair, encoded_pair) in
                        parsed_instance.iter_mut().zip(encoded_instance.iter())
                    {
                        parsed_pair[0] = parse_scalar(encoded_pair[0])?;
                        parsed_pair[1] = parse_scalar(encoded_pair[1])?;
                    }
                }
                Ok(Self(CiphertextMessage {
                    context,
                    triple_index,
                    values: parsed,
                }))
            }

            pub fn into_parts(self) -> (PresignPairContext, TripleIndex, CiphertextBytes) {
                let mut encoded = Box::new([[[[0u8; 32]; 2]; MTA_OT_COUNT]; MTA_INSTANCE_COUNT]);
                for (encoded_instance, scalar_instance) in
                    encoded.iter_mut().zip(self.0.values.iter())
                {
                    for (encoded_pair, scalar_pair) in
                        encoded_instance.iter_mut().zip(scalar_instance.iter())
                    {
                        encoded_pair[0] = scalar_pair[0].to_bytes().into();
                        encoded_pair[1] = scalar_pair[1].to_bytes().into();
                    }
                }
                (self.0.context, self.0.triple_index, encoded)
            }
        }
    };
}

define_ciphertext_message!(ClientMtaCiphertextMessage);
define_ciphertext_message!(SigningWorkerMtaCiphertextMessage);

#[derive(Zeroize, ZeroizeOnDrop)]
struct ResponseMessage {
    #[zeroize(skip)]
    context: PresignPairContext,
    #[zeroize(skip)]
    triple_index: TripleIndex,
    chi_first: [Scalar; MTA_INSTANCE_COUNT],
    seeds: [[u8; 32]; MTA_INSTANCE_COUNT],
}

pub struct ClientMtaResponseMessage(ResponseMessage);
pub struct SigningWorkerMtaResponseMessage(ResponseMessage);

macro_rules! define_response_message {
    ($name:ident) => {
        impl $name {
            pub fn from_parts(
                context: PresignPairContext,
                triple_index: TripleIndex,
                chi_first: [[u8; 32]; MTA_INSTANCE_COUNT],
                seeds: [[u8; 32]; MTA_INSTANCE_COUNT],
            ) -> Result<Self, MtaError> {
                Ok(Self(ResponseMessage {
                    context,
                    triple_index,
                    chi_first: [parse_scalar(chi_first[0])?, parse_scalar(chi_first[1])?],
                    seeds,
                }))
            }

            pub fn into_parts(
                self,
            ) -> (
                PresignPairContext,
                TripleIndex,
                [[u8; 32]; MTA_INSTANCE_COUNT],
                [[u8; 32]; MTA_INSTANCE_COUNT],
            ) {
                (
                    self.0.context,
                    self.0.triple_index,
                    [
                        self.0.chi_first[0].to_bytes().into(),
                        self.0.chi_first[1].to_bytes().into(),
                    ],
                    self.0.seeds,
                )
            }
        }
    };
}

define_response_message!(ClientMtaResponseMessage);
define_response_message!(SigningWorkerMtaResponseMessage);

#[derive(Zeroize, ZeroizeOnDrop)]
struct SenderAwaitingResponse {
    #[zeroize(skip)]
    context: PresignPairContext,
    #[zeroize(skip)]
    triple_index: TripleIndex,
    #[zeroize(skip)]
    sender_role: u8,
    local_product: Scalar,
    masks: Masks,
}

pub struct ClientMtaSenderAwaitingResponse(SenderAwaitingResponse);
pub struct SigningWorkerMtaSenderAwaitingResponse(SenderAwaitingResponse);

#[derive(Zeroize, ZeroizeOnDrop)]
struct MultiplicationShare {
    #[zeroize(skip)]
    context: PresignPairContext,
    #[zeroize(skip)]
    triple_index: TripleIndex,
    #[zeroize(skip)]
    owner_role: u8,
    value: Scalar,
}

#[allow(dead_code)]
pub struct ClientMultiplicationShare(MultiplicationShare);
#[allow(dead_code)]
pub struct SigningWorkerMultiplicationShare(MultiplicationShare);

#[derive(Zeroize, ZeroizeOnDrop)]
struct TwoTripleMultiplicationShares {
    #[zeroize(skip)]
    context: PresignPairContext,
    triple_zero: MultiplicationShare,
    triple_one: MultiplicationShare,
}

#[allow(dead_code)]
pub struct ClientTwoTripleMultiplicationShares(TwoTripleMultiplicationShares);
#[allow(dead_code)]
pub struct SigningWorkerTwoTripleMultiplicationShares(TwoTripleMultiplicationShares);

impl ClientTwoTripleMultiplicationShares {
    pub(crate) fn into_finalization(self) -> FinalizationMultiplicationShares {
        FinalizationMultiplicationShares {
            context: self.0.context,
            role: CLIENT_ROLE,
            values: [self.0.triple_zero.value, self.0.triple_one.value],
        }
    }
}

impl SigningWorkerTwoTripleMultiplicationShares {
    pub(crate) fn into_finalization(self) -> FinalizationMultiplicationShares {
        FinalizationMultiplicationShares {
            context: self.0.context,
            role: SIGNING_WORKER_ROLE,
            values: [self.0.triple_zero.value, self.0.triple_one.value],
        }
    }
}

pub fn combine_client_multiplication_shares(
    triple_zero: ClientMultiplicationShare,
    triple_one: ClientMultiplicationShare,
) -> Result<ClientTwoTripleMultiplicationShares, MtaError> {
    combine_two_triples(triple_zero.0, triple_one.0, CLIENT_ROLE)
        .map(ClientTwoTripleMultiplicationShares)
}

pub fn combine_signing_worker_multiplication_shares(
    triple_zero: SigningWorkerMultiplicationShare,
    triple_one: SigningWorkerMultiplicationShare,
) -> Result<SigningWorkerTwoTripleMultiplicationShares, MtaError> {
    combine_two_triples(triple_zero.0, triple_one.0, SIGNING_WORKER_ROLE)
        .map(SigningWorkerTwoTripleMultiplicationShares)
}

pub fn start_client_multiplication_sender(
    random_ot: ClientRandomOtSenderOutput,
    operands: ClientMultiplicationOperands,
    rng: &mut impl CryptoRngCore,
) -> Result<(ClientMtaSenderAwaitingResponse, ClientMtaCiphertextMessage), MtaError> {
    ensure_fixed_binding(
        random_ot.0.context,
        random_ot.0.triple_index,
        random_ot.0.sender_role,
        &operands.0,
        CLIENT_ROLE,
        TripleIndex::Zero,
    )?;
    let (state, message) = start_sender(random_ot.0, operands.0, rng);
    Ok((
        ClientMtaSenderAwaitingResponse(state),
        ClientMtaCiphertextMessage(message),
    ))
}

pub fn start_signing_worker_multiplication_sender(
    random_ot: super::SigningWorkerRandomOtSenderOutput,
    operands: SigningWorkerMultiplicationOperands,
    rng: &mut impl CryptoRngCore,
) -> Result<
    (
        SigningWorkerMtaSenderAwaitingResponse,
        SigningWorkerMtaCiphertextMessage,
    ),
    MtaError,
> {
    ensure_fixed_binding(
        random_ot.0.context,
        random_ot.0.triple_index,
        random_ot.0.sender_role,
        &operands.0,
        SIGNING_WORKER_ROLE,
        TripleIndex::One,
    )?;
    let (state, message) = start_sender(random_ot.0, operands.0, rng);
    Ok((
        SigningWorkerMtaSenderAwaitingResponse(state),
        SigningWorkerMtaCiphertextMessage(message),
    ))
}

pub fn receive_client_mta_ciphertexts(
    expected_context: PresignPairContext,
    random_ot: SigningWorkerRandomOtReceiverOutput,
    operands: SigningWorkerMultiplicationOperands,
    ciphertexts: ClientMtaCiphertextMessage,
    rng: &mut impl CryptoRngCore,
) -> Result<
    (
        SigningWorkerMultiplicationShare,
        SigningWorkerMtaResponseMessage,
    ),
    MtaError,
> {
    ensure_receiver_binding(
        expected_context,
        &random_ot.0,
        &operands.0,
        &ciphertexts.0,
        CLIENT_ROLE,
        TripleIndex::Zero,
    )?;
    let (share, response) = receive_ciphertexts(random_ot.0, operands.0, ciphertexts.0, rng);
    Ok((
        SigningWorkerMultiplicationShare(share),
        SigningWorkerMtaResponseMessage(response),
    ))
}

pub fn receive_signing_worker_mta_ciphertexts(
    expected_context: PresignPairContext,
    random_ot: super::ClientRandomOtReceiverOutput,
    operands: ClientMultiplicationOperands,
    ciphertexts: SigningWorkerMtaCiphertextMessage,
    rng: &mut impl CryptoRngCore,
) -> Result<(ClientMultiplicationShare, ClientMtaResponseMessage), MtaError> {
    ensure_receiver_binding(
        expected_context,
        &random_ot.0,
        &operands.0,
        &ciphertexts.0,
        SIGNING_WORKER_ROLE,
        TripleIndex::One,
    )?;
    let (share, response) = receive_ciphertexts(random_ot.0, operands.0, ciphertexts.0, rng);
    Ok((
        ClientMultiplicationShare(share),
        ClientMtaResponseMessage(response),
    ))
}

impl ClientMtaSenderAwaitingResponse {
    pub fn receive(
        self,
        response: SigningWorkerMtaResponseMessage,
    ) -> Result<ClientMultiplicationShare, MtaError> {
        finish_sender(self.0, response.0).map(ClientMultiplicationShare)
    }
}

impl SigningWorkerMtaSenderAwaitingResponse {
    pub fn receive(
        self,
        response: ClientMtaResponseMessage,
    ) -> Result<SigningWorkerMultiplicationShare, MtaError> {
        finish_sender(self.0, response.0).map(SigningWorkerMultiplicationShare)
    }
}

#[cfg(any(test, feature = "test-utils"))]
macro_rules! define_share_test_parts {
    ($name:ident) => {
        impl $name {
            pub fn into_test_parts(self) -> (PresignPairContext, TripleIndex, [u8; 32]) {
                (
                    self.0.context,
                    self.0.triple_index,
                    self.0.value.to_bytes().into(),
                )
            }
        }
    };
}

#[cfg(any(test, feature = "test-utils"))]
define_share_test_parts!(ClientMultiplicationShare);
#[cfg(any(test, feature = "test-utils"))]
define_share_test_parts!(SigningWorkerMultiplicationShare);

#[cfg(any(test, feature = "test-utils"))]
macro_rules! define_two_triple_test_parts {
    ($name:ident) => {
        impl $name {
            pub fn into_test_parts(self) -> (PresignPairContext, [[u8; 32]; 2]) {
                (
                    self.0.context,
                    [
                        self.0.triple_zero.value.to_bytes().into(),
                        self.0.triple_one.value.to_bytes().into(),
                    ],
                )
            }
        }
    };
}

#[cfg(any(test, feature = "test-utils"))]
define_two_triple_test_parts!(ClientTwoTripleMultiplicationShares);
#[cfg(any(test, feature = "test-utils"))]
define_two_triple_test_parts!(SigningWorkerTwoTripleMultiplicationShares);

fn start_sender(
    random_ot: ExtensionSenderOutput,
    operands: MultiplicationOperands,
    rng: &mut impl CryptoRngCore,
) -> (SenderAwaitingResponse, CiphertextMessage) {
    debug_assert_eq!(EXTENDED_OT_COUNT, MTA_INSTANCE_COUNT * MTA_OT_COUNT);
    let mut masks = Box::new([[Scalar::ZERO; MTA_OT_COUNT]; MTA_INSTANCE_COUNT]);
    let mut ciphertexts = Box::new([[[Scalar::ZERO; 2]; MTA_OT_COUNT]; MTA_INSTANCE_COUNT]);
    let inputs = [operands.a, operands.b];
    for (instance, ((instance_masks, instance_ciphertexts), input)) in masks
        .iter_mut()
        .zip(ciphertexts.iter_mut())
        .zip(inputs)
        .enumerate()
    {
        for ((mask, ciphertext), random_values) in instance_masks
            .iter_mut()
            .zip(instance_ciphertexts.iter_mut())
            .zip(random_ot.values[instance * MTA_OT_COUNT..(instance + 1) * MTA_OT_COUNT].iter())
        {
            *mask = Scalar::random(&mut *rng);
            ciphertext[0] = random_values[0] + *mask + input;
            ciphertext[1] = random_values[1] + *mask - input;
        }
    }
    let state = SenderAwaitingResponse {
        context: random_ot.context,
        triple_index: random_ot.triple_index,
        sender_role: random_ot.sender_role,
        local_product: operands.a * operands.b,
        masks,
    };
    let message = CiphertextMessage {
        context: random_ot.context,
        triple_index: random_ot.triple_index,
        values: ciphertexts,
    };
    (state, message)
}

fn receive_ciphertexts(
    random_ot: ExtensionReceiverOutput,
    operands: MultiplicationOperands,
    ciphertexts: CiphertextMessage,
    rng: &mut impl CryptoRngCore,
) -> (MultiplicationShare, ResponseMessage) {
    let mut seeds = [[0u8; 32]; MTA_INSTANCE_COUNT];
    for seed in &mut seeds {
        rng.fill_bytes(seed);
    }
    let chi_tail = derive_chi_tail(
        random_ot.context,
        random_ot.triple_index,
        random_ot.sender_role,
        &seeds,
    );
    let receiver_inputs = [operands.b, operands.a];
    let mut chi_first = [Scalar::ZERO; MTA_INSTANCE_COUNT];
    let mut betas = [Scalar::ZERO; MTA_INSTANCE_COUNT];
    for instance in 0..MTA_INSTANCE_COUNT {
        let output_start = instance * MTA_OT_COUNT;
        let first_choice = output_choice(&random_ot.choices, output_start);
        let mut signed_tail_sum = Scalar::ZERO;
        for offset in 1..MTA_OT_COUNT {
            let choice = output_choice(&random_ot.choices, output_start + offset);
            let chi = chi_tail[instance][offset - 1];
            signed_tail_sum += Scalar::conditional_select(&chi, &-chi, choice);
        }
        let unsigned_first = receiver_inputs[instance] - signed_tail_sum;
        chi_first[instance] =
            Scalar::conditional_select(&unsigned_first, &-unsigned_first, first_choice);

        let first_selected = Scalar::conditional_select(
            &ciphertexts.values[instance][0][0],
            &ciphertexts.values[instance][0][1],
            first_choice,
        );
        betas[instance] = chi_first[instance] * (first_selected - random_ot.values[output_start]);
        for offset in 1..MTA_OT_COUNT {
            let output_index = output_start + offset;
            let choice = output_choice(&random_ot.choices, output_index);
            let selected = Scalar::conditional_select(
                &ciphertexts.values[instance][offset][0],
                &ciphertexts.values[instance][offset][1],
                choice,
            );
            betas[instance] +=
                chi_tail[instance][offset - 1] * (selected - random_ot.values[output_index]);
        }
    }
    (
        MultiplicationShare {
            context: random_ot.context,
            triple_index: random_ot.triple_index,
            owner_role: opposite_role(random_ot.sender_role),
            value: operands.a * operands.b + betas[0] + betas[1],
        },
        ResponseMessage {
            context: random_ot.context,
            triple_index: random_ot.triple_index,
            chi_first,
            seeds,
        },
    )
}

fn finish_sender(
    state: SenderAwaitingResponse,
    response: ResponseMessage,
) -> Result<MultiplicationShare, MtaError> {
    check_binding(
        state.context,
        state.triple_index,
        response.context,
        response.triple_index,
    )?;
    let chi_tail = derive_chi_tail(
        state.context,
        state.triple_index,
        state.sender_role,
        &response.seeds,
    );
    let mut alphas = [Scalar::ZERO; MTA_INSTANCE_COUNT];
    for instance in 0..MTA_INSTANCE_COUNT {
        let mut masked_sum = state.masks[instance][0] * response.chi_first[instance];
        for offset in 1..MTA_OT_COUNT {
            masked_sum += state.masks[instance][offset] * chi_tail[instance][offset - 1];
        }
        alphas[instance] = -masked_sum;
    }
    Ok(MultiplicationShare {
        context: state.context,
        triple_index: state.triple_index,
        owner_role: state.sender_role,
        value: state.local_product + alphas[0] + alphas[1],
    })
}

fn derive_chi_tail(
    context: PresignPairContext,
    triple_index: TripleIndex,
    sender_role: u8,
    seeds: &[[u8; 32]; MTA_INSTANCE_COUNT],
) -> ChiTail {
    let mut values = Box::new([[Scalar::ZERO; MTA_TAIL_COUNT]; MTA_INSTANCE_COUNT]);
    for (instance, instance_values) in values.iter_mut().enumerate() {
        for (tail_index, target) in instance_values.iter_mut().enumerate() {
            let mut hasher = Sha512::new();
            absorb_field(&mut hasher, 1, MTA_CHI_DOMAIN);
            absorb_field(&mut hasher, 2, MTA_SUITE);
            absorb_field(&mut hasher, 3, context.signing_scope().as_bytes());
            absorb_field(&mut hasher, 4, context.pair().as_bytes());
            absorb_field(&mut hasher, 5, &[triple_index_byte(triple_index)]);
            absorb_field(&mut hasher, 6, &[sender_role]);
            absorb_field(&mut hasher, 7, &[instance as u8]);
            absorb_field(&mut hasher, 8, &((tail_index + 1) as u16).to_be_bytes());
            absorb_field(&mut hasher, 16, &seeds[instance]);
            let digest: [u8; 64] = hasher.finalize().into();
            let mut wide = WideBytes::default();
            wide.copy_from_slice(&digest);
            *target = <Scalar as Reduce<U512>>::reduce_bytes(&wide);
        }
    }
    values
}

fn ensure_fixed_binding(
    random_context: PresignPairContext,
    random_index: TripleIndex,
    random_sender_role: u8,
    operands: &MultiplicationOperands,
    required_sender_role: u8,
    required_index: TripleIndex,
) -> Result<(), MtaError> {
    check_binding(
        random_context,
        random_index,
        operands.context,
        operands.triple_index,
    )?;
    if random_sender_role != required_sender_role {
        return Err(MtaError::RoleMismatch);
    }
    if random_index != required_index {
        return Err(MtaError::TripleIndexMismatch);
    }
    Ok(())
}

fn combine_two_triples(
    triple_zero: MultiplicationShare,
    triple_one: MultiplicationShare,
    required_role: u8,
) -> Result<TwoTripleMultiplicationShares, MtaError> {
    check_binding(
        triple_zero.context,
        TripleIndex::One,
        triple_one.context,
        triple_one.triple_index,
    )?;
    if triple_zero.triple_index != TripleIndex::Zero {
        return Err(MtaError::TripleIndexMismatch);
    }
    if triple_zero.owner_role != required_role || triple_one.owner_role != required_role {
        return Err(MtaError::RoleMismatch);
    }
    Ok(TwoTripleMultiplicationShares {
        context: triple_zero.context,
        triple_zero,
        triple_one,
    })
}

fn ensure_receiver_binding(
    expected_context: PresignPairContext,
    random_ot: &ExtensionReceiverOutput,
    operands: &MultiplicationOperands,
    ciphertexts: &CiphertextMessage,
    required_sender_role: u8,
    required_index: TripleIndex,
) -> Result<(), MtaError> {
    check_binding(
        expected_context,
        required_index,
        random_ot.context,
        random_ot.triple_index,
    )?;
    check_binding(
        expected_context,
        required_index,
        operands.context,
        operands.triple_index,
    )?;
    check_binding(
        expected_context,
        required_index,
        ciphertexts.context,
        ciphertexts.triple_index,
    )?;
    if random_ot.sender_role != required_sender_role {
        return Err(MtaError::RoleMismatch);
    }
    Ok(())
}

fn check_binding(
    expected_context: PresignPairContext,
    expected_index: TripleIndex,
    actual_context: PresignPairContext,
    actual_index: TripleIndex,
) -> Result<(), MtaError> {
    if actual_context != expected_context {
        return Err(MtaError::ContextMismatch);
    }
    if actual_index != expected_index {
        return Err(MtaError::TripleIndexMismatch);
    }
    Ok(())
}

fn output_choice(choices: &[u8], index: usize) -> Choice {
    Choice::from((choices[index / 8] >> (index % 8)) & 1)
}

fn parse_scalar(bytes: [u8; 32]) -> Result<Scalar, MtaError> {
    Option::<Scalar>::from(Scalar::from_repr(bytes.into())).ok_or(MtaError::NonCanonicalScalar)
}

fn absorb_field<D: Digest>(hasher: &mut D, tag: u16, value: &[u8]) {
    Digest::update(hasher, tag.to_be_bytes());
    Digest::update(hasher, (value.len() as u32).to_be_bytes());
    Digest::update(hasher, value);
}

fn opposite_role(role: u8) -> u8 {
    match role {
        CLIENT_ROLE => SIGNING_WORKER_ROLE,
        SIGNING_WORKER_ROLE => CLIENT_ROLE,
        _ => 0,
    }
}

fn triple_index_byte(index: TripleIndex) -> u8 {
    match index {
        TripleIndex::Zero => 0,
        TripleIndex::One => 1,
    }
}

#[cfg(test)]
mod tests {
    use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
    use router_ab_ecdsa_wire::{PairContextDigest, SigningScopeDigest};

    use super::*;
    use crate::triples::base_rot::{
        receive_client_base_rot_sender_hello, receive_signing_worker_base_rot_sender_hello,
        start_client_base_rot_sender, start_signing_worker_base_rot_sender,
    };

    fn binding() -> PresignPairContext {
        PresignPairContext::new(
            SigningScopeDigest::new([0x24; 32]),
            PairContextDigest::new([0x42; 32]),
        )
    }

    fn scalar_bytes(value: u64) -> ScalarBytes {
        ScalarBytes::new(Scalar::from(value).to_bytes().into())
    }

    fn client_operands(index: TripleIndex, a: u64, b: u64) -> ClientMultiplicationOperands {
        ClientMultiplicationOperands::from_parts(binding(), index, scalar_bytes(a), scalar_bytes(b))
            .expect("client operands")
    }

    fn worker_operands(index: TripleIndex, a: u64, b: u64) -> SigningWorkerMultiplicationOperands {
        SigningWorkerMultiplicationOperands::from_parts(
            binding(),
            index,
            scalar_bytes(a),
            scalar_bytes(b),
        )
        .expect("worker operands")
    }

    fn client_sender_random_ot(
        index: TripleIndex,
        seed: u8,
    ) -> (
        ClientRandomOtSenderOutput,
        SigningWorkerRandomOtReceiverOutput,
    ) {
        let mut base_sender_rng = ChaCha20Rng::from_seed([seed; 32]);
        let mut base_receiver_rng = ChaCha20Rng::from_seed([seed + 1; 32]);
        let (worker_base_state, hello) =
            start_signing_worker_base_rot_sender(binding(), index, &mut base_sender_rng)
                .expect("worker base sender");
        let (client_base_output, response) = receive_signing_worker_base_rot_sender_hello(
            binding(),
            index,
            hello,
            &mut base_receiver_rng,
        )
        .expect("client base receiver");
        let worker_base_output = worker_base_state
            .receive(response)
            .expect("worker base sender finishes");
        let mut extension_receiver_rng = ChaCha20Rng::from_seed([seed + 2; 32]);
        let mut extension_sender_rng = ChaCha20Rng::from_seed([seed + 3; 32]);
        let (worker_state, correlation) = super::super::start_signing_worker_extension_receiver(
            worker_base_output,
            &mut extension_receiver_rng,
        )
        .expect("worker extension receiver");
        let (client_state, challenge) = super::super::start_client_extension_sender(
            binding(),
            index,
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
        index: TripleIndex,
        seed: u8,
    ) -> (
        super::super::SigningWorkerRandomOtSenderOutput,
        super::super::ClientRandomOtReceiverOutput,
    ) {
        let mut base_sender_rng = ChaCha20Rng::from_seed([seed; 32]);
        let mut base_receiver_rng = ChaCha20Rng::from_seed([seed + 1; 32]);
        let (client_base_state, hello) =
            start_client_base_rot_sender(binding(), index, &mut base_sender_rng)
                .expect("client base sender");
        let (worker_base_output, response) =
            receive_client_base_rot_sender_hello(binding(), index, hello, &mut base_receiver_rng)
                .expect("worker base receiver");
        let client_base_output = client_base_state
            .receive(response)
            .expect("client base sender finishes");
        let mut extension_receiver_rng = ChaCha20Rng::from_seed([seed + 2; 32]);
        let mut extension_sender_rng = ChaCha20Rng::from_seed([seed + 3; 32]);
        let (client_state, correlation) = super::super::start_client_extension_receiver(
            client_base_output,
            &mut extension_receiver_rng,
        )
        .expect("client extension receiver");
        let (worker_state, challenge) = super::super::start_signing_worker_extension_sender(
            binding(),
            index,
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

    fn share_scalar(bytes: [u8; 32]) -> Scalar {
        parse_scalar(bytes).expect("canonical share")
    }

    #[test]
    fn client_sender_fixed_mta_produces_a_product_share() {
        let (client_random_ot, worker_random_ot) = client_sender_random_ot(TripleIndex::Zero, 21);
        let mut sender_rng = ChaCha20Rng::from_seed([25; 32]);
        let mut receiver_rng = ChaCha20Rng::from_seed([26; 32]);
        let (client_state, ciphertexts) = start_client_multiplication_sender(
            client_random_ot,
            client_operands(TripleIndex::Zero, 7, 11),
            &mut sender_rng,
        )
        .expect("client MTA sender");
        let (worker_share, response) = receive_client_mta_ciphertexts(
            binding(),
            worker_random_ot,
            worker_operands(TripleIndex::Zero, 13, 17),
            ciphertexts,
            &mut receiver_rng,
        )
        .expect("worker MTA receiver");
        let client_share = client_state.receive(response).expect("client share");
        let (_, _, client_value) = client_share.into_test_parts();
        let (_, _, worker_value) = worker_share.into_test_parts();

        assert_eq!(
            share_scalar(client_value) + share_scalar(worker_value),
            Scalar::from(7u64 + 13) * Scalar::from(11u64 + 17)
        );
    }

    #[test]
    fn signing_worker_sender_fixed_mta_produces_a_product_share() {
        let (worker_random_ot, client_random_ot) = worker_sender_random_ot(TripleIndex::One, 31);
        let mut sender_rng = ChaCha20Rng::from_seed([35; 32]);
        let mut receiver_rng = ChaCha20Rng::from_seed([36; 32]);
        let (worker_state, ciphertexts) = start_signing_worker_multiplication_sender(
            worker_random_ot,
            worker_operands(TripleIndex::One, 19, 23),
            &mut sender_rng,
        )
        .expect("worker MTA sender");
        let (client_share, response) = receive_signing_worker_mta_ciphertexts(
            binding(),
            client_random_ot,
            client_operands(TripleIndex::One, 29, 31),
            ciphertexts,
            &mut receiver_rng,
        )
        .expect("client MTA receiver");
        let worker_share = worker_state.receive(response).expect("worker share");
        let (_, _, client_value) = client_share.into_test_parts();
        let (_, _, worker_value) = worker_share.into_test_parts();

        assert_eq!(
            share_scalar(client_value) + share_scalar(worker_value),
            Scalar::from(19u64 + 29) * Scalar::from(23u64 + 31)
        );
    }

    #[test]
    fn context_substitution_aborts_before_receiver_randomness() {
        let (client_random_ot, worker_random_ot) = client_sender_random_ot(TripleIndex::Zero, 41);
        let mut sender_rng = ChaCha20Rng::from_seed([45; 32]);
        let mut receiver_rng = ChaCha20Rng::from_seed([46; 32]);
        let (_, ciphertexts) = start_client_multiplication_sender(
            client_random_ot,
            client_operands(TripleIndex::Zero, 7, 11),
            &mut sender_rng,
        )
        .expect("client MTA sender");
        let wrong_context = PresignPairContext::new(
            SigningScopeDigest::new([0x24; 32]),
            PairContextDigest::new([0x99; 32]),
        );
        let result = receive_client_mta_ciphertexts(
            wrong_context,
            worker_random_ot,
            worker_operands(TripleIndex::Zero, 13, 17),
            ciphertexts,
            &mut receiver_rng,
        );
        assert!(matches!(result, Err(MtaError::ContextMismatch)));
    }

    #[test]
    fn client_sender_is_restricted_to_triple_zero() {
        let (client_random_ot, _) = client_sender_random_ot(TripleIndex::One, 51);
        let mut sender_rng = ChaCha20Rng::from_seed([55; 32]);
        let result = start_client_multiplication_sender(
            client_random_ot,
            client_operands(TripleIndex::One, 7, 11),
            &mut sender_rng,
        );
        assert!(matches!(result, Err(MtaError::TripleIndexMismatch)));
    }

    #[test]
    fn noncanonical_ciphertext_is_rejected_at_the_boundary() {
        let mut values = Box::new([[[[0u8; 32]; 2]; MTA_OT_COUNT]; MTA_INSTANCE_COUNT]);
        values[0][0][0] = [0xff; 32];
        let result = ClientMtaCiphertextMessage::from_parts(binding(), TripleIndex::Zero, values);
        assert!(matches!(result, Err(MtaError::NonCanonicalScalar)));
    }

    #[test]
    fn two_triple_bundle_requires_zero_then_one() {
        let triple_zero = ClientMultiplicationShare(MultiplicationShare {
            context: binding(),
            triple_index: TripleIndex::Zero,
            owner_role: CLIENT_ROLE,
            value: Scalar::from(5u64),
        });
        let triple_one = ClientMultiplicationShare(MultiplicationShare {
            context: binding(),
            triple_index: TripleIndex::One,
            owner_role: CLIENT_ROLE,
            value: Scalar::from(7u64),
        });
        let bundle = combine_client_multiplication_shares(triple_zero, triple_one)
            .expect("fixed pair combines");
        let (_, values) = bundle.into_test_parts();
        assert_eq!(share_scalar(values[0]), Scalar::from(5u64));
        assert_eq!(share_scalar(values[1]), Scalar::from(7u64));

        let swapped_zero = ClientMultiplicationShare(MultiplicationShare {
            context: binding(),
            triple_index: TripleIndex::One,
            owner_role: CLIENT_ROLE,
            value: Scalar::from(5u64),
        });
        let swapped_one = ClientMultiplicationShare(MultiplicationShare {
            context: binding(),
            triple_index: TripleIndex::Zero,
            owner_role: CLIENT_ROLE,
            value: Scalar::from(7u64),
        });
        let result = combine_client_multiplication_shares(swapped_zero, swapped_one);
        assert!(matches!(result, Err(MtaError::TripleIndexMismatch)));
    }

    #[test]
    fn altered_ciphertext_breaks_the_terminal_product_equation() {
        let (client_random_ot, worker_random_ot) = client_sender_random_ot(TripleIndex::Zero, 61);
        let mut sender_rng = ChaCha20Rng::from_seed([65; 32]);
        let mut receiver_rng = ChaCha20Rng::from_seed([66; 32]);
        let (client_state, mut ciphertexts) = start_client_multiplication_sender(
            client_random_ot,
            client_operands(TripleIndex::Zero, 7, 11),
            &mut sender_rng,
        )
        .expect("client MTA sender");
        ciphertexts.0.values[0][0][0] += Scalar::ONE;
        ciphertexts.0.values[0][0][1] += Scalar::ONE;
        let (worker_share, response) = receive_client_mta_ciphertexts(
            binding(),
            worker_random_ot,
            worker_operands(TripleIndex::Zero, 13, 17),
            ciphertexts,
            &mut receiver_rng,
        )
        .expect("worker MTA receiver");
        let client_share = client_state.receive(response).expect("client share");
        let (_, _, client_value) = client_share.into_test_parts();
        let (_, _, worker_value) = worker_share.into_test_parts();

        assert_ne!(
            share_scalar(client_value) + share_scalar(worker_value),
            Scalar::from(7u64 + 13) * Scalar::from(11u64 + 17)
        );
    }
}
