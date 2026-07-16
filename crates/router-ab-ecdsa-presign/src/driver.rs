use core::fmt;

use rand_core::CryptoRngCore;
use router_ab_ecdsa_wire::{
    ClientAlphaBetaMessage, ClientEShareMessage, CompressedPointBytes, PresignPairContext,
    SigningWorkerAlphaBetaMessage, SigningWorkerEShareMessage,
};

use crate::proofs::TripleIndex;
use crate::triples::base_rot::extension::mta::{
    combine_client_multiplication_shares, combine_signing_worker_multiplication_shares,
    receive_client_mta_ciphertexts, receive_signing_worker_mta_ciphertexts,
    start_client_multiplication_sender, start_signing_worker_multiplication_sender,
    ClientMtaCiphertextMessage, ClientMtaResponseMessage, ClientMtaSenderAwaitingResponse,
    ClientMultiplicationShare, MtaError, SigningWorkerMtaCiphertextMessage,
    SigningWorkerMtaResponseMessage, SigningWorkerMtaSenderAwaitingResponse,
    SigningWorkerMultiplicationShare,
};
use crate::triples::base_rot::extension::{
    start_client_extension_receiver, start_client_extension_sender,
    start_signing_worker_extension_receiver, start_signing_worker_extension_sender,
    ClientExtensionAcceptanceMessage, ClientExtensionChallengeMessage,
    ClientExtensionCorrelationMessage, ClientExtensionProofMessage,
    ClientExtensionReceiverAwaitingAcceptance, ClientExtensionReceiverAwaitingChallenge,
    ClientExtensionSenderAwaitingProof, ClientRandomOtReceiverOutput, ClientRandomOtSenderOutput,
    ExtensionError, SigningWorkerExtensionAcceptanceMessage,
    SigningWorkerExtensionChallengeMessage, SigningWorkerExtensionCorrelationMessage,
    SigningWorkerExtensionProofMessage, SigningWorkerExtensionReceiverAwaitingAcceptance,
    SigningWorkerExtensionReceiverAwaitingChallenge, SigningWorkerExtensionSenderAwaitingProof,
    SigningWorkerRandomOtReceiverOutput, SigningWorkerRandomOtSenderOutput,
};
use crate::triples::base_rot::{
    receive_client_base_rot_sender_hello, receive_signing_worker_base_rot_sender_hello,
    start_client_base_rot_sender, start_signing_worker_base_rot_sender, BaseRotError,
    ClientBaseRotReceiverChoices, ClientBaseRotReceiverOutput, ClientBaseRotSenderHello,
    ClientBaseRotSenderState, SigningWorkerBaseRotReceiverChoices,
    SigningWorkerBaseRotReceiverOutput, SigningWorkerBaseRotSenderHello,
    SigningWorkerBaseRotSenderState,
};
use crate::triples::finalize::{
    prepare_client_triple_finalization, prepare_signing_worker_triple_finalization,
    ClientTripleFinalizationMessage, ClientTripleFinalizationState,
    SigningWorkerTripleFinalizationMessage, SigningWorkerTripleFinalizationState,
    TripleGenerationError,
};
use crate::triples::{
    commit_client_polynomials, commit_signing_worker_polynomials, verify_client_polynomial_opening,
    verify_client_private_share_for_signing_worker, verify_signing_worker_polynomial_opening,
    verify_signing_worker_private_share_for_client, ClientCommittedPolynomials,
    ClientOpenedPolynomials, ClientPolynomialCommitmentMessage, ClientPolynomialOpeningMessage,
    ClientPolynomialShareMessage, PolynomialError, SigningWorkerCommittedPolynomials,
    SigningWorkerOpenedPolynomials, SigningWorkerPolynomialCommitmentMessage,
    SigningWorkerPolynomialOpeningMessage, SigningWorkerPolynomialShareMessage,
    VerifiedClientPrivateShare, VerifiedSigningWorkerPrivateShare,
};
use crate::{
    start_client, start_signing_worker, AdditiveKeyShare, ClientAwaitingPeerAlphaBeta,
    ClientAwaitingPeerE, ClientPresignInput, PresignError, PresignOutput,
    SigningWorkerAwaitingPeerAlphaBeta, SigningWorkerAwaitingPeerE, SigningWorkerPresignInput,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PresignDriverError {
    Polynomial(PolynomialError),
    BaseRot(BaseRotError),
    Extension(ExtensionError),
    Multiplication(MtaError),
    TripleGeneration(TripleGenerationError),
    Presign(PresignError),
}

impl fmt::Display for PresignDriverError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Polynomial(error) => write!(formatter, "polynomial round failed: {error}"),
            Self::BaseRot(error) => write!(formatter, "base ROT round failed: {error}"),
            Self::Extension(error) => write!(formatter, "OT extension round failed: {error}"),
            Self::Multiplication(error) => write!(formatter, "MTA round failed: {error}"),
            Self::TripleGeneration(error) => {
                write!(formatter, "triple finalization failed: {error}")
            }
            Self::Presign(error) => write!(formatter, "presign round failed: {error}"),
        }
    }
}

impl std::error::Error for PresignDriverError {}

macro_rules! impl_error_conversion {
    ($source:ty, $variant:ident) => {
        impl From<$source> for PresignDriverError {
            fn from(error: $source) -> Self {
                Self::$variant(error)
            }
        }
    };
}

impl_error_conversion!(PolynomialError, Polynomial);
impl_error_conversion!(BaseRotError, BaseRot);
impl_error_conversion!(ExtensionError, Extension);
impl_error_conversion!(MtaError, Multiplication);
impl_error_conversion!(TripleGenerationError, TripleGeneration);
impl_error_conversion!(PresignError, Presign);

struct PendingPresignInput {
    key_share: AdditiveKeyShare,
    wallet_public_key: CompressedPointBytes,
}

pub struct ClientRound1Message {
    pub(crate) commitments: [ClientPolynomialCommitmentMessage; 2],
    pub(crate) base_hello: ClientBaseRotSenderHello,
}

pub struct SigningWorkerRound1Message {
    pub(crate) commitments: [SigningWorkerPolynomialCommitmentMessage; 2],
    pub(crate) base_hello: SigningWorkerBaseRotSenderHello,
}

pub struct ClientRound2Message {
    pub(crate) openings: [ClientPolynomialOpeningMessage; 2],
    pub(crate) private_shares: [ClientPolynomialShareMessage; 2],
    pub(crate) base_choices: ClientBaseRotReceiverChoices,
}

pub struct SigningWorkerRound2Message {
    pub(crate) openings: [SigningWorkerPolynomialOpeningMessage; 2],
    pub(crate) private_shares: [SigningWorkerPolynomialShareMessage; 2],
    pub(crate) base_choices: SigningWorkerBaseRotReceiverChoices,
}

pub struct ClientRound1State {
    context: PresignPairContext,
    pending: PendingPresignInput,
    polynomials: [ClientCommittedPolynomials; 2],
    base_sender: ClientBaseRotSenderState,
}

pub struct SigningWorkerRound1State {
    context: PresignPairContext,
    pending: PendingPresignInput,
    polynomials: [SigningWorkerCommittedPolynomials; 2],
    base_sender: SigningWorkerBaseRotSenderState,
}

pub struct ClientRound2State {
    context: PresignPairContext,
    pending: PendingPresignInput,
    opened: [ClientOpenedPolynomials; 2],
    peer_commitments: [SigningWorkerPolynomialCommitmentMessage; 2],
    base_sender: ClientBaseRotSenderState,
    base_receiver: ClientBaseRotReceiverOutput,
}

pub struct SigningWorkerRound2State {
    context: PresignPairContext,
    pending: PendingPresignInput,
    opened: [SigningWorkerOpenedPolynomials; 2],
    peer_commitments: [ClientPolynomialCommitmentMessage; 2],
    base_sender: SigningWorkerBaseRotSenderState,
    base_receiver: SigningWorkerBaseRotReceiverOutput,
}

struct ClientTripleState {
    context: PresignPairContext,
    pending: PendingPresignInput,
    opened: [ClientOpenedPolynomials; 2],
    peer_shares: [VerifiedSigningWorkerPrivateShare; 2],
}

struct SigningWorkerTripleState {
    context: PresignPairContext,
    pending: PendingPresignInput,
    opened: [SigningWorkerOpenedPolynomials; 2],
    peer_shares: [VerifiedClientPrivateShare; 2],
}

pub struct ClientRound3State {
    triple: ClientTripleState,
    base_receiver: ClientBaseRotReceiverOutput,
    extension_receiver: Box<ClientExtensionReceiverAwaitingChallenge>,
}

pub struct SigningWorkerRound3State {
    triple: SigningWorkerTripleState,
    base_receiver: SigningWorkerBaseRotReceiverOutput,
    extension_receiver: Box<SigningWorkerExtensionReceiverAwaitingChallenge>,
}

pub struct ClientRound4State {
    triple: ClientTripleState,
    extension_receiver: Box<ClientExtensionReceiverAwaitingChallenge>,
    extension_sender: Box<ClientExtensionSenderAwaitingProof>,
}

pub struct SigningWorkerRound4State {
    triple: SigningWorkerTripleState,
    extension_receiver: Box<SigningWorkerExtensionReceiverAwaitingChallenge>,
    extension_sender: Box<SigningWorkerExtensionSenderAwaitingProof>,
}

pub struct ClientRound5State {
    triple: ClientTripleState,
    extension_receiver: Box<ClientExtensionReceiverAwaitingAcceptance>,
    extension_sender: Box<ClientExtensionSenderAwaitingProof>,
}

pub struct SigningWorkerRound5State {
    triple: SigningWorkerTripleState,
    extension_receiver: Box<SigningWorkerExtensionReceiverAwaitingAcceptance>,
    extension_sender: Box<SigningWorkerExtensionSenderAwaitingProof>,
}

pub struct ClientRound6State {
    triple: ClientTripleState,
    extension_receiver: Box<ClientExtensionReceiverAwaitingAcceptance>,
    random_sender: Box<ClientRandomOtSenderOutput>,
}

pub struct SigningWorkerRound6State {
    triple: SigningWorkerTripleState,
    extension_receiver: Box<SigningWorkerExtensionReceiverAwaitingAcceptance>,
    random_sender: Box<SigningWorkerRandomOtSenderOutput>,
}

pub struct ClientRound7State {
    triple: ClientTripleState,
    random_receiver: Box<ClientRandomOtReceiverOutput>,
    mta_sender: Box<ClientMtaSenderAwaitingResponse>,
}

pub struct SigningWorkerRound7State {
    triple: SigningWorkerTripleState,
    random_receiver: Box<SigningWorkerRandomOtReceiverOutput>,
    mta_sender: Box<SigningWorkerMtaSenderAwaitingResponse>,
}

pub struct ClientRound8State {
    triple: ClientTripleState,
    mta_sender: Box<ClientMtaSenderAwaitingResponse>,
    receiver_share: ClientMultiplicationShare,
}

pub struct SigningWorkerRound8State {
    triple: SigningWorkerTripleState,
    mta_sender: Box<SigningWorkerMtaSenderAwaitingResponse>,
    receiver_share: SigningWorkerMultiplicationShare,
}

pub struct ClientRound9State {
    pending: PendingPresignInput,
    triple_finalization: ClientTripleFinalizationState,
}

pub struct SigningWorkerRound9State {
    pending: PendingPresignInput,
    triple_finalization: SigningWorkerTripleFinalizationState,
}

pub struct ClientRound10State(ClientAwaitingPeerE);
pub struct SigningWorkerRound10State(SigningWorkerAwaitingPeerE);
pub struct ClientRound11State(ClientAwaitingPeerAlphaBeta);
pub struct SigningWorkerRound11State(SigningWorkerAwaitingPeerAlphaBeta);

pub fn start_client_driver(
    context: PresignPairContext,
    key_share: AdditiveKeyShare,
    wallet_public_key: CompressedPointBytes,
    rng: &mut impl CryptoRngCore,
) -> Result<(ClientRound1State, ClientRound1Message), PresignDriverError> {
    let (polynomial_zero, commitment_zero) =
        commit_client_polynomials(context, TripleIndex::Zero, rng)?;
    let (polynomial_one, commitment_one) =
        commit_client_polynomials(context, TripleIndex::One, rng)?;
    let (base_sender, base_hello) = start_client_base_rot_sender(context, TripleIndex::One, rng)?;
    Ok((
        ClientRound1State {
            context,
            pending: PendingPresignInput {
                key_share,
                wallet_public_key,
            },
            polynomials: [polynomial_zero, polynomial_one],
            base_sender,
        },
        ClientRound1Message {
            commitments: [commitment_zero, commitment_one],
            base_hello,
        },
    ))
}

pub fn start_signing_worker_driver(
    context: PresignPairContext,
    key_share: AdditiveKeyShare,
    wallet_public_key: CompressedPointBytes,
    rng: &mut impl CryptoRngCore,
) -> Result<(SigningWorkerRound1State, SigningWorkerRound1Message), PresignDriverError> {
    let (polynomial_zero, commitment_zero) =
        commit_signing_worker_polynomials(context, TripleIndex::Zero, rng)?;
    let (polynomial_one, commitment_one) =
        commit_signing_worker_polynomials(context, TripleIndex::One, rng)?;
    let (base_sender, base_hello) =
        start_signing_worker_base_rot_sender(context, TripleIndex::Zero, rng)?;
    Ok((
        SigningWorkerRound1State {
            context,
            pending: PendingPresignInput {
                key_share,
                wallet_public_key,
            },
            polynomials: [polynomial_zero, polynomial_one],
            base_sender,
        },
        SigningWorkerRound1Message {
            commitments: [commitment_zero, commitment_one],
            base_hello,
        },
    ))
}

impl ClientRound1State {
    pub fn receive(
        self,
        message: SigningWorkerRound1Message,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(ClientRound2State, ClientRound2Message), PresignDriverError> {
        let [polynomial_zero, polynomial_one] = self.polynomials;
        let (opened_zero, opening_zero) = polynomial_zero.open();
        let (opened_one, opening_one) = polynomial_one.open();
        let private_zero = opened_zero.private_share_for_signing_worker();
        let private_one = opened_one.private_share_for_signing_worker();
        let (base_receiver, base_choices) = receive_signing_worker_base_rot_sender_hello(
            self.context,
            TripleIndex::Zero,
            message.base_hello,
            rng,
        )?;
        Ok((
            ClientRound2State {
                context: self.context,
                pending: self.pending,
                opened: [opened_zero, opened_one],
                peer_commitments: message.commitments,
                base_sender: self.base_sender,
                base_receiver,
            },
            ClientRound2Message {
                openings: [opening_zero, opening_one],
                private_shares: [private_zero, private_one],
                base_choices,
            },
        ))
    }
}

impl SigningWorkerRound1State {
    pub fn receive(
        self,
        message: ClientRound1Message,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(SigningWorkerRound2State, SigningWorkerRound2Message), PresignDriverError> {
        let [polynomial_zero, polynomial_one] = self.polynomials;
        let (opened_zero, opening_zero) = polynomial_zero.open();
        let (opened_one, opening_one) = polynomial_one.open();
        let private_zero = opened_zero.private_share_for_client();
        let private_one = opened_one.private_share_for_client();
        let (base_receiver, base_choices) = receive_client_base_rot_sender_hello(
            self.context,
            TripleIndex::One,
            message.base_hello,
            rng,
        )?;
        Ok((
            SigningWorkerRound2State {
                context: self.context,
                pending: self.pending,
                opened: [opened_zero, opened_one],
                peer_commitments: message.commitments,
                base_sender: self.base_sender,
                base_receiver,
            },
            SigningWorkerRound2Message {
                openings: [opening_zero, opening_one],
                private_shares: [private_zero, private_one],
                base_choices,
            },
        ))
    }
}

impl ClientRound2State {
    pub fn receive(
        self,
        message: SigningWorkerRound2Message,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(ClientRound3State, Box<ClientExtensionCorrelationMessage>), PresignDriverError>
    {
        let [commitment_zero, commitment_one] = self.peer_commitments;
        let [opening_zero, opening_one] = message.openings;
        let [private_zero, private_one] = message.private_shares;
        let verified_zero = verify_signing_worker_polynomial_opening(
            self.context,
            TripleIndex::Zero,
            commitment_zero,
            opening_zero,
        )?;
        let verified_one = verify_signing_worker_polynomial_opening(
            self.context,
            TripleIndex::One,
            commitment_one,
            opening_one,
        )?;
        let peer_zero = verify_signing_worker_private_share_for_client(
            self.context,
            TripleIndex::Zero,
            &verified_zero,
            private_zero,
        )?;
        let peer_one = verify_signing_worker_private_share_for_client(
            self.context,
            TripleIndex::One,
            &verified_one,
            private_one,
        )?;
        let base_sender = self.base_sender.receive(message.base_choices)?;
        let (extension_receiver, correlation) = start_client_extension_receiver(base_sender, rng)?;
        Ok((
            ClientRound3State {
                triple: ClientTripleState {
                    context: self.context,
                    pending: self.pending,
                    opened: self.opened,
                    peer_shares: [peer_zero, peer_one],
                },
                base_receiver: self.base_receiver,
                extension_receiver: Box::new(extension_receiver),
            },
            Box::new(correlation),
        ))
    }
}

impl SigningWorkerRound2State {
    pub fn receive(
        self,
        message: ClientRound2Message,
        rng: &mut impl CryptoRngCore,
    ) -> Result<
        (
            SigningWorkerRound3State,
            Box<SigningWorkerExtensionCorrelationMessage>,
        ),
        PresignDriverError,
    > {
        let [commitment_zero, commitment_one] = self.peer_commitments;
        let [opening_zero, opening_one] = message.openings;
        let [private_zero, private_one] = message.private_shares;
        let verified_zero = verify_client_polynomial_opening(
            self.context,
            TripleIndex::Zero,
            commitment_zero,
            opening_zero,
        )?;
        let verified_one = verify_client_polynomial_opening(
            self.context,
            TripleIndex::One,
            commitment_one,
            opening_one,
        )?;
        let peer_zero = verify_client_private_share_for_signing_worker(
            self.context,
            TripleIndex::Zero,
            &verified_zero,
            private_zero,
        )?;
        let peer_one = verify_client_private_share_for_signing_worker(
            self.context,
            TripleIndex::One,
            &verified_one,
            private_one,
        )?;
        let base_sender = self.base_sender.receive(message.base_choices)?;
        let (extension_receiver, correlation) =
            start_signing_worker_extension_receiver(base_sender, rng)?;
        Ok((
            SigningWorkerRound3State {
                triple: SigningWorkerTripleState {
                    context: self.context,
                    pending: self.pending,
                    opened: self.opened,
                    peer_shares: [peer_zero, peer_one],
                },
                base_receiver: self.base_receiver,
                extension_receiver: Box::new(extension_receiver),
            },
            Box::new(correlation),
        ))
    }
}

impl ClientRound3State {
    pub fn receive(
        self,
        message: SigningWorkerExtensionCorrelationMessage,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(ClientRound4State, ClientExtensionChallengeMessage), PresignDriverError> {
        let (extension_sender, challenge) = start_client_extension_sender(
            self.triple.context,
            TripleIndex::Zero,
            self.base_receiver,
            message,
            rng,
        )?;
        Ok((
            ClientRound4State {
                triple: self.triple,
                extension_receiver: self.extension_receiver,
                extension_sender: Box::new(extension_sender),
            },
            challenge,
        ))
    }
}

impl SigningWorkerRound3State {
    pub fn receive(
        self,
        message: ClientExtensionCorrelationMessage,
        rng: &mut impl CryptoRngCore,
    ) -> Result<
        (
            SigningWorkerRound4State,
            SigningWorkerExtensionChallengeMessage,
        ),
        PresignDriverError,
    > {
        let (extension_sender, challenge) = start_signing_worker_extension_sender(
            self.triple.context,
            TripleIndex::One,
            self.base_receiver,
            message,
            rng,
        )?;
        Ok((
            SigningWorkerRound4State {
                triple: self.triple,
                extension_receiver: self.extension_receiver,
                extension_sender: Box::new(extension_sender),
            },
            challenge,
        ))
    }
}

impl ClientRound4State {
    pub fn receive(
        self,
        message: SigningWorkerExtensionChallengeMessage,
    ) -> Result<(ClientRound5State, ClientExtensionProofMessage), PresignDriverError> {
        let (extension_receiver, proof) = (*self.extension_receiver).receive(message)?;
        Ok((
            ClientRound5State {
                triple: self.triple,
                extension_receiver: Box::new(extension_receiver),
                extension_sender: self.extension_sender,
            },
            proof,
        ))
    }
}

impl SigningWorkerRound4State {
    pub fn receive(
        self,
        message: ClientExtensionChallengeMessage,
    ) -> Result<(SigningWorkerRound5State, SigningWorkerExtensionProofMessage), PresignDriverError>
    {
        let (extension_receiver, proof) = (*self.extension_receiver).receive(message)?;
        Ok((
            SigningWorkerRound5State {
                triple: self.triple,
                extension_receiver: Box::new(extension_receiver),
                extension_sender: self.extension_sender,
            },
            proof,
        ))
    }
}

impl ClientRound5State {
    pub fn receive(
        self,
        message: SigningWorkerExtensionProofMessage,
    ) -> Result<(ClientRound6State, ClientExtensionAcceptanceMessage), PresignDriverError> {
        let (random_sender, acceptance) = (*self.extension_sender).receive(message)?;
        Ok((
            ClientRound6State {
                triple: self.triple,
                extension_receiver: self.extension_receiver,
                random_sender: Box::new(random_sender),
            },
            acceptance,
        ))
    }
}

impl SigningWorkerRound5State {
    pub fn receive(
        self,
        message: ClientExtensionProofMessage,
    ) -> Result<
        (
            SigningWorkerRound6State,
            SigningWorkerExtensionAcceptanceMessage,
        ),
        PresignDriverError,
    > {
        let (random_sender, acceptance) = (*self.extension_sender).receive(message)?;
        Ok((
            SigningWorkerRound6State {
                triple: self.triple,
                extension_receiver: self.extension_receiver,
                random_sender: Box::new(random_sender),
            },
            acceptance,
        ))
    }
}

impl ClientRound6State {
    pub fn receive(
        self,
        message: SigningWorkerExtensionAcceptanceMessage,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(ClientRound7State, ClientMtaCiphertextMessage), PresignDriverError> {
        let random_receiver = (*self.extension_receiver).receive(message)?;
        let [opened_zero, opened_one] = self.triple.opened;
        let operands = opened_zero.multiplication_operands();
        let (mta_sender, ciphertexts) =
            start_client_multiplication_sender(*self.random_sender, operands, rng)?;
        Ok((
            ClientRound7State {
                triple: ClientTripleState {
                    context: self.triple.context,
                    pending: self.triple.pending,
                    opened: [opened_zero, opened_one],
                    peer_shares: self.triple.peer_shares,
                },
                random_receiver: Box::new(random_receiver),
                mta_sender: Box::new(mta_sender),
            },
            ciphertexts,
        ))
    }
}

impl SigningWorkerRound6State {
    pub fn receive(
        self,
        message: ClientExtensionAcceptanceMessage,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(SigningWorkerRound7State, SigningWorkerMtaCiphertextMessage), PresignDriverError>
    {
        let random_receiver = (*self.extension_receiver).receive(message)?;
        let [opened_zero, opened_one] = self.triple.opened;
        let operands = opened_one.multiplication_operands();
        let (mta_sender, ciphertexts) =
            start_signing_worker_multiplication_sender(*self.random_sender, operands, rng)?;
        Ok((
            SigningWorkerRound7State {
                triple: SigningWorkerTripleState {
                    context: self.triple.context,
                    pending: self.triple.pending,
                    opened: [opened_zero, opened_one],
                    peer_shares: self.triple.peer_shares,
                },
                random_receiver: Box::new(random_receiver),
                mta_sender: Box::new(mta_sender),
            },
            ciphertexts,
        ))
    }
}

impl ClientRound7State {
    pub fn receive(
        self,
        message: SigningWorkerMtaCiphertextMessage,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(ClientRound8State, ClientMtaResponseMessage), PresignDriverError> {
        let operands = self.triple.opened[1].multiplication_operands();
        let (receiver_share, response) = receive_signing_worker_mta_ciphertexts(
            self.triple.context,
            *self.random_receiver,
            operands,
            message,
            rng,
        )?;
        Ok((
            ClientRound8State {
                triple: self.triple,
                mta_sender: self.mta_sender,
                receiver_share,
            },
            response,
        ))
    }
}

impl SigningWorkerRound7State {
    pub fn receive(
        self,
        message: ClientMtaCiphertextMessage,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(SigningWorkerRound8State, SigningWorkerMtaResponseMessage), PresignDriverError>
    {
        let operands = self.triple.opened[0].multiplication_operands();
        let (receiver_share, response) = receive_client_mta_ciphertexts(
            self.triple.context,
            *self.random_receiver,
            operands,
            message,
            rng,
        )?;
        Ok((
            SigningWorkerRound8State {
                triple: self.triple,
                mta_sender: self.mta_sender,
                receiver_share,
            },
            response,
        ))
    }
}

impl ClientRound8State {
    pub fn receive(
        self,
        message: SigningWorkerMtaResponseMessage,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(ClientRound9State, ClientTripleFinalizationMessage), PresignDriverError> {
        let sender_share = (*self.mta_sender).receive(message)?;
        let multiplication =
            combine_client_multiplication_shares(sender_share, self.receiver_share)?;
        let (triple_finalization, message) = prepare_client_triple_finalization(
            self.triple.opened,
            self.triple.peer_shares,
            multiplication,
            rng,
        )?;
        Ok((
            ClientRound9State {
                pending: self.triple.pending,
                triple_finalization,
            },
            message,
        ))
    }
}

impl SigningWorkerRound8State {
    pub fn receive(
        self,
        message: ClientMtaResponseMessage,
        rng: &mut impl CryptoRngCore,
    ) -> Result<
        (
            SigningWorkerRound9State,
            SigningWorkerTripleFinalizationMessage,
        ),
        PresignDriverError,
    > {
        let sender_share = (*self.mta_sender).receive(message)?;
        let multiplication =
            combine_signing_worker_multiplication_shares(self.receiver_share, sender_share)?;
        let (triple_finalization, message) = prepare_signing_worker_triple_finalization(
            self.triple.opened,
            self.triple.peer_shares,
            multiplication,
            rng,
        )?;
        Ok((
            SigningWorkerRound9State {
                pending: self.triple.pending,
                triple_finalization,
            },
            message,
        ))
    }
}

impl ClientRound9State {
    pub fn receive(
        self,
        message: SigningWorkerTripleFinalizationMessage,
    ) -> Result<(ClientRound10State, ClientEShareMessage), PresignDriverError> {
        let triples = self.triple_finalization.receive(message)?;
        let (triple_zero, triple_one) = triples.into_triples();
        let input = ClientPresignInput::new(
            self.pending.key_share,
            self.pending.wallet_public_key,
            triple_zero,
            triple_one,
        )?;
        let (state, message) = start_client(input)?;
        Ok((ClientRound10State(state), message))
    }
}

impl SigningWorkerRound9State {
    pub fn receive(
        self,
        message: ClientTripleFinalizationMessage,
    ) -> Result<(SigningWorkerRound10State, SigningWorkerEShareMessage), PresignDriverError> {
        let triples = self.triple_finalization.receive(message)?;
        let (triple_zero, triple_one) = triples.into_triples();
        let input = SigningWorkerPresignInput::new(
            self.pending.key_share,
            self.pending.wallet_public_key,
            triple_zero,
            triple_one,
        )?;
        let (state, message) = start_signing_worker(input)?;
        Ok((SigningWorkerRound10State(state), message))
    }
}

impl ClientRound10State {
    pub fn receive(
        self,
        message: SigningWorkerEShareMessage,
    ) -> Result<(ClientRound11State, ClientAlphaBetaMessage), PresignDriverError> {
        let (state, message) = self.0.receive(message)?;
        Ok((ClientRound11State(state), message))
    }
}

impl SigningWorkerRound10State {
    pub fn receive(
        self,
        message: ClientEShareMessage,
    ) -> Result<(SigningWorkerRound11State, SigningWorkerAlphaBetaMessage), PresignDriverError>
    {
        let (state, message) = self.0.receive(message)?;
        Ok((SigningWorkerRound11State(state), message))
    }
}

impl ClientRound11State {
    pub fn receive(
        self,
        message: SigningWorkerAlphaBetaMessage,
    ) -> Result<PresignOutput, PresignDriverError> {
        self.0.receive(message).map_err(Into::into)
    }
}

impl SigningWorkerRound11State {
    pub fn receive(
        self,
        message: ClientAlphaBetaMessage,
    ) -> Result<PresignOutput, PresignDriverError> {
        self.0.receive(message).map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use k256::{AffinePoint, ProjectivePoint, Scalar};
    use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
    use router_ab_ecdsa_online::{
        compute_client_signature_share, finalize_signing_worker_signature, ClientPresignMaterial,
        OnlineClientInput, SigningWorkerOnlineInput, SigningWorkerPresignMaterial,
    };
    use router_ab_ecdsa_wire::{PairContextDigest, ScalarBytes, SigningScopeDigest};
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::point_bytes;

    fn context() -> PresignPairContext {
        PresignPairContext::new(
            SigningScopeDigest::new([0x24; 32]),
            PairContextDigest::new([0x42; 32]),
        )
    }

    fn key_share(value: u64) -> AdditiveKeyShare {
        AdditiveKeyShare::from_bytes(ScalarBytes::new(Scalar::from(value).to_bytes().into()))
            .expect("non-zero key share")
    }

    #[test]
    fn fixed_driver_completes_new_new_presign() {
        let wallet_public = point_bytes(AffinePoint::from(
            ProjectivePoint::GENERATOR * Scalar::from(42u64),
        ));
        let mut client_rng = ChaCha20Rng::from_seed([0x31; 32]);
        let mut worker_rng = ChaCha20Rng::from_seed([0x32; 32]);

        let (client1, client_message1) =
            start_client_driver(context(), key_share(19), wallet_public, &mut client_rng)
                .expect("client round 1");
        let (worker1, worker_message1) =
            start_signing_worker_driver(context(), key_share(23), wallet_public, &mut worker_rng)
                .expect("worker round 1");
        let (client2, client_message2) = client1
            .receive(worker_message1, &mut client_rng)
            .expect("client round 2");
        let (worker2, worker_message2) = worker1
            .receive(client_message1, &mut worker_rng)
            .expect("worker round 2");
        let (client3, client_message3) = client2
            .receive(worker_message2, &mut client_rng)
            .expect("client round 3");
        let (worker3, worker_message3) = worker2
            .receive(client_message2, &mut worker_rng)
            .expect("worker round 3");
        let (client4, client_message4) = client3
            .receive(*worker_message3, &mut client_rng)
            .expect("client round 4");
        let (worker4, worker_message4) = worker3
            .receive(*client_message3, &mut worker_rng)
            .expect("worker round 4");
        let (client5, client_message5) = client4.receive(worker_message4).expect("client round 5");
        let (worker5, worker_message5) = worker4.receive(client_message4).expect("worker round 5");
        let (client6, client_message6) = client5.receive(worker_message5).expect("client round 6");
        let (worker6, worker_message6) = worker5.receive(client_message5).expect("worker round 6");
        let (client7, client_message7) = client6
            .receive(worker_message6, &mut client_rng)
            .expect("client round 7");
        let (worker7, worker_message7) = worker6
            .receive(client_message6, &mut worker_rng)
            .expect("worker round 7");
        let (client8, client_message8) = client7
            .receive(worker_message7, &mut client_rng)
            .expect("client round 8");
        let (worker8, worker_message8) = worker7
            .receive(client_message7, &mut worker_rng)
            .expect("worker round 8");
        let (client9, client_message9) = client8
            .receive(worker_message8, &mut client_rng)
            .expect("client round 9");
        let (worker9, worker_message9) = worker8
            .receive(client_message8, &mut worker_rng)
            .expect("worker round 9");
        let (client10, client_message10) =
            client9.receive(worker_message9).expect("client round 10");
        let (worker10, worker_message10) =
            worker9.receive(client_message9).expect("worker round 10");
        let (client11, client_message11) =
            client10.receive(worker_message10).expect("client round 11");
        let (worker11, worker_message11) =
            worker10.receive(client_message10).expect("worker round 11");
        let client_output = client11.receive(worker_message11).expect("client output");
        let worker_output = worker11.receive(client_message11).expect("worker output");
        let (client_big_r, client_k, client_sigma) = client_output.into_parts();
        let (worker_big_r, worker_k, worker_sigma) = worker_output.into_parts();
        assert_eq!(client_big_r, worker_big_r);

        let big_r = *client_big_r.as_bytes();
        let wallet_public = *wallet_public.as_bytes();
        let digest = [0x42; 32];
        let entropy = [0x24; 32];
        let client_committed = ClientPresignMaterial::from_bytes(
            big_r,
            client_k.into_bytes(),
            client_sigma.into_bytes(),
        )
        .expect("client material")
        .reserve()
        .commit(
            OnlineClientInput::new(wallet_public, big_r, digest, entropy)
                .expect("client online input"),
        )
        .expect("client commit");
        let client_share = compute_client_signature_share(client_committed).expect("client share");
        let worker_committed = SigningWorkerPresignMaterial::from_bytes(
            big_r,
            worker_k.into_bytes(),
            worker_sigma.into_bytes(),
        )
        .expect("worker material")
        .reserve()
        .commit(
            SigningWorkerOnlineInput::new(wallet_public, big_r, digest, entropy)
                .expect("worker online input"),
        )
        .expect("worker commit");
        let signature = finalize_signing_worker_signature(worker_committed, client_share)
            .expect("recoverable signature");
        let signature_digest: [u8; 32] = Sha256::digest(signature).into();
        assert_eq!(
            signature_digest,
            [
                0x32, 0xd1, 0x80, 0x4e, 0xd9, 0x2c, 0xfb, 0x5f, 0xec, 0x40, 0xf4, 0xef, 0xe7, 0x6b,
                0xff, 0x13, 0xd7, 0x5f, 0x26, 0xe5, 0xab, 0x20, 0x9b, 0x05, 0x09, 0x4c, 0x86, 0x72,
                0x82, 0xaa, 0x91, 0x8c,
            ]
        );
    }
}
