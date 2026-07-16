use core::fmt;

use rand_core::CryptoRngCore;
use router_ab_ecdsa_wire::{
    CompressedPointBytes, PairContextDigest, PresignPairContext, SigningScopeDigest,
};
use sha2::{Digest, Sha256};

use crate::codec::{
    decode_client_round1, decode_client_round10, decode_client_round11, decode_client_round2,
    decode_client_round3, decode_client_round4, decode_client_round5, decode_client_round6,
    decode_client_round7, decode_client_round8, decode_client_round9, decode_signing_worker_round1,
    decode_signing_worker_round10, decode_signing_worker_round11, decode_signing_worker_round2,
    decode_signing_worker_round3, decode_signing_worker_round4, decode_signing_worker_round5,
    decode_signing_worker_round6, decode_signing_worker_round7, decode_signing_worker_round8,
    decode_signing_worker_round9, EncodePresignMessage, PresignCodecError, PRESIGN_PROTOCOL_ID,
};
use crate::driver::{
    start_client_driver, start_signing_worker_driver, ClientRound10State, ClientRound11State,
    ClientRound1State, ClientRound2State, ClientRound3State, ClientRound4State, ClientRound5State,
    ClientRound6State, ClientRound7State, ClientRound8State, ClientRound9State, PresignDriverError,
    SigningWorkerRound10State, SigningWorkerRound11State, SigningWorkerRound1State,
    SigningWorkerRound2State, SigningWorkerRound3State, SigningWorkerRound4State,
    SigningWorkerRound5State, SigningWorkerRound6State, SigningWorkerRound7State,
    SigningWorkerRound8State, SigningWorkerRound9State,
};
use crate::{AdditiveKeyShare, PresignOutput};

const SCOPE_DOMAIN: &[u8] = b"seams/router-ab-ecdsa-presign/signing-scope/v1";
const PAIR_DOMAIN: &[u8] = b"seams/router-ab-ecdsa-presign/pair-context/v1";
const MAX_SESSION_ID_SIZE: usize = 256;
const PRESIGNATURE_SIZE: usize = 97;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PresignSessionStage {
    Triples,
    TriplesDone,
    Presign,
    Done,
}

impl PresignSessionStage {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Triples => "triples",
            Self::TriplesDone => "triples_done",
            Self::Presign => "presign",
            Self::Done => "done",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PresignSessionEvent {
    None,
    TriplesDone,
    PresignDone,
}

impl PresignSessionEvent {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::TriplesDone => "triples_done",
            Self::PresignDone => "presign_done",
        }
    }
}

pub struct PresignSessionProgress {
    pub stage: PresignSessionStage,
    pub event: PresignSessionEvent,
    pub outgoing: Vec<Vec<u8>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PresignSessionError {
    EmptySessionId,
    SessionIdTooLong,
    InvalidState,
    OutputUnavailable,
    Driver(PresignDriverError),
    Codec(PresignCodecError),
}

impl fmt::Display for PresignSessionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptySessionId => formatter.write_str("presign session id is empty"),
            Self::SessionIdTooLong => formatter.write_str("presign session id exceeds 256 bytes"),
            Self::InvalidState => formatter.write_str("presign session transition is invalid"),
            Self::OutputUnavailable => formatter.write_str("presign output is unavailable"),
            Self::Driver(error) => write!(formatter, "presign driver failed: {error}"),
            Self::Codec(error) => write!(formatter, "presign frame failed: {error}"),
        }
    }
}

impl std::error::Error for PresignSessionError {}

impl From<PresignDriverError> for PresignSessionError {
    fn from(error: PresignDriverError) -> Self {
        Self::Driver(error)
    }
}

impl From<PresignCodecError> for PresignSessionError {
    fn from(error: PresignCodecError) -> Self {
        Self::Codec(error)
    }
}

pub fn derive_presign_pair_context(
    wallet_public_key: CompressedPointBytes,
    presign_session_id: &str,
) -> Result<PresignPairContext, PresignSessionError> {
    let session_id = presign_session_id.as_bytes();
    if session_id.is_empty() {
        return Err(PresignSessionError::EmptySessionId);
    }
    if session_id.len() > MAX_SESSION_ID_SIZE {
        return Err(PresignSessionError::SessionIdTooLong);
    }

    let mut scope = Sha256::new();
    scope.update(SCOPE_DOMAIN);
    scope.update(PRESIGN_PROTOCOL_ID.as_bytes());
    scope.update(wallet_public_key.as_bytes());
    let signing_scope = SigningScopeDigest::new(scope.finalize().into());

    let mut pair = Sha256::new();
    pair.update(PAIR_DOMAIN);
    pair.update(PRESIGN_PROTOCOL_ID.as_bytes());
    pair.update(signing_scope.as_bytes());
    pair.update((session_id.len() as u32).to_be_bytes());
    pair.update(session_id);
    Ok(PresignPairContext::new(
        signing_scope,
        PairContextDigest::new(pair.finalize().into()),
    ))
}

enum ClientState {
    Round1(Box<ClientRound1State>),
    Round2(Box<ClientRound2State>),
    Round3(Box<ClientRound3State>),
    Round4(Box<ClientRound4State>),
    Round5(Box<ClientRound5State>),
    Round6(Box<ClientRound6State>),
    Round7(Box<ClientRound7State>),
    Round8(Box<ClientRound8State>),
    Round9(Box<ClientRound9State>),
    TriplesDone {
        state: Box<ClientRound10State>,
        first_presign_message: Vec<u8>,
    },
    Round10(Box<ClientRound10State>),
    Round11(Box<ClientRound11State>),
    Done(Option<Vec<u8>>),
    Poisoned,
}

pub struct ClientPresignSession {
    state: ClientState,
    outgoing: Vec<Vec<u8>>,
    event: PresignSessionEvent,
}

impl ClientPresignSession {
    pub fn new(
        context: PresignPairContext,
        key_share: AdditiveKeyShare,
        wallet_public_key: CompressedPointBytes,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self, PresignSessionError> {
        let (state, message) = start_client_driver(context, key_share, wallet_public_key, rng)?;
        Ok(Self {
            state: ClientState::Round1(Box::new(state)),
            outgoing: vec![message.encode_presign_message()?],
            event: PresignSessionEvent::None,
        })
    }

    pub fn stage(&self) -> PresignSessionStage {
        match self.state {
            ClientState::Round1(_)
            | ClientState::Round2(_)
            | ClientState::Round3(_)
            | ClientState::Round4(_)
            | ClientState::Round5(_)
            | ClientState::Round6(_)
            | ClientState::Round7(_)
            | ClientState::Round8(_)
            | ClientState::Round9(_) => PresignSessionStage::Triples,
            ClientState::TriplesDone { .. } => PresignSessionStage::TriplesDone,
            ClientState::Round10(_) | ClientState::Round11(_) => PresignSessionStage::Presign,
            ClientState::Done(_) | ClientState::Poisoned => PresignSessionStage::Done,
        }
    }

    pub fn poll(&mut self) -> PresignSessionProgress {
        let progress = PresignSessionProgress {
            stage: self.stage(),
            event: self.event,
            outgoing: core::mem::take(&mut self.outgoing),
        };
        self.event = PresignSessionEvent::None;
        progress
    }

    pub fn message(
        &mut self,
        encoded: &[u8],
        rng: &mut impl CryptoRngCore,
    ) -> Result<(), PresignSessionError> {
        let current = core::mem::replace(&mut self.state, ClientState::Poisoned);
        let (next, outgoing, event) = advance_client(current, encoded, rng)?;
        self.state = next;
        if let Some(message) = outgoing {
            self.outgoing.push(message);
        }
        self.event = event;
        Ok(())
    }

    pub fn start_presign(&mut self) -> Result<(), PresignSessionError> {
        let current = core::mem::replace(&mut self.state, ClientState::Poisoned);
        match current {
            ClientState::TriplesDone {
                state,
                first_presign_message,
            } => {
                self.state = ClientState::Round10(state);
                self.outgoing.push(first_presign_message);
                Ok(())
            }
            _ => Err(PresignSessionError::InvalidState),
        }
    }

    pub fn take_presignature_97(&mut self) -> Result<Vec<u8>, PresignSessionError> {
        match &mut self.state {
            ClientState::Done(output) => {
                output.take().ok_or(PresignSessionError::OutputUnavailable)
            }
            _ => Err(PresignSessionError::OutputUnavailable),
        }
    }
}

fn advance_client(
    state: ClientState,
    encoded: &[u8],
    rng: &mut impl CryptoRngCore,
) -> Result<(ClientState, Option<Vec<u8>>, PresignSessionEvent), PresignSessionError> {
    let unchanged = PresignSessionEvent::None;
    match state {
        ClientState::Round1(state) => {
            let (next, message) = (*state).receive(decode_signing_worker_round1(encoded)?, rng)?;
            Ok((
                ClientState::Round2(Box::new(next)),
                Some(message.encode_presign_message()?),
                unchanged,
            ))
        }
        ClientState::Round2(state) => {
            let (next, message) = (*state).receive(decode_signing_worker_round2(encoded)?, rng)?;
            Ok((
                ClientState::Round3(Box::new(next)),
                Some(message.encode_presign_message()?),
                unchanged,
            ))
        }
        ClientState::Round3(state) => {
            let (next, message) = (*state).receive(decode_signing_worker_round3(encoded)?, rng)?;
            Ok((
                ClientState::Round4(Box::new(next)),
                Some(message.encode_presign_message()?),
                unchanged,
            ))
        }
        ClientState::Round4(state) => {
            let (next, message) = (*state).receive(decode_signing_worker_round4(encoded)?)?;
            Ok((
                ClientState::Round5(Box::new(next)),
                Some(message.encode_presign_message()?),
                unchanged,
            ))
        }
        ClientState::Round5(state) => {
            let (next, message) = (*state).receive(decode_signing_worker_round5(encoded)?)?;
            Ok((
                ClientState::Round6(Box::new(next)),
                Some(message.encode_presign_message()?),
                unchanged,
            ))
        }
        ClientState::Round6(state) => {
            let (next, message) = (*state).receive(decode_signing_worker_round6(encoded)?, rng)?;
            Ok((
                ClientState::Round7(Box::new(next)),
                Some(message.encode_presign_message()?),
                unchanged,
            ))
        }
        ClientState::Round7(state) => {
            let (next, message) = (*state).receive(decode_signing_worker_round7(encoded)?, rng)?;
            Ok((
                ClientState::Round8(Box::new(next)),
                Some(message.encode_presign_message()?),
                unchanged,
            ))
        }
        ClientState::Round8(state) => {
            let (next, message) = (*state).receive(decode_signing_worker_round8(encoded)?, rng)?;
            Ok((
                ClientState::Round9(Box::new(next)),
                Some(message.encode_presign_message()?),
                unchanged,
            ))
        }
        ClientState::Round9(state) => {
            let (next, message) = (*state).receive(decode_signing_worker_round9(encoded)?)?;
            Ok((
                ClientState::TriplesDone {
                    state: Box::new(next),
                    first_presign_message: message.encode_presign_message()?,
                },
                None,
                PresignSessionEvent::TriplesDone,
            ))
        }
        ClientState::Round10(state) => {
            let (next, message) = (*state).receive(decode_signing_worker_round10(encoded)?)?;
            Ok((
                ClientState::Round11(Box::new(next)),
                Some(message.encode_presign_message()?),
                unchanged,
            ))
        }
        ClientState::Round11(state) => {
            let output = (*state).receive(decode_signing_worker_round11(encoded)?)?;
            Ok((
                ClientState::Done(Some(output_bytes(output))),
                None,
                PresignSessionEvent::PresignDone,
            ))
        }
        ClientState::TriplesDone { .. } | ClientState::Done(_) | ClientState::Poisoned => {
            Err(PresignSessionError::InvalidState)
        }
    }
}

enum SigningWorkerState {
    Round1(Box<SigningWorkerRound1State>),
    Round2(Box<SigningWorkerRound2State>),
    Round3(Box<SigningWorkerRound3State>),
    Round4(Box<SigningWorkerRound4State>),
    Round5(Box<SigningWorkerRound5State>),
    Round6(Box<SigningWorkerRound6State>),
    Round7(Box<SigningWorkerRound7State>),
    Round8(Box<SigningWorkerRound8State>),
    Round9(Box<SigningWorkerRound9State>),
    TriplesDone {
        state: Box<SigningWorkerRound10State>,
        first_presign_message: Vec<u8>,
    },
    Round10(Box<SigningWorkerRound10State>),
    Round11(Box<SigningWorkerRound11State>),
    Done(Option<Vec<u8>>),
    Poisoned,
}

pub struct SigningWorkerPresignSession {
    state: SigningWorkerState,
    outgoing: Vec<Vec<u8>>,
    event: PresignSessionEvent,
}

impl SigningWorkerPresignSession {
    pub fn new(
        context: PresignPairContext,
        key_share: AdditiveKeyShare,
        wallet_public_key: CompressedPointBytes,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self, PresignSessionError> {
        let (state, message) =
            start_signing_worker_driver(context, key_share, wallet_public_key, rng)?;
        Ok(Self {
            state: SigningWorkerState::Round1(Box::new(state)),
            outgoing: vec![message.encode_presign_message()?],
            event: PresignSessionEvent::None,
        })
    }

    pub fn stage(&self) -> PresignSessionStage {
        match self.state {
            SigningWorkerState::Round1(_)
            | SigningWorkerState::Round2(_)
            | SigningWorkerState::Round3(_)
            | SigningWorkerState::Round4(_)
            | SigningWorkerState::Round5(_)
            | SigningWorkerState::Round6(_)
            | SigningWorkerState::Round7(_)
            | SigningWorkerState::Round8(_)
            | SigningWorkerState::Round9(_) => PresignSessionStage::Triples,
            SigningWorkerState::TriplesDone { .. } => PresignSessionStage::TriplesDone,
            SigningWorkerState::Round10(_) | SigningWorkerState::Round11(_) => {
                PresignSessionStage::Presign
            }
            SigningWorkerState::Done(_) | SigningWorkerState::Poisoned => PresignSessionStage::Done,
        }
    }

    pub fn poll(&mut self) -> PresignSessionProgress {
        let progress = PresignSessionProgress {
            stage: self.stage(),
            event: self.event,
            outgoing: core::mem::take(&mut self.outgoing),
        };
        self.event = PresignSessionEvent::None;
        progress
    }

    pub fn message(
        &mut self,
        encoded: &[u8],
        rng: &mut impl CryptoRngCore,
    ) -> Result<(), PresignSessionError> {
        let current = core::mem::replace(&mut self.state, SigningWorkerState::Poisoned);
        let (next, outgoing, event) = advance_signing_worker(current, encoded, rng)?;
        self.state = next;
        if let Some(message) = outgoing {
            self.outgoing.push(message);
        }
        self.event = event;
        Ok(())
    }

    pub fn start_presign(&mut self) -> Result<(), PresignSessionError> {
        let current = core::mem::replace(&mut self.state, SigningWorkerState::Poisoned);
        match current {
            SigningWorkerState::TriplesDone {
                state,
                first_presign_message,
            } => {
                self.state = SigningWorkerState::Round10(state);
                self.outgoing.push(first_presign_message);
                Ok(())
            }
            _ => Err(PresignSessionError::InvalidState),
        }
    }

    pub fn take_presignature_97(&mut self) -> Result<Vec<u8>, PresignSessionError> {
        match &mut self.state {
            SigningWorkerState::Done(output) => {
                output.take().ok_or(PresignSessionError::OutputUnavailable)
            }
            _ => Err(PresignSessionError::OutputUnavailable),
        }
    }
}

fn advance_signing_worker(
    state: SigningWorkerState,
    encoded: &[u8],
    rng: &mut impl CryptoRngCore,
) -> Result<(SigningWorkerState, Option<Vec<u8>>, PresignSessionEvent), PresignSessionError> {
    let unchanged = PresignSessionEvent::None;
    match state {
        SigningWorkerState::Round1(state) => {
            let (next, message) = (*state).receive(decode_client_round1(encoded)?, rng)?;
            Ok((
                SigningWorkerState::Round2(Box::new(next)),
                Some(message.encode_presign_message()?),
                unchanged,
            ))
        }
        SigningWorkerState::Round2(state) => {
            let (next, message) = (*state).receive(decode_client_round2(encoded)?, rng)?;
            Ok((
                SigningWorkerState::Round3(Box::new(next)),
                Some(message.encode_presign_message()?),
                unchanged,
            ))
        }
        SigningWorkerState::Round3(state) => {
            let (next, message) = (*state).receive(decode_client_round3(encoded)?, rng)?;
            Ok((
                SigningWorkerState::Round4(Box::new(next)),
                Some(message.encode_presign_message()?),
                unchanged,
            ))
        }
        SigningWorkerState::Round4(state) => {
            let (next, message) = (*state).receive(decode_client_round4(encoded)?)?;
            Ok((
                SigningWorkerState::Round5(Box::new(next)),
                Some(message.encode_presign_message()?),
                unchanged,
            ))
        }
        SigningWorkerState::Round5(state) => {
            let (next, message) = (*state).receive(decode_client_round5(encoded)?)?;
            Ok((
                SigningWorkerState::Round6(Box::new(next)),
                Some(message.encode_presign_message()?),
                unchanged,
            ))
        }
        SigningWorkerState::Round6(state) => {
            let (next, message) = (*state).receive(decode_client_round6(encoded)?, rng)?;
            Ok((
                SigningWorkerState::Round7(Box::new(next)),
                Some(message.encode_presign_message()?),
                unchanged,
            ))
        }
        SigningWorkerState::Round7(state) => {
            let (next, message) = (*state).receive(decode_client_round7(encoded)?, rng)?;
            Ok((
                SigningWorkerState::Round8(Box::new(next)),
                Some(message.encode_presign_message()?),
                unchanged,
            ))
        }
        SigningWorkerState::Round8(state) => {
            let (next, message) = (*state).receive(decode_client_round8(encoded)?, rng)?;
            Ok((
                SigningWorkerState::Round9(Box::new(next)),
                Some(message.encode_presign_message()?),
                unchanged,
            ))
        }
        SigningWorkerState::Round9(state) => {
            let (next, message) = (*state).receive(decode_client_round9(encoded)?)?;
            Ok((
                SigningWorkerState::TriplesDone {
                    state: Box::new(next),
                    first_presign_message: message.encode_presign_message()?,
                },
                None,
                PresignSessionEvent::TriplesDone,
            ))
        }
        SigningWorkerState::Round10(state) => {
            let (next, message) = (*state).receive(decode_client_round10(encoded)?)?;
            Ok((
                SigningWorkerState::Round11(Box::new(next)),
                Some(message.encode_presign_message()?),
                unchanged,
            ))
        }
        SigningWorkerState::Round11(state) => {
            let output = (*state).receive(decode_client_round11(encoded)?)?;
            Ok((
                SigningWorkerState::Done(Some(output_bytes(output))),
                None,
                PresignSessionEvent::PresignDone,
            ))
        }
        SigningWorkerState::TriplesDone { .. }
        | SigningWorkerState::Done(_)
        | SigningWorkerState::Poisoned => Err(PresignSessionError::InvalidState),
    }
}

fn output_bytes(output: PresignOutput) -> Vec<u8> {
    let (big_r, k, sigma) = output.into_parts();
    let mut bytes = Vec::with_capacity(PRESIGNATURE_SIZE);
    bytes.extend_from_slice(big_r.as_bytes());
    bytes.extend_from_slice(&k.into_bytes());
    bytes.extend_from_slice(&sigma.into_bytes());
    bytes
}

#[cfg(test)]
mod tests {
    use k256::{ProjectivePoint, Scalar};
    use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
    use router_ab_ecdsa_wire::{ScalarBytes, COMPRESSED_POINT_SIZE};

    use super::*;

    fn key_share(value: u64) -> AdditiveKeyShare {
        AdditiveKeyShare::from_bytes(ScalarBytes::new(Scalar::from(value).to_bytes().into()))
            .expect("nonzero key share")
    }

    fn wallet_public_key() -> CompressedPointBytes {
        let point = (ProjectivePoint::GENERATOR * Scalar::from(18u64)).to_affine();
        let encoded = k256::elliptic_curve::sec1::ToEncodedPoint::to_encoded_point(&point, true);
        CompressedPointBytes::new(
            encoded
                .as_bytes()
                .try_into()
                .expect("compressed point width"),
        )
    }

    fn exchange(
        client: &mut ClientPresignSession,
        worker: &mut SigningWorkerPresignSession,
        client_rng: &mut ChaCha20Rng,
        worker_rng: &mut ChaCha20Rng,
    ) {
        let client_messages = client.poll().outgoing;
        let worker_messages = worker.poll().outgoing;
        assert_eq!(client_messages.len(), 1);
        assert_eq!(worker_messages.len(), 1);
        client
            .message(&worker_messages[0], client_rng)
            .expect("client accepts peer round");
        worker
            .message(&client_messages[0], worker_rng)
            .expect("worker accepts peer round");
    }

    #[test]
    fn fixed_sessions_preserve_the_existing_pause_and_output_shape() {
        let mut client_rng = ChaCha20Rng::from_seed([0x71; 32]);
        let mut worker_rng = ChaCha20Rng::from_seed([0x72; 32]);
        let key = wallet_public_key();
        let context = derive_presign_pair_context(key, "presign-session-1").expect("context");
        let mut client =
            ClientPresignSession::new(context, key_share(7), key, &mut client_rng).expect("client");
        let mut worker =
            SigningWorkerPresignSession::new(context, key_share(11), key, &mut worker_rng)
                .expect("worker");

        for _ in 0..9 {
            exchange(&mut client, &mut worker, &mut client_rng, &mut worker_rng);
        }
        assert_eq!(client.stage(), PresignSessionStage::TriplesDone);
        assert_eq!(worker.stage(), PresignSessionStage::TriplesDone);
        assert_eq!(client.poll().event, PresignSessionEvent::TriplesDone);
        assert_eq!(worker.poll().event, PresignSessionEvent::TriplesDone);

        client.start_presign().expect("start client presign");
        worker.start_presign().expect("start worker presign");
        exchange(&mut client, &mut worker, &mut client_rng, &mut worker_rng);
        exchange(&mut client, &mut worker, &mut client_rng, &mut worker_rng);

        assert_eq!(client.stage(), PresignSessionStage::Done);
        assert_eq!(worker.stage(), PresignSessionStage::Done);
        assert_eq!(client.poll().event, PresignSessionEvent::PresignDone);
        assert_eq!(worker.poll().event, PresignSessionEvent::PresignDone);
        let client_output = client.take_presignature_97().expect("client output");
        let worker_output = worker.take_presignature_97().expect("worker output");
        assert_eq!(client_output.len(), PRESIGNATURE_SIZE);
        assert_eq!(worker_output.len(), PRESIGNATURE_SIZE);
        assert_eq!(
            &client_output[..COMPRESSED_POINT_SIZE],
            &worker_output[..COMPRESSED_POINT_SIZE]
        );
        assert_eq!(
            client.take_presignature_97(),
            Err(PresignSessionError::OutputUnavailable)
        );
    }

    #[test]
    fn pair_context_binds_session_id_and_group_key() {
        let key = wallet_public_key();
        let first = derive_presign_pair_context(key, "pair-a").expect("first");
        let second = derive_presign_pair_context(key, "pair-b").expect("second");
        assert_eq!(first.signing_scope(), second.signing_scope());
        assert_ne!(first.pair(), second.pair());
        assert_eq!(
            derive_presign_pair_context(key, ""),
            Err(PresignSessionError::EmptySessionId)
        );
    }
}
