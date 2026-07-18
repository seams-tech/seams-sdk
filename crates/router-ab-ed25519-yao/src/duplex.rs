//! Transport-neutral driver for the fixed Ed25519 Yao role machines.

use std::collections::VecDeque;
use std::fmt;

use crate::relay::{
    ActivationDeriverACompletion, ActivationDeriverBCompletion, BenchmarkRoleError,
    DirectionalEofEvidence, ExportDeriverACompletion, ExportDeriverBCompletion, RelayEvent,
    RelayInstruction, RelayStep, WireMessage, WireMessageKind,
};
use crate::{ActivationDeriverA, ActivationDeriverB, ExportDeriverA, ExportDeriverB};

/// One inbound protocol event normalized by a duplex transport adapter.
pub enum YaoInboundEvent {
    /// One decoded protocol message.
    Message(WireMessage),
    /// Authenticated directional EOF evidence.
    DirectionalEof(DirectionalEofEvidence),
}

/// Completion returned by a transport after both protocol directions close.
pub trait YaoTransportCompletion {}

impl YaoTransportCompletion for () {}

/// Minimal duplex contract consumed by the fixed role driver.
///
/// HTTP streams, WebSockets, native streams, and local sockets implement this
/// boundary without changing the role machine.
#[allow(async_fn_in_trait)]
pub trait YaoDuplexTransport: Sized {
    /// Transport-specific recoverable failure.
    type Error;
    /// Transport evidence returned after clean protocol completion.
    type Completion: YaoTransportCompletion;

    /// Sends one complete protocol message.
    ///
    /// A transport that must poll both directions while applying backpressure
    /// may return the one peer event observed during the send.
    async fn send(&mut self, message: WireMessage) -> Result<Option<YaoInboundEvent>, Self::Error>;

    /// Receives one complete peer message or directional EOF.
    async fn receive(&mut self) -> Result<YaoInboundEvent, Self::Error>;

    /// Closes the local direction and returns its exact EOF evidence.
    ///
    /// A transport that must poll both directions while closing may return the
    /// one peer event observed during the close.
    async fn close_local_direction(
        &mut self,
    ) -> Result<(DirectionalEofEvidence, Option<YaoInboundEvent>), Self::Error>;

    /// Completes transport teardown after the role machine has finished.
    async fn finish(self) -> Result<Self::Completion, Self::Error>;
}

/// Successful fixed-role execution and transport teardown.
pub struct YaoRoleCompletion<RoleCompletion, TransportCompletion> {
    /// Cryptographic role completion.
    pub role: RoleCompletion,
    /// Transport-specific close evidence and metrics.
    pub transport: TransportCompletion,
}

/// Failure from the fixed role driver.
#[derive(Debug)]
pub enum YaoRoleDriverError<TransportError> {
    /// The role machine or transport event violated the fixed protocol.
    Protocol(&'static str),
    /// The selected transport failed.
    Transport(TransportError),
}

impl<TransportError: fmt::Display> fmt::Display for YaoRoleDriverError<TransportError> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(stage) => {
                write!(formatter, "fixed Ed25519 Yao role protocol failed at {stage}")
            }
            Self::Transport(error) => {
                write!(formatter, "Ed25519 Yao duplex transport failed: {error}")
            }
        }
    }
}

impl<TransportError> From<BenchmarkRoleError> for YaoRoleDriverError<TransportError> {
    fn from(_: BenchmarkRoleError) -> Self {
        Self::Protocol("role_machine")
    }
}

trait FixedYaoRole: Sized {
    type Completion;

    fn instruction(&self) -> Result<RelayInstruction, BenchmarkRoleError>;

    fn handle(
        self,
        event: RelayEvent,
    ) -> Result<RelayStep<Self, Self::Completion>, BenchmarkRoleError>;
}

macro_rules! implement_fixed_role {
    ($role:ty, $completion:ty) => {
        impl FixedYaoRole for $role {
            type Completion = $completion;

            fn instruction(&self) -> Result<RelayInstruction, BenchmarkRoleError> {
                <$role>::instruction(self)
            }

            fn handle(
                self,
                event: RelayEvent,
            ) -> Result<RelayStep<Self, Self::Completion>, BenchmarkRoleError> {
                <$role>::handle(self, event)
            }
        }
    };
}

implement_fixed_role!(ActivationDeriverA, ActivationDeriverACompletion);
implement_fixed_role!(ActivationDeriverB, ActivationDeriverBCompletion);
implement_fixed_role!(ExportDeriverA, ExportDeriverACompletion);
implement_fixed_role!(ExportDeriverB, ExportDeriverBCompletion);

/// Runs the fixed activation Deriver A role over one selected duplex transport.
pub async fn run_activation_deriver_a<T: YaoDuplexTransport>(
    role: ActivationDeriverA,
    transport: T,
) -> Result<
    YaoRoleCompletion<ActivationDeriverACompletion, T::Completion>,
    YaoRoleDriverError<T::Error>,
> {
    run_role(role, transport).await
}

/// Runs the fixed export Deriver A role over one selected duplex transport.
pub async fn run_export_deriver_a<T: YaoDuplexTransport>(
    role: ExportDeriverA,
    transport: T,
) -> Result<YaoRoleCompletion<ExportDeriverACompletion, T::Completion>, YaoRoleDriverError<T::Error>>
{
    run_role(role, transport).await
}

/// Runs the fixed activation Deriver B role over one selected duplex transport.
pub async fn run_activation_deriver_b<T: YaoDuplexTransport>(
    role: ActivationDeriverB,
    transport: T,
) -> Result<
    YaoRoleCompletion<ActivationDeriverBCompletion, T::Completion>,
    YaoRoleDriverError<T::Error>,
> {
    run_role(role, transport).await
}

/// Runs the fixed export Deriver B role over one selected duplex transport.
pub async fn run_export_deriver_b<T: YaoDuplexTransport>(
    role: ExportDeriverB,
    transport: T,
) -> Result<YaoRoleCompletion<ExportDeriverBCompletion, T::Completion>, YaoRoleDriverError<T::Error>>
{
    run_role(role, transport).await
}

async fn run_role<R, T>(
    mut role: R,
    mut transport: T,
) -> Result<YaoRoleCompletion<R::Completion, T::Completion>, YaoRoleDriverError<T::Error>>
where
    R: FixedYaoRole,
    T: YaoDuplexTransport,
{
    let mut deferred = VecDeque::with_capacity(1);
    loop {
        match role
            .instruction()
            .map_err(|_| YaoRoleDriverError::Protocol("instruction"))?
        {
            RelayInstruction::Advance => match role
                .handle(RelayEvent::Advance)
                .map_err(|_| YaoRoleDriverError::Protocol("advance"))?
            {
                RelayStep::Continue(next) => role = next,
                RelayStep::Send {
                    role: next,
                    message,
                } => {
                    if let Some(event) = transport
                        .send(message)
                        .await
                        .map_err(YaoRoleDriverError::Transport)?
                    {
                        push_deferred(&mut deferred, event)?;
                    }
                    role = next;
                }
                RelayStep::Complete(_) => {
                    return Err(YaoRoleDriverError::Protocol("advance_completion"))
                }
            },
            RelayInstruction::Receive {
                kind,
                payload_bytes,
            } => {
                let event = next_event(&mut deferred, &mut transport).await?;
                let YaoInboundEvent::Message(message) = event else {
                    return Err(YaoRoleDriverError::Protocol("expected_message"));
                };
                validate_message(&message, kind, payload_bytes)?;
                match role
                    .handle(RelayEvent::Inbound(message))
                    .map_err(|_| YaoRoleDriverError::Protocol("inbound_message"))?
                {
                    RelayStep::Continue(next) => role = next,
                    RelayStep::Send {
                        role: next,
                        message,
                    } => {
                        if let Some(event) = transport
                            .send(message)
                            .await
                            .map_err(YaoRoleDriverError::Transport)?
                        {
                            push_deferred(&mut deferred, event)?;
                        }
                        role = next;
                    }
                    RelayStep::Complete(_) => {
                        return Err(YaoRoleDriverError::Protocol("inbound_completion"))
                    }
                }
            }
            RelayInstruction::CloseLocalDirection { terminal_kind: _ } => {
                let (evidence, event) = transport
                    .close_local_direction()
                    .await
                    .map_err(YaoRoleDriverError::Transport)?;
                if let Some(event) = event {
                    push_deferred(&mut deferred, event)?;
                }
                match role
                    .handle(RelayEvent::LocalDirectionalEof(evidence))
                    .map_err(|_| YaoRoleDriverError::Protocol("local_directional_eof"))?
                {
                    RelayStep::Continue(next) => role = next,
                    RelayStep::Complete(completion) => {
                        let transport = transport
                            .finish()
                            .await
                            .map_err(YaoRoleDriverError::Transport)?;
                        return Ok(YaoRoleCompletion {
                            role: completion,
                            transport,
                        });
                    }
                    RelayStep::Send { .. } => {
                        return Err(YaoRoleDriverError::Protocol("send_after_local_eof"))
                    }
                }
            }
            RelayInstruction::ObservePeerEof { terminal_kind: _ } => {
                let event = next_event(&mut deferred, &mut transport).await?;
                let YaoInboundEvent::DirectionalEof(evidence) = event else {
                    return Err(YaoRoleDriverError::Protocol("expected_peer_eof"));
                };
                match role
                    .handle(RelayEvent::InboundDirectionalEof(evidence))
                    .map_err(|_| YaoRoleDriverError::Protocol("peer_directional_eof"))?
                {
                    RelayStep::Continue(next) => role = next,
                    RelayStep::Complete(completion) => {
                        let transport = transport
                            .finish()
                            .await
                            .map_err(YaoRoleDriverError::Transport)?;
                        return Ok(YaoRoleCompletion {
                            role: completion,
                            transport,
                        });
                    }
                    RelayStep::Send { .. } => {
                        return Err(YaoRoleDriverError::Protocol("send_after_peer_eof"))
                    }
                }
            }
        }
    }
}

async fn next_event<T: YaoDuplexTransport>(
    deferred: &mut VecDeque<YaoInboundEvent>,
    transport: &mut T,
) -> Result<YaoInboundEvent, YaoRoleDriverError<T::Error>> {
    if let Some(event) = deferred.pop_front() {
        return Ok(event);
    }
    transport
        .receive()
        .await
        .map_err(YaoRoleDriverError::Transport)
}

fn push_deferred<E>(
    deferred: &mut VecDeque<YaoInboundEvent>,
    event: YaoInboundEvent,
) -> Result<(), YaoRoleDriverError<E>> {
    if !deferred.is_empty() {
        return Err(YaoRoleDriverError::Protocol("deferred_event_overflow"));
    }
    deferred.push_back(event);
    Ok(())
}

fn validate_message<E>(
    message: &WireMessage,
    expected_kind: WireMessageKind,
    expected_payload_bytes: usize,
) -> Result<(), YaoRoleDriverError<E>> {
    if message.kind() != expected_kind || message.as_bytes().len() != expected_payload_bytes {
        return Err(YaoRoleDriverError::Protocol("message_shape"));
    }
    Ok(())
}
