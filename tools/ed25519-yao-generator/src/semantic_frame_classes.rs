//! Construction-independent semantic frame classes.
//!
//! A class fixes both endpoints. The module intentionally carries no encoding,
//! transport, sequencing, authentication, or selected-construction data.

/// Endpoint named by a semantic frame class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostOnlySemanticFrameEndpointV1 {
    /// The requesting Client.
    Client,
    /// The strict Router.
    Router,
    /// Deriver A.
    DeriverA,
    /// Deriver B.
    DeriverB,
    /// The isolated signing worker.
    SigningWorker,
}

/// Direction derived from a closed semantic frame class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostOnlySemanticFrameDirectionV1 {
    sender: HostOnlySemanticFrameEndpointV1,
    receiver: HostOnlySemanticFrameEndpointV1,
}

impl HostOnlySemanticFrameDirectionV1 {
    /// Returns the endpoint that originates the semantic frame.
    pub const fn sender(self) -> HostOnlySemanticFrameEndpointV1 {
        self.sender
    }

    /// Returns the endpoint that consumes the semantic frame.
    pub const fn receiver(self) -> HostOnlySemanticFrameEndpointV1 {
        self.receiver
    }
}

/// Exactly eleven construction-independent directed semantic frame classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostOnlySemanticFrameClassV1 {
    /// Client submits an evaluation request to Router.
    ClientToRouterEvaluationRequest,
    /// Router consumes activation control locally.
    RouterLocalActivationControl,
    /// Router delivers the accepted private-input custody to Deriver A.
    RouterToDeriverAInputDelivery,
    /// Router delivers the accepted private-input custody to Deriver B.
    RouterToDeriverBInputDelivery,
    /// Deriver A sends one opaque selected-protocol observation to Deriver B.
    DeriverAToDeriverBPeerProtocol,
    /// Deriver B sends one opaque selected-protocol observation to Deriver A.
    DeriverBToDeriverAPeerProtocol,
    /// Deriver A returns its output packages to Router.
    DeriverAToRouterOutputPackages,
    /// Deriver B returns its output packages to Router.
    DeriverBToRouterOutputPackages,
    /// Router delivers the authorized Client recipient capability.
    RouterToClientRecipientDelivery,
    /// Router delivers the activation authority to SigningWorker.
    RouterToSigningWorkerRecipientDelivery,
    /// SigningWorker returns the verified activation receipt to Router.
    SigningWorkerToRouterActivationReceipt,
}

/// Frozen frame-class order consumed by the strict semantic corpus.
pub const HOST_ONLY_SEMANTIC_FRAME_CLASSES_V1: [HostOnlySemanticFrameClassV1; 11] = [
    HostOnlySemanticFrameClassV1::ClientToRouterEvaluationRequest,
    HostOnlySemanticFrameClassV1::RouterLocalActivationControl,
    HostOnlySemanticFrameClassV1::RouterToDeriverAInputDelivery,
    HostOnlySemanticFrameClassV1::RouterToDeriverBInputDelivery,
    HostOnlySemanticFrameClassV1::DeriverAToDeriverBPeerProtocol,
    HostOnlySemanticFrameClassV1::DeriverBToDeriverAPeerProtocol,
    HostOnlySemanticFrameClassV1::DeriverAToRouterOutputPackages,
    HostOnlySemanticFrameClassV1::DeriverBToRouterOutputPackages,
    HostOnlySemanticFrameClassV1::RouterToClientRecipientDelivery,
    HostOnlySemanticFrameClassV1::RouterToSigningWorkerRecipientDelivery,
    HostOnlySemanticFrameClassV1::SigningWorkerToRouterActivationReceipt,
];

impl HostOnlySemanticFrameClassV1 {
    /// Returns the endpoints fixed by this class.
    pub const fn direction(self) -> HostOnlySemanticFrameDirectionV1 {
        let (sender, receiver) = match self {
            Self::ClientToRouterEvaluationRequest => (
                HostOnlySemanticFrameEndpointV1::Client,
                HostOnlySemanticFrameEndpointV1::Router,
            ),
            Self::RouterLocalActivationControl => (
                HostOnlySemanticFrameEndpointV1::Router,
                HostOnlySemanticFrameEndpointV1::Router,
            ),
            Self::RouterToDeriverAInputDelivery => (
                HostOnlySemanticFrameEndpointV1::Router,
                HostOnlySemanticFrameEndpointV1::DeriverA,
            ),
            Self::RouterToDeriverBInputDelivery => (
                HostOnlySemanticFrameEndpointV1::Router,
                HostOnlySemanticFrameEndpointV1::DeriverB,
            ),
            Self::DeriverAToDeriverBPeerProtocol => (
                HostOnlySemanticFrameEndpointV1::DeriverA,
                HostOnlySemanticFrameEndpointV1::DeriverB,
            ),
            Self::DeriverBToDeriverAPeerProtocol => (
                HostOnlySemanticFrameEndpointV1::DeriverB,
                HostOnlySemanticFrameEndpointV1::DeriverA,
            ),
            Self::DeriverAToRouterOutputPackages => (
                HostOnlySemanticFrameEndpointV1::DeriverA,
                HostOnlySemanticFrameEndpointV1::Router,
            ),
            Self::DeriverBToRouterOutputPackages => (
                HostOnlySemanticFrameEndpointV1::DeriverB,
                HostOnlySemanticFrameEndpointV1::Router,
            ),
            Self::RouterToClientRecipientDelivery => (
                HostOnlySemanticFrameEndpointV1::Router,
                HostOnlySemanticFrameEndpointV1::Client,
            ),
            Self::RouterToSigningWorkerRecipientDelivery => (
                HostOnlySemanticFrameEndpointV1::Router,
                HostOnlySemanticFrameEndpointV1::SigningWorker,
            ),
            Self::SigningWorkerToRouterActivationReceipt => (
                HostOnlySemanticFrameEndpointV1::SigningWorker,
                HostOnlySemanticFrameEndpointV1::Router,
            ),
        };
        HostOnlySemanticFrameDirectionV1 { sender, receiver }
    }

    /// Returns the frozen source label used by semantic fixtures.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ClientToRouterEvaluationRequest => "client_to_router_evaluation_request",
            Self::RouterLocalActivationControl => "router_local_activation_control",
            Self::RouterToDeriverAInputDelivery => "router_to_deriver_a_input_delivery",
            Self::RouterToDeriverBInputDelivery => "router_to_deriver_b_input_delivery",
            Self::DeriverAToDeriverBPeerProtocol => "deriver_a_to_deriver_b_peer_protocol",
            Self::DeriverBToDeriverAPeerProtocol => "deriver_b_to_deriver_a_peer_protocol",
            Self::DeriverAToRouterOutputPackages => "deriver_a_to_router_output_packages",
            Self::DeriverBToRouterOutputPackages => "deriver_b_to_router_output_packages",
            Self::RouterToClientRecipientDelivery => "router_to_client_recipient_delivery",
            Self::RouterToSigningWorkerRecipientDelivery => {
                "router_to_signing_worker_recipient_delivery"
            }
            Self::SigningWorkerToRouterActivationReceipt => {
                "signing_worker_to_router_activation_receipt"
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_eleven_classes_have_fixed_directions_and_labels() {
        let cases = HOST_ONLY_SEMANTIC_FRAME_CLASSES_V1;
        assert_eq!(cases.len(), 11);
        for class in cases {
            assert!(!class.as_str().is_empty());
            let direction = class.direction();
            if class == HostOnlySemanticFrameClassV1::RouterLocalActivationControl {
                assert_eq!(direction.sender(), direction.receiver());
            } else {
                assert_ne!(direction.sender(), direction.receiver());
            }
        }
    }
}
