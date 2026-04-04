use serde::{Deserialize, Serialize};

use crate::ddh::{DdhHssEvaluator, DdhHssOtReceiverStateBundle};
use crate::runtime::SharedRuntimeState;
use crate::wire::ClientOtOffer;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientOtState {
    pub context_binding: [u8; 32],
    pub y_client_local_state: DdhHssOtReceiverStateBundle,
    pub tau_client_local_state: DdhHssOtReceiverStateBundle,
}

#[derive(Clone)]
pub struct ClientSession {
    pub(crate) context_binding: [u8; 32],
    pub(crate) ddh_evaluator: DdhHssEvaluator,
    pub(crate) client_ot_offer: ClientOtOffer,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientSessionState {
    pub context_binding: [u8; 32],
    pub ddh_evaluator: DdhHssEvaluator,
    pub client_ot_offer: ClientOtOffer,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientDriverState {
    pub runtime: SharedRuntimeState,
    pub evaluator_session: ClientSessionState,
}
