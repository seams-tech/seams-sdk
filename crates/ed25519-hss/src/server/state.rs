use serde::{Deserialize, Serialize};

use crate::ddh::ddh_hss::DdhHssPreparedOtSenderStateWord;
use crate::ddh::{DdhHssGarbler, DdhHssOtRemoteBundle, DdhHssOtSenderStateBundle};
use crate::runtime::SharedRuntimeState;
use crate::wire::ClientOtOffer;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerOtState {
    pub context_binding: [u8; 32],
    pub y_client_remote: DdhHssOtRemoteBundle,
    pub tau_client_remote: DdhHssOtRemoteBundle,
    pub y_client_sender_state: DdhHssOtSenderStateBundle,
    pub tau_client_sender_state: DdhHssOtSenderStateBundle,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerSession {
    pub(crate) context_binding: [u8; 32],
    pub(crate) ddh_garbler: DdhHssGarbler,
    pub(crate) client_ot_offer: ClientOtOffer,
    pub(crate) garbler_ot_state: ServerOtState,
    pub(crate) y_client_sender_words_prepared: Vec<DdhHssPreparedOtSenderStateWord>,
    pub(crate) tau_client_sender_words_prepared: Vec<DdhHssPreparedOtSenderStateWord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerSessionState {
    pub context_binding: [u8; 32],
    pub ddh_garbler: DdhHssGarbler,
    pub client_ot_offer: ClientOtOffer,
    pub garbler_ot_state: ServerOtState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerDriverState {
    pub runtime: SharedRuntimeState,
    pub garbler_session: ServerSessionState,
}
