use crate::ddh::ddh_hss::{
    prepare_client_ot_sender_state_words_public, DdhHssPreparedOtSenderStateWord,
};
use crate::server::ServerOtState;
use crate::shared::ProtoResult;
use crate::wire::ClientOtOffer;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ServerPreparedOtState {
    pub(crate) y_client_sender_words_prepared: Vec<DdhHssPreparedOtSenderStateWord>,
    pub(crate) tau_client_sender_words_prepared: Vec<DdhHssPreparedOtSenderStateWord>,
}

pub(crate) fn prepare_garbler_ot_state_for_session(
    client_ot_offer: &ClientOtOffer,
    garbler_ot_state: &ServerOtState,
) -> ProtoResult<ServerPreparedOtState> {
    Ok(ServerPreparedOtState {
        y_client_sender_words_prepared: prepare_client_ot_sender_state_words_public(
            &client_ot_offer.y_client_offer,
            &garbler_ot_state.y_client_sender_state,
        )?,
        tau_client_sender_words_prepared: prepare_client_ot_sender_state_words_public(
            &client_ot_offer.tau_client_offer,
            &garbler_ot_state.tau_client_sender_state,
        )?,
    })
}
