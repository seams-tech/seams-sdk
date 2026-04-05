use crate::client::state::ClientOfferCommitments;
use crate::client::ClientOtState;
use crate::ddh::{DdhHssEvaluator, HiddenEvalInputOwner};
use crate::shared::{ProtoError, ProtoResult};
use crate::wire::{ClientOtOffer, ClientPacket};

pub(crate) fn validate_client_ot_offer(
    context_binding: [u8; 32],
    offer: &ClientOtOffer,
) -> ProtoResult<()> {
    if offer.context_binding != context_binding {
        return Err(ProtoError::InvalidInput(
            "client OT offer context binding does not match evaluator session".to_string(),
        ));
    }
    Ok(())
}

pub(crate) fn build_client_ot_request(
    ddh_evaluator: &DdhHssEvaluator,
    context_binding: [u8; 32],
    offer: &ClientOtOffer,
    y_client: [u8; 32],
    tau_client: [u8; 32],
) -> ProtoResult<(ClientPacket, ClientOtState)> {
    validate_client_ot_offer(context_binding, offer)?;
    let (y_client_request, y_client_local_state) =
        ddh_evaluator.prepare_client_input_ot_request(&offer.y_client_offer, &y_client)?;
    let (tau_client_request, tau_client_local_state) =
        ddh_evaluator.prepare_client_input_ot_request(&offer.tau_client_offer, &tau_client)?;
    let client_packet = ClientPacket {
        context_binding,
        y_client_request,
        tau_client_request,
    };
    Ok((
        client_packet,
        ClientOtState {
            context_binding,
            offer_commitments: ClientOfferCommitments {
                y_client_offer_commitment: offer.y_client_offer.commitment,
                tau_client_offer_commitment: offer.tau_client_offer.commitment,
            },
            y_client_local_state,
            tau_client_local_state,
        },
    ))
}

pub(crate) fn validate_evaluator_ot_state(
    context_binding: [u8; 32],
    evaluator_ot_state: &ClientOtState,
) -> ProtoResult<()> {
    if evaluator_ot_state.context_binding != context_binding {
        return Err(ProtoError::InvalidInput(
            "evaluator OT state context binding does not match evaluator session".to_string(),
        ));
    }
    if evaluator_ot_state.y_client_local_state.owner != HiddenEvalInputOwner::Client
        || evaluator_ot_state.tau_client_local_state.owner != HiddenEvalInputOwner::Client
    {
        return Err(ProtoError::InvalidInput(
            "evaluator OT state must be client-owned".to_string(),
        ));
    }
    if evaluator_ot_state.y_client_local_state.label != "y_client_bits"
        || evaluator_ot_state.tau_client_local_state.label != "tau_client_bits"
    {
        return Err(ProtoError::InvalidInput(
            "evaluator OT state labels are invalid".to_string(),
        ));
    }
    if evaluator_ot_state.y_client_local_state.words.len() != 256
        || evaluator_ot_state.tau_client_local_state.words.len() != 256
    {
        return Err(ProtoError::InvalidInput(
            "evaluator OT state must contain 256 bits".to_string(),
        ));
    }
    Ok(())
}
