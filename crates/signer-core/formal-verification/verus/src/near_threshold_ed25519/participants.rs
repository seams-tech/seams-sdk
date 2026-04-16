//! Verus model for threshold Ed25519 participant-ID normalization and 2P validation.

use vstd::prelude::*;

verus! {

#[derive(Debug, PartialEq, Eq)]
pub struct ParticipantPairV1 {
    pub client_id: u16,
    pub relayer_id: u16,
}

pub open spec fn default_client_participant_id_v1_spec() -> u16 {
    1u16
}

pub open spec fn default_relayer_participant_id_v1_spec() -> u16 {
    2u16
}

pub open spec fn contains_participant_id_v1_spec(ids: Seq<u16>, id: u16) -> bool {
    exists|idx: int| 0 <= idx < ids.len() && ids[idx] == id
}

pub open spec fn normalized_participant_ids_v1_spec(ids: Seq<u16>) -> bool {
    &&& forall|idx: int| 0 <= idx < ids.len() ==> ids[idx] > 0
    &&& forall|left: int, right: int|
            0 <= left < right < ids.len() ==> ids[left] < ids[right]
}

pub uninterp spec fn normalize_participant_ids_v1_spec(raw_ids: Seq<u16>) -> Seq<u16>;

pub broadcast axiom fn axiom_normalize_participant_ids_outputs_normalized_v1(raw_ids: Seq<u16>)
    ensures
        #![trigger normalize_participant_ids_v1_spec(raw_ids)]
        normalized_participant_ids_v1_spec(normalize_participant_ids_v1_spec(raw_ids)),
;

pub open spec fn validate_threshold_ed25519_participant_ids_2p_v1_spec(
    client_id_opt: Option<u16>,
    relayer_id_opt: Option<u16>,
    participant_ids_norm: Seq<u16>,
) -> Option<ParticipantPairV1> {
    match (client_id_opt, relayer_id_opt) {
        (Some(client_id), Some(relayer_id)) => {
            if client_id == relayer_id {
                None
            } else if participant_ids_norm.len() == 0 {
                Some(ParticipantPairV1 { client_id, relayer_id })
            } else if participant_ids_norm.len() < 2 {
                None
            } else if !contains_participant_id_v1_spec(participant_ids_norm, client_id)
                || !contains_participant_id_v1_spec(participant_ids_norm, relayer_id)
            {
                None
            } else {
                Some(ParticipantPairV1 { client_id, relayer_id })
            }
        },
        (None, None) => {
            if participant_ids_norm.len() == 0 {
                Some(ParticipantPairV1 {
                    client_id: default_client_participant_id_v1_spec(),
                    relayer_id: default_relayer_participant_id_v1_spec(),
                })
            } else if participant_ids_norm.len() == 2 {
                Some(ParticipantPairV1 {
                    client_id: participant_ids_norm[0],
                    relayer_id: participant_ids_norm[1],
                })
            } else {
                None
            }
        },
        _ => None,
    }
}

pub proof fn normalized_participant_ids_exclude_zero_v1(ids: Seq<u16>, idx: int)
    requires
        normalized_participant_ids_v1_spec(ids),
        0 <= idx < ids.len(),
    ensures
        ids[idx] > 0,
{
}

pub proof fn normalized_participant_ids_are_strictly_increasing_v1(
    ids: Seq<u16>,
    left: int,
    right: int,
)
    requires
        normalized_participant_ids_v1_spec(ids),
        0 <= left < right < ids.len(),
    ensures
        ids[left] < ids[right],
        ids[left] != ids[right],
{
}

pub proof fn normalized_participant_ids_are_unique_v1(ids: Seq<u16>, left: int, right: int)
    requires
        normalized_participant_ids_v1_spec(ids),
        0 <= left < ids.len(),
        0 <= right < ids.len(),
        left != right,
    ensures
        ids[left] != ids[right],
{
    if left < right {
        normalized_participant_ids_are_strictly_increasing_v1(ids, left, right);
    } else {
        normalized_participant_ids_are_strictly_increasing_v1(ids, right, left);
    }
}

pub proof fn normalized_output_is_normalized_v1(raw_ids: Seq<u16>)
    ensures
        normalized_participant_ids_v1_spec(normalize_participant_ids_v1_spec(raw_ids)),
{
    broadcast use axiom_normalize_participant_ids_outputs_normalized_v1;
}

pub proof fn default_empty_ids_select_1_2_v1()
    ensures
        validate_threshold_ed25519_participant_ids_2p_v1_spec(None, None, Seq::<u16>::empty())
            == Some(ParticipantPairV1 {
                client_id: default_client_participant_id_v1_spec(),
                relayer_id: default_relayer_participant_id_v1_spec(),
            }),
{
}

pub proof fn partial_explicit_ids_are_rejected_v1(
    client_id: u16,
    relayer_id: u16,
    participant_ids_norm: Seq<u16>,
)
    ensures
        validate_threshold_ed25519_participant_ids_2p_v1_spec(
            Some(client_id),
            None,
            participant_ids_norm,
        ).is_none(),
        validate_threshold_ed25519_participant_ids_2p_v1_spec(
            None,
            Some(relayer_id),
            participant_ids_norm,
        ).is_none(),
{
}

pub proof fn duplicate_explicit_ids_are_rejected_v1(
    participant_id: u16,
    participant_ids_norm: Seq<u16>,
)
    ensures
        validate_threshold_ed25519_participant_ids_2p_v1_spec(
            Some(participant_id),
            Some(participant_id),
            participant_ids_norm,
        ).is_none(),
{
}

pub proof fn explicit_ids_with_empty_list_are_accepted_when_distinct_v1(
    client_id: u16,
    relayer_id: u16,
)
    requires
        client_id != relayer_id,
    ensures
        validate_threshold_ed25519_participant_ids_2p_v1_spec(
            Some(client_id),
            Some(relayer_id),
            Seq::<u16>::empty(),
        ) == Some(ParticipantPairV1 { client_id, relayer_id }),
{
}

pub proof fn explicit_ids_missing_from_nonempty_list_are_rejected_v1(
    client_id: u16,
    relayer_id: u16,
    participant_ids_norm: Seq<u16>,
)
    requires
        client_id != relayer_id,
        participant_ids_norm.len() >= 2,
        !contains_participant_id_v1_spec(participant_ids_norm, client_id)
            || !contains_participant_id_v1_spec(participant_ids_norm, relayer_id),
    ensures
        validate_threshold_ed25519_participant_ids_2p_v1_spec(
            Some(client_id),
            Some(relayer_id),
            participant_ids_norm,
        ).is_none(),
{
}

pub proof fn explicit_ids_present_in_nonempty_list_are_accepted_v1(
    client_id: u16,
    relayer_id: u16,
    participant_ids_norm: Seq<u16>,
)
    requires
        client_id != relayer_id,
        participant_ids_norm.len() >= 2,
        contains_participant_id_v1_spec(participant_ids_norm, client_id),
        contains_participant_id_v1_spec(participant_ids_norm, relayer_id),
    ensures
        validate_threshold_ed25519_participant_ids_2p_v1_spec(
            Some(client_id),
            Some(relayer_id),
            participant_ids_norm,
        ) == Some(ParticipantPairV1 { client_id, relayer_id }),
{
}

pub proof fn inferred_single_id_list_is_rejected_v1(id: u16)
    ensures
        validate_threshold_ed25519_participant_ids_2p_v1_spec(None, None, seq![id]).is_none(),
{
}

pub proof fn inferred_two_id_list_selects_sorted_pair_v1(first: u16, second: u16)
    ensures
        validate_threshold_ed25519_participant_ids_2p_v1_spec(None, None, seq![first, second])
            == Some(ParticipantPairV1 { client_id: first, relayer_id: second }),
{
}

pub proof fn inferred_more_than_two_ids_are_rejected_v1(ids: Seq<u16>)
    requires
        ids.len() > 2,
    ensures
        validate_threshold_ed25519_participant_ids_2p_v1_spec(None, None, ids).is_none(),
{
}

}
