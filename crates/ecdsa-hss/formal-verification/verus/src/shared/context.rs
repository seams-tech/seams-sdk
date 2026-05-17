//! Verification entrypoint for the frozen `encode_context_v1` shape.
//!
//! Planned proof targets:
//! - deterministic field order
//! - fixed participant layout `{client=1, relayer=2}`
//! - byte-level anti-drift against the production encoder

use vstd::prelude::*;

verus! {

#[derive(Debug, PartialEq, Eq)]
pub struct CanonicalContextV1 {
    pub scheme_id: String,
    pub curve: String,
    pub wallet_session_user_id: String,
    pub subject_id: String,
    pub chain_target: String,
    pub ecdsa_threshold_key_id: String,
    pub signing_root_id: String,
    pub signing_root_version: String,
    pub key_purpose: String,
    pub key_version: String,
    pub participant_ids: Vec<u16>,
}

pub open spec fn client_participant_id_v1_spec() -> u16 {
    1u16
}

pub open spec fn relayer_participant_id_v1_spec() -> u16 {
    2u16
}

pub open spec fn has_fixed_participant_layout_v1_spec(context: CanonicalContextV1) -> bool {
    context.participant_ids.len() == 2
        && context.participant_ids[0] == client_participant_id_v1_spec()
        && context.participant_ids[1] == relayer_participant_id_v1_spec()
}

pub uninterp spec fn ascii_bytes_v1_spec(value: String) -> Seq<u8>;

pub open spec fn domain_tag_v1_spec() -> Seq<u8> {
    seq![
        101u8, 99u8, 100u8, 115u8, 97u8, 45u8, 104u8, 115u8, 115u8, 58u8,
        99u8, 111u8, 110u8, 116u8, 101u8, 120u8, 116u8, 58u8, 118u8, 49u8
    ]
}

pub open spec fn participant_id_bytes_v1_spec() -> Seq<u8> {
    seq![2u8, 0u8, 1u8, 0u8, 2u8]
}

pub open spec fn key_scope_bytes_v1_spec() -> Seq<u8> {
    seq![101u8, 118u8, 109u8, 45u8, 102u8, 97u8, 109u8, 105u8, 108u8, 121u8]
}

pub open spec fn u16be_bytes_v1_spec(len: nat) -> Seq<u8>
    recommends len <= 0xffff,
{
    seq![((len / 256) as u8), ((len % 256) as u8)]
}

pub open spec fn encoded_ascii_field_v1_spec(value: String) -> Seq<u8> {
    let bytes = ascii_bytes_v1_spec(value);
    u16be_bytes_v1_spec(bytes.len() as nat) + bytes
}

pub open spec fn encoded_key_scope_field_v1_spec() -> Seq<u8> {
    u16be_bytes_v1_spec(10nat) + key_scope_bytes_v1_spec()
}

pub open spec fn encode_context_v1_spec(context: CanonicalContextV1) -> Seq<u8> {
    domain_tag_v1_spec()
        + encoded_ascii_field_v1_spec(context.scheme_id)
        + encoded_ascii_field_v1_spec(context.curve)
        + encoded_ascii_field_v1_spec(context.wallet_session_user_id)
        + encoded_ascii_field_v1_spec(context.subject_id)
        + encoded_key_scope_field_v1_spec()
        + encoded_ascii_field_v1_spec(context.ecdsa_threshold_key_id)
        + encoded_ascii_field_v1_spec(context.signing_root_id)
        + encoded_ascii_field_v1_spec(context.signing_root_version)
        + encoded_ascii_field_v1_spec(context.key_purpose)
        + encoded_ascii_field_v1_spec(context.key_version)
        + participant_id_bytes_v1_spec()
}

pub proof fn encode_context_v1_has_fixed_field_order(context: CanonicalContextV1)
    ensures
        encode_context_v1_spec(context)
            == domain_tag_v1_spec()
                + encoded_ascii_field_v1_spec(context.scheme_id)
                + encoded_ascii_field_v1_spec(context.curve)
                + encoded_ascii_field_v1_spec(context.wallet_session_user_id)
                + encoded_ascii_field_v1_spec(context.subject_id)
                + encoded_key_scope_field_v1_spec()
                + encoded_ascii_field_v1_spec(context.ecdsa_threshold_key_id)
                + encoded_ascii_field_v1_spec(context.signing_root_id)
                + encoded_ascii_field_v1_spec(context.signing_root_version)
                + encoded_ascii_field_v1_spec(context.key_purpose)
                + encoded_ascii_field_v1_spec(context.key_version)
                + participant_id_bytes_v1_spec(),
{
}

pub proof fn encode_context_v1_is_deterministic(
    left: CanonicalContextV1,
    right: CanonicalContextV1,
)
    requires
        left == right,
    ensures
        encode_context_v1_spec(left) == encode_context_v1_spec(right),
{
}

pub proof fn fixed_participant_layout_is_client_then_relayer(context: CanonicalContextV1)
    requires
        has_fixed_participant_layout_v1_spec(context),
    ensures
        context.participant_ids[0] == 1u16,
        context.participant_ids[1] == 2u16,
{
}

pub proof fn encoded_key_scope_field_is_fixed_v1()
    ensures
        key_scope_bytes_v1_spec()
            == seq![101u8, 118u8, 109u8, 45u8, 102u8, 97u8, 109u8, 105u8, 108u8, 121u8],
        encoded_key_scope_field_v1_spec()
            == seq![0u8, 10u8, 101u8, 118u8, 109u8, 45u8, 102u8, 97u8, 109u8, 105u8, 108u8, 121u8],
{
}

pub proof fn participant_id_bytes_are_fixed_v1()
    ensures
        participant_id_bytes_v1_spec() == seq![2u8, 0u8, 1u8, 0u8, 2u8],
        participant_id_bytes_v1_spec().len() == 5,
{
}

}
