//! Verification entrypoint for the frozen `encode_context` shape.
//!
//! Planned proof targets:
//! - deterministic field order
//! - fixed participant layout `{client=1, relayer=2}`
//! - byte-level anti-drift against the production encoder

use vstd::prelude::*;

verus! {

#[derive(Debug, PartialEq, Eq)]
pub struct CanonicalContext {
    pub scheme_id: String,
    pub curve: String,
    pub application_binding_digest: Vec<u8>,
    pub participant_ids: Vec<u16>,
}

pub open spec fn client_participant_id_spec() -> u16 {
    1u16
}

pub open spec fn relayer_participant_id_spec() -> u16 {
    2u16
}

pub open spec fn has_fixed_participant_layout_spec(context: CanonicalContext) -> bool {
    context.participant_ids.len() == 2
        && context.participant_ids[0] == client_participant_id_spec()
        && context.participant_ids[1] == relayer_participant_id_spec()
}

pub uninterp spec fn ascii_bytes_spec(value: String) -> Seq<u8>;

pub open spec fn domain_tag_spec() -> Seq<u8> {
    seq![
        101u8, 99u8, 100u8, 115u8, 97u8, 45u8, 104u8, 115u8, 115u8, 58u8,
        99u8, 111u8, 110u8, 116u8, 101u8, 120u8, 116u8, 58u8, 118u8, 52u8
    ]
}

pub open spec fn participant_id_bytes_spec() -> Seq<u8> {
    seq![2u8, 0u8, 1u8, 0u8, 2u8]
}

pub open spec fn u16be_bytes_spec(len: nat) -> Seq<u8>
    recommends len <= 0xffff,
{
    seq![((len / 256) as u8), ((len % 256) as u8)]
}

pub open spec fn encoded_ascii_field_spec(value: String) -> Seq<u8> {
    let bytes = ascii_bytes_spec(value);
    u16be_bytes_spec(bytes.len() as nat) + bytes
}

pub uninterp spec fn digest_bytes_spec(value: Vec<u8>) -> Seq<u8>;

pub open spec fn encode_context_spec(context: CanonicalContext) -> Seq<u8> {
    domain_tag_spec()
        + encoded_ascii_field_spec(context.scheme_id)
        + encoded_ascii_field_spec(context.curve)
        + digest_bytes_spec(context.application_binding_digest)
        + participant_id_bytes_spec()
}

pub proof fn encode_context_has_fixed_field_order(context: CanonicalContext)
    ensures
        encode_context_spec(context)
            == domain_tag_spec()
                + encoded_ascii_field_spec(context.scheme_id)
                + encoded_ascii_field_spec(context.curve)
                + digest_bytes_spec(context.application_binding_digest)
                + participant_id_bytes_spec(),
{
}

pub proof fn encode_context_is_deterministic(
    left: CanonicalContext,
    right: CanonicalContext,
)
    requires
        left == right,
    ensures
        encode_context_spec(left) == encode_context_spec(right),
{
}

pub proof fn fixed_participant_layout_is_client_then_relayer(context: CanonicalContext)
    requires
        has_fixed_participant_layout_spec(context),
    ensures
        context.participant_ids[0] == 1u16,
        context.participant_ids[1] == 2u16,
{
}

pub proof fn participant_id_bytes_are_fixed()
    ensures
        participant_id_bytes_spec() == seq![2u8, 0u8, 1u8, 0u8, 2u8],
        participant_id_bytes_spec().len() == 5,
{
}

}
