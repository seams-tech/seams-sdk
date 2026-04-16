//! Verus model for NEP-413 digest construction shape and nonce-length validation.

use vstd::prelude::*;

#[allow(unused_imports)]
use super::derivation::Bytes32;

verus! {

pub open spec fn nep413_nonce_width_bytes_v1_spec() -> nat {
    32nat
}

pub open spec fn nep413_digest_width_bytes_v1_spec() -> nat {
    32nat
}

pub open spec fn nep413_payload_prefix_le_bytes_v1_spec() -> Seq<u8> {
    seq![157u8, 3u8, 0u8, 128u8]
}

pub uninterp spec fn borsh_nep413_payload_v1_spec(
    message: Seq<u8>,
    recipient: Seq<u8>,
    nonce32: Bytes32,
    state: Option<Seq<u8>>,
) -> Seq<u8>;

pub uninterp spec fn sha256_digest_v1_spec(input: Seq<u8>) -> Bytes32;

pub uninterp spec fn bytes_seq32_to_array_v1_spec(input: Seq<u8>) -> Bytes32;

pub open spec fn nep413_prefixed_payload_v1_spec(
    message: Seq<u8>,
    recipient: Seq<u8>,
    nonce32: Bytes32,
    state: Option<Seq<u8>>,
) -> Seq<u8> {
    nep413_payload_prefix_le_bytes_v1_spec()
        + borsh_nep413_payload_v1_spec(message, recipient, nonce32, state)
}

pub open spec fn compute_nep413_signing_digest_from_nonce_bytes_v1_spec(
    message: Seq<u8>,
    recipient: Seq<u8>,
    nonce32: Bytes32,
    state: Option<Seq<u8>>,
) -> Bytes32 {
    sha256_digest_v1_spec(nep413_prefixed_payload_v1_spec(
        message,
        recipient,
        nonce32,
        state,
    ))
}

pub open spec fn compute_nep413_signing_digest_from_decoded_nonce_v1_spec(
    message: Seq<u8>,
    recipient: Seq<u8>,
    decoded_nonce: Seq<u8>,
    state: Option<Seq<u8>>,
) -> Option<Bytes32> {
    if decoded_nonce.len() == nep413_nonce_width_bytes_v1_spec() {
        Some(compute_nep413_signing_digest_from_nonce_bytes_v1_spec(
            message,
            recipient,
            bytes_seq32_to_array_v1_spec(decoded_nonce),
            state,
        ))
    } else {
        None
    }
}

pub proof fn nep413_prefix_is_fixed_little_endian_v1()
    ensures
        nep413_payload_prefix_le_bytes_v1_spec() == seq![157u8, 3u8, 0u8, 128u8],
        nep413_payload_prefix_le_bytes_v1_spec().len() == 4,
{
}

pub proof fn nep413_digest_from_nonce_bytes_is_deterministic_v1(
    left_message: Seq<u8>,
    left_recipient: Seq<u8>,
    left_nonce32: Bytes32,
    left_state: Option<Seq<u8>>,
    right_message: Seq<u8>,
    right_recipient: Seq<u8>,
    right_nonce32: Bytes32,
    right_state: Option<Seq<u8>>,
)
    requires
        left_message == right_message,
        left_recipient == right_recipient,
        left_nonce32 == right_nonce32,
        left_state == right_state,
    ensures
        compute_nep413_signing_digest_from_nonce_bytes_v1_spec(
            left_message,
            left_recipient,
            left_nonce32,
            left_state,
        ) == compute_nep413_signing_digest_from_nonce_bytes_v1_spec(
            right_message,
            right_recipient,
            right_nonce32,
            right_state,
        ),
{
}

pub proof fn nep413_digest_output_layout_is_fixed_v1(
    message: Seq<u8>,
    recipient: Seq<u8>,
    nonce32: Bytes32,
    state: Option<Seq<u8>>,
)
    ensures
        compute_nep413_signing_digest_from_nonce_bytes_v1_spec(
            message,
            recipient,
            nonce32,
            state,
        )@.len() == nep413_digest_width_bytes_v1_spec(),
{
}

pub proof fn nep413_decoded_nonce_requires_exactly_32_bytes_v1(
    message: Seq<u8>,
    recipient: Seq<u8>,
    decoded_nonce: Seq<u8>,
    state: Option<Seq<u8>>,
)
    requires
        decoded_nonce.len() != nep413_nonce_width_bytes_v1_spec(),
    ensures
        compute_nep413_signing_digest_from_decoded_nonce_v1_spec(
            message,
            recipient,
            decoded_nonce,
            state,
        ).is_none(),
{
}

pub proof fn nep413_decoded_nonce_accepts_exactly_32_bytes_v1(
    message: Seq<u8>,
    recipient: Seq<u8>,
    decoded_nonce: Seq<u8>,
    state: Option<Seq<u8>>,
)
    requires
        decoded_nonce.len() == nep413_nonce_width_bytes_v1_spec(),
    ensures
        compute_nep413_signing_digest_from_decoded_nonce_v1_spec(
            message,
            recipient,
            decoded_nonce,
            state,
        ) == Some(compute_nep413_signing_digest_from_nonce_bytes_v1_spec(
            message,
            recipient,
            bytes_seq32_to_array_v1_spec(decoded_nonce),
            state,
        )),
{
}

}
