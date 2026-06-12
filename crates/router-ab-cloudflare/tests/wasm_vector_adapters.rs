#![cfg(target_arch = "wasm32")]

use router_ab_cloudflare::{
    validate_cloudflare_signer_peer_request_v1, validate_cloudflare_signer_private_request_v1,
    CloudflareWorkerRoleV1,
};
use router_ab_core::{
    decode_ab_peer_message_payload_v1, decode_router_to_signer_payload_v1,
    parse_payload_vector_fixture_v1, parse_wire_vector_fixture_v1,
    validate_payload_vector_fixture_v1, validate_wire_vector_fixture_v1, CanonicalWireBytesV1,
    PayloadVectorCaseV1, PublicDigest32, WireMessageKindV1, WireMessageV1,
};
use wasm_bindgen_test::wasm_bindgen_test;

const WIRE_FIXTURE_JSON: &str =
    include_str!("../../router-ab-core/fixtures/protocol/wire/wire-vectors-v1.json");
const PAYLOAD_FIXTURE_JSON: &str =
    include_str!("../../router-ab-core/fixtures/protocol/payload/payload-vectors-v1.json");

#[wasm_bindgen_test]
fn wasm_cloudflare_adapter_round_trips_committed_wire_vectors_through_json_boundary() {
    let fixture = parse_wire_vector_fixture_v1(WIRE_FIXTURE_JSON).expect("wire fixture");
    validate_wire_vector_fixture_v1(&fixture).expect("wire vectors validate");

    for case in fixture.cases {
        let message = WireMessageV1::new(
            case.kind,
            digest_from_hex(&case.transcript_digest_hex),
            CanonicalWireBytesV1::new(bytes_from_hex(&case.payload_hex)).expect("payload bytes"),
        )
        .expect("wire message");
        let encoded = serde_json::to_string(&message).expect("wire message json");
        let decoded: WireMessageV1 = serde_json::from_str(&encoded).expect("decode json");

        assert_eq!(decoded, message, "{}", case.case_id);
    }
}

#[wasm_bindgen_test]
fn wasm_cloudflare_adapter_validates_committed_route_payload_vectors() {
    let fixture = parse_payload_vector_fixture_v1(PAYLOAD_FIXTURE_JSON).expect("payload fixture");
    validate_payload_vector_fixture_v1(&fixture).expect("payload vectors validate");

    let mut routed_cases = 0usize;
    for case in fixture.cases {
        if validate_payload_vector_case_through_cloudflare_adapter(&case) {
            routed_cases += 1;
        }
    }

    assert_eq!(routed_cases, 4);
}

fn validate_payload_vector_case_through_cloudflare_adapter(case: &PayloadVectorCaseV1) -> bool {
    let payload = CanonicalWireBytesV1::new(bytes_from_hex(&case.canonical_bytes_hex))
        .expect("payload bytes");
    match case.wire_message_kind {
        WireMessageKindV1::RouterToSignerA => {
            let router_payload =
                decode_router_to_signer_payload_v1(payload.as_bytes()).expect("router payload");
            let message = WireMessageV1::new(
                case.wire_message_kind,
                router_payload.transcript_digest(),
                payload,
            )
            .expect("wire message");
            validate_cloudflare_signer_private_request_v1(
                CloudflareWorkerRoleV1::SignerARelayer,
                &message,
            )
            .expect("signer a private vector");
            true
        }
        WireMessageKindV1::RouterToSignerB => {
            let router_payload =
                decode_router_to_signer_payload_v1(payload.as_bytes()).expect("router payload");
            let message = WireMessageV1::new(
                case.wire_message_kind,
                router_payload.transcript_digest(),
                payload,
            )
            .expect("wire message");
            validate_cloudflare_signer_private_request_v1(
                CloudflareWorkerRoleV1::SignerB,
                &message,
            )
            .expect("signer b private vector");
            true
        }
        WireMessageKindV1::SignerAToSignerB => {
            let peer_payload =
                decode_ab_peer_message_payload_v1(payload.as_bytes()).expect("peer payload");
            let message = WireMessageV1::new(
                case.wire_message_kind,
                peer_payload.transcript_digest,
                payload,
            )
            .expect("wire message");
            validate_cloudflare_signer_peer_request_v1(CloudflareWorkerRoleV1::SignerB, &message)
                .expect("signer b peer vector");
            true
        }
        WireMessageKindV1::SignerBToSignerA => {
            let peer_payload =
                decode_ab_peer_message_payload_v1(payload.as_bytes()).expect("peer payload");
            let message = WireMessageV1::new(
                case.wire_message_kind,
                peer_payload.transcript_digest,
                payload,
            )
            .expect("wire message");
            validate_cloudflare_signer_peer_request_v1(
                CloudflareWorkerRoleV1::SignerARelayer,
                &message,
            )
            .expect("signer a peer vector");
            true
        }
        WireMessageKindV1::SignerResponse
        | WireMessageKindV1::RelayerActivation
        | WireMessageKindV1::RecipientProofBundle => false,
    }
}

fn digest_from_hex(hex: &str) -> PublicDigest32 {
    let bytes = bytes_from_hex(hex);
    let array: [u8; 32] = bytes.try_into().expect("digest length");
    PublicDigest32::new(array)
}

fn bytes_from_hex(hex: &str) -> Vec<u8> {
    assert_eq!(hex.len() % 2, 0, "hex string length");
    (0..hex.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).expect("hex byte"))
        .collect()
}
