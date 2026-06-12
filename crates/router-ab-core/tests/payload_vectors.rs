use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use router_ab_core::{
    generated_payload_vector_fixture_json_v1, parse_payload_vector_fixture_v1,
    validate_payload_vector_fixture_v1, WireMessageKindV1,
};

#[test]
fn committed_payload_vectors_match_generator() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join("protocol")
        .join("payload")
        .join("payload-vectors-v1.json");
    let committed = fs::read_to_string(path).expect("committed payload fixture");
    let generated = format!("{}\n", generated_payload_vector_fixture_json_v1());

    assert_eq!(committed, generated);
}

#[test]
fn committed_payload_vectors_validate() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join("protocol")
        .join("payload")
        .join("payload-vectors-v1.json");
    let committed = fs::read_to_string(path).expect("committed payload fixture");
    let fixture = parse_payload_vector_fixture_v1(&committed).expect("parse fixture");

    validate_payload_vector_fixture_v1(&fixture).expect("validate fixture");
}

#[test]
fn payload_vectors_cover_every_payload_message_kind() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join("protocol")
        .join("payload")
        .join("payload-vectors-v1.json");
    let committed = fs::read_to_string(path).expect("committed payload fixture");
    let fixture = parse_payload_vector_fixture_v1(&committed).expect("parse fixture");
    let kinds = fixture
        .cases
        .iter()
        .map(|case| case.wire_message_kind)
        .collect::<BTreeSet<_>>();
    let expected = [
        WireMessageKindV1::RouterToSignerA,
        WireMessageKindV1::RouterToSignerB,
        WireMessageKindV1::SignerAToSignerB,
        WireMessageKindV1::SignerBToSignerA,
        WireMessageKindV1::SignerResponse,
        WireMessageKindV1::RelayerActivation,
        WireMessageKindV1::RecipientProofBundle,
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();

    assert_eq!(kinds, expected);
}
