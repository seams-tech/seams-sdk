use std::fs;
use std::path::Path;

use ed25519_dalek::{Signature as Ed25519Signature, VerifyingKey};
use ed25519_hss::fixtures::deterministic_fixture_corpus;
use ed25519_hss::role_signing::{
    create_role_separated_ed25519_client_signature_share_v1,
    finalize_role_separated_ed25519_server_signature_v1,
    role_separated_ed25519_client_verifying_share_v1,
    role_separated_ed25519_server_verifying_share_v1, RoleSeparatedEd25519ClientShareRequestV1,
    RoleSeparatedEd25519Round1SecretV1, RoleSeparatedEd25519Round1StateV1,
    RoleSeparatedEd25519ServerFinalizeRequestV1,
};

#[test]
fn role_separated_ed25519_server_finalizer_matches_fixture_public_key() {
    let fixture = deterministic_fixture_corpus().expect("fixtures").remove(0);
    let client_round1 = round1_state(11, 12);
    let server_round1 = round1_state(21, 22);
    let client_verifying_share =
        role_separated_ed25519_client_verifying_share_v1(fixture.output.x_client_base)
            .expect("client verifying share");
    let server_verifying_share =
        role_separated_ed25519_server_verifying_share_v1(fixture.output.x_server_base)
            .expect("server verifying share");
    let payload = b"router-ab normal signing parity payload";

    let client_signature_share = create_role_separated_ed25519_client_signature_share_v1(
        RoleSeparatedEd25519ClientShareRequestV1 {
            x_client_base: fixture.output.x_client_base,
            client_round1: &client_round1,
            group_public_key: fixture.output.public_key,
            client_verifying_share,
            server_verifying_share,
            server_commitments: server_round1.commitments,
            signing_payload: payload,
        },
    )
    .expect("client signature share");

    let output = finalize_role_separated_ed25519_server_signature_v1(
        RoleSeparatedEd25519ServerFinalizeRequestV1 {
            x_server_base: fixture.output.x_server_base,
            server_round1: &server_round1,
            group_public_key: fixture.output.public_key,
            client_commitments: client_round1.commitments,
            server_commitments: server_round1.commitments,
            client_verifying_share,
            server_verifying_share,
            client_signature_share,
            signing_payload: payload,
        },
    )
    .expect("server finalizes signature");

    let verifying_key =
        VerifyingKey::from_bytes(&fixture.output.public_key).expect("fixture verifying key");
    let signature = Ed25519Signature::from_bytes(&output.signature);
    verifying_key
        .verify_strict(payload, &signature)
        .expect("final signature verifies as Ed25519");
}

#[test]
fn role_separated_ed25519_server_finalizer_rejects_bad_client_share() {
    let fixture = deterministic_fixture_corpus().expect("fixtures").remove(1);
    let client_round1 = round1_state(31, 32);
    let server_round1 = round1_state(41, 42);
    let client_verifying_share =
        role_separated_ed25519_client_verifying_share_v1(fixture.output.x_client_base)
            .expect("client verifying share");
    let server_verifying_share =
        role_separated_ed25519_server_verifying_share_v1(fixture.output.x_server_base)
            .expect("server verifying share");
    let payload = b"router-ab tamper parity payload";
    let mut client_signature_share = create_role_separated_ed25519_client_signature_share_v1(
        RoleSeparatedEd25519ClientShareRequestV1 {
            x_client_base: fixture.output.x_client_base,
            client_round1: &client_round1,
            group_public_key: fixture.output.public_key,
            client_verifying_share,
            server_verifying_share,
            server_commitments: server_round1.commitments,
            signing_payload: payload,
        },
    )
    .expect("client signature share");
    client_signature_share[0] ^= 0x01;

    let err = finalize_role_separated_ed25519_server_signature_v1(
        RoleSeparatedEd25519ServerFinalizeRequestV1 {
            x_server_base: fixture.output.x_server_base,
            server_round1: &server_round1,
            group_public_key: fixture.output.public_key,
            client_commitments: client_round1.commitments,
            server_commitments: server_round1.commitments,
            client_verifying_share,
            server_verifying_share,
            client_signature_share,
            signing_payload: payload,
        },
    )
    .expect_err("tampered client share must fail");
    assert!(
        err.to_string()
            .contains("client signature share failed verification"),
        "unexpected error: {err}"
    );
}

#[test]
fn role_separated_ed25519_server_verifying_share_binds_to_x_server_base() {
    let fixture = deterministic_fixture_corpus().expect("fixtures").remove(2);
    let client_round1 = round1_state(51, 52);
    let server_round1 = round1_state(61, 62);
    let client_verifying_share =
        role_separated_ed25519_client_verifying_share_v1(fixture.output.x_client_base)
            .expect("client verifying share");
    let mut server_verifying_share =
        role_separated_ed25519_server_verifying_share_v1(fixture.output.x_server_base)
            .expect("server verifying share");
    server_verifying_share[0] ^= 0x80;

    let err = finalize_role_separated_ed25519_server_signature_v1(
        RoleSeparatedEd25519ServerFinalizeRequestV1 {
            x_server_base: fixture.output.x_server_base,
            server_round1: &server_round1,
            group_public_key: fixture.output.public_key,
            client_commitments: client_round1.commitments,
            server_commitments: server_round1.commitments,
            client_verifying_share,
            server_verifying_share,
            client_signature_share: scalar_bytes(7),
            signing_payload: b"payload",
        },
    )
    .expect_err("wrong server verifying share must fail");
    assert!(
        err.to_string().contains("server verifying share")
            || err.to_string().contains("verifying shares do not sum"),
        "unexpected error: {err}"
    );
}

#[test]
fn role_separated_ed25519_normal_signing_module_does_not_join_hss_state() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let source =
        fs::read_to_string(manifest_dir.join("src/role_signing.rs")).expect("read role_signing.rs");
    for forbidden in [
        "recover_a_from_base_shares",
        "SigningKey::from_bytes",
        "joined_d",
        "joined_a",
    ] {
        assert!(
            !source.contains(forbidden),
            "role-separated signing module must not reference `{forbidden}`"
        );
    }
}

fn round1_state(hiding: u64, binding: u64) -> RoleSeparatedEd25519Round1StateV1 {
    RoleSeparatedEd25519Round1StateV1::new(
        RoleSeparatedEd25519Round1SecretV1::new(scalar_bytes(hiding), scalar_bytes(binding))
            .expect("round1 secret"),
    )
    .expect("round1 state")
}

fn scalar_bytes(value: u64) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&value.to_le_bytes());
    bytes
}
