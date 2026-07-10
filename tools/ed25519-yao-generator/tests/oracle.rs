use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::SigningKey;
use ed25519_yao_generator::{
    clamp_rfc8032, evaluate_activation, evaluate_export, wrapping_add_le_256, ContributionSide,
    DeriverAContribution, DeriverBContribution, DeriverRole, OracleError, OracleMaterial,
    RawDeriverAContribution, RawDeriverBContribution,
};
use sha2::{Digest, Sha512};

const SCALAR_ORDER_BYTES: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

fn decode_hex_32(value: &str) -> [u8; 32] {
    assert_eq!(value.len(), 64);
    let mut output = [0u8; 32];

    for (index, output_byte) in output.iter_mut().enumerate() {
        let offset = index * 2;
        *output_byte = u8::from_str_radix(&value[offset..offset + 2], 16).expect("valid hex byte");
    }

    output
}

fn decode_hex_64(value: &str) -> [u8; 64] {
    assert_eq!(value.len(), 128);
    let mut output = [0u8; 64];

    for (index, output_byte) in output.iter_mut().enumerate() {
        let offset = index * 2;
        *output_byte = u8::from_str_radix(&value[offset..offset + 2], 16).expect("valid hex byte");
    }

    output
}

fn validate_a(raw: RawDeriverAContribution) -> DeriverAContribution {
    DeriverAContribution::try_from(raw).expect("canonical A input")
}

fn validate_b(raw: RawDeriverBContribution) -> DeriverBContribution {
    DeriverBContribution::try_from(raw).expect("canonical B input")
}

fn parse_scalar(bytes: [u8; 32]) -> Scalar {
    Option::<Scalar>::from(Scalar::from_canonical_bytes(bytes)).expect("oracle scalar is canonical")
}

fn decompress_point(bytes: [u8; 32]) -> curve25519_dalek::edwards::EdwardsPoint {
    CompressedEdwardsY(bytes)
        .decompress()
        .expect("oracle point is canonical and on-curve")
}

fn independent_wrapping_add_four(inputs: [[u8; 32]; 4]) -> [u8; 32] {
    let mut output = [0u8; 32];
    let mut carry = 0u16;

    for index in 0..32 {
        let sum = u16::from(inputs[0][index])
            + u16::from(inputs[1][index])
            + u16::from(inputs[2][index])
            + u16::from(inputs[3][index])
            + carry;
        output[index] = sum as u8;
        carry = sum >> 8;
    }

    output
}

fn assert_rfc8032_vector(seed_hex: &str, public_key_hex: &str) {
    let seed = decode_hex_32(seed_hex);
    let expected_public_key = decode_hex_32(public_key_hex);
    let zero = Scalar::ZERO.to_bytes();
    let deriver_a = validate_a(RawDeriverAContribution {
        y_client: seed,
        y_server: [0u8; 32],
        tau_client: zero,
        tau_server: zero,
    });
    let deriver_b = validate_b(RawDeriverBContribution {
        y_client: [0u8; 32],
        y_server: [0u8; 32],
        tau_client: zero,
        tau_server: zero,
    });
    let output = evaluate_export(&deriver_a, &deriver_b);

    assert_eq!(output.seed().expose_bytes(), seed);
    assert_eq!(
        output.material().public_key().expose_bytes(),
        expected_public_key
    );
}

fn assert_material_bytes_equal(left: &OracleMaterial, right: &OracleMaterial) {
    assert_eq!(
        left.sha512_digest().expose_bytes(),
        right.sha512_digest().expose_bytes()
    );
    assert_eq!(
        left.clamped_scalar_bytes().expose_bytes(),
        right.clamped_scalar_bytes().expose_bytes()
    );
    assert_eq!(
        left.signing_scalar().expose_bytes(),
        right.signing_scalar().expose_bytes()
    );
    assert_eq!(left.tau().expose_bytes(), right.tau().expose_bytes());
    assert_eq!(
        left.x_client_base().expose_bytes(),
        right.x_client_base().expose_bytes()
    );
    assert_eq!(
        left.x_server_base().expose_bytes(),
        right.x_server_base().expose_bytes()
    );
    assert_eq!(
        left.x_client().expose_bytes(),
        right.x_client().expose_bytes()
    );
    assert_eq!(
        left.x_server().expose_bytes(),
        right.x_server().expose_bytes()
    );
    assert_eq!(
        left.public_key().expose_bytes(),
        right.public_key().expose_bytes()
    );
}

fn assert_algebra_invariants(material: &OracleMaterial) {
    let signing_scalar = parse_scalar(material.signing_scalar().expose_bytes());
    let tau = parse_scalar(material.tau().expose_bytes());
    let x_client_base = parse_scalar(material.x_client_base().expose_bytes());
    let x_server_base = parse_scalar(material.x_server_base().expose_bytes());

    assert_eq!(x_client_base, signing_scalar + tau);
    assert_eq!(x_server_base, signing_scalar + tau + tau);
    assert_eq!(
        x_client_base + x_client_base - x_server_base,
        signing_scalar
    );

    let x_client = decompress_point(material.x_client().expose_bytes());
    let x_server = decompress_point(material.x_server().expose_bytes());
    let public_key = decompress_point(material.public_key().expose_bytes());

    assert_eq!(
        x_client.compress().to_bytes(),
        (ED25519_BASEPOINT_POINT * x_client_base)
            .compress()
            .to_bytes()
    );
    assert_eq!(
        x_server.compress().to_bytes(),
        (ED25519_BASEPOINT_POINT * x_server_base)
            .compress()
            .to_bytes()
    );
    assert_eq!(x_client + x_client - x_server, public_key);
    assert_eq!(
        public_key,
        ED25519_BASEPOINT_POINT * signing_scalar,
        "RFC 8032 seed key and reduced clamped scalar must agree"
    );
}

#[test]
fn matches_rfc8032_test_vector_one() {
    assert_rfc8032_vector(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    );
}

#[test]
fn matches_rfc8032_test_vector_two() {
    assert_rfc8032_vector(
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
    );
}

#[test]
fn matches_known_rfc8032_hash_and_clamp() {
    let seed = decode_hex_32("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    let expected_hash = decode_hex_64(
        "357c83864f2833cb427a2ef1c00a013cfdff2768d980c0a3a520f006904de90f\
         9b4f0afe280b746a778684e75442502057b7473a03f08f96f5a38e9287e01f8f",
    );
    let expected_clamped =
        decode_hex_32("307c83864f2833cb427a2ef1c00a013cfdff2768d980c0a3a520f006904de94f");
    let zero = Scalar::ZERO.to_bytes();
    let deriver_a = validate_a(RawDeriverAContribution {
        y_client: seed,
        y_server: [0u8; 32],
        tau_client: zero,
        tau_server: zero,
    });
    let deriver_b = validate_b(RawDeriverBContribution {
        y_client: [0u8; 32],
        y_server: [0u8; 32],
        tau_client: zero,
        tau_server: zero,
    });
    let output = evaluate_export(&deriver_a, &deriver_b);

    assert_eq!(
        output.material().sha512_digest().expose_bytes(),
        expected_hash
    );
    assert_eq!(
        output.material().clamped_scalar_bytes().expose_bytes(),
        expected_clamped
    );
    assert_eq!(
        clamp_rfc8032(expected_hash[..32].try_into().expect("32-byte prefix")),
        expected_clamped
    );
    assert_eq!(
        output.material().signing_scalar().expose_bytes(),
        Scalar::from_bytes_mod_order(expected_clamped).to_bytes()
    );
}

#[test]
fn wrapping_little_endian_addition_propagates_and_discards_carry() {
    let mut carry_left = [0u8; 32];
    carry_left[0] = 0xff;
    carry_left[1] = 0xff;
    let mut one = [0u8; 32];
    one[0] = 1;
    let mut expected_carry = [0u8; 32];
    expected_carry[2] = 1;

    assert_eq!(wrapping_add_le_256(carry_left, one), expected_carry);
    assert_eq!(wrapping_add_le_256([0xff; 32], one), [0u8; 32]);

    let zero = Scalar::ZERO.to_bytes();
    let deriver_a = validate_a(RawDeriverAContribution {
        y_client: carry_left,
        y_server: one,
        tau_client: zero,
        tau_server: zero,
    });
    let deriver_b = validate_b(RawDeriverBContribution {
        y_client: [0u8; 32],
        y_server: [0u8; 32],
        tau_client: zero,
        tau_server: zero,
    });
    assert_eq!(
        evaluate_export(&deriver_a, &deriver_b)
            .seed()
            .expose_bytes(),
        expected_carry
    );

    let deriver_a = validate_a(RawDeriverAContribution {
        y_client: [0xff; 32],
        y_server: [0u8; 32],
        tau_client: zero,
        tau_server: zero,
    });
    let deriver_b = validate_b(RawDeriverBContribution {
        y_client: one,
        y_server: [0u8; 32],
        tau_client: zero,
        tau_server: zero,
    });
    assert_eq!(
        evaluate_export(&deriver_a, &deriver_b)
            .seed()
            .expose_bytes(),
        [0u8; 32]
    );
}

#[test]
fn rejects_each_noncanonical_tau_with_role_and_side() {
    let zero = Scalar::ZERO.to_bytes();

    assert_eq!(
        DeriverAContribution::try_from(RawDeriverAContribution {
            y_client: [0u8; 32],
            y_server: [0u8; 32],
            tau_client: SCALAR_ORDER_BYTES,
            tau_server: zero,
        })
        .err(),
        Some(OracleError::NonCanonicalTauContribution {
            role: DeriverRole::A,
            side: ContributionSide::Client,
        })
    );
    assert_eq!(
        DeriverAContribution::try_from(RawDeriverAContribution {
            y_client: [0u8; 32],
            y_server: [0u8; 32],
            tau_client: zero,
            tau_server: SCALAR_ORDER_BYTES,
        })
        .err(),
        Some(OracleError::NonCanonicalTauContribution {
            role: DeriverRole::A,
            side: ContributionSide::Server,
        })
    );
    assert_eq!(
        DeriverBContribution::try_from(RawDeriverBContribution {
            y_client: [0u8; 32],
            y_server: [0u8; 32],
            tau_client: SCALAR_ORDER_BYTES,
            tau_server: zero,
        })
        .err(),
        Some(OracleError::NonCanonicalTauContribution {
            role: DeriverRole::B,
            side: ContributionSide::Client,
        })
    );
    assert_eq!(
        DeriverBContribution::try_from(RawDeriverBContribution {
            y_client: [0u8; 32],
            y_server: [0u8; 32],
            tau_client: zero,
            tau_server: SCALAR_ORDER_BYTES,
        })
        .err(),
        Some(OracleError::NonCanonicalTauContribution {
            role: DeriverRole::B,
            side: ContributionSide::Server,
        })
    );
}

#[test]
fn canonical_tau_sums_wrap_mod_scalar_order_at_both_levels() {
    let deriver_a = validate_a(RawDeriverAContribution {
        y_client: [0x31; 32],
        y_server: [0x13; 32],
        tau_client: (-Scalar::ONE).to_bytes(),
        tau_server: Scalar::from(2u64).to_bytes(),
    });
    let deriver_b = validate_b(RawDeriverBContribution {
        y_client: [0x27; 32],
        y_server: [0x72; 32],
        tau_client: (-Scalar::ONE).to_bytes(),
        tau_server: Scalar::ZERO.to_bytes(),
    });
    let output = evaluate_activation(&deriver_a, &deriver_b);

    assert_eq!(
        output.material().tau().expose_bytes(),
        Scalar::ZERO.to_bytes()
    );
    assert_eq!(
        output.material().x_client_base().expose_bytes(),
        output.material().signing_scalar().expose_bytes()
    );
    assert_eq!(
        output.material().x_server_base().expose_bytes(),
        output.material().signing_scalar().expose_bytes()
    );
}

#[test]
fn activation_and_export_share_the_same_non_seed_material() {
    let deriver_a = validate_a(RawDeriverAContribution {
        y_client: [0x42; 32],
        y_server: [0x12; 32],
        tau_client: Scalar::from(7u64).to_bytes(),
        tau_server: Scalar::from(11u64).to_bytes(),
    });
    let deriver_b = validate_b(RawDeriverBContribution {
        y_client: [0x24; 32],
        y_server: [0x21; 32],
        tau_client: Scalar::from(13u64).to_bytes(),
        tau_server: Scalar::from(17u64).to_bytes(),
    });
    let activation = evaluate_activation(&deriver_a, &deriver_b);
    let export = evaluate_export(&deriver_a, &deriver_b);
    let expected_seed = independent_wrapping_add_four([
        deriver_a.y_client().expose_bytes(),
        deriver_a.y_server().expose_bytes(),
        deriver_b.y_client().expose_bytes(),
        deriver_b.y_server().expose_bytes(),
    ]);

    assert_material_bytes_equal(activation.material(), export.material());
    assert_eq!(export.seed().expose_bytes(), expected_seed);
}

#[test]
fn share_scalars_and_point_commitments_satisfy_approved_invariant() {
    let deriver_a = validate_a(RawDeriverAContribution {
        y_client: [0xa5; 32],
        y_server: [0x1a; 32],
        tau_client: Scalar::from(17u64).to_bytes(),
        tau_server: Scalar::from(19u64).to_bytes(),
    });
    let deriver_b = validate_b(RawDeriverBContribution {
        y_client: [0x5a; 32],
        y_server: [0xa1; 32],
        tau_client: Scalar::from(23u64).to_bytes(),
        tau_server: Scalar::from(29u64).to_bytes(),
    });
    let output = evaluate_activation(&deriver_a, &deriver_b);

    assert_algebra_invariants(output.material());
}

#[test]
fn every_nonzero_contribution_matches_independent_composition() {
    let y_client_a = [0xf1; 32];
    let y_server_a = [0x22; 32];
    let y_client_b = [0x43; 32];
    let y_server_b = [0x84; 32];
    let tau_client_a = Scalar::from(2u64);
    let tau_server_a = Scalar::from(3u64);
    let tau_client_b = Scalar::from(5u64);
    let tau_server_b = Scalar::from(7u64);
    let deriver_a = validate_a(RawDeriverAContribution {
        y_client: y_client_a,
        y_server: y_server_a,
        tau_client: tau_client_a.to_bytes(),
        tau_server: tau_server_a.to_bytes(),
    });
    let deriver_b = validate_b(RawDeriverBContribution {
        y_client: y_client_b,
        y_server: y_server_b,
        tau_client: tau_client_b.to_bytes(),
        tau_server: tau_server_b.to_bytes(),
    });
    let output = evaluate_export(&deriver_a, &deriver_b);

    assert_eq!(deriver_a.y_client().expose_bytes(), y_client_a);
    assert_eq!(deriver_a.y_server().expose_bytes(), y_server_a);
    assert_eq!(
        deriver_a.tau_client().expose_bytes(),
        tau_client_a.to_bytes()
    );
    assert_eq!(
        deriver_a.tau_server().expose_bytes(),
        tau_server_a.to_bytes()
    );
    assert_eq!(deriver_b.y_client().expose_bytes(), y_client_b);
    assert_eq!(deriver_b.y_server().expose_bytes(), y_server_b);
    assert_eq!(
        deriver_b.tau_client().expose_bytes(),
        tau_client_b.to_bytes()
    );
    assert_eq!(
        deriver_b.tau_server().expose_bytes(),
        tau_server_b.to_bytes()
    );

    let expected_seed =
        independent_wrapping_add_four([y_client_a, y_server_a, y_client_b, y_server_b]);
    let expected_hash: [u8; 64] = Sha512::digest(expected_seed).into();
    let mut expected_clamped: [u8; 32] = expected_hash[..32]
        .try_into()
        .expect("SHA-512 lower half is 32 bytes");
    expected_clamped[0] &= 248;
    expected_clamped[31] &= 63;
    expected_clamped[31] |= 64;
    let expected_signing_scalar = Scalar::from_bytes_mod_order(expected_clamped);
    let expected_tau = Scalar::from(17u64);
    let expected_x_client_base = expected_signing_scalar + expected_tau;
    let expected_x_server_base = expected_signing_scalar + expected_tau + expected_tau;
    let expected_x_client = (ED25519_BASEPOINT_POINT * expected_x_client_base)
        .compress()
        .to_bytes();
    let expected_x_server = (ED25519_BASEPOINT_POINT * expected_x_server_base)
        .compress()
        .to_bytes();
    let expected_public_key = SigningKey::from_bytes(&expected_seed)
        .verifying_key()
        .to_bytes();

    assert_eq!(output.seed().expose_bytes(), expected_seed);
    assert_eq!(
        output.material().sha512_digest().expose_bytes(),
        expected_hash
    );
    assert_eq!(
        output.material().clamped_scalar_bytes().expose_bytes(),
        expected_clamped
    );
    assert_eq!(
        output.material().signing_scalar().expose_bytes(),
        expected_signing_scalar.to_bytes()
    );
    assert_eq!(
        output.material().tau().expose_bytes(),
        expected_tau.to_bytes()
    );
    assert_eq!(
        output.material().x_client_base().expose_bytes(),
        expected_x_client_base.to_bytes()
    );
    assert_eq!(
        output.material().x_server_base().expose_bytes(),
        expected_x_server_base.to_bytes()
    );
    assert_eq!(
        output.material().x_client().expose_bytes(),
        expected_x_client
    );
    assert_eq!(
        output.material().x_server().expose_bytes(),
        expected_x_server
    );
    assert_eq!(
        output.material().public_key().expose_bytes(),
        expected_public_key
    );
    assert_algebra_invariants(output.material());
}
