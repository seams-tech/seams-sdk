use ecdsa_hss::fixtures::{FixtureCorpusFile, FixtureRecord, FIXTURE_FORMAT_VERSION};
use ecdsa_hss::shared::context::{
    ECDSA_HSS_V1_CONTEXT_DOMAIN_TAG, ECDSA_HSS_V1_CURVE, ECDSA_HSS_V1_KEY_SCOPE,
    ECDSA_HSS_V1_PARTICIPANT_IDS, ECDSA_HSS_V1_SCHEME_ID,
};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::SecretKey;
use num_bigint::BigUint;
use num_traits::Num;
use sha2::{Digest as Sha2Digest, Sha512};
use sha3::Keccak256;
use signer_core::secp256k1::map_additive_share_to_threshold_signatures_share_2p;

const SECP256K1_ORDER_HEX: &str =
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
const DOMAIN_CANONICAL_X_V1: &[u8] = b"ecdsa-hss:v1:canonical-x";
const DOMAIN_SHARE_V1: &[u8] = b"ecdsa-hss:v1:additive-share:client";

fn fixture_corpus() -> FixtureCorpusFile {
    let bytes = include_bytes!("../../../fixtures/phase1_v1.json");
    serde_json::from_slice(bytes).expect("fixture corpus should parse")
}

fn secp256k1_order() -> BigUint {
    BigUint::from_str_radix(SECP256K1_ORDER_HEX, 16).expect("order should parse")
}

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    let normalized = hex.strip_prefix("0x").unwrap_or(hex);
    assert!(normalized.len() % 2 == 0, "hex must have even length");
    (0..normalized.len())
        .step_by(2)
        .map(|idx| {
            u8::from_str_radix(&normalized[idx..idx + 2], 16).expect("hex byte should parse")
        })
        .collect()
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn bytes_to_biguint_le(bytes: &[u8]) -> BigUint {
    BigUint::from_bytes_le(bytes)
}

fn biguint_to_32_be(value: &BigUint) -> [u8; 32] {
    let bytes = value.to_bytes_be();
    assert!(bytes.len() <= 32, "value must fit into 32 bytes");
    let mut out = [0u8; 32];
    let offset = out.len() - bytes.len();
    out[offset..].copy_from_slice(&bytes);
    out
}

fn biguint_to_32_le(value: &BigUint) -> [u8; 32] {
    let bytes = value.to_bytes_le();
    assert!(bytes.len() <= 32, "value must fit into 32 bytes");
    let mut out = [0u8; 32];
    out[..bytes.len()].copy_from_slice(&bytes);
    out
}

fn encode_ascii_field(value: &str) -> Vec<u8> {
    assert!(!value.is_empty(), "v1 strings must be non-empty");
    assert!(value.is_ascii(), "v1 strings must be ASCII");
    let mut out = Vec::with_capacity(2 + value.len());
    out.extend_from_slice(&(value.len() as u16).to_be_bytes());
    out.extend_from_slice(value.as_bytes());
    out
}

fn encode_context_v1(record: &FixtureRecord) -> Vec<u8> {
    assert_eq!(ECDSA_HSS_V1_PARTICIPANT_IDS, [1, 2]);
    let mut out = Vec::new();
    out.extend_from_slice(ECDSA_HSS_V1_CONTEXT_DOMAIN_TAG);
    out.extend_from_slice(&encode_ascii_field(ECDSA_HSS_V1_SCHEME_ID));
    out.extend_from_slice(&encode_ascii_field(ECDSA_HSS_V1_CURVE));
    out.extend_from_slice(&encode_ascii_field(&record.context.wallet_session_user_id));
    out.extend_from_slice(&encode_ascii_field(&record.context.subject_id));
    out.extend_from_slice(&encode_ascii_field(ECDSA_HSS_V1_KEY_SCOPE));
    out.extend_from_slice(&encode_ascii_field(&record.context.ecdsa_threshold_key_id));
    out.extend_from_slice(&encode_ascii_field(&record.context.signing_root_id));
    out.extend_from_slice(&encode_ascii_field(&record.context.signing_root_version));
    out.extend_from_slice(&encode_ascii_field(&record.context.key_purpose));
    out.extend_from_slice(&encode_ascii_field(&record.context.key_version));
    out.extend_from_slice(&[2u8, 0, 1, 0, 2]);
    out
}

fn derive_canonical_x_v1(
    record: &FixtureRecord,
    context_bytes: &[u8],
) -> ([u8; 32], [u8; 32], [u8; 32]) {
    let y_client = bytes_to_biguint_le(&hex_to_bytes(&record.inputs.y_client32_le_hex));
    let y_relayer = bytes_to_biguint_le(&hex_to_bytes(&record.inputs.y_relayer32_le_hex));
    let two_256 = BigUint::from(1u8) << 256usize;
    let m = (y_client + y_relayer) % two_256;
    let m_le = biguint_to_32_le(&m);
    let d_le = m_le;

    let mut hasher = Sha512::new();
    hasher.update(DOMAIN_CANONICAL_X_V1);
    hasher.update(context_bytes);
    hasher.update(d_le);
    let digest = hasher.finalize();

    let order = secp256k1_order();
    let one = BigUint::from(1u8);
    let x = (BigUint::from_bytes_be(&digest) % (&order - &one)) + &one;
    let x_be = biguint_to_32_be(&x);
    (m_le, d_le, x_be)
}

fn derive_additive_shares_v1(x_be: &[u8; 32], context_bytes: &[u8]) -> (u32, [u8; 32], [u8; 32]) {
    let order = secp256k1_order();
    let one = BigUint::from(1u8);
    let x = BigUint::from_bytes_be(x_be);

    for counter in 0u32.. {
        let mut hasher = Sha512::new();
        hasher.update(DOMAIN_SHARE_V1);
        hasher.update(context_bytes);
        hasher.update(counter.to_be_bytes());
        hasher.update(x_be);
        let digest = hasher.finalize();
        let candidate = (BigUint::from_bytes_be(&digest) % (&order - &one)) + &one;
        if candidate == x {
            continue;
        }
        let x_client_be = biguint_to_32_be(&candidate);
        let x_relayer = if x >= candidate {
            &x - &candidate
        } else {
            (&x + &order) - &candidate
        };
        let x_relayer_be = biguint_to_32_be(&x_relayer);
        assert_ne!(
            x_relayer,
            BigUint::from(0u8),
            "relayer share must be non-zero"
        );
        return (counter, x_client_be, x_relayer_be);
    }
    unreachable!("u32 counter space should not exhaust")
}

fn derive_public_key_and_address(x_be: &[u8; 32]) -> (String, String) {
    let secret_key =
        SecretKey::from_slice(x_be).expect("fixture x should be a valid secp256k1 scalar");
    let compressed = secret_key.public_key().to_encoded_point(true);
    let uncompressed = secret_key.public_key().to_encoded_point(false);

    let mut hasher = Keccak256::new();
    hasher.update(&uncompressed.as_bytes()[1..]);
    let digest = hasher.finalize();
    let address = &digest[digest.len() - 20..];

    (
        bytes_to_hex(compressed.as_bytes()),
        format!("0x{}", bytes_to_hex(address)),
    )
}

#[test]
fn phase1_fixture_corpus_matches_frozen_derivation_rules() {
    let corpus = fixture_corpus();
    assert_eq!(corpus.format_version, FIXTURE_FORMAT_VERSION);
    assert!(
        !corpus.fixtures.is_empty(),
        "fixture corpus should not be empty"
    );

    for fixture in corpus.fixtures.iter() {
        let context_bytes = encode_context_v1(fixture);
        assert_eq!(
            bytes_to_hex(&context_bytes),
            fixture.outputs.context_bytes_hex,
            "{} context bytes drifted",
            fixture.name
        );

        let (m_le, d_le, x_be) = derive_canonical_x_v1(fixture, &context_bytes);
        assert_eq!(
            bytes_to_hex(&d_le),
            fixture.outputs.d32_hex,
            "{} d drifted",
            fixture.name
        );
        assert_eq!(
            bytes_to_hex(&x_be),
            fixture.outputs.x32_hex,
            "{} canonical x drifted",
            fixture.name
        );
        assert_eq!(m_le, d_le, "{} m and d should match in v1", fixture.name);
        let x_big = BigUint::from_bytes_be(&x_be);
        let order = secp256k1_order();
        assert!(
            x_big > BigUint::from(0u8),
            "{} canonical x must be non-zero",
            fixture.name
        );
        assert!(
            x_big < order,
            "{} canonical x must be in scalar range",
            fixture.name
        );

        let (retry_counter, x_client_be, x_relayer_be) =
            derive_additive_shares_v1(&x_be, &context_bytes);
        assert_eq!(
            retry_counter, fixture.outputs.retry_counter,
            "{} retry counter drifted",
            fixture.name
        );
        assert_eq!(
            bytes_to_hex(&x_client_be),
            fixture.outputs.x_client32_hex,
            "{} client share drifted",
            fixture.name
        );
        assert_eq!(
            bytes_to_hex(&x_relayer_be),
            fixture.outputs.x_relayer32_hex,
            "{} relayer share drifted",
            fixture.name
        );
        let x_client_big = BigUint::from_bytes_be(&x_client_be);
        let x_relayer_big = BigUint::from_bytes_be(&x_relayer_be);
        let reconstructed = (&x_client_big + &x_relayer_big) % &order;
        assert!(
            x_client_big > BigUint::from(0u8) && x_client_big < order,
            "{} client share must be in scalar range",
            fixture.name
        );
        assert!(
            x_relayer_big > BigUint::from(0u8) && x_relayer_big < order,
            "{} relayer share must be in scalar range",
            fixture.name
        );
        assert_eq!(
            reconstructed, x_big,
            "{} additive shares must reconstruct the canonical scalar",
            fixture.name
        );

        let mapped_1 = map_additive_share_to_threshold_signatures_share_2p(&x_client_be, 1)
            .expect("participant 1 mapping should succeed");
        let mapped_2 = map_additive_share_to_threshold_signatures_share_2p(&x_relayer_be, 2)
            .expect("participant 2 mapping should succeed");
        assert_eq!(
            bytes_to_hex(&mapped_1),
            fixture.outputs.mapped_client_share32_hex,
            "{} participant 1 mapped share drifted",
            fixture.name
        );
        assert_eq!(
            bytes_to_hex(&mapped_2),
            fixture.outputs.mapped_relayer_share32_hex,
            "{} participant 2 mapped share drifted",
            fixture.name
        );

        let (compressed_public_key_hex, ethereum_address_hex) =
            derive_public_key_and_address(&x_be);
        assert_eq!(
            compressed_public_key_hex, fixture.outputs.public_key33_hex,
            "{} public key drifted",
            fixture.name
        );
        assert_eq!(
            hex_to_bytes(&ethereum_address_hex),
            hex_to_bytes(&fixture.outputs.ethereum_address20_hex),
            "{} ethereum address drifted",
            fixture.name
        );
    }
}
