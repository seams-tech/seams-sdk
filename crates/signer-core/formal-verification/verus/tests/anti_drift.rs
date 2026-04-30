use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::scalar::Scalar as CurveScalar;
use hkdf::Hkdf;
use k256::elliptic_curve::bigint::U512;
use k256::elliptic_curve::ops::Reduce;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{FieldBytes, NonZeroScalar, SecretKey, WideBytes};
use num_bigint::BigUint;
use num_traits::Num;
use serde::Deserialize;
use sha2::{Digest as Sha2Digest, Sha256};
use sha3::Keccak256;
use signer_core::near_threshold_ed25519::{
    compute_nep413_signing_digest_from_nonce_base64,
    compute_nep413_signing_digest_from_nonce_bytes,
    derive_threshold_client_signing_share_bytes_v1_from_wrap_key_seed,
    derive_threshold_client_verifying_share_bytes_v1_from_wrap_key_seed,
    verifying_share_bytes_from_signing_share_bytes,
};
use signer_core::secp256k1::{
    derive_secp256k1_keypair_from_prf_second, derive_threshold_secp256k1_relayer_share,
    map_additive_share_to_threshold_signatures_share_2p, secp256k1_private_key_32_to_public_key_33,
    secp256k1_public_key_33_to_ethereum_address_20, THRESHOLD_SECP256K1_2P_CLIENT_PARTICIPANT_ID,
    THRESHOLD_SECP256K1_2P_RELAYER_PARTICIPANT_ID,
};

const FIXTURE_FORMAT_VERSION: &str = "signer-core-secp256k1-v1";
const FIXTURE_CORPUS_JSON: &str = include_str!("../../fixtures/secp256k1_v1.json");
const ED25519_FIXTURE_FORMAT_VERSION: &str = "signer-core-near-threshold-ed25519-v1";
const ED25519_FIXTURE_CORPUS_JSON: &str =
    include_str!("../../fixtures/near_threshold_ed25519_v1.json");
const THRESHOLD_SECP256K1_RELAYER_SHARE_SALT_V1: &[u8] =
    b"seams/lite/threshold-secp256k1-ecdsa/relayer-share:v1";
const EVM_SECP256K1_PRF_SECOND_HKDF_INFO_V1: &[u8] = b"secp256k1-signing-key-dual-prf-v1";
const EVM_SECP256K1_PRF_SECOND_SALT_PREFIX_V1: &str = "evm-key-derivation:";
const THRESHOLD_ED25519_CLIENT_SHARE_SALT_V1: &[u8] =
    b"seams/lite/threshold-ed25519/client-share:v1";
const SECP256K1_ORDER_HEX: &str =
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";

#[derive(Debug, Deserialize)]
struct FixtureCorpus {
    format_version: String,
    relayer_share_vectors: Vec<RelayerShareVector>,
    prf_second_keypair_vectors: Vec<PrfSecondKeypairVector>,
    mapping_vectors: Vec<MappingVector>,
    rejected_scalar_vectors: Vec<RejectedScalarVector>,
}

#[derive(Debug, Deserialize)]
struct RelayerShareVector {
    name: String,
    master_secret_hex: String,
    relayer_key_id: String,
    okm64_hex: String,
    signing_share32_hex: String,
    verifying_share33_hex: String,
}

#[derive(Debug, Deserialize)]
struct PrfSecondKeypairVector {
    name: String,
    prf_second_hex: String,
    near_account_id: String,
    okm64_hex: String,
    private_key32_hex: String,
    public_key33_hex: String,
    ethereum_address20_hex: String,
}

#[derive(Debug, Deserialize)]
struct MappingVector {
    name: String,
    additive_share32_hex: String,
    mapped_client_share32_hex: String,
    mapped_relayer_share32_hex: String,
}

#[derive(Debug, Deserialize)]
struct RejectedScalarVector {
    name: String,
    scalar32_hex: String,
}

#[derive(Debug, Deserialize)]
struct Ed25519FixtureCorpus {
    format_version: String,
    client_share_vectors: Vec<Ed25519ClientShareVector>,
    rejected_seed_vectors: Vec<Ed25519RejectedSeedVector>,
    nep413_digest_vectors: Vec<Nep413DigestVector>,
    rejected_nonce_base64_vectors: Vec<Nep413RejectedNonceBase64Vector>,
}

#[derive(Debug, Deserialize)]
struct Ed25519ClientShareVector {
    name: String,
    wrap_key_seed32_hex: String,
    near_account_id: String,
    hkdf_info_hex: String,
    okm64_hex: String,
    signing_share32_hex: String,
    verifying_share32_hex: String,
}

#[derive(Debug, Deserialize)]
struct Ed25519RejectedSeedVector {
    name: String,
    wrap_key_seed_hex: String,
}

#[derive(Debug, Deserialize)]
struct Nep413DigestVector {
    name: String,
    message: String,
    recipient: String,
    nonce32_hex: String,
    nonce_base64: String,
    state: Option<String>,
    prefix_le_hex: String,
    borsh_payload_hex: String,
    prefixed_payload_hex: String,
    digest32_hex: String,
}

#[derive(Debug, Deserialize)]
struct Nep413RejectedNonceBase64Vector {
    name: String,
    nonce_base64: String,
    decoded_len: usize,
}

fn fixture_corpus() -> FixtureCorpus {
    let corpus: FixtureCorpus =
        serde_json::from_str(FIXTURE_CORPUS_JSON).expect("fixture corpus should parse");
    assert_eq!(corpus.format_version, FIXTURE_FORMAT_VERSION);
    assert!(
        !corpus.relayer_share_vectors.is_empty(),
        "relayer vectors must not be empty"
    );
    assert!(
        !corpus.prf_second_keypair_vectors.is_empty(),
        "PRF.second vectors must not be empty"
    );
    assert!(
        !corpus.mapping_vectors.is_empty(),
        "mapping vectors must not be empty"
    );
    assert!(
        !corpus.rejected_scalar_vectors.is_empty(),
        "rejected scalar vectors must not be empty"
    );
    corpus
}

fn ed25519_fixture_corpus() -> Ed25519FixtureCorpus {
    let corpus: Ed25519FixtureCorpus =
        serde_json::from_str(ED25519_FIXTURE_CORPUS_JSON).expect("Ed25519 fixture corpus");
    assert_eq!(corpus.format_version, ED25519_FIXTURE_FORMAT_VERSION);
    assert!(
        !corpus.client_share_vectors.is_empty(),
        "Ed25519 client-share vectors must not be empty"
    );
    assert!(
        !corpus.rejected_seed_vectors.is_empty(),
        "Ed25519 rejected-seed vectors must not be empty"
    );
    assert!(
        !corpus.nep413_digest_vectors.is_empty(),
        "NEP-413 digest vectors must not be empty"
    );
    assert!(
        !corpus.rejected_nonce_base64_vectors.is_empty(),
        "NEP-413 rejected nonce vectors must not be empty"
    );
    corpus
}

fn secp256k1_order() -> BigUint {
    BigUint::from_str_radix(SECP256K1_ORDER_HEX, 16).expect("parse secp256k1 order")
}

fn hex_to_vec(hex: &str) -> Vec<u8> {
    assert!(hex.len() % 2 == 0, "hex string must have even length");
    (0..hex.len())
        .step_by(2)
        .map(|idx| u8::from_str_radix(&hex[idx..idx + 2], 16).expect("hex byte should parse"))
        .collect()
}

fn hex_to_array<const N: usize>(hex: &str) -> [u8; N] {
    let bytes = hex_to_vec(hex);
    assert_eq!(bytes.len(), N, "hex string must decode to {N} bytes");
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    out
}

fn biguint_to_32_be(value: &BigUint) -> [u8; 32] {
    let bytes = value.to_bytes_be();
    assert!(bytes.len() <= 32, "value must fit into 32 bytes");
    let mut out = [0u8; 32];
    out[(32 - bytes.len())..].copy_from_slice(&bytes);
    out
}

fn field_bytes_to_array32(bytes: &FieldBytes) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes.as_ref());
    out
}

fn reduce_64_formula(okm64: &[u8; 64]) -> [u8; 32] {
    let order = secp256k1_order();
    let one = BigUint::from(1u8);
    let reduced = (BigUint::from_bytes_be(okm64) % (&order - &one)) + &one;
    biguint_to_32_be(&reduced)
}

fn reduce_64_k256(okm64: &[u8; 64]) -> [u8; 32] {
    let mut wide = WideBytes::default();
    wide.copy_from_slice(okm64);
    field_bytes_to_array32(&FieldBytes::from(
        <NonZeroScalar as Reduce<U512>>::reduce_bytes(&wide),
    ))
}

fn relayer_hkdf_okm(master_secret: &[u8], relayer_key_id: &str) -> [u8; 64] {
    let hk = Hkdf::<Sha256>::new(
        Some(THRESHOLD_SECP256K1_RELAYER_SHARE_SALT_V1),
        master_secret,
    );
    let mut okm64 = [0u8; 64];
    hk.expand(relayer_key_id.as_bytes(), &mut okm64)
        .expect("HKDF expand for relayer share");
    okm64
}

fn prf_second_hkdf_okm(prf_second: &[u8], near_account_id: &str) -> [u8; 64] {
    let mut salt =
        Vec::with_capacity(EVM_SECP256K1_PRF_SECOND_SALT_PREFIX_V1.len() + near_account_id.len());
    salt.extend_from_slice(EVM_SECP256K1_PRF_SECOND_SALT_PREFIX_V1.as_bytes());
    salt.extend_from_slice(near_account_id.as_bytes());

    let hk = Hkdf::<Sha256>::new(Some(&salt), prf_second);
    let mut okm64 = [0u8; 64];
    hk.expand(EVM_SECP256K1_PRF_SECOND_HKDF_INFO_V1, &mut okm64)
        .expect("HKDF expand for PRF.second key derivation");
    okm64
}

fn threshold_ed25519_hkdf_info(near_account_id: &str) -> Vec<u8> {
    let mut info = Vec::with_capacity(near_account_id.len() + 1 + 4);
    info.extend_from_slice(near_account_id.as_bytes());
    info.push(0);
    info.extend_from_slice(&0u32.to_be_bytes());
    info
}

fn threshold_ed25519_hkdf_okm(wrap_key_seed32: &[u8], near_account_id: &str) -> [u8; 64] {
    let hk = Hkdf::<Sha256>::new(
        Some(THRESHOLD_ED25519_CLIENT_SHARE_SALT_V1),
        wrap_key_seed32,
    );
    let info = threshold_ed25519_hkdf_info(near_account_id);
    let mut okm64 = [0u8; 64];
    hk.expand(&info, &mut okm64)
        .expect("HKDF expand for threshold Ed25519 client share");
    okm64
}

fn reduce_threshold_ed25519_okm(okm64: &[u8; 64]) -> [u8; 32] {
    CurveScalar::from_bytes_mod_order_wide(okm64).to_bytes()
}

fn threshold_ed25519_verifying_from_signing(signing_share32: &[u8; 32]) -> [u8; 32] {
    let scalar = CurveScalar::from_bytes_mod_order(*signing_share32);
    (ED25519_BASEPOINT_POINT * scalar).compress().to_bytes()
}

fn borsh_string(value: &str) -> Vec<u8> {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(4 + bytes.len());
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
    out
}

fn borsh_option_string(value: Option<&str>) -> Vec<u8> {
    match value {
        Some(value) => {
            let encoded = borsh_string(value);
            let mut out = Vec::with_capacity(1 + encoded.len());
            out.push(1);
            out.extend_from_slice(&encoded);
            out
        }
        None => vec![0],
    }
}

fn nep413_borsh_payload(
    message: &str,
    recipient: &str,
    nonce32: &[u8; 32],
    state: Option<&str>,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&borsh_string(message));
    out.extend_from_slice(&borsh_string(recipient));
    out.extend_from_slice(nonce32);
    out.extend_from_slice(&borsh_option_string(state));
    out
}

fn nep413_prefixed_payload(
    message: &str,
    recipient: &str,
    nonce32: &[u8; 32],
    state: Option<&str>,
) -> Vec<u8> {
    let mut out = 2_147_484_061u32.to_le_bytes().to_vec();
    out.extend_from_slice(&nep413_borsh_payload(message, recipient, nonce32, state));
    out
}

fn nep413_digest_formula(
    message: &str,
    recipient: &str,
    nonce32: &[u8; 32],
    state: Option<&str>,
) -> [u8; 32] {
    Sha256::digest(nep413_prefixed_payload(message, recipient, nonce32, state)).into()
}

fn compressed_public_key_from_private_key(private_key32: &[u8; 32]) -> Vec<u8> {
    SecretKey::from_slice(private_key32)
        .expect("valid secp256k1 secret key")
        .public_key()
        .to_encoded_point(true)
        .as_bytes()
        .to_vec()
}

fn ethereum_address_from_private_key(private_key32: &[u8; 32]) -> Vec<u8> {
    let uncompressed = SecretKey::from_slice(private_key32)
        .expect("valid secp256k1 secret key")
        .public_key()
        .to_encoded_point(false);
    let mut hasher = Keccak256::new();
    hasher.update(&uncompressed.as_bytes()[1..]);
    let digest = hasher.finalize();
    digest[digest.len() - 20..].to_vec()
}

#[test]
fn anti_drift_relayer_share_derivation_matches_committed_vectors() {
    for vector in fixture_corpus().relayer_share_vectors {
        let master_secret = hex_to_vec(&vector.master_secret_hex);
        let expected_okm64 = hex_to_array::<64>(&vector.okm64_hex);
        let expected_signing_share32 = hex_to_array::<32>(&vector.signing_share32_hex);
        let expected_verifying_share33 = hex_to_vec(&vector.verifying_share33_hex);

        let derived =
            derive_threshold_secp256k1_relayer_share(&master_secret, &vector.relayer_key_id)
                .unwrap_or_else(|err| panic!("{} relayer derivation failed: {err}", vector.name));
        assert_eq!(derived.len(), 65, "{} output layout drifted", vector.name);

        let signing_share32: [u8; 32] = derived[..32]
            .try_into()
            .expect("signing share must be 32 bytes");
        let verifying_share33 = &derived[32..65];
        assert_eq!(verifying_share33.len(), 33);

        let okm64 = relayer_hkdf_okm(&master_secret, &vector.relayer_key_id);
        assert_eq!(okm64, expected_okm64, "{} HKDF OKM drifted", vector.name);
        assert_eq!(
            signing_share32, expected_signing_share32,
            "{} signing share drifted",
            vector.name
        );
        assert_eq!(
            signing_share32,
            reduce_64_formula(&okm64),
            "{} reduction formula drifted",
            vector.name
        );
        assert_eq!(
            signing_share32,
            reduce_64_k256(&okm64),
            "{} k256 reduction drifted",
            vector.name
        );
        assert_eq!(
            verifying_share33, expected_verifying_share33,
            "{} verifying share drifted",
            vector.name
        );
        assert_eq!(
            verifying_share33,
            compressed_public_key_from_private_key(&signing_share32),
            "{} verifying share no longer matches signing share",
            vector.name
        );
    }
}

#[test]
fn anti_drift_prf_second_keypair_matches_committed_vectors() {
    for vector in fixture_corpus().prf_second_keypair_vectors {
        let prf_second = hex_to_vec(&vector.prf_second_hex);
        let expected_okm64 = hex_to_array::<64>(&vector.okm64_hex);
        let expected_private_key32 = hex_to_array::<32>(&vector.private_key32_hex);
        let expected_public_key33 = hex_to_vec(&vector.public_key33_hex);
        let expected_address20 = hex_to_vec(&vector.ethereum_address20_hex);

        let derived =
            derive_secp256k1_keypair_from_prf_second(&prf_second, &vector.near_account_id)
                .unwrap_or_else(|err| {
                    panic!("{} PRF.second derivation failed: {err}", vector.name)
                });
        assert_eq!(derived.len(), 85, "{} output layout drifted", vector.name);

        let private_key32: [u8; 32] = derived[..32]
            .try_into()
            .expect("private key must be 32 bytes");
        let public_key33 = &derived[32..65];
        let address20 = &derived[65..85];

        let okm64 = prf_second_hkdf_okm(&prf_second, &vector.near_account_id);
        assert_eq!(okm64, expected_okm64, "{} HKDF OKM drifted", vector.name);
        assert_eq!(
            private_key32, expected_private_key32,
            "{} private key drifted",
            vector.name
        );
        assert_eq!(
            private_key32,
            reduce_64_formula(&okm64),
            "{} reduction formula drifted",
            vector.name
        );
        assert_eq!(
            private_key32,
            reduce_64_k256(&okm64),
            "{} k256 reduction drifted",
            vector.name
        );
        assert_eq!(
            public_key33, expected_public_key33,
            "{} public key drifted",
            vector.name
        );
        assert_eq!(
            address20, expected_address20,
            "{} address drifted",
            vector.name
        );
        assert_eq!(
            public_key33,
            compressed_public_key_from_private_key(&private_key32),
            "{} public key no longer matches private key",
            vector.name
        );
        assert_eq!(
            address20,
            ethereum_address_from_private_key(&private_key32),
            "{} address no longer matches private key",
            vector.name
        );
        assert_eq!(
            address20,
            secp256k1_public_key_33_to_ethereum_address_20(public_key33)
                .expect("derive address from compressed public key"),
            "{} address helper drifted",
            vector.name
        );
    }
}

#[test]
fn anti_drift_additive_share_mapping_matches_committed_vectors() {
    let corpus = fixture_corpus();
    for vector in corpus.mapping_vectors.iter() {
        let additive_share32 = hex_to_array::<32>(&vector.additive_share32_hex);
        let expected_mapped_client = hex_to_vec(&vector.mapped_client_share32_hex);
        let expected_mapped_relayer = hex_to_vec(&vector.mapped_relayer_share32_hex);

        let mapped_client = map_additive_share_to_threshold_signatures_share_2p(
            &additive_share32,
            THRESHOLD_SECP256K1_2P_CLIENT_PARTICIPANT_ID,
        )
        .unwrap_or_else(|err| panic!("{} client participant mapping failed: {err}", vector.name));
        let mapped_relayer = map_additive_share_to_threshold_signatures_share_2p(
            &additive_share32,
            THRESHOLD_SECP256K1_2P_RELAYER_PARTICIPANT_ID,
        )
        .unwrap_or_else(|err| panic!("{} relayer participant mapping failed: {err}", vector.name));

        assert_eq!(
            mapped_client, expected_mapped_client,
            "{} client mapped share drifted",
            vector.name
        );
        assert_eq!(
            mapped_relayer, expected_mapped_relayer,
            "{} relayer mapped share drifted",
            vector.name
        );
    }

    let first_share = hex_to_array::<32>(&corpus.mapping_vectors[0].additive_share32_hex);
    let unsupported = map_additive_share_to_threshold_signatures_share_2p(&first_share, 3);
    assert!(
        unsupported.is_err(),
        "unsupported 2P participant IDs must fail"
    );
}

#[test]
fn anti_drift_scalar_domain_boundaries_match_public_api_parsing() {
    let corpus = fixture_corpus();
    for vector in corpus.rejected_scalar_vectors {
        let rejected_scalar = hex_to_array::<32>(&vector.scalar32_hex);
        assert!(
            map_additive_share_to_threshold_signatures_share_2p(
                &rejected_scalar,
                THRESHOLD_SECP256K1_2P_CLIENT_PARTICIPANT_ID
            )
            .is_err(),
            "{} invalid scalar should be rejected by mapping",
            vector.name
        );
        assert!(
            secp256k1_private_key_32_to_public_key_33(&rejected_scalar).is_err(),
            "{} invalid scalar should be rejected by private-key helper",
            vector.name
        );
    }

    for vector in fixture_corpus().mapping_vectors {
        let valid_scalar = hex_to_array::<32>(&vector.additive_share32_hex);
        assert!(
            secp256k1_private_key_32_to_public_key_33(&valid_scalar).is_ok(),
            "{} valid scalar should be accepted by private-key helper",
            vector.name
        );
    }
}

#[test]
fn anti_drift_threshold_ed25519_client_share_derivation_matches_committed_vectors() {
    for vector in ed25519_fixture_corpus().client_share_vectors {
        let wrap_key_seed32 = hex_to_array::<32>(&vector.wrap_key_seed32_hex);
        let expected_info = hex_to_vec(&vector.hkdf_info_hex);
        let expected_okm64 = hex_to_array::<64>(&vector.okm64_hex);
        let expected_signing_share32 = hex_to_array::<32>(&vector.signing_share32_hex);
        let expected_verifying_share32 = hex_to_array::<32>(&vector.verifying_share32_hex);

        let signing_share32 = derive_threshold_client_signing_share_bytes_v1_from_wrap_key_seed(
            &wrap_key_seed32,
            &vector.near_account_id,
        )
        .unwrap_or_else(|err| {
            panic!(
                "{} Ed25519 signing-share derivation failed: {err}",
                vector.name
            )
        });
        let verifying_share32 =
            derive_threshold_client_verifying_share_bytes_v1_from_wrap_key_seed(
                &wrap_key_seed32,
                &vector.near_account_id,
            )
            .unwrap_or_else(|err| {
                panic!(
                    "{} Ed25519 verifying-share derivation failed: {err}",
                    vector.name
                )
            });

        let info = threshold_ed25519_hkdf_info(&vector.near_account_id);
        let okm64 = threshold_ed25519_hkdf_okm(&wrap_key_seed32, &vector.near_account_id);
        assert_eq!(info, expected_info, "{} HKDF info drifted", vector.name);
        assert_eq!(okm64, expected_okm64, "{} HKDF OKM drifted", vector.name);
        assert_eq!(
            signing_share32, expected_signing_share32,
            "{} signing share drifted",
            vector.name
        );
        assert_eq!(
            signing_share32,
            reduce_threshold_ed25519_okm(&okm64),
            "{} wide scalar reduction drifted",
            vector.name
        );
        assert_eq!(
            verifying_share32, expected_verifying_share32,
            "{} verifying share drifted",
            vector.name
        );
        assert_eq!(
            verifying_share32,
            threshold_ed25519_verifying_from_signing(&signing_share32),
            "{} verifying share no longer matches signing share",
            vector.name
        );
        assert_eq!(
            verifying_share32,
            verifying_share_bytes_from_signing_share_bytes(&signing_share32),
            "{} verifying-share helper drifted",
            vector.name
        );
    }
}

#[test]
fn anti_drift_threshold_ed25519_client_share_rejects_bad_seed_lengths() {
    for vector in ed25519_fixture_corpus().rejected_seed_vectors {
        let wrap_key_seed = hex_to_vec(&vector.wrap_key_seed_hex);
        let err = derive_threshold_client_signing_share_bytes_v1_from_wrap_key_seed(
            &wrap_key_seed,
            "alice.near",
        )
        .expect_err("invalid WrapKeySeed length should fail");
        assert!(
            err.message.contains("expected 32 bytes"),
            "{} unexpected error: {}",
            vector.name,
            err.message
        );
    }
}

#[test]
fn anti_drift_nep413_digest_matches_committed_vectors() {
    for vector in ed25519_fixture_corpus().nep413_digest_vectors {
        let nonce32 = hex_to_array::<32>(&vector.nonce32_hex);
        let expected_prefix = hex_to_vec(&vector.prefix_le_hex);
        let expected_borsh_payload = hex_to_vec(&vector.borsh_payload_hex);
        let expected_prefixed_payload = hex_to_vec(&vector.prefixed_payload_hex);
        let expected_digest32 = hex_to_array::<32>(&vector.digest32_hex);
        let state = vector.state.as_deref();

        let borsh_payload =
            nep413_borsh_payload(&vector.message, &vector.recipient, &nonce32, state);
        let prefixed_payload =
            nep413_prefixed_payload(&vector.message, &vector.recipient, &nonce32, state);
        assert_eq!(
            2_147_484_061u32.to_le_bytes().as_slice(),
            expected_prefix,
            "{} NEP-413 prefix drifted",
            vector.name
        );
        assert_eq!(
            borsh_payload, expected_borsh_payload,
            "{} Borsh payload drifted",
            vector.name
        );
        assert_eq!(
            prefixed_payload, expected_prefixed_payload,
            "{} prefixed payload drifted",
            vector.name
        );
        assert_eq!(
            nep413_digest_formula(&vector.message, &vector.recipient, &nonce32, state),
            expected_digest32,
            "{} independent digest formula drifted",
            vector.name
        );

        let digest_from_nonce_bytes = compute_nep413_signing_digest_from_nonce_bytes(
            &vector.message,
            &vector.recipient,
            nonce32,
            state,
        )
        .unwrap_or_else(|err| panic!("{} nonce-bytes digest failed: {err}", vector.name));
        let digest_from_nonce_base64 = compute_nep413_signing_digest_from_nonce_base64(
            &vector.message,
            &vector.recipient,
            &vector.nonce_base64,
            state,
        )
        .unwrap_or_else(|err| panic!("{} nonce-base64 digest failed: {err}", vector.name));
        assert_eq!(
            digest_from_nonce_bytes, expected_digest32,
            "{} nonce-bytes digest drifted",
            vector.name
        );
        assert_eq!(
            digest_from_nonce_base64, expected_digest32,
            "{} nonce-base64 digest drifted",
            vector.name
        );
    }
}

#[test]
fn anti_drift_nep413_digest_rejects_bad_nonce_lengths() {
    for vector in ed25519_fixture_corpus().rejected_nonce_base64_vectors {
        let err = compute_nep413_signing_digest_from_nonce_base64(
            "hello",
            "example.near",
            &vector.nonce_base64,
            None,
        )
        .expect_err("invalid nonce length should fail");
        assert!(
            err.message.contains("expected 32 bytes")
                && err.message.contains(&vector.decoded_len.to_string()),
            "{} unexpected error: {}",
            vector.name,
            err.message
        );
    }
}
