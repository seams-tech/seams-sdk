#![cfg(all(feature = "threshold-ecdsa-hss", feature = "typescript-bindings"))]

use std::{env, fs, path::PathBuf};

use base64ct::{Base64UrlUnpadded, Encoding};
use ecdsa_hss::{derive_relayer_share_for_client_public, EcdsaHssStableKeyContext};
use serde::{Deserialize, Serialize};
use signer_core::commands::{
    finalize_ecdsa_client_bootstrap_command_v1, prepare_ecdsa_client_bootstrap_command_v1,
    EcdsaBootstrapSecretSourceV1, EcdsaClientBootstrapAlgorithmV1, EcdsaClientBootstrapContextV1,
    EcdsaClientBootstrapParticipantsV1, FinalizeEcdsaClientBootstrapCommandKindV1,
    FinalizeEcdsaClientBootstrapCommandV1, FinalizeEcdsaClientBootstrapOutputV1,
    PrepareEcdsaClientBootstrapCommandKindV1, PrepareEcdsaClientBootstrapCommandV1,
    PrepareEcdsaClientBootstrapOutputV1, RelayerPublicIdentityV1,
};

const UPDATE_ENV: &str = "UPDATE_NATIVE_READINESS_VECTORS";
const FIXTURE_VERSION: &str = "native_readiness_ecdsa_bootstrap_v1";
const TEST_SECRET_WARNING: &str =
    "Deterministic test-only secret material. Do not use outside tests.";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NativeEcdsaBootstrapVectorV1 {
    fixture_version: String,
    warning: String,
    prepare_command: PrepareEcdsaClientBootstrapCommandV1,
    relayer_root_share32_b64u: String,
    expected_prepare_output: PrepareEcdsaClientBootstrapOutputV1,
    finalize_command: FinalizeEcdsaClientBootstrapCommandV1,
    expected_finalize_output: FinalizeEcdsaClientBootstrapOutputV1,
}

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join("native-readiness")
        .join("ecdsa-bootstrap-v1.json")
}

fn encode_base64_url(input: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(input)
}

fn decode_base64_url(input: &str, field_name: &str) -> Vec<u8> {
    Base64UrlUnpadded::decode_vec(input).unwrap_or_else(|error| {
        panic!("{field_name} must be valid base64url: {error}");
    })
}

fn decode_base64_url_fixed<const N: usize>(input: &str, field_name: &str) -> [u8; N] {
    let bytes = decode_base64_url(input, field_name);
    assert_eq!(bytes.len(), N, "{field_name} must decode to {N} bytes");
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    out
}

fn context() -> EcdsaClientBootstrapContextV1 {
    EcdsaClientBootstrapContextV1 {
        application_binding_digest_b64u: encode_base64_url(&[0x55u8; 32]),
    }
}

fn stable_key_context() -> EcdsaHssStableKeyContext {
    EcdsaHssStableKeyContext::new([0x55u8; 32])
}

fn participants() -> EcdsaClientBootstrapParticipantsV1 {
    EcdsaClientBootstrapParticipantsV1 {
        client_participant_id: 1,
        relayer_participant_id: 2,
        participant_ids: vec![1, 2],
    }
}

fn prepare_command() -> PrepareEcdsaClientBootstrapCommandV1 {
    PrepareEcdsaClientBootstrapCommandV1 {
        kind: PrepareEcdsaClientBootstrapCommandKindV1::PrepareEcdsaClientBootstrapV1,
        algorithm: EcdsaClientBootstrapAlgorithmV1::EcdsaHssSecp256k1RoleLocalV1,
        context: context(),
        participants: participants(),
        secret_source: EcdsaBootstrapSecretSourceV1::WebauthnPrfFirst {
            prf_first_b64u: encode_base64_url(&[0x33u8; 32]),
            rp_id: "localhost".to_owned(),
            credential_id_b64u: encode_base64_url(b"credential"),
        },
    }
}

fn build_vector() -> NativeEcdsaBootstrapVectorV1 {
    let prepare_command = prepare_command();
    let expected_prepare_output =
        prepare_ecdsa_client_bootstrap_command_v1(prepare_command.clone()).expect("prepare");
    let relayer_root_share32_b64u = encode_base64_url(&[0x44u8; 32]);
    let relayer_root_share32 =
        decode_base64_url_fixed::<32>(&relayer_root_share32_b64u, "relayerRootShare32B64u");
    let client_public_key33 = decode_base64_url_fixed::<33>(
        &expected_prepare_output
            .client_bootstrap
            .hss_client_share_public_key33_b64u,
        "clientBootstrap.hssClientSharePublicKey33B64u",
    );
    let (_relayer_share, identity) = derive_relayer_share_for_client_public(
        &stable_key_context(),
        relayer_root_share32,
        &client_public_key33,
        expected_prepare_output
            .client_bootstrap
            .client_share_retry_counter,
    )
    .expect("derive relayer identity");
    let finalize_command = FinalizeEcdsaClientBootstrapCommandV1 {
        kind: FinalizeEcdsaClientBootstrapCommandKindV1::FinalizeEcdsaClientBootstrapV1,
        pending_state_blob: expected_prepare_output.pending_state_blob.clone(),
        relayer_public_identity: RelayerPublicIdentityV1 {
            relayer_key_id: "relayer-key".to_owned(),
            relayer_public_key33_b64u: encode_base64_url(&identity.relayer_public_key33),
            group_public_key33_b64u: encode_base64_url(&identity.threshold_public_key33),
            ethereum_address: hex_prefixed(&identity.threshold_ethereum_address20),
        },
    };
    let expected_finalize_output =
        finalize_ecdsa_client_bootstrap_command_v1(finalize_command.clone()).expect("finalize");

    NativeEcdsaBootstrapVectorV1 {
        fixture_version: FIXTURE_VERSION.to_owned(),
        warning: TEST_SECRET_WARNING.to_owned(),
        prepare_command,
        relayer_root_share32_b64u,
        expected_prepare_output,
        finalize_command,
        expected_finalize_output,
    }
}

fn hex_prefixed(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(2 + bytes.len() * 2);
    out.push_str("0x");
    for byte in bytes {
        use std::fmt::Write;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[test]
fn native_ecdsa_bootstrap_vector_replays_signer_core_commands() {
    let path = fixture_path();

    if env::var(UPDATE_ENV).as_deref() == Ok("1") {
        let generated = serde_json::to_string_pretty(&build_vector()).expect("serialize vector");
        fs::create_dir_all(path.parent().expect("fixture path has parent"))
            .expect("create native readiness fixture directory");
        fs::write(&path, format!("{generated}\n")).expect("write native readiness vector");
        return;
    }

    let fixture_json = fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!(
            "failed to read native readiness vector at {}: {error}",
            path.display()
        )
    });
    let fixture: NativeEcdsaBootstrapVectorV1 =
        serde_json::from_str(&fixture_json).expect("parse native readiness vector");

    assert_eq!(fixture.fixture_version, FIXTURE_VERSION);
    assert_eq!(fixture.warning, TEST_SECRET_WARNING);

    let prepared = prepare_ecdsa_client_bootstrap_command_v1(fixture.prepare_command.clone())
        .expect("prepare command replays");
    assert_eq!(prepared, fixture.expected_prepare_output);
    assert_eq!(
        fixture.finalize_command.pending_state_blob,
        prepared.pending_state_blob
    );

    let relayer_root_share32 =
        decode_base64_url_fixed::<32>(&fixture.relayer_root_share32_b64u, "relayerRootShare32B64u");
    let client_public_key33 = decode_base64_url_fixed::<33>(
        &prepared.client_bootstrap.hss_client_share_public_key33_b64u,
        "clientBootstrap.hssClientSharePublicKey33B64u",
    );
    let (_relayer_share, identity) = derive_relayer_share_for_client_public(
        &stable_key_context(),
        relayer_root_share32,
        &client_public_key33,
        prepared.client_bootstrap.client_share_retry_counter,
    )
    .expect("derive relayer identity");
    assert_eq!(
        fixture
            .finalize_command
            .relayer_public_identity
            .relayer_public_key33_b64u,
        encode_base64_url(&identity.relayer_public_key33)
    );
    assert_eq!(
        fixture
            .finalize_command
            .relayer_public_identity
            .group_public_key33_b64u,
        encode_base64_url(&identity.threshold_public_key33)
    );
    assert_eq!(
        fixture
            .finalize_command
            .relayer_public_identity
            .ethereum_address,
        hex_prefixed(&identity.threshold_ethereum_address20)
    );

    let finalized = finalize_ecdsa_client_bootstrap_command_v1(fixture.finalize_command.clone())
        .expect("finalize command replays");
    assert_eq!(finalized, fixture.expected_finalize_output);
}
