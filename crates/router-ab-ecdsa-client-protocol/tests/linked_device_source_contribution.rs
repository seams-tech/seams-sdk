#![cfg(feature = "hpke")]

use base64ct::{Base64UrlUnpadded, Encoding};
use hpke_ng::{DhKemX25519HkdfSha256, Kem};
use router_ab_ecdsa_client_protocol::{
    open_linked_device_ecdsa_source_contribution_v1,
    seal_linked_device_ecdsa_source_contribution_v1, EcdsaMaterialActivationRefKindV1,
    EcdsaMaterialActivationRefV1, LinkedDeviceEcdsaSourceContributionPackageV1,
    LinkedDeviceEcdsaSourceContributionPreparationV1, LinkedDeviceEcdsaSourceSignerIdentityV1,
    LinkedDeviceEcdsaTargetRecipientPreparationV1,
};
use router_ab_ecdsa_derivation::{
    derive_client_share, derive_ecdsa_lane_delta_from_source_share32_v1,
    derive_relayer_share_for_client_public, rebind_ecdsa_lane_relayer_share_bytes_v1,
    sample_ecdsa_lane_client_share_v1, EcdsaLaneDelta, EcdsaLanePublicIdentityBindingV1,
    RouterAbEcdsaDerivationStableKeyContext,
};

fn b64(bytes: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(bytes)
}

fn x25519_keypair(seed: u8) -> ([u8; 32], String) {
    let (private, public) = DhKemX25519HkdfSha256::derive_key_pair(&[seed; 32]).expect("keypair");
    let private: [u8; 32] = DhKemX25519HkdfSha256::sk_to_bytes(&private)
        .as_slice()
        .try_into()
        .expect("private key bytes");
    let public = b64(DhKemX25519HkdfSha256::pk_to_bytes(&public).as_ref());
    (private, public)
}

fn activation(id: &str) -> EcdsaMaterialActivationRefV1 {
    EcdsaMaterialActivationRefV1 {
        kind: EcdsaMaterialActivationRefKindV1::MpcMaterialActivationRef,
        activation_id: id.to_owned(),
        capability: format!("capability-{id}"),
        material_owner: "wallet-1".to_owned(),
        key_binding: format!("key-binding-{id}"),
        lifecycle_binding: format!("lifecycle-binding-{id}"),
        signing_worker: "worker-1".to_owned(),
    }
}

#[test]
fn source_contribution_package_rebinds_server_share_without_threshold_drift() {
    let context = RouterAbEcdsaDerivationStableKeyContext::new([0x51; 32]);
    let source_client = derive_client_share(&context, [0x11; 32]).expect("source client");
    let (source_relayer, source_identity) = derive_relayer_share_for_client_public(
        &context,
        [0x22; 32],
        &source_client.derivation_client_share_public_key33,
        source_client.retry_counter,
    )
    .expect("source relayer");
    let target_client = sample_ecdsa_lane_client_share_v1([0x33; 32]).expect("target client");
    let delta =
        derive_ecdsa_lane_delta_from_source_share32_v1(source_client.x_client32, &target_client)
            .expect("delta");
    let (_client_private, client_public) = x25519_keypair(0x41);
    let (worker_private, worker_public) = x25519_keypair(0x42);
    let preparation = LinkedDeviceEcdsaSourceContributionPreparationV1 {
        link_session_id: "link-1".to_owned(),
        enrollment_id: "enrollment-1".to_owned(),
        source_authority_id: "authority-1".to_owned(),
        source: LinkedDeviceEcdsaSourceSignerIdentityV1 {
            activation: activation("source-activation"),
            client_public_key33_b64u: b64(&source_identity.derivation_client_share_public_key33),
            relayer_public_key33_b64u: b64(&source_identity.relayer_public_key33),
            threshold_public_key33_b64u: b64(&source_identity.threshold_public_key33),
            threshold_ethereum_address20_b64u: b64(&source_identity.threshold_ethereum_address20),
        },
        target: LinkedDeviceEcdsaTargetRecipientPreparationV1 {
            activation: activation("target-activation"),
            target_device_id: "device-2".to_owned(),
            target_factor_verification_digest_b64u: b64(&[0x71; 32]),
            client_recipient_public_key_b64u: client_public,
            signing_worker_recipient_public_key_b64u: worker_public,
        },
    };
    let binding = preparation
        .bind_target_client_public_key(b64(target_client.public_key33()))
        .expect("binding");
    let binding_digest = binding.digest().expect("binding digest");
    let encrypted_delta = seal_linked_device_ecdsa_source_contribution_v1(
        &binding.target.signing_worker_recipient_public_key_b64u,
        &binding_digest,
        delta.as_bytes(),
        [0x52; 32],
    )
    .expect("delta seal");
    let encrypted_target_client_share = seal_linked_device_ecdsa_source_contribution_v1(
        &binding.target.client_recipient_public_key_b64u,
        &binding_digest,
        target_client.secret_bytes(),
        [0x53; 32],
    )
    .expect("client share seal");
    let package = LinkedDeviceEcdsaSourceContributionPackageV1 {
        binding,
        encrypted_delta,
        encrypted_target_client_share,
    };
    package.validate().expect("package");
    let opened_delta = open_linked_device_ecdsa_source_contribution_v1(
        &package.encrypted_delta,
        &worker_private,
        &binding_digest,
    )
    .expect("delta open");
    let delta32: [u8; 32] = opened_delta.try_into().expect("delta length");
    let rebound = rebind_ecdsa_lane_relayer_share_bytes_v1(
        source_relayer.x_relayer32,
        &EcdsaLanePublicIdentityBindingV1 {
            source_client_public_key33: source_identity.derivation_client_share_public_key33,
            source_relayer_public_key33: source_identity.relayer_public_key33,
            threshold_public_key33: source_identity.threshold_public_key33,
            threshold_ethereum_address20: source_identity.threshold_ethereum_address20,
        },
        &EcdsaLaneDelta::from_bytes(delta32).expect("delta scalar"),
        *target_client.public_key33(),
    )
    .expect("rebind");
    assert_eq!(
        rebound.target_threshold_public_key33,
        source_identity.threshold_public_key33
    );
    assert_eq!(
        rebound.target_ethereum_address20,
        source_identity.threshold_ethereum_address20
    );
}
