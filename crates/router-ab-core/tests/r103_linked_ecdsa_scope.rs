use base64ct::{Base64UrlUnpadded, Encoding};
use router_ab_core::{
    parse_router_ab_ecdsa_derivation_linked_device_normal_signing_scope_v1_json,
    NormalSigningAuthorizationV1, PublicDigest32,
    RouterAbEcdsaDerivationLinkedDeviceEvmDigestSigningFinalizeRequestV1,
    RouterAbEcdsaDerivationLinkedDeviceEvmDigestSigningRequestV1,
    RouterAbEcdsaDerivationOperationDigestsV1, RouterAbProtocolErrorCode,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

fn b64(bytes: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(bytes)
}

#[test]
fn linked_ecdsa_prepare_and_finalize_bind_the_lane_scope() {
    let scope = parse_router_ab_ecdsa_derivation_linked_device_normal_signing_scope_v1_json(
        &serde_json::to_vec(&valid_scope_json()).expect("scope JSON"),
    )
    .expect("scope parses");
    let signing_digest = digest(9);
    let operation_digests = RouterAbEcdsaDerivationOperationDigestsV1 {
        lane_digest_b64u: digest(8),
        intent_digest_b64u: signing_digest.clone(),
        display_digest_b64u: digest(10),
    };
    let authorization = NormalSigningAuthorizationV1::ReusableWalletSession {
        wallet_session_id: "wallet-session:r103".to_owned(),
    };
    let prepare = RouterAbEcdsaDerivationLinkedDeviceEvmDigestSigningRequestV1 {
        scope: scope.clone(),
        request_id: "request:r103".to_owned(),
        operation_id: "signing-operation:r103".to_owned(),
        operation_digests: operation_digests.clone(),
        authorization: authorization.clone(),
        material_activation: scope.material_activation.clone(),
        client_presignature_id: "presignature:r103".to_owned(),
        expires_at_ms: 20_000,
        signing_digest_b64u: signing_digest.clone(),
        client_rerandomization_commitment32_b64u: digest(11),
    };
    prepare.validate_at(10_000).expect("prepare validates");

    let finalize = RouterAbEcdsaDerivationLinkedDeviceEvmDigestSigningFinalizeRequestV1 {
        scope,
        request_id: prepare.request_id.clone(),
        operation_id: prepare.operation_id.clone(),
        operation_digests,
        authorization,
        material_activation: prepare.material_activation.clone(),
        expires_at_ms: prepare.expires_at_ms,
        signing_digest_b64u: signing_digest,
        server_presignature_id: prepare.client_presignature_id.clone(),
        client_signature_share32_b64u: digest(12),
        client_rerandomization_contribution32_b64u: digest(13),
    };
    finalize.validate_at(10_000).expect("finalize validates");
    assert_ne!(
        prepare.request_digest().expect("prepare digest"),
        finalize.request_digest().expect("finalize digest")
    );
}

fn digest(seed: u8) -> String {
    let digest = Sha256::digest([seed; 32]);
    b64(&digest)
}

fn point(prefix: u8, byte: u8) -> String {
    let mut encoded = [byte; 33];
    encoded[0] = prefix;
    b64(&encoded)
}

fn valid_scope_json() -> Value {
    let digest = digest(7);
    let point = point(2, 0x11);
    json!({
        "kind": "linked_device_ecdsa_normal_signing_scope_v1",
        "keyFamily": "ecdsa_secp256k1",
        "laneKind": "linked_device",
        "walletId": "wallet:r103",
        "walletKeyId": "wallet-key:r103",
        "enrollmentId": "enrollment:r103",
        "operationId": "operation:r103",
        "laneId": "lane:r103",
        "laneShareEpoch": "epoch:r103",
        "revocationEpoch": 0,
        "targetMaterialActivationId": "target-activation:r103",
        "materialActivation": {
            "kind": "mpc_material_activation_ref",
            "activationId": "target-activation:r103",
            "capability": "capability:r103",
            "materialOwner": "material-owner:r103",
            "keyBinding": "key-binding:r103",
            "lifecycleBinding": "lifecycle-binding:r103",
            "signingWorker": "worker-r103"
        },
        "targetCapability": {
            "manifestId": "manifest-target-r103",
            "manifestRevision": 1,
            "ecdsaThresholdKeyId": "threshold-key-r103",
            "orderedThresholdSessions": [{
                "chainTarget": {
                    "kind": "evm",
                    "namespace": "eip155",
                    "chainId": 1,
                    "networkSlug": "mainnet"
                },
                "thresholdSessionId": "threshold-session-r103",
                "participantBindingDigestB64u": digest
            }]
        },
        "thresholdPublicKey33B64u": point,
        "evmAddress": "0x0000000000000000000000000000000000000001",
        "publicIdentityDigestB64u": digest,
        "targetHolderPublicCommitmentB64u": point,
        "targetServerPublicCommitmentB64u": point,
        "holderParticipantId": "holder-r103",
        "signingWorkerParticipantId": "worker-r103",
        "holderParticipantBindingDigestB64u": digest,
        "signingWorkerParticipantBindingDigestB64u": digest,
        "holderRecipientKeyDigestB64u": digest,
        "serverRecipientKeyDigestB64u": digest,
        "signingWorkerRecipientKeyId": "worker-key-r103",
        "signingWorkerHpkePublicKeyB64u": digest,
        "transcriptHashB64u": digest,
        "protocolCommitReceiptDigestB64u": digest
    })
}

#[test]
fn linked_ecdsa_scope_roundtrips_with_canonical_digest() {
    let input = valid_scope_json();
    let scope = parse_router_ab_ecdsa_derivation_linked_device_normal_signing_scope_v1_json(
        &serde_json::to_vec(&input).expect("scope JSON"),
    )
    .expect("scope parses");
    let digest_before = scope.scope_digest().expect("scope digest");
    let encoded = serde_json::to_value(&scope).expect("scope encoding");
    let reparsed = parse_router_ab_ecdsa_derivation_linked_device_normal_signing_scope_v1_json(
        &serde_json::to_vec(&encoded).expect("encoded scope JSON"),
    )
    .expect("encoded scope parses");

    assert_eq!(encoded, input);
    assert_eq!(
        reparsed.scope_digest().expect("reparsed digest"),
        digest_before
    );
    assert_eq!(
        reparsed.material_activation_id().expect("activation id"),
        "target-activation:r103"
    );
}

#[test]
fn linked_ecdsa_scope_rejects_owner_root_context_identity_and_policy_fields() {
    for field in [
        "signingRootId",
        "signingRootVersion",
        "context",
        "publicIdentity",
        "signingWorker",
        "activationEpoch",
        "runtimePolicyScope",
        "authorization",
    ] {
        let mut value = valid_scope_json();
        value
            .as_object_mut()
            .expect("scope object")
            .insert(field.to_owned(), json!("owner-field"));
        let error = parse_router_ab_ecdsa_derivation_linked_device_normal_signing_scope_v1_json(
            &serde_json::to_vec(&value).expect("scope JSON"),
        )
        .expect_err("owner field must be rejected");
        assert_eq!(
            error.code(),
            RouterAbProtocolErrorCode::MalformedWirePayload
        );
    }
}

#[test]
fn linked_ecdsa_scope_rejects_binding_substitution() {
    let mut value = valid_scope_json();
    value["targetMaterialActivationId"] = json!("target-activation:other");
    let error = parse_router_ab_ecdsa_derivation_linked_device_normal_signing_scope_v1_json(
        &serde_json::to_vec(&value).expect("scope JSON"),
    )
    .expect_err("activation substitution must be rejected");
    assert_eq!(
        error.code(),
        RouterAbProtocolErrorCode::InvalidLifecycleState
    );

    let mut value = valid_scope_json();
    value["signingWorkerParticipantId"] = json!("worker-r103:other");
    let error = parse_router_ab_ecdsa_derivation_linked_device_normal_signing_scope_v1_json(
        &serde_json::to_vec(&value).expect("scope JSON"),
    )
    .expect_err("SigningWorker substitution must be rejected");
    assert_eq!(
        error.code(),
        RouterAbProtocolErrorCode::InvalidLifecycleState
    );
}

#[test]
fn linked_ecdsa_scope_digest_binds_transcript_and_lane_fields() {
    let mut value = valid_scope_json();
    let original = parse_router_ab_ecdsa_derivation_linked_device_normal_signing_scope_v1_json(
        &serde_json::to_vec(&value).expect("scope JSON"),
    )
    .expect("scope parses")
    .scope_digest()
    .expect("scope digest");

    value["transcriptHashB64u"] = json!(digest(8));
    let changed_transcript =
        parse_router_ab_ecdsa_derivation_linked_device_normal_signing_scope_v1_json(
            &serde_json::to_vec(&value).expect("scope JSON"),
        )
        .expect("changed transcript parses")
        .scope_digest()
        .expect("changed digest");
    assert_ne!(changed_transcript, original);

    value["transcriptHashB64u"] = json!(digest(7));
    value["laneId"] = json!("lane:r103:other");
    let changed_lane = parse_router_ab_ecdsa_derivation_linked_device_normal_signing_scope_v1_json(
        &serde_json::to_vec(&value).expect("scope JSON"),
    )
    .expect("changed lane parses")
    .scope_digest()
    .expect("changed digest");
    assert_ne!(changed_lane, original);
    assert_ne!(changed_lane, PublicDigest32::new([0; 32]));

    value["laneId"] = json!("lane:r103");
    value["materialActivation"]["materialOwner"] = json!("material-owner:r103:other");
    let changed_material_owner =
        parse_router_ab_ecdsa_derivation_linked_device_normal_signing_scope_v1_json(
            &serde_json::to_vec(&value).expect("scope JSON"),
        )
        .expect("changed material owner parses")
        .scope_digest()
        .expect("changed digest");
    assert_ne!(changed_material_owner, original);
}
