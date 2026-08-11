use base64ct::{Base64UrlUnpadded, Encoding};
use router_ab_core::{
    parse_router_ab_ecdsa_derivation_linked_device_normal_signing_scope_v1_json, PublicDigest32,
    RouterAbProtocolErrorCode,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

fn b64(bytes: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(bytes)
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
            "signingWorker": "signing-worker:r103"
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
