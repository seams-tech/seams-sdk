use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use router_ab_cloudflare::{
    parse_cloudflare_router_authorized_linked_device_ecdsa_finalize_request_v1_json,
    CloudflareRouterAuthContextV1, CloudflareRouterEcdsaAcceptedAuthorizedOperationV1,
    CloudflareRouterEcdsaAcceptedCapabilityBindingV1, CloudflareRouterEcdsaAuthorizedOperationV1,
    CloudflareRouterEcdsaCapabilityKindV1, CloudflareRouterEcdsaOperationKindV1,
    CloudflareRouterNormalSigningTrustedAdmissionV1,
    CloudflareRouterNormalSigningTrustedMetadataV1, CloudflareSecretMaterial32V1,
    CloudflareServerOutputMaterialRecordV1,
    CloudflareSigningWorkerAdmittedLinkedDeviceEcdsaPrepareRequestV1,
    CloudflareSigningWorkerLaneKeyFamilyV1, CloudflareSigningWorkerLaneMaterialIdentityV1,
    CloudflareSigningWorkerLinkedDeviceEcdsaPresignSessionBindingV1,
    CloudflareSigningWorkerMaterializedLinkedDeviceEcdsaPrepareRequestV1,
    CloudflareSigningWorkerNormalSigningLaneMaterialLookupV1,
    CloudflareSigningWorkerNormalSigningMaterialSourceV1,
};
use router_ab_core::{
    parse_router_ab_ecdsa_derivation_linked_device_normal_signing_scope_v1_json,
    ActiveSigningWorkerStateV1, ExpensiveWorkGateDecisionV1, NormalSigningAuthorizationV1,
    OpenedShareKind, PublicDigest32, Role,
    RouterAbEcdsaDerivationLinkedDeviceEvmDigestSigningFinalizeRequestV1,
    RouterAbEcdsaDerivationLinkedDeviceEvmDigestSigningResponseV1,
    RouterAbEcdsaDerivationOperationDigestsV1, RouterAbEcdsaDerivationSignatureSchemeV1,
    RouterAbProtocolErrorCode, ServerIdentityV1,
};
use router_ab_ecdsa_derivation::ecdsa_lane_client_public_key_from_share32_v1;
use serde_json::json;
use sha2::{Digest, Sha256};

fn digest(seed: u8) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest([seed; 32]))
}

fn public_digest(seed: u8) -> PublicDigest32 {
    PublicDigest32::new(Sha256::digest([seed; 32]).into())
}

fn point() -> String {
    URL_SAFE_NO_PAD
        .encode(ecdsa_lane_client_public_key_from_share32_v1([1; 32]).expect("valid secp share"))
}

fn scope() -> router_ab_core::RouterAbEcdsaDerivationLinkedDeviceNormalSigningScopeV1 {
    let digest = digest(7);
    let point = point();
    let value = json!({
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
        "targetMaterialActivationId": "activation:r103",
        "materialActivation": {
            "kind": "mpc_material_activation_ref",
            "activationId": "activation:r103",
            "capability": "capability:r103",
            "materialOwner": "material-owner:r103",
            "keyBinding": "key-binding:r103",
            "lifecycleBinding": "lifecycle:r103",
            "signingWorker": "worker:r103"
        },
        "targetCapability": {
            "manifestId": "manifest:r103",
            "manifestRevision": 1,
            "ecdsaThresholdKeyId": "threshold-key:r103",
            "orderedThresholdSessions": [{
                "chainTarget": {
                    "kind": "evm",
                    "namespace": "eip155",
                    "chainId": 1,
                    "networkSlug": "mainnet"
                },
                "thresholdSessionId": "threshold-session:r103",
                "participantBindingDigestB64u": digest
            }]
        },
        "thresholdPublicKey33B64u": point,
        "evmAddress": "0x0000000000000000000000000000000000000001",
        "publicIdentityDigestB64u": digest,
        "targetHolderPublicCommitmentB64u": point,
        "targetServerPublicCommitmentB64u": point,
        "holderParticipantId": "holder:r103",
        "signingWorkerParticipantId": "worker:r103",
        "holderParticipantBindingDigestB64u": digest,
        "signingWorkerParticipantBindingDigestB64u": digest,
        "holderRecipientKeyDigestB64u": digest,
        "serverRecipientKeyDigestB64u": digest,
        "signingWorkerRecipientKeyId": "worker-key:r103",
        "signingWorkerHpkePublicKeyB64u": digest,
        "transcriptHashB64u": digest,
        "protocolCommitReceiptDigestB64u": digest
    });
    parse_router_ab_ecdsa_derivation_linked_device_normal_signing_scope_v1_json(
        &serde_json::to_vec(&value).expect("scope JSON"),
    )
    .expect("scope parses")
}

fn material_source(
    scope: &router_ab_core::RouterAbEcdsaDerivationLinkedDeviceNormalSigningScopeV1,
) -> CloudflareSigningWorkerNormalSigningMaterialSourceV1 {
    let identity = CloudflareSigningWorkerLaneMaterialIdentityV1 {
        operation_id: scope.operation_id.clone(),
        enrollment_id: scope.enrollment_id.clone(),
        wallet_id: scope.wallet_id.clone(),
        wallet_key_id: scope.wallet_key_id.clone(),
        target_lane_id: scope.lane_id.clone(),
        target_lane_share_epoch: scope.lane_share_epoch.clone(),
        target_material_activation_id: scope.target_material_activation_id.clone(),
        key_family: CloudflareSigningWorkerLaneKeyFamilyV1::EcdsaSecp256k1,
        holder_participant_binding_digest_b64u: scope
            .holder_participant_binding_digest_b64u
            .clone(),
        signing_worker_participant_binding_digest_b64u: scope
            .signing_worker_participant_binding_digest_b64u
            .clone(),
        holder_recipient_key_digest_b64u: scope.holder_recipient_key_digest_b64u.clone(),
        server_recipient_key_digest_b64u: scope.server_recipient_key_digest_b64u.clone(),
        transcript_hash_b64u: scope.transcript_hash_b64u.clone(),
        protocol_commit_receipt_digest_b64u: scope.protocol_commit_receipt_digest_b64u.clone(),
    };
    let admitted_lane_identity_digest_b64u = identity.digest_b64u().expect("identity digest");
    CloudflareSigningWorkerNormalSigningMaterialSourceV1::RotatableLane {
        lookup: CloudflareSigningWorkerNormalSigningLaneMaterialLookupV1 {
            identity,
            admitted_lane_identity_digest_b64u,
        },
        group_public_key: scope.threshold_public_key33_b64u.clone(),
    }
}

fn finalize_request(
    scope: router_ab_core::RouterAbEcdsaDerivationLinkedDeviceNormalSigningScopeV1,
) -> RouterAbEcdsaDerivationLinkedDeviceEvmDigestSigningFinalizeRequestV1 {
    let material_activation = scope.material_activation.clone();
    RouterAbEcdsaDerivationLinkedDeviceEvmDigestSigningFinalizeRequestV1 {
        scope,
        request_id: "request:r103".to_owned(),
        operation_id: "signing-operation:r103".to_owned(),
        operation_digests: RouterAbEcdsaDerivationOperationDigestsV1 {
            lane_digest_b64u: digest(1),
            intent_digest_b64u: digest(2),
            display_digest_b64u: digest(3),
        },
        authorization: NormalSigningAuthorizationV1::ReusableWalletSession {
            wallet_session_id: "wallet-session:r103".to_owned(),
        },
        material_activation,
        expires_at_ms: 2_000,
        signing_digest_b64u: digest(2),
        server_presignature_id: "presignature:r103".to_owned(),
        client_signature_share32_b64u: digest(4),
        client_rerandomization_contribution32_b64u: digest(5),
    }
}

fn accepted_operation(
    request: &RouterAbEcdsaDerivationLinkedDeviceEvmDigestSigningFinalizeRequestV1,
) -> CloudflareRouterEcdsaAcceptedAuthorizedOperationV1 {
    CloudflareRouterEcdsaAcceptedAuthorizedOperationV1 {
        binding: CloudflareRouterEcdsaAcceptedCapabilityBindingV1::ReusableWalletSession {
            authorization_id: "authorization:r103".to_owned(),
            wallet_session_id: "wallet-session:r103".to_owned(),
            quota_id: "quota:r103".to_owned(),
        },
        authorized_operation:
            CloudflareRouterEcdsaAuthorizedOperationV1::ReusableWalletSessionAuthorizedOperationV1 {
                authorized_operation_id: "authorized-operation:r103".to_owned(),
                operation_id: request.operation_id.clone(),
                capability_kind: CloudflareRouterEcdsaCapabilityKindV1::EvmEcdsaMpcSigning,
                operation_kind: CloudflareRouterEcdsaOperationKindV1::SignTransaction,
                lane_digest_b64u: request.operation_digests.lane_digest_b64u.clone(),
                intent_digest_b64u: request.operation_digests.intent_digest_b64u.clone(),
                display_digest_b64u: request.operation_digests.display_digest_b64u.clone(),
                operation_fingerprint_digest: digest(12),
            },
    }
}

#[test]
fn router_adapts_the_flat_gateway_finalize_without_owner_policy_claims() {
    let scope = scope();
    let request = finalize_request(scope.clone());
    let mut value = serde_json::to_value(&request)
        .expect("request JSON")
        .as_object()
        .expect("request object")
        .clone();
    value.insert(
        "authorized_operation".to_owned(),
        serde_json::to_value(accepted_operation(&request)).expect("authorized operation JSON"),
    );
    value.insert(
        "material_source".to_owned(),
        serde_json::to_value(material_source(&scope)).expect("material source JSON"),
    );
    let admitted = parse_cloudflare_router_authorized_linked_device_ecdsa_finalize_request_v1_json(
        &serde_json::to_vec(&value).expect("flat Gateway JSON"),
    )
    .expect("flat Gateway finalize adapts");
    admitted.validate().expect("admitted finalize validates");
    assert_eq!(admitted.request, request);

    value.insert(
        "authorized_operation".to_owned(),
        serde_json::to_value(CloudflareRouterEcdsaAcceptedAuthorizedOperationV1 {
            binding: CloudflareRouterEcdsaAcceptedCapabilityBindingV1::ReusableWalletSession {
                authorization_id: "authorization:r103".to_owned(),
                wallet_session_id: "wallet-session:other".to_owned(),
                quota_id: "quota:r103".to_owned(),
            },
            ..accepted_operation(&request)
        })
        .expect("substituted authorized operation JSON"),
    );
    parse_cloudflare_router_authorized_linked_device_ecdsa_finalize_request_v1_json(
        &serde_json::to_vec(&value).expect("substituted Gateway JSON"),
    )
    .expect_err("Wallet Session substitution is rejected");
}

#[test]
fn linked_ecdsa_material_source_requires_the_exact_lane_identity() {
    let scope = scope();
    let source = material_source(&scope);
    source
        .validate_for_linked_ecdsa_scope(&scope)
        .expect("exact lane source validates");

    let CloudflareSigningWorkerNormalSigningMaterialSourceV1::RotatableLane {
        mut lookup,
        group_public_key,
    } = source
    else {
        panic!("expected lane material");
    };
    lookup.identity.wallet_key_id = "wallet-key:other".to_owned();
    lookup.admitted_lane_identity_digest_b64u =
        lookup.identity.digest_b64u().expect("identity digest");
    let substituted = CloudflareSigningWorkerNormalSigningMaterialSourceV1::RotatableLane {
        lookup,
        group_public_key,
    };
    let error = substituted
        .validate_for_linked_ecdsa_scope(&scope)
        .expect_err("wallet-key substitution is rejected");
    assert_eq!(error.code(), RouterAbProtocolErrorCode::InvalidGateDecision);
}

#[test]
fn linked_ecdsa_material_source_rejects_owner_registration_material() {
    let scope = scope();
    let source = CloudflareSigningWorkerNormalSigningMaterialSourceV1::RegistrationActivation {
        lookup: router_ab_cloudflare::CloudflareActiveSigningWorkerStateLookupV1::new(
            scope.wallet_id.clone(),
            scope.target_material_activation_id.clone(),
            scope.signing_worker_participant_id.clone(),
        )
        .expect("lookup"),
    };
    let error = source
        .validate_for_linked_ecdsa_scope(&scope)
        .expect_err("owner material is rejected");
    assert_eq!(error.code(), RouterAbProtocolErrorCode::InvalidGateDecision);
}

#[test]
fn linked_ecdsa_response_binds_the_exact_finalize_request() {
    let scope = scope();
    let request = RouterAbEcdsaDerivationLinkedDeviceEvmDigestSigningFinalizeRequestV1 {
        scope: scope.clone(),
        request_id: "request:r103".to_owned(),
        operation_id: "operation:r103".to_owned(),
        operation_digests: RouterAbEcdsaDerivationOperationDigestsV1 {
            lane_digest_b64u: digest(1),
            intent_digest_b64u: digest(2),
            display_digest_b64u: digest(3),
        },
        authorization: NormalSigningAuthorizationV1::ReusableWalletSession {
            wallet_session_id: "wallet-session:r103".to_owned(),
        },
        material_activation: scope.material_activation.clone(),
        expires_at_ms: 2_000,
        signing_digest_b64u: digest(2),
        server_presignature_id: "presignature:r103".to_owned(),
        client_signature_share32_b64u: digest(4),
        client_rerandomization_contribution32_b64u: digest(5),
    };
    let response = RouterAbEcdsaDerivationLinkedDeviceEvmDigestSigningResponseV1 {
        scope,
        request_id: request.request_id.clone(),
        request_digest: request.request_digest().expect("request digest"),
        signing_digest: request.signing_digest().expect("signing digest"),
        signature_scheme: RouterAbEcdsaDerivationSignatureSchemeV1::EcdsaSecp256k1RecoverableV1,
        signature65_b64u: URL_SAFE_NO_PAD.encode([0x01; 65]),
    };
    response
        .validate_for_request(&request)
        .expect("response binds exact request");

    let substituted = RouterAbEcdsaDerivationLinkedDeviceEvmDigestSigningResponseV1 {
        request_id: "request:other".to_owned(),
        ..response
    };
    let error = substituted
        .validate_for_request(&request)
        .expect_err("request substitution is rejected");
    assert_eq!(
        error.code(),
        RouterAbProtocolErrorCode::InvalidLifecycleState
    );
}

#[test]
fn linked_ecdsa_prepared_bundle_binds_request_and_material() {
    let scope = scope();
    let finalize_request = RouterAbEcdsaDerivationLinkedDeviceEvmDigestSigningFinalizeRequestV1 {
        scope: scope.clone(),
        request_id: "request:r103".to_owned(),
        operation_id: "operation:r103".to_owned(),
        operation_digests: RouterAbEcdsaDerivationOperationDigestsV1 {
            lane_digest_b64u: digest(1),
            intent_digest_b64u: digest(2),
            display_digest_b64u: digest(3),
        },
        authorization: NormalSigningAuthorizationV1::ReusableWalletSession {
            wallet_session_id: "wallet-session:r103".to_owned(),
        },
        material_activation: scope.material_activation.clone(),
        expires_at_ms: 2_000,
        signing_digest_b64u: digest(2),
        server_presignature_id: "presignature:r103".to_owned(),
        client_signature_share32_b64u: digest(4),
        client_rerandomization_contribution32_b64u: digest(5),
    };
    let prepare_request = finalize_request.prepare_request().expect("prepare request");
    let trusted_metadata = CloudflareRouterNormalSigningTrustedMetadataV1::new(
        "org:r103",
        "project:r103",
        "test",
        scope.wallet_id.clone(),
        CloudflareRouterAuthContextV1::authenticated_session("subject:r103", "wallet-session:r103")
            .expect("auth"),
        public_digest(10),
        prepare_request.request_digest().expect("request digest"),
    )
    .expect("trusted metadata");
    let trusted_admission = CloudflareRouterNormalSigningTrustedAdmissionV1::new(
        trusted_metadata,
        ExpensiveWorkGateDecisionV1::accepted(prepare_request.request_id.clone())
            .expect("accepted gate decision"),
    )
    .expect("trusted admission");
    let admitted = CloudflareSigningWorkerAdmittedLinkedDeviceEcdsaPrepareRequestV1::new(
        prepare_request.clone(),
        trusted_admission,
        material_source(&scope),
    )
    .expect("admitted prepare request");
    let signing_worker = ServerIdentityV1::new(
        scope.signing_worker_participant_id.clone(),
        scope.signing_worker_recipient_key_id.clone(),
        scope.signing_worker_hpke_public_key_b64u.clone(),
    )
    .expect("signing worker");
    let active_signing_worker = ActiveSigningWorkerStateV1::new(
        scope.wallet_id.clone(),
        scope.material_activation.clone(),
        "account-key:r103",
        signing_worker,
        public_digest(7),
        public_digest(8),
        "material-handle:r103",
        1_000,
    )
    .expect("active signing worker");
    let material = CloudflareServerOutputMaterialRecordV1::new(
        public_digest(7),
        OpenedShareKind::XServerBase,
        Role::Server,
        scope.signing_worker_participant_id.clone(),
        CloudflareSecretMaterial32V1::new([1; 32]),
    )
    .expect("server material");
    let materialized = CloudflareSigningWorkerMaterializedLinkedDeviceEcdsaPrepareRequestV1::new(
        admitted,
        active_signing_worker.clone(),
        material,
        1_000,
    )
    .expect("materialized prepare request");
    let mut presignature97 = URL_SAFE_NO_PAD.decode(point()).expect("R point");
    presignature97.extend([8; 32]);
    presignature97.extend([9; 32]);
    let binding = CloudflareSigningWorkerLinkedDeviceEcdsaPresignSessionBindingV1::new(
        &materialized,
        "presign-session:r103",
    )
    .expect("presign session binding");
    let prepared = binding
        .complete_from_presignature_output(&materialized, &presignature97, digest(6), 1_500)
        .expect("prepared bundle");

    assert_eq!(prepared.response.request_id, prepare_request.request_id);
    assert_eq!(
        prepared.response.request_digest,
        prepare_request.request_digest().expect("request digest")
    );
    assert_eq!(prepared.record.created_at_ms, 1_500);

    let mut substituted = prepared;
    substituted.record.request_digest = public_digest(11);
    let error = substituted
        .validate_for_request(&materialized)
        .expect_err("request digest substitution is rejected");
    assert_eq!(
        error.code(),
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig
    );

    let mut substituted_binding = binding;
    substituted_binding.operation_id = "operation:other".to_owned();
    let error = substituted_binding
        .complete_from_presignature_output(&materialized, &presignature97, digest(6), 1_500)
        .expect_err("operation substitution is rejected");
    assert_eq!(
        error.code(),
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig
    );
}
