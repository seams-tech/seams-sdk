#![cfg(not(target_arch = "wasm32"))]

use base64::Engine;
use ed25519_dalek::{Signature as Ed25519Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hpke_ng::{DhKemX25519HkdfSha256, Kem};
use rand_core_06::SeedableRng;
use router_ab_cloudflare::{
    build_cloudflare_ecdsa_threshold_prf_proof_batch_peer_message_v1,
    build_cloudflare_preloaded_signer_host_v1,
    build_cloudflare_preloaded_signer_host_with_root_share_wire_v1,
    build_cloudflare_router_public_keyset_v2,
    cloudflare_active_signing_worker_state_from_activation_request_v1,
    cloudflare_recipient_proof_bundle_response_from_ab_proof_batch_v1,
    cloudflare_router_ab_ecdsa_derivation_activation_receipt_from_material_v1,
    cloudflare_router_ab_ecdsa_derivation_activation_refresh_receipt_from_material_v1,
    cloudflare_router_ab_ecdsa_derivation_normal_signing_scope_from_activation_receipt_v1,
    cloudflare_router_ab_ecdsa_derivation_public_identity_from_activation_material_v1,
    cloudflare_router_ab_ecdsa_derivation_public_identity_from_normal_signing_material_v1,
    cloudflare_router_ab_ecdsa_derivation_stable_key_context_v1,
    cloudflare_router_normal_signing_cors_allowed_origin_v1,
    cloudflare_signer_private_bootstrap_from_ecdsa_derivation_registration_v1,
    cloudflare_signer_private_bootstrap_from_public_request_v1,
    decode_and_select_cloudflare_signer_envelope_hpke_decrypt_key_binding_v1,
    decode_and_validate_cloudflare_root_share_wire_secret_v1,
    decode_and_validate_cloudflare_signer_envelope_hpke_payload_v1,
    decode_and_validate_cloudflare_signer_input_plaintext_v1,
    decode_and_verify_cloudflare_ecdsa_threshold_prf_proof_batch_message_v1,
    decode_cloudflare_peer_verifying_key_hex_v1, decode_cloudflare_root_share_wire_secret_v1,
    decode_cloudflare_server_output_hpke_private_key_secret_v1,
    decode_cloudflare_signer_envelope_hpke_private_key_secret_v1,
    derive_cloudflare_router_trusted_admission_from_provider_v1,
    derive_cloudflare_router_trusted_admission_v1,
    encode_cloudflare_server_output_hpke_private_key_secret_v1,
    encode_cloudflare_signer_envelope_hpke_private_key_secret_v1,
    evaluate_cloudflare_validated_mpc_prf_batch_output_v1,
    handle_cloudflare_deriver_a_recipient_proof_bundle_activation_request_v1,
    handle_cloudflare_deriver_peer_request_v1, handle_cloudflare_durable_object_call_v1,
    handle_cloudflare_signer_recipient_proof_bundle_private_request_v1,
    handle_cloudflare_signing_worker_normal_signing_finalize_private_request_v2,
    handle_cloudflare_signing_worker_normal_signing_prepare_private_request_v2,
    handle_cloudflare_signing_worker_router_ab_ecdsa_derivation_evm_digest_finalize_private_request_v1,
    handle_cloudflare_validated_mpc_prf_recipient_proof_bundle_signer_request_v1,
    open_cloudflare_signer_envelope_hpke_payload_v1, parse_cloudflare_deriver_a_bindings_v1,
    parse_cloudflare_deriver_b_bindings_v1, parse_cloudflare_deriver_peer_verifying_key_set_v1,
    parse_cloudflare_router_admission_bindings_v1,
    parse_cloudflare_signer_envelope_hpke_decrypt_key_binding_set_v1,
    parse_cloudflare_signer_envelope_hpke_decrypt_key_binding_v1,
    parse_cloudflare_signer_envelope_hpke_public_key_set_v1,
    parse_cloudflare_signer_envelope_hpke_rotation_public_key_set_v1,
    parse_cloudflare_signing_worker_bindings_v1, parse_cloudflare_worker_bindings_v1,
    prepare_cloudflare_role_separated_router_ab_ecdsa_derivation_evm_digest_from_pool_record_v1,
    seal_cloudflare_signer_envelope_hpke_payload_v1, validate_cloudflare_deriver_peer_request_v1,
    validate_cloudflare_deriver_peer_response_v1,
    validate_cloudflare_peer_signing_key_matches_request_v1,
    validate_cloudflare_router_ab_ecdsa_derivation_activation_refresh_request_for_router_payload_v1,
    validate_cloudflare_router_ab_ecdsa_derivation_export_request_for_router_payload_v1,
    validate_cloudflare_router_ab_ecdsa_derivation_normal_signing_active_material_v1,
    validate_cloudflare_router_ab_ecdsa_derivation_recovery_request_for_router_payload_v1,
    validate_cloudflare_router_ab_ecdsa_derivation_registration_request_for_router_payload_v1,
    validate_cloudflare_signer_private_request_plaintext_v1,
    validate_cloudflare_signer_private_request_v1,
    validate_cloudflare_signer_recipient_proof_bundle_private_response_v1,
    verify_cloudflare_deriver_peer_message_authentication_v1,
    CloudflareActiveSigningWorkerStateLookupV1, CloudflareDerivationCeremonyPutReceiptV1,
    CloudflareDerivationCeremonyStateLabelV1, CloudflareDerivationCeremonyV1,
    CloudflareDeriverABindingsV1, CloudflareDeriverAWorkerRuntimeV1, CloudflareDeriverBBindingsV1,
    CloudflareDeriverBWorkerRuntimeV1, CloudflareDurableObjectBindingV1,
    CloudflareDurableObjectCallV1, CloudflareDurableObjectMemoryStorageV1,
    CloudflareDurableObjectOperationKindV1, CloudflareDurableObjectRequestV1,
    CloudflareDurableObjectResponseV1, CloudflareDurableObjectScopeV1,
    CloudflareDurableObjectStorageV1, CloudflareEd25519Round1StateV1,
    CloudflareEd25519YaoNormalSigningHandlerV1, CloudflareEnvMapV1,
    CloudflareExpiredStateCleanupReportV1, CloudflareExpiredStateCleanupRequestV1,
    CloudflareLifecyclePutReceiptV1, CloudflarePeerBindingV1, CloudflarePreloadedSignerHostV1,
    CloudflareReplayReserveRequestV1, CloudflareReplayReserveResponseV1,
    CloudflareRoleSeparatedRouterAbEcdsaDerivationEvmDigestFinalizeHandlerV1,
    CloudflareRootShareLookupRequestV1, CloudflareRootShareRewrapRequestV1,
    CloudflareRootShareStartupMetadataV1, CloudflareRootShareWireSecretBindingV1,
    CloudflareRouterAbEcdsaDerivationActivationRefreshAdmissionResponseV1,
    CloudflareRouterAbEcdsaDerivationDeriverActivationRefreshPrivateRequestV1,
    CloudflareRouterAbEcdsaDerivationDeriverExportPrivateRequestV1,
    CloudflareRouterAbEcdsaDerivationDeriverRecoveryPrivateRequestV1,
    CloudflareRouterAbEcdsaDerivationDeriverRegistrationPrivateRequestV1,
    CloudflareRouterAbEcdsaDerivationEvmDigestFinalizeAdmissionCandidateV1,
    CloudflareRouterAbEcdsaDerivationEvmDigestPrepareAdmissionCandidateV1,
    CloudflareRouterAbEcdsaDerivationRecoveryAdmissionResponseV1,
    CloudflareRouterAbEcdsaDerivationSigningWorkerActivationReceiptV1,
    CloudflareRouterAbEcdsaDerivationSigningWorkerActivationRefreshRequestV1,
    CloudflareRouterAbEcdsaDerivationSigningWorkerActivationRequestV1,
    CloudflareRouterAbuseCheckV1, CloudflareRouterAbuseRecordV1, CloudflareRouterAbuseStoreV1,
    CloudflareRouterAdmissionBindingsV1, CloudflareRouterAdmissionChecksV1,
    CloudflareRouterAdmissionProviderOutputV1, CloudflareRouterAdmissionProviderV1,
    CloudflareRouterAdmissionStoreRequestV1,
    CloudflareRouterAllowedWorkKindsProjectPolicyProviderV1, CloudflareRouterAuthContextV1,
    CloudflareRouterBearerAuthorizationV1, CloudflareRouterBindingsV1,
    CloudflareRouterCompositeAdmissionProviderV1, CloudflareRouterConfiguredAbuseProviderV1,
    CloudflareRouterConfiguredQuotaProviderV1, CloudflareRouterEd25519JwksJwtVerifierV1,
    CloudflareRouterJwtSessionProviderV1, CloudflareRouterJwtVerifierBindingV1,
    CloudflareRouterJwtVerifierV1, CloudflareRouterNormalSigningAdmissionStoreRequestV1,
    CloudflareRouterNormalSigningFinalizeAdmissionCandidateV2,
    CloudflareRouterNormalSigningPrepareAdmissionCandidateV2,
    CloudflareRouterNormalSigningTrustedAdmissionV1,
    CloudflareRouterNormalSigningTrustedMetadataV1, CloudflareRouterProjectPolicyRecordV1,
    CloudflareRouterProjectPolicyStoreV1, CloudflareRouterProjectPolicyV1,
    CloudflareRouterPublicAdmissionPlanV1, CloudflareRouterQuotaCheckV1,
    CloudflareRouterQuotaReservationV1, CloudflareRouterQuotaStoreV1,
    CloudflareRouterRecipientProofBundleResponseV1, CloudflareRouterStoredAbuseProviderV1,
    CloudflareRouterStoredProjectPolicyProviderV1, CloudflareRouterStoredQuotaProviderV1,
    CloudflareRouterTrustedAdmissionV1, CloudflareRouterTrustedRequestMetadataV1,
    CloudflareRouterVerifiedJwtClaimsV1, CloudflareRouterVerifiedSessionProviderV1,
    CloudflareRouterVerifiedSessionV1, CloudflareRouterVerifiedWalletSessionV1,
    CloudflareRouterWalletBudgetCurveV1, CloudflareRouterWalletBudgetPutGrantRequestV1,
    CloudflareRouterWalletBudgetReserveRequestV1, CloudflareRouterWalletBudgetSignerBindingV1,
    CloudflareRouterWalletSessionCredentialV1, CloudflareRouterWalletSessionVerifierV1,
    CloudflareRouterWorkerRuntimeV1, CloudflareSecretMaterial32V1,
    CloudflareServerOutputHpkeDecryptKeyBindingV1, CloudflareServerOutputMaterialRecordV1,
    CloudflareSignerClientRecipientProofBundleResponseV1,
    CloudflareSignerEnvelopeHpkeDecryptKeyBindingSetV1,
    CloudflareSignerEnvelopeHpkeDecryptKeyBindingV1, CloudflareSignerEnvelopeHpkePublicKeySetV1,
    CloudflareSignerEnvelopeHpkePublicKeyV1, CloudflareSignerEnvelopeHpkeRotationPublicKeySetV1,
    CloudflareSignerHostPeerPreloadInputV1, CloudflareSignerHostPreloadInputV1,
    CloudflareSignerHostPreloadPlanV1, CloudflareSignerPeerSigningKeyBindingV1,
    CloudflareSignerPeerVerifyingKeyBytesV1, CloudflareSignerPeerVerifyingKeySetV1,
    CloudflareSignerPrivateBootstrapRequestV1, CloudflareSignerRecipientProofBundleResponseV1,
    CloudflareSignerRecipientProofBundleWireHandlerV1, CloudflareSignerStartupCheckV1,
    CloudflareSignerWireHandlerV1, CloudflareSigningWorkerAdmittedNormalSigningFinalizeRequestV2,
    CloudflareSigningWorkerAdmittedNormalSigningPrepareRequestV2,
    CloudflareSigningWorkerAdmittedRouterAbEcdsaDerivationEvmDigestFinalizeRequestV1,
    CloudflareSigningWorkerAdmittedRouterAbEcdsaDerivationEvmDigestSigningRequestV1,
    CloudflareSigningWorkerBindingsV1,
    CloudflareSigningWorkerDirectRecipientProofBundleActivationAggregateV1,
    CloudflareSigningWorkerDirectRecipientProofBundleActivationDeliveryV1,
    CloudflareSigningWorkerDirectRecipientProofBundleActivationPutOutcomeV1,
    CloudflareSigningWorkerEcdsaPresignatureLookupV1,
    CloudflareSigningWorkerEcdsaPresignaturePoolLookupV1,
    CloudflareSigningWorkerEcdsaPresignaturePoolPutReceiptV1,
    CloudflareSigningWorkerEcdsaPresignaturePoolRecordV1,
    CloudflareSigningWorkerEcdsaPresignaturePutReceiptV1,
    CloudflareSigningWorkerEcdsaPresignatureRecordV1,
    CloudflareSigningWorkerMaterializedRouterAbEcdsaDerivationEvmDigestFinalizeRequestV1,
    CloudflareSigningWorkerMaterializedRouterAbEcdsaDerivationEvmDigestSigningRequestV1,
    CloudflareSigningWorkerOutputActivationReceiptV1,
    CloudflareSigningWorkerRecipientProofBundleActivationRequestV1,
    CloudflareSigningWorkerRecipientProofBundleActivationV1, CloudflareSigningWorkerRound1LookupV1,
    CloudflareSigningWorkerRound1PutReceiptV1, CloudflareSigningWorkerRound1RecordV1,
    CloudflareSigningWorkerRouterAbEcdsaDerivationEvmDigestFinalizeHandlerV1,
    CloudflareSigningWorkerRouterAbEcdsaDerivationEvmDigestPreparedV1,
    CloudflareSigningWorkerRouterAbEcdsaDerivationPresignaturePoolPutRequestV1,
    CloudflareSigningWorkerRuntimeV1, CloudflareWorkerBindingsV1, CloudflareWorkerRoleV1,
    CLOUDFLARE_ROOT_SHARE_WIRE_SECRET_PREFIX_V1,
    CLOUDFLARE_SERVER_OUTPUT_HPKE_PRIVATE_KEY_SECRET_PREFIX_V1,
    CLOUDFLARE_SIGNER_ENVELOPE_HPKE_PRIVATE_KEY_SECRET_PREFIX_V1,
    DERIVER_A_ENVELOPE_HPKE_KEY_EPOCH_ENV, DERIVER_A_ENVELOPE_HPKE_PRIVATE_KEY_BINDING_ENV,
    DERIVER_A_ENVELOPE_HPKE_PUBLIC_KEY_ENV, DERIVER_A_PEER_BINDING_ENV,
    DERIVER_A_PEER_SIGNING_KEY_BINDING_ENV, DERIVER_A_PEER_SIGNING_KEY_EPOCH_ENV,
    DERIVER_A_PEER_VERIFYING_KEY_HEX_ENV, DERIVER_A_PREVIOUS_ENVELOPE_HPKE_KEY_EPOCH_ENV,
    DERIVER_A_PREVIOUS_ENVELOPE_HPKE_PRIVATE_KEY_BINDING_ENV,
    DERIVER_A_PREVIOUS_ENVELOPE_HPKE_PUBLIC_KEY_ENV, DERIVER_A_ROOT_SHARE_DO_BINDING_ENV,
    DERIVER_A_ROOT_SHARE_DO_KEY_PREFIX_ENV, DERIVER_A_ROOT_SHARE_DO_OBJECT_ENV,
    DERIVER_A_ROOT_SHARE_WIRE_SECRET_BINDING_ENV, DERIVER_B_ENVELOPE_HPKE_KEY_EPOCH_ENV,
    DERIVER_B_ENVELOPE_HPKE_PRIVATE_KEY_BINDING_ENV, DERIVER_B_ENVELOPE_HPKE_PUBLIC_KEY_ENV,
    DERIVER_B_PEER_BINDING_ENV, DERIVER_B_PEER_SIGNING_KEY_BINDING_ENV,
    DERIVER_B_PEER_SIGNING_KEY_EPOCH_ENV, DERIVER_B_PEER_VERIFYING_KEY_HEX_ENV,
    DERIVER_B_PREVIOUS_ENVELOPE_HPKE_KEY_EPOCH_ENV,
    DERIVER_B_PREVIOUS_ENVELOPE_HPKE_PUBLIC_KEY_ENV, DERIVER_B_ROOT_SHARE_DO_BINDING_ENV,
    DERIVER_B_ROOT_SHARE_DO_KEY_PREFIX_ENV, DERIVER_B_ROOT_SHARE_DO_OBJECT_ENV,
    DERIVER_B_ROOT_SHARE_WIRE_SECRET_BINDING_ENV, ROUTER_ABUSE_DO_BINDING_ENV,
    ROUTER_ABUSE_DO_KEY_PREFIX_ENV, ROUTER_ABUSE_DO_OBJECT_ENV,
    ROUTER_AB_PREVIOUS_ENVELOPE_HPKE_RETIRE_AT_MS_ENV, ROUTER_JWT_AUDIENCE_ENV,
    ROUTER_JWT_ISSUER_ENV, ROUTER_JWT_JWKS_URL_ENV, ROUTER_LIFECYCLE_DO_BINDING_ENV,
    ROUTER_LIFECYCLE_DO_KEY_PREFIX_ENV, ROUTER_LIFECYCLE_DO_OBJECT_ENV,
    ROUTER_PROJECT_POLICY_DO_BINDING_ENV, ROUTER_PROJECT_POLICY_DO_KEY_PREFIX_ENV,
    ROUTER_PROJECT_POLICY_DO_OBJECT_ENV, ROUTER_QUOTA_DO_BINDING_ENV,
    ROUTER_QUOTA_DO_KEY_PREFIX_ENV, ROUTER_QUOTA_DO_OBJECT_ENV, ROUTER_REPLAY_DO_BINDING_ENV,
    ROUTER_REPLAY_DO_KEY_PREFIX_ENV, ROUTER_REPLAY_DO_OBJECT_ENV,
    ROUTER_WALLET_BUDGET_DO_BINDING_ENV, ROUTER_WALLET_BUDGET_DO_KEY_PREFIX_ENV,
    ROUTER_WALLET_BUDGET_DO_OBJECT_ENV, SIGNING_WORKER_PEER_BINDING_ENV,
    SIGNING_WORKER_SERVER_OUTPUT_DO_BINDING_ENV, SIGNING_WORKER_SERVER_OUTPUT_DO_KEY_PREFIX_ENV,
    SIGNING_WORKER_SERVER_OUTPUT_DO_OBJECT_ENV, SIGNING_WORKER_SERVER_OUTPUT_HPKE_KEY_EPOCH_ENV,
    SIGNING_WORKER_SERVER_OUTPUT_HPKE_PRIVATE_KEY_BINDING_ENV,
    SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY_ENV,
};
use router_ab_core::{
    ab_peer_message_authentication_input_digest_v1, decode_recipient_proof_bundle_ciphertext_v1,
    decode_router_to_signer_payload_v1, encode_ab_peer_message_authentication_input_v1,
    encode_recipient_proof_bundle_ciphertext_v1, AbPeerMessageAuthenticationV1,
    AbPeerMessagePayloadV1, AbPeerMessageSignatureSchemeV1, AbPeerMessageVerifyingKeyV1,
    ActiveSigningWorkerStateV1, CanonicalWireBytesV1, Clock, Csprng, EcdsaThresholdPrfRequestV1,
    EncryptedPayloadV1, ExpensiveWorkGateContextV1, ExpensiveWorkGateDecisionV1,
    ExpensiveWorkKindV1, GateDeferReasonV1, GatePrincipalV1, GateRejectReasonV1, LifecycleScopeV1,
    MpcPrfOutputRequestV1, MpcPrfSigningRootShareWireV1,
    NormalSigningEd25519TwoPartyFrostCommitmentsV1, NormalSigningScopeV1, OpenedShareKind,
    PeerTransport, RecipientOutputEncryptionAlgorithmV1, RecipientProofBundleCiphertextV1,
    RecipientProofBundleEncryptionRequestV1, RecipientProofBundleEncryptorV1,
    RoleEncryptedEnvelopeV1, RoleEnvelopeAadV1, RouterAbLifecycleStateV1,
    RouterAbProtocolErrorCode, RouterAbProtocolResult, RouterToSignerPayloadV1,
    RouterTranscriptMetadataV1, ServerIdentityV1, SignerEnvelopeHpkePayloadV1, SignerIdentityV1,
    SignerInputPlaintextV1, SignerInputQuorumPolicyV1, SignerKeyStore, SignerSetV1,
    SigningRootShareStore, WireMessageKindV1, WireMessageV1,
    MPC_PRF_SIGNING_ROOT_SHARE_WIRE_V1_LEN, SIGNER_ENVELOPE_HPKE_ENCAPPED_KEY_LEN_V1,
    SIGNER_ENVELOPE_HPKE_TAG_LEN_V1,
};
use router_ab_core::{
    router_ab_ecdsa_derivation_active_state_session_id_v1, router_transcript_digest_v1,
    PublicDigest32, RequestKind, Role, RootShareEpoch,
    RouterAbEcdsaDerivationActivationRefreshRequestV1,
    RouterAbEcdsaDerivationEvmDigestSigningFinalizeRequestV1,
    RouterAbEcdsaDerivationEvmDigestSigningPrepareResponseV1,
    RouterAbEcdsaDerivationEvmDigestSigningRequestV1,
    RouterAbEcdsaDerivationEvmDigestSigningResponseV1,
    RouterAbEcdsaDerivationExplicitExportRequestV1, RouterAbEcdsaDerivationPublicIdentityV1,
    RouterAbEcdsaDerivationRecoveryRequestV1,
    RouterAbEcdsaDerivationRegistrationBootstrapRequestV1,
    RouterAbEcdsaDerivationRegistrationPurposeV1, RouterAbEcdsaDerivationStableKeyContextV1,
    RouterAbEd25519NormalSigningFinalizeProtocolV2, RouterAbEd25519NormalSigningFinalizeRequestV2,
    RouterAbEd25519NormalSigningIntentV2, RouterAbEd25519NormalSigningPrepareBindingV2,
    RouterAbEd25519NormalSigningPrepareRequestV2, RouterAbEd25519SigningPayloadV2,
    RouterAbEd25519TwoPartyFrostFinalizeProtocolV2, RouterAbNearNetworkIdV2,
    RouterAbNearTransactionIntentV1,
};
use router_ab_ecdsa_derivation::shared::secp256k1::{
    map_additive_share_to_threshold_signatures_share_2p,
    THRESHOLD_SECP256K1_2P_CLIENT_PARTICIPANT_ID,
};
use router_ab_ecdsa_derivation::{
    derive_relayer_share_for_client_public, ROUTER_AB_ECDSA_DERIVATION_PARTICIPANT_IDS,
};
use sha2::{Digest as Sha2Digest, Sha256};
use signer_core::near_threshold_ed25519::{
    build_signing_package, client_round1_commit, client_round2_signature_share,
    key_package_from_signing_share_bytes, signature_share_to_b64u,
    verifying_share_bytes_from_signing_share_bytes, ClientRound1State,
};
use signer_core::near_threshold_frost::compute_threshold_ed25519_group_public_key_2p_from_verifying_shares;
use signer_core::threshold_ecdsa::{
    threshold_ecdsa_compute_signature_share, ThresholdEcdsaPresignSession,
};
use std::collections::BTreeMap;

const TEST_ACTIVATED_AT_MS: u64 = 1_000;
const ROUTER_AB_ECDSA_DERIVATION_WALLET_KEY_ID: &str = "wallet-key-1";
const ROUTER_AB_ECDSA_DERIVATION_WALLET_ID: &str = "wallet-1";
const ROUTER_AB_ECDSA_DERIVATION_THRESHOLD_KEY_ID: &str = "ecdsa-key-1";
const ROUTER_AB_ECDSA_DERIVATION_SIGNING_ROOT_ID: &str = "signing-root-1";
const ROUTER_AB_ECDSA_DERIVATION_SIGNING_ROOT_VERSION: &str = "root-version-1";

fn root_epoch() -> RootShareEpoch {
    RootShareEpoch::new("epoch-1").expect("root epoch")
}

fn next_root_epoch() -> RootShareEpoch {
    RootShareEpoch::new("epoch-2").expect("next root epoch")
}

fn root_share_wire(role: Role) -> MpcPrfSigningRootShareWireV1 {
    let share_id = match role {
        Role::SignerA => 1u16,
        Role::SignerB => 2u16,
        _ => panic!("test root share wire requires signer role"),
    };
    let mut bytes = vec![0u8; MPC_PRF_SIGNING_ROOT_SHARE_WIRE_V1_LEN];
    bytes[0..2].copy_from_slice(&share_id.to_be_bytes());
    bytes[2] = (share_id as u8).wrapping_mul(11);
    MpcPrfSigningRootShareWireV1::new(bytes).expect("root share wire")
}

fn digest(byte: u8) -> PublicDigest32 {
    PublicDigest32::new([byte; 32])
}

fn active_signing_worker_state_for_activation(
    activation: &CloudflareSigningWorkerRecipientProofBundleActivationRequestV1,
    material_handle: impl Into<String>,
) -> ActiveSigningWorkerStateV1 {
    cloudflare_active_signing_worker_state_from_activation_request_v1(
        activation,
        material_handle,
        TEST_ACTIVATED_AT_MS,
    )
    .expect("active SigningWorker state")
}

fn normal_signing_scope() -> NormalSigningScopeV1 {
    normal_signing_scope_for_request_id("sign-request-1")
}

fn normal_signing_scope_for_request_id(request_id: &str) -> NormalSigningScopeV1 {
    NormalSigningScopeV1::new(request_id, "account.near", "session-1", "server-a")
        .expect("normal signing scope")
}

fn normal_signing_v2_wallet_session(expires_at_ms: u64) -> CloudflareRouterVerifiedWalletSessionV1 {
    CloudflareRouterVerifiedWalletSessionV1::new(
        "user-1",
        "account.near",
        "session-1",
        "signing-grant-1",
        "org-1",
        "project-1",
        "dev",
        "normal-signing",
        "server-a",
        digest(0x90),
        expires_at_ms,
    )
    .expect("wallet session")
}

fn normal_signing_v2_prepare_request(
    expires_at_ms: u64,
) -> RouterAbEd25519NormalSigningPrepareRequestV2 {
    normal_signing_v2_prepare_request_for_id("sign-request-1", expires_at_ms)
}

fn normal_signing_v2_prepare_request_for_id(
    request_id: &str,
    expires_at_ms: u64,
) -> RouterAbEd25519NormalSigningPrepareRequestV2 {
    let unsigned_transaction_borsh = normal_signing_v2_unsigned_transaction_borsh();
    let unsigned_transaction_borsh_b64u = b64u(&unsigned_transaction_borsh);
    let intent = RouterAbEd25519NormalSigningIntentV2::NearTransactionV1 {
        operation_id: "operation-1".to_owned(),
        operation_fingerprint: "fingerprint-1".to_owned(),
        near_account_id: "account.near".to_owned(),
        near_network_id: RouterAbNearNetworkIdV2::Testnet,
        transactions: vec![RouterAbNearTransactionIntentV1::new(
            "receiver.near",
            normal_signing_v2_action_fingerprint(),
        )
        .expect("near transaction intent")],
        unsigned_transaction_borsh_b64u: unsigned_transaction_borsh_b64u.clone(),
    };
    let signing_payload = RouterAbEd25519SigningPayloadV2::NearUnsignedTransactionBorshV1 {
        unsigned_transaction_borsh_b64u,
        expected_signing_digest_b64u: sha256_digest_b64u(&unsigned_transaction_borsh),
    };
    RouterAbEd25519NormalSigningPrepareRequestV2::new(
        normal_signing_scope_for_request_id(request_id),
        expires_at_ms,
        intent,
        signing_payload,
    )
    .expect("normal signing v2 prepare request")
}

fn normal_signing_v2_finalize_request(
    expires_at_ms: u64,
) -> RouterAbEd25519NormalSigningFinalizeRequestV2 {
    let prepare = normal_signing_v2_prepare_request(expires_at_ms);
    let material = prepare.admission_material().expect("admission material");
    let prepare_binding = RouterAbEd25519NormalSigningPrepareBindingV2::new(
        "server-round1/sign-request-1",
        prepare.round1_binding_digest().expect("round1 binding"),
        material.intent_digest,
        material.signing_payload_digest,
    )
    .expect("prepare binding");
    let protocol = RouterAbEd25519NormalSigningFinalizeProtocolV2::Ed25519TwoPartyFrostFinalizeV1(
        RouterAbEd25519TwoPartyFrostFinalizeProtocolV2::new(
            NormalSigningEd25519TwoPartyFrostCommitmentsV1::new(
                b64u(&[0x11; 32]),
                b64u(&[0x12; 32]),
            )
            .expect("client commitments"),
            NormalSigningEd25519TwoPartyFrostCommitmentsV1::new(
                b64u(&[0x21; 32]),
                b64u(&[0x22; 32]),
            )
            .expect("server commitments"),
            b64u(&[0x31; 32]),
            b64u(&[0x32; 32]),
            b64u(&[0x41; 32]),
        )
        .expect("v2 finalize protocol"),
    );
    RouterAbEd25519NormalSigningFinalizeRequestV2::new(
        normal_signing_scope(),
        expires_at_ms,
        prepare_binding,
        protocol,
    )
    .expect("normal signing v2 finalize request")
}

fn active_signing_worker_state_for_normal_signing() -> ActiveSigningWorkerStateV1 {
    active_signing_worker_state_for_normal_signing_account_public_key(
        "ed25519:11111111111111111111111111111111",
    )
}

fn active_signing_worker_state_for_normal_signing_account_public_key(
    account_public_key: impl Into<String>,
) -> ActiveSigningWorkerStateV1 {
    ActiveSigningWorkerStateV1::new(
        "account.near",
        "session-1",
        account_public_key,
        signer_set().selected_server,
        digest(0x81),
        digest(0x82),
        "server-output/lifecycle-1/material",
        TEST_ACTIVATED_AT_MS,
    )
    .expect("active SigningWorker state")
}

fn active_signing_worker_state_for_normal_signing_public_key(
    public_key: [u8; 32],
) -> ActiveSigningWorkerStateV1 {
    active_signing_worker_state_for_normal_signing_account_public_key(format!(
        "ed25519:{}",
        bs58::encode(public_key).into_string()
    ))
}

fn normal_signing_round1_state() -> CloudflareEd25519Round1StateV1 {
    let signing_share =
        frost_ed25519::keys::SigningShare::deserialize(&scalar_bytes(5)).expect("signing share");
    let mut rng = rand_chacha::ChaCha20Rng::from_seed([0x5a; 32]);
    let (nonces, commitments) = frost_ed25519::round1::commit(&signing_share, &mut rng);
    CloudflareEd25519Round1StateV1::new(nonces, commitments).expect("round1 state")
}

type NormalSigningFrostFixture = (
    [u8; 32],
    [u8; 32],
    [u8; 32],
    [u8; 32],
    [u8; 32],
    ClientRound1State,
    CloudflareEd25519Round1StateV1,
);

fn normal_signing_frost_fixture() -> NormalSigningFrostFixture {
    let client_scalar = scalar_bytes(7);
    let server_scalar = scalar_bytes(5);
    let client_verifying_share = verifying_share_bytes_from_signing_share_bytes(&client_scalar);
    let server_verifying_share = verifying_share_bytes_from_signing_share_bytes(&server_scalar);
    let group_public_key = compute_threshold_ed25519_group_public_key_2p_from_verifying_shares(
        &client_verifying_share,
        &server_verifying_share,
        1,
        2,
    )
    .expect("group public key");
    let client_identifier = frost_ed25519::Identifier::try_from(1_u16).expect("client identifier");
    let client_key_package =
        key_package_from_signing_share_bytes(&client_scalar, &group_public_key, client_identifier)
            .expect("client key package");
    let client_round1 = client_round1_commit(&client_key_package).expect("client round1");
    (
        client_scalar,
        server_scalar,
        client_verifying_share,
        server_verifying_share,
        group_public_key,
        client_round1,
        normal_signing_round1_state(),
    )
}

fn normal_signing_client_signature_share(
    client_scalar: &[u8; 32],
    group_public_key: &[u8; 32],
    client_round1: &ClientRound1State,
    server_round1: &CloudflareEd25519Round1StateV1,
    message: &[u8],
) -> String {
    let client_identifier = frost_ed25519::Identifier::try_from(1_u16).expect("client identifier");
    let signing_worker_identifier =
        frost_ed25519::Identifier::try_from(2_u16).expect("SigningWorker identifier");
    let client_key_package =
        key_package_from_signing_share_bytes(client_scalar, group_public_key, client_identifier)
            .expect("client key package");
    let server_commitments = frost_ed25519::round1::SigningCommitments::new(
        frost_ed25519::round1::NonceCommitment::deserialize(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(&server_round1.commitments.hiding)
                .expect("hiding commitment"),
        )
        .expect("hiding commitment point"),
        frost_ed25519::round1::NonceCommitment::deserialize(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(&server_round1.commitments.binding)
                .expect("binding commitment"),
        )
        .expect("binding commitment point"),
    );
    let signing_package = build_signing_package(
        message,
        BTreeMap::from([
            (client_identifier, client_round1.commitments),
            (signing_worker_identifier, server_commitments),
        ]),
    );
    let share =
        client_round2_signature_share(&signing_package, &client_round1.nonces, &client_key_package)
            .expect("client signature share");
    signature_share_to_b64u(&share).expect("signature share encoding")
}

fn normal_signing_round1_record() -> CloudflareSigningWorkerRound1RecordV1 {
    let request = normal_signing_v2_prepare_request(2_000);
    let material = request.admission_material().expect("admission material");
    CloudflareSigningWorkerRound1RecordV1::new(
        active_signing_worker_state_for_normal_signing(),
        "server-round1/sign-request-1",
        request.round1_binding_digest().expect("round1 binding"),
        material.admitted_signing_digest,
        normal_signing_round1_state(),
        1_000,
        2_000,
    )
    .expect("round1 record")
}

fn normal_signing_round1_lookup(now_unix_ms: u64) -> CloudflareSigningWorkerRound1LookupV1 {
    let request = normal_signing_v2_prepare_request(2_000);
    CloudflareSigningWorkerRound1LookupV1::new(
        active_signing_worker_state_for_normal_signing(),
        "server-round1/sign-request-1",
        request.round1_binding_digest().expect("round1 binding"),
        now_unix_ms,
    )
    .expect("round1 lookup")
}

fn scalar_bytes(value: u64) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&value.to_le_bytes());
    bytes
}

fn request_context_digest(request: &EcdsaThresholdPrfRequestV1) -> PublicDigest32 {
    request
        .request_context_digest()
        .expect("request context digest")
}

fn role_envelope_aad_for_request(
    role: Role,
    request: &EcdsaThresholdPrfRequestV1,
) -> RoleEnvelopeAadV1 {
    let (payload_a, payload_b) = request.to_signer_payloads().expect("signer payloads");
    let payload = match role {
        Role::SignerA => payload_a,
        Role::SignerB => payload_b,
        _ => panic!("test helper requires signer role"),
    };
    let assignment = payload.assignment();
    RoleEnvelopeAadV1::new(
        payload.lifecycle().lifecycle_id.clone(),
        payload.lifecycle().work_kind,
        payload.signer_set().signer_set_id.clone(),
        assignment.signer.clone(),
        payload.signer_set().selected_server.clone(),
        payload.transcript_digest(),
        request_context_digest(request),
        request.expires_at_ms,
    )
    .expect("role envelope aad")
}

fn digest_hex(digest: PublicDigest32) -> String {
    lower_hex(digest.as_bytes())
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn x25519_public_key(byte: u8) -> String {
    let mut out = String::from("x25519:");
    for _ in 0..32 {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn hpke_keypair(seed: u8) -> ([u8; 32], String) {
    let (private_key, public_key) =
        DhKemX25519HkdfSha256::derive_key_pair(&[seed; 32]).expect("hpke keypair derives");
    let private_key_bytes = DhKemX25519HkdfSha256::sk_to_bytes(&private_key);
    let mut private_key_out = [0u8; 32];
    private_key_out.copy_from_slice(&private_key_bytes);
    let public_key = format!(
        "x25519:{}",
        lower_hex(&DhKemX25519HkdfSha256::pk_to_bytes(&public_key))
    );
    (private_key_out, public_key)
}

fn root_share_wire_secret(role: Role) -> String {
    format!(
        "{}{}",
        CLOUDFLARE_ROOT_SHARE_WIRE_SECRET_PREFIX_V1,
        lower_hex(root_share_wire(role).as_bytes())
    )
}

fn signer_identity(role: Role) -> SignerIdentityV1 {
    match role {
        Role::SignerA => {
            SignerIdentityV1::new(Role::SignerA, "signer-a", "key-epoch-a").expect("signer a")
        }
        Role::SignerB => {
            SignerIdentityV1::new(Role::SignerB, "signer-b", "key-epoch-b").expect("signer b")
        }
        _ => panic!("signer role"),
    }
}

fn signer_peer_signing_key(role: Role) -> SigningKey {
    match role {
        Role::SignerA => SigningKey::from_bytes(&[0xa1; 32]),
        Role::SignerB => SigningKey::from_bytes(&[0xb1; 32]),
        _ => panic!("signer role"),
    }
}

fn signer_verifying_key(role: Role) -> AbPeerMessageVerifyingKeyV1 {
    let signing_key = signer_peer_signing_key(role);
    AbPeerMessageVerifyingKeyV1::new(
        signer_identity(role),
        signing_key.verifying_key().to_bytes(),
    )
    .expect("signer verifying key")
}

fn signer_verifying_keys() -> Vec<AbPeerMessageVerifyingKeyV1> {
    vec![
        signer_verifying_key(Role::SignerA),
        signer_verifying_key(Role::SignerB),
    ]
}

fn signer_peer_verifying_key_hex(role: Role) -> String {
    signer_peer_signing_key(role)
        .verifying_key()
        .to_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn cloudflare_peer_verifying_key_bytes(role: Role) -> CloudflareSignerPeerVerifyingKeyBytesV1 {
    let bytes = decode_cloudflare_peer_verifying_key_hex_v1(&signer_peer_verifying_key_hex(role))
        .expect("verifying key hex");
    CloudflareSignerPeerVerifyingKeyBytesV1::new(role, bytes)
        .expect("cloudflare peer verifying key bytes")
}

fn cloudflare_peer_verifying_key_set() -> CloudflareSignerPeerVerifyingKeySetV1 {
    CloudflareSignerPeerVerifyingKeySetV1::new(
        cloudflare_peer_verifying_key_bytes(Role::SignerA),
        cloudflare_peer_verifying_key_bytes(Role::SignerB),
    )
    .expect("cloudflare peer verifying key set")
}

fn do_binding(
    scope: CloudflareDurableObjectScopeV1,
    binding_name: &str,
) -> CloudflareDurableObjectBindingV1 {
    CloudflareDurableObjectBindingV1::new(
        scope,
        binding_name,
        format!("{binding_name}-object"),
        format!("{binding_name}:"),
    )
    .expect("durable object binding")
}

fn peer(peer_role: CloudflareWorkerRoleV1, binding_name: &str) -> CloudflarePeerBindingV1 {
    CloudflarePeerBindingV1::new(peer_role, binding_name).expect("peer binding")
}

fn deriver_a_root_binding() -> CloudflareDurableObjectBindingV1 {
    do_binding(
        CloudflareDurableObjectScopeV1::signer_root_share(Role::SignerA).expect("signer a scope"),
        "DERIVER_A_ROOT_SHARE_DO",
    )
}

fn deriver_b_root_binding() -> CloudflareDurableObjectBindingV1 {
    do_binding(
        CloudflareDurableObjectScopeV1::signer_root_share(Role::SignerB).expect("signer b scope"),
        "DERIVER_B_ROOT_SHARE_DO",
    )
}

fn deriver_a_root_share_wire_secret_binding() -> CloudflareRootShareWireSecretBindingV1 {
    CloudflareRootShareWireSecretBindingV1::new(Role::SignerA, "DERIVER_A_ROOT_SHARE_WIRE_SECRET")
        .expect("signer a root-share wire secret binding")
}

fn deriver_b_root_share_wire_secret_binding() -> CloudflareRootShareWireSecretBindingV1 {
    CloudflareRootShareWireSecretBindingV1::new(Role::SignerB, "DERIVER_B_ROOT_SHARE_WIRE_SECRET")
        .expect("signer b root-share wire secret binding")
}

fn root_share_metadata(role: Role) -> CloudflareRootShareStartupMetadataV1 {
    let (signer_id, key_epoch, storage_key) = match role {
        Role::SignerA => ("signer-a", "key-epoch-a", "sealed/share/a"),
        Role::SignerB => ("signer-b", "key-epoch-b", "sealed/share/b"),
        _ => panic!("test root-share metadata requires signer role"),
    };
    CloudflareRootShareStartupMetadataV1::new(
        "signer-set-v1",
        role,
        signer_id,
        key_epoch,
        root_epoch(),
        storage_key,
    )
    .expect("root-share startup metadata")
}

fn server_output_binding() -> CloudflareDurableObjectBindingV1 {
    do_binding(
        CloudflareDurableObjectScopeV1::signing_worker_server_output(),
        "SIGNING_WORKER_SERVER_OUTPUT_DO",
    )
}

fn deriver_a_envelope_hpke_decrypt_key() -> CloudflareSignerEnvelopeHpkeDecryptKeyBindingV1 {
    CloudflareSignerEnvelopeHpkeDecryptKeyBindingV1::new(
        Role::SignerA,
        "DERIVER_A_ENVELOPE_HPKE_PRIVATE_KEY",
        "envelope-hpke-key-epoch-a",
        x25519_public_key(0x11),
    )
    .expect("signer a hpke envelope decrypt key")
}

fn deriver_a_envelope_hpke_decrypt_key_set() -> CloudflareSignerEnvelopeHpkeDecryptKeyBindingSetV1 {
    CloudflareSignerEnvelopeHpkeDecryptKeyBindingSetV1::current_only(
        deriver_a_envelope_hpke_decrypt_key(),
    )
    .expect("signer a hpke envelope decrypt key set")
}

fn deriver_b_envelope_hpke_decrypt_key() -> CloudflareSignerEnvelopeHpkeDecryptKeyBindingV1 {
    CloudflareSignerEnvelopeHpkeDecryptKeyBindingV1::new(
        Role::SignerB,
        "DERIVER_B_ENVELOPE_HPKE_PRIVATE_KEY",
        "envelope-hpke-key-epoch-b",
        x25519_public_key(0x22),
    )
    .expect("signer b hpke envelope decrypt key")
}

fn server_output_hpke_decrypt_key() -> CloudflareServerOutputHpkeDecryptKeyBindingV1 {
    let server = &signer_set().selected_server;
    CloudflareServerOutputHpkeDecryptKeyBindingV1::new(
        "SIGNING_WORKER_SERVER_OUTPUT_HPKE_PRIVATE_KEY",
        server.key_epoch.clone(),
        server.recipient_encryption_key.clone(),
    )
    .expect("server-output hpke decrypt key")
}

fn deriver_a_peer_signing_key() -> CloudflareSignerPeerSigningKeyBindingV1 {
    CloudflareSignerPeerSigningKeyBindingV1::new(
        Role::SignerA,
        "DERIVER_A_PEER_SIGNING_KEY",
        "key-epoch-a",
    )
    .expect("signer a peer signing key")
}

fn deriver_b_peer_signing_key() -> CloudflareSignerPeerSigningKeyBindingV1 {
    CloudflareSignerPeerSigningKeyBindingV1::new(
        Role::SignerB,
        "DERIVER_B_PEER_SIGNING_KEY",
        "key-epoch-b",
    )
    .expect("signer b peer signing key")
}

fn router_runtime() -> CloudflareRouterWorkerRuntimeV1 {
    CloudflareRouterWorkerRuntimeV1::new(
        CloudflareRouterBindingsV1::new(
            do_binding(
                CloudflareDurableObjectScopeV1::RouterReplay,
                "ROUTER_REPLAY_DO",
            ),
            do_binding(
                CloudflareDurableObjectScopeV1::RouterLifecycle,
                "ROUTER_LIFECYCLE_DO",
            ),
            router_wallet_budget_binding(),
            router_admission_bindings(),
            peer(CloudflareWorkerRoleV1::DeriverA, "DERIVER_A"),
            peer(CloudflareWorkerRoleV1::DeriverB, "DERIVER_B"),
            peer(CloudflareWorkerRoleV1::SigningWorker, "SIGNING_WORKER"),
        )
        .expect("router bindings"),
    )
    .expect("router runtime")
}

fn lifecycle_state() -> RouterAbLifecycleStateV1 {
    RouterAbLifecycleStateV1::requested(
        LifecycleScopeV1::new(
            "lifecycle-1",
            ExpensiveWorkKindV1::RegistrationPrepare,
            root_epoch(),
            "account.near",
            "session-1",
            "signer-set-v1",
            "server-a",
        )
        .expect("lifecycle scope"),
    )
    .expect("lifecycle state")
}

fn lifecycle_scope() -> LifecycleScopeV1 {
    lifecycle_state().scope().clone()
}

fn accepted_lifecycle_state() -> RouterAbLifecycleStateV1 {
    RouterAbLifecycleStateV1::apply_gate_decision(
        lifecycle_scope(),
        ExpensiveWorkGateDecisionV1::accepted("gate-request-1").expect("accepted"),
    )
    .expect("accepted lifecycle state")
}

fn created_derivation_ceremony() -> CloudflareDerivationCeremonyV1 {
    CloudflareDerivationCeremonyV1::created(lifecycle_scope(), TEST_ACTIVATED_AT_MS - 2)
        .expect("created derivation ceremony")
}

fn accepted_derivation_ceremony() -> CloudflareDerivationCeremonyV1 {
    CloudflareDerivationCeremonyV1::admitted(
        lifecycle_scope(),
        "gate-request-1",
        TEST_ACTIVATED_AT_MS - 1,
    )
    .expect("accepted derivation ceremony")
}

fn a_envelope_forwarded_derivation_ceremony() -> CloudflareDerivationCeremonyV1 {
    CloudflareDerivationCeremonyV1::a_envelope_forwarded(
        lifecycle_scope(),
        "gate-request-1",
        "signer-a",
        digest(0xa1),
        TEST_ACTIVATED_AT_MS - 1,
    )
    .expect("A-envelope-forwarded derivation ceremony")
}

fn b_envelope_forwarded_derivation_ceremony() -> CloudflareDerivationCeremonyV1 {
    CloudflareDerivationCeremonyV1::b_envelope_forwarded(
        lifecycle_scope(),
        "gate-request-1",
        "signer-a",
        digest(0xa1),
        "signer-b",
        digest(0xb1),
        TEST_ACTIVATED_AT_MS - 1,
    )
    .expect("B-envelope-forwarded derivation ceremony")
}

fn ab_running_derivation_ceremony() -> CloudflareDerivationCeremonyV1 {
    CloudflareDerivationCeremonyV1::ab_running(
        lifecycle_scope(),
        "gate-request-1",
        digest(0xc1),
        TEST_ACTIVATED_AT_MS - 1,
    )
    .expect("A/B-running derivation ceremony")
}

fn client_output_ready_derivation_ceremony() -> CloudflareDerivationCeremonyV1 {
    CloudflareDerivationCeremonyV1::client_output_ready(
        lifecycle_scope(),
        "gate-request-1",
        vec![digest(0xd1), digest(0xd2)],
        TEST_ACTIVATED_AT_MS - 1,
    )
    .expect("client-output-ready derivation ceremony")
}

fn signing_worker_output_ready_derivation_ceremony() -> CloudflareDerivationCeremonyV1 {
    CloudflareDerivationCeremonyV1::signing_worker_output_ready(
        lifecycle_scope(),
        "gate-request-1",
        vec![digest(0xe1), digest(0xe2)],
        TEST_ACTIVATED_AT_MS - 1,
    )
    .expect("SigningWorker-output-ready derivation ceremony")
}

fn activated_derivation_ceremony() -> CloudflareDerivationCeremonyV1 {
    let activation = signing_worker_activation();
    let active_state = active_signing_worker_state_for_activation(&activation, "material-handle-1");
    CloudflareDerivationCeremonyV1::activated(lifecycle_scope(), "gate-request-1", active_state)
        .expect("activated derivation ceremony")
}

fn signer_set() -> SignerSetV1 {
    SignerSetV1::v1_all2(
        "signer-set-v1",
        SignerIdentityV1::new(Role::SignerA, "signer-a", "key-epoch-a").expect("signer a"),
        SignerIdentityV1::new(Role::SignerB, "signer-b", "key-epoch-b").expect("signer b"),
        ServerIdentityV1::new(
            "server-a",
            "server-epoch",
            "x25519:1111111111111111111111111111111111111111111111111111111111111111",
        )
        .expect("server"),
    )
    .expect("signer set")
}

fn transcript_metadata() -> RouterTranscriptMetadataV1 {
    RouterTranscriptMetadataV1::new(
        "near-mainnet",
        "ed25519:account-public-key",
        "router-1",
        "client-1",
        "x25519:client-ephemeral-public-key",
    )
    .expect("transcript metadata")
}

fn public_request_transcript_digest(
    lifecycle: &LifecycleScopeV1,
    signer_set: &SignerSetV1,
) -> PublicDigest32 {
    router_transcript_digest_v1(lifecycle, signer_set, &transcript_metadata(), root_epoch())
        .expect("public request transcript digest")
}

fn trusted_admission(decision: ExpensiveWorkGateDecisionV1) -> CloudflareRouterTrustedAdmissionV1 {
    CloudflareRouterTrustedAdmissionV1::new(
        ExpensiveWorkGateContextV1::new(
            ExpensiveWorkKindV1::RegistrationPrepare,
            "org-1",
            "project-1",
            "dev",
            "account.near",
            GatePrincipalV1::authenticated_session("user-1", "session-1").expect("principal"),
            digest(0x90),
        )
        .expect("gate context"),
        decision,
    )
    .expect("trusted admission")
}

fn trusted_metadata() -> CloudflareRouterTrustedRequestMetadataV1 {
    CloudflareRouterTrustedRequestMetadataV1::new(
        ExpensiveWorkKindV1::RegistrationPrepare,
        "org-1",
        "project-1",
        "dev",
        "account.near",
        CloudflareRouterAuthContextV1::authenticated_session("user-1", "session-1")
            .expect("auth context"),
        digest(0x90),
    )
    .expect("trusted metadata")
}

fn admission_store_request(now_unix_ms: u64) -> CloudflareRouterAdmissionStoreRequestV1 {
    CloudflareRouterAdmissionStoreRequestV1::new(
        trusted_metadata(),
        &ecdsa_threshold_prf_request(2_000),
        now_unix_ms,
    )
    .expect("admission store request")
}

fn normal_signing_admission_store_request(
    now_unix_ms: u64,
) -> CloudflareRouterNormalSigningAdmissionStoreRequestV1 {
    normal_signing_admission_store_request_for_id("sign-request-1", now_unix_ms)
}

fn normal_signing_admission_store_request_for_id(
    request_id: &str,
    now_unix_ms: u64,
) -> CloudflareRouterNormalSigningAdmissionStoreRequestV1 {
    let request = normal_signing_v2_prepare_request_for_id(request_id, 2_000);
    let wallet_session = normal_signing_v2_wallet_session(3_000);
    let admission = CloudflareRouterNormalSigningPrepareAdmissionCandidateV2::from_prepare_request(
        &wallet_session,
        &request,
        now_unix_ms,
    )
    .expect("normal signing v2 admission");
    admission
        .to_v1_prepare_admission_store_request(&request, now_unix_ms)
        .expect("normal signing admission store request")
}

type TestCompositeAdmissionProvider = CloudflareRouterCompositeAdmissionProviderV1<
    CloudflareRouterVerifiedSessionProviderV1,
    CloudflareRouterAllowedWorkKindsProjectPolicyProviderV1,
    CloudflareRouterConfiguredAbuseProviderV1,
    CloudflareRouterConfiguredQuotaProviderV1,
>;

fn verified_jwt_claims(session_id: &str, account_id: &str) -> CloudflareRouterVerifiedJwtClaimsV1 {
    CloudflareRouterVerifiedJwtClaimsV1::new(
        "user-1",
        session_id,
        "org-1",
        "project-1",
        "dev",
        account_id,
        digest(0x90),
    )
    .expect("verified claims")
}

fn encode_jwt_segment(value: &serde_json::Value) -> String {
    let bytes = serde_json::to_vec(value).expect("json segment");
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn b64u(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn sha256_public_digest(bytes: &[u8]) -> PublicDigest32 {
    let digest = Sha256::digest(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    PublicDigest32::new(out)
}

fn sha256_digest_b64u(bytes: &[u8]) -> String {
    b64u(sha256_public_digest(bytes).as_bytes())
}

fn push_borsh_string(out: &mut Vec<u8>, value: &str) {
    out.extend_from_slice(&(value.len() as u32).to_le_bytes());
    out.extend_from_slice(value.as_bytes());
}

fn push_borsh_bytes(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u32).to_le_bytes());
    out.extend_from_slice(value);
}

fn normal_signing_v2_unsigned_transaction_borsh() -> Vec<u8> {
    let mut out = Vec::new();
    push_borsh_string(&mut out, "account.near");
    out.push(0);
    out.extend_from_slice(&[0; 32]);
    out.extend_from_slice(&7_u64.to_le_bytes());
    push_borsh_string(&mut out, "receiver.near");
    out.extend_from_slice(&[0x44; 32]);
    out.extend_from_slice(&1_u32.to_le_bytes());
    out.push(2);
    push_borsh_string(&mut out, "transfer");
    push_borsh_bytes(&mut out, br#"{"amount":"1"}"#);
    out.extend_from_slice(&30_000_000_000_000_u64.to_le_bytes());
    out.extend_from_slice(&0_u128.to_le_bytes());
    out
}

fn normal_signing_v2_action_fingerprint() -> String {
    sha256_digest_b64u(
        r#"[{"action_type":"FunctionCall","args":"{\"amount\":\"1\"}","deposit":"0","gas":"30000000000000","method_name":"transfer"}]"#
            .as_bytes(),
    )
}

fn ed25519_jwks_json(signing_key: &SigningKey, key_id: &str) -> String {
    let public_key = signing_key.verifying_key().to_bytes();
    serde_json::json!({
        "keys": [{
            "kty": "OKP",
            "crv": "Ed25519",
            "kid": key_id,
            "alg": "EdDSA",
            "use": "sig",
            "x": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(public_key),
        }]
    })
    .to_string()
}

fn ed25519_jwt(signing_key: &SigningKey, key_id: &str, claims: serde_json::Value) -> String {
    let header = encode_jwt_segment(&serde_json::json!({
        "alg": "EdDSA",
        "kid": key_id,
        "typ": "JWT",
    }));
    let payload = encode_jwt_segment(&claims);
    let signing_input = format!("{header}.{payload}");
    let signature = signing_key.sign(signing_input.as_bytes()).to_bytes();
    let signature = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature);
    format!("{signing_input}.{signature}")
}

fn valid_router_jwt_claims() -> serde_json::Value {
    serde_json::json!({
        "iss": "https://issuer.example",
        "sub": "user-1",
        "aud": "router-ab",
        "exp": 3,
        "nbf": 1,
        "iat": 1,
        "sid": "session-1",
        "org_id": "org-1",
        "project_id": "project-1",
        "environment": "dev",
        "account_id": "account.near",
    })
}

fn valid_wallet_session_jwt_claims() -> serde_json::Value {
    let mut claims = valid_router_jwt_claims();
    claims["signingGrantId"] = serde_json::json!("signing-grant-1");
    claims["routerAbNormalSigning"] = serde_json::json!({
        "authorizationLevel": "normal-signing",
        "signingWorkerId": "server-a",
    });
    claims
}

#[test]
fn normal_signing_cors_requires_exact_configured_origin() {
    assert_eq!(
        cloudflare_router_normal_signing_cors_allowed_origin_v1(
            Some("https://wallet.example, https://app.example"),
            "https://app.example",
        ),
        Some("https://app.example".to_owned())
    );
    assert_eq!(
        cloudflare_router_normal_signing_cors_allowed_origin_v1(None, "https://app.example"),
        None
    );
    assert_eq!(
        cloudflare_router_normal_signing_cors_allowed_origin_v1(Some(""), "https://app.example"),
        None
    );
    assert_eq!(
        cloudflare_router_normal_signing_cors_allowed_origin_v1(Some("*"), "https://app.example"),
        None
    );
    assert_eq!(
        cloudflare_router_normal_signing_cors_allowed_origin_v1(
            Some("https://wallet.example"),
            "https://app.example",
        ),
        None
    );
}

fn composite_admission_provider(
    claims: CloudflareRouterVerifiedJwtClaimsV1,
    allowed_work_kinds: Vec<ExpensiveWorkKindV1>,
    abuse: CloudflareRouterAbuseCheckV1,
    quota: CloudflareRouterQuotaCheckV1,
) -> TestCompositeAdmissionProvider {
    CloudflareRouterCompositeAdmissionProviderV1::new(
        CloudflareRouterVerifiedSessionProviderV1::new(
            CloudflareRouterVerifiedSessionV1::jwt(claims).expect("verified jwt session"),
        )
        .expect("verified session provider"),
        CloudflareRouterAllowedWorkKindsProjectPolicyProviderV1::new(allowed_work_kinds, 1_000)
            .expect("project policy provider"),
        CloudflareRouterConfiguredAbuseProviderV1::new(abuse).expect("abuse provider"),
        CloudflareRouterConfiguredQuotaProviderV1::new(quota).expect("quota provider"),
    )
}

fn allow_checks(request_id: &str) -> CloudflareRouterAdmissionChecksV1 {
    CloudflareRouterAdmissionChecksV1::new(
        CloudflareRouterProjectPolicyV1::Allowed,
        CloudflareRouterAbuseCheckV1::Allowed,
        CloudflareRouterQuotaCheckV1::Accepted {
            request_id: request_id.to_owned(),
        },
    )
    .expect("admission checks")
}

#[derive(Debug, Clone)]
struct StaticAdmissionProvider {
    output: CloudflareRouterAdmissionProviderOutputV1,
    calls: usize,
}

impl StaticAdmissionProvider {
    fn new(output: CloudflareRouterAdmissionProviderOutputV1) -> Self {
        Self { output, calls: 0 }
    }
}

impl CloudflareRouterAdmissionProviderV1 for StaticAdmissionProvider {
    fn evaluate_public_request_admission(
        &mut self,
        _request: &EcdsaThresholdPrfRequestV1,
    ) -> RouterAbProtocolResult<CloudflareRouterAdmissionProviderOutputV1> {
        self.calls += 1;
        Ok(self.output.clone())
    }
}

#[derive(Debug, Clone)]
struct StaticJwtVerifier {
    claims: CloudflareRouterVerifiedJwtClaimsV1,
    calls: usize,
}

impl StaticJwtVerifier {
    fn new(claims: CloudflareRouterVerifiedJwtClaimsV1) -> Self {
        Self { claims, calls: 0 }
    }
}

impl CloudflareRouterJwtVerifierV1 for StaticJwtVerifier {
    fn verify_public_request_jwt(
        &mut self,
        verifier: &CloudflareRouterJwtVerifierBindingV1,
        authorization: &CloudflareRouterBearerAuthorizationV1,
        request: &EcdsaThresholdPrfRequestV1,
        now_unix_ms: u64,
        trusted_source_digest: PublicDigest32,
    ) -> RouterAbProtocolResult<CloudflareRouterVerifiedJwtClaimsV1> {
        verifier.validate()?;
        authorization.validate()?;
        request.validate_at(now_unix_ms)?;
        self.calls += 1;
        let mut claims = self.claims.clone();
        claims.trusted_source_digest = trusted_source_digest;
        claims.validate()?;
        Ok(claims)
    }
}

#[derive(Debug, Clone)]
struct StaticProjectPolicyStore {
    outcome: CloudflareRouterProjectPolicyV1,
}

impl StaticProjectPolicyStore {
    fn new(outcome: CloudflareRouterProjectPolicyV1) -> Self {
        Self { outcome }
    }
}

impl CloudflareRouterProjectPolicyStoreV1 for StaticProjectPolicyStore {
    fn evaluate_project_policy_from_store(
        &mut self,
        binding: &CloudflareDurableObjectBindingV1,
        metadata: &CloudflareRouterTrustedRequestMetadataV1,
        request: &EcdsaThresholdPrfRequestV1,
    ) -> RouterAbProtocolResult<CloudflareRouterProjectPolicyV1> {
        binding.validate_visible_to(CloudflareWorkerRoleV1::Router)?;
        metadata.validate_for_request(request)?;
        assert_eq!(
            binding.scope,
            CloudflareDurableObjectScopeV1::RouterProjectPolicy
        );
        Ok(self.outcome.clone())
    }
}

#[derive(Debug, Clone)]
struct StaticAbuseStore {
    outcome: CloudflareRouterAbuseCheckV1,
}

impl StaticAbuseStore {
    fn new(outcome: CloudflareRouterAbuseCheckV1) -> Self {
        Self { outcome }
    }
}

impl CloudflareRouterAbuseStoreV1 for StaticAbuseStore {
    fn evaluate_abuse_from_store(
        &mut self,
        binding: &CloudflareDurableObjectBindingV1,
        metadata: &CloudflareRouterTrustedRequestMetadataV1,
        request: &EcdsaThresholdPrfRequestV1,
    ) -> RouterAbProtocolResult<CloudflareRouterAbuseCheckV1> {
        binding.validate_visible_to(CloudflareWorkerRoleV1::Router)?;
        metadata.validate_for_request(request)?;
        assert_eq!(binding.scope, CloudflareDurableObjectScopeV1::RouterAbuse);
        Ok(self.outcome.clone())
    }
}

#[derive(Debug, Clone)]
struct StaticQuotaStore {
    outcome: CloudflareRouterQuotaCheckV1,
}

impl StaticQuotaStore {
    fn new(outcome: CloudflareRouterQuotaCheckV1) -> Self {
        Self { outcome }
    }
}

impl CloudflareRouterQuotaStoreV1 for StaticQuotaStore {
    fn evaluate_quota_from_store(
        &mut self,
        binding: &CloudflareDurableObjectBindingV1,
        metadata: &CloudflareRouterTrustedRequestMetadataV1,
        request: &EcdsaThresholdPrfRequestV1,
    ) -> RouterAbProtocolResult<CloudflareRouterQuotaCheckV1> {
        binding.validate_visible_to(CloudflareWorkerRoleV1::Router)?;
        metadata.validate_for_request(request)?;
        assert_eq!(binding.scope, CloudflareDurableObjectScopeV1::RouterQuota);
        Ok(self.outcome.clone())
    }
}

fn role_envelope(role: Role, seed: u8) -> RoleEncryptedEnvelopeV1 {
    RoleEncryptedEnvelopeV1::new(
        role,
        digest(seed),
        digest(seed + 1),
        EncryptedPayloadV1::new(vec![seed, seed + 1]).expect("ciphertext"),
    )
    .expect("role envelope")
}

fn ecdsa_derivation_client_share_public_key33() -> [u8; 33] {
    [
        0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
        0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16,
        0xf8, 0x17, 0x98,
    ]
}

fn router_ab_ecdsa_derivation_context() -> RouterAbEcdsaDerivationStableKeyContextV1 {
    RouterAbEcdsaDerivationStableKeyContextV1::new(b64u(&[0x42; 32]))
        .expect("Router A/B ECDSA derivation context")
}

fn router_ab_ecdsa_derivation_active_state_session_id(epoch: &RootShareEpoch) -> String {
    router_ab_ecdsa_derivation_active_state_session_id_v1(
        ROUTER_AB_ECDSA_DERIVATION_THRESHOLD_KEY_ID,
        ROUTER_AB_ECDSA_DERIVATION_SIGNING_ROOT_ID,
        ROUTER_AB_ECDSA_DERIVATION_SIGNING_ROOT_VERSION,
        epoch.as_str(),
    )
    .expect("Router A/B ECDSA derivation active-state session id")
}

fn router_ab_ecdsa_derivation_lifecycle_scope_for(
    lifecycle_id: &str,
    work_kind: ExpensiveWorkKindV1,
    epoch: RootShareEpoch,
) -> LifecycleScopeV1 {
    let session_id = router_ab_ecdsa_derivation_active_state_session_id(&epoch);
    LifecycleScopeV1::new(
        lifecycle_id,
        work_kind,
        epoch,
        ROUTER_AB_ECDSA_DERIVATION_WALLET_ID,
        session_id,
        "signer-set-v1",
        "server-a",
    )
    .expect("Router A/B ECDSA derivation lifecycle scope")
}

fn router_ab_ecdsa_derivation_lifecycle_scope() -> LifecycleScopeV1 {
    router_ab_ecdsa_derivation_lifecycle_scope_for(
        "ecdsa-lifecycle-1",
        ExpensiveWorkKindV1::RegistrationPrepare,
        root_epoch(),
    )
}

fn router_ab_ecdsa_derivation_registration_request(
) -> RouterAbEcdsaDerivationRegistrationBootstrapRequestV1 {
    RouterAbEcdsaDerivationRegistrationBootstrapRequestV1::new(
        RouterAbEcdsaDerivationRegistrationPurposeV1::WalletRegistration,
        router_ab_ecdsa_derivation_context(),
        router_ab_ecdsa_derivation_lifecycle_scope(),
        signer_set(),
        "router-1",
        "client-1",
        "x25519:client-ephemeral-public-key",
        "ecdsa-replay-1",
        2_000,
        b64u(&ecdsa_derivation_client_share_public_key33()),
        0,
        role_envelope(Role::SignerA, 0xa3),
        role_envelope(Role::SignerB, 0xb3),
    )
    .expect("Router A/B ECDSA derivation registration request")
}

fn router_ab_ecdsa_derivation_registration_request_with_aad_bound_envelopes(
) -> RouterAbEcdsaDerivationRegistrationBootstrapRequestV1 {
    let base = router_ab_ecdsa_derivation_registration_request();
    let header = base.header();
    let header_digest = base
        .request_header_digest()
        .expect("Router A/B ECDSA derivation registration header digest");
    let aad_a = header
        .role_aad(Role::SignerA)
        .expect("Router A/B ECDSA derivation registration Deriver A AAD");
    let aad_b = header
        .role_aad(Role::SignerB)
        .expect("Router A/B ECDSA derivation registration Deriver B AAD");
    let request = RouterAbEcdsaDerivationRegistrationBootstrapRequestV1 {
        deriver_a_envelope: RoleEncryptedEnvelopeV1::new(
            Role::SignerA,
            header_digest,
            aad_a.digest(),
            EncryptedPayloadV1::new(vec![0xa3, 0xa4])
                .expect("ECDSA registration signer a ciphertext"),
        )
        .expect("ECDSA registration signer a aad-bound envelope"),
        deriver_b_envelope: RoleEncryptedEnvelopeV1::new(
            Role::SignerB,
            header_digest,
            aad_b.digest(),
            EncryptedPayloadV1::new(vec![0xb3, 0xb4])
                .expect("ECDSA registration signer b ciphertext"),
        )
        .expect("ECDSA registration signer b aad-bound envelope"),
        ..base
    };
    request
        .validate()
        .expect("AAD-bound Router A/B ECDSA derivation registration request");
    request
}

fn router_ab_ecdsa_derivation_export_lifecycle_scope() -> LifecycleScopeV1 {
    router_ab_ecdsa_derivation_lifecycle_scope_for(
        "ecdsa-export-lifecycle-1",
        ExpensiveWorkKindV1::KeyExport,
        root_epoch(),
    )
}

fn router_ab_ecdsa_derivation_public_identity() -> RouterAbEcdsaDerivationPublicIdentityV1 {
    let activation = router_ab_ecdsa_derivation_activation_request();
    let material = router_ab_ecdsa_derivation_server_material_record(&activation);
    cloudflare_router_ab_ecdsa_derivation_public_identity_from_activation_material_v1(
        &activation.registration,
        &material,
    )
    .expect("Router A/B ECDSA derivation public identity")
}

fn router_ab_ecdsa_derivation_export_request_with_aad_bound_envelopes(
) -> RouterAbEcdsaDerivationExplicitExportRequestV1 {
    let registration = router_ab_ecdsa_derivation_registration_request();
    let base = RouterAbEcdsaDerivationExplicitExportRequestV1 {
        context: registration.context,
        lifecycle: router_ab_ecdsa_derivation_export_lifecycle_scope(),
        public_identity: router_ab_ecdsa_derivation_public_identity(),
        signer_set: signer_set(),
        router_id: "router-1".to_owned(),
        client_id: "client-1".to_owned(),
        client_ephemeral_public_key: "x25519:client-ephemeral-public-key".to_owned(),
        export_authorization_digest_b64u: b64u(&[0x44; 32]),
        export_nonce: "ecdsa-export-nonce-1".to_owned(),
        expires_at_ms: 2_000,
        deriver_a_export_envelope: role_envelope(Role::SignerA, 0xc3),
        deriver_b_export_envelope: role_envelope(Role::SignerB, 0xd3),
    };
    base.validate()
        .expect("base Router A/B ECDSA derivation export request");
    let public_request = base
        .to_threshold_prf_request()
        .expect("base Router A/B ECDSA derivation export public request");
    let aad_a = role_envelope_aad_for_request(Role::SignerA, &public_request);
    let aad_b = role_envelope_aad_for_request(Role::SignerB, &public_request);
    let request = RouterAbEcdsaDerivationExplicitExportRequestV1 {
        deriver_a_export_envelope: RoleEncryptedEnvelopeV1::new(
            Role::SignerA,
            digest(0xc3),
            aad_a.digest(),
            EncryptedPayloadV1::new(vec![0xc3, 0xc4]).expect("ECDSA export signer a ciphertext"),
        )
        .expect("ECDSA export signer a aad-bound envelope"),
        deriver_b_export_envelope: RoleEncryptedEnvelopeV1::new(
            Role::SignerB,
            digest(0xd3),
            aad_b.digest(),
            EncryptedPayloadV1::new(vec![0xd3, 0xd4]).expect("ECDSA export signer b ciphertext"),
        )
        .expect("ECDSA export signer b aad-bound envelope"),
        ..base
    };
    request
        .validate()
        .expect("AAD-bound Router A/B ECDSA derivation export request");
    request
}

fn router_ab_ecdsa_derivation_recovery_lifecycle_scope() -> LifecycleScopeV1 {
    router_ab_ecdsa_derivation_lifecycle_scope_for(
        "ecdsa-recovery-lifecycle-1",
        ExpensiveWorkKindV1::Recovery,
        root_epoch(),
    )
}

fn router_ab_ecdsa_derivation_recovery_request_with_aad_bound_envelopes(
) -> RouterAbEcdsaDerivationRecoveryRequestV1 {
    let registration = router_ab_ecdsa_derivation_registration_request();
    let base = RouterAbEcdsaDerivationRecoveryRequestV1 {
        context: registration.context,
        lifecycle: router_ab_ecdsa_derivation_recovery_lifecycle_scope(),
        public_identity: router_ab_ecdsa_derivation_public_identity(),
        signer_set: signer_set(),
        router_id: "router-1".to_owned(),
        client_id: "client-1".to_owned(),
        client_ephemeral_public_key: "x25519:client-recovery-ephemeral-public-key".to_owned(),
        recovery_authorization_digest_b64u: b64u(&[0x45; 32]),
        recovery_nonce: "ecdsa-recovery-nonce-1".to_owned(),
        expires_at_ms: 2_000,
        deriver_a_recovery_envelope: role_envelope(Role::SignerA, 0xe3),
        deriver_b_recovery_envelope: role_envelope(Role::SignerB, 0xf3),
    };
    base.validate()
        .expect("base Router A/B ECDSA derivation recovery request");
    let public_request = base
        .to_threshold_prf_request()
        .expect("base Router A/B ECDSA derivation recovery public request");
    let aad_a = role_envelope_aad_for_request(Role::SignerA, &public_request);
    let aad_b = role_envelope_aad_for_request(Role::SignerB, &public_request);
    let request = RouterAbEcdsaDerivationRecoveryRequestV1 {
        deriver_a_recovery_envelope: RoleEncryptedEnvelopeV1::new(
            Role::SignerA,
            digest(0xe3),
            aad_a.digest(),
            EncryptedPayloadV1::new(vec![0xe3, 0xe4]).expect("ECDSA recovery signer a ciphertext"),
        )
        .expect("ECDSA recovery signer a aad-bound envelope"),
        deriver_b_recovery_envelope: RoleEncryptedEnvelopeV1::new(
            Role::SignerB,
            digest(0xf3),
            aad_b.digest(),
            EncryptedPayloadV1::new(vec![0xf3, 0xf4]).expect("ECDSA recovery signer b ciphertext"),
        )
        .expect("ECDSA recovery signer b aad-bound envelope"),
        ..base
    };
    request
        .validate()
        .expect("AAD-bound Router A/B ECDSA derivation recovery request");
    request
}

fn router_ab_ecdsa_derivation_refresh_lifecycle_scope() -> LifecycleScopeV1 {
    router_ab_ecdsa_derivation_lifecycle_scope_for(
        "ecdsa-refresh-lifecycle-1",
        ExpensiveWorkKindV1::ServerShareRefresh,
        next_root_epoch(),
    )
}

fn router_ab_ecdsa_derivation_activation_refresh_request_with_aad_bound_envelopes(
) -> RouterAbEcdsaDerivationActivationRefreshRequestV1 {
    let registration = router_ab_ecdsa_derivation_registration_request();
    let base = RouterAbEcdsaDerivationActivationRefreshRequestV1 {
        context: registration.context,
        lifecycle: router_ab_ecdsa_derivation_refresh_lifecycle_scope(),
        public_identity: router_ab_ecdsa_derivation_public_identity(),
        signer_set: signer_set(),
        router_id: "router-1".to_owned(),
        client_id: "client-1".to_owned(),
        signing_worker_ephemeral_public_key: "x25519:signing-worker-refresh-ephemeral-key"
            .to_owned(),
        refresh_authorization_digest_b64u: b64u(&[0x46; 32]),
        refresh_nonce: "ecdsa-refresh-nonce-1".to_owned(),
        previous_activation_epoch: root_epoch().as_str().to_owned(),
        next_activation_epoch: next_root_epoch().as_str().to_owned(),
        expires_at_ms: 2_000,
        deriver_a_refresh_envelope: role_envelope(Role::SignerA, 0x83),
        deriver_b_refresh_envelope: role_envelope(Role::SignerB, 0x93),
    };
    base.validate()
        .expect("base Router A/B ECDSA derivation refresh request");
    let public_request = base
        .to_threshold_prf_request()
        .expect("base Router A/B ECDSA derivation refresh public request");
    let aad_a = role_envelope_aad_for_request(Role::SignerA, &public_request);
    let aad_b = role_envelope_aad_for_request(Role::SignerB, &public_request);
    let request = RouterAbEcdsaDerivationActivationRefreshRequestV1 {
        deriver_a_refresh_envelope: RoleEncryptedEnvelopeV1::new(
            Role::SignerA,
            digest(0x83),
            aad_a.digest(),
            EncryptedPayloadV1::new(vec![0x83, 0x84]).expect("ECDSA refresh signer a ciphertext"),
        )
        .expect("ECDSA refresh signer a aad-bound envelope"),
        deriver_b_refresh_envelope: RoleEncryptedEnvelopeV1::new(
            Role::SignerB,
            digest(0x93),
            aad_b.digest(),
            EncryptedPayloadV1::new(vec![0x93, 0x94]).expect("ECDSA refresh signer b ciphertext"),
        )
        .expect("ECDSA refresh signer b aad-bound envelope"),
        ..base
    };
    request
        .validate()
        .expect("AAD-bound Router A/B ECDSA derivation refresh request");
    request
}

fn router_ab_ecdsa_derivation_activation_request(
) -> CloudflareRouterAbEcdsaDerivationSigningWorkerActivationRequestV1 {
    let registration = router_ab_ecdsa_derivation_registration_request();
    let public_request = registration
        .to_threshold_prf_request()
        .expect("Router A/B ECDSA derivation public request");
    let (deriver_a, _) = public_request
        .to_signer_wire_messages()
        .expect("Router A/B ECDSA derivation router-to-signer messages");
    let router_payload =
        decode_router_to_signer_payload_v1(deriver_a.payload.as_bytes()).expect("router payload");
    let activation = CloudflareSigningWorkerRecipientProofBundleActivationV1::new(
        server_proof_bundle_wire(&router_payload, Role::SignerA, 0xa3),
        server_proof_bundle_wire(&router_payload, Role::SignerB, 0xb3),
    )
    .expect("Router A/B ECDSA derivation SigningWorker proof-bundle activation");
    CloudflareRouterAbEcdsaDerivationSigningWorkerActivationRequestV1::new(
        registration,
        router_payload,
        activation,
    )
    .expect("Router A/B ECDSA derivation SigningWorker activation request")
}

fn router_ab_ecdsa_derivation_activation_refresh_request(
) -> CloudflareRouterAbEcdsaDerivationSigningWorkerActivationRefreshRequestV1 {
    let refresh_request =
        router_ab_ecdsa_derivation_activation_refresh_request_with_aad_bound_envelopes();
    let public_request = refresh_request
        .to_threshold_prf_request()
        .expect("Router A/B ECDSA derivation refresh public request");
    let (deriver_a, _) = public_request
        .to_signer_wire_messages()
        .expect("Router A/B ECDSA derivation refresh router-to-signer messages");
    let router_payload = decode_router_to_signer_payload_v1(deriver_a.payload.as_bytes())
        .expect("refresh router payload");
    let activation = CloudflareSigningWorkerRecipientProofBundleActivationV1::new(
        server_proof_bundle_wire(&router_payload, Role::SignerA, 0xc3),
        server_proof_bundle_wire(&router_payload, Role::SignerB, 0xd3),
    )
    .expect("Router A/B ECDSA derivation refresh proof-bundle activation");
    CloudflareRouterAbEcdsaDerivationSigningWorkerActivationRefreshRequestV1::new(
        refresh_request,
        router_payload,
        activation,
    )
    .expect("Router A/B ECDSA derivation SigningWorker activation-refresh request")
}

fn router_ab_ecdsa_derivation_server_material_record(
    activation: &CloudflareRouterAbEcdsaDerivationSigningWorkerActivationRequestV1,
) -> CloudflareServerOutputMaterialRecordV1 {
    let selected_server = &activation.activation_context.signer_set().selected_server;
    CloudflareServerOutputMaterialRecordV1::new(
        activation.activation_context.transcript_digest(),
        OpenedShareKind::XServerBase,
        Role::Server,
        selected_server.server_id.clone(),
        CloudflareSecretMaterial32V1::new([0x5a; 32]),
    )
    .expect("Router A/B ECDSA derivation server output material record")
}

fn router_ab_ecdsa_derivation_refresh_server_material_record(
    activation: &CloudflareRouterAbEcdsaDerivationSigningWorkerActivationRefreshRequestV1,
    seed: u8,
) -> CloudflareServerOutputMaterialRecordV1 {
    let selected_server = &activation.activation_context.signer_set().selected_server;
    CloudflareServerOutputMaterialRecordV1::new(
        activation.activation_context.transcript_digest(),
        OpenedShareKind::XServerBase,
        Role::Server,
        selected_server.server_id.clone(),
        CloudflareSecretMaterial32V1::new([seed; 32]),
    )
    .expect("Router A/B ECDSA derivation refresh server output material record")
}

fn active_signing_worker_state_for_router_ab_ecdsa_derivation() -> ActiveSigningWorkerStateV1 {
    let activation = router_ab_ecdsa_derivation_activation_request();
    cloudflare_active_signing_worker_state_from_activation_request_v1(
        &activation
            .to_recipient_proof_bundle_activation_request()
            .expect("generic Router A/B ECDSA derivation activation request"),
        "router-ab-ecdsa-derivation-material",
        TEST_ACTIVATED_AT_MS,
    )
    .expect("Router A/B ECDSA derivation active SigningWorker state")
}

fn router_ab_ecdsa_derivation_digest_signing_request(
) -> RouterAbEcdsaDerivationEvmDigestSigningRequestV1 {
    let activation = router_ab_ecdsa_derivation_activation_request();
    let material = router_ab_ecdsa_derivation_server_material_record(&activation);
    let receipt = cloudflare_router_ab_ecdsa_derivation_activation_receipt_from_material_v1(
        &activation,
        &material,
        TEST_ACTIVATED_AT_MS,
    )
    .expect("Router A/B ECDSA derivation activation receipt");
    let scope =
        cloudflare_router_ab_ecdsa_derivation_normal_signing_scope_from_activation_receipt_v1(
            &receipt,
            ROUTER_AB_ECDSA_DERIVATION_WALLET_KEY_ID,
            ROUTER_AB_ECDSA_DERIVATION_WALLET_ID,
            ROUTER_AB_ECDSA_DERIVATION_THRESHOLD_KEY_ID,
            ROUTER_AB_ECDSA_DERIVATION_SIGNING_ROOT_ID,
            ROUTER_AB_ECDSA_DERIVATION_SIGNING_ROOT_VERSION,
        )
        .expect("Router A/B ECDSA derivation normal-signing scope");
    RouterAbEcdsaDerivationEvmDigestSigningRequestV1::new(
        scope,
        "router-ab-ecdsa-derivation-sign-request-1",
        "server-presignature-1",
        2_000,
        b64u(&[0x77; 32]),
    )
    .expect("Router A/B ECDSA derivation digest-signing request")
}

fn router_ab_ecdsa_derivation_digest_signing_finalize_request(
) -> RouterAbEcdsaDerivationEvmDigestSigningFinalizeRequestV1 {
    let request = router_ab_ecdsa_derivation_digest_signing_request();
    RouterAbEcdsaDerivationEvmDigestSigningFinalizeRequestV1::new(
        request.scope,
        request.request_id,
        request.expires_at_ms,
        request.signing_digest_b64u,
        request.client_presignature_id,
        b64u(&[0x88; 32]),
    )
    .expect("Router A/B ECDSA derivation digest-signing finalize request")
}

fn router_ab_ecdsa_derivation_trusted_admission(
    request: &RouterAbEcdsaDerivationEvmDigestSigningRequestV1,
) -> CloudflareRouterNormalSigningTrustedAdmissionV1 {
    let active_session_id = request
        .scope
        .active_state_session_id()
        .expect("Router A/B ECDSA derivation active session id");
    CloudflareRouterNormalSigningTrustedAdmissionV1::new(
        CloudflareRouterNormalSigningTrustedMetadataV1::new(
            "org-1",
            "project-1",
            "dev",
            request.scope.wallet_id.clone(),
            CloudflareRouterAuthContextV1::authenticated_session("subject-1", active_session_id)
                .expect("Router A/B ECDSA derivation auth context"),
            digest(0x42),
            request
                .request_digest()
                .expect("Router A/B ECDSA derivation request digest"),
        )
        .expect("Router A/B ECDSA derivation trusted metadata"),
        ExpensiveWorkGateDecisionV1::accepted("router-ab-ecdsa-derivation-gate-request-1")
            .expect("accepted Router A/B ECDSA derivation admission"),
    )
    .expect("Router A/B ECDSA derivation trusted admission")
}

fn router_ab_ecdsa_derivation_finalize_trusted_admission(
    request: &RouterAbEcdsaDerivationEvmDigestSigningFinalizeRequestV1,
) -> CloudflareRouterNormalSigningTrustedAdmissionV1 {
    let active_session_id = request
        .scope
        .active_state_session_id()
        .expect("Router A/B ECDSA derivation finalize active session id");
    CloudflareRouterNormalSigningTrustedAdmissionV1::new(
        CloudflareRouterNormalSigningTrustedMetadataV1::new(
            "org-1",
            "project-1",
            "dev",
            request.scope.wallet_id.clone(),
            CloudflareRouterAuthContextV1::authenticated_session("subject-1", active_session_id)
                .expect("Router A/B ECDSA derivation finalize auth context"),
            digest(0x42),
            request
                .request_digest()
                .expect("Router A/B ECDSA derivation finalize request digest"),
        )
        .expect("Router A/B ECDSA derivation finalize trusted metadata"),
        ExpensiveWorkGateDecisionV1::accepted("router-ab-ecdsa-derivation-finalize-gate-request-1")
            .expect("accepted Router A/B ECDSA derivation finalize admission"),
    )
    .expect("Router A/B ECDSA derivation finalize trusted admission")
}

fn router_ab_ecdsa_derivation_wallet_session(
    request: &RouterAbEcdsaDerivationEvmDigestSigningRequestV1,
) -> CloudflareRouterVerifiedWalletSessionV1 {
    let active_session_id = request
        .scope
        .active_state_session_id()
        .expect("Router A/B ECDSA derivation Wallet Session active session id");
    CloudflareRouterVerifiedWalletSessionV1::new(
        "subject-1",
        request.scope.wallet_id.clone(),
        active_session_id,
        "signing-grant-ecdsa-1",
        "org-1",
        "project-1",
        "dev",
        "wallet-session-v2",
        request.scope.signing_worker.server_id.clone(),
        digest(0x42),
        request.expires_at_ms + 500,
    )
    .expect("Router A/B ECDSA derivation Wallet Session")
}

fn admitted_router_ab_ecdsa_derivation_digest_signing_request(
    request: RouterAbEcdsaDerivationEvmDigestSigningRequestV1,
) -> CloudflareSigningWorkerAdmittedRouterAbEcdsaDerivationEvmDigestSigningRequestV1 {
    let trusted_admission = router_ab_ecdsa_derivation_trusted_admission(&request);
    CloudflareSigningWorkerAdmittedRouterAbEcdsaDerivationEvmDigestSigningRequestV1::new(
        request,
        trusted_admission,
    )
    .expect("admitted Router A/B ECDSA derivation digest-signing request")
}

fn admitted_router_ab_ecdsa_derivation_digest_finalize_request(
    request: RouterAbEcdsaDerivationEvmDigestSigningFinalizeRequestV1,
) -> CloudflareSigningWorkerAdmittedRouterAbEcdsaDerivationEvmDigestFinalizeRequestV1 {
    let trusted_admission = router_ab_ecdsa_derivation_finalize_trusted_admission(&request);
    CloudflareSigningWorkerAdmittedRouterAbEcdsaDerivationEvmDigestFinalizeRequestV1::new(
        request,
        trusted_admission,
    )
    .expect("admitted Router A/B ECDSA derivation digest finalize request")
}

fn router_ab_ecdsa_derivation_presignature_big_r33(seed: u8) -> [u8; 33] {
    let mut bytes = [seed; 33];
    bytes[0] = 0x02;
    bytes
}

fn ecdsa_scalar_one_be32() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[31] = 1;
    bytes
}

fn split_ecdsa_presignature_97(bytes: Vec<u8>) -> ([u8; 33], [u8; 32], [u8; 32]) {
    assert_eq!(bytes.len(), 97, "presignature must be 97 bytes");
    let big_r33 = bytes[0..33]
        .try_into()
        .expect("presignature R point length");
    let k_share32 = bytes[33..65]
        .try_into()
        .expect("presignature k share length");
    let sigma_share32 = bytes[65..97]
        .try_into()
        .expect("presignature sigma share length");
    (big_r33, k_share32, sigma_share32)
}

type EcdsaPresignaturePairFixture = ([u8; 33], [u8; 32], [u8; 32], [u8; 32], [u8; 32]);

fn drive_ecdsa_presignature_pair(
    client_share32: &[u8; 32],
    relayer_share32: &[u8; 32],
    public_key33: &[u8; 33],
) -> EcdsaPresignaturePairFixture {
    let participant_ids = ROUTER_AB_ECDSA_DERIVATION_PARTICIPANT_IDS.map(u32::from);
    let mut client =
        ThresholdEcdsaPresignSession::new(&participant_ids, 1, 2, client_share32, public_key33)
            .expect("client presign session");
    let mut relayer =
        ThresholdEcdsaPresignSession::new(&participant_ids, 2, 2, relayer_share32, public_key33)
            .expect("relayer presign session");
    let mut stage_for_relayer = "triples";
    let mut stage_for_client = "triples";
    let mut client_outgoing = client.poll().expect("client initial poll").outgoing;
    let mut relayer_outgoing = relayer.poll().expect("relayer initial poll").outgoing;

    for _ in 0..96 {
        if !client_outgoing.is_empty() {
            if stage_for_relayer == "presign" && relayer.stage() == "triples_done" {
                relayer.start_presign().expect("relayer starts presign");
            }
            for message in client_outgoing.drain(..) {
                relayer
                    .message(1, &message)
                    .expect("relayer accepts client message");
            }
            let progress = relayer.poll().expect("relayer poll");
            if matches!(progress.stage.as_str(), "triples_done" | "presign" | "done") {
                stage_for_client = "presign";
            }
            relayer_outgoing.extend(progress.outgoing);
        }

        if !relayer_outgoing.is_empty() {
            if stage_for_client == "presign" && client.stage() == "triples_done" {
                client.start_presign().expect("client starts presign");
            }
            for message in relayer_outgoing.drain(..) {
                client
                    .message(2, &message)
                    .expect("client accepts relayer message");
            }
            let progress = client.poll().expect("client poll");
            if matches!(progress.stage.as_str(), "triples_done" | "presign" | "done") {
                stage_for_relayer = "presign";
            }
            client_outgoing.extend(progress.outgoing);
        }

        if client_outgoing.is_empty()
            && relayer_outgoing.is_empty()
            && stage_for_relayer == "presign"
            && relayer.stage() == "triples_done"
        {
            relayer.start_presign().expect("relayer starts presign");
            let progress = relayer.poll().expect("relayer presign poll");
            relayer_outgoing.extend(progress.outgoing);
        }
        if client_outgoing.is_empty()
            && relayer_outgoing.is_empty()
            && stage_for_client == "presign"
            && client.stage() == "triples_done"
        {
            client.start_presign().expect("client starts presign");
            let progress = client.poll().expect("client presign poll");
            client_outgoing.extend(progress.outgoing);
        }

        if client.is_done() && relayer.is_done() {
            let (client_big_r33, client_k_share32, client_sigma_share32) =
                split_ecdsa_presignature_97(
                    client.take_presignature_97().expect("client presignature"),
                );
            let (server_big_r33, server_k_share32, server_sigma_share32) =
                split_ecdsa_presignature_97(
                    relayer
                        .take_presignature_97()
                        .expect("relayer presignature"),
                );
            assert_eq!(client_big_r33, server_big_r33);
            return (
                server_big_r33,
                server_k_share32,
                server_sigma_share32,
                client_k_share32,
                client_sigma_share32,
            );
        }
    }
    panic!("ECDSA presign protocol did not finish");
}

fn router_ab_ecdsa_derivation_presignature_record(
) -> CloudflareSigningWorkerEcdsaPresignatureRecordV1 {
    let request = router_ab_ecdsa_derivation_digest_signing_request();
    CloudflareSigningWorkerEcdsaPresignatureRecordV1::new(
        active_signing_worker_state_for_router_ab_ecdsa_derivation(),
        "server-presignature-1",
        request
            .request_digest()
            .expect("Router A/B ECDSA derivation request digest"),
        request
            .signing_digest()
            .expect("Router A/B ECDSA derivation signing digest"),
        b64u(&router_ab_ecdsa_derivation_presignature_big_r33(0x31)),
        b64u(&[0x55; 32]),
        b64u(&[0x11; 32]),
        b64u(&[0x22; 32]),
        1_000,
        2_000,
    )
    .expect("Router A/B ECDSA derivation presignature record")
}

fn router_ab_ecdsa_derivation_presignature_lookup(
    now_unix_ms: u64,
) -> CloudflareSigningWorkerEcdsaPresignatureLookupV1 {
    let request = router_ab_ecdsa_derivation_digest_signing_request();
    CloudflareSigningWorkerEcdsaPresignatureLookupV1::new(
        active_signing_worker_state_for_router_ab_ecdsa_derivation(),
        "server-presignature-1",
        request
            .request_digest()
            .expect("Router A/B ECDSA derivation request digest"),
        request
            .signing_digest()
            .expect("Router A/B ECDSA derivation signing digest"),
        now_unix_ms,
    )
    .expect("Router A/B ECDSA derivation presignature lookup")
}

fn router_ab_ecdsa_derivation_presignature_pool_record(
) -> CloudflareSigningWorkerEcdsaPresignaturePoolRecordV1 {
    CloudflareSigningWorkerEcdsaPresignaturePoolRecordV1::new(
        active_signing_worker_state_for_router_ab_ecdsa_derivation(),
        "server-presignature-1",
        b64u(&router_ab_ecdsa_derivation_presignature_big_r33(0x31)),
        b64u(&[0x11; 32]),
        b64u(&[0x22; 32]),
        1_000,
        2_000,
    )
    .expect("Router A/B ECDSA derivation presignature pool record")
}

fn router_ab_ecdsa_derivation_presignature_pool_lookup(
    now_unix_ms: u64,
) -> CloudflareSigningWorkerEcdsaPresignaturePoolLookupV1 {
    CloudflareSigningWorkerEcdsaPresignaturePoolLookupV1::new(
        active_signing_worker_state_for_router_ab_ecdsa_derivation(),
        "server-presignature-1",
        now_unix_ms,
    )
    .expect("Router A/B ECDSA derivation presignature pool lookup")
}

fn router_ab_ecdsa_derivation_presignature_pool_put_request(
    expires_at_ms: u64,
) -> CloudflareSigningWorkerRouterAbEcdsaDerivationPresignaturePoolPutRequestV1 {
    CloudflareSigningWorkerRouterAbEcdsaDerivationPresignaturePoolPutRequestV1::new(
        router_ab_ecdsa_derivation_digest_signing_request().scope,
        "server-presignature-1",
        b64u(&router_ab_ecdsa_derivation_presignature_big_r33(0x31)),
        b64u(&[0x11; 32]),
        b64u(&[0x22; 32]),
        expires_at_ms,
    )
    .expect("Router A/B ECDSA derivation presignature pool put request")
}

fn signer_envelope_hpke_payload(
    role: Role,
    key_epoch: &str,
    public_key: &str,
    aad_digest: PublicDigest32,
) -> SignerEnvelopeHpkePayloadV1 {
    let encapped_key_seed = match role {
        Role::SignerA => 0xa2,
        Role::SignerB => 0xb2,
        _ => panic!("test helper requires signer role"),
    };
    SignerEnvelopeHpkePayloadV1::new(
        role,
        key_epoch,
        public_key,
        aad_digest,
        [encapped_key_seed; SIGNER_ENVELOPE_HPKE_ENCAPPED_KEY_LEN_V1],
        vec![0xd1; SIGNER_ENVELOPE_HPKE_TAG_LEN_V1 + 1],
    )
    .expect("signer envelope HPKE payload")
}

fn role_hpke_envelope(
    role: Role,
    seed: u8,
    key_epoch: &str,
    public_key: &str,
) -> RoleEncryptedEnvelopeV1 {
    let aad_digest = digest(seed + 1);
    let hpke = signer_envelope_hpke_payload(role, key_epoch, public_key, aad_digest);
    RoleEncryptedEnvelopeV1::new(
        role,
        digest(seed),
        aad_digest,
        EncryptedPayloadV1::new(hpke.canonical_bytes()).expect("HPKE payload bytes"),
    )
    .expect("role HPKE envelope")
}

struct TestRecipientProofBundleEncryptor;

impl RecipientProofBundleEncryptorV1 for TestRecipientProofBundleEncryptor {
    fn encrypt_recipient_proof_bundle_v1(
        &mut self,
        request: RecipientProofBundleEncryptionRequestV1,
    ) -> router_ab_core::RouterAbProtocolResult<RecipientProofBundleCiphertextV1> {
        request.validate()?;
        let mut ciphertext = Vec::new();
        ciphertext.extend_from_slice(request.transcript_digest().as_bytes());
        ciphertext.extend_from_slice(request.payload_digest().as_bytes());
        ciphertext.extend_from_slice(request.plaintext());
        RecipientProofBundleCiphertextV1::new(
            RecipientOutputEncryptionAlgorithmV1::LocalDeterministicSha256V1,
            request.signer().clone(),
            request.recipient_role(),
            request.opened_share_kind(),
            request.recipient_identity(),
            request.recipient_encryption_key(),
            request.transcript_digest(),
            request.payload_digest(),
            [0x52; 12],
            EncryptedPayloadV1::new(ciphertext)?,
        )
    }
}

fn signer_private_request(kind: WireMessageKindV1) -> WireMessageV1 {
    match kind {
        WireMessageKindV1::RouterToSignerA => {
            ecdsa_threshold_prf_request(2_000)
                .to_signer_wire_messages()
                .expect("signer wire messages")
                .0
        }
        WireMessageKindV1::RouterToSignerB => {
            ecdsa_threshold_prf_request(2_000)
                .to_signer_wire_messages()
                .expect("signer wire messages")
                .1
        }
        _ => WireMessageV1::new(
            kind,
            digest(0x33),
            CanonicalWireBytesV1::new(vec![0x31, 0x32]).expect("private request bytes"),
        )
        .expect("private request"),
    }
}

fn ecdsa_threshold_prf_request_with_hpke_envelopes(
    expires_at_ms: u64,
) -> EcdsaThresholdPrfRequestV1 {
    let lifecycle = lifecycle_scope();
    let signer_set = signer_set();
    let transcript_digest = public_request_transcript_digest(&lifecycle, &signer_set);
    EcdsaThresholdPrfRequestV1::new(
        "request-nonce-1",
        expires_at_ms,
        lifecycle,
        signer_set,
        "near-mainnet",
        "ed25519:account-public-key",
        "router-1",
        "client-1",
        "x25519:client-ephemeral-public-key",
        transcript_digest,
        role_hpke_envelope(
            Role::SignerA,
            0x10,
            "envelope-hpke-key-epoch-a",
            &x25519_public_key(0x11),
        ),
        role_hpke_envelope(
            Role::SignerB,
            0x20,
            "envelope-hpke-key-epoch-b",
            &x25519_public_key(0x22),
        ),
    )
    .expect("public router request with HPKE envelopes")
}

fn deriver_a_private_request_with_sealed_hpke_envelope(
    public_key: &str,
    plaintext: &[u8],
) -> (WireMessageV1, RoleEnvelopeAadV1) {
    deriver_a_private_request_with_sealed_hpke_envelope_for_key(
        "envelope-hpke-key-epoch-a",
        public_key,
        plaintext,
    )
}

fn deriver_a_private_request_with_sealed_hpke_envelope_for_key(
    key_epoch: &str,
    public_key: &str,
    plaintext: &[u8],
) -> (WireMessageV1, RoleEnvelopeAadV1) {
    let base = ecdsa_threshold_prf_request(2_000);
    let aad = role_envelope_aad_for_request(Role::SignerA, &base);
    let recipient_key =
        CloudflareSignerEnvelopeHpkePublicKeyV1::new(Role::SignerA, key_epoch, public_key)
            .expect("signer a hpke public key");
    let sealed = seal_cloudflare_signer_envelope_hpke_payload_v1(&recipient_key, &aad, plaintext)
        .expect("sealed signer a hpke envelope");
    let request = EcdsaThresholdPrfRequestV1::new(
        base.request_nonce,
        base.expires_at_ms,
        base.lifecycle,
        base.signer_set,
        base.network_id,
        base.account_public_key,
        base.router_id,
        base.client_id,
        base.client_ephemeral_public_key,
        base.transcript_digest,
        RoleEncryptedEnvelopeV1::new(
            Role::SignerA,
            digest(0x10),
            aad.digest(),
            EncryptedPayloadV1::new(sealed.canonical_bytes()).expect("sealed hpke payload bytes"),
        )
        .expect("sealed signer a hpke role envelope"),
        role_hpke_envelope(
            Role::SignerB,
            0x20,
            "envelope-hpke-key-epoch-b",
            &x25519_public_key(0x22),
        ),
    )
    .expect("public router request with sealed signer a HPKE envelope");
    let message = request
        .to_signer_wire_messages()
        .expect("signer wire messages")
        .0;
    (message, aad)
}

fn ecdsa_threshold_prf_request_with_aad_bound_envelopes(
    expires_at_ms: u64,
) -> EcdsaThresholdPrfRequestV1 {
    let base = ecdsa_threshold_prf_request(expires_at_ms);
    let aad_a = role_envelope_aad_for_request(Role::SignerA, &base);
    let aad_b = role_envelope_aad_for_request(Role::SignerB, &base);
    EcdsaThresholdPrfRequestV1::new(
        base.request_nonce,
        base.expires_at_ms,
        base.lifecycle,
        base.signer_set,
        base.network_id,
        base.account_public_key,
        base.router_id,
        base.client_id,
        base.client_ephemeral_public_key,
        base.transcript_digest,
        RoleEncryptedEnvelopeV1::new(
            Role::SignerA,
            digest(0x10),
            aad_a.digest(),
            EncryptedPayloadV1::new(vec![0x10, 0x11]).expect("signer a ciphertext"),
        )
        .expect("signer a aad-bound envelope"),
        RoleEncryptedEnvelopeV1::new(
            Role::SignerB,
            digest(0x20),
            aad_b.digest(),
            EncryptedPayloadV1::new(vec![0x20, 0x21]).expect("signer b ciphertext"),
        )
        .expect("signer b aad-bound envelope"),
    )
    .expect("public router request with AAD-bound envelopes")
}

fn ecdsa_threshold_prf_request_with_reconstructed_transcript(
    expires_at_ms: u64,
) -> EcdsaThresholdPrfRequestV1 {
    ecdsa_threshold_prf_request(expires_at_ms)
}

fn signer_private_request_with_reconstructed_transcript(kind: WireMessageKindV1) -> WireMessageV1 {
    match kind {
        WireMessageKindV1::RouterToSignerA => {
            ecdsa_threshold_prf_request_with_reconstructed_transcript(2_000)
                .to_signer_wire_messages()
                .expect("signer wire messages")
                .0
        }
        WireMessageKindV1::RouterToSignerB => {
            ecdsa_threshold_prf_request_with_reconstructed_transcript(2_000)
                .to_signer_wire_messages()
                .expect("signer wire messages")
                .1
        }
        _ => signer_private_request(kind),
    }
}

fn signer_private_request_with_hpke_envelope(kind: WireMessageKindV1) -> WireMessageV1 {
    match kind {
        WireMessageKindV1::RouterToSignerA => {
            ecdsa_threshold_prf_request_with_hpke_envelopes(2_000)
                .to_signer_wire_messages()
                .expect("signer wire messages")
                .0
        }
        WireMessageKindV1::RouterToSignerB => {
            ecdsa_threshold_prf_request_with_hpke_envelopes(2_000)
                .to_signer_wire_messages()
                .expect("signer wire messages")
                .1
        }
        _ => signer_private_request(kind),
    }
}

fn signer_private_request_with_aad_bound_envelope(kind: WireMessageKindV1) -> WireMessageV1 {
    match kind {
        WireMessageKindV1::RouterToSignerA => {
            ecdsa_threshold_prf_request_with_aad_bound_envelopes(2_000)
                .to_signer_wire_messages()
                .expect("signer wire messages")
                .0
        }
        WireMessageKindV1::RouterToSignerB => {
            ecdsa_threshold_prf_request_with_aad_bound_envelopes(2_000)
                .to_signer_wire_messages()
                .expect("signer wire messages")
                .1
        }
        _ => signer_private_request(kind),
    }
}

fn signer_input_plaintext_bytes(role: Role) -> Vec<u8> {
    let request = ecdsa_threshold_prf_request(2_000);
    signer_input_plaintext_bytes_for_request(role, &request)
}

fn signer_input_plaintext_bytes_for_request(
    role: Role,
    request: &EcdsaThresholdPrfRequestV1,
) -> Vec<u8> {
    let (payload_a, payload_b) = request.to_signer_payloads().expect("signer payloads");
    let payload = match role {
        Role::SignerA => payload_a,
        Role::SignerB => payload_b,
        _ => panic!("test helper requires signer role"),
    };
    let assignment = payload.assignment();
    SignerInputPlaintextV1::new(
        RequestKind::Registration,
        payload.lifecycle().lifecycle_id.clone(),
        payload.signer_set().signer_set_id.clone(),
        SignerInputQuorumPolicyV1::All2,
        role,
        assignment.signer.signer_id.clone(),
        assignment.signer.key_epoch.clone(),
        root_epoch(),
        "server-a",
        "server-epoch",
        payload.transcript_digest(),
        request_context_digest(request),
        assignment.envelope.aad_digest,
        vec![
            MpcPrfOutputRequestV1::new(
                OpenedShareKind::XClientBase,
                Role::Client,
                payload.transcript_metadata().client_id.clone(),
            )
            .expect("client output"),
            MpcPrfOutputRequestV1::new(
                OpenedShareKind::XServerBase,
                Role::Server,
                payload.signer_set().selected_server.server_id.clone(),
            )
            .expect("server output"),
        ],
    )
    .expect("signer input plaintext")
    .canonical_bytes()
    .expect("canonical signer input plaintext")
}

fn signer_peer_message(kind: WireMessageKindV1) -> WireMessageV1 {
    signer_peer_message_with_transcript(kind, digest(0x33))
}

fn signer_peer_message_with_transcript(
    kind: WireMessageKindV1,
    transcript_digest: PublicDigest32,
) -> WireMessageV1 {
    let (from_role, to_role, seed) = match kind {
        WireMessageKindV1::SignerAToSignerB => (Role::SignerA, Role::SignerB, 0xa1),
        WireMessageKindV1::SignerBToSignerA => (Role::SignerB, Role::SignerA, 0xb1),
        _ => panic!("peer message kind"),
    };
    let from = signer_identity(from_role);
    let to = signer_identity(to_role);
    let peer_body =
        CanonicalWireBytesV1::new(vec![seed, seed.wrapping_add(1)]).expect("peer message body");
    let auth_digest =
        ab_peer_message_authentication_input_digest_v1(&from, &to, transcript_digest, &peer_body);
    let signature = signer_peer_signing_key(from_role).sign(
        &encode_ab_peer_message_authentication_input_v1(&from, &to, transcript_digest, &peer_body),
    );
    let authentication = AbPeerMessageAuthenticationV1::new(
        AbPeerMessageSignatureSchemeV1::Ed25519V1,
        auth_digest,
        CanonicalWireBytesV1::new(signature.to_bytes().to_vec()).expect("peer signature"),
    )
    .expect("peer authentication");
    let payload =
        AbPeerMessagePayloadV1::new(from, to, transcript_digest, peer_body, authentication)
            .expect("peer payload");
    WireMessageV1::new(
        kind,
        transcript_digest,
        CanonicalWireBytesV1::new(payload.canonical_bytes()).expect("peer message bytes"),
    )
    .expect("peer message")
}

struct TestRecipientProofBundleWireHandler {
    response: CloudflareSignerRecipientProofBundleResponseV1,
}

impl CloudflareSignerRecipientProofBundleWireHandlerV1 for TestRecipientProofBundleWireHandler {
    fn handle_signer_recipient_proof_bundle_wire_message(
        &self,
        _message: WireMessageV1,
    ) -> router_ab_core::RouterAbProtocolResult<CloudflareSignerRecipientProofBundleResponseV1>
    {
        Ok(self.response.clone())
    }
}

struct TestPeerWireHandler {
    response_kind: WireMessageKindV1,
    response_transcript: Option<PublicDigest32>,
}

impl TestPeerWireHandler {
    fn matching(response_kind: WireMessageKindV1) -> Self {
        Self {
            response_kind,
            response_transcript: None,
        }
    }
}

impl CloudflareSignerWireHandlerV1 for TestPeerWireHandler {
    fn handle_signer_wire_message(
        &self,
        message: WireMessageV1,
    ) -> router_ab_core::RouterAbProtocolResult<WireMessageV1> {
        Ok(signer_peer_message_with_transcript(
            self.response_kind,
            self.response_transcript
                .unwrap_or(message.transcript_digest),
        ))
    }
}

struct TestPeerKeyStore;

impl SignerKeyStore for TestPeerKeyStore {
    fn signer_identity(&self, role: Role) -> router_ab_core::RouterAbProtocolResult<String> {
        Ok(signer_identity(role).signer_id)
    }

    fn signer_verifying_key(
        &self,
        signer: &SignerIdentityV1,
    ) -> router_ab_core::RouterAbProtocolResult<AbPeerMessageVerifyingKeyV1> {
        signer_verifying_keys()
            .into_iter()
            .find(|key| key.signer == *signer)
            .ok_or_else(|| {
                router_ab_core::RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::MissingLocalBinding,
                    "test peer key store is missing signer verifying key",
                )
            })
    }
}

struct WrongPeerKeyStore;

impl SignerKeyStore for WrongPeerKeyStore {
    fn signer_identity(&self, role: Role) -> router_ab_core::RouterAbProtocolResult<String> {
        Ok(signer_identity(role).signer_id)
    }

    fn signer_verifying_key(
        &self,
        signer: &SignerIdentityV1,
    ) -> router_ab_core::RouterAbProtocolResult<AbPeerMessageVerifyingKeyV1> {
        let wrong_role = match signer.role {
            Role::SignerA => Role::SignerB,
            Role::SignerB => Role::SignerA,
            _ => panic!("signer role"),
        };
        AbPeerMessageVerifyingKeyV1::new(
            signer.clone(),
            signer_peer_signing_key(wrong_role)
                .verifying_key()
                .to_bytes(),
        )
    }
}

fn ecdsa_threshold_prf_request(expires_at_ms: u64) -> EcdsaThresholdPrfRequestV1 {
    let lifecycle = lifecycle_scope();
    let signer_set = signer_set();
    let transcript_digest = public_request_transcript_digest(&lifecycle, &signer_set);
    EcdsaThresholdPrfRequestV1::new(
        "request-nonce-1",
        expires_at_ms,
        lifecycle,
        signer_set,
        "near-mainnet",
        "ed25519:account-public-key",
        "router-1",
        "client-1",
        "x25519:client-ephemeral-public-key",
        transcript_digest,
        role_envelope(Role::SignerA, 0x10),
        role_envelope(Role::SignerB, 0x20),
    )
    .expect("public router request")
}

fn signing_worker_activation() -> CloudflareSigningWorkerRecipientProofBundleActivationRequestV1 {
    let router_payload = router_payload_for_signing_worker_activation();
    let activation = CloudflareSigningWorkerRecipientProofBundleActivationV1::new(
        server_proof_bundle_wire(&router_payload, Role::SignerA, 0x46),
        server_proof_bundle_wire(&router_payload, Role::SignerB, 0x47),
    )
    .expect("strict SigningWorker proof-bundle activation");
    CloudflareSigningWorkerRecipientProofBundleActivationRequestV1::new(router_payload, activation)
        .expect("strict SigningWorker activation request")
}

fn signing_worker_refresh_activation(
    lifecycle_id: &str,
    deriver_a_nonce_seed: u8,
    deriver_b_nonce_seed: u8,
) -> CloudflareSigningWorkerRecipientProofBundleActivationRequestV1 {
    let lifecycle = LifecycleScopeV1::new(
        lifecycle_id,
        ExpensiveWorkKindV1::ServerShareRefresh,
        root_epoch(),
        "account.near",
        "session-1",
        "signer-set-v1",
        "server-a",
    )
    .expect("refresh lifecycle scope");
    let signer_set = signer_set();
    let transcript_digest = public_request_transcript_digest(&lifecycle, &signer_set);
    let request = EcdsaThresholdPrfRequestV1::new(
        format!("request-nonce-{lifecycle_id}"),
        2_000,
        lifecycle,
        signer_set,
        "near-mainnet",
        "ed25519:account-public-key",
        "router-1",
        "client-1",
        "x25519:client-ephemeral-public-key",
        transcript_digest,
        role_envelope(Role::SignerA, deriver_a_nonce_seed),
        role_envelope(Role::SignerB, deriver_b_nonce_seed),
    )
    .expect("refresh public router request");
    let (deriver_a, _) = request
        .to_signer_wire_messages()
        .expect("refresh router-to-signer messages");
    let router_payload =
        decode_router_to_signer_payload_v1(deriver_a.payload.as_bytes()).expect("router payload");
    let activation = CloudflareSigningWorkerRecipientProofBundleActivationV1::new(
        server_proof_bundle_wire(&router_payload, Role::SignerA, deriver_a_nonce_seed),
        server_proof_bundle_wire(&router_payload, Role::SignerB, deriver_b_nonce_seed),
    )
    .expect("refresh SigningWorker proof-bundle activation");
    CloudflareSigningWorkerRecipientProofBundleActivationRequestV1::new(router_payload, activation)
        .expect("refresh SigningWorker activation request")
}

fn server_output_material_record(
    activation: &CloudflareSigningWorkerRecipientProofBundleActivationRequestV1,
) -> CloudflareServerOutputMaterialRecordV1 {
    let selected_server = &activation.activation_context.signer_set().selected_server;
    CloudflareServerOutputMaterialRecordV1::new(
        activation.activation_context.transcript_digest(),
        OpenedShareKind::XServerBase,
        Role::Server,
        selected_server.server_id.clone(),
        CloudflareSecretMaterial32V1::new([0x5a; 32]),
    )
    .expect("server output material record")
}

fn router_payload_for_signing_worker_activation() -> RouterToSignerPayloadV1 {
    let (deriver_a, _) = ecdsa_threshold_prf_request_with_reconstructed_transcript(2_000)
        .to_signer_wire_messages()
        .expect("router-to-signer messages");
    decode_router_to_signer_payload_v1(deriver_a.payload.as_bytes()).expect("router payload")
}

fn server_proof_bundle_wire(
    router_payload: &RouterToSignerPayloadV1,
    signer_role: Role,
    nonce_seed: u8,
) -> WireMessageV1 {
    let server = &router_payload.signer_set().selected_server;
    let envelope = RecipientProofBundleCiphertextV1::new(
        RecipientOutputEncryptionAlgorithmV1::LocalDeterministicSha256V1,
        signer_identity(signer_role),
        Role::Server,
        OpenedShareKind::XServerBase,
        server.server_id.clone(),
        server.recipient_encryption_key.clone(),
        router_payload.transcript_digest(),
        digest(nonce_seed.wrapping_add(0x10)),
        [nonce_seed; 12],
        EncryptedPayloadV1::new(vec![nonce_seed, nonce_seed.wrapping_add(1)])
            .expect("proof-bundle ciphertext"),
    )
    .expect("recipient proof-bundle envelope");
    WireMessageV1::new(
        WireMessageKindV1::RecipientProofBundle,
        router_payload.transcript_digest(),
        CanonicalWireBytesV1::new(envelope.canonical_bytes().expect("proof-bundle bytes"))
            .expect("wire payload"),
    )
    .expect("recipient proof-bundle wire")
}

fn client_proof_bundle_wire(
    router_payload: &RouterToSignerPayloadV1,
    signer_role: Role,
    nonce_seed: u8,
) -> WireMessageV1 {
    let metadata = router_payload.transcript_metadata();
    let envelope = RecipientProofBundleCiphertextV1::new(
        RecipientOutputEncryptionAlgorithmV1::LocalDeterministicSha256V1,
        signer_identity(signer_role),
        Role::Client,
        OpenedShareKind::XClientBase,
        metadata.client_id.clone(),
        metadata.client_ephemeral_public_key.clone(),
        router_payload.transcript_digest(),
        digest(nonce_seed.wrapping_add(0x20)),
        [nonce_seed; 12],
        EncryptedPayloadV1::new(vec![nonce_seed, nonce_seed.wrapping_add(1)])
            .expect("client proof-bundle ciphertext"),
    )
    .expect("client recipient proof-bundle envelope");
    WireMessageV1::new(
        WireMessageKindV1::RecipientProofBundle,
        router_payload.transcript_digest(),
        CanonicalWireBytesV1::new(
            envelope
                .canonical_bytes()
                .expect("client proof-bundle bytes"),
        )
        .expect("client wire payload"),
    )
    .expect("client recipient proof-bundle wire")
}

fn router_env() -> CloudflareEnvMapV1 {
    CloudflareEnvMapV1::new(vec![
        (ROUTER_REPLAY_DO_BINDING_ENV, " ROUTER_REPLAY_DO "),
        (ROUTER_REPLAY_DO_OBJECT_ENV, "router-replay"),
        (ROUTER_REPLAY_DO_KEY_PREFIX_ENV, "router-replay:"),
        (ROUTER_LIFECYCLE_DO_BINDING_ENV, "ROUTER_LIFECYCLE_DO"),
        (ROUTER_LIFECYCLE_DO_OBJECT_ENV, "router-lifecycle"),
        (ROUTER_LIFECYCLE_DO_KEY_PREFIX_ENV, "router-lifecycle:"),
        (ROUTER_JWT_ISSUER_ENV, "https://issuer.example"),
        (ROUTER_JWT_AUDIENCE_ENV, "router-ab"),
        (
            ROUTER_JWT_JWKS_URL_ENV,
            "https://issuer.example/.well-known/jwks.json",
        ),
        (
            ROUTER_PROJECT_POLICY_DO_BINDING_ENV,
            "ROUTER_PROJECT_POLICY_DO",
        ),
        (ROUTER_PROJECT_POLICY_DO_OBJECT_ENV, "router-project-policy"),
        (
            ROUTER_PROJECT_POLICY_DO_KEY_PREFIX_ENV,
            "router-project-policy:",
        ),
        (ROUTER_QUOTA_DO_BINDING_ENV, "ROUTER_QUOTA_DO"),
        (ROUTER_QUOTA_DO_OBJECT_ENV, "router-quota"),
        (ROUTER_QUOTA_DO_KEY_PREFIX_ENV, "router-quota:"),
        (
            ROUTER_WALLET_BUDGET_DO_BINDING_ENV,
            "ROUTER_WALLET_BUDGET_DO",
        ),
        (ROUTER_WALLET_BUDGET_DO_OBJECT_ENV, "router-wallet-budget"),
        (
            ROUTER_WALLET_BUDGET_DO_KEY_PREFIX_ENV,
            "router-wallet-budget:",
        ),
        (ROUTER_ABUSE_DO_BINDING_ENV, "ROUTER_ABUSE_DO"),
        (ROUTER_ABUSE_DO_OBJECT_ENV, "router-abuse"),
        (ROUTER_ABUSE_DO_KEY_PREFIX_ENV, "router-abuse:"),
        (DERIVER_A_PEER_BINDING_ENV, "DERIVER_A"),
        (DERIVER_B_PEER_BINDING_ENV, "DERIVER_B"),
        (SIGNING_WORKER_PEER_BINDING_ENV, "SIGNING_WORKER"),
    ])
}

fn router_env_with_public_keyset() -> CloudflareEnvMapV1 {
    CloudflareEnvMapV1::new(vec![
        (ROUTER_REPLAY_DO_BINDING_ENV, "ROUTER_REPLAY_DO"),
        (ROUTER_REPLAY_DO_OBJECT_ENV, "router-replay"),
        (ROUTER_REPLAY_DO_KEY_PREFIX_ENV, "router-replay:"),
        (ROUTER_LIFECYCLE_DO_BINDING_ENV, "ROUTER_LIFECYCLE_DO"),
        (ROUTER_LIFECYCLE_DO_OBJECT_ENV, "router-lifecycle"),
        (ROUTER_LIFECYCLE_DO_KEY_PREFIX_ENV, "router-lifecycle:"),
        (ROUTER_JWT_ISSUER_ENV, "https://issuer.example"),
        (ROUTER_JWT_AUDIENCE_ENV, "router-ab"),
        (
            ROUTER_JWT_JWKS_URL_ENV,
            "https://issuer.example/.well-known/jwks.json",
        ),
        (
            ROUTER_PROJECT_POLICY_DO_BINDING_ENV,
            "ROUTER_PROJECT_POLICY_DO",
        ),
        (ROUTER_PROJECT_POLICY_DO_OBJECT_ENV, "router-project-policy"),
        (
            ROUTER_PROJECT_POLICY_DO_KEY_PREFIX_ENV,
            "router-project-policy:",
        ),
        (ROUTER_QUOTA_DO_BINDING_ENV, "ROUTER_QUOTA_DO"),
        (ROUTER_QUOTA_DO_OBJECT_ENV, "router-quota"),
        (ROUTER_QUOTA_DO_KEY_PREFIX_ENV, "router-quota:"),
        (
            ROUTER_WALLET_BUDGET_DO_BINDING_ENV,
            "ROUTER_WALLET_BUDGET_DO",
        ),
        (ROUTER_WALLET_BUDGET_DO_OBJECT_ENV, "router-wallet-budget"),
        (
            ROUTER_WALLET_BUDGET_DO_KEY_PREFIX_ENV,
            "router-wallet-budget:",
        ),
        (ROUTER_ABUSE_DO_BINDING_ENV, "ROUTER_ABUSE_DO"),
        (ROUTER_ABUSE_DO_OBJECT_ENV, "router-abuse"),
        (ROUTER_ABUSE_DO_KEY_PREFIX_ENV, "router-abuse:"),
        (DERIVER_A_PEER_BINDING_ENV, "DERIVER_A"),
        (DERIVER_B_PEER_BINDING_ENV, "DERIVER_B"),
        (SIGNING_WORKER_PEER_BINDING_ENV, "SIGNING_WORKER"),
        (
            DERIVER_A_ENVELOPE_HPKE_KEY_EPOCH_ENV,
            "envelope-hpke-key-epoch-a",
        ),
        (
            DERIVER_A_ENVELOPE_HPKE_PUBLIC_KEY_ENV,
            x25519_public_key(0x11).as_str(),
        ),
        (
            DERIVER_B_ENVELOPE_HPKE_KEY_EPOCH_ENV,
            "envelope-hpke-key-epoch-b",
        ),
        (
            DERIVER_B_ENVELOPE_HPKE_PUBLIC_KEY_ENV,
            x25519_public_key(0x22).as_str(),
        ),
        (
            DERIVER_A_PEER_VERIFYING_KEY_HEX_ENV,
            signer_peer_verifying_key_hex(Role::SignerA).as_str(),
        ),
        (
            DERIVER_B_PEER_VERIFYING_KEY_HEX_ENV,
            signer_peer_verifying_key_hex(Role::SignerB).as_str(),
        ),
        (
            SIGNING_WORKER_SERVER_OUTPUT_HPKE_KEY_EPOCH_ENV,
            signer_set().selected_server.key_epoch.as_str(),
        ),
        (
            SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY_ENV,
            signer_set()
                .selected_server
                .recipient_encryption_key
                .as_str(),
        ),
    ])
}

fn router_admission_env() -> CloudflareEnvMapV1 {
    CloudflareEnvMapV1::new(vec![
        (ROUTER_JWT_ISSUER_ENV, "https://issuer.example"),
        (ROUTER_JWT_AUDIENCE_ENV, "router-ab"),
        (
            ROUTER_JWT_JWKS_URL_ENV,
            "https://issuer.example/.well-known/jwks.json",
        ),
        (
            ROUTER_PROJECT_POLICY_DO_BINDING_ENV,
            "ROUTER_PROJECT_POLICY_DO",
        ),
        (ROUTER_PROJECT_POLICY_DO_OBJECT_ENV, "router-project-policy"),
        (
            ROUTER_PROJECT_POLICY_DO_KEY_PREFIX_ENV,
            "router-project-policy:",
        ),
        (ROUTER_QUOTA_DO_BINDING_ENV, "ROUTER_QUOTA_DO"),
        (ROUTER_QUOTA_DO_OBJECT_ENV, "router-quota"),
        (ROUTER_QUOTA_DO_KEY_PREFIX_ENV, "router-quota:"),
        (ROUTER_ABUSE_DO_BINDING_ENV, "ROUTER_ABUSE_DO"),
        (ROUTER_ABUSE_DO_OBJECT_ENV, "router-abuse"),
        (ROUTER_ABUSE_DO_KEY_PREFIX_ENV, "router-abuse:"),
    ])
}

fn router_admission_bindings() -> CloudflareRouterAdmissionBindingsV1 {
    parse_cloudflare_router_admission_bindings_v1(&router_admission_env())
        .expect("router admission bindings")
}

fn router_wallet_budget_binding() -> CloudflareDurableObjectBindingV1 {
    do_binding(
        CloudflareDurableObjectScopeV1::RouterWalletBudget,
        "ROUTER_WALLET_BUDGET_DO",
    )
}

fn router_wallet_budget_put_grant_request() -> CloudflareRouterWalletBudgetPutGrantRequestV1 {
    CloudflareRouterWalletBudgetPutGrantRequestV1 {
        signing_grant_id: "signing-grant-1".to_owned(),
        wallet_id: "account.near".to_owned(),
        rp_id: "localhost".to_owned(),
        authorized_signers: vec![CloudflareRouterWalletBudgetSignerBindingV1::new(
            CloudflareRouterWalletBudgetCurveV1::Ed25519,
            "session-1",
            "server-a",
        )
        .expect("wallet budget signer binding")],
        initial_signature_uses: 3,
        expires_at_ms: 3_000,
        issuer_jwt_id: "issuer-jwt-1".to_owned(),
        now_unix_ms: 1_000,
    }
}

fn router_wallet_budget_reserve_request() -> CloudflareRouterWalletBudgetReserveRequestV1 {
    CloudflareRouterWalletBudgetReserveRequestV1 {
        signing_grant_id: "signing-grant-1".to_owned(),
        curve: CloudflareRouterWalletBudgetCurveV1::Ed25519,
        threshold_session_id: "session-1".to_owned(),
        signing_worker_id: "server-a".to_owned(),
        operation_id: "operation-1".to_owned(),
        request_digest: digest(0x70),
        signature_uses: 1,
        expires_at_ms: 2_000,
        now_unix_ms: 1_000,
    }
}

fn deriver_a_env() -> CloudflareEnvMapV1 {
    CloudflareEnvMapV1::new(vec![
        (
            DERIVER_A_ROOT_SHARE_DO_BINDING_ENV,
            "DERIVER_A_ROOT_SHARE_DO".to_string(),
        ),
        (
            DERIVER_A_ROOT_SHARE_DO_OBJECT_ENV,
            "deriver-a-root-share".to_string(),
        ),
        (
            DERIVER_A_ROOT_SHARE_DO_KEY_PREFIX_ENV,
            "deriver-a-root-share:".to_string(),
        ),
        (
            DERIVER_A_ROOT_SHARE_WIRE_SECRET_BINDING_ENV,
            "DERIVER_A_ROOT_SHARE_WIRE_SECRET".to_string(),
        ),
        (
            DERIVER_A_ENVELOPE_HPKE_PRIVATE_KEY_BINDING_ENV,
            "DERIVER_A_ENVELOPE_HPKE_PRIVATE_KEY".to_string(),
        ),
        (
            DERIVER_A_ENVELOPE_HPKE_KEY_EPOCH_ENV,
            "envelope-hpke-key-epoch-a".to_string(),
        ),
        (
            DERIVER_A_ENVELOPE_HPKE_PUBLIC_KEY_ENV,
            x25519_public_key(0x11),
        ),
        (
            DERIVER_A_PEER_SIGNING_KEY_BINDING_ENV,
            "DERIVER_A_PEER_SIGNING_KEY".to_string(),
        ),
        (
            DERIVER_A_PEER_SIGNING_KEY_EPOCH_ENV,
            "key-epoch-a".to_string(),
        ),
        (
            DERIVER_A_PEER_VERIFYING_KEY_HEX_ENV,
            signer_peer_verifying_key_hex(Role::SignerA),
        ),
        (
            DERIVER_B_PEER_VERIFYING_KEY_HEX_ENV,
            signer_peer_verifying_key_hex(Role::SignerB),
        ),
        (DERIVER_B_PEER_BINDING_ENV, "DERIVER_B".to_string()),
        (
            SIGNING_WORKER_PEER_BINDING_ENV,
            "SIGNING_WORKER".to_string(),
        ),
    ])
}

fn deriver_b_env() -> CloudflareEnvMapV1 {
    CloudflareEnvMapV1::new(vec![
        (
            DERIVER_B_ROOT_SHARE_DO_BINDING_ENV,
            "DERIVER_B_ROOT_SHARE_DO".to_string(),
        ),
        (
            DERIVER_B_ROOT_SHARE_DO_OBJECT_ENV,
            "deriver-b-root-share".to_string(),
        ),
        (
            DERIVER_B_ROOT_SHARE_DO_KEY_PREFIX_ENV,
            "deriver-b-root-share:".to_string(),
        ),
        (
            DERIVER_B_ROOT_SHARE_WIRE_SECRET_BINDING_ENV,
            "DERIVER_B_ROOT_SHARE_WIRE_SECRET".to_string(),
        ),
        (
            DERIVER_B_ENVELOPE_HPKE_PRIVATE_KEY_BINDING_ENV,
            "DERIVER_B_ENVELOPE_HPKE_PRIVATE_KEY".to_string(),
        ),
        (
            DERIVER_B_ENVELOPE_HPKE_KEY_EPOCH_ENV,
            "envelope-hpke-key-epoch-b".to_string(),
        ),
        (
            DERIVER_B_ENVELOPE_HPKE_PUBLIC_KEY_ENV,
            x25519_public_key(0x22),
        ),
        (
            DERIVER_B_PEER_SIGNING_KEY_BINDING_ENV,
            "DERIVER_B_PEER_SIGNING_KEY".to_string(),
        ),
        (
            DERIVER_B_PEER_SIGNING_KEY_EPOCH_ENV,
            "key-epoch-b".to_string(),
        ),
        (
            DERIVER_A_PEER_VERIFYING_KEY_HEX_ENV,
            signer_peer_verifying_key_hex(Role::SignerA),
        ),
        (
            DERIVER_B_PEER_VERIFYING_KEY_HEX_ENV,
            signer_peer_verifying_key_hex(Role::SignerB),
        ),
        (DERIVER_A_PEER_BINDING_ENV, "DERIVER_A".to_string()),
        (
            SIGNING_WORKER_PEER_BINDING_ENV,
            "SIGNING_WORKER".to_string(),
        ),
    ])
}

fn signing_worker_env() -> CloudflareEnvMapV1 {
    CloudflareEnvMapV1::new(vec![
        (
            SIGNING_WORKER_SERVER_OUTPUT_DO_BINDING_ENV,
            "SIGNING_WORKER_SERVER_OUTPUT_DO".to_string(),
        ),
        (
            SIGNING_WORKER_SERVER_OUTPUT_DO_OBJECT_ENV,
            "signing-worker-server-output".to_string(),
        ),
        (
            SIGNING_WORKER_SERVER_OUTPUT_DO_KEY_PREFIX_ENV,
            "signing-worker-server-output:".to_string(),
        ),
        (
            SIGNING_WORKER_SERVER_OUTPUT_HPKE_PRIVATE_KEY_BINDING_ENV,
            "SIGNING_WORKER_SERVER_OUTPUT_HPKE_PRIVATE_KEY".to_string(),
        ),
        (
            SIGNING_WORKER_SERVER_OUTPUT_HPKE_KEY_EPOCH_ENV,
            "server-epoch".to_string(),
        ),
        (
            SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY_ENV,
            signer_set().selected_server.recipient_encryption_key,
        ),
    ])
}

#[test]
fn router_bindings_accept_router_scoped_durable_objects() {
    let bindings = CloudflareRouterBindingsV1::new(
        do_binding(
            CloudflareDurableObjectScopeV1::RouterReplay,
            "ROUTER_REPLAY_DO",
        ),
        do_binding(
            CloudflareDurableObjectScopeV1::RouterLifecycle,
            "ROUTER_LIFECYCLE_DO",
        ),
        router_wallet_budget_binding(),
        router_admission_bindings(),
        peer(CloudflareWorkerRoleV1::DeriverA, "DERIVER_A"),
        peer(CloudflareWorkerRoleV1::DeriverB, "DERIVER_B"),
        peer(CloudflareWorkerRoleV1::SigningWorker, "SIGNING_WORKER"),
    )
    .expect("router bindings");
    let startup = CloudflareWorkerBindingsV1::router(bindings).expect("router startup");

    assert_eq!(startup.worker_role(), CloudflareWorkerRoleV1::Router);
    let CloudflareWorkerBindingsV1::Router { bindings } = startup else {
        panic!("expected router startup bindings");
    };
    assert_eq!(
        bindings.admission.stores.project_policy.scope,
        CloudflareDurableObjectScopeV1::RouterProjectPolicy
    );
}

#[test]
fn router_admission_bindings_parse_router_only_provider_config() {
    let bindings = parse_cloudflare_router_admission_bindings_v1(&router_admission_env())
        .expect("router admission bindings");

    assert_eq!(bindings.jwt.issuer, "https://issuer.example");
    assert_eq!(
        bindings.stores.project_policy.scope,
        CloudflareDurableObjectScopeV1::RouterProjectPolicy
    );
    assert_eq!(
        bindings.stores.quota.scope,
        CloudflareDurableObjectScopeV1::RouterQuota
    );
    assert_eq!(
        bindings.stores.abuse.scope,
        CloudflareDurableObjectScopeV1::RouterAbuse
    );
}

#[test]
fn router_admission_bindings_reject_missing_jwks_url() {
    let env = CloudflareEnvMapV1::new(vec![
        (ROUTER_JWT_ISSUER_ENV, "https://issuer.example"),
        (ROUTER_JWT_AUDIENCE_ENV, "router-ab"),
        (
            ROUTER_PROJECT_POLICY_DO_BINDING_ENV,
            "ROUTER_PROJECT_POLICY_DO",
        ),
        (ROUTER_PROJECT_POLICY_DO_OBJECT_ENV, "router-project-policy"),
        (
            ROUTER_PROJECT_POLICY_DO_KEY_PREFIX_ENV,
            "router-project-policy:",
        ),
        (ROUTER_QUOTA_DO_BINDING_ENV, "ROUTER_QUOTA_DO"),
        (ROUTER_QUOTA_DO_OBJECT_ENV, "router-quota"),
        (ROUTER_QUOTA_DO_KEY_PREFIX_ENV, "router-quota:"),
        (ROUTER_ABUSE_DO_BINDING_ENV, "ROUTER_ABUSE_DO"),
        (ROUTER_ABUSE_DO_OBJECT_ENV, "router-abuse"),
        (ROUTER_ABUSE_DO_KEY_PREFIX_ENV, "router-abuse:"),
    ]);

    let err = parse_cloudflare_router_admission_bindings_v1(&env)
        .expect_err("missing JWKS URL must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::MissingLocalBinding);
}

#[test]
fn router_worker_runtime_builds_only_router_scoped_durable_object_calls() {
    let runtime = CloudflareRouterWorkerRuntimeV1::new(
        CloudflareRouterBindingsV1::new(
            do_binding(
                CloudflareDurableObjectScopeV1::RouterReplay,
                "ROUTER_REPLAY_DO",
            ),
            do_binding(
                CloudflareDurableObjectScopeV1::RouterLifecycle,
                "ROUTER_LIFECYCLE_DO",
            ),
            router_wallet_budget_binding(),
            router_admission_bindings(),
            peer(CloudflareWorkerRoleV1::DeriverA, "DERIVER_A"),
            peer(CloudflareWorkerRoleV1::DeriverB, "DERIVER_B"),
            peer(CloudflareWorkerRoleV1::SigningWorker, "SIGNING_WORKER"),
        )
        .expect("router bindings"),
    )
    .expect("router runtime");

    let replay_call = runtime
        .replay_reserve_call(
            CloudflareReplayReserveRequestV1::new("request-1", digest(0x11), 1000)
                .expect("replay request"),
        )
        .expect("replay call");
    let lifecycle_call = runtime
        .lifecycle_put_public_state_call(lifecycle_state())
        .expect("lifecycle call");
    let ceremony_call = runtime
        .derivation_ceremony_put_state_call(created_derivation_ceremony())
        .expect("ceremony call");

    assert_eq!(replay_call.worker_role, CloudflareWorkerRoleV1::Router);
    assert_eq!(
        replay_call.binding.scope,
        CloudflareDurableObjectScopeV1::RouterReplay
    );
    assert_eq!(
        lifecycle_call.binding.scope,
        CloudflareDurableObjectScopeV1::RouterLifecycle
    );
    assert_eq!(
        ceremony_call.operation_kind(),
        CloudflareDurableObjectOperationKindV1::DerivationCeremonyPutState
    );
    assert_eq!(
        ceremony_call.binding.scope,
        CloudflareDurableObjectScopeV1::RouterLifecycle
    );
    assert_eq!(
        runtime.admission_bindings().stores.project_policy.scope,
        CloudflareDurableObjectScopeV1::RouterProjectPolicy
    );
    assert_eq!(
        runtime.deriver_a_peer().peer_role,
        CloudflareWorkerRoleV1::DeriverA
    );
    assert_eq!(
        runtime.deriver_b_peer().peer_role,
        CloudflareWorkerRoleV1::DeriverB
    );
    assert_eq!(
        runtime.signing_worker_peer().peer_role,
        CloudflareWorkerRoleV1::SigningWorker
    );
}

#[test]
fn router_worker_runtime_normalizes_public_request_into_admission_plan() {
    let runtime = CloudflareRouterWorkerRuntimeV1::new(
        CloudflareRouterBindingsV1::new(
            do_binding(
                CloudflareDurableObjectScopeV1::RouterReplay,
                "ROUTER_REPLAY_DO",
            ),
            do_binding(
                CloudflareDurableObjectScopeV1::RouterLifecycle,
                "ROUTER_LIFECYCLE_DO",
            ),
            router_wallet_budget_binding(),
            router_admission_bindings(),
            peer(CloudflareWorkerRoleV1::DeriverA, "DERIVER_A"),
            peer(CloudflareWorkerRoleV1::DeriverB, "DERIVER_B"),
            peer(CloudflareWorkerRoleV1::SigningWorker, "SIGNING_WORKER"),
        )
        .expect("router bindings"),
    )
    .expect("router runtime");
    let request = ecdsa_threshold_prf_request(2_000);
    let router_replay_digest = request.router_replay_digest();
    let plan = runtime
        .public_request_admission_plan_at(
            1_000,
            request,
            trusted_admission(
                ExpensiveWorkGateDecisionV1::accepted("gate-request-1").expect("accepted"),
            ),
        )
        .expect("public request admission plan");

    plan.validate().expect("plan validation");
    assert_eq!(
        plan.replay_reserve_call().binding.scope,
        CloudflareDurableObjectScopeV1::RouterReplay
    );
    assert_eq!(
        plan.lifecycle_put_call().binding.scope,
        CloudflareDurableObjectScopeV1::RouterLifecycle
    );
    assert_eq!(
        plan.lifecycle_requested_put_call().binding.scope,
        CloudflareDurableObjectScopeV1::RouterLifecycle
    );
    let CloudflareRouterPublicAdmissionPlanV1::Forward {
        deriver_a_message,
        deriver_b_message,
        ..
    } = &plan
    else {
        panic!("accepted admission must forward");
    };
    assert_eq!(deriver_a_message.kind, WireMessageKindV1::RouterToSignerA);
    assert_eq!(deriver_b_message.kind, WireMessageKindV1::RouterToSignerB);
    assert_eq!(
        plan.replay_reserve_call().storage_key(),
        format!(
            "ROUTER_REPLAY_DO:replay/request-nonce-1/{}",
            digest_hex(router_replay_digest)
        )
    );
}

#[test]
fn router_worker_runtime_builds_forward_plan_for_accepted_admission() {
    let runtime = CloudflareRouterWorkerRuntimeV1::new(
        CloudflareRouterBindingsV1::new(
            do_binding(
                CloudflareDurableObjectScopeV1::RouterReplay,
                "ROUTER_REPLAY_DO",
            ),
            do_binding(
                CloudflareDurableObjectScopeV1::RouterLifecycle,
                "ROUTER_LIFECYCLE_DO",
            ),
            router_wallet_budget_binding(),
            router_admission_bindings(),
            peer(CloudflareWorkerRoleV1::DeriverA, "DERIVER_A"),
            peer(CloudflareWorkerRoleV1::DeriverB, "DERIVER_B"),
            peer(CloudflareWorkerRoleV1::SigningWorker, "SIGNING_WORKER"),
        )
        .expect("router bindings"),
    )
    .expect("router runtime");
    let plan = runtime
        .public_request_admission_plan_at(
            1_000,
            ecdsa_threshold_prf_request(2_000),
            trusted_admission(
                ExpensiveWorkGateDecisionV1::accepted("gate-request-1").expect("accepted"),
            ),
        )
        .expect("admission plan");

    plan.validate().expect("plan validation");
    let CloudflareRouterPublicAdmissionPlanV1::Forward {
        lifecycle_requested_put_call,
        lifecycle_put_call,
        deriver_a_message,
        deriver_b_message,
        ..
    } = plan
    else {
        panic!("accepted admission must forward");
    };
    assert_eq!(deriver_a_message.kind, WireMessageKindV1::RouterToSignerA);
    assert_eq!(deriver_b_message.kind, WireMessageKindV1::RouterToSignerB);
    let CloudflareDurableObjectRequestV1::RouterLifecyclePutPublicState { state } =
        lifecycle_requested_put_call.request
    else {
        panic!("expected requested lifecycle put request");
    };
    assert!(matches!(state, RouterAbLifecycleStateV1::Requested { .. }));
    let CloudflareDurableObjectRequestV1::RouterLifecyclePutPublicState { state } =
        lifecycle_put_call.request
    else {
        panic!("expected lifecycle put request");
    };
    assert!(matches!(
        state,
        RouterAbLifecycleStateV1::GateAccepted { .. }
    ));
}

#[test]
fn router_worker_runtime_builds_stop_plan_for_rejected_admission() {
    let runtime = CloudflareRouterWorkerRuntimeV1::new(
        CloudflareRouterBindingsV1::new(
            do_binding(
                CloudflareDurableObjectScopeV1::RouterReplay,
                "ROUTER_REPLAY_DO",
            ),
            do_binding(
                CloudflareDurableObjectScopeV1::RouterLifecycle,
                "ROUTER_LIFECYCLE_DO",
            ),
            router_wallet_budget_binding(),
            router_admission_bindings(),
            peer(CloudflareWorkerRoleV1::DeriverA, "DERIVER_A"),
            peer(CloudflareWorkerRoleV1::DeriverB, "DERIVER_B"),
            peer(CloudflareWorkerRoleV1::SigningWorker, "SIGNING_WORKER"),
        )
        .expect("router bindings"),
    )
    .expect("router runtime");
    let plan = runtime
        .public_request_admission_plan_at(
            1_000,
            ecdsa_threshold_prf_request(2_000),
            trusted_admission(
                ExpensiveWorkGateDecisionV1::rejected(GateRejectReasonV1::RateLimited, 1_000)
                    .expect("rejected"),
            ),
        )
        .expect("admission plan");

    plan.validate().expect("plan validation");
    let CloudflareRouterPublicAdmissionPlanV1::Stop {
        lifecycle_requested_put_call,
        lifecycle_put_call,
        ..
    } = plan
    else {
        panic!("rejected admission must stop");
    };
    let CloudflareDurableObjectRequestV1::RouterLifecyclePutPublicState { state } =
        lifecycle_requested_put_call.request
    else {
        panic!("expected requested lifecycle put request");
    };
    assert!(matches!(state, RouterAbLifecycleStateV1::Requested { .. }));
    let CloudflareDurableObjectRequestV1::RouterLifecyclePutPublicState { state } =
        lifecycle_put_call.request
    else {
        panic!("expected lifecycle put request");
    };
    assert!(matches!(
        state,
        RouterAbLifecycleStateV1::GateRejected { .. }
    ));
}

#[test]
fn trusted_admission_rejects_mismatched_request_resource() {
    let request = ecdsa_threshold_prf_request(2_000);
    let admission = CloudflareRouterTrustedAdmissionV1::new(
        ExpensiveWorkGateContextV1::new(
            ExpensiveWorkKindV1::RegistrationPrepare,
            "org-1",
            "project-1",
            "dev",
            "different.near",
            GatePrincipalV1::authenticated_session("user-1", "session-1").expect("principal"),
            digest(0x90),
        )
        .expect("gate context"),
        ExpensiveWorkGateDecisionV1::accepted("gate-request-1").expect("accepted"),
    )
    .expect("trusted admission");
    let err = admission
        .validate_for_request(&request)
        .expect_err("mismatched resource must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidGateDecision);
}

#[test]
fn trusted_admission_rejects_preauth_for_non_registration_work() {
    let lifecycle = LifecycleScopeV1::new(
        "lifecycle-2",
        ExpensiveWorkKindV1::KeyExport,
        root_epoch(),
        "account.near",
        "session-1",
        "signer-set-v1",
        "server-a",
    )
    .expect("lifecycle scope");
    let signer_set = signer_set();
    let transcript_digest = public_request_transcript_digest(&lifecycle, &signer_set);
    let request = EcdsaThresholdPrfRequestV1::new(
        "request-nonce-2",
        2_000,
        lifecycle,
        signer_set,
        "near-mainnet",
        "ed25519:account-public-key",
        "router-1",
        "client-1",
        "x25519:client-ephemeral-public-key",
        transcript_digest,
        role_envelope(Role::SignerA, 0x10),
        role_envelope(Role::SignerB, 0x20),
    )
    .expect("public router request");
    let admission = CloudflareRouterTrustedAdmissionV1::new(
        ExpensiveWorkGateContextV1::new(
            ExpensiveWorkKindV1::KeyExport,
            "org-1",
            "project-1",
            "dev",
            "account.near",
            GatePrincipalV1::pre_auth_session("pre-auth-1").expect("principal"),
            digest(0x90),
        )
        .expect("gate context"),
        ExpensiveWorkGateDecisionV1::accepted("gate-request-1").expect("accepted"),
    )
    .expect("trusted admission");
    let err = admission
        .validate_for_request(&request)
        .expect_err("pre-auth key export must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidGateDecision);
}

#[test]
fn router_derives_trusted_admission_from_server_owned_checks() {
    let request = ecdsa_threshold_prf_request(2_000);
    let admission = derive_cloudflare_router_trusted_admission_v1(
        &request,
        trusted_metadata(),
        allow_checks("gate-request-1"),
    )
    .expect("trusted admission");

    admission
        .validate_for_request(&request)
        .expect("admission should match request");
    assert_eq!(admission.context.org_id, "org-1");
    assert_eq!(admission.context.project_id, "project-1");
    assert!(matches!(
        admission.decision,
        ExpensiveWorkGateDecisionV1::Accepted { .. }
    ));
}

#[test]
fn router_derives_trusted_admission_from_provider_boundary() {
    let request = ecdsa_threshold_prf_request(2_000);
    let output =
        CloudflareRouterAdmissionProviderOutputV1::new(trusted_metadata(), allow_checks("gate-1"))
            .expect("provider output");
    let mut provider = StaticAdmissionProvider::new(output);

    let admission =
        derive_cloudflare_router_trusted_admission_from_provider_v1(&request, &mut provider)
            .expect("trusted admission");

    admission
        .validate_for_request(&request)
        .expect("admission should match request");
    assert_eq!(provider.calls, 1);
    assert!(matches!(
        admission.decision,
        ExpensiveWorkGateDecisionV1::Accepted { .. }
    ));
}

#[test]
fn router_admission_provider_output_rejects_metadata_mismatch() {
    let request = ecdsa_threshold_prf_request(2_000);
    let mismatched_metadata = CloudflareRouterTrustedRequestMetadataV1::new(
        ExpensiveWorkKindV1::RegistrationPrepare,
        "org-1",
        "project-1",
        "dev",
        "different.near",
        CloudflareRouterAuthContextV1::authenticated_session("user-1", "session-1")
            .expect("auth context"),
        digest(0x90),
    )
    .expect("metadata");
    let output =
        CloudflareRouterAdmissionProviderOutputV1::new(mismatched_metadata, allow_checks("gate-1"))
            .expect("provider output");
    let mut provider = StaticAdmissionProvider::new(output);

    let err = derive_cloudflare_router_trusted_admission_from_provider_v1(&request, &mut provider)
        .expect_err("metadata mismatch must fail");

    assert_eq!(provider.calls, 1);
    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidGateDecision);
}

#[test]
fn router_admission_provider_output_rejects_invalid_checks() {
    let err = CloudflareRouterAdmissionProviderOutputV1::new(
        trusted_metadata(),
        CloudflareRouterAdmissionChecksV1 {
            project_policy: CloudflareRouterProjectPolicyV1::Allowed,
            abuse: CloudflareRouterAbuseCheckV1::RateLimited { retry_after_ms: 0 },
            quota: CloudflareRouterQuotaCheckV1::Accepted {
                request_id: "gate-1".to_owned(),
            },
        },
    )
    .expect_err("invalid checks must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidTimeRange);
}

#[test]
fn router_composite_provider_accepts_verified_jwt_policy_abuse_and_quota() {
    let request = ecdsa_threshold_prf_request(2_000);
    let mut provider = composite_admission_provider(
        verified_jwt_claims("session-1", "account.near"),
        vec![ExpensiveWorkKindV1::RegistrationPrepare],
        CloudflareRouterAbuseCheckV1::Allowed,
        CloudflareRouterQuotaCheckV1::Accepted {
            request_id: "gate-request-1".to_owned(),
        },
    );

    let admission =
        derive_cloudflare_router_trusted_admission_from_provider_v1(&request, &mut provider)
            .expect("trusted admission");

    admission
        .validate_for_request(&request)
        .expect("admission should match request");
    assert_eq!(admission.context.org_id, "org-1");
    assert_eq!(admission.context.project_id, "project-1");
    assert!(matches!(
        admission.decision,
        ExpensiveWorkGateDecisionV1::Accepted { .. }
    ));
}

#[test]
fn router_composite_provider_rejects_verified_jwt_scope_mismatch() {
    let request = ecdsa_threshold_prf_request(2_000);
    let mut provider = composite_admission_provider(
        verified_jwt_claims("session-1", "different.near"),
        vec![ExpensiveWorkKindV1::RegistrationPrepare],
        CloudflareRouterAbuseCheckV1::Allowed,
        CloudflareRouterQuotaCheckV1::Accepted {
            request_id: "gate-request-1".to_owned(),
        },
    );

    let err = derive_cloudflare_router_trusted_admission_from_provider_v1(&request, &mut provider)
        .expect_err("verified jwt account mismatch must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidGateDecision);
}

#[test]
fn router_composite_provider_derives_stop_from_project_policy() {
    let request = ecdsa_threshold_prf_request(2_000);
    let mut provider = composite_admission_provider(
        verified_jwt_claims("session-1", "account.near"),
        vec![ExpensiveWorkKindV1::KeyExport],
        CloudflareRouterAbuseCheckV1::Allowed,
        CloudflareRouterQuotaCheckV1::Accepted {
            request_id: "gate-request-1".to_owned(),
        },
    );

    let admission =
        derive_cloudflare_router_trusted_admission_from_provider_v1(&request, &mut provider)
            .expect("trusted admission");

    assert!(matches!(
        admission.decision,
        ExpensiveWorkGateDecisionV1::Rejected {
            reason: GateRejectReasonV1::AbusePolicy,
            retry_after_ms: 1_000
        }
    ));
    assert!(!admission
        .allows_signer_forwarding()
        .expect("forwarding decision"));
}

#[test]
fn router_composite_provider_derives_stop_from_abuse_rate_limit() {
    let request = ecdsa_threshold_prf_request(2_000);
    let mut provider = composite_admission_provider(
        verified_jwt_claims("session-1", "account.near"),
        vec![ExpensiveWorkKindV1::RegistrationPrepare],
        CloudflareRouterAbuseCheckV1::RateLimited {
            retry_after_ms: 2_000,
        },
        CloudflareRouterQuotaCheckV1::Accepted {
            request_id: "gate-request-1".to_owned(),
        },
    );

    let admission =
        derive_cloudflare_router_trusted_admission_from_provider_v1(&request, &mut provider)
            .expect("trusted admission");

    assert!(matches!(
        admission.decision,
        ExpensiveWorkGateDecisionV1::Rejected {
            reason: GateRejectReasonV1::RateLimited,
            retry_after_ms: 2_000
        }
    ));
}

#[test]
fn router_bearer_authorization_parses_strict_bearer_header() {
    let authorization = CloudflareRouterBearerAuthorizationV1::from_authorization_header(
        "Bearer header.payload.sig",
    )
    .expect("bearer authorization");

    assert_eq!(authorization.token, "header.payload.sig");
}

#[test]
fn router_bearer_authorization_rejects_wrong_scheme_and_whitespace_token() {
    let wrong_scheme =
        CloudflareRouterBearerAuthorizationV1::from_authorization_header("Basic abc")
            .expect_err("wrong scheme must fail");
    let whitespace_token =
        CloudflareRouterBearerAuthorizationV1::from_authorization_header("Bearer abc def")
            .expect_err("whitespace token must fail");

    assert_eq!(
        wrong_scheme.code(),
        RouterAbProtocolErrorCode::MalformedWirePayload
    );
    assert_eq!(
        whitespace_token.code(),
        RouterAbProtocolErrorCode::MalformedWirePayload
    );
}

#[test]
fn router_ed25519_jwks_jwt_verifier_accepts_bound_claims() {
    let signing_key = SigningKey::from_bytes(&[0x42; 32]);
    let jwks_json = ed25519_jwks_json(&signing_key, "router-key-1");
    let mut verifier = CloudflareRouterEd25519JwksJwtVerifierV1::from_jwks_json(&jwks_json)
        .expect("ed25519 jwks verifier");
    let token = ed25519_jwt(&signing_key, "router-key-1", valid_router_jwt_claims());
    let authorization = CloudflareRouterBearerAuthorizationV1::from_authorization_header(&format!(
        "Bearer {token}"
    ))
    .expect("authorization");

    let claims = verifier
        .verify_public_request_jwt(
            &router_admission_bindings().jwt,
            &authorization,
            &ecdsa_threshold_prf_request(2_000),
            1_000,
            digest(0x91),
        )
        .expect("verified claims");

    assert_eq!(claims.subject_id, "user-1");
    assert_eq!(claims.session_id, "session-1");
    assert_eq!(claims.account_id, "account.near");
    assert_eq!(claims.trusted_source_digest, digest(0x91));
}

#[test]
fn router_ed25519_jwks_jwt_verifier_rejects_bad_signature() {
    let signing_key = SigningKey::from_bytes(&[0x42; 32]);
    let wrong_signing_key = SigningKey::from_bytes(&[0x43; 32]);
    let jwks_json = ed25519_jwks_json(&signing_key, "router-key-1");
    let mut verifier = CloudflareRouterEd25519JwksJwtVerifierV1::from_jwks_json(&jwks_json)
        .expect("ed25519 jwks verifier");
    let token = ed25519_jwt(
        &wrong_signing_key,
        "router-key-1",
        valid_router_jwt_claims(),
    );
    let authorization = CloudflareRouterBearerAuthorizationV1::from_authorization_header(&format!(
        "Bearer {token}"
    ))
    .expect("authorization");

    let err = verifier
        .verify_public_request_jwt(
            &router_admission_bindings().jwt,
            &authorization,
            &ecdsa_threshold_prf_request(2_000),
            1_000,
            digest(0x91),
        )
        .expect_err("bad signature must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::MalformedWirePayload);
}

#[test]
fn router_ed25519_jwks_jwt_verifier_rejects_expired_token() {
    let signing_key = SigningKey::from_bytes(&[0x42; 32]);
    let jwks_json = ed25519_jwks_json(&signing_key, "router-key-1");
    let mut verifier = CloudflareRouterEd25519JwksJwtVerifierV1::from_jwks_json(&jwks_json)
        .expect("ed25519 jwks verifier");
    let mut claims = valid_router_jwt_claims();
    claims["exp"] = serde_json::json!(1);
    let token = ed25519_jwt(&signing_key, "router-key-1", claims);
    let authorization = CloudflareRouterBearerAuthorizationV1::from_authorization_header(&format!(
        "Bearer {token}"
    ))
    .expect("authorization");

    let err = verifier
        .verify_public_request_jwt(
            &router_admission_bindings().jwt,
            &authorization,
            &ecdsa_threshold_prf_request(2_000),
            1_000,
            digest(0x91),
        )
        .expect_err("expired token must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::ExpiredLocalRequest);
}

#[test]
fn router_ed25519_jwks_jwt_verifier_rejects_request_scope_mismatch() {
    let signing_key = SigningKey::from_bytes(&[0x42; 32]);
    let jwks_json = ed25519_jwks_json(&signing_key, "router-key-1");
    let mut verifier = CloudflareRouterEd25519JwksJwtVerifierV1::from_jwks_json(&jwks_json)
        .expect("ed25519 jwks verifier");
    let mut claims = valid_router_jwt_claims();
    claims["account_id"] = serde_json::json!("different.near");
    let token = ed25519_jwt(&signing_key, "router-key-1", claims);
    let authorization = CloudflareRouterBearerAuthorizationV1::from_authorization_header(&format!(
        "Bearer {token}"
    ))
    .expect("authorization");

    let err = verifier
        .verify_public_request_jwt(
            &router_admission_bindings().jwt,
            &authorization,
            &ecdsa_threshold_prf_request(2_000),
            1_000,
            digest(0x91),
        )
        .expect_err("request scope mismatch must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidGateDecision);
}

#[test]
fn router_wallet_session_credential_accepts_bearer_authorization_header() {
    let credential = CloudflareRouterWalletSessionCredentialV1::from_bearer_authorization_header(
        "Bearer wallet-session-token",
    )
    .expect("wallet session credential");

    credential.validate().expect("credential validates");
    match credential {
        CloudflareRouterWalletSessionCredentialV1::Bearer { authorization } => {
            assert_eq!(authorization.token, "wallet-session-token");
        }
    }
}

#[test]
fn router_ed25519_jwks_wallet_session_verifier_accepts_normal_signing_claims() {
    let signing_key = SigningKey::from_bytes(&[0x42; 32]);
    let jwks_json = ed25519_jwks_json(&signing_key, "router-key-1");
    let mut verifier = CloudflareRouterEd25519JwksJwtVerifierV1::from_jwks_json(&jwks_json)
        .expect("ed25519 jwks verifier");
    let token = ed25519_jwt(
        &signing_key,
        "router-key-1",
        valid_wallet_session_jwt_claims(),
    );
    let credential = CloudflareRouterWalletSessionCredentialV1::bearer(
        CloudflareRouterBearerAuthorizationV1::from_authorization_header(&format!(
            "Bearer {token}"
        ))
        .expect("authorization"),
    )
    .expect("wallet session credential");

    let session = verifier
        .verify_wallet_session(
            &router_admission_bindings().jwt,
            &credential,
            digest(0x90),
            1_000,
        )
        .expect("wallet session verifies");

    assert_eq!(session.subject_id, "user-1");
    assert_eq!(session.account_id, "account.near");
    assert_eq!(session.threshold_session_id, "session-1");
    assert_eq!(session.signing_grant_id, "signing-grant-1");
    assert_eq!(session.authorization_level, "normal-signing");
    assert_eq!(session.signing_worker_id, "server-a");
    assert_eq!(session.expires_at_ms, 3_000);
}

#[test]
fn router_ed25519_jwks_wallet_session_verifier_rejects_missing_signing_grant_id() {
    let signing_key = SigningKey::from_bytes(&[0x42; 32]);
    let jwks_json = ed25519_jwks_json(&signing_key, "router-key-1");
    let mut verifier = CloudflareRouterEd25519JwksJwtVerifierV1::from_jwks_json(&jwks_json)
        .expect("ed25519 jwks verifier");
    let mut claims = valid_wallet_session_jwt_claims();
    claims
        .as_object_mut()
        .expect("claims object")
        .remove("signingGrantId");
    let token = ed25519_jwt(&signing_key, "router-key-1", claims);
    let credential = CloudflareRouterWalletSessionCredentialV1::bearer(
        CloudflareRouterBearerAuthorizationV1::from_authorization_header(&format!(
            "Bearer {token}"
        ))
        .expect("authorization"),
    )
    .expect("wallet session credential");

    let err = verifier
        .verify_wallet_session(
            &router_admission_bindings().jwt,
            &credential,
            digest(0x90),
            1_000,
        )
        .expect_err("missing signing grant must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::MalformedWirePayload);
}

#[test]
fn router_ed25519_jwks_wallet_session_verifier_rejects_missing_normal_signing_claims() {
    let signing_key = SigningKey::from_bytes(&[0x42; 32]);
    let jwks_json = ed25519_jwks_json(&signing_key, "router-key-1");
    let mut verifier = CloudflareRouterEd25519JwksJwtVerifierV1::from_jwks_json(&jwks_json)
        .expect("ed25519 jwks verifier");
    let token = ed25519_jwt(&signing_key, "router-key-1", valid_router_jwt_claims());
    let credential = CloudflareRouterWalletSessionCredentialV1::bearer(
        CloudflareRouterBearerAuthorizationV1::from_authorization_header(&format!(
            "Bearer {token}"
        ))
        .expect("authorization"),
    )
    .expect("wallet session credential");

    let err = verifier
        .verify_wallet_session(
            &router_admission_bindings().jwt,
            &credential,
            digest(0x90),
            1_000,
        )
        .expect_err("missing normal-signing claim must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::MalformedWirePayload);
}

#[test]
fn router_verified_wallet_session_authorizes_normal_signing_v2_prepare_scope() {
    let wallet_session = normal_signing_v2_wallet_session(3_000);
    let request = normal_signing_v2_prepare_request(2_000);

    wallet_session
        .validate_for_normal_signing_prepare_request_v2(&request, 1_000)
        .expect("wallet session authorizes v2 prepare request");
    let admission = wallet_session
        .to_normal_signing_prepare_admission_candidate_v2(&request, 1_000)
        .expect("normal signing v2 admission");
    let expected_material = request.admission_material().expect("admission material");

    assert_eq!(
        admission
            .admission_material()
            .expect("carried admission material"),
        expected_material
    );
    assert_eq!(admission.request_id, request.scope.request_id);
    assert_eq!(admission.signing_worker_id, request.scope.signing_worker_id);
    assert_eq!(
        admission.round1_binding_digest,
        Some(request.round1_binding_digest().expect("round1 binding"))
    );
}

#[test]
fn router_verified_wallet_session_rejects_normal_signing_v2_prepare_beyond_session_expiry() {
    let wallet_session = normal_signing_v2_wallet_session(1_500);
    let request = normal_signing_v2_prepare_request(2_000);

    let err = wallet_session
        .validate_for_normal_signing_prepare_request_v2(&request, 1_000)
        .expect_err("request expiry must be bounded by Wallet Session expiry");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidTimeRange);
}

#[test]
fn router_verified_wallet_session_rejects_normal_signing_v2_prepare_at_exact_expiry() {
    let wallet_session = normal_signing_v2_wallet_session(3_000);
    let request = normal_signing_v2_prepare_request(2_000);

    let err = wallet_session
        .validate_for_normal_signing_prepare_request_v2(&request, 2_000)
        .expect_err("request is expired at expires_at_ms");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::ExpiredLocalRequest);
}

#[test]
fn router_verified_wallet_session_rejects_normal_signing_v2_signing_worker_mismatch() {
    let mut wallet_session = normal_signing_v2_wallet_session(3_000);
    wallet_session.signing_worker_id = "server-b".to_owned();
    let request = normal_signing_v2_prepare_request(2_000);

    let err = wallet_session
        .validate_for_normal_signing_prepare_request_v2(&request, 1_000)
        .expect_err("signing worker mismatch must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidGateDecision);
}

#[test]
fn router_verified_wallet_session_rejects_normal_signing_v2_prepare_account_and_session_mismatch() {
    let request = normal_signing_v2_prepare_request(2_000);

    let mut wrong_account = normal_signing_v2_wallet_session(3_000);
    wrong_account.account_id = "other.near".to_owned();
    let err = wrong_account
        .validate_for_normal_signing_prepare_request_v2(&request, 1_000)
        .expect_err("prepare account mismatch must fail");
    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidGateDecision);

    let mut wrong_session = normal_signing_v2_wallet_session(3_000);
    wrong_session.threshold_session_id = "other-session".to_owned();
    let err = wrong_session
        .validate_for_normal_signing_prepare_request_v2(&request, 1_000)
        .expect_err("prepare session mismatch must fail");
    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidGateDecision);
}

#[test]
fn router_verified_wallet_session_authorizes_normal_signing_v2_finalize_scope() {
    let wallet_session = normal_signing_v2_wallet_session(3_000);
    let request = normal_signing_v2_finalize_request(2_000);

    wallet_session
        .validate_for_normal_signing_finalize_request_v2(&request, 1_000)
        .expect("wallet session authorizes v2 finalize request");
    let admission =
        CloudflareRouterNormalSigningFinalizeAdmissionCandidateV2::from_finalize_request(
            &wallet_session,
            &request,
            1_000,
        )
        .expect("normal signing v2 finalize admission");

    assert_eq!(admission.request_id, request.scope.request_id);
    assert_eq!(admission.signing_worker_id, request.scope.signing_worker_id);
    assert_eq!(admission.intent_digest, request.intent_digest());
    assert_eq!(
        admission.signing_payload_digest,
        request.signing_payload_digest()
    );
    assert_eq!(
        admission.round1_binding_digest,
        request.round1_binding_digest()
    );
}

#[test]
fn router_verified_wallet_session_rejects_normal_signing_v2_finalize_beyond_session_expiry() {
    let wallet_session = normal_signing_v2_wallet_session(1_500);
    let request = normal_signing_v2_finalize_request(2_000);

    let err = wallet_session
        .validate_for_normal_signing_finalize_request_v2(&request, 1_000)
        .expect_err("finalize expiry must be bounded by Wallet Session expiry");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidTimeRange);
}

#[test]
fn router_verified_wallet_session_rejects_normal_signing_v2_finalize_at_exact_expiry() {
    let wallet_session = normal_signing_v2_wallet_session(3_000);
    let request = normal_signing_v2_finalize_request(2_000);

    let err = wallet_session
        .validate_for_normal_signing_finalize_request_v2(&request, 2_000)
        .expect_err("finalize is expired at expires_at_ms");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::ExpiredLocalRequest);
}

#[test]
fn router_verified_wallet_session_rejects_normal_signing_v2_finalize_signing_worker_mismatch() {
    let mut wallet_session = normal_signing_v2_wallet_session(3_000);
    wallet_session.signing_worker_id = "server-b".to_owned();
    let request = normal_signing_v2_finalize_request(2_000);

    let err = wallet_session
        .validate_for_normal_signing_finalize_request_v2(&request, 1_000)
        .expect_err("finalize signing worker mismatch must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidGateDecision);
}

#[test]
fn router_verified_wallet_session_rejects_normal_signing_v2_finalize_account_and_session_mismatch()
{
    let request = normal_signing_v2_finalize_request(2_000);

    let mut wrong_account = normal_signing_v2_wallet_session(3_000);
    wrong_account.account_id = "other.near".to_owned();
    let err = wrong_account
        .validate_for_normal_signing_finalize_request_v2(&request, 1_000)
        .expect_err("finalize account mismatch must fail");
    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidGateDecision);

    let mut wrong_session = normal_signing_v2_wallet_session(3_000);
    wrong_session.threshold_session_id = "other-session".to_owned();
    let err = wrong_session
        .validate_for_normal_signing_finalize_request_v2(&request, 1_000)
        .expect_err("finalize session mismatch must fail");
    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidGateDecision);
}

#[test]
fn router_normal_signing_prepare_admission_v2_rejects_scope_and_digest_drift() {
    let wallet_session = normal_signing_v2_wallet_session(3_000);
    let request = normal_signing_v2_prepare_request(2_000);
    let admission = CloudflareRouterNormalSigningPrepareAdmissionCandidateV2::from_prepare_request(
        &wallet_session,
        &request,
        1_000,
    )
    .expect("normal signing v2 admission");

    let mut wrong_account = admission.clone();
    wrong_account.account_id = "other.near".to_owned();
    let err = wrong_account
        .validate_for_prepare_request(&request)
        .expect_err("prepare admission account drift must fail");
    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidGateDecision);

    let mut wrong_session = admission.clone();
    wrong_session.threshold_session_id = "other-session".to_owned();
    let err = wrong_session
        .validate_for_prepare_request(&request)
        .expect_err("prepare admission session drift must fail");
    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidGateDecision);

    let mut wrong_request_id = admission.clone();
    wrong_request_id.request_id = "other-request".to_owned();
    let err = wrong_request_id
        .validate_for_prepare_request(&request)
        .expect_err("prepare admission request id drift must fail");
    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidGateDecision);

    let mut intent_drift = admission.clone();
    intent_drift.intent_digest = digest(0x54);
    let err = intent_drift
        .validate_for_prepare_request(&request)
        .expect_err("prepare admission intent digest drift must fail");
    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidGateDecision);

    let mut signing_payload_drift = admission.clone();
    signing_payload_drift.signing_payload_digest = digest(0x55);
    let err = signing_payload_drift
        .validate_for_prepare_request(&request)
        .expect_err("prepare admission signing payload digest drift must fail");
    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidGateDecision);

    let mut admitted_signing_drift = admission.clone();
    admitted_signing_drift.admitted_signing_digest = digest(0x58);
    let err = admitted_signing_drift
        .validate_for_prepare_request(&request)
        .expect_err("prepare admission admitted signing digest drift must fail");
    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidGateDecision);
}

#[test]
fn router_normal_signing_finalize_admission_v2_rejects_scope_and_digest_drift() {
    let wallet_session = normal_signing_v2_wallet_session(3_000);
    let request = normal_signing_v2_finalize_request(2_000);
    let admission =
        CloudflareRouterNormalSigningFinalizeAdmissionCandidateV2::from_finalize_request(
            &wallet_session,
            &request,
            1_000,
        )
        .expect("normal signing v2 finalize admission");

    let mut wrong_account = admission.clone();
    wrong_account.account_id = "other.near".to_owned();
    let err = wrong_account
        .validate_for_finalize_request(&request)
        .expect_err("finalize admission account drift must fail");
    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidGateDecision);

    let mut wrong_session = admission.clone();
    wrong_session.threshold_session_id = "other-session".to_owned();
    let err = wrong_session
        .validate_for_finalize_request(&request)
        .expect_err("finalize admission session drift must fail");
    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidGateDecision);

    let mut wrong_request_id = admission.clone();
    wrong_request_id.request_id = "other-request".to_owned();
    let err = wrong_request_id
        .validate_for_finalize_request(&request)
        .expect_err("finalize admission request id drift must fail");
    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidGateDecision);

    let mut intent_drift = admission.clone();
    intent_drift.intent_digest = digest(0x54);
    let err = intent_drift
        .validate_for_finalize_request(&request)
        .expect_err("finalize admission intent digest drift must fail");
    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidGateDecision);

    let mut signing_payload_drift = admission.clone();
    signing_payload_drift.signing_payload_digest = digest(0x55);
    let err = signing_payload_drift
        .validate_for_finalize_request(&request)
        .expect_err("finalize admission signing payload digest drift must fail");
    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidGateDecision);
}

#[test]
fn durable_object_handler_rejects_normal_signing_v2_replayed_request_id() {
    let runtime = router_runtime();
    let request = normal_signing_v2_prepare_request(2_000);
    let call = runtime
        .normal_signing_v2_prepare_replay_reserve_call(&request)
        .expect("normal signing v2 replay call");
    let mut storage = CloudflareDurableObjectMemoryStorageV1::new();

    let first = handle_cloudflare_durable_object_call_v1(&call, &mut storage)
        .expect("first normal-signing v2 replay reservation");
    assert_eq!(
        first,
        CloudflareDurableObjectResponseV1::router_replay_reserve(
            CloudflareReplayReserveResponseV1::new(request.scope.request_id.clone(), true)
                .expect("first normal-signing v2 replay response")
        )
        .expect("first normal-signing v2 replay response")
    );

    let second = handle_cloudflare_durable_object_call_v1(&call, &mut storage)
        .expect("second normal-signing v2 replay reservation");
    assert_eq!(
        second,
        CloudflareDurableObjectResponseV1::router_replay_reserve(
            CloudflareReplayReserveResponseV1::new(request.scope.request_id.clone(), false)
                .expect("second normal-signing v2 replay response")
        )
        .expect("second normal-signing v2 replay response")
    );

    let mut conflicting_request = normal_signing_v2_prepare_request_for_id(
        request.scope.request_id.as_str(),
        request.expires_at_ms,
    );
    conflicting_request.scope.signing_worker_id = "server-b".to_owned();
    let conflicting_call = runtime
        .normal_signing_v2_prepare_replay_reserve_call(&conflicting_request)
        .expect("conflicting normal signing v2 replay call");
    let err = handle_cloudflare_durable_object_call_v1(&conflicting_call, &mut storage)
        .expect_err("same request id with different replay material must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::ReplayedLocalRequest);
}

#[test]
fn router_normal_signing_admission_v2_rejects_signing_payload_digest_drift() {
    let wallet_session = normal_signing_v2_wallet_session(3_000);
    let request = normal_signing_v2_prepare_request(2_000);
    let mut admission =
        CloudflareRouterNormalSigningPrepareAdmissionCandidateV2::from_prepare_request(
            &wallet_session,
            &request,
            1_000,
        )
        .expect("normal signing v2 admission");
    admission.signing_payload_digest = digest(0x55);

    let err = admission
        .validate_for_prepare_request(&request)
        .expect_err("signing payload digest drift must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidGateDecision);
}

#[test]
fn router_normal_signing_admission_v2_converts_to_v1_store_metadata() {
    let wallet_session = normal_signing_v2_wallet_session(3_000);
    let request = normal_signing_v2_prepare_request(2_000);
    let admission = CloudflareRouterNormalSigningPrepareAdmissionCandidateV2::from_prepare_request(
        &wallet_session,
        &request,
        1_000,
    )
    .expect("normal signing v2 admission");

    let metadata = admission
        .to_v1_trusted_metadata()
        .expect("v1 trusted metadata");

    assert_eq!(metadata.org_id, admission.org_id);
    assert_eq!(metadata.project_id, admission.project_id);
    assert_eq!(metadata.environment, admission.environment);
    assert_eq!(metadata.account_id, admission.account_id);
    assert_eq!(
        metadata.trusted_source_digest,
        admission.trusted_source_digest
    );
    assert_eq!(metadata.intent_digest, admission.intent_digest);
    assert_eq!(
        metadata.auth,
        CloudflareRouterAuthContextV1::authenticated_session("user-1", "session-1")
            .expect("authenticated session")
    );
}

#[test]
fn router_normal_signing_finalize_admission_v2_converts_to_v1_store_metadata() {
    let wallet_session = normal_signing_v2_wallet_session(3_000);
    let request = normal_signing_v2_finalize_request(2_000);
    let admission =
        CloudflareRouterNormalSigningFinalizeAdmissionCandidateV2::from_finalize_request(
            &wallet_session,
            &request,
            1_000,
        )
        .expect("normal signing v2 finalize admission");

    let metadata = admission
        .to_v1_trusted_metadata()
        .expect("v1 trusted metadata");

    assert_eq!(metadata.org_id, admission.org_id);
    assert_eq!(metadata.project_id, admission.project_id);
    assert_eq!(metadata.environment, admission.environment);
    assert_eq!(metadata.account_id, admission.account_id);
    assert_eq!(
        metadata.trusted_source_digest,
        admission.trusted_source_digest
    );
    assert_eq!(metadata.intent_digest, admission.intent_digest);
    assert_eq!(
        metadata.auth,
        CloudflareRouterAuthContextV1::authenticated_session("user-1", "session-1")
            .expect("authenticated session")
    );
}

#[test]
fn router_normal_signing_finalize_admission_v2_rejects_round1_binding_drift() {
    let wallet_session = normal_signing_v2_wallet_session(3_000);
    let request = normal_signing_v2_finalize_request(2_000);
    let mut admission =
        CloudflareRouterNormalSigningFinalizeAdmissionCandidateV2::from_finalize_request(
            &wallet_session,
            &request,
            1_000,
        )
        .expect("normal signing v2 finalize admission");
    admission.round1_binding_digest = digest(0x57);

    let err = admission
        .validate_for_finalize_request(&request)
        .expect_err("round1 binding drift must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidGateDecision);
}

#[test]
fn router_jwt_session_provider_feeds_composite_admission() {
    let request = ecdsa_threshold_prf_request(2_000);
    let admission_bindings = parse_cloudflare_router_admission_bindings_v1(&router_admission_env())
        .expect("admission bindings");
    let jwt_session = CloudflareRouterJwtSessionProviderV1::new(
        admission_bindings.jwt,
        CloudflareRouterBearerAuthorizationV1::from_authorization_header(
            "Bearer header.payload.sig",
        )
        .expect("authorization"),
        1_000,
        digest(0x90),
        StaticJwtVerifier::new(verified_jwt_claims("session-1", "account.near")),
    )
    .expect("jwt session provider");
    let mut provider = CloudflareRouterCompositeAdmissionProviderV1::new(
        jwt_session,
        CloudflareRouterAllowedWorkKindsProjectPolicyProviderV1::new(
            vec![ExpensiveWorkKindV1::RegistrationPrepare],
            1_000,
        )
        .expect("project policy provider"),
        CloudflareRouterConfiguredAbuseProviderV1::new(CloudflareRouterAbuseCheckV1::Allowed)
            .expect("abuse provider"),
        CloudflareRouterConfiguredQuotaProviderV1::new(CloudflareRouterQuotaCheckV1::Accepted {
            request_id: "gate-request-1".to_owned(),
        })
        .expect("quota provider"),
    );

    let admission =
        derive_cloudflare_router_trusted_admission_from_provider_v1(&request, &mut provider)
            .expect("trusted admission");

    assert_eq!(admission.context.org_id, "org-1");
    assert_eq!(admission.context.project_id, "project-1");
    assert!(matches!(
        admission.decision,
        ExpensiveWorkGateDecisionV1::Accepted { .. }
    ));
}

#[test]
fn router_stored_admission_providers_feed_composite_chain() {
    let request = ecdsa_threshold_prf_request(2_000);
    let admission_bindings = parse_cloudflare_router_admission_bindings_v1(&router_admission_env())
        .expect("admission bindings");
    let session = CloudflareRouterVerifiedSessionProviderV1::new(
        CloudflareRouterVerifiedSessionV1::jwt(verified_jwt_claims("session-1", "account.near"))
            .expect("verified session"),
    )
    .expect("verified session provider");
    let project_policy = CloudflareRouterStoredProjectPolicyProviderV1::new(
        admission_bindings.stores.project_policy,
        StaticProjectPolicyStore::new(CloudflareRouterProjectPolicyV1::Allowed),
    )
    .expect("stored project policy provider");
    let abuse = CloudflareRouterStoredAbuseProviderV1::new(
        admission_bindings.stores.abuse,
        StaticAbuseStore::new(CloudflareRouterAbuseCheckV1::Allowed),
    )
    .expect("stored abuse provider");
    let quota = CloudflareRouterStoredQuotaProviderV1::new(
        admission_bindings.stores.quota,
        StaticQuotaStore::new(CloudflareRouterQuotaCheckV1::Accepted {
            request_id: "gate-request-1".to_owned(),
        }),
    )
    .expect("stored quota provider");
    let mut provider =
        CloudflareRouterCompositeAdmissionProviderV1::new(session, project_policy, abuse, quota);

    let admission =
        derive_cloudflare_router_trusted_admission_from_provider_v1(&request, &mut provider)
            .expect("trusted admission");

    assert!(matches!(
        admission.decision,
        ExpensiveWorkGateDecisionV1::Accepted { .. }
    ));
}

#[test]
fn router_admission_store_bindings_build_scoped_durable_object_calls() {
    let admission_bindings = parse_cloudflare_router_admission_bindings_v1(&router_admission_env())
        .expect("admission bindings");
    let request = admission_store_request(1_000);

    let policy_call = admission_bindings
        .stores
        .project_policy_evaluate_call(request.clone())
        .expect("project policy call");
    let quota_call = admission_bindings
        .stores
        .quota_evaluate_call(request.clone())
        .expect("quota call");
    let abuse_call = admission_bindings
        .stores
        .abuse_evaluate_call(request)
        .expect("abuse call");

    assert_eq!(
        policy_call.operation_kind(),
        CloudflareDurableObjectOperationKindV1::RouterProjectPolicyEvaluate
    );
    assert_eq!(
        policy_call.storage_key(),
        "router-project-policy:project-policy/org-1/project-1/dev"
    );
    assert_eq!(
        quota_call.operation_kind(),
        CloudflareDurableObjectOperationKindV1::RouterQuotaEvaluate
    );
    assert_eq!(
        quota_call.storage_key(),
        "router-quota:quota/org-1/project-1/dev/account.near/registration_prepare"
    );
    assert_eq!(
        abuse_call.operation_kind(),
        CloudflareDurableObjectOperationKindV1::RouterAbuseEvaluate
    );
    assert_eq!(
        abuse_call.storage_key(),
        "router-abuse:abuse/9090909090909090909090909090909090909090909090909090909090909090/account.near"
    );
}

#[test]
fn router_runtime_builds_admission_store_calls_from_trusted_metadata() {
    let runtime = router_runtime();
    let request = ecdsa_threshold_prf_request(2_000);

    let calls = runtime
        .admission_store_calls_at(1_000, &request, trusted_metadata())
        .expect("admission store calls");

    calls.validate().expect("calls validate");
    assert_eq!(
        calls.project_policy.worker_role,
        CloudflareWorkerRoleV1::Router
    );
    assert_eq!(
        calls.project_policy.binding.scope,
        CloudflareDurableObjectScopeV1::RouterProjectPolicy
    );
    assert_eq!(
        calls.quota.binding.scope,
        CloudflareDurableObjectScopeV1::RouterQuota
    );
    assert_eq!(
        calls.abuse.binding.scope,
        CloudflareDurableObjectScopeV1::RouterAbuse
    );
    let CloudflareDurableObjectRequestV1::RouterProjectPolicyEvaluate {
        request: policy_request,
    } = &calls.project_policy.request
    else {
        panic!("expected project policy request");
    };
    assert_eq!(policy_request.lifecycle_id, request.lifecycle.lifecycle_id);
    assert_eq!(policy_request.request_nonce, request.request_nonce);
    assert_eq!(policy_request.metadata.account_id, "account.near");
}

#[test]
fn router_runtime_builds_normal_signing_v2_prepare_replay_reservation() {
    let runtime = router_runtime();
    let request = normal_signing_v2_prepare_request(2_000);

    let call = runtime
        .normal_signing_v2_prepare_replay_reserve_call(&request)
        .expect("normal signing v2 prepare replay call");

    assert_eq!(call.worker_role, CloudflareWorkerRoleV1::Router);
    assert_eq!(
        call.binding.scope,
        CloudflareDurableObjectScopeV1::RouterReplay
    );
    let CloudflareDurableObjectRequestV1::RouterReplayReserve {
        request: replay_request,
    } = &call.request
    else {
        panic!("expected replay reservation request");
    };
    assert_eq!(replay_request.request_id, request.scope.request_id);
    assert_eq!(
        replay_request.replay_material_digest,
        request.round1_binding_digest().expect("round1 binding")
    );
    assert_eq!(replay_request.expires_at_ms, request.expires_at_ms);
}

#[test]
fn router_runtime_builds_normal_signing_v2_prepare_admission_store_calls() {
    let runtime = router_runtime();
    let request = normal_signing_v2_prepare_request(2_000);
    let wallet_session = normal_signing_v2_wallet_session(3_000);
    let admission = CloudflareRouterNormalSigningPrepareAdmissionCandidateV2::from_prepare_request(
        &wallet_session,
        &request,
        1_000,
    )
    .expect("normal signing v2 admission");

    let calls = runtime
        .normal_signing_v2_prepare_admission_store_calls_at(1_000, &request, &admission)
        .expect("normal signing v2 admission store calls");

    calls.validate().expect("normal signing v2 calls validate");
    assert_eq!(
        calls.project_policy.operation_kind(),
        CloudflareDurableObjectOperationKindV1::RouterNormalSigningProjectPolicyEvaluate
    );
    assert_eq!(
        calls.quota.operation_kind(),
        CloudflareDurableObjectOperationKindV1::RouterNormalSigningQuotaEvaluate
    );
    assert_eq!(
        calls.abuse.operation_kind(),
        CloudflareDurableObjectOperationKindV1::RouterNormalSigningAbuseEvaluate
    );
    let CloudflareDurableObjectRequestV1::RouterNormalSigningProjectPolicyEvaluate {
        request: policy_request,
    } = &calls.project_policy.request
    else {
        panic!("expected normal signing project policy request");
    };
    assert_eq!(policy_request.request_id, request.scope.request_id);
    assert_eq!(policy_request.expires_at_ms, request.expires_at_ms);
    assert_eq!(
        policy_request.intent_digest,
        request
            .admission_material()
            .expect("admission material")
            .intent_digest
    );
    assert_eq!(
        policy_request.request_digest,
        request.round1_binding_digest().expect("round1 binding")
    );
    assert_eq!(policy_request.metadata.account_id, "account.near");
    assert_eq!(
        policy_request.metadata.auth,
        CloudflareRouterAuthContextV1::authenticated_session("user-1", "session-1")
            .expect("authenticated session")
    );
}

#[test]
fn router_runtime_builds_normal_signing_v2_finalize_admission_store_calls() {
    let runtime = router_runtime();
    let request = normal_signing_v2_finalize_request(2_000);
    let wallet_session = normal_signing_v2_wallet_session(3_000);
    let admission =
        CloudflareRouterNormalSigningFinalizeAdmissionCandidateV2::from_finalize_request(
            &wallet_session,
            &request,
            1_000,
        )
        .expect("normal signing v2 finalize admission");

    let calls = runtime
        .normal_signing_v2_finalize_admission_store_calls_at(1_000, &request, &admission)
        .expect("normal signing v2 finalize admission store calls");

    calls
        .validate()
        .expect("normal signing v2 finalize calls validate");
    assert_eq!(
        calls.project_policy.operation_kind(),
        CloudflareDurableObjectOperationKindV1::RouterNormalSigningProjectPolicyEvaluate
    );
    assert_eq!(
        calls.quota.operation_kind(),
        CloudflareDurableObjectOperationKindV1::RouterNormalSigningQuotaEvaluate
    );
    assert_eq!(
        calls.abuse.operation_kind(),
        CloudflareDurableObjectOperationKindV1::RouterNormalSigningAbuseEvaluate
    );
    let CloudflareDurableObjectRequestV1::RouterNormalSigningProjectPolicyEvaluate {
        request: policy_request,
    } = &calls.project_policy.request
    else {
        panic!("expected normal signing project policy request");
    };
    assert_eq!(policy_request.request_id, request.scope.request_id);
    assert_eq!(policy_request.expires_at_ms, request.expires_at_ms);
    assert_eq!(policy_request.intent_digest, request.intent_digest());
    assert_eq!(
        policy_request.request_digest,
        request.round1_binding_digest()
    );
    assert_eq!(policy_request.metadata.account_id, "account.near");
    assert_eq!(
        policy_request.metadata.auth,
        CloudflareRouterAuthContextV1::authenticated_session("user-1", "session-1")
            .expect("authenticated session")
    );
}

#[test]
fn router_runtime_builds_router_ab_ecdsa_derivation_finalize_admission_store_calls() {
    let runtime = router_runtime();
    let request = router_ab_ecdsa_derivation_digest_signing_finalize_request();
    let prepare_request = request.prepare_request().expect("prepare request");
    let wallet_session = router_ab_ecdsa_derivation_wallet_session(&prepare_request);
    let admission =
        CloudflareRouterAbEcdsaDerivationEvmDigestFinalizeAdmissionCandidateV1::from_finalize_request(
            &wallet_session,
            &request,
            TEST_ACTIVATED_AT_MS + 1,
        )
        .expect("Router A/B ECDSA derivation finalize admission");

    let calls = runtime
        .router_ab_ecdsa_derivation_evm_digest_finalize_admission_store_calls_at(
            TEST_ACTIVATED_AT_MS + 1,
            &request,
            &admission,
        )
        .expect("Router A/B ECDSA derivation finalize admission store calls");

    calls
        .validate()
        .expect("Router A/B ECDSA derivation finalize calls validate");
    assert_eq!(
        calls.project_policy.operation_kind(),
        CloudflareDurableObjectOperationKindV1::RouterNormalSigningProjectPolicyEvaluate
    );
    let CloudflareDurableObjectRequestV1::RouterNormalSigningProjectPolicyEvaluate {
        request: policy_request,
    } = &calls.project_policy.request
    else {
        panic!("expected Router A/B ECDSA derivation finalize project policy request");
    };
    assert_eq!(policy_request.request_id, request.request_id);
    assert_eq!(policy_request.expires_at_ms, request.expires_at_ms);
    assert_eq!(
        policy_request.intent_digest,
        request
            .prepare_request_digest()
            .expect("prepare request digest")
    );
    assert_eq!(
        policy_request.request_digest,
        request.request_digest().expect("finalize request digest")
    );
    assert_eq!(
        policy_request.metadata.intent_digest,
        request.request_digest().expect("finalize request digest")
    );
}

#[test]
fn router_runtime_rejects_normal_signing_v2_prepare_admission_store_round1_drift() {
    let runtime = router_runtime();
    let request = normal_signing_v2_prepare_request(2_000);
    let wallet_session = normal_signing_v2_wallet_session(3_000);
    let mut admission =
        CloudflareRouterNormalSigningPrepareAdmissionCandidateV2::from_prepare_request(
            &wallet_session,
            &request,
            1_000,
        )
        .expect("normal signing v2 admission");
    admission.round1_binding_digest = Some(digest(0x56));

    let err = runtime
        .normal_signing_v2_prepare_admission_store_calls_at(1_000, &request, &admission)
        .expect_err("round1 drift must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidGateDecision);
}

#[test]
fn router_runtime_admission_store_calls_reject_metadata_mismatch() {
    let runtime = router_runtime();
    let request = ecdsa_threshold_prf_request(2_000);
    let mismatched = CloudflareRouterTrustedRequestMetadataV1::new(
        ExpensiveWorkKindV1::RegistrationPrepare,
        "org-1",
        "project-1",
        "dev",
        "different.near",
        CloudflareRouterAuthContextV1::authenticated_session("user-1", "session-1")
            .expect("auth context"),
        digest(0x90),
    )
    .expect("metadata");

    let err = runtime
        .admission_store_calls_at(1_000, &request, mismatched)
        .expect_err("mismatched metadata must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidGateDecision);
}

#[test]
fn router_stored_project_policy_provider_rejects_wrong_scope() {
    let err = CloudflareRouterStoredProjectPolicyProviderV1::new(
        do_binding(
            CloudflareDurableObjectScopeV1::RouterQuota,
            "ROUTER_QUOTA_DO",
        ),
        StaticProjectPolicyStore::new(CloudflareRouterProjectPolicyV1::Allowed),
    )
    .expect_err("wrong store scope must fail");

    assert_eq!(
        err.code(),
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig
    );
}

#[test]
fn router_runtime_builds_admission_plan_from_composite_provider() {
    let request = ecdsa_threshold_prf_request(2_000);
    let runtime = router_runtime();
    let mut provider = composite_admission_provider(
        verified_jwt_claims("session-1", "account.near"),
        vec![ExpensiveWorkKindV1::RegistrationPrepare],
        CloudflareRouterAbuseCheckV1::Allowed,
        CloudflareRouterQuotaCheckV1::SignerQueueSaturated,
    );

    let plan = runtime
        .public_request_admission_plan_from_provider_at(1_000, request, &mut provider)
        .expect("admission plan");

    assert!(matches!(
        plan,
        CloudflareRouterPublicAdmissionPlanV1::Stop { .. }
    ));
    assert!(matches!(
        plan.trusted_admission().decision,
        ExpensiveWorkGateDecisionV1::Defer {
            reason: GateDeferReasonV1::SignerQueueSaturated
        }
    ));
}

#[test]
fn router_derives_stop_decision_from_project_policy_rejection() {
    let request = ecdsa_threshold_prf_request(2_000);
    let checks = CloudflareRouterAdmissionChecksV1::new(
        CloudflareRouterProjectPolicyV1::Rejected {
            retry_after_ms: 1_000,
        },
        CloudflareRouterAbuseCheckV1::Allowed,
        CloudflareRouterQuotaCheckV1::Accepted {
            request_id: "gate-request-1".to_owned(),
        },
    )
    .expect("checks");
    let admission =
        derive_cloudflare_router_trusted_admission_v1(&request, trusted_metadata(), checks)
            .expect("trusted admission");

    assert!(matches!(
        admission.decision,
        ExpensiveWorkGateDecisionV1::Rejected {
            reason: GateRejectReasonV1::AbusePolicy,
            retry_after_ms: 1_000
        }
    ));
    assert!(!admission
        .allows_signer_forwarding()
        .expect("forwarding check"));
}

#[test]
fn router_derives_rate_limited_admission_before_quota_acceptance() {
    let request = ecdsa_threshold_prf_request(2_000);
    let checks = CloudflareRouterAdmissionChecksV1::new(
        CloudflareRouterProjectPolicyV1::Allowed,
        CloudflareRouterAbuseCheckV1::RateLimited {
            retry_after_ms: 2_000,
        },
        CloudflareRouterQuotaCheckV1::Accepted {
            request_id: "gate-request-1".to_owned(),
        },
    )
    .expect("checks");
    let admission =
        derive_cloudflare_router_trusted_admission_v1(&request, trusted_metadata(), checks)
            .expect("trusted admission");

    assert!(matches!(
        admission.decision,
        ExpensiveWorkGateDecisionV1::Rejected {
            reason: GateRejectReasonV1::RateLimited,
            retry_after_ms: 2_000
        }
    ));
}

#[test]
fn router_derives_quota_defer_admission() {
    let request = ecdsa_threshold_prf_request(2_000);
    let checks = CloudflareRouterAdmissionChecksV1::new(
        CloudflareRouterProjectPolicyV1::Allowed,
        CloudflareRouterAbuseCheckV1::Allowed,
        CloudflareRouterQuotaCheckV1::SignerQueueSaturated,
    )
    .expect("checks");
    let admission =
        derive_cloudflare_router_trusted_admission_v1(&request, trusted_metadata(), checks)
            .expect("trusted admission");

    assert!(matches!(
        admission.decision,
        ExpensiveWorkGateDecisionV1::Defer {
            reason: GateDeferReasonV1::SignerQueueSaturated
        }
    ));
}

#[test]
fn router_trusted_metadata_must_match_public_request_lifecycle() {
    let request = ecdsa_threshold_prf_request(2_000);
    let metadata = CloudflareRouterTrustedRequestMetadataV1::new(
        ExpensiveWorkKindV1::RegistrationPrepare,
        "org-1",
        "project-1",
        "dev",
        "different.near",
        CloudflareRouterAuthContextV1::authenticated_session("user-1", "session-1")
            .expect("auth context"),
        digest(0x90),
    )
    .expect("metadata");
    let err = derive_cloudflare_router_trusted_admission_v1(
        &request,
        metadata,
        allow_checks("gate-request-1"),
    )
    .expect_err("metadata mismatch must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidGateDecision);
}

#[test]
fn router_trusted_metadata_rejects_preauth_session_mismatch() {
    let request = ecdsa_threshold_prf_request(2_000);
    let metadata = CloudflareRouterTrustedRequestMetadataV1::new(
        ExpensiveWorkKindV1::RegistrationPrepare,
        "org-1",
        "project-1",
        "dev",
        "account.near",
        CloudflareRouterAuthContextV1::pre_auth_session("different-session").expect("auth context"),
        digest(0x90),
    )
    .expect("metadata");
    let err = derive_cloudflare_router_trusted_admission_v1(
        &request,
        metadata,
        allow_checks("gate-request-1"),
    )
    .expect_err("pre-auth session mismatch must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidGateDecision);
}

#[test]
fn signer_private_request_accepts_role_specific_router_message() {
    let message = signer_private_request(WireMessageKindV1::RouterToSignerA);

    validate_cloudflare_signer_private_request_v1(CloudflareWorkerRoleV1::DeriverA, &message)
        .expect("signer a request should validate");
}

#[test]
fn signer_private_request_rejects_wrong_role_message() {
    let message = signer_private_request(WireMessageKindV1::RouterToSignerB);
    let err =
        validate_cloudflare_signer_private_request_v1(CloudflareWorkerRoleV1::DeriverA, &message)
            .expect_err("signer a must reject signer b request branch");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidLocalRoute);
}

#[test]
fn signer_private_request_rejects_malformed_router_payload() {
    let message = WireMessageV1::new(
        WireMessageKindV1::RouterToSignerA,
        digest(0x33),
        CanonicalWireBytesV1::new(vec![0x31, 0x32]).expect("malformed payload bytes"),
    )
    .expect("malformed private request");
    let err =
        validate_cloudflare_signer_private_request_v1(CloudflareWorkerRoleV1::DeriverA, &message)
            .expect_err("malformed Router-to-signer payload must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::MalformedWirePayload);
}

#[test]
fn signer_private_request_rejects_payload_transcript_mismatch() {
    let mut message = signer_private_request(WireMessageKindV1::RouterToSignerA);
    message.transcript_digest = digest(0x77);
    let err =
        validate_cloudflare_signer_private_request_v1(CloudflareWorkerRoleV1::DeriverA, &message)
            .expect_err("wire transcript must match decoded payload transcript");

    assert_eq!(
        err.code(),
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig
    );
}

#[test]
fn signer_private_bootstrap_accepts_typed_role_envelope_aad() {
    let request = ecdsa_threshold_prf_request_with_aad_bound_envelopes(2_000);
    let message =
        signer_private_request_with_aad_bound_envelope(WireMessageKindV1::RouterToSignerA);
    let aad = role_envelope_aad_for_request(Role::SignerA, &request);
    let bootstrap = CloudflareSignerPrivateBootstrapRequestV1::new(
        CloudflareWorkerRoleV1::DeriverA,
        message.clone(),
        aad.clone(),
        request_context_digest(&request),
    )
    .expect("strict signer bootstrap");

    assert_eq!(bootstrap.message, message);
    assert_eq!(bootstrap.aad, aad);
}

#[test]
fn signer_private_bootstrap_reconstructs_from_public_request() {
    let request = ecdsa_threshold_prf_request_with_aad_bound_envelopes(2_000);
    let message = request
        .to_signer_wire_messages()
        .expect("signer wire messages")
        .0;
    let bootstrap = cloudflare_signer_private_bootstrap_from_public_request_v1(
        CloudflareWorkerRoleV1::DeriverA,
        &request,
        message.clone(),
    )
    .expect("strict signer bootstrap from public request");

    assert_eq!(bootstrap.message, message);
    assert_eq!(
        bootstrap.router_request_digest,
        request_context_digest(&request)
    );
    assert_eq!(
        bootstrap.aad,
        role_envelope_aad_for_request(Role::SignerA, &request)
    );
}

#[test]
fn router_ab_ecdsa_derivation_deriver_registration_private_request_accepts_matching_payload() {
    let registration_request =
        router_ab_ecdsa_derivation_registration_request_with_aad_bound_envelopes();
    let public_request = registration_request
        .to_threshold_prf_request()
        .expect("Router A/B ECDSA derivation registration public request");
    let (deriver_a_message, _) = public_request
        .to_signer_wire_messages()
        .expect("Router A/B ECDSA derivation registration signer messages");
    let bootstrap = cloudflare_signer_private_bootstrap_from_ecdsa_derivation_registration_v1(
        CloudflareWorkerRoleV1::DeriverA,
        &registration_request,
        deriver_a_message.clone(),
    )
    .expect("Router A/B ECDSA derivation registration bootstrap");
    let router_payload = decode_router_to_signer_payload_v1(deriver_a_message.payload.as_bytes())
        .expect("Router A/B ECDSA derivation registration Router payload");

    validate_cloudflare_router_ab_ecdsa_derivation_registration_request_for_router_payload_v1(
        &registration_request,
        &router_payload,
    )
    .expect("Router A/B ECDSA derivation registration payload binding");
    let private_request =
        CloudflareRouterAbEcdsaDerivationDeriverRegistrationPrivateRequestV1::new(
            CloudflareWorkerRoleV1::DeriverA,
            registration_request,
            bootstrap,
        )
        .expect("Router A/B ECDSA derivation registration private request");

    private_request
        .validate_for_worker_role(CloudflareWorkerRoleV1::DeriverA)
        .expect("Router A/B ECDSA derivation registration private request validates");
}

#[test]
fn router_ab_ecdsa_derivation_deriver_registration_private_request_rejects_payload_drift() {
    let mut registration_request =
        router_ab_ecdsa_derivation_registration_request_with_aad_bound_envelopes();
    let public_request = registration_request
        .to_threshold_prf_request()
        .expect("Router A/B ECDSA derivation registration public request");
    let (deriver_a_message, _) = public_request
        .to_signer_wire_messages()
        .expect("Router A/B ECDSA derivation registration signer messages");
    let bootstrap = cloudflare_signer_private_bootstrap_from_ecdsa_derivation_registration_v1(
        CloudflareWorkerRoleV1::DeriverA,
        &registration_request,
        deriver_a_message,
    )
    .expect("Router A/B ECDSA derivation registration bootstrap");
    registration_request.replay_nonce = "ecdsa-registration-replay-drift".to_owned();

    let err = CloudflareRouterAbEcdsaDerivationDeriverRegistrationPrivateRequestV1::new(
        CloudflareWorkerRoleV1::DeriverA,
        registration_request,
        bootstrap,
    )
    .expect_err("payload drift must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::MalformedWirePayload);
}

#[test]
fn router_ab_ecdsa_derivation_deriver_export_private_request_accepts_matching_payload() {
    let export_request = router_ab_ecdsa_derivation_export_request_with_aad_bound_envelopes();
    let public_request = export_request
        .to_threshold_prf_request()
        .expect("Router A/B ECDSA derivation export public request");
    let (deriver_a_message, _) = public_request
        .to_signer_wire_messages()
        .expect("Router A/B ECDSA derivation export signer messages");
    let bootstrap = cloudflare_signer_private_bootstrap_from_public_request_v1(
        CloudflareWorkerRoleV1::DeriverA,
        &public_request,
        deriver_a_message.clone(),
    )
    .expect("Router A/B ECDSA derivation export bootstrap");
    let router_payload = decode_router_to_signer_payload_v1(deriver_a_message.payload.as_bytes())
        .expect("Router A/B ECDSA derivation export Router payload");

    validate_cloudflare_router_ab_ecdsa_derivation_export_request_for_router_payload_v1(
        &export_request,
        &router_payload,
    )
    .expect("Router A/B ECDSA derivation export payload binding");
    let private_request = CloudflareRouterAbEcdsaDerivationDeriverExportPrivateRequestV1::new(
        CloudflareWorkerRoleV1::DeriverA,
        export_request,
        bootstrap,
    )
    .expect("Router A/B ECDSA derivation export private request");

    private_request
        .validate_for_worker_role(CloudflareWorkerRoleV1::DeriverA)
        .expect("Router A/B ECDSA derivation export private request validates");
}

#[test]
fn router_ab_ecdsa_derivation_deriver_export_private_request_rejects_payload_drift() {
    let mut export_request = router_ab_ecdsa_derivation_export_request_with_aad_bound_envelopes();
    let public_request = export_request
        .to_threshold_prf_request()
        .expect("Router A/B ECDSA derivation export public request");
    let (deriver_a_message, _) = public_request
        .to_signer_wire_messages()
        .expect("Router A/B ECDSA derivation export signer messages");
    let bootstrap = cloudflare_signer_private_bootstrap_from_public_request_v1(
        CloudflareWorkerRoleV1::DeriverA,
        &public_request,
        deriver_a_message,
    )
    .expect("Router A/B ECDSA derivation export bootstrap");
    export_request.export_nonce = "ecdsa-export-nonce-drift".to_owned();

    let err = CloudflareRouterAbEcdsaDerivationDeriverExportPrivateRequestV1::new(
        CloudflareWorkerRoleV1::DeriverA,
        export_request,
        bootstrap,
    )
    .expect_err("payload drift must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::MalformedWirePayload);
}

#[test]
fn router_ab_ecdsa_derivation_deriver_recovery_private_request_accepts_matching_payload() {
    let recovery_request = router_ab_ecdsa_derivation_recovery_request_with_aad_bound_envelopes();
    let public_request = recovery_request
        .to_threshold_prf_request()
        .expect("Router A/B ECDSA derivation recovery public request");
    let (deriver_a_message, _) = public_request
        .to_signer_wire_messages()
        .expect("Router A/B ECDSA derivation recovery signer messages");
    let bootstrap = cloudflare_signer_private_bootstrap_from_public_request_v1(
        CloudflareWorkerRoleV1::DeriverA,
        &public_request,
        deriver_a_message.clone(),
    )
    .expect("Router A/B ECDSA derivation recovery bootstrap");
    let router_payload = decode_router_to_signer_payload_v1(deriver_a_message.payload.as_bytes())
        .expect("Router A/B ECDSA derivation recovery Router payload");

    validate_cloudflare_router_ab_ecdsa_derivation_recovery_request_for_router_payload_v1(
        &recovery_request,
        &router_payload,
    )
    .expect("Router A/B ECDSA derivation recovery payload binding");
    let private_request = CloudflareRouterAbEcdsaDerivationDeriverRecoveryPrivateRequestV1::new(
        CloudflareWorkerRoleV1::DeriverA,
        recovery_request,
        bootstrap,
    )
    .expect("Router A/B ECDSA derivation recovery private request");

    private_request
        .validate_for_worker_role(CloudflareWorkerRoleV1::DeriverA)
        .expect("Router A/B ECDSA derivation recovery private request validates");
}

#[test]
fn router_ab_ecdsa_derivation_recovery_public_admission_response_validates_client_bundles() {
    let recovery_request = router_ab_ecdsa_derivation_recovery_request_with_aad_bound_envelopes();
    let public_request = recovery_request
        .to_threshold_prf_request()
        .expect("Router A/B ECDSA derivation recovery public request");
    let (deriver_a_message, _) = public_request
        .to_signer_wire_messages()
        .expect("Router A/B ECDSA derivation recovery signer messages");
    let router_payload = decode_router_to_signer_payload_v1(deriver_a_message.payload.as_bytes())
        .expect("Router A/B ECDSA derivation recovery Router payload");
    let signer_a_response = CloudflareSignerClientRecipientProofBundleResponseV1::new(
        Role::SignerA,
        client_proof_bundle_wire(&router_payload, Role::SignerA, 0x51),
    )
    .expect("Deriver A recovery client bundle");
    let signer_b_response = CloudflareSignerClientRecipientProofBundleResponseV1::new(
        Role::SignerB,
        client_proof_bundle_wire(&router_payload, Role::SignerB, 0x52),
    )
    .expect("Deriver B recovery client bundle");
    let router_response = CloudflareRouterRecipientProofBundleResponseV1::new(
        CloudflareReplayReserveResponseV1::new(&recovery_request.recovery_nonce, true)
            .expect("recovery replay"),
        CloudflareLifecyclePutReceiptV1::new(&recovery_request.lifecycle.lifecycle_id, true)
            .expect("recovery lifecycle"),
        signer_a_response.client_bundle.clone(),
        signer_b_response.client_bundle.clone(),
    )
    .expect("Router A/B ECDSA derivation recovery Router response");
    router_response
        .validate_for_router_payload(&router_payload)
        .expect("Router A/B ECDSA derivation recovery Router response matches payload");

    let admission =
        CloudflareRouterAbEcdsaDerivationRecoveryAdmissionResponseV1::forwarded(router_response)
            .expect("Router A/B ECDSA derivation recovery admission response");
    admission
        .validate()
        .expect("Router A/B ECDSA derivation recovery admission validates");

    let swapped = CloudflareRouterRecipientProofBundleResponseV1::new(
        CloudflareReplayReserveResponseV1::new(&recovery_request.recovery_nonce, true)
            .expect("recovery replay"),
        CloudflareLifecyclePutReceiptV1::new(&recovery_request.lifecycle.lifecycle_id, true)
            .expect("recovery lifecycle"),
        signer_b_response.client_bundle,
        signer_a_response.client_bundle,
    )
    .expect_err("swapped recovery client bundles must fail");
    assert_eq!(
        swapped.code(),
        RouterAbProtocolErrorCode::InvalidSignerIdentity
    );
}

#[test]
fn router_ab_ecdsa_derivation_deriver_recovery_private_request_rejects_payload_drift() {
    let mut recovery_request =
        router_ab_ecdsa_derivation_recovery_request_with_aad_bound_envelopes();
    let public_request = recovery_request
        .to_threshold_prf_request()
        .expect("Router A/B ECDSA derivation recovery public request");
    let (deriver_a_message, _) = public_request
        .to_signer_wire_messages()
        .expect("Router A/B ECDSA derivation recovery signer messages");
    let bootstrap = cloudflare_signer_private_bootstrap_from_public_request_v1(
        CloudflareWorkerRoleV1::DeriverA,
        &public_request,
        deriver_a_message,
    )
    .expect("Router A/B ECDSA derivation recovery bootstrap");
    recovery_request.recovery_nonce = "ecdsa-recovery-nonce-drift".to_owned();

    let err = CloudflareRouterAbEcdsaDerivationDeriverRecoveryPrivateRequestV1::new(
        CloudflareWorkerRoleV1::DeriverA,
        recovery_request,
        bootstrap,
    )
    .expect_err("payload drift must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::MalformedWirePayload);
}

#[test]
fn router_ab_ecdsa_derivation_deriver_activation_refresh_private_request_accepts_matching_payload()
{
    let refresh_request =
        router_ab_ecdsa_derivation_activation_refresh_request_with_aad_bound_envelopes();
    let public_request = refresh_request
        .to_threshold_prf_request()
        .expect("Router A/B ECDSA derivation refresh public request");
    let (deriver_a_message, _) = public_request
        .to_signer_wire_messages()
        .expect("Router A/B ECDSA derivation refresh signer messages");
    let bootstrap = cloudflare_signer_private_bootstrap_from_public_request_v1(
        CloudflareWorkerRoleV1::DeriverA,
        &public_request,
        deriver_a_message.clone(),
    )
    .expect("Router A/B ECDSA derivation refresh bootstrap");
    let router_payload = decode_router_to_signer_payload_v1(deriver_a_message.payload.as_bytes())
        .expect("Router A/B ECDSA derivation refresh Router payload");

    validate_cloudflare_router_ab_ecdsa_derivation_activation_refresh_request_for_router_payload_v1(
        &refresh_request,
        &router_payload,
    )
    .expect("Router A/B ECDSA derivation refresh payload binding");
    let private_request =
        CloudflareRouterAbEcdsaDerivationDeriverActivationRefreshPrivateRequestV1::new(
            CloudflareWorkerRoleV1::DeriverA,
            refresh_request,
            bootstrap,
        )
        .expect("Router A/B ECDSA derivation refresh private request");

    private_request
        .validate_for_worker_role(CloudflareWorkerRoleV1::DeriverA)
        .expect("Router A/B ECDSA derivation refresh private request validates");
}

#[test]
fn router_ab_ecdsa_derivation_deriver_activation_refresh_private_request_rejects_payload_drift() {
    let mut refresh_request =
        router_ab_ecdsa_derivation_activation_refresh_request_with_aad_bound_envelopes();
    let public_request = refresh_request
        .to_threshold_prf_request()
        .expect("Router A/B ECDSA derivation refresh public request");
    let (deriver_a_message, _) = public_request
        .to_signer_wire_messages()
        .expect("Router A/B ECDSA derivation refresh signer messages");
    let bootstrap = cloudflare_signer_private_bootstrap_from_public_request_v1(
        CloudflareWorkerRoleV1::DeriverA,
        &public_request,
        deriver_a_message,
    )
    .expect("Router A/B ECDSA derivation refresh bootstrap");
    refresh_request.refresh_nonce = "ecdsa-refresh-nonce-drift".to_owned();

    let err = CloudflareRouterAbEcdsaDerivationDeriverActivationRefreshPrivateRequestV1::new(
        CloudflareWorkerRoleV1::DeriverA,
        refresh_request,
        bootstrap,
    )
    .expect_err("payload drift must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::MalformedWirePayload);
}

#[test]
fn client_recipient_proof_bundle_response_rejects_server_bundle() {
    let request = ecdsa_threshold_prf_request_with_reconstructed_transcript(2_000);
    let (deriver_a_message, _) = request
        .to_signer_wire_messages()
        .expect("signer wire messages");
    let router_payload = decode_router_to_signer_payload_v1(deriver_a_message.payload.as_bytes())
        .expect("router payload");
    let server_bundle = server_proof_bundle_wire(&router_payload, Role::SignerA, 0xa3);
    let err =
        CloudflareSignerClientRecipientProofBundleResponseV1::new(Role::SignerA, server_bundle)
            .expect_err("client-only response must reject server bundles");

    assert_eq!(
        err.code(),
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig
    );
}

#[test]
fn router_ab_ecdsa_derivation_lifecycles_enforce_exact_client_and_signing_worker_recipients() {
    let registration = router_ab_ecdsa_derivation_registration_request_with_aad_bound_envelopes()
        .to_threshold_prf_request()
        .expect("registration threshold-PRF request");
    let export = router_ab_ecdsa_derivation_export_request_with_aad_bound_envelopes()
        .to_threshold_prf_request()
        .expect("export threshold-PRF request");
    let recovery = router_ab_ecdsa_derivation_recovery_request_with_aad_bound_envelopes()
        .to_threshold_prf_request()
        .expect("recovery threshold-PRF request");
    let refresh = router_ab_ecdsa_derivation_activation_refresh_request_with_aad_bound_envelopes()
        .to_threshold_prf_request()
        .expect("refresh threshold-PRF request");
    let cases = [
        ("registration", first_router_payload(&registration), true),
        ("export", first_router_payload(&export), false),
        ("recovery", first_router_payload(&recovery), true),
        ("refresh", first_router_payload(&refresh), true),
    ];

    for (operation, router_payload, expects_signing_worker_recipient) in cases {
        assert_exact_lifecycle_recipient_bindings(
            operation,
            &router_payload,
            expects_signing_worker_recipient,
        );
    }
}

fn first_router_payload(request: &EcdsaThresholdPrfRequestV1) -> RouterToSignerPayloadV1 {
    let (deriver_a_message, _) = request
        .to_signer_wire_messages()
        .expect("threshold-PRF signer messages");
    decode_router_to_signer_payload_v1(deriver_a_message.payload.as_bytes())
        .expect("Router payload")
}

fn assert_exact_lifecycle_recipient_bindings(
    operation: &str,
    router_payload: &RouterToSignerPayloadV1,
    expects_signing_worker_recipient: bool,
) {
    let client_a = client_proof_bundle_wire(router_payload, Role::SignerA, 0x81);
    let client_b = client_proof_bundle_wire(router_payload, Role::SignerB, 0x82);
    let response_a =
        CloudflareSignerClientRecipientProofBundleResponseV1::new(Role::SignerA, client_a.clone())
            .expect("Deriver A client response");
    let response_b =
        CloudflareSignerClientRecipientProofBundleResponseV1::new(Role::SignerB, client_b.clone())
            .expect("Deriver B client response");
    response_a
        .validate_for_router_payload(router_payload)
        .expect("Deriver A client binding");
    response_b
        .validate_for_router_payload(router_payload)
        .expect("Deriver B client binding");
    let client_envelope = decode_recipient_proof_bundle_ciphertext_v1(client_a.payload.as_bytes())
        .expect("client envelope");
    assert_eq!(client_envelope.recipient_role, Role::Client, "{operation}");
    assert_eq!(
        client_envelope.opened_share_kind,
        OpenedShareKind::XClientBase,
        "{operation}",
    );
    assert_eq!(
        client_envelope.recipient_identity,
        router_payload.transcript_metadata().client_id,
        "{operation}",
    );
    assert_eq!(
        client_envelope.recipient_encryption_key,
        router_payload
            .transcript_metadata()
            .client_ephemeral_public_key,
        "{operation}",
    );
    assert_eq!(
        client_envelope.transcript_digest,
        router_payload.transcript_digest(),
        "{operation}",
    );

    let substituted_client = recipient_bundle_with_identity(&client_a, "substituted-client");
    let substituted_response = CloudflareSignerClientRecipientProofBundleResponseV1::new(
        Role::SignerA,
        substituted_client,
    )
    .expect("substituted client response remains structurally valid");
    assert!(
        substituted_response
            .validate_for_router_payload(router_payload)
            .is_err(),
        "{operation} must reject client recipient substitution",
    );

    if expects_signing_worker_recipient {
        let server_a = server_proof_bundle_wire(router_payload, Role::SignerA, 0x83);
        let server_b = server_proof_bundle_wire(router_payload, Role::SignerB, 0x84);
        let activation = CloudflareSigningWorkerRecipientProofBundleActivationV1::new(
            server_a.clone(),
            server_b,
        )
        .expect("SigningWorker activation");
        activation
            .validate_for_router_payload(router_payload)
            .expect("SigningWorker binding");
        let server_envelope =
            decode_recipient_proof_bundle_ciphertext_v1(server_a.payload.as_bytes())
                .expect("SigningWorker envelope");
        assert_eq!(server_envelope.recipient_role, Role::Server, "{operation}");
        assert_eq!(
            server_envelope.opened_share_kind,
            OpenedShareKind::XServerBase,
            "{operation}",
        );
        assert_eq!(
            server_envelope.recipient_identity,
            router_payload.signer_set().selected_server.server_id,
            "{operation}",
        );
        assert_eq!(
            server_envelope.recipient_encryption_key,
            router_payload
                .signer_set()
                .selected_server
                .recipient_encryption_key,
            "{operation}",
        );
        assert_eq!(
            server_envelope.transcript_digest,
            router_payload.transcript_digest(),
            "{operation}",
        );
        let substituted_server =
            recipient_bundle_with_identity(&server_a, "substituted-signing-worker");
        let substituted_activation = CloudflareSigningWorkerRecipientProofBundleActivationV1::new(
            substituted_server,
            activation.deriver_b_server_bundle,
        )
        .expect("substituted SigningWorker activation remains structurally valid");
        assert!(
            substituted_activation
                .validate_for_router_payload(router_payload)
                .is_err(),
            "{operation} must reject SigningWorker recipient substitution",
        );
    }
}

fn recipient_bundle_with_identity(
    message: &WireMessageV1,
    recipient_identity: &str,
) -> WireMessageV1 {
    let envelope = decode_recipient_proof_bundle_ciphertext_v1(message.payload.as_bytes())
        .expect("recipient envelope");
    let nonce = *envelope.nonce();
    let ciphertext_and_tag = envelope.ciphertext_and_tag().as_bytes().to_vec();
    let changed = RecipientProofBundleCiphertextV1::new(
        envelope.algorithm,
        envelope.signer,
        envelope.recipient_role,
        envelope.opened_share_kind,
        recipient_identity,
        envelope.recipient_encryption_key,
        envelope.transcript_digest,
        envelope.payload_digest,
        nonce,
        EncryptedPayloadV1::new(ciphertext_and_tag).expect("recipient ciphertext clone"),
    )
    .expect("changed recipient envelope");
    WireMessageV1::new(
        WireMessageKindV1::RecipientProofBundle,
        changed.transcript_digest,
        CanonicalWireBytesV1::new(
            encode_recipient_proof_bundle_ciphertext_v1(&changed)
                .expect("changed recipient envelope bytes"),
        )
        .expect("changed recipient envelope wire"),
    )
    .expect("changed recipient message")
}

#[test]
fn signer_private_bootstrap_rejects_wrong_aad_digest() {
    let request = ecdsa_threshold_prf_request_with_aad_bound_envelopes(2_000);
    let message =
        signer_private_request_with_aad_bound_envelope(WireMessageKindV1::RouterToSignerA);
    let mut aad = role_envelope_aad_for_request(Role::SignerA, &request);
    aad.router_request_digest = digest(0x99);
    let err = CloudflareSignerPrivateBootstrapRequestV1::new(
        CloudflareWorkerRoleV1::DeriverA,
        message,
        aad,
        request_context_digest(&request),
    )
    .expect_err("bootstrap AAD digest mismatch must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::MalformedWirePayload);
}

#[test]
fn signer_private_bootstrap_rejects_body_request_digest_mismatch() {
    let request = ecdsa_threshold_prf_request_with_aad_bound_envelopes(2_000);
    let message =
        signer_private_request_with_aad_bound_envelope(WireMessageKindV1::RouterToSignerA);
    let aad = role_envelope_aad_for_request(Role::SignerA, &request);
    let err = CloudflareSignerPrivateBootstrapRequestV1::new(
        CloudflareWorkerRoleV1::DeriverA,
        message,
        aad,
        digest(0x99),
    )
    .expect_err("bootstrap body Router request digest mismatch must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::MalformedWirePayload);
}

#[test]
fn signer_private_bootstrap_derives_preload_plan() {
    let request = ecdsa_threshold_prf_request_with_aad_bound_envelopes(2_000);
    let message =
        signer_private_request_with_aad_bound_envelope(WireMessageKindV1::RouterToSignerA);
    let aad = role_envelope_aad_for_request(Role::SignerA, &request);
    let bootstrap = CloudflareSignerPrivateBootstrapRequestV1::new(
        CloudflareWorkerRoleV1::DeriverA,
        message.clone(),
        aad,
        request_context_digest(&request),
    )
    .expect("strict signer bootstrap");
    let plan = CloudflareSignerHostPreloadPlanV1::from_private_bootstrap(
        CloudflareWorkerRoleV1::DeriverA,
        &bootstrap,
    )
    .expect("preload plan");

    assert_eq!(plan.worker_role, CloudflareWorkerRoleV1::DeriverA);
    assert_eq!(plan.signer_set_id, "signer-set-v1");
    assert_eq!(plan.root_share_epoch, root_epoch());
    assert_eq!(plan.local_signer, signer_identity(Role::SignerA));
    assert_eq!(plan.signer_set, signer_set());
    assert_eq!(plan.transcript_digest, message.transcript_digest);
    assert_eq!(plan.router_request_digest, request_context_digest(&request));
}

#[test]
fn signer_private_preload_plan_builds_host_preload_input() {
    let request = ecdsa_threshold_prf_request_with_aad_bound_envelopes(2_000);
    let message =
        signer_private_request_with_aad_bound_envelope(WireMessageKindV1::RouterToSignerA);
    let aad = role_envelope_aad_for_request(Role::SignerA, &request);
    let bootstrap = CloudflareSignerPrivateBootstrapRequestV1::new(
        CloudflareWorkerRoleV1::DeriverA,
        message,
        aad,
        request_context_digest(&request),
    )
    .expect("strict signer bootstrap");
    let plan = CloudflareSignerHostPreloadPlanV1::from_private_bootstrap(
        CloudflareWorkerRoleV1::DeriverA,
        &bootstrap,
    )
    .expect("preload plan");
    let input = plan
        .to_host_preload_input_with_key_set(Vec::new(), &cloudflare_peer_verifying_key_set(), 0)
        .expect("host preload input");

    assert_eq!(input.signer_set_id, "signer-set-v1");
    assert_eq!(input.root_share_epoch, root_epoch());
    assert!(input.peer_responses.is_empty());
    assert_eq!(input.signer_verifying_keys, signer_verifying_keys());
    assert_eq!(input.random_bytes_len, 0);
}

#[test]
fn signer_private_preload_plan_rejects_wrong_worker_role() {
    let request = ecdsa_threshold_prf_request_with_aad_bound_envelopes(2_000);
    let message =
        signer_private_request_with_aad_bound_envelope(WireMessageKindV1::RouterToSignerA);
    let aad = role_envelope_aad_for_request(Role::SignerA, &request);
    let bootstrap = CloudflareSignerPrivateBootstrapRequestV1::new(
        CloudflareWorkerRoleV1::DeriverA,
        message,
        aad,
        request_context_digest(&request),
    )
    .expect("strict signer bootstrap");
    let err = CloudflareSignerHostPreloadPlanV1::from_private_bootstrap(
        CloudflareWorkerRoleV1::DeriverB,
        &bootstrap,
    )
    .expect_err("wrong Worker role must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidLocalRoute);
}

#[test]
fn cloudflare_signer_envelope_hpke_public_key_set_parses_from_env() {
    let deriver_a_public_key = x25519_public_key(0x11);
    let deriver_b_public_key = x25519_public_key(0x22);
    let env = CloudflareEnvMapV1::new(vec![
        (
            DERIVER_A_ENVELOPE_HPKE_KEY_EPOCH_ENV,
            "envelope-hpke-key-epoch-a".to_string(),
        ),
        (
            DERIVER_A_ENVELOPE_HPKE_PUBLIC_KEY_ENV,
            deriver_a_public_key.clone(),
        ),
        (
            DERIVER_B_ENVELOPE_HPKE_KEY_EPOCH_ENV,
            "envelope-hpke-key-epoch-b".to_string(),
        ),
        (
            DERIVER_B_ENVELOPE_HPKE_PUBLIC_KEY_ENV,
            deriver_b_public_key.clone(),
        ),
    ]);

    let key_set =
        parse_cloudflare_signer_envelope_hpke_public_key_set_v1(&env).expect("hpke key set");

    assert_eq!(key_set.deriver_a.role, Role::SignerA);
    assert_eq!(key_set.deriver_a.key_epoch, "envelope-hpke-key-epoch-a");
    assert_eq!(key_set.deriver_a.public_key, deriver_a_public_key);
    assert_eq!(key_set.deriver_b.role, Role::SignerB);
    assert_eq!(key_set.deriver_b.key_epoch, "envelope-hpke-key-epoch-b");
    assert_eq!(key_set.deriver_b.public_key, deriver_b_public_key);
}

#[test]
fn cloudflare_deriver_peer_verifying_key_set_parses_from_env() {
    let env = CloudflareEnvMapV1::new(vec![
        (
            DERIVER_A_PEER_VERIFYING_KEY_HEX_ENV,
            signer_peer_verifying_key_hex(Role::SignerA),
        ),
        (
            DERIVER_B_PEER_VERIFYING_KEY_HEX_ENV,
            signer_peer_verifying_key_hex(Role::SignerB),
        ),
    ]);

    let key_set =
        parse_cloudflare_deriver_peer_verifying_key_set_v1(&env).expect("peer verifying key set");

    assert_eq!(key_set.deriver_a.role, Role::SignerA);
    assert_eq!(key_set.deriver_b.role, Role::SignerB);
    assert_eq!(
        key_set
            .to_hex_descriptor_set()
            .expect("hex descriptors")
            .deriver_a
            .verifying_key_hex,
        signer_peer_verifying_key_hex(Role::SignerA)
    );
}

#[test]
fn router_public_keyset_builds_from_public_env_only() {
    let keyset = build_cloudflare_router_public_keyset_v2(&router_env_with_public_keyset())
        .expect("router public keyset");
    assert_eq!(keyset.keyset_version, "router_ab_keyset_v2");
    assert_eq!(
        keyset.signer_envelope_hpke.current.deriver_a.role,
        Role::SignerA
    );
    assert!(keyset.signer_envelope_hpke.previous.is_none());
    assert_eq!(
        keyset
            .signer_peer_verifying_keys
            .deriver_b
            .verifying_key_hex,
        signer_peer_verifying_key_hex(Role::SignerB)
    );
    assert_eq!(
        keyset.signing_worker_server_output_hpke.public_key,
        signer_set().selected_server.recipient_encryption_key
    );

    let json = serde_json::to_string(&keyset).expect("keyset JSON");
    for forbidden in [
        "PRIVATE_KEY",
        "DERIVER_A_PEER_SIGNING_KEY",
        "DERIVER_B_PEER_SIGNING_KEY",
        "ROOT_SHARE_WIRE_SECRET",
        "hpke-x25519-private-v1",
        "hpke-x25519-server-output-private-v1",
        "mpc-prf-root-share-wire-v1",
    ] {
        assert!(
            !json.contains(forbidden),
            "router public keyset leaked private descriptor marker `{forbidden}`"
        );
    }
}

#[test]
fn router_bindings_accept_public_keyset_env_without_private_bindings() {
    let bindings = parse_cloudflare_worker_bindings_v1(
        CloudflareWorkerRoleV1::Router,
        &router_env_with_public_keyset(),
    )
    .expect("router bindings with public keyset env");

    assert!(matches!(
        bindings,
        CloudflareWorkerBindingsV1::Router { bindings: _ }
    ));
}

#[test]
fn cloudflare_signer_envelope_hpke_rotation_keyset_accepts_current_and_previous_overlap() {
    let current = CloudflareSignerEnvelopeHpkePublicKeySetV1::new(
        CloudflareSignerEnvelopeHpkePublicKeyV1::new(
            Role::SignerA,
            "envelope-hpke-key-epoch-a-current",
            x25519_public_key(0x11),
        )
        .expect("current signer a"),
        CloudflareSignerEnvelopeHpkePublicKeyV1::new(
            Role::SignerB,
            "envelope-hpke-key-epoch-b-current",
            x25519_public_key(0x22),
        )
        .expect("current signer b"),
    )
    .expect("current keyset");
    let previous = CloudflareSignerEnvelopeHpkePublicKeySetV1::new(
        CloudflareSignerEnvelopeHpkePublicKeyV1::new(
            Role::SignerA,
            "envelope-hpke-key-epoch-a-previous",
            x25519_public_key(0x33),
        )
        .expect("previous signer a"),
        CloudflareSignerEnvelopeHpkePublicKeyV1::new(
            Role::SignerB,
            "envelope-hpke-key-epoch-b-previous",
            x25519_public_key(0x44),
        )
        .expect("previous signer b"),
    )
    .expect("previous keyset");
    let keyset = CloudflareSignerEnvelopeHpkeRotationPublicKeySetV1::current_and_previous(
        current, previous, 2_000,
    )
    .expect("rotation keyset");

    assert_eq!(
        keyset
            .accepted_for_role_epoch(Role::SignerA, "envelope-hpke-key-epoch-a-current", 3_000)
            .expect("current signer a key")
            .public_key,
        x25519_public_key(0x11)
    );
    assert_eq!(
        keyset
            .accepted_for_role_epoch(Role::SignerB, "envelope-hpke-key-epoch-b-previous", 2_000)
            .expect("previous signer b key in overlap")
            .public_key,
        x25519_public_key(0x44)
    );
}

#[test]
fn cloudflare_signer_envelope_hpke_rotation_keyset_rejects_retired_previous_epoch() {
    let env = CloudflareEnvMapV1::new(vec![
        (
            DERIVER_A_ENVELOPE_HPKE_KEY_EPOCH_ENV,
            "envelope-hpke-key-epoch-a-current".to_string(),
        ),
        (
            DERIVER_A_ENVELOPE_HPKE_PUBLIC_KEY_ENV,
            x25519_public_key(0x11),
        ),
        (
            DERIVER_B_ENVELOPE_HPKE_KEY_EPOCH_ENV,
            "envelope-hpke-key-epoch-b-current".to_string(),
        ),
        (
            DERIVER_B_ENVELOPE_HPKE_PUBLIC_KEY_ENV,
            x25519_public_key(0x22),
        ),
        (
            DERIVER_A_PREVIOUS_ENVELOPE_HPKE_KEY_EPOCH_ENV,
            "envelope-hpke-key-epoch-a-previous".to_string(),
        ),
        (
            DERIVER_A_PREVIOUS_ENVELOPE_HPKE_PUBLIC_KEY_ENV,
            x25519_public_key(0x33),
        ),
        (
            DERIVER_B_PREVIOUS_ENVELOPE_HPKE_KEY_EPOCH_ENV,
            "envelope-hpke-key-epoch-b-previous".to_string(),
        ),
        (
            DERIVER_B_PREVIOUS_ENVELOPE_HPKE_PUBLIC_KEY_ENV,
            x25519_public_key(0x44),
        ),
        (
            ROUTER_AB_PREVIOUS_ENVELOPE_HPKE_RETIRE_AT_MS_ENV,
            "2000".to_string(),
        ),
    ]);
    let keyset = parse_cloudflare_signer_envelope_hpke_rotation_public_key_set_v1(&env)
        .expect("rotation public keyset");

    let err = keyset
        .accepted_for_role_epoch(Role::SignerA, "envelope-hpke-key-epoch-a-previous", 2_001)
        .expect_err("retired previous epoch must fail");
    assert_eq!(err.code(), RouterAbProtocolErrorCode::ExpiredLocalRequest);
}

#[test]
fn cloudflare_signer_envelope_hpke_rotation_keyset_rejects_partial_previous_descriptor() {
    let env = CloudflareEnvMapV1::new(vec![
        (
            DERIVER_A_ENVELOPE_HPKE_KEY_EPOCH_ENV,
            "envelope-hpke-key-epoch-a-current".to_string(),
        ),
        (
            DERIVER_A_ENVELOPE_HPKE_PUBLIC_KEY_ENV,
            x25519_public_key(0x11),
        ),
        (
            DERIVER_B_ENVELOPE_HPKE_KEY_EPOCH_ENV,
            "envelope-hpke-key-epoch-b-current".to_string(),
        ),
        (
            DERIVER_B_ENVELOPE_HPKE_PUBLIC_KEY_ENV,
            x25519_public_key(0x22),
        ),
        (
            DERIVER_A_PREVIOUS_ENVELOPE_HPKE_KEY_EPOCH_ENV,
            "envelope-hpke-key-epoch-a-previous".to_string(),
        ),
    ]);

    let err = parse_cloudflare_signer_envelope_hpke_rotation_public_key_set_v1(&env)
        .expect_err("partial previous descriptor must fail");
    assert_eq!(err.code(), RouterAbProtocolErrorCode::MissingLocalBinding);
}

#[test]
fn cloudflare_signer_envelope_hpke_public_key_set_rejects_role_swap() {
    let err = CloudflareSignerEnvelopeHpkePublicKeySetV1::new(
        CloudflareSignerEnvelopeHpkePublicKeyV1::new(
            Role::SignerB,
            "envelope-hpke-key-epoch-a",
            x25519_public_key(0x11),
        )
        .expect("swapped signer a descriptor"),
        CloudflareSignerEnvelopeHpkePublicKeyV1::new(
            Role::SignerA,
            "envelope-hpke-key-epoch-b",
            x25519_public_key(0x22),
        )
        .expect("swapped signer b descriptor"),
    )
    .expect_err("swapped signer roles must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidRole);
}

#[test]
fn cloudflare_signer_envelope_hpke_decrypt_key_binding_is_role_local() {
    let key = deriver_a_envelope_hpke_decrypt_key();

    key.validate_visible_to(CloudflareWorkerRoleV1::DeriverA)
        .expect("signer a can access signer a hpke key");
    let err = key
        .validate_visible_to(CloudflareWorkerRoleV1::Router)
        .expect_err("router must not access signer hpke key");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::ForbiddenLocalBinding);
}

#[test]
fn cloudflare_signer_envelope_hpke_decrypt_key_parses_from_role_env() {
    let public_key = x25519_public_key(0x11);
    let env = CloudflareEnvMapV1::new(vec![
        (
            DERIVER_A_ENVELOPE_HPKE_PRIVATE_KEY_BINDING_ENV,
            "DERIVER_A_ENVELOPE_HPKE_PRIVATE_KEY".to_string(),
        ),
        (
            DERIVER_A_ENVELOPE_HPKE_KEY_EPOCH_ENV,
            "envelope-hpke-key-epoch-a".to_string(),
        ),
        (DERIVER_A_ENVELOPE_HPKE_PUBLIC_KEY_ENV, public_key.clone()),
    ]);

    let key = parse_cloudflare_signer_envelope_hpke_decrypt_key_binding_v1(
        CloudflareWorkerRoleV1::DeriverA,
        &env,
    )
    .expect("signer a hpke decrypt key");

    assert_eq!(key.role, Role::SignerA);
    assert_eq!(key.binding_name, "DERIVER_A_ENVELOPE_HPKE_PRIVATE_KEY");
    assert_eq!(key.key_epoch, "envelope-hpke-key-epoch-a");
    assert_eq!(key.public_key, public_key);
}

#[test]
fn cloudflare_signer_envelope_hpke_decrypt_key_set_parses_current_only() {
    let key_set = parse_cloudflare_signer_envelope_hpke_decrypt_key_binding_set_v1(
        CloudflareWorkerRoleV1::DeriverA,
        &deriver_a_env(),
    )
    .expect("signer a hpke decrypt key set");

    assert_eq!(key_set.current, deriver_a_envelope_hpke_decrypt_key());
    assert_eq!(key_set.previous, None);
    assert_eq!(key_set.previous_retire_at_ms, None);
}

#[test]
fn cloudflare_signer_envelope_hpke_decrypt_key_set_parses_previous_overlap() {
    let env = deriver_a_env().with_overrides(vec![
        (
            DERIVER_A_PREVIOUS_ENVELOPE_HPKE_PRIVATE_KEY_BINDING_ENV,
            "DERIVER_A_PREVIOUS_ENVELOPE_HPKE_PRIVATE_KEY".to_string(),
        ),
        (
            DERIVER_A_PREVIOUS_ENVELOPE_HPKE_KEY_EPOCH_ENV,
            "envelope-hpke-key-epoch-a-previous".to_string(),
        ),
        (
            DERIVER_A_PREVIOUS_ENVELOPE_HPKE_PUBLIC_KEY_ENV,
            x25519_public_key(0x33),
        ),
        (
            ROUTER_AB_PREVIOUS_ENVELOPE_HPKE_RETIRE_AT_MS_ENV,
            "2000".to_string(),
        ),
    ]);

    let key_set = parse_cloudflare_signer_envelope_hpke_decrypt_key_binding_set_v1(
        CloudflareWorkerRoleV1::DeriverA,
        &env,
    )
    .expect("signer a rotating hpke decrypt key set");

    assert_eq!(key_set.current, deriver_a_envelope_hpke_decrypt_key());
    let previous = key_set.previous.expect("previous hpke decrypt key");
    assert_eq!(
        previous.binding_name,
        "DERIVER_A_PREVIOUS_ENVELOPE_HPKE_PRIVATE_KEY"
    );
    assert_eq!(previous.key_epoch, "envelope-hpke-key-epoch-a-previous");
    assert_eq!(previous.public_key, x25519_public_key(0x33));
    assert_eq!(key_set.previous_retire_at_ms, Some(2_000));
}

#[test]
fn cloudflare_signer_envelope_hpke_decrypt_key_set_rejects_partial_previous_overlap() {
    let env = deriver_a_env().with_overrides(vec![(
        DERIVER_A_PREVIOUS_ENVELOPE_HPKE_PRIVATE_KEY_BINDING_ENV,
        "DERIVER_A_PREVIOUS_ENVELOPE_HPKE_PRIVATE_KEY".to_string(),
    )]);

    let err = parse_cloudflare_signer_envelope_hpke_decrypt_key_binding_set_v1(
        CloudflareWorkerRoleV1::DeriverA,
        &env,
    )
    .expect_err("partial previous private keyset must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::MissingLocalBinding);
}

#[test]
fn cloudflare_signer_envelope_hpke_decrypt_key_set_selects_previous_until_retired() {
    let previous = CloudflareSignerEnvelopeHpkeDecryptKeyBindingV1::new(
        Role::SignerA,
        "DERIVER_A_PREVIOUS_ENVELOPE_HPKE_PRIVATE_KEY",
        "envelope-hpke-key-epoch-a-previous",
        x25519_public_key(0x33),
    )
    .expect("previous signer a hpke decrypt key");
    let key_set = CloudflareSignerEnvelopeHpkeDecryptKeyBindingSetV1::current_and_previous(
        deriver_a_envelope_hpke_decrypt_key(),
        previous.clone(),
        2_000,
    )
    .expect("rotating signer a hpke key set");
    let payload = signer_envelope_hpke_payload(
        Role::SignerA,
        "envelope-hpke-key-epoch-a-previous",
        &x25519_public_key(0x33),
        digest(0x11),
    );

    let selected = key_set
        .accepted_binding_for_payload(CloudflareWorkerRoleV1::DeriverA, &payload, 2_000)
        .expect("previous key accepted before retirement");
    assert_eq!(selected, &previous);

    let err = key_set
        .accepted_binding_for_payload(CloudflareWorkerRoleV1::DeriverA, &payload, 2_001)
        .expect_err("previous key rejected after retirement");
    assert_eq!(err.code(), RouterAbProtocolErrorCode::ExpiredLocalRequest);
}

#[test]
fn cloudflare_signer_envelope_hpke_decrypt_key_set_decodes_current_message() {
    let message = signer_private_request_with_hpke_envelope(WireMessageKindV1::RouterToSignerA);
    let key_set = deriver_a_envelope_hpke_decrypt_key_set();

    let (selected, payload) =
        decode_and_select_cloudflare_signer_envelope_hpke_decrypt_key_binding_v1(
            CloudflareWorkerRoleV1::DeriverA,
            &message,
            &key_set,
            1_500,
        )
        .expect("current signer a key selected");

    assert_eq!(selected, &deriver_a_envelope_hpke_decrypt_key());
    assert_eq!(payload.key_epoch, "envelope-hpke-key-epoch-a");
}

#[test]
fn cloudflare_signer_envelope_hpke_decrypt_key_set_opens_current_and_previous() {
    let (current_private_key, current_public_key) = hpke_keypair(0x42);
    let (previous_private_key, previous_public_key) = hpke_keypair(0x43);
    let current = CloudflareSignerEnvelopeHpkeDecryptKeyBindingV1::new(
        Role::SignerA,
        "DERIVER_A_ENVELOPE_HPKE_PRIVATE_KEY",
        "envelope-hpke-key-epoch-a-current",
        current_public_key,
    )
    .expect("current signer a hpke decrypt key");
    let previous = CloudflareSignerEnvelopeHpkeDecryptKeyBindingV1::new(
        Role::SignerA,
        "DERIVER_A_PREVIOUS_ENVELOPE_HPKE_PRIVATE_KEY",
        "envelope-hpke-key-epoch-a-previous",
        previous_public_key,
    )
    .expect("previous signer a hpke decrypt key");
    let key_set = CloudflareSignerEnvelopeHpkeDecryptKeyBindingSetV1::current_and_previous(
        current.clone(),
        previous.clone(),
        2_000,
    )
    .expect("rotating signer a hpke key set");
    let expected_plaintext = signer_input_plaintext_bytes(Role::SignerA);

    let (current_message, current_aad) =
        deriver_a_private_request_with_sealed_hpke_envelope_for_key(
            &current.key_epoch,
            &current.public_key,
            &expected_plaintext,
        );
    let (current_selected, _) =
        decode_and_select_cloudflare_signer_envelope_hpke_decrypt_key_binding_v1(
            CloudflareWorkerRoleV1::DeriverA,
            &current_message,
            &key_set,
            1_500,
        )
        .expect("current key selected");
    assert_eq!(current_selected, &current);
    let current_plaintext = open_cloudflare_signer_envelope_hpke_payload_v1(
        CloudflareWorkerRoleV1::DeriverA,
        &current_message,
        current_selected,
        &current_aad,
        &current_private_key,
    )
    .expect("current key opens");
    assert_eq!(current_plaintext, expected_plaintext);

    let (previous_message, previous_aad) =
        deriver_a_private_request_with_sealed_hpke_envelope_for_key(
            &previous.key_epoch,
            &previous.public_key,
            &expected_plaintext,
        );
    let (previous_selected, _) =
        decode_and_select_cloudflare_signer_envelope_hpke_decrypt_key_binding_v1(
            CloudflareWorkerRoleV1::DeriverA,
            &previous_message,
            &key_set,
            2_000,
        )
        .expect("previous key selected during overlap");
    assert_eq!(previous_selected, &previous);
    let previous_plaintext = open_cloudflare_signer_envelope_hpke_payload_v1(
        CloudflareWorkerRoleV1::DeriverA,
        &previous_message,
        previous_selected,
        &previous_aad,
        &previous_private_key,
    )
    .expect("previous key opens during overlap");
    assert_eq!(previous_plaintext, expected_plaintext);

    let err = decode_and_select_cloudflare_signer_envelope_hpke_decrypt_key_binding_v1(
        CloudflareWorkerRoleV1::DeriverA,
        &previous_message,
        &key_set,
        2_001,
    )
    .expect_err("previous key must fail after retirement");
    assert_eq!(err.code(), RouterAbProtocolErrorCode::ExpiredLocalRequest);
}

#[test]
fn cloudflare_signer_envelope_hpke_payload_accepts_bound_public_metadata() {
    let message = signer_private_request_with_hpke_envelope(WireMessageKindV1::RouterToSignerA);

    let parsed = decode_and_validate_cloudflare_signer_envelope_hpke_payload_v1(
        CloudflareWorkerRoleV1::DeriverA,
        &message,
        &deriver_a_envelope_hpke_decrypt_key(),
    )
    .expect("validated HPKE payload");

    assert_eq!(parsed.recipient_role, Role::SignerA);
    assert_eq!(parsed.key_epoch, "envelope-hpke-key-epoch-a");
    assert_eq!(parsed.recipient_public_key, x25519_public_key(0x11));
    assert_eq!(parsed.aad_digest, digest(0x11));
}

#[test]
fn cloudflare_signer_envelope_hpke_payload_rejects_wrong_public_key() {
    let message = signer_private_request_with_hpke_envelope(WireMessageKindV1::RouterToSignerA);
    let key = CloudflareSignerEnvelopeHpkeDecryptKeyBindingV1::new(
        Role::SignerA,
        "DERIVER_A_ENVELOPE_HPKE_PRIVATE_KEY",
        "envelope-hpke-key-epoch-a",
        x25519_public_key(0x33),
    )
    .expect("wrong signer a hpke key descriptor");

    let err = decode_and_validate_cloudflare_signer_envelope_hpke_payload_v1(
        CloudflareWorkerRoleV1::DeriverA,
        &message,
        &key,
    )
    .expect_err("wrong hpke public key must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidSignerIdentity);
}

#[test]
fn cloudflare_signer_envelope_hpke_seal_open_round_trips_plaintext() {
    let (private_key, public_key) = hpke_keypair(0x42);
    let expected_plaintext = signer_input_plaintext_bytes(Role::SignerA);
    let (message, aad) =
        deriver_a_private_request_with_sealed_hpke_envelope(&public_key, &expected_plaintext);
    let key = CloudflareSignerEnvelopeHpkeDecryptKeyBindingV1::new(
        Role::SignerA,
        "DERIVER_A_ENVELOPE_HPKE_PRIVATE_KEY",
        "envelope-hpke-key-epoch-a",
        public_key,
    )
    .expect("signer a hpke decrypt key");

    let plaintext = open_cloudflare_signer_envelope_hpke_payload_v1(
        CloudflareWorkerRoleV1::DeriverA,
        &message,
        &key,
        &aad,
        &private_key,
    )
    .expect("hpke signer envelope opens");

    assert_eq!(plaintext, expected_plaintext);
}

#[test]
fn cloudflare_signer_envelope_hpke_open_rejects_wrong_aad() {
    let (private_key, public_key) = hpke_keypair(0x42);
    let expected_plaintext = signer_input_plaintext_bytes(Role::SignerA);
    let (message, mut aad) =
        deriver_a_private_request_with_sealed_hpke_envelope(&public_key, &expected_plaintext);
    aad.expires_at_ms += 1;
    let key = CloudflareSignerEnvelopeHpkeDecryptKeyBindingV1::new(
        Role::SignerA,
        "DERIVER_A_ENVELOPE_HPKE_PRIVATE_KEY",
        "envelope-hpke-key-epoch-a",
        public_key,
    )
    .expect("signer a hpke decrypt key");

    let err = open_cloudflare_signer_envelope_hpke_payload_v1(
        CloudflareWorkerRoleV1::DeriverA,
        &message,
        &key,
        &aad,
        &private_key,
    )
    .expect_err("modified AAD must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::MalformedWirePayload);
}

#[test]
fn cloudflare_signer_envelope_hpke_open_rejects_wrong_private_key() {
    let (_, public_key) = hpke_keypair(0x42);
    let (wrong_private_key, _) = hpke_keypair(0x43);
    let expected_plaintext = signer_input_plaintext_bytes(Role::SignerA);
    let (message, aad) =
        deriver_a_private_request_with_sealed_hpke_envelope(&public_key, &expected_plaintext);
    let key = CloudflareSignerEnvelopeHpkeDecryptKeyBindingV1::new(
        Role::SignerA,
        "DERIVER_A_ENVELOPE_HPKE_PRIVATE_KEY",
        "envelope-hpke-key-epoch-a",
        public_key,
    )
    .expect("signer a hpke decrypt key");

    let err = open_cloudflare_signer_envelope_hpke_payload_v1(
        CloudflareWorkerRoleV1::DeriverA,
        &message,
        &key,
        &aad,
        &wrong_private_key,
    )
    .expect_err("wrong private key must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::MalformedWirePayload);
}

#[test]
fn cloudflare_signer_envelope_hpke_private_key_secret_round_trips() {
    let (private_key, _) = hpke_keypair(0x42);

    let encoded = encode_cloudflare_signer_envelope_hpke_private_key_secret_v1(&private_key)
        .expect("private key secret encodes");
    let decoded = decode_cloudflare_signer_envelope_hpke_private_key_secret_v1(&encoded)
        .expect("private key secret decodes");

    assert!(encoded.starts_with(CLOUDFLARE_SIGNER_ENVELOPE_HPKE_PRIVATE_KEY_SECRET_PREFIX_V1));
    assert_eq!(decoded, private_key);
}

#[test]
fn cloudflare_server_output_hpke_private_key_secret_round_trips() {
    let (private_key, _) = hpke_keypair(0x43);

    let encoded = encode_cloudflare_server_output_hpke_private_key_secret_v1(&private_key)
        .expect("server-output private key secret encodes");
    let decoded = decode_cloudflare_server_output_hpke_private_key_secret_v1(&encoded)
        .expect("server-output private key secret decodes");

    assert!(encoded.starts_with(CLOUDFLARE_SERVER_OUTPUT_HPKE_PRIVATE_KEY_SECRET_PREFIX_V1));
    assert_eq!(decoded, private_key);
}

#[test]
fn cloudflare_signer_envelope_hpke_private_key_secret_rejects_bad_prefix() {
    let (private_key, _) = hpke_keypair(0x42);
    let encoded = format!("wrong-prefix:{}", lower_hex(&private_key));

    let err = decode_cloudflare_signer_envelope_hpke_private_key_secret_v1(&encoded)
        .expect_err("wrong private key secret prefix must fail");

    assert_eq!(
        err.code(),
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig
    );
}

#[test]
fn cloudflare_signer_input_plaintext_accepts_bound_decrypted_bytes() {
    let request = ecdsa_threshold_prf_request(2_000);
    let message = signer_private_request(WireMessageKindV1::RouterToSignerA);
    let plaintext = decode_and_validate_cloudflare_signer_input_plaintext_v1(
        CloudflareWorkerRoleV1::DeriverA,
        &message,
        &signer_input_plaintext_bytes(Role::SignerA),
        request_context_digest(&request),
        &root_share_metadata(Role::SignerA),
    )
    .expect("bound signer input plaintext");

    assert_eq!(plaintext.recipient_role, Role::SignerA);
    assert_eq!(plaintext.recipient_signer_id, "signer-a");
}

#[test]
fn cloudflare_signer_input_plaintext_rejects_wrong_root_metadata_identity() {
    let request = ecdsa_threshold_prf_request(2_000);
    let message = signer_private_request(WireMessageKindV1::RouterToSignerA);
    let metadata = CloudflareRootShareStartupMetadataV1::new(
        "signer-set-v1",
        Role::SignerA,
        "other-signer-a",
        "key-epoch-a",
        root_epoch(),
        "sealed/share/a",
    )
    .expect("metadata");

    let err = decode_and_validate_cloudflare_signer_input_plaintext_v1(
        CloudflareWorkerRoleV1::DeriverA,
        &message,
        &signer_input_plaintext_bytes(Role::SignerA),
        request_context_digest(&request),
        &metadata,
    )
    .expect_err("wrong root metadata identity must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidSignerIdentity);
}

#[test]
fn cloudflare_signer_input_plaintext_rejects_malformed_decrypted_bytes() {
    let request = ecdsa_threshold_prf_request(2_000);
    let message = signer_private_request(WireMessageKindV1::RouterToSignerA);

    let err = decode_and_validate_cloudflare_signer_input_plaintext_v1(
        CloudflareWorkerRoleV1::DeriverA,
        &message,
        &[0xde, 0xad],
        request_context_digest(&request),
        &root_share_metadata(Role::SignerA),
    )
    .expect_err("malformed decrypted plaintext must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::MalformedWirePayload);
}

#[test]
fn cloudflare_validated_signer_private_request_carries_validated_plaintext() {
    let request = ecdsa_threshold_prf_request(2_000);
    let message = signer_private_request(WireMessageKindV1::RouterToSignerA);
    let validated = validate_cloudflare_signer_private_request_plaintext_v1(
        CloudflareWorkerRoleV1::DeriverA,
        message.clone(),
        &signer_input_plaintext_bytes(Role::SignerA),
        request_context_digest(&request),
        &root_share_metadata(Role::SignerA),
    )
    .expect("validated signer request");

    assert_eq!(validated.worker_role(), CloudflareWorkerRoleV1::DeriverA);
    assert_eq!(validated.message(), &message);
    assert_eq!(validated.signer_input().recipient_role, Role::SignerA);
}

#[test]
fn cloudflare_validated_signer_private_request_rejects_bad_plaintext_before_handler() {
    let request = ecdsa_threshold_prf_request(2_000);
    let message = signer_private_request(WireMessageKindV1::RouterToSignerA);

    let err = validate_cloudflare_signer_private_request_plaintext_v1(
        CloudflareWorkerRoleV1::DeriverA,
        message,
        &[0xde, 0xad],
        request_context_digest(&request),
        &root_share_metadata(Role::SignerA),
    )
    .expect_err("malformed signer plaintext must fail before handler");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::MalformedWirePayload);
}

#[test]
fn cloudflare_validated_mpc_prf_engine_runs_deriver_a_batch() {
    let request = ecdsa_threshold_prf_request_with_reconstructed_transcript(2_000);
    let message =
        signer_private_request_with_reconstructed_transcript(WireMessageKindV1::RouterToSignerA);
    let validated = validate_cloudflare_signer_private_request_plaintext_v1(
        CloudflareWorkerRoleV1::DeriverA,
        message,
        &signer_input_plaintext_bytes_for_request(Role::SignerA, &request),
        request_context_digest(&request),
        &root_share_metadata(Role::SignerA),
    )
    .expect("validated signer request");
    let preload = CloudflareSignerHostPreloadInputV1::new(
        "signer-set-v1",
        root_epoch(),
        Vec::new(),
        signer_verifying_keys(),
        0,
    )
    .expect("preload input");
    let host = build_cloudflare_preloaded_signer_host_with_root_share_wire_v1(
        1_000,
        Role::SignerA,
        preload,
        root_share_metadata(Role::SignerA),
        root_share_wire(Role::SignerA),
        Vec::new(),
    )
    .expect("host with signer a root-share wire");
    let output = evaluate_cloudflare_validated_mpc_prf_batch_output_v1(&host, &validated)
        .expect("signer a engine output");

    assert_eq!(output.signer_role, Role::SignerA);
    assert_eq!(output.signer_identity, "signer-a");
    assert_eq!(output.root_share_epoch, root_epoch());
    assert_eq!(output.proof_bundles.len(), 2);
    assert_eq!(
        output.transcript_digest,
        validated.message().transcript_digest
    );
}

#[test]
fn cloudflare_validated_mpc_prf_engine_requires_root_share_wire() {
    let request = ecdsa_threshold_prf_request_with_reconstructed_transcript(2_000);
    let message =
        signer_private_request_with_reconstructed_transcript(WireMessageKindV1::RouterToSignerA);
    let validated = validate_cloudflare_signer_private_request_plaintext_v1(
        CloudflareWorkerRoleV1::DeriverA,
        message,
        &signer_input_plaintext_bytes_for_request(Role::SignerA, &request),
        request_context_digest(&request),
        &root_share_metadata(Role::SignerA),
    )
    .expect("validated signer request");
    let preload = CloudflareSignerHostPreloadInputV1::new(
        "signer-set-v1",
        root_epoch(),
        Vec::new(),
        signer_verifying_keys(),
        0,
    )
    .expect("preload input");
    let host = build_cloudflare_preloaded_signer_host_v1(
        1_000,
        Role::SignerA,
        preload,
        root_share_metadata(Role::SignerA),
        Vec::new(),
    )
    .expect("host without root-share wire");
    let err = evaluate_cloudflare_validated_mpc_prf_batch_output_v1(&host, &validated)
        .expect_err("missing root-share wire must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::MissingLocalBinding);
}

#[test]
fn cloudflare_proof_batch_helpers_build_recipient_proof_bundle_response() {
    let request = ecdsa_threshold_prf_request_with_reconstructed_transcript(2_000);
    let message_a =
        signer_private_request_with_reconstructed_transcript(WireMessageKindV1::RouterToSignerA);
    let message_b =
        signer_private_request_with_reconstructed_transcript(WireMessageKindV1::RouterToSignerB);
    let validated_a = validate_cloudflare_signer_private_request_plaintext_v1(
        CloudflareWorkerRoleV1::DeriverA,
        message_a,
        &signer_input_plaintext_bytes_for_request(Role::SignerA, &request),
        request_context_digest(&request),
        &root_share_metadata(Role::SignerA),
    )
    .expect("validated signer a request");
    let validated_b = validate_cloudflare_signer_private_request_plaintext_v1(
        CloudflareWorkerRoleV1::DeriverB,
        message_b,
        &signer_input_plaintext_bytes_for_request(Role::SignerB, &request),
        request_context_digest(&request),
        &root_share_metadata(Role::SignerB),
    )
    .expect("validated signer b request");
    let preload_a = CloudflareSignerHostPreloadInputV1::new(
        "signer-set-v1",
        root_epoch(),
        Vec::new(),
        signer_verifying_keys(),
        0,
    )
    .expect("preload a");
    let preload_b = CloudflareSignerHostPreloadInputV1::new(
        "signer-set-v1",
        root_epoch(),
        Vec::new(),
        signer_verifying_keys(),
        0,
    )
    .expect("preload b");
    let host_a = build_cloudflare_preloaded_signer_host_with_root_share_wire_v1(
        1_000,
        Role::SignerA,
        preload_a,
        root_share_metadata(Role::SignerA),
        root_share_wire(Role::SignerA),
        Vec::new(),
    )
    .expect("host a");
    let host_b = build_cloudflare_preloaded_signer_host_with_root_share_wire_v1(
        1_000,
        Role::SignerB,
        preload_b,
        root_share_metadata(Role::SignerB),
        root_share_wire(Role::SignerB),
        Vec::new(),
    )
    .expect("host b");
    let output_a = evaluate_cloudflare_validated_mpc_prf_batch_output_v1(&host_a, &validated_a)
        .expect("signer a output");
    let output_b = evaluate_cloudflare_validated_mpc_prf_batch_output_v1(&host_b, &validated_b)
        .expect("signer b output");
    let deriver_a_key = signer_peer_signing_key(Role::SignerA).to_bytes();
    let deriver_b_key = signer_peer_signing_key(Role::SignerB).to_bytes();
    let peer_a = build_cloudflare_ecdsa_threshold_prf_proof_batch_peer_message_v1(
        &deriver_a_key,
        signer_identity(Role::SignerA),
        signer_identity(Role::SignerB),
        output_a,
    )
    .expect("signer a peer proof batch");
    let peer_b = build_cloudflare_ecdsa_threshold_prf_proof_batch_peer_message_v1(
        &deriver_b_key,
        signer_identity(Role::SignerB),
        signer_identity(Role::SignerA),
        output_b,
    )
    .expect("signer b peer proof batch");

    let proof_a =
        decode_and_verify_cloudflare_ecdsa_threshold_prf_proof_batch_message_v1(&host_a, &peer_a)
            .expect("verified signer a proof batch");
    let proof_b =
        decode_and_verify_cloudflare_ecdsa_threshold_prf_proof_batch_message_v1(&host_a, &peer_b)
            .expect("verified signer b proof batch");
    assert_eq!(proof_a.from.role, Role::SignerA);
    assert_eq!(proof_b.from.role, Role::SignerB);

    let mut proof_bundle_encryptor = TestRecipientProofBundleEncryptor;
    let deriver_a_strict: CloudflareSignerRecipientProofBundleResponseV1 =
        cloudflare_recipient_proof_bundle_response_from_ab_proof_batch_v1(
            validated_a.router_payload(),
            proof_a.clone(),
            &mut proof_bundle_encryptor,
        )
        .expect("signer a strict proof-bundle response");
    let deriver_b_strict: CloudflareSignerRecipientProofBundleResponseV1 =
        cloudflare_recipient_proof_bundle_response_from_ab_proof_batch_v1(
            validated_b.router_payload(),
            proof_b.clone(),
            &mut proof_bundle_encryptor,
        )
        .expect("signer b strict proof-bundle response");
    deriver_a_strict
        .validate_for_router_payload(validated_a.router_payload())
        .expect("signer a strict response matches router payload");
    deriver_b_strict
        .validate_for_router_payload(validated_b.router_payload())
        .expect("signer b strict response matches router payload");

    let deriver_a_client = decode_recipient_proof_bundle_ciphertext_v1(
        deriver_a_strict.client_bundle.payload.as_bytes(),
    )
    .expect("signer a client proof-bundle envelope");
    assert_eq!(deriver_a_client.signer, signer_identity(Role::SignerA));
    assert_eq!(deriver_a_client.recipient_role, Role::Client);
    assert_eq!(
        deriver_a_client.recipient_identity,
        validated_a.router_payload().transcript_metadata().client_id
    );

    let router_strict = CloudflareRouterRecipientProofBundleResponseV1::new(
        CloudflareReplayReserveResponseV1::new("request-nonce-1", true).expect("replay"),
        CloudflareLifecyclePutReceiptV1::new("lifecycle-1", true).expect("lifecycle"),
        deriver_a_strict.client_bundle.clone(),
        deriver_b_strict.client_bundle.clone(),
    )
    .expect("strict router proof-bundle response");
    router_strict
        .validate_for_router_payload(validated_a.router_payload())
        .expect("strict router response matches router payload");

    let server_activation = CloudflareSigningWorkerRecipientProofBundleActivationV1::new(
        deriver_a_strict.server_bundle.clone(),
        deriver_b_strict.server_bundle.clone(),
    )
    .expect("strict SigningWorker proof-bundle activation");
    server_activation
        .validate_for_router_payload(validated_a.router_payload())
        .expect("strict SigningWorker activation matches router payload");

    let err = CloudflareRouterRecipientProofBundleResponseV1::new(
        CloudflareReplayReserveResponseV1::new("request-nonce-1", true).expect("replay"),
        CloudflareLifecyclePutReceiptV1::new("lifecycle-1", true).expect("lifecycle"),
        deriver_b_strict.client_bundle.clone(),
        deriver_a_strict.client_bundle.clone(),
    )
    .expect_err("swapped strict client bundles must fail");
    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidSignerIdentity);
}

#[test]
fn direct_recipient_proof_bundle_activation_delivery_accepts_single_server_bundle() {
    let activation = signing_worker_activation();
    let delivery = CloudflareSigningWorkerDirectRecipientProofBundleActivationDeliveryV1::new(
        activation.activation_context.clone(),
        Role::SignerA,
        activation.activation.deriver_a_bundle.clone(),
    )
    .expect("direct Deriver A activation delivery");

    assert_eq!(delivery.deriver_role, Role::SignerA);
    assert_eq!(
        delivery
            .transcript_digest()
            .expect("delivery transcript digest"),
        activation.activation_context.transcript_digest()
    );
}

#[test]
fn direct_recipient_proof_bundle_activation_delivery_builds_from_deriver_response() {
    let router_payload = router_payload_for_signing_worker_activation();
    let activation = signing_worker_activation();
    let response = CloudflareSignerRecipientProofBundleResponseV1::new(
        Role::SignerB,
        client_proof_bundle_wire(&router_payload, Role::SignerB, 0x62),
        server_proof_bundle_wire(&router_payload, Role::SignerB, 0x63),
    )
    .expect("strict Deriver B proof-bundle response");

    let delivery =
        CloudflareSigningWorkerDirectRecipientProofBundleActivationDeliveryV1::from_signer_response(
            activation.activation_context,
            response,
        )
        .expect("direct Deriver B activation delivery");

    assert_eq!(delivery.deriver_role, Role::SignerB);
}

#[test]
fn direct_recipient_proof_bundle_activation_delivery_rejects_client_bundle() {
    let router_payload = router_payload_for_signing_worker_activation();
    let activation = signing_worker_activation();
    let err = CloudflareSigningWorkerDirectRecipientProofBundleActivationDeliveryV1::new(
        activation.activation_context,
        Role::SignerA,
        client_proof_bundle_wire(&router_payload, Role::SignerA, 0x64),
    )
    .expect_err("direct activation delivery must reject client-recipient bundles");

    assert_eq!(
        err.code(),
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig
    );
}

#[test]
fn direct_recipient_proof_bundle_activation_delivery_rejects_wrong_deriver_role() {
    let activation = signing_worker_activation();
    let err = CloudflareSigningWorkerDirectRecipientProofBundleActivationDeliveryV1::new(
        activation.activation_context,
        Role::SignerB,
        activation.activation.deriver_a_bundle,
    )
    .expect_err("direct activation delivery role must match bundle signer");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidSignerIdentity);
}

#[test]
fn direct_recipient_proof_bundle_activation_delivery_rejects_wrong_context() {
    let activation = signing_worker_activation();
    let other_context =
        signing_worker_refresh_activation("direct-delivery-other", 0x70, 0x71).activation_context;
    let err = CloudflareSigningWorkerDirectRecipientProofBundleActivationDeliveryV1::new(
        other_context,
        Role::SignerA,
        activation.activation.deriver_a_bundle,
    )
    .expect_err("direct activation delivery must bind to its activation context");

    assert_eq!(
        err.code(),
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig
    );
}

#[test]
fn direct_recipient_proof_bundle_activation_aggregate_sorts_deriver_deliveries() {
    let activation = signing_worker_activation();
    let deriver_a_delivery =
        CloudflareSigningWorkerDirectRecipientProofBundleActivationDeliveryV1::new(
            activation.activation_context.clone(),
            Role::SignerA,
            activation.activation.deriver_a_bundle.clone(),
        )
        .expect("direct Deriver A activation delivery");
    let deriver_b_delivery =
        CloudflareSigningWorkerDirectRecipientProofBundleActivationDeliveryV1::new(
            activation.activation_context.clone(),
            Role::SignerB,
            activation.activation.deriver_b_server_bundle.clone(),
        )
        .expect("direct Deriver B activation delivery");

    let aggregate = CloudflareSigningWorkerDirectRecipientProofBundleActivationAggregateV1::new(
        deriver_b_delivery,
        deriver_a_delivery,
    )
    .expect("direct activation aggregate");
    let aggregate_request = aggregate
        .to_recipient_proof_bundle_activation_request()
        .expect("aggregate activation request");

    aggregate_request
        .validate()
        .expect("aggregate activation request validates");
    assert_eq!(aggregate.deriver_a_delivery.deriver_role, Role::SignerA);
    assert_eq!(aggregate.deriver_b_delivery.deriver_role, Role::SignerB);
    assert_eq!(
        aggregate_request.activation_context,
        activation.activation_context
    );
}

#[test]
fn direct_recipient_proof_bundle_activation_aggregate_rejects_duplicate_role() {
    let activation = signing_worker_activation();
    let first = CloudflareSigningWorkerDirectRecipientProofBundleActivationDeliveryV1::new(
        activation.activation_context.clone(),
        Role::SignerA,
        activation.activation.deriver_a_bundle.clone(),
    )
    .expect("first direct Deriver A activation delivery");
    let second = CloudflareSigningWorkerDirectRecipientProofBundleActivationDeliveryV1::new(
        activation.activation_context,
        Role::SignerA,
        activation.activation.deriver_a_bundle,
    )
    .expect("second direct Deriver A activation delivery");

    let err =
        CloudflareSigningWorkerDirectRecipientProofBundleActivationAggregateV1::new(first, second)
            .expect_err("direct activation aggregate must reject duplicate Deriver role");

    assert_eq!(
        err.code(),
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig
    );
}

#[test]
fn direct_recipient_proof_bundle_activation_aggregate_rejects_context_conflict() {
    let activation = signing_worker_activation();
    let other_activation = signing_worker_refresh_activation("direct-aggregate-other", 0x72, 0x73);
    let deriver_a_delivery =
        CloudflareSigningWorkerDirectRecipientProofBundleActivationDeliveryV1::new(
            activation.activation_context,
            Role::SignerA,
            activation.activation.deriver_a_bundle,
        )
        .expect("direct Deriver A activation delivery");
    let deriver_b_delivery =
        CloudflareSigningWorkerDirectRecipientProofBundleActivationDeliveryV1::new(
            other_activation.activation_context,
            Role::SignerB,
            other_activation.activation.deriver_b_server_bundle,
        )
        .expect("direct Deriver B activation delivery");

    let err = CloudflareSigningWorkerDirectRecipientProofBundleActivationAggregateV1::new(
        deriver_a_delivery,
        deriver_b_delivery,
    )
    .expect_err("direct activation aggregate must reject context drift");

    assert_eq!(
        err.code(),
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig
    );
}

#[test]
fn durable_object_handler_merges_direct_activation_deliveries() {
    let activation = signing_worker_activation();
    let router_payload = router_payload_for_signing_worker_activation();
    let deriver_a_delivery =
        CloudflareSigningWorkerDirectRecipientProofBundleActivationDeliveryV1::new(
            activation.activation_context.clone(),
            Role::SignerA,
            activation.activation.deriver_a_bundle.clone(),
        )
        .expect("direct Deriver A activation delivery");
    let deriver_b_delivery =
        CloudflareSigningWorkerDirectRecipientProofBundleActivationDeliveryV1::new(
            activation.activation_context.clone(),
            Role::SignerB,
            activation.activation.deriver_b_server_bundle.clone(),
        )
        .expect("direct Deriver B activation delivery");
    let deriver_a_call = CloudflareDurableObjectCallV1::new(
        CloudflareWorkerRoleV1::SigningWorker,
        server_output_binding(),
        CloudflareDurableObjectRequestV1::signing_worker_direct_activation_put(
            deriver_a_delivery.clone(),
        )
        .expect("Deriver A direct activation put request"),
    )
    .expect("Deriver A direct activation put call");
    let deriver_b_call = CloudflareDurableObjectCallV1::new(
        CloudflareWorkerRoleV1::SigningWorker,
        server_output_binding(),
        CloudflareDurableObjectRequestV1::signing_worker_direct_activation_put(
            deriver_b_delivery.clone(),
        )
        .expect("Deriver B direct activation put request"),
    )
    .expect("Deriver B direct activation put call");
    let mut storage = CloudflareDurableObjectMemoryStorageV1::new();

    let first = handle_cloudflare_durable_object_call_v1(&deriver_a_call, &mut storage)
        .expect("first direct activation delivery");
    let CloudflareDurableObjectResponseV1::SigningWorkerDirectActivationPut { outcome } = first
    else {
        panic!("first direct activation delivery must be pending");
    };
    let CloudflareSigningWorkerDirectRecipientProofBundleActivationPutOutcomeV1::Pending { record } =
        *outcome
    else {
        panic!("first direct activation delivery must be pending");
    };
    assert_eq!(record.received_deriver_role(), Role::SignerA);
    assert_eq!(record.waiting_for_deriver_role(), Role::SignerB);
    assert_eq!(
        storage.signing_worker_direct_activation(&deriver_a_call.storage_key()),
        Some(record.as_ref())
    );

    let second = handle_cloudflare_durable_object_call_v1(&deriver_b_call, &mut storage)
        .expect("second direct activation delivery");
    let CloudflareDurableObjectResponseV1::SigningWorkerDirectActivationPut { outcome } = second
    else {
        panic!("second direct activation delivery must be ready");
    };
    let CloudflareSigningWorkerDirectRecipientProofBundleActivationPutOutcomeV1::Ready {
        aggregate,
    } = *outcome
    else {
        panic!("second direct activation delivery must be ready");
    };
    assert_eq!(aggregate.deriver_a_delivery, deriver_a_delivery);
    assert_eq!(aggregate.deriver_b_delivery, deriver_b_delivery.clone());

    let duplicate = handle_cloudflare_durable_object_call_v1(&deriver_b_call, &mut storage)
        .expect("duplicate peer direct activation delivery");
    let CloudflareDurableObjectResponseV1::SigningWorkerDirectActivationPut { outcome } = duplicate
    else {
        panic!("duplicate direct activation delivery returned wrong response branch");
    };
    assert!(matches!(
        outcome.as_ref(),
        CloudflareSigningWorkerDirectRecipientProofBundleActivationPutOutcomeV1::Ready { .. }
    ));

    let conflicting_a_delivery =
        CloudflareSigningWorkerDirectRecipientProofBundleActivationDeliveryV1::new(
            activation.activation_context,
            Role::SignerA,
            server_proof_bundle_wire(&router_payload, Role::SignerA, 0x99),
        )
        .expect("conflicting Deriver A direct activation delivery");
    let conflicting_a_call = CloudflareDurableObjectCallV1::new(
        CloudflareWorkerRoleV1::SigningWorker,
        server_output_binding(),
        CloudflareDurableObjectRequestV1::signing_worker_direct_activation_put(
            conflicting_a_delivery,
        )
        .expect("conflicting Deriver A direct activation put request"),
    )
    .expect("conflicting Deriver A direct activation put call");
    let err = handle_cloudflare_durable_object_call_v1(&conflicting_a_call, &mut storage)
        .expect_err("conflicting same-role direct activation delivery must fail");
    assert_eq!(
        err.code(),
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig
    );
}

#[test]
fn cloudflare_peer_signing_key_binding_matches_validated_request_identity() {
    let request = ecdsa_threshold_prf_request_with_reconstructed_transcript(2_000);
    let message =
        signer_private_request_with_reconstructed_transcript(WireMessageKindV1::RouterToSignerA);
    let validated = validate_cloudflare_signer_private_request_plaintext_v1(
        CloudflareWorkerRoleV1::DeriverA,
        message,
        &signer_input_plaintext_bytes_for_request(Role::SignerA, &request),
        request_context_digest(&request),
        &root_share_metadata(Role::SignerA),
    )
    .expect("validated signer a request");

    let signer = validate_cloudflare_peer_signing_key_matches_request_v1(
        CloudflareWorkerRoleV1::DeriverA,
        &deriver_a_peer_signing_key(),
        &validated,
    )
    .expect("matched signer key");

    assert_eq!(signer, signer_identity(Role::SignerA));
}

#[test]
fn cloudflare_peer_signing_key_binding_rejects_wrong_role_key() {
    let request = ecdsa_threshold_prf_request_with_reconstructed_transcript(2_000);
    let message =
        signer_private_request_with_reconstructed_transcript(WireMessageKindV1::RouterToSignerA);
    let validated = validate_cloudflare_signer_private_request_plaintext_v1(
        CloudflareWorkerRoleV1::DeriverA,
        message,
        &signer_input_plaintext_bytes_for_request(Role::SignerA, &request),
        request_context_digest(&request),
        &root_share_metadata(Role::SignerA),
    )
    .expect("validated signer a request");

    let err = validate_cloudflare_peer_signing_key_matches_request_v1(
        CloudflareWorkerRoleV1::DeriverA,
        &deriver_b_peer_signing_key(),
        &validated,
    )
    .unwrap_err();

    assert_eq!(err.code(), RouterAbProtocolErrorCode::ForbiddenLocalBinding);
}

#[test]
fn cloudflare_peer_signing_key_binding_rejects_stale_epoch() {
    let request = ecdsa_threshold_prf_request_with_reconstructed_transcript(2_000);
    let message =
        signer_private_request_with_reconstructed_transcript(WireMessageKindV1::RouterToSignerA);
    let validated = validate_cloudflare_signer_private_request_plaintext_v1(
        CloudflareWorkerRoleV1::DeriverA,
        message,
        &signer_input_plaintext_bytes_for_request(Role::SignerA, &request),
        request_context_digest(&request),
        &root_share_metadata(Role::SignerA),
    )
    .expect("validated signer a request");
    let stale_key = CloudflareSignerPeerSigningKeyBindingV1::new(
        Role::SignerA,
        "DERIVER_A_PEER_SIGNING_KEY",
        "stale-key-epoch-a",
    )
    .expect("stale signer a peer signing key");

    let err = validate_cloudflare_peer_signing_key_matches_request_v1(
        CloudflareWorkerRoleV1::DeriverA,
        &stale_key,
        &validated,
    )
    .unwrap_err();

    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidSignerIdentity);
}

#[test]
fn cloudflare_peer_signing_key_binding_rejects_mismatched_worker_role_argument() {
    let request = ecdsa_threshold_prf_request_with_reconstructed_transcript(2_000);
    let message =
        signer_private_request_with_reconstructed_transcript(WireMessageKindV1::RouterToSignerA);
    let validated = validate_cloudflare_signer_private_request_plaintext_v1(
        CloudflareWorkerRoleV1::DeriverA,
        message,
        &signer_input_plaintext_bytes_for_request(Role::SignerA, &request),
        request_context_digest(&request),
        &root_share_metadata(Role::SignerA),
    )
    .expect("validated signer a request");

    let err = validate_cloudflare_peer_signing_key_matches_request_v1(
        CloudflareWorkerRoleV1::DeriverB,
        &deriver_b_peer_signing_key(),
        &validated,
    )
    .unwrap_err();

    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidRole);
}

#[test]
fn cloudflare_validated_mpc_prf_handler_returns_signer_responses_for_a_and_b() {
    let request = ecdsa_threshold_prf_request_with_reconstructed_transcript(2_000);
    let message_a =
        signer_private_request_with_reconstructed_transcript(WireMessageKindV1::RouterToSignerA);
    let message_b =
        signer_private_request_with_reconstructed_transcript(WireMessageKindV1::RouterToSignerB);
    let validated_a = validate_cloudflare_signer_private_request_plaintext_v1(
        CloudflareWorkerRoleV1::DeriverA,
        message_a,
        &signer_input_plaintext_bytes_for_request(Role::SignerA, &request),
        request_context_digest(&request),
        &root_share_metadata(Role::SignerA),
    )
    .expect("validated signer a request");
    let validated_b = validate_cloudflare_signer_private_request_plaintext_v1(
        CloudflareWorkerRoleV1::DeriverB,
        message_b,
        &signer_input_plaintext_bytes_for_request(Role::SignerB, &request),
        request_context_digest(&request),
        &root_share_metadata(Role::SignerB),
    )
    .expect("validated signer b request");
    let base_host_a = build_cloudflare_preloaded_signer_host_with_root_share_wire_v1(
        1_000,
        Role::SignerA,
        CloudflareSignerHostPreloadInputV1::new(
            "signer-set-v1",
            root_epoch(),
            Vec::new(),
            signer_verifying_keys(),
            0,
        )
        .expect("base preload a"),
        root_share_metadata(Role::SignerA),
        root_share_wire(Role::SignerA),
        Vec::new(),
    )
    .expect("base host a");
    let base_host_b = build_cloudflare_preloaded_signer_host_with_root_share_wire_v1(
        1_000,
        Role::SignerB,
        CloudflareSignerHostPreloadInputV1::new(
            "signer-set-v1",
            root_epoch(),
            Vec::new(),
            signer_verifying_keys(),
            0,
        )
        .expect("base preload b"),
        root_share_metadata(Role::SignerB),
        root_share_wire(Role::SignerB),
        Vec::new(),
    )
    .expect("base host b");
    let deriver_a_key = signer_peer_signing_key(Role::SignerA).to_bytes();
    let deriver_b_key = signer_peer_signing_key(Role::SignerB).to_bytes();

    let mut proof_bundle_encryptor_a = TestRecipientProofBundleEncryptor;
    let mut proof_bundle_encryptor_b = TestRecipientProofBundleEncryptor;
    let strict_response_a =
        handle_cloudflare_validated_mpc_prf_recipient_proof_bundle_signer_request_v1(
            &base_host_a,
            &deriver_a_key,
            &validated_a,
            &mut proof_bundle_encryptor_a,
        )
        .expect("strict signer a proof-bundle response");
    let strict_response_b =
        handle_cloudflare_validated_mpc_prf_recipient_proof_bundle_signer_request_v1(
            &base_host_b,
            &deriver_b_key,
            &validated_b,
            &mut proof_bundle_encryptor_b,
        )
        .expect("strict signer b proof-bundle response");
    validate_cloudflare_signer_recipient_proof_bundle_private_response_v1(
        CloudflareWorkerRoleV1::DeriverA,
        validated_a.message(),
        &strict_response_a,
    )
    .expect("strict signer a response validates");
    validate_cloudflare_signer_recipient_proof_bundle_private_response_v1(
        CloudflareWorkerRoleV1::DeriverB,
        validated_b.message(),
        &strict_response_b,
    )
    .expect("strict signer b response validates");

    let strict_private_response =
        handle_cloudflare_signer_recipient_proof_bundle_private_request_v1(
            CloudflareWorkerRoleV1::DeriverA,
            &TestRecipientProofBundleWireHandler {
                response: strict_response_a.clone(),
            },
            validated_a.message().clone(),
        )
        .expect("strict private signer handler response");
    assert_eq!(strict_private_response.signer_role, Role::SignerA);

    let wrong_strict_response =
        validate_cloudflare_signer_recipient_proof_bundle_private_response_v1(
            CloudflareWorkerRoleV1::DeriverA,
            validated_a.message(),
            &strict_response_b,
        )
        .expect_err("strict response from wrong signer must fail");
    assert_eq!(
        wrong_strict_response.code(),
        RouterAbProtocolErrorCode::InvalidSignerIdentity
    );

    let strict_router_response = CloudflareRouterRecipientProofBundleResponseV1::new(
        CloudflareReplayReserveResponseV1::new("request-nonce-1", true).expect("replay"),
        CloudflareLifecyclePutReceiptV1::new("lifecycle-1", true).expect("lifecycle"),
        strict_response_a.client_bundle.clone(),
        strict_response_b.client_bundle.clone(),
    )
    .expect("strict router response");
    strict_router_response
        .validate_for_router_payload(validated_a.router_payload())
        .expect("strict router response validates");

    let activation_request = CloudflareSigningWorkerRecipientProofBundleActivationRequestV1::new(
        validated_a.router_payload().clone(),
        CloudflareSigningWorkerRecipientProofBundleActivationV1::new(
            strict_response_a.server_bundle.clone(),
            strict_response_b.server_bundle.clone(),
        )
        .expect("strict SigningWorker activation"),
    )
    .expect("strict SigningWorker activation request");
    let expected_active_signing_worker_state =
        active_signing_worker_state_for_activation(&activation_request, "test-server-material");
    let activation_receipt =
        handle_cloudflare_deriver_a_recipient_proof_bundle_activation_request_v1(
            activation_request,
            "test-server-material",
            TEST_ACTIVATED_AT_MS,
        )
        .expect("strict SigningWorker activation receipt");
    assert_eq!(activation_receipt.signing_worker_id, "server-a");
    assert_eq!(
        activation_receipt.transcript_digest,
        validated_a.router_payload().transcript_digest()
    );
    assert_eq!(
        activation_receipt.active_signing_worker_state,
        expected_active_signing_worker_state
    );
}

#[test]
fn router_ab_ecdsa_derivation_activation_material_derives_context_bound_public_identity() {
    let activation = router_ab_ecdsa_derivation_activation_request();
    let material = router_ab_ecdsa_derivation_server_material_record(&activation);

    let identity =
        cloudflare_router_ab_ecdsa_derivation_public_identity_from_activation_material_v1(
            &activation.registration,
            &material,
        )
        .expect("Router A/B ECDSA derivation public identity");

    identity
        .validate_for_context(&activation.registration.context)
        .expect("identity must validate against core Router A/B ECDSA derivation context");
    assert_eq!(
        identity.context_binding_b64u,
        b64u(
            activation
                .registration
                .context
                .context_binding_digest()
                .expect("context binding")
                .as_bytes()
        )
    );
    assert_eq!(
        identity.derivation_client_share_public_key33_b64u,
        activation
            .registration
            .derivation_client_share_public_key33_b64u
    );

    let receipt = cloudflare_router_ab_ecdsa_derivation_activation_receipt_from_material_v1(
        &activation,
        &material,
        TEST_ACTIVATED_AT_MS,
    )
    .expect("Router A/B ECDSA derivation activation receipt");
    receipt.validate().expect("activation receipt validates");
    assert_eq!(receipt.public_identity, identity);
    assert_eq!(
        receipt.signing_worker,
        activation.activation_context.signer_set().selected_server
    );
}

#[test]
fn router_ab_ecdsa_derivation_activation_refresh_receipt_preserves_identity_for_next_epoch() {
    let refresh = router_ab_ecdsa_derivation_activation_refresh_request();
    let material = router_ab_ecdsa_derivation_refresh_server_material_record(&refresh, 0x5a);

    let receipt =
        cloudflare_router_ab_ecdsa_derivation_activation_refresh_receipt_from_material_v1(
            &refresh,
            &material,
            TEST_ACTIVATED_AT_MS + 1,
        )
        .expect("Router A/B ECDSA derivation activation-refresh receipt");
    receipt
        .validate()
        .expect("activation-refresh receipt validates");
    assert_eq!(receipt.context, refresh.refresh_request.context);
    assert_eq!(
        receipt.public_identity,
        refresh.refresh_request.public_identity
    );
    assert_eq!(
        receipt.signing_worker,
        refresh.activation_context.signer_set().selected_server
    );
    assert_eq!(
        receipt.activation_epoch,
        refresh.refresh_request.next_activation_epoch
    );

    let scope =
        cloudflare_router_ab_ecdsa_derivation_normal_signing_scope_from_activation_receipt_v1(
            &receipt,
            ROUTER_AB_ECDSA_DERIVATION_WALLET_KEY_ID,
            ROUTER_AB_ECDSA_DERIVATION_WALLET_ID,
            ROUTER_AB_ECDSA_DERIVATION_THRESHOLD_KEY_ID,
            ROUTER_AB_ECDSA_DERIVATION_SIGNING_ROOT_ID,
            ROUTER_AB_ECDSA_DERIVATION_SIGNING_ROOT_VERSION,
        )
        .expect("refreshed Router A/B ECDSA derivation normal-signing scope");
    let active_state = cloudflare_active_signing_worker_state_from_activation_request_v1(
        &refresh
            .to_recipient_proof_bundle_activation_request()
            .expect("generic refresh activation request"),
        "router-ab-ecdsa-derivation-refresh-material",
        TEST_ACTIVATED_AT_MS + 1,
    )
    .expect("refreshed active SigningWorker state");
    validate_cloudflare_router_ab_ecdsa_derivation_normal_signing_active_material_v1(
        &scope,
        &active_state,
        &material,
    )
    .expect("refreshed active material preserves public identity");
}

#[test]
fn router_ab_ecdsa_derivation_activation_refresh_receipt_rejects_public_identity_drift() {
    let refresh = router_ab_ecdsa_derivation_activation_refresh_request();
    let drifted_material =
        router_ab_ecdsa_derivation_refresh_server_material_record(&refresh, 0x5b);

    let err = cloudflare_router_ab_ecdsa_derivation_activation_refresh_receipt_from_material_v1(
        &refresh,
        &drifted_material,
        TEST_ACTIVATED_AT_MS + 1,
    )
    .expect_err("refresh material drift must fail");
    assert_eq!(
        err.code(),
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig
    );
}

#[test]
fn router_ab_ecdsa_derivation_activation_refresh_public_admission_response_validates_receipt() {
    let refresh = router_ab_ecdsa_derivation_activation_refresh_request();
    let material = router_ab_ecdsa_derivation_refresh_server_material_record(&refresh, 0x5a);
    let receipt =
        cloudflare_router_ab_ecdsa_derivation_activation_refresh_receipt_from_material_v1(
            &refresh,
            &material,
            TEST_ACTIVATED_AT_MS + 1,
        )
        .expect("Router A/B ECDSA derivation activation-refresh receipt");
    let signing_worker_output = CloudflareSigningWorkerOutputActivationReceiptV1::new(
        refresh.refresh_request.lifecycle.lifecycle_id.clone(),
        refresh
            .activation_context
            .signer_set()
            .selected_server
            .server_id
            .clone(),
        refresh.activation_context.transcript_digest(),
        cloudflare_active_signing_worker_state_from_activation_request_v1(
            &refresh
                .to_recipient_proof_bundle_activation_request()
                .expect("generic refresh activation request"),
            "router-ab-ecdsa-derivation-refresh-material",
            TEST_ACTIVATED_AT_MS + 1,
        )
        .expect("refreshed active SigningWorker state"),
        true,
    )
    .expect("SigningWorker output activation receipt");
    let signing_worker_activation =
        CloudflareRouterAbEcdsaDerivationSigningWorkerActivationReceiptV1::new(
            receipt,
            signing_worker_output,
        )
        .expect("Router A/B ECDSA derivation SigningWorker activation-refresh receipt");
    let public_request = refresh
        .refresh_request
        .to_threshold_prf_request()
        .expect("refresh public request");
    let (deriver_a_message, _) = public_request
        .to_signer_wire_messages()
        .expect("refresh signer messages");
    let router_payload = decode_router_to_signer_payload_v1(deriver_a_message.payload.as_bytes())
        .expect("refresh Router payload");
    let response = CloudflareRouterRecipientProofBundleResponseV1::new(
        CloudflareReplayReserveResponseV1::new(&refresh.refresh_request.refresh_nonce, true)
            .expect("refresh replay"),
        CloudflareLifecyclePutReceiptV1::new(&refresh.refresh_request.lifecycle.lifecycle_id, true)
            .expect("refresh lifecycle"),
        client_proof_bundle_wire(&router_payload, Role::SignerA, 0x61),
        client_proof_bundle_wire(&router_payload, Role::SignerB, 0x62),
    )
    .expect("refresh public Router response");

    let admission =
        CloudflareRouterAbEcdsaDerivationActivationRefreshAdmissionResponseV1::forwarded(
            response,
            signing_worker_activation,
        )
        .expect("refresh public admission response");
    admission
        .validate()
        .expect("refresh public admission validates");
}

#[test]
fn router_ab_ecdsa_derivation_normal_signing_scope_binds_active_material_to_identity() {
    let activation = router_ab_ecdsa_derivation_activation_request();
    let material = router_ab_ecdsa_derivation_server_material_record(&activation);
    let receipt = cloudflare_router_ab_ecdsa_derivation_activation_receipt_from_material_v1(
        &activation,
        &material,
        TEST_ACTIVATED_AT_MS,
    )
    .expect("Router A/B ECDSA derivation activation receipt");
    let scope =
        cloudflare_router_ab_ecdsa_derivation_normal_signing_scope_from_activation_receipt_v1(
            &receipt,
            ROUTER_AB_ECDSA_DERIVATION_WALLET_KEY_ID,
            ROUTER_AB_ECDSA_DERIVATION_WALLET_ID,
            ROUTER_AB_ECDSA_DERIVATION_THRESHOLD_KEY_ID,
            ROUTER_AB_ECDSA_DERIVATION_SIGNING_ROOT_ID,
            ROUTER_AB_ECDSA_DERIVATION_SIGNING_ROOT_VERSION,
        )
        .expect("Router A/B ECDSA derivation normal-signing scope");
    let active_state = cloudflare_active_signing_worker_state_from_activation_request_v1(
        &activation
            .to_recipient_proof_bundle_activation_request()
            .expect("generic activation request"),
        "router-ab-ecdsa-derivation-material",
        TEST_ACTIVATED_AT_MS,
    )
    .expect("Router A/B ECDSA derivation active state");
    let lookup =
        CloudflareActiveSigningWorkerStateLookupV1::from_router_ab_ecdsa_derivation_normal_signing_scope(&scope)
            .expect("Router A/B ECDSA derivation active-state lookup");

    assert_eq!(
        active_state.session_id,
        router_ab_ecdsa_derivation_active_state_session_id(&root_epoch())
    );
    assert_eq!(lookup.session_id, active_state.session_id);
    lookup
        .validate_active_state(&active_state)
        .expect("Router A/B ECDSA derivation lookup matches active state");
    let derived_identity =
        cloudflare_router_ab_ecdsa_derivation_public_identity_from_normal_signing_material_v1(
            &scope, &material,
        )
        .expect("Router A/B ECDSA derivation normal-signing identity");
    assert_eq!(derived_identity, scope.public_identity);
    validate_cloudflare_router_ab_ecdsa_derivation_normal_signing_active_material_v1(
        &scope,
        &active_state,
        &material,
    )
    .expect("Router A/B ECDSA derivation normal-signing active material validates");
}

struct TestRouterAbEcdsaDerivationEvmDigestFinalizeHandler;

impl CloudflareSigningWorkerRouterAbEcdsaDerivationEvmDigestFinalizeHandlerV1
    for TestRouterAbEcdsaDerivationEvmDigestFinalizeHandler
{
    fn handle_router_ab_ecdsa_derivation_evm_digest_finalize_request_v1(
        &self,
        request: CloudflareSigningWorkerMaterializedRouterAbEcdsaDerivationEvmDigestFinalizeRequestV1,
    ) -> RouterAbProtocolResult<RouterAbEcdsaDerivationEvmDigestSigningResponseV1> {
        request.validate()?;
        assert_eq!(
            request.server_presignature.server_presignature_id,
            request.request.request.server_presignature_id
        );
        RouterAbEcdsaDerivationEvmDigestSigningResponseV1::new_for_request(
            &request.prepare_request()?,
            b64u(&[0x99; 65]),
        )
    }
}

#[test]
fn router_ab_ecdsa_derivation_wallet_session_builds_prepare_admission_candidate() {
    let request = router_ab_ecdsa_derivation_digest_signing_request();
    let wallet_session = router_ab_ecdsa_derivation_wallet_session(&request);

    wallet_session
        .validate_for_router_ab_ecdsa_derivation_evm_digest_signing_request_v1(
            &request,
            TEST_ACTIVATED_AT_MS + 1,
        )
        .expect("Wallet Session authorizes Router A/B ECDSA derivation prepare request");
    let admission =
        CloudflareRouterAbEcdsaDerivationEvmDigestPrepareAdmissionCandidateV1::from_prepare_request(
            &wallet_session,
            &request,
            TEST_ACTIVATED_AT_MS + 1,
        )
        .expect("Router A/B ECDSA derivation prepare admission candidate");
    let store_request = admission
        .to_normal_signing_admission_store_request(&request, TEST_ACTIVATED_AT_MS + 1)
        .expect("Router A/B ECDSA derivation admission store request");

    assert_eq!(admission.account_id, request.scope.wallet_id);
    assert_eq!(
        admission.threshold_session_id,
        request
            .scope
            .active_state_session_id()
            .expect("Router A/B ECDSA derivation active session id")
    );
    assert_eq!(
        admission.signing_worker_id,
        request.scope.signing_worker.server_id
    );
    assert_eq!(
        admission.request_digest,
        request.request_digest().expect("request digest")
    );
    assert_eq!(
        admission.client_presignature_id,
        request.client_presignature_id
    );
    assert_eq!(
        admission.signing_digest,
        request.signing_digest().expect("signing digest")
    );
    assert_eq!(store_request.intent_digest, admission.request_digest);
    assert_eq!(store_request.request_digest, admission.request_digest);
}

#[test]
fn router_ab_ecdsa_derivation_wallet_session_builds_finalize_admission_candidate() {
    let request = router_ab_ecdsa_derivation_digest_signing_finalize_request();
    let prepare_request = request.prepare_request().expect("prepare request");
    let wallet_session = router_ab_ecdsa_derivation_wallet_session(&prepare_request);

    wallet_session
        .validate_for_router_ab_ecdsa_derivation_evm_digest_finalize_request_v1(
            &request,
            TEST_ACTIVATED_AT_MS + 1,
        )
        .expect("Wallet Session authorizes Router A/B ECDSA derivation finalize request");
    let admission =
        CloudflareRouterAbEcdsaDerivationEvmDigestFinalizeAdmissionCandidateV1::from_finalize_request(
            &wallet_session,
            &request,
            TEST_ACTIVATED_AT_MS + 1,
        )
        .expect("Router A/B ECDSA derivation finalize admission candidate");
    let store_request = admission
        .to_normal_signing_admission_store_request(&request, TEST_ACTIVATED_AT_MS + 1)
        .expect("Router A/B ECDSA derivation finalize admission store request");

    assert_eq!(admission.account_id, request.scope.wallet_id);
    assert_eq!(
        admission.threshold_session_id,
        request
            .scope
            .active_state_session_id()
            .expect("Router A/B ECDSA derivation finalize active session id")
    );
    assert_eq!(
        admission.finalize_request_digest,
        request.request_digest().expect("finalize request digest")
    );
    assert_eq!(
        admission.prepare_request_digest,
        request
            .prepare_request_digest()
            .expect("prepare request digest")
    );
    assert_eq!(admission.server_presignature_id, "server-presignature-1");
    assert_eq!(
        store_request.intent_digest,
        admission.prepare_request_digest
    );
    assert_eq!(
        store_request.request_digest,
        admission.finalize_request_digest
    );
    assert_eq!(
        store_request.metadata.intent_digest,
        admission.finalize_request_digest
    );
}

#[test]
fn router_ab_ecdsa_derivation_wallet_session_rejects_scope_mismatch() {
    let request = router_ab_ecdsa_derivation_digest_signing_request();
    let mut wallet_session = router_ab_ecdsa_derivation_wallet_session(&request);
    wallet_session.account_id = "different-wallet".to_owned();

    let err = wallet_session
        .validate_for_router_ab_ecdsa_derivation_evm_digest_signing_request_v1(
            &request,
            TEST_ACTIVATED_AT_MS + 1,
        )
        .expect_err("scope mismatch rejects");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidGateDecision);
}

#[test]
fn router_ab_ecdsa_derivation_admitted_request_rejects_trusted_admission_drift() {
    let request = router_ab_ecdsa_derivation_digest_signing_request();
    let mut trusted_admission = router_ab_ecdsa_derivation_trusted_admission(&request);
    trusted_admission.metadata.intent_digest = digest(0x55);

    let err = CloudflareSigningWorkerAdmittedRouterAbEcdsaDerivationEvmDigestSigningRequestV1::new(
        request,
        trusted_admission,
    )
    .expect_err("trusted admission drift rejects");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidGateDecision);
}

#[test]
fn router_ab_ecdsa_derivation_admitted_finalize_request_rejects_trusted_admission_drift() {
    let request = router_ab_ecdsa_derivation_digest_signing_finalize_request();
    let mut trusted_admission = router_ab_ecdsa_derivation_finalize_trusted_admission(&request);
    trusted_admission.metadata.intent_digest = request
        .prepare_request_digest()
        .expect("prepare request digest");

    let err =
        CloudflareSigningWorkerAdmittedRouterAbEcdsaDerivationEvmDigestFinalizeRequestV1::new(
            request,
            trusted_admission,
        )
        .expect_err("finalize trusted admission drift rejects");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidGateDecision);
}

#[test]
fn router_ab_ecdsa_derivation_normal_signing_request_materializes_from_active_state() {
    let activation = router_ab_ecdsa_derivation_activation_request();
    let material = router_ab_ecdsa_derivation_server_material_record(&activation);
    let receipt = cloudflare_router_ab_ecdsa_derivation_activation_receipt_from_material_v1(
        &activation,
        &material,
        TEST_ACTIVATED_AT_MS,
    )
    .expect("Router A/B ECDSA derivation activation receipt");
    let scope =
        cloudflare_router_ab_ecdsa_derivation_normal_signing_scope_from_activation_receipt_v1(
            &receipt,
            ROUTER_AB_ECDSA_DERIVATION_WALLET_KEY_ID,
            ROUTER_AB_ECDSA_DERIVATION_WALLET_ID,
            ROUTER_AB_ECDSA_DERIVATION_THRESHOLD_KEY_ID,
            ROUTER_AB_ECDSA_DERIVATION_SIGNING_ROOT_ID,
            ROUTER_AB_ECDSA_DERIVATION_SIGNING_ROOT_VERSION,
        )
        .expect("Router A/B ECDSA derivation normal-signing scope");
    let active_state = cloudflare_active_signing_worker_state_from_activation_request_v1(
        &activation
            .to_recipient_proof_bundle_activation_request()
            .expect("generic activation request"),
        "router-ab-ecdsa-derivation-material",
        TEST_ACTIVATED_AT_MS,
    )
    .expect("Router A/B ECDSA derivation active state");
    let request = RouterAbEcdsaDerivationEvmDigestSigningRequestV1::new(
        scope,
        "router-ab-ecdsa-derivation-sign-request-1",
        "server-presignature-1",
        2_000,
        b64u(&[0x77; 32]),
    )
    .expect("Router A/B ECDSA derivation normal-signing request");
    let admitted = admitted_router_ab_ecdsa_derivation_digest_signing_request(request);
    let materialized =
        CloudflareSigningWorkerMaterializedRouterAbEcdsaDerivationEvmDigestSigningRequestV1::new(
            admitted,
            active_state,
            material,
            TEST_ACTIVATED_AT_MS + 1,
        )
        .expect("materialized Router A/B ECDSA derivation normal-signing request");

    assert_eq!(
        materialized
            .request
            .request
            .signing_digest()
            .expect("signing digest"),
        PublicDigest32::new([0x77; 32])
    );
}

#[test]
fn router_ab_ecdsa_derivation_evm_digest_prepare_from_pool_binds_selected_presignature() {
    let activation = router_ab_ecdsa_derivation_activation_request();
    let material = router_ab_ecdsa_derivation_server_material_record(&activation);
    let request = router_ab_ecdsa_derivation_digest_signing_request();
    let admitted = admitted_router_ab_ecdsa_derivation_digest_signing_request(request.clone());
    let materialized =
        CloudflareSigningWorkerMaterializedRouterAbEcdsaDerivationEvmDigestSigningRequestV1::new(
            admitted,
            active_signing_worker_state_for_router_ab_ecdsa_derivation(),
            material,
            TEST_ACTIVATED_AT_MS + 1,
        )
        .expect("materialized Router A/B ECDSA derivation prepare request");
    let pool_record = router_ab_ecdsa_derivation_presignature_pool_record();

    let prepared = prepare_cloudflare_role_separated_router_ab_ecdsa_derivation_evm_digest_from_pool_record_v1(
        materialized,
        pool_record.clone(),
        b64u(&[0x55; 32]),
    )
    .expect("pool-backed Router A/B ECDSA derivation prepared bundle");

    prepared
        .response
        .validate_for_request(&request)
        .expect("pool-backed response binds request");
    assert_eq!(
        prepared.response.server_presignature_id,
        request.client_presignature_id
    );
    assert_eq!(
        prepared.record.server_presignature_id,
        request.client_presignature_id
    );
    assert_eq!(
        prepared.record.server_k_share32_b64u,
        pool_record.server_k_share32_b64u
    );
    assert_eq!(
        prepared.record.server_sigma_share32_b64u,
        pool_record.server_sigma_share32_b64u
    );
    assert_eq!(
        prepared.record.request_digest,
        request.request_digest().expect("request digest")
    );
    assert_eq!(
        prepared.record.admitted_signing_digest,
        request.signing_digest().expect("signing digest")
    );
    let public_json = serde_json::to_string(&prepared.response).expect("public response JSON");
    assert!(!public_json.contains("server_k_share32_b64u"));
    assert!(!public_json.contains("server_sigma_share32_b64u"));
}

#[test]
fn router_ab_ecdsa_derivation_presignature_pool_put_request_materializes_active_pool_record() {
    let request = router_ab_ecdsa_derivation_presignature_pool_put_request(2_000);

    let record = request
        .to_pool_record(
            active_signing_worker_state_for_router_ab_ecdsa_derivation(),
            1_500,
        )
        .expect("pool put request materializes");

    assert_eq!(record.server_presignature_id, "server-presignature-1");
    assert_eq!(
        record.active_signing_worker_state,
        active_signing_worker_state_for_router_ab_ecdsa_derivation()
    );
    assert_eq!(record.server_big_r33_b64u, request.server_big_r33_b64u);
    assert_eq!(record.server_k_share32_b64u, request.server_k_share32_b64u);
    assert_eq!(
        record.server_sigma_share32_b64u,
        request.server_sigma_share32_b64u
    );
    assert_eq!(record.created_at_ms, 1_500);
    assert_eq!(record.expires_at_ms, 2_000);
}

#[test]
fn router_ab_ecdsa_derivation_presignature_pool_put_request_rejects_expired_or_mismatched_state() {
    let request = router_ab_ecdsa_derivation_presignature_pool_put_request(1_500);
    let expired = request
        .to_pool_record(
            active_signing_worker_state_for_router_ab_ecdsa_derivation(),
            1_500,
        )
        .expect_err("exact expiry must fail");
    assert_eq!(
        expired.code(),
        RouterAbProtocolErrorCode::ExpiredLocalRequest
    );

    let valid_request = router_ab_ecdsa_derivation_presignature_pool_put_request(2_000);
    let mut mismatched_state = active_signing_worker_state_for_router_ab_ecdsa_derivation();
    mismatched_state.signing_worker.server_id = "server-other".to_owned();
    let mismatched = valid_request
        .to_pool_record(mismatched_state, 1_500)
        .expect_err("scope and active state mismatch must fail");
    assert_eq!(
        mismatched.code(),
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig
    );
}

#[test]
fn router_ab_ecdsa_derivation_prepared_bundle_rejects_private_record_drift() {
    let activation = router_ab_ecdsa_derivation_activation_request();
    let material = router_ab_ecdsa_derivation_server_material_record(&activation);
    let request = router_ab_ecdsa_derivation_digest_signing_request();
    let admitted = admitted_router_ab_ecdsa_derivation_digest_signing_request(request.clone());
    let materialized =
        CloudflareSigningWorkerMaterializedRouterAbEcdsaDerivationEvmDigestSigningRequestV1::new(
            admitted,
            active_signing_worker_state_for_router_ab_ecdsa_derivation(),
            material,
            TEST_ACTIVATED_AT_MS + 1,
        )
        .expect("materialized Router A/B ECDSA derivation prepare request");
    let response = RouterAbEcdsaDerivationEvmDigestSigningPrepareResponseV1::new_for_request(
        &request,
        request.client_presignature_id.clone(),
        b64u(&router_ab_ecdsa_derivation_presignature_big_r33(0x42)),
        b64u(&[0x55; 32]),
        TEST_ACTIVATED_AT_MS + 1,
    )
    .expect("prepare response");
    let record = CloudflareSigningWorkerEcdsaPresignatureRecordV1::new(
        active_signing_worker_state_for_router_ab_ecdsa_derivation(),
        request.client_presignature_id.clone(),
        digest(0x91),
        request.signing_digest().expect("signing digest"),
        b64u(&router_ab_ecdsa_derivation_presignature_big_r33(0x42)),
        b64u(&[0x55; 32]),
        b64u(&[0x33; 32]),
        b64u(&[0x44; 32]),
        TEST_ACTIVATED_AT_MS + 1,
        request.expires_at_ms,
    )
    .expect("drifted presignature record");

    let err = CloudflareSigningWorkerRouterAbEcdsaDerivationEvmDigestPreparedV1::new(
        response,
        record,
        &materialized,
    )
    .expect_err("record drift rejects");

    assert_eq!(
        err.code(),
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig
    );
}

#[test]
fn router_ab_ecdsa_derivation_evm_digest_finalize_private_handler_consumes_presignature_record() {
    let activation = router_ab_ecdsa_derivation_activation_request();
    let material = router_ab_ecdsa_derivation_server_material_record(&activation);
    let finalize_request = router_ab_ecdsa_derivation_digest_signing_finalize_request();
    let prepare_request = finalize_request.prepare_request().expect("prepare request");
    let admitted =
        admitted_router_ab_ecdsa_derivation_digest_finalize_request(finalize_request.clone());
    let response =
        handle_cloudflare_signing_worker_router_ab_ecdsa_derivation_evm_digest_finalize_private_request_v1(
            &TestRouterAbEcdsaDerivationEvmDigestFinalizeHandler,
            TEST_ACTIVATED_AT_MS + 1,
            admitted,
            active_signing_worker_state_for_router_ab_ecdsa_derivation(),
            material,
            router_ab_ecdsa_derivation_presignature_record(),
        )
        .expect("Router A/B ECDSA derivation digest finalize response");

    response
        .validate_for_request(&prepare_request)
        .expect("response validates against prepare request");
    assert_eq!(response.signature65_b64u, b64u(&[0x99; 65]));
}

#[test]
fn router_ab_ecdsa_derivation_production_finalize_handler_returns_real_recoverable_signature() {
    let activation = router_ab_ecdsa_derivation_activation_request();
    let material = router_ab_ecdsa_derivation_server_material_record(&activation);
    let ecdsa_context = cloudflare_router_ab_ecdsa_derivation_stable_key_context_v1(
        &activation.registration.context,
    )
    .expect("Router A/B ECDSA derivation context");
    let (_relayer_role_share, identity) = derive_relayer_share_for_client_public(
        &ecdsa_context,
        *material.output_material.as_bytes(),
        &ecdsa_derivation_client_share_public_key33(),
        activation.registration.client_share_retry_counter,
    )
    .expect("relayer role share");
    let client_threshold_share = map_additive_share_to_threshold_signatures_share_2p(
        &ecdsa_scalar_one_be32(),
        THRESHOLD_SECP256K1_2P_CLIENT_PARTICIPANT_ID,
    )
    .expect("mapped client share");
    let client_threshold_share32: [u8; 32] = client_threshold_share
        .try_into()
        .expect("mapped client share length");
    let (
        server_big_r33,
        server_k_share32,
        server_sigma_share32,
        client_k_share32,
        client_sigma_share32,
    ) = drive_ecdsa_presignature_pair(
        &client_threshold_share32,
        &_relayer_role_share.mapped_relayer_share32,
        &identity.threshold_public_key33,
    );
    let entropy32 = [0x61; 32];
    let base_prepare_request = router_ab_ecdsa_derivation_digest_signing_request();
    let prepare_request = RouterAbEcdsaDerivationEvmDigestSigningRequestV1::new(
        base_prepare_request.scope,
        base_prepare_request.request_id,
        "server-presignature-real-1",
        base_prepare_request.expires_at_ms,
        base_prepare_request.signing_digest_b64u,
    )
    .expect("real Router A/B ECDSA derivation prepare request");
    assert_eq!(
        prepare_request
            .scope
            .public_identity
            .threshold_public_key33_b64u,
        b64u(&identity.threshold_public_key33)
    );
    let participant_ids = ROUTER_AB_ECDSA_DERIVATION_PARTICIPANT_IDS.map(u32::from);
    let client_signature_share32 = threshold_ecdsa_compute_signature_share(
        &participant_ids,
        1,
        &identity.threshold_public_key33,
        &server_big_r33,
        &client_k_share32,
        &client_sigma_share32,
        prepare_request
            .signing_digest()
            .expect("signing digest")
            .as_bytes(),
        &entropy32,
    )
    .expect("client ECDSA signature share");
    let finalize_request = RouterAbEcdsaDerivationEvmDigestSigningFinalizeRequestV1::new(
        prepare_request.scope.clone(),
        prepare_request.request_id.clone(),
        prepare_request.expires_at_ms,
        prepare_request.signing_digest_b64u.clone(),
        "server-presignature-real-1",
        b64u(&client_signature_share32),
    )
    .expect("Router A/B ECDSA derivation finalize request");
    let presignature_record = CloudflareSigningWorkerEcdsaPresignatureRecordV1::new(
        active_signing_worker_state_for_router_ab_ecdsa_derivation(),
        "server-presignature-real-1",
        prepare_request.request_digest().expect("request digest"),
        prepare_request.signing_digest().expect("signing digest"),
        b64u(&server_big_r33),
        b64u(&entropy32),
        b64u(&server_k_share32),
        b64u(&server_sigma_share32),
        TEST_ACTIVATED_AT_MS + 1,
        prepare_request.expires_at_ms,
    )
    .expect("real Router A/B ECDSA derivation presignature record");
    let response =
        handle_cloudflare_signing_worker_router_ab_ecdsa_derivation_evm_digest_finalize_private_request_v1(
            &CloudflareRoleSeparatedRouterAbEcdsaDerivationEvmDigestFinalizeHandlerV1,
            TEST_ACTIVATED_AT_MS + 2,
            admitted_router_ab_ecdsa_derivation_digest_finalize_request(finalize_request),
            active_signing_worker_state_for_router_ab_ecdsa_derivation(),
            material,
            presignature_record,
        )
        .expect("production Router A/B ECDSA derivation finalize response");

    response
        .validate_for_request(&prepare_request)
        .expect("production response binds prepare request");
    assert_ne!(response.signature65_b64u, b64u(&[0x99; 65]));
}

#[test]
fn router_ab_ecdsa_derivation_materialized_finalize_rejects_presignature_drift() {
    let activation = router_ab_ecdsa_derivation_activation_request();
    let material = router_ab_ecdsa_derivation_server_material_record(&activation);
    let finalize_request = router_ab_ecdsa_derivation_digest_signing_finalize_request();
    let admitted = admitted_router_ab_ecdsa_derivation_digest_finalize_request(finalize_request);
    let mut presignature = router_ab_ecdsa_derivation_presignature_record();
    presignature.request_digest = digest(0x92);

    let err =
        CloudflareSigningWorkerMaterializedRouterAbEcdsaDerivationEvmDigestFinalizeRequestV1::new(
            admitted,
            active_signing_worker_state_for_router_ab_ecdsa_derivation(),
            material,
            presignature,
            TEST_ACTIVATED_AT_MS + 1,
        )
        .expect_err("presignature drift rejects");

    assert_eq!(
        err.code(),
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig
    );
}

#[test]
fn router_ab_ecdsa_derivation_normal_signing_request_rejects_active_state_drift() {
    let activation = router_ab_ecdsa_derivation_activation_request();
    let material = router_ab_ecdsa_derivation_server_material_record(&activation);
    let receipt = cloudflare_router_ab_ecdsa_derivation_activation_receipt_from_material_v1(
        &activation,
        &material,
        TEST_ACTIVATED_AT_MS,
    )
    .expect("Router A/B ECDSA derivation activation receipt");
    let scope =
        cloudflare_router_ab_ecdsa_derivation_normal_signing_scope_from_activation_receipt_v1(
            &receipt,
            ROUTER_AB_ECDSA_DERIVATION_WALLET_KEY_ID,
            ROUTER_AB_ECDSA_DERIVATION_WALLET_ID,
            ROUTER_AB_ECDSA_DERIVATION_THRESHOLD_KEY_ID,
            ROUTER_AB_ECDSA_DERIVATION_SIGNING_ROOT_ID,
            ROUTER_AB_ECDSA_DERIVATION_SIGNING_ROOT_VERSION,
        )
        .expect("Router A/B ECDSA derivation normal-signing scope");
    let mut active_state = cloudflare_active_signing_worker_state_from_activation_request_v1(
        &activation
            .to_recipient_proof_bundle_activation_request()
            .expect("generic activation request"),
        "router-ab-ecdsa-derivation-material",
        TEST_ACTIVATED_AT_MS,
    )
    .expect("Router A/B ECDSA derivation active state");
    active_state.session_id = "different-ecdsa-key".to_owned();
    let request = RouterAbEcdsaDerivationEvmDigestSigningRequestV1::new(
        scope,
        "router-ab-ecdsa-derivation-sign-request-1",
        "server-presignature-1",
        2_000,
        b64u(&[0x77; 32]),
    )
    .expect("Router A/B ECDSA derivation normal-signing request");
    let admitted = admitted_router_ab_ecdsa_derivation_digest_signing_request(request);

    let err =
        CloudflareSigningWorkerMaterializedRouterAbEcdsaDerivationEvmDigestSigningRequestV1::new(
            admitted,
            active_state,
            material,
            TEST_ACTIVATED_AT_MS + 1,
        )
        .expect_err("active state drift rejects");

    assert_eq!(
        err.code(),
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig
    );
}

#[test]
fn router_ab_ecdsa_derivation_normal_signing_scope_rejects_public_identity_drift() {
    let activation = router_ab_ecdsa_derivation_activation_request();
    let material = router_ab_ecdsa_derivation_server_material_record(&activation);
    let receipt = cloudflare_router_ab_ecdsa_derivation_activation_receipt_from_material_v1(
        &activation,
        &material,
        TEST_ACTIVATED_AT_MS,
    )
    .expect("Router A/B ECDSA derivation activation receipt");
    let mut scope =
        cloudflare_router_ab_ecdsa_derivation_normal_signing_scope_from_activation_receipt_v1(
            &receipt,
            ROUTER_AB_ECDSA_DERIVATION_WALLET_KEY_ID,
            ROUTER_AB_ECDSA_DERIVATION_WALLET_ID,
            ROUTER_AB_ECDSA_DERIVATION_THRESHOLD_KEY_ID,
            ROUTER_AB_ECDSA_DERIVATION_SIGNING_ROOT_ID,
            ROUTER_AB_ECDSA_DERIVATION_SIGNING_ROOT_VERSION,
        )
        .expect("Router A/B ECDSA derivation normal-signing scope");
    scope.public_identity.ethereum_address20_b64u = b64u(&[0x55; 20]);
    let active_state = cloudflare_active_signing_worker_state_from_activation_request_v1(
        &activation
            .to_recipient_proof_bundle_activation_request()
            .expect("generic activation request"),
        "router-ab-ecdsa-derivation-material",
        TEST_ACTIVATED_AT_MS,
    )
    .expect("Router A/B ECDSA derivation active state");

    let err = validate_cloudflare_router_ab_ecdsa_derivation_normal_signing_active_material_v1(
        &scope,
        &active_state,
        &material,
    )
    .expect_err("identity drift must fail");

    assert_eq!(
        err.code(),
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig
    );
}

#[test]
fn signer_peer_request_accepts_cross_role_message() {
    let message = signer_peer_message(WireMessageKindV1::SignerAToSignerB);

    validate_cloudflare_deriver_peer_request_v1(CloudflareWorkerRoleV1::DeriverB, &message)
        .expect("signer b peer request should validate");
}

#[test]
fn signer_peer_request_rejects_router_private_message() {
    let message = signer_private_request(WireMessageKindV1::RouterToSignerA);
    let err =
        validate_cloudflare_deriver_peer_request_v1(CloudflareWorkerRoleV1::DeriverB, &message)
            .expect_err("peer endpoint must reject Router-to-signer messages");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidLocalRoute);
}

#[test]
fn signer_peer_request_rejects_payload_direction_mismatch() {
    let opposite_payload = signer_peer_message(WireMessageKindV1::SignerBToSignerA);
    let message = WireMessageV1::new(
        WireMessageKindV1::SignerAToSignerB,
        opposite_payload.transcript_digest,
        opposite_payload.payload,
    )
    .expect("mismatched peer message");

    let err =
        validate_cloudflare_deriver_peer_request_v1(CloudflareWorkerRoleV1::DeriverB, &message)
            .expect_err("peer payload direction mismatch must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidSignerIdentity);
}

#[test]
fn signer_peer_request_authentication_verifies_with_key_store() {
    let message = signer_peer_message(WireMessageKindV1::SignerAToSignerB);
    let payload =
        verify_cloudflare_deriver_peer_message_authentication_v1(&TestPeerKeyStore, &message)
            .expect("peer authentication should verify");

    assert_eq!(payload.from, signer_identity(Role::SignerA));
}

#[test]
fn signer_peer_request_authentication_rejects_wrong_key() {
    let message = signer_peer_message(WireMessageKindV1::SignerAToSignerB);
    let err =
        verify_cloudflare_deriver_peer_message_authentication_v1(&WrongPeerKeyStore, &message)
            .expect_err("wrong key must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidSignerIdentity);
}

#[test]
fn signer_peer_response_requires_opposite_peer_direction() {
    let request = signer_peer_message(WireMessageKindV1::SignerAToSignerB);
    let response = signer_peer_message(WireMessageKindV1::SignerBToSignerA);

    validate_cloudflare_deriver_peer_response_v1(
        CloudflareWorkerRoleV1::DeriverB,
        &request,
        &response,
    )
    .expect("opposite peer response should validate");
}

#[test]
fn signer_peer_handler_returns_transcript_bound_peer_response() {
    let request = signer_peer_message(WireMessageKindV1::SignerAToSignerB);
    let response = handle_cloudflare_deriver_peer_request_v1(
        CloudflareWorkerRoleV1::DeriverB,
        &TestPeerKeyStore,
        &TestPeerWireHandler::matching(WireMessageKindV1::SignerBToSignerA),
        request.clone(),
    )
    .expect("signer b peer request");

    assert_eq!(response.kind, WireMessageKindV1::SignerBToSignerA);
    assert_eq!(response.transcript_digest, request.transcript_digest);
}

#[test]
fn signer_host_peer_preload_input_accepts_peer_requests() {
    let input = CloudflareSignerHostPeerPreloadInputV1::new(
        "signer-set-v1",
        root_epoch(),
        vec![signer_peer_message(WireMessageKindV1::SignerAToSignerB)],
        signer_verifying_keys(),
        32,
    )
    .expect("peer preload input");

    assert_eq!(input.peer_requests.len(), 1);
    assert_eq!(input.random_bytes_len, 32);
}

#[test]
fn signer_host_peer_preload_input_rejects_router_private_message() {
    let err = CloudflareSignerHostPeerPreloadInputV1::new(
        "signer-set-v1",
        root_epoch(),
        vec![signer_private_request(WireMessageKindV1::RouterToSignerA)],
        signer_verifying_keys(),
        0,
    )
    .expect_err("router message cannot be preloaded as peer request");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidLocalRoute);
}

#[test]
fn signer_host_peer_preload_input_rejects_missing_sender_verifying_key() {
    let err = CloudflareSignerHostPeerPreloadInputV1::new(
        "signer-set-v1",
        root_epoch(),
        vec![signer_peer_message(WireMessageKindV1::SignerAToSignerB)],
        vec![signer_verifying_key(Role::SignerB)],
        0,
    )
    .expect_err("missing sender verifying key must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::MissingLocalBinding);
}

#[test]
fn signer_host_preload_input_rejects_wrong_sender_verifying_key() {
    let wrong_key = AbPeerMessageVerifyingKeyV1::new(
        signer_identity(Role::SignerA),
        signer_peer_signing_key(Role::SignerB)
            .verifying_key()
            .to_bytes(),
    )
    .expect("wrong key");
    let err = CloudflareSignerHostPreloadInputV1::new(
        "signer-set-v1",
        root_epoch(),
        vec![signer_peer_message(WireMessageKindV1::SignerAToSignerB)],
        vec![wrong_key],
        0,
    )
    .expect_err("wrong sender verifying key must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidSignerIdentity);
}

#[test]
fn signer_host_preload_input_rejects_duplicate_verifying_key_identity() {
    let err = CloudflareSignerHostPreloadInputV1::new(
        "signer-set-v1",
        root_epoch(),
        Vec::new(),
        vec![
            signer_verifying_key(Role::SignerA),
            signer_verifying_key(Role::SignerA),
        ],
        0,
    )
    .expect_err("duplicate signer verifying key must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidSignerIdentity);
}

#[test]
fn router_worker_runtime_rejects_expired_public_request() {
    let runtime = CloudflareRouterWorkerRuntimeV1::new(
        CloudflareRouterBindingsV1::new(
            do_binding(
                CloudflareDurableObjectScopeV1::RouterReplay,
                "ROUTER_REPLAY_DO",
            ),
            do_binding(
                CloudflareDurableObjectScopeV1::RouterLifecycle,
                "ROUTER_LIFECYCLE_DO",
            ),
            router_wallet_budget_binding(),
            router_admission_bindings(),
            peer(CloudflareWorkerRoleV1::DeriverA, "DERIVER_A"),
            peer(CloudflareWorkerRoleV1::DeriverB, "DERIVER_B"),
            peer(CloudflareWorkerRoleV1::SigningWorker, "SIGNING_WORKER"),
        )
        .expect("router bindings"),
    )
    .expect("router runtime");
    let err = runtime
        .public_request_admission_plan_at(
            2_000,
            ecdsa_threshold_prf_request(2_000),
            trusted_admission(
                ExpensiveWorkGateDecisionV1::accepted("gate-request-1").expect("accepted"),
            ),
        )
        .expect_err("expired request must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::ExpiredLocalRequest);
}

#[test]
fn router_bindings_reject_signer_root_share_scope() {
    let err = CloudflareRouterBindingsV1::new(
        deriver_a_root_binding(),
        do_binding(
            CloudflareDurableObjectScopeV1::RouterLifecycle,
            "ROUTER_LIFECYCLE_DO",
        ),
        router_wallet_budget_binding(),
        router_admission_bindings(),
        peer(CloudflareWorkerRoleV1::DeriverA, "DERIVER_A"),
        peer(CloudflareWorkerRoleV1::DeriverB, "DERIVER_B"),
        peer(CloudflareWorkerRoleV1::SigningWorker, "SIGNING_WORKER"),
    )
    .expect_err("router must reject signer root-share binding");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::ForbiddenLocalBinding);
}

#[test]
fn deriver_a_bindings_accept_a_root_share() {
    let bindings = CloudflareDeriverABindingsV1::new(
        deriver_a_root_binding(),
        deriver_a_root_share_wire_secret_binding(),
        deriver_a_envelope_hpke_decrypt_key(),
        deriver_a_peer_signing_key(),
        cloudflare_peer_verifying_key_set(),
        peer(CloudflareWorkerRoleV1::DeriverB, "DERIVER_B"),
        peer(CloudflareWorkerRoleV1::SigningWorker, "SIGNING_WORKER"),
    )
    .expect("signer a bindings");
    let startup = CloudflareWorkerBindingsV1::deriver_a(bindings).expect("signer a startup");

    assert_eq!(startup.worker_role(), CloudflareWorkerRoleV1::DeriverA);
}

#[test]
fn deriver_a_bindings_reject_non_signing_worker_activation_peer() {
    let err = CloudflareDeriverABindingsV1::new(
        deriver_a_root_binding(),
        deriver_a_root_share_wire_secret_binding(),
        deriver_a_envelope_hpke_decrypt_key(),
        deriver_a_peer_signing_key(),
        cloudflare_peer_verifying_key_set(),
        peer(CloudflareWorkerRoleV1::DeriverB, "DERIVER_B"),
        peer(CloudflareWorkerRoleV1::Router, "ROUTER"),
    )
    .expect_err("signer a must reject non-SigningWorker activation peer");

    assert_eq!(
        err.code(),
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig
    );
}

#[test]
fn signing_worker_bindings_accept_server_output_scope() {
    let bindings = CloudflareSigningWorkerBindingsV1::new(
        server_output_binding(),
        server_output_hpke_decrypt_key(),
    )
    .expect("signing worker bindings");
    let startup =
        CloudflareWorkerBindingsV1::signing_worker(bindings).expect("signing worker startup");

    assert_eq!(startup.worker_role(), CloudflareWorkerRoleV1::SigningWorker);
}

#[test]
fn signing_worker_bindings_reject_deriver_a_root_scope() {
    let err = CloudflareSigningWorkerBindingsV1::new(
        deriver_a_root_binding(),
        server_output_hpke_decrypt_key(),
    )
    .expect_err("signing worker must reject signer a root-share binding");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::ForbiddenLocalBinding);
}

#[test]
fn deriver_a_bindings_reject_b_root_share_scope() {
    let err = CloudflareDeriverABindingsV1::new(
        deriver_b_root_binding(),
        deriver_a_root_share_wire_secret_binding(),
        deriver_a_envelope_hpke_decrypt_key(),
        deriver_a_peer_signing_key(),
        cloudflare_peer_verifying_key_set(),
        peer(CloudflareWorkerRoleV1::DeriverB, "DERIVER_B"),
        peer(CloudflareWorkerRoleV1::SigningWorker, "SIGNING_WORKER"),
    )
    .expect_err("signer a must reject signer b root-share binding");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::ForbiddenLocalBinding);
}

#[test]
fn deriver_a_bindings_reject_b_root_share_wire_secret() {
    let err = CloudflareDeriverABindingsV1::new(
        deriver_a_root_binding(),
        deriver_b_root_share_wire_secret_binding(),
        deriver_a_envelope_hpke_decrypt_key(),
        deriver_a_peer_signing_key(),
        cloudflare_peer_verifying_key_set(),
        peer(CloudflareWorkerRoleV1::DeriverB, "DERIVER_B"),
        peer(CloudflareWorkerRoleV1::SigningWorker, "SIGNING_WORKER"),
    )
    .expect_err("signer a must reject signer b root-share wire secret");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::ForbiddenLocalBinding);
}

#[test]
fn deriver_a_bindings_reject_b_envelope_decrypt_key() {
    let err = CloudflareDeriverABindingsV1::new(
        deriver_a_root_binding(),
        deriver_a_root_share_wire_secret_binding(),
        deriver_b_envelope_hpke_decrypt_key(),
        deriver_a_peer_signing_key(),
        cloudflare_peer_verifying_key_set(),
        peer(CloudflareWorkerRoleV1::DeriverB, "DERIVER_B"),
        peer(CloudflareWorkerRoleV1::SigningWorker, "SIGNING_WORKER"),
    )
    .expect_err("signer a must reject signer b decrypt key");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::ForbiddenLocalBinding);
}

#[test]
fn deriver_a_bindings_reject_b_peer_signing_key() {
    let err = CloudflareDeriverABindingsV1::new(
        deriver_a_root_binding(),
        deriver_a_root_share_wire_secret_binding(),
        deriver_a_envelope_hpke_decrypt_key(),
        deriver_b_peer_signing_key(),
        cloudflare_peer_verifying_key_set(),
        peer(CloudflareWorkerRoleV1::DeriverB, "DERIVER_B"),
        peer(CloudflareWorkerRoleV1::SigningWorker, "SIGNING_WORKER"),
    )
    .expect_err("signer a must reject signer b peer signing key");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::ForbiddenLocalBinding);
}

#[test]
fn deriver_b_bindings_accept_b_root_share_scope() {
    let bindings = CloudflareDeriverBBindingsV1::new(
        deriver_b_root_binding(),
        deriver_b_root_share_wire_secret_binding(),
        deriver_b_envelope_hpke_decrypt_key(),
        deriver_b_peer_signing_key(),
        cloudflare_peer_verifying_key_set(),
        peer(CloudflareWorkerRoleV1::DeriverA, "DERIVER_A"),
        peer(CloudflareWorkerRoleV1::SigningWorker, "SIGNING_WORKER"),
    )
    .expect("signer b bindings");
    let startup = CloudflareWorkerBindingsV1::deriver_b(bindings).expect("signer b startup");

    assert_eq!(startup.worker_role(), CloudflareWorkerRoleV1::DeriverB);
}

#[test]
fn deriver_b_bindings_reject_non_signing_worker_activation_peer() {
    let err = CloudflareDeriverBBindingsV1::new(
        deriver_b_root_binding(),
        deriver_b_root_share_wire_secret_binding(),
        deriver_b_envelope_hpke_decrypt_key(),
        deriver_b_peer_signing_key(),
        cloudflare_peer_verifying_key_set(),
        peer(CloudflareWorkerRoleV1::DeriverA, "DERIVER_A"),
        peer(CloudflareWorkerRoleV1::Router, "ROUTER"),
    )
    .expect_err("signer b must reject non-SigningWorker activation peer");

    assert_eq!(
        err.code(),
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig
    );
}

#[test]
fn deriver_b_bindings_reject_server_output_scope() {
    let err = CloudflareDeriverBBindingsV1::new(
        server_output_binding(),
        deriver_b_root_share_wire_secret_binding(),
        deriver_b_envelope_hpke_decrypt_key(),
        deriver_b_peer_signing_key(),
        cloudflare_peer_verifying_key_set(),
        peer(CloudflareWorkerRoleV1::DeriverA, "DERIVER_A"),
        peer(CloudflareWorkerRoleV1::SigningWorker, "SIGNING_WORKER"),
    )
    .expect_err("signer b must reject server-output binding");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::ForbiddenLocalBinding);
}

#[test]
fn deriver_b_bindings_reject_a_root_share_wire_secret() {
    let err = CloudflareDeriverBBindingsV1::new(
        deriver_b_root_binding(),
        deriver_a_root_share_wire_secret_binding(),
        deriver_b_envelope_hpke_decrypt_key(),
        deriver_b_peer_signing_key(),
        cloudflare_peer_verifying_key_set(),
        peer(CloudflareWorkerRoleV1::DeriverA, "DERIVER_A"),
        peer(CloudflareWorkerRoleV1::SigningWorker, "SIGNING_WORKER"),
    )
    .expect_err("signer b must reject signer a root-share wire secret");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::ForbiddenLocalBinding);
}

#[test]
fn deriver_b_bindings_reject_a_envelope_decrypt_key() {
    let err = CloudflareDeriverBBindingsV1::new(
        deriver_b_root_binding(),
        deriver_b_root_share_wire_secret_binding(),
        deriver_a_envelope_hpke_decrypt_key(),
        deriver_b_peer_signing_key(),
        cloudflare_peer_verifying_key_set(),
        peer(CloudflareWorkerRoleV1::DeriverA, "DERIVER_A"),
        peer(CloudflareWorkerRoleV1::SigningWorker, "SIGNING_WORKER"),
    )
    .expect_err("signer b must reject signer a decrypt key");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::ForbiddenLocalBinding);
}

#[test]
fn deriver_b_bindings_reject_a_peer_signing_key() {
    let err = CloudflareDeriverBBindingsV1::new(
        deriver_b_root_binding(),
        deriver_b_root_share_wire_secret_binding(),
        deriver_b_envelope_hpke_decrypt_key(),
        deriver_a_peer_signing_key(),
        cloudflare_peer_verifying_key_set(),
        peer(CloudflareWorkerRoleV1::DeriverA, "DERIVER_A"),
        peer(CloudflareWorkerRoleV1::SigningWorker, "SIGNING_WORKER"),
    )
    .expect_err("signer b must reject signer a peer signing key");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::ForbiddenLocalBinding);
}

#[test]
fn cloudflare_peer_verifying_key_set_binds_to_signer_set() {
    let keys = cloudflare_peer_verifying_key_set()
        .to_protocol_keys(&signer_set())
        .expect("protocol verifying keys");

    assert_eq!(keys, signer_verifying_keys());
}

#[test]
fn cloudflare_peer_verifying_key_hex_rejects_uppercase() {
    let upper = signer_peer_verifying_key_hex(Role::SignerA).to_uppercase();
    let err =
        decode_cloudflare_peer_verifying_key_hex_v1(&upper).expect_err("uppercase hex must fail");

    assert_eq!(
        err.code(),
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig
    );
}

#[test]
fn signer_startup_checks_accept_matching_role_bindings() {
    let deriver_a = CloudflareSignerStartupCheckV1::deriver_a(
        "signer-set-v1",
        root_epoch(),
        deriver_a_root_binding(),
    )
    .expect("signer a startup check");
    let deriver_b = CloudflareSignerStartupCheckV1::deriver_b(
        "signer-set-v1",
        root_epoch(),
        deriver_b_root_binding(),
    )
    .expect("signer b startup check");

    assert_eq!(deriver_a.signer_role, Role::SignerA);
    assert_eq!(deriver_b.signer_role, Role::SignerB);
}

#[test]
fn signer_startup_check_rejects_mismatched_root_share_binding() {
    let err = CloudflareSignerStartupCheckV1::deriver_a(
        "signer-set-v1",
        root_epoch(),
        deriver_b_root_binding(),
    )
    .expect_err("signer a startup must reject signer b root-share binding");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::ForbiddenLocalBinding);
}

#[test]
fn deriver_a_runtime_builds_only_a_scoped_storage_calls() {
    let runtime = CloudflareDeriverAWorkerRuntimeV1::new(
        CloudflareDeriverABindingsV1::new(
            deriver_a_root_binding(),
            deriver_a_root_share_wire_secret_binding(),
            deriver_a_envelope_hpke_decrypt_key(),
            deriver_a_peer_signing_key(),
            cloudflare_peer_verifying_key_set(),
            peer(CloudflareWorkerRoleV1::DeriverB, "DERIVER_B"),
            peer(CloudflareWorkerRoleV1::SigningWorker, "SIGNING_WORKER"),
        )
        .expect("signer a bindings"),
    )
    .expect("signer a runtime");
    let has_call = runtime
        .root_share_has_call("signer-set-v1", root_epoch())
        .expect("root-share has call");
    let metadata_call = runtime
        .root_share_startup_metadata_call("signer-set-v1", root_epoch())
        .expect("root-share metadata call");
    assert_eq!(has_call.worker_role, CloudflareWorkerRoleV1::DeriverA);
    assert_eq!(
        has_call.binding.scope,
        CloudflareDurableObjectScopeV1::SignerRootShare {
            role: Role::SignerA
        }
    );
    assert_eq!(
        metadata_call.operation_kind(),
        CloudflareDurableObjectOperationKindV1::RootShareStartupMetadata
    );
    assert_eq!(
        runtime.deriver_b_peer().peer_role,
        CloudflareWorkerRoleV1::DeriverB
    );
    assert_eq!(runtime.root_share_wire_secret().role, Role::SignerA);
    assert_eq!(runtime.envelope_decrypt_key().current.role, Role::SignerA);
    assert_eq!(runtime.peer_signing_key().role, Role::SignerA);
    assert_eq!(
        runtime
            .peer_verifying_keys_for_signer_set(&signer_set())
            .expect("signer a runtime verifying keys"),
        signer_verifying_keys()
    );
}

#[test]
fn signing_worker_runtime_builds_only_server_output_calls() {
    let runtime = CloudflareSigningWorkerRuntimeV1::new(
        CloudflareSigningWorkerBindingsV1::new(
            server_output_binding(),
            server_output_hpke_decrypt_key(),
        )
        .expect("signing worker bindings"),
    )
    .expect("signing worker runtime");
    let activation = signing_worker_activation();
    let material = server_output_material_record(&activation);
    let activation_call = runtime
        .signing_worker_output_activate_call(activation, material, TEST_ACTIVATED_AT_MS)
        .expect("SigningWorker activation call");
    let active_state_call = runtime
        .active_signing_worker_state_get_call(
            CloudflareActiveSigningWorkerStateLookupV1::new(
                "account.near",
                "session-1",
                "server-a",
            )
            .expect("active SigningWorker lookup"),
        )
        .expect("active SigningWorker lookup call");
    let material_call = runtime
        .signing_worker_output_material_get_call(
            router_ab_cloudflare::CloudflareSigningWorkerOutputMaterialLookupV1::new(
                active_signing_worker_state_for_normal_signing(),
            )
            .expect("SigningWorker material lookup"),
        )
        .expect("SigningWorker material lookup call");
    let round1_put_call = runtime
        .signing_worker_round1_put_call(normal_signing_round1_record())
        .expect("SigningWorker round1 put call");
    let round1_take_call = runtime
        .signing_worker_round1_take_call(normal_signing_round1_lookup(1_500))
        .expect("SigningWorker round1 take call");

    assert_eq!(
        activation_call.worker_role,
        CloudflareWorkerRoleV1::SigningWorker
    );
    assert_eq!(
        activation_call.binding.scope,
        CloudflareDurableObjectScopeV1::signing_worker_server_output()
    );
    assert_eq!(
        active_state_call.operation_kind(),
        CloudflareDurableObjectOperationKindV1::SigningWorkerOutputActiveStateGet
    );
    assert_eq!(
        material_call.operation_kind(),
        CloudflareDurableObjectOperationKindV1::SigningWorkerOutputMaterialGet
    );
    assert_eq!(
        round1_put_call.operation_kind(),
        CloudflareDurableObjectOperationKindV1::SigningWorkerRound1Put
    );
    assert_eq!(
        round1_take_call.operation_kind(),
        CloudflareDurableObjectOperationKindV1::SigningWorkerRound1Take
    );
    assert_eq!(
        material_call.storage_key(),
        "server-output/lifecycle-1/material"
    );
    assert_eq!(
        round1_put_call.storage_key(),
        "SIGNING_WORKER_SERVER_OUTPUT_DO:signing-worker-round1/account.near/session-1/server-a/server-round1/sign-request-1"
    );
    assert_eq!(
        round1_take_call.storage_key(),
        round1_put_call.storage_key()
    );
    assert_eq!(
        active_state_call.binding.scope,
        CloudflareDurableObjectScopeV1::signing_worker_server_output()
    );
    assert_eq!(
        runtime.server_output_decrypt_key().binding_name,
        "SIGNING_WORKER_SERVER_OUTPUT_HPKE_PRIVATE_KEY"
    );
}

#[test]
fn deriver_b_runtime_builds_only_b_scoped_storage_calls() {
    let runtime = CloudflareDeriverBWorkerRuntimeV1::new(
        CloudflareDeriverBBindingsV1::new(
            deriver_b_root_binding(),
            deriver_b_root_share_wire_secret_binding(),
            deriver_b_envelope_hpke_decrypt_key(),
            deriver_b_peer_signing_key(),
            cloudflare_peer_verifying_key_set(),
            peer(CloudflareWorkerRoleV1::DeriverA, "DERIVER_A"),
            peer(CloudflareWorkerRoleV1::SigningWorker, "SIGNING_WORKER"),
        )
        .expect("signer b bindings"),
    )
    .expect("signer b runtime");
    let has_call = runtime
        .root_share_has_call("signer-set-v1", root_epoch())
        .expect("root-share has call");
    let metadata_call = runtime
        .root_share_startup_metadata_call("signer-set-v1", root_epoch())
        .expect("root-share metadata call");

    assert_eq!(has_call.worker_role, CloudflareWorkerRoleV1::DeriverB);
    assert_eq!(
        has_call.binding.scope,
        CloudflareDurableObjectScopeV1::SignerRootShare {
            role: Role::SignerB
        }
    );
    assert_eq!(
        metadata_call.operation_kind(),
        CloudflareDurableObjectOperationKindV1::RootShareStartupMetadata
    );
    assert_eq!(
        runtime.deriver_a_peer().peer_role,
        CloudflareWorkerRoleV1::DeriverA
    );
    assert_eq!(runtime.root_share_wire_secret().role, Role::SignerB);
    assert_eq!(runtime.envelope_decrypt_key().current.role, Role::SignerB);
    assert_eq!(runtime.peer_signing_key().role, Role::SignerB);
    assert_eq!(
        runtime
            .peer_verifying_keys_for_signer_set(&signer_set())
            .expect("signer b runtime verifying keys"),
        signer_verifying_keys()
    );
}

#[test]
fn signing_worker_production_v2_prepare_returns_router_admitted_public_material() {
    let request = normal_signing_v2_prepare_request(2_000);
    let wallet_session = normal_signing_v2_wallet_session(3_000);
    let admission = CloudflareRouterNormalSigningPrepareAdmissionCandidateV2::from_prepare_request(
        &wallet_session,
        &request,
        1_000,
    )
    .expect("normal signing v2 admission");
    let trusted_admission = CloudflareRouterNormalSigningTrustedAdmissionV1::new(
        admission
            .to_v1_trusted_metadata()
            .expect("v1 trusted metadata"),
        ExpensiveWorkGateDecisionV1::accepted("gate-request-1").expect("accepted"),
    )
    .expect("trusted admission");
    let admitted = CloudflareSigningWorkerAdmittedNormalSigningPrepareRequestV2::new(
        request.scope.clone(),
        request.expires_at_ms,
        admission.clone(),
        trusted_admission,
    )
    .expect("admitted v2 prepare");
    let active_signing_worker = active_signing_worker_state_for_normal_signing();
    let material = CloudflareServerOutputMaterialRecordV1::new(
        active_signing_worker.activation_transcript_digest,
        OpenedShareKind::XServerBase,
        Role::Server,
        "server-a",
        CloudflareSecretMaterial32V1::new(scalar_bytes(5)),
    )
    .expect("server output material");

    let prepared = handle_cloudflare_signing_worker_normal_signing_prepare_private_request_v2(
        &CloudflareEd25519YaoNormalSigningHandlerV1,
        1_500,
        admitted,
        active_signing_worker,
        material,
    )
    .expect("production v2 prepare");

    assert_eq!(prepared.response.scope, request.scope);
    assert_eq!(
        prepared.response.signing_payload_digest,
        admission.signing_payload_digest
    );
    assert_eq!(
        prepared.response.round1_binding_digest,
        request.round1_binding_digest().expect("round1 binding")
    );
    assert_eq!(
        prepared.record.admitted_signing_digest,
        admission.admitted_signing_digest
    );
    assert_eq!(
        prepared.record.round1_binding_digest,
        request.round1_binding_digest().expect("round1 binding")
    );
}

#[test]
fn signing_worker_production_v2_finalize_signs_router_admitted_digest_from_round1_record() {
    let (
        client_scalar,
        server_scalar,
        client_verifying_share,
        server_verifying_share,
        group_public_key,
        client_round1,
        server_round1,
    ) = normal_signing_frost_fixture();
    let prepare_request = normal_signing_v2_prepare_request(2_000);
    let material = prepare_request
        .admission_material()
        .expect("admission material");
    let client_signature_share = normal_signing_client_signature_share(
        &client_scalar,
        &group_public_key,
        &client_round1,
        &server_round1,
        material.admitted_signing_digest.as_bytes(),
    );
    let prepare_binding = RouterAbEd25519NormalSigningPrepareBindingV2::new(
        "server-round1/sign-request-1",
        prepare_request
            .round1_binding_digest()
            .expect("round1 binding"),
        material.intent_digest,
        material.signing_payload_digest,
    )
    .expect("prepare binding");
    let protocol = RouterAbEd25519NormalSigningFinalizeProtocolV2::Ed25519TwoPartyFrostFinalizeV1(
        RouterAbEd25519TwoPartyFrostFinalizeProtocolV2::new(
            NormalSigningEd25519TwoPartyFrostCommitmentsV1::new(
                client_round1.commitments_wire.hiding.clone(),
                client_round1.commitments_wire.binding.clone(),
            )
            .expect("client commitments"),
            server_round1.commitments.clone(),
            b64u(&client_verifying_share),
            b64u(&server_verifying_share),
            client_signature_share,
        )
        .expect("v2 finalize protocol"),
    );
    let request = RouterAbEd25519NormalSigningFinalizeRequestV2::new(
        normal_signing_scope(),
        2_000,
        prepare_binding,
        protocol,
    )
    .expect("v2 finalize request");
    let wallet_session = normal_signing_v2_wallet_session(3_000);
    let finalize_admission =
        CloudflareRouterNormalSigningFinalizeAdmissionCandidateV2::from_finalize_request(
            &wallet_session,
            &request,
            1_000,
        )
        .expect("v2 finalize admission");
    let trusted_admission = CloudflareRouterNormalSigningTrustedAdmissionV1::new(
        finalize_admission
            .to_v1_trusted_metadata()
            .expect("v1 trusted metadata"),
        ExpensiveWorkGateDecisionV1::accepted("gate-request-1").expect("accepted"),
    )
    .expect("trusted admission");
    let active_signing_worker =
        active_signing_worker_state_for_normal_signing_public_key(group_public_key);
    let material_record = CloudflareServerOutputMaterialRecordV1::new(
        active_signing_worker.activation_transcript_digest,
        OpenedShareKind::XServerBase,
        Role::Server,
        "server-a",
        CloudflareSecretMaterial32V1::new(server_scalar),
    )
    .expect("server output material");
    let server_round1_record = CloudflareSigningWorkerRound1RecordV1::new(
        active_signing_worker.clone(),
        "server-round1/sign-request-1",
        request.round1_binding_digest(),
        material.admitted_signing_digest,
        server_round1,
        1_000,
        2_000,
    )
    .expect("server round1 record");
    let admitted = CloudflareSigningWorkerAdmittedNormalSigningFinalizeRequestV2::new(
        request.clone(),
        trusted_admission,
    )
    .expect("admitted v2 finalize");

    let response = handle_cloudflare_signing_worker_normal_signing_finalize_private_request_v2(
        &CloudflareEd25519YaoNormalSigningHandlerV1,
        1_500,
        admitted,
        active_signing_worker,
        material_record,
        server_round1_record,
    )
    .expect("production v2 finalize response");

    response.validate().expect("v2 finalize response validates");
    assert_eq!(response.scope, request.scope);
    assert_eq!(
        response.signing_payload_digest,
        material.signing_payload_digest
    );
    let verifying_key = VerifyingKey::from_bytes(&group_public_key).expect("fixture verifying key");
    let signature: [u8; 64] = response
        .signature
        .as_bytes()
        .try_into()
        .expect("64-byte signature");
    verifying_key
        .verify(
            material.admitted_signing_digest.as_bytes(),
            &Ed25519Signature::from_bytes(&signature),
        )
        .expect("production v2 handler signature verifies over admitted digest");
}

#[test]
fn preloaded_signer_host_implements_core_host_traits() {
    let request = signer_private_request(WireMessageKindV1::RouterToSignerA);
    let peer_response = signer_peer_message_with_transcript(
        WireMessageKindV1::SignerBToSignerA,
        request.transcript_digest,
    );
    let mut host = CloudflarePreloadedSignerHostV1::new(
        1_000,
        vec![root_share_metadata(Role::SignerA)],
        vec![peer_response.clone()],
        signer_verifying_keys(),
        vec![0x42, 0x43],
    )
    .expect("preloaded host");

    assert_eq!(host.now_unix_ms(), 1_000);
    assert_eq!(
        host.signer_identity(Role::SignerA).expect("identity"),
        "signer-a"
    );
    assert_eq!(
        host.signer_verifying_key(&signer_identity(Role::SignerB))
            .expect("verifying key")
            .signer,
        signer_identity(Role::SignerB)
    );
    assert!(host
        .has_root_share(Role::SignerA, &root_epoch())
        .expect("root share"));
    assert!(!host
        .has_root_share(Role::SignerB, &root_epoch())
        .expect("root share"));
    let mut random = [0u8; 2];
    host.fill_random(&mut random).expect("random");
    assert_eq!(random, [0x42, 0x43]);
    assert_eq!(
        host.send_peer_message(request).expect("peer response"),
        peer_response
    );
    assert_eq!(host.now_unix_ms(), 1_000);
}

#[test]
fn preloaded_signer_host_builds_from_loaded_parts() {
    let peer_response = signer_peer_message(WireMessageKindV1::SignerBToSignerA);
    let input = CloudflareSignerHostPreloadInputV1::new(
        "signer-set-v1",
        root_epoch(),
        vec![peer_response],
        signer_verifying_keys(),
        2,
    )
    .expect("preload input");
    let mut host = build_cloudflare_preloaded_signer_host_v1(
        1_000,
        Role::SignerA,
        input,
        root_share_metadata(Role::SignerA),
        vec![0x42, 0x43],
    )
    .expect("preloaded host");

    assert_eq!(
        host.signer_identity(Role::SignerA).expect("identity"),
        "signer-a"
    );
    let mut random = [0u8; 2];
    host.fill_random(&mut random).expect("random");
    assert_eq!(random, [0x42, 0x43]);
}

#[test]
fn preloaded_signer_host_exposes_role_local_root_share_wire() {
    let input = CloudflareSignerHostPreloadInputV1::new(
        "signer-set-v1",
        root_epoch(),
        Vec::new(),
        signer_verifying_keys(),
        0,
    )
    .expect("preload input");
    let share_wire = root_share_wire(Role::SignerA);
    let host = build_cloudflare_preloaded_signer_host_with_root_share_wire_v1(
        1_000,
        Role::SignerA,
        input,
        root_share_metadata(Role::SignerA),
        share_wire.clone(),
        Vec::new(),
    )
    .expect("preloaded host with root-share wire");

    assert_eq!(
        host.signing_root_share_wire(Role::SignerA, &root_epoch())
            .expect("root-share wire"),
        share_wire
    );
    assert_eq!(
        host.signing_root_share_wire(Role::SignerB, &root_epoch())
            .expect_err("opposite role root-share wire must be absent")
            .code(),
        RouterAbProtocolErrorCode::MissingLocalBinding
    );
}

#[test]
fn root_share_wire_secret_decoder_builds_preloaded_record() {
    let metadata = root_share_metadata(Role::SignerA);
    let decoded = decode_cloudflare_root_share_wire_secret_v1(
        &metadata,
        &root_share_wire_secret(Role::SignerA),
    )
    .expect("decoded root-share wire");

    assert_eq!(decoded.signer_role, Role::SignerA);
    assert_eq!(decoded.root_share_epoch, root_epoch());
    assert_eq!(
        decoded.signing_root_share_wire(),
        root_share_wire(Role::SignerA)
    );

    let host = CloudflarePreloadedSignerHostV1::new_with_root_share_wires(
        1_000,
        vec![metadata],
        vec![decoded],
        Vec::new(),
        signer_verifying_keys(),
        Vec::new(),
    )
    .expect("host with decoded root-share wire");

    assert_eq!(
        host.signing_root_share_wire(Role::SignerA, &root_epoch())
            .expect("root-share wire"),
        root_share_wire(Role::SignerA)
    );
}

#[test]
fn root_share_wire_secret_decoder_rejects_share_id_for_other_deriver() {
    let secret = format!(
        "{}{}",
        CLOUDFLARE_ROOT_SHARE_WIRE_SECRET_PREFIX_V1,
        lower_hex(root_share_wire(Role::SignerB).as_bytes())
    );
    let err =
        decode_cloudflare_root_share_wire_secret_v1(&root_share_metadata(Role::SignerA), &secret)
            .expect_err("Deriver A must reject the Deriver B share id");

    assert_eq!(
        err.code(),
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig
    );
}

#[test]
fn root_share_wire_secret_binding_decoder_accepts_visible_binding() {
    let decoded = decode_and_validate_cloudflare_root_share_wire_secret_v1(
        CloudflareWorkerRoleV1::DeriverA,
        &deriver_a_root_share_wire_secret_binding(),
        &root_share_metadata(Role::SignerA),
        &root_share_wire_secret(Role::SignerA),
    )
    .expect("binding-aware root-share wire decoder");

    assert_eq!(decoded.signer_role, Role::SignerA);
    assert_eq!(
        decoded.signing_root_share_wire(),
        root_share_wire(Role::SignerA)
    );
}

#[test]
fn root_share_wire_secret_binding_decoder_rejects_cross_role_binding() {
    let err = decode_and_validate_cloudflare_root_share_wire_secret_v1(
        CloudflareWorkerRoleV1::DeriverA,
        &deriver_b_root_share_wire_secret_binding(),
        &root_share_metadata(Role::SignerB),
        &root_share_wire_secret(Role::SignerB),
    )
    .expect_err("signer a cannot decode signer b root-share wire secret");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::ForbiddenLocalBinding);
}

#[test]
fn root_share_wire_secret_binding_decoder_rejects_metadata_role_mismatch() {
    let err = decode_and_validate_cloudflare_root_share_wire_secret_v1(
        CloudflareWorkerRoleV1::DeriverA,
        &deriver_a_root_share_wire_secret_binding(),
        &root_share_metadata(Role::SignerB),
        &root_share_wire_secret(Role::SignerA),
    )
    .expect_err("binding role must match root-share metadata role");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidRole);
}

#[test]
fn root_share_wire_secret_decoder_rejects_wrong_prefix() {
    let err = decode_cloudflare_root_share_wire_secret_v1(
        &root_share_metadata(Role::SignerA),
        "raw:0102",
    )
    .expect_err("wrong prefix must fail");

    assert_eq!(
        err.code(),
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig
    );
}

#[test]
fn root_share_wire_secret_decoder_rejects_uppercase_hex() {
    let secret = format!(
        "{}{}",
        CLOUDFLARE_ROOT_SHARE_WIRE_SECRET_PREFIX_V1,
        lower_hex(root_share_wire(Role::SignerA).as_bytes()).to_uppercase()
    );
    let err =
        decode_cloudflare_root_share_wire_secret_v1(&root_share_metadata(Role::SignerA), &secret)
            .expect_err("uppercase encoding must fail");

    assert_eq!(
        err.code(),
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig
    );
}

#[test]
fn root_share_wire_secret_decoder_rejects_wrong_length() {
    let secret = format!("{}00", CLOUDFLARE_ROOT_SHARE_WIRE_SECRET_PREFIX_V1);
    let err =
        decode_cloudflare_root_share_wire_secret_v1(&root_share_metadata(Role::SignerA), &secret)
            .expect_err("short root-share wire must fail");

    assert_eq!(
        err.code(),
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig
    );
}

#[test]
fn preloaded_signer_host_rejects_metadata_mismatch() {
    let input = CloudflareSignerHostPreloadInputV1::new(
        "signer-set-v1",
        root_epoch(),
        Vec::new(),
        signer_verifying_keys(),
        0,
    )
    .expect("preload input");
    let metadata = CloudflareRootShareStartupMetadataV1::new(
        "other-signer-set",
        Role::SignerA,
        "signer-a",
        "key-epoch-a",
        root_epoch(),
        "sealed/share/a",
    )
    .expect("metadata");

    let err = build_cloudflare_preloaded_signer_host_v1(
        1_000,
        Role::SignerA,
        input,
        metadata,
        Vec::new(),
    )
    .expect_err("mismatched metadata must fail");

    assert_eq!(
        err.code(),
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig
    );
}

#[test]
fn preloaded_signer_host_rejects_non_local_root_metadata_role() {
    let input = CloudflareSignerHostPreloadInputV1::new(
        "signer-set-v1",
        root_epoch(),
        Vec::new(),
        signer_verifying_keys(),
        0,
    )
    .expect("preload input");

    let err = build_cloudflare_preloaded_signer_host_v1(
        1_000,
        Role::SignerA,
        input,
        root_share_metadata(Role::SignerB),
        Vec::new(),
    )
    .expect_err("wrong role metadata must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidRole);
}

#[test]
fn signer_host_preload_input_rejects_non_peer_response_kind() {
    let err = CloudflareSignerHostPreloadInputV1::new(
        "signer-set-v1",
        root_epoch(),
        vec![signer_private_request(WireMessageKindV1::RouterToSignerA)],
        signer_verifying_keys(),
        0,
    )
    .expect_err("Router-to-signer message cannot be preloaded as peer response");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidLocalRoute);
}

#[test]
fn preloaded_signer_host_rejects_random_length_mismatch() {
    let input = CloudflareSignerHostPreloadInputV1::new(
        "signer-set-v1",
        root_epoch(),
        Vec::new(),
        signer_verifying_keys(),
        2,
    )
    .expect("preload input");
    let err = build_cloudflare_preloaded_signer_host_v1(
        1_000,
        Role::SignerA,
        input,
        root_share_metadata(Role::SignerA),
        vec![0x42],
    )
    .expect_err("random length mismatch must fail");

    assert_eq!(
        err.code(),
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig
    );
}

#[test]
fn preloaded_signer_host_rejects_random_exhaustion() {
    let mut host = CloudflarePreloadedSignerHostV1::new(
        1_000,
        vec![root_share_metadata(Role::SignerA)],
        Vec::new(),
        signer_verifying_keys(),
        vec![0x42],
    )
    .expect("preloaded host");
    let mut random = [0u8; 2];
    let err = host
        .fill_random(&mut random)
        .expect_err("random buffer exhaustion must fail");

    assert_eq!(
        err.code(),
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig
    );
}

#[test]
fn preloaded_signer_host_rejects_missing_peer_response() {
    let host = CloudflarePreloadedSignerHostV1::new(
        1_000,
        vec![root_share_metadata(Role::SignerA)],
        Vec::new(),
        signer_verifying_keys(),
        vec![0x42, 0x43],
    )
    .expect("preloaded host");
    let request = signer_private_request(WireMessageKindV1::RouterToSignerA);
    let err = host
        .send_peer_message(request)
        .expect_err("missing peer response must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::MissingLocalBinding);
}

#[test]
fn durable_object_scope_rejects_non_signer_root_share_role() {
    let err = CloudflareDurableObjectScopeV1::signer_root_share(Role::Router)
        .expect_err("router role cannot own signer root-share scope");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidRole);
}

#[test]
fn durable_object_binding_rejects_non_signing_worker_server_output_owner() {
    let err = CloudflareDurableObjectBindingV1::new(
        CloudflareDurableObjectScopeV1::ServerOutput {
            owner_role: CloudflareWorkerRoleV1::DeriverB,
        },
        "BAD_SERVER_OUTPUT_DO",
        "bad-server-output",
        "bad-server-output:",
    )
    .expect_err("v1 server output must be owned by signing worker");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidRole);
}

#[test]
fn env_parser_builds_router_bindings_from_required_keys() {
    let parsed = parse_cloudflare_worker_bindings_v1(CloudflareWorkerRoleV1::Router, &router_env())
        .expect("router env");

    let CloudflareWorkerBindingsV1::Router { bindings } = parsed else {
        panic!("expected router bindings");
    };
    assert_eq!(bindings.replay.binding_name, "ROUTER_REPLAY_DO");
    assert_eq!(bindings.lifecycle.object_name, "router-lifecycle");
    assert_eq!(
        bindings.deriver_a.peer_role,
        CloudflareWorkerRoleV1::DeriverA
    );
    assert_eq!(bindings.deriver_b.binding_name, "DERIVER_B");
    assert_eq!(
        bindings.signing_worker.peer_role,
        CloudflareWorkerRoleV1::SigningWorker
    );
}

#[test]
fn env_parser_builds_deriver_a_bindings_from_required_keys() {
    let bindings = parse_cloudflare_deriver_a_bindings_v1(&deriver_a_env()).expect("signer a env");

    assert_eq!(bindings.root_share.binding_name, "DERIVER_A_ROOT_SHARE_DO");
    assert_eq!(
        bindings.root_share.scope,
        CloudflareDurableObjectScopeV1::SignerRootShare {
            role: Role::SignerA
        }
    );
    assert_eq!(
        bindings.root_share_wire_secret.binding_name,
        "DERIVER_A_ROOT_SHARE_WIRE_SECRET"
    );
    assert_eq!(bindings.root_share_wire_secret.role, Role::SignerA);
    assert_eq!(
        bindings.envelope_decrypt_key.current.binding_name,
        "DERIVER_A_ENVELOPE_HPKE_PRIVATE_KEY"
    );
    assert_eq!(
        bindings.envelope_decrypt_key.current.key_epoch,
        "envelope-hpke-key-epoch-a"
    );
    assert_eq!(
        bindings.envelope_decrypt_key.current.public_key,
        x25519_public_key(0x11)
    );
    assert_eq!(
        bindings.peer_signing_key.binding_name,
        "DERIVER_A_PEER_SIGNING_KEY"
    );
    assert_eq!(bindings.peer_signing_key.key_epoch, "key-epoch-a");
    assert_eq!(
        bindings
            .peer_verifying_keys
            .to_protocol_keys(&signer_set())
            .expect("signer a peer verifying keys"),
        signer_verifying_keys()
    );
}

#[test]
fn env_parser_builds_signing_worker_bindings_from_required_keys() {
    let bindings = parse_cloudflare_signing_worker_bindings_v1(&signing_worker_env())
        .expect("signing worker env");

    assert_eq!(
        bindings.server_output.scope,
        CloudflareDurableObjectScopeV1::signing_worker_server_output()
    );
    assert_eq!(
        bindings.server_output_decrypt_key.binding_name,
        "SIGNING_WORKER_SERVER_OUTPUT_HPKE_PRIVATE_KEY"
    );
    assert_eq!(bindings.server_output_decrypt_key.key_epoch, "server-epoch");
    assert_eq!(
        bindings.server_output_decrypt_key.public_key,
        signer_set().selected_server.recipient_encryption_key
    );
}

#[test]
fn env_parser_builds_deriver_b_bindings_from_required_keys() {
    let bindings = parse_cloudflare_deriver_b_bindings_v1(&deriver_b_env()).expect("signer b env");

    assert_eq!(bindings.root_share.binding_name, "DERIVER_B_ROOT_SHARE_DO");
    assert_eq!(
        bindings.root_share.scope,
        CloudflareDurableObjectScopeV1::SignerRootShare {
            role: Role::SignerB
        }
    );
    assert_eq!(
        bindings.deriver_a.peer_role,
        CloudflareWorkerRoleV1::DeriverA
    );
    assert_eq!(
        bindings.root_share_wire_secret.binding_name,
        "DERIVER_B_ROOT_SHARE_WIRE_SECRET"
    );
    assert_eq!(bindings.root_share_wire_secret.role, Role::SignerB);
    assert_eq!(
        bindings.envelope_decrypt_key.current.binding_name,
        "DERIVER_B_ENVELOPE_HPKE_PRIVATE_KEY"
    );
    assert_eq!(
        bindings.envelope_decrypt_key.current.key_epoch,
        "envelope-hpke-key-epoch-b"
    );
    assert_eq!(
        bindings.envelope_decrypt_key.current.public_key,
        x25519_public_key(0x22)
    );
    assert_eq!(
        bindings.peer_signing_key.binding_name,
        "DERIVER_B_PEER_SIGNING_KEY"
    );
    assert_eq!(bindings.peer_signing_key.key_epoch, "key-epoch-b");
    assert_eq!(
        bindings
            .peer_verifying_keys
            .to_protocol_keys(&signer_set())
            .expect("signer b peer verifying keys"),
        signer_verifying_keys()
    );
}

#[test]
fn env_parser_rejects_router_with_signer_envelope_hpke_private_key_binding() {
    let env = CloudflareEnvMapV1::new(vec![(
        DERIVER_A_ENVELOPE_HPKE_PRIVATE_KEY_BINDING_ENV,
        "DERIVER_A_ENVELOPE_HPKE_PRIVATE_KEY",
    )]);

    let err = parse_cloudflare_worker_bindings_v1(CloudflareWorkerRoleV1::Router, &env)
        .expect_err("router must reject signer hpke private key env");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::ForbiddenLocalBinding);
}

#[test]
fn env_parser_rejects_router_with_signer_peer_signing_key_binding() {
    let env = CloudflareEnvMapV1::new(vec![(
        DERIVER_A_PEER_SIGNING_KEY_BINDING_ENV,
        "DERIVER_A_PEER_SIGNING_KEY",
    )]);

    let err = parse_cloudflare_worker_bindings_v1(CloudflareWorkerRoleV1::Router, &env)
        .expect_err("router must reject signer peer signing key env");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::ForbiddenLocalBinding);
}

#[test]
fn env_parser_rejects_router_with_signer_root_share_wire_secret_binding() {
    let env = CloudflareEnvMapV1::new(vec![(
        DERIVER_A_ROOT_SHARE_WIRE_SECRET_BINDING_ENV,
        "DERIVER_A_ROOT_SHARE_WIRE_SECRET",
    )]);

    let err = parse_cloudflare_worker_bindings_v1(CloudflareWorkerRoleV1::Router, &env)
        .expect_err("router must reject signer root-share wire secret env");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::ForbiddenLocalBinding);
}

#[test]
fn env_parser_rejects_deriver_a_with_deriver_b_envelope_hpke_private_key_binding() {
    let env = CloudflareEnvMapV1::new(vec![(
        DERIVER_B_ENVELOPE_HPKE_PRIVATE_KEY_BINDING_ENV,
        "DERIVER_B_ENVELOPE_HPKE_PRIVATE_KEY",
    )]);

    let err = parse_cloudflare_worker_bindings_v1(CloudflareWorkerRoleV1::DeriverA, &env)
        .expect_err("signer a must reject signer b hpke private key env");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::ForbiddenLocalBinding);
}

#[test]
fn env_parser_rejects_deriver_a_with_deriver_b_peer_signing_key_binding() {
    let env = CloudflareEnvMapV1::new(vec![(
        DERIVER_B_PEER_SIGNING_KEY_BINDING_ENV,
        "DERIVER_B_PEER_SIGNING_KEY",
    )]);

    let err = parse_cloudflare_worker_bindings_v1(CloudflareWorkerRoleV1::DeriverA, &env)
        .expect_err("signer a must reject signer b peer signing key env");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::ForbiddenLocalBinding);
}

#[test]
fn env_parser_rejects_deriver_a_with_deriver_b_root_share_wire_secret_binding() {
    let env = CloudflareEnvMapV1::new(vec![(
        DERIVER_B_ROOT_SHARE_WIRE_SECRET_BINDING_ENV,
        "DERIVER_B_ROOT_SHARE_WIRE_SECRET",
    )]);

    let err = parse_cloudflare_worker_bindings_v1(CloudflareWorkerRoleV1::DeriverA, &env)
        .expect_err("signer a must reject signer b root-share wire secret env");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::ForbiddenLocalBinding);
}

#[test]
fn env_parser_rejects_deriver_b_with_deriver_a_envelope_hpke_private_key_binding() {
    let env = CloudflareEnvMapV1::new(vec![(
        DERIVER_A_ENVELOPE_HPKE_PRIVATE_KEY_BINDING_ENV,
        "DERIVER_A_ENVELOPE_HPKE_PRIVATE_KEY",
    )]);

    let err = parse_cloudflare_worker_bindings_v1(CloudflareWorkerRoleV1::DeriverB, &env)
        .expect_err("signer b must reject signer a hpke private key env");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::ForbiddenLocalBinding);
}

#[test]
fn env_parser_rejects_deriver_b_with_deriver_a_peer_signing_key_binding() {
    let env = CloudflareEnvMapV1::new(vec![(
        DERIVER_A_PEER_SIGNING_KEY_BINDING_ENV,
        "DERIVER_A_PEER_SIGNING_KEY",
    )]);

    let err = parse_cloudflare_worker_bindings_v1(CloudflareWorkerRoleV1::DeriverB, &env)
        .expect_err("signer b must reject signer a peer signing key env");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::ForbiddenLocalBinding);
}

#[test]
fn env_parser_rejects_deriver_b_with_deriver_a_root_share_wire_secret_binding() {
    let env = CloudflareEnvMapV1::new(vec![(
        DERIVER_A_ROOT_SHARE_WIRE_SECRET_BINDING_ENV,
        "DERIVER_A_ROOT_SHARE_WIRE_SECRET",
    )]);

    let err = parse_cloudflare_worker_bindings_v1(CloudflareWorkerRoleV1::DeriverB, &env)
        .expect_err("signer b must reject signer a root-share wire secret env");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::ForbiddenLocalBinding);
}

#[test]
fn env_parser_rejects_missing_required_key() {
    let env = CloudflareEnvMapV1::new(vec![
        (ROUTER_REPLAY_DO_BINDING_ENV, "ROUTER_REPLAY_DO"),
        (ROUTER_REPLAY_DO_OBJECT_ENV, "router-replay"),
        (ROUTER_REPLAY_DO_KEY_PREFIX_ENV, "router-replay:"),
        (ROUTER_LIFECYCLE_DO_BINDING_ENV, "ROUTER_LIFECYCLE_DO"),
        (ROUTER_LIFECYCLE_DO_OBJECT_ENV, "router-lifecycle"),
        (ROUTER_LIFECYCLE_DO_KEY_PREFIX_ENV, "router-lifecycle:"),
        (DERIVER_A_PEER_BINDING_ENV, "DERIVER_A"),
    ]);

    let err = parse_cloudflare_worker_bindings_v1(CloudflareWorkerRoleV1::Router, &env)
        .expect_err("missing signer b peer must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::MissingLocalBinding);
}

#[test]
fn env_parser_rejects_empty_required_key_after_trimming() {
    let env = CloudflareEnvMapV1::new(vec![
        (
            DERIVER_B_ROOT_SHARE_DO_BINDING_ENV,
            "DERIVER_B_ROOT_SHARE_DO",
        ),
        (DERIVER_B_ROOT_SHARE_DO_OBJECT_ENV, "  "),
        (
            DERIVER_B_ROOT_SHARE_DO_KEY_PREFIX_ENV,
            "deriver-b-root-share:",
        ),
        (DERIVER_A_PEER_BINDING_ENV, "DERIVER_A"),
    ]);

    let err = parse_cloudflare_worker_bindings_v1(CloudflareWorkerRoleV1::DeriverB, &env)
        .expect_err("empty object name must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::EmptyField);
}

#[test]
fn env_parser_rejects_router_env_with_signer_root_share_key() {
    let env = CloudflareEnvMapV1::new(vec![
        (ROUTER_REPLAY_DO_BINDING_ENV, "ROUTER_REPLAY_DO"),
        (ROUTER_REPLAY_DO_OBJECT_ENV, "router-replay"),
        (ROUTER_REPLAY_DO_KEY_PREFIX_ENV, "router-replay:"),
        (ROUTER_LIFECYCLE_DO_BINDING_ENV, "ROUTER_LIFECYCLE_DO"),
        (ROUTER_LIFECYCLE_DO_OBJECT_ENV, "router-lifecycle"),
        (ROUTER_LIFECYCLE_DO_KEY_PREFIX_ENV, "router-lifecycle:"),
        (DERIVER_A_PEER_BINDING_ENV, "DERIVER_A"),
        (DERIVER_B_PEER_BINDING_ENV, "DERIVER_B"),
        (
            DERIVER_A_ROOT_SHARE_DO_BINDING_ENV,
            "DERIVER_A_ROOT_SHARE_DO",
        ),
    ]);

    let err = parse_cloudflare_worker_bindings_v1(CloudflareWorkerRoleV1::Router, &env)
        .expect_err("router env must reject signer storage key");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::ForbiddenLocalBinding);
}

#[test]
fn env_parser_rejects_signer_env_with_router_admission_key() {
    let env = CloudflareEnvMapV1::new(vec![(ROUTER_JWT_ISSUER_ENV, "https://issuer.example")]);

    let err = parse_cloudflare_worker_bindings_v1(CloudflareWorkerRoleV1::DeriverA, &env)
        .expect_err("signer env must reject router admission key");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::ForbiddenLocalBinding);
}

#[test]
fn env_parser_rejects_deriver_a_env_with_deriver_b_root_share_key() {
    let env = CloudflareEnvMapV1::new(vec![
        (
            DERIVER_A_ROOT_SHARE_DO_BINDING_ENV,
            "DERIVER_A_ROOT_SHARE_DO",
        ),
        (DERIVER_A_ROOT_SHARE_DO_OBJECT_ENV, "deriver-a-root-share"),
        (
            DERIVER_A_ROOT_SHARE_DO_KEY_PREFIX_ENV,
            "deriver-a-root-share:",
        ),
        (
            SIGNING_WORKER_SERVER_OUTPUT_DO_BINDING_ENV,
            "SIGNING_WORKER_SERVER_OUTPUT_DO",
        ),
        (
            SIGNING_WORKER_SERVER_OUTPUT_DO_OBJECT_ENV,
            "signer-a-server-output",
        ),
        (
            SIGNING_WORKER_SERVER_OUTPUT_DO_KEY_PREFIX_ENV,
            "signer-a-server-output:",
        ),
        (DERIVER_B_PEER_BINDING_ENV, "DERIVER_B"),
        (
            DERIVER_B_ROOT_SHARE_DO_BINDING_ENV,
            "DERIVER_B_ROOT_SHARE_DO",
        ),
    ]);

    let err = parse_cloudflare_worker_bindings_v1(CloudflareWorkerRoleV1::DeriverA, &env)
        .expect_err("signer a env must reject signer b storage key");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::ForbiddenLocalBinding);
}

#[test]
fn env_parser_rejects_deriver_b_env_with_server_output_key() {
    let env = CloudflareEnvMapV1::new(vec![
        (
            DERIVER_B_ROOT_SHARE_DO_BINDING_ENV,
            "DERIVER_B_ROOT_SHARE_DO",
        ),
        (DERIVER_B_ROOT_SHARE_DO_OBJECT_ENV, "deriver-b-root-share"),
        (
            DERIVER_B_ROOT_SHARE_DO_KEY_PREFIX_ENV,
            "deriver-b-root-share:",
        ),
        (DERIVER_A_PEER_BINDING_ENV, "DERIVER_A"),
        (
            SIGNING_WORKER_SERVER_OUTPUT_DO_BINDING_ENV,
            "SIGNING_WORKER_SERVER_OUTPUT_DO",
        ),
    ]);

    let err = parse_cloudflare_worker_bindings_v1(CloudflareWorkerRoleV1::DeriverB, &env)
        .expect_err("signer b env must reject server-output key");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::ForbiddenLocalBinding);
}

#[test]
fn durable_object_call_routes_root_share_has_to_signer_scope() {
    let lookup =
        CloudflareRootShareLookupRequestV1::new("signer-set-v1", Role::SignerA, root_epoch())
            .expect("lookup");
    let request = CloudflareDurableObjectRequestV1::root_share_has(lookup).expect("request");
    let call = CloudflareDurableObjectCallV1::new(
        CloudflareWorkerRoleV1::DeriverA,
        deriver_a_root_binding(),
        request,
    )
    .expect("call");

    assert_eq!(
        call.operation_kind(),
        CloudflareDurableObjectOperationKindV1::RootShareHas
    );
    assert_eq!(
        call.durable_object_url(),
        "https://router-ab-durable-object.internal/router-ab/do/root-share/has"
    );
    assert_eq!(
        call.storage_key(),
        "DERIVER_A_ROOT_SHARE_DO:root-share/signer-set-v1/signer_a/epoch-1"
    );
}

#[test]
fn durable_object_call_rejects_router_access_to_signer_root_share() {
    let lookup =
        CloudflareRootShareLookupRequestV1::new("signer-set-v1", Role::SignerA, root_epoch())
            .expect("lookup");
    let request = CloudflareDurableObjectRequestV1::root_share_has(lookup).expect("request");
    let err = CloudflareDurableObjectCallV1::new(
        CloudflareWorkerRoleV1::Router,
        deriver_a_root_binding(),
        request,
    )
    .expect_err("router must not call signer root-share Durable Object");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::ForbiddenLocalBinding);
}

#[test]
fn durable_object_call_rejects_operation_scope_mismatch() {
    let lookup =
        CloudflareRootShareLookupRequestV1::new("signer-set-v1", Role::SignerA, root_epoch())
            .expect("lookup");
    let request = CloudflareDurableObjectRequestV1::root_share_has(lookup).expect("request");
    let err = CloudflareDurableObjectCallV1::new(
        CloudflareWorkerRoleV1::DeriverB,
        deriver_b_root_binding(),
        request,
    )
    .expect_err("signer b binding cannot serve signer a lookup");

    assert_eq!(
        err.code(),
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig
    );
}

#[test]
fn durable_object_call_routes_router_replay_and_lifecycle_state() {
    let replay = CloudflareReplayReserveRequestV1::new("request-1", digest(0x11), 1000)
        .expect("replay request");
    let replay_call = CloudflareDurableObjectCallV1::new(
        CloudflareWorkerRoleV1::Router,
        do_binding(
            CloudflareDurableObjectScopeV1::RouterReplay,
            "ROUTER_REPLAY_DO",
        ),
        CloudflareDurableObjectRequestV1::router_replay_reserve(replay).expect("replay op"),
    )
    .expect("replay call");

    assert_eq!(
        replay_call.storage_key(),
        "ROUTER_REPLAY_DO:replay/request-1/1111111111111111111111111111111111111111111111111111111111111111"
    );

    let lifecycle_call = CloudflareDurableObjectCallV1::new(
        CloudflareWorkerRoleV1::Router,
        do_binding(
            CloudflareDurableObjectScopeV1::RouterLifecycle,
            "ROUTER_LIFECYCLE_DO",
        ),
        CloudflareDurableObjectRequestV1::router_lifecycle_put_public_state(lifecycle_state())
            .expect("lifecycle op"),
    )
    .expect("lifecycle call");

    assert_eq!(
        lifecycle_call.operation_kind(),
        CloudflareDurableObjectOperationKindV1::RouterLifecyclePutPublicState
    );
    assert_eq!(
        lifecycle_call.storage_key(),
        "ROUTER_LIFECYCLE_DO:lifecycle/lifecycle-1"
    );

    let ceremony_call = CloudflareDurableObjectCallV1::new(
        CloudflareWorkerRoleV1::Router,
        do_binding(
            CloudflareDurableObjectScopeV1::RouterLifecycle,
            "ROUTER_LIFECYCLE_DO",
        ),
        CloudflareDurableObjectRequestV1::derivation_ceremony_put_state(
            created_derivation_ceremony(),
        )
        .expect("ceremony op"),
    )
    .expect("ceremony call");

    assert_eq!(
        ceremony_call.operation_kind(),
        CloudflareDurableObjectOperationKindV1::DerivationCeremonyPutState
    );
    assert_eq!(
        ceremony_call.storage_key(),
        "ROUTER_LIFECYCLE_DO:derivation-ceremony/lifecycle-1"
    );
}

#[test]
fn durable_object_call_routes_server_activation_to_signing_worker_scope() {
    let activation = signing_worker_activation();
    let material = server_output_material_record(&activation);
    let expected_storage_key = format!(
        "SIGNING_WORKER_SERVER_OUTPUT_DO:signing-worker-output/lifecycle-1/{}",
        digest_hex(activation.activation_context.transcript_digest())
    );
    let request = CloudflareDurableObjectRequestV1::signing_worker_output_activate(
        activation.clone(),
        material,
        TEST_ACTIVATED_AT_MS,
    )
    .expect("activation request");
    let call = CloudflareDurableObjectCallV1::new(
        CloudflareWorkerRoleV1::SigningWorker,
        server_output_binding(),
        request,
    )
    .expect("activation call");

    assert_eq!(
        call.operation_kind(),
        CloudflareDurableObjectOperationKindV1::SigningWorkerOutputActivate
    );
    assert_eq!(call.storage_key(), expected_storage_key);
    assert_eq!(
        call.active_signing_worker_state_index_storage_key()
            .expect("active SigningWorker index key"),
        "SIGNING_WORKER_SERVER_OUTPUT_DO:active-signing-worker/account.near/session-1/server-a"
    );

    let lookup =
        CloudflareActiveSigningWorkerStateLookupV1::new("account.near", "session-1", "server-a")
            .expect("active SigningWorker lookup");
    let lookup_call = CloudflareDurableObjectCallV1::new(
        CloudflareWorkerRoleV1::SigningWorker,
        server_output_binding(),
        CloudflareDurableObjectRequestV1::signing_worker_output_active_state_get(lookup)
            .expect("lookup request"),
    )
    .expect("lookup call");
    assert_eq!(
        lookup_call.operation_kind(),
        CloudflareDurableObjectOperationKindV1::SigningWorkerOutputActiveStateGet
    );
    assert_eq!(
        lookup_call.storage_key(),
        "SIGNING_WORKER_SERVER_OUTPUT_DO:active-signing-worker/account.near/session-1/server-a"
    );

    let material_lookup = router_ab_cloudflare::CloudflareSigningWorkerOutputMaterialLookupV1::new(
        active_signing_worker_state_for_activation(&activation, expected_storage_key.clone()),
    )
    .expect("material lookup");
    let material_lookup_call = CloudflareDurableObjectCallV1::new(
        CloudflareWorkerRoleV1::SigningWorker,
        server_output_binding(),
        CloudflareDurableObjectRequestV1::signing_worker_output_material_get(material_lookup)
            .expect("material lookup request"),
    )
    .expect("material lookup call");
    assert_eq!(
        material_lookup_call.operation_kind(),
        CloudflareDurableObjectOperationKindV1::SigningWorkerOutputMaterialGet
    );
    assert_eq!(material_lookup_call.storage_key(), expected_storage_key);
}

#[test]
fn durable_object_call_routes_signing_worker_round1_to_server_output_scope() {
    let record = normal_signing_round1_record();
    let put_call = CloudflareDurableObjectCallV1::new(
        CloudflareWorkerRoleV1::SigningWorker,
        server_output_binding(),
        CloudflareDurableObjectRequestV1::signing_worker_round1_put(record)
            .expect("round1 put request"),
    )
    .expect("round1 put call");

    assert_eq!(
        put_call.operation_kind(),
        CloudflareDurableObjectOperationKindV1::SigningWorkerRound1Put
    );
    assert_eq!(
        put_call.storage_key(),
        "SIGNING_WORKER_SERVER_OUTPUT_DO:signing-worker-round1/account.near/session-1/server-a/server-round1/sign-request-1"
    );

    let take_call = CloudflareDurableObjectCallV1::new(
        CloudflareWorkerRoleV1::SigningWorker,
        server_output_binding(),
        CloudflareDurableObjectRequestV1::signing_worker_round1_take(normal_signing_round1_lookup(
            1_500,
        ))
        .expect("round1 take request"),
    )
    .expect("round1 take call");
    assert_eq!(
        take_call.operation_kind(),
        CloudflareDurableObjectOperationKindV1::SigningWorkerRound1Take
    );
    assert_eq!(take_call.storage_key(), put_call.storage_key());
}

#[test]
fn durable_object_request_rejects_non_signer_root_share_lookup() {
    let err = CloudflareRootShareLookupRequestV1::new("signer-set-v1", Role::Router, root_epoch())
        .expect_err("root-share lookup must require signer role");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidRole);
}

#[test]
fn durable_object_request_rejects_zero_replay_expiry() {
    let err = CloudflareReplayReserveRequestV1::new("request-1", digest(0x11), 0)
        .expect_err("zero expiry must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidTimeRange);
}

#[test]
fn durable_object_response_validates_metadata_matches_lookup() {
    let lookup =
        CloudflareRootShareLookupRequestV1::new("signer-set-v1", Role::SignerA, root_epoch())
            .expect("lookup");
    let request = CloudflareDurableObjectRequestV1::root_share_startup_metadata(lookup)
        .expect("metadata request");
    let metadata = CloudflareRootShareStartupMetadataV1::new(
        "signer-set-v1",
        Role::SignerA,
        "signer-a",
        "key-epoch-1",
        root_epoch(),
        "sealed/share/a",
    )
    .expect("metadata");
    let response = CloudflareDurableObjectResponseV1::root_share_startup_metadata(metadata)
        .expect("metadata response");

    response
        .validate_for_request(&request)
        .expect("matching metadata response");
}

#[test]
fn durable_object_response_rejects_mismatched_replay_request_id() {
    let request = CloudflareDurableObjectRequestV1::router_replay_reserve(
        CloudflareReplayReserveRequestV1::new("request-1", digest(0x11), 1000)
            .expect("replay request"),
    )
    .expect("request");
    let response = CloudflareDurableObjectResponseV1::router_replay_reserve(
        CloudflareReplayReserveResponseV1::new("request-2", true).expect("replay response"),
    )
    .expect("response");

    let err = response
        .validate_for_request(&request)
        .expect_err("mismatched request id must fail");

    assert_eq!(
        err.code(),
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig
    );
}

#[test]
fn durable_object_response_rejects_mismatched_response_branch() {
    let request =
        CloudflareDurableObjectRequestV1::router_lifecycle_put_public_state(lifecycle_state())
            .expect("request");
    let response = CloudflareDurableObjectResponseV1::router_replay_reserve(
        CloudflareReplayReserveResponseV1::new("request-1", true).expect("replay response"),
    )
    .expect("response");

    let err = response
        .validate_for_request(&request)
        .expect_err("wrong response branch must fail");

    assert_eq!(
        err.code(),
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig
    );
}

#[test]
fn durable_object_response_validates_server_activation_receipt() {
    let activation = signing_worker_activation();
    let material = server_output_material_record(&activation);
    let receipt_digest = activation.activation_context.transcript_digest();
    let request = CloudflareDurableObjectRequestV1::signing_worker_output_activate(
        activation.clone(),
        material,
        TEST_ACTIVATED_AT_MS,
    )
    .expect("request");
    let active_signing_worker_state =
        active_signing_worker_state_for_activation(&activation, "test-server-material");
    let response = CloudflareDurableObjectResponseV1::signing_worker_output_activate(
        CloudflareSigningWorkerOutputActivationReceiptV1::new(
            "lifecycle-1",
            "server-a",
            receipt_digest,
            active_signing_worker_state,
            true,
        )
        .expect("receipt"),
    )
    .expect("response");

    response
        .validate_for_request(&request)
        .expect("matching activation response");
}

#[test]
fn durable_object_response_validates_lifecycle_receipt() {
    let request =
        CloudflareDurableObjectRequestV1::router_lifecycle_put_public_state(lifecycle_state())
            .expect("request");
    let response = CloudflareDurableObjectResponseV1::router_lifecycle_put_public_state(
        CloudflareLifecyclePutReceiptV1::new("lifecycle-1", true).expect("receipt"),
    )
    .expect("response");

    response
        .validate_for_request(&request)
        .expect("matching lifecycle response");
}

#[test]
fn durable_object_response_validates_derivation_ceremony_receipt() {
    let ceremony = created_derivation_ceremony();
    let request = CloudflareDurableObjectRequestV1::derivation_ceremony_put_state(ceremony.clone())
        .expect("request");
    let response = CloudflareDurableObjectResponseV1::derivation_ceremony_put_state(
        CloudflareDerivationCeremonyPutReceiptV1::new(
            "lifecycle-1",
            CloudflareDerivationCeremonyStateLabelV1::Created,
            true,
        )
        .expect("receipt"),
    )
    .expect("response");

    response
        .validate_for_request(&request)
        .expect("matching ceremony response");

    let mismatched = CloudflareDurableObjectResponseV1::derivation_ceremony_put_state(
        CloudflareDerivationCeremonyPutReceiptV1::new(
            "lifecycle-1",
            CloudflareDerivationCeremonyStateLabelV1::Activated,
            true,
        )
        .expect("mismatched receipt"),
    )
    .expect("mismatched response");
    let err = mismatched
        .validate_for_request(&request)
        .expect_err("mismatched ceremony state must fail");

    assert_eq!(
        err.code(),
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig
    );
}

#[test]
fn durable_object_handler_serves_root_share_presence_and_metadata() {
    let lookup =
        CloudflareRootShareLookupRequestV1::new("signer-set-v1", Role::SignerA, root_epoch())
            .expect("lookup");
    let has_request =
        CloudflareDurableObjectRequestV1::root_share_has(lookup.clone()).expect("has request");
    let has_call = CloudflareDurableObjectCallV1::new(
        CloudflareWorkerRoleV1::DeriverA,
        deriver_a_root_binding(),
        has_request,
    )
    .expect("has call");
    let metadata_request = CloudflareDurableObjectRequestV1::root_share_startup_metadata(lookup)
        .expect("metadata request");
    let metadata_call = CloudflareDurableObjectCallV1::new(
        CloudflareWorkerRoleV1::DeriverA,
        deriver_a_root_binding(),
        metadata_request,
    )
    .expect("metadata call");
    let metadata = CloudflareRootShareStartupMetadataV1::new(
        "signer-set-v1",
        Role::SignerA,
        "signer-a",
        "key-epoch-1",
        root_epoch(),
        "sealed/share/a",
    )
    .expect("metadata");
    let mut storage = CloudflareDurableObjectMemoryStorageV1::new();

    let missing = handle_cloudflare_durable_object_call_v1(&has_call, &mut storage)
        .expect("missing has response");
    assert_eq!(
        missing,
        CloudflareDurableObjectResponseV1::root_share_has(false)
    );

    storage
        .seed_root_share_startup_metadata(metadata_call.storage_key(), metadata.clone())
        .expect("seed metadata");

    let present = handle_cloudflare_durable_object_call_v1(&has_call, &mut storage)
        .expect("present has response");
    assert_eq!(
        present,
        CloudflareDurableObjectResponseV1::root_share_has(true)
    );

    let loaded = handle_cloudflare_durable_object_call_v1(&metadata_call, &mut storage)
        .expect("metadata response");
    assert_eq!(
        loaded,
        CloudflareDurableObjectResponseV1::root_share_startup_metadata(metadata)
            .expect("expected metadata response")
    );
}

#[test]
fn durable_object_handler_rewraps_root_share_startup_metadata_storage_key() {
    let lookup =
        CloudflareRootShareLookupRequestV1::new("signer-set-v1", Role::SignerA, root_epoch())
            .expect("lookup");
    let existing = CloudflareRootShareStartupMetadataV1::new(
        "signer-set-v1",
        Role::SignerA,
        "signer-a",
        "key-epoch-1",
        root_epoch(),
        "sealed/share/a",
    )
    .expect("existing metadata");
    let replacement = CloudflareRootShareStartupMetadataV1::new(
        "signer-set-v1",
        Role::SignerA,
        "signer-a",
        "key-epoch-1",
        root_epoch(),
        "sealed/share/a/rewrapped",
    )
    .expect("rewrapped metadata");
    let rewrap_request =
        CloudflareRootShareRewrapRequestV1::new(lookup.clone(), replacement.clone(), 2_000)
            .expect("rewrap request");
    let rewrap_call = CloudflareDurableObjectCallV1::new(
        CloudflareWorkerRoleV1::DeriverA,
        deriver_a_root_binding(),
        CloudflareDurableObjectRequestV1::root_share_rewrap_startup_metadata(rewrap_request)
            .expect("rewrap operation"),
    )
    .expect("rewrap call");
    let metadata_call = CloudflareDurableObjectCallV1::new(
        CloudflareWorkerRoleV1::DeriverA,
        deriver_a_root_binding(),
        CloudflareDurableObjectRequestV1::root_share_startup_metadata(lookup)
            .expect("metadata operation"),
    )
    .expect("metadata call");
    let mut storage = CloudflareDurableObjectMemoryStorageV1::new();
    storage
        .seed_root_share_startup_metadata(rewrap_call.storage_key(), existing.clone())
        .expect("seed existing metadata");

    let response = handle_cloudflare_durable_object_call_v1(&rewrap_call, &mut storage)
        .expect("rewrap response");
    let CloudflareDurableObjectResponseV1::RootShareRewrapStartupMetadata { receipt } = response
    else {
        panic!("expected root-share rewrap receipt");
    };
    assert_eq!(
        receipt.previous_sealed_share_storage_key,
        existing.sealed_share_storage_key
    );
    assert_eq!(
        receipt.replacement_sealed_share_storage_key,
        replacement.sealed_share_storage_key
    );
    assert_eq!(receipt.rewrapped_at_ms, 2_000);

    let loaded = handle_cloudflare_durable_object_call_v1(&metadata_call, &mut storage)
        .expect("metadata response after rewrap");
    assert_eq!(
        loaded,
        CloudflareDurableObjectResponseV1::root_share_startup_metadata(replacement)
            .expect("expected replacement metadata response")
    );
}

#[test]
fn durable_object_handler_rejects_root_share_rewrap_identity_drift() {
    let lookup =
        CloudflareRootShareLookupRequestV1::new("signer-set-v1", Role::SignerA, root_epoch())
            .expect("lookup");
    let existing = CloudflareRootShareStartupMetadataV1::new(
        "signer-set-v1",
        Role::SignerA,
        "signer-a",
        "key-epoch-1",
        root_epoch(),
        "sealed/share/a",
    )
    .expect("existing metadata");
    let replacement = CloudflareRootShareStartupMetadataV1::new(
        "signer-set-v1",
        Role::SignerA,
        "signer-a",
        "key-epoch-2",
        root_epoch(),
        "sealed/share/a/rewrapped",
    )
    .expect("identity-drift replacement metadata");
    let rewrap_call = CloudflareDurableObjectCallV1::new(
        CloudflareWorkerRoleV1::DeriverA,
        deriver_a_root_binding(),
        CloudflareDurableObjectRequestV1::root_share_rewrap_startup_metadata(
            CloudflareRootShareRewrapRequestV1::new(lookup, replacement, 2_000)
                .expect("rewrap request"),
        )
        .expect("rewrap operation"),
    )
    .expect("rewrap call");
    let mut storage = CloudflareDurableObjectMemoryStorageV1::new();
    storage
        .seed_root_share_startup_metadata(rewrap_call.storage_key(), existing)
        .expect("seed existing metadata");

    let err = handle_cloudflare_durable_object_call_v1(&rewrap_call, &mut storage)
        .expect_err("identity drift must fail");
    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidSignerIdentity);
}

#[test]
fn durable_object_handler_rejects_root_share_rewrap_same_storage_key() {
    let lookup =
        CloudflareRootShareLookupRequestV1::new("signer-set-v1", Role::SignerA, root_epoch())
            .expect("lookup");
    let existing = CloudflareRootShareStartupMetadataV1::new(
        "signer-set-v1",
        Role::SignerA,
        "signer-a",
        "key-epoch-1",
        root_epoch(),
        "sealed/share/a",
    )
    .expect("existing metadata");
    let rewrap_call = CloudflareDurableObjectCallV1::new(
        CloudflareWorkerRoleV1::DeriverA,
        deriver_a_root_binding(),
        CloudflareDurableObjectRequestV1::root_share_rewrap_startup_metadata(
            CloudflareRootShareRewrapRequestV1::new(lookup, existing.clone(), 2_000)
                .expect("same-key rewrap request"),
        )
        .expect("rewrap operation"),
    )
    .expect("rewrap call");
    let mut storage = CloudflareDurableObjectMemoryStorageV1::new();
    storage
        .seed_root_share_startup_metadata(rewrap_call.storage_key(), existing)
        .expect("seed existing metadata");

    let err = handle_cloudflare_durable_object_call_v1(&rewrap_call, &mut storage)
        .expect_err("same storage key must fail");
    assert_eq!(
        err.code(),
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig
    );
}

#[test]
fn durable_object_request_rejects_root_share_rewrap_scope_drift() {
    let lookup =
        CloudflareRootShareLookupRequestV1::new("signer-set-v1", Role::SignerA, root_epoch())
            .expect("lookup");
    let replacement = CloudflareRootShareStartupMetadataV1::new(
        "signer-set-v1",
        Role::SignerA,
        "signer-a",
        "key-epoch-1",
        next_root_epoch(),
        "sealed/share/a/rewrapped",
    )
    .expect("scope-drift replacement metadata");

    let err = CloudflareRootShareRewrapRequestV1::new(lookup, replacement, 2_000)
        .expect_err("root-share rewrap scope drift must fail");
    assert_eq!(
        err.code(),
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig
    );
}

#[test]
fn durable_object_handler_rejects_stale_root_share_epoch_after_epoch_advance() {
    let old_lookup =
        CloudflareRootShareLookupRequestV1::new("signer-set-v1", Role::SignerA, root_epoch())
            .expect("old epoch lookup");
    let next_lookup =
        CloudflareRootShareLookupRequestV1::new("signer-set-v1", Role::SignerA, next_root_epoch())
            .expect("next epoch lookup");
    let old_has_call = CloudflareDurableObjectCallV1::new(
        CloudflareWorkerRoleV1::DeriverA,
        deriver_a_root_binding(),
        CloudflareDurableObjectRequestV1::root_share_has(old_lookup.clone())
            .expect("old epoch has request"),
    )
    .expect("old epoch has call");
    let old_metadata_call = CloudflareDurableObjectCallV1::new(
        CloudflareWorkerRoleV1::DeriverA,
        deriver_a_root_binding(),
        CloudflareDurableObjectRequestV1::root_share_startup_metadata(old_lookup)
            .expect("old epoch metadata request"),
    )
    .expect("old epoch metadata call");
    let next_metadata_call = CloudflareDurableObjectCallV1::new(
        CloudflareWorkerRoleV1::DeriverA,
        deriver_a_root_binding(),
        CloudflareDurableObjectRequestV1::root_share_startup_metadata(next_lookup)
            .expect("next epoch metadata request"),
    )
    .expect("next epoch metadata call");
    let next_metadata = CloudflareRootShareStartupMetadataV1::new(
        "signer-set-v1",
        Role::SignerA,
        "signer-a",
        "key-epoch-2",
        next_root_epoch(),
        "sealed/share/a/epoch-2",
    )
    .expect("next epoch metadata");
    let mut storage = CloudflareDurableObjectMemoryStorageV1::new();
    storage
        .seed_root_share_startup_metadata(next_metadata_call.storage_key(), next_metadata.clone())
        .expect("seed next epoch metadata");

    let stale_presence = handle_cloudflare_durable_object_call_v1(&old_has_call, &mut storage)
        .expect("stale old epoch presence check");
    assert_eq!(
        stale_presence,
        CloudflareDurableObjectResponseV1::root_share_has(false)
    );

    let stale_metadata_err =
        handle_cloudflare_durable_object_call_v1(&old_metadata_call, &mut storage)
            .expect_err("stale old epoch metadata must be missing");
    assert_eq!(
        stale_metadata_err.code(),
        RouterAbProtocolErrorCode::MissingLocalBinding
    );

    let loaded_next = handle_cloudflare_durable_object_call_v1(&next_metadata_call, &mut storage)
        .expect("next epoch metadata response");
    assert_eq!(
        loaded_next,
        CloudflareDurableObjectResponseV1::root_share_startup_metadata(next_metadata.clone())
            .expect("expected next epoch metadata response")
    );

    let mut misindexed_storage = CloudflareDurableObjectMemoryStorageV1::new();
    misindexed_storage
        .seed_root_share_startup_metadata(old_metadata_call.storage_key(), next_metadata)
        .expect("seed misindexed next epoch metadata");
    let err = handle_cloudflare_durable_object_call_v1(&old_has_call, &mut misindexed_storage)
        .expect_err("old epoch lookup must reject misindexed next epoch metadata");
    assert_eq!(
        err.code(),
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig
    );
}

#[test]
fn durable_object_handler_reserves_replay_request_id_once() {
    let request = CloudflareReplayReserveRequestV1::new("request-1", digest(0x11), 1000)
        .expect("replay request");
    let call = CloudflareDurableObjectCallV1::new(
        CloudflareWorkerRoleV1::Router,
        do_binding(
            CloudflareDurableObjectScopeV1::RouterReplay,
            "ROUTER_REPLAY_DO",
        ),
        CloudflareDurableObjectRequestV1::router_replay_reserve(request).expect("replay op"),
    )
    .expect("replay call");
    let mut storage = CloudflareDurableObjectMemoryStorageV1::new();

    let first =
        handle_cloudflare_durable_object_call_v1(&call, &mut storage).expect("first reservation");
    assert_eq!(
        first,
        CloudflareDurableObjectResponseV1::router_replay_reserve(
            CloudflareReplayReserveResponseV1::new("request-1", true).expect("reserved response")
        )
        .expect("first response")
    );
    assert!(
        storage.replay_reservation(&call.storage_key()).is_some(),
        "transcript-bound replay reservation should be stored"
    );

    let second = handle_cloudflare_durable_object_call_v1(&call, &mut storage)
        .expect("idempotent reservation");
    assert_eq!(
        second,
        CloudflareDurableObjectResponseV1::router_replay_reserve(
            CloudflareReplayReserveResponseV1::new("request-1", false)
                .expect("idempotent response")
        )
        .expect("second response")
    );

    let conflicting = CloudflareDurableObjectCallV1::new(
        CloudflareWorkerRoleV1::Router,
        do_binding(
            CloudflareDurableObjectScopeV1::RouterReplay,
            "ROUTER_REPLAY_DO",
        ),
        CloudflareDurableObjectRequestV1::router_replay_reserve(
            CloudflareReplayReserveRequestV1::new("request-1", digest(0x12), 1000)
                .expect("conflicting replay request"),
        )
        .expect("conflicting replay op"),
    )
    .expect("conflicting replay call");
    let err = handle_cloudflare_durable_object_call_v1(&conflicting, &mut storage)
        .expect_err("conflicting replay request id must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::ReplayedLocalRequest);
}

#[test]
fn durable_object_handler_stores_router_lifecycle_state() {
    let state = lifecycle_state();
    let call = CloudflareDurableObjectCallV1::new(
        CloudflareWorkerRoleV1::Router,
        do_binding(
            CloudflareDurableObjectScopeV1::RouterLifecycle,
            "ROUTER_LIFECYCLE_DO",
        ),
        CloudflareDurableObjectRequestV1::router_lifecycle_put_public_state(state.clone())
            .expect("lifecycle op"),
    )
    .expect("lifecycle call");
    let mut storage = CloudflareDurableObjectMemoryStorageV1::new();

    let response =
        handle_cloudflare_durable_object_call_v1(&call, &mut storage).expect("lifecycle put");

    assert_eq!(
        response,
        CloudflareDurableObjectResponseV1::router_lifecycle_put_public_state(
            CloudflareLifecyclePutReceiptV1::new("lifecycle-1", true).expect("receipt")
        )
        .expect("response")
    );
    assert_eq!(storage.lifecycle_state(&call.storage_key()), Some(&state));
}

#[test]
fn durable_object_handler_rejects_lifecycle_gate_state_without_requested_state() {
    let state = accepted_lifecycle_state();
    let call = CloudflareDurableObjectCallV1::new(
        CloudflareWorkerRoleV1::Router,
        do_binding(
            CloudflareDurableObjectScopeV1::RouterLifecycle,
            "ROUTER_LIFECYCLE_DO",
        ),
        CloudflareDurableObjectRequestV1::router_lifecycle_put_public_state(state)
            .expect("accepted lifecycle op"),
    )
    .expect("accepted lifecycle call");
    let mut storage = CloudflareDurableObjectMemoryStorageV1::new();

    let err = handle_cloudflare_durable_object_call_v1(&call, &mut storage)
        .expect_err("gate outcome cannot create lifecycle storage");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidLifecycleState);
    assert_eq!(storage.lifecycle_state(&call.storage_key()), None);
}

#[test]
fn durable_object_handler_enforces_router_lifecycle_transition() {
    let requested = lifecycle_state();
    let accepted = accepted_lifecycle_state();
    let binding = do_binding(
        CloudflareDurableObjectScopeV1::RouterLifecycle,
        "ROUTER_LIFECYCLE_DO",
    );
    let requested_call = CloudflareDurableObjectCallV1::new(
        CloudflareWorkerRoleV1::Router,
        binding.clone(),
        CloudflareDurableObjectRequestV1::router_lifecycle_put_public_state(requested)
            .expect("requested lifecycle op"),
    )
    .expect("requested lifecycle call");
    let accepted_call = CloudflareDurableObjectCallV1::new(
        CloudflareWorkerRoleV1::Router,
        binding,
        CloudflareDurableObjectRequestV1::router_lifecycle_put_public_state(accepted.clone())
            .expect("accepted lifecycle op"),
    )
    .expect("accepted lifecycle call");
    let mut storage = CloudflareDurableObjectMemoryStorageV1::new();

    handle_cloudflare_durable_object_call_v1(&requested_call, &mut storage)
        .expect("requested lifecycle put");
    handle_cloudflare_durable_object_call_v1(&accepted_call, &mut storage)
        .expect("accepted lifecycle put");
    handle_cloudflare_durable_object_call_v1(&accepted_call, &mut storage)
        .expect("idempotent accepted lifecycle retry");

    assert_eq!(
        storage.lifecycle_state(&accepted_call.storage_key()),
        Some(&accepted)
    );
}

#[test]
fn durable_object_handler_rejects_terminal_lifecycle_rewrite() {
    let requested = lifecycle_state();
    let accepted = accepted_lifecycle_state();
    let deferred = RouterAbLifecycleStateV1::apply_gate_decision(
        lifecycle_scope(),
        ExpensiveWorkGateDecisionV1::defer(GateDeferReasonV1::ShortWindowSaturated),
    )
    .expect("deferred lifecycle");
    let binding = do_binding(
        CloudflareDurableObjectScopeV1::RouterLifecycle,
        "ROUTER_LIFECYCLE_DO",
    );
    let requested_call = CloudflareDurableObjectCallV1::new(
        CloudflareWorkerRoleV1::Router,
        binding.clone(),
        CloudflareDurableObjectRequestV1::router_lifecycle_put_public_state(requested)
            .expect("requested lifecycle op"),
    )
    .expect("requested lifecycle call");
    let accepted_call = CloudflareDurableObjectCallV1::new(
        CloudflareWorkerRoleV1::Router,
        binding.clone(),
        CloudflareDurableObjectRequestV1::router_lifecycle_put_public_state(accepted.clone())
            .expect("accepted lifecycle op"),
    )
    .expect("accepted lifecycle call");
    let deferred_call = CloudflareDurableObjectCallV1::new(
        CloudflareWorkerRoleV1::Router,
        binding,
        CloudflareDurableObjectRequestV1::router_lifecycle_put_public_state(deferred)
            .expect("deferred lifecycle op"),
    )
    .expect("deferred lifecycle call");
    let mut storage = CloudflareDurableObjectMemoryStorageV1::new();

    handle_cloudflare_durable_object_call_v1(&requested_call, &mut storage)
        .expect("requested lifecycle put");
    handle_cloudflare_durable_object_call_v1(&accepted_call, &mut storage)
        .expect("accepted lifecycle put");
    let err = handle_cloudflare_durable_object_call_v1(&deferred_call, &mut storage)
        .expect_err("terminal lifecycle rewrite must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidLifecycleState);
    assert_eq!(
        storage.lifecycle_state(&accepted_call.storage_key()),
        Some(&accepted)
    );
}

#[test]
fn durable_object_handler_stores_full_derivation_ceremony_lifecycle() {
    let binding = do_binding(
        CloudflareDurableObjectScopeV1::RouterLifecycle,
        "ROUTER_LIFECYCLE_DO",
    );
    let created = created_derivation_ceremony();
    let accepted = accepted_derivation_ceremony();
    let a_forwarded = a_envelope_forwarded_derivation_ceremony();
    let b_forwarded = b_envelope_forwarded_derivation_ceremony();
    let ab_running = ab_running_derivation_ceremony();
    let client_output_ready = client_output_ready_derivation_ceremony();
    let signing_worker_output_ready = signing_worker_output_ready_derivation_ceremony();
    let activated = activated_derivation_ceremony();
    let created_call = CloudflareDurableObjectCallV1::new(
        CloudflareWorkerRoleV1::Router,
        binding.clone(),
        CloudflareDurableObjectRequestV1::derivation_ceremony_put_state(created.clone())
            .expect("created ceremony op"),
    )
    .expect("created ceremony call");
    let accepted_call = CloudflareDurableObjectCallV1::new(
        CloudflareWorkerRoleV1::Router,
        binding.clone(),
        CloudflareDurableObjectRequestV1::derivation_ceremony_put_state(accepted.clone())
            .expect("accepted ceremony op"),
    )
    .expect("accepted ceremony call");
    let mut storage = CloudflareDurableObjectMemoryStorageV1::new();

    let created_response = handle_cloudflare_durable_object_call_v1(&created_call, &mut storage)
        .expect("created ceremony put");
    assert_eq!(
        created_response,
        CloudflareDurableObjectResponseV1::derivation_ceremony_put_state(
            CloudflareDerivationCeremonyPutReceiptV1::new(
                "lifecycle-1",
                CloudflareDerivationCeremonyStateLabelV1::Created,
                true,
            )
            .expect("created receipt")
        )
        .expect("created response")
    );
    assert_eq!(
        storage.derivation_ceremony(&created_call.storage_key()),
        Some(&created)
    );

    handle_cloudflare_durable_object_call_v1(&accepted_call, &mut storage)
        .expect("accepted ceremony put");
    let accepted_retry = handle_cloudflare_durable_object_call_v1(&accepted_call, &mut storage)
        .expect("accepted ceremony retry");
    assert_eq!(
        accepted_retry,
        CloudflareDurableObjectResponseV1::derivation_ceremony_put_state(
            CloudflareDerivationCeremonyPutReceiptV1::new(
                "lifecycle-1",
                CloudflareDerivationCeremonyStateLabelV1::Admitted,
                false,
            )
            .expect("accepted retry receipt")
        )
        .expect("accepted retry response")
    );

    for ceremony in [
        a_forwarded,
        b_forwarded,
        ab_running,
        client_output_ready,
        signing_worker_output_ready,
        activated.clone(),
    ] {
        let call = CloudflareDurableObjectCallV1::new(
            CloudflareWorkerRoleV1::Router,
            binding.clone(),
            CloudflareDurableObjectRequestV1::derivation_ceremony_put_state(ceremony)
                .expect("ceremony op"),
        )
        .expect("ceremony call");
        handle_cloudflare_durable_object_call_v1(&call, &mut storage).expect("ceremony transition");
    }
    assert_eq!(
        storage.derivation_ceremony(&created_call.storage_key()),
        Some(&activated)
    );
}

#[test]
fn durable_object_handler_rejects_skipped_derivation_ceremony_activation() {
    let activated = activated_derivation_ceremony();
    let call = CloudflareDurableObjectCallV1::new(
        CloudflareWorkerRoleV1::Router,
        do_binding(
            CloudflareDurableObjectScopeV1::RouterLifecycle,
            "ROUTER_LIFECYCLE_DO",
        ),
        CloudflareDurableObjectRequestV1::derivation_ceremony_put_state(activated)
            .expect("activated ceremony op"),
    )
    .expect("activated ceremony call");
    let mut storage = CloudflareDurableObjectMemoryStorageV1::new();

    let err = handle_cloudflare_durable_object_call_v1(&call, &mut storage)
        .expect_err("activation cannot create ceremony storage");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidLifecycleState);
    assert_eq!(storage.derivation_ceremony(&call.storage_key()), None);
}

#[test]
fn durable_object_handler_rejects_derivation_ceremony_scope_change() {
    let created = created_derivation_ceremony();
    let mut changed_scope = lifecycle_scope();
    changed_scope.session_id = "session-2".to_owned();
    let accepted = CloudflareDerivationCeremonyV1::admitted(
        changed_scope,
        "gate-request-1",
        TEST_ACTIVATED_AT_MS - 1,
    )
    .expect("accepted ceremony with changed scope");
    let binding = do_binding(
        CloudflareDurableObjectScopeV1::RouterLifecycle,
        "ROUTER_LIFECYCLE_DO",
    );
    let created_call = CloudflareDurableObjectCallV1::new(
        CloudflareWorkerRoleV1::Router,
        binding.clone(),
        CloudflareDurableObjectRequestV1::derivation_ceremony_put_state(created)
            .expect("created ceremony op"),
    )
    .expect("created ceremony call");
    let accepted_call = CloudflareDurableObjectCallV1::new(
        CloudflareWorkerRoleV1::Router,
        binding,
        CloudflareDurableObjectRequestV1::derivation_ceremony_put_state(accepted)
            .expect("accepted ceremony op"),
    )
    .expect("accepted ceremony call");
    let mut storage = CloudflareDurableObjectMemoryStorageV1::new();

    handle_cloudflare_durable_object_call_v1(&created_call, &mut storage)
        .expect("created ceremony put");
    let err = handle_cloudflare_durable_object_call_v1(&accepted_call, &mut storage)
        .expect_err("scope-changing ceremony transition must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidLifecycleState);
}

#[test]
fn durable_object_handler_rejects_terminal_derivation_ceremony_rewrite() {
    let binding = do_binding(
        CloudflareDurableObjectScopeV1::RouterLifecycle,
        "ROUTER_LIFECYCLE_DO",
    );
    let created = created_derivation_ceremony();
    let abandoned = CloudflareDerivationCeremonyV1::abandoned(
        lifecycle_scope(),
        CloudflareDerivationCeremonyStateLabelV1::Created,
        "user cancelled",
        TEST_ACTIVATED_AT_MS - 1,
    )
    .expect("abandoned ceremony");
    let failed = CloudflareDerivationCeremonyV1::failed(
        lifecycle_scope(),
        CloudflareDerivationCeremonyStateLabelV1::Created,
        "activation_failed",
        "activation failed",
        TEST_ACTIVATED_AT_MS,
    )
    .expect("failed ceremony");
    let created_call = CloudflareDurableObjectCallV1::new(
        CloudflareWorkerRoleV1::Router,
        binding.clone(),
        CloudflareDurableObjectRequestV1::derivation_ceremony_put_state(created)
            .expect("created ceremony op"),
    )
    .expect("created ceremony call");
    let abandoned_call = CloudflareDurableObjectCallV1::new(
        CloudflareWorkerRoleV1::Router,
        binding.clone(),
        CloudflareDurableObjectRequestV1::derivation_ceremony_put_state(abandoned.clone())
            .expect("abandoned ceremony op"),
    )
    .expect("abandoned ceremony call");
    let failed_call = CloudflareDurableObjectCallV1::new(
        CloudflareWorkerRoleV1::Router,
        binding,
        CloudflareDurableObjectRequestV1::derivation_ceremony_put_state(failed)
            .expect("failed ceremony op"),
    )
    .expect("failed ceremony call");
    let mut storage = CloudflareDurableObjectMemoryStorageV1::new();

    handle_cloudflare_durable_object_call_v1(&created_call, &mut storage)
        .expect("created ceremony put");
    handle_cloudflare_durable_object_call_v1(&abandoned_call, &mut storage)
        .expect("abandoned ceremony put");
    let err = handle_cloudflare_durable_object_call_v1(&failed_call, &mut storage)
        .expect_err("terminal ceremony rewrite must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidLifecycleState);
    assert_eq!(
        storage.derivation_ceremony(&created_call.storage_key()),
        Some(&abandoned)
    );
}

#[test]
fn durable_object_handler_evaluates_router_project_policy() {
    let request = admission_store_request(1_000);
    let call = CloudflareDurableObjectCallV1::new(
        CloudflareWorkerRoleV1::Router,
        do_binding(
            CloudflareDurableObjectScopeV1::RouterProjectPolicy,
            "ROUTER_PROJECT_POLICY_DO",
        ),
        CloudflareDurableObjectRequestV1::router_project_policy_evaluate(request)
            .expect("project policy op"),
    )
    .expect("project policy call");
    let mut storage = CloudflareDurableObjectMemoryStorageV1::new();

    let missing = handle_cloudflare_durable_object_call_v1(&call, &mut storage)
        .expect_err("missing policy must fail closed");
    assert_eq!(
        missing.code(),
        RouterAbProtocolErrorCode::MissingLocalBinding
    );

    storage
        .seed_router_project_policy(
            call.storage_key(),
            CloudflareRouterProjectPolicyRecordV1::new(
                "org-1",
                "project-1",
                "dev",
                vec![ExpensiveWorkKindV1::RegistrationPrepare],
                true,
                1_000,
            )
            .expect("policy record"),
        )
        .expect("seed policy");

    let allowed =
        handle_cloudflare_durable_object_call_v1(&call, &mut storage).expect("policy response");
    assert_eq!(
        allowed,
        CloudflareDurableObjectResponseV1::router_project_policy_evaluate(
            CloudflareRouterProjectPolicyV1::Allowed
        )
        .expect("allowed response")
    );
}

#[test]
fn durable_object_handler_evaluates_normal_signing_project_policy() {
    let request = normal_signing_admission_store_request(1_000);
    let call = CloudflareDurableObjectCallV1::new(
        CloudflareWorkerRoleV1::Router,
        do_binding(
            CloudflareDurableObjectScopeV1::RouterProjectPolicy,
            "ROUTER_PROJECT_POLICY_DO",
        ),
        CloudflareDurableObjectRequestV1::router_normal_signing_project_policy_evaluate(request)
            .expect("normal signing project policy op"),
    )
    .expect("normal signing project policy call");
    let mut storage = CloudflareDurableObjectMemoryStorageV1::new();

    let missing = handle_cloudflare_durable_object_call_v1(&call, &mut storage)
        .expect_err("missing normal signing policy must fail closed");
    assert_eq!(
        missing.code(),
        RouterAbProtocolErrorCode::MissingLocalBinding
    );

    storage
        .seed_router_project_policy(
            call.storage_key(),
            CloudflareRouterProjectPolicyRecordV1::new(
                "org-1",
                "project-1",
                "dev",
                vec![ExpensiveWorkKindV1::RegistrationPrepare],
                false,
                1_000,
            )
            .expect("policy record"),
        )
        .expect("seed policy");

    let rejected =
        handle_cloudflare_durable_object_call_v1(&call, &mut storage).expect("policy response");
    assert_eq!(
        rejected,
        CloudflareDurableObjectResponseV1::router_normal_signing_project_policy_evaluate(
            CloudflareRouterProjectPolicyV1::Rejected {
                retry_after_ms: 1_000
            }
        )
        .expect("rejected response")
    );
}

#[test]
fn durable_object_handler_evaluates_normal_signing_quota() {
    let first = normal_signing_admission_store_request(1_000);
    let first_call = CloudflareDurableObjectCallV1::new(
        CloudflareWorkerRoleV1::Router,
        do_binding(
            CloudflareDurableObjectScopeV1::RouterQuota,
            "ROUTER_QUOTA_DO",
        ),
        CloudflareDurableObjectRequestV1::router_normal_signing_quota_evaluate(first.clone())
            .expect("normal signing quota op"),
    )
    .expect("normal signing quota call");
    let mut storage = CloudflareDurableObjectMemoryStorageV1::new();

    let accepted =
        handle_cloudflare_durable_object_call_v1(&first_call, &mut storage).expect("quota accept");
    assert_eq!(
        accepted,
        CloudflareDurableObjectResponseV1::router_normal_signing_quota_evaluate(
            CloudflareRouterQuotaCheckV1::Accepted {
                request_id: "sign-request-1".to_string()
            }
        )
        .expect("accepted response")
    );
    assert_eq!(
        storage
            .quota_reservation(&first_call.storage_key())
            .expect("quota reservation")
            .request_id,
        "sign-request-1"
    );

    let duplicate =
        handle_cloudflare_durable_object_call_v1(&first_call, &mut storage).expect("duplicate");
    assert_eq!(
        duplicate,
        CloudflareDurableObjectResponseV1::router_normal_signing_quota_evaluate(
            CloudflareRouterQuotaCheckV1::Accepted {
                request_id: "sign-request-1".to_string()
            }
        )
        .expect("duplicate accepted response")
    );

    let second_store_request =
        normal_signing_admission_store_request_for_id("sign-request-2", 1_000);
    let second_call = CloudflareDurableObjectCallV1::new(
        CloudflareWorkerRoleV1::Router,
        do_binding(
            CloudflareDurableObjectScopeV1::RouterQuota,
            "ROUTER_QUOTA_DO",
        ),
        CloudflareDurableObjectRequestV1::router_normal_signing_quota_evaluate(
            second_store_request,
        )
        .expect("second normal signing quota op"),
    )
    .expect("second normal signing quota call");

    let saturated = handle_cloudflare_durable_object_call_v1(&second_call, &mut storage)
        .expect("second active request should saturate");
    assert_eq!(
        saturated,
        CloudflareDurableObjectResponseV1::router_normal_signing_quota_evaluate(
            CloudflareRouterQuotaCheckV1::ShortWindowSaturated
        )
        .expect("saturated response")
    );
}

#[test]
fn durable_object_cleanup_removes_expired_replay_reservations() {
    let expired_call = CloudflareDurableObjectCallV1::new(
        CloudflareWorkerRoleV1::Router,
        do_binding(
            CloudflareDurableObjectScopeV1::RouterReplay,
            "ROUTER_REPLAY_DO",
        ),
        CloudflareDurableObjectRequestV1::router_replay_reserve(
            CloudflareReplayReserveRequestV1::new("expired-request", digest(0x71), 2_000)
                .expect("expired replay request"),
        )
        .expect("expired replay op"),
    )
    .expect("expired replay call");
    let active_call = CloudflareDurableObjectCallV1::new(
        CloudflareWorkerRoleV1::Router,
        do_binding(
            CloudflareDurableObjectScopeV1::RouterReplay,
            "ROUTER_REPLAY_DO",
        ),
        CloudflareDurableObjectRequestV1::router_replay_reserve(
            CloudflareReplayReserveRequestV1::new("active-request", digest(0x72), 3_000)
                .expect("active replay request"),
        )
        .expect("active replay op"),
    )
    .expect("active replay call");
    let cleanup_call = CloudflareDurableObjectCallV1::new(
        CloudflareWorkerRoleV1::Router,
        do_binding(
            CloudflareDurableObjectScopeV1::RouterReplay,
            "ROUTER_REPLAY_DO",
        ),
        CloudflareDurableObjectRequestV1::router_replay_cleanup_expired(
            CloudflareExpiredStateCleanupRequestV1::new(2_000).expect("cleanup request"),
        )
        .expect("cleanup op"),
    )
    .expect("cleanup call");
    let mut storage = CloudflareDurableObjectMemoryStorageV1::new();

    handle_cloudflare_durable_object_call_v1(&expired_call, &mut storage)
        .expect("expired replay reserve");
    handle_cloudflare_durable_object_call_v1(&active_call, &mut storage)
        .expect("active replay reserve");
    let response =
        handle_cloudflare_durable_object_call_v1(&cleanup_call, &mut storage).expect("cleanup");

    assert_eq!(
        response,
        CloudflareDurableObjectResponseV1::router_replay_cleanup_expired(
            CloudflareExpiredStateCleanupReportV1::new(2_000, 1, 1).expect("cleanup report")
        )
        .expect("cleanup response")
    );
    assert!(storage
        .replay_reservation(&expired_call.storage_key())
        .is_none());
    assert!(storage
        .replay_reservation_by_request_id(
            &expired_call
                .replay_request_index_storage_key()
                .expect("expired replay index")
        )
        .expect("expired replay index lookup")
        .is_none());
    assert!(storage
        .replay_reservation(&active_call.storage_key())
        .is_some());
    assert!(storage
        .replay_reservation_by_request_id(
            &active_call
                .replay_request_index_storage_key()
                .expect("active replay index")
        )
        .expect("active replay index lookup")
        .is_some());
}

#[test]
fn durable_object_cleanup_removes_expired_quota_reservations() {
    let expired_request = normal_signing_admission_store_request_for_id("expired-request", 1_000);
    let mut active_request = normal_signing_admission_store_request_for_id("active-request", 1_000);
    active_request.metadata.account_id = "other.near".to_owned();
    active_request.expires_at_ms = 3_000;
    let expired_call = CloudflareDurableObjectCallV1::new(
        CloudflareWorkerRoleV1::Router,
        do_binding(
            CloudflareDurableObjectScopeV1::RouterQuota,
            "ROUTER_QUOTA_DO",
        ),
        CloudflareDurableObjectRequestV1::router_normal_signing_quota_evaluate(expired_request)
            .expect("expired quota op"),
    )
    .expect("expired quota call");
    let active_call = CloudflareDurableObjectCallV1::new(
        CloudflareWorkerRoleV1::Router,
        do_binding(
            CloudflareDurableObjectScopeV1::RouterQuota,
            "ROUTER_QUOTA_DO",
        ),
        CloudflareDurableObjectRequestV1::router_normal_signing_quota_evaluate(active_request)
            .expect("active quota op"),
    )
    .expect("active quota call");
    let cleanup_call = CloudflareDurableObjectCallV1::new(
        CloudflareWorkerRoleV1::Router,
        do_binding(
            CloudflareDurableObjectScopeV1::RouterQuota,
            "ROUTER_QUOTA_DO",
        ),
        CloudflareDurableObjectRequestV1::router_quota_cleanup_expired(
            CloudflareExpiredStateCleanupRequestV1::new(2_000).expect("cleanup request"),
        )
        .expect("cleanup op"),
    )
    .expect("cleanup call");
    let mut storage = CloudflareDurableObjectMemoryStorageV1::new();

    handle_cloudflare_durable_object_call_v1(&expired_call, &mut storage)
        .expect("expired quota reserve");
    handle_cloudflare_durable_object_call_v1(&active_call, &mut storage)
        .expect("active quota reserve");
    let response =
        handle_cloudflare_durable_object_call_v1(&cleanup_call, &mut storage).expect("cleanup");

    assert_eq!(
        response,
        CloudflareDurableObjectResponseV1::router_quota_cleanup_expired(
            CloudflareExpiredStateCleanupReportV1::new(2_000, 1, 0).expect("cleanup report")
        )
        .expect("cleanup response")
    );
    assert!(storage
        .quota_reservation(&expired_call.storage_key())
        .is_none());
    assert!(storage
        .quota_reservation(&active_call.storage_key())
        .is_some());
}

#[test]
fn durable_object_handler_evaluates_normal_signing_abuse_state() {
    let request = normal_signing_admission_store_request(1_000);
    let call = CloudflareDurableObjectCallV1::new(
        CloudflareWorkerRoleV1::Router,
        do_binding(
            CloudflareDurableObjectScopeV1::RouterAbuse,
            "ROUTER_ABUSE_DO",
        ),
        CloudflareDurableObjectRequestV1::router_normal_signing_abuse_evaluate(request)
            .expect("normal signing abuse op"),
    )
    .expect("normal signing abuse call");
    let mut storage = CloudflareDurableObjectMemoryStorageV1::new();

    let allowed =
        handle_cloudflare_durable_object_call_v1(&call, &mut storage).expect("default abuse");
    assert_eq!(
        allowed,
        CloudflareDurableObjectResponseV1::router_normal_signing_abuse_evaluate(
            CloudflareRouterAbuseCheckV1::Allowed
        )
        .expect("allowed response")
    );

    storage
        .seed_router_abuse(
            call.storage_key(),
            CloudflareRouterAbuseRecordV1::new(CloudflareRouterAbuseCheckV1::RateLimited {
                retry_after_ms: 250,
            })
            .expect("abuse record"),
        )
        .expect("seed abuse");

    let rate_limited =
        handle_cloudflare_durable_object_call_v1(&call, &mut storage).expect("seeded abuse");
    assert_eq!(
        rate_limited,
        CloudflareDurableObjectResponseV1::router_normal_signing_abuse_evaluate(
            CloudflareRouterAbuseCheckV1::RateLimited {
                retry_after_ms: 250
            }
        )
        .expect("rate-limited response")
    );
}

#[test]
fn durable_object_handler_evaluates_router_abuse_state() {
    let request = admission_store_request(1_000);
    let call = CloudflareDurableObjectCallV1::new(
        CloudflareWorkerRoleV1::Router,
        do_binding(
            CloudflareDurableObjectScopeV1::RouterAbuse,
            "ROUTER_ABUSE_DO",
        ),
        CloudflareDurableObjectRequestV1::router_abuse_evaluate(request).expect("abuse op"),
    )
    .expect("abuse call");
    let mut storage = CloudflareDurableObjectMemoryStorageV1::new();

    let allowed =
        handle_cloudflare_durable_object_call_v1(&call, &mut storage).expect("default abuse");
    assert_eq!(
        allowed,
        CloudflareDurableObjectResponseV1::router_abuse_evaluate(
            CloudflareRouterAbuseCheckV1::Allowed
        )
        .expect("allowed response")
    );

    storage
        .seed_router_abuse(
            call.storage_key(),
            CloudflareRouterAbuseRecordV1::new(CloudflareRouterAbuseCheckV1::RateLimited {
                retry_after_ms: 250,
            })
            .expect("abuse record"),
        )
        .expect("seed abuse");

    let limited =
        handle_cloudflare_durable_object_call_v1(&call, &mut storage).expect("limited abuse");
    assert_eq!(
        limited,
        CloudflareDurableObjectResponseV1::router_abuse_evaluate(
            CloudflareRouterAbuseCheckV1::RateLimited {
                retry_after_ms: 250
            }
        )
        .expect("limited response")
    );
}

#[test]
fn durable_object_handler_accepts_and_reuses_router_quota() {
    let request = admission_store_request(1_000);
    let call = CloudflareDurableObjectCallV1::new(
        CloudflareWorkerRoleV1::Router,
        do_binding(
            CloudflareDurableObjectScopeV1::RouterQuota,
            "ROUTER_QUOTA_DO",
        ),
        CloudflareDurableObjectRequestV1::router_quota_evaluate(request).expect("quota op"),
    )
    .expect("quota call");
    let mut storage = CloudflareDurableObjectMemoryStorageV1::new();

    let accepted =
        handle_cloudflare_durable_object_call_v1(&call, &mut storage).expect("accepted quota");
    assert_eq!(
        accepted,
        CloudflareDurableObjectResponseV1::router_quota_evaluate(
            CloudflareRouterQuotaCheckV1::Accepted {
                request_id: "request-nonce-1".to_owned()
            }
        )
        .expect("accepted response")
    );
    assert_eq!(
        storage.quota_reservation(&call.storage_key()),
        Some(
            &CloudflareRouterQuotaReservationV1::new("request-nonce-1", "lifecycle-1", 2_000)
                .expect("quota reservation")
        )
    );

    let reused =
        handle_cloudflare_durable_object_call_v1(&call, &mut storage).expect("reused quota");
    assert_eq!(
        reused,
        CloudflareDurableObjectResponseV1::router_quota_evaluate(
            CloudflareRouterQuotaCheckV1::ReuseExisting {
                request_id: "request-nonce-1".to_owned(),
                existing_lifecycle_id: "lifecycle-1".to_owned()
            }
        )
        .expect("reuse response")
    );
}

#[test]
fn durable_object_wallet_budget_put_grant_is_idempotent_for_same_material() {
    let runtime = router_runtime();
    let request = router_wallet_budget_put_grant_request();
    let call = runtime
        .wallet_budget_put_grant_call(request)
        .expect("wallet budget put grant call");
    let mut storage = CloudflareDurableObjectMemoryStorageV1::new();

    let first = handle_cloudflare_durable_object_call_v1(&call, &mut storage)
        .expect("first wallet budget grant put");
    let second = handle_cloudflare_durable_object_call_v1(&call, &mut storage)
        .expect("idempotent wallet budget grant put");

    assert_eq!(first, second);
    let CloudflareDurableObjectResponseV1::RouterWalletBudgetGrantPut { status } = first else {
        panic!("put grant response branch");
    };
    assert_eq!(status.signing_grant_id, "signing-grant-1");
    assert_eq!(status.committed_remaining_uses, 3);
    assert_eq!(status.available_uses, 3);
    assert!(
        storage.wallet_budget_grant(&call.storage_key()).is_some(),
        "wallet budget grant should be stored"
    );
}

#[test]
fn durable_object_wallet_budget_put_grant_rejects_reused_id_with_different_binding() {
    let runtime = router_runtime();
    let request = router_wallet_budget_put_grant_request();
    let call = runtime
        .wallet_budget_put_grant_call(request)
        .expect("wallet budget put grant call");
    let mut conflicting = router_wallet_budget_put_grant_request();
    conflicting.authorized_signers = vec![CloudflareRouterWalletBudgetSignerBindingV1::new(
        CloudflareRouterWalletBudgetCurveV1::Ed25519,
        "session-1",
        "server-b",
    )
    .expect("conflicting wallet budget signer binding")];
    let conflicting_call = runtime
        .wallet_budget_put_grant_call(conflicting)
        .expect("conflicting wallet budget put grant call");
    let mut storage = CloudflareDurableObjectMemoryStorageV1::new();

    handle_cloudflare_durable_object_call_v1(&call, &mut storage).expect("first grant put");
    let err = handle_cloudflare_durable_object_call_v1(&conflicting_call, &mut storage)
        .expect_err("conflicting grant material must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::ReplayedLocalRequest);
}

#[test]
fn durable_object_wallet_budget_reserve_rejects_missing_grant_record() {
    let runtime = router_runtime();
    let call = runtime
        .wallet_budget_reserve_call(router_wallet_budget_reserve_request())
        .expect("wallet budget reserve call");
    let mut storage = CloudflareDurableObjectMemoryStorageV1::new();

    let err = handle_cloudflare_durable_object_call_v1(&call, &mut storage)
        .expect_err("reserve without grant must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::MissingLocalBinding);
}

#[test]
fn durable_object_wallet_budget_reserve_rejects_unauthorized_signer_binding() {
    let runtime = router_runtime();
    let put_call = runtime
        .wallet_budget_put_grant_call(router_wallet_budget_put_grant_request())
        .expect("wallet budget put grant call");
    let mut reserve_request = router_wallet_budget_reserve_request();
    reserve_request.signing_worker_id = "server-b".to_owned();
    let reserve_call = runtime
        .wallet_budget_reserve_call(reserve_request)
        .expect("wallet budget reserve call");
    let mut storage = CloudflareDurableObjectMemoryStorageV1::new();

    handle_cloudflare_durable_object_call_v1(&put_call, &mut storage).expect("grant put");
    let err = handle_cloudflare_durable_object_call_v1(&reserve_call, &mut storage)
        .expect_err("unauthorized signer must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::ForbiddenLocalBinding);
}

#[test]
fn durable_object_router_storage_surface_is_public_state_and_hashes() {
    let public_request = ecdsa_threshold_prf_request(2_000);
    let lifecycle_call = CloudflareDurableObjectCallV1::new(
        CloudflareWorkerRoleV1::Router,
        do_binding(
            CloudflareDurableObjectScopeV1::RouterLifecycle,
            "ROUTER_LIFECYCLE_DO",
        ),
        CloudflareDurableObjectRequestV1::router_lifecycle_put_public_state(lifecycle_state())
            .expect("lifecycle op"),
    )
    .expect("lifecycle call");
    let replay_call = CloudflareDurableObjectCallV1::new(
        CloudflareWorkerRoleV1::Router,
        do_binding(
            CloudflareDurableObjectScopeV1::RouterReplay,
            "ROUTER_REPLAY_DO",
        ),
        CloudflareDurableObjectRequestV1::router_replay_reserve(
            CloudflareReplayReserveRequestV1::new(
                "request-1",
                public_request.router_replay_digest(),
                1000,
            )
            .expect("replay request"),
        )
        .expect("replay op"),
    )
    .expect("replay call");

    let lifecycle_json = serde_json::to_string(&lifecycle_call.request).expect("lifecycle json");
    let replay_json = serde_json::to_string(&replay_call.request).expect("replay json");

    assert!(lifecycle_json.contains("\"state\":\"requested\""));
    assert!(replay_json.contains("replay_material_digest"));
    assert!(replay_call
        .storage_key()
        .contains(&digest_hex(public_request.router_replay_digest())));
    for forbidden in ["ciphertext", "encrypted_payload", "[16,17]", "[32,33]"] {
        assert!(
            !lifecycle_json.contains(forbidden),
            "lifecycle persistence leaked request payload marker `{forbidden}`"
        );
        assert!(
            !replay_json.contains(forbidden),
            "replay persistence leaked request payload marker `{forbidden}`"
        );
    }
}

#[test]
fn durable_object_handler_activates_signing_worker_output_idempotently() {
    let activation = signing_worker_activation();
    let material = server_output_material_record(&activation);
    let receipt_digest = activation.activation_context.transcript_digest();
    let call = CloudflareDurableObjectCallV1::new(
        CloudflareWorkerRoleV1::SigningWorker,
        server_output_binding(),
        CloudflareDurableObjectRequestV1::signing_worker_output_activate(
            activation.clone(),
            material.clone(),
            TEST_ACTIVATED_AT_MS,
        )
        .expect("activation request"),
    )
    .expect("activation call");
    let mut storage = CloudflareDurableObjectMemoryStorageV1::new();
    let expected_active_signing_worker_state =
        active_signing_worker_state_for_activation(&activation, call.storage_key());
    let active_state_index_key = call
        .active_signing_worker_state_index_storage_key()
        .expect("active SigningWorker index key");

    let first =
        handle_cloudflare_durable_object_call_v1(&call, &mut storage).expect("first activation");
    assert_eq!(
        first,
        CloudflareDurableObjectResponseV1::signing_worker_output_activate(
            CloudflareSigningWorkerOutputActivationReceiptV1::new(
                "lifecycle-1",
                "server-a",
                receipt_digest,
                expected_active_signing_worker_state.clone(),
                true,
            )
            .expect("first receipt")
        )
        .expect("first response")
    );
    let stored_activation = storage
        .signing_worker_activation(&call.storage_key())
        .expect("stored activation record");
    assert_eq!(stored_activation.activation, activation);
    assert_eq!(stored_activation.material, material);
    assert_eq!(
        stored_activation.active_signing_worker_state,
        expected_active_signing_worker_state
    );
    assert_eq!(
        storage.active_signing_worker_state(&active_state_index_key),
        Some(&expected_active_signing_worker_state)
    );

    let second = handle_cloudflare_durable_object_call_v1(&call, &mut storage)
        .expect("idempotent activation");
    assert_eq!(
        second,
        CloudflareDurableObjectResponseV1::signing_worker_output_activate(
            CloudflareSigningWorkerOutputActivationReceiptV1::new(
                "lifecycle-1",
                "server-a",
                receipt_digest,
                expected_active_signing_worker_state,
                false,
            )
            .expect("second receipt")
        )
        .expect("second response")
    );

    let lookup_call = CloudflareDurableObjectCallV1::new(
        CloudflareWorkerRoleV1::SigningWorker,
        server_output_binding(),
        CloudflareDurableObjectRequestV1::signing_worker_output_active_state_get(
            CloudflareActiveSigningWorkerStateLookupV1::new(
                "account.near",
                "session-1",
                "server-a",
            )
            .expect("active SigningWorker lookup"),
        )
        .expect("lookup request"),
    )
    .expect("lookup call");
    let lookup_response = handle_cloudflare_durable_object_call_v1(&lookup_call, &mut storage)
        .expect("active SigningWorker lookup");
    assert_eq!(
        lookup_response,
        CloudflareDurableObjectResponseV1::signing_worker_output_active_state_get(
            active_signing_worker_state_for_activation(&activation, call.storage_key())
        )
        .expect("lookup response")
    );
    let material_lookup_call = CloudflareDurableObjectCallV1::new(
        CloudflareWorkerRoleV1::SigningWorker,
        server_output_binding(),
        CloudflareDurableObjectRequestV1::signing_worker_output_material_get(
            router_ab_cloudflare::CloudflareSigningWorkerOutputMaterialLookupV1::new(
                active_signing_worker_state_for_activation(&activation, call.storage_key()),
            )
            .expect("material lookup"),
        )
        .expect("material request"),
    )
    .expect("material call");
    let material_response =
        handle_cloudflare_durable_object_call_v1(&material_lookup_call, &mut storage)
            .expect("SigningWorker material lookup");
    assert_eq!(
        material_response,
        CloudflareDurableObjectResponseV1::signing_worker_output_material_get(material.clone())
            .expect("material response")
    );

    let conflicting_router_payload = router_payload_for_signing_worker_activation();
    let conflicting_activation =
        CloudflareSigningWorkerRecipientProofBundleActivationRequestV1::new(
            conflicting_router_payload.clone(),
            CloudflareSigningWorkerRecipientProofBundleActivationV1::new(
                server_proof_bundle_wire(&conflicting_router_payload, Role::SignerA, 0x55),
                server_proof_bundle_wire(&conflicting_router_payload, Role::SignerB, 0x56),
            )
            .expect("conflicting server"),
        )
        .expect("conflicting activation request");
    let conflicting_call = CloudflareDurableObjectCallV1::new(
        CloudflareWorkerRoleV1::SigningWorker,
        server_output_binding(),
        CloudflareDurableObjectRequestV1::signing_worker_output_activate(
            conflicting_activation.clone(),
            server_output_material_record(&conflicting_activation),
            TEST_ACTIVATED_AT_MS,
        )
        .expect("conflicting activation request"),
    )
    .expect("conflicting activation call");
    let err = handle_cloudflare_durable_object_call_v1(&conflicting_call, &mut storage)
        .expect_err("conflicting SigningWorker activation must fail");

    assert_eq!(
        err.code(),
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig
    );
}

#[test]
fn durable_object_handler_puts_and_takes_signing_worker_round1_once() {
    let record = normal_signing_round1_record();
    let put_call = CloudflareDurableObjectCallV1::new(
        CloudflareWorkerRoleV1::SigningWorker,
        server_output_binding(),
        CloudflareDurableObjectRequestV1::signing_worker_round1_put(record.clone())
            .expect("round1 put request"),
    )
    .expect("round1 put call");
    let take_call = CloudflareDurableObjectCallV1::new(
        CloudflareWorkerRoleV1::SigningWorker,
        server_output_binding(),
        CloudflareDurableObjectRequestV1::signing_worker_round1_take(normal_signing_round1_lookup(
            1_500,
        ))
        .expect("round1 take request"),
    )
    .expect("round1 take call");
    let mut storage = CloudflareDurableObjectMemoryStorageV1::new();

    let first_put =
        handle_cloudflare_durable_object_call_v1(&put_call, &mut storage).expect("first put");
    assert_eq!(
        first_put,
        CloudflareDurableObjectResponseV1::signing_worker_round1_put(
            CloudflareSigningWorkerRound1PutReceiptV1::from_record(&record, true)
                .expect("first put receipt")
        )
        .expect("first put response")
    );

    let second_put =
        handle_cloudflare_durable_object_call_v1(&put_call, &mut storage).expect("second put");
    assert_eq!(
        second_put,
        CloudflareDurableObjectResponseV1::signing_worker_round1_put(
            CloudflareSigningWorkerRound1PutReceiptV1::from_record(&record, false)
                .expect("second put receipt")
        )
        .expect("second put response")
    );

    let taken =
        handle_cloudflare_durable_object_call_v1(&take_call, &mut storage).expect("round1 take");
    assert_eq!(
        taken,
        CloudflareDurableObjectResponseV1::signing_worker_round1_take(record)
            .expect("round1 take response")
    );

    let missing = handle_cloudflare_durable_object_call_v1(&take_call, &mut storage)
        .expect_err("round1 take must be single-use");
    assert_eq!(
        missing.code(),
        RouterAbProtocolErrorCode::MissingLocalBinding
    );
}

#[test]
fn durable_object_cleanup_removes_expired_signing_worker_round1_records() {
    let expired_record = normal_signing_round1_record();
    let mut active_record = expired_record.clone();
    active_record.server_round1_handle = "server-round1/active-request".to_owned();
    active_record.expires_at_ms = 3_000;
    let expired_put_call = CloudflareDurableObjectCallV1::new(
        CloudflareWorkerRoleV1::SigningWorker,
        server_output_binding(),
        CloudflareDurableObjectRequestV1::signing_worker_round1_put(expired_record)
            .expect("expired round1 put request"),
    )
    .expect("expired round1 put call");
    let active_put_call = CloudflareDurableObjectCallV1::new(
        CloudflareWorkerRoleV1::SigningWorker,
        server_output_binding(),
        CloudflareDurableObjectRequestV1::signing_worker_round1_put(active_record)
            .expect("active round1 put request"),
    )
    .expect("active round1 put call");
    let cleanup_call = CloudflareDurableObjectCallV1::new(
        CloudflareWorkerRoleV1::SigningWorker,
        server_output_binding(),
        CloudflareDurableObjectRequestV1::signing_worker_round1_cleanup_expired(
            CloudflareExpiredStateCleanupRequestV1::new(2_000).expect("cleanup request"),
        )
        .expect("cleanup op"),
    )
    .expect("cleanup call");
    let mut storage = CloudflareDurableObjectMemoryStorageV1::new();

    handle_cloudflare_durable_object_call_v1(&expired_put_call, &mut storage)
        .expect("expired round1 put");
    handle_cloudflare_durable_object_call_v1(&active_put_call, &mut storage)
        .expect("active round1 put");
    let response =
        handle_cloudflare_durable_object_call_v1(&cleanup_call, &mut storage).expect("cleanup");

    assert_eq!(
        response,
        CloudflareDurableObjectResponseV1::signing_worker_round1_cleanup_expired(
            CloudflareExpiredStateCleanupReportV1::new(2_000, 1, 0).expect("cleanup report")
        )
        .expect("cleanup response")
    );
    assert!(storage
        .signing_worker_round1(&expired_put_call.storage_key())
        .expect("expired round1 lookup")
        .is_none());
    assert!(storage
        .signing_worker_round1(&active_put_call.storage_key())
        .expect("active round1 lookup")
        .is_some());
}

#[test]
fn durable_object_handler_rejects_conflicting_signing_worker_round1_handle() {
    let record = normal_signing_round1_record();
    let mut conflicting = record.clone();
    conflicting.expires_at_ms = 2_500;
    let put_call = CloudflareDurableObjectCallV1::new(
        CloudflareWorkerRoleV1::SigningWorker,
        server_output_binding(),
        CloudflareDurableObjectRequestV1::signing_worker_round1_put(record)
            .expect("round1 put request"),
    )
    .expect("round1 put call");
    let conflicting_put_call = CloudflareDurableObjectCallV1::new(
        CloudflareWorkerRoleV1::SigningWorker,
        server_output_binding(),
        CloudflareDurableObjectRequestV1::signing_worker_round1_put(conflicting)
            .expect("conflicting round1 put request"),
    )
    .expect("conflicting round1 put call");
    let mut storage = CloudflareDurableObjectMemoryStorageV1::new();

    handle_cloudflare_durable_object_call_v1(&put_call, &mut storage).expect("first put");
    let err = handle_cloudflare_durable_object_call_v1(&conflicting_put_call, &mut storage)
        .expect_err("conflicting round1 material must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::ReplayedLocalRequest);
}

#[test]
fn durable_object_handler_rejects_expired_signing_worker_round1_take() {
    let record = normal_signing_round1_record();
    let put_call = CloudflareDurableObjectCallV1::new(
        CloudflareWorkerRoleV1::SigningWorker,
        server_output_binding(),
        CloudflareDurableObjectRequestV1::signing_worker_round1_put(record.clone())
            .expect("round1 put request"),
    )
    .expect("round1 put call");
    let expired_take_call = CloudflareDurableObjectCallV1::new(
        CloudflareWorkerRoleV1::SigningWorker,
        server_output_binding(),
        CloudflareDurableObjectRequestV1::signing_worker_round1_take(normal_signing_round1_lookup(
            record.expires_at_ms,
        ))
        .expect("expired round1 take request"),
    )
    .expect("expired round1 take call");
    let mut storage = CloudflareDurableObjectMemoryStorageV1::new();

    handle_cloudflare_durable_object_call_v1(&put_call, &mut storage).expect("first put");
    let err = handle_cloudflare_durable_object_call_v1(&expired_take_call, &mut storage)
        .expect_err("expired round1 material must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::ExpiredLocalRequest);
    assert!(
        storage
            .signing_worker_round1(&put_call.storage_key())
            .expect("round1 storage lookup")
            .is_some(),
        "failed exact lookup must not consume nonce material"
    );
}

#[test]
fn durable_object_handler_rejects_round1_binding_mismatch_without_consuming_record() {
    let record = normal_signing_round1_record();
    let put_call = CloudflareDurableObjectCallV1::new(
        CloudflareWorkerRoleV1::SigningWorker,
        server_output_binding(),
        CloudflareDurableObjectRequestV1::signing_worker_round1_put(record)
            .expect("round1 put request"),
    )
    .expect("round1 put call");
    let mismatched_lookup = CloudflareSigningWorkerRound1LookupV1::new(
        active_signing_worker_state_for_normal_signing(),
        "server-round1/sign-request-1",
        digest(0x77),
        1_500,
    )
    .expect("mismatched lookup");
    let mismatched_take_call = CloudflareDurableObjectCallV1::new(
        CloudflareWorkerRoleV1::SigningWorker,
        server_output_binding(),
        CloudflareDurableObjectRequestV1::signing_worker_round1_take(mismatched_lookup)
            .expect("mismatched round1 take request"),
    )
    .expect("mismatched round1 take call");
    let mut storage = CloudflareDurableObjectMemoryStorageV1::new();

    handle_cloudflare_durable_object_call_v1(&put_call, &mut storage).expect("first put");
    let err = handle_cloudflare_durable_object_call_v1(&mismatched_take_call, &mut storage)
        .expect_err("mismatched round1 binding must fail");

    assert_eq!(
        err.code(),
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig
    );
    assert!(
        storage
            .signing_worker_round1(&put_call.storage_key())
            .expect("round1 storage lookup")
            .is_some(),
        "failed exact lookup must not consume nonce material"
    );
}

#[test]
fn router_ab_ecdsa_derivation_presignature_record_rejects_malformed_material() {
    let mut invalid_big_r = router_ab_ecdsa_derivation_presignature_record();
    invalid_big_r.server_big_r33_b64u = b64u(&[0x04; 33]);
    let err = invalid_big_r
        .validate()
        .expect_err("uncompressed ECDSA point prefix must fail");
    assert_eq!(err.code(), RouterAbProtocolErrorCode::MalformedWirePayload);

    let mut invalid_scalar = router_ab_ecdsa_derivation_presignature_record();
    invalid_scalar.server_k_share32_b64u = b64u(&[0x11; 31]);
    let err = invalid_scalar
        .validate()
        .expect_err("short ECDSA scalar share must fail");
    assert_eq!(err.code(), RouterAbProtocolErrorCode::MalformedWirePayload);

    let mut invalid_entropy = router_ab_ecdsa_derivation_presignature_record();
    invalid_entropy.rerandomization_entropy32_b64u = b64u(&[0x55; 31]);
    let err = invalid_entropy
        .validate()
        .expect_err("short ECDSA rerandomization entropy must fail");
    assert_eq!(err.code(), RouterAbProtocolErrorCode::MalformedWirePayload);
}

#[test]
fn durable_object_call_scopes_router_ab_ecdsa_derivation_presignature_storage_key() {
    let record = router_ab_ecdsa_derivation_presignature_record();
    let put_call = CloudflareDurableObjectCallV1::new(
        CloudflareWorkerRoleV1::SigningWorker,
        server_output_binding(),
        CloudflareDurableObjectRequestV1::signing_worker_ecdsa_presignature_put(record)
            .expect("ECDSA presignature put request"),
    )
    .expect("ECDSA presignature put call");

    assert_eq!(
        put_call.operation_kind(),
        CloudflareDurableObjectOperationKindV1::SigningWorkerEcdsaPresignaturePut
    );
    assert_eq!(
        put_call.storage_key(),
        format!(
            "SIGNING_WORKER_SERVER_OUTPUT_DO:signing-worker-ecdsa-presignature/wallet-1/{}/server-a/server-presignature-1",
            router_ab_ecdsa_derivation_active_state_session_id(&root_epoch())
        )
    );
}

#[test]
fn durable_object_call_scopes_router_ab_ecdsa_derivation_presignature_pool_storage_key() {
    let record = router_ab_ecdsa_derivation_presignature_pool_record();
    let put_call = CloudflareDurableObjectCallV1::new(
        CloudflareWorkerRoleV1::SigningWorker,
        server_output_binding(),
        CloudflareDurableObjectRequestV1::signing_worker_ecdsa_presignature_pool_put(record)
            .expect("ECDSA presignature pool put request"),
    )
    .expect("ECDSA presignature pool put call");

    assert_eq!(
        put_call.operation_kind(),
        CloudflareDurableObjectOperationKindV1::SigningWorkerEcdsaPresignaturePoolPut
    );
    assert_eq!(
        put_call.storage_key(),
        format!(
            "SIGNING_WORKER_SERVER_OUTPUT_DO:signing-worker-ecdsa-presignature-pool/wallet-1/{}/server-a/server-presignature-1",
            router_ab_ecdsa_derivation_active_state_session_id(&root_epoch())
        )
    );
}

#[test]
fn durable_object_handler_puts_and_takes_router_ab_ecdsa_derivation_presignature_once() {
    let record = router_ab_ecdsa_derivation_presignature_record();
    let put_call = CloudflareDurableObjectCallV1::new(
        CloudflareWorkerRoleV1::SigningWorker,
        server_output_binding(),
        CloudflareDurableObjectRequestV1::signing_worker_ecdsa_presignature_put(record.clone())
            .expect("ECDSA presignature put request"),
    )
    .expect("ECDSA presignature put call");
    let take_call = CloudflareDurableObjectCallV1::new(
        CloudflareWorkerRoleV1::SigningWorker,
        server_output_binding(),
        CloudflareDurableObjectRequestV1::signing_worker_ecdsa_presignature_take(
            router_ab_ecdsa_derivation_presignature_lookup(1_500),
        )
        .expect("ECDSA presignature take request"),
    )
    .expect("ECDSA presignature take call");
    let mut storage = CloudflareDurableObjectMemoryStorageV1::new();

    let first_put =
        handle_cloudflare_durable_object_call_v1(&put_call, &mut storage).expect("first put");
    assert_eq!(
        first_put,
        CloudflareDurableObjectResponseV1::signing_worker_ecdsa_presignature_put(
            CloudflareSigningWorkerEcdsaPresignaturePutReceiptV1::from_record(&record, true)
                .expect("first put receipt")
        )
        .expect("first put response")
    );

    let second_put =
        handle_cloudflare_durable_object_call_v1(&put_call, &mut storage).expect("second put");
    assert_eq!(
        second_put,
        CloudflareDurableObjectResponseV1::signing_worker_ecdsa_presignature_put(
            CloudflareSigningWorkerEcdsaPresignaturePutReceiptV1::from_record(&record, false)
                .expect("second put receipt")
        )
        .expect("second put response")
    );

    let taken = handle_cloudflare_durable_object_call_v1(&take_call, &mut storage)
        .expect("ECDSA presignature take");
    assert_eq!(
        taken,
        CloudflareDurableObjectResponseV1::signing_worker_ecdsa_presignature_take(record)
            .expect("ECDSA presignature take response")
    );

    let missing = handle_cloudflare_durable_object_call_v1(&take_call, &mut storage)
        .expect_err("ECDSA presignature take must be single-use");
    assert_eq!(
        missing.code(),
        RouterAbProtocolErrorCode::MissingLocalBinding
    );
}

#[test]
fn durable_object_handler_puts_and_takes_router_ab_ecdsa_derivation_presignature_pool_once() {
    let record = router_ab_ecdsa_derivation_presignature_pool_record();
    let put_call = CloudflareDurableObjectCallV1::new(
        CloudflareWorkerRoleV1::SigningWorker,
        server_output_binding(),
        CloudflareDurableObjectRequestV1::signing_worker_ecdsa_presignature_pool_put(
            record.clone(),
        )
        .expect("ECDSA presignature pool put request"),
    )
    .expect("ECDSA presignature pool put call");
    let take_call = CloudflareDurableObjectCallV1::new(
        CloudflareWorkerRoleV1::SigningWorker,
        server_output_binding(),
        CloudflareDurableObjectRequestV1::signing_worker_ecdsa_presignature_pool_take(
            router_ab_ecdsa_derivation_presignature_pool_lookup(1_500),
        )
        .expect("ECDSA presignature pool take request"),
    )
    .expect("ECDSA presignature pool take call");
    let mut storage = CloudflareDurableObjectMemoryStorageV1::new();

    let first_put =
        handle_cloudflare_durable_object_call_v1(&put_call, &mut storage).expect("first put");
    assert_eq!(
        first_put,
        CloudflareDurableObjectResponseV1::signing_worker_ecdsa_presignature_pool_put(
            CloudflareSigningWorkerEcdsaPresignaturePoolPutReceiptV1::from_record(&record, true)
                .expect("first pool put receipt")
        )
        .expect("first pool put response")
    );

    let second_put =
        handle_cloudflare_durable_object_call_v1(&put_call, &mut storage).expect("second put");
    assert_eq!(
        second_put,
        CloudflareDurableObjectResponseV1::signing_worker_ecdsa_presignature_pool_put(
            CloudflareSigningWorkerEcdsaPresignaturePoolPutReceiptV1::from_record(&record, false)
                .expect("second pool put receipt")
        )
        .expect("second pool put response")
    );

    let taken = handle_cloudflare_durable_object_call_v1(&take_call, &mut storage)
        .expect("ECDSA presignature pool take");
    assert_eq!(
        taken,
        CloudflareDurableObjectResponseV1::signing_worker_ecdsa_presignature_pool_take(record)
            .expect("ECDSA presignature pool take response")
    );

    let missing = handle_cloudflare_durable_object_call_v1(&take_call, &mut storage)
        .expect_err("ECDSA presignature pool take must be single-use");
    assert_eq!(
        missing.code(),
        RouterAbProtocolErrorCode::MissingLocalBinding
    );
}

#[test]
fn durable_object_handler_rejects_conflicting_router_ab_ecdsa_derivation_presignature_id() {
    let record = router_ab_ecdsa_derivation_presignature_record();
    let mut conflicting = record.clone();
    conflicting.server_k_share32_b64u = b64u(&[0x44; 32]);
    let put_call = CloudflareDurableObjectCallV1::new(
        CloudflareWorkerRoleV1::SigningWorker,
        server_output_binding(),
        CloudflareDurableObjectRequestV1::signing_worker_ecdsa_presignature_put(record)
            .expect("ECDSA presignature put request"),
    )
    .expect("ECDSA presignature put call");
    let conflicting_put_call = CloudflareDurableObjectCallV1::new(
        CloudflareWorkerRoleV1::SigningWorker,
        server_output_binding(),
        CloudflareDurableObjectRequestV1::signing_worker_ecdsa_presignature_put(conflicting)
            .expect("conflicting ECDSA presignature put request"),
    )
    .expect("conflicting ECDSA presignature put call");
    let mut storage = CloudflareDurableObjectMemoryStorageV1::new();

    handle_cloudflare_durable_object_call_v1(&put_call, &mut storage).expect("first put");
    let err = handle_cloudflare_durable_object_call_v1(&conflicting_put_call, &mut storage)
        .expect_err("conflicting ECDSA presignature material must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::ReplayedLocalRequest);
}

#[test]
fn durable_object_handler_rejects_expired_router_ab_ecdsa_derivation_presignature_take() {
    let record = router_ab_ecdsa_derivation_presignature_record();
    let put_call = CloudflareDurableObjectCallV1::new(
        CloudflareWorkerRoleV1::SigningWorker,
        server_output_binding(),
        CloudflareDurableObjectRequestV1::signing_worker_ecdsa_presignature_put(record.clone())
            .expect("ECDSA presignature put request"),
    )
    .expect("ECDSA presignature put call");
    let expired_take_call = CloudflareDurableObjectCallV1::new(
        CloudflareWorkerRoleV1::SigningWorker,
        server_output_binding(),
        CloudflareDurableObjectRequestV1::signing_worker_ecdsa_presignature_take(
            router_ab_ecdsa_derivation_presignature_lookup(record.expires_at_ms),
        )
        .expect("expired ECDSA presignature take request"),
    )
    .expect("expired ECDSA presignature take call");
    let mut storage = CloudflareDurableObjectMemoryStorageV1::new();

    handle_cloudflare_durable_object_call_v1(&put_call, &mut storage).expect("first put");
    let err = handle_cloudflare_durable_object_call_v1(&expired_take_call, &mut storage)
        .expect_err("expired ECDSA presignature material must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::ExpiredLocalRequest);
    assert!(
        storage
            .signing_worker_ecdsa_presignature(&put_call.storage_key())
            .is_some(),
        "failed exact lookup must not consume ECDSA presignature material"
    );
}

#[test]
fn durable_object_handler_rejects_router_ab_ecdsa_derivation_request_digest_mismatch_without_consuming_record(
) {
    let record = router_ab_ecdsa_derivation_presignature_record();
    let put_call = CloudflareDurableObjectCallV1::new(
        CloudflareWorkerRoleV1::SigningWorker,
        server_output_binding(),
        CloudflareDurableObjectRequestV1::signing_worker_ecdsa_presignature_put(record)
            .expect("ECDSA presignature put request"),
    )
    .expect("ECDSA presignature put call");
    let request = router_ab_ecdsa_derivation_digest_signing_request();
    let mismatched_lookup = CloudflareSigningWorkerEcdsaPresignatureLookupV1::new(
        active_signing_worker_state_for_router_ab_ecdsa_derivation(),
        "server-presignature-1",
        digest(0x87),
        request
            .signing_digest()
            .expect("Router A/B ECDSA derivation signing digest"),
        1_500,
    )
    .expect("mismatched ECDSA presignature lookup");
    let mismatched_take_call = CloudflareDurableObjectCallV1::new(
        CloudflareWorkerRoleV1::SigningWorker,
        server_output_binding(),
        CloudflareDurableObjectRequestV1::signing_worker_ecdsa_presignature_take(mismatched_lookup)
            .expect("mismatched ECDSA presignature take request"),
    )
    .expect("mismatched ECDSA presignature take call");
    let mut storage = CloudflareDurableObjectMemoryStorageV1::new();

    handle_cloudflare_durable_object_call_v1(&put_call, &mut storage).expect("first put");
    let err = handle_cloudflare_durable_object_call_v1(&mismatched_take_call, &mut storage)
        .expect_err("mismatched ECDSA request digest must fail");

    assert_eq!(
        err.code(),
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig
    );
    assert!(
        storage
            .signing_worker_ecdsa_presignature(&put_call.storage_key())
            .is_some(),
        "failed exact lookup must not consume ECDSA presignature material"
    );
}

#[test]
fn durable_object_cleanup_removes_expired_router_ab_ecdsa_derivation_presignature_records() {
    let expired_record = router_ab_ecdsa_derivation_presignature_record();
    let mut active_record = expired_record.clone();
    active_record.server_presignature_id = "server-presignature-active".to_owned();
    active_record.expires_at_ms = 3_000;
    let expired_put_call = CloudflareDurableObjectCallV1::new(
        CloudflareWorkerRoleV1::SigningWorker,
        server_output_binding(),
        CloudflareDurableObjectRequestV1::signing_worker_ecdsa_presignature_put(expired_record)
            .expect("expired ECDSA presignature put request"),
    )
    .expect("expired ECDSA presignature put call");
    let active_put_call = CloudflareDurableObjectCallV1::new(
        CloudflareWorkerRoleV1::SigningWorker,
        server_output_binding(),
        CloudflareDurableObjectRequestV1::signing_worker_ecdsa_presignature_put(active_record)
            .expect("active ECDSA presignature put request"),
    )
    .expect("active ECDSA presignature put call");
    let cleanup_call = CloudflareDurableObjectCallV1::new(
        CloudflareWorkerRoleV1::SigningWorker,
        server_output_binding(),
        CloudflareDurableObjectRequestV1::signing_worker_ecdsa_presignature_cleanup_expired(
            CloudflareExpiredStateCleanupRequestV1::new(2_000).expect("cleanup request"),
        )
        .expect("ECDSA presignature cleanup request"),
    )
    .expect("ECDSA presignature cleanup call");
    let mut storage = CloudflareDurableObjectMemoryStorageV1::new();

    handle_cloudflare_durable_object_call_v1(&expired_put_call, &mut storage)
        .expect("expired ECDSA presignature put");
    handle_cloudflare_durable_object_call_v1(&active_put_call, &mut storage)
        .expect("active ECDSA presignature put");
    let response =
        handle_cloudflare_durable_object_call_v1(&cleanup_call, &mut storage).expect("cleanup");

    assert_eq!(
        response,
        CloudflareDurableObjectResponseV1::signing_worker_ecdsa_presignature_cleanup_expired(
            CloudflareExpiredStateCleanupReportV1::new(2_000, 1, 0).expect("cleanup report")
        )
        .expect("cleanup response")
    );
    assert!(storage
        .signing_worker_ecdsa_presignature(&expired_put_call.storage_key())
        .is_none());
    assert!(storage
        .signing_worker_ecdsa_presignature(&active_put_call.storage_key())
        .is_some());
}

#[test]
fn durable_object_handler_allows_newer_signing_worker_output_refresh_activation() {
    let initial_activation = signing_worker_activation();
    let initial_material = server_output_material_record(&initial_activation);
    let initial_call = CloudflareDurableObjectCallV1::new(
        CloudflareWorkerRoleV1::SigningWorker,
        server_output_binding(),
        CloudflareDurableObjectRequestV1::signing_worker_output_activate(
            initial_activation,
            initial_material,
            TEST_ACTIVATED_AT_MS,
        )
        .expect("initial activation request"),
    )
    .expect("initial activation call");
    let mut storage = CloudflareDurableObjectMemoryStorageV1::new();
    handle_cloudflare_durable_object_call_v1(&initial_call, &mut storage)
        .expect("initial activation");

    let refresh_activation = signing_worker_refresh_activation("lifecycle-refresh-1", 0x66, 0x67);
    let refresh_material = server_output_material_record(&refresh_activation);
    let refresh_call = CloudflareDurableObjectCallV1::new(
        CloudflareWorkerRoleV1::SigningWorker,
        server_output_binding(),
        CloudflareDurableObjectRequestV1::signing_worker_output_activate(
            refresh_activation.clone(),
            refresh_material,
            TEST_ACTIVATED_AT_MS + 1,
        )
        .expect("refresh activation request"),
    )
    .expect("refresh activation call");
    let active_state_index_key = refresh_call
        .active_signing_worker_state_index_storage_key()
        .expect("active SigningWorker index key");

    let response = handle_cloudflare_durable_object_call_v1(&refresh_call, &mut storage)
        .expect("newer refresh activation");
    let expected_active_state = cloudflare_active_signing_worker_state_from_activation_request_v1(
        &refresh_activation,
        refresh_call.storage_key(),
        TEST_ACTIVATED_AT_MS + 1,
    )
    .expect("refresh active state");
    assert_eq!(
        response,
        CloudflareDurableObjectResponseV1::signing_worker_output_activate(
            CloudflareSigningWorkerOutputActivationReceiptV1::new(
                "lifecycle-refresh-1",
                "server-a",
                refresh_activation.activation_context.transcript_digest(),
                expected_active_state.clone(),
                true,
            )
            .expect("refresh receipt")
        )
        .expect("refresh response")
    );
    assert_eq!(
        storage.active_signing_worker_state(&active_state_index_key),
        Some(&expected_active_state)
    );
}

#[test]
fn durable_object_handler_rejects_stale_signing_worker_output_refresh_activation() {
    let initial_activation = signing_worker_activation();
    let initial_material = server_output_material_record(&initial_activation);
    let initial_call = CloudflareDurableObjectCallV1::new(
        CloudflareWorkerRoleV1::SigningWorker,
        server_output_binding(),
        CloudflareDurableObjectRequestV1::signing_worker_output_activate(
            initial_activation.clone(),
            initial_material,
            TEST_ACTIVATED_AT_MS,
        )
        .expect("initial activation request"),
    )
    .expect("initial activation call");
    let mut storage = CloudflareDurableObjectMemoryStorageV1::new();
    handle_cloudflare_durable_object_call_v1(&initial_call, &mut storage)
        .expect("initial activation");

    let stale_activation = signing_worker_refresh_activation("lifecycle-refresh-stale", 0x76, 0x77);
    let stale_material = server_output_material_record(&stale_activation);
    let stale_call = CloudflareDurableObjectCallV1::new(
        CloudflareWorkerRoleV1::SigningWorker,
        server_output_binding(),
        CloudflareDurableObjectRequestV1::signing_worker_output_activate(
            stale_activation,
            stale_material,
            TEST_ACTIVATED_AT_MS,
        )
        .expect("stale activation request"),
    )
    .expect("stale activation call");

    let err = handle_cloudflare_durable_object_call_v1(&stale_call, &mut storage)
        .expect_err("stale refresh activation must fail");
    assert_eq!(
        err.code(),
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig
    );

    let active_state_index_key = initial_call
        .active_signing_worker_state_index_storage_key()
        .expect("active SigningWorker index key");
    assert_eq!(
        storage.active_signing_worker_state(&active_state_index_key),
        Some(&active_signing_worker_state_for_activation(
            &initial_activation,
            initial_call.storage_key()
        ))
    );
}
