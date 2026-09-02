#![cfg(not(target_arch = "wasm32"))]

use base64::Engine;
use ed25519_dalek::{Signature as Ed25519Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hpke_ng::{DhKemX25519HkdfSha256, Kem};
use rand_core_06::SeedableRng;
use router_ab_cloudflare::{
    apply_cloudflare_signing_worker_ecdsa_pool_command_v1,
    build_cloudflare_ecdsa_threshold_prf_proof_batch_peer_message_v1,
    build_cloudflare_preloaded_signer_host_v1,
    build_cloudflare_preloaded_signer_host_with_root_share_wire_v1,
    build_cloudflare_router_public_keyset_v2,
    cloudflare_active_signing_worker_state_from_activation_request_v1,
    cloudflare_recipient_proof_bundle_response_from_ab_proof_batch_v1,
    cloudflare_router_ab_ecdsa_derivation_activation_receipt_from_material_v1,
    cloudflare_router_ab_ecdsa_derivation_activation_refresh_receipt_from_material_v1,
    cloudflare_router_ab_ecdsa_derivation_material_activation_ref_v1,
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
    handle_cloudflare_deriver_peer_request_v1,
    handle_cloudflare_signer_recipient_proof_bundle_private_request_v1,
    handle_cloudflare_signing_worker_normal_signing_finalize_private_request_v2,
    handle_cloudflare_signing_worker_normal_signing_prepare_private_request_v2,
    handle_cloudflare_signing_worker_router_ab_ecdsa_derivation_evm_digest_finalize_private_request_v1,
    handle_cloudflare_validated_mpc_prf_recipient_proof_bundle_signer_request_v1,
    open_cloudflare_signer_envelope_hpke_payload_v1, parse_cloudflare_deriver_a_bindings_v1,
    parse_cloudflare_deriver_b_bindings_v1, parse_cloudflare_deriver_peer_verifying_key_set_v1,
    parse_cloudflare_router_admission_bindings_v1,
    parse_cloudflare_router_authorized_ed25519_finalize_request_v2_json,
    parse_cloudflare_router_authorized_router_ab_ecdsa_derivation_finalize_request_v1_json,
    parse_cloudflare_signer_envelope_hpke_decrypt_key_binding_set_v1,
    parse_cloudflare_signer_envelope_hpke_decrypt_key_binding_v1,
    parse_cloudflare_signer_envelope_hpke_public_key_set_v1,
    parse_cloudflare_signer_envelope_hpke_rotation_public_key_set_v1,
    parse_cloudflare_signing_worker_bindings_v1,
    parse_cloudflare_tenant_root_control_plane_bindings_v1,
    parse_cloudflare_tenant_root_control_plane_issuer_signing_key_binding_v1,
    parse_cloudflare_worker_bindings_v1, seal_cloudflare_signer_envelope_hpke_payload_v1,
    validate_cloudflare_deriver_peer_request_v1, validate_cloudflare_deriver_peer_response_v1,
    validate_cloudflare_peer_signing_key_matches_request_v1,
    validate_cloudflare_router_ab_ecdsa_derivation_activation_refresh_request_for_router_payload_v1,
    validate_cloudflare_router_ab_ecdsa_derivation_export_request_for_router_payload_v1,
    validate_cloudflare_router_ab_ecdsa_derivation_normal_signing_active_material_v1,
    validate_cloudflare_router_ab_ecdsa_derivation_registration_request_for_router_payload_v1,
    validate_cloudflare_signer_private_request_plaintext_v1,
    validate_cloudflare_signer_private_request_v1,
    validate_cloudflare_signer_recipient_proof_bundle_private_response_v1,
    verify_cloudflare_deriver_peer_message_authentication_v1,
    CloudflareActiveSigningWorkerStateLookupV1, CloudflareDeriverABindingsV1,
    CloudflareDeriverAWorkerRuntimeV1, CloudflareDeriverBBindingsV1,
    CloudflareDeriverBWorkerRuntimeV1, CloudflareEd25519Round1StateV1,
    CloudflareEd25519YaoNormalSigningHandlerV1, CloudflareEnvMapV1, CloudflarePeerBindingV1,
    CloudflarePreloadedSignerHostV1,
    CloudflareRoleSeparatedRouterAbEcdsaDerivationEvmDigestFinalizeHandlerV1,
    CloudflareRootShareStartupMetadataV1, CloudflareRootShareWireSecretBindingV1,
    CloudflareRouterAbEcdsaDerivationActivationCommandV1,
    CloudflareRouterAbEcdsaDerivationActivationRefreshAdmissionResponseV1,
    CloudflareRouterAbEcdsaDerivationDeriverActivationRefreshPrivateRequestV1,
    CloudflareRouterAbEcdsaDerivationDeriverExportPrivateRequestV1,
    CloudflareRouterAbEcdsaDerivationDeriverRegistrationPrivateRequestV1,
    CloudflareRouterAbEcdsaDerivationEvmDigestFinalizeAdmissionCandidateV1,
    CloudflareRouterAbEcdsaDerivationEvmDigestPrepareAdmissionCandidateV1,
    CloudflareRouterAbEcdsaDerivationPendingSigningWorkerActivationV1,
    CloudflareRouterAbEcdsaDerivationSigningWorkerActivationReceiptV1,
    CloudflareRouterAbEcdsaDerivationSigningWorkerActivationRefreshRequestV1,
    CloudflareRouterAbEcdsaDerivationSigningWorkerActivationRequestV1,
    CloudflareRouterAbuseCheckV1, CloudflareRouterAdmissionBindingsV1,
    CloudflareRouterAdmissionChecksV1, CloudflareRouterAdmissionProviderOutputV1,
    CloudflareRouterAdmissionProviderV1, CloudflareRouterAllowedWorkKindsProjectPolicyProviderV1,
    CloudflareRouterAuthContextV1, CloudflareRouterBearerAuthorizationV1,
    CloudflareRouterBindingsV1, CloudflareRouterCompositeAdmissionProviderV1,
    CloudflareRouterConfiguredAbuseProviderV1, CloudflareRouterConfiguredQuotaProviderV1,
    CloudflareRouterEcdsaAcceptedAuthorizedOperationV1,
    CloudflareRouterEcdsaAcceptedCapabilityBindingV1, CloudflareRouterEcdsaAuthorizedOperationV1,
    CloudflareRouterEcdsaCapabilityKindV1, CloudflareRouterEcdsaOperationKindV1,
    CloudflareRouterEd25519JwksJwtVerifierV1, CloudflareRouterJwtSessionProviderV1,
    CloudflareRouterJwtVerifierBindingV1, CloudflareRouterJwtVerifierV1,
    CloudflareRouterNormalSigningAuthorizationV2,
    CloudflareRouterNormalSigningFinalizeAdmissionCandidateV2,
    CloudflareRouterNormalSigningPrepareAdmissionCandidateV2,
    CloudflareRouterNormalSigningTrustedAdmissionV1,
    CloudflareRouterNormalSigningTrustedMetadataV1, CloudflareRouterProjectPolicyBindingV1,
    CloudflareRouterProjectPolicyV1, CloudflareRouterPublicAdmissionPlanV1,
    CloudflareRouterQuotaCheckV1, CloudflareRouterRecipientProofBundleResponseV1,
    CloudflareRouterTrustedAdmissionV1, CloudflareRouterTrustedRequestMetadataV1,
    CloudflareRouterVerifiedJwtClaimsV1, CloudflareRouterVerifiedSessionProviderV1,
    CloudflareRouterVerifiedSessionV1, CloudflareRouterVerifiedWalletSessionV1,
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
    CloudflareSignerRecipientProofBundleWireHandlerV1, CloudflareSignerWireHandlerV1,
    CloudflareSigningWorkerAdmittedNormalSigningFinalizeRequestV2,
    CloudflareSigningWorkerAdmittedNormalSigningPrepareRequestV2,
    CloudflareSigningWorkerAdmittedRouterAbEcdsaDerivationEvmDigestFinalizeRequestV1,
    CloudflareSigningWorkerAdmittedRouterAbEcdsaDerivationEvmDigestSigningRequestV1,
    CloudflareSigningWorkerAuthorizedOperationIdentityV1, CloudflareSigningWorkerBindingsV1,
    CloudflareSigningWorkerEcdsaPoolCommandV1, CloudflareSigningWorkerEcdsaPoolConsumeDecisionV1,
    CloudflareSigningWorkerEcdsaPoolLifecycleRecordV1,
    CloudflareSigningWorkerEcdsaPoolMutationOutcomeV1,
    CloudflareSigningWorkerEcdsaPresignaturePoolRecordV1,
    CloudflareSigningWorkerEcdsaPresignatureRecordV1,
    CloudflareSigningWorkerMaterializedNormalSigningFinalizeRequestV2,
    CloudflareSigningWorkerMaterializedRouterAbEcdsaDerivationEvmDigestFinalizeRequestV1,
    CloudflareSigningWorkerMaterializedRouterAbEcdsaDerivationEvmDigestSigningRequestV1,
    CloudflareSigningWorkerNormalSigningEffectClaimV1,
    CloudflareSigningWorkerNormalSigningTerminalV1,
    CloudflareSigningWorkerOutputActivationReceiptV1,
    CloudflareSigningWorkerPresignSessionBindingV1, CloudflareSigningWorkerPrivateD1RequestV1,
    CloudflareSigningWorkerRecipientProofBundleActivationRequestV1,
    CloudflareSigningWorkerRecipientProofBundleActivationV1,
    CloudflareSigningWorkerReusableWalletSessionEffectClaimV1,
    CloudflareSigningWorkerRound1RecordV1,
    CloudflareSigningWorkerRouterAbEcdsaDerivationEvmDigestFinalizeHandlerV1,
    CloudflareSigningWorkerRouterAbEcdsaDerivationEvmDigestPreparedV1,
    CloudflareSigningWorkerRouterAbEcdsaDerivationPresignaturePoolPutRequestV1,
    CloudflareSigningWorkerRuntimeV1, CloudflareTenantRootControlPlaneIssuerVerifyingKeysV1,
    CloudflareTenantRootCustodyBindingWireV1, CloudflareWorkerBindingsV1, CloudflareWorkerRoleV1,
    EcdsaVerifiedClientActivationFactsV1, PoolRecord, TombstoneReason,
    CLOUDFLARE_ROOT_SHARE_WIRE_SECRET_PREFIX_V1,
    CLOUDFLARE_SERVER_OUTPUT_HPKE_PRIVATE_KEY_SECRET_PREFIX_V1,
    CLOUDFLARE_SIGNER_ENVELOPE_HPKE_PRIVATE_KEY_SECRET_PREFIX_V1,
    DERIVER_A_ENVELOPE_HPKE_KEY_EPOCH_ENV, DERIVER_A_ENVELOPE_HPKE_PRIVATE_KEY_BINDING_ENV,
    DERIVER_A_ENVELOPE_HPKE_PUBLIC_KEY_ENV, DERIVER_A_PEER_BINDING_ENV,
    DERIVER_A_PEER_SIGNING_KEY_BINDING_ENV, DERIVER_A_PEER_SIGNING_KEY_EPOCH_ENV,
    DERIVER_A_PEER_VERIFYING_KEY_HEX_ENV, DERIVER_A_PREVIOUS_ENVELOPE_HPKE_KEY_EPOCH_ENV,
    DERIVER_A_PREVIOUS_ENVELOPE_HPKE_PRIVATE_KEY_BINDING_ENV,
    DERIVER_A_PREVIOUS_ENVELOPE_HPKE_PUBLIC_KEY_ENV, DERIVER_A_ROOT_SHARE_WIRE_SECRET_BINDING_ENV,
    DERIVER_B_ENVELOPE_HPKE_KEY_EPOCH_ENV, DERIVER_B_ENVELOPE_HPKE_PRIVATE_KEY_BINDING_ENV,
    DERIVER_B_ENVELOPE_HPKE_PUBLIC_KEY_ENV, DERIVER_B_PEER_BINDING_ENV,
    DERIVER_B_PEER_SIGNING_KEY_BINDING_ENV, DERIVER_B_PEER_SIGNING_KEY_EPOCH_ENV,
    DERIVER_B_PEER_VERIFYING_KEY_HEX_ENV, DERIVER_B_PREVIOUS_ENVELOPE_HPKE_KEY_EPOCH_ENV,
    DERIVER_B_PREVIOUS_ENVELOPE_HPKE_PUBLIC_KEY_ENV, DERIVER_B_ROOT_SHARE_WIRE_SECRET_BINDING_ENV,
    ROUTER_AB_PREVIOUS_ENVELOPE_HPKE_RETIRE_AT_MS_ENV, ROUTER_JWT_AUDIENCE_ENV,
    ROUTER_JWT_ISSUER_ENV, ROUTER_JWT_JWKS_JSON_ENV, ROUTER_PROJECT_POLICY_BOOTSTRAP_JSON_ENV,
    SIGNING_WORKER_PEER_BINDING_ENV, SIGNING_WORKER_PRESIGN_SESSION_DO_BINDING_ENV,
    SIGNING_WORKER_PRESIGN_SESSION_DO_KEY_PREFIX_ENV, SIGNING_WORKER_PRESIGN_SESSION_DO_OBJECT_ENV,
    SIGNING_WORKER_SERVER_OUTPUT_HPKE_KEY_EPOCH_ENV,
    SIGNING_WORKER_SERVER_OUTPUT_HPKE_PRIVATE_KEY_BINDING_ENV,
    SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY_ENV,
    TENANT_ROOT_CONTROL_PLANE_ISSUER_VERIFYING_KEYS_JSON_ENV,
};
use router_ab_core::{
    ab_peer_message_authentication_input_digest_v1, decode_recipient_proof_bundle_ciphertext_v1,
    decode_router_to_signer_payload_v1, encode_ab_peer_message_authentication_input_v1,
    encode_recipient_proof_bundle_ciphertext_v1, AbPeerMessageAuthenticationV1,
    AbPeerMessagePayloadV1, AbPeerMessageSignatureSchemeV1, AbPeerMessageVerifyingKeyV1,
    ActiveSigningWorkerStateV1, CanonicalWireBytesV1, Clock, Csprng, EcdsaThresholdPrfRequestV1,
    EncryptedPayloadV1, ExpensiveWorkGateContextV1, ExpensiveWorkGateDecisionV1,
    ExpensiveWorkKindV1, GateDeferReasonV1, GatePrincipalV1, GateRejectReasonV1, LifecycleScopeV1,
    MpcMaterialActivationRefV1, MpcPrfOutputRequestV1, MpcPrfSigningRootShareWireV1,
    NormalSigningAuthorizationV1, NormalSigningEd25519TwoPartyFrostCommitmentsV1,
    NormalSigningScopeV1, OpenedShareKind, PeerTransport, RecipientOutputEncryptionAlgorithmV1,
    RecipientProofBundleCiphertextV1, RecipientProofBundleEncryptionRequestV1,
    RecipientProofBundleEncryptorV1, RoleEncryptedEnvelopeV1, RoleEnvelopeAadV1,
    RouterAbLifecycleStateV1, RouterAbProtocolErrorCode, RouterAbProtocolResult,
    RouterToSignerPayloadV1, RouterTranscriptMetadataV1, ServerIdentityV1,
    SignerEnvelopeHpkePayloadV1, SignerIdentityV1, SignerInputPlaintextV1,
    SignerInputQuorumPolicyV1, SignerKeyStore, SignerSetV1, SigningRootShareStore,
    WireMessageKindV1, WireMessageV1, MPC_PRF_SIGNING_ROOT_SHARE_WIRE_V1_LEN,
    SIGNER_ENVELOPE_HPKE_ENCAPPED_KEY_LEN_V1, SIGNER_ENVELOPE_HPKE_TAG_LEN_V1,
};
use router_ab_core::{
    router_ab_ecdsa_rerandomization_client_commitment_v1, router_transcript_digest_v1,
    PublicDigest32, RequestKind, Role, RootShareEpoch,
    RouterAbEcdsaDerivationActivationRefreshRequestV1,
    RouterAbEcdsaDerivationEvmDigestSigningFinalizeRequestV1,
    RouterAbEcdsaDerivationEvmDigestSigningPrepareResponseV1,
    RouterAbEcdsaDerivationEvmDigestSigningRequestV1,
    RouterAbEcdsaDerivationEvmDigestSigningResponseV1,
    RouterAbEcdsaDerivationExplicitExportRequestV1, RouterAbEcdsaDerivationOperationDigestsV1,
    RouterAbEcdsaDerivationPublicIdentityV1, RouterAbEcdsaDerivationRegistrationBootstrapRequestV1,
    RouterAbEcdsaDerivationRegistrationPurposeV1, RouterAbEcdsaDerivationStableKeyContextV1,
    RouterAbEd25519NormalSigningFinalizeProtocolV2, RouterAbEd25519NormalSigningFinalizeRequestV2,
    RouterAbEd25519NormalSigningIntentV2, RouterAbEd25519NormalSigningPrepareBindingV2,
    RouterAbEd25519NormalSigningPrepareRequestV2, RouterAbEd25519SigningPayloadV2,
    RouterAbEd25519TwoPartyFrostFinalizeProtocolV2, RouterAbNearNetworkIdV2,
    RouterAbNearTransactionIntentV1, TenantRootDerivationNonceV1,
    TenantRootDerivationOperationIdV1, TenantRootDerivationSessionIdV1, TenantRootProtocolDigestV1,
};
use router_ab_ecdsa_derivation::derive_relayer_share_for_client_public;
use router_ab_ecdsa_online::{
    compute_client_signature_share, ClientPresignMaterial, OnlineClientInput,
};
use router_ab_ecdsa_presign::session::{
    derive_presign_pair_context, ClientPresignSession, SigningWorkerPresignSession,
};
use router_ab_ecdsa_presign::AdditiveKeyShare;
use router_ab_ecdsa_wire::{CompressedPointBytes, ScalarBytes};
use sha2::{Digest as Sha2Digest, Sha256};
use signer_core::near_threshold_ed25519::{
    build_signing_package, client_round1_commit, client_round2_signature_share,
    key_package_from_signing_share_bytes, signature_share_to_b64u,
    verifying_share_bytes_from_signing_share_bytes, ClientRound1State,
};
use signer_core::near_threshold_frost::compute_threshold_ed25519_group_public_key_2p_from_verifying_shares;
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
        activation.material_activation.clone(),
        material_handle,
        TEST_ACTIVATED_AT_MS,
    )
    .expect("active SigningWorker state")
}

fn normal_signing_scope() -> NormalSigningScopeV1 {
    normal_signing_scope_for_request_id("sign-request-1")
}

fn normal_signing_scope_for_request_id(request_id: &str) -> NormalSigningScopeV1 {
    NormalSigningScopeV1::new(
        request_id,
        "account.near",
        NormalSigningAuthorizationV1::reusable_wallet_session("wallet-session-1")
            .expect("normal signing authorization"),
        MpcMaterialActivationRefV1::new(
            "session-1",
            "ed25519-signing-capability-1",
            "account.near",
            "ed25519-public-key-1",
            "ed25519-material-lifecycle-1",
            "server-a",
        )
        .expect("normal signing material activation"),
        "server-a",
    )
    .expect("normal signing scope")
}

fn normal_signing_v2_wallet_session(expires_at_ms: u64) -> CloudflareRouterVerifiedWalletSessionV1 {
    CloudflareRouterVerifiedWalletSessionV1::new(
        "user-1",
        "account.near",
        "authorization-1",
        "wallet-session-1",
        "quota-1",
        "threshold-session-1",
        "org-1",
        "project-1",
        "dev",
        "near-ed25519",
        "server-a",
        digest(0x90),
        expires_at_ms,
    )
    .expect("wallet session")
}

fn ecdsa_wallet_session(expires_at_ms: u64) -> CloudflareRouterVerifiedWalletSessionV1 {
    CloudflareRouterVerifiedWalletSessionV1::new(
        "wallet-1",
        "wallet-1",
        "authorization-1",
        "wallet-session-1",
        "quota-1",
        "ecdsa-material-lifecycle-1",
        "org-1",
        "project-1",
        "dev",
        "evm-family",
        "server-a",
        digest(0x90),
        expires_at_ms,
    )
    .expect("ECDSA wallet session")
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
        digest(0x91),
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
        MpcMaterialActivationRefV1::new(
            "session-1",
            "ed25519-signing-capability-1",
            "account.near",
            "ed25519-public-key-1",
            "ed25519-material-lifecycle-1",
            "server-a",
        )
        .expect("active SigningWorker material activation"),
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

fn presign_session_binding(binding_name: &str) -> CloudflareSigningWorkerPresignSessionBindingV1 {
    CloudflareSigningWorkerPresignSessionBindingV1::new(
        binding_name,
        format!("{binding_name}-object"),
        format!("{binding_name}:"),
    )
    .expect("durable object binding")
}

fn peer(peer_role: CloudflareWorkerRoleV1, binding_name: &str) -> CloudflarePeerBindingV1 {
    CloudflarePeerBindingV1::new(peer_role, binding_name).expect("peer binding")
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

fn signing_worker_presign_session_binding() -> CloudflareSigningWorkerPresignSessionBindingV1 {
    presign_session_binding("SIGNING_WORKER_PRESIGN_SESSION_DO")
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
            router_admission_bindings(),
            peer(CloudflareWorkerRoleV1::DeriverA, "DERIVER_A"),
            peer(CloudflareWorkerRoleV1::DeriverB, "DERIVER_B"),
            peer(CloudflareWorkerRoleV1::SigningWorker, "SIGNING_WORKER"),
            issuer_verifying_keys(),
        )
        .expect("router bindings"),
    )
    .expect("router runtime")
}

fn router_runtime_with_project_policy(
    allowed_work_kinds: &str,
    allow_normal_signing: bool,
) -> CloudflareRouterWorkerRuntimeV1 {
    let env = router_env().with_overrides(vec![(
        ROUTER_PROJECT_POLICY_BOOTSTRAP_JSON_ENV,
        configured_project_policy_json(allowed_work_kinds, allow_normal_signing),
    )]);
    let admission = parse_cloudflare_router_admission_bindings_v1(&env)
        .expect("configured router admission bindings");
    CloudflareRouterWorkerRuntimeV1::new(
        CloudflareRouterBindingsV1::new(
            admission,
            peer(CloudflareWorkerRoleV1::DeriverA, "DERIVER_A"),
            peer(CloudflareWorkerRoleV1::DeriverB, "DERIVER_B"),
            peer(CloudflareWorkerRoleV1::SigningWorker, "SIGNING_WORKER"),
            issuer_verifying_keys(),
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
            GatePrincipalV1::router_jwt_session("user-1", "session-1").expect("principal"),
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
        CloudflareRouterAuthContextV1::router_jwt_session("user-1", "session-1")
            .expect("auth context"),
        digest(0x90),
    )
    .expect("trusted metadata")
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
    let request = ecdsa_threshold_prf_request(2_000);
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
        "routerAbRequestPolicy": {
            "policyVersion": "policy-v1",
            "workKind": request.lifecycle.work_kind,
            "requestDigest": request.router_replay_digest(),
        },
    })
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
        _request_policy_digest: PublicDigest32,
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

fn router_ab_ecdsa_derivation_material_activation_for_epoch(
    epoch: &str,
) -> MpcMaterialActivationRefV1 {
    let context = router_ab_ecdsa_derivation_context();
    MpcMaterialActivationRefV1::new(
        format!("ecdsa-activation-{epoch}"),
        "ecdsa-signing-capability-1",
        ROUTER_AB_ECDSA_DERIVATION_WALLET_ID,
        b64u(
            context
                .context_binding_digest()
                .expect("context binding")
                .as_bytes(),
        ),
        "ecdsa-material-lifecycle-1",
        signer_set().selected_server.server_id.clone(),
    )
    .expect("ECDSA material activation")
}

fn router_ab_ecdsa_derivation_lifecycle_scope_for(
    lifecycle_id: &str,
    work_kind: ExpensiveWorkKindV1,
    epoch: RootShareEpoch,
) -> LifecycleScopeV1 {
    let session_id = format!("ecdsa-session-{}", epoch.as_str());
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
    router_ab_ecdsa_derivation_registration_request_for(
        RouterAbEcdsaDerivationRegistrationPurposeV1::WalletRegistration,
    )
}

fn router_ab_ecdsa_derivation_registration_request_for(
    purpose: RouterAbEcdsaDerivationRegistrationPurposeV1,
) -> RouterAbEcdsaDerivationRegistrationBootstrapRequestV1 {
    RouterAbEcdsaDerivationRegistrationBootstrapRequestV1::new(
        purpose,
        router_ab_ecdsa_derivation_context(),
        router_ab_ecdsa_derivation_lifecycle_scope(),
        signer_set(),
        "router-1",
        "client-1",
        "x25519:client-ephemeral-public-key",
        "ecdsa-replay-1",
        2_000,
        role_envelope(Role::SignerA, 0xa3),
        role_envelope(Role::SignerB, 0xb3),
    )
    .expect("Router A/B ECDSA derivation registration request")
}

fn router_ab_ecdsa_derivation_registration_request_with_aad_bound_envelopes(
) -> RouterAbEcdsaDerivationRegistrationBootstrapRequestV1 {
    router_ab_ecdsa_derivation_registration_request_with_aad_bound_envelopes_for(
        RouterAbEcdsaDerivationRegistrationPurposeV1::WalletRegistration,
    )
}

fn router_ab_ecdsa_derivation_registration_request_with_aad_bound_envelopes_for(
    purpose: RouterAbEcdsaDerivationRegistrationPurposeV1,
) -> RouterAbEcdsaDerivationRegistrationBootstrapRequestV1 {
    let base = router_ab_ecdsa_derivation_registration_request_for(purpose);
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
        &activation.pending.registration,
        &activation.client_activation,
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
        authorization: NormalSigningAuthorizationV1::reusable_wallet_session("session-1")
            .expect("export authorization"),
        material_activation: MpcMaterialActivationRefV1::new(
            "ecdsa-material-activation-1",
            "ecdsa-signing-capability-1",
            ROUTER_AB_ECDSA_DERIVATION_WALLET_ID,
            ROUTER_AB_ECDSA_DERIVATION_WALLET_KEY_ID,
            "ecdsa-material-lifecycle-1",
            "server-a",
        )
        .expect("ECDSA export material activation"),
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
        material_activation: router_ab_ecdsa_derivation_material_activation_for_epoch(
            next_root_epoch().as_str(),
        ),
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
    let pending = CloudflareRouterAbEcdsaDerivationPendingSigningWorkerActivationV1::new(
        registration,
        TenantRootProtocolDigestV1::from_bytes([0x55; 32]).expect("custody binding digest"),
        router_payload,
        activation,
    )
    .expect("pending Router A/B ECDSA derivation SigningWorker activation");
    let client_activation = EcdsaVerifiedClientActivationFactsV1 {
        registration_request_digest_b64u: b64u(
            pending
                .registration
                .request_digest()
                .expect("registration request digest")
                .as_bytes(),
        ),
        proof_transcript_digest_b64u: b64u(
            pending.activation_context.transcript_digest().as_bytes(),
        ),
        context_binding32_b64u: b64u(
            pending
                .registration
                .context
                .context_binding_digest()
                .expect("context binding")
                .as_bytes(),
        ),
        derivation_client_share_public_key33_b64u: b64u(
            &ecdsa_derivation_client_share_public_key33(),
        ),
        client_share_retry_counter: 0,
        participant_id: 1,
    };
    let activation_correlation_id = pending.activation_context.lifecycle.lifecycle_id.clone();
    CloudflareRouterAbEcdsaDerivationSigningWorkerActivationRequestV1::new(
        activation_correlation_id,
        pending,
        client_activation,
        router_ab_ecdsa_derivation_material_activation_for_epoch("epoch-1"),
    )
    .expect("Router A/B ECDSA derivation SigningWorker activation request")
}

#[test]
fn router_mints_stable_domain_separated_ecdsa_material_activation() {
    let existing = router_ab_ecdsa_derivation_activation_request();
    let command = CloudflareRouterAbEcdsaDerivationActivationCommandV1::new(
        existing.activation_correlation_id.clone(),
        existing.pending.clone(),
        existing.client_activation.clone(),
    )
    .expect("public ECDSA activation command");
    let first = cloudflare_router_ab_ecdsa_derivation_material_activation_ref_v1(&command)
        .expect("Router-minted ECDSA activation ref");
    let second = cloudflare_router_ab_ecdsa_derivation_material_activation_ref_v1(&command)
        .expect("idempotent Router-minted ECDSA activation ref");

    assert_eq!(first, second);
    assert_eq!(
        first.activation_id,
        "ecdsa-activation-v1-crkrm9mr28cJQj6z6haRzW0ZBSw1NH5DYdl7bKNtpJQ"
    );
    assert_eq!(
        first.capability,
        "ecdsa-capability-v1-Mm1SNWRATVrl4lCOPo5qXuNy_yho_YlWScmJC3M4DU8"
    );
    assert_ne!(first.activation_id, first.capability);
    assert!(first.activation_id.starts_with("ecdsa-activation-v1-"));
    assert!(first.capability.starts_with("ecdsa-capability-v1-"));
    assert_eq!(
        first.material_owner,
        command.pending.activation_context.lifecycle.account_id
    );
    assert_eq!(
        first.key_binding,
        command.client_activation.context_binding32_b64u
    );
    assert_eq!(
        first.lifecycle_binding,
        command.pending.activation_context.lifecycle.lifecycle_id
    );
    assert_eq!(
        first.signing_worker,
        command
            .pending
            .activation_context
            .signer_set()
            .selected_server
            .server_id
    );

    let mut public_json = serde_json::to_value(command).expect("public activation JSON");
    assert!(public_json.get("material_activation").is_none());
    public_json
        .as_object_mut()
        .expect("public activation object")
        .insert(
            "material_activation".to_string(),
            serde_json::to_value(existing.material_activation).expect("material activation JSON"),
        );
    assert!(
        serde_json::from_value::<CloudflareRouterAbEcdsaDerivationActivationCommandV1>(public_json)
            .is_err()
    );
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
        router_ab_ecdsa_derivation_material_activation_for_epoch("epoch-2"),
        TenantRootProtocolDigestV1::from_bytes([0x56; 32]).expect("custody binding digest"),
    )
    .expect("Router A/B ECDSA derivation SigningWorker activation-refresh request")
}

fn router_ab_ecdsa_derivation_server_material_record(
    activation: &CloudflareRouterAbEcdsaDerivationSigningWorkerActivationRequestV1,
) -> CloudflareServerOutputMaterialRecordV1 {
    let selected_server = &activation
        .pending
        .activation_context
        .signer_set()
        .selected_server;
    CloudflareServerOutputMaterialRecordV1::new(
        activation.pending.activation_context.transcript_digest(),
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
        activation.material_activation.clone(),
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
            ROUTER_AB_ECDSA_DERIVATION_WALLET_ID,
            ROUTER_AB_ECDSA_DERIVATION_THRESHOLD_KEY_ID,
            ROUTER_AB_ECDSA_DERIVATION_SIGNING_ROOT_ID,
            ROUTER_AB_ECDSA_DERIVATION_SIGNING_ROOT_VERSION,
            router_ab_ecdsa_derivation_material_activation_for_epoch(&receipt.activation_epoch),
        )
        .expect("Router A/B ECDSA derivation normal-signing scope");
    let material_activation = router_ab_ecdsa_derivation_material_activation(&scope);
    RouterAbEcdsaDerivationEvmDigestSigningRequestV1::new(
        scope,
        "router-ab-ecdsa-derivation-sign-request-1",
        "router-ab-ecdsa-operation-1",
        router_ab_ecdsa_derivation_operation_digests(),
        NormalSigningAuthorizationV1::reusable_wallet_session("ecdsa-wallet-session-1")
            .expect("ECDSA authorization"),
        material_activation,
        "server-presignature-1",
        2_000,
        b64u(&[0x77; 32]),
        b64u(&router_ab_ecdsa_rerandomization_client_commitment_v1(
            [0x66; 32],
        )),
    )
    .expect("Router A/B ECDSA derivation digest-signing request")
}

fn router_ab_ecdsa_derivation_digest_signing_finalize_request(
) -> RouterAbEcdsaDerivationEvmDigestSigningFinalizeRequestV1 {
    let request = router_ab_ecdsa_derivation_digest_signing_request();
    RouterAbEcdsaDerivationEvmDigestSigningFinalizeRequestV1::new(
        request.scope,
        request.request_id,
        request.operation_id,
        request.operation_digests,
        request.authorization,
        request.material_activation,
        request.expires_at_ms,
        request.signing_digest_b64u,
        request.client_presignature_id,
        b64u(&[0x88; 32]),
        b64u(&[0x66; 32]),
    )
    .expect("Router A/B ECDSA derivation digest-signing finalize request")
}

fn router_ab_ecdsa_derivation_operation_digests() -> RouterAbEcdsaDerivationOperationDigestsV1 {
    RouterAbEcdsaDerivationOperationDigestsV1 {
        lane_digest_b64u: b64u(&[0x31; 32]),
        intent_digest_b64u: b64u(&[0x77; 32]),
        display_digest_b64u: b64u(&[0x33; 32]),
    }
}

fn router_ab_ecdsa_derivation_material_activation(
    scope: &router_ab_core::RouterAbEcdsaDerivationNormalSigningScopeV1,
) -> MpcMaterialActivationRefV1 {
    scope.material_activation.clone()
}

fn router_ab_ecdsa_derivation_trusted_admission(
    request: &RouterAbEcdsaDerivationEvmDigestSigningRequestV1,
) -> CloudflareRouterNormalSigningTrustedAdmissionV1 {
    let auth = match &request.authorization {
        NormalSigningAuthorizationV1::ReusableWalletSession { wallet_session_id } => {
            CloudflareRouterAuthContextV1::owner_wallet_session(
                "subject-1",
                wallet_session_id.clone(),
            )
            .expect("Router A/B ECDSA derivation auth context")
        }
        NormalSigningAuthorizationV1::OperationStepUp => {
            CloudflareRouterAuthContextV1::owner_operation_step_up(
                "subject-1",
                "authorization-session-ecdsa-1",
            )
            .expect("Router A/B ECDSA derivation operation-step-up auth context")
        }
    };
    CloudflareRouterNormalSigningTrustedAdmissionV1::new(
        CloudflareRouterNormalSigningTrustedMetadataV1::new(
            "org-1",
            "project-1",
            "dev",
            request.scope.wallet_id.clone(),
            auth,
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
    let auth = match &request.authorization {
        NormalSigningAuthorizationV1::ReusableWalletSession { wallet_session_id } => {
            CloudflareRouterAuthContextV1::owner_wallet_session(
                "subject-1",
                wallet_session_id.clone(),
            )
            .expect("Router A/B ECDSA derivation finalize auth context")
        }
        NormalSigningAuthorizationV1::OperationStepUp => {
            CloudflareRouterAuthContextV1::owner_operation_step_up(
                "subject-1",
                "authorization-session-ecdsa-1",
            )
            .expect("Router A/B ECDSA derivation finalize operation-step-up auth context")
        }
    };
    CloudflareRouterNormalSigningTrustedAdmissionV1::new(
        CloudflareRouterNormalSigningTrustedMetadataV1::new(
            "org-1",
            "project-1",
            "dev",
            request.scope.wallet_id.clone(),
            auth,
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
    CloudflareRouterVerifiedWalletSessionV1::new(
        "subject-1",
        request.scope.wallet_id.clone(),
        "authorization-ecdsa-1",
        "ecdsa-wallet-session-1",
        "quota-ecdsa-1",
        "threshold-session-ecdsa-1",
        "org-1",
        "project-1",
        "dev",
        "evm-family",
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
    let effect_claim = ecdsa_effect_claim(&request);
    let effect_identity = ecdsa_effect_identity(&request);
    CloudflareSigningWorkerAdmittedRouterAbEcdsaDerivationEvmDigestFinalizeRequestV1::new(
        request,
        trusted_admission,
        effect_identity,
        effect_claim,
    )
    .expect("admitted Router A/B ECDSA derivation digest finalize request")
}

fn ecdsa_effect_claim(
    request: &RouterAbEcdsaDerivationEvmDigestSigningFinalizeRequestV1,
) -> CloudflareSigningWorkerNormalSigningEffectClaimV1 {
    match &request.authorization {
        NormalSigningAuthorizationV1::ReusableWalletSession { wallet_session_id } => {
            CloudflareSigningWorkerNormalSigningEffectClaimV1::ReusableWalletSession {
                claim: CloudflareSigningWorkerReusableWalletSessionEffectClaimV1::new(
                    "authorization-ecdsa-1",
                    wallet_session_id.clone(),
                    request.operation_id.clone(),
                    request.operation_id.clone(),
                    request.operation_digests.intent_digest_b64u.clone(),
                )
                .expect("ECDSA reusable effect claim"),
            }
        }
        NormalSigningAuthorizationV1::OperationStepUp => {
            CloudflareSigningWorkerNormalSigningEffectClaimV1::OperationStepUp {
                authorization_session_id: "authorization-session-ecdsa-1".to_owned(),
                authorized_operation_id: request.operation_id.clone(),
                operation_id: request.operation_id.clone(),
                operation_fingerprint_digest: request.operation_digests.intent_digest_b64u.clone(),
            }
        }
    }
}

fn ecdsa_effect_identity(
    request: &RouterAbEcdsaDerivationEvmDigestSigningFinalizeRequestV1,
) -> CloudflareSigningWorkerAuthorizedOperationIdentityV1 {
    match &request.authorization {
        NormalSigningAuthorizationV1::ReusableWalletSession { wallet_session_id } => {
            CloudflareSigningWorkerAuthorizedOperationIdentityV1::ReusableWalletSession {
                authorization_id: "authorization-ecdsa-1".to_owned(),
                wallet_session_id: wallet_session_id.clone(),
                authorized_operation_id: request.operation_id.clone(),
                operation_id: request.operation_id.clone(),
                operation_fingerprint_digest: request.operation_digests.intent_digest_b64u.clone(),
            }
        }
        NormalSigningAuthorizationV1::OperationStepUp => {
            CloudflareSigningWorkerAuthorizedOperationIdentityV1::OperationStepUp {
                authorization_session_id: "authorization-session-ecdsa-1".to_owned(),
                authorized_operation_id: request.operation_id.clone(),
                operation_id: request.operation_id.clone(),
                operation_fingerprint_digest: request.operation_digests.intent_digest_b64u.clone(),
            }
        }
    }
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
    client_additive_share32: &[u8; 32],
    relayer_additive_share32: &[u8; 32],
    public_key33: &[u8; 33],
) -> EcdsaPresignaturePairFixture {
    let key = CompressedPointBytes::new(*public_key33);
    let context = derive_presign_pair_context(key, "cloudflare-bindings-presign-pair")
        .expect("fixed presign context");
    let client_share = AdditiveKeyShare::from_bytes(ScalarBytes::new(*client_additive_share32))
        .expect("client additive share");
    let worker_share = AdditiveKeyShare::from_bytes(ScalarBytes::new(*relayer_additive_share32))
        .expect("SigningWorker additive share");
    let mut client_rng = rand_chacha::ChaCha20Rng::from_seed([0x81; 32]);
    let mut worker_rng = rand_chacha::ChaCha20Rng::from_seed([0x82; 32]);
    let mut client = ClientPresignSession::new(context, client_share, key, &mut client_rng)
        .expect("client presign session");
    let mut worker = SigningWorkerPresignSession::new(context, worker_share, key, &mut worker_rng)
        .expect("SigningWorker presign session");

    for _ in 0..9 {
        exchange_ecdsa_presign_round(&mut client, &mut worker, &mut client_rng, &mut worker_rng);
    }
    client.start_presign().expect("client starts presign");
    worker
        .start_presign()
        .expect("SigningWorker starts presign");
    for _ in 0..2 {
        exchange_ecdsa_presign_round(&mut client, &mut worker, &mut client_rng, &mut worker_rng);
    }

    let (client_big_r33, client_k_share32, client_sigma_share32) =
        split_ecdsa_presignature_97(client.take_presignature_97().expect("client presignature"));
    let (server_big_r33, server_k_share32, server_sigma_share32) = split_ecdsa_presignature_97(
        worker
            .take_presignature_97()
            .expect("SigningWorker presignature"),
    );
    assert_eq!(client_big_r33, server_big_r33);
    (
        server_big_r33,
        server_k_share32,
        server_sigma_share32,
        client_k_share32,
        client_sigma_share32,
    )
}

fn exchange_ecdsa_presign_round(
    client: &mut ClientPresignSession,
    worker: &mut SigningWorkerPresignSession,
    client_rng: &mut rand_chacha::ChaCha20Rng,
    worker_rng: &mut rand_chacha::ChaCha20Rng,
) {
    let client_messages = client.poll().outgoing;
    let worker_messages = worker.poll().outgoing;
    assert_eq!(client_messages.len(), 1);
    assert_eq!(worker_messages.len(), 1);
    client
        .message(&worker_messages[0], client_rng)
        .expect("client accepts SigningWorker frame");
    worker
        .message(&client_messages[0], worker_rng)
        .expect("SigningWorker accepts client frame");
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

fn router_ab_ecdsa_derivation_presignature_pool_record(
) -> CloudflareSigningWorkerEcdsaPresignaturePoolRecordV1 {
    CloudflareSigningWorkerEcdsaPresignaturePoolRecordV1::new(
        router_ab_ecdsa_derivation_digest_signing_request().scope,
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

fn router_ab_ecdsa_derivation_presignature_pool_record_with_expiry(
    expires_at_ms: u64,
) -> CloudflareSigningWorkerEcdsaPresignaturePoolRecordV1 {
    let mut record = router_ab_ecdsa_derivation_presignature_pool_record();
    record.expires_at_ms = expires_at_ms;
    record
        .validate()
        .expect("custom SigningWorker presignature expiry");
    record
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

fn test_router_jwks_json() -> &'static str {
    r#"{"keys":[{"alg":"EdDSA","crv":"Ed25519","kid":"test-router-key","kty":"OKP","use":"sig","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}]}"#
}

fn configured_project_policy_json(allowed_work_kinds: &str, allow_normal_signing: bool) -> String {
    format!(
        r#"{{"org_id":"org-1","project_id":"project-1","environment":"dev","allowed_work_kinds":[{allowed_work_kinds}],"allow_normal_signing":{allow_normal_signing},"rejected_retry_after_ms":1000}}"#
    )
}

/// The published control-plane issuer anchor every verifier Worker requires.
static ISSUER_VERIFYING_KEYS_JSON: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
    let verifying = SigningKey::from_bytes(&[0x51; 32])
        .verifying_key()
        .to_bytes();
    let hex: String = verifying.iter().map(|byte| format!("{byte:02x}")).collect();
    format!(
        "{{\"keys\":[{{\"issuer_key_id\":\"control-plane-issuer-v1\",\"verifying_key_hex\":\"{hex}\"}}]}}"
    )
});

/// Grant authorities the issuer trusts. Deliberately a different key from the
/// issuer's own: the bindings reject reuse.
static GRANT_AUTHORITY_VERIFYING_KEYS_JSON: std::sync::LazyLock<String> = std::sync::LazyLock::new(
    || {
        let verifying = SigningKey::from_bytes(&[0x71; 32])
            .verifying_key()
            .to_bytes();
        let hex: String = verifying.iter().map(|byte| format!("{byte:02x}")).collect();
        format!(
            "{{\"keys\":[{{\"issuer_key_id\":\"provisioning-authority-v1\",\"verifying_key_hex\":\"{hex}\"}}]}}"
        )
    },
);

/// The published role keyset the control plane resolves its configured signing
/// IDs against. Keys are distinct from the issuer and grant authorities.
static ROLE_VERIFYING_KEYS_JSON: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
    let hex = |seed: u8| -> String {
        SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    };
    format!(
        "{{\"keys\":[{{\"role\":\"deriver_a\",\"signing_key_id\":\"deriver-a-signing-key-7\",\"verifying_key_hex\":\"{}\"}},{{\"role\":\"deriver_b\",\"signing_key_id\":\"deriver-b-signing-key-9\",\"verifying_key_hex\":\"{}\"}}]}}",
        hex(0xa1),
        hex(0xb1)
    )
});

fn issuer_verifying_keys() -> CloudflareTenantRootControlPlaneIssuerVerifyingKeysV1 {
    CloudflareTenantRootControlPlaneIssuerVerifyingKeysV1::decode(&ISSUER_VERIFYING_KEYS_JSON)
        .expect("issuer verifying keys")
}

fn router_env() -> CloudflareEnvMapV1 {
    CloudflareEnvMapV1::new(vec![
        (
            TENANT_ROOT_CONTROL_PLANE_ISSUER_VERIFYING_KEYS_JSON_ENV,
            ISSUER_VERIFYING_KEYS_JSON.as_str(),
        ),
        (ROUTER_JWT_ISSUER_ENV, "https://issuer.example"),
        (ROUTER_JWT_AUDIENCE_ENV, "router-ab"),
        (ROUTER_JWT_JWKS_JSON_ENV, test_router_jwks_json()),
        (DERIVER_A_PEER_BINDING_ENV, "DERIVER_A"),
        (DERIVER_B_PEER_BINDING_ENV, "DERIVER_B"),
        (SIGNING_WORKER_PEER_BINDING_ENV, "SIGNING_WORKER"),
    ])
}

fn router_env_with_public_keyset() -> CloudflareEnvMapV1 {
    CloudflareEnvMapV1::new(vec![
        (
            TENANT_ROOT_CONTROL_PLANE_ISSUER_VERIFYING_KEYS_JSON_ENV,
            ISSUER_VERIFYING_KEYS_JSON.as_str(),
        ),
        (ROUTER_JWT_ISSUER_ENV, "https://issuer.example"),
        (ROUTER_JWT_AUDIENCE_ENV, "router-ab"),
        (ROUTER_JWT_JWKS_JSON_ENV, test_router_jwks_json()),
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
        (ROUTER_JWT_JWKS_JSON_ENV, test_router_jwks_json()),
    ])
}

fn router_admission_bindings() -> CloudflareRouterAdmissionBindingsV1 {
    parse_cloudflare_router_admission_bindings_v1(&router_admission_env())
        .expect("router admission bindings")
}

fn deriver_a_env() -> CloudflareEnvMapV1 {
    CloudflareEnvMapV1::new(vec![
        (
            TENANT_ROOT_CONTROL_PLANE_ISSUER_VERIFYING_KEYS_JSON_ENV,
            ISSUER_VERIFYING_KEYS_JSON.to_string(),
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
    ])
}

fn deriver_b_env() -> CloudflareEnvMapV1 {
    CloudflareEnvMapV1::new(vec![
        (
            TENANT_ROOT_CONTROL_PLANE_ISSUER_VERIFYING_KEYS_JSON_ENV,
            ISSUER_VERIFYING_KEYS_JSON.to_string(),
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
    ])
}

fn signing_worker_env() -> CloudflareEnvMapV1 {
    CloudflareEnvMapV1::new(vec![
        (
            SIGNING_WORKER_PRESIGN_SESSION_DO_BINDING_ENV,
            "SIGNING_WORKER_PRESIGN_SESSION_DO".to_string(),
        ),
        (
            SIGNING_WORKER_PRESIGN_SESSION_DO_OBJECT_ENV,
            "signing-worker-presign-session".to_string(),
        ),
        (
            SIGNING_WORKER_PRESIGN_SESSION_DO_KEY_PREFIX_ENV,
            "signing-worker-presign-session:".to_string(),
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
fn router_bindings_accept_stateless_router_peers() {
    let bindings = CloudflareRouterBindingsV1::new(
        router_admission_bindings(),
        peer(CloudflareWorkerRoleV1::DeriverA, "DERIVER_A"),
        peer(CloudflareWorkerRoleV1::DeriverB, "DERIVER_B"),
        peer(CloudflareWorkerRoleV1::SigningWorker, "SIGNING_WORKER"),
        issuer_verifying_keys(),
    )
    .expect("router bindings");
    let startup = CloudflareWorkerBindingsV1::router(bindings).expect("router startup");

    assert_eq!(startup.worker_role(), CloudflareWorkerRoleV1::Router);
    let CloudflareWorkerBindingsV1::Router { bindings } = startup else {
        panic!("expected router startup bindings");
    };
    assert_eq!(bindings.admission.jwt.audience, "router-ab");
}

#[test]
fn router_admission_bindings_parse_router_only_provider_config() {
    let bindings = parse_cloudflare_router_admission_bindings_v1(&router_admission_env())
        .expect("router admission bindings");

    assert_eq!(bindings.jwt.issuer, "https://issuer.example");
    assert_eq!(bindings.jwt.audience, "router-ab");
    assert!(matches!(
        bindings.project_policy,
        CloudflareRouterProjectPolicyBindingV1::AllowAll
    ));
}

#[test]
fn router_admission_bindings_parse_configured_project_policy() {
    let env = router_admission_env().with_overrides(vec![(
        ROUTER_PROJECT_POLICY_BOOTSTRAP_JSON_ENV,
        configured_project_policy_json("\"registration_prepare\"", true),
    )]);

    let bindings = parse_cloudflare_router_admission_bindings_v1(&env)
        .expect("configured router project policy");

    let CloudflareRouterProjectPolicyBindingV1::Configured {
        org_id,
        project_id,
        environment,
        allowed_work_kinds,
        allow_normal_signing,
        rejected_retry_after_ms,
    } = bindings.project_policy
    else {
        panic!("expected configured project policy");
    };
    assert_eq!(org_id, "org-1");
    assert_eq!(project_id, "project-1");
    assert_eq!(environment, "dev");
    assert_eq!(
        allowed_work_kinds,
        vec![ExpensiveWorkKindV1::RegistrationPrepare]
    );
    assert!(allow_normal_signing);
    assert_eq!(rejected_retry_after_ms, 1_000);
}

#[test]
fn router_admission_bindings_reject_malformed_project_policy() {
    let env = router_admission_env().with_overrides(vec![(
        ROUTER_PROJECT_POLICY_BOOTSTRAP_JSON_ENV,
        "{\"org_id\":\"org-1\"}",
    )]);

    let err = parse_cloudflare_router_admission_bindings_v1(&env)
        .expect_err("malformed project policy must fail startup parsing");

    assert_eq!(
        err.code(),
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig
    );
}

#[test]
fn router_admission_bindings_reject_missing_jwks_json() {
    let env = CloudflareEnvMapV1::new(vec![
        (ROUTER_JWT_ISSUER_ENV, "https://issuer.example"),
        (ROUTER_JWT_AUDIENCE_ENV, "router-ab"),
    ]);

    let err = parse_cloudflare_router_admission_bindings_v1(&env)
        .expect_err("missing JWKS JSON must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::MissingLocalBinding);
}

#[test]
fn router_jwt_binding_rejects_invalid_deployment_jwks() {
    let err = CloudflareRouterJwtVerifierBindingV1::new(
        "https://issuer.example",
        "router-ab",
        r#"{"keys":[]}"#,
    )
    .expect_err("empty deployment JWKS must fail");

    assert_eq!(
        err.code(),
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig
    );
}

#[test]
fn router_worker_runtime_normalizes_public_request_into_admission_plan() {
    let runtime = CloudflareRouterWorkerRuntimeV1::new(
        CloudflareRouterBindingsV1::new(
            router_admission_bindings(),
            peer(CloudflareWorkerRoleV1::DeriverA, "DERIVER_A"),
            peer(CloudflareWorkerRoleV1::DeriverB, "DERIVER_B"),
            peer(CloudflareWorkerRoleV1::SigningWorker, "SIGNING_WORKER"),
            issuer_verifying_keys(),
        )
        .expect("router bindings"),
    )
    .expect("router runtime");
    let request = ecdsa_threshold_prf_request(2_000);
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
}

#[test]
fn router_worker_runtime_builds_forward_plan_for_accepted_admission() {
    let runtime = CloudflareRouterWorkerRuntimeV1::new(
        CloudflareRouterBindingsV1::new(
            router_admission_bindings(),
            peer(CloudflareWorkerRoleV1::DeriverA, "DERIVER_A"),
            peer(CloudflareWorkerRoleV1::DeriverB, "DERIVER_B"),
            peer(CloudflareWorkerRoleV1::SigningWorker, "SIGNING_WORKER"),
            issuer_verifying_keys(),
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
        deriver_a_message,
        deriver_b_message,
        ..
    } = plan
    else {
        panic!("accepted admission must forward");
    };
    assert_eq!(deriver_a_message.kind, WireMessageKindV1::RouterToSignerA);
    assert_eq!(deriver_b_message.kind, WireMessageKindV1::RouterToSignerB);
}

#[test]
fn router_worker_runtime_builds_stop_plan_for_rejected_admission() {
    let runtime = CloudflareRouterWorkerRuntimeV1::new(
        CloudflareRouterBindingsV1::new(
            router_admission_bindings(),
            peer(CloudflareWorkerRoleV1::DeriverA, "DERIVER_A"),
            peer(CloudflareWorkerRoleV1::DeriverB, "DERIVER_B"),
            peer(CloudflareWorkerRoleV1::SigningWorker, "SIGNING_WORKER"),
            issuer_verifying_keys(),
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
    let CloudflareRouterPublicAdmissionPlanV1::Stop { trusted_admission } = plan else {
        panic!("rejected admission must stop");
    };
    assert!(matches!(
        trusted_admission.decision,
        ExpensiveWorkGateDecisionV1::Rejected { .. }
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
            GatePrincipalV1::router_jwt_session("user-1", "session-1").expect("principal"),
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
        CloudflareRouterAuthContextV1::router_jwt_session("user-1", "session-1")
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
            ecdsa_threshold_prf_request(2_000).router_replay_digest(),
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
fn router_ed25519_jwks_jwt_verifier_rejects_legacy_session_id_claim() {
    let signing_key = SigningKey::from_bytes(&[0x42; 32]);
    let jwks_json = ed25519_jwks_json(&signing_key, "router-key-1");
    let mut verifier = CloudflareRouterEd25519JwksJwtVerifierV1::from_jwks_json(&jwks_json)
        .expect("ed25519 jwks verifier");
    let mut claims = valid_router_jwt_claims();
    claims["session_id"] = claims["sid"].take();
    let token = ed25519_jwt(&signing_key, "router-key-1", claims);
    let authorization = CloudflareRouterBearerAuthorizationV1::from_authorization_header(&format!(
        "Bearer {token}"
    ))
    .expect("authorization");

    let error = verifier
        .verify_public_request_jwt(
            &router_admission_bindings().jwt,
            &authorization,
            &ecdsa_threshold_prf_request(2_000),
            ecdsa_threshold_prf_request(2_000).router_replay_digest(),
            1_000,
            digest(0x91),
        )
        .expect_err("legacy session_id must not satisfy canonical sid");

    assert_eq!(
        error.code(),
        RouterAbProtocolErrorCode::MalformedWirePayload
    );
}

#[test]
fn router_jwt_policy_binds_the_public_route_digest() {
    let signing_key = SigningKey::from_bytes(&[0x42; 32]);
    let jwks_json = ed25519_jwks_json(&signing_key, "router-key-1");
    let mut verifier = CloudflareRouterEd25519JwksJwtVerifierV1::from_jwks_json(&jwks_json)
        .expect("ed25519 jwks verifier");
    let route_digest = digest(0x67);
    let mut claims = valid_router_jwt_claims();
    claims["routerAbRequestPolicy"]["requestDigest"] =
        serde_json::to_value(route_digest).expect("route digest json");
    let token = ed25519_jwt(&signing_key, "router-key-1", claims);
    let authorization = CloudflareRouterBearerAuthorizationV1::from_authorization_header(&format!(
        "Bearer {token}"
    ))
    .expect("authorization");

    verifier
        .verify_public_request_jwt(
            &router_admission_bindings().jwt,
            &authorization,
            &ecdsa_threshold_prf_request(2_000),
            route_digest,
            1_000,
            digest(0x91),
        )
        .expect("route-bound claims");
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
            ecdsa_threshold_prf_request(2_000).router_replay_digest(),
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
            ecdsa_threshold_prf_request(2_000).router_replay_digest(),
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
            ecdsa_threshold_prf_request(2_000).router_replay_digest(),
            1_000,
            digest(0x91),
        )
        .expect_err("request scope mismatch must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidGateDecision);
}

#[test]
fn router_wallet_session_credential_accepts_gateway_owner_projection() {
    let session = normal_signing_v2_wallet_session(3_000);
    let credential = CloudflareRouterWalletSessionCredentialV1::gateway_owner(session.clone())
        .expect("Gateway owner credential");

    credential.validate().expect("credential validates");
    match credential {
        CloudflareRouterWalletSessionCredentialV1::GatewayOwner { wallet_session } => {
            assert_eq!(wallet_session.wallet_session_id, session.wallet_session_id);
        }
    }
}

#[test]
fn router_wallet_session_verifier_accepts_normal_signing_projection() {
    let signing_key = SigningKey::from_bytes(&[0x42; 32]);
    let jwks_json = ed25519_jwks_json(&signing_key, "router-key-1");
    let mut verifier = CloudflareRouterEd25519JwksJwtVerifierV1::from_jwks_json(&jwks_json)
        .expect("Ed25519 JWK verifier");
    let session = normal_signing_v2_wallet_session(3_000);
    let credential =
        CloudflareRouterWalletSessionCredentialV1::gateway_owner(session).expect("credential");

    let session = verifier
        .verify_wallet_session(
            &router_admission_bindings().jwt,
            &credential,
            digest(0x90),
            1_000,
        )
        .expect("Wallet Session verifies");

    assert_eq!(session.account_id, "account.near");
    assert_eq!(session.wallet_session_id, "wallet-session-1");
    assert_eq!(session.authorization_level, "near-ed25519");
    assert_eq!(session.signing_worker_id, "server-a");
}

#[test]
fn router_wallet_session_verifier_accepts_ecdsa_projection() {
    let signing_key = SigningKey::from_bytes(&[0x42; 32]);
    let jwks_json = ed25519_jwks_json(&signing_key, "router-key-1");
    let mut verifier = CloudflareRouterEd25519JwksJwtVerifierV1::from_jwks_json(&jwks_json)
        .expect("Ed25519 JWK verifier");
    let credential =
        CloudflareRouterWalletSessionCredentialV1::gateway_owner(ecdsa_wallet_session(3_000))
            .expect("credential");

    let session = verifier
        .verify_wallet_session(
            &router_admission_bindings().jwt,
            &credential,
            digest(0x90),
            1_000,
        )
        .expect("ECDSA Wallet Session verifies");

    assert_eq!(session.account_id, "wallet-1");
    assert_eq!(session.authorization_id, "authorization-1");
    assert_eq!(session.authorization_level, "evm-family");
}

#[test]
fn router_wallet_session_verifier_rejects_source_mismatch() {
    let signing_key = SigningKey::from_bytes(&[0x42; 32]);
    let jwks_json = ed25519_jwks_json(&signing_key, "router-key-1");
    let mut verifier = CloudflareRouterEd25519JwksJwtVerifierV1::from_jwks_json(&jwks_json)
        .expect("Ed25519 JWK verifier");
    let credential = CloudflareRouterWalletSessionCredentialV1::gateway_owner(
        normal_signing_v2_wallet_session(3_000),
    )
    .expect("credential");

    let err = verifier
        .verify_wallet_session(
            &router_admission_bindings().jwt,
            &credential,
            digest(0x91),
            1_000,
        )
        .expect_err("source mismatch must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidGateDecision);
}

#[test]
fn router_wallet_session_verifier_rejects_expired_projection() {
    let signing_key = SigningKey::from_bytes(&[0x42; 32]);
    let jwks_json = ed25519_jwks_json(&signing_key, "router-key-1");
    let mut verifier = CloudflareRouterEd25519JwksJwtVerifierV1::from_jwks_json(&jwks_json)
        .expect("Ed25519 JWK verifier");
    let credential = CloudflareRouterWalletSessionCredentialV1::gateway_owner(
        normal_signing_v2_wallet_session(1_000),
    )
    .expect("credential");

    let err = verifier
        .verify_wallet_session(
            &router_admission_bindings().jwt,
            &credential,
            digest(0x90),
            1_000,
        )
        .expect_err("expired Wallet Session must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::ExpiredLocalRequest);
}

#[test]
fn router_wallet_session_credential_rejects_duplicate_authorization_ids() {
    let mut session = normal_signing_v2_wallet_session(3_000);
    session.authorization_id = session.wallet_session_id.clone();

    let err = CloudflareRouterWalletSessionCredentialV1::gateway_owner(session)
        .expect_err("duplicate authorization and Wallet Session ids must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidGateDecision);
}

#[test]
fn router_wallet_session_credential_rejects_missing_quota_id() {
    let mut session = normal_signing_v2_wallet_session(3_000);
    session.quota_id.clear();

    let err = CloudflareRouterWalletSessionCredentialV1::gateway_owner(session)
        .expect_err("missing quota id must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::EmptyField);
}

#[test]
fn router_wallet_session_credential_rejects_missing_normal_signing_claims() {
    let mut session = normal_signing_v2_wallet_session(3_000);
    session.authorization_level.clear();

    let err = CloudflareRouterWalletSessionCredentialV1::gateway_owner(session)
        .expect_err("missing authorization level must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::EmptyField);
}

#[test]
fn router_verified_wallet_session_authorizes_normal_signing_v2_prepare_scope() {
    let wallet_session = normal_signing_v2_wallet_session(3_000);
    let request = normal_signing_v2_prepare_request(2_000);

    assert_ne!(
        wallet_session.threshold_session_id,
        request.scope.material_activation.activation_id
    );
    assert_ne!(
        wallet_session.threshold_session_id,
        wallet_session.wallet_session_id
    );
    assert_ne!(
        wallet_session.threshold_session_id,
        request.scope.material_activation.lifecycle_binding
    );
    assert_ne!(
        wallet_session.wallet_session_id,
        request.scope.material_activation.activation_id
    );
    assert_ne!(
        wallet_session.wallet_session_id,
        request.scope.material_activation.lifecycle_binding
    );
    assert_ne!(
        request.scope.material_activation.activation_id,
        request.scope.material_activation.lifecycle_binding
    );

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
fn router_verified_wallet_session_rejects_v2_prepare_account_or_wallet_session_mismatch() {
    let request = normal_signing_v2_prepare_request(2_000);

    let mut wrong_account = normal_signing_v2_wallet_session(3_000);
    wrong_account.account_id = "other.near".to_owned();
    let err = wrong_account
        .validate_for_normal_signing_prepare_request_v2(&request, 1_000)
        .expect_err("prepare account mismatch must fail");
    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidGateDecision);

    let wallet_session = normal_signing_v2_wallet_session(3_000);
    let mut wrong_authorization = request;
    wrong_authorization.scope.authorization =
        NormalSigningAuthorizationV1::reusable_wallet_session("other-wallet-session")
            .expect("substituted Wallet Session authorization");
    let err = wallet_session
        .validate_for_normal_signing_prepare_request_v2(&wrong_authorization, 1_000)
        .expect_err("prepare Wallet Session authorization mismatch must fail");
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
fn router_verified_wallet_session_rejects_v2_finalize_account_or_wallet_session_mismatch() {
    let request = normal_signing_v2_finalize_request(2_000);

    let mut wrong_account = normal_signing_v2_wallet_session(3_000);
    wrong_account.account_id = "other.near".to_owned();
    let err = wrong_account
        .validate_for_normal_signing_finalize_request_v2(&request, 1_000)
        .expect_err("finalize account mismatch must fail");
    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidGateDecision);

    let wallet_session = normal_signing_v2_wallet_session(3_000);
    let mut wrong_authorization = request;
    wrong_authorization.scope.authorization =
        NormalSigningAuthorizationV1::reusable_wallet_session("other-wallet-session")
            .expect("substituted Wallet Session authorization");
    let err = wallet_session
        .validate_for_normal_signing_finalize_request_v2(&wrong_authorization, 1_000)
        .expect_err("finalize Wallet Session authorization mismatch must fail");
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
    wrong_session.authorization =
        CloudflareRouterNormalSigningAuthorizationV2::reusable_wallet_session(
            "other-authorization",
            "other-session",
        )
        .expect("wrong prepare authorization");
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
    wrong_session.authorization =
        CloudflareRouterNormalSigningAuthorizationV2::reusable_wallet_session(
            "other-authorization",
            "other-session",
        )
        .expect("wrong finalize authorization");
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
        CloudflareRouterAuthContextV1::owner_wallet_session("user-1", "wallet-session-1")
            .expect("owner Wallet Session auth context")
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
        CloudflareRouterAuthContextV1::owner_wallet_session("user-1", "wallet-session-1")
            .expect("owner Wallet Session auth context")
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
        request.router_replay_digest(),
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
fn router_runtime_project_policy_rejects_identity_mismatch() {
    let request = ecdsa_threshold_prf_request(2_000);
    let admission = derive_cloudflare_router_trusted_admission_v1(
        &request,
        trusted_metadata(),
        allow_checks("gate-request-1"),
    )
    .expect("trusted admission");
    let policy = configured_project_policy_json("\"registration_prepare\"", true)
        .replace("\"org-1\"", "\"org-2\"");
    let env = router_env().with_overrides(vec![(ROUTER_PROJECT_POLICY_BOOTSTRAP_JSON_ENV, policy)]);
    let runtime = CloudflareRouterWorkerRuntimeV1::new(
        CloudflareRouterBindingsV1::new(
            parse_cloudflare_router_admission_bindings_v1(&env).expect("admission bindings"),
            peer(CloudflareWorkerRoleV1::DeriverA, "DERIVER_A"),
            peer(CloudflareWorkerRoleV1::DeriverB, "DERIVER_B"),
            peer(CloudflareWorkerRoleV1::SigningWorker, "SIGNING_WORKER"),
            issuer_verifying_keys(),
        )
        .expect("router bindings"),
    )
    .expect("router runtime");

    let err = runtime
        .apply_project_policy_to_trusted_admission_v1(&request, admission)
        .expect_err("identity mismatch must fail admission");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidGateDecision);
}

#[test]
fn router_runtime_project_policy_rejects_denied_work_kind() {
    let request = ecdsa_threshold_prf_request(2_000);
    let admission = derive_cloudflare_router_trusted_admission_v1(
        &request,
        trusted_metadata(),
        allow_checks("gate-request-1"),
    )
    .expect("trusted admission");
    let runtime = router_runtime_with_project_policy("\"key_export\"", true);

    let admission = runtime
        .apply_project_policy_to_trusted_admission_v1(&request, admission)
        .expect("policy evaluation");

    assert!(matches!(
        admission.decision,
        ExpensiveWorkGateDecisionV1::Rejected {
            reason: GateRejectReasonV1::AbusePolicy,
            retry_after_ms: 1_000,
        }
    ));
}

#[test]
fn router_runtime_project_policy_allows_yao_work_kind() {
    let runtime = router_runtime_with_project_policy("\"registration_prepare\"", true);

    let policy = runtime
        .evaluate_project_policy_for_yao_work_kind_v1(ExpensiveWorkKindV1::RegistrationPrepare)
        .expect("Yao project policy evaluation");

    assert_eq!(policy, CloudflareRouterProjectPolicyV1::Allowed);
}

#[test]
fn router_runtime_allow_all_project_policy_allows_yao_work_kind() {
    let policy = router_runtime()
        .evaluate_project_policy_for_yao_work_kind_v1(ExpensiveWorkKindV1::KeyExport)
        .expect("Yao project policy evaluation");

    assert_eq!(policy, CloudflareRouterProjectPolicyV1::Allowed);
}

#[test]
fn router_runtime_project_policy_rejects_denied_yao_work_kind() {
    let runtime = router_runtime_with_project_policy("\"key_export\"", true);

    let policy = runtime
        .evaluate_project_policy_for_yao_work_kind_v1(ExpensiveWorkKindV1::RegistrationPrepare)
        .expect("Yao project policy evaluation");

    assert_eq!(
        policy,
        CloudflareRouterProjectPolicyV1::Rejected {
            retry_after_ms: 1_000,
        }
    );
}

#[test]
fn router_runtime_project_policy_rejects_normal_signing_when_disabled() {
    let metadata = CloudflareRouterNormalSigningTrustedMetadataV1::new(
        "org-1",
        "project-1",
        "dev",
        "account.near",
        CloudflareRouterAuthContextV1::router_jwt_session("user-1", "session-1")
            .expect("auth context"),
        digest(0x90),
        digest(0x91),
    )
    .expect("normal-signing metadata");
    let admission = CloudflareRouterNormalSigningTrustedAdmissionV1::new(
        metadata,
        ExpensiveWorkGateDecisionV1::accepted("normal-request-1").expect("accepted decision"),
    )
    .expect("normal-signing admission");
    let runtime = router_runtime_with_project_policy("\"registration_prepare\"", false);

    let admission = runtime
        .apply_project_policy_to_normal_signing_admission_v1("normal-request-1", admission)
        .expect("policy evaluation");

    assert!(matches!(
        admission.decision,
        ExpensiveWorkGateDecisionV1::Rejected {
            reason: GateRejectReasonV1::AbusePolicy,
            retry_after_ms: 1_000,
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
        CloudflareRouterAuthContextV1::router_jwt_session("user-1", "session-1")
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

fn tenant_root_registration_transport_fixture() -> CloudflareTenantRootCustodyBindingWireV1 {
    CloudflareTenantRootCustodyBindingWireV1 {
        activation_receipt_b64u: "AQ".to_owned(),
        operation_id: TenantRootDerivationOperationIdV1::from_bytes([0x31; 16])
            .expect("tenant-root operation id"),
        session_id: TenantRootDerivationSessionIdV1::from_bytes([0x32; 16])
            .expect("tenant-root session id"),
        nonce: TenantRootDerivationNonceV1::from_bytes([0x33; 32]).expect("tenant-root nonce"),
        issued_at_ms: 1,
        expires_at_ms: 2_000,
    }
}

#[test]
fn router_ab_ecdsa_derivation_deriver_registration_private_request_accepts_matching_payload() {
    let registration_request =
        router_ab_ecdsa_derivation_registration_request_with_aad_bound_envelopes_for(
            RouterAbEcdsaDerivationRegistrationPurposeV1::WalletAddSigner,
        );
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
            tenant_root_registration_transport_fixture(),
        )
        .expect("Router A/B ECDSA derivation registration private request");

    private_request
        .validate_for_worker_role(CloudflareWorkerRoleV1::DeriverA)
        .expect("Router A/B ECDSA derivation registration private request validates");
}

#[test]
fn router_ab_ecdsa_derivation_deriver_registration_private_request_rejects_payload_drift() {
    let mut registration_request =
        router_ab_ecdsa_derivation_registration_request_with_aad_bound_envelopes_for(
            RouterAbEcdsaDerivationRegistrationPurposeV1::WalletAddSigner,
        );
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
        tenant_root_registration_transport_fixture(),
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
        tenant_root_registration_transport_fixture(),
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
        tenant_root_registration_transport_fixture(),
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
            tenant_root_registration_transport_fixture(),
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
        tenant_root_registration_transport_fixture(),
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
    let refresh = router_ab_ecdsa_derivation_activation_refresh_request_with_aad_bound_envelopes()
        .to_threshold_prf_request()
        .expect("refresh threshold-PRF request");
    let cases = [
        ("registration", first_router_payload(&registration), true),
        ("export", first_router_payload(&export), false),
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
        deriver_b_strict.client_bundle.clone(),
        deriver_a_strict.client_bundle.clone(),
    )
    .expect_err("swapped strict client bundles must fail");
    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidSignerIdentity);
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
        MpcMaterialActivationRefV1::new(
            validated_a.router_payload().lifecycle().session_id.clone(),
            "ed25519-yao-signing-capability",
            validated_a.router_payload().lifecycle().account_id.clone(),
            "ed25519-key-binding",
            validated_a
                .router_payload()
                .lifecycle()
                .lifecycle_id
                .clone(),
            validated_a
                .router_payload()
                .signer_set()
                .selected_server
                .server_id
                .clone(),
        )
        .expect("Ed25519 material activation"),
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
            &activation.pending.registration,
            &activation.client_activation,
            &material,
        )
        .expect("Router A/B ECDSA derivation public identity");

    identity
        .validate_for_context(&activation.pending.registration.context)
        .expect("identity must validate against core Router A/B ECDSA derivation context");
    assert_eq!(
        identity.context_binding_b64u,
        b64u(
            activation
                .pending
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
            .client_activation
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
        activation
            .pending
            .activation_context
            .signer_set()
            .selected_server
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
            ROUTER_AB_ECDSA_DERIVATION_WALLET_ID,
            ROUTER_AB_ECDSA_DERIVATION_THRESHOLD_KEY_ID,
            ROUTER_AB_ECDSA_DERIVATION_SIGNING_ROOT_ID,
            ROUTER_AB_ECDSA_DERIVATION_SIGNING_ROOT_VERSION,
            router_ab_ecdsa_derivation_material_activation_for_epoch(&receipt.activation_epoch),
        )
        .expect("refreshed Router A/B ECDSA derivation normal-signing scope");
    let active_state = cloudflare_active_signing_worker_state_from_activation_request_v1(
        &refresh
            .to_recipient_proof_bundle_activation_request()
            .expect("generic refresh activation request"),
        refresh.material_activation.clone(),
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
            refresh.material_activation.clone(),
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
            ROUTER_AB_ECDSA_DERIVATION_WALLET_ID,
            ROUTER_AB_ECDSA_DERIVATION_THRESHOLD_KEY_ID,
            ROUTER_AB_ECDSA_DERIVATION_SIGNING_ROOT_ID,
            ROUTER_AB_ECDSA_DERIVATION_SIGNING_ROOT_VERSION,
            router_ab_ecdsa_derivation_material_activation_for_epoch(&receipt.activation_epoch),
        )
        .expect("Router A/B ECDSA derivation normal-signing scope");
    let active_state = cloudflare_active_signing_worker_state_from_activation_request_v1(
        &activation
            .to_recipient_proof_bundle_activation_request()
            .expect("generic activation request"),
        activation.material_activation.clone(),
        "router-ab-ecdsa-derivation-material",
        TEST_ACTIVATED_AT_MS,
    )
    .expect("Router A/B ECDSA derivation active state");
    let lookup =
        CloudflareActiveSigningWorkerStateLookupV1::from_router_ab_ecdsa_derivation_normal_signing_scope(&scope)
            .expect("Router A/B ECDSA derivation active-state lookup");

    assert_eq!(
        active_state.material_activation.activation_id,
        format!("ecdsa-activation-{}", root_epoch().as_str())
    );
    assert_eq!(
        lookup.material_activation_id,
        active_state.material_activation.activation_id
    );
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

#[test]
fn signing_worker_output_activate_and_active_state_get_share_opaque_material_activation_key() {
    let mut activation = router_ab_ecdsa_derivation_activation_request();
    activation.material_activation.activation_id = "opaque-ecdsa-activation-id".to_owned();
    activation
        .validate()
        .expect("opaque material activation remains context-valid");
    let generic_activation = activation
        .to_recipient_proof_bundle_activation_request()
        .expect("generic SigningWorker activation request");
    let material = router_ab_ecdsa_derivation_server_material_record(&activation);
    let output_activate = CloudflareSigningWorkerPrivateD1RequestV1::OutputActivate {
        activation: generic_activation.clone(),
        material,
        activated_at_ms: TEST_ACTIVATED_AT_MS,
    };
    output_activate
        .validate()
        .expect("OutputActivate request validates");
    let active_state = active_signing_worker_state_for_activation(
        &generic_activation,
        "opaque-ecdsa-activation-material",
    );
    let active_state_get = CloudflareSigningWorkerPrivateD1RequestV1::ActiveStateGet {
        lookup: CloudflareActiveSigningWorkerStateLookupV1::new(
            active_state.account_id.clone(),
            active_state.material_activation.activation_id.clone(),
            active_state.signing_worker.server_id.clone(),
        )
        .expect("active SigningWorker lookup"),
    };

    assert_eq!(
        output_activate
            .active_state_index_key()
            .expect("OutputActivate active-state key"),
        active_state_get
            .active_state_index_key()
            .expect("ActiveStateGet active-state key")
    );
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
            &request.request.request,
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
    assert_eq!(admission.account_id, request.scope.wallet_id);
    assert_eq!(
        admission.authorization,
        CloudflareRouterNormalSigningAuthorizationV2::ReusableWalletSession {
            authorization_id: "authorization-ecdsa-1".to_owned(),
            wallet_session_id: "ecdsa-wallet-session-1".to_owned(),
        }
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
    assert_eq!(admission.account_id, request.scope.wallet_id);
    assert_eq!(
        admission.authorization,
        CloudflareRouterNormalSigningAuthorizationV2::ReusableWalletSession {
            authorization_id: "authorization-ecdsa-1".to_owned(),
            wallet_session_id: "ecdsa-wallet-session-1".to_owned(),
        }
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
fn router_ab_ecdsa_derivation_wallet_session_rejects_wallet_session_substitution() {
    let mut request = router_ab_ecdsa_derivation_digest_signing_request();
    request.authorization =
        NormalSigningAuthorizationV1::reusable_wallet_session("wallet-session-substituted")
            .expect("substituted Wallet Session authorization");
    let wallet_session = router_ab_ecdsa_derivation_wallet_session(&request);

    let err = wallet_session
        .validate_for_router_ab_ecdsa_derivation_evm_digest_signing_request_v1(
            &request,
            TEST_ACTIVATED_AT_MS + 1,
        )
        .expect_err("substituted Wallet Session id rejects");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidGateDecision);
}

#[test]
fn router_ab_ecdsa_derivation_operation_step_up_admission_retains_authorization_session_id() {
    let mut request = router_ab_ecdsa_derivation_digest_signing_request();
    request.authorization = NormalSigningAuthorizationV1::OperationStepUp;
    let authorization = CloudflareRouterNormalSigningAuthorizationV2::operation_step_up(
        "authorization-session-step-up",
        b64u(&[0x44; 32]),
    )
    .expect("operation step-up authorization");
    let admission = CloudflareRouterAbEcdsaDerivationEvmDigestPrepareAdmissionCandidateV1::new(
        "org-1",
        "project-1",
        "dev",
        request.scope.wallet_id.clone(),
        "subject-1",
        authorization,
        request.scope.signing_worker.server_id.clone(),
        request.request_id.clone(),
        request.client_presignature_id.clone(),
        request.scope.scope_digest().expect("scope digest"),
        request.request_digest().expect("request digest"),
        request.signing_digest().expect("signing digest"),
        digest(0x42),
        request.expires_at_ms,
    )
    .expect("operation step-up admission");

    admission
        .validate_for_prepare_request(&request)
        .expect("operation step-up authorization matches request");
    assert!(matches!(
        admission.authorization,
        CloudflareRouterNormalSigningAuthorizationV2::OperationStepUp {
            authorization_session_id,
            ..
        } if authorization_session_id == "authorization-session-step-up"
    ));
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
fn router_ab_ecdsa_derivation_admitted_request_accepts_reusable_wallet_session_distinct_from_material_activation(
) {
    let request = router_ab_ecdsa_derivation_digest_signing_request();
    let material_activation_id = request
        .scope
        .material_activation_id()
        .expect("material activation id");
    let wallet_session_id = request
        .authorization
        .reusable_wallet_session_id()
        .expect("reusable Wallet Session id");
    assert_ne!(wallet_session_id, material_activation_id);

    let admitted =
        CloudflareSigningWorkerAdmittedRouterAbEcdsaDerivationEvmDigestSigningRequestV1::new(
            request,
            router_ab_ecdsa_derivation_trusted_admission(
                &router_ab_ecdsa_derivation_digest_signing_request(),
            ),
        )
        .expect("reusable Wallet Session authorization is independent of material activation");
    assert!(matches!(
        admitted.trusted_admission.metadata.auth,
        CloudflareRouterAuthContextV1::OwnerWalletSession { .. }
    ));
}

#[test]
fn router_ab_ecdsa_derivation_admitted_request_rejects_wrong_reusable_wallet_session() {
    let request = router_ab_ecdsa_derivation_digest_signing_request();
    let mut trusted_admission = router_ab_ecdsa_derivation_trusted_admission(&request);
    trusted_admission.metadata.auth =
        CloudflareRouterAuthContextV1::owner_wallet_session("subject-1", "wrong-wallet-session")
            .expect("wrong Wallet Session auth context");

    let err = CloudflareSigningWorkerAdmittedRouterAbEcdsaDerivationEvmDigestSigningRequestV1::new(
        request,
        trusted_admission,
    )
    .expect_err("wrong reusable Wallet Session authorization rejects");
    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidGateDecision);
}

#[test]
fn router_ab_ecdsa_derivation_admitted_request_accepts_operation_step_up_only_with_step_up_auth() {
    let mut request = router_ab_ecdsa_derivation_digest_signing_request();
    request.authorization =
        NormalSigningAuthorizationV1::operation_step_up().expect("operation step-up authorization");
    let trusted_admission = router_ab_ecdsa_derivation_trusted_admission(&request);

    let admitted =
        CloudflareSigningWorkerAdmittedRouterAbEcdsaDerivationEvmDigestSigningRequestV1::new(
            request,
            trusted_admission,
        )
        .expect("operation step-up authorization is accepted with step-up auth context");
    assert!(matches!(
        admitted.trusted_admission.metadata.auth,
        CloudflareRouterAuthContextV1::OwnerOperationStepUp { .. }
    ));
}

#[test]
fn router_ab_ecdsa_derivation_admitted_finalize_request_rejects_trusted_admission_drift() {
    let request = router_ab_ecdsa_derivation_digest_signing_finalize_request();
    let mut trusted_admission = router_ab_ecdsa_derivation_finalize_trusted_admission(&request);
    trusted_admission.metadata.intent_digest = request
        .prepare_request_digest()
        .expect("prepare request digest");
    let effect_claim = ecdsa_effect_claim(&request);
    let effect_identity = ecdsa_effect_identity(&request);

    let err =
        CloudflareSigningWorkerAdmittedRouterAbEcdsaDerivationEvmDigestFinalizeRequestV1::new(
            request,
            trusted_admission,
            effect_identity,
            effect_claim,
        )
        .expect_err("finalize trusted admission drift rejects");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidGateDecision);
}

#[test]
fn router_ab_ecdsa_derivation_admitted_finalize_accepts_reusable_wallet_session_distinct_from_material_activation(
) {
    let request = router_ab_ecdsa_derivation_digest_signing_finalize_request();
    let effect_claim = ecdsa_effect_claim(&request);
    let effect_identity = ecdsa_effect_identity(&request);

    let admitted =
        CloudflareSigningWorkerAdmittedRouterAbEcdsaDerivationEvmDigestFinalizeRequestV1::new(
            request.clone(),
            router_ab_ecdsa_derivation_finalize_trusted_admission(&request),
            effect_identity,
            effect_claim,
        )
        .expect("reusable Wallet Session authorization is independent of material activation");
    assert!(matches!(
        admitted.trusted_admission.metadata.auth,
        CloudflareRouterAuthContextV1::OwnerWalletSession { .. }
    ));
    let admitted_session_id = match &admitted.trusted_admission.metadata.auth {
        CloudflareRouterAuthContextV1::OwnerWalletSession {
            wallet_session_id, ..
        } => wallet_session_id,
        _ => unreachable!("reusable authorization must use owner Wallet Session auth"),
    };
    assert_ne!(
        admitted_session_id,
        &request
            .scope
            .material_activation_id()
            .expect("material activation id")
    );
}

#[test]
fn router_ab_ecdsa_derivation_admitted_finalize_rejects_owner_wallet_session_auth_for_operation_step_up(
) {
    let mut request = router_ab_ecdsa_derivation_digest_signing_finalize_request();
    request.authorization =
        NormalSigningAuthorizationV1::operation_step_up().expect("operation step-up authorization");
    let mut trusted_admission = router_ab_ecdsa_derivation_finalize_trusted_admission(&request);
    trusted_admission.metadata.auth =
        CloudflareRouterAuthContextV1::owner_wallet_session("subject-1", "wallet-session-ecdsa-1")
            .expect("owner Wallet Session auth context");
    let effect_claim = ecdsa_effect_claim(&request);
    let effect_identity = ecdsa_effect_identity(&request);

    let err =
        CloudflareSigningWorkerAdmittedRouterAbEcdsaDerivationEvmDigestFinalizeRequestV1::new(
            request,
            trusted_admission,
            effect_identity,
            effect_claim,
        )
        .expect_err("operation step-up request cannot use reusable Wallet Session auth");
    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidGateDecision);
}

#[test]
fn router_ab_ecdsa_reusable_authorized_operation_rejects_substitution() {
    let request = router_ab_ecdsa_derivation_digest_signing_finalize_request();
    let authorized_operation =
        CloudflareRouterEcdsaAuthorizedOperationV1::ReusableWalletSessionAuthorizedOperationV1 {
            authorized_operation_id: "authorized-operation-ecdsa-1".to_owned(),
            operation_id: request.operation_id.clone(),
            capability_kind: CloudflareRouterEcdsaCapabilityKindV1::EvmEcdsaMpcSigning,
            operation_kind: CloudflareRouterEcdsaOperationKindV1::SignTransaction,
            lane_digest_b64u: request.operation_digests.lane_digest_b64u.clone(),
            intent_digest_b64u: request.operation_digests.intent_digest_b64u.clone(),
            display_digest_b64u: request.operation_digests.display_digest_b64u.clone(),
            operation_fingerprint_digest: request.operation_digests.intent_digest_b64u.clone(),
        };
    authorized_operation
        .validate_for_finalize_request_with_session(&request, None)
        .expect("matching reusable authorized operation");

    let substituted = match authorized_operation {
        CloudflareRouterEcdsaAuthorizedOperationV1::ReusableWalletSessionAuthorizedOperationV1 {
            authorized_operation_id: _,
            operation_id: _,
            capability_kind,
            operation_kind,
            lane_digest_b64u,
            intent_digest_b64u,
            display_digest_b64u,
            operation_fingerprint_digest,
        } => CloudflareRouterEcdsaAuthorizedOperationV1::ReusableWalletSessionAuthorizedOperationV1 {
            authorized_operation_id: "authorized-operation-substituted".to_owned(),
            operation_id: "substituted-operation".to_owned(),
            capability_kind,
            operation_kind,
            lane_digest_b64u,
            intent_digest_b64u,
            display_digest_b64u,
            operation_fingerprint_digest,
        },
        CloudflareRouterEcdsaAuthorizedOperationV1::VerifiedStepUpAuthorizedOperationV1 { .. } => {
            unreachable!("fixture uses reusable authorization")
        }
    };
    let error = substituted
        .validate_for_finalize_request_with_session(&request, None)
        .expect_err("substituted reusable operation must fail before signing");
    assert_eq!(error.code(), RouterAbProtocolErrorCode::InvalidGateDecision);
}

#[test]
fn router_ab_ecdsa_authorized_finalize_parser_requires_authorized_operation_and_rejects_legacy_fields(
) {
    let request = router_ab_ecdsa_derivation_digest_signing_finalize_request();
    let mut body = serde_json::to_value(&request)
        .expect("ECDSA finalize request JSON")
        .as_object()
        .expect("ECDSA finalize request object")
        .clone();

    let missing_authorized_operation =
        serde_json::to_vec(&body).expect("ECDSA finalize request without authorized operation");
    let error =
        parse_cloudflare_router_authorized_router_ab_ecdsa_derivation_finalize_request_v1_json(
            &missing_authorized_operation,
        )
        .expect_err("ECDSA finalize must require authorized operation");
    assert_eq!(
        error.code(),
        RouterAbProtocolErrorCode::MalformedWirePayload
    );

    let authorized_operation =
        CloudflareRouterEcdsaAuthorizedOperationV1::ReusableWalletSessionAuthorizedOperationV1 {
            authorized_operation_id: "authorized-operation-ecdsa-parser-1".to_owned(),
            operation_id: request.operation_id.clone(),
            capability_kind: CloudflareRouterEcdsaCapabilityKindV1::EvmEcdsaMpcSigning,
            operation_kind: CloudflareRouterEcdsaOperationKindV1::SignTransaction,
            lane_digest_b64u: request.operation_digests.lane_digest_b64u.clone(),
            intent_digest_b64u: request.operation_digests.intent_digest_b64u.clone(),
            display_digest_b64u: request.operation_digests.display_digest_b64u.clone(),
            operation_fingerprint_digest: request.operation_digests.intent_digest_b64u.clone(),
        };
    let accepted_authorized_operation = CloudflareRouterEcdsaAcceptedAuthorizedOperationV1 {
        binding: CloudflareRouterEcdsaAcceptedCapabilityBindingV1::ReusableWalletSession {
            authorization_id: "authorization-ecdsa-parser-1".to_owned(),
            wallet_session_id: "wallet-ecdsa-parser-1".to_owned(),
            quota_id: "quota-ecdsa-parser-1".to_owned(),
        },
        authorized_operation,
    };
    body.insert(
        "authorized_operation".to_owned(),
        serde_json::to_value(&accepted_authorized_operation)
            .expect("ECDSA accepted authorized operation JSON"),
    );
    let parsed =
        parse_cloudflare_router_authorized_router_ab_ecdsa_derivation_finalize_request_v1_json(
            &serde_json::to_vec(&body).expect("ECDSA accepted finalize request JSON"),
        )
        .expect("ECDSA finalize parser accepts a bound authorized operation");
    assert_eq!(parsed.0.operation_id, request.operation_id);

    let mut aliased_body = body.clone();
    aliased_body["authorized_operation"]["binding"]["quota_id"] =
        serde_json::json!("wallet-ecdsa-parser-1");
    let error =
        parse_cloudflare_router_authorized_router_ab_ecdsa_derivation_finalize_request_v1_json(
            &serde_json::to_vec(&aliased_body).expect("aliased ECDSA finalize request JSON"),
        )
        .expect_err("Wallet Session and quota ids must remain distinct");
    assert_eq!(error.code(), RouterAbProtocolErrorCode::InvalidGateDecision);

    let mut legacy_accepted = serde_json::to_value(&accepted_authorized_operation)
        .expect("ECDSA accepted authorized operation JSON");
    let legacy_operation = legacy_accepted
        .as_object_mut()
        .expect("ECDSA accepted authorization object")
        .remove("authorized_operation")
        .expect("authorized_operation field");
    legacy_accepted
        .as_object_mut()
        .expect("ECDSA accepted authorization object")
        .insert("claim".to_owned(), legacy_operation);
    let mut legacy_nested_body = body.clone();
    legacy_nested_body.insert("authorized_operation".to_owned(), legacy_accepted);
    let error =
        parse_cloudflare_router_authorized_router_ab_ecdsa_derivation_finalize_request_v1_json(
            &serde_json::to_vec(&legacy_nested_body)
                .expect("ECDSA legacy nested operation request JSON"),
        )
        .expect_err("legacy nested operation field must be rejected");
    assert_eq!(
        error.code(),
        RouterAbProtocolErrorCode::MalformedWirePayload
    );

    body.insert("sessionId".to_owned(), serde_json::json!("legacy-session"));
    let legacy_alias = serde_json::to_vec(&body).expect("ECDSA legacy alias request JSON");
    let error =
        parse_cloudflare_router_authorized_router_ab_ecdsa_derivation_finalize_request_v1_json(
            &legacy_alias,
        )
        .expect_err("legacy session aliases must be rejected");
    assert_eq!(
        error.code(),
        RouterAbProtocolErrorCode::MalformedWirePayload
    );
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
            ROUTER_AB_ECDSA_DERIVATION_WALLET_ID,
            ROUTER_AB_ECDSA_DERIVATION_THRESHOLD_KEY_ID,
            ROUTER_AB_ECDSA_DERIVATION_SIGNING_ROOT_ID,
            ROUTER_AB_ECDSA_DERIVATION_SIGNING_ROOT_VERSION,
            router_ab_ecdsa_derivation_material_activation_for_epoch(&receipt.activation_epoch),
        )
        .expect("Router A/B ECDSA derivation normal-signing scope");
    let active_state = cloudflare_active_signing_worker_state_from_activation_request_v1(
        &activation
            .to_recipient_proof_bundle_activation_request()
            .expect("generic activation request"),
        activation.material_activation.clone(),
        "router-ab-ecdsa-derivation-material",
        TEST_ACTIVATED_AT_MS,
    )
    .expect("Router A/B ECDSA derivation active state");
    let material_activation = router_ab_ecdsa_derivation_material_activation(&scope);
    let request = RouterAbEcdsaDerivationEvmDigestSigningRequestV1::new(
        scope,
        "router-ab-ecdsa-derivation-sign-request-1",
        "router-ab-ecdsa-operation-1",
        router_ab_ecdsa_derivation_operation_digests(),
        NormalSigningAuthorizationV1::reusable_wallet_session("ecdsa-wallet-session-1")
            .expect("ECDSA authorization"),
        material_activation,
        "server-presignature-1",
        2_000,
        b64u(&[0x77; 32]),
        b64u(&router_ab_ecdsa_rerandomization_client_commitment_v1(
            [0x66; 32],
        )),
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
fn signing_worker_ecdsa_pool_lifecycle_atomically_consumes_and_destroys_material() {
    let request = router_ab_ecdsa_derivation_digest_signing_request();
    let available = CloudflareSigningWorkerEcdsaPoolLifecycleRecordV1::new_available(
        router_ab_ecdsa_derivation_presignature_pool_record(),
    )
    .expect("available SigningWorker pool lifecycle");
    assert!(matches!(available.lifecycle, PoolRecord::Available(_)));
    let persisted_available = serde_json::to_string(&available).expect("serialize available pool");
    let available: CloudflareSigningWorkerEcdsaPoolLifecycleRecordV1 =
        serde_json::from_str(&persisted_available).expect("restore available pool");
    let reserved = available
        .reserve(
            request.request_digest().expect("prepare request digest"),
            request.signing_digest().expect("signing digest"),
            b64u(&[0x55; 32]),
            1_100,
            1_900,
        )
        .expect("reserve exact SigningWorker pool material");
    assert_eq!(reserved.lifecycle.revision().value(), 1);

    let (consumed, consumed_material) = match reserved
        .consume(
            request.request_digest().expect("prepare request digest"),
            1_200,
        )
        .expect("consume exact SigningWorker reservation")
    {
        CloudflareSigningWorkerEcdsaPoolConsumeDecisionV1::Consumed { record, material } => {
            (record, material)
        }
        CloudflareSigningWorkerEcdsaPoolConsumeDecisionV1::Burned(_) => {
            panic!("exact live reservation must consume")
        }
    };
    assert_eq!(consumed.lifecycle.revision().value(), 2);
    assert!(matches!(consumed.lifecycle, PoolRecord::Consumed(_)));
    assert_eq!(consumed_material.server_k_share32_b64u, b64u(&[0x11; 32]));
    let persisted_consumed =
        serde_json::to_string(&consumed).expect("serialize consumed SigningWorker record");
    assert!(!persisted_consumed.contains("server_k_share32_b64u"));
    assert!(!persisted_consumed.contains("server_sigma_share32_b64u"));
    serde_json::from_str::<CloudflareSigningWorkerEcdsaPoolLifecycleRecordV1>(&persisted_consumed)
        .expect("restore consumed SigningWorker pool lifecycle");
}

#[test]
fn signing_worker_ecdsa_pool_lifecycle_burns_substituted_consume() {
    let request = router_ab_ecdsa_derivation_digest_signing_request();
    let reserved = CloudflareSigningWorkerEcdsaPoolLifecycleRecordV1::new_available(
        router_ab_ecdsa_derivation_presignature_pool_record(),
    )
    .expect("available SigningWorker pool lifecycle")
    .reserve(
        request.request_digest().expect("prepare request digest"),
        request.signing_digest().expect("signing digest"),
        b64u(&[0x55; 32]),
        1_100,
        1_900,
    )
    .expect("reserve exact SigningWorker pool material");

    let burned = match reserved
        .consume(digest(0xA7), 1_200)
        .expect("substituted consume produces a persistent burn")
    {
        CloudflareSigningWorkerEcdsaPoolConsumeDecisionV1::Burned(record) => record,
        CloudflareSigningWorkerEcdsaPoolConsumeDecisionV1::Consumed { .. } => {
            panic!("substituted request must not consume")
        }
    };
    let PoolRecord::Tombstone(terminal) = &burned.lifecycle else {
        panic!("substituted consume must be terminal");
    };
    assert_eq!(terminal.reason(), TombstoneReason::BindingRejected);
}

#[test]
fn signing_worker_ecdsa_pool_reservation_lease_is_capped_at_sixty_seconds() {
    let request = router_ab_ecdsa_derivation_digest_signing_request();
    let capped = CloudflareSigningWorkerEcdsaPoolLifecycleRecordV1::new_available(
        router_ab_ecdsa_derivation_presignature_pool_record_with_expiry(100_000),
    )
    .expect("long-lived available material")
    .reserve(
        request.request_digest().expect("request digest"),
        request.signing_digest().expect("signing digest"),
        b64u(&[0x55; 32]),
        1_100,
        100_000,
    )
    .expect("reserve with capped lease");
    let PoolRecord::Reserved(capped) = &capped.lifecycle else {
        panic!("reservation must persist");
    };
    assert_eq!(capped.lease_expires_at_ms(), 61_100);
    assert_eq!(capped.cleanup_deadline_ms(), 61_100);

    let request_limited = CloudflareSigningWorkerEcdsaPoolLifecycleRecordV1::new_available(
        router_ab_ecdsa_derivation_presignature_pool_record_with_expiry(100_000),
    )
    .expect("long-lived available material")
    .reserve(
        request.request_digest().expect("request digest"),
        request.signing_digest().expect("signing digest"),
        b64u(&[0x55; 32]),
        1_100,
        50_000,
    )
    .expect("reserve with request-limited lease");
    let PoolRecord::Reserved(request_limited) = &request_limited.lifecycle else {
        panic!("reservation must persist");
    };
    assert_eq!(request_limited.lease_expires_at_ms(), 50_000);

    let overflow = CloudflareSigningWorkerEcdsaPoolLifecycleRecordV1::new_available(
        router_ab_ecdsa_derivation_presignature_pool_record_with_expiry(u64::MAX),
    )
    .expect("maximum-lifetime available material")
    .reserve(
        request.request_digest().expect("request digest"),
        request.signing_digest().expect("signing digest"),
        b64u(&[0x55; 32]),
        u64::MAX - 1,
        u64::MAX,
    )
    .expect_err("reservation lease arithmetic must be checked");
    assert_eq!(overflow.code(), RouterAbProtocolErrorCode::InvalidTimeRange);
}

#[test]
fn signing_worker_ecdsa_pool_expiry_and_retirement_destroy_material() {
    let available = CloudflareSigningWorkerEcdsaPoolLifecycleRecordV1::new_available(
        router_ab_ecdsa_derivation_presignature_pool_record(),
    )
    .expect("available material");
    assert!(available.clone().expire(1_999).is_err());
    let expired = available.expire(2_000).expect("expire available material");
    let PoolRecord::Tombstone(expired_tombstone) = &expired.lifecycle else {
        panic!("expired material must become terminal");
    };
    assert_eq!(expired_tombstone.reason(), TombstoneReason::MaterialExpired);
    let persisted = serde_json::to_string(&expired).expect("serialize expired record");
    assert!(!persisted.contains("server_k_share32_b64u"));
    assert!(!persisted.contains("server_sigma_share32_b64u"));

    let retired = CloudflareSigningWorkerEcdsaPoolLifecycleRecordV1::new_available(
        router_ab_ecdsa_derivation_presignature_pool_record(),
    )
    .expect("available material")
    .retire(TombstoneReason::ActivationEpochRetired, 1_500)
    .expect("retire available material");
    let PoolRecord::Tombstone(retired_tombstone) = &retired.lifecycle else {
        panic!("retired material must become terminal");
    };
    assert_eq!(
        retired_tombstone.reason(),
        TombstoneReason::ActivationEpochRetired
    );
}

#[test]
fn signing_worker_ecdsa_pool_atomic_reducer_rejects_stale_reservation() {
    let request = router_ab_ecdsa_derivation_digest_signing_request();
    let available = match apply_cloudflare_signing_worker_ecdsa_pool_command_v1(
        None,
        CloudflareSigningWorkerEcdsaPoolCommandV1::PutAvailable {
            material: router_ab_ecdsa_derivation_presignature_pool_record(),
        },
    )
    .expect("admit available SigningWorker material")
    {
        CloudflareSigningWorkerEcdsaPoolMutationOutcomeV1::Available { record, stored } => {
            assert!(stored);
            record
        }
        _ => panic!("pool admission must return available material"),
    };
    let reserve = CloudflareSigningWorkerEcdsaPoolCommandV1::Reserve {
        scope: request.scope.clone(),
        server_presignature_id: "server-presignature-1".to_owned(),
        expected_revision: 0,
        request_digest: request.request_digest().expect("prepare request digest"),
        admitted_signing_digest: request.signing_digest().expect("signing digest"),
        signing_worker_rerandomization_contribution32_b64u: b64u(&[0x55; 32]),
        reserved_at_ms: 1_100,
        request_expires_at_ms: 1_900,
    };
    let reserved = match apply_cloudflare_signing_worker_ecdsa_pool_command_v1(
        Some(available.clone()),
        reserve.clone(),
    )
    .expect("first reservation wins")
    {
        CloudflareSigningWorkerEcdsaPoolMutationOutcomeV1::Reserved { record } => record,
        _ => panic!("reserve command must return reserved material"),
    };
    let stale = apply_cloudflare_signing_worker_ecdsa_pool_command_v1(Some(reserved), reserve)
        .expect_err("stale revision cannot reserve twice");
    assert_eq!(
        stale.code(),
        RouterAbProtocolErrorCode::ReplayedLocalRequest
    );
}

#[test]
fn router_ab_ecdsa_derivation_presignature_pool_put_request_materializes_active_pool_record() {
    let request = router_ab_ecdsa_derivation_presignature_pool_put_request(2_000);
    let activation = router_ab_ecdsa_derivation_activation_request();
    let active_material = router_ab_ecdsa_derivation_server_material_record(&activation);

    let record = request
        .to_pool_record(
            active_signing_worker_state_for_router_ab_ecdsa_derivation(),
            &active_material,
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
    let activation = router_ab_ecdsa_derivation_activation_request();
    let active_material = router_ab_ecdsa_derivation_server_material_record(&activation);
    let expired = request
        .to_pool_record(
            active_signing_worker_state_for_router_ab_ecdsa_derivation(),
            &active_material,
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
        .to_pool_record(mismatched_state, &active_material, 1_500)
        .expect_err("scope and active state mismatch must fail");
    assert_eq!(
        mismatched.code(),
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig
    );

    let mut mismatched_public_key = router_ab_ecdsa_derivation_presignature_pool_put_request(2_000);
    mismatched_public_key
        .scope
        .public_identity
        .threshold_public_key33_b64u = b64u(&ecdsa_derivation_client_share_public_key33());
    let mismatched = mismatched_public_key
        .to_pool_record(
            active_signing_worker_state_for_router_ab_ecdsa_derivation(),
            &active_material,
            1_500,
        )
        .expect_err("scope public key must match active SigningWorker material");
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
        .validate_for_request(&finalize_request)
        .expect("response validates against finalize request");
    assert_eq!(response.signature65_b64u, b64u(&[0x99; 65]));
}

#[test]
fn router_ab_ecdsa_derivation_production_finalize_handler_returns_real_recoverable_signature() {
    let activation = router_ab_ecdsa_derivation_activation_request();
    let material = router_ab_ecdsa_derivation_server_material_record(&activation);
    let ecdsa_context = cloudflare_router_ab_ecdsa_derivation_stable_key_context_v1(
        &activation.pending.registration.context,
    )
    .expect("Router A/B ECDSA derivation context");
    let (_relayer_role_share, identity) = derive_relayer_share_for_client_public(
        &ecdsa_context,
        *material.output_material.as_bytes(),
        &ecdsa_derivation_client_share_public_key33(),
        activation.client_activation.client_share_retry_counter,
    )
    .expect("relayer role share");
    let client_additive_share32 = ecdsa_scalar_one_be32();
    let (
        server_big_r33,
        server_k_share32,
        server_sigma_share32,
        client_k_share32,
        client_sigma_share32,
    ) = drive_ecdsa_presignature_pair(
        &client_additive_share32,
        &_relayer_role_share.x_relayer32,
        &identity.threshold_public_key33,
    );
    let client_rerandomization_contribution32 = [0x60; 32];
    let signing_worker_rerandomization_contribution32 = [0x01; 32];
    let entropy32 = [0x61; 32];
    let base_prepare_request = router_ab_ecdsa_derivation_digest_signing_request();
    let prepare_request = RouterAbEcdsaDerivationEvmDigestSigningRequestV1::new(
        base_prepare_request.scope.clone(),
        base_prepare_request.request_id.clone(),
        base_prepare_request.operation_id.clone(),
        base_prepare_request.operation_digests.clone(),
        base_prepare_request.authorization.clone(),
        base_prepare_request.material_activation.clone(),
        "server-presignature-real-1",
        base_prepare_request.expires_at_ms,
        base_prepare_request.signing_digest_b64u.clone(),
        b64u(&router_ab_ecdsa_rerandomization_client_commitment_v1(
            client_rerandomization_contribution32,
        )),
    )
    .expect("real Router A/B ECDSA derivation prepare request");
    assert_eq!(
        prepare_request
            .scope
            .public_identity
            .threshold_public_key33_b64u,
        b64u(&identity.threshold_public_key33)
    );
    let client_material =
        ClientPresignMaterial::from_bytes(server_big_r33, client_k_share32, client_sigma_share32)
            .expect("client presign material");
    let client_online_input = OnlineClientInput::new(
        identity.threshold_public_key33,
        server_big_r33,
        *prepare_request
            .signing_digest()
            .expect("signing digest")
            .as_bytes(),
        entropy32,
    )
    .expect("client online input");
    let client_signature_share32 = compute_client_signature_share(
        client_material
            .reserve()
            .commit(client_online_input)
            .expect("committed client presign material"),
    )
    .expect("client ECDSA signature share");
    let finalize_request = RouterAbEcdsaDerivationEvmDigestSigningFinalizeRequestV1::new(
        prepare_request.scope.clone(),
        prepare_request.request_id.clone(),
        prepare_request.operation_id.clone(),
        prepare_request.operation_digests.clone(),
        prepare_request.authorization.clone(),
        prepare_request.material_activation.clone(),
        prepare_request.expires_at_ms,
        prepare_request.signing_digest_b64u.clone(),
        "server-presignature-real-1",
        b64u(&client_signature_share32),
        b64u(&client_rerandomization_contribution32),
    )
    .expect("Router A/B ECDSA derivation finalize request");
    let presignature_record = CloudflareSigningWorkerEcdsaPresignatureRecordV1::new(
        active_signing_worker_state_for_router_ab_ecdsa_derivation(),
        "server-presignature-real-1",
        prepare_request.request_digest().expect("request digest"),
        prepare_request.signing_digest().expect("signing digest"),
        b64u(&server_big_r33),
        b64u(&signing_worker_rerandomization_contribution32),
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
            admitted_router_ab_ecdsa_derivation_digest_finalize_request(finalize_request.clone()),
            active_signing_worker_state_for_router_ab_ecdsa_derivation(),
            material,
            presignature_record,
        )
        .expect("production Router A/B ECDSA derivation finalize response");

    response
        .validate_for_request(&finalize_request)
        .expect("production response binds finalize request");
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
            ROUTER_AB_ECDSA_DERIVATION_WALLET_ID,
            ROUTER_AB_ECDSA_DERIVATION_THRESHOLD_KEY_ID,
            ROUTER_AB_ECDSA_DERIVATION_SIGNING_ROOT_ID,
            ROUTER_AB_ECDSA_DERIVATION_SIGNING_ROOT_VERSION,
            router_ab_ecdsa_derivation_material_activation_for_epoch(&receipt.activation_epoch),
        )
        .expect("Router A/B ECDSA derivation normal-signing scope");
    let mut active_state = cloudflare_active_signing_worker_state_from_activation_request_v1(
        &activation
            .to_recipient_proof_bundle_activation_request()
            .expect("generic activation request"),
        activation.material_activation.clone(),
        "router-ab-ecdsa-derivation-material",
        TEST_ACTIVATED_AT_MS,
    )
    .expect("Router A/B ECDSA derivation active state");
    active_state.material_activation.activation_id = "different-ecdsa-key".to_owned();
    let material_activation = router_ab_ecdsa_derivation_material_activation(&scope);
    let request = RouterAbEcdsaDerivationEvmDigestSigningRequestV1::new(
        scope,
        "router-ab-ecdsa-derivation-sign-request-1",
        "router-ab-ecdsa-operation-1",
        router_ab_ecdsa_derivation_operation_digests(),
        NormalSigningAuthorizationV1::reusable_wallet_session("ecdsa-wallet-session-1")
            .expect("ECDSA authorization"),
        material_activation,
        "server-presignature-1",
        2_000,
        b64u(&[0x77; 32]),
        b64u(&router_ab_ecdsa_rerandomization_client_commitment_v1(
            [0x66; 32],
        )),
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
            ROUTER_AB_ECDSA_DERIVATION_WALLET_ID,
            ROUTER_AB_ECDSA_DERIVATION_THRESHOLD_KEY_ID,
            ROUTER_AB_ECDSA_DERIVATION_SIGNING_ROOT_ID,
            ROUTER_AB_ECDSA_DERIVATION_SIGNING_ROOT_VERSION,
            router_ab_ecdsa_derivation_material_activation_for_epoch(&receipt.activation_epoch),
        )
        .expect("Router A/B ECDSA derivation normal-signing scope");
    scope.public_identity.ethereum_address20_b64u = b64u(&[0x55; 20]);
    let active_state = cloudflare_active_signing_worker_state_from_activation_request_v1(
        &activation
            .to_recipient_proof_bundle_activation_request()
            .expect("generic activation request"),
        activation.material_activation.clone(),
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
            router_admission_bindings(),
            peer(CloudflareWorkerRoleV1::DeriverA, "DERIVER_A"),
            peer(CloudflareWorkerRoleV1::DeriverB, "DERIVER_B"),
            peer(CloudflareWorkerRoleV1::SigningWorker, "SIGNING_WORKER"),
            issuer_verifying_keys(),
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
fn deriver_a_bindings_accept_role_private_secrets() {
    let bindings = CloudflareDeriverABindingsV1::new(
        deriver_a_root_share_wire_secret_binding(),
        deriver_a_envelope_hpke_decrypt_key(),
        deriver_a_peer_signing_key(),
        cloudflare_peer_verifying_key_set(),
        peer(CloudflareWorkerRoleV1::DeriverB, "DERIVER_B"),
        issuer_verifying_keys(),
    )
    .expect("signer a bindings");
    let startup = CloudflareWorkerBindingsV1::deriver_a(bindings).expect("signer a startup");

    assert_eq!(startup.worker_role(), CloudflareWorkerRoleV1::DeriverA);
}

#[test]
fn signing_worker_bindings_accept_presign_session_scope() {
    let bindings = CloudflareSigningWorkerBindingsV1::new(
        signing_worker_presign_session_binding(),
        server_output_hpke_decrypt_key(),
    )
    .expect("signing worker bindings");
    let startup =
        CloudflareWorkerBindingsV1::signing_worker(bindings).expect("signing worker startup");

    assert_eq!(startup.worker_role(), CloudflareWorkerRoleV1::SigningWorker);
}

#[test]
fn deriver_a_bindings_reject_b_root_share_wire_secret() {
    let err = CloudflareDeriverABindingsV1::new(
        deriver_b_root_share_wire_secret_binding(),
        deriver_a_envelope_hpke_decrypt_key(),
        deriver_a_peer_signing_key(),
        cloudflare_peer_verifying_key_set(),
        peer(CloudflareWorkerRoleV1::DeriverB, "DERIVER_B"),
        issuer_verifying_keys(),
    )
    .expect_err("signer a must reject signer b root-share wire secret");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::ForbiddenLocalBinding);
}

#[test]
fn deriver_a_bindings_reject_b_envelope_decrypt_key() {
    let err = CloudflareDeriverABindingsV1::new(
        deriver_a_root_share_wire_secret_binding(),
        deriver_b_envelope_hpke_decrypt_key(),
        deriver_a_peer_signing_key(),
        cloudflare_peer_verifying_key_set(),
        peer(CloudflareWorkerRoleV1::DeriverB, "DERIVER_B"),
        issuer_verifying_keys(),
    )
    .expect_err("signer a must reject signer b decrypt key");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::ForbiddenLocalBinding);
}

#[test]
fn deriver_a_bindings_reject_b_peer_signing_key() {
    let err = CloudflareDeriverABindingsV1::new(
        deriver_a_root_share_wire_secret_binding(),
        deriver_a_envelope_hpke_decrypt_key(),
        deriver_b_peer_signing_key(),
        cloudflare_peer_verifying_key_set(),
        peer(CloudflareWorkerRoleV1::DeriverB, "DERIVER_B"),
        issuer_verifying_keys(),
    )
    .expect_err("signer a must reject signer b peer signing key");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::ForbiddenLocalBinding);
}

#[test]
fn deriver_b_bindings_accept_role_private_secrets() {
    let bindings = CloudflareDeriverBBindingsV1::new(
        deriver_b_root_share_wire_secret_binding(),
        deriver_b_envelope_hpke_decrypt_key(),
        deriver_b_peer_signing_key(),
        cloudflare_peer_verifying_key_set(),
        peer(CloudflareWorkerRoleV1::DeriverA, "DERIVER_A"),
        issuer_verifying_keys(),
    )
    .expect("signer b bindings");
    let startup = CloudflareWorkerBindingsV1::deriver_b(bindings).expect("signer b startup");

    assert_eq!(startup.worker_role(), CloudflareWorkerRoleV1::DeriverB);
}

#[test]
fn deriver_b_bindings_reject_a_root_share_wire_secret() {
    let err = CloudflareDeriverBBindingsV1::new(
        deriver_a_root_share_wire_secret_binding(),
        deriver_b_envelope_hpke_decrypt_key(),
        deriver_b_peer_signing_key(),
        cloudflare_peer_verifying_key_set(),
        peer(CloudflareWorkerRoleV1::DeriverA, "DERIVER_A"),
        issuer_verifying_keys(),
    )
    .expect_err("signer b must reject signer a root-share wire secret");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::ForbiddenLocalBinding);
}

#[test]
fn deriver_b_bindings_reject_a_envelope_decrypt_key() {
    let err = CloudflareDeriverBBindingsV1::new(
        deriver_b_root_share_wire_secret_binding(),
        deriver_a_envelope_hpke_decrypt_key(),
        deriver_b_peer_signing_key(),
        cloudflare_peer_verifying_key_set(),
        peer(CloudflareWorkerRoleV1::DeriverA, "DERIVER_A"),
        issuer_verifying_keys(),
    )
    .expect_err("signer b must reject signer a decrypt key");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::ForbiddenLocalBinding);
}

#[test]
fn deriver_b_bindings_reject_a_peer_signing_key() {
    let err = CloudflareDeriverBBindingsV1::new(
        deriver_b_root_share_wire_secret_binding(),
        deriver_b_envelope_hpke_decrypt_key(),
        deriver_a_peer_signing_key(),
        cloudflare_peer_verifying_key_set(),
        peer(CloudflareWorkerRoleV1::DeriverA, "DERIVER_A"),
        issuer_verifying_keys(),
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
fn deriver_a_runtime_exposes_role_private_secrets_and_peer() {
    let runtime = CloudflareDeriverAWorkerRuntimeV1::new(
        CloudflareDeriverABindingsV1::new(
            deriver_a_root_share_wire_secret_binding(),
            deriver_a_envelope_hpke_decrypt_key(),
            deriver_a_peer_signing_key(),
            cloudflare_peer_verifying_key_set(),
            peer(CloudflareWorkerRoleV1::DeriverB, "DERIVER_B"),
            issuer_verifying_keys(),
        )
        .expect("signer a bindings"),
    )
    .expect("signer a runtime");
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
fn signing_worker_runtime_retains_only_ephemeral_presign_session_do() {
    let runtime = CloudflareSigningWorkerRuntimeV1::new(
        CloudflareSigningWorkerBindingsV1::new(
            signing_worker_presign_session_binding(),
            server_output_hpke_decrypt_key(),
        )
        .expect("signing worker bindings"),
    )
    .expect("signing worker runtime");
    assert_eq!(
        runtime.bindings().presign_session.binding_name,
        "SIGNING_WORKER_PRESIGN_SESSION_DO"
    );
    assert_eq!(
        runtime.server_output_decrypt_key().binding_name,
        "SIGNING_WORKER_SERVER_OUTPUT_HPKE_PRIVATE_KEY"
    );
}

#[test]
fn deriver_b_runtime_exposes_role_private_secrets_and_peer() {
    let runtime = CloudflareDeriverBWorkerRuntimeV1::new(
        CloudflareDeriverBBindingsV1::new(
            deriver_b_root_share_wire_secret_binding(),
            deriver_b_envelope_hpke_decrypt_key(),
            deriver_b_peer_signing_key(),
            cloudflare_peer_verifying_key_set(),
            peer(CloudflareWorkerRoleV1::DeriverA, "DERIVER_A"),
            issuer_verifying_keys(),
        )
        .expect("signer b bindings"),
    )
    .expect("signer b runtime");
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
        request.intent_digest(),
        request.signing_payload_digest(),
        material.admitted_signing_digest,
        server_round1,
        1_000,
        2_000,
    )
    .expect("server round1 record");
    let authorized_operation_identity =
        CloudflareSigningWorkerAuthorizedOperationIdentityV1::ReusableWalletSession {
            authorization_id: "authorization-1".to_owned(),
            wallet_session_id: wallet_session.wallet_session_id.clone(),
            authorized_operation_id: "authorized-operation-1".to_owned(),
            operation_id: "operation-1".to_owned(),
            operation_fingerprint_digest: "fingerprint-1".to_owned(),
        };
    let admitted = CloudflareSigningWorkerAdmittedNormalSigningFinalizeRequestV2::new(
        request.clone(),
        finalize_admission,
        trusted_admission,
        authorized_operation_identity,
        CloudflareSigningWorkerNormalSigningEffectClaimV1::ReusableWalletSession {
            claim: CloudflareSigningWorkerReusableWalletSessionEffectClaimV1::new(
                "authorization-1",
                wallet_session.wallet_session_id.clone(),
                "authorized-operation-1",
                "operation-1",
                "fingerprint-1",
            )
            .expect("stable effect claim"),
        },
    )
    .expect("admitted v2 finalize");

    let mut intent_drift_record = server_round1_record.clone();
    intent_drift_record.intent_digest = digest(0xa1);
    let err = CloudflareSigningWorkerMaterializedNormalSigningFinalizeRequestV2::new(
        admitted.clone(),
        active_signing_worker.clone(),
        material_record.clone(),
        intent_drift_record,
        1_500,
    )
    .expect_err("finalize intent must match the persisted prepare record");
    assert_eq!(
        err.code(),
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig
    );

    let mut payload_drift_record = server_round1_record.clone();
    payload_drift_record.signing_payload_digest = digest(0xa2);
    let err = CloudflareSigningWorkerMaterializedNormalSigningFinalizeRequestV2::new(
        admitted.clone(),
        active_signing_worker.clone(),
        material_record.clone(),
        payload_drift_record,
        1_500,
    )
    .expect_err("finalize signing payload must match the persisted prepare record");
    assert_eq!(
        err.code(),
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig
    );

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
fn normal_signing_step_up_admission_derives_the_exact_authorized_operation() {
    let mut request = normal_signing_v2_finalize_request(2_000);
    request.scope.authorization =
        NormalSigningAuthorizationV1::operation_step_up().expect("step-up scope authorization");
    request.validate().expect("step-up finalize request");
    let admission = CloudflareRouterNormalSigningFinalizeAdmissionCandidateV2::new(
        "org-1",
        "project-1",
        "dev",
        request.scope.account_id.clone(),
        "principal-1",
        CloudflareRouterNormalSigningAuthorizationV2::operation_step_up(
            "authorization-session-1",
            "evidence-set-digest-1",
        )
        .expect("step-up admission authorization"),
        request.scope.signing_worker_id.clone(),
        request.scope.request_id.clone(),
        request.intent_digest(),
        request.signing_payload_digest(),
        request.round1_binding_digest(),
        digest(0x90),
        request.expires_at_ms,
    )
    .expect("step-up admission");
    let trusted_admission = CloudflareRouterNormalSigningTrustedAdmissionV1::new(
        admission
            .to_v1_trusted_metadata()
            .expect("trusted metadata"),
        ExpensiveWorkGateDecisionV1::accepted(request.scope.request_id.clone()).expect("accepted"),
    )
    .expect("trusted admission");
    let authorized_operation_identity =
        CloudflareSigningWorkerAuthorizedOperationIdentityV1::OperationStepUp {
            authorization_session_id: "authorization-session-1".to_owned(),
            authorized_operation_id: "authorized-operation-1".to_owned(),
            operation_id: "operation-1".to_owned(),
            operation_fingerprint_digest: "fingerprint-1".to_owned(),
        };
    let admitted = CloudflareSigningWorkerAdmittedNormalSigningFinalizeRequestV2::new(
        request,
        admission,
        trusted_admission,
        authorized_operation_identity,
        CloudflareSigningWorkerNormalSigningEffectClaimV1::OperationStepUp {
            authorization_session_id: "authorization-session-1".to_owned(),
            authorized_operation_id: "authorized-operation-1".to_owned(),
            operation_id: "operation-1".to_owned(),
            operation_fingerprint_digest: "fingerprint-1".to_owned(),
        },
    )
    .expect("admitted step-up finalize");

    assert_eq!(
        admitted.effect_claim,
        CloudflareSigningWorkerNormalSigningEffectClaimV1::OperationStepUp {
            authorization_session_id: "authorization-session-1".to_owned(),
            authorized_operation_id: "authorized-operation-1".to_owned(),
            operation_id: "operation-1".to_owned(),
            operation_fingerprint_digest: "fingerprint-1".to_owned(),
        }
    );
    let operation_key = admitted.effect_operation_key().expect("operation key");
    assert!(operation_key.contains("session-1"));
    assert!(!operation_key.contains("authorized-operation-1"));
}

#[test]
fn signing_worker_effect_claim_rejects_authorized_operation_identity_substitution() {
    let claim = CloudflareSigningWorkerNormalSigningEffectClaimV1::OperationStepUp {
        authorization_session_id: "authorization-session-1".to_owned(),
        authorized_operation_id: "authorized-operation-1".to_owned(),
        operation_id: "operation-1".to_owned(),
        operation_fingerprint_digest: "fingerprint-1".to_owned(),
    };
    let matching = CloudflareSigningWorkerAuthorizedOperationIdentityV1::OperationStepUp {
        authorization_session_id: "authorization-session-1".to_owned(),
        authorized_operation_id: "authorized-operation-1".to_owned(),
        operation_id: "operation-1".to_owned(),
        operation_fingerprint_digest: "fingerprint-1".to_owned(),
    };
    claim
        .validate_for_authorized_operation_identity(&matching)
        .expect("matching operation identity");

    let substituted = CloudflareSigningWorkerAuthorizedOperationIdentityV1::OperationStepUp {
        authorization_session_id: "authorization-session-1".to_owned(),
        authorized_operation_id: "authorized-operation-substituted".to_owned(),
        operation_id: "operation-1".to_owned(),
        operation_fingerprint_digest: "fingerprint-1".to_owned(),
    };
    let error = claim
        .validate_for_authorized_operation_identity(&substituted)
        .expect_err("substituted authorized operation identity must fail closed");
    assert_eq!(error.code(), RouterAbProtocolErrorCode::InvalidGateDecision);
}

#[test]
fn signing_worker_reusable_identity_rejects_pairwise_authorization_alias() {
    let error = CloudflareSigningWorkerReusableWalletSessionEffectClaimV1::new(
        "wallet-session-1",
        "wallet-session-1",
        "authorized-operation-1",
        "operation-1",
        "fingerprint-1",
    )
    .expect_err("authorization and Wallet Session ids must remain distinct");
    assert_eq!(error.code(), RouterAbProtocolErrorCode::InvalidGateDecision);

    let identity = CloudflareSigningWorkerAuthorizedOperationIdentityV1::ReusableWalletSession {
        authorization_id: "wallet-session-1".to_owned(),
        wallet_session_id: "wallet-session-1".to_owned(),
        authorized_operation_id: "authorized-operation-1".to_owned(),
        operation_id: "operation-1".to_owned(),
        operation_fingerprint_digest: "fingerprint-1".to_owned(),
    };
    let error = identity
        .validate()
        .expect_err("accepted worker identity must reject authorization alias");
    assert_eq!(error.code(), RouterAbProtocolErrorCode::InvalidGateDecision);

    let error = CloudflareRouterNormalSigningAuthorizationV2::reusable_wallet_session(
        "wallet-session-1",
        "wallet-session-1",
    )
    .expect_err("normal-signing authorization must reject Wallet Session alias");
    assert_eq!(error.code(), RouterAbProtocolErrorCode::InvalidGateDecision);
}

#[test]
fn normal_signing_finalize_boundary_extracts_reusable_authorized_operation() {
    let request = normal_signing_v2_finalize_request(2_000);
    let mut body = serde_json::to_value(&request)
        .expect("finalize request JSON")
        .as_object()
        .expect("finalize request object")
        .clone();
    body.insert(
        "authorized_operation".to_owned(),
        serde_json::json!({
            "binding": {
                "kind": "reusable_wallet_session",
                "authorization_id": "authorization-1",
                "wallet_session_id": "wallet-session-1",
                "quota_id": "quota-1"
            },
            "authorized_operation": {
                "kind": "reusable_wallet_session_authorized_operation_v1",
                "authorized_operation_id": "authorized-operation-1",
                "operation_id": "operation-1",
                "capability_kind": "near_ed25519_mpc_signing",
                "operation_kind": "near.sign_transaction",
                "lane_digest_b64u": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x11; 32]),
                "intent_digest_b64u": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(request.intent_digest().as_bytes()),
                "display_digest_b64u": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x22; 32]),
                "operation_fingerprint_digest": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x33; 32])
            }
        }),
    );
    let bytes = serde_json::to_vec(&body).expect("authorized finalize JSON");
    let (parsed_request, authorized_operation) =
        parse_cloudflare_router_authorized_ed25519_finalize_request_v2_json(&bytes)
            .expect("authorized finalize request");

    assert_eq!(parsed_request, request);

    let mut aliased_body = body.clone();
    aliased_body["authorized_operation"]["binding"]["authorization_id"] =
        serde_json::json!("wallet-session-1");
    let error = parse_cloudflare_router_authorized_ed25519_finalize_request_v2_json(
        &serde_json::to_vec(&aliased_body).expect("aliased authorized finalize JSON"),
    )
    .expect_err("authorization and Wallet Session ids must remain distinct");
    assert_eq!(error.code(), RouterAbProtocolErrorCode::InvalidGateDecision);

    let mut legacy_body = body.clone();
    let mut legacy_accepted = legacy_body
        .remove("authorized_operation")
        .expect("authorized operation object");
    let legacy_operation = legacy_accepted
        .as_object_mut()
        .expect("accepted authorization object")
        .remove("authorized_operation")
        .expect("nested authorized operation field");
    legacy_accepted
        .as_object_mut()
        .expect("accepted authorization object")
        .insert("claim".to_owned(), legacy_operation);
    legacy_body.insert("authorized_operation".to_owned(), legacy_accepted);
    let error = parse_cloudflare_router_authorized_ed25519_finalize_request_v2_json(
        &serde_json::to_vec(&legacy_body).expect("legacy nested operation request JSON"),
    )
    .expect_err("legacy nested operation field must be rejected");
    assert_eq!(
        error.code(),
        RouterAbProtocolErrorCode::MalformedWirePayload
    );

    let authorization = CloudflareRouterNormalSigningAuthorizationV2::reusable_wallet_session(
        "authorization-1",
        "wallet-session-1",
    )
    .expect("reusable authorization");
    authorized_operation
        .authorized_operation
        .validate_for_finalize_request(&parsed_request, &authorization)
        .expect("authorized operation matches finalize request");
}

#[test]
fn normal_signing_finalize_boundary_extracts_verified_step_up_authorized_operation() {
    let mut request = normal_signing_v2_finalize_request(2_000);
    request.scope.authorization =
        NormalSigningAuthorizationV1::operation_step_up().expect("operation step-up");
    let mut body = serde_json::to_value(&request)
        .expect("operation-step-up finalize JSON")
        .as_object()
        .expect("operation-step-up finalize object")
        .clone();
    body.insert(
        "authorized_operation".to_owned(),
        serde_json::json!({
            "binding": {
                "kind": "operation_step_up",
                "authorization_session_id": "authorization-session-1",
                "org_id": "org-1",
                "project_id": "project-1",
                "environment": "dev",
                "subject_id": "user-1"
            },
            "authorized_operation": {
                "kind": "verified_step_up_authorized_operation_v1",
                "authorization_session_id": "authorization-session-1",
                "evidence_set_digest": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x55; 32]),
                "authorized_operation_id": "authorized-operation-1",
                "operation_id": "operation-1",
                "capability_kind": "near_ed25519_mpc_signing",
                "operation_kind": "near.sign_transaction",
                "lane_digest_b64u": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x11; 32]),
                "intent_digest_b64u": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(request.intent_digest().as_bytes()),
                "display_digest_b64u": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x22; 32]),
                "operation_fingerprint_digest": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x33; 32])
            }
        }),
    );
    let bytes = serde_json::to_vec(&body).expect("authorized operation-step-up finalize JSON");

    let (parsed_request, authorized_operation) =
        parse_cloudflare_router_authorized_ed25519_finalize_request_v2_json(&bytes)
            .expect("operation-step-up finalize request");

    assert_eq!(parsed_request, request);
    let authorization = CloudflareRouterNormalSigningAuthorizationV2::operation_step_up(
        "authorization-session-1",
        "evidence-set-digest-1",
    )
    .expect("operation-step-up authorization");
    authorized_operation
        .authorized_operation
        .validate_for_finalize_request(&parsed_request, &authorization)
        .expect("step-up authorized operation matches finalize request");
}

#[test]
fn normal_signing_finalize_admission_rejects_operation_step_up_from_wallet_session() {
    let mut request = normal_signing_v2_finalize_request(2_000);
    request.scope.authorization =
        NormalSigningAuthorizationV1::operation_step_up().expect("operation step-up");
    let wallet_session = normal_signing_v2_wallet_session(3_000);

    let error = CloudflareRouterNormalSigningFinalizeAdmissionCandidateV2::from_finalize_request(
        &wallet_session,
        &request,
        1_000,
    )
    .expect_err("Wallet Session bearer cannot authorize operation-step-up signing");

    assert_eq!(error.code(), RouterAbProtocolErrorCode::InvalidGateDecision);
}

#[test]
fn normal_signing_effect_digest_binds_policy_principal_capability_and_terminal_failure() {
    let request = normal_signing_v2_finalize_request(2_000);
    let wallet_session = normal_signing_v2_wallet_session(3_000);
    let admission =
        CloudflareRouterNormalSigningFinalizeAdmissionCandidateV2::from_finalize_request(
            &wallet_session,
            &request,
            1_000,
        )
        .expect("finalize admission");
    let trusted = CloudflareRouterNormalSigningTrustedAdmissionV1::new(
        admission
            .to_v1_trusted_metadata()
            .expect("trusted metadata"),
        ExpensiveWorkGateDecisionV1::accepted("gate-request-1").expect("accepted"),
    )
    .expect("trusted admission");
    let effect_claim = CloudflareSigningWorkerNormalSigningEffectClaimV1::ReusableWalletSession {
        claim: CloudflareSigningWorkerReusableWalletSessionEffectClaimV1::new(
            "authorization-1",
            wallet_session.wallet_session_id.clone(),
            "authorized-operation-1",
            "operation-1",
            "fingerprint-1",
        )
        .expect("stable effect claim"),
    };
    let effect_identity =
        CloudflareSigningWorkerAuthorizedOperationIdentityV1::ReusableWalletSession {
            authorization_id: "authorization-1".to_owned(),
            wallet_session_id: wallet_session.wallet_session_id.clone(),
            authorized_operation_id: "authorized-operation-1".to_owned(),
            operation_id: "operation-1".to_owned(),
            operation_fingerprint_digest: "fingerprint-1".to_owned(),
        };
    let admitted = CloudflareSigningWorkerAdmittedNormalSigningFinalizeRequestV2::new(
        request.clone(),
        admission.clone(),
        trusted,
        effect_identity.clone(),
        effect_claim.clone(),
    )
    .expect("admitted finalize");
    let retry_claim = CloudflareSigningWorkerReusableWalletSessionEffectClaimV1::new(
        "authorization-1",
        wallet_session.wallet_session_id.clone(),
        "authorized-operation-1",
        "operation-1",
        "fingerprint-1",
    )
    .expect("stable retry effect claim");
    assert_eq!(
        admitted.effect_claim,
        CloudflareSigningWorkerNormalSigningEffectClaimV1::ReusableWalletSession {
            claim: retry_claim,
        }
    );
    let effect_json = serde_json::to_value(&admitted.effect_claim).expect("effect claim JSON");
    assert!(effect_json["claim"].get("now_unix_ms").is_none());

    let mut changed_admission = admission;
    changed_admission.org_id = "org-2".to_owned();
    changed_admission.subject_id = "principal-2".to_owned();
    let changed_trusted = CloudflareRouterNormalSigningTrustedAdmissionV1::new(
        changed_admission
            .to_v1_trusted_metadata()
            .expect("changed trusted metadata"),
        ExpensiveWorkGateDecisionV1::accepted("gate-request-1").expect("accepted"),
    )
    .expect("changed trusted admission");
    let changed = CloudflareSigningWorkerAdmittedNormalSigningFinalizeRequestV2::new(
        request,
        changed_admission,
        changed_trusted,
        effect_identity.clone(),
        effect_claim,
    )
    .expect("changed admitted finalize");
    assert_eq!(
        admitted.effect_operation_key().expect("operation key"),
        changed
            .effect_operation_key()
            .expect("changed operation key")
    );
    assert_ne!(
        admitted.effect_request_digest().expect("request digest"),
        changed
            .effect_request_digest()
            .expect("changed request digest")
    );

    let mut changed_capability_request = admitted.request.clone();
    changed_capability_request
        .scope
        .material_activation
        .capability = "ed25519-signing-capability-2".to_owned();
    changed_capability_request
        .validate()
        .expect("changed capability request");
    let changed_capability_admission =
        CloudflareRouterNormalSigningFinalizeAdmissionCandidateV2::from_finalize_request(
            &wallet_session,
            &changed_capability_request,
            1_000,
        )
        .expect("changed capability admission");
    let changed_capability_trusted = CloudflareRouterNormalSigningTrustedAdmissionV1::new(
        changed_capability_admission
            .to_v1_trusted_metadata()
            .expect("changed capability metadata"),
        ExpensiveWorkGateDecisionV1::accepted("gate-request-1").expect("accepted"),
    )
    .expect("changed capability trusted admission");
    let changed_capability = CloudflareSigningWorkerAdmittedNormalSigningFinalizeRequestV2::new(
        changed_capability_request,
        changed_capability_admission,
        changed_capability_trusted,
        effect_identity,
        admitted.effect_claim.clone(),
    )
    .expect("changed capability admitted finalize");
    assert_eq!(
        admitted.effect_operation_key().expect("operation key"),
        changed_capability
            .effect_operation_key()
            .expect("changed capability operation key")
    );
    assert_ne!(
        admitted.effect_request_digest().expect("request digest"),
        changed_capability
            .effect_request_digest()
            .expect("changed capability request digest")
    );

    let terminal = CloudflareSigningWorkerNormalSigningTerminalV1::from_result(Err(
        router_ab_core::RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MissingLocalBinding,
            "round-1 material is missing",
        ),
    ));
    terminal
        .validate_for_request(&admitted)
        .expect("terminal failure validates");
    let round_trip: CloudflareSigningWorkerNormalSigningTerminalV1 =
        serde_json::from_str(&serde_json::to_string(&terminal).expect("serialize terminal"))
            .expect("deserialize terminal");
    let error = round_trip
        .into_result()
        .expect_err("terminal failure replays as failure");
    assert_eq!(error.code(), RouterAbProtocolErrorCode::MissingLocalBinding);
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

    let actual_share_wire = host
        .signing_root_share_wire(Role::SignerA, &root_epoch())
        .expect("root-share wire");
    assert_eq!(actual_share_wire.share_id(), share_wire.share_id());
    assert_eq!(actual_share_wire.as_bytes(), share_wire.as_bytes());
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
    let actual_share_wire = decoded.signing_root_share_wire();
    let expected_share_wire = root_share_wire(Role::SignerA);
    assert_eq!(actual_share_wire.share_id(), expected_share_wire.share_id());
    assert_eq!(actual_share_wire.as_bytes(), expected_share_wire.as_bytes());

    let host = CloudflarePreloadedSignerHostV1::new_with_root_share_wires(
        1_000,
        vec![metadata],
        vec![decoded],
        Vec::new(),
        signer_verifying_keys(),
        Vec::new(),
    )
    .expect("host with decoded root-share wire");

    let actual_share_wire = host
        .signing_root_share_wire(Role::SignerA, &root_epoch())
        .expect("root-share wire");
    let expected_share_wire = root_share_wire(Role::SignerA);
    assert_eq!(actual_share_wire.share_id(), expected_share_wire.share_id());
    assert_eq!(actual_share_wire.as_bytes(), expected_share_wire.as_bytes());
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
    let actual_share_wire = decoded.signing_root_share_wire();
    let expected_share_wire = root_share_wire(Role::SignerA);
    assert_eq!(actual_share_wire.share_id(), expected_share_wire.share_id());
    assert_eq!(actual_share_wire.as_bytes(), expected_share_wire.as_bytes());
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
fn env_parser_builds_router_bindings_from_required_keys() {
    let parsed = parse_cloudflare_worker_bindings_v1(CloudflareWorkerRoleV1::Router, &router_env())
        .expect("router env");

    let CloudflareWorkerBindingsV1::Router { bindings } = parsed else {
        panic!("expected router bindings");
    };
    assert_eq!(bindings.admission.jwt.audience, "router-ab");
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
        bindings.presign_session.binding_name,
        "SIGNING_WORKER_PRESIGN_SESSION_DO"
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
        (ROUTER_JWT_ISSUER_ENV, "https://issuer.example"),
        (ROUTER_JWT_AUDIENCE_ENV, "router-ab"),
        (ROUTER_JWT_JWKS_JSON_ENV, test_router_jwks_json()),
        (DERIVER_A_PEER_BINDING_ENV, "DERIVER_A"),
    ]);

    let err = parse_cloudflare_worker_bindings_v1(CloudflareWorkerRoleV1::Router, &env)
        .expect_err("missing signer b peer must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::MissingLocalBinding);
}

#[test]
fn env_parser_rejects_signer_env_with_router_admission_key() {
    let env = CloudflareEnvMapV1::new(vec![(ROUTER_JWT_ISSUER_ENV, "https://issuer.example")]);

    let err = parse_cloudflare_worker_bindings_v1(CloudflareWorkerRoleV1::DeriverA, &env)
        .expect_err("signer env must reject router admission key");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::ForbiddenLocalBinding);
}

#[test]
fn env_parser_rejects_deriver_b_env_with_server_output_key() {
    let env = CloudflareEnvMapV1::new(vec![(
        SIGNING_WORKER_PRESIGN_SESSION_DO_BINDING_ENV,
        "SIGNING_WORKER_PRESIGN_SESSION_DO",
    )]);

    let err = parse_cloudflare_worker_bindings_v1(CloudflareWorkerRoleV1::DeriverB, &env)
        .expect_err("signer b env must reject server-output key");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::ForbiddenLocalBinding);
}

// --- R120 tenant-root control-plane Worker ---------------------------------
//
// | Material                        | Owner                             |
// |---------------------------------|-----------------------------------|
// | issuer private signing key      | control-plane Worker only         |
// | issuer public verifying keyset  | Router, Deriver A, Deriver B      |

fn tenant_root_control_plane_env() -> CloudflareEnvMapV1 {
    CloudflareEnvMapV1::new(vec![
        (
            router_ab_cloudflare::TENANT_ROOT_CONTROL_PLANE_ISSUER_SIGNING_KEY_ID_ENV,
            "control-plane-issuer-v1".to_string(),
        ),
        (
            router_ab_cloudflare::TENANT_ROOT_CONTROL_PLANE_ISSUER_SIGNING_KEY_BINDING_ENV,
            "TENANT_ROOT_CONTROL_PLANE_ISSUER_SIGNING_KEY".to_string(),
        ),
        (
            TENANT_ROOT_CONTROL_PLANE_ISSUER_VERIFYING_KEYS_JSON_ENV,
            ISSUER_VERIFYING_KEYS_JSON.to_string(),
        ),
        (
            router_ab_cloudflare::TENANT_ROOT_CONTROL_PLANE_GRANT_AUTHORITY_VERIFYING_KEYS_JSON_ENV,
            GRANT_AUTHORITY_VERIFYING_KEYS_JSON.to_string(),
        ),
        (
            router_ab_cloudflare::DERIVER_A_TENANT_ROOT_CREATION_SIGNING_KEY_ID_ENV,
            "deriver-a-signing-key-7".to_string(),
        ),
        (
            router_ab_cloudflare::DERIVER_B_TENANT_ROOT_CREATION_SIGNING_KEY_ID_ENV,
            "deriver-b-signing-key-9".to_string(),
        ),
        (
            router_ab_cloudflare::ROUTER_TENANT_ROOT_CREATION_ROLE_VERIFYING_KEYS_JSON_ENV,
            ROLE_VERIFYING_KEYS_JSON.to_string(),
        ),
    ])
}

#[test]
fn control_plane_bindings_parse_and_describe_only_the_issuer_secret() {
    let bindings =
        parse_cloudflare_tenant_root_control_plane_bindings_v1(&tenant_root_control_plane_env())
            .expect("control-plane bindings");
    assert_eq!(
        bindings.issuer_signing_key.signing_key_id(),
        "control-plane-issuer-v1"
    );
    assert_eq!(
        bindings.issuer_signing_key.binding_name(),
        "TENANT_ROOT_CONTROL_PLANE_ISSUER_SIGNING_KEY"
    );
    // The issuer holds its own published anchor so it can prove at boot that
    // its Secret derives the key registered under its active id.
    assert!(bindings
        .issuer_verifying_keys
        .for_issuer_key_id("control-plane-issuer-v1")
        .is_some());

    let parsed = parse_cloudflare_worker_bindings_v1(
        CloudflareWorkerRoleV1::TenantRootControlPlane,
        &tenant_root_control_plane_env(),
    )
    .expect("worker bindings");
    assert_eq!(
        parsed.worker_role(),
        CloudflareWorkerRoleV1::TenantRootControlPlane
    );
    assert!(matches!(
        parsed,
        router_ab_cloudflare::CloudflareWorkerBindingsV1::TenantRootControlPlane { .. }
    ));
}

#[test]
fn issuer_signing_secret_is_accepted_only_by_the_control_plane_worker() {
    // The parser itself refuses every other role before reading Env.
    for worker_role in [
        CloudflareWorkerRoleV1::Router,
        CloudflareWorkerRoleV1::DeriverA,
        CloudflareWorkerRoleV1::DeriverB,
        CloudflareWorkerRoleV1::SigningWorker,
    ] {
        let err = parse_cloudflare_tenant_root_control_plane_issuer_signing_key_binding_v1(
            worker_role,
            &tenant_root_control_plane_env(),
        )
        .expect_err("only the control plane may parse the issuer signing secret");
        assert_eq!(
            err.code(),
            RouterAbProtocolErrorCode::ForbiddenLocalBinding,
            "{}",
            worker_role.as_str()
        );
    }

    // And every other Worker's own startup parser rejects the binding at boot.
    for worker_role in [
        CloudflareWorkerRoleV1::Router,
        CloudflareWorkerRoleV1::DeriverA,
        CloudflareWorkerRoleV1::DeriverB,
        CloudflareWorkerRoleV1::SigningWorker,
    ] {
        let env = CloudflareEnvMapV1::new(vec![(
            router_ab_cloudflare::TENANT_ROOT_CONTROL_PLANE_ISSUER_SIGNING_KEY_BINDING_ENV,
            "TENANT_ROOT_CONTROL_PLANE_ISSUER_SIGNING_KEY",
        )]);
        let err = parse_cloudflare_worker_bindings_v1(worker_role, &env)
            .expect_err("non-issuer Workers must reject the issuer private binding");
        assert_eq!(
            err.code(),
            RouterAbProtocolErrorCode::ForbiddenLocalBinding,
            "{}",
            worker_role.as_str()
        );
    }
}

#[test]
fn control_plane_rejects_every_scalar_and_router_auth_config() {
    for (key, value) in [
        // Deriver scalar and Secret material.
        (
            DERIVER_A_ROOT_SHARE_WIRE_SECRET_BINDING_ENV,
            "DERIVER_A_ROOT_SHARE_WIRE_SECRET",
        ),
        (
            DERIVER_B_ROOT_SHARE_WIRE_SECRET_BINDING_ENV,
            "DERIVER_B_ROOT_SHARE_WIRE_SECRET",
        ),
        (
            DERIVER_A_ENVELOPE_HPKE_PRIVATE_KEY_BINDING_ENV,
            "DERIVER_A_ENVELOPE_HPKE_PRIVATE_KEY",
        ),
        (
            DERIVER_B_PEER_SIGNING_KEY_BINDING_ENV,
            "DERIVER_B_PEER_SIGNING_KEY",
        ),
        (
            router_ab_cloudflare::DERIVER_A_TENANT_ROOT_CREATION_SIGNING_KEY_BINDING_ENV,
            "DERIVER_A_TENANT_ROOT_CREATION_SIGNING_KEY",
        ),
        (
            router_ab_cloudflare::DERIVER_B_TENANT_ROOT_ONLINE_HPKE_PRIVATE_KEY_BINDING_ENV,
            "DERIVER_B_TENANT_ROOT_ONLINE_HPKE_PRIVATE_KEY",
        ),
        // SigningWorker material.
        (
            SIGNING_WORKER_SERVER_OUTPUT_HPKE_PRIVATE_KEY_BINDING_ENV,
            "SIGNING_WORKER_SERVER_OUTPUT_HPKE_PRIVATE_KEY",
        ),
        // Router authorization configuration: the issuer validates from
        // authenticated capabilities and DO state, never raw credentials.
        (ROUTER_JWT_ISSUER_ENV, "https://issuer.example"),
        (ROUTER_JWT_JWKS_JSON_ENV, "{}"),
        (ROUTER_PROJECT_POLICY_BOOTSTRAP_JSON_ENV, "{}"),
    ] {
        // Start from a fully valid control plane, so the rejection is the
        // forbidden-material check and not a missing-configuration error.
        let err = parse_cloudflare_worker_bindings_v1(
            CloudflareWorkerRoleV1::TenantRootControlPlane,
            &control_plane_env_with(key, value),
        )
        .expect_err("control plane must reject foreign material");
        assert_eq!(
            err.code(),
            RouterAbProtocolErrorCode::ForbiddenLocalBinding,
            "{key}"
        );
    }
}

/// The issuer must not be able to authorize the creations it then signs.
#[test]
fn a_grant_authority_may_not_reuse_a_control_plane_issuer_key() {
    let entries: Vec<(&str, String)> = tenant_root_control_plane_env()
        .entries()
        .iter()
        .map(|(key, value)| {
            let value = if key.as_str()
                == router_ab_cloudflare::TENANT_ROOT_CONTROL_PLANE_GRANT_AUTHORITY_VERIFYING_KEYS_JSON_ENV
            {
                // Publish the ISSUER's key as a grant authority.
                ISSUER_VERIFYING_KEYS_JSON.to_string()
            } else {
                value.clone()
            };
            (
                Box::leak(key.clone().into_boxed_str()) as &str,
                value,
            )
        })
        .collect();
    let error = parse_cloudflare_worker_bindings_v1(
        CloudflareWorkerRoleV1::TenantRootControlPlane,
        &CloudflareEnvMapV1::new(entries),
    )
    .expect_err("a grant authority reusing an issuer key must fail closed");
    assert_eq!(
        error.code(),
        RouterAbProtocolErrorCode::ForbiddenLocalBinding
    );
}

/// The complete control-plane fixture with one entry overridden, so a boundary
/// test fails on the boundary it is testing rather than on missing config.
fn control_plane_env_with(key: &str, value: &str) -> CloudflareEnvMapV1 {
    let mut entries: Vec<(String, String)> = tenant_root_control_plane_env()
        .entries()
        .iter()
        .map(|(name, existing)| (name.clone(), existing.clone()))
        .collect();
    match entries.iter_mut().find(|(name, _)| name == key) {
        Some(slot) => slot.1 = value.to_string(),
        None => entries.push((key.to_string(), value.to_string())),
    }
    CloudflareEnvMapV1::new(entries)
}

/// A configured role signing ID must exist in the published keyset under its
/// own role: otherwise a typo mints a ceremony no Deriver can ever execute.
#[test]
fn control_plane_role_signing_ids_must_be_published_under_their_roles() {
    let base: Vec<(String, String)> = tenant_root_control_plane_env()
        .entries()
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    let with = |key: &str, value: &str| -> CloudflareEnvMapV1 {
        let mut next = base.clone();
        next.iter_mut()
            .find(|(name, _)| name == key)
            .expect("fixture entry")
            .1 = value.to_string();
        CloudflareEnvMapV1::new(next)
    };
    let parse = |env: &CloudflareEnvMapV1| {
        parse_cloudflare_worker_bindings_v1(CloudflareWorkerRoleV1::TenantRootControlPlane, env)
    };

    // The matching configuration parses and resolves both roles' keys.
    parse(&CloudflareEnvMapV1::new(base.clone())).expect("published role IDs");

    // An ID absent from the keyset.
    assert_eq!(
        parse(&with(
            router_ab_cloudflare::DERIVER_A_TENANT_ROOT_CREATION_SIGNING_KEY_ID_ENV,
            "deriver-a-signing-key-typo",
        ))
        .expect_err("unpublished role signing ID")
        .code(),
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig
    );

    // An ID published for the OTHER role: present in the keyset, wrong role.
    assert!(parse(&with(
        router_ab_cloudflare::DERIVER_A_TENANT_ROOT_CREATION_SIGNING_KEY_ID_ENV,
        "deriver-b-signing-key-9",
    ))
    .is_err());
    assert!(parse(&with(
        router_ab_cloudflare::DERIVER_B_TENANT_ROOT_CREATION_SIGNING_KEY_ID_ENV,
        "deriver-a-signing-key-7",
    ))
    .is_err());

    // A missing keyset fails the Worker at boot.
    let without: Vec<(String, String)> = base
        .iter()
        .filter(|(key, _)| {
            key != router_ab_cloudflare::ROUTER_TENANT_ROOT_CREATION_ROLE_VERIFYING_KEYS_JSON_ENV
        })
        .cloned()
        .collect();
    assert!(parse(&CloudflareEnvMapV1::new(without)).is_err());
}

/// The issuer names both roles' public signing key IDs, and never their Secrets.
#[test]
fn the_control_plane_holds_role_signing_key_ids_but_never_their_bindings() {
    let bindings = parse_cloudflare_worker_bindings_v1(
        CloudflareWorkerRoleV1::TenantRootControlPlane,
        &tenant_root_control_plane_env(),
    )
    .expect("control-plane bindings");
    let CloudflareWorkerBindingsV1::TenantRootControlPlane {
        bindings: control_plane,
    } = bindings
    else {
        panic!("expected control-plane bindings");
    };
    assert_eq!(
        control_plane.deriver_a_signing_key_id,
        "deriver-a-signing-key-7"
    );
    assert_eq!(
        control_plane.deriver_b_signing_key_id,
        "deriver-b-signing-key-9"
    );

    for binding in [
        router_ab_cloudflare::DERIVER_A_TENANT_ROOT_CREATION_SIGNING_KEY_BINDING_ENV,
        router_ab_cloudflare::DERIVER_B_TENANT_ROOT_CREATION_SIGNING_KEY_BINDING_ENV,
    ] {
        let mut entries: Vec<(String, String)> = tenant_root_control_plane_env()
            .entries()
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        entries.push((binding.to_string(), "SOME_SECRET".to_string()));
        assert_eq!(
            parse_cloudflare_worker_bindings_v1(
                CloudflareWorkerRoleV1::TenantRootControlPlane,
                &CloudflareEnvMapV1::new(entries),
            )
            .expect_err("a role signing Secret binding must be refused")
            .code(),
            RouterAbProtocolErrorCode::ForbiddenLocalBinding
        );
    }
}

#[test]
fn control_plane_requires_its_active_issuer_key_id_to_be_published() {
    // Missing anchor: the issuer cannot boot without its own published set.
    let mut entries: Vec<(&str, String)> = vec![
        (
            router_ab_cloudflare::TENANT_ROOT_CONTROL_PLANE_ISSUER_SIGNING_KEY_ID_ENV,
            "control-plane-issuer-v1".to_string(),
        ),
        (
            router_ab_cloudflare::TENANT_ROOT_CONTROL_PLANE_ISSUER_SIGNING_KEY_BINDING_ENV,
            "TENANT_ROOT_CONTROL_PLANE_ISSUER_SIGNING_KEY".to_string(),
        ),
        (
            router_ab_cloudflare::TENANT_ROOT_CONTROL_PLANE_GRANT_AUTHORITY_VERIFYING_KEYS_JSON_ENV,
            GRANT_AUTHORITY_VERIFYING_KEYS_JSON.to_string(),
        ),
        (
            router_ab_cloudflare::DERIVER_A_TENANT_ROOT_CREATION_SIGNING_KEY_ID_ENV,
            "deriver-a-signing-key-7".to_string(),
        ),
        (
            router_ab_cloudflare::DERIVER_B_TENANT_ROOT_CREATION_SIGNING_KEY_ID_ENV,
            "deriver-b-signing-key-9".to_string(),
        ),
        (
            router_ab_cloudflare::ROUTER_TENANT_ROOT_CREATION_ROLE_VERIFYING_KEYS_JSON_ENV,
            ROLE_VERIFYING_KEYS_JSON.to_string(),
        ),
    ];
    parse_cloudflare_worker_bindings_v1(
        CloudflareWorkerRoleV1::TenantRootControlPlane,
        &CloudflareEnvMapV1::new(entries.clone()),
    )
    .expect_err("issuer requires its published anchor");

    // An anchor that does not publish the active key id fails closed: an issuer
    // signing under an unpublished id could never be verified.
    entries.push((
        TENANT_ROOT_CONTROL_PLANE_ISSUER_VERIFYING_KEYS_JSON_ENV,
        ISSUER_VERIFYING_KEYS_JSON.to_string(),
    ));
    let set = |entries: &Vec<(&'static str, String)>, key: &str, value: &str| {
        let mut next = entries.clone();
        let slot = next
            .iter_mut()
            .find(|(name, _)| *name == key)
            .expect("fixture entry");
        slot.1 = value.to_string();
        next
    };

    let foreign = set(
        &entries,
        router_ab_cloudflare::TENANT_ROOT_CONTROL_PLANE_ISSUER_SIGNING_KEY_ID_ENV,
        "control-plane-issuer-unpublished",
    );
    let err = parse_cloudflare_worker_bindings_v1(
        CloudflareWorkerRoleV1::TenantRootControlPlane,
        &CloudflareEnvMapV1::new(foreign),
    )
    .expect_err("unpublished active key id");
    assert_eq!(
        err.code(),
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig
    );

    // A malformed anchor fails at boot, not at first verification.
    let malformed = set(
        &entries,
        TENANT_ROOT_CONTROL_PLANE_ISSUER_VERIFYING_KEYS_JSON_ENV,
        "{\"keys\":[]}",
    );
    parse_cloudflare_worker_bindings_v1(
        CloudflareWorkerRoleV1::TenantRootControlPlane,
        &CloudflareEnvMapV1::new(malformed),
    )
    .expect_err("empty published set");

    // The matching configuration parses.
    parse_cloudflare_worker_bindings_v1(
        CloudflareWorkerRoleV1::TenantRootControlPlane,
        &CloudflareEnvMapV1::new(entries),
    )
    .expect("published active issuer key id");
}

#[test]
fn control_plane_issuer_binding_must_be_control_plane_scoped_and_complete() {
    // Missing key ID.
    let err =
        parse_cloudflare_tenant_root_control_plane_bindings_v1(&CloudflareEnvMapV1::new(vec![(
            router_ab_cloudflare::TENANT_ROOT_CONTROL_PLANE_ISSUER_SIGNING_KEY_BINDING_ENV,
            "TENANT_ROOT_CONTROL_PLANE_ISSUER_SIGNING_KEY",
        )]))
        .expect_err("key id is required");
    assert_ne!(err.code(), RouterAbProtocolErrorCode::ForbiddenLocalBinding);

    // Missing binding name.
    parse_cloudflare_tenant_root_control_plane_bindings_v1(&CloudflareEnvMapV1::new(vec![(
        router_ab_cloudflare::TENANT_ROOT_CONTROL_PLANE_ISSUER_SIGNING_KEY_ID_ENV,
        "control-plane-issuer-v1",
    )]))
    .expect_err("binding name is required");

    // A binding name that is not control-plane scoped: an operator must not be
    // able to point the issuer at a Deriver's or Router's Secret.
    for foreign in [
        "DERIVER_A_TENANT_ROOT_CREATION_SIGNING_KEY",
        "ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET",
        "ISSUER_SIGNING_KEY",
    ] {
        let err = parse_cloudflare_tenant_root_control_plane_bindings_v1(&control_plane_env_with(
            router_ab_cloudflare::TENANT_ROOT_CONTROL_PLANE_ISSUER_SIGNING_KEY_BINDING_ENV,
            foreign,
        ))
        .expect_err("foreign binding name must be rejected");
        assert_eq!(
            err.code(),
            RouterAbProtocolErrorCode::ForbiddenLocalBinding,
            "{foreign}"
        );
    }
}

#[test]
fn every_verifier_worker_requires_the_published_issuer_anchor_at_boot() {
    // A signed creation command is verified at each Worker's own boundary, so a
    // missing or malformed anchor must fail the Worker at startup rather than
    // at first verification.
    for (worker_role, env) in [
        (CloudflareWorkerRoleV1::Router, router_env()),
        (CloudflareWorkerRoleV1::DeriverA, deriver_a_env()),
        (CloudflareWorkerRoleV1::DeriverB, deriver_b_env()),
    ] {
        parse_cloudflare_worker_bindings_v1(worker_role, &env)
            .expect("published anchor parses at boot");

        let without: Vec<(String, String)> = env
            .entries()
            .iter()
            .filter(|(key, _)| {
                key.as_str() != TENANT_ROOT_CONTROL_PLANE_ISSUER_VERIFYING_KEYS_JSON_ENV
            })
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        parse_cloudflare_worker_bindings_v1(worker_role, &CloudflareEnvMapV1::new(without.clone()))
            .expect_err("missing published anchor must fail closed");

        for malformed in [
            "",
            "{}",
            "not json",
            "{\"keys\":[]}",
            // Not a valid Ed25519 point.
            "{\"keys\":[{\"issuer_key_id\":\"k\",\"verifying_key_hex\":\"00000000000000000000000000000000000000000000000000000000000000ff\"}]}",
            // Duplicated issuer key id.
            "{\"keys\":[{\"issuer_key_id\":\"k\",\"verifying_key_hex\":\"0000000000000000000000000000000000000000000000000000000000000000\"},{\"issuer_key_id\":\"k\",\"verifying_key_hex\":\"0000000000000000000000000000000000000000000000000000000000000000\"}]}",
            // Unknown field: the wire denies them.
            "{\"keys\":[],\"extra\":1}",
        ] {
            let mut entries = without.clone();
            entries.push((
                TENANT_ROOT_CONTROL_PLANE_ISSUER_VERIFYING_KEYS_JSON_ENV.to_string(),
                malformed.to_string(),
            ));
            assert!(
                parse_cloudflare_worker_bindings_v1(worker_role, &CloudflareEnvMapV1::new(entries))
                    .is_err(),
                "{} must reject a malformed published anchor",
                worker_role.as_str()
            );
        }
    }
}
