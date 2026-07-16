#![forbid(unsafe_code)]
//! Service-level protocol types for Router/A/B signing.
//!
//! This module stays transport-neutral. Runtime adapters should parse boundary
//! inputs and call these typed APIs.

mod ecdsa_threshold_prf_request;
mod ed25519_yao;
mod engine;
mod envelope;
mod error;
mod gate;
mod identity;
mod lifecycle;
mod local;
mod normal_signing;
mod output;
mod payload;
mod router_ab_ecdsa_derivation;
mod signer_input;
mod vectors;
mod wire;

pub use self::ecdsa_threshold_prf_request::{
    EcdsaThresholdPrfRequestContextV1, EcdsaThresholdPrfRequestV1,
    EcdsaThresholdPrfRequestVersionV1,
};
pub use self::ed25519_yao::{
    Ed25519YaoCeremonyBindingV1, Ed25519YaoCircuitFamilyV1, Ed25519YaoDeriverRoleV1,
    Ed25519YaoEncryptedInputV1, Ed25519YaoEncryptedPackageV1, Ed25519YaoEpochTransitionV1,
    Ed25519YaoInputKindV1, Ed25519YaoOperationV1, Ed25519YaoPackageKindV1,
    Ed25519YaoRefreshBindingV1, Ed25519YaoRefreshEpochsV1, Ed25519YaoSessionIdV1,
    Ed25519YaoStableKeyContextBindingV1, Ed25519YaoStateEpochV1,
    RouterAbEd25519YaoActivationAdmissionReceiptV1, RouterAbEd25519YaoActivationExecuteRequestV1,
    RouterAbEd25519YaoActivationKeysetV1, RouterAbEd25519YaoActivationPublicReceiptV1,
    RouterAbEd25519YaoActivationResultV1, RouterAbEd25519YaoApplicationBindingFactsV1,
    RouterAbEd25519YaoExportAdmissionReceiptV1, RouterAbEd25519YaoExportAdmissionRequestV1,
    RouterAbEd25519YaoExportAuthorizationV1, RouterAbEd25519YaoExportBindingV1,
    RouterAbEd25519YaoExportExecuteRequestV1, RouterAbEd25519YaoExportResultV1,
    RouterAbEd25519YaoLifecycleScopeV1, RouterAbEd25519YaoRegistrationAdmissionRequestV1,
    ED25519_YAO_CONTROL_CIPHERTEXT_MAX_BYTES_V1, ROUTER_AB_ED25519_YAO_EXPORT_ADMISSION_PATH_V1,
    ROUTER_AB_ED25519_YAO_EXPORT_EXECUTE_PATH_V1,
    ROUTER_AB_ED25519_YAO_REGISTRATION_ADMISSION_PATH_V1,
    ROUTER_AB_ED25519_YAO_REGISTRATION_EXECUTE_PATH_V1,
};
pub use self::engine::{
    AuditEventV1, AuditSink, Clock, Csprng, DeriverAEngine, DeriverBEngine, PeerTransport,
    RouterAbEcdsaDerivationExplicitExportAuditDecisionV1, SignerKeyStore, SigningRootShareStore,
};
pub use self::envelope::{
    decode_and_validate_signer_envelope_hpke_payload_v1, decode_signer_envelope_hpke_payload_v1,
    encode_role_envelope_aad_v1, encode_signer_envelope_hpke_payload_v1,
    role_encrypted_envelope_digest_v1, role_envelope_aad_digest_v1, EncryptedPayloadV1,
    RoleEncryptedEnvelopeV1, RoleEnvelopeAadV1, SignerEnvelopeHpkePayloadV1,
    SIGNER_ENVELOPE_HPKE_ENCAPPED_KEY_LEN_V1, SIGNER_ENVELOPE_HPKE_TAG_LEN_V1,
};
pub use self::error::{RouterAbProtocolError, RouterAbProtocolErrorCode, RouterAbProtocolResult};
pub use self::gate::{
    ExpensiveWorkGateContextV1, ExpensiveWorkGateDecisionV1, ExpensiveWorkKindV1,
    GateDeferReasonV1, GatePrincipalV1, GateRejectReasonV1, RegistrationPrepareHandleV1,
};
pub use self::identity::{
    RoleEnvelopeAssignmentV1, ServerIdentityV1, SignerIdentityV1, SignerSetPolicyV1, SignerSetV1,
};
pub use self::lifecycle::{
    AuthorityVerifiedFallbackReasonV1, LifecycleScopeV1, NormalSigningScopeV1,
    RouterAbLifecycleStateV1,
};
pub use self::local::{
    execute_local_persistence_sql_seed_plan_v1, local_persistence_seed_sql_plan_v1,
    validate_local_env_keys_v1, LocalClientRouterRequestV1, LocalDeriverAEndpointV1,
    LocalDeriverAServiceV1, LocalDeriverBEndpointV1, LocalDeriverBServiceV1,
    LocalDeterministicSignerEnvelopeDecryptorV1, LocalEnvSnapshotV1, LocalHttpCeremonyResultV1,
    LocalHttpMethodV1, LocalHttpPathV1, LocalHttpRequestV1, LocalInProcessCeremonyResultV1,
    LocalPersistenceSeedV1, LocalPersistenceSqlExecutionReceiptV1,
    LocalPersistenceSqlSeedExecutorV1, LocalPersistenceSqlSeedPlanV1,
    LocalPersistenceSqlStatementV1, LocalPersistenceSqlValueV1, LocalReplayCacheV1,
    LocalRouterDispatchV1, LocalRouterEndpointV1, LocalRouterRecipientProofBundleResponseV1,
    LocalRouterServiceV1, LocalSealedRootShareRecordV1, LocalServiceEndpointV1, LocalServiceRoleV1,
    LocalServiceStackV1, LocalServiceStartupV1, LocalSignerEnvelopeDecryptorV1,
    LocalSignerHandlerContextV1, LocalSignerHandlerOutputV1,
    LocalSignerRecipientProofBundleResponseV1, LocalSigningRootMetadataV1,
    LocalSigningWorkerActivationReceiptV1, LocalSigningWorkerEndpointV1,
    LocalSigningWorkerRecipientProofBundleActivationV1, LocalSigningWorkerServiceV1,
    LocalTransportEnvelopeV1, LocalTransportRouteV1,
};
pub use self::normal_signing::{
    derive_router_ab_ed25519_normal_signing_admission_material_v2,
    parse_router_ab_ed25519_normal_signing_finalize_request_v2_json,
    parse_router_ab_ed25519_normal_signing_prepare_request_v2_json,
    parse_router_ab_ed25519_presign_pool_hit_finalize_request_v2_json,
    parse_router_ab_ed25519_presign_pool_prepare_request_v2_json,
    parse_router_ab_ed25519_presign_pool_prepare_response_v2_json,
    router_ab_delegate_action_fingerprint_from_canonical_borsh_b64u_v2,
    router_ab_ed25519_nep413_canonical_message_b64u_v2,
    router_ab_near_transaction_action_fingerprint_from_unsigned_borsh_b64u_v2,
    ActiveSigningWorkerStateV1, NormalSigningEd25519TwoPartyFrostCommitmentsV1,
    NormalSigningEd25519TwoPartyFrostFinalizeV1, NormalSigningProtocolV1, NormalSigningResponseV1,
    NormalSigningRound1PrepareResponseV1, NormalSigningSignatureSchemeV1,
    RouterAbEd25519NormalSigningAdmissionMaterialV2,
    RouterAbEd25519NormalSigningFinalizeProtocolV2, RouterAbEd25519NormalSigningFinalizeRequestV2,
    RouterAbEd25519NormalSigningIntentV2, RouterAbEd25519NormalSigningPrepareBindingV2,
    RouterAbEd25519NormalSigningPrepareRequestV2, RouterAbEd25519PresignPoolAcceptedEntryV2,
    RouterAbEd25519PresignPoolClientOfferV2, RouterAbEd25519PresignPoolHitBindingV2,
    RouterAbEd25519PresignPoolHitFinalizeRequestV2, RouterAbEd25519PresignPoolPrepareRequestV2,
    RouterAbEd25519PresignPoolPrepareResponseV2, RouterAbEd25519SigningPayloadV2,
    RouterAbEd25519TwoPartyFrostFinalizeProtocolV2, RouterAbNearDelegateActionIntentV1,
    RouterAbNearNetworkIdV2, RouterAbNearTransactionIntentV1,
};
pub use self::output::{
    combine_mpc_prf_recipient_output_from_ab_proof_batches_v1,
    combine_mpc_prf_recipient_output_from_proof_bundle_payloads_v1,
    combine_mpc_prf_signing_worker_output_from_activation_context_v1,
    decode_recipient_output_ciphertext_v1, decode_recipient_proof_bundle_ciphertext_v1,
    ecdsa_threshold_prf_proof_batch_recipient_view_v1, encode_recipient_output_ciphertext_aad_v1,
    encode_recipient_output_ciphertext_v1, encode_recipient_proof_bundle_ciphertext_aad_v1,
    encode_recipient_proof_bundle_ciphertext_v1, encrypt_recipient_proof_bundle_payload_v1,
    mpc_prf_batch_output_from_ab_proof_batch_v1, recipient_output_ciphertext_aad_digest_v1,
    recipient_proof_bundle_ciphertext_aad_digest_v1, recipient_proof_bundle_ciphertext_digest_v1,
    recipient_proof_bundle_payload_from_ab_proof_batch_v1,
    recipient_proof_bundle_wire_message_from_ab_proof_batch_v1,
    verify_recipient_proof_bundle_ciphertext_payload_v1, RecipientOutputCiphertextV1,
    RecipientOutputEncryptionAlgorithmV1, RecipientOutputEncryptionRequestV1,
    RecipientOutputEncryptorV1, RecipientProofBundleCiphertextV1,
    RecipientProofBundleEncryptionRequestV1, RecipientProofBundleEncryptorV1,
    RECIPIENT_OUTPUT_CIPHERTEXT_NONCE_LEN_V1,
};
pub use self::payload::{
    ab_peer_message_authentication_input_digest_v1, ab_peer_message_payload_digest_v1,
    build_mpc_prf_signer_partial_input_v1, decode_ab_peer_message_payload_v1,
    decode_and_validate_ecdsa_threshold_prf_proof_batch_peer_payload_v1,
    decode_ecdsa_threshold_prf_proof_batch_payload_v1, decode_recipient_proof_bundle_payload_v1,
    decode_router_to_signer_payload_v1, ecdsa_threshold_prf_proof_batch_payload_digest_v1,
    encode_ab_peer_message_authentication_input_v1, encode_ab_peer_message_payload_v1,
    encode_ecdsa_threshold_prf_proof_batch_payload_v1, encode_recipient_proof_bundle_payload_v1,
    encode_router_to_signer_payload_v1, recipient_proof_bundle_payload_digest_v1,
    router_to_signer_payload_digest_v1, router_transcript_binding_v1, router_transcript_digest_v1,
    sign_ab_peer_message_ed25519_authentication_v1,
    sign_ecdsa_threshold_prf_proof_batch_peer_payload_v1,
    validate_signer_input_plaintext_binding_v1, verify_ab_peer_message_ed25519_signature_v1,
    AbPeerMessageAuthenticationV1, AbPeerMessagePayloadV1, AbPeerMessageSignatureSchemeV1,
    AbPeerMessageVerifyingKeyV1, EcdsaThresholdPrfProofBatchPayloadV1,
    RecipientProofBundlePayloadV1, RouterEnvelopeDigestSetV1, RouterToSignerPayloadV1,
    RouterTranscriptMetadataV1, SigningWorkerActivationContextV1,
};
pub use self::router_ab_ecdsa_derivation::{
    parse_router_ab_ecdsa_derivation_activation_refresh_request_v1_json,
    parse_router_ab_ecdsa_derivation_deriver_envelope_plaintext_v1_json,
    parse_router_ab_ecdsa_derivation_evm_digest_signing_finalize_request_v1_json,
    parse_router_ab_ecdsa_derivation_evm_digest_signing_prepare_response_v1_json,
    parse_router_ab_ecdsa_derivation_evm_digest_signing_request_v1_json,
    parse_router_ab_ecdsa_derivation_explicit_export_request_v1_json,
    parse_router_ab_ecdsa_derivation_normal_signing_scope_v1_json,
    parse_router_ab_ecdsa_derivation_recovery_request_v1_json,
    parse_router_ab_ecdsa_derivation_registration_bootstrap_request_v1_json,
    router_ab_ecdsa_derivation_active_state_session_id_v1,
    RouterAbEcdsaDerivationActivationReceiptV1, RouterAbEcdsaDerivationActivationRefreshRequestV1,
    RouterAbEcdsaDerivationDeriverEnvelopeCommonV1,
    RouterAbEcdsaDerivationDeriverEnvelopePlaintextV1,
    RouterAbEcdsaDerivationDeriverExportEnvelopePlaintextV1,
    RouterAbEcdsaDerivationDeriverRecoveryEnvelopePlaintextV1,
    RouterAbEcdsaDerivationDeriverRefreshEnvelopePlaintextV1,
    RouterAbEcdsaDerivationDeriverRegistrationEnvelopePlaintextV1,
    RouterAbEcdsaDerivationEvmDigestSigningFinalizeRequestV1,
    RouterAbEcdsaDerivationEvmDigestSigningPrepareResponseV1,
    RouterAbEcdsaDerivationEvmDigestSigningRequestV1,
    RouterAbEcdsaDerivationEvmDigestSigningResponseV1,
    RouterAbEcdsaDerivationExplicitExportRequestV1, RouterAbEcdsaDerivationNormalSigningScopeV1,
    RouterAbEcdsaDerivationOutputKindV1, RouterAbEcdsaDerivationPublicIdentityV1,
    RouterAbEcdsaDerivationRecoveryRequestV1,
    RouterAbEcdsaDerivationRegistrationBootstrapRequestV1,
    RouterAbEcdsaDerivationRegistrationHeaderV1, RouterAbEcdsaDerivationRegistrationPurposeV1,
    RouterAbEcdsaDerivationRequestKindV1, RouterAbEcdsaDerivationSignatureSchemeV1,
    RouterAbEcdsaDerivationStableKeyContextV1, ROUTER_AB_ECDSA_DERIVATION_KEY_SCOPE_V1,
    ROUTER_AB_ECDSA_DERIVATION_PROTOCOL_VERSION_V1,
};
pub use self::signer_input::build_mpc_prf_threshold_signer_batch_input_v1;
pub use self::vectors::{
    generated_normal_signing_vector_fixture_json_v2, generated_normal_signing_vector_fixture_v2,
    generated_payload_vector_fixture_json_v1, generated_payload_vector_fixture_v1,
    generated_wire_vector_fixture_json_v1, generated_wire_vector_fixture_v1,
    parse_normal_signing_vector_fixture_v2, parse_payload_vector_fixture_v1,
    parse_wire_vector_fixture_v1, validate_normal_signing_vector_fixture_v2,
    validate_payload_vector_fixture_v1, validate_wire_vector_fixture_v1, NormalSigningVectorCaseV2,
    NormalSigningVectorFixtureV2, PayloadVectorCaseV1, PayloadVectorFixtureV1,
    WireMessageVectorCaseV1, WireVectorFixtureV1, NORMAL_SIGNING_VECTOR_FIXTURE_VERSION_V2,
    PAYLOAD_VECTOR_FIXTURE_VERSION_V1, WIRE_VECTOR_FIXTURE_VERSION_V1,
};
pub use self::wire::{
    encode_wire_message_v1, wire_message_digest_v1, CanonicalWireBytesV1, WireMessageKindV1,
    WireMessageV1,
};
