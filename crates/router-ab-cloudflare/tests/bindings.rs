use ed25519_dalek::{Signer, SigningKey};
use router_ab_cloudflare::{
    build_cloudflare_ab_derivation_proof_batch_peer_message_v1,
    build_cloudflare_preloaded_signer_host_v1,
    build_cloudflare_preloaded_signer_host_with_root_share_wire_v1,
    cloudflare_recipient_proof_bundle_response_from_ab_proof_batch_v1,
    cloudflare_signer_response_from_mpc_prf_packages_v1,
    combine_cloudflare_mpc_prf_output_packages_from_peer_messages_v1,
    decode_and_validate_cloudflare_root_share_wire_secret_v1,
    decode_and_validate_cloudflare_signer_envelope_aead_payload_v1,
    decode_and_validate_cloudflare_signer_envelope_hpke_payload_v1,
    decode_and_validate_cloudflare_signer_input_plaintext_v1,
    decode_and_verify_cloudflare_ab_derivation_proof_batch_message_v1,
    decode_cloudflare_peer_verifying_key_hex_v1, decode_cloudflare_root_share_wire_secret_v1,
    derive_cloudflare_router_trusted_admission_from_provider_v1,
    derive_cloudflare_router_trusted_admission_v1,
    evaluate_cloudflare_validated_mpc_prf_batch_output_v1,
    execute_cloudflare_router_public_admission_plan_v1, handle_cloudflare_durable_object_call_v1,
    handle_cloudflare_signer_a_recipient_proof_bundle_activation_request_v1,
    handle_cloudflare_signer_peer_request_v1, handle_cloudflare_signer_private_request_v1,
    handle_cloudflare_signer_recipient_proof_bundle_private_request_v1,
    handle_cloudflare_validated_mpc_prf_recipient_proof_bundle_signer_request_v1,
    handle_cloudflare_validated_mpc_prf_signer_request_v1,
    handle_cloudflare_validated_signer_private_request_v1,
    parse_cloudflare_router_admission_bindings_v1, parse_cloudflare_signer_a_relayer_bindings_v1,
    parse_cloudflare_signer_b_bindings_v1,
    parse_cloudflare_signer_envelope_hpke_decrypt_key_binding_v1,
    parse_cloudflare_signer_envelope_hpke_public_key_set_v1, parse_cloudflare_worker_bindings_v1,
    validate_cloudflare_peer_signing_key_matches_request_v1,
    validate_cloudflare_signer_peer_request_v1, validate_cloudflare_signer_peer_response_v1,
    validate_cloudflare_signer_private_request_plaintext_v1,
    validate_cloudflare_signer_private_request_v1, validate_cloudflare_signer_private_response_v1,
    validate_cloudflare_signer_recipient_proof_bundle_private_response_v1,
    verify_cloudflare_signer_peer_message_authentication_v1, CloudflareDurableObjectBindingV1,
    CloudflareDurableObjectCallV1, CloudflareDurableObjectMemoryStorageV1,
    CloudflareDurableObjectOperationKindV1, CloudflareDurableObjectRequestV1,
    CloudflareDurableObjectResponseV1, CloudflareDurableObjectScopeV1, CloudflareEnvMapV1,
    CloudflareLifecyclePutReceiptV1, CloudflarePeerBindingV1, CloudflarePreloadedSignerHostV1,
    CloudflareRelayerOutputActivationReceiptV1,
    CloudflareRelayerRecipientProofBundleActivationRequestV1,
    CloudflareRelayerRecipientProofBundleActivationV1, CloudflareReplayReserveRequestV1,
    CloudflareReplayReserveResponseV1, CloudflareRootShareLookupRequestV1,
    CloudflareRootShareStartupMetadataV1, CloudflareRootShareWireSecretBindingV1,
    CloudflareRouterAbuseCheckV1, CloudflareRouterAbuseStoreV1, CloudflareRouterAdmissionChecksV1,
    CloudflareRouterAdmissionProviderOutputV1, CloudflareRouterAdmissionProviderV1,
    CloudflareRouterAllowedWorkKindsProjectPolicyProviderV1, CloudflareRouterAuthContextV1,
    CloudflareRouterBearerAuthorizationV1, CloudflareRouterBindingsV1,
    CloudflareRouterCompositeAdmissionProviderV1, CloudflareRouterConfiguredAbuseProviderV1,
    CloudflareRouterConfiguredQuotaProviderV1, CloudflareRouterJwtSessionProviderV1,
    CloudflareRouterJwtVerifierBindingV1, CloudflareRouterJwtVerifierV1,
    CloudflareRouterProjectPolicyStoreV1, CloudflareRouterProjectPolicyV1,
    CloudflareRouterPublicAdmissionPlanV1, CloudflareRouterPublicAdmissionResponseV1,
    CloudflareRouterPublicPlanExecutorV1, CloudflareRouterPublicResponseV1,
    CloudflareRouterQuotaCheckV1, CloudflareRouterQuotaStoreV1,
    CloudflareRouterRecipientProofBundleAdmissionResponseV1,
    CloudflareRouterRecipientProofBundleResponseV1, CloudflareRouterStoredAbuseProviderV1,
    CloudflareRouterStoredProjectPolicyProviderV1, CloudflareRouterStoredQuotaProviderV1,
    CloudflareRouterTrustedAdmissionV1, CloudflareRouterTrustedRequestMetadataV1,
    CloudflareRouterVerifiedJwtClaimsV1, CloudflareRouterVerifiedSessionProviderV1,
    CloudflareRouterVerifiedSessionV1, CloudflareRouterWorkerRuntimeV1,
    CloudflareSignerARelayerBindingsV1, CloudflareSignerARelayerWorkerRuntimeV1,
    CloudflareSignerBBindingsV1, CloudflareSignerBWorkerRuntimeV1,
    CloudflareSignerEnvelopeDecryptKeyBindingV1,
    CloudflareSignerEnvelopeHpkeDecryptKeyBindingV1, CloudflareSignerEnvelopeHpkePublicKeyV1,
    CloudflareSignerEnvelopeHpkePublicKeySetV1, CloudflareSignerHostPeerPreloadInputV1,
    CloudflareSignerHostPreloadInputV1, CloudflareSignerHostPreloadPlanV1,
    CloudflareSignerPeerSigningKeyBindingV1, CloudflareSignerPeerVerifyingKeyBytesV1,
    CloudflareSignerPeerVerifyingKeySetV1, CloudflareSignerPrivateBootstrapRequestV1,
    CloudflareSignerRecipientProofBundleResponseV1,
    CloudflareSignerRecipientProofBundleWireHandlerV1, CloudflareSignerStartupCheckV1,
    CloudflareSignerWireHandlerV1, CloudflareValidatedSignerInputHandlerV1,
    CloudflareValidatedSignerPrivateRequestV1, CloudflareWorkerBindingsV1, CloudflareWorkerRoleV1,
    CLOUDFLARE_ROOT_SHARE_WIRE_SECRET_PREFIX_V1, ROUTER_ABUSE_DO_BINDING_ENV,
    ROUTER_ABUSE_DO_KEY_PREFIX_ENV, ROUTER_ABUSE_DO_OBJECT_ENV, ROUTER_JWT_AUDIENCE_ENV,
    ROUTER_JWT_ISSUER_ENV, ROUTER_JWT_JWKS_URL_ENV, ROUTER_LIFECYCLE_DO_BINDING_ENV,
    ROUTER_LIFECYCLE_DO_KEY_PREFIX_ENV, ROUTER_LIFECYCLE_DO_OBJECT_ENV,
    ROUTER_PROJECT_POLICY_DO_BINDING_ENV, ROUTER_PROJECT_POLICY_DO_KEY_PREFIX_ENV,
    ROUTER_PROJECT_POLICY_DO_OBJECT_ENV, ROUTER_QUOTA_DO_BINDING_ENV,
    ROUTER_QUOTA_DO_KEY_PREFIX_ENV, ROUTER_QUOTA_DO_OBJECT_ENV, ROUTER_REPLAY_DO_BINDING_ENV,
    ROUTER_REPLAY_DO_KEY_PREFIX_ENV, ROUTER_REPLAY_DO_OBJECT_ENV,
    SIGNER_A_ENVELOPE_AEAD_KEY_BINDING_ENV, SIGNER_A_ENVELOPE_AEAD_KEY_EPOCH_ENV,
    SIGNER_A_ENVELOPE_HPKE_KEY_EPOCH_ENV, SIGNER_A_ENVELOPE_HPKE_PRIVATE_KEY_BINDING_ENV,
    SIGNER_A_ENVELOPE_HPKE_PUBLIC_KEY_ENV, SIGNER_A_PEER_BINDING_ENV,
    SIGNER_A_PEER_SIGNING_KEY_BINDING_ENV, SIGNER_A_PEER_SIGNING_KEY_EPOCH_ENV,
    SIGNER_A_PEER_VERIFYING_KEY_HEX_ENV,
    SIGNER_A_RELAYER_OUTPUT_DO_BINDING_ENV, SIGNER_A_RELAYER_OUTPUT_DO_KEY_PREFIX_ENV,
    SIGNER_A_RELAYER_OUTPUT_DO_OBJECT_ENV, SIGNER_A_ROOT_SHARE_DO_BINDING_ENV,
    SIGNER_A_ROOT_SHARE_DO_KEY_PREFIX_ENV, SIGNER_A_ROOT_SHARE_DO_OBJECT_ENV,
    SIGNER_A_ROOT_SHARE_WIRE_SECRET_BINDING_ENV, SIGNER_B_ENVELOPE_AEAD_KEY_BINDING_ENV,
    SIGNER_B_ENVELOPE_AEAD_KEY_EPOCH_ENV, SIGNER_B_ENVELOPE_HPKE_KEY_EPOCH_ENV,
    SIGNER_B_ENVELOPE_HPKE_PRIVATE_KEY_BINDING_ENV, SIGNER_B_ENVELOPE_HPKE_PUBLIC_KEY_ENV,
    SIGNER_B_PEER_BINDING_ENV, SIGNER_B_PEER_SIGNING_KEY_BINDING_ENV,
    SIGNER_B_PEER_SIGNING_KEY_EPOCH_ENV, SIGNER_B_PEER_VERIFYING_KEY_HEX_ENV,
    SIGNER_B_ROOT_SHARE_DO_BINDING_ENV,
    SIGNER_B_ROOT_SHARE_DO_KEY_PREFIX_ENV, SIGNER_B_ROOT_SHARE_DO_OBJECT_ENV,
    SIGNER_B_ROOT_SHARE_WIRE_SECRET_BINDING_ENV,
};
use router_ab_core::{
    ab_peer_message_authentication_input_digest_v1, decode_recipient_proof_bundle_ciphertext_v1,
    decode_signer_response_payload_v1, encode_ab_peer_message_authentication_input_v1,
    AbPeerMessageAuthenticationV1, AbPeerMessagePayloadV1, AbPeerMessageSignatureSchemeV1,
    AbPeerMessageVerifyingKeyV1, CanonicalWireBytesV1, Clock, CorrectnessLevel, Csprng,
    EncryptedPayloadV1, ExpensiveWorkGateContextV1, ExpensiveWorkGateDecisionV1,
    ExpensiveWorkKindV1, GateDeferReasonV1, GatePrincipalV1, GateRejectReasonV1, LifecycleScopeV1,
    MpcPrfOutputRequestV1, MpcPrfSigningRootShareWireV1, MpcPrfSuiteId, OpenedShareKind,
    PeerTransport, PublicRouterRequestV1, RecipientOutputCiphertextV1,
    RecipientOutputEncryptionAlgorithmV1, RecipientOutputEncryptionRequestV1,
    RecipientOutputEncryptorV1, RecipientProofBundleCiphertextV1,
    RecipientProofBundleEncryptionRequestV1, RecipientProofBundleEncryptorV1,
    RelayerActivationPayloadV1, RelayerIdentityV1, RelayerOutputPackageV1, RoleEncryptedEnvelopeV1,
    RoleEnvelopeAadV1, RouterAbLifecycleStateV1, RouterAbProtocolErrorCode, RouterAbProtocolResult,
    RouterTranscriptMetadataV1, SignerAEngine, SignerEnvelopeAeadPayloadV1,
    SignerEnvelopeHpkePayloadV1, SignerIdentityV1, SignerInputPlaintextV1,
    SignerInputQuorumPolicyV1, SignerKeyStore, SignerSetV1, SigningRootShareStore,
    WireMessageKindV1, WireMessageV1, SIGNER_ENVELOPE_HPKE_ENCAPPED_KEY_LEN_V1,
    SIGNER_ENVELOPE_HPKE_TAG_LEN_V1,
};
use router_ab_core::{
    router_transcript_digest_v1, CandidateId, PublicDigest32, RequestKind, Role, RootShareEpoch,
};

fn root_epoch() -> RootShareEpoch {
    RootShareEpoch::new("epoch-1").expect("root epoch")
}

fn root_share_wire(role: Role) -> MpcPrfSigningRootShareWireV1 {
    let share_id = match role {
        Role::SignerA => 1u8,
        Role::SignerB => 3u8,
        _ => panic!("test root share wire requires signer role"),
    };
    let mut bytes = vec![0u8; 33];
    bytes[0] = share_id;
    bytes[1] = share_id.wrapping_mul(11);
    MpcPrfSigningRootShareWireV1::new(bytes).expect("root share wire")
}

fn digest(byte: u8) -> PublicDigest32 {
    PublicDigest32::new([byte; 32])
}

fn request_context_digest(request: &PublicRouterRequestV1) -> PublicDigest32 {
    request
        .request_context_digest()
        .expect("request context digest")
}

fn role_envelope_aad_for_request(role: Role, request: &PublicRouterRequestV1) -> RoleEnvelopeAadV1 {
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
        payload.signer_set().selected_relayer.clone(),
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

fn signer_a_root_binding() -> CloudflareDurableObjectBindingV1 {
    do_binding(
        CloudflareDurableObjectScopeV1::signer_root_share(Role::SignerA).expect("signer a scope"),
        "SIGNER_A_ROOT_SHARE_DO",
    )
}

fn signer_b_root_binding() -> CloudflareDurableObjectBindingV1 {
    do_binding(
        CloudflareDurableObjectScopeV1::signer_root_share(Role::SignerB).expect("signer b scope"),
        "SIGNER_B_ROOT_SHARE_DO",
    )
}

fn signer_a_root_share_wire_secret_binding() -> CloudflareRootShareWireSecretBindingV1 {
    CloudflareRootShareWireSecretBindingV1::new(Role::SignerA, "SIGNER_A_ROOT_SHARE_WIRE_SECRET")
        .expect("signer a root-share wire secret binding")
}

fn signer_b_root_share_wire_secret_binding() -> CloudflareRootShareWireSecretBindingV1 {
    CloudflareRootShareWireSecretBindingV1::new(Role::SignerB, "SIGNER_B_ROOT_SHARE_WIRE_SECRET")
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

fn relayer_output_binding() -> CloudflareDurableObjectBindingV1 {
    do_binding(
        CloudflareDurableObjectScopeV1::signer_a_relayer_output(),
        "SIGNER_A_RELAYER_OUTPUT_DO",
    )
}

fn signer_a_envelope_decrypt_key() -> CloudflareSignerEnvelopeDecryptKeyBindingV1 {
    CloudflareSignerEnvelopeDecryptKeyBindingV1::new(
        Role::SignerA,
        "SIGNER_A_ENVELOPE_AEAD_KEY",
        "envelope-key-epoch-a",
    )
    .expect("signer a envelope decrypt key")
}

fn signer_b_envelope_decrypt_key() -> CloudflareSignerEnvelopeDecryptKeyBindingV1 {
    CloudflareSignerEnvelopeDecryptKeyBindingV1::new(
        Role::SignerB,
        "SIGNER_B_ENVELOPE_AEAD_KEY",
        "envelope-key-epoch-b",
    )
    .expect("signer b envelope decrypt key")
}

fn signer_a_envelope_hpke_decrypt_key() -> CloudflareSignerEnvelopeHpkeDecryptKeyBindingV1 {
    CloudflareSignerEnvelopeHpkeDecryptKeyBindingV1::new(
        Role::SignerA,
        "SIGNER_A_ENVELOPE_HPKE_PRIVATE_KEY",
        "envelope-hpke-key-epoch-a",
        x25519_public_key(0x11),
    )
    .expect("signer a hpke envelope decrypt key")
}

fn signer_b_envelope_hpke_decrypt_key() -> CloudflareSignerEnvelopeHpkeDecryptKeyBindingV1 {
    CloudflareSignerEnvelopeHpkeDecryptKeyBindingV1::new(
        Role::SignerB,
        "SIGNER_B_ENVELOPE_HPKE_PRIVATE_KEY",
        "envelope-hpke-key-epoch-b",
        x25519_public_key(0x22),
    )
    .expect("signer b hpke envelope decrypt key")
}

fn signer_a_peer_signing_key() -> CloudflareSignerPeerSigningKeyBindingV1 {
    CloudflareSignerPeerSigningKeyBindingV1::new(
        Role::SignerA,
        "SIGNER_A_PEER_SIGNING_KEY",
        "key-epoch-a",
    )
    .expect("signer a peer signing key")
}

fn signer_b_peer_signing_key() -> CloudflareSignerPeerSigningKeyBindingV1 {
    CloudflareSignerPeerSigningKeyBindingV1::new(
        Role::SignerB,
        "SIGNER_B_PEER_SIGNING_KEY",
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
            peer(CloudflareWorkerRoleV1::SignerARelayer, "SIGNER_A"),
            peer(CloudflareWorkerRoleV1::SignerB, "SIGNER_B"),
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
            "relayer-a",
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
        RelayerIdentityV1::new(
            "relayer-a",
            "relayer-epoch",
            "x25519:1111111111111111111111111111111111111111111111111111111111111111",
        )
        .expect("relayer"),
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
    router_transcript_digest_v1(
        lifecycle,
        signer_set,
        &transcript_metadata(),
        CandidateId::MpcThresholdPrfV1,
        CorrectnessLevel::MinimumLevelC,
        root_epoch(),
    )
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
        _request: &PublicRouterRequestV1,
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
        request: &PublicRouterRequestV1,
        trusted_source_digest: PublicDigest32,
    ) -> RouterAbProtocolResult<CloudflareRouterVerifiedJwtClaimsV1> {
        verifier.validate()?;
        authorization.validate()?;
        request.validate()?;
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
        request: &PublicRouterRequestV1,
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
        request: &PublicRouterRequestV1,
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
        request: &PublicRouterRequestV1,
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

fn signer_envelope_aead_payload(
    role: Role,
    key_epoch: &str,
    aad_digest: PublicDigest32,
) -> SignerEnvelopeAeadPayloadV1 {
    let nonce_seed = match role {
        Role::SignerA => 0xa1,
        Role::SignerB => 0xb1,
        _ => panic!("test helper requires signer role"),
    };
    SignerEnvelopeAeadPayloadV1::new(
        role,
        key_epoch,
        aad_digest,
        [nonce_seed; 12],
        vec![
            0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd,
            0xce, 0xcf, 0xd0, 0xd1,
        ],
    )
    .expect("signer envelope AEAD payload")
}

fn role_aead_envelope(role: Role, seed: u8, key_epoch: &str) -> RoleEncryptedEnvelopeV1 {
    let aad_digest = digest(seed + 1);
    let aead = signer_envelope_aead_payload(role, key_epoch, aad_digest);
    RoleEncryptedEnvelopeV1::new(
        role,
        digest(seed),
        aad_digest,
        EncryptedPayloadV1::new(aead.canonical_bytes()).expect("AEAD payload bytes"),
    )
    .expect("role AEAD envelope")
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

fn signer_response(transcript_digest: PublicDigest32, seed: u8) -> WireMessageV1 {
    WireMessageV1::new(
        WireMessageKindV1::SignerResponse,
        transcript_digest,
        CanonicalWireBytesV1::new(vec![seed, seed + 1]).expect("signer response bytes"),
    )
    .expect("signer response")
}

struct TestRecipientOutputEncryptor;

impl RecipientOutputEncryptorV1 for TestRecipientOutputEncryptor {
    fn encrypt_recipient_output_v1(
        &mut self,
        request: RecipientOutputEncryptionRequestV1<'_>,
    ) -> router_ab_core::RouterAbProtocolResult<RecipientOutputCiphertextV1> {
        request.validate()?;
        let mut ciphertext = Vec::new();
        ciphertext.extend_from_slice(request.transcript_digest().as_bytes());
        ciphertext.extend_from_slice(request.package_commitment().as_bytes());
        ciphertext.extend_from_slice(request.plaintext().as_bytes());
        RecipientOutputCiphertextV1::new(
            RecipientOutputEncryptionAlgorithmV1::LocalDeterministicSha256V1,
            request.recipient_role(),
            request.opened_share_kind(),
            request.recipient_identity(),
            request.recipient_encryption_key(),
            request.transcript_digest(),
            request.package_commitment(),
            [0x42; 12],
            EncryptedPayloadV1::new(ciphertext)?,
        )
    }
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
            public_router_request(2_000)
                .to_signer_wire_messages()
                .expect("signer wire messages")
                .0
        }
        WireMessageKindV1::RouterToSignerB => {
            public_router_request(2_000)
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

fn public_router_request_with_aead_envelopes(expires_at_ms: u64) -> PublicRouterRequestV1 {
    let lifecycle = lifecycle_scope();
    let signer_set = signer_set();
    let transcript_digest = public_request_transcript_digest(&lifecycle, &signer_set);
    PublicRouterRequestV1::new(
        "request-nonce-1",
        expires_at_ms,
        lifecycle,
        CandidateId::MpcThresholdPrfV1,
        signer_set,
        "near-mainnet",
        "ed25519:account-public-key",
        "router-1",
        "client-1",
        "x25519:client-ephemeral-public-key",
        transcript_digest,
        role_aead_envelope(Role::SignerA, 0x10, "envelope-key-epoch-a"),
        role_aead_envelope(Role::SignerB, 0x20, "envelope-key-epoch-b"),
    )
    .expect("public router request with AEAD envelopes")
}

fn public_router_request_with_hpke_envelopes(expires_at_ms: u64) -> PublicRouterRequestV1 {
    let lifecycle = lifecycle_scope();
    let signer_set = signer_set();
    let transcript_digest = public_request_transcript_digest(&lifecycle, &signer_set);
    PublicRouterRequestV1::new(
        "request-nonce-1",
        expires_at_ms,
        lifecycle,
        CandidateId::MpcThresholdPrfV1,
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

fn public_router_request_with_aad_bound_envelopes(expires_at_ms: u64) -> PublicRouterRequestV1 {
    let base = public_router_request(expires_at_ms);
    let aad_a = role_envelope_aad_for_request(Role::SignerA, &base);
    let aad_b = role_envelope_aad_for_request(Role::SignerB, &base);
    PublicRouterRequestV1::new(
        base.request_nonce,
        base.expires_at_ms,
        base.lifecycle,
        base.required_derivation_candidate,
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

fn public_router_request_with_reconstructed_transcript(
    expires_at_ms: u64,
) -> PublicRouterRequestV1 {
    public_router_request(expires_at_ms)
}

fn signer_private_request_with_reconstructed_transcript(kind: WireMessageKindV1) -> WireMessageV1 {
    match kind {
        WireMessageKindV1::RouterToSignerA => {
            public_router_request_with_reconstructed_transcript(2_000)
                .to_signer_wire_messages()
                .expect("signer wire messages")
                .0
        }
        WireMessageKindV1::RouterToSignerB => {
            public_router_request_with_reconstructed_transcript(2_000)
                .to_signer_wire_messages()
                .expect("signer wire messages")
                .1
        }
        _ => signer_private_request(kind),
    }
}

fn signer_private_request_with_aead_envelope(kind: WireMessageKindV1) -> WireMessageV1 {
    match kind {
        WireMessageKindV1::RouterToSignerA => {
            public_router_request_with_aead_envelopes(2_000)
                .to_signer_wire_messages()
                .expect("signer wire messages")
                .0
        }
        WireMessageKindV1::RouterToSignerB => {
            public_router_request_with_aead_envelopes(2_000)
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
            public_router_request_with_hpke_envelopes(2_000)
                .to_signer_wire_messages()
                .expect("signer wire messages")
                .0
        }
        WireMessageKindV1::RouterToSignerB => {
            public_router_request_with_hpke_envelopes(2_000)
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
            public_router_request_with_aad_bound_envelopes(2_000)
                .to_signer_wire_messages()
                .expect("signer wire messages")
                .0
        }
        WireMessageKindV1::RouterToSignerB => {
            public_router_request_with_aad_bound_envelopes(2_000)
                .to_signer_wire_messages()
                .expect("signer wire messages")
                .1
        }
        _ => signer_private_request(kind),
    }
}

fn signer_input_plaintext_bytes(role: Role) -> Vec<u8> {
    let request = public_router_request(2_000);
    signer_input_plaintext_bytes_for_request(role, &request)
}

fn signer_input_plaintext_bytes_for_request(
    role: Role,
    request: &PublicRouterRequestV1,
) -> Vec<u8> {
    let (payload_a, payload_b) = request.to_signer_payloads().expect("signer payloads");
    let payload = match role {
        Role::SignerA => payload_a,
        Role::SignerB => payload_b,
        _ => panic!("test helper requires signer role"),
    };
    let assignment = payload.assignment();
    SignerInputPlaintextV1::new(
        CandidateId::MpcThresholdPrfV1,
        MpcPrfSuiteId::ThresholdPrfRistretto255Sha512V1,
        RequestKind::Registration,
        payload.lifecycle().lifecycle_id.clone(),
        payload.signer_set().signer_set_id.clone(),
        SignerInputQuorumPolicyV1::All2,
        role,
        assignment.signer.signer_id.clone(),
        assignment.signer.key_epoch.clone(),
        root_epoch(),
        "relayer-a",
        "relayer-epoch",
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
                OpenedShareKind::XRelayerBase,
                Role::Relayer,
                payload.signer_set().selected_relayer.relayer_id.clone(),
            )
            .expect("relayer output"),
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

struct TestSignerWireHandler {
    response_transcript: Option<PublicDigest32>,
}

impl TestSignerWireHandler {
    fn matching() -> Self {
        Self {
            response_transcript: None,
        }
    }

    fn mismatched(response_transcript: PublicDigest32) -> Self {
        Self {
            response_transcript: Some(response_transcript),
        }
    }
}

impl CloudflareSignerWireHandlerV1 for TestSignerWireHandler {
    fn handle_signer_wire_message(
        &self,
        message: WireMessageV1,
    ) -> router_ab_core::RouterAbProtocolResult<WireMessageV1> {
        Ok(signer_response(
            self.response_transcript
                .unwrap_or(message.transcript_digest),
            0x70,
        ))
    }
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

struct TestValidatedSignerInputHandler {
    response_transcript: Option<PublicDigest32>,
}

impl TestValidatedSignerInputHandler {
    fn matching() -> Self {
        Self {
            response_transcript: None,
        }
    }

    fn mismatched(response_transcript: PublicDigest32) -> Self {
        Self {
            response_transcript: Some(response_transcript),
        }
    }
}

impl CloudflareValidatedSignerInputHandlerV1 for TestValidatedSignerInputHandler {
    fn handle_validated_signer_input(
        &self,
        request: &CloudflareValidatedSignerPrivateRequestV1,
    ) -> router_ab_core::RouterAbProtocolResult<WireMessageV1> {
        assert_eq!(
            request.worker_role(),
            CloudflareWorkerRoleV1::SignerARelayer
        );
        assert_eq!(request.signer_input().recipient_role, Role::SignerA);
        assert_eq!(
            request.router_payload().transcript_digest(),
            request.message().transcript_digest
        );
        Ok(signer_response(
            self.response_transcript
                .unwrap_or(request.message().transcript_digest),
            0x71,
        ))
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

struct TestRouterPublicPlanExecutor {
    replay_reserved: bool,
    durable_operations: Vec<CloudflareDurableObjectOperationKindV1>,
    signer_peers: Vec<CloudflareWorkerRoleV1>,
}

impl TestRouterPublicPlanExecutor {
    fn new(replay_reserved: bool) -> Self {
        Self {
            replay_reserved,
            durable_operations: Vec::new(),
            signer_peers: Vec::new(),
        }
    }
}

impl CloudflareRouterPublicPlanExecutorV1 for TestRouterPublicPlanExecutor {
    fn execute_durable_object_call(
        &mut self,
        call: &CloudflareDurableObjectCallV1,
    ) -> router_ab_core::RouterAbProtocolResult<CloudflareDurableObjectResponseV1> {
        call.validate()?;
        self.durable_operations.push(call.operation_kind());
        match &call.request {
            CloudflareDurableObjectRequestV1::RouterReplayReserve { request } => {
                CloudflareDurableObjectResponseV1::router_replay_reserve(
                    CloudflareReplayReserveResponseV1::new(
                        request.request_id.clone(),
                        self.replay_reserved,
                    )?,
                )
            }
            CloudflareDurableObjectRequestV1::RouterLifecyclePutPublicState { state } => {
                CloudflareDurableObjectResponseV1::router_lifecycle_put_public_state(
                    CloudflareLifecyclePutReceiptV1::new(state.scope().lifecycle_id.clone(), true)?,
                )
            }
            _ => Err(router_ab_core::RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "test public Router executor received unexpected Durable Object operation",
            )),
        }
    }

    fn send_signer_message(
        &mut self,
        peer: &CloudflarePeerBindingV1,
        message: &WireMessageV1,
    ) -> router_ab_core::RouterAbProtocolResult<WireMessageV1> {
        self.signer_peers.push(peer.peer_role);
        Ok(signer_response(message.transcript_digest, 0x80))
    }
}

fn public_router_request(expires_at_ms: u64) -> PublicRouterRequestV1 {
    let lifecycle = lifecycle_scope();
    let signer_set = signer_set();
    let transcript_digest = public_request_transcript_digest(&lifecycle, &signer_set);
    PublicRouterRequestV1::new(
        "request-nonce-1",
        expires_at_ms,
        lifecycle,
        CandidateId::MpcThresholdPrfV1,
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

fn relayer_activation() -> RelayerActivationPayloadV1 {
    let relayer = RelayerIdentityV1::new(
        "relayer-a",
        "relayer-epoch",
        "x25519:1111111111111111111111111111111111111111111111111111111111111111",
    )
    .expect("relayer");
    let transcript_digest = digest(0x44);
    let package_commitment = digest(0x45);
    let ciphertext = RecipientOutputCiphertextV1::new(
        RecipientOutputEncryptionAlgorithmV1::LocalDeterministicSha256V1,
        Role::Relayer,
        OpenedShareKind::XRelayerBase,
        "relayer-a",
        "relayer-key-epoch:relayer-epoch",
        transcript_digest,
        package_commitment,
        [0x46; 12],
        EncryptedPayloadV1::new(vec![1, 2, 3]).expect("ciphertext"),
    )
    .expect("recipient output ciphertext");
    let output = RelayerOutputPackageV1::new(transcript_digest, package_commitment, ciphertext)
        .expect("relayer output");
    RelayerActivationPayloadV1::new("lifecycle-1", relayer, transcript_digest, output)
        .expect("activation")
}

fn router_env() -> CloudflareEnvMapV1 {
    CloudflareEnvMapV1::new(vec![
        (ROUTER_REPLAY_DO_BINDING_ENV, " ROUTER_REPLAY_DO "),
        (ROUTER_REPLAY_DO_OBJECT_ENV, "router-replay"),
        (ROUTER_REPLAY_DO_KEY_PREFIX_ENV, "router-replay:"),
        (ROUTER_LIFECYCLE_DO_BINDING_ENV, "ROUTER_LIFECYCLE_DO"),
        (ROUTER_LIFECYCLE_DO_OBJECT_ENV, "router-lifecycle"),
        (ROUTER_LIFECYCLE_DO_KEY_PREFIX_ENV, "router-lifecycle:"),
        (SIGNER_A_PEER_BINDING_ENV, "SIGNER_A"),
        (SIGNER_B_PEER_BINDING_ENV, "SIGNER_B"),
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

fn signer_a_env() -> CloudflareEnvMapV1 {
    CloudflareEnvMapV1::new(vec![
        (
            SIGNER_A_ROOT_SHARE_DO_BINDING_ENV,
            "SIGNER_A_ROOT_SHARE_DO".to_string(),
        ),
        (
            SIGNER_A_ROOT_SHARE_DO_OBJECT_ENV,
            "signer-a-root-share".to_string(),
        ),
        (
            SIGNER_A_ROOT_SHARE_DO_KEY_PREFIX_ENV,
            "signer-a-root-share:".to_string(),
        ),
        (
            SIGNER_A_ROOT_SHARE_WIRE_SECRET_BINDING_ENV,
            "SIGNER_A_ROOT_SHARE_WIRE_SECRET".to_string(),
        ),
        (
            SIGNER_A_RELAYER_OUTPUT_DO_BINDING_ENV,
            "SIGNER_A_RELAYER_OUTPUT_DO".to_string(),
        ),
        (
            SIGNER_A_RELAYER_OUTPUT_DO_OBJECT_ENV,
            "signer-a-relayer-output".to_string(),
        ),
        (
            SIGNER_A_RELAYER_OUTPUT_DO_KEY_PREFIX_ENV,
            "signer-a-relayer-output:".to_string(),
        ),
        (
            SIGNER_A_ENVELOPE_AEAD_KEY_BINDING_ENV,
            "SIGNER_A_ENVELOPE_AEAD_KEY".to_string(),
        ),
        (
            SIGNER_A_ENVELOPE_AEAD_KEY_EPOCH_ENV,
            "envelope-key-epoch-a".to_string(),
        ),
        (
            SIGNER_A_PEER_SIGNING_KEY_BINDING_ENV,
            "SIGNER_A_PEER_SIGNING_KEY".to_string(),
        ),
        (
            SIGNER_A_PEER_SIGNING_KEY_EPOCH_ENV,
            "key-epoch-a".to_string(),
        ),
        (
            SIGNER_A_PEER_VERIFYING_KEY_HEX_ENV,
            signer_peer_verifying_key_hex(Role::SignerA),
        ),
        (
            SIGNER_B_PEER_VERIFYING_KEY_HEX_ENV,
            signer_peer_verifying_key_hex(Role::SignerB),
        ),
        (SIGNER_B_PEER_BINDING_ENV, "SIGNER_B".to_string()),
    ])
}

fn signer_b_env() -> CloudflareEnvMapV1 {
    CloudflareEnvMapV1::new(vec![
        (
            SIGNER_B_ROOT_SHARE_DO_BINDING_ENV,
            "SIGNER_B_ROOT_SHARE_DO".to_string(),
        ),
        (
            SIGNER_B_ROOT_SHARE_DO_OBJECT_ENV,
            "signer-b-root-share".to_string(),
        ),
        (
            SIGNER_B_ROOT_SHARE_DO_KEY_PREFIX_ENV,
            "signer-b-root-share:".to_string(),
        ),
        (
            SIGNER_B_ROOT_SHARE_WIRE_SECRET_BINDING_ENV,
            "SIGNER_B_ROOT_SHARE_WIRE_SECRET".to_string(),
        ),
        (
            SIGNER_B_ENVELOPE_AEAD_KEY_BINDING_ENV,
            "SIGNER_B_ENVELOPE_AEAD_KEY".to_string(),
        ),
        (
            SIGNER_B_ENVELOPE_AEAD_KEY_EPOCH_ENV,
            "envelope-key-epoch-b".to_string(),
        ),
        (
            SIGNER_B_PEER_SIGNING_KEY_BINDING_ENV,
            "SIGNER_B_PEER_SIGNING_KEY".to_string(),
        ),
        (
            SIGNER_B_PEER_SIGNING_KEY_EPOCH_ENV,
            "key-epoch-b".to_string(),
        ),
        (
            SIGNER_A_PEER_VERIFYING_KEY_HEX_ENV,
            signer_peer_verifying_key_hex(Role::SignerA),
        ),
        (
            SIGNER_B_PEER_VERIFYING_KEY_HEX_ENV,
            signer_peer_verifying_key_hex(Role::SignerB),
        ),
        (SIGNER_A_PEER_BINDING_ENV, "SIGNER_A".to_string()),
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
        peer(CloudflareWorkerRoleV1::SignerARelayer, "SIGNER_A"),
        peer(CloudflareWorkerRoleV1::SignerB, "SIGNER_B"),
    )
    .expect("router bindings");
    let startup = CloudflareWorkerBindingsV1::router(bindings).expect("router startup");

    assert_eq!(startup.worker_role(), CloudflareWorkerRoleV1::Router);
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
            peer(CloudflareWorkerRoleV1::SignerARelayer, "SIGNER_A"),
            peer(CloudflareWorkerRoleV1::SignerB, "SIGNER_B"),
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
        runtime.signer_a_peer().peer_role,
        CloudflareWorkerRoleV1::SignerARelayer
    );
    assert_eq!(
        runtime.signer_b_peer().peer_role,
        CloudflareWorkerRoleV1::SignerB
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
            peer(CloudflareWorkerRoleV1::SignerARelayer, "SIGNER_A"),
            peer(CloudflareWorkerRoleV1::SignerB, "SIGNER_B"),
        )
        .expect("router bindings"),
    )
    .expect("router runtime");
    let request = public_router_request(2_000);
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
    let CloudflareRouterPublicAdmissionPlanV1::Forward {
        signer_a_message,
        signer_b_message,
        ..
    } = &plan
    else {
        panic!("accepted admission must forward");
    };
    assert_eq!(signer_a_message.kind, WireMessageKindV1::RouterToSignerA);
    assert_eq!(signer_b_message.kind, WireMessageKindV1::RouterToSignerB);
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
            peer(CloudflareWorkerRoleV1::SignerARelayer, "SIGNER_A"),
            peer(CloudflareWorkerRoleV1::SignerB, "SIGNER_B"),
        )
        .expect("router bindings"),
    )
    .expect("router runtime");
    let plan = runtime
        .public_request_admission_plan_at(
            1_000,
            public_router_request(2_000),
            trusted_admission(
                ExpensiveWorkGateDecisionV1::accepted("gate-request-1").expect("accepted"),
            ),
        )
        .expect("admission plan");

    plan.validate().expect("plan validation");
    let CloudflareRouterPublicAdmissionPlanV1::Forward {
        lifecycle_put_call,
        signer_a_message,
        signer_b_message,
        ..
    } = plan
    else {
        panic!("accepted admission must forward");
    };
    assert_eq!(signer_a_message.kind, WireMessageKindV1::RouterToSignerA);
    assert_eq!(signer_b_message.kind, WireMessageKindV1::RouterToSignerB);
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
            peer(CloudflareWorkerRoleV1::SignerARelayer, "SIGNER_A"),
            peer(CloudflareWorkerRoleV1::SignerB, "SIGNER_B"),
        )
        .expect("router bindings"),
    )
    .expect("router runtime");
    let plan = runtime
        .public_request_admission_plan_at(
            1_000,
            public_router_request(2_000),
            trusted_admission(
                ExpensiveWorkGateDecisionV1::rejected(GateRejectReasonV1::RateLimited, 1_000)
                    .expect("rejected"),
            ),
        )
        .expect("admission plan");

    plan.validate().expect("plan validation");
    let CloudflareRouterPublicAdmissionPlanV1::Stop {
        lifecycle_put_call, ..
    } = plan
    else {
        panic!("rejected admission must stop");
    };
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
fn router_public_plan_executor_forwards_only_after_accepted_admission() {
    let runtime = router_runtime();
    let plan = runtime
        .public_request_admission_plan_at(
            1_000,
            public_router_request(2_000),
            derive_cloudflare_router_trusted_admission_v1(
                &public_router_request(2_000),
                trusted_metadata(),
                allow_checks("gate-request-1"),
            )
            .expect("trusted admission"),
        )
        .expect("admission plan");
    let mut executor = TestRouterPublicPlanExecutor::new(true);
    let response =
        execute_cloudflare_router_public_admission_plan_v1(&runtime, &plan, &mut executor)
            .expect("public plan response");

    assert!(matches!(
        response,
        CloudflareRouterPublicAdmissionResponseV1::Forwarded { .. }
    ));
    assert_eq!(
        executor.durable_operations,
        vec![
            CloudflareDurableObjectOperationKindV1::RouterReplayReserve,
            CloudflareDurableObjectOperationKindV1::RouterLifecyclePutPublicState
        ]
    );
    assert_eq!(
        executor.signer_peers,
        vec![
            CloudflareWorkerRoleV1::SignerARelayer,
            CloudflareWorkerRoleV1::SignerB
        ]
    );
}

#[test]
fn router_public_plan_executor_stops_rejected_admission_before_signers() {
    let runtime = router_runtime();
    let checks = CloudflareRouterAdmissionChecksV1::new(
        CloudflareRouterProjectPolicyV1::Allowed,
        CloudflareRouterAbuseCheckV1::Rejected {
            retry_after_ms: 1_000,
        },
        CloudflareRouterQuotaCheckV1::Accepted {
            request_id: "gate-request-1".to_owned(),
        },
    )
    .expect("checks");
    let request = public_router_request(2_000);
    let plan = runtime
        .public_request_admission_plan_at(
            1_000,
            request.clone(),
            derive_cloudflare_router_trusted_admission_v1(&request, trusted_metadata(), checks)
                .expect("trusted admission"),
        )
        .expect("admission plan");
    let mut executor = TestRouterPublicPlanExecutor::new(true);
    let response =
        execute_cloudflare_router_public_admission_plan_v1(&runtime, &plan, &mut executor)
            .expect("public plan response");

    assert!(matches!(
        response,
        CloudflareRouterPublicAdmissionResponseV1::Stopped { .. }
    ));
    assert_eq!(
        executor.durable_operations,
        vec![
            CloudflareDurableObjectOperationKindV1::RouterReplayReserve,
            CloudflareDurableObjectOperationKindV1::RouterLifecyclePutPublicState
        ]
    );
    assert!(executor.signer_peers.is_empty());
}

#[test]
fn router_public_plan_executor_stops_replay_before_lifecycle_and_signers() {
    let runtime = router_runtime();
    let request = public_router_request(2_000);
    let plan = runtime
        .public_request_admission_plan_at(
            1_000,
            request.clone(),
            derive_cloudflare_router_trusted_admission_v1(
                &request,
                trusted_metadata(),
                allow_checks("gate-request-1"),
            )
            .expect("trusted admission"),
        )
        .expect("admission plan");
    let mut executor = TestRouterPublicPlanExecutor::new(false);
    let err = execute_cloudflare_router_public_admission_plan_v1(&runtime, &plan, &mut executor)
        .expect_err("replayed request must fail before signer forwarding");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::ReplayedLocalRequest);
    assert_eq!(
        executor.durable_operations,
        vec![CloudflareDurableObjectOperationKindV1::RouterReplayReserve]
    );
    assert!(executor.signer_peers.is_empty());
}

#[test]
fn trusted_admission_rejects_mismatched_request_resource() {
    let request = public_router_request(2_000);
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
        "relayer-a",
    )
    .expect("lifecycle scope");
    let signer_set = signer_set();
    let transcript_digest = public_request_transcript_digest(&lifecycle, &signer_set);
    let request = PublicRouterRequestV1::new(
        "request-nonce-2",
        2_000,
        lifecycle,
        CandidateId::MpcThresholdPrfV1,
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
    let request = public_router_request(2_000);
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
    let request = public_router_request(2_000);
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
    let request = public_router_request(2_000);
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
    let request = public_router_request(2_000);
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
    let request = public_router_request(2_000);
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
    let request = public_router_request(2_000);
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
    let request = public_router_request(2_000);
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
fn router_jwt_session_provider_feeds_composite_admission() {
    let request = public_router_request(2_000);
    let admission_bindings = parse_cloudflare_router_admission_bindings_v1(&router_admission_env())
        .expect("admission bindings");
    let jwt_session = CloudflareRouterJwtSessionProviderV1::new(
        admission_bindings.jwt,
        CloudflareRouterBearerAuthorizationV1::from_authorization_header(
            "Bearer header.payload.sig",
        )
        .expect("authorization"),
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
    let request = public_router_request(2_000);
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
    let request = public_router_request(2_000);
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
    let request = public_router_request(2_000);
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
    let request = public_router_request(2_000);
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
    let request = public_router_request(2_000);
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
    let request = public_router_request(2_000);
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
    let request = public_router_request(2_000);
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
fn router_public_response_accepts_matching_signer_outputs() {
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
            peer(CloudflareWorkerRoleV1::SignerARelayer, "SIGNER_A"),
            peer(CloudflareWorkerRoleV1::SignerB, "SIGNER_B"),
        )
        .expect("router bindings"),
    )
    .expect("router runtime");
    let plan = runtime
        .public_request_admission_plan_at(
            1_000,
            public_router_request(2_000),
            trusted_admission(
                ExpensiveWorkGateDecisionV1::accepted("gate-request-1").expect("accepted"),
            ),
        )
        .expect("public request admission plan");
    let CloudflareRouterPublicAdmissionPlanV1::Forward {
        signer_a_message, ..
    } = &plan
    else {
        panic!("accepted admission must forward");
    };
    let transcript_digest = signer_a_message.transcript_digest;
    let response = CloudflareRouterPublicResponseV1::new(
        CloudflareReplayReserveResponseV1::new("request-nonce-1", true).expect("replay"),
        CloudflareLifecyclePutReceiptV1::new("lifecycle-1", true).expect("lifecycle"),
        signer_response(transcript_digest, 0x50),
        signer_response(transcript_digest, 0x60),
    )
    .expect("public response");

    response
        .validate_for_admission_plan(&plan)
        .expect("response should match plan");
}

#[test]
fn router_public_response_rejects_wrong_signer_response_branch() {
    let wrong_branch = WireMessageV1::new(
        WireMessageKindV1::RouterToSignerA,
        digest(0x33),
        CanonicalWireBytesV1::new(vec![1, 2]).expect("payload"),
    )
    .expect("wrong branch message");
    let err = CloudflareRouterPublicResponseV1::new(
        CloudflareReplayReserveResponseV1::new("request-nonce-1", true).expect("replay"),
        CloudflareLifecyclePutReceiptV1::new("lifecycle-1", true).expect("lifecycle"),
        wrong_branch,
        signer_response(digest(0x33), 0x60),
    )
    .expect_err("wrong response branch must fail");

    assert_eq!(
        err.code(),
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig
    );
}

#[test]
fn router_public_response_rejects_transcript_mismatch_with_plan() {
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
            peer(CloudflareWorkerRoleV1::SignerARelayer, "SIGNER_A"),
            peer(CloudflareWorkerRoleV1::SignerB, "SIGNER_B"),
        )
        .expect("router bindings"),
    )
    .expect("router runtime");
    let plan = runtime
        .public_request_admission_plan_at(
            1_000,
            public_router_request(2_000),
            trusted_admission(
                ExpensiveWorkGateDecisionV1::accepted("gate-request-1").expect("accepted"),
            ),
        )
        .expect("public request admission plan");
    let response = CloudflareRouterPublicResponseV1::new(
        CloudflareReplayReserveResponseV1::new("request-nonce-1", true).expect("replay"),
        CloudflareLifecyclePutReceiptV1::new("lifecycle-1", true).expect("lifecycle"),
        signer_response(digest(0x77), 0x50),
        signer_response(digest(0x77), 0x60),
    )
    .expect("matching signer response transcripts");
    let err = response
        .validate_for_admission_plan(&plan)
        .expect_err("plan transcript mismatch must fail");

    assert_eq!(
        err.code(),
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig
    );
}

#[test]
fn signer_private_request_accepts_role_specific_router_message() {
    let message = signer_private_request(WireMessageKindV1::RouterToSignerA);

    validate_cloudflare_signer_private_request_v1(CloudflareWorkerRoleV1::SignerARelayer, &message)
        .expect("signer a request should validate");
}

#[test]
fn signer_private_request_rejects_wrong_role_message() {
    let message = signer_private_request(WireMessageKindV1::RouterToSignerB);
    let err = validate_cloudflare_signer_private_request_v1(
        CloudflareWorkerRoleV1::SignerARelayer,
        &message,
    )
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
    let err = validate_cloudflare_signer_private_request_v1(
        CloudflareWorkerRoleV1::SignerARelayer,
        &message,
    )
    .expect_err("malformed Router-to-signer payload must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::MalformedWirePayload);
}

#[test]
fn signer_private_request_rejects_payload_transcript_mismatch() {
    let mut message = signer_private_request(WireMessageKindV1::RouterToSignerA);
    message.transcript_digest = digest(0x77);
    let err = validate_cloudflare_signer_private_request_v1(
        CloudflareWorkerRoleV1::SignerARelayer,
        &message,
    )
    .expect_err("wire transcript must match decoded payload transcript");

    assert_eq!(
        err.code(),
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig
    );
}

#[test]
fn signer_private_bootstrap_accepts_typed_role_envelope_aad() {
    let request = public_router_request_with_aad_bound_envelopes(2_000);
    let message =
        signer_private_request_with_aad_bound_envelope(WireMessageKindV1::RouterToSignerA);
    let aad = role_envelope_aad_for_request(Role::SignerA, &request);
    let bootstrap = CloudflareSignerPrivateBootstrapRequestV1::new(
        CloudflareWorkerRoleV1::SignerARelayer,
        message.clone(),
        aad.clone(),
        request_context_digest(&request),
    )
    .expect("strict signer bootstrap");

    assert_eq!(bootstrap.message, message);
    assert_eq!(bootstrap.aad, aad);
}

#[test]
fn signer_private_bootstrap_rejects_wrong_aad_digest() {
    let request = public_router_request_with_aad_bound_envelopes(2_000);
    let message =
        signer_private_request_with_aad_bound_envelope(WireMessageKindV1::RouterToSignerA);
    let mut aad = role_envelope_aad_for_request(Role::SignerA, &request);
    aad.router_request_digest = digest(0x99);
    let err = CloudflareSignerPrivateBootstrapRequestV1::new(
        CloudflareWorkerRoleV1::SignerARelayer,
        message,
        aad,
        request_context_digest(&request),
    )
    .expect_err("bootstrap AAD digest mismatch must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::MalformedWirePayload);
}

#[test]
fn signer_private_bootstrap_rejects_body_request_digest_mismatch() {
    let request = public_router_request_with_aad_bound_envelopes(2_000);
    let message =
        signer_private_request_with_aad_bound_envelope(WireMessageKindV1::RouterToSignerA);
    let aad = role_envelope_aad_for_request(Role::SignerA, &request);
    let err = CloudflareSignerPrivateBootstrapRequestV1::new(
        CloudflareWorkerRoleV1::SignerARelayer,
        message,
        aad,
        digest(0x99),
    )
    .expect_err("bootstrap body Router request digest mismatch must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::MalformedWirePayload);
}

#[test]
fn signer_private_bootstrap_derives_preload_plan() {
    let request = public_router_request_with_aad_bound_envelopes(2_000);
    let message =
        signer_private_request_with_aad_bound_envelope(WireMessageKindV1::RouterToSignerA);
    let aad = role_envelope_aad_for_request(Role::SignerA, &request);
    let bootstrap = CloudflareSignerPrivateBootstrapRequestV1::new(
        CloudflareWorkerRoleV1::SignerARelayer,
        message.clone(),
        aad,
        request_context_digest(&request),
    )
    .expect("strict signer bootstrap");
    let plan = CloudflareSignerHostPreloadPlanV1::from_private_bootstrap(
        CloudflareWorkerRoleV1::SignerARelayer,
        &bootstrap,
    )
    .expect("preload plan");

    assert_eq!(plan.worker_role, CloudflareWorkerRoleV1::SignerARelayer);
    assert_eq!(plan.signer_set_id, "signer-set-v1");
    assert_eq!(plan.root_share_epoch, root_epoch());
    assert_eq!(plan.local_signer, signer_identity(Role::SignerA));
    assert_eq!(plan.signer_set, signer_set());
    assert_eq!(plan.transcript_digest, message.transcript_digest);
    assert_eq!(plan.router_request_digest, request_context_digest(&request));
}

#[test]
fn signer_private_preload_plan_builds_host_preload_input() {
    let request = public_router_request_with_aad_bound_envelopes(2_000);
    let message =
        signer_private_request_with_aad_bound_envelope(WireMessageKindV1::RouterToSignerA);
    let aad = role_envelope_aad_for_request(Role::SignerA, &request);
    let bootstrap = CloudflareSignerPrivateBootstrapRequestV1::new(
        CloudflareWorkerRoleV1::SignerARelayer,
        message,
        aad,
        request_context_digest(&request),
    )
    .expect("strict signer bootstrap");
    let plan = CloudflareSignerHostPreloadPlanV1::from_private_bootstrap(
        CloudflareWorkerRoleV1::SignerARelayer,
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
    let request = public_router_request_with_aad_bound_envelopes(2_000);
    let message =
        signer_private_request_with_aad_bound_envelope(WireMessageKindV1::RouterToSignerA);
    let aad = role_envelope_aad_for_request(Role::SignerA, &request);
    let bootstrap = CloudflareSignerPrivateBootstrapRequestV1::new(
        CloudflareWorkerRoleV1::SignerARelayer,
        message,
        aad,
        request_context_digest(&request),
    )
    .expect("strict signer bootstrap");
    let err = CloudflareSignerHostPreloadPlanV1::from_private_bootstrap(
        CloudflareWorkerRoleV1::SignerB,
        &bootstrap,
    )
    .expect_err("wrong Worker role must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidLocalRoute);
}

#[test]
fn cloudflare_signer_envelope_aead_payload_accepts_bound_public_metadata() {
    let message = signer_private_request_with_aead_envelope(WireMessageKindV1::RouterToSignerA);

    let parsed = decode_and_validate_cloudflare_signer_envelope_aead_payload_v1(
        CloudflareWorkerRoleV1::SignerARelayer,
        &message,
        &signer_a_envelope_decrypt_key(),
    )
    .expect("validated AEAD payload");

    assert_eq!(parsed.recipient_role, Role::SignerA);
    assert_eq!(parsed.key_epoch, "envelope-key-epoch-a");
    assert_eq!(parsed.aad_digest, digest(0x11));
}

#[test]
fn cloudflare_signer_envelope_aead_payload_rejects_wrong_key_epoch() {
    let message = signer_private_request_with_aead_envelope(WireMessageKindV1::RouterToSignerA);
    let key = CloudflareSignerEnvelopeDecryptKeyBindingV1::new(
        Role::SignerA,
        "SIGNER_A_ENVELOPE_AEAD_KEY",
        "stale-envelope-key-epoch-a",
    )
    .expect("stale key descriptor");

    let err = decode_and_validate_cloudflare_signer_envelope_aead_payload_v1(
        CloudflareWorkerRoleV1::SignerARelayer,
        &message,
        &key,
    )
    .expect_err("wrong key epoch must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidSignerIdentity);
}

#[test]
fn cloudflare_signer_envelope_aead_payload_rejects_wrong_role_key() {
    let message = signer_private_request_with_aead_envelope(WireMessageKindV1::RouterToSignerA);

    let err = decode_and_validate_cloudflare_signer_envelope_aead_payload_v1(
        CloudflareWorkerRoleV1::SignerARelayer,
        &message,
        &signer_b_envelope_decrypt_key(),
    )
    .expect_err("wrong role key must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::ForbiddenLocalBinding);
}

#[test]
fn cloudflare_signer_envelope_aead_payload_rejects_malformed_ciphertext() {
    let message = signer_private_request(WireMessageKindV1::RouterToSignerA);

    let err = decode_and_validate_cloudflare_signer_envelope_aead_payload_v1(
        CloudflareWorkerRoleV1::SignerARelayer,
        &message,
        &signer_a_envelope_decrypt_key(),
    )
    .expect_err("placeholder ciphertext is not a valid AEAD payload");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::MalformedWirePayload);
}

#[test]
fn cloudflare_signer_input_plaintext_accepts_bound_decrypted_bytes() {
    let request = public_router_request(2_000);
    let message = signer_private_request(WireMessageKindV1::RouterToSignerA);
    let plaintext = decode_and_validate_cloudflare_signer_input_plaintext_v1(
        CloudflareWorkerRoleV1::SignerARelayer,
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
    let request = public_router_request(2_000);
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
        CloudflareWorkerRoleV1::SignerARelayer,
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
    let request = public_router_request(2_000);
    let message = signer_private_request(WireMessageKindV1::RouterToSignerA);

    let err = decode_and_validate_cloudflare_signer_input_plaintext_v1(
        CloudflareWorkerRoleV1::SignerARelayer,
        &message,
        &[0xde, 0xad],
        request_context_digest(&request),
        &root_share_metadata(Role::SignerA),
    )
    .expect_err("malformed decrypted plaintext must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::MalformedWirePayload);
}

#[test]
fn cloudflare_validated_signer_private_request_carries_only_validated_plaintext_to_handler() {
    let request = public_router_request(2_000);
    let message = signer_private_request(WireMessageKindV1::RouterToSignerA);
    let validated = validate_cloudflare_signer_private_request_plaintext_v1(
        CloudflareWorkerRoleV1::SignerARelayer,
        message.clone(),
        &signer_input_plaintext_bytes(Role::SignerA),
        request_context_digest(&request),
        &root_share_metadata(Role::SignerA),
    )
    .expect("validated signer request");

    assert_eq!(
        validated.worker_role(),
        CloudflareWorkerRoleV1::SignerARelayer
    );
    assert_eq!(validated.message(), &message);
    assert_eq!(validated.signer_input().recipient_role, Role::SignerA);

    let response = handle_cloudflare_validated_signer_private_request_v1(
        &TestValidatedSignerInputHandler::matching(),
        validated,
    )
    .expect("validated signer handler response");

    assert_eq!(response.kind, WireMessageKindV1::SignerResponse);
    assert_eq!(response.transcript_digest, message.transcript_digest);
}

#[test]
fn cloudflare_validated_signer_private_request_rejects_bad_plaintext_before_handler() {
    let request = public_router_request(2_000);
    let message = signer_private_request(WireMessageKindV1::RouterToSignerA);

    let err = validate_cloudflare_signer_private_request_plaintext_v1(
        CloudflareWorkerRoleV1::SignerARelayer,
        message,
        &[0xde, 0xad],
        request_context_digest(&request),
        &root_share_metadata(Role::SignerA),
    )
    .expect_err("malformed signer plaintext must fail before handler");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::MalformedWirePayload);
}

#[test]
fn cloudflare_validated_mpc_prf_engine_runs_signer_a_batch() {
    let request = public_router_request_with_reconstructed_transcript(2_000);
    let message =
        signer_private_request_with_reconstructed_transcript(WireMessageKindV1::RouterToSignerA);
    let validated = validate_cloudflare_signer_private_request_plaintext_v1(
        CloudflareWorkerRoleV1::SignerARelayer,
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
    let request = public_router_request_with_reconstructed_transcript(2_000);
    let message =
        signer_private_request_with_reconstructed_transcript(WireMessageKindV1::RouterToSignerA);
    let validated = validate_cloudflare_signer_private_request_plaintext_v1(
        CloudflareWorkerRoleV1::SignerARelayer,
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
fn cloudflare_proof_batch_helpers_combine_and_build_signer_response() {
    let request = public_router_request_with_reconstructed_transcript(2_000);
    let message_a =
        signer_private_request_with_reconstructed_transcript(WireMessageKindV1::RouterToSignerA);
    let message_b =
        signer_private_request_with_reconstructed_transcript(WireMessageKindV1::RouterToSignerB);
    let validated_a = validate_cloudflare_signer_private_request_plaintext_v1(
        CloudflareWorkerRoleV1::SignerARelayer,
        message_a,
        &signer_input_plaintext_bytes_for_request(Role::SignerA, &request),
        request_context_digest(&request),
        &root_share_metadata(Role::SignerA),
    )
    .expect("validated signer a request");
    let validated_b = validate_cloudflare_signer_private_request_plaintext_v1(
        CloudflareWorkerRoleV1::SignerB,
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
    let signer_a_key = signer_peer_signing_key(Role::SignerA).to_bytes();
    let signer_b_key = signer_peer_signing_key(Role::SignerB).to_bytes();
    let peer_a = build_cloudflare_ab_derivation_proof_batch_peer_message_v1(
        &signer_a_key,
        signer_identity(Role::SignerA),
        signer_identity(Role::SignerB),
        output_a,
    )
    .expect("signer a peer proof batch");
    let peer_b = build_cloudflare_ab_derivation_proof_batch_peer_message_v1(
        &signer_b_key,
        signer_identity(Role::SignerB),
        signer_identity(Role::SignerA),
        output_b,
    )
    .expect("signer b peer proof batch");

    let proof_a =
        decode_and_verify_cloudflare_ab_derivation_proof_batch_message_v1(&host_a, &peer_a)
            .expect("verified signer a proof batch");
    let proof_b =
        decode_and_verify_cloudflare_ab_derivation_proof_batch_message_v1(&host_a, &peer_b)
            .expect("verified signer b proof batch");
    assert_eq!(proof_a.from.role, Role::SignerA);
    assert_eq!(proof_b.from.role, Role::SignerB);

    let mut encryptor = TestRecipientOutputEncryptor;
    let packages = combine_cloudflare_mpc_prf_output_packages_from_peer_messages_v1(
        &host_a,
        validated_a.router_payload(),
        &peer_a,
        &peer_b,
        &mut encryptor,
    )
    .expect("combined output packages");
    let response = cloudflare_signer_response_from_mpc_prf_packages_v1(
        validated_a.signer_input().lifecycle_id.as_str(),
        signer_identity(Role::SignerA),
        &packages,
    )
    .expect("signer response");
    let response_payload =
        decode_signer_response_payload_v1(response.payload.as_bytes()).expect("response payload");

    assert_eq!(response.kind, WireMessageKindV1::SignerResponse);
    assert_eq!(
        response.transcript_digest,
        validated_a.message().transcript_digest
    );
    assert_eq!(response_payload.signer, signer_identity(Role::SignerA));
    assert_eq!(
        response_payload.client_output.transcript_digest(),
        response.transcript_digest
    );

    let mut proof_bundle_encryptor = TestRecipientProofBundleEncryptor;
    let signer_a_strict: CloudflareSignerRecipientProofBundleResponseV1 =
        cloudflare_recipient_proof_bundle_response_from_ab_proof_batch_v1(
            validated_a.router_payload(),
            proof_a.clone(),
            &mut proof_bundle_encryptor,
        )
        .expect("signer a strict proof-bundle response");
    let signer_b_strict: CloudflareSignerRecipientProofBundleResponseV1 =
        cloudflare_recipient_proof_bundle_response_from_ab_proof_batch_v1(
            validated_b.router_payload(),
            proof_b.clone(),
            &mut proof_bundle_encryptor,
        )
        .expect("signer b strict proof-bundle response");
    signer_a_strict
        .validate_for_router_payload(validated_a.router_payload())
        .expect("signer a strict response matches router payload");
    signer_b_strict
        .validate_for_router_payload(validated_b.router_payload())
        .expect("signer b strict response matches router payload");

    let signer_a_client = decode_recipient_proof_bundle_ciphertext_v1(
        signer_a_strict.client_bundle.payload.as_bytes(),
    )
    .expect("signer a client proof-bundle envelope");
    assert_eq!(signer_a_client.signer, signer_identity(Role::SignerA));
    assert_eq!(signer_a_client.recipient_role, Role::Client);
    assert_eq!(
        signer_a_client.recipient_identity,
        validated_a.router_payload().transcript_metadata().client_id
    );

    let router_strict = CloudflareRouterRecipientProofBundleResponseV1::new(
        CloudflareReplayReserveResponseV1::new("request-nonce-1", true).expect("replay"),
        CloudflareLifecyclePutReceiptV1::new("lifecycle-1", true).expect("lifecycle"),
        signer_a_strict.client_bundle.clone(),
        signer_b_strict.client_bundle.clone(),
    )
    .expect("strict router proof-bundle response");
    router_strict
        .validate_for_router_payload(validated_a.router_payload())
        .expect("strict router response matches router payload");

    let relayer_activation = CloudflareRelayerRecipientProofBundleActivationV1::new(
        signer_a_strict.relayer_bundle.clone(),
        signer_b_strict.relayer_bundle.clone(),
    )
    .expect("strict relayer proof-bundle activation");
    relayer_activation
        .validate_for_router_payload(validated_a.router_payload())
        .expect("strict relayer activation matches router payload");

    let err = CloudflareRouterRecipientProofBundleResponseV1::new(
        CloudflareReplayReserveResponseV1::new("request-nonce-1", true).expect("replay"),
        CloudflareLifecyclePutReceiptV1::new("lifecycle-1", true).expect("lifecycle"),
        signer_b_strict.client_bundle.clone(),
        signer_a_strict.client_bundle.clone(),
    )
    .expect_err("swapped strict client bundles must fail");
    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidSignerIdentity);
}

#[test]
fn cloudflare_peer_signing_key_binding_matches_validated_request_identity() {
    let request = public_router_request_with_reconstructed_transcript(2_000);
    let message =
        signer_private_request_with_reconstructed_transcript(WireMessageKindV1::RouterToSignerA);
    let validated = validate_cloudflare_signer_private_request_plaintext_v1(
        CloudflareWorkerRoleV1::SignerARelayer,
        message,
        &signer_input_plaintext_bytes_for_request(Role::SignerA, &request),
        request_context_digest(&request),
        &root_share_metadata(Role::SignerA),
    )
    .expect("validated signer a request");

    let signer = validate_cloudflare_peer_signing_key_matches_request_v1(
        CloudflareWorkerRoleV1::SignerARelayer,
        &signer_a_peer_signing_key(),
        &validated,
    )
    .expect("matched signer key");

    assert_eq!(signer, signer_identity(Role::SignerA));
}

#[test]
fn cloudflare_peer_signing_key_binding_rejects_wrong_role_key() {
    let request = public_router_request_with_reconstructed_transcript(2_000);
    let message =
        signer_private_request_with_reconstructed_transcript(WireMessageKindV1::RouterToSignerA);
    let validated = validate_cloudflare_signer_private_request_plaintext_v1(
        CloudflareWorkerRoleV1::SignerARelayer,
        message,
        &signer_input_plaintext_bytes_for_request(Role::SignerA, &request),
        request_context_digest(&request),
        &root_share_metadata(Role::SignerA),
    )
    .expect("validated signer a request");

    let err = validate_cloudflare_peer_signing_key_matches_request_v1(
        CloudflareWorkerRoleV1::SignerARelayer,
        &signer_b_peer_signing_key(),
        &validated,
    )
    .unwrap_err();

    assert_eq!(err.code(), RouterAbProtocolErrorCode::ForbiddenLocalBinding);
}

#[test]
fn cloudflare_peer_signing_key_binding_rejects_stale_epoch() {
    let request = public_router_request_with_reconstructed_transcript(2_000);
    let message =
        signer_private_request_with_reconstructed_transcript(WireMessageKindV1::RouterToSignerA);
    let validated = validate_cloudflare_signer_private_request_plaintext_v1(
        CloudflareWorkerRoleV1::SignerARelayer,
        message,
        &signer_input_plaintext_bytes_for_request(Role::SignerA, &request),
        request_context_digest(&request),
        &root_share_metadata(Role::SignerA),
    )
    .expect("validated signer a request");
    let stale_key = CloudflareSignerPeerSigningKeyBindingV1::new(
        Role::SignerA,
        "SIGNER_A_PEER_SIGNING_KEY",
        "stale-key-epoch-a",
    )
    .expect("stale signer a peer signing key");

    let err = validate_cloudflare_peer_signing_key_matches_request_v1(
        CloudflareWorkerRoleV1::SignerARelayer,
        &stale_key,
        &validated,
    )
    .unwrap_err();

    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidSignerIdentity);
}

#[test]
fn cloudflare_peer_signing_key_binding_rejects_mismatched_worker_role_argument() {
    let request = public_router_request_with_reconstructed_transcript(2_000);
    let message =
        signer_private_request_with_reconstructed_transcript(WireMessageKindV1::RouterToSignerA);
    let validated = validate_cloudflare_signer_private_request_plaintext_v1(
        CloudflareWorkerRoleV1::SignerARelayer,
        message,
        &signer_input_plaintext_bytes_for_request(Role::SignerA, &request),
        request_context_digest(&request),
        &root_share_metadata(Role::SignerA),
    )
    .expect("validated signer a request");

    let err = validate_cloudflare_peer_signing_key_matches_request_v1(
        CloudflareWorkerRoleV1::SignerB,
        &signer_b_peer_signing_key(),
        &validated,
    )
    .unwrap_err();

    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidRole);
}

#[test]
fn cloudflare_validated_mpc_prf_handler_returns_signer_responses_for_a_and_b() {
    let request = public_router_request_with_reconstructed_transcript(2_000);
    let message_a =
        signer_private_request_with_reconstructed_transcript(WireMessageKindV1::RouterToSignerA);
    let message_b =
        signer_private_request_with_reconstructed_transcript(WireMessageKindV1::RouterToSignerB);
    let validated_a = validate_cloudflare_signer_private_request_plaintext_v1(
        CloudflareWorkerRoleV1::SignerARelayer,
        message_a,
        &signer_input_plaintext_bytes_for_request(Role::SignerA, &request),
        request_context_digest(&request),
        &root_share_metadata(Role::SignerA),
    )
    .expect("validated signer a request");
    let validated_b = validate_cloudflare_signer_private_request_plaintext_v1(
        CloudflareWorkerRoleV1::SignerB,
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
    let output_a =
        evaluate_cloudflare_validated_mpc_prf_batch_output_v1(&base_host_a, &validated_a)
            .expect("signer a output");
    let output_b =
        evaluate_cloudflare_validated_mpc_prf_batch_output_v1(&base_host_b, &validated_b)
            .expect("signer b output");
    let signer_a_key = signer_peer_signing_key(Role::SignerA).to_bytes();
    let signer_b_key = signer_peer_signing_key(Role::SignerB).to_bytes();
    let peer_a = build_cloudflare_ab_derivation_proof_batch_peer_message_v1(
        &signer_a_key,
        signer_identity(Role::SignerA),
        signer_identity(Role::SignerB),
        output_a,
    )
    .expect("signer a peer proof batch");
    let peer_b = build_cloudflare_ab_derivation_proof_batch_peer_message_v1(
        &signer_b_key,
        signer_identity(Role::SignerB),
        signer_identity(Role::SignerA),
        output_b,
    )
    .expect("signer b peer proof batch");
    let host_a = build_cloudflare_preloaded_signer_host_with_root_share_wire_v1(
        1_000,
        Role::SignerA,
        CloudflareSignerHostPreloadInputV1::new(
            "signer-set-v1",
            root_epoch(),
            vec![peer_b.clone()],
            signer_verifying_keys(),
            0,
        )
        .expect("preload a"),
        root_share_metadata(Role::SignerA),
        root_share_wire(Role::SignerA),
        Vec::new(),
    )
    .expect("host a with peer response");
    let host_b = build_cloudflare_preloaded_signer_host_with_root_share_wire_v1(
        1_000,
        Role::SignerB,
        CloudflareSignerHostPreloadInputV1::new(
            "signer-set-v1",
            root_epoch(),
            vec![peer_a.clone()],
            signer_verifying_keys(),
            0,
        )
        .expect("preload b"),
        root_share_metadata(Role::SignerB),
        root_share_wire(Role::SignerB),
        Vec::new(),
    )
    .expect("host b with peer response");
    let mut encryptor_a = TestRecipientOutputEncryptor;
    let mut encryptor_b = TestRecipientOutputEncryptor;
    let response_a = handle_cloudflare_validated_mpc_prf_signer_request_v1(
        &host_a,
        &signer_a_key,
        &validated_a,
        &mut encryptor_a,
    )
    .expect("signer a response");
    let response_b = handle_cloudflare_validated_mpc_prf_signer_request_v1(
        &host_b,
        &signer_b_key,
        &validated_b,
        &mut encryptor_b,
    )
    .expect("signer b response");
    let payload_a =
        decode_signer_response_payload_v1(response_a.payload.as_bytes()).expect("payload a");
    let payload_b =
        decode_signer_response_payload_v1(response_b.payload.as_bytes()).expect("payload b");

    assert_eq!(response_a.kind, WireMessageKindV1::SignerResponse);
    assert_eq!(response_b.kind, WireMessageKindV1::SignerResponse);
    assert_eq!(response_a.transcript_digest, response_b.transcript_digest);
    assert_eq!(payload_a.signer, signer_identity(Role::SignerA));
    assert_eq!(payload_b.signer, signer_identity(Role::SignerB));
    assert_eq!(
        payload_a.client_output.package_commitment(),
        payload_b.client_output.package_commitment()
    );

    let mut proof_bundle_encryptor_a = TestRecipientProofBundleEncryptor;
    let mut proof_bundle_encryptor_b = TestRecipientProofBundleEncryptor;
    let strict_response_a =
        handle_cloudflare_validated_mpc_prf_recipient_proof_bundle_signer_request_v1(
            &base_host_a,
            &signer_a_key,
            &validated_a,
            &mut proof_bundle_encryptor_a,
        )
        .expect("strict signer a proof-bundle response");
    let strict_response_b =
        handle_cloudflare_validated_mpc_prf_recipient_proof_bundle_signer_request_v1(
            &base_host_b,
            &signer_b_key,
            &validated_b,
            &mut proof_bundle_encryptor_b,
        )
        .expect("strict signer b proof-bundle response");
    validate_cloudflare_signer_recipient_proof_bundle_private_response_v1(
        CloudflareWorkerRoleV1::SignerARelayer,
        validated_a.message(),
        &strict_response_a,
    )
    .expect("strict signer a response validates");
    validate_cloudflare_signer_recipient_proof_bundle_private_response_v1(
        CloudflareWorkerRoleV1::SignerB,
        validated_b.message(),
        &strict_response_b,
    )
    .expect("strict signer b response validates");

    let strict_private_response =
        handle_cloudflare_signer_recipient_proof_bundle_private_request_v1(
            CloudflareWorkerRoleV1::SignerARelayer,
            &TestRecipientProofBundleWireHandler {
                response: strict_response_a.clone(),
            },
            validated_a.message().clone(),
        )
        .expect("strict private signer handler response");
    assert_eq!(strict_private_response.signer_role, Role::SignerA);

    let wrong_strict_response =
        validate_cloudflare_signer_recipient_proof_bundle_private_response_v1(
            CloudflareWorkerRoleV1::SignerARelayer,
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

    let activation_request = CloudflareRelayerRecipientProofBundleActivationRequestV1::new(
        validated_a.router_payload().clone(),
        CloudflareRelayerRecipientProofBundleActivationV1::new(
            strict_response_a.relayer_bundle.clone(),
            strict_response_b.relayer_bundle.clone(),
        )
        .expect("strict relayer activation"),
    )
    .expect("strict relayer activation request");
    let activation_receipt =
        handle_cloudflare_signer_a_recipient_proof_bundle_activation_request_v1(activation_request)
            .expect("strict relayer activation receipt");
    assert_eq!(activation_receipt.relayer_id, "relayer-a");
    assert_eq!(
        activation_receipt.transcript_digest,
        validated_a.router_payload().transcript_digest()
    );

    let strict_admission = CloudflareRouterRecipientProofBundleAdmissionResponseV1::forwarded(
        strict_router_response,
        activation_receipt,
    )
    .expect("strict Router admission response");
    strict_admission
        .validate()
        .expect("strict Router admission response validates");
}

#[test]
fn cloudflare_validated_signer_private_handler_rejects_response_transcript_mismatch() {
    let request = public_router_request(2_000);
    let message = signer_private_request(WireMessageKindV1::RouterToSignerA);
    let validated = validate_cloudflare_signer_private_request_plaintext_v1(
        CloudflareWorkerRoleV1::SignerARelayer,
        message,
        &signer_input_plaintext_bytes(Role::SignerA),
        request_context_digest(&request),
        &root_share_metadata(Role::SignerA),
    )
    .expect("validated signer request");

    let err = handle_cloudflare_validated_signer_private_request_v1(
        &TestValidatedSignerInputHandler::mismatched(digest(0x99)),
        validated,
    )
    .expect_err("response transcript mismatch must fail");

    assert_eq!(
        err.code(),
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig
    );
}

#[test]
fn signer_private_handler_returns_transcript_bound_signer_response() {
    let message = signer_private_request(WireMessageKindV1::RouterToSignerB);
    let response = handle_cloudflare_signer_private_request_v1(
        CloudflareWorkerRoleV1::SignerB,
        &TestSignerWireHandler::matching(),
        message.clone(),
    )
    .expect("signer b private request");

    assert_eq!(response.kind, WireMessageKindV1::SignerResponse);
    assert_eq!(response.transcript_digest, message.transcript_digest);
}

#[test]
fn signer_private_response_rejects_transcript_mismatch() {
    let request = signer_private_request(WireMessageKindV1::RouterToSignerA);
    let response = signer_response(digest(0x77), 0x70);
    let err = validate_cloudflare_signer_private_response_v1(&request, &response)
        .expect_err("transcript mismatch must fail");

    assert_eq!(
        err.code(),
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig
    );
}

#[test]
fn signer_private_handler_rejects_mismatched_handler_response() {
    let message = signer_private_request(WireMessageKindV1::RouterToSignerA);
    let err = handle_cloudflare_signer_private_request_v1(
        CloudflareWorkerRoleV1::SignerARelayer,
        &TestSignerWireHandler::mismatched(digest(0x77)),
        message,
    )
    .expect_err("mismatched handler response must fail");

    assert_eq!(
        err.code(),
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig
    );
}

#[test]
fn signer_peer_request_accepts_cross_role_message() {
    let message = signer_peer_message(WireMessageKindV1::SignerAToSignerB);

    validate_cloudflare_signer_peer_request_v1(CloudflareWorkerRoleV1::SignerB, &message)
        .expect("signer b peer request should validate");
}

#[test]
fn signer_peer_request_rejects_router_private_message() {
    let message = signer_private_request(WireMessageKindV1::RouterToSignerA);
    let err = validate_cloudflare_signer_peer_request_v1(CloudflareWorkerRoleV1::SignerB, &message)
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

    let err = validate_cloudflare_signer_peer_request_v1(CloudflareWorkerRoleV1::SignerB, &message)
        .expect_err("peer payload direction mismatch must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidSignerIdentity);
}

#[test]
fn signer_peer_request_authentication_verifies_with_key_store() {
    let message = signer_peer_message(WireMessageKindV1::SignerAToSignerB);
    let payload =
        verify_cloudflare_signer_peer_message_authentication_v1(&TestPeerKeyStore, &message)
            .expect("peer authentication should verify");

    assert_eq!(payload.from, signer_identity(Role::SignerA));
}

#[test]
fn signer_peer_request_authentication_rejects_wrong_key() {
    let message = signer_peer_message(WireMessageKindV1::SignerAToSignerB);
    let err = verify_cloudflare_signer_peer_message_authentication_v1(&WrongPeerKeyStore, &message)
        .expect_err("wrong key must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidSignerIdentity);
}

#[test]
fn signer_peer_response_requires_opposite_peer_direction() {
    let request = signer_peer_message(WireMessageKindV1::SignerAToSignerB);
    let response = signer_peer_message(WireMessageKindV1::SignerBToSignerA);

    validate_cloudflare_signer_peer_response_v1(
        CloudflareWorkerRoleV1::SignerB,
        &request,
        &response,
    )
    .expect("opposite peer response should validate");
}

#[test]
fn signer_peer_handler_returns_transcript_bound_peer_response() {
    let request = signer_peer_message(WireMessageKindV1::SignerAToSignerB);
    let response = handle_cloudflare_signer_peer_request_v1(
        CloudflareWorkerRoleV1::SignerB,
        &TestPeerKeyStore,
        &TestPeerWireHandler::matching(WireMessageKindV1::SignerBToSignerA),
        request.clone(),
    )
    .expect("signer b peer request");

    assert_eq!(response.kind, WireMessageKindV1::SignerBToSignerA);
    assert_eq!(response.transcript_digest, request.transcript_digest);
}

#[test]
fn signer_peer_handler_rejects_signer_response_branch() {
    let request = signer_peer_message(WireMessageKindV1::SignerAToSignerB);
    let err = handle_cloudflare_signer_peer_request_v1(
        CloudflareWorkerRoleV1::SignerB,
        &TestPeerKeyStore,
        &TestSignerWireHandler::matching(),
        request,
    )
    .expect_err("peer endpoint must reject signer_response branch");

    assert_eq!(
        err.code(),
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig
    );
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
            peer(CloudflareWorkerRoleV1::SignerARelayer, "SIGNER_A"),
            peer(CloudflareWorkerRoleV1::SignerB, "SIGNER_B"),
        )
        .expect("router bindings"),
    )
    .expect("router runtime");
    let err = runtime
        .public_request_admission_plan_at(
            2_000,
            public_router_request(2_000),
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
        signer_a_root_binding(),
        do_binding(
            CloudflareDurableObjectScopeV1::RouterLifecycle,
            "ROUTER_LIFECYCLE_DO",
        ),
        peer(CloudflareWorkerRoleV1::SignerARelayer, "SIGNER_A"),
        peer(CloudflareWorkerRoleV1::SignerB, "SIGNER_B"),
    )
    .expect_err("router must reject signer root-share binding");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::ForbiddenLocalBinding);
}

#[test]
fn signer_a_relayer_bindings_accept_a_root_and_relayer_output() {
    let bindings = CloudflareSignerARelayerBindingsV1::new(
        signer_a_root_binding(),
        signer_a_root_share_wire_secret_binding(),
        relayer_output_binding(),
        signer_a_envelope_decrypt_key(),
        signer_a_peer_signing_key(),
        cloudflare_peer_verifying_key_set(),
        peer(CloudflareWorkerRoleV1::SignerB, "SIGNER_B"),
    )
    .expect("signer a bindings");
    let startup = CloudflareWorkerBindingsV1::signer_a_relayer(bindings).expect("signer a startup");

    assert_eq!(
        startup.worker_role(),
        CloudflareWorkerRoleV1::SignerARelayer
    );
}

#[test]
fn signer_a_relayer_bindings_reject_b_root_share_scope() {
    let err = CloudflareSignerARelayerBindingsV1::new(
        signer_b_root_binding(),
        signer_a_root_share_wire_secret_binding(),
        relayer_output_binding(),
        signer_a_envelope_decrypt_key(),
        signer_a_peer_signing_key(),
        cloudflare_peer_verifying_key_set(),
        peer(CloudflareWorkerRoleV1::SignerB, "SIGNER_B"),
    )
    .expect_err("signer a must reject signer b root-share binding");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::ForbiddenLocalBinding);
}

#[test]
fn signer_a_relayer_bindings_reject_b_root_share_wire_secret() {
    let err = CloudflareSignerARelayerBindingsV1::new(
        signer_a_root_binding(),
        signer_b_root_share_wire_secret_binding(),
        relayer_output_binding(),
        signer_a_envelope_decrypt_key(),
        signer_a_peer_signing_key(),
        cloudflare_peer_verifying_key_set(),
        peer(CloudflareWorkerRoleV1::SignerB, "SIGNER_B"),
    )
    .expect_err("signer a must reject signer b root-share wire secret");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::ForbiddenLocalBinding);
}

#[test]
fn signer_a_relayer_bindings_reject_b_envelope_decrypt_key() {
    let err = CloudflareSignerARelayerBindingsV1::new(
        signer_a_root_binding(),
        signer_a_root_share_wire_secret_binding(),
        relayer_output_binding(),
        signer_b_envelope_decrypt_key(),
        signer_a_peer_signing_key(),
        cloudflare_peer_verifying_key_set(),
        peer(CloudflareWorkerRoleV1::SignerB, "SIGNER_B"),
    )
    .expect_err("signer a must reject signer b decrypt key");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::ForbiddenLocalBinding);
}

#[test]
fn signer_a_relayer_bindings_reject_b_peer_signing_key() {
    let err = CloudflareSignerARelayerBindingsV1::new(
        signer_a_root_binding(),
        signer_a_root_share_wire_secret_binding(),
        relayer_output_binding(),
        signer_a_envelope_decrypt_key(),
        signer_b_peer_signing_key(),
        cloudflare_peer_verifying_key_set(),
        peer(CloudflareWorkerRoleV1::SignerB, "SIGNER_B"),
    )
    .expect_err("signer a must reject signer b peer signing key");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::ForbiddenLocalBinding);
}

#[test]
fn signer_b_bindings_accept_b_root_share_scope() {
    let bindings = CloudflareSignerBBindingsV1::new(
        signer_b_root_binding(),
        signer_b_root_share_wire_secret_binding(),
        signer_b_envelope_decrypt_key(),
        signer_b_peer_signing_key(),
        cloudflare_peer_verifying_key_set(),
        peer(CloudflareWorkerRoleV1::SignerARelayer, "SIGNER_A"),
    )
    .expect("signer b bindings");
    let startup = CloudflareWorkerBindingsV1::signer_b(bindings).expect("signer b startup");

    assert_eq!(startup.worker_role(), CloudflareWorkerRoleV1::SignerB);
}

#[test]
fn signer_b_bindings_reject_relayer_output_scope() {
    let err = CloudflareSignerBBindingsV1::new(
        relayer_output_binding(),
        signer_b_root_share_wire_secret_binding(),
        signer_b_envelope_decrypt_key(),
        signer_b_peer_signing_key(),
        cloudflare_peer_verifying_key_set(),
        peer(CloudflareWorkerRoleV1::SignerARelayer, "SIGNER_A"),
    )
    .expect_err("signer b must reject relayer-output binding");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::ForbiddenLocalBinding);
}

#[test]
fn signer_b_bindings_reject_a_root_share_wire_secret() {
    let err = CloudflareSignerBBindingsV1::new(
        signer_b_root_binding(),
        signer_a_root_share_wire_secret_binding(),
        signer_b_envelope_decrypt_key(),
        signer_b_peer_signing_key(),
        cloudflare_peer_verifying_key_set(),
        peer(CloudflareWorkerRoleV1::SignerARelayer, "SIGNER_A"),
    )
    .expect_err("signer b must reject signer a root-share wire secret");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::ForbiddenLocalBinding);
}

#[test]
fn signer_b_bindings_reject_a_envelope_decrypt_key() {
    let err = CloudflareSignerBBindingsV1::new(
        signer_b_root_binding(),
        signer_b_root_share_wire_secret_binding(),
        signer_a_envelope_decrypt_key(),
        signer_b_peer_signing_key(),
        cloudflare_peer_verifying_key_set(),
        peer(CloudflareWorkerRoleV1::SignerARelayer, "SIGNER_A"),
    )
    .expect_err("signer b must reject signer a decrypt key");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::ForbiddenLocalBinding);
}

#[test]
fn signer_b_bindings_reject_a_peer_signing_key() {
    let err = CloudflareSignerBBindingsV1::new(
        signer_b_root_binding(),
        signer_b_root_share_wire_secret_binding(),
        signer_b_envelope_decrypt_key(),
        signer_a_peer_signing_key(),
        cloudflare_peer_verifying_key_set(),
        peer(CloudflareWorkerRoleV1::SignerARelayer, "SIGNER_A"),
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
    let signer_a = CloudflareSignerStartupCheckV1::signer_a(
        "signer-set-v1",
        root_epoch(),
        signer_a_root_binding(),
    )
    .expect("signer a startup check");
    let signer_b = CloudflareSignerStartupCheckV1::signer_b(
        "signer-set-v1",
        root_epoch(),
        signer_b_root_binding(),
    )
    .expect("signer b startup check");

    assert_eq!(signer_a.signer_role, Role::SignerA);
    assert_eq!(signer_b.signer_role, Role::SignerB);
}

#[test]
fn signer_startup_check_rejects_mismatched_root_share_binding() {
    let err = CloudflareSignerStartupCheckV1::signer_a(
        "signer-set-v1",
        root_epoch(),
        signer_b_root_binding(),
    )
    .expect_err("signer a startup must reject signer b root-share binding");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::ForbiddenLocalBinding);
}

#[test]
fn signer_a_runtime_builds_only_a_scoped_storage_calls() {
    let runtime = CloudflareSignerARelayerWorkerRuntimeV1::new(
        CloudflareSignerARelayerBindingsV1::new(
            signer_a_root_binding(),
            signer_a_root_share_wire_secret_binding(),
            relayer_output_binding(),
            signer_a_envelope_decrypt_key(),
            signer_a_peer_signing_key(),
            cloudflare_peer_verifying_key_set(),
            peer(CloudflareWorkerRoleV1::SignerB, "SIGNER_B"),
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
    let activation_call = runtime
        .relayer_output_activate_call(relayer_activation())
        .expect("relayer activation call");

    assert_eq!(has_call.worker_role, CloudflareWorkerRoleV1::SignerARelayer);
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
        activation_call.binding.scope,
        CloudflareDurableObjectScopeV1::signer_a_relayer_output()
    );
    assert_eq!(
        runtime.signer_b_peer().peer_role,
        CloudflareWorkerRoleV1::SignerB
    );
    assert_eq!(runtime.root_share_wire_secret().role, Role::SignerA);
    assert_eq!(runtime.envelope_decrypt_key().role, Role::SignerA);
    assert_eq!(runtime.peer_signing_key().role, Role::SignerA);
    assert_eq!(
        runtime
            .peer_verifying_keys_for_signer_set(&signer_set())
            .expect("signer a runtime verifying keys"),
        signer_verifying_keys()
    );
}

#[test]
fn signer_b_runtime_builds_only_b_scoped_storage_calls() {
    let runtime = CloudflareSignerBWorkerRuntimeV1::new(
        CloudflareSignerBBindingsV1::new(
            signer_b_root_binding(),
            signer_b_root_share_wire_secret_binding(),
            signer_b_envelope_decrypt_key(),
            signer_b_peer_signing_key(),
            cloudflare_peer_verifying_key_set(),
            peer(CloudflareWorkerRoleV1::SignerARelayer, "SIGNER_A"),
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

    assert_eq!(has_call.worker_role, CloudflareWorkerRoleV1::SignerB);
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
        runtime.signer_a_relayer_peer().peer_role,
        CloudflareWorkerRoleV1::SignerARelayer
    );
    assert_eq!(runtime.root_share_wire_secret().role, Role::SignerB);
    assert_eq!(runtime.envelope_decrypt_key().role, Role::SignerB);
    assert_eq!(runtime.peer_signing_key().role, Role::SignerB);
    assert_eq!(
        runtime
            .peer_verifying_keys_for_signer_set(&signer_set())
            .expect("signer b runtime verifying keys"),
        signer_verifying_keys()
    );
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
    let engine = SignerAEngine::new(host);
    assert_eq!(engine.host().now_unix_ms(), 1_000);
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
fn root_share_wire_secret_binding_decoder_accepts_visible_binding() {
    let decoded = decode_and_validate_cloudflare_root_share_wire_secret_v1(
        CloudflareWorkerRoleV1::SignerARelayer,
        &signer_a_root_share_wire_secret_binding(),
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
        CloudflareWorkerRoleV1::SignerARelayer,
        &signer_b_root_share_wire_secret_binding(),
        &root_share_metadata(Role::SignerB),
        &root_share_wire_secret(Role::SignerB),
    )
    .expect_err("signer a cannot decode signer b root-share wire secret");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::ForbiddenLocalBinding);
}

#[test]
fn root_share_wire_secret_binding_decoder_rejects_metadata_role_mismatch() {
    let err = decode_and_validate_cloudflare_root_share_wire_secret_v1(
        CloudflareWorkerRoleV1::SignerARelayer,
        &signer_a_root_share_wire_secret_binding(),
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
        vec![signer_response(digest(0x33), 0x80)],
        signer_verifying_keys(),
        0,
    )
    .expect_err("signer response cannot be preloaded as peer response");

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
fn durable_object_binding_rejects_non_a_relayer_output_owner() {
    let err = CloudflareDurableObjectBindingV1::new(
        CloudflareDurableObjectScopeV1::RelayerOutput {
            owner_role: Role::SignerB,
        },
        "BAD_RELAYER_OUTPUT_DO",
        "bad-relayer-output",
        "bad-relayer-output:",
    )
    .expect_err("v1 relayer output must be owned by signer a");

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
        bindings.signer_a.peer_role,
        CloudflareWorkerRoleV1::SignerARelayer
    );
    assert_eq!(bindings.signer_b.binding_name, "SIGNER_B");
}

#[test]
fn env_parser_builds_signer_a_relayer_bindings_from_required_keys() {
    let bindings =
        parse_cloudflare_signer_a_relayer_bindings_v1(&signer_a_env()).expect("signer a env");

    assert_eq!(bindings.root_share.binding_name, "SIGNER_A_ROOT_SHARE_DO");
    assert_eq!(
        bindings.root_share.scope,
        CloudflareDurableObjectScopeV1::SignerRootShare {
            role: Role::SignerA
        }
    );
    assert_eq!(
        bindings.relayer_output.scope,
        CloudflareDurableObjectScopeV1::signer_a_relayer_output()
    );
    assert_eq!(
        bindings.root_share_wire_secret.binding_name,
        "SIGNER_A_ROOT_SHARE_WIRE_SECRET"
    );
    assert_eq!(bindings.root_share_wire_secret.role, Role::SignerA);
    assert_eq!(
        bindings.envelope_decrypt_key.binding_name,
        "SIGNER_A_ENVELOPE_AEAD_KEY"
    );
    assert_eq!(
        bindings.envelope_decrypt_key.key_epoch,
        "envelope-key-epoch-a"
    );
    assert_eq!(
        bindings.peer_signing_key.binding_name,
        "SIGNER_A_PEER_SIGNING_KEY"
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
fn env_parser_builds_signer_b_bindings_from_required_keys() {
    let bindings = parse_cloudflare_signer_b_bindings_v1(&signer_b_env()).expect("signer b env");

    assert_eq!(bindings.root_share.binding_name, "SIGNER_B_ROOT_SHARE_DO");
    assert_eq!(
        bindings.root_share.scope,
        CloudflareDurableObjectScopeV1::SignerRootShare {
            role: Role::SignerB
        }
    );
    assert_eq!(
        bindings.signer_a_relayer.peer_role,
        CloudflareWorkerRoleV1::SignerARelayer
    );
    assert_eq!(
        bindings.root_share_wire_secret.binding_name,
        "SIGNER_B_ROOT_SHARE_WIRE_SECRET"
    );
    assert_eq!(bindings.root_share_wire_secret.role, Role::SignerB);
    assert_eq!(
        bindings.envelope_decrypt_key.binding_name,
        "SIGNER_B_ENVELOPE_AEAD_KEY"
    );
    assert_eq!(
        bindings.envelope_decrypt_key.key_epoch,
        "envelope-key-epoch-b"
    );
    assert_eq!(
        bindings.peer_signing_key.binding_name,
        "SIGNER_B_PEER_SIGNING_KEY"
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
fn env_parser_rejects_router_with_signer_envelope_decrypt_key_binding() {
    let env = CloudflareEnvMapV1::new(vec![(
        SIGNER_A_ENVELOPE_AEAD_KEY_BINDING_ENV,
        "SIGNER_A_ENVELOPE_AEAD_KEY",
    )]);

    let err = parse_cloudflare_worker_bindings_v1(CloudflareWorkerRoleV1::Router, &env)
        .expect_err("router must reject signer decrypt key env");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::ForbiddenLocalBinding);
}

#[test]
fn env_parser_rejects_router_with_signer_peer_signing_key_binding() {
    let env = CloudflareEnvMapV1::new(vec![(
        SIGNER_A_PEER_SIGNING_KEY_BINDING_ENV,
        "SIGNER_A_PEER_SIGNING_KEY",
    )]);

    let err = parse_cloudflare_worker_bindings_v1(CloudflareWorkerRoleV1::Router, &env)
        .expect_err("router must reject signer peer signing key env");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::ForbiddenLocalBinding);
}

#[test]
fn env_parser_rejects_router_with_signer_root_share_wire_secret_binding() {
    let env = CloudflareEnvMapV1::new(vec![(
        SIGNER_A_ROOT_SHARE_WIRE_SECRET_BINDING_ENV,
        "SIGNER_A_ROOT_SHARE_WIRE_SECRET",
    )]);

    let err = parse_cloudflare_worker_bindings_v1(CloudflareWorkerRoleV1::Router, &env)
        .expect_err("router must reject signer root-share wire secret env");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::ForbiddenLocalBinding);
}

#[test]
fn env_parser_rejects_signer_a_with_signer_b_envelope_decrypt_key_binding() {
    let env = CloudflareEnvMapV1::new(vec![(
        SIGNER_B_ENVELOPE_AEAD_KEY_BINDING_ENV,
        "SIGNER_B_ENVELOPE_AEAD_KEY",
    )]);

    let err = parse_cloudflare_worker_bindings_v1(CloudflareWorkerRoleV1::SignerARelayer, &env)
        .expect_err("signer a must reject signer b decrypt key env");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::ForbiddenLocalBinding);
}

#[test]
fn env_parser_rejects_signer_a_with_signer_b_peer_signing_key_binding() {
    let env = CloudflareEnvMapV1::new(vec![(
        SIGNER_B_PEER_SIGNING_KEY_BINDING_ENV,
        "SIGNER_B_PEER_SIGNING_KEY",
    )]);

    let err = parse_cloudflare_worker_bindings_v1(CloudflareWorkerRoleV1::SignerARelayer, &env)
        .expect_err("signer a must reject signer b peer signing key env");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::ForbiddenLocalBinding);
}

#[test]
fn env_parser_rejects_signer_a_with_signer_b_root_share_wire_secret_binding() {
    let env = CloudflareEnvMapV1::new(vec![(
        SIGNER_B_ROOT_SHARE_WIRE_SECRET_BINDING_ENV,
        "SIGNER_B_ROOT_SHARE_WIRE_SECRET",
    )]);

    let err = parse_cloudflare_worker_bindings_v1(CloudflareWorkerRoleV1::SignerARelayer, &env)
        .expect_err("signer a must reject signer b root-share wire secret env");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::ForbiddenLocalBinding);
}

#[test]
fn env_parser_rejects_signer_b_with_signer_a_envelope_decrypt_key_binding() {
    let env = CloudflareEnvMapV1::new(vec![(
        SIGNER_A_ENVELOPE_AEAD_KEY_BINDING_ENV,
        "SIGNER_A_ENVELOPE_AEAD_KEY",
    )]);

    let err = parse_cloudflare_worker_bindings_v1(CloudflareWorkerRoleV1::SignerB, &env)
        .expect_err("signer b must reject signer a decrypt key env");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::ForbiddenLocalBinding);
}

#[test]
fn env_parser_rejects_signer_b_with_signer_a_peer_signing_key_binding() {
    let env = CloudflareEnvMapV1::new(vec![(
        SIGNER_A_PEER_SIGNING_KEY_BINDING_ENV,
        "SIGNER_A_PEER_SIGNING_KEY",
    )]);

    let err = parse_cloudflare_worker_bindings_v1(CloudflareWorkerRoleV1::SignerB, &env)
        .expect_err("signer b must reject signer a peer signing key env");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::ForbiddenLocalBinding);
}

#[test]
fn env_parser_rejects_signer_b_with_signer_a_root_share_wire_secret_binding() {
    let env = CloudflareEnvMapV1::new(vec![(
        SIGNER_A_ROOT_SHARE_WIRE_SECRET_BINDING_ENV,
        "SIGNER_A_ROOT_SHARE_WIRE_SECRET",
    )]);

    let err = parse_cloudflare_worker_bindings_v1(CloudflareWorkerRoleV1::SignerB, &env)
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
        (SIGNER_A_PEER_BINDING_ENV, "SIGNER_A"),
    ]);

    let err = parse_cloudflare_worker_bindings_v1(CloudflareWorkerRoleV1::Router, &env)
        .expect_err("missing signer b peer must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::MissingLocalBinding);
}

#[test]
fn env_parser_rejects_empty_required_key_after_trimming() {
    let env = CloudflareEnvMapV1::new(vec![
        (SIGNER_B_ROOT_SHARE_DO_BINDING_ENV, "SIGNER_B_ROOT_SHARE_DO"),
        (SIGNER_B_ROOT_SHARE_DO_OBJECT_ENV, "  "),
        (
            SIGNER_B_ROOT_SHARE_DO_KEY_PREFIX_ENV,
            "signer-b-root-share:",
        ),
        (SIGNER_A_PEER_BINDING_ENV, "SIGNER_A"),
    ]);

    let err = parse_cloudflare_worker_bindings_v1(CloudflareWorkerRoleV1::SignerB, &env)
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
        (SIGNER_A_PEER_BINDING_ENV, "SIGNER_A"),
        (SIGNER_B_PEER_BINDING_ENV, "SIGNER_B"),
        (SIGNER_A_ROOT_SHARE_DO_BINDING_ENV, "SIGNER_A_ROOT_SHARE_DO"),
    ]);

    let err = parse_cloudflare_worker_bindings_v1(CloudflareWorkerRoleV1::Router, &env)
        .expect_err("router env must reject signer storage key");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::ForbiddenLocalBinding);
}

#[test]
fn env_parser_rejects_signer_env_with_router_admission_key() {
    let env = CloudflareEnvMapV1::new(vec![(ROUTER_JWT_ISSUER_ENV, "https://issuer.example")]);

    let err = parse_cloudflare_worker_bindings_v1(CloudflareWorkerRoleV1::SignerARelayer, &env)
        .expect_err("signer env must reject router admission key");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::ForbiddenLocalBinding);
}

#[test]
fn env_parser_rejects_signer_a_env_with_signer_b_root_share_key() {
    let env = CloudflareEnvMapV1::new(vec![
        (SIGNER_A_ROOT_SHARE_DO_BINDING_ENV, "SIGNER_A_ROOT_SHARE_DO"),
        (SIGNER_A_ROOT_SHARE_DO_OBJECT_ENV, "signer-a-root-share"),
        (
            SIGNER_A_ROOT_SHARE_DO_KEY_PREFIX_ENV,
            "signer-a-root-share:",
        ),
        (
            SIGNER_A_RELAYER_OUTPUT_DO_BINDING_ENV,
            "SIGNER_A_RELAYER_OUTPUT_DO",
        ),
        (
            SIGNER_A_RELAYER_OUTPUT_DO_OBJECT_ENV,
            "signer-a-relayer-output",
        ),
        (
            SIGNER_A_RELAYER_OUTPUT_DO_KEY_PREFIX_ENV,
            "signer-a-relayer-output:",
        ),
        (SIGNER_B_PEER_BINDING_ENV, "SIGNER_B"),
        (SIGNER_B_ROOT_SHARE_DO_BINDING_ENV, "SIGNER_B_ROOT_SHARE_DO"),
    ]);

    let err = parse_cloudflare_worker_bindings_v1(CloudflareWorkerRoleV1::SignerARelayer, &env)
        .expect_err("signer a env must reject signer b storage key");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::ForbiddenLocalBinding);
}

#[test]
fn env_parser_rejects_signer_b_env_with_relayer_output_key() {
    let env = CloudflareEnvMapV1::new(vec![
        (SIGNER_B_ROOT_SHARE_DO_BINDING_ENV, "SIGNER_B_ROOT_SHARE_DO"),
        (SIGNER_B_ROOT_SHARE_DO_OBJECT_ENV, "signer-b-root-share"),
        (
            SIGNER_B_ROOT_SHARE_DO_KEY_PREFIX_ENV,
            "signer-b-root-share:",
        ),
        (SIGNER_A_PEER_BINDING_ENV, "SIGNER_A"),
        (
            SIGNER_A_RELAYER_OUTPUT_DO_BINDING_ENV,
            "SIGNER_A_RELAYER_OUTPUT_DO",
        ),
    ]);

    let err = parse_cloudflare_worker_bindings_v1(CloudflareWorkerRoleV1::SignerB, &env)
        .expect_err("signer b env must reject relayer-output key");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::ForbiddenLocalBinding);
}

#[test]
fn durable_object_call_routes_root_share_has_to_signer_scope() {
    let lookup =
        CloudflareRootShareLookupRequestV1::new("signer-set-v1", Role::SignerA, root_epoch())
            .expect("lookup");
    let request = CloudflareDurableObjectRequestV1::root_share_has(lookup).expect("request");
    let call = CloudflareDurableObjectCallV1::new(
        CloudflareWorkerRoleV1::SignerARelayer,
        signer_a_root_binding(),
        request,
    )
    .expect("call");

    assert_eq!(
        call.operation_kind(),
        CloudflareDurableObjectOperationKindV1::RootShareHas
    );
    assert_eq!(
        call.durable_object_url(),
        "https://router-ab-durable-object.internal/router-ab/do/v1/root-share/has"
    );
    assert_eq!(
        call.storage_key(),
        "SIGNER_A_ROOT_SHARE_DO:root-share/signer-set-v1/signer_a/epoch-1"
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
        signer_a_root_binding(),
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
        CloudflareWorkerRoleV1::SignerB,
        signer_b_root_binding(),
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
}

#[test]
fn durable_object_call_routes_relayer_activation_to_signer_a_relayer_scope() {
    let request = CloudflareDurableObjectRequestV1::relayer_output_activate(relayer_activation())
        .expect("activation request");
    let call = CloudflareDurableObjectCallV1::new(
        CloudflareWorkerRoleV1::SignerARelayer,
        relayer_output_binding(),
        request,
    )
    .expect("activation call");

    assert_eq!(
        call.operation_kind(),
        CloudflareDurableObjectOperationKindV1::RelayerOutputActivate
    );
    assert_eq!(
        call.storage_key(),
        "SIGNER_A_RELAYER_OUTPUT_DO:relayer-output/lifecycle-1/4444444444444444444444444444444444444444444444444444444444444444"
    );
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
fn durable_object_response_validates_relayer_activation_receipt() {
    let activation = relayer_activation();
    let request = CloudflareDurableObjectRequestV1::relayer_output_activate(activation)
        .expect("activation request");
    let response = CloudflareDurableObjectResponseV1::relayer_output_activate(
        CloudflareRelayerOutputActivationReceiptV1::new(
            "lifecycle-1",
            "relayer-a",
            digest(0x44),
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
fn durable_object_handler_serves_root_share_presence_and_metadata() {
    let lookup =
        CloudflareRootShareLookupRequestV1::new("signer-set-v1", Role::SignerA, root_epoch())
            .expect("lookup");
    let has_request =
        CloudflareDurableObjectRequestV1::root_share_has(lookup.clone()).expect("has request");
    let has_call = CloudflareDurableObjectCallV1::new(
        CloudflareWorkerRoleV1::SignerARelayer,
        signer_a_root_binding(),
        has_request,
    )
    .expect("has call");
    let metadata_request = CloudflareDurableObjectRequestV1::root_share_startup_metadata(lookup)
        .expect("metadata request");
    let metadata_call = CloudflareDurableObjectCallV1::new(
        CloudflareWorkerRoleV1::SignerARelayer,
        signer_a_root_binding(),
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
fn durable_object_router_storage_surface_is_public_state_and_hashes() {
    let public_request = public_router_request(2_000);
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
fn durable_object_handler_activates_relayer_output_idempotently() {
    let activation = relayer_activation();
    let call = CloudflareDurableObjectCallV1::new(
        CloudflareWorkerRoleV1::SignerARelayer,
        relayer_output_binding(),
        CloudflareDurableObjectRequestV1::relayer_output_activate(activation.clone())
            .expect("activation request"),
    )
    .expect("activation call");
    let mut storage = CloudflareDurableObjectMemoryStorageV1::new();

    let first =
        handle_cloudflare_durable_object_call_v1(&call, &mut storage).expect("first activation");
    assert_eq!(
        first,
        CloudflareDurableObjectResponseV1::relayer_output_activate(
            CloudflareRelayerOutputActivationReceiptV1::new(
                "lifecycle-1",
                "relayer-a",
                digest(0x44),
                true,
            )
            .expect("first receipt")
        )
        .expect("first response")
    );
    assert_eq!(
        storage.relayer_activation(&call.storage_key()),
        Some(&activation)
    );

    let second = handle_cloudflare_durable_object_call_v1(&call, &mut storage)
        .expect("idempotent activation");
    assert_eq!(
        second,
        CloudflareDurableObjectResponseV1::relayer_output_activate(
            CloudflareRelayerOutputActivationReceiptV1::new(
                "lifecycle-1",
                "relayer-a",
                digest(0x44),
                false,
            )
            .expect("second receipt")
        )
        .expect("second response")
    );

    let mut conflicting_activation = relayer_activation();
    conflicting_activation.relayer = RelayerIdentityV1::new(
        "relayer-b",
        "relayer-epoch",
        "x25519:1111111111111111111111111111111111111111111111111111111111111111",
    )
    .expect("conflicting relayer");
    let conflicting_call = CloudflareDurableObjectCallV1::new(
        CloudflareWorkerRoleV1::SignerARelayer,
        relayer_output_binding(),
        CloudflareDurableObjectRequestV1::relayer_output_activate(conflicting_activation)
            .expect("conflicting activation request"),
    )
    .expect("conflicting activation call");
    let err = handle_cloudflare_durable_object_call_v1(&conflicting_call, &mut storage)
        .expect_err("conflicting relayer activation must fail");

    assert_eq!(
        err.code(),
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig
    );
}
