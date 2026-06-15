use base64ct::{Base64UrlUnpadded, Encoding};
use router_ab_core::{
    derive_router_ab_ed25519_normal_signing_admission_material_v2,
    parse_router_ab_ed25519_normal_signing_finalize_request_v2_json,
    parse_router_ab_ed25519_normal_signing_prepare_request_v2_json,
    router_ab_ed25519_nep413_canonical_message_b64u_v2, NormalSigningScopeV1, PublicDigest32,
    RouterAbEd25519NormalSigningFinalizeProtocolV2, RouterAbEd25519NormalSigningFinalizeRequestV2,
    RouterAbEd25519NormalSigningIntentV2, RouterAbEd25519NormalSigningPrepareBindingV2,
    RouterAbEd25519NormalSigningPrepareRequestV2, RouterAbEd25519SigningPayloadV2,
    RouterAbEd25519TwoPartyFrostFinalizeProtocolV2, RouterAbNearDelegateActionIntentV1,
    RouterAbNearNetworkIdV2, RouterAbNearTransactionIntentV1, RouterAbProtocolErrorCode,
};
use sha2::{Digest, Sha256};

fn b64u(bytes: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(bytes)
}

fn decode_b64u(value: &str) -> Vec<u8> {
    Base64UrlUnpadded::decode_vec(value).expect("base64url fixture decodes")
}

fn digest(bytes: &[u8]) -> PublicDigest32 {
    let digest = Sha256::digest(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    PublicDigest32::new(out)
}

fn digest_b64u(bytes: &[u8]) -> String {
    b64u(digest(bytes).as_bytes())
}

fn action_fingerprint(json: &str) -> String {
    digest_b64u(json.as_bytes())
}

fn fixture_public_key_string() -> &'static str {
    "ed25519:11111111111111111111111111111111"
}

fn push_borsh_string(out: &mut Vec<u8>, value: &str) {
    out.extend_from_slice(&(value.len() as u32).to_le_bytes());
    out.extend_from_slice(value.as_bytes());
}

fn push_borsh_bytes(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u32).to_le_bytes());
    out.extend_from_slice(value);
}

fn fixture_near_unsigned_transaction_borsh() -> Vec<u8> {
    let mut out = Vec::new();
    push_borsh_string(&mut out, "alice.testnet");
    out.push(0);
    out.extend_from_slice(&[0; 32]);
    out.extend_from_slice(&7_u64.to_le_bytes());
    push_borsh_string(&mut out, "contract.testnet");
    out.extend_from_slice(&[0x44; 32]);
    out.extend_from_slice(&1_u32.to_le_bytes());
    out.push(2);
    push_borsh_string(&mut out, "transfer");
    push_borsh_bytes(&mut out, br#"{"amount":"1"}"#);
    out.extend_from_slice(&30_000_000_000_000_u64.to_le_bytes());
    out.extend_from_slice(&0_u128.to_le_bytes());
    out
}

fn fixture_near_transaction_action_fingerprint() -> String {
    action_fingerprint(
        r#"[{"action_type":"FunctionCall","args":"{\"amount\":\"1\"}","deposit":"0","gas":"30000000000000","method_name":"transfer"}]"#,
    )
}

fn fixture_canonical_delegate_borsh() -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&1_073_742_190_u32.to_le_bytes());
    push_borsh_string(&mut out, "alice.testnet");
    push_borsh_string(&mut out, "contract.testnet");
    out.extend_from_slice(&1_u32.to_le_bytes());
    out.push(3);
    out.extend_from_slice(&1_u128.to_le_bytes());
    out.extend_from_slice(&7_u64.to_le_bytes());
    out.extend_from_slice(&999_999_u64.to_le_bytes());
    out.push(0);
    out.extend_from_slice(&[0; 32]);
    out
}

fn fixture_delegate_action_fingerprint() -> String {
    action_fingerprint(r#"[{"action_type":"Transfer","deposit":"1"}]"#)
}

fn normal_scope() -> NormalSigningScopeV1 {
    NormalSigningScopeV1::new(
        "router-ab-normal-signing/request-1",
        "alice.testnet",
        "session-1",
        "signing-worker-1",
    )
    .expect("scope")
}

fn near_transaction_intent(
    unsigned_transaction_borsh_b64u: String,
) -> RouterAbEd25519NormalSigningIntentV2 {
    RouterAbEd25519NormalSigningIntentV2::NearTransactionV1 {
        operation_id: "operation-1".to_owned(),
        operation_fingerprint: "fingerprint-1".to_owned(),
        near_account_id: "alice.testnet".to_owned(),
        near_network_id: RouterAbNearNetworkIdV2::Testnet,
        transactions: vec![RouterAbNearTransactionIntentV1::new(
            "contract.testnet",
            fixture_near_transaction_action_fingerprint(),
        )
        .expect("transaction intent")],
        unsigned_transaction_borsh_b64u,
    }
}

fn near_transaction_payload(preimage_b64u: String) -> RouterAbEd25519SigningPayloadV2 {
    let preimage = decode_b64u(&preimage_b64u);
    RouterAbEd25519SigningPayloadV2::NearUnsignedTransactionBorshV1 {
        unsigned_transaction_borsh_b64u: preimage_b64u,
        expected_signing_digest_b64u: digest_b64u(&preimage),
    }
}

fn nep413_payload(canonical_message_b64u: String) -> RouterAbEd25519SigningPayloadV2 {
    let preimage = decode_b64u(&canonical_message_b64u);
    RouterAbEd25519SigningPayloadV2::Nep413MessageV1 {
        canonical_message_b64u,
        expected_signing_digest_b64u: digest_b64u(&preimage),
    }
}

fn finalize_protocol() -> RouterAbEd25519NormalSigningFinalizeProtocolV2 {
    RouterAbEd25519NormalSigningFinalizeProtocolV2::Ed25519TwoPartyFrostFinalizeV1(
        RouterAbEd25519TwoPartyFrostFinalizeProtocolV2::new(
            fixture_public_key_string(),
            router_ab_core::NormalSigningEd25519TwoPartyFrostCommitmentsV1::new(
                b64u(&[0x11; 32]),
                b64u(&[0x12; 32]),
            )
            .expect("client commitments"),
            router_ab_core::NormalSigningEd25519TwoPartyFrostCommitmentsV1::new(
                b64u(&[0x21; 32]),
                b64u(&[0x22; 32]),
            )
            .expect("server commitments"),
            b64u(&[0x31; 32]),
            b64u(&[0x32; 32]),
            b64u(&[0x41; 32]),
        )
        .expect("finalize protocol"),
    )
}

fn prepare_request_fixture() -> RouterAbEd25519NormalSigningPrepareRequestV2 {
    let preimage = fixture_near_unsigned_transaction_borsh();
    let preimage_b64u = b64u(&preimage);
    RouterAbEd25519NormalSigningPrepareRequestV2::new(
        normal_scope(),
        1_900_000_000_000,
        near_transaction_intent(preimage_b64u.clone()),
        near_transaction_payload(preimage_b64u),
    )
    .expect("prepare request")
}

fn finalize_request_fixture() -> RouterAbEd25519NormalSigningFinalizeRequestV2 {
    let prepare_request = prepare_request_fixture();
    let material = prepare_request
        .admission_material()
        .expect("admission material");
    let prepare_binding = RouterAbEd25519NormalSigningPrepareBindingV2::new(
        "server-round1/sign-request-1",
        prepare_request
            .round1_binding_digest()
            .expect("round1 binding"),
        material.intent_digest,
        material.signing_payload_digest,
    )
    .expect("prepare binding");
    RouterAbEd25519NormalSigningFinalizeRequestV2::new(
        normal_scope(),
        prepare_request.expires_at_ms,
        prepare_binding,
        finalize_protocol(),
    )
    .expect("finalize request")
}

#[test]
fn near_transaction_v2_admission_material_derives_from_typed_payload() {
    let preimage = fixture_near_unsigned_transaction_borsh();
    let preimage_b64u = b64u(&preimage);
    let intent = near_transaction_intent(preimage_b64u.clone());
    let payload = near_transaction_payload(preimage_b64u);

    let material = derive_router_ab_ed25519_normal_signing_admission_material_v2(&intent, &payload)
        .expect("admission material");
    let request = RouterAbEd25519NormalSigningPrepareRequestV2::new(
        normal_scope(),
        1_900_000_000_000,
        intent,
        payload,
    )
    .expect("prepare request");

    assert_eq!(material.admitted_signing_digest, digest(&preimage));
    assert_eq!(
        request.round1_binding_digest().expect("round1 binding"),
        material
            .round1_binding_digest(&request.scope, request.expires_at_ms)
            .expect("material binding")
    );
}

#[test]
fn v2_prepare_boundary_parser_rejects_unknown_top_level_and_scope_fields() {
    let request = prepare_request_fixture();
    let parsed = parse_router_ab_ed25519_normal_signing_prepare_request_v2_json(
        &serde_json::to_vec(&request).expect("prepare request json"),
    )
    .expect("prepare request parses");
    assert_eq!(parsed, request);

    let mut with_legacy_grant = serde_json::to_value(&request).expect("prepare request value");
    with_legacy_grant
        .as_object_mut()
        .expect("prepare object")
        .insert(
            "threshold_session_grant".to_owned(),
            serde_json::json!("legacy-grant"),
        );
    let err = parse_router_ab_ed25519_normal_signing_prepare_request_v2_json(
        &serde_json::to_vec(&with_legacy_grant).expect("legacy prepare json"),
    )
    .expect_err("legacy grant field must fail");
    assert_eq!(err.code(), RouterAbProtocolErrorCode::MalformedWirePayload);

    let mut with_legacy_scope = serde_json::to_value(&request).expect("prepare request value");
    with_legacy_scope["scope"]
        .as_object_mut()
        .expect("scope object")
        .insert(
            "threshold_session_id".to_owned(),
            serde_json::json!("legacy-session"),
        );
    let err = parse_router_ab_ed25519_normal_signing_prepare_request_v2_json(
        &serde_json::to_vec(&with_legacy_scope).expect("legacy scope json"),
    )
    .expect_err("legacy scope field must fail");
    assert_eq!(err.code(), RouterAbProtocolErrorCode::MalformedWirePayload);
}

#[test]
fn v2_finalize_boundary_parser_rejects_unknown_prepare_and_protocol_fields() {
    let request = finalize_request_fixture();
    let parsed = parse_router_ab_ed25519_normal_signing_finalize_request_v2_json(
        &serde_json::to_vec(&request).expect("finalize request json"),
    )
    .expect("finalize request parses");
    assert_eq!(parsed, request);

    let mut with_legacy_prepare = serde_json::to_value(&request).expect("finalize request value");
    with_legacy_prepare["prepare_binding"]
        .as_object_mut()
        .expect("prepare binding object")
        .insert(
            "server_normal_signing_session".to_owned(),
            serde_json::json!("legacy-session"),
        );
    let err = parse_router_ab_ed25519_normal_signing_finalize_request_v2_json(
        &serde_json::to_vec(&with_legacy_prepare).expect("legacy finalize json"),
    )
    .expect_err("legacy prepare field must fail");
    assert_eq!(err.code(), RouterAbProtocolErrorCode::MalformedWirePayload);

    let mut with_legacy_protocol = serde_json::to_value(&request).expect("finalize request value");
    with_legacy_protocol["protocol"]
        .as_object_mut()
        .expect("protocol object")
        .insert(
            "threshold_session_id".to_owned(),
            serde_json::json!("legacy-session"),
        );
    let err = parse_router_ab_ed25519_normal_signing_finalize_request_v2_json(
        &serde_json::to_vec(&with_legacy_protocol).expect("legacy protocol json"),
    )
    .expect_err("legacy protocol field must fail");
    assert_eq!(err.code(), RouterAbProtocolErrorCode::MalformedWirePayload);
}

#[test]
fn near_transaction_v2_rejects_receiver_metadata_drift_from_preimage() {
    let preimage = fixture_near_unsigned_transaction_borsh();
    let preimage_b64u = b64u(&preimage);
    let intent = RouterAbEd25519NormalSigningIntentV2::NearTransactionV1 {
        operation_id: "operation-1".to_owned(),
        operation_fingerprint: "fingerprint-1".to_owned(),
        near_account_id: "alice.testnet".to_owned(),
        near_network_id: RouterAbNearNetworkIdV2::Testnet,
        transactions: vec![RouterAbNearTransactionIntentV1::new(
            "other-contract.testnet",
            fixture_near_transaction_action_fingerprint(),
        )
        .expect("transaction intent")],
        unsigned_transaction_borsh_b64u: preimage_b64u.clone(),
    };
    let payload = near_transaction_payload(preimage_b64u);

    let err = derive_router_ab_ed25519_normal_signing_admission_material_v2(&intent, &payload)
        .expect_err("receiver drift must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::MalformedWirePayload);
}

#[test]
fn near_transaction_v2_rejects_action_fingerprint_drift_from_preimage() {
    let preimage = fixture_near_unsigned_transaction_borsh();
    let preimage_b64u = b64u(&preimage);
    let intent = RouterAbEd25519NormalSigningIntentV2::NearTransactionV1 {
        operation_id: "operation-1".to_owned(),
        operation_fingerprint: "fingerprint-1".to_owned(),
        near_account_id: "alice.testnet".to_owned(),
        near_network_id: RouterAbNearNetworkIdV2::Testnet,
        transactions: vec![RouterAbNearTransactionIntentV1::new(
            "contract.testnet",
            action_fingerprint(r#"[{"action_type":"Transfer","deposit":"1"}]"#),
        )
        .expect("transaction intent")],
        unsigned_transaction_borsh_b64u: preimage_b64u.clone(),
    };
    let payload = near_transaction_payload(preimage_b64u);

    let err = derive_router_ab_ed25519_normal_signing_admission_material_v2(&intent, &payload)
        .expect_err("action fingerprint drift must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::MalformedWirePayload);
}

#[test]
fn nep413_v2_admission_requires_canonical_message_from_intent() {
    let nonce_b64u = b64u(&[0x41; 32]);
    let canonical_message_b64u = router_ab_ed25519_nep413_canonical_message_b64u_v2(
        "Sign in to Seams",
        "wallet.example.near",
        &nonce_b64u,
        Some("https://example.com/callback"),
    )
    .expect("canonical nep413 message");
    let intent = RouterAbEd25519NormalSigningIntentV2::Nep413V1 {
        operation_id: "operation-nep413".to_owned(),
        operation_fingerprint: "fingerprint-nep413".to_owned(),
        near_account_id: "alice.testnet".to_owned(),
        near_network_id: RouterAbNearNetworkIdV2::Testnet,
        recipient: "wallet.example.near".to_owned(),
        message: "Sign in to Seams".to_owned(),
        nonce_b64u,
        callback_url: Some("https://example.com/callback".to_owned()),
    };
    let payload = nep413_payload(canonical_message_b64u);

    let material = derive_router_ab_ed25519_normal_signing_admission_material_v2(&intent, &payload)
        .expect("admission material");

    assert_eq!(
        material.admitted_signing_digest,
        payload.admitted_signing_digest().expect("payload digest")
    );
}

#[test]
fn delegate_action_v2_admission_binds_delegate_preimage() {
    let delegate_preimage = fixture_canonical_delegate_borsh();
    let delegate_preimage_b64u = b64u(&delegate_preimage);
    let delegate = RouterAbNearDelegateActionIntentV1::new(
        "alice.testnet",
        "contract.testnet",
        fixture_public_key_string(),
        "7",
        "999999",
        fixture_delegate_action_fingerprint(),
        delegate_preimage_b64u.clone(),
    )
    .expect("delegate intent");
    let intent = RouterAbEd25519NormalSigningIntentV2::NearDelegateActionV1 {
        operation_id: "operation-delegate".to_owned(),
        operation_fingerprint: "fingerprint-delegate".to_owned(),
        near_account_id: "alice.testnet".to_owned(),
        near_network_id: RouterAbNearNetworkIdV2::Testnet,
        delegate,
    };
    let payload = RouterAbEd25519SigningPayloadV2::NearDelegateActionV1 {
        canonical_delegate_borsh_b64u: delegate_preimage_b64u,
        expected_signing_digest_b64u: digest_b64u(&delegate_preimage),
    };

    let material = derive_router_ab_ed25519_normal_signing_admission_material_v2(&intent, &payload)
        .expect("admission material");

    assert_eq!(material.admitted_signing_digest, digest(&delegate_preimage));
}

#[test]
fn delegate_action_v2_rejects_metadata_drift_from_preimage() {
    let delegate_preimage = fixture_canonical_delegate_borsh();
    let delegate_preimage_b64u = b64u(&delegate_preimage);
    let delegate = RouterAbNearDelegateActionIntentV1::new(
        "alice.testnet",
        "other-contract.testnet",
        fixture_public_key_string(),
        "7",
        "999999",
        fixture_delegate_action_fingerprint(),
        delegate_preimage_b64u.clone(),
    )
    .expect("delegate intent");
    let intent = RouterAbEd25519NormalSigningIntentV2::NearDelegateActionV1 {
        operation_id: "operation-delegate".to_owned(),
        operation_fingerprint: "fingerprint-delegate".to_owned(),
        near_account_id: "alice.testnet".to_owned(),
        near_network_id: RouterAbNearNetworkIdV2::Testnet,
        delegate,
    };
    let payload = RouterAbEd25519SigningPayloadV2::NearDelegateActionV1 {
        canonical_delegate_borsh_b64u: delegate_preimage_b64u,
        expected_signing_digest_b64u: digest_b64u(&delegate_preimage),
    };

    let err = derive_router_ab_ed25519_normal_signing_admission_material_v2(&intent, &payload)
        .expect_err("delegate receiver drift must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::MalformedWirePayload);
}

#[test]
fn delegate_action_v2_rejects_action_fingerprint_drift_from_preimage() {
    let delegate_preimage = fixture_canonical_delegate_borsh();
    let delegate_preimage_b64u = b64u(&delegate_preimage);
    let delegate = RouterAbNearDelegateActionIntentV1::new(
        "alice.testnet",
        "contract.testnet",
        fixture_public_key_string(),
        "7",
        "999999",
        fixture_near_transaction_action_fingerprint(),
        delegate_preimage_b64u.clone(),
    )
    .expect("delegate intent");
    let intent = RouterAbEd25519NormalSigningIntentV2::NearDelegateActionV1 {
        operation_id: "operation-delegate".to_owned(),
        operation_fingerprint: "fingerprint-delegate".to_owned(),
        near_account_id: "alice.testnet".to_owned(),
        near_network_id: RouterAbNearNetworkIdV2::Testnet,
        delegate,
    };
    let payload = RouterAbEd25519SigningPayloadV2::NearDelegateActionV1 {
        canonical_delegate_borsh_b64u: delegate_preimage_b64u,
        expected_signing_digest_b64u: digest_b64u(&delegate_preimage),
    };

    let err = derive_router_ab_ed25519_normal_signing_admission_material_v2(&intent, &payload)
        .expect_err("delegate action fingerprint drift must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::MalformedWirePayload);
}

#[test]
fn v2_payload_rejects_expected_signing_digest_drift() {
    let preimage = b"unsigned-near-transaction-borsh-v1";
    let preimage_b64u = b64u(preimage);
    let intent = near_transaction_intent(preimage_b64u.clone());
    let payload = RouterAbEd25519SigningPayloadV2::NearUnsignedTransactionBorshV1 {
        unsigned_transaction_borsh_b64u: preimage_b64u,
        expected_signing_digest_b64u: b64u(&[0x99; 32]),
    };

    let err = derive_router_ab_ed25519_normal_signing_admission_material_v2(&intent, &payload)
        .expect_err("expected digest drift must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::MalformedWirePayload);
}

#[test]
fn v2_admission_rejects_intent_payload_branch_mismatch() {
    let preimage_b64u = b64u(b"unsigned-near-transaction-borsh-v1");
    let intent = near_transaction_intent(preimage_b64u);
    let nonce_b64u = b64u(&[0x22; 32]);
    let canonical_message_b64u = router_ab_ed25519_nep413_canonical_message_b64u_v2(
        "Sign in",
        "wallet.example.near",
        &nonce_b64u,
        None,
    )
    .expect("canonical nep413 message");
    let payload = nep413_payload(canonical_message_b64u);

    let err = derive_router_ab_ed25519_normal_signing_admission_material_v2(&intent, &payload)
        .expect_err("branch mismatch must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidLifecycleState);
}

#[test]
fn v2_admission_rejects_intent_preimage_mismatch() {
    let intent_preimage_b64u = b64u(b"unsigned-near-transaction-borsh-v1");
    let payload_preimage_b64u = b64u(b"other-unsigned-near-transaction-borsh-v1");
    let intent = near_transaction_intent(intent_preimage_b64u);
    let payload = near_transaction_payload(payload_preimage_b64u);

    let err = derive_router_ab_ed25519_normal_signing_admission_material_v2(&intent, &payload)
        .expect_err("intent payload mismatch must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::MalformedWirePayload);
}

#[test]
fn v2_admission_rejects_nep413_canonical_message_mismatch() {
    let nonce_b64u = b64u(&[0x33; 32]);
    let intent = RouterAbEd25519NormalSigningIntentV2::Nep413V1 {
        operation_id: "operation-nep413".to_owned(),
        operation_fingerprint: "fingerprint-nep413".to_owned(),
        near_account_id: "alice.testnet".to_owned(),
        near_network_id: RouterAbNearNetworkIdV2::Testnet,
        recipient: "wallet.example.near".to_owned(),
        message: "Sign in to Seams".to_owned(),
        nonce_b64u: nonce_b64u.clone(),
        callback_url: None,
    };
    let wrong_canonical_message_b64u = router_ab_ed25519_nep413_canonical_message_b64u_v2(
        "Different message",
        "wallet.example.near",
        &nonce_b64u,
        None,
    )
    .expect("canonical nep413 message");
    let payload = nep413_payload(wrong_canonical_message_b64u);

    let err = derive_router_ab_ed25519_normal_signing_admission_material_v2(&intent, &payload)
        .expect_err("nep413 mismatch must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::MalformedWirePayload);
}

#[test]
fn v2_finalize_request_carries_prepare_binding_and_protocol_material() {
    let prepare = RouterAbEd25519NormalSigningPrepareBindingV2::new(
        "server-round1/sign-request-1",
        digest(b"round1-binding"),
        digest(b"intent"),
        digest(b"payload"),
    )
    .expect("prepare binding");

    let request = RouterAbEd25519NormalSigningFinalizeRequestV2::new(
        normal_scope(),
        1_900_000_000_000,
        prepare.clone(),
        finalize_protocol(),
    )
    .expect("finalize request");

    request
        .validate_at(1_800_000_000_000)
        .expect("finalize request validates before expiry");
    assert_eq!(
        request.server_round1_handle(),
        "server-round1/sign-request-1"
    );
    assert_eq!(
        request.round1_binding_digest(),
        prepare.round1_binding_digest
    );
    assert_eq!(request.intent_digest(), prepare.intent_digest);
    assert_eq!(
        request.signing_payload_digest(),
        prepare.signing_payload_digest
    );
}

#[test]
fn v2_finalize_request_rejects_expired_request() {
    let prepare = RouterAbEd25519NormalSigningPrepareBindingV2::new(
        "server-round1/sign-request-1",
        digest(b"round1-binding"),
        digest(b"intent"),
        digest(b"payload"),
    )
    .expect("prepare binding");
    let request = RouterAbEd25519NormalSigningFinalizeRequestV2::new(
        normal_scope(),
        1_900_000_000_000,
        prepare,
        finalize_protocol(),
    )
    .expect("finalize request");

    let err = request
        .validate_at(1_900_000_000_000)
        .expect_err("expired finalize request must fail");

    assert_eq!(err.code(), RouterAbProtocolErrorCode::ExpiredLocalRequest);
}
