use base64ct::{Base64UrlUnpadded, Encoding};
use router_ab_core::{
    derive_router_ab_ed25519_normal_signing_admission_material_v2,
    parse_router_ab_ed25519_normal_signing_finalize_request_v2_json,
    parse_router_ab_ed25519_normal_signing_prepare_request_v2_json,
    parse_router_ab_ed25519_presign_pool_hit_finalize_request_v2_json,
    parse_router_ab_ed25519_presign_pool_prepare_request_v2_json,
    parse_router_ab_ed25519_presign_pool_prepare_response_v2_json,
    router_ab_ed25519_nep413_canonical_message_b64u_v2,
    NormalSigningEd25519TwoPartyFrostCommitmentsV1, NormalSigningScopeV1,
    NormalSigningSignatureSchemeV1, PublicDigest32, RouterAbEd25519NormalSigningFinalizeProtocolV2,
    RouterAbEd25519NormalSigningFinalizeRequestV2, RouterAbEd25519NormalSigningIntentV2,
    RouterAbEd25519NormalSigningPrepareBindingV2, RouterAbEd25519NormalSigningPrepareRequestV2,
    RouterAbEd25519PresignPoolAcceptedEntryV2, RouterAbEd25519PresignPoolClientOfferV2,
    RouterAbEd25519PresignPoolHitBindingV2, RouterAbEd25519PresignPoolHitFinalizeRequestV2,
    RouterAbEd25519PresignPoolPrepareRequestV2, RouterAbEd25519PresignPoolPrepareResponseV2,
    RouterAbEd25519SigningPayloadV2, RouterAbEd25519TwoPartyFrostFinalizeProtocolV2,
    RouterAbNearDelegateActionIntentV1, RouterAbNearNetworkIdV2, RouterAbNearTransactionIntentV1,
    RouterAbProtocolErrorCode, ServerIdentityV1,
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
            commitments(0x11, 0x12),
            commitments(0x21, 0x22),
            b64u(&[0x31; 32]),
            b64u(&[0x32; 32]),
            b64u(&[0x41; 32]),
        )
        .expect("finalize protocol"),
    )
}

fn commitments(hiding: u8, binding: u8) -> NormalSigningEd25519TwoPartyFrostCommitmentsV1 {
    NormalSigningEd25519TwoPartyFrostCommitmentsV1::new(b64u(&[hiding; 32]), b64u(&[binding; 32]))
        .expect("commitments")
}

fn signing_worker_identity() -> ServerIdentityV1 {
    ServerIdentityV1::new(
        "signing-worker-1",
        "epoch-1",
        "x25519:signing-worker-recipient-key",
    )
    .expect("server identity")
}

fn pool_offer(client_presign_id: &str, nonce_seed: u8) -> RouterAbEd25519PresignPoolClientOfferV2 {
    RouterAbEd25519PresignPoolClientOfferV2::new(
        client_presign_id,
        format!("client-nonce-handle-{nonce_seed}"),
        commitments(nonce_seed, nonce_seed.wrapping_add(1)),
        b64u(&[nonce_seed.wrapping_add(2); 32]),
    )
    .expect("client offer")
}

fn pool_prepare_request() -> RouterAbEd25519PresignPoolPrepareRequestV2 {
    RouterAbEd25519PresignPoolPrepareRequestV2::new(
        normal_scope(),
        1_900_000_000_000,
        7,
        vec![
            pool_offer("client-presign-1", 0x51),
            pool_offer("client-presign-2", 0x61),
        ],
    )
    .expect("pool prepare request")
}

fn accepted_pool_entry(
    request: &RouterAbEd25519PresignPoolPrepareRequestV2,
    offer: &RouterAbEd25519PresignPoolClientOfferV2,
    nonce_seed: u8,
) -> RouterAbEd25519PresignPoolAcceptedEntryV2 {
    RouterAbEd25519PresignPoolAcceptedEntryV2::new(
        offer.client_presign_id.clone(),
        request.generation,
        request
            .pool_entry_binding_digest(offer)
            .expect("pool entry binding digest"),
        signing_worker_identity(),
        format!("server-round1/pool-{nonce_seed}"),
        commitments(nonce_seed, nonce_seed.wrapping_add(1)),
        b64u(&[nonce_seed.wrapping_add(2); 32]),
        NormalSigningSignatureSchemeV1::Ed25519V1,
        1_800_000_000_000,
        request.expires_at_ms,
    )
    .expect("accepted pool entry")
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

    let mut with_client_group_public_key =
        serde_json::to_value(&request).expect("finalize request value");
    with_client_group_public_key["protocol"]
        .as_object_mut()
        .expect("protocol object")
        .insert(
            "group_public_key".to_owned(),
            serde_json::json!(fixture_public_key_string()),
        );
    let err = parse_router_ab_ed25519_normal_signing_finalize_request_v2_json(
        &serde_json::to_vec(&with_client_group_public_key).expect("group public key json"),
    )
    .expect_err("client-supplied group public key must fail");
    assert_eq!(err.code(), RouterAbProtocolErrorCode::MalformedWirePayload);
}

#[test]
fn presign_pool_prepare_request_is_message_agnostic_and_parses_at_boundary() {
    let request = pool_prepare_request();
    let parsed = parse_router_ab_ed25519_presign_pool_prepare_request_v2_json(
        &serde_json::to_vec(&request).expect("pool prepare request json"),
    )
    .expect("pool prepare request parses");
    assert_eq!(parsed, request);

    let value = serde_json::to_value(&request).expect("pool prepare value");
    assert!(value.get("intent").is_none());
    assert!(value.get("signing_payload").is_none());
    assert!(value.get("admitted_signing_digest").is_none());

    let mut with_intent = value.clone();
    with_intent
        .as_object_mut()
        .expect("pool prepare object")
        .insert("intent".to_owned(), serde_json::json!({"kind": "legacy"}));
    let err = parse_router_ab_ed25519_presign_pool_prepare_request_v2_json(
        &serde_json::to_vec(&with_intent).expect("pool prepare intent json"),
    )
    .expect_err("intent field must fail on pool refill");
    assert_eq!(err.code(), RouterAbProtocolErrorCode::MalformedWirePayload);

    let mut with_legacy_offer_field = value;
    with_legacy_offer_field["client_offers"][0]
        .as_object_mut()
        .expect("client offer object")
        .insert(
            "threshold_session_id".to_owned(),
            serde_json::json!("legacy-session"),
        );
    let err = parse_router_ab_ed25519_presign_pool_prepare_request_v2_json(
        &serde_json::to_vec(&with_legacy_offer_field).expect("legacy offer json"),
    )
    .expect_err("legacy offer field must fail");
    assert_eq!(err.code(), RouterAbProtocolErrorCode::MalformedWirePayload);
}

#[test]
fn presign_pool_prepare_rejects_duplicate_offer_ids_and_nonce_handles() {
    let err = RouterAbEd25519PresignPoolPrepareRequestV2::new(
        normal_scope(),
        1_900_000_000_000,
        7,
        vec![
            pool_offer("client-presign-dup", 0x51),
            pool_offer("client-presign-dup", 0x52),
        ],
    )
    .expect_err("duplicated client presign id must fail");
    assert_eq!(
        err.code(),
        RouterAbProtocolErrorCode::InvalidLocalHttpRequest
    );

    let duplicate_nonce = RouterAbEd25519PresignPoolClientOfferV2::new(
        "client-presign-other",
        "client-nonce-handle-81",
        commitments(0x71, 0x72),
        b64u(&[0x73; 32]),
    )
    .expect("duplicate nonce offer");
    let err = RouterAbEd25519PresignPoolPrepareRequestV2::new(
        normal_scope(),
        1_900_000_000_000,
        7,
        vec![pool_offer("client-presign-1", 0x51), duplicate_nonce],
    )
    .expect_err("duplicated client nonce handle must fail");
    assert_eq!(
        err.code(),
        RouterAbProtocolErrorCode::InvalidLocalHttpRequest
    );
}

#[test]
fn presign_pool_prepare_response_binds_accepted_entries_to_offers() {
    let request = pool_prepare_request();
    let offer = request
        .client_offers
        .first()
        .expect("first client offer")
        .clone();
    let rejected_offer = request
        .client_offers
        .get(1)
        .expect("second client offer")
        .clone();
    let accepted = accepted_pool_entry(&request, &offer, 0x81);
    let response = RouterAbEd25519PresignPoolPrepareResponseV2::new(
        request.scope.clone(),
        request.generation,
        vec![accepted.clone()],
        vec![rejected_offer.client_presign_id],
    )
    .expect("pool prepare response");

    response
        .validate_for_request(&request)
        .expect("response validates against originating request");
    let parsed = parse_router_ab_ed25519_presign_pool_prepare_response_v2_json(
        &serde_json::to_vec(&response).expect("pool prepare response json"),
    )
    .expect("pool prepare response parses");
    assert_eq!(parsed, response);

    let wrong_digest = RouterAbEd25519PresignPoolAcceptedEntryV2::new(
        offer.client_presign_id,
        request.generation,
        digest(b"wrong pool entry binding"),
        signing_worker_identity(),
        "server-round1/pool-wrong",
        commitments(0x91, 0x92),
        b64u(&[0x93; 32]),
        NormalSigningSignatureSchemeV1::Ed25519V1,
        1_800_000_000_000,
        request.expires_at_ms,
    )
    .expect("wrong digest entry validates structurally");
    let response = RouterAbEd25519PresignPoolPrepareResponseV2::new(
        request.scope.clone(),
        request.generation,
        vec![wrong_digest],
        vec![],
    )
    .expect("wrong digest response validates structurally");
    let err = response
        .validate_for_request(&request)
        .expect_err("wrong offer binding digest must fail");
    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidLifecycleState);

    let wrong_scope = NormalSigningScopeV1::new(
        "router-ab-normal-signing/request-1",
        "alice.testnet",
        "session-2",
        "session-1",
        "signing-worker-1",
    )
    .expect("wrong response scope");
    let response = RouterAbEd25519PresignPoolPrepareResponseV2::new(
        wrong_scope,
        request.generation,
        vec![accepted],
        vec![],
    )
    .expect("wrong scope response validates structurally");
    let err = response
        .validate_for_request(&request)
        .expect_err("cross-session response must fail");
    assert_eq!(err.code(), RouterAbProtocolErrorCode::InvalidLifecycleState);
}

#[test]
fn presign_pool_hit_finalize_carries_admission_material_and_lowers_to_v2_finalize() {
    let request = pool_prepare_request();
    let offer = request
        .client_offers
        .first()
        .expect("first client offer")
        .clone();
    let accepted = accepted_pool_entry(&request, &offer, 0x81);
    let preimage = fixture_near_unsigned_transaction_borsh();
    let preimage_b64u = b64u(&preimage);
    let intent = near_transaction_intent(preimage_b64u.clone());
    let payload = near_transaction_payload(preimage_b64u);
    let pool_binding = RouterAbEd25519PresignPoolHitBindingV2::new(
        offer.client_presign_id,
        offer.client_nonce_handle,
        request.generation,
        accepted.server_round1_handle,
        accepted.pool_entry_binding_digest,
    )
    .expect("pool hit binding");
    let pool_hit = RouterAbEd25519PresignPoolHitFinalizeRequestV2::new(
        request.scope.clone(),
        request.expires_at_ms,
        pool_binding,
        intent,
        payload,
        finalize_protocol(),
    )
    .expect("pool hit finalize request");
    let material = pool_hit
        .admission_material()
        .expect("pool hit admission material");
    let lowered = pool_hit
        .to_normal_finalize_request_v2()
        .expect("lowered finalize request");

    assert_eq!(lowered.scope, pool_hit.scope);
    assert_eq!(lowered.expires_at_ms, pool_hit.expires_at_ms);
    assert_eq!(lowered.intent_digest(), material.intent_digest);
    assert_eq!(
        lowered.signing_payload_digest(),
        material.signing_payload_digest
    );
    assert_eq!(
        lowered.round1_binding_digest(),
        pool_hit
            .round1_binding_digest()
            .expect("pool hit round1 binding")
    );
    assert_eq!(
        lowered.server_round1_handle(),
        pool_hit.server_round1_handle()
    );

    let parsed = parse_router_ab_ed25519_presign_pool_hit_finalize_request_v2_json(
        &serde_json::to_vec(&pool_hit).expect("pool hit finalize json"),
    )
    .expect("pool hit finalize parses");
    assert_eq!(parsed, pool_hit);

    let mut with_legacy_binding_field =
        serde_json::to_value(&pool_hit).expect("pool hit finalize value");
    with_legacy_binding_field["pool_binding"]
        .as_object_mut()
        .expect("pool binding object")
        .insert(
            "threshold_session_id".to_owned(),
            serde_json::json!("legacy-session"),
        );
    let err = parse_router_ab_ed25519_presign_pool_hit_finalize_request_v2_json(
        &serde_json::to_vec(&with_legacy_binding_field).expect("pool hit legacy json"),
    )
    .expect_err("legacy pool binding field must fail");
    assert_eq!(err.code(), RouterAbProtocolErrorCode::MalformedWirePayload);

    let mut with_client_group_public_key =
        serde_json::to_value(&pool_hit).expect("pool hit finalize value");
    with_client_group_public_key["protocol"]
        .as_object_mut()
        .expect("protocol object")
        .insert(
            "group_public_key".to_owned(),
            serde_json::json!(fixture_public_key_string()),
        );
    let err = parse_router_ab_ed25519_presign_pool_hit_finalize_request_v2_json(
        &serde_json::to_vec(&with_client_group_public_key).expect("pool hit group key json"),
    )
    .expect_err("pool-hit client-supplied group public key must fail");
    assert_eq!(err.code(), RouterAbProtocolErrorCode::MalformedWirePayload);
}

#[test]
fn presign_pool_hit_finalize_rejects_intent_payload_drift() {
    let request = pool_prepare_request();
    let offer = request
        .client_offers
        .first()
        .expect("first client offer")
        .clone();
    let accepted = accepted_pool_entry(&request, &offer, 0x81);
    let intent_preimage_b64u = b64u(b"unsigned-near-transaction-borsh-v1");
    let payload_preimage_b64u = b64u(b"other-unsigned-near-transaction-borsh-v1");
    let pool_binding = RouterAbEd25519PresignPoolHitBindingV2::new(
        offer.client_presign_id,
        offer.client_nonce_handle,
        request.generation,
        accepted.server_round1_handle,
        accepted.pool_entry_binding_digest,
    )
    .expect("pool hit binding");

    let err = RouterAbEd25519PresignPoolHitFinalizeRequestV2::new(
        request.scope,
        request.expires_at_ms,
        pool_binding,
        near_transaction_intent(intent_preimage_b64u),
        near_transaction_payload(payload_preimage_b64u),
        finalize_protocol(),
    )
    .expect_err("pool hit intent payload drift must fail");
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
