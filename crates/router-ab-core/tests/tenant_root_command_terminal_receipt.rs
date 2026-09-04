use std::ops::Range;

use ed25519_dalek::SigningKey;
use router_ab_core::{
    reserve_tenant_root_command_v1, RouterAbDerivationErrorCode, TenantRootCeremonyNonceV1,
    TenantRootCeremonySessionIdV1, TenantRootCommandReplayKeyV1,
    TenantRootCommandTerminalReceiptV1, TenantRootCustodyLineageId, TenantRootIdentityDigestV1,
    TenantRootProtocolDigestV1,
};
use sha2::{Digest, Sha256};
use threshold_prf::TwoPartyDeriverRole;

const ROLE_KEY_ID: &str = "deriver-a-key-v1";
const SIGNING_KEY_BYTES: [u8; 32] = [0x41; 32];

fn key(role: TwoPartyDeriverRole) -> TenantRootCommandReplayKeyV1 {
    TenantRootCommandReplayKeyV1::new(
        TenantRootIdentityDigestV1::from_bytes([0x11; 32]),
        TenantRootCustodyLineageId::from_bytes([0x22; 16]).expect("lineage"),
        TenantRootCeremonySessionIdV1::from_bytes([0x33; 16]).expect("session"),
        TenantRootCeremonyNonceV1::from_bytes([0x44; 32]).expect("nonce"),
        role,
    )
}

fn command_digest(marker: u8) -> TenantRootProtocolDigestV1 {
    TenantRootProtocolDigestV1::from_bytes([marker; 32]).expect("digest")
}

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&SIGNING_KEY_BYTES)
}

fn executed() -> router_ab_core::ExecutedTenantRootCommandV1 {
    let key = key(TwoPartyDeriverRole::DeriverA);
    let command_digest = command_digest(0x55);
    let decision =
        reserve_tenant_root_command_v1(None, key, command_digest, 10).expect("reserve command");
    let router_ab_core::TenantRootCommandReplayDecisionV1::Execute(reservation) = decision else {
        panic!("fresh command must execute");
    };
    reservation
        .checkpoint_executed(12)
        .expect("checkpoint command")
}

fn reserved() -> router_ab_core::ReservedTenantRootCommandV1 {
    let key = key(TwoPartyDeriverRole::DeriverA);
    let command_digest = command_digest(0x55);
    let decision =
        reserve_tenant_root_command_v1(None, key, command_digest, 10).expect("reserve command");
    let router_ab_core::TenantRootCommandReplayDecisionV1::Execute(reservation) = decision else {
        panic!("fresh command must execute");
    };
    reservation
}

fn signed_success(
    key: TenantRootCommandReplayKeyV1,
    command_digest: TenantRootProtocolDigestV1,
    payload: &[u8],
    terminal_at_ms: u64,
    role_key_id: &str,
) -> TenantRootCommandTerminalReceiptV1 {
    TenantRootCommandTerminalReceiptV1::sign_success(
        key,
        command_digest,
        payload.to_vec(),
        terminal_at_ms,
        role_key_id,
        &SIGNING_KEY_BYTES,
    )
    .expect("signed success receipt")
}

fn signed_failure(
    key: TenantRootCommandReplayKeyV1,
    command_digest: TenantRootProtocolDigestV1,
    payload: &[u8],
    terminal_at_ms: u64,
    role_key_id: &str,
) -> TenantRootCommandTerminalReceiptV1 {
    TenantRootCommandTerminalReceiptV1::sign_failure(
        key,
        command_digest,
        payload.to_vec(),
        terminal_at_ms,
        role_key_id,
        &SIGNING_KEY_BYTES,
    )
    .expect("signed failure receipt")
}

fn decoded_success() -> TenantRootCommandTerminalReceiptV1 {
    let raw = signed_success(
        key(TwoPartyDeriverRole::DeriverA),
        command_digest(0x55),
        b"{\"kind\":\"completed\"}",
        13,
        ROLE_KEY_ID,
    );
    TenantRootCommandTerminalReceiptV1::decode_canonical_bytes(
        &raw.canonical_bytes().expect("receipt bytes"),
    )
    .expect("decoded success receipt")
}

fn decoded_failure() -> TenantRootCommandTerminalReceiptV1 {
    let raw = signed_failure(
        key(TwoPartyDeriverRole::DeriverA),
        command_digest(0x55),
        b"{\"kind\":\"failed\"}",
        11,
        ROLE_KEY_ID,
    );
    TenantRootCommandTerminalReceiptV1::decode_canonical_bytes(
        &raw.canonical_bytes().expect("receipt bytes"),
    )
    .expect("decoded failure receipt")
}

#[test]
fn signed_success_round_trips_and_yields_a_nonforgeable_verified_token() {
    let decoded = decoded_success();
    let canonical = decoded.canonical_bytes().expect("canonical receipt");
    let digest = decoded.digest().expect("receipt digest");
    let verified = decoded
        .verify_success(
            &executed(),
            ROLE_KEY_ID,
            &signing_key().verifying_key().to_bytes(),
        )
        .expect("verified success receipt");

    assert_eq!(verified.canonical_bytes(), canonical.as_slice());
    assert_eq!(verified.digest(), digest);
    assert_eq!(verified.key(), &key(TwoPartyDeriverRole::DeriverA));
    assert_eq!(verified.command_digest(), command_digest(0x55));
    assert_eq!(verified.payload_bytes(), b"{\"kind\":\"completed\"}");
    assert_eq!(
        verified.payload_digest(),
        decoded_success().payload_digest()
    );
    assert_eq!(verified.terminal_at_ms(), 13);
    assert_eq!(verified.role_signing_key_id(), ROLE_KEY_ID);
}

#[test]
fn signed_failure_round_trips_and_yields_a_branch_specific_verified_token() {
    let decoded = decoded_failure();
    let canonical = decoded.canonical_bytes().expect("canonical receipt");
    let digest = decoded.digest().expect("receipt digest");
    let verified = decoded
        .verify_failure(
            &reserved(),
            ROLE_KEY_ID,
            &signing_key().verifying_key().to_bytes(),
        )
        .expect("verified failure receipt");

    assert_eq!(verified.canonical_bytes(), canonical.as_slice());
    assert_eq!(verified.digest(), digest);
    assert_eq!(verified.payload_bytes(), b"{\"kind\":\"failed\"}");
    assert_eq!(verified.terminal_at_ms(), 11);
}

#[test]
fn success_and_failure_verification_are_cross_branch_exclusive() {
    let success = decoded_success();
    assert_eq!(
        success
            .verify_failure(
                &reserved(),
                ROLE_KEY_ID,
                &signing_key().verifying_key().to_bytes()
            )
            .expect_err("success cannot verify as failure")
            .code(),
        RouterAbDerivationErrorCode::ReplayMismatch
    );

    let failure = decoded_failure();
    assert_eq!(
        failure
            .verify_success(
                &executed(),
                ROLE_KEY_ID,
                &signing_key().verifying_key().to_bytes()
            )
            .expect_err("failure cannot verify as success")
            .code(),
        RouterAbDerivationErrorCode::ReplayMismatch
    );
}

#[test]
fn verification_rejects_every_replay_and_authentication_substitution() {
    let success = decoded_success();
    let wrong_key = TenantRootCommandReplayKeyV1::new(
        TenantRootIdentityDigestV1::from_bytes([0x12; 32]),
        TenantRootCustodyLineageId::from_bytes([0x22; 16]).expect("lineage"),
        TenantRootCeremonySessionIdV1::from_bytes([0x33; 16]).expect("session"),
        TenantRootCeremonyNonceV1::from_bytes([0x44; 32]).expect("nonce"),
        TwoPartyDeriverRole::DeriverA,
    );
    let wrong_key_token = reserve_tenant_root_command_v1(None, wrong_key, command_digest(0x55), 10)
        .expect("reserve wrong-key command");
    let router_ab_core::TenantRootCommandReplayDecisionV1::Execute(wrong_reservation) =
        wrong_key_token
    else {
        panic!("fresh command must execute");
    };
    let wrong_executed = wrong_reservation
        .checkpoint_executed(12)
        .expect("checkpoint wrong-key command");

    assert_eq!(
        success
            .verify_success(
                &wrong_executed,
                ROLE_KEY_ID,
                &signing_key().verifying_key().to_bytes(),
            )
            .expect_err("identity substitution must fail")
            .code(),
        RouterAbDerivationErrorCode::ReplayMismatch
    );

    let wrong_command = signed_success(
        key(TwoPartyDeriverRole::DeriverA),
        command_digest(0x56),
        b"{\"kind\":\"completed\"}",
        13,
        ROLE_KEY_ID,
    );
    assert_eq!(
        wrong_command
            .verify_success(
                &executed(),
                ROLE_KEY_ID,
                &signing_key().verifying_key().to_bytes(),
            )
            .expect_err("command substitution must fail")
            .code(),
        RouterAbDerivationErrorCode::ReplayMismatch
    );

    let wrong_role = signed_success(
        key(TwoPartyDeriverRole::DeriverB),
        command_digest(0x55),
        b"{\"kind\":\"completed\"}",
        13,
        "deriver-b-key-v1",
    );
    assert_eq!(
        wrong_role
            .verify_success(
                &executed(),
                ROLE_KEY_ID,
                &signing_key().verifying_key().to_bytes(),
            )
            .expect_err("role substitution must fail")
            .code(),
        RouterAbDerivationErrorCode::ReplayMismatch
    );

    let wrong_role_key_id = signed_success(
        key(TwoPartyDeriverRole::DeriverA),
        command_digest(0x55),
        b"{\"kind\":\"completed\"}",
        13,
        "deriver-a-key-v2",
    );
    assert_eq!(
        wrong_role_key_id
            .verify_success(
                &executed(),
                ROLE_KEY_ID,
                &signing_key().verifying_key().to_bytes(),
            )
            .expect_err("role signing-key id substitution must fail")
            .code(),
        RouterAbDerivationErrorCode::ReplayMismatch
    );

    let wrong_timestamp = signed_success(
        key(TwoPartyDeriverRole::DeriverA),
        command_digest(0x55),
        b"{\"kind\":\"completed\"}",
        11,
        ROLE_KEY_ID,
    );
    assert_eq!(
        wrong_timestamp
            .verify_success(
                &executed(),
                ROLE_KEY_ID,
                &signing_key().verifying_key().to_bytes(),
            )
            .expect_err("terminal timestamp substitution must fail")
            .code(),
        RouterAbDerivationErrorCode::ReplayMismatch
    );

    let wrong_public_key = SigningKey::from_bytes(&[0x42; 32]);
    assert_eq!(
        success
            .verify_success(
                &executed(),
                ROLE_KEY_ID,
                &wrong_public_key.verifying_key().to_bytes(),
            )
            .expect_err("wrong role public key must fail")
            .code(),
        RouterAbDerivationErrorCode::OutputVerificationFailed
    );
}

#[test]
fn canonical_digest_is_stable_and_payload_bytes_are_replayable() {
    let receipt = decoded_success();
    assert_eq!(receipt.payload_bytes(), b"{\"kind\":\"completed\"}");
    assert_eq!(
        hex::encode(receipt.digest().expect("receipt digest").as_bytes()),
        "441b8c22b88a7ded87fc8eee086d00a6e28f4fdbacea7b2c884d21d22f97e290",
    );
}

#[test]
fn valid_nonzero_tampering_fails_signature_verification() {
    let receipt = decoded_success();
    let canonical = receipt.canonical_bytes().expect("canonical receipt");

    let outcome = replace_field(&canonical, 1, b"failure");
    let decoded_outcome = TenantRootCommandTerminalReceiptV1::decode_canonical_bytes(&outcome)
        .expect("outcome tamper remains structurally valid");
    let outcome_error = match decoded_outcome {
        TenantRootCommandTerminalReceiptV1::Success(receipt) => receipt
            .verify(
                &executed(),
                ROLE_KEY_ID,
                &signing_key().verifying_key().to_bytes(),
            )
            .expect_err("outcome tamper must fail signature verification"),
        TenantRootCommandTerminalReceiptV1::Failure(receipt) => receipt
            .verify(
                &reserved(),
                ROLE_KEY_ID,
                &signing_key().verifying_key().to_bytes(),
            )
            .expect_err("outcome tamper must fail signature verification"),
    };
    assert_eq!(
        outcome_error.code(),
        RouterAbDerivationErrorCode::OutputVerificationFailed
    );

    let mut payload = receipt.payload_bytes().to_vec();
    payload[0] = b'[';
    let payload_digest = Sha256::digest(&payload);
    let payload_tamper =
        replace_field(&replace_field(&canonical, 9, &payload_digest), 10, &payload);
    let decoded_payload =
        TenantRootCommandTerminalReceiptV1::decode_canonical_bytes(&payload_tamper)
            .expect("payload tamper remains structurally valid");
    let payload_error = match decoded_payload {
        TenantRootCommandTerminalReceiptV1::Success(receipt) => receipt
            .verify(
                &executed(),
                ROLE_KEY_ID,
                &signing_key().verifying_key().to_bytes(),
            )
            .expect_err("payload tamper must fail signature verification"),
        TenantRootCommandTerminalReceiptV1::Failure(receipt) => receipt
            .verify(
                &reserved(),
                ROLE_KEY_ID,
                &signing_key().verifying_key().to_bytes(),
            )
            .expect_err("payload tamper must fail signature verification"),
    };
    assert_eq!(
        payload_error.code(),
        RouterAbDerivationErrorCode::OutputVerificationFailed
    );

    let timestamp_tamper = replace_field(&canonical, 11, &14_u64.to_be_bytes());
    let decoded_timestamp =
        TenantRootCommandTerminalReceiptV1::decode_canonical_bytes(&timestamp_tamper)
            .expect("timestamp tamper remains structurally valid");
    let timestamp_error = match decoded_timestamp {
        TenantRootCommandTerminalReceiptV1::Success(receipt) => receipt
            .verify(
                &executed(),
                ROLE_KEY_ID,
                &signing_key().verifying_key().to_bytes(),
            )
            .expect_err("timestamp tamper must fail signature verification"),
        TenantRootCommandTerminalReceiptV1::Failure(receipt) => receipt
            .verify(
                &reserved(),
                ROLE_KEY_ID,
                &signing_key().verifying_key().to_bytes(),
            )
            .expect_err("timestamp tamper must fail signature verification"),
    };
    assert_eq!(
        timestamp_error.code(),
        RouterAbDerivationErrorCode::OutputVerificationFailed
    );

    let signature_range = field_range(&canonical, 13);
    let mut signature_tamper = canonical.clone();
    let signature_byte = signature_tamper[signature_range.start];
    signature_tamper[signature_range.start] = if signature_byte == u8::MAX {
        1
    } else {
        signature_byte + 1
    };
    let decoded_signature =
        TenantRootCommandTerminalReceiptV1::decode_canonical_bytes(&signature_tamper)
            .expect("signature tamper remains structurally valid");
    let signature_error = match decoded_signature {
        TenantRootCommandTerminalReceiptV1::Success(receipt) => receipt
            .verify(
                &executed(),
                ROLE_KEY_ID,
                &signing_key().verifying_key().to_bytes(),
            )
            .expect_err("signature tamper must fail signature verification"),
        TenantRootCommandTerminalReceiptV1::Failure(receipt) => receipt
            .verify(
                &reserved(),
                ROLE_KEY_ID,
                &signing_key().verifying_key().to_bytes(),
            )
            .expect_err("signature tamper must fail signature verification"),
    };
    assert_eq!(
        signature_error.code(),
        RouterAbDerivationErrorCode::OutputVerificationFailed
    );
}

#[test]
fn truncated_wire_is_rejected_and_signing_rejects_oversized_wire() {
    let receipt = decoded_success();
    let canonical = receipt.canonical_bytes().expect("canonical receipt");
    assert!(
        TenantRootCommandTerminalReceiptV1::decode_canonical_bytes(
            &canonical[..canonical.len() - 1]
        )
        .is_err(),
        "truncated canonical wire must fail closed"
    );

    let oversized = TenantRootCommandTerminalReceiptV1::sign_success(
        key(TwoPartyDeriverRole::DeriverA),
        command_digest(0x55),
        vec![0x7f; router_ab_core::TENANT_ROOT_COMMAND_TERMINAL_RECEIPT_MAX_BYTES_V1],
        13,
        ROLE_KEY_ID,
        &SIGNING_KEY_BYTES,
    )
    .expect_err("oversized final wire must be rejected during signing");
    assert_eq!(
        oversized.code(),
        RouterAbDerivationErrorCode::MalformedInput
    );
}

#[test]
fn malformed_receipt_vectors_fail_closed() {
    let receipt = decoded_success();
    let canonical = receipt.canonical_bytes().expect("canonical receipt");

    let malformed_vectors = [
        ("empty", Vec::new()),
        ("trailing", append_byte(&canonical, 0)),
        ("domain", replace_field_byte(&canonical, 0, 0, 0xff)),
        ("outcome", replace_field_byte(&canonical, 1, 0, b'x')),
        ("lineage", replace_field(&canonical, 3, &[0; 16])),
        ("role label", replace_field_byte(&canonical, 4, 0, b'x')),
        ("role share id", replace_field(&canonical, 5, &[0; 2])),
        ("session", replace_field(&canonical, 6, &[0; 16])),
        ("nonce", replace_field(&canonical, 7, &[0; 32])),
        ("command digest", replace_field(&canonical, 8, &[0; 32])),
        ("payload digest", replace_field_byte(&canonical, 9, 0, 0xff)),
        ("payload", replace_field_byte(&canonical, 10, 0, b'[')),
        ("empty payload", zero_field_length(&canonical, 10)),
        (
            "role key id utf8",
            replace_field_byte(&canonical, 12, 0, 0xff),
        ),
        ("zero signature", replace_field(&canonical, 13, &[0; 64])),
    ];

    for (name, bytes) in malformed_vectors {
        assert!(
            TenantRootCommandTerminalReceiptV1::decode_canonical_bytes(&bytes).is_err(),
            "malformed vector {name} must fail",
        );
    }
}

fn field_range(bytes: &[u8], index: usize) -> Range<usize> {
    let mut offset = 0;
    for current in 0..=index {
        let length_start = offset;
        let length_end = length_start + 4;
        let length = u32::from_be_bytes(
            bytes[length_start..length_end]
                .try_into()
                .expect("field length"),
        ) as usize;
        let value_start = length_end;
        let value_end = value_start + length;
        if current == index {
            return value_start..value_end;
        }
        offset = value_end;
    }
    unreachable!("field index is in range")
}

fn replace_field(bytes: &[u8], index: usize, replacement: &[u8]) -> Vec<u8> {
    let range = field_range(bytes, index);
    assert_eq!(range.len(), replacement.len(), "replacement field length");
    let mut result = bytes.to_vec();
    result[range].copy_from_slice(replacement);
    result
}

fn replace_field_byte(bytes: &[u8], index: usize, byte_index: usize, value: u8) -> Vec<u8> {
    let range = field_range(bytes, index);
    let mut result = bytes.to_vec();
    result[range.start + byte_index] = value;
    result
}

fn zero_field_length(bytes: &[u8], index: usize) -> Vec<u8> {
    let range = field_range(bytes, index);
    let length_start = range.start - 4;
    let mut result = bytes.to_vec();
    result[length_start..range.start].copy_from_slice(&[0; 4]);
    result
}

fn append_byte(bytes: &[u8], byte: u8) -> Vec<u8> {
    let mut result = bytes.to_vec();
    result.push(byte);
    result
}
