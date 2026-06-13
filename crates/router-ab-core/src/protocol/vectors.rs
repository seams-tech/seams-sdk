use crate::derivation::{
    MpcPrfDleqProofWireV1, MpcPrfPartialBindingV1, MpcPrfPartialProofBundleV1, MpcPrfPartialWireV1,
    MpcPrfShareCommitmentWireV1, MpcPrfSignerPartialV1, MpcPrfSuiteId, OpenedShareKind,
    PublicDigest32, Role, RootShareEpoch, MPC_PRF_COMMITMENT_WIRE_V1_LEN,
    MPC_PRF_DLEQ_PROOF_WIRE_V1_LEN, MPC_PRF_PARTIAL_WIRE_V1_LEN,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::protocol::envelope::{
    role_encrypted_envelope_digest_v1, EncryptedPayloadV1, RoleEncryptedEnvelopeV1,
};
use crate::protocol::error::{
    RouterAbProtocolError, RouterAbProtocolErrorCode, RouterAbProtocolResult,
};
use crate::protocol::gate::ExpensiveWorkKindV1;
use crate::protocol::identity::{
    RelayerIdentityV1, RoleEnvelopeAssignmentV1, SignerIdentityV1, SignerSetV1,
};
use crate::protocol::lifecycle::LifecycleScopeV1;
use crate::protocol::output::{
    encode_recipient_proof_bundle_ciphertext_v1, RecipientOutputEncryptionAlgorithmV1,
    RecipientProofBundleCiphertextV1,
};
use crate::protocol::payload::{
    ab_peer_message_authentication_input_digest_v1, encode_ab_peer_message_payload_v1,
    encode_router_to_signer_payload_v1, AbDerivationProofBatchPayloadV1,
    AbPeerMessageAuthenticationV1, AbPeerMessagePayloadV1, AbPeerMessageSignatureSchemeV1,
    RecipientProofBundlePayloadV1, RouterEnvelopeDigestSetV1, RouterToSignerPayloadV1,
    RouterTranscriptMetadataV1,
};
use crate::protocol::wire::{
    encode_wire_message_v1, wire_message_digest_v1, CanonicalWireBytesV1, WireMessageKindV1,
    WireMessageV1,
};

/// Wire vector fixture version.
pub const WIRE_VECTOR_FIXTURE_VERSION_V1: &str = "router_ab_core_wire_vectors_v1";
/// Payload vector fixture version.
pub const PAYLOAD_VECTOR_FIXTURE_VERSION_V1: &str = "router_ab_core_payload_vectors_v1";

/// One canonical wire-message vector case.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireMessageVectorCaseV1 {
    /// Stable vector case id.
    pub case_id: String,
    /// Message kind.
    pub kind: WireMessageKindV1,
    /// Transcript digest bytes as lowercase hex.
    pub transcript_digest_hex: String,
    /// Payload bytes as lowercase hex.
    pub payload_hex: String,
    /// Canonical encoded message bytes as lowercase hex.
    pub canonical_bytes_hex: String,
    /// SHA-256 digest of canonical bytes as lowercase hex.
    pub digest_hex: String,
}

/// Committed wire-vector fixture.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireVectorFixtureV1 {
    /// Fixture version.
    pub version: String,
    /// Vector cases.
    pub cases: Vec<WireMessageVectorCaseV1>,
}

/// One canonical inner-payload vector case.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PayloadVectorCaseV1 {
    /// Stable vector case id.
    pub case_id: String,
    /// Wire message kind that carries this payload.
    pub wire_message_kind: WireMessageKindV1,
    /// Typed payload input encoded as JSON for cross-host test fixtures.
    pub payload_json: Value,
    /// Canonical encoded payload bytes as lowercase hex.
    pub canonical_bytes_hex: String,
    /// SHA-256 digest of canonical bytes as lowercase hex.
    pub digest_hex: String,
}

/// Committed inner-payload vector fixture.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PayloadVectorFixtureV1 {
    /// Fixture version.
    pub version: String,
    /// Vector cases.
    pub cases: Vec<PayloadVectorCaseV1>,
}

/// Returns the generated v1 wire-vector fixture.
pub fn generated_wire_vector_fixture_v1() -> WireVectorFixtureV1 {
    let cases = [
        (
            WireMessageKindV1::RouterToSignerA,
            0x11,
            b"router-a-envelope-v1".as_slice(),
        ),
        (
            WireMessageKindV1::RouterToSignerB,
            0x22,
            b"router-b-envelope-v1".as_slice(),
        ),
        (
            WireMessageKindV1::SignerAToSignerB,
            0x33,
            b"signer-a-to-b-message-v1".as_slice(),
        ),
        (
            WireMessageKindV1::SignerBToSignerA,
            0x44,
            b"signer-b-to-a-message-v1".as_slice(),
        ),
        (
            WireMessageKindV1::RecipientProofBundle,
            0x77,
            b"recipient-proof-bundle-v1".as_slice(),
        ),
    ]
    .into_iter()
    .map(|(kind, seed, payload)| vector_case(kind, seed, payload))
    .collect();

    WireVectorFixtureV1 {
        version: WIRE_VECTOR_FIXTURE_VERSION_V1.to_owned(),
        cases,
    }
}

/// Returns the generated v1 wire-vector fixture as pretty JSON.
pub fn generated_wire_vector_fixture_json_v1() -> String {
    serde_json::to_string_pretty(&generated_wire_vector_fixture_v1()).expect("serialize vectors")
}

/// Returns the generated v1 payload-vector fixture.
pub fn generated_payload_vector_fixture_v1() -> PayloadVectorFixtureV1 {
    let cases = [
        payload_vector_case(
            "router_to_signer_a_payload",
            WireMessageKindV1::RouterToSignerA,
            sample_router_to_signer_a_payload(),
        ),
        payload_vector_case(
            "router_to_signer_b_payload",
            WireMessageKindV1::RouterToSignerB,
            sample_router_to_signer_b_payload(),
        ),
        payload_vector_case(
            "signer_a_to_signer_b_payload",
            WireMessageKindV1::SignerAToSignerB,
            sample_ab_peer_message_payload(Role::SignerA),
        ),
        payload_vector_case(
            "signer_b_to_signer_a_payload",
            WireMessageKindV1::SignerBToSignerA,
            sample_ab_peer_message_payload(Role::SignerB),
        ),
        recipient_proof_bundle_payload_vector_case(),
    ];

    PayloadVectorFixtureV1 {
        version: PAYLOAD_VECTOR_FIXTURE_VERSION_V1.to_owned(),
        cases: cases.into_iter().collect(),
    }
}

/// Returns the generated v1 payload-vector fixture as pretty JSON.
pub fn generated_payload_vector_fixture_json_v1() -> String {
    serde_json::to_string_pretty(&generated_payload_vector_fixture_v1())
        .expect("serialize payload vectors")
}

/// Parses a wire-vector fixture JSON blob.
pub fn parse_wire_vector_fixture_v1(json: &str) -> RouterAbProtocolResult<WireVectorFixtureV1> {
    serde_json::from_str(json).map_err(|err| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("wire vector fixture JSON is invalid: {err}"),
        )
    })
}

/// Parses a payload-vector fixture JSON blob.
pub fn parse_payload_vector_fixture_v1(
    json: &str,
) -> RouterAbProtocolResult<PayloadVectorFixtureV1> {
    serde_json::from_str(json).map_err(|err| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("payload vector fixture JSON is invalid: {err}"),
        )
    })
}

/// Validates a wire-vector fixture against the canonical encoder.
pub fn validate_wire_vector_fixture_v1(
    fixture: &WireVectorFixtureV1,
) -> RouterAbProtocolResult<()> {
    if fixture.version != WIRE_VECTOR_FIXTURE_VERSION_V1 {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::UnsupportedVectorVersion,
            "wire vector fixture version is unsupported",
        ));
    }

    for case in &fixture.cases {
        let transcript_digest = public_digest_from_hex(&case.transcript_digest_hex)?;
        let payload = CanonicalWireBytesV1::new(hex_to_bytes(&case.payload_hex)?)?;
        let message = WireMessageV1::new(case.kind, transcript_digest, payload)?;
        let canonical_bytes = encode_wire_message_v1(&message);
        let digest = wire_message_digest_v1(&message);

        if hex::encode(canonical_bytes) != case.canonical_bytes_hex {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                format!("wire vector case {} canonical bytes mismatch", case.case_id),
            ));
        }
        if hex::encode(digest.as_bytes()) != case.digest_hex {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                format!("wire vector case {} digest mismatch", case.case_id),
            ));
        }
    }

    Ok(())
}

/// Validates a payload-vector fixture against the canonical encoders.
pub fn validate_payload_vector_fixture_v1(
    fixture: &PayloadVectorFixtureV1,
) -> RouterAbProtocolResult<()> {
    if fixture.version != PAYLOAD_VECTOR_FIXTURE_VERSION_V1 {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::UnsupportedVectorVersion,
            "payload vector fixture version is unsupported",
        ));
    }

    for case in &fixture.cases {
        let (canonical_bytes, digest) =
            encode_payload_case(case.wire_message_kind, case.payload_json.clone())?;
        if hex::encode(canonical_bytes) != case.canonical_bytes_hex {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                format!(
                    "payload vector case {} canonical bytes mismatch",
                    case.case_id
                ),
            ));
        }
        if hex::encode(digest.as_bytes()) != case.digest_hex {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                format!("payload vector case {} digest mismatch", case.case_id),
            ));
        }
    }

    Ok(())
}

fn vector_case(kind: WireMessageKindV1, seed: u8, payload: &[u8]) -> WireMessageVectorCaseV1 {
    let transcript_digest = PublicDigest32::new([seed; 32]);
    let message = WireMessageV1::new(
        kind,
        transcript_digest,
        CanonicalWireBytesV1::new(payload.to_vec()).expect("vector payload"),
    )
    .expect("wire message");
    WireMessageVectorCaseV1 {
        case_id: kind.as_str().to_owned(),
        kind,
        transcript_digest_hex: hex::encode(transcript_digest.as_bytes()),
        payload_hex: hex::encode(payload),
        canonical_bytes_hex: hex::encode(message.canonical_bytes()),
        digest_hex: hex::encode(message.digest().as_bytes()),
    }
}

fn payload_vector_case<T>(
    case_id: &'static str,
    wire_message_kind: WireMessageKindV1,
    payload: T,
) -> PayloadVectorCaseV1
where
    T: Serialize,
{
    let payload_json = serde_json::to_value(payload).expect("payload JSON");
    let (canonical_bytes, digest) =
        encode_payload_case(wire_message_kind, payload_json.clone()).expect("payload encoding");
    PayloadVectorCaseV1 {
        case_id: case_id.to_owned(),
        wire_message_kind,
        payload_json,
        canonical_bytes_hex: hex::encode(canonical_bytes),
        digest_hex: hex::encode(digest.as_bytes()),
    }
}

fn recipient_proof_bundle_payload_vector_case() -> PayloadVectorCaseV1 {
    let payload = sample_recipient_proof_bundle_ciphertext();
    let payload_json = serde_json::to_value(payload).expect("recipient proof-bundle payload JSON");
    let (canonical_bytes, digest) = encode_payload_case(
        WireMessageKindV1::RecipientProofBundle,
        payload_json.clone(),
    )
    .expect("recipient proof-bundle payload encoding");
    PayloadVectorCaseV1 {
        case_id: "recipient_proof_bundle_ciphertext".to_owned(),
        wire_message_kind: WireMessageKindV1::RecipientProofBundle,
        payload_json,
        canonical_bytes_hex: hex::encode(canonical_bytes),
        digest_hex: hex::encode(digest.as_bytes()),
    }
}

fn encode_payload_case(
    wire_message_kind: WireMessageKindV1,
    payload_json: Value,
) -> RouterAbProtocolResult<(Vec<u8>, PublicDigest32)> {
    match wire_message_kind {
        WireMessageKindV1::RouterToSignerA | WireMessageKindV1::RouterToSignerB => {
            let payload: RouterToSignerPayloadV1 = payload_from_json(payload_json)?;
            let canonical_bytes = encode_router_to_signer_payload_v1(&payload);
            let digest = payload.digest();
            Ok((canonical_bytes, digest))
        }
        WireMessageKindV1::SignerAToSignerB | WireMessageKindV1::SignerBToSignerA => {
            let payload: AbPeerMessagePayloadV1 = payload_from_json(payload_json)?;
            let canonical_bytes = encode_ab_peer_message_payload_v1(&payload);
            let digest = payload.digest();
            Ok((canonical_bytes, digest))
        }
        WireMessageKindV1::RecipientProofBundle => {
            let payload: RecipientProofBundleCiphertextV1 = payload_from_json(payload_json)?;
            let canonical_bytes = encode_recipient_proof_bundle_ciphertext_v1(&payload)?;
            let digest = payload.digest()?;
            Ok((canonical_bytes, digest))
        }
    }
}

fn payload_from_json<T>(value: Value) -> RouterAbProtocolResult<T>
where
    T: for<'de> Deserialize<'de>,
{
    serde_json::from_value(value).map_err(|err| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("payload JSON is invalid: {err}"),
        )
    })
}

fn sample_router_to_signer_a_payload() -> RouterToSignerPayloadV1 {
    RouterToSignerPayloadV1::signer_a(
        sample_lifecycle_scope(),
        sample_signer_set(),
        sample_transcript_metadata(),
        sample_envelope_digest_set(),
        digest_seed(0x33),
        sample_assignment(Role::SignerA, 0xa1),
    )
    .expect("router-to-signer-a payload")
}

fn sample_router_to_signer_b_payload() -> RouterToSignerPayloadV1 {
    RouterToSignerPayloadV1::signer_b(
        sample_lifecycle_scope(),
        sample_signer_set(),
        sample_transcript_metadata(),
        sample_envelope_digest_set(),
        digest_seed(0x33),
        sample_assignment(Role::SignerB, 0xb1),
    )
    .expect("router-to-signer-b payload")
}

fn sample_ab_peer_message_payload(from_role: Role) -> AbPeerMessagePayloadV1 {
    let (from, to, seed) = match from_role {
        Role::SignerA => (sample_signer_a(), sample_signer_b(), 0xd1),
        Role::SignerB => (sample_signer_b(), sample_signer_a(), 0xd2),
        _ => unreachable!("sample peer role"),
    };
    let transcript_digest = digest_seed(seed);
    let payload =
        CanonicalWireBytesV1::new(vec![seed, seed.wrapping_add(1)]).expect("peer payload");
    let auth_digest =
        ab_peer_message_authentication_input_digest_v1(&from, &to, transcript_digest, &payload);
    AbPeerMessagePayloadV1::new(
        from,
        to,
        transcript_digest,
        payload,
        AbPeerMessageAuthenticationV1::new(
            AbPeerMessageSignatureSchemeV1::Ed25519V1,
            auth_digest,
            CanonicalWireBytesV1::new(vec![seed, 0xed, 0x19]).expect("peer signature"),
        )
        .expect("peer authentication"),
    )
    .expect("ab peer payload")
}

fn sample_recipient_proof_bundle_payload() -> RecipientProofBundlePayloadV1 {
    let transcript_digest = digest_seed(0x77);
    let root_share_epoch = RootShareEpoch::new("epoch-1").expect("root epoch");
    let proof_bundle = sample_mpc_prf_proof_bundle(
        transcript_digest,
        root_share_epoch.clone(),
        OpenedShareKind::XClientBase,
        Role::Client,
        "client",
        Role::SignerA,
        "signer-a",
        0x77,
    );
    let proof_batch = AbDerivationProofBatchPayloadV1::new(
        sample_signer_a(),
        sample_signer_b(),
        transcript_digest,
        root_share_epoch,
        vec![proof_bundle],
    )
    .expect("recipient proof batch");
    RecipientProofBundlePayloadV1::new(
        "lifecycle-1",
        sample_signer_a(),
        Role::Client,
        OpenedShareKind::XClientBase,
        "client",
        transcript_digest,
        proof_batch,
    )
    .expect("recipient proof-bundle payload")
}

fn sample_recipient_proof_bundle_ciphertext() -> RecipientProofBundleCiphertextV1 {
    let payload = sample_recipient_proof_bundle_payload();
    RecipientProofBundleCiphertextV1::new(
        RecipientOutputEncryptionAlgorithmV1::LocalDeterministicSha256V1,
        payload.signer.clone(),
        payload.recipient_role,
        payload.opened_share_kind,
        payload.recipient_identity.clone(),
        "local-client-recipient-key",
        payload.transcript_digest,
        payload.digest(),
        [0x77; 12],
        EncryptedPayloadV1::new(payload.canonical_bytes()).expect("proof-bundle ciphertext"),
    )
    .expect("recipient proof-bundle ciphertext")
}

#[allow(clippy::too_many_arguments)]
fn sample_mpc_prf_proof_bundle(
    transcript_digest: PublicDigest32,
    root_share_epoch: RootShareEpoch,
    opened_share_kind: OpenedShareKind,
    recipient_role: Role,
    recipient_identity: &str,
    signer_role: Role,
    signer_identity: &str,
    seed: u8,
) -> MpcPrfPartialProofBundleV1 {
    let binding = MpcPrfPartialBindingV1 {
        suite_id: MpcPrfSuiteId::ThresholdPrfRistretto255Sha512,
        transcript_digest,
        root_share_epoch,
        opened_share_kind,
        recipient_role,
        recipient_identity: recipient_identity.to_owned(),
        signer_role,
        signer_identity: signer_identity.to_owned(),
    };
    let signer_partial = MpcPrfSignerPartialV1::new(
        binding,
        MpcPrfPartialWireV1::new(vec![seed; MPC_PRF_PARTIAL_WIRE_V1_LEN]).expect("partial wire"),
    )
    .expect("signer partial");
    MpcPrfPartialProofBundleV1::new(
        signer_partial,
        MpcPrfShareCommitmentWireV1::new(vec![
            seed.wrapping_add(1);
            MPC_PRF_COMMITMENT_WIRE_V1_LEN
        ])
        .expect("commitment wire"),
        MpcPrfDleqProofWireV1::new(vec![seed.wrapping_add(2); MPC_PRF_DLEQ_PROOF_WIRE_V1_LEN])
            .expect("DLEQ proof wire"),
    )
    .expect("proof bundle")
}

fn sample_lifecycle_scope() -> LifecycleScopeV1 {
    LifecycleScopeV1::new(
        "lifecycle-1",
        ExpensiveWorkKindV1::RegistrationPrepare,
        RootShareEpoch::new("epoch-1").expect("root epoch"),
        "wallet-1",
        "session-1",
        "signer-set-v1",
        "relayer-a",
    )
    .expect("lifecycle scope")
}

fn sample_signer_set() -> SignerSetV1 {
    SignerSetV1::v1_all2(
        "signer-set-v1",
        sample_signer_a(),
        sample_signer_b(),
        sample_relayer(),
    )
    .expect("signer set")
}

fn sample_assignment(role: Role, seed: u8) -> RoleEnvelopeAssignmentV1 {
    let signer = match role {
        Role::SignerA => sample_signer_a(),
        Role::SignerB => sample_signer_b(),
        _ => unreachable!("sample assignment role"),
    };
    RoleEnvelopeAssignmentV1::new(signer, sample_role_envelope(role, seed))
        .expect("role envelope assignment")
}

fn sample_role_envelope(role: Role, seed: u8) -> RoleEncryptedEnvelopeV1 {
    RoleEncryptedEnvelopeV1::new(
        role,
        digest_seed(seed),
        digest_seed(seed.wrapping_add(1)),
        EncryptedPayloadV1::new(vec![seed, seed.wrapping_add(1), seed.wrapping_add(2)])
            .expect("encrypted payload"),
    )
    .expect("role envelope")
}

fn sample_transcript_metadata() -> RouterTranscriptMetadataV1 {
    RouterTranscriptMetadataV1::new(
        "near-testnet",
        "ed25519:11111111111111111111111111111111",
        "router",
        "client",
        "x25519:client-ephemeral-public-key",
    )
    .expect("transcript metadata")
}

fn sample_envelope_digest_set() -> RouterEnvelopeDigestSetV1 {
    RouterEnvelopeDigestSetV1::new(
        role_encrypted_envelope_digest_v1(&sample_role_envelope(Role::SignerA, 0xa1))
            .expect("signer a envelope digest"),
        role_encrypted_envelope_digest_v1(&sample_role_envelope(Role::SignerB, 0xb1))
            .expect("signer b envelope digest"),
    )
}

fn sample_signer_a() -> SignerIdentityV1 {
    SignerIdentityV1::new(Role::SignerA, "signer-a", "signer-a-key-epoch-1").expect("signer a")
}

fn sample_signer_b() -> SignerIdentityV1 {
    SignerIdentityV1::new(Role::SignerB, "signer-b", "signer-b-key-epoch-1").expect("signer b")
}

fn sample_relayer() -> RelayerIdentityV1 {
    RelayerIdentityV1::new(
        "relayer-a",
        "relayer-key-epoch-1",
        "x25519:1111111111111111111111111111111111111111111111111111111111111111",
    )
    .expect("relayer")
}

fn digest_seed(seed: u8) -> PublicDigest32 {
    PublicDigest32::new([seed; 32])
}

fn public_digest_from_hex(hex_value: &str) -> RouterAbProtocolResult<PublicDigest32> {
    let bytes = hex_to_bytes(hex_value)?;
    let digest: [u8; 32] = bytes.try_into().map_err(|_| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "public digest hex must decode to 32 bytes",
        )
    })?;
    Ok(PublicDigest32::new(digest))
}

fn hex_to_bytes(hex_value: &str) -> RouterAbProtocolResult<Vec<u8>> {
    hex::decode(hex_value).map_err(|err| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("hex field is invalid: {err}"),
        )
    })
}
