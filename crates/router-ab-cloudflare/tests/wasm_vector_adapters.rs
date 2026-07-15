#![cfg(target_arch = "wasm32")]

use hpke_ng::{DhKemX25519HkdfSha256, Kem};
use router_ab_cloudflare::{
    open_cloudflare_recipient_proof_bundle_hpke_payload_v1,
    validate_cloudflare_deriver_peer_request_v1, validate_cloudflare_signer_private_request_v1,
    CloudflareHpkeRecipientProofBundleEncryptorV1, CloudflareWorkerRoleV1,
};
use router_ab_core::{
    decode_ab_peer_message_payload_v1, decode_router_to_signer_payload_v1,
    parse_payload_vector_fixture_v1, parse_wire_vector_fixture_v1,
    validate_payload_vector_fixture_v1, validate_wire_vector_fixture_v1, CanonicalWireBytesV1,
    EcdsaThresholdPrfProofBatchPayloadV1, EncryptedPayloadV1, MpcPrfDleqProofWireV1,
    MpcPrfPartialBindingV1, MpcPrfPartialProofBundleV1, MpcPrfPartialWireV1,
    MpcPrfShareCommitmentWireV1, MpcPrfSignerPartialV1, OpenedShareKind, PayloadVectorCaseV1,
    PublicDigest32, RecipientOutputEncryptionAlgorithmV1, RecipientProofBundleCiphertextV1,
    RecipientProofBundleEncryptionRequestV1, RecipientProofBundleEncryptorV1,
    RecipientProofBundlePayloadV1, Role, RootShareEpoch, SignerIdentityV1, WireMessageKindV1,
    WireMessageV1, MPC_PRF_COMMITMENT_WIRE_V1_LEN, MPC_PRF_DLEQ_PROOF_WIRE_V1_LEN,
    MPC_PRF_PARTIAL_WIRE_V1_LEN,
};
use wasm_bindgen_test::wasm_bindgen_test;

const WIRE_FIXTURE_JSON: &str =
    include_str!("../../router-ab-core/fixtures/protocol/wire/wire-vectors-v1.json");
const PAYLOAD_FIXTURE_JSON: &str =
    include_str!("../../router-ab-core/fixtures/protocol/payload/payload-vectors-v1.json");

#[wasm_bindgen_test]
fn wasm_cloudflare_adapter_round_trips_committed_wire_vectors_through_json_boundary() {
    let fixture = parse_wire_vector_fixture_v1(WIRE_FIXTURE_JSON).expect("wire fixture");
    validate_wire_vector_fixture_v1(&fixture).expect("wire vectors validate");

    for case in fixture.cases {
        let message = WireMessageV1::new(
            case.kind,
            digest_from_hex(&case.transcript_digest_hex),
            CanonicalWireBytesV1::new(bytes_from_hex(&case.payload_hex)).expect("payload bytes"),
        )
        .expect("wire message");
        let encoded = serde_json::to_string(&message).expect("wire message json");
        let decoded: WireMessageV1 = serde_json::from_str(&encoded).expect("decode json");

        assert_eq!(decoded, message, "{}", case.case_id);
    }
}

#[wasm_bindgen_test]
fn wasm_cloudflare_adapter_validates_committed_route_payload_vectors() {
    let fixture = parse_payload_vector_fixture_v1(PAYLOAD_FIXTURE_JSON).expect("payload fixture");
    validate_payload_vector_fixture_v1(&fixture).expect("payload vectors validate");

    let mut routed_cases = 0usize;
    for case in fixture.cases {
        if validate_payload_vector_case_through_cloudflare_adapter(&case) {
            routed_cases += 1;
        }
    }

    assert_eq!(routed_cases, 4);
}

#[wasm_bindgen_test]
fn wasm_cloudflare_hpke_recipient_proof_bundle_seals_opens_and_rejects_aad_drift() {
    let (recipient_private_key, recipient_public_key) =
        DhKemX25519HkdfSha256::derive_key_pair(&[0x44; 32]).expect("recipient keypair derives");
    let recipient_private_key = DhKemX25519HkdfSha256::sk_to_bytes(&recipient_private_key);
    let recipient_public_key = format!(
        "x25519:{}",
        lower_hex(&DhKemX25519HkdfSha256::pk_to_bytes(&recipient_public_key))
    );
    let payload = sample_recipient_proof_bundle_payload();
    let request = RecipientProofBundleEncryptionRequestV1::new(&payload, recipient_public_key)
        .expect("recipient proof-bundle encryption request");
    let mut encryptor = CloudflareHpkeRecipientProofBundleEncryptorV1::new();
    let envelope = encryptor
        .encrypt_recipient_proof_bundle_v1(request)
        .expect("proof-bundle HPKE seals in wasm");

    assert_eq!(
        envelope.algorithm,
        RecipientOutputEncryptionAlgorithmV1::HpkeX25519HkdfSha256Aes256GcmV1
    );
    let opened =
        open_cloudflare_recipient_proof_bundle_hpke_payload_v1(&envelope, &recipient_private_key)
            .expect("proof-bundle HPKE opens in wasm");
    assert_eq!(opened, payload);

    let mut tampered = envelope.clone();
    tampered.payload_digest = PublicDigest32::new([0xee; 32]);
    let tampered_nonce = *tampered.nonce();
    let tampered_ciphertext =
        EncryptedPayloadV1::new(tampered.ciphertext_and_tag().as_bytes().to_vec())
            .expect("tampered ciphertext clone");
    let tampered = RecipientProofBundleCiphertextV1::new(
        tampered.algorithm,
        tampered.signer,
        tampered.recipient_role,
        tampered.opened_share_kind,
        tampered.recipient_identity,
        tampered.recipient_encryption_key,
        tampered.transcript_digest,
        tampered.payload_digest,
        tampered_nonce,
        tampered_ciphertext,
    )
    .expect("tampered envelope remains structurally valid");

    open_cloudflare_recipient_proof_bundle_hpke_payload_v1(&tampered, &recipient_private_key)
        .expect_err("AAD-bound payload digest drift must fail in wasm");
}

fn validate_payload_vector_case_through_cloudflare_adapter(case: &PayloadVectorCaseV1) -> bool {
    let payload = CanonicalWireBytesV1::new(bytes_from_hex(&case.canonical_bytes_hex))
        .expect("payload bytes");
    match case.wire_message_kind {
        WireMessageKindV1::RouterToSignerA => {
            let router_payload =
                decode_router_to_signer_payload_v1(payload.as_bytes()).expect("router payload");
            let message = WireMessageV1::new(
                case.wire_message_kind,
                router_payload.transcript_digest(),
                payload,
            )
            .expect("wire message");
            validate_cloudflare_signer_private_request_v1(
                CloudflareWorkerRoleV1::DeriverA,
                &message,
            )
            .expect("signer a private vector");
            true
        }
        WireMessageKindV1::RouterToSignerB => {
            let router_payload =
                decode_router_to_signer_payload_v1(payload.as_bytes()).expect("router payload");
            let message = WireMessageV1::new(
                case.wire_message_kind,
                router_payload.transcript_digest(),
                payload,
            )
            .expect("wire message");
            validate_cloudflare_signer_private_request_v1(
                CloudflareWorkerRoleV1::DeriverB,
                &message,
            )
            .expect("signer b private vector");
            true
        }
        WireMessageKindV1::SignerAToSignerB => {
            let peer_payload =
                decode_ab_peer_message_payload_v1(payload.as_bytes()).expect("peer payload");
            let message = WireMessageV1::new(
                case.wire_message_kind,
                peer_payload.transcript_digest,
                payload,
            )
            .expect("wire message");
            validate_cloudflare_deriver_peer_request_v1(CloudflareWorkerRoleV1::DeriverB, &message)
                .expect("signer b peer vector");
            true
        }
        WireMessageKindV1::SignerBToSignerA => {
            let peer_payload =
                decode_ab_peer_message_payload_v1(payload.as_bytes()).expect("peer payload");
            let message = WireMessageV1::new(
                case.wire_message_kind,
                peer_payload.transcript_digest,
                payload,
            )
            .expect("wire message");
            validate_cloudflare_deriver_peer_request_v1(CloudflareWorkerRoleV1::DeriverA, &message)
                .expect("signer a peer vector");
            true
        }
        WireMessageKindV1::RecipientProofBundle => false,
    }
}

fn digest_from_hex(hex: &str) -> PublicDigest32 {
    let bytes = bytes_from_hex(hex);
    let array: [u8; 32] = bytes.try_into().expect("digest length");
    PublicDigest32::new(array)
}

fn bytes_from_hex(hex: &str) -> Vec<u8> {
    assert_eq!(hex.len() % 2, 0, "hex string length");
    (0..hex.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).expect("hex byte"))
        .collect()
}

fn digest(seed: u8) -> PublicDigest32 {
    PublicDigest32::new([seed; 32])
}

fn sample_recipient_proof_bundle_payload() -> RecipientProofBundlePayloadV1 {
    let transcript_digest = digest(0x77);
    let root_share_epoch = RootShareEpoch::new("epoch-1").expect("root epoch");
    let proof_batch = EcdsaThresholdPrfProofBatchPayloadV1::new(
        signer(Role::SignerA, "signer-a"),
        signer(Role::SignerB, "signer-b"),
        transcript_digest,
        root_share_epoch.clone(),
        vec![sample_mpc_prf_proof_bundle(
            transcript_digest,
            root_share_epoch,
            OpenedShareKind::XClientBase,
            Role::Client,
            "client",
            Role::SignerA,
            "signer-a",
            0x77,
        )],
    )
    .expect("proof batch");
    RecipientProofBundlePayloadV1::new(
        "lifecycle-1",
        signer(Role::SignerA, "signer-a"),
        Role::Client,
        OpenedShareKind::XClientBase,
        "client",
        transcript_digest,
        proof_batch,
    )
    .expect("recipient proof-bundle payload")
}

fn signer(role: Role, signer_id: &str) -> SignerIdentityV1 {
    SignerIdentityV1::new(role, signer_id, "key-epoch-1").expect("signer identity")
}

fn fixed_share_wire_bytes(role: Role, fill: u8, len: usize) -> Vec<u8> {
    let share_id = match role {
        Role::SignerA => 1u16,
        Role::SignerB => 2u16,
        _ => panic!("fixed share wire requires a Deriver role"),
    };
    let mut bytes = vec![fill; len];
    bytes[..2].copy_from_slice(&share_id.to_be_bytes());
    bytes
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
        MpcPrfPartialWireV1::new(fixed_share_wire_bytes(
            signer_role,
            seed,
            MPC_PRF_PARTIAL_WIRE_V1_LEN,
        ))
        .expect("partial wire"),
    )
    .expect("signer partial");
    MpcPrfPartialProofBundleV1::new(
        signer_partial,
        MpcPrfShareCommitmentWireV1::new(fixed_share_wire_bytes(
            signer_role,
            seed.wrapping_add(1),
            MPC_PRF_COMMITMENT_WIRE_V1_LEN,
        ))
        .expect("commitment wire"),
        MpcPrfDleqProofWireV1::new(vec![seed.wrapping_add(2); MPC_PRF_DLEQ_PROOF_WIRE_V1_LEN])
            .expect("DLEQ proof wire"),
    )
    .expect("proof bundle")
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
