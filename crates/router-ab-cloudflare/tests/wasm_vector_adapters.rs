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
use router_ab_ecdsa_client_protocol::{
    decode_ecdsa_client_proof_bundle_envelope_v1, open_ecdsa_client_proof_bundle_v1,
    pair_ecdsa_opened_client_proof_bundles_v1, EcdsaClientProtocolError, EcdsaDeriverRoleV1,
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

    let client_envelope = decode_ecdsa_client_proof_bundle_envelope_v1(
        &envelope.canonical_bytes().expect("canonical envelope"),
    )
    .expect("client-safe decoder accepts Cloudflare envelope");
    let client_private_key: [u8; 32] = recipient_private_key
        .as_slice()
        .try_into()
        .expect("fixed client private key");
    let client_opened = open_ecdsa_client_proof_bundle_v1(&client_envelope, &client_private_key)
        .expect("client-safe opener accepts Cloudflare envelope");
    assert_eq!(client_opened.lifecycle_id, "lifecycle-1");
    assert_eq!(client_opened.root_share_epoch, "epoch-1");
    assert_eq!(client_opened.recipient_identity, "client");
    assert_eq!(client_opened.role_bound_proof.role, EcdsaDeriverRoleV1::A);
    assert_eq!(
        client_opened.role_bound_proof.proof.partial_wire.as_slice(),
        opened.proof_batch.proof_bundles[0]
            .signer_partial
            .partial_wire
            .as_bytes(),
    );

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

#[wasm_bindgen_test]
fn wasm_client_safe_pair_rejects_core_proof_batch_peer_identity_drift() {
    let (recipient_private_key, recipient_public_key) =
        DhKemX25519HkdfSha256::derive_key_pair(&[0x54; 32]).expect("recipient keypair derives");
    let recipient_private_key = DhKemX25519HkdfSha256::sk_to_bytes(&recipient_private_key);
    let recipient_private_key: [u8; 32] = recipient_private_key
        .as_slice()
        .try_into()
        .expect("fixed client private key");
    let recipient_public_key = format!(
        "x25519:{}",
        lower_hex(&DhKemX25519HkdfSha256::pk_to_bytes(&recipient_public_key))
    );
    let signer_a_payload = sample_recipient_proof_bundle_payload_for_role(Role::SignerA);
    let signer_b_payload = sample_recipient_proof_bundle_payload_for_role(Role::SignerB);
    let opened_a = open_core_generated_client_payload(
        &signer_a_payload,
        &recipient_public_key,
        &recipient_private_key,
    );
    let opened_b = open_core_generated_client_payload(
        &signer_b_payload,
        &recipient_public_key,
        &recipient_private_key,
    );
    pair_ecdsa_opened_client_proof_bundles_v1(opened_a, opened_b.clone()).expect("exact A/B pair");

    let mut drifted_batch = signer_a_payload.proof_batch;
    drifted_batch.to = signer(Role::SignerB, "substituted-signer-b");
    let drifted_payload = RecipientProofBundlePayloadV1::new(
        signer_a_payload.lifecycle_id,
        signer_a_payload.signer,
        signer_a_payload.recipient_role,
        signer_a_payload.opened_share_kind,
        signer_a_payload.recipient_identity,
        signer_a_payload.transcript_digest,
        drifted_batch,
    )
    .expect("peer-id drift remains a valid isolated core payload");
    let drifted_opened = open_core_generated_client_payload(
        &drifted_payload,
        &recipient_public_key,
        &recipient_private_key,
    );
    assert_eq!(
        pair_ecdsa_opened_client_proof_bundles_v1(drifted_opened, opened_b),
        Err(EcdsaClientProtocolError::InvalidShape),
    );

    let mut drifted_epoch_batch =
        sample_recipient_proof_bundle_payload_for_role(Role::SignerA).proof_batch;
    drifted_epoch_batch.to =
        SignerIdentityV1::new(Role::SignerB, "signer-b", "substituted-key-epoch")
            .expect("drifted peer epoch");
    let base = sample_recipient_proof_bundle_payload_for_role(Role::SignerA);
    let drifted_epoch_payload = RecipientProofBundlePayloadV1::new(
        base.lifecycle_id,
        base.signer,
        base.recipient_role,
        base.opened_share_kind,
        base.recipient_identity,
        base.transcript_digest,
        drifted_epoch_batch,
    )
    .expect("peer-epoch drift remains a valid isolated core payload");
    let drifted_epoch_opened = open_core_generated_client_payload(
        &drifted_epoch_payload,
        &recipient_public_key,
        &recipient_private_key,
    );
    let opened_b = open_core_generated_client_payload(
        &signer_b_payload,
        &recipient_public_key,
        &recipient_private_key,
    );
    assert_eq!(
        pair_ecdsa_opened_client_proof_bundles_v1(drifted_epoch_opened, opened_b),
        Err(EcdsaClientProtocolError::InvalidShape),
    );
}

fn open_core_generated_client_payload(
    payload: &RecipientProofBundlePayloadV1,
    recipient_public_key: &str,
    recipient_private_key: &[u8; 32],
) -> router_ab_ecdsa_client_protocol::EcdsaOpenedClientProofBundleV1 {
    let request = RecipientProofBundleEncryptionRequestV1::new(payload, recipient_public_key)
        .expect("recipient proof-bundle encryption request");
    let envelope = CloudflareHpkeRecipientProofBundleEncryptorV1::new()
        .encrypt_recipient_proof_bundle_v1(request)
        .expect("Cloudflare envelope");
    let client_envelope = decode_ecdsa_client_proof_bundle_envelope_v1(
        &envelope.canonical_bytes().expect("canonical envelope"),
    )
    .expect("client-safe envelope");
    open_ecdsa_client_proof_bundle_v1(&client_envelope, recipient_private_key)
        .expect("client-safe opened payload")
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
    sample_recipient_proof_bundle_payload_for_role(Role::SignerA)
}

fn sample_recipient_proof_bundle_payload_for_role(
    signer_role: Role,
) -> RecipientProofBundlePayloadV1 {
    let transcript_digest = digest(0x77);
    let root_share_epoch = RootShareEpoch::new("epoch-1").expect("root epoch");
    let (from, to) = match signer_role {
        Role::SignerA => (
            signer(Role::SignerA, "signer-a"),
            signer(Role::SignerB, "signer-b"),
        ),
        Role::SignerB => (
            signer(Role::SignerB, "signer-b"),
            signer(Role::SignerA, "signer-a"),
        ),
        _ => panic!("sample proof payload requires a Deriver role"),
    };
    let proof_batch = EcdsaThresholdPrfProofBatchPayloadV1::new(
        from.clone(),
        to,
        transcript_digest,
        root_share_epoch.clone(),
        vec![sample_mpc_prf_proof_bundle(
            transcript_digest,
            root_share_epoch,
            OpenedShareKind::XClientBase,
            Role::Client,
            "client",
            signer_role,
            &from.signer_id,
            0x77,
        )],
    )
    .expect("proof batch");
    RecipientProofBundlePayloadV1::new(
        "lifecycle-1",
        from,
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
