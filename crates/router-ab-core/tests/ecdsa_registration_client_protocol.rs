use base64ct::{Base64UrlUnpadded, Encoding};
use router_ab_core::derivation::{PublicDigest32, Role, RootShareEpoch};
use router_ab_core::protocol::{
    decode_signer_envelope_hpke_payload_v1, encode_signer_envelope_hpke_payload_v1,
    role_encrypted_envelope_digest_v1, EncryptedPayloadV1, ExpensiveWorkKindV1, LifecycleScopeV1,
    RoleEncryptedEnvelopeV1, RouterAbEcdsaDerivationDeriverEnvelopePlaintextV1,
    RouterAbEcdsaDerivationRegistrationBootstrapRequestV1,
    RouterAbEcdsaDerivationRegistrationPurposeV1, RouterAbEcdsaDerivationStableKeyContextV1,
    ServerIdentityV1, SignerIdentityV1, SignerSetV1,
};
use router_ab_ecdsa_client_protocol::{
    build_ecdsa_registration_request_v1, derive_ecdsa_client_ephemeral_keypair_v1,
    open_ecdsa_signer_envelope_v1, EcdsaClientProtocolError, EcdsaDeriverRoleV1,
    EcdsaRegistrationHeaderInputV1, EcdsaRegistrationHeaderV1, EcdsaRegistrationLifecycleV1,
    EcdsaRegistrationLifecycleWireV1, EcdsaRegistrationPurposeV1, EcdsaRegistrationRecipientKeysV1,
    EcdsaRegistrationRequestV1, EcdsaRegistrationSealSeedsV1, EcdsaRegistrationSignerSetV1,
    EcdsaSelectedServerIdentityV1, EcdsaSignerEnvelopeHpkePayloadV1,
    EcdsaSignerEnvelopePublicKeyV1, EcdsaSignerIdentityV1, EcdsaStableKeyContextV1,
};

const SIGNER_SET_ID: &str = "ecdsa-signers-v1";
const SERVER_ID: &str = "signing-worker-1";

fn lifecycle_wire() -> EcdsaRegistrationLifecycleWireV1 {
    EcdsaRegistrationLifecycleWireV1 {
        lifecycle_id: "registration-lifecycle-1".to_owned(),
        work_kind: "registration_prepare".to_owned(),
        primitive_request_kind: "registration".to_owned(),
        root_share_epoch: "root-epoch-7".to_owned(),
        account_id: "wallet-1".to_owned(),
        session_id: "registration-session-1".to_owned(),
        signer_set_id: SIGNER_SET_ID.to_owned(),
        selected_server_id: SERVER_ID.to_owned(),
    }
}

fn signer_a() -> EcdsaSignerIdentityV1 {
    EcdsaSignerIdentityV1 {
        role: EcdsaDeriverRoleV1::A,
        signer_id: "deriver-a-1".to_owned(),
        key_epoch: "deriver-a-epoch-3".to_owned(),
    }
}

fn signer_b() -> EcdsaSignerIdentityV1 {
    EcdsaSignerIdentityV1 {
        role: EcdsaDeriverRoleV1::B,
        signer_id: "deriver-b-1".to_owned(),
        key_epoch: "deriver-b-epoch-4".to_owned(),
    }
}

fn selected_server() -> EcdsaSelectedServerIdentityV1 {
    EcdsaSelectedServerIdentityV1 {
        server_id: SERVER_ID.to_owned(),
        key_epoch: "signing-worker-epoch-2".to_owned(),
        recipient_encryption_key:
            "x25519:1111111111111111111111111111111111111111111111111111111111111111".to_owned(),
    }
}

fn application_binding_digest() -> String {
    Base64UrlUnpadded::encode_string(&[0x29; 32])
}

fn client_header() -> EcdsaRegistrationHeaderV1 {
    let client_ephemeral =
        derive_ecdsa_client_ephemeral_keypair_v1([0x91; 32]).expect("client ephemeral keypair");
    EcdsaRegistrationHeaderV1::new(EcdsaRegistrationHeaderInputV1 {
        registration_purpose: EcdsaRegistrationPurposeV1::WalletRegistration,
        context: EcdsaStableKeyContextV1::new(application_binding_digest()).expect("context"),
        lifecycle: EcdsaRegistrationLifecycleV1::from_wire(lifecycle_wire()).expect("lifecycle"),
        signer_set: EcdsaRegistrationSignerSetV1::new(
            SIGNER_SET_ID,
            signer_a(),
            signer_b(),
            selected_server(),
        )
        .expect("signer set"),
        router_id: "router-1".to_owned(),
        client_id: "browser-client-1".to_owned(),
        client_ephemeral_public_key: client_ephemeral.public_key().to_owned(),
        replay_nonce: "registration-nonce-1".to_owned(),
        expires_at_ms: 8_000_000,
    })
    .expect("header")
}

fn recipient_keys() -> EcdsaRegistrationRecipientKeysV1 {
    let deriver_a =
        derive_ecdsa_client_ephemeral_keypair_v1([0xa1; 32]).expect("Deriver A recipient key");
    let deriver_b =
        derive_ecdsa_client_ephemeral_keypair_v1([0xb2; 32]).expect("Deriver B recipient key");
    EcdsaRegistrationRecipientKeysV1 {
        deriver_a: EcdsaSignerEnvelopePublicKeyV1 {
            role: EcdsaDeriverRoleV1::A,
            key_epoch: signer_a().key_epoch,
            public_key: deriver_a.public_key().to_owned(),
        },
        deriver_b: EcdsaSignerEnvelopePublicKeyV1 {
            role: EcdsaDeriverRoleV1::B,
            key_epoch: signer_b().key_epoch,
            public_key: deriver_b.public_key().to_owned(),
        },
    }
}

fn recipient_private_key(role: EcdsaDeriverRoleV1) -> [u8; 32] {
    let seed = match role {
        EcdsaDeriverRoleV1::A => [0xa1; 32],
        EcdsaDeriverRoleV1::B => [0xb2; 32],
    };
    *derive_ecdsa_client_ephemeral_keypair_v1(seed)
        .expect("recipient keypair")
        .private_key_bytes()
}

fn client_request() -> EcdsaRegistrationRequestV1 {
    build_ecdsa_registration_request_v1(
        client_header(),
        recipient_keys(),
        EcdsaRegistrationSealSeedsV1 {
            deriver_a: [0xc3; 32],
            deriver_b: [0xd4; 32],
        },
    )
    .expect("client registration request")
}

fn core_signer_set() -> SignerSetV1 {
    SignerSetV1::v1_all2(
        SIGNER_SET_ID,
        SignerIdentityV1::new(Role::SignerA, signer_a().signer_id, signer_a().key_epoch)
            .expect("Signer A"),
        SignerIdentityV1::new(Role::SignerB, signer_b().signer_id, signer_b().key_epoch)
            .expect("Signer B"),
        ServerIdentityV1::new(
            selected_server().server_id,
            selected_server().key_epoch,
            selected_server().recipient_encryption_key,
        )
        .expect("selected server"),
    )
    .expect("core signer set")
}

fn core_lifecycle() -> LifecycleScopeV1 {
    let wire = lifecycle_wire();
    LifecycleScopeV1::new(
        wire.lifecycle_id,
        ExpensiveWorkKindV1::RegistrationPrepare,
        RootShareEpoch::new(wire.root_share_epoch).expect("root epoch"),
        wire.account_id,
        wire.session_id,
        wire.signer_set_id,
        wire.selected_server_id,
    )
    .expect("core lifecycle")
}

fn core_envelope(
    envelope: &router_ab_ecdsa_client_protocol::EcdsaRegistrationEncryptedEnvelopeV1,
) -> RoleEncryptedEnvelopeV1 {
    let role = match envelope.recipient_role() {
        EcdsaDeriverRoleV1::A => Role::SignerA,
        EcdsaDeriverRoleV1::B => Role::SignerB,
    };
    RoleEncryptedEnvelopeV1::new(
        role,
        PublicDigest32::new(envelope.header_digest()),
        PublicDigest32::new(envelope.aad_digest()),
        EncryptedPayloadV1::new(envelope.ciphertext().to_vec()).expect("ciphertext"),
    )
    .expect("core envelope")
}

fn core_request(
    client: &EcdsaRegistrationRequestV1,
) -> RouterAbEcdsaDerivationRegistrationBootstrapRequestV1 {
    RouterAbEcdsaDerivationRegistrationBootstrapRequestV1::new(
        RouterAbEcdsaDerivationRegistrationPurposeV1::WalletRegistration,
        RouterAbEcdsaDerivationStableKeyContextV1::new(application_binding_digest())
            .expect("core context"),
        core_lifecycle(),
        core_signer_set(),
        client.header().router_id(),
        client.header().client_id(),
        client.header().client_ephemeral_public_key(),
        client.header().replay_nonce(),
        client.header().expires_at_ms(),
        core_envelope(client.deriver_a_envelope()),
        core_envelope(client.deriver_b_envelope()),
    )
    .expect("core request")
}

#[test]
fn client_registration_header_aad_envelopes_and_request_match_core() {
    let client = client_request();
    let core = core_request(&client);

    assert_eq!(
        client.header().canonical_bytes().expect("client header"),
        core.canonical_request_header_bytes().expect("core header"),
    );
    assert_eq!(
        client.header().digest().expect("client header digest"),
        *core
            .request_header_digest()
            .expect("core header digest")
            .as_bytes(),
    );
    assert_eq!(
        client
            .header()
            .transcript_digest()
            .expect("client transcript"),
        *core
            .header()
            .transcript_digest()
            .expect("core transcript")
            .as_bytes(),
    );

    for (client_role, core_role) in [
        (EcdsaDeriverRoleV1::A, Role::SignerA),
        (EcdsaDeriverRoleV1::B, Role::SignerB),
    ] {
        let client_aad = client.header().role_aad(client_role).expect("client AAD");
        let core_aad = core.header().role_aad(core_role).expect("core AAD");
        assert_eq!(
            client_aad.canonical_bytes().expect("client AAD bytes"),
            core_aad.canonical_bytes()
        );
        assert_eq!(
            client_aad.digest().expect("client AAD digest"),
            *core_aad.digest().as_bytes()
        );
    }

    for (client_envelope, core_envelope) in [
        (client.deriver_a_envelope(), &core.deriver_a_envelope),
        (client.deriver_b_envelope(), &core.deriver_b_envelope),
    ] {
        assert_eq!(
            client_envelope.digest().expect("client envelope digest"),
            *role_encrypted_envelope_digest_v1(core_envelope)
                .expect("core envelope digest")
                .as_bytes(),
        );
        let decoded = decode_signer_envelope_hpke_payload_v1(client_envelope.ciphertext())
            .expect("core HPKE payload decode");
        assert_eq!(
            encode_signer_envelope_hpke_payload_v1(&decoded),
            client_envelope.ciphertext(),
        );
        let client_payload = EcdsaSignerEnvelopeHpkePayloadV1 {
            recipient_role: client_envelope.recipient_role(),
            key_epoch: decoded.key_epoch.clone(),
            recipient_public_key: decoded.recipient_public_key.clone(),
            aad_digest: client_envelope.aad_digest(),
            encapped_key: *decoded.encapped_key(),
            ciphertext_and_tag: decoded.ciphertext_and_tag().to_vec(),
        };
        let client_aad = client
            .header()
            .role_aad(client_envelope.recipient_role())
            .expect("client role AAD");
        let opened = open_ecdsa_signer_envelope_v1(
            &client_payload,
            &client_aad,
            &recipient_private_key(client_envelope.recipient_role()),
        )
        .expect("open client envelope");
        let expected_plaintext =
            RouterAbEcdsaDerivationDeriverEnvelopePlaintextV1::registration_for_request(
                &core,
                core_envelope.recipient_role,
                core_envelope.aad_digest,
            )
            .expect("core registration plaintext")
            .canonical_plaintext_bytes()
            .expect("core plaintext bytes");
        assert_eq!(opened, expected_plaintext);
    }

    assert_eq!(
        client.canonical_bytes().expect("client request bytes"),
        core.canonical_request_bytes().expect("core request bytes"),
    );
    assert_eq!(
        client.digest().expect("client request digest"),
        *core
            .request_digest()
            .expect("core request digest")
            .as_bytes(),
    );
}

#[test]
fn registration_boundary_rejects_unknown_and_mismatched_lifecycle_or_purpose() {
    assert_eq!(
        EcdsaRegistrationPurposeV1::from_wire_label("recovery"),
        Err(EcdsaClientProtocolError::InvalidShape),
    );

    let mut unknown_work = lifecycle_wire();
    unknown_work.work_kind = "registration_unknown".to_owned();
    assert_eq!(
        EcdsaRegistrationLifecycleV1::from_wire(unknown_work),
        Err(EcdsaClientProtocolError::InvalidShape),
    );

    let mut mismatched_primitive = lifecycle_wire();
    mismatched_primitive.primitive_request_kind = "recovery".to_owned();
    assert_eq!(
        EcdsaRegistrationLifecycleV1::from_wire(mismatched_primitive),
        Err(EcdsaClientProtocolError::InvalidShape),
    );

    let request = client_request();
    assert_eq!(
        request.validate_for_registration_purpose(EcdsaRegistrationPurposeV1::WalletAddSigner),
        Err(EcdsaClientProtocolError::InvalidShape),
    );
}

#[test]
fn registration_builder_rejects_recipient_key_epoch_drift() {
    let mut keys = recipient_keys();
    keys.deriver_b.key_epoch = "wrong-epoch".to_owned();
    assert_eq!(
        build_ecdsa_registration_request_v1(
            client_header(),
            keys,
            EcdsaRegistrationSealSeedsV1 {
                deriver_a: [0xc3; 32],
                deriver_b: [0xd4; 32],
            },
        ),
        Err(EcdsaClientProtocolError::InvalidShape),
    );
}

#[test]
fn client_ephemeral_keypair_is_deterministic_and_seed_bound() {
    let first = derive_ecdsa_client_ephemeral_keypair_v1([0x51; 32]).expect("first keypair");
    let second = derive_ecdsa_client_ephemeral_keypair_v1([0x51; 32]).expect("second keypair");
    let other = derive_ecdsa_client_ephemeral_keypair_v1([0x52; 32]).expect("other keypair");
    assert_eq!(first.public_key(), second.public_key());
    assert_eq!(first.private_key_bytes(), second.private_key_bytes());
    assert_ne!(first.public_key(), other.public_key());
    assert_ne!(first.private_key_bytes(), other.private_key_bytes());
    assert!(first.public_key().starts_with("x25519:"));
    assert_eq!(first.public_key().len(), "x25519:".len() + 64);
}
