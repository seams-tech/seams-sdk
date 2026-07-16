use base64ct::{Base64UrlUnpadded, Encoding};
use router_ab_core::derivation::{PublicDigest32, Role, RootShareEpoch};
use router_ab_core::protocol::{
    decode_signer_envelope_hpke_payload_v1, role_encrypted_envelope_digest_v1,
    EcdsaThresholdPrfRequestV1, EncryptedPayloadV1, ExpensiveWorkKindV1, LifecycleScopeV1,
    RoleEncryptedEnvelopeV1, RoleEnvelopeAadV1, RouterAbEcdsaDerivationActivationRefreshRequestV1,
    RouterAbEcdsaDerivationDeriverEnvelopePlaintextV1,
    RouterAbEcdsaDerivationExplicitExportRequestV1, RouterAbEcdsaDerivationPublicIdentityV1,
    RouterAbEcdsaDerivationRecoveryRequestV1, RouterAbEcdsaDerivationStableKeyContextV1,
    ServerIdentityV1, SignerIdentityV1, SignerSetV1,
};
use router_ab_ecdsa_client_protocol::{
    build_ecdsa_post_registration_request_v1, derive_ecdsa_client_ephemeral_keypair_v1,
    open_ecdsa_signer_envelope_v1, EcdsaClientProtocolError, EcdsaDeriverRoleV1,
    EcdsaPostRegistrationCeremonyV1, EcdsaPostRegistrationHeaderInputV1,
    EcdsaPostRegistrationHeaderV1, EcdsaPostRegistrationLifecycleV1,
    EcdsaPostRegistrationLifecycleWireV1, EcdsaPostRegistrationOperationV1,
    EcdsaPostRegistrationRecipientV1, EcdsaPostRegistrationRequestV1, EcdsaPublicIdentityInputV1,
    EcdsaPublicIdentityV1, EcdsaRegistrationEncryptedEnvelopeV1, EcdsaRegistrationRecipientKeysV1,
    EcdsaRegistrationSealSeedsV1, EcdsaRegistrationSignerSetV1, EcdsaSelectedServerIdentityV1,
    EcdsaSignerEnvelopeHpkePayloadV1, EcdsaSignerEnvelopePublicKeyV1, EcdsaSignerIdentityV1,
    EcdsaStableKeyContextV1,
};

const SIGNER_SET_ID: &str = "ecdsa-signers-v1";
const SERVER_ID: &str = "signing-worker-1";

enum CorePostRequest {
    Export(RouterAbEcdsaDerivationExplicitExportRequestV1),
    Recovery(RouterAbEcdsaDerivationRecoveryRequestV1),
    Refresh(RouterAbEcdsaDerivationActivationRefreshRequestV1),
}

impl CorePostRequest {
    fn header_bytes(&self) -> Vec<u8> {
        match self {
            Self::Export(request) => request.canonical_request_header_bytes(),
            Self::Recovery(request) => request.canonical_request_header_bytes(),
            Self::Refresh(request) => request.canonical_request_header_bytes(),
        }
        .expect("core header bytes")
    }

    fn header_digest(&self) -> PublicDigest32 {
        match self {
            Self::Export(request) => request.request_header_digest(),
            Self::Recovery(request) => request.request_header_digest(),
            Self::Refresh(request) => request.request_header_digest(),
        }
        .expect("core header digest")
    }

    fn request_bytes(&self) -> Vec<u8> {
        match self {
            Self::Export(request) => request.canonical_request_bytes(),
            Self::Recovery(request) => request.canonical_request_bytes(),
            Self::Refresh(request) => request.canonical_request_bytes(),
        }
        .expect("core request bytes")
    }

    fn request_digest(&self) -> PublicDigest32 {
        match self {
            Self::Export(request) => request.request_digest(),
            Self::Recovery(request) => request.request_digest(),
            Self::Refresh(request) => request.request_digest(),
        }
        .expect("core request digest")
    }

    fn threshold_request(&self) -> EcdsaThresholdPrfRequestV1 {
        match self {
            Self::Export(request) => request.to_threshold_prf_request(),
            Self::Recovery(request) => request.to_threshold_prf_request(),
            Self::Refresh(request) => request.to_threshold_prf_request(),
        }
        .expect("core threshold request")
    }

    fn plaintext(&self, role: Role, aad_digest: PublicDigest32) -> Vec<u8> {
        match self {
            Self::Export(request) => {
                RouterAbEcdsaDerivationDeriverEnvelopePlaintextV1::export_for_request(
                    request, role, aad_digest,
                )
            }
            Self::Recovery(request) => {
                RouterAbEcdsaDerivationDeriverEnvelopePlaintextV1::recovery_for_request(
                    request, role, aad_digest,
                )
            }
            Self::Refresh(request) => {
                RouterAbEcdsaDerivationDeriverEnvelopePlaintextV1::refresh_for_request(
                    request, role, aad_digest,
                )
            }
        }
        .expect("core plaintext")
        .canonical_plaintext_bytes()
        .expect("core plaintext bytes")
    }
}

fn b64u<const N: usize>(bytes: &[u8; N]) -> String {
    Base64UrlUnpadded::encode_string(bytes)
}

fn public_key(prefix: u8, byte: u8) -> String {
    let mut bytes = [byte; 33];
    bytes[0] = prefix;
    b64u(&bytes)
}

fn client_context() -> EcdsaStableKeyContextV1 {
    EcdsaStableKeyContextV1::new(b64u(&[0x29; 32])).expect("client context")
}

fn core_context() -> RouterAbEcdsaDerivationStableKeyContextV1 {
    RouterAbEcdsaDerivationStableKeyContextV1::new(b64u(&[0x29; 32])).expect("core context")
}

fn client_identity() -> EcdsaPublicIdentityV1 {
    let context = client_context();
    EcdsaPublicIdentityV1::new(
        &context,
        EcdsaPublicIdentityInputV1 {
            context_binding_b64u: b64u(&context.binding_digest().expect("context binding")),
            derivation_client_share_public_key33_b64u: public_key(0x02, 0x11),
            server_public_key33_b64u: public_key(0x03, 0x22),
            threshold_public_key33_b64u: public_key(0x02, 0x33),
            ethereum_address20_b64u: b64u(&[0x44; 20]),
            client_share_retry_counter: 5,
            server_share_retry_counter: 7,
        },
    )
    .expect("client identity")
}

fn core_identity() -> RouterAbEcdsaDerivationPublicIdentityV1 {
    let context = core_context();
    RouterAbEcdsaDerivationPublicIdentityV1::new(
        b64u(
            context
                .context_binding_digest()
                .expect("core binding")
                .as_bytes(),
        ),
        public_key(0x02, 0x11),
        public_key(0x03, 0x22),
        public_key(0x02, 0x33),
        b64u(&[0x44; 20]),
        5,
        7,
    )
    .expect("core identity")
}

fn client_signer_set() -> EcdsaRegistrationSignerSetV1 {
    EcdsaRegistrationSignerSetV1::new(
        SIGNER_SET_ID,
        EcdsaSignerIdentityV1 {
            role: EcdsaDeriverRoleV1::A,
            signer_id: "deriver-a-1".to_owned(),
            key_epoch: "deriver-a-epoch-3".to_owned(),
        },
        EcdsaSignerIdentityV1 {
            role: EcdsaDeriverRoleV1::B,
            signer_id: "deriver-b-1".to_owned(),
            key_epoch: "deriver-b-epoch-4".to_owned(),
        },
        EcdsaSelectedServerIdentityV1 {
            server_id: SERVER_ID.to_owned(),
            key_epoch: "signing-worker-epoch-2".to_owned(),
            recipient_encryption_key:
                "x25519:1111111111111111111111111111111111111111111111111111111111111111"
                    .to_owned(),
        },
    )
    .expect("client signer set")
}

fn core_signer_set() -> SignerSetV1 {
    let client = client_signer_set();
    SignerSetV1::v1_all2(
        SIGNER_SET_ID,
        SignerIdentityV1::new(
            Role::SignerA,
            client.signer_a().signer_id.clone(),
            client.signer_a().key_epoch.clone(),
        )
        .expect("core A"),
        SignerIdentityV1::new(
            Role::SignerB,
            client.signer_b().signer_id.clone(),
            client.signer_b().key_epoch.clone(),
        )
        .expect("core B"),
        ServerIdentityV1::new(
            SERVER_ID,
            client.selected_server().key_epoch.clone(),
            client.selected_server().recipient_encryption_key.clone(),
        )
        .expect("core server"),
    )
    .expect("core signer set")
}

fn lifecycle_wire(
    ceremony: EcdsaPostRegistrationCeremonyV1,
) -> EcdsaPostRegistrationLifecycleWireV1 {
    let (work_kind, primitive, lifecycle_id, root_epoch) = match ceremony {
        EcdsaPostRegistrationCeremonyV1::ExplicitExport => {
            ("key_export", "export", "export-lifecycle-1", "root-epoch-1")
        }
        EcdsaPostRegistrationCeremonyV1::Recovery => (
            "recovery",
            "recovery",
            "recovery-lifecycle-1",
            "root-epoch-1",
        ),
        EcdsaPostRegistrationCeremonyV1::ActivationRefresh => (
            "server_share_refresh",
            "refresh",
            "refresh-lifecycle-1",
            "root-epoch-2",
        ),
    };
    EcdsaPostRegistrationLifecycleWireV1 {
        lifecycle_id: lifecycle_id.to_owned(),
        work_kind: work_kind.to_owned(),
        primitive_request_kind: primitive.to_owned(),
        root_share_epoch: root_epoch.to_owned(),
        account_id: "wallet-1".to_owned(),
        session_id: "wallet-session-1".to_owned(),
        signer_set_id: SIGNER_SET_ID.to_owned(),
        selected_server_id: SERVER_ID.to_owned(),
    }
}

fn core_lifecycle(ceremony: EcdsaPostRegistrationCeremonyV1) -> LifecycleScopeV1 {
    let wire = lifecycle_wire(ceremony);
    let work_kind = match ceremony {
        EcdsaPostRegistrationCeremonyV1::ExplicitExport => ExpensiveWorkKindV1::KeyExport,
        EcdsaPostRegistrationCeremonyV1::Recovery => ExpensiveWorkKindV1::Recovery,
        EcdsaPostRegistrationCeremonyV1::ActivationRefresh => {
            ExpensiveWorkKindV1::ServerShareRefresh
        }
    };
    LifecycleScopeV1::new(
        wire.lifecycle_id,
        work_kind,
        RootShareEpoch::new(wire.root_share_epoch).expect("root epoch"),
        wire.account_id,
        wire.session_id,
        wire.signer_set_id,
        wire.selected_server_id,
    )
    .expect("core lifecycle")
}

fn recipient_key(ceremony: EcdsaPostRegistrationCeremonyV1) -> String {
    let seed = match ceremony {
        EcdsaPostRegistrationCeremonyV1::ExplicitExport => [0x71; 32],
        EcdsaPostRegistrationCeremonyV1::Recovery => [0x72; 32],
        EcdsaPostRegistrationCeremonyV1::ActivationRefresh => [0x73; 32],
    };
    derive_ecdsa_client_ephemeral_keypair_v1(seed)
        .expect("output recipient")
        .public_key()
        .to_owned()
}

fn operation(ceremony: EcdsaPostRegistrationCeremonyV1) -> EcdsaPostRegistrationOperationV1 {
    match ceremony {
        EcdsaPostRegistrationCeremonyV1::ExplicitExport => {
            EcdsaPostRegistrationOperationV1::ExplicitExport {
                authorization_digest_b64u: b64u(&[0x51; 32]),
                nonce: "export-nonce-1".to_owned(),
            }
        }
        EcdsaPostRegistrationCeremonyV1::Recovery => EcdsaPostRegistrationOperationV1::Recovery {
            authorization_digest_b64u: b64u(&[0x52; 32]),
            nonce: "recovery-nonce-1".to_owned(),
        },
        EcdsaPostRegistrationCeremonyV1::ActivationRefresh => {
            EcdsaPostRegistrationOperationV1::ActivationRefresh {
                authorization_digest_b64u: b64u(&[0x53; 32]),
                nonce: "refresh-nonce-1".to_owned(),
                previous_activation_epoch: "root-epoch-1".to_owned(),
                next_activation_epoch: "root-epoch-2".to_owned(),
            }
        }
    }
}

fn recipient(ceremony: EcdsaPostRegistrationCeremonyV1) -> EcdsaPostRegistrationRecipientV1 {
    match ceremony {
        EcdsaPostRegistrationCeremonyV1::ExplicitExport
        | EcdsaPostRegistrationCeremonyV1::Recovery => {
            EcdsaPostRegistrationRecipientV1::ClientProofBundles {
                client_ephemeral_public_key: recipient_key(ceremony),
            }
        }
        EcdsaPostRegistrationCeremonyV1::ActivationRefresh => {
            EcdsaPostRegistrationRecipientV1::SigningWorkerActivation {
                signing_worker_ephemeral_public_key: recipient_key(ceremony),
            }
        }
    }
}

fn client_header(ceremony: EcdsaPostRegistrationCeremonyV1) -> EcdsaPostRegistrationHeaderV1 {
    EcdsaPostRegistrationHeaderV1::new(EcdsaPostRegistrationHeaderInputV1 {
        context: client_context(),
        lifecycle: EcdsaPostRegistrationLifecycleV1::from_wire(ceremony, lifecycle_wire(ceremony))
            .expect("client lifecycle"),
        public_identity: client_identity(),
        signer_set: client_signer_set(),
        router_id: "router-1".to_owned(),
        client_id: "client-1".to_owned(),
        recipient: recipient(ceremony),
        operation: operation(ceremony),
        expires_at_ms: 8_000_000,
    })
    .expect("client header")
}

fn deriver_recipient_keys() -> EcdsaRegistrationRecipientKeysV1 {
    let signer_set = client_signer_set();
    EcdsaRegistrationRecipientKeysV1 {
        deriver_a: EcdsaSignerEnvelopePublicKeyV1 {
            role: EcdsaDeriverRoleV1::A,
            key_epoch: signer_set.signer_a().key_epoch.clone(),
            public_key: derive_ecdsa_client_ephemeral_keypair_v1([0xa1; 32])
                .expect("Deriver A key")
                .public_key()
                .to_owned(),
        },
        deriver_b: EcdsaSignerEnvelopePublicKeyV1 {
            role: EcdsaDeriverRoleV1::B,
            key_epoch: signer_set.signer_b().key_epoch.clone(),
            public_key: derive_ecdsa_client_ephemeral_keypair_v1([0xb2; 32])
                .expect("Deriver B key")
                .public_key()
                .to_owned(),
        },
    }
}

fn client_request(ceremony: EcdsaPostRegistrationCeremonyV1) -> EcdsaPostRegistrationRequestV1 {
    build_ecdsa_post_registration_request_v1(
        client_header(ceremony),
        deriver_recipient_keys(),
        EcdsaRegistrationSealSeedsV1 {
            deriver_a: [0xc3; 32],
            deriver_b: [0xd4; 32],
        },
    )
    .expect("client request")
}

fn core_envelope(envelope: &EcdsaRegistrationEncryptedEnvelopeV1) -> RoleEncryptedEnvelopeV1 {
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
    ceremony: EcdsaPostRegistrationCeremonyV1,
    client: &EcdsaPostRegistrationRequestV1,
) -> CorePostRequest {
    let common = (
        core_context(),
        core_lifecycle(ceremony),
        core_identity(),
        core_signer_set(),
        client.header().router_id().to_owned(),
        client.header().client_id().to_owned(),
        recipient_key(ceremony),
        client.header().expires_at_ms(),
        core_envelope(client.deriver_a_envelope()),
        core_envelope(client.deriver_b_envelope()),
    );
    match ceremony {
        EcdsaPostRegistrationCeremonyV1::ExplicitExport => {
            CorePostRequest::Export(RouterAbEcdsaDerivationExplicitExportRequestV1 {
                context: common.0,
                lifecycle: common.1,
                public_identity: common.2,
                signer_set: common.3,
                router_id: common.4,
                client_id: common.5,
                client_ephemeral_public_key: common.6,
                export_authorization_digest_b64u: b64u(&[0x51; 32]),
                export_nonce: "export-nonce-1".to_owned(),
                expires_at_ms: common.7,
                deriver_a_export_envelope: common.8,
                deriver_b_export_envelope: common.9,
            })
        }
        EcdsaPostRegistrationCeremonyV1::Recovery => {
            CorePostRequest::Recovery(RouterAbEcdsaDerivationRecoveryRequestV1 {
                context: common.0,
                lifecycle: common.1,
                public_identity: common.2,
                signer_set: common.3,
                router_id: common.4,
                client_id: common.5,
                client_ephemeral_public_key: common.6,
                recovery_authorization_digest_b64u: b64u(&[0x52; 32]),
                recovery_nonce: "recovery-nonce-1".to_owned(),
                expires_at_ms: common.7,
                deriver_a_recovery_envelope: common.8,
                deriver_b_recovery_envelope: common.9,
            })
        }
        EcdsaPostRegistrationCeremonyV1::ActivationRefresh => {
            CorePostRequest::Refresh(RouterAbEcdsaDerivationActivationRefreshRequestV1 {
                context: common.0,
                lifecycle: common.1,
                public_identity: common.2,
                signer_set: common.3,
                router_id: common.4,
                client_id: common.5,
                signing_worker_ephemeral_public_key: common.6,
                refresh_authorization_digest_b64u: b64u(&[0x53; 32]),
                refresh_nonce: "refresh-nonce-1".to_owned(),
                previous_activation_epoch: "root-epoch-1".to_owned(),
                next_activation_epoch: "root-epoch-2".to_owned(),
                expires_at_ms: common.7,
                deriver_a_refresh_envelope: common.8,
                deriver_b_refresh_envelope: common.9,
            })
        }
    }
}

fn core_aad(request: &EcdsaThresholdPrfRequestV1, role: Role) -> RoleEnvelopeAadV1 {
    let (payload_a, payload_b) = request.to_signer_payloads().expect("signer payloads");
    let payload = match role {
        Role::SignerA => payload_a,
        Role::SignerB => payload_b,
        _ => panic!("signer role required"),
    };
    RoleEnvelopeAadV1::new(
        payload.lifecycle().lifecycle_id.clone(),
        payload.lifecycle().work_kind,
        payload.signer_set().signer_set_id.clone(),
        payload.assignment().signer.clone(),
        payload.signer_set().selected_server.clone(),
        payload.transcript_digest(),
        request.request_context_digest().expect("context digest"),
        request.expires_at_ms,
    )
    .expect("core AAD")
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

fn assert_parity(ceremony: EcdsaPostRegistrationCeremonyV1) {
    let client = client_request(ceremony);
    let core = core_request(ceremony, &client);
    assert_eq!(
        client.header().canonical_bytes().unwrap(),
        core.header_bytes()
    );
    assert_eq!(
        client.header().digest().unwrap(),
        *core.header_digest().as_bytes()
    );
    assert_eq!(client.canonical_bytes().unwrap(), core.request_bytes());
    assert_eq!(client.digest().unwrap(), *core.request_digest().as_bytes());

    let threshold = core.threshold_request();
    for (client_envelope, core_role) in [
        (client.deriver_a_envelope(), Role::SignerA),
        (client.deriver_b_envelope(), Role::SignerB),
    ] {
        let client_aad = client
            .header()
            .role_aad(client_envelope.recipient_role())
            .expect("client AAD");
        let expected_aad = core_aad(&threshold, core_role);
        assert_eq!(
            client_aad.canonical_bytes().unwrap(),
            expected_aad.canonical_bytes()
        );
        assert_eq!(
            client_aad.digest().unwrap(),
            *expected_aad.digest().as_bytes()
        );
        assert_eq!(
            client_envelope.digest().unwrap(),
            *role_encrypted_envelope_digest_v1(&core_envelope(client_envelope))
                .unwrap()
                .as_bytes(),
        );

        let decoded = decode_signer_envelope_hpke_payload_v1(client_envelope.ciphertext())
            .expect("core HPKE decode");
        let payload = EcdsaSignerEnvelopeHpkePayloadV1 {
            recipient_role: client_envelope.recipient_role(),
            key_epoch: decoded.key_epoch.clone(),
            recipient_public_key: decoded.recipient_public_key.clone(),
            aad_digest: client_envelope.aad_digest(),
            encapped_key: *decoded.encapped_key(),
            ciphertext_and_tag: decoded.ciphertext_and_tag().to_vec(),
        };
        let opened = open_ecdsa_signer_envelope_v1(
            &payload,
            &client_aad,
            &recipient_private_key(client_envelope.recipient_role()),
        )
        .expect("open envelope");
        assert_eq!(opened, core.plaintext(core_role, expected_aad.digest()));
    }
}

#[test]
fn explicit_export_recovery_and_refresh_match_core_exactly() {
    for ceremony in [
        EcdsaPostRegistrationCeremonyV1::ExplicitExport,
        EcdsaPostRegistrationCeremonyV1::Recovery,
        EcdsaPostRegistrationCeremonyV1::ActivationRefresh,
    ] {
        assert_parity(ceremony);
    }
}

#[test]
fn post_registration_rejects_lifecycle_output_authorization_nonce_epoch_and_recipient_drift() {
    let mut lifecycle = lifecycle_wire(EcdsaPostRegistrationCeremonyV1::ExplicitExport);
    lifecycle.primitive_request_kind = "recovery".to_owned();
    assert_eq!(
        EcdsaPostRegistrationLifecycleV1::from_wire(
            EcdsaPostRegistrationCeremonyV1::ExplicitExport,
            lifecycle,
        ),
        Err(EcdsaClientProtocolError::InvalidShape),
    );
    assert_eq!(
        EcdsaPostRegistrationCeremonyV1::ExplicitExport
            .validate_output_kind_wire("signing_worker_activation"),
        Err(EcdsaClientProtocolError::InvalidShape),
    );

    let export_lifecycle = EcdsaPostRegistrationLifecycleV1::from_wire(
        EcdsaPostRegistrationCeremonyV1::ExplicitExport,
        lifecycle_wire(EcdsaPostRegistrationCeremonyV1::ExplicitExport),
    )
    .unwrap();
    let invalid_recipient =
        EcdsaPostRegistrationHeaderV1::new(EcdsaPostRegistrationHeaderInputV1 {
            context: client_context(),
            lifecycle: export_lifecycle.clone(),
            public_identity: client_identity(),
            signer_set: client_signer_set(),
            router_id: "router-1".to_owned(),
            client_id: "client-1".to_owned(),
            recipient: EcdsaPostRegistrationRecipientV1::SigningWorkerActivation {
                signing_worker_ephemeral_public_key: recipient_key(
                    EcdsaPostRegistrationCeremonyV1::ExplicitExport,
                ),
            },
            operation: operation(EcdsaPostRegistrationCeremonyV1::ExplicitExport),
            expires_at_ms: 8_000_000,
        });
    assert_eq!(
        invalid_recipient,
        Err(EcdsaClientProtocolError::InvalidShape)
    );

    let invalid_authorization =
        EcdsaPostRegistrationHeaderV1::new(EcdsaPostRegistrationHeaderInputV1 {
            context: client_context(),
            lifecycle: export_lifecycle.clone(),
            public_identity: client_identity(),
            signer_set: client_signer_set(),
            router_id: "router-1".to_owned(),
            client_id: "client-1".to_owned(),
            recipient: recipient(EcdsaPostRegistrationCeremonyV1::ExplicitExport),
            operation: EcdsaPostRegistrationOperationV1::ExplicitExport {
                authorization_digest_b64u: b64u(&[0x11; 31]),
                nonce: "export-nonce-1".to_owned(),
            },
            expires_at_ms: 8_000_000,
        });
    assert_eq!(
        invalid_authorization,
        Err(EcdsaClientProtocolError::InvalidShape)
    );

    let invalid_nonce = EcdsaPostRegistrationHeaderV1::new(EcdsaPostRegistrationHeaderInputV1 {
        context: client_context(),
        lifecycle: export_lifecycle,
        public_identity: client_identity(),
        signer_set: client_signer_set(),
        router_id: "router-1".to_owned(),
        client_id: "client-1".to_owned(),
        recipient: recipient(EcdsaPostRegistrationCeremonyV1::ExplicitExport),
        operation: EcdsaPostRegistrationOperationV1::ExplicitExport {
            authorization_digest_b64u: b64u(&[0x51; 32]),
            nonce: String::new(),
        },
        expires_at_ms: 8_000_000,
    });
    assert_eq!(invalid_nonce, Err(EcdsaClientProtocolError::InvalidShape));

    let refresh_lifecycle = EcdsaPostRegistrationLifecycleV1::from_wire(
        EcdsaPostRegistrationCeremonyV1::ActivationRefresh,
        lifecycle_wire(EcdsaPostRegistrationCeremonyV1::ActivationRefresh),
    )
    .unwrap();
    let invalid_epoch = EcdsaPostRegistrationHeaderV1::new(EcdsaPostRegistrationHeaderInputV1 {
        context: client_context(),
        lifecycle: refresh_lifecycle,
        public_identity: client_identity(),
        signer_set: client_signer_set(),
        router_id: "router-1".to_owned(),
        client_id: "client-1".to_owned(),
        recipient: recipient(EcdsaPostRegistrationCeremonyV1::ActivationRefresh),
        operation: EcdsaPostRegistrationOperationV1::ActivationRefresh {
            authorization_digest_b64u: b64u(&[0x53; 32]),
            nonce: "refresh-nonce-1".to_owned(),
            previous_activation_epoch: "root-epoch-2".to_owned(),
            next_activation_epoch: "root-epoch-2".to_owned(),
        },
        expires_at_ms: 8_000_000,
    });
    assert_eq!(invalid_epoch, Err(EcdsaClientProtocolError::InvalidShape));
}
