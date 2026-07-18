use router_ab_core::{
    Ed25519YaoCeremonyBindingV1, Ed25519YaoOperationV1, Ed25519YaoSessionIdV1,
    Ed25519YaoStableKeyContextBindingV1, ExpensiveWorkKindV1, LifecycleScopeV1, RootShareEpoch,
};
use router_ab_dev::{
    build_local_activation_deriver_a_v1, build_local_activation_deriver_b_v1,
    LocalDeriverAWorkerConfigV1, LocalDeriverBWorkerConfigV1,
    LocalEd25519YaoActivationDeriverARequestV1, LocalEd25519YaoActivationDeriverBRequestV1,
    LocalEd25519YaoActivationRecipientsV1, LocalEd25519YaoClientContributionV1,
    RouterAbEd25519YaoApplicationBindingFactsV1,
};
use signer_core::ed25519_yao_derivation::{
    derive_ed25519_yao_client_contributions_v1, Ed25519YaoApplicationBindingFactsV1,
    Ed25519YaoApplicationBindingKeyCreationSignerSlotV1,
    Ed25519YaoApplicationBindingSigningKeyIdV1, Ed25519YaoApplicationBindingSigningRootIdV1,
    Ed25519YaoApplicationBindingWalletIdV1, Ed25519YaoClientDerivationRootV1,
    Ed25519YaoStableKeyDerivationContextV1,
};

fn application_request() -> RouterAbEd25519YaoApplicationBindingFactsV1 {
    RouterAbEd25519YaoApplicationBindingFactsV1::new(
        "wallet-fixture",
        "ed25519ks_fixture",
        "project-fixture:env-fixture",
        1,
    )
    .expect("application binding")
}

fn context() -> Ed25519YaoStableKeyDerivationContextV1 {
    let facts = Ed25519YaoApplicationBindingFactsV1::new(
        Ed25519YaoApplicationBindingWalletIdV1::parse("wallet-fixture").expect("wallet"),
        Ed25519YaoApplicationBindingSigningKeyIdV1::parse("ed25519ks_fixture")
            .expect("signing key"),
        Ed25519YaoApplicationBindingSigningRootIdV1::parse("project-fixture:env-fixture")
            .expect("root"),
        Ed25519YaoApplicationBindingKeyCreationSignerSlotV1::new(1).expect("slot"),
    );
    Ed25519YaoStableKeyDerivationContextV1::new(facts.digest(), 1, 2).expect("context")
}

fn binding(context_binding: [u8; 32]) -> Ed25519YaoCeremonyBindingV1 {
    let lifecycle = LifecycleScopeV1::new(
        "lifecycle-1",
        ExpensiveWorkKindV1::RegistrationPrepare,
        RootShareEpoch::new("epoch-1").expect("epoch"),
        "account-1",
        "wallet-session-1",
        "signer-set-1",
        "signing-worker-1",
    )
    .expect("lifecycle");
    Ed25519YaoCeremonyBindingV1::new(
        lifecycle,
        Ed25519YaoOperationV1::Registration,
        Ed25519YaoSessionIdV1::new([0x51; 32]).expect("session"),
        Ed25519YaoStableKeyContextBindingV1::new(context_binding),
    )
    .expect("binding")
}

fn deriver_a_config() -> LocalDeriverAWorkerConfigV1 {
    LocalDeriverAWorkerConfigV1 {
        deriver_a_url: "http://127.0.0.1:9101".to_owned(),
        deriver_b_url: "http://127.0.0.1:9102".to_owned(),
        envelope_hpke_private_key: "a-hpke".to_owned(),
        root_share_wire_secret: "a-wire".to_owned(),
        ed25519_yao_derivation_root_hex: hex::encode([0x22; 32]),
        peer_signing_key: "a-signing".to_owned(),
        deriver_a_peer_verifying_key: "a-verifying".to_owned(),
        deriver_b_peer_verifying_key: "b-verifying".to_owned(),
        root_share_storage_path: "a-root.sqlite".to_owned(),
        sealed_root_shares_path: "a-sealed.sqlite".to_owned(),
    }
}

fn deriver_b_config() -> LocalDeriverBWorkerConfigV1 {
    LocalDeriverBWorkerConfigV1 {
        deriver_b_url: "http://127.0.0.1:9102".to_owned(),
        deriver_a_url: "http://127.0.0.1:9101".to_owned(),
        envelope_hpke_private_key: "b-hpke".to_owned(),
        root_share_wire_secret: "b-wire".to_owned(),
        ed25519_yao_derivation_root_hex: hex::encode([0x33; 32]),
        peer_signing_key: "b-signing".to_owned(),
        deriver_a_peer_verifying_key: "a-verifying".to_owned(),
        deriver_b_peer_verifying_key: "b-verifying".to_owned(),
        root_share_storage_path: "b-root.sqlite".to_owned(),
        sealed_root_shares_path: "b-sealed.sqlite".to_owned(),
    }
}

fn transport_contribution(
    contribution: (
        signer_core::ed25519_yao_derivation::Ed25519YaoYContributionV1,
        signer_core::ed25519_yao_derivation::Ed25519YaoTauContributionV1,
    ),
) -> LocalEd25519YaoClientContributionV1 {
    LocalEd25519YaoClientContributionV1 {
        y: contribution.0.into_bytes(),
        tau: contribution.1.into_bytes(),
    }
}

#[test]
fn role_request_builders_keep_server_roots_separate_and_bind_the_canonical_context() {
    let context = context();
    let client_root = Ed25519YaoClientDerivationRootV1::from_secret_bytes([0x11; 32]);
    let (client_a, client_b) = derive_ed25519_yao_client_contributions_v1(&client_root, &context)
        .expect("client KDF")
        .into_parts();
    let admitted_binding = binding(context.binding_digest());

    let a = build_local_activation_deriver_a_v1(
        &deriver_a_config(),
        LocalEd25519YaoActivationDeriverARequestV1 {
            binding: admitted_binding.clone(),
            application_binding: application_request(),
            participant_ids: [1, 2],
            client_contribution: transport_contribution(client_a.into_parts()),
            recipients: LocalEd25519YaoActivationRecipientsV1 {
                client_public_key: [4; 32],
                signing_worker_public_key: [5; 32],
            },
        },
    );
    let b = build_local_activation_deriver_b_v1(
        &deriver_b_config(),
        LocalEd25519YaoActivationDeriverBRequestV1 {
            binding: admitted_binding,
            application_binding: application_request(),
            participant_ids: [2, 1],
            client_contribution: transport_contribution(client_b.into_parts()),
            recipients: LocalEd25519YaoActivationRecipientsV1 {
                client_public_key: [4; 32],
                signing_worker_public_key: [5; 32],
            },
        },
    );
    assert!(a.is_ok());
    assert!(b.is_ok());

    let (client_a, _) = derive_ed25519_yao_client_contributions_v1(&client_root, &context)
        .expect("second client KDF")
        .into_parts();
    let mismatched = build_local_activation_deriver_a_v1(
        &deriver_a_config(),
        LocalEd25519YaoActivationDeriverARequestV1 {
            binding: binding([0x99; 32]),
            application_binding: application_request(),
            participant_ids: [1, 2],
            client_contribution: transport_contribution(client_a.into_parts()),
            recipients: LocalEd25519YaoActivationRecipientsV1 {
                client_public_key: [4; 32],
                signing_worker_public_key: [5; 32],
            },
        },
    );
    assert!(mismatched.is_err());
}
