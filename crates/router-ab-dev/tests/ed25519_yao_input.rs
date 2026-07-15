use router_ab_core::{
    Ed25519YaoEpochTransitionV1, Ed25519YaoRefreshEpochsV1, Ed25519YaoStateEpochV1, RootShareEpoch,
};
use router_ab_dev::{
    admit_local_ed25519_yao_registration_v1, generate_local_ed25519_yao_recipient_key_pair_v1,
    open_local_ed25519_yao_activation_deriver_a_input_v1,
    open_local_ed25519_yao_activation_deriver_b_input_v1,
    open_local_ed25519_yao_refresh_deriver_a_input_v1,
    open_local_ed25519_yao_refresh_deriver_b_input_v1,
    seal_local_ed25519_yao_activation_deriver_a_input_v1,
    seal_local_ed25519_yao_refresh_deriver_a_input_v1, Ed25519YaoEncryptedInputV1,
    LocalEd25519YaoActivationDeriverARequestV1, LocalEd25519YaoActivationRecipientsV1,
    LocalEd25519YaoClientContributionV1, LocalEd25519YaoRefreshActiveEpochsV1,
    LocalEd25519YaoRefreshDeriverARequestV1, LocalEd25519YaoRouterRefreshAdmissionRequestV1,
    LocalEd25519YaoRouterRefreshStateV1, RouterAbEd25519YaoApplicationBindingFactsV1,
    RouterAbEd25519YaoLifecycleScopeV1, RouterAbEd25519YaoRegistrationAdmissionRequestV1,
};

fn tamper_input_ciphertext(envelope: &Ed25519YaoEncryptedInputV1) -> Ed25519YaoEncryptedInputV1 {
    let mut ciphertext = envelope.ciphertext().to_vec();
    ciphertext[0] ^= 1;
    Ed25519YaoEncryptedInputV1::new(
        envelope.kind(),
        envelope.deriver(),
        envelope.operation(),
        envelope.session(),
        envelope.stable_context_binding(),
        *envelope.encapsulated_key(),
        ciphertext,
    )
    .expect("structurally valid ciphertext tamper")
}

fn tamper_input_context(envelope: &Ed25519YaoEncryptedInputV1) -> Ed25519YaoEncryptedInputV1 {
    let mut stable_context_binding = envelope.stable_context_binding();
    stable_context_binding[0] ^= 1;
    Ed25519YaoEncryptedInputV1::new(
        envelope.kind(),
        envelope.deriver(),
        envelope.operation(),
        envelope.session(),
        stable_context_binding,
        *envelope.encapsulated_key(),
        envelope.ciphertext().to_vec(),
    )
    .expect("structurally valid context tamper")
}

#[test]
fn role_input_opens_only_at_the_intended_deriver() {
    let deriver_a = generate_local_ed25519_yao_recipient_key_pair_v1().expect("A key");
    let deriver_b = generate_local_ed25519_yao_recipient_key_pair_v1().expect("B key");
    let request = activation_a_request();
    let envelope =
        seal_local_ed25519_yao_activation_deriver_a_input_v1(&request, deriver_a.public_key)
            .expect("seal");

    let opened =
        open_local_ed25519_yao_activation_deriver_a_input_v1(&envelope, &deriver_a.private_key)
            .expect("open A");
    assert_eq!(opened.binding, request.binding);
    assert_eq!(opened.client_contribution.y, [0x31; 32]);
    assert!(open_local_ed25519_yao_activation_deriver_b_input_v1(
        &envelope,
        &deriver_b.private_key
    )
    .is_err());
    assert!(open_local_ed25519_yao_activation_deriver_a_input_v1(
        &envelope,
        &deriver_b.private_key
    )
    .is_err());
}

#[test]
fn role_input_rejects_ciphertext_and_binding_metadata_tampering() {
    let deriver_a = generate_local_ed25519_yao_recipient_key_pair_v1().expect("A key");
    let request = activation_a_request();
    let envelope =
        seal_local_ed25519_yao_activation_deriver_a_input_v1(&request, deriver_a.public_key)
            .expect("seal");

    let ciphertext_tamper = tamper_input_ciphertext(&envelope);
    assert!(open_local_ed25519_yao_activation_deriver_a_input_v1(
        &ciphertext_tamper,
        &deriver_a.private_key
    )
    .is_err());

    let binding_tamper = tamper_input_context(&envelope);
    assert!(open_local_ed25519_yao_activation_deriver_a_input_v1(
        &binding_tamper,
        &deriver_a.private_key
    )
    .is_err());
}

#[test]
fn router_admission_json_contains_no_role_contributions() {
    let request = admission_request();
    let json = serde_json::to_string(&request).expect("admission JSON");
    assert!(!json.contains("client_contribution"));
    assert!(!json.contains("deriver_a"));
    assert!(!json.contains("deriver_b"));
    assert!(!json.contains("\"y\""));
    assert!(!json.contains("\"tau\""));
}

#[test]
fn refresh_input_binds_role_session_context_and_all_epochs() {
    let deriver_a = generate_local_ed25519_yao_recipient_key_pair_v1().expect("A key");
    let deriver_b = generate_local_ed25519_yao_recipient_key_pair_v1().expect("B key");
    let request = refresh_a_request();
    let envelope =
        seal_local_ed25519_yao_refresh_deriver_a_input_v1(&request, deriver_a.public_key)
            .expect("seal refresh");
    let opened =
        open_local_ed25519_yao_refresh_deriver_a_input_v1(&envelope, &deriver_a.private_key)
            .expect("open refresh A");
    assert_eq!(opened.binding, request.binding);
    assert!(
        open_local_ed25519_yao_refresh_deriver_b_input_v1(&envelope, &deriver_b.private_key,)
            .is_err()
    );

    let mut digest_tamper = envelope;
    digest_tamper.refresh_binding_digest[0] ^= 1;
    assert!(open_local_ed25519_yao_refresh_deriver_a_input_v1(
        &digest_tamper,
        &deriver_a.private_key,
    )
    .is_err());
}

#[test]
fn base_activation_envelope_rejects_refresh_operation() {
    let deriver_a = generate_local_ed25519_yao_recipient_key_pair_v1().expect("A key");
    let mut request = activation_a_request();
    request.binding = refresh_a_request().binding.ceremony().clone();

    assert!(
        seal_local_ed25519_yao_activation_deriver_a_input_v1(&request, deriver_a.public_key,)
            .is_err()
    );
}

fn activation_a_request() -> LocalEd25519YaoActivationDeriverARequestV1 {
    let application_binding = application();
    let admission = admit_local_ed25519_yao_registration_v1(admission_request())
        .expect("registration admission");
    LocalEd25519YaoActivationDeriverARequestV1 {
        binding: admission.binding,
        application_binding,
        participant_ids: [1, 2],
        client_contribution: LocalEd25519YaoClientContributionV1 {
            y: [0x31; 32],
            tau: [0x32; 32],
        },
        recipients: LocalEd25519YaoActivationRecipientsV1 {
            client_public_key: [0x41; 32],
            signing_worker_public_key: [0x42; 32],
        },
    }
}

fn admission_request() -> RouterAbEd25519YaoRegistrationAdmissionRequestV1 {
    RouterAbEd25519YaoRegistrationAdmissionRequestV1::new(
        scope("input-test-lifecycle", "session-1"),
        application(),
        [1, 2],
    )
    .expect("registration request")
}

fn scope(lifecycle_id: &str, wallet_session_id: &str) -> RouterAbEd25519YaoLifecycleScopeV1 {
    RouterAbEd25519YaoLifecycleScopeV1::new(
        lifecycle_id,
        RootShareEpoch::new("epoch-1").expect("epoch"),
        "account-1",
        wallet_session_id,
        "set-1",
        "worker-1",
    )
    .expect("lifecycle scope")
}

fn refresh_a_request() -> LocalEd25519YaoRefreshDeriverARequestV1 {
    let active = admit_local_ed25519_yao_registration_v1(admission_request())
        .expect("registration admission")
        .binding;
    let epoch_1 = Ed25519YaoStateEpochV1::new(1).expect("epoch 1");
    let epoch_2 = Ed25519YaoStateEpochV1::new(2).expect("epoch 2");
    let transition = Ed25519YaoEpochTransitionV1::new(epoch_1, epoch_2).expect("transition");
    let mut state = LocalEd25519YaoRouterRefreshStateV1::new(
        &active,
        [0x61; 32],
        LocalEd25519YaoRefreshActiveEpochsV1 {
            deriver_a: epoch_1,
            deriver_b: epoch_1,
            signing_worker: epoch_1,
        },
    )
    .expect("refresh state");
    let binding = state
        .begin(LocalEd25519YaoRouterRefreshAdmissionRequestV1 {
            scope: scope("input-test-refresh", "session-2"),
            application_binding: application(),
            participant_ids: [1, 2],
            registered_public_key: [0x61; 32],
            epochs: Ed25519YaoRefreshEpochsV1 {
                deriver_a: transition,
                deriver_b: transition,
                signing_worker: transition,
            },
        })
        .expect("refresh admission");
    LocalEd25519YaoRefreshDeriverARequestV1 {
        binding,
        application_binding: application(),
        participant_ids: [1, 2],
        client_contribution: LocalEd25519YaoClientContributionV1 {
            y: [0x31; 32],
            tau: [0x32; 32],
        },
        recipients: LocalEd25519YaoActivationRecipientsV1 {
            client_public_key: [0x41; 32],
            signing_worker_public_key: [0x42; 32],
        },
    }
}

fn application() -> RouterAbEd25519YaoApplicationBindingFactsV1 {
    RouterAbEd25519YaoApplicationBindingFactsV1::new(
        "wallet-input",
        "ed25519ks_input",
        "project:local",
        1,
    )
    .expect("application binding")
}
