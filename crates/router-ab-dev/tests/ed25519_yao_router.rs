use router_ab_core::{
    Ed25519YaoCircuitFamilyV1, Ed25519YaoEpochTransitionV1, Ed25519YaoOperationV1,
    Ed25519YaoRefreshEpochsV1, Ed25519YaoStateEpochV1, ExpensiveWorkKindV1, RootShareEpoch,
};
use router_ab_dev::{
    admit_local_ed25519_yao_export_v1, admit_local_ed25519_yao_registration_v1,
    LocalEd25519YaoRecoveryCredentialBindingV1, LocalEd25519YaoRefreshActiveEpochsV1,
    LocalEd25519YaoRouterExportAdmissionRequestV1, LocalEd25519YaoRouterRecoveryAdmissionRequestV1,
    LocalEd25519YaoRouterRecoveryStateV1, LocalEd25519YaoRouterRefreshAdmissionRequestV1,
    LocalEd25519YaoRouterRefreshStateV1, RouterAbEd25519YaoApplicationBindingFactsV1,
    RouterAbEd25519YaoLifecycleScopeV1, RouterAbEd25519YaoRegistrationAdmissionRequestV1,
};

#[test]
fn router_admits_registration_into_fresh_bound_role_requests() {
    let first = admit_local_ed25519_yao_registration_v1(registration_request()).expect("first");
    let second = admit_local_ed25519_yao_registration_v1(registration_request()).expect("second");

    assert_eq!(first.binding.operation, Ed25519YaoOperationV1::Registration);
    assert_eq!(
        first.binding.lifecycle.work_kind,
        ExpensiveWorkKindV1::RegistrationPrepare
    );
    assert_eq!(
        first.binding.circuit_family(),
        Ed25519YaoCircuitFamilyV1::Activation
    );
    assert_ne!(
        first.binding.session_id.into_bytes(),
        second.binding.session_id.into_bytes()
    );
}

#[test]
fn router_admits_export_into_the_export_family_only() {
    let admitted =
        admit_local_ed25519_yao_export_v1(LocalEd25519YaoRouterExportAdmissionRequestV1 {
            scope: scope("export-1"),
            application_binding: application(),
            participant_ids: [1, 2],
        })
        .expect("export");

    assert_eq!(admitted.binding.operation, Ed25519YaoOperationV1::Export);
    assert_eq!(
        admitted.binding.lifecycle.work_kind,
        ExpensiveWorkKindV1::KeyExport
    );
    assert_eq!(
        admitted.binding.circuit_family(),
        Ed25519YaoCircuitFamilyV1::Export
    );
}

#[test]
fn router_rejects_ambiguous_participant_and_scope_inputs() {
    let mut invalid_participants =
        serde_json::to_value(registration_request()).expect("registration JSON");
    invalid_participants["participant_ids"] = serde_json::json!([1, 1]);
    assert!(
        serde_json::from_value::<RouterAbEd25519YaoRegistrationAdmissionRequestV1>(
            invalid_participants
        )
        .is_err()
    );

    let mut invalid_scope =
        serde_json::to_value(registration_request()).expect("registration JSON");
    invalid_scope["scope"]["wallet_session_id"] = serde_json::json!("");
    assert!(
        serde_json::from_value::<RouterAbEd25519YaoRegistrationAdmissionRequestV1>(invalid_scope)
            .is_err()
    );
}

#[test]
fn recovery_suspends_then_retires_the_old_credential() {
    let old = LocalEd25519YaoRecoveryCredentialBindingV1::new([0x61; 32]).expect("old");
    let replacement =
        LocalEd25519YaoRecoveryCredentialBindingV1::new([0x62; 32]).expect("replacement");
    let public_key = [0x71; 32];
    let mut state =
        LocalEd25519YaoRouterRecoveryStateV1::new(old, public_key).expect("recovery state");
    let admission = state
        .begin(recovery_request(old, replacement))
        .expect("admission");
    assert_eq!(admission.binding.operation, Ed25519YaoOperationV1::Recovery);
    assert!(state.begin(recovery_request(old, replacement)).is_err());
    assert!(state.promote(&admission.binding, [0x72; 32]).is_err());

    let receipt = state
        .promote(&admission.binding, public_key)
        .expect("promotion");
    assert_eq!(receipt.active_credential, replacement);
    assert_eq!(receipt.retired_credential, old);
    assert!(state.is_tombstoned(old));
    assert!(state.begin(recovery_request(old, replacement)).is_err());
}

#[test]
fn refresh_rejects_stale_epochs_and_promotes_only_after_worker_activation() {
    let epoch_1 = Ed25519YaoStateEpochV1::new(1).expect("epoch 1");
    let epoch_2 = Ed25519YaoStateEpochV1::new(2).expect("epoch 2");
    let transition = Ed25519YaoEpochTransitionV1::new(epoch_1, epoch_2).expect("transition");
    let active_epochs = LocalEd25519YaoRefreshActiveEpochsV1 {
        deriver_a: epoch_1,
        deriver_b: epoch_1,
        signing_worker: epoch_1,
    };
    let public_key = [0x81; 32];
    let active_binding = admit_local_ed25519_yao_registration_v1(registration_request())
        .expect("registration")
        .binding;
    let mut state =
        LocalEd25519YaoRouterRefreshStateV1::new(&active_binding, public_key, active_epochs)
            .expect("state");
    let binding = state
        .begin(refresh_request(public_key, transition))
        .expect("refresh admission");
    assert!(state
        .begin(refresh_request(public_key, transition))
        .is_err());
    state
        .mark_output_committed(&binding)
        .expect("output committed");
    assert!(state.mark_worker_activated(&binding, [0x82; 32]).is_err());
    state
        .mark_worker_activated(&binding, public_key)
        .expect("worker activated");
    let promoted = state.promote(&binding).expect("promotion");
    assert_eq!(promoted.deriver_a, epoch_2);
    assert_eq!(promoted.deriver_b, epoch_2);
    assert_eq!(promoted.signing_worker, epoch_2);
    assert!(state.is_retired(active_epochs));
    assert!(state
        .begin(refresh_request(public_key, transition))
        .is_err());
}

#[test]
fn refresh_rejects_each_mixed_current_epoch_without_mutation() {
    let epoch_1 = Ed25519YaoStateEpochV1::new(1).expect("epoch 1");
    let epoch_2 = Ed25519YaoStateEpochV1::new(2).expect("epoch 2");
    let epoch_3 = Ed25519YaoStateEpochV1::new(3).expect("epoch 3");
    let valid = Ed25519YaoEpochTransitionV1::new(epoch_1, epoch_2).expect("valid transition");
    let stale = Ed25519YaoEpochTransitionV1::new(epoch_2, epoch_3).expect("stale transition");
    let active_epochs = LocalEd25519YaoRefreshActiveEpochsV1 {
        deriver_a: epoch_1,
        deriver_b: epoch_1,
        signing_worker: epoch_1,
    };
    let public_key = [0x91; 32];
    let active_binding = admit_local_ed25519_yao_registration_v1(registration_request())
        .expect("registration")
        .binding;

    for mixed in [
        Ed25519YaoRefreshEpochsV1 {
            deriver_a: stale,
            deriver_b: valid,
            signing_worker: valid,
        },
        Ed25519YaoRefreshEpochsV1 {
            deriver_a: valid,
            deriver_b: stale,
            signing_worker: valid,
        },
        Ed25519YaoRefreshEpochsV1 {
            deriver_a: valid,
            deriver_b: valid,
            signing_worker: stale,
        },
    ] {
        let mut state =
            LocalEd25519YaoRouterRefreshStateV1::new(&active_binding, public_key, active_epochs)
                .expect("state");
        let mut invalid = refresh_request(public_key, valid);
        invalid.epochs = mixed;
        assert!(state.begin(invalid).is_err());
        assert!(state.begin(refresh_request(public_key, valid)).is_ok());
    }
}

fn registration_request() -> RouterAbEd25519YaoRegistrationAdmissionRequestV1 {
    RouterAbEd25519YaoRegistrationAdmissionRequestV1::new(
        scope("registration-1"),
        application(),
        [1, 2],
    )
    .expect("registration request")
}

fn scope(lifecycle_id: &str) -> RouterAbEd25519YaoLifecycleScopeV1 {
    RouterAbEd25519YaoLifecycleScopeV1::new(
        lifecycle_id,
        RootShareEpoch::new("epoch-1").expect("epoch"),
        "account-1",
        "wallet-session-1",
        "signer-set-1",
        "signing-worker-1",
    )
    .expect("lifecycle scope")
}

fn application() -> RouterAbEd25519YaoApplicationBindingFactsV1 {
    RouterAbEd25519YaoApplicationBindingFactsV1::new(
        "wallet-router",
        "ed25519ks_router",
        "project:local",
        1,
    )
    .expect("application binding")
}

fn recovery_request(
    active_credential: LocalEd25519YaoRecoveryCredentialBindingV1,
    replacement_credential: LocalEd25519YaoRecoveryCredentialBindingV1,
) -> LocalEd25519YaoRouterRecoveryAdmissionRequestV1 {
    LocalEd25519YaoRouterRecoveryAdmissionRequestV1 {
        scope: scope("recovery-1"),
        application_binding: application(),
        participant_ids: [1, 2],
        active_credential,
        replacement_credential,
    }
}

fn refresh_request(
    registered_public_key: [u8; 32],
    transition: Ed25519YaoEpochTransitionV1,
) -> LocalEd25519YaoRouterRefreshAdmissionRequestV1 {
    LocalEd25519YaoRouterRefreshAdmissionRequestV1 {
        scope: scope("refresh-1"),
        application_binding: application(),
        participant_ids: [1, 2],
        registered_public_key,
        epochs: Ed25519YaoRefreshEpochsV1 {
            deriver_a: transition,
            deriver_b: transition,
            signing_worker: transition,
        },
    }
}
