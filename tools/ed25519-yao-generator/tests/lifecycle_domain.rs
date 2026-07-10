use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_yao_generator::lifecycle_domain::*;
use ed25519_yao_generator::LifecycleRequestKindV1;

#[derive(Debug, Clone, Copy)]
enum TestOrigin {
    Registration,
    Recovery,
    Refresh,
}

#[derive(Debug, Clone, Copy)]
enum CommonField {
    RequestId,
    ReplayNonce,
    AccountId,
    WalletId,
    SessionId,
    OrganizationId,
    ProjectId,
    EnvironmentId,
    SigningRootId,
    SigningRootVersion,
    RootShareEpoch,
    DeriverAIdentity,
    DeriverAKeyEpoch,
    DeriverBIdentity,
    DeriverBKeyEpoch,
    SigningWorkerIdentity,
    SigningWorkerKeyEpoch,
    ClientEphemeralKey,
    RequestExpiry,
    RequestContextDigest,
    TranscriptDigest,
}

const COMMON_FIELDS: [CommonField; 21] = [
    CommonField::RequestId,
    CommonField::ReplayNonce,
    CommonField::AccountId,
    CommonField::WalletId,
    CommonField::SessionId,
    CommonField::OrganizationId,
    CommonField::ProjectId,
    CommonField::EnvironmentId,
    CommonField::SigningRootId,
    CommonField::SigningRootVersion,
    CommonField::RootShareEpoch,
    CommonField::DeriverAIdentity,
    CommonField::DeriverAKeyEpoch,
    CommonField::DeriverBIdentity,
    CommonField::DeriverBKeyEpoch,
    CommonField::SigningWorkerIdentity,
    CommonField::SigningWorkerKeyEpoch,
    CommonField::ClientEphemeralKey,
    CommonField::RequestExpiry,
    CommonField::RequestContextDigest,
    CommonField::TranscriptDigest,
];

#[derive(Debug, Clone, Copy)]
enum CommonLocation {
    Request,
    ClientPackage,
    SigningWorkerPackage,
    BothPackages,
}

#[derive(Debug, Clone, Copy)]
enum FixtureMutation {
    None,
    Common(CommonLocation, CommonField),
    TargetIdentityScope,
    TargetRootEpoch,
    TargetDeriverA,
    TargetDeriverB,
    PendingClientRecipient,
    PendingSigningWorkerRecipient,
    ManifestOrigin,
    ManifestTransition,
    ManifestClientReference,
    ManifestSigningWorkerReference,
    ManifestDigest,
    ClientPackageRecipient,
    SigningWorkerPackageRecipient,
    BothPackageRecipients,
    ClientBindingIdentity,
    SigningWorkerBindingIdentity,
    BothBindingsIdentity,
    ClientBindingRoleEpochs,
    SigningWorkerBindingRoleEpochs,
    BothBindingsRoleEpochs,
    ClientBindingCommitments,
    SigningWorkerBindingCommitments,
    BothBindingsCommitments,
    ClientBindingActivationEpoch,
    SigningWorkerBindingActivationEpoch,
    BothBindingsActivationEpoch,
    ClientBindingDigest,
    SigningWorkerBindingDigest,
    BothBindingsDigest,
}

const METADATA_MUTATIONS: [FixtureMutation; 29] = [
    FixtureMutation::TargetIdentityScope,
    FixtureMutation::TargetRootEpoch,
    FixtureMutation::TargetDeriverA,
    FixtureMutation::TargetDeriverB,
    FixtureMutation::PendingClientRecipient,
    FixtureMutation::PendingSigningWorkerRecipient,
    FixtureMutation::ManifestOrigin,
    FixtureMutation::ManifestTransition,
    FixtureMutation::ManifestClientReference,
    FixtureMutation::ManifestSigningWorkerReference,
    FixtureMutation::ManifestDigest,
    FixtureMutation::ClientPackageRecipient,
    FixtureMutation::SigningWorkerPackageRecipient,
    FixtureMutation::BothPackageRecipients,
    FixtureMutation::ClientBindingIdentity,
    FixtureMutation::SigningWorkerBindingIdentity,
    FixtureMutation::BothBindingsIdentity,
    FixtureMutation::ClientBindingRoleEpochs,
    FixtureMutation::SigningWorkerBindingRoleEpochs,
    FixtureMutation::BothBindingsRoleEpochs,
    FixtureMutation::ClientBindingCommitments,
    FixtureMutation::SigningWorkerBindingCommitments,
    FixtureMutation::BothBindingsCommitments,
    FixtureMutation::ClientBindingActivationEpoch,
    FixtureMutation::SigningWorkerBindingActivationEpoch,
    FixtureMutation::BothBindingsActivationEpoch,
    FixtureMutation::ClientBindingDigest,
    FixtureMutation::SigningWorkerBindingDigest,
    FixtureMutation::BothBindingsDigest,
];

#[derive(Clone, Copy)]
struct CommonSpec {
    request_id: u64,
    replay_nonce: u64,
    account_id: u64,
    wallet_id: u64,
    session_id: u64,
    organization_id: u64,
    project_id: u64,
    environment_id: u64,
    signing_root_id: u64,
    signing_root_version: u64,
    root_share_epoch: u64,
    deriver_a_identity: u64,
    deriver_a_key_epoch: u64,
    deriver_b_identity: u64,
    deriver_b_key_epoch: u64,
    signing_worker_identity: u64,
    signing_worker_key_epoch: u64,
    client_ephemeral_key: u64,
    request_expiry: u64,
    request_context_digest: u64,
    transcript_digest: u64,
}

impl CommonSpec {
    const fn base() -> Self {
        Self {
            request_id: 1,
            replay_nonce: 2,
            account_id: 3,
            wallet_id: 4,
            session_id: 5,
            organization_id: 6,
            project_id: 7,
            environment_id: 8,
            signing_root_id: 9,
            signing_root_version: 10,
            root_share_epoch: 20,
            deriver_a_identity: 21,
            deriver_a_key_epoch: 22,
            deriver_b_identity: 23,
            deriver_b_key_epoch: 24,
            signing_worker_identity: 25,
            signing_worker_key_epoch: 26,
            client_ephemeral_key: 27,
            request_expiry: 28,
            request_context_digest: 29,
            transcript_digest: 30,
        }
    }

    fn mutated(mut self, field: CommonField) -> Self {
        let replacement = 10_000;
        match field {
            CommonField::RequestId => self.request_id = replacement,
            CommonField::ReplayNonce => self.replay_nonce = replacement,
            CommonField::AccountId => self.account_id = replacement,
            CommonField::WalletId => self.wallet_id = replacement,
            CommonField::SessionId => self.session_id = replacement,
            CommonField::OrganizationId => self.organization_id = replacement,
            CommonField::ProjectId => self.project_id = replacement,
            CommonField::EnvironmentId => self.environment_id = replacement,
            CommonField::SigningRootId => self.signing_root_id = replacement,
            CommonField::SigningRootVersion => self.signing_root_version = replacement,
            CommonField::RootShareEpoch => self.root_share_epoch = replacement,
            CommonField::DeriverAIdentity => self.deriver_a_identity = replacement,
            CommonField::DeriverAKeyEpoch => self.deriver_a_key_epoch = replacement,
            CommonField::DeriverBIdentity => self.deriver_b_identity = replacement,
            CommonField::DeriverBKeyEpoch => self.deriver_b_key_epoch = replacement,
            CommonField::SigningWorkerIdentity => self.signing_worker_identity = replacement,
            CommonField::SigningWorkerKeyEpoch => self.signing_worker_key_epoch = replacement,
            CommonField::ClientEphemeralKey => self.client_ephemeral_key = replacement,
            CommonField::RequestExpiry => self.request_expiry = replacement,
            CommonField::RequestContextDigest => self.request_context_digest = replacement,
            CommonField::TranscriptDigest => self.transcript_digest = replacement,
        }
        self
    }

    fn scope(self) -> PublicIdentityScopeV1 {
        PublicIdentityScopeV1::new(
            PublicAccountIdV1::from_synthetic_tag(self.account_id),
            PublicWalletIdV1::from_synthetic_tag(self.wallet_id),
            PublicSessionIdV1::from_synthetic_tag(self.session_id),
            PublicOrganizationIdV1::from_synthetic_tag(self.organization_id),
            PublicProjectIdV1::from_synthetic_tag(self.project_id),
            PublicEnvironmentIdV1::from_synthetic_tag(self.environment_id),
            PublicSigningRootIdV1::from_synthetic_tag(self.signing_root_id),
            PublicSigningRootVersionV1::from_synthetic_tag(self.signing_root_version),
        )
    }

    fn deriver_a(self) -> PublicDeriverABindingV1 {
        PublicDeriverABindingV1::new(
            DeriverAIdentityV1::from_synthetic_tag(self.deriver_a_identity),
            DeriverAKeyEpochV1::from_synthetic_tag(self.deriver_a_key_epoch),
        )
    }

    fn deriver_b(self) -> PublicDeriverBBindingV1 {
        PublicDeriverBBindingV1::new(
            DeriverBIdentityV1::from_synthetic_tag(self.deriver_b_identity),
            DeriverBKeyEpochV1::from_synthetic_tag(self.deriver_b_key_epoch),
        )
    }

    fn build(self) -> CommonLifecyclePublicInputV1 {
        CommonLifecyclePublicInputV1::new(
            PublicRequestIdV1::from_synthetic_tag(self.request_id),
            PublicReplayNonceV1::from_synthetic_tag(self.replay_nonce),
            self.scope(),
            root_epoch(self.root_share_epoch),
            self.deriver_a(),
            self.deriver_b(),
            PublicSigningWorkerBindingV1::new(
                SigningWorkerIdentityV1::from_synthetic_tag(self.signing_worker_identity),
                SigningWorkerKeyEpochV1::from_synthetic_tag(self.signing_worker_key_epoch),
            ),
            ClientEphemeralPublicKeyV1::from_synthetic_tag(self.client_ephemeral_key),
            PublicRequestExpiryV1::from_synthetic_tag(self.request_expiry),
            PublicRequestContextDigestV1::from_synthetic_tag(self.request_context_digest),
            PublicTranscriptDigestV1::from_synthetic_tag(self.transcript_digest),
        )
    }
}

fn root_epoch(value: u64) -> RootShareEpochV1 {
    RootShareEpochV1::new(value).expect("test root epoch is nonzero")
}

fn deriver_a_epoch(value: u64) -> DeriverAInputStateEpochV1 {
    DeriverAInputStateEpochV1::new(value).expect("test Deriver A epoch is nonzero")
}

fn deriver_b_epoch(value: u64) -> DeriverBInputStateEpochV1 {
    DeriverBInputStateEpochV1::new(value).expect("test Deriver B epoch is nonzero")
}

fn activation_epoch(value: u64) -> ActivationEpochV1 {
    ActivationEpochV1::new(value).expect("test activation epoch is nonzero")
}

fn commitments(a: u64, b: u64) -> CurrentRoleContributionCommitmentsV1 {
    CurrentRoleContributionCommitmentsV1::new(
        DeriverAContributionCommitmentRefV1::from_synthetic_tag(a),
        DeriverBContributionCommitmentRefV1::from_synthetic_tag(b),
    )
}

#[derive(Clone, Copy)]
struct TargetMetadata {
    identity: RegisteredEd25519IdentityV1,
    role_epochs: CurrentRoleEpochsV1,
    root_binding: ActiveClientRootBindingV1,
    role_commitments: CurrentRoleContributionCommitmentsV1,
    recipients: ActivationRecipientsV1,
    activation_epoch: ActivationEpochV1,
}

fn base_target(
    origin: TestOrigin,
    spec: CommonSpec,
    common: &CommonLifecyclePublicInputV1,
) -> TargetMetadata {
    let (a_input, b_input, root_reference, role_commitments) = match origin {
        TestOrigin::Registration | TestOrigin::Recovery => (3, 4, 701, commitments(801, 802)),
        TestOrigin::Refresh => (5, 6, 700, commitments(811, 812)),
    };
    TargetMetadata {
        identity: RegisteredEd25519IdentityV1::new(
            spec.scope(),
            RegisteredEd25519PublicKeyV1::from_synthetic_tag(600),
        ),
        role_epochs: CurrentRoleEpochsV1::new(
            spec.deriver_a(),
            spec.deriver_b(),
            deriver_a_epoch(a_input),
            deriver_b_epoch(b_input),
        ),
        root_binding: ActiveClientRootBindingV1::new(
            ActiveClientRootBindingRefV1::from_synthetic_tag(root_reference),
            root_epoch(spec.root_share_epoch),
        ),
        role_commitments,
        recipients: ActivationRecipientsV1::from_common(common),
        activation_epoch: activation_epoch(10),
    }
}

fn mutate_target(
    mut target: TargetMetadata,
    mutation: FixtureMutation,
    spec: CommonSpec,
) -> TargetMetadata {
    match mutation {
        FixtureMutation::TargetIdentityScope => {
            target.identity = RegisteredEd25519IdentityV1::new(
                spec.mutated(CommonField::WalletId).scope(),
                target.identity.public_key(),
            );
        }
        FixtureMutation::TargetRootEpoch => {
            target.root_binding =
                ActiveClientRootBindingV1::new(target.root_binding.reference(), root_epoch(99));
        }
        FixtureMutation::TargetDeriverA => {
            target.role_epochs = CurrentRoleEpochsV1::new(
                spec.mutated(CommonField::DeriverAIdentity).deriver_a(),
                spec.deriver_b(),
                target.role_epochs.deriver_a_input_state_epoch(),
                target.role_epochs.deriver_b_input_state_epoch(),
            );
        }
        FixtureMutation::TargetDeriverB => {
            target.role_epochs = CurrentRoleEpochsV1::new(
                spec.deriver_a(),
                spec.mutated(CommonField::DeriverBIdentity).deriver_b(),
                target.role_epochs.deriver_a_input_state_epoch(),
                target.role_epochs.deriver_b_input_state_epoch(),
            );
        }
        FixtureMutation::PendingClientRecipient => {
            target.recipients = ActivationRecipientsV1::from_common(
                &spec.mutated(CommonField::ClientEphemeralKey).build(),
            );
        }
        FixtureMutation::PendingSigningWorkerRecipient => {
            target.recipients = ActivationRecipientsV1::from_common(
                &spec.mutated(CommonField::SigningWorkerIdentity).build(),
            );
        }
        _ => {}
    }
    target
}

fn transition(origin: TestOrigin, tag: u64) -> ActivationTransitionRefV1 {
    match origin {
        TestOrigin::Registration => ActivationTransitionRefV1::Registration(
            RegistrationTransitionRefV1::from_synthetic_tag(tag),
        ),
        TestOrigin::Recovery => {
            ActivationTransitionRefV1::Recovery(RecoveryTransitionRefV1::from_synthetic_tag(tag))
        }
        TestOrigin::Refresh => {
            ActivationTransitionRefV1::Refresh(RefreshTransitionRefV1::from_synthetic_tag(tag))
        }
    }
}

fn origin_kind(origin: TestOrigin) -> ActivationPackageOriginV1 {
    match origin {
        TestOrigin::Registration => ActivationPackageOriginV1::Registration,
        TestOrigin::Recovery => ActivationPackageOriginV1::Recovery,
        TestOrigin::Refresh => ActivationPackageOriginV1::Refresh,
    }
}

fn different_origin(origin: TestOrigin) -> ActivationPackageOriginV1 {
    match origin {
        TestOrigin::Registration => ActivationPackageOriginV1::Recovery,
        TestOrigin::Recovery | TestOrigin::Refresh => ActivationPackageOriginV1::Registration,
    }
}

fn package_binding(
    side_is_client: bool,
    common: CommonLifecyclePublicInputV1,
    target: TargetMetadata,
    mutation: FixtureMutation,
    spec: CommonSpec,
    digest: PublicActivationPackageSetDigestV1,
) -> SyntheticActivationPackageBindingV1 {
    let mut identity = target.identity;
    let mut role_epochs = target.role_epochs;
    let mut role_commitments = target.role_commitments;
    let mut activation_epoch_value = target.activation_epoch;
    let mut binding_digest = digest;
    let side_matches = matches!(
        (side_is_client, mutation),
        (true, FixtureMutation::ClientBindingIdentity)
            | (true, FixtureMutation::BothBindingsIdentity)
            | (true, FixtureMutation::ClientBindingRoleEpochs)
            | (true, FixtureMutation::BothBindingsRoleEpochs)
            | (true, FixtureMutation::ClientBindingCommitments)
            | (true, FixtureMutation::BothBindingsCommitments)
            | (true, FixtureMutation::ClientBindingActivationEpoch)
            | (true, FixtureMutation::BothBindingsActivationEpoch)
            | (true, FixtureMutation::ClientBindingDigest)
            | (true, FixtureMutation::BothBindingsDigest)
            | (false, FixtureMutation::SigningWorkerBindingIdentity)
            | (false, FixtureMutation::BothBindingsIdentity)
            | (false, FixtureMutation::SigningWorkerBindingRoleEpochs)
            | (false, FixtureMutation::BothBindingsRoleEpochs)
            | (false, FixtureMutation::SigningWorkerBindingCommitments)
            | (false, FixtureMutation::BothBindingsCommitments)
            | (false, FixtureMutation::SigningWorkerBindingActivationEpoch)
            | (false, FixtureMutation::BothBindingsActivationEpoch)
            | (false, FixtureMutation::SigningWorkerBindingDigest)
            | (false, FixtureMutation::BothBindingsDigest)
    );
    if side_matches {
        match mutation {
            FixtureMutation::ClientBindingIdentity
            | FixtureMutation::SigningWorkerBindingIdentity
            | FixtureMutation::BothBindingsIdentity => {
                identity = RegisteredEd25519IdentityV1::new(
                    identity.scope(),
                    RegisteredEd25519PublicKeyV1::from_synthetic_tag(60_001),
                );
            }
            FixtureMutation::ClientBindingRoleEpochs
            | FixtureMutation::SigningWorkerBindingRoleEpochs
            | FixtureMutation::BothBindingsRoleEpochs => {
                role_epochs = CurrentRoleEpochsV1::new(
                    spec.deriver_a(),
                    spec.deriver_b(),
                    deriver_a_epoch(61),
                    deriver_b_epoch(62),
                );
            }
            FixtureMutation::ClientBindingCommitments
            | FixtureMutation::SigningWorkerBindingCommitments
            | FixtureMutation::BothBindingsCommitments => {
                role_commitments = commitments(63, 64);
            }
            FixtureMutation::ClientBindingActivationEpoch
            | FixtureMutation::SigningWorkerBindingActivationEpoch
            | FixtureMutation::BothBindingsActivationEpoch => {
                activation_epoch_value = activation_epoch(65);
            }
            FixtureMutation::ClientBindingDigest
            | FixtureMutation::SigningWorkerBindingDigest
            | FixtureMutation::BothBindingsDigest => {
                binding_digest = PublicActivationPackageSetDigestV1::from_synthetic_tag(66);
            }
            _ => {}
        }
    }
    SyntheticActivationPackageBindingV1::new(
        common,
        identity,
        role_epochs,
        role_commitments,
        activation_epoch_value,
        binding_digest,
    )
}

fn package_set(
    origin: TestOrigin,
    target: TargetMetadata,
    base_common: &CommonLifecyclePublicInputV1,
    mutation: FixtureMutation,
    spec: CommonSpec,
) -> SyntheticCommittedActivationPackageRefsV1 {
    let client_common = match mutation {
        FixtureMutation::Common(
            CommonLocation::ClientPackage | CommonLocation::BothPackages,
            field,
        ) => spec.mutated(field).build(),
        _ => base_common.clone(),
    };
    let worker_common = match mutation {
        FixtureMutation::Common(
            CommonLocation::SigningWorkerPackage | CommonLocation::BothPackages,
            field,
        ) => spec.mutated(field).build(),
        _ => base_common.clone(),
    };
    let client_reference = SyntheticClientActivationPackageRefV1::from_synthetic_tag(901);
    let worker_reference = SyntheticSigningWorkerActivationPackageRefV1::from_synthetic_tag(902);
    let digest = PublicActivationPackageSetDigestV1::from_synthetic_tag(903);
    let manifest_origin = match mutation {
        FixtureMutation::ManifestOrigin => different_origin(origin),
        _ => origin_kind(origin),
    };
    let manifest_transition = match mutation {
        FixtureMutation::ManifestTransition => transition(origin, 999),
        _ => transition(origin, 900),
    };
    let manifest_client_reference = match mutation {
        FixtureMutation::ManifestClientReference => {
            SyntheticClientActivationPackageRefV1::from_synthetic_tag(998)
        }
        _ => client_reference,
    };
    let manifest_worker_reference = match mutation {
        FixtureMutation::ManifestSigningWorkerReference => {
            SyntheticSigningWorkerActivationPackageRefV1::from_synthetic_tag(997)
        }
        _ => worker_reference,
    };
    let manifest_digest = match mutation {
        FixtureMutation::ManifestDigest => {
            PublicActivationPackageSetDigestV1::from_synthetic_tag(996)
        }
        _ => digest,
    };
    let client_recipient = match mutation {
        FixtureMutation::ClientPackageRecipient | FixtureMutation::BothPackageRecipients => {
            ActivationRecipientsV1::from_common(
                &spec.mutated(CommonField::ClientEphemeralKey).build(),
            )
        }
        _ => target.recipients,
    };
    let worker_recipient = match mutation {
        FixtureMutation::SigningWorkerPackageRecipient | FixtureMutation::BothPackageRecipients => {
            ActivationRecipientsV1::from_common(
                &spec.mutated(CommonField::SigningWorkerIdentity).build(),
            )
        }
        _ => target.recipients,
    };
    let client = client_recipient.client();
    let signing_worker = worker_recipient.signing_worker();
    SyntheticCommittedActivationPackageRefsV1::new(
        SyntheticCommittedActivationManifestV1::new(
            manifest_origin,
            manifest_transition,
            manifest_client_reference,
            manifest_worker_reference,
            manifest_digest,
        ),
        SyntheticCommittedClientActivationPackageV1::new(
            client_reference,
            client,
            package_binding(true, client_common, target, mutation, spec, digest),
        ),
        SyntheticCommittedSigningWorkerActivationPackageV1::new(
            worker_reference,
            signing_worker,
            package_binding(false, worker_common, target, mutation, spec, digest),
        ),
    )
}

fn current_recovery_state(target: TargetMetadata, spec: CommonSpec) -> RegisteredPreStateV1 {
    RegisteredPreStateV1::new(
        target.identity,
        target.role_epochs,
        ActiveClientRootBindingV1::new(
            ActiveClientRootBindingRefV1::from_synthetic_tag(700),
            root_epoch(spec.root_share_epoch),
        ),
        target.role_commitments,
        activation_epoch(9),
    )
}

fn current_refresh_state(target: TargetMetadata) -> RegisteredPreStateV1 {
    RegisteredPreStateV1::new(
        target.identity,
        CurrentRoleEpochsV1::new(
            CommonSpec::base().deriver_a(),
            CommonSpec::base().deriver_b(),
            deriver_a_epoch(3),
            deriver_b_epoch(4),
        ),
        target.root_binding,
        commitments(801, 802),
        activation_epoch(9),
    )
}

fn activation_request(origin: TestOrigin, mutation: FixtureMutation) -> ActivationRequestV1 {
    let spec = CommonSpec::base();
    let base_common = spec.build();
    let request_common = match mutation {
        FixtureMutation::Common(CommonLocation::Request, field) => spec.mutated(field).build(),
        _ => base_common.clone(),
    };
    let target = mutate_target(base_target(origin, spec, &base_common), mutation, spec);
    let packages = package_set(origin, target, &base_common, mutation, spec);
    let pending = match origin {
        TestOrigin::Registration => {
            PendingActivationPreStateV1::Registration(RegistrationPendingActivationV1::new(
                RegistrationTransitionRefV1::from_synthetic_tag(900),
                RegistrationCandidateStateV1::new(
                    target.identity,
                    target.role_epochs,
                    target.root_binding,
                    target.role_commitments,
                ),
                target.recipients,
                target.activation_epoch,
                packages,
            ))
        }
        TestOrigin::Recovery => PendingActivationPreStateV1::Recovery(
            RecoveryPendingActivationV1::new(
                RecoveryTransitionRefV1::from_synthetic_tag(900),
                current_recovery_state(target, spec),
                target.root_binding,
                target.recipients,
                target.activation_epoch,
                packages,
            )
            .expect("normal recovery fixture advances and replaces state"),
        ),
        TestOrigin::Refresh => PendingActivationPreStateV1::Refresh(
            RefreshPendingActivationV1::new(
                RefreshTransitionRefV1::from_synthetic_tag(900),
                current_refresh_state(target),
                target.role_epochs.deriver_a_input_state_epoch(),
                target.role_epochs.deriver_b_input_state_epoch(),
                target.role_commitments,
                target.recipients,
                target.activation_epoch,
                packages,
            )
            .expect("normal refresh fixture advances and replaces state"),
        ),
    };
    ActivationRequestV1::new(ActivationPublicInputV1::new(request_common), pending)
}

fn assert_uniform_abort(request: ActivationRequestV1, label: &str) {
    let expected_transcript = request.public.common().transcript_digest();
    let abort = match consume_activation_metadata_v1(request) {
        Ok(_) => panic!("{label} unexpectedly passed metadata validation"),
        Err(abort) => abort,
    };
    assert_eq!(abort.request_kind, LifecycleRequestKindV1::Activation);
    assert_eq!(abort.public_transcript_digest, expected_transcript);
    assert_eq!(
        abort.public_failure_code,
        RedactedFailureCodeV1::ReferenceRejected
    );
    assert_eq!(abort.terminal, AbortedTerminalStateV1::Aborted);
}

#[test]
fn branch_wrappers_derive_dispatch_recipient_and_package_shapes() {
    let common = CommonSpec::base().build();
    let registration = RegistrationPublicInputV1::new(common.clone());
    let activation = ActivationPublicInputV1::new(common.clone());
    let recovery = RecoveryPublicInputV1::new(common.clone());
    let refresh = RefreshPublicInputV1::new(common.clone());
    let export = ExportPublicInputV1::new(common);

    assert_eq!(
        registration.request_kind(),
        LifecycleRequestKindV1::Registration
    );
    assert_eq!(
        activation.request_kind(),
        LifecycleRequestKindV1::Activation
    );
    assert_eq!(recovery.request_kind(), LifecycleRequestKindV1::Recovery);
    assert_eq!(refresh.request_kind(), LifecycleRequestKindV1::Refresh);
    assert_eq!(export.request_kind(), LifecycleRequestKindV1::Export);
    for circuit in [
        registration.circuit_family(),
        activation.circuit_family(),
        recovery.circuit_family(),
        refresh.circuit_family(),
    ] {
        assert_eq!(circuit, LifecycleCircuitFamilyV1::Activation);
    }
    assert_eq!(export.circuit_family(), LifecycleCircuitFamilyV1::Export);
    for package_kind in [
        registration.output_package_kind(),
        activation.output_package_kind(),
        recovery.output_package_kind(),
        refresh.output_package_kind(),
    ] {
        assert_eq!(package_kind, LifecycleOutputPackageKindV1::ActivationFamily);
    }
    assert_eq!(
        export.output_package_kind(),
        LifecycleOutputPackageKindV1::Export
    );
    for recipient_plan in [
        registration.recipient_plan(),
        recovery.recipient_plan(),
        refresh.recipient_plan(),
    ] {
        assert!(matches!(
            recipient_plan,
            LifecycleRecipientPlanV1::ActivationFamily { .. }
        ));
    }
    assert!(matches!(
        activation.recipient_plan(),
        LifecycleRecipientPlanV1::ActivationContinuation { .. }
    ));
    assert!(matches!(
        registration.recipient_plan(),
        LifecycleRecipientPlanV1::ActivationFamily { .. }
    ));
    assert!(matches!(
        recovery.recipient_plan(),
        LifecycleRecipientPlanV1::ActivationFamily { .. }
    ));
    assert!(matches!(
        refresh.recipient_plan(),
        LifecycleRecipientPlanV1::ActivationFamily { .. }
    ));
    assert!(matches!(
        export.recipient_plan(),
        LifecycleRecipientPlanV1::Export { .. }
    ));
}

#[test]
fn metadata_consumption_promotes_each_origin_and_consumes_refs() {
    for origin in [
        TestOrigin::Registration,
        TestOrigin::Recovery,
        TestOrigin::Refresh,
    ] {
        let success =
            consume_activation_metadata_v1(activation_request(origin, FixtureMutation::None))
                .expect("valid synthetic metadata must promote");
        let registered = success.post_state.registered();
        assert_eq!(
            registered.identity().public_key(),
            RegisteredEd25519PublicKeyV1::from_synthetic_tag(600)
        );
        assert_eq!(registered.active_activation_epoch(), activation_epoch(10));
        assert_eq!(success.post_state.consumed().origin(), origin_kind(origin));
        assert_eq!(
            success.post_state.consumed().transition(),
            transition(origin, 900)
        );
        assert_eq!(
            success.post_state.consumed().client_package_reference(),
            SyntheticClientActivationPackageRefV1::from_synthetic_tag(901)
        );
        assert_eq!(
            success
                .post_state
                .consumed()
                .signing_worker_package_reference(),
            SyntheticSigningWorkerActivationPackageRefV1::from_synthetic_tag(902)
        );
        assert_eq!(success.zero_evaluation.yao_evaluations(), 0);
        assert_eq!(success.zero_evaluation.deriver_a_invocations(), 0);
        assert_eq!(success.zero_evaluation.deriver_b_invocations(), 0);
        assert_eq!(success.zero_evaluation.contribution_derivations(), 0);
        assert_eq!(success.zero_evaluation.output_share_samples(), 0);

        match origin {
            TestOrigin::Registration => {
                assert_eq!(
                    registered.active_client_root_binding().reference(),
                    ActiveClientRootBindingRefV1::from_synthetic_tag(701)
                );
            }
            TestOrigin::Recovery => {
                assert_eq!(
                    registered.active_client_root_binding().reference(),
                    ActiveClientRootBindingRefV1::from_synthetic_tag(701)
                );
            }
            TestOrigin::Refresh => {
                assert_eq!(
                    registered
                        .current_role_epochs()
                        .deriver_a_input_state_epoch(),
                    deriver_a_epoch(5)
                );
                assert_eq!(
                    registered
                        .current_role_epochs()
                        .deriver_b_input_state_epoch(),
                    deriver_b_epoch(6)
                );
                assert_eq!(registered.current_role_commitments(), commitments(811, 812));
            }
        }
    }
}

#[test]
fn every_checked_metadata_predicate_uses_exact_uniform_abort() {
    for field in COMMON_FIELDS {
        for location in [
            CommonLocation::Request,
            CommonLocation::ClientPackage,
            CommonLocation::SigningWorkerPackage,
            CommonLocation::BothPackages,
        ] {
            assert_uniform_abort(
                activation_request(
                    TestOrigin::Registration,
                    FixtureMutation::Common(location, field),
                ),
                &format!("{location:?} {field:?}"),
            );
        }
    }
    for mutation in METADATA_MUTATIONS {
        assert_uniform_abort(
            activation_request(TestOrigin::Registration, mutation),
            &format!("{mutation:?}"),
        );
    }
}

fn base_recovery_parts(
    replacement: ActiveClientRootBindingV1,
    next_activation_epoch: ActivationEpochV1,
) -> Result<RecoveryPendingActivationV1, LifecycleTransitionErrorV1> {
    let spec = CommonSpec::base();
    let common = spec.build();
    let target = base_target(TestOrigin::Recovery, spec, &common);
    RecoveryPendingActivationV1::new(
        RecoveryTransitionRefV1::from_synthetic_tag(900),
        current_recovery_state(target, spec),
        replacement,
        target.recipients,
        next_activation_epoch,
        package_set(
            TestOrigin::Recovery,
            target,
            &common,
            FixtureMutation::None,
            spec,
        ),
    )
}

fn base_refresh_parts(
    next_a: DeriverAInputStateEpochV1,
    next_b: DeriverBInputStateEpochV1,
    next_commitments: CurrentRoleContributionCommitmentsV1,
    next_activation_epoch: ActivationEpochV1,
) -> Result<RefreshPendingActivationV1, LifecycleTransitionErrorV1> {
    let spec = CommonSpec::base();
    let common = spec.build();
    let target = base_target(TestOrigin::Refresh, spec, &common);
    RefreshPendingActivationV1::new(
        RefreshTransitionRefV1::from_synthetic_tag(900),
        current_refresh_state(target),
        next_a,
        next_b,
        next_commitments,
        target.recipients,
        next_activation_epoch,
        package_set(
            TestOrigin::Refresh,
            target,
            &common,
            FixtureMutation::None,
            spec,
        ),
    )
}

#[test]
fn epochs_and_staged_transitions_reject_zero_stale_or_noop() {
    assert_eq!(RootShareEpochV1::new(0), Err(LifecycleEpochErrorV1::Zero));
    assert_eq!(
        DeriverAInputStateEpochV1::new(0),
        Err(LifecycleEpochErrorV1::Zero)
    );
    assert_eq!(
        DeriverBInputStateEpochV1::new(0),
        Err(LifecycleEpochErrorV1::Zero)
    );
    assert_eq!(ActivationEpochV1::new(0), Err(LifecycleEpochErrorV1::Zero));

    let unchanged_root = ActiveClientRootBindingV1::new(
        ActiveClientRootBindingRefV1::from_synthetic_tag(700),
        root_epoch(20),
    );
    assert!(matches!(
        base_recovery_parts(unchanged_root, activation_epoch(10)),
        Err(LifecycleTransitionErrorV1::RecoveryRootBindingDidNotChange)
    ));
    let same_reference_new_epoch = ActiveClientRootBindingV1::new(
        ActiveClientRootBindingRefV1::from_synthetic_tag(700),
        root_epoch(21),
    );
    assert!(matches!(
        base_recovery_parts(same_reference_new_epoch, activation_epoch(10)),
        Err(LifecycleTransitionErrorV1::RecoveryRootBindingDidNotChange)
    ));
    let changed_epoch = ActiveClientRootBindingV1::new(
        ActiveClientRootBindingRefV1::from_synthetic_tag(701),
        root_epoch(21),
    );
    assert!(matches!(
        base_recovery_parts(changed_epoch, activation_epoch(10)),
        Err(LifecycleTransitionErrorV1::RecoveryRootEpochChanged)
    ));
    let replacement_root = ActiveClientRootBindingV1::new(
        ActiveClientRootBindingRefV1::from_synthetic_tag(701),
        root_epoch(20),
    );
    assert!(matches!(
        base_recovery_parts(replacement_root, activation_epoch(9)),
        Err(LifecycleTransitionErrorV1::Epoch(
            LifecycleEpochErrorV1::DidNotStrictlyAdvance
        ))
    ));
    let replacement_root = ActiveClientRootBindingV1::new(
        ActiveClientRootBindingRefV1::from_synthetic_tag(701),
        root_epoch(20),
    );
    assert!(matches!(
        base_recovery_parts(replacement_root, activation_epoch(8)),
        Err(LifecycleTransitionErrorV1::Epoch(
            LifecycleEpochErrorV1::DidNotStrictlyAdvance
        ))
    ));
    assert!(matches!(
        base_refresh_parts(
            deriver_a_epoch(3),
            deriver_b_epoch(6),
            commitments(811, 812),
            activation_epoch(10)
        ),
        Err(LifecycleTransitionErrorV1::Epoch(
            LifecycleEpochErrorV1::DidNotStrictlyAdvance
        ))
    ));
    assert!(matches!(
        base_refresh_parts(
            deriver_a_epoch(2),
            deriver_b_epoch(6),
            commitments(811, 812),
            activation_epoch(10)
        ),
        Err(LifecycleTransitionErrorV1::Epoch(
            LifecycleEpochErrorV1::DidNotStrictlyAdvance
        ))
    ));
    assert!(matches!(
        base_refresh_parts(
            deriver_a_epoch(5),
            deriver_b_epoch(4),
            commitments(811, 812),
            activation_epoch(10)
        ),
        Err(LifecycleTransitionErrorV1::Epoch(
            LifecycleEpochErrorV1::DidNotStrictlyAdvance
        ))
    ));
    assert!(matches!(
        base_refresh_parts(
            deriver_a_epoch(5),
            deriver_b_epoch(6),
            commitments(811, 812),
            activation_epoch(8)
        ),
        Err(LifecycleTransitionErrorV1::Epoch(
            LifecycleEpochErrorV1::DidNotStrictlyAdvance
        ))
    ));
    assert!(matches!(
        base_refresh_parts(
            deriver_a_epoch(5),
            deriver_b_epoch(6),
            commitments(801, 802),
            activation_epoch(10)
        ),
        Err(LifecycleTransitionErrorV1::RefreshCommitmentsDidNotChange)
    ));
    assert!(matches!(
        base_refresh_parts(
            deriver_a_epoch(5),
            deriver_b_epoch(6),
            commitments(801, 812),
            activation_epoch(10)
        ),
        Err(LifecycleTransitionErrorV1::RefreshCommitmentsDidNotChange)
    ));
    assert!(matches!(
        base_refresh_parts(
            deriver_a_epoch(5),
            deriver_b_epoch(6),
            commitments(811, 802),
            activation_epoch(10)
        ),
        Err(LifecycleTransitionErrorV1::RefreshCommitmentsDidNotChange)
    ));
    assert!(matches!(
        base_refresh_parts(
            deriver_a_epoch(5),
            deriver_b_epoch(6),
            commitments(811, 812),
            activation_epoch(9)
        ),
        Err(LifecycleTransitionErrorV1::Epoch(
            LifecycleEpochErrorV1::DidNotStrictlyAdvance
        ))
    ));
}

struct UiHarness {
    directory: PathBuf,
}

impl UiHarness {
    fn create() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock must follow Unix epoch")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "ed25519-yao-lifecycle-ui-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(directory.join("src")).expect("create UI harness source directory");
        let manifest_directory = Path::new(env!("CARGO_MANIFEST_DIR"))
            .canonicalize()
            .expect("canonical generator path");
        let dependency_path = manifest_directory.to_string_lossy().replace('\\', "\\\\");
        fs::write(
            directory.join("Cargo.toml"),
            format!(
                "[package]\nname = \"lifecycle-domain-ui\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\
                 [dependencies]\ned25519-yao-generator = {{ path = \"{dependency_path}\" }}\n"
            ),
        )
        .expect("write UI harness manifest");
        Self { directory }
    }

    fn check(&self, body: &str) -> std::process::Output {
        fs::write(self.directory.join("src/main.rs"), body).expect("write UI harness source");
        Command::new(std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into()))
            .args(["check", "--quiet", "--offline"])
            .current_dir(&self.directory)
            .env("CARGO_TARGET_DIR", self.directory.join("target"))
            .output()
            .expect("execute UI cargo check")
    }
}

impl Drop for UiHarness {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

fn assert_compile_failure(harness: &UiHarness, body: &str, code: &str) {
    let output = harness.check(body);
    assert!(!output.status.success(), "UI case unexpectedly compiled");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(code),
        "UI case failed without {code}:\n{stderr}"
    );
}

#[test]
fn compile_fail_and_source_guards_close_escape_hatches() {
    let harness = UiHarness::create();
    let control = harness.check(
        "use ed25519_yao_generator::lifecycle_domain::ActivationRequestV1;\n\
         fn accept(_: ActivationRequestV1) {}\nfn main() {}",
    );
    assert!(
        control.status.success(),
        "UI control failed:\n{}",
        String::from_utf8_lossy(&control.stderr)
    );
    for (body, code) in [
        (
            "use ed25519_yao_generator::lifecycle_domain::*;\n\
             fn take(_: PendingActivationPreStateV1) {}\n\
             fn invalid(value: PendingActivationPreStateV1) { take(value); take(value); }\nfn main() {}",
            "E0382",
        ),
        (
            "use ed25519_yao_generator::lifecycle_domain::*;\n\
             fn take(_: RegistrationPublicInputV1) {}\n\
             fn invalid(value: RecoveryPublicInputV1) { take(value); }\nfn main() {}",
            "E0308",
        ),
        (
            "use ed25519_yao_generator::lifecycle_domain::*;\n\
             fn invalid(public: RegistrationPublicInputV1, pending: PendingActivationPreStateV1) {\n\
                 let _ = ActivationRequestV1::new(public, pending);\n}\nfn main() {}",
            "E0308",
        ),
        (
            "use ed25519_yao_generator::lifecycle_domain::*;\n\
             fn invalid(public: RecoveryPublicInputV1, authorization: ApprovedExportAuthorizationV1, replacement_credential: ReplacementCredentialBindingV1) {\n\
                 let _ = RecoveryRequestV1 { public, authorization, replacement_credential };\n}\nfn main() {}",
            "E0308",
        ),
        (
            "use ed25519_yao_generator::lifecycle_domain::*;\n\
             fn invalid(value: ActivationMetadataConsumptionSuccessV1) { let _ = value.seed(); }\nfn main() {}",
            "E0599",
        ),
        (
            "use ed25519_yao_generator::lifecycle_domain::*;\n\
             fn invalid(value: ActivationRequestV1) { let _ = consume_activation_metadata_v1(value, 0); }\nfn main() {}",
            "E0061",
        ),
        (
            "use ed25519_yao_generator::lifecycle_domain::*;\n\
             fn take(_: DeriverAInputStateEpochV1) {}\n\
             fn invalid(value: RootShareEpochV1) { take(value); }\nfn main() {}",
            "E0308",
        ),
        (
            "use ed25519_yao_generator::lifecycle_domain::*;\n\
             fn take(_: DeriverBInputStateEpochV1) {}\n\
             fn invalid(value: DeriverAInputStateEpochV1) { take(value); }\nfn main() {}",
            "E0308",
        ),
        (
            "use ed25519_yao_generator::lifecycle_domain::*;\n\
             fn needs_clone<T: Clone>() {}\n\
             fn main() { needs_clone::<SyntheticCommittedActivationPackageRefsV1>(); }",
            "E0277",
        ),
        (
            "use ed25519_yao_generator::lifecycle_domain::*;\n\
             fn needs_clone<T: Clone>() {}\n\
             fn main() { needs_clone::<RegisteredPreStateV1>(); }",
            "E0277",
        ),
        (
            "use ed25519_yao_generator::lifecycle_domain::*;\n\
             fn invalid(common: CommonLifecyclePublicInputV1, plan: LifecycleRecipientPlanV1) {\n\
                 let _ = RegistrationPublicInputV1::new(common, plan);\n}\nfn main() {}",
            "E0061",
        ),
    ] {
        assert_compile_failure(&harness, body, code);
    }

    let source = include_str!("../src/lifecycle_domain.rs");
    for forbidden in [
        "#![allow(dead_code)]",
        "Option<",
        "serde::",
        "SeedBytes",
        "evaluate_activation_v1(",
        "evaluate_registration_v1(",
        "evaluate_recovery_v1(",
        "evaluate_refresh_v1(",
        "evaluate_export_v1(",
        "ActivatedRegisteredStateV1",
        "SigningWorkerActivatedOutputV1",
    ] {
        assert!(
            !source.contains(forbidden),
            "blocked or overstated surface `{forbidden}` entered the module"
        );
    }
    let common = source
        .split("pub struct CommonLifecyclePublicInputV1 {")
        .nth(1)
        .expect("common public input declaration")
        .split("}\n\nimpl CommonLifecyclePublicInputV1")
        .next()
        .expect("common public input fields");
    assert!(!common.contains("request_kind"));
    assert!(!common.contains("recipient_kind"));
    assert!(!common.contains("output_package_kind"));

    let abort = source
        .split("pub struct UniformLifecycleAbortV1 {")
        .nth(1)
        .expect("uniform abort declaration")
        .split("}\n\n/// Common result shape")
        .next()
        .expect("uniform abort fields");
    for required in [
        "request_kind:",
        "public_transcript_digest:",
        "public_failure_code:",
        "terminal:",
    ] {
        assert!(abort.contains(required), "abort omitted `{required}`");
    }
    for forbidden in ["role", "peer", "package", "contribution", "share", "scalar"] {
        assert!(
            !abort.contains(forbidden),
            "abort leaked forbidden field class `{forbidden}`"
        );
    }
}
