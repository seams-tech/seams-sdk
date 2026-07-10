//! Host-only semantic lifecycle types for the Ed25519 Yao reference model.
//! The implementation is intentionally limited to synthetic metadata transitions.
//!
//! This module models public metadata equality, origin-specific state promotion,
//! and Rust move consumption. It does not model ciphertext opening, package
//! authentication, server-share combination, distributed replay protection, or
//! production persistence.

use core::num::NonZeroU64;

use crate::LifecycleRequestKindV1;

macro_rules! public_token {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub struct $name(u64);

        impl $name {
            /// Creates a synthetic semantic equality token with no wire encoding.
            pub const fn from_synthetic_tag(tag: u64) -> Self {
                Self(tag)
            }
        }
    };
}

public_token!(/// Public request identifier.
    PublicRequestIdV1);
public_token!(/// Public replay nonce.
    PublicReplayNonceV1);
public_token!(/// Public account identifier.
    PublicAccountIdV1);
public_token!(/// Public wallet identifier.
    PublicWalletIdV1);
public_token!(/// Public session identifier.
    PublicSessionIdV1);
public_token!(/// Public organization identifier.
    PublicOrganizationIdV1);
public_token!(/// Public project identifier.
    PublicProjectIdV1);
public_token!(/// Public deployment-environment identifier.
    PublicEnvironmentIdV1);
public_token!(/// Public signing-root identifier.
    PublicSigningRootIdV1);
public_token!(/// Public signing-root version.
    PublicSigningRootVersionV1);
public_token!(/// Public Deriver A identity.
    DeriverAIdentityV1);
public_token!(/// Public Deriver A key epoch.
    DeriverAKeyEpochV1);
public_token!(/// Public Deriver B identity.
    DeriverBIdentityV1);
public_token!(/// Public Deriver B key epoch.
    DeriverBKeyEpochV1);
public_token!(/// Public SigningWorker identity.
    SigningWorkerIdentityV1);
public_token!(/// Public SigningWorker key epoch.
    SigningWorkerKeyEpochV1);
public_token!(/// Public client ephemeral key.
    ClientEphemeralPublicKeyV1);
public_token!(/// Public request expiry.
    PublicRequestExpiryV1);
public_token!(/// Public request-context digest semantic token.
    PublicRequestContextDigestV1);
public_token!(/// Public transcript digest semantic token.
    PublicTranscriptDigestV1);
public_token!(/// Registered Ed25519 public-key semantic token.
    RegisteredEd25519PublicKeyV1);
public_token!(/// Public active-client-root binding reference.
    ActiveClientRootBindingRefV1);
public_token!(/// Public Deriver A contribution commitment.
    DeriverAContributionCommitmentRefV1);
public_token!(/// Public Deriver B contribution commitment.
    DeriverBContributionCommitmentRefV1);
public_token!(/// Synthetic client activation-package reference.
    SyntheticClientActivationPackageRefV1);
public_token!(/// Synthetic SigningWorker activation-package reference.
    SyntheticSigningWorkerActivationPackageRefV1);
public_token!(/// Public complete activation-package-set digest.
    PublicActivationPackageSetDigestV1);
public_token!(/// Registration transition reference consumed by Rust move.
    RegistrationTransitionRefV1);
public_token!(/// Recovery transition reference consumed by Rust move.
    RecoveryTransitionRefV1);
public_token!(/// Refresh transition reference consumed by Rust move.
    RefreshTransitionRefV1);
public_token!(/// Approved recovery-authorization reference.
    ApprovedRecoveryAuthorizationV1);
public_token!(/// Approved refresh-authorization reference.
    ApprovedRefreshAuthorizationV1);
public_token!(/// Approved export-authorization reference.
    ApprovedExportAuthorizationV1);
public_token!(/// Replacement credential-binding reference.
    ReplacementCredentialBindingV1);
public_token!(/// Consumed export-authorization reference.
    ConsumedExportAuthorizationV1);
public_token!(/// Host-reference Deriver A activation output.
    DeriverAActivationOutputRefV1);
public_token!(/// Host-reference Deriver B activation output.
    DeriverBActivationOutputRefV1);
public_token!(/// Host-reference client scalar deliverable.
    ClientScalarDeliverableRefV1);
public_token!(/// Host-reference SigningWorker scalar deliverable.
    SigningWorkerScalarDeliverableRefV1);
public_token!(/// Public activation-family receipt reference.
    ActivationFamilyPublicReceiptRefV1);
public_token!(/// Host-reference Deriver A export share.
    DeriverASeedExportShareRefV1);
public_token!(/// Host-reference Deriver B export share.
    DeriverBSeedExportShareRefV1);
public_token!(/// Host-reference authorized client export output.
    AuthorizedClientSeedOutputRefV1);
public_token!(/// Public Router export-relay reference.
    RouterExportRelayRefV1);
public_token!(/// Public export receipt reference.
    ExportPublicReceiptRefV1);

/// Fixed semantic protocol version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleProtocolVersionV1 {
    /// Version one.
    V1,
}

/// Circuit artifact family derived from a request branch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleCircuitFamilyV1 {
    /// Activation-family artifact.
    Activation,
    /// Explicit export artifact.
    Export,
}

/// Recipient plan derived from a request branch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleRecipientPlanV1 {
    /// Client and SigningWorker receive activation-family packages.
    ActivationFamily {
        /// Client recipient.
        client: ClientRecipientV1,
        /// SigningWorker recipient.
        signing_worker: SigningWorkerRecipientV1,
    },
    /// The continuation selects only the already-bound SigningWorker package.
    ActivationContinuation {
        /// Selected SigningWorker recipient.
        signing_worker: SigningWorkerRecipientV1,
    },
    /// Export addresses only the client.
    Export {
        /// Authorized export client.
        client: ClientRecipientV1,
    },
}

/// Output-package class derived from a request branch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleOutputPackageKindV1 {
    /// Activation-family scalar packages.
    ActivationFamily,
    /// Authorized seed-export packages.
    Export,
}

/// Validation failure for a semantic epoch value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleEpochErrorV1 {
    /// Epoch zero is invalid.
    Zero,
    /// A proposed epoch did not strictly advance its current epoch.
    DidNotStrictlyAdvance,
}

/// Validation failure for an origin-specific staged metadata transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleTransitionErrorV1 {
    /// An activation or role input-state epoch was invalid.
    Epoch(LifecycleEpochErrorV1),
    /// Recovery did not stage a replacement root binding.
    RecoveryRootBindingDidNotChange,
    /// Recovery changed the root-share epoch for an unchanged logical root.
    RecoveryRootEpochChanged,
    /// Refresh did not stage changed role contribution commitments.
    RefreshCommitmentsDidNotChange,
}

macro_rules! checked_epoch {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
        pub struct $name(NonZeroU64);

        impl $name {
            /// Validates and creates a nonzero epoch.
            pub const fn new(value: u64) -> Result<Self, LifecycleEpochErrorV1> {
                match NonZeroU64::new(value) {
                    Some(value) => Ok(Self(value)),
                    None => Err(LifecycleEpochErrorV1::Zero),
                }
            }

            /// Returns the semantic epoch number.
            pub const fn value(self) -> u64 {
                self.0.get()
            }

            /// Returns whether this epoch strictly advances the supplied epoch.
            pub const fn is_strictly_after(self, current: Self) -> bool {
                self.0.get() > current.0.get()
            }
        }
    };
}

checked_epoch!(/// Public root-share epoch.
    RootShareEpochV1);
checked_epoch!(/// Deriver A input-state epoch.
    DeriverAInputStateEpochV1);
checked_epoch!(/// Deriver B input-state epoch.
    DeriverBInputStateEpochV1);
checked_epoch!(/// Activation epoch.
    ActivationEpochV1);

/// Public account, wallet, tenancy, and signing-root identity scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicIdentityScopeV1 {
    account_id: PublicAccountIdV1,
    wallet_id: PublicWalletIdV1,
    session_id: PublicSessionIdV1,
    organization_id: PublicOrganizationIdV1,
    project_id: PublicProjectIdV1,
    environment_id: PublicEnvironmentIdV1,
    signing_root_id: PublicSigningRootIdV1,
    signing_root_version: PublicSigningRootVersionV1,
}

impl PublicIdentityScopeV1 {
    /// Creates a complete public identity scope.
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        account_id: PublicAccountIdV1,
        wallet_id: PublicWalletIdV1,
        session_id: PublicSessionIdV1,
        organization_id: PublicOrganizationIdV1,
        project_id: PublicProjectIdV1,
        environment_id: PublicEnvironmentIdV1,
        signing_root_id: PublicSigningRootIdV1,
        signing_root_version: PublicSigningRootVersionV1,
    ) -> Self {
        Self {
            account_id,
            wallet_id,
            session_id,
            organization_id,
            project_id,
            environment_id,
            signing_root_id,
            signing_root_version,
        }
    }
}

/// Public Deriver A identity and key epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicDeriverABindingV1 {
    identity: DeriverAIdentityV1,
    key_epoch: DeriverAKeyEpochV1,
}

impl PublicDeriverABindingV1 {
    /// Creates a Deriver A binding.
    pub const fn new(identity: DeriverAIdentityV1, key_epoch: DeriverAKeyEpochV1) -> Self {
        Self {
            identity,
            key_epoch,
        }
    }
}

/// Public Deriver B identity and key epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicDeriverBBindingV1 {
    identity: DeriverBIdentityV1,
    key_epoch: DeriverBKeyEpochV1,
}

impl PublicDeriverBBindingV1 {
    /// Creates a Deriver B binding.
    pub const fn new(identity: DeriverBIdentityV1, key_epoch: DeriverBKeyEpochV1) -> Self {
        Self {
            identity,
            key_epoch,
        }
    }
}

/// Neutral public SigningWorker identity and key epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicSigningWorkerBindingV1 {
    identity: SigningWorkerIdentityV1,
    key_epoch: SigningWorkerKeyEpochV1,
}

impl PublicSigningWorkerBindingV1 {
    /// Creates a neutral SigningWorker binding.
    pub const fn new(
        identity: SigningWorkerIdentityV1,
        key_epoch: SigningWorkerKeyEpochV1,
    ) -> Self {
        Self {
            identity,
            key_epoch,
        }
    }
}

/// Public SigningWorker recipient derived by an activation-family branch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SigningWorkerRecipientV1 {
    binding: PublicSigningWorkerBindingV1,
}

impl SigningWorkerRecipientV1 {
    const fn from_public_binding(binding: PublicSigningWorkerBindingV1) -> Self {
        Self { binding }
    }
}

/// Public client recipient derived by a branch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientRecipientV1 {
    ephemeral_public_key: ClientEphemeralPublicKeyV1,
}

impl ClientRecipientV1 {
    const fn from_ephemeral_public_key(ephemeral_public_key: ClientEphemeralPublicKeyV1) -> Self {
        Self {
            ephemeral_public_key,
        }
    }
}

/// Branch-neutral common public lifecycle context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommonLifecyclePublicInputV1 {
    protocol_version: LifecycleProtocolVersionV1,
    request_id: PublicRequestIdV1,
    replay_nonce: PublicReplayNonceV1,
    identity_scope: PublicIdentityScopeV1,
    root_share_epoch: RootShareEpochV1,
    deriver_a: PublicDeriverABindingV1,
    deriver_b: PublicDeriverBBindingV1,
    signing_worker: PublicSigningWorkerBindingV1,
    client_ephemeral_public_key: ClientEphemeralPublicKeyV1,
    request_expiry: PublicRequestExpiryV1,
    request_context_digest: PublicRequestContextDigestV1,
    transcript_digest: PublicTranscriptDigestV1,
}

impl CommonLifecyclePublicInputV1 {
    /// Creates a complete semantic context without branch discriminants.
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        request_id: PublicRequestIdV1,
        replay_nonce: PublicReplayNonceV1,
        identity_scope: PublicIdentityScopeV1,
        root_share_epoch: RootShareEpochV1,
        deriver_a: PublicDeriverABindingV1,
        deriver_b: PublicDeriverBBindingV1,
        signing_worker: PublicSigningWorkerBindingV1,
        client_ephemeral_public_key: ClientEphemeralPublicKeyV1,
        request_expiry: PublicRequestExpiryV1,
        request_context_digest: PublicRequestContextDigestV1,
        transcript_digest: PublicTranscriptDigestV1,
    ) -> Self {
        Self {
            protocol_version: LifecycleProtocolVersionV1::V1,
            request_id,
            replay_nonce,
            identity_scope,
            root_share_epoch,
            deriver_a,
            deriver_b,
            signing_worker,
            client_ephemeral_public_key,
            request_expiry,
            request_context_digest,
            transcript_digest,
        }
    }

    /// Returns the public transcript digest.
    pub const fn transcript_digest(&self) -> PublicTranscriptDigestV1 {
        self.transcript_digest
    }

    const fn client_recipient(&self) -> ClientRecipientV1 {
        ClientRecipientV1::from_ephemeral_public_key(self.client_ephemeral_public_key)
    }

    const fn signing_worker_recipient(&self) -> SigningWorkerRecipientV1 {
        SigningWorkerRecipientV1::from_public_binding(self.signing_worker)
    }
}

macro_rules! branch_public_input {
    (
        $(#[$meta:meta])*
        $name:ident,
        $kind:ident,
        $circuit:ident,
        $package:ident,
        $recipient:ident
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct $name {
            common: CommonLifecyclePublicInputV1,
        }

        impl $name {
            /// Wraps branch-neutral public input in this fixed lifecycle branch.
            pub const fn new(common: CommonLifecyclePublicInputV1) -> Self {
                Self { common }
            }

            /// Returns the branch-neutral public context.
            pub const fn common(&self) -> &CommonLifecyclePublicInputV1 {
                &self.common
            }

            /// Returns the request kind derived from this wrapper.
            pub const fn request_kind(&self) -> LifecycleRequestKindV1 {
                LifecycleRequestKindV1::$kind
            }

            /// Returns the circuit family derived from this wrapper.
            pub const fn circuit_family(&self) -> LifecycleCircuitFamilyV1 {
                LifecycleCircuitFamilyV1::$circuit
            }

            /// Returns the output package kind derived from this wrapper.
            pub const fn output_package_kind(&self) -> LifecycleOutputPackageKindV1 {
                LifecycleOutputPackageKindV1::$package
            }

            /// Returns the recipient plan derived from this wrapper.
            pub const fn recipient_plan(&self) -> LifecycleRecipientPlanV1 {
                branch_public_input!(@recipient self.common, $recipient)
            }
        }
    };
    (@recipient $common:expr, activation_family) => {
        LifecycleRecipientPlanV1::ActivationFamily {
            client: $common.client_recipient(),
            signing_worker: $common.signing_worker_recipient(),
        }
    };
    (@recipient $common:expr, activation_continuation) => {
        LifecycleRecipientPlanV1::ActivationContinuation {
            signing_worker: $common.signing_worker_recipient(),
        }
    };
    (@recipient $common:expr, export) => {
        LifecycleRecipientPlanV1::Export {
            client: $common.client_recipient(),
        }
    };
}

branch_public_input!(
    /// Registration-specific public input wrapper.
    RegistrationPublicInputV1,
    Registration,
    Activation,
    ActivationFamily,
    activation_family
);
branch_public_input!(
    /// Activation-continuation public input wrapper.
    ActivationPublicInputV1,
    Activation,
    Activation,
    ActivationFamily,
    activation_continuation
);
branch_public_input!(
    /// Recovery-specific public input wrapper.
    RecoveryPublicInputV1,
    Recovery,
    Activation,
    ActivationFamily,
    activation_family
);
branch_public_input!(
    /// Refresh-specific public input wrapper.
    RefreshPublicInputV1,
    Refresh,
    Activation,
    ActivationFamily,
    activation_family
);
branch_public_input!(
    /// Export-specific public input wrapper.
    ExportPublicInputV1,
    Export,
    Export,
    Export,
    export
);

/// Fixed pair of activation-family recipients.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActivationRecipientsV1 {
    client: ClientRecipientV1,
    signing_worker: SigningWorkerRecipientV1,
}

impl ActivationRecipientsV1 {
    /// Derives activation recipients from branch-neutral public input.
    pub const fn from_common(public: &CommonLifecyclePublicInputV1) -> Self {
        Self {
            client: public.client_recipient(),
            signing_worker: public.signing_worker_recipient(),
        }
    }

    /// Returns the client recipient.
    pub const fn client(&self) -> ClientRecipientV1 {
        self.client
    }

    /// Returns the SigningWorker recipient.
    pub const fn signing_worker(&self) -> SigningWorkerRecipientV1 {
        self.signing_worker
    }
}

/// Registered Ed25519 public identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegisteredEd25519IdentityV1 {
    scope: PublicIdentityScopeV1,
    public_key: RegisteredEd25519PublicKeyV1,
}

impl RegisteredEd25519IdentityV1 {
    /// Creates a registered public identity.
    pub const fn new(
        scope: PublicIdentityScopeV1,
        public_key: RegisteredEd25519PublicKeyV1,
    ) -> Self {
        Self { scope, public_key }
    }

    /// Returns the public identity scope.
    pub const fn scope(&self) -> PublicIdentityScopeV1 {
        self.scope
    }

    /// Returns the registered public key.
    pub const fn public_key(&self) -> RegisteredEd25519PublicKeyV1 {
        self.public_key
    }
}

/// Current public role identity, key, and input-state epochs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CurrentRoleEpochsV1 {
    deriver_a: PublicDeriverABindingV1,
    deriver_b: PublicDeriverBBindingV1,
    deriver_a_input_state_epoch: DeriverAInputStateEpochV1,
    deriver_b_input_state_epoch: DeriverBInputStateEpochV1,
}

impl CurrentRoleEpochsV1 {
    /// Creates current role epochs from nonzero input-state epochs.
    pub const fn new(
        deriver_a: PublicDeriverABindingV1,
        deriver_b: PublicDeriverBBindingV1,
        deriver_a_input_state_epoch: DeriverAInputStateEpochV1,
        deriver_b_input_state_epoch: DeriverBInputStateEpochV1,
    ) -> Self {
        Self {
            deriver_a,
            deriver_b,
            deriver_a_input_state_epoch,
            deriver_b_input_state_epoch,
        }
    }

    /// Returns Deriver A's input-state epoch.
    pub const fn deriver_a_input_state_epoch(&self) -> DeriverAInputStateEpochV1 {
        self.deriver_a_input_state_epoch
    }

    /// Returns Deriver B's input-state epoch.
    pub const fn deriver_b_input_state_epoch(&self) -> DeriverBInputStateEpochV1 {
        self.deriver_b_input_state_epoch
    }
}

/// Strictly advanced role input-state epochs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NextRoleEpochsV1 {
    deriver_a: DeriverAInputStateEpochV1,
    deriver_b: DeriverBInputStateEpochV1,
}

impl NextRoleEpochsV1 {
    /// Validates that both role input-state epochs strictly advance.
    pub const fn strictly_after(
        current: &CurrentRoleEpochsV1,
        deriver_a: DeriverAInputStateEpochV1,
        deriver_b: DeriverBInputStateEpochV1,
    ) -> Result<Self, LifecycleEpochErrorV1> {
        if !deriver_a.is_strictly_after(current.deriver_a_input_state_epoch)
            || !deriver_b.is_strictly_after(current.deriver_b_input_state_epoch)
        {
            return Err(LifecycleEpochErrorV1::DidNotStrictlyAdvance);
        }
        Ok(Self {
            deriver_a,
            deriver_b,
        })
    }

    const fn promoted_role_epochs(self, current: CurrentRoleEpochsV1) -> CurrentRoleEpochsV1 {
        CurrentRoleEpochsV1 {
            deriver_a: current.deriver_a,
            deriver_b: current.deriver_b,
            deriver_a_input_state_epoch: self.deriver_a,
            deriver_b_input_state_epoch: self.deriver_b,
        }
    }
}

/// Public active logical-client root binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActiveClientRootBindingV1 {
    reference: ActiveClientRootBindingRefV1,
    root_share_epoch: RootShareEpochV1,
}

impl ActiveClientRootBindingV1 {
    /// Creates an active root-binding reference.
    pub const fn new(
        reference: ActiveClientRootBindingRefV1,
        root_share_epoch: RootShareEpochV1,
    ) -> Self {
        Self {
            reference,
            root_share_epoch,
        }
    }

    /// Returns the public root-share epoch.
    pub const fn root_share_epoch(&self) -> RootShareEpochV1 {
        self.root_share_epoch
    }

    /// Returns the public root-binding reference.
    pub const fn reference(&self) -> ActiveClientRootBindingRefV1 {
        self.reference
    }
}

/// Current public role contribution commitments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CurrentRoleContributionCommitmentsV1 {
    deriver_a: DeriverAContributionCommitmentRefV1,
    deriver_b: DeriverBContributionCommitmentRefV1,
}

impl CurrentRoleContributionCommitmentsV1 {
    /// Creates current role commitment references.
    pub const fn new(
        deriver_a: DeriverAContributionCommitmentRefV1,
        deriver_b: DeriverBContributionCommitmentRefV1,
    ) -> Self {
        Self {
            deriver_a,
            deriver_b,
        }
    }
}

/// Registered public-reference state after metadata promotion.
#[derive(Debug, PartialEq, Eq)]
pub struct RegisteredPreStateV1 {
    identity: RegisteredEd25519IdentityV1,
    current_role_epochs: CurrentRoleEpochsV1,
    active_client_root_binding: ActiveClientRootBindingV1,
    current_role_commitments: CurrentRoleContributionCommitmentsV1,
    active_activation_epoch: ActivationEpochV1,
}

impl RegisteredPreStateV1 {
    /// Creates a registered public-reference state.
    pub const fn new(
        identity: RegisteredEd25519IdentityV1,
        current_role_epochs: CurrentRoleEpochsV1,
        active_client_root_binding: ActiveClientRootBindingV1,
        current_role_commitments: CurrentRoleContributionCommitmentsV1,
        active_activation_epoch: ActivationEpochV1,
    ) -> Self {
        Self {
            identity,
            current_role_epochs,
            active_client_root_binding,
            current_role_commitments,
            active_activation_epoch,
        }
    }

    /// Returns the registered identity.
    pub const fn identity(&self) -> RegisteredEd25519IdentityV1 {
        self.identity
    }

    /// Returns current role epochs.
    pub const fn current_role_epochs(&self) -> CurrentRoleEpochsV1 {
        self.current_role_epochs
    }

    /// Returns the active root binding.
    pub const fn active_client_root_binding(&self) -> ActiveClientRootBindingV1 {
        self.active_client_root_binding
    }

    /// Returns current role commitments.
    pub const fn current_role_commitments(&self) -> CurrentRoleContributionCommitmentsV1 {
        self.current_role_commitments
    }

    /// Returns the active activation epoch.
    pub const fn active_activation_epoch(&self) -> ActivationEpochV1 {
        self.active_activation_epoch
    }
}

/// Registration pre-state with no registered key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnregisteredPreStateV1 {
    /// Public identity scope that has no registered Ed25519 key.
    pub scope: PublicIdentityScopeV1,
}

/// Candidate registered metadata created by registration before first activation.
#[derive(Debug, PartialEq, Eq)]
pub struct RegistrationCandidateStateV1 {
    identity: RegisteredEd25519IdentityV1,
    role_epochs: CurrentRoleEpochsV1,
    client_root_binding: ActiveClientRootBindingV1,
    role_commitments: CurrentRoleContributionCommitmentsV1,
}

impl RegistrationCandidateStateV1 {
    /// Creates registration candidate metadata with no active activation epoch.
    pub const fn new(
        identity: RegisteredEd25519IdentityV1,
        role_epochs: CurrentRoleEpochsV1,
        client_root_binding: ActiveClientRootBindingV1,
        role_commitments: CurrentRoleContributionCommitmentsV1,
    ) -> Self {
        Self {
            identity,
            role_epochs,
            client_root_binding,
            role_commitments,
        }
    }
}

/// Full synthetic public binding repeated on each committed package reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyntheticActivationPackageBindingV1 {
    public: CommonLifecyclePublicInputV1,
    identity: RegisteredEd25519IdentityV1,
    role_epochs: CurrentRoleEpochsV1,
    role_commitments: CurrentRoleContributionCommitmentsV1,
    activation_epoch: ActivationEpochV1,
    package_set_digest: PublicActivationPackageSetDigestV1,
}

impl SyntheticActivationPackageBindingV1 {
    /// Creates an independently supplied host-reference package binding.
    pub const fn new(
        public: CommonLifecyclePublicInputV1,
        identity: RegisteredEd25519IdentityV1,
        role_epochs: CurrentRoleEpochsV1,
        role_commitments: CurrentRoleContributionCommitmentsV1,
        activation_epoch: ActivationEpochV1,
        package_set_digest: PublicActivationPackageSetDigestV1,
    ) -> Self {
        Self {
            public,
            identity,
            role_epochs,
            role_commitments,
            activation_epoch,
            package_set_digest,
        }
    }
}

/// Origin of a synthetic activation package set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivationPackageOriginV1 {
    /// Registration-created metadata.
    Registration,
    /// Recovery-created metadata.
    Recovery,
    /// Refresh-created metadata.
    Refresh,
}

/// Origin-specific transition reference in a synthetic package manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivationTransitionRefV1 {
    /// Registration transition.
    Registration(RegistrationTransitionRefV1),
    /// Recovery transition.
    Recovery(RecoveryTransitionRefV1),
    /// Refresh transition.
    Refresh(RefreshTransitionRefV1),
}

/// Synthetic metadata manifest committing package and transition references.
#[derive(Debug, PartialEq, Eq)]
pub struct SyntheticCommittedActivationManifestV1 {
    origin: ActivationPackageOriginV1,
    transition: ActivationTransitionRefV1,
    client_package: SyntheticClientActivationPackageRefV1,
    signing_worker_package: SyntheticSigningWorkerActivationPackageRefV1,
    package_set_digest: PublicActivationPackageSetDigestV1,
}

impl SyntheticCommittedActivationManifestV1 {
    /// Creates a synthetic package-reference manifest.
    pub const fn new(
        origin: ActivationPackageOriginV1,
        transition: ActivationTransitionRefV1,
        client_package: SyntheticClientActivationPackageRefV1,
        signing_worker_package: SyntheticSigningWorkerActivationPackageRefV1,
        package_set_digest: PublicActivationPackageSetDigestV1,
    ) -> Self {
        Self {
            origin,
            transition,
            client_package,
            signing_worker_package,
            package_set_digest,
        }
    }
}

/// Synthetic committed client package metadata.
#[derive(Debug, PartialEq, Eq)]
pub struct SyntheticCommittedClientActivationPackageV1 {
    reference: SyntheticClientActivationPackageRefV1,
    recipient: ClientRecipientV1,
    binding: SyntheticActivationPackageBindingV1,
}

impl SyntheticCommittedClientActivationPackageV1 {
    /// Creates synthetic client package metadata.
    pub const fn new(
        reference: SyntheticClientActivationPackageRefV1,
        recipient: ClientRecipientV1,
        binding: SyntheticActivationPackageBindingV1,
    ) -> Self {
        Self {
            reference,
            recipient,
            binding,
        }
    }
}

/// Synthetic committed SigningWorker package metadata.
#[derive(Debug, PartialEq, Eq)]
pub struct SyntheticCommittedSigningWorkerActivationPackageV1 {
    reference: SyntheticSigningWorkerActivationPackageRefV1,
    recipient: SigningWorkerRecipientV1,
    binding: SyntheticActivationPackageBindingV1,
}

impl SyntheticCommittedSigningWorkerActivationPackageV1 {
    /// Creates synthetic SigningWorker package metadata.
    pub const fn new(
        reference: SyntheticSigningWorkerActivationPackageRefV1,
        recipient: SigningWorkerRecipientV1,
        binding: SyntheticActivationPackageBindingV1,
    ) -> Self {
        Self {
            reference,
            recipient,
            binding,
        }
    }
}

/// Move-consumed synthetic package metadata and manifest.
#[derive(Debug, PartialEq, Eq)]
pub struct SyntheticCommittedActivationPackageRefsV1 {
    manifest: SyntheticCommittedActivationManifestV1,
    client: SyntheticCommittedClientActivationPackageV1,
    signing_worker: SyntheticCommittedSigningWorkerActivationPackageV1,
}

impl SyntheticCommittedActivationPackageRefsV1 {
    /// Creates a complete synthetic package metadata set.
    pub const fn new(
        manifest: SyntheticCommittedActivationManifestV1,
        client: SyntheticCommittedClientActivationPackageV1,
        signing_worker: SyntheticCommittedSigningWorkerActivationPackageV1,
    ) -> Self {
        Self {
            manifest,
            client,
            signing_worker,
        }
    }
}

/// Registration candidate and package metadata awaiting first activation.
pub struct RegistrationPendingActivationV1 {
    transition: RegistrationTransitionRefV1,
    candidate: RegistrationCandidateStateV1,
    recipients: ActivationRecipientsV1,
    first_activation_epoch: ActivationEpochV1,
    packages: SyntheticCommittedActivationPackageRefsV1,
}

impl RegistrationPendingActivationV1 {
    /// Creates registration-pending metadata without an active epoch.
    pub const fn new(
        transition: RegistrationTransitionRefV1,
        candidate: RegistrationCandidateStateV1,
        recipients: ActivationRecipientsV1,
        first_activation_epoch: ActivationEpochV1,
        packages: SyntheticCommittedActivationPackageRefsV1,
    ) -> Self {
        Self {
            transition,
            candidate,
            recipients,
            first_activation_epoch,
            packages,
        }
    }
}

/// Recovery metadata staging a replacement logical-client root binding.
pub struct RecoveryPendingActivationV1 {
    transition: RecoveryTransitionRefV1,
    current: RegisteredPreStateV1,
    staged_replacement_root_binding: ActiveClientRootBindingV1,
    recipients: ActivationRecipientsV1,
    next_activation_epoch: ActivationEpochV1,
    packages: SyntheticCommittedActivationPackageRefsV1,
}

impl RecoveryPendingActivationV1 {
    /// Requires a new binding reference, unchanged root epoch, and advanced activation epoch.
    pub fn new(
        transition: RecoveryTransitionRefV1,
        current: RegisteredPreStateV1,
        staged_replacement_root_binding: ActiveClientRootBindingV1,
        recipients: ActivationRecipientsV1,
        next_activation_epoch: ActivationEpochV1,
        packages: SyntheticCommittedActivationPackageRefsV1,
    ) -> Result<Self, LifecycleTransitionErrorV1> {
        if staged_replacement_root_binding.reference == current.active_client_root_binding.reference
        {
            return Err(LifecycleTransitionErrorV1::RecoveryRootBindingDidNotChange);
        }
        if staged_replacement_root_binding.root_share_epoch
            != current.active_client_root_binding.root_share_epoch
        {
            return Err(LifecycleTransitionErrorV1::RecoveryRootEpochChanged);
        }
        if !next_activation_epoch.is_strictly_after(current.active_activation_epoch) {
            return Err(LifecycleTransitionErrorV1::Epoch(
                LifecycleEpochErrorV1::DidNotStrictlyAdvance,
            ));
        }
        Ok(Self {
            transition,
            current,
            staged_replacement_root_binding,
            recipients,
            next_activation_epoch,
            packages,
        })
    }
}

/// Refresh metadata staging next role epochs and contribution commitments.
pub struct RefreshPendingActivationV1 {
    transition: RefreshTransitionRefV1,
    current: RegisteredPreStateV1,
    staged_next_role_epochs: NextRoleEpochsV1,
    staged_next_role_commitments: CurrentRoleContributionCommitmentsV1,
    recipients: ActivationRecipientsV1,
    next_activation_epoch: ActivationEpochV1,
    packages: SyntheticCommittedActivationPackageRefsV1,
}

impl RefreshPendingActivationV1 {
    /// Requires advanced epochs and changed commitments for both roles.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        transition: RefreshTransitionRefV1,
        current: RegisteredPreStateV1,
        staged_deriver_a_input_epoch: DeriverAInputStateEpochV1,
        staged_deriver_b_input_epoch: DeriverBInputStateEpochV1,
        staged_next_role_commitments: CurrentRoleContributionCommitmentsV1,
        recipients: ActivationRecipientsV1,
        next_activation_epoch: ActivationEpochV1,
        packages: SyntheticCommittedActivationPackageRefsV1,
    ) -> Result<Self, LifecycleTransitionErrorV1> {
        let staged_next_role_epochs = match NextRoleEpochsV1::strictly_after(
            &current.current_role_epochs,
            staged_deriver_a_input_epoch,
            staged_deriver_b_input_epoch,
        ) {
            Ok(epochs) => epochs,
            Err(error) => return Err(LifecycleTransitionErrorV1::Epoch(error)),
        };
        if staged_next_role_commitments.deriver_a == current.current_role_commitments.deriver_a
            || staged_next_role_commitments.deriver_b == current.current_role_commitments.deriver_b
        {
            return Err(LifecycleTransitionErrorV1::RefreshCommitmentsDidNotChange);
        }
        if !next_activation_epoch.is_strictly_after(current.active_activation_epoch) {
            return Err(LifecycleTransitionErrorV1::Epoch(
                LifecycleEpochErrorV1::DidNotStrictlyAdvance,
            ));
        }
        Ok(Self {
            transition,
            current,
            staged_next_role_epochs,
            staged_next_role_commitments,
            recipients,
            next_activation_epoch,
            packages,
        })
    }
}

/// Pending activation metadata restricted to the three valid origins.
pub enum PendingActivationPreStateV1 {
    /// Registration candidate.
    Registration(RegistrationPendingActivationV1),
    /// Recovery staged state.
    Recovery(RecoveryPendingActivationV1),
    /// Refresh staged state.
    Refresh(RefreshPendingActivationV1),
}

/// Registration request branch.
pub struct RegistrationRequestV1 {
    /// Registration-specific public wrapper.
    pub public: RegistrationPublicInputV1,
}

/// Activation metadata-continuation request branch.
pub struct ActivationRequestV1 {
    /// Activation-specific public wrapper.
    pub public: ActivationPublicInputV1,
    /// Origin-specific pending metadata consumed by move.
    pub pending: PendingActivationPreStateV1,
}

impl ActivationRequestV1 {
    /// Creates an activation metadata-continuation request.
    pub const fn new(
        public: ActivationPublicInputV1,
        pending: PendingActivationPreStateV1,
    ) -> Self {
        Self { public, pending }
    }
}

/// Recovery request branch.
pub struct RecoveryRequestV1 {
    /// Recovery-specific public wrapper.
    pub public: RecoveryPublicInputV1,
    /// Approved recovery authorization.
    pub authorization: ApprovedRecoveryAuthorizationV1,
    /// Replacement credential binding.
    pub replacement_credential: ReplacementCredentialBindingV1,
}

/// Refresh request branch.
pub struct RefreshRequestV1 {
    /// Refresh-specific public wrapper.
    pub public: RefreshPublicInputV1,
    /// Approved refresh authorization.
    pub authorization: ApprovedRefreshAuthorizationV1,
    /// Strictly advanced role input-state epochs.
    pub next_role_epochs: NextRoleEpochsV1,
}

/// Export request branch.
pub struct ExportRequestV1 {
    /// Export-specific public wrapper.
    pub public: ExportPublicInputV1,
    /// Approved export authorization.
    pub authorization: ApprovedExportAuthorizationV1,
}

/// Exhaustive five-branch lifecycle request family.
pub enum ReferenceLifecycleRequestV1 {
    /// Registration request.
    Registration(RegistrationRequestV1),
    /// Activation metadata continuation.
    Activation(Box<ActivationRequestV1>),
    /// Recovery request.
    Recovery(RecoveryRequestV1),
    /// Refresh request.
    Refresh(RefreshRequestV1),
    /// Export request.
    Export(ExportRequestV1),
}

impl ReferenceLifecycleRequestV1 {
    /// Derives the canonical request kind from the branch.
    pub const fn request_kind(&self) -> LifecycleRequestKindV1 {
        match self {
            Self::Registration(request) => request.public.request_kind(),
            Self::Activation(request) => request.public.request_kind(),
            Self::Recovery(request) => request.public.request_kind(),
            Self::Refresh(request) => request.public.request_kind(),
            Self::Export(request) => request.public.request_kind(),
        }
    }

    /// Derives the circuit family from the branch.
    pub const fn circuit_family(&self) -> LifecycleCircuitFamilyV1 {
        match self {
            Self::Registration(request) => request.public.circuit_family(),
            Self::Activation(request) => request.public.circuit_family(),
            Self::Recovery(request) => request.public.circuit_family(),
            Self::Refresh(request) => request.public.circuit_family(),
            Self::Export(request) => request.public.circuit_family(),
        }
    }
}

/// Exhaustive five-branch lifecycle pre-state family.
pub enum ReferenceLifecyclePreStateV1 {
    /// Registration pre-state.
    Registration(UnregisteredPreStateV1),
    /// Activation pending metadata.
    Activation(Box<PendingActivationPreStateV1>),
    /// Recovery registered pre-state.
    Recovery(RegisteredPreStateV1),
    /// Refresh registered pre-state.
    Refresh(RegisteredPreStateV1),
    /// Export registered pre-state.
    Export(RegisteredPreStateV1),
}

/// Freely constructible host-reference output DTO for blocked evaluators.
///
/// This structural shape conveys no authorization or verification capability.
pub struct ReferenceActivationFamilyOutputsV1 {
    /// Deriver A output reference.
    pub deriver_a: DeriverAActivationOutputRefV1,
    /// Deriver B output reference.
    pub deriver_b: DeriverBActivationOutputRefV1,
    /// Client deliverable reference.
    pub client_deliverable: ClientScalarDeliverableRefV1,
    /// SigningWorker deliverable reference.
    pub signing_worker_deliverable: SigningWorkerScalarDeliverableRefV1,
    /// Public receipt reference.
    pub public_receipt: ActivationFamilyPublicReceiptRefV1,
}

/// Marker proving SigningWorker has no export output field.
pub struct NoSigningWorkerExportOutputV1;

/// Freely constructible host-reference export DTO for the blocked evaluator.
///
/// This structural shape conveys no authorization or verification capability.
pub struct ReferenceExportOutputsV1 {
    /// Deriver A export-share reference.
    pub deriver_a: DeriverASeedExportShareRefV1,
    /// Deriver B export-share reference.
    pub deriver_b: DeriverBSeedExportShareRefV1,
    /// Authorized client output reference.
    pub client: AuthorizedClientSeedOutputRefV1,
    /// Router relay reference.
    pub router: RouterExportRelayRefV1,
    /// Explicit no-SigningWorker marker.
    pub signing_worker: NoSigningWorkerExportOutputV1,
    /// Public export receipt reference.
    pub public_receipt: ExportPublicReceiptRefV1,
}

/// Public activation-family leakage for blocked preparation evaluators.
pub struct ActivationFamilyPublicLeakageV1 {
    /// Branch-specific public context.
    pub public: CommonLifecyclePublicInputV1,
    /// Registered identity.
    pub identity: RegisteredEd25519IdentityV1,
    /// Complete package-set digest.
    pub package_set_digest: PublicActivationPackageSetDigestV1,
}

/// Public export leakage for the blocked export evaluator.
pub struct ExportPublicLeakageV1 {
    /// Export public context.
    pub public: ExportPublicInputV1,
    /// Registered identity.
    pub identity: RegisteredEd25519IdentityV1,
    /// Public receipt reference.
    pub public_receipt: ExportPublicReceiptRefV1,
}

/// Freely constructible registration success structural branch.
///
/// This DTO conveys no authorization or verification capability.
pub struct RegistrationSuccessV1 {
    /// Pending registration candidate.
    pub post_state: RegistrationPendingActivationV1,
    /// Required host-reference outputs.
    pub outputs: ReferenceActivationFamilyOutputsV1,
    /// Public leakage.
    pub leakage: ActivationFamilyPublicLeakageV1,
}

/// Freely constructible recovery success structural branch.
///
/// This DTO conveys no authorization or verification capability.
pub struct RecoverySuccessV1 {
    /// Pending recovery staged state.
    pub post_state: RecoveryPendingActivationV1,
    /// Required host-reference outputs.
    pub outputs: ReferenceActivationFamilyOutputsV1,
    /// Public leakage.
    pub leakage: ActivationFamilyPublicLeakageV1,
}

/// Freely constructible refresh success structural branch.
///
/// This DTO conveys no authorization or verification capability.
pub struct RefreshSuccessV1 {
    /// Pending refresh staged state.
    pub post_state: RefreshPendingActivationV1,
    /// Required host-reference outputs.
    pub outputs: ReferenceActivationFamilyOutputsV1,
    /// Public leakage.
    pub leakage: ActivationFamilyPublicLeakageV1,
}

/// Freely constructible export success structural branch.
///
/// This DTO conveys no authorization or verification capability.
pub struct ExportSuccessV1 {
    /// Retained registered state.
    pub retained_state: RegisteredPreStateV1,
    /// Consumed export authorization.
    pub consumed_authorization: ConsumedExportAuthorizationV1,
    /// Required host-reference export outputs.
    pub outputs: ReferenceExportOutputsV1,
    /// Public export leakage.
    pub leakage: ExportPublicLeakageV1,
}

/// Terminal state emitted by every public abort.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbortedTerminalStateV1 {
    /// The semantic transition aborted.
    Aborted,
}

/// Provisional public failure code for this semantic slice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedactedFailureCodeV1 {
    /// A public metadata binding was rejected.
    ReferenceRejected,
}

/// Uniform public-only lifecycle abort envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UniformLifecycleAbortV1 {
    /// Branch-derived request kind.
    pub request_kind: LifecycleRequestKindV1,
    /// Public transcript digest.
    pub public_transcript_digest: PublicTranscriptDigestV1,
    /// Provisional redacted failure code.
    pub public_failure_code: RedactedFailureCodeV1,
    /// Terminal abort state.
    pub terminal: AbortedTerminalStateV1,
}

/// Common result shape for lifecycle semantic operations.
pub type ReferenceLifecycleResultV1<S> = Result<S, UniformLifecycleAbortV1>;

/// Package and transition metadata consumed by Rust move.
pub struct ConsumedActivationMetadataV1 {
    transition: ActivationTransitionRefV1,
    manifest: SyntheticCommittedActivationManifestV1,
    client: SyntheticCommittedClientActivationPackageV1,
    signing_worker: SyntheticCommittedSigningWorkerActivationPackageV1,
}

impl ConsumedActivationMetadataV1 {
    /// Returns the moved transition reference.
    pub const fn transition(&self) -> ActivationTransitionRefV1 {
        self.transition
    }

    /// Returns the moved client package reference.
    pub const fn client_package_reference(&self) -> SyntheticClientActivationPackageRefV1 {
        self.client.reference
    }

    /// Returns the moved SigningWorker package reference.
    pub const fn signing_worker_package_reference(
        &self,
    ) -> SyntheticSigningWorkerActivationPackageRefV1 {
        self.signing_worker.reference
    }

    /// Returns the manifest origin.
    pub const fn origin(&self) -> ActivationPackageOriginV1 {
        self.manifest.origin
    }
}

/// Registered metadata after origin-specific promotion.
pub struct PromotedRegisteredMetadataStateV1 {
    registered: RegisteredPreStateV1,
    consumed: ConsumedActivationMetadataV1,
}

impl PromotedRegisteredMetadataStateV1 {
    /// Returns the promoted registered state.
    pub const fn registered(&self) -> &RegisteredPreStateV1 {
        &self.registered
    }

    /// Returns the metadata consumed by Rust move.
    pub const fn consumed(&self) -> &ConsumedActivationMetadataV1 {
        &self.consumed
    }
}

/// Exact operation counts for metadata-only activation continuation.
pub struct ZeroEvaluationWitnessV1 {
    yao_evaluations: u8,
    deriver_a_invocations: u8,
    deriver_b_invocations: u8,
    contribution_derivations: u8,
    output_share_samples: u8,
}

impl ZeroEvaluationWitnessV1 {
    const fn metadata_continuation() -> Self {
        Self {
            yao_evaluations: 0,
            deriver_a_invocations: 0,
            deriver_b_invocations: 0,
            contribution_derivations: 0,
            output_share_samples: 0,
        }
    }

    /// Returns the number of Yao evaluations.
    pub const fn yao_evaluations(&self) -> u8 {
        self.yao_evaluations
    }

    /// Returns the number of Deriver A invocations.
    pub const fn deriver_a_invocations(&self) -> u8 {
        self.deriver_a_invocations
    }

    /// Returns the number of Deriver B invocations.
    pub const fn deriver_b_invocations(&self) -> u8 {
        self.deriver_b_invocations
    }

    /// Returns the number of contribution derivations.
    pub const fn contribution_derivations(&self) -> u8 {
        self.contribution_derivations
    }

    /// Returns the number of output-share samples.
    pub const fn output_share_samples(&self) -> u8 {
        self.output_share_samples
    }
}

/// Public metadata emitted after move consumption.
pub struct ActivationMetadataPublicLeakageV1 {
    /// Activation-specific public input.
    pub public: ActivationPublicInputV1,
    /// Preserved registered identity.
    pub identity: RegisteredEd25519IdentityV1,
    /// Promoted activation epoch.
    pub activation_epoch: ActivationEpochV1,
    /// Consumed package-set digest.
    pub package_set_digest: PublicActivationPackageSetDigestV1,
}

/// Metadata-only activation continuation success.
pub struct ActivationMetadataConsumptionSuccessV1 {
    /// Origin-specific promoted registered metadata.
    pub post_state: PromotedRegisteredMetadataStateV1,
    /// Exact zero-work witness.
    pub zero_evaluation: ZeroEvaluationWitnessV1,
    /// Public metadata leakage.
    pub leakage: ActivationMetadataPublicLeakageV1,
}

/// Exhaustive five-branch lifecycle success family.
pub enum ReferenceLifecycleSuccessV1 {
    /// Registration success.
    Registration(RegistrationSuccessV1),
    /// Activation metadata consumption success.
    Activation(ActivationMetadataConsumptionSuccessV1),
    /// Recovery success.
    Recovery(RecoverySuccessV1),
    /// Refresh success.
    Refresh(RefreshSuccessV1),
    /// Export success.
    Export(ExportSuccessV1),
}

struct ExpectedActivationMetadataV1<'a> {
    origin: ActivationPackageOriginV1,
    transition: ActivationTransitionRefV1,
    public: &'a CommonLifecyclePublicInputV1,
    identity: RegisteredEd25519IdentityV1,
    role_epochs: CurrentRoleEpochsV1,
    root_binding: ActiveClientRootBindingV1,
    role_commitments: CurrentRoleContributionCommitmentsV1,
    recipients: ActivationRecipientsV1,
    activation_epoch: ActivationEpochV1,
}

fn package_binding_matches(
    binding: &SyntheticActivationPackageBindingV1,
    expected: &ExpectedActivationMetadataV1<'_>,
    package_set_digest: PublicActivationPackageSetDigestV1,
) -> bool {
    binding.public == *expected.public
        && binding.identity == expected.identity
        && binding.role_epochs == expected.role_epochs
        && binding.role_commitments == expected.role_commitments
        && binding.activation_epoch == expected.activation_epoch
        && binding.package_set_digest == package_set_digest
}

fn activation_metadata_matches(
    expected: &ExpectedActivationMetadataV1<'_>,
    packages: &SyntheticCommittedActivationPackageRefsV1,
) -> bool {
    expected.public.identity_scope == expected.identity.scope
        && expected.public.root_share_epoch == expected.root_binding.root_share_epoch
        && expected.public.deriver_a == expected.role_epochs.deriver_a
        && expected.public.deriver_b == expected.role_epochs.deriver_b
        && expected.public.client_recipient() == expected.recipients.client
        && expected.public.signing_worker_recipient() == expected.recipients.signing_worker
        && packages.manifest.origin == expected.origin
        && packages.manifest.transition == expected.transition
        && packages.client.reference == packages.manifest.client_package
        && packages.signing_worker.reference == packages.manifest.signing_worker_package
        && packages.client.recipient == expected.recipients.client
        && packages.signing_worker.recipient == expected.recipients.signing_worker
        && package_binding_matches(
            &packages.client.binding,
            expected,
            packages.manifest.package_set_digest,
        )
        && package_binding_matches(
            &packages.signing_worker.binding,
            expected,
            packages.manifest.package_set_digest,
        )
}

fn metadata_abort(public: &ActivationPublicInputV1) -> UniformLifecycleAbortV1 {
    UniformLifecycleAbortV1 {
        request_kind: public.request_kind(),
        public_transcript_digest: public.common.transcript_digest,
        public_failure_code: RedactedFailureCodeV1::ReferenceRejected,
        terminal: AbortedTerminalStateV1::Aborted,
    }
}

fn consume_registration_metadata(
    public: &ActivationPublicInputV1,
    pending: RegistrationPendingActivationV1,
) -> ReferenceLifecycleResultV1<PromotedRegisteredMetadataStateV1> {
    let expected = ExpectedActivationMetadataV1 {
        origin: ActivationPackageOriginV1::Registration,
        transition: ActivationTransitionRefV1::Registration(pending.transition),
        public: &public.common,
        identity: pending.candidate.identity,
        role_epochs: pending.candidate.role_epochs,
        root_binding: pending.candidate.client_root_binding,
        role_commitments: pending.candidate.role_commitments,
        recipients: pending.recipients,
        activation_epoch: pending.first_activation_epoch,
    };
    if !activation_metadata_matches(&expected, &pending.packages) {
        return Err(metadata_abort(public));
    }
    Ok(PromotedRegisteredMetadataStateV1 {
        registered: RegisteredPreStateV1::new(
            pending.candidate.identity,
            pending.candidate.role_epochs,
            pending.candidate.client_root_binding,
            pending.candidate.role_commitments,
            pending.first_activation_epoch,
        ),
        consumed: ConsumedActivationMetadataV1 {
            transition: expected.transition,
            manifest: pending.packages.manifest,
            client: pending.packages.client,
            signing_worker: pending.packages.signing_worker,
        },
    })
}

fn consume_recovery_metadata(
    public: &ActivationPublicInputV1,
    pending: RecoveryPendingActivationV1,
) -> ReferenceLifecycleResultV1<PromotedRegisteredMetadataStateV1> {
    let expected = ExpectedActivationMetadataV1 {
        origin: ActivationPackageOriginV1::Recovery,
        transition: ActivationTransitionRefV1::Recovery(pending.transition),
        public: &public.common,
        identity: pending.current.identity,
        role_epochs: pending.current.current_role_epochs,
        root_binding: pending.staged_replacement_root_binding,
        role_commitments: pending.current.current_role_commitments,
        recipients: pending.recipients,
        activation_epoch: pending.next_activation_epoch,
    };
    if !activation_metadata_matches(&expected, &pending.packages) {
        return Err(metadata_abort(public));
    }
    Ok(PromotedRegisteredMetadataStateV1 {
        registered: RegisteredPreStateV1::new(
            pending.current.identity,
            pending.current.current_role_epochs,
            pending.staged_replacement_root_binding,
            pending.current.current_role_commitments,
            pending.next_activation_epoch,
        ),
        consumed: ConsumedActivationMetadataV1 {
            transition: expected.transition,
            manifest: pending.packages.manifest,
            client: pending.packages.client,
            signing_worker: pending.packages.signing_worker,
        },
    })
}

fn consume_refresh_metadata(
    public: &ActivationPublicInputV1,
    pending: RefreshPendingActivationV1,
) -> ReferenceLifecycleResultV1<PromotedRegisteredMetadataStateV1> {
    let promoted_role_epochs = pending
        .staged_next_role_epochs
        .promoted_role_epochs(pending.current.current_role_epochs);
    let expected = ExpectedActivationMetadataV1 {
        origin: ActivationPackageOriginV1::Refresh,
        transition: ActivationTransitionRefV1::Refresh(pending.transition),
        public: &public.common,
        identity: pending.current.identity,
        role_epochs: promoted_role_epochs,
        root_binding: pending.current.active_client_root_binding,
        role_commitments: pending.staged_next_role_commitments,
        recipients: pending.recipients,
        activation_epoch: pending.next_activation_epoch,
    };
    if !activation_metadata_matches(&expected, &pending.packages) {
        return Err(metadata_abort(public));
    }
    Ok(PromotedRegisteredMetadataStateV1 {
        registered: RegisteredPreStateV1::new(
            pending.current.identity,
            promoted_role_epochs,
            pending.current.active_client_root_binding,
            pending.staged_next_role_commitments,
            pending.next_activation_epoch,
        ),
        consumed: ConsumedActivationMetadataV1 {
            transition: expected.transition,
            manifest: pending.packages.manifest,
            client: pending.packages.client,
            signing_worker: pending.packages.signing_worker,
        },
    })
}

/// Validates and move-consumes synthetic activation metadata with zero evaluation.
///
/// Success promotes public reference state only. It makes no claim that package
/// ciphertexts were opened, authenticated, or combined by a SigningWorker.
pub fn consume_activation_metadata_v1(
    request: ActivationRequestV1,
) -> ReferenceLifecycleResultV1<ActivationMetadataConsumptionSuccessV1> {
    let public = request.public;
    let post_state = match request.pending {
        PendingActivationPreStateV1::Registration(pending) => {
            consume_registration_metadata(&public, pending)?
        }
        PendingActivationPreStateV1::Recovery(pending) => {
            consume_recovery_metadata(&public, pending)?
        }
        PendingActivationPreStateV1::Refresh(pending) => {
            consume_refresh_metadata(&public, pending)?
        }
    };
    let registered = post_state.registered();
    let leakage = ActivationMetadataPublicLeakageV1 {
        public,
        identity: registered.identity,
        activation_epoch: registered.active_activation_epoch,
        package_set_digest: post_state.consumed.manifest.package_set_digest,
    };
    Ok(ActivationMetadataConsumptionSuccessV1 {
        post_state,
        zero_evaluation: ZeroEvaluationWitnessV1::metadata_continuation(),
        leakage,
    })
}
