use getrandom::getrandom;
use router_ab_core::{
    Ed25519YaoCeremonyBindingV1, Ed25519YaoOperationV1, Ed25519YaoRefreshBindingV1,
    Ed25519YaoRefreshEpochsV1, Ed25519YaoSessionIdV1, Ed25519YaoStableKeyContextBindingV1,
    Ed25519YaoStateEpochV1, RootShareEpoch, RouterAbEd25519YaoApplicationBindingFactsV1,
    RouterAbEd25519YaoLifecycleScopeV1, RouterAbEd25519YaoRegistrationAdmissionRequestV1,
    RouterAbProtocolError, RouterAbProtocolErrorCode, RouterAbProtocolResult,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalEd25519YaoRouterExportAdmissionRequestV1 {
    pub scope: RouterAbEd25519YaoLifecycleScopeV1,
    pub application_binding: RouterAbEd25519YaoApplicationBindingFactsV1,
    pub participant_ids: [u16; 2],
}

pub struct LocalEd25519YaoRouterRegistrationAdmissionV1 {
    pub binding: Ed25519YaoCeremonyBindingV1,
}

pub struct LocalEd25519YaoRouterExportAdmissionV1 {
    pub binding: Ed25519YaoCeremonyBindingV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct LocalEd25519YaoRecoveryCredentialBindingV1([u8; 32]);

impl LocalEd25519YaoRecoveryCredentialBindingV1 {
    pub fn new(binding: [u8; 32]) -> RouterAbProtocolResult<Self> {
        if binding.iter().all(|byte| *byte == 0) {
            return Err(invalid_recovery(
                "recovery credential binding must be nonzero",
            ));
        }
        Ok(Self(binding))
    }

    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalEd25519YaoRouterRecoveryAdmissionRequestV1 {
    pub scope: RouterAbEd25519YaoLifecycleScopeV1,
    pub application_binding: RouterAbEd25519YaoApplicationBindingFactsV1,
    pub participant_ids: [u16; 2],
    pub active_credential: LocalEd25519YaoRecoveryCredentialBindingV1,
    pub replacement_credential: LocalEd25519YaoRecoveryCredentialBindingV1,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalEd25519YaoRouterRecoveryAdmissionV1 {
    pub binding: Ed25519YaoCeremonyBindingV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalEd25519YaoRouterRefreshAdmissionRequestV1 {
    pub scope: RouterAbEd25519YaoLifecycleScopeV1,
    pub application_binding: RouterAbEd25519YaoApplicationBindingFactsV1,
    pub participant_ids: [u16; 2],
    pub registered_public_key: [u8; 32],
    pub epochs: Ed25519YaoRefreshEpochsV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalEd25519YaoRefreshActiveEpochsV1 {
    pub deriver_a: Ed25519YaoStateEpochV1,
    pub deriver_b: Ed25519YaoStateEpochV1,
    pub signing_worker: Ed25519YaoStateEpochV1,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum LocalEd25519YaoRefreshLifecycleV1 {
    Active {
        registered_public_key: [u8; 32],
        epochs: LocalEd25519YaoRefreshActiveEpochsV1,
    },
    Prepared {
        binding: Ed25519YaoRefreshBindingV1,
    },
    OutputCommitted {
        binding: Ed25519YaoRefreshBindingV1,
    },
    WorkerActivated {
        binding: Ed25519YaoRefreshBindingV1,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LocalEd25519YaoRefreshStableIdentityV1 {
    stable_key_context_binding: Ed25519YaoStableKeyContextBindingV1,
    root_share_epoch: RootShareEpoch,
    account_id: String,
    signer_set_id: String,
    signing_worker_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalEd25519YaoRouterRefreshStateV1 {
    stable_identity: LocalEd25519YaoRefreshStableIdentityV1,
    lifecycle: LocalEd25519YaoRefreshLifecycleV1,
    retired_epochs: BTreeSet<LocalEd25519YaoRefreshActiveEpochsV1>,
}

impl LocalEd25519YaoRouterRefreshStateV1 {
    pub fn new(
        active_binding: &Ed25519YaoCeremonyBindingV1,
        registered_public_key: [u8; 32],
        epochs: LocalEd25519YaoRefreshActiveEpochsV1,
    ) -> RouterAbProtocolResult<Self> {
        active_binding.validate()?;
        if registered_public_key.iter().all(|byte| *byte == 0) {
            return Err(invalid_refresh("registered public key must be nonzero"));
        }
        Ok(Self {
            stable_identity: refresh_stable_identity(active_binding),
            lifecycle: LocalEd25519YaoRefreshLifecycleV1::Active {
                registered_public_key,
                epochs,
            },
            retired_epochs: BTreeSet::new(),
        })
    }

    pub fn begin(
        &mut self,
        request: LocalEd25519YaoRouterRefreshAdmissionRequestV1,
    ) -> RouterAbProtocolResult<Ed25519YaoRefreshBindingV1> {
        let LocalEd25519YaoRefreshLifecycleV1::Active {
            registered_public_key,
            epochs,
        } = &self.lifecycle
        else {
            return Err(invalid_refresh("another refresh transition is in progress"));
        };
        if *registered_public_key != request.registered_public_key
            || request.epochs.deriver_a.current() != epochs.deriver_a
            || request.epochs.deriver_b.current() != epochs.deriver_b
            || request.epochs.signing_worker.current() != epochs.signing_worker
        {
            return Err(invalid_refresh(
                "refresh does not match the active public identity and epochs",
            ));
        }
        let ceremony = admitted_binding(
            request.scope,
            &request.application_binding,
            request.participant_ids,
            Ed25519YaoOperationV1::Refresh,
        )?;
        let binding = Ed25519YaoRefreshBindingV1::new(
            ceremony,
            request.registered_public_key,
            request.epochs,
        )?;
        if !refresh_identity_matches(&self.stable_identity, binding.ceremony()) {
            return Err(invalid_refresh(
                "refresh does not match the active stable identity",
            ));
        }
        self.lifecycle = LocalEd25519YaoRefreshLifecycleV1::Prepared {
            binding: binding.clone(),
        };
        Ok(binding)
    }

    pub fn abort_prepared(
        &mut self,
        binding: &Ed25519YaoRefreshBindingV1,
    ) -> RouterAbProtocolResult<()> {
        let LocalEd25519YaoRefreshLifecycleV1::Prepared { binding: prepared } = &self.lifecycle
        else {
            return Err(invalid_refresh("only a prepared refresh may abort"));
        };
        if prepared != binding {
            return Err(invalid_refresh("prepared refresh binding does not match"));
        }
        self.lifecycle = LocalEd25519YaoRefreshLifecycleV1::Active {
            registered_public_key: *binding.registered_public_key(),
            epochs: current_refresh_epochs(binding),
        };
        Ok(())
    }

    pub fn mark_output_committed(
        &mut self,
        binding: &Ed25519YaoRefreshBindingV1,
    ) -> RouterAbProtocolResult<()> {
        let LocalEd25519YaoRefreshLifecycleV1::Prepared { binding: prepared } = &self.lifecycle
        else {
            return Err(invalid_refresh("refresh is not prepared"));
        };
        if prepared != binding {
            return Err(invalid_refresh("prepared refresh binding does not match"));
        }
        self.lifecycle = LocalEd25519YaoRefreshLifecycleV1::OutputCommitted {
            binding: binding.clone(),
        };
        Ok(())
    }

    pub fn mark_worker_activated(
        &mut self,
        binding: &Ed25519YaoRefreshBindingV1,
        refreshed_public_key: [u8; 32],
    ) -> RouterAbProtocolResult<()> {
        let LocalEd25519YaoRefreshLifecycleV1::OutputCommitted { binding: committed } =
            &self.lifecycle
        else {
            return Err(invalid_refresh("refresh output is not committed"));
        };
        if committed != binding || *binding.registered_public_key() != refreshed_public_key {
            return Err(invalid_refresh(
                "refresh result does not preserve its admitted binding and public identity",
            ));
        }
        self.lifecycle = LocalEd25519YaoRefreshLifecycleV1::WorkerActivated {
            binding: binding.clone(),
        };
        Ok(())
    }

    pub fn promote(
        &mut self,
        binding: &Ed25519YaoRefreshBindingV1,
    ) -> RouterAbProtocolResult<LocalEd25519YaoRefreshActiveEpochsV1> {
        let LocalEd25519YaoRefreshLifecycleV1::WorkerActivated { binding: activated } =
            &self.lifecycle
        else {
            return Err(invalid_refresh("refresh worker is not activated"));
        };
        if activated != binding {
            return Err(invalid_refresh("activated refresh binding does not match"));
        }
        let retired = current_refresh_epochs(binding);
        let epochs = next_refresh_epochs(binding);
        self.retired_epochs.insert(retired);
        self.lifecycle = LocalEd25519YaoRefreshLifecycleV1::Active {
            registered_public_key: *binding.registered_public_key(),
            epochs,
        };
        Ok(epochs)
    }

    pub fn is_retired(&self, epochs: LocalEd25519YaoRefreshActiveEpochsV1) -> bool {
        self.retired_epochs.contains(&epochs)
    }
}

fn refresh_stable_identity(
    binding: &Ed25519YaoCeremonyBindingV1,
) -> LocalEd25519YaoRefreshStableIdentityV1 {
    LocalEd25519YaoRefreshStableIdentityV1 {
        stable_key_context_binding: binding.stable_key_context_binding,
        root_share_epoch: binding.lifecycle.root_share_epoch.clone(),
        account_id: binding.lifecycle.account_id.clone(),
        signer_set_id: binding.lifecycle.signer_set_id.clone(),
        signing_worker_id: binding.lifecycle.selected_server_id.clone(),
    }
}

fn refresh_identity_matches(
    active: &LocalEd25519YaoRefreshStableIdentityV1,
    refresh: &Ed25519YaoCeremonyBindingV1,
) -> bool {
    active.stable_key_context_binding == refresh.stable_key_context_binding
        && active.root_share_epoch == refresh.lifecycle.root_share_epoch
        && active.account_id == refresh.lifecycle.account_id
        && active.signer_set_id == refresh.lifecycle.signer_set_id
        && active.signing_worker_id == refresh.lifecycle.selected_server_id
}

fn current_refresh_epochs(
    binding: &Ed25519YaoRefreshBindingV1,
) -> LocalEd25519YaoRefreshActiveEpochsV1 {
    LocalEd25519YaoRefreshActiveEpochsV1 {
        deriver_a: binding.epochs().deriver_a.current(),
        deriver_b: binding.epochs().deriver_b.current(),
        signing_worker: binding.epochs().signing_worker.current(),
    }
}

fn next_refresh_epochs(
    binding: &Ed25519YaoRefreshBindingV1,
) -> LocalEd25519YaoRefreshActiveEpochsV1 {
    LocalEd25519YaoRefreshActiveEpochsV1 {
        deriver_a: binding.epochs().deriver_a.next(),
        deriver_b: binding.epochs().deriver_b.next(),
        signing_worker: binding.epochs().signing_worker.next(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalEd25519YaoRouterRecoveryPromotionReceiptV1 {
    pub binding: Ed25519YaoCeremonyBindingV1,
    pub registered_public_key: [u8; 32],
    pub active_credential: LocalEd25519YaoRecoveryCredentialBindingV1,
    pub retired_credential: LocalEd25519YaoRecoveryCredentialBindingV1,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum LocalEd25519YaoRecoveryLifecycleV1 {
    Active {
        credential: LocalEd25519YaoRecoveryCredentialBindingV1,
        registered_public_key: [u8; 32],
    },
    Suspended {
        binding: Ed25519YaoCeremonyBindingV1,
        active_credential: LocalEd25519YaoRecoveryCredentialBindingV1,
        replacement_credential: LocalEd25519YaoRecoveryCredentialBindingV1,
        registered_public_key: [u8; 32],
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalEd25519YaoRouterRecoveryStateV1 {
    lifecycle: LocalEd25519YaoRecoveryLifecycleV1,
    tombstones: BTreeSet<LocalEd25519YaoRecoveryCredentialBindingV1>,
}

impl LocalEd25519YaoRouterRecoveryStateV1 {
    pub fn new(
        active_credential: LocalEd25519YaoRecoveryCredentialBindingV1,
        registered_public_key: [u8; 32],
    ) -> RouterAbProtocolResult<Self> {
        if registered_public_key.iter().all(|byte| *byte == 0) {
            return Err(invalid_recovery("registered public key must be nonzero"));
        }
        Ok(Self {
            lifecycle: LocalEd25519YaoRecoveryLifecycleV1::Active {
                credential: active_credential,
                registered_public_key,
            },
            tombstones: BTreeSet::new(),
        })
    }

    pub fn begin(
        &mut self,
        request: LocalEd25519YaoRouterRecoveryAdmissionRequestV1,
    ) -> RouterAbProtocolResult<LocalEd25519YaoRouterRecoveryAdmissionV1> {
        let LocalEd25519YaoRouterRecoveryAdmissionRequestV1 {
            scope,
            application_binding,
            participant_ids,
            active_credential,
            replacement_credential,
        } = request;
        let LocalEd25519YaoRecoveryLifecycleV1::Active {
            credential,
            registered_public_key,
        } = &self.lifecycle
        else {
            return Err(invalid_recovery(
                "another recovery credential transition is already suspended",
            ));
        };
        if *credential != active_credential || self.tombstones.contains(&active_credential) {
            return Err(invalid_recovery(
                "recovery credential is not the active credential",
            ));
        }
        if replacement_credential == active_credential
            || self.tombstones.contains(&replacement_credential)
        {
            return Err(invalid_recovery(
                "replacement recovery credential must be fresh",
            ));
        }
        let binding = admitted_binding(
            scope,
            &application_binding,
            participant_ids,
            Ed25519YaoOperationV1::Recovery,
        )?;
        let registered_public_key = *registered_public_key;
        self.lifecycle = LocalEd25519YaoRecoveryLifecycleV1::Suspended {
            binding: binding.clone(),
            active_credential,
            replacement_credential,
            registered_public_key,
        };
        Ok(LocalEd25519YaoRouterRecoveryAdmissionV1 { binding })
    }

    pub fn promote(
        &mut self,
        binding: &Ed25519YaoCeremonyBindingV1,
        recovered_public_key: [u8; 32],
    ) -> RouterAbProtocolResult<LocalEd25519YaoRouterRecoveryPromotionReceiptV1> {
        let LocalEd25519YaoRecoveryLifecycleV1::Suspended {
            binding: suspended_binding,
            active_credential,
            replacement_credential,
            registered_public_key,
        } = &self.lifecycle
        else {
            return Err(invalid_recovery("no recovery transition is suspended"));
        };
        if suspended_binding != binding || *registered_public_key != recovered_public_key {
            return Err(invalid_recovery(
                "recovery result does not preserve its admitted binding and public identity",
            ));
        }
        let retired_credential = *active_credential;
        let active_credential = *replacement_credential;
        let registered_public_key = *registered_public_key;
        self.tombstones.insert(retired_credential);
        self.lifecycle = LocalEd25519YaoRecoveryLifecycleV1::Active {
            credential: active_credential,
            registered_public_key,
        };
        Ok(LocalEd25519YaoRouterRecoveryPromotionReceiptV1 {
            binding: binding.clone(),
            registered_public_key,
            active_credential,
            retired_credential,
        })
    }

    pub fn is_tombstoned(&self, credential: LocalEd25519YaoRecoveryCredentialBindingV1) -> bool {
        self.tombstones.contains(&credential)
    }
}

pub fn admit_local_ed25519_yao_registration_v1(
    request: RouterAbEd25519YaoRegistrationAdmissionRequestV1,
) -> RouterAbProtocolResult<LocalEd25519YaoRouterRegistrationAdmissionV1> {
    let (scope, application_binding, participant_ids) = request.into_parts();
    let binding = admitted_binding(
        scope,
        &application_binding,
        participant_ids,
        Ed25519YaoOperationV1::Registration,
    )?;
    Ok(LocalEd25519YaoRouterRegistrationAdmissionV1 { binding })
}

pub fn admit_local_ed25519_yao_export_v1(
    request: LocalEd25519YaoRouterExportAdmissionRequestV1,
) -> RouterAbProtocolResult<LocalEd25519YaoRouterExportAdmissionV1> {
    let LocalEd25519YaoRouterExportAdmissionRequestV1 {
        scope,
        application_binding,
        participant_ids,
    } = request;
    let binding = admitted_binding(
        scope,
        &application_binding,
        participant_ids,
        Ed25519YaoOperationV1::Export,
    )?;
    Ok(LocalEd25519YaoRouterExportAdmissionV1 { binding })
}

fn admitted_binding(
    scope: RouterAbEd25519YaoLifecycleScopeV1,
    application_binding: &RouterAbEd25519YaoApplicationBindingFactsV1,
    participant_ids: [u16; 2],
    operation: Ed25519YaoOperationV1,
) -> RouterAbProtocolResult<Ed25519YaoCeremonyBindingV1> {
    let context =
        super::local_ed25519_yao_api::stable_context(application_binding, participant_ids)?;
    Ed25519YaoCeremonyBindingV1::new(
        scope.into_lifecycle(operation)?,
        operation,
        Ed25519YaoSessionIdV1::new(fresh_session_id()?)?,
        Ed25519YaoStableKeyContextBindingV1::new(context.binding_digest()),
    )
}

fn fresh_session_id() -> RouterAbProtocolResult<[u8; 32]> {
    loop {
        let mut session = [0_u8; 32];
        getrandom(&mut session).map_err(|error| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                format!("local Router Yao session randomness failed: {error}"),
            )
        })?;
        if session.iter().any(|byte| *byte != 0) {
            return Ok(session);
        }
    }
}

fn invalid_recovery(message: &'static str) -> RouterAbProtocolError {
    RouterAbProtocolError::new(RouterAbProtocolErrorCode::InvalidLifecycleState, message)
}

fn invalid_refresh(message: &'static str) -> RouterAbProtocolError {
    RouterAbProtocolError::new(RouterAbProtocolErrorCode::InvalidLifecycleState, message)
}
