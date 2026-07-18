use std::{
    collections::BTreeMap,
    time::{SystemTime, UNIX_EPOCH},
};

use base64::Engine;
use router_ab_cloudflare::{
    CloudflareSigningWorkerAdmittedNormalSigningFinalizeRequestV2,
    CloudflareSigningWorkerAdmittedNormalSigningPrepareRequestV2,
};
use router_ab_core::{
    ActiveSigningWorkerStateV1, CanonicalWireBytesV1, Ed25519YaoCeremonyBindingV1,
    Ed25519YaoOperationV1, Ed25519YaoRefreshBindingV1, Ed25519YaoStateEpochV1,
    NormalSigningEd25519TwoPartyFrostCommitmentsV1, NormalSigningResponseV1,
    NormalSigningRound1PrepareResponseV1, NormalSigningScopeV1, NormalSigningSignatureSchemeV1,
    PublicDigest32, RouterAbEd25519NormalSigningFinalizeProtocolV2, RouterAbProtocolError,
    RouterAbProtocolErrorCode, RouterAbProtocolResult, ServerIdentityV1,
};
use router_ab_ed25519_yao::recipient::signing_worker::{
    combine_signing_worker_activation_packages, SigningWorkerBaseScalar,
};
use router_ab_ed25519_yao::relay::{
    derive_registration_receipt, ActivationDeriverASigningWorkerPackage,
    ActivationDeriverBSigningWorkerPackage, ActivationPublicCommitments,
};
use serde::{Deserialize, Serialize};
use signer_core::near_threshold_ed25519::{
    aggregate_signature, build_signing_package, client_round1_commit,
    client_round2_signature_share, commitments_from_wire, key_package_from_signing_share_bytes,
    signature_share_from_b64u, verifying_share_bytes_from_signing_share_bytes,
    verifying_share_from_b64u, ClientRound1State, CommitmentsWire,
};
use signer_core::near_threshold_frost::compute_threshold_ed25519_group_public_key_2p_from_verifying_shares;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::{
    local_ed25519_yao_refresh::LocalEd25519YaoEffectiveIdentityV1,
    open_local_ed25519_yao_signing_worker_package_v1, Ed25519YaoDeriverRoleV1,
    Ed25519YaoEncryptedPackageV1, Ed25519YaoPackageKindV1, LocalEd25519YaoRecipientPrivateKeyV1,
    LocalSigningWorkerConfigV1,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalEd25519YaoSigningWorkerPackageDeliveryV1 {
    pub binding: Ed25519YaoCeremonyBindingV1,
    pub client_commitment: [u8; 32],
    pub signing_worker_commitment: [u8; 32],
    pub package: Ed25519YaoEncryptedPackageV1,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalEd25519YaoSigningWorkerRefreshPackageDeliveryV1 {
    pub binding: Ed25519YaoRefreshBindingV1,
    pub client_commitment: [u8; 32],
    pub signing_worker_commitment: [u8; 32],
    pub package: Ed25519YaoEncryptedPackageV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum LocalEd25519YaoSigningWorkerActivationReceiptV1 {
    Pending {
        accepted_deriver: Ed25519YaoDeriverRoleV1,
        session: [u8; 32],
        transcript: [u8; 32],
    },
    Staged {
        promotion: LocalEd25519YaoSigningWorkerRecoveryPromotionRequestV1,
    },
    Active {
        session: [u8; 32],
        transcript: [u8; 32],
        registered_public_key: [u8; 32],
        joined_client_commitment: [u8; 32],
        joined_signing_worker_commitment: [u8; 32],
        signing_worker_verifying_share: [u8; 32],
        state_epoch: Ed25519YaoStateEpochV1,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalEd25519YaoSigningWorkerRecoveryPromotionRequestV1 {
    pub binding: Ed25519YaoCeremonyBindingV1,
    pub session: [u8; 32],
    pub transcript: [u8; 32],
    pub registered_public_key: [u8; 32],
    pub joined_client_commitment: [u8; 32],
    pub joined_signing_worker_commitment: [u8; 32],
    pub signing_worker_verifying_share: [u8; 32],
    pub state_epoch: Ed25519YaoStateEpochV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum LocalEd25519YaoSigningWorkerRefreshReceiptV1 {
    Pending {
        accepted_deriver: Ed25519YaoDeriverRoleV1,
        session: [u8; 32],
        transcript: [u8; 32],
        current_epoch: Ed25519YaoStateEpochV1,
        next_epoch: Ed25519YaoStateEpochV1,
    },
    Active {
        session: [u8; 32],
        transcript: [u8; 32],
        registered_public_key: [u8; 32],
        signing_worker_verifying_share: [u8; 32],
        state_epoch: Ed25519YaoStateEpochV1,
    },
}

#[derive(Clone, PartialEq, Eq)]
struct PendingDelivery {
    binding: Ed25519YaoCeremonyBindingV1,
    client_commitment: [u8; 32],
    signing_worker_commitment: [u8; 32],
    package: Ed25519YaoEncryptedPackageV1,
}

#[derive(Clone)]
struct PendingRefreshDelivery {
    binding: Ed25519YaoRefreshBindingV1,
    client_commitment: [u8; 32],
    signing_worker_commitment: [u8; 32],
    package: Ed25519YaoEncryptedPackageV1,
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct ActiveSigningShare {
    scalar: Zeroizing<[u8; 32]>,
    #[zeroize(skip)]
    binding: Ed25519YaoCeremonyBindingV1,
    #[zeroize(skip)]
    state_epoch: Ed25519YaoStateEpochV1,
    transcript: [u8; 32],
    registered_public_key: [u8; 32],
}

struct ActivationCandidate {
    next_active: ActiveSigningShare,
    promotion: LocalEd25519YaoSigningWorkerRecoveryPromotionRequestV1,
    deriver_a: PendingDelivery,
    deriver_b: PendingDelivery,
}

enum RecoveryPromotionState {
    Staged {
        candidate: ActivationCandidate,
    },
    Promoted {
        promotion: LocalEd25519YaoSigningWorkerRecoveryPromotionRequestV1,
        deriver_a: PendingDelivery,
        deriver_b: PendingDelivery,
    },
}

impl RecoveryPromotionState {
    fn promotion(&self) -> &LocalEd25519YaoSigningWorkerRecoveryPromotionRequestV1 {
        match self {
            Self::Staged { candidate } => &candidate.promotion,
            Self::Promoted { promotion, .. } => promotion,
        }
    }

    fn delivery(&self, deriver: Ed25519YaoDeriverRoleV1) -> &PendingDelivery {
        match (self, deriver) {
            (Self::Staged { candidate }, Ed25519YaoDeriverRoleV1::DeriverA) => &candidate.deriver_a,
            (Self::Staged { candidate }, Ed25519YaoDeriverRoleV1::DeriverB) => &candidate.deriver_b,
            (Self::Promoted { deriver_a, .. }, Ed25519YaoDeriverRoleV1::DeriverA) => deriver_a,
            (Self::Promoted { deriver_b, .. }, Ed25519YaoDeriverRoleV1::DeriverB) => deriver_b,
        }
    }
}

struct PendingNormalSigningRound {
    scope: NormalSigningScopeV1,
    state_epoch: Ed25519YaoStateEpochV1,
    registered_public_key: [u8; 32],
    round1_binding_digest: PublicDigest32,
    intent_digest: PublicDigest32,
    signing_payload_digest: PublicDigest32,
    admitted_signing_digest: PublicDigest32,
    round1: ClientRound1State,
    expires_at_ms: u64,
}

#[derive(Default)]
pub struct LocalEd25519YaoSigningWorkerStateV1 {
    identities: BTreeMap<LocalEd25519YaoEffectiveIdentityV1, LocalEd25519YaoSigningIdentityStateV1>,
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub(crate) struct LocalEd25519YaoSigningWorkerDurableStateV1 {
    active_identities: Vec<LocalEd25519YaoSigningWorkerDurableActiveStateV1>,
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct LocalEd25519YaoSigningWorkerDurableActiveStateV1 {
    scalar: [u8; 32],
    #[zeroize(skip)]
    identity: LocalEd25519YaoEffectiveIdentityV1,
    #[zeroize(skip)]
    binding: Ed25519YaoCeremonyBindingV1,
    #[zeroize(skip)]
    state_epoch: Ed25519YaoStateEpochV1,
    transcript: [u8; 32],
    registered_public_key: [u8; 32],
}

#[derive(Default)]
struct LocalEd25519YaoSigningIdentityStateV1 {
    pending_a: Option<PendingDelivery>,
    pending_b: Option<PendingDelivery>,
    pending_refresh_a: Option<PendingRefreshDelivery>,
    pending_refresh_b: Option<PendingRefreshDelivery>,
    active: Option<ActiveSigningShare>,
    recovery_promotion: Option<RecoveryPromotionState>,
    pending_normal_signing: BTreeMap<String, PendingNormalSigningRound>,
}

impl LocalEd25519YaoSigningWorkerStateV1 {
    pub(crate) fn durable_state_v1(&self) -> LocalEd25519YaoSigningWorkerDurableStateV1 {
        let active_identities = self
            .identities
            .iter()
            .filter_map(|(identity, state)| {
                let active = state.active.as_ref()?;
                Some(LocalEd25519YaoSigningWorkerDurableActiveStateV1 {
                    scalar: *active.scalar,
                    identity: identity.clone(),
                    binding: active.binding.clone(),
                    state_epoch: active.state_epoch,
                    transcript: active.transcript,
                    registered_public_key: active.registered_public_key,
                })
            })
            .collect();
        LocalEd25519YaoSigningWorkerDurableStateV1 { active_identities }
    }

    pub(crate) fn from_durable_state_v1(
        mut state: LocalEd25519YaoSigningWorkerDurableStateV1,
    ) -> RouterAbProtocolResult<Self> {
        let mut identities = BTreeMap::new();
        for mut active in core::mem::take(&mut state.active_identities) {
            active.binding.validate()?;
            active.identity.validate_persisted_v1()?;
            if active.identity != LocalEd25519YaoEffectiveIdentityV1::from_binding(&active.binding)
                || active.scalar.iter().all(|byte| *byte == 0)
                || active.transcript.iter().all(|byte| *byte == 0)
                || active.registered_public_key.iter().all(|byte| *byte == 0)
            {
                return Err(invalid_activation(
                    "persisted SigningWorker active Yao state is invalid",
                ));
            }
            let identity = active.identity.clone();
            let identity_state = LocalEd25519YaoSigningIdentityStateV1 {
                active: Some(ActiveSigningShare {
                    scalar: Zeroizing::new(core::mem::take(&mut active.scalar)),
                    binding: active.binding.clone(),
                    state_epoch: active.state_epoch,
                    transcript: active.transcript,
                    registered_public_key: active.registered_public_key,
                }),
                ..Default::default()
            };
            if identities.insert(identity, identity_state).is_some() {
                return Err(invalid_activation(
                    "persisted SigningWorker state contains a duplicate Yao identity",
                ));
            }
        }
        Ok(Self { identities })
    }

    pub fn accept_deriver_a(
        &mut self,
        config: &LocalSigningWorkerConfigV1,
        request: LocalEd25519YaoSigningWorkerPackageDeliveryV1,
    ) -> RouterAbProtocolResult<LocalEd25519YaoSigningWorkerActivationReceiptV1> {
        let identity = LocalEd25519YaoEffectiveIdentityV1::from_binding(&request.binding);
        self.activation_identity_state_mut(identity, request.binding.operation)?
            .accept_deriver_a(config, request)
    }

    pub fn accept_deriver_b(
        &mut self,
        config: &LocalSigningWorkerConfigV1,
        request: LocalEd25519YaoSigningWorkerPackageDeliveryV1,
    ) -> RouterAbProtocolResult<LocalEd25519YaoSigningWorkerActivationReceiptV1> {
        let identity = LocalEd25519YaoEffectiveIdentityV1::from_binding(&request.binding);
        self.activation_identity_state_mut(identity, request.binding.operation)?
            .accept_deriver_b(config, request)
    }

    pub fn promote_recovery_candidate(
        &mut self,
        request: LocalEd25519YaoSigningWorkerRecoveryPromotionRequestV1,
    ) -> RouterAbProtocolResult<LocalEd25519YaoSigningWorkerActivationReceiptV1> {
        let identity = LocalEd25519YaoEffectiveIdentityV1::from_binding(&request.binding);
        self.identities
            .get_mut(&identity)
            .ok_or_else(|| {
                invalid_activation("SigningWorker has no active state for this recovery identity")
            })?
            .promote_recovery_candidate(request)
    }

    pub fn accept_refresh_deriver_a(
        &mut self,
        config: &LocalSigningWorkerConfigV1,
        request: LocalEd25519YaoSigningWorkerRefreshPackageDeliveryV1,
    ) -> RouterAbProtocolResult<LocalEd25519YaoSigningWorkerRefreshReceiptV1> {
        let identity = LocalEd25519YaoEffectiveIdentityV1::from_binding(request.binding.ceremony());
        self.identities
            .get_mut(&identity)
            .ok_or_else(|| {
                invalid_activation("SigningWorker has no active state for this refresh identity")
            })?
            .accept_refresh_deriver_a(config, request)
    }

    pub fn accept_refresh_deriver_b(
        &mut self,
        config: &LocalSigningWorkerConfigV1,
        request: LocalEd25519YaoSigningWorkerRefreshPackageDeliveryV1,
    ) -> RouterAbProtocolResult<LocalEd25519YaoSigningWorkerRefreshReceiptV1> {
        let identity = LocalEd25519YaoEffectiveIdentityV1::from_binding(request.binding.ceremony());
        self.identities
            .get_mut(&identity)
            .ok_or_else(|| {
                invalid_activation("SigningWorker has no active state for this refresh identity")
            })?
            .accept_refresh_deriver_b(config, request)
    }

    pub fn prepare_normal_signing(
        &mut self,
        config: &LocalSigningWorkerConfigV1,
        body: &[u8],
    ) -> RouterAbProtocolResult<String> {
        let request = serde_json::from_slice::<
            CloudflareSigningWorkerAdmittedNormalSigningPrepareRequestV2,
        >(body)
        .map_err(|_| invalid_normal_signing("SigningWorker prepare request is malformed"))?;
        let identity = self.identity_for_scope(&request.scope)?;
        self.identities
            .get_mut(&identity)
            .expect("normal-signing identity was selected from the same map")
            .prepare_normal_signing(config, body)
    }

    pub fn finalize_normal_signing(
        &mut self,
        config: &LocalSigningWorkerConfigV1,
        body: &[u8],
    ) -> RouterAbProtocolResult<String> {
        let request = serde_json::from_slice::<
            CloudflareSigningWorkerAdmittedNormalSigningFinalizeRequestV2,
        >(body)
        .map_err(|error| {
            invalid_normal_signing(format!(
                "SigningWorker finalize request is malformed: {error}"
            ))
        })?;
        let identity = self.identity_for_scope(&request.request.scope)?;
        self.identities
            .get_mut(&identity)
            .expect("normal-signing identity was selected from the same map")
            .finalize_normal_signing(config, body)
    }

    pub fn active_public_key(&self) -> Option<&[u8; 32]> {
        self.sole_identity_state()?.active_public_key()
    }

    pub fn active_signing_share(&self) -> Option<&[u8; 32]> {
        self.sole_identity_state()?.active_signing_share()
    }

    pub fn active_binding(&self) -> Option<&Ed25519YaoCeremonyBindingV1> {
        self.sole_identity_state()?.active_binding()
    }

    pub fn active_transcript(&self) -> Option<&[u8; 32]> {
        self.sole_identity_state()?.active_transcript()
    }

    pub fn active_state_epoch(&self) -> Option<Ed25519YaoStateEpochV1> {
        self.sole_identity_state()?.active_state_epoch()
    }

    fn activation_identity_state_mut(
        &mut self,
        identity: LocalEd25519YaoEffectiveIdentityV1,
        operation: Ed25519YaoOperationV1,
    ) -> RouterAbProtocolResult<&mut LocalEd25519YaoSigningIdentityStateV1> {
        match operation {
            Ed25519YaoOperationV1::Registration => Ok(self.identities.entry(identity).or_default()),
            Ed25519YaoOperationV1::Recovery => {
                self.identities.get_mut(&identity).ok_or_else(|| {
                    invalid_activation(
                        "SigningWorker recovery requires active state for this identity",
                    )
                })
            }
            Ed25519YaoOperationV1::Refresh | Ed25519YaoOperationV1::Export => Err(
                invalid_activation("SigningWorker activation operation is invalid"),
            ),
        }
    }

    fn identity_for_scope(
        &self,
        scope: &NormalSigningScopeV1,
    ) -> RouterAbProtocolResult<LocalEd25519YaoEffectiveIdentityV1> {
        let mut selected = None;
        for (identity, state) in &self.identities {
            let Some(active) = state.active.as_ref() else {
                continue;
            };
            if active.binding.lifecycle.account_id != scope.account_id
                || active.binding.lifecycle.session_id != scope.session_id
                || active.binding.lifecycle.selected_server_id != scope.signing_worker_id
            {
                continue;
            }
            if selected.is_some() {
                return Err(invalid_normal_signing(
                    "normal-signing scope matches multiple Yao identities",
                ));
            }
            selected = Some(identity.clone());
        }
        selected.ok_or_else(|| {
            invalid_normal_signing("normal-signing scope does not match active Yao lifecycle")
        })
    }

    fn sole_identity_state(&self) -> Option<&LocalEd25519YaoSigningIdentityStateV1> {
        if self.identities.len() != 1 {
            return None;
        }
        self.identities.values().next()
    }
}

impl LocalEd25519YaoSigningIdentityStateV1 {
    pub fn accept_deriver_a(
        &mut self,
        config: &LocalSigningWorkerConfigV1,
        request: LocalEd25519YaoSigningWorkerPackageDeliveryV1,
    ) -> RouterAbProtocolResult<LocalEd25519YaoSigningWorkerActivationReceiptV1> {
        let pending = validate_delivery(Ed25519YaoDeriverRoleV1::DeriverA, request)?;
        if let Some(receipt) =
            self.exact_activation_delivery_retry(Ed25519YaoDeriverRoleV1::DeriverA, &pending)?
        {
            return Ok(receipt);
        }
        self.validate_activation_transition(&pending.binding)?;
        if self.pending_a.is_some() {
            return Err(invalid_activation(
                "Deriver A activation delivery slot is occupied",
            ));
        }
        let receipt = pending_receipt(Ed25519YaoDeriverRoleV1::DeriverA, &pending);
        if let Some(pending_b) = self.pending_b.as_ref() {
            let state_epoch = self.activation_state_epoch(&pending.binding)?;
            let activated = activate(config, pending, pending_b.clone(), state_epoch)?;
            let receipt = self.commit_activation_candidate(activated)?;
            self.pending_b = None;
            return Ok(receipt);
        }
        self.pending_a = Some(pending);
        Ok(receipt)
    }

    pub fn accept_deriver_b(
        &mut self,
        config: &LocalSigningWorkerConfigV1,
        request: LocalEd25519YaoSigningWorkerPackageDeliveryV1,
    ) -> RouterAbProtocolResult<LocalEd25519YaoSigningWorkerActivationReceiptV1> {
        let pending = validate_delivery(Ed25519YaoDeriverRoleV1::DeriverB, request)?;
        if let Some(receipt) =
            self.exact_activation_delivery_retry(Ed25519YaoDeriverRoleV1::DeriverB, &pending)?
        {
            return Ok(receipt);
        }
        self.validate_activation_transition(&pending.binding)?;
        if self.pending_b.is_some() {
            return Err(invalid_activation(
                "Deriver B activation delivery slot is occupied",
            ));
        }
        let receipt = pending_receipt(Ed25519YaoDeriverRoleV1::DeriverB, &pending);
        if let Some(pending_a) = self.pending_a.as_ref() {
            let state_epoch = self.activation_state_epoch(&pending.binding)?;
            let activated = activate(config, pending_a.clone(), pending, state_epoch)?;
            let receipt = self.commit_activation_candidate(activated)?;
            self.pending_a = None;
            return Ok(receipt);
        }
        self.pending_b = Some(pending);
        Ok(receipt)
    }

    pub fn promote_recovery_candidate(
        &mut self,
        request: LocalEd25519YaoSigningWorkerRecoveryPromotionRequestV1,
    ) -> RouterAbProtocolResult<LocalEd25519YaoSigningWorkerActivationReceiptV1> {
        validate_recovery_promotion_request(&request)?;
        let promotion_state = self
            .recovery_promotion
            .as_ref()
            .ok_or_else(|| invalid_activation("SigningWorker has no staged recovery candidate"))?;
        if promotion_state.promotion() != &request {
            return Err(invalid_activation(
                "recovery promotion does not match the staged candidate",
            ));
        }
        if matches!(promotion_state, RecoveryPromotionState::Promoted { .. }) {
            return Ok(active_activation_receipt(&request));
        }
        let RecoveryPromotionState::Staged { candidate } = promotion_state else {
            unreachable!();
        };
        self.validate_recovery_candidate(&candidate.next_active)?;
        let RecoveryPromotionState::Staged { candidate } = self
            .recovery_promotion
            .take()
            .expect("recovery promotion state was checked above")
        else {
            unreachable!();
        };
        let ActivationCandidate {
            next_active,
            promotion,
            deriver_a,
            deriver_b,
        } = candidate;
        self.active = Some(next_active);
        self.recovery_promotion = Some(RecoveryPromotionState::Promoted {
            promotion,
            deriver_a,
            deriver_b,
        });
        Ok(active_activation_receipt(&request))
    }

    pub fn accept_refresh_deriver_a(
        &mut self,
        config: &LocalSigningWorkerConfigV1,
        request: LocalEd25519YaoSigningWorkerRefreshPackageDeliveryV1,
    ) -> RouterAbProtocolResult<LocalEd25519YaoSigningWorkerRefreshReceiptV1> {
        self.validate_refresh_transition(&request.binding)?;
        let pending = validate_refresh_delivery(Ed25519YaoDeriverRoleV1::DeriverA, request)?;
        if self.pending_refresh_a.is_some() {
            return Err(invalid_activation(
                "Deriver A refresh delivery slot is occupied",
            ));
        }
        let receipt = pending_refresh_receipt(Ed25519YaoDeriverRoleV1::DeriverA, &pending);
        if let Some(pending_b) = self.pending_refresh_b.as_ref() {
            let activated = activate_refresh(config, pending, pending_b.clone())?;
            let receipt = self.commit_refresh_candidate(activated)?;
            self.pending_refresh_b = None;
            return Ok(receipt);
        }
        self.pending_refresh_a = Some(pending);
        Ok(receipt)
    }

    pub fn accept_refresh_deriver_b(
        &mut self,
        config: &LocalSigningWorkerConfigV1,
        request: LocalEd25519YaoSigningWorkerRefreshPackageDeliveryV1,
    ) -> RouterAbProtocolResult<LocalEd25519YaoSigningWorkerRefreshReceiptV1> {
        self.validate_refresh_transition(&request.binding)?;
        let pending = validate_refresh_delivery(Ed25519YaoDeriverRoleV1::DeriverB, request)?;
        if self.pending_refresh_b.is_some() {
            return Err(invalid_activation(
                "Deriver B refresh delivery slot is occupied",
            ));
        }
        let receipt = pending_refresh_receipt(Ed25519YaoDeriverRoleV1::DeriverB, &pending);
        if let Some(pending_a) = self.pending_refresh_a.as_ref() {
            let activated = activate_refresh(config, pending_a.clone(), pending)?;
            let receipt = self.commit_refresh_candidate(activated)?;
            self.pending_refresh_a = None;
            return Ok(receipt);
        }
        self.pending_refresh_b = Some(pending);
        Ok(receipt)
    }

    pub fn active_public_key(&self) -> Option<&[u8; 32]> {
        self.active
            .as_ref()
            .map(|active| &active.registered_public_key)
    }

    pub fn active_signing_share(&self) -> Option<&[u8; 32]> {
        self.active.as_ref().map(|active| &*active.scalar)
    }

    pub fn active_binding(&self) -> Option<&Ed25519YaoCeremonyBindingV1> {
        self.active.as_ref().map(|active| &active.binding)
    }

    pub fn active_transcript(&self) -> Option<&[u8; 32]> {
        self.active.as_ref().map(|active| &active.transcript)
    }

    pub fn active_state_epoch(&self) -> Option<Ed25519YaoStateEpochV1> {
        self.active.as_ref().map(|active| active.state_epoch)
    }

    pub fn prepare_normal_signing(
        &mut self,
        config: &LocalSigningWorkerConfigV1,
        body: &[u8],
    ) -> RouterAbProtocolResult<String> {
        let private_request = serde_json::from_slice::<
            CloudflareSigningWorkerAdmittedNormalSigningPrepareRequestV2,
        >(body)
        .map_err(|_| invalid_normal_signing("SigningWorker prepare request is malformed"))?;
        private_request.validate()?;
        let request_scope = private_request.scope;
        let request_expires_at_ms = private_request.expires_at_ms;
        let admission = private_request.admission_candidate;
        let round1_binding_digest = admission.round1_binding_digest.ok_or_else(|| {
            invalid_normal_signing("SigningWorker prepare request lacks round-1 binding")
        })?;
        let prepared_at_ms = now_unix_ms()?;
        if prepared_at_ms >= request_expires_at_ms {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ExpiredLocalRequest,
                "SigningWorker prepare request expired",
            ));
        }
        let active_state =
            self.active_normal_signing_state(config, &request_scope, prepared_at_ms)?;
        let active = self.active.as_ref().ok_or_else(|| {
            invalid_normal_signing("SigningWorker has no active Yao signing share")
        })?;
        let signing_worker_identifier = frost_ed25519::Identifier::try_from(2_u16)
            .map_err(|_| invalid_normal_signing("SigningWorker FROST identifier is invalid"))?;
        let mut key_package = key_package_from_signing_share_bytes(
            &active.scalar,
            &active.registered_public_key,
            signing_worker_identifier,
        )
        .map_err(map_signer_error)?;
        let round1 = client_round1_commit(&key_package).map_err(map_signer_error)?;
        key_package.zeroize();
        let mut handle_random = [0_u8; 16];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut handle_random);
        let server_round1_handle = format!(
            "yao-server-round1/{}/{}",
            request_scope.request_id,
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(handle_random)
        );
        let server_commitments = normal_signing_commitments(&round1.commitments_wire)?;
        let server_verifying_share = verifying_share_bytes_from_signing_share_bytes(&active.scalar);
        let record = PendingNormalSigningRound {
            scope: request_scope.clone(),
            state_epoch: active.state_epoch,
            registered_public_key: active.registered_public_key,
            round1_binding_digest,
            intent_digest: admission.intent_digest,
            signing_payload_digest: admission.signing_payload_digest,
            admitted_signing_digest: admission.admitted_signing_digest,
            round1,
            expires_at_ms: request_expires_at_ms,
        };
        if self
            .pending_normal_signing
            .insert(server_round1_handle.clone(), record)
            .is_some()
        {
            return Err(invalid_normal_signing(
                "SigningWorker round-one handle collision",
            ));
        }
        let response = NormalSigningRound1PrepareResponseV1::new(
            request_scope,
            admission.signing_payload_digest,
            round1_binding_digest,
            active_state.signing_worker,
            server_round1_handle,
            server_commitments,
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(server_verifying_share),
            NormalSigningSignatureSchemeV1::Ed25519V1,
            prepared_at_ms,
            request_expires_at_ms,
        )?;
        serde_json::to_string(&response)
            .map_err(|_| invalid_normal_signing("SigningWorker prepare response encoding failed"))
    }

    pub fn finalize_normal_signing(
        &mut self,
        config: &LocalSigningWorkerConfigV1,
        body: &[u8],
    ) -> RouterAbProtocolResult<String> {
        let private_request = serde_json::from_slice::<
            CloudflareSigningWorkerAdmittedNormalSigningFinalizeRequestV2,
        >(body)
        .map_err(|error| {
            invalid_normal_signing(format!(
                "SigningWorker finalize request is malformed: {error}"
            ))
        })?;
        private_request.validate()?;
        let request = private_request.request;
        let signed_at_ms = now_unix_ms()?;
        let active_state =
            self.active_normal_signing_state(config, &request.scope, signed_at_ms)?;
        let mut record = self
            .pending_normal_signing
            .remove(request.server_round1_handle())
            .ok_or_else(|| {
                invalid_normal_signing("SigningWorker round-one state is unavailable")
            })?;
        if signed_at_ms >= record.expires_at_ms {
            record.round1.nonces.zeroize();
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ExpiredLocalRequest,
                "SigningWorker round-one state expired",
            ));
        }
        let active = self.active.as_ref().ok_or_else(|| {
            invalid_normal_signing("SigningWorker has no active Yao signing share")
        })?;
        if record.scope != request.scope
            || record.state_epoch != active.state_epoch
            || record.registered_public_key != active.registered_public_key
            || record.round1_binding_digest != request.round1_binding_digest()
            || record.intent_digest != request.intent_digest()
            || record.signing_payload_digest != request.signing_payload_digest()
            || record.expires_at_ms != request.expires_at_ms
        {
            record.round1.nonces.zeroize();
            return Err(invalid_normal_signing(
                "SigningWorker finalize request does not match prepared state",
            ));
        }
        let RouterAbEd25519NormalSigningFinalizeProtocolV2::Ed25519TwoPartyFrostFinalizeV1(
            protocol,
        ) = &request.protocol;
        let server_commitments_wire = signer_commitments(&protocol.server_commitments);
        if server_commitments_wire.hiding != record.round1.commitments_wire.hiding
            || server_commitments_wire.binding != record.round1.commitments_wire.binding
        {
            record.round1.nonces.zeroize();
            return Err(invalid_normal_signing(
                "SigningWorker commitments do not match prepared state",
            ));
        }
        let expected_server_verifying_share =
            verifying_share_bytes_from_signing_share_bytes(&active.scalar);
        let supplied_server_verifying_share = decode_b64u_32(
            &protocol.server_verifying_share_b64u,
            "SigningWorker verifying share",
        )?;
        let client_verifying_share = decode_b64u_32(
            &protocol.client_verifying_share_b64u,
            "Client verifying share",
        )?;
        let computed_public_key =
            compute_threshold_ed25519_group_public_key_2p_from_verifying_shares(
                &client_verifying_share,
                &supplied_server_verifying_share,
                1,
                2,
            )
            .map_err(map_signer_error)?;
        let public_relation_valid = supplied_server_verifying_share
            .ct_eq(&expected_server_verifying_share)
            & computed_public_key.ct_eq(&active.registered_public_key);
        if !bool::from(public_relation_valid) {
            record.round1.nonces.zeroize();
            return Err(invalid_normal_signing(
                "FROST verifying shares do not match the active Yao public key",
            ));
        }
        let client_identifier = frost_ed25519::Identifier::try_from(1_u16)
            .map_err(|_| invalid_normal_signing("Client FROST identifier is invalid"))?;
        let signing_worker_identifier = frost_ed25519::Identifier::try_from(2_u16)
            .map_err(|_| invalid_normal_signing("SigningWorker FROST identifier is invalid"))?;
        let client_commitments =
            commitments_from_wire(&signer_commitments(&protocol.client_commitments))
                .map_err(map_signer_error)?;
        let signing_package = build_signing_package(
            record.admitted_signing_digest.as_bytes(),
            BTreeMap::from([
                (client_identifier, client_commitments),
                (signing_worker_identifier, record.round1.commitments),
            ]),
        );
        let mut key_package = key_package_from_signing_share_bytes(
            &active.scalar,
            &active.registered_public_key,
            signing_worker_identifier,
        )
        .map_err(map_signer_error)?;
        let signing_worker_signature_share =
            client_round2_signature_share(&signing_package, &record.round1.nonces, &key_package)
                .map_err(map_signer_error)?;
        record.round1.nonces.zeroize();
        key_package.zeroize();
        let verifying_key = frost_ed25519::VerifyingKey::deserialize(&active.registered_public_key)
            .map_err(|_| invalid_normal_signing("registered Ed25519 public key is invalid"))?;
        let signature = aggregate_signature(
            &signing_package,
            verifying_key,
            BTreeMap::from([
                (
                    client_identifier,
                    verifying_share_from_b64u(&protocol.client_verifying_share_b64u)
                        .map_err(map_signer_error)?,
                ),
                (
                    signing_worker_identifier,
                    verifying_share_from_b64u(&protocol.server_verifying_share_b64u)
                        .map_err(map_signer_error)?,
                ),
            ]),
            BTreeMap::from([
                (
                    client_identifier,
                    signature_share_from_b64u(&protocol.client_signature_share_b64u)
                        .map_err(map_signer_error)?,
                ),
                (signing_worker_identifier, signing_worker_signature_share),
            ]),
        )
        .map_err(map_signer_error)?;
        let response = NormalSigningResponseV1::new(
            request.scope.clone(),
            request.signing_payload_digest(),
            active_state.signing_worker,
            request.protocol.signature_scheme(),
            CanonicalWireBytesV1::new(signature.to_vec())?,
            signed_at_ms,
        )?;
        response.validate_for_v2_finalize_request(&request)?;
        serde_json::to_string(&response)
            .map_err(|_| invalid_normal_signing("SigningWorker response encoding failed"))
    }

    fn active_normal_signing_state(
        &self,
        config: &LocalSigningWorkerConfigV1,
        scope: &NormalSigningScopeV1,
        now_ms: u64,
    ) -> RouterAbProtocolResult<ActiveSigningWorkerStateV1> {
        let active = self.active.as_ref().ok_or_else(|| {
            invalid_normal_signing("SigningWorker has no active Yao signing share")
        })?;
        if active.binding.lifecycle.account_id != scope.account_id
            || active.binding.lifecycle.session_id != scope.session_id
            || active.binding.lifecycle.selected_server_id != scope.signing_worker_id
        {
            return Err(invalid_normal_signing(
                "normal-signing scope does not match active Yao lifecycle",
            ));
        }
        let public_key = format!(
            "ed25519:{}",
            bs58::encode(active.registered_public_key).into_string()
        );
        let state = ActiveSigningWorkerStateV1::new(
            scope.account_id.clone(),
            scope.session_id.clone(),
            public_key,
            ServerIdentityV1::new(
                config.signing_worker_id.clone(),
                config.signing_worker_key_epoch.clone(),
                config.server_output_hpke_public_key.clone(),
            )?,
            PublicDigest32::new(active.transcript),
            PublicDigest32::new(active.registered_public_key),
            format!(
                "ed25519-yao/{}/{}",
                active.binding.lifecycle.lifecycle_id,
                active.state_epoch.get()
            ),
            now_ms,
        )?;
        state.validate_for_scope(scope)?;
        Ok(state)
    }

    fn commit_activation_candidate(
        &mut self,
        candidate: ActivationCandidate,
    ) -> RouterAbProtocolResult<LocalEd25519YaoSigningWorkerActivationReceiptV1> {
        validate_activation_candidate(&candidate)?;
        match candidate.next_active.binding.operation {
            Ed25519YaoOperationV1::Registration => {
                if self.active.is_some()
                    || candidate.next_active.state_epoch != Ed25519YaoStateEpochV1::new(1)?
                {
                    return Err(invalid_activation(
                        "registration activation requires an empty state at epoch one",
                    ));
                }
                let receipt = active_activation_receipt(&candidate.promotion);
                self.active = Some(candidate.next_active);
                Ok(receipt)
            }
            Ed25519YaoOperationV1::Recovery => {
                if matches!(
                    self.recovery_promotion,
                    Some(RecoveryPromotionState::Staged { .. })
                ) {
                    return Err(invalid_activation(
                        "SigningWorker recovery promotion is pending",
                    ));
                }
                self.validate_recovery_candidate(&candidate.next_active)?;
                let receipt = LocalEd25519YaoSigningWorkerActivationReceiptV1::Staged {
                    promotion: candidate.promotion.clone(),
                };
                self.recovery_promotion = Some(RecoveryPromotionState::Staged { candidate });
                Ok(receipt)
            }
            _ => Err(invalid_activation(
                "SigningWorker activation candidate operation is invalid",
            )),
        }
    }

    fn commit_refresh_candidate(
        &mut self,
        candidate: (
            ActiveSigningShare,
            LocalEd25519YaoSigningWorkerRefreshReceiptV1,
        ),
    ) -> RouterAbProtocolResult<LocalEd25519YaoSigningWorkerRefreshReceiptV1> {
        if matches!(
            self.recovery_promotion,
            Some(RecoveryPromotionState::Staged { .. })
        ) {
            return Err(invalid_activation(
                "SigningWorker recovery promotion is pending",
            ));
        }
        let (next_active, receipt) = candidate;
        let current = self
            .active
            .as_ref()
            .ok_or_else(|| invalid_activation("refresh requires an active Yao signing share"))?;
        if next_active.registered_public_key != current.registered_public_key
            || next_active.state_epoch <= current.state_epoch
        {
            return Err(invalid_activation(
                "refresh candidate did not preserve the active public identity and advance epoch",
            ));
        }
        self.active = Some(next_active);
        Ok(receipt)
    }

    fn validate_activation_transition(
        &self,
        binding: &Ed25519YaoCeremonyBindingV1,
    ) -> RouterAbProtocolResult<()> {
        if matches!(
            self.recovery_promotion,
            Some(RecoveryPromotionState::Staged { .. })
        ) {
            return Err(invalid_activation(
                "SigningWorker recovery promotion is pending",
            ));
        }
        if self.pending_refresh_a.is_some() || self.pending_refresh_b.is_some() {
            return Err(invalid_activation(
                "SigningWorker refresh package delivery is in progress",
            ));
        }
        match (&self.active, binding.operation) {
            (None, Ed25519YaoOperationV1::Registration) => Ok(()),
            (Some(active), Ed25519YaoOperationV1::Recovery)
                if same_signing_identity(&active.binding, binding) =>
            {
                Ok(())
            }
            (None, Ed25519YaoOperationV1::Recovery) => Err(invalid_activation(
                "recovery requires an active Yao signing share",
            )),
            (Some(_), Ed25519YaoOperationV1::Registration) => Err(invalid_activation(
                "SigningWorker already has an active Yao signing share",
            )),
            _ => Err(invalid_activation(
                "SigningWorker activation transition is invalid",
            )),
        }
    }

    fn validate_refresh_transition(
        &self,
        binding: &Ed25519YaoRefreshBindingV1,
    ) -> RouterAbProtocolResult<()> {
        binding.ceremony().validate()?;
        if matches!(
            self.recovery_promotion,
            Some(RecoveryPromotionState::Staged { .. })
        ) {
            return Err(invalid_activation(
                "SigningWorker recovery promotion is pending",
            ));
        }
        if self.pending_a.is_some() || self.pending_b.is_some() {
            return Err(invalid_activation(
                "SigningWorker activation package delivery is in progress",
            ));
        }
        let active = self
            .active
            .as_ref()
            .ok_or_else(|| invalid_activation("refresh requires an active Yao signing share"))?;
        let transition = binding.epochs().signing_worker;
        if !same_signing_identity(&active.binding, binding.ceremony())
            || binding.registered_public_key() != &active.registered_public_key
            || transition.current() != active.state_epoch
        {
            return Err(invalid_activation(
                "refresh binding does not match the active SigningWorker state",
            ));
        }
        Ok(())
    }

    fn activation_state_epoch(
        &self,
        binding: &Ed25519YaoCeremonyBindingV1,
    ) -> RouterAbProtocolResult<Ed25519YaoStateEpochV1> {
        match binding.operation {
            Ed25519YaoOperationV1::Registration => Ed25519YaoStateEpochV1::new(1),
            Ed25519YaoOperationV1::Recovery => self.next_recovery_state_epoch(),
            _ => Err(invalid_activation(
                "SigningWorker activation operation is invalid",
            )),
        }
    }

    fn next_recovery_state_epoch(&self) -> RouterAbProtocolResult<Ed25519YaoStateEpochV1> {
        let current = self
            .active
            .as_ref()
            .ok_or_else(|| invalid_activation("recovery requires an active Yao signing share"))?;
        let next =
            current.state_epoch.get().checked_add(1).ok_or_else(|| {
                invalid_activation("SigningWorker recovery state epoch is exhausted")
            })?;
        Ed25519YaoStateEpochV1::new(next)
    }

    fn validate_recovery_candidate(
        &self,
        candidate: &ActiveSigningShare,
    ) -> RouterAbProtocolResult<()> {
        let current = self
            .active
            .as_ref()
            .ok_or_else(|| invalid_activation("recovery requires an active Yao signing share"))?;
        if candidate.binding.operation != Ed25519YaoOperationV1::Recovery
            || !same_signing_identity(&current.binding, &candidate.binding)
            || candidate.registered_public_key != current.registered_public_key
            || candidate.state_epoch != self.next_recovery_state_epoch()?
        {
            return Err(invalid_activation(
                "recovery candidate does not preserve the public identity at the exact next epoch",
            ));
        }
        Ok(())
    }

    fn exact_activation_delivery_retry(
        &self,
        deriver: Ed25519YaoDeriverRoleV1,
        delivery: &PendingDelivery,
    ) -> RouterAbProtocolResult<Option<LocalEd25519YaoSigningWorkerActivationReceiptV1>> {
        let pending = match deriver {
            Ed25519YaoDeriverRoleV1::DeriverA => self.pending_a.as_ref(),
            Ed25519YaoDeriverRoleV1::DeriverB => self.pending_b.as_ref(),
        };
        if let Some(pending) = pending {
            if pending == delivery {
                return Ok(Some(pending_receipt(deriver, delivery)));
            }
            let message = match deriver {
                Ed25519YaoDeriverRoleV1::DeriverA => {
                    "Deriver A activation delivery slot is occupied"
                }
                Ed25519YaoDeriverRoleV1::DeriverB => {
                    "Deriver B activation delivery slot is occupied"
                }
            };
            return Err(invalid_activation(message));
        }
        let Some(promotion_state) = self.recovery_promotion.as_ref() else {
            return Ok(None);
        };
        if promotion_state.delivery(deriver) == delivery {
            let receipt = match promotion_state {
                RecoveryPromotionState::Staged { .. } => {
                    LocalEd25519YaoSigningWorkerActivationReceiptV1::Staged {
                        promotion: promotion_state.promotion().clone(),
                    }
                }
                RecoveryPromotionState::Promoted { .. } => {
                    active_activation_receipt(promotion_state.promotion())
                }
            };
            return Ok(Some(receipt));
        }
        if matches!(promotion_state, RecoveryPromotionState::Staged { .. }) {
            return Err(invalid_activation(
                "activation delivery does not match the staged recovery candidate",
            ));
        }
        Ok(None)
    }
}

fn same_signing_identity(
    active: &Ed25519YaoCeremonyBindingV1,
    recovery: &Ed25519YaoCeremonyBindingV1,
) -> bool {
    active.stable_key_context_binding == recovery.stable_key_context_binding
        && active.lifecycle.root_share_epoch == recovery.lifecycle.root_share_epoch
        && active.lifecycle.account_id == recovery.lifecycle.account_id
        && active.lifecycle.signer_set_id == recovery.lifecycle.signer_set_id
        && active.lifecycle.selected_server_id == recovery.lifecycle.selected_server_id
}

fn validate_delivery(
    expected_deriver: Ed25519YaoDeriverRoleV1,
    request: LocalEd25519YaoSigningWorkerPackageDeliveryV1,
) -> RouterAbProtocolResult<PendingDelivery> {
    request.binding.validate()?;
    if !matches!(
        request.binding.operation,
        Ed25519YaoOperationV1::Registration | Ed25519YaoOperationV1::Recovery
    ) {
        return Err(invalid_activation(
            "SigningWorker activation requires registration or recovery",
        ));
    }
    request.package.validate()?;
    if request.package.kind() != Ed25519YaoPackageKindV1::ActivationSigningWorker
        || request.package.deriver() != expected_deriver
        || request.package.session() != request.binding.session_id.into_bytes()
    {
        return Err(invalid_activation(
            "SigningWorker package role, family, or session is invalid",
        ));
    }
    Ok(PendingDelivery {
        binding: request.binding,
        client_commitment: request.client_commitment,
        signing_worker_commitment: request.signing_worker_commitment,
        package: request.package,
    })
}

fn validate_refresh_delivery(
    expected_deriver: Ed25519YaoDeriverRoleV1,
    request: LocalEd25519YaoSigningWorkerRefreshPackageDeliveryV1,
) -> RouterAbProtocolResult<PendingRefreshDelivery> {
    request.binding.ceremony().validate()?;
    request.package.validate()?;
    if request.package.kind() != Ed25519YaoPackageKindV1::ActivationSigningWorker
        || request.package.deriver() != expected_deriver
        || request.package.session() != request.binding.ceremony().session_id.into_bytes()
    {
        return Err(invalid_activation(
            "SigningWorker refresh package role, family, or session is invalid",
        ));
    }
    Ok(PendingRefreshDelivery {
        binding: request.binding,
        client_commitment: request.client_commitment,
        signing_worker_commitment: request.signing_worker_commitment,
        package: request.package,
    })
}

fn pending_receipt(
    accepted_deriver: Ed25519YaoDeriverRoleV1,
    pending: &PendingDelivery,
) -> LocalEd25519YaoSigningWorkerActivationReceiptV1 {
    LocalEd25519YaoSigningWorkerActivationReceiptV1::Pending {
        accepted_deriver,
        session: pending.package.session(),
        transcript: pending.package.transcript(),
    }
}

fn pending_refresh_receipt(
    accepted_deriver: Ed25519YaoDeriverRoleV1,
    pending: &PendingRefreshDelivery,
) -> LocalEd25519YaoSigningWorkerRefreshReceiptV1 {
    let transition = pending.binding.epochs().signing_worker;
    LocalEd25519YaoSigningWorkerRefreshReceiptV1::Pending {
        accepted_deriver,
        session: pending.package.session(),
        transcript: pending.package.transcript(),
        current_epoch: transition.current(),
        next_epoch: transition.next(),
    }
}

fn activate(
    config: &LocalSigningWorkerConfigV1,
    a: PendingDelivery,
    b: PendingDelivery,
    state_epoch: Ed25519YaoStateEpochV1,
) -> RouterAbProtocolResult<ActivationCandidate> {
    if a.binding != b.binding || a.package.transcript() != b.package.transcript() {
        return Err(invalid_activation(
            "SigningWorker activation package bindings do not match",
        ));
    }
    let private_key = parse_private_key(&config.server_output_hpke_private_key)?;
    let mut a_plaintext =
        open_local_ed25519_yao_signing_worker_package_v1(&a.package, &private_key)?;
    let mut b_plaintext =
        open_local_ed25519_yao_signing_worker_package_v1(&b.package, &private_key)?;
    let a_package =
        ActivationDeriverASigningWorkerPackage::from_bytes(core::mem::take(&mut *a_plaintext))
            .map_err(map_role_error)?;
    let b_package =
        ActivationDeriverBSigningWorkerPackage::from_bytes(core::mem::take(&mut *b_plaintext))
            .map_err(map_role_error)?;
    let session = a.binding.session_id.into_bytes();
    let transcript = a.package.transcript();
    let scalar =
        combine_signing_worker_activation_packages(session, transcript, a_package, b_package)
            .map_err(map_role_error)?;
    let scalar = signing_scalar(scalar);
    let commitments = ActivationPublicCommitments::new(
        a.client_commitment,
        b.client_commitment,
        a.signing_worker_commitment,
        b.signing_worker_commitment,
    );
    let public_receipt = derive_registration_receipt(commitments).map_err(map_role_error)?;
    let signing_worker_verifying_share = verifying_share_bytes_from_signing_share_bytes(&scalar);
    if &signing_worker_verifying_share != public_receipt.joined_signing_worker_commitment() {
        return Err(invalid_activation(
            "SigningWorker share does not match the public activation commitment",
        ));
    }
    let registered_public_key = *public_receipt.registered_public_key();
    let binding = a.binding.clone();
    let next_active = ActiveSigningShare {
        scalar,
        binding: binding.clone(),
        state_epoch,
        transcript,
        registered_public_key,
    };
    let promotion = LocalEd25519YaoSigningWorkerRecoveryPromotionRequestV1 {
        binding,
        session,
        transcript,
        registered_public_key,
        joined_client_commitment: *public_receipt.joined_client_commitment(),
        joined_signing_worker_commitment: *public_receipt.joined_signing_worker_commitment(),
        signing_worker_verifying_share,
        state_epoch,
    };
    Ok(ActivationCandidate {
        next_active,
        promotion,
        deriver_a: a,
        deriver_b: b,
    })
}

fn active_activation_receipt(
    promotion: &LocalEd25519YaoSigningWorkerRecoveryPromotionRequestV1,
) -> LocalEd25519YaoSigningWorkerActivationReceiptV1 {
    LocalEd25519YaoSigningWorkerActivationReceiptV1::Active {
        session: promotion.session,
        transcript: promotion.transcript,
        registered_public_key: promotion.registered_public_key,
        joined_client_commitment: promotion.joined_client_commitment,
        joined_signing_worker_commitment: promotion.joined_signing_worker_commitment,
        signing_worker_verifying_share: promotion.signing_worker_verifying_share,
        state_epoch: promotion.state_epoch,
    }
}

fn validate_activation_candidate(candidate: &ActivationCandidate) -> RouterAbProtocolResult<()> {
    let active = &candidate.next_active;
    let promotion = &candidate.promotion;
    if promotion.binding != active.binding
        || promotion.session != active.binding.session_id.into_bytes()
        || promotion.transcript != active.transcript
        || promotion.registered_public_key != active.registered_public_key
        || promotion.state_epoch != active.state_epoch
        || promotion.joined_signing_worker_commitment != promotion.signing_worker_verifying_share
        || candidate.deriver_a.binding != active.binding
        || candidate.deriver_b.binding != active.binding
    {
        return Err(invalid_activation(
            "SigningWorker activation candidate metadata is inconsistent",
        ));
    }
    Ok(())
}

fn validate_recovery_promotion_request(
    request: &LocalEd25519YaoSigningWorkerRecoveryPromotionRequestV1,
) -> RouterAbProtocolResult<()> {
    request.binding.validate()?;
    if request.binding.operation != Ed25519YaoOperationV1::Recovery
        || request.session != request.binding.session_id.into_bytes()
        || request.transcript.iter().all(|byte| *byte == 0)
        || request.registered_public_key.iter().all(|byte| *byte == 0)
        || request
            .joined_client_commitment
            .iter()
            .all(|byte| *byte == 0)
        || request
            .joined_signing_worker_commitment
            .iter()
            .all(|byte| *byte == 0)
        || request
            .signing_worker_verifying_share
            .iter()
            .all(|byte| *byte == 0)
        || request.joined_signing_worker_commitment != request.signing_worker_verifying_share
    {
        return Err(invalid_activation(
            "SigningWorker recovery promotion request is invalid",
        ));
    }
    Ok(())
}

fn activate_refresh(
    config: &LocalSigningWorkerConfigV1,
    a: PendingRefreshDelivery,
    b: PendingRefreshDelivery,
) -> RouterAbProtocolResult<(
    ActiveSigningShare,
    LocalEd25519YaoSigningWorkerRefreshReceiptV1,
)> {
    if a.binding != b.binding || a.package.transcript() != b.package.transcript() {
        return Err(invalid_activation(
            "SigningWorker refresh package bindings do not match",
        ));
    }
    let private_key = parse_private_key(&config.server_output_hpke_private_key)?;
    let mut a_plaintext =
        open_local_ed25519_yao_signing_worker_package_v1(&a.package, &private_key)?;
    let mut b_plaintext =
        open_local_ed25519_yao_signing_worker_package_v1(&b.package, &private_key)?;
    let a_package =
        ActivationDeriverASigningWorkerPackage::from_bytes(core::mem::take(&mut *a_plaintext))
            .map_err(map_role_error)?;
    let b_package =
        ActivationDeriverBSigningWorkerPackage::from_bytes(core::mem::take(&mut *b_plaintext))
            .map_err(map_role_error)?;
    let session = a.binding.ceremony().session_id.into_bytes();
    let transcript = a.package.transcript();
    let scalar =
        combine_signing_worker_activation_packages(session, transcript, a_package, b_package)
            .map_err(map_role_error)?;
    let scalar = signing_scalar(scalar);
    let commitments = ActivationPublicCommitments::new(
        a.client_commitment,
        b.client_commitment,
        a.signing_worker_commitment,
        b.signing_worker_commitment,
    );
    let public_receipt = derive_registration_receipt(commitments).map_err(map_role_error)?;
    let signing_worker_verifying_share = verifying_share_bytes_from_signing_share_bytes(&scalar);
    if &signing_worker_verifying_share != public_receipt.joined_signing_worker_commitment()
        || public_receipt.registered_public_key() != a.binding.registered_public_key()
    {
        return Err(invalid_activation(
            "SigningWorker refresh did not preserve the admitted public identity",
        ));
    }
    let registered_public_key = *public_receipt.registered_public_key();
    let state_epoch = a.binding.epochs().signing_worker.next();
    let active = ActiveSigningShare {
        scalar,
        binding: a.binding.ceremony().clone(),
        state_epoch,
        transcript,
        registered_public_key,
    };
    let receipt = LocalEd25519YaoSigningWorkerRefreshReceiptV1::Active {
        session,
        transcript,
        registered_public_key,
        signing_worker_verifying_share,
        state_epoch,
    };
    Ok((active, receipt))
}

fn signing_scalar(value: SigningWorkerBaseScalar) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(value.into_bytes())
}

fn normal_signing_commitments(
    commitments: &CommitmentsWire,
) -> RouterAbProtocolResult<NormalSigningEd25519TwoPartyFrostCommitmentsV1> {
    NormalSigningEd25519TwoPartyFrostCommitmentsV1::new(
        commitments.hiding.clone(),
        commitments.binding.clone(),
    )
}

fn signer_commitments(
    commitments: &NormalSigningEd25519TwoPartyFrostCommitmentsV1,
) -> CommitmentsWire {
    CommitmentsWire {
        hiding: commitments.hiding.clone(),
        binding: commitments.binding.clone(),
    }
}

fn decode_b64u_32(value: &str, label: &'static str) -> RouterAbProtocolResult<[u8; 32]> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| invalid_normal_signing(label))?;
    bytes.try_into().map_err(|_| invalid_normal_signing(label))
}

fn now_unix_ms() -> RouterAbProtocolResult<u64> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| invalid_normal_signing("system clock precedes Unix epoch"))?
        .as_millis();
    u64::try_from(millis)
        .map_err(|_| invalid_normal_signing("system clock exceeds supported range"))
}

fn parse_private_key(value: &str) -> RouterAbProtocolResult<LocalEd25519YaoRecipientPrivateKeyV1> {
    let bytes = hex::decode(value).map_err(|_| {
        invalid_activation("SigningWorker recipient private key must be lowercase hex")
    })?;
    let bytes: [u8; 32] = bytes.try_into().map_err(|_| {
        invalid_activation("SigningWorker recipient private key must contain 32 bytes")
    })?;
    Ok(LocalEd25519YaoRecipientPrivateKeyV1::from_bytes(bytes))
}

fn map_role_error(_: router_ab_ed25519_yao::relay::BenchmarkRoleError) -> RouterAbProtocolError {
    invalid_activation("SigningWorker recipient package validation failed")
}

fn map_signer_error(error: signer_core::error::SignerCoreError) -> RouterAbProtocolError {
    RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
        format!("SigningWorker FROST signing failed: {error}"),
    )
}

fn invalid_activation(message: &'static str) -> RouterAbProtocolError {
    RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
        message,
    )
}

fn invalid_normal_signing(message: impl Into<String>) -> RouterAbProtocolError {
    RouterAbProtocolError::new(RouterAbProtocolErrorCode::InvalidLifecycleState, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use router_ab_core::{
        Ed25519YaoSessionIdV1, Ed25519YaoStableKeyContextBindingV1, RootShareEpoch,
        RouterAbEd25519YaoLifecycleScopeV1,
    };

    #[test]
    fn recovery_stages_exact_next_epoch_and_promotes_only_the_exact_candidate() {
        let mut state = LocalEd25519YaoSigningIdentityStateV1::default();
        let public_key = [0x71; 32];
        let registration = activation_candidate(
            ceremony_binding(Ed25519YaoOperationV1::Registration, 0x11),
            epoch(1),
            [0x21; 32],
            public_key,
            0x31,
        );
        let registration_receipt = state
            .commit_activation_candidate(registration)
            .expect("registration activation");
        assert!(matches!(
            registration_receipt,
            LocalEd25519YaoSigningWorkerActivationReceiptV1::Active { state_epoch, .. }
                if state_epoch == epoch(1)
        ));

        let recovery = activation_candidate(
            ceremony_binding(Ed25519YaoOperationV1::Recovery, 0x12),
            epoch(2),
            [0x22; 32],
            public_key,
            0x32,
        );
        let recovery_delivery_a = recovery.deriver_a.clone();
        let staged = state
            .commit_activation_candidate(recovery)
            .expect("stage recovery");
        let LocalEd25519YaoSigningWorkerActivationReceiptV1::Staged { promotion } = staged else {
            panic!("recovery must remain staged");
        };
        assert_eq!(state.active_state_epoch(), Some(epoch(1)));
        assert_eq!(state.active_signing_share(), Some(&[0x21; 32]));

        let mut conflicting = promotion.clone();
        conflicting.transcript[0] ^= 1;
        assert!(state.promote_recovery_candidate(conflicting).is_err());
        assert_eq!(state.active_state_epoch(), Some(epoch(1)));
        assert_eq!(state.active_signing_share(), Some(&[0x21; 32]));

        let promoted = state
            .promote_recovery_candidate(promotion.clone())
            .expect("promote exact recovery");
        assert!(matches!(
            promoted,
            LocalEd25519YaoSigningWorkerActivationReceiptV1::Active { state_epoch, .. }
                if state_epoch == epoch(2)
        ));
        assert_eq!(state.active_state_epoch(), Some(epoch(2)));
        assert_eq!(state.active_signing_share(), Some(&[0x22; 32]));
        assert_eq!(
            state
                .exact_activation_delivery_retry(
                    Ed25519YaoDeriverRoleV1::DeriverA,
                    &recovery_delivery_a,
                )
                .expect("promoted delivery retry"),
            Some(promoted.clone())
        );
        assert_eq!(
            state
                .promote_recovery_candidate(promotion)
                .expect("exact promotion retry"),
            promoted
        );
    }

    #[test]
    fn recovery_rejects_stale_skipped_and_exhausted_epochs_without_mutation() {
        let mut state = active_state(epoch(4), [0x41; 32]);
        let public_key = state.active_public_key().copied().expect("public key");
        for invalid_epoch in [epoch(4), epoch(6)] {
            let candidate = activation_candidate(
                ceremony_binding(Ed25519YaoOperationV1::Recovery, 0x42),
                invalid_epoch,
                [0x42; 32],
                public_key,
                0x43,
            );
            assert!(state.commit_activation_candidate(candidate).is_err());
            assert_eq!(state.active_state_epoch(), Some(epoch(4)));
            assert_eq!(state.active_signing_share(), Some(&[0x41; 32]));
        }
        assert_eq!(
            state.next_recovery_state_epoch().expect("next epoch"),
            epoch(5)
        );

        let exhausted = active_state(epoch(u64::MAX), [0x51; 32]);
        assert!(exhausted.next_recovery_state_epoch().is_err());
    }

    #[test]
    fn staged_recovery_deliveries_allow_only_exact_retries() {
        let mut state = active_state(epoch(1), [0x61; 32]);
        let public_key = state.active_public_key().copied().expect("public key");
        let recovery = activation_candidate(
            ceremony_binding(Ed25519YaoOperationV1::Recovery, 0x62),
            epoch(2),
            [0x62; 32],
            public_key,
            0x63,
        );
        let exact_a = recovery.deriver_a.clone();
        let staged = state
            .commit_activation_candidate(recovery)
            .expect("stage recovery");
        assert_eq!(
            state
                .exact_activation_delivery_retry(Ed25519YaoDeriverRoleV1::DeriverA, &exact_a)
                .expect("exact delivery retry"),
            Some(staged)
        );

        let mut conflicting_a = exact_a;
        conflicting_a.client_commitment[0] ^= 1;
        assert!(state
            .exact_activation_delivery_retry(Ed25519YaoDeriverRoleV1::DeriverA, &conflicting_a,)
            .is_err());
        assert_eq!(state.active_state_epoch(), Some(epoch(1)));
        assert_eq!(state.active_signing_share(), Some(&[0x61; 32]));
    }

    #[test]
    fn worker_keeps_registration_and_recovery_state_isolated_by_full_identity() {
        let mut worker = LocalEd25519YaoSigningWorkerStateV1::default();
        for identity_tag in [1_u8, 2_u8] {
            let binding = ceremony_binding_for_identity(
                Ed25519YaoOperationV1::Registration,
                identity_tag,
                identity_tag,
            );
            let identity = LocalEd25519YaoEffectiveIdentityV1::from_binding(&binding);
            let candidate = activation_candidate(
                binding,
                epoch(1),
                [identity_tag; 32],
                [identity_tag.wrapping_add(0x20); 32],
                identity_tag.wrapping_add(0x40),
            );
            worker
                .identities
                .entry(identity)
                .or_default()
                .commit_activation_candidate(candidate)
                .expect("independent registration");
        }
        assert_eq!(worker.identities.len(), 2);

        let recovery_binding = ceremony_binding_for_identity(Ed25519YaoOperationV1::Recovery, 3, 1);
        let recovery_identity = LocalEd25519YaoEffectiveIdentityV1::from_binding(&recovery_binding);
        let recovery =
            activation_candidate(recovery_binding, epoch(2), [0x31; 32], [0x21; 32], 0x51);
        let staged = worker
            .identities
            .get_mut(&recovery_identity)
            .expect("first identity")
            .commit_activation_candidate(recovery)
            .expect("first identity recovery");
        let LocalEd25519YaoSigningWorkerActivationReceiptV1::Staged { promotion } = staged else {
            panic!("recovery must be staged");
        };
        worker
            .promote_recovery_candidate(promotion)
            .expect("first identity recovery promotion");

        let first = worker
            .identities
            .get(&recovery_identity)
            .expect("first state");
        assert_eq!(first.active_state_epoch(), Some(epoch(2)));
        assert_eq!(first.active_signing_share(), Some(&[0x31; 32]));
        let second_identity = LocalEd25519YaoEffectiveIdentityV1::from_binding(
            &ceremony_binding_for_identity(Ed25519YaoOperationV1::Registration, 2, 2),
        );
        let second = worker
            .identities
            .get(&second_identity)
            .expect("second state");
        assert_eq!(second.active_state_epoch(), Some(epoch(1)));
        assert_eq!(second.active_signing_share(), Some(&[2; 32]));
    }

    fn active_state(
        state_epoch: Ed25519YaoStateEpochV1,
        scalar: [u8; 32],
    ) -> LocalEd25519YaoSigningIdentityStateV1 {
        LocalEd25519YaoSigningIdentityStateV1 {
            active: Some(ActiveSigningShare {
                scalar: Zeroizing::new(scalar),
                binding: ceremony_binding(Ed25519YaoOperationV1::Registration, 0x71),
                state_epoch,
                transcript: [0x72; 32],
                registered_public_key: [0x73; 32],
            }),
            ..Default::default()
        }
    }

    #[test]
    fn signing_worker_durable_state_restores_only_active_identity_state() {
        let binding = ceremony_binding(Ed25519YaoOperationV1::Registration, 0x71);
        let identity = LocalEd25519YaoEffectiveIdentityV1::from_binding(&binding);
        let mut worker = LocalEd25519YaoSigningWorkerStateV1::default();
        worker
            .identities
            .insert(identity.clone(), active_state(epoch(4), [0x44; 32]));

        let restored =
            LocalEd25519YaoSigningWorkerStateV1::from_durable_state_v1(worker.durable_state_v1())
                .expect("restore SigningWorker state");
        let restored_identity = restored.identities.get(&identity).expect("active identity");
        assert_eq!(restored_identity.active_state_epoch(), Some(epoch(4)));
        assert_eq!(restored_identity.active_signing_share(), Some(&[0x44; 32]));
        assert!(restored_identity.pending_a.is_none());
        assert!(restored_identity.pending_b.is_none());
        assert!(restored_identity.pending_normal_signing.is_empty());
    }

    fn activation_candidate(
        binding: Ed25519YaoCeremonyBindingV1,
        state_epoch: Ed25519YaoStateEpochV1,
        scalar: [u8; 32],
        registered_public_key: [u8; 32],
        tag: u8,
    ) -> ActivationCandidate {
        let transcript = [tag; 32];
        let signing_worker_verifying_share = [tag.wrapping_add(1); 32];
        ActivationCandidate {
            next_active: ActiveSigningShare {
                scalar: Zeroizing::new(scalar),
                binding: binding.clone(),
                state_epoch,
                transcript,
                registered_public_key,
            },
            promotion: LocalEd25519YaoSigningWorkerRecoveryPromotionRequestV1 {
                binding: binding.clone(),
                session: binding.session_id.into_bytes(),
                transcript,
                registered_public_key,
                joined_client_commitment: [tag.wrapping_add(2); 32],
                joined_signing_worker_commitment: signing_worker_verifying_share,
                signing_worker_verifying_share,
                state_epoch,
            },
            deriver_a: pending_delivery(
                &binding,
                Ed25519YaoDeriverRoleV1::DeriverA,
                transcript,
                tag.wrapping_add(3),
            ),
            deriver_b: pending_delivery(
                &binding,
                Ed25519YaoDeriverRoleV1::DeriverB,
                transcript,
                tag.wrapping_add(4),
            ),
        }
    }

    fn pending_delivery(
        binding: &Ed25519YaoCeremonyBindingV1,
        deriver: Ed25519YaoDeriverRoleV1,
        transcript: [u8; 32],
        tag: u8,
    ) -> PendingDelivery {
        PendingDelivery {
            binding: binding.clone(),
            client_commitment: [tag; 32],
            signing_worker_commitment: [tag.wrapping_add(1); 32],
            package: Ed25519YaoEncryptedPackageV1::new(
                Ed25519YaoPackageKindV1::ActivationSigningWorker,
                deriver,
                binding.session_id.into_bytes(),
                transcript,
                [tag.wrapping_add(2); 32],
                vec![tag.wrapping_add(3); 16],
            )
            .expect("encrypted package"),
        }
    }

    fn ceremony_binding(
        operation: Ed25519YaoOperationV1,
        session_tag: u8,
    ) -> Ed25519YaoCeremonyBindingV1 {
        ceremony_binding_for_identity(operation, session_tag, 1)
    }

    fn ceremony_binding_for_identity(
        operation: Ed25519YaoOperationV1,
        session_tag: u8,
        identity_tag: u8,
    ) -> Ed25519YaoCeremonyBindingV1 {
        let scope = RouterAbEd25519YaoLifecycleScopeV1::new(
            format!("lifecycle-{session_tag}"),
            RootShareEpoch::new(format!("root-epoch-{identity_tag}")).expect("root epoch"),
            format!("account-{identity_tag}"),
            format!("wallet-session-{session_tag}"),
            format!("signer-set-{identity_tag}"),
            "signing-worker-1",
        )
        .expect("scope");
        Ed25519YaoCeremonyBindingV1::new(
            scope.into_lifecycle(operation).expect("lifecycle"),
            operation,
            Ed25519YaoSessionIdV1::new([session_tag; 32]).expect("session"),
            Ed25519YaoStableKeyContextBindingV1::new([identity_tag; 32]),
        )
        .expect("binding")
    }

    fn epoch(value: u64) -> Ed25519YaoStateEpochV1 {
        Ed25519YaoStateEpochV1::new(value).expect("state epoch")
    }
}
