use router_ab_core::{
    Ed25519YaoCeremonyBindingV1, Ed25519YaoDeriverRoleV1, Ed25519YaoEncryptedPackageV1,
    Ed25519YaoOperationV1, Ed25519YaoPackageKindV1, Ed25519YaoStateEpochV1, RouterAbProtocolError,
    RouterAbProtocolErrorCode, RouterAbProtocolResult,
};
use serde::{Deserialize, Serialize};
use signer_core::near_threshold_ed25519::verifying_share_bytes_from_signing_share_bytes;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::crypto::{open_ed25519_yao_signing_worker_package_v1, Ed25519YaoRecipientPrivateKeyV1};
use crate::recipient::signing_worker::{
    combine_signing_worker_activation_packages, SigningWorkerBaseScalar,
};
use crate::relay::{
    derive_registration_receipt, ActivationDeriverASigningWorkerPackage,
    ActivationDeriverBSigningWorkerPackage, ActivationPublicCommitments, BenchmarkRoleError,
};

/// One role-bound activation package delivered to the Signing Worker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ed25519YaoSigningWorkerPackageDeliveryV1 {
    /// Router-admitted ceremony binding.
    pub binding: Ed25519YaoCeremonyBindingV1,
    /// Role-local public Client commitment.
    pub client_commitment: [u8; 32],
    /// Role-local public Signing Worker commitment.
    pub signing_worker_commitment: [u8; 32],
    /// Recipient-encrypted Signing Worker package.
    pub package: Ed25519YaoEncryptedPackageV1,
}

impl Ed25519YaoSigningWorkerPackageDeliveryV1 {
    /// Validates this delivery for one exact Deriver role.
    pub fn validate_for_deriver(
        &self,
        expected_deriver: Ed25519YaoDeriverRoleV1,
    ) -> RouterAbProtocolResult<()> {
        self.binding.validate()?;
        if !matches!(
            self.binding.operation,
            Ed25519YaoOperationV1::Registration | Ed25519YaoOperationV1::Recovery
        ) {
            return Err(invalid_activation(
                "Signing Worker activation requires registration or recovery",
            ));
        }
        self.package.validate()?;
        if self.package.kind() != Ed25519YaoPackageKindV1::ActivationSigningWorker
            || self.package.deriver() != expected_deriver
            || self.package.session() != self.binding.session_id.into_bytes()
        {
            return Err(invalid_activation(
                "Signing Worker activation package role, family, or session is invalid",
            ));
        }
        if self.client_commitment.iter().all(|byte| *byte == 0)
            || self.signing_worker_commitment.iter().all(|byte| *byte == 0)
        {
            return Err(invalid_activation(
                "Signing Worker activation commitments must be nonzero",
            ));
        }
        Ok(())
    }
}

/// Active Ed25519 material held only by the Signing Worker.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct Ed25519YaoActiveSigningMaterialV1 {
    scalar: [u8; 32],
    #[zeroize(skip)]
    binding: Ed25519YaoCeremonyBindingV1,
    #[zeroize(skip)]
    state_epoch: Ed25519YaoStateEpochV1,
    transcript: [u8; 32],
    registered_public_key: [u8; 32],
}

impl core::fmt::Debug for Ed25519YaoActiveSigningMaterialV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("Ed25519YaoActiveSigningMaterialV1")
            .field("scalar", &"[REDACTED]")
            .field("binding", &self.binding)
            .field("state_epoch", &self.state_epoch)
            .field("transcript", &self.transcript)
            .field("registered_public_key", &self.registered_public_key)
            .finish()
    }
}

impl Ed25519YaoActiveSigningMaterialV1 {
    /// Validates persisted Signing Worker material.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.binding.validate()?;
        if self.scalar.iter().all(|byte| *byte == 0)
            || self.transcript.iter().all(|byte| *byte == 0)
            || self.registered_public_key.iter().all(|byte| *byte == 0)
        {
            return Err(invalid_activation(
                "active Ed25519 Yao Signing Worker material is invalid",
            ));
        }
        Ok(())
    }

    /// Borrows the zeroizing FROST signing share.
    pub fn scalar(&self) -> &[u8; 32] {
        &self.scalar
    }

    /// Returns the ceremony binding that established this material.
    pub fn binding(&self) -> &Ed25519YaoCeremonyBindingV1 {
        &self.binding
    }

    /// Returns the monotonic state epoch.
    pub fn state_epoch(&self) -> Ed25519YaoStateEpochV1 {
        self.state_epoch
    }

    /// Returns the activation transcript.
    pub fn transcript(&self) -> [u8; 32] {
        self.transcript
    }

    /// Returns the registered Ed25519 public key.
    pub fn registered_public_key(&self) -> [u8; 32] {
        self.registered_public_key
    }
}

/// Public activation receipt returned to the Router.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ed25519YaoSigningWorkerActivationReceiptV1 {
    /// Ceremony session.
    pub session: [u8; 32],
    /// Joint activation transcript.
    pub transcript: [u8; 32],
    /// Registered Ed25519 public key.
    pub registered_public_key: [u8; 32],
    /// Joined Client verifying-share commitment.
    pub joined_client_commitment: [u8; 32],
    /// Joined Signing Worker verifying-share commitment.
    pub joined_signing_worker_commitment: [u8; 32],
    /// Signing Worker verifying share derived from its stored scalar.
    pub signing_worker_verifying_share: [u8; 32],
    /// Monotonic Signing Worker state epoch.
    pub state_epoch: Ed25519YaoStateEpochV1,
}

/// One candidate produced after both Signing Worker packages are combined.
#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct Ed25519YaoSigningWorkerActivationCandidateV1 {
    /// Secret active material. Registration commits it immediately; recovery
    /// retains it until the Client confirms public continuity.
    pub material: Ed25519YaoActiveSigningMaterialV1,
    /// Public receipt checked by the Client and Router.
    #[zeroize(skip)]
    pub receipt: Ed25519YaoSigningWorkerActivationReceiptV1,
}

impl Ed25519YaoSigningWorkerActivationCandidateV1 {
    /// Moves secret material into durable lifecycle state without cloning it.
    pub fn into_parts(mut self) -> (
        Ed25519YaoActiveSigningMaterialV1,
        Ed25519YaoSigningWorkerActivationReceiptV1,
    ) {
        let material = Ed25519YaoActiveSigningMaterialV1 {
            scalar: core::mem::take(&mut self.material.scalar),
            binding: self.material.binding.clone(),
            state_epoch: self.material.state_epoch,
            transcript: self.material.transcript,
            registered_public_key: self.material.registered_public_key,
        };
        let receipt = self.receipt.clone();
        (material, receipt)
    }
}

/// Combines the exact A/B Signing Worker packages into one activation candidate.
pub fn combine_ed25519_yao_signing_worker_packages_v1(
    private_key: &Ed25519YaoRecipientPrivateKeyV1,
    deriver_a: Ed25519YaoSigningWorkerPackageDeliveryV1,
    deriver_b: Ed25519YaoSigningWorkerPackageDeliveryV1,
    active: Option<&Ed25519YaoActiveSigningMaterialV1>,
) -> RouterAbProtocolResult<Ed25519YaoSigningWorkerActivationCandidateV1> {
    deriver_a.validate_for_deriver(Ed25519YaoDeriverRoleV1::DeriverA)?;
    deriver_b.validate_for_deriver(Ed25519YaoDeriverRoleV1::DeriverB)?;
    if deriver_a.binding != deriver_b.binding
        || deriver_a.package.transcript() != deriver_b.package.transcript()
    {
        return Err(invalid_activation(
            "Signing Worker activation package bindings do not match",
        ));
    }
    let state_epoch = activation_state_epoch(&deriver_a.binding, active)?;
    let mut a_plaintext =
        open_ed25519_yao_signing_worker_package_v1(&deriver_a.package, private_key)?;
    let mut b_plaintext =
        open_ed25519_yao_signing_worker_package_v1(&deriver_b.package, private_key)?;
    let a_package =
        ActivationDeriverASigningWorkerPackage::from_bytes(core::mem::take(&mut *a_plaintext))
            .map_err(map_role_error)?;
    let b_package =
        ActivationDeriverBSigningWorkerPackage::from_bytes(core::mem::take(&mut *b_plaintext))
            .map_err(map_role_error)?;
    let session = deriver_a.binding.session_id.into_bytes();
    let transcript = deriver_a.package.transcript();
    let scalar =
        combine_signing_worker_activation_packages(session, transcript, a_package, b_package)
            .map_err(map_role_error)?;
    build_candidate(deriver_a, deriver_b, scalar, state_epoch, active)
}

fn build_candidate(
    deriver_a: Ed25519YaoSigningWorkerPackageDeliveryV1,
    deriver_b: Ed25519YaoSigningWorkerPackageDeliveryV1,
    scalar: SigningWorkerBaseScalar,
    state_epoch: Ed25519YaoStateEpochV1,
    active: Option<&Ed25519YaoActiveSigningMaterialV1>,
) -> RouterAbProtocolResult<Ed25519YaoSigningWorkerActivationCandidateV1> {
    let scalar = Zeroizing::new(scalar.into_bytes());
    let transcript = deriver_a.package.transcript();
    let commitments = ActivationPublicCommitments::new(
        deriver_a.client_commitment,
        deriver_b.client_commitment,
        deriver_a.signing_worker_commitment,
        deriver_b.signing_worker_commitment,
    );
    let public_receipt = derive_registration_receipt(commitments).map_err(map_role_error)?;
    let signing_worker_verifying_share = verifying_share_bytes_from_signing_share_bytes(&scalar);
    if &signing_worker_verifying_share != public_receipt.joined_signing_worker_commitment() {
        return Err(invalid_activation(
            "Signing Worker share does not match its public activation commitment",
        ));
    }
    let registered_public_key = *public_receipt.registered_public_key();
    if let Some(active) = active {
        if registered_public_key != active.registered_public_key {
            return Err(invalid_activation(
                "recovery candidate changed the registered public key",
            ));
        }
    }
    let binding = deriver_a.binding;
    let material = Ed25519YaoActiveSigningMaterialV1 {
        scalar: *scalar,
        binding,
        state_epoch,
        transcript,
        registered_public_key,
    };
    material.validate()?;
    let receipt = Ed25519YaoSigningWorkerActivationReceiptV1 {
        session: material.binding.session_id.into_bytes(),
        transcript,
        registered_public_key,
        joined_client_commitment: *public_receipt.joined_client_commitment(),
        joined_signing_worker_commitment: *public_receipt.joined_signing_worker_commitment(),
        signing_worker_verifying_share,
        state_epoch,
    };
    Ok(Ed25519YaoSigningWorkerActivationCandidateV1 { material, receipt })
}

fn activation_state_epoch(
    binding: &Ed25519YaoCeremonyBindingV1,
    active: Option<&Ed25519YaoActiveSigningMaterialV1>,
) -> RouterAbProtocolResult<Ed25519YaoStateEpochV1> {
    match (binding.operation, active) {
        (Ed25519YaoOperationV1::Registration, None) => Ed25519YaoStateEpochV1::new(1),
        (Ed25519YaoOperationV1::Recovery, Some(active))
            if same_signing_identity(active.binding(), binding) =>
        {
            let next = active
                .state_epoch()
                .get()
                .checked_add(1)
                .ok_or_else(|| invalid_activation("Signing Worker state epoch is exhausted"))?;
            Ed25519YaoStateEpochV1::new(next)
        }
        (Ed25519YaoOperationV1::Registration, Some(_)) => Err(invalid_activation(
            "registration requires an empty Signing Worker state",
        )),
        (Ed25519YaoOperationV1::Recovery, None) => Err(invalid_activation(
            "recovery requires active Signing Worker state",
        )),
        _ => Err(invalid_activation(
            "Signing Worker activation transition is invalid",
        )),
    }
}

fn same_signing_identity(
    active: &Ed25519YaoCeremonyBindingV1,
    candidate: &Ed25519YaoCeremonyBindingV1,
) -> bool {
    active.stable_key_context_binding == candidate.stable_key_context_binding
        && active.lifecycle.root_share_epoch == candidate.lifecycle.root_share_epoch
        && active.lifecycle.account_id == candidate.lifecycle.account_id
        && active.lifecycle.signer_set_id == candidate.lifecycle.signer_set_id
        && active.lifecycle.selected_server_id == candidate.lifecycle.selected_server_id
}

fn map_role_error(_: BenchmarkRoleError) -> RouterAbProtocolError {
    invalid_activation("Signing Worker recipient package validation failed")
}

fn invalid_activation(message: &'static str) -> RouterAbProtocolError {
    RouterAbProtocolError::new(RouterAbProtocolErrorCode::InvalidLifecycleState, message)
}
