use rand_core_09::{CryptoRng, RngCore};
use router_ab_core::{
    Ed25519YaoCeremonyBindingV1, Ed25519YaoDeriverRoleV1, Ed25519YaoEncryptedPackageV1,
    Ed25519YaoOperationV1, Ed25519YaoPackageKindV1, RouterAbProtocolError,
    RouterAbProtocolErrorCode, RouterAbProtocolResult,
};
use serde::{Deserialize, Serialize};

use crate::{
    relay::{
        ActivationDeriverACompletion, ActivationDeriverBCompletion, ExportDeriverACompletion,
        ExportDeriverBCompletion,
    },
    seal_ed25519_yao_package_v1, LocalEd25519YaoActivationRecipientsV1,
    LocalEd25519YaoExportRecipientV1,
};

/// Complete, recipient-encrypted output from one activation-family Deriver role.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ed25519YaoActivationRoleExecutionV1 {
    /// Exact Router-admitted ceremony binding.
    pub binding: Ed25519YaoCeremonyBindingV1,
    /// Deriver that produced this output.
    pub deriver: Ed25519YaoDeriverRoleV1,
    /// Joint final transcript.
    pub transcript: [u8; 32],
    /// Public commitment to this role's Client share.
    pub client_commitment: [u8; 32],
    /// Public commitment to this role's Signing Worker share.
    pub signing_worker_commitment: [u8; 32],
    /// Client-recipient encrypted activation package.
    pub client_package: Ed25519YaoEncryptedPackageV1,
    /// Signing Worker-recipient encrypted activation package.
    pub signing_worker_package: Ed25519YaoEncryptedPackageV1,
}

impl Ed25519YaoActivationRoleExecutionV1 {
    /// Creates and validates one complete activation role result.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        binding: Ed25519YaoCeremonyBindingV1,
        deriver: Ed25519YaoDeriverRoleV1,
        transcript: [u8; 32],
        client_commitment: [u8; 32],
        signing_worker_commitment: [u8; 32],
        client_package: Ed25519YaoEncryptedPackageV1,
        signing_worker_package: Ed25519YaoEncryptedPackageV1,
    ) -> RouterAbProtocolResult<Self> {
        let execution = Self {
            binding,
            deriver,
            transcript,
            client_commitment,
            signing_worker_commitment,
            client_package,
            signing_worker_package,
        };
        execution.validate()?;
        Ok(execution)
    }

    /// Validates role, operation, transcript, session, and recipient packages.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.binding.validate()?;
        if !matches!(
            self.binding.operation,
            Ed25519YaoOperationV1::Registration | Ed25519YaoOperationV1::Recovery
        ) {
            return Err(invalid_execution(
                "activation role execution requires registration or recovery",
            ));
        }
        validate_nonzero(self.transcript, "activation transcript")?;
        validate_nonzero(self.client_commitment, "Client commitment")?;
        validate_nonzero(self.signing_worker_commitment, "Signing Worker commitment")?;
        validate_package(
            &self.client_package,
            Ed25519YaoPackageKindV1::ActivationClient,
            self.deriver,
            &self.binding,
            self.transcript,
        )?;
        validate_package(
            &self.signing_worker_package,
            Ed25519YaoPackageKindV1::ActivationSigningWorker,
            self.deriver,
            &self.binding,
            self.transcript,
        )
    }
}

/// Complete, recipient-encrypted output from one explicit-export Deriver role.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ed25519YaoExportRoleExecutionV1 {
    /// Exact Router-admitted ceremony binding.
    pub binding: Ed25519YaoCeremonyBindingV1,
    /// Deriver that produced this output.
    pub deriver: Ed25519YaoDeriverRoleV1,
    /// Joint final transcript.
    pub transcript: [u8; 32],
    /// Client-recipient encrypted exact-seed share.
    pub client_package: Ed25519YaoEncryptedPackageV1,
}

impl Ed25519YaoExportRoleExecutionV1 {
    /// Creates and validates one complete export role result.
    pub fn new(
        binding: Ed25519YaoCeremonyBindingV1,
        deriver: Ed25519YaoDeriverRoleV1,
        transcript: [u8; 32],
        client_package: Ed25519YaoEncryptedPackageV1,
    ) -> RouterAbProtocolResult<Self> {
        let execution = Self {
            binding,
            deriver,
            transcript,
            client_package,
        };
        execution.validate()?;
        Ok(execution)
    }

    /// Validates role, operation, transcript, session, and recipient package.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.binding.validate()?;
        if self.binding.operation != Ed25519YaoOperationV1::Export {
            return Err(invalid_execution(
                "export role execution requires the export operation",
            ));
        }
        validate_nonzero(self.transcript, "export transcript")?;
        validate_package(
            &self.client_package,
            Ed25519YaoPackageKindV1::ExportClient,
            self.deriver,
            &self.binding,
            self.transcript,
        )
    }
}

/// One exact completed role result stored or returned at a transport boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "family", rename_all = "snake_case")]
pub enum Ed25519YaoRoleExecutionV1 {
    /// Registration or recovery activation result.
    Activation(Ed25519YaoActivationRoleExecutionV1),
    /// Explicit exact-seed export result.
    Export(Ed25519YaoExportRoleExecutionV1),
}

impl Ed25519YaoRoleExecutionV1 {
    /// Validates the selected execution branch.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        match self {
            Self::Activation(execution) => execution.validate(),
            Self::Export(execution) => execution.validate(),
        }
    }

    /// Returns the exact ceremony session.
    pub fn session(&self) -> [u8; 32] {
        match self {
            Self::Activation(execution) => execution.binding.session_id.into_bytes(),
            Self::Export(execution) => execution.binding.session_id.into_bytes(),
        }
    }

    /// Returns the producing Deriver.
    pub const fn deriver(&self) -> Ed25519YaoDeriverRoleV1 {
        match self {
            Self::Activation(execution) => execution.deriver,
            Self::Export(execution) => execution.deriver,
        }
    }
}

/// Seals one completed activation Deriver A role to its exact recipients.
pub fn seal_ed25519_yao_activation_deriver_a_execution_v1<R>(
    rng: &mut R,
    binding: Ed25519YaoCeremonyBindingV1,
    recipients: LocalEd25519YaoActivationRecipientsV1,
    completion: &ActivationDeriverACompletion,
) -> RouterAbProtocolResult<Ed25519YaoRoleExecutionV1>
where
    R: CryptoRng + RngCore,
{
    let client_package = completion.client_package();
    let signing_worker_package = completion.signing_worker_package();
    seal_activation_role_execution(
        rng,
        binding,
        recipients,
        Ed25519YaoDeriverRoleV1::DeriverA,
        completion.final_transcript(),
        completion.client_commitment(),
        completion.signing_worker_commitment(),
        client_package.as_bytes(),
        signing_worker_package.as_bytes(),
    )
    .map(Ed25519YaoRoleExecutionV1::Activation)
}

/// Seals one completed activation Deriver B role to its exact recipients.
pub fn seal_ed25519_yao_activation_deriver_b_execution_v1<R>(
    rng: &mut R,
    binding: Ed25519YaoCeremonyBindingV1,
    recipients: LocalEd25519YaoActivationRecipientsV1,
    completion: &ActivationDeriverBCompletion,
) -> RouterAbProtocolResult<Ed25519YaoRoleExecutionV1>
where
    R: CryptoRng + RngCore,
{
    let client_package = completion.client_package();
    let signing_worker_package = completion.signing_worker_package();
    seal_activation_role_execution(
        rng,
        binding,
        recipients,
        Ed25519YaoDeriverRoleV1::DeriverB,
        completion.final_transcript(),
        completion.client_commitment(),
        completion.signing_worker_commitment(),
        client_package.as_bytes(),
        signing_worker_package.as_bytes(),
    )
    .map(Ed25519YaoRoleExecutionV1::Activation)
}

/// Seals one completed explicit-export Deriver A role to the exact Client.
pub fn seal_ed25519_yao_export_deriver_a_execution_v1<R>(
    rng: &mut R,
    binding: Ed25519YaoCeremonyBindingV1,
    recipient: LocalEd25519YaoExportRecipientV1,
    completion: &ExportDeriverACompletion,
) -> RouterAbProtocolResult<Ed25519YaoRoleExecutionV1>
where
    R: CryptoRng + RngCore,
{
    let client_package = completion.export_package();
    seal_export_role_execution(
        rng,
        binding,
        recipient,
        Ed25519YaoDeriverRoleV1::DeriverA,
        completion.final_transcript(),
        client_package.as_bytes(),
    )
    .map(Ed25519YaoRoleExecutionV1::Export)
}

/// Seals one completed explicit-export Deriver B role to the exact Client.
pub fn seal_ed25519_yao_export_deriver_b_execution_v1<R>(
    rng: &mut R,
    binding: Ed25519YaoCeremonyBindingV1,
    recipient: LocalEd25519YaoExportRecipientV1,
    completion: &ExportDeriverBCompletion,
) -> RouterAbProtocolResult<Ed25519YaoRoleExecutionV1>
where
    R: CryptoRng + RngCore,
{
    let client_package = completion.export_package();
    seal_export_role_execution(
        rng,
        binding,
        recipient,
        Ed25519YaoDeriverRoleV1::DeriverB,
        completion.final_transcript(),
        client_package.as_bytes(),
    )
    .map(Ed25519YaoRoleExecutionV1::Export)
}

#[allow(clippy::too_many_arguments)]
fn seal_activation_role_execution<R>(
    rng: &mut R,
    binding: Ed25519YaoCeremonyBindingV1,
    recipients: LocalEd25519YaoActivationRecipientsV1,
    deriver: Ed25519YaoDeriverRoleV1,
    transcript: [u8; 32],
    client_commitment: [u8; 32],
    signing_worker_commitment: [u8; 32],
    client_plaintext: &[u8],
    signing_worker_plaintext: &[u8],
) -> RouterAbProtocolResult<Ed25519YaoActivationRoleExecutionV1>
where
    R: CryptoRng + RngCore,
{
    let session = binding.session_id.into_bytes();
    let client_package = seal_ed25519_yao_package_v1(
        rng,
        Ed25519YaoPackageKindV1::ActivationClient,
        deriver,
        session,
        transcript,
        recipients.client_public_key,
        client_plaintext,
    )?;
    let signing_worker_package = seal_ed25519_yao_package_v1(
        rng,
        Ed25519YaoPackageKindV1::ActivationSigningWorker,
        deriver,
        session,
        transcript,
        recipients.signing_worker_public_key,
        signing_worker_plaintext,
    )?;
    Ed25519YaoActivationRoleExecutionV1::new(
        binding,
        deriver,
        transcript,
        client_commitment,
        signing_worker_commitment,
        client_package,
        signing_worker_package,
    )
}

fn seal_export_role_execution<R>(
    rng: &mut R,
    binding: Ed25519YaoCeremonyBindingV1,
    recipient: LocalEd25519YaoExportRecipientV1,
    deriver: Ed25519YaoDeriverRoleV1,
    transcript: [u8; 32],
    client_plaintext: &[u8],
) -> RouterAbProtocolResult<Ed25519YaoExportRoleExecutionV1>
where
    R: CryptoRng + RngCore,
{
    let client_package = seal_ed25519_yao_package_v1(
        rng,
        Ed25519YaoPackageKindV1::ExportClient,
        deriver,
        binding.session_id.into_bytes(),
        transcript,
        recipient.client_public_key,
        client_plaintext,
    )?;
    Ed25519YaoExportRoleExecutionV1::new(binding, deriver, transcript, client_package)
}

fn validate_package(
    package: &Ed25519YaoEncryptedPackageV1,
    kind: Ed25519YaoPackageKindV1,
    deriver: Ed25519YaoDeriverRoleV1,
    binding: &Ed25519YaoCeremonyBindingV1,
    transcript: [u8; 32],
) -> RouterAbProtocolResult<()> {
    package.validate()?;
    if package.kind() != kind
        || package.deriver() != deriver
        || package.session() != binding.session_id.into_bytes()
        || package.transcript() != transcript
    {
        return Err(invalid_execution(
            "recipient package does not match its role execution",
        ));
    }
    Ok(())
}

fn validate_nonzero(value: [u8; 32], label: &'static str) -> RouterAbProtocolResult<()> {
    if value.iter().all(|byte| *byte == 0) {
        return Err(invalid_execution(label));
    }
    Ok(())
}

fn invalid_execution(message: impl Into<String>) -> RouterAbProtocolError {
    RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::InvalidLifecycleState,
        message.into(),
    )
}
