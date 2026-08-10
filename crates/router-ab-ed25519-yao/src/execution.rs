use base64ct::{Base64UrlUnpadded, Encoding};
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::traits::IsIdentity;
use rand_core_09::{CryptoRng, RngCore};
use router_ab_core::{
    Ed25519YaoCeremonyBindingV1, Ed25519YaoDeriverRoleV1, Ed25519YaoEncryptedPackageV1,
    Ed25519YaoLaneJobV1, Ed25519YaoLaneProtocolCommittedV1, Ed25519YaoOperationV1,
    Ed25519YaoPackageKindV1, RouterAbEd25519YaoLaneResultV1, RouterAbProtocolError,
    RouterAbProtocolErrorCode, RouterAbProtocolResult,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    relay::{
        ActivationDeriverACompletion, ActivationDeriverBCompletion, ExportDeriverACompletion,
        ExportDeriverBCompletion, LaneDeriverACompletion, LaneDeriverBCompletion,
    },
    seal_ed25519_yao_lane_package_v1, seal_ed25519_yao_package_v1,
    LocalEd25519YaoActivationRecipientsV1, LocalEd25519YaoExportRecipientV1,
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

/// Complete recipient-encrypted output from one lane-materialization Deriver role.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ed25519YaoLaneRoleExecutionV1 {
    /// Immutable lane job admitted before the role protocol started.
    pub job: Ed25519YaoLaneJobV1,
    /// Producing Deriver role.
    pub deriver: Ed25519YaoDeriverRoleV1,
    /// Joint terminal transcript.
    pub transcript: [u8; 32],
    /// Public commitment to the holder output share.
    pub holder_commitment: [u8; 32],
    /// Public commitment to the SigningWorker output share.
    pub signing_worker_commitment: [u8; 32],
    /// Holder-recipient ciphertext.
    pub holder_package: Ed25519YaoEncryptedPackageV1,
    /// SigningWorker-recipient ciphertext.
    pub signing_worker_package: Ed25519YaoEncryptedPackageV1,
}

impl Ed25519YaoLaneRoleExecutionV1 {
    /// Creates and validates one complete lane role result.
    pub fn new(
        job: Ed25519YaoLaneJobV1,
        deriver: Ed25519YaoDeriverRoleV1,
        transcript: [u8; 32],
        holder_commitment: [u8; 32],
        signing_worker_commitment: [u8; 32],
        holder_package: Ed25519YaoEncryptedPackageV1,
        signing_worker_package: Ed25519YaoEncryptedPackageV1,
    ) -> RouterAbProtocolResult<Self> {
        let execution = Self {
            job,
            deriver,
            transcript,
            holder_commitment,
            signing_worker_commitment,
            holder_package,
            signing_worker_package,
        };
        execution.validate()?;
        Ok(execution)
    }

    /// Validates exact lane job, transcript, role, and recipient package bindings.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.job.validate()?;
        let expected_transcript = self.job.transcript_digest_v1()?;
        if self.transcript != expected_transcript {
            return Err(invalid_execution("lane role transcript does not match job"));
        }
        validate_nonzero(self.holder_commitment, "lane holder commitment")?;
        validate_nonzero(
            self.signing_worker_commitment,
            "lane SigningWorker commitment",
        )?;
        let session = self.job.session_v1()?;
        validate_lane_package(
            &self.holder_package,
            Ed25519YaoPackageKindV1::LaneHolder,
            self.deriver,
            session,
            self.transcript,
        )?;
        validate_lane_package(
            &self.signing_worker_package,
            Ed25519YaoPackageKindV1::LaneSigningWorker,
            self.deriver,
            session,
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

/// Seals one completed lane Deriver A role to its holder and SigningWorker recipients.
pub fn seal_ed25519_yao_lane_deriver_a_execution_v1<R>(
    rng: &mut R,
    job: Ed25519YaoLaneJobV1,
    completion: &LaneDeriverACompletion,
) -> RouterAbProtocolResult<Ed25519YaoLaneRoleExecutionV1>
where
    R: CryptoRng + RngCore,
{
    seal_lane_role_execution(
        rng,
        job,
        Ed25519YaoDeriverRoleV1::DeriverA,
        completion.final_transcript(),
        completion.holder_commitment(),
        completion.signing_worker_commitment(),
        completion.holder_package().as_bytes(),
        completion.signing_worker_package().as_bytes(),
    )
}

/// Seals one completed lane Deriver B role to its holder and SigningWorker recipients.
pub fn seal_ed25519_yao_lane_deriver_b_execution_v1<R>(
    rng: &mut R,
    job: Ed25519YaoLaneJobV1,
    completion: &LaneDeriverBCompletion,
) -> RouterAbProtocolResult<Ed25519YaoLaneRoleExecutionV1>
where
    R: CryptoRng + RngCore,
{
    seal_lane_role_execution(
        rng,
        job,
        Ed25519YaoDeriverRoleV1::DeriverB,
        completion.final_transcript(),
        completion.holder_commitment(),
        completion.signing_worker_commitment(),
        completion.holder_package().as_bytes(),
        completion.signing_worker_package().as_bytes(),
    )
}

fn seal_lane_role_execution<R>(
    rng: &mut R,
    job: Ed25519YaoLaneJobV1,
    deriver: Ed25519YaoDeriverRoleV1,
    transcript: [u8; 32],
    holder_commitment: [u8; 32],
    signing_worker_commitment: [u8; 32],
    holder_plaintext: &[u8],
    signing_worker_plaintext: &[u8],
) -> RouterAbProtocolResult<Ed25519YaoLaneRoleExecutionV1>
where
    R: CryptoRng + RngCore,
{
    job.validate()?;
    let session = job.session_v1()?;
    let target_lane_id_digest: [u8; 32] = Sha256::digest(job.target_lane_id().as_bytes()).into();
    let holder_public_key = decode_lane_digest(&job.target_holder.hpke_public_key_b64u)?;
    let signing_worker_public_key =
        decode_lane_digest(&job.target_signing_worker.hpke_public_key_b64u)?;
    let holder_package = seal_ed25519_yao_lane_package_v1(
        rng,
        Ed25519YaoPackageKindV1::LaneHolder,
        deriver,
        session,
        transcript,
        target_lane_id_digest,
        holder_public_key,
        holder_plaintext,
    )?;
    let signing_worker_package = seal_ed25519_yao_lane_package_v1(
        rng,
        Ed25519YaoPackageKindV1::LaneSigningWorker,
        deriver,
        session,
        transcript,
        target_lane_id_digest,
        signing_worker_public_key,
        signing_worker_plaintext,
    )?;
    Ed25519YaoLaneRoleExecutionV1::new(
        job,
        deriver,
        transcript,
        holder_commitment,
        signing_worker_commitment,
        holder_package,
        signing_worker_package,
    )
}

/// Commits both role outputs into one immutable lane result after checking the public relation.
pub fn commit_ed25519_yao_lane_result_v1(
    deriver_a: Ed25519YaoLaneRoleExecutionV1,
    deriver_b: Ed25519YaoLaneRoleExecutionV1,
    committed_at_ms: u64,
) -> RouterAbProtocolResult<RouterAbEd25519YaoLaneResultV1> {
    deriver_a.validate()?;
    deriver_b.validate()?;
    if deriver_a.deriver != Ed25519YaoDeriverRoleV1::DeriverA
        || deriver_b.deriver != Ed25519YaoDeriverRoleV1::DeriverB
        || deriver_a.job != deriver_b.job
        || deriver_a.transcript != deriver_b.transcript
    {
        return Err(invalid_execution(
            "lane role outputs are not one exact ceremony",
        ));
    }
    let registered = CompressedEdwardsY(decode_lane_digest(
        &deriver_a.job.registered_public_key_b64u,
    )?)
    .decompress()
    .ok_or_else(|| invalid_execution("registered Ed25519 identity is not a point"))?;
    if registered.is_identity() {
        return Err(invalid_execution(
            "registered Ed25519 identity is the identity",
        ));
    }
    let holder = decode_commitment(deriver_a.holder_commitment)?
        + decode_commitment(deriver_b.holder_commitment)?;
    let signing_worker = decode_commitment(deriver_a.signing_worker_commitment)?
        + decode_commitment(deriver_b.signing_worker_commitment)?;
    if holder + holder - signing_worker != registered {
        return Err(invalid_execution(
            "lane output commitments do not satisfy 2*X_holder-X_worker=A_pub",
        ));
    }
    let holder_commitment = holder.compress().to_bytes();
    let signing_worker_commitment = signing_worker.compress().to_bytes();
    let public_identity_digest = lane_public_identity_digest(
        deriver_a.transcript,
        holder_commitment,
        signing_worker_commitment,
        deriver_a.job.registered_public_key_b64u.as_bytes(),
    );
    let holder_ciphertext_digest_set = lane_ciphertext_digest_set(
        b"holder",
        &deriver_a.holder_package,
        &deriver_b.holder_package,
    );
    let signing_worker_ciphertext_digest_set = lane_ciphertext_digest_set(
        b"signing-worker",
        &deriver_a.signing_worker_package,
        &deriver_b.signing_worker_package,
    );
    let holder_key_digest =
        decode_lane_digest(&deriver_a.job.target_holder.hpke_public_key_digest_b64u)?;
    let signing_worker_key_digest = decode_lane_digest(
        &deriver_a
            .job
            .target_signing_worker
            .hpke_public_key_digest_b64u,
    )?;
    let encode = |bytes: [u8; 32]| Base64UrlUnpadded::encode_string(&bytes);
    let result = RouterAbEd25519YaoLaneResultV1 {
        job: deriver_a.job,
        transcript_hash_b64u: encode(deriver_a.transcript),
        public_identity_digest_b64u: encode(public_identity_digest),
        target_holder_public_commitment_b64u: encode(holder_commitment),
        target_server_public_commitment_b64u: encode(signing_worker_commitment),
        target_holder_ciphertext_digest_set_b64u: encode(holder_ciphertext_digest_set),
        target_server_ciphertext_digest_set_b64u: encode(signing_worker_ciphertext_digest_set),
        holder_recipient_key_digest_b64u: encode(holder_key_digest),
        server_recipient_key_digest_b64u: encode(signing_worker_key_digest),
        deriver_a_holder_package: deriver_a.holder_package,
        deriver_b_holder_package: deriver_b.holder_package,
        deriver_a_signing_worker_package: deriver_a.signing_worker_package,
        deriver_b_signing_worker_package: deriver_b.signing_worker_package,
        committed_at_ms,
    };
    result.validate()?;
    Ok(result)
}

/// Builds the exact terminal receipt from one already-committed lane result.
pub fn lane_protocol_commit_receipt_v1(
    result: &RouterAbEd25519YaoLaneResultV1,
) -> RouterAbProtocolResult<Ed25519YaoLaneProtocolCommittedV1> {
    result.validate()?;
    let target = result.job.target_lane_id().to_owned();
    Ed25519YaoLaneProtocolCommittedV1::new(
        result.job.operation_id.clone(),
        result.job.enrollment_id.clone(),
        result.job.wallet_id.clone(),
        result.job.wallet_key_id.clone(),
        result.job.source.lane_id.clone(),
        result.job.source.lane_share_epoch,
        result.job.source.revocation_epoch,
        result.job.source.material_activation.clone(),
        target,
        result.job.target_lane_share_epoch(),
        result.job.target_material_activation_id.clone(),
        result.job.key_family.clone(),
        result.public_identity_digest_b64u.clone(),
        result.target_holder_public_commitment_b64u.clone(),
        result.target_server_public_commitment_b64u.clone(),
        result.target_holder_ciphertext_digest_set_b64u.clone(),
        result.target_server_ciphertext_digest_set_b64u.clone(),
        result.holder_recipient_key_digest_b64u.clone(),
        result.server_recipient_key_digest_b64u.clone(),
        result.transcript_hash_b64u.clone(),
        result.committed_at_ms,
    )
}

/// Forward-only commitment state for exact lane output redelivery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ed25519YaoLaneOutputCommitV1 {
    /// Admitted operation identifier.
    pub operation_id: String,
    /// Committed transcript hash.
    pub transcript: [u8; 32],
    /// Digest of the exact committed package/result set.
    pub result_digest: [u8; 32],
    /// Commit timestamp.
    pub committed_at_ms: u64,
}

impl Ed25519YaoLaneOutputCommitV1 {
    /// Creates one immutable commit marker from an already-validated result.
    pub fn from_result(result: &RouterAbEd25519YaoLaneResultV1) -> RouterAbProtocolResult<Self> {
        result.validate()?;
        Ok(Self {
            operation_id: result.job.operation_id.clone(),
            transcript: decode_lane_digest(&result.transcript_hash_b64u)?,
            result_digest: lane_result_digest(result),
            committed_at_ms: result.committed_at_ms,
        })
    }

    /// Accepts only an exact same-operation, same-transcript, same-result redelivery.
    pub fn accepts_redelivery(
        &self,
        operation_id: &str,
        transcript: [u8; 32],
        result_digest: [u8; 32],
    ) -> bool {
        self.operation_id == operation_id
            && self.transcript == transcript
            && self.result_digest == result_digest
    }
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

fn validate_lane_package(
    package: &Ed25519YaoEncryptedPackageV1,
    kind: Ed25519YaoPackageKindV1,
    deriver: Ed25519YaoDeriverRoleV1,
    session: [u8; 32],
    transcript: [u8; 32],
) -> RouterAbProtocolResult<()> {
    package.validate()?;
    if package.kind() != kind
        || package.deriver() != deriver
        || package.session() != session
        || package.transcript() != transcript
    {
        return Err(invalid_execution(
            "lane recipient package binding is invalid",
        ));
    }
    Ok(())
}

fn decode_lane_digest(value: &str) -> RouterAbProtocolResult<[u8; 32]> {
    let mut decoded = [0_u8; 32];
    Base64UrlUnpadded::decode(value, &mut decoded)
        .map_err(|_| invalid_execution("lane base64url binding is invalid"))?;
    if decoded.iter().all(|byte| *byte == 0) {
        return Err(invalid_execution("lane binding is zero"));
    }
    Ok(decoded)
}

fn decode_commitment(
    bytes: [u8; 32],
) -> RouterAbProtocolResult<curve25519_dalek::edwards::EdwardsPoint> {
    let point = CompressedEdwardsY(bytes)
        .decompress()
        .ok_or_else(|| invalid_execution("lane commitment is not an Ed25519 point"))?;
    if point.compress().to_bytes() != bytes || point.is_small_order() || !point.is_torsion_free() {
        return Err(invalid_execution(
            "lane commitment encoding is not canonical",
        ));
    }
    Ok(point)
}

fn lane_public_identity_digest(
    transcript: [u8; 32],
    holder_commitment: [u8; 32],
    signing_worker_commitment: [u8; 32],
    registered_identity: &[u8],
) -> [u8; 32] {
    Sha256::new()
        .chain_update(b"seams/rotatable-signing-lanes/ed25519-public-relation/v1")
        .chain_update(transcript)
        .chain_update(holder_commitment)
        .chain_update(signing_worker_commitment)
        .chain_update(registered_identity)
        .finalize()
        .into()
}

fn lane_ciphertext_digest_set(
    recipient_domain: &[u8],
    deriver_a: &Ed25519YaoEncryptedPackageV1,
    deriver_b: &Ed25519YaoEncryptedPackageV1,
) -> [u8; 32] {
    Sha256::new()
        .chain_update(b"seams/rotatable-signing-lanes/ed25519-ciphertext-set/v1")
        .chain_update(recipient_domain)
        .chain_update([deriver_a.deriver().wire_tag()])
        .chain_update([deriver_a.kind().wire_tag()])
        .chain_update(deriver_a.encapsulated_key())
        .chain_update(deriver_a.ciphertext())
        .chain_update([deriver_b.deriver().wire_tag()])
        .chain_update([deriver_b.kind().wire_tag()])
        .chain_update(deriver_b.encapsulated_key())
        .chain_update(deriver_b.ciphertext())
        .finalize()
        .into()
}

fn lane_result_digest(result: &RouterAbEd25519YaoLaneResultV1) -> [u8; 32] {
    Sha256::new()
        .chain_update(b"seams/rotatable-signing-lanes/ed25519-result-commit/v1")
        .chain_update(result.job.operation_id.as_bytes())
        .chain_update(result.job.idempotency_key.as_bytes())
        .chain_update(result.transcript_hash_b64u.as_bytes())
        .chain_update(result.public_identity_digest_b64u.as_bytes())
        .chain_update(result.target_holder_public_commitment_b64u.as_bytes())
        .chain_update(result.target_server_public_commitment_b64u.as_bytes())
        .chain_update(result.target_holder_ciphertext_digest_set_b64u.as_bytes())
        .chain_update(result.target_server_ciphertext_digest_set_b64u.as_bytes())
        .chain_update(result.holder_recipient_key_digest_b64u.as_bytes())
        .chain_update(result.server_recipient_key_digest_b64u.as_bytes())
        .chain_update(result.committed_at_ms.to_be_bytes())
        .finalize()
        .into()
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
