use router_ab_core::{
    MpcPrfShareCommitmentWireV1, MpcPrfSigningRootShareWireV1,
    PendingTenantRootInitialRoleAttemptV1, RouterAbDerivationError, RouterAbDerivationErrorCode,
    RouterAbDerivationResult, TenantRootCeremonyContextV1, TenantRootCeremonyEpochsV1,
    TenantRootControlPlaneAuthorityIdV1, TenantRootCustodyLineageId, TenantRootIdentityDigestV1,
    TenantRootManagedBackupBindingV1, TenantRootManagedBackupSealRequestV1,
    TenantRootOnlineRoleShareBindingV1, TenantRootOnlineRoleShareSealRequestV1,
    TenantRootRoleCreationCommandPackageV1, TenantRootSealedOnlineRoleShareV1,
    TenantRootShareEpoch, TenantRootSignedCreationCommitmentV1,
    TenantRootSignedShareInstallationEvidenceV1, TwoPartyDeriverRole,
    VerifiedTenantRootCreationCommitmentPairV1, VerifiedTenantRootCreationCommitmentV1,
    VerifiedTenantRootInitialRoleAttemptV1, VerifiedTenantRootManagedBackupShareV1,
    VerifiedTenantRootManagedBackupV1, VerifiedTenantRootOnlineRoleShareV1,
    VerifiedTenantRootRoleCreationCommandV1,
    VerifiedTenantRootSignedShareInstallationEvidenceWireV1,
};
use zeroize::Zeroizing;

use crate::env::{
    CloudflareTenantRootControlPlaneIssuerVerifyingKeysV1,
    CloudflareTenantRootCreationRoleSignerV1, TenantRootCreationRoleVerifyingKeysV1,
};
use crate::{RouterAbProtocolError, RouterAbProtocolErrorCode, RouterAbProtocolResult};

/// Admits one issuer-signed role creation package at a Deriver's own boundary.
///
/// This is where a Deriver stops trusting its caller. The package arrived over
/// an internally authenticated hop, but internal-service auth proves only
/// "inside the deployment"; the authorization comes from the issuer signature,
/// checked here against this Worker's own configured anchor.
///
/// `worker_role` is the role this Worker *is*, taken from its own runtime, and
/// it is what the command must match. Passing the command's own role would make
/// the check vacuous and let a Deriver execute its peer's command.
///
/// On success the Deriver holds a live share it has committed to. The scalar
/// never leaves this process: only the signed public commitment does.
#[allow(clippy::too_many_arguments)]
pub(crate) fn admit_tenant_root_role_creation_package_v1<R>(
    package_bytes: &[u8],
    worker_role: TwoPartyDeriverRole,
    expected_authority_id: TenantRootControlPlaneAuthorityIdV1,
    trusted_issuer_keys: &CloudflareTenantRootControlPlaneIssuerVerifyingKeysV1,
    role_signer: &CloudflareTenantRootCreationRoleSignerV1,
    role_signing_key_bytes: &[u8; 32],
    now_ms: u64,
    rng: &mut R,
) -> RouterAbProtocolResult<PendingTenantRootInitialRoleAttemptV1>
where
    R: rand_core_06::RngCore + rand_core_06::CryptoRng,
{
    if role_signer.role() != worker_role {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ForbiddenLocalBinding,
            "tenant-root role signer does not belong to this Worker's role",
        ));
    }
    let package = TenantRootRoleCreationCommandPackageV1::decode_canonical_bytes(package_bytes)
        .map_err(candidate_derivation_error)?;
    // The trusted key is selected by the command's issuer key id but supplied by
    // this Worker's configuration: an unpublished issuer has no key here, so an
    // unsigned or foreign-signed package cannot proceed.
    let issuer_key_id = package.issuer_key_id().to_owned();
    let Some(trusted_key) = trusted_issuer_keys.for_issuer_key_id(&issuer_key_id) else {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ForbiddenLocalBinding,
            "tenant-root role creation command issuer is not trusted by this Worker",
        ));
    };
    let verified = package
        .verify(
            worker_role,
            expected_authority_id,
            &issuer_key_id,
            trusted_key,
        )
        .map_err(candidate_derivation_error)?;
    let context = verified.creation_context().clone();
    // The ceremony must name THIS Worker's signing key: a ceremony expecting a
    // different role signer is not one this Worker may execute.
    if context.signing_key_id(worker_role) != role_signer.signing_key_id() {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ForbiddenLocalBinding,
            "tenant-root ceremony does not name this Worker's role signing key",
        ));
    }
    let verifying_key = role_signer.verifying_key_bytes();
    PendingTenantRootInitialRoleAttemptV1::new(
        verified.into_command(),
        context,
        role_signing_key_bytes,
        &verifying_key,
        now_ms,
        rng,
    )
    .map_err(candidate_derivation_error)
}

fn candidate_derivation_error(error: RouterAbDerivationError) -> RouterAbProtocolError {
    RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::MalformedWirePayload,
        format!("tenant-root role creation package was refused: {error}"),
    )
}

/// The rendezvous outcome a Deriver receives back from the Router-owned object.
///
/// Public evidence only: two signed commitments and the pair digest the object
/// computed. Nothing here is role-private, which is why it may cross back to
/// the peer Deriver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TenantRootCreationCommitmentPairWiresV1 {
    pub(crate) deriver_a_signed_commitment: Vec<u8>,
    pub(crate) deriver_b_signed_commitment: Vec<u8>,
}

/// Finalizes this role's attempt against the completed commitment pair.
///
/// Both commitments are re-verified here against the ceremony context and the
/// published role keys. The Deriver does not trust the object's assembly of the
/// pair: it trusts the two role signatures, which the object cannot forge.
///
/// The peer's commitment is a public curve point. The scalar stays in this
/// process; what leaves is the signed installation evidence.
pub(crate) fn finalize_tenant_root_role_attempt_v1<R>(
    pending: PendingTenantRootInitialRoleAttemptV1,
    pair_wires: &TenantRootCreationCommitmentPairWiresV1,
    context: &TenantRootCeremonyContextV1,
    role_keys: &TenantRootCreationRoleVerifyingKeysV1,
    role_signing_key_bytes: &[u8; 32],
    rng: &mut R,
) -> RouterAbProtocolResult<VerifiedTenantRootInitialRoleAttemptV1>
where
    R: rand_core_06::RngCore + rand_core_06::CryptoRng,
{
    let verify_side = |bytes: &[u8],
                       role: TwoPartyDeriverRole|
     -> RouterAbProtocolResult<VerifiedTenantRootCreationCommitmentV1> {
        let signed = TenantRootSignedCreationCommitmentV1::decode_canonical_bytes(bytes)
            .map_err(candidate_derivation_error)?;
        let expected_key = role_keys
            .for_role_and_key_id(role, context.signing_key_id(role))
            .map_err(|_| {
                RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::ForbiddenLocalBinding,
                    "tenant-root ceremony names a role signing key that is not published",
                )
            })?;
        signed
            .verify_strict(context, role, context.signing_key_id(role), expected_key)
            .map_err(candidate_derivation_error)
    };
    let pair = VerifiedTenantRootCreationCommitmentPairV1::new(
        verify_side(
            &pair_wires.deriver_a_signed_commitment,
            TwoPartyDeriverRole::DeriverA,
        )?,
        verify_side(
            &pair_wires.deriver_b_signed_commitment,
            TwoPartyDeriverRole::DeriverB,
        )?,
    )
    .map_err(candidate_derivation_error)?;
    // finalize() independently requires the pair to contain THIS role's exact
    // commitment, so a pair assembled from someone else's ceremony is refused.
    pending
        .finalize(pair, role_signing_key_bytes, rng)
        .map_err(candidate_derivation_error)
}

/// Operations needed by one role-local online-share provider.
pub(crate) trait TenantRootOnlineRoleShareProviderV1 {
    fn seal_online_role_share(
        &mut self,
        request: &TenantRootOnlineRoleShareSealRequestV1,
    ) -> RouterAbDerivationResult<Vec<u8>>;

    fn open_online_role_share(
        &mut self,
        sealed: TenantRootSealedOnlineRoleShareV1,
    ) -> RouterAbDerivationResult<VerifiedTenantRootOnlineRoleShareV1>;
}

/// Operations needed by one role-local managed-backup provider.
pub(crate) trait TenantRootManagedBackupProviderV1 {
    fn seal_managed_backup(
        &mut self,
        request: &TenantRootManagedBackupSealRequestV1,
    ) -> RouterAbDerivationResult<Vec<u8>>;

    fn open_managed_backup(
        &mut self,
        backup: VerifiedTenantRootManagedBackupV1,
    ) -> RouterAbDerivationResult<VerifiedTenantRootManagedBackupShareV1>;
}

/// Provider references for one role-local ceremony attempt. The epoch is derived from evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TenantRootRoleRuntimeProviderConfigV1 {
    online_epoch_wrapping_key_ref: String,
    managed_backup_provider_id: String,
    managed_backup_key_version: String,
}

impl TenantRootRoleRuntimeProviderConfigV1 {
    pub(crate) fn new(
        online_epoch_wrapping_key_ref: impl Into<String>,
        managed_backup_provider_id: impl Into<String>,
        managed_backup_key_version: impl Into<String>,
    ) -> RouterAbDerivationResult<Self> {
        let config = Self {
            online_epoch_wrapping_key_ref: online_epoch_wrapping_key_ref.into(),
            managed_backup_provider_id: managed_backup_provider_id.into(),
            managed_backup_key_version: managed_backup_key_version.into(),
        };
        for (field, value) in [
            (
                "tenant-root online epoch wrapping-key reference",
                config.online_epoch_wrapping_key_ref.as_str(),
            ),
            (
                "tenant-root managed-backup provider id",
                config.managed_backup_provider_id.as_str(),
            ),
            (
                "tenant-root managed-backup key version",
                config.managed_backup_key_version.as_str(),
            ),
        ] {
            require_identifier(field, value)?;
        }
        Ok(config)
    }
}

/// Exact provider artifacts retained after one role-local attempt.
#[derive(Debug)]
pub(crate) struct TenantRootRoleRuntimeArtifactsV1 {
    online_sealed: TenantRootSealedOnlineRoleShareV1,
    managed_backup: VerifiedTenantRootManagedBackupV1,
}

impl TenantRootRoleRuntimeArtifactsV1 {
    pub(crate) const fn online_sealed(&self) -> &TenantRootSealedOnlineRoleShareV1 {
        &self.online_sealed
    }

    pub(crate) const fn managed_backup(&self) -> &VerifiedTenantRootManagedBackupV1 {
        &self.managed_backup
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        TenantRootSealedOnlineRoleShareV1,
        VerifiedTenantRootManagedBackupV1,
    ) {
        (self.online_sealed, self.managed_backup)
    }
}

/// Composes one verified initial role attempt through online and managed sealing.
#[allow(clippy::too_many_arguments)]
pub(crate) fn compose_initial_tenant_root_role_runtime_v1<Online, Backup>(
    attempt: VerifiedTenantRootInitialRoleAttemptV1,
    signer: &crate::CloudflareTenantRootCreationRoleSignerV1,
    provider_config: &TenantRootRoleRuntimeProviderConfigV1,
    online_provider: &mut Online,
    managed_backup_provider: &mut Backup,
) -> RouterAbDerivationResult<(
    VerifiedTenantRootRoleCreationCommandV1,
    VerifiedTenantRootSignedShareInstallationEvidenceWireV1,
    TenantRootRoleRuntimeArtifactsV1,
)>
where
    Online: TenantRootOnlineRoleShareProviderV1,
    Backup: TenantRootManagedBackupProviderV1,
{
    let (command, share_wire, evidence) = attempt.into_parts();
    let role = command.role();
    validate_attempt(
        role,
        command.identity_digest(),
        command.custody_lineage(),
        command.epoch(),
        &evidence,
        signer,
    )?;
    let share_commitment = MpcPrfShareCommitmentWireV1::new(
        evidence
            .evidence()
            .transcript()
            .commitment()
            .to_bytes()
            .to_vec(),
    )?;
    let online_binding = TenantRootOnlineRoleShareBindingV1::new(
        command.identity_digest(),
        command.custody_lineage(),
        role,
        command.epoch(),
        share_commitment,
        provider_config.online_epoch_wrapping_key_ref.clone(),
        &evidence,
    )?;
    let managed_share =
        MpcPrfSigningRootShareWireV1::new(Zeroizing::new(share_wire.to_bytes()).to_vec())?;
    let online_request = TenantRootOnlineRoleShareSealRequestV1::new(online_binding, share_wire)?;
    let online_ciphertext = online_provider.seal_online_role_share(&online_request)?;
    let online_sealed = online_request.complete(online_ciphertext)?;

    let context = evidence.evidence().transcript().context();
    let managed_binding = TenantRootManagedBackupBindingV1::from_verified_installation_evidence(
        &evidence,
        provider_config.managed_backup_provider_id.clone(),
        provider_config.managed_backup_key_version.clone(),
        signer.signing_key_id().to_owned(),
        context.issued_at_ms(),
    )?;
    let managed_request =
        TenantRootManagedBackupSealRequestV1::new(managed_binding.clone(), managed_share)?;
    let managed_ciphertext = managed_backup_provider.seal_managed_backup(&managed_request)?;
    let signed_backup = signer.sign_managed_backup(managed_request, managed_ciphertext)?;
    let managed_backup = signed_backup.verify(&managed_binding, &signer.verifying_key_bytes())?;
    let artifacts = TenantRootRoleRuntimeArtifactsV1 {
        online_sealed,
        managed_backup,
    };
    Ok((command, evidence, artifacts))
}

/// Opens an online artifact and re-verifies its role share commitment.
pub(crate) fn open_tenant_root_online_role_share_v1<Provider>(
    sealed: TenantRootSealedOnlineRoleShareV1,
    provider: &mut Provider,
) -> RouterAbDerivationResult<VerifiedTenantRootOnlineRoleShareV1>
where
    Provider: TenantRootOnlineRoleShareProviderV1,
{
    provider.open_online_role_share(sealed)
}

/// Opens a managed-backup artifact and re-verifies its role share commitment.
pub(crate) fn open_tenant_root_managed_backup_v1<Provider>(
    backup: VerifiedTenantRootManagedBackupV1,
    provider: &mut Provider,
) -> RouterAbDerivationResult<VerifiedTenantRootManagedBackupShareV1>
where
    Provider: TenantRootManagedBackupProviderV1,
{
    provider.open_managed_backup(backup)
}

fn validate_attempt(
    role: TwoPartyDeriverRole,
    identity_digest: TenantRootIdentityDigestV1,
    custody_lineage: TenantRootCustodyLineageId,
    epoch: TenantRootShareEpoch,
    evidence: &VerifiedTenantRootSignedShareInstallationEvidenceWireV1,
    signer: &crate::CloudflareTenantRootCreationRoleSignerV1,
) -> RouterAbDerivationResult<()> {
    let transcript = evidence.evidence().transcript();
    let context = transcript.context();
    let evidence_epoch = installation_epoch(context.epochs());
    if context.identity_digest() != identity_digest
        || context.custody_lineage() != custody_lineage
        || transcript.role() != role
        || evidence_epoch != epoch
        || signer.role() != role
        || signer.signing_key_id() != context.signing_key_id(role)
    {
        return Err(malformed(
            "tenant-root role attempt, installation evidence, and signer do not match",
        ));
    }
    TenantRootSignedShareInstallationEvidenceV1::decode_and_verify_canonical_bytes(
        evidence.canonical_bytes(),
        &signer.verifying_key_bytes(),
    )
    .map_err(|_| {
        malformed("tenant-root installation evidence does not verify with the constrained signer")
    })?;
    Ok(())
}

fn installation_epoch(epochs: TenantRootCeremonyEpochsV1) -> TenantRootShareEpoch {
    match epochs {
        TenantRootCeremonyEpochsV1::Create { next }
        | TenantRootCeremonyEpochsV1::Refresh { next, .. } => next,
    }
}

fn require_identifier(field: &'static str, value: &str) -> RouterAbDerivationResult<()> {
    if value.is_empty()
        || value.len() > 256
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(malformed(field));
    }
    Ok(())
}

fn malformed(message: &'static str) -> RouterAbDerivationError {
    RouterAbDerivationError::new(RouterAbDerivationErrorCode::MalformedInput, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use ed25519_dalek::SigningKey;
    use hpke_ng::{DhKemX25519HkdfSha256, Kem};
    use rand_chacha::ChaCha20Rng;
    use rand_core_06::SeedableRng;
    use router_ab_core::{
        verify_tenant_root_creation_evidence_v1, TenantRootCeremonyContextV1,
        TenantRootCeremonyNonceV1, TenantRootControlPlaneAuthorityIdV1,
        TenantRootCreationJournalV1, TenantRootCustodyLineageId, TenantRootIdentityV1,
        TenantRootRoleCreationCommandV1, TenantRootSignedCreationCommitmentV1,
        VerifiedTenantRootCreationCommitmentPairV1, VerifiedTenantRootCreationCommitmentV1,
    };
    use threshold_prf::SigningRootShareWire;

    use crate::tenant_root_operational_provider::CloudflareTenantRootOperationalRotationProviderV1;

    const ISSUER_KEY: [u8; 32] = [0x41; 32];
    const ISSUER_KEY_ID: &str = "tenant-root-issuer-v1";
    const ISSUED_AT_MS: u64 = 1_000_000;
    const EXPIRES_AT_MS: u64 = 1_030_000;
    const ONLINE_REF: &str = "online-key/tenant-7/epoch-1";
    const BACKUP_PROVIDER: &str = "backup-provider-a";
    const BACKUP_VERSION: &str = "backup-key-a/tenant-7/epoch-1";

    struct InMemoryProvider {
        online_share: Option<SigningRootShareWire>,
        managed_share: Option<MpcPrfSigningRootShareWireV1>,
        online_role: Option<TwoPartyDeriverRole>,
        backup_role: Option<router_ab_core::TenantRootManagedRestoreRoleV1>,
    }

    impl InMemoryProvider {
        fn new() -> Self {
            Self {
                online_share: None,
                managed_share: None,
                online_role: None,
                backup_role: None,
            }
        }
    }

    impl TenantRootOnlineRoleShareProviderV1 for InMemoryProvider {
        fn seal_online_role_share(
            &mut self,
            request: &TenantRootOnlineRoleShareSealRequestV1,
        ) -> RouterAbDerivationResult<Vec<u8>> {
            self.online_role = Some(request.binding().role());
            self.online_share = Some(request.share_wire().clone());
            Ok(vec![0xa5; 96])
        }

        fn open_online_role_share(
            &mut self,
            sealed: TenantRootSealedOnlineRoleShareV1,
        ) -> RouterAbDerivationResult<VerifiedTenantRootOnlineRoleShareV1> {
            let opened_share = self
                .online_share
                .clone()
                .ok_or_else(|| malformed("online share was not sealed"))?;
            sealed.verify_opened_share(opened_share)
        }
    }

    impl TenantRootManagedBackupProviderV1 for InMemoryProvider {
        fn seal_managed_backup(
            &mut self,
            request: &TenantRootManagedBackupSealRequestV1,
        ) -> RouterAbDerivationResult<Vec<u8>> {
            self.backup_role = Some(request.binding().role());
            self.managed_share = Some(MpcPrfSigningRootShareWireV1::new(
                request.plaintext_share().to_vec(),
            )?);
            Ok(vec![0xb5; 96])
        }

        fn open_managed_backup(
            &mut self,
            backup: VerifiedTenantRootManagedBackupV1,
        ) -> RouterAbDerivationResult<VerifiedTenantRootManagedBackupShareV1> {
            let opened_share = self
                .managed_share
                .clone()
                .ok_or_else(|| malformed("managed backup was not sealed"))?;
            backup.verify_opened_share(opened_share)
        }
    }

    pub(crate) fn identity() -> TenantRootIdentityV1 {
        TenantRootIdentityV1::new("org-1", "project-2", "production", "root-main", "v3")
            .expect("identity")
    }

    pub(crate) fn context() -> TenantRootCeremonyContextV1 {
        TenantRootCeremonyContextV1::new(
            identity().digest().expect("identity digest"),
            TenantRootCustodyLineageId::from_bytes([0x22; 16]).expect("lineage"),
            TenantRootCeremonyEpochsV1::create(),
            router_ab_core::TenantRootCeremonySessionIdV1::from_bytes([0x11; 16]).expect("session"),
            TenantRootCeremonyNonceV1::from_bytes([0x33; 32]).expect("nonce"),
            ISSUED_AT_MS,
            EXPIRES_AT_MS,
            "deriver-a-signing-key-7",
            "deriver-b-signing-key-9",
        )
        .expect("context")
    }

    pub(crate) fn role_key(role: TwoPartyDeriverRole) -> SigningKey {
        SigningKey::from_bytes(
            &[match role {
                TwoPartyDeriverRole::DeriverA => 0x51,
                TwoPartyDeriverRole::DeriverB => 0x61,
            }; 32],
        )
    }

    fn command(
        ceremony_context: &TenantRootCeremonyContextV1,
        role: TwoPartyDeriverRole,
    ) -> router_ab_core::VerifiedTenantRootRoleCreationCommandV1 {
        let journal = TenantRootCreationJournalV1::started(
            identity(),
            ceremony_context.custody_lineage(),
            ceremony_context.clone(),
        )
        .expect("journal");
        let signed = TenantRootRoleCreationCommandV1::sign(
            &journal,
            ceremony_context,
            role,
            TenantRootControlPlaneAuthorityIdV1::from_bytes([0x44; 32]),
            ISSUED_AT_MS + 1,
            EXPIRES_AT_MS - 1,
            ISSUER_KEY_ID,
            &ISSUER_KEY,
        )
        .expect("signed command");
        signed
            .verify(
                &journal,
                ceremony_context,
                role,
                TenantRootControlPlaneAuthorityIdV1::from_bytes([0x44; 32]),
                ISSUER_KEY_ID,
                &SigningKey::from_bytes(&ISSUER_KEY)
                    .verifying_key()
                    .to_bytes(),
            )
            .expect("verified command")
    }

    fn pending(
        ceremony_context: &TenantRootCeremonyContextV1,
        role: TwoPartyDeriverRole,
        seed: u8,
    ) -> router_ab_core::PendingTenantRootInitialRoleAttemptV1 {
        let key = role_key(role);
        router_ab_core::PendingTenantRootInitialRoleAttemptV1::new(
            command(ceremony_context, role),
            ceremony_context.clone(),
            &key.to_bytes(),
            &key.verifying_key().to_bytes(),
            ISSUED_AT_MS + 10,
            &mut ChaCha20Rng::from_seed([seed; 32]),
        )
        .expect("pending attempt")
    }

    fn verified_commitment(
        pending: &router_ab_core::PendingTenantRootInitialRoleAttemptV1,
    ) -> VerifiedTenantRootCreationCommitmentV1 {
        let role = pending.role();
        let key = role_key(role);
        TenantRootSignedCreationCommitmentV1::decode_and_verify_canonical_bytes(
            pending.commitment_bytes(),
            pending.commitment().context(),
            role,
            pending.commitment().context().signing_key_id(role),
            &key.verifying_key().to_bytes(),
        )
        .expect("verified commitment")
    }

    fn verified_commitment_bytes(
        bytes: &[u8],
        ceremony_context: &TenantRootCeremonyContextV1,
        role: TwoPartyDeriverRole,
    ) -> VerifiedTenantRootCreationCommitmentV1 {
        let key = role_key(role);
        TenantRootSignedCreationCommitmentV1::decode_and_verify_canonical_bytes(
            bytes,
            ceremony_context,
            role,
            ceremony_context.signing_key_id(role),
            &key.verifying_key().to_bytes(),
        )
        .expect("verified commitment bytes")
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    pub(crate) fn signer(
        role: TwoPartyDeriverRole,
    ) -> crate::CloudflareTenantRootCreationRoleSignerV1 {
        signer_with_keys(
            role,
            role_key(TwoPartyDeriverRole::DeriverA),
            role_key(TwoPartyDeriverRole::DeriverB),
        )
    }

    fn signer_with_keys(
        role: TwoPartyDeriverRole,
        key_a: SigningKey,
        key_b: SigningKey,
    ) -> crate::CloudflareTenantRootCreationRoleSignerV1 {
        let key_set = format!(
            r#"{{"keys":[{{"role":"deriver_a","signing_key_id":"deriver-a-signing-key-7","verifying_key_hex":"{}"}},{{"role":"deriver_b","signing_key_id":"deriver-b-signing-key-9","verifying_key_hex":"{}"}}]}}"#,
            hex(&key_a.verifying_key().to_bytes()),
            hex(&key_b.verifying_key().to_bytes()),
        );
        let (worker_role, binding_env, key_id_env, binding_name, key_id) = match role {
            TwoPartyDeriverRole::DeriverA => (
                crate::CloudflareWorkerRoleV1::DeriverA,
                crate::DERIVER_A_TENANT_ROOT_CREATION_SIGNING_KEY_BINDING_ENV,
                crate::DERIVER_A_TENANT_ROOT_CREATION_SIGNING_KEY_ID_ENV,
                "DERIVER_A_TENANT_ROOT_CREATION_SIGNING_KEY",
                "deriver-a-signing-key-7",
            ),
            TwoPartyDeriverRole::DeriverB => (
                crate::CloudflareWorkerRoleV1::DeriverB,
                crate::DERIVER_B_TENANT_ROOT_CREATION_SIGNING_KEY_BINDING_ENV,
                crate::DERIVER_B_TENANT_ROOT_CREATION_SIGNING_KEY_ID_ENV,
                "DERIVER_B_TENANT_ROOT_CREATION_SIGNING_KEY",
                "deriver-b-signing-key-9",
            ),
        };
        let key = match role {
            TwoPartyDeriverRole::DeriverA => key_a,
            TwoPartyDeriverRole::DeriverB => key_b,
        };
        let env = crate::CloudflareEnvMapV1::new(vec![
            (binding_env, binding_name),
            (key_id_env, key_id),
            (
                crate::ROUTER_TENANT_ROOT_CREATION_ROLE_VERIFYING_KEYS_JSON_ENV,
                key_set.as_str(),
            ),
        ]);
        let selection = crate::parse_cloudflare_tenant_root_creation_role_signing_key_selection_v1(
            worker_role,
            &env,
        )
        .expect("role signer selection");
        let secret = crate::decode_cloudflare_tenant_root_creation_role_signing_secret_v1(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key.to_bytes()),
        )
        .expect("role signer secret");
        crate::derive_cloudflare_tenant_root_creation_role_signing_key_v1(selection, secret)
            .expect("role signer")
    }

    fn operational_keypair(seed: u8) -> ([u8; 32], [u8; 32]) {
        let (private_key, public_key) =
            DhKemX25519HkdfSha256::derive_key_pair(&[seed; 32]).expect("operational key pair");
        let private_key_bytes = DhKemX25519HkdfSha256::sk_to_bytes(&private_key);
        let public_key_bytes = DhKemX25519HkdfSha256::pk_to_bytes(&public_key);
        let mut private_key_out = [0u8; 32];
        let mut public_key_out = [0u8; 32];
        private_key_out.copy_from_slice(&private_key_bytes);
        public_key_out.copy_from_slice(&public_key_bytes);
        (private_key_out, public_key_out)
    }

    fn operational_provider(
        role: TwoPartyDeriverRole,
        online_seed: u8,
        backup_seed: u8,
        online_ref: &str,
    ) -> CloudflareTenantRootOperationalRotationProviderV1 {
        let (online_secret, online_public) = operational_keypair(online_seed);
        let (backup_secret, backup_public) = operational_keypair(backup_seed);
        CloudflareTenantRootOperationalRotationProviderV1::new(
            role,
            online_ref,
            online_public,
            Zeroizing::new(online_secret.to_vec()),
            BACKUP_PROVIDER,
            BACKUP_VERSION,
            backup_public,
            Zeroizing::new(backup_secret.to_vec()),
        )
        .expect("operational provider")
    }

    #[test]
    fn initial_role_attempts_remain_live_through_pair_and_compose_both_roles() {
        let ceremony_context = context();
        let pending_a = pending(&ceremony_context, TwoPartyDeriverRole::DeriverA, 0x51);
        let pending_b = pending(&ceremony_context, TwoPartyDeriverRole::DeriverB, 0x61);

        let commitment_a_bytes = pending_a.commitment_bytes().to_vec();
        let commitment_b_bytes = pending_b.commitment_bytes().to_vec();
        let commitment_a = verified_commitment(&pending_a);
        assert_eq!(commitment_a.role(), TwoPartyDeriverRole::DeriverA);
        let commitment_b = verified_commitment(&pending_b);
        assert_eq!(commitment_b.role(), TwoPartyDeriverRole::DeriverB);
        let pair_a = VerifiedTenantRootCreationCommitmentPairV1::new(
            verified_commitment(&pending_a),
            verified_commitment(&pending_b),
        )
        .expect("A/B commitment pair");
        let pair_b = VerifiedTenantRootCreationCommitmentPairV1::new(
            verified_commitment_bytes(
                &commitment_a_bytes,
                &ceremony_context,
                TwoPartyDeriverRole::DeriverA,
            ),
            verified_commitment_bytes(
                &commitment_b_bytes,
                &ceremony_context,
                TwoPartyDeriverRole::DeriverB,
            ),
        )
        .expect("exact A/B commitment pair replay");
        assert_eq!(pair_a.canonical_bytes(), pair_b.canonical_bytes());
        assert_eq!(pair_a.pair_digest(), pair_b.pair_digest());

        let key_a = role_key(TwoPartyDeriverRole::DeriverA);
        let attempt_a = pending_a
            .finalize(
                pair_a,
                &key_a.to_bytes(),
                &mut ChaCha20Rng::from_seed([0x71; 32]),
            )
            .expect("Deriver A initial role attempt");
        let key_b = role_key(TwoPartyDeriverRole::DeriverB);
        let attempt_b = pending_b
            .finalize(
                pair_b,
                &key_b.to_bytes(),
                &mut ChaCha20Rng::from_seed([0x72; 32]),
            )
            .expect("Deriver B initial role attempt");

        let config =
            TenantRootRoleRuntimeProviderConfigV1::new(ONLINE_REF, BACKUP_PROVIDER, BACKUP_VERSION)
                .expect("provider config");
        let mut online_provider_a = InMemoryProvider::new();
        let mut backup_provider_a = InMemoryProvider::new();
        let (command_a, evidence_a, artifacts_a) = compose_initial_tenant_root_role_runtime_v1(
            attempt_a,
            &signer(TwoPartyDeriverRole::DeriverA),
            &config,
            &mut online_provider_a,
            &mut backup_provider_a,
        )
        .expect("composed Deriver A role runtime");
        let mut online_provider_b = InMemoryProvider::new();
        let mut backup_provider_b = InMemoryProvider::new();
        let (command_b, evidence_b, artifacts_b) = compose_initial_tenant_root_role_runtime_v1(
            attempt_b,
            &signer(TwoPartyDeriverRole::DeriverB),
            &config,
            &mut online_provider_b,
            &mut backup_provider_b,
        )
        .expect("composed Deriver B role runtime");

        assert_eq!(command_a.role(), TwoPartyDeriverRole::DeriverA);
        assert_eq!(command_b.role(), TwoPartyDeriverRole::DeriverB);
        assert_eq!(
            artifacts_a
                .online_sealed()
                .binding()
                .epoch_wrapping_key_ref(),
            ONLINE_REF
        );
        assert_eq!(
            artifacts_b.online_sealed().binding().epoch(),
            TenantRootShareEpoch::INITIAL
        );
        assert_eq!(
            artifacts_a.managed_backup().binding().backup_provider_id(),
            BACKUP_PROVIDER
        );
        assert_eq!(
            artifacts_b.managed_backup().binding().backup_key_version(),
            BACKUP_VERSION
        );
        assert_eq!(
            artifacts_a
                .managed_backup()
                .binding()
                .installation_receipt_digest(),
            evidence_a
                .lifecycle_receipt_digest()
                .expect("evidence digest")
        );
        assert_eq!(
            artifacts_b
                .managed_backup()
                .binding()
                .installation_receipt_digest(),
            evidence_b
                .lifecycle_receipt_digest()
                .expect("evidence digest")
        );
        assert_eq!(
            online_provider_a.online_role,
            Some(TwoPartyDeriverRole::DeriverA)
        );
        assert_eq!(
            backup_provider_a.backup_role,
            Some(router_ab_core::TenantRootManagedRestoreRoleV1::DeriverA)
        );
        assert_eq!(
            online_provider_b.online_role,
            Some(TwoPartyDeriverRole::DeriverB)
        );
        assert_eq!(
            backup_provider_b.backup_role,
            Some(router_ab_core::TenantRootManagedRestoreRoleV1::DeriverB)
        );

        let root_commitments =
            verify_tenant_root_creation_evidence_v1(evidence_a.evidence(), evidence_b.evidence())
                .expect("exact A/B installation evidence pair");
        assert_eq!(
            root_commitments.deriver_a(),
            evidence_a.evidence().transcript().commitment()
        );
        assert_eq!(
            root_commitments.deriver_b(),
            evidence_b.evidence().transcript().commitment()
        );
        assert_ne!(root_commitments.root().to_bytes(), [0; 32]);

        let (online_sealed, managed_backup) = artifacts_a.into_parts();
        let online_opened =
            open_tenant_root_online_role_share_v1(online_sealed, &mut online_provider_a)
                .expect("opened online share");
        let managed_opened =
            open_tenant_root_managed_backup_v1(managed_backup, &mut backup_provider_a)
                .expect("opened managed backup");
        assert_eq!(online_opened.role(), TwoPartyDeriverRole::DeriverA);
        assert_eq!(
            managed_opened.role(),
            router_ab_core::TenantRootManagedRestoreRoleV1::DeriverA
        );
        assert_eq!(
            online_opened.share_commitment(),
            managed_opened.share_commitment()
        );
        assert_eq!(
            online_opened.share_commitment().as_bytes(),
            root_commitments.deriver_a().to_bytes().as_slice()
        );

        let (online_sealed, managed_backup) = artifacts_b.into_parts();
        let online_opened =
            open_tenant_root_online_role_share_v1(online_sealed, &mut online_provider_b)
                .expect("opened online share");
        let managed_opened =
            open_tenant_root_managed_backup_v1(managed_backup, &mut backup_provider_b)
                .expect("opened managed backup");
        assert_eq!(online_opened.role(), TwoPartyDeriverRole::DeriverB);
        assert_eq!(
            managed_opened.role(),
            router_ab_core::TenantRootManagedRestoreRoleV1::DeriverB
        );
        assert_eq!(
            online_opened.share_commitment(),
            managed_opened.share_commitment()
        );
        assert_eq!(
            online_opened.share_commitment().as_bytes(),
            root_commitments.deriver_b().to_bytes().as_slice()
        );
    }

    #[test]
    fn compose_rejects_same_role_and_key_id_with_alternate_evidence_key() {
        let ceremony_context = context();
        let pending_a = pending(&ceremony_context, TwoPartyDeriverRole::DeriverA, 0x51);
        let pending_b = pending(&ceremony_context, TwoPartyDeriverRole::DeriverB, 0x61);
        let pair = VerifiedTenantRootCreationCommitmentPairV1::new(
            verified_commitment(&pending_a),
            verified_commitment(&pending_b),
        )
        .expect("A/B commitment pair");
        let key_a = role_key(TwoPartyDeriverRole::DeriverA);
        let attempt = pending_a
            .finalize(
                pair,
                &key_a.to_bytes(),
                &mut ChaCha20Rng::from_seed([0x73; 32]),
            )
            .expect("initial role attempt");
        let alternate_signer = signer_with_keys(
            TwoPartyDeriverRole::DeriverA,
            SigningKey::from_bytes(&[0x71; 32]),
            role_key(TwoPartyDeriverRole::DeriverB),
        );
        let config =
            TenantRootRoleRuntimeProviderConfigV1::new(ONLINE_REF, BACKUP_PROVIDER, BACKUP_VERSION)
                .expect("provider config");
        let mut online_provider = InMemoryProvider::new();
        let mut backup_provider = InMemoryProvider::new();
        let result = compose_initial_tenant_root_role_runtime_v1(
            attempt,
            &alternate_signer,
            &config,
            &mut online_provider,
            &mut backup_provider,
        );

        assert!(result.is_err());
        assert_eq!(online_provider.online_role, None);
        assert_eq!(backup_provider.backup_role, None);
    }

    #[test]
    fn operational_provider_roundtrip_and_rejections() {
        let ceremony_context = context();
        let pending_a = pending(&ceremony_context, TwoPartyDeriverRole::DeriverA, 0x51);
        let pending_b = pending(&ceremony_context, TwoPartyDeriverRole::DeriverB, 0x61);
        let pair = VerifiedTenantRootCreationCommitmentPairV1::new(
            verified_commitment(&pending_a),
            verified_commitment(&pending_b),
        )
        .expect("A/B commitment pair");
        let key_a = role_key(TwoPartyDeriverRole::DeriverA);
        let attempt = pending_a
            .finalize(
                pair,
                &key_a.to_bytes(),
                &mut ChaCha20Rng::from_seed([0x71; 32]),
            )
            .expect("initial role attempt");
        let config =
            TenantRootRoleRuntimeProviderConfigV1::new(ONLINE_REF, BACKUP_PROVIDER, BACKUP_VERSION)
                .expect("provider config");
        let mut online_provider =
            operational_provider(TwoPartyDeriverRole::DeriverA, 0x81, 0x82, ONLINE_REF);
        let mut backup_provider =
            operational_provider(TwoPartyDeriverRole::DeriverA, 0x81, 0x82, ONLINE_REF);
        let (_, _, artifacts) = compose_initial_tenant_root_role_runtime_v1(
            attempt,
            &signer(TwoPartyDeriverRole::DeriverA),
            &config,
            &mut online_provider,
            &mut backup_provider,
        )
        .expect("composed operational provider artifacts");
        let (online_sealed, managed_backup) = artifacts.into_parts();
        let managed_backup_bytes = managed_backup.canonical_bytes().to_vec();
        let managed_binding = managed_backup.binding().clone();
        let managed_verifying_key = signer(TwoPartyDeriverRole::DeriverA).verifying_key_bytes();

        let online_opened =
            open_tenant_root_online_role_share_v1(online_sealed.clone(), &mut online_provider)
                .expect("opened online share");
        let managed_opened =
            open_tenant_root_managed_backup_v1(managed_backup, &mut backup_provider)
                .expect("opened managed backup");
        assert_eq!(
            online_opened.share_commitment(),
            managed_opened.share_commitment()
        );

        let mut wrong_provider =
            operational_provider(TwoPartyDeriverRole::DeriverA, 0x91, 0x92, ONLINE_REF);
        assert!(
            open_tenant_root_online_role_share_v1(online_sealed, &mut wrong_provider).is_err(),
            "a ciphertext sealed to another provider key must not open"
        );

        let (reused_secret, reused_public) = operational_keypair(0xa1);
        assert!(CloudflareTenantRootOperationalRotationProviderV1::new(
            TwoPartyDeriverRole::DeriverA,
            ONLINE_REF,
            reused_public,
            Zeroizing::new(reused_secret.to_vec()),
            BACKUP_PROVIDER,
            BACKUP_VERSION,
            reused_public,
            Zeroizing::new(reused_secret.to_vec()),
        )
        .is_err());
        assert!(CloudflareTenantRootOperationalRotationProviderV1::new(
            TwoPartyDeriverRole::DeriverA,
            ONLINE_REF,
            operational_keypair(0xb1).1,
            Zeroizing::new(operational_keypair(0xb1).0.to_vec()),
            ONLINE_REF,
            BACKUP_VERSION,
            operational_keypair(0xb2).1,
            Zeroizing::new(operational_keypair(0xb2).0.to_vec()),
        )
        .is_err());

        let reconstructed_backup =
            router_ab_core::TenantRootSignedManagedBackupV1::decode_and_verify_canonical_bytes(
                &managed_backup_bytes,
                &managed_binding,
                &managed_verifying_key,
            )
            .expect("reconstruct managed backup after rejection checks");
        assert!(
            open_tenant_root_managed_backup_v1(reconstructed_backup, &mut wrong_provider).is_err(),
            "a managed backup sealed to another provider key must not open"
        );
    }
}

#[cfg(test)]
pub(crate) mod admission_tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand_chacha::ChaCha20Rng;
    use rand_core_06::SeedableRng;
    use router_ab_core::{
        TenantRootCeremonyContextV1, TenantRootCeremonyEpochsV1, TenantRootCeremonyNonceV1,
        TenantRootCeremonySessionIdV1, TenantRootCreationJournalV1, TenantRootCustodyLineageId,
        TenantRootIdentityV1, TenantRootRoleCreationCommandV1,
    };

    const ISSUER_KEY: [u8; 32] = [0x41; 32];
    const ISSUER_KEY_ID: &str = "tenant-root-issuer-v1";
    const FOREIGN_ISSUER_KEY: [u8; 32] = [0x42; 32];
    const ISSUED_AT_MS: u64 = 1_000_000;
    const EXPIRES_AT_MS: u64 = 1_030_000;
    const AUTHORITY: [u8; 32] = [0x44; 32];

    pub(crate) fn authority() -> TenantRootControlPlaneAuthorityIdV1 {
        TenantRootControlPlaneAuthorityIdV1::from_bytes(AUTHORITY)
    }

    pub(crate) fn identity() -> TenantRootIdentityV1 {
        TenantRootIdentityV1::new("org-1", "project-2", "production", "root-main", "v3")
            .expect("identity")
    }

    pub(crate) fn role_key(role: TwoPartyDeriverRole) -> SigningKey {
        SigningKey::from_bytes(&match role {
            TwoPartyDeriverRole::DeriverA => [0xa1; 32],
            TwoPartyDeriverRole::DeriverB => [0xb1; 32],
        })
    }

    pub(crate) fn signing_key_id(role: TwoPartyDeriverRole) -> &'static str {
        match role {
            TwoPartyDeriverRole::DeriverA => "deriver-a-signing-key-7",
            TwoPartyDeriverRole::DeriverB => "deriver-b-signing-key-9",
        }
    }

    pub(crate) fn context() -> TenantRootCeremonyContextV1 {
        TenantRootCeremonyContextV1::new(
            identity().digest().expect("identity digest"),
            TenantRootCustodyLineageId::from_bytes([0x22; 16]).expect("lineage"),
            TenantRootCeremonyEpochsV1::create(),
            TenantRootCeremonySessionIdV1::from_bytes([0x11; 16]).expect("session"),
            TenantRootCeremonyNonceV1::from_bytes([0x33; 32]).expect("nonce"),
            ISSUED_AT_MS,
            EXPIRES_AT_MS,
            signing_key_id(TwoPartyDeriverRole::DeriverA),
            signing_key_id(TwoPartyDeriverRole::DeriverB),
        )
        .expect("context")
    }

    /// A package exactly as it reaches a Deriver over the wire.
    pub(crate) fn package_bytes(role: TwoPartyDeriverRole, issuer_seed: &[u8; 32]) -> Vec<u8> {
        let context = context();
        let journal = TenantRootCreationJournalV1::started(
            identity(),
            context.custody_lineage(),
            context.clone(),
        )
        .expect("journal");
        let command = TenantRootRoleCreationCommandV1::sign(
            &journal,
            &context,
            role,
            authority(),
            ISSUED_AT_MS + 1,
            EXPIRES_AT_MS - 1,
            ISSUER_KEY_ID,
            issuer_seed,
        )
        .expect("signed command");
        TenantRootRoleCreationCommandPackageV1::new(journal, command)
            .expect("package")
            .canonical_bytes()
            .expect("package bytes")
    }

    pub(crate) fn trusted_issuer_keys() -> CloudflareTenantRootControlPlaneIssuerVerifyingKeysV1 {
        let hex: String = SigningKey::from_bytes(&ISSUER_KEY)
            .verifying_key()
            .to_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        CloudflareTenantRootControlPlaneIssuerVerifyingKeysV1::decode(&format!(
            "{{\"keys\":[{{\"issuer_key_id\":\"{ISSUER_KEY_ID}\",\"verifying_key_hex\":\"{hex}\"}}]}}"
        ))
        .expect("trusted issuer keys")
    }

    pub(crate) fn signer(role: TwoPartyDeriverRole) -> CloudflareTenantRootCreationRoleSignerV1 {
        crate::env::test_support_tenant_root_creation_role_signer_v1(
            role,
            signing_key_id(role),
            role_key(role),
        )
    }

    /// Admits a package for `role`.
    ///
    /// The seed is role-specific because each Deriver draws from its own RNG in
    /// production; a shared seed would make both roles commit to the same point,
    /// which the pair type correctly rejects as duplicate.
    pub(crate) fn admit_for(role: TwoPartyDeriverRole) -> PendingTenantRootInitialRoleAttemptV1 {
        admit_for_with_rng(
            role,
            match role {
                TwoPartyDeriverRole::DeriverA => 0x77,
                TwoPartyDeriverRole::DeriverB => 0x88,
            },
        )
    }

    /// Admits a package for `role` with an explicit RNG seed, so two runs of the
    /// same ceremony produce different shares.
    pub(crate) fn admit_for_with_rng(
        role: TwoPartyDeriverRole,
        seed: u8,
    ) -> PendingTenantRootInitialRoleAttemptV1 {
        admit_tenant_root_role_creation_package_v1(
            &package_bytes(role, &ISSUER_KEY),
            role,
            authority(),
            &trusted_issuer_keys(),
            &signer(role),
            &role_key(role).to_bytes(),
            ISSUED_AT_MS + 2,
            &mut ChaCha20Rng::from_seed([seed; 32]),
        )
        .expect("admitted")
    }

    pub(crate) fn test_context() -> TenantRootCeremonyContextV1 {
        context()
    }

    pub(crate) fn test_role_key(role: TwoPartyDeriverRole) -> SigningKey {
        role_key(role)
    }

    /// The published role keyset, matching the ceremony context's key IDs.
    pub(crate) fn test_role_keys() -> TenantRootCreationRoleVerifyingKeysV1 {
        let hex = |role: TwoPartyDeriverRole| -> String {
            role_key(role)
                .verifying_key()
                .to_bytes()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect()
        };
        crate::env::decode_role_verifying_keys(&format!(
            "{{\"keys\":[{{\"role\":\"deriver_a\",\"signing_key_id\":\"{}\",\"verifying_key_hex\":\"{}\"}},{{\"role\":\"deriver_b\",\"signing_key_id\":\"{}\",\"verifying_key_hex\":\"{}\"}}]}}",
            signing_key_id(TwoPartyDeriverRole::DeriverA),
            hex(TwoPartyDeriverRole::DeriverA),
            signing_key_id(TwoPartyDeriverRole::DeriverB),
            hex(TwoPartyDeriverRole::DeriverB),
        ))
        .expect("role keyset")
    }

    pub(crate) fn admit(
        bytes: &[u8],
        worker_role: TwoPartyDeriverRole,
        authority_id: TenantRootControlPlaneAuthorityIdV1,
        now_ms: u64,
    ) -> RouterAbProtocolResult<PendingTenantRootInitialRoleAttemptV1> {
        admit_tenant_root_role_creation_package_v1(
            bytes,
            worker_role,
            authority_id,
            &trusted_issuer_keys(),
            &signer(worker_role),
            &role_key(worker_role).to_bytes(),
            now_ms,
            &mut ChaCha20Rng::from_seed([0x77; 32]),
        )
    }

    /// The Deriver admits its own command and commits to a live share.
    #[test]
    fn a_deriver_admits_its_own_command_and_commits_to_a_share() {
        for role in [TwoPartyDeriverRole::DeriverA, TwoPartyDeriverRole::DeriverB] {
            let pending = admit(
                &package_bytes(role, &ISSUER_KEY),
                role,
                authority(),
                ISSUED_AT_MS + 2,
            )
            .expect("admitted");
            assert_eq!(pending.role(), role);
            // Only the signed public commitment leaves this process.
            assert!(!pending.commitment_bytes().is_empty());
            assert_eq!(pending.commitment().role(), role);
        }
    }

    /// The expected role comes from the Worker, so a Deriver cannot execute its
    /// peer's command even though both are issuer-signed.
    #[test]
    fn a_deriver_refuses_its_peers_command() {
        for (packaged, worker) in [
            (TwoPartyDeriverRole::DeriverA, TwoPartyDeriverRole::DeriverB),
            (TwoPartyDeriverRole::DeriverB, TwoPartyDeriverRole::DeriverA),
        ] {
            assert!(
                admit(
                    &package_bytes(packaged, &ISSUER_KEY),
                    worker,
                    authority(),
                    ISSUED_AT_MS + 2,
                )
                .is_err(),
                "{worker:?} must refuse a {packaged:?} command"
            );
        }
    }

    /// Internal-service auth proves only "inside the deployment"; authorization
    /// comes from the issuer signature checked against this Worker's anchor.
    #[test]
    fn a_deriver_refuses_a_package_from_an_untrusted_issuer() {
        let role = TwoPartyDeriverRole::DeriverA;
        assert_eq!(
            admit(
                &package_bytes(role, &FOREIGN_ISSUER_KEY),
                role,
                authority(),
                ISSUED_AT_MS + 2,
            )
            .expect_err("foreign issuer")
            .code(),
            RouterAbProtocolErrorCode::MalformedWirePayload
        );
    }

    #[test]
    fn a_deriver_refuses_a_foreign_authority_and_a_stale_command() {
        let role = TwoPartyDeriverRole::DeriverA;
        let bytes = package_bytes(role, &ISSUER_KEY);

        // An authority this Worker did not derive.
        assert!(admit(
            &bytes,
            role,
            TenantRootControlPlaneAuthorityIdV1::from_bytes([0x45; 32]),
            ISSUED_AT_MS + 2,
        )
        .is_err());

        // Outside the command's freshness window, at both edges.
        assert!(admit(&bytes, role, authority(), ISSUED_AT_MS).is_err());
        assert!(admit(&bytes, role, authority(), EXPIRES_AT_MS).is_err());
        assert!(admit(&bytes, role, authority(), ISSUED_AT_MS + 2).is_ok());
    }

    /// A Worker whose signer does not match its role, or whose role signing key
    /// the ceremony does not name, may not execute the ceremony.
    #[test]
    fn a_deriver_refuses_a_ceremony_that_does_not_name_its_signing_key() {
        let role = TwoPartyDeriverRole::DeriverA;
        let bytes = package_bytes(role, &ISSUER_KEY);
        let mismatched = crate::env::test_support_tenant_root_creation_role_signer_v1(
            role,
            "deriver-a-signing-key-rotated",
            role_key(role),
        );
        assert_eq!(
            admit_tenant_root_role_creation_package_v1(
                &bytes,
                role,
                authority(),
                &trusted_issuer_keys(),
                &mismatched,
                &role_key(role).to_bytes(),
                ISSUED_AT_MS + 2,
                &mut ChaCha20Rng::from_seed([0x77; 32]),
            )
            .expect_err("ceremony names a different signing key")
            .code(),
            RouterAbProtocolErrorCode::ForbiddenLocalBinding
        );

        // A signer belonging to the peer role is refused before anything else.
        assert_eq!(
            admit_tenant_root_role_creation_package_v1(
                &bytes,
                role,
                authority(),
                &trusted_issuer_keys(),
                &signer(TwoPartyDeriverRole::DeriverB),
                &role_key(role).to_bytes(),
                ISSUED_AT_MS + 2,
                &mut ChaCha20Rng::from_seed([0x77; 32]),
            )
            .expect_err("peer-role signer")
            .code(),
            RouterAbProtocolErrorCode::ForbiddenLocalBinding
        );
    }

    #[test]
    fn every_package_wire_mutation_is_refused_at_the_deriver() {
        let role = TwoPartyDeriverRole::DeriverA;
        let bytes = package_bytes(role, &ISSUER_KEY);
        for index in (0..bytes.len()).step_by(7) {
            let mut mutated = bytes.clone();
            mutated[index] ^= 0xff;
            assert!(
                admit(&mutated, role, authority(), ISSUED_AT_MS + 2).is_err(),
                "mutated byte {index} must be refused"
            );
        }
        assert!(admit(&[], role, authority(), ISSUED_AT_MS + 2).is_err());
    }
}

#[cfg(test)]
mod exchange_tests {
    use super::admission_tests::*;
    use super::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core_06::SeedableRng;

    fn rng(seed: u8) -> ChaCha20Rng {
        ChaCha20Rng::from_seed([seed; 32])
    }

    /// Both roles admit, exchange commitments, and finalize independently.
    fn run_exchange() -> (
        PendingTenantRootInitialRoleAttemptV1,
        PendingTenantRootInitialRoleAttemptV1,
        TenantRootCreationCommitmentPairWiresV1,
    ) {
        let a = admit_for(TwoPartyDeriverRole::DeriverA);
        let b = admit_for(TwoPartyDeriverRole::DeriverB);
        let wires = TenantRootCreationCommitmentPairWiresV1 {
            deriver_a_signed_commitment: a.commitment_bytes().to_vec(),
            deriver_b_signed_commitment: b.commitment_bytes().to_vec(),
        };
        (a, b, wires)
    }

    #[test]
    fn both_roles_finalize_against_the_same_commitment_pair() {
        let (a, b, wires) = run_exchange();
        for (pending, role) in [
            (a, TwoPartyDeriverRole::DeriverA),
            (b, TwoPartyDeriverRole::DeriverB),
        ] {
            let finalized = finalize_tenant_root_role_attempt_v1(
                pending,
                &wires,
                &test_context(),
                &test_role_keys(),
                &test_role_key(role).to_bytes(),
                &mut rng(0x91),
            )
            .expect("finalized");
            let (command, _share, evidence) = finalized.into_parts();
            assert_eq!(command.role(), role);
            assert!(!evidence.canonical_bytes().is_empty());
        }
    }

    /// A Deriver trusts the two role signatures, not the object's assembly, so
    /// a pair it did not participate in is refused.
    #[test]
    fn a_role_refuses_a_pair_that_does_not_contain_its_own_commitment() {
        let (a, _b, _wires) = run_exchange();
        // A second, independent ceremony run produces different commitments.
        let (other_a, other_b, _) = {
            let a2 = admit_for_with_rng(TwoPartyDeriverRole::DeriverA, 0x33);
            let b2 = admit_for_with_rng(TwoPartyDeriverRole::DeriverB, 0x44);
            let w = TenantRootCreationCommitmentPairWiresV1 {
                deriver_a_signed_commitment: a2.commitment_bytes().to_vec(),
                deriver_b_signed_commitment: b2.commitment_bytes().to_vec(),
            };
            (a2, b2, w)
        };
        let foreign = TenantRootCreationCommitmentPairWiresV1 {
            deriver_a_signed_commitment: other_a.commitment_bytes().to_vec(),
            deriver_b_signed_commitment: other_b.commitment_bytes().to_vec(),
        };
        assert!(
            finalize_tenant_root_role_attempt_v1(
                a,
                &foreign,
                &test_context(),
                &test_role_keys(),
                &test_role_key(TwoPartyDeriverRole::DeriverA).to_bytes(),
                &mut rng(0x91),
            )
            .is_err(),
            "a pair without this role's own commitment must be refused"
        );
    }

    #[test]
    fn swapped_or_duplicated_roles_in_the_pair_fail_closed() {
        let (a, _b, wires) = run_exchange();
        // Roles swapped: A's commitment presented as B's and vice versa.
        let swapped = TenantRootCreationCommitmentPairWiresV1 {
            deriver_a_signed_commitment: wires.deriver_b_signed_commitment.clone(),
            deriver_b_signed_commitment: wires.deriver_a_signed_commitment.clone(),
        };
        assert!(finalize_tenant_root_role_attempt_v1(
            a,
            &swapped,
            &test_context(),
            &test_role_keys(),
            &test_role_key(TwoPartyDeriverRole::DeriverA).to_bytes(),
            &mut rng(0x91),
        )
        .is_err());

        // One role's commitment duplicated into both positions.
        let (a2, _b2, wires2) = run_exchange();
        let duplicated = TenantRootCreationCommitmentPairWiresV1 {
            deriver_a_signed_commitment: wires2.deriver_a_signed_commitment.clone(),
            deriver_b_signed_commitment: wires2.deriver_a_signed_commitment.clone(),
        };
        assert!(finalize_tenant_root_role_attempt_v1(
            a2,
            &duplicated,
            &test_context(),
            &test_role_keys(),
            &test_role_key(TwoPartyDeriverRole::DeriverA).to_bytes(),
            &mut rng(0x91),
        )
        .is_err());
    }

    #[test]
    fn every_commitment_wire_mutation_fails_closed() {
        let (a, _b, wires) = run_exchange();
        let bytes = wires.deriver_b_signed_commitment.clone();
        for index in (0..bytes.len()).step_by(5) {
            let mut mutated = bytes.clone();
            mutated[index] ^= 0xff;
            let tampered = TenantRootCreationCommitmentPairWiresV1 {
                deriver_a_signed_commitment: wires.deriver_a_signed_commitment.clone(),
                deriver_b_signed_commitment: mutated,
            };
            assert!(
                finalize_tenant_root_role_attempt_v1(
                    admit_for(TwoPartyDeriverRole::DeriverA),
                    &tampered,
                    &test_context(),
                    &test_role_keys(),
                    &test_role_key(TwoPartyDeriverRole::DeriverA).to_bytes(),
                    &mut rng(0x91),
                )
                .is_err(),
                "mutated peer commitment byte {index} must be refused"
            );
        }
        drop(a);
    }

    /// Behavioural proof that no scalar reaches any wire that leaves a Deriver.
    ///
    /// Rather than scanning source text, this reconstructs the exact bytes that
    /// cross each boundary and asserts the secret share does not appear in any
    /// of them: the signed commitment sent to the object, the pair wires
    /// returned to the peer, and the signed installation evidence.
    #[test]
    fn no_wire_leaving_a_deriver_contains_the_secret_share() {
        let (a, b, wires) = run_exchange();

        // Recover each role's raw scalar bytes from the finalized attempt.
        let mut scalars: Vec<Vec<u8>> = Vec::new();
        let mut outbound: Vec<Vec<u8>> = vec![
            wires.deriver_a_signed_commitment.clone(),
            wires.deriver_b_signed_commitment.clone(),
        ];
        for (pending, role) in [
            (a, TwoPartyDeriverRole::DeriverA),
            (b, TwoPartyDeriverRole::DeriverB),
        ] {
            let finalized = finalize_tenant_root_role_attempt_v1(
                pending,
                &wires,
                &test_context(),
                &test_role_keys(),
                &test_role_key(role).to_bytes(),
                &mut rng(0x91),
            )
            .expect("finalized");
            let (_command, share_wire, evidence) = finalized.into_parts();
            scalars.push(share_wire.to_bytes().to_vec());
            // The signed installation evidence crosses to the object.
            outbound.push(evidence.canonical_bytes().to_vec());
        }

        assert_eq!(scalars.len(), 2);
        assert_ne!(scalars[0], scalars[1], "roles must hold distinct scalars");
        for share_wire_bytes in &scalars {
            // The share wire is a 2-byte share id followed by the 32-byte
            // scalar; search for the full wire AND the bare scalar, so a leak
            // that drops the prefix is still caught.
            assert_eq!(share_wire_bytes.len(), 34);
            let scalar = &share_wire_bytes[2..];
            assert_eq!(scalar.len(), 32);
            assert!(
                scalar.iter().any(|byte| *byte != 0),
                "a zero scalar would make this test vacuous"
            );
            for needle in [share_wire_bytes.as_slice(), scalar] {
                for (index, wire) in outbound.iter().enumerate() {
                    assert!(
                        !wire.windows(needle.len()).any(|window| window == needle),
                        "outbound wire {index} contains secret share material"
                    );
                }
            }
        }
    }
}
