#[cfg(any(feature = "workers-rs", test))]
use router_ab_core::MpcPrfSigningRootShareWireV1;
#[cfg(feature = "workers-rs")]
use router_ab_core::{
    MpcPrfShareCommitmentWireV1, TenantRootActivationReceiptTransitionV1,
    TenantRootCanaryCurveFamilyV1, TenantRootCeremonyNonceV1, TenantRootCeremonySessionIdV1,
    TenantRootCommandReplayKeyV1, TenantRootCommandScopeV1, TenantRootCommandTerminalReceiptV1,
    TenantRootEpochCommitmentsV1, TenantRootIdentityV1, TenantRootManagedBackupBindingV1,
    TenantRootManagedRestoreRoleV1, TenantRootOnlineRoleShareBindingV1,
    TenantRootProviderCanaryReceiptBindingV1, TenantRootRoleCleanupCommandV1,
    TenantRootSignedActivationReceiptV1, TenantRootSignedProviderCanaryReceiptV1,
    VerifiedTenantRootRoleCreationCommandV1, VerifiedTenantRootSignedActivationReceiptV1,
};
use router_ab_core::{
    PendingTenantRootInitialRoleAttemptV1, PendingTenantRootRefreshRoleAttemptV1,
    RouterAbDerivationError, RouterAbDerivationErrorCode, RouterAbDerivationResult,
    TenantRootActiveRoleBindingV1, TenantRootCeremonyContextV1, TenantRootCeremonyEpochsV1,
    TenantRootControlPlaneAuthorityIdV1, TenantRootCustodyLineageId, TenantRootIdentityDigestV1,
    TenantRootManagedBackupSealRequestV1, TenantRootOnlineRoleShareSealRequestV1,
    TenantRootRefreshHpkePublicKeyV1, TenantRootRoleCreationCommandPackageV1,
    TenantRootSealedOnlineRoleShareV1, TenantRootShareEpoch, TenantRootSignedCreationCommitmentV1,
    TenantRootSignedShareInstallationEvidenceV1, TwoPartyDeriverRole,
    VerifiedTenantRootCreationCommitmentPairV1, VerifiedTenantRootCreationCommitmentV1,
    VerifiedTenantRootInitialRoleAttemptV1, VerifiedTenantRootManagedBackupShareV1,
    VerifiedTenantRootManagedBackupV1, VerifiedTenantRootOnlineRoleShareV1,
    VerifiedTenantRootRoleCreationCommandPackageV1, VerifiedTenantRootRoleRefreshCommandV1,
    VerifiedTenantRootSignedShareInstallationEvidenceWireV1,
};
#[cfg(feature = "workers-rs")]
use router_ab_core::{
    VerifiedTenantRootRefreshCommitmentPairV1, VerifiedTenantRootRefreshRoleAttemptV1,
};
#[cfg(any(feature = "workers-rs", test))]
use zeroize::Zeroizing;

use threshold_prf::SigningRootShare;
#[cfg(feature = "workers-rs")]
use threshold_prf::{RootShareRefreshContributionWire, SigningRootShareWire};

#[cfg(feature = "workers-rs")]
use sha2::{Digest, Sha256};

#[cfg(feature = "workers-rs")]
use crate::durable_object::{
    execute_cloudflare_router_tenant_root_creation_commitment_call_v1,
    execute_cloudflare_router_tenant_root_creation_installation_call_v1,
};
use crate::env::{
    CloudflareTenantRootControlPlaneIssuerVerifyingKeysV1,
    CloudflareTenantRootCreationRoleSignerV1, TenantRootCreationRoleVerifyingKeysV1,
};
#[cfg(feature = "workers-rs")]
use crate::tenant_root_role_d1::{
    CloudflareStoredTenantRootRoleShareV1, CloudflareTenantRootActivateInitialPendingDecisionV1,
    CloudflareTenantRootActivationV1, CloudflareTenantRootDeriverRoleV1,
    CloudflareTenantRootInitialCreationInputV1,
    CloudflareTenantRootInitialCreationPersistenceOutcomeV1,
    CloudflareTenantRootInitialCreationPreflightV1,
    CloudflareTenantRootInitialCreationShareInputV1, CloudflareTenantRootRefreshInputV1,
    CloudflareTenantRootRefreshShareInputV1, CloudflareTenantRootRetirementV1,
    CloudflareTenantRootRoleShareLifecycleV1, CloudflareTenantRootRoleShareStoreV1,
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
pub(crate) fn verify_tenant_root_role_creation_package_v1(
    package_bytes: &[u8],
    worker_role: TwoPartyDeriverRole,
    expected_authority_id: TenantRootControlPlaneAuthorityIdV1,
    trusted_issuer_keys: &CloudflareTenantRootControlPlaneIssuerVerifyingKeysV1,
    role_signer: &CloudflareTenantRootCreationRoleSignerV1,
) -> RouterAbProtocolResult<VerifiedTenantRootRoleCreationCommandPackageV1> {
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
    Ok(verified)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn admit_tenant_root_role_creation_package_v1<R>(
    package_bytes: &[u8],
    worker_role: TwoPartyDeriverRole,
    expected_authority_id: TenantRootControlPlaneAuthorityIdV1,
    trusted_issuer_keys: &CloudflareTenantRootControlPlaneIssuerVerifyingKeysV1,
    role_signer: &CloudflareTenantRootCreationRoleSignerV1,
    now_ms: u64,
    rng: &mut R,
) -> RouterAbProtocolResult<PendingTenantRootInitialRoleAttemptV1>
where
    R: rand_core_06::RngCore + rand_core_06::CryptoRng,
{
    let verified = verify_tenant_root_role_creation_package_v1(
        package_bytes,
        worker_role,
        expected_authority_id,
        trusted_issuer_keys,
        role_signer,
    )?;
    let context = verified.creation_context().clone();
    role_signer
        .begin_initial_role_attempt(verified.into_command(), context, now_ms, rng)
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
    role_signer: &CloudflareTenantRootCreationRoleSignerV1,
    rng: &mut R,
) -> RouterAbProtocolResult<VerifiedTenantRootInitialRoleAttemptV1>
where
    R: rand_core_06::RngCore + rand_core_06::CryptoRng,
{
    let pair = VerifiedTenantRootCreationCommitmentPairV1::new(
        decode_verified_creation_commitment_v1(
            &pair_wires.deriver_a_signed_commitment,
            context,
            TwoPartyDeriverRole::DeriverA,
            role_keys,
        )?,
        decode_verified_creation_commitment_v1(
            &pair_wires.deriver_b_signed_commitment,
            context,
            TwoPartyDeriverRole::DeriverB,
            role_keys,
        )?,
    )
    .map_err(candidate_derivation_error)?;
    // finalize() independently requires the pair to contain THIS role's exact
    // commitment, so a pair assembled from someone else's ceremony is refused.
    role_signer
        .finalize_initial_role_attempt(pending, pair, rng)
        .map_err(candidate_derivation_error)
}

#[cfg(feature = "workers-rs")]
/// Seals a finalized role attempt and builds its role-local persistence input.
///
/// This is the last step before anything durable exists for this role. The
/// scalar is consumed here: it goes into the online provider's sealed
/// ciphertext and the managed backup, and neither the returned value nor
/// anything it contains carries it in the clear.
///
/// The returned input is not yet persisted. Reservation and insertion are
/// separate, one-use, and exactly retryable, so a lost response after sealing
/// re-reserves the same command rather than creating a second share.
#[cfg(feature = "workers-rs")]
pub(crate) fn seal_initial_role_creation_for_persistence_v1<Online, Backup>(
    finalized: VerifiedTenantRootInitialRoleAttemptV1,
    signer: &crate::CloudflareTenantRootCreationRoleSignerV1,
    provider_config: &TenantRootRoleRuntimeProviderConfigV1,
    online_provider: &mut Online,
    managed_backup_provider: &mut Backup,
    identity: TenantRootIdentityV1,
    staged_at_ms: u64,
) -> RouterAbProtocolResult<(
    CloudflareTenantRootInitialCreationInputV1,
    VerifiedTenantRootManagedBackupV1,
    Vec<u8>,
)>
where
    Online: TenantRootOnlineRoleShareProviderV1,
    Backup: TenantRootManagedBackupProviderV1,
{
    let (command, evidence, artifacts) = compose_initial_tenant_root_role_runtime_v1(
        finalized,
        signer,
        provider_config,
        online_provider,
        managed_backup_provider,
        staged_at_ms,
    )
    .map_err(candidate_derivation_error)?;
    // The command names the tenant; the caller's identity must be that tenant,
    // so a mis-supplied identity cannot seal a share under the wrong record.
    let identity_digest = identity.digest().map_err(candidate_derivation_error)?;
    if identity_digest != command.identity_digest() {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ForbiddenLocalBinding,
            "tenant-root sealing identity does not match its authorized command",
        ));
    }
    let (online_sealed, managed_backup, provider_canary_receipt) = artifacts.into_parts();
    let input = CloudflareTenantRootInitialCreationInputV1::new(
        command,
        evidence,
        CloudflareTenantRootInitialCreationShareInputV1::new(identity, online_sealed, staged_at_ms),
    )
    .map_err(|error| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("tenant-root role creation persistence input was refused: {error}"),
        )
    })?;
    Ok((input, managed_backup, provider_canary_receipt))
}

/// Maximum accepted request size for one Deriver creation call.
pub const DERIVER_TENANT_ROOT_CREATE_ROLE_SHARE_REQUEST_MAX_BYTES_V1: usize = 96 * 1024;
pub const DERIVER_TENANT_ROOT_CLEANUP_PENDING_REQUEST_MAX_BYTES_V1: usize = 24 * 1024;

/// Router -> Deriver: execute this role's part of one creation ceremony.
///
/// Everything here is issuer-signed or public. The Deriver derives its own
/// role, authority id, clock and signer locally, so nothing in this request
/// can select them.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CloudflareDeriverTenantRootCreateRoleShareRequestV1 {
    /// Router -> initiating Deriver: run both role legs in one request.
    Initiator {
        /// Exact canonical package for this Deriver's role, issuer-signed.
        role_creation_command_package_b64u: String,
        /// Exact canonical package to hand to the peer Deriver.
        peer_role_creation_command_package_b64u: String,
    },
    /// Initiating Deriver -> peer Deriver: complete against the initiator's
    /// public commitment while keeping this Deriver's share request-local.
    PeerCompletion {
        /// Exact canonical package for the peer's role, issuer-signed.
        role_creation_command_package_b64u: String,
        /// The initiating Deriver's signed public commitment.
        initiator_signed_commitment_b64u: String,
    },
}

/// Deriver -> caller: the completed role's public result.
///
/// Public authenticated artifacts only. No scalar or unwrapped share material
/// is named here. A managed backup remains opaque inside its signed artifact.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CloudflareDeriverTenantRootCreateRoleShareResponseV1 {
    Completed {
        /// The role that initiated this two-role completion, from its own runtime.
        role: CloudflareTenantRootCreateRoleV1,
        /// Deriver A's signed public commitment.
        deriver_a_signed_commitment_b64u: String,
        /// Deriver B's signed public commitment.
        deriver_b_signed_commitment_b64u: String,
        /// Deriver A's signed installation evidence.
        deriver_a_signed_installation_evidence_b64u: String,
        /// Deriver B's signed installation evidence.
        deriver_b_signed_installation_evidence_b64u: String,
        /// Deriver A's opaque signed managed-backup artifact.
        deriver_a_signed_managed_backup_b64u: String,
        /// Deriver B's opaque signed managed-backup artifact.
        deriver_b_signed_managed_backup_b64u: String,
        /// Deriver A's authenticated terminal receipt.
        deriver_a_terminal_receipt_b64u: String,
        /// Deriver B's authenticated terminal receipt.
        deriver_b_terminal_receipt_b64u: String,
        /// Deriver A's exact signed online-provider canary receipt.
        ecdsa_provider_canary_receipt_b64u: String,
        /// Deriver B's exact signed online-provider canary receipt.
        ed25519_provider_canary_receipt_b64u: String,
    },
    PeerCompleted {
        /// The role this Deriver executed, from its own runtime.
        role: CloudflareTenantRootCreateRoleV1,
        /// This role's signed public commitment.
        signed_commitment_b64u: String,
        /// This role's signed installation evidence.
        signed_installation_evidence_b64u: String,
        /// This role's opaque signed managed-backup artifact.
        signed_managed_backup_b64u: String,
        /// Authenticated terminal receipt for this role's insertion.
        terminal_receipt_b64u: String,
        /// This role's exact signed online-provider canary receipt.
        provider_canary_receipt_b64u: String,
    },
}

/// Control plane -> Deriver: remove one exact stranded pending role share.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareDeriverTenantRootCleanupPendingRequestV1 {
    /// Exact issuer-signed cleanup command. Its unverified target may only be
    /// used to locate the row; the Deriver verifies it against that row before deletion.
    pub cleanup_command_b64u: String,
}

/// Deriver -> Router: exact public receipt proving the role-local cleanup completed.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareDeriverTenantRootCleanupPendingResponseV1 {
    pub role: CloudflareTenantRootCreateRoleV1,
    pub cleanup_receipt_b64u: String,
}

/// Router -> Deriver: activate the exact pending role share named by the
/// control-plane receipt. All tenant, lineage, role, epoch and command scope
/// values are derived after signature verification.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareDeriverTenantRootInitialActivationRequestV1 {
    pub activation_receipt_b64u: String,
}

/// Deriver -> Router: authenticated completion of one role-local activation.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareDeriverTenantRootInitialActivationResponseV1 {
    pub role: CloudflareTenantRootCreateRoleV1,
    pub activation_terminal_receipt_b64u: String,
}

/// Control plane -> Deriver: activate one exact pending refresh epoch.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareDeriverTenantRootRefreshActivationRequestV1 {
    pub activation_receipt_b64u: String,
}

/// Deriver -> Router: authenticated completion of one role-local refresh swap.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareDeriverTenantRootRefreshActivationResponseV1 {
    pub role: CloudflareTenantRootCreateRoleV1,
    pub activation_terminal_receipt_b64u: String,
}

/// Role label on the Deriver creation wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CloudflareTenantRootCreateRoleV1 {
    DeriverA,
    DeriverB,
}

impl CloudflareTenantRootCreateRoleV1 {
    pub(crate) const fn from_protocol(role: TwoPartyDeriverRole) -> Self {
        match role {
            TwoPartyDeriverRole::DeriverA => Self::DeriverA,
            TwoPartyDeriverRole::DeriverB => Self::DeriverB,
        }
    }
}

/// One role's outcome for a creation ceremony, before any transport.
///
/// `Committed` is the first leg: this role holds a live share and has
/// published its commitment, but the pair is not complete, so nothing durable
/// exists yet and the attempt is abandonable by simply dropping it.
///
/// `Sealed` is the second leg: the pair completed, the share is sealed, and the
/// input is ready for the role's one-use reserve-and-insert.
// The sealed variant is boxed, but the committed variant deliberately is not:
// it holds the live share, and moving secret material onto the heap to satisfy
// a size lint would trade a zeroizing stack value for an allocation whose
// intermediate copies are harder to reason about.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub(crate) enum TenantRootRoleCreationProgressV1 {
    Committed {
        pending: PendingTenantRootInitialRoleAttemptV1,
    },
    #[cfg(feature = "workers-rs")]
    Sealed {
        signed_commitment: Vec<u8>,
        signed_installation_evidence: Vec<u8>,
        /// Boxed: the persistence input dwarfs the committed variant, and this
        /// enum is returned by value from every role execution.
        input: Box<CloudflareTenantRootInitialCreationInputV1>,
        managed_backup: Box<VerifiedTenantRootManagedBackupV1>,
        completion: TenantRootRoleCreationCompletionV1,
    },
}

/// Distinguishes a role-only completion from an initiator completion that also
/// retains the peer's exact public artifacts for the Router activation call.
#[cfg(feature = "workers-rs")]
#[derive(Debug)]
pub(crate) enum TenantRootRoleCreationCompletionV1 {
    RoleOnly {
        provider_canary_receipt: Vec<u8>,
    },
    Initiator {
        provider_canary_receipt: Vec<u8>,
        peer: Box<TenantRootPeerRoleOutcomeV1>,
    },
}

/// One role's outcome for a refresh ceremony, before persistence.
// The committed variant owns the coefficient and current share; the sealed
// variant owns the provider-backed pending-row input after finalization.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub(crate) enum TenantRootRoleRefreshProgressV1 {
    Committed {
        pending: PendingTenantRootRefreshRoleAttemptV1,
    },
    #[cfg(feature = "workers-rs")]
    Sealed {
        signed_commitment: Vec<u8>,
        signed_installation_evidence: Vec<u8>,
        input: Box<CloudflareTenantRootRefreshInputV1>,
        managed_backup: Box<VerifiedTenantRootManagedBackupV1>,
        provider_canary_receipt: Vec<u8>,
    },
}

/// Starts one role-local refresh attempt from already-verified public state
/// and the provider-opened current share.
#[allow(clippy::too_many_arguments)]
pub(crate) fn begin_tenant_root_role_refresh_v1<R>(
    command: VerifiedTenantRootRoleRefreshCommandV1,
    context: TenantRootCeremonyContextV1,
    active_binding: TenantRootActiveRoleBindingV1,
    current_share: SigningRootShare,
    role_signing_key_bytes: &[u8; 32],
    expected_role_verifying_key_bytes: &[u8; 32],
    recipient_key_id: impl Into<String>,
    recipient_public_key: TenantRootRefreshHpkePublicKeyV1,
    now_ms: u64,
    rng: &mut R,
) -> RouterAbProtocolResult<TenantRootRoleRefreshProgressV1>
where
    R: rand_core_06::RngCore + rand_core_06::CryptoRng,
{
    let pending = PendingTenantRootRefreshRoleAttemptV1::new(
        command,
        context,
        active_binding,
        current_share,
        role_signing_key_bytes,
        expected_role_verifying_key_bytes,
        recipient_key_id,
        recipient_public_key,
        now_ms,
        rng,
    )
    .map_err(candidate_derivation_error)?;
    Ok(TenantRootRoleRefreshProgressV1::Committed { pending })
}

/// Finalizes a live refresh attempt and seals its next-epoch share for the
/// role-private pending-row insertion path.
#[cfg(feature = "workers-rs")]
#[allow(clippy::too_many_arguments)]
pub(crate) fn finalize_tenant_root_role_refresh_v1<Online, Backup, R>(
    pending: PendingTenantRootRefreshRoleAttemptV1,
    commitment_pair: VerifiedTenantRootRefreshCommitmentPairV1,
    peer_contribution: RootShareRefreshContributionWire,
    role_signer: &crate::CloudflareTenantRootCreationRoleSignerV1,
    identity: TenantRootIdentityV1,
    provider_config: &TenantRootRoleRuntimeProviderConfigV1,
    online_provider: &mut Online,
    managed_backup_provider: &mut Backup,
    staged_at_ms: u64,
    rng: &mut R,
) -> RouterAbProtocolResult<TenantRootRoleRefreshProgressV1>
where
    Online: TenantRootOnlineRoleShareProviderV1,
    Backup: TenantRootManagedBackupProviderV1,
    R: rand_core_06::RngCore + rand_core_06::CryptoRng,
{
    let signed_commitment = pending.commitment_bytes().to_vec();
    let finalized = pending
        .finalize(commitment_pair, peer_contribution, rng)
        .map_err(candidate_derivation_error)?;
    let (input, managed_backup, provider_canary_receipt) = seal_refresh_role_for_persistence_v1(
        finalized,
        role_signer,
        identity,
        provider_config,
        online_provider,
        managed_backup_provider,
        staged_at_ms,
    )?;
    let signed_installation_evidence = input.installation_evidence_bytes().to_vec();
    Ok(TenantRootRoleRefreshProgressV1::Sealed {
        signed_commitment,
        signed_installation_evidence,
        input: Box::new(input),
        managed_backup: Box::new(managed_backup),
        provider_canary_receipt,
    })
}

/// Executes one role's part of a creation ceremony.
///
/// `worker_role` and `expected_authority_id` come from the Worker's own
/// runtime and Durable Object binding; `role_signer` is its own configured
/// signer. None of them may be taken from the request, which is why they are
/// arguments rather than fields of the decoded package.
///
/// With no peer commitment this returns `Committed`: the role generates and
/// commits, and its commitment goes back so the peer can be driven. With the
/// peer's commitment it finalizes and seals in the same call, so the scalar
/// never has to survive across a request boundary.
#[cfg(feature = "workers-rs")]
#[allow(clippy::too_many_arguments)]
pub(crate) fn execute_tenant_root_role_creation_v1<Online, Backup, R>(
    package_bytes: &[u8],
    peer_signed_commitment: Option<&[u8]>,
    worker_role: TwoPartyDeriverRole,
    expected_authority_id: TenantRootControlPlaneAuthorityIdV1,
    trusted_issuer_keys: &CloudflareTenantRootControlPlaneIssuerVerifyingKeysV1,
    role_keys: &TenantRootCreationRoleVerifyingKeysV1,
    role_signer: &crate::CloudflareTenantRootCreationRoleSignerV1,
    provider_config: &TenantRootRoleRuntimeProviderConfigV1,
    online_provider: &mut Online,
    managed_backup_provider: &mut Backup,
    now_ms: u64,
    rng: &mut R,
) -> RouterAbProtocolResult<TenantRootRoleCreationProgressV1>
where
    Online: TenantRootOnlineRoleShareProviderV1,
    Backup: TenantRootManagedBackupProviderV1,
    R: rand_core_06::RngCore + rand_core_06::CryptoRng,
{
    let pending = admit_tenant_root_role_creation_package_v1(
        package_bytes,
        worker_role,
        expected_authority_id,
        trusted_issuer_keys,
        role_signer,
        now_ms,
        rng,
    )?;
    let Some(peer_signed_commitment) = peer_signed_commitment else {
        return Ok(TenantRootRoleCreationProgressV1::Committed { pending });
    };

    // The identity comes from the package's own Started journal, which the
    // issuer signature already commits to; it is never a request field.
    let package = TenantRootRoleCreationCommandPackageV1::decode_canonical_bytes(package_bytes)
        .map_err(candidate_derivation_error)?;
    let identity = package.identity().map_err(candidate_derivation_error)?;

    let signed_commitment = pending.commitment_bytes().to_vec();
    let context = pending.commitment().context().clone();
    let pair_wires = match worker_role {
        TwoPartyDeriverRole::DeriverA => TenantRootCreationCommitmentPairWiresV1 {
            deriver_a_signed_commitment: signed_commitment.clone(),
            deriver_b_signed_commitment: peer_signed_commitment.to_vec(),
        },
        TwoPartyDeriverRole::DeriverB => TenantRootCreationCommitmentPairWiresV1 {
            deriver_a_signed_commitment: peer_signed_commitment.to_vec(),
            deriver_b_signed_commitment: signed_commitment.clone(),
        },
    };
    let finalized = finalize_tenant_root_role_attempt_v1(
        pending,
        &pair_wires,
        &context,
        role_keys,
        role_signer,
        rng,
    )?;
    let (input, managed_backup, provider_canary_receipt) =
        seal_initial_role_creation_for_persistence_v1(
            finalized,
            role_signer,
            provider_config,
            online_provider,
            managed_backup_provider,
            identity,
            now_ms,
        )?;
    let signed_installation_evidence = input.installation_evidence_bytes().to_vec();
    Ok(TenantRootRoleCreationProgressV1::Sealed {
        signed_commitment,
        signed_installation_evidence,
        input: Box::new(input),
        managed_backup: Box::new(managed_backup),
        completion: TenantRootRoleCreationCompletionV1::RoleOnly {
            provider_canary_receipt,
        },
    })
}

/// Recovers the committed point from a signed commitment wire.
#[cfg(feature = "workers-rs")]
fn decode_signed_commitment_point(
    signed_commitment: &[u8],
    context: &TenantRootCeremonyContextV1,
    role: TwoPartyDeriverRole,
    role_keys: &TenantRootCreationRoleVerifyingKeysV1,
) -> RouterAbProtocolResult<threshold_prf::SigningRootShareCommitment> {
    Ok(
        decode_verified_creation_commitment_v1(signed_commitment, context, role, role_keys)?
            .commitment(),
    )
}

/// Strictly verifies one exact signed commitment before it reaches either
/// local persistence or the Router-owned checkpoint.
fn decode_verified_creation_commitment_v1(
    signed_commitment: &[u8],
    context: &TenantRootCeremonyContextV1,
    role: TwoPartyDeriverRole,
    role_keys: &TenantRootCreationRoleVerifyingKeysV1,
) -> RouterAbProtocolResult<VerifiedTenantRootCreationCommitmentV1> {
    let signing_key_id = context.signing_key_id(role);
    let trusted = role_keys
        .for_role_and_key_id(role, signing_key_id)
        .map_err(|_| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ForbiddenLocalBinding,
                "tenant-root ceremony names a signing key that is not published",
            )
        })?;
    let signed = TenantRootSignedCreationCommitmentV1::decode_canonical_bytes(signed_commitment)
        .map_err(candidate_derivation_error)?;
    signed
        .verify_strict(context, role, signing_key_id, trusted)
        .map_err(candidate_derivation_error)
}

/// A verified role attestation that the peer completed its own insertion.
///
/// This is the peer's signed statement, checked against expectations the
/// verifier derived independently. It is NOT independent proof of the peer's
/// D1 state: only the peer can observe its own store. A peer whose role key is
/// compromised can attest an insertion that did not happen, which is why the
/// role signing keys are role-local and never leave their Deriver.
///
/// Deliberately neither cloneable nor serializable: it is a conclusion reached
/// locally from verified bytes, not a value to forward.
#[cfg(feature = "workers-rs")]
pub(crate) struct VerifiedTenantRootPeerPersistenceAttestationV1 {
    peer_role: TwoPartyDeriverRole,
}

#[cfg(feature = "workers-rs")]
impl VerifiedTenantRootPeerPersistenceAttestationV1 {
    pub(crate) const fn peer_role(&self) -> TwoPartyDeriverRole {
        self.peer_role
    }
}

/// Verifies a peer's terminal receipt using only public expectations.
///
/// The security split is deliberate. The peer verifies the full command digest
/// locally against its own `ExecutedTenantRootCommandV1`, because that digest
/// covers the peer's sealed record and is role-private. The verifier here
/// checks the public attestation instead: the exact replay key, the exact
/// installation-evidence bytes, the expected role and signing key id, the role
/// signature, and the ceremony timing.
///
/// The peer's issuer-signed package yields the replay key. It does not yield
/// the command digest, and this function does not attempt to derive one.
/// Requiring that would either expose the peer's private ciphertext inputs or
/// introduce a second public command digest with overlapping semantics.
///
/// The payload binding is what constrains the receipt: it must attest exactly
/// this installation, not another operation by the same role in the ceremony.
#[cfg(feature = "workers-rs")]
#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_tenant_root_peer_persistence_v1(
    terminal_receipt_bytes: &[u8],
    peer_package_bytes: &[u8],
    peer_signed_installation_evidence: &[u8],
    peer_role: TwoPartyDeriverRole,
    expected_authority_id: TenantRootControlPlaneAuthorityIdV1,
    trusted_issuer_keys: &CloudflareTenantRootControlPlaneIssuerVerifyingKeysV1,
    role_keys: &TenantRootCreationRoleVerifyingKeysV1,
    context: &TenantRootCeremonyContextV1,
) -> RouterAbProtocolResult<VerifiedTenantRootPeerPersistenceAttestationV1> {
    let peer_package =
        TenantRootRoleCreationCommandPackageV1::decode_canonical_bytes(peer_package_bytes)
            .map_err(candidate_derivation_error)?;
    let issuer_key_id = peer_package.issuer_key_id().to_owned();
    let Some(trusted_issuer_key) = trusted_issuer_keys.for_issuer_key_id(&issuer_key_id) else {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ForbiddenLocalBinding,
            "tenant-root peer command issuer is not trusted by this Worker",
        ));
    };
    if peer_package
        .creation_context()
        .map_err(candidate_derivation_error)?
        != *context
    {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ForbiddenLocalBinding,
            "tenant-root peer command belongs to a different ceremony",
        ));
    }
    let peer_command = peer_package
        .verify(
            peer_role,
            expected_authority_id,
            &issuer_key_id,
            trusted_issuer_key,
        )
        .map_err(candidate_derivation_error)?
        .into_command();

    let signing_key_id = context.signing_key_id(peer_role);
    let trusted_role_key = role_keys
        .for_role_and_key_id(peer_role, signing_key_id)
        .map_err(|_| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ForbiddenLocalBinding,
                "tenant-root ceremony names a peer signing key that is not published",
            )
        })?;

    // A failure receipt is not persistence: only the success variant attests
    // that the peer's insertion completed.
    let TenantRootCommandTerminalReceiptV1::Success(receipt) =
        TenantRootCommandTerminalReceiptV1::decode_canonical_bytes(terminal_receipt_bytes)
            .map_err(candidate_derivation_error)?
    else {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ForbiddenLocalBinding,
            "tenant-root peer returned a failure receipt, which is not persistence",
        ));
    };
    receipt
        .verify_remote_public(
            peer_command.scope().key(),
            peer_signed_installation_evidence,
            context.issued_at_ms(),
            signing_key_id,
            trusted_role_key,
        )
        .map_err(candidate_derivation_error)?;
    Ok(VerifiedTenantRootPeerPersistenceAttestationV1 { peer_role })
}

/// Drives the peer Deriver over a service binding.
///
/// Async because the real call is a Worker-to-Worker service binding and must
/// be awaited. Modelled as a trait so the initiating role's orchestration is
/// testable without a Worker, and so only bytes ever cross to the peer.
#[cfg(feature = "workers-rs")]
pub(crate) trait TenantRootPeerRoleDriverV1 {
    /// Hands the peer everything it needs and receives its public result.
    ///
    /// The peer receives its command package and the initiator's exact signed
    /// commitment. It cannot recompute that commitment: the initiator's share is
    /// random and lives only in the initiator's process, so the commitment has
    /// to travel.
    async fn drive_peer(
        &mut self,
        peer_package_bytes: &[u8],
        initiator_signed_commitment: &[u8],
    ) -> RouterAbProtocolResult<TenantRootPeerRoleOutcomeV1>;
}

/// What the peer returns: authenticated public bytes only.
///
/// Deliberately not a "persisted" boolean. A boolean is the peer's own claim and
/// admits states that never happened; these are artifacts the initiator can
/// check against the ceremony it is already party to.
#[cfg(feature = "workers-rs")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TenantRootPeerRoleOutcomeV1 {
    /// The peer's signed public commitment.
    pub(crate) signed_commitment: Vec<u8>,
    /// The peer's signed installation evidence, which the initiator verifies.
    pub(crate) signed_installation_evidence: Vec<u8>,
    /// The peer's opaque signed managed-backup artifact.
    pub(crate) signed_managed_backup: Vec<u8>,
    /// The peer's exact signed online-provider canary receipt.
    pub(crate) provider_canary_receipt: Vec<u8>,
    /// The peer's role-signed terminal receipt for its own insertion.
    ///
    /// Fully verified by the initiator against expectations it computes from
    /// public material: the peer's own issuer-signed package yields the replay
    /// key, and the ceremony yields the signing key id, trusted verifying key,
    /// and earliest legitimate terminal time.
    pub(crate) terminal_receipt: Vec<u8>,
}

/// Runs the initiating role's ceremony without ever parking its scalar.
///
/// The initiating role commits, drives the peer, and finalizes inside a single
/// invocation. Its share is random, so it cannot be regenerated on a later
/// request: parking the commitment durably and returning would strand a
/// ceremony whose scalar no longer exists. Holding the request open for the
/// peer call is what makes the share's lifetime equal to this function's.
///
/// If the peer call fails, or the peer's commitment does not complete the
/// pair, this returns an error and the share is dropped. Nothing durable was
/// written for the initiating role, so the attempt is abandoned by returning.
#[cfg(feature = "workers-rs")]
#[allow(clippy::too_many_arguments)]
pub(crate) async fn drive_tenant_root_role_creation_as_initiator_v1<Online, Backup, Peer, R>(
    package_bytes: &[u8],
    peer_package_bytes: &[u8],
    worker_role: TwoPartyDeriverRole,
    expected_authority_id: TenantRootControlPlaneAuthorityIdV1,
    trusted_issuer_keys: &CloudflareTenantRootControlPlaneIssuerVerifyingKeysV1,
    role_keys: &TenantRootCreationRoleVerifyingKeysV1,
    role_signer: &crate::CloudflareTenantRootCreationRoleSignerV1,
    provider_config: &TenantRootRoleRuntimeProviderConfigV1,
    online_provider: &mut Online,
    managed_backup_provider: &mut Backup,
    peer: &mut Peer,
    now_ms: u64,
    rng: &mut R,
) -> RouterAbProtocolResult<TenantRootRoleCreationProgressV1>
where
    Online: TenantRootOnlineRoleShareProviderV1,
    Backup: TenantRootManagedBackupProviderV1,
    Peer: TenantRootPeerRoleDriverV1,
    R: rand_core_06::RngCore + rand_core_06::CryptoRng,
{
    // Commit first, so the peer is only ever driven for a ceremony this role
    // has already been authorized to execute.
    let pending = admit_tenant_root_role_creation_package_v1(
        package_bytes,
        worker_role,
        expected_authority_id,
        trusted_issuer_keys,
        role_signer,
        now_ms,
        rng,
    )?;
    let signed_commitment = pending.commitment_bytes().to_vec();
    let context = pending.commitment().context().clone();

    // The share stays on this stack for exactly the span of the peer call. The
    // peer receives the initiator's exact commitment because it cannot derive
    // it: that share exists only here.
    let peer_outcome = peer
        .drive_peer(peer_package_bytes, &signed_commitment)
        .await?;
    let peer_role = worker_role.peer();
    let peer_verifying_key = role_keys
        .for_role_and_key_id(peer_role, context.signing_key_id(peer_role))
        .map_err(|_| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ForbiddenLocalBinding,
                "tenant-root ceremony names a peer signing key that is not published",
            )
        })?;
    let peer_evidence =
        TenantRootSignedShareInstallationEvidenceV1::decode_and_verify_canonical_bytes(
            &peer_outcome.signed_installation_evidence,
            peer_verifying_key,
        )
        .map_err(candidate_derivation_error)?;
    let peer_transcript = peer_evidence.evidence().transcript();
    if peer_transcript.role() != peer_role || peer_transcript.context() != &context {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ForbiddenLocalBinding,
            "tenant-root peer installation evidence belongs to a different ceremony",
        ));
    }
    // Bind the evidence to the exact pair. A valid peer signature over some
    // OTHER pair satisfies every check above but attests a different ceremony
    // outcome.
    let initiator_commitment =
        decode_signed_commitment_point(&signed_commitment, &context, worker_role, role_keys)?;
    let peer_commitment_point = decode_signed_commitment_point(
        &peer_outcome.signed_commitment,
        &context,
        peer_role,
        role_keys,
    )?;
    if peer_transcript.commitment() != peer_commitment_point
        || peer_transcript.peer_commitment() != initiator_commitment
    {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ForbiddenLocalBinding,
            "tenant-root peer installation evidence is not bound to this commitment pair",
        ));
    }
    // The peer's persistence is a verified conclusion, not a reported claim.
    let _peer_persistence = verify_tenant_root_peer_persistence_v1(
        &peer_outcome.terminal_receipt,
        peer_package_bytes,
        &peer_outcome.signed_installation_evidence,
        peer_role,
        expected_authority_id,
        trusted_issuer_keys,
        role_keys,
        &context,
    )?;

    let pair_wires = match worker_role {
        TwoPartyDeriverRole::DeriverA => TenantRootCreationCommitmentPairWiresV1 {
            deriver_a_signed_commitment: signed_commitment.clone(),
            deriver_b_signed_commitment: peer_outcome.signed_commitment.clone(),
        },
        TwoPartyDeriverRole::DeriverB => TenantRootCreationCommitmentPairWiresV1 {
            deriver_a_signed_commitment: peer_outcome.signed_commitment.clone(),
            deriver_b_signed_commitment: signed_commitment.clone(),
        },
    };
    let finalized = finalize_tenant_root_role_attempt_v1(
        pending,
        &pair_wires,
        &context,
        role_keys,
        role_signer,
        rng,
    )?;
    let package = TenantRootRoleCreationCommandPackageV1::decode_canonical_bytes(package_bytes)
        .map_err(candidate_derivation_error)?;
    let identity = package.identity().map_err(candidate_derivation_error)?;
    let (input, managed_backup, provider_canary_receipt) =
        seal_initial_role_creation_for_persistence_v1(
            finalized,
            role_signer,
            provider_config,
            online_provider,
            managed_backup_provider,
            identity,
            now_ms,
        )?;
    let signed_installation_evidence = input.installation_evidence_bytes().to_vec();
    Ok(TenantRootRoleCreationProgressV1::Sealed {
        signed_commitment,
        signed_installation_evidence,
        input: Box::new(input),
        managed_backup: Box::new(managed_backup),
        completion: TenantRootRoleCreationCompletionV1::Initiator {
            provider_canary_receipt,
            peer: Box::new(peer_outcome),
        },
    })
}

#[cfg(feature = "workers-rs")]
struct CloudflareTenantRootCreationPeerV1<'a> {
    env: &'a worker::Env,
    binding: &'a crate::CloudflarePeerBindingV1,
    expected_role: TwoPartyDeriverRole,
    initiator_command: VerifiedTenantRootRoleCreationCommandV1,
    initiator_context: TenantRootCeremonyContextV1,
    role_keys: &'a TenantRootCreationRoleVerifyingKeysV1,
}

#[cfg(feature = "workers-rs")]
impl TenantRootPeerRoleDriverV1 for CloudflareTenantRootCreationPeerV1<'_> {
    async fn drive_peer(
        &mut self,
        peer_package_bytes: &[u8],
        initiator_signed_commitment: &[u8],
    ) -> RouterAbProtocolResult<TenantRootPeerRoleOutcomeV1> {
        let commitment = decode_verified_creation_commitment_v1(
            initiator_signed_commitment,
            &self.initiator_context,
            self.initiator_command.role(),
            self.role_keys,
        )?;
        execute_cloudflare_router_tenant_root_creation_commitment_call_v1(
            self.env,
            &self.initiator_command,
            &commitment,
        )
        .await?;
        let request = CloudflareDeriverTenantRootCreateRoleShareRequestV1::PeerCompletion {
            role_creation_command_package_b64u: crate::encode_base64url_bytes_v1(
                peer_package_bytes,
            ),
            initiator_signed_commitment_b64u: crate::encode_base64url_bytes_v1(
                initiator_signed_commitment,
            ),
        };
        let response =
            crate::execute_cloudflare_deriver_tenant_root_create_role_share_service_call_v1(
                self.env,
                self.binding,
                &request,
            )
            .await?;
        let CloudflareDeriverTenantRootCreateRoleShareResponseV1::PeerCompleted {
            role,
            signed_commitment_b64u,
            signed_installation_evidence_b64u,
            signed_managed_backup_b64u,
            terminal_receipt_b64u,
            provider_canary_receipt_b64u,
        } = response
        else {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "tenant-root creation peer returned an initiator-only response",
            ));
        };
        if role != CloudflareTenantRootCreateRoleV1::from_protocol(self.expected_role) {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ForbiddenLocalBinding,
                "tenant-root creation peer response came from the wrong Deriver role",
            ));
        }
        let provider_canary_receipt = crate::decode_base64url_bytes_v1(
            "tenant-root peer provider canary receipt",
            &provider_canary_receipt_b64u,
        )?;
        TenantRootSignedProviderCanaryReceiptV1::decode_canonical_bytes(&provider_canary_receipt)
            .map_err(candidate_derivation_error)?;
        Ok(TenantRootPeerRoleOutcomeV1 {
            signed_commitment: crate::decode_base64url_bytes_v1(
                "tenant-root peer signed commitment",
                &signed_commitment_b64u,
            )?,
            signed_installation_evidence: crate::decode_base64url_bytes_v1(
                "tenant-root peer signed installation evidence",
                &signed_installation_evidence_b64u,
            )?,
            signed_managed_backup: crate::decode_base64url_bytes_v1(
                "tenant-root peer signed managed backup",
                &signed_managed_backup_b64u,
            )?,
            provider_canary_receipt,
            terminal_receipt: crate::decode_base64url_bytes_v1(
                "tenant-root peer terminal receipt",
                &terminal_receipt_b64u,
            )?,
        })
    }
}

#[cfg(feature = "workers-rs")]
fn tenant_root_creation_protocol_role_v1(
    worker_role: crate::CloudflareWorkerRoleV1,
) -> RouterAbProtocolResult<TwoPartyDeriverRole> {
    match worker_role {
        crate::CloudflareWorkerRoleV1::DeriverA => Ok(TwoPartyDeriverRole::DeriverA),
        crate::CloudflareWorkerRoleV1::DeriverB => Ok(TwoPartyDeriverRole::DeriverB),
        crate::CloudflareWorkerRoleV1::Router
        | crate::CloudflareWorkerRoleV1::SigningWorker
        | crate::CloudflareWorkerRoleV1::TenantRootControlPlane => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ForbiddenLocalBinding,
            "only a Deriver may execute tenant-root role creation",
        )),
    }
}

#[cfg(feature = "workers-rs")]
fn tenant_root_managed_restore_role_v1(
    role: TwoPartyDeriverRole,
) -> TenantRootManagedRestoreRoleV1 {
    match role {
        TwoPartyDeriverRole::DeriverA => TenantRootManagedRestoreRoleV1::DeriverA,
        TwoPartyDeriverRole::DeriverB => TenantRootManagedRestoreRoleV1::DeriverB,
    }
}

#[cfg(feature = "workers-rs")]
fn tenant_root_creation_package_authority_v1(
    env: &worker::Env,
    package_bytes: &[u8],
) -> RouterAbProtocolResult<TenantRootControlPlaneAuthorityIdV1> {
    let package = TenantRootRoleCreationCommandPackageV1::decode_canonical_bytes(package_bytes)
        .map_err(candidate_derivation_error)?;
    let context = package
        .creation_context()
        .map_err(candidate_derivation_error)?;
    let (authority_id, _) =
        crate::durable_object::tenant_root_creation::derive_tenant_root_creation_authority_object_v1(
            env,
            context.identity_digest(),
            context.custody_lineage(),
        )?;
    Ok(authority_id)
}

#[cfg(feature = "workers-rs")]
fn tenant_root_role_runtime_provider_config_from_env_v1(
    env: &worker::Env,
    worker_role: crate::CloudflareWorkerRoleV1,
) -> RouterAbProtocolResult<TenantRootRoleRuntimeProviderConfigV1> {
    let reader = crate::CloudflareWorkerEnvReaderV1::new(env);
    let config = crate::env::parse_cloudflare_tenant_root_operational_rotation_provider_config_v1(
        worker_role,
        &reader,
    )?;
    TenantRootRoleRuntimeProviderConfigV1::new(
        config.online_epoch_wrapping_key_ref(),
        config.backup_provider_id(),
        config.backup_key_version(),
    )
    .map_err(candidate_derivation_error)
}

#[cfg(feature = "workers-rs")]
fn tenant_root_store_error_v1(
    operation: &'static str,
    error: worker::Error,
) -> RouterAbProtocolError {
    RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
        format!("{operation} failed: {error}"),
    )
}

#[cfg(feature = "workers-rs")]
fn tenant_root_initial_activation_scope_v1(
    activation_receipt: &VerifiedTenantRootSignedActivationReceiptV1,
    pending: &CloudflareStoredTenantRootRoleShareV1,
) -> RouterAbProtocolResult<TenantRootCommandScopeV1> {
    if !matches!(
        activation_receipt.binding(),
        router_ab_core::TenantRootActivationReceiptBindingV1::InitialCreation(_)
    ) {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ForbiddenLocalBinding,
            "tenant-root initial activation requires an initial-creation receipt",
        ));
    }
    let record = pending.record();
    let identity_digest = record
        .identity()
        .digest()
        .map_err(candidate_derivation_error)?;
    if activation_receipt.identity_digest() != identity_digest
        || activation_receipt.custody_lineage() != record.custody_lineage()
        || record.epoch() != TenantRootShareEpoch::INITIAL
    {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ForbiddenLocalBinding,
            "tenant-root initial activation receipt does not match its pending role share",
        ));
    }

    let role_tag = match record.role() {
        CloudflareTenantRootDeriverRoleV1::DeriverA => 1_u8,
        CloudflareTenantRootDeriverRoleV1::DeriverB => 2_u8,
    };
    let mut scope_material = Vec::with_capacity(32 + 32 + 16 + 8 + 8 + 1);
    scope_material.extend_from_slice(b"seams/tenant-root/initial-activation-scope/v1");
    scope_material.extend_from_slice(activation_receipt.digest().as_bytes());
    scope_material.extend_from_slice(identity_digest.as_bytes());
    scope_material.extend_from_slice(record.custody_lineage().as_bytes());
    scope_material.extend_from_slice(&record.epoch().get().get().to_be_bytes());
    scope_material.extend_from_slice(&pending.revision().to_be_bytes());
    scope_material.push(role_tag);

    let mut session_material = scope_material.clone();
    session_material.extend_from_slice(b"/session");
    let session_digest = Sha256::digest(&session_material);
    let mut session_bytes = [0_u8; 16];
    session_bytes.copy_from_slice(&session_digest[..16]);
    let session_id = TenantRootCeremonySessionIdV1::from_bytes(session_bytes)
        .map_err(candidate_derivation_error)?;

    scope_material.extend_from_slice(b"/nonce");
    let nonce_digest = Sha256::digest(&scope_material);
    let mut nonce_bytes = [0_u8; 32];
    nonce_bytes.copy_from_slice(&nonce_digest);
    let nonce =
        TenantRootCeremonyNonceV1::from_bytes(nonce_bytes).map_err(candidate_derivation_error)?;

    let key = match record.role() {
        CloudflareTenantRootDeriverRoleV1::DeriverA => TenantRootCommandReplayKeyV1::deriver_a(
            identity_digest,
            record.custody_lineage(),
            session_id,
            nonce,
        ),
        CloudflareTenantRootDeriverRoleV1::DeriverB => TenantRootCommandReplayKeyV1::deriver_b(
            identity_digest,
            record.custody_lineage(),
            session_id,
            nonce,
        ),
    };
    TenantRootCommandScopeV1::new(
        key,
        record.epoch(),
        activation_receipt.expected_control_plane_revision(),
    )
    .map_err(candidate_derivation_error)
}

/// Activates one exact role-local epoch-one pending share from verified
/// control-plane evidence and the role's managed backup.
#[cfg(feature = "workers-rs")]
pub(crate) async fn persist_tenant_root_initial_activation_v1(
    store: &CloudflareTenantRootRoleShareStoreV1,
    stored: CloudflareStoredTenantRootRoleShareV1,
    managed_backup: &VerifiedTenantRootManagedBackupV1,
    activation_receipt: VerifiedTenantRootSignedActivationReceiptV1,
    role_signer: &CloudflareTenantRootCreationRoleSignerV1,
    now_ms: u64,
) -> RouterAbProtocolResult<Vec<u8>> {
    let active_retry = matches!(
        stored.record().lifecycle(),
        CloudflareTenantRootRoleShareLifecycleV1::Active(_)
    );
    let (pending, updated_at_ms) = match stored.record().lifecycle() {
        CloudflareTenantRootRoleShareLifecycleV1::Pending(_) => (stored, now_ms),
        CloudflareTenantRootRoleShareLifecycleV1::Active(_) => {
            if stored.active_activation_receipt_bytes().map_err(|error| {
                tenant_root_store_error_v1("tenant-root activation retry", error)
            })? != activation_receipt.canonical_bytes()
            {
                return Err(RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::ForbiddenLocalBinding,
                    "tenant-root activation retry does not match the stored activation receipt",
                ));
            }
            let updated_at_ms = stored.record().updated_at_ms();
            let pending = stored.initial_activation_retry_pending().map_err(|error| {
                tenant_root_store_error_v1("tenant-root activation retry", error)
            })?;
            (pending, updated_at_ms)
        }
        CloudflareTenantRootRoleShareLifecycleV1::Retired(_) => {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLifecycleState,
                "tenant-root initial activation cannot retry a retired role share",
            ));
        }
    };
    let scope = tenant_root_initial_activation_scope_v1(&activation_receipt, &pending)?;
    let replay_exists = store
        .activation_replay_exists(&scope)
        .await
        .map_err(|error| {
            tenant_root_store_error_v1("tenant-root activation replay lookup", error)
        })?;
    if active_retry && !replay_exists {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLifecycleState,
            "tenant-root active role share has no matching activation replay record",
        ));
    }
    if !replay_exists {
        activation_receipt
            .require_fresh(now_ms)
            .map_err(candidate_derivation_error)?;
    }
    let activation = CloudflareTenantRootActivationV1::with_current_role_backup(
        pending.record(),
        managed_backup,
        activation_receipt,
    )
    .map_err(|error| tenant_root_store_error_v1("tenant-root activation evidence", error))?;
    let activation_for_completion = activation.clone();
    let decision = store
        .reserve_activate_initial_pending(scope, pending, activation, updated_at_ms, now_ms)
        .await
        .map_err(|error| tenant_root_store_error_v1("tenant-root activation reservation", error))?;
    let executed = match decision {
        CloudflareTenantRootActivateInitialPendingDecisionV1::Execute { command }
        | CloudflareTenantRootActivateInitialPendingDecisionV1::ResumeExecution { command } => {
            store
                .activate_initial_pending(command, now_ms)
                .await
                .map_err(|error| {
                    tenant_root_store_error_v1("tenant-root activation execution", error)
                })?
                .1
        }
        CloudflareTenantRootActivateInitialPendingDecisionV1::ResumeCompletion { executed } => {
            executed
        }
        CloudflareTenantRootActivateInitialPendingDecisionV1::ReplayCompleted { receipt_bytes } => {
            return Ok(receipt_bytes);
        }
        CloudflareTenantRootActivateInitialPendingDecisionV1::InProgress => {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ReplayedLocalRequest,
                "tenant-root activation is already in progress",
            ));
        }
        CloudflareTenantRootActivateInitialPendingDecisionV1::ReplayFailed { .. } => {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ReplayedLocalRequest,
                "tenant-root activation previously failed",
            ));
        }
    };
    let receipt = role_signer
        .sign_verified_success_terminal_receipt(
            &executed,
            activation_for_completion.activation_receipt_bytes(),
            now_ms,
        )
        .map_err(candidate_derivation_error)?;
    let terminal = store
        .complete_activation(executed, &activation_for_completion, receipt)
        .await
        .map_err(|error| tenant_root_store_error_v1("tenant-root activation completion", error))?;
    match terminal {
        crate::tenant_root_role_d1::CloudflareTenantRootCommandTerminalCommitV1::Committed {
            receipt_bytes,
        }
        | crate::tenant_root_role_d1::CloudflareTenantRootCommandTerminalCommitV1::Replay {
            receipt_bytes,
        } => Ok(receipt_bytes),
    }
}

/// Verifies and applies one control-plane initial-activation receipt at its
/// owning Deriver. The request contains no caller-selected storage selector.
#[cfg(feature = "workers-rs")]
pub(crate) async fn handle_cloudflare_deriver_tenant_root_initial_activation_v1(
    env: &worker::Env,
    worker_role: crate::CloudflareWorkerRoleV1,
    request: CloudflareDeriverTenantRootInitialActivationRequestV1,
    now_ms: u64,
) -> RouterAbProtocolResult<CloudflareDeriverTenantRootInitialActivationResponseV1> {
    let role = tenant_root_creation_protocol_role_v1(worker_role)?;
    let receipt_bytes = crate::decode_base64url_bytes_v1(
        "tenant-root initial activation receipt",
        &request.activation_receipt_b64u,
    )?;
    let receipt = TenantRootSignedActivationReceiptV1::decode_canonical_bytes(&receipt_bytes)
        .map_err(candidate_derivation_error)?;
    if receipt.transition() != TenantRootActivationReceiptTransitionV1::InitialCreation {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ForbiddenLocalBinding,
            "tenant-root role activation requires an initial-creation receipt",
        ));
    }
    let reader = crate::CloudflareWorkerEnvReaderV1::new(env);
    let issuer_keys =
        crate::env::parse_cloudflare_tenant_root_control_plane_issuer_verifying_keys_v1(&reader)?;
    let issuer_key = issuer_keys
        .for_issuer_key_id(receipt.issuer_key_id())
        .ok_or_else(|| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ForbiddenLocalBinding,
                "tenant-root activation receipt issuer is not trusted by this Worker",
            )
        })?;
    let verified = receipt
        .verify_issuer_signature(issuer_key)
        .map_err(candidate_derivation_error)?;
    let (authority_id, _) =
        crate::durable_object::tenant_root_creation::derive_tenant_root_creation_authority_object_v1(
            env,
            verified.identity_digest(),
            verified.custody_lineage(),
        )?;
    if verified.binding().authority_id() != authority_id {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ForbiddenLocalBinding,
            "tenant-root activation receipt names a foreign control-plane authority",
        ));
    }

    let store = CloudflareTenantRootRoleShareStoreV1::from_env(env)
        .map_err(|error| tenant_root_store_error_v1("tenant-root role store lookup", error))?;
    let pending = store
        .load_initial_pending_for_activation(verified.identity_digest(), verified.custody_lineage())
        .await
        .map_err(|error| tenant_root_store_error_v1("tenant-root pending share lookup", error))?;
    let pending_role = match pending.record().role() {
        CloudflareTenantRootDeriverRoleV1::DeriverA => TwoPartyDeriverRole::DeriverA,
        CloudflareTenantRootDeriverRoleV1::DeriverB => TwoPartyDeriverRole::DeriverB,
    };
    if pending_role != role {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ForbiddenLocalBinding,
            "tenant-root pending share belongs to the other Deriver",
        ));
    }

    let backup_role = tenant_root_managed_restore_role_v1(role);
    let backup_store =
        crate::tenant_root_managed_backup_r2::CloudflareTenantRootManagedBackupStoreV1::from_env(
            env,
            backup_role,
        )
        .map_err(|error| tenant_root_store_error_v1("tenant-root backup store lookup", error))?;
    let (_, role_signer) =
        crate::env::load_cloudflare_tenant_root_creation_role_signing_key_v1(env, worker_role)?;
    let managed_backup = backup_store
        .get_verified(
            crate::tenant_root_managed_backup_r2::TenantRootManagedBackupObjectCoordinatesV1::new(
                verified.identity_digest(),
                verified.custody_lineage(),
                backup_role,
                TenantRootShareEpoch::INITIAL,
            ),
            &role_signer.verifying_key_bytes(),
        )
        .await
        .map_err(|error| tenant_root_store_error_v1("tenant-root backup lookup", error))?;
    let terminal_receipt = persist_tenant_root_initial_activation_v1(
        &store,
        pending,
        &managed_backup,
        verified,
        &role_signer,
        now_ms,
    )
    .await?;
    Ok(CloudflareDeriverTenantRootInitialActivationResponseV1 {
        role: CloudflareTenantRootCreateRoleV1::from_protocol(role),
        activation_terminal_receipt_b64u: crate::encode_base64url_bytes_v1(&terminal_receipt),
    })
}

#[cfg(feature = "workers-rs")]
fn tenant_root_refresh_activation_scope_v1(
    activation: &router_ab_core::VerifiedTenantRootSignedActivationReceiptV1,
    pending: &CloudflareStoredTenantRootRoleShareV1,
    role: TwoPartyDeriverRole,
) -> RouterAbProtocolResult<TenantRootCommandScopeV1> {
    let router_ab_core::TenantRootActivationReceiptBindingV1::RefreshSwap(binding) =
        activation.binding()
    else {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ForbiddenLocalBinding,
            "tenant-root refresh activation requires a refresh-swap receipt",
        ));
    };
    if pending.record().epoch() != binding.next_epoch()
        || pending.record().custody_lineage() != binding.custody_lineage()
        || pending
            .record()
            .identity()
            .digest()
            .map_err(candidate_derivation_error)?
            != binding.identity_digest()
    {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ForbiddenLocalBinding,
            "tenant-root refresh activation scope does not match its pending role share",
        ));
    }
    let role_tag = match role {
        TwoPartyDeriverRole::DeriverA => 1_u8,
        TwoPartyDeriverRole::DeriverB => 2_u8,
    };
    let mut scope_material = Vec::with_capacity(32 + 32 + 16 + 8 + 8 + 1);
    scope_material.extend_from_slice(b"seams/tenant-root/refresh-activation-scope/v1");
    scope_material.extend_from_slice(activation.digest().as_bytes());
    scope_material.extend_from_slice(binding.identity_digest().as_bytes());
    scope_material.extend_from_slice(binding.custody_lineage().as_bytes());
    scope_material.extend_from_slice(&binding.current_epoch().get().get().to_be_bytes());
    scope_material.extend_from_slice(&binding.next_epoch().get().get().to_be_bytes());
    scope_material.extend_from_slice(&pending.revision().to_be_bytes());
    scope_material.push(role_tag);

    let mut session_material = scope_material.clone();
    session_material.extend_from_slice(b"/session");
    let session_digest = Sha256::digest(&session_material);
    let mut session_bytes = [0_u8; 16];
    session_bytes.copy_from_slice(&session_digest[..16]);
    let session_id = TenantRootCeremonySessionIdV1::from_bytes(session_bytes)
        .map_err(candidate_derivation_error)?;

    scope_material.extend_from_slice(b"/nonce");
    let nonce_digest = Sha256::digest(&scope_material);
    let mut nonce_bytes = [0_u8; 32];
    nonce_bytes.copy_from_slice(&nonce_digest);
    let nonce =
        TenantRootCeremonyNonceV1::from_bytes(nonce_bytes).map_err(candidate_derivation_error)?;
    let key = match role {
        TwoPartyDeriverRole::DeriverA => TenantRootCommandReplayKeyV1::deriver_a(
            binding.identity_digest(),
            binding.custody_lineage(),
            session_id,
            nonce,
        ),
        TwoPartyDeriverRole::DeriverB => TenantRootCommandReplayKeyV1::deriver_b(
            binding.identity_digest(),
            binding.custody_lineage(),
            session_id,
            nonce,
        ),
    };
    TenantRootCommandScopeV1::new(
        key,
        binding.next_epoch(),
        binding.expected_control_plane_revision(),
    )
    .map_err(candidate_derivation_error)
}

#[cfg(feature = "workers-rs")]
fn validate_tenant_root_refresh_activation_rows_v1(
    activation: &router_ab_core::VerifiedTenantRootSignedActivationReceiptV1,
    active: &CloudflareStoredTenantRootRoleShareV1,
    pending: &CloudflareStoredTenantRootRoleShareV1,
    role: TwoPartyDeriverRole,
) -> RouterAbProtocolResult<()> {
    let router_ab_core::TenantRootActivationReceiptBindingV1::RefreshSwap(binding) =
        activation.binding()
    else {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ForbiddenLocalBinding,
            "tenant-root refresh activation requires a refresh-swap receipt",
        ));
    };
    let active_identity = active
        .record()
        .identity()
        .digest()
        .map_err(candidate_derivation_error)?;
    let pending_identity = pending
        .record()
        .identity()
        .digest()
        .map_err(candidate_derivation_error)?;
    if !matches!(
        active.record().lifecycle(),
        CloudflareTenantRootRoleShareLifecycleV1::Active(_)
    ) || !matches!(
        pending.record().lifecycle(),
        CloudflareTenantRootRoleShareLifecycleV1::Pending(_)
    ) {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLifecycleState,
            "tenant-root refresh activation requires one active and one pending role share",
        ));
    }
    if active_identity != pending_identity
        || active_identity != binding.identity_digest()
        || active.record().custody_lineage() != binding.custody_lineage()
        || pending.record().custody_lineage() != binding.custody_lineage()
        || active.record().epoch() != binding.current_epoch()
        || pending.record().epoch() != binding.next_epoch()
    {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ForbiddenLocalBinding,
            "tenant-root refresh activation receipt does not match local role-share rows",
        ));
    }
    let active_commitment = match role {
        TwoPartyDeriverRole::DeriverA => binding.current_commitments().deriver_a(),
        TwoPartyDeriverRole::DeriverB => binding.current_commitments().deriver_b(),
    };
    let pending_commitment = match role {
        TwoPartyDeriverRole::DeriverA => binding.next_commitments().deriver_a(),
        TwoPartyDeriverRole::DeriverB => binding.next_commitments().deriver_b(),
    };
    if active.record().share_commitment() != active_commitment
        || pending.record().share_commitment() != pending_commitment
    {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ForbiddenLocalBinding,
            "tenant-root refresh activation commitments do not match local role-share rows",
        ));
    }
    let installation_receipt = match role {
        TwoPartyDeriverRole::DeriverA => binding.installation_receipts().deriver_a(),
        TwoPartyDeriverRole::DeriverB => binding.installation_receipts().deriver_b(),
    };
    let pending_evidence = match pending.record().lifecycle() {
        CloudflareTenantRootRoleShareLifecycleV1::Pending(pending) => {
            pending.installation_evidence_digest()
        }
        CloudflareTenantRootRoleShareLifecycleV1::Active(_)
        | CloudflareTenantRootRoleShareLifecycleV1::Retired(_) => {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLifecycleState,
                "tenant-root refresh activation pending row changed lifecycle",
            ));
        }
    };
    if installation_receipt != pending_evidence {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ForbiddenLocalBinding,
            "tenant-root refresh activation evidence does not match the pending role-share row",
        ));
    }
    Ok(())
}

/// Verifies and applies one control-plane refresh-swap receipt at its owning
/// Deriver. Only the exact active and pending rows named by the receipt may
/// participate in the atomic role-local epoch swap.
#[cfg(feature = "workers-rs")]
pub(crate) async fn handle_cloudflare_deriver_tenant_root_refresh_activation_v1(
    env: &worker::Env,
    worker_role: crate::CloudflareWorkerRoleV1,
    request: CloudflareDeriverTenantRootRefreshActivationRequestV1,
    now_ms: u64,
) -> RouterAbProtocolResult<CloudflareDeriverTenantRootRefreshActivationResponseV1> {
    let role = tenant_root_creation_protocol_role_v1(worker_role)?;
    let receipt_bytes = crate::decode_base64url_bytes_v1(
        "tenant-root refresh activation receipt",
        &request.activation_receipt_b64u,
    )?;
    let receipt = TenantRootSignedActivationReceiptV1::decode_canonical_bytes(&receipt_bytes)
        .map_err(candidate_derivation_error)?;
    if receipt.transition() != TenantRootActivationReceiptTransitionV1::RefreshSwap {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ForbiddenLocalBinding,
            "tenant-root role activation requires a refresh-swap receipt",
        ));
    }
    let reader = crate::CloudflareWorkerEnvReaderV1::new(env);
    let issuer_keys =
        crate::env::parse_cloudflare_tenant_root_control_plane_issuer_verifying_keys_v1(&reader)?;
    let issuer_key = issuer_keys
        .for_issuer_key_id(receipt.issuer_key_id())
        .ok_or_else(|| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ForbiddenLocalBinding,
                "tenant-root refresh activation issuer is not trusted by this Worker",
            )
        })?;
    let verified = receipt
        .verify_issuer_signature(issuer_key)
        .map_err(candidate_derivation_error)?;
    let (authority_id, _) =
        crate::durable_object::tenant_root_creation::derive_tenant_root_creation_authority_object_v1(
            env,
            verified.identity_digest(),
            verified.custody_lineage(),
        )?;
    if verified.binding().authority_id() != authority_id {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ForbiddenLocalBinding,
            "tenant-root refresh activation receipt names a foreign control-plane authority",
        ));
    }

    let store = CloudflareTenantRootRoleShareStoreV1::from_env(env)
        .map_err(|error| tenant_root_store_error_v1("tenant-root role store lookup", error))?;
    let active = store
        .load_epoch_by_identity_digest(
            verified.identity_digest(),
            verified.custody_lineage(),
            refresh_activation_current_epoch_v1(&verified)?,
        )
        .await
        .map_err(|error| tenant_root_store_error_v1("tenant-root active share lookup", error))?
        .ok_or_else(|| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLifecycleState,
                "tenant-root refresh activation active share does not exist",
            )
        })?;
    let pending = store
        .load_epoch_by_identity_digest(
            verified.identity_digest(),
            verified.custody_lineage(),
            refresh_activation_next_epoch_v1(&verified)?,
        )
        .await
        .map_err(|error| tenant_root_store_error_v1("tenant-root pending share lookup", error))?
        .ok_or_else(|| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLifecycleState,
                "tenant-root refresh activation pending share does not exist",
            )
        })?;
    let scope = tenant_root_refresh_activation_scope_v1(&verified, &pending, role)?;
    let replay_exists = store
        .activation_replay_exists(&scope)
        .await
        .map_err(|error| {
            tenant_root_store_error_v1("tenant-root refresh activation replay lookup", error)
        })?;
    if !replay_exists {
        verified
            .require_fresh(now_ms)
            .map_err(candidate_derivation_error)?;
    }
    validate_tenant_root_refresh_activation_rows_v1(&verified, &active, &pending, role)?;

    let backup_role = tenant_root_managed_restore_role_v1(role);
    let backup_store =
        crate::tenant_root_managed_backup_r2::CloudflareTenantRootManagedBackupStoreV1::from_env(
            env,
            backup_role,
        )
        .map_err(|error| tenant_root_store_error_v1("tenant-root backup store lookup", error))?;
    let (_, role_signer) =
        crate::env::load_cloudflare_tenant_root_creation_role_signing_key_v1(env, worker_role)?;
    let managed_backup = backup_store
        .get_verified(
            crate::tenant_root_managed_backup_r2::TenantRootManagedBackupObjectCoordinatesV1::new(
                verified.identity_digest(),
                verified.custody_lineage(),
                backup_role,
                refresh_activation_next_epoch_v1(&verified)?,
            ),
            &role_signer.verifying_key_bytes(),
        )
        .await
        .map_err(|error| tenant_root_store_error_v1("tenant-root backup lookup", error))?;
    let activation = CloudflareTenantRootActivationV1::with_current_role_backup(
        pending.record(),
        &managed_backup,
        verified,
    )
    .map_err(|error| {
        tenant_root_store_error_v1("tenant-root refresh activation evidence", error)
    })?;
    let activation_receipt_bytes = activation.activation_receipt_bytes().to_vec();
    let activation_for_completion = activation.clone();
    let activated_at_ms = activation.activated_at_ms();
    let updated_at_ms = now_ms.max(activated_at_ms);
    let retirement = CloudflareTenantRootRetirementV1::new(
        activation.activation_receipt_digest(),
        updated_at_ms,
    )
    .map_err(|error| tenant_root_store_error_v1("tenant-root refresh retirement", error))?;
    let decision = store
        .reserve_swap_active_epoch(
            scope,
            active,
            pending,
            activation,
            retirement,
            updated_at_ms,
            now_ms,
        )
        .await
        .map_err(|error| {
            tenant_root_store_error_v1("tenant-root refresh swap reservation", error)
        })?;
    let executed = match decision {
        crate::tenant_root_role_d1::CloudflareTenantRootSwapActiveEpochDecisionV1::Execute {
            command,
        }
        | crate::tenant_root_role_d1::CloudflareTenantRootSwapActiveEpochDecisionV1::ResumeExecution {
            command,
        } => store
            .swap_active_epoch(command, now_ms)
            .await
            .map_err(|error| tenant_root_store_error_v1("tenant-root refresh swap execution", error))?
            .1,
        crate::tenant_root_role_d1::CloudflareTenantRootSwapActiveEpochDecisionV1::ResumeCompletion {
            executed,
        } => executed,
        crate::tenant_root_role_d1::CloudflareTenantRootSwapActiveEpochDecisionV1::ReplayCompleted {
            receipt_bytes,
        } => {
            return Ok(CloudflareDeriverTenantRootRefreshActivationResponseV1 {
                role: CloudflareTenantRootCreateRoleV1::from_protocol(role),
                activation_terminal_receipt_b64u: crate::encode_base64url_bytes_v1(&receipt_bytes),
            });
        }
        crate::tenant_root_role_d1::CloudflareTenantRootSwapActiveEpochDecisionV1::InProgress => {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ReplayedLocalRequest,
                "tenant-root refresh activation is already in progress",
            ));
        }
        crate::tenant_root_role_d1::CloudflareTenantRootSwapActiveEpochDecisionV1::ReplayFailed {
            ..
        } => {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ReplayedLocalRequest,
                "tenant-root refresh activation previously failed",
            ));
        }
    };
    let terminal_receipt = role_signer
        .sign_verified_success_terminal_receipt(&executed, &activation_receipt_bytes, updated_at_ms)
        .map_err(candidate_derivation_error)?;
    let terminal = store
        .complete_activation(executed, &activation_for_completion, terminal_receipt)
        .await
        .map_err(|error| {
            tenant_root_store_error_v1("tenant-root refresh activation completion", error)
        })?;
    let terminal_bytes = match terminal {
        crate::tenant_root_role_d1::CloudflareTenantRootCommandTerminalCommitV1::Committed {
            receipt_bytes,
        }
        | crate::tenant_root_role_d1::CloudflareTenantRootCommandTerminalCommitV1::Replay {
            receipt_bytes,
        } => receipt_bytes,
    };
    Ok(CloudflareDeriverTenantRootRefreshActivationResponseV1 {
        role: CloudflareTenantRootCreateRoleV1::from_protocol(role),
        activation_terminal_receipt_b64u: crate::encode_base64url_bytes_v1(&terminal_bytes),
    })
}

#[cfg(feature = "workers-rs")]
fn refresh_activation_current_epoch_v1(
    activation: &router_ab_core::VerifiedTenantRootSignedActivationReceiptV1,
) -> RouterAbProtocolResult<TenantRootShareEpoch> {
    let router_ab_core::TenantRootActivationReceiptBindingV1::RefreshSwap(binding) =
        activation.binding()
    else {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ForbiddenLocalBinding,
            "tenant-root refresh activation requires a refresh-swap receipt",
        ));
    };
    Ok(binding.current_epoch())
}

#[cfg(feature = "workers-rs")]
fn refresh_activation_next_epoch_v1(
    activation: &router_ab_core::VerifiedTenantRootSignedActivationReceiptV1,
) -> RouterAbProtocolResult<TenantRootShareEpoch> {
    let router_ab_core::TenantRootActivationReceiptBindingV1::RefreshSwap(binding) =
        activation.binding()
    else {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ForbiddenLocalBinding,
            "tenant-root refresh activation requires a refresh-swap receipt",
        ));
    };
    Ok(binding.next_epoch())
}

#[cfg(feature = "workers-rs")]
async fn require_fresh_tenant_root_creation_v1(
    store: &CloudflareTenantRootRoleShareStoreV1,
    package_bytes: &[u8],
    role: TwoPartyDeriverRole,
    authority_id: TenantRootControlPlaneAuthorityIdV1,
    trusted_issuer_keys: &CloudflareTenantRootControlPlaneIssuerVerifyingKeysV1,
    role_signer: &CloudflareTenantRootCreationRoleSignerV1,
    now_ms: u64,
) -> RouterAbProtocolResult<()> {
    let verified = verify_tenant_root_role_creation_package_v1(
        package_bytes,
        role,
        authority_id,
        trusted_issuer_keys,
        role_signer,
    )?;
    match store
        .preflight_initial_creation(verified.command(), now_ms)
        .await
        .map_err(|error| tenant_root_store_error_v1("tenant-root creation preflight", error))?
    {
        CloudflareTenantRootInitialCreationPreflightV1::Fresh => Ok(()),
        CloudflareTenantRootInitialCreationPreflightV1::InProgress => {
            Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ReplayedLocalRequest,
                "tenant-root creation is already in progress and requires cleanup",
            ))
        }
        CloudflareTenantRootInitialCreationPreflightV1::ReplayCompleted { .. } => {
            Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ReplayedLocalRequest,
                "tenant-root creation already completed for this role",
            ))
        }
        CloudflareTenantRootInitialCreationPreflightV1::ReplayFailed { .. } => {
            Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ReplayedLocalRequest,
                "tenant-root creation already failed for this role",
            ))
        }
    }
}

#[cfg(feature = "workers-rs")]
async fn persist_tenant_root_creation_progress_v1(
    env: &worker::Env,
    role: TwoPartyDeriverRole,
    package_bytes: &[u8],
    authority_id: TenantRootControlPlaneAuthorityIdV1,
    trusted_issuer_keys: &CloudflareTenantRootControlPlaneIssuerVerifyingKeysV1,
    role_keys: &TenantRootCreationRoleVerifyingKeysV1,
    role_signer: &CloudflareTenantRootCreationRoleSignerV1,
    store: &CloudflareTenantRootRoleShareStoreV1,
    progress: TenantRootRoleCreationProgressV1,
    now_ms: u64,
) -> RouterAbProtocolResult<CloudflareDeriverTenantRootCreateRoleShareResponseV1> {
    let TenantRootRoleCreationProgressV1::Sealed {
        signed_commitment,
        signed_installation_evidence,
        input,
        managed_backup,
        completion,
    } = progress
    else {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "tenant-root creation did not complete its commitment pair",
        ));
    };
    let backup_store =
        crate::tenant_root_managed_backup_r2::CloudflareTenantRootManagedBackupStoreV1::from_env(
            env,
            tenant_root_managed_restore_role_v1(role),
        )
        .map_err(|error| tenant_root_store_error_v1("tenant-root backup store lookup", error))?;
    let signed_managed_backup = managed_backup.canonical_bytes().to_vec();
    backup_store
        .put_verified(&managed_backup)
        .await
        .map_err(|error| tenant_root_store_error_v1("tenant-root backup persistence", error))?;
    let persisted = store
        .persist_initial_creation(*input, role_signer, now_ms, now_ms, now_ms)
        .await
        .map_err(|error| tenant_root_store_error_v1("tenant-root role persistence", error))?;
    let receipt_bytes = match persisted {
        CloudflareTenantRootInitialCreationPersistenceOutcomeV1::Committed { receipt_bytes } => {
            receipt_bytes
        }
        CloudflareTenantRootInitialCreationPersistenceOutcomeV1::InProgress => {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ReplayedLocalRequest,
                "tenant-root role persistence is already in progress",
            ));
        }
        CloudflareTenantRootInitialCreationPersistenceOutcomeV1::ReplayCompleted { .. } => {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ReplayedLocalRequest,
                "tenant-root role persistence completed before this live attempt",
            ));
        }
        CloudflareTenantRootInitialCreationPersistenceOutcomeV1::ReplayFailed { .. } => {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ReplayedLocalRequest,
                "tenant-root role persistence previously failed",
            ));
        }
    };
    let verified_package = verify_tenant_root_role_creation_package_v1(
        package_bytes,
        role,
        authority_id,
        trusted_issuer_keys,
        role_signer,
    )?;
    let command = verified_package.command();
    let context = verified_package.creation_context();
    let commitment =
        decode_verified_creation_commitment_v1(&signed_commitment, context, role, role_keys)?;
    let evidence_key = role_keys
        .for_role_and_key_id(role, context.signing_key_id(role))
        .map_err(|_| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ForbiddenLocalBinding,
                "tenant-root creation evidence names an unpublished role signing key",
            )
        })?;
    let evidence = TenantRootSignedShareInstallationEvidenceV1::decode_and_verify_canonical_bytes(
        &signed_installation_evidence,
        evidence_key,
    )
    .map_err(candidate_derivation_error)?;
    execute_cloudflare_router_tenant_root_creation_commitment_call_v1(env, command, &commitment)
        .await?;
    execute_cloudflare_router_tenant_root_creation_installation_call_v1(env, command, &evidence)
        .await?;
    let local_role = CloudflareTenantRootCreateRoleV1::from_protocol(role);
    Ok(match completion {
        TenantRootRoleCreationCompletionV1::RoleOnly {
            provider_canary_receipt,
        } => CloudflareDeriverTenantRootCreateRoleShareResponseV1::PeerCompleted {
            role: local_role,
            signed_commitment_b64u: crate::encode_base64url_bytes_v1(&signed_commitment),
            signed_installation_evidence_b64u: crate::encode_base64url_bytes_v1(
                &signed_installation_evidence,
            ),
            signed_managed_backup_b64u: crate::encode_base64url_bytes_v1(&signed_managed_backup),
            terminal_receipt_b64u: crate::encode_base64url_bytes_v1(&receipt_bytes),
            provider_canary_receipt_b64u: crate::encode_base64url_bytes_v1(
                &provider_canary_receipt,
            ),
        },
        TenantRootRoleCreationCompletionV1::Initiator {
            provider_canary_receipt,
            peer,
        } => {
            let (
                deriver_a_signed_commitment,
                deriver_b_signed_commitment,
                deriver_a_signed_installation_evidence,
                deriver_b_signed_installation_evidence,
                deriver_a_signed_managed_backup,
                deriver_b_signed_managed_backup,
                deriver_a_terminal_receipt,
                deriver_b_terminal_receipt,
                ecdsa_provider_canary_receipt,
                ed25519_provider_canary_receipt,
            ) = match role {
                TwoPartyDeriverRole::DeriverA => (
                    signed_commitment,
                    peer.signed_commitment,
                    signed_installation_evidence,
                    peer.signed_installation_evidence,
                    signed_managed_backup,
                    peer.signed_managed_backup,
                    receipt_bytes,
                    peer.terminal_receipt,
                    provider_canary_receipt,
                    peer.provider_canary_receipt,
                ),
                TwoPartyDeriverRole::DeriverB => (
                    peer.signed_commitment,
                    signed_commitment,
                    peer.signed_installation_evidence,
                    signed_installation_evidence,
                    peer.signed_managed_backup,
                    signed_managed_backup,
                    peer.terminal_receipt,
                    receipt_bytes,
                    peer.provider_canary_receipt,
                    provider_canary_receipt,
                ),
            };
            CloudflareDeriverTenantRootCreateRoleShareResponseV1::Completed {
                role: local_role,
                deriver_a_signed_commitment_b64u: crate::encode_base64url_bytes_v1(
                    &deriver_a_signed_commitment,
                ),
                deriver_b_signed_commitment_b64u: crate::encode_base64url_bytes_v1(
                    &deriver_b_signed_commitment,
                ),
                deriver_a_signed_installation_evidence_b64u: crate::encode_base64url_bytes_v1(
                    &deriver_a_signed_installation_evidence,
                ),
                deriver_b_signed_installation_evidence_b64u: crate::encode_base64url_bytes_v1(
                    &deriver_b_signed_installation_evidence,
                ),
                deriver_a_signed_managed_backup_b64u: crate::encode_base64url_bytes_v1(
                    &deriver_a_signed_managed_backup,
                ),
                deriver_b_signed_managed_backup_b64u: crate::encode_base64url_bytes_v1(
                    &deriver_b_signed_managed_backup,
                ),
                deriver_a_terminal_receipt_b64u: crate::encode_base64url_bytes_v1(
                    &deriver_a_terminal_receipt,
                ),
                deriver_b_terminal_receipt_b64u: crate::encode_base64url_bytes_v1(
                    &deriver_b_terminal_receipt,
                ),
                ecdsa_provider_canary_receipt_b64u: crate::encode_base64url_bytes_v1(
                    &ecdsa_provider_canary_receipt,
                ),
                ed25519_provider_canary_receipt_b64u: crate::encode_base64url_bytes_v1(
                    &ed25519_provider_canary_receipt,
                ),
            }
        }
    })
}

#[cfg(feature = "workers-rs")]
pub(crate) async fn handle_cloudflare_deriver_tenant_root_create_role_share_v1(
    env: &worker::Env,
    worker_role: crate::CloudflareWorkerRoleV1,
    peer_binding: &crate::CloudflarePeerBindingV1,
    request: CloudflareDeriverTenantRootCreateRoleShareRequestV1,
    now_ms: u64,
) -> RouterAbProtocolResult<CloudflareDeriverTenantRootCreateRoleShareResponseV1> {
    let role = tenant_root_creation_protocol_role_v1(worker_role)?;
    let reader = crate::CloudflareWorkerEnvReaderV1::new(env);
    let trusted_issuer_keys =
        crate::env::parse_cloudflare_tenant_root_control_plane_issuer_verifying_keys_v1(&reader)?;
    let role_keys =
        crate::env::parse_cloudflare_tenant_root_creation_role_verifying_keys_v1(&reader)?;
    let (_, role_signer) =
        crate::env::load_cloudflare_tenant_root_creation_role_signing_key_v1(env, worker_role)?;
    let provider_config = tenant_root_role_runtime_provider_config_from_env_v1(env, worker_role)?;
    let store = CloudflareTenantRootRoleShareStoreV1::from_env(env)
        .map_err(|error| tenant_root_store_error_v1("tenant-root role store lookup", error))?;
    let mut online_provider =
        crate::env::load_cloudflare_tenant_root_operational_rotation_provider_v1(env, worker_role)?;
    let mut backup_provider =
        crate::env::load_cloudflare_tenant_root_operational_rotation_provider_v1(env, worker_role)?;
    let mut rng = crate::CloudflareSignerProofGetrandomRngV1;

    let (progress, package_bytes, authority_id) = match request {
        CloudflareDeriverTenantRootCreateRoleShareRequestV1::Initiator {
            role_creation_command_package_b64u,
            peer_role_creation_command_package_b64u,
        } => {
            let package_bytes = crate::decode_base64url_bytes_v1(
                "tenant-root role creation package",
                &role_creation_command_package_b64u,
            )?;
            let peer_package_bytes = crate::decode_base64url_bytes_v1(
                "tenant-root peer role creation package",
                &peer_role_creation_command_package_b64u,
            )?;
            let authority_id = tenant_root_creation_package_authority_v1(env, &package_bytes)?;
            require_fresh_tenant_root_creation_v1(
                &store,
                &package_bytes,
                role,
                authority_id,
                &trusted_issuer_keys,
                &role_signer,
                now_ms,
            )
            .await?;
            let initiator_package = verify_tenant_root_role_creation_package_v1(
                &package_bytes,
                role,
                authority_id,
                &trusted_issuer_keys,
                &role_signer,
            )?;
            let initiator_context = initiator_package.creation_context().clone();
            let mut peer = CloudflareTenantRootCreationPeerV1 {
                env,
                binding: peer_binding,
                expected_role: role.peer(),
                initiator_command: initiator_package.into_command(),
                initiator_context,
                role_keys: &role_keys,
            };
            let progress = drive_tenant_root_role_creation_as_initiator_v1(
                &package_bytes,
                &peer_package_bytes,
                role,
                authority_id,
                &trusted_issuer_keys,
                &role_keys,
                &role_signer,
                &provider_config,
                &mut online_provider,
                &mut backup_provider,
                &mut peer,
                now_ms,
                &mut rng,
            )
            .await?;
            (progress, package_bytes, authority_id)
        }
        CloudflareDeriverTenantRootCreateRoleShareRequestV1::PeerCompletion {
            role_creation_command_package_b64u,
            initiator_signed_commitment_b64u,
        } => {
            let package_bytes = crate::decode_base64url_bytes_v1(
                "tenant-root role creation package",
                &role_creation_command_package_b64u,
            )?;
            let initiator_signed_commitment = crate::decode_base64url_bytes_v1(
                "tenant-root initiator signed commitment",
                &initiator_signed_commitment_b64u,
            )?;
            let authority_id = tenant_root_creation_package_authority_v1(env, &package_bytes)?;
            require_fresh_tenant_root_creation_v1(
                &store,
                &package_bytes,
                role,
                authority_id,
                &trusted_issuer_keys,
                &role_signer,
                now_ms,
            )
            .await?;
            let progress = execute_tenant_root_role_creation_v1(
                &package_bytes,
                Some(&initiator_signed_commitment),
                role,
                authority_id,
                &trusted_issuer_keys,
                &role_keys,
                &role_signer,
                &provider_config,
                &mut online_provider,
                &mut backup_provider,
                now_ms,
                &mut rng,
            )?;
            (progress, package_bytes, authority_id)
        }
    };
    persist_tenant_root_creation_progress_v1(
        env,
        role,
        &package_bytes,
        authority_id,
        &trusted_issuer_keys,
        &role_keys,
        &role_signer,
        &store,
        progress,
        now_ms,
    )
    .await
}

/// Removes the exact pending row authorized by the control-plane issuer.
#[cfg(feature = "workers-rs")]
pub(crate) async fn handle_cloudflare_deriver_tenant_root_cleanup_pending_v1(
    env: &worker::Env,
    worker_role: crate::CloudflareWorkerRoleV1,
    request: CloudflareDeriverTenantRootCleanupPendingRequestV1,
    now_ms: u64,
) -> RouterAbProtocolResult<CloudflareDeriverTenantRootCleanupPendingResponseV1> {
    let role = tenant_root_creation_protocol_role_v1(worker_role)?;
    let command_bytes = crate::decode_base64url_bytes_v1(
        "tenant-root cleanup command",
        &request.cleanup_command_b64u,
    )?;
    let command = TenantRootRoleCleanupCommandV1::decode_canonical_bytes(&command_bytes)
        .map_err(candidate_derivation_error)?;
    let claimed_target = command.claimed_target();
    let (authority_id, _) =
        crate::durable_object::tenant_root_creation::derive_tenant_root_creation_authority_object_v1(
            env,
            claimed_target.identity_digest,
            claimed_target.custody_lineage,
        )?;
    let reader = crate::CloudflareWorkerEnvReaderV1::new(env);
    let trusted_issuer_keys =
        crate::env::parse_cloudflare_tenant_root_control_plane_issuer_verifying_keys_v1(&reader)?;
    let issuer_key_id = command.issuer_key_id().to_owned();
    let trusted_issuer_key = trusted_issuer_keys
        .for_issuer_key_id(&issuer_key_id)
        .ok_or_else(|| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ForbiddenLocalBinding,
                "tenant-root cleanup command issuer is not trusted by this Worker",
            )
        })?;
    let authorization = command
        .verify(
            &claimed_target,
            role,
            authority_id,
            &issuer_key_id,
            trusted_issuer_key,
        )
        .map_err(candidate_derivation_error)?;
    let (_, role_signer) =
        crate::env::load_cloudflare_tenant_root_creation_role_signing_key_v1(env, worker_role)?;
    let store = CloudflareTenantRootRoleShareStoreV1::from_env(env)
        .map_err(|error| tenant_root_store_error_v1("tenant-root role store lookup", error))?;
    let receipt_bytes = store
        .persist_authorized_cleanup(authorization, &role_signer, now_ms, now_ms, now_ms)
        .await
        .map_err(|error| tenant_root_store_error_v1("tenant-root pending cleanup", error))?;
    let backup_role = tenant_root_managed_restore_role_v1(role);
    let backup_store =
        crate::tenant_root_managed_backup_r2::CloudflareTenantRootManagedBackupStoreV1::from_env(
            env,
            backup_role,
        )
        .map_err(|error| tenant_root_store_error_v1("tenant-root backup store lookup", error))?;
    backup_store
        .delete_coordinates(
            crate::tenant_root_managed_backup_r2::TenantRootManagedBackupObjectCoordinatesV1::new(
                claimed_target.identity_digest,
                claimed_target.custody_lineage,
                backup_role,
                claimed_target.epoch,
            ),
        )
        .await
        .map_err(|error| tenant_root_store_error_v1("tenant-root backup cleanup", error))?;
    Ok(CloudflareDeriverTenantRootCleanupPendingResponseV1 {
        role: CloudflareTenantRootCreateRoleV1::from_protocol(role),
        cleanup_receipt_b64u: crate::encode_base64url_bytes_v1(&receipt_bytes),
    })
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
    provider_canary_receipt: Vec<u8>,
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
        Vec<u8>,
    ) {
        (
            self.online_sealed,
            self.managed_backup,
            self.provider_canary_receipt,
        )
    }
}

/// Composes one verified initial role attempt through online and managed sealing.
#[cfg(feature = "workers-rs")]
#[allow(clippy::too_many_arguments)]
pub(crate) fn compose_initial_tenant_root_role_runtime_v1<Online, Backup>(
    attempt: VerifiedTenantRootInitialRoleAttemptV1,
    signer: &crate::CloudflareTenantRootCreationRoleSignerV1,
    provider_config: &TenantRootRoleRuntimeProviderConfigV1,
    online_provider: &mut Online,
    managed_backup_provider: &mut Backup,
    completed_at_ms: u64,
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
    let opened_online =
        open_tenant_root_online_role_share_v1(online_sealed.clone(), online_provider)?;
    let evidence_commitment = evidence.evidence().transcript().commitment().to_bytes();
    if opened_online.binding().share_commitment().as_bytes() != evidence_commitment.as_ref() {
        return Err(malformed(
            "tenant-root online provider returned a share with the wrong commitment",
        ));
    }
    drop(opened_online);
    if command.epoch() != TenantRootShareEpoch::INITIAL {
        return Err(malformed(
            "tenant-root initial creation canary requires the initial epoch",
        ));
    }
    let commitments = tenant_root_epoch_commitments_v1(&evidence)?;
    let canary_binding = TenantRootProviderCanaryReceiptBindingV1::new(
        command.identity_digest(),
        command.custody_lineage(),
        TenantRootActivationReceiptTransitionV1::InitialCreation,
        TenantRootShareEpoch::INITIAL,
        commitments,
        tenant_root_provider_canary_curve_family_v1(role),
        provider_config.online_epoch_wrapping_key_ref.clone(),
        completed_at_ms,
        command.authority_id(),
        signer.signing_key_id().to_owned(),
        context.issued_at_ms(),
        context.expires_at_ms(),
    )?;
    let provider_canary_receipt = signer.sign_provider_canary(canary_binding)?;
    let provider_canary_receipt = provider_canary_receipt.canonical_bytes()?;
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
        provider_canary_receipt,
    };
    Ok((command, evidence, artifacts))
}

/// Seals one verified refresh role attempt into the exact pending D1 input.
///
/// Refresh finalization owns the current share and emits this verified token;
/// this adapter is the only boundary that turns its next-epoch share into
/// provider ciphertext. The provider result is opened immediately so a bad
/// provider response cannot reach D1.
#[cfg(feature = "workers-rs")]
pub(crate) fn compose_refresh_tenant_root_role_runtime_v1<Online>(
    attempt: VerifiedTenantRootRefreshRoleAttemptV1,
    identity: TenantRootIdentityV1,
    provider_config: &TenantRootRoleRuntimeProviderConfigV1,
    online_provider: &mut Online,
    staged_at_ms: u64,
) -> RouterAbProtocolResult<CloudflareTenantRootRefreshInputV1>
where
    Online: TenantRootOnlineRoleShareProviderV1,
{
    let (command, share_wire, evidence) = attempt.into_parts();
    let (command, evidence, online_sealed, _) = compose_refresh_role_online_artifacts_v1(
        command,
        share_wire,
        evidence,
        &identity,
        provider_config,
        online_provider,
    )?;
    CloudflareTenantRootRefreshInputV1::new(
        command,
        evidence,
        CloudflareTenantRootRefreshShareInputV1::new(identity, online_sealed, staged_at_ms),
    )
    .map_err(|error| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("tenant-root refresh persistence input was refused: {error}"),
        )
    })
}

#[cfg(feature = "workers-rs")]
fn compose_refresh_role_online_artifacts_v1<Online>(
    command: VerifiedTenantRootRoleRefreshCommandV1,
    share_wire: SigningRootShareWire,
    evidence: VerifiedTenantRootSignedShareInstallationEvidenceWireV1,
    identity: &TenantRootIdentityV1,
    provider_config: &TenantRootRoleRuntimeProviderConfigV1,
    online_provider: &mut Online,
) -> RouterAbProtocolResult<(
    VerifiedTenantRootRoleRefreshCommandV1,
    VerifiedTenantRootSignedShareInstallationEvidenceWireV1,
    TenantRootSealedOnlineRoleShareV1,
    MpcPrfSigningRootShareWireV1,
)>
where
    Online: TenantRootOnlineRoleShareProviderV1,
{
    let identity_digest = identity.digest().map_err(candidate_derivation_error)?;
    if identity_digest != command.identity_digest() {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ForbiddenLocalBinding,
            "tenant-root refresh sealing identity does not match its authorized command",
        ));
    }
    let transcript = evidence.evidence().transcript();
    let share_commitment =
        MpcPrfShareCommitmentWireV1::new(transcript.commitment().to_bytes().to_vec())
            .map_err(candidate_derivation_error)?;
    let managed_share =
        MpcPrfSigningRootShareWireV1::new(Zeroizing::new(share_wire.to_bytes()).to_vec())
            .map_err(candidate_derivation_error)?;
    let online_binding = TenantRootOnlineRoleShareBindingV1::new(
        command.identity_digest(),
        command.custody_lineage(),
        command.role(),
        command.next_epoch(),
        share_commitment,
        provider_config.online_epoch_wrapping_key_ref.clone(),
        &evidence,
    )
    .map_err(candidate_derivation_error)?;
    let online_request = TenantRootOnlineRoleShareSealRequestV1::new(online_binding, share_wire)
        .map_err(candidate_derivation_error)?;
    let online_ciphertext = online_provider
        .seal_online_role_share(&online_request)
        .map_err(candidate_derivation_error)?;
    let online_sealed = online_request
        .complete(online_ciphertext)
        .map_err(candidate_derivation_error)?;
    let opened_online =
        open_tenant_root_online_role_share_v1(online_sealed.clone(), online_provider)
            .map_err(candidate_derivation_error)?;
    if opened_online.identity_digest() != identity_digest
        || opened_online.custody_lineage() != command.custody_lineage()
        || opened_online.role() != command.role()
        || opened_online.epoch() != command.next_epoch()
        || opened_online.share_commitment() != online_sealed.binding().share_commitment()
    {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ForbiddenLocalBinding,
            "tenant-root refresh provider returned a share with the wrong binding",
        ));
    }
    drop(opened_online);
    Ok((command, evidence, online_sealed, managed_share))
}

#[cfg(feature = "workers-rs")]
#[allow(clippy::too_many_arguments)]
fn seal_refresh_role_for_persistence_v1<Online, Backup>(
    attempt: VerifiedTenantRootRefreshRoleAttemptV1,
    role_signer: &crate::CloudflareTenantRootCreationRoleSignerV1,
    identity: TenantRootIdentityV1,
    provider_config: &TenantRootRoleRuntimeProviderConfigV1,
    online_provider: &mut Online,
    managed_backup_provider: &mut Backup,
    staged_at_ms: u64,
) -> RouterAbProtocolResult<(
    CloudflareTenantRootRefreshInputV1,
    VerifiedTenantRootManagedBackupV1,
    Vec<u8>,
)>
where
    Online: TenantRootOnlineRoleShareProviderV1,
    Backup: TenantRootManagedBackupProviderV1,
{
    let (command, share_wire, evidence) = attempt.into_parts();
    validate_attempt(
        command.role(),
        command.identity_digest(),
        command.custody_lineage(),
        command.next_epoch(),
        &evidence,
        role_signer,
    )
    .map_err(candidate_derivation_error)?;
    let (command, evidence, online_sealed, managed_share) =
        compose_refresh_role_online_artifacts_v1(
            command,
            share_wire,
            evidence,
            &identity,
            provider_config,
            online_provider,
        )?;
    let context = evidence.evidence().transcript().context();
    let commitments =
        tenant_root_epoch_commitments_v1(&evidence).map_err(candidate_derivation_error)?;
    let canary_binding = TenantRootProviderCanaryReceiptBindingV1::new(
        command.identity_digest(),
        command.custody_lineage(),
        TenantRootActivationReceiptTransitionV1::RefreshSwap,
        command.next_epoch(),
        commitments,
        tenant_root_provider_canary_curve_family_v1(command.role()),
        provider_config.online_epoch_wrapping_key_ref.clone(),
        staged_at_ms,
        command.authority_id(),
        role_signer.signing_key_id().to_owned(),
        context.issued_at_ms(),
        context.expires_at_ms(),
    )
    .map_err(candidate_derivation_error)?;
    let provider_canary_receipt = role_signer
        .sign_provider_canary(canary_binding)
        .map_err(candidate_derivation_error)?
        .canonical_bytes()
        .map_err(candidate_derivation_error)?;
    let managed_binding = TenantRootManagedBackupBindingV1::from_verified_installation_evidence(
        &evidence,
        provider_config.managed_backup_provider_id.clone(),
        provider_config.managed_backup_key_version.clone(),
        role_signer.signing_key_id().to_owned(),
        context.issued_at_ms(),
    )
    .map_err(candidate_derivation_error)?;
    let managed_request =
        TenantRootManagedBackupSealRequestV1::new(managed_binding.clone(), managed_share)
            .map_err(candidate_derivation_error)?;
    let managed_ciphertext = managed_backup_provider
        .seal_managed_backup(&managed_request)
        .map_err(candidate_derivation_error)?;
    let managed_backup = role_signer
        .sign_managed_backup(managed_request, managed_ciphertext)
        .map_err(candidate_derivation_error)?
        .verify(&managed_binding, &role_signer.verifying_key_bytes())
        .map_err(candidate_derivation_error)?;
    let input = CloudflareTenantRootRefreshInputV1::new(
        command,
        evidence,
        CloudflareTenantRootRefreshShareInputV1::new(identity, online_sealed, staged_at_ms),
    )
    .map_err(|error| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("tenant-root refresh persistence input was refused: {error}"),
        )
    })?;
    Ok((input, managed_backup, provider_canary_receipt))
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

#[cfg(feature = "workers-rs")]
fn tenant_root_epoch_commitments_v1(
    evidence: &VerifiedTenantRootSignedShareInstallationEvidenceWireV1,
) -> RouterAbDerivationResult<TenantRootEpochCommitmentsV1> {
    let transcript = evidence.evidence().transcript();
    let (deriver_a, deriver_b) = match transcript.role() {
        TwoPartyDeriverRole::DeriverA => (transcript.commitment(), transcript.peer_commitment()),
        TwoPartyDeriverRole::DeriverB => (transcript.peer_commitment(), transcript.commitment()),
    };
    TenantRootEpochCommitmentsV1::new(
        MpcPrfShareCommitmentWireV1::new(deriver_a.to_bytes().to_vec())?,
        MpcPrfShareCommitmentWireV1::new(deriver_b.to_bytes().to_vec())?,
    )
}

#[cfg(feature = "workers-rs")]
const fn tenant_root_provider_canary_curve_family_v1(
    role: TwoPartyDeriverRole,
) -> TenantRootCanaryCurveFamilyV1 {
    match role {
        TwoPartyDeriverRole::DeriverA => TenantRootCanaryCurveFamilyV1::Ecdsa,
        TwoPartyDeriverRole::DeriverB => TenantRootCanaryCurveFamilyV1::Ed25519,
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
pub(crate) mod tests {
    use super::*;
    use base64::Engine;
    use curve25519_dalek::scalar::Scalar;
    use ed25519_dalek::SigningKey;
    use hpke_ng::{DhKemX25519HkdfSha256, Kem};
    use rand_chacha::ChaCha20Rng;
    use rand_core_06::SeedableRng;
    use router_ab_core::{
        resolve_active_tenant_root_pair_binding_v1, verify_tenant_root_creation_evidence_v1,
        PendingTenantRootRefreshRoleAttemptV1, TenantRootActiveRoleBindingV1,
        TenantRootActiveRoleResolutionV1, TenantRootActiveRoleRowKeyV1,
        TenantRootCeremonyContextV1, TenantRootCeremonyNonceV1,
        TenantRootControlPlaneAuthorityIdV1, TenantRootCreationJournalV1,
        TenantRootCustodyLineageId, TenantRootIdentityV1, TenantRootLifecycleReceiptDigestV1,
        TenantRootManagedRestoreRoleV1, TenantRootRefreshHpkeKeypairV1,
        TenantRootRoleCreationCommandV1, TenantRootRoleRefreshCommandV1, TenantRootShareEpoch,
        TenantRootSignedCreationCommitmentV1, TenantRootSignedRefreshCommitmentV1,
        VerifiedTenantRootCreationCommitmentPairV1, VerifiedTenantRootCreationCommitmentV1,
        VerifiedTenantRootRefreshCommitmentPairV1,
    };
    use threshold_prf::{SigningRootShare, SigningRootShareCommitment, SigningRootShareWire};

    use crate::tenant_root_operational_provider::CloudflareTenantRootOperationalRotationProviderV1;

    pub(crate) const ISSUER_KEY: [u8; 32] = [0x41; 32];
    pub(crate) const ISSUER_KEY_ID: &str = "tenant-root-issuer-v1";
    pub(crate) const ISSUED_AT_MS: u64 = 1_000_000;
    const EXPIRES_AT_MS: u64 = 1_030_000;
    const ONLINE_REF: &str = "online-key/tenant-7/epoch-1";
    const BACKUP_PROVIDER: &str = "backup-provider-a";
    const BACKUP_VERSION: &str = "backup-key-a/tenant-7/epoch-1";

    pub(crate) struct InMemoryProvider {
        online_share: Option<SigningRootShareWire>,
        managed_share: Option<MpcPrfSigningRootShareWireV1>,
        online_role: Option<TwoPartyDeriverRole>,
        backup_role: Option<router_ab_core::TenantRootManagedRestoreRoleV1>,
    }

    impl InMemoryProvider {
        pub(crate) fn new() -> Self {
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

    #[cfg(feature = "workers-rs")]
    fn refresh_context() -> TenantRootCeremonyContextV1 {
        TenantRootCeremonyContextV1::new(
            identity().digest().expect("identity digest"),
            TenantRootCustodyLineageId::from_bytes([0x22; 16]).expect("lineage"),
            TenantRootCeremonyEpochsV1::refresh(
                TenantRootShareEpoch::new(7).expect("current epoch"),
                TenantRootShareEpoch::new(8).expect("next epoch"),
            )
            .expect("refresh epochs"),
            router_ab_core::TenantRootCeremonySessionIdV1::from_bytes([0x11; 16]).expect("session"),
            TenantRootCeremonyNonceV1::from_bytes([0x33; 32]).expect("nonce"),
            ISSUED_AT_MS,
            EXPIRES_AT_MS,
            "deriver-a-signing-key-7",
            "deriver-b-signing-key-9",
        )
        .expect("refresh context")
    }

    #[cfg(feature = "workers-rs")]
    fn refresh_share(role: TwoPartyDeriverRole) -> SigningRootShare {
        SigningRootShare::from_canonical_bytes(
            role.share_id(),
            Scalar::from(match role {
                TwoPartyDeriverRole::DeriverA => 17_u64,
                TwoPartyDeriverRole::DeriverB => 29_u64,
            })
            .to_bytes(),
        )
        .expect("refresh share")
    }

    #[cfg(feature = "workers-rs")]
    fn refresh_active_pair() -> router_ab_core::TenantRootActiveRootPairV1 {
        let identity_digest = identity().digest().expect("identity digest");
        let lineage = TenantRootCustodyLineageId::from_bytes([0x22; 16]).expect("lineage");
        let epoch = TenantRootShareEpoch::new(7).expect("current epoch");
        let receipt = TenantRootLifecycleReceiptDigestV1::from_bytes([0x77; 32])
            .expect("activation receipt digest");
        let binding_a = TenantRootActiveRoleBindingV1::new(
            TenantRootActiveRoleRowKeyV1::new(
                identity_digest,
                lineage,
                epoch,
                TenantRootManagedRestoreRoleV1::DeriverA,
            ),
            MpcPrfShareCommitmentWireV1::new(
                SigningRootShareCommitment::from_share(&refresh_share(
                    TwoPartyDeriverRole::DeriverA,
                ))
                .to_bytes()
                .to_vec(),
            )
            .expect("Deriver A commitment"),
            receipt,
        )
        .expect("Deriver A active binding");
        let binding_b = TenantRootActiveRoleBindingV1::new(
            TenantRootActiveRoleRowKeyV1::new(
                identity_digest,
                lineage,
                epoch,
                TenantRootManagedRestoreRoleV1::DeriverB,
            ),
            MpcPrfShareCommitmentWireV1::new(
                SigningRootShareCommitment::from_share(&refresh_share(
                    TwoPartyDeriverRole::DeriverB,
                ))
                .to_bytes()
                .to_vec(),
            )
            .expect("Deriver B commitment"),
            receipt,
        )
        .expect("Deriver B active binding");
        resolve_active_tenant_root_pair_binding_v1(
            identity_digest,
            &TenantRootActiveRoleResolutionV1::Active(binding_a),
            &TenantRootActiveRoleResolutionV1::Active(binding_b),
        )
        .expect("active pair resolution")
        .require_active()
        .expect("active pair")
        .clone()
    }

    #[cfg(feature = "workers-rs")]
    fn refresh_active_binding(role: TwoPartyDeriverRole) -> TenantRootActiveRoleBindingV1 {
        let pair = refresh_active_pair();
        match role {
            TwoPartyDeriverRole::DeriverA => pair.deriver_a().clone(),
            TwoPartyDeriverRole::DeriverB => pair.deriver_b().clone(),
        }
    }

    #[cfg(feature = "workers-rs")]
    fn refresh_recipient(
        role: TwoPartyDeriverRole,
    ) -> (&'static str, TenantRootRefreshHpkePublicKeyV1) {
        match role {
            TwoPartyDeriverRole::DeriverA => (
                "deriver-a-refresh-hpke-key-1",
                TenantRootRefreshHpkeKeypairV1::derive_from_ikm([0xa1; 32])
                    .expect("Deriver A refresh HPKE key")
                    .public_key(),
            ),
            TwoPartyDeriverRole::DeriverB => (
                "deriver-b-refresh-hpke-key-1",
                TenantRootRefreshHpkeKeypairV1::derive_from_ikm([0xb1; 32])
                    .expect("Deriver B refresh HPKE key")
                    .public_key(),
            ),
        }
    }

    #[cfg(feature = "workers-rs")]
    fn refresh_command(
        context: &TenantRootCeremonyContextV1,
        role: TwoPartyDeriverRole,
    ) -> router_ab_core::VerifiedTenantRootRoleRefreshCommandV1 {
        let active_pair = refresh_active_pair();
        let issuer = SigningKey::from_bytes(&ISSUER_KEY);
        TenantRootRoleRefreshCommandV1::sign(
            &active_pair,
            context,
            role,
            4,
            TenantRootControlPlaneAuthorityIdV1::from_bytes([0x44; 32]),
            ISSUED_AT_MS + 1,
            EXPIRES_AT_MS - 1,
            ISSUER_KEY_ID,
            &ISSUER_KEY,
        )
        .expect("signed refresh command")
        .verify(
            &active_pair,
            context,
            role,
            4,
            TenantRootControlPlaneAuthorityIdV1::from_bytes([0x44; 32]),
            ISSUER_KEY_ID,
            issuer.verifying_key().as_bytes(),
        )
        .expect("verified refresh command")
    }

    #[cfg(feature = "workers-rs")]
    fn refresh_pending(
        context: &TenantRootCeremonyContextV1,
        role: TwoPartyDeriverRole,
        coefficient_seed: u8,
    ) -> PendingTenantRootRefreshRoleAttemptV1 {
        let signing_key = role_key(role);
        let verifying_key = signing_key.verifying_key().to_bytes();
        let (recipient_key_id, recipient_public_key) = refresh_recipient(role);
        PendingTenantRootRefreshRoleAttemptV1::new(
            refresh_command(context, role),
            context.clone(),
            refresh_active_binding(role),
            refresh_share(role),
            &signing_key.to_bytes(),
            &verifying_key,
            recipient_key_id,
            recipient_public_key,
            ISSUED_AT_MS + 10,
            &mut ChaCha20Rng::from_seed([coefficient_seed; 32]),
        )
        .expect("pending refresh role attempt")
    }

    #[cfg(feature = "workers-rs")]
    fn begun_refresh_pending(
        context: &TenantRootCeremonyContextV1,
        role: TwoPartyDeriverRole,
        coefficient_seed: u8,
    ) -> PendingTenantRootRefreshRoleAttemptV1 {
        let signing_key = role_key(role);
        let signing_key_bytes = signing_key.to_bytes();
        let verifying_key_bytes = signing_key.verifying_key().to_bytes();
        let (recipient_key_id, recipient_public_key) = refresh_recipient(role);
        let progress = begin_tenant_root_role_refresh_v1(
            refresh_command(context, role),
            context.clone(),
            refresh_active_binding(role),
            refresh_share(role),
            &signing_key_bytes,
            &verifying_key_bytes,
            recipient_key_id,
            recipient_public_key,
            ISSUED_AT_MS + 10,
            &mut ChaCha20Rng::from_seed([coefficient_seed; 32]),
        )
        .expect("started refresh role attempt");
        let TenantRootRoleRefreshProgressV1::Committed { pending } = progress else {
            panic!("refresh start should expose a pending commitment");
        };
        pending
    }

    #[cfg(feature = "workers-rs")]
    fn verified_refresh_commitment(
        pending: &PendingTenantRootRefreshRoleAttemptV1,
    ) -> router_ab_core::VerifiedTenantRootRefreshCommitmentV1 {
        let role = pending.role();
        let context = pending.commitment().transcript().context();
        let key = role_key(role);
        TenantRootSignedRefreshCommitmentV1::decode_and_verify_canonical_bytes(
            pending.commitment_bytes(),
            context,
            role,
            context.signing_key_id(role),
            key.verifying_key().as_bytes(),
        )
        .expect("verified refresh commitment")
    }

    #[cfg(feature = "workers-rs")]
    fn completed_refresh_attempt() -> router_ab_core::VerifiedTenantRootRefreshRoleAttemptV1 {
        let context = refresh_context();
        let pending_a = refresh_pending(&context, TwoPartyDeriverRole::DeriverA, 0x51);
        let pending_b = refresh_pending(&context, TwoPartyDeriverRole::DeriverB, 0x61);
        let pair = VerifiedTenantRootRefreshCommitmentPairV1::new(
            verified_refresh_commitment(&pending_a),
            verified_refresh_commitment(&pending_b),
        )
        .expect("verified refresh commitment pair");
        pending_a
            .finalize(
                pair,
                pending_b.contribution_for_peer(),
                &mut ChaCha20Rng::from_seed([0x71; 32]),
            )
            .expect("completed refresh role attempt")
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

    #[cfg(feature = "workers-rs")]
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
            ISSUED_AT_MS + 2,
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
            ISSUED_AT_MS + 2,
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

        let (online_sealed, managed_backup, provider_canary_receipt) = artifacts_a.into_parts();
        assert!(!provider_canary_receipt.is_empty());
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

        let (online_sealed, managed_backup, provider_canary_receipt) = artifacts_b.into_parts();
        assert!(!provider_canary_receipt.is_empty());
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

    #[cfg(feature = "workers-rs")]
    #[test]
    fn refresh_role_attempt_composes_a_provider_sealed_d1_input() {
        let config =
            TenantRootRoleRuntimeProviderConfigV1::new(ONLINE_REF, BACKUP_PROVIDER, BACKUP_VERSION)
                .expect("provider config");
        let mut provider = InMemoryProvider::new();
        let input = compose_refresh_tenant_root_role_runtime_v1(
            completed_refresh_attempt(),
            identity(),
            &config,
            &mut provider,
            ISSUED_AT_MS + 11,
        )
        .expect("refresh persistence input");

        assert_eq!(provider.online_role, Some(TwoPartyDeriverRole::DeriverA));
        assert_eq!(
            provider
                .online_share
                .as_ref()
                .expect("provider received the next share")
                .to_share()
                .expect("provider share wire")
                .id(),
            TwoPartyDeriverRole::DeriverA.share_id()
        );
        assert!(format!("{input:?}").contains("CloudflareTenantRootRefreshInputV1"));
    }

    #[cfg(feature = "workers-rs")]
    #[test]
    fn refresh_role_progresses_from_commitment_to_composed_input() {
        let context = refresh_context();
        let role = TwoPartyDeriverRole::DeriverA;
        let pending = begun_refresh_pending(&context, role, 0x51);

        let peer_pending = refresh_pending(&context, role.peer(), 0x61);
        let pair = VerifiedTenantRootRefreshCommitmentPairV1::new(
            verified_refresh_commitment(&pending),
            verified_refresh_commitment(&peer_pending),
        )
        .expect("verified refresh commitment pair");
        let config =
            TenantRootRoleRuntimeProviderConfigV1::new(ONLINE_REF, BACKUP_PROVIDER, BACKUP_VERSION)
                .expect("provider config");
        let mut provider = InMemoryProvider::new();
        let mut backup_provider = InMemoryProvider::new();
        let role_signer = signer(role);
        let progress = finalize_tenant_root_role_refresh_v1(
            pending,
            pair,
            peer_pending.contribution_for_peer(),
            &role_signer,
            identity(),
            &config,
            &mut provider,
            &mut backup_provider,
            ISSUED_AT_MS + 11,
            &mut ChaCha20Rng::from_seed([0x71; 32]),
        )
        .expect("finalized refresh role attempt");

        let TenantRootRoleRefreshProgressV1::Sealed {
            signed_commitment,
            signed_installation_evidence,
            input,
            managed_backup,
            provider_canary_receipt,
        } = progress
        else {
            panic!("refresh finalization should expose a composed input");
        };
        assert!(!signed_commitment.is_empty());
        assert!(!signed_installation_evidence.is_empty());
        assert_eq!(provider.online_role, Some(role));
        assert_eq!(
            backup_provider.backup_role,
            Some(router_ab_core::TenantRootManagedRestoreRoleV1::DeriverA)
        );
        assert_eq!(
            managed_backup.binding().backup_provider_id(),
            BACKUP_PROVIDER
        );
        assert!(!provider_canary_receipt.is_empty());
        assert_eq!(
            input.installation_evidence_bytes(),
            signed_installation_evidence.as_slice()
        );
        let canary = TenantRootSignedProviderCanaryReceiptV1::decode_canonical_bytes(
            &provider_canary_receipt,
        )
        .expect("canonical refresh provider canary");
        assert_eq!(
            canary.transition(),
            TenantRootActivationReceiptTransitionV1::RefreshSwap
        );
        assert_eq!(
            canary.target_epoch(),
            TenantRootShareEpoch::new(8).expect("next epoch")
        );
        assert_eq!(canary.provider_key_version_ref(), ONLINE_REF);
        canary
            .verify(
                &canary.binding().clone(),
                &role_signer.verifying_key_bytes(),
            )
            .expect("refresh provider canary signature");
        assert!(format!("{input:?}").contains("CloudflareTenantRootRefreshInputV1"));
    }

    #[cfg(feature = "workers-rs")]
    #[test]
    fn refresh_role_refuses_a_contribution_from_the_wrong_peer() {
        let context = refresh_context();
        let role = TwoPartyDeriverRole::DeriverA;
        let pending = begun_refresh_pending(&context, role, 0x51);
        let peer_pending = refresh_pending(&context, role.peer(), 0x61);
        let pair = VerifiedTenantRootRefreshCommitmentPairV1::new(
            verified_refresh_commitment(&pending),
            verified_refresh_commitment(&peer_pending),
        )
        .expect("verified refresh commitment pair");
        let wrong_peer_contribution = pending.contribution_for_peer();
        let config =
            TenantRootRoleRuntimeProviderConfigV1::new(ONLINE_REF, BACKUP_PROVIDER, BACKUP_VERSION)
                .expect("provider config");
        let mut provider = InMemoryProvider::new();
        let mut backup_provider = InMemoryProvider::new();
        let role_signer = signer(role);
        assert!(finalize_tenant_root_role_refresh_v1(
            pending,
            pair,
            wrong_peer_contribution,
            &role_signer,
            identity(),
            &config,
            &mut provider,
            &mut backup_provider,
            ISSUED_AT_MS + 11,
            &mut ChaCha20Rng::from_seed([0x71; 32]),
        )
        .is_err());
        assert_eq!(provider.online_role, None);
        assert!(provider.online_share.is_none());
    }

    #[cfg(feature = "workers-rs")]
    #[test]
    fn refresh_role_attempt_rejects_a_sealing_identity_substitution_before_provider_use() {
        let config =
            TenantRootRoleRuntimeProviderConfigV1::new(ONLINE_REF, BACKUP_PROVIDER, BACKUP_VERSION)
                .expect("provider config");
        let wrong_identity =
            TenantRootIdentityV1::new("org-1", "project-2", "production", "root-substituted", "v3")
                .expect("wrong identity");
        let mut provider = InMemoryProvider::new();
        assert!(compose_refresh_tenant_root_role_runtime_v1(
            completed_refresh_attempt(),
            wrong_identity,
            &config,
            &mut provider,
            ISSUED_AT_MS + 11,
        )
        .is_err());
        assert_eq!(provider.online_role, None);
        assert!(provider.online_share.is_none());
    }

    #[cfg(feature = "workers-rs")]
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
            ISSUED_AT_MS + 2,
        );

        assert!(result.is_err());
        assert_eq!(online_provider.online_role, None);
        assert_eq!(backup_provider.backup_role, None);
    }

    #[cfg(feature = "workers-rs")]
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
            ISSUED_AT_MS + 2,
        )
        .expect("composed operational provider artifacts");
        let (online_sealed, managed_backup, provider_canary_receipt) = artifacts.into_parts();
        assert!(!provider_canary_receipt.is_empty());
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

    pub(crate) const ISSUER_KEY: [u8; 32] = [0x41; 32];
    pub(crate) const ISSUER_KEY_ID: &str = "tenant-root-issuer-v1";
    const FOREIGN_ISSUER_KEY: [u8; 32] = [0x42; 32];
    pub(crate) const ISSUED_AT_MS: u64 = 1_000_000;
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
                &signer(role),
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
                &signer(TwoPartyDeriverRole::DeriverA),
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
            &signer(TwoPartyDeriverRole::DeriverA),
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
            &signer(TwoPartyDeriverRole::DeriverA),
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
                    &signer(TwoPartyDeriverRole::DeriverA),
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
                &signer(role),
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

#[cfg(all(test, feature = "workers-rs"))]
pub(crate) mod live_execution_tests {
    use super::admission_tests::*;
    use super::tests::InMemoryProvider;
    use super::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core_06::SeedableRng;

    const ONLINE_REF: &str = "online-key/tenant-7/epoch-1";
    const BACKUP_PROVIDER: &str = "backup-provider-a";
    const BACKUP_VERSION: &str = "backup-key-a/tenant-7/epoch-1";

    pub(crate) fn test_provider_config() -> TenantRootRoleRuntimeProviderConfigV1 {
        provider_config()
    }

    fn provider_config() -> TenantRootRoleRuntimeProviderConfigV1 {
        TenantRootRoleRuntimeProviderConfigV1::new(ONLINE_REF, BACKUP_PROVIDER, BACKUP_VERSION)
            .expect("provider config")
    }

    fn execute(
        role: TwoPartyDeriverRole,
        peer: Option<&[u8]>,
        seed: u8,
    ) -> RouterAbProtocolResult<TenantRootRoleCreationProgressV1> {
        let mut online = InMemoryProvider::new();
        let mut backup = InMemoryProvider::new();
        execute_tenant_root_role_creation_v1(
            &package_bytes(role, &ISSUER_KEY),
            peer,
            role,
            authority(),
            &trusted_issuer_keys(),
            &test_role_keys(),
            &signer(role),
            &provider_config(),
            &mut online,
            &mut backup,
            ISSUED_AT_MS + 2,
            &mut ChaCha20Rng::from_seed([seed; 32]),
        )
    }

    /// The first leg commits without creating anything durable.
    #[test]
    fn the_first_leg_commits_and_produces_nothing_durable() {
        let progress = execute(TwoPartyDeriverRole::DeriverA, None, 0x77).expect("committed");
        match progress {
            TenantRootRoleCreationProgressV1::Committed { pending } => {
                assert_eq!(pending.role(), TwoPartyDeriverRole::DeriverA);
                assert!(!pending.commitment_bytes().is_empty());
            }
            TenantRootRoleCreationProgressV1::Sealed { .. } => {
                panic!("no peer commitment must not produce sealed material")
            }
        }
    }

    /// The second leg finalizes and seals in one call, so the scalar never has
    /// to survive a request boundary.
    #[test]
    fn the_second_leg_finalizes_and_seals_in_one_call() {
        let TenantRootRoleCreationProgressV1::Committed { pending: a } =
            execute(TwoPartyDeriverRole::DeriverA, None, 0x77).expect("A committed")
        else {
            panic!("expected a committed first leg")
        };
        let a_commitment = a.commitment_bytes().to_vec();

        let progress =
            execute(TwoPartyDeriverRole::DeriverB, Some(&a_commitment), 0x88).expect("B sealed");
        let TenantRootRoleCreationProgressV1::Sealed {
            signed_commitment,
            signed_installation_evidence,
            input,
            managed_backup,
            ..
        } = progress
        else {
            panic!("expected a sealed second leg")
        };
        assert!(!signed_commitment.is_empty());
        assert!(!signed_installation_evidence.is_empty());
        assert_eq!(
            input.installation_evidence_bytes(),
            signed_installation_evidence
        );
        let _ = managed_backup;
    }

    /// A Deriver executes its own role, never the peer's, even when handed the
    /// peer's package: the role comes from the Worker runtime.
    #[test]
    fn a_deriver_will_not_execute_a_package_addressed_to_its_peer() {
        for (packaged, worker) in [
            (TwoPartyDeriverRole::DeriverA, TwoPartyDeriverRole::DeriverB),
            (TwoPartyDeriverRole::DeriverB, TwoPartyDeriverRole::DeriverA),
        ] {
            let mut online = InMemoryProvider::new();
            let mut backup = InMemoryProvider::new();
            assert!(
                execute_tenant_root_role_creation_v1(
                    &package_bytes(packaged, &ISSUER_KEY),
                    None,
                    worker,
                    authority(),
                    &trusted_issuer_keys(),
                    &test_role_keys(),
                    &signer(worker),
                    &provider_config(),
                    &mut online,
                    &mut backup,
                    ISSUED_AT_MS + 2,
                    &mut ChaCha20Rng::from_seed([0x77; 32]),
                )
                .is_err(),
                "{worker:?} must refuse a {packaged:?} package"
            );
        }
    }

    /// The request surface cannot select role, authority, clock, or signer.
    #[test]
    fn the_deriver_request_surface_carries_only_signed_and_public_material() {
        let request = CloudflareDeriverTenantRootCreateRoleShareRequestV1::Initiator {
            role_creation_command_package_b64u: "abc".to_owned(),
            peer_role_creation_command_package_b64u: "peer-package".to_owned(),
        };
        let json = serde_json::to_value(&request).expect("json");
        assert_eq!(json["kind"], "initiator");
        assert_eq!(json["role_creation_command_package_b64u"], "abc");
        assert_eq!(
            json["peer_role_creation_command_package_b64u"],
            "peer-package"
        );

        let request = CloudflareDeriverTenantRootCreateRoleShareRequestV1::PeerCompletion {
            role_creation_command_package_b64u: "peer-package".to_owned(),
            initiator_signed_commitment_b64u: "commitment".to_owned(),
        };
        let json = serde_json::to_value(&request).expect("json");
        assert_eq!(json["kind"], "peer_completion");
        assert_eq!(json["role_creation_command_package_b64u"], "peer-package");
        assert_eq!(json["initiator_signed_commitment_b64u"], "commitment");

        for smuggled in [
            r#"{"role_creation_command_package_b64u":"a","role":"deriver_a"}"#,
            r#"{"role_creation_command_package_b64u":"a","authority_id_b64u":"x"}"#,
            r#"{"role_creation_command_package_b64u":"a","now_ms":1}"#,
            r#"{"role_creation_command_package_b64u":"a","signing_key_id":"k"}"#,
            r#"{"kind":"initiator","role_creation_command_package_b64u":"a"}"#,
            r#"{"kind":"initiator","role_creation_command_package_b64u":"a","peer_role_creation_command_package_b64u":"b","initiator_signed_commitment_b64u":"c"}"#,
            r#"{"kind":"peer_completion","role_creation_command_package_b64u":"a"}"#,
            r#"{"kind":"peer_completion","role_creation_command_package_b64u":"a","initiator_role_creation_command_package_b64u":"b","initiator_signed_commitment_b64u":"c"}"#,
            r#"{"kind":"peer_completion","role_creation_command_package_b64u":"a","initiator_signed_commitment_b64u":"c","pending_persisted":true}"#,
        ] {
            assert!(
                serde_json::from_str::<CloudflareDeriverTenantRootCreateRoleShareRequestV1>(
                    smuggled
                )
                .is_err(),
                "request must reject {smuggled}"
            );
        }
    }

    /// The scalar-leak proof, extended over the sealed persistence input.
    #[test]
    fn no_deriver_response_field_carries_share_material() {
        let TenantRootRoleCreationProgressV1::Committed { pending: a } =
            execute(TwoPartyDeriverRole::DeriverA, None, 0x77).expect("A committed")
        else {
            panic!("expected a committed first leg")
        };
        let a_commitment = a.commitment_bytes().to_vec();
        let TenantRootRoleCreationProgressV1::Sealed {
            signed_commitment,
            signed_installation_evidence,
            input,
            managed_backup,
            completion:
                TenantRootRoleCreationCompletionV1::RoleOnly {
                    provider_canary_receipt,
                },
            ..
        } = execute(TwoPartyDeriverRole::DeriverB, Some(&a_commitment), 0x88).expect("B sealed")
        else {
            panic!("expected a sealed second leg")
        };

        // Everything this Deriver would put on the wire back to the Router.
        let signed_managed_backup = managed_backup.canonical_bytes().to_vec();
        let response = CloudflareDeriverTenantRootCreateRoleShareResponseV1::PeerCompleted {
            role: CloudflareTenantRootCreateRoleV1::from_protocol(TwoPartyDeriverRole::DeriverB),
            signed_commitment_b64u: crate::encode_base64url_bytes_v1(&signed_commitment),
            signed_installation_evidence_b64u: crate::encode_base64url_bytes_v1(
                &signed_installation_evidence,
            ),
            signed_managed_backup_b64u: crate::encode_base64url_bytes_v1(&signed_managed_backup),
            terminal_receipt_b64u: crate::encode_base64url_bytes_v1(b"terminal-receipt"),
            provider_canary_receipt_b64u: crate::encode_base64url_bytes_v1(
                &provider_canary_receipt,
            ),
        };
        let response_json = serde_json::to_string(&response).expect("response json");
        assert!(response_json.contains("\"kind\":\"peer_completed\""));
        assert!(response_json.contains("signed_managed_backup_b64u"));
        assert!(response_json.contains("provider_canary_receipt_b64u"));
        assert!(response_json.contains("terminal_receipt_b64u"));
        assert!(!response_json.contains("pending_persisted"));
        for incomplete in [
            r#"{"role":"deriver_b","signed_commitment_b64u":"c","signed_installation_evidence_b64u":"e","signed_managed_backup_b64u":"b","terminal_receipt_b64u":"r","provider_canary_receipt_b64u":"p"}"#,
            r#"{"kind":"peer_completed","role":"deriver_b","signed_commitment_b64u":"c","signed_installation_evidence_b64u":"e"}"#,
            r#"{"kind":"peer_completed","role":"deriver_b","signed_commitment_b64u":"c","signed_installation_evidence_b64u":"e","signed_managed_backup_b64u":"b","terminal_receipt_b64u":"r","provider_canary_receipt_b64u":"p","pending_persisted":true}"#,
        ] {
            assert!(
                serde_json::from_str::<CloudflareDeriverTenantRootCreateRoleShareResponseV1>(
                    incomplete
                )
                .is_err(),
                "response must reject {incomplete}"
            );
        }

        // B's scalar, recovered from the record it is about to persist.
        let sealed = input.sealed_share_ciphertext_for_test();
        assert!(!sealed.is_empty());

        // The commitment is a public point; the evidence is a proof. Neither,
        // nor the serialized response, may contain the sealed ciphertext.
        for (label, wire) in [
            ("signed commitment", signed_commitment.as_slice()),
            (
                "signed installation evidence",
                signed_installation_evidence.as_slice(),
            ),
            ("response json", response_json.as_bytes()),
        ] {
            assert!(
                !wire
                    .windows(sealed.len())
                    .any(|window| window == sealed.as_slice()),
                "{label} contains sealed share material"
            );
        }
    }
}

#[cfg(all(test, feature = "workers-rs"))]
mod initiator_tests {
    use super::admission_tests::*;
    use super::live_execution_tests::test_provider_config;
    use super::tests::InMemoryProvider;
    use super::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core_06::SeedableRng;

    /// A peer that runs the real second leg against whatever commitment it is
    /// actually handed.
    ///
    /// It deliberately does NOT recompute the initiator's commitment. An
    /// earlier version did, using the same deterministic seed, which hid that
    /// production B has no way to obtain it.
    struct RealPeer {
        role: TwoPartyDeriverRole,
        received_initiator_commitment: Option<Vec<u8>>,
        withhold_receipt: bool,
        calls: usize,
    }

    impl RealPeer {
        fn new(role: TwoPartyDeriverRole) -> Self {
            Self {
                role,
                received_initiator_commitment: None,
                withhold_receipt: false,
                calls: 0,
            }
        }
    }

    /// Mints the receipt B's role key would actually sign for its insertion.
    ///
    /// Signed over B's real replay key and the exact installation evidence, so
    /// the tests exercise the verifier rather than a placeholder.
    pub(crate) fn peer_terminal_receipt(
        peer_role: TwoPartyDeriverRole,
        peer_package: &[u8],
        evidence_bytes: &[u8],
        signing_key: &[u8; 32],
    ) -> Vec<u8> {
        let package = TenantRootRoleCreationCommandPackageV1::decode_canonical_bytes(peer_package)
            .expect("peer package");
        let command = package
            .verify(
                peer_role,
                authority(),
                ISSUER_KEY_ID,
                &ed25519_dalek::SigningKey::from_bytes(&ISSUER_KEY)
                    .verifying_key()
                    .to_bytes(),
            )
            .expect("verified peer command")
            .into_command();
        router_ab_core::TenantRootCommandTerminalReceiptV1::sign_success(
            *command.scope().key(),
            command.digest(),
            evidence_bytes.to_vec(),
            ISSUED_AT_MS + 3,
            signing_key_id(peer_role),
            signing_key,
        )
        .expect("terminal receipt")
        .canonical_bytes()
        .expect("receipt bytes")
    }

    impl TenantRootPeerRoleDriverV1 for RealPeer {
        async fn drive_peer(
            &mut self,
            peer_package_bytes: &[u8],
            initiator_signed_commitment: &[u8],
        ) -> RouterAbProtocolResult<TenantRootPeerRoleOutcomeV1> {
            self.calls += 1;
            self.received_initiator_commitment = Some(initiator_signed_commitment.to_vec());

            let mut online = InMemoryProvider::new();
            let mut backup = InMemoryProvider::new();
            let progress = execute_tenant_root_role_creation_v1(
                peer_package_bytes,
                Some(initiator_signed_commitment),
                self.role,
                authority(),
                &trusted_issuer_keys(),
                &test_role_keys(),
                &signer(self.role),
                &test_provider_config(),
                &mut online,
                &mut backup,
                ISSUED_AT_MS + 2,
                &mut ChaCha20Rng::from_seed([0x88; 32]),
            )?;
            let TenantRootRoleCreationProgressV1::Sealed {
                signed_commitment,
                signed_installation_evidence,
                managed_backup,
                completion:
                    TenantRootRoleCreationCompletionV1::RoleOnly {
                        provider_canary_receipt,
                    },
                ..
            } = progress
            else {
                panic!("the peer leg must seal")
            };
            let signed_managed_backup = managed_backup.canonical_bytes().to_vec();
            // The receipt B's role key would really sign for this insertion.
            let terminal_receipt = if self.withhold_receipt {
                b"not-a-receipt-at-all".to_vec()
            } else {
                peer_terminal_receipt(
                    self.role,
                    peer_package_bytes,
                    &signed_installation_evidence,
                    &role_key(self.role).to_bytes(),
                )
            };
            Ok(TenantRootPeerRoleOutcomeV1 {
                signed_commitment,
                signed_installation_evidence,
                signed_managed_backup,
                provider_canary_receipt,
                terminal_receipt,
            })
        }
    }

    /// A peer that fails, standing in for a lost or refused service call.
    struct FailingPeer;
    impl TenantRootPeerRoleDriverV1 for FailingPeer {
        async fn drive_peer(
            &mut self,
            _: &[u8],
            _: &[u8],
        ) -> RouterAbProtocolResult<TenantRootPeerRoleOutcomeV1> {
            Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "peer unavailable",
            ))
        }
    }

    /// A peer that returns another ceremony's installation evidence.
    struct ForeignEvidencePeer {
        role: TwoPartyDeriverRole,
    }
    impl TenantRootPeerRoleDriverV1 for ForeignEvidencePeer {
        async fn drive_peer(
            &mut self,
            peer_package_bytes: &[u8],
            initiator_signed_commitment: &[u8],
        ) -> RouterAbProtocolResult<TenantRootPeerRoleOutcomeV1> {
            let mut honest = RealPeer::new(self.role);
            let mut outcome = honest
                .drive_peer(peer_package_bytes, initiator_signed_commitment)
                .await?;
            // Corrupt the evidence so its signature no longer verifies.
            outcome.signed_installation_evidence[0] ^= 0xff;
            Ok(outcome)
        }
    }

    async fn drive<P: TenantRootPeerRoleDriverV1>(
        peer: &mut P,
    ) -> RouterAbProtocolResult<TenantRootRoleCreationProgressV1> {
        let mut online = InMemoryProvider::new();
        let mut backup = InMemoryProvider::new();
        drive_tenant_root_role_creation_as_initiator_v1(
            &package_bytes(TwoPartyDeriverRole::DeriverA, &ISSUER_KEY),
            &package_bytes(TwoPartyDeriverRole::DeriverB, &ISSUER_KEY),
            TwoPartyDeriverRole::DeriverA,
            authority(),
            &trusted_issuer_keys(),
            &test_role_keys(),
            &signer(TwoPartyDeriverRole::DeriverA),
            &test_provider_config(),
            &mut online,
            &mut backup,
            peer,
            ISSUED_AT_MS + 2,
            &mut ChaCha20Rng::from_seed([0x77; 32]),
        )
        .await
    }

    fn block_on<F: core::future::Future>(future: F) -> F::Output {
        futures::executor::block_on(future)
    }

    /// The peer is handed the initiator's exact commitment and package.
    ///
    /// This is the property the earlier test masked: B cannot derive A's
    /// commitment, so the orchestration must transport it.
    #[test]
    fn the_peer_receives_the_initiators_exact_commitment() {
        let mut peer = RealPeer::new(TwoPartyDeriverRole::DeriverB);
        let progress = block_on(drive(&mut peer)).expect("initiator sealed");
        assert_eq!(peer.calls, 1, "the peer is driven exactly once");

        let received = peer
            .received_initiator_commitment
            .expect("the peer must receive a commitment");
        let TenantRootRoleCreationProgressV1::Sealed {
            signed_commitment, ..
        } = progress
        else {
            panic!("expected a sealed initiator")
        };
        assert_eq!(
            received, signed_commitment,
            "the peer must receive the initiator's exact commitment"
        );
    }

    /// A failed peer call abandons the attempt. Nothing durable was written for
    /// the initiator, so returning the error IS the cleanup.
    #[test]
    fn a_failed_peer_call_abandons_the_initiator_attempt() {
        assert!(
            block_on(drive(&mut FailingPeer)).is_err(),
            "a failed peer call must abandon rather than park a scalar"
        );
    }

    /// Non-empty garbage is refused. The earlier check only required bytes to
    /// be present, which is the same trust problem as a boolean.
    #[test]
    fn a_non_empty_garbage_receipt_is_refused() {
        let mut peer = RealPeer::new(TwoPartyDeriverRole::DeriverB);
        peer.withhold_receipt = true;
        assert!(
            block_on(drive(&mut peer)).is_err(),
            "non-empty bytes must not stand in for a receipt"
        );
    }

    /// A validly signed receipt for DIFFERENT evidence is refused: the payload
    /// must be exactly the installation it attests.
    #[test]
    fn a_valid_receipt_for_other_evidence_is_refused() {
        struct WrongPayloadPeer(TwoPartyDeriverRole);
        impl TenantRootPeerRoleDriverV1 for WrongPayloadPeer {
            async fn drive_peer(
                &mut self,
                peer_package_bytes: &[u8],
                initiator_signed_commitment: &[u8],
            ) -> RouterAbProtocolResult<TenantRootPeerRoleOutcomeV1> {
                let mut honest = RealPeer::new(self.0);
                let mut outcome = honest
                    .drive_peer(peer_package_bytes, initiator_signed_commitment)
                    .await?;
                // A real signature over a real replay key, but attesting other bytes.
                outcome.terminal_receipt = peer_terminal_receipt(
                    self.0,
                    peer_package_bytes,
                    b"some other evidence",
                    &role_key(self.0).to_bytes(),
                );
                Ok(outcome)
            }
        }
        assert!(
            block_on(drive(&mut WrongPayloadPeer(TwoPartyDeriverRole::DeriverB))).is_err(),
            "a receipt attesting other evidence must be refused"
        );
    }

    /// A receipt signed by the wrong role key is refused.
    #[test]
    fn a_receipt_signed_by_the_wrong_role_is_refused() {
        struct WrongSignerPeer(TwoPartyDeriverRole);
        impl TenantRootPeerRoleDriverV1 for WrongSignerPeer {
            async fn drive_peer(
                &mut self,
                peer_package_bytes: &[u8],
                initiator_signed_commitment: &[u8],
            ) -> RouterAbProtocolResult<TenantRootPeerRoleOutcomeV1> {
                let mut honest = RealPeer::new(self.0);
                let mut outcome = honest
                    .drive_peer(peer_package_bytes, initiator_signed_commitment)
                    .await?;
                outcome.terminal_receipt = peer_terminal_receipt(
                    self.0,
                    peer_package_bytes,
                    &outcome.signed_installation_evidence,
                    // The initiator's key, not the peer's.
                    &role_key(TwoPartyDeriverRole::DeriverA).to_bytes(),
                );
                Ok(outcome)
            }
        }
        assert!(
            block_on(drive(&mut WrongSignerPeer(TwoPartyDeriverRole::DeriverB))).is_err(),
            "a receipt signed by the wrong role must be refused"
        );
    }

    /// A peer whose evidence is validly signed over a DIFFERENT commitment pair
    /// is refused.
    ///
    /// This is the case a signature-only check cannot catch: every signature
    /// verifies, the role and ceremony match, but the transcript attests a pair
    /// the initiator is not part of.
    #[test]
    fn valid_evidence_over_a_different_commitment_pair_is_refused() {
        struct OtherPairPeer(TwoPartyDeriverRole);
        impl TenantRootPeerRoleDriverV1 for OtherPairPeer {
            async fn drive_peer(
                &mut self,
                peer_package_bytes: &[u8],
                _initiator_signed_commitment: &[u8],
            ) -> RouterAbProtocolResult<TenantRootPeerRoleOutcomeV1> {
                // Build a SECOND initiator commitment the real initiator never
                // produced, and have the peer finalize against that instead.
                let other_initiator = admit_for_with_rng(TwoPartyDeriverRole::DeriverA, 0x5a);
                let other_commitment = other_initiator.commitment_bytes().to_vec();
                let mut honest = RealPeer::new(self.0);
                honest
                    .drive_peer(peer_package_bytes, &other_commitment)
                    .await
            }
        }
        let err = block_on(drive(&mut OtherPairPeer(TwoPartyDeriverRole::DeriverB)))
            .expect_err("evidence over another pair");
        assert_eq!(err.code(), RouterAbProtocolErrorCode::ForbiddenLocalBinding);
    }

    /// The exact receipt and the exact pair are accepted.
    #[test]
    fn the_exact_receipt_and_commitment_pair_are_accepted() {
        let mut peer = RealPeer::new(TwoPartyDeriverRole::DeriverB);
        assert!(matches!(
            block_on(drive(&mut peer)).expect("accepted"),
            TenantRootRoleCreationProgressV1::Sealed { .. }
        ));
    }

    /// The peer's installation evidence is verified, not taken on trust.
    #[test]
    fn the_initiator_verifies_the_peers_installation_evidence() {
        let mut peer = ForeignEvidencePeer {
            role: TwoPartyDeriverRole::DeriverB,
        };
        assert!(
            block_on(drive(&mut peer)).is_err(),
            "unverifiable peer evidence must be refused"
        );
    }
}

#[cfg(all(test, feature = "workers-rs"))]
mod progress_debug_tests {
    use super::admission_tests::*;
    use super::live_execution_tests::test_provider_config;
    use super::tests::InMemoryProvider;
    use super::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core_06::SeedableRng;

    /// The progress enum derives Debug, so pin that the derive cannot print
    /// share material: a future field that is not itself redacting would be
    /// caught here rather than in a log.
    #[test]
    fn the_progress_debug_never_prints_share_material() {
        let mut online = InMemoryProvider::new();
        let mut backup = InMemoryProvider::new();
        let progress = execute_tenant_root_role_creation_v1(
            &package_bytes(TwoPartyDeriverRole::DeriverA, &ISSUER_KEY),
            None,
            TwoPartyDeriverRole::DeriverA,
            authority(),
            &trusted_issuer_keys(),
            &test_role_keys(),
            &signer(TwoPartyDeriverRole::DeriverA),
            &test_provider_config(),
            &mut online,
            &mut backup,
            ISSUED_AT_MS + 2,
            &mut ChaCha20Rng::from_seed([0x77; 32]),
        )
        .expect("committed");
        let rendered = format!("{progress:?}");
        assert!(
            rendered.contains("[redacted]"),
            "the share must render redacted, got: {rendered}"
        );
    }
}
