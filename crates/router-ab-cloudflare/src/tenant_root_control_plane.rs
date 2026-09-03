//! Tenant-root control-plane issuer operations.
//!
//! The control plane is the sole holder of the R120 issuer private signing
//! key. Every operation here constructs a canonical artifact from
//! authoritative Durable Object state and local key configuration, then
//! signs it. There is deliberately no raw-payload signing entry point: the
//! request types name *what* to issue, never the bytes to sign.

use router_ab_core::{
    TenantRootActivationReceiptTransitionV1, TenantRootActiveRootPairV1,
    TenantRootCanaryCurveFamilyV1, TenantRootCeremonyContextV1, TenantRootCeremonyEpochsV1,
    TenantRootCeremonyNonceV1, TenantRootCeremonySessionIdV1, TenantRootControlPlaneAuthorityIdV1,
    TenantRootCreationCapabilityNonceV1, TenantRootCreationCapabilityV1,
    TenantRootCreationJournalV1, TenantRootManagedRestoreRoleV1, TenantRootProtocolDigestV1,
    TenantRootRoleCleanupCommandV1, TenantRootRoleCleanupTargetV1,
    TenantRootRoleCreationCommandPackageV1, TenantRootRoleCreationCommandV1,
    TenantRootRoleRefreshCommandV1, TenantRootShareEpoch, TenantRootSignedActivationReceiptV1,
    TenantRootSignedManagedBackupV1, TenantRootSignedProviderCanaryReceiptV1,
    TenantRootSignedShareInstallationEvidenceV1, VerifiedTenantRootCreationGrantV1,
    VerifiedTenantRootInitialCreationActivationEvidenceBundleV1,
    VerifiedTenantRootRefreshSwapActivationEvidenceBundleV1,
    TENANT_ROOT_ACTIVATION_RECEIPT_MAX_BYTES_V1, TENANT_ROOT_MAX_LIFETIME_MS_V1,
    TENANT_ROOT_PROVIDER_CANARY_RECEIPT_MAX_BYTES_V1,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use threshold_prf::TwoPartyDeriverRole;
use zeroize::Zeroizing;

use crate::durable_object::tenant_root_creation::{
    CloudflareTenantRootCreationInstallationCheckpointReadStateV1,
    CloudflareTenantRootCreationInstallationRoleV1,
    CloudflareTenantRootCreationJournalReadResponseV1, ValidatedTenantRootCreationJournalV1,
};
use crate::{RouterAbProtocolError, RouterAbProtocolErrorCode, RouterAbProtocolResult};

/// Maximum accepted request size for the role creation command operation.
pub const TENANT_ROOT_CONTROL_PLANE_ROLE_CREATION_COMMAND_REQUEST_MAX_BYTES_V1: usize = 2 * 1024;
pub const TENANT_ROOT_CONTROL_PLANE_CLEANUP_COMMAND_REQUEST_MAX_BYTES_V1: usize = 2 * 1024;
pub const TENANT_ROOT_CONTROL_PLANE_REFRESH_COMMANDS_REQUEST_MAX_BYTES_V1: usize = 2 * 1024;

/// Role label on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CloudflareTenantRootControlPlaneRoleV1 {
    DeriverA,
    DeriverB,
}

impl CloudflareTenantRootControlPlaneRoleV1 {
    pub(crate) const fn to_protocol(self) -> TwoPartyDeriverRole {
        match self {
            Self::DeriverA => TwoPartyDeriverRole::DeriverA,
            Self::DeriverB => TwoPartyDeriverRole::DeriverB,
        }
    }

    pub(crate) const fn from_protocol(role: TwoPartyDeriverRole) -> Self {
        match role {
            TwoPartyDeriverRole::DeriverA => Self::DeriverA,
            TwoPartyDeriverRole::DeriverB => Self::DeriverB,
        }
    }
}

/// Router -> control plane: mint the creation command for one role.
///
/// This is the entire caller-supplied surface. Authority, revision, session,
/// nonce, journal, context, time window, and issuer key are all derived.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareTenantRootControlPlaneRoleCreationCommandRequestV1 {
    pub identity_digest_b64u: String,
    pub custody_lineage_b64u: String,
    pub role: CloudflareTenantRootControlPlaneRoleV1,
}

/// Control plane -> Router: the signed command and its self-contained package.
///
/// Public bytes only. The package carries the Started journal preimage so a
/// Deriver can verify the command at its own boundary with no Router state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareTenantRootControlPlaneRoleCreationCommandResponseV1 {
    pub role: CloudflareTenantRootControlPlaneRoleV1,
    pub issuer_key_id: String,
    pub role_creation_command_b64u: String,
    pub role_creation_command_package_b64u: String,
}

/// Router -> control plane: mint both role commands for one fresh refresh.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareTenantRootControlPlaneRefreshCommandsRequestV1 {
    pub identity_digest_b64u: String,
    pub custody_lineage_b64u: String,
}

/// Control plane -> Router: one exact context and its A/B issuer commands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareTenantRootControlPlaneRefreshCommandsResponseV1 {
    pub refresh_context_b64u: String,
    pub deriver_a_refresh_command_b64u: String,
    pub deriver_b_refresh_command_b64u: String,
    pub issuer_key_id: String,
}

/// Router -> control plane: issue cleanup for the one stranded role, if any.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareTenantRootControlPlaneCleanupCommandRequestV1 {
    pub identity_digest_b64u: String,
    pub custody_lineage_b64u: String,
}

/// Control plane -> Router: exact issuer-signed cleanup authorization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareTenantRootControlPlaneCleanupCommandResponseV1 {
    pub role: CloudflareTenantRootControlPlaneRoleV1,
    pub cleanup_command_b64u: String,
}

/// Maximum accepted request size for the genesis operation.
pub const TENANT_ROOT_CONTROL_PLANE_CREATE_TENANT_ROOT_REQUEST_MAX_BYTES_V1: usize = 32 * 1024;

/// Maximum accepted request size for initial activation evidence.
pub(crate) const TENANT_ROOT_CONTROL_PLANE_INITIAL_ACTIVATION_REQUEST_MAX_BYTES_V1: usize =
    256 * 1024;
const TENANT_ROOT_CONTROL_PLANE_INITIAL_ACTIVATION_RESPONSE_MAX_BYTES_V1: usize = 32 * 1024;
/// Maximum accepted request size for refresh activation evidence.
pub(crate) const TENANT_ROOT_CONTROL_PLANE_REFRESH_ACTIVATION_REQUEST_MAX_BYTES_V1: usize =
    256 * 1024;

/// Router -> control plane: issue the signed initial-activation receipt from
/// exact public installation, managed-backup, and provider-canary wires.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CloudflareTenantRootControlPlaneInitialActivationRequestV1 {
    pub(crate) deriver_a_signed_installation_evidence_b64u: String,
    pub(crate) deriver_b_signed_installation_evidence_b64u: String,
    pub(crate) deriver_a_signed_managed_backup_b64u: String,
    pub(crate) deriver_b_signed_managed_backup_b64u: String,
    pub(crate) ecdsa_provider_canary_receipt_b64u: String,
    pub(crate) ed25519_provider_canary_receipt_b64u: String,
}

/// Router -> control plane: issue the signed refresh-swap receipt from exact
/// public installation, managed-backup, and provider-canary wires.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CloudflareTenantRootControlPlaneRefreshActivationRequestV1 {
    pub(crate) deriver_a_signed_installation_evidence_b64u: String,
    pub(crate) deriver_b_signed_installation_evidence_b64u: String,
    pub(crate) deriver_a_signed_managed_backup_b64u: String,
    pub(crate) deriver_b_signed_managed_backup_b64u: String,
    pub(crate) ecdsa_provider_canary_receipt_b64u: String,
    pub(crate) ed25519_provider_canary_receipt_b64u: String,
}

/// Router -> control plane: open a tenant root under a signed grant.
///
/// The grant is the entire caller-supplied surface. It is authorization, not
/// instruction: the issuer reads a tenant and a lineage from it and derives
/// everything else.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareTenantRootControlPlaneCreateTenantRootRequestV1 {
    pub creation_grant_b64u: String,
}

/// Control plane -> Router: the persisted creation, public evidence only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareTenantRootControlPlaneCreateTenantRootResponseV1 {
    pub identity_digest_b64u: String,
    pub custody_lineage_b64u: String,
    pub revision: u64,
    pub journal_digest_b64u: String,
    pub capability_digest_b64u: String,
    pub status: CloudflareTenantRootCreationStatusV1,
    /// True when this exact creation had already been persisted.
    pub replayed: bool,
}

/// Control plane -> Router: the exact signed initial-activation receipt.
///
/// The receipt contains the complete verified evidence binding. Keeping the
/// transport projection to canonical bytes prevents a second, weaker metadata
/// shape from becoming an activation authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareTenantRootControlPlaneInitialActivationReceiptResponseV1 {
    pub activation_receipt_b64u: String,
}

/// Control plane -> Router: the exact signed refresh-swap activation receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CloudflareTenantRootControlPlaneRefreshActivationReceiptResponseV1 {
    pub(crate) activation_receipt_b64u: String,
}

/// Exhaustive durable state of one tenant-root creation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CloudflareTenantRootCreationStatusV1 {
    Pending,
    OneRoleInstalled {
        role: CloudflareTenantRootControlPlaneRoleV1,
    },
    Ready {
        root_commitment_b64u: String,
    },
    Abandoned {
        role: CloudflareTenantRootControlPlaneRoleV1,
    },
}

/// Public creation progress the issuer must respect before minting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TenantRootCreationProgressV1 {
    pub(crate) committed_roles: Vec<TwoPartyDeriverRole>,
    pub(crate) installation_checkpoint:
        CloudflareTenantRootCreationInstallationCheckpointReadStateV1,
    pub(crate) cleanup_checkpointed: bool,
}

impl TenantRootCreationProgressV1 {
    pub(crate) fn from_read_response(
        response: &CloudflareTenantRootCreationJournalReadResponseV1,
    ) -> Self {
        Self {
            committed_roles: response
                .committed_roles
                .iter()
                .map(|role: &CloudflareTenantRootCreationInstallationRoleV1| role.to_protocol())
                .collect(),
            installation_checkpoint: response.installation_checkpoint.clone(),
            cleanup_checkpointed: response.cleanup_checkpointed,
        }
    }
}

/// Everything the issuer derives before it signs; nothing here is caller-chosen.
pub(crate) struct TenantRootRoleCreationCommandIssuanceV1<'a> {
    /// Validated against the issuer's own published keys and the locally
    /// derived authority id.
    pub(crate) journal: &'a ValidatedTenantRootCreationJournalV1,
    pub(crate) progress: &'a TenantRootCreationProgressV1,
    pub(crate) role: TwoPartyDeriverRole,
    /// Derived from the Durable Object binding, never read from a request.
    pub(crate) authority_id: TenantRootControlPlaneAuthorityIdV1,
    pub(crate) now_ms: u64,
}

/// A signed command and the package a Deriver consumes. Both are public artifacts.
#[derive(Debug)]
pub(crate) struct IssuedTenantRootRoleCreationCommandV1 {
    pub(crate) command: TenantRootRoleCreationCommandV1,
    pub(crate) package: TenantRootRoleCreationCommandPackageV1,
}

/// Everything the issuer derives before it signs one refresh pair; nothing
/// here is caller-chosen.
pub(crate) struct TenantRootRoleRefreshCommandIssuanceV1<'a> {
    /// The one active A/B pair resolved from the tenant's private stores.
    pub(crate) active_pair: &'a TenantRootActiveRootPairV1,
    /// The exact refresh ceremony context selected by the control plane.
    pub(crate) refresh_context: &'a TenantRootCeremonyContextV1,
    /// The lifecycle revision the Router must still hold when applying either command.
    pub(crate) expected_control_plane_revision: u64,
    /// The locally derived control-plane authority binding.
    pub(crate) authority_id: TenantRootControlPlaneAuthorityIdV1,
    /// The issuer's current time, used for both commands.
    pub(crate) now_ms: u64,
}

/// The two signed role wires for one exact refresh ceremony.
#[derive(Debug)]
pub(crate) struct IssuedTenantRootRoleRefreshCommandsV1 {
    pub(crate) deriver_a: TenantRootRoleRefreshCommandV1,
    pub(crate) deriver_b: TenantRootRoleRefreshCommandV1,
}

fn refused(message: &'static str) -> RouterAbProtocolError {
    RouterAbProtocolError::new(RouterAbProtocolErrorCode::ForbiddenLocalBinding, message)
}

fn derivation(error: router_ab_core::RouterAbDerivationError) -> RouterAbProtocolError {
    RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::MalformedWirePayload,
        format!("tenant-root control-plane issuance failed: {error}"),
    )
}

/// Signs an initial-activation receipt from a fully verified evidence bundle.
///
/// Evidence collection and lifecycle mutation stay outside this boundary. A
/// caller must supply the core bundle, whose constructor already enforces both
/// role installations, the selected availability branch, and both canaries.
pub(crate) fn issue_tenant_root_initial_activation_receipt_v1(
    bundle: &VerifiedTenantRootInitialCreationActivationEvidenceBundleV1,
    activated_at_ms: u64,
    authority_id: TenantRootControlPlaneAuthorityIdV1,
    issuer_key_id: &str,
    issuer_seed: &Zeroizing<[u8; 32]>,
) -> RouterAbProtocolResult<TenantRootSignedActivationReceiptV1> {
    TenantRootSignedActivationReceiptV1::sign_initial_creation(
        bundle,
        activated_at_ms,
        authority_id,
        issuer_key_id,
        issuer_seed,
    )
    .map_err(derivation)
}

/// Signs a refresh-swap activation receipt from a fully verified evidence bundle.
///
/// The bundle owns the exact current/next pair and lifecycle revisions, so the
/// issuer only supplies its local authority, signing key, and activation time.
pub(crate) fn issue_tenant_root_refresh_activation_receipt_v1(
    bundle: &VerifiedTenantRootRefreshSwapActivationEvidenceBundleV1,
    activated_at_ms: u64,
    authority_id: TenantRootControlPlaneAuthorityIdV1,
    issuer_key_id: &str,
    issuer_seed: &Zeroizing<[u8; 32]>,
) -> RouterAbProtocolResult<TenantRootSignedActivationReceiptV1> {
    TenantRootSignedActivationReceiptV1::sign_refresh_swap(
        bundle,
        activated_at_ms,
        authority_id,
        issuer_key_id,
        issuer_seed,
    )
    .map_err(derivation)
}

/// Projects an issued receipt onto the strict service-binding wire.
pub(crate) fn initial_activation_receipt_response_v1(
    receipt: TenantRootSignedActivationReceiptV1,
) -> RouterAbProtocolResult<CloudflareTenantRootControlPlaneInitialActivationReceiptResponseV1> {
    let receipt_bytes = receipt.canonical_bytes().map_err(derivation)?;
    Ok(
        CloudflareTenantRootControlPlaneInitialActivationReceiptResponseV1 {
            activation_receipt_b64u: crate::encode_base64url_bytes_v1(&receipt_bytes),
        },
    )
}

/// Projects an issued refresh receipt onto the strict service-binding wire.
pub(crate) fn refresh_activation_receipt_response_v1(
    receipt: TenantRootSignedActivationReceiptV1,
) -> RouterAbProtocolResult<CloudflareTenantRootControlPlaneRefreshActivationReceiptResponseV1> {
    let receipt_bytes = receipt.canonical_bytes().map_err(derivation)?;
    Ok(
        CloudflareTenantRootControlPlaneRefreshActivationReceiptResponseV1 {
            activation_receipt_b64u: crate::encode_base64url_bytes_v1(&receipt_bytes),
        },
    )
}

/// Mints one role creation command from authoritative state.
///
/// Fail-closed conditions, in order: creation already checkpointed; the role
/// already committed; `now` outside the ceremony window; a command window
/// that would be empty. The command is then signed with the active issuer key
/// and packaged with the Started journal preimage.
pub(crate) fn issue_tenant_root_role_creation_command_v1(
    issuance: TenantRootRoleCreationCommandIssuanceV1<'_>,
    active_issuer_key_id: &str,
    issuer_seed: &Zeroizing<[u8; 32]>,
) -> RouterAbProtocolResult<IssuedTenantRootRoleCreationCommandV1> {
    if issuance.progress.cleanup_checkpointed {
        return Err(refused(
            "tenant-root creation was abandoned and cleaned; no further role command may be issued",
        ));
    }
    if !matches!(
        issuance.progress.installation_checkpoint,
        CloudflareTenantRootCreationInstallationCheckpointReadStateV1::None
    ) {
        return Err(refused(
            "tenant-root creation already installed a role; cleanup or completion must finish first",
        ));
    }
    if issuance.progress.committed_roles.contains(&issuance.role) {
        return Err(refused(
            "tenant-root creation role has already committed; its command may not be reissued",
        ));
    }
    let context: &TenantRootCeremonyContextV1 = &issuance.journal.ceremony_context;
    if issuance.now_ms < context.issued_at_ms() || issuance.now_ms >= context.expires_at_ms() {
        return Err(refused(
            "tenant-root creation ceremony window does not contain the issuance time",
        ));
    }
    let issued_at_ms = issuance.now_ms;
    let expires_at_ms = issued_at_ms
        .saturating_add(TENANT_ROOT_MAX_LIFETIME_MS_V1)
        .min(context.expires_at_ms());
    if expires_at_ms <= issued_at_ms {
        return Err(refused(
            "tenant-root creation ceremony window leaves no room for a role command",
        ));
    }
    let journal: &TenantRootCreationJournalV1 = &issuance.journal.journal;
    let command = TenantRootRoleCreationCommandV1::sign(
        journal,
        context,
        issuance.role,
        issuance.authority_id,
        issued_at_ms,
        expires_at_ms,
        active_issuer_key_id,
        issuer_seed,
    )
    .map_err(derivation)?;
    let package = TenantRootRoleCreationCommandPackageV1::new(journal.clone(), command.clone())
        .map_err(derivation)?;
    Ok(IssuedTenantRootRoleCreationCommandV1 { command, package })
}

/// Mints both refresh role commands from one validated active pair and one
/// exact refresh context.
pub(crate) fn issue_tenant_root_role_refresh_commands_v1(
    issuance: TenantRootRoleRefreshCommandIssuanceV1<'_>,
    active_issuer_key_id: &str,
    issuer_seed: &Zeroizing<[u8; 32]>,
) -> RouterAbProtocolResult<IssuedTenantRootRoleRefreshCommandsV1> {
    let context = issuance.refresh_context;
    if issuance.now_ms < context.issued_at_ms() || issuance.now_ms >= context.expires_at_ms() {
        return Err(refused(
            "tenant-root refresh ceremony window does not contain the issuance time",
        ));
    }
    let issued_at_ms = issuance.now_ms;
    let expires_at_ms = issued_at_ms
        .saturating_add(TENANT_ROOT_MAX_LIFETIME_MS_V1)
        .min(context.expires_at_ms());
    if expires_at_ms <= issued_at_ms {
        return Err(refused(
            "tenant-root refresh ceremony window leaves no room for a role command",
        ));
    }

    let deriver_a = TenantRootRoleRefreshCommandV1::sign(
        issuance.active_pair,
        context,
        TwoPartyDeriverRole::DeriverA,
        issuance.expected_control_plane_revision,
        issuance.authority_id,
        issued_at_ms,
        expires_at_ms,
        active_issuer_key_id,
        issuer_seed,
    )
    .map_err(derivation)?;
    let deriver_b = TenantRootRoleRefreshCommandV1::sign(
        issuance.active_pair,
        context,
        TwoPartyDeriverRole::DeriverB,
        issuance.expected_control_plane_revision,
        issuance.authority_id,
        issued_at_ms,
        expires_at_ms,
        active_issuer_key_id,
        issuer_seed,
    )
    .map_err(derivation)?;

    Ok(IssuedTenantRootRoleRefreshCommandsV1 {
        deriver_a,
        deriver_b,
    })
}

const TENANT_ROOT_CEREMONY_SESSION_DOMAIN_V1: &[u8] = b"tenant_root_creation_ceremony_session_v1";
const TENANT_ROOT_CEREMONY_NONCE_DOMAIN_V1: &[u8] = b"tenant_root_creation_ceremony_nonce_v1";
const TENANT_ROOT_CAPABILITY_NONCE_DOMAIN_V1: &[u8] = b"tenant_root_creation_capability_nonce_v1";

/// Ceremony material for one genesis operation, derived from the grant.
///
/// A caller cannot supply a session, a nonce, a window, or the expected role
/// signers: choosing any of them would let a caller steer the ceremony that a
/// later role command is bound to.
///
/// The material is *derived*, not drawn, so genesis is a pure function of the
/// authorization. The Durable Object recognises a replay only when the journal
/// and capability match byte for byte, so freshly drawn randomness would make a
/// lost-response retry of the same grant conflict with its own first attempt.
/// Deriving instead means the same grant reproduces the same creation and the
/// retry lands on the object's existing replay path, while a different grant
/// for the same tenant still produces different bytes and conflicts.
///
/// Unpredictability is preserved: the derivation is domain-separated over the
/// grant's canonical bytes, which carry the authority's 32-byte random nonce.
/// Predicting this material requires the grant, and holding the grant already
/// authorizes opening the creation.
pub(crate) struct TenantRootCreationCeremonyDrawV1 {
    pub(crate) session_id: TenantRootCeremonySessionIdV1,
    pub(crate) ceremony_nonce: TenantRootCeremonyNonceV1,
    pub(crate) capability_nonce: TenantRootCreationCapabilityNonceV1,
    pub(crate) deriver_a_signing_key_id: String,
    pub(crate) deriver_b_signing_key_id: String,
}

fn derive_ceremony_bytes_v1<const N: usize>(domain: &[u8], grant_bytes: &[u8]) -> [u8; N] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update((grant_bytes.len() as u64).to_be_bytes());
    hasher.update(grant_bytes);
    let digest: [u8; 32] = hasher.finalize().into();
    let mut out = [0_u8; N];
    out.copy_from_slice(&digest[..N]);
    out
}

/// Derives one ceremony's material from the exact signed grant.
pub(crate) fn derive_tenant_root_creation_ceremony_v1(
    grant_canonical_bytes: &[u8],
    deriver_a_signing_key_id: String,
    deriver_b_signing_key_id: String,
) -> RouterAbProtocolResult<TenantRootCreationCeremonyDrawV1> {
    Ok(TenantRootCreationCeremonyDrawV1 {
        session_id: TenantRootCeremonySessionIdV1::from_bytes(derive_ceremony_bytes_v1::<16>(
            TENANT_ROOT_CEREMONY_SESSION_DOMAIN_V1,
            grant_canonical_bytes,
        ))
        .map_err(derivation)?,
        ceremony_nonce: TenantRootCeremonyNonceV1::from_bytes(derive_ceremony_bytes_v1::<32>(
            TENANT_ROOT_CEREMONY_NONCE_DOMAIN_V1,
            grant_canonical_bytes,
        ))
        .map_err(derivation)?,
        capability_nonce: TenantRootCreationCapabilityNonceV1::from_bytes(
            derive_ceremony_bytes_v1::<32>(
                TENANT_ROOT_CAPABILITY_NONCE_DOMAIN_V1,
                grant_canonical_bytes,
            ),
        )
        .map_err(derivation)?,
        deriver_a_signing_key_id,
        deriver_b_signing_key_id,
    })
}

/// The Started journal and its issuer capability, ready to persist.
#[derive(Debug)]
pub(crate) struct AuthorizedTenantRootCreationV1 {
    pub(crate) journal: TenantRootCreationJournalV1,
    pub(crate) capability: TenantRootCreationCapabilityV1,
}

/// Opens one tenant-root creation from a verified grant.
///
/// The grant authorizes a tenant and a custody lineage and nothing else; the
/// journal, ceremony context, window, and capability are constructed here from
/// that authorization plus locally drawn material. The capability is signed over
/// the journal the issuer just built, so it cannot attest a journal the issuer
/// did not construct.
pub(crate) fn authorize_tenant_root_creation_v1(
    grant: &VerifiedTenantRootCreationGrantV1,
    draw: &TenantRootCreationCeremonyDrawV1,
    now_ms: u64,
    authority_id: TenantRootControlPlaneAuthorityIdV1,
    active_issuer_key_id: &str,
    issuer_seed: &Zeroizing<[u8; 32]>,
) -> RouterAbProtocolResult<AuthorizedTenantRootCreationV1> {
    // The grant's own window gates the operation: an expired authorization
    // cannot open a ceremony, however fresh the issuer's clock is. `now_ms` is
    // the only non-derived input, and it gates admission without entering the
    // constructed bytes, so a retry inside the window is byte-identical.
    grant.require_fresh(now_ms).map_err(|_| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ExpiredLocalRequest,
            "tenant-root creation grant is outside its authorized window",
        )
    })?;
    if draw.deriver_a_signing_key_id == draw.deriver_b_signing_key_id {
        return Err(refused(
            "tenant-root creation ceremony must name distinct role signers",
        ));
    }
    // The ceremony window IS the authorization's window, so it is reproducible
    // and can never outlive the grant that opened it.
    let issued_at_ms = grant.issued_at_ms();
    let expires_at_ms = issued_at_ms
        .saturating_add(TENANT_ROOT_MAX_LIFETIME_MS_V1)
        .min(grant.expires_at_ms());
    if expires_at_ms <= issued_at_ms {
        return Err(refused(
            "tenant-root creation grant leaves no room for a ceremony window",
        ));
    }
    let context = TenantRootCeremonyContextV1::new(
        grant.identity_digest(),
        grant.custody_lineage(),
        TenantRootCeremonyEpochsV1::create(),
        draw.session_id,
        draw.ceremony_nonce,
        issued_at_ms,
        expires_at_ms,
        draw.deriver_a_signing_key_id.as_str(),
        draw.deriver_b_signing_key_id.as_str(),
    )
    .map_err(derivation)?;
    let journal = TenantRootCreationJournalV1::started(
        grant.identity().clone(),
        grant.custody_lineage(),
        context,
    )
    .map_err(derivation)?;
    let capability = TenantRootCreationCapabilityV1::sign(
        journal.identity_digest(),
        journal.custody_lineage(),
        journal.digest().map_err(derivation)?,
        authority_id,
        draw.capability_nonce,
        issued_at_ms,
        expires_at_ms,
        active_issuer_key_id,
        issuer_seed,
    )
    .map_err(derivation)?;
    Ok(AuthorizedTenantRootCreationV1 {
        journal,
        capability,
    })
}

#[cfg(feature = "workers-rs")]
pub use live::{
    handle_cloudflare_tenant_root_control_plane_cleanup_command_v1,
    handle_cloudflare_tenant_root_control_plane_create_tenant_root_v1,
    handle_cloudflare_tenant_root_control_plane_refresh_commands_v1,
    handle_cloudflare_tenant_root_control_plane_role_creation_command_v1,
};

#[cfg(feature = "workers-rs")]
#[allow(unused_imports)]
pub(crate) use live::{
    execute_cloudflare_tenant_root_control_plane_initial_activation_service_call_v1,
    handle_cloudflare_tenant_root_control_plane_initial_activation_v1,
    handle_cloudflare_tenant_root_control_plane_refresh_activation_v1,
};

#[cfg(feature = "workers-rs")]
mod live {
    use super::*;
    use crate::durable_object::tenant_root_creation::{
        decode_canonical_base64url, derive_tenant_root_creation_authority_object_v1,
        execute_cloudflare_router_tenant_root_creation_active_state_with_revision_read_call_v1,
        execute_cloudflare_router_tenant_root_creation_journal_call_v1, validate_creation_record,
        CloudflareTenantRootCreationJournalOutcomeV1,
        CloudflareTenantRootCreationJournalReadRequestV1,
        CloudflareTenantRootCreationJournalRecordV1,
        CLOUDFLARE_TENANT_ROOT_CREATION_JOURNAL_READ_PATH,
    };
    use crate::env::decode_cloudflare_tenant_root_control_plane_issuer_signing_secret_v1;
    use crate::{encode_base64url_bytes_v1, CloudflareTenantRootControlPlaneRuntimeV1};
    use router_ab_core::{
        TenantRootCreationGrantV1, TenantRootCustodyLineageId, TenantRootIdentityDigestV1,
        TENANT_ROOT_CREATION_GRANT_MAX_BYTES_V1,
    };
    use zeroize::Zeroize;

    const ROUTER_TENANT_ROOT_CREATION_DO_BINDING_V1: &str = "ROUTER_TENANT_ROOT_CREATION_DO";

    fn local(message: String) -> RouterAbProtocolError {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            message,
        )
    }

    /// Reads authoritative creation state from the Router-owned Durable Object
    /// through this Worker's own external binding.
    /// Derives the creation object's name and its authority id from a tenant.
    ///
    /// The authority id IS the Durable Object id: derived here from the identity
    /// and lineage, never read from a request.
    pub(crate) fn read_creation_object_binding(
        env: &worker::Env,
        identity_digest: TenantRootIdentityDigestV1,
        custody_lineage: TenantRootCustodyLineageId,
    ) -> RouterAbProtocolResult<(TenantRootControlPlaneAuthorityIdV1, String)> {
        derive_tenant_root_creation_authority_object_v1(env, identity_digest, custody_lineage)
    }

    async fn read_creation_state(
        env: &worker::Env,
        identity_digest: TenantRootIdentityDigestV1,
        custody_lineage: TenantRootCustodyLineageId,
    ) -> RouterAbProtocolResult<(
        TenantRootControlPlaneAuthorityIdV1,
        CloudflareTenantRootCreationJournalReadResponseV1,
    )> {
        let namespace = env
            .durable_object(ROUTER_TENANT_ROOT_CREATION_DO_BINDING_V1)
            .map_err(|error| {
                RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::MissingLocalBinding,
                    format!("tenant-root creation Durable Object binding is unavailable: {error}"),
                )
            })?;
        let (authority_id, object_name) =
            read_creation_object_binding(env, identity_digest, custody_lineage)?;
        let stub = namespace.get_by_name(&object_name).map_err(|error| {
            local(format!(
                "tenant-root creation Durable Object stub lookup failed: {error}"
            ))
        })?;
        let body = serde_json::to_string(&CloudflareTenantRootCreationJournalReadRequestV1 {
            identity_digest_b64u: encode_base64url_bytes_v1(identity_digest.as_bytes()),
            custody_lineage_b64u: encode_base64url_bytes_v1(custody_lineage.as_bytes()),
        })
        .map_err(|error| {
            local(format!(
                "tenant-root creation read request encoding failed: {error}"
            ))
        })?;
        let headers = worker::Headers::new();
        headers
            .set("content-type", "application/json")
            .map_err(|error| local(format!("tenant-root creation read headers failed: {error}")))?;
        crate::set_cloudflare_internal_service_auth_header_v1(
            env,
            &headers,
            "tenant-root creation read",
        )?;
        let mut init = worker::RequestInit::new();
        init.with_method(worker::Method::Post)
            .with_headers(headers)
            .with_body(Some(worker::wasm_bindgen::JsValue::from_str(&body)));
        let request = worker::Request::new_with_init(
            &format!(
                "https://router-ab-do.internal{CLOUDFLARE_TENANT_ROOT_CREATION_JOURNAL_READ_PATH}"
            ),
            &init,
        )
        .map_err(|error| {
            local(format!(
                "tenant-root creation read request construction failed: {error}"
            ))
        })?;
        let mut response = stub
            .fetch_with_request(request)
            .await
            .map_err(|error| local(format!("tenant-root creation read request failed: {error}")))?;
        if response.status_code() != 200 {
            return Err(refused(
                "tenant-root creation Durable Object refused the read",
            ));
        }
        let parsed: CloudflareTenantRootCreationJournalReadResponseV1 =
            response.json().await.map_err(|error| {
                local(format!(
                    "tenant-root creation read response decoding failed: {error}"
                ))
            })?;
        Ok((authority_id, parsed))
    }

    fn creation_status(
        state: &CloudflareTenantRootCreationJournalReadResponseV1,
    ) -> RouterAbProtocolResult<CloudflareTenantRootCreationStatusV1> {
        match (&state.installation_checkpoint, state.cleanup_checkpointed) {
            (CloudflareTenantRootCreationInstallationCheckpointReadStateV1::None, false) => {
                Ok(CloudflareTenantRootCreationStatusV1::Pending)
            }
            (
                CloudflareTenantRootCreationInstallationCheckpointReadStateV1::OneRoleReady {
                    role,
                    ..
                },
                false,
            ) => Ok(CloudflareTenantRootCreationStatusV1::OneRoleInstalled {
                role: CloudflareTenantRootControlPlaneRoleV1::from_protocol(role.to_protocol()),
            }),
            (
                CloudflareTenantRootCreationInstallationCheckpointReadStateV1::BothRolesReady {
                    root_commitment_b64u,
                },
                false,
            ) => Ok(CloudflareTenantRootCreationStatusV1::Ready {
                root_commitment_b64u: root_commitment_b64u.clone(),
            }),
            (
                CloudflareTenantRootCreationInstallationCheckpointReadStateV1::OneRoleReady {
                    role,
                    ..
                },
                true,
            ) => Ok(CloudflareTenantRootCreationStatusV1::Abandoned {
                role: CloudflareTenantRootControlPlaneRoleV1::from_protocol(role.to_protocol()),
            }),
            _ => Err(refused(
                "tenant-root creation Durable Object returned an invalid cleanup state",
            )),
        }
    }

    /// The typed issuer operation: mint one role creation command.
    pub async fn handle_cloudflare_tenant_root_control_plane_role_creation_command_v1(
        request: CloudflareTenantRootControlPlaneRoleCreationCommandRequestV1,
        env: &worker::Env,
        runtime: &CloudflareTenantRootControlPlaneRuntimeV1,
    ) -> RouterAbProtocolResult<CloudflareTenantRootControlPlaneRoleCreationCommandResponseV1> {
        let identity_digest = TenantRootIdentityDigestV1::from_bytes(
            decode_canonical_base64url(
                "tenant-root control-plane identity digest",
                &request.identity_digest_b64u,
                32,
                48,
            )?
            .as_slice()
            .try_into()
            .map_err(|_| refused("tenant-root control-plane identity digest length is invalid"))?,
        );
        let custody_lineage = TenantRootCustodyLineageId::from_bytes(
            decode_canonical_base64url(
                "tenant-root control-plane custody lineage",
                &request.custody_lineage_b64u,
                16,
                24,
            )?
            .as_slice()
            .try_into()
            .map_err(|_| refused("tenant-root control-plane custody lineage length is invalid"))?,
        )
        .map_err(|error| {
            refused_owned(format!(
                "tenant-root control-plane custody lineage is invalid: {error}"
            ))
        })?;

        let (authority_id, read) =
            read_creation_state(env, identity_digest, custody_lineage).await?;
        // Re-validate the returned bytes against OUR published keys and OUR derived
        // authority id: the object is authoritative, but the issuer trusts nothing
        // it did not verify itself.
        let record = CloudflareTenantRootCreationJournalRecordV1 {
            journal_b64u: read.journal_b64u.clone(),
            creation_capability_b64u: read.creation_capability_b64u.clone(),
        };
        let journal = validate_creation_record(
            record,
            authority_id,
            runtime.bindings().issuer_verifying_keys.keys(),
        )?;
        if journal.identity_digest != identity_digest || journal.custody_lineage != custody_lineage
        {
            return Err(refused(
                "tenant-root creation state does not name the requested identity and lineage",
            ));
        }
        let progress = TenantRootCreationProgressV1::from_read_response(&read);
        let now_ms = crate::cloudflare_now_unix_ms_v1()?;

        let binding = &runtime.bindings().issuer_signing_key;
        let secret = env.secret(binding.binding_name()).map_err(|error| {
            crate::worker_binding_error(
                crate::worker_binding_error_code(&error, binding.binding_name()),
                binding.binding_name(),
                "secret",
                error,
            )
        })?;
        let mut secret_value = secret.to_string();
        let seed =
            decode_cloudflare_tenant_root_control_plane_issuer_signing_secret_v1(&secret_value);
        secret_value.zeroize();
        let seed = seed?;

        let issued = issue_tenant_root_role_creation_command_v1(
            TenantRootRoleCreationCommandIssuanceV1 {
                journal: &journal,
                progress: &progress,
                role: request.role.to_protocol(),
                authority_id,
                now_ms,
            },
            binding.signing_key_id(),
            &seed,
        )?;
        Ok(
            CloudflareTenantRootControlPlaneRoleCreationCommandResponseV1 {
                role: request.role,
                issuer_key_id: binding.signing_key_id().to_owned(),
                role_creation_command_b64u: encode_base64url_bytes_v1(
                    &issued.command.canonical_bytes().map_err(derivation)?,
                ),
                role_creation_command_package_b64u: encode_base64url_bytes_v1(
                    &issued.package.canonical_bytes().map_err(derivation)?,
                ),
            },
        )
    }

    /// Mints one fresh A/B refresh command pair from authoritative active state.
    pub async fn handle_cloudflare_tenant_root_control_plane_refresh_commands_v1(
        request: CloudflareTenantRootControlPlaneRefreshCommandsRequestV1,
        env: &worker::Env,
        runtime: &CloudflareTenantRootControlPlaneRuntimeV1,
    ) -> RouterAbProtocolResult<CloudflareTenantRootControlPlaneRefreshCommandsResponseV1> {
        let identity_digest = TenantRootIdentityDigestV1::from_bytes(
            decode_canonical_base64url(
                "tenant-root refresh identity digest",
                &request.identity_digest_b64u,
                32,
                48,
            )?
            .as_slice()
            .try_into()
            .map_err(|_| refused("tenant-root refresh identity digest length is invalid"))?,
        );
        let custody_lineage = TenantRootCustodyLineageId::from_bytes(
            decode_canonical_base64url(
                "tenant-root refresh custody lineage",
                &request.custody_lineage_b64u,
                16,
                24,
            )?
            .as_slice()
            .try_into()
            .map_err(|_| refused("tenant-root refresh custody lineage length is invalid"))?,
        )
        .map_err(derivation)?;
        let active =
            execute_cloudflare_router_tenant_root_creation_active_state_with_revision_read_call_v1(
                env,
                identity_digest,
                custody_lineage,
            )
            .await?;
        let authority_id = active.activation_receipt.binding().authority_id();
        let active_pair = TenantRootActiveRootPairV1::from_verified_activation_receipt(
            &active.activation_receipt,
        )
        .map_err(derivation)?;
        let session_bytes: [u8; 16] = crate::cloudflare_random_bytes_v1(16)?
            .try_into()
            .map_err(|_| refused("tenant-root refresh session generation failed"))?;
        let nonce_bytes: [u8; 32] = crate::cloudflare_random_bytes_v1(32)?
            .try_into()
            .map_err(|_| refused("tenant-root refresh nonce generation failed"))?;
        let now_ms = crate::cloudflare_now_unix_ms_v1()?;
        let expires_at_ms = now_ms.saturating_add(TENANT_ROOT_MAX_LIFETIME_MS_V1);
        let bindings = runtime.bindings();
        let refresh_context = TenantRootCeremonyContextV1::new(
            identity_digest,
            custody_lineage,
            TenantRootCeremonyEpochsV1::refresh(
                active_pair.epoch(),
                active_pair.epoch().next().map_err(derivation)?,
            )
            .map_err(derivation)?,
            TenantRootCeremonySessionIdV1::from_bytes(session_bytes).map_err(derivation)?,
            TenantRootCeremonyNonceV1::from_bytes(nonce_bytes).map_err(derivation)?,
            now_ms,
            expires_at_ms,
            bindings.deriver_a_signing_key_id.clone(),
            bindings.deriver_b_signing_key_id.clone(),
        )
        .map_err(derivation)?;
        let issuer_seed = load_issuer_seed(env, runtime)?;
        let issued = issue_tenant_root_role_refresh_commands_v1(
            TenantRootRoleRefreshCommandIssuanceV1 {
                active_pair: &active_pair,
                refresh_context: &refresh_context,
                expected_control_plane_revision: active.lifecycle_revision,
                authority_id,
                now_ms,
            },
            bindings.issuer_signing_key.signing_key_id(),
            &issuer_seed,
        )?;
        Ok(CloudflareTenantRootControlPlaneRefreshCommandsResponseV1 {
            refresh_context_b64u: encode_base64url_bytes_v1(
                &refresh_context.canonical_bytes().map_err(derivation)?,
            ),
            deriver_a_refresh_command_b64u: encode_base64url_bytes_v1(
                &issued.deriver_a.canonical_bytes().map_err(derivation)?,
            ),
            deriver_b_refresh_command_b64u: encode_base64url_bytes_v1(
                &issued.deriver_b.canonical_bytes().map_err(derivation)?,
            ),
            issuer_key_id: bindings.issuer_signing_key.signing_key_id().to_owned(),
        })
    }

    /// Issues cleanup for the exact sole role installation recorded by the DO.
    pub async fn handle_cloudflare_tenant_root_control_plane_cleanup_command_v1(
        request: CloudflareTenantRootControlPlaneCleanupCommandRequestV1,
        env: &worker::Env,
        runtime: &CloudflareTenantRootControlPlaneRuntimeV1,
    ) -> RouterAbProtocolResult<CloudflareTenantRootControlPlaneCleanupCommandResponseV1> {
        let identity_digest = TenantRootIdentityDigestV1::from_bytes(
            decode_canonical_base64url(
                "tenant-root cleanup identity digest",
                &request.identity_digest_b64u,
                32,
                48,
            )?
            .as_slice()
            .try_into()
            .map_err(|_| refused("tenant-root cleanup identity digest length is invalid"))?,
        );
        let custody_lineage = TenantRootCustodyLineageId::from_bytes(
            decode_canonical_base64url(
                "tenant-root cleanup custody lineage",
                &request.custody_lineage_b64u,
                16,
                24,
            )?
            .as_slice()
            .try_into()
            .map_err(|_| refused("tenant-root cleanup custody lineage length is invalid"))?,
        )
        .map_err(derivation)?;
        let (authority_id, read) =
            read_creation_state(env, identity_digest, custody_lineage).await?;
        if read.cleanup_checkpointed {
            return Err(refused(
                "tenant-root creation is already abandoned and cleaned",
            ));
        }
        let record = CloudflareTenantRootCreationJournalRecordV1 {
            journal_b64u: read.journal_b64u.clone(),
            creation_capability_b64u: read.creation_capability_b64u.clone(),
        };
        let journal = validate_creation_record(
            record,
            authority_id,
            runtime.bindings().issuer_verifying_keys.keys(),
        )?;
        if journal.identity_digest != identity_digest || journal.custody_lineage != custody_lineage
        {
            return Err(refused(
                "tenant-root cleanup state does not name the requested identity and lineage",
            ));
        }
        let CloudflareTenantRootCreationInstallationCheckpointReadStateV1::OneRoleReady {
            role,
            signed_evidence_b64u,
        } = read.installation_checkpoint
        else {
            return Err(refused(
                "tenant-root cleanup requires exactly one installed role",
            ));
        };
        let role = role.to_protocol();
        let evidence_bytes = decode_canonical_base64url(
            "tenant-root cleanup installation evidence",
            &signed_evidence_b64u,
            router_ab_core::TENANT_ROOT_SIGNED_SHARE_INSTALLATION_EVIDENCE_MAX_BYTES_V1,
            router_ab_core::TENANT_ROOT_SIGNED_SHARE_INSTALLATION_EVIDENCE_MAX_BYTES_V1 * 2,
        )?;
        let (expected_key_id, verifying_key) = match role {
            TwoPartyDeriverRole::DeriverA => (
                runtime.bindings().deriver_a_signing_key_id.as_str(),
                &runtime.bindings().deriver_a_verifying_key,
            ),
            TwoPartyDeriverRole::DeriverB => (
                runtime.bindings().deriver_b_signing_key_id.as_str(),
                &runtime.bindings().deriver_b_verifying_key,
            ),
        };
        if journal.ceremony_context.signing_key_id(role) != expected_key_id {
            return Err(refused(
                "tenant-root cleanup evidence names a retired role signing key",
            ));
        }
        let evidence =
            TenantRootSignedShareInstallationEvidenceV1::decode_and_verify_canonical_bytes(
                &evidence_bytes,
                verifying_key,
            )
            .map_err(derivation)?;
        if evidence.evidence().transcript().context() != &journal.ceremony_context
            || evidence.evidence().transcript().role() != role
        {
            return Err(refused(
                "tenant-root cleanup evidence belongs to a different ceremony or role",
            ));
        }
        let installation_evidence_digest =
            TenantRootProtocolDigestV1::from_bytes(Sha256::digest(&evidence_bytes).into())
                .map_err(derivation)?;
        let target = TenantRootRoleCleanupTargetV1::Pending {
            identity_digest,
            custody_lineage,
            role,
            epoch: TenantRootShareEpoch::INITIAL,
            expected_row_revision: 1,
            session_id: journal.ceremony_context.session_id(),
            ceremony_nonce: journal.ceremony_context.nonce(),
            installation_evidence_digest,
        };
        let mut nonce_hasher = Sha256::new();
        nonce_hasher.update(b"seams/tenant-root/creation-cleanup-nonce/v1");
        nonce_hasher.update(journal.journal_digest.as_bytes());
        nonce_hasher.update(installation_evidence_digest.as_bytes());
        let cleanup_nonce = TenantRootCeremonyNonceV1::from_bytes(nonce_hasher.finalize().into())
            .map_err(derivation)?;
        let seed = load_issuer_seed(env, runtime)?;
        let command = TenantRootRoleCleanupCommandV1::sign(
            &target,
            authority_id,
            cleanup_nonce,
            journal.ceremony_context.issued_at_ms(),
            journal.ceremony_context.expires_at_ms(),
            runtime.bindings().issuer_signing_key.signing_key_id(),
            &seed,
        )
        .map_err(derivation)?;
        Ok(CloudflareTenantRootControlPlaneCleanupCommandResponseV1 {
            role: CloudflareTenantRootControlPlaneRoleV1::from_protocol(role),
            cleanup_command_b64u: encode_base64url_bytes_v1(
                &command.canonical_bytes().map_err(derivation)?,
            ),
        })
    }

    fn refused_owned(message: String) -> RouterAbProtocolError {
        RouterAbProtocolError::new(RouterAbProtocolErrorCode::ForbiddenLocalBinding, message)
    }

    /// Loads the issuer signing seed for one operation.
    fn load_issuer_seed(
        env: &worker::Env,
        runtime: &CloudflareTenantRootControlPlaneRuntimeV1,
    ) -> RouterAbProtocolResult<Zeroizing<[u8; 32]>> {
        let binding = &runtime.bindings().issuer_signing_key;
        let secret = env.secret(binding.binding_name()).map_err(|error| {
            crate::worker_binding_error(
                crate::worker_binding_error_code(&error, binding.binding_name()),
                binding.binding_name(),
                "secret",
                error,
            )
        })?;
        let mut secret_value = secret.to_string();
        let seed =
            decode_cloudflare_tenant_root_control_plane_issuer_signing_secret_v1(&secret_value);
        secret_value.zeroize();
        seed
    }

    const TENANT_ROOT_SIGNED_MANAGED_BACKUP_MAX_BYTES_V1: usize = 72 * 1024;

    fn decode_verified_installation_evidence_v1(
        field: &'static str,
        encoded: &str,
        expected_role: TwoPartyDeriverRole,
        expected_signing_key_id: &str,
        verifying_key: &[u8; 32],
    ) -> RouterAbProtocolResult<
        router_ab_core::VerifiedTenantRootSignedShareInstallationEvidenceWireV1,
    > {
        let bytes = decode_canonical_base64url(
            field,
            encoded,
            router_ab_core::TENANT_ROOT_SIGNED_SHARE_INSTALLATION_EVIDENCE_MAX_BYTES_V1,
            router_ab_core::TENANT_ROOT_SIGNED_SHARE_INSTALLATION_EVIDENCE_MAX_BYTES_V1 * 2,
        )?;
        let signed = TenantRootSignedShareInstallationEvidenceV1::decode_canonical_bytes(&bytes)
            .map_err(derivation)?;
        if signed.role() != expected_role || signed.signing_key_id() != expected_signing_key_id {
            return Err(refused(
                "tenant-root installation evidence names the wrong role signing key",
            ));
        }
        TenantRootSignedShareInstallationEvidenceV1::decode_and_verify_canonical_bytes(
            &bytes,
            verifying_key,
        )
        .map_err(derivation)
    }

    fn decode_verified_managed_backup_v1(
        field: &'static str,
        encoded: &str,
        expected_role: TenantRootManagedRestoreRoleV1,
        expected_signing_key_id: &str,
        verifying_key: &[u8; 32],
    ) -> RouterAbProtocolResult<router_ab_core::VerifiedTenantRootManagedBackupV1> {
        let bytes = decode_canonical_base64url(
            field,
            encoded,
            TENANT_ROOT_SIGNED_MANAGED_BACKUP_MAX_BYTES_V1,
            TENANT_ROOT_SIGNED_MANAGED_BACKUP_MAX_BYTES_V1 * 2,
        )?;
        let signed =
            TenantRootSignedManagedBackupV1::decode_canonical_bytes(&bytes).map_err(derivation)?;
        if signed.binding().role() != expected_role
            || signed.binding().role_signing_key_id() != expected_signing_key_id
        {
            return Err(refused(
                "tenant-root managed backup names the wrong role signing key",
            ));
        }
        signed
            .verify(signed.binding(), verifying_key)
            .map_err(derivation)
    }

    fn decode_verified_provider_canary_v1(
        field: &'static str,
        encoded: &str,
        expected_family: TenantRootCanaryCurveFamilyV1,
        expected_signing_key_id: &str,
        verifying_key: &[u8; 32],
    ) -> RouterAbProtocolResult<router_ab_core::VerifiedTenantRootProviderCanaryReceiptV1> {
        let bytes = decode_canonical_base64url(
            field,
            encoded,
            TENANT_ROOT_PROVIDER_CANARY_RECEIPT_MAX_BYTES_V1,
            TENANT_ROOT_PROVIDER_CANARY_RECEIPT_MAX_BYTES_V1 * 2,
        )?;
        let signed = TenantRootSignedProviderCanaryReceiptV1::decode_canonical_bytes(&bytes)
            .map_err(derivation)?;
        if signed.curve_family() != expected_family
            || signed.signing_key_id() != expected_signing_key_id
        {
            return Err(refused(
                "tenant-root provider canary names the wrong role signing key",
            ));
        }
        signed
            .verify(signed.binding(), verifying_key)
            .map_err(derivation)
    }

    pub(super) fn require_persisted_initial_activation_state_v1(
        read: &CloudflareTenantRootCreationJournalReadResponseV1,
        bundle: &VerifiedTenantRootInitialCreationActivationEvidenceBundleV1,
    ) -> RouterAbProtocolResult<()> {
        if read.cleanup_checkpointed {
            return Err(refused(
                "tenant-root initial activation cannot issue after creation cleanup",
            ));
        }
        if read.committed_roles.len() != 2
            || !read
                .committed_roles
                .contains(&CloudflareTenantRootCreationInstallationRoleV1::DeriverA)
            || !read
                .committed_roles
                .contains(&CloudflareTenantRootCreationInstallationRoleV1::DeriverB)
        {
            return Err(refused(
                "tenant-root initial activation requires both persisted role commitments",
            ));
        }
        let CloudflareTenantRootCreationInstallationCheckpointReadStateV1::BothRolesReady {
            root_commitment_b64u,
        } = &read.installation_checkpoint
        else {
            return Err(refused(
                "tenant-root initial activation requires both persisted role installations",
            ));
        };
        let root_commitment = decode_canonical_base64url(
            "tenant-root persisted installation root commitment",
            root_commitment_b64u,
            32,
            48,
        )?;
        if root_commitment.as_slice() != bundle.root_commitment() {
            return Err(refused(
                "tenant-root persisted installation root does not match the activation evidence",
            ));
        }
        Ok(())
    }

    /// Verifies the six public activation artifacts and issues the exact receipt.
    pub(crate) async fn handle_cloudflare_tenant_root_control_plane_initial_activation_v1(
        request: CloudflareTenantRootControlPlaneInitialActivationRequestV1,
        env: &worker::Env,
        runtime: &CloudflareTenantRootControlPlaneRuntimeV1,
    ) -> RouterAbProtocolResult<CloudflareTenantRootControlPlaneInitialActivationReceiptResponseV1>
    {
        let bindings = runtime.bindings();
        let deriver_a_installation = decode_verified_installation_evidence_v1(
            "tenant-root Deriver A installation evidence",
            &request.deriver_a_signed_installation_evidence_b64u,
            TwoPartyDeriverRole::DeriverA,
            &bindings.deriver_a_signing_key_id,
            &bindings.deriver_a_verifying_key,
        )?;
        let deriver_b_installation = decode_verified_installation_evidence_v1(
            "tenant-root Deriver B installation evidence",
            &request.deriver_b_signed_installation_evidence_b64u,
            TwoPartyDeriverRole::DeriverB,
            &bindings.deriver_b_signing_key_id,
            &bindings.deriver_b_verifying_key,
        )?;
        let deriver_a_backup = decode_verified_managed_backup_v1(
            "tenant-root Deriver A managed backup",
            &request.deriver_a_signed_managed_backup_b64u,
            TenantRootManagedRestoreRoleV1::DeriverA,
            &bindings.deriver_a_signing_key_id,
            &bindings.deriver_a_verifying_key,
        )?;
        let deriver_b_backup = decode_verified_managed_backup_v1(
            "tenant-root Deriver B managed backup",
            &request.deriver_b_signed_managed_backup_b64u,
            TenantRootManagedRestoreRoleV1::DeriverB,
            &bindings.deriver_b_signing_key_id,
            &bindings.deriver_b_verifying_key,
        )?;
        let ecdsa_canary = decode_verified_provider_canary_v1(
            "tenant-root ECDSA provider canary",
            &request.ecdsa_provider_canary_receipt_b64u,
            TenantRootCanaryCurveFamilyV1::Ecdsa,
            &bindings.deriver_a_signing_key_id,
            &bindings.deriver_a_verifying_key,
        )?;
        let ed25519_canary = decode_verified_provider_canary_v1(
            "tenant-root Ed25519 provider canary",
            &request.ed25519_provider_canary_receipt_b64u,
            TenantRootCanaryCurveFamilyV1::Ed25519,
            &bindings.deriver_b_signing_key_id,
            &bindings.deriver_b_verifying_key,
        )?;
        let bundle = VerifiedTenantRootInitialCreationActivationEvidenceBundleV1::from_verified_managed_backups(
            deriver_a_installation,
            deriver_b_installation,
            deriver_a_backup,
            deriver_b_backup,
            ecdsa_canary,
            ed25519_canary,
            2,
            3,
        )
        .map_err(derivation)?;
        let activated_at_ms = crate::cloudflare_now_unix_ms_v1()?;
        let (authority_id, read) =
            read_creation_state(env, bundle.identity_digest(), bundle.custody_lineage()).await?;
        let record = CloudflareTenantRootCreationJournalRecordV1 {
            journal_b64u: read.journal_b64u.clone(),
            creation_capability_b64u: read.creation_capability_b64u.clone(),
        };
        let journal = validate_creation_record(
            record,
            authority_id,
            runtime.bindings().issuer_verifying_keys.keys(),
        )?;
        if journal.identity_digest != bundle.identity_digest()
            || journal.custody_lineage != bundle.custody_lineage()
            || journal.ceremony_context.digest().map_err(derivation)? != bundle.context_digest()
        {
            return Err(refused(
                "tenant-root persisted creation state does not match the activation evidence",
            ));
        }
        require_persisted_initial_activation_state_v1(&read, &bundle)?;
        let issuer_binding = &bindings.issuer_signing_key;
        let issuer_seed = load_issuer_seed(env, runtime)?;
        let receipt = super::issue_tenant_root_initial_activation_receipt_v1(
            &bundle,
            activated_at_ms,
            authority_id,
            issuer_binding.signing_key_id(),
            &issuer_seed,
        )?;
        super::initial_activation_receipt_response_v1(receipt)
    }

    /// Verifies the six public refresh artifacts against the active state and
    /// issues the exact refresh-swap receipt.
    pub(crate) async fn handle_cloudflare_tenant_root_control_plane_refresh_activation_v1(
        request: CloudflareTenantRootControlPlaneRefreshActivationRequestV1,
        env: &worker::Env,
        runtime: &CloudflareTenantRootControlPlaneRuntimeV1,
    ) -> RouterAbProtocolResult<CloudflareTenantRootControlPlaneRefreshActivationReceiptResponseV1>
    {
        let bindings = runtime.bindings();
        let deriver_a_installation = decode_verified_installation_evidence_v1(
            "tenant-root Deriver A refresh installation evidence",
            &request.deriver_a_signed_installation_evidence_b64u,
            TwoPartyDeriverRole::DeriverA,
            &bindings.deriver_a_signing_key_id,
            &bindings.deriver_a_verifying_key,
        )?;
        let deriver_b_installation = decode_verified_installation_evidence_v1(
            "tenant-root Deriver B refresh installation evidence",
            &request.deriver_b_signed_installation_evidence_b64u,
            TwoPartyDeriverRole::DeriverB,
            &bindings.deriver_b_signing_key_id,
            &bindings.deriver_b_verifying_key,
        )?;
        let deriver_a_backup = decode_verified_managed_backup_v1(
            "tenant-root Deriver A refresh managed backup",
            &request.deriver_a_signed_managed_backup_b64u,
            TenantRootManagedRestoreRoleV1::DeriverA,
            &bindings.deriver_a_signing_key_id,
            &bindings.deriver_a_verifying_key,
        )?;
        let deriver_b_backup = decode_verified_managed_backup_v1(
            "tenant-root Deriver B refresh managed backup",
            &request.deriver_b_signed_managed_backup_b64u,
            TenantRootManagedRestoreRoleV1::DeriverB,
            &bindings.deriver_b_signing_key_id,
            &bindings.deriver_b_verifying_key,
        )?;
        let ecdsa_canary = decode_verified_provider_canary_v1(
            "tenant-root ECDSA refresh provider canary",
            &request.ecdsa_provider_canary_receipt_b64u,
            TenantRootCanaryCurveFamilyV1::Ecdsa,
            &bindings.deriver_a_signing_key_id,
            &bindings.deriver_a_verifying_key,
        )?;
        let ed25519_canary = decode_verified_provider_canary_v1(
            "tenant-root Ed25519 refresh provider canary",
            &request.ed25519_provider_canary_receipt_b64u,
            TenantRootCanaryCurveFamilyV1::Ed25519,
            &bindings.deriver_b_signing_key_id,
            &bindings.deriver_b_verifying_key,
        )?;

        let context = deriver_a_installation.evidence().transcript().context();
        let identity_digest = context.identity_digest();
        let custody_lineage = context.custody_lineage();
        let active =
            execute_cloudflare_router_tenant_root_creation_active_state_with_revision_read_call_v1(
                env,
                identity_digest,
                custody_lineage,
            )
            .await?;
        let authority_id = active.activation_receipt.binding().authority_id();
        let active_pair = TenantRootActiveRootPairV1::from_verified_activation_receipt(
            &active.activation_receipt,
        )
        .map_err(derivation)?;
        if active_pair.identity_digest() != identity_digest
            || active_pair.custody_lineage() != custody_lineage
        {
            return Err(refused(
                "tenant-root active state does not match refresh installation evidence",
            ));
        }
        let TenantRootCeremonyEpochsV1::Refresh { current, .. } = context.epochs() else {
            return Err(refused(
                "tenant-root refresh activation requires refresh ceremony epochs",
            ));
        };
        if current != active_pair.epoch() {
            return Err(refused(
                "tenant-root refresh activation current epoch does not match active state",
            ));
        }
        let expected_control_plane_revision = active.lifecycle_revision;
        let result_control_plane_revision = expected_control_plane_revision
            .checked_add(1)
            .ok_or_else(|| refused("tenant-root refresh activation revision cannot advance"))?;
        let bundle =
            VerifiedTenantRootRefreshSwapActivationEvidenceBundleV1::from_verified_managed_backups(
                active_pair.commitments(),
                deriver_a_installation,
                deriver_b_installation,
                deriver_a_backup,
                deriver_b_backup,
                ecdsa_canary,
                ed25519_canary,
                expected_control_plane_revision,
                result_control_plane_revision,
            )
            .map_err(derivation)?;
        let activated_at_ms = crate::cloudflare_now_unix_ms_v1()?;
        let issuer_binding = &bindings.issuer_signing_key;
        let issuer_seed = load_issuer_seed(env, runtime)?;
        let receipt = super::issue_tenant_root_refresh_activation_receipt_v1(
            &bundle,
            activated_at_ms,
            authority_id,
            issuer_binding.signing_key_id(),
            &issuer_seed,
        )?;
        super::refresh_activation_receipt_response_v1(receipt)
    }

    async fn read_bounded_initial_activation_response_body_v1(
        response: &mut worker::Response,
        max_bytes: usize,
        label: &str,
    ) -> RouterAbProtocolResult<Vec<u8>> {
        use futures::StreamExt;

        if let Ok(mut stream) = response.stream() {
            let mut body = Vec::new();
            while let Some(chunk) = stream.next().await {
                let chunk = chunk.map_err(|error| {
                    RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::MalformedWirePayload,
                        format!("{label} response body read failed: {error}"),
                    )
                })?;
                let next_len = body.len().checked_add(chunk.len()).ok_or_else(|| {
                    RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::MalformedWirePayload,
                        format!("{label} response body length overflows"),
                    )
                })?;
                if next_len > max_bytes {
                    return Err(RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::MalformedWirePayload,
                        format!("{label} response exceeds its maximum size"),
                    ));
                }
                body.extend_from_slice(&chunk);
            }
            return Ok(body);
        }

        let body = response.bytes().await.map_err(|error| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                format!("{label} response body read failed: {error}"),
            )
        })?;
        if body.len() > max_bytes {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                format!("{label} response exceeds its maximum size"),
            ));
        }
        Ok(body)
    }

    /// Sends the typed activation request over the private control-plane binding.
    pub(crate) async fn execute_cloudflare_tenant_root_control_plane_initial_activation_service_call_v1(
        env: &worker::Env,
        request: &CloudflareTenantRootControlPlaneInitialActivationRequestV1,
    ) -> RouterAbProtocolResult<CloudflareTenantRootControlPlaneInitialActivationReceiptResponseV1>
    {
        let label = "tenant-root control-plane initial activation request";
        let request_body = crate::cloudflare_service_json_request_body_v1(label, request)?;
        if request_body.len() > TENANT_ROOT_CONTROL_PLANE_INITIAL_ACTIVATION_REQUEST_MAX_BYTES_V1 {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                format!("{label} exceeds its maximum size"),
            ));
        }
        let fetcher = env
            .service(crate::TENANT_ROOT_CONTROL_PLANE_SERVICE_BINDING_V1)
            .map_err(|error| {
                crate::worker_binding_error(
                    crate::worker_binding_error_code(
                        &error,
                        crate::TENANT_ROOT_CONTROL_PLANE_SERVICE_BINDING_V1,
                    ),
                    crate::TENANT_ROOT_CONTROL_PLANE_SERVICE_BINDING_V1,
                    "service",
                    error,
                )
            })?;
        let headers = worker::Headers::new();
        headers
            .set("content-type", "application/json")
            .map_err(|error| {
                RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                    format!("{label} request headers failed: {error}"),
                )
            })?;
        crate::set_cloudflare_internal_service_auth_header_v1(env, &headers, label)?;
        let mut init = worker::RequestInit::new();
        init.with_method(worker::Method::Post)
            .with_headers(headers)
            .with_body(Some(worker::wasm_bindgen::JsValue::from_str(&request_body)));
        let request_for_fetch = worker::Request::new_with_init(
            crate::cloudflare_tenant_root_control_plane_initial_activation_service_url(),
            &init,
        )
        .map_err(|error| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                format!("{label} request construction failed: {error}"),
            )
        })?;
        let mut response = fetcher
            .fetch_request(request_for_fetch)
            .await
            .map_err(|error| {
                RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                    format!("{label} request failed: {error}"),
                )
            })?;
        let status = response.status_code();
        let response_body = read_bounded_initial_activation_response_body_v1(
            &mut response,
            TENANT_ROOT_CONTROL_PLANE_INITIAL_ACTIVATION_RESPONSE_MAX_BYTES_V1,
            label,
        )
        .await?;
        if !(200..=299).contains(&status) {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                format!("{label} service returned HTTP status {status}"),
            ));
        }
        let parsed: CloudflareTenantRootControlPlaneInitialActivationReceiptResponseV1 =
            serde_json::from_slice(&response_body).map_err(|error| {
                RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::MalformedWirePayload,
                    format!("{label} response JSON parse failed: {error}"),
                )
            })?;
        let receipt_bytes = decode_canonical_base64url(
            "tenant-root initial activation receipt",
            &parsed.activation_receipt_b64u,
            TENANT_ROOT_ACTIVATION_RECEIPT_MAX_BYTES_V1,
            TENANT_ROOT_ACTIVATION_RECEIPT_MAX_BYTES_V1 * 2,
        )?;
        let receipt = TenantRootSignedActivationReceiptV1::decode_canonical_bytes(&receipt_bytes)
            .map_err(derivation)?;
        if receipt.transition() != TenantRootActivationReceiptTransitionV1::InitialCreation {
            return Err(refused(
                "tenant-root control-plane returned a non-initial activation receipt",
            ));
        }
        Ok(parsed)
    }

    /// The genesis operation: open a tenant root under a signed grant.
    ///
    /// The grant is verified against the issuer's own configured authorities,
    /// never against anything the request names. The authority id is derived
    /// from the Durable Object binding, and the Durable Object independently
    /// re-verifies the capability before persisting, so reaching this route
    /// grants no ability to write state.
    pub async fn handle_cloudflare_tenant_root_control_plane_create_tenant_root_v1(
        request: CloudflareTenantRootControlPlaneCreateTenantRootRequestV1,
        env: &worker::Env,
        runtime: &CloudflareTenantRootControlPlaneRuntimeV1,
    ) -> RouterAbProtocolResult<CloudflareTenantRootControlPlaneCreateTenantRootResponseV1> {
        let grant_bytes = decode_canonical_base64url(
            "tenant-root creation grant",
            &request.creation_grant_b64u,
            TENANT_ROOT_CREATION_GRANT_MAX_BYTES_V1,
            TENANT_ROOT_CREATION_GRANT_MAX_BYTES_V1 * 2,
        )?;
        let grant =
            TenantRootCreationGrantV1::decode_canonical_bytes(&grant_bytes).map_err(derivation)?;
        // The trusted key is selected by the grant's key id but supplied by the
        // issuer's own configuration: an unlisted authority has no key here.
        let grant_key_id = grant.grant_key_id().to_owned();
        let Some(trusted_key) = runtime
            .bindings()
            .grant_authority_verifying_keys
            .for_grant_key_id(&grant_key_id)
        else {
            return Err(refused(
                "tenant-root creation grant authority is not trusted by this control plane",
            ));
        };
        let verified = grant
            .verify(&grant_key_id, trusted_key)
            .map_err(derivation)?;

        let now_ms = crate::cloudflare_now_unix_ms_v1()?;
        let draw = derive_tenant_root_creation_ceremony_v1(
            &grant_bytes,
            runtime.bindings().deriver_a_signing_key_id.clone(),
            runtime.bindings().deriver_b_signing_key_id.clone(),
        )?;
        let (authority_id, _) = read_creation_object_binding(
            env,
            verified.identity_digest(),
            verified.custody_lineage(),
        )?;
        let seed = load_issuer_seed(env, runtime)?;
        let authorized = authorize_tenant_root_creation_v1(
            &verified,
            &draw,
            now_ms,
            authority_id,
            runtime.bindings().issuer_signing_key.signing_key_id(),
            &seed,
        )?;

        let persisted = execute_cloudflare_router_tenant_root_creation_journal_call_v1(
            env,
            &authorized.journal,
            &authorized.capability,
        )
        .await?;
        let (_, current) =
            read_creation_state(env, verified.identity_digest(), verified.custody_lineage())
                .await?;
        Ok(CloudflareTenantRootControlPlaneCreateTenantRootResponseV1 {
            identity_digest_b64u: encode_base64url_bytes_v1(verified.identity_digest().as_bytes()),
            custody_lineage_b64u: encode_base64url_bytes_v1(verified.custody_lineage().as_bytes()),
            revision: persisted.revision,
            journal_digest_b64u: persisted.journal_digest_b64u,
            capability_digest_b64u: persisted.capability_digest_b64u,
            status: creation_status(&current)?,
            replayed: matches!(
                persisted.outcome,
                CloudflareTenantRootCreationJournalOutcomeV1::Replay
            ),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::durable_object::tenant_root_creation::{
        validate_creation_record, CloudflareTenantRootCreationJournalRecordV1,
    };
    use crate::encode_base64url_bytes_v1;
    use curve25519_dalek::scalar::Scalar;
    use ed25519_dalek::SigningKey;
    use rand_chacha::ChaCha20Rng;
    use rand_core_06::SeedableRng;
    use router_ab_core::{
        TenantRootActivationReceiptBindingV1, TenantRootActivationReceiptTransitionV1,
        TenantRootCanaryCurveFamilyV1, TenantRootCeremonyEpochsV1, TenantRootCeremonyNonceV1,
        TenantRootCeremonySessionIdV1, TenantRootCreationCapabilityNonceV1,
        TenantRootCreationCapabilityV1, TenantRootCustodyLineageId, TenantRootEpochCommitmentsV1,
        TenantRootIdentityV1, TenantRootManagedBackupBindingV1,
        TenantRootManagedBackupSealRequestV1, TenantRootProviderCanaryReceiptBindingV1,
        TenantRootShareInstallationEvidenceV1, TenantRootShareInstallationTranscriptV1,
        TenantRootSignedManagedBackupV1, TenantRootSignedProviderCanaryReceiptV1,
        TenantRootSignedShareInstallationEvidenceV1,
        VerifiedTenantRootInitialCreationActivationEvidenceBundleV1,
    };
    use std::collections::BTreeMap;
    use threshold_prf::{
        prove_root_share_knowledge, SigningRootShare, SigningRootShareCommitment,
        SigningRootShareWire,
    };

    const ISSUER_KEY_ID: &str = "control-plane-issuer-active";
    const ISSUER_SEED: [u8; 32] = [0x51; 32];
    const OTHER_SEED: [u8; 32] = [0x52; 32];
    const AUTHORITY: [u8; 32] = [0x44; 32];
    // A 30-second ceremony window, inside the frozen 300-second maximum lifetime
    // that the capability, context, and command all enforce.
    const CEREMONY_ISSUED_AT_MS: u64 = 1_000_000;
    const CEREMONY_EXPIRES_AT_MS: u64 = 1_030_000;

    fn seed() -> Zeroizing<[u8; 32]> {
        Zeroizing::new(ISSUER_SEED)
    }

    fn published() -> BTreeMap<String, [u8; 32]> {
        BTreeMap::from([(
            ISSUER_KEY_ID.to_owned(),
            SigningKey::from_bytes(&ISSUER_SEED)
                .verifying_key()
                .to_bytes(),
        )])
    }

    fn authority() -> TenantRootControlPlaneAuthorityIdV1 {
        TenantRootControlPlaneAuthorityIdV1::from_bytes(AUTHORITY)
    }

    /// A persisted, issuer-authorized Started journal exactly as the Durable
    /// Object would hand it back and the issuer would re-validate it.
    fn validated_journal() -> ValidatedTenantRootCreationJournalV1 {
        let identity =
            TenantRootIdentityV1::new("org-1", "project-2", "production", "root-main", "v3")
                .expect("identity");
        let lineage = TenantRootCustodyLineageId::from_bytes([0x22; 16]).expect("lineage");
        let context = TenantRootCeremonyContextV1::new(
            identity.digest().expect("identity digest"),
            lineage,
            TenantRootCeremonyEpochsV1::create(),
            TenantRootCeremonySessionIdV1::from_bytes([0x11; 16]).expect("session"),
            TenantRootCeremonyNonceV1::from_bytes([0x33; 32]).expect("nonce"),
            CEREMONY_ISSUED_AT_MS,
            CEREMONY_EXPIRES_AT_MS,
            "deriver-a-signing-key-7",
            "deriver-b-signing-key-9",
        )
        .expect("context");
        let journal =
            TenantRootCreationJournalV1::started(identity, lineage, context).expect("journal");
        let capability = TenantRootCreationCapabilityV1::sign(
            journal.identity_digest(),
            journal.custody_lineage(),
            journal.digest().expect("journal digest"),
            authority(),
            TenantRootCreationCapabilityNonceV1::from_bytes([0x55; 32]).expect("capability nonce"),
            CEREMONY_ISSUED_AT_MS,
            CEREMONY_EXPIRES_AT_MS,
            ISSUER_KEY_ID,
            &ISSUER_SEED,
        )
        .expect("capability");
        validate_creation_record(
            CloudflareTenantRootCreationJournalRecordV1 {
                journal_b64u: encode_base64url_bytes_v1(
                    &journal.canonical_bytes().expect("journal bytes"),
                ),
                creation_capability_b64u: encode_base64url_bytes_v1(
                    &capability.canonical_bytes().expect("capability bytes"),
                ),
            },
            authority(),
            &published(),
        )
        .expect("validated journal")
    }

    fn fresh() -> TenantRootCreationProgressV1 {
        TenantRootCreationProgressV1 {
            committed_roles: Vec::new(),
            installation_checkpoint:
                CloudflareTenantRootCreationInstallationCheckpointReadStateV1::None,
            cleanup_checkpointed: false,
        }
    }

    fn issue(
        journal: &ValidatedTenantRootCreationJournalV1,
        progress: &TenantRootCreationProgressV1,
        role: TwoPartyDeriverRole,
        now_ms: u64,
        issuer_seed: &Zeroizing<[u8; 32]>,
    ) -> RouterAbProtocolResult<IssuedTenantRootRoleCreationCommandV1> {
        issue_tenant_root_role_creation_command_v1(
            TenantRootRoleCreationCommandIssuanceV1 {
                journal,
                progress: &progress.clone(),
                role,
                authority_id: authority(),
                now_ms,
            },
            ISSUER_KEY_ID,
            issuer_seed,
        )
    }

    const GRANT_KEY_ID: &str = "provisioning-authority-v1";
    const GRANT_SEED: [u8; 32] = [0x71; 32];

    fn grant_verifying_key() -> [u8; 32] {
        SigningKey::from_bytes(&GRANT_SEED)
            .verifying_key()
            .to_bytes()
    }

    fn signed_grant(
        org: &str,
        issued_at_ms: u64,
        expires_at_ms: u64,
    ) -> router_ab_core::TenantRootCreationGrantV1 {
        router_ab_core::TenantRootCreationGrantV1::sign(
            &TenantRootIdentityV1::new(org, "project-2", "production", "root-main", "v3")
                .expect("identity"),
            TenantRootCustodyLineageId::from_bytes([0x22; 16]).expect("lineage"),
            router_ab_core::TenantRootCreationGrantNonceV1::from_bytes([0x33; 32])
                .expect("grant nonce"),
            issued_at_ms,
            expires_at_ms,
            GRANT_KEY_ID,
            &GRANT_SEED,
        )
        .expect("signed grant")
    }

    fn verified_grant(org: &str) -> VerifiedTenantRootCreationGrantV1 {
        signed_grant(org, CEREMONY_ISSUED_AT_MS, CEREMONY_EXPIRES_AT_MS)
            .verify(GRANT_KEY_ID, &grant_verifying_key())
            .expect("verified grant")
    }

    /// The ceremony as the handler derives it: from the exact grant bytes.
    fn ceremony_draw_for(org: &str) -> TenantRootCreationCeremonyDrawV1 {
        derive_tenant_root_creation_ceremony_v1(
            &signed_grant(org, CEREMONY_ISSUED_AT_MS, CEREMONY_EXPIRES_AT_MS)
                .canonical_bytes()
                .expect("grant bytes"),
            "deriver-a-signing-key-7".to_owned(),
            "deriver-b-signing-key-9".to_owned(),
        )
        .expect("derived ceremony")
    }

    fn ceremony_draw() -> TenantRootCreationCeremonyDrawV1 {
        ceremony_draw_for("org-1")
    }

    /// Genesis constructs the journal and capability from the grant alone; the
    /// result is exactly what the Durable Object independently admits.
    #[test]
    fn genesis_builds_a_journal_the_durable_object_accepts() {
        let grant = verified_grant("org-1");
        let now = CEREMONY_ISSUED_AT_MS + 1;
        let authorized = authorize_tenant_root_creation_v1(
            &grant,
            &ceremony_draw(),
            now,
            authority(),
            ISSUER_KEY_ID,
            &seed(),
        )
        .expect("authorized");

        // The journal names exactly the authorized tenant and lineage.
        assert_eq!(
            authorized.journal.identity_digest(),
            grant.identity_digest()
        );
        assert_eq!(
            authorized.journal.custody_lineage(),
            grant.custody_lineage()
        );

        // The capability attests the journal the issuer just built, and
        // re-validates through the same path the Durable Object uses.
        let validated = validate_creation_record(
            CloudflareTenantRootCreationJournalRecordV1 {
                journal_b64u: encode_base64url_bytes_v1(
                    &authorized.journal.canonical_bytes().expect("journal bytes"),
                ),
                creation_capability_b64u: encode_base64url_bytes_v1(
                    &authorized
                        .capability
                        .canonical_bytes()
                        .expect("capability bytes"),
                ),
            },
            authority(),
            &published(),
        )
        .expect("the Durable Object admits this creation");
        assert_eq!(validated.identity_digest, grant.identity_digest());

        // The ceremony window IS the authorization's window: reproducible, and
        // it can never outlive the grant that opened it.
        let context = &validated.ceremony_context;
        assert_eq!(context.issued_at_ms(), grant.issued_at_ms());
        assert!(context.expires_at_ms() <= grant.expires_at_ms());
        assert_eq!(
            context.signing_key_id(TwoPartyDeriverRole::DeriverA),
            "deriver-a-signing-key-7"
        );
        assert_eq!(
            context.signing_key_id(TwoPartyDeriverRole::DeriverB),
            "deriver-b-signing-key-9"
        );
    }

    /// The whole creation path, end to end: a grant opens a ceremony, and the
    /// role command minted against it verifies at a Deriver.
    #[test]
    fn genesis_then_role_command_verifies_at_a_deriver() {
        let grant = verified_grant("org-1");
        let now = CEREMONY_ISSUED_AT_MS + 1;
        let authorized = authorize_tenant_root_creation_v1(
            &grant,
            &ceremony_draw(),
            now,
            authority(),
            ISSUER_KEY_ID,
            &seed(),
        )
        .expect("authorized");
        let journal = validate_creation_record(
            CloudflareTenantRootCreationJournalRecordV1 {
                journal_b64u: encode_base64url_bytes_v1(
                    &authorized.journal.canonical_bytes().expect("journal bytes"),
                ),
                creation_capability_b64u: encode_base64url_bytes_v1(
                    &authorized
                        .capability
                        .canonical_bytes()
                        .expect("capability bytes"),
                ),
            },
            authority(),
            &published(),
        )
        .expect("validated journal");

        for role in [TwoPartyDeriverRole::DeriverA, TwoPartyDeriverRole::DeriverB] {
            let issued = issue_tenant_root_role_creation_command_v1(
                TenantRootRoleCreationCommandIssuanceV1 {
                    journal: &journal,
                    progress: &fresh(),
                    role,
                    authority_id: authority(),
                    now_ms: now + 1,
                },
                ISSUER_KEY_ID,
                &seed(),
            )
            .expect("issued command");
            let verified = issued
                .package
                .verify(
                    role,
                    authority(),
                    ISSUER_KEY_ID,
                    &published()[ISSUER_KEY_ID],
                )
                .expect("a Deriver verifies it with only the package and the public anchor");
            assert_eq!(verified.command().role(), role);
        }
    }

    /// A lost-response retry of the SAME grant must reproduce the SAME creation.
    ///
    /// The Durable Object recognises a replay only on an exact byte match, so
    /// any per-request randomness or clock reading in the constructed bytes
    /// would make a retry conflict with its own first attempt.
    #[test]
    fn the_same_grant_reproduces_the_same_creation_byte_for_byte() {
        let grant = verified_grant("org-1");
        // Two attempts at different wall-clock instants inside the window.
        let first = authorize_tenant_root_creation_v1(
            &grant,
            &ceremony_draw(),
            CEREMONY_ISSUED_AT_MS + 1,
            authority(),
            ISSUER_KEY_ID,
            &seed(),
        )
        .expect("first attempt");
        let retry = authorize_tenant_root_creation_v1(
            &grant,
            &ceremony_draw(),
            CEREMONY_EXPIRES_AT_MS - 1,
            authority(),
            ISSUER_KEY_ID,
            &seed(),
        )
        .expect("lost-response retry");

        assert_eq!(
            first.journal.canonical_bytes().expect("journal"),
            retry.journal.canonical_bytes().expect("journal"),
        );
        assert_eq!(
            first.capability.canonical_bytes().expect("capability"),
            retry.capability.canonical_bytes().expect("capability"),
        );
        assert_eq!(
            first.journal.digest().expect("digest"),
            retry.journal.digest().expect("digest")
        );
        assert_eq!(
            first.capability.digest().expect("digest"),
            retry.capability.digest().expect("digest")
        );

        // The Durable Object therefore sees an identical record and replays it
        // rather than reporting a conflicting pair.
        let record =
            |a: &AuthorizedTenantRootCreationV1| CloudflareTenantRootCreationJournalRecordV1 {
                journal_b64u: encode_base64url_bytes_v1(
                    &a.journal.canonical_bytes().expect("journal"),
                ),
                creation_capability_b64u: encode_base64url_bytes_v1(
                    &a.capability.canonical_bytes().expect("capability"),
                ),
            };
        assert_eq!(record(&first), record(&retry));

        // A DIFFERENT grant for the same tenant still produces different bytes,
        // so it conflicts rather than silently replaying.
        let other = signed_grant("org-1", CEREMONY_ISSUED_AT_MS + 5, CEREMONY_EXPIRES_AT_MS)
            .verify(GRANT_KEY_ID, &grant_verifying_key())
            .expect("second grant");
        let other_draw = derive_tenant_root_creation_ceremony_v1(
            &signed_grant("org-1", CEREMONY_ISSUED_AT_MS + 5, CEREMONY_EXPIRES_AT_MS)
                .canonical_bytes()
                .expect("grant bytes"),
            "deriver-a-signing-key-7".to_owned(),
            "deriver-b-signing-key-9".to_owned(),
        )
        .expect("derived");
        let different = authorize_tenant_root_creation_v1(
            &other,
            &other_draw,
            CEREMONY_ISSUED_AT_MS + 6,
            authority(),
            ISSUER_KEY_ID,
            &seed(),
        )
        .expect("different grant");
        assert_ne!(record(&first), record(&different));
    }

    /// The derived material is grant-specific, not a constant.
    #[test]
    fn ceremony_material_is_derived_per_grant() {
        let a = ceremony_draw_for("org-1");
        let b = ceremony_draw_for("org-2");
        assert_ne!(a.session_id, b.session_id);
        assert_ne!(a.ceremony_nonce, b.ceremony_nonce);
        assert_ne!(a.capability_nonce, b.capability_nonce);
        // Domain separation: the three values differ within one grant.
        assert_ne!(a.ceremony_nonce.as_bytes(), a.capability_nonce.as_bytes());
    }

    #[test]
    fn genesis_fails_closed_outside_the_authorized_window() {
        let grant = verified_grant("org-1");
        for now in [
            0,
            CEREMONY_ISSUED_AT_MS,
            CEREMONY_EXPIRES_AT_MS,
            CEREMONY_EXPIRES_AT_MS + 1,
        ] {
            assert!(
                authorize_tenant_root_creation_v1(
                    &grant,
                    &ceremony_draw(),
                    now,
                    authority(),
                    ISSUER_KEY_ID,
                    &seed(),
                )
                .is_err(),
                "now={now} must be refused"
            );
        }
    }

    #[test]
    fn genesis_refuses_a_ceremony_that_cannot_separate_the_roles() {
        let grant = verified_grant("org-1");
        let mut draw = ceremony_draw();
        draw.deriver_b_signing_key_id = draw.deriver_a_signing_key_id.clone();
        assert_eq!(
            authorize_tenant_root_creation_v1(
                &grant,
                &draw,
                CEREMONY_ISSUED_AT_MS + 1,
                authority(),
                ISSUER_KEY_ID,
                &seed(),
            )
            .expect_err("identical role signers")
            .code(),
            RouterAbProtocolErrorCode::ForbiddenLocalBinding
        );
    }

    #[test]
    fn distinct_tenants_open_distinct_creations() {
        let now = CEREMONY_ISSUED_AT_MS + 1;
        let a = authorize_tenant_root_creation_v1(
            &verified_grant("org-1"),
            &ceremony_draw(),
            now,
            authority(),
            ISSUER_KEY_ID,
            &seed(),
        )
        .expect("org-1");
        let b = authorize_tenant_root_creation_v1(
            &verified_grant("org-2"),
            &ceremony_draw_for("org-2"),
            now,
            authority(),
            ISSUER_KEY_ID,
            &seed(),
        )
        .expect("org-2");
        assert_ne!(a.journal.identity_digest(), b.journal.identity_digest());
        assert_ne!(
            a.journal.digest().expect("digest"),
            b.journal.digest().expect("digest")
        );
        assert_ne!(
            a.capability.digest().expect("digest"),
            b.capability.digest().expect("digest")
        );
    }

    #[test]
    fn the_genesis_request_surface_carries_only_a_grant() {
        let request = CloudflareTenantRootControlPlaneCreateTenantRootRequestV1 {
            creation_grant_b64u: "abc".to_owned(),
        };
        let json = serde_json::to_value(&request).expect("json");
        let keys: Vec<&str> = json
            .as_object()
            .expect("object")
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(keys, ["creation_grant_b64u"]);
        // A smuggled identity, lineage, or window is rejected outright.
        let smuggled = r#"{"creation_grant_b64u":"abc","custody_lineage_b64u":"x"}"#;
        assert!(
            serde_json::from_str::<CloudflareTenantRootControlPlaneCreateTenantRootRequestV1>(
                smuggled
            )
            .is_err()
        );
    }

    #[test]
    fn issued_command_verifies_at_a_deriver_with_only_the_package_and_the_public_anchor() {
        let journal = validated_journal();
        let now = CEREMONY_ISSUED_AT_MS + 10_000;
        for role in [TwoPartyDeriverRole::DeriverA, TwoPartyDeriverRole::DeriverB] {
            let issued = issue(&journal, &fresh(), role, now, &seed()).expect("issued");

            // Exactly what a Deriver holds: the package bytes, its own expected
            // role and authority, and the published issuer key. No Router state.
            let package = TenantRootRoleCreationCommandPackageV1::decode_canonical_bytes(
                &issued.package.canonical_bytes().expect("package bytes"),
            )
            .expect("package decodes");
            let verified = package
                .verify(
                    role,
                    authority(),
                    ISSUER_KEY_ID,
                    &published()[ISSUER_KEY_ID],
                )
                .expect("verifies");
            assert_eq!(verified.command().role(), role);
            assert_eq!(verified.command().issuer_key_id(), ISSUER_KEY_ID);
            assert_eq!(issued.command.role(), role);

            // The window is derived: starts now, capped by the ceremony window
            // and the frozen maximum lifetime.
            assert_eq!(issued.command.issued_at_ms(), now);
            assert_eq!(
                issued.command.expires_at_ms(),
                (now + TENANT_ROOT_MAX_LIFETIME_MS_V1).min(CEREMONY_EXPIRES_AT_MS)
            );
            assert!(verified.command().require_fresh(now + 1).is_ok());

            // A Deriver expecting the other role must reject it.
            let other = match role {
                TwoPartyDeriverRole::DeriverA => TwoPartyDeriverRole::DeriverB,
                TwoPartyDeriverRole::DeriverB => TwoPartyDeriverRole::DeriverA,
            };
            assert!(package
                .verify(
                    other,
                    authority(),
                    ISSUER_KEY_ID,
                    &published()[ISSUER_KEY_ID]
                )
                .is_err());
        }
    }

    #[test]
    fn issuance_fails_closed_once_creation_is_checkpointed_or_the_role_committed() {
        let journal = validated_journal();
        let now = CEREMONY_ISSUED_AT_MS + 10_000;

        let abandoned = TenantRootCreationProgressV1 {
            committed_roles: vec![TwoPartyDeriverRole::DeriverB],
            installation_checkpoint:
                CloudflareTenantRootCreationInstallationCheckpointReadStateV1::OneRoleReady {
                    role: CloudflareTenantRootCreationInstallationRoleV1::DeriverB,
                    signed_evidence_b64u: "evidence".to_owned(),
                },
            cleanup_checkpointed: true,
        };
        assert_eq!(
            issue(
                &journal,
                &abandoned,
                TwoPartyDeriverRole::DeriverA,
                now,
                &seed()
            )
            .expect_err("abandoned")
            .code(),
            RouterAbProtocolErrorCode::ForbiddenLocalBinding
        );

        let checkpointed = TenantRootCreationProgressV1 {
            committed_roles: Vec::new(),
            installation_checkpoint:
                CloudflareTenantRootCreationInstallationCheckpointReadStateV1::BothRolesReady {
                    root_commitment_b64u: "root".to_owned(),
                },
            cleanup_checkpointed: false,
        };
        assert_eq!(
            issue(
                &journal,
                &checkpointed,
                TwoPartyDeriverRole::DeriverA,
                now,
                &seed()
            )
            .expect_err("checkpointed")
            .code(),
            RouterAbProtocolErrorCode::ForbiddenLocalBinding
        );

        let a_committed = TenantRootCreationProgressV1 {
            committed_roles: vec![TwoPartyDeriverRole::DeriverA],
            installation_checkpoint:
                CloudflareTenantRootCreationInstallationCheckpointReadStateV1::None,
            cleanup_checkpointed: false,
        };
        assert!(issue(
            &journal,
            &a_committed,
            TwoPartyDeriverRole::DeriverA,
            now,
            &seed()
        )
        .is_err());
        // The peer that has not committed may still be issued its command.
        assert!(issue(
            &journal,
            &a_committed,
            TwoPartyDeriverRole::DeriverB,
            now,
            &seed()
        )
        .is_ok());
    }

    #[test]
    fn issuance_fails_closed_outside_the_ceremony_window() {
        let journal = validated_journal();
        for now in [
            0,
            CEREMONY_ISSUED_AT_MS - 1,
            CEREMONY_EXPIRES_AT_MS,
            CEREMONY_EXPIRES_AT_MS + 1,
        ] {
            assert!(
                issue(
                    &journal,
                    &fresh(),
                    TwoPartyDeriverRole::DeriverA,
                    now,
                    &seed()
                )
                .is_err(),
                "now={now} must be refused"
            );
        }
        // The last instant inside the window still yields a non-empty command window.
        let issued = issue(
            &journal,
            &fresh(),
            TwoPartyDeriverRole::DeriverA,
            CEREMONY_EXPIRES_AT_MS - 1,
            &seed(),
        )
        .expect("edge of window");
        assert_eq!(issued.command.expires_at_ms(), CEREMONY_EXPIRES_AT_MS);
    }

    #[test]
    fn a_command_signed_with_the_wrong_seed_never_verifies_under_the_published_key() {
        // The issuer cannot mint a verifiable command without the seed that
        // derives the published active key; boot-time provenance proves the
        // seed, this proves the consequence if it were ever bypassed.
        let journal = validated_journal();
        let issued = issue(
            &journal,
            &fresh(),
            TwoPartyDeriverRole::DeriverA,
            CEREMONY_ISSUED_AT_MS + 10_000,
            &Zeroizing::new(OTHER_SEED),
        )
        .expect("signing itself succeeds");
        assert!(issued
            .package
            .verify(
                TwoPartyDeriverRole::DeriverA,
                authority(),
                ISSUER_KEY_ID,
                &published()[ISSUER_KEY_ID],
            )
            .is_err());
    }

    #[test]
    fn the_request_surface_names_only_identity_lineage_and_role() {
        // Structural: every other command field is derived by the issuer.
        let request = CloudflareTenantRootControlPlaneRoleCreationCommandRequestV1 {
            identity_digest_b64u: "a".repeat(43),
            custody_lineage_b64u: "b".repeat(22),
            role: CloudflareTenantRootControlPlaneRoleV1::DeriverB,
        };
        let json = serde_json::to_value(&request).expect("json");
        let mut keys: Vec<&str> = json
            .as_object()
            .expect("object")
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            ["custody_lineage_b64u", "identity_digest_b64u", "role"]
        );
        // Unknown fields such as an authority id or a time window are rejected.
        let smuggled = r#"{"identity_digest_b64u":"a","custody_lineage_b64u":"b","role":"deriver_a","authority_id_b64u":"x"}"#;
        assert!(
            serde_json::from_str::<CloudflareTenantRootControlPlaneRoleCreationCommandRequestV1>(
                smuggled
            )
            .is_err()
        );
    }

    const ACTIVATION_ISSUER_SEED: [u8; 32] = [0x51; 32];
    const ACTIVATION_CANARY_SEED: [u8; 32] = [0x71; 32];

    fn activation_context() -> TenantRootCeremonyContextV1 {
        let identity = TenantRootIdentityV1::new(
            "activation-org",
            "activation-project",
            "production",
            "root-main",
            "v1",
        )
        .expect("identity");
        TenantRootCeremonyContextV1::new(
            identity.digest().expect("identity digest"),
            TenantRootCustodyLineageId::from_bytes([0x23; 16]).expect("lineage"),
            TenantRootCeremonyEpochsV1::create(),
            TenantRootCeremonySessionIdV1::from_bytes([0x24; 16]).expect("session"),
            TenantRootCeremonyNonceV1::from_bytes([0x25; 32]).expect("nonce"),
            CEREMONY_ISSUED_AT_MS,
            CEREMONY_EXPIRES_AT_MS,
            "deriver-a-signing-key-7",
            "deriver-b-signing-key-9",
        )
        .expect("context")
    }

    fn refresh_activation_context() -> TenantRootCeremonyContextV1 {
        let identity = TenantRootIdentityV1::new(
            "activation-org",
            "activation-project",
            "production",
            "root-main",
            "v1",
        )
        .expect("identity");
        let epochs = TenantRootCeremonyEpochsV1::refresh(
            TenantRootShareEpoch::new(7).expect("current epoch"),
            TenantRootShareEpoch::new(8).expect("next epoch"),
        )
        .expect("refresh epochs");
        TenantRootCeremonyContextV1::new(
            identity.digest().expect("identity digest"),
            TenantRootCustodyLineageId::from_bytes([0x23; 16]).expect("lineage"),
            epochs,
            TenantRootCeremonySessionIdV1::from_bytes([0x64; 16]).expect("session"),
            TenantRootCeremonyNonceV1::from_bytes([0x65; 32]).expect("nonce"),
            CEREMONY_ISSUED_AT_MS,
            CEREMONY_EXPIRES_AT_MS,
            "deriver-a-signing-key-7",
            "deriver-b-signing-key-9",
        )
        .expect("refresh context")
    }

    fn activation_share(role: TwoPartyDeriverRole, scalar: u64) -> SigningRootShare {
        SigningRootShare::from_canonical_bytes(role.share_id(), Scalar::from(scalar).to_bytes())
            .expect("share")
    }

    fn activation_role_signing_key(role: TwoPartyDeriverRole) -> SigningKey {
        SigningKey::from_bytes(match role {
            TwoPartyDeriverRole::DeriverA => &[0x61; 32],
            TwoPartyDeriverRole::DeriverB => &[0x62; 32],
        })
    }

    fn activation_role_signing_key_id(role: TwoPartyDeriverRole) -> &'static str {
        match role {
            TwoPartyDeriverRole::DeriverA => "deriver-a-signing-key-7",
            TwoPartyDeriverRole::DeriverB => "deriver-b-signing-key-9",
        }
    }

    fn activation_installation(
        context: TenantRootCeremonyContextV1,
        role: TwoPartyDeriverRole,
        share: &SigningRootShare,
        peer: &SigningRootShare,
        proof_seed: u8,
    ) -> router_ab_core::VerifiedTenantRootSignedShareInstallationEvidenceWireV1 {
        let transcript = TenantRootShareInstallationTranscriptV1::new(
            context,
            role,
            SigningRootShareCommitment::from_share(share),
            SigningRootShareCommitment::from_share(peer),
        )
        .expect("installation transcript");
        let proof = prove_root_share_knowledge(
            share,
            &transcript.canonical_bytes().expect("transcript bytes"),
            &mut ChaCha20Rng::from_seed([proof_seed; 32]),
        )
        .expect("knowledge proof");
        let evidence = TenantRootShareInstallationEvidenceV1::new(transcript, proof)
            .expect("installation evidence");
        let signing_key = activation_role_signing_key(role);
        let signed =
            TenantRootSignedShareInstallationEvidenceV1::sign(evidence, &signing_key.to_bytes())
                .expect("signed installation evidence");
        let bytes = signed.canonical_bytes().expect("installation bytes");
        TenantRootSignedShareInstallationEvidenceV1::decode_and_verify_canonical_bytes(
            &bytes,
            signing_key.verifying_key().as_bytes(),
        )
        .expect("verified installation evidence")
    }

    fn activation_commitments(
        share_a: &SigningRootShare,
        share_b: &SigningRootShare,
    ) -> TenantRootEpochCommitmentsV1 {
        TenantRootEpochCommitmentsV1::new(
            router_ab_core::MpcPrfShareCommitmentWireV1::new(
                SigningRootShareCommitment::from_share(share_a)
                    .to_bytes()
                    .to_vec(),
            )
            .expect("A commitment"),
            router_ab_core::MpcPrfShareCommitmentWireV1::new(
                SigningRootShareCommitment::from_share(share_b)
                    .to_bytes()
                    .to_vec(),
            )
            .expect("B commitment"),
        )
        .expect("commitments")
    }

    fn activation_backup(
        installation: &router_ab_core::VerifiedTenantRootSignedShareInstallationEvidenceWireV1,
        share: &SigningRootShare,
        role: TwoPartyDeriverRole,
    ) -> router_ab_core::VerifiedTenantRootManagedBackupV1 {
        let binding = TenantRootManagedBackupBindingV1::from_verified_installation_evidence(
            installation,
            format!("backup-provider-{}", role.as_str()),
            format!("kms/tenant-root/{}/epoch-1/v1", role.as_str()),
            activation_role_signing_key_id(role),
            CEREMONY_ISSUED_AT_MS,
        )
        .expect("backup binding");
        let share_wire = router_ab_core::MpcPrfSigningRootShareWireV1::new(
            SigningRootShareWire::from_share(share).to_bytes().to_vec(),
        )
        .expect("share wire");
        let request = TenantRootManagedBackupSealRequestV1::new(binding.clone(), share_wire)
            .expect("backup seal request");
        let signing_key = activation_role_signing_key(role);
        let ciphertext = match role {
            TwoPartyDeriverRole::DeriverA => vec![0xa5; 96],
            TwoPartyDeriverRole::DeriverB => vec![0xb5; 96],
        };
        let signed =
            TenantRootSignedManagedBackupV1::sign(request, ciphertext, &signing_key.to_bytes())
                .expect("signed managed backup");
        signed
            .verify(&binding, signing_key.verifying_key().as_bytes())
            .expect("verified managed backup")
    }

    fn activation_canary(
        context: &TenantRootCeremonyContextV1,
        commitments: &TenantRootEpochCommitmentsV1,
        family: TenantRootCanaryCurveFamilyV1,
    ) -> router_ab_core::VerifiedTenantRootProviderCanaryReceiptV1 {
        let (transition, target_epoch) = match context.epochs() {
            TenantRootCeremonyEpochsV1::Create { next } => (
                TenantRootActivationReceiptTransitionV1::InitialCreation,
                next,
            ),
            TenantRootCeremonyEpochsV1::Refresh { next, .. } => {
                (TenantRootActivationReceiptTransitionV1::RefreshSwap, next)
            }
        };
        let binding = TenantRootProviderCanaryReceiptBindingV1::new(
            context.identity_digest(),
            context.custody_lineage(),
            transition,
            target_epoch,
            commitments.clone(),
            family,
            format!("kms/tenant-root/{}/canary-v1", family.as_str()),
            CEREMONY_ISSUED_AT_MS + 10,
            TenantRootControlPlaneAuthorityIdV1::from_bytes([0x72; 32]),
            "control-plane-canary-v1",
            CEREMONY_ISSUED_AT_MS,
            CEREMONY_EXPIRES_AT_MS,
        )
        .expect("canary binding");
        let signed =
            TenantRootSignedProviderCanaryReceiptV1::sign(binding.clone(), &ACTIVATION_CANARY_SEED)
                .expect("signed canary");
        signed
            .verify(
                &binding,
                &SigningKey::from_bytes(&ACTIVATION_CANARY_SEED)
                    .verifying_key()
                    .to_bytes(),
            )
            .expect("verified canary")
    }

    fn activation_bundle() -> VerifiedTenantRootInitialCreationActivationEvidenceBundleV1 {
        let context = activation_context();
        let share_a = activation_share(TwoPartyDeriverRole::DeriverA, 12);
        let share_b = activation_share(TwoPartyDeriverRole::DeriverB, 19);
        let installation_a = activation_installation(
            context.clone(),
            TwoPartyDeriverRole::DeriverA,
            &share_a,
            &share_b,
            0x31,
        );
        let installation_b = activation_installation(
            context.clone(),
            TwoPartyDeriverRole::DeriverB,
            &share_b,
            &share_a,
            0x32,
        );
        let commitments = activation_commitments(&share_a, &share_b);
        let backup_a = activation_backup(&installation_a, &share_a, TwoPartyDeriverRole::DeriverA);
        let backup_b = activation_backup(&installation_b, &share_b, TwoPartyDeriverRole::DeriverB);
        let canary_ecdsa =
            activation_canary(&context, &commitments, TenantRootCanaryCurveFamilyV1::Ecdsa);
        let canary_ed25519 = activation_canary(
            &context,
            &commitments,
            TenantRootCanaryCurveFamilyV1::Ed25519,
        );
        VerifiedTenantRootInitialCreationActivationEvidenceBundleV1::from_verified_managed_backups(
            installation_a,
            installation_b,
            backup_a,
            backup_b,
            canary_ecdsa,
            canary_ed25519,
            2,
            3,
        )
        .expect("verified initial activation evidence")
    }

    fn refresh_activation_bundle() -> VerifiedTenantRootRefreshSwapActivationEvidenceBundleV1 {
        refresh_activation_bundle_with_scalars(12, 19, 19, 33, 5, 6)
    }

    fn refresh_activation_bundle_with_scalars(
        current_a_scalar: u64,
        current_b_scalar: u64,
        next_a_scalar: u64,
        next_b_scalar: u64,
        expected_control_plane_revision: u64,
        result_control_plane_revision: u64,
    ) -> VerifiedTenantRootRefreshSwapActivationEvidenceBundleV1 {
        let context = refresh_activation_context();
        let current_a = activation_share(TwoPartyDeriverRole::DeriverA, current_a_scalar);
        let current_b = activation_share(TwoPartyDeriverRole::DeriverB, current_b_scalar);
        let next_a = activation_share(TwoPartyDeriverRole::DeriverA, next_a_scalar);
        let next_b = activation_share(TwoPartyDeriverRole::DeriverB, next_b_scalar);
        let current_commitments = activation_commitments(&current_a, &current_b);
        let installation_a = activation_installation(
            context.clone(),
            TwoPartyDeriverRole::DeriverA,
            &next_a,
            &next_b,
            0x41,
        );
        let installation_b = activation_installation(
            context.clone(),
            TwoPartyDeriverRole::DeriverB,
            &next_b,
            &next_a,
            0x42,
        );
        let next_commitments = activation_commitments(&next_a, &next_b);
        let backup_a = activation_backup(&installation_a, &next_a, TwoPartyDeriverRole::DeriverA);
        let backup_b = activation_backup(&installation_b, &next_b, TwoPartyDeriverRole::DeriverB);
        let canary_ecdsa = activation_canary(
            &context,
            &next_commitments,
            TenantRootCanaryCurveFamilyV1::Ecdsa,
        );
        let canary_ed25519 = activation_canary(
            &context,
            &next_commitments,
            TenantRootCanaryCurveFamilyV1::Ed25519,
        );
        VerifiedTenantRootRefreshSwapActivationEvidenceBundleV1::from_verified_managed_backups(
            &current_commitments,
            installation_a,
            installation_b,
            backup_a,
            backup_b,
            canary_ecdsa,
            canary_ed25519,
            expected_control_plane_revision,
            result_control_plane_revision,
        )
        .expect("verified refresh activation evidence")
    }

    #[test]
    fn initial_activation_issuance_returns_the_exact_typed_receipt_wire() {
        let bundle = activation_bundle();
        let activated_at_ms = CEREMONY_ISSUED_AT_MS + 20;
        let receipt = issue_tenant_root_initial_activation_receipt_v1(
            &bundle,
            activated_at_ms,
            authority(),
            ISSUER_KEY_ID,
            &Zeroizing::new(ACTIVATION_ISSUER_SEED),
        )
        .expect("issued initial activation receipt");
        let receipt_bytes = receipt.canonical_bytes().expect("receipt bytes");
        let verified = receipt
            .clone()
            .verify_initial_creation(
                &bundle,
                activated_at_ms,
                authority(),
                ISSUER_KEY_ID,
                &SigningKey::from_bytes(&ACTIVATION_ISSUER_SEED)
                    .verifying_key()
                    .to_bytes(),
            )
            .expect("receipt verifies against the complete bundle");
        assert_eq!(
            verified.transition(),
            TenantRootActivationReceiptTransitionV1::InitialCreation
        );

        let response = initial_activation_receipt_response_v1(receipt).expect("typed response");
        assert_eq!(
            crate::decode_base64url_bytes_v1(
                "initial activation receipt",
                &response.activation_receipt_b64u
            )
            .expect("response receipt bytes"),
            receipt_bytes
        );
    }

    #[test]
    fn refresh_activation_issuance_binds_the_exact_pair_and_revision() {
        let bundle = refresh_activation_bundle();
        let activated_at_ms = CEREMONY_ISSUED_AT_MS + 20;
        let receipt = issue_tenant_root_refresh_activation_receipt_v1(
            &bundle,
            activated_at_ms,
            authority(),
            ISSUER_KEY_ID,
            &Zeroizing::new(ACTIVATION_ISSUER_SEED),
        )
        .expect("issued refresh activation receipt");
        let issuer_verifying_key = SigningKey::from_bytes(&ACTIVATION_ISSUER_SEED)
            .verifying_key()
            .to_bytes();
        let verified = receipt
            .clone()
            .verify_refresh_swap(
                &bundle,
                activated_at_ms,
                authority(),
                ISSUER_KEY_ID,
                &issuer_verifying_key,
            )
            .expect("receipt verifies against the exact refresh bundle");
        let TenantRootActivationReceiptBindingV1::RefreshSwap(binding) = verified.binding() else {
            panic!("refresh issuer must produce a refresh-swap receipt")
        };
        assert_eq!(
            binding.current_epoch(),
            TenantRootShareEpoch::new(7).unwrap()
        );
        assert_eq!(binding.next_epoch(), TenantRootShareEpoch::new(8).unwrap());
        assert_eq!(binding.expected_control_plane_revision(), 5);
        assert_eq!(binding.result_control_plane_revision(), 6);
        assert_eq!(binding.current_commitments(), bundle.current_commitments());
        assert_eq!(binding.next_commitments(), bundle.next_commitments());

        let wrong_pair = refresh_activation_bundle_with_scalars(13, 20, 20, 34, 5, 6);
        assert!(receipt
            .clone()
            .verify_refresh_swap(
                &wrong_pair,
                activated_at_ms,
                authority(),
                ISSUER_KEY_ID,
                &issuer_verifying_key,
            )
            .is_err());

        let wrong_revision = refresh_activation_bundle_with_scalars(12, 19, 19, 33, 6, 7);
        assert!(receipt
            .verify_refresh_swap(
                &wrong_revision,
                activated_at_ms,
                authority(),
                ISSUER_KEY_ID,
                &issuer_verifying_key,
            )
            .is_err());
    }

    #[test]
    fn refresh_command_issuance_binds_both_roles_to_one_active_pair_and_context() {
        let bundle = activation_bundle();
        let activated_at_ms = CEREMONY_ISSUED_AT_MS + 20;
        let receipt = issue_tenant_root_initial_activation_receipt_v1(
            &bundle,
            activated_at_ms,
            authority(),
            ISSUER_KEY_ID,
            &Zeroizing::new(ACTIVATION_ISSUER_SEED),
        )
        .expect("issued initial activation receipt")
        .verify_initial_creation(
            &bundle,
            activated_at_ms,
            authority(),
            ISSUER_KEY_ID,
            &SigningKey::from_bytes(&ACTIVATION_ISSUER_SEED)
                .verifying_key()
                .to_bytes(),
        )
        .expect("verified active receipt");
        let active_pair = TenantRootActiveRootPairV1::from_verified_activation_receipt(&receipt)
            .expect("active pair from receipt");
        let refresh_context = TenantRootCeremonyContextV1::new(
            active_pair.identity_digest(),
            active_pair.custody_lineage(),
            TenantRootCeremonyEpochsV1::refresh(
                active_pair.epoch(),
                active_pair.epoch().next().expect("next epoch"),
            )
            .expect("refresh epochs"),
            TenantRootCeremonySessionIdV1::from_bytes([0x61; 16]).expect("session"),
            TenantRootCeremonyNonceV1::from_bytes([0x62; 32]).expect("nonce"),
            activated_at_ms + 1,
            activated_at_ms + 10_000,
            activation_role_signing_key_id(TwoPartyDeriverRole::DeriverA),
            activation_role_signing_key_id(TwoPartyDeriverRole::DeriverB),
        )
        .expect("refresh context");
        let issuer_seed = Zeroizing::new(ACTIVATION_ISSUER_SEED);
        let issued = issue_tenant_root_role_refresh_commands_v1(
            TenantRootRoleRefreshCommandIssuanceV1 {
                active_pair: &active_pair,
                refresh_context: &refresh_context,
                expected_control_plane_revision: receipt.result_control_plane_revision(),
                authority_id: authority(),
                now_ms: refresh_context.issued_at_ms(),
            },
            ISSUER_KEY_ID,
            &issuer_seed,
        )
        .expect("issued refresh role commands");
        let issuer_verifying_key = SigningKey::from_bytes(&ACTIVATION_ISSUER_SEED)
            .verifying_key()
            .to_bytes();
        let verified_a = issued
            .deriver_a
            .verify(
                &active_pair,
                &refresh_context,
                TwoPartyDeriverRole::DeriverA,
                receipt.result_control_plane_revision(),
                authority(),
                ISSUER_KEY_ID,
                &issuer_verifying_key,
            )
            .expect("verified Deriver A command");
        let verified_b = issued
            .deriver_b
            .verify(
                &active_pair,
                &refresh_context,
                TwoPartyDeriverRole::DeriverB,
                receipt.result_control_plane_revision(),
                authority(),
                ISSUER_KEY_ID,
                &issuer_verifying_key,
            )
            .expect("verified Deriver B command");
        assert_eq!(
            verified_a.refresh_context_digest(),
            verified_b.refresh_context_digest()
        );
        assert_ne!(verified_a.digest(), verified_b.digest());
    }

    #[cfg(feature = "workers-rs")]
    #[test]
    fn initial_activation_requires_the_exact_persisted_both_roles_state() {
        let bundle = activation_bundle();
        let mut read = CloudflareTenantRootCreationJournalReadResponseV1 {
            journal_b64u: "journal".to_owned(),
            creation_capability_b64u: "capability".to_owned(),
            revision: 1,
            committed_roles: vec![
                CloudflareTenantRootCreationInstallationRoleV1::DeriverA,
                CloudflareTenantRootCreationInstallationRoleV1::DeriverB,
            ],
            installation_checkpoint:
                CloudflareTenantRootCreationInstallationCheckpointReadStateV1::BothRolesReady {
                    root_commitment_b64u: crate::encode_base64url_bytes_v1(
                        bundle.root_commitment(),
                    ),
                },
            cleanup_checkpointed: false,
        };
        live::require_persisted_initial_activation_state_v1(&read, &bundle)
            .expect("exact persisted installation state");

        read.installation_checkpoint =
            CloudflareTenantRootCreationInstallationCheckpointReadStateV1::BothRolesReady {
                root_commitment_b64u: crate::encode_base64url_bytes_v1(&[0x55; 32]),
            };
        assert_eq!(
            live::require_persisted_initial_activation_state_v1(&read, &bundle)
                .expect_err("foreign persisted root")
                .code(),
            RouterAbProtocolErrorCode::ForbiddenLocalBinding
        );

        read.installation_checkpoint =
            CloudflareTenantRootCreationInstallationCheckpointReadStateV1::BothRolesReady {
                root_commitment_b64u: crate::encode_base64url_bytes_v1(bundle.root_commitment()),
            };
        read.cleanup_checkpointed = true;
        assert_eq!(
            live::require_persisted_initial_activation_state_v1(&read, &bundle)
                .expect_err("cleaned creation")
                .code(),
            RouterAbProtocolErrorCode::ForbiddenLocalBinding
        );
    }
}
