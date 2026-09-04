use std::collections::BTreeMap;

#[cfg(feature = "workers-rs")]
use std::{cell::RefCell, rc::Rc};

use router_ab_core::{
    evaluate_tenant_root_refresh_commitment_checkpoint_v1,
    resolve_active_tenant_root_pair_binding_v1, verify_tenant_root_creation_evidence_v1,
    verify_tenant_root_refresh_installation_transition_v1, MpcPrfShareCommitmentWireV1,
    RouterAbDerivationError, RouterAbDerivationErrorCode, TenantRootActivationReceiptBindingV1,
    TenantRootActivationReceiptTransitionV1, TenantRootActiveRoleBindingV1,
    TenantRootActiveRoleResolutionV1, TenantRootActiveRoleRowKeyV1, TenantRootCeremonyContextV1,
    TenantRootCeremonyEpochsV1, TenantRootCeremonySessionIdV1, TenantRootCommandReplayKeyV1,
    TenantRootCommandSuccessReceiptV1, TenantRootCommandTerminalReceiptV1,
    TenantRootControlPlaneAuthorityIdV1, TenantRootCreationCapabilityV1,
    TenantRootCreationJournalV1, TenantRootCustodyLineageId, TenantRootEpochCommitmentsV1,
    TenantRootIdentityDigestV1, TenantRootIdentityV1, TenantRootLifecycleReceiptDigestV1,
    TenantRootManagedRestoreRoleV1, TenantRootProtocolDigestV1,
    TenantRootRefreshCommitmentCheckpointActiveBindingV1,
    TenantRootRefreshCommitmentCheckpointEvaluationV1,
    TenantRootRefreshCommitmentCheckpointOutcomeV1, TenantRootRefreshCommitmentCheckpointScopeV1,
    TenantRootRefreshCommitmentCheckpointStateV1, TenantRootRefreshCommitmentCheckpointV1,
    TenantRootRefreshContributionAadV1, TenantRootRoleCleanupCommandV1,
    TenantRootRoleCleanupTargetV1, TenantRootRoleCreationCommandV1,
    TenantRootRoleInstallationReceiptsV1, TenantRootRoleRefreshCommandV1, TenantRootShareEpoch,
    TenantRootSignedActivationReceiptV1, TenantRootSignedCreationCommitmentV1,
    TenantRootSignedRefreshCommitmentV1, TenantRootSignedRefreshContributionV1,
    TenantRootSignedShareInstallationEvidenceV1, TwoPartyDeriverRole,
    VerifiedTenantRootCreationCapabilityV1, VerifiedTenantRootCreationCommitmentPairV1,
    VerifiedTenantRootCreationCommitmentV1, VerifiedTenantRootRefreshCommitmentPairV1,
    VerifiedTenantRootRefreshCommitmentV1, VerifiedTenantRootRoleCleanupCommandV1,
    VerifiedTenantRootRoleCreationCommandV1, VerifiedTenantRootRoleRefreshCommandV1,
    VerifiedTenantRootSignedRefreshContributionV1,
    VerifiedTenantRootSignedShareInstallationEvidenceWireV1,
    TENANT_ROOT_COMMAND_TERMINAL_RECEIPT_MAX_BYTES_V1,
    TENANT_ROOT_CREATION_CAPABILITY_MAX_BYTES_V1, TENANT_ROOT_CREATION_JOURNAL_MAX_BYTES_V1,
    TENANT_ROOT_MANAGED_RESTORE_CAPABILITY_MAX_BYTES_V1,
    TENANT_ROOT_MANAGED_RESTORE_INCIDENT_AUTHORIZATION_MAX_BYTES_V1,
    TENANT_ROOT_MANAGED_RESTORE_PUBLIC_STATE_MAX_BYTES, TENANT_ROOT_MAX_LIFETIME_MS_V1,
    TENANT_ROOT_REFRESH_COMMITMENT_CHECKPOINT_MAX_BYTES_V1,
    TENANT_ROOT_ROLE_CLEANUP_COMMAND_MAX_BYTES_V1,
    TENANT_ROOT_SIGNED_CREATION_COMMITMENT_MAX_BYTES_V1,
    TENANT_ROOT_SIGNED_SHARE_INSTALLATION_EVIDENCE_MAX_BYTES_V1,
};
#[cfg(feature = "workers-rs")]
use router_ab_core::{
    TENANT_ROOT_ROLE_CREATION_COMMAND_MAX_BYTES_V1, TENANT_ROOT_ROLE_REFRESH_COMMAND_MAX_BYTES_V1,
};
#[cfg(feature = "workers-rs")]
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[cfg(all(test, feature = "workers-rs"))]
use crate::tenant_root_role_d1::CloudflareTenantRootPendingShareV1;
#[cfg(feature = "workers-rs")]
use crate::CloudflareWorkerEnvReaderV1;
use crate::{
    decode_base64url_bytes_v1, decode_role_verifying_keys, encode_base64url_bytes_v1,
    validate_tenant_root_creation_role_verifying_keys_against_peer_v1, RouterAbProtocolError,
    RouterAbProtocolErrorCode, RouterAbProtocolResult, TenantRootCreationRoleVerifyingKeysV1,
    TenantRootCutoverRecordUpdateV1, TenantRootCutoverRecordV1,
};

#[cfg_attr(not(feature = "workers-rs"), allow(dead_code))]
pub(crate) const CLOUDFLARE_TENANT_ROOT_CREATION_JOURNAL_PATH: &str =
    "/router-ab/internal/tenant-root/creation/v1/journal";
/// Reads the persisted Started journal, its issuer capability, and public
/// creation progress. Public evidence only: no scalar, share, or sealed
/// material is ever stored here, so nothing private can be returned.
#[cfg_attr(not(feature = "workers-rs"), allow(dead_code))]
pub(crate) const CLOUDFLARE_TENANT_ROOT_CREATION_JOURNAL_READ_PATH: &str =
    "/router-ab/internal/tenant-root/creation/v1/journal/read";
#[cfg_attr(not(feature = "workers-rs"), allow(dead_code))]
pub(crate) const CLOUDFLARE_TENANT_ROOT_CREATION_INITIAL_ACTIVATION_PATH: &str =
    "/router-ab/internal/tenant-root/creation/v1/initial-activation";
#[cfg_attr(not(feature = "workers-rs"), allow(dead_code))]
pub(crate) const CLOUDFLARE_TENANT_ROOT_REFRESH_ACTIVATION_PATH: &str =
    "/router-ab/internal/tenant-root/refresh/v1/activation";
#[cfg_attr(not(feature = "workers-rs"), allow(dead_code))]
pub(crate) const CLOUDFLARE_TENANT_ROOT_CREATION_ACTIVE_STATE_READ_PATH: &str =
    "/router-ab/internal/tenant-root/creation/v1/active-state";
#[cfg_attr(not(feature = "workers-rs"), allow(dead_code))]
pub(crate) const CLOUDFLARE_TENANT_ROOT_CREATION_COMMITMENT_RENDEZVOUS_PATH: &str =
    "/router-ab/internal/tenant-root/creation/v1/commitment-rendezvous";
#[cfg_attr(not(feature = "workers-rs"), allow(dead_code))]
pub(crate) const CLOUDFLARE_TENANT_ROOT_CREATION_INSTALLATION_CHECKPOINT_PATH: &str =
    "/router-ab/internal/tenant-root/creation/v1/installation-checkpoint";
#[cfg_attr(not(feature = "workers-rs"), allow(dead_code))]
pub(crate) const CLOUDFLARE_TENANT_ROOT_CREATION_CLEANUP_CHECKPOINT_PATH: &str =
    "/router-ab/internal/tenant-root/creation/v1/cleanup-checkpoint";
#[cfg_attr(not(feature = "workers-rs"), allow(dead_code))]
pub(crate) const TENANT_ROOT_CREATION_JOURNAL_STORAGE_KEY_V1: &str = "creation/v1/journal";
#[cfg_attr(not(feature = "workers-rs"), allow(dead_code))]
pub(crate) const TENANT_ROOT_CREATION_INSTALLATION_CHECKPOINT_STORAGE_KEY_V1: &str =
    "creation/v1/installation-checkpoint";
#[cfg_attr(not(feature = "workers-rs"), allow(dead_code))]
pub(crate) const TENANT_ROOT_CREATION_COMMITMENT_RENDEZVOUS_STORAGE_KEY_V1: &str =
    "creation/v1/commitment-rendezvous";
#[cfg_attr(not(feature = "workers-rs"), allow(dead_code))]
pub(crate) const TENANT_ROOT_CREATION_CLEANUP_CHECKPOINT_STORAGE_KEY_V1: &str =
    "creation/v1/cleanup-checkpoint";
#[cfg_attr(not(feature = "workers-rs"), allow(dead_code))]
pub(crate) const CLOUDFLARE_TENANT_ROOT_CUTOVER_READ_PATH: &str =
    "/router-ab/internal/tenant-root/cutover/v1/read";
#[cfg_attr(not(feature = "workers-rs"), allow(dead_code))]
pub(crate) const CLOUDFLARE_TENANT_ROOT_CUTOVER_WRITE_PATH: &str =
    "/router-ab/internal/tenant-root/cutover/v1/write";
#[cfg_attr(not(feature = "workers-rs"), allow(dead_code))]
pub(crate) const TENANT_ROOT_CUTOVER_STORAGE_KEY_V1: &str = "cutover/v1/state";
pub(crate) const TENANT_ROOT_CUTOVER_REQUEST_MAX_BYTES_V1: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CloudflareTenantRootCutoverReadRequestV1 {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum CloudflareTenantRootCutoverWriteRequestV1 {
    Initialize {
        record: TenantRootCutoverRecordV1,
    },
    Update {
        expected_revision: u64,
        record: TenantRootCutoverRecordV1,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CloudflareTenantRootCutoverWriteOutcomeV1 {
    Initialized,
    ExactReplay,
    Advanced,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CloudflareTenantRootCutoverWriteResponseV1 {
    outcome: CloudflareTenantRootCutoverWriteOutcomeV1,
    record: TenantRootCutoverRecordV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum CloudflareTenantRootCutoverReadResponseV1 {
    Empty,
    Present { record: TenantRootCutoverRecordV1 },
}

#[cfg_attr(not(feature = "workers-rs"), allow(dead_code))]
pub(crate) const CLOUDFLARE_TENANT_ROOT_REFRESH_COMMITMENT_CHECKPOINT_PATH: &str =
    "/router-ab/internal/tenant-root/refresh/v1/commitment-checkpoint";
#[cfg_attr(not(feature = "workers-rs"), allow(dead_code))]
pub(crate) const CLOUDFLARE_TENANT_ROOT_REFRESH_INSTALLATION_CHECKPOINT_PATH: &str =
    "/router-ab/internal/tenant-root/refresh/v1/installation-checkpoint";
#[cfg_attr(not(feature = "workers-rs"), allow(dead_code))]
pub(crate) const CLOUDFLARE_TENANT_ROOT_REFRESH_CONTRIBUTION_RENDEZVOUS_PATH: &str =
    "/router-ab/internal/tenant-root/refresh/v1/contribution-rendezvous";
#[cfg_attr(not(feature = "workers-rs"), allow(dead_code))]
pub(crate) const TENANT_ROOT_REFRESH_ACTIVE_STATE_STORAGE_KEY_V1: &str = "refresh/v1/active-state";
#[cfg_attr(not(feature = "workers-rs"), allow(dead_code))]
pub(crate) const TENANT_ROOT_REFRESH_COMMITMENT_CHECKPOINT_STORAGE_KEY_V1: &str =
    "refresh/v1/commitment-checkpoint";
#[cfg_attr(not(feature = "workers-rs"), allow(dead_code))]
pub(crate) const TENANT_ROOT_REFRESH_INSTALLATION_CHECKPOINT_STORAGE_KEY_V1: &str =
    "refresh/v1/installation-checkpoint";
#[cfg_attr(not(feature = "workers-rs"), allow(dead_code))]
pub(crate) const TENANT_ROOT_REFRESH_CONTRIBUTION_RENDEZVOUS_STORAGE_KEY_V1: &str =
    "refresh/v1/contribution-rendezvous";

#[allow(dead_code)]
const TENANT_ROOT_CREATION_OBJECT_NAME_DOMAIN_V1: &[u8] =
    b"seams/tenant-root-creation-object-name/v1";
#[allow(dead_code)]
const TENANT_ROOT_CREATION_OBJECT_NAME_PREFIX_V1: &str = "tenant-root-creation-v1";
const TENANT_ROOT_CREATION_JOURNAL_MAX_BASE64URL_BYTES_V1: usize =
    base64url_len_for_bytes(TENANT_ROOT_CREATION_JOURNAL_MAX_BYTES_V1);
const TENANT_ROOT_CREATION_CAPABILITY_MAX_BASE64URL_BYTES_V1: usize =
    base64url_len_for_bytes(TENANT_ROOT_CREATION_CAPABILITY_MAX_BYTES_V1);
const TENANT_ROOT_CREATION_INSTALLATION_EVIDENCE_MAX_BASE64URL_BYTES_V1: usize =
    base64url_len_for_bytes(TENANT_ROOT_SIGNED_SHARE_INSTALLATION_EVIDENCE_MAX_BYTES_V1);
const TENANT_ROOT_CREATION_COMMITMENT_MAX_BASE64URL_BYTES_V1: usize =
    base64url_len_for_bytes(TENANT_ROOT_SIGNED_CREATION_COMMITMENT_MAX_BYTES_V1);
const TENANT_ROOT_REFRESH_COMMITMENT_MAX_BYTES_V1: usize = 4 * 1024;
const TENANT_ROOT_REFRESH_COMMITMENT_MAX_BASE64URL_BYTES_V1: usize =
    base64url_len_for_bytes(TENANT_ROOT_REFRESH_COMMITMENT_MAX_BYTES_V1);
const TENANT_ROOT_REFRESH_CONTRIBUTION_MAX_BYTES_V1: usize = 4 * 1024;
const TENANT_ROOT_REFRESH_CONTRIBUTION_MAX_BASE64URL_BYTES_V1: usize =
    base64url_len_for_bytes(TENANT_ROOT_REFRESH_CONTRIBUTION_MAX_BYTES_V1);
const TENANT_ROOT_REFRESH_CHECKPOINT_MAX_BASE64URL_BYTES_V1: usize =
    base64url_len_for_bytes(TENANT_ROOT_REFRESH_COMMITMENT_CHECKPOINT_MAX_BYTES_V1);
#[cfg(feature = "workers-rs")]
const TENANT_ROOT_ROLE_CREATION_COMMAND_MAX_BASE64URL_BYTES_V1: usize =
    base64url_len_for_bytes(TENANT_ROOT_ROLE_CREATION_COMMAND_MAX_BYTES_V1);
#[cfg(feature = "workers-rs")]
const TENANT_ROOT_ROLE_REFRESH_COMMAND_MAX_BASE64URL_BYTES_V1: usize =
    base64url_len_for_bytes(TENANT_ROOT_ROLE_REFRESH_COMMAND_MAX_BYTES_V1);
const TENANT_ROOT_ROLE_CLEANUP_COMMAND_MAX_BASE64URL_BYTES_V1: usize =
    base64url_len_for_bytes(TENANT_ROOT_ROLE_CLEANUP_COMMAND_MAX_BYTES_V1);
const TENANT_ROOT_COMMAND_TERMINAL_RECEIPT_MAX_BASE64URL_BYTES_V1: usize =
    base64url_len_for_bytes(TENANT_ROOT_COMMAND_TERMINAL_RECEIPT_MAX_BYTES_V1);
const TENANT_ROOT_REFRESH_ACTIVE_RECEIPT_MAX_BYTES_V1: usize = 16 * 1024;
const TENANT_ROOT_REFRESH_ACTIVE_RECEIPT_MAX_BASE64URL_BYTES_V1: usize =
    base64url_len_for_bytes(TENANT_ROOT_REFRESH_ACTIVE_RECEIPT_MAX_BYTES_V1);
const TENANT_ROOT_REFRESH_ATTEMPT_CONTEXT_MAX_BYTES_V1: usize = 8 * 1024;
const TENANT_ROOT_REFRESH_ATTEMPT_COMMAND_MAX_BYTES_V1: usize = 16 * 1024;
const TENANT_ROOT_MANAGED_RESTORE_INCIDENT_MAX_BYTES_V1: usize = 256;
const TENANT_ROOT_MANAGED_RESTORE_NONCE_BYTES_V1: usize = 32;
const TENANT_ROOT_MANAGED_RESTORE_INCIDENT_AUTHORIZATION_MAX_BASE64URL_BYTES_V1: usize =
    base64url_len_for_bytes(TENANT_ROOT_MANAGED_RESTORE_INCIDENT_AUTHORIZATION_MAX_BYTES_V1);
const TENANT_ROOT_MANAGED_RESTORE_IDENTITY_MAX_BYTES_V1: usize = 8 * 1024;
#[cfg(feature = "workers-rs")]
const TENANT_ROOT_MANAGED_RESTORE_IDENTITY_MAX_BASE64URL_BYTES_V1: usize =
    base64url_len_for_bytes(TENANT_ROOT_MANAGED_RESTORE_IDENTITY_MAX_BYTES_V1);
#[cfg(feature = "workers-rs")]
const TENANT_ROOT_MANAGED_RESTORE_ARTIFACT_MAX_BYTES_V1: usize = 48 * 1024;
const TENANT_ROOT_MANAGED_RESTORE_CAPABILITY_MAX_BASE64URL_BYTES_V1: usize =
    base64url_len_for_bytes(TENANT_ROOT_MANAGED_RESTORE_CAPABILITY_MAX_BYTES_V1);
const TENANT_ROOT_MANAGED_RESTORE_PUBLIC_STATE_MAX_BASE64URL_BYTES_V1: usize =
    base64url_len_for_bytes(TENANT_ROOT_MANAGED_RESTORE_PUBLIC_STATE_MAX_BYTES);
#[cfg(feature = "workers-rs")]
const TENANT_ROOT_MANAGED_RESTORE_ARTIFACT_MAX_BASE64URL_BYTES_V1: usize =
    base64url_len_for_bytes(TENANT_ROOT_MANAGED_RESTORE_ARTIFACT_MAX_BYTES_V1);
const TENANT_ROOT_MANAGED_RESTORE_CHALLENGE_DOMAIN_V1: &[u8] =
    b"tenant_root_managed_restore_authorization_challenge_v1";
const TENANT_ROOT_MANAGED_RESTORE_ATTEMPT_DOMAIN_V1: &[u8] =
    b"tenant_root_managed_restore_authorization_attempt_v1";
#[cfg(feature = "workers-rs")]
const ROUTER_TENANT_ROOT_CREATION_DO_BINDING_V1: &str = "ROUTER_TENANT_ROOT_CREATION_DO";
#[cfg(feature = "workers-rs")]
const TENANT_ROOT_CUTOVER_OBJECT_NAME_V1: &str = "tenant-root-cutover-v1";
#[cfg(feature = "workers-rs")]
const TENANT_ROOT_CREATION_REQUEST_MAX_BYTES_V1: usize =
    TENANT_ROOT_CREATION_JOURNAL_MAX_BASE64URL_BYTES_V1
        + TENANT_ROOT_CREATION_CAPABILITY_MAX_BASE64URL_BYTES_V1
        + 128;
#[cfg(feature = "workers-rs")]
const TENANT_ROOT_CREATION_INITIAL_ACTIVATION_REQUEST_MAX_BYTES_V1: usize =
    TENANT_ROOT_REFRESH_ACTIVE_RECEIPT_MAX_BASE64URL_BYTES_V1 + 128;
#[cfg(feature = "workers-rs")]
const TENANT_ROOT_CREATION_INITIAL_ACTIVATION_RESPONSE_MAX_BYTES_V1: usize = 1024;
#[cfg(feature = "workers-rs")]
const TENANT_ROOT_REFRESH_ACTIVATION_RESPONSE_MAX_BYTES_V1: usize = 1024;
#[cfg(feature = "workers-rs")]
const TENANT_ROOT_CREATION_ACTIVE_STATE_READ_REQUEST_MAX_BYTES_V1: usize =
    TENANT_ROOT_MANAGED_RESTORE_ACTIVE_STATE_REQUEST_MAX_BYTES_V1;
#[cfg(feature = "workers-rs")]
const TENANT_ROOT_CREATION_ACTIVE_STATE_READ_RESPONSE_MAX_BYTES_V1: usize =
    TENANT_ROOT_REFRESH_ACTIVE_RECEIPT_MAX_BASE64URL_BYTES_V1
        + TENANT_ROOT_ROLE_REFRESH_COMMAND_MAX_BASE64URL_BYTES_V1 * 2
        + 8 * 1024
        + TENANT_ROOT_MANAGED_RESTORE_ARTIFACT_MAX_BASE64URL_BYTES_V1 * 2
        + TENANT_ROOT_MANAGED_RESTORE_INCIDENT_AUTHORIZATION_MAX_BASE64URL_BYTES_V1
        + TENANT_ROOT_MANAGED_RESTORE_IDENTITY_MAX_BASE64URL_BYTES_V1
        + 16 * 1024
        + 1024;
#[cfg(feature = "workers-rs")]
const TENANT_ROOT_MANAGED_RESTORE_ACTIVE_STATE_REQUEST_MAX_BYTES_V1: usize =
    TENANT_ROOT_MANAGED_RESTORE_ARTIFACT_MAX_BASE64URL_BYTES_V1 * 2
        + TENANT_ROOT_MANAGED_RESTORE_INCIDENT_AUTHORIZATION_MAX_BASE64URL_BYTES_V1
        + TENANT_ROOT_MANAGED_RESTORE_IDENTITY_MAX_BASE64URL_BYTES_V1 * 2
        + TENANT_ROOT_REFRESH_ACTIVE_RECEIPT_MAX_BASE64URL_BYTES_V1 * 2
        + 16 * 1024;
#[cfg(feature = "workers-rs")]
const TENANT_ROOT_CREATION_COMMITMENT_REQUEST_MAX_BYTES_V1: usize =
    TENANT_ROOT_ROLE_CREATION_COMMAND_MAX_BASE64URL_BYTES_V1
        + TENANT_ROOT_CREATION_COMMITMENT_MAX_BASE64URL_BYTES_V1
        + 128;
#[cfg(feature = "workers-rs")]
const TENANT_ROOT_CREATION_INSTALLATION_REQUEST_MAX_BYTES_V1: usize =
    TENANT_ROOT_ROLE_CREATION_COMMAND_MAX_BASE64URL_BYTES_V1
        + TENANT_ROOT_CREATION_INSTALLATION_EVIDENCE_MAX_BASE64URL_BYTES_V1
        + 128;
#[cfg(feature = "workers-rs")]
const TENANT_ROOT_CREATION_CLEANUP_REQUEST_MAX_BYTES_V1: usize =
    TENANT_ROOT_ROLE_CLEANUP_COMMAND_MAX_BASE64URL_BYTES_V1
        + TENANT_ROOT_COMMAND_TERMINAL_RECEIPT_MAX_BASE64URL_BYTES_V1
        + 128;
#[cfg(feature = "workers-rs")]
const TENANT_ROOT_CREATION_CLEANUP_RESPONSE_MAX_BYTES_V1: usize = 1024;
#[cfg(feature = "workers-rs")]
#[allow(dead_code)]
const TENANT_ROOT_CREATION_COMMITMENT_RESPONSE_MAX_BYTES_V1: usize =
    TENANT_ROOT_CREATION_COMMITMENT_MAX_BASE64URL_BYTES_V1 * 2 + 512;
#[cfg(feature = "workers-rs")]
#[allow(dead_code)]
const TENANT_ROOT_CREATION_INSTALLATION_RESPONSE_MAX_BYTES_V1: usize =
    TENANT_ROOT_CREATION_INSTALLATION_EVIDENCE_MAX_BASE64URL_BYTES_V1 * 2 + 512;
#[cfg(feature = "workers-rs")]
const TENANT_ROOT_REFRESH_COMMITMENT_REQUEST_MAX_BYTES_V1: usize =
    TENANT_ROOT_ROLE_REFRESH_COMMAND_MAX_BASE64URL_BYTES_V1
        + TENANT_ROOT_REFRESH_COMMITMENT_MAX_BASE64URL_BYTES_V1
        + 128;
#[cfg(feature = "workers-rs")]
const TENANT_ROOT_REFRESH_INSTALLATION_REQUEST_MAX_BYTES_V1: usize =
    TENANT_ROOT_ROLE_REFRESH_COMMAND_MAX_BASE64URL_BYTES_V1
        + TENANT_ROOT_CREATION_INSTALLATION_EVIDENCE_MAX_BASE64URL_BYTES_V1
        + TENANT_ROOT_COMMAND_TERMINAL_RECEIPT_MAX_BASE64URL_BYTES_V1
        + 128;
#[cfg(feature = "workers-rs")]
const TENANT_ROOT_REFRESH_CONTRIBUTION_REQUEST_MAX_BYTES_V1: usize =
    TENANT_ROOT_ROLE_REFRESH_COMMAND_MAX_BASE64URL_BYTES_V1
        + TENANT_ROOT_REFRESH_CONTRIBUTION_MAX_BASE64URL_BYTES_V1
        + 128;
#[cfg(feature = "workers-rs")]
const TENANT_ROOT_REFRESH_COMMITMENT_RESPONSE_MAX_BYTES_V1: usize =
    TENANT_ROOT_REFRESH_COMMITMENT_MAX_BASE64URL_BYTES_V1 * 2 + 2048;
#[cfg(feature = "workers-rs")]
const TENANT_ROOT_REFRESH_INSTALLATION_RESPONSE_MAX_BYTES_V1: usize = 4096;
#[cfg(feature = "workers-rs")]
const TENANT_ROOT_REFRESH_CONTRIBUTION_RESPONSE_MAX_BYTES_V1: usize =
    TENANT_ROOT_REFRESH_CONTRIBUTION_MAX_BASE64URL_BYTES_V1 * 2 + 2048;

#[allow(dead_code)]
pub(crate) fn tenant_root_creation_object_name_v1(
    identity_digest: TenantRootIdentityDigestV1,
    custody_lineage: TenantRootCustodyLineageId,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(TENANT_ROOT_CREATION_OBJECT_NAME_DOMAIN_V1);
    hasher.update(identity_digest.as_bytes());
    hasher.update(custody_lineage.as_bytes());
    format!(
        "{TENANT_ROOT_CREATION_OBJECT_NAME_PREFIX_V1}-{}",
        encode_base64url_bytes_v1(&hasher.finalize())
    )
}

#[cfg(feature = "workers-rs")]
struct LoadedTenantRootRefreshRequestV1 {
    active: ValidatedTenantRootRefreshActiveStateV1,
    context: TenantRootCeremonyContextV1,
    command: VerifiedTenantRootRoleRefreshCommandV1,
    candidate_bytes: Vec<u8>,
    role_keys: TenantRootCreationRoleVerifyingKeysV1,
    issuer_keys: BTreeMap<String, [u8; 32]>,
    now_ms: u64,
}

#[cfg(feature = "workers-rs")]
struct LoadedTenantRootRefreshInstallationRequestV1 {
    active: ValidatedTenantRootRefreshActiveStateV1,
    context: TenantRootCeremonyContextV1,
    command: VerifiedTenantRootRoleRefreshCommandV1,
    candidate_bytes: Vec<u8>,
    terminal_receipt: VerifiedTenantRootRefreshInstallationReceiptV1,
    role_keys: TenantRootCreationRoleVerifyingKeysV1,
    issuer_keys: BTreeMap<String, [u8; 32]>,
    now_ms: u64,
}

struct VerifiedTenantRootRefreshInstallationReceiptV1 {
    receipt: TenantRootCommandSuccessReceiptV1,
}

impl VerifiedTenantRootRefreshInstallationReceiptV1 {
    fn new(
        receipt: TenantRootCommandSuccessReceiptV1,
        candidate_bytes: &[u8],
        command: &VerifiedTenantRootRoleRefreshCommandV1,
        context: &TenantRootCeremonyContextV1,
        role_keys: &TenantRootCreationRoleVerifyingKeysV1,
    ) -> RouterAbProtocolResult<Self> {
        let trusted_role_key = role_keys
            .for_role_and_key_id(command.role(), context.signing_key_id(command.role()))?;
        receipt
            .verify_remote_public(
                command.scope().key(),
                candidate_bytes,
                command.issued_at_ms(),
                context.signing_key_id(command.role()),
                trusted_role_key,
            )
            .map_err(candidate_derivation_error)?;
        Ok(Self { receipt })
    }

    fn require_matches(
        &self,
        candidate_bytes: &[u8],
        command: &VerifiedTenantRootRoleRefreshCommandV1,
        context: &TenantRootCeremonyContextV1,
    ) -> RouterAbProtocolResult<()> {
        if self.receipt.key() != command.scope().key()
            || self.receipt.payload_bytes() != candidate_bytes
            || self.receipt.role_signing_key_id() != context.signing_key_id(command.role())
            || self.receipt.terminal_at_ms() < command.issued_at_ms()
        {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ForbiddenLocalBinding,
                "tenant-root refresh terminal receipt does not match its command and evidence",
            ));
        }
        Ok(())
    }
}

#[cfg(feature = "workers-rs")]
struct LoadedTenantRootRefreshContributionRequestV1 {
    active: ValidatedTenantRootRefreshActiveStateV1,
    context: TenantRootCeremonyContextV1,
    command: VerifiedTenantRootRoleRefreshCommandV1,
    candidate_bytes: Vec<u8>,
    role_keys: TenantRootCreationRoleVerifyingKeysV1,
    issuer_keys: BTreeMap<String, [u8; 32]>,
    now_ms: u64,
}

/// Fails closed unless `encoded` is exactly the base64url of `expected`.
pub(crate) fn require_base64url_matches(
    field: &str,
    encoded: &str,
    expected: &[u8],
) -> RouterAbProtocolResult<()> {
    let decoded = decode_canonical_base64url(field, encoded, expected.len(), encoded.len().max(4))?;
    if decoded.as_slice() != expected {
        return Err(malformed_input(format!(
            "{field} does not match the persisted tenant-root creation value"
        )));
    }
    Ok(())
}

fn authority_id_from_object_id(
    authority_object_id: &str,
) -> RouterAbProtocolResult<TenantRootControlPlaneAuthorityIdV1> {
    Ok(TenantRootControlPlaneAuthorityIdV1::from_bytes(
        decode_lower_hex_32(
            "tenant-root creation Durable Object id",
            authority_object_id,
        )?,
    ))
}

#[cfg(feature = "workers-rs")]
fn validate_refresh_role_command(
    encoded: &str,
    active: &ValidatedTenantRootRefreshActiveStateV1,
    context: &TenantRootCeremonyContextV1,
    expected_role: TwoPartyDeriverRole,
    expected_authority_id: TenantRootControlPlaneAuthorityIdV1,
    issuer_keys: &BTreeMap<String, [u8; 32]>,
) -> RouterAbProtocolResult<VerifiedTenantRootRoleRefreshCommandV1> {
    let bytes = decode_canonical_base64url(
        "tenant-root role refresh command",
        encoded,
        TENANT_ROOT_ROLE_REFRESH_COMMAND_MAX_BYTES_V1,
        TENANT_ROOT_ROLE_REFRESH_COMMAND_MAX_BASE64URL_BYTES_V1,
    )?;
    let command = decode_and_verify_refresh_role_command(
        &bytes,
        active,
        context,
        issuer_keys,
        expected_authority_id,
    )?;
    if command.role() != expected_role {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ForbiddenLocalBinding,
            "tenant-root refresh command role does not match its signed payload",
        ));
    }
    Ok(command)
}

#[cfg(feature = "workers-rs")]
fn decode_and_verify_refresh_role_command(
    bytes: &[u8],
    active: &ValidatedTenantRootRefreshActiveStateV1,
    context: &TenantRootCeremonyContextV1,
    issuer_keys: &BTreeMap<String, [u8; 32]>,
    expected_authority_id: TenantRootControlPlaneAuthorityIdV1,
) -> RouterAbProtocolResult<VerifiedTenantRootRoleRefreshCommandV1> {
    let command = TenantRootRoleRefreshCommandV1::decode_canonical_bytes(bytes)
        .map_err(candidate_derivation_error)?;
    let issuer_key_id = command.issuer_key_id();
    let verifying_key = issuer_keys.get(issuer_key_id).ok_or_else(|| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ForbiddenLocalBinding,
            "tenant-root refresh command issuer is not trusted",
        )
    })?;
    command
        .verify(
            &active.active_pair,
            context,
            command.role(),
            active.record.lifecycle_revision,
            expected_authority_id,
            issuer_key_id,
            verifying_key,
        )
        .map_err(candidate_authorization_error)
}

struct RefreshResponseScopeV1 {
    command_digest_b64u: String,
    identity_digest_b64u: String,
    custody_lineage_b64u: String,
    authority_id_b64u: String,
    ceremony_context_digest_b64u: String,
    current_epoch: u64,
    next_epoch: u64,
    expected_control_plane_revision: u64,
    active_root_commitment_b64u: String,
    active_activation_receipt_digest_b64u: String,
}

fn refresh_response_scope(
    command: &VerifiedTenantRootRoleRefreshCommandV1,
    active: &ValidatedTenantRootRefreshActiveStateV1,
    context: &TenantRootCeremonyContextV1,
) -> RouterAbProtocolResult<RefreshResponseScopeV1> {
    let scope = refresh_checkpoint_scope(command, active, context, command.authority_id())?;
    Ok(RefreshResponseScopeV1 {
        command_digest_b64u: encode_base64url_bytes_v1(command.digest().as_bytes()),
        identity_digest_b64u: scope.identity_digest_b64u,
        custody_lineage_b64u: scope.custody_lineage_b64u,
        authority_id_b64u: scope.authority_id_b64u,
        ceremony_context_digest_b64u: scope.ceremony_context_digest_b64u,
        current_epoch: scope.current_epoch,
        next_epoch: scope.next_epoch,
        expected_control_plane_revision: scope.expected_control_plane_revision,
        active_root_commitment_b64u: scope.active_root_commitment_b64u,
        active_activation_receipt_digest_b64u: scope.active_activation_receipt_digest_b64u,
    })
}

fn refresh_commitment_response(
    scope: RefreshResponseScopeV1,
    outcome: CloudflareTenantRootRefreshCommitmentResponseOutcomeV1,
) -> RouterAbProtocolResult<CloudflareTenantRootRefreshCommitmentResponseV1> {
    Ok(CloudflareTenantRootRefreshCommitmentResponseV1 {
        outcome,
        command_digest_b64u: scope.command_digest_b64u,
        identity_digest_b64u: scope.identity_digest_b64u,
        custody_lineage_b64u: scope.custody_lineage_b64u,
        authority_id_b64u: scope.authority_id_b64u,
        ceremony_context_digest_b64u: scope.ceremony_context_digest_b64u,
        current_epoch: scope.current_epoch,
        next_epoch: scope.next_epoch,
        expected_control_plane_revision: scope.expected_control_plane_revision,
        active_root_commitment_b64u: scope.active_root_commitment_b64u,
        active_activation_receipt_digest_b64u: scope.active_activation_receipt_digest_b64u,
    })
}

fn refresh_installation_response(
    scope: RefreshResponseScopeV1,
    outcome: CloudflareTenantRootRefreshInstallationResponseOutcomeV1,
) -> RouterAbProtocolResult<CloudflareTenantRootRefreshInstallationResponseV1> {
    Ok(CloudflareTenantRootRefreshInstallationResponseV1 {
        outcome,
        command_digest_b64u: scope.command_digest_b64u,
        identity_digest_b64u: scope.identity_digest_b64u,
        custody_lineage_b64u: scope.custody_lineage_b64u,
        authority_id_b64u: scope.authority_id_b64u,
        ceremony_context_digest_b64u: scope.ceremony_context_digest_b64u,
        current_epoch: scope.current_epoch,
        next_epoch: scope.next_epoch,
        expected_control_plane_revision: scope.expected_control_plane_revision,
        active_root_commitment_b64u: scope.active_root_commitment_b64u,
        active_activation_receipt_digest_b64u: scope.active_activation_receipt_digest_b64u,
    })
}

fn refresh_contribution_response(
    scope: RefreshResponseScopeV1,
    outcome: CloudflareTenantRootRefreshContributionResponseOutcomeV1,
) -> RouterAbProtocolResult<CloudflareTenantRootRefreshContributionResponseV1> {
    Ok(CloudflareTenantRootRefreshContributionResponseV1 {
        outcome,
        command_digest_b64u: scope.command_digest_b64u,
        identity_digest_b64u: scope.identity_digest_b64u,
        custody_lineage_b64u: scope.custody_lineage_b64u,
        authority_id_b64u: scope.authority_id_b64u,
        ceremony_context_digest_b64u: scope.ceremony_context_digest_b64u,
        current_epoch: scope.current_epoch,
        next_epoch: scope.next_epoch,
        expected_control_plane_revision: scope.expected_control_plane_revision,
        active_root_commitment_b64u: scope.active_root_commitment_b64u,
        active_activation_receipt_digest_b64u: scope.active_activation_receipt_digest_b64u,
    })
}

#[allow(dead_code)]
fn validate_tenant_root_creation_object_binding_v1(
    object_id: &str,
    expected_authority_id: TenantRootControlPlaneAuthorityIdV1,
) -> RouterAbProtocolResult<()> {
    let derived_authority_id = TenantRootControlPlaneAuthorityIdV1::from_bytes(
        decode_lower_hex_32("tenant-root creation Durable Object id", object_id)?,
    );
    if derived_authority_id != expected_authority_id {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ForbiddenLocalBinding,
            "tenant-root creation capability authority does not match the derived Durable Object id",
        ));
    }
    Ok(())
}

#[cfg(feature = "workers-rs")]
pub(crate) fn derive_tenant_root_creation_authority_object_v1(
    env: &worker::Env,
    identity_digest: TenantRootIdentityDigestV1,
    custody_lineage: TenantRootCustodyLineageId,
) -> RouterAbProtocolResult<(TenantRootControlPlaneAuthorityIdV1, String)> {
    let namespace = env
        .durable_object(ROUTER_TENANT_ROOT_CREATION_DO_BINDING_V1)
        .map_err(|error| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MissingLocalBinding,
                format!("tenant-root creation Durable Object binding is unavailable: {error}"),
            )
        })?;
    let object_name = tenant_root_creation_object_name_v1(identity_digest, custody_lineage);
    let object_id = namespace
        .id_from_name(&object_name)
        .map_err(|error| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                format!("tenant-root creation Durable Object id derivation failed: {error}"),
            )
        })?
        .to_string();
    let authority_id = TenantRootControlPlaneAuthorityIdV1::from_bytes(decode_lower_hex_32(
        "tenant-root creation Durable Object id",
        &object_id,
    )?);
    Ok((authority_id, object_name))
}

#[cfg(feature = "workers-rs")]
fn require_tenant_root_creation_authority_object_v1(
    env: &worker::Env,
    authority_object_id: &str,
    identity_digest: TenantRootIdentityDigestV1,
    custody_lineage: TenantRootCustodyLineageId,
) -> RouterAbProtocolResult<()> {
    let (expected_authority_id, _) =
        derive_tenant_root_creation_authority_object_v1(env, identity_digest, custody_lineage)?;
    let authority_id = TenantRootControlPlaneAuthorityIdV1::from_bytes(decode_lower_hex_32(
        "tenant-root creation Durable Object id",
        authority_object_id,
    )?);
    if expected_authority_id != authority_id {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ForbiddenLocalBinding,
            "tenant-root creation command reached a non-authoritative Durable Object",
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CloudflareTenantRootCreationJournalRequestV1 {
    pub(crate) journal_b64u: String,
    pub(crate) creation_capability_b64u: String,
}

impl CloudflareTenantRootCreationJournalRequestV1 {
    #[cfg_attr(not(feature = "workers-rs"), allow(dead_code))]
    fn into_record(self) -> CloudflareTenantRootCreationJournalRecordV1 {
        CloudflareTenantRootCreationJournalRecordV1 {
            journal_b64u: self.journal_b64u,
            creation_capability_b64u: self.creation_capability_b64u,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CloudflareTenantRootCreationJournalRecordV1 {
    pub(crate) journal_b64u: String,
    pub(crate) creation_capability_b64u: String,
}

#[cfg_attr(not(feature = "workers-rs"), allow(dead_code))]
pub(crate) struct ValidatedTenantRootCreationJournalV1 {
    pub(crate) record: CloudflareTenantRootCreationJournalRecordV1,
    pub(crate) journal: TenantRootCreationJournalV1,
    pub(crate) identity_digest: TenantRootIdentityDigestV1,
    pub(crate) custody_lineage: router_ab_core::TenantRootCustodyLineageId,
    pub(crate) ceremony_context: TenantRootCeremonyContextV1,
    pub(crate) revision: u64,
    pub(crate) journal_digest: TenantRootProtocolDigestV1,
    pub(crate) capability: VerifiedTenantRootCreationCapabilityV1,
}

impl ValidatedTenantRootCreationJournalV1 {
    fn response(
        &self,
        outcome: CloudflareTenantRootCreationJournalOutcomeV1,
    ) -> CloudflareTenantRootCreationJournalResponseV1 {
        CloudflareTenantRootCreationJournalResponseV1 {
            outcome,
            revision: self.revision,
            journal_digest_b64u: encode_base64url_bytes_v1(self.journal_digest.as_bytes()),
            capability_digest_b64u: encode_base64url_bytes_v1(self.capability.digest().as_bytes()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CloudflareTenantRootCreationJournalOutcomeV1 {
    Committed,
    Replay,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CloudflareTenantRootCreationJournalResponseV1 {
    pub(crate) outcome: CloudflareTenantRootCreationJournalOutcomeV1,
    pub(crate) revision: u64,
    pub(crate) journal_digest_b64u: String,
    pub(crate) capability_digest_b64u: String,
}

/// Asks the Durable Object for its persisted creation state.
///
/// Identity and lineage are carried so the object can fail closed if a caller
/// reached the wrong object: the stored journal must name exactly this pair.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CloudflareTenantRootCreationJournalReadRequestV1 {
    pub(crate) identity_digest_b64u: String,
    pub(crate) custody_lineage_b64u: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CloudflareTenantRootCreationInitialActivationRequestV1 {
    pub(crate) activation_receipt_b64u: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CloudflareTenantRootCreationInitialActivationResponseV1 {
    pub(crate) activation_receipt_digest_b64u: String,
    pub(crate) lifecycle_revision: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CloudflareTenantRootRefreshActivationRequestV1 {
    pub(crate) activation_receipt_b64u: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CloudflareTenantRootRefreshActivationResponseV1 {
    pub(crate) activation_receipt_digest_b64u: String,
    pub(crate) lifecycle_revision: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum CloudflareTenantRootCreationActiveStateReadRequestV1 {
    Read {
        identity_digest_b64u: String,
        custody_lineage_b64u: String,
    },
    ReserveRefresh {
        identity_digest_b64u: String,
        custody_lineage_b64u: String,
        refresh_context_b64u: String,
        deriver_a_refresh_command_b64u: String,
        deriver_b_refresh_command_b64u: String,
    },
    ReserveManagedRestore {
        identity_digest_b64u: String,
        custody_lineage_b64u: String,
        authorization: CloudflareTenantRootManagedRestoreAuthorizationRequestV1,
    },
    CheckpointManagedRestore {
        identity_digest_b64u: String,
        custody_lineage_b64u: String,
        checkpoint: CloudflareTenantRootManagedRestoreAuthorizationCheckpointV1,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CloudflareTenantRootCreationActiveStateReadResponseV1 {
    pub(crate) activation_receipt_b64u: String,
    pub(crate) activation_receipt_digest_b64u: String,
    pub(crate) identity_digest_b64u: String,
    pub(crate) custody_lineage_b64u: String,
    pub(crate) lifecycle_revision: u64,
    pub(crate) fence: CloudflareTenantRootRefreshFenceV1,
    pub(crate) managed_restore_fence: CloudflareTenantRootManagedRestoreFenceV1,
}

/// Public installation progress from one fully validated checkpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum CloudflareTenantRootCreationInstallationCheckpointReadStateV1 {
    None,
    OneRoleReady {
        role: CloudflareTenantRootCreationInstallationRoleV1,
        signed_evidence_b64u: String,
    },
    BothRolesReady {
        root_commitment_b64u: String,
    },
}

/// Persisted creation state, public evidence only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CloudflareTenantRootCreationJournalReadResponseV1 {
    /// Exact canonical Started journal bytes as persisted.
    pub(crate) journal_b64u: String,
    /// Exact canonical issuer capability bytes as persisted.
    pub(crate) creation_capability_b64u: String,
    /// Control-plane revision the Started journal authenticates.
    pub(crate) revision: u64,
    /// Roles whose signed public commitment has already reached this object.
    pub(crate) committed_roles: Vec<CloudflareTenantRootCreationInstallationRoleV1>,
    /// Validated public installation checkpoint, when one exists.
    pub(crate) installation_checkpoint:
        CloudflareTenantRootCreationInstallationCheckpointReadStateV1,
    /// Whether the sole installed role was removed and this ceremony was abandoned.
    pub(crate) cleanup_checkpointed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CloudflareTenantRootCreationCommitmentRequestV1 {
    pub(crate) role_creation_command_b64u: String,
    pub(crate) signed_commitment_b64u: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CloudflareTenantRootCreationInstallationRequestV1 {
    pub(crate) role_creation_command_b64u: String,
    pub(crate) signed_evidence_b64u: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CloudflareTenantRootCreationCleanupRequestV1 {
    pub(crate) cleanup_command_b64u: String,
    pub(crate) cleanup_receipt_b64u: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CloudflareTenantRootCreationCleanupOutcomeV1 {
    Committed,
    Replay,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CloudflareTenantRootCreationCleanupResponseV1 {
    pub(crate) outcome: CloudflareTenantRootCreationCleanupOutcomeV1,
    pub(crate) role: CloudflareTenantRootCreationInstallationRoleV1,
    pub(crate) cleanup_receipt_digest_b64u: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum CloudflareTenantRootCreationCommitmentResponseOutcomeV1 {
    WaitingForPeer {
        role: CloudflareTenantRootCreationInstallationRoleV1,
        signed_commitment_b64u: String,
    },
    BothRolesCommitted {
        deriver_a_signed_commitment_b64u: String,
        deriver_b_signed_commitment_b64u: String,
        pair_digest_b64u: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CloudflareTenantRootCreationCommitmentResponseV1 {
    pub(crate) outcome: CloudflareTenantRootCreationCommitmentResponseOutcomeV1,
    pub(crate) command_digest_b64u: String,
    pub(crate) journal_digest_b64u: String,
    pub(crate) identity_digest_b64u: String,
    pub(crate) custody_lineage_b64u: String,
    pub(crate) ceremony_context_digest_b64u: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum CloudflareTenantRootCreationInstallationResponseOutcomeV1 {
    WaitingForPeer {
        role: CloudflareTenantRootCreationInstallationRoleV1,
    },
    BothRolesReady {
        root_commitment_b64u: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CloudflareTenantRootCreationInstallationResponseV1 {
    pub(crate) outcome: CloudflareTenantRootCreationInstallationResponseOutcomeV1,
    pub(crate) command_digest_b64u: String,
    pub(crate) journal_digest_b64u: String,
    pub(crate) identity_digest_b64u: String,
    pub(crate) custody_lineage_b64u: String,
    pub(crate) ceremony_context_digest_b64u: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CloudflareTenantRootRefreshCommitmentRequestV1 {
    pub(crate) role_refresh_command_b64u: String,
    pub(crate) signed_commitment_b64u: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CloudflareTenantRootRefreshInstallationRequestV1 {
    pub(crate) role_refresh_command_b64u: String,
    pub(crate) signed_evidence_b64u: String,
    pub(crate) terminal_receipt_b64u: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CloudflareTenantRootRefreshContributionRequestV1 {
    pub(crate) role_refresh_command_b64u: String,
    pub(crate) signed_contribution_b64u: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum CloudflareTenantRootRefreshCommitmentResponseOutcomeV1 {
    WaitingForPeer {
        role: CloudflareTenantRootCreationInstallationRoleV1,
        signed_commitment_b64u: String,
    },
    BothRolesCommitted {
        deriver_a_signed_commitment_b64u: String,
        deriver_b_signed_commitment_b64u: String,
        pair_digest_b64u: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CloudflareTenantRootRefreshCommitmentResponseV1 {
    pub(crate) outcome: CloudflareTenantRootRefreshCommitmentResponseOutcomeV1,
    pub(crate) command_digest_b64u: String,
    pub(crate) identity_digest_b64u: String,
    pub(crate) custody_lineage_b64u: String,
    pub(crate) authority_id_b64u: String,
    pub(crate) ceremony_context_digest_b64u: String,
    pub(crate) current_epoch: u64,
    pub(crate) next_epoch: u64,
    pub(crate) expected_control_plane_revision: u64,
    pub(crate) active_root_commitment_b64u: String,
    pub(crate) active_activation_receipt_digest_b64u: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum CloudflareTenantRootRefreshInstallationResponseOutcomeV1 {
    WaitingForPeer {
        role: CloudflareTenantRootCreationInstallationRoleV1,
    },
    BothRolesReady {
        root_commitment_b64u: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CloudflareTenantRootRefreshInstallationResponseV1 {
    pub(crate) outcome: CloudflareTenantRootRefreshInstallationResponseOutcomeV1,
    pub(crate) command_digest_b64u: String,
    pub(crate) identity_digest_b64u: String,
    pub(crate) custody_lineage_b64u: String,
    pub(crate) authority_id_b64u: String,
    pub(crate) ceremony_context_digest_b64u: String,
    pub(crate) current_epoch: u64,
    pub(crate) next_epoch: u64,
    pub(crate) expected_control_plane_revision: u64,
    pub(crate) active_root_commitment_b64u: String,
    pub(crate) active_activation_receipt_digest_b64u: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum CloudflareTenantRootRefreshContributionResponseOutcomeV1 {
    WaitingForPeer {
        role: CloudflareTenantRootCreationInstallationRoleV1,
    },
    BothRolesContributed {
        deriver_a_signed_contribution_b64u: String,
        deriver_b_signed_contribution_b64u: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CloudflareTenantRootRefreshContributionResponseV1 {
    pub(crate) outcome: CloudflareTenantRootRefreshContributionResponseOutcomeV1,
    pub(crate) command_digest_b64u: String,
    pub(crate) identity_digest_b64u: String,
    pub(crate) custody_lineage_b64u: String,
    pub(crate) authority_id_b64u: String,
    pub(crate) ceremony_context_digest_b64u: String,
    pub(crate) current_epoch: u64,
    pub(crate) next_epoch: u64,
    pub(crate) expected_control_plane_revision: u64,
    pub(crate) active_root_commitment_b64u: String,
    pub(crate) active_activation_receipt_digest_b64u: String,
}

/// Public operation coordinates retained beside the authoritative active state.
/// The session id is the attempt id; nonce and command digest remain part of the
/// fence so a restarted request cannot silently resume another ceremony.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CloudflareTenantRootRefreshAttemptV1 {
    pub(crate) attempt_id_b64u: String,
    pub(crate) identity_digest_b64u: String,
    pub(crate) custody_lineage_b64u: String,
    pub(crate) command_digest_b64u: String,
    pub(crate) deriver_b_command_digest_b64u: String,
    pub(crate) ceremony_context_digest_b64u: String,
    pub(crate) refresh_context_b64u: String,
    pub(crate) deriver_a_refresh_command_b64u: String,
    pub(crate) deriver_b_refresh_command_b64u: String,
    pub(crate) session_id_b64u: String,
    pub(crate) nonce_b64u: String,
    pub(crate) current_epoch: u64,
    pub(crate) next_epoch: u64,
    pub(crate) expected_control_plane_revision: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CloudflareTenantRootRefreshTerminalOutcomeV1 {
    Completed,
    Failed,
    Aborted,
}

/// Forward-only public refresh fence. The activation path owns terminal
/// transitions; the terminal state retains the exact activation response for
/// a lost-response retry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum CloudflareTenantRootRefreshFenceV1 {
    Open,
    Reserved {
        attempt: CloudflareTenantRootRefreshAttemptV1,
    },
    Executed {
        attempt: CloudflareTenantRootRefreshAttemptV1,
    },
    Terminal {
        attempt: CloudflareTenantRootRefreshAttemptV1,
        outcome: CloudflareTenantRootRefreshTerminalOutcomeV1,
        response: CloudflareTenantRootRefreshActivationResponseV1,
    },
}

/// Operator-supplied inputs for one managed role-restore authorization.
///
/// Tenant identity, custody lineage, active epoch, and activation receipt are
/// deliberately absent. The Durable Object derives those values from its
/// validated active state before constructing the challenge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CloudflareTenantRootManagedRestoreAuthorizationRequestV1 {
    pub(crate) incident_id: String,
    pub(crate) outage_observation_digest_b64u: String,
    pub(crate) issued_at_ms: u64,
    pub(crate) expires_at_ms: u64,
    pub(crate) nonce_b64u: String,
    pub(crate) unavailable_role: TenantRootManagedRestoreRoleV1,
}

/// Exact challenge bound to one active tenant-root state and one operator
/// authorization request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CloudflareTenantRootManagedRestoreAuthorizationChallengeV1 {
    pub(crate) identity_b64u: String,
    pub(crate) identity_digest_b64u: String,
    pub(crate) custody_lineage_b64u: String,
    pub(crate) active_epoch: u64,
    pub(crate) active_lifecycle_revision: u64,
    pub(crate) activation_receipt_b64u: String,
    pub(crate) activation_receipt_digest_b64u: String,
    pub(crate) incident_id: String,
    pub(crate) outage_observation_digest_b64u: String,
    pub(crate) issued_at_ms: u64,
    pub(crate) expires_at_ms: u64,
    pub(crate) nonce_b64u: String,
    pub(crate) unavailable_role: TenantRootManagedRestoreRoleV1,
    pub(crate) challenge_digest_b64u: String,
}

/// Exact attempt identity derived from one authorization challenge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CloudflareTenantRootManagedRestoreAuthorizationAttemptV1 {
    pub(crate) attempt_id_b64u: String,
    pub(crate) challenge_digest_b64u: String,
}

/// Public artifacts retained after an authorization is terminalized. The
/// signed bytes remain opaque here; cryptographic verification belongs to the
/// control-plane and role boundaries that consume them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CloudflareTenantRootManagedRestoreAuthorizationCheckpointV1 {
    pub(crate) challenge: CloudflareTenantRootManagedRestoreAuthorizationChallengeV1,
    pub(crate) attempt: CloudflareTenantRootManagedRestoreAuthorizationAttemptV1,
    pub(crate) public_state_b64u: String,
    pub(crate) capability_b64u: String,
    pub(crate) incident_authorization_b64u: String,
}

/// Forward-only one-use managed-restore authorization fence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum CloudflareTenantRootManagedRestoreFenceV1 {
    Open,
    Reserved {
        challenge: CloudflareTenantRootManagedRestoreAuthorizationChallengeV1,
        attempt: CloudflareTenantRootManagedRestoreAuthorizationAttemptV1,
    },
    Terminal {
        challenge: CloudflareTenantRootManagedRestoreAuthorizationChallengeV1,
        attempt: CloudflareTenantRootManagedRestoreAuthorizationAttemptV1,
        public_state_b64u: String,
        capability_b64u: String,
        incident_authorization_b64u: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CloudflareTenantRootManagedRestoreFenceEvaluationV1 {
    Commit {
        fence: CloudflareTenantRootManagedRestoreFenceV1,
    },
    Replay {
        fence: CloudflareTenantRootManagedRestoreFenceV1,
    },
}

#[cfg(feature = "workers-rs")]
enum CloudflareTenantRootManagedRestoreActiveStateOperationV1 {
    Reserve(CloudflareTenantRootManagedRestoreAuthorizationRequestV1),
    Checkpoint(CloudflareTenantRootManagedRestoreAuthorizationCheckpointV1),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CloudflareTenantRootRefreshActiveStateRecordV1 {
    pub(crate) activation_receipt_b64u: String,
    pub(crate) activation_receipt_digest_b64u: String,
    pub(crate) identity_digest_b64u: String,
    pub(crate) custody_lineage_b64u: String,
    pub(crate) active_epoch: u64,
    pub(crate) deriver_a_commitment_b64u: String,
    pub(crate) deriver_b_commitment_b64u: String,
    pub(crate) active_root_commitment_b64u: String,
    pub(crate) lifecycle_revision: u64,
    pub(crate) fence: CloudflareTenantRootRefreshFenceV1,
    pub(crate) managed_restore_fence: CloudflareTenantRootManagedRestoreFenceV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CloudflareTenantRootRefreshCheckpointScopeV1 {
    identity_digest_b64u: String,
    custody_lineage_b64u: String,
    authority_id_b64u: String,
    ceremony_context_digest_b64u: String,
    current_epoch: u64,
    next_epoch: u64,
    expected_control_plane_revision: u64,
    active_root_commitment_b64u: String,
    active_activation_receipt_digest_b64u: String,
    deriver_a_commitment_b64u: String,
    deriver_b_commitment_b64u: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum CloudflareTenantRootRefreshInstallationCheckpointStateV1 {
    OneRoleReady {
        role: CloudflareTenantRootCreationInstallationRoleV1,
        command_digest_b64u: String,
        signed_evidence_b64u: String,
    },
    BothRolesReady {
        deriver_a_command_digest_b64u: String,
        deriver_b_command_digest_b64u: String,
        deriver_a_signed_evidence_b64u: String,
        deriver_b_signed_evidence_b64u: String,
        root_commitment_b64u: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CloudflareTenantRootRefreshInstallationCheckpointRecordV1 {
    scope: CloudflareTenantRootRefreshCheckpointScopeV1,
    state: CloudflareTenantRootRefreshInstallationCheckpointStateV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum CloudflareTenantRootRefreshContributionRendezvousStateV1 {
    OneRoleContributed {
        role: CloudflareTenantRootCreationInstallationRoleV1,
        command_digest_b64u: String,
        signed_contribution_b64u: String,
    },
    BothRolesContributed {
        deriver_a_command_digest_b64u: String,
        deriver_b_command_digest_b64u: String,
        deriver_a_signed_contribution_b64u: String,
        deriver_b_signed_contribution_b64u: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CloudflareTenantRootRefreshContributionRendezvousRecordV1 {
    scope: CloudflareTenantRootRefreshCheckpointScopeV1,
    state: CloudflareTenantRootRefreshContributionRendezvousStateV1,
}

#[allow(dead_code)]
fn validate_cloudflare_tenant_root_creation_journal_response_v1(
    response: &CloudflareTenantRootCreationJournalResponseV1,
    expected_revision: u64,
    expected_journal_digest: TenantRootProtocolDigestV1,
    expected_capability_digest: TenantRootProtocolDigestV1,
) -> RouterAbProtocolResult<()> {
    if response.revision != expected_revision {
        return Err(malformed_input(
            "tenant-root creation journal response revision does not match the submitted journal",
        ));
    }
    validate_response_digest(
        "tenant-root creation journal response journal digest",
        &response.journal_digest_b64u,
        expected_journal_digest,
    )?;
    validate_response_digest(
        "tenant-root creation journal response capability digest",
        &response.capability_digest_b64u,
        expected_capability_digest,
    )
}

#[allow(dead_code)]
fn validate_response_digest(
    field: &str,
    encoded: &str,
    expected: TenantRootProtocolDigestV1,
) -> RouterAbProtocolResult<()> {
    let decoded = decode_canonical_base64url(field, encoded, 32, base64url_len_for_bytes(32))?;
    if decoded.as_slice() != expected.as_bytes() {
        return Err(malformed_input(format!(
            "{field} does not match the submitted tenant-root creation value"
        )));
    }
    Ok(())
}

#[cfg(feature = "workers-rs")]
#[allow(dead_code)]
pub(crate) async fn execute_cloudflare_router_tenant_root_creation_journal_call_v1(
    env: &worker::Env,
    journal: &TenantRootCreationJournalV1,
    capability: &TenantRootCreationCapabilityV1,
) -> RouterAbProtocolResult<CloudflareTenantRootCreationJournalResponseV1> {
    let identity = tenant_root_creation_identity_v1(journal)?;
    let custody_lineage = journal.custody_lineage();
    journal
        .rebuild(identity.clone(), custody_lineage)
        .map_err(candidate_derivation_error)?;
    let identity_digest = identity.digest().map_err(candidate_derivation_error)?;
    let journal_digest = journal.digest().map_err(candidate_derivation_error)?;
    let revision = journal.revision();
    if capability.identity_digest() != identity_digest
        || capability.custody_lineage() != custody_lineage
        || capability.started_journal_digest() != journal_digest
        || capability.expected_revision() != revision
    {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ForbiddenLocalBinding,
            "tenant-root creation capability does not match the submitted journal",
        ));
    }

    let journal_bytes = journal
        .canonical_bytes()
        .map_err(candidate_derivation_error)?;
    let capability_bytes = capability
        .canonical_bytes()
        .map_err(candidate_derivation_error)?;
    let capability_digest = capability.digest().map_err(candidate_derivation_error)?;
    let object_name = tenant_root_creation_object_name_v1(identity_digest, custody_lineage);
    let namespace = env
        .durable_object(ROUTER_TENANT_ROOT_CREATION_DO_BINDING_V1)
        .map_err(|error| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MissingLocalBinding,
                format!("tenant-root creation Durable Object namespace lookup failed: {error}"),
            )
        })?;
    let object_id = namespace.id_from_name(&object_name).map_err(|error| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            format!("tenant-root creation Durable Object id derivation failed: {error}"),
        )
    })?;
    let object_id = object_id.to_string();
    validate_tenant_root_creation_object_binding_v1(&object_id, capability.authority_id())?;
    let stub = namespace.get_by_name(&object_name).map_err(|error| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            format!("tenant-root creation Durable Object stub lookup failed: {error}"),
        )
    })?;
    let request = CloudflareTenantRootCreationJournalRequestV1 {
        journal_b64u: encode_base64url_bytes_v1(&journal_bytes),
        creation_capability_b64u: encode_base64url_bytes_v1(&capability_bytes),
    };
    let request_body = serde_json::to_string(&request).map_err(|error| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("tenant-root creation journal request JSON encoding failed: {error}"),
        )
    })?;
    if request_body.len() > TENANT_ROOT_CREATION_REQUEST_MAX_BYTES_V1 {
        return Err(malformed_input(
            "tenant-root creation journal request exceeds its maximum size",
        ));
    }
    let headers = worker::Headers::new();
    headers
        .set("content-type", "application/json")
        .map_err(|error| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                format!("tenant-root creation journal request headers failed: {error}"),
            )
        })?;
    crate::set_cloudflare_internal_service_auth_header_v1(
        env,
        &headers,
        "tenant-root creation journal",
    )?;
    let mut init = worker::RequestInit::new();
    init.with_method(worker::Method::Post)
        .with_headers(headers)
        .with_body(Some(worker::wasm_bindgen::JsValue::from_str(&request_body)));
    let request = worker::Request::new_with_init(
        &format!(
            "https://router-ab-do.internal{}",
            CLOUDFLARE_TENANT_ROOT_CREATION_JOURNAL_PATH
        ),
        &init,
    )
    .map_err(|error| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            format!("tenant-root creation journal request construction failed: {error}"),
        )
    })?;
    let mut response = stub.fetch_with_request(request).await.map_err(|error| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            format!("tenant-root creation journal request failed: {error}"),
        )
    })?;
    let status = response.status_code();
    if !(200..=299).contains(&status) {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            format!("tenant-root creation journal returned HTTP {status}"),
        ));
    }
    let response = response
        .json::<CloudflareTenantRootCreationJournalResponseV1>()
        .await
        .map_err(|error| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                format!("tenant-root creation journal response JSON parse failed: {error}"),
            )
        })?;
    validate_cloudflare_tenant_root_creation_journal_response_v1(
        &response,
        revision,
        journal_digest,
        capability_digest,
    )?;
    Ok(response)
}

#[cfg(feature = "workers-rs")]
#[allow(dead_code)]
#[allow(clippy::too_many_arguments)]
async fn execute_cloudflare_router_tenant_root_creation_private_call_v1<
    TRequest: Serialize,
    TResponse: DeserializeOwned,
>(
    env: &worker::Env,
    authority_id: TenantRootControlPlaneAuthorityIdV1,
    identity_digest: TenantRootIdentityDigestV1,
    custody_lineage: TenantRootCustodyLineageId,
    path: &str,
    label: &str,
    request: &TRequest,
    request_max_bytes: usize,
    response_max_bytes: usize,
) -> RouterAbProtocolResult<TResponse> {
    let object_name = tenant_root_creation_object_name_v1(identity_digest, custody_lineage);
    let namespace = env
        .durable_object(ROUTER_TENANT_ROOT_CREATION_DO_BINDING_V1)
        .map_err(|error| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MissingLocalBinding,
                format!("{label} Durable Object namespace lookup failed: {error}"),
            )
        })?;
    let object_id = namespace.id_from_name(&object_name).map_err(|error| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            format!("{label} Durable Object id derivation failed: {error}"),
        )
    })?;
    let object_id = object_id.to_string();
    validate_tenant_root_creation_object_binding_v1(&object_id, authority_id)?;
    let stub = namespace.get_by_name(&object_name).map_err(|error| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            format!("{label} Durable Object stub lookup failed: {error}"),
        )
    })?;
    execute_cloudflare_router_tenant_root_stub_private_call_v1(
        env,
        stub,
        path,
        label,
        request,
        request_max_bytes,
        response_max_bytes,
    )
    .await
}

#[cfg(feature = "workers-rs")]
async fn execute_cloudflare_router_tenant_root_stub_private_call_v1<
    TRequest: Serialize,
    TResponse: DeserializeOwned,
>(
    env: &worker::Env,
    stub: worker::Stub,
    path: &str,
    label: &str,
    request: &TRequest,
    request_max_bytes: usize,
    response_max_bytes: usize,
) -> RouterAbProtocolResult<TResponse> {
    let request_body = serde_json::to_string(request).map_err(|error| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("{label} request JSON encoding failed: {error}"),
        )
    })?;
    if request_body.len() > request_max_bytes {
        return Err(malformed_input(format!(
            "{label} request exceeds its maximum size"
        )));
    }
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
    let request =
        worker::Request::new_with_init(&format!("https://router-ab-do.internal{path}"), &init)
            .map_err(|error| {
                RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                    format!("{label} request construction failed: {error}"),
                )
            })?;
    let mut response = stub.fetch_with_request(request).await.map_err(|error| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            format!("{label} request failed: {error}"),
        )
    })?;
    let status = response.status_code();
    if !(200..=299).contains(&status) {
        let _ = read_bounded_response_body(&mut response, response_max_bytes, label).await?;
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            format!("{label} returned HTTP {status}"),
        ));
    }
    if !response_has_json_content_type(&response, label)? {
        return Err(malformed_input(format!(
            "{label} response content-type is not application/json"
        )));
    }
    decode_bounded_json_response(&mut response, response_max_bytes, label).await
}

#[cfg(feature = "workers-rs")]
fn tenant_root_cutover_stub_v1(env: &worker::Env) -> RouterAbProtocolResult<worker::Stub> {
    let namespace = env
        .durable_object(ROUTER_TENANT_ROOT_CREATION_DO_BINDING_V1)
        .map_err(|error| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MissingLocalBinding,
                format!("tenant-root cutover Durable Object namespace lookup failed: {error}"),
            )
        })?;
    namespace
        .get_by_name(TENANT_ROOT_CUTOVER_OBJECT_NAME_V1)
        .map_err(|error| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                format!("tenant-root cutover Durable Object stub lookup failed: {error}"),
            )
        })
}

#[cfg(feature = "workers-rs")]
pub(crate) async fn execute_cloudflare_router_tenant_root_cutover_read_call_v1(
    env: &worker::Env,
) -> RouterAbProtocolResult<CloudflareTenantRootCutoverReadResponseV1> {
    execute_cloudflare_router_tenant_root_stub_private_call_v1(
        env,
        tenant_root_cutover_stub_v1(env)?,
        CLOUDFLARE_TENANT_ROOT_CUTOVER_READ_PATH,
        "tenant-root cutover read",
        &CloudflareTenantRootCutoverReadRequestV1 {},
        TENANT_ROOT_CUTOVER_REQUEST_MAX_BYTES_V1,
        TENANT_ROOT_CUTOVER_REQUEST_MAX_BYTES_V1,
    )
    .await
}

#[cfg(feature = "workers-rs")]
pub(crate) async fn execute_cloudflare_router_tenant_root_cutover_write_call_v1(
    env: &worker::Env,
    request: &CloudflareTenantRootCutoverWriteRequestV1,
) -> RouterAbProtocolResult<CloudflareTenantRootCutoverWriteResponseV1> {
    execute_cloudflare_router_tenant_root_stub_private_call_v1(
        env,
        tenant_root_cutover_stub_v1(env)?,
        CLOUDFLARE_TENANT_ROOT_CUTOVER_WRITE_PATH,
        "tenant-root cutover write",
        request,
        TENANT_ROOT_CUTOVER_REQUEST_MAX_BYTES_V1,
        TENANT_ROOT_CUTOVER_REQUEST_MAX_BYTES_V1,
    )
    .await
}

#[cfg(feature = "workers-rs")]
#[allow(dead_code)]
fn response_has_json_content_type(
    response: &worker::Response,
    label: &str,
) -> RouterAbProtocolResult<bool> {
    let Some(content_type) = response.headers().get("content-type").map_err(|error| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("{label} response content-type header read failed: {error}"),
        )
    })?
    else {
        return Ok(false);
    };
    Ok(content_type
        .split(';')
        .next()
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json")))
}

#[cfg(feature = "workers-rs")]
#[allow(dead_code)]
async fn read_bounded_response_body(
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
                malformed_input(format!("{label} response body length overflows"))
            })?;
            if next_len > max_bytes {
                return Err(malformed_input(format!(
                    "{label} response exceeds its maximum size"
                )));
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
        return Err(malformed_input(format!(
            "{label} response exceeds its maximum size"
        )));
    }
    Ok(body)
}

#[cfg(feature = "workers-rs")]
#[allow(dead_code)]
async fn decode_bounded_json_response<T: DeserializeOwned>(
    response: &mut worker::Response,
    max_bytes: usize,
    label: &str,
) -> RouterAbProtocolResult<T> {
    let body = read_bounded_response_body(response, max_bytes, label).await?;
    serde_json::from_slice(&body).map_err(|error| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("{label} response JSON parse failed: {error}"),
        )
    })
}

#[allow(dead_code)]
fn validate_commitment_wire_for_role_command(
    bytes: &[u8],
    command: &VerifiedTenantRootRoleCreationCommandV1,
    expected_role: TwoPartyDeriverRole,
    role_keys: &TenantRootCreationRoleVerifyingKeysV1,
) -> RouterAbProtocolResult<VerifiedTenantRootCreationCommitmentV1> {
    let signed = TenantRootSignedCreationCommitmentV1::decode_canonical_bytes(bytes)
        .map_err(candidate_derivation_error)?;
    let context = signed.transcript().context().clone();
    let context_digest = context.digest().map_err(candidate_derivation_error)?;
    if context_digest != command.creation_context_digest() {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ForbiddenLocalBinding,
            "tenant-root creation commitment does not match its role creation command",
        ));
    }
    let role = signed.role();
    if role != expected_role {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ForbiddenLocalBinding,
            "tenant-root creation commitment role does not match its role creation command",
        ));
    }
    verify_creation_commitment(signed, &context, expected_role, role_keys)
}

#[allow(dead_code)]
fn validate_creation_commitment_response_v1(
    response: &CloudflareTenantRootCreationCommitmentResponseV1,
    command: &VerifiedTenantRootRoleCreationCommandV1,
    candidate_bytes: &[u8],
    role_keys: &TenantRootCreationRoleVerifyingKeysV1,
) -> RouterAbProtocolResult<CloudflareTenantRootCreationCommitmentOutcomeV1> {
    let command_digest = command.digest();
    validate_response_digest(
        "tenant-root creation commitment response command digest",
        &response.command_digest_b64u,
        command_digest,
    )?;
    validate_response_digest(
        "tenant-root creation commitment response journal digest",
        &response.journal_digest_b64u,
        command.started_journal_digest(),
    )?;
    validate_response_digest(
        "tenant-root creation commitment response identity digest",
        &response.identity_digest_b64u,
        TenantRootProtocolDigestV1::from_bytes(*command.identity_digest().as_bytes())
            .map_err(candidate_derivation_error)?,
    )?;
    validate_response_lineage(
        "tenant-root creation commitment response custody lineage",
        &response.custody_lineage_b64u,
        command.custody_lineage(),
    )?;
    validate_response_digest(
        "tenant-root creation commitment response ceremony context digest",
        &response.ceremony_context_digest_b64u,
        command.creation_context_digest(),
    )?;
    match &response.outcome {
        CloudflareTenantRootCreationCommitmentResponseOutcomeV1::WaitingForPeer {
            role,
            signed_commitment_b64u,
        } => {
            if role.to_protocol() != command.role() {
                return Err(malformed_input(
                    "tenant-root creation commitment response role is invalid",
                ));
            }
            let returned = decode_canonical_base64url(
                "tenant-root creation commitment response signed commitment",
                signed_commitment_b64u,
                TENANT_ROOT_SIGNED_CREATION_COMMITMENT_MAX_BYTES_V1,
                TENANT_ROOT_CREATION_COMMITMENT_MAX_BASE64URL_BYTES_V1,
            )?;
            if returned != candidate_bytes {
                return Err(malformed_input(
                    "tenant-root creation commitment response does not replay the submitted commitment",
                ));
            }
            validate_commitment_wire_for_role_command(
                &returned,
                command,
                command.role(),
                role_keys,
            )?;
            Ok(CloudflareTenantRootCreationCommitmentOutcomeV1::WaitingForPeer { role: *role })
        }
        CloudflareTenantRootCreationCommitmentResponseOutcomeV1::BothRolesCommitted {
            deriver_a_signed_commitment_b64u,
            deriver_b_signed_commitment_b64u,
            pair_digest_b64u,
        } => {
            let deriver_a_bytes = decode_canonical_base64url(
                "tenant-root creation commitment response Deriver A commitment",
                deriver_a_signed_commitment_b64u,
                TENANT_ROOT_SIGNED_CREATION_COMMITMENT_MAX_BYTES_V1,
                TENANT_ROOT_CREATION_COMMITMENT_MAX_BASE64URL_BYTES_V1,
            )?;
            let deriver_b_bytes = decode_canonical_base64url(
                "tenant-root creation commitment response Deriver B commitment",
                deriver_b_signed_commitment_b64u,
                TENANT_ROOT_SIGNED_CREATION_COMMITMENT_MAX_BYTES_V1,
                TENANT_ROOT_CREATION_COMMITMENT_MAX_BASE64URL_BYTES_V1,
            )?;
            let deriver_a = validate_commitment_wire_for_role_command(
                &deriver_a_bytes,
                command,
                TwoPartyDeriverRole::DeriverA,
                role_keys,
            )?;
            let deriver_b = validate_commitment_wire_for_role_command(
                &deriver_b_bytes,
                command,
                TwoPartyDeriverRole::DeriverB,
                role_keys,
            )?;
            let pair = VerifiedTenantRootCreationCommitmentPairV1::new(deriver_a, deriver_b)
                .map_err(candidate_derivation_error)?;
            validate_response_digest(
                "tenant-root creation commitment response pair digest",
                pair_digest_b64u,
                pair.digest(),
            )?;
            let expected_candidate = match command.role() {
                TwoPartyDeriverRole::DeriverA => pair.deriver_a().canonical_bytes(),
                TwoPartyDeriverRole::DeriverB => pair.deriver_b().canonical_bytes(),
            };
            if expected_candidate != candidate_bytes {
                return Err(malformed_input(
                    "tenant-root creation commitment response pair omits the submitted commitment",
                ));
            }
            Ok(CloudflareTenantRootCreationCommitmentOutcomeV1::BothRolesCommitted { pair })
        }
    }
}

#[allow(dead_code)]
fn validate_response_lineage(
    field: &str,
    encoded: &str,
    expected: TenantRootCustodyLineageId,
) -> RouterAbProtocolResult<()> {
    let decoded = decode_canonical_base64url(field, encoded, 16, base64url_len_for_bytes(16))?;
    if decoded.as_slice() != expected.as_bytes() {
        return Err(malformed_input(format!(
            "{field} does not match the submitted tenant-root creation value"
        )));
    }
    Ok(())
}

#[cfg(feature = "workers-rs")]
#[allow(dead_code)]
pub(crate) async fn execute_cloudflare_router_tenant_root_creation_commitment_call_v1(
    env: &worker::Env,
    command: &VerifiedTenantRootRoleCreationCommandV1,
    commitment: &VerifiedTenantRootCreationCommitmentV1,
) -> RouterAbProtocolResult<CloudflareTenantRootCreationCommitmentOutcomeV1> {
    let command_bytes = command.canonical_bytes().to_vec();
    let commitment_bytes = commitment.canonical_bytes().to_vec();
    let role_keys = read_tenant_root_creation_role_verifying_keys(env)?;
    validate_commitment_wire_for_role_command(
        &commitment_bytes,
        command,
        command.role(),
        &role_keys,
    )?;
    let request = CloudflareTenantRootCreationCommitmentRequestV1 {
        role_creation_command_b64u: encode_base64url_bytes_v1(&command_bytes),
        signed_commitment_b64u: encode_base64url_bytes_v1(&commitment_bytes),
    };
    let response = execute_cloudflare_router_tenant_root_creation_private_call_v1(
        env,
        command.authority_id(),
        command.identity_digest(),
        command.custody_lineage(),
        CLOUDFLARE_TENANT_ROOT_CREATION_COMMITMENT_RENDEZVOUS_PATH,
        "tenant-root creation commitment",
        &request,
        TENANT_ROOT_CREATION_COMMITMENT_REQUEST_MAX_BYTES_V1,
        TENANT_ROOT_CREATION_COMMITMENT_RESPONSE_MAX_BYTES_V1,
    )
    .await?;
    validate_creation_commitment_response_v1(&response, command, &commitment_bytes, &role_keys)
}

#[allow(dead_code)]
fn validate_installation_response_v1(
    response: &CloudflareTenantRootCreationInstallationResponseV1,
    command: &VerifiedTenantRootRoleCreationCommandV1,
    evidence: &VerifiedTenantRootSignedShareInstallationEvidenceWireV1,
) -> RouterAbProtocolResult<CloudflareTenantRootCreationInstallationOutcomeV1> {
    let command_digest = command.digest();
    validate_response_digest(
        "tenant-root installation response command digest",
        &response.command_digest_b64u,
        command_digest,
    )?;
    validate_response_digest(
        "tenant-root installation response journal digest",
        &response.journal_digest_b64u,
        command.started_journal_digest(),
    )?;
    validate_response_digest(
        "tenant-root installation response identity digest",
        &response.identity_digest_b64u,
        TenantRootProtocolDigestV1::from_bytes(*command.identity_digest().as_bytes())
            .map_err(candidate_derivation_error)?,
    )?;
    validate_response_lineage(
        "tenant-root installation response custody lineage",
        &response.custody_lineage_b64u,
        command.custody_lineage(),
    )?;
    validate_response_digest(
        "tenant-root installation response ceremony context digest",
        &response.ceremony_context_digest_b64u,
        command.creation_context_digest(),
    )?;
    let transcript = evidence.evidence().transcript();
    if transcript.role() != command.role()
        || transcript
            .context()
            .digest()
            .map_err(candidate_derivation_error)?
            != command.creation_context_digest()
    {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ForbiddenLocalBinding,
            "tenant-root installation evidence does not match its role creation command",
        ));
    }
    match &response.outcome {
        CloudflareTenantRootCreationInstallationResponseOutcomeV1::WaitingForPeer { role } => {
            if role.to_protocol() != command.role() {
                return Err(malformed_input(
                    "tenant-root installation response role is invalid",
                ));
            }
            Ok(CloudflareTenantRootCreationInstallationOutcomeV1::WaitingForPeer { role: *role })
        }
        CloudflareTenantRootCreationInstallationResponseOutcomeV1::BothRolesReady {
            root_commitment_b64u,
        } => {
            let _ = decode_fixed_base64url_32(
                "tenant-root installation response root commitment",
                root_commitment_b64u,
            )?;
            Ok(
                CloudflareTenantRootCreationInstallationOutcomeV1::BothRolesReady {
                    root_commitment_b64u: root_commitment_b64u.clone(),
                },
            )
        }
    }
}

#[cfg(feature = "workers-rs")]
#[allow(dead_code)]
pub(crate) async fn execute_cloudflare_router_tenant_root_creation_installation_call_v1(
    env: &worker::Env,
    command: &VerifiedTenantRootRoleCreationCommandV1,
    evidence: &VerifiedTenantRootSignedShareInstallationEvidenceWireV1,
) -> RouterAbProtocolResult<CloudflareTenantRootCreationInstallationOutcomeV1> {
    let command_bytes = command.canonical_bytes().to_vec();
    let evidence_bytes = evidence.canonical_bytes();
    let transcript = evidence.evidence().transcript();
    if transcript.role() != command.role()
        || transcript
            .context()
            .digest()
            .map_err(candidate_derivation_error)?
            != command.creation_context_digest()
    {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ForbiddenLocalBinding,
            "tenant-root installation evidence does not match its role creation command",
        ));
    }
    let request = CloudflareTenantRootCreationInstallationRequestV1 {
        role_creation_command_b64u: encode_base64url_bytes_v1(&command_bytes),
        signed_evidence_b64u: encode_base64url_bytes_v1(evidence_bytes),
    };
    let response = execute_cloudflare_router_tenant_root_creation_private_call_v1(
        env,
        command.authority_id(),
        command.identity_digest(),
        command.custody_lineage(),
        CLOUDFLARE_TENANT_ROOT_CREATION_INSTALLATION_CHECKPOINT_PATH,
        "tenant-root installation checkpoint",
        &request,
        TENANT_ROOT_CREATION_INSTALLATION_REQUEST_MAX_BYTES_V1,
        TENANT_ROOT_CREATION_INSTALLATION_RESPONSE_MAX_BYTES_V1,
    )
    .await?;
    validate_installation_response_v1(&response, command, evidence)
}

/// Sends one verified cleanup command and its exact successful terminal receipt
/// to the Router-owned creation object.
#[cfg(feature = "workers-rs")]
pub(crate) async fn execute_cloudflare_router_tenant_root_creation_cleanup_call_v1(
    env: &worker::Env,
    command: &VerifiedTenantRootRoleCleanupCommandV1,
    receipt_bytes: &[u8],
) -> RouterAbProtocolResult<CloudflareTenantRootCreationCleanupResponseV1> {
    let receipt = TenantRootCommandTerminalReceiptV1::decode_canonical_bytes(receipt_bytes)
        .map_err(candidate_derivation_error)?;
    let TenantRootCommandTerminalReceiptV1::Success(receipt) = receipt else {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ForbiddenLocalBinding,
            "tenant-root creation cleanup requires a successful terminal receipt",
        ));
    };
    let receipt_digest = receipt.digest().map_err(candidate_derivation_error)?;
    let command_bytes = command
        .canonical_bytes()
        .map_err(candidate_derivation_error)?;
    let (authority_id, _) = derive_tenant_root_creation_authority_object_v1(
        env,
        command.identity_digest(),
        command.custody_lineage(),
    )?;
    let request = CloudflareTenantRootCreationCleanupRequestV1 {
        cleanup_command_b64u: encode_base64url_bytes_v1(&command_bytes),
        cleanup_receipt_b64u: encode_base64url_bytes_v1(receipt_bytes),
    };
    let response: CloudflareTenantRootCreationCleanupResponseV1 =
        execute_cloudflare_router_tenant_root_creation_private_call_v1(
            env,
            authority_id,
            command.identity_digest(),
            command.custody_lineage(),
            CLOUDFLARE_TENANT_ROOT_CREATION_CLEANUP_CHECKPOINT_PATH,
            "tenant-root creation cleanup checkpoint",
            &request,
            TENANT_ROOT_CREATION_CLEANUP_REQUEST_MAX_BYTES_V1,
            TENANT_ROOT_CREATION_CLEANUP_RESPONSE_MAX_BYTES_V1,
        )
        .await?;
    if response.role.to_protocol() != command.role() {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ForbiddenLocalBinding,
            "tenant-root creation cleanup response role does not match its command",
        ));
    }
    validate_response_digest(
        "tenant-root creation cleanup response receipt digest",
        &response.cleanup_receipt_digest_b64u,
        receipt_digest,
    )?;
    Ok(response)
}

/// Sends a control-plane initial-activation receipt to the Router-owned
/// creation object for authoritative persistence.
#[cfg(feature = "workers-rs")]
pub(crate) async fn execute_cloudflare_router_tenant_root_creation_initial_activation_call_v1(
    env: &worker::Env,
    receipt_bytes: &[u8],
) -> RouterAbProtocolResult<CloudflareTenantRootCreationInitialActivationResponseV1> {
    let receipt = TenantRootSignedActivationReceiptV1::decode_canonical_bytes(receipt_bytes)
        .map_err(candidate_derivation_error)?;
    if receipt.transition() != TenantRootActivationReceiptTransitionV1::InitialCreation {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ForbiddenLocalBinding,
            "tenant-root initial activation persistence requires an initial-creation receipt",
        ));
    }
    let receipt_digest = receipt.digest().map_err(candidate_derivation_error)?;
    let (authority_id, _) = derive_tenant_root_creation_authority_object_v1(
        env,
        receipt.identity_digest(),
        receipt.custody_lineage(),
    )?;
    let request = CloudflareTenantRootCreationInitialActivationRequestV1 {
        activation_receipt_b64u: encode_base64url_bytes_v1(receipt_bytes),
    };
    let response: CloudflareTenantRootCreationInitialActivationResponseV1 =
        execute_cloudflare_router_tenant_root_creation_private_call_v1(
            env,
            authority_id,
            receipt.identity_digest(),
            receipt.custody_lineage(),
            CLOUDFLARE_TENANT_ROOT_CREATION_INITIAL_ACTIVATION_PATH,
            "tenant-root initial activation",
            &request,
            TENANT_ROOT_CREATION_INITIAL_ACTIVATION_REQUEST_MAX_BYTES_V1,
            TENANT_ROOT_CREATION_INITIAL_ACTIVATION_RESPONSE_MAX_BYTES_V1,
        )
        .await?;
    let response_digest = decode_lifecycle_receipt_digest(
        "tenant-root initial activation response receipt digest",
        &response.activation_receipt_digest_b64u,
    )?;
    if response_digest != receipt_digest {
        return Err(malformed_input(
            "tenant-root initial activation response receipt digest does not match the submitted receipt",
        ));
    }
    if response.lifecycle_revision != receipt.result_control_plane_revision() {
        return Err(malformed_input(
            "tenant-root initial activation response revision does not match the submitted receipt",
        ));
    }
    Ok(response)
}

/// Sends a verified refresh-swap activation receipt to the Router-owned
/// creation object after both role-private swaps have committed.
#[cfg(feature = "workers-rs")]
pub(crate) async fn execute_cloudflare_router_tenant_root_refresh_activation_call_v1(
    env: &worker::Env,
    receipt_bytes: &[u8],
) -> RouterAbProtocolResult<CloudflareTenantRootRefreshActivationResponseV1> {
    let receipt = TenantRootSignedActivationReceiptV1::decode_canonical_bytes(receipt_bytes)
        .map_err(candidate_derivation_error)?;
    if receipt.transition() != TenantRootActivationReceiptTransitionV1::RefreshSwap {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ForbiddenLocalBinding,
            "tenant-root refresh activation persistence requires a refresh-swap receipt",
        ));
    }
    let receipt_digest = receipt.digest().map_err(candidate_derivation_error)?;
    let (authority_id, _) = derive_tenant_root_creation_authority_object_v1(
        env,
        receipt.identity_digest(),
        receipt.custody_lineage(),
    )?;
    let request = CloudflareTenantRootRefreshActivationRequestV1 {
        activation_receipt_b64u: encode_base64url_bytes_v1(receipt_bytes),
    };
    let response: CloudflareTenantRootRefreshActivationResponseV1 =
        execute_cloudflare_router_tenant_root_creation_private_call_v1(
            env,
            authority_id,
            receipt.identity_digest(),
            receipt.custody_lineage(),
            CLOUDFLARE_TENANT_ROOT_REFRESH_ACTIVATION_PATH,
            "tenant-root refresh activation",
            &request,
            TENANT_ROOT_CREATION_INITIAL_ACTIVATION_REQUEST_MAX_BYTES_V1,
            TENANT_ROOT_REFRESH_ACTIVATION_RESPONSE_MAX_BYTES_V1,
        )
        .await?;
    let response_digest = decode_lifecycle_receipt_digest(
        "tenant-root refresh activation response receipt digest",
        &response.activation_receipt_digest_b64u,
    )?;
    if response_digest != receipt_digest {
        return Err(malformed_input(
            "tenant-root refresh activation response receipt digest does not match the submitted receipt",
        ));
    }
    if response.lifecycle_revision != receipt.result_control_plane_revision() {
        return Err(malformed_input(
            "tenant-root refresh activation response revision does not match the submitted receipt",
        ));
    }
    Ok(response)
}

/// Issuer-verified active public state read from the Router-owned object.
#[cfg(feature = "workers-rs")]
pub(crate) struct CloudflareVerifiedTenantRootActiveStateV1 {
    pub(crate) activation_receipt: router_ab_core::VerifiedTenantRootSignedActivationReceiptV1,
    pub(crate) lifecycle_revision: u64,
    pub(crate) refresh_fence: CloudflareTenantRootRefreshFenceV1,
    pub(crate) managed_restore_fence: CloudflareTenantRootManagedRestoreFenceV1,
}

/// Reads the Router-owned active state and returns its issuer-verified receipt.
#[cfg(feature = "workers-rs")]
pub(crate) async fn execute_cloudflare_router_tenant_root_creation_active_state_read_call_v1(
    env: &worker::Env,
    identity_digest: TenantRootIdentityDigestV1,
    custody_lineage: TenantRootCustodyLineageId,
) -> RouterAbProtocolResult<router_ab_core::VerifiedTenantRootSignedActivationReceiptV1> {
    Ok(
        execute_cloudflare_router_tenant_root_creation_active_state_with_revision_read_call_v1(
            env,
            identity_digest,
            custody_lineage,
        )
        .await?
        .activation_receipt,
    )
}

/// Reads the authoritative active receipt together with its current lifecycle revision.
#[cfg(feature = "workers-rs")]
pub(crate) async fn execute_cloudflare_router_tenant_root_creation_active_state_with_revision_read_call_v1(
    env: &worker::Env,
    identity_digest: TenantRootIdentityDigestV1,
    custody_lineage: TenantRootCustodyLineageId,
) -> RouterAbProtocolResult<CloudflareVerifiedTenantRootActiveStateV1> {
    let (authority_id, _) =
        derive_tenant_root_creation_authority_object_v1(env, identity_digest, custody_lineage)?;
    let request = CloudflareTenantRootCreationActiveStateReadRequestV1::Read {
        identity_digest_b64u: encode_base64url_bytes_v1(identity_digest.as_bytes()),
        custody_lineage_b64u: custody_lineage.to_base64url(),
    };
    let response: CloudflareTenantRootCreationActiveStateReadResponseV1 =
        execute_cloudflare_router_tenant_root_creation_private_call_v1(
            env,
            authority_id,
            identity_digest,
            custody_lineage,
            CLOUDFLARE_TENANT_ROOT_CREATION_ACTIVE_STATE_READ_PATH,
            "tenant-root active-state read",
            &request,
            TENANT_ROOT_CREATION_ACTIVE_STATE_READ_REQUEST_MAX_BYTES_V1,
            TENANT_ROOT_CREATION_ACTIVE_STATE_READ_RESPONSE_MAX_BYTES_V1,
        )
        .await?;
    let response_identity_digest =
        TenantRootIdentityDigestV1::from_bytes(decode_fixed_base64url_32(
            "tenant-root active-state response identity digest",
            &response.identity_digest_b64u,
        )?);
    if response_identity_digest != identity_digest {
        return Err(malformed_input(
            "tenant-root active-state response identity digest does not match the request",
        ));
    }
    let response_custody_lineage = decode_lineage_b64u(
        "tenant-root active-state response custody lineage",
        &response.custody_lineage_b64u,
    )?;
    if response_custody_lineage != custody_lineage {
        return Err(malformed_input(
            "tenant-root active-state response custody lineage does not match the request",
        ));
    }
    let receipt_bytes = decode_canonical_base64url(
        "tenant-root active-state response activation receipt",
        &response.activation_receipt_b64u,
        TENANT_ROOT_REFRESH_ACTIVE_RECEIPT_MAX_BYTES_V1,
        TENANT_ROOT_REFRESH_ACTIVE_RECEIPT_MAX_BASE64URL_BYTES_V1,
    )?;
    let receipt = TenantRootSignedActivationReceiptV1::decode_canonical_bytes(&receipt_bytes)
        .map_err(candidate_derivation_error)?;
    let issuer_keys_json = read_required_worker_var(
        env,
        crate::TENANT_ROOT_CONTROL_PLANE_ISSUER_VERIFYING_KEYS_JSON_ENV,
    )?;
    let issuer_keys = crate::env::decode_issuer_verifying_keys(&issuer_keys_json)?;
    let issuer_verifying_key = issuer_keys.get(receipt.issuer_key_id()).ok_or_else(|| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ForbiddenLocalBinding,
            "tenant-root active-state response receipt issuer is not trusted",
        )
    })?;
    let receipt = receipt
        .verify_issuer_signature(issuer_verifying_key)
        .map_err(candidate_authorization_error)?;
    if receipt.identity_digest() != identity_digest
        || receipt.custody_lineage() != custody_lineage
        || receipt.binding().authority_id() != authority_id
    {
        return Err(malformed_input(
            "tenant-root active-state response receipt does not match the request authority",
        ));
    }
    let response_receipt_digest = decode_lifecycle_receipt_digest(
        "tenant-root active-state response receipt digest",
        &response.activation_receipt_digest_b64u,
    )?;
    if response_receipt_digest != receipt.digest() {
        return Err(malformed_input(
            "tenant-root active-state response receipt digest does not match its receipt",
        ));
    }
    if response.lifecycle_revision == 0
        || response.lifecycle_revision < receipt.result_control_plane_revision()
    {
        return Err(malformed_input(
            "tenant-root active-state response lifecycle revision is invalid",
        ));
    }
    validate_refresh_fence(&response.fence)?;
    validate_managed_restore_fence_shape(&response.managed_restore_fence)?;
    Ok(CloudflareVerifiedTenantRootActiveStateV1 {
        activation_receipt: receipt,
        lifecycle_revision: response.lifecycle_revision,
        refresh_fence: response.fence,
        managed_restore_fence: response.managed_restore_fence,
    })
}

/// Reserves one managed-restore authorization at the Router-owned Durable
/// Object and returns the exact persisted challenge. A terminal retry returns
/// the challenge from that terminal fence.
#[cfg(feature = "workers-rs")]
pub(crate) async fn execute_cloudflare_router_tenant_root_managed_restore_authorization_challenge_call_v1(
    env: &worker::Env,
    identity_digest: TenantRootIdentityDigestV1,
    custody_lineage: TenantRootCustodyLineageId,
    authorization: CloudflareTenantRootManagedRestoreAuthorizationRequestV1,
) -> RouterAbProtocolResult<CloudflareTenantRootManagedRestoreAuthorizationChallengeV1> {
    let (authority_id, _) =
        derive_tenant_root_creation_authority_object_v1(env, identity_digest, custody_lineage)?;
    let request = CloudflareTenantRootCreationActiveStateReadRequestV1::ReserveManagedRestore {
        identity_digest_b64u: encode_base64url_bytes_v1(identity_digest.as_bytes()),
        custody_lineage_b64u: custody_lineage.to_base64url(),
        authorization,
    };
    let response: CloudflareTenantRootCreationActiveStateReadResponseV1 =
        execute_cloudflare_router_tenant_root_creation_private_call_v1(
            env,
            authority_id,
            identity_digest,
            custody_lineage,
            CLOUDFLARE_TENANT_ROOT_CREATION_ACTIVE_STATE_READ_PATH,
            "tenant-root managed-restore authorization reservation",
            &request,
            TENANT_ROOT_CREATION_ACTIVE_STATE_READ_REQUEST_MAX_BYTES_V1,
            TENANT_ROOT_CREATION_ACTIVE_STATE_READ_RESPONSE_MAX_BYTES_V1,
        )
        .await?;
    let active = decode_verified_active_state_response_v1(
        env,
        authority_id,
        identity_digest,
        custody_lineage,
        response,
    )?;
    match active.managed_restore_fence {
        CloudflareTenantRootManagedRestoreFenceV1::Reserved { challenge, .. }
        | CloudflareTenantRootManagedRestoreFenceV1::Terminal { challenge, .. } => Ok(challenge),
        CloudflareTenantRootManagedRestoreFenceV1::Open => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "tenant-root managed-restore reservation response omitted its persisted challenge",
        )),
    }
}

/// Checkpoints the exact issuer-signed managed-restore artifacts at the
/// Router-owned Durable Object and returns the issuer-verified active state.
#[cfg(feature = "workers-rs")]
pub(crate) async fn execute_cloudflare_router_tenant_root_managed_restore_authorization_checkpoint_call_v1(
    env: &worker::Env,
    identity_digest: TenantRootIdentityDigestV1,
    custody_lineage: TenantRootCustodyLineageId,
    checkpoint: CloudflareTenantRootManagedRestoreAuthorizationCheckpointV1,
) -> RouterAbProtocolResult<CloudflareVerifiedTenantRootActiveStateV1> {
    let (authority_id, _) =
        derive_tenant_root_creation_authority_object_v1(env, identity_digest, custody_lineage)?;
    let request = CloudflareTenantRootCreationActiveStateReadRequestV1::CheckpointManagedRestore {
        identity_digest_b64u: encode_base64url_bytes_v1(identity_digest.as_bytes()),
        custody_lineage_b64u: custody_lineage.to_base64url(),
        checkpoint,
    };
    let response: CloudflareTenantRootCreationActiveStateReadResponseV1 =
        execute_cloudflare_router_tenant_root_creation_private_call_v1(
            env,
            authority_id,
            identity_digest,
            custody_lineage,
            CLOUDFLARE_TENANT_ROOT_CREATION_ACTIVE_STATE_READ_PATH,
            "tenant-root managed-restore authorization checkpoint",
            &request,
            TENANT_ROOT_CREATION_ACTIVE_STATE_READ_REQUEST_MAX_BYTES_V1,
            TENANT_ROOT_CREATION_ACTIVE_STATE_READ_RESPONSE_MAX_BYTES_V1,
        )
        .await?;
    decode_verified_active_state_response_v1(
        env,
        authority_id,
        identity_digest,
        custody_lineage,
        response,
    )
}

/// Reserves the exact refresh context and both issuer commands before either
/// Deriver is invoked. A replay returns the already persisted attempt, so a
/// restarted Router resumes the same session and nonce.
#[cfg(feature = "workers-rs")]
pub(crate) async fn execute_cloudflare_router_tenant_root_refresh_attempt_reservation_call_v1(
    env: &worker::Env,
    identity_digest: TenantRootIdentityDigestV1,
    custody_lineage: TenantRootCustodyLineageId,
    refresh_context_b64u: String,
    deriver_a_refresh_command_b64u: String,
    deriver_b_refresh_command_b64u: String,
) -> RouterAbProtocolResult<CloudflareVerifiedTenantRootActiveStateV1> {
    let (authority_id, _) =
        derive_tenant_root_creation_authority_object_v1(env, identity_digest, custody_lineage)?;
    let request = CloudflareTenantRootCreationActiveStateReadRequestV1::ReserveRefresh {
        identity_digest_b64u: encode_base64url_bytes_v1(identity_digest.as_bytes()),
        custody_lineage_b64u: custody_lineage.to_base64url(),
        refresh_context_b64u,
        deriver_a_refresh_command_b64u,
        deriver_b_refresh_command_b64u,
    };
    let response: CloudflareTenantRootCreationActiveStateReadResponseV1 =
        execute_cloudflare_router_tenant_root_creation_private_call_v1(
            env,
            authority_id,
            identity_digest,
            custody_lineage,
            CLOUDFLARE_TENANT_ROOT_CREATION_ACTIVE_STATE_READ_PATH,
            "tenant-root refresh attempt reservation",
            &request,
            TENANT_ROOT_CREATION_ACTIVE_STATE_READ_REQUEST_MAX_BYTES_V1,
            TENANT_ROOT_CREATION_ACTIVE_STATE_READ_RESPONSE_MAX_BYTES_V1,
        )
        .await?;
    decode_verified_active_state_response_v1(
        env,
        authority_id,
        identity_digest,
        custody_lineage,
        response,
    )
}

#[cfg(feature = "workers-rs")]
fn decode_verified_active_state_response_v1(
    env: &worker::Env,
    authority_id: TenantRootControlPlaneAuthorityIdV1,
    identity_digest: TenantRootIdentityDigestV1,
    custody_lineage: TenantRootCustodyLineageId,
    response: CloudflareTenantRootCreationActiveStateReadResponseV1,
) -> RouterAbProtocolResult<CloudflareVerifiedTenantRootActiveStateV1> {
    let response_identity_digest =
        TenantRootIdentityDigestV1::from_bytes(decode_fixed_base64url_32(
            "tenant-root active-state response identity digest",
            &response.identity_digest_b64u,
        )?);
    if response_identity_digest != identity_digest {
        return Err(malformed_input(
            "tenant-root active-state response identity digest does not match the request",
        ));
    }
    let response_custody_lineage = decode_lineage_b64u(
        "tenant-root active-state response custody lineage",
        &response.custody_lineage_b64u,
    )?;
    if response_custody_lineage != custody_lineage {
        return Err(malformed_input(
            "tenant-root active-state response custody lineage does not match the request",
        ));
    }
    let receipt_bytes = decode_canonical_base64url(
        "tenant-root active-state response activation receipt",
        &response.activation_receipt_b64u,
        TENANT_ROOT_REFRESH_ACTIVE_RECEIPT_MAX_BYTES_V1,
        TENANT_ROOT_REFRESH_ACTIVE_RECEIPT_MAX_BASE64URL_BYTES_V1,
    )?;
    let receipt = TenantRootSignedActivationReceiptV1::decode_canonical_bytes(&receipt_bytes)
        .map_err(candidate_derivation_error)?;
    let issuer_keys_json = read_required_worker_var(
        env,
        crate::TENANT_ROOT_CONTROL_PLANE_ISSUER_VERIFYING_KEYS_JSON_ENV,
    )?;
    let issuer_keys = crate::env::decode_issuer_verifying_keys(&issuer_keys_json)?;
    let issuer_verifying_key = issuer_keys.get(receipt.issuer_key_id()).ok_or_else(|| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ForbiddenLocalBinding,
            "tenant-root active-state response receipt issuer is not trusted",
        )
    })?;
    let receipt = receipt
        .verify_issuer_signature(issuer_verifying_key)
        .map_err(candidate_authorization_error)?;
    if receipt.identity_digest() != identity_digest
        || receipt.custody_lineage() != custody_lineage
        || receipt.binding().authority_id() != authority_id
    {
        return Err(malformed_input(
            "tenant-root active-state response receipt does not match the request authority",
        ));
    }
    let response_receipt_digest = decode_lifecycle_receipt_digest(
        "tenant-root active-state response receipt digest",
        &response.activation_receipt_digest_b64u,
    )?;
    if response_receipt_digest != receipt.digest() {
        return Err(malformed_input(
            "tenant-root active-state response receipt digest does not match its receipt",
        ));
    }
    if response.lifecycle_revision == 0
        || response.lifecycle_revision < receipt.result_control_plane_revision()
    {
        return Err(malformed_input(
            "tenant-root active-state response lifecycle revision is invalid",
        ));
    }
    validate_refresh_fence(&response.fence)?;
    validate_managed_restore_fence_shape(&response.managed_restore_fence)?;
    Ok(CloudflareVerifiedTenantRootActiveStateV1 {
        activation_receipt: receipt,
        lifecycle_revision: response.lifecycle_revision,
        refresh_fence: response.fence,
        managed_restore_fence: response.managed_restore_fence,
    })
}

fn tenant_root_creation_identity_v1(
    journal: &TenantRootCreationJournalV1,
) -> RouterAbProtocolResult<TenantRootIdentityV1> {
    match journal {
        TenantRootCreationJournalV1::Started(event) => {
            TenantRootIdentityV1::decode_canonical_bytes(event.identity_canonical_bytes())
                .map_err(candidate_derivation_error)
        }
    }
}

#[derive(Debug)]
#[cfg_attr(not(feature = "workers-rs"), allow(dead_code))]
enum TenantRootCreationJournalEvaluationV1 {
    Commit {
        record: CloudflareTenantRootCreationJournalRecordV1,
        response: CloudflareTenantRootCreationJournalResponseV1,
    },
    Replay(CloudflareTenantRootCreationJournalResponseV1),
}

pub(crate) fn validate_creation_record(
    record: CloudflareTenantRootCreationJournalRecordV1,
    authority_id: TenantRootControlPlaneAuthorityIdV1,
    trusted_issuer_verifying_keys: &BTreeMap<String, [u8; 32]>,
) -> RouterAbProtocolResult<ValidatedTenantRootCreationJournalV1> {
    let journal_bytes = decode_canonical_base64url(
        "tenant-root creation journal",
        &record.journal_b64u,
        TENANT_ROOT_CREATION_JOURNAL_MAX_BYTES_V1,
        TENANT_ROOT_CREATION_JOURNAL_MAX_BASE64URL_BYTES_V1,
    )?;
    let journal = TenantRootCreationJournalV1::decode_canonical_bytes(&journal_bytes)
        .map_err(candidate_derivation_error)?;
    let (identity, ceremony_context) = match &journal {
        TenantRootCreationJournalV1::Started(event) => (
            TenantRootIdentityV1::decode_canonical_bytes(event.identity_canonical_bytes())
                .map_err(candidate_derivation_error)?,
            TenantRootCeremonyContextV1::decode_canonical_bytes(
                event.ceremony_context_canonical_bytes(),
            )
            .map_err(candidate_derivation_error)?,
        ),
    };
    journal
        .rebuild(identity, journal.custody_lineage())
        .map_err(candidate_derivation_error)?;
    let journal_digest = journal.digest().map_err(candidate_derivation_error)?;
    let capability_bytes = decode_canonical_base64url(
        "tenant-root creation capability",
        &record.creation_capability_b64u,
        TENANT_ROOT_CREATION_CAPABILITY_MAX_BYTES_V1,
        TENANT_ROOT_CREATION_CAPABILITY_MAX_BASE64URL_BYTES_V1,
    )?;
    let raw_capability = TenantRootCreationCapabilityV1::decode_canonical_bytes(&capability_bytes)
        .map_err(candidate_derivation_error)?;
    let issuer_key_id = raw_capability.issuer_key_id();
    let trusted_issuer_verifying_key = trusted_issuer_verifying_keys
        .get(issuer_key_id)
        .ok_or_else(|| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ForbiddenLocalBinding,
                "tenant-root creation capability issuer is not trusted",
            )
        })?;
    let capability = raw_capability
        .verify(
            journal.identity_digest(),
            journal.custody_lineage(),
            journal_digest,
            journal.revision(),
            authority_id,
            issuer_key_id,
            trusted_issuer_verifying_key,
        )
        .map_err(candidate_authorization_error)?;
    let identity_digest = journal.identity_digest();
    let custody_lineage = journal.custody_lineage();
    let revision = journal.revision();
    Ok(ValidatedTenantRootCreationJournalV1 {
        record,
        journal,
        identity_digest,
        custody_lineage,
        ceremony_context,
        revision,
        journal_digest,
        capability,
    })
}

fn evaluate_creation_record(
    existing: Option<CloudflareTenantRootCreationJournalRecordV1>,
    candidate: ValidatedTenantRootCreationJournalV1,
    authority_id: TenantRootControlPlaneAuthorityIdV1,
    trusted_issuer_verifying_keys: &BTreeMap<String, [u8; 32]>,
    now_ms: u64,
) -> RouterAbProtocolResult<TenantRootCreationJournalEvaluationV1> {
    let Some(existing) = existing else {
        candidate.capability.require_fresh(now_ms).map_err(|_| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ExpiredLocalRequest,
                "tenant-root creation capability is outside its freshness window",
            )
        })?;
        let response = candidate.response(CloudflareTenantRootCreationJournalOutcomeV1::Committed);
        return Ok(TenantRootCreationJournalEvaluationV1::Commit {
            record: candidate.record,
            response,
        });
    };
    let existing_validated =
        validate_creation_record(existing, authority_id, trusted_issuer_verifying_keys)
            .map_err(stored_record_error)?;
    if existing_validated.record != candidate.record {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ConflictingPair,
            "tenant-root creation command conflicts with the accepted command",
        ));
    }
    Ok(TenantRootCreationJournalEvaluationV1::Replay(
        candidate.response(CloudflareTenantRootCreationJournalOutcomeV1::Replay),
    ))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CloudflareTenantRootCreationInstallationRoleV1 {
    DeriverA,
    DeriverB,
}

impl CloudflareTenantRootCreationInstallationRoleV1 {
    const fn from_protocol(role: TwoPartyDeriverRole) -> Self {
        match role {
            TwoPartyDeriverRole::DeriverA => Self::DeriverA,
            TwoPartyDeriverRole::DeriverB => Self::DeriverB,
        }
    }

    pub(crate) const fn to_protocol(self) -> TwoPartyDeriverRole {
        match self {
            Self::DeriverA => TwoPartyDeriverRole::DeriverA,
            Self::DeriverB => TwoPartyDeriverRole::DeriverB,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum CloudflareTenantRootCreationCommitmentRendezvousStateV1 {
    OneRoleCommitted {
        role: CloudflareTenantRootCreationInstallationRoleV1,
        signed_commitment_b64u: String,
    },
    BothRolesCommitted {
        deriver_a_signed_commitment_b64u: String,
        deriver_b_signed_commitment_b64u: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CloudflareTenantRootCreationCommitmentRendezvousRecordV1 {
    pub(crate) journal_digest_b64u: String,
    pub(crate) identity_digest_b64u: String,
    pub(crate) custody_lineage_b64u: String,
    pub(crate) ceremony_context_digest_b64u: String,
    pub(crate) state: CloudflareTenantRootCreationCommitmentRendezvousStateV1,
}

#[derive(Debug)]
enum TenantRootCreationCommitmentRendezvousEvaluationV1 {
    Commit {
        rendezvous: CloudflareTenantRootCreationCommitmentRendezvousRecordV1,
        outcome: CloudflareTenantRootCreationCommitmentOutcomeV1,
    },
    Replay(CloudflareTenantRootCreationCommitmentOutcomeV1),
}

#[derive(Debug)]
#[allow(dead_code)]
#[allow(clippy::large_enum_variant)]
pub(crate) enum CloudflareTenantRootCreationCommitmentOutcomeV1 {
    WaitingForPeer {
        role: CloudflareTenantRootCreationInstallationRoleV1,
    },
    BothRolesCommitted {
        pair: VerifiedTenantRootCreationCommitmentPairV1,
    },
}

#[allow(clippy::large_enum_variant)]
enum ValidatedTenantRootCreationCommitmentRendezvousStateV1 {
    OneRoleCommitted {
        role: TwoPartyDeriverRole,
        commitment: VerifiedTenantRootCreationCommitmentV1,
    },
    BothRolesCommitted {
        pair: VerifiedTenantRootCreationCommitmentPairV1,
    },
}

struct ValidatedTenantRootCreationCommitmentRendezvousV1 {
    state: ValidatedTenantRootCreationCommitmentRendezvousStateV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum CloudflareTenantRootCreationInstallationStateV1 {
    OneRoleReady {
        role: CloudflareTenantRootCreationInstallationRoleV1,
        signed_evidence_b64u: String,
    },
    BothRolesReady {
        deriver_a_signed_evidence_b64u: String,
        deriver_b_signed_evidence_b64u: String,
        root_commitment_b64u: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CloudflareTenantRootCreationInstallationCheckpointV1 {
    journal_digest_b64u: String,
    identity_digest_b64u: String,
    custody_lineage_b64u: String,
    ceremony_context_digest_b64u: String,
    state: CloudflareTenantRootCreationInstallationStateV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CloudflareTenantRootCreationCleanupCheckpointV1 {
    journal_digest_b64u: String,
    identity_digest_b64u: String,
    custody_lineage_b64u: String,
    ceremony_context_digest_b64u: String,
    role: CloudflareTenantRootCreationInstallationRoleV1,
    cleanup_command_b64u: String,
    cleanup_receipt_b64u: String,
    cleanup_receipt_digest_b64u: String,
}

struct ValidatedTenantRootCreationCleanupCheckpointV1 {
    record: CloudflareTenantRootCreationCleanupCheckpointV1,
    authorization: router_ab_core::VerifiedTenantRootRoleCleanupCommandV1,
    receipt_digest: TenantRootProtocolDigestV1,
}

enum TenantRootCreationCleanupEvaluationV1 {
    Commit {
        checkpoint: CloudflareTenantRootCreationCleanupCheckpointV1,
        response: CloudflareTenantRootCreationCleanupResponseV1,
    },
    Replay(CloudflareTenantRootCreationCleanupResponseV1),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CloudflareTenantRootCreationInstallationOutcomeV1 {
    WaitingForPeer {
        role: CloudflareTenantRootCreationInstallationRoleV1,
    },
    BothRolesReady {
        root_commitment_b64u: String,
    },
}

#[derive(Debug)]
enum TenantRootCreationInstallationEvaluationV1 {
    Commit {
        checkpoint: CloudflareTenantRootCreationInstallationCheckpointV1,
        outcome: CloudflareTenantRootCreationInstallationOutcomeV1,
    },
    Replay(CloudflareTenantRootCreationInstallationOutcomeV1),
}

#[cfg(feature = "workers-rs")]
fn validate_role_creation_command(
    encoded: &str,
    journal: &ValidatedTenantRootCreationJournalV1,
    authority_id: TenantRootControlPlaneAuthorityIdV1,
    trusted_issuer_verifying_keys: &BTreeMap<String, [u8; 32]>,
) -> RouterAbProtocolResult<VerifiedTenantRootRoleCreationCommandV1> {
    let bytes = decode_canonical_base64url(
        "tenant-root role creation command",
        encoded,
        TENANT_ROOT_ROLE_CREATION_COMMAND_MAX_BYTES_V1,
        TENANT_ROOT_ROLE_CREATION_COMMAND_MAX_BASE64URL_BYTES_V1,
    )?;
    let command = TenantRootRoleCreationCommandV1::decode_canonical_bytes(&bytes)
        .map_err(candidate_derivation_error)?;
    let issuer_key_id = command.issuer_key_id();
    let verifying_key = trusted_issuer_verifying_keys
        .get(issuer_key_id)
        .ok_or_else(|| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ForbiddenLocalBinding,
                "tenant-root creation role command issuer is not trusted",
            )
        })?;
    command
        .verify(
            &journal.journal,
            &journal.ceremony_context,
            command.role(),
            authority_id,
            issuer_key_id,
            verifying_key,
        )
        .map_err(candidate_authorization_error)
}

fn require_fresh_role_creation_command(
    command: &VerifiedTenantRootRoleCreationCommandV1,
    now_ms: u64,
) -> RouterAbProtocolResult<()> {
    command.require_fresh(now_ms).map_err(|_| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ExpiredLocalRequest,
            "tenant-root role creation command is outside its freshness window",
        )
    })
}

fn validate_creation_commitment_rendezvous(
    record: CloudflareTenantRootCreationCommitmentRendezvousRecordV1,
    journal: &ValidatedTenantRootCreationJournalV1,
    role_keys: &TenantRootCreationRoleVerifyingKeysV1,
) -> RouterAbProtocolResult<ValidatedTenantRootCreationCommitmentRendezvousV1> {
    let ceremony_context_digest = journal
        .ceremony_context
        .digest()
        .map_err(candidate_derivation_error)?;
    if record.journal_digest_b64u != encode_base64url_bytes_v1(journal.journal_digest.as_bytes())
        || record.identity_digest_b64u
            != encode_base64url_bytes_v1(journal.identity_digest.as_bytes())
        || record.custody_lineage_b64u != journal.custody_lineage.to_base64url()
        || record.ceremony_context_digest_b64u
            != encode_base64url_bytes_v1(ceremony_context_digest.as_bytes())
    {
        return Err(malformed_input(
            "tenant-root creation commitment rendezvous scope is invalid",
        ));
    }

    let state = match record.state {
        CloudflareTenantRootCreationCommitmentRendezvousStateV1::OneRoleCommitted {
            role,
            signed_commitment_b64u,
        } => {
            let role = role.to_protocol();
            let commitment = validate_creation_commitment_wire(
                &signed_commitment_b64u,
                &journal.ceremony_context,
                role,
                role_keys,
            )?;
            ValidatedTenantRootCreationCommitmentRendezvousStateV1::OneRoleCommitted {
                role,
                commitment,
            }
        }
        CloudflareTenantRootCreationCommitmentRendezvousStateV1::BothRolesCommitted {
            deriver_a_signed_commitment_b64u,
            deriver_b_signed_commitment_b64u,
        } => {
            let deriver_a = validate_creation_commitment_wire(
                &deriver_a_signed_commitment_b64u,
                &journal.ceremony_context,
                TwoPartyDeriverRole::DeriverA,
                role_keys,
            )?;
            let deriver_b = validate_creation_commitment_wire(
                &deriver_b_signed_commitment_b64u,
                &journal.ceremony_context,
                TwoPartyDeriverRole::DeriverB,
                role_keys,
            )?;
            let pair = VerifiedTenantRootCreationCommitmentPairV1::new(deriver_a, deriver_b)
                .map_err(candidate_derivation_error)?;
            ValidatedTenantRootCreationCommitmentRendezvousStateV1::BothRolesCommitted { pair }
        }
    };

    Ok(ValidatedTenantRootCreationCommitmentRendezvousV1 { state })
}

fn require_complete_creation_commitment_rendezvous(
    record: Option<CloudflareTenantRootCreationCommitmentRendezvousRecordV1>,
    journal: &ValidatedTenantRootCreationJournalV1,
    role_keys: &TenantRootCreationRoleVerifyingKeysV1,
) -> RouterAbProtocolResult<VerifiedTenantRootCreationCommitmentPairV1> {
    let record = record.ok_or_else(|| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "tenant-root installation checkpoint has no creation commitment rendezvous",
        )
    })?;
    let validated = validate_creation_commitment_rendezvous(record, journal, role_keys)
        .map_err(stored_record_error)?;
    match validated.state {
        ValidatedTenantRootCreationCommitmentRendezvousStateV1::BothRolesCommitted { pair } => {
            Ok(pair)
        }
        ValidatedTenantRootCreationCommitmentRendezvousStateV1::OneRoleCommitted { .. } => {
            Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "tenant-root installation checkpoint requires both creation commitments",
            ))
        }
    }
}

fn evaluate_creation_commitment_rendezvous(
    existing: Option<CloudflareTenantRootCreationCommitmentRendezvousRecordV1>,
    candidate_bytes: &[u8],
    command: &VerifiedTenantRootRoleCreationCommandV1,
    journal: &ValidatedTenantRootCreationJournalV1,
    role_keys: &TenantRootCreationRoleVerifyingKeysV1,
    now_ms: u64,
) -> RouterAbProtocolResult<TenantRootCreationCommitmentRendezvousEvaluationV1> {
    let candidate = decode_creation_commitment_candidate(
        candidate_bytes,
        &journal.ceremony_context,
        command.role(),
        role_keys,
    )?;
    let candidate_role = candidate.role();
    let candidate_bytes = candidate.canonical_bytes().to_vec();
    let Some(existing) = existing else {
        require_fresh_role_creation_command(command, now_ms)?;
        let rendezvous = commitment_rendezvous_record(
            journal,
            CloudflareTenantRootCreationCommitmentRendezvousStateV1::OneRoleCommitted {
                role: CloudflareTenantRootCreationInstallationRoleV1::from_protocol(candidate_role),
                signed_commitment_b64u: encode_base64url_bytes_v1(&candidate_bytes),
            },
        )?;
        return Ok(TenantRootCreationCommitmentRendezvousEvaluationV1::Commit {
            rendezvous,
            outcome: CloudflareTenantRootCreationCommitmentOutcomeV1::WaitingForPeer {
                role: CloudflareTenantRootCreationInstallationRoleV1::from_protocol(candidate_role),
            },
        });
    };

    let existing = validate_creation_commitment_rendezvous(existing, journal, role_keys)
        .map_err(stored_record_error)?;
    match existing.state {
        ValidatedTenantRootCreationCommitmentRendezvousStateV1::OneRoleCommitted {
            role,
            commitment,
        } => {
            if role == candidate_role {
                if commitment.canonical_bytes() != candidate_bytes {
                    return Err(commitment_conflict());
                }
                return Ok(TenantRootCreationCommitmentRendezvousEvaluationV1::Replay(
                    CloudflareTenantRootCreationCommitmentOutcomeV1::WaitingForPeer {
                        role: CloudflareTenantRootCreationInstallationRoleV1::from_protocol(role),
                    },
                ));
            }

            require_fresh_role_creation_command(command, now_ms)?;
            let (deriver_a, deriver_b) = match candidate_role {
                TwoPartyDeriverRole::DeriverA => (candidate, commitment),
                TwoPartyDeriverRole::DeriverB => (commitment, candidate),
            };
            let deriver_a_bytes = deriver_a.canonical_bytes().to_vec();
            let deriver_b_bytes = deriver_b.canonical_bytes().to_vec();
            let pair = VerifiedTenantRootCreationCommitmentPairV1::new(deriver_a, deriver_b)
                .map_err(candidate_derivation_error)?;
            let rendezvous = commitment_rendezvous_record(
                journal,
                CloudflareTenantRootCreationCommitmentRendezvousStateV1::BothRolesCommitted {
                    deriver_a_signed_commitment_b64u: encode_base64url_bytes_v1(&deriver_a_bytes),
                    deriver_b_signed_commitment_b64u: encode_base64url_bytes_v1(&deriver_b_bytes),
                },
            )?;
            Ok(TenantRootCreationCommitmentRendezvousEvaluationV1::Commit {
                rendezvous,
                outcome: CloudflareTenantRootCreationCommitmentOutcomeV1::BothRolesCommitted {
                    pair,
                },
            })
        }
        ValidatedTenantRootCreationCommitmentRendezvousStateV1::BothRolesCommitted { pair } => {
            let accepted = match candidate_role {
                TwoPartyDeriverRole::DeriverA => pair.deriver_a().canonical_bytes(),
                TwoPartyDeriverRole::DeriverB => pair.deriver_b().canonical_bytes(),
            };
            if accepted != candidate_bytes {
                return Err(commitment_conflict());
            }
            Ok(TenantRootCreationCommitmentRendezvousEvaluationV1::Replay(
                CloudflareTenantRootCreationCommitmentOutcomeV1::BothRolesCommitted { pair },
            ))
        }
    }
}

fn commitment_rendezvous_record(
    journal: &ValidatedTenantRootCreationJournalV1,
    state: CloudflareTenantRootCreationCommitmentRendezvousStateV1,
) -> RouterAbProtocolResult<CloudflareTenantRootCreationCommitmentRendezvousRecordV1> {
    Ok(CloudflareTenantRootCreationCommitmentRendezvousRecordV1 {
        journal_digest_b64u: encode_base64url_bytes_v1(journal.journal_digest.as_bytes()),
        identity_digest_b64u: encode_base64url_bytes_v1(journal.identity_digest.as_bytes()),
        custody_lineage_b64u: journal.custody_lineage.to_base64url(),
        ceremony_context_digest_b64u: encode_base64url_bytes_v1(
            journal
                .ceremony_context
                .digest()
                .map_err(candidate_derivation_error)?
                .as_bytes(),
        ),
        state,
    })
}

fn decode_creation_commitment_candidate(
    bytes: &[u8],
    expected_context: &TenantRootCeremonyContextV1,
    expected_role: TwoPartyDeriverRole,
    role_keys: &TenantRootCreationRoleVerifyingKeysV1,
) -> RouterAbProtocolResult<VerifiedTenantRootCreationCommitmentV1> {
    let signed = TenantRootSignedCreationCommitmentV1::decode_canonical_bytes(bytes)
        .map_err(candidate_derivation_error)?;
    verify_creation_commitment(signed, expected_context, expected_role, role_keys)
}

fn validate_creation_commitment_wire(
    encoded: &str,
    expected_context: &TenantRootCeremonyContextV1,
    expected_role: TwoPartyDeriverRole,
    role_keys: &TenantRootCreationRoleVerifyingKeysV1,
) -> RouterAbProtocolResult<VerifiedTenantRootCreationCommitmentV1> {
    let bytes = decode_canonical_base64url(
        "tenant-root signed creation commitment",
        encoded,
        TENANT_ROOT_SIGNED_CREATION_COMMITMENT_MAX_BYTES_V1,
        TENANT_ROOT_CREATION_COMMITMENT_MAX_BASE64URL_BYTES_V1,
    )?;
    let signed = TenantRootSignedCreationCommitmentV1::decode_canonical_bytes(&bytes)
        .map_err(candidate_derivation_error)?;
    verify_creation_commitment(signed, expected_context, expected_role, role_keys)
}

fn verify_creation_commitment(
    signed: TenantRootSignedCreationCommitmentV1,
    expected_context: &TenantRootCeremonyContextV1,
    expected_role: TwoPartyDeriverRole,
    role_keys: &TenantRootCreationRoleVerifyingKeysV1,
) -> RouterAbProtocolResult<VerifiedTenantRootCreationCommitmentV1> {
    let role = signed.role();
    let signing_key_id = signed.signing_key_id().to_owned();
    let verifying_key = role_keys.for_role_and_key_id(role, &signing_key_id)?;
    signed
        .verify_strict(
            expected_context,
            expected_role,
            &signing_key_id,
            verifying_key,
        )
        .map_err(candidate_authorization_error)
}

fn commitment_conflict() -> RouterAbProtocolError {
    RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::ConflictingPair,
        "tenant-root creation commitment conflicts with the accepted rendezvous",
    )
}

enum ValidatedTenantRootCreationInstallationStateV1 {
    OneRoleReady {
        role: TwoPartyDeriverRole,
        evidence: Box<VerifiedTenantRootSignedShareInstallationEvidenceWireV1>,
    },
    BothRolesReady {
        deriver_a: Box<VerifiedTenantRootSignedShareInstallationEvidenceWireV1>,
        deriver_b: Box<VerifiedTenantRootSignedShareInstallationEvidenceWireV1>,
        root_commitment: [u8; 32],
    },
}

pub(crate) struct ValidatedTenantRootCreationInstallationCheckpointV1 {
    state: ValidatedTenantRootCreationInstallationStateV1,
}

fn validate_installation_checkpoint(
    record: CloudflareTenantRootCreationInstallationCheckpointV1,
    journal: &ValidatedTenantRootCreationJournalV1,
    role_keys: &TenantRootCreationRoleVerifyingKeysV1,
    commitments: &VerifiedTenantRootCreationCommitmentPairV1,
) -> RouterAbProtocolResult<ValidatedTenantRootCreationInstallationCheckpointV1> {
    let ceremony_context_digest = journal
        .ceremony_context
        .digest()
        .map_err(candidate_derivation_error)?;
    if record.journal_digest_b64u != encode_base64url_bytes_v1(journal.journal_digest.as_bytes())
        || record.identity_digest_b64u
            != encode_base64url_bytes_v1(journal.identity_digest.as_bytes())
        || record.custody_lineage_b64u != journal.custody_lineage.to_base64url()
        || record.ceremony_context_digest_b64u
            != encode_base64url_bytes_v1(ceremony_context_digest.as_bytes())
    {
        return Err(malformed_input(
            "tenant-root creation installation checkpoint scope is invalid",
        ));
    }
    let state = match &record.state {
        CloudflareTenantRootCreationInstallationStateV1::OneRoleReady {
            role,
            signed_evidence_b64u,
        } => {
            let evidence = validate_installation_evidence_wire(
                signed_evidence_b64u,
                &journal.ceremony_context,
                role_keys,
            )?;
            if evidence.evidence().transcript().role() != role.to_protocol() {
                return Err(malformed_input(
                    "tenant-root creation installation checkpoint role is invalid",
                ));
            }
            require_installation_commitments_match(&evidence, commitments)?;
            ValidatedTenantRootCreationInstallationStateV1::OneRoleReady {
                role: role.to_protocol(),
                evidence: Box::new(evidence),
            }
        }
        CloudflareTenantRootCreationInstallationStateV1::BothRolesReady {
            deriver_a_signed_evidence_b64u,
            deriver_b_signed_evidence_b64u,
            root_commitment_b64u,
        } => {
            let deriver_a = validate_installation_evidence_wire(
                deriver_a_signed_evidence_b64u,
                &journal.ceremony_context,
                role_keys,
            )?;
            let deriver_b = validate_installation_evidence_wire(
                deriver_b_signed_evidence_b64u,
                &journal.ceremony_context,
                role_keys,
            )?;
            if deriver_a.evidence().transcript().role() != TwoPartyDeriverRole::DeriverA
                || deriver_b.evidence().transcript().role() != TwoPartyDeriverRole::DeriverB
            {
                return Err(malformed_input(
                    "tenant-root creation installation checkpoint pair roles are invalid",
                ));
            }
            require_installation_commitments_match(&deriver_a, commitments)?;
            require_installation_commitments_match(&deriver_b, commitments)?;
            let commitments =
                verify_tenant_root_creation_evidence_v1(deriver_a.evidence(), deriver_b.evidence())
                    .map_err(candidate_derivation_error)?;
            let root_commitment = commitments.root().to_bytes();
            let stored_root = decode_fixed_base64url_32(
                "tenant-root creation installation root commitment",
                root_commitment_b64u,
            )?;
            if stored_root != root_commitment {
                return Err(malformed_input(
                    "tenant-root creation installation checkpoint root commitment is invalid",
                ));
            }
            ValidatedTenantRootCreationInstallationStateV1::BothRolesReady {
                deriver_a: Box::new(deriver_a),
                deriver_b: Box::new(deriver_b),
                root_commitment,
            }
        }
    };
    Ok(ValidatedTenantRootCreationInstallationCheckpointV1 { state })
}

fn decode_and_verify_initial_activation_receipt(
    encoded: &str,
    issuer_keys: &BTreeMap<String, [u8; 32]>,
) -> RouterAbProtocolResult<router_ab_core::VerifiedTenantRootSignedActivationReceiptV1> {
    let bytes = decode_canonical_base64url(
        "tenant-root initial activation receipt",
        encoded,
        TENANT_ROOT_REFRESH_ACTIVE_RECEIPT_MAX_BYTES_V1,
        TENANT_ROOT_REFRESH_ACTIVE_RECEIPT_MAX_BASE64URL_BYTES_V1,
    )?;
    let receipt = TenantRootSignedActivationReceiptV1::decode_canonical_bytes(&bytes)
        .map_err(candidate_derivation_error)?;
    let issuer_key_id = receipt.issuer_key_id();
    let issuer_verifying_key = issuer_keys.get(issuer_key_id).ok_or_else(|| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ForbiddenLocalBinding,
            "tenant-root initial activation receipt issuer is not trusted",
        )
    })?;
    receipt
        .verify_issuer_signature(issuer_verifying_key)
        .map_err(candidate_authorization_error)
}

fn decode_and_verify_refresh_activation_receipt(
    encoded: &str,
    issuer_keys: &BTreeMap<String, [u8; 32]>,
) -> RouterAbProtocolResult<router_ab_core::VerifiedTenantRootSignedActivationReceiptV1> {
    let bytes = decode_canonical_base64url(
        "tenant-root refresh activation receipt",
        encoded,
        TENANT_ROOT_REFRESH_ACTIVE_RECEIPT_MAX_BYTES_V1,
        TENANT_ROOT_REFRESH_ACTIVE_RECEIPT_MAX_BASE64URL_BYTES_V1,
    )?;
    let receipt = TenantRootSignedActivationReceiptV1::decode_canonical_bytes(&bytes)
        .map_err(candidate_derivation_error)?;
    if receipt.transition() != TenantRootActivationReceiptTransitionV1::RefreshSwap {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ForbiddenLocalBinding,
            "tenant-root refresh activation requires a refresh-swap receipt",
        ));
    }
    let issuer_key_id = receipt.issuer_key_id();
    let issuer_verifying_key = issuer_keys.get(issuer_key_id).ok_or_else(|| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ForbiddenLocalBinding,
            "tenant-root refresh activation receipt issuer is not trusted",
        )
    })?;
    receipt
        .verify_issuer_signature(issuer_verifying_key)
        .map_err(candidate_authorization_error)
}

fn validate_initial_activation_receipt_against_creation_state(
    activation_receipt: &router_ab_core::VerifiedTenantRootSignedActivationReceiptV1,
    journal: &ValidatedTenantRootCreationJournalV1,
    installation: &ValidatedTenantRootCreationInstallationCheckpointV1,
) -> RouterAbProtocolResult<()> {
    if activation_receipt.transition() != TenantRootActivationReceiptTransitionV1::InitialCreation {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ForbiddenLocalBinding,
            "tenant-root initial activation requires an initial-creation receipt",
        ));
    }
    let ceremony_context_digest = journal
        .ceremony_context
        .digest()
        .map_err(candidate_derivation_error)?;
    let expected_revision = journal.revision.checked_add(1).ok_or_else(|| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "tenant-root creation journal revision cannot advance for activation",
        )
    })?;
    let result_revision = expected_revision.checked_add(1).ok_or_else(|| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "tenant-root activation result revision cannot advance",
        )
    })?;
    if activation_receipt.identity_digest() != journal.identity_digest
        || activation_receipt.custody_lineage() != journal.custody_lineage
        || activation_receipt.context_digest() != ceremony_context_digest
        || activation_receipt.expected_control_plane_revision() != expected_revision
        || activation_receipt.result_control_plane_revision() != result_revision
    {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ForbiddenLocalBinding,
            "tenant-root initial activation receipt does not match the creation journal",
        ));
    }

    let ValidatedTenantRootCreationInstallationStateV1::BothRolesReady {
        deriver_a,
        deriver_b,
        root_commitment,
    } = &installation.state
    else {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "tenant-root initial activation requires BothRolesReady installation state",
        ));
    };
    let verified_pair =
        verify_tenant_root_creation_evidence_v1(deriver_a.evidence(), deriver_b.evidence())
            .map_err(candidate_derivation_error)?;
    let commitments = TenantRootEpochCommitmentsV1::from_verified(verified_pair)
        .map_err(candidate_derivation_error)?;
    let installation_receipts = TenantRootRoleInstallationReceiptsV1::new(
        deriver_a
            .lifecycle_receipt_digest()
            .map_err(candidate_derivation_error)?,
        deriver_b
            .lifecycle_receipt_digest()
            .map_err(candidate_derivation_error)?,
    )
    .map_err(candidate_derivation_error)?;
    if commitments.root_commitment() != root_commitment {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "tenant-root initial activation installation root commitment is invalid",
        ));
    }
    let TenantRootActivationReceiptBindingV1::InitialCreation(receipt_binding) =
        activation_receipt.binding()
    else {
        unreachable!("initial activation transition selects the initial binding");
    };
    if receipt_binding.commitments() != &commitments
        || receipt_binding.installation_receipts() != installation_receipts
    {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ForbiddenLocalBinding,
            "tenant-root initial activation receipt does not match the installation checkpoint",
        ));
    }
    Ok(())
}

fn evaluate_installation_checkpoint(
    existing: Option<CloudflareTenantRootCreationInstallationCheckpointV1>,
    candidate: VerifiedTenantRootSignedShareInstallationEvidenceWireV1,
    command: &VerifiedTenantRootRoleCreationCommandV1,
    journal: &ValidatedTenantRootCreationJournalV1,
    role_keys: &TenantRootCreationRoleVerifyingKeysV1,
    commitments: &VerifiedTenantRootCreationCommitmentPairV1,
    now_ms: u64,
) -> RouterAbProtocolResult<TenantRootCreationInstallationEvaluationV1> {
    let candidate = validate_installation_evidence_wire(
        &encode_base64url_bytes_v1(candidate.canonical_bytes()),
        &journal.ceremony_context,
        role_keys,
    )?;
    require_installation_commitments_match(&candidate, commitments)?;
    let candidate_role = candidate.evidence().transcript().role();
    if candidate_role != command.role() {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ForbiddenLocalBinding,
            "tenant-root installation evidence role does not match its role creation command",
        ));
    }
    let candidate_bytes = candidate.canonical_bytes().to_vec();
    let Some(existing) = existing else {
        require_fresh_role_creation_command(command, now_ms)?;
        let checkpoint = installation_checkpoint_record(
            journal,
            CloudflareTenantRootCreationInstallationStateV1::OneRoleReady {
                role: CloudflareTenantRootCreationInstallationRoleV1::from_protocol(candidate_role),
                signed_evidence_b64u: encode_base64url_bytes_v1(&candidate_bytes),
            },
        )?;
        return Ok(TenantRootCreationInstallationEvaluationV1::Commit {
            checkpoint,
            outcome: CloudflareTenantRootCreationInstallationOutcomeV1::WaitingForPeer {
                role: CloudflareTenantRootCreationInstallationRoleV1::from_protocol(candidate_role),
            },
        });
    };
    let existing = validate_installation_checkpoint(existing, journal, role_keys, commitments)
        .map_err(stored_record_error)?;
    match existing.state {
        ValidatedTenantRootCreationInstallationStateV1::OneRoleReady { role, evidence } => {
            if role == candidate_role {
                if evidence.canonical_bytes() != candidate_bytes {
                    return Err(installation_conflict());
                }
                return Ok(TenantRootCreationInstallationEvaluationV1::Replay(
                    CloudflareTenantRootCreationInstallationOutcomeV1::WaitingForPeer {
                        role: CloudflareTenantRootCreationInstallationRoleV1::from_protocol(role),
                    },
                ));
            }
            require_fresh_role_creation_command(command, now_ms)?;
            let (deriver_a, deriver_b) = match candidate_role {
                TwoPartyDeriverRole::DeriverA => (candidate, *evidence),
                TwoPartyDeriverRole::DeriverB => (*evidence, candidate),
            };
            let commitments =
                verify_tenant_root_creation_evidence_v1(deriver_a.evidence(), deriver_b.evidence())
                    .map_err(candidate_derivation_error)?;
            let root_commitment = commitments.root().to_bytes();
            let checkpoint = installation_checkpoint_record(
                journal,
                CloudflareTenantRootCreationInstallationStateV1::BothRolesReady {
                    deriver_a_signed_evidence_b64u: encode_base64url_bytes_v1(
                        deriver_a.canonical_bytes(),
                    ),
                    deriver_b_signed_evidence_b64u: encode_base64url_bytes_v1(
                        deriver_b.canonical_bytes(),
                    ),
                    root_commitment_b64u: encode_base64url_bytes_v1(&root_commitment),
                },
            )?;
            Ok(TenantRootCreationInstallationEvaluationV1::Commit {
                checkpoint,
                outcome: CloudflareTenantRootCreationInstallationOutcomeV1::BothRolesReady {
                    root_commitment_b64u: encode_base64url_bytes_v1(&root_commitment),
                },
            })
        }
        ValidatedTenantRootCreationInstallationStateV1::BothRolesReady {
            deriver_a,
            deriver_b,
            root_commitment,
        } => {
            let accepted = match candidate_role {
                TwoPartyDeriverRole::DeriverA => deriver_a.canonical_bytes(),
                TwoPartyDeriverRole::DeriverB => deriver_b.canonical_bytes(),
            };
            if accepted != candidate_bytes {
                return Err(installation_conflict());
            }
            Ok(TenantRootCreationInstallationEvaluationV1::Replay(
                CloudflareTenantRootCreationInstallationOutcomeV1::BothRolesReady {
                    root_commitment_b64u: encode_base64url_bytes_v1(&root_commitment),
                },
            ))
        }
    }
}

fn installation_checkpoint_record(
    journal: &ValidatedTenantRootCreationJournalV1,
    state: CloudflareTenantRootCreationInstallationStateV1,
) -> RouterAbProtocolResult<CloudflareTenantRootCreationInstallationCheckpointV1> {
    Ok(CloudflareTenantRootCreationInstallationCheckpointV1 {
        journal_digest_b64u: encode_base64url_bytes_v1(journal.journal_digest.as_bytes()),
        identity_digest_b64u: encode_base64url_bytes_v1(journal.identity_digest.as_bytes()),
        custody_lineage_b64u: journal.custody_lineage.to_base64url(),
        ceremony_context_digest_b64u: encode_base64url_bytes_v1(
            journal
                .ceremony_context
                .digest()
                .map_err(candidate_derivation_error)?
                .as_bytes(),
        ),
        state,
    })
}

fn creation_cleanup_target(
    journal: &ValidatedTenantRootCreationJournalV1,
    installation: &ValidatedTenantRootCreationInstallationCheckpointV1,
) -> RouterAbProtocolResult<(
    TenantRootRoleCleanupTargetV1,
    CloudflareTenantRootCreationInstallationRoleV1,
)> {
    let ValidatedTenantRootCreationInstallationStateV1::OneRoleReady { role, evidence } =
        &installation.state
    else {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ConflictingPair,
            "tenant-root creation cleanup requires exactly one installed role",
        ));
    };
    let evidence_digest = evidence
        .lifecycle_receipt_digest()
        .map_err(candidate_derivation_error)?;
    Ok((
        TenantRootRoleCleanupTargetV1::Pending {
            identity_digest: journal.identity_digest,
            custody_lineage: journal.custody_lineage,
            role: *role,
            epoch: TenantRootShareEpoch::INITIAL,
            expected_row_revision: 1,
            session_id: journal.ceremony_context.session_id(),
            ceremony_nonce: journal.ceremony_context.nonce(),
            installation_evidence_digest: TenantRootProtocolDigestV1::from_bytes(
                *evidence_digest.as_bytes(),
            )
            .map_err(candidate_derivation_error)?,
        },
        CloudflareTenantRootCreationInstallationRoleV1::from_protocol(*role),
    ))
}

fn validate_creation_cleanup_checkpoint(
    record: CloudflareTenantRootCreationCleanupCheckpointV1,
    journal: &ValidatedTenantRootCreationJournalV1,
    installation: &ValidatedTenantRootCreationInstallationCheckpointV1,
    authority_id: TenantRootControlPlaneAuthorityIdV1,
    trusted_issuer_verifying_keys: &BTreeMap<String, [u8; 32]>,
    role_keys: &TenantRootCreationRoleVerifyingKeysV1,
) -> RouterAbProtocolResult<ValidatedTenantRootCreationCleanupCheckpointV1> {
    let context_digest = journal
        .ceremony_context
        .digest()
        .map_err(candidate_derivation_error)?;
    if record.journal_digest_b64u != encode_base64url_bytes_v1(journal.journal_digest.as_bytes())
        || record.identity_digest_b64u
            != encode_base64url_bytes_v1(journal.identity_digest.as_bytes())
        || record.custody_lineage_b64u != journal.custody_lineage.to_base64url()
        || record.ceremony_context_digest_b64u
            != encode_base64url_bytes_v1(context_digest.as_bytes())
    {
        return Err(malformed_input(
            "tenant-root creation cleanup checkpoint scope is invalid",
        ));
    }
    let (target, role) = creation_cleanup_target(journal, installation)?;
    if record.role != role {
        return Err(malformed_input(
            "tenant-root creation cleanup checkpoint role is invalid",
        ));
    }
    let cleanup_command_bytes = decode_canonical_base64url(
        "tenant-root creation cleanup command",
        &record.cleanup_command_b64u,
        TENANT_ROOT_ROLE_CLEANUP_COMMAND_MAX_BYTES_V1,
        TENANT_ROOT_ROLE_CLEANUP_COMMAND_MAX_BASE64URL_BYTES_V1,
    )?;
    let cleanup_command =
        TenantRootRoleCleanupCommandV1::decode_canonical_bytes(&cleanup_command_bytes)
            .map_err(candidate_derivation_error)?;
    let issuer_key_id = cleanup_command.issuer_key_id();
    let issuer_key = trusted_issuer_verifying_keys
        .get(issuer_key_id)
        .ok_or_else(|| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ForbiddenLocalBinding,
                "tenant-root creation cleanup issuer is not trusted",
            )
        })?;
    let authorization = cleanup_command
        .verify(
            &target,
            target.role(),
            authority_id,
            issuer_key_id,
            issuer_key,
        )
        .map_err(candidate_authorization_error)?;
    let authorization_bytes = authorization
        .canonical_bytes()
        .map_err(candidate_derivation_error)?;
    if authorization_bytes != cleanup_command_bytes {
        return Err(malformed_input(
            "tenant-root creation cleanup authorization bytes changed during verification",
        ));
    }
    let cleanup_receipt_bytes = decode_canonical_base64url(
        "tenant-root creation cleanup receipt",
        &record.cleanup_receipt_b64u,
        TENANT_ROOT_COMMAND_TERMINAL_RECEIPT_MAX_BYTES_V1,
        TENANT_ROOT_COMMAND_TERMINAL_RECEIPT_MAX_BASE64URL_BYTES_V1,
    )?;
    let cleanup_receipt =
        TenantRootCommandTerminalReceiptV1::decode_canonical_bytes(&cleanup_receipt_bytes)
            .map_err(candidate_derivation_error)?;
    let TenantRootCommandTerminalReceiptV1::Success(cleanup_receipt) = cleanup_receipt else {
        return Err(malformed_input(
            "tenant-root creation cleanup requires a successful terminal receipt",
        ));
    };
    let cleanup_nonce = authorization.nonce();
    let replay_session = TenantRootCeremonySessionIdV1::from_bytes(
        cleanup_nonce.as_bytes()[..16]
            .try_into()
            .expect("sixteen cleanup nonce bytes"),
    )
    .map_err(candidate_derivation_error)?;
    let replay_key = TenantRootCommandReplayKeyV1::new(
        journal.identity_digest,
        journal.custody_lineage,
        replay_session,
        cleanup_nonce,
        target.role(),
    );
    let role_signing_key_id = journal.ceremony_context.signing_key_id(target.role());
    let role_verifying_key = role_keys.for_role_and_key_id(target.role(), role_signing_key_id)?;
    cleanup_receipt
        .verify_remote_public(
            &replay_key,
            &authorization_bytes,
            authorization.issued_at_ms(),
            role_signing_key_id,
            role_verifying_key,
        )
        .map_err(candidate_authorization_error)?;
    let receipt_digest = cleanup_receipt
        .digest()
        .map_err(candidate_derivation_error)?;
    if record.cleanup_receipt_digest_b64u != encode_base64url_bytes_v1(receipt_digest.as_bytes()) {
        return Err(malformed_input(
            "tenant-root creation cleanup receipt digest does not match its bytes",
        ));
    }
    Ok(ValidatedTenantRootCreationCleanupCheckpointV1 {
        record,
        authorization,
        receipt_digest,
    })
}

fn creation_cleanup_checkpoint_record(
    request: CloudflareTenantRootCreationCleanupRequestV1,
    journal: &ValidatedTenantRootCreationJournalV1,
    role: CloudflareTenantRootCreationInstallationRoleV1,
) -> RouterAbProtocolResult<CloudflareTenantRootCreationCleanupCheckpointV1> {
    let receipt_bytes = decode_canonical_base64url(
        "tenant-root creation cleanup receipt",
        &request.cleanup_receipt_b64u,
        TENANT_ROOT_COMMAND_TERMINAL_RECEIPT_MAX_BYTES_V1,
        TENANT_ROOT_COMMAND_TERMINAL_RECEIPT_MAX_BASE64URL_BYTES_V1,
    )?;
    let receipt = TenantRootCommandTerminalReceiptV1::decode_canonical_bytes(&receipt_bytes)
        .map_err(candidate_derivation_error)?;
    Ok(CloudflareTenantRootCreationCleanupCheckpointV1 {
        journal_digest_b64u: encode_base64url_bytes_v1(journal.journal_digest.as_bytes()),
        identity_digest_b64u: encode_base64url_bytes_v1(journal.identity_digest.as_bytes()),
        custody_lineage_b64u: journal.custody_lineage.to_base64url(),
        ceremony_context_digest_b64u: encode_base64url_bytes_v1(
            journal
                .ceremony_context
                .digest()
                .map_err(candidate_derivation_error)?
                .as_bytes(),
        ),
        role,
        cleanup_command_b64u: request.cleanup_command_b64u,
        cleanup_receipt_b64u: request.cleanup_receipt_b64u,
        cleanup_receipt_digest_b64u: encode_base64url_bytes_v1(
            receipt
                .digest()
                .map_err(candidate_derivation_error)?
                .as_bytes(),
        ),
    })
}

fn creation_cleanup_response(
    outcome: CloudflareTenantRootCreationCleanupOutcomeV1,
    validated: &ValidatedTenantRootCreationCleanupCheckpointV1,
) -> CloudflareTenantRootCreationCleanupResponseV1 {
    CloudflareTenantRootCreationCleanupResponseV1 {
        outcome,
        role: validated.record.role,
        cleanup_receipt_digest_b64u: encode_base64url_bytes_v1(validated.receipt_digest.as_bytes()),
    }
}

fn evaluate_creation_cleanup_checkpoint(
    existing: Option<CloudflareTenantRootCreationCleanupCheckpointV1>,
    candidate: ValidatedTenantRootCreationCleanupCheckpointV1,
    journal: &ValidatedTenantRootCreationJournalV1,
    installation: &ValidatedTenantRootCreationInstallationCheckpointV1,
    authority_id: TenantRootControlPlaneAuthorityIdV1,
    trusted_issuer_verifying_keys: &BTreeMap<String, [u8; 32]>,
    role_keys: &TenantRootCreationRoleVerifyingKeysV1,
    now_ms: u64,
) -> RouterAbProtocolResult<TenantRootCreationCleanupEvaluationV1> {
    let Some(existing) = existing else {
        candidate
            .authorization
            .require_fresh(now_ms)
            .map_err(candidate_authorization_error)?;
        let response = creation_cleanup_response(
            CloudflareTenantRootCreationCleanupOutcomeV1::Committed,
            &candidate,
        );
        return Ok(TenantRootCreationCleanupEvaluationV1::Commit {
            checkpoint: candidate.record,
            response,
        });
    };
    let existing = validate_creation_cleanup_checkpoint(
        existing,
        journal,
        installation,
        authority_id,
        trusted_issuer_verifying_keys,
        role_keys,
    )
    .map_err(stored_record_error)?;
    if existing.record != candidate.record {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ConflictingPair,
            "tenant-root creation cleanup conflicts with the accepted cleanup",
        ));
    }
    Ok(TenantRootCreationCleanupEvaluationV1::Replay(
        creation_cleanup_response(
            CloudflareTenantRootCreationCleanupOutcomeV1::Replay,
            &existing,
        ),
    ))
}

fn validate_installation_evidence_wire(
    encoded: &str,
    expected_context: &TenantRootCeremonyContextV1,
    role_keys: &TenantRootCreationRoleVerifyingKeysV1,
) -> RouterAbProtocolResult<VerifiedTenantRootSignedShareInstallationEvidenceWireV1> {
    let bytes = decode_canonical_base64url(
        "tenant-root signed installation evidence",
        encoded,
        TENANT_ROOT_SIGNED_SHARE_INSTALLATION_EVIDENCE_MAX_BYTES_V1,
        TENANT_ROOT_CREATION_INSTALLATION_EVIDENCE_MAX_BASE64URL_BYTES_V1,
    )?;
    let decoded = TenantRootSignedShareInstallationEvidenceV1::decode_canonical_bytes(&bytes)
        .map_err(candidate_derivation_error)?;
    let role = decoded.role();
    let verifying_key = role_keys.for_role_and_key_id(role, decoded.signing_key_id())?;
    let verified = TenantRootSignedShareInstallationEvidenceV1::decode_and_verify_canonical_bytes(
        &bytes,
        verifying_key,
    )
    .map_err(candidate_authorization_error)?;
    if verified.evidence().transcript().context() != expected_context {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ForbiddenLocalBinding,
            "tenant-root installation evidence does not match the Started ceremony",
        ));
    }
    Ok(verified)
}

fn require_installation_commitments_match(
    evidence: &VerifiedTenantRootSignedShareInstallationEvidenceWireV1,
    commitments: &VerifiedTenantRootCreationCommitmentPairV1,
) -> RouterAbProtocolResult<()> {
    let transcript = evidence.evidence().transcript();
    let (expected_commitment, expected_peer_commitment) = match transcript.role() {
        TwoPartyDeriverRole::DeriverA => (
            commitments.deriver_a().commitment(),
            commitments.deriver_b().commitment(),
        ),
        TwoPartyDeriverRole::DeriverB => (
            commitments.deriver_b().commitment(),
            commitments.deriver_a().commitment(),
        ),
    };
    if transcript.commitment() != expected_commitment
        || transcript.peer_commitment() != expected_peer_commitment
    {
        return Err(installation_conflict());
    }
    Ok(())
}

fn decode_fixed_base64url_32(field: &str, encoded: &str) -> RouterAbProtocolResult<[u8; 32]> {
    decode_canonical_base64url(field, encoded, 32, base64url_len_for_bytes(32))?
        .try_into()
        .map_err(|_| malformed_input(format!("{field} must contain exactly 32 bytes")))
}

fn installation_conflict() -> RouterAbProtocolError {
    RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::ConflictingPair,
        "tenant-root creation installation evidence conflicts with the accepted checkpoint",
    )
}

struct CreationResponseScopeV1 {
    command_digest_b64u: String,
    journal_digest_b64u: String,
    identity_digest_b64u: String,
    custody_lineage_b64u: String,
    ceremony_context_digest_b64u: String,
}

fn creation_response_scope(
    command: &VerifiedTenantRootRoleCreationCommandV1,
    journal: &ValidatedTenantRootCreationJournalV1,
) -> RouterAbProtocolResult<CreationResponseScopeV1> {
    Ok(CreationResponseScopeV1 {
        command_digest_b64u: encode_base64url_bytes_v1(command.digest().as_bytes()),
        journal_digest_b64u: encode_base64url_bytes_v1(journal.journal_digest.as_bytes()),
        identity_digest_b64u: encode_base64url_bytes_v1(journal.identity_digest.as_bytes()),
        custody_lineage_b64u: journal.custody_lineage.to_base64url(),
        ceremony_context_digest_b64u: encode_base64url_bytes_v1(
            journal
                .ceremony_context
                .digest()
                .map_err(candidate_derivation_error)?
                .as_bytes(),
        ),
    })
}

fn commitment_response(
    scope: CreationResponseScopeV1,
    candidate_bytes: &[u8],
    outcome: CloudflareTenantRootCreationCommitmentOutcomeV1,
) -> RouterAbProtocolResult<CloudflareTenantRootCreationCommitmentResponseV1> {
    let outcome = match outcome {
        CloudflareTenantRootCreationCommitmentOutcomeV1::WaitingForPeer { role } => {
            CloudflareTenantRootCreationCommitmentResponseOutcomeV1::WaitingForPeer {
                role,
                signed_commitment_b64u: encode_base64url_bytes_v1(candidate_bytes),
            }
        }
        CloudflareTenantRootCreationCommitmentOutcomeV1::BothRolesCommitted { pair } => {
            CloudflareTenantRootCreationCommitmentResponseOutcomeV1::BothRolesCommitted {
                deriver_a_signed_commitment_b64u: encode_base64url_bytes_v1(
                    pair.deriver_a().canonical_bytes(),
                ),
                deriver_b_signed_commitment_b64u: encode_base64url_bytes_v1(
                    pair.deriver_b().canonical_bytes(),
                ),
                pair_digest_b64u: encode_base64url_bytes_v1(pair.digest().as_bytes()),
            }
        }
    };
    Ok(CloudflareTenantRootCreationCommitmentResponseV1 {
        outcome,
        command_digest_b64u: scope.command_digest_b64u,
        journal_digest_b64u: scope.journal_digest_b64u,
        identity_digest_b64u: scope.identity_digest_b64u,
        custody_lineage_b64u: scope.custody_lineage_b64u,
        ceremony_context_digest_b64u: scope.ceremony_context_digest_b64u,
    })
}

fn installation_response(
    scope: CreationResponseScopeV1,
    outcome: CloudflareTenantRootCreationInstallationOutcomeV1,
) -> RouterAbProtocolResult<CloudflareTenantRootCreationInstallationResponseV1> {
    let outcome = match outcome {
        CloudflareTenantRootCreationInstallationOutcomeV1::WaitingForPeer { role } => {
            CloudflareTenantRootCreationInstallationResponseOutcomeV1::WaitingForPeer { role }
        }
        CloudflareTenantRootCreationInstallationOutcomeV1::BothRolesReady {
            root_commitment_b64u,
        } => CloudflareTenantRootCreationInstallationResponseOutcomeV1::BothRolesReady {
            root_commitment_b64u,
        },
    };
    Ok(CloudflareTenantRootCreationInstallationResponseV1 {
        outcome,
        command_digest_b64u: scope.command_digest_b64u,
        journal_digest_b64u: scope.journal_digest_b64u,
        identity_digest_b64u: scope.identity_digest_b64u,
        custody_lineage_b64u: scope.custody_lineage_b64u,
        ceremony_context_digest_b64u: scope.ceremony_context_digest_b64u,
    })
}

fn evaluate_cutover_write(
    current: Option<&TenantRootCutoverRecordV1>,
    request: CloudflareTenantRootCutoverWriteRequestV1,
) -> RouterAbProtocolResult<CloudflareTenantRootCutoverWriteResponseV1> {
    match request {
        CloudflareTenantRootCutoverWriteRequestV1::Initialize { record } => match current {
            None if record.revision() == 0 => Ok(CloudflareTenantRootCutoverWriteResponseV1 {
                outcome: CloudflareTenantRootCutoverWriteOutcomeV1::Initialized,
                record,
            }),
            None => Err(cutover_conflict(
                "R120 cutover initialization must persist revision 0",
            )),
            Some(stored) if stored == &record => Ok(CloudflareTenantRootCutoverWriteResponseV1 {
                outcome: CloudflareTenantRootCutoverWriteOutcomeV1::ExactReplay,
                record,
            }),
            Some(_) => Err(cutover_conflict(
                "R120 cutover initialization conflicts with durable state",
            )),
        },
        CloudflareTenantRootCutoverWriteRequestV1::Update {
            expected_revision,
            record,
        } => {
            let stored = current.ok_or_else(|| {
                cutover_conflict("R120 cutover update has no durable initial state")
            })?;
            if stored.revision() != expected_revision {
                return Err(cutover_conflict(
                    "R120 cutover update expected another durable revision",
                ));
            }
            let outcome = match record.classify_update_after(stored)? {
                TenantRootCutoverRecordUpdateV1::ExactReplay => {
                    CloudflareTenantRootCutoverWriteOutcomeV1::ExactReplay
                }
                TenantRootCutoverRecordUpdateV1::Advanced => {
                    CloudflareTenantRootCutoverWriteOutcomeV1::Advanced
                }
            };
            Ok(CloudflareTenantRootCutoverWriteResponseV1 { outcome, record })
        }
    }
}

fn cutover_conflict(message: &'static str) -> RouterAbProtocolError {
    RouterAbProtocolError::new(RouterAbProtocolErrorCode::ConflictingPair, message)
}

#[cfg(feature = "workers-rs")]
#[worker::durable_object(fetch)]
pub struct RouterAbTenantRootCreationDurableObject {
    storage: worker::Storage,
    env: worker::Env,
    authority_object_id: String,
}

#[cfg(feature = "workers-rs")]
struct LoadedTenantRootRoleCreationRequestV1 {
    journal: ValidatedTenantRootCreationJournalV1,
    command: VerifiedTenantRootRoleCreationCommandV1,
    role_keys: TenantRootCreationRoleVerifyingKeysV1,
    now_ms: u64,
}

#[cfg(feature = "workers-rs")]
impl worker::DurableObject for RouterAbTenantRootCreationDurableObject {
    fn new(state: worker::State, env: worker::Env) -> Self {
        Self {
            storage: state.storage(),
            env,
            authority_object_id: state.id().to_string(),
        }
    }

    async fn fetch(&self, mut request: worker::Request) -> worker::Result<worker::Response> {
        if let Err(error) =
            crate::require_cloudflare_internal_service_auth_request_v1(&request, &self.env)
        {
            return crate::cloudflare_private_service_auth_error_response_v1(error);
        }
        if request.method() != worker::Method::Post {
            return worker::Response::error(
                "Tenant-root creation private routes require POST",
                405,
            );
        }
        let path = request.path();
        match path.as_str() {
            CLOUDFLARE_TENANT_ROOT_CUTOVER_READ_PATH => {
                if !request_has_json_content_type(&request)? {
                    return worker::Response::error(
                        "tenant-root cutover read request requires JSON",
                        415,
                    );
                }
                if decode_bounded_json_request::<CloudflareTenantRootCutoverReadRequestV1>(
                    &mut request,
                    TENANT_ROOT_CUTOVER_REQUEST_MAX_BYTES_V1,
                )
                .await
                .is_err()
                {
                    return worker::Response::error(
                        "tenant-root cutover read request rejected",
                        400,
                    );
                }
                match self.read_cutover_record().await {
                    Ok(response) => worker::Response::from_json(&response),
                    Err(error) => tenant_root_creation_do_error_response(error),
                }
            }
            CLOUDFLARE_TENANT_ROOT_CUTOVER_WRITE_PATH => {
                if !request_has_json_content_type(&request)? {
                    return worker::Response::error(
                        "tenant-root cutover write request requires JSON",
                        415,
                    );
                }
                let parsed = match decode_bounded_json_request::<
                    CloudflareTenantRootCutoverWriteRequestV1,
                >(
                    &mut request, TENANT_ROOT_CUTOVER_REQUEST_MAX_BYTES_V1
                )
                .await
                {
                    Ok(value) => value,
                    Err(_) => {
                        return worker::Response::error(
                            "tenant-root cutover write request rejected",
                            400,
                        )
                    }
                };
                match self.persist_cutover_record(parsed).await {
                    Ok(response) => worker::Response::from_json(&response),
                    Err(error) => tenant_root_creation_do_error_response(error),
                }
            }
            CLOUDFLARE_TENANT_ROOT_CREATION_JOURNAL_PATH => {
                if !request_has_json_content_type(&request)? {
                    return worker::Response::error(
                        "tenant-root creation journal request requires JSON",
                        415,
                    );
                }
                let parsed = match decode_bounded_creation_request(&mut request).await {
                    Ok(value) => value,
                    Err(_) => {
                        return worker::Response::error(
                            "tenant-root creation request rejected",
                            400,
                        )
                    }
                };
                match self.persist(parsed).await {
                    Ok(response) => worker::Response::from_json(&response),
                    Err(error) => tenant_root_creation_do_error_response(error),
                }
            }
            CLOUDFLARE_TENANT_ROOT_CREATION_JOURNAL_READ_PATH => {
                if !request_has_json_content_type(&request)? {
                    return worker::Response::error(
                        "tenant-root creation read request requires JSON",
                        415,
                    );
                }
                let parsed = match decode_bounded_json_request::<
                    CloudflareTenantRootCreationJournalReadRequestV1,
                >(
                    &mut request, TENANT_ROOT_CREATION_REQUEST_MAX_BYTES_V1
                )
                .await
                {
                    Ok(value) => value,
                    Err(error) => return tenant_root_creation_do_error_response(error),
                };
                match self.read_creation_journal(parsed).await {
                    Ok(response) => worker::Response::from_json(&response),
                    Err(error) => tenant_root_creation_do_error_response(error),
                }
            }
            CLOUDFLARE_TENANT_ROOT_CREATION_INITIAL_ACTIVATION_PATH => {
                if !request_has_json_content_type(&request)? {
                    return worker::Response::error(
                        "tenant-root initial activation request requires JSON",
                        415,
                    );
                }
                let parsed = match decode_bounded_json_request::<
                    CloudflareTenantRootCreationInitialActivationRequestV1,
                >(
                    &mut request,
                    TENANT_ROOT_CREATION_INITIAL_ACTIVATION_REQUEST_MAX_BYTES_V1,
                )
                .await
                {
                    Ok(value) => value,
                    Err(_) => {
                        return worker::Response::error(
                            "tenant-root initial activation request rejected",
                            400,
                        )
                    }
                };
                match self.persist_initial_activation(parsed).await {
                    Ok(response) => worker::Response::from_json(&response),
                    Err(error) => tenant_root_creation_do_error_response(error),
                }
            }
            CLOUDFLARE_TENANT_ROOT_REFRESH_ACTIVATION_PATH => {
                if !request_has_json_content_type(&request)? {
                    return worker::Response::error(
                        "tenant-root refresh activation request requires JSON",
                        415,
                    );
                }
                let parsed = match decode_bounded_json_request::<
                    CloudflareTenantRootRefreshActivationRequestV1,
                >(
                    &mut request,
                    TENANT_ROOT_CREATION_INITIAL_ACTIVATION_REQUEST_MAX_BYTES_V1,
                )
                .await
                {
                    Ok(value) => value,
                    Err(_) => {
                        return worker::Response::error(
                            "tenant-root refresh activation request rejected",
                            400,
                        )
                    }
                };
                match self.persist_refresh_activation(parsed).await {
                    Ok(response) => worker::Response::from_json(&response),
                    Err(error) => tenant_root_creation_do_error_response(error),
                }
            }
            CLOUDFLARE_TENANT_ROOT_CREATION_ACTIVE_STATE_READ_PATH => {
                if !request_has_json_content_type(&request)? {
                    return worker::Response::error(
                        "tenant-root active-state read request requires JSON",
                        415,
                    );
                }
                let parsed = match decode_bounded_json_request::<
                    CloudflareTenantRootCreationActiveStateReadRequestV1,
                >(
                    &mut request,
                    TENANT_ROOT_CREATION_ACTIVE_STATE_READ_REQUEST_MAX_BYTES_V1,
                )
                .await
                {
                    Ok(value) => value,
                    Err(_) => {
                        return worker::Response::error(
                            "tenant-root active-state read request rejected",
                            400,
                        )
                    }
                };
                match self
                    .read_or_reserve_authoritative_active_state(parsed)
                    .await
                {
                    Ok(response) => worker::Response::from_json(&response),
                    Err(error) => tenant_root_creation_do_error_response(error),
                }
            }
            CLOUDFLARE_TENANT_ROOT_CREATION_COMMITMENT_RENDEZVOUS_PATH => {
                if !request_has_json_content_type(&request)? {
                    return worker::Response::error(
                        "tenant-root creation commitment request requires JSON",
                        415,
                    );
                }
                let parsed = match decode_bounded_json_request::<
                    CloudflareTenantRootCreationCommitmentRequestV1,
                >(
                    &mut request,
                    TENANT_ROOT_CREATION_COMMITMENT_REQUEST_MAX_BYTES_V1,
                )
                .await
                {
                    Ok(value) => value,
                    Err(_) => {
                        return worker::Response::error(
                            "tenant-root creation commitment request rejected",
                            400,
                        )
                    }
                };
                match self.persist_creation_commitment_rendezvous(parsed).await {
                    Ok(response) => worker::Response::from_json(&response),
                    Err(error) => tenant_root_creation_do_error_response(error),
                }
            }
            CLOUDFLARE_TENANT_ROOT_CREATION_INSTALLATION_CHECKPOINT_PATH => {
                if !request_has_json_content_type(&request)? {
                    return worker::Response::error(
                        "tenant-root installation request requires JSON",
                        415,
                    );
                }
                let parsed = match decode_bounded_json_request::<
                    CloudflareTenantRootCreationInstallationRequestV1,
                >(
                    &mut request,
                    TENANT_ROOT_CREATION_INSTALLATION_REQUEST_MAX_BYTES_V1,
                )
                .await
                {
                    Ok(value) => value,
                    Err(_) => {
                        return worker::Response::error(
                            "tenant-root installation request rejected",
                            400,
                        )
                    }
                };
                match self.persist_installation_checkpoint(parsed).await {
                    Ok(response) => worker::Response::from_json(&response),
                    Err(error) => tenant_root_creation_do_error_response(error),
                }
            }
            CLOUDFLARE_TENANT_ROOT_CREATION_CLEANUP_CHECKPOINT_PATH => {
                if !request_has_json_content_type(&request)? {
                    return worker::Response::error(
                        "tenant-root creation cleanup request requires JSON",
                        415,
                    );
                }
                let parsed = match decode_bounded_json_request::<
                    CloudflareTenantRootCreationCleanupRequestV1,
                >(
                    &mut request,
                    TENANT_ROOT_CREATION_CLEANUP_REQUEST_MAX_BYTES_V1,
                )
                .await
                {
                    Ok(value) => value,
                    Err(_) => {
                        return worker::Response::error(
                            "tenant-root creation cleanup request rejected",
                            400,
                        )
                    }
                };
                match self.persist_creation_cleanup_checkpoint(parsed).await {
                    Ok(response) => worker::Response::from_json(&response),
                    Err(error) => tenant_root_creation_do_error_response(error),
                }
            }
            CLOUDFLARE_TENANT_ROOT_REFRESH_COMMITMENT_CHECKPOINT_PATH => {
                if !request_has_json_content_type(&request)? {
                    return worker::Response::error(
                        "tenant-root refresh commitment request requires JSON",
                        415,
                    );
                }
                let parsed = match decode_bounded_json_request::<
                    CloudflareTenantRootRefreshCommitmentRequestV1,
                >(
                    &mut request,
                    TENANT_ROOT_REFRESH_COMMITMENT_REQUEST_MAX_BYTES_V1,
                )
                .await
                {
                    Ok(value) => value,
                    Err(_) => {
                        return worker::Response::error(
                            "tenant-root refresh commitment request rejected",
                            400,
                        )
                    }
                };
                match self.persist_refresh_commitment_checkpoint(parsed).await {
                    Ok(response) => worker::Response::from_json(&response),
                    Err(error) => tenant_root_creation_do_error_response(error),
                }
            }
            CLOUDFLARE_TENANT_ROOT_REFRESH_INSTALLATION_CHECKPOINT_PATH => {
                if !request_has_json_content_type(&request)? {
                    return worker::Response::error(
                        "tenant-root refresh installation request requires JSON",
                        415,
                    );
                }
                let parsed = match decode_bounded_json_request::<
                    CloudflareTenantRootRefreshInstallationRequestV1,
                >(
                    &mut request,
                    TENANT_ROOT_REFRESH_INSTALLATION_REQUEST_MAX_BYTES_V1,
                )
                .await
                {
                    Ok(value) => value,
                    Err(_) => {
                        return worker::Response::error(
                            "tenant-root refresh installation request rejected",
                            400,
                        )
                    }
                };
                match self.persist_refresh_installation_checkpoint(parsed).await {
                    Ok(response) => worker::Response::from_json(&response),
                    Err(error) => tenant_root_creation_do_error_response(error),
                }
            }
            CLOUDFLARE_TENANT_ROOT_REFRESH_CONTRIBUTION_RENDEZVOUS_PATH => {
                if !request_has_json_content_type(&request)? {
                    return worker::Response::error(
                        "tenant-root refresh contribution request requires JSON",
                        415,
                    );
                }
                let parsed = match decode_bounded_json_request::<
                    CloudflareTenantRootRefreshContributionRequestV1,
                >(
                    &mut request,
                    TENANT_ROOT_REFRESH_CONTRIBUTION_REQUEST_MAX_BYTES_V1,
                )
                .await
                {
                    Ok(value) => value,
                    Err(_) => {
                        return worker::Response::error(
                            "tenant-root refresh contribution request rejected",
                            400,
                        )
                    }
                };
                match self.persist_refresh_contribution_rendezvous(parsed).await {
                    Ok(response) => worker::Response::from_json(&response),
                    Err(error) => tenant_root_creation_do_error_response(error),
                }
            }
            _ => worker::Response::error("Tenant-root creation private route not found", 404),
        }
    }
}

/// Projects validated creation state into the public read response.
///
/// Pure so the projection is testable without a Durable Object: the caller's
/// identity and lineage must match the persisted journal, and only bytes that
/// are already public evidence are returned.
fn creation_installation_checkpoint_read_state_v1(
    checkpoint: Option<&ValidatedTenantRootCreationInstallationCheckpointV1>,
) -> CloudflareTenantRootCreationInstallationCheckpointReadStateV1 {
    let Some(checkpoint) = checkpoint else {
        return CloudflareTenantRootCreationInstallationCheckpointReadStateV1::None;
    };
    match &checkpoint.state {
        ValidatedTenantRootCreationInstallationStateV1::OneRoleReady { role, evidence } => {
            CloudflareTenantRootCreationInstallationCheckpointReadStateV1::OneRoleReady {
                role: CloudflareTenantRootCreationInstallationRoleV1::from_protocol(*role),
                signed_evidence_b64u: encode_base64url_bytes_v1(evidence.canonical_bytes()),
            }
        }
        ValidatedTenantRootCreationInstallationStateV1::BothRolesReady {
            root_commitment, ..
        } => CloudflareTenantRootCreationInstallationCheckpointReadStateV1::BothRolesReady {
            root_commitment_b64u: encode_base64url_bytes_v1(root_commitment),
        },
    }
}

fn active_state_read_response_from_record(
    record: CloudflareTenantRootRefreshActiveStateRecordV1,
) -> CloudflareTenantRootCreationActiveStateReadResponseV1 {
    CloudflareTenantRootCreationActiveStateReadResponseV1 {
        activation_receipt_b64u: record.activation_receipt_b64u,
        activation_receipt_digest_b64u: record.activation_receipt_digest_b64u,
        identity_digest_b64u: record.identity_digest_b64u,
        custody_lineage_b64u: record.custody_lineage_b64u,
        lifecycle_revision: record.lifecycle_revision,
        fence: record.fence,
        managed_restore_fence: record.managed_restore_fence,
    }
}

pub(crate) fn build_creation_journal_read_response(
    request: &CloudflareTenantRootCreationJournalReadRequestV1,
    journal: &ValidatedTenantRootCreationJournalV1,
    rendezvous: Option<&CloudflareTenantRootCreationCommitmentRendezvousRecordV1>,
    installation_checkpoint: Option<&ValidatedTenantRootCreationInstallationCheckpointV1>,
    cleanup_checkpointed: bool,
) -> RouterAbProtocolResult<CloudflareTenantRootCreationJournalReadResponseV1> {
    require_base64url_matches(
        "tenant-root creation read identity digest",
        &request.identity_digest_b64u,
        journal.identity_digest.as_bytes(),
    )?;
    require_base64url_matches(
        "tenant-root creation read custody lineage",
        &request.custody_lineage_b64u,
        journal.custody_lineage.as_bytes(),
    )?;
    let committed_roles = match rendezvous.map(|record| &record.state) {
        None => Vec::new(),
        Some(CloudflareTenantRootCreationCommitmentRendezvousStateV1::OneRoleCommitted {
            role,
            ..
        }) => vec![*role],
        Some(CloudflareTenantRootCreationCommitmentRendezvousStateV1::BothRolesCommitted {
            ..
        }) => vec![
            CloudflareTenantRootCreationInstallationRoleV1::DeriverA,
            CloudflareTenantRootCreationInstallationRoleV1::DeriverB,
        ],
    };
    Ok(CloudflareTenantRootCreationJournalReadResponseV1 {
        journal_b64u: journal.record.journal_b64u.clone(),
        creation_capability_b64u: journal.record.creation_capability_b64u.clone(),
        revision: journal.journal.revision(),
        committed_roles,
        installation_checkpoint: creation_installation_checkpoint_read_state_v1(
            installation_checkpoint,
        ),
        cleanup_checkpointed,
    })
}

#[cfg(feature = "workers-rs")]
impl RouterAbTenantRootCreationDurableObject {
    async fn read_cutover_record(
        &self,
    ) -> RouterAbProtocolResult<CloudflareTenantRootCutoverReadResponseV1> {
        let record = storage_get_optional::<TenantRootCutoverRecordV1>(
            &self.storage,
            TENANT_ROOT_CUTOVER_STORAGE_KEY_V1,
        )
        .await
        .map_err(durable_storage_protocol_error)?;
        Ok(match record {
            Some(record) => CloudflareTenantRootCutoverReadResponseV1::Present { record },
            None => CloudflareTenantRootCutoverReadResponseV1::Empty,
        })
    }

    async fn persist_cutover_record(
        &self,
        request: CloudflareTenantRootCutoverWriteRequestV1,
    ) -> RouterAbProtocolResult<CloudflareTenantRootCutoverWriteResponseV1> {
        let outcome: Rc<
            RefCell<Option<RouterAbProtocolResult<CloudflareTenantRootCutoverWriteResponseV1>>>,
        > = Rc::new(RefCell::new(None));
        let outcome_for_transaction = Rc::clone(&outcome);
        self.storage
            .transaction(move |transaction| async move {
                let current = transaction_get_optional::<TenantRootCutoverRecordV1>(
                    &transaction,
                    TENANT_ROOT_CUTOVER_STORAGE_KEY_V1,
                )
                .await?;
                let response = match evaluate_cutover_write(current.as_ref(), request) {
                    Ok(response) => response,
                    Err(error) => {
                        outcome_for_transaction.replace(Some(Err(error)));
                        return Ok(());
                    }
                };
                if response.outcome != CloudflareTenantRootCutoverWriteOutcomeV1::ExactReplay {
                    transaction
                        .put(TENANT_ROOT_CUTOVER_STORAGE_KEY_V1, &response.record)
                        .await?;
                }
                outcome_for_transaction.replace(Some(Ok(response)));
                Ok(())
            })
            .await
            .map_err(durable_storage_protocol_error)?;
        let response = outcome.borrow_mut().take().ok_or_else(|| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "tenant-root cutover transaction did not produce an outcome",
            )
        })?;
        response
    }

    /// Serves the persisted creation state to an authenticated internal caller.
    pub(crate) async fn read_creation_journal(
        &self,
        request: CloudflareTenantRootCreationJournalReadRequestV1,
    ) -> RouterAbProtocolResult<CloudflareTenantRootCreationJournalReadResponseV1> {
        let issuer_keys_json = read_required_worker_var(
            &self.env,
            crate::TENANT_ROOT_CONTROL_PLANE_ISSUER_VERIFYING_KEYS_JSON_ENV,
        )?;
        let issuer_keys = crate::env::decode_issuer_verifying_keys(&issuer_keys_json)?;
        let authority_id = authority_id_from_object_id(&self.authority_object_id)?;
        let journal_record = storage_get_optional::<CloudflareTenantRootCreationJournalRecordV1>(
            &self.storage,
            TENANT_ROOT_CREATION_JOURNAL_STORAGE_KEY_V1,
        )
        .await
        .map_err(durable_storage_protocol_error)?
        .ok_or_else(|| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "tenant-root creation read has no Started journal",
            )
        })?;
        let journal = validate_creation_record(journal_record, authority_id, &issuer_keys)
            .map_err(stored_record_error)?;
        let rendezvous =
            storage_get_optional::<CloudflareTenantRootCreationCommitmentRendezvousRecordV1>(
                &self.storage,
                TENANT_ROOT_CREATION_COMMITMENT_RENDEZVOUS_STORAGE_KEY_V1,
            )
            .await
            .map_err(durable_storage_protocol_error)?;
        let installation_record =
            storage_get_optional::<CloudflareTenantRootCreationInstallationCheckpointV1>(
                &self.storage,
                TENANT_ROOT_CREATION_INSTALLATION_CHECKPOINT_STORAGE_KEY_V1,
            )
            .await
            .map_err(durable_storage_protocol_error)?;
        let role_keys = if rendezvous.is_some() || installation_record.is_some() {
            Some(read_tenant_root_creation_role_verifying_keys(&self.env)?)
        } else {
            None
        };
        // Progress is only reported from records that validate against the
        // Started journal and retained role keys. A corrupt record fails the
        // read rather than producing a misleading lifecycle projection.
        if let (Some(record), Some(role_keys)) = (&rendezvous, role_keys.as_ref()) {
            validate_creation_commitment_rendezvous(record.clone(), &journal, role_keys)
                .map_err(stored_record_error)?;
        }
        let installation_checkpoint = match installation_record {
            None => None,
            Some(record) => {
                let role_keys = role_keys.as_ref().ok_or_else(|| {
                    RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                        "tenant-root installation checkpoint has no role-key set",
                    )
                })?;
                let commitments = require_complete_creation_commitment_rendezvous(
                    rendezvous.clone(),
                    &journal,
                    role_keys,
                )?;
                Some(
                    validate_installation_checkpoint(record, &journal, role_keys, &commitments)
                        .map_err(stored_record_error)?,
                )
            }
        };
        let cleanup_checkpointed =
            storage_get_optional::<CloudflareTenantRootCreationCleanupCheckpointV1>(
                &self.storage,
                TENANT_ROOT_CREATION_CLEANUP_CHECKPOINT_STORAGE_KEY_V1,
            )
            .await
            .map_err(durable_storage_protocol_error)?
            .is_some();
        build_creation_journal_read_response(
            &request,
            &journal,
            rendezvous.as_ref(),
            installation_checkpoint.as_ref(),
            cleanup_checkpointed,
        )
    }

    async fn read_or_reserve_authoritative_active_state(
        &self,
        request: CloudflareTenantRootCreationActiveStateReadRequestV1,
    ) -> RouterAbProtocolResult<CloudflareTenantRootCreationActiveStateReadResponseV1> {
        let (
            identity_digest_b64u,
            custody_lineage_b64u,
            refresh_context_b64u,
            deriver_a_refresh_command_b64u,
            deriver_b_refresh_command_b64u,
            managed_restore_operation,
        ) = match request {
            CloudflareTenantRootCreationActiveStateReadRequestV1::Read {
                identity_digest_b64u,
                custody_lineage_b64u,
            } => (
                identity_digest_b64u,
                custody_lineage_b64u,
                None,
                None,
                None,
                None,
            ),
            CloudflareTenantRootCreationActiveStateReadRequestV1::ReserveRefresh {
                identity_digest_b64u,
                custody_lineage_b64u,
                refresh_context_b64u,
                deriver_a_refresh_command_b64u,
                deriver_b_refresh_command_b64u,
            } => (
                identity_digest_b64u,
                custody_lineage_b64u,
                Some(refresh_context_b64u),
                Some(deriver_a_refresh_command_b64u),
                Some(deriver_b_refresh_command_b64u),
                None,
            ),
            CloudflareTenantRootCreationActiveStateReadRequestV1::ReserveManagedRestore {
                identity_digest_b64u,
                custody_lineage_b64u,
                authorization,
            } => (
                identity_digest_b64u,
                custody_lineage_b64u,
                None,
                None,
                None,
                Some(
                    CloudflareTenantRootManagedRestoreActiveStateOperationV1::Reserve(
                        authorization,
                    ),
                ),
            ),
            CloudflareTenantRootCreationActiveStateReadRequestV1::CheckpointManagedRestore {
                identity_digest_b64u,
                custody_lineage_b64u,
                checkpoint,
            } => (
                identity_digest_b64u,
                custody_lineage_b64u,
                None,
                None,
                None,
                Some(
                    CloudflareTenantRootManagedRestoreActiveStateOperationV1::Checkpoint(
                        checkpoint,
                    ),
                ),
            ),
        };
        let identity_digest = TenantRootIdentityDigestV1::from_bytes(decode_fixed_base64url_32(
            "tenant-root active-state read identity digest",
            &identity_digest_b64u,
        )?);
        let custody_lineage = decode_lineage_b64u(
            "tenant-root active-state read custody lineage",
            &custody_lineage_b64u,
        )?;
        let _authority_id = authority_id_from_object_id(&self.authority_object_id)?;
        require_tenant_root_creation_authority_object_v1(
            &self.env,
            &self.authority_object_id,
            identity_digest,
            custody_lineage,
        )?;
        let active = self.load_authoritative_active_refresh_state().await?;
        if active.identity_digest != identity_digest || active.custody_lineage != custody_lineage {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ForbiddenLocalBinding,
                "tenant-root active state does not match the requested identity and custody lineage",
            ));
        }
        if let (
            Some(refresh_context_b64u),
            Some(deriver_a_refresh_command_b64u),
            Some(deriver_b_refresh_command_b64u),
        ) = (
            refresh_context_b64u,
            deriver_a_refresh_command_b64u,
            deriver_b_refresh_command_b64u,
        ) {
            return self
                .reserve_refresh_attempt(
                    active,
                    identity_digest,
                    custody_lineage,
                    refresh_context_b64u,
                    deriver_a_refresh_command_b64u,
                    deriver_b_refresh_command_b64u,
                )
                .await;
        }
        if let Some(operation) = managed_restore_operation {
            return match operation {
                CloudflareTenantRootManagedRestoreActiveStateOperationV1::Reserve(
                    authorization,
                ) => {
                    self.reserve_managed_restore_authorization(
                        active,
                        identity_digest,
                        custody_lineage,
                        authorization,
                    )
                    .await
                }
                CloudflareTenantRootManagedRestoreActiveStateOperationV1::Checkpoint(
                    checkpoint,
                ) => {
                    self.checkpoint_managed_restore_authorization(
                        active,
                        identity_digest,
                        custody_lineage,
                        checkpoint,
                    )
                    .await
                }
            };
        }
        Ok(active_state_read_response_from_record(active.record))
    }

    async fn reserve_managed_restore_authorization(
        &self,
        loaded_active: ValidatedTenantRootRefreshActiveStateV1,
        identity_digest: TenantRootIdentityDigestV1,
        custody_lineage: TenantRootCustodyLineageId,
        authorization: CloudflareTenantRootManagedRestoreAuthorizationRequestV1,
    ) -> RouterAbProtocolResult<CloudflareTenantRootCreationActiveStateReadResponseV1> {
        if loaded_active.identity_digest != identity_digest
            || loaded_active.custody_lineage != custody_lineage
        {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ForbiddenLocalBinding,
                "tenant-root managed-restore reservation identity changed",
            ));
        }
        let issuer_keys_json = read_required_worker_var(
            &self.env,
            crate::TENANT_ROOT_CONTROL_PLANE_ISSUER_VERIFYING_KEYS_JSON_ENV,
        )?;
        let issuer_keys = crate::env::decode_issuer_verifying_keys(&issuer_keys_json)?;
        let authority_id = authority_id_from_object_id(&self.authority_object_id)?;
        let now_ms = crate::cloudflare_now_unix_ms_v1()?;
        let outcome: Rc<
            RefCell<
                Option<
                    RouterAbProtocolResult<CloudflareTenantRootCreationActiveStateReadResponseV1>,
                >,
            >,
        > = Rc::new(RefCell::new(None));
        let outcome_for_transaction = Rc::clone(&outcome);
        self.storage
            .transaction(move |transaction| async move {
                let active_record = match transaction_get_optional::<
                    CloudflareTenantRootRefreshActiveStateRecordV1,
                >(
                    &transaction,
                    TENANT_ROOT_REFRESH_ACTIVE_STATE_STORAGE_KEY_V1,
                )
                .await
                {
                    Ok(Some(record)) => record,
                    Ok(None) => {
                        outcome_for_transaction.replace(Some(Err(
                            RouterAbProtocolError::new(
                                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                                "tenant-root managed-restore reservation has no authoritative active public state",
                            ),
                        )));
                        return Ok(());
                    }
                    Err(error) => return Err(error),
                };
                let active = match validate_refresh_active_state_record(
                    active_record,
                    authority_id,
                    &issuer_keys,
                ) {
                    Ok(value) => value,
                    Err(error) => {
                        outcome_for_transaction
                            .replace(Some(Err(stored_refresh_record_error(error))));
                        return Ok(());
                    }
                };
                if active.identity_digest != identity_digest
                    || active.custody_lineage != custody_lineage
                {
                    outcome_for_transaction.replace(Some(Err(
                        RouterAbProtocolError::new(
                            RouterAbProtocolErrorCode::ForbiddenLocalBinding,
                            "tenant-root managed-restore reservation identity changed",
                        ),
                    )));
                    return Ok(());
                }
                let journal_record = match transaction_get_optional::<
                    CloudflareTenantRootCreationJournalRecordV1,
                >(
                    &transaction,
                    TENANT_ROOT_CREATION_JOURNAL_STORAGE_KEY_V1,
                )
                .await
                {
                    Ok(Some(record)) => record,
                    Ok(None) => {
                        outcome_for_transaction.replace(Some(Err(
                            RouterAbProtocolError::new(
                                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                                "tenant-root managed-restore reservation has no Started journal",
                            ),
                        )));
                        return Ok(());
                    }
                    Err(error) => return Err(error),
                };
                let journal = match validate_creation_record(journal_record, authority_id, &issuer_keys)
                {
                    Ok(value) => value,
                    Err(error) => {
                        outcome_for_transaction.replace(Some(Err(stored_record_error(error))));
                        return Ok(());
                    }
                };
                let evaluation = match reserve_managed_restore_authorization_fence_v1(
                    &active,
                    &journal,
                    authorization,
                    now_ms,
                ) {
                    Ok(value) => value,
                    Err(error) => {
                        outcome_for_transaction.replace(Some(Err(error)));
                        return Ok(());
                    }
                };
                let response_record = match evaluation {
                    CloudflareTenantRootManagedRestoreFenceEvaluationV1::Commit { fence } => {
                        let mut candidate = active.record.clone();
                        candidate.managed_restore_fence = fence;
                        if let Err(error) = validate_refresh_active_state_record(
                            candidate.clone(),
                            authority_id,
                            &issuer_keys,
                        ) {
                            outcome_for_transaction.replace(Some(Err(error)));
                            return Ok(());
                        }
                        transaction
                            .put(
                                TENANT_ROOT_REFRESH_ACTIVE_STATE_STORAGE_KEY_V1,
                                &candidate,
                            )
                            .await?;
                        candidate
                    }
                    CloudflareTenantRootManagedRestoreFenceEvaluationV1::Replay { .. } => {
                        active.record
                    }
                };
                outcome_for_transaction.replace(Some(Ok(
                    active_state_read_response_from_record(response_record),
                )));
                Ok(())
            })
            .await
            .map_err(durable_storage_protocol_error)?;
        let outcome = outcome.borrow_mut().take().ok_or_else(|| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "tenant-root managed-restore reservation transaction did not produce an outcome",
            )
        })?;
        outcome
    }

    async fn checkpoint_managed_restore_authorization(
        &self,
        loaded_active: ValidatedTenantRootRefreshActiveStateV1,
        identity_digest: TenantRootIdentityDigestV1,
        custody_lineage: TenantRootCustodyLineageId,
        checkpoint: CloudflareTenantRootManagedRestoreAuthorizationCheckpointV1,
    ) -> RouterAbProtocolResult<CloudflareTenantRootCreationActiveStateReadResponseV1> {
        if loaded_active.identity_digest != identity_digest
            || loaded_active.custody_lineage != custody_lineage
        {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ForbiddenLocalBinding,
                "tenant-root managed-restore checkpoint identity changed",
            ));
        }
        let issuer_keys_json = read_required_worker_var(
            &self.env,
            crate::TENANT_ROOT_CONTROL_PLANE_ISSUER_VERIFYING_KEYS_JSON_ENV,
        )?;
        let issuer_keys = crate::env::decode_issuer_verifying_keys(&issuer_keys_json)?;
        let authority_id = authority_id_from_object_id(&self.authority_object_id)?;
        let outcome: Rc<
            RefCell<
                Option<
                    RouterAbProtocolResult<CloudflareTenantRootCreationActiveStateReadResponseV1>,
                >,
            >,
        > = Rc::new(RefCell::new(None));
        let outcome_for_transaction = Rc::clone(&outcome);
        self.storage
            .transaction(move |transaction| async move {
                let active_record = match transaction_get_optional::<
                    CloudflareTenantRootRefreshActiveStateRecordV1,
                >(
                    &transaction,
                    TENANT_ROOT_REFRESH_ACTIVE_STATE_STORAGE_KEY_V1,
                )
                .await
                {
                    Ok(Some(record)) => record,
                    Ok(None) => {
                        outcome_for_transaction.replace(Some(Err(
                            RouterAbProtocolError::new(
                                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                                "tenant-root managed-restore checkpoint has no authoritative active public state",
                            ),
                        )));
                        return Ok(());
                    }
                    Err(error) => return Err(error),
                };
                let active = match validate_refresh_active_state_record(
                    active_record,
                    authority_id,
                    &issuer_keys,
                ) {
                    Ok(value) => value,
                    Err(error) => {
                        outcome_for_transaction
                            .replace(Some(Err(stored_refresh_record_error(error))));
                        return Ok(());
                    }
                };
                if active.identity_digest != identity_digest
                    || active.custody_lineage != custody_lineage
                {
                    outcome_for_transaction.replace(Some(Err(
                        RouterAbProtocolError::new(
                            RouterAbProtocolErrorCode::ForbiddenLocalBinding,
                            "tenant-root managed-restore checkpoint identity changed",
                        ),
                    )));
                    return Ok(());
                }
                let journal_record = match transaction_get_optional::<
                    CloudflareTenantRootCreationJournalRecordV1,
                >(
                    &transaction,
                    TENANT_ROOT_CREATION_JOURNAL_STORAGE_KEY_V1,
                )
                .await
                {
                    Ok(Some(record)) => record,
                    Ok(None) => {
                        outcome_for_transaction.replace(Some(Err(
                            RouterAbProtocolError::new(
                                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                                "tenant-root managed-restore checkpoint has no Started journal",
                            ),
                        )));
                        return Ok(());
                    }
                    Err(error) => return Err(error),
                };
                let journal = match validate_creation_record(journal_record, authority_id, &issuer_keys)
                {
                    Ok(value) => value,
                    Err(error) => {
                        outcome_for_transaction.replace(Some(Err(stored_record_error(error))));
                        return Ok(());
                    }
                };
                if let Err(error) = require_managed_restore_challenge_matches_started_journal_v1(
                    &active,
                    &journal,
                    &checkpoint.challenge,
                ) {
                    outcome_for_transaction.replace(Some(Err(error)));
                    return Ok(());
                }
                let evaluation = match checkpoint_managed_restore_authorization_fence_v1(
                    &active,
                    checkpoint,
                ) {
                    Ok(value) => value,
                    Err(error) => {
                        outcome_for_transaction.replace(Some(Err(error)));
                        return Ok(());
                    }
                };
                let response_record = match evaluation {
                    CloudflareTenantRootManagedRestoreFenceEvaluationV1::Commit { fence } => {
                        let mut candidate = active.record.clone();
                        candidate.managed_restore_fence = fence;
                        if let Err(error) = validate_refresh_active_state_record(
                            candidate.clone(),
                            authority_id,
                            &issuer_keys,
                        ) {
                            outcome_for_transaction.replace(Some(Err(error)));
                            return Ok(());
                        }
                        transaction
                            .put(
                                TENANT_ROOT_REFRESH_ACTIVE_STATE_STORAGE_KEY_V1,
                                &candidate,
                            )
                            .await?;
                        candidate
                    }
                    CloudflareTenantRootManagedRestoreFenceEvaluationV1::Replay { .. } => {
                        active.record
                    }
                };
                outcome_for_transaction.replace(Some(Ok(
                    active_state_read_response_from_record(response_record),
                )));
                Ok(())
        })
            .await
            .map_err(durable_storage_protocol_error)?;
        let outcome = outcome.borrow_mut().take().ok_or_else(|| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "tenant-root managed-restore checkpoint transaction did not produce an outcome",
            )
        })?;
        outcome
    }

    async fn reserve_refresh_attempt(
        &self,
        loaded_active: ValidatedTenantRootRefreshActiveStateV1,
        identity_digest: TenantRootIdentityDigestV1,
        custody_lineage: TenantRootCustodyLineageId,
        refresh_context_b64u: String,
        deriver_a_refresh_command_b64u: String,
        deriver_b_refresh_command_b64u: String,
    ) -> RouterAbProtocolResult<CloudflareTenantRootCreationActiveStateReadResponseV1> {
        let context_bytes = decode_canonical_base64url(
            "tenant-root refresh reservation context",
            &refresh_context_b64u,
            8 * 1024,
            base64url_len_for_bytes(8 * 1024),
        )?;
        let context = TenantRootCeremonyContextV1::decode_canonical_bytes(&context_bytes)
            .map_err(candidate_derivation_error)?;
        let issuer_keys_json = read_required_worker_var(
            &self.env,
            crate::TENANT_ROOT_CONTROL_PLANE_ISSUER_VERIFYING_KEYS_JSON_ENV,
        )?;
        let issuer_keys = crate::env::decode_issuer_verifying_keys(&issuer_keys_json)?;
        let expected_authority_id = authority_id_from_object_id(&self.authority_object_id)?;
        let now_ms = crate::cloudflare_now_unix_ms_v1()?;
        let outcome: Rc<
            RefCell<
                Option<
                    RouterAbProtocolResult<CloudflareTenantRootCreationActiveStateReadResponseV1>,
                >,
            >,
        > = Rc::new(RefCell::new(None));
        let outcome_for_transaction = Rc::clone(&outcome);
        let active_identity = loaded_active.identity_digest;
        let active_lineage = loaded_active.custody_lineage;
        self.storage
            .transaction(move |transaction| async move {
                let active_record = match transaction_get_optional::<
                    CloudflareTenantRootRefreshActiveStateRecordV1,
                >(
                    &transaction,
                    TENANT_ROOT_REFRESH_ACTIVE_STATE_STORAGE_KEY_V1,
                )
                .await
                {
                    Ok(Some(record)) => record,
                    Ok(None) => {
                        outcome_for_transaction.replace(Some(Err(RouterAbProtocolError::new(
                            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                            "tenant-root refresh has no authoritative active public state",
                        ))));
                        return Ok(());
                    }
                    Err(error) => return Err(error),
                };
                let active = match validate_refresh_active_state_record(
                    active_record,
                    expected_authority_id,
                    &issuer_keys,
                ) {
                    Ok(value) => value,
                    Err(error) => {
                        outcome_for_transaction
                            .replace(Some(Err(stored_refresh_record_error(error))));
                        return Ok(());
                    }
                };
                if active.identity_digest != active_identity
                    || active.custody_lineage != active_lineage
                    || active.identity_digest != identity_digest
                    || active.custody_lineage != custody_lineage
                {
                    outcome_for_transaction.replace(Some(Err(RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::ForbiddenLocalBinding,
                        "tenant-root refresh reservation identity changed",
                    ))));
                    return Ok(());
                }
                let command_a = match validate_refresh_role_command(
                    &deriver_a_refresh_command_b64u,
                    &active,
                    &context,
                    TwoPartyDeriverRole::DeriverA,
                    expected_authority_id,
                    &issuer_keys,
                ) {
                    Ok(value) => value,
                    Err(error) => {
                        outcome_for_transaction.replace(Some(Err(error)));
                        return Ok(());
                    }
                };
                let command_b = match validate_refresh_role_command(
                    &deriver_b_refresh_command_b64u,
                    &active,
                    &context,
                    TwoPartyDeriverRole::DeriverB,
                    expected_authority_id,
                    &issuer_keys,
                ) {
                    Ok(value) => value,
                    Err(error) => {
                        outcome_for_transaction.replace(Some(Err(error)));
                        return Ok(());
                    }
                };
                let attempt = match refresh_attempt_from_commands(&context, &command_a, &command_b)
                {
                    Ok(value) => value,
                    Err(error) => {
                        outcome_for_transaction.replace(Some(Err(error)));
                        return Ok(());
                    }
                };
                if let Err(error) = require_fresh_refresh_command(&command_a, &context, now_ms)
                    .and_then(|_| require_fresh_refresh_command(&command_b, &context, now_ms))
                {
                    outcome_for_transaction.replace(Some(Err(error)));
                    return Ok(());
                }
                let response_record = match &active.record.fence {
                    CloudflareTenantRootRefreshFenceV1::Open => {
                        let mut record = active.record.clone();
                        record.fence = CloudflareTenantRootRefreshFenceV1::Reserved { attempt };
                        transaction
                            .put(TENANT_ROOT_REFRESH_ACTIVE_STATE_STORAGE_KEY_V1, &record)
                            .await?;
                        record
                    }
                    CloudflareTenantRootRefreshFenceV1::Reserved { attempt: stored }
                    | CloudflareTenantRootRefreshFenceV1::Executed { attempt: stored } => {
                        if let Err(error) = validate_refresh_attempt_packages(stored) {
                            outcome_for_transaction.replace(Some(Err(error)));
                            return Ok(());
                        }
                        active.record.clone()
                    }
                    CloudflareTenantRootRefreshFenceV1::Terminal { .. } => {
                        outcome_for_transaction.replace(Some(Err(RouterAbProtocolError::new(
                            RouterAbProtocolErrorCode::ConflictingPair,
                            "tenant-root refresh operation is terminal",
                        ))));
                        return Ok(());
                    }
                };
                let response = match response_record {
                    CloudflareTenantRootRefreshActiveStateRecordV1 {
                        activation_receipt_b64u,
                        activation_receipt_digest_b64u,
                        identity_digest_b64u,
                        custody_lineage_b64u,
                        lifecycle_revision,
                        fence,
                        managed_restore_fence,
                        ..
                    } => CloudflareTenantRootCreationActiveStateReadResponseV1 {
                        activation_receipt_b64u,
                        activation_receipt_digest_b64u,
                        identity_digest_b64u,
                        custody_lineage_b64u,
                        lifecycle_revision,
                        fence,
                        managed_restore_fence,
                    },
                };
                outcome_for_transaction.replace(Some(Ok(response)));
                Ok(())
            })
            .await
            .map_err(durable_storage_protocol_error)?;
        let outcome = outcome.borrow_mut().take().ok_or_else(|| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "tenant-root refresh reservation transaction did not produce an outcome",
            )
        })?;
        outcome
    }

    async fn load_role_creation_request(
        &self,
        command_b64u: &str,
    ) -> RouterAbProtocolResult<LoadedTenantRootRoleCreationRequestV1> {
        let issuer_keys_json = read_required_worker_var(
            &self.env,
            crate::TENANT_ROOT_CONTROL_PLANE_ISSUER_VERIFYING_KEYS_JSON_ENV,
        )?;
        let issuer_keys = crate::env::decode_issuer_verifying_keys(&issuer_keys_json)?;
        let authority_id = TenantRootControlPlaneAuthorityIdV1::from_bytes(decode_lower_hex_32(
            "tenant-root creation Durable Object id",
            &self.authority_object_id,
        )?);
        let journal_record = storage_get_optional::<CloudflareTenantRootCreationJournalRecordV1>(
            &self.storage,
            TENANT_ROOT_CREATION_JOURNAL_STORAGE_KEY_V1,
        )
        .await
        .map_err(durable_storage_protocol_error)?
        .ok_or_else(|| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "tenant-root role creation request has no Started journal",
            )
        })?;
        let journal = validate_creation_record(journal_record, authority_id, &issuer_keys)
            .map_err(stored_record_error)?;
        require_tenant_root_creation_authority_object_v1(
            &self.env,
            &self.authority_object_id,
            journal.identity_digest,
            journal.custody_lineage,
        )?;
        let command =
            validate_role_creation_command(command_b64u, &journal, authority_id, &issuer_keys)?;
        let role_keys = read_tenant_root_creation_role_verifying_keys(&self.env)?;
        let now_ms = crate::cloudflare_now_unix_ms_v1()?;
        Ok(LoadedTenantRootRoleCreationRequestV1 {
            journal,
            command,
            role_keys,
            now_ms,
        })
    }

    async fn persist(
        &self,
        request: CloudflareTenantRootCreationJournalRequestV1,
    ) -> RouterAbProtocolResult<CloudflareTenantRootCreationJournalResponseV1> {
        let verifying_keys_json = read_required_worker_var(
            &self.env,
            crate::TENANT_ROOT_CONTROL_PLANE_ISSUER_VERIFYING_KEYS_JSON_ENV,
        )?;
        let verifying_keys = crate::env::decode_issuer_verifying_keys(&verifying_keys_json)?;
        let authority_id = TenantRootControlPlaneAuthorityIdV1::from_bytes(decode_lower_hex_32(
            "tenant-root creation Durable Object id",
            &self.authority_object_id,
        )?);
        let candidate =
            validate_creation_record(request.into_record(), authority_id, &verifying_keys)?;
        require_tenant_root_creation_authority_object_v1(
            &self.env,
            &self.authority_object_id,
            candidate.identity_digest,
            candidate.custody_lineage,
        )?;
        let now_ms = crate::cloudflare_now_unix_ms_v1()?;
        let outcome: Rc<
            RefCell<Option<RouterAbProtocolResult<CloudflareTenantRootCreationJournalResponseV1>>>,
        > = Rc::new(RefCell::new(None));
        let outcome_for_transaction = Rc::clone(&outcome);
        self.storage
            .transaction(move |transaction| async move {
                let existing = match transaction_get_optional::<
                    CloudflareTenantRootCreationJournalRecordV1,
                >(
                    &transaction, TENANT_ROOT_CREATION_JOURNAL_STORAGE_KEY_V1
                )
                .await
                {
                    Ok(existing) => existing,
                    Err(error) => return Err(error),
                };
                match evaluate_creation_record(
                    existing,
                    candidate,
                    authority_id,
                    &verifying_keys,
                    now_ms,
                ) {
                    Ok(TenantRootCreationJournalEvaluationV1::Commit { record, response }) => {
                        transaction
                            .put(TENANT_ROOT_CREATION_JOURNAL_STORAGE_KEY_V1, &record)
                            .await?;
                        outcome_for_transaction.replace(Some(Ok(response)));
                    }
                    Ok(TenantRootCreationJournalEvaluationV1::Replay(response)) => {
                        outcome_for_transaction.replace(Some(Ok(response)));
                    }
                    Err(error) => {
                        outcome_for_transaction.replace(Some(Err(error)));
                    }
                }
                Ok(())
            })
            .await
            .map_err(durable_storage_protocol_error)?;
        let outcome = outcome.borrow_mut().take().ok_or_else(|| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "tenant-root creation journal transaction did not produce an outcome",
            )
        })?;
        outcome
    }

    pub(crate) async fn persist_creation_commitment_rendezvous(
        &self,
        request: CloudflareTenantRootCreationCommitmentRequestV1,
    ) -> RouterAbProtocolResult<CloudflareTenantRootCreationCommitmentResponseV1> {
        let loaded = self
            .load_role_creation_request(&request.role_creation_command_b64u)
            .await?;
        let candidate_bytes = decode_canonical_base64url(
            "tenant-root signed creation commitment",
            &request.signed_commitment_b64u,
            TENANT_ROOT_SIGNED_CREATION_COMMITMENT_MAX_BYTES_V1,
            TENANT_ROOT_CREATION_COMMITMENT_MAX_BASE64URL_BYTES_V1,
        )?;
        let response_candidate_bytes = candidate_bytes.clone();
        let journal = loaded.journal;
        let command = loaded.command;
        let role_keys = loaded.role_keys;
        let now_ms = loaded.now_ms;
        let response_scope = creation_response_scope(&command, &journal)?;
        let commitment_bytes = candidate_bytes;
        let outcome: Rc<
            RefCell<
                Option<RouterAbProtocolResult<CloudflareTenantRootCreationCommitmentOutcomeV1>>,
            >,
        > = Rc::new(RefCell::new(None));
        let outcome_for_transaction = Rc::clone(&outcome);
        self.storage
            .transaction(move |transaction| async move {
                let existing = match transaction_get_optional::<
                    CloudflareTenantRootCreationCommitmentRendezvousRecordV1,
                >(
                    &transaction,
                    TENANT_ROOT_CREATION_COMMITMENT_RENDEZVOUS_STORAGE_KEY_V1,
                )
                .await
                {
                    Ok(existing) => existing,
                    Err(error) => return Err(error),
                };
                match evaluate_creation_commitment_rendezvous(
                    existing,
                    &commitment_bytes,
                    &command,
                    &journal,
                    &role_keys,
                    now_ms,
                ) {
                    Ok(TenantRootCreationCommitmentRendezvousEvaluationV1::Commit {
                        rendezvous,
                        outcome,
                    }) => {
                        transaction
                            .put(
                                TENANT_ROOT_CREATION_COMMITMENT_RENDEZVOUS_STORAGE_KEY_V1,
                                &rendezvous,
                            )
                            .await?;
                        outcome_for_transaction.replace(Some(Ok(outcome)));
                    }
                    Ok(TenantRootCreationCommitmentRendezvousEvaluationV1::Replay(outcome)) => {
                        outcome_for_transaction.replace(Some(Ok(outcome)));
                    }
                    Err(error) => {
                        outcome_for_transaction.replace(Some(Err(error)));
                    }
                }
                Ok(())
            })
            .await
            .map_err(durable_storage_protocol_error)?;
        let outcome = outcome.borrow_mut().take().ok_or_else(|| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "tenant-root creation commitment transaction did not produce an outcome",
            )
        })?;
        commitment_response(response_scope, &response_candidate_bytes, outcome?)
    }

    pub(crate) async fn persist_installation_checkpoint(
        &self,
        request: CloudflareTenantRootCreationInstallationRequestV1,
    ) -> RouterAbProtocolResult<CloudflareTenantRootCreationInstallationResponseV1> {
        let loaded = self
            .load_role_creation_request(&request.role_creation_command_b64u)
            .await?;
        let evidence = validate_installation_evidence_wire(
            &request.signed_evidence_b64u,
            &loaded.journal.ceremony_context,
            &loaded.role_keys,
        )?;
        let journal = loaded.journal;
        let command = loaded.command;
        let role_keys = loaded.role_keys;
        let now_ms = loaded.now_ms;
        let response_scope = creation_response_scope(&command, &journal)?;
        let outcome: Rc<
            RefCell<
                Option<RouterAbProtocolResult<CloudflareTenantRootCreationInstallationOutcomeV1>>,
            >,
        > = Rc::new(RefCell::new(None));
        let outcome_for_transaction = Rc::clone(&outcome);
        self.storage
            .transaction(move |transaction| async move {
                let commitment_record = match transaction_get_optional::<
                    CloudflareTenantRootCreationCommitmentRendezvousRecordV1,
                >(
                    &transaction,
                    TENANT_ROOT_CREATION_COMMITMENT_RENDEZVOUS_STORAGE_KEY_V1,
                )
                .await
                {
                    Ok(commitment_record) => commitment_record,
                    Err(error) => return Err(error),
                };
                let commitments = match require_complete_creation_commitment_rendezvous(
                    commitment_record,
                    &journal,
                    &role_keys,
                ) {
                    Ok(commitments) => commitments,
                    Err(error) => {
                        outcome_for_transaction.replace(Some(Err(error)));
                        return Ok(());
                    }
                };
                let existing = match transaction_get_optional::<
                    CloudflareTenantRootCreationInstallationCheckpointV1,
                >(
                    &transaction,
                    TENANT_ROOT_CREATION_INSTALLATION_CHECKPOINT_STORAGE_KEY_V1,
                )
                .await
                {
                    Ok(existing) => existing,
                    Err(error) => return Err(error),
                };
                let cleanup = match transaction_get_optional::<
                    CloudflareTenantRootCreationCleanupCheckpointV1,
                >(
                    &transaction,
                    TENANT_ROOT_CREATION_CLEANUP_CHECKPOINT_STORAGE_KEY_V1,
                )
                .await
                {
                    Ok(cleanup) => cleanup,
                    Err(error) => return Err(error),
                };
                if cleanup.is_some() {
                    outcome_for_transaction.replace(Some(Err(RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::ConflictingPair,
                        "tenant-root installation cannot resume after cleanup",
                    ))));
                    return Ok(());
                }
                match evaluate_installation_checkpoint(
                    existing,
                    evidence,
                    &command,
                    &journal,
                    &role_keys,
                    &commitments,
                    now_ms,
                ) {
                    Ok(TenantRootCreationInstallationEvaluationV1::Commit {
                        checkpoint,
                        outcome,
                    }) => {
                        transaction
                            .put(
                                TENANT_ROOT_CREATION_INSTALLATION_CHECKPOINT_STORAGE_KEY_V1,
                                &checkpoint,
                            )
                            .await?;
                        outcome_for_transaction.replace(Some(Ok(outcome)));
                    }
                    Ok(TenantRootCreationInstallationEvaluationV1::Replay(outcome)) => {
                        outcome_for_transaction.replace(Some(Ok(outcome)));
                    }
                    Err(error) => {
                        outcome_for_transaction.replace(Some(Err(error)));
                    }
                }
                Ok(())
            })
            .await
            .map_err(durable_storage_protocol_error)?;
        let outcome = outcome.borrow_mut().take().ok_or_else(|| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "tenant-root installation checkpoint transaction did not produce an outcome",
            )
        })?;
        installation_response(response_scope, outcome?)
    }

    pub(crate) async fn persist_creation_cleanup_checkpoint(
        &self,
        request: CloudflareTenantRootCreationCleanupRequestV1,
    ) -> RouterAbProtocolResult<CloudflareTenantRootCreationCleanupResponseV1> {
        let issuer_keys_json = read_required_worker_var(
            &self.env,
            crate::TENANT_ROOT_CONTROL_PLANE_ISSUER_VERIFYING_KEYS_JSON_ENV,
        )?;
        let issuer_keys = crate::env::decode_issuer_verifying_keys(&issuer_keys_json)?;
        let role_keys = read_tenant_root_creation_role_verifying_keys(&self.env)?;
        let authority_id = authority_id_from_object_id(&self.authority_object_id)?;
        let journal_record = storage_get_optional::<CloudflareTenantRootCreationJournalRecordV1>(
            &self.storage,
            TENANT_ROOT_CREATION_JOURNAL_STORAGE_KEY_V1,
        )
        .await
        .map_err(durable_storage_protocol_error)?
        .ok_or_else(|| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "tenant-root creation cleanup has no Started journal",
            )
        })?;
        let journal = validate_creation_record(journal_record, authority_id, &issuer_keys)
            .map_err(stored_record_error)?;
        require_tenant_root_creation_authority_object_v1(
            &self.env,
            &self.authority_object_id,
            journal.identity_digest,
            journal.custody_lineage,
        )?;
        let now_ms = crate::cloudflare_now_unix_ms_v1()?;
        let outcome: Rc<
            RefCell<Option<RouterAbProtocolResult<CloudflareTenantRootCreationCleanupResponseV1>>>,
        > = Rc::new(RefCell::new(None));
        let outcome_for_transaction = Rc::clone(&outcome);
        self.storage
            .transaction(move |transaction| async move {
                let commitment_record = match transaction_get_optional::<
                    CloudflareTenantRootCreationCommitmentRendezvousRecordV1,
                >(
                    &transaction,
                    TENANT_ROOT_CREATION_COMMITMENT_RENDEZVOUS_STORAGE_KEY_V1,
                )
                .await
                {
                    Ok(record) => record,
                    Err(error) => return Err(error),
                };
                let commitments = match require_complete_creation_commitment_rendezvous(
                    commitment_record,
                    &journal,
                    &role_keys,
                ) {
                    Ok(commitments) => commitments,
                    Err(error) => {
                        outcome_for_transaction.replace(Some(Err(error)));
                        return Ok(());
                    }
                };
                let installation_record = match transaction_get_optional::<
                    CloudflareTenantRootCreationInstallationCheckpointV1,
                >(
                    &transaction,
                    TENANT_ROOT_CREATION_INSTALLATION_CHECKPOINT_STORAGE_KEY_V1,
                )
                .await
                {
                    Ok(Some(record)) => record,
                    Ok(None) => {
                        outcome_for_transaction.replace(Some(Err(RouterAbProtocolError::new(
                            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                            "tenant-root creation cleanup has no installation checkpoint",
                        ))));
                        return Ok(());
                    }
                    Err(error) => return Err(error),
                };
                let installation = match validate_installation_checkpoint(
                    installation_record,
                    &journal,
                    &role_keys,
                    &commitments,
                ) {
                    Ok(installation) => installation,
                    Err(error) => {
                        outcome_for_transaction.replace(Some(Err(stored_record_error(error))));
                        return Ok(());
                    }
                };
                let (_, role) = match creation_cleanup_target(&journal, &installation) {
                    Ok(target) => target,
                    Err(error) => {
                        outcome_for_transaction.replace(Some(Err(error)));
                        return Ok(());
                    }
                };
                let candidate_record =
                    match creation_cleanup_checkpoint_record(request, &journal, role) {
                        Ok(record) => record,
                        Err(error) => {
                            outcome_for_transaction.replace(Some(Err(error)));
                            return Ok(());
                        }
                    };
                let candidate = match validate_creation_cleanup_checkpoint(
                    candidate_record,
                    &journal,
                    &installation,
                    authority_id,
                    &issuer_keys,
                    &role_keys,
                ) {
                    Ok(candidate) => candidate,
                    Err(error) => {
                        outcome_for_transaction.replace(Some(Err(error)));
                        return Ok(());
                    }
                };
                let existing = match transaction_get_optional::<
                    CloudflareTenantRootCreationCleanupCheckpointV1,
                >(
                    &transaction,
                    TENANT_ROOT_CREATION_CLEANUP_CHECKPOINT_STORAGE_KEY_V1,
                )
                .await
                {
                    Ok(existing) => existing,
                    Err(error) => return Err(error),
                };
                match evaluate_creation_cleanup_checkpoint(
                    existing,
                    candidate,
                    &journal,
                    &installation,
                    authority_id,
                    &issuer_keys,
                    &role_keys,
                    now_ms,
                ) {
                    Ok(TenantRootCreationCleanupEvaluationV1::Commit {
                        checkpoint,
                        response,
                    }) => {
                        transaction
                            .put(
                                TENANT_ROOT_CREATION_CLEANUP_CHECKPOINT_STORAGE_KEY_V1,
                                &checkpoint,
                            )
                            .await?;
                        outcome_for_transaction.replace(Some(Ok(response)));
                    }
                    Ok(TenantRootCreationCleanupEvaluationV1::Replay(response)) => {
                        outcome_for_transaction.replace(Some(Ok(response)));
                    }
                    Err(error) => {
                        outcome_for_transaction.replace(Some(Err(error)));
                    }
                }
                Ok(())
            })
            .await
            .map_err(durable_storage_protocol_error)?;
        let outcome = outcome.borrow_mut().take().ok_or_else(|| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "tenant-root creation cleanup transaction did not produce an outcome",
            )
        })?;
        outcome
    }

    pub(crate) async fn persist_initial_activation(
        &self,
        request: CloudflareTenantRootCreationInitialActivationRequestV1,
    ) -> RouterAbProtocolResult<CloudflareTenantRootCreationInitialActivationResponseV1> {
        let issuer_keys_json = read_required_worker_var(
            &self.env,
            crate::TENANT_ROOT_CONTROL_PLANE_ISSUER_VERIFYING_KEYS_JSON_ENV,
        )?;
        let issuer_keys = crate::env::decode_issuer_verifying_keys(&issuer_keys_json)?;
        let authority_id = authority_id_from_object_id(&self.authority_object_id)?;
        let activation_receipt = decode_and_verify_initial_activation_receipt(
            &request.activation_receipt_b64u,
            &issuer_keys,
        )?;
        require_tenant_root_creation_authority_object_v1(
            &self.env,
            &self.authority_object_id,
            activation_receipt.identity_digest(),
            activation_receipt.custody_lineage(),
        )?;
        if activation_receipt.binding().authority_id() != authority_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ForbiddenLocalBinding,
                "tenant-root initial activation receipt authority does not match its Durable Object",
            ));
        }

        let role_keys = read_tenant_root_creation_role_verifying_keys(&self.env)?;
        let receipt_digest = activation_receipt.digest();
        let lifecycle_revision = activation_receipt.result_control_plane_revision();
        let outcome: Rc<RefCell<Option<RouterAbProtocolResult<()>>>> = Rc::new(RefCell::new(None));
        let outcome_for_transaction = Rc::clone(&outcome);
        self.storage
            .transaction(move |transaction| async move {
                let journal_record =
                    match transaction_get_optional::<CloudflareTenantRootCreationJournalRecordV1>(
                        &transaction,
                        TENANT_ROOT_CREATION_JOURNAL_STORAGE_KEY_V1,
                    )
                    .await
                    {
                        Ok(Some(record)) => record,
                        Ok(None) => {
                            outcome_for_transaction.replace(Some(Err(RouterAbProtocolError::new(
                                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                                "tenant-root initial activation has no Started journal",
                            ))));
                            return Ok(());
                        }
                        Err(error) => return Err(error),
                    };
                let journal =
                    match validate_creation_record(journal_record, authority_id, &issuer_keys) {
                        Ok(journal) => journal,
                        Err(error) => {
                            outcome_for_transaction.replace(Some(Err(stored_record_error(error))));
                            return Ok(());
                        }
                    };
                let commitment_record = match transaction_get_optional::<
                    CloudflareTenantRootCreationCommitmentRendezvousRecordV1,
                >(
                    &transaction,
                    TENANT_ROOT_CREATION_COMMITMENT_RENDEZVOUS_STORAGE_KEY_V1,
                )
                .await
                {
                    Ok(record) => record,
                    Err(error) => return Err(error),
                };
                let commitments = match require_complete_creation_commitment_rendezvous(
                    commitment_record,
                    &journal,
                    &role_keys,
                ) {
                    Ok(commitments) => commitments,
                    Err(error) => {
                        outcome_for_transaction.replace(Some(Err(error)));
                        return Ok(());
                    }
                };
                let installation_record = match transaction_get_optional::<
                    CloudflareTenantRootCreationInstallationCheckpointV1,
                >(
                    &transaction,
                    TENANT_ROOT_CREATION_INSTALLATION_CHECKPOINT_STORAGE_KEY_V1,
                )
                .await
                {
                    Ok(Some(record)) => record,
                    Ok(None) => {
                        outcome_for_transaction.replace(Some(Err(RouterAbProtocolError::new(
                            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                            "tenant-root initial activation has no installation checkpoint",
                        ))));
                        return Ok(());
                    }
                    Err(error) => return Err(error),
                };
                let installation = match validate_installation_checkpoint(
                    installation_record,
                    &journal,
                    &role_keys,
                    &commitments,
                ) {
                    Ok(installation) => installation,
                    Err(error) => {
                        outcome_for_transaction.replace(Some(Err(stored_record_error(error))));
                        return Ok(());
                    }
                };
                let cleanup_checkpointed = match transaction_get_optional::<
                    CloudflareTenantRootCreationCleanupCheckpointV1,
                >(
                    &transaction,
                    TENANT_ROOT_CREATION_CLEANUP_CHECKPOINT_STORAGE_KEY_V1,
                )
                .await
                {
                    Ok(cleanup) => cleanup.is_some(),
                    Err(error) => return Err(error),
                };
                if cleanup_checkpointed {
                    outcome_for_transaction.replace(Some(Err(RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::ConflictingPair,
                        "tenant-root initial activation cannot follow creation cleanup",
                    ))));
                    return Ok(());
                }
                if let Err(error) = validate_initial_activation_receipt_against_creation_state(
                    &activation_receipt,
                    &journal,
                    &installation,
                ) {
                    outcome_for_transaction.replace(Some(Err(error)));
                    return Ok(());
                }
                let candidate = match refresh_active_state_record_from_verified_receipt(
                    activation_receipt,
                    lifecycle_revision,
                ) {
                    Ok(candidate) => candidate,
                    Err(error) => {
                        outcome_for_transaction.replace(Some(Err(error)));
                        return Ok(());
                    }
                };
                let result = Self::persist_authoritative_active_state_in_transaction_v1(
                    &transaction,
                    candidate,
                    authority_id,
                    &issuer_keys,
                )
                .await;
                outcome_for_transaction.replace(Some(result));
                Ok(())
            })
            .await
            .map_err(durable_storage_protocol_error)?;
        let outcome = outcome.borrow_mut().take().ok_or_else(|| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "tenant-root initial activation transaction did not produce an outcome",
            )
        })?;
        outcome?;
        Ok(CloudflareTenantRootCreationInitialActivationResponseV1 {
            activation_receipt_digest_b64u: encode_base64url_bytes_v1(receipt_digest.as_bytes()),
            lifecycle_revision,
        })
    }

    pub(crate) async fn persist_refresh_activation(
        &self,
        request: CloudflareTenantRootRefreshActivationRequestV1,
    ) -> RouterAbProtocolResult<CloudflareTenantRootRefreshActivationResponseV1> {
        let issuer_keys_json = read_required_worker_var(
            &self.env,
            crate::TENANT_ROOT_CONTROL_PLANE_ISSUER_VERIFYING_KEYS_JSON_ENV,
        )?;
        let issuer_keys = crate::env::decode_issuer_verifying_keys(&issuer_keys_json)?;
        let activation_receipt = decode_and_verify_refresh_activation_receipt(
            &request.activation_receipt_b64u,
            &issuer_keys,
        )?;
        let authority_id = authority_id_from_object_id(&self.authority_object_id)?;
        require_tenant_root_creation_authority_object_v1(
            &self.env,
            &self.authority_object_id,
            activation_receipt.identity_digest(),
            activation_receipt.custody_lineage(),
        )?;
        if activation_receipt.binding().authority_id() != authority_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ForbiddenLocalBinding,
                "tenant-root refresh activation receipt authority does not match its Durable Object",
            ));
        }
        let receipt_digest = activation_receipt.digest();
        let lifecycle_revision = activation_receipt.result_control_plane_revision();
        self.persist_authoritative_active_refresh_state_v1(activation_receipt, lifecycle_revision)
            .await?;
        Ok(CloudflareTenantRootRefreshActivationResponseV1 {
            activation_receipt_digest_b64u: encode_base64url_bytes_v1(receipt_digest.as_bytes()),
            lifecycle_revision,
        })
    }

    /// Applies the authoritative active-state write inside an existing
    /// Durable Object transaction. The transaction owns exact replay/conflict
    /// handling for every activation path.
    #[cfg(feature = "workers-rs")]
    async fn persist_authoritative_active_state_in_transaction_v1(
        transaction: &worker::Transaction,
        candidate: CloudflareTenantRootRefreshActiveStateRecordV1,
        authority_id: TenantRootControlPlaneAuthorityIdV1,
        issuer_keys: &BTreeMap<String, [u8; 32]>,
    ) -> RouterAbProtocolResult<()> {
        let existing = transaction_get_optional::<CloudflareTenantRootRefreshActiveStateRecordV1>(
            transaction,
            TENANT_ROOT_REFRESH_ACTIVE_STATE_STORAGE_KEY_V1,
        )
        .await
        .map_err(durable_storage_protocol_error)?;
        let Some(existing) = existing else {
            transaction
                .put(TENANT_ROOT_REFRESH_ACTIVE_STATE_STORAGE_KEY_V1, &candidate)
                .await
                .map_err(durable_storage_protocol_error)?;
            return Ok(());
        };
        let existing_validated =
            validate_refresh_active_state_record(existing, authority_id, issuer_keys)
                .map_err(stored_refresh_record_error)?;
        let existing_projection = refresh_active_state_projection(&existing_validated.record);
        if existing_projection == refresh_active_state_projection(&candidate) {
            Ok(())
        } else {
            Err(refresh_replay_conflict(
                "tenant-root refresh active state conflicts with the accepted activation receipt",
            ))
        }
    }

    #[cfg(feature = "workers-rs")]
    async fn persist_authoritative_active_refresh_state_in_transaction_v1(
        transaction: &worker::Transaction,
        mut candidate: CloudflareTenantRootRefreshActiveStateRecordV1,
        authority_id: TenantRootControlPlaneAuthorityIdV1,
        issuer_keys: &BTreeMap<String, [u8; 32]>,
        role_keys: &TenantRootCreationRoleVerifyingKeysV1,
    ) -> RouterAbProtocolResult<()> {
        let existing_record = transaction_get_optional::<
            CloudflareTenantRootRefreshActiveStateRecordV1,
        >(
            transaction, TENANT_ROOT_REFRESH_ACTIVE_STATE_STORAGE_KEY_V1
        )
        .await
        .map_err(durable_storage_protocol_error)?
        .ok_or_else(|| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLifecycleState,
                "tenant-root refresh activation has no authoritative active public state",
            )
        })?;
        let existing =
            validate_refresh_active_state_record(existing_record, authority_id, issuer_keys)
                .map_err(stored_refresh_record_error)?;
        if refresh_active_state_projection(&existing.record)
            == refresh_active_state_projection(&candidate)
        {
            return Ok(());
        }

        let attempt = match &existing.record.fence {
            CloudflareTenantRootRefreshFenceV1::Executed { attempt } => attempt.clone(),
            CloudflareTenantRootRefreshFenceV1::Open
            | CloudflareTenantRootRefreshFenceV1::Reserved { .. } => {
                return Err(RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::MissingPairPreparation,
                    "tenant-root refresh activation requires an executed refresh attempt",
                ));
            }
            CloudflareTenantRootRefreshFenceV1::Terminal { .. } => {
                return Err(refresh_replay_conflict(
                    "tenant-root refresh activation conflicts with the terminal refresh state",
                ));
            }
        };
        candidate.fence = CloudflareTenantRootRefreshFenceV1::Terminal {
            attempt,
            outcome: CloudflareTenantRootRefreshTerminalOutcomeV1::Completed,
            response: refresh_terminal_response_from_record(&candidate),
        };
        candidate.managed_restore_fence = match &existing.record.managed_restore_fence {
            CloudflareTenantRootManagedRestoreFenceV1::Open => {
                CloudflareTenantRootManagedRestoreFenceV1::Open
            }
            CloudflareTenantRootManagedRestoreFenceV1::Terminal { .. } => {
                existing.record.managed_restore_fence.clone()
            }
            CloudflareTenantRootManagedRestoreFenceV1::Reserved { .. } => {
                return Err(managed_restore_conflict(
                    "tenant-root refresh activation conflicts with a reserved managed-restore authorization",
                ));
            }
        };

        let candidate_state =
            validate_refresh_active_state_record(candidate.clone(), authority_id, issuer_keys)?;
        validate_refresh_active_state_transition_v1(&existing, &candidate_state)?;

        let expected_scope =
            refresh_activation_checkpoint_scope_v1(&existing, &candidate_state.activation_receipt)?;
        let commitment_encoded = transaction_get_optional::<String>(
            transaction,
            TENANT_ROOT_REFRESH_COMMITMENT_CHECKPOINT_STORAGE_KEY_V1,
        )
        .await
        .map_err(durable_storage_protocol_error)?
        .ok_or_else(|| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MissingPairPreparation,
                "tenant-root refresh activation has no commitment checkpoint",
            )
        })?;
        let commitment_checkpoint = decode_refresh_commitment_checkpoint(&commitment_encoded)
            .map_err(stored_refresh_record_error)?;
        validate_refresh_commitment_checkpoint_scope(
            commitment_checkpoint.scope(),
            &expected_scope,
        )
        .map_err(stored_refresh_record_error)?;
        let deriver_a_commitment = commitment_checkpoint
            .state()
            .deriver_a_signed_commitment()
            .ok_or_else(|| {
                RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::MissingPairPreparation,
                    "tenant-root refresh activation requires both commitments",
                )
            })?;
        let commitment =
            TenantRootSignedRefreshCommitmentV1::decode_canonical_bytes(deriver_a_commitment)
                .map_err(candidate_derivation_error)?;
        let context = commitment.transcript().context().clone();
        let commitments = require_complete_refresh_commitment_checkpoint(
            &commitment_checkpoint,
            &context,
            role_keys,
        )
        .map_err(stored_refresh_record_error)?;
        let installation_record =
            transaction_get_optional::<CloudflareTenantRootRefreshInstallationCheckpointRecordV1>(
                transaction,
                TENANT_ROOT_REFRESH_INSTALLATION_CHECKPOINT_STORAGE_KEY_V1,
            )
            .await
            .map_err(durable_storage_protocol_error)?
            .ok_or_else(|| {
                RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::MissingPairPreparation,
                    "tenant-root refresh activation has no installation checkpoint",
                )
            })?;
        let installation = validate_refresh_installation_checkpoint(
            installation_record,
            &expected_scope,
            &context,
            role_keys,
            &commitments,
            &existing.commitments,
        )
        .map_err(stored_refresh_record_error)?;
        let ValidatedTenantRootRefreshInstallationStateV1::BothRoles {
            deriver_a,
            deriver_b,
            root_commitment,
            ..
        } = installation
        else {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MissingPairPreparation,
                "tenant-root refresh activation requires both roles ready",
            ));
        };
        let next_commitments = verify_tenant_root_refresh_installation_transition_v1(
            &existing.commitments,
            &commitments,
            &deriver_a,
            &deriver_b,
        )
        .map_err(candidate_derivation_error)
        .map_err(stored_refresh_record_error)?;
        let TenantRootActivationReceiptBindingV1::RefreshSwap(binding) =
            candidate_state.activation_receipt.binding()
        else {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ForbiddenLocalBinding,
                "tenant-root refresh activation requires a refresh-swap receipt",
            ));
        };
        if &next_commitments != binding.next_commitments()
            || root_commitment != *binding.next_commitments().root_commitment()
            || deriver_a
                .lifecycle_receipt_digest()
                .map_err(candidate_derivation_error)?
                != binding.installation_receipts().deriver_a()
            || deriver_b
                .lifecycle_receipt_digest()
                .map_err(candidate_derivation_error)?
                != binding.installation_receipts().deriver_b()
        {
            return Err(refresh_replay_conflict(
                "tenant-root refresh activation receipt does not match the installation checkpoint",
            ));
        }

        transaction
            .put(TENANT_ROOT_REFRESH_ACTIVE_STATE_STORAGE_KEY_V1, &candidate)
            .await
            .map_err(durable_storage_protocol_error)?;
        transaction
            .delete(TENANT_ROOT_REFRESH_COMMITMENT_CHECKPOINT_STORAGE_KEY_V1)
            .await
            .map_err(durable_storage_protocol_error)?;
        transaction
            .delete(TENANT_ROOT_REFRESH_INSTALLATION_CHECKPOINT_STORAGE_KEY_V1)
            .await
            .map_err(durable_storage_protocol_error)?;
        Ok(())
    }

    /// Persists the public active state only from an already issuer-verified
    /// activation receipt. Checkpoint routes never call this method.
    pub(crate) async fn persist_authoritative_active_refresh_state_v1(
        &self,
        activation_receipt: router_ab_core::VerifiedTenantRootSignedActivationReceiptV1,
        lifecycle_revision: u64,
    ) -> RouterAbProtocolResult<()> {
        let authority_id = TenantRootControlPlaneAuthorityIdV1::from_bytes(decode_lower_hex_32(
            "tenant-root creation Durable Object id",
            &self.authority_object_id,
        )?);
        require_tenant_root_creation_authority_object_v1(
            &self.env,
            &self.authority_object_id,
            activation_receipt.identity_digest(),
            activation_receipt.custody_lineage(),
        )?;
        if activation_receipt.binding().authority_id() != authority_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ForbiddenLocalBinding,
                "tenant-root activation receipt authority does not match its Durable Object",
            ));
        }
        if activation_receipt.transition() != TenantRootActivationReceiptTransitionV1::RefreshSwap {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ForbiddenLocalBinding,
                "tenant-root refresh active state requires a refresh-swap receipt",
            ));
        }
        if lifecycle_revision != activation_receipt.result_control_plane_revision() {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ConflictingPair,
                "tenant-root refresh activation revision does not match its receipt",
            ));
        }
        let issuer_keys_json = read_required_worker_var(
            &self.env,
            crate::TENANT_ROOT_CONTROL_PLANE_ISSUER_VERIFYING_KEYS_JSON_ENV,
        )?;
        let issuer_keys = crate::env::decode_issuer_verifying_keys(&issuer_keys_json)?;
        let role_keys = read_tenant_root_creation_role_verifying_keys(&self.env)?;
        let candidate = refresh_active_state_record_from_verified_receipt(
            activation_receipt,
            lifecycle_revision,
        )?;
        let outcome: Rc<RefCell<Option<RouterAbProtocolResult<()>>>> = Rc::new(RefCell::new(None));
        let outcome_for_transaction = Rc::clone(&outcome);
        self.storage
            .transaction(move |transaction| async move {
                let result = Self::persist_authoritative_active_refresh_state_in_transaction_v1(
                    &transaction,
                    candidate,
                    authority_id,
                    &issuer_keys,
                    &role_keys,
                )
                .await;
                outcome_for_transaction.replace(Some(result));
                Ok(())
            })
            .await
            .map_err(durable_storage_protocol_error)?;
        let outcome = outcome.borrow_mut().take().ok_or_else(|| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "tenant-root refresh active-state transaction did not produce an outcome",
            )
        })?;
        outcome
    }

    async fn load_authoritative_active_refresh_state(
        &self,
    ) -> RouterAbProtocolResult<ValidatedTenantRootRefreshActiveStateV1> {
        let authority_id = TenantRootControlPlaneAuthorityIdV1::from_bytes(decode_lower_hex_32(
            "tenant-root creation Durable Object id",
            &self.authority_object_id,
        )?);
        let issuer_keys_json = read_required_worker_var(
            &self.env,
            crate::TENANT_ROOT_CONTROL_PLANE_ISSUER_VERIFYING_KEYS_JSON_ENV,
        )?;
        let issuer_keys = crate::env::decode_issuer_verifying_keys(&issuer_keys_json)?;
        let record = storage_get_optional::<CloudflareTenantRootRefreshActiveStateRecordV1>(
            &self.storage,
            TENANT_ROOT_REFRESH_ACTIVE_STATE_STORAGE_KEY_V1,
        )
        .await
        .map_err(durable_storage_protocol_error)?
        .ok_or_else(|| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "tenant-root refresh has no authoritative active public state",
            )
        })?;
        validate_refresh_active_state_record(record, authority_id, &issuer_keys)
            .map_err(stored_refresh_record_error)
    }

    async fn load_refresh_commitment_request(
        &self,
        request: CloudflareTenantRootRefreshCommitmentRequestV1,
    ) -> RouterAbProtocolResult<LoadedTenantRootRefreshRequestV1> {
        let active = self.load_authoritative_active_refresh_state().await?;
        let issuer_keys_json = read_required_worker_var(
            &self.env,
            crate::TENANT_ROOT_CONTROL_PLANE_ISSUER_VERIFYING_KEYS_JSON_ENV,
        )?;
        let issuer_keys = crate::env::decode_issuer_verifying_keys(&issuer_keys_json)?;
        let role_keys = read_tenant_root_creation_role_verifying_keys(&self.env)?;
        let candidate_bytes = decode_canonical_base64url(
            "tenant-root signed refresh commitment",
            &request.signed_commitment_b64u,
            TENANT_ROOT_REFRESH_COMMITMENT_MAX_BYTES_V1,
            TENANT_ROOT_REFRESH_COMMITMENT_MAX_BASE64URL_BYTES_V1,
        )?;
        let signed = TenantRootSignedRefreshCommitmentV1::decode_canonical_bytes(&candidate_bytes)
            .map_err(candidate_derivation_error)?;
        let context = signed.transcript().context().clone();
        let candidate = verify_refresh_commitment_wire(&candidate_bytes, &context, &role_keys)?;
        let command = validate_refresh_role_command(
            &request.role_refresh_command_b64u,
            &active,
            &context,
            candidate.role(),
            authority_id_from_object_id(&self.authority_object_id)?,
            &issuer_keys,
        )?;
        if command.role() != candidate.role() {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ForbiddenLocalBinding,
                "tenant-root refresh commitment role does not match its command",
            ));
        }
        let now_ms = crate::cloudflare_now_unix_ms_v1()?;
        Ok(LoadedTenantRootRefreshRequestV1 {
            active,
            context,
            command,
            candidate_bytes,
            role_keys,
            issuer_keys,
            now_ms,
        })
    }

    async fn load_refresh_installation_request(
        &self,
        request: CloudflareTenantRootRefreshInstallationRequestV1,
    ) -> RouterAbProtocolResult<LoadedTenantRootRefreshInstallationRequestV1> {
        let active = self.load_authoritative_active_refresh_state().await?;
        let issuer_keys_json = read_required_worker_var(
            &self.env,
            crate::TENANT_ROOT_CONTROL_PLANE_ISSUER_VERIFYING_KEYS_JSON_ENV,
        )?;
        let issuer_keys = crate::env::decode_issuer_verifying_keys(&issuer_keys_json)?;
        let role_keys = read_tenant_root_creation_role_verifying_keys(&self.env)?;
        let candidate_bytes = decode_canonical_base64url(
            "tenant-root signed refresh installation evidence",
            &request.signed_evidence_b64u,
            TENANT_ROOT_SIGNED_SHARE_INSTALLATION_EVIDENCE_MAX_BYTES_V1,
            TENANT_ROOT_CREATION_INSTALLATION_EVIDENCE_MAX_BASE64URL_BYTES_V1,
        )?;
        let candidate =
            decode_and_verify_refresh_installation_evidence(&candidate_bytes, &role_keys)?;
        let context = candidate.evidence().transcript().context().clone();
        let command = validate_refresh_role_command(
            &request.role_refresh_command_b64u,
            &active,
            &context,
            candidate.evidence().transcript().role(),
            authority_id_from_object_id(&self.authority_object_id)?,
            &issuer_keys,
        )?;
        if command.role() != candidate.evidence().transcript().role() {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ForbiddenLocalBinding,
                "tenant-root refresh installation role does not match its command",
            ));
        }
        let terminal_receipt_bytes = decode_canonical_base64url(
            "tenant-root refresh terminal receipt",
            &request.terminal_receipt_b64u,
            TENANT_ROOT_COMMAND_TERMINAL_RECEIPT_MAX_BYTES_V1,
            TENANT_ROOT_COMMAND_TERMINAL_RECEIPT_MAX_BASE64URL_BYTES_V1,
        )?;
        let terminal_receipt =
            TenantRootCommandTerminalReceiptV1::decode_canonical_bytes(&terminal_receipt_bytes)
                .map_err(candidate_derivation_error)?;
        if terminal_receipt
            .canonical_bytes()
            .map_err(candidate_derivation_error)?
            != terminal_receipt_bytes
        {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ForbiddenLocalBinding,
                "tenant-root refresh terminal receipt is not canonical",
            ));
        }
        let success = match terminal_receipt {
            TenantRootCommandTerminalReceiptV1::Success(receipt) => receipt,
            TenantRootCommandTerminalReceiptV1::Failure(_) => {
                return Err(RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::ReplayedLocalRequest,
                    "tenant-root refresh installation requires a successful terminal receipt",
                ));
            }
        };
        let terminal_receipt = VerifiedTenantRootRefreshInstallationReceiptV1::new(
            success,
            &candidate_bytes,
            &command,
            &context,
            &role_keys,
        )?;
        let now_ms = crate::cloudflare_now_unix_ms_v1()?;
        Ok(LoadedTenantRootRefreshInstallationRequestV1 {
            active,
            context,
            command,
            candidate_bytes,
            terminal_receipt,
            role_keys,
            issuer_keys,
            now_ms,
        })
    }

    async fn load_refresh_contribution_request(
        &self,
        request: CloudflareTenantRootRefreshContributionRequestV1,
    ) -> RouterAbProtocolResult<LoadedTenantRootRefreshContributionRequestV1> {
        let active = self.load_authoritative_active_refresh_state().await?;
        let issuer_keys_json = read_required_worker_var(
            &self.env,
            crate::TENANT_ROOT_CONTROL_PLANE_ISSUER_VERIFYING_KEYS_JSON_ENV,
        )?;
        let issuer_keys = crate::env::decode_issuer_verifying_keys(&issuer_keys_json)?;
        let role_keys = read_tenant_root_creation_role_verifying_keys(&self.env)?;
        let candidate_bytes = decode_canonical_base64url(
            "tenant-root signed refresh contribution",
            &request.signed_contribution_b64u,
            TENANT_ROOT_REFRESH_CONTRIBUTION_MAX_BYTES_V1,
            TENANT_ROOT_REFRESH_CONTRIBUTION_MAX_BASE64URL_BYTES_V1,
        )?;
        let signed =
            TenantRootSignedRefreshContributionV1::decode_canonical_bytes(&candidate_bytes)
                .map_err(candidate_derivation_error)?;
        let candidate_role = signed.envelope().source();
        let checkpoint_encoded = storage_get_optional::<String>(
            &self.storage,
            TENANT_ROOT_REFRESH_COMMITMENT_CHECKPOINT_STORAGE_KEY_V1,
        )
        .await
        .map_err(durable_storage_protocol_error)?
        .ok_or_else(|| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MissingPairPreparation,
                "tenant-root refresh contribution has no commitment checkpoint",
            )
        })?;
        let checkpoint = decode_refresh_commitment_checkpoint(&checkpoint_encoded)
            .map_err(stored_refresh_record_error)?;
        let commitment_bytes = checkpoint
            .state()
            .deriver_a_signed_commitment()
            .ok_or_else(|| {
                RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::MissingPairPreparation,
                    "tenant-root refresh contribution requires both commitments",
                )
            })?;
        let commitment =
            TenantRootSignedRefreshCommitmentV1::decode_canonical_bytes(commitment_bytes)
                .map_err(candidate_derivation_error)?;
        let context = commitment.transcript().context().clone();
        let commitments =
            require_complete_refresh_commitment_checkpoint(&checkpoint, &context, &role_keys)
                .map_err(stored_refresh_record_error)?;
        let expected_authority_id = authority_id_from_object_id(&self.authority_object_id)?;
        let command = validate_refresh_role_command(
            &request.role_refresh_command_b64u,
            &active,
            &context,
            candidate_role,
            expected_authority_id,
            &issuer_keys,
        )?;
        let expected_scope =
            refresh_checkpoint_scope(&command, &active, &context, expected_authority_id)?;
        validate_refresh_commitment_checkpoint_scope(checkpoint.scope(), &expected_scope)
            .map_err(stored_refresh_record_error)?;
        verify_refresh_contribution_wire(&candidate_bytes, &context, &commitments, &role_keys)?;
        let now_ms = crate::cloudflare_now_unix_ms_v1()?;
        Ok(LoadedTenantRootRefreshContributionRequestV1 {
            active,
            context,
            command,
            candidate_bytes,
            role_keys,
            issuer_keys,
            now_ms,
        })
    }

    pub(crate) async fn persist_refresh_commitment_checkpoint(
        &self,
        request: CloudflareTenantRootRefreshCommitmentRequestV1,
    ) -> RouterAbProtocolResult<CloudflareTenantRootRefreshCommitmentResponseV1> {
        let loaded = self.load_refresh_commitment_request(request).await?;
        let response_scope =
            refresh_response_scope(&loaded.command, &loaded.active, &loaded.context)?;
        let command_bytes = loaded.command.canonical_bytes().to_vec();
        let candidate_bytes = loaded.candidate_bytes;
        let context = loaded.context;
        let role_keys = loaded.role_keys;
        let issuer_keys = loaded.issuer_keys;
        let expected_authority_id = authority_id_from_object_id(&self.authority_object_id)?;
        let now_ms = loaded.now_ms;
        let outcome: Rc<
            RefCell<
                Option<
                    RouterAbProtocolResult<CloudflareTenantRootRefreshCommitmentResponseOutcomeV1>,
                >,
            >,
        > = Rc::new(RefCell::new(None));
        let outcome_for_transaction = Rc::clone(&outcome);
        self.storage
            .transaction(move |transaction| async move {
                let active_record = match transaction_get_optional::<
                    CloudflareTenantRootRefreshActiveStateRecordV1,
                >(
                    &transaction,
                    TENANT_ROOT_REFRESH_ACTIVE_STATE_STORAGE_KEY_V1,
                )
                .await
                {
                    Ok(Some(record)) => record,
                    Ok(None) => {
                        outcome_for_transaction.replace(Some(Err(RouterAbProtocolError::new(
                            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                            "tenant-root refresh has no authoritative active public state",
                        ))));
                        return Ok(());
                    }
                    Err(error) => return Err(error),
                };
                let active = match validate_refresh_active_state_record(
                    active_record,
                    expected_authority_id,
                    &issuer_keys,
                ) {
                    Ok(value) => value,
                    Err(error) => {
                        outcome_for_transaction
                            .replace(Some(Err(stored_refresh_record_error(error))));
                        return Ok(());
                    }
                };
                let command = match decode_and_verify_refresh_role_command(
                    &command_bytes,
                    &active,
                    &context,
                    &issuer_keys,
                    expected_authority_id,
                ) {
                    Ok(value) => value,
                    Err(error) => {
                        outcome_for_transaction.replace(Some(Err(error)));
                        return Ok(());
                    }
                };
                let existing = match transaction_get_optional::<String>(
                    &transaction,
                    TENANT_ROOT_REFRESH_COMMITMENT_CHECKPOINT_STORAGE_KEY_V1,
                )
                .await
                {
                    Ok(Some(encoded)) => match decode_refresh_commitment_checkpoint(&encoded) {
                        Ok(checkpoint) => Some(checkpoint),
                        Err(error) => {
                            outcome_for_transaction
                                .replace(Some(Err(stored_refresh_record_error(error))));
                            return Ok(());
                        }
                    },
                    Ok(None) => None,
                    Err(error) => return Err(error),
                };
                let candidate = match verify_refresh_commitment_wire(
                    &candidate_bytes,
                    &context,
                    &role_keys,
                ) {
                    Ok(candidate) => candidate,
                    Err(error) => {
                        outcome_for_transaction.replace(Some(Err(error)));
                        return Ok(());
                    }
                };
                let candidate_role = candidate.role();
                if let Err(error) = require_refresh_fence_matches_command(&active.record.fence, &command)
                {
                    outcome_for_transaction.replace(Some(Err(error)));
                    return Ok(());
                }
                if let Err(error) = require_fresh_refresh_commitment_command(
                    existing.as_ref(),
                    candidate_role,
                    &command,
                    &context,
                    now_ms,
                ) {
                    outcome_for_transaction.replace(Some(Err(error)));
                    return Ok(());
                }
                let active_binding = match TenantRootRefreshCommitmentCheckpointActiveBindingV1::from_verified_activation_receipt(
                    active.activation_receipt,
                    &active.active_pair,
                    active.record.lifecycle_revision,
                ) {
                    Ok(binding) => binding,
                    Err(error) => {
                        outcome_for_transaction.replace(Some(Err(stored_refresh_record_error(
                            candidate_derivation_error(error),
                        ))));
                        return Ok(());
                    }
                };
                let deriver_a_verifying_key = match role_keys.for_role_and_key_id(
                    TwoPartyDeriverRole::DeriverA,
                    context.signing_key_id(TwoPartyDeriverRole::DeriverA),
                ) {
                    Ok(key) => key,
                    Err(error) => {
                        outcome_for_transaction.replace(Some(Err(error)));
                        return Ok(());
                    }
                };
                let deriver_b_verifying_key = match role_keys.for_role_and_key_id(
                    TwoPartyDeriverRole::DeriverB,
                    context.signing_key_id(TwoPartyDeriverRole::DeriverB),
                ) {
                    Ok(key) => key,
                    Err(error) => {
                        outcome_for_transaction.replace(Some(Err(error)));
                        return Ok(());
                    }
                };
                let has_existing_checkpoint = existing.is_some();
                let evaluation = evaluate_tenant_root_refresh_commitment_checkpoint_v1(
                    existing,
                    candidate,
                    &command,
                    &active_binding,
                    &context,
                    expected_authority_id,
                    deriver_a_verifying_key,
                    deriver_b_verifying_key,
                    now_ms,
                )
                .map_err(|error| {
                    refresh_commitment_evaluation_error(error, has_existing_checkpoint)
                });
                match evaluation {
                    Ok(TenantRootRefreshCommitmentCheckpointEvaluationV1::Commit {
                        checkpoint,
                        outcome,
                    }) => {
                        let checkpoint_b64u = match encode_refresh_commitment_checkpoint(&checkpoint)
                        {
                            Ok(value) => value,
                            Err(error) => {
                                outcome_for_transaction.replace(Some(Err(error)));
                                return Ok(());
                            }
                        };
                        let response_outcome = match refresh_commitment_response_outcome(
                            outcome,
                            &candidate_bytes,
                        ) {
                            Ok(value) => value,
                            Err(error) => {
                                outcome_for_transaction.replace(Some(Err(error)));
                                return Ok(());
                            }
                        };
                        let fence = match refresh_reserved_fence(&active.record.fence, &command) {
                            Ok(value) => value,
                            Err(error) => {
                                outcome_for_transaction.replace(Some(Err(error)));
                                return Ok(());
                            }
                        };
                        let mut active_record = active.record.clone();
                        active_record.fence = fence;
                        transaction
                            .put(
                                TENANT_ROOT_REFRESH_COMMITMENT_CHECKPOINT_STORAGE_KEY_V1,
                                &checkpoint_b64u,
                            )
                            .await?;
                        transaction
                            .put(
                                TENANT_ROOT_REFRESH_ACTIVE_STATE_STORAGE_KEY_V1,
                                &active_record,
                            )
                            .await?;
                        outcome_for_transaction.replace(Some(Ok(response_outcome)));
                    }
                    Ok(TenantRootRefreshCommitmentCheckpointEvaluationV1::Replay(outcome)) => {
                        match refresh_commitment_response_outcome(outcome, &candidate_bytes) {
                            Ok(response_outcome) => {
                                outcome_for_transaction.replace(Some(Ok(response_outcome)));
                            }
                            Err(error) => {
                                outcome_for_transaction.replace(Some(Err(error)));
                            }
                        }
                    }
                    Err(error) => {
                        outcome_for_transaction.replace(Some(Err(error)));
                    }
                }
                Ok(())
            })
            .await
            .map_err(durable_storage_protocol_error)?;
        let evaluation = outcome.borrow_mut().take().ok_or_else(|| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "tenant-root refresh commitment transaction did not produce an outcome",
            )
        })??;
        let response = refresh_commitment_response(response_scope, evaluation)?;
        Ok(response)
    }

    pub(crate) async fn persist_refresh_installation_checkpoint(
        &self,
        request: CloudflareTenantRootRefreshInstallationRequestV1,
    ) -> RouterAbProtocolResult<CloudflareTenantRootRefreshInstallationResponseV1> {
        let loaded = self.load_refresh_installation_request(request).await?;
        let response_scope =
            refresh_response_scope(&loaded.command, &loaded.active, &loaded.context)?;
        let command_bytes = loaded.command.canonical_bytes().to_vec();
        let candidate_bytes = loaded.candidate_bytes;
        let context = loaded.context;
        let role_keys = loaded.role_keys;
        let issuer_keys = loaded.issuer_keys;
        let terminal_receipt = loaded.terminal_receipt;
        let expected_authority_id = authority_id_from_object_id(&self.authority_object_id)?;
        let now_ms = loaded.now_ms;
        let outcome: Rc<
            RefCell<
                Option<
                    RouterAbProtocolResult<
                        CloudflareTenantRootRefreshInstallationResponseOutcomeV1,
                    >,
                >,
            >,
        > = Rc::new(RefCell::new(None));
        let outcome_for_transaction = Rc::clone(&outcome);
        self.storage
            .transaction(move |transaction| async move {
                let active_record = match transaction_get_optional::<
                    CloudflareTenantRootRefreshActiveStateRecordV1,
                >(
                    &transaction,
                    TENANT_ROOT_REFRESH_ACTIVE_STATE_STORAGE_KEY_V1,
                )
                .await
                {
                    Ok(Some(record)) => record,
                    Ok(None) => {
                        outcome_for_transaction.replace(Some(Err(RouterAbProtocolError::new(
                            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                            "tenant-root refresh has no authoritative active public state",
                        ))));
                        return Ok(());
                    }
                    Err(error) => return Err(error),
                };
                let active = match validate_refresh_active_state_record(
                    active_record,
                    expected_authority_id,
                    &issuer_keys,
                ) {
                    Ok(value) => value,
                    Err(error) => {
                        outcome_for_transaction
                            .replace(Some(Err(stored_refresh_record_error(error))));
                        return Ok(());
                    }
                };
                let command = match decode_and_verify_refresh_role_command(
                    &command_bytes,
                    &active,
                    &context,
                    &issuer_keys,
                    expected_authority_id,
                ) {
                    Ok(value) => value,
                    Err(error) => {
                        outcome_for_transaction.replace(Some(Err(error)));
                        return Ok(());
                    }
                };
                let commitment_record = match transaction_get_optional::<String>(
                    &transaction,
                    TENANT_ROOT_REFRESH_COMMITMENT_CHECKPOINT_STORAGE_KEY_V1,
                )
                .await
                {
                    Ok(existing) => existing,
                    Err(error) => return Err(error),
                };
                let scope = match refresh_checkpoint_scope(
                    &command,
                    &active,
                    &context,
                    expected_authority_id,
                ) {
                    Ok(scope) => scope,
                    Err(error) => {
                        outcome_for_transaction.replace(Some(Err(error)));
                        return Ok(());
                    }
                };
                let commitment_state = match commitment_record {
                    Some(encoded) => match decode_refresh_commitment_checkpoint(&encoded) {
                        Ok(checkpoint) => {
                            if let Err(error) = validate_refresh_commitment_checkpoint_scope(
                                checkpoint.scope(),
                                &scope,
                            ) {
                                outcome_for_transaction
                                    .replace(Some(Err(stored_refresh_record_error(error))));
                                return Ok(());
                            }
                            match require_complete_refresh_commitment_checkpoint(
                                &checkpoint,
                                &context,
                                &role_keys,
                            ) {
                                Ok(pair) => pair,
                                Err(error) => {
                                    outcome_for_transaction
                                        .replace(Some(Err(stored_refresh_record_error(error))));
                                    return Ok(());
                                }
                            }
                        }
                        Err(error) => {
                            outcome_for_transaction
                                .replace(Some(Err(stored_refresh_record_error(error))));
                            return Ok(());
                        }
                    },
                    None => {
                        outcome_for_transaction.replace(Some(Err(RouterAbProtocolError::new(
                            RouterAbProtocolErrorCode::MissingPairPreparation,
                            "tenant-root refresh installation has no commitment checkpoint",
                        ))));
                        return Ok(());
                    }
                };
                let existing = match transaction_get_optional::<
                    CloudflareTenantRootRefreshInstallationCheckpointRecordV1,
                >(
                    &transaction,
                    TENANT_ROOT_REFRESH_INSTALLATION_CHECKPOINT_STORAGE_KEY_V1,
                )
                .await
                {
                    Ok(existing) => existing,
                    Err(error) => return Err(error),
                };
                match evaluate_refresh_installation_checkpoint(
                    existing,
                    &candidate_bytes,
                    &command,
                    &active,
                    &context,
                    &role_keys,
                    &commitment_state,
                    expected_authority_id,
                    &terminal_receipt,
                    now_ms,
                ) {
                    Ok(TenantRootRefreshInstallationCheckpointEvaluationV1::Commit {
                        checkpoint,
                        fence,
                        outcome,
                    }) => {
                        let mut active_record = active.record.clone();
                        active_record.fence = fence;
                        transaction
                            .put(
                                TENANT_ROOT_REFRESH_INSTALLATION_CHECKPOINT_STORAGE_KEY_V1,
                                &checkpoint,
                            )
                            .await?;
                        transaction
                            .put(
                                TENANT_ROOT_REFRESH_ACTIVE_STATE_STORAGE_KEY_V1,
                                &active_record,
                            )
                            .await?;
                        outcome_for_transaction.replace(Some(Ok(outcome)));
                    }
                    Ok(TenantRootRefreshInstallationCheckpointEvaluationV1::Replay(outcome)) => {
                        outcome_for_transaction.replace(Some(Ok(outcome)));
                    }
                    Err(error) => {
                        outcome_for_transaction.replace(Some(Err(error)));
                    }
                }
                Ok(())
            })
            .await
            .map_err(durable_storage_protocol_error)?;
        let evaluation = outcome.borrow_mut().take().ok_or_else(|| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "tenant-root refresh installation transaction did not produce an outcome",
            )
        })??;
        let response = refresh_installation_response(response_scope, evaluation)?;
        Ok(response)
    }

    pub(crate) async fn persist_refresh_contribution_rendezvous(
        &self,
        request: CloudflareTenantRootRefreshContributionRequestV1,
    ) -> RouterAbProtocolResult<CloudflareTenantRootRefreshContributionResponseV1> {
        let loaded = self.load_refresh_contribution_request(request).await?;
        let response_scope =
            refresh_response_scope(&loaded.command, &loaded.active, &loaded.context)?;
        let command_bytes = loaded.command.canonical_bytes().to_vec();
        let candidate_bytes = loaded.candidate_bytes;
        let context = loaded.context;
        let role_keys = loaded.role_keys;
        let issuer_keys = loaded.issuer_keys;
        let expected_authority_id = authority_id_from_object_id(&self.authority_object_id)?;
        let now_ms = loaded.now_ms;
        let outcome: Rc<
            RefCell<
                Option<
                    RouterAbProtocolResult<
                        CloudflareTenantRootRefreshContributionResponseOutcomeV1,
                    >,
                >,
            >,
        > = Rc::new(RefCell::new(None));
        let outcome_for_transaction = Rc::clone(&outcome);
        self.storage
            .transaction(move |transaction| async move {
                let active_record = match transaction_get_optional::<
                    CloudflareTenantRootRefreshActiveStateRecordV1,
                >(
                    &transaction,
                    TENANT_ROOT_REFRESH_ACTIVE_STATE_STORAGE_KEY_V1,
                )
                .await
                {
                    Ok(Some(record)) => record,
                    Ok(None) => {
                        outcome_for_transaction.replace(Some(Err(RouterAbProtocolError::new(
                            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                            "tenant-root refresh has no authoritative active public state",
                        ))));
                        return Ok(());
                    }
                    Err(error) => return Err(error),
                };
                let active = match validate_refresh_active_state_record(
                    active_record,
                    expected_authority_id,
                    &issuer_keys,
                ) {
                    Ok(value) => value,
                    Err(error) => {
                        outcome_for_transaction
                            .replace(Some(Err(stored_refresh_record_error(error))));
                        return Ok(());
                    }
                };
                let command = match decode_and_verify_refresh_role_command(
                    &command_bytes,
                    &active,
                    &context,
                    &issuer_keys,
                    expected_authority_id,
                ) {
                    Ok(value) => value,
                    Err(error) => {
                        outcome_for_transaction.replace(Some(Err(error)));
                        return Ok(());
                    }
                };
                let checkpoint_encoded = match transaction_get_optional::<String>(
                    &transaction,
                    TENANT_ROOT_REFRESH_COMMITMENT_CHECKPOINT_STORAGE_KEY_V1,
                )
                .await
                {
                    Ok(Some(encoded)) => encoded,
                    Ok(None) => {
                        outcome_for_transaction.replace(Some(Err(RouterAbProtocolError::new(
                            RouterAbProtocolErrorCode::MissingPairPreparation,
                            "tenant-root refresh contribution has no commitment checkpoint",
                        ))));
                        return Ok(());
                    }
                    Err(error) => return Err(error),
                };
                let checkpoint = match decode_refresh_commitment_checkpoint(&checkpoint_encoded) {
                    Ok(checkpoint) => checkpoint,
                    Err(error) => {
                        outcome_for_transaction
                            .replace(Some(Err(stored_refresh_record_error(error))));
                        return Ok(());
                    }
                };
                let scope = match refresh_checkpoint_scope(
                    &command,
                    &active,
                    &context,
                    expected_authority_id,
                ) {
                    Ok(scope) => scope,
                    Err(error) => {
                        outcome_for_transaction.replace(Some(Err(error)));
                        return Ok(());
                    }
                };
                if let Err(error) =
                    validate_refresh_commitment_checkpoint_scope(checkpoint.scope(), &scope)
                {
                    outcome_for_transaction.replace(Some(Err(stored_refresh_record_error(error))));
                    return Ok(());
                }
                let commitments = match require_complete_refresh_commitment_checkpoint(
                    &checkpoint,
                    &context,
                    &role_keys,
                ) {
                    Ok(pair) => pair,
                    Err(error) => {
                        outcome_for_transaction
                            .replace(Some(Err(stored_refresh_record_error(error))));
                        return Ok(());
                    }
                };
                let candidate = match verify_refresh_contribution_wire(
                    &candidate_bytes,
                    &context,
                    &commitments,
                    &role_keys,
                ) {
                    Ok(candidate) => candidate,
                    Err(error) => {
                        outcome_for_transaction.replace(Some(Err(error)));
                        return Ok(());
                    }
                };
                let existing = match transaction_get_optional::<
                    CloudflareTenantRootRefreshContributionRendezvousRecordV1,
                >(
                    &transaction,
                    TENANT_ROOT_REFRESH_CONTRIBUTION_RENDEZVOUS_STORAGE_KEY_V1,
                )
                .await
                {
                    Ok(existing) => existing,
                    Err(error) => return Err(error),
                };
                let evaluation = evaluate_refresh_contribution_rendezvous(
                    existing,
                    candidate,
                    &command,
                    &active,
                    &context,
                    &commitments,
                    &role_keys,
                    expected_authority_id,
                    now_ms,
                );
                match evaluation {
                    Ok(TenantRootRefreshContributionRendezvousEvaluationV1::Commit {
                        record,
                        outcome,
                    }) => {
                        transaction
                            .put(
                                TENANT_ROOT_REFRESH_CONTRIBUTION_RENDEZVOUS_STORAGE_KEY_V1,
                                &record,
                            )
                            .await?;
                        outcome_for_transaction.replace(Some(Ok(outcome)));
                    }
                    Ok(TenantRootRefreshContributionRendezvousEvaluationV1::Replay(outcome)) => {
                        outcome_for_transaction.replace(Some(Ok(outcome)));
                    }
                    Err(error) => {
                        outcome_for_transaction.replace(Some(Err(error)));
                    }
                }
                Ok(())
            })
            .await
            .map_err(durable_storage_protocol_error)?;
        let evaluation = outcome.borrow_mut().take().ok_or_else(|| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "tenant-root refresh contribution transaction did not produce an outcome",
            )
        })??;
        refresh_contribution_response(response_scope, evaluation)
    }
}

#[cfg(feature = "workers-rs")]
async fn storage_get_optional<T: serde::de::DeserializeOwned>(
    storage: &worker::Storage,
    key: &str,
) -> worker::Result<Option<T>> {
    storage.get(key).await
}

#[cfg(feature = "workers-rs")]
async fn transaction_get_optional<T: serde::de::DeserializeOwned>(
    transaction: &worker::Transaction,
    key: &str,
) -> worker::Result<Option<T>> {
    match transaction.get(key).await {
        Ok(value) => Ok(Some(value)),
        Err(worker::Error::JsError(message)) if message == "No such value in storage." => Ok(None),
        Err(error) => Err(error),
    }
}

#[cfg(feature = "workers-rs")]
fn request_has_json_content_type(request: &worker::Request) -> worker::Result<bool> {
    let Some(content_type) = request.headers().get("content-type")? else {
        return Ok(false);
    };
    Ok(content_type
        .split(';')
        .next()
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json")))
}

#[cfg(feature = "workers-rs")]
pub(crate) async fn decode_bounded_json_request<T: DeserializeOwned>(
    request: &mut worker::Request,
    max_bytes: usize,
) -> RouterAbProtocolResult<T> {
    use futures::StreamExt;

    let mut stream = request.stream().map_err(|error| {
        malformed_input(format!(
            "tenant-root creation request body is unavailable: {error}"
        ))
    })?;
    let mut body = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|error| {
            malformed_input(format!(
                "tenant-root creation request body read failed: {error}"
            ))
        })?;
        let next_len = body
            .len()
            .checked_add(chunk.len())
            .ok_or_else(|| malformed_input("tenant-root creation request length overflows"))?;
        if next_len > max_bytes {
            return Err(malformed_input(
                "tenant-root creation request exceeds its maximum size",
            ));
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body).map_err(|error| {
        malformed_input(format!(
            "tenant-root creation request JSON is invalid: {error}"
        ))
    })
}

#[cfg(feature = "workers-rs")]
async fn decode_bounded_creation_request(
    request: &mut worker::Request,
) -> RouterAbProtocolResult<CloudflareTenantRootCreationJournalRequestV1> {
    decode_bounded_json_request(request, TENANT_ROOT_CREATION_REQUEST_MAX_BYTES_V1).await
}

#[cfg(feature = "workers-rs")]
pub(crate) fn read_required_worker_var(
    env: &worker::Env,
    name: &str,
) -> RouterAbProtocolResult<String> {
    let value = env.var(name).map_err(|error| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MissingLocalBinding,
            format!("required tenant-root creation binding {name} is unavailable: {error}"),
        )
    })?;
    let value = value.to_string();
    if value.is_empty() || value.trim() != value {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            format!("tenant-root creation binding {name} is invalid"),
        ));
    }
    Ok(value)
}

#[cfg(feature = "workers-rs")]
fn read_tenant_root_creation_role_verifying_keys(
    env: &worker::Env,
) -> RouterAbProtocolResult<TenantRootCreationRoleVerifyingKeysV1> {
    let role_keys = decode_role_verifying_keys(&read_required_worker_var(
        env,
        crate::ROUTER_TENANT_ROOT_CREATION_ROLE_VERIFYING_KEYS_JSON_ENV,
    )?)?;
    validate_tenant_root_creation_role_verifying_keys_against_peer_v1(
        &CloudflareWorkerEnvReaderV1::new(env),
        &role_keys,
    )?;
    Ok(role_keys)
}

#[cfg_attr(not(feature = "workers-rs"), allow(dead_code))]
pub(crate) fn decode_lower_hex_32(field: &str, value: &str) -> RouterAbProtocolResult<[u8; 32]> {
    if value.len() != 64
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
    {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            format!("{field} must be exactly 64 lowercase hexadecimal characters"),
        ));
    }
    let mut decoded = [0_u8; 32];
    for (output, pair) in decoded.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        *output = (lower_hex_nibble(pair[0]) << 4) | lower_hex_nibble(pair[1]);
    }
    Ok(decoded)
}

#[cfg_attr(not(feature = "workers-rs"), allow(dead_code))]
fn lower_hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => unreachable!("lowercase hexadecimal input was validated"),
    }
}

pub(crate) fn decode_canonical_base64url(
    field: &str,
    value: &str,
    max_decoded_bytes: usize,
    max_encoded_bytes: usize,
) -> RouterAbProtocolResult<Vec<u8>> {
    if value.is_empty() || value.len() > max_encoded_bytes {
        return Err(malformed_input(format!("{field} length is invalid")));
    }
    let decoded = decode_base64url_bytes_v1(field, value)?;
    if decoded.len() > max_decoded_bytes || encode_base64url_bytes_v1(&decoded) != value {
        return Err(malformed_input(format!("{field} is not canonical")));
    }
    Ok(decoded)
}

#[cfg(feature = "workers-rs")]
fn durable_storage_protocol_error(error: worker::Error) -> RouterAbProtocolError {
    RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
        format!("tenant-root creation journal durable storage failed: {error}"),
    )
}

#[cfg(feature = "workers-rs")]
fn tenant_root_creation_do_error_response(
    error: RouterAbProtocolError,
) -> worker::Result<worker::Response> {
    if error.code() == RouterAbProtocolErrorCode::ForbiddenLocalBinding {
        return worker::Response::error("tenant-root creation capability rejected", 403);
    }
    worker::Response::error(
        "tenant-root creation journal unavailable",
        super::durable_object_error_status(error.code()),
    )
}

fn candidate_derivation_error(error: RouterAbDerivationError) -> RouterAbProtocolError {
    malformed_input(format!(
        "tenant-root creation request rejected: {:?}",
        error.code()
    ))
}

fn candidate_authorization_error(error: RouterAbDerivationError) -> RouterAbProtocolError {
    RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::ForbiddenLocalBinding,
        format!(
            "tenant-root creation capability verification failed: {:?}",
            error.code()
        ),
    )
}

fn stored_record_error(error: RouterAbProtocolError) -> RouterAbProtocolError {
    RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
        format!(
            "stored tenant-root creation record is invalid: {:?}",
            error.code()
        ),
    )
}

fn malformed_input(message: impl Into<String>) -> RouterAbProtocolError {
    RouterAbProtocolError::new(RouterAbProtocolErrorCode::MalformedWirePayload, message)
}

struct ValidatedTenantRootRefreshActiveStateV1 {
    record: CloudflareTenantRootRefreshActiveStateRecordV1,
    identity_digest: TenantRootIdentityDigestV1,
    custody_lineage: TenantRootCustodyLineageId,
    active_epoch: TenantRootShareEpoch,
    commitments: TenantRootEpochCommitmentsV1,
    activation_receipt_digest: TenantRootLifecycleReceiptDigestV1,
    activation_receipt: router_ab_core::VerifiedTenantRootSignedActivationReceiptV1,
    active_pair: router_ab_core::TenantRootActiveRootPairV1,
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
struct TenantRootRefreshActiveStateProjectionV1 {
    activation_receipt_b64u: String,
    activation_receipt_digest_b64u: String,
    identity_digest_b64u: String,
    custody_lineage_b64u: String,
    active_epoch: u64,
    deriver_a_commitment_b64u: String,
    deriver_b_commitment_b64u: String,
    active_root_commitment_b64u: String,
    lifecycle_revision: u64,
}

#[allow(dead_code)]
fn refresh_active_state_projection(
    record: &CloudflareTenantRootRefreshActiveStateRecordV1,
) -> TenantRootRefreshActiveStateProjectionV1 {
    TenantRootRefreshActiveStateProjectionV1 {
        activation_receipt_b64u: record.activation_receipt_b64u.clone(),
        activation_receipt_digest_b64u: record.activation_receipt_digest_b64u.clone(),
        identity_digest_b64u: record.identity_digest_b64u.clone(),
        custody_lineage_b64u: record.custody_lineage_b64u.clone(),
        active_epoch: record.active_epoch,
        deriver_a_commitment_b64u: record.deriver_a_commitment_b64u.clone(),
        deriver_b_commitment_b64u: record.deriver_b_commitment_b64u.clone(),
        active_root_commitment_b64u: record.active_root_commitment_b64u.clone(),
        lifecycle_revision: record.lifecycle_revision,
    }
}

fn refresh_terminal_response_from_record(
    record: &CloudflareTenantRootRefreshActiveStateRecordV1,
) -> CloudflareTenantRootRefreshActivationResponseV1 {
    CloudflareTenantRootRefreshActivationResponseV1 {
        activation_receipt_digest_b64u: record.activation_receipt_digest_b64u.clone(),
        lifecycle_revision: record.lifecycle_revision,
    }
}

fn validate_refresh_terminal_response(
    record: &CloudflareTenantRootRefreshActiveStateRecordV1,
    activation_receipt: &router_ab_core::VerifiedTenantRootSignedActivationReceiptV1,
    attempt: &CloudflareTenantRootRefreshAttemptV1,
    response: &CloudflareTenantRootRefreshActivationResponseV1,
) -> RouterAbProtocolResult<()> {
    let response_digest = decode_lifecycle_receipt_digest(
        "tenant-root terminal refresh response receipt digest",
        &response.activation_receipt_digest_b64u,
    )?;
    if response_digest != activation_receipt.digest()
        || response.activation_receipt_digest_b64u != record.activation_receipt_digest_b64u
        || response.lifecycle_revision != record.lifecycle_revision
        || response.lifecycle_revision != activation_receipt.result_control_plane_revision()
    {
        return Err(malformed_input(
            "tenant-root terminal refresh response does not match its activation state",
        ));
    }
    let TenantRootActivationReceiptBindingV1::RefreshSwap(binding) = activation_receipt.binding()
    else {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ForbiddenLocalBinding,
            "tenant-root terminal refresh response requires a refresh-swap receipt",
        ));
    };
    let attempt_context_digest = decode_protocol_digest_b64u(
        "tenant-root terminal refresh attempt context digest",
        &attempt.ceremony_context_digest_b64u,
    )?;
    if attempt.identity_digest_b64u != record.identity_digest_b64u
        || attempt.custody_lineage_b64u != record.custody_lineage_b64u
        || binding.identity_digest() != activation_receipt.identity_digest()
        || binding.custody_lineage() != activation_receipt.custody_lineage()
        || binding.context_digest() != attempt_context_digest
        || binding.current_epoch().get().get() != attempt.current_epoch
        || binding.next_epoch().get().get() != attempt.next_epoch
        || binding.expected_control_plane_revision() != attempt.expected_control_plane_revision
        || binding.result_control_plane_revision() != response.lifecycle_revision
    {
        return Err(malformed_input(
            "tenant-root terminal refresh response does not match its persisted attempt",
        ));
    }
    Ok(())
}

#[allow(dead_code)]
fn refresh_active_state_record_from_verified_receipt(
    activation_receipt: router_ab_core::VerifiedTenantRootSignedActivationReceiptV1,
    lifecycle_revision: u64,
) -> RouterAbProtocolResult<CloudflareTenantRootRefreshActiveStateRecordV1> {
    if lifecycle_revision == 0 {
        return Err(malformed_input(
            "tenant-root refresh active lifecycle revision must be positive",
        ));
    }
    if lifecycle_revision < activation_receipt.result_control_plane_revision() {
        return Err(malformed_input(
            "tenant-root refresh active lifecycle revision predates activation",
        ));
    }
    let receipt_bytes = activation_receipt.canonical_bytes().to_vec();
    let receipt_digest = activation_receipt.digest();
    let (active_epoch, commitments) = match activation_receipt.binding() {
        TenantRootActivationReceiptBindingV1::InitialCreation(binding) => {
            (binding.epoch(), binding.commitments())
        }
        TenantRootActivationReceiptBindingV1::RefreshSwap(binding) => {
            (binding.next_epoch(), binding.next_commitments())
        }
    };
    Ok(CloudflareTenantRootRefreshActiveStateRecordV1 {
        activation_receipt_b64u: encode_base64url_bytes_v1(&receipt_bytes),
        activation_receipt_digest_b64u: encode_base64url_bytes_v1(receipt_digest.as_bytes()),
        identity_digest_b64u: encode_base64url_bytes_v1(
            activation_receipt.identity_digest().as_bytes(),
        ),
        custody_lineage_b64u: activation_receipt.custody_lineage().to_base64url(),
        active_epoch: active_epoch.get().get(),
        deriver_a_commitment_b64u: encode_base64url_bytes_v1(commitments.deriver_a().as_bytes()),
        deriver_b_commitment_b64u: encode_base64url_bytes_v1(commitments.deriver_b().as_bytes()),
        active_root_commitment_b64u: encode_base64url_bytes_v1(commitments.root_commitment()),
        lifecycle_revision,
        fence: CloudflareTenantRootRefreshFenceV1::Open,
        managed_restore_fence: CloudflareTenantRootManagedRestoreFenceV1::Open,
    })
}

#[cfg(feature = "workers-rs")]
fn validate_refresh_active_state_transition_v1(
    existing: &ValidatedTenantRootRefreshActiveStateV1,
    candidate: &ValidatedTenantRootRefreshActiveStateV1,
) -> RouterAbProtocolResult<()> {
    let TenantRootActivationReceiptBindingV1::RefreshSwap(binding) =
        candidate.activation_receipt.binding()
    else {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ForbiddenLocalBinding,
            "tenant-root refresh activation requires a refresh-swap receipt",
        ));
    };
    let expected_result_revision = existing
        .record
        .lifecycle_revision
        .checked_add(1)
        .ok_or_else(|| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "tenant-root refresh lifecycle revision cannot advance",
            )
        })?;
    if binding.identity_digest() != existing.identity_digest
        || binding.custody_lineage() != existing.custody_lineage
        || binding.current_epoch() != existing.active_epoch
        || binding.current_commitments() != &existing.commitments
        || binding.expected_control_plane_revision() != existing.record.lifecycle_revision
        || binding.result_control_plane_revision() != expected_result_revision
        || candidate.record.lifecycle_revision != expected_result_revision
    {
        return Err(refresh_replay_conflict(
            "tenant-root refresh activation receipt does not advance the authoritative active state",
        ));
    }
    if binding.next_epoch()
        != existing
            .active_epoch
            .next()
            .map_err(candidate_derivation_error)?
    {
        return Err(refresh_replay_conflict(
            "tenant-root refresh activation receipt epoch does not advance the authoritative active state",
        ));
    }
    Ok(())
}

#[cfg(feature = "workers-rs")]
fn refresh_activation_checkpoint_scope_v1(
    active: &ValidatedTenantRootRefreshActiveStateV1,
    activation_receipt: &router_ab_core::VerifiedTenantRootSignedActivationReceiptV1,
) -> RouterAbProtocolResult<CloudflareTenantRootRefreshCheckpointScopeV1> {
    let TenantRootActivationReceiptBindingV1::RefreshSwap(binding) = activation_receipt.binding()
    else {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ForbiddenLocalBinding,
            "tenant-root refresh activation requires a refresh-swap receipt",
        ));
    };
    Ok(CloudflareTenantRootRefreshCheckpointScopeV1 {
        identity_digest_b64u: encode_base64url_bytes_v1(active.identity_digest.as_bytes()),
        custody_lineage_b64u: active.custody_lineage.to_base64url(),
        authority_id_b64u: encode_base64url_bytes_v1(binding.authority_id().as_bytes()),
        ceremony_context_digest_b64u: encode_base64url_bytes_v1(
            binding.context_digest().as_bytes(),
        ),
        current_epoch: binding.current_epoch().get().get(),
        next_epoch: binding.next_epoch().get().get(),
        expected_control_plane_revision: binding.expected_control_plane_revision(),
        active_root_commitment_b64u: encode_base64url_bytes_v1(
            active.commitments.root_commitment(),
        ),
        active_activation_receipt_digest_b64u: encode_base64url_bytes_v1(
            active.activation_receipt_digest.as_bytes(),
        ),
        deriver_a_commitment_b64u: encode_base64url_bytes_v1(
            active.commitments.deriver_a().as_bytes(),
        ),
        deriver_b_commitment_b64u: encode_base64url_bytes_v1(
            active.commitments.deriver_b().as_bytes(),
        ),
    })
}

fn validate_refresh_active_state_record(
    record: CloudflareTenantRootRefreshActiveStateRecordV1,
    expected_authority_id: TenantRootControlPlaneAuthorityIdV1,
    issuer_keys: &BTreeMap<String, [u8; 32]>,
) -> RouterAbProtocolResult<ValidatedTenantRootRefreshActiveStateV1> {
    let receipt_bytes = decode_canonical_base64url(
        "tenant-root refresh active activation receipt",
        &record.activation_receipt_b64u,
        TENANT_ROOT_REFRESH_ACTIVE_RECEIPT_MAX_BYTES_V1,
        TENANT_ROOT_REFRESH_ACTIVE_RECEIPT_MAX_BASE64URL_BYTES_V1,
    )?;
    let activation_receipt =
        TenantRootSignedActivationReceiptV1::decode_canonical_bytes(&receipt_bytes)
            .map_err(candidate_derivation_error)?;
    let issuer_key_id = activation_receipt.issuer_key_id();
    let issuer_verifying_key = issuer_keys.get(issuer_key_id).ok_or_else(|| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ForbiddenLocalBinding,
            "stored tenant-root refresh activation receipt issuer is not trusted",
        )
    })?;
    let activation_receipt = activation_receipt
        .verify_issuer_signature(issuer_verifying_key)
        .map_err(candidate_authorization_error)?;
    let activation_receipt_digest = activation_receipt.digest();
    let stored_receipt_digest = decode_lifecycle_receipt_digest(
        "tenant-root refresh active activation receipt digest",
        &record.activation_receipt_digest_b64u,
    )?;
    if stored_receipt_digest != activation_receipt_digest {
        return Err(malformed_input(
            "tenant-root refresh active activation receipt digest does not match its bytes",
        ));
    }
    let identity_digest = TenantRootIdentityDigestV1::from_bytes(decode_fixed_base64url_32(
        "tenant-root refresh active identity digest",
        &record.identity_digest_b64u,
    )?);
    let custody_lineage = decode_lineage_b64u(
        "tenant-root refresh active custody lineage",
        &record.custody_lineage_b64u,
    )?;
    let active_epoch = TenantRootShareEpoch::new(record.active_epoch).map_err(|error| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            format!(
                "stored tenant-root refresh active epoch is invalid: {:?}",
                error.code()
            ),
        )
    })?;
    if record.lifecycle_revision == 0 {
        return Err(malformed_input(
            "stored tenant-root refresh lifecycle revision must be positive",
        ));
    }
    let commitments = TenantRootEpochCommitmentsV1::new(
        decode_share_commitment_b64u(
            "tenant-root refresh active Deriver A commitment",
            &record.deriver_a_commitment_b64u,
        )?,
        decode_share_commitment_b64u(
            "tenant-root refresh active Deriver B commitment",
            &record.deriver_b_commitment_b64u,
        )?,
    )
    .map_err(candidate_derivation_error)?;
    let active_root_commitment = decode_fixed_base64url_32(
        "tenant-root refresh active root commitment",
        &record.active_root_commitment_b64u,
    )?;
    if commitments.root_commitment() != &active_root_commitment {
        return Err(malformed_input(
            "tenant-root refresh active root commitment does not match its role commitments",
        ));
    }
    if activation_receipt.identity_digest() != identity_digest
        || activation_receipt.custody_lineage() != custody_lineage
        || activation_receipt.binding().authority_id() != expected_authority_id
    {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ForbiddenLocalBinding,
            "tenant-root refresh active state does not match its Durable Object authority",
        ));
    }
    let (receipt_epoch, receipt_commitments) = match activation_receipt.binding() {
        TenantRootActivationReceiptBindingV1::InitialCreation(binding) => {
            (binding.epoch(), binding.commitments())
        }
        TenantRootActivationReceiptBindingV1::RefreshSwap(binding) => {
            (binding.next_epoch(), binding.next_commitments())
        }
    };
    if active_epoch != receipt_epoch || &commitments != receipt_commitments {
        return Err(malformed_input(
            "tenant-root refresh active state does not match its activation receipt",
        ));
    }
    if record.lifecycle_revision < activation_receipt.result_control_plane_revision() {
        return Err(malformed_input(
            "tenant-root refresh active lifecycle revision predates activation receipt result",
        ));
    }
    let deriver_a = TenantRootActiveRoleBindingV1::new(
        TenantRootActiveRoleRowKeyV1::new(
            identity_digest,
            custody_lineage,
            active_epoch,
            TenantRootManagedRestoreRoleV1::DeriverA,
        ),
        commitments.deriver_a().clone(),
        activation_receipt_digest,
    )
    .map_err(candidate_derivation_error)?;
    let deriver_b = TenantRootActiveRoleBindingV1::new(
        TenantRootActiveRoleRowKeyV1::new(
            identity_digest,
            custody_lineage,
            active_epoch,
            TenantRootManagedRestoreRoleV1::DeriverB,
        ),
        commitments.deriver_b().clone(),
        activation_receipt_digest,
    )
    .map_err(candidate_derivation_error)?;
    let deriver_a = TenantRootActiveRoleResolutionV1::Active(deriver_a);
    let deriver_b = TenantRootActiveRoleResolutionV1::Active(deriver_b);
    let active_pair =
        resolve_active_tenant_root_pair_binding_v1(identity_digest, &deriver_a, &deriver_b)
            .map_err(candidate_derivation_error)?
            .require_active()
            .map_err(candidate_derivation_error)?
            .clone();
    if active_pair.root_commitment() != &active_root_commitment
        || active_pair.activation_receipt_digest() != activation_receipt_digest
    {
        return Err(malformed_input(
            "tenant-root refresh active pair does not match its persisted public state",
        ));
    }
    if let CloudflareTenantRootRefreshFenceV1::Terminal {
        attempt, response, ..
    } = &record.fence
    {
        validate_refresh_terminal_response(&record, &activation_receipt, attempt, response)?;
    }
    validate_refresh_fence(&record.fence)?;
    validate_managed_restore_fence_shape(&record.managed_restore_fence)?;
    require_managed_restore_fence_matches_active_fields_v1(
        &record.fence,
        &record.managed_restore_fence,
        identity_digest,
        custody_lineage,
        active_epoch,
        record.lifecycle_revision,
        &record.activation_receipt_b64u,
        activation_receipt_digest,
    )?;
    Ok(ValidatedTenantRootRefreshActiveStateV1 {
        record,
        identity_digest,
        custody_lineage,
        active_epoch,
        commitments,
        activation_receipt_digest,
        activation_receipt,
        active_pair,
    })
}

fn validate_refresh_attempt_packages(
    attempt: &CloudflareTenantRootRefreshAttemptV1,
) -> RouterAbProtocolResult<()> {
    let context_bytes = decode_canonical_base64url(
        "tenant-root refresh attempt context",
        &attempt.refresh_context_b64u,
        TENANT_ROOT_REFRESH_ATTEMPT_CONTEXT_MAX_BYTES_V1,
        base64url_len_for_bytes(TENANT_ROOT_REFRESH_ATTEMPT_CONTEXT_MAX_BYTES_V1),
    )?;
    let context = TenantRootCeremonyContextV1::decode_canonical_bytes(&context_bytes)
        .map_err(candidate_derivation_error)?;
    let context_digest = context.digest().map_err(candidate_derivation_error)?;
    if *context_digest.as_bytes()
        != decode_fixed_base64url_32(
            "tenant-root refresh attempt context digest",
            &attempt.ceremony_context_digest_b64u,
        )?
        || context.identity_digest()
            != TenantRootIdentityDigestV1::from_bytes(decode_fixed_base64url_32(
                "tenant-root refresh attempt identity digest",
                &attempt.identity_digest_b64u,
            )?)
    {
        return Err(malformed_input(
            "tenant-root refresh attempt context does not match its metadata",
        ));
    }
    let command_a_bytes = decode_canonical_base64url(
        "tenant-root refresh attempt Deriver A command",
        &attempt.deriver_a_refresh_command_b64u,
        TENANT_ROOT_REFRESH_ATTEMPT_COMMAND_MAX_BYTES_V1,
        base64url_len_for_bytes(TENANT_ROOT_REFRESH_ATTEMPT_COMMAND_MAX_BYTES_V1),
    )?;
    let command_b_bytes = decode_canonical_base64url(
        "tenant-root refresh attempt Deriver B command",
        &attempt.deriver_b_refresh_command_b64u,
        TENANT_ROOT_REFRESH_ATTEMPT_COMMAND_MAX_BYTES_V1,
        base64url_len_for_bytes(TENANT_ROOT_REFRESH_ATTEMPT_COMMAND_MAX_BYTES_V1),
    )?;
    let command_a = TenantRootRoleRefreshCommandV1::decode_canonical_bytes(&command_a_bytes)
        .map_err(candidate_derivation_error)?;
    let command_b = TenantRootRoleRefreshCommandV1::decode_canonical_bytes(&command_b_bytes)
        .map_err(candidate_derivation_error)?;
    if command_a
        .canonical_bytes()
        .map_err(candidate_derivation_error)?
        != command_a_bytes
        || command_b
            .canonical_bytes()
            .map_err(candidate_derivation_error)?
            != command_b_bytes
    {
        return Err(malformed_input(
            "tenant-root refresh attempt command package is not canonical",
        ));
    }
    let command_a_digest = command_a.digest().map_err(candidate_derivation_error)?;
    let command_b_digest = command_b.digest().map_err(candidate_derivation_error)?;
    if command_a.role() != TwoPartyDeriverRole::DeriverA
        || command_b.role() != TwoPartyDeriverRole::DeriverB
        || command_a.identity_digest() != command_b.identity_digest()
        || command_a.custody_lineage() != command_b.custody_lineage()
        || command_a.current_epoch() != command_b.current_epoch()
        || command_a.next_epoch() != command_b.next_epoch()
        || command_a.expected_control_plane_revision()
            != command_b.expected_control_plane_revision()
        || command_a.authority_id() != command_b.authority_id()
        || command_a.refresh_context_digest() != command_b.refresh_context_digest()
        || command_a.session_id() != command_b.session_id()
        || command_a.nonce() != command_b.nonce()
        || command_a.refresh_context_digest() != context_digest
        || context.identity_digest() != command_a.identity_digest()
        || context.custody_lineage() != command_a.custody_lineage()
        || context.session_id() != command_a.session_id()
        || context.nonce() != command_a.nonce()
        || command_a.current_epoch().get().get() != attempt.current_epoch
        || command_a.next_epoch().get().get() != attempt.next_epoch
        || command_a.expected_control_plane_revision() != attempt.expected_control_plane_revision
        || encode_base64url_bytes_v1(command_a_digest.as_bytes()) != attempt.command_digest_b64u
        || encode_base64url_bytes_v1(command_b_digest.as_bytes())
            != attempt.deriver_b_command_digest_b64u
        || encode_base64url_bytes_v1(context_digest.as_bytes())
            != attempt.ceremony_context_digest_b64u
        || encode_base64url_bytes_v1(command_a.session_id().as_bytes()) != attempt.attempt_id_b64u
        || attempt.attempt_id_b64u != attempt.session_id_b64u
        || encode_base64url_bytes_v1(command_a.nonce().as_bytes()) != attempt.nonce_b64u
    {
        return Err(malformed_input(
            "tenant-root refresh attempt command packages do not match their metadata",
        ));
    }
    Ok(())
}

fn validate_refresh_fence(
    fence: &CloudflareTenantRootRefreshFenceV1,
) -> RouterAbProtocolResult<()> {
    let attempt = match fence {
        CloudflareTenantRootRefreshFenceV1::Open => return Ok(()),
        CloudflareTenantRootRefreshFenceV1::Reserved { attempt }
        | CloudflareTenantRootRefreshFenceV1::Executed { attempt }
        | CloudflareTenantRootRefreshFenceV1::Terminal { attempt, .. } => attempt,
    };
    validate_refresh_attempt_packages(attempt)?;
    let attempt_id = decode_canonical_base64url(
        "tenant-root refresh attempt id",
        &attempt.attempt_id_b64u,
        16,
        base64url_len_for_bytes(16),
    )?;
    let session_id = decode_canonical_base64url(
        "tenant-root refresh attempt session id",
        &attempt.session_id_b64u,
        16,
        base64url_len_for_bytes(16),
    )?;
    if attempt_id != session_id {
        return Err(malformed_input(
            "tenant-root refresh attempt id must equal its session id",
        ));
    }
    let _ = decode_canonical_base64url(
        "tenant-root refresh attempt nonce",
        &attempt.nonce_b64u,
        32,
        base64url_len_for_bytes(32),
    )?;
    let _ = decode_protocol_digest_b64u(
        "tenant-root refresh attempt command digest",
        &attempt.command_digest_b64u,
    )?;
    let _ = decode_protocol_digest_b64u(
        "tenant-root refresh attempt context digest",
        &attempt.ceremony_context_digest_b64u,
    )?;
    let current_epoch =
        TenantRootShareEpoch::new(attempt.current_epoch).map_err(candidate_derivation_error)?;
    let next_epoch =
        TenantRootShareEpoch::new(attempt.next_epoch).map_err(candidate_derivation_error)?;
    if current_epoch.next().map_err(candidate_derivation_error)? != next_epoch {
        return Err(malformed_input(
            "tenant-root refresh attempt epochs must advance exactly one",
        ));
    }
    if attempt.expected_control_plane_revision == 0 {
        return Err(malformed_input(
            "tenant-root refresh attempt revision must be positive",
        ));
    }
    Ok(())
}

/// Builds the managed-restore challenge from the validated Started journal and
/// active activation receipt. The operator request contains only incident
/// coordinates and freshness data.
fn managed_restore_authorization_challenge_from_active_state_v1(
    active: &ValidatedTenantRootRefreshActiveStateV1,
    started_journal: &ValidatedTenantRootCreationJournalV1,
    request: CloudflareTenantRootManagedRestoreAuthorizationRequestV1,
) -> RouterAbProtocolResult<CloudflareTenantRootManagedRestoreAuthorizationChallengeV1> {
    validate_managed_restore_authorization_request_v1(&request)?;
    let identity = managed_restore_identity_from_started_journal_v1(active, started_journal)?;
    let identity_bytes = identity
        .canonical_bytes()
        .map_err(candidate_derivation_error)?;
    let activation_receipt_bytes = active.activation_receipt.canonical_bytes();
    let challenge = CloudflareTenantRootManagedRestoreAuthorizationChallengeV1 {
        identity_b64u: encode_base64url_bytes_v1(&identity_bytes),
        identity_digest_b64u: encode_base64url_bytes_v1(active.identity_digest.as_bytes()),
        custody_lineage_b64u: active.custody_lineage.to_base64url(),
        active_epoch: active.active_epoch.get().get(),
        active_lifecycle_revision: active.record.lifecycle_revision,
        activation_receipt_b64u: encode_base64url_bytes_v1(&activation_receipt_bytes),
        activation_receipt_digest_b64u: encode_base64url_bytes_v1(
            active.activation_receipt_digest.as_bytes(),
        ),
        incident_id: request.incident_id,
        outage_observation_digest_b64u: request.outage_observation_digest_b64u,
        issued_at_ms: request.issued_at_ms,
        expires_at_ms: request.expires_at_ms,
        nonce_b64u: request.nonce_b64u,
        unavailable_role: request.unavailable_role,
        challenge_digest_b64u: String::new(),
    };
    let challenge_digest = managed_restore_authorization_challenge_digest_v1(&challenge)?;
    Ok(CloudflareTenantRootManagedRestoreAuthorizationChallengeV1 {
        challenge_digest_b64u: encode_base64url_bytes_v1(challenge_digest.as_bytes()),
        ..challenge
    })
}

/// Reserves one managed-restore challenge/attempt or replays its exact fence.
/// A fresh request is required only while the fence is open; an exact retry
/// remains replayable after the original freshness window expires.
fn reserve_managed_restore_authorization_fence_v1(
    active: &ValidatedTenantRootRefreshActiveStateV1,
    started_journal: &ValidatedTenantRootCreationJournalV1,
    request: CloudflareTenantRootManagedRestoreAuthorizationRequestV1,
    now_ms: u64,
) -> RouterAbProtocolResult<CloudflareTenantRootManagedRestoreFenceEvaluationV1> {
    validate_managed_restore_fence_against_active_v1(active)?;
    match &active.record.managed_restore_fence {
        CloudflareTenantRootManagedRestoreFenceV1::Open => {
            let challenge = managed_restore_authorization_challenge_from_active_state_v1(
                active,
                started_journal,
                request,
            )?;
            let attempt = managed_restore_authorization_attempt_from_challenge_v1(&challenge)?;
            if !matches!(
                active.record.fence,
                CloudflareTenantRootRefreshFenceV1::Open
            ) {
                return Err(managed_restore_conflict(
                    "tenant-root managed-restore authorization conflicts with an active refresh",
                ));
            }
            require_managed_restore_challenge_fresh_v1(&challenge, now_ms)?;
            Ok(
                CloudflareTenantRootManagedRestoreFenceEvaluationV1::Commit {
                    fence: CloudflareTenantRootManagedRestoreFenceV1::Reserved {
                        challenge,
                        attempt,
                    },
                },
            )
        }
        CloudflareTenantRootManagedRestoreFenceV1::Reserved {
            challenge: stored_challenge,
            attempt: stored_attempt,
        } => {
            let challenge = managed_restore_authorization_challenge_from_active_state_v1(
                active,
                started_journal,
                request,
            )?;
            let attempt = managed_restore_authorization_attempt_from_challenge_v1(&challenge)?;
            if stored_challenge == &challenge && stored_attempt == &attempt {
                return Ok(
                    CloudflareTenantRootManagedRestoreFenceEvaluationV1::Replay {
                        fence: active.record.managed_restore_fence.clone(),
                    },
                );
            }
            Err(managed_restore_conflict(
                "tenant-root managed-restore authorization attempt conflicts with the accepted fence",
            ))
        }
        CloudflareTenantRootManagedRestoreFenceV1::Terminal {
            challenge: stored_challenge,
            ..
        } => {
            require_managed_restore_request_matches_terminal_challenge_v1(
                &request,
                stored_challenge,
            )?;
            Ok(
                CloudflareTenantRootManagedRestoreFenceEvaluationV1::Replay {
                    fence: active.record.managed_restore_fence.clone(),
                },
            )
        }
    }
}

/// A terminal fence is the authoritative replay record after activation has
/// advanced the active receipt and epoch. Match only the operator inputs; the
/// persisted challenge retains the prior active state that was authorized.
fn require_managed_restore_request_matches_terminal_challenge_v1(
    request: &CloudflareTenantRootManagedRestoreAuthorizationRequestV1,
    challenge: &CloudflareTenantRootManagedRestoreAuthorizationChallengeV1,
) -> RouterAbProtocolResult<()> {
    validate_managed_restore_authorization_request_v1(request)?;
    if request.incident_id != challenge.incident_id
        || request.outage_observation_digest_b64u != challenge.outage_observation_digest_b64u
        || request.issued_at_ms != challenge.issued_at_ms
        || request.expires_at_ms != challenge.expires_at_ms
        || request.nonce_b64u != challenge.nonce_b64u
        || request.unavailable_role != challenge.unavailable_role
    {
        return Err(managed_restore_conflict(
            "tenant-root managed-restore authorization attempt conflicts with the accepted fence",
        ));
    }
    Ok(())
}

/// Checkpoints exact signed public-state, capability, and incident-authorization
/// wires and terminalizes the reserved managed-restore fence. The wires remain
/// opaque to the DO.
fn checkpoint_managed_restore_authorization_fence_v1(
    active: &ValidatedTenantRootRefreshActiveStateV1,
    checkpoint: CloudflareTenantRootManagedRestoreAuthorizationCheckpointV1,
) -> RouterAbProtocolResult<CloudflareTenantRootManagedRestoreFenceEvaluationV1> {
    validate_managed_restore_fence_against_active_v1(active)?;
    validate_managed_restore_challenge_shape_v1(&checkpoint.challenge)?;
    validate_managed_restore_attempt_shape_v1(&checkpoint.attempt)?;
    validate_managed_restore_artifacts_v1(
        &checkpoint.public_state_b64u,
        &checkpoint.capability_b64u,
        &checkpoint.incident_authorization_b64u,
    )?;
    require_managed_restore_attempt_matches_challenge_v1(
        &checkpoint.challenge,
        &checkpoint.attempt,
    )?;

    match &active.record.managed_restore_fence {
        CloudflareTenantRootManagedRestoreFenceV1::Open => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MissingPairPreparation,
            "tenant-root managed-restore authorization requires a persisted reservation",
        )),
        CloudflareTenantRootManagedRestoreFenceV1::Reserved { challenge, attempt }
            if challenge == &checkpoint.challenge && attempt == &checkpoint.attempt =>
        {
            require_managed_restore_challenge_matches_active_v1(active, &checkpoint.challenge)?;
            Ok(
                CloudflareTenantRootManagedRestoreFenceEvaluationV1::Commit {
                    fence: CloudflareTenantRootManagedRestoreFenceV1::Terminal {
                        challenge: checkpoint.challenge,
                        attempt: checkpoint.attempt,
                        public_state_b64u: checkpoint.public_state_b64u,
                        capability_b64u: checkpoint.capability_b64u,
                        incident_authorization_b64u: checkpoint.incident_authorization_b64u,
                    },
                },
            )
        }
        CloudflareTenantRootManagedRestoreFenceV1::Terminal {
            challenge,
            attempt,
            public_state_b64u,
            capability_b64u,
            incident_authorization_b64u,
        } if challenge == &checkpoint.challenge
            && attempt == &checkpoint.attempt
            && public_state_b64u == &checkpoint.public_state_b64u
            && capability_b64u == &checkpoint.capability_b64u
            && incident_authorization_b64u == &checkpoint.incident_authorization_b64u =>
        {
            Ok(
                CloudflareTenantRootManagedRestoreFenceEvaluationV1::Replay {
                    fence: active.record.managed_restore_fence.clone(),
                },
            )
        }
        CloudflareTenantRootManagedRestoreFenceV1::Reserved { .. }
        | CloudflareTenantRootManagedRestoreFenceV1::Terminal { .. } => {
            Err(managed_restore_conflict(
                "tenant-root managed-restore checkpoint conflicts with the accepted fence",
            ))
        }
    }
}

fn managed_restore_identity_from_started_journal_v1(
    active: &ValidatedTenantRootRefreshActiveStateV1,
    started_journal: &ValidatedTenantRootCreationJournalV1,
) -> RouterAbProtocolResult<TenantRootIdentityV1> {
    if started_journal.identity_digest != active.identity_digest
        || started_journal.custody_lineage != active.custody_lineage
        || started_journal.journal.identity_digest() != active.identity_digest
        || started_journal.journal.custody_lineage() != active.custody_lineage
    {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ForbiddenLocalBinding,
            "tenant-root managed-restore Started journal does not match active state",
        ));
    }
    let identity = tenant_root_creation_identity_v1(&started_journal.journal)?;
    if identity.digest().map_err(candidate_derivation_error)? != active.identity_digest {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ForbiddenLocalBinding,
            "tenant-root managed-restore identity does not match active state",
        ));
    }
    Ok(identity)
}

fn require_managed_restore_challenge_matches_started_journal_v1(
    active: &ValidatedTenantRootRefreshActiveStateV1,
    started_journal: &ValidatedTenantRootCreationJournalV1,
    challenge: &CloudflareTenantRootManagedRestoreAuthorizationChallengeV1,
) -> RouterAbProtocolResult<()> {
    let identity = managed_restore_identity_from_started_journal_v1(active, started_journal)?;
    let identity_bytes = identity
        .canonical_bytes()
        .map_err(candidate_derivation_error)?;
    if challenge.identity_b64u != encode_base64url_bytes_v1(&identity_bytes) {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ForbiddenLocalBinding,
            "tenant-root managed-restore challenge identity is not the Started journal identity",
        ));
    }
    Ok(())
}

fn validate_managed_restore_authorization_request_v1(
    request: &CloudflareTenantRootManagedRestoreAuthorizationRequestV1,
) -> RouterAbProtocolResult<[u8; 32]> {
    validate_managed_restore_identifier_v1(
        "tenant-root managed-restore incident id",
        &request.incident_id,
    )?;
    let outage_observation_digest = decode_fixed_base64url_32(
        "tenant-root managed-restore outage observation digest",
        &request.outage_observation_digest_b64u,
    )?;
    TenantRootLifecycleReceiptDigestV1::from_bytes(outage_observation_digest)
        .map_err(candidate_derivation_error)?;
    validate_managed_restore_time_window_v1(
        "tenant-root managed-restore authorization",
        request.issued_at_ms,
        request.expires_at_ms,
    )?;
    let nonce = decode_canonical_base64url(
        "tenant-root managed-restore authorization nonce",
        &request.nonce_b64u,
        TENANT_ROOT_MANAGED_RESTORE_NONCE_BYTES_V1,
        base64url_len_for_bytes(TENANT_ROOT_MANAGED_RESTORE_NONCE_BYTES_V1),
    )?;
    if nonce.iter().all(|byte| *byte == 0) {
        return Err(malformed_input(
            "tenant-root managed-restore authorization nonce must be non-zero",
        ));
    }
    Ok(outage_observation_digest)
}

fn validate_managed_restore_challenge_shape_v1(
    challenge: &CloudflareTenantRootManagedRestoreAuthorizationChallengeV1,
) -> RouterAbProtocolResult<()> {
    let identity_bytes = decode_canonical_base64url(
        "tenant-root managed-restore challenge identity",
        &challenge.identity_b64u,
        TENANT_ROOT_MANAGED_RESTORE_IDENTITY_MAX_BYTES_V1,
        base64url_len_for_bytes(TENANT_ROOT_MANAGED_RESTORE_IDENTITY_MAX_BYTES_V1),
    )?;
    let identity = TenantRootIdentityV1::decode_canonical_bytes(&identity_bytes)
        .map_err(candidate_derivation_error)?;
    let identity_digest = TenantRootIdentityDigestV1::from_bytes(decode_fixed_base64url_32(
        "tenant-root managed-restore challenge identity digest",
        &challenge.identity_digest_b64u,
    )?);
    if identity.digest().map_err(candidate_derivation_error)? != identity_digest {
        return Err(malformed_input(
            "tenant-root managed-restore challenge identity does not match its digest",
        ));
    }
    let custody_lineage = decode_lineage_b64u(
        "tenant-root managed-restore challenge custody lineage",
        &challenge.custody_lineage_b64u,
    )?;
    let active_epoch =
        TenantRootShareEpoch::new(challenge.active_epoch).map_err(candidate_derivation_error)?;
    if challenge.active_lifecycle_revision == 0 {
        return Err(malformed_input(
            "tenant-root managed-restore challenge lifecycle revision must be positive",
        ));
    }
    let receipt_bytes = decode_canonical_base64url(
        "tenant-root managed-restore challenge activation receipt",
        &challenge.activation_receipt_b64u,
        TENANT_ROOT_REFRESH_ACTIVE_RECEIPT_MAX_BYTES_V1,
        TENANT_ROOT_REFRESH_ACTIVE_RECEIPT_MAX_BASE64URL_BYTES_V1,
    )?;
    let activation_receipt =
        TenantRootSignedActivationReceiptV1::decode_canonical_bytes(&receipt_bytes)
            .map_err(candidate_derivation_error)?;
    let activation_receipt_digest = decode_lifecycle_receipt_digest(
        "tenant-root managed-restore challenge activation receipt digest",
        &challenge.activation_receipt_digest_b64u,
    )?;
    if activation_receipt
        .digest()
        .map_err(candidate_derivation_error)?
        != activation_receipt_digest
        || activation_receipt.identity_digest() != identity_digest
        || activation_receipt.custody_lineage() != custody_lineage
    {
        return Err(malformed_input(
            "tenant-root managed-restore challenge activation receipt does not match its binding",
        ));
    }
    let activation_receipt_epoch = match activation_receipt.binding() {
        TenantRootActivationReceiptBindingV1::InitialCreation(binding) => binding.epoch(),
        TenantRootActivationReceiptBindingV1::RefreshSwap(binding) => binding.next_epoch(),
    };
    if activation_receipt_epoch != active_epoch {
        return Err(malformed_input(
            "tenant-root managed-restore challenge activation receipt epoch does not match its active epoch",
        ));
    }
    validate_managed_restore_identifier_v1(
        "tenant-root managed-restore challenge incident id",
        &challenge.incident_id,
    )?;
    TenantRootLifecycleReceiptDigestV1::from_bytes(decode_fixed_base64url_32(
        "tenant-root managed-restore challenge outage observation digest",
        &challenge.outage_observation_digest_b64u,
    )?)
    .map_err(candidate_derivation_error)?;
    validate_managed_restore_time_window_v1(
        "tenant-root managed-restore challenge",
        challenge.issued_at_ms,
        challenge.expires_at_ms,
    )?;
    let nonce = decode_canonical_base64url(
        "tenant-root managed-restore challenge nonce",
        &challenge.nonce_b64u,
        TENANT_ROOT_MANAGED_RESTORE_NONCE_BYTES_V1,
        base64url_len_for_bytes(TENANT_ROOT_MANAGED_RESTORE_NONCE_BYTES_V1),
    )?;
    if nonce.iter().all(|byte| *byte == 0) {
        return Err(malformed_input(
            "tenant-root managed-restore challenge nonce must be non-zero",
        ));
    }
    let expected_digest = managed_restore_authorization_challenge_digest_v1(challenge)?;
    if challenge.challenge_digest_b64u != encode_base64url_bytes_v1(expected_digest.as_bytes()) {
        return Err(malformed_input(
            "tenant-root managed-restore challenge digest does not match its fields",
        ));
    }
    Ok(())
}

fn validate_managed_restore_attempt_shape_v1(
    attempt: &CloudflareTenantRootManagedRestoreAuthorizationAttemptV1,
) -> RouterAbProtocolResult<()> {
    decode_protocol_digest_b64u(
        "tenant-root managed-restore attempt id",
        &attempt.attempt_id_b64u,
    )?;
    decode_protocol_digest_b64u(
        "tenant-root managed-restore attempt challenge digest",
        &attempt.challenge_digest_b64u,
    )?;
    Ok(())
}

fn validate_managed_restore_fence_shape(
    fence: &CloudflareTenantRootManagedRestoreFenceV1,
) -> RouterAbProtocolResult<()> {
    match fence {
        CloudflareTenantRootManagedRestoreFenceV1::Open => Ok(()),
        CloudflareTenantRootManagedRestoreFenceV1::Reserved { challenge, attempt } => {
            validate_managed_restore_challenge_shape_v1(challenge)?;
            validate_managed_restore_attempt_shape_v1(attempt)?;
            require_managed_restore_attempt_matches_challenge_v1(challenge, attempt)
        }
        CloudflareTenantRootManagedRestoreFenceV1::Terminal {
            challenge,
            attempt,
            public_state_b64u,
            capability_b64u,
            incident_authorization_b64u,
        } => {
            validate_managed_restore_challenge_shape_v1(challenge)?;
            validate_managed_restore_attempt_shape_v1(attempt)?;
            require_managed_restore_attempt_matches_challenge_v1(challenge, attempt)?;
            validate_managed_restore_artifacts_v1(
                public_state_b64u,
                capability_b64u,
                incident_authorization_b64u,
            )
        }
    }
}

fn validate_managed_restore_fence_against_active_v1(
    active: &ValidatedTenantRootRefreshActiveStateV1,
) -> RouterAbProtocolResult<()> {
    validate_managed_restore_fence_shape(&active.record.managed_restore_fence)?;
    require_managed_restore_fence_matches_active_fields_v1(
        &active.record.fence,
        &active.record.managed_restore_fence,
        active.identity_digest,
        active.custody_lineage,
        active.active_epoch,
        active.record.lifecycle_revision,
        &active.record.activation_receipt_b64u,
        active.activation_receipt_digest,
    )
}

fn require_managed_restore_fence_matches_active_fields_v1(
    refresh_fence: &CloudflareTenantRootRefreshFenceV1,
    fence: &CloudflareTenantRootManagedRestoreFenceV1,
    identity_digest: TenantRootIdentityDigestV1,
    custody_lineage: TenantRootCustodyLineageId,
    active_epoch: TenantRootShareEpoch,
    active_lifecycle_revision: u64,
    activation_receipt_b64u: &str,
    activation_receipt_digest: TenantRootLifecycleReceiptDigestV1,
) -> RouterAbProtocolResult<()> {
    let (challenge, _) = match fence {
        CloudflareTenantRootManagedRestoreFenceV1::Open => return Ok(()),
        CloudflareTenantRootManagedRestoreFenceV1::Reserved { challenge, attempt }
        | CloudflareTenantRootManagedRestoreFenceV1::Terminal {
            challenge, attempt, ..
        } => (challenge, attempt),
    };
    if require_managed_restore_challenge_matches_active_fields_v1(
        challenge,
        identity_digest,
        custody_lineage,
        active_epoch,
        active_lifecycle_revision,
        activation_receipt_b64u,
        activation_receipt_digest,
    )
    .is_ok()
    {
        return Ok(());
    }
    if matches!(
        fence,
        CloudflareTenantRootManagedRestoreFenceV1::Reserved { .. }
    ) {
        return Err(managed_restore_conflict(
            "tenant-root managed-restore reserved challenge does not match active state",
        ));
    }
    require_managed_restore_terminal_fence_matches_refresh_transition_v1(
        refresh_fence,
        challenge,
        identity_digest,
        custody_lineage,
        active_epoch,
        active_lifecycle_revision,
    )
}

fn require_managed_restore_terminal_fence_matches_refresh_transition_v1(
    refresh_fence: &CloudflareTenantRootRefreshFenceV1,
    challenge: &CloudflareTenantRootManagedRestoreAuthorizationChallengeV1,
    identity_digest: TenantRootIdentityDigestV1,
    custody_lineage: TenantRootCustodyLineageId,
    active_epoch: TenantRootShareEpoch,
    active_lifecycle_revision: u64,
) -> RouterAbProtocolResult<()> {
    let CloudflareTenantRootRefreshFenceV1::Terminal {
        attempt: refresh_attempt_for_state,
        outcome: CloudflareTenantRootRefreshTerminalOutcomeV1::Completed,
        ..
    } = refresh_fence
    else {
        return Err(managed_restore_conflict(
            "tenant-root managed-restore terminal challenge does not match active state",
        ));
    };
    if refresh_attempt_for_state.identity_digest_b64u
        != encode_base64url_bytes_v1(identity_digest.as_bytes())
        || refresh_attempt_for_state.custody_lineage_b64u != custody_lineage.to_base64url()
        || refresh_attempt_for_state.identity_digest_b64u != challenge.identity_digest_b64u
        || refresh_attempt_for_state.custody_lineage_b64u != challenge.custody_lineage_b64u
        || refresh_attempt_for_state.current_epoch != challenge.active_epoch
        || refresh_attempt_for_state.next_epoch != active_epoch.get().get()
        || refresh_attempt_for_state.expected_control_plane_revision
            != challenge.active_lifecycle_revision
        || challenge.active_lifecycle_revision.checked_add(1) != Some(active_lifecycle_revision)
    {
        return Err(managed_restore_conflict(
            "tenant-root managed-restore terminal challenge does not match the completed refresh transition",
        ));
    }
    Ok(())
}

fn require_managed_restore_challenge_matches_active_v1(
    active: &ValidatedTenantRootRefreshActiveStateV1,
    challenge: &CloudflareTenantRootManagedRestoreAuthorizationChallengeV1,
) -> RouterAbProtocolResult<()> {
    require_managed_restore_challenge_matches_active_fields_v1(
        challenge,
        active.identity_digest,
        active.custody_lineage,
        active.active_epoch,
        active.record.lifecycle_revision,
        &active.record.activation_receipt_b64u,
        active.activation_receipt_digest,
    )
}

fn require_managed_restore_challenge_matches_active_fields_v1(
    challenge: &CloudflareTenantRootManagedRestoreAuthorizationChallengeV1,
    identity_digest: TenantRootIdentityDigestV1,
    custody_lineage: TenantRootCustodyLineageId,
    active_epoch: TenantRootShareEpoch,
    active_lifecycle_revision: u64,
    activation_receipt_b64u: &str,
    activation_receipt_digest: TenantRootLifecycleReceiptDigestV1,
) -> RouterAbProtocolResult<()> {
    if challenge.identity_digest_b64u != encode_base64url_bytes_v1(identity_digest.as_bytes())
        || challenge.custody_lineage_b64u != custody_lineage.to_base64url()
        || challenge.active_epoch != active_epoch.get().get()
        || challenge.active_lifecycle_revision != active_lifecycle_revision
        || challenge.activation_receipt_b64u != activation_receipt_b64u
        || challenge.activation_receipt_digest_b64u
            != encode_base64url_bytes_v1(activation_receipt_digest.as_bytes())
    {
        return Err(managed_restore_conflict(
            "tenant-root managed-restore challenge does not match active state",
        ));
    }
    Ok(())
}

fn require_managed_restore_attempt_matches_challenge_v1(
    challenge: &CloudflareTenantRootManagedRestoreAuthorizationChallengeV1,
    attempt: &CloudflareTenantRootManagedRestoreAuthorizationAttemptV1,
) -> RouterAbProtocolResult<()> {
    let expected = managed_restore_authorization_attempt_from_challenge_v1(challenge)?;
    if &expected != attempt {
        return Err(managed_restore_conflict(
            "tenant-root managed-restore attempt does not match its challenge",
        ));
    }
    Ok(())
}

pub(crate) fn managed_restore_authorization_attempt_from_challenge_v1(
    challenge: &CloudflareTenantRootManagedRestoreAuthorizationChallengeV1,
) -> RouterAbProtocolResult<CloudflareTenantRootManagedRestoreAuthorizationAttemptV1> {
    let challenge_digest = decode_protocol_digest_b64u(
        "tenant-root managed-restore challenge digest",
        &challenge.challenge_digest_b64u,
    )?;
    let mut hasher = Sha256::new();
    hasher.update(TENANT_ROOT_MANAGED_RESTORE_ATTEMPT_DOMAIN_V1);
    update_managed_restore_hash_field(&mut hasher, challenge_digest.as_bytes())?;
    let attempt_id = TenantRootProtocolDigestV1::from_bytes(hasher.finalize().into())
        .map_err(candidate_derivation_error)?;
    Ok(CloudflareTenantRootManagedRestoreAuthorizationAttemptV1 {
        attempt_id_b64u: encode_base64url_bytes_v1(attempt_id.as_bytes()),
        challenge_digest_b64u: challenge.challenge_digest_b64u.clone(),
    })
}

fn managed_restore_authorization_challenge_digest_v1(
    challenge: &CloudflareTenantRootManagedRestoreAuthorizationChallengeV1,
) -> RouterAbProtocolResult<TenantRootProtocolDigestV1> {
    let identity_bytes = decode_canonical_base64url(
        "tenant-root managed-restore challenge identity",
        &challenge.identity_b64u,
        TENANT_ROOT_MANAGED_RESTORE_IDENTITY_MAX_BYTES_V1,
        base64url_len_for_bytes(TENANT_ROOT_MANAGED_RESTORE_IDENTITY_MAX_BYTES_V1),
    )?;
    let identity_digest = decode_fixed_base64url_32(
        "tenant-root managed-restore challenge identity digest",
        &challenge.identity_digest_b64u,
    )?;
    let custody_lineage = decode_canonical_base64url(
        "tenant-root managed-restore challenge custody lineage",
        &challenge.custody_lineage_b64u,
        16,
        base64url_len_for_bytes(16),
    )?;
    let receipt_bytes = decode_canonical_base64url(
        "tenant-root managed-restore challenge activation receipt",
        &challenge.activation_receipt_b64u,
        TENANT_ROOT_REFRESH_ACTIVE_RECEIPT_MAX_BYTES_V1,
        TENANT_ROOT_REFRESH_ACTIVE_RECEIPT_MAX_BASE64URL_BYTES_V1,
    )?;
    let receipt_digest = decode_fixed_base64url_32(
        "tenant-root managed-restore challenge activation receipt digest",
        &challenge.activation_receipt_digest_b64u,
    )?;
    let outage_observation_digest = decode_fixed_base64url_32(
        "tenant-root managed-restore challenge outage observation digest",
        &challenge.outage_observation_digest_b64u,
    )?;
    let nonce = decode_canonical_base64url(
        "tenant-root managed-restore challenge nonce",
        &challenge.nonce_b64u,
        TENANT_ROOT_MANAGED_RESTORE_NONCE_BYTES_V1,
        base64url_len_for_bytes(TENANT_ROOT_MANAGED_RESTORE_NONCE_BYTES_V1),
    )?;
    let mut hasher = Sha256::new();
    hasher.update(TENANT_ROOT_MANAGED_RESTORE_CHALLENGE_DOMAIN_V1);
    update_managed_restore_hash_field(&mut hasher, &identity_bytes)?;
    update_managed_restore_hash_field(&mut hasher, &identity_digest)?;
    update_managed_restore_hash_field(&mut hasher, &custody_lineage)?;
    update_managed_restore_hash_field(&mut hasher, &challenge.active_epoch.to_be_bytes())?;
    update_managed_restore_hash_field(
        &mut hasher,
        &challenge.active_lifecycle_revision.to_be_bytes(),
    )?;
    update_managed_restore_hash_field(&mut hasher, &receipt_bytes)?;
    update_managed_restore_hash_field(&mut hasher, &receipt_digest)?;
    update_managed_restore_hash_field(&mut hasher, challenge.incident_id.as_bytes())?;
    update_managed_restore_hash_field(&mut hasher, &outage_observation_digest)?;
    update_managed_restore_hash_field(&mut hasher, &challenge.issued_at_ms.to_be_bytes())?;
    update_managed_restore_hash_field(&mut hasher, &challenge.expires_at_ms.to_be_bytes())?;
    update_managed_restore_hash_field(&mut hasher, &nonce)?;
    let (role_label, role_id) = match challenge.unavailable_role {
        TenantRootManagedRestoreRoleV1::DeriverA => (b"deriver_a".as_slice(), 1_u16),
        TenantRootManagedRestoreRoleV1::DeriverB => (b"deriver_b".as_slice(), 2_u16),
    };
    update_managed_restore_hash_field(&mut hasher, role_label)?;
    update_managed_restore_hash_field(&mut hasher, &role_id.to_be_bytes())?;
    TenantRootProtocolDigestV1::from_bytes(hasher.finalize().into())
        .map_err(candidate_derivation_error)
}

fn update_managed_restore_hash_field(
    hasher: &mut Sha256,
    value: &[u8],
) -> RouterAbProtocolResult<()> {
    let length = u32::try_from(value.len())
        .map_err(|_| malformed_input("tenant-root managed-restore challenge field is too long"))?;
    hasher.update(length.to_be_bytes());
    hasher.update(value);
    Ok(())
}

fn require_managed_restore_challenge_fresh_v1(
    challenge: &CloudflareTenantRootManagedRestoreAuthorizationChallengeV1,
    now_ms: u64,
) -> RouterAbProtocolResult<()> {
    if now_ms < challenge.issued_at_ms || now_ms > challenge.expires_at_ms {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ExpiredLocalRequest,
            "tenant-root managed-restore authorization is outside its freshness window",
        ));
    }
    Ok(())
}

fn validate_managed_restore_time_window_v1(
    field: &'static str,
    issued_at_ms: u64,
    expires_at_ms: u64,
) -> RouterAbProtocolResult<()> {
    if issued_at_ms == 0 || expires_at_ms <= issued_at_ms {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidTimeRange,
            format!("{field} time window is invalid"),
        ));
    }
    if expires_at_ms - issued_at_ms > TENANT_ROOT_MAX_LIFETIME_MS_V1 {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidTimeRange,
            format!("{field} lifetime exceeds the frozen maximum window"),
        ));
    }
    Ok(())
}

fn validate_managed_restore_identifier_v1(
    field: &'static str,
    value: &str,
) -> RouterAbProtocolResult<()> {
    if value.is_empty() {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::EmptyField,
            format!("{field} is required"),
        ));
    }
    if value.len() > TENANT_ROOT_MANAGED_RESTORE_INCIDENT_MAX_BYTES_V1 {
        return Err(malformed_input(format!("{field} is too long")));
    }
    if value.trim() != value || value.chars().any(char::is_control) {
        return Err(malformed_input(format!(
            "{field} is not a valid identifier"
        )));
    }
    Ok(())
}

fn validate_managed_restore_artifacts_v1(
    public_state_b64u: &str,
    capability_b64u: &str,
    incident_authorization_b64u: &str,
) -> RouterAbProtocolResult<()> {
    // The DO records exact canonical wires. Signature verification belongs to
    // the control-plane and role boundaries that consume these artifacts.
    decode_canonical_base64url(
        "tenant-root managed-restore public state",
        public_state_b64u,
        TENANT_ROOT_MANAGED_RESTORE_PUBLIC_STATE_MAX_BYTES,
        TENANT_ROOT_MANAGED_RESTORE_PUBLIC_STATE_MAX_BASE64URL_BYTES_V1,
    )?;
    decode_canonical_base64url(
        "tenant-root managed-restore capability",
        capability_b64u,
        TENANT_ROOT_MANAGED_RESTORE_CAPABILITY_MAX_BYTES_V1,
        TENANT_ROOT_MANAGED_RESTORE_CAPABILITY_MAX_BASE64URL_BYTES_V1,
    )?;
    decode_canonical_base64url(
        "tenant-root managed-restore incident authorization",
        incident_authorization_b64u,
        TENANT_ROOT_MANAGED_RESTORE_INCIDENT_AUTHORIZATION_MAX_BYTES_V1,
        TENANT_ROOT_MANAGED_RESTORE_INCIDENT_AUTHORIZATION_MAX_BASE64URL_BYTES_V1,
    )?;
    Ok(())
}

fn managed_restore_conflict(message: &'static str) -> RouterAbProtocolError {
    RouterAbProtocolError::new(RouterAbProtocolErrorCode::ConflictingPair, message)
}

fn decode_lifecycle_receipt_digest(
    field: &str,
    encoded: &str,
) -> RouterAbProtocolResult<TenantRootLifecycleReceiptDigestV1> {
    TenantRootLifecycleReceiptDigestV1::from_bytes(decode_fixed_base64url_32(field, encoded)?)
        .map_err(candidate_derivation_error)
}

fn decode_lineage_b64u(
    field: &str,
    encoded: &str,
) -> RouterAbProtocolResult<TenantRootCustodyLineageId> {
    let bytes = decode_canonical_base64url(field, encoded, 16, base64url_len_for_bytes(16))?;
    TenantRootCustodyLineageId::from_bytes(
        bytes
            .try_into()
            .map_err(|_| malformed_input(format!("{field} must contain exactly 16 bytes")))?,
    )
    .map_err(candidate_derivation_error)
}

fn decode_share_commitment_b64u(
    field: &str,
    encoded: &str,
) -> RouterAbProtocolResult<MpcPrfShareCommitmentWireV1> {
    let bytes = decode_canonical_base64url(field, encoded, 128, base64url_len_for_bytes(128))?;
    MpcPrfShareCommitmentWireV1::new(bytes).map_err(candidate_derivation_error)
}

fn refresh_attempt_from_commands(
    context: &TenantRootCeremonyContextV1,
    deriver_a: &VerifiedTenantRootRoleRefreshCommandV1,
    deriver_b: &VerifiedTenantRootRoleRefreshCommandV1,
) -> RouterAbProtocolResult<CloudflareTenantRootRefreshAttemptV1> {
    if deriver_a.role() != TwoPartyDeriverRole::DeriverA
        || deriver_b.role() != TwoPartyDeriverRole::DeriverB
        || deriver_a.identity_digest() != deriver_b.identity_digest()
        || deriver_a.custody_lineage() != deriver_b.custody_lineage()
        || deriver_a.current_epoch() != deriver_b.current_epoch()
        || deriver_a.next_epoch() != deriver_b.next_epoch()
        || deriver_a.expected_control_plane_revision()
            != deriver_b.expected_control_plane_revision()
        || deriver_a.authority_id() != deriver_b.authority_id()
        || deriver_a.refresh_context_digest() != deriver_b.refresh_context_digest()
        || deriver_a.session_id() != deriver_b.session_id()
        || deriver_a.nonce() != deriver_b.nonce()
        || deriver_a.refresh_context_digest()
            != context.digest().map_err(candidate_derivation_error)?
        || context.identity_digest() != deriver_a.identity_digest()
        || context.custody_lineage() != deriver_a.custody_lineage()
        || context.session_id() != deriver_a.session_id()
        || context.nonce() != deriver_a.nonce()
    {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ConflictingPair,
            "tenant-root refresh attempt commands do not share one exact context",
        ));
    }
    Ok(CloudflareTenantRootRefreshAttemptV1 {
        attempt_id_b64u: encode_base64url_bytes_v1(deriver_a.session_id().as_bytes()),
        identity_digest_b64u: encode_base64url_bytes_v1(deriver_a.identity_digest().as_bytes()),
        custody_lineage_b64u: deriver_a.custody_lineage().to_base64url(),
        command_digest_b64u: encode_base64url_bytes_v1(deriver_a.digest().as_bytes()),
        deriver_b_command_digest_b64u: encode_base64url_bytes_v1(deriver_b.digest().as_bytes()),
        ceremony_context_digest_b64u: encode_base64url_bytes_v1(
            deriver_a.refresh_context_digest().as_bytes(),
        ),
        refresh_context_b64u: encode_base64url_bytes_v1(
            &context
                .canonical_bytes()
                .map_err(candidate_derivation_error)?,
        ),
        deriver_a_refresh_command_b64u: encode_base64url_bytes_v1(deriver_a.canonical_bytes()),
        deriver_b_refresh_command_b64u: encode_base64url_bytes_v1(deriver_b.canonical_bytes()),
        session_id_b64u: encode_base64url_bytes_v1(deriver_a.session_id().as_bytes()),
        nonce_b64u: encode_base64url_bytes_v1(deriver_a.nonce().as_bytes()),
        current_epoch: deriver_a.current_epoch().get().get(),
        next_epoch: deriver_a.next_epoch().get().get(),
        expected_control_plane_revision: deriver_a.expected_control_plane_revision(),
    })
}

fn require_refresh_attempt_matches_command(
    attempt: &CloudflareTenantRootRefreshAttemptV1,
    command: &VerifiedTenantRootRoleRefreshCommandV1,
) -> RouterAbProtocolResult<()> {
    let command_digest_b64u = encode_base64url_bytes_v1(command.digest().as_bytes());
    let expected_command_digest_b64u = match command.role() {
        TwoPartyDeriverRole::DeriverA => &attempt.command_digest_b64u,
        TwoPartyDeriverRole::DeriverB => &attempt.deriver_b_command_digest_b64u,
    };
    if command_digest_b64u != *expected_command_digest_b64u
        || encode_base64url_bytes_v1(command.identity_digest().as_bytes())
            != attempt.identity_digest_b64u
        || command.custody_lineage().to_base64url() != attempt.custody_lineage_b64u
        || encode_base64url_bytes_v1(command.refresh_context_digest().as_bytes())
            != attempt.ceremony_context_digest_b64u
        || encode_base64url_bytes_v1(command.session_id().as_bytes()) != attempt.session_id_b64u
        || encode_base64url_bytes_v1(command.nonce().as_bytes()) != attempt.nonce_b64u
        || command.current_epoch().get().get() != attempt.current_epoch
        || command.next_epoch().get().get() != attempt.next_epoch
        || command.expected_control_plane_revision() != attempt.expected_control_plane_revision
    {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ConflictingPair,
            "tenant-root refresh operation fence does not match the authenticated command",
        ));
    }
    Ok(())
}

fn require_refresh_fence_matches_command(
    fence: &CloudflareTenantRootRefreshFenceV1,
    command: &VerifiedTenantRootRoleRefreshCommandV1,
) -> RouterAbProtocolResult<()> {
    match fence {
        CloudflareTenantRootRefreshFenceV1::Open => Ok(()),
        CloudflareTenantRootRefreshFenceV1::Reserved { attempt }
        | CloudflareTenantRootRefreshFenceV1::Executed { attempt } => {
            require_refresh_attempt_matches_command(attempt, command)
        }
        CloudflareTenantRootRefreshFenceV1::Terminal { .. } => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ConflictingPair,
            "tenant-root refresh operation is terminal",
        )),
    }
}

fn refresh_reserved_fence(
    fence: &CloudflareTenantRootRefreshFenceV1,
    command: &VerifiedTenantRootRoleRefreshCommandV1,
) -> RouterAbProtocolResult<CloudflareTenantRootRefreshFenceV1> {
    match fence {
        CloudflareTenantRootRefreshFenceV1::Reserved { attempt } => {
            require_refresh_attempt_matches_command(attempt, command)?;
            Ok(CloudflareTenantRootRefreshFenceV1::Reserved {
                attempt: attempt.clone(),
            })
        }
        CloudflareTenantRootRefreshFenceV1::Open => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MissingPairPreparation,
            "tenant-root refresh commitment requires a persisted Router attempt",
        )),
        CloudflareTenantRootRefreshFenceV1::Executed { .. }
        | CloudflareTenantRootRefreshFenceV1::Terminal { .. } => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ConflictingPair,
            "tenant-root refresh operation has passed its commitment checkpoint",
        )),
    }
}

fn refresh_executed_fence(
    fence: &CloudflareTenantRootRefreshFenceV1,
    command: &VerifiedTenantRootRoleRefreshCommandV1,
) -> RouterAbProtocolResult<CloudflareTenantRootRefreshFenceV1> {
    match fence {
        CloudflareTenantRootRefreshFenceV1::Reserved { attempt }
        | CloudflareTenantRootRefreshFenceV1::Executed { attempt } => {
            require_refresh_attempt_matches_command(attempt, command)?;
            Ok(CloudflareTenantRootRefreshFenceV1::Executed {
                attempt: attempt.clone(),
            })
        }
        CloudflareTenantRootRefreshFenceV1::Open => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MissingPairPreparation,
            "tenant-root refresh installation requires a reserved operation",
        )),
        CloudflareTenantRootRefreshFenceV1::Terminal { .. } => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ConflictingPair,
            "tenant-root refresh operation is terminal",
        )),
    }
}

fn refresh_checkpoint_scope(
    command: &VerifiedTenantRootRoleRefreshCommandV1,
    active: &ValidatedTenantRootRefreshActiveStateV1,
    context: &TenantRootCeremonyContextV1,
    expected_authority_id: TenantRootControlPlaneAuthorityIdV1,
) -> RouterAbProtocolResult<CloudflareTenantRootRefreshCheckpointScopeV1> {
    context.validate().map_err(candidate_derivation_error)?;
    let TenantRootCeremonyEpochsV1::Refresh { current, next } = context.epochs() else {
        return Err(malformed_input(
            "tenant-root refresh checkpoint requires a refresh ceremony context",
        ));
    };
    let context_digest = context.digest().map_err(candidate_derivation_error)?;
    if command.authority_id() != expected_authority_id
        || command.identity_digest() != active.identity_digest
        || command.custody_lineage() != active.custody_lineage
        || command.current_epoch() != active.active_epoch
        || command.expected_control_plane_revision() != active.record.lifecycle_revision
        || command.deriver_a_share_commitment() != active.commitments.deriver_a()
        || command.deriver_b_share_commitment() != active.commitments.deriver_b()
        || command.active_root_commitment() != active.commitments.root_commitment()
        || command.active_activation_receipt_digest() != active.activation_receipt_digest
        || command.refresh_context_digest() != context_digest
        || context.identity_digest() != active.identity_digest
        || context.custody_lineage() != active.custody_lineage
        || current != active.active_epoch
        || command.next_epoch() != next
        || command.session_id() != context.session_id()
        || command.nonce() != context.nonce()
    {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ForbiddenLocalBinding,
            "tenant-root refresh command does not match the authoritative active state",
        ));
    }
    Ok(CloudflareTenantRootRefreshCheckpointScopeV1 {
        identity_digest_b64u: encode_base64url_bytes_v1(active.identity_digest.as_bytes()),
        custody_lineage_b64u: active.custody_lineage.to_base64url(),
        authority_id_b64u: encode_base64url_bytes_v1(expected_authority_id.as_bytes()),
        ceremony_context_digest_b64u: encode_base64url_bytes_v1(context_digest.as_bytes()),
        current_epoch: current.get().get(),
        next_epoch: next.get().get(),
        expected_control_plane_revision: active.record.lifecycle_revision,
        active_root_commitment_b64u: encode_base64url_bytes_v1(
            active.commitments.root_commitment(),
        ),
        active_activation_receipt_digest_b64u: encode_base64url_bytes_v1(
            active.activation_receipt_digest.as_bytes(),
        ),
        deriver_a_commitment_b64u: encode_base64url_bytes_v1(
            active.commitments.deriver_a().as_bytes(),
        ),
        deriver_b_commitment_b64u: encode_base64url_bytes_v1(
            active.commitments.deriver_b().as_bytes(),
        ),
    })
}

#[allow(dead_code)]
enum ValidatedTenantRootRefreshInstallationStateV1 {
    OneRole {
        role: TwoPartyDeriverRole,
        command_digest: TenantRootProtocolDigestV1,
        evidence: Box<VerifiedTenantRootSignedShareInstallationEvidenceWireV1>,
    },
    BothRoles {
        deriver_a_command_digest: TenantRootProtocolDigestV1,
        deriver_b_command_digest: TenantRootProtocolDigestV1,
        deriver_a: Box<VerifiedTenantRootSignedShareInstallationEvidenceWireV1>,
        deriver_b: Box<VerifiedTenantRootSignedShareInstallationEvidenceWireV1>,
        root_commitment: [u8; 32],
    },
}

fn verify_refresh_commitment_wire(
    bytes: &[u8],
    context: &TenantRootCeremonyContextV1,
    role_keys: &TenantRootCreationRoleVerifyingKeysV1,
) -> RouterAbProtocolResult<VerifiedTenantRootRefreshCommitmentV1> {
    let signed = TenantRootSignedRefreshCommitmentV1::decode_canonical_bytes(bytes)
        .map_err(candidate_derivation_error)?;
    let role = signed.role();
    let verifying_key = role_keys.for_role_and_key_id(role, signed.signing_key_id())?;
    signed
        .verify_strict(context, role, context.signing_key_id(role), verifying_key)
        .map_err(candidate_authorization_error)
}

fn verify_refresh_contribution_wire(
    bytes: &[u8],
    context: &TenantRootCeremonyContextV1,
    commitments: &VerifiedTenantRootRefreshCommitmentPairV1,
    role_keys: &TenantRootCreationRoleVerifyingKeysV1,
) -> RouterAbProtocolResult<VerifiedTenantRootSignedRefreshContributionV1> {
    let signed = TenantRootSignedRefreshContributionV1::decode_canonical_bytes(bytes)
        .map_err(candidate_derivation_error)?;
    let role = signed.envelope().source();
    let aad = match role {
        TwoPartyDeriverRole::DeriverA => {
            TenantRootRefreshContributionAadV1::deriver_a_to_b(commitments)
        }
        TwoPartyDeriverRole::DeriverB => {
            TenantRootRefreshContributionAadV1::deriver_b_to_a(commitments)
        }
    }
    .map_err(candidate_derivation_error)?;
    if aad.context() != context {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ForbiddenLocalBinding,
            "tenant-root refresh contribution does not match its ceremony context",
        ));
    }
    let verifying_key = role_keys.for_role_and_key_id(role, context.signing_key_id(role))?;
    signed
        .verify_signature(&aad, verifying_key)
        .map_err(candidate_authorization_error)
}

fn refresh_commitment_checkpoint_pair_digest(
    pair: &VerifiedTenantRootRefreshCommitmentPairV1,
) -> RouterAbProtocolResult<TenantRootProtocolDigestV1> {
    let mut hasher = Sha256::new();
    hasher.update(b"tenant_root_refresh_commitment_pair_v1");
    let deriver_a = pair.deriver_a().canonical_bytes();
    let deriver_b = pair.deriver_b().canonical_bytes();
    hasher.update((deriver_a.len() as u32).to_be_bytes());
    hasher.update(deriver_a);
    hasher.update((deriver_b.len() as u32).to_be_bytes());
    hasher.update(deriver_b);
    TenantRootProtocolDigestV1::from_bytes(hasher.finalize().into())
        .map_err(candidate_derivation_error)
}

fn encode_refresh_commitment_checkpoint(
    checkpoint: &TenantRootRefreshCommitmentCheckpointV1,
) -> RouterAbProtocolResult<String> {
    let bytes = checkpoint
        .canonical_bytes()
        .map_err(candidate_derivation_error)?;
    Ok(encode_base64url_bytes_v1(&bytes))
}

fn decode_refresh_commitment_checkpoint(
    encoded: &str,
) -> RouterAbProtocolResult<TenantRootRefreshCommitmentCheckpointV1> {
    let bytes = decode_canonical_base64url(
        "tenant-root refresh commitment checkpoint",
        encoded,
        TENANT_ROOT_REFRESH_COMMITMENT_CHECKPOINT_MAX_BYTES_V1,
        TENANT_ROOT_REFRESH_CHECKPOINT_MAX_BASE64URL_BYTES_V1,
    )?;
    TenantRootRefreshCommitmentCheckpointV1::decode_canonical_bytes(&bytes)
        .map_err(candidate_derivation_error)
}

fn validate_refresh_commitment_checkpoint_scope(
    stored: &TenantRootRefreshCommitmentCheckpointScopeV1,
    expected: &CloudflareTenantRootRefreshCheckpointScopeV1,
) -> RouterAbProtocolResult<()> {
    let expected_identity = TenantRootIdentityDigestV1::from_bytes(decode_fixed_base64url_32(
        "tenant-root refresh checkpoint identity digest",
        &expected.identity_digest_b64u,
    )?);
    let expected_lineage = decode_lineage_b64u(
        "tenant-root refresh checkpoint custody lineage",
        &expected.custody_lineage_b64u,
    )?;
    let expected_authority =
        TenantRootControlPlaneAuthorityIdV1::from_bytes(decode_fixed_base64url_32(
            "tenant-root refresh checkpoint authority id",
            &expected.authority_id_b64u,
        )?);
    let expected_context = decode_protocol_digest_b64u(
        "tenant-root refresh checkpoint context digest",
        &expected.ceremony_context_digest_b64u,
    )?;
    let expected_receipt = decode_lifecycle_receipt_digest(
        "tenant-root refresh checkpoint activation receipt digest",
        &expected.active_activation_receipt_digest_b64u,
    )?;
    let expected_deriver_a = decode_share_commitment_b64u(
        "tenant-root refresh checkpoint Deriver A commitment",
        &expected.deriver_a_commitment_b64u,
    )?;
    let expected_deriver_b = decode_share_commitment_b64u(
        "tenant-root refresh checkpoint Deriver B commitment",
        &expected.deriver_b_commitment_b64u,
    )?;
    let expected_root = decode_fixed_base64url_32(
        "tenant-root refresh checkpoint active root commitment",
        &expected.active_root_commitment_b64u,
    )?;
    if stored.identity_digest() != expected_identity
        || stored.custody_lineage() != expected_lineage
        || stored.authority_id() != expected_authority
        || stored.ceremony_context_digest() != expected_context
        || stored.current_epoch().get().get() != expected.current_epoch
        || stored.next_epoch().get().get() != expected.next_epoch
        || stored.expected_control_plane_revision() != expected.expected_control_plane_revision
        || stored.active_root_commitment() != &expected_root
        || stored.active_activation_receipt_digest() != expected_receipt
        || stored.deriver_a_share_commitment() != &expected_deriver_a
        || stored.deriver_b_share_commitment() != &expected_deriver_b
    {
        return Err(malformed_input(
            "stored tenant-root refresh commitment checkpoint scope is invalid",
        ));
    }
    Ok(())
}

fn require_complete_refresh_commitment_checkpoint(
    checkpoint: &TenantRootRefreshCommitmentCheckpointV1,
    context: &TenantRootCeremonyContextV1,
    role_keys: &TenantRootCreationRoleVerifyingKeysV1,
) -> RouterAbProtocolResult<VerifiedTenantRootRefreshCommitmentPairV1> {
    let deriver_a_bytes = checkpoint
        .state()
        .deriver_a_signed_commitment()
        .ok_or_else(|| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MissingPairPreparation,
                "tenant-root refresh installation requires both commitments",
            )
        })?;
    let deriver_b_bytes = checkpoint
        .state()
        .deriver_b_signed_commitment()
        .ok_or_else(|| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MissingPairPreparation,
                "tenant-root refresh installation requires both commitments",
            )
        })?;
    let deriver_a = verify_refresh_commitment_wire(deriver_a_bytes, context, role_keys)?;
    let deriver_b = verify_refresh_commitment_wire(deriver_b_bytes, context, role_keys)?;
    VerifiedTenantRootRefreshCommitmentPairV1::new(deriver_a, deriver_b)
        .map_err(candidate_derivation_error)
}

fn refresh_commitment_response_outcome(
    outcome: TenantRootRefreshCommitmentCheckpointOutcomeV1,
    candidate_bytes: &[u8],
) -> RouterAbProtocolResult<CloudflareTenantRootRefreshCommitmentResponseOutcomeV1> {
    match outcome {
        TenantRootRefreshCommitmentCheckpointOutcomeV1::WaitingForPeer { role } => Ok(
            CloudflareTenantRootRefreshCommitmentResponseOutcomeV1::WaitingForPeer {
                role: CloudflareTenantRootCreationInstallationRoleV1::from_protocol(role),
                signed_commitment_b64u: encode_base64url_bytes_v1(candidate_bytes),
            },
        ),
        TenantRootRefreshCommitmentCheckpointOutcomeV1::BothRolesCommitted { pair } => Ok(
            CloudflareTenantRootRefreshCommitmentResponseOutcomeV1::BothRolesCommitted {
                deriver_a_signed_commitment_b64u: encode_base64url_bytes_v1(
                    pair.deriver_a().canonical_bytes(),
                ),
                deriver_b_signed_commitment_b64u: encode_base64url_bytes_v1(
                    pair.deriver_b().canonical_bytes(),
                ),
                pair_digest_b64u: encode_base64url_bytes_v1(
                    refresh_commitment_checkpoint_pair_digest(&pair)?.as_bytes(),
                ),
            },
        ),
    }
}

fn refresh_commitment_evaluation_error(
    error: RouterAbDerivationError,
    has_existing_checkpoint: bool,
) -> RouterAbProtocolError {
    if error.code() == RouterAbDerivationErrorCode::ReplayMismatch {
        return refresh_replay_conflict(
            "tenant-root refresh commitment checkpoint conflicts with the accepted state",
        );
    }
    if has_existing_checkpoint {
        return stored_refresh_record_error(candidate_derivation_error(error));
    }
    candidate_derivation_error(error)
}

fn validate_refresh_installation_evidence_candidate(
    encoded: &str,
    context: &TenantRootCeremonyContextV1,
    role_keys: &TenantRootCreationRoleVerifyingKeysV1,
) -> RouterAbProtocolResult<VerifiedTenantRootSignedShareInstallationEvidenceWireV1> {
    let bytes = decode_canonical_base64url(
        "tenant-root signed refresh installation evidence",
        encoded,
        TENANT_ROOT_SIGNED_SHARE_INSTALLATION_EVIDENCE_MAX_BYTES_V1,
        TENANT_ROOT_CREATION_INSTALLATION_EVIDENCE_MAX_BASE64URL_BYTES_V1,
    )?;
    let verified = decode_and_verify_refresh_installation_evidence(&bytes, role_keys)?;
    if verified.evidence().transcript().context() != context {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ForbiddenLocalBinding,
            "tenant-root refresh installation evidence does not match its ceremony context",
        ));
    }
    Ok(verified)
}

fn decode_and_verify_refresh_installation_evidence(
    bytes: &[u8],
    role_keys: &TenantRootCreationRoleVerifyingKeysV1,
) -> RouterAbProtocolResult<VerifiedTenantRootSignedShareInstallationEvidenceWireV1> {
    let signed = TenantRootSignedShareInstallationEvidenceV1::decode_canonical_bytes(bytes)
        .map_err(candidate_derivation_error)?;
    let role = signed.role();
    let verifying_key = role_keys.for_role_and_key_id(role, signed.signing_key_id())?;
    TenantRootSignedShareInstallationEvidenceV1::decode_and_verify_canonical_bytes(
        bytes,
        verifying_key,
    )
    .map_err(candidate_authorization_error)
}

fn validate_refresh_installation_checkpoint(
    record: CloudflareTenantRootRefreshInstallationCheckpointRecordV1,
    expected_scope: &CloudflareTenantRootRefreshCheckpointScopeV1,
    context: &TenantRootCeremonyContextV1,
    role_keys: &TenantRootCreationRoleVerifyingKeysV1,
    commitments: &VerifiedTenantRootRefreshCommitmentPairV1,
    current_commitments: &TenantRootEpochCommitmentsV1,
) -> RouterAbProtocolResult<ValidatedTenantRootRefreshInstallationStateV1> {
    if &record.scope != expected_scope {
        return Err(malformed_input(
            "stored tenant-root refresh installation checkpoint scope is invalid",
        ));
    }
    match record.state {
        CloudflareTenantRootRefreshInstallationCheckpointStateV1::OneRoleReady {
            role,
            command_digest_b64u,
            signed_evidence_b64u,
        } => {
            let command_digest = decode_protocol_digest_b64u(
                "stored tenant-root refresh installation command digest",
                &command_digest_b64u,
            )?;
            let evidence = validate_refresh_installation_evidence_candidate(
                &signed_evidence_b64u,
                context,
                role_keys,
            )?;
            if evidence.evidence().transcript().role() != role.to_protocol() {
                return Err(malformed_input(
                    "stored tenant-root refresh installation role does not match its wire",
                ));
            }
            Ok(ValidatedTenantRootRefreshInstallationStateV1::OneRole {
                role: role.to_protocol(),
                command_digest,
                evidence: Box::new(evidence),
            })
        }
        CloudflareTenantRootRefreshInstallationCheckpointStateV1::BothRolesReady {
            deriver_a_command_digest_b64u,
            deriver_b_command_digest_b64u,
            deriver_a_signed_evidence_b64u,
            deriver_b_signed_evidence_b64u,
            root_commitment_b64u,
        } => {
            let deriver_a_command_digest = decode_protocol_digest_b64u(
                "stored tenant-root refresh Deriver A installation command digest",
                &deriver_a_command_digest_b64u,
            )?;
            let deriver_b_command_digest = decode_protocol_digest_b64u(
                "stored tenant-root refresh Deriver B installation command digest",
                &deriver_b_command_digest_b64u,
            )?;
            let deriver_a = validate_refresh_installation_evidence_candidate(
                &deriver_a_signed_evidence_b64u,
                context,
                role_keys,
            )?;
            let deriver_b = validate_refresh_installation_evidence_candidate(
                &deriver_b_signed_evidence_b64u,
                context,
                role_keys,
            )?;
            if deriver_a.evidence().transcript().role() != TwoPartyDeriverRole::DeriverA
                || deriver_b.evidence().transcript().role() != TwoPartyDeriverRole::DeriverB
            {
                return Err(malformed_input(
                    "stored tenant-root refresh installation pair roles are invalid",
                ));
            }
            let next_commitments = verify_tenant_root_refresh_installation_transition_v1(
                current_commitments,
                commitments,
                &deriver_a,
                &deriver_b,
            )
            .map_err(candidate_derivation_error)
            .map_err(stored_refresh_record_error)?;
            let stored_root = decode_fixed_base64url_32(
                "stored tenant-root refresh installation root commitment",
                &root_commitment_b64u,
            )?;
            if stored_root != *next_commitments.root_commitment() {
                return Err(malformed_input(
                    "stored tenant-root refresh installation root commitment is invalid",
                ));
            }
            Ok(ValidatedTenantRootRefreshInstallationStateV1::BothRoles {
                deriver_a_command_digest,
                deriver_b_command_digest,
                deriver_a: Box::new(deriver_a),
                deriver_b: Box::new(deriver_b),
                root_commitment: stored_root,
            })
        }
    }
}

fn decode_protocol_digest_b64u(
    field: &str,
    encoded: &str,
) -> RouterAbProtocolResult<TenantRootProtocolDigestV1> {
    TenantRootProtocolDigestV1::from_bytes(decode_fixed_base64url_32(field, encoded)?)
        .map_err(candidate_derivation_error)
}

fn require_fresh_refresh_command(
    command: &VerifiedTenantRootRoleRefreshCommandV1,
    context: &TenantRootCeremonyContextV1,
    now_ms: u64,
) -> RouterAbProtocolResult<()> {
    command.require_fresh(now_ms).map_err(|_| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ExpiredLocalRequest,
            "tenant-root refresh command is outside its freshness window",
        )
    })?;
    context.validate_at(now_ms).map_err(|_| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ExpiredLocalRequest,
            "tenant-root refresh ceremony context is outside its freshness window",
        )
    })
}

fn require_fresh_refresh_commitment_command(
    existing: Option<&TenantRootRefreshCommitmentCheckpointV1>,
    candidate_role: TwoPartyDeriverRole,
    command: &VerifiedTenantRootRoleRefreshCommandV1,
    context: &TenantRootCeremonyContextV1,
    now_ms: u64,
) -> RouterAbProtocolResult<()> {
    let requires_fresh = match existing {
        None => true,
        Some(checkpoint) => match checkpoint.state() {
            TenantRootRefreshCommitmentCheckpointStateV1::OneRoleCommitted { role, .. } => {
                *role != candidate_role
            }
            TenantRootRefreshCommitmentCheckpointStateV1::BothRolesCommitted { .. } => false,
        },
    };
    if requires_fresh {
        require_fresh_refresh_command(command, context, now_ms)?;
    }
    Ok(())
}

enum ValidatedTenantRootRefreshContributionRendezvousStateV1 {
    OneRole {
        role: TwoPartyDeriverRole,
        command_digest: TenantRootProtocolDigestV1,
        contribution: VerifiedTenantRootSignedRefreshContributionV1,
    },
    BothRoles {
        deriver_a_command_digest: TenantRootProtocolDigestV1,
        deriver_b_command_digest: TenantRootProtocolDigestV1,
        deriver_a: VerifiedTenantRootSignedRefreshContributionV1,
        deriver_b: VerifiedTenantRootSignedRefreshContributionV1,
    },
}

fn validate_refresh_contribution_rendezvous(
    record: CloudflareTenantRootRefreshContributionRendezvousRecordV1,
    expected_scope: &CloudflareTenantRootRefreshCheckpointScopeV1,
    context: &TenantRootCeremonyContextV1,
    commitments: &VerifiedTenantRootRefreshCommitmentPairV1,
    role_keys: &TenantRootCreationRoleVerifyingKeysV1,
) -> RouterAbProtocolResult<ValidatedTenantRootRefreshContributionRendezvousStateV1> {
    if &record.scope != expected_scope {
        return Err(malformed_input(
            "stored tenant-root refresh contribution rendezvous scope is invalid",
        ));
    }
    match record.state {
        CloudflareTenantRootRefreshContributionRendezvousStateV1::OneRoleContributed {
            role,
            command_digest_b64u,
            signed_contribution_b64u,
        } => {
            let command_digest = decode_protocol_digest_b64u(
                "stored tenant-root refresh contribution command digest",
                &command_digest_b64u,
            )?;
            let contribution_bytes = decode_canonical_base64url(
                "stored tenant-root signed refresh contribution",
                &signed_contribution_b64u,
                TENANT_ROOT_REFRESH_CONTRIBUTION_MAX_BYTES_V1,
                TENANT_ROOT_REFRESH_CONTRIBUTION_MAX_BASE64URL_BYTES_V1,
            )?;
            let contribution = verify_refresh_contribution_wire(
                &contribution_bytes,
                context,
                commitments,
                role_keys,
            )?;
            if contribution.source() != role.to_protocol() {
                return Err(malformed_input(
                    "stored tenant-root refresh contribution role does not match its wire",
                ));
            }
            Ok(
                ValidatedTenantRootRefreshContributionRendezvousStateV1::OneRole {
                    role: role.to_protocol(),
                    command_digest,
                    contribution,
                },
            )
        }
        CloudflareTenantRootRefreshContributionRendezvousStateV1::BothRolesContributed {
            deriver_a_command_digest_b64u,
            deriver_b_command_digest_b64u,
            deriver_a_signed_contribution_b64u,
            deriver_b_signed_contribution_b64u,
        } => {
            let deriver_a_command_digest = decode_protocol_digest_b64u(
                "stored tenant-root refresh Deriver A contribution command digest",
                &deriver_a_command_digest_b64u,
            )?;
            let deriver_b_command_digest = decode_protocol_digest_b64u(
                "stored tenant-root refresh Deriver B contribution command digest",
                &deriver_b_command_digest_b64u,
            )?;
            let deriver_a_bytes = decode_canonical_base64url(
                "stored tenant-root refresh Deriver A contribution",
                &deriver_a_signed_contribution_b64u,
                TENANT_ROOT_REFRESH_CONTRIBUTION_MAX_BYTES_V1,
                TENANT_ROOT_REFRESH_CONTRIBUTION_MAX_BASE64URL_BYTES_V1,
            )?;
            let deriver_b_bytes = decode_canonical_base64url(
                "stored tenant-root refresh Deriver B contribution",
                &deriver_b_signed_contribution_b64u,
                TENANT_ROOT_REFRESH_CONTRIBUTION_MAX_BYTES_V1,
                TENANT_ROOT_REFRESH_CONTRIBUTION_MAX_BASE64URL_BYTES_V1,
            )?;
            let deriver_a = verify_refresh_contribution_wire(
                &deriver_a_bytes,
                context,
                commitments,
                role_keys,
            )?;
            let deriver_b = verify_refresh_contribution_wire(
                &deriver_b_bytes,
                context,
                commitments,
                role_keys,
            )?;
            if deriver_a.source() != TwoPartyDeriverRole::DeriverA
                || deriver_b.source() != TwoPartyDeriverRole::DeriverB
            {
                return Err(malformed_input(
                    "stored tenant-root refresh contribution pair roles are invalid",
                ));
            }
            Ok(
                ValidatedTenantRootRefreshContributionRendezvousStateV1::BothRoles {
                    deriver_a_command_digest,
                    deriver_b_command_digest,
                    deriver_a,
                    deriver_b,
                },
            )
        }
    }
}

enum TenantRootRefreshContributionRendezvousEvaluationV1 {
    Commit {
        record: CloudflareTenantRootRefreshContributionRendezvousRecordV1,
        outcome: CloudflareTenantRootRefreshContributionResponseOutcomeV1,
    },
    Replay(CloudflareTenantRootRefreshContributionResponseOutcomeV1),
}

fn refresh_contribution_pair_outcome(
    deriver_a: &VerifiedTenantRootSignedRefreshContributionV1,
    deriver_b: &VerifiedTenantRootSignedRefreshContributionV1,
) -> CloudflareTenantRootRefreshContributionResponseOutcomeV1 {
    CloudflareTenantRootRefreshContributionResponseOutcomeV1::BothRolesContributed {
        deriver_a_signed_contribution_b64u: encode_base64url_bytes_v1(deriver_a.canonical_bytes()),
        deriver_b_signed_contribution_b64u: encode_base64url_bytes_v1(deriver_b.canonical_bytes()),
    }
}

fn evaluate_refresh_contribution_rendezvous(
    existing: Option<CloudflareTenantRootRefreshContributionRendezvousRecordV1>,
    candidate: VerifiedTenantRootSignedRefreshContributionV1,
    command: &VerifiedTenantRootRoleRefreshCommandV1,
    active: &ValidatedTenantRootRefreshActiveStateV1,
    context: &TenantRootCeremonyContextV1,
    commitments: &VerifiedTenantRootRefreshCommitmentPairV1,
    role_keys: &TenantRootCreationRoleVerifyingKeysV1,
    expected_authority_id: TenantRootControlPlaneAuthorityIdV1,
    now_ms: u64,
) -> RouterAbProtocolResult<TenantRootRefreshContributionRendezvousEvaluationV1> {
    require_refresh_fence_matches_command(&active.record.fence, command)?;
    let scope = refresh_checkpoint_scope(command, active, context, expected_authority_id)?;
    let candidate_role = candidate.source();
    if candidate_role != command.role() {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ForbiddenLocalBinding,
            "tenant-root refresh contribution role does not match its command",
        ));
    }
    let candidate_command_digest = command.digest();
    let candidate_bytes = candidate.canonical_bytes();
    let Some(existing) = existing else {
        require_fresh_refresh_command(command, context, now_ms)?;
        let record = CloudflareTenantRootRefreshContributionRendezvousRecordV1 {
            scope,
            state: CloudflareTenantRootRefreshContributionRendezvousStateV1::OneRoleContributed {
                role: CloudflareTenantRootCreationInstallationRoleV1::from_protocol(candidate_role),
                command_digest_b64u: encode_base64url_bytes_v1(candidate_command_digest.as_bytes()),
                signed_contribution_b64u: encode_base64url_bytes_v1(candidate_bytes),
            },
        };
        return Ok(
            TenantRootRefreshContributionRendezvousEvaluationV1::Commit {
                record,
                outcome: CloudflareTenantRootRefreshContributionResponseOutcomeV1::WaitingForPeer {
                    role: CloudflareTenantRootCreationInstallationRoleV1::from_protocol(
                        candidate_role,
                    ),
                },
            },
        );
    };
    let existing =
        validate_refresh_contribution_rendezvous(existing, &scope, context, commitments, role_keys)
            .map_err(stored_refresh_record_error)?;
    match existing {
        ValidatedTenantRootRefreshContributionRendezvousStateV1::OneRole {
            role,
            command_digest,
            contribution,
        } => {
            if role == candidate_role {
                if command_digest != candidate_command_digest
                    || contribution.canonical_bytes() != candidate_bytes
                {
                    return Err(refresh_replay_conflict(
                        "tenant-root refresh contribution retry does not match the accepted command and wire",
                    ));
                }
                return Ok(TenantRootRefreshContributionRendezvousEvaluationV1::Replay(
                    CloudflareTenantRootRefreshContributionResponseOutcomeV1::WaitingForPeer {
                        role: CloudflareTenantRootCreationInstallationRoleV1::from_protocol(role),
                    },
                ));
            }
            require_fresh_refresh_command(command, context, now_ms)?;
            let (deriver_a_command_digest, deriver_b_command_digest, deriver_a, deriver_b) =
                match candidate_role {
                    TwoPartyDeriverRole::DeriverA => (
                        candidate_command_digest,
                        command_digest,
                        candidate,
                        contribution,
                    ),
                    TwoPartyDeriverRole::DeriverB => (
                        command_digest,
                        candidate_command_digest,
                        contribution,
                        candidate,
                    ),
                };
            let outcome = refresh_contribution_pair_outcome(&deriver_a, &deriver_b);
            let record = CloudflareTenantRootRefreshContributionRendezvousRecordV1 {
                scope,
                state:
                    CloudflareTenantRootRefreshContributionRendezvousStateV1::BothRolesContributed {
                        deriver_a_command_digest_b64u: encode_base64url_bytes_v1(
                            deriver_a_command_digest.as_bytes(),
                        ),
                        deriver_b_command_digest_b64u: encode_base64url_bytes_v1(
                            deriver_b_command_digest.as_bytes(),
                        ),
                        deriver_a_signed_contribution_b64u: encode_base64url_bytes_v1(
                            deriver_a.canonical_bytes(),
                        ),
                        deriver_b_signed_contribution_b64u: encode_base64url_bytes_v1(
                            deriver_b.canonical_bytes(),
                        ),
                    },
            };
            Ok(TenantRootRefreshContributionRendezvousEvaluationV1::Commit { record, outcome })
        }
        ValidatedTenantRootRefreshContributionRendezvousStateV1::BothRoles {
            deriver_a_command_digest,
            deriver_b_command_digest,
            deriver_a,
            deriver_b,
        } => {
            let accepted_command_digest = match candidate_role {
                TwoPartyDeriverRole::DeriverA => deriver_a_command_digest,
                TwoPartyDeriverRole::DeriverB => deriver_b_command_digest,
            };
            let accepted_contribution = match candidate_role {
                TwoPartyDeriverRole::DeriverA => &deriver_a,
                TwoPartyDeriverRole::DeriverB => &deriver_b,
            };
            if accepted_command_digest != candidate_command_digest
                || accepted_contribution.canonical_bytes() != candidate_bytes
            {
                return Err(refresh_replay_conflict(
                    "tenant-root refresh contribution pair retry does not match the accepted command and wire",
                ));
            }
            let outcome = match candidate_role {
                TwoPartyDeriverRole::DeriverA => {
                    refresh_contribution_pair_outcome(accepted_contribution, &deriver_b)
                }
                TwoPartyDeriverRole::DeriverB => {
                    refresh_contribution_pair_outcome(&deriver_a, accepted_contribution)
                }
            };
            Ok(TenantRootRefreshContributionRendezvousEvaluationV1::Replay(
                outcome,
            ))
        }
    }
}

enum TenantRootRefreshInstallationCheckpointEvaluationV1 {
    Commit {
        checkpoint: CloudflareTenantRootRefreshInstallationCheckpointRecordV1,
        fence: CloudflareTenantRootRefreshFenceV1,
        outcome: CloudflareTenantRootRefreshInstallationResponseOutcomeV1,
    },
    Replay(CloudflareTenantRootRefreshInstallationResponseOutcomeV1),
}

fn evaluate_refresh_installation_checkpoint(
    existing: Option<CloudflareTenantRootRefreshInstallationCheckpointRecordV1>,
    candidate_bytes: &[u8],
    command: &VerifiedTenantRootRoleRefreshCommandV1,
    active: &ValidatedTenantRootRefreshActiveStateV1,
    context: &TenantRootCeremonyContextV1,
    role_keys: &TenantRootCreationRoleVerifyingKeysV1,
    commitments: &VerifiedTenantRootRefreshCommitmentPairV1,
    expected_authority_id: TenantRootControlPlaneAuthorityIdV1,
    terminal_receipt: &VerifiedTenantRootRefreshInstallationReceiptV1,
    _now_ms: u64,
) -> RouterAbProtocolResult<TenantRootRefreshInstallationCheckpointEvaluationV1> {
    require_refresh_fence_matches_command(&active.record.fence, command)?;
    let scope = refresh_checkpoint_scope(command, active, context, expected_authority_id)?;
    let encoded_candidate = encode_base64url_bytes_v1(candidate_bytes);
    let candidate =
        validate_refresh_installation_evidence_candidate(&encoded_candidate, context, role_keys)?;
    terminal_receipt.require_matches(candidate_bytes, command, context)?;
    if candidate.evidence().transcript().role() != command.role() {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ForbiddenLocalBinding,
            "tenant-root refresh installation evidence role does not match its command",
        ));
    }
    let candidate_role = candidate.evidence().transcript().role();
    let candidate_command_digest = command.digest();
    let Some(existing) = existing else {
        let checkpoint = refresh_installation_checkpoint_record(
            scope,
            CloudflareTenantRootRefreshInstallationCheckpointStateV1::OneRoleReady {
                role: CloudflareTenantRootCreationInstallationRoleV1::from_protocol(candidate_role),
                command_digest_b64u: encode_base64url_bytes_v1(candidate_command_digest.as_bytes()),
                signed_evidence_b64u: encoded_candidate,
            },
        );
        let fence = refresh_executed_fence(&active.record.fence, command)?;
        return Ok(
            TenantRootRefreshInstallationCheckpointEvaluationV1::Commit {
                checkpoint,
                fence,
                outcome: CloudflareTenantRootRefreshInstallationResponseOutcomeV1::WaitingForPeer {
                    role: CloudflareTenantRootCreationInstallationRoleV1::from_protocol(
                        candidate_role,
                    ),
                },
            },
        );
    };
    let existing = validate_refresh_installation_checkpoint(
        existing,
        &scope,
        context,
        role_keys,
        commitments,
        &active.commitments,
    )
    .map_err(stored_refresh_record_error)?;
    match existing {
        ValidatedTenantRootRefreshInstallationStateV1::OneRole {
            role,
            command_digest,
            evidence,
        } => {
            if role == candidate_role {
                if command_digest != candidate_command_digest
                    || evidence.canonical_bytes() != candidate_bytes
                {
                    return Err(refresh_replay_conflict(
                        "tenant-root refresh installation retry does not match the accepted command and wire",
                    ));
                }
                return Ok(TenantRootRefreshInstallationCheckpointEvaluationV1::Replay(
                    CloudflareTenantRootRefreshInstallationResponseOutcomeV1::WaitingForPeer {
                        role: CloudflareTenantRootCreationInstallationRoleV1::from_protocol(role),
                    },
                ));
            }
            let (deriver_a, deriver_b) = match candidate_role {
                TwoPartyDeriverRole::DeriverA => (candidate, *evidence),
                TwoPartyDeriverRole::DeriverB => (*evidence, candidate),
            };
            let next_commitments = verify_tenant_root_refresh_installation_transition_v1(
                &active.commitments,
                commitments,
                &deriver_a,
                &deriver_b,
            )
            .map_err(refresh_installation_transition_error)?;
            let root_commitment = *next_commitments.root_commitment();
            let (deriver_a_command_digest, deriver_b_command_digest) = match candidate_role {
                TwoPartyDeriverRole::DeriverA => (candidate_command_digest, command_digest),
                TwoPartyDeriverRole::DeriverB => (command_digest, candidate_command_digest),
            };
            let checkpoint = refresh_installation_checkpoint_record(
                scope,
                CloudflareTenantRootRefreshInstallationCheckpointStateV1::BothRolesReady {
                    deriver_a_command_digest_b64u: encode_base64url_bytes_v1(
                        deriver_a_command_digest.as_bytes(),
                    ),
                    deriver_b_command_digest_b64u: encode_base64url_bytes_v1(
                        deriver_b_command_digest.as_bytes(),
                    ),
                    deriver_a_signed_evidence_b64u: encode_base64url_bytes_v1(
                        deriver_a.canonical_bytes(),
                    ),
                    deriver_b_signed_evidence_b64u: encode_base64url_bytes_v1(
                        deriver_b.canonical_bytes(),
                    ),
                    root_commitment_b64u: encode_base64url_bytes_v1(&root_commitment),
                },
            );
            let fence = refresh_executed_fence(&active.record.fence, command)?;
            Ok(
                TenantRootRefreshInstallationCheckpointEvaluationV1::Commit {
                    checkpoint,
                    fence,
                    outcome:
                        CloudflareTenantRootRefreshInstallationResponseOutcomeV1::BothRolesReady {
                            root_commitment_b64u: encode_base64url_bytes_v1(&root_commitment),
                        },
                },
            )
        }
        ValidatedTenantRootRefreshInstallationStateV1::BothRoles {
            deriver_a_command_digest,
            deriver_b_command_digest,
            deriver_a,
            deriver_b,
            root_commitment,
        } => {
            let accepted_digest = match candidate_role {
                TwoPartyDeriverRole::DeriverA => deriver_a_command_digest,
                TwoPartyDeriverRole::DeriverB => deriver_b_command_digest,
            };
            let accepted = match candidate_role {
                TwoPartyDeriverRole::DeriverA => deriver_a,
                TwoPartyDeriverRole::DeriverB => deriver_b,
            };
            if accepted_digest != candidate_command_digest
                || accepted.canonical_bytes() != candidate_bytes
            {
                return Err(refresh_replay_conflict(
                    "tenant-root refresh installation pair retry does not match the accepted command and wire",
                ));
            }
            Ok(TenantRootRefreshInstallationCheckpointEvaluationV1::Replay(
                CloudflareTenantRootRefreshInstallationResponseOutcomeV1::BothRolesReady {
                    root_commitment_b64u: encode_base64url_bytes_v1(&root_commitment),
                },
            ))
        }
    }
}

fn refresh_installation_transition_error(_error: RouterAbDerivationError) -> RouterAbProtocolError {
    refresh_replay_conflict(
        "tenant-root refresh installation evidence conflicts with the accepted refresh transition",
    )
}

fn refresh_installation_checkpoint_record(
    scope: CloudflareTenantRootRefreshCheckpointScopeV1,
    state: CloudflareTenantRootRefreshInstallationCheckpointStateV1,
) -> CloudflareTenantRootRefreshInstallationCheckpointRecordV1 {
    CloudflareTenantRootRefreshInstallationCheckpointRecordV1 { scope, state }
}

fn refresh_replay_conflict(message: &'static str) -> RouterAbProtocolError {
    RouterAbProtocolError::new(RouterAbProtocolErrorCode::ConflictingPair, message)
}

fn stored_refresh_record_error(error: RouterAbProtocolError) -> RouterAbProtocolError {
    RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
        format!(
            "stored tenant-root refresh checkpoint is invalid: {:?}",
            error.code()
        ),
    )
}

#[cfg(feature = "workers-rs")]
#[allow(dead_code)]
pub(crate) async fn execute_cloudflare_router_tenant_root_refresh_commitment_call_v1(
    env: &worker::Env,
    command: &VerifiedTenantRootRoleRefreshCommandV1,
    commitment: &VerifiedTenantRootRefreshCommitmentV1,
) -> RouterAbProtocolResult<CloudflareTenantRootRefreshCommitmentResponseV1> {
    let context = commitment.transcript().context();
    let context_digest = context.digest().map_err(candidate_derivation_error)?;
    if command.refresh_context_digest() != context_digest || command.role() != commitment.role() {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ForbiddenLocalBinding,
            "tenant-root refresh commitment does not match its command",
        ));
    }
    let authority_id = command.authority_id();
    let request = CloudflareTenantRootRefreshCommitmentRequestV1 {
        role_refresh_command_b64u: encode_base64url_bytes_v1(command.canonical_bytes()),
        signed_commitment_b64u: encode_base64url_bytes_v1(commitment.canonical_bytes()),
    };
    let response = execute_cloudflare_router_tenant_root_creation_private_call_v1(
        env,
        authority_id,
        command.identity_digest(),
        command.custody_lineage(),
        CLOUDFLARE_TENANT_ROOT_REFRESH_COMMITMENT_CHECKPOINT_PATH,
        "tenant-root refresh commitment checkpoint",
        &request,
        TENANT_ROOT_REFRESH_COMMITMENT_REQUEST_MAX_BYTES_V1,
        TENANT_ROOT_REFRESH_COMMITMENT_RESPONSE_MAX_BYTES_V1,
    )
    .await?;
    validate_refresh_commitment_response(
        &response,
        command,
        commitment.canonical_bytes(),
        context,
    )?;
    Ok(response)
}

/// Sends one role-signed, recipient-bound encrypted refresh contribution to the
/// Router-owned public rendezvous after both commitments have completed.
#[cfg(feature = "workers-rs")]
#[allow(dead_code)]
pub(crate) async fn execute_cloudflare_router_tenant_root_refresh_contribution_call_v1(
    env: &worker::Env,
    command: &VerifiedTenantRootRoleRefreshCommandV1,
    commitments: &VerifiedTenantRootRefreshCommitmentPairV1,
    contribution: &VerifiedTenantRootSignedRefreshContributionV1,
) -> RouterAbProtocolResult<CloudflareTenantRootRefreshContributionResponseV1> {
    let context = commitments.context();
    let context_digest = context.digest().map_err(candidate_derivation_error)?;
    if command.refresh_context_digest() != context_digest || command.role() != contribution.source()
    {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ForbiddenLocalBinding,
            "tenant-root refresh contribution does not match its command or commitment pair",
        ));
    }
    let role_keys = read_tenant_root_creation_role_verifying_keys(env)?;
    let contribution_bytes = contribution.canonical_bytes();
    verify_refresh_contribution_wire(contribution_bytes, context, commitments, &role_keys)?;
    let request = CloudflareTenantRootRefreshContributionRequestV1 {
        role_refresh_command_b64u: encode_base64url_bytes_v1(command.canonical_bytes()),
        signed_contribution_b64u: encode_base64url_bytes_v1(contribution_bytes),
    };
    let response = execute_cloudflare_router_tenant_root_creation_private_call_v1(
        env,
        command.authority_id(),
        command.identity_digest(),
        command.custody_lineage(),
        CLOUDFLARE_TENANT_ROOT_REFRESH_CONTRIBUTION_RENDEZVOUS_PATH,
        "tenant-root refresh contribution rendezvous",
        &request,
        TENANT_ROOT_REFRESH_CONTRIBUTION_REQUEST_MAX_BYTES_V1,
        TENANT_ROOT_REFRESH_CONTRIBUTION_RESPONSE_MAX_BYTES_V1,
    )
    .await?;
    validate_refresh_contribution_response(
        &response,
        command,
        commitments,
        context,
        contribution_bytes,
        &role_keys,
    )?;
    Ok(response)
}

#[cfg(feature = "workers-rs")]
#[allow(dead_code)]
pub(crate) async fn execute_cloudflare_router_tenant_root_refresh_installation_call_v1(
    env: &worker::Env,
    command: &VerifiedTenantRootRoleRefreshCommandV1,
    evidence: &VerifiedTenantRootSignedShareInstallationEvidenceWireV1,
    terminal_receipt_bytes: &[u8],
) -> RouterAbProtocolResult<CloudflareTenantRootRefreshInstallationResponseV1> {
    let context = evidence.evidence().transcript().context();
    let context_digest = context.digest().map_err(candidate_derivation_error)?;
    if command.refresh_context_digest() != context_digest
        || command.role() != evidence.evidence().transcript().role()
    {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ForbiddenLocalBinding,
            "tenant-root refresh installation evidence does not match its command",
        ));
    }
    let request = CloudflareTenantRootRefreshInstallationRequestV1 {
        role_refresh_command_b64u: encode_base64url_bytes_v1(command.canonical_bytes()),
        signed_evidence_b64u: encode_base64url_bytes_v1(evidence.canonical_bytes()),
        terminal_receipt_b64u: encode_base64url_bytes_v1(terminal_receipt_bytes),
    };
    let response = execute_cloudflare_router_tenant_root_creation_private_call_v1(
        env,
        command.authority_id(),
        command.identity_digest(),
        command.custody_lineage(),
        CLOUDFLARE_TENANT_ROOT_REFRESH_INSTALLATION_CHECKPOINT_PATH,
        "tenant-root refresh installation checkpoint",
        &request,
        TENANT_ROOT_REFRESH_INSTALLATION_REQUEST_MAX_BYTES_V1,
        TENANT_ROOT_REFRESH_INSTALLATION_RESPONSE_MAX_BYTES_V1,
    )
    .await?;
    validate_refresh_installation_response(&response, command, context)?;
    Ok(response)
}

#[cfg(feature = "workers-rs")]
fn validate_refresh_commitment_response(
    response: &CloudflareTenantRootRefreshCommitmentResponseV1,
    command: &VerifiedTenantRootRoleRefreshCommandV1,
    candidate_bytes: &[u8],
    context: &TenantRootCeremonyContextV1,
) -> RouterAbProtocolResult<()> {
    validate_refresh_response_scope(response, command, context)?;
    match &response.outcome {
        CloudflareTenantRootRefreshCommitmentResponseOutcomeV1::WaitingForPeer {
            role,
            signed_commitment_b64u,
        } => {
            if role.to_protocol() != command.role() {
                return Err(malformed_input(
                    "tenant-root refresh commitment response role is invalid",
                ));
            }
            let returned = decode_canonical_base64url(
                "tenant-root refresh commitment response signed commitment",
                signed_commitment_b64u,
                TENANT_ROOT_REFRESH_COMMITMENT_MAX_BYTES_V1,
                TENANT_ROOT_REFRESH_COMMITMENT_MAX_BASE64URL_BYTES_V1,
            )?;
            if returned != candidate_bytes {
                return Err(malformed_input(
                    "tenant-root refresh commitment response does not replay the submitted wire",
                ));
            }
            let signed = TenantRootSignedRefreshCommitmentV1::decode_canonical_bytes(&returned)
                .map_err(candidate_derivation_error)?;
            if signed.role() != command.role() || signed.transcript().context() != context {
                return Err(malformed_input(
                    "tenant-root refresh commitment response wire is out of scope",
                ));
            }
        }
        CloudflareTenantRootRefreshCommitmentResponseOutcomeV1::BothRolesCommitted {
            deriver_a_signed_commitment_b64u,
            deriver_b_signed_commitment_b64u,
            pair_digest_b64u,
        } => {
            let deriver_a = decode_canonical_base64url(
                "tenant-root refresh response Deriver A commitment",
                deriver_a_signed_commitment_b64u,
                TENANT_ROOT_REFRESH_COMMITMENT_MAX_BYTES_V1,
                TENANT_ROOT_REFRESH_COMMITMENT_MAX_BASE64URL_BYTES_V1,
            )?;
            let deriver_b = decode_canonical_base64url(
                "tenant-root refresh response Deriver B commitment",
                deriver_b_signed_commitment_b64u,
                TENANT_ROOT_REFRESH_COMMITMENT_MAX_BYTES_V1,
                TENANT_ROOT_REFRESH_COMMITMENT_MAX_BASE64URL_BYTES_V1,
            )?;
            let deriver_a_signed =
                TenantRootSignedRefreshCommitmentV1::decode_canonical_bytes(&deriver_a)
                    .map_err(candidate_derivation_error)?;
            let deriver_b_signed =
                TenantRootSignedRefreshCommitmentV1::decode_canonical_bytes(&deriver_b)
                    .map_err(candidate_derivation_error)?;
            if deriver_a_signed.role() != TwoPartyDeriverRole::DeriverA
                || deriver_b_signed.role() != TwoPartyDeriverRole::DeriverB
                || deriver_a_signed.transcript().context() != context
                || deriver_b_signed.transcript().context() != context
            {
                return Err(malformed_input(
                    "tenant-root refresh commitment response pair is out of scope",
                ));
            }
            let expected_digest =
                refresh_commitment_pair_digest_from_bytes(&deriver_a, &deriver_b)?;
            validate_response_digest(
                "tenant-root refresh commitment response pair digest",
                pair_digest_b64u,
                expected_digest,
            )?;
            if deriver_a != candidate_bytes && deriver_b != candidate_bytes {
                return Err(malformed_input(
                    "tenant-root refresh commitment response pair omits the submitted wire",
                ));
            }
        }
    }
    Ok(())
}

#[cfg(feature = "workers-rs")]
fn validate_refresh_installation_response(
    response: &CloudflareTenantRootRefreshInstallationResponseV1,
    command: &VerifiedTenantRootRoleRefreshCommandV1,
    context: &TenantRootCeremonyContextV1,
) -> RouterAbProtocolResult<()> {
    validate_refresh_response_scope(response, command, context)?;
    if let CloudflareTenantRootRefreshInstallationResponseOutcomeV1::WaitingForPeer { role } =
        &response.outcome
    {
        if role.to_protocol() != command.role() {
            return Err(malformed_input(
                "tenant-root refresh installation response role is invalid",
            ));
        }
    }
    if let CloudflareTenantRootRefreshInstallationResponseOutcomeV1::BothRolesReady {
        root_commitment_b64u,
    } = &response.outcome
    {
        let _ = decode_fixed_base64url_32(
            "tenant-root refresh installation response root commitment",
            root_commitment_b64u,
        )?;
    }
    Ok(())
}

#[cfg(feature = "workers-rs")]
fn validate_refresh_contribution_response(
    response: &CloudflareTenantRootRefreshContributionResponseV1,
    command: &VerifiedTenantRootRoleRefreshCommandV1,
    commitments: &VerifiedTenantRootRefreshCommitmentPairV1,
    context: &TenantRootCeremonyContextV1,
    candidate_bytes: &[u8],
    role_keys: &TenantRootCreationRoleVerifyingKeysV1,
) -> RouterAbProtocolResult<()> {
    validate_refresh_response_scope(response, command, context)?;
    match &response.outcome {
        CloudflareTenantRootRefreshContributionResponseOutcomeV1::WaitingForPeer { role } => {
            if role.to_protocol() != command.role() {
                return Err(malformed_input(
                    "tenant-root refresh contribution response role is invalid",
                ));
            }
        }
        CloudflareTenantRootRefreshContributionResponseOutcomeV1::BothRolesContributed {
            deriver_a_signed_contribution_b64u,
            deriver_b_signed_contribution_b64u,
        } => {
            let deriver_a = decode_canonical_base64url(
                "tenant-root refresh response Deriver A contribution",
                deriver_a_signed_contribution_b64u,
                TENANT_ROOT_REFRESH_CONTRIBUTION_MAX_BYTES_V1,
                TENANT_ROOT_REFRESH_CONTRIBUTION_MAX_BASE64URL_BYTES_V1,
            )?;
            let deriver_b = decode_canonical_base64url(
                "tenant-root refresh response Deriver B contribution",
                deriver_b_signed_contribution_b64u,
                TENANT_ROOT_REFRESH_CONTRIBUTION_MAX_BYTES_V1,
                TENANT_ROOT_REFRESH_CONTRIBUTION_MAX_BASE64URL_BYTES_V1,
            )?;
            let verified_a =
                verify_refresh_contribution_wire(&deriver_a, context, commitments, role_keys)?;
            let verified_b =
                verify_refresh_contribution_wire(&deriver_b, context, commitments, role_keys)?;
            if verified_a.source() != TwoPartyDeriverRole::DeriverA
                || verified_b.source() != TwoPartyDeriverRole::DeriverB
            {
                return Err(malformed_input(
                    "tenant-root refresh contribution response pair roles are invalid",
                ));
            }
            let expected_candidate = match command.role() {
                TwoPartyDeriverRole::DeriverA => &deriver_a,
                TwoPartyDeriverRole::DeriverB => &deriver_b,
            };
            if expected_candidate.as_slice() != candidate_bytes {
                return Err(malformed_input(
                    "tenant-root refresh contribution response pair omits the submitted wire",
                ));
            }
        }
    }
    Ok(())
}

#[cfg(feature = "workers-rs")]
fn validate_refresh_response_scope<T>(
    response: &T,
    command: &VerifiedTenantRootRoleRefreshCommandV1,
    context: &TenantRootCeremonyContextV1,
) -> RouterAbProtocolResult<()>
where
    T: RefreshResponseScopeView,
{
    validate_response_digest(
        "tenant-root refresh response command digest",
        response.command_digest_b64u(),
        command.digest(),
    )?;
    validate_response_digest(
        "tenant-root refresh response identity digest",
        response.identity_digest_b64u(),
        TenantRootProtocolDigestV1::from_bytes(*command.identity_digest().as_bytes())
            .map_err(candidate_derivation_error)?,
    )?;
    validate_response_lineage(
        "tenant-root refresh response custody lineage",
        response.custody_lineage_b64u(),
        command.custody_lineage(),
    )?;
    validate_response_fixed_bytes(
        "tenant-root refresh response authority id",
        response.authority_id_b64u(),
        command.authority_id().as_bytes(),
    )?;
    validate_response_digest(
        "tenant-root refresh response ceremony context digest",
        response.ceremony_context_digest_b64u(),
        context.digest().map_err(candidate_derivation_error)?,
    )?;
    if response.current_epoch() != command.current_epoch().get().get()
        || response.next_epoch() != command.next_epoch().get().get()
        || response.expected_control_plane_revision() != command.expected_control_plane_revision()
    {
        return Err(malformed_input(
            "tenant-root refresh response scope does not match its command",
        ));
    }
    validate_response_fixed_bytes(
        "tenant-root refresh response active root commitment",
        response.active_root_commitment_b64u(),
        command.active_root_commitment(),
    )?;
    let expected_receipt_digest = command.active_activation_receipt_digest();
    validate_response_fixed_bytes(
        "tenant-root refresh response active activation receipt digest",
        response.active_activation_receipt_digest_b64u(),
        expected_receipt_digest.as_bytes(),
    )
}

#[cfg(feature = "workers-rs")]
trait RefreshResponseScopeView {
    fn command_digest_b64u(&self) -> &str;
    fn identity_digest_b64u(&self) -> &str;
    fn custody_lineage_b64u(&self) -> &str;
    fn authority_id_b64u(&self) -> &str;
    fn ceremony_context_digest_b64u(&self) -> &str;
    fn current_epoch(&self) -> u64;
    fn next_epoch(&self) -> u64;
    fn expected_control_plane_revision(&self) -> u64;
    fn active_root_commitment_b64u(&self) -> &str;
    fn active_activation_receipt_digest_b64u(&self) -> &str;
}

#[cfg(feature = "workers-rs")]
impl RefreshResponseScopeView for CloudflareTenantRootRefreshCommitmentResponseV1 {
    fn command_digest_b64u(&self) -> &str {
        &self.command_digest_b64u
    }
    fn identity_digest_b64u(&self) -> &str {
        &self.identity_digest_b64u
    }
    fn custody_lineage_b64u(&self) -> &str {
        &self.custody_lineage_b64u
    }
    fn authority_id_b64u(&self) -> &str {
        &self.authority_id_b64u
    }
    fn ceremony_context_digest_b64u(&self) -> &str {
        &self.ceremony_context_digest_b64u
    }
    fn current_epoch(&self) -> u64 {
        self.current_epoch
    }
    fn next_epoch(&self) -> u64 {
        self.next_epoch
    }
    fn expected_control_plane_revision(&self) -> u64 {
        self.expected_control_plane_revision
    }
    fn active_root_commitment_b64u(&self) -> &str {
        &self.active_root_commitment_b64u
    }
    fn active_activation_receipt_digest_b64u(&self) -> &str {
        &self.active_activation_receipt_digest_b64u
    }
}

#[cfg(feature = "workers-rs")]
impl RefreshResponseScopeView for CloudflareTenantRootRefreshInstallationResponseV1 {
    fn command_digest_b64u(&self) -> &str {
        &self.command_digest_b64u
    }
    fn identity_digest_b64u(&self) -> &str {
        &self.identity_digest_b64u
    }
    fn custody_lineage_b64u(&self) -> &str {
        &self.custody_lineage_b64u
    }
    fn authority_id_b64u(&self) -> &str {
        &self.authority_id_b64u
    }
    fn ceremony_context_digest_b64u(&self) -> &str {
        &self.ceremony_context_digest_b64u
    }
    fn current_epoch(&self) -> u64 {
        self.current_epoch
    }
    fn next_epoch(&self) -> u64 {
        self.next_epoch
    }
    fn expected_control_plane_revision(&self) -> u64 {
        self.expected_control_plane_revision
    }
    fn active_root_commitment_b64u(&self) -> &str {
        &self.active_root_commitment_b64u
    }
    fn active_activation_receipt_digest_b64u(&self) -> &str {
        &self.active_activation_receipt_digest_b64u
    }
}

#[cfg(feature = "workers-rs")]
impl RefreshResponseScopeView for CloudflareTenantRootRefreshContributionResponseV1 {
    fn command_digest_b64u(&self) -> &str {
        &self.command_digest_b64u
    }
    fn identity_digest_b64u(&self) -> &str {
        &self.identity_digest_b64u
    }
    fn custody_lineage_b64u(&self) -> &str {
        &self.custody_lineage_b64u
    }
    fn authority_id_b64u(&self) -> &str {
        &self.authority_id_b64u
    }
    fn ceremony_context_digest_b64u(&self) -> &str {
        &self.ceremony_context_digest_b64u
    }
    fn current_epoch(&self) -> u64 {
        self.current_epoch
    }
    fn next_epoch(&self) -> u64 {
        self.next_epoch
    }
    fn expected_control_plane_revision(&self) -> u64 {
        self.expected_control_plane_revision
    }
    fn active_root_commitment_b64u(&self) -> &str {
        &self.active_root_commitment_b64u
    }
    fn active_activation_receipt_digest_b64u(&self) -> &str {
        &self.active_activation_receipt_digest_b64u
    }
}

#[cfg(feature = "workers-rs")]
fn validate_response_fixed_bytes(
    field: &str,
    encoded: &str,
    expected: &[u8],
) -> RouterAbProtocolResult<()> {
    let decoded = decode_canonical_base64url(
        field,
        encoded,
        expected.len(),
        base64url_len_for_bytes(expected.len()),
    )?;
    if decoded != expected {
        return Err(malformed_input(format!(
            "{field} does not match the authenticated refresh scope"
        )));
    }
    Ok(())
}

fn refresh_commitment_pair_digest_from_bytes(
    deriver_a: &[u8],
    deriver_b: &[u8],
) -> RouterAbProtocolResult<TenantRootProtocolDigestV1> {
    let mut hasher = Sha256::new();
    hasher.update(b"tenant_root_refresh_commitment_pair_v1");
    hasher.update(
        u32::try_from(deriver_a.len())
            .map_err(|_| malformed_input("tenant-root refresh commitment wire is too long"))?
            .to_be_bytes(),
    );
    hasher.update(deriver_a);
    hasher.update(
        u32::try_from(deriver_b.len())
            .map_err(|_| malformed_input("tenant-root refresh commitment wire is too long"))?
            .to_be_bytes(),
    );
    hasher.update(deriver_b);
    TenantRootProtocolDigestV1::from_bytes(hasher.finalize().into())
        .map_err(candidate_derivation_error)
}

const fn base64url_len_for_bytes(bytes: usize) -> usize {
    (bytes / 3) * 4
        + match bytes % 3 {
            0 => 0,
            1 => 2,
            _ => 3,
        }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        TenantRootCutoverAttemptIdV1, TenantRootCutoverDrainReceiptV1,
        TenantRootCutoverFenceReceiptV1, TenantRootCutoverOpenV1, TenantRootCutoverPrerequisitesV1,
        TenantRootCutoverReceiptDigestV1,
    };
    use curve25519_dalek::scalar::Scalar;
    use ed25519_dalek::SigningKey;
    use rand_chacha::ChaCha20Rng;
    use rand_core::{CryptoRng, RngCore};
    use rand_core_06::SeedableRng;
    use router_ab_core::{
        seal_tenant_root_refresh_contribution_v1, MpcPrfSigningRootShareWireV1,
        TenantRootActivationReceiptTransitionV1, TenantRootCanaryCurveFamilyV1,
        TenantRootCeremonyContextV1, TenantRootCeremonyEpochsV1, TenantRootCeremonyNonceV1,
        TenantRootCeremonySessionIdV1, TenantRootCreationCapabilityNonceV1,
        TenantRootCreationCommitmentTranscriptV1, TenantRootCustodyLineageId,
        TenantRootManagedBackupBindingV1, TenantRootManagedBackupSealRequestV1,
        TenantRootProviderCanaryReceiptBindingV1, TenantRootRefreshCommitmentTranscriptV1,
        TenantRootRefreshContributionAadV1, TenantRootRefreshHpkeKeypairV1,
        TenantRootShareInstallationEvidenceV1, TenantRootShareInstallationTranscriptV1,
        TenantRootSignedManagedBackupV1, TenantRootSignedProviderCanaryReceiptV1,
        TenantRootSignedRefreshContributionV1,
        VerifiedTenantRootInitialCreationActivationEvidenceBundleV1,
        VerifiedTenantRootRefreshSwapActivationEvidenceBundleV1,
    };
    use threshold_prf::{
        prove_root_share_knowledge, RootShareRefreshCoefficient, SigningRootShare,
        SigningRootShareCommitment, SigningRootShareWire,
    };

    const ISSUER_KEY_ID: &str = "tenant-root-creation-issuer-v1";
    const SIGNING_KEY_BYTES: [u8; 32] = [0x71; 32];
    const DERIVER_A_SIGNING_KEY_BYTES: [u8; 32] = [0xa1; 32];
    const DERIVER_B_SIGNING_KEY_BYTES: [u8; 32] = [0xb1; 32];

    struct TestRng(u64);

    impl RngCore for TestRng {
        fn next_u32(&mut self) -> u32 {
            self.next_u64() as u32
        }

        fn next_u64(&mut self) -> u64 {
            self.0 ^= self.0 << 7;
            self.0 ^= self.0 >> 9;
            self.0 ^= self.0 << 8;
            self.0
        }

        fn fill_bytes(&mut self, destination: &mut [u8]) {
            for chunk in destination.chunks_mut(8) {
                let bytes = self.next_u64().to_le_bytes();
                let length = chunk.len();
                chunk.copy_from_slice(&bytes[..length]);
            }
        }
    }

    impl CryptoRng for TestRng {}
    const ACTIVE_RECEIPT_B64U: &str = "AAAAJ3NlYW1zL3RlbmFudC1yb290LWFjdGl2YXRpb24tcmVjZWlwdC92MQAAABBpbml0aWFsX2NyZWF0aW9uAAAAIBERERERERERERERERERERERERERERERERERERERERERAAAAECIiIiIiIiIiIiIiIiIiIiIAAAAIAAAAAAAAAAEAAAAgkI_pwUXEA4gcAvabBzqouVV7bYFT9VPpRZ10ciaUPikAAAAIAAAAAAAAAAIAAAAIAAAAAAAAAAMAAAAiAAHkVJ7ha5qgMJnKIIxnra_K-kw_Pk5TA95gJuPKj_hEYAAAACIAAkzxud7ak-uf1RX8yZJirtE2i0jySiev0phNqP57sjQfAAAAIOiCsTEBa1LB0zNwgBh892hCPvzLtRe7SVq4EsQWD_ROAAAAIMQ9g3dCkm7LYr3LZYshGa91a8Z9PLnqT3uf3jTE4aIxAAAAIDakJhm_fPXLIc4wnkXePcNdYGfNUjiEna5UZhH5AFHPAAAAFGN1cnJlbnRfcm9sZV9iYWNrdXBzAAAAIC2mFYLjHTKbc8aMOkEmcTVBYQfG-haBElDQh2WGuka_AAAAID1zStMyGYGvRh9E-TLEGvjbICdBkWWjxV1MO29AkQOMAAAAIIM2B2FzSVsXBnkngfyo5gVXqcVmpiT1tyNwUXER7ef7AAAAIPEpISsVxYb2unONkNRuxtq6LW6rokS_H89t5CwHRn1gAAAACAAAAAAAD0JKAAAAIHFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxAAAACAAAAAAAD0JAAAAACAAAAAAAD7dwAAAAF2NvbnRyb2wtcGxhbmUtaXNzdWVyLXYxAAAAQNj5VPnQhsrHKxUDM1Qj3_FxrfZPpPvjAdqVjvbR_dX9QguP3nfue5x0vHeXlHP1qC41Z2FODFPXTpYJb5GaPwE";

    fn authority(marker: u8) -> TenantRootControlPlaneAuthorityIdV1 {
        TenantRootControlPlaneAuthorityIdV1::from_bytes([marker; 32])
    }

    fn record(
        session_seed: u8,
        nonce_seed: u8,
        authority_id: TenantRootControlPlaneAuthorityIdV1,
        issued_at_ms: u64,
        expires_at_ms: u64,
    ) -> CloudflareTenantRootCreationJournalRecordV1 {
        let identity =
            TenantRootIdentityV1::new("org-1", "project-2", "production", "root-main", "v3")
                .expect("identity");
        let lineage = TenantRootCustodyLineageId::from_bytes([0x31; 16]).expect("lineage");
        let context = TenantRootCeremonyContextV1::new(
            identity.digest().expect("identity digest"),
            lineage,
            TenantRootCeremonyEpochsV1::create(),
            TenantRootCeremonySessionIdV1::from_bytes([session_seed; 16]).expect("session"),
            TenantRootCeremonyNonceV1::from_bytes([0x41; 32]).expect("nonce"),
            1_000_000,
            1_030_000,
            "deriver-a-signing-key-7",
            "deriver-b-signing-key-9",
        )
        .expect("context");
        let journal =
            TenantRootCreationJournalV1::started(identity, lineage, context).expect("journal");
        let journal_bytes = journal.canonical_bytes().expect("canonical journal");
        let capability = TenantRootCreationCapabilityV1::sign(
            journal.identity_digest(),
            journal.custody_lineage(),
            journal.digest().expect("journal digest"),
            authority_id,
            TenantRootCreationCapabilityNonceV1::from_bytes([nonce_seed; 32])
                .expect("capability nonce"),
            issued_at_ms,
            expires_at_ms,
            ISSUER_KEY_ID,
            &SIGNING_KEY_BYTES,
        )
        .expect("capability");
        CloudflareTenantRootCreationJournalRecordV1 {
            journal_b64u: encode_base64url_bytes_v1(&journal_bytes),
            creation_capability_b64u: encode_base64url_bytes_v1(
                &capability.canonical_bytes().expect("capability bytes"),
            ),
        }
    }

    fn read_request(
        journal: &ValidatedTenantRootCreationJournalV1,
    ) -> CloudflareTenantRootCreationJournalReadRequestV1 {
        CloudflareTenantRootCreationJournalReadRequestV1 {
            identity_digest_b64u: encode_base64url_bytes_v1(journal.identity_digest.as_bytes()),
            custody_lineage_b64u: encode_base64url_bytes_v1(journal.custody_lineage.as_bytes()),
        }
    }

    fn rendezvous_with(
        state: CloudflareTenantRootCreationCommitmentRendezvousStateV1,
    ) -> CloudflareTenantRootCreationCommitmentRendezvousRecordV1 {
        CloudflareTenantRootCreationCommitmentRendezvousRecordV1 {
            journal_digest_b64u: String::new(),
            identity_digest_b64u: String::new(),
            custody_lineage_b64u: String::new(),
            ceremony_context_digest_b64u: String::new(),
            state,
        }
    }

    /// The read projection returns exactly the persisted public bytes and the
    /// creation progress the issuer must respect, and nothing else.
    #[test]
    fn creation_journal_read_projects_exact_bytes_and_progress() {
        let record = record(0x11, 0x21, authority(0x44), 1_000_000, 1_030_000);
        let journal = validate_creation_record(record.clone(), authority(0x44), &verifying_keys())
            .expect("validated journal");
        let request = read_request(&journal);

        let fresh = build_creation_journal_read_response(&request, &journal, None, None, false)
            .expect("fresh");
        assert_eq!(fresh.journal_b64u, record.journal_b64u);
        assert_eq!(
            fresh.creation_capability_b64u,
            record.creation_capability_b64u
        );
        assert_eq!(fresh.revision, journal.journal.revision());
        assert!(fresh.committed_roles.is_empty());
        assert_eq!(
            fresh.installation_checkpoint,
            CloudflareTenantRootCreationInstallationCheckpointReadStateV1::None
        );
        assert!(!fresh.cleanup_checkpointed);

        let one = rendezvous_with(
            CloudflareTenantRootCreationCommitmentRendezvousStateV1::OneRoleCommitted {
                role: CloudflareTenantRootCreationInstallationRoleV1::DeriverB,
                signed_commitment_b64u: String::new(),
            },
        );
        let one_committed =
            build_creation_journal_read_response(&request, &journal, Some(&one), None, false)
                .expect("one committed");
        assert_eq!(
            one_committed.committed_roles,
            vec![CloudflareTenantRootCreationInstallationRoleV1::DeriverB]
        );

        let both = rendezvous_with(
            CloudflareTenantRootCreationCommitmentRendezvousStateV1::BothRolesCommitted {
                deriver_a_signed_commitment_b64u: String::new(),
                deriver_b_signed_commitment_b64u: String::new(),
            },
        );
        let (one_checkpoint, commitments) = deriver_b_installation_checkpoint(&journal, 1_010_000);
        let expected_evidence = match &one_checkpoint.state {
            CloudflareTenantRootCreationInstallationStateV1::OneRoleReady {
                signed_evidence_b64u,
                ..
            } => signed_evidence_b64u.clone(),
            CloudflareTenantRootCreationInstallationStateV1::BothRolesReady { .. } => {
                panic!("expected one installation record")
            }
        };
        let one_checkpoint_for_read = validate_installation_checkpoint(
            one_checkpoint.clone(),
            &journal,
            &role_keys(),
            &commitments,
        )
        .expect("one installation checkpoint");
        let one_read = build_creation_journal_read_response(
            &request,
            &journal,
            Some(&both),
            Some(&one_checkpoint_for_read),
            false,
        )
        .expect("one ready");
        assert_eq!(
            one_read.committed_roles,
            vec![
                CloudflareTenantRootCreationInstallationRoleV1::DeriverA,
                CloudflareTenantRootCreationInstallationRoleV1::DeriverB,
            ]
        );
        let CloudflareTenantRootCreationInstallationCheckpointReadStateV1::OneRoleReady {
            role,
            signed_evidence_b64u,
        } = one_read.installation_checkpoint
        else {
            panic!("expected one installation checkpoint");
        };
        assert_eq!(
            role,
            CloudflareTenantRootCreationInstallationRoleV1::DeriverB
        );
        assert_eq!(signed_evidence_b64u, expected_evidence);
        assert!(!one_read.cleanup_checkpointed);

        let command_a = role_creation_command(&journal, TwoPartyDeriverRole::DeriverA);
        let both_checkpoint = match evaluate_installation_checkpoint(
            Some(one_checkpoint),
            installation_wire(&journal, TwoPartyDeriverRole::DeriverA, 12, 19, 0x61),
            &command_a,
            &journal,
            &role_keys(),
            &commitments,
            1_010_000,
        )
        .expect("both installation checkpoints")
        {
            TenantRootCreationInstallationEvaluationV1::Commit { checkpoint, .. } => checkpoint,
            other => panic!("unexpected installation checkpoint outcome: {other:?}"),
        };
        let expected_root = match &both_checkpoint.state {
            CloudflareTenantRootCreationInstallationStateV1::BothRolesReady {
                root_commitment_b64u,
                ..
            } => root_commitment_b64u.clone(),
            CloudflareTenantRootCreationInstallationStateV1::OneRoleReady { .. } => {
                panic!("expected both installation record")
            }
        };
        let both_checkpoint =
            validate_installation_checkpoint(both_checkpoint, &journal, &role_keys(), &commitments)
                .expect("both installation checkpoint");
        let completed = build_creation_journal_read_response(
            &request,
            &journal,
            Some(&both),
            Some(&both_checkpoint),
            false,
        )
        .expect("both ready");
        assert!(matches!(
            completed.installation_checkpoint,
            CloudflareTenantRootCreationInstallationCheckpointReadStateV1::BothRolesReady {
                root_commitment_b64u
            } if root_commitment_b64u == expected_root
        ));

        let abandoned = build_creation_journal_read_response(
            &request,
            &journal,
            Some(&both),
            Some(&both_checkpoint),
            true,
        )
        .expect("abandoned");
        assert!(matches!(
            abandoned.installation_checkpoint,
            CloudflareTenantRootCreationInstallationCheckpointReadStateV1::BothRolesReady { .. }
        ));
        assert!(abandoned.cleanup_checkpointed);
    }

    /// A caller that reached the wrong object fails closed on identity or lineage.
    #[test]
    fn creation_journal_read_rejects_a_foreign_identity_or_lineage() {
        let record = record(0x11, 0x21, authority(0x44), 1_000_000, 1_030_000);
        let journal = validate_creation_record(record, authority(0x44), &verifying_keys())
            .expect("validated journal");
        let honest = read_request(&journal);

        let mut foreign_identity = honest.clone();
        foreign_identity.identity_digest_b64u = encode_base64url_bytes_v1(&[0x99; 32]);
        assert!(build_creation_journal_read_response(
            &foreign_identity,
            &journal,
            None,
            None,
            false
        )
        .is_err());

        let mut foreign_lineage = honest.clone();
        foreign_lineage.custody_lineage_b64u = encode_base64url_bytes_v1(&[0x98; 16]);
        assert!(build_creation_journal_read_response(
            &foreign_lineage,
            &journal,
            None,
            None,
            false
        )
        .is_err());

        // Malformed encodings fail closed rather than comparing loosely.
        let mut malformed = honest;
        malformed.identity_digest_b64u = "not base64url!".to_owned();
        assert!(
            build_creation_journal_read_response(&malformed, &journal, None, None, false).is_err()
        );
    }

    fn verifying_key() -> [u8; 32] {
        SigningKey::from_bytes(&SIGNING_KEY_BYTES)
            .verifying_key()
            .to_bytes()
    }

    fn verifying_keys() -> BTreeMap<String, [u8; 32]> {
        BTreeMap::from([(ISSUER_KEY_ID.to_owned(), verifying_key())])
    }

    fn active_refresh_state_fixture() -> (
        CloudflareTenantRootRefreshActiveStateRecordV1,
        BTreeMap<String, [u8; 32]>,
    ) {
        let receipt_b64u = ACTIVE_RECEIPT_B64U.to_owned();
        let receipt_bytes = decode_base64url_bytes_v1("active activation receipt", &receipt_b64u)
            .expect("active receipt bytes");
        let receipt = TenantRootSignedActivationReceiptV1::decode_canonical_bytes(&receipt_bytes)
            .expect("active receipt");
        let digest = receipt.digest().expect("active receipt digest");
        let (active_epoch, commitments) = match receipt.binding() {
            TenantRootActivationReceiptBindingV1::InitialCreation(binding) => {
                (binding.epoch(), binding.commitments())
            }
            TenantRootActivationReceiptBindingV1::RefreshSwap(binding) => {
                (binding.next_epoch(), binding.next_commitments())
            }
        };
        let record = CloudflareTenantRootRefreshActiveStateRecordV1 {
            activation_receipt_b64u: receipt_b64u,
            activation_receipt_digest_b64u: encode_base64url_bytes_v1(digest.as_bytes()),
            identity_digest_b64u: encode_base64url_bytes_v1(receipt.identity_digest().as_bytes()),
            custody_lineage_b64u: receipt.custody_lineage().to_base64url(),
            active_epoch: active_epoch.get().get(),
            deriver_a_commitment_b64u: encode_base64url_bytes_v1(
                commitments.deriver_a().as_bytes(),
            ),
            deriver_b_commitment_b64u: encode_base64url_bytes_v1(
                commitments.deriver_b().as_bytes(),
            ),
            active_root_commitment_b64u: encode_base64url_bytes_v1(commitments.root_commitment()),
            lifecycle_revision: receipt.result_control_plane_revision(),
            fence: CloudflareTenantRootRefreshFenceV1::Open,
            managed_restore_fence: CloudflareTenantRootManagedRestoreFenceV1::Open,
        };
        let verifying_key = SigningKey::from_bytes(&[0x41; 32])
            .verifying_key()
            .to_bytes();
        let issuer_keys = BTreeMap::from([(receipt.issuer_key_id().to_owned(), verifying_key)]);
        (record, issuer_keys)
    }

    fn validate(
        record: CloudflareTenantRootCreationJournalRecordV1,
        authority_id: TenantRootControlPlaneAuthorityIdV1,
    ) -> RouterAbProtocolResult<ValidatedTenantRootCreationJournalV1> {
        validate_creation_record(record, authority_id, &verifying_keys())
    }

    fn role_signing_key(role: TwoPartyDeriverRole) -> SigningKey {
        SigningKey::from_bytes(match role {
            TwoPartyDeriverRole::DeriverA => &DERIVER_A_SIGNING_KEY_BYTES,
            TwoPartyDeriverRole::DeriverB => &DERIVER_B_SIGNING_KEY_BYTES,
        })
    }

    fn role_keys_from_verifiers(
        deriver_a_key_id: &str,
        deriver_a_verifying_key: [u8; 32],
        deriver_b_key_id: &str,
        deriver_b_verifying_key: [u8; 32],
    ) -> TenantRootCreationRoleVerifyingKeysV1 {
        let key_json = serde_json::json!({
            "active_deriver_a_signing_key_id": deriver_a_key_id,
            "active_deriver_b_signing_key_id": deriver_b_key_id,
            "keys": [
                {
                    "role": "deriver_a",
                    "signing_key_id": deriver_a_key_id,
                    "verifying_key_hex": lower_hex(&deriver_a_verifying_key),
                },
                {
                    "role": "deriver_b",
                    "signing_key_id": deriver_b_key_id,
                    "verifying_key_hex": lower_hex(&deriver_b_verifying_key),
                },
            ],
        })
        .to_string();
        decode_role_verifying_keys(&key_json).expect("valid role key set")
    }

    fn role_keys() -> TenantRootCreationRoleVerifyingKeysV1 {
        role_keys_from_verifiers(
            "deriver-a-signing-key-7",
            role_signing_key(TwoPartyDeriverRole::DeriverA)
                .verifying_key()
                .to_bytes(),
            "deriver-b-signing-key-9",
            role_signing_key(TwoPartyDeriverRole::DeriverB)
                .verifying_key()
                .to_bytes(),
        )
    }

    fn validated_active_refresh_state() -> ValidatedTenantRootRefreshActiveStateV1 {
        let (record, issuer_keys) = active_refresh_state_fixture();
        validate_refresh_active_state_record(record, authority(0x71), &issuer_keys)
            .expect("active refresh state")
    }

    fn managed_restore_active_state_fixture() -> (
        ValidatedTenantRootRefreshActiveStateV1,
        ValidatedTenantRootCreationJournalV1,
        BTreeMap<String, [u8; 32]>,
    ) {
        let journal = validate(
            record(0x19, 0x29, authority(0x71), 1_000_000, 1_030_000),
            authority(0x71),
        )
        .expect("managed-restore Started journal");
        let (_, creation_commitments) = publish_creation_commitment_pair(&journal, 1_000_100);
        let command_a = role_creation_command(&journal, TwoPartyDeriverRole::DeriverA);
        let command_b = role_creation_command(&journal, TwoPartyDeriverRole::DeriverB);
        let deriver_b_checkpoint = match evaluate_installation_checkpoint(
            None,
            installation_wire(&journal, TwoPartyDeriverRole::DeriverB, 19, 12, 0x92),
            &command_b,
            &journal,
            &role_keys(),
            &creation_commitments,
            1_000_100,
        )
        .expect("Deriver B installation")
        {
            TenantRootCreationInstallationEvaluationV1::Commit { checkpoint, .. } => checkpoint,
            other => panic!("unexpected Deriver B installation outcome: {other:?}"),
        };
        let complete_installation = match evaluate_installation_checkpoint(
            Some(deriver_b_checkpoint),
            installation_wire(&journal, TwoPartyDeriverRole::DeriverA, 12, 19, 0x91),
            &command_a,
            &journal,
            &role_keys(),
            &creation_commitments,
            1_000_100,
        )
        .expect("Deriver A installation")
        {
            TenantRootCreationInstallationEvaluationV1::Commit { checkpoint, .. } => checkpoint,
            other => panic!("unexpected complete installation outcome: {other:?}"),
        };
        validate_installation_checkpoint(
            complete_installation,
            &journal,
            &role_keys(),
            &creation_commitments,
        )
        .expect("validated complete installation");

        let deriver_a_installation =
            installation_wire(&journal, TwoPartyDeriverRole::DeriverA, 12, 19, 0x91);
        let deriver_b_installation =
            installation_wire(&journal, TwoPartyDeriverRole::DeriverB, 19, 12, 0x92);
        let commitments = creation_commitments_from_installation(
            &deriver_a_installation,
            &deriver_b_installation,
        );
        let deriver_a_backup =
            refresh_managed_backup(&deriver_a_installation, TwoPartyDeriverRole::DeriverA, 12);
        let deriver_b_backup =
            refresh_managed_backup(&deriver_b_installation, TwoPartyDeriverRole::DeriverB, 19);
        let ecdsa_canary = creation_provider_canary(
            &journal.ceremony_context,
            &commitments,
            TenantRootCanaryCurveFamilyV1::Ecdsa,
        );
        let ed25519_canary = creation_provider_canary(
            &journal.ceremony_context,
            &commitments,
            TenantRootCanaryCurveFamilyV1::Ed25519,
        );
        let expected_revision = 2;
        let result_revision = 3;
        let bundle = VerifiedTenantRootInitialCreationActivationEvidenceBundleV1::from_verified_managed_backups(
            deriver_a_installation,
            deriver_b_installation,
            deriver_a_backup,
            deriver_b_backup,
            ecdsa_canary,
            ed25519_canary,
            expected_revision,
            result_revision,
        )
        .expect("initial activation evidence");
        let signed = TenantRootSignedActivationReceiptV1::sign_initial_creation(
            &bundle,
            1_000_120,
            authority(0x71),
            ISSUER_KEY_ID,
            &[0x41; 32],
        )
        .expect("initial activation receipt");
        let receipt_bytes = signed
            .canonical_bytes()
            .expect("initial activation receipt bytes");
        let receipt = TenantRootSignedActivationReceiptV1::decode_canonical_bytes(&receipt_bytes)
            .expect("decoded initial activation receipt")
            .verify_issuer_signature(
                &SigningKey::from_bytes(&[0x41; 32])
                    .verifying_key()
                    .to_bytes(),
            )
            .expect("verified initial activation receipt");
        let record = refresh_active_state_record_from_verified_receipt(receipt, result_revision)
            .expect("managed-restore active state");
        let issuer_keys = BTreeMap::from([(
            ISSUER_KEY_ID.to_owned(),
            SigningKey::from_bytes(&[0x41; 32])
                .verifying_key()
                .to_bytes(),
        )]);
        let active = validate_refresh_active_state_record(record, authority(0x71), &issuer_keys)
            .expect("validated managed-restore active state");
        (active, journal, issuer_keys)
    }

    fn managed_restore_request(
        incident_seed: u8,
    ) -> CloudflareTenantRootManagedRestoreAuthorizationRequestV1 {
        CloudflareTenantRootManagedRestoreAuthorizationRequestV1 {
            incident_id: format!("incident-{incident_seed}"),
            outage_observation_digest_b64u: encode_base64url_bytes_v1(&[incident_seed; 32]),
            issued_at_ms: 1_000_200,
            expires_at_ms: 1_000_300,
            nonce_b64u: encode_base64url_bytes_v1(&[incident_seed.wrapping_add(1); 32]),
            unavailable_role: TenantRootManagedRestoreRoleV1::DeriverA,
        }
    }

    fn refresh_context(
        active: &ValidatedTenantRootRefreshActiveStateV1,
    ) -> TenantRootCeremonyContextV1 {
        TenantRootCeremonyContextV1::new(
            active.identity_digest,
            active.custody_lineage,
            TenantRootCeremonyEpochsV1::refresh(
                active.active_epoch,
                active.active_epoch.next().expect("next epoch"),
            )
            .expect("refresh epochs"),
            TenantRootCeremonySessionIdV1::from_bytes([0x52; 16]).expect("session"),
            TenantRootCeremonyNonceV1::from_bytes([0x53; 32]).expect("nonce"),
            1_000_000,
            1_030_000,
            "deriver-a-signing-key-7",
            "deriver-b-signing-key-9",
        )
        .expect("refresh context")
    }

    fn refresh_command(
        active: &ValidatedTenantRootRefreshActiveStateV1,
        context: &TenantRootCeremonyContextV1,
        role: TwoPartyDeriverRole,
    ) -> VerifiedTenantRootRoleRefreshCommandV1 {
        let issuer_signing_key = SigningKey::from_bytes(&[0x41; 32]);
        let issuer_signing_key_bytes = issuer_signing_key.to_bytes();
        let issuer_verifying_key_bytes = issuer_signing_key.verifying_key().to_bytes();
        let issuer_key_id = active.activation_receipt.issuer_key_id().to_owned();
        let command = TenantRootRoleRefreshCommandV1::sign(
            &active.active_pair,
            context,
            role,
            active.record.lifecycle_revision,
            authority(0x71),
            1_000_000,
            1_030_000,
            issuer_key_id.clone(),
            &issuer_signing_key_bytes,
        )
        .expect("refresh command");
        let bytes = command.canonical_bytes().expect("refresh command bytes");
        let command = TenantRootRoleRefreshCommandV1::decode_canonical_bytes(&bytes)
            .expect("decoded refresh command");
        command
            .verify(
                &active.active_pair,
                context,
                role,
                active.record.lifecycle_revision,
                authority(0x71),
                &issuer_key_id,
                &issuer_verifying_key_bytes,
            )
            .expect("verified refresh command")
    }

    fn refresh_managed_backup(
        evidence: &VerifiedTenantRootSignedShareInstallationEvidenceWireV1,
        role: TwoPartyDeriverRole,
        share_scalar: u64,
    ) -> router_ab_core::VerifiedTenantRootManagedBackupV1 {
        let context = evidence.evidence().transcript().context();
        let share = SigningRootShare::from_canonical_bytes(
            role.share_id(),
            Scalar::from(share_scalar).to_bytes(),
        )
        .expect("refresh backup share");
        let binding = TenantRootManagedBackupBindingV1::from_verified_installation_evidence(
            evidence,
            format!("backup-provider-{}", role.as_str()),
            format!("kms/tenant-root/{}/epoch-2/v1", role.as_str()),
            context.signing_key_id(role),
            1_000_010,
        )
        .expect("refresh backup binding");
        let share_wire = MpcPrfSigningRootShareWireV1::new(
            SigningRootShareWire::from_share(&share).to_bytes().to_vec(),
        )
        .expect("refresh backup share wire");
        let request = TenantRootManagedBackupSealRequestV1::new(binding.clone(), share_wire)
            .expect("refresh backup seal request");
        let ciphertext = match role {
            TwoPartyDeriverRole::DeriverA => vec![0xa5; 96],
            TwoPartyDeriverRole::DeriverB => vec![0xb5; 96],
        };
        let signing_key = role_signing_key(role);
        let signed =
            TenantRootSignedManagedBackupV1::sign(request, ciphertext, &signing_key.to_bytes())
                .expect("signed refresh backup");
        signed
            .verify(&binding, &signing_key.verifying_key().to_bytes())
            .expect("verified refresh backup")
    }

    fn refresh_provider_canary(
        context: &TenantRootCeremonyContextV1,
        commitments: &TenantRootEpochCommitmentsV1,
        family: TenantRootCanaryCurveFamilyV1,
    ) -> router_ab_core::VerifiedTenantRootProviderCanaryReceiptV1 {
        let target_epoch = match context.epochs() {
            TenantRootCeremonyEpochsV1::Refresh { next, .. } => next,
            TenantRootCeremonyEpochsV1::Create { .. } => {
                panic!("refresh canary requires refresh epochs")
            }
        };
        let binding = TenantRootProviderCanaryReceiptBindingV1::new(
            context.identity_digest(),
            context.custody_lineage(),
            TenantRootActivationReceiptTransitionV1::RefreshSwap,
            target_epoch,
            commitments.clone(),
            family,
            format!("kms/tenant-root/{}/canary-v1", family.as_str()),
            1_000_010,
            authority(0x72),
            "control-plane-canary-v1",
            1_000_000,
            1_030_000,
        )
        .expect("refresh canary binding");
        let signing_key = SigningKey::from_bytes(&[0x72; 32]);
        let signed =
            TenantRootSignedProviderCanaryReceiptV1::sign(binding.clone(), &signing_key.to_bytes())
                .expect("signed refresh canary");
        signed
            .verify(&binding, &signing_key.verifying_key().to_bytes())
            .expect("verified refresh canary")
    }

    fn refresh_activation_receipt(
        active: &ValidatedTenantRootRefreshActiveStateV1,
        context: &TenantRootCeremonyContextV1,
    ) -> router_ab_core::VerifiedTenantRootSignedActivationReceiptV1 {
        let share_a = SigningRootShare::from_canonical_bytes(
            TwoPartyDeriverRole::DeriverA.share_id(),
            Scalar::from(30u64).to_bytes(),
        )
        .expect("refresh Deriver A share");
        let share_b = SigningRootShare::from_canonical_bytes(
            TwoPartyDeriverRole::DeriverB.share_id(),
            Scalar::from(55u64).to_bytes(),
        )
        .expect("refresh Deriver B share");
        let installation_a =
            refresh_installation_wire(context, TwoPartyDeriverRole::DeriverA, 30, 55, 0x75);
        let installation_b =
            refresh_installation_wire(context, TwoPartyDeriverRole::DeriverB, 55, 30, 0x76);
        let next_commitments = TenantRootEpochCommitmentsV1::new(
            MpcPrfShareCommitmentWireV1::new(
                SigningRootShareCommitment::from_share(&share_a)
                    .to_bytes()
                    .to_vec(),
            )
            .expect("refresh Deriver A commitment"),
            MpcPrfShareCommitmentWireV1::new(
                SigningRootShareCommitment::from_share(&share_b)
                    .to_bytes()
                    .to_vec(),
            )
            .expect("refresh Deriver B commitment"),
        )
        .expect("refresh next commitments");
        let backup_a = refresh_managed_backup(&installation_a, TwoPartyDeriverRole::DeriverA, 30);
        let backup_b = refresh_managed_backup(&installation_b, TwoPartyDeriverRole::DeriverB, 55);
        let canary_ecdsa = refresh_provider_canary(
            context,
            &next_commitments,
            TenantRootCanaryCurveFamilyV1::Ecdsa,
        );
        let canary_ed25519 = refresh_provider_canary(
            context,
            &next_commitments,
            TenantRootCanaryCurveFamilyV1::Ed25519,
        );
        let result_revision = active
            .record
            .lifecycle_revision
            .checked_add(1)
            .expect("refresh result revision");
        let bundle =
            VerifiedTenantRootRefreshSwapActivationEvidenceBundleV1::from_verified_managed_backups(
                &active.commitments,
                installation_a,
                installation_b,
                backup_a,
                backup_b,
                canary_ecdsa,
                canary_ed25519,
                active.record.lifecycle_revision,
                result_revision,
            )
            .expect("refresh activation bundle");
        let signed = TenantRootSignedActivationReceiptV1::sign_refresh_swap(
            &bundle,
            1_000_020,
            authority(0x71),
            active.activation_receipt.issuer_key_id(),
            &[0x41; 32],
        )
        .expect("signed refresh activation receipt");
        let bytes = signed
            .canonical_bytes()
            .expect("refresh activation receipt bytes");
        TenantRootSignedActivationReceiptV1::decode_canonical_bytes(&bytes)
            .expect("decoded refresh activation receipt")
            .verify_issuer_signature(
                &SigningKey::from_bytes(&[0x41; 32])
                    .verifying_key()
                    .to_bytes(),
            )
            .expect("verified refresh activation receipt")
    }

    fn refresh_recipient(
        role: TwoPartyDeriverRole,
    ) -> (
        &'static str,
        router_ab_core::TenantRootRefreshHpkePublicKeyV1,
    ) {
        match role {
            TwoPartyDeriverRole::DeriverA => (
                "deriver-b-refresh-hpke-key-1",
                TenantRootRefreshHpkeKeypairV1::derive_from_ikm([0xb2; 32])
                    .expect("Deriver B refresh HPKE key")
                    .public_key(),
            ),
            TwoPartyDeriverRole::DeriverB => (
                "deriver-a-refresh-hpke-key-1",
                TenantRootRefreshHpkeKeypairV1::derive_from_ikm([0xa2; 32])
                    .expect("Deriver A refresh HPKE key")
                    .public_key(),
            ),
        }
    }

    fn refresh_commitment(
        context: &TenantRootCeremonyContextV1,
        role: TwoPartyDeriverRole,
        scalar: u64,
    ) -> VerifiedTenantRootRefreshCommitmentV1 {
        let coefficient = RootShareRefreshCoefficient::from_canonical_bytes(
            role,
            Scalar::from(scalar).to_bytes(),
        )
        .expect("refresh coefficient");
        let (recipient_key_id, recipient_public_key) = refresh_recipient(role);
        let transcript = TenantRootRefreshCommitmentTranscriptV1::new(
            context.clone(),
            coefficient.commitment(),
            recipient_key_id,
            recipient_public_key,
        )
        .expect("refresh commitment transcript");
        let signing_key = role_signing_key(role);
        let signed = TenantRootSignedRefreshCommitmentV1::sign(transcript, &signing_key.to_bytes())
            .expect("signed refresh commitment");
        let bytes = signed.canonical_bytes().expect("refresh commitment bytes");
        let signed = TenantRootSignedRefreshCommitmentV1::decode_canonical_bytes(&bytes)
            .expect("decoded refresh commitment");
        let keys = role_keys();
        signed
            .verify_strict(
                context,
                role,
                context.signing_key_id(role),
                keys.for_role_and_key_id(role, context.signing_key_id(role))
                    .expect("refresh commitment key"),
            )
            .expect("verified refresh commitment")
    }

    fn refresh_commitment_pair(
        context: &TenantRootCeremonyContextV1,
    ) -> VerifiedTenantRootRefreshCommitmentPairV1 {
        VerifiedTenantRootRefreshCommitmentPairV1::new(
            refresh_commitment(context, TwoPartyDeriverRole::DeriverA, 7),
            refresh_commitment(context, TwoPartyDeriverRole::DeriverB, 11),
        )
        .expect("refresh commitment pair")
    }

    fn refresh_contribution(
        context: &TenantRootCeremonyContextV1,
        commitments: &VerifiedTenantRootRefreshCommitmentPairV1,
        role: TwoPartyDeriverRole,
        scalar: u64,
        rng_seed: u64,
    ) -> VerifiedTenantRootSignedRefreshContributionV1 {
        let coefficient = RootShareRefreshCoefficient::from_canonical_bytes(
            role,
            Scalar::from(scalar).to_bytes(),
        )
        .expect("refresh coefficient");
        let aad = match role {
            TwoPartyDeriverRole::DeriverA => {
                TenantRootRefreshContributionAadV1::deriver_a_to_b(commitments)
            }
            TwoPartyDeriverRole::DeriverB => {
                TenantRootRefreshContributionAadV1::deriver_b_to_a(commitments)
            }
        }
        .expect("refresh contribution AAD");
        let envelope = seal_tenant_root_refresh_contribution_v1(
            &aad,
            &coefficient.contribution_for(role.peer()),
            &mut TestRng(rng_seed),
        )
        .expect("sealed refresh contribution");
        let signed = TenantRootSignedRefreshContributionV1::sign(
            &aad,
            envelope,
            &role_signing_key(role).to_bytes(),
        )
        .expect("signed refresh contribution");
        let bytes = signed
            .canonical_bytes()
            .expect("refresh contribution bytes");
        verify_refresh_contribution_wire(&bytes, context, commitments, &role_keys())
            .expect("verified refresh contribution")
    }

    fn refresh_installation_wire(
        context: &TenantRootCeremonyContextV1,
        role: TwoPartyDeriverRole,
        share_scalar: u64,
        peer_scalar: u64,
        proof_seed: u8,
    ) -> VerifiedTenantRootSignedShareInstallationEvidenceWireV1 {
        let share = SigningRootShare::from_canonical_bytes(
            role.share_id(),
            Scalar::from(share_scalar).to_bytes(),
        )
        .expect("share");
        let peer = SigningRootShare::from_canonical_bytes(
            role.peer().share_id(),
            Scalar::from(peer_scalar).to_bytes(),
        )
        .expect("peer share");
        let transcript = TenantRootShareInstallationTranscriptV1::new(
            context.clone(),
            role,
            SigningRootShareCommitment::from_share(&share),
            SigningRootShareCommitment::from_share(&peer),
        )
        .expect("transcript");
        let proof = prove_root_share_knowledge(
            &share,
            &transcript.canonical_bytes().expect("transcript bytes"),
            &mut ChaCha20Rng::from_seed([proof_seed; 32]),
        )
        .expect("proof");
        let signing_key = role_signing_key(role);
        let signed = TenantRootSignedShareInstallationEvidenceV1::sign(
            TenantRootShareInstallationEvidenceV1::new(transcript, proof).expect("evidence"),
            &signing_key.to_bytes(),
        )
        .expect("signed evidence");
        let bytes = signed.canonical_bytes().expect("signed evidence bytes");
        let keys = role_keys();
        TenantRootSignedShareInstallationEvidenceV1::decode_and_verify_canonical_bytes(
            &bytes,
            keys.for_role_and_key_id(role, context.signing_key_id(role))
                .expect("installation evidence key"),
        )
        .expect("verified installation evidence")
    }

    fn refresh_installation_terminal_receipt(
        command: &VerifiedTenantRootRoleRefreshCommandV1,
        evidence: &VerifiedTenantRootSignedShareInstallationEvidenceWireV1,
    ) -> VerifiedTenantRootRefreshInstallationReceiptV1 {
        let role = command.role();
        let context = evidence.evidence().transcript().context();
        let receipt = match TenantRootCommandTerminalReceiptV1::sign_success(
            TenantRootCommandReplayKeyV1::new(
                command.identity_digest(),
                command.custody_lineage(),
                command.session_id(),
                command.nonce(),
                role,
            ),
            TenantRootProtocolDigestV1::from_bytes([0x91; 32]).expect("receipt digest"),
            evidence.canonical_bytes().to_vec(),
            command.issued_at_ms(),
            context.signing_key_id(role),
            &role_signing_key(role).to_bytes(),
        )
        .expect("terminal receipt")
        {
            TenantRootCommandTerminalReceiptV1::Success(receipt) => receipt,
            TenantRootCommandTerminalReceiptV1::Failure(_) => {
                unreachable!("sign_success returns a success receipt")
            }
        };
        VerifiedTenantRootRefreshInstallationReceiptV1::new(
            receipt,
            evidence.canonical_bytes(),
            command,
            context,
            &role_keys(),
        )
        .expect("verified terminal receipt")
    }

    #[test]
    fn completed_refresh_commitment_replay_after_expiry_reaches_core_evaluator() {
        let active = validated_active_refresh_state();
        let context = refresh_context(&active);
        let command_a = refresh_command(&active, &context, TwoPartyDeriverRole::DeriverA);
        let command_b = refresh_command(&active, &context, TwoPartyDeriverRole::DeriverB);
        let commitment_a = refresh_commitment(&context, TwoPartyDeriverRole::DeriverA, 7);
        let commitment_b = refresh_commitment(&context, TwoPartyDeriverRole::DeriverB, 11);
        let active_binding =
            TenantRootRefreshCommitmentCheckpointActiveBindingV1::from_verified_activation_receipt(
                active.activation_receipt,
                &active.active_pair,
                active.record.lifecycle_revision,
            )
            .expect("active checkpoint binding");
        let deriver_a_verifying_key = role_signing_key(TwoPartyDeriverRole::DeriverA)
            .verifying_key()
            .to_bytes();
        let deriver_b_verifying_key = role_signing_key(TwoPartyDeriverRole::DeriverB)
            .verifying_key()
            .to_bytes();
        let first = evaluate_tenant_root_refresh_commitment_checkpoint_v1(
            None,
            commitment_a,
            &command_a,
            &active_binding,
            &context,
            authority(0x71),
            &deriver_a_verifying_key,
            &deriver_b_verifying_key,
            1_000_100,
        )
        .expect("first refresh commitment");
        let first_checkpoint = match first {
            TenantRootRefreshCommitmentCheckpointEvaluationV1::Commit { checkpoint, .. } => {
                checkpoint
            }
            other => panic!("unexpected first refresh commitment outcome: {other:?}"),
        };
        let second = evaluate_tenant_root_refresh_commitment_checkpoint_v1(
            Some(first_checkpoint),
            commitment_b,
            &command_b,
            &active_binding,
            &context,
            authority(0x71),
            &deriver_a_verifying_key,
            &deriver_b_verifying_key,
            1_000_100,
        )
        .expect("completed refresh commitment");
        let completed_checkpoint = match second {
            TenantRootRefreshCommitmentCheckpointEvaluationV1::Commit { checkpoint, .. } => {
                checkpoint
            }
            other => panic!("unexpected completed refresh commitment outcome: {other:?}"),
        };

        require_fresh_refresh_commitment_command(
            Some(&completed_checkpoint),
            TwoPartyDeriverRole::DeriverB,
            &command_b,
            &context,
            1_030_001,
        )
        .expect("completed exact replay bypasses freshness");
        let replay = evaluate_tenant_root_refresh_commitment_checkpoint_v1(
            Some(completed_checkpoint.clone()),
            refresh_commitment(&context, TwoPartyDeriverRole::DeriverB, 11),
            &command_b,
            &active_binding,
            &context,
            authority(0x71),
            &deriver_a_verifying_key,
            &deriver_b_verifying_key,
            1_030_001,
        )
        .expect("exact completed replay");
        assert!(matches!(
            replay,
            TenantRootRefreshCommitmentCheckpointEvaluationV1::Replay(
                TenantRootRefreshCommitmentCheckpointOutcomeV1::BothRolesCommitted { .. }
            )
        ));

        require_fresh_refresh_commitment_command(
            Some(&completed_checkpoint),
            TwoPartyDeriverRole::DeriverB,
            &command_b,
            &context,
            1_030_001,
        )
        .expect("changed completed candidate reaches replay evaluator");
        let changed_error = evaluate_tenant_root_refresh_commitment_checkpoint_v1(
            Some(completed_checkpoint),
            refresh_commitment(&context, TwoPartyDeriverRole::DeriverB, 12),
            &command_b,
            &active_binding,
            &context,
            authority(0x71),
            &deriver_a_verifying_key,
            &deriver_b_verifying_key,
            1_030_001,
        )
        .err()
        .expect("changed completed candidate conflicts");
        assert_eq!(
            changed_error.code(),
            RouterAbDerivationErrorCode::ReplayMismatch
        );
        assert_eq!(
            refresh_commitment_evaluation_error(changed_error, true).code(),
            RouterAbProtocolErrorCode::ConflictingPair
        );
    }

    #[test]
    fn refresh_contribution_rendezvous_replays_completed_pair_after_expiry() {
        let mut active = validated_active_refresh_state();
        let context = refresh_context(&active);
        let commitments = refresh_commitment_pair(&context);
        let command_a = refresh_command(&active, &context, TwoPartyDeriverRole::DeriverA);
        let command_b = refresh_command(&active, &context, TwoPartyDeriverRole::DeriverB);
        active.record.fence = CloudflareTenantRootRefreshFenceV1::Reserved {
            attempt: refresh_attempt_from_commands(&context, &command_a, &command_b)
                .expect("refresh attempt"),
        };

        let contribution_b = refresh_contribution(
            &context,
            &commitments,
            TwoPartyDeriverRole::DeriverB,
            11,
            0x22,
        );
        let expected_b = encode_base64url_bytes_v1(contribution_b.canonical_bytes());
        let first = evaluate_refresh_contribution_rendezvous(
            None,
            contribution_b,
            &command_b,
            &active,
            &context,
            &commitments,
            &role_keys(),
            authority(0x71),
            1_000_100,
        )
        .expect("first contribution");
        let first_record = match first {
            TenantRootRefreshContributionRendezvousEvaluationV1::Commit {
                record,
                outcome:
                    CloudflareTenantRootRefreshContributionResponseOutcomeV1::WaitingForPeer {
                        role: CloudflareTenantRootCreationInstallationRoleV1::DeriverB,
                    },
            } => record,
            _ => panic!("unexpected first contribution outcome"),
        };

        let contribution_a = refresh_contribution(
            &context,
            &commitments,
            TwoPartyDeriverRole::DeriverA,
            7,
            0x33,
        );
        let expected_a = encode_base64url_bytes_v1(contribution_a.canonical_bytes());
        let completed = evaluate_refresh_contribution_rendezvous(
            Some(first_record),
            contribution_a,
            &command_a,
            &active,
            &context,
            &commitments,
            &role_keys(),
            authority(0x71),
            1_000_100,
        )
        .expect("completed contribution pair");
        let completed_record = match completed {
            TenantRootRefreshContributionRendezvousEvaluationV1::Commit {
                record,
                outcome:
                    CloudflareTenantRootRefreshContributionResponseOutcomeV1::BothRolesContributed {
                        deriver_a_signed_contribution_b64u,
                        deriver_b_signed_contribution_b64u,
                    },
            } => {
                assert_eq!(deriver_a_signed_contribution_b64u, expected_a);
                assert_eq!(deriver_b_signed_contribution_b64u, expected_b);
                record
            }
            _ => panic!("unexpected completed contribution outcome"),
        };

        let replay = evaluate_refresh_contribution_rendezvous(
            Some(completed_record.clone()),
            refresh_contribution(
                &context,
                &commitments,
                TwoPartyDeriverRole::DeriverA,
                7,
                0x33,
            ),
            &command_a,
            &active,
            &context,
            &commitments,
            &role_keys(),
            authority(0x71),
            1_030_001,
        )
        .expect("exact completed replay");
        assert!(matches!(
            replay,
            TenantRootRefreshContributionRendezvousEvaluationV1::Replay(
                CloudflareTenantRootRefreshContributionResponseOutcomeV1::BothRolesContributed { .. }
            )
        ));

        let conflict = evaluate_refresh_contribution_rendezvous(
            Some(completed_record),
            refresh_contribution(
                &context,
                &commitments,
                TwoPartyDeriverRole::DeriverA,
                7,
                0x34,
            ),
            &command_a,
            &active,
            &context,
            &commitments,
            &role_keys(),
            authority(0x71),
            1_030_001,
        )
        .err()
        .expect("changed completed contribution conflicts");
        assert_eq!(conflict.code(), RouterAbProtocolErrorCode::ConflictingPair);
    }

    #[test]
    fn refresh_installation_checkpoint_rejects_role_commitment_substitutions() {
        let mut active = validated_active_refresh_state();
        let context = refresh_context(&active);
        let commitments = refresh_commitment_pair(&context);
        let command_a = refresh_command(&active, &context, TwoPartyDeriverRole::DeriverA);
        let command_b = refresh_command(&active, &context, TwoPartyDeriverRole::DeriverB);
        active.record.fence = CloudflareTenantRootRefreshFenceV1::Reserved {
            attempt: refresh_attempt_from_commands(&context, &command_a, &command_b)
                .expect("refresh attempt"),
        };

        // Active shares are 12 and 19; coefficients 7 and 11 produce next shares 30 and 55.
        let exact_a =
            refresh_installation_wire(&context, TwoPartyDeriverRole::DeriverA, 30, 55, 0x61);
        let exact_b =
            refresh_installation_wire(&context, TwoPartyDeriverRole::DeriverB, 55, 30, 0x62);
        let exact_a_receipt = refresh_installation_terminal_receipt(&command_a, &exact_a);
        let exact_b_receipt = refresh_installation_terminal_receipt(&command_b, &exact_b);
        let first = evaluate_refresh_installation_checkpoint(
            None,
            exact_a.canonical_bytes(),
            &command_a,
            &active,
            &context,
            &role_keys(),
            &commitments,
            authority(0x71),
            &exact_a_receipt,
            1_000_100,
        )
        .expect("first exact role installation");
        let first_checkpoint = match first {
            TenantRootRefreshInstallationCheckpointEvaluationV1::Commit { checkpoint, .. } => {
                checkpoint
            }
            _ => panic!("unexpected first installation outcome"),
        };
        match evaluate_refresh_installation_checkpoint(
            Some(first_checkpoint),
            exact_b.canonical_bytes(),
            &command_b,
            &active,
            &context,
            &role_keys(),
            &commitments,
            authority(0x71),
            &exact_b_receipt,
            1_000_100,
        )
        .expect("complete exact role installation")
        {
            TenantRootRefreshInstallationCheckpointEvaluationV1::Commit {
                outcome:
                    CloudflareTenantRootRefreshInstallationResponseOutcomeV1::BothRolesReady { .. },
                ..
            } => {}
            _ => panic!("unexpected complete installation outcome"),
        }

        for (share_scalar, peer_scalar, proof_seed) in
            [(7, 11, 0x63), (31, 55, 0x64), (30, 56, 0x65)]
        {
            let substituted_a = refresh_installation_wire(
                &context,
                TwoPartyDeriverRole::DeriverA,
                share_scalar,
                peer_scalar,
                proof_seed,
            );
            let substituted_a_receipt =
                refresh_installation_terminal_receipt(&command_a, &substituted_a);
            let first = evaluate_refresh_installation_checkpoint(
                None,
                substituted_a.canonical_bytes(),
                &command_a,
                &active,
                &context,
                &role_keys(),
                &commitments,
                authority(0x71),
                &substituted_a_receipt,
                1_000_100,
            )
            .expect("substituted first role installation is retained pending its peer");
            let first_checkpoint = match first {
                TenantRootRefreshInstallationCheckpointEvaluationV1::Commit {
                    checkpoint, ..
                } => checkpoint,
                _ => panic!("unexpected substituted first outcome"),
            };
            let substituted_b = refresh_installation_wire(
                &context,
                TwoPartyDeriverRole::DeriverB,
                peer_scalar,
                share_scalar,
                proof_seed.wrapping_add(1),
            );
            let substituted_b_receipt =
                refresh_installation_terminal_receipt(&command_b, &substituted_b);
            let error = evaluate_refresh_installation_checkpoint(
                Some(first_checkpoint),
                substituted_b.canonical_bytes(),
                &command_b,
                &active,
                &context,
                &role_keys(),
                &commitments,
                authority(0x71),
                &substituted_b_receipt,
                1_000_100,
            )
            .err()
            .expect("substituted role commitment must conflict at pair completion");
            assert_eq!(error.code(), RouterAbProtocolErrorCode::ConflictingPair);
        }
    }

    #[test]
    fn refresh_installation_checkpoint_recovers_after_terminal_d1_commit() {
        const EXPIRED_NOW_MS: u64 = 1_030_001;
        let mut active = validated_active_refresh_state();
        let context = refresh_context(&active);
        let commitments = refresh_commitment_pair(&context);
        let command = refresh_command(&active, &context, TwoPartyDeriverRole::DeriverA);
        let command_b = refresh_command(&active, &context, TwoPartyDeriverRole::DeriverB);
        active.record.fence = CloudflareTenantRootRefreshFenceV1::Reserved {
            attempt: refresh_attempt_from_commands(&context, &command, &command_b)
                .expect("refresh attempt"),
        };
        let persisted_record = serde_json::from_slice(
            &serde_json::to_vec(&active.record).expect("persisted reserved refresh state"),
        )
        .expect("reload reserved refresh state");
        let mut restarted_active = validated_active_refresh_state();
        restarted_active.record = persisted_record;
        let evidence =
            refresh_installation_wire(&context, TwoPartyDeriverRole::DeriverA, 30, 55, 0x71);
        let terminal_receipt = refresh_installation_terminal_receipt(&command, &evidence);

        let evaluation = evaluate_refresh_installation_checkpoint(
            None,
            evidence.canonical_bytes(),
            &command,
            &restarted_active,
            &context,
            &role_keys(),
            &commitments,
            authority(0x71),
            &terminal_receipt,
            EXPIRED_NOW_MS,
        )
        .expect("terminal D1 receipt permits checkpoint recovery");
        match evaluation {
            TenantRootRefreshInstallationCheckpointEvaluationV1::Commit {
                checkpoint,
                fence: CloudflareTenantRootRefreshFenceV1::Executed { .. },
                outcome:
                    CloudflareTenantRootRefreshInstallationResponseOutcomeV1::WaitingForPeer {
                        role: CloudflareTenantRootCreationInstallationRoleV1::DeriverA,
                    },
            } => {
                validate_refresh_installation_checkpoint(
                    checkpoint,
                    &refresh_checkpoint_scope(
                        &command,
                        &restarted_active,
                        &context,
                        authority(0x71),
                    )
                    .expect("refresh checkpoint scope"),
                    &context,
                    &role_keys(),
                    &commitments,
                    &restarted_active.commitments,
                )
                .expect("recovered installation checkpoint");
            }
            TenantRootRefreshInstallationCheckpointEvaluationV1::Commit { .. } => {
                panic!("terminal D1 recovery must execute the refresh fence")
            }
            TenantRootRefreshInstallationCheckpointEvaluationV1::Replay(_) => {
                panic!("missing checkpoint must commit after terminal D1 recovery")
            }
        }
    }

    #[test]
    fn refresh_installation_checkpoint_replays_persisted_terminal_receipt_after_restart() {
        const FRESH_NOW_MS: u64 = 1_000_100;
        const EXPIRED_NOW_MS: u64 = 1_030_001;
        let mut active = validated_active_refresh_state();
        let context = refresh_context(&active);
        let commitments = refresh_commitment_pair(&context);
        let command = refresh_command(&active, &context, TwoPartyDeriverRole::DeriverA);
        let command_b = refresh_command(&active, &context, TwoPartyDeriverRole::DeriverB);
        active.record.fence = CloudflareTenantRootRefreshFenceV1::Reserved {
            attempt: refresh_attempt_from_commands(&context, &command, &command_b)
                .expect("refresh attempt"),
        };
        let evidence =
            refresh_installation_wire(&context, TwoPartyDeriverRole::DeriverA, 30, 55, 0x72);
        let terminal_receipt = refresh_installation_terminal_receipt(&command, &evidence);
        let first = evaluate_refresh_installation_checkpoint(
            None,
            evidence.canonical_bytes(),
            &command,
            &active,
            &context,
            &role_keys(),
            &commitments,
            authority(0x71),
            &terminal_receipt,
            FRESH_NOW_MS,
        )
        .expect("first installation checkpoint");
        let (checkpoint, executed_fence) = match first {
            TenantRootRefreshInstallationCheckpointEvaluationV1::Commit {
                checkpoint,
                fence: executed_fence,
                ..
            } => (checkpoint, executed_fence),
            TenantRootRefreshInstallationCheckpointEvaluationV1::Replay(_) => {
                panic!("first installation must commit")
            }
        };

        active.record.fence = executed_fence;
        let persisted_record = serde_json::from_slice(
            &serde_json::to_vec(&active.record).expect("persisted refresh active state"),
        )
        .expect("decode persisted refresh active state");
        let mut restarted_active = validated_active_refresh_state();
        restarted_active.record = persisted_record;

        assert!(matches!(
            evaluate_refresh_installation_checkpoint(
                Some(checkpoint),
                evidence.canonical_bytes(),
                &command,
                &restarted_active,
                &context,
                &role_keys(),
                &commitments,
                authority(0x71),
                &terminal_receipt,
                EXPIRED_NOW_MS,
            )
            .expect("exact retry after expiry"),
            TenantRootRefreshInstallationCheckpointEvaluationV1::Replay(
                CloudflareTenantRootRefreshInstallationResponseOutcomeV1::WaitingForPeer {
                    role: CloudflareTenantRootCreationInstallationRoleV1::DeriverA,
                }
            )
        ));
    }

    #[test]
    fn refresh_installation_checkpoint_rejects_mismatched_terminal_receipt_context() {
        let mut active = validated_active_refresh_state();
        let context = refresh_context(&active);
        let commitments = refresh_commitment_pair(&context);
        let command = refresh_command(&active, &context, TwoPartyDeriverRole::DeriverA);
        let command_b = refresh_command(&active, &context, TwoPartyDeriverRole::DeriverB);
        active.record.fence = CloudflareTenantRootRefreshFenceV1::Reserved {
            attempt: refresh_attempt_from_commands(&context, &command, &command_b)
                .expect("refresh attempt"),
        };
        let evidence =
            refresh_installation_wire(&context, TwoPartyDeriverRole::DeriverA, 30, 55, 0x73);
        let foreign_context = TenantRootCeremonyContextV1::new(
            context.identity_digest(),
            context.custody_lineage(),
            context.epochs().clone(),
            TenantRootCeremonySessionIdV1::from_bytes([0x62; 16]).expect("foreign session"),
            context.nonce(),
            context.issued_at_ms(),
            context.expires_at_ms(),
            context.signing_key_id(TwoPartyDeriverRole::DeriverA),
            context.signing_key_id(TwoPartyDeriverRole::DeriverB),
        )
        .expect("foreign context");
        let foreign_command =
            refresh_command(&active, &foreign_context, TwoPartyDeriverRole::DeriverA);
        let foreign_evidence = refresh_installation_wire(
            &foreign_context,
            TwoPartyDeriverRole::DeriverA,
            30,
            55,
            0x74,
        );
        let foreign_receipt =
            refresh_installation_terminal_receipt(&foreign_command, &foreign_evidence);

        let error = evaluate_refresh_installation_checkpoint(
            None,
            evidence.canonical_bytes(),
            &command,
            &active,
            &context,
            &role_keys(),
            &commitments,
            authority(0x71),
            &foreign_receipt,
            1_030_001,
        )
        .err()
        .expect("foreign terminal receipt must fail closed");
        assert_eq!(
            error.code(),
            RouterAbProtocolErrorCode::ForbiddenLocalBinding
        );
    }

    fn creation_commitment_wire(
        journal: &ValidatedTenantRootCreationJournalV1,
        role: TwoPartyDeriverRole,
        share_scalar: u64,
    ) -> Vec<u8> {
        let key = role_signing_key(role).to_bytes();
        creation_commitment_wire_with_key(journal, role, share_scalar, &key)
    }

    fn creation_commitment_wire_with_key(
        journal: &ValidatedTenantRootCreationJournalV1,
        role: TwoPartyDeriverRole,
        share_scalar: u64,
        signing_key_bytes: &[u8; 32],
    ) -> Vec<u8> {
        let share = SigningRootShare::from_canonical_bytes(
            role.share_id(),
            Scalar::from(share_scalar).to_bytes(),
        )
        .expect("share");
        let transcript = TenantRootCreationCommitmentTranscriptV1::new(
            journal.ceremony_context.clone(),
            role,
            SigningRootShareCommitment::from_share(&share),
        )
        .expect("creation commitment transcript");
        TenantRootSignedCreationCommitmentV1::sign(transcript, signing_key_bytes)
            .expect("signed creation commitment")
            .canonical_bytes()
            .expect("creation commitment bytes")
    }

    fn role_creation_command(
        journal: &ValidatedTenantRootCreationJournalV1,
        role: TwoPartyDeriverRole,
    ) -> VerifiedTenantRootRoleCreationCommandV1 {
        let command = TenantRootRoleCreationCommandV1::sign(
            &journal.journal,
            &journal.ceremony_context,
            role,
            authority(0x44),
            1_000_000,
            1_030_000,
            ISSUER_KEY_ID,
            &SIGNING_KEY_BYTES,
        )
        .expect("role creation command");
        let bytes = command.canonical_bytes().expect("role command bytes");
        let command = TenantRootRoleCreationCommandV1::decode_canonical_bytes(&bytes)
            .expect("decoded role command");
        command
            .verify(
                &journal.journal,
                &journal.ceremony_context,
                role,
                authority(0x44),
                ISSUER_KEY_ID,
                &verifying_key(),
            )
            .expect("verified role command")
    }

    fn publish_creation_commitment_pair(
        journal: &ValidatedTenantRootCreationJournalV1,
        now_ms: u64,
    ) -> (
        CloudflareTenantRootCreationCommitmentRendezvousRecordV1,
        VerifiedTenantRootCreationCommitmentPairV1,
    ) {
        let deriver_a = creation_commitment_wire(journal, TwoPartyDeriverRole::DeriverA, 12);
        let deriver_a_command = role_creation_command(journal, TwoPartyDeriverRole::DeriverA);
        let first = evaluate_creation_commitment_rendezvous(
            None,
            &deriver_a,
            &deriver_a_command,
            journal,
            &role_keys(),
            now_ms,
        )
        .expect("first creation commitment");
        let first_record = match first {
            TenantRootCreationCommitmentRendezvousEvaluationV1::Commit { rendezvous, .. } => {
                rendezvous
            }
            other => panic!("unexpected first commitment outcome: {other:?}"),
        };
        let deriver_b = creation_commitment_wire(journal, TwoPartyDeriverRole::DeriverB, 19);
        let deriver_b_command = role_creation_command(journal, TwoPartyDeriverRole::DeriverB);
        let second = evaluate_creation_commitment_rendezvous(
            Some(first_record),
            &deriver_b,
            &deriver_b_command,
            journal,
            &role_keys(),
            now_ms,
        )
        .expect("second creation commitment");
        match second {
            TenantRootCreationCommitmentRendezvousEvaluationV1::Commit {
                rendezvous,
                outcome:
                    CloudflareTenantRootCreationCommitmentOutcomeV1::BothRolesCommitted { pair },
            } => (rendezvous, pair),
            other => panic!("unexpected completed commitment outcome: {other:?}"),
        }
    }

    fn installation_wire(
        journal: &ValidatedTenantRootCreationJournalV1,
        role: TwoPartyDeriverRole,
        share_scalar: u64,
        peer_scalar: u64,
        proof_seed: u8,
    ) -> VerifiedTenantRootSignedShareInstallationEvidenceWireV1 {
        let share = SigningRootShare::from_canonical_bytes(
            role.share_id(),
            Scalar::from(share_scalar).to_bytes(),
        )
        .expect("share");
        let peer = SigningRootShare::from_canonical_bytes(
            role.peer().share_id(),
            Scalar::from(peer_scalar).to_bytes(),
        )
        .expect("peer share");
        let transcript = TenantRootShareInstallationTranscriptV1::new(
            journal.ceremony_context.clone(),
            role,
            SigningRootShareCommitment::from_share(&share),
            SigningRootShareCommitment::from_share(&peer),
        )
        .expect("transcript");
        let proof = prove_root_share_knowledge(
            &share,
            &transcript.canonical_bytes().expect("transcript bytes"),
            &mut ChaCha20Rng::from_seed([proof_seed; 32]),
        )
        .expect("proof");
        let signed = TenantRootSignedShareInstallationEvidenceV1::sign(
            TenantRootShareInstallationEvidenceV1::new(transcript, proof).expect("evidence"),
            &role_signing_key(role).to_bytes(),
        )
        .expect("signed evidence");
        let bytes = signed.canonical_bytes().expect("signed bytes");
        TenantRootSignedShareInstallationEvidenceV1::decode_and_verify_canonical_bytes(
            &bytes,
            role_keys()
                .for_role_and_key_id(role, journal.ceremony_context.signing_key_id(role))
                .expect("role key"),
        )
        .expect("verified wire")
    }

    fn creation_commitments_from_installation(
        deriver_a: &VerifiedTenantRootSignedShareInstallationEvidenceWireV1,
        deriver_b: &VerifiedTenantRootSignedShareInstallationEvidenceWireV1,
    ) -> TenantRootEpochCommitmentsV1 {
        TenantRootEpochCommitmentsV1::new(
            MpcPrfShareCommitmentWireV1::new(
                deriver_a
                    .evidence()
                    .transcript()
                    .commitment()
                    .to_bytes()
                    .to_vec(),
            )
            .expect("creation Deriver A commitment"),
            MpcPrfShareCommitmentWireV1::new(
                deriver_b
                    .evidence()
                    .transcript()
                    .commitment()
                    .to_bytes()
                    .to_vec(),
            )
            .expect("creation Deriver B commitment"),
        )
        .expect("creation commitments")
    }

    fn creation_provider_canary(
        context: &TenantRootCeremonyContextV1,
        commitments: &TenantRootEpochCommitmentsV1,
        family: TenantRootCanaryCurveFamilyV1,
    ) -> router_ab_core::VerifiedTenantRootProviderCanaryReceiptV1 {
        let binding = TenantRootProviderCanaryReceiptBindingV1::new(
            context.identity_digest(),
            context.custody_lineage(),
            TenantRootActivationReceiptTransitionV1::InitialCreation,
            TenantRootShareEpoch::INITIAL,
            commitments.clone(),
            family,
            format!("kms/tenant-root/{}/canary-v1", family.as_str()),
            1_000_110,
            authority(0x72),
            "control-plane-canary-v1",
            context.issued_at_ms(),
            context.expires_at_ms(),
        )
        .expect("creation canary binding");
        let signing_key = SigningKey::from_bytes(&[0x72; 32]);
        let signed =
            TenantRootSignedProviderCanaryReceiptV1::sign(binding.clone(), &signing_key.to_bytes())
                .expect("signed creation canary");
        signed
            .verify(&binding, &signing_key.verifying_key().to_bytes())
            .expect("verified creation canary")
    }

    fn deriver_b_installation_checkpoint(
        journal: &ValidatedTenantRootCreationJournalV1,
        now_ms: u64,
    ) -> (
        CloudflareTenantRootCreationInstallationCheckpointV1,
        VerifiedTenantRootCreationCommitmentPairV1,
    ) {
        let (_, commitments) = publish_creation_commitment_pair(journal, now_ms);
        let command = role_creation_command(journal, TwoPartyDeriverRole::DeriverB);
        let evaluated = evaluate_installation_checkpoint(
            None,
            installation_wire(journal, TwoPartyDeriverRole::DeriverB, 19, 12, 0x62),
            &command,
            journal,
            &role_keys(),
            &commitments,
            now_ms,
        )
        .expect("Deriver B installation checkpoint");
        let TenantRootCreationInstallationEvaluationV1::Commit { checkpoint, .. } = evaluated
        else {
            panic!("fresh Deriver B installation must commit");
        };
        (checkpoint, commitments)
    }

    fn cleanup_checkpoint_fixture(
        journal: &ValidatedTenantRootCreationJournalV1,
        installation: &ValidatedTenantRootCreationInstallationCheckpointV1,
        cleanup_nonce_seed: u8,
        receipt_signer: TwoPartyDeriverRole,
        replacement_payload: Option<&[u8]>,
    ) -> CloudflareTenantRootCreationCleanupCheckpointV1 {
        let (target, role) =
            creation_cleanup_target(journal, installation).expect("cleanup target");
        let cleanup_nonce =
            TenantRootCeremonyNonceV1::from_bytes([cleanup_nonce_seed; 32]).expect("cleanup nonce");
        let command = TenantRootRoleCleanupCommandV1::sign(
            &target,
            authority(0x44),
            cleanup_nonce,
            1_000_001,
            1_030_000,
            ISSUER_KEY_ID,
            &SIGNING_KEY_BYTES,
        )
        .expect("cleanup command");
        let command_bytes = command.canonical_bytes().expect("cleanup command bytes");
        let replay_session = TenantRootCeremonySessionIdV1::from_bytes(
            cleanup_nonce.as_bytes()[..16]
                .try_into()
                .expect("sixteen cleanup nonce bytes"),
        )
        .expect("cleanup replay session");
        let replay_key = TenantRootCommandReplayKeyV1::new(
            journal.identity_digest,
            journal.custody_lineage,
            replay_session,
            cleanup_nonce,
            target.role(),
        );
        let payload = replacement_payload.unwrap_or(&command_bytes);
        let receipt = TenantRootCommandTerminalReceiptV1::sign_success(
            replay_key,
            TenantRootProtocolDigestV1::from_bytes([0xd1; 32]).expect("command digest"),
            payload.to_vec(),
            1_010_000,
            journal.ceremony_context.signing_key_id(target.role()),
            &role_signing_key(receipt_signer).to_bytes(),
        )
        .expect("cleanup receipt");
        creation_cleanup_checkpoint_record(
            CloudflareTenantRootCreationCleanupRequestV1 {
                cleanup_command_b64u: encode_base64url_bytes_v1(&command_bytes),
                cleanup_receipt_b64u: encode_base64url_bytes_v1(
                    &receipt.canonical_bytes().expect("cleanup receipt bytes"),
                ),
            },
            journal,
            role,
        )
        .expect("cleanup checkpoint record")
    }

    #[test]
    fn creation_cleanup_commits_once_and_replays_exactly_after_expiry() {
        const FRESH_NOW_MS: u64 = 1_010_000;
        const EXPIRED_NOW_MS: u64 = 1_030_001;
        let journal = validate(
            record(0x21, 0x51, authority(0x44), 1_000, 1_030),
            authority(0x44),
        )
        .expect("journal");
        let (installation_record, commitments) =
            deriver_b_installation_checkpoint(&journal, FRESH_NOW_MS);
        let installation = validate_installation_checkpoint(
            installation_record,
            &journal,
            &role_keys(),
            &commitments,
        )
        .expect("installation");
        let candidate_record = cleanup_checkpoint_fixture(
            &journal,
            &installation,
            0x83,
            TwoPartyDeriverRole::DeriverB,
            None,
        );
        let candidate = validate_creation_cleanup_checkpoint(
            candidate_record.clone(),
            &journal,
            &installation,
            authority(0x44),
            &verifying_keys(),
            &role_keys(),
        )
        .expect("cleanup candidate");
        let committed = evaluate_creation_cleanup_checkpoint(
            None,
            candidate,
            &journal,
            &installation,
            authority(0x44),
            &verifying_keys(),
            &role_keys(),
            FRESH_NOW_MS,
        )
        .expect("cleanup commit");
        let checkpoint = match committed {
            TenantRootCreationCleanupEvaluationV1::Commit {
                checkpoint,
                response,
            } => {
                assert_eq!(
                    response.outcome,
                    CloudflareTenantRootCreationCleanupOutcomeV1::Committed
                );
                checkpoint
            }
            TenantRootCreationCleanupEvaluationV1::Replay(_) => {
                panic!("fresh cleanup cannot replay")
            }
        };
        let replay_candidate = validate_creation_cleanup_checkpoint(
            candidate_record,
            &journal,
            &installation,
            authority(0x44),
            &verifying_keys(),
            &role_keys(),
        )
        .expect("replay candidate");
        let replay = evaluate_creation_cleanup_checkpoint(
            Some(checkpoint),
            replay_candidate,
            &journal,
            &installation,
            authority(0x44),
            &verifying_keys(),
            &role_keys(),
            EXPIRED_NOW_MS,
        )
        .expect("exact expired cleanup replay");
        assert!(matches!(
            replay,
            TenantRootCreationCleanupEvaluationV1::Replay(
                CloudflareTenantRootCreationCleanupResponseV1 {
                    outcome: CloudflareTenantRootCreationCleanupOutcomeV1::Replay,
                    ..
                }
            )
        ));
    }

    #[test]
    fn creation_cleanup_rejects_role_signer_payload_and_lifecycle_substitution() {
        const NOW_MS: u64 = 1_010_000;
        let journal = validate(
            record(0x21, 0x51, authority(0x44), 1_000, 1_030),
            authority(0x44),
        )
        .expect("journal");
        let (installation_record, commitments) =
            deriver_b_installation_checkpoint(&journal, NOW_MS);
        let installation = validate_installation_checkpoint(
            installation_record.clone(),
            &journal,
            &role_keys(),
            &commitments,
        )
        .expect("installation");

        let mut wrong_role = cleanup_checkpoint_fixture(
            &journal,
            &installation,
            0x83,
            TwoPartyDeriverRole::DeriverB,
            None,
        );
        wrong_role.role = CloudflareTenantRootCreationInstallationRoleV1::DeriverA;
        assert!(validate_creation_cleanup_checkpoint(
            wrong_role,
            &journal,
            &installation,
            authority(0x44),
            &verifying_keys(),
            &role_keys(),
        )
        .is_err());

        let wrong_signer = cleanup_checkpoint_fixture(
            &journal,
            &installation,
            0x83,
            TwoPartyDeriverRole::DeriverA,
            None,
        );
        assert!(validate_creation_cleanup_checkpoint(
            wrong_signer,
            &journal,
            &installation,
            authority(0x44),
            &verifying_keys(),
            &role_keys(),
        )
        .is_err());

        let wrong_payload = cleanup_checkpoint_fixture(
            &journal,
            &installation,
            0x83,
            TwoPartyDeriverRole::DeriverB,
            Some(b"other cleanup authorization"),
        );
        assert!(validate_creation_cleanup_checkpoint(
            wrong_payload,
            &journal,
            &installation,
            authority(0x44),
            &verifying_keys(),
            &role_keys(),
        )
        .is_err());

        let command_a = role_creation_command(&journal, TwoPartyDeriverRole::DeriverA);
        let completed = evaluate_installation_checkpoint(
            Some(installation_record),
            installation_wire(&journal, TwoPartyDeriverRole::DeriverA, 12, 19, 0x61),
            &command_a,
            &journal,
            &role_keys(),
            &commitments,
            NOW_MS,
        )
        .expect("complete installation");
        let completed_record = match completed {
            TenantRootCreationInstallationEvaluationV1::Commit { checkpoint, .. } => checkpoint,
            other => panic!("unexpected completion outcome: {other:?}"),
        };
        let completed_installation = validate_installation_checkpoint(
            completed_record,
            &journal,
            &role_keys(),
            &commitments,
        )
        .expect("completed installation");
        assert_eq!(
            creation_cleanup_target(&journal, &completed_installation)
                .expect_err("completed installation cannot be cleaned")
                .code(),
            RouterAbProtocolErrorCode::ConflictingPair
        );
    }

    #[test]
    fn first_acceptance_and_exact_expired_replay_are_distinct() {
        let accepted = record(0x21, 0x51, authority(0x44), 1_000, 1_030);
        let commit = evaluate_creation_record(
            None,
            validate(accepted.clone(), authority(0x44)).expect("candidate"),
            authority(0x44),
            &verifying_keys(),
            1_015,
        )
        .expect("commit");
        assert!(matches!(
            commit,
            TenantRootCreationJournalEvaluationV1::Commit { .. }
        ));
        let mut retained_keys = verifying_keys();
        retained_keys.insert(
            "tenant-root-creation-issuer-v2".to_owned(),
            SigningKey::from_bytes(&[0x73; 32])
                .verifying_key()
                .to_bytes(),
        );
        let replay = evaluate_creation_record(
            Some(accepted.clone()),
            validate(accepted, authority(0x44)).expect("replay candidate"),
            authority(0x44),
            &retained_keys,
            1_031,
        )
        .expect("expired exact replay");
        assert!(matches!(
            replay,
            TenantRootCreationJournalEvaluationV1::Replay(_)
        ));
    }

    #[test]
    fn unseen_expired_and_every_changed_command_fail_closed() {
        let accepted = record(0x21, 0x51, authority(0x44), 1_000, 1_030);
        assert_eq!(
            evaluate_creation_record(
                None,
                validate(accepted.clone(), authority(0x44)).expect("expired candidate"),
                authority(0x44),
                &verifying_keys(),
                1_031,
            )
            .expect_err("unseen expired capability")
            .code(),
            RouterAbProtocolErrorCode::ExpiredLocalRequest
        );
        for changed in [
            record(0x21, 0x52, authority(0x44), 1_000, 1_030),
            record(0x22, 0x51, authority(0x44), 1_000, 1_030),
        ] {
            assert_eq!(
                evaluate_creation_record(
                    Some(accepted.clone()),
                    validate(changed, authority(0x44)).expect("changed candidate"),
                    authority(0x44),
                    &verifying_keys(),
                    1_015,
                )
                .expect_err("changed command")
                .code(),
                RouterAbProtocolErrorCode::ConflictingPair
            );
        }
    }

    #[test]
    fn issuer_key_authority_and_journal_substitutions_are_rejected() {
        let accepted = record(0x21, 0x51, authority(0x44), 1_000, 1_030);
        assert!(
            validate_creation_record(accepted.clone(), authority(0x45), &verifying_keys()).is_err()
        );
        assert!(
            validate_creation_record(accepted.clone(), authority(0x44), &BTreeMap::new()).is_err()
        );
        let wrong_key = SigningKey::from_bytes(&[0x72; 32])
            .verifying_key()
            .to_bytes();
        let wrong_keys = BTreeMap::from([(ISSUER_KEY_ID.to_owned(), wrong_key)]);
        assert!(validate_creation_record(accepted.clone(), authority(0x44), &wrong_keys).is_err());
        let mut tampered = accepted;
        let mut journal =
            decode_base64url_bytes_v1("journal", &tampered.journal_b64u).expect("journal bytes");
        journal[0] ^= 1;
        tampered.journal_b64u = encode_base64url_bytes_v1(&journal);
        assert!(validate(tampered, authority(0x44)).is_err());
    }

    #[test]
    fn refresh_active_state_accepts_exact_signed_receipt_replay() {
        let (record, issuer_keys) = active_refresh_state_fixture();
        let receipt_bytes =
            decode_base64url_bytes_v1("active activation receipt", &record.activation_receipt_b64u)
                .expect("active receipt bytes");
        let receipt = TenantRootSignedActivationReceiptV1::decode_canonical_bytes(&receipt_bytes)
            .expect("active receipt");
        let expected_digest = receipt.digest().expect("active receipt digest");
        let validated = validate_refresh_active_state_record(record, authority(0x71), &issuer_keys)
            .expect("exact active state replay");
        assert_eq!(validated.active_epoch.get().get(), 1);
        assert_eq!(validated.activation_receipt_digest, expected_digest);
    }

    #[test]
    fn refresh_terminal_fence_replays_exact_response_after_json_restart() {
        let (record, issuer_keys) = active_refresh_state_fixture();
        let active =
            validate_refresh_active_state_record(record.clone(), authority(0x71), &issuer_keys)
                .expect("active refresh state");
        let context = refresh_context(&active);
        let command_a = refresh_command(&active, &context, TwoPartyDeriverRole::DeriverA);
        let command_b = refresh_command(&active, &context, TwoPartyDeriverRole::DeriverB);
        let attempt = refresh_attempt_from_commands(&context, &command_a, &command_b)
            .expect("refresh attempt");
        let activation_receipt = refresh_activation_receipt(&active, &context);
        let result_revision = active
            .record
            .lifecycle_revision
            .checked_add(1)
            .expect("refresh result revision");
        let mut terminal_record =
            refresh_active_state_record_from_verified_receipt(activation_receipt, result_revision)
                .expect("refresh active record");
        let response = refresh_terminal_response_from_record(&terminal_record);
        terminal_record.fence = CloudflareTenantRootRefreshFenceV1::Terminal {
            attempt,
            outcome: CloudflareTenantRootRefreshTerminalOutcomeV1::Completed,
            response: response.clone(),
        };
        validate_refresh_active_state_record(
            terminal_record.clone(),
            authority(0x71),
            &issuer_keys,
        )
        .expect("terminal refresh state validates against its activation");

        let restarted: CloudflareTenantRootRefreshActiveStateRecordV1 = serde_json::from_slice(
            &serde_json::to_vec(&terminal_record).expect("persist terminal refresh state"),
        )
        .expect("reload terminal refresh state");
        let CloudflareTenantRootRefreshFenceV1::Terminal {
            response: restarted_response,
            ..
        } = &restarted.fence
        else {
            panic!("restart must retain the terminal refresh fence")
        };
        assert_eq!(restarted_response, &response);
        assert_eq!(
            restarted_response,
            &refresh_terminal_response_from_record(&restarted)
        );
        validate_refresh_active_state_record(restarted, authority(0x71), &issuer_keys)
            .expect("restarted terminal refresh state validates");
    }

    #[test]
    fn managed_restore_fence_reserves_checkpoints_and_replays_after_json_restart() {
        const RESERVE_NOW_MS: u64 = 1_000_250;
        const EXPIRED_RETRY_NOW_MS: u64 = 1_000_301;
        let (mut active, journal, issuer_keys) = managed_restore_active_state_fixture();
        let request = managed_restore_request(0x61);
        let challenge = managed_restore_authorization_challenge_from_active_state_v1(
            &active,
            &journal,
            request.clone(),
        )
        .expect("managed-restore challenge");
        let mut tampered_challenge = challenge;
        tampered_challenge.activation_receipt_digest_b64u = encode_base64url_bytes_v1(&[0x62; 32]);
        assert!(validate_managed_restore_challenge_shape_v1(&tampered_challenge).is_err());
        let reserved = match reserve_managed_restore_authorization_fence_v1(
            &active,
            &journal,
            request.clone(),
            RESERVE_NOW_MS,
        )
        .expect("managed-restore reservation")
        {
            CloudflareTenantRootManagedRestoreFenceEvaluationV1::Commit { fence } => fence,
            CloudflareTenantRootManagedRestoreFenceEvaluationV1::Replay { .. } => {
                panic!("fresh managed-restore request must reserve")
            }
        };
        active.record.managed_restore_fence = reserved.clone();
        let persisted_reserved: CloudflareTenantRootRefreshActiveStateRecordV1 =
            serde_json::from_slice(
                &serde_json::to_vec(&active.record).expect("persist reserved managed restore"),
            )
            .expect("reload reserved managed restore");
        active =
            validate_refresh_active_state_record(persisted_reserved, authority(0x71), &issuer_keys)
                .expect("reloaded reserved managed restore");
        assert!(matches!(
            reserve_managed_restore_authorization_fence_v1(
                &active,
                &journal,
                request.clone(),
                EXPIRED_RETRY_NOW_MS,
            )
            .expect("exact reservation replay after expiry"),
            CloudflareTenantRootManagedRestoreFenceEvaluationV1::Replay { fence }
                if fence == reserved
        ));

        let (challenge, attempt) = match &reserved {
            CloudflareTenantRootManagedRestoreFenceV1::Reserved { challenge, attempt } => {
                (challenge.clone(), attempt.clone())
            }
            CloudflareTenantRootManagedRestoreFenceV1::Open
            | CloudflareTenantRootManagedRestoreFenceV1::Terminal { .. } => {
                panic!("reservation must retain the reserved challenge")
            }
        };
        let checkpoint = CloudflareTenantRootManagedRestoreAuthorizationCheckpointV1 {
            challenge,
            attempt,
            public_state_b64u: encode_base64url_bytes_v1(b"managed-restore-public-state"),
            capability_b64u: encode_base64url_bytes_v1(b"managed-restore-capability"),
            incident_authorization_b64u: encode_base64url_bytes_v1(
                b"managed-restore-incident-authorization",
            ),
        };
        let terminal =
            match checkpoint_managed_restore_authorization_fence_v1(&active, checkpoint.clone())
                .expect("managed-restore checkpoint")
            {
                CloudflareTenantRootManagedRestoreFenceEvaluationV1::Commit { fence } => fence,
                CloudflareTenantRootManagedRestoreFenceEvaluationV1::Replay { .. } => {
                    panic!("first managed-restore checkpoint must commit")
                }
            };
        active.record.managed_restore_fence = terminal.clone();
        let persisted_terminal: CloudflareTenantRootRefreshActiveStateRecordV1 =
            serde_json::from_slice(
                &serde_json::to_vec(&active.record).expect("persist terminal managed restore"),
            )
            .expect("reload terminal managed restore");
        active =
            validate_refresh_active_state_record(persisted_terminal, authority(0x71), &issuer_keys)
                .expect("reloaded terminal managed restore");
        assert!(matches!(
            checkpoint_managed_restore_authorization_fence_v1(&active, checkpoint)
                .expect("exact terminal checkpoint replay after restart"),
            CloudflareTenantRootManagedRestoreFenceEvaluationV1::Replay { fence }
                if fence == terminal
        ));
    }

    #[test]
    fn managed_restore_fence_rejects_changed_attempt_or_artifact_after_terminal() {
        let (mut active, journal, issuer_keys) = managed_restore_active_state_fixture();
        let request = managed_restore_request(0x63);
        let reserved = match reserve_managed_restore_authorization_fence_v1(
            &active,
            &journal,
            request.clone(),
            1_000_250,
        )
        .expect("managed-restore reservation")
        {
            CloudflareTenantRootManagedRestoreFenceEvaluationV1::Commit { fence } => fence,
            CloudflareTenantRootManagedRestoreFenceEvaluationV1::Replay { .. } => {
                panic!("fresh managed-restore request must reserve")
            }
        };
        active.record.managed_restore_fence = reserved.clone();
        let (challenge, attempt) = match reserved {
            CloudflareTenantRootManagedRestoreFenceV1::Reserved { challenge, attempt } => {
                (challenge, attempt)
            }
            CloudflareTenantRootManagedRestoreFenceV1::Open
            | CloudflareTenantRootManagedRestoreFenceV1::Terminal { .. } => {
                panic!("reservation must retain the reserved challenge")
            }
        };
        let checkpoint = CloudflareTenantRootManagedRestoreAuthorizationCheckpointV1 {
            challenge,
            attempt,
            public_state_b64u: encode_base64url_bytes_v1(b"managed-restore-public-state"),
            capability_b64u: encode_base64url_bytes_v1(b"managed-restore-capability"),
            incident_authorization_b64u: encode_base64url_bytes_v1(
                b"managed-restore-incident-authorization",
            ),
        };
        let terminal =
            match checkpoint_managed_restore_authorization_fence_v1(&active, checkpoint.clone())
                .expect("managed-restore checkpoint")
            {
                CloudflareTenantRootManagedRestoreFenceEvaluationV1::Commit { fence } => fence,
                CloudflareTenantRootManagedRestoreFenceEvaluationV1::Replay { .. } => {
                    panic!("first managed-restore checkpoint must commit")
                }
            };
        active.record.managed_restore_fence = terminal;
        validate_refresh_active_state_record(
            serde_json::from_slice(
                &serde_json::to_vec(&active.record).expect("persist managed restore"),
            )
            .expect("reload managed restore"),
            authority(0x71),
            &issuer_keys,
        )
        .expect("terminal managed restore remains valid");

        let error = reserve_managed_restore_authorization_fence_v1(
            &active,
            &journal,
            managed_restore_request(0x64),
            1_000_250,
        )
        .expect_err("changed operator attempt must conflict");
        assert_eq!(error.code(), RouterAbProtocolErrorCode::ConflictingPair);

        let mut changed_artifact = checkpoint.clone();
        changed_artifact.public_state_b64u = encode_base64url_bytes_v1(b"changed-public-state");
        let error = checkpoint_managed_restore_authorization_fence_v1(&active, changed_artifact)
            .expect_err("changed terminal artifact must conflict");
        assert_eq!(error.code(), RouterAbProtocolErrorCode::ConflictingPair);
        let mut changed_incident_authorization = checkpoint;
        changed_incident_authorization.incident_authorization_b64u =
            encode_base64url_bytes_v1(b"changed-incident-authorization");
        let error = checkpoint_managed_restore_authorization_fence_v1(
            &active,
            changed_incident_authorization,
        )
        .expect_err("changed incident authorization must conflict");
        assert_eq!(error.code(), RouterAbProtocolErrorCode::ConflictingPair);
    }

    #[test]
    fn managed_restore_terminal_fence_survives_one_completed_refresh_transition() {
        let (mut active, journal, issuer_keys) = managed_restore_active_state_fixture();
        let request = managed_restore_request(0x65);
        let reserved = match reserve_managed_restore_authorization_fence_v1(
            &active,
            &journal,
            request.clone(),
            1_000_250,
        )
        .expect("managed-restore reservation")
        {
            CloudflareTenantRootManagedRestoreFenceEvaluationV1::Commit { fence } => fence,
            CloudflareTenantRootManagedRestoreFenceEvaluationV1::Replay { .. } => {
                panic!("fresh managed-restore request must reserve")
            }
        };
        active.record.managed_restore_fence = reserved.clone();
        let checkpoint = match reserved {
            CloudflareTenantRootManagedRestoreFenceV1::Reserved { challenge, attempt } => {
                CloudflareTenantRootManagedRestoreAuthorizationCheckpointV1 {
                    challenge,
                    attempt,
                    public_state_b64u: encode_base64url_bytes_v1(b"managed-restore-public-state"),
                    capability_b64u: encode_base64url_bytes_v1(b"managed-restore-capability"),
                    incident_authorization_b64u: encode_base64url_bytes_v1(
                        b"managed-restore-incident-authorization",
                    ),
                }
            }
            CloudflareTenantRootManagedRestoreFenceV1::Open
            | CloudflareTenantRootManagedRestoreFenceV1::Terminal { .. } => {
                panic!("reservation must retain the reserved challenge")
            }
        };
        let terminal =
            match checkpoint_managed_restore_authorization_fence_v1(&active, checkpoint.clone())
                .expect("managed-restore checkpoint")
            {
                CloudflareTenantRootManagedRestoreFenceEvaluationV1::Commit { fence } => fence,
                CloudflareTenantRootManagedRestoreFenceEvaluationV1::Replay { .. } => {
                    panic!("first managed-restore checkpoint must commit")
                }
            };
        active.record.managed_restore_fence = terminal;

        let context = refresh_context(&active);
        let command_a = refresh_command(&active, &context, TwoPartyDeriverRole::DeriverA);
        let command_b = refresh_command(&active, &context, TwoPartyDeriverRole::DeriverB);
        let refresh_attempt = refresh_attempt_from_commands(&context, &command_a, &command_b)
            .expect("refresh attempt");
        let result_revision = active
            .record
            .lifecycle_revision
            .checked_add(1)
            .expect("refresh result revision");
        let activation_receipt = refresh_activation_receipt(&active, &context);
        let mut refreshed_record =
            refresh_active_state_record_from_verified_receipt(activation_receipt, result_revision)
                .expect("refreshed active record");
        let response = refresh_terminal_response_from_record(&refreshed_record);
        refreshed_record.fence = CloudflareTenantRootRefreshFenceV1::Terminal {
            attempt: refresh_attempt,
            outcome: CloudflareTenantRootRefreshTerminalOutcomeV1::Completed,
            response,
        };
        refreshed_record.managed_restore_fence = active.record.managed_restore_fence.clone();
        let refreshed =
            validate_refresh_active_state_record(refreshed_record, authority(0x71), &issuer_keys)
                .expect("completed refresh preserves the terminal managed-restore fence");
        assert!(matches!(
            reserve_managed_restore_authorization_fence_v1(
                &refreshed, &journal, request, 1_000_250,
            )
            .expect("managed-restore terminal request replay after refresh"),
            CloudflareTenantRootManagedRestoreFenceEvaluationV1::Replay { .. }
        ));
        assert!(matches!(
            checkpoint_managed_restore_authorization_fence_v1(&refreshed, checkpoint)
                .expect("managed-restore terminal retry after refresh"),
            CloudflareTenantRootManagedRestoreFenceEvaluationV1::Replay { .. }
        ));
    }

    #[test]
    fn refresh_active_state_rejects_nonzero_signature_substitution() {
        let (mut record, issuer_keys) = active_refresh_state_fixture();
        let mut receipt_bytes =
            decode_base64url_bytes_v1("active activation receipt", &record.activation_receipt_b64u)
                .expect("active receipt bytes");
        let last_byte = receipt_bytes
            .last_mut()
            .expect("active receipt has a signature");
        *last_byte ^= 1;
        record.activation_receipt_b64u = encode_base64url_bytes_v1(&receipt_bytes);
        let error = validate_refresh_active_state_record(record, authority(0x71), &issuer_keys)
            .err()
            .expect("substituted signature must fail");
        assert_eq!(
            error.code(),
            RouterAbProtocolErrorCode::ForbiddenLocalBinding
        );
    }

    #[test]
    fn refresh_active_state_rejects_unknown_receipt_issuer_key_id() {
        let (record, _) = active_refresh_state_fixture();
        let wrong_keys = BTreeMap::from([(
            "different-issuer-v1".to_owned(),
            SigningKey::from_bytes(&[0x41; 32])
                .verifying_key()
                .to_bytes(),
        )]);
        let error = validate_refresh_active_state_record(record, authority(0x71), &wrong_keys)
            .err()
            .expect("unknown issuer key id must fail");
        assert_eq!(
            error.code(),
            RouterAbProtocolErrorCode::ForbiddenLocalBinding
        );
    }

    #[test]
    fn refresh_active_state_rejects_corrupt_reload() {
        let (mut record, issuer_keys) = active_refresh_state_fixture();
        record.activation_receipt_b64u = encode_base64url_bytes_v1(&[0x91; 8]);
        let error = validate_refresh_active_state_record(record, authority(0x71), &issuer_keys)
            .err()
            .expect("corrupt active state must fail");
        assert_eq!(
            error.code(),
            RouterAbProtocolErrorCode::MalformedWirePayload
        );
    }

    #[test]
    fn stored_corruption_is_not_reported_as_a_request_conflict() {
        let mut corrupt = record(0x21, 0x51, authority(0x44), 1_000, 1_030);
        corrupt.creation_capability_b64u.push('A');
        let candidate = record(0x22, 0x52, authority(0x44), 1_000, 1_030);
        let error = evaluate_creation_record(
            Some(corrupt),
            validate(candidate, authority(0x44)).expect("candidate"),
            authority(0x44),
            &verifying_keys(),
            1_015,
        )
        .expect_err("stored corruption");
        assert_eq!(
            error.code(),
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig
        );
    }

    #[test]
    fn object_names_are_stable_and_identity_lineage_scoped() {
        let first = tenant_root_creation_object_name_v1(
            TenantRootIdentityDigestV1::from_bytes([0x11; 32]),
            TenantRootCustodyLineageId::from_bytes([0x22; 16]).expect("lineage"),
        );
        let replay = tenant_root_creation_object_name_v1(
            TenantRootIdentityDigestV1::from_bytes([0x11; 32]),
            TenantRootCustodyLineageId::from_bytes([0x22; 16]).expect("lineage"),
        );
        let other_identity = tenant_root_creation_object_name_v1(
            TenantRootIdentityDigestV1::from_bytes([0x12; 32]),
            TenantRootCustodyLineageId::from_bytes([0x22; 16]).expect("lineage"),
        );
        let other_lineage = tenant_root_creation_object_name_v1(
            TenantRootIdentityDigestV1::from_bytes([0x11; 32]),
            TenantRootCustodyLineageId::from_bytes([0x23; 16]).expect("lineage"),
        );
        assert_eq!(first, replay);
        assert_ne!(first, other_identity);
        assert_ne!(first, other_lineage);
        assert!(first.starts_with("tenant-root-creation-v1-"));
    }

    #[test]
    fn object_binding_requires_the_exact_derived_authority_id() {
        let expected = authority(0xab);
        let object_id = lower_hex(expected.as_bytes());
        assert!(validate_tenant_root_creation_object_binding_v1(&object_id, expected).is_ok());
        assert_eq!(
            validate_tenant_root_creation_object_binding_v1(&object_id, authority(0xac))
                .expect_err("mismatched authority")
                .code(),
            RouterAbProtocolErrorCode::ForbiddenLocalBinding
        );
        assert_eq!(
            validate_tenant_root_creation_object_binding_v1(&object_id.to_uppercase(), expected)
                .expect_err("non-canonical object id")
                .code(),
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig
        );
    }

    #[test]
    fn response_validation_requires_exact_revision_and_digests() {
        let candidate = validate(
            record(0x21, 0x51, authority(0x44), 1_000, 1_030),
            authority(0x44),
        )
        .expect("candidate");
        let expected_revision = candidate.revision;
        let expected_journal_digest = candidate.journal_digest;
        let expected_capability_digest = candidate.capability.digest();
        let response = candidate.response(CloudflareTenantRootCreationJournalOutcomeV1::Committed);
        assert!(
            validate_cloudflare_tenant_root_creation_journal_response_v1(
                &response,
                expected_revision,
                expected_journal_digest,
                expected_capability_digest,
            )
            .is_ok()
        );

        let mut wrong_revision = response.clone();
        wrong_revision.revision += 1;
        assert_eq!(
            validate_cloudflare_tenant_root_creation_journal_response_v1(
                &wrong_revision,
                expected_revision,
                expected_journal_digest,
                expected_capability_digest,
            )
            .expect_err("wrong revision")
            .code(),
            RouterAbProtocolErrorCode::MalformedWirePayload
        );

        let mut wrong_digest = response.clone();
        wrong_digest.journal_digest_b64u = encode_base64url_bytes_v1(&[0x81; 32]);
        assert_eq!(
            validate_cloudflare_tenant_root_creation_journal_response_v1(
                &wrong_digest,
                expected_revision,
                expected_journal_digest,
                expected_capability_digest,
            )
            .expect_err("wrong journal digest")
            .code(),
            RouterAbProtocolErrorCode::MalformedWirePayload
        );

        let mut wrong_capability_digest = response;
        wrong_capability_digest.capability_digest_b64u = encode_base64url_bytes_v1(&[0x82; 32]);
        assert_eq!(
            validate_cloudflare_tenant_root_creation_journal_response_v1(
                &wrong_capability_digest,
                expected_revision,
                expected_journal_digest,
                expected_capability_digest,
            )
            .expect_err("wrong capability digest")
            .code(),
            RouterAbProtocolErrorCode::MalformedWirePayload
        );
    }

    #[test]
    fn creation_commitment_rendezvous_accepts_both_orders_and_exact_expired_replays() {
        const FRESH_NOW_MS: u64 = 1_010_000;
        const EXPIRED_NOW_MS: u64 = 1_030_001;
        let journal = validate(
            record(0x21, 0x51, authority(0x44), 1_000, 1_030),
            authority(0x44),
        )
        .expect("journal");
        let deriver_a = creation_commitment_wire(&journal, TwoPartyDeriverRole::DeriverA, 12);
        let deriver_a_command = role_creation_command(&journal, TwoPartyDeriverRole::DeriverA);
        let first = evaluate_creation_commitment_rendezvous(
            None,
            &deriver_a,
            &deriver_a_command,
            &journal,
            &role_keys(),
            FRESH_NOW_MS,
        )
        .expect("first commitment");
        let first_record = match first {
            TenantRootCreationCommitmentRendezvousEvaluationV1::Commit {
                rendezvous,
                outcome:
                    CloudflareTenantRootCreationCommitmentOutcomeV1::WaitingForPeer {
                        role: CloudflareTenantRootCreationInstallationRoleV1::DeriverA,
                    },
            } => rendezvous,
            other => panic!("unexpected first commitment outcome: {other:?}"),
        };

        assert!(matches!(
            evaluate_creation_commitment_rendezvous(
                Some(first_record.clone()),
                &deriver_a,
                &deriver_a_command,
                &journal,
                &role_keys(),
                EXPIRED_NOW_MS,
            )
            .expect("exact expired retry"),
            TenantRootCreationCommitmentRendezvousEvaluationV1::Replay(
                CloudflareTenantRootCreationCommitmentOutcomeV1::WaitingForPeer {
                    role: CloudflareTenantRootCreationInstallationRoleV1::DeriverA,
                }
            )
        ));
        assert_eq!(
            evaluate_creation_commitment_rendezvous(
                Some(first_record.clone()),
                &creation_commitment_wire(&journal, TwoPartyDeriverRole::DeriverA, 13),
                &deriver_a_command,
                &journal,
                &role_keys(),
                EXPIRED_NOW_MS,
            )
            .expect_err("same-role substitution")
            .code(),
            RouterAbProtocolErrorCode::ConflictingPair
        );

        let deriver_b = creation_commitment_wire(&journal, TwoPartyDeriverRole::DeriverB, 19);
        let deriver_b_command = role_creation_command(&journal, TwoPartyDeriverRole::DeriverB);
        let completed = evaluate_creation_commitment_rendezvous(
            Some(first_record),
            &deriver_b,
            &deriver_b_command,
            &journal,
            &role_keys(),
            FRESH_NOW_MS,
        )
        .expect("opposite-role commitment");
        let (completed_record, pair_wire) = match completed {
            TenantRootCreationCommitmentRendezvousEvaluationV1::Commit {
                rendezvous,
                outcome:
                    CloudflareTenantRootCreationCommitmentOutcomeV1::BothRolesCommitted { pair },
            } => (rendezvous, pair.canonical_bytes().to_vec()),
            other => panic!("unexpected completed commitment outcome: {other:?}"),
        };
        match evaluate_creation_commitment_rendezvous(
            Some(completed_record.clone()),
            &deriver_b,
            &deriver_b_command,
            &journal,
            &role_keys(),
            EXPIRED_NOW_MS,
        )
        .expect("exact completed retry")
        {
            TenantRootCreationCommitmentRendezvousEvaluationV1::Replay(
                CloudflareTenantRootCreationCommitmentOutcomeV1::BothRolesCommitted { pair },
            ) => assert_eq!(pair.canonical_bytes(), pair_wire.as_slice()),
            other => panic!("unexpected completed retry outcome: {other:?}"),
        }

        let reverse_first = evaluate_creation_commitment_rendezvous(
            None,
            &deriver_b,
            &deriver_b_command,
            &journal,
            &role_keys(),
            FRESH_NOW_MS,
        )
        .expect("reverse first commitment");
        let reverse_record = match reverse_first {
            TenantRootCreationCommitmentRendezvousEvaluationV1::Commit { rendezvous, .. } => {
                rendezvous
            }
            other => panic!("unexpected reverse first outcome: {other:?}"),
        };
        assert!(matches!(
            evaluate_creation_commitment_rendezvous(
                Some(reverse_record),
                &deriver_a,
                &deriver_a_command,
                &journal,
                &role_keys(),
                FRESH_NOW_MS,
            )
            .expect("reverse completion"),
            TenantRootCreationCommitmentRendezvousEvaluationV1::Commit {
                outcome: CloudflareTenantRootCreationCommitmentOutcomeV1::BothRolesCommitted { .. },
                ..
            }
        ));
    }

    #[test]
    fn creation_commitment_rendezvous_rejects_wrong_bindings_and_corrupt_reload() {
        const FRESH_NOW_MS: u64 = 1_010_000;
        const EXPIRED_NOW_MS: u64 = 1_030_001;
        let journal = validate(
            record(0x21, 0x51, authority(0x44), 1_000, 1_030),
            authority(0x44),
        )
        .expect("journal");
        let candidate = creation_commitment_wire(&journal, TwoPartyDeriverRole::DeriverA, 12);
        let deriver_a_command = role_creation_command(&journal, TwoPartyDeriverRole::DeriverA);
        let deriver_b_command = role_creation_command(&journal, TwoPartyDeriverRole::DeriverB);
        let wrong_key = SigningKey::from_bytes(&[0xa3; 32]);
        let wrong_keys = role_keys_from_verifiers(
            "deriver-a-signing-key-7",
            wrong_key.verifying_key().to_bytes(),
            "deriver-b-signing-key-9",
            role_signing_key(TwoPartyDeriverRole::DeriverB)
                .verifying_key()
                .to_bytes(),
        );
        assert_eq!(
            evaluate_creation_commitment_rendezvous(
                None,
                &candidate,
                &deriver_a_command,
                &journal,
                &wrong_keys,
                FRESH_NOW_MS,
            )
            .expect_err("wrong signing key")
            .code(),
            RouterAbProtocolErrorCode::ForbiddenLocalBinding
        );

        let foreign_journal = validate(
            record(0x22, 0x52, authority(0x44), 1_000, 1_030),
            authority(0x44),
        )
        .expect("foreign journal");
        let foreign_candidate =
            creation_commitment_wire(&foreign_journal, TwoPartyDeriverRole::DeriverA, 12);
        assert_eq!(
            evaluate_creation_commitment_rendezvous(
                None,
                &foreign_candidate,
                &deriver_a_command,
                &journal,
                &role_keys(),
                FRESH_NOW_MS,
            )
            .expect_err("wrong ceremony context")
            .code(),
            RouterAbProtocolErrorCode::ForbiddenLocalBinding
        );

        let first = evaluate_creation_commitment_rendezvous(
            None,
            &candidate,
            &deriver_a_command,
            &journal,
            &role_keys(),
            FRESH_NOW_MS,
        )
        .expect("first commitment");
        let first_record = match first {
            TenantRootCreationCommitmentRendezvousEvaluationV1::Commit { rendezvous, .. } => {
                rendezvous
            }
            other => panic!("unexpected first outcome: {other:?}"),
        };
        let mut wrong_journal = first_record.clone();
        wrong_journal.journal_digest_b64u = encode_base64url_bytes_v1(&[0xa4; 32]);
        assert_eq!(
            evaluate_creation_commitment_rendezvous(
                Some(wrong_journal),
                &creation_commitment_wire(&journal, TwoPartyDeriverRole::DeriverB, 19),
                &deriver_b_command,
                &journal,
                &role_keys(),
                FRESH_NOW_MS,
            )
            .expect_err("wrong stored journal binding")
            .code(),
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig
        );
        let mut corrupt = first_record.clone();
        match &mut corrupt.state {
            CloudflareTenantRootCreationCommitmentRendezvousStateV1::OneRoleCommitted {
                signed_commitment_b64u,
                ..
            } => signed_commitment_b64u.push('A'),
            _ => panic!("first commitment must contain one role"),
        }
        assert_eq!(
            evaluate_creation_commitment_rendezvous(
                Some(corrupt),
                &creation_commitment_wire(&journal, TwoPartyDeriverRole::DeriverB, 19),
                &deriver_b_command,
                &journal,
                &role_keys(),
                FRESH_NOW_MS,
            )
            .expect_err("corrupt stored commitment")
            .code(),
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig
        );
        assert_eq!(
            evaluate_creation_commitment_rendezvous(
                None,
                &candidate,
                &deriver_a_command,
                &journal,
                &role_keys(),
                EXPIRED_NOW_MS,
            )
            .expect_err("unseen expired commitment")
            .code(),
            RouterAbProtocolErrorCode::ExpiredLocalRequest
        );

        let mut unknown = serde_json::to_value(first_record).expect("rendezvous JSON");
        unknown["unexpected"] = serde_json::Value::Bool(true);
        assert!(
            serde_json::from_value::<CloudflareTenantRootCreationCommitmentRendezvousRecordV1>(
                unknown
            )
            .is_err()
        );
    }

    #[test]
    fn installation_checkpoint_requires_the_complete_creation_commitment_pair() {
        const NOW_MS: u64 = 1_010_000;
        let journal = validate(
            record(0x21, 0x51, authority(0x44), 1_000, 1_030),
            authority(0x44),
        )
        .expect("journal");
        let deriver_a = creation_commitment_wire(&journal, TwoPartyDeriverRole::DeriverA, 12);
        let deriver_a_command = role_creation_command(&journal, TwoPartyDeriverRole::DeriverA);
        let first = evaluate_creation_commitment_rendezvous(
            None,
            &deriver_a,
            &deriver_a_command,
            &journal,
            &role_keys(),
            NOW_MS,
        )
        .expect("first commitment");
        let first_record = match first {
            TenantRootCreationCommitmentRendezvousEvaluationV1::Commit { rendezvous, .. } => {
                rendezvous
            }
            other => panic!("unexpected first commitment outcome: {other:?}"),
        };
        assert_eq!(
            require_complete_creation_commitment_rendezvous(None, &journal, &role_keys())
                .expect_err("missing rendezvous")
                .code(),
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig
        );
        assert_eq!(
            require_complete_creation_commitment_rendezvous(
                Some(first_record.clone()),
                &journal,
                &role_keys(),
            )
            .expect_err("one-role rendezvous")
            .code(),
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig
        );

        let (complete_record, commitments) = publish_creation_commitment_pair(&journal, NOW_MS);
        let reloaded = require_complete_creation_commitment_rendezvous(
            Some(complete_record),
            &journal,
            &role_keys(),
        )
        .expect("complete rendezvous");
        assert_eq!(reloaded.canonical_bytes(), commitments.canonical_bytes());
    }

    #[test]
    fn installation_checkpoint_accepts_both_orders_and_replays_exact_evidence() {
        const NOW_MS: u64 = 1_010_000;
        let journal = validate(
            record(0x21, 0x51, authority(0x44), 1_000, 1_030),
            authority(0x44),
        )
        .expect("journal");
        let (_commitment_rendezvous, commitments) =
            publish_creation_commitment_pair(&journal, NOW_MS);
        let command_a = role_creation_command(&journal, TwoPartyDeriverRole::DeriverA);
        let command_b = role_creation_command(&journal, TwoPartyDeriverRole::DeriverB);
        let deriver_a_wire =
            installation_wire(&journal, TwoPartyDeriverRole::DeriverA, 12, 19, 0x61);
        #[cfg(feature = "workers-rs")]
        let pending = CloudflareTenantRootPendingShareV1::from_verified_installation_evidence(
            &deriver_a_wire,
            NOW_MS,
        )
        .expect("pending evidence binding");
        #[cfg(feature = "workers-rs")]
        assert_eq!(
            pending.installation_evidence_digest(),
            deriver_a_wire
                .lifecycle_receipt_digest()
                .expect("evidence digest"),
        );
        let first = evaluate_installation_checkpoint(
            None,
            deriver_a_wire,
            &command_a,
            &journal,
            &role_keys(),
            &commitments,
            NOW_MS,
        )
        .expect("first role");
        let first_checkpoint = match first {
            TenantRootCreationInstallationEvaluationV1::Commit {
                checkpoint,
                outcome:
                    CloudflareTenantRootCreationInstallationOutcomeV1::WaitingForPeer {
                        role: CloudflareTenantRootCreationInstallationRoleV1::DeriverA,
                    },
            } => checkpoint,
            other => panic!("unexpected first-role outcome: {other:?}"),
        };
        assert!(matches!(
            evaluate_installation_checkpoint(
                Some(first_checkpoint.clone()),
                installation_wire(&journal, TwoPartyDeriverRole::DeriverA, 12, 19, 0x61),
                &command_a,
                &journal,
                &role_keys(),
                &commitments,
                NOW_MS,
            )
            .expect("exact retry"),
            TenantRootCreationInstallationEvaluationV1::Replay(
                CloudflareTenantRootCreationInstallationOutcomeV1::WaitingForPeer {
                    role: CloudflareTenantRootCreationInstallationRoleV1::DeriverA,
                }
            )
        ));
        let completed = evaluate_installation_checkpoint(
            Some(first_checkpoint),
            installation_wire(&journal, TwoPartyDeriverRole::DeriverB, 19, 12, 0x62),
            &command_b,
            &journal,
            &role_keys(),
            &commitments,
            NOW_MS,
        )
        .expect("second role");
        let completed_checkpoint = match completed {
            TenantRootCreationInstallationEvaluationV1::Commit {
                checkpoint,
                outcome: CloudflareTenantRootCreationInstallationOutcomeV1::BothRolesReady { .. },
            } => checkpoint,
            other => panic!("unexpected completed outcome: {other:?}"),
        };
        assert!(matches!(
            validate_installation_checkpoint(
                completed_checkpoint.clone(),
                &journal,
                &role_keys(),
                &commitments,
            )
            .expect("durable reload")
            .state,
            ValidatedTenantRootCreationInstallationStateV1::BothRolesReady { .. }
        ));
        assert!(matches!(
            evaluate_installation_checkpoint(
                Some(completed_checkpoint),
                installation_wire(&journal, TwoPartyDeriverRole::DeriverB, 19, 12, 0x62),
                &command_b,
                &journal,
                &role_keys(),
                &commitments,
                NOW_MS,
            )
            .expect("completed retry"),
            TenantRootCreationInstallationEvaluationV1::Replay(
                CloudflareTenantRootCreationInstallationOutcomeV1::BothRolesReady { .. }
            )
        ));

        let reverse_first = evaluate_installation_checkpoint(
            None,
            installation_wire(&journal, TwoPartyDeriverRole::DeriverB, 19, 12, 0x62),
            &command_b,
            &journal,
            &role_keys(),
            &commitments,
            NOW_MS,
        )
        .expect("reverse first");
        let reverse_checkpoint = match reverse_first {
            TenantRootCreationInstallationEvaluationV1::Commit { checkpoint, .. } => checkpoint,
            other => panic!("unexpected reverse first outcome: {other:?}"),
        };
        assert!(matches!(
            evaluate_installation_checkpoint(
                Some(reverse_checkpoint),
                installation_wire(&journal, TwoPartyDeriverRole::DeriverA, 12, 19, 0x61),
                &command_a,
                &journal,
                &role_keys(),
                &commitments,
                NOW_MS,
            )
            .expect("reverse completion"),
            TenantRootCreationInstallationEvaluationV1::Commit {
                outcome: CloudflareTenantRootCreationInstallationOutcomeV1::BothRolesReady { .. },
                ..
            }
        ));
    }

    #[test]
    fn installation_checkpoint_rejects_substitution_and_corrupt_reload() {
        const NOW_MS: u64 = 1_010_000;
        let journal = validate(
            record(0x21, 0x51, authority(0x44), 1_000, 1_030),
            authority(0x44),
        )
        .expect("journal");
        let (_commitment_rendezvous, commitments) =
            publish_creation_commitment_pair(&journal, NOW_MS);
        let command_a = role_creation_command(&journal, TwoPartyDeriverRole::DeriverA);
        let command_b = role_creation_command(&journal, TwoPartyDeriverRole::DeriverB);
        let first = evaluate_installation_checkpoint(
            None,
            installation_wire(&journal, TwoPartyDeriverRole::DeriverB, 19, 12, 0x62),
            &command_b,
            &journal,
            &role_keys(),
            &commitments,
            NOW_MS,
        )
        .expect("first role");
        let first_checkpoint = match first {
            TenantRootCreationInstallationEvaluationV1::Commit { checkpoint, .. } => checkpoint,
            other => panic!("unexpected first outcome: {other:?}"),
        };
        assert_eq!(
            evaluate_installation_checkpoint(
                Some(first_checkpoint.clone()),
                installation_wire(&journal, TwoPartyDeriverRole::DeriverB, 20, 12, 0x63),
                &command_b,
                &journal,
                &role_keys(),
                &commitments,
                NOW_MS,
            )
            .expect_err("same-role substitution")
            .code(),
            RouterAbProtocolErrorCode::ConflictingPair
        );
        let completed = evaluate_installation_checkpoint(
            Some(first_checkpoint),
            installation_wire(&journal, TwoPartyDeriverRole::DeriverA, 12, 19, 0x61),
            &command_a,
            &journal,
            &role_keys(),
            &commitments,
            NOW_MS,
        )
        .expect("completion");
        let mut corrupt = match completed {
            TenantRootCreationInstallationEvaluationV1::Commit { checkpoint, .. } => checkpoint,
            other => panic!("unexpected completed outcome: {other:?}"),
        };
        match &mut corrupt.state {
            CloudflareTenantRootCreationInstallationStateV1::BothRolesReady {
                root_commitment_b64u,
                ..
            } => *root_commitment_b64u = encode_base64url_bytes_v1(&[0x91; 32]),
            _ => panic!("completed checkpoint must contain both roles"),
        }
        assert_eq!(
            evaluate_installation_checkpoint(
                Some(corrupt),
                installation_wire(&journal, TwoPartyDeriverRole::DeriverA, 12, 19, 0x61),
                &command_a,
                &journal,
                &role_keys(),
                &commitments,
                NOW_MS,
            )
            .expect_err("corrupt stored root")
            .code(),
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig
        );

        let foreign_journal = validate(
            record(0x22, 0x52, authority(0x44), 1_000, 1_030),
            authority(0x44),
        )
        .expect("foreign journal");
        assert_eq!(
            evaluate_installation_checkpoint(
                None,
                installation_wire(
                    &foreign_journal,
                    TwoPartyDeriverRole::DeriverA,
                    12,
                    19,
                    0x64,
                ),
                &command_a,
                &journal,
                &role_keys(),
                &commitments,
                NOW_MS,
            )
            .expect_err("foreign ceremony")
            .code(),
            RouterAbProtocolErrorCode::ForbiddenLocalBinding
        );
    }

    #[test]
    fn installation_checkpoint_allows_only_exact_replay_after_expiry() {
        const FRESH_NOW_MS: u64 = 1_010_000;
        const EXPIRED_NOW_MS: u64 = 1_030_001;
        let journal = validate(
            record(0x21, 0x51, authority(0x44), 1_000, 1_030),
            authority(0x44),
        )
        .expect("journal");
        let (_commitment_rendezvous, commitments) =
            publish_creation_commitment_pair(&journal, FRESH_NOW_MS);
        let command_a = role_creation_command(&journal, TwoPartyDeriverRole::DeriverA);
        let command_b = role_creation_command(&journal, TwoPartyDeriverRole::DeriverB);
        let deriver_a = installation_wire(&journal, TwoPartyDeriverRole::DeriverA, 12, 19, 0x61);
        let first = evaluate_installation_checkpoint(
            None,
            deriver_a,
            &command_a,
            &journal,
            &role_keys(),
            &commitments,
            FRESH_NOW_MS,
        )
        .expect("first role");
        let checkpoint = match first {
            TenantRootCreationInstallationEvaluationV1::Commit { checkpoint, .. } => checkpoint,
            other => panic!("unexpected first outcome: {other:?}"),
        };

        assert!(matches!(
            evaluate_installation_checkpoint(
                Some(checkpoint.clone()),
                installation_wire(&journal, TwoPartyDeriverRole::DeriverA, 12, 19, 0x61,),
                &command_a,
                &journal,
                &role_keys(),
                &commitments,
                EXPIRED_NOW_MS,
            )
            .expect("exact expired retry"),
            TenantRootCreationInstallationEvaluationV1::Replay(
                CloudflareTenantRootCreationInstallationOutcomeV1::WaitingForPeer { .. }
            )
        ));
        assert_eq!(
            evaluate_installation_checkpoint(
                Some(checkpoint),
                installation_wire(&journal, TwoPartyDeriverRole::DeriverB, 19, 12, 0x62,),
                &command_b,
                &journal,
                &role_keys(),
                &commitments,
                EXPIRED_NOW_MS,
            )
            .expect_err("unseen peer evidence after expiry")
            .code(),
            RouterAbProtocolErrorCode::ExpiredLocalRequest
        );
        assert_eq!(
            evaluate_installation_checkpoint(
                None,
                installation_wire(&journal, TwoPartyDeriverRole::DeriverA, 12, 19, 0x61,),
                &command_a,
                &journal,
                &role_keys(),
                &commitments,
                EXPIRED_NOW_MS,
            )
            .expect_err("unseen evidence after expiry")
            .code(),
            RouterAbProtocolErrorCode::ExpiredLocalRequest
        );
    }

    #[test]
    fn request_json_and_base64url_are_strict() {
        let accepted = record(0x21, 0x51, authority(0x44), 1_000, 1_030);
        let value = serde_json::json!({
            "journal_b64u": accepted.journal_b64u,
            "creation_capability_b64u": accepted.creation_capability_b64u,
            "unexpected": true,
        });
        assert!(
            serde_json::from_value::<CloudflareTenantRootCreationJournalRequestV1>(value).is_err()
        );
        assert!(decode_canonical_base64url("journal", "", 1, 1).is_err());
        assert!(decode_canonical_base64url("journal", "AAAA", 1, 4).is_err());
        let key_json = format!(
            "{{\"keys\":[{{\"issuer_key_id\":\"{ISSUER_KEY_ID}\",\"verifying_key_hex\":\"{}\"}}]}}",
            lower_hex(&verifying_key())
        );
        assert_eq!(
            crate::env::decode_issuer_verifying_keys(&key_json)
                .expect("issuer key set")
                .get(ISSUER_KEY_ID),
            Some(&verifying_key())
        );
        let duplicate = format!(
            "{{\"keys\":[{{\"issuer_key_id\":\"{ISSUER_KEY_ID}\",\"verifying_key_hex\":\"{}\"}},{{\"issuer_key_id\":\"{ISSUER_KEY_ID}\",\"verifying_key_hex\":\"{}\"}}]}}",
            lower_hex(&verifying_key()),
            lower_hex(&verifying_key())
        );
        assert!(crate::env::decode_issuer_verifying_keys(&duplicate).is_err());
        let invalid_point_bytes = (0_u8..=u8::MAX)
            .map(|marker| [marker; 32])
            .find(|candidate| ed25519_dalek::VerifyingKey::from_bytes(candidate).is_err())
            .expect("at least one repeated-byte encoding is not an Ed25519 point");
        let invalid_point = format!(
            "{{\"keys\":[{{\"issuer_key_id\":\"{ISSUER_KEY_ID}\",\"verifying_key_hex\":\"{}\"}}]}}",
            lower_hex(&invalid_point_bytes)
        );
        assert!(crate::env::decode_issuer_verifying_keys(&invalid_point).is_err());
    }

    #[test]
    fn private_creation_responses_retain_and_validate_exact_pair() {
        let journal = validate(
            record(0x21, 0x51, authority(0x44), 1_000, 1_030),
            authority(0x44),
        )
        .expect("journal");
        let (_rendezvous, pair) = publish_creation_commitment_pair(&journal, 1_010_000);
        let command_b = role_creation_command(&journal, TwoPartyDeriverRole::DeriverB);
        let candidate = creation_commitment_wire(&journal, TwoPartyDeriverRole::DeriverB, 19);
        let response = commitment_response(
            creation_response_scope(&command_b, &journal).expect("response scope"),
            &candidate,
            CloudflareTenantRootCreationCommitmentOutcomeV1::BothRolesCommitted { pair },
        )
        .expect("commitment response");
        let validated = validate_creation_commitment_response_v1(
            &response,
            &command_b,
            &candidate,
            &role_keys(),
        )
        .expect("validated commitment response");
        match validated {
            CloudflareTenantRootCreationCommitmentOutcomeV1::BothRolesCommitted { pair } => {
                assert_eq!(pair.deriver_b().canonical_bytes(), candidate.as_slice(),);
            }
            other => panic!("unexpected response outcome: {other:?}"),
        }

        let mut wrong_scope = response;
        wrong_scope.identity_digest_b64u = encode_base64url_bytes_v1(&[0xa1; 32]);
        assert_eq!(
            validate_creation_commitment_response_v1(
                &wrong_scope,
                &command_b,
                &candidate,
                &role_keys(),
            )
            .expect_err("wrong response scope")
            .code(),
            RouterAbProtocolErrorCode::MalformedWirePayload
        );
    }

    #[test]
    fn private_request_wires_are_strict_and_installation_response_is_public() {
        let journal = validate(
            record(0x21, 0x51, authority(0x44), 1_000, 1_030),
            authority(0x44),
        )
        .expect("journal");
        let command_a = role_creation_command(&journal, TwoPartyDeriverRole::DeriverA);
        let command_bytes = command_a.canonical_bytes();
        let commitment = creation_commitment_wire(&journal, TwoPartyDeriverRole::DeriverA, 12);
        let commitment_request = CloudflareTenantRootCreationCommitmentRequestV1 {
            role_creation_command_b64u: encode_base64url_bytes_v1(command_bytes),
            signed_commitment_b64u: encode_base64url_bytes_v1(&commitment),
        };
        let mut request_value = serde_json::to_value(commitment_request).expect("request JSON");
        request_value["unexpected"] = serde_json::Value::Bool(true);
        assert!(
            serde_json::from_value::<CloudflareTenantRootCreationCommitmentRequestV1>(
                request_value
            )
            .is_err()
        );

        let evidence = installation_wire(&journal, TwoPartyDeriverRole::DeriverA, 12, 19, 0x61);
        let installation_request = CloudflareTenantRootCreationInstallationRequestV1 {
            role_creation_command_b64u: encode_base64url_bytes_v1(command_bytes),
            signed_evidence_b64u: encode_base64url_bytes_v1(evidence.canonical_bytes()),
        };
        let mut installation_value =
            serde_json::to_value(installation_request).expect("installation request JSON");
        installation_value["unexpected"] = serde_json::Value::Bool(true);
        assert!(
            serde_json::from_value::<CloudflareTenantRootCreationInstallationRequestV1>(
                installation_value
            )
            .is_err()
        );
        let response = installation_response(
            creation_response_scope(&command_a, &journal).expect("response scope"),
            CloudflareTenantRootCreationInstallationOutcomeV1::WaitingForPeer {
                role: CloudflareTenantRootCreationInstallationRoleV1::DeriverA,
            },
        )
        .expect("installation response");
        assert!(matches!(
            validate_installation_response_v1(&response, &command_a, &evidence)
                .expect("validated installation response"),
            CloudflareTenantRootCreationInstallationOutcomeV1::WaitingForPeer {
                role: CloudflareTenantRootCreationInstallationRoleV1::DeriverA,
            }
        ));
    }

    #[test]
    fn role_key_set_retains_exact_role_and_key_id_across_rotation() {
        let previous_a = SigningKey::from_bytes(&[0xa2; 32])
            .verifying_key()
            .to_bytes();
        let current_a = role_signing_key(TwoPartyDeriverRole::DeriverA)
            .verifying_key()
            .to_bytes();
        let current_b = role_signing_key(TwoPartyDeriverRole::DeriverB)
            .verifying_key()
            .to_bytes();
        let key_json = serde_json::json!({
            "active_deriver_a_signing_key_id": "deriver-a-signing-key-7",
            "active_deriver_b_signing_key_id": "deriver-b-signing-key-9",
            "keys": [
                {
                    "role": "deriver_a",
                    "signing_key_id": "deriver-a-signing-key-6",
                    "verifying_key_hex": lower_hex(&previous_a),
                },
                {
                    "role": "deriver_a",
                    "signing_key_id": "deriver-a-signing-key-7",
                    "verifying_key_hex": lower_hex(&current_a),
                },
                {
                    "role": "deriver_b",
                    "signing_key_id": "deriver-b-signing-key-9",
                    "verifying_key_hex": lower_hex(&current_b),
                }
            ]
        })
        .to_string();
        let keys = decode_role_verifying_keys(&key_json).expect("retained role key set");
        assert_eq!(
            keys.for_role_and_key_id(TwoPartyDeriverRole::DeriverA, "deriver-a-signing-key-6",)
                .expect("previous A key"),
            &previous_a
        );
        assert_eq!(
            keys.for_role_and_key_id(TwoPartyDeriverRole::DeriverA, "deriver-a-signing-key-7",)
                .expect("current A key"),
            &current_a
        );
        assert!(keys
            .for_role_and_key_id(TwoPartyDeriverRole::DeriverB, "deriver-a-signing-key-7",)
            .is_err());

        let journal = validate(
            record(0x21, 0x51, authority(0x44), 1_000, 1_030),
            authority(0x44),
        )
        .expect("journal");
        let (_commitment_rendezvous, commitments) =
            publish_creation_commitment_pair(&journal, 1_010_000);
        let command_a = role_creation_command(&journal, TwoPartyDeriverRole::DeriverA);
        let first = evaluate_installation_checkpoint(
            None,
            installation_wire(&journal, TwoPartyDeriverRole::DeriverA, 12, 19, 0x61),
            &command_a,
            &journal,
            &keys,
            &commitments,
            1_010_000,
        )
        .expect("checkpoint signed by retained key");
        let checkpoint = match first {
            TenantRootCreationInstallationEvaluationV1::Commit { checkpoint, .. } => checkpoint,
            other => panic!("unexpected retained-key outcome: {other:?}"),
        };
        validate_installation_checkpoint(checkpoint.clone(), &journal, &keys, &commitments)
            .expect("retained key reload");
        let without_original = role_keys_from_verifiers(
            "deriver-a-signing-key-6",
            previous_a,
            "deriver-b-signing-key-9",
            current_b,
        );
        assert!(validate_installation_checkpoint(
            checkpoint,
            &journal,
            &without_original,
            &commitments
        )
        .is_err());

        let duplicate = serde_json::json!({
            "active_deriver_a_signing_key_id": "deriver-a-signing-key-7",
            "active_deriver_b_signing_key_id": "deriver-b-signing-key-9",
            "keys": [
                {
                    "role": "deriver_a",
                    "signing_key_id": "deriver-a-signing-key-7",
                    "verifying_key_hex": lower_hex(&current_a),
                },
                {
                    "role": "deriver_a",
                    "signing_key_id": "deriver-a-signing-key-7",
                    "verifying_key_hex": lower_hex(&previous_a),
                },
                {
                    "role": "deriver_b",
                    "signing_key_id": "deriver-b-signing-key-9",
                    "verifying_key_hex": lower_hex(&current_b),
                }
            ]
        })
        .to_string();
        assert!(decode_role_verifying_keys(&duplicate).is_err());

        let missing_role = serde_json::json!({
            "active_deriver_a_signing_key_id": "deriver-a-signing-key-7",
            "active_deriver_b_signing_key_id": "deriver-b-signing-key-9",
            "keys": [
                {
                    "role": "deriver_a",
                    "signing_key_id": "deriver-a-signing-key-6",
                    "verifying_key_hex": lower_hex(&previous_a),
                },
                {
                    "role": "deriver_a",
                    "signing_key_id": "deriver-a-signing-key-7",
                    "verifying_key_hex": lower_hex(&current_a),
                }
            ]
        })
        .to_string();
        assert!(decode_role_verifying_keys(&missing_role).is_err());
    }

    #[test]
    fn cutover_do_write_initializes_replays_and_advances_one_revision() {
        let attempt = TenantRootCutoverAttemptIdV1::from_bytes([0x41; 16]).expect("attempt");
        let receipt =
            |seed| TenantRootCutoverReceiptDigestV1::from_bytes([seed; 32]).expect("receipt");
        let prerequisites =
            TenantRootCutoverPrerequisitesV1::new(receipt(1), receipt(2), receipt(3), [0x44; 32])
                .expect("prerequisites");
        let open = TenantRootCutoverOpenV1::new(attempt, prerequisites);
        let open_record = TenantRootCutoverRecordV1::new(open.clone().into());
        let initialized = evaluate_cutover_write(
            None,
            CloudflareTenantRootCutoverWriteRequestV1::Initialize {
                record: open_record.clone(),
            },
        )
        .expect("initialize");
        assert_eq!(
            initialized.outcome,
            CloudflareTenantRootCutoverWriteOutcomeV1::Initialized
        );

        let replayed = evaluate_cutover_write(
            Some(&open_record),
            CloudflareTenantRootCutoverWriteRequestV1::Initialize {
                record: open_record.clone(),
            },
        )
        .expect("replay initialize");
        assert_eq!(
            replayed.outcome,
            CloudflareTenantRootCutoverWriteOutcomeV1::ExactReplay
        );

        let fenced = open
            .fence(
                TenantRootCutoverFenceReceiptV1::new(attempt, receipt(4), 100)
                    .expect("fence receipt"),
            )
            .expect("fenced");
        let fenced_record = TenantRootCutoverRecordV1::new(fenced.into());
        let advanced = evaluate_cutover_write(
            Some(&open_record),
            CloudflareTenantRootCutoverWriteRequestV1::Update {
                expected_revision: 0,
                record: fenced_record.clone(),
            },
        )
        .expect("advance");
        assert_eq!(
            advanced.outcome,
            CloudflareTenantRootCutoverWriteOutcomeV1::Advanced
        );
        assert_eq!(advanced.record, fenced_record);
    }

    #[test]
    fn cutover_do_write_rejects_missing_stale_and_skipped_state() {
        let attempt = TenantRootCutoverAttemptIdV1::from_bytes([0x41; 16]).expect("attempt");
        let receipt =
            |seed| TenantRootCutoverReceiptDigestV1::from_bytes([seed; 32]).expect("receipt");
        let prerequisites =
            TenantRootCutoverPrerequisitesV1::new(receipt(1), receipt(2), receipt(3), [0x44; 32])
                .expect("prerequisites");
        let open = TenantRootCutoverOpenV1::new(attempt, prerequisites);
        let open_record = TenantRootCutoverRecordV1::new(open.clone().into());
        let fenced = open
            .fence(
                TenantRootCutoverFenceReceiptV1::new(attempt, receipt(4), 100)
                    .expect("fence receipt"),
            )
            .expect("fenced");
        let fenced_record = TenantRootCutoverRecordV1::new(fenced.clone().into());

        assert!(evaluate_cutover_write(
            None,
            CloudflareTenantRootCutoverWriteRequestV1::Update {
                expected_revision: 0,
                record: fenced_record.clone(),
            },
        )
        .is_err());
        assert!(evaluate_cutover_write(
            Some(&open_record),
            CloudflareTenantRootCutoverWriteRequestV1::Update {
                expected_revision: 1,
                record: fenced_record,
            },
        )
        .is_err());

        let drained = fenced
            .drain(
                TenantRootCutoverDrainReceiptV1::new(attempt, receipt(5), receipt(6), 200)
                    .expect("drain receipt"),
            )
            .expect("drained");
        let drained_record = TenantRootCutoverRecordV1::new(drained.into());
        assert!(evaluate_cutover_write(
            Some(&open_record),
            CloudflareTenantRootCutoverWriteRequestV1::Update {
                expected_revision: 0,
                record: drained_record,
            },
        )
        .is_err());
    }

    fn lower_hex(bytes: &[u8]) -> String {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        let mut output = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            output.push(DIGITS[(byte >> 4) as usize] as char);
            output.push(DIGITS[(byte & 0x0f) as usize] as char);
        }
        output
    }
}
