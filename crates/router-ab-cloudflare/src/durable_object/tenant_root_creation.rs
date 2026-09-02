use std::collections::BTreeMap;

#[cfg(feature = "workers-rs")]
use std::{cell::RefCell, rc::Rc};

use router_ab_core::{
    evaluate_tenant_root_refresh_commitment_checkpoint_v1,
    resolve_active_tenant_root_pair_binding_v1, verify_tenant_root_creation_evidence_v1,
    verify_tenant_root_refresh_installation_transition_v1, MpcPrfShareCommitmentWireV1,
    RouterAbDerivationError, RouterAbDerivationErrorCode, TenantRootActivationReceiptBindingV1,
    TenantRootActiveRoleBindingV1, TenantRootActiveRoleResolutionV1, TenantRootActiveRoleRowKeyV1,
    TenantRootCeremonyContextV1, TenantRootCeremonyEpochsV1, TenantRootControlPlaneAuthorityIdV1,
    TenantRootCreationCapabilityV1, TenantRootCreationJournalV1, TenantRootCustodyLineageId,
    TenantRootEpochCommitmentsV1, TenantRootIdentityDigestV1, TenantRootIdentityV1,
    TenantRootLifecycleReceiptDigestV1, TenantRootManagedRestoreRoleV1, TenantRootProtocolDigestV1,
    TenantRootRefreshCommitmentCheckpointActiveBindingV1,
    TenantRootRefreshCommitmentCheckpointEvaluationV1,
    TenantRootRefreshCommitmentCheckpointOutcomeV1, TenantRootRefreshCommitmentCheckpointScopeV1,
    TenantRootRefreshCommitmentCheckpointStateV1, TenantRootRefreshCommitmentCheckpointV1,
    TenantRootRoleCreationCommandV1, TenantRootRoleRefreshCommandV1, TenantRootShareEpoch,
    TenantRootSignedActivationReceiptV1, TenantRootSignedCreationCommitmentV1,
    TenantRootSignedRefreshCommitmentV1, TenantRootSignedShareInstallationEvidenceV1,
    TwoPartyDeriverRole, VerifiedTenantRootCreationCapabilityV1,
    VerifiedTenantRootCreationCommitmentPairV1, VerifiedTenantRootCreationCommitmentV1,
    VerifiedTenantRootRefreshCommitmentPairV1, VerifiedTenantRootRefreshCommitmentV1,
    VerifiedTenantRootRoleCreationCommandV1, VerifiedTenantRootRoleRefreshCommandV1,
    VerifiedTenantRootSignedShareInstallationEvidenceWireV1,
    TENANT_ROOT_CREATION_CAPABILITY_MAX_BYTES_V1, TENANT_ROOT_CREATION_JOURNAL_MAX_BYTES_V1,
    TENANT_ROOT_REFRESH_COMMITMENT_CHECKPOINT_MAX_BYTES_V1,
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
};

#[cfg_attr(not(feature = "workers-rs"), allow(dead_code))]
pub(crate) const CLOUDFLARE_TENANT_ROOT_CREATION_JOURNAL_PATH: &str =
    "/router-ab/internal/tenant-root/creation/v1/journal";
#[cfg_attr(not(feature = "workers-rs"), allow(dead_code))]
pub(crate) const CLOUDFLARE_TENANT_ROOT_CREATION_COMMITMENT_RENDEZVOUS_PATH: &str =
    "/router-ab/internal/tenant-root/creation/v1/commitment-rendezvous";
#[cfg_attr(not(feature = "workers-rs"), allow(dead_code))]
pub(crate) const CLOUDFLARE_TENANT_ROOT_CREATION_INSTALLATION_CHECKPOINT_PATH: &str =
    "/router-ab/internal/tenant-root/creation/v1/installation-checkpoint";
#[cfg_attr(not(feature = "workers-rs"), allow(dead_code))]
pub(crate) const TENANT_ROOT_CREATION_JOURNAL_STORAGE_KEY_V1: &str = "creation/v1/journal";
#[cfg_attr(not(feature = "workers-rs"), allow(dead_code))]
pub(crate) const TENANT_ROOT_CREATION_INSTALLATION_CHECKPOINT_STORAGE_KEY_V1: &str =
    "creation/v1/installation-checkpoint";
#[cfg_attr(not(feature = "workers-rs"), allow(dead_code))]
pub(crate) const TENANT_ROOT_CREATION_COMMITMENT_RENDEZVOUS_STORAGE_KEY_V1: &str =
    "creation/v1/commitment-rendezvous";

#[cfg_attr(not(feature = "workers-rs"), allow(dead_code))]
pub(crate) const CLOUDFLARE_TENANT_ROOT_REFRESH_COMMITMENT_CHECKPOINT_PATH: &str =
    "/router-ab/internal/tenant-root/refresh/v1/commitment-checkpoint";
#[cfg_attr(not(feature = "workers-rs"), allow(dead_code))]
pub(crate) const CLOUDFLARE_TENANT_ROOT_REFRESH_INSTALLATION_CHECKPOINT_PATH: &str =
    "/router-ab/internal/tenant-root/refresh/v1/installation-checkpoint";
#[cfg_attr(not(feature = "workers-rs"), allow(dead_code))]
pub(crate) const TENANT_ROOT_REFRESH_ACTIVE_STATE_STORAGE_KEY_V1: &str = "refresh/v1/active-state";
#[cfg_attr(not(feature = "workers-rs"), allow(dead_code))]
pub(crate) const TENANT_ROOT_REFRESH_COMMITMENT_CHECKPOINT_STORAGE_KEY_V1: &str =
    "refresh/v1/commitment-checkpoint";
#[cfg_attr(not(feature = "workers-rs"), allow(dead_code))]
pub(crate) const TENANT_ROOT_REFRESH_INSTALLATION_CHECKPOINT_STORAGE_KEY_V1: &str =
    "refresh/v1/installation-checkpoint";

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
const TENANT_ROOT_REFRESH_CHECKPOINT_MAX_BASE64URL_BYTES_V1: usize =
    base64url_len_for_bytes(TENANT_ROOT_REFRESH_COMMITMENT_CHECKPOINT_MAX_BYTES_V1);
#[cfg(feature = "workers-rs")]
const TENANT_ROOT_ROLE_CREATION_COMMAND_MAX_BASE64URL_BYTES_V1: usize =
    base64url_len_for_bytes(TENANT_ROOT_ROLE_CREATION_COMMAND_MAX_BYTES_V1);
#[cfg(feature = "workers-rs")]
const TENANT_ROOT_ROLE_REFRESH_COMMAND_MAX_BASE64URL_BYTES_V1: usize =
    base64url_len_for_bytes(TENANT_ROOT_ROLE_REFRESH_COMMAND_MAX_BYTES_V1);
const TENANT_ROOT_REFRESH_ACTIVE_RECEIPT_MAX_BYTES_V1: usize = 16 * 1024;
const TENANT_ROOT_REFRESH_ACTIVE_RECEIPT_MAX_BASE64URL_BYTES_V1: usize =
    base64url_len_for_bytes(TENANT_ROOT_REFRESH_ACTIVE_RECEIPT_MAX_BYTES_V1);
#[cfg(feature = "workers-rs")]
const ROUTER_TENANT_ROOT_CREATION_DO_BINDING_V1: &str = "ROUTER_TENANT_ROOT_CREATION_DO";
#[cfg(feature = "workers-rs")]
const TENANT_ROOT_CREATION_REQUEST_MAX_BYTES_V1: usize =
    TENANT_ROOT_CREATION_JOURNAL_MAX_BASE64URL_BYTES_V1
        + TENANT_ROOT_CREATION_CAPABILITY_MAX_BASE64URL_BYTES_V1
        + 128;
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
        + 128;
#[cfg(feature = "workers-rs")]
const TENANT_ROOT_REFRESH_COMMITMENT_RESPONSE_MAX_BYTES_V1: usize =
    TENANT_ROOT_REFRESH_COMMITMENT_MAX_BASE64URL_BYTES_V1 * 2 + 2048;
#[cfg(feature = "workers-rs")]
const TENANT_ROOT_REFRESH_INSTALLATION_RESPONSE_MAX_BYTES_V1: usize = 4096;

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
fn require_tenant_root_creation_authority_object_v1(
    env: &worker::Env,
    authority_object_id: &str,
    identity_digest: TenantRootIdentityDigestV1,
    custody_lineage: TenantRootCustodyLineageId,
) -> RouterAbProtocolResult<()> {
    let namespace = env
        .durable_object(ROUTER_TENANT_ROOT_CREATION_DO_BINDING_V1)
        .map_err(|error| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MissingLocalBinding,
                format!("tenant-root creation Durable Object binding is unavailable: {error}"),
            )
        })?;
    let expected_object_name =
        tenant_root_creation_object_name_v1(identity_digest, custody_lineage);
    let expected_object_id = namespace
        .id_from_name(&expected_object_name)
        .map_err(|error| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                format!("tenant-root creation Durable Object id derivation failed: {error}"),
            )
        })?
        .to_string();
    if expected_object_id != authority_object_id {
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
struct ValidatedTenantRootCreationJournalV1 {
    record: CloudflareTenantRootCreationJournalRecordV1,
    journal: TenantRootCreationJournalV1,
    identity_digest: TenantRootIdentityDigestV1,
    custody_lineage: router_ab_core::TenantRootCustodyLineageId,
    ceremony_context: TenantRootCeremonyContextV1,
    revision: u64,
    journal_digest: TenantRootProtocolDigestV1,
    capability: VerifiedTenantRootCreationCapabilityV1,
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

/// Public operation coordinates retained beside the authoritative active state.
/// The session id is the attempt id; nonce and command digest remain part of the
/// fence so a restarted request cannot silently resume another ceremony.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CloudflareTenantRootRefreshAttemptV1 {
    pub(crate) attempt_id_b64u: String,
    pub(crate) command_digest_b64u: String,
    pub(crate) ceremony_context_digest_b64u: String,
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
/// transitions; this checkpoint slice only advances Open -> Reserved -> Executed.
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
    },
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

#[cfg(feature = "workers-rs")]
#[allow(dead_code)]
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

fn validate_creation_record(
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

    const fn to_protocol(self) -> TwoPartyDeriverRole {
        match self {
            Self::DeriverA => TwoPartyDeriverRole::DeriverA,
            Self::DeriverB => TwoPartyDeriverRole::DeriverB,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum CloudflareTenantRootCreationCommitmentRendezvousStateV1 {
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
struct CloudflareTenantRootCreationCommitmentRendezvousRecordV1 {
    journal_digest_b64u: String,
    identity_digest_b64u: String,
    custody_lineage_b64u: String,
    ceremony_context_digest_b64u: String,
    state: CloudflareTenantRootCreationCommitmentRendezvousStateV1,
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

struct ValidatedTenantRootCreationInstallationCheckpointV1 {
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
            _ => worker::Response::error("Tenant-root creation private route not found", 404),
        }
    }
}

#[cfg(feature = "workers-rs")]
impl RouterAbTenantRootCreationDurableObject {
    async fn load_role_creation_request(
        &self,
        command_b64u: &str,
    ) -> RouterAbProtocolResult<LoadedTenantRootRoleCreationRequestV1> {
        let issuer_keys_json = read_required_worker_var(
            &self.env,
            crate::ROUTER_TENANT_ROOT_CREATION_ISSUER_VERIFYING_KEYS_JSON_ENV,
        )?;
        let issuer_keys = decode_issuer_verifying_keys(&issuer_keys_json)?;
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
            crate::ROUTER_TENANT_ROOT_CREATION_ISSUER_VERIFYING_KEYS_JSON_ENV,
        )?;
        let verifying_keys = decode_issuer_verifying_keys(&verifying_keys_json)?;
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

    /// Persists the public active state only from an already issuer-verified
    /// activation receipt. Checkpoint routes never call this method.
    #[allow(dead_code)]
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
        let issuer_keys_json = read_required_worker_var(
            &self.env,
            crate::ROUTER_TENANT_ROOT_CREATION_ISSUER_VERIFYING_KEYS_JSON_ENV,
        )?;
        let issuer_keys = decode_issuer_verifying_keys(&issuer_keys_json)?;
        let candidate = refresh_active_state_record_from_verified_receipt(
            activation_receipt,
            lifecycle_revision,
        )?;
        let candidate_projection = refresh_active_state_projection(&candidate);
        let outcome: Rc<RefCell<Option<RouterAbProtocolResult<()>>>> = Rc::new(RefCell::new(None));
        let outcome_for_transaction = Rc::clone(&outcome);
        self.storage
            .transaction(move |transaction| async move {
                let existing = match transaction_get_optional::<
                    CloudflareTenantRootRefreshActiveStateRecordV1,
                >(
                    &transaction,
                    TENANT_ROOT_REFRESH_ACTIVE_STATE_STORAGE_KEY_V1,
                )
                .await
                {
                    Ok(existing) => existing,
                    Err(error) => return Err(error),
                };
                let Some(existing) = existing else {
                    transaction
                        .put(
                            TENANT_ROOT_REFRESH_ACTIVE_STATE_STORAGE_KEY_V1,
                            &candidate,
                        )
                        .await?;
                    outcome_for_transaction.replace(Some(Ok(())));
                    return Ok(());
                };
                let existing_validated = match validate_refresh_active_state_record(
                    existing,
                    authority_id,
                    &issuer_keys,
                ) {
                    Ok(value) => value,
                    Err(error) => {
                        outcome_for_transaction.replace(Some(Err(stored_refresh_record_error(error))));
                        return Ok(());
                    }
                };
                let existing_projection =
                    refresh_active_state_projection(&existing_validated.record);
                if existing_projection == candidate_projection {
                    outcome_for_transaction.replace(Some(Ok(())));
                } else {
                    outcome_for_transaction.replace(Some(Err(refresh_replay_conflict(
                        "tenant-root refresh active state conflicts with the accepted activation receipt",
                    ))));
                }
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
            crate::ROUTER_TENANT_ROOT_CREATION_ISSUER_VERIFYING_KEYS_JSON_ENV,
        )?;
        let issuer_keys = decode_issuer_verifying_keys(&issuer_keys_json)?;
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
            crate::ROUTER_TENANT_ROOT_CREATION_ISSUER_VERIFYING_KEYS_JSON_ENV,
        )?;
        let issuer_keys = decode_issuer_verifying_keys(&issuer_keys_json)?;
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
    ) -> RouterAbProtocolResult<LoadedTenantRootRefreshRequestV1> {
        let active = self.load_authoritative_active_refresh_state().await?;
        let issuer_keys_json = read_required_worker_var(
            &self.env,
            crate::ROUTER_TENANT_ROOT_CREATION_ISSUER_VERIFYING_KEYS_JSON_ENV,
        )?;
        let issuer_keys = decode_issuer_verifying_keys(&issuer_keys_json)?;
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
                        let attempt = match refresh_attempt_from_command(&command) {
                            Ok(value) => value,
                            Err(error) => {
                                outcome_for_transaction.replace(Some(Err(error)));
                                return Ok(());
                            }
                        };
                        let fence = match refresh_reserved_fence(&active.record.fence, attempt) {
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
async fn decode_bounded_json_request<T: DeserializeOwned>(
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
fn read_required_worker_var(env: &worker::Env, name: &str) -> RouterAbProtocolResult<String> {
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TenantRootCreationIssuerKeySetWireV1 {
    keys: Vec<TenantRootCreationIssuerKeyWireV1>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TenantRootCreationIssuerKeyWireV1 {
    issuer_key_id: String,
    verifying_key_hex: String,
}

fn decode_issuer_verifying_keys(json: &str) -> RouterAbProtocolResult<BTreeMap<String, [u8; 32]>> {
    let wire: TenantRootCreationIssuerKeySetWireV1 =
        serde_json::from_str(json).map_err(|error| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                format!("tenant-root creation issuer key set JSON is invalid: {error}"),
            )
        })?;
    if wire.keys.is_empty() || wire.keys.len() > 32 {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "tenant-root creation issuer key set must contain between one and 32 keys",
        ));
    }
    let mut keys = BTreeMap::new();
    for entry in wire.keys {
        if !valid_config_key_id(&entry.issuer_key_id) {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "tenant-root creation issuer key id is invalid",
            ));
        }
        let verifying_key = decode_lower_hex_32(
            "tenant-root creation issuer verifying key",
            &entry.verifying_key_hex,
        )?;
        ed25519_dalek::VerifyingKey::from_bytes(&verifying_key).map_err(|_| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "tenant-root creation issuer verifying key is not a valid Ed25519 point",
            )
        })?;
        if keys.insert(entry.issuer_key_id, verifying_key).is_some() {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "tenant-root creation issuer key id is duplicated",
            ));
        }
    }
    Ok(keys)
}

fn valid_config_key_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

#[cfg_attr(not(feature = "workers-rs"), allow(dead_code))]
fn decode_lower_hex_32(field: &str, value: &str) -> RouterAbProtocolResult<[u8; 32]> {
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

fn decode_canonical_base64url(
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
    validate_refresh_fence(&record.fence)?;
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

fn validate_refresh_fence(
    fence: &CloudflareTenantRootRefreshFenceV1,
) -> RouterAbProtocolResult<()> {
    let attempt = match fence {
        CloudflareTenantRootRefreshFenceV1::Open => return Ok(()),
        CloudflareTenantRootRefreshFenceV1::Reserved { attempt }
        | CloudflareTenantRootRefreshFenceV1::Executed { attempt }
        | CloudflareTenantRootRefreshFenceV1::Terminal { attempt, .. } => attempt,
    };
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

fn refresh_attempt_from_command(
    command: &VerifiedTenantRootRoleRefreshCommandV1,
) -> RouterAbProtocolResult<CloudflareTenantRootRefreshAttemptV1> {
    Ok(CloudflareTenantRootRefreshAttemptV1 {
        attempt_id_b64u: encode_base64url_bytes_v1(command.session_id().as_bytes()),
        command_digest_b64u: encode_base64url_bytes_v1(command.digest().as_bytes()),
        ceremony_context_digest_b64u: encode_base64url_bytes_v1(
            command.refresh_context_digest().as_bytes(),
        ),
        session_id_b64u: encode_base64url_bytes_v1(command.session_id().as_bytes()),
        nonce_b64u: encode_base64url_bytes_v1(command.nonce().as_bytes()),
        current_epoch: command.current_epoch().get().get(),
        next_epoch: command.next_epoch().get().get(),
        expected_control_plane_revision: command.expected_control_plane_revision(),
    })
}

fn require_refresh_attempt_matches_command(
    attempt: &CloudflareTenantRootRefreshAttemptV1,
    command: &VerifiedTenantRootRoleRefreshCommandV1,
) -> RouterAbProtocolResult<()> {
    let mut expected = refresh_attempt_from_command(command)?;
    // Each role has its own signed command digest; session/context coordinates
    // identify the shared operation while checkpoint records retain both digests.
    expected.command_digest_b64u = attempt.command_digest_b64u.clone();
    if attempt != &expected {
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
    attempt: CloudflareTenantRootRefreshAttemptV1,
) -> RouterAbProtocolResult<CloudflareTenantRootRefreshFenceV1> {
    match fence {
        CloudflareTenantRootRefreshFenceV1::Open
        | CloudflareTenantRootRefreshFenceV1::Reserved { .. } => {
            Ok(CloudflareTenantRootRefreshFenceV1::Reserved { attempt })
        }
        CloudflareTenantRootRefreshFenceV1::Executed { .. }
        | CloudflareTenantRootRefreshFenceV1::Terminal { .. } => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ConflictingPair,
            "tenant-root refresh operation has passed its commitment checkpoint",
        )),
    }
}

fn refresh_executed_fence(
    fence: &CloudflareTenantRootRefreshFenceV1,
    attempt: CloudflareTenantRootRefreshAttemptV1,
) -> RouterAbProtocolResult<CloudflareTenantRootRefreshFenceV1> {
    match fence {
        CloudflareTenantRootRefreshFenceV1::Reserved { .. }
        | CloudflareTenantRootRefreshFenceV1::Executed { .. } => {
            Ok(CloudflareTenantRootRefreshFenceV1::Executed { attempt })
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
    now_ms: u64,
) -> RouterAbProtocolResult<TenantRootRefreshInstallationCheckpointEvaluationV1> {
    require_refresh_fence_matches_command(&active.record.fence, command)?;
    let scope = refresh_checkpoint_scope(command, active, context, expected_authority_id)?;
    let encoded_candidate = encode_base64url_bytes_v1(candidate_bytes);
    let candidate =
        validate_refresh_installation_evidence_candidate(&encoded_candidate, context, role_keys)?;
    if candidate.evidence().transcript().role() != command.role() {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ForbiddenLocalBinding,
            "tenant-root refresh installation evidence role does not match its command",
        ));
    }
    let candidate_role = candidate.evidence().transcript().role();
    let candidate_command_digest = command.digest();
    let attempt = refresh_attempt_from_command(command)?;
    let Some(existing) = existing else {
        require_fresh_refresh_command(command, context, now_ms)?;
        let checkpoint = refresh_installation_checkpoint_record(
            scope,
            CloudflareTenantRootRefreshInstallationCheckpointStateV1::OneRoleReady {
                role: CloudflareTenantRootCreationInstallationRoleV1::from_protocol(candidate_role),
                command_digest_b64u: encode_base64url_bytes_v1(candidate_command_digest.as_bytes()),
                signed_evidence_b64u: encoded_candidate,
            },
        );
        let fence = refresh_executed_fence(&active.record.fence, attempt)?;
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
            require_fresh_refresh_command(command, context, now_ms)?;
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
            let fence = refresh_executed_fence(&active.record.fence, attempt)?;
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

#[cfg(feature = "workers-rs")]
#[allow(dead_code)]
pub(crate) async fn execute_cloudflare_router_tenant_root_refresh_installation_call_v1(
    env: &worker::Env,
    command: &VerifiedTenantRootRoleRefreshCommandV1,
    evidence: &VerifiedTenantRootSignedShareInstallationEvidenceWireV1,
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
    use curve25519_dalek::scalar::Scalar;
    use ed25519_dalek::SigningKey;
    use rand_chacha::ChaCha20Rng;
    use rand_core_06::SeedableRng;
    use router_ab_core::{
        TenantRootCeremonyContextV1, TenantRootCeremonyEpochsV1, TenantRootCeremonyNonceV1,
        TenantRootCeremonySessionIdV1, TenantRootCreationCapabilityNonceV1,
        TenantRootCreationCommitmentTranscriptV1, TenantRootCustodyLineageId,
        TenantRootRefreshCommitmentTranscriptV1, TenantRootShareInstallationEvidenceV1,
        TenantRootShareInstallationTranscriptV1,
    };
    use threshold_prf::{
        prove_root_share_knowledge, RootShareRefreshCoefficient, SigningRootShare,
        SigningRootShareCommitment,
    };

    const ISSUER_KEY_ID: &str = "tenant-root-creation-issuer-v1";
    const SIGNING_KEY_BYTES: [u8; 32] = [0x71; 32];
    const DERIVER_A_SIGNING_KEY_BYTES: [u8; 32] = [0xa1; 32];
    const DERIVER_B_SIGNING_KEY_BYTES: [u8; 32] = [0xb1; 32];
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
        let transcript =
            TenantRootRefreshCommitmentTranscriptV1::new(context.clone(), coefficient.commitment())
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
    fn refresh_installation_checkpoint_rejects_role_commitment_substitutions() {
        let mut active = validated_active_refresh_state();
        let context = refresh_context(&active);
        let commitments = refresh_commitment_pair(&context);
        let command_a = refresh_command(&active, &context, TwoPartyDeriverRole::DeriverA);
        let command_b = refresh_command(&active, &context, TwoPartyDeriverRole::DeriverB);
        active.record.fence = refresh_reserved_fence(
            &active.record.fence,
            refresh_attempt_from_command(&command_a).expect("refresh attempt"),
        )
        .expect("reserved refresh fence");

        // Active shares are 12 and 19; coefficients 7 and 11 produce next shares 30 and 55.
        let exact_a =
            refresh_installation_wire(&context, TwoPartyDeriverRole::DeriverA, 30, 55, 0x61);
        let exact_b =
            refresh_installation_wire(&context, TwoPartyDeriverRole::DeriverB, 55, 30, 0x62);
        let first = evaluate_refresh_installation_checkpoint(
            None,
            exact_a.canonical_bytes(),
            &command_a,
            &active,
            &context,
            &role_keys(),
            &commitments,
            authority(0x71),
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
            let first = evaluate_refresh_installation_checkpoint(
                None,
                substituted_a.canonical_bytes(),
                &command_a,
                &active,
                &context,
                &role_keys(),
                &commitments,
                authority(0x71),
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
            let error = evaluate_refresh_installation_checkpoint(
                Some(first_checkpoint),
                substituted_b.canonical_bytes(),
                &command_b,
                &active,
                &context,
                &role_keys(),
                &commitments,
                authority(0x71),
                1_000_100,
            )
            .err()
            .expect("substituted role commitment must conflict at pair completion");
            assert_eq!(error.code(), RouterAbProtocolErrorCode::ConflictingPair);
        }
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
            decode_issuer_verifying_keys(&key_json)
                .expect("issuer key set")
                .get(ISSUER_KEY_ID),
            Some(&verifying_key())
        );
        let duplicate = format!(
            "{{\"keys\":[{{\"issuer_key_id\":\"{ISSUER_KEY_ID}\",\"verifying_key_hex\":\"{}\"}},{{\"issuer_key_id\":\"{ISSUER_KEY_ID}\",\"verifying_key_hex\":\"{}\"}}]}}",
            lower_hex(&verifying_key()),
            lower_hex(&verifying_key())
        );
        assert!(decode_issuer_verifying_keys(&duplicate).is_err());
        let invalid_point_bytes = (0_u8..=u8::MAX)
            .map(|marker| [marker; 32])
            .find(|candidate| ed25519_dalek::VerifyingKey::from_bytes(candidate).is_err())
            .expect("at least one repeated-byte encoding is not an Ed25519 point");
        let invalid_point = format!(
            "{{\"keys\":[{{\"issuer_key_id\":\"{ISSUER_KEY_ID}\",\"verifying_key_hex\":\"{}\"}}]}}",
            lower_hex(&invalid_point_bytes)
        );
        assert!(decode_issuer_verifying_keys(&invalid_point).is_err());
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
