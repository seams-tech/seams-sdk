use crate::authenticate_local_ed25519_yao_deriver_b_peer_http_v1;
use crate::local_ed25519_yao_pair::verify_local_pair_readiness_receipt_v1;
use crate::local_ed25519_yao_refresh::LocalEd25519YaoEffectiveIdentityV1;
use crate::local_ed25519_yao_signing_worker::LocalEd25519YaoSigningWorkerDurableStateV1;
use crate::local_ed25519_yao_stream::{
    authenticate_local_ed25519_yao_deriver_b_peer_http_with_pair_v2,
    connect_local_deriver_a_pair_http_v2, open_local_deriver_b_target_proof_v2,
    run_local_activation_deriver_a_pair_connected_v2,
    run_local_activation_deriver_b_authenticated_http_open_v2,
    run_local_export_deriver_a_pair_connected_v2,
    run_local_export_deriver_b_authenticated_http_open_v2, seal_local_deriver_a_target_proof_v2,
    seal_local_deriver_b_target_proof_v2,
};
use crate::{
    build_local_activation_deriver_a_with_server_v1,
    build_local_activation_deriver_b_with_server_v1, build_local_export_deriver_a_with_server_v1,
    build_local_export_deriver_b_with_server_v1, build_local_refresh_deriver_a_v1,
    build_local_refresh_deriver_b_v1, complete_local_deriver_a_target_v2,
    complete_local_deriver_b_target_v2, derive_local_ed25519_yao_joint_refresh_delta_v1,
    generate_local_ed25519_yao_deriver_a_refresh_delta_v1,
    generate_local_ed25519_yao_deriver_b_refresh_delta_v1, local_dev_http_error_body_v1,
    local_ed25519_yao_refresh_binding_digest_v1, local_router_ab_internal_service_auth_secret_v1,
    local_tenant_root_coordinates_for_context_v1,
    open_local_ed25519_yao_activation_deriver_a_input_v1,
    open_local_ed25519_yao_activation_deriver_b_input_v1,
    open_local_ed25519_yao_export_deriver_a_input_v1,
    open_local_ed25519_yao_export_deriver_b_input_v1,
    open_local_ed25519_yao_refresh_deriver_a_input_v1,
    open_local_ed25519_yao_refresh_deriver_b_input_v1, prepare_local_deriver_a_target_v2,
    prepare_local_deriver_b_target_v2, read_local_dev_http_request_v1,
    require_local_dev_internal_service_auth_v1, run_local_activation_deriver_a_http_v1,
    run_local_activation_deriver_b_authenticated_http_v1, seal_local_ed25519_yao_package_v1,
    write_local_dev_http_response_v1, Ed25519YaoDeriverRoleV1, Ed25519YaoEncryptedInputV1,
    Ed25519YaoEncryptedPackageV1, Ed25519YaoPackageKindV1,
    LocalEd25519YaoActivationDeriverARequestV1, LocalEd25519YaoActivationDeriverBRequestV1,
    LocalEd25519YaoActivationRecipientsV1, LocalEd25519YaoDeriverAEffectiveStateV1,
    LocalEd25519YaoDeriverAPreparedRefreshV1, LocalEd25519YaoDeriverARefreshDeltaWireV1,
    LocalEd25519YaoDeriverBEffectiveStateV1, LocalEd25519YaoDeriverBPreparedRefreshV1,
    LocalEd25519YaoDeriverBRefreshDeltaWireV1, LocalEd25519YaoEncryptedRefreshInputV1,
    LocalEd25519YaoExportRecipientV1, LocalEd25519YaoRecipientPrivateKeyV1,
    LocalEd25519YaoRefreshDeriverBRequestV1, LocalEd25519YaoSigningWorkerPackagePairDeliveryV1,
    LocalEd25519YaoSigningWorkerRecoveryPromotionRequestV1,
    LocalEd25519YaoSigningWorkerRefreshPackageDeliveryV1, LocalEd25519YaoSigningWorkerStateV1,
    LocalWorkerRoleConfigV1, LOCAL_DERIVER_A_ED25519_YAO_BURN_PAIR_PATH,
    LOCAL_DERIVER_A_ED25519_YAO_EXECUTE_PAIR_PATH, LOCAL_DERIVER_A_ED25519_YAO_PREPARE_PAIR_PATH,
    LOCAL_DERIVER_A_ED25519_YAO_READ_PAIR_STATUS_PATH,
    LOCAL_DERIVER_A_ED25519_YAO_REFRESH_CLIENT_PACKAGE_PATH,
    LOCAL_DERIVER_A_ED25519_YAO_REFRESH_PROMOTE_PATH,
    LOCAL_DERIVER_A_ED25519_YAO_REFRESH_SIGNING_WORKER_PACKAGE_PATH,
    LOCAL_DERIVER_A_ED25519_YAO_REFRESH_START_PATH, LOCAL_DERIVER_B_ED25519_YAO_BURN_PAIR_PATH,
    LOCAL_DERIVER_B_ED25519_YAO_PEER_PATH, LOCAL_DERIVER_B_ED25519_YAO_PREPARE_PAIR_PATH,
    LOCAL_DERIVER_B_ED25519_YAO_READ_PAIR_STATUS_PATH,
    LOCAL_DERIVER_B_ED25519_YAO_REFRESH_CLIENT_PACKAGE_PATH,
    LOCAL_DERIVER_B_ED25519_YAO_REFRESH_DELTA_PATH,
    LOCAL_DERIVER_B_ED25519_YAO_REFRESH_PROMOTE_PATH,
    LOCAL_DERIVER_B_ED25519_YAO_REFRESH_RESULT_PATH,
    LOCAL_DERIVER_B_ED25519_YAO_REFRESH_SIGNING_WORKER_PACKAGE_PATH,
    LOCAL_DERIVER_B_ED25519_YAO_REFRESH_STAGE_PATH, LOCAL_HTTP_SERVICE_BINDING_TIMEOUT_MS_V1,
    LOCAL_ROUTER_AB_INTERNAL_SERVICE_AUTH_HEADER_V1,
    LOCAL_SIGNING_WORKER_ED25519_YAO_ACTIVATION_PACKAGES_PATH,
    LOCAL_SIGNING_WORKER_ED25519_YAO_RECOVERY_PROMOTE_PATH,
    LOCAL_SIGNING_WORKER_ED25519_YAO_REFRESH_DERIVER_A_PATH,
    LOCAL_SIGNING_WORKER_ED25519_YAO_REFRESH_DERIVER_B_PATH,
    LOCAL_SIGNING_WORKER_NORMAL_SIGNING_PATH, LOCAL_SIGNING_WORKER_NORMAL_SIGNING_PREPARE_PATH,
};
use crate::{LocalEd25519YaoPairLifecycleV1, LocalEd25519YaoPairSigningKeysV1};
use base64::Engine as _;
use router_ab_core::{
    ed25519_yao_encrypted_input_digest_v1, Ed25519YaoCeremonyBindingV1, Ed25519YaoExecutionIdV1,
    Ed25519YaoOperationV1, Ed25519YaoRefreshBindingV1, Ed25519YaoRoleSignatureSchemeV1,
    Ed25519YaoRoleStartAcceptanceV1, Ed25519YaoSessionIdV1, Ed25519YaoStateEpochV1,
    LocalServiceRoleV1, PublicDigest32, RouterAbProtocolError, RouterAbProtocolErrorCode,
    RouterAbProtocolResult,
};
use router_ab_ed25519_yao::relay::{ActivationDeriverACompletion, ActivationDeriverBCompletion};
use router_ab_ed25519_yao::{
    ActivationDeriverA, ActivationDeriverB, Ed25519YaoActivationRoleExecutionV1,
    Ed25519YaoExportRoleExecutionV1, Ed25519YaoRoleExecutionV1,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::Digest;
use signer_core::ed25519_yao_derivation::{
    Ed25519YaoDeriverAServerContributionV1, Ed25519YaoDeriverBServerContributionV1,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{self, Read, Write},
    net::{Shutdown, TcpStream},
    thread,
    time::Duration,
};
use zeroize::{Zeroize, Zeroizing};

use router_ab_cloudflare::{
    CloudflareEd25519YaoPairExecuteRequestV1, CloudflareEd25519YaoPairExecuteResponseV1,
    CloudflareEd25519YaoPairLookupRequestV1, CloudflareEd25519YaoPairPrepareRequestV1,
    CloudflareEd25519YaoPairStatusResponseV1,
};

enum PendingDeriverBRoleV1 {
    Refresh {
        binding: Ed25519YaoRefreshBindingV1,
        binding_digest: [u8; 32],
        recipients: LocalEd25519YaoActivationRecipientsV1,
        prepared: LocalEd25519YaoDeriverBPreparedRefreshV1,
        role: ActivationDeriverB,
    },
}

impl PendingDeriverBRoleV1 {
    fn session(&self) -> [u8; 32] {
        match self {
            Self::Refresh { binding, .. } => binding.ceremony().session_id.into_bytes(),
        }
    }
}

enum CompletedDeriverBRoleV1 {
    Refresh {
        binding: Ed25519YaoRefreshBindingV1,
        binding_digest: [u8; 32],
        packages: EncryptedActivationPackagesV1,
        promotion: DeriverBRefreshPromotionStateV1,
        completion: Box<ActivationDeriverBCompletion>,
    },
}

enum CompletedDeriverARoleV1 {
    Refresh {
        binding: Ed25519YaoRefreshBindingV1,
        binding_digest: [u8; 32],
        packages: EncryptedActivationPackagesV1,
        promotion: DeriverARefreshPromotionStateV1,
    },
}

struct EncryptedActivationPackagesV1 {
    client: Ed25519YaoEncryptedPackageV1,
    signing_worker: Ed25519YaoEncryptedPackageV1,
}

enum DeriverARefreshPromotionStateV1 {
    Prepared(LocalEd25519YaoDeriverAPreparedRefreshV1),
    Promoted(LocalEd25519YaoRefreshPromotionReceiptV1),
}

enum DeriverBRefreshPromotionStateV1 {
    Prepared(LocalEd25519YaoDeriverBPreparedRefreshV1),
    Promoted(LocalEd25519YaoRefreshPromotionReceiptV1),
}

struct StagedDeriverBRefreshV1 {
    request: LocalEd25519YaoRefreshDeriverBRequestV1,
    binding_digest: [u8; 32],
    delta: LocalEd25519YaoDeriverBRefreshDeltaWireV1,
}

/// Persisted admission state for one role-owned pair lifecycle.
///
/// The encrypted input remains opaque at this boundary. Decryption and role
/// execution stay in the role worker that owns the corresponding private key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum LocalEd25519YaoPairRoleRecordV1 {
    Prepared {
        session: [u8; 32],
        pair_digest: [u8; 32],
        pair_binding: Box<router_ab_core::Ed25519YaoInputPairBindingV1>,
        tenant_root: Box<router_ab_cloudflare::CloudflareEd25519YaoTenantRootContextV2>,
        input_digest: [u8; 32],
        root_metadata_digest: [u8; 32],
        expires_at_ms: u64,
        input: Box<Ed25519YaoEncryptedInputV1>,
        receipt: Box<router_ab_core::Ed25519YaoRoleReadinessReceiptV1>,
    },
    Running {
        session: [u8; 32],
        pair_digest: [u8; 32],
        pair_binding: Box<router_ab_core::Ed25519YaoInputPairBindingV1>,
        tenant_root: Box<router_ab_cloudflare::CloudflareEd25519YaoTenantRootContextV2>,
        input_digest: [u8; 32],
        root_metadata_digest: [u8; 32],
        expires_at_ms: u64,
        execution_id: [u8; 32],
        input: Box<Ed25519YaoEncryptedInputV1>,
        receipt: Box<router_ab_core::Ed25519YaoRoleReadinessReceiptV1>,
    },
    Completed {
        session: [u8; 32],
        pair_digest: [u8; 32],
        pair_binding: Box<router_ab_core::Ed25519YaoInputPairBindingV1>,
        execution_id: [u8; 32],
        execution: Box<Ed25519YaoRoleExecutionV1>,
    },
    Expired {
        session: [u8; 32],
        pair_digest: [u8; 32],
    },
    Burned {
        session: [u8; 32],
        pair_digest: [u8; 32],
    },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalEd25519YaoRefreshDeltaExchangeRequestV1 {
    deriver_a_delta: LocalEd25519YaoDeriverARefreshDeltaWireV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalEd25519YaoRefreshPromotionRequestV1 {
    pub binding_digest: [u8; 32],
    pub session: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalEd25519YaoRefreshPromotionReceiptV1 {
    pub state_epoch: Ed25519YaoStateEpochV1,
}

#[derive(Default)]
pub struct LocalEd25519YaoWorkerStateV1 {
    pending_deriver_b: Option<PendingDeriverBRoleV1>,
    staged_deriver_b_refresh: Option<StagedDeriverBRefreshV1>,
    completed_deriver_a: Option<CompletedDeriverARoleV1>,
    completed_deriver_b: Option<CompletedDeriverBRoleV1>,
    deriver_a_effective:
        BTreeMap<LocalEd25519YaoEffectiveIdentityV1, LocalEd25519YaoDeriverAEffectiveStateV1>,
    deriver_b_effective:
        BTreeMap<LocalEd25519YaoEffectiveIdentityV1, LocalEd25519YaoDeriverBEffectiveStateV1>,
    consumed_deriver_a_sessions: BTreeSet<[u8; 32]>,
    consumed_deriver_b_sessions: BTreeSet<[u8; 32]>,
    pair_roles: BTreeMap<[u8; 32], LocalEd25519YaoPairRoleRecordV1>,
    signing_worker: LocalEd25519YaoSigningWorkerStateV1,
}

const LOCAL_ED25519_YAO_DURABLE_STATE_VERSION_V1: &str =
    "local_ed25519_yao_worker_durable_state_v1";

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct LocalEd25519YaoDurableStateEnvelopeRefV1<'state> {
    version: &'static str,
    state: LocalEd25519YaoDurableRoleStateRefV1<'state>,
}

#[derive(Serialize)]
#[serde(tag = "role", rename_all = "snake_case", deny_unknown_fields)]
enum LocalEd25519YaoDurableRoleStateRefV1<'state> {
    DeriverA {
        effective: Vec<&'state LocalEd25519YaoDeriverAEffectiveStateV1>,
        pair_roles: Vec<&'state LocalEd25519YaoPairRoleRecordV1>,
    },
    DeriverB {
        effective: Vec<&'state LocalEd25519YaoDeriverBEffectiveStateV1>,
        pair_roles: Vec<&'state LocalEd25519YaoPairRoleRecordV1>,
    },
    SigningWorker {
        active: LocalEd25519YaoSigningWorkerDurableStateV1,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalEd25519YaoDurableStateEnvelopeV1 {
    version: String,
    state: LocalEd25519YaoDurableRoleStateV1,
}

#[derive(Deserialize)]
#[serde(tag = "role", rename_all = "snake_case", deny_unknown_fields)]
enum LocalEd25519YaoDurableRoleStateV1 {
    DeriverA {
        effective: Vec<LocalEd25519YaoDeriverAEffectiveStateV1>,
        #[serde(default)]
        pair_roles: Vec<LocalEd25519YaoPairRoleRecordV1>,
    },
    DeriverB {
        effective: Vec<LocalEd25519YaoDeriverBEffectiveStateV1>,
        #[serde(default)]
        pair_roles: Vec<LocalEd25519YaoPairRoleRecordV1>,
    },
    SigningWorker {
        active: LocalEd25519YaoSigningWorkerDurableStateV1,
    },
}

impl LocalEd25519YaoWorkerStateV1 {
    pub fn encode_durable_state_for_role_v1(
        &self,
        role: LocalServiceRoleV1,
    ) -> RouterAbProtocolResult<Vec<u8>> {
        let state = match role {
            LocalServiceRoleV1::DeriverA => LocalEd25519YaoDurableRoleStateRefV1::DeriverA {
                effective: self.deriver_a_effective.values().collect(),
                pair_roles: self.pair_roles.values().collect(),
            },
            LocalServiceRoleV1::DeriverB => LocalEd25519YaoDurableRoleStateRefV1::DeriverB {
                effective: self.deriver_b_effective.values().collect(),
                pair_roles: self.pair_roles.values().collect(),
            },
            LocalServiceRoleV1::SigningWorker => {
                LocalEd25519YaoDurableRoleStateRefV1::SigningWorker {
                    active: self.signing_worker.durable_state_v1(),
                }
            }
            LocalServiceRoleV1::Router => {
                return Err(invalid_worker_state(
                    "Router does not own local Ed25519 Yao secret state",
                ));
            }
        };
        serde_json::to_vec(&LocalEd25519YaoDurableStateEnvelopeRefV1 {
            version: LOCAL_ED25519_YAO_DURABLE_STATE_VERSION_V1,
            state,
        })
        .map_err(|_| invalid_worker_state("local Ed25519 Yao durable state encoding failed"))
    }

    pub fn decode_durable_state_for_role_v1(
        role: LocalServiceRoleV1,
        bytes: &[u8],
    ) -> RouterAbProtocolResult<Self> {
        let decoded = serde_json::from_slice::<LocalEd25519YaoDurableStateEnvelopeV1>(bytes)
            .map_err(|_| invalid_worker_state("local Ed25519 Yao durable state is malformed"))?;
        if decoded.version != LOCAL_ED25519_YAO_DURABLE_STATE_VERSION_V1 {
            return Err(invalid_worker_state(
                "local Ed25519 Yao durable state version is unsupported",
            ));
        }
        let mut restored = Self::default();
        match (role, decoded.state) {
            (
                LocalServiceRoleV1::DeriverA,
                LocalEd25519YaoDurableRoleStateV1::DeriverA {
                    effective,
                    pair_roles,
                },
            ) => {
                for state in effective {
                    state.identity().validate_persisted_v1()?;
                    let identity = state.identity().clone();
                    if restored
                        .deriver_a_effective
                        .insert(identity, state)
                        .is_some()
                    {
                        return Err(invalid_worker_state(
                            "persisted Deriver A state contains a duplicate Yao identity",
                        ));
                    }
                }
                restored.pair_roles =
                    decode_pair_role_records(LocalServiceRoleV1::DeriverA, pair_roles)?;
            }
            (
                LocalServiceRoleV1::DeriverB,
                LocalEd25519YaoDurableRoleStateV1::DeriverB {
                    effective,
                    pair_roles,
                },
            ) => {
                for state in effective {
                    state.identity().validate_persisted_v1()?;
                    let identity = state.identity().clone();
                    if restored
                        .deriver_b_effective
                        .insert(identity, state)
                        .is_some()
                    {
                        return Err(invalid_worker_state(
                            "persisted Deriver B state contains a duplicate Yao identity",
                        ));
                    }
                }
                restored.pair_roles =
                    decode_pair_role_records(LocalServiceRoleV1::DeriverB, pair_roles)?;
            }
            (
                LocalServiceRoleV1::SigningWorker,
                LocalEd25519YaoDurableRoleStateV1::SigningWorker { active },
            ) => {
                restored.signing_worker =
                    LocalEd25519YaoSigningWorkerStateV1::from_durable_state_v1(active)?;
            }
            (LocalServiceRoleV1::Router, _) => {
                return Err(invalid_worker_state(
                    "Router does not own local Ed25519 Yao secret state",
                ));
            }
            _ => {
                return Err(invalid_worker_state(
                    "local Ed25519 Yao durable state belongs to a different worker role",
                ));
            }
        }
        Ok(restored)
    }
}

fn decode_pair_role_records(
    role: LocalServiceRoleV1,
    records: Vec<LocalEd25519YaoPairRoleRecordV1>,
) -> RouterAbProtocolResult<BTreeMap<[u8; 32], LocalEd25519YaoPairRoleRecordV1>> {
    let mut decoded = BTreeMap::new();
    for record in records {
        validate_pair_role_record(role, &record)?;
        let pair_digest = pair_role_record_digest(&record);
        if pair_digest.iter().all(|byte| *byte == 0)
            || decoded.insert(pair_digest, record).is_some()
        {
            return Err(invalid_worker_state(
                "persisted pair lifecycle contains a duplicate or empty identity",
            ));
        }
    }
    Ok(decoded)
}

fn validate_pair_role_record(
    role: LocalServiceRoleV1,
    record: &LocalEd25519YaoPairRoleRecordV1,
) -> RouterAbProtocolResult<()> {
    match record {
        LocalEd25519YaoPairRoleRecordV1::Prepared {
            session,
            pair_digest,
            pair_binding,
            tenant_root,
            input_digest,
            root_metadata_digest,
            expires_at_ms,
            input,
            receipt,
        } => {
            if session.iter().all(|byte| *byte == 0)
                || pair_digest.iter().all(|byte| *byte == 0)
                || input_digest.iter().all(|byte| *byte == 0)
                || root_metadata_digest.iter().all(|byte| *byte == 0)
                || *expires_at_ms == 0
            {
                return Err(invalid_worker_state(
                    "persisted pair preparation has an empty identity or time",
                ));
            }
            input.validate()?;
            pair_binding.validate()?;
            tenant_root.validate_for_pair(pair_binding)?;
            if input.session() != *session
                || pair_binding.session() != *session
                || pair_binding.pair_digest().bytes != *pair_digest
                || receipt.session().into_bytes() != *session
                || receipt.pair_digest().bytes != *pair_digest
                || receipt.local_input_digest().bytes != *input_digest
                || receipt.root_metadata_digest().bytes != *root_metadata_digest
                || local_pair_tenant_root_metadata_digest_v1(tenant_root)? != *root_metadata_digest
                || ((role == LocalServiceRoleV1::DeriverA
                    && receipt.role() != Ed25519YaoDeriverRoleV1::DeriverA)
                    || (role == LocalServiceRoleV1::DeriverB
                        && receipt.role() != Ed25519YaoDeriverRoleV1::DeriverB))
            {
                return Err(invalid_worker_state(
                    "persisted pair preparation identity does not match its receipt",
                ));
            }
        }
        LocalEd25519YaoPairRoleRecordV1::Running {
            session,
            pair_digest,
            pair_binding,
            tenant_root,
            input_digest,
            root_metadata_digest,
            expires_at_ms,
            execution_id,
            input,
            receipt,
        } => {
            if session.iter().all(|byte| *byte == 0)
                || pair_digest.iter().all(|byte| *byte == 0)
                || input_digest.iter().all(|byte| *byte == 0)
                || root_metadata_digest.iter().all(|byte| *byte == 0)
                || expires_at_ms == &0
                || execution_id.iter().all(|byte| *byte == 0)
            {
                return Err(invalid_worker_state(
                    "persisted running pair has an empty identity or time",
                ));
            }
            input.validate()?;
            pair_binding.validate()?;
            tenant_root.validate_for_pair(pair_binding)?;
            if input.session() != *session
                || pair_binding.session() != *session
                || pair_binding.pair_digest().bytes != *pair_digest
                || receipt.session_bytes() != *session
                || receipt.pair_digest().bytes != *pair_digest
                || receipt.local_input_digest().bytes != *input_digest
                || receipt.root_metadata_digest().bytes != *root_metadata_digest
                || local_pair_tenant_root_metadata_digest_v1(tenant_root)? != *root_metadata_digest
                || ((role == LocalServiceRoleV1::DeriverA
                    && receipt.role() != Ed25519YaoDeriverRoleV1::DeriverA)
                    || (role == LocalServiceRoleV1::DeriverB
                        && receipt.role() != Ed25519YaoDeriverRoleV1::DeriverB))
            {
                return Err(invalid_worker_state(
                    "persisted running pair identity does not match its receipt",
                ));
            }
        }
        LocalEd25519YaoPairRoleRecordV1::Completed {
            session,
            pair_digest,
            pair_binding,
            execution_id,
            execution,
        } => {
            if session.iter().all(|byte| *byte == 0)
                || pair_digest.iter().all(|byte| *byte == 0)
                || execution_id.iter().all(|byte| *byte == 0)
            {
                return Err(invalid_worker_state(
                    "persisted completed pair has an empty identity",
                ));
            }
            execution.validate()?;
            pair_binding.validate()?;
            if execution.session() != *session
                || pair_binding.session() != *session
                || pair_binding.pair_digest().bytes != *pair_digest
                || !completed_execution_matches_pair_v1(execution, pair_binding)
                || execution.deriver()
                    != match role {
                        LocalServiceRoleV1::DeriverA => Ed25519YaoDeriverRoleV1::DeriverA,
                        LocalServiceRoleV1::DeriverB => Ed25519YaoDeriverRoleV1::DeriverB,
                        _ => {
                            return Err(invalid_worker_state(
                                "pair completion cannot belong to this worker role",
                            ))
                        }
                    }
            {
                return Err(invalid_worker_state(
                    "persisted completed pair identity does not match its role",
                ));
            }
        }
        LocalEd25519YaoPairRoleRecordV1::Expired {
            session,
            pair_digest,
        }
        | LocalEd25519YaoPairRoleRecordV1::Burned {
            session,
            pair_digest,
        } if session.iter().all(|byte| *byte == 0) || pair_digest.iter().all(|byte| *byte == 0) => {
            return Err(invalid_worker_state(
                "persisted pair terminal state has an empty identity",
            ));
        }
        _ => {}
    }
    Ok(())
}

fn pair_role_record_digest(record: &LocalEd25519YaoPairRoleRecordV1) -> [u8; 32] {
    match record {
        LocalEd25519YaoPairRoleRecordV1::Prepared { pair_digest, .. }
        | LocalEd25519YaoPairRoleRecordV1::Running { pair_digest, .. }
        | LocalEd25519YaoPairRoleRecordV1::Completed { pair_digest, .. }
        | LocalEd25519YaoPairRoleRecordV1::Expired { pair_digest, .. }
        | LocalEd25519YaoPairRoleRecordV1::Burned { pair_digest, .. } => *pair_digest,
    }
}

fn completed_execution_matches_pair_v1(
    execution: &Ed25519YaoRoleExecutionV1,
    pair_binding: &router_ab_core::Ed25519YaoInputPairBindingV1,
) -> bool {
    match execution {
        Ed25519YaoRoleExecutionV1::Activation(execution) => {
            &execution.binding == pair_binding.binding()
        }
        Ed25519YaoRoleExecutionV1::Export(execution) => {
            &execution.binding == pair_binding.binding()
        }
        Ed25519YaoRoleExecutionV1::Lane(execution) => {
            execution.session == pair_binding.session()
                && execution.job.yao_request_kind.operation() == pair_binding.binding().operation
        }
    }
}

fn build_deriver_a_activation_from_effective_state(
    state: &LocalEd25519YaoWorkerStateV1,
    request: LocalEd25519YaoActivationDeriverARequestV1,
    server: Ed25519YaoDeriverAServerContributionV1,
) -> RouterAbProtocolResult<(
    Ed25519YaoCeremonyBindingV1,
    ActivationDeriverA,
    Option<LocalEd25519YaoDeriverAEffectiveStateV1>,
)> {
    match request.binding.operation {
        Ed25519YaoOperationV1::Registration => {
            let identity = LocalEd25519YaoEffectiveIdentityV1::from_binding(&request.binding);
            if state.deriver_a_effective.contains_key(&identity) {
                return Err(invalid_worker_state(
                    "Deriver A already has an effective Yao contribution for this identity",
                ));
            }
            let epoch = Ed25519YaoStateEpochV1::new(1)?;
            let (server_y, server_tau) = server.into_parts();
            let server_y = server_y.into_bytes();
            let server_tau = server_tau.into_bytes();
            let role_contribution =
                Ed25519YaoDeriverAServerContributionV1::from_secret_bytes(server_y, server_tau);
            let state_contribution =
                Ed25519YaoDeriverAServerContributionV1::from_secret_bytes(server_y, server_tau);
            let initial = LocalEd25519YaoDeriverAEffectiveStateV1::from_initial(
                &request.binding,
                epoch,
                state_contribution,
            )?;
            let (binding, role) =
                build_local_activation_deriver_a_with_server_v1(request, role_contribution)?;
            Ok((binding, role, Some(initial)))
        }
        Ed25519YaoOperationV1::Recovery => {
            let identity = LocalEd25519YaoEffectiveIdentityV1::from_binding(&request.binding);
            if !state.deriver_a_effective.contains_key(&identity) {
                return Err(invalid_worker_state(
                    "Deriver A recovery requires active Yao state for this identity",
                ));
            }
            let (binding, role) = build_local_activation_deriver_a_with_server_v1(request, server)?;
            Ok((binding, role, None))
        }
        Ed25519YaoOperationV1::Refresh
        | Ed25519YaoOperationV1::Export
        | Ed25519YaoOperationV1::LaneProvisioning
        | Ed25519YaoOperationV1::LaneRefresh => Err(invalid_worker_state(
            "Deriver A activation request selected an invalid operation",
        )),
    }
}

fn build_deriver_b_activation_from_effective_state(
    state: &LocalEd25519YaoWorkerStateV1,
    request: LocalEd25519YaoActivationDeriverBRequestV1,
    server: Ed25519YaoDeriverBServerContributionV1,
) -> RouterAbProtocolResult<(
    Ed25519YaoCeremonyBindingV1,
    ActivationDeriverB,
    Option<LocalEd25519YaoDeriverBEffectiveStateV1>,
)> {
    match request.binding.operation {
        Ed25519YaoOperationV1::Registration => {
            let identity = LocalEd25519YaoEffectiveIdentityV1::from_binding(&request.binding);
            if state.deriver_b_effective.contains_key(&identity) {
                return Err(invalid_worker_state(
                    "Deriver B already has an effective Yao contribution for this identity",
                ));
            }
            let epoch = Ed25519YaoStateEpochV1::new(1)?;
            let (server_y, server_tau) = server.into_parts();
            let server_y = server_y.into_bytes();
            let server_tau = server_tau.into_bytes();
            let role_contribution =
                Ed25519YaoDeriverBServerContributionV1::from_secret_bytes(server_y, server_tau);
            let state_contribution =
                Ed25519YaoDeriverBServerContributionV1::from_secret_bytes(server_y, server_tau);
            let initial = LocalEd25519YaoDeriverBEffectiveStateV1::from_initial(
                &request.binding,
                epoch,
                state_contribution,
            )?;
            let (binding, role) =
                build_local_activation_deriver_b_with_server_v1(request, role_contribution)?;
            Ok((binding, role, Some(initial)))
        }
        Ed25519YaoOperationV1::Recovery => {
            let identity = LocalEd25519YaoEffectiveIdentityV1::from_binding(&request.binding);
            if !state.deriver_b_effective.contains_key(&identity) {
                return Err(invalid_worker_state(
                    "Deriver B recovery requires active Yao state for this identity",
                ));
            }
            let (binding, role) = build_local_activation_deriver_b_with_server_v1(request, server)?;
            Ok((binding, role, None))
        }
        Ed25519YaoOperationV1::Refresh
        | Ed25519YaoOperationV1::Export
        | Ed25519YaoOperationV1::LaneProvisioning
        | Ed25519YaoOperationV1::LaneRefresh => Err(invalid_worker_state(
            "Deriver B activation request selected an invalid operation",
        )),
    }
}

pub enum LocalEd25519YaoConnectionDispatchV1 {
    Handled,
    Unhandled(TcpStream),
}

pub type LocalEd25519YaoPersistBeforeNetworkV1<'a> =
    &'a mut dyn FnMut(&LocalEd25519YaoWorkerStateV1) -> Result<(), Box<dyn std::error::Error>>;

enum LocalEd25519YaoRequestClassV1 {
    Peer,
    Control,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "family", rename_all = "snake_case", deny_unknown_fields)]
pub enum LocalEd25519YaoRoleCompletionV1 {
    Activation {
        session_hex: String,
        transcript_hex: String,
        client_commitment_hex: String,
        signing_worker_commitment_hex: String,
        frame_count: u32,
        deriver_a_to_b_transport_bytes: u64,
        deriver_b_to_a_transport_bytes: u64,
        total_ab_transport_bytes: u64,
    },
}

pub fn dispatch_local_ed25519_yao_connection_v1(
    stream: TcpStream,
    config: &LocalWorkerRoleConfigV1,
    state: &mut LocalEd25519YaoWorkerStateV1,
) -> Result<LocalEd25519YaoConnectionDispatchV1, Box<dyn std::error::Error>> {
    let mut no_persist = |_state: &LocalEd25519YaoWorkerStateV1| Ok(());
    dispatch_local_ed25519_yao_connection_with_persistence_v1(
        stream,
        config,
        state,
        &mut no_persist,
    )
}

pub fn dispatch_local_ed25519_yao_connection_with_persistence_v1(
    mut stream: TcpStream,
    config: &LocalWorkerRoleConfigV1,
    state: &mut LocalEd25519YaoWorkerStateV1,
    persist_before_network: LocalEd25519YaoPersistBeforeNetworkV1<'_>,
) -> Result<LocalEd25519YaoConnectionDispatchV1, Box<dyn std::error::Error>> {
    match classify_request(&stream)? {
        LocalEd25519YaoRequestClassV1::Peer if config.role() == LocalServiceRoleV1::DeriverB => {
            let result =
                handle_deriver_b_peer_stream(stream, config, state, persist_before_network);
            if result.is_err() {
                // A pair failure after B claims Running burns the in-memory
                // record. Persist again before returning the transport error;
                // the outer worker loop only persists successful dispatches.
                persist_before_network(state)?;
            }
            result?;
            return Ok(LocalEd25519YaoConnectionDispatchV1::Handled);
        }
        LocalEd25519YaoRequestClassV1::Control => {}
        LocalEd25519YaoRequestClassV1::Peer | LocalEd25519YaoRequestClassV1::Other => {
            return Ok(LocalEd25519YaoConnectionDispatchV1::Unhandled(stream));
        }
    }

    let mut request = read_local_dev_http_request_v1(&mut stream)?;
    let result =
        handle_yao_control_request(&mut stream, config, state, &request, persist_before_network);
    request.body.fill(0);
    if let Err(error) = result {
        let (status, body) =
            local_dev_http_error_body_v1(config.role(), &request.path, 400, &error.to_string())?;
        write_local_dev_http_response_v1(&mut stream, status, &body)?;
    }
    Ok(LocalEd25519YaoConnectionDispatchV1::Handled)
}

fn handle_yao_control_request(
    stream: &mut TcpStream,
    config: &LocalWorkerRoleConfigV1,
    state: &mut LocalEd25519YaoWorkerStateV1,
    request: &crate::LocalDevHttpRequestPartsV1,
    persist_before_network: LocalEd25519YaoPersistBeforeNetworkV1<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    require_local_dev_internal_service_auth_v1(request).map_err(io::Error::other)?;
    match (config, request.path.as_str()) {
        (
            LocalWorkerRoleConfigV1::DeriverA(config),
            LOCAL_DERIVER_A_ED25519_YAO_PREPARE_PAIR_PATH,
        ) => {
            let pair_request =
                serde_json::from_slice::<CloudflareEd25519YaoPairPrepareRequestV1>(&request.body)?;
            let receipt = prepare_local_pair_role_v1(
                state,
                Ed25519YaoDeriverRoleV1::DeriverA,
                &pair_request,
                &config.peer_signing_key,
            )?;
            write_local_dev_http_response_v1(stream, 200, &serde_json::to_string(&receipt)?)
        }
        (
            LocalWorkerRoleConfigV1::DeriverB(config),
            LOCAL_DERIVER_B_ED25519_YAO_PREPARE_PAIR_PATH,
        ) => {
            let pair_request =
                serde_json::from_slice::<CloudflareEd25519YaoPairPrepareRequestV1>(&request.body)?;
            let receipt = prepare_local_pair_role_v1(
                state,
                Ed25519YaoDeriverRoleV1::DeriverB,
                &pair_request,
                &config.peer_signing_key,
            )?;
            write_local_dev_http_response_v1(stream, 200, &serde_json::to_string(&receipt)?)
        }
        (
            LocalWorkerRoleConfigV1::DeriverA(config),
            LOCAL_DERIVER_A_ED25519_YAO_EXECUTE_PAIR_PATH,
        ) => {
            let pair_request =
                serde_json::from_slice::<CloudflareEd25519YaoPairExecuteRequestV1>(&request.body)?;
            let execution = execute_local_pair_deriver_a_v1(
                state,
                config,
                pair_request,
                persist_before_network,
            )?;
            write_local_dev_http_response_v1(stream, 200, &serde_json::to_string(&execution)?)
        }
        (
            LocalWorkerRoleConfigV1::DeriverA(_),
            LOCAL_DERIVER_A_ED25519_YAO_READ_PAIR_STATUS_PATH,
        )
        | (
            LocalWorkerRoleConfigV1::DeriverB(_),
            LOCAL_DERIVER_B_ED25519_YAO_READ_PAIR_STATUS_PATH,
        ) => {
            let lookup =
                serde_json::from_slice::<CloudflareEd25519YaoPairLookupRequestV1>(&request.body)?;
            let status = read_local_pair_role_status_v1(state, lookup)?;
            write_local_dev_http_response_v1(stream, 200, &serde_json::to_string(&status)?)
        }
        (LocalWorkerRoleConfigV1::DeriverA(_), LOCAL_DERIVER_A_ED25519_YAO_BURN_PAIR_PATH)
        | (LocalWorkerRoleConfigV1::DeriverB(_), LOCAL_DERIVER_B_ED25519_YAO_BURN_PAIR_PATH) => {
            let lookup =
                serde_json::from_slice::<CloudflareEd25519YaoPairLookupRequestV1>(&request.body)?;
            let status = burn_local_pair_role_v1(state, lookup)?;
            write_local_dev_http_response_v1(stream, 200, &serde_json::to_string(&status)?)
        }
        (
            LocalWorkerRoleConfigV1::DeriverB(config),
            LOCAL_DERIVER_B_ED25519_YAO_REFRESH_STAGE_PATH,
        ) => {
            let envelope =
                serde_json::from_slice::<LocalEd25519YaoEncryptedRefreshInputV1>(&request.body)?;
            let private_key = deriver_input_private_key(&config.envelope_hpke_private_key)?;
            let role_request =
                open_local_ed25519_yao_refresh_deriver_b_input_v1(&envelope, &private_key)?;
            require_empty_pending_b(state)?;
            require_no_unpromoted_refresh_b(state)?;
            if state.staged_deriver_b_refresh.is_some() {
                return Err(io::Error::other("a Deriver B refresh is already staged").into());
            }
            let identity =
                LocalEd25519YaoEffectiveIdentityV1::from_binding(role_request.binding.ceremony());
            state
                .deriver_b_effective
                .get(&identity)
                .ok_or_else(|| {
                    io::Error::other(
                        "Deriver B refresh requires active Yao state for this identity",
                    )
                })?
                .validate_refresh_binding(&role_request.binding)?;
            consume_deriver_b_session(
                state,
                role_request.binding.ceremony().session_id.into_bytes(),
            )?;
            state.completed_deriver_b = None;
            let binding_digest = local_ed25519_yao_refresh_binding_digest_v1(&role_request.binding);
            let delta = generate_local_ed25519_yao_deriver_b_refresh_delta_v1(
                &role_request.binding,
                binding_digest,
            );
            state.staged_deriver_b_refresh = Some(StagedDeriverBRefreshV1 {
                request: role_request,
                binding_digest,
                delta,
            });
            write_local_dev_http_response_v1(stream, 200, "{\"status\":\"staged\"}")
        }
        (LocalWorkerRoleConfigV1::DeriverB(_), LOCAL_DERIVER_B_ED25519_YAO_REFRESH_DELTA_PATH) => {
            let exchange = serde_json::from_slice::<LocalEd25519YaoRefreshDeltaExchangeRequestV1>(
                &request.body,
            )?;
            let staged = state
                .staged_deriver_b_refresh
                .take()
                .ok_or_else(|| io::Error::other("no staged Deriver B refresh"))?;
            require_empty_pending_b(state)?;
            let joint = derive_local_ed25519_yao_joint_refresh_delta_v1(
                &staged.request.binding,
                staged.binding_digest,
                &exchange.deriver_a_delta,
                &staged.delta,
            )?;
            let identity =
                LocalEd25519YaoEffectiveIdentityV1::from_binding(staged.request.binding.ceremony());
            let prepared = state
                .deriver_b_effective
                .get(&identity)
                .ok_or_else(|| {
                    io::Error::other(
                        "Deriver B refresh requires active Yao state for this identity",
                    )
                })?
                .prepare_refresh(&staged.request.binding, &joint)?;
            let recipients = staged.request.recipients;
            let (binding, role) = build_local_refresh_deriver_b_v1(
                staged.request,
                prepared.candidate_contribution(),
            )?;
            let response = Zeroizing::new(serde_json::to_vec(&staged.delta)?);
            state.pending_deriver_b = Some(PendingDeriverBRoleV1::Refresh {
                binding,
                binding_digest: staged.binding_digest,
                recipients,
                prepared,
                role,
            });
            write_local_dev_http_response_v1(stream, 200, std::str::from_utf8(&response)?)
        }
        (
            LocalWorkerRoleConfigV1::DeriverA(config),
            LOCAL_DERIVER_A_ED25519_YAO_REFRESH_START_PATH,
        ) => {
            let envelope =
                serde_json::from_slice::<LocalEd25519YaoEncryptedRefreshInputV1>(&request.body)?;
            let private_key = deriver_input_private_key(&config.envelope_hpke_private_key)?;
            let role_request =
                open_local_ed25519_yao_refresh_deriver_a_input_v1(&envelope, &private_key)?;
            require_no_unpromoted_refresh_a(state)?;
            let identity =
                LocalEd25519YaoEffectiveIdentityV1::from_binding(role_request.binding.ceremony());
            state
                .deriver_a_effective
                .get(&identity)
                .ok_or_else(|| {
                    io::Error::other(
                        "Deriver A refresh requires active Yao state for this identity",
                    )
                })?
                .validate_refresh_binding(&role_request.binding)?;
            let session = role_request.binding.ceremony().session_id.into_bytes();
            consume_deriver_a_session(state, session)?;
            state.completed_deriver_a = None;
            let binding_digest = local_ed25519_yao_refresh_binding_digest_v1(&role_request.binding);
            let delta_a = generate_local_ed25519_yao_deriver_a_refresh_delta_v1(
                &role_request.binding,
                binding_digest,
            );
            let exchange = LocalEd25519YaoRefreshDeltaExchangeRequestV1 {
                deriver_a_delta: delta_a,
            };
            let delta_b = post_internal_json_v1::<_, LocalEd25519YaoDeriverBRefreshDeltaWireV1>(
                &config.deriver_b_url,
                LOCAL_DERIVER_B_ED25519_YAO_REFRESH_DELTA_PATH,
                &exchange,
            )?;
            let joint = derive_local_ed25519_yao_joint_refresh_delta_v1(
                &role_request.binding,
                binding_digest,
                &exchange.deriver_a_delta,
                &delta_b,
            )?;
            let prepared = state
                .deriver_a_effective
                .get(&identity)
                .ok_or_else(|| {
                    io::Error::other(
                        "Deriver A refresh requires active Yao state for this identity",
                    )
                })?
                .prepare_refresh(&role_request.binding, &joint)?;
            let recipients = role_request.recipients;
            let (binding, role) =
                build_local_refresh_deriver_a_v1(role_request, prepared.candidate_contribution())?;
            let session = binding.ceremony().session_id.into_bytes();
            let completion = run_local_activation_deriver_a_http_v1(
                http_authority(&config.deriver_b_url)?,
                session,
                &local_router_ab_internal_service_auth_secret_v1(),
                role,
            )?;
            let packages = seal_activation_output_v1(
                Ed25519YaoDeriverRoleV1::DeriverA,
                session,
                recipients,
                completion.final_transcript(),
                completion.client_package().as_bytes(),
                completion.signing_worker_package().as_bytes(),
            )?;
            let receipt = public_refresh_a_completion(session, &completion);
            state.completed_deriver_a = Some(CompletedDeriverARoleV1::Refresh {
                binding,
                binding_digest,
                packages,
                promotion: DeriverARefreshPromotionStateV1::Prepared(prepared),
            });
            write_local_dev_http_response_v1(stream, 200, &serde_json::to_string(&receipt)?)
        }
        (
            LocalWorkerRoleConfigV1::DeriverA(_),
            LOCAL_DERIVER_A_ED25519_YAO_REFRESH_PROMOTE_PATH,
        ) => {
            let promotion =
                serde_json::from_slice::<LocalEd25519YaoRefreshPromotionRequestV1>(&request.body)?;
            let receipt = promote_deriver_a_refresh(state, promotion)?;
            write_local_dev_http_response_v1(stream, 200, &serde_json::to_string(&receipt)?)
        }
        (
            LocalWorkerRoleConfigV1::DeriverB(_),
            LOCAL_DERIVER_B_ED25519_YAO_REFRESH_PROMOTE_PATH,
        ) => {
            let promotion =
                serde_json::from_slice::<LocalEd25519YaoRefreshPromotionRequestV1>(&request.body)?;
            let receipt = promote_deriver_b_refresh(state, promotion)?;
            write_local_dev_http_response_v1(stream, 200, &serde_json::to_string(&receipt)?)
        }
        (LocalWorkerRoleConfigV1::DeriverB(_), LOCAL_DERIVER_B_ED25519_YAO_REFRESH_RESULT_PATH) => {
            let receipt = state
                .completed_deriver_b
                .as_ref()
                .map(public_deriver_b_completion)
                .transpose()?
                .ok_or_else(|| io::Error::other("no completed Deriver B refresh"))?;
            write_local_dev_http_response_v1(stream, 200, &serde_json::to_string(&receipt)?)
        }
        (
            LocalWorkerRoleConfigV1::DeriverA(_),
            path @ (LOCAL_DERIVER_A_ED25519_YAO_REFRESH_CLIENT_PACKAGE_PATH
            | LOCAL_DERIVER_A_ED25519_YAO_REFRESH_SIGNING_WORKER_PACKAGE_PATH),
        ) => {
            let envelope = encrypted_deriver_a_package(state, path)?;
            write_local_dev_http_response_v1(stream, 200, &serde_json::to_string(&envelope)?)
        }
        (
            LocalWorkerRoleConfigV1::DeriverB(_),
            path @ (LOCAL_DERIVER_B_ED25519_YAO_REFRESH_CLIENT_PACKAGE_PATH
            | LOCAL_DERIVER_B_ED25519_YAO_REFRESH_SIGNING_WORKER_PACKAGE_PATH),
        ) => {
            let envelope = encrypted_deriver_b_package(state, path)?;
            write_local_dev_http_response_v1(stream, 200, &serde_json::to_string(&envelope)?)
        }
        (
            LocalWorkerRoleConfigV1::SigningWorker(config),
            LOCAL_SIGNING_WORKER_ED25519_YAO_ACTIVATION_PACKAGES_PATH,
        ) => {
            let delivery = serde_json::from_slice::<
                LocalEd25519YaoSigningWorkerPackagePairDeliveryV1,
            >(&request.body)?;
            let receipt = state.signing_worker.accept_package_pair(config, delivery)?;
            write_local_dev_http_response_v1(stream, 200, &serde_json::to_string(&receipt)?)
        }
        (
            LocalWorkerRoleConfigV1::SigningWorker(_),
            LOCAL_SIGNING_WORKER_ED25519_YAO_RECOVERY_PROMOTE_PATH,
        ) => {
            let promotion = serde_json::from_slice::<
                LocalEd25519YaoSigningWorkerRecoveryPromotionRequestV1,
            >(&request.body)?;
            let receipt = state.signing_worker.promote_recovery_candidate(promotion)?;
            write_local_dev_http_response_v1(stream, 200, &serde_json::to_string(&receipt)?)
        }
        (
            LocalWorkerRoleConfigV1::SigningWorker(config),
            LOCAL_SIGNING_WORKER_ED25519_YAO_REFRESH_DERIVER_A_PATH,
        ) => {
            let delivery = serde_json::from_slice::<
                LocalEd25519YaoSigningWorkerRefreshPackageDeliveryV1,
            >(&request.body)?;
            let receipt = state
                .signing_worker
                .accept_refresh_deriver_a(config, delivery)?;
            write_local_dev_http_response_v1(stream, 200, &serde_json::to_string(&receipt)?)
        }
        (
            LocalWorkerRoleConfigV1::SigningWorker(config),
            LOCAL_SIGNING_WORKER_ED25519_YAO_REFRESH_DERIVER_B_PATH,
        ) => {
            let delivery = serde_json::from_slice::<
                LocalEd25519YaoSigningWorkerRefreshPackageDeliveryV1,
            >(&request.body)?;
            let receipt = state
                .signing_worker
                .accept_refresh_deriver_b(config, delivery)?;
            write_local_dev_http_response_v1(stream, 200, &serde_json::to_string(&receipt)?)
        }
        (
            LocalWorkerRoleConfigV1::SigningWorker(config),
            LOCAL_SIGNING_WORKER_NORMAL_SIGNING_PREPARE_PATH,
        ) => {
            let response = state
                .signing_worker
                .prepare_normal_signing(config, &request.body)?;
            write_local_dev_http_response_v1(stream, 200, &response)
        }
        (
            LocalWorkerRoleConfigV1::SigningWorker(config),
            LOCAL_SIGNING_WORKER_NORMAL_SIGNING_PATH,
        ) => {
            let response = state
                .signing_worker
                .finalize_normal_signing(config, &request.body)?;
            write_local_dev_http_response_v1(stream, 200, &response)
        }
        _ => Err(io::Error::other("Yao control path is not owned by this worker").into()),
    }
}

fn prepare_local_pair_role_v1(
    state: &mut LocalEd25519YaoWorkerStateV1,
    role: Ed25519YaoDeriverRoleV1,
    request: &CloudflareEd25519YaoPairPrepareRequestV1,
    signing_key_material: &str,
) -> RouterAbProtocolResult<router_ab_core::Ed25519YaoRoleReadinessReceiptV1> {
    request.pair_binding.validate()?;
    request
        .tenant_root
        .validate_for_pair(&request.pair_binding)?;
    request.input.validate()?;
    if request.input.deriver() != role || request.input.session() != request.pair_binding.session()
    {
        return Err(invalid_worker_state(
            "pair role input does not match its binding",
        ));
    }
    let input_digest = ed25519_yao_encrypted_input_digest_v1(&request.input)?.bytes;
    let expected_digest = match role {
        Ed25519YaoDeriverRoleV1::DeriverA => request.pair_binding.deriver_a_input_digest(),
        Ed25519YaoDeriverRoleV1::DeriverB => request.pair_binding.deriver_b_input_digest(),
    };
    if input_digest != expected_digest.bytes {
        return Err(invalid_worker_state(
            "pair role input does not match its canonical digest",
        ));
    }
    let pair_digest = request.pair_binding.pair_digest().bytes;
    let now_ms = crate::local_now_unix_ms_v1()?;
    if let Some(existing) = state.pair_roles.get_mut(&pair_digest) {
        return match existing {
            LocalEd25519YaoPairRoleRecordV1::Prepared {
                input_digest: stored_input,
                expires_at_ms,
                receipt,
                ..
            } if *stored_input == input_digest && now_ms < *expires_at_ms => {
                Ok((**receipt).clone())
            }
            LocalEd25519YaoPairRoleRecordV1::Prepared { .. } => {
                *existing = LocalEd25519YaoPairRoleRecordV1::Expired {
                    session: request.pair_binding.session(),
                    pair_digest,
                };
                Err(pair_preparation_expired())
            }
            LocalEd25519YaoPairRoleRecordV1::Expired { .. }
            | LocalEd25519YaoPairRoleRecordV1::Burned { .. } => {
                Err(invalid_worker_state("pair role lifecycle is terminal"))
            }
            LocalEd25519YaoPairRoleRecordV1::Running { .. } => {
                Err(pair_conflict("pair role is already running"))
            }
            LocalEd25519YaoPairRoleRecordV1::Completed { .. } => Err(invalid_worker_state(
                "pair role lifecycle is already completed",
            )),
        };
    }
    let expires_at_ms = now_ms
        .checked_add(60_000)
        .ok_or_else(|| invalid_worker_state("pair role preparation expiry overflow"))?;
    let root_metadata_digest = local_pair_tenant_root_metadata_digest_v1(&request.tenant_root)?;
    let signing_key = local_pair_signing_key_v1(signing_key_material)?;
    let signing_keys = LocalEd25519YaoPairSigningKeysV1 {
        deriver_a: signing_key,
        deriver_b: signing_key,
    };
    let mut lifecycle = LocalEd25519YaoPairLifecycleV1::default();
    let receipt = lifecycle.prepare_role(
        role,
        &request.pair_binding,
        request.input.clone(),
        root_metadata_digest,
        now_ms,
        expires_at_ms,
        signing_keys,
    )?;
    state.pair_roles.insert(
        pair_digest,
        LocalEd25519YaoPairRoleRecordV1::Prepared {
            session: request.pair_binding.session(),
            pair_digest,
            pair_binding: Box::new(request.pair_binding.clone()),
            tenant_root: Box::new(request.tenant_root.clone()),
            input_digest,
            root_metadata_digest,
            expires_at_ms,
            input: Box::new(request.input.clone()),
            receipt: Box::new(receipt.clone()),
        },
    );
    Ok(receipt)
}

fn execute_local_pair_deriver_a_v1(
    state: &mut LocalEd25519YaoWorkerStateV1,
    config: &crate::LocalDeriverAWorkerConfigV1,
    request: CloudflareEd25519YaoPairExecuteRequestV1,
    persist_before_network: LocalEd25519YaoPersistBeforeNetworkV1<'_>,
) -> RouterAbProtocolResult<CloudflareEd25519YaoPairExecuteResponseV1> {
    let pair_digest = request.pair_binding.pair_digest().bytes;
    let result =
        execute_local_pair_deriver_a_inner_v1(state, config, request, persist_before_network);
    if result.is_err()
        && matches!(
            state.pair_roles.get(&pair_digest),
            Some(LocalEd25519YaoPairRoleRecordV1::Running { .. })
        )
    {
        let session = match state.pair_roles.get(&pair_digest) {
            Some(LocalEd25519YaoPairRoleRecordV1::Running { session, .. }) => *session,
            _ => unreachable!("running pair disappeared during failure handling"),
        };
        state.pair_roles.insert(
            pair_digest,
            LocalEd25519YaoPairRoleRecordV1::Burned {
                session,
                pair_digest,
            },
        );
    }
    result
}

fn execute_local_pair_deriver_a_inner_v1(
    state: &mut LocalEd25519YaoWorkerStateV1,
    config: &crate::LocalDeriverAWorkerConfigV1,
    request: CloudflareEd25519YaoPairExecuteRequestV1,
    persist_before_network: LocalEd25519YaoPersistBeforeNetworkV1<'_>,
) -> RouterAbProtocolResult<CloudflareEd25519YaoPairExecuteResponseV1> {
    request.pair_binding.validate()?;
    request
        .tenant_root
        .validate_for_pair(&request.pair_binding)?;
    request
        .peer_receipt
        .validate_for_pair(&request.pair_binding)?;
    if request.peer_receipt.role() != Ed25519YaoDeriverRoleV1::DeriverB {
        return Err(invalid_worker_state(
            "Deriver A pair execution requires a Deriver B readiness receipt",
        ));
    }
    verify_local_pair_readiness_receipt_v1(
        &request.peer_receipt,
        local_pair_verifying_key_v1(&config.deriver_b_peer_verifying_key)?,
    )?;
    let peer_root_metadata_digest = request.peer_receipt.root_metadata_digest().bytes;
    let pair_digest = request.pair_binding.pair_digest().bytes;
    let execution_id = Ed25519YaoExecutionIdV1::new(pair_digest)?;
    let record = state
        .pair_roles
        .get(&pair_digest)
        .cloned()
        .ok_or_else(missing_pair_preparation)?;
    let LocalEd25519YaoPairRoleRecordV1::Prepared {
        session,
        pair_digest: stored_pair_digest,
        pair_binding,
        tenant_root,
        input_digest,
        root_metadata_digest,
        expires_at_ms,
        input,
        receipt,
    } = record
    else {
        return match record {
            LocalEd25519YaoPairRoleRecordV1::Completed { .. } => Err(invalid_worker_state(
                "Deriver A pair completion is available through Router reconciliation",
            )),
            LocalEd25519YaoPairRoleRecordV1::Running { .. } => {
                Err(pair_conflict("Deriver A pair is already running"))
            }
            LocalEd25519YaoPairRoleRecordV1::Expired { .. }
            | LocalEd25519YaoPairRoleRecordV1::Burned { .. } => {
                Err(invalid_worker_state("Deriver A pair lifecycle is terminal"))
            }
            LocalEd25519YaoPairRoleRecordV1::Prepared { .. } => unreachable!(),
        };
    };
    if stored_pair_digest != pair_digest || *pair_binding != request.pair_binding {
        return Err(invalid_worker_state("Deriver A pair identity mismatch"));
    }
    if local_pair_tenant_root_metadata_digest_v1(&request.tenant_root)?
        != local_pair_tenant_root_metadata_digest_v1(&tenant_root)?
    {
        return Err(invalid_worker_state(
            "Deriver A pair tenant-root context changed after preparation",
        ));
    }
    let now_ms = crate::local_now_unix_ms_v1()?;
    if now_ms >= expires_at_ms {
        state.pair_roles.insert(
            pair_digest,
            LocalEd25519YaoPairRoleRecordV1::Expired {
                session,
                pair_digest,
            },
        );
        return Err(pair_preparation_expired());
    }
    let running = LocalEd25519YaoPairRoleRecordV1::Running {
        session,
        pair_digest,
        pair_binding: pair_binding.clone(),
        tenant_root: tenant_root.clone(),
        input_digest,
        root_metadata_digest,
        expires_at_ms: now_ms
            .checked_add(60_000)
            .ok_or_else(|| invalid_worker_state("Deriver A pair running expiry overflow"))?,
        execution_id: execution_id.into_bytes(),
        input: input.clone(),
        receipt: receipt.clone(),
    };
    state.pair_roles.insert(pair_digest, running);
    persist_before_network(state)
        .map_err(|_| invalid_worker_state("Deriver A running pair persistence failed"))?;
    let private_key = deriver_input_private_key(&config.envelope_hpke_private_key)
        .map_err(|_| invalid_worker_state("Deriver A pair input key is malformed"))?;
    let coordinates = local_tenant_root_coordinates_for_context_v1(&tenant_root)?;
    let role_share = config.tenant_root_role_shares.resolve_for_context(
        &coordinates,
        &tenant_root,
        router_ab_core::TwoPartyDeriverRole::DeriverA,
    )?;
    let preface = prepare_local_deriver_a_target_v2(&tenant_root, &pair_binding, &role_share)?;
    let target_proof_peer_public_key =
        local_target_proof_public_key_v1(&config.target_proof_peer_public_key)?;
    let outbound_target_proof = seal_local_deriver_a_target_proof_v2(
        &tenant_root.outer_binding,
        preface.outbound_plaintext(),
        &target_proof_peer_public_key,
    )
    .map_err(|_| pair_execution_error("Deriver A target-proof encryption failed"))?;
    let pair_context = crate::local_ed25519_yao_stream::LocalEd25519YaoPairPeerContextV1 {
        pair_digest,
        execution_id,
        peer_receipt: (*receipt).clone(),
    };
    let (connection, incoming_target_proof, incoming_plaintext) =
        connect_local_deriver_a_pair_http_v2(
            http_authority(&config.deriver_b_url)
                .map_err(|_| pair_execution_error("Deriver B URL is malformed"))?,
            session,
            &local_router_ab_internal_service_auth_secret_v1(),
            &pair_context,
            &outbound_target_proof,
            private_key.as_bytes(),
        )
        .map_err(|_| pair_execution_error("Deriver A target-proof preface failed"))?;
    let server_contribution = complete_local_deriver_a_target_v2(
        preface,
        &incoming_target_proof,
        &incoming_plaintext,
        &tenant_root,
    )?;
    let (execution, deriver_b_sealed_execution) = match input.kind() {
        router_ab_core::Ed25519YaoInputKindV1::Activation => {
            let role_request =
                open_local_ed25519_yao_activation_deriver_a_input_v1(&input, &private_key)?;
            if role_request.binding != pair_binding.binding().clone() {
                return Err(pair_execution_error(
                    "Deriver A pair activation binding mismatch",
                ));
            }
            let recipients = role_request.recipients;
            let (binding, role, initial_effective) =
                build_deriver_a_activation_from_effective_state(
                    state,
                    role_request,
                    server_contribution,
                )?;
            let (completion, acceptance, deriver_b_sealed_execution) =
                run_local_activation_deriver_a_pair_connected_v2(connection, role)
                    .map_err(|_| pair_execution_error("Deriver A pair activation stream failed"))?;
            validate_local_pair_start_acceptance_v1(
                &acceptance,
                &pair_binding,
                execution_id,
                peer_root_metadata_digest,
                &config.deriver_b_peer_verifying_key,
            )?;
            let packages = seal_activation_output_v1(
                Ed25519YaoDeriverRoleV1::DeriverA,
                session,
                recipients,
                completion.final_transcript(),
                completion.client_package().as_bytes(),
                completion.signing_worker_package().as_bytes(),
            )?;
            if let Some(initial_effective) = initial_effective {
                let identity = initial_effective.identity().clone();
                if state
                    .deriver_a_effective
                    .insert(identity, initial_effective)
                    .is_some()
                {
                    return Err(invalid_worker_state(
                        "Deriver A effective identity was concurrently registered",
                    ));
                }
            }
            (
                Ed25519YaoRoleExecutionV1::Activation(Ed25519YaoActivationRoleExecutionV1::new(
                    binding,
                    Ed25519YaoDeriverRoleV1::DeriverA,
                    completion.final_transcript(),
                    completion.client_commitment(),
                    completion.signing_worker_commitment(),
                    packages.client,
                    packages.signing_worker,
                )?),
                deriver_b_sealed_execution,
            )
        }
        router_ab_core::Ed25519YaoInputKindV1::Export => {
            let role_request =
                open_local_ed25519_yao_export_deriver_a_input_v1(&input, &private_key)?;
            if role_request.binding != pair_binding.binding().clone() {
                return Err(pair_execution_error(
                    "Deriver A pair export binding mismatch",
                ));
            }
            let recipient = role_request.recipients;
            let (binding, role) =
                build_local_export_deriver_a_with_server_v1(role_request, server_contribution)?;
            let (completion, acceptance, deriver_b_sealed_execution) =
                run_local_export_deriver_a_pair_connected_v2(connection, role)
                    .map_err(|_| pair_execution_error("Deriver A pair export stream failed"))?;
            validate_local_pair_start_acceptance_v1(
                &acceptance,
                &pair_binding,
                execution_id,
                peer_root_metadata_digest,
                &config.deriver_b_peer_verifying_key,
            )?;
            let client_package = seal_export_output_v1(
                Ed25519YaoDeriverRoleV1::DeriverA,
                session,
                recipient,
                completion.final_transcript(),
                completion.export_package().as_bytes(),
            )?;
            (
                Ed25519YaoRoleExecutionV1::Export(Ed25519YaoExportRoleExecutionV1::new(
                    binding,
                    Ed25519YaoDeriverRoleV1::DeriverA,
                    completion.final_transcript(),
                    client_package,
                )?),
                deriver_b_sealed_execution,
            )
        }
        router_ab_core::Ed25519YaoInputKindV1::LaneMaterialization => {
            return Err(pair_execution_error(
                "legacy local Deriver HTTP does not support authenticated lane dispatch",
            ));
        }
    };
    state.pair_roles.insert(
        pair_digest,
        LocalEd25519YaoPairRoleRecordV1::Completed {
            session,
            pair_digest,
            pair_binding: pair_binding.clone(),
            execution_id: execution_id.into_bytes(),
            execution: Box::new(execution.clone()),
        },
    );
    let deriver_b_sealed_execution_json = String::from_utf8(deriver_b_sealed_execution)
        .map_err(|_| invalid_worker_state("Deriver B sealed execution is not UTF-8 JSON"))?;
    Ok(CloudflareEd25519YaoPairExecuteResponseV1 {
        deriver_a_execution: execution,
        deriver_b_sealed_execution_json,
    })
}

fn pair_execution_error(message: &'static str) -> RouterAbProtocolError {
    RouterAbProtocolError::new(RouterAbProtocolErrorCode::InvalidLifecycleState, message)
}

fn local_pair_verifying_key_v1(material: &str) -> RouterAbProtocolResult<[u8; 32]> {
    hex::decode(material)
        .map_err(|_| invalid_worker_state("local pair verifying key is malformed"))?
        .try_into()
        .map_err(|_| invalid_worker_state("local pair verifying key must contain 32 bytes"))
}

fn local_target_proof_public_key_v1(material: &str) -> RouterAbProtocolResult<[u8; 32]> {
    let encoded = material.strip_prefix("x25519:").ok_or_else(|| {
        invalid_worker_state("local target-proof public key must use x25519:<hex>")
    })?;
    let key: [u8; 32] = hex::decode(encoded)
        .map_err(|_| invalid_worker_state("local target-proof public key is malformed"))?
        .try_into()
        .map_err(|_| invalid_worker_state("local target-proof public key must contain 32 bytes"))?;
    if key.iter().all(|byte| *byte == 0) {
        return Err(invalid_worker_state(
            "local target-proof public key must be nonzero",
        ));
    }
    Ok(key)
}

fn sign_local_pair_start_acceptance_v1(
    role: Ed25519YaoDeriverRoleV1,
    session: [u8; 32],
    pair_digest: [u8; 32],
    execution_id: Ed25519YaoExecutionIdV1,
    root_metadata_digest: [u8; 32],
    accepted_at_ms: u64,
    expires_at_ms: u64,
    signing_key_material: &str,
) -> RouterAbProtocolResult<Ed25519YaoRoleStartAcceptanceV1> {
    let session = Ed25519YaoSessionIdV1::new(session)?;
    let placeholder = router_ab_core::Ed25519YaoRoleSignatureV1::new(
        Ed25519YaoRoleSignatureSchemeV1::Ed25519V1,
        [1_u8; 64],
    )?;
    let unsigned = Ed25519YaoRoleStartAcceptanceV1::new(
        role,
        session,
        PublicDigest32::new(pair_digest),
        execution_id,
        PublicDigest32::new(root_metadata_digest),
        accepted_at_ms,
        expires_at_ms,
        placeholder,
    )?;
    let signing_key =
        ed25519_dalek::SigningKey::from_bytes(&local_pair_signing_key_v1(signing_key_material)?);
    let signature =
        ed25519_dalek::Signer::sign(&signing_key, unsigned.signed_message_digest().as_bytes())
            .to_bytes();
    let signature = router_ab_core::Ed25519YaoRoleSignatureV1::new(
        Ed25519YaoRoleSignatureSchemeV1::Ed25519V1,
        signature,
    )?;
    Ed25519YaoRoleStartAcceptanceV1::new(
        role,
        session,
        PublicDigest32::new(pair_digest),
        execution_id,
        PublicDigest32::new(root_metadata_digest),
        accepted_at_ms,
        expires_at_ms,
        signature,
    )
}

fn validate_local_pair_start_acceptance_v1(
    acceptance: &Ed25519YaoRoleStartAcceptanceV1,
    pair_binding: &router_ab_core::Ed25519YaoInputPairBindingV1,
    execution_id: Ed25519YaoExecutionIdV1,
    root_metadata_digest: [u8; 32],
    verifying_key: &str,
) -> RouterAbProtocolResult<()> {
    acceptance.validate_for_pair(pair_binding)?;
    if acceptance.role() != Ed25519YaoDeriverRoleV1::DeriverB
        || acceptance.execution_id() != execution_id
        || acceptance.root_metadata_digest().bytes != root_metadata_digest
    {
        return Err(invalid_worker_state(
            "Deriver B pair start acceptance identity mismatch",
        ));
    }
    acceptance.validate_at(crate::local_now_unix_ms_v1()?)?;
    let verifying_key = local_pair_verifying_key_v1(verifying_key)?;
    let key = ed25519_dalek::VerifyingKey::from_bytes(&verifying_key)
        .map_err(|_| invalid_worker_state("local pair verifying key is malformed"))?;
    let signature = ed25519_dalek::Signature::from_slice(acceptance.signature().bytes())
        .map_err(|_| invalid_worker_state("local pair start acceptance signature is malformed"))?;
    key.verify_strict(acceptance.signed_message_digest().as_bytes(), &signature)
        .map_err(|_| invalid_worker_state("local pair start acceptance signature is invalid"))
}

fn read_local_pair_role_status_v1(
    state: &mut LocalEd25519YaoWorkerStateV1,
    lookup: CloudflareEd25519YaoPairLookupRequestV1,
) -> RouterAbProtocolResult<CloudflareEd25519YaoPairStatusResponseV1> {
    let Some(record) = state.pair_roles.get_mut(&lookup.pair_digest) else {
        return Ok(CloudflareEd25519YaoPairStatusResponseV1::Missing {
            session: lookup.session,
            pair_digest: lookup.pair_digest,
        });
    };
    match record {
        LocalEd25519YaoPairRoleRecordV1::Prepared {
            session,
            pair_digest,
            expires_at_ms,
            ..
        } if *session == lookup.session && *pair_digest == lookup.pair_digest => {
            if crate::local_now_unix_ms_v1()? >= *expires_at_ms {
                *record = LocalEd25519YaoPairRoleRecordV1::Expired {
                    session: *session,
                    pair_digest: *pair_digest,
                };
                Ok(CloudflareEd25519YaoPairStatusResponseV1::Expired {
                    session: lookup.session,
                    pair_digest: lookup.pair_digest,
                })
            } else {
                Ok(CloudflareEd25519YaoPairStatusResponseV1::Prepared {
                    session: lookup.session,
                    pair_digest: lookup.pair_digest,
                })
            }
        }
        LocalEd25519YaoPairRoleRecordV1::Running {
            session,
            pair_digest,
            expires_at_ms,
            execution_id: _,
            ..
        } if *session == lookup.session && *pair_digest == lookup.pair_digest => {
            if crate::local_now_unix_ms_v1()? >= *expires_at_ms {
                *record = LocalEd25519YaoPairRoleRecordV1::Burned {
                    session: *session,
                    pair_digest: *pair_digest,
                };
                Ok(CloudflareEd25519YaoPairStatusResponseV1::Burned {
                    session: lookup.session,
                    pair_digest: lookup.pair_digest,
                })
            } else {
                Ok(CloudflareEd25519YaoPairStatusResponseV1::Running {
                    session: lookup.session,
                    pair_digest: lookup.pair_digest,
                })
            }
        }
        LocalEd25519YaoPairRoleRecordV1::Completed {
            session,
            pair_digest,
            execution,
            ..
        } if *session == lookup.session && *pair_digest == lookup.pair_digest => {
            Ok(CloudflareEd25519YaoPairStatusResponseV1::Completed {
                execution: execution.clone(),
            })
        }
        LocalEd25519YaoPairRoleRecordV1::Expired {
            session,
            pair_digest,
        } if *session == lookup.session && *pair_digest == lookup.pair_digest => {
            Ok(CloudflareEd25519YaoPairStatusResponseV1::Expired {
                session: lookup.session,
                pair_digest: lookup.pair_digest,
            })
        }
        LocalEd25519YaoPairRoleRecordV1::Burned {
            session,
            pair_digest,
        } if *session == lookup.session && *pair_digest == lookup.pair_digest => {
            Ok(CloudflareEd25519YaoPairStatusResponseV1::Burned {
                session: lookup.session,
                pair_digest: lookup.pair_digest,
            })
        }
        _ => Err(invalid_worker_state("pair role lookup identity mismatch")),
    }
}

fn burn_local_pair_role_v1(
    state: &mut LocalEd25519YaoWorkerStateV1,
    lookup: CloudflareEd25519YaoPairLookupRequestV1,
) -> RouterAbProtocolResult<CloudflareEd25519YaoPairStatusResponseV1> {
    let Some(record) = state.pair_roles.get_mut(&lookup.pair_digest) else {
        return Ok(CloudflareEd25519YaoPairStatusResponseV1::Missing {
            session: lookup.session,
            pair_digest: lookup.pair_digest,
        });
    };
    match record {
        LocalEd25519YaoPairRoleRecordV1::Burned {
            session,
            pair_digest,
        } if *session == lookup.session && *pair_digest == lookup.pair_digest => {
            Ok(CloudflareEd25519YaoPairStatusResponseV1::Burned {
                session: lookup.session,
                pair_digest: lookup.pair_digest,
            })
        }
        LocalEd25519YaoPairRoleRecordV1::Expired {
            session,
            pair_digest,
        } if *session == lookup.session && *pair_digest == lookup.pair_digest => {
            Ok(CloudflareEd25519YaoPairStatusResponseV1::Expired {
                session: lookup.session,
                pair_digest: lookup.pair_digest,
            })
        }
        LocalEd25519YaoPairRoleRecordV1::Running {
            session,
            pair_digest,
            ..
        } if *session == lookup.session && *pair_digest == lookup.pair_digest => {
            *record = LocalEd25519YaoPairRoleRecordV1::Burned {
                session: lookup.session,
                pair_digest: lookup.pair_digest,
            };
            Ok(CloudflareEd25519YaoPairStatusResponseV1::Burned {
                session: lookup.session,
                pair_digest: lookup.pair_digest,
            })
        }
        LocalEd25519YaoPairRoleRecordV1::Prepared { .. } => Err(invalid_worker_state(
            "prepared pair role cannot be burned before execution",
        )),
        _ => Err(invalid_worker_state("pair role lookup identity mismatch")),
    }
}

fn local_pair_tenant_root_metadata_digest_v1(
    tenant_root: &router_ab_cloudflare::CloudflareEd25519YaoTenantRootContextV2,
) -> RouterAbProtocolResult<[u8; 32]> {
    let receipt = tenant_root.custody_binding.activation_receipt_bytes()?;
    let digest: [u8; 32] = sha2::Sha256::digest(receipt).into();
    if digest.iter().all(|byte| *byte == 0) {
        return Err(invalid_worker_state(
            "tenant-root activation receipt digest is empty",
        ));
    }
    Ok(digest)
}

fn local_pair_signing_key_v1(material: &str) -> RouterAbProtocolResult<[u8; 32]> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(material)
        .map_err(|_| invalid_worker_state("local peer signing key is malformed"))?
        .try_into()
        .map_err(|_| invalid_worker_state("local peer signing key must contain 32 bytes"))
}

fn require_empty_pending_b(
    state: &LocalEd25519YaoWorkerStateV1,
) -> Result<(), Box<dyn std::error::Error>> {
    if state.pending_deriver_b.is_some() {
        return Err(io::Error::other("a Deriver B Yao ceremony is already staged").into());
    }
    Ok(())
}

fn consume_deriver_a_session(
    state: &mut LocalEd25519YaoWorkerStateV1,
    session: [u8; 32],
) -> Result<(), Box<dyn std::error::Error>> {
    if !state.consumed_deriver_a_sessions.insert(session) {
        return Err(io::Error::other("Deriver A Yao session has already been consumed").into());
    }
    Ok(())
}

fn consume_deriver_b_session(
    state: &mut LocalEd25519YaoWorkerStateV1,
    session: [u8; 32],
) -> Result<(), Box<dyn std::error::Error>> {
    if !state.consumed_deriver_b_sessions.insert(session) {
        return Err(io::Error::other("Deriver B Yao session has already been consumed").into());
    }
    Ok(())
}

fn require_no_unpromoted_refresh_a(
    state: &LocalEd25519YaoWorkerStateV1,
) -> Result<(), Box<dyn std::error::Error>> {
    if matches!(
        state.completed_deriver_a,
        Some(CompletedDeriverARoleV1::Refresh {
            promotion: DeriverARefreshPromotionStateV1::Prepared(_),
            ..
        })
    ) {
        return Err(io::Error::other("Deriver A has an unpromoted refresh").into());
    }
    Ok(())
}

fn require_no_unpromoted_refresh_b(
    state: &LocalEd25519YaoWorkerStateV1,
) -> Result<(), Box<dyn std::error::Error>> {
    if matches!(
        state.completed_deriver_b,
        Some(CompletedDeriverBRoleV1::Refresh {
            promotion: DeriverBRefreshPromotionStateV1::Prepared(_),
            ..
        })
    ) {
        return Err(io::Error::other("Deriver B has an unpromoted refresh").into());
    }
    Ok(())
}

fn promote_deriver_a_refresh(
    state: &mut LocalEd25519YaoWorkerStateV1,
    request: LocalEd25519YaoRefreshPromotionRequestV1,
) -> RouterAbProtocolResult<LocalEd25519YaoRefreshPromotionReceiptV1> {
    let completed = state
        .completed_deriver_a
        .as_mut()
        .ok_or_else(|| invalid_worker_state("Deriver A has no completed refresh"))?;
    let CompletedDeriverARoleV1::Refresh {
        binding,
        binding_digest,
        promotion,
        ..
    } = completed;
    if request.binding_digest != *binding_digest
        || request.session != binding.ceremony().session_id.into_bytes()
    {
        return Err(invalid_worker_state(
            "Deriver A refresh promotion binding does not match",
        ));
    }
    if let DeriverARefreshPromotionStateV1::Promoted(receipt) = promotion {
        return Ok(*receipt);
    }
    let receipt = match promotion {
        DeriverARefreshPromotionStateV1::Prepared(prepared) => {
            LocalEd25519YaoRefreshPromotionReceiptV1 {
                state_epoch: prepared.next_epoch(),
            }
        }
        DeriverARefreshPromotionStateV1::Promoted(_) => unreachable!(),
    };
    let DeriverARefreshPromotionStateV1::Prepared(prepared) = core::mem::replace(
        promotion,
        DeriverARefreshPromotionStateV1::Promoted(receipt),
    ) else {
        unreachable!();
    };
    let identity = LocalEd25519YaoEffectiveIdentityV1::from_binding(binding.ceremony());
    state
        .deriver_a_effective
        .get_mut(&identity)
        .ok_or_else(|| {
            invalid_worker_state("Deriver A refresh requires active Yao state for this identity")
        })?
        .promote(prepared)?;
    Ok(receipt)
}

fn promote_deriver_b_refresh(
    state: &mut LocalEd25519YaoWorkerStateV1,
    request: LocalEd25519YaoRefreshPromotionRequestV1,
) -> RouterAbProtocolResult<LocalEd25519YaoRefreshPromotionReceiptV1> {
    let completed = state
        .completed_deriver_b
        .as_mut()
        .ok_or_else(|| invalid_worker_state("Deriver B has no completed refresh"))?;
    let CompletedDeriverBRoleV1::Refresh {
        binding,
        binding_digest,
        promotion,
        ..
    } = completed;
    if request.binding_digest != *binding_digest
        || request.session != binding.ceremony().session_id.into_bytes()
    {
        return Err(invalid_worker_state(
            "Deriver B refresh promotion binding does not match",
        ));
    }
    if let DeriverBRefreshPromotionStateV1::Promoted(receipt) = promotion {
        return Ok(*receipt);
    }
    let receipt = match promotion {
        DeriverBRefreshPromotionStateV1::Prepared(prepared) => {
            LocalEd25519YaoRefreshPromotionReceiptV1 {
                state_epoch: prepared.next_epoch(),
            }
        }
        DeriverBRefreshPromotionStateV1::Promoted(_) => unreachable!(),
    };
    let DeriverBRefreshPromotionStateV1::Prepared(prepared) = core::mem::replace(
        promotion,
        DeriverBRefreshPromotionStateV1::Promoted(receipt),
    ) else {
        unreachable!();
    };
    let identity = LocalEd25519YaoEffectiveIdentityV1::from_binding(binding.ceremony());
    state
        .deriver_b_effective
        .get_mut(&identity)
        .ok_or_else(|| {
            invalid_worker_state("Deriver B refresh requires active Yao state for this identity")
        })?
        .promote(prepared)?;
    Ok(receipt)
}

fn post_internal_json_v1<Request, Response>(
    base_url: &str,
    path: &str,
    request: &Request,
) -> Result<Response, Box<dyn std::error::Error>>
where
    Request: Serialize,
    Response: DeserializeOwned,
{
    let authority = http_authority(base_url)?;
    let mut request_body = Zeroizing::new(serde_json::to_vec(request)?);
    let mut stream = TcpStream::connect(authority)?;
    let timeout = Duration::from_millis(LOCAL_HTTP_SERVICE_BINDING_TIMEOUT_MS_V1);
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    let auth = local_router_ab_internal_service_auth_secret_v1();
    write!(
        stream,
        "POST {path} HTTP/1.1\r\nhost: {authority}\r\ncontent-type: application/json\r\n{LOCAL_ROUTER_AB_INTERNAL_SERVICE_AUTH_HEADER_V1}: {auth}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        request_body.len()
    )?;
    stream.write_all(&request_body)?;
    stream.flush()?;
    stream.shutdown(Shutdown::Write)?;
    request_body.zeroize();
    let mut response = Zeroizing::new(Vec::new());
    stream.read_to_end(&mut response)?;
    let (status, mut response_body) = crate::split_local_http_response_v1(&response)?;
    response.zeroize();
    if !(200..=299).contains(&status) {
        response_body.zeroize();
        return Err(io::Error::other(format!(
            "internal refresh delta exchange failed with status {status}"
        ))
        .into());
    }
    let parsed = serde_json::from_slice(&response_body)?;
    response_body.zeroize();
    Ok(parsed)
}

fn seal_activation_output_v1(
    deriver: Ed25519YaoDeriverRoleV1,
    session: [u8; 32],
    recipients: LocalEd25519YaoActivationRecipientsV1,
    transcript: [u8; 32],
    client_plaintext: &[u8],
    signing_worker_plaintext: &[u8],
) -> RouterAbProtocolResult<EncryptedActivationPackagesV1> {
    Ok(EncryptedActivationPackagesV1 {
        client: seal_local_ed25519_yao_package_v1(
            Ed25519YaoPackageKindV1::ActivationClient,
            deriver,
            session,
            transcript,
            recipients.client_public_key,
            client_plaintext,
        )?,
        signing_worker: seal_local_ed25519_yao_package_v1(
            Ed25519YaoPackageKindV1::ActivationSigningWorker,
            deriver,
            session,
            transcript,
            recipients.signing_worker_public_key,
            signing_worker_plaintext,
        )?,
    })
}

fn seal_export_output_v1(
    deriver: Ed25519YaoDeriverRoleV1,
    session: [u8; 32],
    recipient: LocalEd25519YaoExportRecipientV1,
    transcript: [u8; 32],
    plaintext: &[u8],
) -> RouterAbProtocolResult<Ed25519YaoEncryptedPackageV1> {
    seal_local_ed25519_yao_package_v1(
        Ed25519YaoPackageKindV1::ExportClient,
        deriver,
        session,
        transcript,
        recipient.client_public_key,
        plaintext,
    )
}

fn encrypted_deriver_a_package(
    state: &LocalEd25519YaoWorkerStateV1,
    path: &str,
) -> Result<Ed25519YaoEncryptedPackageV1, Box<dyn std::error::Error>> {
    match (&state.completed_deriver_a, path) {
        (
            Some(CompletedDeriverARoleV1::Refresh { packages, .. }),
            LOCAL_DERIVER_A_ED25519_YAO_REFRESH_CLIENT_PACKAGE_PATH,
        ) => Ok(packages.client.clone()),
        (
            Some(CompletedDeriverARoleV1::Refresh { packages, .. }),
            LOCAL_DERIVER_A_ED25519_YAO_REFRESH_SIGNING_WORKER_PACKAGE_PATH,
        ) => Ok(packages.signing_worker.clone()),
        _ => Err(io::Error::other("requested Deriver A package is unavailable").into()),
    }
}

fn encrypted_deriver_b_package(
    state: &LocalEd25519YaoWorkerStateV1,
    path: &str,
) -> Result<Ed25519YaoEncryptedPackageV1, Box<dyn std::error::Error>> {
    match (&state.completed_deriver_b, path) {
        (
            Some(CompletedDeriverBRoleV1::Refresh { packages, .. }),
            LOCAL_DERIVER_B_ED25519_YAO_REFRESH_CLIENT_PACKAGE_PATH,
        ) => Ok(packages.client.clone()),
        (
            Some(CompletedDeriverBRoleV1::Refresh { packages, .. }),
            LOCAL_DERIVER_B_ED25519_YAO_REFRESH_SIGNING_WORKER_PACKAGE_PATH,
        ) => Ok(packages.signing_worker.clone()),
        _ => Err(io::Error::other("requested Deriver B package is unavailable").into()),
    }
}

fn handle_deriver_b_peer_stream(
    stream: TcpStream,
    config: &LocalWorkerRoleConfigV1,
    state: &mut LocalEd25519YaoWorkerStateV1,
    persist_before_network: LocalEd25519YaoPersistBeforeNetworkV1<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    let auth = local_router_ab_internal_service_auth_secret_v1();
    if state.pending_deriver_b.is_none() {
        let expected_session = peek_local_peer_session_v1(&stream)?;
        let authenticated = authenticate_local_ed25519_yao_deriver_b_peer_http_with_pair_v2(
            stream,
            expected_session,
            &auth,
        )?;
        let Some(pair) = authenticated.pair_context().cloned() else {
            return Err(io::Error::other("no staged Deriver B Yao role").into());
        };
        execute_local_pair_deriver_b_v1(
            config,
            state,
            authenticated,
            pair,
            persist_before_network,
        )?;
        return Ok(());
    }
    let expected_session = state
        .pending_deriver_b
        .as_ref()
        .ok_or_else(|| io::Error::other("no staged Deriver B Yao role"))?
        .session();
    let authenticated =
        authenticate_local_ed25519_yao_deriver_b_peer_http_v1(stream, expected_session, &auth)?;
    let pending = state
        .pending_deriver_b
        .take()
        .ok_or_else(|| io::Error::other("authenticated Deriver B role disappeared"))?;
    let completed = match pending {
        PendingDeriverBRoleV1::Refresh {
            binding,
            binding_digest,
            recipients,
            prepared,
            role,
        } => {
            let session = binding.ceremony().session_id.into_bytes();
            let completion =
                run_local_activation_deriver_b_authenticated_http_v1(authenticated, role)?;
            let packages = seal_activation_output_v1(
                Ed25519YaoDeriverRoleV1::DeriverB,
                session,
                recipients,
                completion.final_transcript(),
                completion.client_package().as_bytes(),
                completion.signing_worker_package().as_bytes(),
            )?;
            CompletedDeriverBRoleV1::Refresh {
                binding,
                binding_digest,
                packages,
                promotion: DeriverBRefreshPromotionStateV1::Prepared(prepared),
                completion: Box::new(completion),
            }
        }
    };
    state.completed_deriver_b = Some(completed);
    Ok(())
}

fn peek_local_peer_session_v1(stream: &TcpStream) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let mut buffer = [0_u8; 8 * 1024];
    for _ in 0..250 {
        let bytes = stream.peek(&mut buffer)?;
        let head = std::str::from_utf8(&buffer[..bytes])?;
        if head.contains("\r\n\r\n") {
            let session_line = head
                .split("\r\n")
                .find(|line| {
                    line.to_ascii_lowercase()
                        .starts_with("x-seams-ed25519-yao-session:")
                })
                .ok_or_else(|| io::Error::other("pair stream session header is missing"))?;
            let value = session_line
                .split_once(':')
                .map(|(_, value)| value.trim())
                .ok_or_else(|| io::Error::other("pair stream session header is malformed"))?;
            return hex::decode(value)?.try_into().map_err(|_| {
                io::Error::other("pair stream session header must contain 32 bytes").into()
            });
        }
        thread::sleep(Duration::from_millis(1));
    }
    Err(io::Error::other("pair stream request head timed out").into())
}

fn execute_local_pair_deriver_b_v1(
    topology_config: &LocalWorkerRoleConfigV1,
    state: &mut LocalEd25519YaoWorkerStateV1,
    authenticated: crate::LocalEd25519YaoAuthenticatedDeriverBPeerV1,
    peer: crate::local_ed25519_yao_stream::LocalEd25519YaoPairPeerContextV1,
    persist_before_network: LocalEd25519YaoPersistBeforeNetworkV1<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    let pair_digest = peer.pair_digest;
    let result = execute_local_pair_deriver_b_inner_v1(
        topology_config,
        state,
        authenticated,
        peer,
        persist_before_network,
    );
    if result.is_err()
        && matches!(
            state.pair_roles.get(&pair_digest),
            Some(LocalEd25519YaoPairRoleRecordV1::Running { .. })
        )
    {
        let session = match state.pair_roles.get(&pair_digest) {
            Some(LocalEd25519YaoPairRoleRecordV1::Running { session, .. }) => *session,
            _ => unreachable!("running pair disappeared during failure handling"),
        };
        state.pair_roles.insert(
            pair_digest,
            LocalEd25519YaoPairRoleRecordV1::Burned {
                session,
                pair_digest,
            },
        );
    }
    result
}

fn execute_local_pair_deriver_b_inner_v1(
    topology_config: &LocalWorkerRoleConfigV1,
    state: &mut LocalEd25519YaoWorkerStateV1,
    mut authenticated: crate::LocalEd25519YaoAuthenticatedDeriverBPeerV1,
    peer: crate::local_ed25519_yao_stream::LocalEd25519YaoPairPeerContextV1,
    persist_before_network: LocalEd25519YaoPersistBeforeNetworkV1<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    let LocalWorkerRoleConfigV1::DeriverB(config) = topology_config else {
        return Err(io::Error::other("pair B execution requires Deriver B config").into());
    };
    let pair_digest = peer.pair_digest;
    let record = state
        .pair_roles
        .get(&pair_digest)
        .cloned()
        .ok_or_else(|| io::Error::other("Deriver B pair is not prepared"))?;
    let LocalEd25519YaoPairRoleRecordV1::Prepared {
        session,
        pair_digest: stored_pair_digest,
        pair_binding,
        tenant_root,
        input_digest,
        root_metadata_digest,
        expires_at_ms,
        input,
        receipt,
    } = record
    else {
        return Err(io::Error::other("Deriver B pair is not prepared").into());
    };
    if stored_pair_digest != pair_digest || session != peer.peer_receipt.session_bytes() {
        return Err(io::Error::other("Deriver B pair identity mismatch").into());
    }
    pair_binding.validate()?;
    tenant_root.validate_for_pair(&pair_binding)?;
    if local_pair_tenant_root_metadata_digest_v1(&tenant_root)? != root_metadata_digest
        || peer.peer_receipt.root_metadata_digest().bytes != root_metadata_digest
    {
        return Err(io::Error::other("Deriver B pair tenant-root context mismatch").into());
    }
    peer.peer_receipt.validate_for_pair(&pair_binding)?;
    verify_local_pair_readiness_receipt_v1(
        &peer.peer_receipt,
        local_pair_verifying_key_v1(&config.deriver_a_peer_verifying_key)?,
    )?;
    receipt.validate_for_pair(&pair_binding)?;
    receipt.validate_at(crate::local_now_unix_ms_v1()?)?;
    if peer.execution_id.into_bytes() == [0; 32] {
        return Err(io::Error::other("Deriver B pair execution id is empty").into());
    }
    let now_ms = crate::local_now_unix_ms_v1()?;
    if now_ms >= expires_at_ms {
        state.pair_roles.insert(
            pair_digest,
            LocalEd25519YaoPairRoleRecordV1::Expired {
                session,
                pair_digest,
            },
        );
        return Err(io::Error::other("Deriver B pair preparation expired").into());
    }
    let running_expires_at_ms = now_ms
        .checked_add(60_000)
        .ok_or_else(|| io::Error::other("Deriver B pair running expiry overflow"))?;
    state.pair_roles.insert(
        pair_digest,
        LocalEd25519YaoPairRoleRecordV1::Running {
            session,
            pair_digest,
            pair_binding: pair_binding.clone(),
            tenant_root: tenant_root.clone(),
            input_digest,
            root_metadata_digest,
            expires_at_ms: running_expires_at_ms,
            execution_id: peer.execution_id.into_bytes(),
            input: input.clone(),
            receipt: receipt.clone(),
        },
    );
    persist_before_network(state)?;
    let acceptance = sign_local_pair_start_acceptance_v1(
        Ed25519YaoDeriverRoleV1::DeriverB,
        session,
        pair_digest,
        peer.execution_id,
        root_metadata_digest,
        now_ms,
        running_expires_at_ms,
        &config.peer_signing_key,
    )?;
    authenticated.set_start_acceptance(acceptance)?;
    let private_key = deriver_input_private_key(&config.envelope_hpke_private_key)?;
    let coordinates = local_tenant_root_coordinates_for_context_v1(&tenant_root)?;
    let role_share = config.tenant_root_role_shares.resolve_for_context(
        &coordinates,
        &tenant_root,
        router_ab_core::TwoPartyDeriverRole::DeriverB,
    )?;
    let preface = prepare_local_deriver_b_target_v2(&tenant_root, &pair_binding, &role_share)?;
    let incoming_target_proof = authenticated
        .target_proof_a_to_b()
        .cloned()
        .ok_or_else(|| io::Error::other("Deriver B target-proof preface is missing"))?;
    let incoming_plaintext =
        open_local_deriver_b_target_proof_v2(&incoming_target_proof, private_key.as_bytes())?;
    let target_proof_peer_public_key =
        local_target_proof_public_key_v1(&config.target_proof_peer_public_key)?;
    let outbound_target_proof = seal_local_deriver_b_target_proof_v2(
        &tenant_root.outer_binding,
        preface.outbound_plaintext(),
        &target_proof_peer_public_key,
    )?;
    let server_contribution = complete_local_deriver_b_target_v2(
        preface,
        &incoming_target_proof,
        &incoming_plaintext,
        &tenant_root,
    )?;
    let (execution_result, completed_response) = match input.kind() {
        router_ab_core::Ed25519YaoInputKindV1::Activation => {
            let role_request =
                open_local_ed25519_yao_activation_deriver_b_input_v1(&input, &private_key)?;
            if role_request.binding != pair_binding.binding().clone() {
                return Err(io::Error::other("Deriver B pair activation binding mismatch").into());
            }
            let recipients = role_request.recipients;
            let (binding, role, initial_effective) =
                build_deriver_b_activation_from_effective_state(
                    state,
                    role_request,
                    server_contribution,
                )?;
            let (completion, completed_response) =
                match run_local_activation_deriver_b_authenticated_http_open_v2(
                    authenticated,
                    role,
                    outbound_target_proof,
                ) {
                    Ok(completion) => completion,
                    Err(error) => {
                        state.pair_roles.insert(
                            pair_digest,
                            LocalEd25519YaoPairRoleRecordV1::Burned {
                                session,
                                pair_digest,
                            },
                        );
                        return Err(Box::new(error));
                    }
                };
            let packages = seal_activation_output_v1(
                Ed25519YaoDeriverRoleV1::DeriverB,
                session,
                recipients,
                completion.final_transcript(),
                completion.client_package().as_bytes(),
                completion.signing_worker_package().as_bytes(),
            )?;
            if let Some(initial_effective) = initial_effective {
                let identity = initial_effective.identity().clone();
                if state
                    .deriver_b_effective
                    .insert(identity, initial_effective)
                    .is_some()
                {
                    return Err(io::Error::other(
                        "Deriver B effective identity was concurrently registered",
                    )
                    .into());
                }
            }
            (
                Ed25519YaoRoleExecutionV1::Activation(Ed25519YaoActivationRoleExecutionV1::new(
                    binding,
                    Ed25519YaoDeriverRoleV1::DeriverB,
                    completion.final_transcript(),
                    completion.client_commitment(),
                    completion.signing_worker_commitment(),
                    packages.client,
                    packages.signing_worker,
                )?),
                completed_response,
            )
        }
        router_ab_core::Ed25519YaoInputKindV1::Export => {
            let role_request =
                open_local_ed25519_yao_export_deriver_b_input_v1(&input, &private_key)?;
            if role_request.binding != pair_binding.binding().clone() {
                return Err(io::Error::other("Deriver B pair export binding mismatch").into());
            }
            let recipient = role_request.recipients;
            let (binding, role) =
                build_local_export_deriver_b_with_server_v1(role_request, server_contribution)?;
            let (completion, completed_response) =
                match run_local_export_deriver_b_authenticated_http_open_v2(
                    authenticated,
                    role,
                    outbound_target_proof,
                ) {
                    Ok(completion) => completion,
                    Err(error) => {
                        state.pair_roles.insert(
                            pair_digest,
                            LocalEd25519YaoPairRoleRecordV1::Burned {
                                session,
                                pair_digest,
                            },
                        );
                        return Err(Box::new(error));
                    }
                };
            let client_package = seal_export_output_v1(
                Ed25519YaoDeriverRoleV1::DeriverB,
                session,
                recipient,
                completion.final_transcript(),
                completion.export_package().as_bytes(),
            )?;
            (
                Ed25519YaoRoleExecutionV1::Export(Ed25519YaoExportRoleExecutionV1::new(
                    binding,
                    Ed25519YaoDeriverRoleV1::DeriverB,
                    completion.final_transcript(),
                    client_package,
                )?),
                completed_response,
            )
        }
        router_ab_core::Ed25519YaoInputKindV1::LaneMaterialization => {
            return Err(io::Error::other(
                "legacy local Deriver HTTP does not support authenticated lane dispatch",
            )
            .into());
        }
    };
    let serialized_execution = serde_json::to_vec(&execution_result)?;
    state.pair_roles.insert(
        pair_digest,
        LocalEd25519YaoPairRoleRecordV1::Completed {
            session,
            pair_digest,
            pair_binding,
            execution_id: peer.execution_id.into_bytes(),
            execution: Box::new(execution_result),
        },
    );
    completed_response.send_sealed_completion(&serialized_execution)?;
    Ok(())
}

fn classify_request(stream: &TcpStream) -> io::Result<LocalEd25519YaoRequestClassV1> {
    let mut buffer = [0_u8; 512];
    for _ in 0..250 {
        let bytes = stream.peek(&mut buffer)?;
        if let Some(line_end) = buffer[..bytes]
            .windows(2)
            .position(|window| window == b"\r\n")
        {
            let Ok(line) = std::str::from_utf8(&buffer[..line_end]) else {
                return Ok(LocalEd25519YaoRequestClassV1::Other);
            };
            let mut parts = line.split_whitespace();
            let method = parts.next().unwrap_or_default();
            let path = parts.next().unwrap_or_default();
            if method == "POST" && path == LOCAL_DERIVER_B_ED25519_YAO_PEER_PATH {
                return Ok(LocalEd25519YaoRequestClassV1::Peer);
            }
            return Ok(if is_yao_control_path(path) {
                LocalEd25519YaoRequestClassV1::Control
            } else {
                LocalEd25519YaoRequestClassV1::Other
            });
        }
        thread::sleep(Duration::from_millis(1));
    }
    Ok(LocalEd25519YaoRequestClassV1::Other)
}

fn is_yao_control_path(path: &str) -> bool {
    matches!(
        path,
        LOCAL_DERIVER_A_ED25519_YAO_PREPARE_PAIR_PATH
            | LOCAL_DERIVER_A_ED25519_YAO_EXECUTE_PAIR_PATH
            | LOCAL_DERIVER_A_ED25519_YAO_READ_PAIR_STATUS_PATH
            | LOCAL_DERIVER_A_ED25519_YAO_BURN_PAIR_PATH
            | LOCAL_DERIVER_B_ED25519_YAO_PREPARE_PAIR_PATH
            | LOCAL_DERIVER_B_ED25519_YAO_READ_PAIR_STATUS_PATH
            | LOCAL_DERIVER_B_ED25519_YAO_BURN_PAIR_PATH
            | LOCAL_DERIVER_B_ED25519_YAO_REFRESH_STAGE_PATH
            | LOCAL_DERIVER_B_ED25519_YAO_REFRESH_DELTA_PATH
            | LOCAL_DERIVER_B_ED25519_YAO_REFRESH_PROMOTE_PATH
            | LOCAL_DERIVER_B_ED25519_YAO_REFRESH_RESULT_PATH
            | LOCAL_DERIVER_A_ED25519_YAO_REFRESH_START_PATH
            | LOCAL_DERIVER_A_ED25519_YAO_REFRESH_PROMOTE_PATH
            | LOCAL_DERIVER_A_ED25519_YAO_REFRESH_CLIENT_PACKAGE_PATH
            | LOCAL_DERIVER_A_ED25519_YAO_REFRESH_SIGNING_WORKER_PACKAGE_PATH
            | LOCAL_DERIVER_B_ED25519_YAO_REFRESH_CLIENT_PACKAGE_PATH
            | LOCAL_DERIVER_B_ED25519_YAO_REFRESH_SIGNING_WORKER_PACKAGE_PATH
            | LOCAL_SIGNING_WORKER_ED25519_YAO_ACTIVATION_PACKAGES_PATH
            | LOCAL_SIGNING_WORKER_ED25519_YAO_RECOVERY_PROMOTE_PATH
            | LOCAL_SIGNING_WORKER_ED25519_YAO_REFRESH_DERIVER_A_PATH
            | LOCAL_SIGNING_WORKER_ED25519_YAO_REFRESH_DERIVER_B_PATH
            | LOCAL_SIGNING_WORKER_NORMAL_SIGNING_PREPARE_PATH
            | LOCAL_SIGNING_WORKER_NORMAL_SIGNING_PATH
    )
}

fn http_authority(url: &str) -> Result<&str, Box<dyn std::error::Error>> {
    let authority = url
        .strip_prefix("http://")
        .ok_or_else(|| io::Error::other("local Deriver URL must use http://"))?;
    if authority.is_empty() || authority.contains('/') {
        return Err(io::Error::other("local Deriver URL must contain only an authority").into());
    }
    Ok(authority)
}

fn deriver_input_private_key(
    value: &str,
) -> Result<LocalEd25519YaoRecipientPrivateKeyV1, Box<dyn std::error::Error>> {
    let bytes: [u8; 32] = hex::decode(value)?
        .try_into()
        .map_err(|_| io::Error::other("Deriver input HPKE private key must contain 32 bytes"))?;
    Ok(LocalEd25519YaoRecipientPrivateKeyV1::from_bytes(bytes))
}

fn public_refresh_a_completion(
    session: [u8; 32],
    completion: &ActivationDeriverACompletion,
) -> LocalEd25519YaoRoleCompletionV1 {
    let wire = completion.wire_byte_ledger();
    LocalEd25519YaoRoleCompletionV1::Activation {
        session_hex: hex::encode(session),
        transcript_hex: hex::encode(completion.final_transcript()),
        client_commitment_hex: hex::encode(completion.client_commitment()),
        signing_worker_commitment_hex: hex::encode(completion.signing_worker_commitment()),
        frame_count: completion.stream_metrics().frame_count(),
        deriver_a_to_b_transport_bytes: wire.deriver_a_to_b_transport_bytes(),
        deriver_b_to_a_transport_bytes: wire.deriver_b_to_a_transport_bytes(),
        total_ab_transport_bytes: wire.total_ab_transport_bytes(),
    }
}

fn public_deriver_b_completion(
    completion: &CompletedDeriverBRoleV1,
) -> Result<LocalEd25519YaoRoleCompletionV1, Box<dyn std::error::Error>> {
    match completion {
        CompletedDeriverBRoleV1::Refresh {
            binding,
            completion,
            ..
        } => Ok(LocalEd25519YaoRoleCompletionV1::Activation {
            deriver_a_to_b_transport_bytes: completion
                .wire_byte_ledger()
                .deriver_a_to_b_transport_bytes(),
            deriver_b_to_a_transport_bytes: completion
                .wire_byte_ledger()
                .deriver_b_to_a_transport_bytes(),
            total_ab_transport_bytes: completion.wire_byte_ledger().total_ab_transport_bytes(),
            session_hex: hex::encode(binding.ceremony().session_id.into_bytes()),
            transcript_hex: hex::encode(completion.final_transcript()),
            client_commitment_hex: hex::encode(completion.client_commitment()),
            signing_worker_commitment_hex: hex::encode(completion.signing_worker_commitment()),
            frame_count: completion.stream_metrics().frame_count(),
        }),
    }
}

fn invalid_worker_state(message: &'static str) -> RouterAbProtocolError {
    RouterAbProtocolError::new(RouterAbProtocolErrorCode::InvalidLifecycleState, message)
}

fn pair_conflict(message: &'static str) -> RouterAbProtocolError {
    RouterAbProtocolError::new(RouterAbProtocolErrorCode::ConflictingPair, message)
}

fn missing_pair_preparation() -> RouterAbProtocolError {
    RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::MissingPairPreparation,
        "pair role preparation is missing",
    )
}

fn pair_preparation_expired() -> RouterAbProtocolError {
    RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::PairPreparationExpired,
        "pair role preparation expired",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::scalar::Scalar;
    use router_ab_core::{
        Ed25519YaoCeremonyIdentityV1, Ed25519YaoEpochTransitionV1, Ed25519YaoInputKindV1,
        Ed25519YaoInputPairBindingV1, Ed25519YaoRefreshEpochsV1, Ed25519YaoSessionIdV1,
        Ed25519YaoStableKeyContextBindingV1, ExpensiveWorkKindV1, LifecycleScopeV1,
        MpcMaterialActivationRefV1, PublicDigest32, RootShareEpoch,
    };
    use signer_core::ed25519_yao_derivation::{
        derive_ed25519_yao_joint_refresh_delta_v1, Ed25519YaoDeriverARefreshDeltaContributionV1,
        Ed25519YaoDeriverAServerContributionV1, Ed25519YaoDeriverBRefreshDeltaContributionV1,
        Ed25519YaoDeriverBServerContributionV1,
    };

    #[test]
    fn pair_role_status_and_burn_missing_are_idempotent_without_claiming_execution() {
        let mut worker = LocalEd25519YaoWorkerStateV1::default();
        let lookup = CloudflareEd25519YaoPairLookupRequestV1 {
            session: [1; 32],
            pair_digest: [2; 32],
        };
        assert!(matches!(
            read_local_pair_role_status_v1(&mut worker, lookup).expect("missing status"),
            CloudflareEd25519YaoPairStatusResponseV1::Missing { .. }
        ));
        assert!(matches!(
            burn_local_pair_role_v1(&mut worker, lookup).expect("missing burn"),
            CloudflareEd25519YaoPairStatusResponseV1::Missing { .. }
        ));
    }

    #[test]
    fn pair_execute_route_is_classified_as_a_yao_control_request() {
        assert!(is_yao_control_path(
            LOCAL_DERIVER_A_ED25519_YAO_EXECUTE_PAIR_PATH
        ));
    }

    #[test]
    fn running_pair_burn_transitions_to_burned_for_exact_identity() {
        let binding = ceremony(
            7,
            Ed25519YaoOperationV1::Registration,
            ExpensiveWorkKindV1::RegistrationPrepare,
            8,
        );
        let session = binding.session_id.into_bytes();
        let input_a = Ed25519YaoEncryptedInputV1::new(
            Ed25519YaoInputKindV1::Activation,
            Ed25519YaoDeriverRoleV1::DeriverA,
            Ed25519YaoOperationV1::Registration,
            session,
            [7; 32],
            [0x51; 32],
            vec![0x61; 16],
        )
        .expect("A input");
        let input_b = Ed25519YaoEncryptedInputV1::new(
            Ed25519YaoInputKindV1::Activation,
            Ed25519YaoDeriverRoleV1::DeriverB,
            Ed25519YaoOperationV1::Registration,
            session,
            [7; 32],
            [0x52; 32],
            vec![0x62; 16],
        )
        .expect("B input");
        let pair_binding = Ed25519YaoInputPairBindingV1::from_inputs(
            Ed25519YaoCeremonyIdentityV1::from_binding(binding).expect("pair identity"),
            &input_a,
            &input_b,
            PublicDigest32::new([0x71; 32]),
            PublicDigest32::new([0x72; 32]),
        )
        .expect("pair binding");
        let pair_digest = pair_binding.pair_digest().bytes;
        let mut state = LocalEd25519YaoWorkerStateV1::default();
        let root_metadata_digest = [0x81; 32];
        let mut lifecycle = LocalEd25519YaoPairLifecycleV1::default();
        let receipt = lifecycle
            .prepare_role(
                Ed25519YaoDeriverRoleV1::DeriverB,
                &pair_binding,
                input_b.clone(),
                root_metadata_digest,
                1,
                100,
                LocalEd25519YaoPairSigningKeysV1 {
                    deriver_a: [0x91; 32],
                    deriver_b: [0x91; 32],
                },
            )
            .expect("prepared B pair");
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x91; 32]);
        verify_local_pair_readiness_receipt_v1(&receipt, signing_key.verifying_key().to_bytes())
            .expect("receipt uses the canonical local peer seed");
        let input_digest = router_ab_core::ed25519_yao_encrypted_input_digest_v1(&input_b)
            .expect("input digest")
            .bytes;
        state.pair_roles.insert(
            pair_digest,
            LocalEd25519YaoPairRoleRecordV1::Running {
                session: pair_binding.session(),
                pair_digest,
                pair_binding: Box::new(pair_binding.clone()),
                tenant_root: Box::new(test_tenant_root_context(&pair_binding)),
                input_digest,
                root_metadata_digest,
                expires_at_ms: 100,
                execution_id: [0x91; 32],
                input: Box::new(input_b),
                receipt: Box::new(receipt),
            },
        );
        let lookup = CloudflareEd25519YaoPairLookupRequestV1 {
            session: pair_binding.session(),
            pair_digest,
        };
        assert!(matches!(
            burn_local_pair_role_v1(&mut state, lookup).expect("running burn"),
            CloudflareEd25519YaoPairStatusResponseV1::Burned { .. }
        ));
        assert!(matches!(
            state.pair_roles.get(&pair_digest),
            Some(LocalEd25519YaoPairRoleRecordV1::Burned { .. })
        ));
    }

    fn test_tenant_root_context(
        pair_binding: &Ed25519YaoInputPairBindingV1,
    ) -> router_ab_cloudflare::CloudflareEd25519YaoTenantRootContextV2 {
        let pair_session = router_ab_core::Ed25519YaoPairSessionIdV2::new(pair_binding.session())
            .expect("pair session");
        let outer_binding = router_ab_core::Ed25519YaoOuterBindingV2::new(
            pair_session,
            pair_binding.binding().stable_key_context_binding,
            PublicDigest32::new([0x41; 32]),
            [0x42; 16],
            1,
            100,
        )
        .expect("outer binding");
        router_ab_cloudflare::CloudflareEd25519YaoTenantRootContextV2 {
            custody_binding: router_ab_cloudflare::CloudflareTenantRootCustodyBindingWireV1 {
                activation_receipt_b64u: "AQ".to_owned(),
                operation_id: router_ab_core::TenantRootDerivationOperationIdV1::from_bytes(
                    [0x43; 16],
                )
                .expect("operation id"),
                session_id: router_ab_core::TenantRootDerivationSessionIdV1::from_bytes(
                    [0x44; 16],
                )
                .expect("session id"),
                nonce: router_ab_core::TenantRootDerivationNonceV1::from_bytes([0x45; 32])
                    .expect("nonce"),
                issued_at_ms: 1,
                expires_at_ms: 100,
            },
            outer_binding,
            application: router_ab_core::RouterAbEd25519YaoApplicationBindingFactsV1::new(
                pair_binding.binding().lifecycle.account_id.clone(),
                "local-key",
                "local-root",
                1,
            )
            .expect("application"),
            participant_ids: [1, 2],
        }
    }

    #[test]
    fn pair_role_durable_decode_rejects_duplicate_identities() {
        let records = vec![
            LocalEd25519YaoPairRoleRecordV1::Burned {
                session: [1; 32],
                pair_digest: [2; 32],
            },
            LocalEd25519YaoPairRoleRecordV1::Expired {
                session: [1; 32],
                pair_digest: [2; 32],
            },
        ];
        assert!(decode_pair_role_records(LocalServiceRoleV1::DeriverA, records).is_err());
    }

    #[test]
    fn two_registration_identities_select_exact_recovery_refresh_export_and_promotion_state() {
        let epoch_one = Ed25519YaoStateEpochV1::new(1).expect("epoch one");
        let epoch_two = Ed25519YaoStateEpochV1::new(2).expect("epoch two");
        let mut worker = LocalEd25519YaoWorkerStateV1::default();
        for identity_tag in [1_u8, 2_u8] {
            let registration = ceremony(
                identity_tag,
                Ed25519YaoOperationV1::Registration,
                ExpensiveWorkKindV1::RegistrationPrepare,
                identity_tag,
            );
            let identity = LocalEd25519YaoEffectiveIdentityV1::from_binding(&registration);
            worker.deriver_a_effective.insert(
                identity.clone(),
                LocalEd25519YaoDeriverAEffectiveStateV1::from_initial(
                    &registration,
                    epoch_one,
                    server_a(identity_tag, u64::from(identity_tag) * 100),
                )
                .expect("Deriver A registration"),
            );
            worker.deriver_b_effective.insert(
                identity,
                LocalEd25519YaoDeriverBEffectiveStateV1::from_initial(
                    &registration,
                    epoch_one,
                    server_b(identity_tag + 10, u64::from(identity_tag) * 200),
                )
                .expect("Deriver B registration"),
            );
        }
        assert_eq!(worker.deriver_a_effective.len(), 2);
        assert_eq!(worker.deriver_b_effective.len(), 2);

        for (operation, work_kind, session_tag) in [
            (
                Ed25519YaoOperationV1::Recovery,
                ExpensiveWorkKindV1::Recovery,
                3,
            ),
            (
                Ed25519YaoOperationV1::Export,
                ExpensiveWorkKindV1::KeyExport,
                4,
            ),
        ] {
            let binding = ceremony(1, operation, work_kind, session_tag);
            let identity = LocalEd25519YaoEffectiveIdentityV1::from_binding(&binding);
            assert_eq!(
                contribution_a_y(worker.deriver_a_effective[&identity].active_contribution())[0],
                1
            );
            assert_eq!(
                contribution_b_y(worker.deriver_b_effective[&identity].active_contribution())[0],
                11
            );
        }

        let transition =
            Ed25519YaoEpochTransitionV1::new(epoch_one, epoch_two).expect("transition");
        let registration_material_activation = ceremony(
            1,
            Ed25519YaoOperationV1::Registration,
            ExpensiveWorkKindV1::RegistrationPrepare,
            1,
        )
        .material_activation;
        let mut refresh_ceremony = ceremony(
            1,
            Ed25519YaoOperationV1::Refresh,
            ExpensiveWorkKindV1::ServerShareRefresh,
            5,
        );
        refresh_ceremony.material_activation = registration_material_activation;
        let refresh = Ed25519YaoRefreshBindingV1::new(
            refresh_ceremony,
            [0x71; 32],
            Ed25519YaoRefreshEpochsV1 {
                deriver_a: transition,
                deriver_b: transition,
                signing_worker: transition,
            },
        )
        .expect("refresh binding");
        let refresh_identity = LocalEd25519YaoEffectiveIdentityV1::from_binding(refresh.ceremony());
        let delta = derive_ed25519_yao_joint_refresh_delta_v1(
            Ed25519YaoDeriverARefreshDeltaContributionV1::from_secret_bytes(
                little_endian_u8(1),
                Scalar::from(5_u64).to_bytes(),
            )
            .expect("A delta"),
            Ed25519YaoDeriverBRefreshDeltaContributionV1::from_secret_bytes(
                little_endian_u8(2),
                Scalar::from(7_u64).to_bytes(),
            )
            .expect("B delta"),
        )
        .expect("joint delta");
        let prepared_a = worker.deriver_a_effective[&refresh_identity]
            .prepare_refresh(&refresh, &delta)
            .expect("prepare A");
        let prepared_b = worker.deriver_b_effective[&refresh_identity]
            .prepare_refresh(&refresh, &delta)
            .expect("prepare B");
        worker
            .deriver_a_effective
            .get_mut(&refresh_identity)
            .expect("first A identity")
            .promote(prepared_a)
            .expect("promote A");
        worker
            .deriver_b_effective
            .get_mut(&refresh_identity)
            .expect("first B identity")
            .promote(prepared_b)
            .expect("promote B");
        assert_eq!(
            worker.deriver_a_effective[&refresh_identity].active_epoch(),
            epoch_two
        );
        assert_eq!(
            worker.deriver_b_effective[&refresh_identity].active_epoch(),
            epoch_two
        );

        let second = LocalEd25519YaoEffectiveIdentityV1::from_binding(&ceremony(
            2,
            Ed25519YaoOperationV1::Export,
            ExpensiveWorkKindV1::KeyExport,
            6,
        ));
        assert_eq!(
            worker.deriver_a_effective[&second].active_epoch(),
            epoch_one
        );
        assert_eq!(
            worker.deriver_b_effective[&second].active_epoch(),
            epoch_one
        );
        assert_eq!(
            contribution_a_y(worker.deriver_a_effective[&second].active_contribution())[0],
            2
        );
        assert_eq!(
            contribution_b_y(worker.deriver_b_effective[&second].active_contribution())[0],
            12
        );
    }

    #[test]
    fn deriver_durable_state_round_trip_is_role_bound() {
        let binding = ceremony(
            7,
            Ed25519YaoOperationV1::Registration,
            ExpensiveWorkKindV1::RegistrationPrepare,
            8,
        );
        let identity = LocalEd25519YaoEffectiveIdentityV1::from_binding(&binding);
        let mut worker = LocalEd25519YaoWorkerStateV1::default();
        worker.deriver_a_effective.insert(
            identity.clone(),
            LocalEd25519YaoDeriverAEffectiveStateV1::from_initial(
                &binding,
                Ed25519YaoStateEpochV1::new(3).expect("state epoch"),
                server_a(9, 10),
            )
            .expect("Deriver A state"),
        );

        let encoded = worker
            .encode_durable_state_for_role_v1(LocalServiceRoleV1::DeriverA)
            .expect("encode Deriver A state");
        let restored = LocalEd25519YaoWorkerStateV1::decode_durable_state_for_role_v1(
            LocalServiceRoleV1::DeriverA,
            &encoded,
        )
        .expect("restore Deriver A state");
        assert_eq!(restored.deriver_a_effective.len(), 1);
        assert_eq!(
            restored.deriver_a_effective[&identity].active_epoch().get(),
            3
        );
        assert_eq!(
            contribution_a_y(restored.deriver_a_effective[&identity].active_contribution()),
            little_endian_u8(9),
        );
        assert!(
            LocalEd25519YaoWorkerStateV1::decode_durable_state_for_role_v1(
                LocalServiceRoleV1::DeriverB,
                &encoded,
            )
            .is_err()
        );
    }

    fn ceremony(
        identity_tag: u8,
        operation: Ed25519YaoOperationV1,
        work_kind: ExpensiveWorkKindV1,
        session_tag: u8,
    ) -> Ed25519YaoCeremonyBindingV1 {
        Ed25519YaoCeremonyBindingV1::new(
            LifecycleScopeV1::new(
                format!("lifecycle-{identity_tag}-{session_tag}"),
                work_kind,
                RootShareEpoch::new(format!("root-epoch-{identity_tag}")).expect("root epoch"),
                format!("account-{identity_tag}"),
                format!("wallet-session-{identity_tag}"),
                format!("signer-set-{identity_tag}"),
                "signing-worker-1",
            )
            .expect("lifecycle"),
            operation,
            Ed25519YaoSessionIdV1::new([session_tag; 32]).expect("session"),
            Ed25519YaoStableKeyContextBindingV1::new([identity_tag; 32]),
            MpcMaterialActivationRefV1::new(
                format!("activation-{identity_tag}-{session_tag}"),
                format!("capability-{identity_tag}"),
                format!("account-{identity_tag}"),
                format!("key-{identity_tag}"),
                format!("lifecycle-{identity_tag}-{session_tag}"),
                "signing-worker-1",
            )
            .expect("material activation"),
        )
        .expect("ceremony")
    }

    fn little_endian_u8(value: u8) -> [u8; 32] {
        let mut bytes = [0_u8; 32];
        bytes[0] = value;
        bytes
    }

    fn server_a(y: u8, tau: u64) -> Ed25519YaoDeriverAServerContributionV1 {
        Ed25519YaoDeriverAServerContributionV1::from_secret_bytes(
            little_endian_u8(y),
            Scalar::from(tau).to_bytes(),
        )
    }

    fn server_b(y: u8, tau: u64) -> Ed25519YaoDeriverBServerContributionV1 {
        Ed25519YaoDeriverBServerContributionV1::from_secret_bytes(
            little_endian_u8(y),
            Scalar::from(tau).to_bytes(),
        )
    }

    fn contribution_a_y(contribution: Ed25519YaoDeriverAServerContributionV1) -> [u8; 32] {
        contribution.into_parts().0.into_bytes()
    }

    fn contribution_b_y(contribution: Ed25519YaoDeriverBServerContributionV1) -> [u8; 32] {
        contribution.into_parts().0.into_bytes()
    }
}
