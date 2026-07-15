use crate::authenticate_local_ed25519_yao_deriver_b_peer_http_v1;
use crate::local_ed25519_yao_refresh::LocalEd25519YaoEffectiveIdentityV1;
use crate::local_ed25519_yao_signing_worker::LocalEd25519YaoSigningWorkerDurableStateV1;
use crate::{
    build_local_activation_deriver_a_with_server_v1,
    build_local_activation_deriver_b_with_server_v1, build_local_export_deriver_a_with_server_v1,
    build_local_export_deriver_b_with_server_v1, build_local_refresh_deriver_a_v1,
    build_local_refresh_deriver_b_v1, derive_local_ed25519_yao_deriver_a_initial_contribution_v1,
    derive_local_ed25519_yao_deriver_b_initial_contribution_v1,
    derive_local_ed25519_yao_joint_refresh_delta_v1,
    generate_local_ed25519_yao_deriver_a_refresh_delta_v1,
    generate_local_ed25519_yao_deriver_b_refresh_delta_v1, local_dev_http_error_body_v1,
    local_ed25519_yao_refresh_binding_digest_v1, local_router_ab_internal_service_auth_secret_v1,
    open_local_ed25519_yao_activation_deriver_a_input_v1,
    open_local_ed25519_yao_activation_deriver_b_input_v1,
    open_local_ed25519_yao_export_deriver_a_input_v1,
    open_local_ed25519_yao_export_deriver_b_input_v1,
    open_local_ed25519_yao_refresh_deriver_a_input_v1,
    open_local_ed25519_yao_refresh_deriver_b_input_v1, read_local_dev_http_request_v1,
    require_local_dev_internal_service_auth_v1, run_local_activation_deriver_a_http_v1,
    run_local_activation_deriver_b_authenticated_http_v1, run_local_export_deriver_a_http_v1,
    run_local_export_deriver_b_authenticated_http_v1, seal_local_ed25519_yao_package_v1,
    write_local_dev_http_response_v1, Ed25519YaoDeriverRoleV1, Ed25519YaoEncryptedInputV1,
    Ed25519YaoEncryptedPackageV1, Ed25519YaoPackageKindV1,
    LocalEd25519YaoActivationDeriverARequestV1, LocalEd25519YaoActivationDeriverBRequestV1,
    LocalEd25519YaoActivationRecipientsV1, LocalEd25519YaoDeriverAEffectiveStateV1,
    LocalEd25519YaoDeriverAPreparedRefreshV1, LocalEd25519YaoDeriverARefreshDeltaWireV1,
    LocalEd25519YaoDeriverBEffectiveStateV1, LocalEd25519YaoDeriverBPreparedRefreshV1,
    LocalEd25519YaoDeriverBRefreshDeltaWireV1, LocalEd25519YaoEncryptedRefreshInputV1,
    LocalEd25519YaoExportRecipientV1, LocalEd25519YaoRecipientPrivateKeyV1,
    LocalEd25519YaoRefreshDeriverBRequestV1, LocalEd25519YaoSigningWorkerPackageDeliveryV1,
    LocalEd25519YaoSigningWorkerRecoveryPromotionRequestV1,
    LocalEd25519YaoSigningWorkerRefreshPackageDeliveryV1, LocalEd25519YaoSigningWorkerStateV1,
    LocalWorkerRoleConfigV1, LOCAL_DERIVER_A_ED25519_YAO_ACTIVATION_CLIENT_PACKAGE_PATH,
    LOCAL_DERIVER_A_ED25519_YAO_ACTIVATION_SIGNING_WORKER_PACKAGE_PATH,
    LOCAL_DERIVER_A_ED25519_YAO_ACTIVATION_START_PATH,
    LOCAL_DERIVER_A_ED25519_YAO_EXPORT_CLIENT_PACKAGE_PATH,
    LOCAL_DERIVER_A_ED25519_YAO_EXPORT_START_PATH,
    LOCAL_DERIVER_A_ED25519_YAO_REFRESH_CLIENT_PACKAGE_PATH,
    LOCAL_DERIVER_A_ED25519_YAO_REFRESH_PROMOTE_PATH,
    LOCAL_DERIVER_A_ED25519_YAO_REFRESH_SIGNING_WORKER_PACKAGE_PATH,
    LOCAL_DERIVER_A_ED25519_YAO_REFRESH_START_PATH, LOCAL_DERIVER_A_ED25519_YAO_RESULT_PATH,
    LOCAL_DERIVER_B_ED25519_YAO_ACTIVATION_CLIENT_PACKAGE_PATH,
    LOCAL_DERIVER_B_ED25519_YAO_ACTIVATION_SIGNING_WORKER_PACKAGE_PATH,
    LOCAL_DERIVER_B_ED25519_YAO_ACTIVATION_STAGE_PATH,
    LOCAL_DERIVER_B_ED25519_YAO_EXPORT_CLIENT_PACKAGE_PATH,
    LOCAL_DERIVER_B_ED25519_YAO_EXPORT_STAGE_PATH, LOCAL_DERIVER_B_ED25519_YAO_PEER_PATH,
    LOCAL_DERIVER_B_ED25519_YAO_REFRESH_CLIENT_PACKAGE_PATH,
    LOCAL_DERIVER_B_ED25519_YAO_REFRESH_DELTA_PATH,
    LOCAL_DERIVER_B_ED25519_YAO_REFRESH_PROMOTE_PATH,
    LOCAL_DERIVER_B_ED25519_YAO_REFRESH_SIGNING_WORKER_PACKAGE_PATH,
    LOCAL_DERIVER_B_ED25519_YAO_REFRESH_STAGE_PATH, LOCAL_DERIVER_B_ED25519_YAO_RESULT_PATH,
    LOCAL_HTTP_SERVICE_BINDING_TIMEOUT_MS_V1, LOCAL_ROUTER_AB_INTERNAL_SERVICE_AUTH_HEADER_V1,
    LOCAL_SIGNING_WORKER_ED25519_YAO_ACTIVATION_DERIVER_A_PATH,
    LOCAL_SIGNING_WORKER_ED25519_YAO_ACTIVATION_DERIVER_B_PATH,
    LOCAL_SIGNING_WORKER_ED25519_YAO_RECOVERY_PROMOTE_PATH,
    LOCAL_SIGNING_WORKER_ED25519_YAO_REFRESH_DERIVER_A_PATH,
    LOCAL_SIGNING_WORKER_ED25519_YAO_REFRESH_DERIVER_B_PATH,
    LOCAL_SIGNING_WORKER_NORMAL_SIGNING_PATH, LOCAL_SIGNING_WORKER_NORMAL_SIGNING_PREPARE_PATH,
};
use router_ab_core::{
    Ed25519YaoCeremonyBindingV1, Ed25519YaoOperationV1, Ed25519YaoRefreshBindingV1,
    Ed25519YaoStateEpochV1, LocalServiceRoleV1, RouterAbProtocolError, RouterAbProtocolErrorCode,
    RouterAbProtocolResult,
};
use router_ab_ed25519_yao::relay::{
    ActivationDeriverACompletion, ActivationDeriverBCompletion, ExportDeriverACompletion,
    ExportDeriverBCompletion,
};
use router_ab_ed25519_yao::{ActivationDeriverA, ActivationDeriverB, ExportDeriverB};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{self, Read, Write},
    net::{Shutdown, TcpStream},
    thread,
    time::Duration,
};
use zeroize::{Zeroize, Zeroizing};

enum PendingDeriverBRoleV1 {
    Activation {
        session: [u8; 32],
        recipients: LocalEd25519YaoActivationRecipientsV1,
        initial_effective: Option<LocalEd25519YaoDeriverBEffectiveStateV1>,
        role: ActivationDeriverB,
    },
    Refresh {
        binding: Ed25519YaoRefreshBindingV1,
        binding_digest: [u8; 32],
        recipients: LocalEd25519YaoActivationRecipientsV1,
        prepared: LocalEd25519YaoDeriverBPreparedRefreshV1,
        role: ActivationDeriverB,
    },
    Export {
        session: [u8; 32],
        recipient: LocalEd25519YaoExportRecipientV1,
        role: ExportDeriverB,
    },
}

impl PendingDeriverBRoleV1 {
    fn session(&self) -> [u8; 32] {
        match self {
            Self::Activation { session, .. } | Self::Export { session, .. } => *session,
            Self::Refresh { binding, .. } => binding.ceremony().session_id.into_bytes(),
        }
    }
}

enum CompletedDeriverBRoleV1 {
    Activation {
        session: [u8; 32],
        packages: EncryptedActivationPackagesV1,
        completion: Box<ActivationDeriverBCompletion>,
    },
    Refresh {
        binding: Ed25519YaoRefreshBindingV1,
        binding_digest: [u8; 32],
        packages: EncryptedActivationPackagesV1,
        promotion: DeriverBRefreshPromotionStateV1,
        completion: Box<ActivationDeriverBCompletion>,
    },
    Export {
        session: [u8; 32],
        client_package: Ed25519YaoEncryptedPackageV1,
        completion: Box<ExportDeriverBCompletion>,
    },
}

enum CompletedDeriverARoleV1 {
    Activation {
        session: [u8; 32],
        packages: EncryptedActivationPackagesV1,
        completion: Box<ActivationDeriverACompletion>,
    },
    Refresh {
        binding: Ed25519YaoRefreshBindingV1,
        binding_digest: [u8; 32],
        packages: EncryptedActivationPackagesV1,
        promotion: DeriverARefreshPromotionStateV1,
        completion: Box<ActivationDeriverACompletion>,
    },
    Export {
        session: [u8; 32],
        client_package: Ed25519YaoEncryptedPackageV1,
        completion: Box<ExportDeriverACompletion>,
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
    },
    DeriverB {
        effective: Vec<&'state LocalEd25519YaoDeriverBEffectiveStateV1>,
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
    },
    DeriverB {
        effective: Vec<LocalEd25519YaoDeriverBEffectiveStateV1>,
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
            },
            LocalServiceRoleV1::DeriverB => LocalEd25519YaoDurableRoleStateRefV1::DeriverB {
                effective: self.deriver_b_effective.values().collect(),
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
                LocalEd25519YaoDurableRoleStateV1::DeriverA { effective },
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
            }
            (
                LocalServiceRoleV1::DeriverB,
                LocalEd25519YaoDurableRoleStateV1::DeriverB { effective },
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

fn build_deriver_a_activation_from_effective_state(
    config: &crate::LocalDeriverAWorkerConfigV1,
    state: &LocalEd25519YaoWorkerStateV1,
    request: LocalEd25519YaoActivationDeriverARequestV1,
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
            let role_contribution = derive_local_ed25519_yao_deriver_a_initial_contribution_v1(
                config,
                &request.application_binding,
                request.participant_ids,
            )?;
            let state_contribution = derive_local_ed25519_yao_deriver_a_initial_contribution_v1(
                config,
                &request.application_binding,
                request.participant_ids,
            )?;
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
            let contribution = state
                .deriver_a_effective
                .get(&identity)
                .ok_or_else(|| {
                    invalid_worker_state(
                        "Deriver A recovery requires active Yao state for this identity",
                    )
                })?
                .active_contribution();
            let (binding, role) =
                build_local_activation_deriver_a_with_server_v1(request, contribution)?;
            Ok((binding, role, None))
        }
        Ed25519YaoOperationV1::Refresh | Ed25519YaoOperationV1::Export => Err(
            invalid_worker_state("Deriver A activation request selected an invalid operation"),
        ),
    }
}

fn build_deriver_b_activation_from_effective_state(
    config: &crate::LocalDeriverBWorkerConfigV1,
    state: &LocalEd25519YaoWorkerStateV1,
    request: LocalEd25519YaoActivationDeriverBRequestV1,
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
            let role_contribution = derive_local_ed25519_yao_deriver_b_initial_contribution_v1(
                config,
                &request.application_binding,
                request.participant_ids,
            )?;
            let state_contribution = derive_local_ed25519_yao_deriver_b_initial_contribution_v1(
                config,
                &request.application_binding,
                request.participant_ids,
            )?;
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
            let contribution = state
                .deriver_b_effective
                .get(&identity)
                .ok_or_else(|| {
                    invalid_worker_state(
                        "Deriver B recovery requires active Yao state for this identity",
                    )
                })?
                .active_contribution();
            let (binding, role) =
                build_local_activation_deriver_b_with_server_v1(request, contribution)?;
            Ok((binding, role, None))
        }
        Ed25519YaoOperationV1::Refresh | Ed25519YaoOperationV1::Export => Err(
            invalid_worker_state("Deriver B activation request selected an invalid operation"),
        ),
    }
}

pub enum LocalEd25519YaoConnectionDispatchV1 {
    Handled,
    Unhandled(TcpStream),
}

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
    Export {
        session_hex: String,
        transcript_hex: String,
        frame_count: u32,
        deriver_a_to_b_transport_bytes: u64,
        deriver_b_to_a_transport_bytes: u64,
        total_ab_transport_bytes: u64,
    },
}

pub fn dispatch_local_ed25519_yao_connection_v1(
    mut stream: TcpStream,
    config: &LocalWorkerRoleConfigV1,
    state: &mut LocalEd25519YaoWorkerStateV1,
) -> Result<LocalEd25519YaoConnectionDispatchV1, Box<dyn std::error::Error>> {
    match classify_request(&stream)? {
        LocalEd25519YaoRequestClassV1::Peer if config.role() == LocalServiceRoleV1::DeriverB => {
            handle_deriver_b_peer_stream(stream, state)?;
            return Ok(LocalEd25519YaoConnectionDispatchV1::Handled);
        }
        LocalEd25519YaoRequestClassV1::Control => {}
        LocalEd25519YaoRequestClassV1::Peer | LocalEd25519YaoRequestClassV1::Other => {
            return Ok(LocalEd25519YaoConnectionDispatchV1::Unhandled(stream));
        }
    }

    let mut request = read_local_dev_http_request_v1(&mut stream)?;
    let result = handle_yao_control_request(&mut stream, config, state, &request);
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
) -> Result<(), Box<dyn std::error::Error>> {
    require_local_dev_internal_service_auth_v1(request).map_err(io::Error::other)?;
    match (config, request.path.as_str()) {
        (
            LocalWorkerRoleConfigV1::DeriverB(config),
            LOCAL_DERIVER_B_ED25519_YAO_ACTIVATION_STAGE_PATH,
        ) => {
            let envelope = serde_json::from_slice::<Ed25519YaoEncryptedInputV1>(&request.body)?;
            let private_key = deriver_input_private_key(&config.envelope_hpke_private_key)?;
            let role_request =
                open_local_ed25519_yao_activation_deriver_b_input_v1(&envelope, &private_key)?;
            require_empty_pending_b(state)?;
            let recipients = role_request.recipients;
            let (binding, role, initial_effective) =
                build_deriver_b_activation_from_effective_state(config, state, role_request)?;
            consume_deriver_b_session(state, binding.session_id.into_bytes())?;
            state.completed_deriver_b = None;
            state.pending_deriver_b = Some(PendingDeriverBRoleV1::Activation {
                session: binding.session_id.into_bytes(),
                recipients,
                initial_effective,
                role,
            });
            write_local_dev_http_response_v1(stream, 200, "{\"status\":\"staged\"}")
        }
        (
            LocalWorkerRoleConfigV1::DeriverB(config),
            LOCAL_DERIVER_B_ED25519_YAO_EXPORT_STAGE_PATH,
        ) => {
            let envelope = serde_json::from_slice::<Ed25519YaoEncryptedInputV1>(&request.body)?;
            let private_key = deriver_input_private_key(&config.envelope_hpke_private_key)?;
            let role_request =
                open_local_ed25519_yao_export_deriver_b_input_v1(&envelope, &private_key)?;
            require_empty_pending_b(state)?;
            let identity = LocalEd25519YaoEffectiveIdentityV1::from_binding(&role_request.binding);
            let recipient = role_request.recipients;
            let contribution = state
                .deriver_b_effective
                .get(&identity)
                .ok_or_else(|| {
                    io::Error::other("Deriver B export requires active Yao state for this identity")
                })?
                .active_contribution();
            let (binding, role) =
                build_local_export_deriver_b_with_server_v1(role_request, contribution)?;
            consume_deriver_b_session(state, binding.session_id.into_bytes())?;
            state.completed_deriver_b = None;
            state.pending_deriver_b = Some(PendingDeriverBRoleV1::Export {
                session: binding.session_id.into_bytes(),
                recipient,
                role,
            });
            write_local_dev_http_response_v1(stream, 200, "{\"status\":\"staged\"}")
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
            LOCAL_DERIVER_A_ED25519_YAO_ACTIVATION_START_PATH,
        ) => {
            let envelope = serde_json::from_slice::<Ed25519YaoEncryptedInputV1>(&request.body)?;
            let private_key = deriver_input_private_key(&config.envelope_hpke_private_key)?;
            let role_request =
                open_local_ed25519_yao_activation_deriver_a_input_v1(&envelope, &private_key)?;
            let recipients = role_request.recipients;
            let (binding, role, initial_effective) =
                build_deriver_a_activation_from_effective_state(config, state, role_request)?;
            let session = binding.session_id.into_bytes();
            consume_deriver_a_session(state, session)?;
            state.completed_deriver_a = None;
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
            let receipt = public_activation_a_completion(session, &completion);
            if let Some(initial_effective) = initial_effective {
                let identity = initial_effective.identity().clone();
                if state
                    .deriver_a_effective
                    .insert(identity, initial_effective)
                    .is_some()
                {
                    return Err(io::Error::other(
                        "Deriver A effective identity was concurrently registered",
                    )
                    .into());
                }
            }
            state.completed_deriver_a = Some(CompletedDeriverARoleV1::Activation {
                session,
                packages,
                completion: Box::new(completion),
            });
            write_local_dev_http_response_v1(stream, 200, &serde_json::to_string(&receipt)?)
        }
        (
            LocalWorkerRoleConfigV1::DeriverA(config),
            LOCAL_DERIVER_A_ED25519_YAO_EXPORT_START_PATH,
        ) => {
            let envelope = serde_json::from_slice::<Ed25519YaoEncryptedInputV1>(&request.body)?;
            let private_key = deriver_input_private_key(&config.envelope_hpke_private_key)?;
            let role_request =
                open_local_ed25519_yao_export_deriver_a_input_v1(&envelope, &private_key)?;
            let identity = LocalEd25519YaoEffectiveIdentityV1::from_binding(&role_request.binding);
            let recipient = role_request.recipients;
            let contribution = state
                .deriver_a_effective
                .get(&identity)
                .ok_or_else(|| {
                    io::Error::other("Deriver A export requires active Yao state for this identity")
                })?
                .active_contribution();
            let (binding, role) =
                build_local_export_deriver_a_with_server_v1(role_request, contribution)?;
            let session = binding.session_id.into_bytes();
            consume_deriver_a_session(state, session)?;
            state.completed_deriver_a = None;
            let completion = run_local_export_deriver_a_http_v1(
                http_authority(&config.deriver_b_url)?,
                session,
                &local_router_ab_internal_service_auth_secret_v1(),
                role,
            )?;
            let client_package = seal_export_output_v1(
                Ed25519YaoDeriverRoleV1::DeriverA,
                session,
                recipient,
                completion.final_transcript(),
                completion.export_package().as_bytes(),
            )?;
            let receipt = public_export_a_completion(session, &completion);
            state.completed_deriver_a = Some(CompletedDeriverARoleV1::Export {
                session,
                client_package,
                completion: Box::new(completion),
            });
            write_local_dev_http_response_v1(stream, 200, &serde_json::to_string(&receipt)?)
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
            let receipt = public_activation_a_completion(session, &completion);
            state.completed_deriver_a = Some(CompletedDeriverARoleV1::Refresh {
                binding,
                binding_digest,
                packages,
                promotion: DeriverARefreshPromotionStateV1::Prepared(prepared),
                completion: Box::new(completion),
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
        (LocalWorkerRoleConfigV1::DeriverA(_), LOCAL_DERIVER_A_ED25519_YAO_RESULT_PATH) => {
            let receipt = state
                .completed_deriver_a
                .as_ref()
                .map(public_deriver_a_completion)
                .ok_or_else(|| io::Error::other("no completed Deriver A Yao ceremony"))?;
            write_local_dev_http_response_v1(stream, 200, &serde_json::to_string(&receipt)?)
        }
        (LocalWorkerRoleConfigV1::DeriverB(_), LOCAL_DERIVER_B_ED25519_YAO_RESULT_PATH) => {
            let receipt = state
                .completed_deriver_b
                .as_ref()
                .map(public_deriver_b_completion)
                .ok_or_else(|| io::Error::other("no completed Deriver B Yao ceremony"))?;
            write_local_dev_http_response_v1(stream, 200, &serde_json::to_string(&receipt)?)
        }
        (
            LocalWorkerRoleConfigV1::DeriverA(_),
            path @ (LOCAL_DERIVER_A_ED25519_YAO_ACTIVATION_CLIENT_PACKAGE_PATH
            | LOCAL_DERIVER_A_ED25519_YAO_ACTIVATION_SIGNING_WORKER_PACKAGE_PATH
            | LOCAL_DERIVER_A_ED25519_YAO_REFRESH_CLIENT_PACKAGE_PATH
            | LOCAL_DERIVER_A_ED25519_YAO_REFRESH_SIGNING_WORKER_PACKAGE_PATH
            | LOCAL_DERIVER_A_ED25519_YAO_EXPORT_CLIENT_PACKAGE_PATH),
        ) => {
            let envelope = encrypted_deriver_a_package(state, path)?;
            write_local_dev_http_response_v1(stream, 200, &serde_json::to_string(&envelope)?)
        }
        (
            LocalWorkerRoleConfigV1::DeriverB(_),
            path @ (LOCAL_DERIVER_B_ED25519_YAO_ACTIVATION_CLIENT_PACKAGE_PATH
            | LOCAL_DERIVER_B_ED25519_YAO_ACTIVATION_SIGNING_WORKER_PACKAGE_PATH
            | LOCAL_DERIVER_B_ED25519_YAO_REFRESH_CLIENT_PACKAGE_PATH
            | LOCAL_DERIVER_B_ED25519_YAO_REFRESH_SIGNING_WORKER_PACKAGE_PATH
            | LOCAL_DERIVER_B_ED25519_YAO_EXPORT_CLIENT_PACKAGE_PATH),
        ) => {
            let envelope = encrypted_deriver_b_package(state, path)?;
            write_local_dev_http_response_v1(stream, 200, &serde_json::to_string(&envelope)?)
        }
        (
            LocalWorkerRoleConfigV1::SigningWorker(config),
            LOCAL_SIGNING_WORKER_ED25519_YAO_ACTIVATION_DERIVER_A_PATH,
        ) => {
            let delivery = serde_json::from_slice::<LocalEd25519YaoSigningWorkerPackageDeliveryV1>(
                &request.body,
            )?;
            let receipt = state.signing_worker.accept_deriver_a(config, delivery)?;
            write_local_dev_http_response_v1(stream, 200, &serde_json::to_string(&receipt)?)
        }
        (
            LocalWorkerRoleConfigV1::SigningWorker(config),
            LOCAL_SIGNING_WORKER_ED25519_YAO_ACTIVATION_DERIVER_B_PATH,
        ) => {
            let delivery = serde_json::from_slice::<LocalEd25519YaoSigningWorkerPackageDeliveryV1>(
                &request.body,
            )?;
            let receipt = state.signing_worker.accept_deriver_b(config, delivery)?;
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
    } = completed
    else {
        return Err(invalid_worker_state("Deriver A has no completed refresh"));
    };
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
    } = completed
    else {
        return Err(invalid_worker_state("Deriver B has no completed refresh"));
    };
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
            Some(CompletedDeriverARoleV1::Activation { packages, .. }),
            LOCAL_DERIVER_A_ED25519_YAO_ACTIVATION_CLIENT_PACKAGE_PATH,
        ) => Ok(packages.client.clone()),
        (
            Some(CompletedDeriverARoleV1::Refresh { packages, .. }),
            LOCAL_DERIVER_A_ED25519_YAO_REFRESH_CLIENT_PACKAGE_PATH,
        ) => Ok(packages.client.clone()),
        (
            Some(CompletedDeriverARoleV1::Refresh { packages, .. }),
            LOCAL_DERIVER_A_ED25519_YAO_REFRESH_SIGNING_WORKER_PACKAGE_PATH,
        ) => Ok(packages.signing_worker.clone()),
        (
            Some(CompletedDeriverARoleV1::Activation { packages, .. }),
            LOCAL_DERIVER_A_ED25519_YAO_ACTIVATION_SIGNING_WORKER_PACKAGE_PATH,
        ) => Ok(packages.signing_worker.clone()),
        (
            Some(CompletedDeriverARoleV1::Export { client_package, .. }),
            LOCAL_DERIVER_A_ED25519_YAO_EXPORT_CLIENT_PACKAGE_PATH,
        ) => Ok(client_package.clone()),
        _ => Err(io::Error::other("requested Deriver A package is unavailable").into()),
    }
}

fn encrypted_deriver_b_package(
    state: &LocalEd25519YaoWorkerStateV1,
    path: &str,
) -> Result<Ed25519YaoEncryptedPackageV1, Box<dyn std::error::Error>> {
    match (&state.completed_deriver_b, path) {
        (
            Some(CompletedDeriverBRoleV1::Activation { packages, .. }),
            LOCAL_DERIVER_B_ED25519_YAO_ACTIVATION_CLIENT_PACKAGE_PATH,
        ) => Ok(packages.client.clone()),
        (
            Some(CompletedDeriverBRoleV1::Refresh { packages, .. }),
            LOCAL_DERIVER_B_ED25519_YAO_REFRESH_CLIENT_PACKAGE_PATH,
        ) => Ok(packages.client.clone()),
        (
            Some(CompletedDeriverBRoleV1::Refresh { packages, .. }),
            LOCAL_DERIVER_B_ED25519_YAO_REFRESH_SIGNING_WORKER_PACKAGE_PATH,
        ) => Ok(packages.signing_worker.clone()),
        (
            Some(CompletedDeriverBRoleV1::Activation { packages, .. }),
            LOCAL_DERIVER_B_ED25519_YAO_ACTIVATION_SIGNING_WORKER_PACKAGE_PATH,
        ) => Ok(packages.signing_worker.clone()),
        (
            Some(CompletedDeriverBRoleV1::Export { client_package, .. }),
            LOCAL_DERIVER_B_ED25519_YAO_EXPORT_CLIENT_PACKAGE_PATH,
        ) => Ok(client_package.clone()),
        _ => Err(io::Error::other("requested Deriver B package is unavailable").into()),
    }
}

fn handle_deriver_b_peer_stream(
    stream: TcpStream,
    state: &mut LocalEd25519YaoWorkerStateV1,
) -> Result<(), Box<dyn std::error::Error>> {
    let expected_session = state
        .pending_deriver_b
        .as_ref()
        .ok_or_else(|| io::Error::other("no staged Deriver B Yao role"))?
        .session();
    let auth = local_router_ab_internal_service_auth_secret_v1();
    let authenticated =
        authenticate_local_ed25519_yao_deriver_b_peer_http_v1(stream, expected_session, &auth)?;
    let pending = state
        .pending_deriver_b
        .take()
        .ok_or_else(|| io::Error::other("authenticated Deriver B role disappeared"))?;
    let completed = match pending {
        PendingDeriverBRoleV1::Activation {
            session,
            recipients,
            initial_effective,
            role,
        } => {
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
            CompletedDeriverBRoleV1::Activation {
                session,
                packages,
                completion: Box::new(completion),
            }
        }
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
        PendingDeriverBRoleV1::Export {
            session,
            recipient,
            role,
        } => {
            let completion = run_local_export_deriver_b_authenticated_http_v1(authenticated, role)?;
            let client_package = seal_export_output_v1(
                Ed25519YaoDeriverRoleV1::DeriverB,
                session,
                recipient,
                completion.final_transcript(),
                completion.export_package().as_bytes(),
            )?;
            CompletedDeriverBRoleV1::Export {
                session,
                client_package,
                completion: Box::new(completion),
            }
        }
    };
    state.completed_deriver_b = Some(completed);
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
        LOCAL_DERIVER_B_ED25519_YAO_ACTIVATION_STAGE_PATH
            | LOCAL_DERIVER_B_ED25519_YAO_EXPORT_STAGE_PATH
            | LOCAL_DERIVER_B_ED25519_YAO_REFRESH_STAGE_PATH
            | LOCAL_DERIVER_B_ED25519_YAO_REFRESH_DELTA_PATH
            | LOCAL_DERIVER_B_ED25519_YAO_REFRESH_PROMOTE_PATH
            | LOCAL_DERIVER_B_ED25519_YAO_RESULT_PATH
            | LOCAL_DERIVER_A_ED25519_YAO_ACTIVATION_START_PATH
            | LOCAL_DERIVER_A_ED25519_YAO_EXPORT_START_PATH
            | LOCAL_DERIVER_A_ED25519_YAO_REFRESH_START_PATH
            | LOCAL_DERIVER_A_ED25519_YAO_REFRESH_PROMOTE_PATH
            | LOCAL_DERIVER_A_ED25519_YAO_RESULT_PATH
            | LOCAL_DERIVER_A_ED25519_YAO_ACTIVATION_CLIENT_PACKAGE_PATH
            | LOCAL_DERIVER_A_ED25519_YAO_ACTIVATION_SIGNING_WORKER_PACKAGE_PATH
            | LOCAL_DERIVER_A_ED25519_YAO_EXPORT_CLIENT_PACKAGE_PATH
            | LOCAL_DERIVER_A_ED25519_YAO_REFRESH_CLIENT_PACKAGE_PATH
            | LOCAL_DERIVER_A_ED25519_YAO_REFRESH_SIGNING_WORKER_PACKAGE_PATH
            | LOCAL_DERIVER_B_ED25519_YAO_ACTIVATION_CLIENT_PACKAGE_PATH
            | LOCAL_DERIVER_B_ED25519_YAO_ACTIVATION_SIGNING_WORKER_PACKAGE_PATH
            | LOCAL_DERIVER_B_ED25519_YAO_EXPORT_CLIENT_PACKAGE_PATH
            | LOCAL_DERIVER_B_ED25519_YAO_REFRESH_CLIENT_PACKAGE_PATH
            | LOCAL_DERIVER_B_ED25519_YAO_REFRESH_SIGNING_WORKER_PACKAGE_PATH
            | LOCAL_SIGNING_WORKER_ED25519_YAO_ACTIVATION_DERIVER_A_PATH
            | LOCAL_SIGNING_WORKER_ED25519_YAO_ACTIVATION_DERIVER_B_PATH
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

fn public_activation_a_completion(
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

fn public_export_a_completion(
    session: [u8; 32],
    completion: &ExportDeriverACompletion,
) -> LocalEd25519YaoRoleCompletionV1 {
    let wire = completion.wire_byte_ledger();
    LocalEd25519YaoRoleCompletionV1::Export {
        session_hex: hex::encode(session),
        transcript_hex: hex::encode(completion.final_transcript()),
        frame_count: completion.stream_metrics().frame_count(),
        deriver_a_to_b_transport_bytes: wire.deriver_a_to_b_transport_bytes(),
        deriver_b_to_a_transport_bytes: wire.deriver_b_to_a_transport_bytes(),
        total_ab_transport_bytes: wire.total_ab_transport_bytes(),
    }
}

fn public_deriver_b_completion(
    completion: &CompletedDeriverBRoleV1,
) -> LocalEd25519YaoRoleCompletionV1 {
    match completion {
        CompletedDeriverBRoleV1::Activation {
            session,
            completion,
            ..
        } => LocalEd25519YaoRoleCompletionV1::Activation {
            deriver_a_to_b_transport_bytes: completion
                .wire_byte_ledger()
                .deriver_a_to_b_transport_bytes(),
            deriver_b_to_a_transport_bytes: completion
                .wire_byte_ledger()
                .deriver_b_to_a_transport_bytes(),
            total_ab_transport_bytes: completion.wire_byte_ledger().total_ab_transport_bytes(),
            session_hex: hex::encode(session),
            transcript_hex: hex::encode(completion.final_transcript()),
            client_commitment_hex: hex::encode(completion.client_commitment()),
            signing_worker_commitment_hex: hex::encode(completion.signing_worker_commitment()),
            frame_count: completion.stream_metrics().frame_count(),
        },
        CompletedDeriverBRoleV1::Refresh {
            binding,
            completion,
            ..
        } => LocalEd25519YaoRoleCompletionV1::Activation {
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
        },
        CompletedDeriverBRoleV1::Export {
            session,
            completion,
            ..
        } => LocalEd25519YaoRoleCompletionV1::Export {
            deriver_a_to_b_transport_bytes: completion
                .wire_byte_ledger()
                .deriver_a_to_b_transport_bytes(),
            deriver_b_to_a_transport_bytes: completion
                .wire_byte_ledger()
                .deriver_b_to_a_transport_bytes(),
            total_ab_transport_bytes: completion.wire_byte_ledger().total_ab_transport_bytes(),
            session_hex: hex::encode(session),
            transcript_hex: hex::encode(completion.final_transcript()),
            frame_count: completion.stream_metrics().frame_count(),
        },
    }
}

fn public_deriver_a_completion(
    completion: &CompletedDeriverARoleV1,
) -> LocalEd25519YaoRoleCompletionV1 {
    match completion {
        CompletedDeriverARoleV1::Activation {
            session,
            completion,
            ..
        } => public_activation_a_completion(*session, completion),
        CompletedDeriverARoleV1::Refresh {
            binding,
            completion,
            ..
        } => public_activation_a_completion(binding.ceremony().session_id.into_bytes(), completion),
        CompletedDeriverARoleV1::Export {
            session,
            completion,
            ..
        } => public_export_a_completion(*session, completion),
    }
}

fn invalid_worker_state(message: &'static str) -> RouterAbProtocolError {
    RouterAbProtocolError::new(RouterAbProtocolErrorCode::InvalidLifecycleState, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::scalar::Scalar;
    use router_ab_core::{
        Ed25519YaoEpochTransitionV1, Ed25519YaoRefreshEpochsV1, Ed25519YaoSessionIdV1,
        Ed25519YaoStableKeyContextBindingV1, ExpensiveWorkKindV1, LifecycleScopeV1, RootShareEpoch,
    };
    use signer_core::ed25519_yao_derivation::{
        derive_ed25519_yao_joint_refresh_delta_v1, Ed25519YaoDeriverARefreshDeltaContributionV1,
        Ed25519YaoDeriverAServerContributionV1, Ed25519YaoDeriverBRefreshDeltaContributionV1,
        Ed25519YaoDeriverBServerContributionV1,
    };

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
        let refresh = Ed25519YaoRefreshBindingV1::new(
            ceremony(
                1,
                Ed25519YaoOperationV1::Refresh,
                ExpensiveWorkKindV1::ServerShareRefresh,
                5,
            ),
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
