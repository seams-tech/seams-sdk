use router_ab_core::{
    LocalServiceRoleV1, RouterAbProtocolError, RouterAbProtocolErrorCode, RouterAbProtocolResult,
};
use serde::Serialize;

use super::{
    LocalWorkerRoleConfigV1, LOCAL_DERIVER_A_PEER_PATH_V1, LOCAL_DERIVER_A_PRIVATE_PATH_V1,
    LOCAL_DERIVER_B_PEER_PATH_V1, LOCAL_DERIVER_B_PRIVATE_PATH_V1,
    LOCAL_ROUTER_ECDSA_HSS_SIGNING_PATH_V1, LOCAL_ROUTER_ECDSA_HSS_SIGNING_PREPARE_PATH_V1,
    LOCAL_ROUTER_NORMAL_SIGNING_PATH_V2, LOCAL_ROUTER_NORMAL_SIGNING_PREPARE_PATH_V2,
    LOCAL_SIGNING_WORKER_ACTIVATION_PATH_V1,
    LOCAL_SIGNING_WORKER_ECDSA_HSS_PRESIGNATURE_POOL_PUT_PATH_V1,
    LOCAL_SIGNING_WORKER_ECDSA_HSS_SIGNING_PATH_V1,
    LOCAL_SIGNING_WORKER_ECDSA_HSS_SIGNING_PREPARE_PATH_V1,
    LOCAL_SIGNING_WORKER_NORMAL_SIGNING_PATH_V1,
    LOCAL_SIGNING_WORKER_NORMAL_SIGNING_PREPARE_PATH_V1,
    LOCAL_SIGNING_WORKER_NORMAL_SIGNING_PRESIGN_POOL_PATH_V1,
    LOCAL_SIGNING_WORKER_NORMAL_SIGNING_PRESIGN_POOL_PREPARE_PATH_V1, LOCAL_WORKER_HEALTH_PATH_V1,
    LOCAL_WORKER_READY_PATH_V1, LOCAL_WORKER_STARTUP_EPOCH_V1,
};

/// Redacted local worker health response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LocalWorkerHealthResponseV1 {
    /// Local worker role.
    pub role: LocalServiceRoleV1,
    /// Stable role label.
    pub role_label: String,
    /// URL this worker is expected to bind.
    pub bind_url: String,
    /// Redacted startup status.
    pub status: String,
    /// Local startup epoch safe for diagnostics.
    pub startup_epoch: String,
    /// Config branch label safe for diagnostics.
    pub config_branch: String,
}

/// Returns the host:port bind address from one local worker config.
pub fn local_worker_bind_addr_v1(
    config: &LocalWorkerRoleConfigV1,
) -> RouterAbProtocolResult<String> {
    super::parse_http_bind_addr_v1(config.bind_url())
}

/// Returns known local HTTP paths owned by one worker role.
pub fn local_worker_owned_paths_v1(role: LocalServiceRoleV1) -> &'static [&'static str] {
    match role {
        LocalServiceRoleV1::Router => &[
            LOCAL_WORKER_HEALTH_PATH_V1,
            LOCAL_WORKER_READY_PATH_V1,
            LOCAL_ROUTER_NORMAL_SIGNING_PREPARE_PATH_V2,
            LOCAL_ROUTER_NORMAL_SIGNING_PATH_V2,
            LOCAL_ROUTER_ECDSA_HSS_SIGNING_PREPARE_PATH_V1,
            LOCAL_ROUTER_ECDSA_HSS_SIGNING_PATH_V1,
        ],
        LocalServiceRoleV1::DeriverA => &[
            LOCAL_WORKER_HEALTH_PATH_V1,
            LOCAL_WORKER_READY_PATH_V1,
            LOCAL_DERIVER_A_PRIVATE_PATH_V1,
            LOCAL_DERIVER_A_PEER_PATH_V1,
        ],
        LocalServiceRoleV1::DeriverB => &[
            LOCAL_WORKER_HEALTH_PATH_V1,
            LOCAL_WORKER_READY_PATH_V1,
            LOCAL_DERIVER_B_PRIVATE_PATH_V1,
            LOCAL_DERIVER_B_PEER_PATH_V1,
        ],
        LocalServiceRoleV1::SigningWorker => &[
            LOCAL_WORKER_HEALTH_PATH_V1,
            LOCAL_WORKER_READY_PATH_V1,
            LOCAL_SIGNING_WORKER_ACTIVATION_PATH_V1,
            LOCAL_SIGNING_WORKER_NORMAL_SIGNING_PREPARE_PATH_V1,
            LOCAL_SIGNING_WORKER_NORMAL_SIGNING_PRESIGN_POOL_PREPARE_PATH_V1,
            LOCAL_SIGNING_WORKER_NORMAL_SIGNING_PRESIGN_POOL_PATH_V1,
            LOCAL_SIGNING_WORKER_NORMAL_SIGNING_PATH_V1,
            LOCAL_SIGNING_WORKER_ECDSA_HSS_PRESIGNATURE_POOL_PUT_PATH_V1,
            LOCAL_SIGNING_WORKER_ECDSA_HSS_SIGNING_PREPARE_PATH_V1,
            LOCAL_SIGNING_WORKER_ECDSA_HSS_SIGNING_PATH_V1,
        ],
    }
}

/// Returns true when a path is owned by the selected local worker role.
pub fn local_worker_owns_path_v1(role: LocalServiceRoleV1, path: &str) -> bool {
    local_worker_owned_paths_v1(role).contains(&path)
}

/// Builds a redacted health response for one local worker config.
pub fn local_worker_health_response_v1(
    config: &LocalWorkerRoleConfigV1,
) -> RouterAbProtocolResult<LocalWorkerHealthResponseV1> {
    let bind_url = config.bind_url();
    super::require_non_empty("local worker bind URL", bind_url)?;
    Ok(LocalWorkerHealthResponseV1 {
        role: config.role(),
        role_label: config.role().as_str().to_owned(),
        bind_url: bind_url.to_owned(),
        status: "ready".to_owned(),
        startup_epoch: LOCAL_WORKER_STARTUP_EPOCH_V1.to_owned(),
        config_branch: config.role().as_str().to_owned(),
    })
}

/// Builds a redacted health response JSON body for one local worker config.
pub fn local_worker_health_response_json_v1(
    config: &LocalWorkerRoleConfigV1,
) -> RouterAbProtocolResult<String> {
    serde_json::to_string(&local_worker_health_response_v1(config)?).map_err(|error| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            format!("local worker health response JSON failed: {error}"),
        )
    })
}
