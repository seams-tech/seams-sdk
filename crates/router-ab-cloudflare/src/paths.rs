#[cfg(feature = "workers-rs")]
use crate::{CloudflarePeerBindingV1, CloudflareWorkerRoleV1};
#[cfg(feature = "workers-rs")]
use router_ab_core::{RouterAbProtocolError, RouterAbProtocolErrorCode, RouterAbProtocolResult};

/// Public Router endpoint for derivation-time Router/A/B ceremonies.
pub const CLOUDFLARE_ROUTER_PUBLIC_REQUEST_PATH_V1: &str = "/v1/hss/split-derivation";
/// Well-known public Router endpoint for Router A/B public deployment keys.
pub const CLOUDFLARE_ROUTER_PUBLIC_KEYSET_WELL_KNOWN_PATH_V2: &str =
    "/.well-known/router-ab/keyset";
/// Versioned public Router endpoint for Router A/B public deployment keys.
pub const CLOUDFLARE_ROUTER_PUBLIC_KEYSET_PATH_V2: &str = "/v2/router-ab/keyset";
/// Public Router endpoint for normal signing through the active SigningWorker.
pub const CLOUDFLARE_ROUTER_NORMAL_SIGNING_PUBLIC_REQUEST_PATH_V2: &str =
    "/v2/router-ab/ed25519/sign";
/// Public Router endpoint for preparing normal-signing round-1 material.
pub const CLOUDFLARE_ROUTER_NORMAL_SIGNING_ROUND1_PREPARE_PUBLIC_REQUEST_PATH_V2: &str =
    "/v2/router-ab/ed25519/sign/prepare";
/// Public Router endpoint for refilling normal-signing Ed25519 presign-pool material.
pub const CLOUDFLARE_ROUTER_NORMAL_SIGNING_PRESIGN_POOL_PREPARE_PUBLIC_REQUEST_PATH_V2: &str =
    "/v2/router-ab/ed25519/sign/presign-pool/prepare";
/// Public Router endpoint for ECDSA-HSS Router A/B registration/bootstrap.
pub const CLOUDFLARE_ROUTER_ECDSA_HSS_REGISTRATION_PUBLIC_REQUEST_PATH_V1: &str =
    "/v1/hss/ecdsa/register";
/// Public Router endpoint for ECDSA-HSS Router A/B explicit export.
pub const CLOUDFLARE_ROUTER_ECDSA_HSS_EXPORT_PUBLIC_REQUEST_PATH_V1: &str = "/v1/hss/ecdsa/export";
/// Public Router endpoint for ECDSA-HSS recovery.
pub const CLOUDFLARE_ROUTER_ECDSA_HSS_RECOVERY_PUBLIC_REQUEST_PATH_V1: &str =
    "/v1/hss/ecdsa/recover";
/// Public Router endpoint for ECDSA-HSS activation refresh.
pub const CLOUDFLARE_ROUTER_ECDSA_HSS_REFRESH_PUBLIC_REQUEST_PATH_V1: &str =
    "/v1/hss/ecdsa/refresh";
/// Public Router endpoint for preparing ECDSA-HSS normal signing.
pub const CLOUDFLARE_ROUTER_ECDSA_HSS_SIGNING_PREPARE_PUBLIC_REQUEST_PATH_V1: &str =
    "/v1/hss/ecdsa/sign/prepare";
/// Public Router endpoint for finalizing ECDSA-HSS normal signing.
pub const CLOUDFLARE_ROUTER_ECDSA_HSS_SIGNING_PUBLIC_REQUEST_PATH_V1: &str = "/v1/hss/ecdsa/sign";
/// Public Router endpoint for reading server-authoritative Wallet Session budget status.
pub const CLOUDFLARE_ROUTER_WALLET_BUDGET_STATUS_PUBLIC_REQUEST_PATH_V1: &str =
    "/session/signing-budget/status";
/// Private Router endpoint for issuing Wallet Session signing-budget grants.
pub const CLOUDFLARE_ROUTER_WALLET_BUDGET_PUT_GRANT_PRIVATE_REQUEST_PATH_V1: &str =
    "/router-ab/v1/router/wallet-budget/put-grant";

/// Returns the exact configured browser Origin allowed for normal-signing CORS.
pub fn cloudflare_router_normal_signing_cors_allowed_origin_v1(
    configured_origins: Option<&str>,
    request_origin: &str,
) -> Option<String> {
    let configured_origins = configured_origins?;
    let request_origin = request_origin.trim();
    if request_origin.is_empty() {
        return None;
    }
    configured_origins
        .split(',')
        .map(str::trim)
        .filter(|origin| !origin.is_empty())
        .find(|origin| *origin == request_origin)
        .map(str::to_owned)
}

/// Private Signer A service-binding endpoint for Router-dispatched work.
pub const CLOUDFLARE_SIGNER_A_PRIVATE_REQUEST_PATH_V1: &str = "/router-ab/v1/signer-a";
/// Private Signer B service-binding endpoint for Router-dispatched work.
pub const CLOUDFLARE_SIGNER_B_PRIVATE_REQUEST_PATH_V1: &str = "/router-ab/v1/signer-b";
/// Private Signer A service-binding endpoint for ECDSA-HSS registration.
pub const CLOUDFLARE_SIGNER_A_ECDSA_HSS_REGISTRATION_PRIVATE_REQUEST_PATH_V1: &str =
    "/router-ab/v1/signer-a/ecdsa-hss/register";
/// Private Signer B service-binding endpoint for ECDSA-HSS registration.
pub const CLOUDFLARE_SIGNER_B_ECDSA_HSS_REGISTRATION_PRIVATE_REQUEST_PATH_V1: &str =
    "/router-ab/v1/signer-b/ecdsa-hss/register";
/// Private Signer A service-binding endpoint for ECDSA-HSS explicit export.
pub const CLOUDFLARE_SIGNER_A_ECDSA_HSS_EXPORT_PRIVATE_REQUEST_PATH_V1: &str =
    "/router-ab/v1/signer-a/ecdsa-hss/export";
/// Private Signer B service-binding endpoint for ECDSA-HSS explicit export.
pub const CLOUDFLARE_SIGNER_B_ECDSA_HSS_EXPORT_PRIVATE_REQUEST_PATH_V1: &str =
    "/router-ab/v1/signer-b/ecdsa-hss/export";
/// Private Signer A service-binding endpoint for ECDSA-HSS recovery.
pub const CLOUDFLARE_SIGNER_A_ECDSA_HSS_RECOVERY_PRIVATE_REQUEST_PATH_V1: &str =
    "/router-ab/v1/signer-a/ecdsa-hss/recover";
/// Private Signer B service-binding endpoint for ECDSA-HSS recovery.
pub const CLOUDFLARE_SIGNER_B_ECDSA_HSS_RECOVERY_PRIVATE_REQUEST_PATH_V1: &str =
    "/router-ab/v1/signer-b/ecdsa-hss/recover";
/// Private Signer A service-binding endpoint for ECDSA-HSS activation refresh.
pub const CLOUDFLARE_SIGNER_A_ECDSA_HSS_REFRESH_PRIVATE_REQUEST_PATH_V1: &str =
    "/router-ab/v1/signer-a/ecdsa-hss/refresh";
/// Private Signer B service-binding endpoint for ECDSA-HSS activation refresh.
pub const CLOUDFLARE_SIGNER_B_ECDSA_HSS_REFRESH_PRIVATE_REQUEST_PATH_V1: &str =
    "/router-ab/v1/signer-b/ecdsa-hss/refresh";
/// Private Signer A endpoint for direct B-to-A coordination.
pub const CLOUDFLARE_SIGNER_A_PEER_REQUEST_PATH_V1: &str = "/router-ab/v1/signer-a/peer";
/// Private Signer B endpoint for direct A-to-B coordination.
pub const CLOUDFLARE_SIGNER_B_PEER_REQUEST_PATH_V1: &str = "/router-ab/v1/signer-b/peer";
/// Private SigningWorker endpoint for strict SigningWorker proof-bundle activation.
pub const CLOUDFLARE_SIGNING_WORKER_PROOF_BUNDLE_ACTIVATION_PATH_V1: &str =
    "/router-ab/v1/signing-worker/proof-bundle-activation";
/// Private SigningWorker endpoint for ECDSA-HSS activation.
pub const CLOUDFLARE_SIGNING_WORKER_ECDSA_HSS_ACTIVATION_PATH_V1: &str =
    "/router-ab/v1/signing-worker/ecdsa-hss/activate";
/// Private SigningWorker endpoint for ECDSA-HSS activation refresh.
pub const CLOUDFLARE_SIGNING_WORKER_ECDSA_HSS_REFRESH_PATH_V1: &str =
    "/router-ab/v1/signing-worker/ecdsa-hss/refresh";
/// Private SigningWorker endpoint for filling the ECDSA-HSS presignature pool.
pub const CLOUDFLARE_SIGNING_WORKER_ECDSA_HSS_PRESIGNATURE_POOL_PUT_PATH_V1: &str =
    "/router-ab/v1/signing-worker/ecdsa-hss/presignature-pool/put";
/// Private SigningWorker endpoint for normal signing.
pub const CLOUDFLARE_SIGNING_WORKER_NORMAL_SIGNING_PATH_V1: &str =
    "/router-ab/v1/signing-worker/sign";
/// Private SigningWorker endpoint for Ed25519 presign-pool-hit normal signing.
pub const CLOUDFLARE_SIGNING_WORKER_NORMAL_SIGNING_PRESIGN_POOL_PATH_V1: &str =
    "/router-ab/v1/signing-worker/sign/presign-pool";
/// Private SigningWorker endpoint for normal-signing round-1 prepare.
pub const CLOUDFLARE_SIGNING_WORKER_NORMAL_SIGNING_ROUND1_PREPARE_PATH_V1: &str =
    "/router-ab/v1/signing-worker/sign/prepare";
/// Private SigningWorker endpoint for refilling the Ed25519 normal-signing presign pool.
pub const CLOUDFLARE_SIGNING_WORKER_NORMAL_SIGNING_PRESIGN_POOL_PREPARE_PATH_V1: &str =
    "/router-ab/v1/signing-worker/sign/presign-pool/prepare";
/// Private SigningWorker endpoint for ECDSA-HSS normal-signing prepare.
pub const CLOUDFLARE_SIGNING_WORKER_ECDSA_HSS_SIGNING_PREPARE_PATH_V1: &str =
    "/router-ab/v1/signing-worker/ecdsa-hss/sign/prepare";
/// Private SigningWorker endpoint for ECDSA-HSS normal-signing finalize.
pub const CLOUDFLARE_SIGNING_WORKER_ECDSA_HSS_SIGNING_PATH_V1: &str =
    "/router-ab/v1/signing-worker/ecdsa-hss/sign";

#[cfg(feature = "workers-rs")]
pub(crate) fn cloudflare_signer_service_url_v1(
    peer: &CloudflarePeerBindingV1,
) -> RouterAbProtocolResult<&'static str> {
    match peer.peer_role {
        CloudflareWorkerRoleV1::SignerA => Ok(concat!(
            "https://router-ab-signer-a.internal",
            "/router-ab/v1/signer-a"
        )),
        CloudflareWorkerRoleV1::SignerB => Ok(concat!(
            "https://router-ab-signer-b.internal",
            "/router-ab/v1/signer-b"
        )),
        CloudflareWorkerRoleV1::Router | CloudflareWorkerRoleV1::SigningWorker => {
            Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "Router public handler can forward signer work only to signer peers",
            ))
        }
    }
}

#[cfg(feature = "workers-rs")]
pub(crate) fn cloudflare_ecdsa_hss_deriver_registration_service_url_v1(
    peer: &CloudflarePeerBindingV1,
) -> RouterAbProtocolResult<&'static str> {
    match peer.peer_role {
        CloudflareWorkerRoleV1::SignerA => Ok(concat!(
            "https://router-ab-signer-a.internal",
            "/router-ab/v1/signer-a/ecdsa-hss/register"
        )),
        CloudflareWorkerRoleV1::SignerB => Ok(concat!(
            "https://router-ab-signer-b.internal",
            "/router-ab/v1/signer-b/ecdsa-hss/register"
        )),
        CloudflareWorkerRoleV1::Router | CloudflareWorkerRoleV1::SigningWorker => {
            Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "ECDSA-HSS registration can forward Deriver work only to signer peers",
            ))
        }
    }
}

#[cfg(feature = "workers-rs")]
pub(crate) fn cloudflare_ecdsa_hss_deriver_export_service_url_v1(
    peer: &CloudflarePeerBindingV1,
) -> RouterAbProtocolResult<&'static str> {
    match peer.peer_role {
        CloudflareWorkerRoleV1::SignerA => Ok(concat!(
            "https://router-ab-signer-a.internal",
            "/router-ab/v1/signer-a/ecdsa-hss/export"
        )),
        CloudflareWorkerRoleV1::SignerB => Ok(concat!(
            "https://router-ab-signer-b.internal",
            "/router-ab/v1/signer-b/ecdsa-hss/export"
        )),
        CloudflareWorkerRoleV1::Router | CloudflareWorkerRoleV1::SigningWorker => {
            Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "ECDSA-HSS export can forward Deriver work only to signer peers",
            ))
        }
    }
}

#[cfg(feature = "workers-rs")]
pub(crate) fn cloudflare_ecdsa_hss_deriver_recovery_service_url_v1(
    peer: &CloudflarePeerBindingV1,
) -> RouterAbProtocolResult<&'static str> {
    match peer.peer_role {
        CloudflareWorkerRoleV1::SignerA => Ok(concat!(
            "https://router-ab-signer-a.internal",
            "/router-ab/v1/signer-a/ecdsa-hss/recover"
        )),
        CloudflareWorkerRoleV1::SignerB => Ok(concat!(
            "https://router-ab-signer-b.internal",
            "/router-ab/v1/signer-b/ecdsa-hss/recover"
        )),
        CloudflareWorkerRoleV1::Router | CloudflareWorkerRoleV1::SigningWorker => {
            Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "ECDSA-HSS recovery can forward Deriver work only to signer peers",
            ))
        }
    }
}

#[cfg(feature = "workers-rs")]
pub(crate) fn cloudflare_ecdsa_hss_deriver_refresh_service_url_v1(
    peer: &CloudflarePeerBindingV1,
) -> RouterAbProtocolResult<&'static str> {
    match peer.peer_role {
        CloudflareWorkerRoleV1::SignerA => Ok(concat!(
            "https://router-ab-signer-a.internal",
            "/router-ab/v1/signer-a/ecdsa-hss/refresh"
        )),
        CloudflareWorkerRoleV1::SignerB => Ok(concat!(
            "https://router-ab-signer-b.internal",
            "/router-ab/v1/signer-b/ecdsa-hss/refresh"
        )),
        CloudflareWorkerRoleV1::Router | CloudflareWorkerRoleV1::SigningWorker => {
            Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "ECDSA-HSS activation refresh can forward Deriver work only to signer peers",
            ))
        }
    }
}

#[cfg(feature = "workers-rs")]
pub(crate) fn cloudflare_signer_peer_service_url_v1(
    peer: &CloudflarePeerBindingV1,
) -> RouterAbProtocolResult<&'static str> {
    match peer.peer_role {
        CloudflareWorkerRoleV1::SignerA => Ok(concat!(
            "https://router-ab-signer-a.internal",
            "/router-ab/v1/signer-a/peer"
        )),
        CloudflareWorkerRoleV1::SignerB => Ok(concat!(
            "https://router-ab-signer-b.internal",
            "/router-ab/v1/signer-b/peer"
        )),
        CloudflareWorkerRoleV1::Router | CloudflareWorkerRoleV1::SigningWorker => {
            Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "direct A/B peer handler can send peer work only to signer peers",
            ))
        }
    }
}

#[cfg(feature = "workers-rs")]
pub(crate) fn cloudflare_signing_worker_recipient_proof_bundle_activation_service_url_v1(
    peer: &CloudflarePeerBindingV1,
) -> RouterAbProtocolResult<&'static str> {
    match peer.peer_role {
        CloudflareWorkerRoleV1::SigningWorker => Ok(concat!(
            "https://router-ab-signing-worker.internal",
            "/router-ab/v1/signing-worker/proof-bundle-activation"
        )),
        CloudflareWorkerRoleV1::Router
        | CloudflareWorkerRoleV1::SignerA
        | CloudflareWorkerRoleV1::SignerB => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "strict SigningWorker proof-bundle activation can target only SigningWorker",
        )),
    }
}

#[cfg(feature = "workers-rs")]
pub(crate) fn cloudflare_ecdsa_hss_signing_worker_activation_service_url_v1(
    peer: &CloudflarePeerBindingV1,
) -> RouterAbProtocolResult<&'static str> {
    match peer.peer_role {
        CloudflareWorkerRoleV1::SigningWorker => Ok(concat!(
            "https://router-ab-signing-worker.internal",
            "/router-ab/v1/signing-worker/ecdsa-hss/activate"
        )),
        CloudflareWorkerRoleV1::Router
        | CloudflareWorkerRoleV1::SignerA
        | CloudflareWorkerRoleV1::SignerB => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "strict ECDSA-HSS SigningWorker activation can target only SigningWorker",
        )),
    }
}

#[cfg(feature = "workers-rs")]
pub(crate) fn cloudflare_ecdsa_hss_signing_worker_activation_refresh_service_url_v1(
    peer: &CloudflarePeerBindingV1,
) -> RouterAbProtocolResult<&'static str> {
    match peer.peer_role {
        CloudflareWorkerRoleV1::SigningWorker => Ok(concat!(
            "https://router-ab-signing-worker.internal",
            "/router-ab/v1/signing-worker/ecdsa-hss/refresh"
        )),
        CloudflareWorkerRoleV1::Router
        | CloudflareWorkerRoleV1::SignerA
        | CloudflareWorkerRoleV1::SignerB => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "strict ECDSA-HSS SigningWorker activation refresh can target only SigningWorker",
        )),
    }
}

#[cfg(feature = "workers-rs")]
pub(crate) fn cloudflare_signing_worker_normal_signing_service_url_v1(
    peer: &CloudflarePeerBindingV1,
) -> RouterAbProtocolResult<&'static str> {
    match peer.peer_role {
        CloudflareWorkerRoleV1::SigningWorker => Ok(concat!(
            "https://router-ab-signing-worker.internal",
            "/router-ab/v1/signing-worker/sign"
        )),
        CloudflareWorkerRoleV1::Router
        | CloudflareWorkerRoleV1::SignerA
        | CloudflareWorkerRoleV1::SignerB => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "normal signing can target only SigningWorker",
        )),
    }
}

#[cfg(feature = "workers-rs")]
pub(crate) fn cloudflare_signing_worker_normal_signing_presign_pool_service_url_v1(
    peer: &CloudflarePeerBindingV1,
) -> RouterAbProtocolResult<&'static str> {
    match peer.peer_role {
        CloudflareWorkerRoleV1::SigningWorker => Ok(concat!(
            "https://router-ab-signing-worker.internal",
            "/router-ab/v1/signing-worker/sign/presign-pool"
        )),
        CloudflareWorkerRoleV1::Router
        | CloudflareWorkerRoleV1::SignerA
        | CloudflareWorkerRoleV1::SignerB => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "normal-signing presign-pool finalize can target only SigningWorker",
        )),
    }
}

#[cfg(feature = "workers-rs")]
pub(crate) fn cloudflare_signing_worker_normal_signing_round1_prepare_service_url_v1(
    peer: &CloudflarePeerBindingV1,
) -> RouterAbProtocolResult<&'static str> {
    match peer.peer_role {
        CloudflareWorkerRoleV1::SigningWorker => Ok(concat!(
            "https://router-ab-signing-worker.internal",
            "/router-ab/v1/signing-worker/sign/prepare"
        )),
        CloudflareWorkerRoleV1::Router
        | CloudflareWorkerRoleV1::SignerA
        | CloudflareWorkerRoleV1::SignerB => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "normal-signing round-1 prepare can target only SigningWorker",
        )),
    }
}

#[cfg(feature = "workers-rs")]
pub(crate) fn cloudflare_signing_worker_normal_signing_presign_pool_prepare_service_url_v1(
    peer: &CloudflarePeerBindingV1,
) -> RouterAbProtocolResult<&'static str> {
    match peer.peer_role {
        CloudflareWorkerRoleV1::SigningWorker => Ok(concat!(
            "https://router-ab-signing-worker.internal",
            "/router-ab/v1/signing-worker/sign/presign-pool/prepare"
        )),
        CloudflareWorkerRoleV1::Router
        | CloudflareWorkerRoleV1::SignerA
        | CloudflareWorkerRoleV1::SignerB => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "normal-signing presign-pool prepare can target only SigningWorker",
        )),
    }
}

#[cfg(feature = "workers-rs")]
pub(crate) fn cloudflare_signing_worker_ecdsa_hss_evm_digest_prepare_service_url_v1(
    peer: &CloudflarePeerBindingV1,
) -> RouterAbProtocolResult<&'static str> {
    match peer.peer_role {
        CloudflareWorkerRoleV1::SigningWorker => Ok(concat!(
            "https://router-ab-signing-worker.internal",
            "/router-ab/v1/signing-worker/ecdsa-hss/sign/prepare"
        )),
        CloudflareWorkerRoleV1::Router
        | CloudflareWorkerRoleV1::SignerA
        | CloudflareWorkerRoleV1::SignerB => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "ECDSA-HSS prepare can target only SigningWorker",
        )),
    }
}

#[cfg(feature = "workers-rs")]
pub(crate) fn cloudflare_signing_worker_ecdsa_hss_evm_digest_finalize_service_url_v1(
    peer: &CloudflarePeerBindingV1,
) -> RouterAbProtocolResult<&'static str> {
    match peer.peer_role {
        CloudflareWorkerRoleV1::SigningWorker => Ok(concat!(
            "https://router-ab-signing-worker.internal",
            "/router-ab/v1/signing-worker/ecdsa-hss/sign"
        )),
        CloudflareWorkerRoleV1::Router
        | CloudflareWorkerRoleV1::SignerA
        | CloudflareWorkerRoleV1::SignerB => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "ECDSA-HSS finalize can target only SigningWorker",
        )),
    }
}
