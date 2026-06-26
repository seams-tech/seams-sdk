#[cfg(feature = "workers-rs")]
use crate::{CloudflarePeerBindingV1, CloudflareWorkerRoleV1};
#[cfg(feature = "workers-rs")]
use router_ab_core::{RouterAbProtocolError, RouterAbProtocolErrorCode, RouterAbProtocolResult};

/// Public Router endpoint for derivation-time Router/A/B ceremonies.
pub const CLOUDFLARE_ROUTER_SPLIT_DERIVATION_PUBLIC_REQUEST_PATH: &str =
    "/router-ab/split-derivation";
/// Well-known public Router endpoint for Router A/B public deployment keys.
pub const CLOUDFLARE_ROUTER_PUBLIC_KEYSET_WELL_KNOWN_PATH: &str = "/.well-known/router-ab/keyset";
/// Public Router endpoint for Router A/B public deployment keys.
pub const CLOUDFLARE_ROUTER_PUBLIC_KEYSET_PATH: &str = "/router-ab/keyset";
/// Public Router endpoint for normal signing through the active SigningWorker.
pub const CLOUDFLARE_ROUTER_NORMAL_SIGNING_PUBLIC_REQUEST_PATH: &str = "/router-ab/ed25519/sign";
/// Public Router endpoint for preparing normal-signing round-1 material.
pub const CLOUDFLARE_ROUTER_NORMAL_SIGNING_ROUND1_PREPARE_PUBLIC_REQUEST_PATH: &str =
    "/router-ab/ed25519/sign/prepare";
/// Public Router endpoint for refilling normal-signing Ed25519 presign-pool material.
pub const CLOUDFLARE_ROUTER_NORMAL_SIGNING_PRESIGN_POOL_PREPARE_PUBLIC_REQUEST_PATH: &str =
    "/router-ab/ed25519/sign/presign-pool/prepare";
/// Public Router endpoint for ECDSA-HSS Router A/B registration/bootstrap.
pub const CLOUDFLARE_ROUTER_ECDSA_HSS_REGISTRATION_PUBLIC_REQUEST_PATH: &str =
    "/router-ab/ecdsa-hss/register";
/// Public Router endpoint for ECDSA-HSS Router A/B explicit export.
pub const CLOUDFLARE_ROUTER_ECDSA_HSS_EXPORT_PUBLIC_REQUEST_PATH: &str =
    "/router-ab/ecdsa-hss/export";
/// Public Router endpoint for ECDSA-HSS recovery.
pub const CLOUDFLARE_ROUTER_ECDSA_HSS_RECOVERY_PUBLIC_REQUEST_PATH: &str =
    "/router-ab/ecdsa-hss/recover";
/// Public Router endpoint for ECDSA-HSS activation refresh.
pub const CLOUDFLARE_ROUTER_ECDSA_HSS_REFRESH_PUBLIC_REQUEST_PATH: &str =
    "/router-ab/ecdsa-hss/refresh";
/// Public Router endpoint for preparing ECDSA-HSS normal signing.
pub const CLOUDFLARE_ROUTER_ECDSA_HSS_SIGNING_PREPARE_PUBLIC_REQUEST_PATH: &str =
    "/router-ab/ecdsa-hss/sign/prepare";
/// Public Router endpoint for finalizing ECDSA-HSS normal signing.
pub const CLOUDFLARE_ROUTER_ECDSA_HSS_SIGNING_PUBLIC_REQUEST_PATH: &str =
    "/router-ab/ecdsa-hss/sign";
/// Public Router endpoint for reading server-authoritative Wallet Session budget status.
pub const CLOUDFLARE_ROUTER_WALLET_BUDGET_STATUS_PUBLIC_REQUEST_PATH: &str =
    "/router-ab/wallet-budget/status";
/// Private Router endpoint for issuing Wallet Session signing-budget grants.
pub const CLOUDFLARE_ROUTER_WALLET_BUDGET_PUT_GRANT_PRIVATE_REQUEST_PATH: &str =
    "/router-ab/router/wallet-budget/put-grant";

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
pub const CLOUDFLARE_SIGNER_A_PRIVATE_REQUEST_PATH: &str = "/router-ab/signer-a";
/// Private Signer B service-binding endpoint for Router-dispatched work.
pub const CLOUDFLARE_SIGNER_B_PRIVATE_REQUEST_PATH: &str = "/router-ab/signer-b";
/// Private Signer A service-binding endpoint for ECDSA-HSS registration.
pub const CLOUDFLARE_SIGNER_A_ECDSA_HSS_REGISTRATION_PRIVATE_REQUEST_PATH: &str =
    "/router-ab/signer-a/ecdsa-hss/register";
/// Private Signer B service-binding endpoint for ECDSA-HSS registration.
pub const CLOUDFLARE_SIGNER_B_ECDSA_HSS_REGISTRATION_PRIVATE_REQUEST_PATH: &str =
    "/router-ab/signer-b/ecdsa-hss/register";
/// Private Signer A service-binding endpoint for ECDSA-HSS explicit export.
pub const CLOUDFLARE_SIGNER_A_ECDSA_HSS_EXPORT_PRIVATE_REQUEST_PATH: &str =
    "/router-ab/signer-a/ecdsa-hss/export";
/// Private Signer B service-binding endpoint for ECDSA-HSS explicit export.
pub const CLOUDFLARE_SIGNER_B_ECDSA_HSS_EXPORT_PRIVATE_REQUEST_PATH: &str =
    "/router-ab/signer-b/ecdsa-hss/export";
/// Private Signer A service-binding endpoint for ECDSA-HSS recovery.
pub const CLOUDFLARE_SIGNER_A_ECDSA_HSS_RECOVERY_PRIVATE_REQUEST_PATH: &str =
    "/router-ab/signer-a/ecdsa-hss/recover";
/// Private Signer B service-binding endpoint for ECDSA-HSS recovery.
pub const CLOUDFLARE_SIGNER_B_ECDSA_HSS_RECOVERY_PRIVATE_REQUEST_PATH: &str =
    "/router-ab/signer-b/ecdsa-hss/recover";
/// Private Signer A service-binding endpoint for ECDSA-HSS activation refresh.
pub const CLOUDFLARE_SIGNER_A_ECDSA_HSS_REFRESH_PRIVATE_REQUEST_PATH: &str =
    "/router-ab/signer-a/ecdsa-hss/refresh";
/// Private Signer B service-binding endpoint for ECDSA-HSS activation refresh.
pub const CLOUDFLARE_SIGNER_B_ECDSA_HSS_REFRESH_PRIVATE_REQUEST_PATH: &str =
    "/router-ab/signer-b/ecdsa-hss/refresh";
/// Private Signer A endpoint for direct B-to-A coordination.
pub const CLOUDFLARE_SIGNER_A_PEER_REQUEST_PATH: &str = "/router-ab/signer-a/peer";
/// Private Signer B endpoint for direct A-to-B coordination.
pub const CLOUDFLARE_SIGNER_B_PEER_REQUEST_PATH: &str = "/router-ab/signer-b/peer";
/// Private SigningWorker endpoint for strict SigningWorker proof-bundle activation.
pub const CLOUDFLARE_SIGNING_WORKER_PROOF_BUNDLE_ACTIVATION_PATH: &str =
    "/router-ab/signing-worker/proof-bundle-activation";
/// Private SigningWorker endpoint for ECDSA-HSS activation.
pub const CLOUDFLARE_SIGNING_WORKER_ECDSA_HSS_ACTIVATION_PATH: &str =
    "/router-ab/signing-worker/ecdsa-hss/activate";
/// Private SigningWorker endpoint for ECDSA-HSS activation refresh.
pub const CLOUDFLARE_SIGNING_WORKER_ECDSA_HSS_REFRESH_PATH: &str =
    "/router-ab/signing-worker/ecdsa-hss/refresh";
/// Private SigningWorker endpoint for filling the ECDSA-HSS presignature pool.
pub const CLOUDFLARE_SIGNING_WORKER_ECDSA_HSS_PRESIGNATURE_POOL_PUT_PATH: &str =
    "/router-ab/signing-worker/ecdsa-hss/presignature-pool/put";
/// Private SigningWorker endpoint for normal signing.
pub const CLOUDFLARE_SIGNING_WORKER_NORMAL_SIGNING_PATH: &str = "/router-ab/signing-worker/sign";
/// Private SigningWorker endpoint for Ed25519 presign-pool-hit normal signing.
pub const CLOUDFLARE_SIGNING_WORKER_NORMAL_SIGNING_PRESIGN_POOL_PATH: &str =
    "/router-ab/signing-worker/sign/presign-pool";
/// Private SigningWorker endpoint for normal-signing round-1 prepare.
pub const CLOUDFLARE_SIGNING_WORKER_NORMAL_SIGNING_ROUND1_PREPARE_PATH: &str =
    "/router-ab/signing-worker/sign/prepare";
/// Private SigningWorker endpoint for refilling the Ed25519 normal-signing presign pool.
pub const CLOUDFLARE_SIGNING_WORKER_NORMAL_SIGNING_PRESIGN_POOL_PREPARE_PATH: &str =
    "/router-ab/signing-worker/sign/presign-pool/prepare";
/// Private SigningWorker endpoint for ECDSA-HSS normal-signing prepare.
pub const CLOUDFLARE_SIGNING_WORKER_ECDSA_HSS_SIGNING_PREPARE_PATH: &str =
    "/router-ab/signing-worker/ecdsa-hss/sign/prepare";
/// Private SigningWorker endpoint for ECDSA-HSS normal-signing finalize.
pub const CLOUDFLARE_SIGNING_WORKER_ECDSA_HSS_SIGNING_PATH: &str =
    "/router-ab/signing-worker/ecdsa-hss/sign";

#[cfg(feature = "workers-rs")]
const CLOUDFLARE_SIGNER_A_PRIVATE_REQUEST_URL: &str =
    concat!("https://router-ab-signer-a.internal", "/router-ab/signer-a");
#[cfg(feature = "workers-rs")]
const CLOUDFLARE_SIGNER_B_PRIVATE_REQUEST_URL: &str =
    concat!("https://router-ab-signer-b.internal", "/router-ab/signer-b");
#[cfg(feature = "workers-rs")]
const CLOUDFLARE_SIGNER_A_ECDSA_HSS_REGISTRATION_PRIVATE_REQUEST_URL: &str = concat!(
    "https://router-ab-signer-a.internal",
    "/router-ab/signer-a/ecdsa-hss/register"
);
#[cfg(feature = "workers-rs")]
const CLOUDFLARE_SIGNER_B_ECDSA_HSS_REGISTRATION_PRIVATE_REQUEST_URL: &str = concat!(
    "https://router-ab-signer-b.internal",
    "/router-ab/signer-b/ecdsa-hss/register"
);
#[cfg(feature = "workers-rs")]
const CLOUDFLARE_SIGNER_A_ECDSA_HSS_EXPORT_PRIVATE_REQUEST_URL: &str = concat!(
    "https://router-ab-signer-a.internal",
    "/router-ab/signer-a/ecdsa-hss/export"
);
#[cfg(feature = "workers-rs")]
const CLOUDFLARE_SIGNER_B_ECDSA_HSS_EXPORT_PRIVATE_REQUEST_URL: &str = concat!(
    "https://router-ab-signer-b.internal",
    "/router-ab/signer-b/ecdsa-hss/export"
);
#[cfg(feature = "workers-rs")]
const CLOUDFLARE_SIGNER_A_ECDSA_HSS_RECOVERY_PRIVATE_REQUEST_URL: &str = concat!(
    "https://router-ab-signer-a.internal",
    "/router-ab/signer-a/ecdsa-hss/recover"
);
#[cfg(feature = "workers-rs")]
const CLOUDFLARE_SIGNER_B_ECDSA_HSS_RECOVERY_PRIVATE_REQUEST_URL: &str = concat!(
    "https://router-ab-signer-b.internal",
    "/router-ab/signer-b/ecdsa-hss/recover"
);
#[cfg(feature = "workers-rs")]
const CLOUDFLARE_SIGNER_A_ECDSA_HSS_REFRESH_PRIVATE_REQUEST_URL: &str = concat!(
    "https://router-ab-signer-a.internal",
    "/router-ab/signer-a/ecdsa-hss/refresh"
);
#[cfg(feature = "workers-rs")]
const CLOUDFLARE_SIGNER_B_ECDSA_HSS_REFRESH_PRIVATE_REQUEST_URL: &str = concat!(
    "https://router-ab-signer-b.internal",
    "/router-ab/signer-b/ecdsa-hss/refresh"
);
#[cfg(feature = "workers-rs")]
const CLOUDFLARE_SIGNER_A_PEER_REQUEST_URL: &str = concat!(
    "https://router-ab-signer-a.internal",
    "/router-ab/signer-a/peer"
);
#[cfg(feature = "workers-rs")]
const CLOUDFLARE_SIGNER_B_PEER_REQUEST_URL: &str = concat!(
    "https://router-ab-signer-b.internal",
    "/router-ab/signer-b/peer"
);
#[cfg(feature = "workers-rs")]
const CLOUDFLARE_SIGNING_WORKER_PROOF_BUNDLE_ACTIVATION_URL: &str = concat!(
    "https://router-ab-signing-worker.internal",
    "/router-ab/signing-worker/proof-bundle-activation"
);
#[cfg(feature = "workers-rs")]
const CLOUDFLARE_SIGNING_WORKER_ECDSA_HSS_ACTIVATION_URL: &str = concat!(
    "https://router-ab-signing-worker.internal",
    "/router-ab/signing-worker/ecdsa-hss/activate"
);
#[cfg(feature = "workers-rs")]
const CLOUDFLARE_SIGNING_WORKER_ECDSA_HSS_REFRESH_URL: &str = concat!(
    "https://router-ab-signing-worker.internal",
    "/router-ab/signing-worker/ecdsa-hss/refresh"
);
#[cfg(feature = "workers-rs")]
const CLOUDFLARE_SIGNING_WORKER_NORMAL_SIGNING_URL: &str = concat!(
    "https://router-ab-signing-worker.internal",
    "/router-ab/signing-worker/sign"
);
#[cfg(feature = "workers-rs")]
const CLOUDFLARE_SIGNING_WORKER_NORMAL_SIGNING_PRESIGN_POOL_URL: &str = concat!(
    "https://router-ab-signing-worker.internal",
    "/router-ab/signing-worker/sign/presign-pool"
);
#[cfg(feature = "workers-rs")]
const CLOUDFLARE_SIGNING_WORKER_NORMAL_SIGNING_ROUND1_PREPARE_URL: &str = concat!(
    "https://router-ab-signing-worker.internal",
    "/router-ab/signing-worker/sign/prepare"
);
#[cfg(feature = "workers-rs")]
const CLOUDFLARE_SIGNING_WORKER_NORMAL_SIGNING_PRESIGN_POOL_PREPARE_URL: &str = concat!(
    "https://router-ab-signing-worker.internal",
    "/router-ab/signing-worker/sign/presign-pool/prepare"
);
#[cfg(feature = "workers-rs")]
const CLOUDFLARE_SIGNING_WORKER_ECDSA_HSS_SIGNING_PREPARE_URL: &str = concat!(
    "https://router-ab-signing-worker.internal",
    "/router-ab/signing-worker/ecdsa-hss/sign/prepare"
);
#[cfg(feature = "workers-rs")]
const CLOUDFLARE_SIGNING_WORKER_ECDSA_HSS_SIGNING_URL: &str = concat!(
    "https://router-ab-signing-worker.internal",
    "/router-ab/signing-worker/ecdsa-hss/sign"
);

#[cfg(feature = "workers-rs")]
fn cloudflare_signer_peer_url(
    peer: &CloudflarePeerBindingV1,
    signer_a_url: &'static str,
    signer_b_url: &'static str,
    message: &'static str,
) -> RouterAbProtocolResult<&'static str> {
    match peer.peer_role {
        CloudflareWorkerRoleV1::SignerA => Ok(signer_a_url),
        CloudflareWorkerRoleV1::SignerB => Ok(signer_b_url),
        CloudflareWorkerRoleV1::Router | CloudflareWorkerRoleV1::SigningWorker => {
            Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                message,
            ))
        }
    }
}

#[cfg(feature = "workers-rs")]
fn cloudflare_signing_worker_url(
    peer: &CloudflarePeerBindingV1,
    service_url: &'static str,
    message: &'static str,
) -> RouterAbProtocolResult<&'static str> {
    match peer.peer_role {
        CloudflareWorkerRoleV1::SigningWorker => Ok(service_url),
        CloudflareWorkerRoleV1::Router
        | CloudflareWorkerRoleV1::SignerA
        | CloudflareWorkerRoleV1::SignerB => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            message,
        )),
    }
}

#[cfg(feature = "workers-rs")]
pub(crate) fn cloudflare_signer_service_url(
    peer: &CloudflarePeerBindingV1,
) -> RouterAbProtocolResult<&'static str> {
    cloudflare_signer_peer_url(
        peer,
        CLOUDFLARE_SIGNER_A_PRIVATE_REQUEST_URL,
        CLOUDFLARE_SIGNER_B_PRIVATE_REQUEST_URL,
        "Router public handler can forward signer work only to signer peers",
    )
}

#[cfg(feature = "workers-rs")]
pub(crate) fn cloudflare_ecdsa_hss_deriver_registration_service_url(
    peer: &CloudflarePeerBindingV1,
) -> RouterAbProtocolResult<&'static str> {
    cloudflare_signer_peer_url(
        peer,
        CLOUDFLARE_SIGNER_A_ECDSA_HSS_REGISTRATION_PRIVATE_REQUEST_URL,
        CLOUDFLARE_SIGNER_B_ECDSA_HSS_REGISTRATION_PRIVATE_REQUEST_URL,
        "ECDSA-HSS registration can forward Deriver work only to signer peers",
    )
}

#[cfg(feature = "workers-rs")]
pub(crate) fn cloudflare_ecdsa_hss_deriver_export_service_url(
    peer: &CloudflarePeerBindingV1,
) -> RouterAbProtocolResult<&'static str> {
    cloudflare_signer_peer_url(
        peer,
        CLOUDFLARE_SIGNER_A_ECDSA_HSS_EXPORT_PRIVATE_REQUEST_URL,
        CLOUDFLARE_SIGNER_B_ECDSA_HSS_EXPORT_PRIVATE_REQUEST_URL,
        "ECDSA-HSS export can forward Deriver work only to signer peers",
    )
}

#[cfg(feature = "workers-rs")]
pub(crate) fn cloudflare_ecdsa_hss_deriver_recovery_service_url(
    peer: &CloudflarePeerBindingV1,
) -> RouterAbProtocolResult<&'static str> {
    cloudflare_signer_peer_url(
        peer,
        CLOUDFLARE_SIGNER_A_ECDSA_HSS_RECOVERY_PRIVATE_REQUEST_URL,
        CLOUDFLARE_SIGNER_B_ECDSA_HSS_RECOVERY_PRIVATE_REQUEST_URL,
        "ECDSA-HSS recovery can forward Deriver work only to signer peers",
    )
}

#[cfg(feature = "workers-rs")]
pub(crate) fn cloudflare_ecdsa_hss_deriver_refresh_service_url(
    peer: &CloudflarePeerBindingV1,
) -> RouterAbProtocolResult<&'static str> {
    cloudflare_signer_peer_url(
        peer,
        CLOUDFLARE_SIGNER_A_ECDSA_HSS_REFRESH_PRIVATE_REQUEST_URL,
        CLOUDFLARE_SIGNER_B_ECDSA_HSS_REFRESH_PRIVATE_REQUEST_URL,
        "ECDSA-HSS activation refresh can forward Deriver work only to signer peers",
    )
}

#[cfg(feature = "workers-rs")]
pub(crate) fn cloudflare_signer_peer_service_url(
    peer: &CloudflarePeerBindingV1,
) -> RouterAbProtocolResult<&'static str> {
    cloudflare_signer_peer_url(
        peer,
        CLOUDFLARE_SIGNER_A_PEER_REQUEST_URL,
        CLOUDFLARE_SIGNER_B_PEER_REQUEST_URL,
        "direct A/B peer handler can send peer work only to signer peers",
    )
}

#[cfg(feature = "workers-rs")]
pub(crate) fn cloudflare_signing_worker_recipient_proof_bundle_activation_service_url(
    peer: &CloudflarePeerBindingV1,
) -> RouterAbProtocolResult<&'static str> {
    cloudflare_signing_worker_url(
        peer,
        CLOUDFLARE_SIGNING_WORKER_PROOF_BUNDLE_ACTIVATION_URL,
        "strict SigningWorker proof-bundle activation can target only SigningWorker",
    )
}

#[cfg(feature = "workers-rs")]
pub(crate) fn cloudflare_ecdsa_hss_signing_worker_activation_service_url(
    peer: &CloudflarePeerBindingV1,
) -> RouterAbProtocolResult<&'static str> {
    cloudflare_signing_worker_url(
        peer,
        CLOUDFLARE_SIGNING_WORKER_ECDSA_HSS_ACTIVATION_URL,
        "strict ECDSA-HSS SigningWorker activation can target only SigningWorker",
    )
}

#[cfg(feature = "workers-rs")]
pub(crate) fn cloudflare_ecdsa_hss_signing_worker_activation_refresh_service_url(
    peer: &CloudflarePeerBindingV1,
) -> RouterAbProtocolResult<&'static str> {
    cloudflare_signing_worker_url(
        peer,
        CLOUDFLARE_SIGNING_WORKER_ECDSA_HSS_REFRESH_URL,
        "strict ECDSA-HSS SigningWorker activation refresh can target only SigningWorker",
    )
}

#[cfg(feature = "workers-rs")]
pub(crate) fn cloudflare_signing_worker_normal_signing_service_url(
    peer: &CloudflarePeerBindingV1,
) -> RouterAbProtocolResult<&'static str> {
    cloudflare_signing_worker_url(
        peer,
        CLOUDFLARE_SIGNING_WORKER_NORMAL_SIGNING_URL,
        "normal signing can target only SigningWorker",
    )
}

#[cfg(feature = "workers-rs")]
pub(crate) fn cloudflare_signing_worker_normal_signing_presign_pool_service_url(
    peer: &CloudflarePeerBindingV1,
) -> RouterAbProtocolResult<&'static str> {
    cloudflare_signing_worker_url(
        peer,
        CLOUDFLARE_SIGNING_WORKER_NORMAL_SIGNING_PRESIGN_POOL_URL,
        "normal-signing presign-pool finalize can target only SigningWorker",
    )
}

#[cfg(feature = "workers-rs")]
pub(crate) fn cloudflare_signing_worker_normal_signing_round1_prepare_service_url(
    peer: &CloudflarePeerBindingV1,
) -> RouterAbProtocolResult<&'static str> {
    cloudflare_signing_worker_url(
        peer,
        CLOUDFLARE_SIGNING_WORKER_NORMAL_SIGNING_ROUND1_PREPARE_URL,
        "normal-signing round-1 prepare can target only SigningWorker",
    )
}

#[cfg(feature = "workers-rs")]
pub(crate) fn cloudflare_signing_worker_normal_signing_presign_pool_prepare_service_url(
    peer: &CloudflarePeerBindingV1,
) -> RouterAbProtocolResult<&'static str> {
    cloudflare_signing_worker_url(
        peer,
        CLOUDFLARE_SIGNING_WORKER_NORMAL_SIGNING_PRESIGN_POOL_PREPARE_URL,
        "normal-signing presign-pool prepare can target only SigningWorker",
    )
}

#[cfg(feature = "workers-rs")]
pub(crate) fn cloudflare_signing_worker_ecdsa_hss_evm_digest_prepare_service_url(
    peer: &CloudflarePeerBindingV1,
) -> RouterAbProtocolResult<&'static str> {
    cloudflare_signing_worker_url(
        peer,
        CLOUDFLARE_SIGNING_WORKER_ECDSA_HSS_SIGNING_PREPARE_URL,
        "ECDSA-HSS prepare can target only SigningWorker",
    )
}

#[cfg(feature = "workers-rs")]
pub(crate) fn cloudflare_signing_worker_ecdsa_hss_evm_digest_finalize_service_url(
    peer: &CloudflarePeerBindingV1,
) -> RouterAbProtocolResult<&'static str> {
    cloudflare_signing_worker_url(
        peer,
        CLOUDFLARE_SIGNING_WORKER_ECDSA_HSS_SIGNING_URL,
        "ECDSA-HSS finalize can target only SigningWorker",
    )
}
