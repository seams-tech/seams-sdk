#[cfg(feature = "workers-rs")]
use crate::{CloudflarePeerBindingV1, CloudflareWorkerRoleV1};
#[cfg(feature = "workers-rs")]
use router_ab_core::{RouterAbProtocolError, RouterAbProtocolErrorCode, RouterAbProtocolResult};

/// Well-known public Router endpoint for Router A/B public deployment keys.
pub const CLOUDFLARE_ROUTER_PUBLIC_KEYSET_WELL_KNOWN_PATH: &str = "/.well-known/router-ab/keyset";
/// Public Router endpoint for Router A/B public deployment keys.
pub const CLOUDFLARE_ROUTER_PUBLIC_KEYSET_PATH: &str = "/router-ab/keyset";
/// Public Router endpoint for normal signing through the active SigningWorker.
pub const CLOUDFLARE_ROUTER_NORMAL_SIGNING_PUBLIC_REQUEST_PATH: &str = "/router-ab/ed25519/sign";
/// Public Router endpoint for preparing normal-signing round-1 material.
pub const CLOUDFLARE_ROUTER_NORMAL_SIGNING_ROUND1_PREPARE_PUBLIC_REQUEST_PATH: &str =
    "/router-ab/ed25519/sign/prepare";
/// Public Router endpoint for Router A/B ECDSA derivation Router A/B registration/bootstrap.
pub const CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_REGISTRATION_PUBLIC_REQUEST_PATH: &str =
    "/router-ab/ecdsa-derivation/register";
/// Public Router endpoint for completing registration after client proof verification.
pub const CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_ACTIVATION_PUBLIC_REQUEST_PATH: &str =
    "/router-ab/ecdsa-derivation/activate";
/// Public Router endpoint for bootstrapping an additional ECDSA signer.
pub const CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_ADD_SIGNER_PUBLIC_REQUEST_PATH: &str =
    "/router-ab/ecdsa-derivation/add-signer";
/// Public Router endpoint for Router A/B ECDSA derivation Router A/B explicit export.
pub const CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_EXPORT_PUBLIC_REQUEST_PATH: &str =
    "/router-ab/ecdsa-derivation/export";
/// Public Router endpoint for Router A/B ECDSA derivation recovery.
pub const CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_RECOVERY_PUBLIC_REQUEST_PATH: &str =
    "/router-ab/ecdsa-derivation/recover";
/// Public Router endpoint for Router A/B ECDSA derivation activation refresh.
pub const CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_REFRESH_PUBLIC_REQUEST_PATH: &str =
    "/router-ab/ecdsa-derivation/refresh";
/// Public Router endpoint for preparing Router A/B ECDSA derivation normal signing.
pub const CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_SIGNING_PREPARE_PUBLIC_REQUEST_PATH: &str =
    "/router-ab/ecdsa-derivation/sign/prepare";
/// Public Router endpoint for finalizing Router A/B ECDSA derivation normal signing.
pub const CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_SIGNING_PUBLIC_REQUEST_PATH: &str =
    "/router-ab/ecdsa-derivation/sign";
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

/// Private Deriver A service-binding endpoint for Router-dispatched work.
pub const CLOUDFLARE_DERIVER_A_PRIVATE_REQUEST_PATH: &str = "/router-ab/deriver-a";
/// Private Deriver B service-binding endpoint for Router-dispatched work.
pub const CLOUDFLARE_DERIVER_B_PRIVATE_REQUEST_PATH: &str = "/router-ab/deriver-b";
/// Private Deriver A service-binding endpoint for Router A/B ECDSA derivation registration.
pub const CLOUDFLARE_DERIVER_A_ROUTER_AB_ECDSA_DERIVATION_REGISTRATION_PRIVATE_REQUEST_PATH: &str =
    "/router-ab/deriver-a/ecdsa-derivation/register";
/// Private Deriver B service-binding endpoint for Router A/B ECDSA derivation registration.
pub const CLOUDFLARE_DERIVER_B_ROUTER_AB_ECDSA_DERIVATION_REGISTRATION_PRIVATE_REQUEST_PATH: &str =
    "/router-ab/deriver-b/ecdsa-derivation/register";
/// Private Deriver A service-binding endpoint for Router A/B ECDSA derivation explicit export.
pub const CLOUDFLARE_DERIVER_A_ROUTER_AB_ECDSA_DERIVATION_EXPORT_PRIVATE_REQUEST_PATH: &str =
    "/router-ab/deriver-a/ecdsa-derivation/export";
/// Private Deriver B service-binding endpoint for Router A/B ECDSA derivation explicit export.
pub const CLOUDFLARE_DERIVER_B_ROUTER_AB_ECDSA_DERIVATION_EXPORT_PRIVATE_REQUEST_PATH: &str =
    "/router-ab/deriver-b/ecdsa-derivation/export";
/// Private Deriver A service-binding endpoint for Router A/B ECDSA derivation recovery.
pub const CLOUDFLARE_DERIVER_A_ROUTER_AB_ECDSA_DERIVATION_RECOVERY_PRIVATE_REQUEST_PATH: &str =
    "/router-ab/deriver-a/ecdsa-derivation/recover";
/// Private Deriver B service-binding endpoint for Router A/B ECDSA derivation recovery.
pub const CLOUDFLARE_DERIVER_B_ROUTER_AB_ECDSA_DERIVATION_RECOVERY_PRIVATE_REQUEST_PATH: &str =
    "/router-ab/deriver-b/ecdsa-derivation/recover";
/// Private Deriver A service-binding endpoint for Router A/B ECDSA derivation activation refresh.
pub const CLOUDFLARE_DERIVER_A_ROUTER_AB_ECDSA_DERIVATION_REFRESH_PRIVATE_REQUEST_PATH: &str =
    "/router-ab/deriver-a/ecdsa-derivation/refresh";
/// Private Deriver B service-binding endpoint for Router A/B ECDSA derivation activation refresh.
pub const CLOUDFLARE_DERIVER_B_ROUTER_AB_ECDSA_DERIVATION_REFRESH_PRIVATE_REQUEST_PATH: &str =
    "/router-ab/deriver-b/ecdsa-derivation/refresh";
/// Private Deriver A endpoint for direct B-to-A coordination.
pub const CLOUDFLARE_DERIVER_A_PEER_REQUEST_PATH: &str = "/router-ab/deriver-a/peer";
/// Private Deriver B endpoint for direct A-to-B coordination.
pub const CLOUDFLARE_DERIVER_B_PEER_REQUEST_PATH: &str = "/router-ab/deriver-b/peer";
/// Private SigningWorker endpoint for strict SigningWorker proof-bundle activation.
pub const CLOUDFLARE_SIGNING_WORKER_PROOF_BUNDLE_ACTIVATION_PATH: &str =
    "/router-ab/signing-worker/proof-bundle-activation";
/// Private SigningWorker endpoint for Router A/B ECDSA derivation activation.
pub const CLOUDFLARE_SIGNING_WORKER_ROUTER_AB_ECDSA_DERIVATION_ACTIVATION_PATH: &str =
    "/router-ab/signing-worker/ecdsa-derivation/activate";
/// Private SigningWorker endpoint for Router A/B ECDSA derivation activation refresh.
pub const CLOUDFLARE_SIGNING_WORKER_ROUTER_AB_ECDSA_DERIVATION_REFRESH_PATH: &str =
    "/router-ab/signing-worker/ecdsa-derivation/refresh";
/// Private SigningWorker endpoint for one-time explicit-export share delivery.
pub const CLOUDFLARE_SIGNING_WORKER_ROUTER_AB_ECDSA_DERIVATION_EXPORT_SHARE_PATH: &str =
    "/router-ab/signing-worker/ecdsa-derivation/export-share";
/// Private SigningWorker endpoint for filling the Router A/B ECDSA derivation presignature pool.
pub const CLOUDFLARE_SIGNING_WORKER_ROUTER_AB_ECDSA_DERIVATION_PRESIGNATURE_POOL_PUT_PATH: &str =
    "/router-ab/signing-worker/ecdsa-derivation/presignature-pool/put";
/// Private SigningWorker endpoint for starting an ECDSA presign session.
pub const CLOUDFLARE_SIGNING_WORKER_ROUTER_AB_ECDSA_DERIVATION_PRESIGNATURE_SESSION_INIT_PATH:
    &str = "/router-ab/signing-worker/ecdsa-derivation/presignature-session/init";
/// Private SigningWorker endpoint for advancing an ECDSA presign session.
pub const CLOUDFLARE_SIGNING_WORKER_ROUTER_AB_ECDSA_DERIVATION_PRESIGNATURE_SESSION_STEP_PATH:
    &str = "/router-ab/signing-worker/ecdsa-derivation/presignature-session/step";
/// SigningWorker-output Durable Object endpoint for starting a live ECDSA presign session.
pub const CLOUDFLARE_SIGNING_WORKER_ECDSA_PRESIGN_SESSION_DO_INIT_PATH: &str =
    "/router-ab/internal/signing-worker/ecdsa-presign-session/init";
/// SigningWorker-output Durable Object endpoint for advancing a live ECDSA presign session.
pub const CLOUDFLARE_SIGNING_WORKER_ECDSA_PRESIGN_SESSION_DO_STEP_PATH: &str =
    "/router-ab/internal/signing-worker/ecdsa-presign-session/step";
/// Private SigningWorker endpoint for normal signing.
pub const CLOUDFLARE_SIGNING_WORKER_NORMAL_SIGNING_PATH: &str = "/router-ab/signing-worker/sign";
/// Private SigningWorker endpoint for normal-signing round-1 prepare.
pub const CLOUDFLARE_SIGNING_WORKER_NORMAL_SIGNING_ROUND1_PREPARE_PATH: &str =
    "/router-ab/signing-worker/sign/prepare";
/// Private SigningWorker endpoint for Router A/B ECDSA derivation normal-signing prepare.
pub const CLOUDFLARE_SIGNING_WORKER_ROUTER_AB_ECDSA_DERIVATION_SIGNING_PREPARE_PATH: &str =
    "/router-ab/signing-worker/ecdsa-derivation/sign/prepare";
/// Private SigningWorker endpoint for Router A/B ECDSA derivation normal-signing finalize.
pub const CLOUDFLARE_SIGNING_WORKER_ROUTER_AB_ECDSA_DERIVATION_SIGNING_PATH: &str =
    "/router-ab/signing-worker/ecdsa-derivation/sign";

#[cfg(feature = "workers-rs")]
const CLOUDFLARE_DERIVER_A_ROUTER_AB_ECDSA_DERIVATION_REGISTRATION_PRIVATE_REQUEST_URL: &str = concat!(
    "https://router-ab-deriver-a.internal",
    "/router-ab/deriver-a/ecdsa-derivation/register"
);
#[cfg(feature = "workers-rs")]
const CLOUDFLARE_DERIVER_B_ROUTER_AB_ECDSA_DERIVATION_REGISTRATION_PRIVATE_REQUEST_URL: &str = concat!(
    "https://router-ab-deriver-b.internal",
    "/router-ab/deriver-b/ecdsa-derivation/register"
);
#[cfg(feature = "workers-rs")]
const CLOUDFLARE_DERIVER_A_ROUTER_AB_ECDSA_DERIVATION_EXPORT_PRIVATE_REQUEST_URL: &str = concat!(
    "https://router-ab-deriver-a.internal",
    "/router-ab/deriver-a/ecdsa-derivation/export"
);
#[cfg(feature = "workers-rs")]
const CLOUDFLARE_DERIVER_B_ROUTER_AB_ECDSA_DERIVATION_EXPORT_PRIVATE_REQUEST_URL: &str = concat!(
    "https://router-ab-deriver-b.internal",
    "/router-ab/deriver-b/ecdsa-derivation/export"
);
#[cfg(feature = "workers-rs")]
const CLOUDFLARE_DERIVER_A_ROUTER_AB_ECDSA_DERIVATION_RECOVERY_PRIVATE_REQUEST_URL: &str = concat!(
    "https://router-ab-deriver-a.internal",
    "/router-ab/deriver-a/ecdsa-derivation/recover"
);
#[cfg(feature = "workers-rs")]
const CLOUDFLARE_DERIVER_B_ROUTER_AB_ECDSA_DERIVATION_RECOVERY_PRIVATE_REQUEST_URL: &str = concat!(
    "https://router-ab-deriver-b.internal",
    "/router-ab/deriver-b/ecdsa-derivation/recover"
);
#[cfg(feature = "workers-rs")]
const CLOUDFLARE_DERIVER_A_ROUTER_AB_ECDSA_DERIVATION_REFRESH_PRIVATE_REQUEST_URL: &str = concat!(
    "https://router-ab-deriver-a.internal",
    "/router-ab/deriver-a/ecdsa-derivation/refresh"
);
#[cfg(feature = "workers-rs")]
const CLOUDFLARE_DERIVER_B_ROUTER_AB_ECDSA_DERIVATION_REFRESH_PRIVATE_REQUEST_URL: &str = concat!(
    "https://router-ab-deriver-b.internal",
    "/router-ab/deriver-b/ecdsa-derivation/refresh"
);
#[cfg(feature = "workers-rs")]
const CLOUDFLARE_DERIVER_A_PEER_REQUEST_URL: &str = concat!(
    "https://router-ab-deriver-a.internal",
    "/router-ab/deriver-a/peer"
);
#[cfg(feature = "workers-rs")]
const CLOUDFLARE_DERIVER_B_PEER_REQUEST_URL: &str = concat!(
    "https://router-ab-deriver-b.internal",
    "/router-ab/deriver-b/peer"
);
#[cfg(feature = "workers-rs")]
const CLOUDFLARE_SIGNING_WORKER_ROUTER_AB_ECDSA_DERIVATION_ACTIVATION_URL: &str = concat!(
    "https://router-ab-signing-worker.internal",
    "/router-ab/signing-worker/ecdsa-derivation/activate"
);
#[cfg(feature = "workers-rs")]
const CLOUDFLARE_SIGNING_WORKER_ROUTER_AB_ECDSA_DERIVATION_REFRESH_URL: &str = concat!(
    "https://router-ab-signing-worker.internal",
    "/router-ab/signing-worker/ecdsa-derivation/refresh"
);
#[cfg(feature = "workers-rs")]
const CLOUDFLARE_SIGNING_WORKER_ROUTER_AB_ECDSA_DERIVATION_EXPORT_SHARE_URL: &str = concat!(
    "https://router-ab-signing-worker.internal",
    "/router-ab/signing-worker/ecdsa-derivation/export-share"
);
#[cfg(feature = "workers-rs")]
const CLOUDFLARE_SIGNING_WORKER_NORMAL_SIGNING_URL: &str = concat!(
    "https://router-ab-signing-worker.internal",
    "/router-ab/signing-worker/sign"
);
#[cfg(feature = "workers-rs")]
const CLOUDFLARE_SIGNING_WORKER_NORMAL_SIGNING_ROUND1_PREPARE_URL: &str = concat!(
    "https://router-ab-signing-worker.internal",
    "/router-ab/signing-worker/sign/prepare"
);
#[cfg(feature = "workers-rs")]
const CLOUDFLARE_SIGNING_WORKER_ROUTER_AB_ECDSA_DERIVATION_SIGNING_PREPARE_URL: &str = concat!(
    "https://router-ab-signing-worker.internal",
    "/router-ab/signing-worker/ecdsa-derivation/sign/prepare"
);
#[cfg(feature = "workers-rs")]
const CLOUDFLARE_SIGNING_WORKER_ROUTER_AB_ECDSA_DERIVATION_SIGNING_URL: &str = concat!(
    "https://router-ab-signing-worker.internal",
    "/router-ab/signing-worker/ecdsa-derivation/sign"
);

#[cfg(feature = "workers-rs")]
fn cloudflare_deriver_peer_url(
    peer: &CloudflarePeerBindingV1,
    deriver_a_url: &'static str,
    deriver_b_url: &'static str,
    message: &'static str,
) -> RouterAbProtocolResult<&'static str> {
    match peer.peer_role {
        CloudflareWorkerRoleV1::DeriverA => Ok(deriver_a_url),
        CloudflareWorkerRoleV1::DeriverB => Ok(deriver_b_url),
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
        | CloudflareWorkerRoleV1::DeriverA
        | CloudflareWorkerRoleV1::DeriverB => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            message,
        )),
    }
}

#[cfg(feature = "workers-rs")]
pub(crate) fn cloudflare_router_ab_ecdsa_derivation_deriver_registration_service_url(
    peer: &CloudflarePeerBindingV1,
) -> RouterAbProtocolResult<&'static str> {
    cloudflare_deriver_peer_url(
        peer,
        CLOUDFLARE_DERIVER_A_ROUTER_AB_ECDSA_DERIVATION_REGISTRATION_PRIVATE_REQUEST_URL,
        CLOUDFLARE_DERIVER_B_ROUTER_AB_ECDSA_DERIVATION_REGISTRATION_PRIVATE_REQUEST_URL,
        "Router A/B ECDSA derivation registration can forward Deriver work only to signer peers",
    )
}

#[cfg(feature = "workers-rs")]
pub(crate) fn cloudflare_router_ab_ecdsa_derivation_deriver_export_service_url(
    peer: &CloudflarePeerBindingV1,
) -> RouterAbProtocolResult<&'static str> {
    cloudflare_deriver_peer_url(
        peer,
        CLOUDFLARE_DERIVER_A_ROUTER_AB_ECDSA_DERIVATION_EXPORT_PRIVATE_REQUEST_URL,
        CLOUDFLARE_DERIVER_B_ROUTER_AB_ECDSA_DERIVATION_EXPORT_PRIVATE_REQUEST_URL,
        "Router A/B ECDSA derivation export can forward Deriver work only to signer peers",
    )
}

#[cfg(feature = "workers-rs")]
pub(crate) fn cloudflare_router_ab_ecdsa_derivation_deriver_recovery_service_url(
    peer: &CloudflarePeerBindingV1,
) -> RouterAbProtocolResult<&'static str> {
    cloudflare_deriver_peer_url(
        peer,
        CLOUDFLARE_DERIVER_A_ROUTER_AB_ECDSA_DERIVATION_RECOVERY_PRIVATE_REQUEST_URL,
        CLOUDFLARE_DERIVER_B_ROUTER_AB_ECDSA_DERIVATION_RECOVERY_PRIVATE_REQUEST_URL,
        "Router A/B ECDSA derivation recovery can forward Deriver work only to signer peers",
    )
}

#[cfg(feature = "workers-rs")]
pub(crate) fn cloudflare_router_ab_ecdsa_derivation_deriver_refresh_service_url(
    peer: &CloudflarePeerBindingV1,
) -> RouterAbProtocolResult<&'static str> {
    cloudflare_deriver_peer_url(
        peer,
        CLOUDFLARE_DERIVER_A_ROUTER_AB_ECDSA_DERIVATION_REFRESH_PRIVATE_REQUEST_URL,
        CLOUDFLARE_DERIVER_B_ROUTER_AB_ECDSA_DERIVATION_REFRESH_PRIVATE_REQUEST_URL,
        "Router A/B ECDSA derivation activation refresh can forward Deriver work only to signer peers",
    )
}

#[cfg(feature = "workers-rs")]
pub(crate) fn cloudflare_deriver_peer_service_url(
    peer: &CloudflarePeerBindingV1,
) -> RouterAbProtocolResult<&'static str> {
    cloudflare_deriver_peer_url(
        peer,
        CLOUDFLARE_DERIVER_A_PEER_REQUEST_URL,
        CLOUDFLARE_DERIVER_B_PEER_REQUEST_URL,
        "direct A/B peer handler can send peer work only to signer peers",
    )
}

#[cfg(feature = "workers-rs")]
pub(crate) fn cloudflare_router_ab_ecdsa_derivation_signing_worker_activation_service_url(
    peer: &CloudflarePeerBindingV1,
) -> RouterAbProtocolResult<&'static str> {
    cloudflare_signing_worker_url(
        peer,
        CLOUDFLARE_SIGNING_WORKER_ROUTER_AB_ECDSA_DERIVATION_ACTIVATION_URL,
        "strict Router A/B ECDSA derivation SigningWorker activation can target only SigningWorker",
    )
}

#[cfg(feature = "workers-rs")]
pub(crate) fn cloudflare_router_ab_ecdsa_derivation_signing_worker_activation_refresh_service_url(
    peer: &CloudflarePeerBindingV1,
) -> RouterAbProtocolResult<&'static str> {
    cloudflare_signing_worker_url(
        peer,
        CLOUDFLARE_SIGNING_WORKER_ROUTER_AB_ECDSA_DERIVATION_REFRESH_URL,
        "strict Router A/B ECDSA derivation SigningWorker activation refresh can target only SigningWorker",
    )
}

#[cfg(feature = "workers-rs")]
pub(crate) fn cloudflare_router_ab_ecdsa_derivation_signing_worker_export_share_service_url(
    peer: &CloudflarePeerBindingV1,
) -> RouterAbProtocolResult<&'static str> {
    cloudflare_signing_worker_url(
        peer,
        CLOUDFLARE_SIGNING_WORKER_ROUTER_AB_ECDSA_DERIVATION_EXPORT_SHARE_URL,
        "strict Router A/B ECDSA export-share redemption can target only SigningWorker",
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
pub(crate) fn cloudflare_signing_worker_router_ab_ecdsa_derivation_evm_digest_prepare_service_url(
    peer: &CloudflarePeerBindingV1,
) -> RouterAbProtocolResult<&'static str> {
    cloudflare_signing_worker_url(
        peer,
        CLOUDFLARE_SIGNING_WORKER_ROUTER_AB_ECDSA_DERIVATION_SIGNING_PREPARE_URL,
        "Router A/B ECDSA derivation prepare can target only SigningWorker",
    )
}

#[cfg(feature = "workers-rs")]
pub(crate) fn cloudflare_signing_worker_router_ab_ecdsa_derivation_evm_digest_finalize_service_url(
    peer: &CloudflarePeerBindingV1,
) -> RouterAbProtocolResult<&'static str> {
    cloudflare_signing_worker_url(
        peer,
        CLOUDFLARE_SIGNING_WORKER_ROUTER_AB_ECDSA_DERIVATION_SIGNING_URL,
        "Router A/B ECDSA derivation finalize can target only SigningWorker",
    )
}
