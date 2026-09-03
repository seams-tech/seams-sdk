#[cfg(feature = "workers-rs")]
use crate::{CloudflarePeerBindingV1, CloudflareWorkerRoleV1};
#[cfg(feature = "workers-rs")]
use router_ab_core::{RouterAbProtocolError, RouterAbProtocolErrorCode, RouterAbProtocolResult};

/// Well-known public Router endpoint for Router A/B public deployment keys.
pub const CLOUDFLARE_ROUTER_PUBLIC_KEYSET_WELL_KNOWN_PATH: &str = "/.well-known/router-ab/keyset";
/// Public Router endpoint for Router A/B public deployment keys.
pub const CLOUDFLARE_ROUTER_PUBLIC_KEYSET_PATH: &str = "/router-ab/keyset";
/// Authenticated internal endpoint that initializes one deployed Worker isolate.
pub const CLOUDFLARE_INTERNAL_PREWARM_PATH: &str = "/internal/prewarm";
/// Authenticated private Router endpoint for starting tenant-root creation.
pub const CLOUDFLARE_ROUTER_TENANT_ROOT_CREATION_PRIVATE_REQUEST_PATH: &str =
    "/router-ab/internal/tenant-root/creation/v1/create";
/// Tenant-root control-plane issuer operation: mint one role creation command.
///
/// Private, internal-service-authenticated. The request names only an
/// identity, a custody lineage, and a role; every other command field is
/// derived by the issuer from authoritative Durable Object state and its own
/// local key configuration, so a caller cannot select authority, revision,
/// session, nonce, time window, or signing key.
/// Tenant-root control-plane genesis operation: open one tenant root.
///
/// Private, internal-service-authenticated. The request carries only a signed
/// creation grant; the issuer verifies it against its own configured
/// authorities and derives every ceremony field itself.
/// Deriver tenant-root creation: admit an issuer-signed role command package.
///
/// Private, internal-service-authenticated. The Deriver derives its own role,
/// authority, clock, and signer locally; the request carries only the signed
/// package and the peer material the ceremony needs.
pub const CLOUDFLARE_DERIVER_TENANT_ROOT_CREATE_ROLE_SHARE_PRIVATE_REQUEST_PATH: &str =
    "/router-ab/internal/deriver/tenant-root/creation/v1/create-role-share";
pub const CLOUDFLARE_DERIVER_TENANT_ROOT_CLEANUP_PENDING_PRIVATE_REQUEST_PATH: &str =
    "/router-ab/internal/deriver/tenant-root/creation/v1/cleanup-pending";
pub const CLOUDFLARE_DERIVER_TENANT_ROOT_INITIAL_ACTIVATION_PRIVATE_REQUEST_PATH: &str =
    "/router-ab/internal/deriver/tenant-root/creation/v1/activate";
pub const CLOUDFLARE_DERIVER_TENANT_ROOT_REFRESH_ACTIVATION_PRIVATE_REQUEST_PATH: &str =
    "/router-ab/internal/deriver/tenant-root/refresh/v1/activate";
pub const CLOUDFLARE_TENANT_ROOT_CONTROL_PLANE_CREATE_TENANT_ROOT_PRIVATE_REQUEST_PATH: &str =
    "/tenant-root-control-plane/creation/v1/create";
pub const CLOUDFLARE_TENANT_ROOT_CONTROL_PLANE_ROLE_CREATION_COMMAND_PRIVATE_REQUEST_PATH: &str =
    "/tenant-root-control-plane/creation/v1/role-command";
pub const CLOUDFLARE_TENANT_ROOT_CONTROL_PLANE_REFRESH_COMMANDS_PRIVATE_REQUEST_PATH: &str =
    "/tenant-root-control-plane/refresh/v1/commands";
pub const CLOUDFLARE_TENANT_ROOT_CONTROL_PLANE_REFRESH_ACTIVATION_PRIVATE_REQUEST_PATH: &str =
    "/tenant-root-control-plane/refresh/v1/activate";
pub const CLOUDFLARE_TENANT_ROOT_CONTROL_PLANE_CLEANUP_COMMAND_PRIVATE_REQUEST_PATH: &str =
    "/tenant-root-control-plane/creation/v1/cleanup-command";
/// Tenant-root control-plane issuer operation: issue the initial activation receipt.
///
/// Private, internal-service-authenticated. The request carries only exact
/// canonical public installation, backup, and provider-canary artifacts.
pub const CLOUDFLARE_TENANT_ROOT_CONTROL_PLANE_INITIAL_ACTIVATION_PRIVATE_REQUEST_PATH: &str =
    "/tenant-root-control-plane/creation/v1/activate";
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
/// Public Router endpoint for Router A/B ECDSA derivation activation refresh.
pub const CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_REFRESH_PUBLIC_REQUEST_PATH: &str =
    "/router-ab/ecdsa-derivation/refresh";
/// Public Router endpoint for preparing Router A/B ECDSA derivation normal signing.
pub const CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_SIGNING_PREPARE_PUBLIC_REQUEST_PATH: &str =
    "/router-ab/ecdsa-derivation/sign/prepare";
/// Public Router endpoint for finalizing Router A/B ECDSA derivation normal signing.
pub const CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_SIGNING_PUBLIC_REQUEST_PATH: &str =
    "/router-ab/ecdsa-derivation/sign";
/// Private Router endpoint for an admitted linked-device ECDSA finalize request.
pub const CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_LINKED_SIGNING_PRIVATE_REQUEST_PATH: &str =
    "/router-ab/ecdsa-derivation/linked-device/sign";
/// Private Router endpoint for one admitted Ed25519 Yao ceremony execution.
pub const CLOUDFLARE_ROUTER_ED25519_YAO_EXECUTE_PRIVATE_REQUEST_PATH: &str =
    "/router-ab/router/ed25519-yao/execute";
/// Private Router endpoint for source-preserving linked-device registration.
pub const CLOUDFLARE_ROUTER_ED25519_YAO_SOURCE_PRESERVING_EXECUTE_PRIVATE_REQUEST_PATH: &str =
    "/router-ab/router/ed25519-yao/execute-source-preserving";
/// Private Router endpoint for promoting a verified recovery result.
pub const CLOUDFLARE_ROUTER_ED25519_YAO_RECOVERY_PROMOTE_PRIVATE_REQUEST_PATH: &str =
    "/router-ab/router/ed25519-yao/recovery/promote";
/// Authenticated internal Router endpoint for an admitted Ed25519 lane ceremony.
pub const CLOUDFLARE_ROUTER_ED25519_YAO_LANE_EXECUTE_PRIVATE_REQUEST_PATH: &str =
    "/router-ab/internal/ed25519-yao/lane/execute";

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
/// Private SigningWorker endpoint for one active additive-lane export share.
pub const CLOUDFLARE_SIGNING_WORKER_LINKED_ECDSA_EXPORT_SHARE_PATH: &str =
    "/router-ab/signing-worker/ecdsa-derivation/linked-device/export-share";
/// Private SigningWorker endpoint for validating active ECDSA export material without releasing a share.
pub const CLOUDFLARE_SIGNING_WORKER_ROUTER_AB_ECDSA_DERIVATION_EXPORT_PREFLIGHT_PATH: &str =
    "/router-ab/signing-worker/ecdsa-derivation/export-preflight";
/// Private SigningWorker endpoint for filling the Router A/B ECDSA derivation presignature pool.
pub const CLOUDFLARE_SIGNING_WORKER_ROUTER_AB_ECDSA_DERIVATION_PRESIGNATURE_POOL_PUT_PATH: &str =
    "/router-ab/signing-worker/ecdsa-derivation/presignature-pool/put";
/// Private SigningWorker endpoint for starting an ECDSA presign session.
pub const CLOUDFLARE_SIGNING_WORKER_ROUTER_AB_ECDSA_DERIVATION_PRESIGNATURE_SESSION_INIT_PATH:
    &str = "/router-ab/signing-worker/ecdsa-derivation/presignature-session/init";
/// Private SigningWorker endpoint for advancing an ECDSA presign session.
pub const CLOUDFLARE_SIGNING_WORKER_ROUTER_AB_ECDSA_DERIVATION_PRESIGNATURE_SESSION_STEP_PATH:
    &str = "/router-ab/signing-worker/ecdsa-derivation/presignature-session/step";
/// Private SigningWorker endpoint for starting one linked-device ECDSA presign session.
pub const CLOUDFLARE_SIGNING_WORKER_ROUTER_AB_ECDSA_DERIVATION_LINKED_PRESIGNATURE_SESSION_INIT_PATH:
    &str = "/router-ab/signing-worker/ecdsa-derivation/linked-device/presignature-session/init";
/// Private SigningWorker endpoint for advancing one linked-device ECDSA presign session.
pub const CLOUDFLARE_SIGNING_WORKER_ROUTER_AB_ECDSA_DERIVATION_LINKED_PRESIGNATURE_SESSION_STEP_PATH:
    &str = "/router-ab/signing-worker/ecdsa-derivation/linked-device/presignature-session/step";
/// Private SigningWorker endpoint for finalizing one linked-device ECDSA request.
pub const CLOUDFLARE_SIGNING_WORKER_ROUTER_AB_ECDSA_DERIVATION_LINKED_SIGNING_PATH: &str =
    "/router-ab/signing-worker/ecdsa-derivation/linked-device/sign";
/// SigningWorker-output Durable Object endpoint for starting a live ECDSA presign session.
pub const CLOUDFLARE_SIGNING_WORKER_ECDSA_PRESIGN_SESSION_DO_INIT_PATH: &str =
    "/router-ab/internal/signing-worker/ecdsa-presign-session/init";
/// SigningWorker-output Durable Object endpoint for advancing a live ECDSA presign session.
pub const CLOUDFLARE_SIGNING_WORKER_ECDSA_PRESIGN_SESSION_DO_STEP_PATH: &str =
    "/router-ab/internal/signing-worker/ecdsa-presign-session/step";
/// SigningWorker-output Durable Object endpoint for starting a linked-device ECDSA presign session.
pub const CLOUDFLARE_SIGNING_WORKER_LINKED_ECDSA_PRESIGN_SESSION_DO_INIT_PATH: &str =
    "/router-ab/internal/signing-worker/linked-ecdsa-presign-session/init";
/// SigningWorker-output Durable Object endpoint for advancing a linked-device ECDSA presign session.
pub const CLOUDFLARE_SIGNING_WORKER_LINKED_ECDSA_PRESIGN_SESSION_DO_STEP_PATH: &str =
    "/router-ab/internal/signing-worker/linked-ecdsa-presign-session/step";
/// SigningWorker-output Durable Object endpoint for consuming one completed linked-device
/// ECDSA presignature record.
pub const CLOUDFLARE_SIGNING_WORKER_LINKED_ECDSA_PRESIGNATURE_DO_CONSUME_PATH: &str =
    "/router-ab/internal/signing-worker/linked-ecdsa-presignature/consume";
/// Private SigningWorker endpoint for normal signing.
pub const CLOUDFLARE_SIGNING_WORKER_NORMAL_SIGNING_PATH: &str = "/router-ab/signing-worker/sign";
/// Authenticated private SigningWorker lane-material reducer endpoint.
pub const CLOUDFLARE_SIGNING_WORKER_LANE_MATERIAL_COMMAND_PATH: &str =
    "/router-ab/internal/signing-worker/lane-material/command";
/// Authenticated private SigningWorker endpoint for ECDSA lane execution.
pub const CLOUDFLARE_SIGNING_WORKER_ECDSA_LANE_EXECUTE_PATH: &str =
    "/router-ab/internal/signing-worker/ecdsa-additive-lane/execute";
/// Authenticated private SigningWorker endpoint for ECDSA lane activation.
pub const CLOUDFLARE_SIGNING_WORKER_ECDSA_LANE_ACTIVATE_PATH: &str =
    "/router-ab/internal/signing-worker/ecdsa-additive-lane/activate";
/// Authenticated private SigningWorker endpoint for Ed25519 Yao lane activation.
pub const CLOUDFLARE_SIGNING_WORKER_ED25519_YAO_LANE_ACTIVATE_PATH: &str =
    "/router-ab/internal/signing-worker/ed25519-yao-lane/activate";
/// Authenticated private SigningWorker endpoint for exact Ed25519 Yao lane retirement.
pub const CLOUDFLARE_SIGNING_WORKER_ED25519_YAO_LANE_RETIRE_PATH: &str =
    "/router-ab/internal/signing-worker/ed25519-yao-lane/retire";
/// Authenticated private SigningWorker endpoint for exact ECDSA lane retirement.
pub const CLOUDFLARE_SIGNING_WORKER_ECDSA_LANE_RETIRE_PATH: &str =
    "/router-ab/internal/signing-worker/ecdsa-additive-lane/retire";
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
#[allow(dead_code)]
const CLOUDFLARE_DERIVER_A_TENANT_ROOT_CREATE_ROLE_SHARE_PRIVATE_REQUEST_URL: &str = concat!(
    "https://router-ab-deriver-a.internal",
    "/router-ab/internal/deriver/tenant-root/creation/v1/create-role-share"
);
#[cfg(feature = "workers-rs")]
#[allow(dead_code)]
const CLOUDFLARE_DERIVER_B_TENANT_ROOT_CREATE_ROLE_SHARE_PRIVATE_REQUEST_URL: &str = concat!(
    "https://router-ab-deriver-b.internal",
    "/router-ab/internal/deriver/tenant-root/creation/v1/create-role-share"
);
#[cfg(feature = "workers-rs")]
const CLOUDFLARE_DERIVER_A_TENANT_ROOT_CLEANUP_PENDING_PRIVATE_REQUEST_URL: &str = concat!(
    "https://router-ab-deriver-a.internal",
    "/router-ab/internal/deriver/tenant-root/creation/v1/cleanup-pending"
);
#[cfg(feature = "workers-rs")]
const CLOUDFLARE_DERIVER_B_TENANT_ROOT_CLEANUP_PENDING_PRIVATE_REQUEST_URL: &str = concat!(
    "https://router-ab-deriver-b.internal",
    "/router-ab/internal/deriver/tenant-root/creation/v1/cleanup-pending"
);
#[cfg(feature = "workers-rs")]
const CLOUDFLARE_DERIVER_A_TENANT_ROOT_INITIAL_ACTIVATION_PRIVATE_REQUEST_URL: &str = concat!(
    "https://router-ab-deriver-a.internal",
    "/router-ab/internal/deriver/tenant-root/creation/v1/activate"
);
#[cfg(feature = "workers-rs")]
const CLOUDFLARE_DERIVER_B_TENANT_ROOT_INITIAL_ACTIVATION_PRIVATE_REQUEST_URL: &str = concat!(
    "https://router-ab-deriver-b.internal",
    "/router-ab/internal/deriver/tenant-root/creation/v1/activate"
);
#[cfg(feature = "workers-rs")]
const CLOUDFLARE_DERIVER_A_TENANT_ROOT_REFRESH_ACTIVATION_PRIVATE_REQUEST_URL: &str = concat!(
    "https://router-ab-deriver-a.internal",
    "/router-ab/internal/deriver/tenant-root/refresh/v1/activate"
);
#[cfg(feature = "workers-rs")]
const CLOUDFLARE_DERIVER_B_TENANT_ROOT_REFRESH_ACTIVATION_PRIVATE_REQUEST_URL: &str = concat!(
    "https://router-ab-deriver-b.internal",
    "/router-ab/internal/deriver/tenant-root/refresh/v1/activate"
);
#[cfg(feature = "workers-rs")]
const CLOUDFLARE_TENANT_ROOT_CONTROL_PLANE_CREATE_TENANT_ROOT_PRIVATE_REQUEST_URL: &str = concat!(
    "https://router-ab-tenant-root-control-plane.internal",
    "/tenant-root-control-plane/creation/v1/create"
);
#[cfg(feature = "workers-rs")]
const CLOUDFLARE_TENANT_ROOT_CONTROL_PLANE_ROLE_CREATION_COMMAND_PRIVATE_REQUEST_URL: &str = concat!(
    "https://router-ab-tenant-root-control-plane.internal",
    "/tenant-root-control-plane/creation/v1/role-command"
);
#[cfg(feature = "workers-rs")]
const CLOUDFLARE_TENANT_ROOT_CONTROL_PLANE_REFRESH_COMMANDS_PRIVATE_REQUEST_URL: &str = concat!(
    "https://router-ab-tenant-root-control-plane.internal",
    "/tenant-root-control-plane/refresh/v1/commands"
);
#[cfg(feature = "workers-rs")]
const CLOUDFLARE_TENANT_ROOT_CONTROL_PLANE_REFRESH_ACTIVATION_PRIVATE_REQUEST_URL: &str = concat!(
    "https://router-ab-tenant-root-control-plane.internal",
    "/tenant-root-control-plane/refresh/v1/activate"
);
#[cfg(feature = "workers-rs")]
const CLOUDFLARE_TENANT_ROOT_CONTROL_PLANE_CLEANUP_COMMAND_PRIVATE_REQUEST_URL: &str = concat!(
    "https://router-ab-tenant-root-control-plane.internal",
    "/tenant-root-control-plane/creation/v1/cleanup-command"
);
#[cfg(feature = "workers-rs")]
const CLOUDFLARE_TENANT_ROOT_CONTROL_PLANE_INITIAL_ACTIVATION_PRIVATE_REQUEST_URL: &str = concat!(
    "https://router-ab-tenant-root-control-plane.internal",
    "/tenant-root-control-plane/creation/v1/activate"
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
const CLOUDFLARE_SIGNING_WORKER_ROUTER_AB_ECDSA_DERIVATION_EXPORT_PREFLIGHT_URL: &str = concat!(
    "https://router-ab-signing-worker.internal",
    "/router-ab/signing-worker/ecdsa-derivation/export-preflight"
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
const CLOUDFLARE_SIGNING_WORKER_ROUTER_AB_ECDSA_DERIVATION_LINKED_SIGNING_URL: &str = concat!(
    "https://router-ab-signing-worker.internal",
    "/router-ab/signing-worker/ecdsa-derivation/linked-device/sign"
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
        CloudflareWorkerRoleV1::Router
        | CloudflareWorkerRoleV1::SigningWorker
        | CloudflareWorkerRoleV1::TenantRootControlPlane => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            message,
        )),
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
        | CloudflareWorkerRoleV1::DeriverB
        | CloudflareWorkerRoleV1::TenantRootControlPlane => Err(RouterAbProtocolError::new(
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
pub(crate) fn cloudflare_deriver_tenant_root_create_role_share_service_url(
    peer: &CloudflarePeerBindingV1,
) -> RouterAbProtocolResult<&'static str> {
    cloudflare_deriver_peer_url(
        peer,
        CLOUDFLARE_DERIVER_A_TENANT_ROOT_CREATE_ROLE_SHARE_PRIVATE_REQUEST_URL,
        CLOUDFLARE_DERIVER_B_TENANT_ROOT_CREATE_ROLE_SHARE_PRIVATE_REQUEST_URL,
        "tenant-root role creation can target only Deriver A or Deriver B",
    )
}

#[cfg(feature = "workers-rs")]
pub(crate) fn cloudflare_deriver_tenant_root_cleanup_pending_service_url(
    peer: &CloudflarePeerBindingV1,
) -> RouterAbProtocolResult<&'static str> {
    cloudflare_deriver_peer_url(
        peer,
        CLOUDFLARE_DERIVER_A_TENANT_ROOT_CLEANUP_PENDING_PRIVATE_REQUEST_URL,
        CLOUDFLARE_DERIVER_B_TENANT_ROOT_CLEANUP_PENDING_PRIVATE_REQUEST_URL,
        "tenant-root pending cleanup can target only Deriver A or Deriver B",
    )
}

#[cfg(feature = "workers-rs")]
pub(crate) fn cloudflare_deriver_tenant_root_initial_activation_service_url(
    peer: &CloudflarePeerBindingV1,
) -> RouterAbProtocolResult<&'static str> {
    cloudflare_deriver_peer_url(
        peer,
        CLOUDFLARE_DERIVER_A_TENANT_ROOT_INITIAL_ACTIVATION_PRIVATE_REQUEST_URL,
        CLOUDFLARE_DERIVER_B_TENANT_ROOT_INITIAL_ACTIVATION_PRIVATE_REQUEST_URL,
        "tenant-root initial activation can target only Deriver A or Deriver B",
    )
}

#[cfg(feature = "workers-rs")]
pub(crate) fn cloudflare_deriver_tenant_root_refresh_activation_service_url(
    peer: &CloudflarePeerBindingV1,
) -> RouterAbProtocolResult<&'static str> {
    cloudflare_deriver_peer_url(
        peer,
        CLOUDFLARE_DERIVER_A_TENANT_ROOT_REFRESH_ACTIVATION_PRIVATE_REQUEST_URL,
        CLOUDFLARE_DERIVER_B_TENANT_ROOT_REFRESH_ACTIVATION_PRIVATE_REQUEST_URL,
        "tenant-root refresh activation can target only Deriver A or Deriver B",
    )
}

#[cfg(feature = "workers-rs")]
pub(crate) const fn cloudflare_tenant_root_control_plane_create_tenant_root_service_url(
) -> &'static str {
    CLOUDFLARE_TENANT_ROOT_CONTROL_PLANE_CREATE_TENANT_ROOT_PRIVATE_REQUEST_URL
}

#[cfg(feature = "workers-rs")]
pub(crate) const fn cloudflare_tenant_root_control_plane_role_creation_command_service_url(
) -> &'static str {
    CLOUDFLARE_TENANT_ROOT_CONTROL_PLANE_ROLE_CREATION_COMMAND_PRIVATE_REQUEST_URL
}

#[cfg(feature = "workers-rs")]
pub(crate) const fn cloudflare_tenant_root_control_plane_refresh_commands_service_url(
) -> &'static str {
    CLOUDFLARE_TENANT_ROOT_CONTROL_PLANE_REFRESH_COMMANDS_PRIVATE_REQUEST_URL
}

#[cfg(feature = "workers-rs")]
pub(crate) const fn cloudflare_tenant_root_control_plane_refresh_activation_service_url(
) -> &'static str {
    CLOUDFLARE_TENANT_ROOT_CONTROL_PLANE_REFRESH_ACTIVATION_PRIVATE_REQUEST_URL
}

#[cfg(feature = "workers-rs")]
pub(crate) const fn cloudflare_tenant_root_control_plane_cleanup_command_service_url(
) -> &'static str {
    CLOUDFLARE_TENANT_ROOT_CONTROL_PLANE_CLEANUP_COMMAND_PRIVATE_REQUEST_URL
}

#[cfg(feature = "workers-rs")]
pub(crate) const fn cloudflare_tenant_root_control_plane_initial_activation_service_url(
) -> &'static str {
    CLOUDFLARE_TENANT_ROOT_CONTROL_PLANE_INITIAL_ACTIVATION_PRIVATE_REQUEST_URL
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
pub(crate) fn cloudflare_router_ab_ecdsa_derivation_signing_worker_export_preflight_service_url(
    peer: &CloudflarePeerBindingV1,
) -> RouterAbProtocolResult<&'static str> {
    cloudflare_signing_worker_url(
        peer,
        CLOUDFLARE_SIGNING_WORKER_ROUTER_AB_ECDSA_DERIVATION_EXPORT_PREFLIGHT_URL,
        "strict Router A/B ECDSA export preflight can target only SigningWorker",
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

#[cfg(feature = "workers-rs")]
pub(crate) fn cloudflare_signing_worker_linked_device_ecdsa_finalize_service_url(
    peer: &CloudflarePeerBindingV1,
) -> RouterAbProtocolResult<&'static str> {
    cloudflare_signing_worker_url(
        peer,
        CLOUDFLARE_SIGNING_WORKER_ROUTER_AB_ECDSA_DERIVATION_LINKED_SIGNING_URL,
        "linked ECDSA finalize can target only SigningWorker",
    )
}
