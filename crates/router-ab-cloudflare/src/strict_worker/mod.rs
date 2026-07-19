#![cfg(any(
    feature = "strict-worker-router-entrypoint",
    feature = "strict-worker-deriver-a-entrypoint",
    feature = "strict-worker-deriver-b-entrypoint",
    feature = "strict-worker-signing-worker-entrypoint"
))]

use crate::cloudflare_router_error_status;
#[cfg(feature = "strict-worker-router-entrypoint")]
use crate::{
    build_cloudflare_router_public_keyset_v2, cloudflare_now_unix_ms_v1,
    cloudflare_router_normal_signing_cors_allowed_origin_v1, cloudflare_trusted_source_digest_v1,
    handle_cloudflare_router_ab_ecdsa_derivation_activation_authenticated_public_request_v1,
    handle_cloudflare_router_ab_ecdsa_derivation_activation_refresh_authenticated_public_request_v1,
    handle_cloudflare_router_ab_ecdsa_derivation_evm_digest_signing_finalize_authenticated_public_request_v1,
    handle_cloudflare_router_ab_ecdsa_derivation_evm_digest_signing_prepare_authenticated_public_request_v1,
    handle_cloudflare_router_ab_ecdsa_derivation_explicit_export_authenticated_public_request_v1,
    handle_cloudflare_router_ab_ecdsa_derivation_recovery_authenticated_public_request_v1,
    handle_cloudflare_router_ab_ecdsa_derivation_registration_bootstrap_authenticated_public_request_v1,
    handle_cloudflare_router_normal_signing_finalize_authenticated_public_request_v2,
    handle_cloudflare_router_normal_signing_prepare_authenticated_public_request_v2,
    handle_cloudflare_router_wallet_budget_put_grant_private_fetch_v1,
    handle_cloudflare_router_wallet_budget_status_authenticated_public_request_v1,
    load_cloudflare_router_ed25519_jwks_jwt_verifier_v1,
    parse_cloudflare_router_ab_ecdsa_derivation_activation_request_v1_json,
    parse_cloudflare_router_ab_ecdsa_derivation_export_command_v1_json,
    parse_cloudflare_router_bearer_authorization_from_request_v1,
    parse_cloudflare_router_budgeted_ed25519_finalize_request_v2_json,
    parse_cloudflare_router_budgeted_router_ab_ecdsa_derivation_finalize_request_v1_json,
    CloudflareRouterWalletSessionCredentialV1, CloudflareRouterWorkerRuntimeV1,
    CloudflareWorkerEnvReaderV1,
    CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_ACTIVATION_PUBLIC_REQUEST_PATH,
    CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_ADD_SIGNER_PUBLIC_REQUEST_PATH,
    CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_EXPORT_PUBLIC_REQUEST_PATH,
    CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_RECOVERY_PUBLIC_REQUEST_PATH,
    CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_REFRESH_PUBLIC_REQUEST_PATH,
    CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_REGISTRATION_PUBLIC_REQUEST_PATH,
    CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_SIGNING_PREPARE_PUBLIC_REQUEST_PATH,
    CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_SIGNING_PUBLIC_REQUEST_PATH,
    CLOUDFLARE_ROUTER_NORMAL_SIGNING_PUBLIC_REQUEST_PATH,
    CLOUDFLARE_ROUTER_NORMAL_SIGNING_ROUND1_PREPARE_PUBLIC_REQUEST_PATH,
    CLOUDFLARE_ROUTER_PUBLIC_KEYSET_PATH, CLOUDFLARE_ROUTER_PUBLIC_KEYSET_WELL_KNOWN_PATH,
    CLOUDFLARE_ROUTER_WALLET_BUDGET_PUT_GRANT_PRIVATE_REQUEST_PATH,
    CLOUDFLARE_ROUTER_WALLET_BUDGET_STATUS_PUBLIC_REQUEST_PATH,
};
#[cfg(any(
    feature = "strict-worker-deriver-a-entrypoint",
    feature = "strict-worker-deriver-b-entrypoint"
))]
use crate::{
    cloudflare_now_unix_ms_v1,
    decrypt_and_handle_cloudflare_mpc_prf_recipient_proof_bundle_signer_private_request_v1,
    decrypt_and_handle_cloudflare_router_ab_ecdsa_derivation_activation_refresh_signer_private_request_v1,
    decrypt_and_handle_cloudflare_router_ab_ecdsa_derivation_export_signer_private_request_v1,
    decrypt_and_handle_cloudflare_router_ab_ecdsa_derivation_recovery_signer_private_request_v1,
    decrypt_and_handle_cloudflare_router_ab_ecdsa_derivation_registration_signer_private_request_v1,
    CloudflarePreloadedSignerHostV1, CloudflareRootShareStartupMetadataV1,
    CloudflareRouterAbEcdsaDerivationDeriverActivationRefreshPrivateRequestV1,
    CloudflareRouterAbEcdsaDerivationDeriverExportPrivateRequestV1,
    CloudflareRouterAbEcdsaDerivationDeriverRecoveryPrivateRequestV1,
    CloudflareRouterAbEcdsaDerivationDeriverRegistrationPrivateRequestV1,
    CloudflareSignerEnvelopeHpkeDecryptKeyBindingSetV1, CloudflareSignerHostPreloadInputV1,
    CloudflareSignerHostPreloadPlanV1, CloudflareSignerPeerSigningKeyBindingV1,
    CloudflareSignerPrivateBootstrapRequestV1, CloudflareWorkerRoleV1,
};
#[cfg(feature = "strict-worker-signing-worker-entrypoint")]
use crate::{
    cloudflare_now_unix_ms_v1,
    handle_cloudflare_router_ab_ecdsa_derivation_signing_worker_activation_fetch_v1,
    handle_cloudflare_router_ab_ecdsa_derivation_signing_worker_activation_refresh_fetch_v1,
    handle_cloudflare_signing_worker_ecdsa_export_share_private_fetch_v1,
    handle_cloudflare_signing_worker_ecdsa_presign_session_init_private_fetch_v1,
    handle_cloudflare_signing_worker_ecdsa_presign_session_step_private_fetch_v1,
    handle_cloudflare_signing_worker_ed25519_yao_deriver_a_v1,
    handle_cloudflare_signing_worker_ed25519_yao_deriver_b_v1,
    handle_cloudflare_signing_worker_ed25519_yao_recovery_promote_v1,
    handle_cloudflare_signing_worker_normal_signing_private_fetch_v1,
    handle_cloudflare_signing_worker_normal_signing_round1_prepare_private_fetch_v1,
    handle_cloudflare_signing_worker_recipient_proof_bundle_activation_fetch_v1,
    handle_cloudflare_signing_worker_router_ab_ecdsa_derivation_evm_digest_finalize_private_fetch_v1,
    handle_cloudflare_signing_worker_router_ab_ecdsa_derivation_evm_digest_prepare_private_fetch_from_pool_v1,
    handle_cloudflare_signing_worker_router_ab_ecdsa_derivation_presignature_pool_put_private_fetch_v1,
    CloudflareEd25519YaoNormalSigningHandlerV1,
    CloudflareRoleSeparatedRouterAbEcdsaDerivationEvmDigestFinalizeHandlerV1,
    CloudflareSigningWorkerRuntimeV1, CLOUDFLARE_SIGNING_WORKER_ED25519_YAO_DERIVER_A_PATH,
    CLOUDFLARE_SIGNING_WORKER_ED25519_YAO_DERIVER_B_PATH,
    CLOUDFLARE_SIGNING_WORKER_ED25519_YAO_RECOVERY_PROMOTE_PATH,
    CLOUDFLARE_SIGNING_WORKER_NORMAL_SIGNING_PATH,
    CLOUDFLARE_SIGNING_WORKER_NORMAL_SIGNING_ROUND1_PREPARE_PATH,
    CLOUDFLARE_SIGNING_WORKER_PROOF_BUNDLE_ACTIVATION_PATH,
    CLOUDFLARE_SIGNING_WORKER_ROUTER_AB_ECDSA_DERIVATION_ACTIVATION_PATH,
    CLOUDFLARE_SIGNING_WORKER_ROUTER_AB_ECDSA_DERIVATION_EXPORT_SHARE_PATH,
    CLOUDFLARE_SIGNING_WORKER_ROUTER_AB_ECDSA_DERIVATION_PRESIGNATURE_POOL_PUT_PATH,
    CLOUDFLARE_SIGNING_WORKER_ROUTER_AB_ECDSA_DERIVATION_PRESIGNATURE_SESSION_INIT_PATH,
    CLOUDFLARE_SIGNING_WORKER_ROUTER_AB_ECDSA_DERIVATION_PRESIGNATURE_SESSION_STEP_PATH,
    CLOUDFLARE_SIGNING_WORKER_ROUTER_AB_ECDSA_DERIVATION_REFRESH_PATH,
    CLOUDFLARE_SIGNING_WORKER_ROUTER_AB_ECDSA_DERIVATION_SIGNING_PATH,
    CLOUDFLARE_SIGNING_WORKER_ROUTER_AB_ECDSA_DERIVATION_SIGNING_PREPARE_PATH,
};
#[cfg(any(
    feature = "strict-worker-router-entrypoint",
    feature = "strict-worker-deriver-a-entrypoint",
    feature = "strict-worker-deriver-b-entrypoint",
    feature = "strict-worker-signing-worker-entrypoint"
))]
use crate::{
    cloudflare_private_service_auth_error_response_v1,
    require_cloudflare_internal_service_auth_request_v1,
};
#[cfg(feature = "strict-worker-deriver-a-entrypoint")]
use crate::{
    handle_cloudflare_ed25519_yao_deriver_a_start_v1, preload_cloudflare_deriver_a_host_v1,
    CloudflareDeriverAWorkerRuntimeV1, CLOUDFLARE_DERIVER_A_ED25519_YAO_ACTIVATION_START_PATH,
    CLOUDFLARE_DERIVER_A_ED25519_YAO_EXPORT_START_PATH, CLOUDFLARE_DERIVER_A_PRIVATE_REQUEST_PATH,
    CLOUDFLARE_DERIVER_A_ROUTER_AB_ECDSA_DERIVATION_EXPORT_PRIVATE_REQUEST_PATH,
    CLOUDFLARE_DERIVER_A_ROUTER_AB_ECDSA_DERIVATION_RECOVERY_PRIVATE_REQUEST_PATH,
    CLOUDFLARE_DERIVER_A_ROUTER_AB_ECDSA_DERIVATION_REFRESH_PRIVATE_REQUEST_PATH,
    CLOUDFLARE_DERIVER_A_ROUTER_AB_ECDSA_DERIVATION_REGISTRATION_PRIVATE_REQUEST_PATH,
};
#[cfg(feature = "strict-worker-deriver-b-entrypoint")]
use crate::{
    handle_cloudflare_ed25519_yao_deriver_b_result_v1,
    handle_cloudflare_ed25519_yao_deriver_b_stage_v1,
    handle_cloudflare_ed25519_yao_deriver_b_websocket_v1, preload_cloudflare_deriver_b_host_v1,
    CloudflareDeriverBWorkerRuntimeV1, CLOUDFLARE_DERIVER_B_ED25519_YAO_ACTIVATION_RESULT_PATH,
    CLOUDFLARE_DERIVER_B_ED25519_YAO_ACTIVATION_STAGE_PATH,
    CLOUDFLARE_DERIVER_B_ED25519_YAO_DUPLEX_PATH,
    CLOUDFLARE_DERIVER_B_ED25519_YAO_EXPORT_RESULT_PATH,
    CLOUDFLARE_DERIVER_B_ED25519_YAO_EXPORT_STAGE_PATH, CLOUDFLARE_DERIVER_B_PRIVATE_REQUEST_PATH,
    CLOUDFLARE_DERIVER_B_ROUTER_AB_ECDSA_DERIVATION_EXPORT_PRIVATE_REQUEST_PATH,
    CLOUDFLARE_DERIVER_B_ROUTER_AB_ECDSA_DERIVATION_RECOVERY_PRIVATE_REQUEST_PATH,
    CLOUDFLARE_DERIVER_B_ROUTER_AB_ECDSA_DERIVATION_REFRESH_PRIVATE_REQUEST_PATH,
    CLOUDFLARE_DERIVER_B_ROUTER_AB_ECDSA_DERIVATION_REGISTRATION_PRIVATE_REQUEST_PATH,
};
use router_ab_core::RouterAbProtocolError;
#[cfg(feature = "strict-worker-router-entrypoint")]
use router_ab_core::{
    parse_router_ab_ecdsa_derivation_activation_refresh_request_v1_json,
    parse_router_ab_ecdsa_derivation_evm_digest_signing_request_v1_json,
    parse_router_ab_ecdsa_derivation_recovery_request_v1_json,
    parse_router_ab_ecdsa_derivation_registration_bootstrap_request_v1_json,
    parse_router_ab_ed25519_normal_signing_prepare_request_v2_json,
    RouterAbEcdsaDerivationRegistrationPurposeV1,
};
#[cfg(any(
    feature = "strict-worker-deriver-a-entrypoint",
    feature = "strict-worker-deriver-b-entrypoint"
))]
use router_ab_core::{
    AbPeerMessageVerifyingKeyV1, Ed25519YaoInputKindV1, Role, RouterAbProtocolResult, SignerSetV1,
};
#[cfg(feature = "strict-worker-router-entrypoint")]
use worker::Method;
use worker::{Context, Env, Request, Response};

#[cfg(feature = "strict-worker-router-entrypoint")]
mod cors;
#[cfg(any(
    feature = "strict-worker-deriver-a-entrypoint",
    feature = "strict-worker-deriver-b-entrypoint"
))]
mod deriver;
#[cfg(feature = "strict-worker-router-entrypoint")]
mod router;
#[cfg(feature = "strict-worker-signing-worker-entrypoint")]
mod signing_worker;
#[cfg(feature = "strict-worker-deriver-a-entrypoint")]
use deriver::handle_strict_deriver_a_fetch_v1;
#[cfg(feature = "strict-worker-deriver-b-entrypoint")]
use deriver::handle_strict_deriver_b_fetch_v1;
#[cfg(feature = "strict-worker-router-entrypoint")]
use router::handle_strict_router_fetch_v1;
#[cfg(feature = "strict-worker-signing-worker-entrypoint")]
use signing_worker::handle_strict_signing_worker_fetch_v1;

/// Deployable workers-rs fetch entrypoint for strict Router/A/B proof-bundle Workers.
#[worker::event(fetch)]
pub async fn fetch(request: Request, env: Env, _ctx: Context) -> worker::Result<Response> {
    #[cfg(feature = "strict-worker-router-entrypoint")]
    {
        return handle_strict_router_fetch_v1(request, env).await;
    }
    #[cfg(feature = "strict-worker-deriver-a-entrypoint")]
    {
        return handle_strict_deriver_a_fetch_v1(request, env, _ctx).await;
    }
    #[cfg(feature = "strict-worker-deriver-b-entrypoint")]
    {
        return handle_strict_deriver_b_fetch_v1(request, env, _ctx).await;
    }
    #[cfg(feature = "strict-worker-signing-worker-entrypoint")]
    {
        return handle_strict_signing_worker_fetch_v1(request, env).await;
    }
}

pub(super) fn cloudflare_protocol_error_response_v1(
    err: RouterAbProtocolError,
) -> worker::Result<Response> {
    Response::error(
        format!("{:?}: {}", err.code(), err.message()),
        cloudflare_router_error_status(err.code()),
    )
}
