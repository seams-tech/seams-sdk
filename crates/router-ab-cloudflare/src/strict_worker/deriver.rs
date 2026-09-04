use super::*;
use crate::tenant_root_role_runtime::{
    CloudflareDeriverTenantRootCleanupRequestV1,
    CloudflareDeriverTenantRootCreateRoleShareRequestV1,
    CloudflareDeriverTenantRootInitialActivationRequestV1,
    CloudflareDeriverTenantRootManagedRestoreForwardRefreshRequestV1,
    CloudflareDeriverTenantRootManagedRestoreRequestV1,
    CloudflareDeriverTenantRootRefreshActivationRequestV1,
    CloudflareDeriverTenantRootRefreshRequestV1,
};
use crate::{
    build_cloudflare_ecdsa_threshold_prf_outer_request_v2,
    build_cloudflare_preloaded_signer_host_v1, cloudflare_now_unix_ms_v1,
    cloudflare_random_bytes_v1, load_cloudflare_active_tenant_root_role_share_v1,
    CloudflareAuthenticatedSignerPrivateBootstrapRequestV1, CloudflarePeerBindingV1,
    CloudflareRootShareStartupMetadataV1,
    CLOUDFLARE_DERIVER_TENANT_ROOT_CLEANUP_PRIVATE_REQUEST_PATH,
    CLOUDFLARE_DERIVER_TENANT_ROOT_CREATE_ROLE_SHARE_PRIVATE_REQUEST_PATH,
    CLOUDFLARE_DERIVER_TENANT_ROOT_INITIAL_ACTIVATION_PRIVATE_REQUEST_PATH,
    CLOUDFLARE_DERIVER_TENANT_ROOT_MANAGED_RESTORE_FORWARD_REFRESH_PRIVATE_REQUEST_PATH,
    CLOUDFLARE_DERIVER_TENANT_ROOT_MANAGED_RESTORE_PRIVATE_REQUEST_PATH,
    CLOUDFLARE_DERIVER_TENANT_ROOT_REFRESH_ACTIVATION_PRIVATE_REQUEST_PATH,
    CLOUDFLARE_DERIVER_TENANT_ROOT_REFRESH_PRIVATE_REQUEST_PATH,
};
use router_ab_core::VerifiedTenantRootOnlineRoleShareV1;

#[cfg(feature = "strict-worker-deriver-a-entrypoint")]
pub(super) async fn handle_strict_deriver_a_fetch_v1(
    request: Request,
    env: Env,
    context: Context,
) -> worker::Result<Response> {
    if let Err(err) = require_cloudflare_internal_service_auth_request_v1(&request, &env) {
        return cloudflare_private_service_auth_error_response_v1(err);
    }
    if request.path() == CLOUDFLARE_INTERNAL_PREWARM_PATH {
        if request.method() != Method::Post {
            return cloudflare_prewarm_response_v1(&request);
        }
        if let Err(err) = CloudflareDeriverAWorkerRuntimeV1::from_worker_env(&env) {
            return cloudflare_protocol_error_response_v1(err);
        }
        return cloudflare_prewarm_response_v1(&request);
    }
    let runtime = match CloudflareDeriverAWorkerRuntimeV1::from_worker_env(&env) {
        Ok(runtime) => StrictDeriverRuntimeV1::DeriverA(runtime),
        Err(err) => return cloudflare_protocol_error_response_v1(err),
    };
    handle_strict_deriver_fetch_v1(request, env, runtime, context).await
}

#[cfg(any(
    feature = "strict-worker-deriver-a-entrypoint",
    feature = "strict-worker-deriver-b-entrypoint"
))]
enum StrictDeriverRuntimeV1 {
    #[cfg(feature = "strict-worker-deriver-a-entrypoint")]
    DeriverA(CloudflareDeriverAWorkerRuntimeV1),
    #[cfg(feature = "strict-worker-deriver-b-entrypoint")]
    DeriverB(CloudflareDeriverBWorkerRuntimeV1),
}

#[cfg(any(
    feature = "strict-worker-deriver-a-entrypoint",
    feature = "strict-worker-deriver-b-entrypoint"
))]
impl StrictDeriverRuntimeV1 {
    fn label(&self) -> &'static str {
        match self {
            #[cfg(feature = "strict-worker-deriver-a-entrypoint")]
            Self::DeriverA(_) => "Deriver A",
            #[cfg(feature = "strict-worker-deriver-b-entrypoint")]
            Self::DeriverB(_) => "Deriver B",
        }
    }

    fn worker_role(&self) -> CloudflareWorkerRoleV1 {
        match self {
            #[cfg(feature = "strict-worker-deriver-a-entrypoint")]
            Self::DeriverA(_) => CloudflareWorkerRoleV1::DeriverA,
            #[cfg(feature = "strict-worker-deriver-b-entrypoint")]
            Self::DeriverB(_) => CloudflareWorkerRoleV1::DeriverB,
        }
    }

    fn protocol_role(&self) -> Role {
        match self {
            #[cfg(feature = "strict-worker-deriver-a-entrypoint")]
            Self::DeriverA(_) => Role::SignerA,
            #[cfg(feature = "strict-worker-deriver-b-entrypoint")]
            Self::DeriverB(_) => Role::SignerB,
        }
    }

    fn registration_private_path(&self) -> &'static str {
        match self {
            #[cfg(feature = "strict-worker-deriver-a-entrypoint")]
            Self::DeriverA(_) => {
                CLOUDFLARE_DERIVER_A_ROUTER_AB_ECDSA_DERIVATION_REGISTRATION_PRIVATE_REQUEST_PATH
            }
            #[cfg(feature = "strict-worker-deriver-b-entrypoint")]
            Self::DeriverB(_) => {
                CLOUDFLARE_DERIVER_B_ROUTER_AB_ECDSA_DERIVATION_REGISTRATION_PRIVATE_REQUEST_PATH
            }
        }
    }

    fn export_private_path(&self) -> &'static str {
        match self {
            #[cfg(feature = "strict-worker-deriver-a-entrypoint")]
            Self::DeriverA(_) => {
                CLOUDFLARE_DERIVER_A_ROUTER_AB_ECDSA_DERIVATION_EXPORT_PRIVATE_REQUEST_PATH
            }
            #[cfg(feature = "strict-worker-deriver-b-entrypoint")]
            Self::DeriverB(_) => {
                CLOUDFLARE_DERIVER_B_ROUTER_AB_ECDSA_DERIVATION_EXPORT_PRIVATE_REQUEST_PATH
            }
        }
    }

    fn refresh_private_path(&self) -> &'static str {
        match self {
            #[cfg(feature = "strict-worker-deriver-a-entrypoint")]
            Self::DeriverA(_) => {
                CLOUDFLARE_DERIVER_A_ROUTER_AB_ECDSA_DERIVATION_REFRESH_PRIVATE_REQUEST_PATH
            }
            #[cfg(feature = "strict-worker-deriver-b-entrypoint")]
            Self::DeriverB(_) => {
                CLOUDFLARE_DERIVER_B_ROUTER_AB_ECDSA_DERIVATION_REFRESH_PRIVATE_REQUEST_PATH
            }
        }
    }

    fn peer_verifying_keys_for_signer_set(
        &self,
        signer_set: &SignerSetV1,
    ) -> RouterAbProtocolResult<Vec<AbPeerMessageVerifyingKeyV1>> {
        match self {
            #[cfg(feature = "strict-worker-deriver-a-entrypoint")]
            Self::DeriverA(runtime) => runtime.peer_verifying_keys_for_signer_set(signer_set),
            #[cfg(feature = "strict-worker-deriver-b-entrypoint")]
            Self::DeriverB(runtime) => runtime.peer_verifying_keys_for_signer_set(signer_set),
        }
    }

    fn envelope_decrypt_key(&self) -> &CloudflareSignerEnvelopeHpkeDecryptKeyBindingSetV1 {
        match self {
            #[cfg(feature = "strict-worker-deriver-a-entrypoint")]
            Self::DeriverA(runtime) => runtime.envelope_decrypt_key(),
            #[cfg(feature = "strict-worker-deriver-b-entrypoint")]
            Self::DeriverB(runtime) => runtime.envelope_decrypt_key(),
        }
    }

    fn tenant_root_peer(&self) -> &CloudflarePeerBindingV1 {
        match self {
            #[cfg(feature = "strict-worker-deriver-a-entrypoint")]
            Self::DeriverA(runtime) => runtime.deriver_b_peer(),
            #[cfg(feature = "strict-worker-deriver-b-entrypoint")]
            Self::DeriverB(runtime) => runtime.deriver_a_peer(),
        }
    }

    fn route_error_message(&self) -> String {
        format!(
            "{} strict Worker route must be served at {}, {}, {}, {}, {}, {}, {}, {}, {}, or {}",
            self.label(),
            self.registration_private_path(),
            self.export_private_path(),
            self.refresh_private_path(),
            CLOUDFLARE_DERIVER_TENANT_ROOT_CREATE_ROLE_SHARE_PRIVATE_REQUEST_PATH,
            CLOUDFLARE_DERIVER_TENANT_ROOT_CLEANUP_PRIVATE_REQUEST_PATH,
            CLOUDFLARE_DERIVER_TENANT_ROOT_INITIAL_ACTIVATION_PRIVATE_REQUEST_PATH,
            CLOUDFLARE_DERIVER_TENANT_ROOT_REFRESH_ACTIVATION_PRIVATE_REQUEST_PATH,
            CLOUDFLARE_DERIVER_TENANT_ROOT_REFRESH_PRIVATE_REQUEST_PATH,
            CLOUDFLARE_DERIVER_TENANT_ROOT_MANAGED_RESTORE_PRIVATE_REQUEST_PATH,
            CLOUDFLARE_DERIVER_TENANT_ROOT_MANAGED_RESTORE_FORWARD_REFRESH_PRIVATE_REQUEST_PATH,
        )
    }
}

#[cfg(any(
    feature = "strict-worker-deriver-a-entrypoint",
    feature = "strict-worker-deriver-b-entrypoint"
))]
struct StrictDeriverPreloadedRequestV2 {
    host: CloudflarePreloadedSignerHostV1,
    root_share_metadata: CloudflareRootShareStartupMetadataV1,
    tenant_root_share: VerifiedTenantRootOnlineRoleShareV1,
}

#[cfg(any(
    feature = "strict-worker-deriver-a-entrypoint",
    feature = "strict-worker-deriver-b-entrypoint"
))]
async fn handle_strict_deriver_fetch_v1(
    mut request: Request,
    env: Env,
    runtime: StrictDeriverRuntimeV1,
    _context: Context,
) -> worker::Result<Response> {
    let path = request.path();
    let worker_role = runtime.worker_role();
    let label = runtime.label();
    let now_unix_ms = match cloudflare_now_unix_ms_v1() {
        Ok(now_unix_ms) => now_unix_ms,
        Err(err) => return cloudflare_protocol_error_response_v1(err),
    };

    #[cfg(debug_assertions)]
    if path == CLOUDFLARE_TENANT_ROOT_ROLE_D1_INTEGRATION_PATH
        && cloudflare_tenant_root_role_d1_integration_enabled_v1(&env)
    {
        let integration_request: CloudflareTenantRootRoleD1IntegrationRequestV1 =
            match parse_strict_deriver_json_v1(
                &mut request,
                format!("Router A/B strict {label} tenant-root role-store integration"),
            )
            .await?
            {
                Ok(parsed) => parsed,
                Err(response) => return Ok(response),
            };
        return match run_cloudflare_tenant_root_role_d1_integration_v1(&env, integration_request)
            .await
        {
            Ok(receipt) => Response::from_json(&receipt),
            Err(err) => Response::error(
                format!("tenant-root role-store integration failed: {err}"),
                500,
            ),
        };
    }

    if path == CLOUDFLARE_DERIVER_TENANT_ROOT_CREATE_ROLE_SHARE_PRIVATE_REQUEST_PATH {
        let creation_request: CloudflareDeriverTenantRootCreateRoleShareRequestV1 =
            match parse_strict_deriver_json_v1(
                &mut request,
                format!("Router A/B strict {label} tenant-root role creation"),
            )
            .await?
            {
                Ok(parsed) => parsed,
                Err(response) => return Ok(response),
            };
        return match crate::tenant_root_role_runtime::handle_cloudflare_deriver_tenant_root_create_role_share_v1(
            &env,
            worker_role,
            runtime.tenant_root_peer(),
            creation_request,
            now_unix_ms,
        )
        .await
        {
            Ok(response) => Response::from_json(&response),
            Err(error) => cloudflare_protocol_error_response_v1(error),
        };
    }

    if path == CLOUDFLARE_DERIVER_TENANT_ROOT_CLEANUP_PRIVATE_REQUEST_PATH {
        let cleanup_request: CloudflareDeriverTenantRootCleanupRequestV1 =
            match parse_strict_deriver_json_v1(
                &mut request,
                format!("Router A/B strict {label} tenant-root pending cleanup"),
            )
            .await?
            {
                Ok(parsed) => parsed,
                Err(response) => return Ok(response),
            };
        return match crate::tenant_root_role_runtime::handle_cloudflare_deriver_tenant_root_cleanup_v1(
            &env,
            worker_role,
            cleanup_request,
            now_unix_ms,
        )
        .await
        {
            Ok(response) => Response::from_json(&response),
            Err(error) => cloudflare_protocol_error_response_v1(error),
        };
    }

    if path == CLOUDFLARE_DERIVER_TENANT_ROOT_MANAGED_RESTORE_PRIVATE_REQUEST_PATH {
        let restore_request: CloudflareDeriverTenantRootManagedRestoreRequestV1 =
            match parse_strict_deriver_json_v1(
                &mut request,
                format!("Router A/B strict {label} tenant-root managed restore"),
            )
            .await?
            {
                Ok(parsed) => parsed,
                Err(response) => return Ok(response),
            };
        return match crate::tenant_root_role_runtime::
            handle_cloudflare_deriver_tenant_root_managed_restore_v1(
                &env,
                worker_role,
                restore_request,
                now_unix_ms,
            )
            .await
        {
            Ok(response) => Response::from_json(&response),
            Err(error) => cloudflare_protocol_error_response_v1(error),
        };
    }

    if path == CLOUDFLARE_DERIVER_TENANT_ROOT_MANAGED_RESTORE_FORWARD_REFRESH_PRIVATE_REQUEST_PATH {
        let forward_refresh_request:
            CloudflareDeriverTenantRootManagedRestoreForwardRefreshRequestV1 =
            match parse_strict_deriver_json_v1(
                &mut request,
                format!("Router A/B strict {label} tenant-root managed restore forward refresh"),
            )
            .await?
            {
                Ok(parsed) => parsed,
                Err(response) => return Ok(response),
            };
        return match crate::tenant_root_role_runtime::
            handle_cloudflare_deriver_tenant_root_managed_restore_forward_refresh_v1(
                &env,
                worker_role,
                forward_refresh_request,
                now_unix_ms,
            )
            .await
        {
            Ok(response) => Response::from_json(&response),
            Err(error) => cloudflare_protocol_error_response_v1(error),
        };
    }

    if path == CLOUDFLARE_DERIVER_TENANT_ROOT_INITIAL_ACTIVATION_PRIVATE_REQUEST_PATH {
        let activation_request: CloudflareDeriverTenantRootInitialActivationRequestV1 =
            match parse_strict_deriver_json_v1(
                &mut request,
                format!("Router A/B strict {label} tenant-root initial activation"),
            )
            .await?
            {
                Ok(parsed) => parsed,
                Err(response) => return Ok(response),
            };
        return match crate::tenant_root_role_runtime::handle_cloudflare_deriver_tenant_root_initial_activation_v1(
            &env,
            worker_role,
            activation_request,
            now_unix_ms,
        )
        .await
        {
            Ok(response) => Response::from_json(&response),
            Err(error) => cloudflare_protocol_error_response_v1(error),
        };
    }

    if path == CLOUDFLARE_DERIVER_TENANT_ROOT_REFRESH_ACTIVATION_PRIVATE_REQUEST_PATH {
        let activation_request: CloudflareDeriverTenantRootRefreshActivationRequestV1 =
            match parse_strict_deriver_json_v1(
                &mut request,
                format!("Router A/B strict {label} tenant-root refresh activation"),
            )
            .await?
            {
                Ok(parsed) => parsed,
                Err(response) => return Ok(response),
            };
        return match crate::tenant_root_role_runtime::handle_cloudflare_deriver_tenant_root_refresh_activation_v1(
            &env,
            worker_role,
            activation_request,
            now_unix_ms,
        )
        .await
        {
            Ok(response) => Response::from_json(&response),
            Err(error) => cloudflare_protocol_error_response_v1(error),
        };
    }

    if path == CLOUDFLARE_DERIVER_TENANT_ROOT_REFRESH_PRIVATE_REQUEST_PATH {
        let refresh_request: CloudflareDeriverTenantRootRefreshRequestV1 =
            match parse_strict_deriver_json_v1(
                &mut request,
                format!("Router A/B strict {label} tenant-root refresh"),
            )
            .await?
            {
                Ok(parsed) => parsed,
                Err(response) => return Ok(response),
            };
        return match crate::tenant_root_role_runtime::handle_cloudflare_deriver_tenant_root_refresh_v1(
            &env,
            worker_role,
            refresh_request,
            now_unix_ms,
        )
        .await
        {
            Ok(response) => Response::from_json(&response),
            Err(error) => cloudflare_protocol_error_response_v1(error),
        };
    }

    #[cfg(feature = "strict-worker-deriver-a-entrypoint")]
    if path == CLOUDFLARE_DERIVER_A_ED25519_YAO_PREPARE_PAIR_PATH {
        return match handle_cloudflare_ed25519_yao_deriver_a_prepare_pair_v1(request, &env).await {
            Ok(response) => Ok(response),
            Err(error) => cloudflare_role_failure_response_v1(error),
        };
    }

    #[cfg(feature = "strict-worker-deriver-a-entrypoint")]
    if path == CLOUDFLARE_DERIVER_A_ED25519_YAO_EXECUTE_PAIR_PATH {
        return match handle_cloudflare_ed25519_yao_deriver_a_execute_pair_v1(request, &env).await {
            Ok(response) => Ok(response),
            Err(error) => cloudflare_role_failure_response_v1(error),
        };
    }

    #[cfg(feature = "strict-worker-deriver-a-entrypoint")]
    if path == CLOUDFLARE_DERIVER_A_ED25519_YAO_READ_PAIR_STATUS_PATH {
        return match handle_cloudflare_ed25519_yao_deriver_a_read_pair_status_v1(request, &env)
            .await
        {
            Ok(response) => Ok(response),
            Err(error) => cloudflare_role_failure_response_v1(error),
        };
    }

    #[cfg(feature = "strict-worker-deriver-a-entrypoint")]
    if path == CLOUDFLARE_DERIVER_A_ED25519_YAO_BURN_PAIR_PATH {
        return match handle_cloudflare_ed25519_yao_deriver_a_burn_pair_v1(request, &env).await {
            Ok(response) => Ok(response),
            Err(error) => cloudflare_role_failure_response_v1(error),
        };
    }

    #[cfg(feature = "strict-worker-deriver-b-entrypoint")]
    if path == CLOUDFLARE_DERIVER_B_ED25519_YAO_PREPARE_PAIR_PATH {
        return match handle_cloudflare_ed25519_yao_deriver_b_prepare_pair_v1(request, &env).await {
            Ok(response) => Ok(response),
            Err(error) => cloudflare_role_failure_response_v1(error),
        };
    }

    #[cfg(feature = "strict-worker-deriver-b-entrypoint")]
    if path == CLOUDFLARE_DERIVER_B_ED25519_YAO_READ_PAIR_STATUS_PATH {
        return match handle_cloudflare_ed25519_yao_deriver_b_read_pair_status_v1(request, &env)
            .await
        {
            Ok(response) => Ok(response),
            Err(error) => cloudflare_role_failure_response_v1(error),
        };
    }

    #[cfg(feature = "strict-worker-deriver-b-entrypoint")]
    if path == CLOUDFLARE_DERIVER_B_ED25519_YAO_BURN_PAIR_PATH {
        return match handle_cloudflare_ed25519_yao_deriver_b_burn_pair_v1(request, &env).await {
            Ok(response) => Ok(response),
            Err(error) => cloudflare_role_failure_response_v1(error),
        };
    }

    #[cfg(feature = "strict-worker-deriver-b-entrypoint")]
    if path == CLOUDFLARE_DERIVER_B_ED25519_YAO_DUPLEX_PATH {
        let StrictDeriverRuntimeV1::DeriverB(runtime) = runtime;
        return match handle_cloudflare_ed25519_yao_deriver_b_websocket_v1(
            request, env, runtime, _context,
        )
        .await
        {
            Ok(response) => Ok(response),
            Err(error) => cloudflare_protocol_error_response_v1(error),
        };
    }

    if path == runtime.registration_private_path() {
        /* Refactor 94B Phase 0. The Router folds this header into its own under
        an `ecdsa_a_`/`ecdsa_b_` prefix, so a cold registration shows whether
        the time went to the root-metadata load or to proof generation. */
        let mut timing = CloudflareEcdsaBoundaryTimingV1::new();
        let total_started_at_ms = CloudflareEcdsaBoundaryTimingV1::now_ms();
        let private_request: CloudflareRouterAbEcdsaDerivationDeriverRegistrationPrivateRequestV1 =
            match parse_strict_deriver_json_v1(
                &mut request,
                format!("Router A/B strict {label} Router A/B ECDSA derivation registration"),
            )
            .await?
            {
                Ok(parsed) => parsed,
                Err(response) => return Ok(response),
            };
        timing.mark("parse", total_started_at_ms);
        let preload_started_at_ms = CloudflareEcdsaBoundaryTimingV1::now_ms();
        let (registration_request, authenticated, custody_wire) =
            match private_request.into_authenticated_parts(&env, worker_role, now_unix_ms) {
                Ok(parts) => parts,
                Err(err) => return cloudflare_protocol_error_response_v1(err),
            };
        let public_request = match registration_request.to_threshold_prf_request() {
            Ok(request) => request,
            Err(err) => return cloudflare_protocol_error_response_v1(err),
        };
        let outer_request = match build_cloudflare_ecdsa_threshold_prf_outer_request_v2(
            &public_request,
            authenticated.tenant_root_custody_binding(),
            &custody_wire,
        ) {
            Ok(request) => request,
            Err(err) => return cloudflare_protocol_error_response_v1(err),
        };
        let preloaded = match preload_strict_deriver_request_with_authenticated_binding_v2(
            &env,
            &runtime,
            &authenticated,
        )
        .await
        {
            Ok(loaded) => loaded,
            Err(err) => return cloudflare_protocol_error_response_v1(err),
        };
        let signer_bootstrap = authenticated.bootstrap;
        let tenant_root_custody_binding = authenticated.tenant_root_custody_binding;
        timing.mark("preload", preload_started_at_ms);
        let execute_started_at_ms = CloudflareEcdsaBoundaryTimingV1::now_ms();
        let response =
            match decrypt_and_handle_cloudflare_router_ab_ecdsa_derivation_registration_signer_private_request_v1(
                &env,
                worker_role,
                &preloaded.host,
                registration_request,
                signer_bootstrap,
                tenant_root_custody_binding,
                outer_request,
                preloaded.tenant_root_share,
                runtime.envelope_decrypt_key(),
                &preloaded.root_share_metadata,
                now_unix_ms,
            )
            .await
            {
                Ok(response) => response,
                Err(err) => return cloudflare_protocol_error_response_v1(err),
            };
        timing.mark("execute", execute_started_at_ms);
        timing.mark("total", total_started_at_ms);
        return strict_deriver_timed_json_response_v1(&response, &timing);
    }

    if path == runtime.export_private_path() {
        let export_request: CloudflareRouterAbEcdsaDerivationDeriverExportPrivateRequestV1 =
            match parse_strict_deriver_json_v1(
                &mut request,
                format!("Router A/B strict {label} Router A/B ECDSA derivation export"),
            )
            .await?
            {
                Ok(parsed) => parsed,
                Err(response) => return Ok(response),
            };
        let (export_request, authenticated, custody_wire) =
            match export_request.into_authenticated_parts(&env, worker_role, now_unix_ms) {
                Ok(parts) => parts,
                Err(err) => return cloudflare_protocol_error_response_v1(err),
            };
        let public_request = match export_request.to_threshold_prf_request() {
            Ok(request) => request,
            Err(err) => return cloudflare_protocol_error_response_v1(err),
        };
        let outer_request = match build_cloudflare_ecdsa_threshold_prf_outer_request_v2(
            &public_request,
            authenticated.tenant_root_custody_binding(),
            &custody_wire,
        ) {
            Ok(request) => request,
            Err(err) => return cloudflare_protocol_error_response_v1(err),
        };
        let preloaded = match preload_strict_deriver_request_with_authenticated_binding_v2(
            &env,
            &runtime,
            &authenticated,
        )
        .await
        {
            Ok(loaded) => loaded,
            Err(err) => return cloudflare_protocol_error_response_v1(err),
        };
        let signer_bootstrap = authenticated.bootstrap;
        let tenant_root_custody_binding = authenticated.tenant_root_custody_binding;
        return match decrypt_and_handle_cloudflare_router_ab_ecdsa_derivation_export_signer_private_request_v1(
            &env,
            worker_role,
            &preloaded.host,
            export_request,
            signer_bootstrap,
            tenant_root_custody_binding,
            outer_request,
            preloaded.tenant_root_share,
            runtime.envelope_decrypt_key(),
            &preloaded.root_share_metadata,
            now_unix_ms,
        )
        .await
        {
            Ok(response) => Response::from_json(&response),
            Err(err) => cloudflare_protocol_error_response_v1(err),
        };
    }

    if path == runtime.refresh_private_path() {
        let refresh_request: CloudflareRouterAbEcdsaDerivationDeriverActivationRefreshPrivateRequestV1 =
            match parse_strict_deriver_json_v1(
                &mut request,
                format!("Router A/B strict {label} Router A/B ECDSA derivation refresh"),
            )
            .await?
            {
                Ok(parsed) => parsed,
                Err(response) => return Ok(response),
            };
        let (refresh_request, authenticated, custody_wire) =
            match refresh_request.into_authenticated_parts(&env, worker_role, now_unix_ms) {
                Ok(parts) => parts,
                Err(err) => return cloudflare_protocol_error_response_v1(err),
            };
        let public_request = match refresh_request.to_threshold_prf_request() {
            Ok(request) => request,
            Err(err) => return cloudflare_protocol_error_response_v1(err),
        };
        let outer_request = match build_cloudflare_ecdsa_threshold_prf_outer_request_v2(
            &public_request,
            authenticated.tenant_root_custody_binding(),
            &custody_wire,
        ) {
            Ok(request) => request,
            Err(err) => return cloudflare_protocol_error_response_v1(err),
        };
        let preloaded = match preload_strict_deriver_request_with_authenticated_binding_v2(
            &env,
            &runtime,
            &authenticated,
        )
        .await
        {
            Ok(loaded) => loaded,
            Err(err) => return cloudflare_protocol_error_response_v1(err),
        };
        let signer_bootstrap = authenticated.bootstrap;
        let tenant_root_custody_binding = authenticated.tenant_root_custody_binding;
        let response = match decrypt_and_handle_cloudflare_router_ab_ecdsa_derivation_activation_refresh_signer_private_request_v1(
            &env,
            worker_role,
            &preloaded.host,
            refresh_request,
            signer_bootstrap,
            tenant_root_custody_binding,
            outer_request,
            preloaded.tenant_root_share,
            runtime.envelope_decrypt_key(),
            &preloaded.root_share_metadata,
            now_unix_ms,
        )
        .await
        {
            Ok(response) => response,
            Err(err) => return cloudflare_protocol_error_response_v1(err),
        };
        return Response::from_json(&response);
    }

    Response::error(runtime.route_error_message(), 404)
}

/// Serialises a deriver response and attaches its role-local `Server-Timing`.
/// The body is unchanged: only the Router reads this header, and it folds the
/// metrics into its own before the Gateway ever sees them.
#[cfg(any(
    feature = "strict-worker-deriver-a-entrypoint",
    feature = "strict-worker-deriver-b-entrypoint"
))]
fn strict_deriver_timed_json_response_v1<T: serde::Serialize>(
    body: &T,
    timing: &CloudflareEcdsaBoundaryTimingV1,
) -> worker::Result<Response> {
    let response = Response::from_json(body)?;
    timing.apply_to(&response)?;
    Ok(response)
}

#[cfg(any(
    feature = "strict-worker-deriver-a-entrypoint",
    feature = "strict-worker-deriver-b-entrypoint"
))]
async fn parse_strict_deriver_json_v1<T>(
    request: &mut Request,
    label: String,
) -> worker::Result<Result<T, Response>>
where
    T: serde::de::DeserializeOwned,
{
    match request.json::<T>().await {
        Ok(parsed) => Ok(Ok(parsed)),
        Err(err) => Ok(Err(Response::error(
            format!("{label} JSON parse failed: {err}"),
            400,
        )?)),
    }
}

#[cfg(any(
    feature = "strict-worker-deriver-a-entrypoint",
    feature = "strict-worker-deriver-b-entrypoint"
))]
async fn preload_strict_deriver_request_with_authenticated_binding_v2(
    env: &Env,
    runtime: &StrictDeriverRuntimeV1,
    authenticated_request: &CloudflareAuthenticatedSignerPrivateBootstrapRequestV1,
) -> RouterAbProtocolResult<StrictDeriverPreloadedRequestV2> {
    let (preload_plan, host) =
        preload_strict_deriver_host_with_authenticated_binding_v1(runtime, authenticated_request)
            .await?;
    let root_share_metadata = host
        .root_share_startup_metadata(runtime.protocol_role(), &preload_plan.root_share_epoch)?
        .clone();
    let tenant_root_share = load_cloudflare_active_tenant_root_role_share_v1(
        env,
        runtime.worker_role(),
        authenticated_request.tenant_root_custody_binding(),
    )
    .await?;
    Ok(StrictDeriverPreloadedRequestV2 {
        host,
        root_share_metadata,
        tenant_root_share,
    })
}

#[cfg(any(
    feature = "strict-worker-deriver-a-entrypoint",
    feature = "strict-worker-deriver-b-entrypoint"
))]
async fn preload_strict_deriver_host_with_authenticated_binding_v1(
    runtime: &StrictDeriverRuntimeV1,
    authenticated_request: &CloudflareAuthenticatedSignerPrivateBootstrapRequestV1,
) -> RouterAbProtocolResult<(
    CloudflareSignerHostPreloadPlanV1,
    CloudflarePreloadedSignerHostV1,
)> {
    let bootstrap = &authenticated_request.bootstrap;
    let preload_plan = CloudflareSignerHostPreloadPlanV1::from_private_bootstrap(
        runtime.worker_role(),
        bootstrap,
    )?;
    let verifying_keys = runtime.peer_verifying_keys_for_signer_set(&preload_plan.signer_set)?;
    let preload_input = preload_plan.to_host_preload_input(Vec::new(), verifying_keys, 0)?;
    let root_share_metadata = CloudflareRootShareStartupMetadataV1::new(
        preload_plan.signer_set_id.clone(),
        runtime.protocol_role(),
        preload_plan.local_signer.signer_id.clone(),
        preload_plan.local_signer.key_epoch.clone(),
        preload_plan.root_share_epoch.clone(),
        format!(
            "tenant-root-role-private-d1/{}/active",
            runtime.worker_role().as_str()
        ),
    )?;
    let host = build_cloudflare_preloaded_signer_host_v1(
        cloudflare_now_unix_ms_v1()?,
        runtime.protocol_role(),
        preload_input,
        root_share_metadata,
        cloudflare_random_bytes_v1(0)?,
    )?;
    Ok((preload_plan, host))
}

#[cfg(feature = "strict-worker-deriver-b-entrypoint")]
pub(super) async fn handle_strict_deriver_b_fetch_v1(
    request: Request,
    env: Env,
    context: Context,
) -> worker::Result<Response> {
    if let Err(err) = require_cloudflare_internal_service_auth_request_v1(&request, &env) {
        return cloudflare_private_service_auth_error_response_v1(err);
    }
    if request.path() == CLOUDFLARE_INTERNAL_PREWARM_PATH {
        if request.method() != Method::Post {
            return cloudflare_prewarm_response_v1(&request);
        }
        if let Err(err) = CloudflareDeriverBWorkerRuntimeV1::from_worker_env(&env) {
            return cloudflare_protocol_error_response_v1(err);
        }
        return cloudflare_prewarm_response_v1(&request);
    }
    let runtime = match CloudflareDeriverBWorkerRuntimeV1::from_worker_env(&env) {
        Ok(runtime) => StrictDeriverRuntimeV1::DeriverB(runtime),
        Err(err) => return cloudflare_protocol_error_response_v1(err),
    };
    handle_strict_deriver_fetch_v1(request, env, runtime, context).await
}
