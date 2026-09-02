use super::cors::{
    cloudflare_router_normal_signing_preflight_response_v1,
    cloudflare_router_normal_signing_response_v1,
    cloudflare_router_public_keyset_preflight_response_v1,
    cloudflare_router_public_keyset_response_v1,
};
use super::*;
use crate::durable_object::tenant_root_creation::{
    decode_bounded_json_request, derive_tenant_root_creation_authority_object_v1,
    execute_cloudflare_router_tenant_root_creation_active_state_read_call_v1,
    execute_cloudflare_router_tenant_root_creation_cleanup_call_v1,
    execute_cloudflare_router_tenant_root_creation_initial_activation_call_v1,
};
use crate::tenant_root_control_plane::{
    execute_cloudflare_tenant_root_control_plane_initial_activation_service_call_v1,
    CloudflareTenantRootControlPlaneInitialActivationRequestV1,
};
use crate::tenant_root_role_runtime::CloudflareTenantRootCreateRoleV1;
use crate::{
    execute_cloudflare_deriver_tenant_root_cleanup_pending_service_call_v1,
    execute_cloudflare_deriver_tenant_root_create_role_share_service_call_v1,
    execute_cloudflare_deriver_tenant_root_initial_activation_service_call_v1,
    execute_cloudflare_signing_worker_linked_device_ecdsa_finalize_service_call_v1,
    execute_cloudflare_tenant_root_control_plane_cleanup_command_service_call_v1,
    execute_cloudflare_tenant_root_control_plane_create_tenant_root_service_call_v1,
    execute_cloudflare_tenant_root_control_plane_role_creation_command_service_call_v1,
    handle_cloudflare_router_ab_ecdsa_derivation_evm_digest_signing_finalize_internal_step_up_request_v1,
    handle_cloudflare_router_ab_ecdsa_derivation_evm_digest_signing_prepare_internal_step_up_request_v1,
    handle_cloudflare_router_normal_signing_finalize_internal_linked_device_request_v2,
    handle_cloudflare_router_normal_signing_finalize_internal_step_up_request_v2,
    handle_cloudflare_router_normal_signing_prepare_internal_linked_device_request_v2,
    handle_cloudflare_router_normal_signing_prepare_internal_step_up_request_v2,
    parse_cloudflare_router_authorized_ed25519_prepare_request_v2_json,
    parse_cloudflare_router_authorized_linked_device_ecdsa_finalize_request_v1_json,
    CloudflareDeriverTenantRootCleanupPendingRequestV1,
    CloudflareDeriverTenantRootCreateRoleShareRequestV1,
    CloudflareDeriverTenantRootCreateRoleShareResponseV1,
    CloudflareDeriverTenantRootInitialActivationRequestV1,
    CloudflareRouterEcdsaAcceptedAuthorizedOperationV1,
    CloudflareRouterEcdsaAcceptedCapabilityBindingV1,
    CloudflareRouterEd25519AcceptedAuthorizedOperationV1,
    CloudflareRouterEd25519AcceptedCapabilityBindingV1, CloudflareRouterEd25519JwksJwtVerifierV1,
    CloudflareTenantRootControlPlaneCleanupCommandRequestV1,
    CloudflareTenantRootControlPlaneCreateTenantRootRequestV1,
    CloudflareTenantRootControlPlaneCreateTenantRootResponseV1,
    CloudflareTenantRootControlPlaneRoleCreationCommandRequestV1,
    CloudflareTenantRootControlPlaneRoleV1, CloudflareTenantRootCreationStatusV1,
    CLOUDFLARE_ROUTER_TENANT_ROOT_CREATION_PRIVATE_REQUEST_PATH,
    TENANT_ROOT_CONTROL_PLANE_CREATE_TENANT_ROOT_REQUEST_MAX_BYTES_V1,
};

#[cfg(feature = "strict-worker-router-entrypoint")]
async fn finish_cloudflare_router_tenant_root_initial_activation_v1(
    env: &Env,
    runtime: &CloudflareRouterWorkerRuntimeV1,
    genesis: &CloudflareTenantRootControlPlaneCreateTenantRootResponseV1,
) -> RouterAbProtocolResult<()> {
    let identity_digest_bytes = crate::decode_base64url_bytes_v1(
        "tenant-root creation identity digest",
        &genesis.identity_digest_b64u,
    )?;
    let identity_digest = router_ab_core::TenantRootIdentityDigestV1::from_bytes(
        identity_digest_bytes.try_into().map_err(|_| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "tenant-root creation identity digest must contain exactly 32 bytes",
            )
        })?,
    );
    let custody_lineage =
        router_ab_core::TenantRootCustodyLineageId::from_base64url(&genesis.custody_lineage_b64u)
            .map_err(|error| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                format!("tenant-root creation custody lineage is invalid: {error}"),
            )
        })?;
    let active = execute_cloudflare_router_tenant_root_creation_active_state_read_call_v1(
        env,
        identity_digest,
        custody_lineage,
    )
    .await?;
    if active.transition()
        != router_ab_core::TenantRootActivationReceiptTransitionV1::InitialCreation
    {
        return Ok(());
    }
    let role_activation = CloudflareDeriverTenantRootInitialActivationRequestV1 {
        activation_receipt_b64u: crate::encode_base64url_bytes_v1(active.canonical_bytes()),
    };
    execute_cloudflare_deriver_tenant_root_initial_activation_service_call_v1(
        env,
        &runtime.bindings().deriver_a,
        &role_activation,
    )
    .await?;
    execute_cloudflare_deriver_tenant_root_initial_activation_service_call_v1(
        env,
        &runtime.bindings().deriver_b,
        &role_activation,
    )
    .await?;
    Ok(())
}

#[cfg(feature = "strict-worker-router-entrypoint")]
async fn coordinate_cloudflare_router_tenant_root_creation_v1(
    env: &Env,
    runtime: &CloudflareRouterWorkerRuntimeV1,
    request: CloudflareTenantRootControlPlaneCreateTenantRootRequestV1,
) -> RouterAbProtocolResult<CloudflareTenantRootControlPlaneCreateTenantRootResponseV1> {
    let genesis = execute_cloudflare_tenant_root_control_plane_create_tenant_root_service_call_v1(
        env, &request,
    )
    .await?;
    match &genesis.status {
        CloudflareTenantRootCreationStatusV1::Ready { .. } => {
            finish_cloudflare_router_tenant_root_initial_activation_v1(env, runtime, &genesis)
                .await?;
            return Ok(genesis);
        }
        CloudflareTenantRootCreationStatusV1::Abandoned { .. } => {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLifecycleState,
                "tenant-root creation was abandoned; a fresh grant is required",
            ));
        }
        CloudflareTenantRootCreationStatusV1::OneRoleInstalled { role } => {
            let cleanup =
                execute_cloudflare_tenant_root_control_plane_cleanup_command_service_call_v1(
                    env,
                    &CloudflareTenantRootControlPlaneCleanupCommandRequestV1 {
                        identity_digest_b64u: genesis.identity_digest_b64u.clone(),
                        custody_lineage_b64u: genesis.custody_lineage_b64u.clone(),
                    },
                )
                .await?;
            if cleanup.role != *role {
                return Err(RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::ForbiddenLocalBinding,
                    "tenant-root cleanup command names a different installed role",
                ));
            }
            let cleanup_command_bytes = crate::decode_base64url_bytes_v1(
                "tenant-root cleanup command",
                &cleanup.cleanup_command_b64u,
            )?;
            let cleanup_command =
                router_ab_core::TenantRootRoleCleanupCommandV1::decode_canonical_bytes(
                    &cleanup_command_bytes,
                )
                .map_err(|error| {
                    RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::MalformedWirePayload,
                        format!("tenant-root cleanup command was malformed: {error}"),
                    )
                })?;
            let claimed_target = cleanup_command.claimed_target();
            let expected_role = role.to_protocol();
            let (authority_id, _) = derive_tenant_root_creation_authority_object_v1(
                env,
                claimed_target.identity_digest,
                claimed_target.custody_lineage,
            )?;
            let reader = crate::CloudflareWorkerEnvReaderV1::new(env);
            let issuer_keys =
                crate::env::parse_cloudflare_tenant_root_control_plane_issuer_verifying_keys_v1(
                    &reader,
                )?;
            let issuer_key_id = cleanup_command.issuer_key_id().to_owned();
            let issuer_key = issuer_keys
                .for_issuer_key_id(&issuer_key_id)
                .ok_or_else(|| {
                    RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::ForbiddenLocalBinding,
                        "tenant-root cleanup command issuer is not trusted by the Router",
                    )
                })?;
            let verified_cleanup = cleanup_command
                .verify(
                    &claimed_target,
                    expected_role,
                    authority_id,
                    &issuer_key_id,
                    issuer_key,
                )
                .map_err(|error| {
                    RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::ForbiddenLocalBinding,
                        format!("tenant-root cleanup command verification failed: {error}"),
                    )
                })?;
            let deriver = match role {
                CloudflareTenantRootControlPlaneRoleV1::DeriverA => &runtime.bindings().deriver_a,
                CloudflareTenantRootControlPlaneRoleV1::DeriverB => &runtime.bindings().deriver_b,
            };
            let cleaned = execute_cloudflare_deriver_tenant_root_cleanup_pending_service_call_v1(
                env,
                deriver,
                &CloudflareDeriverTenantRootCleanupPendingRequestV1 {
                    cleanup_command_b64u: cleanup.cleanup_command_b64u,
                },
            )
            .await?;
            let cleanup_receipt = crate::decode_base64url_bytes_v1(
                "tenant-root cleanup terminal receipt",
                &cleaned.cleanup_receipt_b64u,
            )?;
            execute_cloudflare_router_tenant_root_creation_cleanup_call_v1(
                env,
                &verified_cleanup,
                &cleanup_receipt,
            )
            .await?;
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLifecycleState,
                "tenant-root partial creation was cleaned; a fresh grant is required",
            ));
        }
        CloudflareTenantRootCreationStatusV1::Pending => {}
    }

    let command_request = |role| CloudflareTenantRootControlPlaneRoleCreationCommandRequestV1 {
        identity_digest_b64u: genesis.identity_digest_b64u.clone(),
        custody_lineage_b64u: genesis.custody_lineage_b64u.clone(),
        role,
    };
    let deriver_a =
        execute_cloudflare_tenant_root_control_plane_role_creation_command_service_call_v1(
            env,
            &command_request(CloudflareTenantRootControlPlaneRoleV1::DeriverA),
        )
        .await?;
    let deriver_b =
        execute_cloudflare_tenant_root_control_plane_role_creation_command_service_call_v1(
            env,
            &command_request(CloudflareTenantRootControlPlaneRoleV1::DeriverB),
        )
        .await?;

    let completed = execute_cloudflare_deriver_tenant_root_create_role_share_service_call_v1(
        env,
        &runtime.bindings().deriver_a,
        &CloudflareDeriverTenantRootCreateRoleShareRequestV1::Initiator {
            role_creation_command_package_b64u: deriver_a.role_creation_command_package_b64u,
            peer_role_creation_command_package_b64u: deriver_b.role_creation_command_package_b64u,
        },
    )
    .await?;
    let CloudflareDeriverTenantRootCreateRoleShareResponseV1::Completed {
        role: CloudflareTenantRootCreateRoleV1::DeriverA,
        deriver_a_signed_installation_evidence_b64u,
        deriver_b_signed_installation_evidence_b64u,
        deriver_a_signed_managed_backup_b64u,
        deriver_b_signed_managed_backup_b64u,
        ecdsa_provider_canary_receipt_b64u,
        ed25519_provider_canary_receipt_b64u,
        ..
    } = completed
    else {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "tenant-root creation initiator response names the wrong role",
        ));
    };

    let issued_activation =
        execute_cloudflare_tenant_root_control_plane_initial_activation_service_call_v1(
            env,
            &CloudflareTenantRootControlPlaneInitialActivationRequestV1 {
                deriver_a_signed_installation_evidence_b64u,
                deriver_b_signed_installation_evidence_b64u,
                deriver_a_signed_managed_backup_b64u,
                deriver_b_signed_managed_backup_b64u,
                ecdsa_provider_canary_receipt_b64u,
                ed25519_provider_canary_receipt_b64u,
            },
        )
        .await?;
    let activation_receipt_bytes = crate::decode_base64url_bytes_v1(
        "tenant-root initial activation receipt",
        &issued_activation.activation_receipt_b64u,
    )?;
    execute_cloudflare_router_tenant_root_creation_initial_activation_call_v1(
        env,
        &activation_receipt_bytes,
    )
    .await?;
    let role_activation = CloudflareDeriverTenantRootInitialActivationRequestV1 {
        activation_receipt_b64u: issued_activation.activation_receipt_b64u,
    };
    execute_cloudflare_deriver_tenant_root_initial_activation_service_call_v1(
        env,
        &runtime.bindings().deriver_a,
        &role_activation,
    )
    .await?;
    execute_cloudflare_deriver_tenant_root_initial_activation_service_call_v1(
        env,
        &runtime.bindings().deriver_b,
        &role_activation,
    )
    .await?;

    let completed_state =
        execute_cloudflare_tenant_root_control_plane_create_tenant_root_service_call_v1(
            env, &request,
        )
        .await?;
    if !matches!(
        completed_state.status,
        CloudflareTenantRootCreationStatusV1::Ready { .. }
    ) {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLifecycleState,
            "tenant-root creation returned before both role installations were checkpointed",
        ));
    }
    Ok(completed_state)
}
use router_ab_core::{
    PublicDigest32, RouterAbEcdsaDerivationEvmDigestSigningFinalizeRequestV1,
    RouterAbEcdsaDerivationEvmDigestSigningRequestV1,
    RouterAbEd25519NormalSigningFinalizeRequestV2, RouterAbEd25519NormalSigningPrepareRequestV2,
    RouterAbProtocolErrorCode, RouterAbProtocolResult,
};

#[cfg(feature = "strict-worker-router-entrypoint")]
enum StrictRouterNormalSigningRequestV1 {
    Ed25519Prepare {
        request: RouterAbEd25519NormalSigningPrepareRequestV2,
        authorized_operation: CloudflareRouterEd25519AcceptedAuthorizedOperationV1,
    },
    Ed25519Finalize {
        request: RouterAbEd25519NormalSigningFinalizeRequestV2,
        authorized_operation: CloudflareRouterEd25519AcceptedAuthorizedOperationV1,
    },
    EcdsaPrepare {
        request: RouterAbEcdsaDerivationEvmDigestSigningRequestV1,
        authorized_operation: CloudflareRouterEcdsaAcceptedAuthorizedOperationV1,
    },
    EcdsaFinalize {
        request: RouterAbEcdsaDerivationEvmDigestSigningFinalizeRequestV1,
        authorized_operation: CloudflareRouterEcdsaAcceptedAuthorizedOperationV1,
    },
}

#[cfg(feature = "strict-worker-router-entrypoint")]
impl StrictRouterNormalSigningRequestV1 {
    fn is_operation_step_up(&self) -> bool {
        match self {
            Self::Ed25519Prepare {
                authorized_operation,
                ..
            }
            | Self::Ed25519Finalize {
                authorized_operation,
                ..
            } => matches!(
                &authorized_operation.binding,
                CloudflareRouterEd25519AcceptedCapabilityBindingV1::OperationStepUp { .. }
            ),
            Self::EcdsaPrepare {
                authorized_operation,
                ..
            }
            | Self::EcdsaFinalize {
                authorized_operation,
                ..
            } => matches!(
                &authorized_operation.binding,
                CloudflareRouterEcdsaAcceptedCapabilityBindingV1::OperationStepUp { .. }
            ),
        }
    }

    fn is_gateway_wallet_session(&self) -> bool {
        matches!(
            self,
            Self::EcdsaPrepare {
                authorized_operation:
                    CloudflareRouterEcdsaAcceptedAuthorizedOperationV1 {
                        binding: CloudflareRouterEcdsaAcceptedCapabilityBindingV1::GatewayOwnerWalletSession { .. },
                        ..
                    },
                ..
            }
                | Self::EcdsaFinalize {
                    authorized_operation:
                        CloudflareRouterEcdsaAcceptedAuthorizedOperationV1 {
                            binding: CloudflareRouterEcdsaAcceptedCapabilityBindingV1::GatewayOwnerWalletSession { .. },
                            ..
                        },
                    ..
                }
                | Self::Ed25519Prepare {
                    authorized_operation:
                        CloudflareRouterEd25519AcceptedAuthorizedOperationV1 {
                            binding: CloudflareRouterEd25519AcceptedCapabilityBindingV1::GatewayOwnerWalletSession { .. },
                            ..
                        },
                    ..
                }
                | Self::Ed25519Finalize {
                    authorized_operation:
                        CloudflareRouterEd25519AcceptedAuthorizedOperationV1 {
                            binding: CloudflareRouterEd25519AcceptedCapabilityBindingV1::GatewayOwnerWalletSession { .. },
                            ..
                    },
                    ..
                }
                | Self::EcdsaPrepare {
                    authorized_operation:
                        CloudflareRouterEcdsaAcceptedAuthorizedOperationV1 {
                            binding: CloudflareRouterEcdsaAcceptedCapabilityBindingV1::ReusableWalletSession { .. },
                            ..
                        },
                    ..
                }
                | Self::EcdsaFinalize {
                    authorized_operation:
                        CloudflareRouterEcdsaAcceptedAuthorizedOperationV1 {
                            binding: CloudflareRouterEcdsaAcceptedCapabilityBindingV1::ReusableWalletSession { .. },
                            ..
                        },
                    ..
                }
                | Self::Ed25519Prepare {
                    authorized_operation:
                        CloudflareRouterEd25519AcceptedAuthorizedOperationV1 {
                        binding: CloudflareRouterEd25519AcceptedCapabilityBindingV1::ReusableWalletSession { .. },
                            ..
                        },
                    ..
                }
                | Self::Ed25519Finalize {
                    authorized_operation:
                        CloudflareRouterEd25519AcceptedAuthorizedOperationV1 {
                            binding: CloudflareRouterEd25519AcceptedCapabilityBindingV1::ReusableWalletSession { .. },
                            ..
                        },
                    ..
                }
                | Self::Ed25519Prepare {
                    authorized_operation:
                        CloudflareRouterEd25519AcceptedAuthorizedOperationV1 {
                            binding: CloudflareRouterEd25519AcceptedCapabilityBindingV1::GatewayLinkedDeviceWalletSession { .. },
                            ..
                        },
                    ..
                }
                | Self::Ed25519Finalize {
                    authorized_operation:
                        CloudflareRouterEd25519AcceptedAuthorizedOperationV1 {
                            binding: CloudflareRouterEd25519AcceptedCapabilityBindingV1::GatewayLinkedDeviceWalletSession { .. },
                            ..
                        },
                    ..
                }
        )
    }

    fn is_gateway_linked_device_wallet_session(&self) -> bool {
        matches!(
            self,
            Self::Ed25519Prepare {
                authorized_operation:
                    CloudflareRouterEd25519AcceptedAuthorizedOperationV1 {
                        binding: CloudflareRouterEd25519AcceptedCapabilityBindingV1::GatewayLinkedDeviceWalletSession { .. },
                        ..
                    },
                ..
            } | Self::Ed25519Finalize {
                authorized_operation:
                    CloudflareRouterEd25519AcceptedAuthorizedOperationV1 {
                        binding: CloudflareRouterEd25519AcceptedCapabilityBindingV1::GatewayLinkedDeviceWalletSession { .. },
                        ..
                    },
                ..
            }
        )
    }
}

#[cfg(feature = "strict-worker-router-entrypoint")]
pub(super) async fn handle_strict_router_fetch_v1(
    mut request: Request,
    env: Env,
) -> worker::Result<Response> {
    let path = request.path();
    if path == CLOUDFLARE_INTERNAL_PREWARM_PATH {
        return handle_router_prewarm_v1(&request, &env).await;
    }
    if path == CLOUDFLARE_ROUTER_TENANT_ROOT_CREATION_PRIVATE_REQUEST_PATH {
        if let Err(err) = require_cloudflare_internal_service_auth_request_v1(&request, &env) {
            return cloudflare_private_service_auth_error_response_v1(err);
        }
        if request.method() != Method::Post {
            return Response::error("tenant-root creation route requires POST", 405);
        }
        let runtime = match CloudflareRouterWorkerRuntimeV1::from_worker_env(&env) {
            Ok(runtime) => runtime,
            Err(err) => return cloudflare_protocol_error_response_v1(err),
        };
        let parsed: CloudflareTenantRootControlPlaneCreateTenantRootRequestV1 =
            match decode_bounded_json_request(
                &mut request,
                TENANT_ROOT_CONTROL_PLANE_CREATE_TENANT_ROOT_REQUEST_MAX_BYTES_V1,
            )
            .await
            {
                Ok(value) => value,
                Err(err) => return cloudflare_protocol_error_response_v1(err),
            };
        return match coordinate_cloudflare_router_tenant_root_creation_v1(&env, &runtime, parsed)
            .await
        {
            Ok(response) => Response::from_json(&response),
            Err(err) => cloudflare_protocol_error_response_v1(err),
        };
    }
    if is_cloudflare_router_public_keyset_path(&path) {
        if request.method() == Method::Options {
            return cloudflare_router_public_keyset_preflight_response_v1(&request, &env);
        }
        if request.method() != Method::Get {
            let response = Response::error("Router A/B public keyset route requires GET", 405)?;
            return cloudflare_router_public_keyset_response_v1(response, &request, &env);
        }
        let reader = CloudflareWorkerEnvReaderV1::new(&env);
        let response = match build_cloudflare_router_public_keyset_v2(&reader) {
            Ok(keyset) => Response::from_json(&keyset)?,
            Err(err) => cloudflare_protocol_error_response_v1(err)?,
        };
        return cloudflare_router_public_keyset_response_v1(response, &request, &env);
    }

    if path == CLOUDFLARE_ROUTER_ED25519_YAO_EXECUTE_PRIVATE_REQUEST_PATH {
        return handle_cloudflare_router_ed25519_yao_execute_private_fetch_v1(request, &env).await;
    }
    if path == CLOUDFLARE_ROUTER_ED25519_YAO_SOURCE_PRESERVING_EXECUTE_PRIVATE_REQUEST_PATH {
        return handle_cloudflare_router_ed25519_yao_source_preserving_execute_private_fetch_v1(
            request, &env,
        )
        .await;
    }
    if path == CLOUDFLARE_ROUTER_ED25519_YAO_LANE_EXECUTE_PRIVATE_REQUEST_PATH {
        return handle_cloudflare_router_ed25519_yao_lane_execute_private_fetch_v1(request, &env)
            .await;
    }
    if path == CLOUDFLARE_ROUTER_ED25519_YAO_RECOVERY_PROMOTE_PRIVATE_REQUEST_PATH {
        return handle_cloudflare_router_ed25519_yao_recovery_promote_private_fetch_v1(
            request, &env,
        )
        .await;
    }

    if request.method() == Method::Options
        && (is_cloudflare_router_normal_signing_public_path(&path)
            || is_cloudflare_router_ab_ecdsa_derivation_public_path(&path))
    {
        return cloudflare_router_normal_signing_preflight_response_v1(&request, &env);
    }

    if request.method() != Method::Post {
        return Response::error("Router A/B strict public route requires POST", 405);
    }
    if path == CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_LINKED_SIGNING_PRIVATE_REQUEST_PATH {
        if let Err(err) = require_cloudflare_internal_service_auth_request_v1(&request, &env) {
            return cloudflare_private_service_auth_error_response_v1(err);
        }
        let runtime = match CloudflareRouterWorkerRuntimeV1::from_worker_env(&env) {
            Ok(runtime) => runtime,
            Err(err) => return cloudflare_protocol_error_response_v1(err),
        };
        let request_body =
            match read_router_public_body_v1(&mut request, &env, "linked ECDSA finalize request")
                .await?
            {
                Ok(bytes) => bytes,
                Err(response) => return Ok(response),
            };
        let parsed =
            match parse_cloudflare_router_authorized_linked_device_ecdsa_finalize_request_v1_json(
                &request_body,
            ) {
                Ok(parsed) => parsed,
                Err(err) => return cloudflare_protocol_error_response_v1(err),
            };
        let response =
            execute_cloudflare_signing_worker_linked_device_ecdsa_finalize_service_call_v1(
                &env,
                runtime.signing_worker_peer(),
                parsed,
            )
            .await;
        return match response {
            Ok(response) => Response::from_json(&response),
            Err(err) => cloudflare_protocol_error_response_v1(err),
        };
    }
    if path == CLOUDFLARE_ROUTER_NORMAL_SIGNING_ROUND1_PREPARE_PUBLIC_REQUEST_PATH
        || path == CLOUDFLARE_ROUTER_NORMAL_SIGNING_PUBLIC_REQUEST_PATH
        || path == CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_SIGNING_PREPARE_PUBLIC_REQUEST_PATH
        || path == CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_SIGNING_PUBLIC_REQUEST_PATH
    {
        if let Err(err) = require_cloudflare_internal_service_auth_request_v1(&request, &env) {
            return cloudflare_private_service_auth_error_response_v1(err);
        }
    }
    if path != CLOUDFLARE_ROUTER_NORMAL_SIGNING_ROUND1_PREPARE_PUBLIC_REQUEST_PATH
        && path != CLOUDFLARE_ROUTER_NORMAL_SIGNING_PUBLIC_REQUEST_PATH
        && path != CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_REGISTRATION_PUBLIC_REQUEST_PATH
        && path != CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_ACTIVATION_PUBLIC_REQUEST_PATH
        && path != CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_ADD_SIGNER_PUBLIC_REQUEST_PATH
        && path != CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_EXPORT_PUBLIC_REQUEST_PATH
        && path != CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_REFRESH_PUBLIC_REQUEST_PATH
        && path != CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_SIGNING_PREPARE_PUBLIC_REQUEST_PATH
        && path != CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_SIGNING_PUBLIC_REQUEST_PATH
    {
        return Response::error(
            format!(
                "Router A/B strict public request must be served at {}, {}, {}, {}, {}, {}, {}, {}, or {}",
                CLOUDFLARE_ROUTER_NORMAL_SIGNING_ROUND1_PREPARE_PUBLIC_REQUEST_PATH,
                CLOUDFLARE_ROUTER_NORMAL_SIGNING_PUBLIC_REQUEST_PATH,
                CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_REGISTRATION_PUBLIC_REQUEST_PATH,
                CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_ACTIVATION_PUBLIC_REQUEST_PATH,
                CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_ADD_SIGNER_PUBLIC_REQUEST_PATH,
                CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_EXPORT_PUBLIC_REQUEST_PATH,
                CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_REFRESH_PUBLIC_REQUEST_PATH,
                CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_SIGNING_PREPARE_PUBLIC_REQUEST_PATH,
                CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_SIGNING_PUBLIC_REQUEST_PATH
            ),
            404,
        );
    }
    let parsed_normal_signing = if path
        == CLOUDFLARE_ROUTER_NORMAL_SIGNING_ROUND1_PREPARE_PUBLIC_REQUEST_PATH
        || path == CLOUDFLARE_ROUTER_NORMAL_SIGNING_PUBLIC_REQUEST_PATH
        || path == CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_SIGNING_PREPARE_PUBLIC_REQUEST_PATH
        || path == CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_SIGNING_PUBLIC_REQUEST_PATH
    {
        match parse_strict_router_normal_signing_request_v1(&mut request, &env, &path).await? {
            Ok(parsed) => Some(parsed),
            Err(response) => return Ok(response),
        }
    } else {
        None
    };
    let authorization_header_present = match request.headers().get("authorization") {
        Ok(value) => value.is_some(),
        Err(err) => {
            return cloudflare_protocol_error_response_v1(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalHttpRequest,
                format!("Router authorization header read failed: {err}"),
            ));
        }
    };
    let gateway_wallet_session_request = parsed_normal_signing
        .as_ref()
        .is_some_and(StrictRouterNormalSigningRequestV1::is_gateway_wallet_session);
    if parsed_normal_signing
        .as_ref()
        .is_some_and(|parsed| !parsed.is_gateway_wallet_session() && !parsed.is_operation_step_up())
    {
        return cloudflare_protocol_error_response_v1(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidGateDecision,
            "Normal signing requires Gateway Wallet Session admission or operation step-up",
        ));
    }
    if gateway_wallet_session_request && authorization_header_present {
        return cloudflare_protocol_error_response_v1(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalHttpRequest,
            "Gateway Wallet Session requests must omit Authorization",
        ));
    }
    let authorization = if parsed_normal_signing.is_some() {
        None
    } else {
        match parse_cloudflare_router_bearer_authorization_from_request_v1(&request) {
            Ok(authorization) => Some(authorization),
            Err(_err)
                if parsed_normal_signing
                    .as_ref()
                    .is_some_and(StrictRouterNormalSigningRequestV1::is_operation_step_up) =>
            {
                None
            }
            Err(err) => return cloudflare_protocol_error_response_v1(err),
        }
    };
    let trusted_source_digest = match cloudflare_trusted_source_digest_v1(&request) {
        Ok(digest) => digest,
        Err(err) => return cloudflare_protocol_error_response_v1(err),
    };
    let runtime = match CloudflareRouterWorkerRuntimeV1::from_worker_env(&env) {
        Ok(runtime) => runtime,
        Err(err) => return cloudflare_protocol_error_response_v1(err),
    };
    let now_unix_ms = match cloudflare_now_unix_ms_v1() {
        Ok(now_unix_ms) => now_unix_ms,
        Err(err) => return cloudflare_protocol_error_response_v1(err),
    };
    let verifier = match build_cloudflare_router_ed25519_jwks_jwt_verifier_v1(
        &runtime.admission_bindings().jwt,
    ) {
        Ok(verifier) => verifier,
        Err(err) => return cloudflare_protocol_error_response_v1(err),
    };

    if let Some(parsed) = parsed_normal_signing {
        return execute_strict_router_normal_signing_request_v1(
            parsed,
            &request,
            &env,
            &runtime,
            now_unix_ms,
            trusted_source_digest,
            verifier,
        )
        .await;
    }
    let authorization = match authorization {
        Some(authorization) => authorization,
        None => {
            return cloudflare_protocol_error_response_v1(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "Bearer authorization is required",
            ));
        }
    };

    if path == CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_ACTIVATION_PUBLIC_REQUEST_PATH {
        let trace_id = match router_ecdsa_trace_context_v1(&request, &env)? {
            Ok(trace_id) => trace_id,
            Err(response) => return Ok(response),
        };
        let request_body = match read_router_public_body_v1(
            &mut request,
            &env,
            "Router A/B strict ECDSA registration activation",
        )
        .await?
        {
            Ok(bytes) => bytes,
            Err(response) => return Ok(response),
        };
        let activation_request = match parse_router_public_body_v1(
            &request_body,
            parse_cloudflare_router_ab_ecdsa_derivation_activation_request_v1_json,
            &request,
            &env,
        )? {
            Ok(parsed) => parsed,
            Err(response) => return Ok(response),
        };
        let mut timing = CloudflareEcdsaBoundaryTimingV1::with_trace_id(trace_id);
        let response =
            handle_cloudflare_router_ab_ecdsa_derivation_activation_authenticated_public_request_v1(
                &env,
                &runtime,
                now_unix_ms,
                activation_request,
                authorization,
                trusted_source_digest,
                verifier,
                &mut timing,
            )
            .await;
        return router_ecdsa_timed_json_cors_response_v1(response, &timing, &request, &env);
    }

    if let Some(registration_purpose) =
        router_ab_ecdsa_derivation_registration_purpose_for_public_path(&path)
    {
        let trace_id = match router_ecdsa_trace_context_v1(&request, &env)? {
            Ok(trace_id) => trace_id,
            Err(response) => return Ok(response),
        };
        let request_body = match read_router_public_body_v1(
            &mut request,
            &env,
            "Router A/B strict Router A/B ECDSA derivation registration",
        )
        .await?
        {
            Ok(bytes) => bytes,
            Err(response) => return Ok(response),
        };
        match registration_purpose {
            RouterAbEcdsaDerivationRegistrationPurposeV1::WalletRegistration => {
                let (registration_request, identity_digest, custody_lineage) =
                    match parse_router_public_body_v1(
                        &request_body,
                        parse_cloudflare_router_ab_ecdsa_derivation_registration_gateway_request_v1,
                        &request,
                        &env,
                    )? {
                        Ok(parsed) => parsed,
                        Err(response) => return Ok(response),
                    };
                if let Err(err) =
                    registration_request.validate_for_registration_purpose(registration_purpose)
                {
                    let response = cloudflare_protocol_error_response_v1(err)?;
                    return cloudflare_router_normal_signing_response_v1(response, &request, &env);
                }
                let active_receipt =
                    match execute_cloudflare_router_tenant_root_creation_active_state_read_call_v1(
                        &env,
                        identity_digest,
                        custody_lineage,
                    )
                    .await
                    {
                        Ok(receipt) => receipt,
                        Err(err) => {
                            let response = cloudflare_protocol_error_response_v1(err)?;
                            return cloudflare_router_normal_signing_response_v1(
                                response, &request, &env,
                            );
                        }
                    };
                let custody_binding = match cloudflare_tenant_root_registration_binding_wire_v1(
                    &registration_request,
                    registration_purpose,
                    &active_receipt,
                ) {
                    Ok(binding) => binding,
                    Err(err) => {
                        let response = cloudflare_protocol_error_response_v1(err)?;
                        return cloudflare_router_normal_signing_response_v1(
                            response, &request, &env,
                        );
                    }
                };
                let mut timing = CloudflareEcdsaBoundaryTimingV1::with_trace_id(trace_id);
                let response = handle_cloudflare_router_ab_ecdsa_derivation_registration_bootstrap_authenticated_public_request_v1(
                    &env,
                    &runtime,
                    now_unix_ms,
                    registration_request,
                    &custody_binding,
                    authorization,
                    trusted_source_digest,
                    verifier,
                    &mut timing,
                )
                .await;
                return router_ecdsa_timed_json_cors_response_v1(response, &timing, &request, &env);
            }
            RouterAbEcdsaDerivationRegistrationPurposeV1::WalletAddSigner => {
                let (registration_request, identity_digest, custody_lineage) =
                    match parse_router_public_body_v1(
                        &request_body,
                        parse_cloudflare_router_ab_ecdsa_derivation_registration_gateway_request_v1,
                        &request,
                        &env,
                    )? {
                        Ok(parsed) => parsed,
                        Err(response) => return Ok(response),
                    };
                if let Err(err) =
                    registration_request.validate_for_registration_purpose(registration_purpose)
                {
                    let response = cloudflare_protocol_error_response_v1(err)?;
                    return cloudflare_router_normal_signing_response_v1(response, &request, &env);
                }
                let active_receipt =
                    match execute_cloudflare_router_tenant_root_creation_active_state_read_call_v1(
                        &env,
                        identity_digest,
                        custody_lineage,
                    )
                    .await
                    {
                        Ok(receipt) => receipt,
                        Err(err) => {
                            let response = cloudflare_protocol_error_response_v1(err)?;
                            return cloudflare_router_normal_signing_response_v1(
                                response, &request, &env,
                            );
                        }
                    };
                let custody_binding = match cloudflare_tenant_root_registration_binding_wire_v1(
                    &registration_request,
                    registration_purpose,
                    &active_receipt,
                ) {
                    Ok(binding) => binding,
                    Err(err) => {
                        let response = cloudflare_protocol_error_response_v1(err)?;
                        return cloudflare_router_normal_signing_response_v1(
                            response, &request, &env,
                        );
                    }
                };
                let mut timing = CloudflareEcdsaBoundaryTimingV1::with_trace_id(trace_id);
                let response = handle_cloudflare_router_ab_ecdsa_derivation_registration_bootstrap_authenticated_public_request_v1(
                    &env,
                    &runtime,
                    now_unix_ms,
                    registration_request,
                    &custody_binding,
                    authorization,
                    trusted_source_digest,
                    verifier,
                    &mut timing,
                )
                .await;
                return router_ecdsa_timed_json_cors_response_v1(response, &timing, &request, &env);
            }
        }
    }

    if path == CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_EXPORT_PUBLIC_REQUEST_PATH {
        let request_body = match read_router_public_body_v1(
            &mut request,
            &env,
            "Router A/B strict Router A/B ECDSA derivation export",
        )
        .await?
        {
            Ok(bytes) => bytes,
            Err(response) => return Ok(response),
        };
        let export_request = match parse_router_public_body_v1(
            &request_body,
            parse_cloudflare_router_ab_ecdsa_derivation_export_command_v1_json,
            &request,
            &env,
        )? {
            Ok(parsed) => parsed,
            Err(response) => return Ok(response),
        };
        let response =
            handle_cloudflare_router_ab_ecdsa_derivation_explicit_export_authenticated_public_request_v1(
                &env,
                &runtime,
                now_unix_ms,
                export_request,
                authorization,
                trusted_source_digest,
                verifier,
            )
            .await;
        return router_json_cors_response_v1(response, &request, &env);
    }

    if path == CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_REFRESH_PUBLIC_REQUEST_PATH {
        let request_body = match read_router_public_body_v1(
            &mut request,
            &env,
            "Router A/B strict Router A/B ECDSA derivation activation-refresh",
        )
        .await?
        {
            Ok(bytes) => bytes,
            Err(response) => return Ok(response),
        };
        let refresh_request = match parse_router_public_body_v1(
            &request_body,
            parse_cloudflare_router_ab_ecdsa_derivation_activation_refresh_request_v1_json,
            &request,
            &env,
        )? {
            Ok(parsed) => parsed,
            Err(response) => return Ok(response),
        };
        let response =
            handle_cloudflare_router_ab_ecdsa_derivation_activation_refresh_authenticated_public_request_v1(
                &env,
                &runtime,
                now_unix_ms,
                refresh_request,
                authorization,
                trusted_source_digest,
                verifier,
            )
            .await;
        return router_json_cors_response_v1(response, &request, &env);
    }

    Response::error("Router A/B strict public route is unavailable", 404)
}

#[cfg(feature = "strict-worker-router-entrypoint")]
async fn parse_strict_router_normal_signing_request_v1(
    request: &mut Request,
    env: &Env,
    path: &str,
) -> worker::Result<Result<StrictRouterNormalSigningRequestV1, Response>> {
    let request_body =
        match read_router_public_body_v1(request, env, "Router A/B strict normal-signing request")
            .await?
        {
            Ok(bytes) => bytes,
            Err(response) => return Ok(Err(response)),
        };
    let parsed = match path {
        CLOUDFLARE_ROUTER_NORMAL_SIGNING_ROUND1_PREPARE_PUBLIC_REQUEST_PATH => {
            parse_router_public_body_v1(
                &request_body,
                parse_cloudflare_router_authorized_ed25519_prepare_request_v2_json,
                request,
                env,
            )?
            .map(|(request, authorized_operation)| {
                StrictRouterNormalSigningRequestV1::Ed25519Prepare {
                    request,
                    authorized_operation,
                }
            })
        }
        CLOUDFLARE_ROUTER_NORMAL_SIGNING_PUBLIC_REQUEST_PATH => parse_router_public_body_v1(
            &request_body,
            parse_cloudflare_router_authorized_ed25519_finalize_request_v2_json,
            request,
            env,
        )?
        .map(|(request, authorized_operation)| {
            StrictRouterNormalSigningRequestV1::Ed25519Finalize {
                request,
                authorized_operation,
            }
        }),
        CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_SIGNING_PREPARE_PUBLIC_REQUEST_PATH => {
            parse_router_public_body_v1(
                &request_body,
                parse_cloudflare_router_authorized_router_ab_ecdsa_derivation_prepare_request_v1_json,
                request,
                env,
            )?
            .map(|(request, authorized_operation)| {
                StrictRouterNormalSigningRequestV1::EcdsaPrepare {
                    request,
                    authorized_operation,
                }
            })
        }
        CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_SIGNING_PUBLIC_REQUEST_PATH => {
            parse_router_public_body_v1(
                &request_body,
                parse_cloudflare_router_authorized_router_ab_ecdsa_derivation_finalize_request_v1_json,
                request,
                env,
            )?
            .map(|(request, authorized_operation)| {
                StrictRouterNormalSigningRequestV1::EcdsaFinalize {
                    request,
                    authorized_operation,
                }
            })
        }
        _ => {
            return Ok(Err(Response::error(
                "Router A/B strict normal-signing route is unavailable",
                404,
            )?));
        }
    };
    Ok(parsed)
}

#[cfg(feature = "strict-worker-router-entrypoint")]
async fn execute_strict_router_normal_signing_request_v1(
    parsed: StrictRouterNormalSigningRequestV1,
    request: &Request,
    env: &Env,
    runtime: &CloudflareRouterWorkerRuntimeV1,
    now_unix_ms: u64,
    trusted_source_digest: PublicDigest32,
    verifier: CloudflareRouterEd25519JwksJwtVerifierV1,
) -> worker::Result<Response> {
    let operation_step_up = parsed.is_operation_step_up();
    let gateway_linked_device_wallet_session = parsed.is_gateway_linked_device_wallet_session();
    match parsed {
        StrictRouterNormalSigningRequestV1::Ed25519Prepare {
            request: signing_request,
            authorized_operation,
        } if gateway_linked_device_wallet_session => {
            let response =
                handle_cloudflare_router_normal_signing_prepare_internal_linked_device_request_v2(
                    env,
                    runtime,
                    now_unix_ms,
                    signing_request,
                    authorized_operation,
                    trusted_source_digest,
                )
                .await;
            router_json_cors_response_v1(response, request, env)
        }
        StrictRouterNormalSigningRequestV1::Ed25519Prepare {
            request: signing_request,
            authorized_operation,
        } if operation_step_up => {
            let response =
                handle_cloudflare_router_normal_signing_prepare_internal_step_up_request_v2(
                    env,
                    runtime,
                    now_unix_ms,
                    signing_request,
                    authorized_operation,
                    trusted_source_digest,
                )
                .await;
            router_json_cors_response_v1(response, request, env)
        }
        StrictRouterNormalSigningRequestV1::Ed25519Prepare {
            request: signing_request,
            authorized_operation,
        } => {
            let credential = match authorized_operation
                .gateway_owner_wallet_session_credential(trusted_source_digest)
            {
                Ok(credential) => credential,
                Err(err) => {
                    return router_json_cors_response_v1::<serde_json::Value>(
                        Err(err),
                        request,
                        env,
                    )
                }
            };
            let response =
                handle_cloudflare_router_normal_signing_prepare_authenticated_public_request_v2(
                    env,
                    runtime,
                    now_unix_ms,
                    signing_request,
                    authorized_operation,
                    credential,
                    trusted_source_digest,
                    verifier,
                )
                .await;
            router_json_cors_response_v1(response, request, env)
        }
        StrictRouterNormalSigningRequestV1::Ed25519Finalize {
            request: signing_request,
            authorized_operation,
        } if gateway_linked_device_wallet_session => {
            let response =
                handle_cloudflare_router_normal_signing_finalize_internal_linked_device_request_v2(
                    env,
                    runtime,
                    now_unix_ms,
                    signing_request,
                    authorized_operation,
                    trusted_source_digest,
                )
                .await;
            router_json_cors_response_v1(response, request, env)
        }
        StrictRouterNormalSigningRequestV1::Ed25519Finalize {
            request: signing_request,
            authorized_operation,
        } if operation_step_up => {
            let response =
                handle_cloudflare_router_normal_signing_finalize_internal_step_up_request_v2(
                    env,
                    runtime,
                    now_unix_ms,
                    signing_request,
                    authorized_operation,
                    trusted_source_digest,
                )
                .await;
            router_json_cors_response_v1(response, request, env)
        }
        StrictRouterNormalSigningRequestV1::Ed25519Finalize {
            request: signing_request,
            authorized_operation,
        } => {
            let credential = match authorized_operation
                .gateway_owner_wallet_session_credential(trusted_source_digest)
            {
                Ok(credential) => credential,
                Err(err) => {
                    return router_json_cors_response_v1::<serde_json::Value>(
                        Err(err),
                        request,
                        env,
                    )
                }
            };
            let response =
                handle_cloudflare_router_normal_signing_finalize_authenticated_public_request_v2(
                    env,
                    runtime,
                    now_unix_ms,
                    signing_request,
                    authorized_operation,
                    credential,
                    trusted_source_digest,
                    verifier,
                )
                .await;
            router_json_cors_response_v1(response, request, env)
        }
        StrictRouterNormalSigningRequestV1::EcdsaPrepare {
            request: signing_request,
            authorized_operation,
        } if operation_step_up => {
            let response = handle_cloudflare_router_ab_ecdsa_derivation_evm_digest_signing_prepare_internal_step_up_request_v1(
                env,
                runtime,
                now_unix_ms,
                signing_request,
                authorized_operation,
                trusted_source_digest,
            )
            .await;
            router_json_cors_response_v1(response, request, env)
        }
        StrictRouterNormalSigningRequestV1::EcdsaPrepare {
            request: signing_request,
            authorized_operation,
        } => {
            let credential = match authorized_operation
                .gateway_owner_wallet_session_credential(trusted_source_digest)
            {
                Ok(credential) => credential,
                Err(err) => {
                    return router_json_cors_response_v1::<serde_json::Value>(
                        Err(err),
                        request,
                        env,
                    )
                }
            };
            let response = handle_cloudflare_router_ab_ecdsa_derivation_evm_digest_signing_prepare_authenticated_public_request_v1(
                env,
                runtime,
                now_unix_ms,
                signing_request,
                authorized_operation,
                credential,
                trusted_source_digest,
                verifier,
            )
            .await;
            router_json_cors_response_v1(response, request, env)
        }
        StrictRouterNormalSigningRequestV1::EcdsaFinalize {
            request: signing_request,
            authorized_operation,
        } if operation_step_up => {
            let response = handle_cloudflare_router_ab_ecdsa_derivation_evm_digest_signing_finalize_internal_step_up_request_v1(
                env,
                runtime,
                now_unix_ms,
                signing_request,
                authorized_operation,
                trusted_source_digest,
            )
            .await;
            router_json_cors_response_v1(response, request, env)
        }
        StrictRouterNormalSigningRequestV1::EcdsaFinalize {
            request: signing_request,
            authorized_operation,
        } => {
            let credential = match authorized_operation
                .gateway_owner_wallet_session_credential(trusted_source_digest)
            {
                Ok(credential) => credential,
                Err(err) => {
                    return router_json_cors_response_v1::<serde_json::Value>(
                        Err(err),
                        request,
                        env,
                    )
                }
            };
            let response = handle_cloudflare_router_ab_ecdsa_derivation_evm_digest_signing_finalize_authenticated_public_request_v1(
                env,
                runtime,
                now_unix_ms,
                signing_request,
                authorized_operation,
                credential,
                trusted_source_digest,
                verifier,
            )
            .await;
            router_json_cors_response_v1(response, request, env)
        }
    }
}

#[cfg(feature = "strict-worker-router-entrypoint")]
async fn handle_router_prewarm_v1(request: &Request, env: &Env) -> worker::Result<Response> {
    if let Err(err) = require_cloudflare_internal_service_auth_request_v1(request, env) {
        return cloudflare_private_service_auth_error_response_v1(err);
    }
    if request.method() != Method::Post {
        return cloudflare_prewarm_response_v1(request);
    }
    if let Err(err) = CloudflareRouterWorkerRuntimeV1::from_worker_env(env) {
        return cloudflare_protocol_error_response_v1(err);
    }
    let result = await_prewarm_fanout_v1(
        prewarm_service_binding_v1(env, "DERIVER_A"),
        prewarm_service_binding_v1(env, "DERIVER_B"),
        prewarm_service_binding_v1(env, "SIGNING_WORKER"),
    )
    .await;
    if result.is_err() {
        return Response::error("Router A/B prewarm fan-out failed", 502);
    }
    cloudflare_prewarm_response_v1(request)
}

#[cfg(feature = "strict-worker-router-entrypoint")]
async fn prewarm_service_binding_v1(env: &Env, binding_name: &str) -> Result<(), ()> {
    let fetcher = env.service(binding_name).map_err(|_| ())?;
    let headers = worker::Headers::new();
    set_cloudflare_internal_service_auth_header_v1(env, &headers, "Worker prewarm")
        .map_err(|_| ())?;
    let mut init = worker::RequestInit::new();
    init.with_method(Method::Post).with_headers(headers);
    let request =
        Request::new_with_init("https://router-ab-prewarm.internal/internal/prewarm", &init)
            .map_err(|_| ())?;
    let response = fetcher.fetch_request(request).await.map_err(|_| ())?;
    if !(200..=299).contains(&response.status_code()) {
        return Err(());
    }
    Ok(())
}

#[cfg(feature = "strict-worker-router-entrypoint")]
async fn await_prewarm_fanout_v1<A, B, C, E>(a: A, b: B, c: C) -> Result<(), E>
where
    A: core::future::Future<Output = Result<(), E>>,
    B: core::future::Future<Output = Result<(), E>>,
    C: core::future::Future<Output = Result<(), E>>,
{
    futures::try_join!(a, b, c)?;
    Ok(())
}

#[cfg(all(test, feature = "strict-worker-router-entrypoint"))]
mod prewarm_tests {
    use super::await_prewarm_fanout_v1;
    use core::task::Poll;
    use futures::future::poll_fn;
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;
    use std::task::Waker;

    fn gated_prewarm_child(
        started: Rc<Cell<usize>>,
        waiting: Rc<RefCell<Vec<Waker>>>,
    ) -> impl core::future::Future<Output = Result<(), ()>> {
        let mut entered = false;
        poll_fn(move |context| {
            if !entered {
                entered = true;
                started.set(started.get() + 1);
            }
            if started.get() == 3 {
                for waker in waiting.borrow_mut().drain(..) {
                    waker.wake();
                }
                return Poll::Ready(Ok(()));
            }
            waiting.borrow_mut().push(context.waker().clone());
            Poll::Pending
        })
    }

    #[test]
    fn router_prewarm_polls_all_three_role_bindings_concurrently() {
        let started = Rc::new(Cell::new(0));
        let waiting = Rc::new(RefCell::new(Vec::new()));
        let result = futures::executor::block_on(await_prewarm_fanout_v1(
            gated_prewarm_child(started.clone(), waiting.clone()),
            gated_prewarm_child(started.clone(), waiting.clone()),
            gated_prewarm_child(started.clone(), waiting),
        ));

        assert_eq!(result, Ok(()));
        assert_eq!(started.get(), 3);
    }
}

#[cfg(feature = "strict-worker-router-entrypoint")]
async fn read_router_public_body_v1(
    request: &mut Request,
    env: &Env,
    label: &'static str,
) -> worker::Result<Result<Vec<u8>, Response>> {
    match request.bytes().await {
        Ok(bytes) => Ok(Ok(bytes)),
        Err(err) => {
            let response = Response::error(format!("{label} body read failed: {err}"), 400)?;
            Ok(Err(cloudflare_router_normal_signing_response_v1(
                response, request, env,
            )?))
        }
    }
}

#[cfg(feature = "strict-worker-router-entrypoint")]
fn parse_router_public_body_v1<T>(
    body: &[u8],
    parser: fn(&[u8]) -> RouterAbProtocolResult<T>,
    request: &Request,
    env: &Env,
) -> worker::Result<Result<T, Response>> {
    match parser(body) {
        Ok(parsed) => Ok(Ok(parsed)),
        Err(err) => {
            let response = cloudflare_protocol_error_response_v1(err)?;
            Ok(Err(cloudflare_router_normal_signing_response_v1(
                response, request, env,
            )?))
        }
    }
}

#[cfg(feature = "strict-worker-router-entrypoint")]
fn router_json_cors_response_v1<T: serde::Serialize>(
    result: RouterAbProtocolResult<T>,
    request: &Request,
    env: &Env,
) -> worker::Result<Response> {
    match result {
        Ok(response) => {
            let response = Response::from_json(&response)?;
            cloudflare_router_normal_signing_response_v1(response, request, env)
        }
        Err(err) => {
            let response = cloudflare_protocol_error_response_v1(err)?;
            cloudflare_router_normal_signing_response_v1(response, request, env)
        }
    }
}

/// As `router_json_cors_response_v1`, but attaches the Router's ECDSA boundary
/// spans as `Server-Timing` (Refactor 94B Phase 0). The response body is
/// untouched — the Gateway reads the header and drops it before the browser.
/// A failed leg still carries whatever spans completed before it failed.
#[cfg(feature = "strict-worker-router-entrypoint")]
fn router_ecdsa_timed_json_cors_response_v1<T: serde::Serialize>(
    result: RouterAbProtocolResult<T>,
    timing: &CloudflareEcdsaBoundaryTimingV1,
    request: &Request,
    env: &Env,
) -> worker::Result<Response> {
    let response = router_json_cors_response_v1(result, request, env)?;
    timing.apply_to(&response)?;
    Ok(response)
}

#[cfg(feature = "strict-worker-router-entrypoint")]
fn router_ecdsa_trace_context_v1(
    request: &Request,
    env: &Env,
) -> worker::Result<Result<Option<CloudflareTraceIdV1>, Response>> {
    match parse_cloudflare_trace_id_from_request_v1(request) {
        Ok(trace_id) => Ok(Ok(trace_id)),
        Err(error) => {
            let response = cloudflare_protocol_error_response_v1(error)?;
            Ok(Err(cloudflare_router_normal_signing_response_v1(
                response, request, env,
            )?))
        }
    }
}

#[cfg(feature = "strict-worker-router-entrypoint")]
fn is_cloudflare_router_public_keyset_path(path: &str) -> bool {
    let normalized = path.strip_suffix('/').unwrap_or(path);
    normalized == CLOUDFLARE_ROUTER_PUBLIC_KEYSET_WELL_KNOWN_PATH
        || normalized == CLOUDFLARE_ROUTER_PUBLIC_KEYSET_PATH
}

#[cfg(feature = "strict-worker-router-entrypoint")]
fn is_cloudflare_router_normal_signing_public_path(path: &str) -> bool {
    let normalized = path.strip_suffix('/').unwrap_or(path);
    normalized == CLOUDFLARE_ROUTER_NORMAL_SIGNING_ROUND1_PREPARE_PUBLIC_REQUEST_PATH
        || normalized == CLOUDFLARE_ROUTER_NORMAL_SIGNING_PUBLIC_REQUEST_PATH
}

#[cfg(feature = "strict-worker-router-entrypoint")]
fn is_cloudflare_router_ab_ecdsa_derivation_public_path(path: &str) -> bool {
    let normalized = path.strip_suffix('/').unwrap_or(path);
    normalized == CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_REGISTRATION_PUBLIC_REQUEST_PATH
        || normalized == CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_ACTIVATION_PUBLIC_REQUEST_PATH
        || normalized == CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_ADD_SIGNER_PUBLIC_REQUEST_PATH
        || normalized == CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_EXPORT_PUBLIC_REQUEST_PATH
        || normalized == CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_REFRESH_PUBLIC_REQUEST_PATH
        || normalized == CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_SIGNING_PREPARE_PUBLIC_REQUEST_PATH
        || normalized == CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_SIGNING_PUBLIC_REQUEST_PATH
}

#[cfg(feature = "strict-worker-router-entrypoint")]
fn router_ab_ecdsa_derivation_registration_purpose_for_public_path(
    path: &str,
) -> Option<RouterAbEcdsaDerivationRegistrationPurposeV1> {
    let normalized = path.strip_suffix('/').unwrap_or(path);
    match normalized {
        CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_REGISTRATION_PUBLIC_REQUEST_PATH => {
            Some(RouterAbEcdsaDerivationRegistrationPurposeV1::WalletRegistration)
        }
        CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_ADD_SIGNER_PUBLIC_REQUEST_PATH => {
            Some(RouterAbEcdsaDerivationRegistrationPurposeV1::WalletAddSigner)
        }
        _ => None,
    }
}
