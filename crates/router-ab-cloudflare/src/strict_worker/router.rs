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
    execute_cloudflare_router_tenant_root_creation_active_state_with_revision_read_call_v1,
    execute_cloudflare_router_tenant_root_creation_cleanup_call_v1,
    execute_cloudflare_router_tenant_root_creation_initial_activation_call_v1,
    execute_cloudflare_router_tenant_root_refresh_activation_call_v1,
    execute_cloudflare_router_tenant_root_refresh_attempt_reservation_call_v1,
    CloudflareTenantRootRefreshFenceV1,
};
use crate::tenant_root_control_plane::{
    execute_cloudflare_tenant_root_control_plane_initial_activation_service_call_v1,
    CloudflareTenantRootControlPlaneInitialActivationRequestV1,
    CloudflareTenantRootControlPlaneRefreshActivationRequestV1,
};
#[cfg(feature = "strict-worker-router-entrypoint")]
use crate::tenant_root_managed_backup_r2::TenantRootManagedBackupObjectCoordinatesV1;
use crate::tenant_root_role_runtime::{
    CloudflareDeriverTenantRootCleanupResponseV1,
    CloudflareDeriverTenantRootManagedRestoreForwardRefreshRequestV1,
    CloudflareDeriverTenantRootManagedRestoreRequestV1,
    CloudflareDeriverTenantRootManagedRestoreResponseV1,
    CloudflareDeriverTenantRootManagedRestoreStatusV1,
    CloudflareDeriverTenantRootRefreshActivationRequestV1,
    CloudflareDeriverTenantRootRefreshActivationResponseV1,
    CloudflareDeriverTenantRootRefreshRequestV1, CloudflareDeriverTenantRootRefreshResponseV1,
    CloudflareTenantRootCreateRoleV1,
};
use crate::{
    execute_cloudflare_deriver_tenant_root_cleanup_service_call_v1,
    execute_cloudflare_deriver_tenant_root_create_role_share_service_call_v1,
    execute_cloudflare_deriver_tenant_root_initial_activation_service_call_v1,
    execute_cloudflare_deriver_tenant_root_refresh_activation_service_call_v1,
    execute_cloudflare_deriver_tenant_root_refresh_service_call_v1,
    execute_cloudflare_signing_worker_linked_device_ecdsa_finalize_service_call_v1,
    execute_cloudflare_tenant_root_control_plane_cleanup_command_service_call_v1,
    execute_cloudflare_tenant_root_control_plane_create_tenant_root_service_call_v1,
    execute_cloudflare_tenant_root_control_plane_refresh_activation_service_call_v1,
    execute_cloudflare_tenant_root_control_plane_refresh_commands_service_call_v1,
    execute_cloudflare_tenant_root_control_plane_role_creation_command_service_call_v1,
    handle_cloudflare_router_ab_ecdsa_derivation_evm_digest_signing_finalize_internal_step_up_request_v1,
    handle_cloudflare_router_ab_ecdsa_derivation_evm_digest_signing_prepare_internal_step_up_request_v1,
    handle_cloudflare_router_normal_signing_finalize_internal_linked_device_request_v2,
    handle_cloudflare_router_normal_signing_finalize_internal_step_up_request_v2,
    handle_cloudflare_router_normal_signing_prepare_internal_linked_device_request_v2,
    handle_cloudflare_router_normal_signing_prepare_internal_step_up_request_v2,
    parse_cloudflare_router_authorized_ed25519_prepare_request_v2_json,
    parse_cloudflare_router_authorized_linked_device_ecdsa_finalize_request_v1_json,
    CloudflareDeriverTenantRootCleanupRequestV1,
    CloudflareDeriverTenantRootCreateRoleShareRequestV1,
    CloudflareDeriverTenantRootCreateRoleShareResponseV1,
    CloudflareDeriverTenantRootInitialActivationRequestV1, CloudflarePeerBindingV1,
    CloudflareRouterEcdsaAcceptedAuthorizedOperationV1,
    CloudflareRouterEcdsaAcceptedCapabilityBindingV1,
    CloudflareRouterEd25519AcceptedAuthorizedOperationV1,
    CloudflareRouterEd25519AcceptedCapabilityBindingV1, CloudflareRouterEd25519JwksJwtVerifierV1,
    CloudflareTenantRootControlPlaneCleanupCommandRequestV1,
    CloudflareTenantRootControlPlaneCreateTenantRootRequestV1,
    CloudflareTenantRootControlPlaneCreateTenantRootResponseV1,
    CloudflareTenantRootControlPlaneRefreshCommandsRequestV1,
    CloudflareTenantRootControlPlaneRoleCreationCommandRequestV1,
    CloudflareTenantRootControlPlaneRoleV1, CloudflareTenantRootCreationStatusV1,
    CLOUDFLARE_ROUTER_TENANT_ROOT_CREATION_PRIVATE_REQUEST_PATH,
    CLOUDFLARE_ROUTER_TENANT_ROOT_MANAGED_RESTORE_PRIVATE_REQUEST_PATH,
    CLOUDFLARE_ROUTER_TENANT_ROOT_REFRESH_PRIVATE_REQUEST_PATH,
    TENANT_ROOT_CONTROL_PLANE_CREATE_TENANT_ROOT_REQUEST_MAX_BYTES_V1,
    TENANT_ROOT_CONTROL_PLANE_REFRESH_COMMANDS_REQUEST_MAX_BYTES_V1,
};

#[cfg(feature = "strict-worker-router-entrypoint")]
#[derive(Debug, serde::Serialize)]
struct CloudflareRouterTenantRootRefreshResponseV1 {
    activation_receipt_digest_b64u: String,
    lifecycle_revision: u64,
}

#[cfg(feature = "strict-worker-router-entrypoint")]
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CloudflareRouterTenantRootManagedRestoreRequestV1 {
    /// Exact control-plane-signed public role-unavailable state.
    public_state_b64u: String,
    /// Exact control-plane-signed one-use restore capability.
    restore_capability_b64u: String,
}

#[cfg(feature = "strict-worker-router-entrypoint")]
const TENANT_ROOT_MANAGED_RESTORE_REQUEST_MAX_BYTES_V1: usize = 128 * 1024;

#[cfg(feature = "strict-worker-router-entrypoint")]
struct VerifiedCloudflareRouterTenantRootManagedRestoreRequestV1 {
    public_state_b64u: String,
    restore_capability_b64u: String,
    identity_b64u: String,
    identity_digest: TenantRootIdentityDigestV1,
    custody_lineage: TenantRootCustodyLineageId,
    active_epoch: u64,
    active_lifecycle_revision: u64,
    active_activation_receipt_b64u: String,
    unavailable_role: TenantRootManagedRestoreRoleV1,
    outage_observation_digest: TenantRootLifecycleReceiptDigestV1,
    active_activation_receipt_digest: TenantRootLifecycleReceiptDigestV1,
    capability: VerifiedTenantRootManagedRestoreCapabilityV1,
}

#[cfg(feature = "strict-worker-router-entrypoint")]
fn decode_exact_managed_restore_wire_v1(
    field: &'static str,
    encoded: &str,
) -> RouterAbProtocolResult<Vec<u8>> {
    let bytes = crate::decode_base64url_bytes_v1(field, encoded)?;
    if crate::encode_base64url_bytes_v1(&bytes) != encoded {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("{field} must use canonical unpadded base64url"),
        ));
    }
    Ok(bytes)
}

#[cfg(feature = "strict-worker-router-entrypoint")]
fn managed_restore_derivation_error_v1(
    field: &'static str,
    error: router_ab_core::RouterAbDerivationError,
) -> RouterAbProtocolError {
    RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::MalformedWirePayload,
        format!("{field} was refused: {error}"),
    )
}

#[cfg(feature = "strict-worker-router-entrypoint")]
fn verify_cloudflare_router_tenant_root_managed_restore_request_v1(
    env: &Env,
    request: CloudflareRouterTenantRootManagedRestoreRequestV1,
) -> RouterAbProtocolResult<VerifiedCloudflareRouterTenantRootManagedRestoreRequestV1> {
    let public_state_bytes = decode_exact_managed_restore_wire_v1(
        "tenant-root managed-restore public state",
        &request.public_state_b64u,
    )?;
    let signed_public_state =
        TenantRootSignedManagedRestoreRoleUnavailableV1::decode_canonical_bytes(
            &public_state_bytes,
        )
        .map_err(|error| {
            managed_restore_derivation_error_v1("tenant-root managed-restore public state", error)
        })?;
    let reader = CloudflareWorkerEnvReaderV1::new(env);
    let issuer_keys =
        crate::env::parse_cloudflare_tenant_root_control_plane_issuer_verifying_keys_v1(&reader)?;
    let issuer_key_id = signed_public_state.issuer_key_id().to_owned();
    let issuer_key = issuer_keys
        .for_issuer_key_id(&issuer_key_id)
        .ok_or_else(|| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ForbiddenLocalBinding,
                "tenant-root managed-restore public-state issuer is not trusted by the Router",
            )
        })?;
    let verified_public_state = signed_public_state
        .verify(&issuer_key_id, issuer_key)
        .map_err(|error| {
            managed_restore_derivation_error_v1("tenant-root managed-restore public state", error)
        })?;

    let capability_bytes = decode_exact_managed_restore_wire_v1(
        "tenant-root managed-restore capability",
        &request.restore_capability_b64u,
    )?;
    let signed_capability =
        TenantRootSignedManagedRestoreCapabilityV1::decode_canonical_bytes(&capability_bytes)
            .map_err(|error| {
                managed_restore_derivation_error_v1("tenant-root managed-restore capability", error)
            })?;
    if signed_capability.issuer_key_id() != verified_public_state.issuer_key_id() {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ForbiddenLocalBinding,
            "tenant-root managed-restore capability and public state use different issuers",
        ));
    }
    let capability = signed_capability
        .verify(
            verified_public_state.state(),
            verified_public_state.issuer_key_id(),
            issuer_key,
        )
        .map_err(|error| {
            managed_restore_derivation_error_v1("tenant-root managed-restore capability", error)
        })?;
    let identity_digest = verified_public_state
        .state()
        .active()
        .identity()
        .digest()
        .map_err(|error| {
            managed_restore_derivation_error_v1(
                "tenant-root managed-restore public-state identity",
                error,
            )
        })?;
    let custody_lineage = verified_public_state.state().active().custody_lineage();
    let identity_canonical_bytes = verified_public_state
        .state()
        .active()
        .identity()
        .canonical_bytes()
        .map_err(|error| {
            managed_restore_derivation_error_v1(
                "tenant-root managed-restore public-state identity",
                error,
            )
        })?;
    let identity_b64u = crate::encode_base64url_bytes_v1(&identity_canonical_bytes);
    let active_epoch = verified_public_state
        .state()
        .active()
        .current()
        .epoch()
        .get()
        .get();
    let active_lifecycle_revision = verified_public_state.state().active().revision();
    let active_activation_receipt_b64u = crate::encode_base64url_bytes_v1(
        verified_public_state
            .state()
            .active()
            .activation_receipt_bytes(),
    );
    let outage_observation_digest = verified_public_state.state().unavailable_receipt().digest();
    let active_activation_receipt_digest = verified_public_state
        .state()
        .active()
        .activation_receipt_digest();
    if verified_public_state.unavailable_role() != capability.role()
        || capability.identity_digest() != identity_digest
        || capability.custody_lineage() != custody_lineage
        || capability.activation_receipt_digest() != active_activation_receipt_digest
    {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ForbiddenLocalBinding,
            "tenant-root managed-restore capability does not match the signed unavailable state",
        ));
    }
    Ok(VerifiedCloudflareRouterTenantRootManagedRestoreRequestV1 {
        public_state_b64u: request.public_state_b64u,
        restore_capability_b64u: request.restore_capability_b64u,
        identity_b64u,
        identity_digest,
        custody_lineage,
        active_epoch,
        active_lifecycle_revision,
        active_activation_receipt_b64u,
        unavailable_role: capability.role(),
        outage_observation_digest,
        active_activation_receipt_digest,
        capability,
    })
}

#[cfg(feature = "strict-worker-router-entrypoint")]
fn require_cloudflare_router_managed_restore_checkpoint_artifacts_v1(
    active: &crate::durable_object::tenant_root_creation::CloudflareVerifiedTenantRootActiveStateV1,
    authorization: &VerifiedCloudflareRouterTenantRootManagedRestoreRequestV1,
) -> RouterAbProtocolResult<()> {
    let identity_digest_b64u =
        crate::encode_base64url_bytes_v1(authorization.identity_digest.as_bytes());
    let custody_lineage_b64u = authorization.custody_lineage.to_base64url();
    let activation_receipt_digest_b64u =
        crate::encode_base64url_bytes_v1(authorization.active_activation_receipt_digest.as_bytes());

    let crate::durable_object::tenant_root_creation::CloudflareTenantRootManagedRestoreFenceV1::Terminal {
        challenge,
        public_state_b64u,
        capability_b64u,
        ..
    } = &active.managed_restore_fence
    else {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLifecycleState,
            "tenant-root managed-restore authorization is not terminally checkpointed",
        ));
    };
    let challenge_identity =
        TenantRootIdentityV1::decode_canonical_bytes(&decode_exact_managed_restore_wire_v1(
            "tenant-root managed-restore checkpoint identity",
            &challenge.identity_b64u,
        )?)
        .map_err(|error| {
            managed_restore_derivation_error_v1(
                "tenant-root managed-restore checkpoint identity",
                error,
            )
        })?;
    let challenge_identity_canonical_bytes =
        challenge_identity.canonical_bytes().map_err(|error| {
            managed_restore_derivation_error_v1(
                "tenant-root managed-restore checkpoint identity",
                error,
            )
        })?;
    let challenge_identity_b64u =
        crate::encode_base64url_bytes_v1(&challenge_identity_canonical_bytes);
    let challenge_identity_digest = challenge_identity.digest().map_err(|error| {
        managed_restore_derivation_error_v1(
            "tenant-root managed-restore checkpoint identity",
            error,
        )
    })?;
    let outage_observation_digest_b64u =
        crate::encode_base64url_bytes_v1(authorization.outage_observation_digest.as_bytes());
    if public_state_b64u != &authorization.public_state_b64u
        || capability_b64u != &authorization.restore_capability_b64u
        || challenge.identity_b64u != authorization.identity_b64u
        || challenge_identity_b64u != authorization.identity_b64u
        || challenge_identity_digest != authorization.identity_digest
        || challenge.identity_digest_b64u != identity_digest_b64u
        || challenge.custody_lineage_b64u != custody_lineage_b64u
        || challenge.active_epoch != authorization.active_epoch
        || challenge.active_lifecycle_revision != authorization.active_lifecycle_revision
        || challenge.activation_receipt_b64u != authorization.active_activation_receipt_b64u
        || challenge.activation_receipt_digest_b64u != activation_receipt_digest_b64u
        || challenge.outage_observation_digest_b64u != outage_observation_digest_b64u
        || challenge.unavailable_role != authorization.unavailable_role
    {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ForbiddenLocalBinding,
            "tenant-root managed-restore authorization checkpoint does not match its signed scope",
        ));
    }
    Ok(())
}

#[cfg(feature = "strict-worker-router-entrypoint")]
fn require_cloudflare_router_managed_restore_checkpoint_current_state_v1(
    active: &crate::durable_object::tenant_root_creation::CloudflareVerifiedTenantRootActiveStateV1,
    authorization: &VerifiedCloudflareRouterTenantRootManagedRestoreRequestV1,
) -> RouterAbProtocolResult<()> {
    let active_epoch = match active.activation_receipt.binding() {
        TenantRootActivationReceiptBindingV1::InitialCreation(binding) => binding.epoch(),
        TenantRootActivationReceiptBindingV1::RefreshSwap(binding) => binding.next_epoch(),
    }
    .get()
    .get();
    let active_activation_receipt_b64u =
        crate::encode_base64url_bytes_v1(active.activation_receipt.canonical_bytes());
    let identity_digest_b64u =
        crate::encode_base64url_bytes_v1(authorization.identity_digest.as_bytes());
    let custody_lineage_b64u = authorization.custody_lineage.to_base64url();
    let crate::durable_object::tenant_root_creation::CloudflareTenantRootManagedRestoreFenceV1::Terminal {
        challenge,
        ..
    } = &active.managed_restore_fence
    else {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLifecycleState,
            "tenant-root managed-restore authorization is not terminally checkpointed",
        ));
    };
    if active.activation_receipt.digest() != authorization.active_activation_receipt_digest
        || challenge.identity_b64u != authorization.identity_b64u
        || challenge.identity_digest_b64u != identity_digest_b64u
        || challenge.custody_lineage_b64u != custody_lineage_b64u
        || challenge.unavailable_role != authorization.unavailable_role
        || challenge.active_epoch != active_epoch
        || challenge.active_lifecycle_revision != active.lifecycle_revision
        || challenge.activation_receipt_b64u != active_activation_receipt_b64u
        || challenge.activation_receipt_digest_b64u
            != crate::encode_base64url_bytes_v1(active.activation_receipt.digest().as_bytes())
    {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ForbiddenLocalBinding,
            "tenant-root managed-restore authorization checkpoint does not match current active state",
        ));
    }
    Ok(())
}

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
                    &CloudflareTenantRootControlPlaneCleanupCommandRequestV1::PendingCreation {
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
                claimed_target.identity_digest(),
                claimed_target.custody_lineage(),
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
            let cleaned = execute_cloudflare_deriver_tenant_root_cleanup_service_call_v1(
                env,
                deriver,
                &CloudflareDeriverTenantRootCleanupRequestV1 {
                    cleanup_command_b64u: cleanup.cleanup_command_b64u,
                },
            )
            .await?;
            let cleanup_receipt = crate::decode_base64url_bytes_v1(
                "tenant-root cleanup terminal receipt",
                cleaned.cleanup_receipt_b64u(),
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

#[cfg(feature = "strict-worker-router-entrypoint")]
const fn tenant_root_control_plane_role_v1(
    role: CloudflareTenantRootCreateRoleV1,
) -> CloudflareTenantRootControlPlaneRoleV1 {
    match role {
        CloudflareTenantRootCreateRoleV1::DeriverA => {
            CloudflareTenantRootControlPlaneRoleV1::DeriverA
        }
        CloudflareTenantRootCreateRoleV1::DeriverB => {
            CloudflareTenantRootControlPlaneRoleV1::DeriverB
        }
    }
}

#[cfg(feature = "strict-worker-router-entrypoint")]
async fn cleanup_cloudflare_router_retired_tenant_root_role_v1(
    env: &Env,
    runtime: &CloudflareRouterWorkerRuntimeV1,
    identity_digest_b64u: &str,
    custody_lineage_b64u: &str,
    activation: &CloudflareDeriverTenantRootRefreshActivationResponseV1,
) -> RouterAbProtocolResult<()> {
    let expected_role = tenant_root_control_plane_role_v1(activation.role);
    let issued = execute_cloudflare_tenant_root_control_plane_cleanup_command_service_call_v1(
        env,
        &CloudflareTenantRootControlPlaneCleanupCommandRequestV1::RetiredAfterRefresh {
            identity_digest_b64u: identity_digest_b64u.to_owned(),
            custody_lineage_b64u: custody_lineage_b64u.to_owned(),
            role: expected_role,
            expected_retired_revision: activation.retired_revision,
            expected_active_revision: activation.active_revision,
        },
    )
    .await?;
    if issued.role != expected_role {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ForbiddenLocalBinding,
            "tenant-root retired cleanup command names a different Deriver",
        ));
    }
    let command_bytes = crate::decode_base64url_bytes_v1(
        "tenant-root retired cleanup command",
        &issued.cleanup_command_b64u,
    )?;
    let command =
        router_ab_core::TenantRootRoleCleanupCommandV1::decode_canonical_bytes(&command_bytes)
            .map_err(|error| {
                RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::MalformedWirePayload,
                    format!("tenant-root retired cleanup command was malformed: {error}"),
                )
            })?;
    let claimed_target = command.claimed_target();
    let router_ab_core::TenantRootRoleCleanupTargetV1::Retired {
        role,
        retired_epoch,
        expected_retired_revision,
        expected_active_epoch,
        expected_active_revision,
        ..
    } = &claimed_target
    else {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ForbiddenLocalBinding,
            "tenant-root post-refresh cleanup command is not a retired-share command",
        ));
    };
    if *role != activation.role.to_protocol()
        || retired_epoch.get().get() != activation.retired_epoch
        || *expected_retired_revision != activation.retired_revision
        || expected_active_epoch.get().get() != activation.active_epoch
        || *expected_active_revision != activation.active_revision
    {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ForbiddenLocalBinding,
            "tenant-root retired cleanup command does not match the completed role swap",
        ));
    }
    let (authority_id, _) = derive_tenant_root_creation_authority_object_v1(
        env,
        claimed_target.identity_digest(),
        claimed_target.custody_lineage(),
    )?;
    let reader = crate::CloudflareWorkerEnvReaderV1::new(env);
    let issuer_keys =
        crate::env::parse_cloudflare_tenant_root_control_plane_issuer_verifying_keys_v1(&reader)?;
    let issuer_key_id = command.issuer_key_id().to_owned();
    let issuer_key = issuer_keys
        .for_issuer_key_id(&issuer_key_id)
        .ok_or_else(|| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ForbiddenLocalBinding,
                "tenant-root retired cleanup issuer is not trusted by the Router",
            )
        })?;
    command
        .verify(
            &claimed_target,
            activation.role.to_protocol(),
            authority_id,
            &issuer_key_id,
            issuer_key,
        )
        .map_err(|error| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ForbiddenLocalBinding,
                format!("tenant-root retired cleanup command verification failed: {error}"),
            )
        })?;
    let deriver = match activation.role {
        CloudflareTenantRootCreateRoleV1::DeriverA => &runtime.bindings().deriver_a,
        CloudflareTenantRootCreateRoleV1::DeriverB => &runtime.bindings().deriver_b,
    };
    let cleaned = execute_cloudflare_deriver_tenant_root_cleanup_service_call_v1(
        env,
        deriver,
        &CloudflareDeriverTenantRootCleanupRequestV1 {
            cleanup_command_b64u: issued.cleanup_command_b64u,
        },
    )
    .await?;
    match cleaned {
        CloudflareDeriverTenantRootCleanupResponseV1::RetiredDeleted {
            role, r2_deletion, ..
        } if role == activation.role => {
            let expected_coordinates = TenantRootManagedBackupObjectCoordinatesV1::new(
                claimed_target.identity_digest(),
                claimed_target.custody_lineage(),
                match activation.role {
                    CloudflareTenantRootCreateRoleV1::DeriverA => {
                        TenantRootManagedRestoreRoleV1::DeriverA
                    }
                    CloudflareTenantRootCreateRoleV1::DeriverB => {
                        TenantRootManagedRestoreRoleV1::DeriverB
                    }
                },
                router_ab_core::TenantRootShareEpoch::new(activation.retired_epoch).map_err(
                    |error| {
                        managed_restore_derivation_error_v1(
                            "tenant-root retired cleanup epoch",
                            error,
                        )
                    },
                )?,
            );
            if r2_deletion.managed_backup_object_key() != expected_coordinates.object_key()
                || r2_deletion.provider_canary_object_key()
                    != expected_coordinates.provider_canary_object_key()
            {
                return Err(RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::ForbiddenLocalBinding,
                    "tenant-root retired cleanup returned unrelated managed-backup objects",
                ));
            }
            Ok(())
        }
        _ => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLifecycleState,
            "tenant-root Deriver did not confirm retired-share deletion",
        )),
    }
}

#[cfg(feature = "strict-worker-router-entrypoint")]
async fn execute_cloudflare_deriver_tenant_root_refresh_service_call_with_retry_v1<'a>(
    env: &'a Env,
    peer: &'a CloudflarePeerBindingV1,
    request: &'a CloudflareDeriverTenantRootRefreshRequestV1,
) -> RouterAbProtocolResult<CloudflareDeriverTenantRootRefreshResponseV1> {
    match execute_cloudflare_deriver_tenant_root_refresh_service_call_v1(env, peer, request).await {
        Ok(response) => Ok(response),
        Err(_) => {
            execute_cloudflare_deriver_tenant_root_refresh_service_call_v1(env, peer, request).await
        }
    }
}

#[cfg(feature = "strict-worker-router-entrypoint")]
fn tenant_root_deriver_role_for_peer_v1(
    peer: &CloudflarePeerBindingV1,
) -> RouterAbProtocolResult<CloudflareTenantRootCreateRoleV1> {
    match peer.peer_role {
        crate::CloudflareWorkerRoleV1::DeriverA => Ok(CloudflareTenantRootCreateRoleV1::DeriverA),
        crate::CloudflareWorkerRoleV1::DeriverB => Ok(CloudflareTenantRootCreateRoleV1::DeriverB),
        _ => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "tenant-root managed restore can target only a Deriver",
        )),
    }
}

#[cfg(feature = "strict-worker-router-entrypoint")]
fn tenant_root_deriver_managed_restore_service_url_v1(
    peer: &CloudflarePeerBindingV1,
    path: &'static str,
) -> RouterAbProtocolResult<String> {
    peer.validate()?;
    let host = match peer.peer_role {
        crate::CloudflareWorkerRoleV1::DeriverA => "router-ab-deriver-a.internal",
        crate::CloudflareWorkerRoleV1::DeriverB => "router-ab-deriver-b.internal",
        _ => {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "tenant-root managed restore can target only a Deriver",
            ));
        }
    };
    Ok(format!("https://{host}{path}"))
}

#[cfg(feature = "strict-worker-router-entrypoint")]
async fn execute_cloudflare_deriver_tenant_root_managed_restore_service_call_v1(
    env: &Env,
    peer: &CloudflarePeerBindingV1,
    request: &CloudflareDeriverTenantRootManagedRestoreRequestV1,
    expected_capability_digest: TenantRootLifecycleReceiptDigestV1,
) -> RouterAbProtocolResult<CloudflareDeriverTenantRootManagedRestoreResponseV1> {
    let expected_role = tenant_root_deriver_role_for_peer_v1(peer)?;
    let url = tenant_root_deriver_managed_restore_service_url_v1(
        peer,
        crate::CLOUDFLARE_DERIVER_TENANT_ROOT_MANAGED_RESTORE_PRIVATE_REQUEST_PATH,
    )?;
    let response: CloudflareDeriverTenantRootManagedRestoreResponseV1 = crate::post_service_json(
        env,
        &peer.binding_name,
        &url,
        "tenant-root managed-restore staging request",
        request,
    )
    .await?;
    if response.role != expected_role
        || response.status
            != CloudflareDeriverTenantRootManagedRestoreStatusV1::StagedForForwardRefresh
    {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "tenant-root managed-restore response does not confirm staged forward refresh",
        ));
    }
    let capability_digest = decode_exact_managed_restore_wire_v1(
        "tenant-root managed-restore staging capability digest",
        &response.capability_digest_b64u,
    )?;
    if capability_digest.as_slice() != expected_capability_digest.as_bytes() {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ForbiddenLocalBinding,
            "tenant-root managed-restore staging response names a different capability",
        ));
    }
    let terminal_receipt = decode_exact_managed_restore_wire_v1(
        "tenant-root managed-restore staging terminal receipt",
        &response.staging_terminal_receipt_b64u,
    )?;
    if !matches!(
        TenantRootCommandTerminalReceiptV1::decode_canonical_bytes(&terminal_receipt).map_err(
            |error| {
                managed_restore_derivation_error_v1(
                    "tenant-root managed-restore staging terminal receipt",
                    error,
                )
            }
        )?,
        TenantRootCommandTerminalReceiptV1::Success(_)
    ) {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLifecycleState,
            "tenant-root managed-restore staging did not complete successfully",
        ));
    }
    Ok(response)
}

#[cfg(feature = "strict-worker-router-entrypoint")]
async fn execute_cloudflare_deriver_tenant_root_managed_restore_forward_refresh_service_call_v1(
    env: &Env,
    peer: &CloudflarePeerBindingV1,
    request: &CloudflareDeriverTenantRootManagedRestoreForwardRefreshRequestV1,
) -> RouterAbProtocolResult<CloudflareDeriverTenantRootRefreshResponseV1> {
    let expected_role = tenant_root_deriver_role_for_peer_v1(peer)?;
    let url = tenant_root_deriver_managed_restore_service_url_v1(
        peer,
        crate::CLOUDFLARE_DERIVER_TENANT_ROOT_MANAGED_RESTORE_FORWARD_REFRESH_PRIVATE_REQUEST_PATH,
    )?;
    let response: CloudflareDeriverTenantRootRefreshResponseV1 = crate::post_service_json(
        env,
        &peer.binding_name,
        &url,
        "tenant-root managed-restore forward-refresh request",
        request,
    )
    .await?;
    if response.role != expected_role {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "tenant-root managed-restore forward-refresh response names the wrong role",
        ));
    }
    Ok(response)
}

#[cfg(feature = "strict-worker-router-entrypoint")]
async fn execute_cloudflare_deriver_tenant_root_managed_restore_forward_refresh_service_call_with_retry_v1<
    'a,
>(
    env: &'a Env,
    peer: &'a CloudflarePeerBindingV1,
    request: &'a CloudflareDeriverTenantRootManagedRestoreForwardRefreshRequestV1,
) -> RouterAbProtocolResult<CloudflareDeriverTenantRootRefreshResponseV1> {
    match execute_cloudflare_deriver_tenant_root_managed_restore_forward_refresh_service_call_v1(
        env, peer, request,
    )
    .await
    {
        Ok(response) => Ok(response),
        Err(_) => {
            execute_cloudflare_deriver_tenant_root_managed_restore_forward_refresh_service_call_v1(
                env, peer, request,
            )
            .await
        }
    }
}

#[cfg(feature = "strict-worker-router-entrypoint")]
enum CloudflareManagedRestoreForwardRefreshRequestOrNormalV1 {
    Managed(CloudflareDeriverTenantRootManagedRestoreForwardRefreshRequestV1),
    Normal(CloudflareDeriverTenantRootRefreshRequestV1),
}

#[cfg(feature = "strict-worker-router-entrypoint")]
async fn execute_cloudflare_router_managed_restore_forward_refresh_request_with_retry_v1(
    env: &Env,
    peer: &CloudflarePeerBindingV1,
    request: CloudflareManagedRestoreForwardRefreshRequestOrNormalV1,
) -> RouterAbProtocolResult<CloudflareDeriverTenantRootRefreshResponseV1> {
    match request {
        CloudflareManagedRestoreForwardRefreshRequestOrNormalV1::Managed(request) => {
            execute_cloudflare_deriver_tenant_root_managed_restore_forward_refresh_service_call_with_retry_v1(
                env, peer, &request,
            )
            .await
        }
        CloudflareManagedRestoreForwardRefreshRequestOrNormalV1::Normal(request) => {
            execute_cloudflare_deriver_tenant_root_refresh_service_call_with_retry_v1(
                env, peer, &request,
            )
            .await
        }
    }
}

#[cfg(feature = "strict-worker-router-entrypoint")]
fn refresh_attempt_packages_v1(
    fence: CloudflareTenantRootRefreshFenceV1,
) -> RouterAbProtocolResult<(String, String, String)> {
    match fence {
        CloudflareTenantRootRefreshFenceV1::Reserved { attempt }
        | CloudflareTenantRootRefreshFenceV1::Executed { attempt } => Ok((
            attempt.refresh_context_b64u,
            attempt.deriver_a_refresh_command_b64u,
            attempt.deriver_b_refresh_command_b64u,
        )),
        CloudflareTenantRootRefreshFenceV1::Open => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLifecycleState,
            "tenant-root refresh attempt is not reserved",
        )),
        CloudflareTenantRootRefreshFenceV1::Terminal { .. } => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ConflictingPair,
            "tenant-root refresh operation is terminal",
        )),
    }
}

#[cfg(feature = "strict-worker-router-entrypoint")]
fn replay_terminal_refresh_response_v1(
    fence: &CloudflareTenantRootRefreshFenceV1,
) -> RouterAbProtocolResult<Option<CloudflareRouterTenantRootRefreshResponseV1>> {
    match fence {
        CloudflareTenantRootRefreshFenceV1::Terminal {
            outcome: crate::durable_object::tenant_root_creation::CloudflareTenantRootRefreshTerminalOutcomeV1::Completed,
            response,
            ..
        } => Ok(Some(CloudflareRouterTenantRootRefreshResponseV1 {
            activation_receipt_digest_b64u: response.activation_receipt_digest_b64u.clone(),
            lifecycle_revision: response.lifecycle_revision,
        })),
        CloudflareTenantRootRefreshFenceV1::Terminal { .. } => {
            Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ConflictingPair,
                "tenant-root refresh operation is terminal without a successful activation",
            ))
        }
        _ => Ok(None),
    }
}

#[cfg(feature = "strict-worker-router-entrypoint")]
async fn replay_cloudflare_router_terminal_refresh_cleanup_v1(
    env: &Env,
    runtime: &CloudflareRouterWorkerRuntimeV1,
    identity_digest_b64u: &str,
    custody_lineage_b64u: &str,
    activation_receipt_b64u: String,
) -> RouterAbProtocolResult<()> {
    let role_activation = CloudflareDeriverTenantRootRefreshActivationRequestV1 {
        activation_receipt_b64u,
    };
    let (deriver_a_activation, deriver_b_activation) = futures::try_join!(
        execute_cloudflare_deriver_tenant_root_refresh_activation_service_call_v1(
            env,
            &runtime.bindings().deriver_a,
            &role_activation,
        ),
        execute_cloudflare_deriver_tenant_root_refresh_activation_service_call_v1(
            env,
            &runtime.bindings().deriver_b,
            &role_activation,
        ),
    )?;
    futures::try_join!(
        cleanup_cloudflare_router_retired_tenant_root_role_v1(
            env,
            runtime,
            identity_digest_b64u,
            custody_lineage_b64u,
            &deriver_a_activation,
        ),
        cleanup_cloudflare_router_retired_tenant_root_role_v1(
            env,
            runtime,
            identity_digest_b64u,
            custody_lineage_b64u,
            &deriver_b_activation,
        ),
    )?;
    Ok(())
}

#[cfg(feature = "strict-worker-router-entrypoint")]
async fn finish_cloudflare_router_tenant_root_refresh_v1(
    env: &Env,
    runtime: &CloudflareRouterWorkerRuntimeV1,
    identity_digest_b64u: &str,
    custody_lineage_b64u: &str,
    deriver_a: CloudflareDeriverTenantRootRefreshResponseV1,
    deriver_b: CloudflareDeriverTenantRootRefreshResponseV1,
) -> RouterAbProtocolResult<CloudflareRouterTenantRootRefreshResponseV1> {
    let issued_activation =
        execute_cloudflare_tenant_root_control_plane_refresh_activation_service_call_v1(
            env,
            &CloudflareTenantRootControlPlaneRefreshActivationRequestV1 {
                deriver_a_signed_installation_evidence_b64u: deriver_a
                    .signed_installation_evidence_b64u,
                deriver_b_signed_installation_evidence_b64u: deriver_b
                    .signed_installation_evidence_b64u,
                deriver_a_signed_managed_backup_b64u: deriver_a.signed_managed_backup_b64u,
                deriver_b_signed_managed_backup_b64u: deriver_b.signed_managed_backup_b64u,
                ecdsa_provider_canary_receipt_b64u: deriver_a.provider_canary_receipt_b64u,
                ed25519_provider_canary_receipt_b64u: deriver_b.provider_canary_receipt_b64u,
            },
        )
        .await?;
    let role_activation = CloudflareDeriverTenantRootRefreshActivationRequestV1 {
        activation_receipt_b64u: issued_activation.activation_receipt_b64u.clone(),
    };
    let (deriver_a_activation, deriver_b_activation) = futures::try_join!(
        execute_cloudflare_deriver_tenant_root_refresh_activation_service_call_v1(
            env,
            &runtime.bindings().deriver_a,
            &role_activation,
        ),
        execute_cloudflare_deriver_tenant_root_refresh_activation_service_call_v1(
            env,
            &runtime.bindings().deriver_b,
            &role_activation,
        ),
    )?;
    let activation_receipt = crate::decode_base64url_bytes_v1(
        "tenant-root refresh activation receipt",
        &issued_activation.activation_receipt_b64u,
    )?;
    let activated =
        execute_cloudflare_router_tenant_root_refresh_activation_call_v1(env, &activation_receipt)
            .await?;
    futures::try_join!(
        cleanup_cloudflare_router_retired_tenant_root_role_v1(
            env,
            runtime,
            identity_digest_b64u,
            custody_lineage_b64u,
            &deriver_a_activation,
        ),
        cleanup_cloudflare_router_retired_tenant_root_role_v1(
            env,
            runtime,
            identity_digest_b64u,
            custody_lineage_b64u,
            &deriver_b_activation,
        ),
    )?;
    Ok(CloudflareRouterTenantRootRefreshResponseV1 {
        activation_receipt_digest_b64u: activated.activation_receipt_digest_b64u,
        lifecycle_revision: activated.lifecycle_revision,
    })
}

#[cfg(feature = "strict-worker-router-entrypoint")]
async fn coordinate_cloudflare_router_tenant_root_refresh_v1(
    env: &Env,
    runtime: &CloudflareRouterWorkerRuntimeV1,
    request: CloudflareTenantRootControlPlaneRefreshCommandsRequestV1,
) -> RouterAbProtocolResult<CloudflareRouterTenantRootRefreshResponseV1> {
    let identity_digest = TenantRootIdentityDigestV1::from_bytes(
        crate::decode_base64url_bytes_v1(
            "tenant-root refresh identity digest",
            &request.identity_digest_b64u,
        )?
        .try_into()
        .map_err(|_| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "tenant-root refresh identity digest must contain exactly 32 bytes",
            )
        })?,
    );
    let custody_lineage = TenantRootCustodyLineageId::from_base64url(&request.custody_lineage_b64u)
        .map_err(|error| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                format!("tenant-root refresh custody lineage is invalid: {error}"),
            )
        })?;
    let active =
        execute_cloudflare_router_tenant_root_creation_active_state_with_revision_read_call_v1(
            env,
            identity_digest,
            custody_lineage,
        )
        .await?;
    if let Some(response) = replay_terminal_refresh_response_v1(&active.refresh_fence)? {
        replay_cloudflare_router_terminal_refresh_cleanup_v1(
            env,
            runtime,
            &request.identity_digest_b64u,
            &request.custody_lineage_b64u,
            crate::encode_base64url_bytes_v1(active.activation_receipt.canonical_bytes()),
        )
        .await?;
        return Ok(response);
    }
    let (refresh_context_b64u, deriver_a_refresh_command_b64u, deriver_b_refresh_command_b64u) =
        match active.refresh_fence {
            CloudflareTenantRootRefreshFenceV1::Open => {
                let issued =
                    execute_cloudflare_tenant_root_control_plane_refresh_commands_service_call_v1(
                        env, &request,
                    )
                    .await?;
                let reserved =
                    execute_cloudflare_router_tenant_root_refresh_attempt_reservation_call_v1(
                        env,
                        identity_digest,
                        custody_lineage,
                        issued.refresh_context_b64u,
                        issued.deriver_a_refresh_command_b64u,
                        issued.deriver_b_refresh_command_b64u,
                    )
                    .await?;
                refresh_attempt_packages_v1(reserved.refresh_fence)?
            }
            fence => refresh_attempt_packages_v1(fence)?,
        };
    let deriver_a_request = CloudflareDeriverTenantRootRefreshRequestV1 {
        refresh_context_b64u: refresh_context_b64u.clone(),
        role_refresh_command_b64u: deriver_a_refresh_command_b64u,
    };
    let deriver_b_request = CloudflareDeriverTenantRootRefreshRequestV1 {
        refresh_context_b64u,
        role_refresh_command_b64u: deriver_b_refresh_command_b64u,
    };
    let (deriver_a, deriver_b) = futures::join!(
        execute_cloudflare_deriver_tenant_root_refresh_service_call_with_retry_v1(
            env,
            &runtime.bindings().deriver_a,
            &deriver_a_request,
        ),
        execute_cloudflare_deriver_tenant_root_refresh_service_call_with_retry_v1(
            env,
            &runtime.bindings().deriver_b,
            &deriver_b_request,
        ),
    );
    let deriver_a = deriver_a?;
    let deriver_b = deriver_b?;
    finish_cloudflare_router_tenant_root_refresh_v1(
        env,
        runtime,
        &request.identity_digest_b64u,
        &request.custody_lineage_b64u,
        deriver_a,
        deriver_b,
    )
    .await
}

#[cfg(feature = "strict-worker-router-entrypoint")]
async fn coordinate_cloudflare_router_tenant_root_managed_restore_v1(
    env: &Env,
    runtime: &CloudflareRouterWorkerRuntimeV1,
    request: CloudflareRouterTenantRootManagedRestoreRequestV1,
) -> RouterAbProtocolResult<CloudflareRouterTenantRootRefreshResponseV1> {
    let authorization =
        verify_cloudflare_router_tenant_root_managed_restore_request_v1(env, request)?;
    let active =
        execute_cloudflare_router_tenant_root_creation_active_state_with_revision_read_call_v1(
            env,
            authorization.identity_digest,
            authorization.custody_lineage,
        )
        .await?;
    require_cloudflare_router_managed_restore_checkpoint_artifacts_v1(&active, &authorization)?;
    let terminal_belongs_to_this_restore = matches!(
        &active.refresh_fence,
        CloudflareTenantRootRefreshFenceV1::Terminal { attempt, .. }
            if attempt.current_epoch == authorization.active_epoch
    );
    if terminal_belongs_to_this_restore {
        let response =
            replay_terminal_refresh_response_v1(&active.refresh_fence)?.ok_or_else(|| {
                RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::InvalidLifecycleState,
                    "tenant-root managed-restore terminal refresh response is unavailable",
                )
            })?;
        replay_cloudflare_router_terminal_refresh_cleanup_v1(
            env,
            runtime,
            &crate::encode_base64url_bytes_v1(authorization.identity_digest.as_bytes()),
            &authorization.custody_lineage.to_base64url(),
            crate::encode_base64url_bytes_v1(active.activation_receipt.canonical_bytes()),
        )
        .await?;
        return Ok(response);
    }
    require_cloudflare_router_managed_restore_checkpoint_current_state_v1(&active, &authorization)?;

    let must_start_forward_refresh = matches!(
        &active.refresh_fence,
        CloudflareTenantRootRefreshFenceV1::Open
    ) || matches!(
        &active.refresh_fence,
        CloudflareTenantRootRefreshFenceV1::Terminal { attempt, .. }
            if attempt.next_epoch == authorization.active_epoch
    );

    let (refresh_context_b64u, deriver_a_refresh_command_b64u, deriver_b_refresh_command_b64u) =
        if must_start_forward_refresh {
            let deriver = match authorization.unavailable_role {
                TenantRootManagedRestoreRoleV1::DeriverA => &runtime.bindings().deriver_a,
                TenantRootManagedRestoreRoleV1::DeriverB => &runtime.bindings().deriver_b,
            };
            execute_cloudflare_deriver_tenant_root_managed_restore_service_call_v1(
                env,
                deriver,
                &CloudflareDeriverTenantRootManagedRestoreRequestV1 {
                    public_state_b64u: authorization.public_state_b64u.clone(),
                    restore_capability_b64u: authorization.restore_capability_b64u.clone(),
                },
                authorization.capability.capability_digest(),
            )
            .await?;

            let refresh_commands_request =
                CloudflareTenantRootControlPlaneRefreshCommandsRequestV1 {
                    identity_digest_b64u: crate::encode_base64url_bytes_v1(
                        authorization.identity_digest.as_bytes(),
                    ),
                    custody_lineage_b64u: authorization.custody_lineage.to_base64url(),
                };
            let issued =
                execute_cloudflare_tenant_root_control_plane_refresh_commands_service_call_v1(
                    env,
                    &refresh_commands_request,
                )
                .await?;
            let reserved =
                execute_cloudflare_router_tenant_root_refresh_attempt_reservation_call_v1(
                    env,
                    authorization.identity_digest,
                    authorization.custody_lineage,
                    issued.refresh_context_b64u,
                    issued.deriver_a_refresh_command_b64u,
                    issued.deriver_b_refresh_command_b64u,
                )
                .await?;
            refresh_attempt_packages_v1(reserved.refresh_fence)?
        } else {
            refresh_attempt_packages_v1(active.refresh_fence)?
        };

    let deriver_a_request = match authorization.unavailable_role {
        TenantRootManagedRestoreRoleV1::DeriverA => {
            CloudflareManagedRestoreForwardRefreshRequestOrNormalV1::Managed(
                CloudflareDeriverTenantRootManagedRestoreForwardRefreshRequestV1 {
                    public_state_b64u: authorization.public_state_b64u.clone(),
                    restore_capability_b64u: authorization.restore_capability_b64u.clone(),
                    refresh_context_b64u: refresh_context_b64u.clone(),
                    role_refresh_command_b64u: deriver_a_refresh_command_b64u,
                },
            )
        }
        TenantRootManagedRestoreRoleV1::DeriverB => {
            CloudflareManagedRestoreForwardRefreshRequestOrNormalV1::Normal(
                CloudflareDeriverTenantRootRefreshRequestV1 {
                    refresh_context_b64u: refresh_context_b64u.clone(),
                    role_refresh_command_b64u: deriver_a_refresh_command_b64u,
                },
            )
        }
    };
    let deriver_b_request = match authorization.unavailable_role {
        TenantRootManagedRestoreRoleV1::DeriverA => {
            CloudflareManagedRestoreForwardRefreshRequestOrNormalV1::Normal(
                CloudflareDeriverTenantRootRefreshRequestV1 {
                    refresh_context_b64u,
                    role_refresh_command_b64u: deriver_b_refresh_command_b64u,
                },
            )
        }
        TenantRootManagedRestoreRoleV1::DeriverB => {
            CloudflareManagedRestoreForwardRefreshRequestOrNormalV1::Managed(
                CloudflareDeriverTenantRootManagedRestoreForwardRefreshRequestV1 {
                    public_state_b64u: authorization.public_state_b64u,
                    restore_capability_b64u: authorization.restore_capability_b64u,
                    refresh_context_b64u,
                    role_refresh_command_b64u: deriver_b_refresh_command_b64u,
                },
            )
        }
    };
    let (deriver_a, deriver_b) = futures::join!(
        execute_cloudflare_router_managed_restore_forward_refresh_request_with_retry_v1(
            env,
            &runtime.bindings().deriver_a,
            deriver_a_request,
        ),
        execute_cloudflare_router_managed_restore_forward_refresh_request_with_retry_v1(
            env,
            &runtime.bindings().deriver_b,
            deriver_b_request,
        ),
    );
    finish_cloudflare_router_tenant_root_refresh_v1(
        env,
        runtime,
        &crate::encode_base64url_bytes_v1(authorization.identity_digest.as_bytes()),
        &authorization.custody_lineage.to_base64url(),
        deriver_a?,
        deriver_b?,
    )
    .await
}
use router_ab_core::{
    PublicDigest32, RouterAbEcdsaDerivationEvmDigestSigningFinalizeRequestV1,
    RouterAbEcdsaDerivationEvmDigestSigningRequestV1,
    RouterAbEd25519NormalSigningFinalizeRequestV2, RouterAbEd25519NormalSigningPrepareRequestV2,
    RouterAbProtocolErrorCode, RouterAbProtocolResult, TenantRootActivationReceiptBindingV1,
    TenantRootCommandTerminalReceiptV1, TenantRootCustodyLineageId, TenantRootIdentityDigestV1,
    TenantRootIdentityV1, TenantRootLifecycleReceiptDigestV1, TenantRootManagedRestoreRoleV1,
    TenantRootSignedManagedRestoreCapabilityV1, TenantRootSignedManagedRestoreRoleUnavailableV1,
    VerifiedTenantRootManagedRestoreCapabilityV1,
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
    if path == CLOUDFLARE_ROUTER_TENANT_ROOT_REFRESH_PRIVATE_REQUEST_PATH {
        if let Err(err) = require_cloudflare_internal_service_auth_request_v1(&request, &env) {
            return cloudflare_private_service_auth_error_response_v1(err);
        }
        if request.method() != Method::Post {
            return Response::error("tenant-root refresh route requires POST", 405);
        }
        let runtime = match CloudflareRouterWorkerRuntimeV1::from_worker_env(&env) {
            Ok(runtime) => runtime,
            Err(err) => return cloudflare_protocol_error_response_v1(err),
        };
        let parsed: CloudflareTenantRootControlPlaneRefreshCommandsRequestV1 =
            match decode_bounded_json_request(
                &mut request,
                TENANT_ROOT_CONTROL_PLANE_REFRESH_COMMANDS_REQUEST_MAX_BYTES_V1,
            )
            .await
            {
                Ok(value) => value,
                Err(err) => return cloudflare_protocol_error_response_v1(err),
            };
        return match coordinate_cloudflare_router_tenant_root_refresh_v1(&env, &runtime, parsed)
            .await
        {
            Ok(response) => Response::from_json(&response),
            Err(err) => cloudflare_protocol_error_response_v1(err),
        };
    }
    if path == CLOUDFLARE_ROUTER_TENANT_ROOT_MANAGED_RESTORE_PRIVATE_REQUEST_PATH {
        if let Err(err) = require_cloudflare_internal_service_auth_request_v1(&request, &env) {
            return cloudflare_private_service_auth_error_response_v1(err);
        }
        if request.method() != Method::Post {
            return Response::error("tenant-root managed-restore route requires POST", 405);
        }
        let runtime = match CloudflareRouterWorkerRuntimeV1::from_worker_env(&env) {
            Ok(runtime) => runtime,
            Err(err) => return cloudflare_protocol_error_response_v1(err),
        };
        let parsed: CloudflareRouterTenantRootManagedRestoreRequestV1 =
            match decode_bounded_json_request(
                &mut request,
                TENANT_ROOT_MANAGED_RESTORE_REQUEST_MAX_BYTES_V1,
            )
            .await
            {
                Ok(value) => value,
                Err(err) => return cloudflare_protocol_error_response_v1(err),
            };
        return match coordinate_cloudflare_router_tenant_root_managed_restore_v1(
            &env, &runtime, parsed,
        )
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
            parse_cloudflare_router_ab_ecdsa_derivation_activation_refresh_command_v1_json,
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

#[cfg(all(test, feature = "strict-worker-router-entrypoint"))]
mod refresh_replay_tests {
    use super::replay_terminal_refresh_response_v1;
    use crate::durable_object::tenant_root_creation::{
        CloudflareTenantRootRefreshActivationResponseV1, CloudflareTenantRootRefreshAttemptV1,
        CloudflareTenantRootRefreshFenceV1, CloudflareTenantRootRefreshTerminalOutcomeV1,
    };

    #[test]
    fn completed_refresh_replay_returns_the_persisted_activation_response() {
        let persisted = CloudflareTenantRootRefreshActivationResponseV1 {
            activation_receipt_digest_b64u: "persisted-receipt-digest".to_owned(),
            lifecycle_revision: 42,
        };
        let fence = CloudflareTenantRootRefreshFenceV1::Terminal {
            attempt: CloudflareTenantRootRefreshAttemptV1 {
                attempt_id_b64u: "attempt".to_owned(),
                identity_digest_b64u: "identity".to_owned(),
                custody_lineage_b64u: "lineage".to_owned(),
                command_digest_b64u: "command-a".to_owned(),
                deriver_b_command_digest_b64u: "command-b".to_owned(),
                ceremony_context_digest_b64u: "context".to_owned(),
                refresh_context_b64u: "refresh-context".to_owned(),
                deriver_a_refresh_command_b64u: "refresh-command-a".to_owned(),
                deriver_b_refresh_command_b64u: "refresh-command-b".to_owned(),
                session_id_b64u: "session".to_owned(),
                nonce_b64u: "nonce".to_owned(),
                current_epoch: 7,
                next_epoch: 8,
                expected_control_plane_revision: 41,
            },
            outcome: CloudflareTenantRootRefreshTerminalOutcomeV1::Completed,
            response: persisted.clone(),
        };

        let replay = replay_terminal_refresh_response_v1(&fence)
            .expect("completed terminal state must replay")
            .expect("completed terminal state must return a response");
        assert_eq!(
            replay.activation_receipt_digest_b64u,
            persisted.activation_receipt_digest_b64u
        );
        assert_eq!(replay.lifecycle_revision, persisted.lifecycle_revision);
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
