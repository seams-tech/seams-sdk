use super::*;

use crate::durable_object::tenant_root_creation::decode_bounded_json_request;
use crate::{
    handle_cloudflare_tenant_root_control_plane_create_tenant_root_v1,
    handle_cloudflare_tenant_root_control_plane_role_creation_command_v1,
    CloudflareTenantRootControlPlaneCreateTenantRootRequestV1,
    CloudflareTenantRootControlPlaneRoleCreationCommandRequestV1,
    CloudflareTenantRootControlPlaneRuntimeV1,
    CLOUDFLARE_TENANT_ROOT_CONTROL_PLANE_CREATE_TENANT_ROOT_PRIVATE_REQUEST_PATH,
    CLOUDFLARE_TENANT_ROOT_CONTROL_PLANE_ROLE_CREATION_COMMAND_PRIVATE_REQUEST_PATH,
    TENANT_ROOT_CONTROL_PLANE_CREATE_TENANT_ROOT_REQUEST_MAX_BYTES_V1,
    TENANT_ROOT_CONTROL_PLANE_ROLE_CREATION_COMMAND_REQUEST_MAX_BYTES_V1,
};

/// Fetch entrypoint for the internal tenant-root control-plane Worker.
///
/// The control plane is the sole holder of the R120 issuer private signing
/// key. Every request must carry internal-service authentication, and startup
/// fails closed on any forbidden key or missing issuer Secret before a single
/// route is considered.
///
/// Two issuer operations are exposed, and no raw-payload signing method ever
/// will be. Genesis opens a tenant root under a signed creation grant; the role
/// command operation mints one Deriver's creation command. Both construct every
/// canonical artifact from exact tenant authorization and authoritative Durable
/// Object state, and derive authority, revision, session, nonce, window and
/// signing key locally rather than accepting them from a request.
#[cfg(feature = "strict-worker-tenant-root-control-plane-entrypoint")]
pub(super) async fn handle_strict_tenant_root_control_plane_fetch_v1(
    mut request: Request,
    env: Env,
) -> worker::Result<Response> {
    if let Err(err) = require_cloudflare_internal_service_auth_request_v1(&request, &env) {
        return cloudflare_private_service_auth_error_response_v1(err);
    }
    let path = request.path();
    if path == CLOUDFLARE_INTERNAL_PREWARM_PATH {
        if request.method() != Method::Post {
            return cloudflare_prewarm_response_v1(&request);
        }
        if let Err(err) = CloudflareTenantRootControlPlaneRuntimeV1::from_worker_env(&env) {
            return cloudflare_protocol_error_response_v1(err);
        }
        return cloudflare_prewarm_response_v1(&request);
    }
    let runtime = match CloudflareTenantRootControlPlaneRuntimeV1::from_worker_env(&env) {
        Ok(runtime) => runtime,
        Err(err) => return cloudflare_protocol_error_response_v1(err),
    };
    match path.as_str() {
        CLOUDFLARE_TENANT_ROOT_CONTROL_PLANE_ROLE_CREATION_COMMAND_PRIVATE_REQUEST_PATH => {
            if request.method() != Method::Post {
                return Response::error("tenant-root control-plane routes require POST", 405);
            }
            let parsed: CloudflareTenantRootControlPlaneRoleCreationCommandRequestV1 =
                match decode_bounded_json_request(
                    &mut request,
                    TENANT_ROOT_CONTROL_PLANE_ROLE_CREATION_COMMAND_REQUEST_MAX_BYTES_V1,
                )
                .await
                {
                    Ok(value) => value,
                    Err(err) => return cloudflare_protocol_error_response_v1(err),
                };
            match handle_cloudflare_tenant_root_control_plane_role_creation_command_v1(
                parsed, &env, &runtime,
            )
            .await
            {
                Ok(response) => Response::from_json(&response),
                Err(err) => cloudflare_protocol_error_response_v1(err),
            }
        }
        CLOUDFLARE_TENANT_ROOT_CONTROL_PLANE_CREATE_TENANT_ROOT_PRIVATE_REQUEST_PATH => {
            if request.method() != Method::Post {
                return Response::error("tenant-root control-plane routes require POST", 405);
            }
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
            match handle_cloudflare_tenant_root_control_plane_create_tenant_root_v1(
                parsed, &env, &runtime,
            )
            .await
            {
                Ok(response) => Response::from_json(&response),
                Err(err) => cloudflare_protocol_error_response_v1(err),
            }
        }
        _ => Response::error("not found", 404),
    }
}
