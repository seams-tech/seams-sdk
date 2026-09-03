//! Cloudflare Worker adapter for the Router-owned Refactor 93 ceremony.

use crate::durable_object::tenant_root_creation::execute_cloudflare_router_tenant_root_creation_active_state_read_call_v1;
use crate::{
    build_cloudflare_router_public_keyset_v2, cloudflare_now_unix_ms_v1,
    cloudflare_router_error_status, cloudflare_service_json_request_body_v1,
    cloudflare_tenant_root_ed25519_yao_binding_v2, encode_base64url_bytes_v1,
    parse_cloudflare_deriver_peer_verifying_key_set_v1, parse_cloudflare_trace_id_from_request_v1,
    require_cloudflare_internal_service_auth_request_v1,
    set_cloudflare_internal_service_auth_header_v1, set_cloudflare_trace_id_header_v1,
    CloudflareEd25519YaoInactiveReservationResponseV1, CloudflareEd25519YaoPackagePairDeliveryV1,
    CloudflareEd25519YaoPairExecuteRequestV1, CloudflareEd25519YaoPairExecuteResponseV1,
    CloudflareEd25519YaoPairLookupRequestV1, CloudflareEd25519YaoPairPrepareRequestV1,
    CloudflareEd25519YaoPairStatusResponseV1, CloudflareEd25519YaoRoleFailureResponseV1,
    CloudflareEd25519YaoSourcePreservingInactiveReservationRequestV1,
    CloudflareEd25519YaoTenantRootContextV2, CloudflareRouterProjectPolicyV1,
    CloudflareRouterWorkerRuntimeV1, CloudflareTenantRootCoordinatesV1,
    CloudflareWorkerEnvReaderV1, CLOUDFLARE_DERIVER_A_ED25519_YAO_BURN_PAIR_PATH,
    CLOUDFLARE_DERIVER_A_ED25519_YAO_EXECUTE_PAIR_PATH,
    CLOUDFLARE_DERIVER_A_ED25519_YAO_PREPARE_PAIR_PATH,
    CLOUDFLARE_DERIVER_A_ED25519_YAO_READ_PAIR_STATUS_PATH,
    CLOUDFLARE_DERIVER_B_ED25519_YAO_BURN_PAIR_PATH,
    CLOUDFLARE_DERIVER_B_ED25519_YAO_PREPARE_PAIR_PATH,
    CLOUDFLARE_DERIVER_B_ED25519_YAO_READ_PAIR_STATUS_PATH,
    CLOUDFLARE_SIGNING_WORKER_ED25519_YAO_PACKAGES_PATH,
    CLOUDFLARE_SIGNING_WORKER_ED25519_YAO_RECOVERY_PROMOTE_PATH,
    CLOUDFLARE_SIGNING_WORKER_ED25519_YAO_RESERVE_INACTIVE_SOURCE_PRESERVING_PATH,
    CLOUDFLARE_SIGNING_WORKER_LANE_MATERIAL_COMMAND_PATH,
};
use router_ab_core::{
    ed25519_yao_recipient_set_digest_v1, Ed25519YaoCeremonyBindingV1, Ed25519YaoDeriverRoleV1,
    Ed25519YaoInputPairBindingV1, Ed25519YaoOperationV1, Ed25519YaoPackageKindV1,
    Ed25519YaoRoleReadinessReceiptV1, PublicDigest32, RouterAbEd25519YaoActivationPublicReceiptV1,
    RouterAbEd25519YaoActivationResultV1, RouterAbEd25519YaoApplicationBindingFactsV1,
    RouterAbEd25519YaoExportResultV1, RouterAbEd25519YaoLaneDispatchRequestV1,
    RouterAbEd25519YaoLaneDispatchResponseV1, RouterAbProtocolError, RouterAbProtocolErrorCode,
    RouterAbProtocolResult, RouterEd25519YaoExecuteRequestV1, RouterEd25519YaoExecuteResultV1,
    RouterEd25519YaoExecuteSuccessV1, RouterEd25519YaoGatewayExecuteTargetV2,
};
use router_ab_ed25519_yao::{
    commit_ed25519_yao_lane_result_v1, lane_protocol_commit_receipt_v1,
    stable_key_derivation_context_v1, Ed25519YaoActivationRoleExecutionV1,
    Ed25519YaoExportRoleExecutionV1, Ed25519YaoLaneRoleExecutionV1, Ed25519YaoRoleExecutionV1,
    Ed25519YaoSigningWorkerPackageDeliveryV1,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use worker::{Env, Method, Request, RequestInit, Response};

const DERIVER_A_SERVICE_URL: &str = "https://router-ab-deriver-a.internal";
const DERIVER_B_SERVICE_URL: &str = "https://router-ab-deriver-b.internal";
const SIGNING_WORKER_SERVICE_URL: &str = "https://router-ab-signing-worker.internal";
const ROUTER_SPAN_EVENT: &str = "router_ab_yao_coordinator_span_v1";
const ROUTER_REPLAY_HEADER: &str = "x-seams-yao-replay";
const ROUTER_AUTHORITY_TTL_MS: u64 = 60_000;

/// Server-admitted execution envelope. Tenant-root selectors and stable-context
/// facts are supplied by the authenticated wallet server, never by the browser.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareRouterEd25519YaoExecuteRequestV2 {
    pub tenant_root: CloudflareTenantRootCoordinatesV1,
    pub application: RouterAbEd25519YaoApplicationBindingFactsV1,
    pub participant_ids: [u16; 2],
    pub target: RouterEd25519YaoGatewayExecuteTargetV2,
}

impl CloudflareRouterEd25519YaoExecuteRequestV2 {
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.tenant_root.resolve()?;
        validate_source_preserving_participant_ids_v1(self.participant_ids)?;
        if self.application.wallet_id() != self.target.ceremony_binding().lifecycle.account_id {
            return Err(invalid_coordinator(
                "server-resolved Ed25519 application wallet does not match the ceremony",
            ));
        }
        let stable_context =
            stable_key_derivation_context_v1(&self.application, self.participant_ids).map_err(
                |_| invalid_coordinator("server-resolved Ed25519 stable context is invalid"),
            )?;
        if stable_context.binding_digest()
            != self
                .target
                .ceremony_binding()
                .stable_key_context_binding
                .into_bytes()
        {
            return Err(invalid_coordinator(
                "server-resolved Ed25519 facts do not match the ceremony stable context",
            ));
        }
        Ok(())
    }
}

/// Server-admitted lane envelope with the same tenant-root binding as ceremonies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareRouterEd25519YaoLaneExecuteRequestV2 {
    pub tenant_root: CloudflareTenantRootCoordinatesV1,
    pub application: RouterAbEd25519YaoApplicationBindingFactsV1,
    pub participant_ids: [u16; 2],
    pub target: RouterAbEd25519YaoLaneDispatchRequestV1,
}

impl CloudflareRouterEd25519YaoLaneExecuteRequestV2 {
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.target.validate()?;
        self.tenant_root.resolve()?;
        validate_source_preserving_participant_ids_v1(self.participant_ids)?;
        if self.application.wallet_id() != self.target.binding.lifecycle.account_id {
            return Err(invalid_coordinator(
                "server-resolved Ed25519 lane wallet does not match the ceremony",
            ));
        }
        let stable_context =
            stable_key_derivation_context_v1(&self.application, self.participant_ids).map_err(
                |_| invalid_coordinator("server-resolved Ed25519 lane stable context is invalid"),
            )?;
        if stable_context.binding_digest()
            != self.target.binding.stable_key_context_binding.into_bytes()
        {
            return Err(invalid_coordinator(
                "server-resolved Ed25519 lane facts do not match the ceremony stable context",
            ));
        }
        Ok(())
    }
}

/// Source-preserving target execution request. The target remains the normal
/// Gateway request shape; the source binding is carried beside it so Router
/// can preserve the exact active public identity without persisting a link
/// ceremony or invoking lifecycle activation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareRouterEd25519YaoSourcePreservingExecuteRequestV1 {
    pub source_binding: Ed25519YaoCeremonyBindingV1,
    pub target: CloudflareRouterEd25519YaoExecuteRequestV2,
}

impl CloudflareRouterEd25519YaoSourcePreservingExecuteRequestV1 {
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.source_binding.validate()?;
        self.target.validate()?;
        if self.source_binding.operation != Ed25519YaoOperationV1::Registration {
            return Err(invalid_coordinator(
                "source-preserving Router execution requires a registration source binding",
            ));
        }
        if self.target.target.operation() != Ed25519YaoOperationV1::Registration {
            return Err(invalid_coordinator(
                "source-preserving Router execution requires a registration target request",
            ));
        }
        validate_source_target_identity_v1(
            &self.source_binding,
            self.target.target.ceremony_binding(),
        )
    }
}

#[derive(Clone)]
enum RouterCeremonyFinalizationV1 {
    Standard,
    SourcePreserving {
        source_binding: Ed25519YaoCeremonyBindingV1,
        participant_ids: [u16; 2],
    },
}

enum RouterCeremonyOutcomeV1 {
    Standard(RouterEd25519YaoExecuteResultV1),
    SourcePreserving(CloudflareEd25519YaoInactiveReservationResponseV1),
}

#[derive(Default)]
struct RouterExecutionTimingV1 {
    prepare_pair_ms: u64,
    verify_readiness_ms: u64,
    role_execution_ms: u64,
    signing_worker_delivery_ms: u64,
}

impl RouterExecutionTimingV1 {
    fn server_timing(&self) -> String {
        format!(
            "yao_router_prepare_pair;dur={}, yao_router_verify_readiness;dur={}, \
             yao_router_role_execution;dur={}, yao_router_signing_worker_delivery;dur={}",
            self.prepare_pair_ms,
            self.verify_readiness_ms,
            self.role_execution_ms,
            self.signing_worker_delivery_ms,
        )
    }
}

enum RouterRoleCallError {
    Protocol(RouterAbProtocolError),
    Failure(CloudflareEd25519YaoRoleFailureResponseV1),
}

impl From<RouterAbProtocolError> for RouterRoleCallError {
    fn from(error: RouterAbProtocolError) -> Self {
        Self::Protocol(error)
    }
}

#[derive(Serialize)]
struct CoordinatorSpan<'a> {
    event: &'static str,
    span: &'a str,
    operation: &'a str,
    outcome: &'a str,
    duration_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    trace_id: Option<String>,
}

fn emit_span(
    trace_id: Option<crate::CloudflareTraceIdV1>,
    span: &str,
    operation: &str,
    started_at_ms: u64,
    outcome: &str,
) {
    let event = CoordinatorSpan {
        event: ROUTER_SPAN_EVENT,
        span,
        operation,
        outcome,
        duration_ms: cloudflare_now_unix_ms_v1()
            .unwrap_or(started_at_ms)
            .saturating_sub(started_at_ms),
        trace_id: trace_id.map(crate::CloudflareTraceIdV1::as_hex),
    };
    if let Ok(serialized) = serde_json::to_string(&event) {
        worker::console_log!("{serialized}");
    }
}

/// Handles one authenticated Gateway-to-Router Yao execution request.
pub async fn handle_cloudflare_router_ed25519_yao_execute_private_fetch_v1(
    mut request: Request,
    env: &Env,
) -> worker::Result<Response> {
    if request.method() != Method::Post {
        return Response::error("Router Yao execute route requires POST", 405);
    }
    if let Err(error) = require_cloudflare_internal_service_auth_request_v1(&request, env) {
        return crate::cloudflare_private_service_auth_error_response_v1(error);
    }
    let parse_started_at_ms = cloudflare_now_unix_ms_v1().unwrap_or_default();
    let trace_id = match parse_cloudflare_trace_id_from_request_v1(&request) {
        Ok(trace_id) => trace_id,
        Err(error) => return protocol_error_response(error),
    };
    let replay = match parse_router_replay_header(&request) {
        Ok(replay) => replay,
        Err(error) => return protocol_error_response(error),
    };
    let gateway_envelope = match request
        .json::<CloudflareRouterEd25519YaoExecuteRequestV2>()
        .await
    {
        Ok(request) => request,
        Err(error) => {
            return protocol_error_response(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                format!("Router Yao execute request JSON is malformed: {error}"),
            ))
        }
    };
    if let Err(error) = gateway_envelope.validate() {
        return protocol_error_response(error);
    }
    let CloudflareRouterEd25519YaoExecuteRequestV2 {
        tenant_root,
        application,
        participant_ids,
        target: gateway_request,
    } = gateway_envelope;
    let now_ms = match cloudflare_now_unix_ms_v1() {
        Ok(now_ms) => now_ms,
        Err(error) => return protocol_error_response(error),
    };
    let runtime = match CloudflareRouterWorkerRuntimeV1::from_worker_env(env) {
        Ok(runtime) => runtime,
        Err(error) => return protocol_error_response(error),
    };
    let recipient_set_digest = match router_recipient_set_digest_v1(env) {
        Ok(digest) => digest,
        Err(error) => return protocol_error_response(error),
    };
    let execute_request = match gateway_request.into_execute_request(
        recipient_set_digest,
        now_ms,
        now_ms.saturating_add(ROUTER_AUTHORITY_TTL_MS),
    ) {
        Ok(request) => request,
        Err(error) => return protocol_error_response(error),
    };
    let tenant_root = match resolve_ed25519_yao_tenant_root_context_v2(
        env,
        tenant_root,
        application,
        participant_ids,
        execute_request.pair_binding(),
        now_ms,
    )
    .await
    {
        Ok(context) => context,
        Err(error) => return protocol_error_response(error),
    };
    let operation = execute_request.operation();
    emit_span(
        trace_id,
        "router.parse_and_authorize",
        operation_label(operation),
        parse_started_at_ms,
        "success",
    );
    let started_at_ms = now_ms;
    let mut timing = RouterExecutionTimingV1::default();
    let result = execute_router_ceremony_v1(
        env,
        &runtime,
        execute_request,
        tenant_root,
        now_ms,
        trace_id,
        replay,
        &mut timing,
    )
    .await;
    emit_span(
        trace_id,
        "router.yao_execute",
        operation_label(operation),
        started_at_ms,
        if result.is_ok() { "success" } else { "failure" },
    );
    let response = match result {
        Ok(result) => Response::from_json(&result)?,
        Err(error) => protocol_error_response(error)?,
    };
    response
        .headers()
        .set("Server-Timing", &timing.server_timing())?;
    Ok(response)
}

/// Handles one authenticated source-preserving target registration.
pub async fn handle_cloudflare_router_ed25519_yao_source_preserving_execute_private_fetch_v1(
    mut request: Request,
    env: &Env,
) -> worker::Result<Response> {
    if request.method() != Method::Post {
        return Response::error(
            "Router source-preserving Yao execute route requires POST",
            405,
        );
    }
    if let Err(error) = require_cloudflare_internal_service_auth_request_v1(&request, env) {
        return crate::cloudflare_private_service_auth_error_response_v1(error);
    }
    let parse_started_at_ms = cloudflare_now_unix_ms_v1().unwrap_or_default();
    let trace_id = match parse_cloudflare_trace_id_from_request_v1(&request) {
        Ok(trace_id) => trace_id,
        Err(error) => return protocol_error_response(error),
    };
    let replay = match parse_router_replay_header(&request) {
        Ok(replay) => replay,
        Err(error) => return protocol_error_response(error),
    };
    let source_request = match request
        .json::<CloudflareRouterEd25519YaoSourcePreservingExecuteRequestV1>()
        .await
    {
        Ok(request) => request,
        Err(error) => {
            return protocol_error_response(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                format!("Router source-preserving Yao request JSON is malformed: {error}"),
            ))
        }
    };
    if let Err(error) = source_request.validate() {
        return protocol_error_response(error);
    }
    let source_binding = source_request.source_binding;
    let CloudflareRouterEd25519YaoExecuteRequestV2 {
        tenant_root,
        application,
        participant_ids,
        target,
    } = source_request.target;
    let target_operation = target.operation();
    let now_ms = match cloudflare_now_unix_ms_v1() {
        Ok(now_ms) => now_ms,
        Err(error) => return protocol_error_response(error),
    };
    let runtime = match CloudflareRouterWorkerRuntimeV1::from_worker_env(env) {
        Ok(runtime) => runtime,
        Err(error) => return protocol_error_response(error),
    };
    let recipient_set_digest = match router_recipient_set_digest_v1(env) {
        Ok(digest) => digest,
        Err(error) => return protocol_error_response(error),
    };
    let execute_request = match target.into_execute_request(
        recipient_set_digest,
        now_ms,
        now_ms.saturating_add(ROUTER_AUTHORITY_TTL_MS),
    ) {
        Ok(request) => request,
        Err(error) => return protocol_error_response(error),
    };
    let tenant_root = match resolve_ed25519_yao_tenant_root_context_v2(
        env,
        tenant_root,
        application,
        participant_ids,
        execute_request.pair_binding(),
        now_ms,
    )
    .await
    {
        Ok(context) => context,
        Err(error) => return protocol_error_response(error),
    };
    emit_span(
        trace_id,
        "router.parse_and_authorize",
        operation_label(target_operation),
        parse_started_at_ms,
        "success",
    );
    let started_at_ms = now_ms;
    let mut timing = RouterExecutionTimingV1::default();
    let result = execute_router_source_preserving_ceremony_v1(
        env,
        &runtime,
        execute_request,
        tenant_root,
        source_binding,
        participant_ids,
        now_ms,
        trace_id,
        replay,
        &mut timing,
    )
    .await;
    emit_span(
        trace_id,
        "router.yao_source_preserving_execute",
        operation_label(target_operation),
        started_at_ms,
        if result.is_ok() { "success" } else { "failure" },
    );
    let response = match result {
        Ok(result) => Response::from_json(&result)?,
        Err(error) => protocol_error_response(error)?,
    };
    response
        .headers()
        .set("Server-Timing", &timing.server_timing())?;
    Ok(response)
}

/// Executes one authenticated, already-admitted Ed25519 lane command.
pub async fn handle_cloudflare_router_ed25519_yao_lane_execute_private_fetch_v1(
    mut request: Request,
    env: &Env,
) -> worker::Result<Response> {
    if request.method() != Method::Post {
        return Response::error("Router Ed25519 lane execute route requires POST", 405);
    }
    if let Err(error) = require_cloudflare_internal_service_auth_request_v1(&request, env) {
        return crate::cloudflare_private_service_auth_error_response_v1(error);
    }
    let trace_id = match parse_cloudflare_trace_id_from_request_v1(&request) {
        Ok(trace_id) => trace_id,
        Err(error) => return protocol_error_response(error),
    };
    let lane_envelope = match request
        .json::<CloudflareRouterEd25519YaoLaneExecuteRequestV2>()
        .await
    {
        Ok(dispatch) => dispatch,
        Err(error) => {
            return protocol_error_response(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                format!("Router Ed25519 lane dispatch JSON is malformed: {error}"),
            ))
        }
    };
    if let Err(error) = lane_envelope.validate() {
        return protocol_error_response(error);
    }
    let CloudflareRouterEd25519YaoLaneExecuteRequestV2 {
        tenant_root,
        application,
        participant_ids,
        target: dispatch,
    } = lane_envelope;
    let now_ms = match cloudflare_now_unix_ms_v1() {
        Ok(now_ms) => now_ms,
        Err(error) => return protocol_error_response(error),
    };
    if dispatch.request.job.expires_at_ms <= now_ms {
        return protocol_error_response(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ExpiredLocalRequest,
            "Router Ed25519 lane job expired before execution",
        ));
    }
    let runtime = match CloudflareRouterWorkerRuntimeV1::from_worker_env(env) {
        Ok(runtime) => runtime,
        Err(error) => return protocol_error_response(error),
    };
    let recipient_set_digest = match router_recipient_set_digest_v1(env) {
        Ok(digest) => digest,
        Err(error) => return protocol_error_response(error),
    };
    let execute_request = match dispatch.into_router_execute_request(
        recipient_set_digest,
        now_ms,
        now_ms.saturating_add(ROUTER_AUTHORITY_TTL_MS),
    ) {
        Ok(request) => request,
        Err(error) => return protocol_error_response(error),
    };
    let tenant_root = match resolve_ed25519_yao_tenant_root_context_v2(
        env,
        tenant_root,
        application,
        participant_ids,
        execute_request.pair_binding(),
        now_ms,
    )
    .await
    {
        Ok(context) => context,
        Err(error) => return protocol_error_response(error),
    };
    let mut timing = RouterExecutionTimingV1::default();
    let execute_result = match execute_router_ceremony_v1(
        env,
        &runtime,
        execute_request,
        tenant_root,
        now_ms,
        trace_id,
        true,
        &mut timing,
    )
    .await
    {
        Ok(result) => result,
        Err(error) => return protocol_error_response(error),
    };
    let lane_result = match execute_result {
        RouterEd25519YaoExecuteResultV1::Succeeded { result } => match *result {
            RouterEd25519YaoExecuteSuccessV1::LaneProvisioning { result }
            | RouterEd25519YaoExecuteSuccessV1::LaneRefresh { result } => result,
            RouterEd25519YaoExecuteSuccessV1::Registration { .. }
            | RouterEd25519YaoExecuteSuccessV1::Recovery { .. }
            | RouterEd25519YaoExecuteSuccessV1::Export { .. } => {
                return protocol_error_response(invalid_coordinator(
                    "Router lane dispatch returned a ceremony result",
                ))
            }
        },
        RouterEd25519YaoExecuteResultV1::RecoverableFailure {
            code,
            retry_after_ms,
        } => {
            let message = format!(
                "Router lane dispatch ended with recoverable failure {code:?} after {retry_after_ms}ms",
            );
            return protocol_error_response(invalid_coordinator(&message));
        }
        RouterEd25519YaoExecuteResultV1::Rejected { code } => {
            return protocol_error_response(invalid_coordinator(&format!(
                "Router lane dispatch was rejected with {code:?}",
            )))
        }
        RouterEd25519YaoExecuteResultV1::Burned {
            execution_id: _,
            reason,
        } => {
            return protocol_error_response(invalid_coordinator(&format!(
                "Router lane dispatch burned the execution with {reason:?}",
            )))
        }
    };
    let receipt = match lane_protocol_commit_receipt_v1(&lane_result) {
        Ok(receipt) => receipt,
        Err(error) => return protocol_error_response(error),
    };
    match RouterAbEd25519YaoLaneDispatchResponseV1::new(lane_result, receipt) {
        Ok(response) => Response::from_json(&response),
        Err(error) => protocol_error_response(error),
    }
}

fn router_recipient_set_digest_v1(env: &Env) -> RouterAbProtocolResult<PublicDigest32> {
    let keyset = build_cloudflare_router_public_keyset_v2(&CloudflareWorkerEnvReaderV1::new(env))?;
    let deriver_a = crate::hpke::cloudflare_hpke_x25519_public_key_bytes_v1(
        &keyset.signer_envelope_hpke.current.deriver_a.public_key,
    )?;
    let deriver_b = crate::hpke::cloudflare_hpke_x25519_public_key_bytes_v1(
        &keyset.signer_envelope_hpke.current.deriver_b.public_key,
    )?;
    let signing_worker = crate::hpke::cloudflare_hpke_x25519_public_key_bytes_v1(
        &keyset.signing_worker_server_output_hpke.public_key,
    )?;
    ed25519_yao_recipient_set_digest_v1(deriver_a, deriver_b, signing_worker)
}

/// Handles explicit recovery promotion without exposing the SigningWorker to the Gateway.
pub async fn handle_cloudflare_router_ed25519_yao_recovery_promote_private_fetch_v1(
    mut request: Request,
    env: &Env,
) -> worker::Result<Response> {
    if request.method() != Method::Post {
        return Response::error("Router recovery promotion route requires POST", 405);
    }
    if let Err(error) = require_cloudflare_internal_service_auth_request_v1(&request, env) {
        return crate::cloudflare_private_service_auth_error_response_v1(error);
    }
    let trace_id = match parse_cloudflare_trace_id_from_request_v1(&request) {
        Ok(trace_id) => trace_id,
        Err(error) => return protocol_error_response(error),
    };
    let promotion = match request
        .json::<crate::CloudflareEd25519YaoRecoveryPromotionRequestV1>()
        .await
    {
        Ok(promotion) => promotion,
        Err(error) => {
            return protocol_error_response(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                format!("Router recovery promotion JSON is malformed: {error}"),
            ))
        }
    };
    if let Err(error) = promotion.validate() {
        return protocol_error_response(error);
    }
    let runtime = match CloudflareRouterWorkerRuntimeV1::from_worker_env(env) {
        Ok(runtime) => runtime,
        Err(error) => return protocol_error_response(error),
    };
    let result = post_role_json::<_, SigningWorkerReceiptV1>(
        env,
        runtime.signing_worker_peer().binding_name.as_str(),
        SIGNING_WORKER_SERVICE_URL,
        CLOUDFLARE_SIGNING_WORKER_ED25519_YAO_RECOVERY_PROMOTE_PATH,
        "SigningWorker recovery promotion",
        &promotion,
        trace_id,
    )
    .await;
    match result {
        Ok(receipt) => match receipt.validate_for_recovery_promotion() {
            Ok(()) => Response::from_json(&receipt),
            Err(error) => protocol_error_response(error),
        },
        Err(error) => protocol_error_response(error),
    }
}

async fn resolve_ed25519_yao_tenant_root_context_v2(
    env: &Env,
    coordinates: CloudflareTenantRootCoordinatesV1,
    application: RouterAbEd25519YaoApplicationBindingFactsV1,
    participant_ids: [u16; 2],
    pair_binding: &Ed25519YaoInputPairBindingV1,
    now_ms: u64,
) -> RouterAbProtocolResult<CloudflareEd25519YaoTenantRootContextV2> {
    let (identity_digest, custody_lineage) = coordinates.resolve()?;
    let activation_receipt =
        execute_cloudflare_router_tenant_root_creation_active_state_read_call_v1(
            env,
            identity_digest,
            custody_lineage,
        )
        .await?;
    let (custody_binding, outer_binding) = cloudflare_tenant_root_ed25519_yao_binding_v2(
        env,
        pair_binding,
        &activation_receipt,
        now_ms,
        now_ms.saturating_add(ROUTER_AUTHORITY_TTL_MS),
    )?;
    let context = CloudflareEd25519YaoTenantRootContextV2 {
        custody_binding,
        outer_binding,
        application,
        participant_ids,
    };
    context.validate_for_pair(pair_binding)?;
    Ok(context)
}

async fn execute_router_ceremony_v1(
    env: &Env,
    runtime: &CloudflareRouterWorkerRuntimeV1,
    request: RouterEd25519YaoExecuteRequestV1,
    tenant_root: CloudflareEd25519YaoTenantRootContextV2,
    now_ms: u64,
    trace_id: Option<crate::CloudflareTraceIdV1>,
    replay: bool,
    timing: &mut RouterExecutionTimingV1,
) -> RouterAbProtocolResult<RouterEd25519YaoExecuteResultV1> {
    let finalization = RouterCeremonyFinalizationV1::Standard;
    match execute_router_ceremony_with_finalization_v1(
        env,
        runtime,
        request,
        tenant_root,
        now_ms,
        trace_id,
        replay,
        &finalization,
        timing,
    )
    .await?
    {
        RouterCeremonyOutcomeV1::Standard(result) => Ok(result),
        RouterCeremonyOutcomeV1::SourcePreserving(_) => Err(invalid_coordinator(
            "standard Router ceremony returned a source-preserving result",
        )),
    }
}

async fn execute_router_source_preserving_ceremony_v1(
    env: &Env,
    runtime: &CloudflareRouterWorkerRuntimeV1,
    request: RouterEd25519YaoExecuteRequestV1,
    tenant_root: CloudflareEd25519YaoTenantRootContextV2,
    source_binding: Ed25519YaoCeremonyBindingV1,
    participant_ids: [u16; 2],
    now_ms: u64,
    trace_id: Option<crate::CloudflareTraceIdV1>,
    replay: bool,
    timing: &mut RouterExecutionTimingV1,
) -> RouterAbProtocolResult<CloudflareEd25519YaoInactiveReservationResponseV1> {
    let finalization = RouterCeremonyFinalizationV1::SourcePreserving {
        source_binding,
        participant_ids,
    };
    match execute_router_ceremony_with_finalization_v1(
        env,
        runtime,
        request,
        tenant_root,
        now_ms,
        trace_id,
        replay,
        &finalization,
        timing,
    )
    .await?
    {
        RouterCeremonyOutcomeV1::SourcePreserving(result) => Ok(result),
        RouterCeremonyOutcomeV1::Standard(_) => Err(invalid_coordinator(
            "source-preserving Router ceremony returned a standard result",
        )),
    }
}

async fn execute_router_ceremony_with_finalization_v1(
    env: &Env,
    runtime: &CloudflareRouterWorkerRuntimeV1,
    request: RouterEd25519YaoExecuteRequestV1,
    tenant_root: CloudflareEd25519YaoTenantRootContextV2,
    now_ms: u64,
    trace_id: Option<crate::CloudflareTraceIdV1>,
    replay: bool,
    finalization: &RouterCeremonyFinalizationV1,
    timing: &mut RouterExecutionTimingV1,
) -> RouterAbProtocolResult<RouterCeremonyOutcomeV1> {
    request.authority().validate_at(now_ms)?;
    request.pair_binding().validate()?;
    tenant_root.validate_for_pair(request.pair_binding())?;
    let (binding, input_a, input_b) = request_parts(&request);
    let project_policy =
        runtime.evaluate_project_policy_for_yao_work_kind_v1(binding.lifecycle.work_kind)?;
    if let CloudflareRouterProjectPolicyV1::Rejected { retry_after_ms } = project_policy {
        return Ok(RouterCeremonyOutcomeV1::Standard(
            RouterEd25519YaoExecuteResultV1::recoverable(
                router_ab_core::RouterEd25519YaoExecuteFailureCodeV1::AuthorizationRejected,
                retry_after_ms,
            )?,
        ));
    }
    let verifying_keys =
        parse_cloudflare_deriver_peer_verifying_key_set_v1(&CloudflareWorkerEnvReaderV1::new(env))?;
    let operation = request.operation();
    let pair_binding = request.pair_binding().clone();
    let work = pair_work(&request);

    if replay {
        if let Some(result) = reconcile_router_replay_v1(
            env,
            runtime,
            &request,
            &binding,
            &pair_binding,
            trace_id,
            finalization,
            timing,
        )
        .await?
        {
            return Ok(result);
        }
    }

    let prepare_started_at_ms = cloudflare_now_unix_ms_v1()?;
    let prepare_request_a = CloudflareEd25519YaoPairPrepareRequestV1 {
        pair_binding: pair_binding.clone(),
        tenant_root: tenant_root.clone(),
        work: work.clone(),
        input: input_a.clone(),
    };
    let prepare_request_b = CloudflareEd25519YaoPairPrepareRequestV1 {
        pair_binding: pair_binding.clone(),
        tenant_root: tenant_root.clone(),
        work: work.clone(),
        input: input_b,
    };
    let prepare_a = post_role_json_for_ceremony_with_span::<_, Ed25519YaoRoleReadinessReceiptV1>(
        env,
        runtime.deriver_a_peer().binding_name.as_str(),
        DERIVER_A_SERVICE_URL,
        CLOUDFLARE_DERIVER_A_ED25519_YAO_PREPARE_PAIR_PATH,
        "Deriver A pair preparation",
        &prepare_request_a,
        trace_id,
        "router.prepare_pair.deriver_a",
        operation_label(operation),
    );
    let prepare_b = post_role_json_for_ceremony_with_span::<_, Ed25519YaoRoleReadinessReceiptV1>(
        env,
        runtime.deriver_b_peer().binding_name.as_str(),
        DERIVER_B_SERVICE_URL,
        CLOUDFLARE_DERIVER_B_ED25519_YAO_PREPARE_PAIR_PATH,
        "Deriver B pair preparation",
        &prepare_request_b,
        trace_id,
        "router.prepare_pair.deriver_b",
        operation_label(operation),
    );
    let (receipt_a, receipt_b) = match futures::try_join!(prepare_a, prepare_b) {
        Ok(receipts) => receipts,
        Err(error) => {
            emit_span(
                trace_id,
                "router.prepare_pair",
                operation_label(operation),
                prepare_started_at_ms,
                "failure",
            );
            return resolve_role_call_error(error, &pair_binding)
                .map(RouterCeremonyOutcomeV1::Standard);
        }
    };
    emit_span(
        trace_id,
        "router.prepare_pair",
        operation_label(operation),
        prepare_started_at_ms,
        "success",
    );
    timing.prepare_pair_ms = cloudflare_now_unix_ms_v1()?.saturating_sub(prepare_started_at_ms);
    let readiness_now_ms = cloudflare_now_unix_ms_v1()?;
    let readiness_started_at_ms = cloudflare_now_unix_ms_v1()?;
    let readiness_result = validate_readiness(
        &receipt_a,
        &pair_binding,
        readiness_now_ms,
        Ed25519YaoDeriverRoleV1::DeriverA,
        &verifying_keys,
    )
    .and_then(|()| {
        validate_readiness(
            &receipt_b,
            &pair_binding,
            readiness_now_ms,
            Ed25519YaoDeriverRoleV1::DeriverB,
            &verifying_keys,
        )
    });
    emit_span(
        trace_id,
        "router.verify_readiness_receipts",
        operation_label(operation),
        readiness_started_at_ms,
        if readiness_result.is_ok() {
            "success"
        } else {
            "failure"
        },
    );
    timing.verify_readiness_ms =
        cloudflare_now_unix_ms_v1()?.saturating_sub(readiness_started_at_ms);
    readiness_result?;
    let execute_started_at_ms = cloudflare_now_unix_ms_v1()?;
    let execution = match post_role_json_for_ceremony_with_span::<
        _,
        CloudflareEd25519YaoPairExecuteResponseV1,
    >(
        env,
        runtime.deriver_a_peer().binding_name.as_str(),
        DERIVER_A_SERVICE_URL,
        CLOUDFLARE_DERIVER_A_ED25519_YAO_EXECUTE_PAIR_PATH,
        "Deriver A pair execution",
        &CloudflareEd25519YaoPairExecuteRequestV1 {
            pair_binding: pair_binding.clone(),
            tenant_root,
            work,
            input: input_a,
            local_receipt: receipt_a,
            peer_receipt: receipt_b,
        },
        trace_id,
        "router.deriver_a_execute.http",
        operation_label(operation),
    )
    .await
    {
        Ok(execution) => execution,
        Err(error) => {
            emit_span(
                trace_id,
                "router.deriver_a_execute",
                operation_label(operation),
                execute_started_at_ms,
                "failure",
            );
            return resolve_role_call_error(error, &pair_binding)
                .map(RouterCeremonyOutcomeV1::Standard);
        }
    };
    let execution_validation = match execution.deriver_a_execution.validate() {
        Ok(()) => validate_execution(
            &execution.deriver_a_execution,
            Ed25519YaoDeriverRoleV1::DeriverA,
            &binding,
            None,
        ),
        Err(error) => Err(error),
    };
    emit_span(
        trace_id,
        "router.deriver_a_execute",
        operation_label(operation),
        execute_started_at_ms,
        if execution_validation.is_ok() {
            "success"
        } else {
            "failure"
        },
    );
    timing.role_execution_ms = cloudflare_now_unix_ms_v1()?.saturating_sub(execute_started_at_ms);
    execution_validation?;

    let transcript = execution_transcript(&execution.deriver_a_execution);
    let completed_b = serde_json::from_str::<Ed25519YaoRoleExecutionV1>(
        &execution.deriver_b_sealed_execution_json,
    )
    .map_err(|_| invalid_coordinator("Deriver B sealed execution is malformed"))?;
    validate_execution(
        &completed_b,
        Ed25519YaoDeriverRoleV1::DeriverB,
        &binding,
        Some(transcript),
    )?;

    finalize_router_result_v1(
        env,
        runtime,
        &request,
        &binding,
        execution.deriver_a_execution,
        completed_b,
        trace_id,
        finalization,
        timing,
    )
    .await
}

async fn reconcile_router_replay_v1(
    env: &Env,
    runtime: &CloudflareRouterWorkerRuntimeV1,
    request: &RouterEd25519YaoExecuteRequestV1,
    binding: &router_ab_core::Ed25519YaoCeremonyBindingV1,
    pair_binding: &Ed25519YaoInputPairBindingV1,
    trace_id: Option<crate::CloudflareTraceIdV1>,
    finalization: &RouterCeremonyFinalizationV1,
    timing: &mut RouterExecutionTimingV1,
) -> RouterAbProtocolResult<Option<RouterCeremonyOutcomeV1>> {
    let reconciliation_started_at_ms = cloudflare_now_unix_ms_v1()?;
    let statuses = futures::try_join!(
        read_pair_status_v1(
            env,
            runtime.deriver_a_peer().binding_name.as_str(),
            DERIVER_A_SERVICE_URL,
            CLOUDFLARE_DERIVER_A_ED25519_YAO_READ_PAIR_STATUS_PATH,
            "Deriver A pair status",
            pair_binding,
            trace_id,
        ),
        read_pair_status_v1(
            env,
            runtime.deriver_b_peer().binding_name.as_str(),
            DERIVER_B_SERVICE_URL,
            CLOUDFLARE_DERIVER_B_ED25519_YAO_READ_PAIR_STATUS_PATH,
            "Deriver B pair status",
            pair_binding,
            trace_id,
        )
    );
    let (status_a, status_b) = match statuses {
        Ok(statuses) => {
            emit_span(
                trace_id,
                "router.role_status_reconciliation",
                operation_label(request.operation()),
                reconciliation_started_at_ms,
                "success",
            );
            statuses
        }
        Err(error) => {
            emit_span(
                trace_id,
                "router.role_status_reconciliation",
                operation_label(request.operation()),
                reconciliation_started_at_ms,
                "failure",
            );
            return Err(error);
        }
    };
    if pair_status_is_completed(&status_a) && pair_status_is_completed(&status_b) {
        let execution_a = completed_execution(&status_a)?;
        let execution_b = completed_execution(&status_b)?;
        execution_a.validate()?;
        execution_b.validate()?;
        validate_execution(
            &execution_a,
            Ed25519YaoDeriverRoleV1::DeriverA,
            binding,
            None,
        )?;
        let transcript = execution_transcript(&execution_a);
        validate_execution(
            &execution_b,
            Ed25519YaoDeriverRoleV1::DeriverB,
            binding,
            Some(transcript),
        )?;
        return finalize_router_result_v1(
            env,
            runtime,
            request,
            binding,
            execution_a,
            execution_b,
            trace_id,
            finalization,
            timing,
        )
        .await
        .map(Some);
    }

    if pair_status_is_running(&status_a)
        || pair_status_is_running(&status_b)
        || pair_status_is_completed(&status_a)
        || pair_status_is_completed(&status_b)
    {
        let _ = burn_pair_v1(
            env,
            runtime.deriver_a_peer().binding_name.as_str(),
            DERIVER_A_SERVICE_URL,
            CLOUDFLARE_DERIVER_A_ED25519_YAO_BURN_PAIR_PATH,
            "Deriver A pair burn",
            pair_binding,
            trace_id,
        )
        .await;
        let _ = burn_pair_v1(
            env,
            runtime.deriver_b_peer().binding_name.as_str(),
            DERIVER_B_SERVICE_URL,
            CLOUDFLARE_DERIVER_B_ED25519_YAO_BURN_PAIR_PATH,
            "Deriver B pair burn",
            pair_binding,
            trace_id,
        )
        .await;
        let execution_id = router_execution_id(pair_binding)?;
        return Ok(Some(RouterCeremonyOutcomeV1::Standard(
            RouterEd25519YaoExecuteResultV1::burned(
                execution_id,
                router_ab_core::RouterEd25519YaoBurnReasonV1::PeerUncertain,
            ),
        )));
    }

    if pair_status_is_burned(&status_a) || pair_status_is_burned(&status_b) {
        let execution_id = router_execution_id(pair_binding)?;
        return Ok(Some(RouterCeremonyOutcomeV1::Standard(
            RouterEd25519YaoExecuteResultV1::burned(
                execution_id,
                router_ab_core::RouterEd25519YaoBurnReasonV1::PeerUncertain,
            ),
        )));
    }

    if pair_status_is_expired(&status_a) || pair_status_is_expired(&status_b) {
        return Ok(Some(RouterCeremonyOutcomeV1::Standard(
            RouterEd25519YaoExecuteResultV1::recoverable(
                router_ab_core::RouterEd25519YaoExecuteFailureCodeV1::CeremonyExpired,
                1_000,
            )?,
        )));
    }

    Ok(None)
}

fn completed_execution(
    status: &CloudflareEd25519YaoPairStatusResponseV1,
) -> RouterAbProtocolResult<Ed25519YaoRoleExecutionV1> {
    match status {
        CloudflareEd25519YaoPairStatusResponseV1::Completed { execution } => {
            Ok((**execution).clone())
        }
        _ => Err(invalid_coordinator(
            "completed pair status is missing execution",
        )),
    }
}

fn router_execution_id(
    pair_binding: &Ed25519YaoInputPairBindingV1,
) -> RouterAbProtocolResult<router_ab_core::Ed25519YaoExecutionIdV1> {
    router_ab_core::Ed25519YaoExecutionIdV1::new(pair_binding.pair_digest().bytes)
}

async fn read_pair_status_v1(
    env: &Env,
    binding_name: &str,
    service_origin: &str,
    path: &str,
    label: &str,
    pair_binding: &Ed25519YaoInputPairBindingV1,
    trace_id: Option<crate::CloudflareTraceIdV1>,
) -> RouterAbProtocolResult<CloudflareEd25519YaoPairStatusResponseV1> {
    post_role_json::<_, CloudflareEd25519YaoPairStatusResponseV1>(
        env,
        binding_name,
        service_origin,
        path,
        label,
        &CloudflareEd25519YaoPairLookupRequestV1 {
            session: pair_binding.session(),
            pair_digest: pair_binding.pair_digest().bytes,
        },
        trace_id,
    )
    .await
}

async fn burn_pair_v1(
    env: &Env,
    binding_name: &str,
    service_origin: &str,
    path: &str,
    label: &str,
    pair_binding: &Ed25519YaoInputPairBindingV1,
    trace_id: Option<crate::CloudflareTraceIdV1>,
) -> RouterAbProtocolResult<CloudflareEd25519YaoPairStatusResponseV1> {
    post_role_json::<_, CloudflareEd25519YaoPairStatusResponseV1>(
        env,
        binding_name,
        service_origin,
        path,
        label,
        &CloudflareEd25519YaoPairLookupRequestV1 {
            session: pair_binding.session(),
            pair_digest: pair_binding.pair_digest().bytes,
        },
        trace_id,
    )
    .await
}

async fn finalize_router_result_v1(
    env: &Env,
    runtime: &CloudflareRouterWorkerRuntimeV1,
    request: &RouterEd25519YaoExecuteRequestV1,
    binding: &router_ab_core::Ed25519YaoCeremonyBindingV1,
    execution: Ed25519YaoRoleExecutionV1,
    completed_b: Ed25519YaoRoleExecutionV1,
    trace_id: Option<crate::CloudflareTraceIdV1>,
    finalization: &RouterCeremonyFinalizationV1,
    timing: &mut RouterExecutionTimingV1,
) -> RouterAbProtocolResult<RouterCeremonyOutcomeV1> {
    let operation = request.operation();
    let success = match operation {
        Ed25519YaoOperationV1::Registration | Ed25519YaoOperationV1::Recovery => {
            let activation_a = activation_execution(&execution)?;
            let activation_b = activation_execution(&completed_b)?;
            let delivery = CloudflareEd25519YaoPackagePairDeliveryV1 {
                deriver_a: signing_worker_delivery(activation_a),
                deriver_b: signing_worker_delivery(activation_b),
            };
            match finalization {
                RouterCeremonyFinalizationV1::Standard => {
                    let delivery_started_at_ms = cloudflare_now_unix_ms_v1()?;
                    let worker_response = post_role_json::<_, SigningWorkerReceiptV1>(
                        env,
                        runtime.signing_worker_peer().binding_name.as_str(),
                        SIGNING_WORKER_SERVICE_URL,
                        CLOUDFLARE_SIGNING_WORKER_ED25519_YAO_PACKAGES_PATH,
                        "SigningWorker Yao package delivery",
                        &delivery,
                        trace_id,
                    )
                    .await;
                    let worker_response = match worker_response {
                        Ok(receipt) => {
                            timing.signing_worker_delivery_ms =
                                cloudflare_now_unix_ms_v1()?.saturating_sub(delivery_started_at_ms);
                            emit_span(
                                trace_id,
                                "router.signing_worker_delivery",
                                operation_label(operation),
                                delivery_started_at_ms,
                                "success",
                            );
                            receipt
                        }
                        Err(error) => {
                            timing.signing_worker_delivery_ms =
                                cloudflare_now_unix_ms_v1()?.saturating_sub(delivery_started_at_ms);
                            emit_span(
                                trace_id,
                                "router.signing_worker_delivery",
                                operation_label(operation),
                                delivery_started_at_ms,
                                "failure",
                            );
                            return Err(error);
                        }
                    };
                    worker_response.validate_for_operation(operation)?;
                    let public_receipt = worker_response
                        .into_public_receipt(binding.material_activation().clone())?;
                    let result = RouterAbEd25519YaoActivationResultV1::new(
                        binding.clone(),
                        activation_a.client_package.clone(),
                        activation_b.client_package.clone(),
                        public_receipt,
                    )?;
                    let success = match operation {
                        Ed25519YaoOperationV1::Registration => {
                            RouterEd25519YaoExecuteSuccessV1::registration(result)?
                        }
                        Ed25519YaoOperationV1::Recovery => {
                            RouterEd25519YaoExecuteSuccessV1::recovery(result)?
                        }
                        Ed25519YaoOperationV1::Export | Ed25519YaoOperationV1::Refresh => {
                            unreachable!("activation branch excludes this operation")
                        }
                        Ed25519YaoOperationV1::LaneProvisioning
                        | Ed25519YaoOperationV1::LaneRefresh => {
                            unreachable!("activation branch excludes lane operations")
                        }
                    };
                    RouterCeremonyOutcomeV1::Standard(RouterEd25519YaoExecuteResultV1::succeeded(
                        success,
                    ))
                }
                RouterCeremonyFinalizationV1::SourcePreserving {
                    source_binding,
                    participant_ids,
                } => {
                    if operation != Ed25519YaoOperationV1::Registration {
                        return Err(invalid_coordinator(
                            "source-preserving finalization requires registration",
                        ));
                    }
                    validate_source_target_identity_v1(source_binding, binding)?;
                    let delivery_started_at_ms = cloudflare_now_unix_ms_v1()?;
                    let reservation = post_role_json::<
                        _,
                        CloudflareEd25519YaoInactiveReservationResponseV1,
                    >(
                        env,
                        runtime.signing_worker_peer().binding_name.as_str(),
                        SIGNING_WORKER_SERVICE_URL,
                        CLOUDFLARE_SIGNING_WORKER_ED25519_YAO_RESERVE_INACTIVE_SOURCE_PRESERVING_PATH,
                        "SigningWorker source-preserving Yao reservation",
                        &CloudflareEd25519YaoSourcePreservingInactiveReservationRequestV1 {
                            source_binding: source_binding.clone(),
                            delivery,
                            participant_ids: *participant_ids,
                            deriver_a_client_package: activation_a.client_package.clone(),
                            deriver_b_client_package: activation_b.client_package.clone(),
                        },
                        trace_id,
                    )
                    .await;
                    let reservation = match reservation {
                        Ok(reservation) => reservation,
                        Err(error) => {
                            timing.signing_worker_delivery_ms =
                                cloudflare_now_unix_ms_v1()?.saturating_sub(delivery_started_at_ms);
                            emit_span(
                                trace_id,
                                "router.signing_worker_source_preserving_reservation",
                                operation_label(operation),
                                delivery_started_at_ms,
                                "failure",
                            );
                            return Err(error);
                        }
                    };
                    timing.signing_worker_delivery_ms =
                        cloudflare_now_unix_ms_v1()?.saturating_sub(delivery_started_at_ms);
                    emit_span(
                        trace_id,
                        "router.signing_worker_source_preserving_reservation",
                        operation_label(operation),
                        delivery_started_at_ms,
                        "success",
                    );
                    validate_source_preserving_reservation_response_v1(
                        &reservation,
                        binding,
                        *participant_ids,
                        &activation_a.client_package,
                        &activation_b.client_package,
                    )?;
                    RouterCeremonyOutcomeV1::SourcePreserving(reservation)
                }
            }
        }
        Ed25519YaoOperationV1::Export => {
            let export_binding = match request {
                RouterEd25519YaoExecuteRequestV1::Export { binding, .. } => binding.clone(),
                _ => unreachable!("export operation must carry export binding"),
            };
            let export_a = export_execution(&execution)?;
            let export_b = export_execution(&completed_b)?;
            let result = RouterAbEd25519YaoExportResultV1::new(
                export_binding,
                execution_transcript(&execution),
                export_a.client_package.clone(),
                export_b.client_package.clone(),
            )?;
            RouterCeremonyOutcomeV1::Standard(RouterEd25519YaoExecuteResultV1::succeeded(
                RouterEd25519YaoExecuteSuccessV1::export(result)?,
            ))
        }
        Ed25519YaoOperationV1::Refresh => {
            return Err(invalid_coordinator(
                "Refresh is not an admitted Ed25519 Yao operation",
            ))
        }
        Ed25519YaoOperationV1::LaneProvisioning | Ed25519YaoOperationV1::LaneRefresh => {
            let expected_job = match request {
                RouterEd25519YaoExecuteRequestV1::LaneProvisioning { job, .. }
                | RouterEd25519YaoExecuteRequestV1::LaneRefresh { job, .. } => job,
                _ => {
                    return Err(invalid_coordinator(
                        "lane operation is missing its admitted job",
                    ))
                }
            };
            let result = commit_ed25519_yao_lane_result_v1(
                lane_execution(&execution)?.clone(),
                lane_execution(&completed_b)?.clone(),
                cloudflare_now_unix_ms_v1()?,
            )?;
            if &result.job != expected_job {
                return Err(invalid_coordinator(
                    "lane role execution does not match the admitted job",
                ));
            }
            let receipt = lane_protocol_commit_receipt_v1(&result)?;
            commit_lane_material_to_signing_worker_v1(env, runtime, &result, &receipt, trace_id)
                .await?;
            match operation {
                Ed25519YaoOperationV1::LaneProvisioning => {
                    RouterCeremonyOutcomeV1::Standard(RouterEd25519YaoExecuteResultV1::succeeded(
                        RouterEd25519YaoExecuteSuccessV1::lane_provisioning(result)?,
                    ))
                }
                Ed25519YaoOperationV1::LaneRefresh => {
                    RouterCeremonyOutcomeV1::Standard(RouterEd25519YaoExecuteResultV1::succeeded(
                        RouterEd25519YaoExecuteSuccessV1::lane_refresh(result)?,
                    ))
                }
                Ed25519YaoOperationV1::Registration
                | Ed25519YaoOperationV1::Recovery
                | Ed25519YaoOperationV1::Refresh
                | Ed25519YaoOperationV1::Export => {
                    unreachable!("lane branch excludes ceremony operations")
                }
            }
        }
    };
    Ok(success)
}

async fn commit_lane_material_to_signing_worker_v1(
    env: &Env,
    runtime: &CloudflareRouterWorkerRuntimeV1,
    result: &router_ab_core::RouterAbEd25519YaoLaneResultV1,
    receipt: &router_ab_core::Ed25519YaoLaneProtocolCommittedV1,
    trace_id: Option<crate::CloudflareTraceIdV1>,
) -> RouterAbProtocolResult<()> {
    use crate::{
        CloudflareSigningWorkerLaneArtifactKindV1, CloudflareSigningWorkerLaneArtifactV1,
        CloudflareSigningWorkerLaneCommittedArtifactsV1, CloudflareSigningWorkerLaneKeyFamilyV1,
        CloudflareSigningWorkerLaneMaterialCommandV1, CloudflareSigningWorkerLaneMaterialEffectV1,
        CloudflareSigningWorkerLaneMaterialIdentityV1,
    };

    let holder_package = CloudflareSigningWorkerLaneArtifactV1::from_bytes(
        CloudflareSigningWorkerLaneArtifactKindV1::HolderPackage,
        &serde_json::to_vec(&(
            &result.deriver_a_holder_package,
            &result.deriver_b_holder_package,
        ))
        .map_err(|_| invalid_coordinator("lane holder package set could not be serialized"))?,
    )?;
    let signing_worker_package = CloudflareSigningWorkerLaneArtifactV1::from_bytes(
        CloudflareSigningWorkerLaneArtifactKindV1::SigningWorkerPackage,
        &serde_json::to_vec(&(
            &result.deriver_a_signing_worker_package,
            &result.deriver_b_signing_worker_package,
        ))
        .map_err(|_| {
            invalid_coordinator("lane SigningWorker package set could not be serialized")
        })?,
    )?;
    let protocol_commit_receipt = CloudflareSigningWorkerLaneArtifactV1::from_bytes(
        CloudflareSigningWorkerLaneArtifactKindV1::ProtocolCommitReceipt,
        &serde_json::to_vec(receipt)
            .map_err(|_| invalid_coordinator("lane protocol receipt could not be serialized"))?,
    )?;
    let transcript = CloudflareSigningWorkerLaneArtifactV1::from_bytes(
        CloudflareSigningWorkerLaneArtifactKindV1::Transcript,
        result.transcript_hash_b64u.as_bytes(),
    )?;
    let identity = CloudflareSigningWorkerLaneMaterialIdentityV1 {
        operation_id: result.job.operation_id.clone(),
        enrollment_id: result.job.enrollment_id.clone(),
        wallet_id: result.job.wallet_id.clone(),
        wallet_key_id: result.job.wallet_key_id.clone(),
        target_lane_id: result.job.target_lane_id().to_owned(),
        target_lane_share_epoch: result.job.target_lane_share_epoch().to_owned(),
        target_material_activation_id: result.job.target_material_activation_id.clone(),
        key_family: CloudflareSigningWorkerLaneKeyFamilyV1::Ed25519,
        holder_participant_binding_digest_b64u: result
            .job
            .target_holder
            .participant_binding_digest_b64u
            .clone(),
        signing_worker_participant_binding_digest_b64u: result
            .job
            .target_signing_worker
            .participant_binding_digest_b64u
            .clone(),
        holder_recipient_key_digest_b64u: result.holder_recipient_key_digest_b64u.clone(),
        server_recipient_key_digest_b64u: result.server_recipient_key_digest_b64u.clone(),
        transcript_hash_b64u: result.transcript_hash_b64u.clone(),
        protocol_commit_receipt_digest_b64u: encode_base64url_bytes_v1(&receipt.digest_v1()?),
    };
    let expected_identity_digest = identity.digest_b64u()?;
    let expected_receipt = protocol_commit_receipt.clone();
    let command = CloudflareSigningWorkerLaneMaterialCommandV1::Commit {
        identity,
        committed_artifacts: CloudflareSigningWorkerLaneCommittedArtifactsV1::Ed25519Yao {
            holder_package,
            signing_worker_package,
            protocol_commit_receipt,
            transcript,
        },
        committed_at_ms: result.committed_at_ms,
    };
    let effect = post_role_json::<_, CloudflareSigningWorkerLaneMaterialEffectV1>(
        env,
        runtime.signing_worker_peer().binding_name.as_str(),
        SIGNING_WORKER_SERVICE_URL,
        CLOUDFLARE_SIGNING_WORKER_LANE_MATERIAL_COMMAND_PATH,
        "SigningWorker lane-material commitment",
        &command,
        trace_id,
    )
    .await?;
    match effect {
        CloudflareSigningWorkerLaneMaterialEffectV1::ProtocolCommitted {
            identity_digest_b64u,
            receipt,
            ..
        } if identity_digest_b64u == expected_identity_digest && receipt == expected_receipt => {
            Ok(())
        }
        CloudflareSigningWorkerLaneMaterialEffectV1::ProtocolCommitted { .. }
        | CloudflareSigningWorkerLaneMaterialEffectV1::HolderDeliveryRecorded { .. }
        | CloudflareSigningWorkerLaneMaterialEffectV1::ServerMaterialActivated { .. }
        | CloudflareSigningWorkerLaneMaterialEffectV1::Retired { .. } => Err(invalid_coordinator(
            "SigningWorker lane-material commitment effect does not match the submitted receipt",
        )),
    }
}

fn validate_source_target_identity_v1(
    source: &Ed25519YaoCeremonyBindingV1,
    target: &Ed25519YaoCeremonyBindingV1,
) -> RouterAbProtocolResult<()> {
    source.validate()?;
    target.validate()?;
    if source.operation != Ed25519YaoOperationV1::Registration
        || target.operation != Ed25519YaoOperationV1::Registration
        || source.material_activation == target.material_activation
        || source.material_activation.kind != target.material_activation.kind
        || source.material_activation.capability != target.material_activation.capability
        || source.material_activation.material_owner != target.material_activation.material_owner
        || source.material_activation.key_binding != target.material_activation.key_binding
        || source.material_activation.lifecycle_binding
            != target.material_activation.lifecycle_binding
        || source.material_activation.signing_worker != target.material_activation.signing_worker
        || source.stable_key_context_binding != target.stable_key_context_binding
        || source.lifecycle.root_share_epoch != target.lifecycle.root_share_epoch
        || source.lifecycle.account_id != target.lifecycle.account_id
        || source.lifecycle.signer_set_id != target.lifecycle.signer_set_id
        || source.lifecycle.selected_server_id != target.lifecycle.selected_server_id
    {
        return Err(invalid_coordinator(
            "source-preserving Router execution changed the stable signing identity",
        ));
    }
    Ok(())
}

fn validate_source_preserving_participant_ids_v1(
    participant_ids: [u16; 2],
) -> RouterAbProtocolResult<()> {
    if participant_ids[0] == 0
        || participant_ids[1] == 0
        || participant_ids[0] >= participant_ids[1]
    {
        return Err(invalid_coordinator(
            "source-preserving Router participant ids must be distinct, nonzero, ascending values",
        ));
    }
    Ok(())
}

fn validate_source_preserving_reservation_response_v1(
    response: &CloudflareEd25519YaoInactiveReservationResponseV1,
    target_binding: &Ed25519YaoCeremonyBindingV1,
    participant_ids: [u16; 2],
    deriver_a_client_package: &router_ab_core::Ed25519YaoEncryptedPackageV1,
    deriver_b_client_package: &router_ab_core::Ed25519YaoEncryptedPackageV1,
) -> RouterAbProtocolResult<()> {
    if response.state != "inactive"
        || response.reservation_id.is_empty()
        || response
            .reservation_id
            .chars()
            .any(|character| character.is_ascii_control())
        || response.participant_ids != participant_ids
        || response.deriver_a_client_package != *deriver_a_client_package
        || response.deriver_b_client_package != *deriver_b_client_package
        || response.activation_receipt.material_activation() != target_binding.material_activation()
        || response.activation_receipt.transcript() != deriver_a_client_package.transcript()
        || response.activation_receipt.transcript() != deriver_b_client_package.transcript()
    {
        return Err(invalid_coordinator(
            "source-preserving SigningWorker reservation response does not match the target",
        ));
    }
    validate_activation_client_package_v1(
        deriver_a_client_package,
        target_binding,
        Ed25519YaoDeriverRoleV1::DeriverA,
    )?;
    validate_activation_client_package_v1(
        deriver_b_client_package,
        target_binding,
        Ed25519YaoDeriverRoleV1::DeriverB,
    )
}

fn validate_activation_client_package_v1(
    package: &router_ab_core::Ed25519YaoEncryptedPackageV1,
    target_binding: &Ed25519YaoCeremonyBindingV1,
    deriver: Ed25519YaoDeriverRoleV1,
) -> RouterAbProtocolResult<()> {
    package.validate()?;
    if package.kind() != Ed25519YaoPackageKindV1::ActivationClient
        || package.deriver() != deriver
        || package.session() != target_binding.session_id.into_bytes()
        || package.transcript() == [0; 32]
    {
        return Err(invalid_coordinator(
            "source-preserving client package does not match the target binding",
        ));
    }
    Ok(())
}

fn pair_status_is_completed(status: &CloudflareEd25519YaoPairStatusResponseV1) -> bool {
    matches!(
        status,
        CloudflareEd25519YaoPairStatusResponseV1::Completed { .. }
    )
}

fn pair_status_is_running(status: &CloudflareEd25519YaoPairStatusResponseV1) -> bool {
    matches!(
        status,
        CloudflareEd25519YaoPairStatusResponseV1::Running { .. }
    )
}

fn pair_status_is_burned(status: &CloudflareEd25519YaoPairStatusResponseV1) -> bool {
    matches!(
        status,
        CloudflareEd25519YaoPairStatusResponseV1::Burned { .. }
    )
}

fn pair_status_is_expired(status: &CloudflareEd25519YaoPairStatusResponseV1) -> bool {
    matches!(
        status,
        CloudflareEd25519YaoPairStatusResponseV1::Expired { .. }
    )
}

fn request_parts(
    request: &RouterEd25519YaoExecuteRequestV1,
) -> (
    router_ab_core::Ed25519YaoCeremonyBindingV1,
    router_ab_core::Ed25519YaoEncryptedInputV1,
    router_ab_core::Ed25519YaoEncryptedInputV1,
) {
    match request {
        RouterEd25519YaoExecuteRequestV1::Registration {
            binding,
            deriver_a_input,
            deriver_b_input,
            ..
        }
        | RouterEd25519YaoExecuteRequestV1::Recovery {
            binding,
            deriver_a_input,
            deriver_b_input,
            ..
        } => (
            binding.clone(),
            deriver_a_input.clone(),
            deriver_b_input.clone(),
        ),
        RouterEd25519YaoExecuteRequestV1::Export {
            binding,
            deriver_a_input,
            deriver_b_input,
            ..
        } => (
            binding.ceremony().clone(),
            deriver_a_input.clone(),
            deriver_b_input.clone(),
        ),
        RouterEd25519YaoExecuteRequestV1::LaneProvisioning {
            binding,
            deriver_a_input,
            deriver_b_input,
            ..
        }
        | RouterEd25519YaoExecuteRequestV1::LaneRefresh {
            binding,
            deriver_a_input,
            deriver_b_input,
            ..
        } => (
            binding.clone(),
            deriver_a_input.clone(),
            deriver_b_input.clone(),
        ),
    }
}

fn pair_work(request: &RouterEd25519YaoExecuteRequestV1) -> crate::CloudflareEd25519YaoPairWorkV1 {
    match request {
        RouterEd25519YaoExecuteRequestV1::Registration { .. }
        | RouterEd25519YaoExecuteRequestV1::Recovery { .. }
        | RouterEd25519YaoExecuteRequestV1::Export { .. } => {
            crate::CloudflareEd25519YaoPairWorkV1::Ceremony
        }
        RouterEd25519YaoExecuteRequestV1::LaneProvisioning { job, .. }
        | RouterEd25519YaoExecuteRequestV1::LaneRefresh { job, .. } => {
            crate::CloudflareEd25519YaoPairWorkV1::Lane { job: job.clone() }
        }
    }
}

fn validate_readiness(
    receipt: &Ed25519YaoRoleReadinessReceiptV1,
    pair_binding: &Ed25519YaoInputPairBindingV1,
    now_ms: u64,
    role: Ed25519YaoDeriverRoleV1,
    verifying_keys: &crate::CloudflareSignerPeerVerifyingKeySetV1,
) -> RouterAbProtocolResult<()> {
    if receipt.role() != role {
        return Err(invalid_coordinator("readiness receipt role mismatch"));
    }
    receipt.validate_for_pair(pair_binding)?;
    crate::ed25519_yao_lifecycle::validate_cloudflare_role_readiness_receipt_v1(receipt, now_ms)?;
    crate::verify_role_readiness_receipt_v1(receipt, verifying_keys)
}

fn validate_execution(
    execution: &Ed25519YaoRoleExecutionV1,
    role: Ed25519YaoDeriverRoleV1,
    binding: &router_ab_core::Ed25519YaoCeremonyBindingV1,
    transcript: Option<[u8; 32]>,
) -> RouterAbProtocolResult<()> {
    let binding_matches = match execution {
        Ed25519YaoRoleExecutionV1::Activation(value) => &value.binding == binding,
        Ed25519YaoRoleExecutionV1::Export(value) => &value.binding == binding,
        Ed25519YaoRoleExecutionV1::Lane(value) => {
            value.job.yao_request_kind.operation() == binding.operation
                && value.session == binding.session_id.into_bytes()
                && value
                    .job
                    .stable_context_binding_v1()
                    .is_ok_and(|stable| stable == binding.stable_key_context_binding.into_bytes())
                && value.job.source.material_activation == *binding.material_activation()
        }
    };
    if execution.deriver() != role || !binding_matches {
        return Err(invalid_coordinator("role execution binding mismatch"));
    }
    if let Some(transcript) = transcript {
        if execution_transcript(execution) != transcript {
            return Err(invalid_coordinator("role execution transcript mismatch"));
        }
    }
    Ok(())
}

fn execution_transcript(execution: &Ed25519YaoRoleExecutionV1) -> [u8; 32] {
    match execution {
        Ed25519YaoRoleExecutionV1::Activation(value) => value.transcript,
        Ed25519YaoRoleExecutionV1::Export(value) => value.transcript,
        Ed25519YaoRoleExecutionV1::Lane(value) => value.transcript,
    }
}

fn activation_execution(
    execution: &Ed25519YaoRoleExecutionV1,
) -> RouterAbProtocolResult<&Ed25519YaoActivationRoleExecutionV1> {
    match execution {
        Ed25519YaoRoleExecutionV1::Activation(value) => Ok(value),
        Ed25519YaoRoleExecutionV1::Export(_) => Err(invalid_coordinator(
            "activation operation returned an export role execution",
        )),
        Ed25519YaoRoleExecutionV1::Lane(_) => Err(invalid_coordinator(
            "activation operation returned a lane role execution",
        )),
    }
}

fn export_execution(
    execution: &Ed25519YaoRoleExecutionV1,
) -> RouterAbProtocolResult<&Ed25519YaoExportRoleExecutionV1> {
    match execution {
        Ed25519YaoRoleExecutionV1::Export(value) => Ok(value),
        Ed25519YaoRoleExecutionV1::Activation(_) => Err(invalid_coordinator(
            "export operation returned an activation role execution",
        )),
        Ed25519YaoRoleExecutionV1::Lane(_) => Err(invalid_coordinator(
            "export operation returned a lane role execution",
        )),
    }
}

fn lane_execution(
    execution: &Ed25519YaoRoleExecutionV1,
) -> RouterAbProtocolResult<&Ed25519YaoLaneRoleExecutionV1> {
    match execution {
        Ed25519YaoRoleExecutionV1::Lane(value) => Ok(value),
        Ed25519YaoRoleExecutionV1::Activation(_) => Err(invalid_coordinator(
            "lane operation returned an activation role execution",
        )),
        Ed25519YaoRoleExecutionV1::Export(_) => Err(invalid_coordinator(
            "lane operation returned an export role execution",
        )),
    }
}

fn signing_worker_delivery(
    execution: &Ed25519YaoActivationRoleExecutionV1,
) -> Ed25519YaoSigningWorkerPackageDeliveryV1 {
    Ed25519YaoSigningWorkerPackageDeliveryV1 {
        binding: execution.binding.clone(),
        client_commitment: execution.client_commitment,
        signing_worker_commitment: execution.signing_worker_commitment,
        package: execution.signing_worker_package.clone(),
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
enum SigningWorkerReceiptV1 {
    Active {
        session: [u8; 32],
        transcript: [u8; 32],
        registered_public_key: [u8; 32],
        joined_client_commitment: [u8; 32],
        joined_signing_worker_commitment: [u8; 32],
        signing_worker_verifying_share: [u8; 32],
        state_epoch: router_ab_core::Ed25519YaoStateEpochV1,
    },
    Staged {
        session: [u8; 32],
        transcript: [u8; 32],
        registered_public_key: [u8; 32],
        joined_client_commitment: [u8; 32],
        joined_signing_worker_commitment: [u8; 32],
        signing_worker_verifying_share: [u8; 32],
        state_epoch: router_ab_core::Ed25519YaoStateEpochV1,
    },
}

impl SigningWorkerReceiptV1 {
    fn validate(&self) -> RouterAbProtocolResult<()> {
        let (session, transcript, public_key, client, worker, verifying) = match self {
            Self::Active {
                session,
                transcript,
                registered_public_key,
                joined_client_commitment,
                joined_signing_worker_commitment,
                signing_worker_verifying_share,
                ..
            }
            | Self::Staged {
                session,
                transcript,
                registered_public_key,
                joined_client_commitment,
                joined_signing_worker_commitment,
                signing_worker_verifying_share,
                ..
            } => (
                session,
                transcript,
                registered_public_key,
                joined_client_commitment,
                joined_signing_worker_commitment,
                signing_worker_verifying_share,
            ),
        };
        if [session, transcript, public_key, client, worker, verifying]
            .iter()
            .any(|value| value.iter().all(|byte| *byte == 0))
        {
            return Err(invalid_coordinator(
                "SigningWorker receipt contains a zero field",
            ));
        }
        Ok(())
    }

    fn validate_for_operation(
        &self,
        operation: Ed25519YaoOperationV1,
    ) -> RouterAbProtocolResult<()> {
        self.validate()?;
        match (operation, self) {
            (Ed25519YaoOperationV1::Registration, Self::Active { .. })
            | (Ed25519YaoOperationV1::Recovery, Self::Staged { .. }) => Ok(()),
            (Ed25519YaoOperationV1::Registration, Self::Staged { .. }) => Err(invalid_coordinator(
                "registration requires an Active SigningWorker receipt",
            )),
            (Ed25519YaoOperationV1::Recovery, Self::Active { .. }) => Err(invalid_coordinator(
                "recovery requires a Staged SigningWorker receipt",
            )),
            (Ed25519YaoOperationV1::Export | Ed25519YaoOperationV1::Refresh, _) => Err(
                invalid_coordinator("activation delivery cannot produce this operation receipt"),
            ),
            (Ed25519YaoOperationV1::LaneProvisioning | Ed25519YaoOperationV1::LaneRefresh, _) => {
                Err(invalid_coordinator(
                    "activation delivery cannot produce a lane operation receipt",
                ))
            }
        }
    }

    fn validate_for_recovery_promotion(&self) -> RouterAbProtocolResult<()> {
        self.validate()?;
        match self {
            Self::Active { .. } => Ok(()),
            Self::Staged { .. } => Err(invalid_coordinator(
                "recovery promotion requires an Active SigningWorker receipt",
            )),
        }
    }

    fn into_public_receipt(
        self,
        material_activation: router_ab_core::MpcMaterialActivationRefV1,
    ) -> RouterAbProtocolResult<RouterAbEd25519YaoActivationPublicReceiptV1> {
        let (transcript, public_key, client, worker, verifying, epoch) = match self {
            Self::Active {
                transcript,
                registered_public_key,
                joined_client_commitment,
                joined_signing_worker_commitment,
                signing_worker_verifying_share,
                state_epoch,
                ..
            }
            | Self::Staged {
                transcript,
                registered_public_key,
                joined_client_commitment,
                joined_signing_worker_commitment,
                signing_worker_verifying_share,
                state_epoch,
                ..
            } => (
                transcript,
                registered_public_key,
                joined_client_commitment,
                joined_signing_worker_commitment,
                signing_worker_verifying_share,
                state_epoch,
            ),
        };
        RouterAbEd25519YaoActivationPublicReceiptV1::new(
            transcript,
            public_key,
            client,
            worker,
            verifying,
            epoch,
            material_activation,
        )
    }
}

async fn post_role_json<TRequest, TResponse>(
    env: &Env,
    binding_name: &str,
    service_origin: &str,
    path: &str,
    label: &str,
    body: &TRequest,
    trace_id: Option<crate::CloudflareTraceIdV1>,
) -> RouterAbProtocolResult<TResponse>
where
    TRequest: Serialize,
    TResponse: DeserializeOwned,
{
    let mut response = post_role_request(
        env,
        binding_name,
        service_origin,
        path,
        label,
        body,
        trace_id,
    )
    .await?;
    if !(200..=299).contains(&response.status_code()) {
        let status = response.status_code();
        let _ = response.text().await;
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            format!("{label} service returned HTTP {status}"),
        ));
    }
    response.json::<TResponse>().await.map_err(|error| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("{label} response JSON parse failed: {error}"),
        )
    })
}

async fn post_role_json_for_ceremony<TRequest, TResponse>(
    env: &Env,
    binding_name: &str,
    service_origin: &str,
    path: &str,
    label: &str,
    body: &TRequest,
    trace_id: Option<crate::CloudflareTraceIdV1>,
) -> Result<TResponse, RouterRoleCallError>
where
    TRequest: Serialize,
    TResponse: DeserializeOwned,
{
    let mut response = post_role_request(
        env,
        binding_name,
        service_origin,
        path,
        label,
        body,
        trace_id,
    )
    .await
    .map_err(RouterRoleCallError::Protocol)?;
    if !(200..=299).contains(&response.status_code()) {
        let status = response.status_code();
        let response_body = response.text().await.map_err(|error| {
            RouterRoleCallError::Protocol(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                format!("{label} error response body read failed: {error}"),
            ))
        })?;
        if let Ok(failure) =
            serde_json::from_str::<CloudflareEd25519YaoRoleFailureResponseV1>(&response_body)
        {
            return Err(RouterRoleCallError::Failure(failure));
        }
        return Err(RouterRoleCallError::Protocol(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            format!("{label} service returned HTTP {status}"),
        )));
    }
    response.json::<TResponse>().await.map_err(|error| {
        RouterRoleCallError::Protocol(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("{label} response JSON parse failed: {error}"),
        ))
    })
}

async fn post_role_request<TRequest>(
    env: &Env,
    binding_name: &str,
    service_origin: &str,
    path: &str,
    label: &str,
    body: &TRequest,
    trace_id: Option<crate::CloudflareTraceIdV1>,
) -> RouterAbProtocolResult<Response>
where
    TRequest: Serialize,
{
    let fetcher = env.service(binding_name).map_err(|error| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            format!("{label} service binding lookup failed: {error}"),
        )
    })?;
    let serialized = cloudflare_service_json_request_body_v1(label, body)?;
    let headers = worker::Headers::new();
    headers
        .set("content-type", "application/json")
        .map_err(|error| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                format!("{label} content-type header failed: {error}"),
            )
        })?;
    set_cloudflare_internal_service_auth_header_v1(env, &headers, label)?;
    if let Some(trace_id) = trace_id {
        set_cloudflare_trace_id_header_v1(&headers, trace_id)?;
    }
    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_headers(headers)
        .with_body(Some(worker::wasm_bindgen::JsValue::from_str(&serialized)));
    let request =
        Request::new_with_init(&format!("{service_origin}{path}"), &init).map_err(|error| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                format!("{label} request construction failed: {error}"),
            )
        })?;
    let response = fetcher.fetch_request(request).await.map_err(|error| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            format!("{label} service request failed: {error}"),
        )
    })?;
    Ok(response)
}

#[allow(clippy::too_many_arguments)]
async fn post_role_json_for_ceremony_with_span<TRequest, TResponse>(
    env: &Env,
    binding_name: &str,
    service_origin: &str,
    path: &str,
    label: &str,
    body: &TRequest,
    trace_id: Option<crate::CloudflareTraceIdV1>,
    span: &str,
    operation: &str,
) -> Result<TResponse, RouterRoleCallError>
where
    TRequest: Serialize,
    TResponse: DeserializeOwned,
{
    let started_at_ms = cloudflare_now_unix_ms_v1().unwrap_or_default();
    let result = post_role_json_for_ceremony(
        env,
        binding_name,
        service_origin,
        path,
        label,
        body,
        trace_id,
    )
    .await;
    emit_span(
        trace_id,
        span,
        operation,
        started_at_ms,
        if result.is_ok() { "success" } else { "failure" },
    );
    result
}

fn invalid_coordinator(message: &str) -> RouterAbProtocolError {
    RouterAbProtocolError::new(RouterAbProtocolErrorCode::MalformedWirePayload, message)
}

fn resolve_role_call_error(
    error: RouterRoleCallError,
    pair_binding: &Ed25519YaoInputPairBindingV1,
) -> RouterAbProtocolResult<RouterEd25519YaoExecuteResultV1> {
    match error {
        RouterRoleCallError::Protocol(error) => Err(error),
        RouterRoleCallError::Failure(
            CloudflareEd25519YaoRoleFailureResponseV1::RecoverableFailure {
                code,
                retry_after_ms,
            },
        ) => RouterEd25519YaoExecuteResultV1::recoverable(code, retry_after_ms),
        RouterRoleCallError::Failure(CloudflareEd25519YaoRoleFailureResponseV1::Rejected {
            code,
        }) => Ok(RouterEd25519YaoExecuteResultV1::rejected(code)),
        RouterRoleCallError::Failure(CloudflareEd25519YaoRoleFailureResponseV1::Burned {
            reason,
        }) => Ok(RouterEd25519YaoExecuteResultV1::burned(
            router_execution_id(pair_binding)?,
            reason,
        )),
    }
}

fn parse_router_replay_header(request: &Request) -> RouterAbProtocolResult<bool> {
    let value = request
        .headers()
        .get(ROUTER_REPLAY_HEADER)
        .map_err(|error| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalHttpRequest,
                format!("Router replay header read failed: {error}"),
            )
        })?;
    match value.as_deref() {
        None => Ok(false),
        Some("1") => Ok(true),
        Some("0") => Ok(false),
        Some(_) => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalHttpRequest,
            "Router replay header must be 0 or 1",
        )),
    }
}

fn operation_label(operation: Ed25519YaoOperationV1) -> &'static str {
    match operation {
        Ed25519YaoOperationV1::Registration => "registration",
        Ed25519YaoOperationV1::Recovery => "recovery",
        Ed25519YaoOperationV1::Export => "export",
        Ed25519YaoOperationV1::Refresh => "refresh",
        Ed25519YaoOperationV1::LaneProvisioning => "lane_provisioning",
        Ed25519YaoOperationV1::LaneRefresh => "lane_refresh",
    }
}

fn protocol_error_response(error: RouterAbProtocolError) -> worker::Result<Response> {
    Response::error(
        format!("{:?}: {}", error.code(), error.message()),
        cloudflare_router_error_status(error.code()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use router_ab_core::{
        Ed25519YaoEncryptedInputV1, Ed25519YaoInputKindV1, Ed25519YaoSessionIdV1,
        Ed25519YaoStableKeyContextBindingV1, ExpensiveWorkKindV1, LifecycleScopeV1,
        MpcMaterialActivationRefV1, RootShareEpoch, TenantRootCustodyLineageId,
    };

    fn application() -> RouterAbEd25519YaoApplicationBindingFactsV1 {
        RouterAbEd25519YaoApplicationBindingFactsV1::new(
            "wallet.testnet",
            "near-ed25519-key-1",
            "signing-root-1",
            1,
        )
        .expect("application")
    }

    fn binding(activation_id: &str, session: u8) -> Ed25519YaoCeremonyBindingV1 {
        let lifecycle = LifecycleScopeV1::new(
            format!("lifecycle-{activation_id}"),
            ExpensiveWorkKindV1::RegistrationPrepare,
            RootShareEpoch::new("root-epoch-1").expect("root epoch"),
            "wallet.testnet",
            format!("scope-session-{session}"),
            "signer-set-1",
            "signing-worker-1",
        )
        .expect("lifecycle");
        Ed25519YaoCeremonyBindingV1::new(
            lifecycle,
            Ed25519YaoOperationV1::Registration,
            Ed25519YaoSessionIdV1::new([session; 32]).expect("session"),
            Ed25519YaoStableKeyContextBindingV1::new(
                stable_key_derivation_context_v1(&application(), [1, 2])
                    .expect("stable context")
                    .binding_digest(),
            ),
            MpcMaterialActivationRefV1::new(
                activation_id,
                "ed25519-yao",
                "wallet.testnet",
                "wallet-key-1",
                "lifecycle-binding-1",
                "signing-worker-1",
            )
            .expect("activation"),
        )
        .expect("binding")
    }

    fn gateway_registration(
        binding: Ed25519YaoCeremonyBindingV1,
    ) -> RouterEd25519YaoGatewayExecuteTargetV2 {
        let session = binding.session_id.into_bytes();
        let stable = binding.stable_key_context_binding.into_bytes();
        let input_a = Ed25519YaoEncryptedInputV1::new(
            Ed25519YaoInputKindV1::Activation,
            Ed25519YaoDeriverRoleV1::DeriverA,
            Ed25519YaoOperationV1::Registration,
            session,
            stable,
            [3; 32],
            vec![7; 16],
        )
        .expect("deriver A input");
        let input_b = Ed25519YaoEncryptedInputV1::new(
            Ed25519YaoInputKindV1::Activation,
            Ed25519YaoDeriverRoleV1::DeriverB,
            Ed25519YaoOperationV1::Registration,
            session,
            stable,
            [4; 32],
            vec![8; 16],
        )
        .expect("deriver B input");
        RouterEd25519YaoGatewayExecuteTargetV2::registration(binding, input_a, input_b)
            .expect("gateway registration")
    }

    fn server_envelope(
        target: RouterEd25519YaoGatewayExecuteTargetV2,
        participant_ids: [u16; 2],
    ) -> CloudflareRouterEd25519YaoExecuteRequestV2 {
        CloudflareRouterEd25519YaoExecuteRequestV2 {
            tenant_root: CloudflareTenantRootCoordinatesV1 {
                identity_digest_b64u: crate::encode_base64url_bytes_v1(&[7; 32]),
                custody_lineage_b64u: TenantRootCustodyLineageId::from_bytes([8; 16])
                    .expect("lineage")
                    .to_base64url(),
            },
            application: application(),
            participant_ids,
            target,
        }
    }

    fn receipt(active: bool) -> SigningWorkerReceiptV1 {
        let epoch = router_ab_core::Ed25519YaoStateEpochV1::new(1).expect("nonzero epoch");
        if active {
            SigningWorkerReceiptV1::Active {
                session: [1; 32],
                transcript: [2; 32],
                registered_public_key: [3; 32],
                joined_client_commitment: [4; 32],
                joined_signing_worker_commitment: [5; 32],
                signing_worker_verifying_share: [5; 32],
                state_epoch: epoch,
            }
        } else {
            SigningWorkerReceiptV1::Staged {
                session: [1; 32],
                transcript: [2; 32],
                registered_public_key: [3; 32],
                joined_client_commitment: [4; 32],
                joined_signing_worker_commitment: [5; 32],
                signing_worker_verifying_share: [5; 32],
                state_epoch: epoch,
            }
        }
    }

    #[test]
    fn signing_worker_receipt_status_is_bound_to_activation_operation() {
        assert!(receipt(true)
            .validate_for_operation(Ed25519YaoOperationV1::Registration)
            .is_ok());
        assert!(receipt(false)
            .validate_for_operation(Ed25519YaoOperationV1::Registration)
            .is_err());
        assert!(receipt(false)
            .validate_for_operation(Ed25519YaoOperationV1::Recovery)
            .is_ok());
        assert!(receipt(true)
            .validate_for_operation(Ed25519YaoOperationV1::Recovery)
            .is_err());
    }

    #[test]
    fn recovery_promotion_requires_an_active_receipt() {
        assert!(receipt(true).validate_for_recovery_promotion().is_ok());
        assert!(receipt(false).validate_for_recovery_promotion().is_err());
    }

    #[test]
    fn source_preserving_request_rejects_unknown_fields() {
        let source_binding = binding("source-activation", 1);
        let target = gateway_registration(binding("target-activation", 2));
        let request = CloudflareRouterEd25519YaoSourcePreservingExecuteRequestV1 {
            source_binding,
            target: server_envelope(target, [1, 2]),
        };
        let mut wire = serde_json::to_value(request).expect("request wire");
        wire.as_object_mut()
            .expect("request object")
            .insert("unexpected".to_owned(), serde_json::json!(true));
        assert!(
            serde_json::from_value::<CloudflareRouterEd25519YaoSourcePreservingExecuteRequestV1>(
                wire
            )
            .is_err()
        );
    }

    #[test]
    fn source_preserving_request_requires_fresh_target_with_same_stable_identity() {
        let source_binding = binding("source-activation", 1);
        let same_activation = gateway_registration(source_binding.clone());
        let same_activation_request = CloudflareRouterEd25519YaoSourcePreservingExecuteRequestV1 {
            source_binding: source_binding.clone(),
            target: server_envelope(same_activation, [1, 2]),
        };
        assert!(same_activation_request.validate().is_err());

        let mut changed_target = binding("target-activation", 2);
        changed_target.stable_key_context_binding =
            Ed25519YaoStableKeyContextBindingV1::new([10; 32]);
        let changed_identity_request = CloudflareRouterEd25519YaoSourcePreservingExecuteRequestV1 {
            source_binding,
            target: server_envelope(gateway_registration(changed_target), [1, 2]),
        };
        assert!(changed_identity_request.validate().is_err());
    }

    #[test]
    fn source_preserving_request_rejects_invalid_participant_order() {
        let request = CloudflareRouterEd25519YaoSourcePreservingExecuteRequestV1 {
            source_binding: binding("source-activation", 1),
            target: server_envelope(
                gateway_registration(binding("target-activation", 2)),
                [2, 1],
            ),
        };
        assert!(request.validate().is_err());
    }
}
