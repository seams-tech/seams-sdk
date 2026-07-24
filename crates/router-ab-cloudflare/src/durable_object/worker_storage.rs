use super::handlers::{
    require_existing_record_v1, validate_idempotent_put_record_v1,
    validate_router_replay_reservation_v1,
    validate_signing_worker_output_active_state_replacement_v1,
};
use super::*;
use crate::ed25519_yao_signing_worker::{
    CloudflareEd25519YaoOutputActivationPutV1, CloudflareEd25519YaoOutputActivationReceiptV1,
    CLOUDFLARE_SIGNING_WORKER_ED25519_YAO_OUTPUT_ACTIVATE_DO_PATH,
};

/// Handles a real `workers-rs` Durable Object fetch event for Router/A/B storage.
#[cfg(feature = "workers-rs")]
pub async fn handle_cloudflare_durable_object_fetch_v1(
    binding: &CloudflareDurableObjectBindingV1,
    request: worker::Request,
    storage: &worker::Storage,
) -> worker::Result<worker::Response> {
    handle_cloudflare_durable_object_fetch_with_project_policy_v1(binding, request, storage, None)
        .await
}

#[cfg(feature = "workers-rs")]
async fn handle_cloudflare_durable_object_fetch_with_project_policy_v1(
    binding: &CloudflareDurableObjectBindingV1,
    mut request: worker::Request,
    storage: &worker::Storage,
    project_policy_bootstrap: Option<&CloudflareRouterProjectPolicyRecordV1>,
) -> worker::Result<worker::Response> {
    if request.method() != worker::Method::Post {
        return worker::Response::error("Router A/B Durable Object requires POST", 405);
    }
    let parsed = match request.json::<CloudflareDurableObjectRequestV1>().await {
        Ok(parsed) => parsed,
        Err(err) => {
            return worker::Response::error(
                format!("Router A/B Durable Object request JSON parse failed: {err}"),
                400,
            );
        }
    };
    if request.path() != parsed.operation_kind().path() {
        return worker::Response::error(
            format!(
                "{} must be served at {}",
                parsed.operation_kind().as_str(),
                parsed.operation_kind().path()
            ),
            404,
        );
    }
    match handle_cloudflare_durable_object_worker_request_with_project_policy_v1(
        binding,
        parsed,
        storage,
        project_policy_bootstrap,
    )
    .await
    {
        Ok(response) => worker::Response::from_json(&response),
        Err(err) => worker::Response::error(
            format!("{:?}: {}", err.code(), err.message()),
            durable_object_error_status(err.code()),
        ),
    }
}

#[cfg(feature = "workers-rs")]
pub(super) async fn handle_cloudflare_project_policy_durable_object_class_fetch_v1(
    scope: CloudflareDurableObjectScopeV1,
    binding_env_key: &str,
    object_env_key: &str,
    key_prefix_env_key: &str,
    bootstrap_json_env_key: &str,
    env: &worker::Env,
    state: &worker::State,
    request: worker::Request,
) -> worker::Result<worker::Response> {
    let binding = match cloudflare_durable_object_class_binding_v1(
        scope,
        binding_env_key,
        object_env_key,
        key_prefix_env_key,
        env,
    ) {
        Ok(binding) => binding,
        Err(err) => {
            return worker::Response::error(
                format!("{:?}: {}", err.code(), err.message()),
                durable_object_error_status(err.code()),
            );
        }
    };
    let bootstrap_json =
        match read_cloudflare_durable_object_class_env_text_v1(env, bootstrap_json_env_key) {
            Ok(value) => value,
            Err(err) => {
                return worker::Response::error(
                    format!("{:?}: {}", err.code(), err.message()),
                    durable_object_error_status(err.code()),
                );
            }
        };
    let bootstrap =
        match serde_json::from_str::<CloudflareRouterProjectPolicyRecordV1>(&bootstrap_json) {
            Ok(record) => record,
            Err(err) => {
                return worker::Response::error(
                    format!("Router project-policy bootstrap JSON parse failed: {err}"),
                    500,
                );
            }
        };
    if let Err(err) = bootstrap.validate() {
        return worker::Response::error(
            format!("{:?}: {}", err.code(), err.message()),
            durable_object_error_status(err.code()),
        );
    }
    handle_cloudflare_durable_object_fetch_with_project_policy_v1(
        &binding,
        request,
        &state.storage(),
        Some(&bootstrap),
    )
    .await
}

#[cfg(feature = "workers-rs")]
pub(super) async fn handle_cloudflare_durable_object_class_fetch_v1(
    scope: CloudflareDurableObjectScopeV1,
    binding_env_key: &str,
    object_env_key: &str,
    key_prefix_env_key: &str,
    env: &worker::Env,
    state: &worker::State,
    request: worker::Request,
) -> worker::Result<worker::Response> {
    let binding = match cloudflare_durable_object_class_binding_v1(
        scope,
        binding_env_key,
        object_env_key,
        key_prefix_env_key,
        env,
    ) {
        Ok(binding) => binding,
        Err(err) => {
            return worker::Response::error(
                format!("{:?}: {}", err.code(), err.message()),
                durable_object_error_status(err.code()),
            );
        }
    };
    let storage = state.storage();
    if scope == CloudflareDurableObjectScopeV1::signing_worker_server_output()
        && request.path() == CLOUDFLARE_SIGNING_WORKER_ED25519_YAO_OUTPUT_ACTIVATE_DO_PATH
    {
        return handle_cloudflare_ed25519_yao_output_activation_fetch_v1(
            &binding, request, &storage,
        )
        .await;
    }
    handle_cloudflare_durable_object_fetch_v1(&binding, request, &storage).await
}

#[cfg(feature = "workers-rs")]
async fn handle_cloudflare_ed25519_yao_output_activation_fetch_v1(
    binding: &CloudflareDurableObjectBindingV1,
    mut request: worker::Request,
    storage: &worker::Storage,
) -> worker::Result<worker::Response> {
    if request.method() != worker::Method::Post {
        return worker::Response::error(
            "Signing Worker Ed25519 Yao output activation requires POST",
            405,
        );
    }
    let parsed = match request
        .json::<CloudflareEd25519YaoOutputActivationPutV1>()
        .await
    {
        Ok(parsed) => parsed,
        Err(err) => {
            return worker::Response::error(
                format!("Signing Worker Ed25519 Yao output JSON parse failed: {err}"),
                400,
            );
        }
    };
    match persist_cloudflare_ed25519_yao_output_activation_v1(binding, parsed, storage).await {
        Ok(receipt) => worker::Response::from_json(&receipt),
        Err(err) => worker::Response::error(
            format!("{:?}: {}", err.code(), err.message()),
            durable_object_error_status(err.code()),
        ),
    }
}

#[cfg(feature = "workers-rs")]
async fn persist_cloudflare_ed25519_yao_output_activation_v1(
    binding: &CloudflareDurableObjectBindingV1,
    request: CloudflareEd25519YaoOutputActivationPutV1,
    storage: &worker::Storage,
) -> RouterAbProtocolResult<CloudflareEd25519YaoOutputActivationReceiptV1> {
    binding.validate()?;
    request.validate()?;
    let active_state = request.record.active_signing_worker_state().clone();
    let material_key = active_state.signing_worker_material_handle.clone();
    let expected_material_prefix = format!("{}ed25519-yao/", binding.key_prefix);
    if !material_key.starts_with(&expected_material_prefix) {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "Signing Worker Ed25519 Yao material handle is outside its Durable Object scope",
        ));
    }
    let active_state_key = format!(
        "{}active-signing-worker/{}/{}/{}",
        binding.key_prefix,
        active_state.account_id,
        active_state.session_id,
        active_state.signing_worker.server_id
    );
    let existing_record = storage
        .get::<CloudflareSigningWorkerOutputActivationRecordV1>(&material_key)
        .await
        .map_err(|err| ed25519_yao_output_storage_error("read material", err))?;
    let existing_active_state = storage
        .get::<ActiveSigningWorkerStateV1>(&active_state_key)
        .await
        .map_err(|err| ed25519_yao_output_storage_error("read active state", err))?;
    if let Some(existing_record) = existing_record {
        existing_record.validate()?;
        let canonical_active_state = existing_record.active_signing_worker_state().clone();
        if !same_ed25519_yao_activation_ignoring_timestamp(&existing_record, &request.record)
            || existing_active_state.as_ref() != Some(&canonical_active_state)
        {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ReplayedLocalRequest,
                "Signing Worker Ed25519 Yao activation conflicts with durable state",
            ));
        }
        return CloudflareEd25519YaoOutputActivationReceiptV1::new(canonical_active_state, false);
    }
    validate_signing_worker_output_active_state_replacement_v1(
        existing_active_state.as_ref(),
        &active_state,
    )?;
    let writes = worker::js_sys::Object::new();
    set_durable_object_put_multiple_value(
        &writes,
        &material_key,
        &request.record,
        "Signing Worker Ed25519 Yao material",
    )?;
    set_durable_object_put_multiple_value(
        &writes,
        &active_state_key,
        &active_state,
        "Signing Worker Ed25519 Yao active state",
    )?;
    storage
        .put_multiple_raw(writes)
        .await
        .map_err(|err| ed25519_yao_output_storage_error("commit activation", err))?;
    let committed_record = storage
        .get::<CloudflareSigningWorkerOutputActivationRecordV1>(&material_key)
        .await
        .map_err(|err| ed25519_yao_output_storage_error("verify committed material", err))?;
    let committed_active_state = storage
        .get::<ActiveSigningWorkerStateV1>(&active_state_key)
        .await
        .map_err(|err| ed25519_yao_output_storage_error("verify committed active state", err))?;
    if committed_record.as_ref() != Some(&request.record)
        || committed_active_state.as_ref() != Some(&active_state)
    {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "Signing Worker Ed25519 Yao activation did not commit exact durable state",
        ));
    }
    CloudflareEd25519YaoOutputActivationReceiptV1::new(active_state, true)
}

#[cfg(feature = "workers-rs")]
fn same_ed25519_yao_activation_ignoring_timestamp(
    existing: &CloudflareSigningWorkerOutputActivationRecordV1,
    requested: &CloudflareSigningWorkerOutputActivationRecordV1,
) -> bool {
    match (existing, requested) {
        (
            CloudflareSigningWorkerOutputActivationRecordV1::Ed25519Yao {
                binding: existing_binding,
                receipt: existing_receipt,
                active_signing_worker_state: existing_active_state,
                material: existing_material,
            },
            CloudflareSigningWorkerOutputActivationRecordV1::Ed25519Yao {
                binding: requested_binding,
                receipt: requested_receipt,
                active_signing_worker_state: requested_active_state,
                material: requested_material,
            },
        ) => {
            let mut canonical_requested_active_state = requested_active_state.clone();
            canonical_requested_active_state.activated_at_ms =
                existing_active_state.activated_at_ms;
            existing_binding == requested_binding
                && existing_receipt == requested_receipt
                && existing_active_state == &canonical_requested_active_state
                && existing_material == requested_material
        }
        _ => existing == requested,
    }
}

#[cfg(feature = "workers-rs")]
fn set_durable_object_put_multiple_value<T: Serialize>(
    writes: &worker::js_sys::Object,
    key: &str,
    value: &T,
    label: &'static str,
) -> RouterAbProtocolResult<()> {
    let json = serde_json::to_string(value).map_err(|err| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("{label} encoding failed: {err}"),
        )
    })?;
    let js_value = worker::js_sys::JSON::parse(&json).map_err(|err| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("{label} JavaScript encoding failed: {err:?}"),
        )
    })?;
    worker::js_sys::Reflect::set(
        writes,
        &worker::wasm_bindgen::JsValue::from_str(key),
        &js_value,
    )
    .map_err(|err| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("{label} Durable Object write assembly failed: {err:?}"),
        )
    })?;
    Ok(())
}

#[cfg(feature = "workers-rs")]
fn ed25519_yao_output_storage_error(
    operation: &'static str,
    error: worker::Error,
) -> RouterAbProtocolError {
    RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
        format!("Signing Worker Ed25519 Yao Durable Object {operation} failed: {error}"),
    )
}

#[cfg(feature = "workers-rs")]
pub(super) fn cloudflare_durable_object_class_binding_v1(
    scope: CloudflareDurableObjectScopeV1,
    binding_env_key: &str,
    object_env_key: &str,
    key_prefix_env_key: &str,
    env: &worker::Env,
) -> RouterAbProtocolResult<CloudflareDurableObjectBindingV1> {
    CloudflareDurableObjectBindingV1::new(
        scope,
        read_cloudflare_durable_object_class_env_text_v1(env, binding_env_key)?,
        read_cloudflare_durable_object_class_env_text_v1(env, object_env_key)?,
        read_cloudflare_durable_object_class_env_text_v1(env, key_prefix_env_key)?,
    )
}

#[cfg(feature = "workers-rs")]
fn read_cloudflare_durable_object_class_env_text_v1(
    env: &worker::Env,
    key: &str,
) -> RouterAbProtocolResult<String> {
    let value = env.var(key).map_err(|err| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MissingLocalBinding,
            format!("Durable Object class is missing Env key {key}: {err}"),
        )
    })?;
    let value = value.to_string().trim().to_owned();
    require_non_empty(key, &value)?;
    Ok(value)
}

#[cfg(feature = "workers-rs")]
async fn worker_wallet_budget_record_v1(
    storage: &worker::Storage,
    storage_key: &str,
    operation_kind: CloudflareDurableObjectOperationKindV1,
) -> RouterAbProtocolResult<CloudflareRouterWalletBudgetGrantRecordV1> {
    require_existing_record_v1(
        worker_storage_get::<CloudflareRouterWalletBudgetGrantRecordV1>(
            storage,
            storage_key,
            operation_kind,
        )
        .await?,
        "wallet budget grant is missing",
    )
}

#[cfg(feature = "workers-rs")]
fn single_index_cleanup_report_v1(
    now_unix_ms: u64,
    records_removed: u64,
) -> RouterAbProtocolResult<CloudflareExpiredStateCleanupReportV1> {
    CloudflareExpiredStateCleanupReportV1::new(now_unix_ms, records_removed, 0)
}

#[cfg(feature = "workers-rs")]
#[derive(Clone, Copy)]
struct WorkerProjectPolicyScopeV1<'a> {
    org_id: &'a str,
    project_id: &'a str,
    environment: &'a str,
}

#[cfg(feature = "workers-rs")]
impl WorkerProjectPolicyScopeV1<'_> {
    fn matches(self, policy: &CloudflareRouterProjectPolicyRecordV1) -> bool {
        policy.org_id == self.org_id
            && policy.project_id == self.project_id
            && policy.environment == self.environment
    }
}

#[cfg(feature = "workers-rs")]
async fn worker_storage_project_policy_v1(
    storage: &worker::Storage,
    storage_key: &str,
    operation_kind: CloudflareDurableObjectOperationKindV1,
    bootstrap: Option<&CloudflareRouterProjectPolicyRecordV1>,
    expected_scope: WorkerProjectPolicyScopeV1<'_>,
) -> RouterAbProtocolResult<CloudflareRouterProjectPolicyRecordV1> {
    if let Some(existing) = worker_storage_get::<CloudflareRouterProjectPolicyRecordV1>(
        storage,
        storage_key,
        operation_kind,
    )
    .await?
    {
        existing.validate()?;
        if expected_scope.matches(&existing) {
            if bootstrap.is_some_and(|configured| configured != &existing) {
                return Err(RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                    "router project-policy bootstrap does not match durable state",
                ));
            }
            return Ok(existing);
        }
        let configured = bootstrap.ok_or_else(|| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "router project-policy durable state has an invalid scope",
            )
        })?;
        configured.validate()?;
        if !expected_scope.matches(configured) {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "router project-policy bootstrap does not match the requested scope",
            ));
        }
        worker_storage_put(storage, storage_key, configured.clone(), operation_kind).await?;
        return Ok(configured.clone());
    }
    let policy = bootstrap.cloned().ok_or_else(|| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MissingLocalBinding,
            "router project-policy record is missing",
        )
    })?;
    policy.validate()?;
    if !expected_scope.matches(&policy) {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "router project-policy bootstrap does not match the requested scope",
        ));
    }
    worker_storage_put(storage, storage_key, policy.clone(), operation_kind).await?;
    Ok(policy)
}

/// Handles a parsed Durable Object request against real Cloudflare storage.
#[cfg(feature = "workers-rs")]
pub async fn handle_cloudflare_durable_object_worker_request_v1(
    binding: &CloudflareDurableObjectBindingV1,
    request: CloudflareDurableObjectRequestV1,
    storage: &worker::Storage,
) -> RouterAbProtocolResult<CloudflareDurableObjectResponseV1> {
    handle_cloudflare_durable_object_worker_request_with_project_policy_v1(
        binding, request, storage, None,
    )
    .await
}

#[cfg(feature = "workers-rs")]
async fn handle_cloudflare_durable_object_worker_request_with_project_policy_v1(
    binding: &CloudflareDurableObjectBindingV1,
    request: CloudflareDurableObjectRequestV1,
    storage: &worker::Storage,
    project_policy_bootstrap: Option<&CloudflareRouterProjectPolicyRecordV1>,
) -> RouterAbProtocolResult<CloudflareDurableObjectResponseV1> {
    let worker_role = worker_role_for_durable_object_scope(binding.scope)?;
    let call = CloudflareDurableObjectCallV1::new(worker_role, binding.clone(), request)?;
    let storage_key = call.storage_key();
    let response = match &call.request {
        CloudflareDurableObjectRequestV1::RootShareHas { lookup } => {
            let present = match worker_storage_get::<CloudflareRootShareStartupMetadataV1>(
                storage,
                &storage_key,
                call.operation_kind(),
            )
            .await?
            {
                Some(metadata) => {
                    metadata.validate_matches_lookup(lookup)?;
                    true
                }
                None => false,
            };
            CloudflareDurableObjectResponseV1::root_share_has(present)
        }
        CloudflareDurableObjectRequestV1::RootShareStartupMetadata { metadata } => {
            let stored = validate_idempotent_put_record_v1(
                worker_storage_get::<CloudflareRootShareStartupMetadataV1>(
                    storage,
                    &storage_key,
                    call.operation_kind(),
                )
                .await?,
                metadata,
                CloudflareRootShareStartupMetadataV1::validate,
                "root-share startup metadata is already initialized with different material",
            )?;
            if stored {
                worker_storage_put(
                    storage,
                    &storage_key,
                    metadata.clone(),
                    call.operation_kind(),
                )
                .await?;
            }
            CloudflareDurableObjectResponseV1::root_share_startup_metadata(metadata.clone())?
        }
        CloudflareDurableObjectRequestV1::RootShareRewrapStartupMetadata { request } => {
            let existing = require_existing_record_v1(
                worker_storage_get::<CloudflareRootShareStartupMetadataV1>(
                    storage,
                    &storage_key,
                    call.operation_kind(),
                )
                .await?,
                "root-share startup metadata is missing",
            )?;
            request.validate_replaces(&existing)?;
            worker_storage_put(
                storage,
                &storage_key,
                request.replacement_metadata.clone(),
                call.operation_kind(),
            )
            .await?;
            CloudflareDurableObjectResponseV1::root_share_rewrap_startup_metadata(
                CloudflareRootShareRewrapReceiptV1::new(request, &existing)?,
            )?
        }
        CloudflareDurableObjectRequestV1::RouterReplayReserve { request } => {
            let request_index_key = call.replay_request_index_storage_key()?;
            let reserved = validate_router_replay_reservation_v1(
                worker_storage_get::<CloudflareReplayReserveRequestV1>(
                    storage,
                    &request_index_key,
                    call.operation_kind(),
                )
                .await?,
                request,
            )?;
            if reserved {
                worker_storage_put(
                    storage,
                    &request_index_key,
                    request.clone(),
                    call.operation_kind(),
                )
                .await?;
                worker_storage_put(
                    storage,
                    &storage_key,
                    request.clone(),
                    call.operation_kind(),
                )
                .await?;
            }
            CloudflareDurableObjectResponseV1::router_replay_reserve(
                CloudflareReplayReserveResponseV1::new(request.request_id.clone(), reserved)?,
            )?
        }
        CloudflareDurableObjectRequestV1::RouterReplayCleanupExpired { cleanup } => {
            cleanup.validate()?;
            let records_removed = worker_storage_cleanup_expired_values(
                storage,
                &call.replay_storage_prefix(),
                cleanup.now_unix_ms,
                call.operation_kind(),
                cloudflare_replay_reservation_expires_at_ms_v1,
            )
            .await?;
            let index_records_removed = worker_storage_cleanup_expired_values(
                storage,
                &call.replay_request_index_storage_prefix(),
                cleanup.now_unix_ms,
                call.operation_kind(),
                cloudflare_replay_reservation_expires_at_ms_v1,
            )
            .await?;
            CloudflareDurableObjectResponseV1::router_replay_cleanup_expired(
                CloudflareExpiredStateCleanupReportV1::new(
                    cleanup.now_unix_ms,
                    records_removed,
                    index_records_removed,
                )?,
            )?
        }
        CloudflareDurableObjectRequestV1::RouterLifecyclePutPublicState { state } => {
            let previous = worker_storage_get::<RouterAbLifecycleStateV1>(
                storage,
                &storage_key,
                call.operation_kind(),
            )
            .await?;
            RouterAbLifecycleStateV1::validate_transition_from(previous.as_ref(), state)?;
            worker_storage_put(storage, &storage_key, state.clone(), call.operation_kind()).await?;
            CloudflareDurableObjectResponseV1::router_lifecycle_put_public_state(
                CloudflareLifecyclePutReceiptV1::new(state.scope().lifecycle_id.clone(), true)?,
            )?
        }
        CloudflareDurableObjectRequestV1::DerivationCeremonyPutState { ceremony } => {
            let previous = worker_storage_get::<CloudflareDerivationCeremonyV1>(
                storage,
                &storage_key,
                call.operation_kind(),
            )
            .await?;
            CloudflareDerivationCeremonyV1::validate_transition_from(previous.as_ref(), ceremony)?;
            let stored = previous.as_ref() != Some(ceremony);
            if stored {
                worker_storage_put(
                    storage,
                    &storage_key,
                    ceremony.clone(),
                    call.operation_kind(),
                )
                .await?;
            }
            CloudflareDurableObjectResponseV1::derivation_ceremony_put_state(
                CloudflareDerivationCeremonyPutReceiptV1::new(
                    ceremony.scope().lifecycle_id.clone(),
                    ceremony.label(),
                    stored,
                )?,
            )?
        }
        CloudflareDurableObjectRequestV1::RouterProjectPolicyEvaluate { request } => {
            let policy = worker_storage_project_policy_v1(
                storage,
                &storage_key,
                call.operation_kind(),
                project_policy_bootstrap,
                WorkerProjectPolicyScopeV1 {
                    org_id: &request.metadata.org_id,
                    project_id: &request.metadata.project_id,
                    environment: &request.metadata.environment,
                },
            )
            .await?
            .evaluate(request)?;
            CloudflareDurableObjectResponseV1::router_project_policy_evaluate(policy)?
        }
        CloudflareDurableObjectRequestV1::RouterQuotaEvaluate { request } => {
            let quota = match worker_storage_get::<CloudflareRouterQuotaReservationV1>(
                storage,
                &storage_key,
                call.operation_kind(),
            )
            .await?
            {
                Some(existing) if existing.is_active_at(request.now_unix_ms) => {
                    existing.validate()?;
                    CloudflareRouterQuotaCheckV1::ReuseExisting {
                        request_id: request.request_nonce.clone(),
                        existing_lifecycle_id: existing.lifecycle_id,
                    }
                }
                _ => {
                    let reservation = CloudflareRouterQuotaReservationV1::new(
                        request.request_nonce.clone(),
                        request.lifecycle_id.clone(),
                        request.expires_at_ms,
                    )?;
                    worker_storage_put(storage, &storage_key, reservation, call.operation_kind())
                        .await?;
                    CloudflareRouterQuotaCheckV1::Accepted {
                        request_id: request.request_nonce.clone(),
                    }
                }
            };
            CloudflareDurableObjectResponseV1::router_quota_evaluate(quota)?
        }
        CloudflareDurableObjectRequestV1::RouterQuotaCleanupExpired { cleanup } => {
            cleanup.validate()?;
            let records_removed = worker_storage_cleanup_expired_values(
                storage,
                &call.quota_storage_prefix(),
                cleanup.now_unix_ms,
                call.operation_kind(),
                cloudflare_quota_reservation_expires_at_ms_v1,
            )
            .await?;
            CloudflareDurableObjectResponseV1::router_quota_cleanup_expired(
                CloudflareExpiredStateCleanupReportV1::new(
                    cleanup.now_unix_ms,
                    records_removed,
                    0,
                )?,
            )?
        }
        CloudflareDurableObjectRequestV1::RouterAbuseEvaluate { request } => {
            request.validate()?;
            let abuse = match worker_storage_get::<CloudflareRouterAbuseRecordV1>(
                storage,
                &storage_key,
                call.operation_kind(),
            )
            .await?
            {
                Some(record) => {
                    record.validate()?;
                    record.outcome
                }
                None => CloudflareRouterAbuseCheckV1::Allowed,
            };
            CloudflareDurableObjectResponseV1::router_abuse_evaluate(abuse)?
        }
        CloudflareDurableObjectRequestV1::RouterNormalSigningProjectPolicyEvaluate { request } => {
            let policy = worker_storage_project_policy_v1(
                storage,
                &storage_key,
                call.operation_kind(),
                project_policy_bootstrap,
                WorkerProjectPolicyScopeV1 {
                    org_id: &request.metadata.org_id,
                    project_id: &request.metadata.project_id,
                    environment: &request.metadata.environment,
                },
            )
            .await?
            .evaluate_normal_signing(request)?;
            CloudflareDurableObjectResponseV1::router_normal_signing_project_policy_evaluate(
                policy,
            )?
        }
        CloudflareDurableObjectRequestV1::RouterNormalSigningQuotaEvaluate { request } => {
            let quota = match worker_storage_get::<CloudflareRouterQuotaReservationV1>(
                storage,
                &storage_key,
                call.operation_kind(),
            )
            .await?
            {
                Some(existing)
                    if existing.is_active_at(request.now_unix_ms)
                        && existing.request_id == request.request_id =>
                {
                    existing.validate()?;
                    CloudflareRouterQuotaCheckV1::Accepted {
                        request_id: request.request_id.clone(),
                    }
                }
                Some(existing) if existing.is_active_at(request.now_unix_ms) => {
                    existing.validate()?;
                    CloudflareRouterQuotaCheckV1::ShortWindowSaturated
                }
                _ => {
                    let reservation = CloudflareRouterQuotaReservationV1::new(
                        request.request_id.clone(),
                        request.request_id.clone(),
                        request.expires_at_ms,
                    )?;
                    worker_storage_put(storage, &storage_key, reservation, call.operation_kind())
                        .await?;
                    CloudflareRouterQuotaCheckV1::Accepted {
                        request_id: request.request_id.clone(),
                    }
                }
            };
            CloudflareDurableObjectResponseV1::router_normal_signing_quota_evaluate(quota)?
        }
        CloudflareDurableObjectRequestV1::RouterNormalSigningAbuseEvaluate { request } => {
            request.validate()?;
            let abuse = match worker_storage_get::<CloudflareRouterAbuseRecordV1>(
                storage,
                &storage_key,
                call.operation_kind(),
            )
            .await?
            {
                Some(record) => {
                    record.validate()?;
                    record.outcome
                }
                None => CloudflareRouterAbuseCheckV1::Allowed,
            };
            CloudflareDurableObjectResponseV1::router_normal_signing_abuse_evaluate(abuse)?
        }
        CloudflareDurableObjectRequestV1::RouterWalletBudgetPutGrant { request } => {
            let record = match worker_storage_get::<CloudflareRouterWalletBudgetGrantRecordV1>(
                storage,
                &storage_key,
                call.operation_kind(),
            )
            .await?
            {
                Some(existing) => {
                    existing.validate_matches_put_request(request)?;
                    existing
                }
                None => {
                    let record =
                        CloudflareRouterWalletBudgetGrantRecordV1::from_put_request(request)?;
                    worker_storage_put(
                        storage,
                        &storage_key,
                        record.clone(),
                        call.operation_kind(),
                    )
                    .await?;
                    record
                }
            };
            CloudflareDurableObjectResponseV1::router_wallet_budget_grant_put(
                record.status_at(request.now_unix_ms)?,
            )?
        }
        CloudflareDurableObjectRequestV1::RouterWalletBudgetReserve { request } => {
            let mut record =
                worker_wallet_budget_record_v1(storage, &storage_key, call.operation_kind())
                    .await?;
            let reservation_id = record.reserve(request)?;
            let status = record.status_at(request.now_unix_ms)?;
            worker_storage_put(storage, &storage_key, record, call.operation_kind()).await?;
            CloudflareDurableObjectResponseV1::router_wallet_budget_reserved(
                reservation_id,
                status,
            )?
        }
        CloudflareDurableObjectRequestV1::RouterWalletBudgetValidate { identity } => {
            let mut record =
                worker_wallet_budget_record_v1(storage, &storage_key, call.operation_kind())
                    .await?;
            record.validate_reservation(identity)?;
            let status = record.status_at(identity.now_unix_ms)?;
            worker_storage_put(storage, &storage_key, record, call.operation_kind()).await?;
            CloudflareDurableObjectResponseV1::router_wallet_budget_validated(
                identity.reservation_id.clone(),
                status,
            )?
        }
        CloudflareDurableObjectRequestV1::RouterWalletBudgetCommit { identity } => {
            let mut record =
                worker_wallet_budget_record_v1(storage, &storage_key, call.operation_kind())
                    .await?;
            record.commit(identity)?;
            let status = record.status_at(identity.now_unix_ms)?;
            worker_storage_put(storage, &storage_key, record, call.operation_kind()).await?;
            CloudflareDurableObjectResponseV1::router_wallet_budget_committed(
                identity.reservation_id.clone(),
                status,
            )?
        }
        CloudflareDurableObjectRequestV1::RouterWalletBudgetRelease { request } => {
            let mut record =
                worker_wallet_budget_record_v1(storage, &storage_key, call.operation_kind())
                    .await?;
            record.release(request)?;
            let status = record.status_at(request.now_unix_ms)?;
            worker_storage_put(storage, &storage_key, record, call.operation_kind()).await?;
            CloudflareDurableObjectResponseV1::router_wallet_budget_released(
                request.reservation_id.clone(),
                status,
            )?
        }
        CloudflareDurableObjectRequestV1::RouterWalletBudgetStatus { request } => {
            let mut record =
                worker_wallet_budget_record_v1(storage, &storage_key, call.operation_kind())
                    .await?;
            let changed = record.clean_expired_reservations(request.now_unix_ms)?;
            let status = record.status_at(request.now_unix_ms)?;
            if changed {
                worker_storage_put(storage, &storage_key, record, call.operation_kind()).await?;
            }
            CloudflareDurableObjectResponseV1::router_wallet_budget_status(status)?
        }
        CloudflareDurableObjectRequestV1::SigningWorkerOutputActivate {
            activation,
            material,
            activated_at_ms,
        } => {
            let active_state_index_key = call.active_signing_worker_state_index_storage_key()?;
            let existing_record = worker_storage_get::<
                CloudflareSigningWorkerOutputActivationRecordV1,
            >(storage, &storage_key, call.operation_kind())
            .await?;
            let existing_active_state = worker_storage_get::<ActiveSigningWorkerStateV1>(
                storage,
                &active_state_index_key,
                call.operation_kind(),
            )
            .await?;
            let (record, active_signing_worker_state, activated) = match existing_record {
                Some(existing) => {
                    existing.validate()?;
                    match existing {
                        CloudflareSigningWorkerOutputActivationRecordV1::RecipientProofBundle {
                            activation: existing_activation,
                            active_signing_worker_state,
                            material: existing_material,
                        } if existing_activation == *activation
                            && existing_material == *material =>
                        {
                            let record = CloudflareSigningWorkerOutputActivationRecordV1::new(
                                existing_activation,
                                active_signing_worker_state.clone(),
                                existing_material,
                            )?;
                            (record, active_signing_worker_state, false)
                        }
                        _ => {
                            return Err(RouterAbProtocolError::new(
                                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                                "server-output activation conflicts with existing activation or material",
                            ));
                        }
                    }
                }
                None => {
                    let active_signing_worker_state =
                        cloudflare_active_signing_worker_state_from_activation_request_v1(
                            activation,
                            storage_key.clone(),
                            *activated_at_ms,
                        )?;
                    let record = CloudflareSigningWorkerOutputActivationRecordV1::new(
                        activation.clone(),
                        active_signing_worker_state.clone(),
                        material.clone(),
                    )?;
                    (record, active_signing_worker_state, true)
                }
            };
            if activated || existing_active_state.as_ref() != Some(&active_signing_worker_state) {
                validate_signing_worker_output_active_state_replacement_v1(
                    existing_active_state.as_ref(),
                    &active_signing_worker_state,
                )?;
                persist_cloudflare_signing_worker_output_activation_pair_v1(
                    storage,
                    &storage_key,
                    &active_state_index_key,
                    &record,
                    &active_signing_worker_state,
                    call.operation_kind(),
                )
                .await?;
            }
            let activation_context = &activation.activation_context;
            let selected_server = &activation_context.signer_set().selected_server;
            CloudflareDurableObjectResponseV1::signing_worker_output_activate(
                CloudflareSigningWorkerOutputActivationReceiptV1::new(
                    activation_context.lifecycle().lifecycle_id.clone(),
                    selected_server.server_id.clone(),
                    activation_context.transcript_digest(),
                    active_signing_worker_state,
                    activated,
                )?,
            )?
        }
        CloudflareDurableObjectRequestV1::SigningWorkerOutputActiveStateGet { lookup } => {
            lookup.validate()?;
            let active_signing_worker_state =
                match worker_storage_get::<ActiveSigningWorkerStateV1>(
                    storage,
                    &storage_key,
                    call.operation_kind(),
                )
                .await?
                {
                    Some(active_signing_worker_state) => active_signing_worker_state,
                    None => recover_signing_worker_output_active_state_index_v1(
                        binding,
                        storage,
                        lookup,
                        call.operation_kind(),
                    )
                    .await?
                    .ok_or_else(|| {
                        RouterAbProtocolError::new(
                            RouterAbProtocolErrorCode::MissingLocalBinding,
                            "active SigningWorker state is missing",
                        )
                    })?,
                };
            lookup.validate_active_state(&active_signing_worker_state)?;
            CloudflareDurableObjectResponseV1::signing_worker_output_active_state_get(
                active_signing_worker_state,
            )?
        }
        CloudflareDurableObjectRequestV1::SigningWorkerOutputMaterialGet { lookup } => {
            lookup.validate()?;
            let record = require_existing_record_v1(
                worker_storage_get::<CloudflareSigningWorkerOutputActivationRecordV1>(
                    storage,
                    &storage_key,
                    call.operation_kind(),
                )
                .await?,
                "SigningWorker-output material is missing",
            )?;
            record.validate()?;
            if record.active_signing_worker_state() != &lookup.active_signing_worker_state {
                return Err(RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                    "SigningWorker-output material active state does not match lookup",
                ));
            }
            lookup.validate_material(record.material())?;
            CloudflareDurableObjectResponseV1::signing_worker_output_material_get(
                record.into_material(),
            )?
        }
        CloudflareDurableObjectRequestV1::SigningWorkerRound1Put { record } => {
            record.validate()?;
            let stored = validate_idempotent_put_record_v1(
                worker_storage_get::<CloudflareSigningWorkerRound1RecordV1>(
                    storage,
                    &storage_key,
                    call.operation_kind(),
                )
                .await?,
                record,
                CloudflareSigningWorkerRound1RecordV1::validate,
                "SigningWorker round-1 handle is already stored for different material",
            )?;
            if stored {
                worker_storage_put(storage, &storage_key, record.clone(), call.operation_kind())
                    .await?;
            }
            CloudflareDurableObjectResponseV1::signing_worker_round1_put(
                CloudflareSigningWorkerRound1PutReceiptV1::from_record(record, stored)?,
            )?
        }
        CloudflareDurableObjectRequestV1::SigningWorkerRound1Take { lookup } => {
            lookup.validate()?;
            let record = require_existing_record_v1(
                worker_storage_get::<CloudflareSigningWorkerRound1RecordV1>(
                    storage,
                    &storage_key,
                    call.operation_kind(),
                )
                .await?,
                "SigningWorker round-1 nonce material is missing",
            )?;
            record.validate_for_lookup(lookup)?;
            worker_storage_delete(storage, &storage_key, call.operation_kind()).await?;
            CloudflareDurableObjectResponseV1::signing_worker_round1_take(record)?
        }
        CloudflareDurableObjectRequestV1::SigningWorkerRound1CleanupExpired { cleanup } => {
            cleanup.validate()?;
            let records_removed = worker_storage_cleanup_expired_values(
                storage,
                &call.signing_worker_round1_storage_prefix(),
                cleanup.now_unix_ms,
                call.operation_kind(),
                cloudflare_signing_worker_round1_expires_at_ms_v1,
            )
            .await?;
            CloudflareDurableObjectResponseV1::signing_worker_round1_cleanup_expired(
                single_index_cleanup_report_v1(cleanup.now_unix_ms, records_removed)?,
            )?
        }
        CloudflareDurableObjectRequestV1::SigningWorkerEcdsaPoolMutate { command } => {
            let current = worker_storage_get::<CloudflareSigningWorkerEcdsaPoolLifecycleRecordV1>(
                storage,
                &storage_key,
                call.operation_kind(),
            )
            .await?;
            let outcome =
                apply_cloudflare_signing_worker_ecdsa_pool_command_v1(current, command.clone())?;
            schedule_cloudflare_signing_worker_ecdsa_pool_cleanup_v1(
                storage,
                outcome.record().cleanup_deadline_ms(),
                &call.signing_worker_ecdsa_pool_storage_prefix(),
            )
            .await?;
            worker_storage_put(
                storage,
                &storage_key,
                outcome.record().clone(),
                call.operation_kind(),
            )
            .await?;
            CloudflareDurableObjectResponseV1::signing_worker_ecdsa_pool_mutate(outcome)?
        }
    };
    response.validate_for_request(&call.request)?;
    Ok(response)
}

#[cfg(feature = "workers-rs")]
// Repair the denormalized active-state index from the canonical activation record.
async fn recover_signing_worker_output_active_state_index_v1(
    binding: &CloudflareDurableObjectBindingV1,
    storage: &worker::Storage,
    lookup: &CloudflareActiveSigningWorkerStateLookupV1,
    operation_kind: CloudflareDurableObjectOperationKindV1,
) -> RouterAbProtocolResult<Option<ActiveSigningWorkerStateV1>> {
    binding.validate()?;
    lookup.validate()?;
    let output_prefix = format!("{}signing-worker-output/", binding.key_prefix);
    let values = storage
        .list_with_options(worker::ListOptions::new().prefix(&output_prefix))
        .await
        .map_err(|error| {
            worker_storage_error(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                operation_kind,
                &output_prefix,
                format!("Durable Object activation-record list failed: {error}"),
            )
        })?;
    let keys = worker::js_sys::Array::from(&values.keys());
    let mut recovered: Option<ActiveSigningWorkerStateV1> = None;
    for key in keys.iter() {
        let material_key = key.as_string().ok_or_else(|| {
            worker_storage_error(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                operation_kind,
                &output_prefix,
                "Durable Object activation-record list returned a non-string key".to_owned(),
            )
        })?;
        let Some(record) = worker_storage_get::<CloudflareSigningWorkerOutputActivationRecordV1>(
            storage,
            &material_key,
            operation_kind,
        )
        .await?
        else {
            continue;
        };
        record.validate()?;
        let candidate = record.active_signing_worker_state();
        if lookup.validate_active_state(candidate).is_err() {
            continue;
        }
        if recovered
            .as_ref()
            .is_some_and(|existing| existing != candidate)
        {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "multiple conflicting SigningWorker activation records match active-state lookup",
            ));
        }
        recovered = Some(candidate.clone());
    }
    let Some(active_signing_worker_state) = recovered else {
        return Ok(None);
    };
    let active_state_key = format!(
        "{}active-signing-worker/{}/{}/{}",
        binding.key_prefix, lookup.account_id, lookup.session_id, lookup.signing_worker_id
    );
    worker_storage_put(
        storage,
        &active_state_key,
        active_signing_worker_state.clone(),
        operation_kind,
    )
    .await?;
    let committed = worker_storage_get::<ActiveSigningWorkerStateV1>(
        storage,
        &active_state_key,
        operation_kind,
    )
    .await?;
    if committed.as_ref() != Some(&active_signing_worker_state) {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "recovered active SigningWorker state did not commit exact durable state",
        ));
    }
    Ok(Some(active_signing_worker_state))
}

#[cfg(feature = "workers-rs")]
async fn persist_cloudflare_signing_worker_output_activation_pair_v1(
    storage: &worker::Storage,
    material_key: &str,
    active_state_key: &str,
    record: &CloudflareSigningWorkerOutputActivationRecordV1,
    active_state: &ActiveSigningWorkerStateV1,
    operation_kind: CloudflareDurableObjectOperationKindV1,
) -> RouterAbProtocolResult<()> {
    let writes = worker::js_sys::Object::new();
    set_durable_object_put_multiple_value(
        &writes,
        material_key,
        record,
        "SigningWorker ECDSA activation material",
    )?;
    set_durable_object_put_multiple_value(
        &writes,
        active_state_key,
        active_state,
        "SigningWorker ECDSA active state",
    )?;
    storage.put_multiple_raw(writes).await.map_err(|error| {
        worker_storage_error(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            operation_kind,
            material_key,
            format!("Durable Object atomic activation write failed: {error}"),
        )
    })?;
    let committed_record = worker_storage_get::<CloudflareSigningWorkerOutputActivationRecordV1>(
        storage,
        material_key,
        operation_kind,
    )
    .await?;
    let committed_active_state =
        worker_storage_get::<ActiveSigningWorkerStateV1>(storage, active_state_key, operation_kind)
            .await?;
    if committed_record.as_ref() != Some(record)
        || committed_active_state.as_ref() != Some(active_state)
    {
        return Err(worker_storage_error(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            operation_kind,
            material_key,
            "Durable Object activation read-back did not match the exact committed pair".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(feature = "workers-rs")]
async fn schedule_cloudflare_signing_worker_ecdsa_pool_cleanup_v1(
    storage: &worker::Storage,
    cleanup_deadline_ms: Option<u64>,
    storage_prefix: &str,
) -> RouterAbProtocolResult<()> {
    let Some(cleanup_deadline_ms) = cleanup_deadline_ms else {
        return Ok(());
    };
    let cleanup_deadline_ms = i64::try_from(cleanup_deadline_ms).map_err(|_| {
        worker_storage_error(
            RouterAbProtocolErrorCode::InvalidTimeRange,
            CloudflareDurableObjectOperationKindV1::SigningWorkerEcdsaPoolMutate,
            storage_prefix,
            "ECDSA cleanup deadline exceeds the Durable Object alarm range".to_owned(),
        )
    })?;
    let current_alarm = storage.get_alarm().await.map_err(|err| {
        worker_storage_error(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            CloudflareDurableObjectOperationKindV1::SigningWorkerEcdsaPoolMutate,
            storage_prefix,
            format!("Durable Object alarm read failed: {err}"),
        )
    })?;
    if current_alarm.is_none_or(|current| cleanup_deadline_ms < current) {
        storage
            .set_alarm(cleanup_deadline_ms)
            .await
            .map_err(|err| {
                worker_storage_error(
                    RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                    CloudflareDurableObjectOperationKindV1::SigningWorkerEcdsaPoolMutate,
                    storage_prefix,
                    format!("Durable Object alarm scheduling failed: {err}"),
                )
            })?;
    }
    Ok(())
}

#[cfg(feature = "workers-rs")]
pub(super) async fn handle_cloudflare_signing_worker_ecdsa_pool_alarm_v1(
    binding: &CloudflareDurableObjectBindingV1,
    storage: &worker::Storage,
) -> worker::Result<worker::Response> {
    let now_unix_ms = worker::Date::now().as_millis();
    match cleanup_expired_cloudflare_signing_worker_ecdsa_pool_records_v1(
        binding,
        storage,
        now_unix_ms,
    )
    .await
    {
        Ok(records_burned) => worker::Response::ok(format!(
            "SigningWorker ECDSA pool cleanup burned {records_burned} record(s)"
        )),
        Err(err) => Err(worker::Error::RustError(format!(
            "{:?}: {}",
            err.code(),
            err.message()
        ))),
    }
}

#[cfg(feature = "workers-rs")]
async fn cleanup_expired_cloudflare_signing_worker_ecdsa_pool_records_v1(
    binding: &CloudflareDurableObjectBindingV1,
    storage: &worker::Storage,
    now_unix_ms: u64,
) -> RouterAbProtocolResult<u64> {
    let operation_kind = CloudflareDurableObjectOperationKindV1::SigningWorkerEcdsaPoolMutate;
    let storage_prefix = format!("{}signing-worker-ecdsa-pool/", binding.key_prefix);
    let values = storage
        .list_with_options(worker::ListOptions::new().prefix(&storage_prefix))
        .await
        .map_err(|err| {
            worker_storage_error(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                operation_kind,
                &storage_prefix,
                format!("Durable Object ECDSA pool list failed: {err}"),
            )
        })?;
    let keys = worker::js_sys::Array::from(&values.keys());
    let mut records_burned = 0u64;
    let mut next_deadline_ms = None;
    for key in keys.iter() {
        let storage_key = key.as_string().ok_or_else(|| {
            worker_storage_error(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                operation_kind,
                &storage_prefix,
                "Durable Object ECDSA pool list returned a non-string key".to_owned(),
            )
        })?;
        let Some(record) = worker_storage_get::<CloudflareSigningWorkerEcdsaPoolLifecycleRecordV1>(
            storage,
            &storage_key,
            operation_kind,
        )
        .await?
        else {
            continue;
        };
        let Some(deadline_ms) = record.cleanup_deadline_ms() else {
            continue;
        };
        if deadline_ms <= now_unix_ms {
            let replacement = record.expire(now_unix_ms)?;
            worker_storage_put(storage, &storage_key, replacement, operation_kind).await?;
            records_burned = records_burned.checked_add(1).ok_or_else(|| {
                worker_storage_error(
                    RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                    operation_kind,
                    &storage_prefix,
                    "ECDSA cleanup count overflowed".to_owned(),
                )
            })?;
        } else {
            next_deadline_ms =
                Some(next_deadline_ms.map_or(deadline_ms, |current: u64| current.min(deadline_ms)));
        }
    }
    match next_deadline_ms {
        Some(deadline_ms) => storage
            .set_alarm(i64::try_from(deadline_ms).map_err(|_| {
                worker_storage_error(
                    RouterAbProtocolErrorCode::InvalidTimeRange,
                    operation_kind,
                    &storage_prefix,
                    "ECDSA cleanup deadline exceeds the Durable Object alarm range".to_owned(),
                )
            })?)
            .await
            .map_err(|err| {
                worker_storage_error(
                    RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                    operation_kind,
                    &storage_prefix,
                    format!("Durable Object alarm rescheduling failed: {err}"),
                )
            })?,
        None => storage.delete_alarm().await.map_err(|err| {
            worker_storage_error(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                operation_kind,
                &storage_prefix,
                format!("Durable Object alarm deletion failed: {err}"),
            )
        })?,
    }
    Ok(records_burned)
}

/// Executes a typed Durable Object call through a real `workers-rs` Env.
#[cfg(feature = "workers-rs")]
pub async fn execute_cloudflare_durable_object_call_v1(
    env: &worker::Env,
    call: &CloudflareDurableObjectCallV1,
) -> RouterAbProtocolResult<CloudflareDurableObjectResponseV1> {
    call.validate()?;
    let namespace = env
        .durable_object(&call.binding.binding_name)
        .map_err(|err| {
            worker_do_error(
                RouterAbProtocolErrorCode::MissingLocalBinding,
                call,
                format!("Durable Object namespace lookup failed: {err}"),
            )
        })?;
    let stub = namespace
        .get_by_name(&call.binding.object_name)
        .map_err(|err| {
            worker_do_error(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                call,
                format!("Durable Object stub lookup failed: {err}"),
            )
        })?;
    let request_body = serde_json::to_string(&call.request).map_err(|err| {
        worker_do_error(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            call,
            format!("Durable Object request serialization failed: {err}"),
        )
    })?;
    let mut init = worker::RequestInit::new();
    init.with_method(worker::Method::Post)
        .with_body(Some(worker::wasm_bindgen::JsValue::from_str(&request_body)));
    let request =
        worker::Request::new_with_init(&call.durable_object_url(), &init).map_err(|err| {
            worker_do_error(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                call,
                format!("Durable Object request construction failed: {err}"),
            )
        })?;
    let mut response = stub.fetch_with_request(request).await.map_err(|err| {
        worker_do_error(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            call,
            format!("Durable Object request failed: {err}"),
        )
    })?;
    let status = response.status_code();
    if !(200..=299).contains(&status) {
        let body = response.text().await.unwrap_or_default();
        return Err(worker_do_error(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            call,
            format!("Durable Object returned HTTP status {status}: {body}"),
        ));
    }
    let parsed = response
        .json::<CloudflareDurableObjectResponseV1>()
        .await
        .map_err(|err| {
            worker_do_error(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                call,
                format!("Durable Object response parsing failed: {err}"),
            )
        })?;
    parsed.validate_for_request(&call.request)?;
    Ok(parsed)
}

/// Executes a private JSON call against a role-owned Durable Object route.
#[cfg(feature = "workers-rs")]
pub(crate) async fn execute_cloudflare_durable_object_custom_json_call_v1<TRequest, TResponse>(
    env: &worker::Env,
    binding: &CloudflareDurableObjectBindingV1,
    path: &str,
    request: &TRequest,
) -> RouterAbProtocolResult<TResponse>
where
    TRequest: Serialize,
    TResponse: DeserializeOwned,
{
    binding.validate_visible_to(CloudflareWorkerRoleV1::SigningWorker)?;
    require_non_empty("Durable Object custom path", path)?;
    let namespace = env.durable_object(&binding.binding_name).map_err(|error| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MissingLocalBinding,
            format!("Durable Object namespace lookup failed: {error}"),
        )
    })?;
    let stub = namespace
        .get_by_name(&binding.object_name)
        .map_err(|error| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                format!("Durable Object stub lookup failed: {error}"),
            )
        })?;
    let request_body = serde_json::to_string(request).map_err(|error| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("Durable Object custom request encoding failed: {error}"),
        )
    })?;
    let mut init = worker::RequestInit::new();
    init.with_method(worker::Method::Post)
        .with_body(Some(worker::wasm_bindgen::JsValue::from_str(&request_body)));
    let url = format!("https://router-ab-do.internal{path}");
    let request = worker::Request::new_with_init(&url, &init).map_err(|error| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            format!("Durable Object custom request construction failed: {error}"),
        )
    })?;
    let mut response = stub.fetch_with_request(request).await.map_err(|error| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            format!("Durable Object custom request failed: {error}"),
        )
    })?;
    let status = response.status_code();
    if !(200..=299).contains(&status) {
        let body = response.text().await.unwrap_or_default();
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            format!("Durable Object custom request returned HTTP {status}: {body}"),
        ));
    }
    response.json::<TResponse>().await.map_err(|error| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("Durable Object custom response JSON is invalid: {error}"),
        )
    })
}
