use super::handlers::{
    require_existing_record_v1, validate_idempotent_put_record_v1,
    validate_router_replay_reservation_v1,
    validate_signing_worker_output_active_state_replacement_v1,
};
use super::*;

/// Handles a real `workers-rs` Durable Object fetch event for Router/A/B storage.
#[cfg(feature = "workers-rs")]
pub async fn handle_cloudflare_durable_object_fetch_v1(
    binding: &CloudflareDurableObjectBindingV1,
    mut request: worker::Request,
    storage: &worker::Storage,
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
    match handle_cloudflare_durable_object_worker_request_v1(binding, parsed, storage).await {
        Ok(response) => worker::Response::from_json(&response),
        Err(err) => worker::Response::error(
            format!("{:?}: {}", err.code(), err.message()),
            durable_object_error_status(err.code()),
        ),
    }
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
    handle_cloudflare_durable_object_fetch_v1(&binding, request, &storage).await
}

#[cfg(feature = "workers-rs")]
fn cloudflare_durable_object_class_binding_v1(
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

/// Handles a parsed Durable Object request against real Cloudflare storage.
#[cfg(feature = "workers-rs")]
pub async fn handle_cloudflare_durable_object_worker_request_v1(
    binding: &CloudflareDurableObjectBindingV1,
    request: CloudflareDurableObjectRequestV1,
    storage: &worker::Storage,
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
        CloudflareDurableObjectRequestV1::RootShareStartupMetadata { lookup } => {
            let metadata = require_existing_record_v1(
                worker_storage_get::<CloudflareRootShareStartupMetadataV1>(
                    storage,
                    &storage_key,
                    call.operation_kind(),
                )
                .await?,
                "root-share startup metadata is missing",
            )?;
            metadata.validate_matches_lookup(lookup)?;
            CloudflareDurableObjectResponseV1::root_share_startup_metadata(metadata)?
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
            let policy = worker_storage_get::<CloudflareRouterProjectPolicyRecordV1>(
                storage,
                &storage_key,
                call.operation_kind(),
            )
            .await?
            .ok_or_else(|| {
                RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::MissingLocalBinding,
                    "router project-policy record is missing",
                )
            })?
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
            let policy = worker_storage_get::<CloudflareRouterProjectPolicyRecordV1>(
                storage,
                &storage_key,
                call.operation_kind(),
            )
            .await?
            .ok_or_else(|| {
                RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::MissingLocalBinding,
                    "router project-policy record is missing",
                )
            })?
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
            let (active_signing_worker_state, activated) = match worker_storage_get::<
                CloudflareSigningWorkerOutputActivationRecordV1,
            >(
                storage,
                &storage_key,
                call.operation_kind(),
            )
            .await?
            {
                Some(existing) => {
                    existing.validate()?;
                    if existing.activation == *activation && existing.material == *material {
                        (existing.active_signing_worker_state, false)
                    } else {
                        return Err(RouterAbProtocolError::new(
                                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                                "server-output activation conflicts with existing activation or material",
                            ));
                    }
                }
                None => {
                    let active_signing_worker_state =
                        cloudflare_active_signing_worker_state_from_activation_request_v1(
                            activation,
                            storage_key.clone(),
                            *activated_at_ms,
                        )?;
                    let existing_active_state = worker_storage_get::<ActiveSigningWorkerStateV1>(
                        storage,
                        &active_state_index_key,
                        call.operation_kind(),
                    )
                    .await?;
                    validate_signing_worker_output_active_state_replacement_v1(
                        existing_active_state.as_ref(),
                        &active_signing_worker_state,
                    )?;
                    let record = CloudflareSigningWorkerOutputActivationRecordV1::new(
                        activation.clone(),
                        active_signing_worker_state.clone(),
                        material.clone(),
                    )?;
                    worker_storage_put(storage, &storage_key, record, call.operation_kind())
                        .await?;
                    worker_storage_put(
                        storage,
                        &active_state_index_key,
                        active_signing_worker_state.clone(),
                        call.operation_kind(),
                    )
                    .await?;
                    (active_signing_worker_state, true)
                }
            };
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
        CloudflareDurableObjectRequestV1::SigningWorkerDirectActivationPut { delivery } => {
            delivery.validate()?;
            let outcome = match worker_storage_get::<
                CloudflareSigningWorkerDirectRecipientProofBundleActivationPendingRecordV1,
            >(storage, &storage_key, call.operation_kind())
            .await?
            {
                Some(existing) => existing.apply_delivery(delivery.clone())?,
                None => {
                    let record =
                        CloudflareSigningWorkerDirectRecipientProofBundleActivationPendingRecordV1::new(
                            delivery.clone(),
                        )?;
                    worker_storage_put(
                        storage,
                        &storage_key,
                        record.clone(),
                        call.operation_kind(),
                    )
                    .await?;
                    CloudflareSigningWorkerDirectRecipientProofBundleActivationPutOutcomeV1::pending(
                        record,
                    )?
                }
            };
            CloudflareDurableObjectResponseV1::signing_worker_direct_activation_put(outcome)?
        }
        CloudflareDurableObjectRequestV1::SigningWorkerOutputActiveStateGet { lookup } => {
            lookup.validate()?;
            let active_signing_worker_state = require_existing_record_v1(
                worker_storage_get::<ActiveSigningWorkerStateV1>(
                    storage,
                    &storage_key,
                    call.operation_kind(),
                )
                .await?,
                "active SigningWorker state is missing",
            )?;
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
            if record.active_signing_worker_state != lookup.active_signing_worker_state {
                return Err(RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                    "SigningWorker-output material active state does not match lookup",
                ));
            }
            lookup.validate_material(&record.material)?;
            CloudflareDurableObjectResponseV1::signing_worker_output_material_get(record.material)?
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
        CloudflareDurableObjectRequestV1::SigningWorkerEd25519PresignPoolPut { record } => {
            record.validate()?;
            let stored = validate_idempotent_put_record_v1(
                worker_storage_get::<CloudflareSigningWorkerEd25519PresignPoolRecordV1>(
                    storage,
                    &storage_key,
                    call.operation_kind(),
                )
                .await?,
                record,
                CloudflareSigningWorkerEd25519PresignPoolRecordV1::validate,
                "SigningWorker Ed25519 presign-pool id is already stored for different material",
            )?;
            if stored {
                worker_storage_put(storage, &storage_key, record.clone(), call.operation_kind())
                    .await?;
            }
            CloudflareDurableObjectResponseV1::signing_worker_ed25519_presign_pool_put(
                CloudflareSigningWorkerEd25519PresignPoolPutReceiptV1::from_record(record, stored)?,
            )?
        }
        CloudflareDurableObjectRequestV1::SigningWorkerEd25519PresignPoolTake { lookup } => {
            lookup.validate()?;
            let record = require_existing_record_v1(
                worker_storage_get::<CloudflareSigningWorkerEd25519PresignPoolRecordV1>(
                    storage,
                    &storage_key,
                    call.operation_kind(),
                )
                .await?,
                "SigningWorker Ed25519 presign-pool material is missing",
            )?;
            record.validate_for_lookup(lookup)?;
            worker_storage_delete(storage, &storage_key, call.operation_kind()).await?;
            CloudflareDurableObjectResponseV1::signing_worker_ed25519_presign_pool_take(record)?
        }
        CloudflareDurableObjectRequestV1::SigningWorkerEd25519PresignPoolCleanupExpired {
            cleanup,
        } => {
            cleanup.validate()?;
            let records_removed = worker_storage_cleanup_expired_values(
                storage,
                &call.signing_worker_ed25519_presign_pool_storage_prefix(),
                cleanup.now_unix_ms,
                call.operation_kind(),
                cloudflare_signing_worker_ed25519_presign_pool_expires_at_ms_v1,
            )
            .await?;
            CloudflareDurableObjectResponseV1::signing_worker_ed25519_presign_pool_cleanup_expired(
                single_index_cleanup_report_v1(cleanup.now_unix_ms, records_removed)?,
            )?
        }
        CloudflareDurableObjectRequestV1::SigningWorkerEcdsaPresignaturePut { record } => {
            record.validate()?;
            let stored = validate_idempotent_put_record_v1(
                worker_storage_get::<CloudflareSigningWorkerEcdsaPresignatureRecordV1>(
                    storage,
                    &storage_key,
                    call.operation_kind(),
                )
                .await?,
                record,
                CloudflareSigningWorkerEcdsaPresignatureRecordV1::validate,
                "SigningWorker ECDSA presignature id is already stored for different material",
            )?;
            if stored {
                worker_storage_put(storage, &storage_key, record.clone(), call.operation_kind())
                    .await?;
            }
            CloudflareDurableObjectResponseV1::signing_worker_ecdsa_presignature_put(
                CloudflareSigningWorkerEcdsaPresignaturePutReceiptV1::from_record(record, stored)?,
            )?
        }
        CloudflareDurableObjectRequestV1::SigningWorkerEcdsaPresignatureTake { lookup } => {
            lookup.validate()?;
            let record = require_existing_record_v1(
                worker_storage_get::<CloudflareSigningWorkerEcdsaPresignatureRecordV1>(
                    storage,
                    &storage_key,
                    call.operation_kind(),
                )
                .await?,
                "SigningWorker ECDSA presignature material is missing",
            )?;
            record.validate_for_lookup(lookup)?;
            worker_storage_delete(storage, &storage_key, call.operation_kind()).await?;
            CloudflareDurableObjectResponseV1::signing_worker_ecdsa_presignature_take(record)?
        }
        CloudflareDurableObjectRequestV1::SigningWorkerEcdsaPresignatureCleanupExpired {
            cleanup,
        } => {
            cleanup.validate()?;
            let records_removed = worker_storage_cleanup_expired_values(
                storage,
                &call.signing_worker_ecdsa_presignature_storage_prefix(),
                cleanup.now_unix_ms,
                call.operation_kind(),
                cloudflare_signing_worker_ecdsa_presignature_expires_at_ms_v1,
            )
            .await?;
            CloudflareDurableObjectResponseV1::signing_worker_ecdsa_presignature_cleanup_expired(
                single_index_cleanup_report_v1(cleanup.now_unix_ms, records_removed)?,
            )?
        }
        CloudflareDurableObjectRequestV1::SigningWorkerEcdsaPresignaturePoolPut { record } => {
            record.validate()?;
            let stored = validate_idempotent_put_record_v1(
                worker_storage_get::<CloudflareSigningWorkerEcdsaPresignaturePoolRecordV1>(
                    storage,
                    &storage_key,
                    call.operation_kind(),
                )
                .await?,
                record,
                CloudflareSigningWorkerEcdsaPresignaturePoolRecordV1::validate,
                "SigningWorker ECDSA presignature pool id is already stored for different material",
            )?;
            if stored {
                worker_storage_put(storage, &storage_key, record.clone(), call.operation_kind())
                    .await?;
            }
            CloudflareDurableObjectResponseV1::signing_worker_ecdsa_presignature_pool_put(
                CloudflareSigningWorkerEcdsaPresignaturePoolPutReceiptV1::from_record(
                    record, stored,
                )?,
            )?
        }
        CloudflareDurableObjectRequestV1::SigningWorkerEcdsaPresignaturePoolTake { lookup } => {
            lookup.validate()?;
            let record = require_existing_record_v1(
                worker_storage_get::<CloudflareSigningWorkerEcdsaPresignaturePoolRecordV1>(
                    storage,
                    &storage_key,
                    call.operation_kind(),
                )
                .await?,
                "SigningWorker ECDSA presignature pool material is missing",
            )?;
            record.validate_for_lookup(lookup)?;
            worker_storage_delete(storage, &storage_key, call.operation_kind()).await?;
            CloudflareDurableObjectResponseV1::signing_worker_ecdsa_presignature_pool_take(record)?
        }
        CloudflareDurableObjectRequestV1::SigningWorkerEcdsaPresignaturePoolCleanupExpired {
            cleanup,
        } => {
            cleanup.validate()?;
            let records_removed = worker_storage_cleanup_expired_values(
                storage,
                &call.signing_worker_ecdsa_presignature_pool_storage_prefix(),
                cleanup.now_unix_ms,
                call.operation_kind(),
                cloudflare_signing_worker_ecdsa_presignature_pool_expires_at_ms_v1,
            )
            .await?;
            CloudflareDurableObjectResponseV1::signing_worker_ecdsa_presignature_pool_cleanup_expired(
                CloudflareExpiredStateCleanupReportV1::new(
                    cleanup.now_unix_ms,
                    records_removed,
                    0,
                )?,
            )?
        }
    };
    response.validate_for_request(&call.request)?;
    Ok(response)
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
        return Err(worker_do_error(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            call,
            format!("Durable Object returned HTTP status {status}"),
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
