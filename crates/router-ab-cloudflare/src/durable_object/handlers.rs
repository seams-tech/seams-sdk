use super::*;

pub(super) fn validate_signing_worker_output_active_state_replacement_v1(
    existing: Option<&ActiveSigningWorkerStateV1>,
    replacement: &ActiveSigningWorkerStateV1,
) -> RouterAbProtocolResult<()> {
    replacement.validate()?;
    let Some(existing) = existing else {
        return Ok(());
    };
    existing.validate()?;
    if existing.account_id != replacement.account_id
        || existing.session_id != replacement.session_id
        || existing.signing_worker.server_id != replacement.signing_worker.server_id
    {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "SigningWorker-output activation cannot replace a different active SigningWorker scope",
        ));
    }
    if replacement.activated_at_ms <= existing.activated_at_ms {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "SigningWorker-output activation must be newer than current active state",
        ));
    }
    Ok(())
}

pub(super) fn require_existing_record_v1<T>(
    record: Option<T>,
    missing_message: &'static str,
) -> RouterAbProtocolResult<T> {
    record.ok_or_else(|| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MissingLocalBinding,
            missing_message,
        )
    })
}

pub(super) fn validate_idempotent_put_record_v1<T>(
    existing: Option<T>,
    record: &T,
    validate_existing: fn(&T) -> RouterAbProtocolResult<()>,
    conflict_message: &'static str,
) -> RouterAbProtocolResult<bool>
where
    T: PartialEq,
{
    let Some(existing) = existing else {
        return Ok(true);
    };
    validate_existing(&existing)?;
    if existing == *record {
        return Ok(false);
    }
    Err(RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::ReplayedLocalRequest,
        conflict_message,
    ))
}

pub(super) fn validate_router_replay_reservation_v1(
    existing: Option<CloudflareReplayReserveRequestV1>,
    request: &CloudflareReplayReserveRequestV1,
) -> RouterAbProtocolResult<bool> {
    let Some(existing) = existing else {
        return Ok(true);
    };
    if existing == *request {
        return Ok(false);
    }
    Err(RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::ReplayedLocalRequest,
        "router replay request id is already reserved for different material",
    ))
}

fn router_wallet_budget_record_v1(
    storage: &impl CloudflareDurableObjectStorageV1,
    storage_key: &str,
) -> RouterAbProtocolResult<CloudflareRouterWalletBudgetGrantRecordV1> {
    require_existing_record_v1(
        storage.router_wallet_budget(storage_key)?,
        "wallet budget grant is missing",
    )
}

/// Handles a validated Durable Object operation against typed storage.
pub fn handle_cloudflare_durable_object_call_v1(
    call: &CloudflareDurableObjectCallV1,
    storage: &mut impl CloudflareDurableObjectStorageV1,
) -> RouterAbProtocolResult<CloudflareDurableObjectResponseV1> {
    call.validate()?;
    let storage_key = call.storage_key();
    let response = match &call.request {
        CloudflareDurableObjectRequestV1::RootShareHas { lookup } => {
            let present = match storage.root_share_startup_metadata(&storage_key)? {
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
                storage.root_share_startup_metadata(&storage_key)?,
                "root-share startup metadata is missing",
            )?;
            metadata.validate_matches_lookup(lookup)?;
            CloudflareDurableObjectResponseV1::root_share_startup_metadata(metadata)?
        }
        CloudflareDurableObjectRequestV1::RootShareRewrapStartupMetadata { request } => {
            let existing = require_existing_record_v1(
                storage.root_share_startup_metadata(&storage_key)?,
                "root-share startup metadata is missing",
            )?;
            request.validate_replaces(&existing)?;
            storage.put_root_share_startup_metadata(
                &storage_key,
                request.replacement_metadata.clone(),
            )?;
            CloudflareDurableObjectResponseV1::root_share_rewrap_startup_metadata(
                CloudflareRootShareRewrapReceiptV1::new(request, &existing)?,
            )?
        }
        CloudflareDurableObjectRequestV1::RouterReplayReserve { request } => {
            let request_index_key = call.replay_request_index_storage_key()?;
            let reserved = validate_router_replay_reservation_v1(
                storage.replay_reservation_by_request_id(&request_index_key)?,
                request,
            )?;
            if reserved {
                storage.put_replay_reservation(
                    &request_index_key,
                    &storage_key,
                    request.clone(),
                )?;
            }
            CloudflareDurableObjectResponseV1::router_replay_reserve(
                CloudflareReplayReserveResponseV1::new(request.request_id.clone(), reserved)?,
            )?
        }
        CloudflareDurableObjectRequestV1::RouterReplayCleanupExpired { cleanup } => {
            cleanup.validate()?;
            CloudflareDurableObjectResponseV1::router_replay_cleanup_expired(
                storage.cleanup_expired_replay_reservations(cleanup.now_unix_ms)?,
            )?
        }
        CloudflareDurableObjectRequestV1::RouterLifecyclePutPublicState { state } => {
            let previous = storage.router_lifecycle_state(&storage_key)?;
            RouterAbLifecycleStateV1::validate_transition_from(previous.as_ref(), state)?;
            storage.put_router_lifecycle_state(&storage_key, state.clone())?;
            CloudflareDurableObjectResponseV1::router_lifecycle_put_public_state(
                CloudflareLifecyclePutReceiptV1::new(state.scope().lifecycle_id.clone(), true)?,
            )?
        }
        CloudflareDurableObjectRequestV1::DerivationCeremonyPutState { ceremony } => {
            let previous = storage.derivation_ceremony(&storage_key)?;
            CloudflareDerivationCeremonyV1::validate_transition_from(previous.as_ref(), ceremony)?;
            let stored = previous.as_ref() != Some(ceremony);
            if stored {
                storage.put_derivation_ceremony(&storage_key, ceremony.clone())?;
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
            let policy = storage
                .router_project_policy(&storage_key)?
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
            let quota = match storage.router_quota(&storage_key)? {
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
                    storage.put_router_quota(&storage_key, reservation)?;
                    CloudflareRouterQuotaCheckV1::Accepted {
                        request_id: request.request_nonce.clone(),
                    }
                }
            };
            CloudflareDurableObjectResponseV1::router_quota_evaluate(quota)?
        }
        CloudflareDurableObjectRequestV1::RouterQuotaCleanupExpired { cleanup } => {
            cleanup.validate()?;
            CloudflareDurableObjectResponseV1::router_quota_cleanup_expired(
                storage.cleanup_expired_router_quota_reservations(cleanup.now_unix_ms)?,
            )?
        }
        CloudflareDurableObjectRequestV1::RouterAbuseEvaluate { request } => {
            request.validate()?;
            let abuse = match storage.router_abuse(&storage_key)? {
                Some(record) => {
                    record.validate()?;
                    record.outcome
                }
                None => CloudflareRouterAbuseCheckV1::Allowed,
            };
            CloudflareDurableObjectResponseV1::router_abuse_evaluate(abuse)?
        }
        CloudflareDurableObjectRequestV1::RouterNormalSigningProjectPolicyEvaluate { request } => {
            let policy = storage
                .router_project_policy(&storage_key)?
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
            let quota = match storage.router_quota(&storage_key)? {
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
                    storage.put_router_quota(&storage_key, reservation)?;
                    CloudflareRouterQuotaCheckV1::Accepted {
                        request_id: request.request_id.clone(),
                    }
                }
            };
            CloudflareDurableObjectResponseV1::router_normal_signing_quota_evaluate(quota)?
        }
        CloudflareDurableObjectRequestV1::RouterNormalSigningAbuseEvaluate { request } => {
            request.validate()?;
            let abuse = match storage.router_abuse(&storage_key)? {
                Some(record) => {
                    record.validate()?;
                    record.outcome
                }
                None => CloudflareRouterAbuseCheckV1::Allowed,
            };
            CloudflareDurableObjectResponseV1::router_normal_signing_abuse_evaluate(abuse)?
        }
        CloudflareDurableObjectRequestV1::RouterWalletBudgetPutGrant { request } => {
            let record = match storage.router_wallet_budget(&storage_key)? {
                Some(existing) => {
                    existing.validate_matches_put_request(request)?;
                    existing
                }
                None => {
                    let record =
                        CloudflareRouterWalletBudgetGrantRecordV1::from_put_request(request)?;
                    storage.put_router_wallet_budget(&storage_key, record.clone())?;
                    record
                }
            };
            CloudflareDurableObjectResponseV1::router_wallet_budget_grant_put(
                record.status_at(request.now_unix_ms)?,
            )?
        }
        CloudflareDurableObjectRequestV1::RouterWalletBudgetReserve { request } => {
            let mut record = router_wallet_budget_record_v1(storage, &storage_key)?;
            let reservation_id = record.reserve(request)?;
            let status = record.status_at(request.now_unix_ms)?;
            storage.put_router_wallet_budget(&storage_key, record)?;
            CloudflareDurableObjectResponseV1::router_wallet_budget_reserved(
                reservation_id,
                status,
            )?
        }
        CloudflareDurableObjectRequestV1::RouterWalletBudgetValidate { identity } => {
            let mut record = router_wallet_budget_record_v1(storage, &storage_key)?;
            record.validate_reservation(identity)?;
            let status = record.status_at(identity.now_unix_ms)?;
            storage.put_router_wallet_budget(&storage_key, record)?;
            CloudflareDurableObjectResponseV1::router_wallet_budget_validated(
                identity.reservation_id.clone(),
                status,
            )?
        }
        CloudflareDurableObjectRequestV1::RouterWalletBudgetCommit { identity } => {
            let mut record = router_wallet_budget_record_v1(storage, &storage_key)?;
            record.commit(identity)?;
            let status = record.status_at(identity.now_unix_ms)?;
            storage.put_router_wallet_budget(&storage_key, record)?;
            CloudflareDurableObjectResponseV1::router_wallet_budget_committed(
                identity.reservation_id.clone(),
                status,
            )?
        }
        CloudflareDurableObjectRequestV1::RouterWalletBudgetRelease { request } => {
            let mut record = router_wallet_budget_record_v1(storage, &storage_key)?;
            record.release(request)?;
            let status = record.status_at(request.now_unix_ms)?;
            storage.put_router_wallet_budget(&storage_key, record)?;
            CloudflareDurableObjectResponseV1::router_wallet_budget_released(
                request.reservation_id.clone(),
                status,
            )?
        }
        CloudflareDurableObjectRequestV1::RouterWalletBudgetStatus { request } => {
            let mut record = router_wallet_budget_record_v1(storage, &storage_key)?;
            let changed = record.clean_expired_reservations(request.now_unix_ms)?;
            let status = record.status_at(request.now_unix_ms)?;
            if changed {
                storage.put_router_wallet_budget(&storage_key, record)?;
            }
            CloudflareDurableObjectResponseV1::router_wallet_budget_status(status)?
        }
        CloudflareDurableObjectRequestV1::SigningWorkerOutputActivate {
            activation,
            material,
            activated_at_ms,
        } => {
            let active_state_index_key = call.active_signing_worker_state_index_storage_key()?;
            let (active_signing_worker_state, activated) = match storage
                .signing_worker_output_activation(&storage_key)?
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
                    let existing_active_state =
                        storage.active_signing_worker_state(&active_state_index_key)?;
                    validate_signing_worker_output_active_state_replacement_v1(
                        existing_active_state.as_ref(),
                        &active_signing_worker_state,
                    )?;
                    let record = CloudflareSigningWorkerOutputActivationRecordV1::new(
                        activation.clone(),
                        active_signing_worker_state.clone(),
                        material.clone(),
                    )?;
                    storage.put_signing_worker_output_activation(
                        &storage_key,
                        &active_state_index_key,
                        record,
                    )?;
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
            let outcome = match storage.signing_worker_direct_activation(&storage_key)? {
                Some(existing) => existing.apply_delivery(delivery.clone())?,
                None => {
                    let record =
                        CloudflareSigningWorkerDirectRecipientProofBundleActivationPendingRecordV1::new(
                            delivery.clone(),
                        )?;
                    storage.put_signing_worker_direct_activation(&storage_key, record.clone())?;
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
                storage.active_signing_worker_state(&storage_key)?,
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
                storage.signing_worker_output_activation(&storage_key)?,
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
                storage.signing_worker_round1(&storage_key)?,
                record,
                CloudflareSigningWorkerRound1RecordV1::validate,
                "SigningWorker round-1 handle is already stored for different material",
            )?;
            if stored {
                storage.put_signing_worker_round1(&storage_key, record.clone())?;
            }
            CloudflareDurableObjectResponseV1::signing_worker_round1_put(
                CloudflareSigningWorkerRound1PutReceiptV1::from_record(record, stored)?,
            )?
        }
        CloudflareDurableObjectRequestV1::SigningWorkerRound1Take { lookup } => {
            lookup.validate()?;
            let record = require_existing_record_v1(
                storage.signing_worker_round1(&storage_key)?,
                "SigningWorker round-1 nonce material is missing",
            )?;
            record.validate_for_lookup(lookup)?;
            storage.take_signing_worker_round1(&storage_key)?;
            CloudflareDurableObjectResponseV1::signing_worker_round1_take(record)?
        }
        CloudflareDurableObjectRequestV1::SigningWorkerRound1CleanupExpired { cleanup } => {
            cleanup.validate()?;
            CloudflareDurableObjectResponseV1::signing_worker_round1_cleanup_expired(
                storage.cleanup_expired_signing_worker_round1_records(cleanup.now_unix_ms)?,
            )?
        }
        CloudflareDurableObjectRequestV1::SigningWorkerEd25519PresignPoolPut { record } => {
            record.validate()?;
            let stored = validate_idempotent_put_record_v1(
                storage.signing_worker_ed25519_presign_pool(&storage_key)?,
                record,
                CloudflareSigningWorkerEd25519PresignPoolRecordV1::validate,
                "SigningWorker Ed25519 presign-pool id is already stored for different material",
            )?;
            if stored {
                storage.put_signing_worker_ed25519_presign_pool(&storage_key, record.clone())?;
            }
            CloudflareDurableObjectResponseV1::signing_worker_ed25519_presign_pool_put(
                CloudflareSigningWorkerEd25519PresignPoolPutReceiptV1::from_record(record, stored)?,
            )?
        }
        CloudflareDurableObjectRequestV1::SigningWorkerEd25519PresignPoolTake { lookup } => {
            lookup.validate()?;
            let record = require_existing_record_v1(
                storage.signing_worker_ed25519_presign_pool(&storage_key)?,
                "SigningWorker Ed25519 presign-pool material is missing",
            )?;
            record.validate_for_lookup(lookup)?;
            storage.take_signing_worker_ed25519_presign_pool(&storage_key)?;
            CloudflareDurableObjectResponseV1::signing_worker_ed25519_presign_pool_take(record)?
        }
        CloudflareDurableObjectRequestV1::SigningWorkerEd25519PresignPoolCleanupExpired {
            cleanup,
        } => {
            cleanup.validate()?;
            CloudflareDurableObjectResponseV1::signing_worker_ed25519_presign_pool_cleanup_expired(
                storage.cleanup_expired_signing_worker_ed25519_presign_pool_records(
                    cleanup.now_unix_ms,
                )?,
            )?
        }
        CloudflareDurableObjectRequestV1::SigningWorkerEcdsaPresignaturePut { record } => {
            record.validate()?;
            let stored = validate_idempotent_put_record_v1(
                storage.signing_worker_ecdsa_presignature(&storage_key)?,
                record,
                CloudflareSigningWorkerEcdsaPresignatureRecordV1::validate,
                "SigningWorker ECDSA presignature id is already stored for different material",
            )?;
            if stored {
                storage.put_signing_worker_ecdsa_presignature(&storage_key, record.clone())?;
            }
            CloudflareDurableObjectResponseV1::signing_worker_ecdsa_presignature_put(
                CloudflareSigningWorkerEcdsaPresignaturePutReceiptV1::from_record(record, stored)?,
            )?
        }
        CloudflareDurableObjectRequestV1::SigningWorkerEcdsaPresignatureTake { lookup } => {
            lookup.validate()?;
            let record = require_existing_record_v1(
                storage.signing_worker_ecdsa_presignature(&storage_key)?,
                "SigningWorker ECDSA presignature material is missing",
            )?;
            record.validate_for_lookup(lookup)?;
            storage.take_signing_worker_ecdsa_presignature(&storage_key)?;
            CloudflareDurableObjectResponseV1::signing_worker_ecdsa_presignature_take(record)?
        }
        CloudflareDurableObjectRequestV1::SigningWorkerEcdsaPresignatureCleanupExpired {
            cleanup,
        } => {
            cleanup.validate()?;
            CloudflareDurableObjectResponseV1::signing_worker_ecdsa_presignature_cleanup_expired(
                storage.cleanup_expired_signing_worker_ecdsa_presignature_records(
                    cleanup.now_unix_ms,
                )?,
            )?
        }
        CloudflareDurableObjectRequestV1::SigningWorkerEcdsaPresignaturePoolPut { record } => {
            record.validate()?;
            let stored = validate_idempotent_put_record_v1(
                storage.signing_worker_ecdsa_presignature_pool(&storage_key)?,
                record,
                CloudflareSigningWorkerEcdsaPresignaturePoolRecordV1::validate,
                "SigningWorker ECDSA presignature pool id is already stored for different material",
            )?;
            if stored {
                storage.put_signing_worker_ecdsa_presignature_pool(&storage_key, record.clone())?;
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
                storage.signing_worker_ecdsa_presignature_pool(&storage_key)?,
                "SigningWorker ECDSA presignature pool material is missing",
            )?;
            record.validate_for_lookup(lookup)?;
            storage.take_signing_worker_ecdsa_presignature_pool(&storage_key)?;
            CloudflareDurableObjectResponseV1::signing_worker_ecdsa_presignature_pool_take(record)?
        }
        CloudflareDurableObjectRequestV1::SigningWorkerEcdsaPresignaturePoolCleanupExpired {
            cleanup,
        } => {
            cleanup.validate()?;
            CloudflareDurableObjectResponseV1::signing_worker_ecdsa_presignature_pool_cleanup_expired(
                storage.cleanup_expired_signing_worker_ecdsa_presignature_pool_records(
                    cleanup.now_unix_ms,
                )?,
            )?
        }
    };
    response.validate_for_request(&call.request)?;
    Ok(response)
}
