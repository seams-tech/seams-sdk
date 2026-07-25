use router_ab_cloudflare::{
    CloudflareEd25519YaoPairCompletionAcknowledgementV1, CloudflareEd25519YaoPairExecuteRequestV1,
    CloudflareEd25519YaoPairPrepareRequestV1, CloudflareEd25519YaoReadCompletedPairRequestV1,
};
use router_ab_core::{
    Ed25519YaoDeriverRoleV1, Ed25519YaoOperationV1, RouterAbEd25519YaoActivationPublicReceiptV1,
    RouterAbEd25519YaoActivationResultV1, RouterAbEd25519YaoExportResultV1, RouterAbProtocolError,
    RouterAbProtocolErrorCode, RouterAbProtocolResult, RouterEd25519YaoExecuteFailureCodeV1,
    RouterEd25519YaoExecuteResultV1, RouterEd25519YaoExecuteSuccessV1,
};
use router_ab_ed25519_yao::{
    Ed25519YaoActivationRoleExecutionV1, Ed25519YaoExportRoleExecutionV1, Ed25519YaoRoleExecutionV1,
};
use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use super::{
    decode_local_router_ed25519_yao_execute_request_v1, local_dev_http_route_error_v1,
    LocalDevHttpRequestPartsV1, LocalEd25519YaoSigningWorkerActivationReceiptV1,
    LocalEd25519YaoSigningWorkerPackageDeliveryV1,
    LocalEd25519YaoSigningWorkerPackagePairDeliveryV1, LocalHttpServiceBindingClientV1,
    LocalRouterRequestDispatcherV1, LocalRouterWorkerConfigV1, LocalServiceRoleV1,
    LOCAL_DERIVER_A_ED25519_YAO_BURN_PAIR_PATH, LOCAL_DERIVER_A_ED25519_YAO_EXECUTE_PAIR_PATH,
    LOCAL_DERIVER_A_ED25519_YAO_PREPARE_PAIR_PATH, LOCAL_DERIVER_B_ED25519_YAO_BURN_PAIR_PATH,
    LOCAL_DERIVER_B_ED25519_YAO_PREPARE_PAIR_PATH,
    LOCAL_DERIVER_B_ED25519_YAO_READ_COMPLETED_PAIR_PATH, LOCAL_ROUTER_ED25519_YAO_EXECUTE_PATH,
    LOCAL_SIGNING_WORKER_ED25519_YAO_ACTIVATION_PACKAGES_PATH,
};

/// Native local equivalent of the private Router coordinator boundary.
///
/// The coordinator owns only authenticated routing metadata and opaque role
/// envelopes. Role workers retain all decrypted inputs and cryptographic state.
#[derive(Debug, Clone, Default)]
pub struct LocalRouterEd25519YaoCoordinatorV1 {
    client: LocalHttpServiceBindingClientV1,
}

impl LocalRouterEd25519YaoCoordinatorV1 {
    fn execute(
        &self,
        config: &LocalRouterWorkerConfigV1,
        body: &[u8],
    ) -> RouterAbProtocolResult<RouterEd25519YaoExecuteResultV1> {
        let request = decode_local_router_ed25519_yao_execute_request_v1(body)?;
        request.authority.validate_at(local_now_ms_v1()?)?;
        let pair = request.pair_binding.clone();
        let prepare_a = CloudflareEd25519YaoPairPrepareRequestV1 {
            pair_binding: pair.clone(),
            input: request.deriver_a_input.clone(),
        };
        let prepare_b = CloudflareEd25519YaoPairPrepareRequestV1 {
            pair_binding: pair.clone(),
            input: request.deriver_b_input.clone(),
        };
        let (receipt_a, receipt_b) = match self.prepare_pair(config, prepare_a, prepare_b) {
            Ok(receipts) => receipts,
            Err(_) => {
                self.burn_pair(config, &pair);
                return RouterEd25519YaoExecuteResultV1::recoverable(
                    RouterEd25519YaoExecuteFailureCodeV1::ServiceUnavailable,
                    1_000,
                );
            }
        };
        if receipt_a.validate_for_pair(&pair).is_err()
            || receipt_b.validate_for_pair(&pair).is_err()
        {
            self.burn_pair(config, &pair);
            return Ok(RouterEd25519YaoExecuteResultV1::burned(
                execution_id_for_pair(&pair)?,
                router_ab_core::RouterEd25519YaoBurnReasonV1::ProtocolFailure,
            ));
        }
        if receipt_a.role() != Ed25519YaoDeriverRoleV1::DeriverA
            || receipt_b.role() != Ed25519YaoDeriverRoleV1::DeriverB
        {
            self.burn_pair(config, &pair);
            return Ok(RouterEd25519YaoExecuteResultV1::burned(
                execution_id_for_pair(&pair)?,
                router_ab_core::RouterEd25519YaoBurnReasonV1::ProtocolFailure,
            ));
        }
        let execution = match self.client.post_json_authenticated_v1(
            &config.deriver_a_url,
            LocalServiceRoleV1::DeriverA,
            LOCAL_DERIVER_A_ED25519_YAO_EXECUTE_PAIR_PATH,
            &config.internal_service_auth,
            &CloudflareEd25519YaoPairExecuteRequestV1 {
                pair_binding: pair.clone(),
                peer_receipt: receipt_b,
            },
        ) {
            Ok(execution) => execution,
            Err(_) => {
                self.burn_pair(config, &pair);
                return Ok(RouterEd25519YaoExecuteResultV1::burned(
                    execution_id_for_pair(&pair)?,
                    router_ab_core::RouterEd25519YaoBurnReasonV1::PeerUncertain,
                ));
            }
        };
        if validate_execution(&execution, Ed25519YaoDeriverRoleV1::DeriverA, &request).is_err() {
            self.burn_pair(config, &pair);
            return Ok(RouterEd25519YaoExecuteResultV1::burned(
                execution_id_for_pair(&pair)?,
                router_ab_core::RouterEd25519YaoBurnReasonV1::ProtocolFailure,
            ));
        }
        let completed_request = CloudflareEd25519YaoReadCompletedPairRequestV1 {
            session: pair.session(),
            pair_digest: pair.pair_digest().bytes,
        };
        let completed = match self
            .client
            .post_json_authenticated_v1::<_, CloudflareEd25519YaoPairCompletionAcknowledgementV1>(
                &config.deriver_b_url,
                LocalServiceRoleV1::DeriverB,
                LOCAL_DERIVER_B_ED25519_YAO_READ_COMPLETED_PAIR_PATH,
                &config.internal_service_auth,
                &completed_request,
            ) {
            Ok(acknowledgement) => acknowledgement.validate_for_request(&completed_request),
            Err(error) => Err(error),
        };
        let completed = match completed {
            Ok(execution) => execution,
            Err(_) => {
                self.burn_pair(config, &pair);
                return Ok(RouterEd25519YaoExecuteResultV1::burned(
                    execution_id_for_pair(&pair)?,
                    router_ab_core::RouterEd25519YaoBurnReasonV1::PeerUncertain,
                ));
            }
        };
        if validate_execution(&completed, Ed25519YaoDeriverRoleV1::DeriverB, &request).is_err() {
            self.burn_pair(config, &pair);
            return Ok(RouterEd25519YaoExecuteResultV1::burned(
                execution_id_for_pair(&pair)?,
                router_ab_core::RouterEd25519YaoBurnReasonV1::ProtocolFailure,
            ));
        }
        if execution_transcript(&execution) != execution_transcript(&completed) {
            self.burn_pair(config, &pair);
            return Ok(RouterEd25519YaoExecuteResultV1::burned(
                execution_id_for_pair(&pair)?,
                router_ab_core::RouterEd25519YaoBurnReasonV1::ProtocolFailure,
            ));
        }
        match self.finalize(config, &request, execution, completed) {
            Ok(result) => Ok(result),
            Err(_) => {
                self.burn_pair(config, &pair);
                Ok(RouterEd25519YaoExecuteResultV1::burned(
                    execution_id_for_pair(&pair)?,
                    router_ab_core::RouterEd25519YaoBurnReasonV1::ProtocolFailure,
                ))
            }
        }
    }

    fn prepare_pair(
        &self,
        config: &LocalRouterWorkerConfigV1,
        prepare_a: CloudflareEd25519YaoPairPrepareRequestV1,
        prepare_b: CloudflareEd25519YaoPairPrepareRequestV1,
    ) -> RouterAbProtocolResult<(
        router_ab_core::Ed25519YaoRoleReadinessReceiptV1,
        router_ab_core::Ed25519YaoRoleReadinessReceiptV1,
    )> {
        let client = Arc::new(self.client.clone());
        let auth = config.internal_service_auth.clone();
        let auth_b = auth.clone();
        let url_a = config.deriver_a_url.clone();
        let url_b = config.deriver_b_url.clone();
        std::thread::scope(|scope| {
            let client_a = Arc::clone(&client);
            let client_b = Arc::clone(&client);
            let a = scope.spawn(move || {
                client_a.post_json_authenticated_v1(
                    &url_a,
                    LocalServiceRoleV1::DeriverA,
                    LOCAL_DERIVER_A_ED25519_YAO_PREPARE_PAIR_PATH,
                    &auth,
                    &prepare_a,
                )
            });
            let b = scope.spawn(move || {
                client_b.post_json_authenticated_v1(
                    &url_b,
                    LocalServiceRoleV1::DeriverB,
                    LOCAL_DERIVER_B_ED25519_YAO_PREPARE_PAIR_PATH,
                    &auth_b,
                    &prepare_b,
                )
            });
            let receipt_a = a
                .join()
                .map_err(|_| coordinator_error("Deriver A preparation thread panicked"))??;
            let receipt_b = b
                .join()
                .map_err(|_| coordinator_error("Deriver B preparation thread panicked"))??;
            Ok((receipt_a, receipt_b))
        })
    }

    fn burn_pair(
        &self,
        config: &LocalRouterWorkerConfigV1,
        pair: &router_ab_core::Ed25519YaoInputPairBindingV1,
    ) {
        let request = CloudflareEd25519YaoReadCompletedPairRequestV1 {
            session: pair.session(),
            pair_digest: pair.pair_digest().bytes,
        };
        let _ = self.client.post_json_authenticated_v1::<_, router_ab_cloudflare::CloudflareEd25519YaoPairStatusResponseV1>(
            &config.deriver_a_url,
            LocalServiceRoleV1::DeriverA,
            LOCAL_DERIVER_A_ED25519_YAO_BURN_PAIR_PATH,
            &config.internal_service_auth,
            &request,
        );
        let _ = self.client.post_json_authenticated_v1::<_, router_ab_cloudflare::CloudflareEd25519YaoPairStatusResponseV1>(
            &config.deriver_b_url,
            LocalServiceRoleV1::DeriverB,
            LOCAL_DERIVER_B_ED25519_YAO_BURN_PAIR_PATH,
            &config.internal_service_auth,
            &request,
        );
    }

    fn finalize(
        &self,
        config: &LocalRouterWorkerConfigV1,
        request: &super::LocalRouterEd25519YaoPairDispatchV1,
        execution_a: Ed25519YaoRoleExecutionV1,
        execution_b: Ed25519YaoRoleExecutionV1,
    ) -> RouterAbProtocolResult<RouterEd25519YaoExecuteResultV1> {
        match request.operation {
            Ed25519YaoOperationV1::Registration | Ed25519YaoOperationV1::Recovery => {
                let a = activation_execution(&execution_a)?;
                let b = activation_execution(&execution_b)?;
                let delivery = LocalEd25519YaoSigningWorkerPackagePairDeliveryV1 {
                    deriver_a: package_delivery(a),
                    deriver_b: package_delivery(b),
                };
                let receipt = self.client.post_json_authenticated_v1::<_, LocalEd25519YaoSigningWorkerActivationReceiptV1>(
                    &config.signing_worker_url,
                    LocalServiceRoleV1::SigningWorker,
                    LOCAL_SIGNING_WORKER_ED25519_YAO_ACTIVATION_PACKAGES_PATH,
                    &config.internal_service_auth,
                    &delivery,
                )?;
                let public_receipt = activation_public_receipt(receipt, request.operation)?;
                let result = RouterAbEd25519YaoActivationResultV1::new(
                    request.binding.clone(),
                    a.client_package.clone(),
                    b.client_package.clone(),
                    public_receipt,
                )?;
                let success = match request.operation {
                    Ed25519YaoOperationV1::Registration => {
                        RouterEd25519YaoExecuteSuccessV1::registration(result)?
                    }
                    Ed25519YaoOperationV1::Recovery => {
                        RouterEd25519YaoExecuteSuccessV1::recovery(result)?
                    }
                    _ => unreachable!("activation branch excludes export"),
                };
                Ok(RouterEd25519YaoExecuteResultV1::succeeded(success))
            }
            Ed25519YaoOperationV1::Export => {
                let export_binding = request
                    .export_binding
                    .clone()
                    .ok_or_else(|| coordinator_error("export binding is missing"))?;
                let a = export_execution(&execution_a)?;
                let b = export_execution(&execution_b)?;
                let result = RouterAbEd25519YaoExportResultV1::new(
                    export_binding,
                    a.transcript,
                    a.client_package.clone(),
                    b.client_package.clone(),
                )?;
                Ok(RouterEd25519YaoExecuteResultV1::succeeded(
                    RouterEd25519YaoExecuteSuccessV1::export(result)?,
                ))
            }
            Ed25519YaoOperationV1::Refresh => Err(coordinator_error(
                "Refresh is not an admitted Yao operation",
            )),
        }
    }
}

impl LocalRouterRequestDispatcherV1 for LocalRouterEd25519YaoCoordinatorV1 {
    fn dispatch(
        &self,
        config: &LocalRouterWorkerConfigV1,
        request: &LocalDevHttpRequestPartsV1,
    ) -> Result<Option<(u16, String)>, Box<dyn std::error::Error>> {
        if request.path != LOCAL_ROUTER_ED25519_YAO_EXECUTE_PATH {
            return Ok(None);
        }
        match self.execute(config, &request.body) {
            Ok(result) => Ok(Some((200, serde_json::to_string(&result)?))),
            Err(error) => Ok(Some(local_dev_http_route_error_v1(
                LocalServiceRoleV1::Router,
                &request.path,
                error,
            )?)),
        }
    }
}

fn validate_execution(
    execution: &Ed25519YaoRoleExecutionV1,
    role: Ed25519YaoDeriverRoleV1,
    request: &super::LocalRouterEd25519YaoPairDispatchV1,
) -> RouterAbProtocolResult<()> {
    execution.validate()?;
    if execution.deriver() != role || execution.session() != request.pair_binding.session() {
        return Err(coordinator_error(
            "role execution identity does not match the admitted pair",
        ));
    }
    if execution_binding(execution) != &request.binding {
        return Err(coordinator_error(
            "role execution binding does not match the admitted ceremony",
        ));
    }
    Ok(())
}

fn activation_execution(
    execution: &Ed25519YaoRoleExecutionV1,
) -> RouterAbProtocolResult<&Ed25519YaoActivationRoleExecutionV1> {
    match execution {
        Ed25519YaoRoleExecutionV1::Activation(value) => Ok(value),
        Ed25519YaoRoleExecutionV1::Export(_) => {
            Err(coordinator_error("activation execution was not returned"))
        }
    }
}

fn export_execution(
    execution: &Ed25519YaoRoleExecutionV1,
) -> RouterAbProtocolResult<&Ed25519YaoExportRoleExecutionV1> {
    match execution {
        Ed25519YaoRoleExecutionV1::Export(value) => Ok(value),
        Ed25519YaoRoleExecutionV1::Activation(_) => {
            Err(coordinator_error("export execution was not returned"))
        }
    }
}

fn package_delivery(
    execution: &Ed25519YaoActivationRoleExecutionV1,
) -> LocalEd25519YaoSigningWorkerPackageDeliveryV1 {
    LocalEd25519YaoSigningWorkerPackageDeliveryV1 {
        binding: execution.binding.clone(),
        client_commitment: execution.client_commitment,
        signing_worker_commitment: execution.signing_worker_commitment,
        package: execution.signing_worker_package.clone(),
    }
}

fn activation_public_receipt(
    receipt: LocalEd25519YaoSigningWorkerActivationReceiptV1,
    operation: Ed25519YaoOperationV1,
) -> RouterAbProtocolResult<RouterAbEd25519YaoActivationPublicReceiptV1> {
    let (
        status_operation,
        transcript,
        registered_public_key,
        joined_client_commitment,
        joined_signing_worker_commitment,
        signing_worker_verifying_share,
        state_epoch,
    ) = match receipt {
        LocalEd25519YaoSigningWorkerActivationReceiptV1::Active {
            session: _,
            transcript,
            registered_public_key,
            joined_client_commitment,
            joined_signing_worker_commitment,
            signing_worker_verifying_share,
            state_epoch,
        } => (
            Ed25519YaoOperationV1::Registration,
            transcript,
            registered_public_key,
            joined_client_commitment,
            joined_signing_worker_commitment,
            signing_worker_verifying_share,
            state_epoch,
        ),
        LocalEd25519YaoSigningWorkerActivationReceiptV1::Staged { promotion } => (
            Ed25519YaoOperationV1::Recovery,
            promotion.transcript,
            promotion.registered_public_key,
            promotion.joined_client_commitment,
            promotion.joined_signing_worker_commitment,
            promotion.signing_worker_verifying_share,
            promotion.state_epoch,
        ),
    };
    if status_operation != operation {
        return Err(coordinator_error(
            "SigningWorker receipt status does not match the admitted operation",
        ));
    }
    RouterAbEd25519YaoActivationPublicReceiptV1::new(
        transcript,
        registered_public_key,
        joined_client_commitment,
        joined_signing_worker_commitment,
        signing_worker_verifying_share,
        state_epoch,
    )
}

fn execution_binding(
    execution: &Ed25519YaoRoleExecutionV1,
) -> &router_ab_core::Ed25519YaoCeremonyBindingV1 {
    match execution {
        Ed25519YaoRoleExecutionV1::Activation(value) => &value.binding,
        Ed25519YaoRoleExecutionV1::Export(value) => &value.binding,
    }
}

fn execution_transcript(execution: &Ed25519YaoRoleExecutionV1) -> [u8; 32] {
    match execution {
        Ed25519YaoRoleExecutionV1::Activation(value) => value.transcript,
        Ed25519YaoRoleExecutionV1::Export(value) => value.transcript,
    }
}

fn execution_id_for_pair(
    pair: &router_ab_core::Ed25519YaoInputPairBindingV1,
) -> RouterAbProtocolResult<router_ab_core::Ed25519YaoExecutionIdV1> {
    router_ab_core::Ed25519YaoExecutionIdV1::new(pair.pair_digest().bytes)
}

fn local_now_ms_v1() -> RouterAbProtocolResult<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis().try_into().unwrap_or(u64::MAX))
        .map_err(|_| coordinator_error("local system clock predates the Unix epoch"))
}

fn coordinator_error(message: &'static str) -> RouterAbProtocolError {
    RouterAbProtocolError::new(RouterAbProtocolErrorCode::InvalidLifecycleState, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_execute_body_is_rejected_before_any_role_call() {
        let error = decode_local_router_ed25519_yao_execute_request_v1(
            br#"{"operation":"registration","unknown":true}"#,
        )
        .expect_err("malformed request must not reach a role");
        assert_eq!(
            error.code(),
            RouterAbProtocolErrorCode::MalformedWirePayload
        );
    }

    #[test]
    fn signing_worker_receipt_operation_mismatch_is_rejected() {
        let receipt = LocalEd25519YaoSigningWorkerActivationReceiptV1::Active {
            session: [1; 32],
            transcript: [2; 32],
            registered_public_key: [3; 32],
            joined_client_commitment: [4; 32],
            joined_signing_worker_commitment: [5; 32],
            signing_worker_verifying_share: [6; 32],
            state_epoch: router_ab_core::Ed25519YaoStateEpochV1::new(1).expect("epoch"),
        };
        assert!(activation_public_receipt(receipt, Ed25519YaoOperationV1::Recovery).is_err());
    }
}
