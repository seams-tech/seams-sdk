use super::*;

#[cfg(feature = "strict-worker-signer-a-entrypoint")]
pub(super) async fn handle_strict_deriver_a_fetch_v1(
    request: Request,
    env: Env,
) -> worker::Result<Response> {
    if let Err(err) = require_cloudflare_internal_service_auth_request_v1(&request, &env) {
        return cloudflare_private_service_auth_error_response_v1(err);
    }
    let runtime = match CloudflareDeriverAWorkerRuntimeV1::from_worker_env(&env) {
        Ok(runtime) => StrictDeriverRuntimeV1::DeriverA(runtime),
        Err(err) => return cloudflare_protocol_error_response_v1(err),
    };
    handle_strict_deriver_fetch_v1(request, env, runtime).await
}

#[cfg(any(
    feature = "strict-worker-signer-a-entrypoint",
    feature = "strict-worker-signer-b-entrypoint"
))]
enum StrictDeriverRuntimeV1 {
    #[cfg(feature = "strict-worker-signer-a-entrypoint")]
    DeriverA(CloudflareDeriverAWorkerRuntimeV1),
    #[cfg(feature = "strict-worker-signer-b-entrypoint")]
    DeriverB(CloudflareDeriverBWorkerRuntimeV1),
}

#[cfg(any(
    feature = "strict-worker-signer-a-entrypoint",
    feature = "strict-worker-signer-b-entrypoint"
))]
impl StrictDeriverRuntimeV1 {
    fn label(&self) -> &'static str {
        match self {
            #[cfg(feature = "strict-worker-signer-a-entrypoint")]
            Self::DeriverA(_) => "Deriver A",
            #[cfg(feature = "strict-worker-signer-b-entrypoint")]
            Self::DeriverB(_) => "Deriver B",
        }
    }

    fn worker_role(&self) -> CloudflareWorkerRoleV1 {
        match self {
            #[cfg(feature = "strict-worker-signer-a-entrypoint")]
            Self::DeriverA(_) => CloudflareWorkerRoleV1::SignerA,
            #[cfg(feature = "strict-worker-signer-b-entrypoint")]
            Self::DeriverB(_) => CloudflareWorkerRoleV1::SignerB,
        }
    }

    fn protocol_role(&self) -> Role {
        match self {
            #[cfg(feature = "strict-worker-signer-a-entrypoint")]
            Self::DeriverA(_) => Role::SignerA,
            #[cfg(feature = "strict-worker-signer-b-entrypoint")]
            Self::DeriverB(_) => Role::SignerB,
        }
    }

    fn bootstrap_private_path(&self) -> &'static str {
        match self {
            #[cfg(feature = "strict-worker-signer-a-entrypoint")]
            Self::DeriverA(_) => CLOUDFLARE_SIGNER_A_PRIVATE_REQUEST_PATH,
            #[cfg(feature = "strict-worker-signer-b-entrypoint")]
            Self::DeriverB(_) => CLOUDFLARE_SIGNER_B_PRIVATE_REQUEST_PATH,
        }
    }

    fn registration_private_path(&self) -> &'static str {
        match self {
            #[cfg(feature = "strict-worker-signer-a-entrypoint")]
            Self::DeriverA(_) => CLOUDFLARE_SIGNER_A_ECDSA_HSS_REGISTRATION_PRIVATE_REQUEST_PATH,
            #[cfg(feature = "strict-worker-signer-b-entrypoint")]
            Self::DeriverB(_) => CLOUDFLARE_SIGNER_B_ECDSA_HSS_REGISTRATION_PRIVATE_REQUEST_PATH,
        }
    }

    fn export_private_path(&self) -> &'static str {
        match self {
            #[cfg(feature = "strict-worker-signer-a-entrypoint")]
            Self::DeriverA(_) => CLOUDFLARE_SIGNER_A_ECDSA_HSS_EXPORT_PRIVATE_REQUEST_PATH,
            #[cfg(feature = "strict-worker-signer-b-entrypoint")]
            Self::DeriverB(_) => CLOUDFLARE_SIGNER_B_ECDSA_HSS_EXPORT_PRIVATE_REQUEST_PATH,
        }
    }

    fn recovery_private_path(&self) -> &'static str {
        match self {
            #[cfg(feature = "strict-worker-signer-a-entrypoint")]
            Self::DeriverA(_) => CLOUDFLARE_SIGNER_A_ECDSA_HSS_RECOVERY_PRIVATE_REQUEST_PATH,
            #[cfg(feature = "strict-worker-signer-b-entrypoint")]
            Self::DeriverB(_) => CLOUDFLARE_SIGNER_B_ECDSA_HSS_RECOVERY_PRIVATE_REQUEST_PATH,
        }
    }

    fn refresh_private_path(&self) -> &'static str {
        match self {
            #[cfg(feature = "strict-worker-signer-a-entrypoint")]
            Self::DeriverA(_) => CLOUDFLARE_SIGNER_A_ECDSA_HSS_REFRESH_PRIVATE_REQUEST_PATH,
            #[cfg(feature = "strict-worker-signer-b-entrypoint")]
            Self::DeriverB(_) => CLOUDFLARE_SIGNER_B_ECDSA_HSS_REFRESH_PRIVATE_REQUEST_PATH,
        }
    }

    fn peer_verifying_keys_for_signer_set(
        &self,
        signer_set: &SignerSetV1,
    ) -> RouterAbProtocolResult<Vec<AbPeerMessageVerifyingKeyV1>> {
        match self {
            #[cfg(feature = "strict-worker-signer-a-entrypoint")]
            Self::DeriverA(runtime) => runtime.peer_verifying_keys_for_signer_set(signer_set),
            #[cfg(feature = "strict-worker-signer-b-entrypoint")]
            Self::DeriverB(runtime) => runtime.peer_verifying_keys_for_signer_set(signer_set),
        }
    }

    fn envelope_decrypt_key(&self) -> &CloudflareSignerEnvelopeHpkeDecryptKeyBindingSetV1 {
        match self {
            #[cfg(feature = "strict-worker-signer-a-entrypoint")]
            Self::DeriverA(runtime) => runtime.envelope_decrypt_key(),
            #[cfg(feature = "strict-worker-signer-b-entrypoint")]
            Self::DeriverB(runtime) => runtime.envelope_decrypt_key(),
        }
    }

    fn peer_signing_key(&self) -> &CloudflareSignerPeerSigningKeyBindingV1 {
        match self {
            #[cfg(feature = "strict-worker-signer-a-entrypoint")]
            Self::DeriverA(runtime) => runtime.peer_signing_key(),
            #[cfg(feature = "strict-worker-signer-b-entrypoint")]
            Self::DeriverB(runtime) => runtime.peer_signing_key(),
        }
    }

    fn signing_worker_peer(&self) -> &CloudflarePeerBindingV1 {
        match self {
            #[cfg(feature = "strict-worker-signer-a-entrypoint")]
            Self::DeriverA(runtime) => runtime.signing_worker_peer(),
            #[cfg(feature = "strict-worker-signer-b-entrypoint")]
            Self::DeriverB(runtime) => runtime.signing_worker_peer(),
        }
    }

    async fn preload_host(
        &self,
        env: &Env,
        input: CloudflareSignerHostPreloadInputV1,
    ) -> RouterAbProtocolResult<CloudflarePreloadedSignerHostV1> {
        match self {
            #[cfg(feature = "strict-worker-signer-a-entrypoint")]
            Self::DeriverA(runtime) => {
                preload_cloudflare_deriver_a_host_v1(env, runtime, input).await
            }
            #[cfg(feature = "strict-worker-signer-b-entrypoint")]
            Self::DeriverB(runtime) => {
                preload_cloudflare_deriver_b_host_v1(env, runtime, input).await
            }
        }
    }

    fn route_error_message(&self) -> String {
        format!(
            "{} strict Worker route must be served at {}, {}, {}, {}, or {}",
            self.label(),
            self.bootstrap_private_path(),
            self.registration_private_path(),
            self.export_private_path(),
            self.recovery_private_path(),
            self.refresh_private_path()
        )
    }
}

#[cfg(any(
    feature = "strict-worker-signer-a-entrypoint",
    feature = "strict-worker-signer-b-entrypoint"
))]
struct StrictDeriverPreloadedRequestV1 {
    host: CloudflarePreloadedSignerHostV1,
    root_share_metadata: CloudflareRootShareStartupMetadataV1,
}

#[cfg(any(
    feature = "strict-worker-signer-a-entrypoint",
    feature = "strict-worker-signer-b-entrypoint"
))]
async fn handle_strict_deriver_fetch_v1(
    mut request: Request,
    env: Env,
    runtime: StrictDeriverRuntimeV1,
) -> worker::Result<Response> {
    let path = request.path();
    let worker_role = runtime.worker_role();
    let label = runtime.label();
    let now_unix_ms = match cloudflare_now_unix_ms_v1() {
        Ok(now_unix_ms) => now_unix_ms,
        Err(err) => return cloudflare_protocol_error_response_v1(err),
    };

    if path == runtime.registration_private_path() {
        let registration_request: CloudflareEcdsaHssDeriverRegistrationPrivateRequestV1 =
            match parse_strict_deriver_json_v1(
                &mut request,
                format!("Router A/B strict {label} ECDSA-HSS registration"),
            )
            .await?
            {
                Ok(parsed) => parsed,
                Err(response) => return Ok(response),
            };
        if let Err(err) = registration_request.validate_for_worker_role(worker_role) {
            return cloudflare_protocol_error_response_v1(err);
        }
        let preloaded = match preload_strict_deriver_request_v1(
            &env,
            &runtime,
            &registration_request.signer_bootstrap,
        )
        .await
        {
            Ok(loaded) => loaded,
            Err(err) => return cloudflare_protocol_error_response_v1(err),
        };
        let registration_bootstrap = registration_request.signer_bootstrap.clone();
        let response =
            match decrypt_and_handle_cloudflare_ecdsa_hss_registration_signer_private_request_v1(
                &env,
                worker_role,
                &preloaded.host,
                registration_request,
                runtime.envelope_decrypt_key(),
                runtime.peer_signing_key(),
                &preloaded.root_share_metadata,
                now_unix_ms,
            )
            .await
            {
                Ok(response) => response,
                Err(err) => return cloudflare_protocol_error_response_v1(err),
            };
        if let Err(err) = send_strict_deriver_direct_activation_delivery_v1(
            &env,
            &runtime,
            &registration_bootstrap,
            &response,
        )
        .await
        {
            return cloudflare_protocol_error_response_v1(err);
        }
        return Response::from_json(&response);
    }

    if path == runtime.export_private_path() {
        let export_request: CloudflareEcdsaHssDeriverExportPrivateRequestV1 =
            match parse_strict_deriver_json_v1(
                &mut request,
                format!("Router A/B strict {label} ECDSA-HSS export"),
            )
            .await?
            {
                Ok(parsed) => parsed,
                Err(response) => return Ok(response),
            };
        if let Err(err) = export_request.validate_for_worker_role(worker_role) {
            return cloudflare_protocol_error_response_v1(err);
        }
        let preloaded = match preload_strict_deriver_request_v1(
            &env,
            &runtime,
            &export_request.signer_bootstrap,
        )
        .await
        {
            Ok(loaded) => loaded,
            Err(err) => return cloudflare_protocol_error_response_v1(err),
        };
        return match decrypt_and_handle_cloudflare_ecdsa_hss_export_signer_private_request_v1(
            &env,
            worker_role,
            &preloaded.host,
            export_request,
            runtime.envelope_decrypt_key(),
            runtime.peer_signing_key(),
            &preloaded.root_share_metadata,
            now_unix_ms,
        )
        .await
        {
            Ok(response) => Response::from_json(&response),
            Err(err) => cloudflare_protocol_error_response_v1(err),
        };
    }

    if path == runtime.recovery_private_path() {
        let recovery_request: CloudflareEcdsaHssDeriverRecoveryPrivateRequestV1 =
            match parse_strict_deriver_json_v1(
                &mut request,
                format!("Router A/B strict {label} ECDSA-HSS recovery"),
            )
            .await?
            {
                Ok(parsed) => parsed,
                Err(response) => return Ok(response),
            };
        if let Err(err) = recovery_request.validate_for_worker_role(worker_role) {
            return cloudflare_protocol_error_response_v1(err);
        }
        let preloaded = match preload_strict_deriver_request_v1(
            &env,
            &runtime,
            &recovery_request.signer_bootstrap,
        )
        .await
        {
            Ok(loaded) => loaded,
            Err(err) => return cloudflare_protocol_error_response_v1(err),
        };
        return match decrypt_and_handle_cloudflare_ecdsa_hss_recovery_signer_private_request_v1(
            &env,
            worker_role,
            &preloaded.host,
            recovery_request,
            runtime.envelope_decrypt_key(),
            runtime.peer_signing_key(),
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
        let refresh_request: CloudflareEcdsaHssDeriverActivationRefreshPrivateRequestV1 =
            match parse_strict_deriver_json_v1(
                &mut request,
                format!("Router A/B strict {label} ECDSA-HSS refresh"),
            )
            .await?
            {
                Ok(parsed) => parsed,
                Err(response) => return Ok(response),
            };
        if let Err(err) = refresh_request.validate_for_worker_role(worker_role) {
            return cloudflare_protocol_error_response_v1(err);
        }
        let preloaded = match preload_strict_deriver_request_v1(
            &env,
            &runtime,
            &refresh_request.signer_bootstrap,
        )
        .await
        {
            Ok(loaded) => loaded,
            Err(err) => return cloudflare_protocol_error_response_v1(err),
        };
        let refresh_bootstrap = refresh_request.signer_bootstrap.clone();
        let response = match decrypt_and_handle_cloudflare_ecdsa_hss_activation_refresh_signer_private_request_v1(
            &env,
            worker_role,
            &preloaded.host,
            refresh_request,
            runtime.envelope_decrypt_key(),
            runtime.peer_signing_key(),
            &preloaded.root_share_metadata,
            now_unix_ms,
        )
        .await
        {
            Ok(response) => response,
            Err(err) => return cloudflare_protocol_error_response_v1(err),
        };
        if let Err(err) = send_strict_deriver_direct_activation_delivery_v1(
            &env,
            &runtime,
            &refresh_bootstrap,
            &response,
        )
        .await
        {
            return cloudflare_protocol_error_response_v1(err);
        }
        return Response::from_json(&response);
    }

    if path == runtime.bootstrap_private_path() {
        let bootstrap: CloudflareSignerPrivateBootstrapRequestV1 =
            match parse_strict_deriver_json_v1(
                &mut request,
                format!("Router A/B strict {label} bootstrap"),
            )
            .await?
            {
                Ok(parsed) => parsed,
                Err(response) => return Ok(response),
            };
        if let Err(err) = bootstrap.validate_for_worker_role(worker_role) {
            return cloudflare_protocol_error_response_v1(err);
        }
        let preloaded = match preload_strict_deriver_request_v1(&env, &runtime, &bootstrap).await {
            Ok(loaded) => loaded,
            Err(err) => return cloudflare_protocol_error_response_v1(err),
        };
        let message = bootstrap.message;
        let aad = bootstrap.aad;
        let router_request_digest = bootstrap.router_request_digest;
        return match decrypt_and_handle_cloudflare_mpc_prf_recipient_proof_bundle_signer_private_request_v1(
            &env,
            worker_role,
            &preloaded.host,
            message,
            runtime.envelope_decrypt_key(),
            runtime.peer_signing_key(),
            &aad,
            router_request_digest,
            &preloaded.root_share_metadata,
            now_unix_ms,
        )
        .await
        {
            Ok(response) => Response::from_json(&response),
            Err(err) => cloudflare_protocol_error_response_v1(err),
        };
    }

    Response::error(runtime.route_error_message(), 404)
}

#[cfg(any(
    feature = "strict-worker-signer-a-entrypoint",
    feature = "strict-worker-signer-b-entrypoint"
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
    feature = "strict-worker-signer-a-entrypoint",
    feature = "strict-worker-signer-b-entrypoint"
))]
async fn preload_strict_deriver_request_v1(
    env: &Env,
    runtime: &StrictDeriverRuntimeV1,
    bootstrap: &CloudflareSignerPrivateBootstrapRequestV1,
) -> RouterAbProtocolResult<StrictDeriverPreloadedRequestV1> {
    let (preload_plan, host) = preload_strict_deriver_host_v1(env, runtime, bootstrap).await?;
    let root_share_metadata = host
        .root_share_startup_metadata(runtime.protocol_role(), &preload_plan.root_share_epoch)?
        .clone();
    Ok(StrictDeriverPreloadedRequestV1 {
        host,
        root_share_metadata,
    })
}

#[cfg(any(
    feature = "strict-worker-signer-a-entrypoint",
    feature = "strict-worker-signer-b-entrypoint"
))]
async fn preload_strict_deriver_host_v1(
    env: &Env,
    runtime: &StrictDeriverRuntimeV1,
    bootstrap: &CloudflareSignerPrivateBootstrapRequestV1,
) -> RouterAbProtocolResult<(
    CloudflareSignerHostPreloadPlanV1,
    CloudflarePreloadedSignerHostV1,
)> {
    let preload_plan = CloudflareSignerHostPreloadPlanV1::from_private_bootstrap(
        runtime.worker_role(),
        bootstrap,
    )?;
    let verifying_keys = runtime.peer_verifying_keys_for_signer_set(&preload_plan.signer_set)?;
    let preload_input = preload_plan.to_host_preload_input(Vec::new(), verifying_keys, 0)?;
    let host = runtime.preload_host(env, preload_input).await?;
    Ok((preload_plan, host))
}

#[cfg(any(
    feature = "strict-worker-signer-a-entrypoint",
    feature = "strict-worker-signer-b-entrypoint"
))]
async fn send_strict_deriver_direct_activation_delivery_v1(
    env: &Env,
    runtime: &StrictDeriverRuntimeV1,
    bootstrap: &CloudflareSignerPrivateBootstrapRequestV1,
    response: &CloudflareSignerRecipientProofBundleResponseV1,
) -> RouterAbProtocolResult<()> {
    bootstrap.validate_for_worker_role(runtime.worker_role())?;
    response.validate()?;
    let router_payload = decode_router_to_signer_payload_v1(bootstrap.message.payload.as_bytes())?;
    let activation_context =
        SigningWorkerActivationContextV1::from_router_payload(&router_payload)?;
    let delivery = CloudflareSigningWorkerDirectRecipientProofBundleActivationDeliveryV1::from_signer_response(
        activation_context,
        response.clone(),
    )?;
    execute_cloudflare_signing_worker_direct_recipient_proof_bundle_activation_service_call_v1(
        env,
        runtime.signing_worker_peer(),
        &delivery,
    )
    .await?;
    Ok(())
}

#[cfg(feature = "strict-worker-signer-b-entrypoint")]
pub(super) async fn handle_strict_deriver_b_fetch_v1(
    request: Request,
    env: Env,
) -> worker::Result<Response> {
    if let Err(err) = require_cloudflare_internal_service_auth_request_v1(&request, &env) {
        return cloudflare_private_service_auth_error_response_v1(err);
    }
    let runtime = match CloudflareDeriverBWorkerRuntimeV1::from_worker_env(&env) {
        Ok(runtime) => StrictDeriverRuntimeV1::DeriverB(runtime),
        Err(err) => return cloudflare_protocol_error_response_v1(err),
    };
    handle_strict_deriver_fetch_v1(request, env, runtime).await
}
