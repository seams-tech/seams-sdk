use crate::*;
use futures::future::LocalBoxFuture;

pub(crate) enum CloudflareRouterAbEcdsaNormalSigningServiceRequestV1 {
    Prepare(CloudflareSigningWorkerAdmittedRouterAbEcdsaDerivationEvmDigestSigningRequestV1),
    Finalize(CloudflareSigningWorkerAdmittedRouterAbEcdsaDerivationEvmDigestFinalizeRequestV1),
}

pub(crate) enum CloudflareRouterAbEcdsaNormalSigningServiceResponseV1 {
    Prepare(RouterAbEcdsaDerivationEvmDigestSigningPrepareResponseV1),
    Finalize(RouterAbEcdsaDerivationEvmDigestSigningResponseV1),
}

pub(crate) trait CloudflareRouterAbEcdsaNormalSigningServiceTransportV1 {
    fn send<'a>(
        &'a mut self,
        peer: &'a CloudflarePeerBindingV1,
        request: CloudflareRouterAbEcdsaNormalSigningServiceRequestV1,
    ) -> LocalBoxFuture<
        'a,
        RouterAbProtocolResult<CloudflareRouterAbEcdsaNormalSigningServiceResponseV1>,
    >;
}

pub(crate) struct CloudflareWorkerEcdsaNormalSigningServiceTransportV1<'a> {
    env: &'a worker::Env,
}

impl<'a> CloudflareWorkerEcdsaNormalSigningServiceTransportV1<'a> {
    pub(crate) fn new(env: &'a worker::Env) -> Self {
        Self { env }
    }
}

impl CloudflareRouterAbEcdsaNormalSigningServiceTransportV1
    for CloudflareWorkerEcdsaNormalSigningServiceTransportV1<'_>
{
    fn send<'a>(
        &'a mut self,
        peer: &'a CloudflarePeerBindingV1,
        request: CloudflareRouterAbEcdsaNormalSigningServiceRequestV1,
    ) -> LocalBoxFuture<
        'a,
        RouterAbProtocolResult<CloudflareRouterAbEcdsaNormalSigningServiceResponseV1>,
    > {
        Box::pin(async move {
            match request {
                CloudflareRouterAbEcdsaNormalSigningServiceRequestV1::Prepare(request) => {
                    let response = post_service_json(
                        self.env,
                        &peer.binding_name,
                        &cloudflare_signing_worker_router_ab_ecdsa_derivation_evm_digest_prepare_service_url(peer)?,
                        "Router A/B ECDSA derivation prepare",
                        &request,
                    )
                    .await?;
                    Ok(CloudflareRouterAbEcdsaNormalSigningServiceResponseV1::Prepare(response))
                }
                CloudflareRouterAbEcdsaNormalSigningServiceRequestV1::Finalize(request) => {
                    let response = post_service_json(
                        self.env,
                        &peer.binding_name,
                        &cloudflare_signing_worker_router_ab_ecdsa_derivation_evm_digest_finalize_service_url(peer)?,
                        "Router A/B ECDSA derivation finalize",
                        &request,
                    )
                    .await?;
                    Ok(CloudflareRouterAbEcdsaNormalSigningServiceResponseV1::Finalize(response))
                }
            }
        })
    }
}

pub(crate) async fn execute_cloudflare_router_ab_ecdsa_normal_signing_prepare_with_transport_v1<
    Transport,
>(
    transport: &mut Transport,
    peer: &CloudflarePeerBindingV1,
    request: CloudflareSigningWorkerAdmittedRouterAbEcdsaDerivationEvmDigestSigningRequestV1,
) -> RouterAbProtocolResult<RouterAbEcdsaDerivationEvmDigestSigningPrepareResponseV1>
where
    Transport: CloudflareRouterAbEcdsaNormalSigningServiceTransportV1,
{
    validate_signing_worker_target(peer, "Router A/B ECDSA derivation prepare")?;
    request.validate()?;
    let expected_request = request.request.clone();
    let response = transport
        .send(
            peer,
            CloudflareRouterAbEcdsaNormalSigningServiceRequestV1::Prepare(request),
        )
        .await?;
    let CloudflareRouterAbEcdsaNormalSigningServiceResponseV1::Prepare(response) = response else {
        return Err(wrong_response_branch("prepare"));
    };
    response.validate_for_request(&expected_request)?;
    Ok(response)
}

pub(crate) async fn execute_cloudflare_router_ab_ecdsa_normal_signing_finalize_with_transport_v1<
    Transport,
>(
    transport: &mut Transport,
    peer: &CloudflarePeerBindingV1,
    request: CloudflareSigningWorkerAdmittedRouterAbEcdsaDerivationEvmDigestFinalizeRequestV1,
) -> RouterAbProtocolResult<RouterAbEcdsaDerivationEvmDigestSigningResponseV1>
where
    Transport: CloudflareRouterAbEcdsaNormalSigningServiceTransportV1,
{
    validate_signing_worker_target(peer, "Router A/B ECDSA derivation finalize")?;
    request.validate()?;
    let expected_finalize_request = request.request.clone();
    let response = transport
        .send(
            peer,
            CloudflareRouterAbEcdsaNormalSigningServiceRequestV1::Finalize(request),
        )
        .await?;
    let CloudflareRouterAbEcdsaNormalSigningServiceResponseV1::Finalize(response) = response else {
        return Err(wrong_response_branch("finalize"));
    };
    response.validate_for_request(&expected_finalize_request)?;
    Ok(response)
}

fn validate_signing_worker_target(
    peer: &CloudflarePeerBindingV1,
    operation: &str,
) -> RouterAbProtocolResult<()> {
    peer.validate()?;
    if peer.peer_role == CloudflareWorkerRoleV1::SigningWorker {
        return Ok(());
    }
    Err(RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
        format!("{operation} must target SigningWorker"),
    ))
}

fn wrong_response_branch(operation: &str) -> RouterAbProtocolError {
    RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
        format!("Router A/B ECDSA derivation {operation} transport returned the wrong branch"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use futures::executor::block_on;

    const COMPRESSED_SECP256K1_GENERATOR: [u8; 33] = [
        0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
        0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16,
        0xf8, 0x17, 0x98,
    ];

    #[derive(Default)]
    struct CountingServiceTransport {
        router_calls: usize,
        deriver_a_calls: usize,
        deriver_b_calls: usize,
        signing_worker_calls: usize,
    }

    impl CountingServiceTransport {
        fn record_call(&mut self, role: CloudflareWorkerRoleV1) {
            match role {
                CloudflareWorkerRoleV1::Router => self.router_calls += 1,
                CloudflareWorkerRoleV1::DeriverA => self.deriver_a_calls += 1,
                CloudflareWorkerRoleV1::DeriverB => self.deriver_b_calls += 1,
                CloudflareWorkerRoleV1::SigningWorker => self.signing_worker_calls += 1,
            }
        }
    }

    impl CloudflareRouterAbEcdsaNormalSigningServiceTransportV1 for CountingServiceTransport {
        fn send<'a>(
            &'a mut self,
            peer: &'a CloudflarePeerBindingV1,
            request: CloudflareRouterAbEcdsaNormalSigningServiceRequestV1,
        ) -> LocalBoxFuture<
            'a,
            RouterAbProtocolResult<CloudflareRouterAbEcdsaNormalSigningServiceResponseV1>,
        > {
            Box::pin(async move {
                self.record_call(peer.peer_role);
                match request {
                    CloudflareRouterAbEcdsaNormalSigningServiceRequestV1::Prepare(request) => {
                        let response =
                            RouterAbEcdsaDerivationEvmDigestSigningPrepareResponseV1::new_for_request(
                                &request.request,
                                request.request.client_presignature_id.clone(),
                                base64url(&COMPRESSED_SECP256K1_GENERATOR),
                                base64url(&[0x55; 32]),
                                1_500,
                            )?;
                        Ok(
                            CloudflareRouterAbEcdsaNormalSigningServiceResponseV1::Prepare(
                                response,
                            ),
                        )
                    }
                    CloudflareRouterAbEcdsaNormalSigningServiceRequestV1::Finalize(request) => {
                        let response =
                            RouterAbEcdsaDerivationEvmDigestSigningResponseV1::new_for_request(
                                &request.request,
                                base64url(&[0x99; 65]),
                            )?;
                        Ok(
                            CloudflareRouterAbEcdsaNormalSigningServiceResponseV1::Finalize(
                                response,
                            ),
                        )
                    }
                }
            })
        }
    }

    #[test]
    fn normal_ecdsa_prepare_and_finalize_dispatch_only_to_signing_worker() {
        let prepare_request = prepare_request();
        let finalize_request = finalize_request(&prepare_request);
        let admitted_prepare = admitted_prepare_request(prepare_request);
        let admitted_finalize = admitted_finalize_request(finalize_request);
        let signing_worker =
            CloudflarePeerBindingV1::new(CloudflareWorkerRoleV1::SigningWorker, "SIGNING_WORKER")
                .expect("SigningWorker peer");
        let mut transport = CountingServiceTransport::default();

        block_on(async {
            execute_cloudflare_router_ab_ecdsa_normal_signing_prepare_with_transport_v1(
                &mut transport,
                &signing_worker,
                admitted_prepare,
            )
            .await
            .expect("prepare dispatches");
            execute_cloudflare_router_ab_ecdsa_normal_signing_finalize_with_transport_v1(
                &mut transport,
                &signing_worker,
                admitted_finalize,
            )
            .await
            .expect("finalize dispatches");
        });

        assert_eq!(transport.signing_worker_calls, 2);
        assert_eq!(transport.deriver_a_calls, 0);
        assert_eq!(transport.deriver_b_calls, 0);
        assert_eq!(transport.router_calls, 0);
    }

    fn prepare_request() -> RouterAbEcdsaDerivationEvmDigestSigningRequestV1 {
        RouterAbEcdsaDerivationEvmDigestSigningRequestV1::new(
            normal_signing_scope(),
            "normal-signing-request-1",
            "presignature-1",
            2_000,
            base64url(&[0x77; 32]),
            base64url(
                &router_ab_core::router_ab_ecdsa_rerandomization_client_commitment_v1([0x44; 32]),
            ),
        )
        .expect("prepare request")
    }

    fn finalize_request(
        prepare: &RouterAbEcdsaDerivationEvmDigestSigningRequestV1,
    ) -> RouterAbEcdsaDerivationEvmDigestSigningFinalizeRequestV1 {
        RouterAbEcdsaDerivationEvmDigestSigningFinalizeRequestV1::new(
            prepare.scope.clone(),
            prepare.request_id.clone(),
            prepare.expires_at_ms,
            prepare.signing_digest_b64u.clone(),
            prepare.client_presignature_id.clone(),
            base64url(&[0x88; 32]),
            base64url(&[0x44; 32]),
        )
        .expect("finalize request")
    }

    fn admitted_prepare_request(
        request: RouterAbEcdsaDerivationEvmDigestSigningRequestV1,
    ) -> CloudflareSigningWorkerAdmittedRouterAbEcdsaDerivationEvmDigestSigningRequestV1 {
        let admission =
            trusted_admission(&request.scope, request.request_digest().expect("digest"));
        CloudflareSigningWorkerAdmittedRouterAbEcdsaDerivationEvmDigestSigningRequestV1::new(
            request, admission,
        )
        .expect("admitted prepare")
    }

    fn admitted_finalize_request(
        request: RouterAbEcdsaDerivationEvmDigestSigningFinalizeRequestV1,
    ) -> CloudflareSigningWorkerAdmittedRouterAbEcdsaDerivationEvmDigestFinalizeRequestV1 {
        let admission =
            trusted_admission(&request.scope, request.request_digest().expect("digest"));
        CloudflareSigningWorkerAdmittedRouterAbEcdsaDerivationEvmDigestFinalizeRequestV1::new(
            request, admission,
        )
        .expect("admitted finalize")
    }

    fn trusted_admission(
        scope: &RouterAbEcdsaDerivationNormalSigningScopeV1,
        intent_digest: PublicDigest32,
    ) -> CloudflareRouterNormalSigningTrustedAdmissionV1 {
        let session_id = scope.active_state_session_id().expect("active session id");
        let metadata = CloudflareRouterNormalSigningTrustedMetadataV1::new(
            "org-1",
            "project-1",
            "dev",
            scope.wallet_id.clone(),
            CloudflareRouterAuthContextV1::authenticated_session("subject-1", session_id)
                .expect("auth context"),
            PublicDigest32::new([0x42; 32]),
            intent_digest,
        )
        .expect("trusted metadata");
        CloudflareRouterNormalSigningTrustedAdmissionV1::new(
            metadata,
            ExpensiveWorkGateDecisionV1::accepted("gate-request-1")
                .expect("accepted gate decision"),
        )
        .expect("trusted admission")
    }

    fn normal_signing_scope() -> RouterAbEcdsaDerivationNormalSigningScopeV1 {
        let context = RouterAbEcdsaDerivationStableKeyContextV1::new(base64url(&[0x42; 32]))
            .expect("stable context");
        let context_binding = context.context_binding_digest().expect("context binding");
        let public_identity = RouterAbEcdsaDerivationPublicIdentityV1::new(
            base64url(context_binding.as_bytes()),
            base64url(&COMPRESSED_SECP256K1_GENERATOR),
            base64url(&COMPRESSED_SECP256K1_GENERATOR),
            base64url(&COMPRESSED_SECP256K1_GENERATOR),
            base64url(&[0x11; 20]),
            0,
            0,
        )
        .expect("public identity");
        RouterAbEcdsaDerivationNormalSigningScopeV1::new(
            "wallet-key-1",
            "wallet-1",
            "threshold-key-1",
            "signing-root-1",
            "7",
            context,
            public_identity,
            ServerIdentityV1::new("signing-worker-1", "key-epoch-1", "x25519:public-key")
                .expect("SigningWorker identity"),
            "root-epoch-7",
        )
        .expect("normal-signing scope")
    }

    fn base64url(bytes: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(bytes)
    }
}
