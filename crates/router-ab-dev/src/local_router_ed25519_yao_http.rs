use router_ab_core::{
    Ed25519YaoCeremonyBindingV1, Ed25519YaoEncryptedInputV1, Ed25519YaoInputPairBindingV1,
    Ed25519YaoOperationV1, PublicDigest32, RouterAbEd25519YaoExportBindingV1,
    RouterAbProtocolError, RouterAbProtocolErrorCode, RouterAbProtocolResult,
    RouterAdmittedExecutionAuthorityV1, RouterEd25519YaoExecuteRequestV1,
    RouterEd25519YaoGatewayExecuteRequestV1,
};

/// Exact role inputs extracted from one validated Router execution request.
///
/// This adapter carries opaque encrypted inputs only. It does not decrypt or
/// persist role material, and it does not perform lifecycle transitions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalRouterEd25519YaoPairDispatchV1 {
    pub authority: RouterAdmittedExecutionAuthorityV1,
    pub operation: Ed25519YaoOperationV1,
    pub binding: Ed25519YaoCeremonyBindingV1,
    pub export_binding: Option<RouterAbEd25519YaoExportBindingV1>,
    pub work: router_ab_cloudflare::CloudflareEd25519YaoPairWorkV1,
    pub pair_binding: Ed25519YaoInputPairBindingV1,
    pub deriver_a_input: Ed25519YaoEncryptedInputV1,
    pub deriver_b_input: Ed25519YaoEncryptedInputV1,
}

impl LocalRouterEd25519YaoPairDispatchV1 {
    /// Converts the canonical core request into role-specific dispatch data.
    pub fn from_request(request: RouterEd25519YaoExecuteRequestV1) -> Self {
        match request {
            RouterEd25519YaoExecuteRequestV1::Registration {
                authority,
                binding,
                pair_binding,
                deriver_a_input,
                deriver_b_input,
            }
            | RouterEd25519YaoExecuteRequestV1::Recovery {
                authority,
                binding,
                pair_binding,
                deriver_a_input,
                deriver_b_input,
            } => Self {
                authority,
                operation: binding.operation,
                binding,
                export_binding: None,
                work: router_ab_cloudflare::CloudflareEd25519YaoPairWorkV1::Ceremony,
                pair_binding,
                deriver_a_input,
                deriver_b_input,
            },
            RouterEd25519YaoExecuteRequestV1::Export {
                authority,
                binding,
                pair_binding,
                deriver_a_input,
                deriver_b_input,
            } => Self {
                authority,
                operation: binding.ceremony().operation,
                binding: binding.ceremony().clone(),
                export_binding: Some(binding),
                work: router_ab_cloudflare::CloudflareEd25519YaoPairWorkV1::Ceremony,
                pair_binding,
                deriver_a_input,
                deriver_b_input,
            },
            RouterEd25519YaoExecuteRequestV1::LaneProvisioning {
                authority,
                binding,
                pair_binding,
                job,
                deriver_a_input,
                deriver_b_input,
            }
            | RouterEd25519YaoExecuteRequestV1::LaneRefresh {
                authority,
                binding,
                pair_binding,
                job,
                deriver_a_input,
                deriver_b_input,
            } => Self {
                authority,
                operation: binding.operation,
                binding,
                export_binding: None,
                work: router_ab_cloudflare::CloudflareEd25519YaoPairWorkV1::Lane { job },
                pair_binding,
                deriver_a_input,
                deriver_b_input,
            },
        }
    }

    /// Revalidates the pair identity before any role-boundary call.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.binding.validate()?;
        match (self.operation, self.export_binding.is_some()) {
            (Ed25519YaoOperationV1::Export, true)
            | (Ed25519YaoOperationV1::Registration, false)
            | (Ed25519YaoOperationV1::Recovery, false)
            | (Ed25519YaoOperationV1::LaneProvisioning, false)
            | (Ed25519YaoOperationV1::LaneRefresh, false) => {}
            (Ed25519YaoOperationV1::Export, false) => {
                return Err(pair_http_error(
                    "Router export dispatch is missing its export binding",
                ))
            }
            (
                Ed25519YaoOperationV1::Registration
                | Ed25519YaoOperationV1::Recovery
                | Ed25519YaoOperationV1::LaneProvisioning
                | Ed25519YaoOperationV1::LaneRefresh,
                true,
            ) => {
                return Err(pair_http_error(
                    "non-export dispatch carries an export binding",
                ))
            }
            (Ed25519YaoOperationV1::Refresh, _) => {
                return Err(pair_http_error(
                    "Router refresh is not an admitted Yao operation",
                ))
            }
        }
        if let Some(export_binding) = &self.export_binding {
            if export_binding.ceremony() != &self.binding {
                return Err(pair_http_error(
                    "Router export binding does not match its ceremony",
                ));
            }
        }
        self.pair_binding.validate()?;
        if self.pair_binding.ceremony().binding() != &self.binding
            || self.pair_binding.ceremony().binding().operation != self.operation
        {
            return Err(pair_http_error(
                "Router pair dispatch binding does not match its operation",
            ));
        }
        self.deriver_a_input.validate()?;
        self.deriver_b_input.validate()?;
        if self.deriver_a_input.deriver() != router_ab_core::Ed25519YaoDeriverRoleV1::DeriverA
            || self.deriver_b_input.deriver() != router_ab_core::Ed25519YaoDeriverRoleV1::DeriverB
        {
            return Err(pair_http_error(
                "Router pair dispatch role inputs are assigned to the wrong derivers",
            ));
        }
        if self.deriver_a_input.session() != self.pair_binding.session()
            || self.deriver_b_input.session() != self.pair_binding.session()
        {
            return Err(pair_http_error(
                "Router pair dispatch role sessions do not match the pair",
            ));
        }
        Ok(())
    }
}

/// Decodes and validates the canonical Gateway→Router execution body once.
pub fn decode_local_router_ed25519_yao_execute_request_v1(
    body: &[u8],
    recipient_set_digest: PublicDigest32,
    issued_at_ms: u64,
    expires_at_ms: u64,
) -> RouterAbProtocolResult<LocalRouterEd25519YaoPairDispatchV1> {
    let gateway_request = serde_json::from_slice::<RouterEd25519YaoGatewayExecuteRequestV1>(body)
        .map_err(|error| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("local Router Ed25519 Yao execute request is malformed: {error}"),
        )
    })?;
    let request =
        gateway_request.into_execute_request(recipient_set_digest, issued_at_ms, expires_at_ms)?;
    let dispatch = LocalRouterEd25519YaoPairDispatchV1::from_request(request);
    dispatch.validate()?;
    Ok(dispatch)
}

fn pair_http_error(message: &'static str) -> RouterAbProtocolError {
    RouterAbProtocolError::new(RouterAbProtocolErrorCode::InvalidLifecycleState, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use router_ab_core::{
        Ed25519YaoCeremonyBindingV1, Ed25519YaoDeriverRoleV1, Ed25519YaoEncryptedInputV1,
        Ed25519YaoInputKindV1, Ed25519YaoOperationV1, Ed25519YaoSessionIdV1,
        Ed25519YaoStableKeyContextBindingV1, ExpensiveWorkKindV1, LifecycleScopeV1,
        MpcMaterialActivationRefV1, RootShareEpoch,
    };

    fn request_fixture() -> RouterEd25519YaoGatewayExecuteRequestV1 {
        let lifecycle = LifecycleScopeV1::new(
            "local-http",
            ExpensiveWorkKindV1::RegistrationPrepare,
            RootShareEpoch::new("local-root").expect("root epoch"),
            "local-account",
            "local-session",
            "local-signer-set",
            "local-worker",
        )
        .expect("lifecycle");
        let session = Ed25519YaoSessionIdV1::new([0x51; 32]).expect("session");
        let stable = Ed25519YaoStableKeyContextBindingV1::new([0x61; 32]);
        let binding = Ed25519YaoCeremonyBindingV1::new(
            lifecycle,
            Ed25519YaoOperationV1::Registration,
            session,
            stable,
            MpcMaterialActivationRefV1::new(
                "http-activation",
                "http-capability",
                "local-account",
                "http-key",
                "local-http",
                "local-worker",
            )
            .expect("material activation"),
        )
        .expect("binding");
        let input_a = Ed25519YaoEncryptedInputV1::new(
            Ed25519YaoInputKindV1::Activation,
            Ed25519YaoDeriverRoleV1::DeriverA,
            Ed25519YaoOperationV1::Registration,
            [0x51; 32],
            [0x61; 32],
            [0x81; 32],
            vec![0x91; 16],
        )
        .expect("A input");
        let input_b = Ed25519YaoEncryptedInputV1::new(
            Ed25519YaoInputKindV1::Activation,
            Ed25519YaoDeriverRoleV1::DeriverB,
            Ed25519YaoOperationV1::Registration,
            [0x51; 32],
            [0x61; 32],
            [0x82; 32],
            vec![0x92; 16],
        )
        .expect("B input");
        RouterEd25519YaoGatewayExecuteRequestV1::registration(binding, input_a, input_b)
            .expect("gateway request")
    }

    #[test]
    fn canonical_request_decodes_into_exact_role_inputs() {
        let request = request_fixture();
        let encoded = serde_json::to_vec(&request).expect("request JSON");
        let encoded_text = std::str::from_utf8(&encoded).expect("request JSON is UTF-8");
        assert!(!encoded_text.contains("\"authority\""));
        assert!(!encoded_text.contains("\"pair_binding\""));
        let recipient_set_digest = PublicDigest32::new([0xa1; 32]);
        let dispatch = decode_local_router_ed25519_yao_execute_request_v1(
            &encoded,
            recipient_set_digest,
            1,
            100,
        )
        .expect("request should decode");
        assert_eq!(dispatch.operation, Ed25519YaoOperationV1::Registration);
        assert_eq!(dispatch.deriver_a_input.ciphertext(), &[0x91; 16]);
        assert_eq!(dispatch.deriver_b_input.ciphertext(), &[0x92; 16]);
        assert_eq!(
            dispatch.pair_binding.recipient_set_digest(),
            recipient_set_digest
        );
        assert_eq!(
            dispatch.authority.authority_digest(),
            dispatch.pair_binding.authorization_digest()
        );
    }

    #[test]
    fn malformed_canonical_request_is_rejected_before_dispatch() {
        let error = decode_local_router_ed25519_yao_execute_request_v1(
            br#"{"operation":"registration","unknown":true}"#,
            PublicDigest32::new([0xa1; 32]),
            1,
            100,
        )
        .expect_err("unknown fields must be rejected");
        assert_eq!(
            error.code(),
            RouterAbProtocolErrorCode::MalformedWirePayload
        );
    }
}
