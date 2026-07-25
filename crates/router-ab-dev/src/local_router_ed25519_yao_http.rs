use router_ab_core::{
    Ed25519YaoCeremonyBindingV1, Ed25519YaoEncryptedInputV1, Ed25519YaoInputPairBindingV1,
    Ed25519YaoOperationV1, RouterAbProtocolError, RouterAbProtocolErrorCode,
    RouterAbProtocolResult, RouterAdmittedExecutionAuthorityV1, RouterEd25519YaoExecuteRequestV1,
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
                pair_binding,
                deriver_a_input,
                deriver_b_input,
            },
        }
    }

    /// Revalidates the pair identity before any role-boundary call.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.binding.validate()?;
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
) -> RouterAbProtocolResult<LocalRouterEd25519YaoPairDispatchV1> {
    let request =
        serde_json::from_slice::<RouterEd25519YaoExecuteRequestV1>(body).map_err(|error| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                format!("local Router Ed25519 Yao execute request is malformed: {error}"),
            )
        })?;
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
        Ed25519YaoCeremonyBindingV1, Ed25519YaoCeremonyIdentityV1, Ed25519YaoDeriverRoleV1,
        Ed25519YaoEncryptedInputV1, Ed25519YaoInputKindV1, Ed25519YaoOperationV1,
        Ed25519YaoSessionIdV1, Ed25519YaoStableKeyContextBindingV1, ExpensiveWorkKindV1,
        LifecycleScopeV1, PublicDigest32, RootShareEpoch,
    };

    fn request_fixture() -> RouterEd25519YaoExecuteRequestV1 {
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
        let ceremony =
            Ed25519YaoCeremonyIdentityV1::from_binding(binding.clone()).expect("ceremony identity");
        let pair = Ed25519YaoInputPairBindingV1::from_inputs(
            ceremony,
            &input_a,
            &input_b,
            PublicDigest32::new([0xa1; 32]),
            PublicDigest32::new([0xb1; 32]),
        )
        .expect("pair");
        let authority =
            RouterAdmittedExecutionAuthorityV1::new(pair.authorization_digest(), 1, 100)
                .expect("authority");
        RouterEd25519YaoExecuteRequestV1::registration(authority, binding, pair, input_a, input_b)
            .expect("request")
    }

    #[test]
    fn canonical_request_decodes_into_exact_role_inputs() {
        let request = request_fixture();
        let encoded = serde_json::to_vec(&request).expect("request JSON");
        let dispatch = decode_local_router_ed25519_yao_execute_request_v1(&encoded)
            .expect("request should decode");
        assert_eq!(dispatch.operation, Ed25519YaoOperationV1::Registration);
        assert_eq!(dispatch.deriver_a_input.ciphertext(), &[0x91; 16]);
        assert_eq!(dispatch.deriver_b_input.ciphertext(), &[0x92; 16]);
        assert_eq!(
            dispatch.pair_binding.pair_digest(),
            request.pair_binding().pair_digest()
        );
    }

    #[test]
    fn malformed_canonical_request_is_rejected_before_dispatch() {
        let error = decode_local_router_ed25519_yao_execute_request_v1(
            br#"{"operation":"registration","unknown":true}"#,
        )
        .expect_err("unknown fields must be rejected");
        assert_eq!(
            error.code(),
            RouterAbProtocolErrorCode::MalformedWirePayload
        );
    }
}
