//! Contract-level Refactor 93 coordinator choreography.
//!
//! This module deliberately has no Worker bindings and is not wired into a
//! production route yet. It freezes the Phase 3 call sequence against role
//! ports while the role-local Phase 2 commands are finalized.

use futures::future::{join, LocalBoxFuture};
use router_ab_core::{
    Ed25519YaoDeriverRoleV1, Ed25519YaoEncryptedInputV1, Ed25519YaoInputPairBindingV1,
    Ed25519YaoOperationV1, Ed25519YaoRoleReadinessReceiptV1, PublicDigest32,
    RouterEd25519YaoExecuteRequestV1,
};

/// Sanitized coordinator failure classes. The coordinator never retries a
/// role call after it has been issued.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refactor93CoordinatorError {
    /// The request failed boundary validation.
    InvalidRequest,
    /// A role failed while preparing its exact pair.
    PreparationFailed(Ed25519YaoDeriverRoleV1),
    /// A readiness receipt was missing or did not match the pair.
    ReadinessMismatch(Ed25519YaoDeriverRoleV1),
    /// A role failed after preparation.
    ExecutionFailed(Ed25519YaoDeriverRoleV1),
    /// A role result did not match the exact pair or transcript.
    ResultMismatch(Ed25519YaoDeriverRoleV1),
    /// SigningWorker delivery failed or was uncertain.
    SigningWorkerDeliveryFailed,
}

/// Exact opaque input sent to one role's preparation command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refactor93RolePrepareRequest {
    /// Operation selected by the admitted request.
    pub operation: Ed25519YaoOperationV1,
    /// Canonical A/B pair binding.
    pub pair_binding: Ed25519YaoInputPairBindingV1,
    /// Opaque role envelope.
    pub input: Ed25519YaoEncryptedInputV1,
}

/// Exact request sent to Deriver A after both roles prepare.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refactor93RoleExecuteRequest {
    /// Operation selected by the admitted request.
    pub operation: Ed25519YaoOperationV1,
    /// Canonical A/B pair binding.
    pub pair_binding: Ed25519YaoInputPairBindingV1,
    /// A readiness proof.
    pub readiness_a: Ed25519YaoRoleReadinessReceiptV1,
    /// B readiness proof.
    pub readiness_b: Ed25519YaoRoleReadinessReceiptV1,
}

/// Exact request sent to B for its already-completed encrypted output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refactor93CompletedReadRequest {
    /// Operation selected by the admitted request.
    pub operation: Ed25519YaoOperationV1,
    /// Canonical A/B pair binding.
    pub pair_binding: Ed25519YaoInputPairBindingV1,
    /// Transcript digest returned by A.
    pub transcript_digest: PublicDigest32,
}

/// Opaque role result returned after the existing Yao protocol completes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refactor93RoleResult {
    /// Role that produced the result.
    pub role: Ed25519YaoDeriverRoleV1,
    /// Pair digest bound into the result.
    pub pair_digest: PublicDigest32,
    /// Public transcript digest shared by both roles.
    pub transcript_digest: PublicDigest32,
    /// Encrypted role package. The coordinator never interprets these bytes.
    pub encrypted_package: Vec<u8>,
}

/// Atomic package pair handed to SigningWorker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refactor93SigningWorkerDeliveryRequest {
    /// Operation selected by the admitted request.
    pub operation: Ed25519YaoOperationV1,
    /// Canonical A/B pair binding.
    pub pair_binding: Ed25519YaoInputPairBindingV1,
    /// Shared transcript digest.
    pub transcript_digest: PublicDigest32,
    /// A's encrypted package.
    pub package_a: Vec<u8>,
    /// B's encrypted package.
    pub package_b: Vec<u8>,
}

/// Sanitized result returned by the contract-level coordinator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refactor93CoordinatorResult {
    /// Operation selected by the admitted request.
    pub operation: Ed25519YaoOperationV1,
    /// Canonical A/B pair digest.
    pub pair_digest: PublicDigest32,
    /// Shared transcript digest.
    pub transcript_digest: PublicDigest32,
    /// Opaque SigningWorker receipt.
    pub signing_worker_receipt: Vec<u8>,
}

/// Port implemented by one role adapter.
pub trait Refactor93RolePort {
    /// Persists exact prepared state and returns a signed readiness receipt.
    fn prepare_pair<'a>(
        &'a mut self,
        request: Refactor93RolePrepareRequest,
    ) -> LocalBoxFuture<'a, Result<Ed25519YaoRoleReadinessReceiptV1, Refactor93CoordinatorError>>;

    /// Runs A's existing protocol after both receipts are verified.
    fn execute_pair<'a>(
        &'a mut self,
        request: Refactor93RoleExecuteRequest,
    ) -> LocalBoxFuture<'a, Result<Refactor93RoleResult, Refactor93CoordinatorError>>;

    /// Reads B's exact completed result without polling or reevaluation.
    fn read_completed_pair<'a>(
        &'a mut self,
        request: Refactor93CompletedReadRequest,
    ) -> LocalBoxFuture<'a, Result<Refactor93RoleResult, Refactor93CoordinatorError>>;
}

/// Port implemented by the atomic SigningWorker adapter.
pub trait Refactor93SigningWorkerPort {
    /// Delivers both encrypted packages as one command.
    fn deliver_atomic<'a>(
        &'a mut self,
        request: Refactor93SigningWorkerDeliveryRequest,
    ) -> LocalBoxFuture<'a, Result<Vec<u8>, Refactor93CoordinatorError>>;
}

/// Pure Phase 3 choreography. It performs one preparation call per role,
/// exactly one A execution, one exact B completed read, and one atomic
/// SigningWorker delivery.
pub struct Refactor93Coordinator;

impl Refactor93Coordinator {
    /// Executes the contract-level choreography without Worker or Gateway I/O.
    pub async fn execute<A, B, S>(
        request: RouterEd25519YaoExecuteRequestV1,
        now_ms: u64,
        deriver_a: &mut A,
        deriver_b: &mut B,
        signing_worker: &mut S,
    ) -> Result<Refactor93CoordinatorResult, Refactor93CoordinatorError>
    where
        A: Refactor93RolePort,
        B: Refactor93RolePort,
        S: Refactor93SigningWorkerPort,
    {
        request
            .authority()
            .validate_at(now_ms)
            .map_err(|_| Refactor93CoordinatorError::InvalidRequest)?;
        request
            .pair_binding()
            .validate()
            .map_err(|_| Refactor93CoordinatorError::InvalidRequest)?;
        let (pair_binding, input_a, input_b) = request_parts(&request)?;
        let operation = request.operation();

        let prepare_a = deriver_a.prepare_pair(Refactor93RolePrepareRequest {
            operation,
            pair_binding: pair_binding.clone(),
            input: input_a,
        });
        let prepare_b = deriver_b.prepare_pair(Refactor93RolePrepareRequest {
            operation,
            pair_binding: pair_binding.clone(),
            input: input_b,
        });
        let (prepared_a, prepared_b) = join(prepare_a, prepare_b).await;
        let readiness_a = prepared_a.map_err(|_| {
            Refactor93CoordinatorError::PreparationFailed(Ed25519YaoDeriverRoleV1::DeriverA)
        })?;
        let readiness_b = prepared_b.map_err(|_| {
            Refactor93CoordinatorError::PreparationFailed(Ed25519YaoDeriverRoleV1::DeriverB)
        })?;
        validate_readiness(
            &readiness_a,
            &pair_binding,
            now_ms,
            Ed25519YaoDeriverRoleV1::DeriverA,
        )?;
        validate_readiness(
            &readiness_b,
            &pair_binding,
            now_ms,
            Ed25519YaoDeriverRoleV1::DeriverB,
        )?;

        let execution = deriver_a
            .execute_pair(Refactor93RoleExecuteRequest {
                operation,
                pair_binding: pair_binding.clone(),
                readiness_a,
                readiness_b,
            })
            .await
            .map_err(|_| {
                Refactor93CoordinatorError::ExecutionFailed(Ed25519YaoDeriverRoleV1::DeriverA)
            })?;
        validate_role_result(
            &execution,
            Ed25519YaoDeriverRoleV1::DeriverA,
            pair_binding.pair_digest(),
            None,
        )?;

        let completed = deriver_b
            .read_completed_pair(Refactor93CompletedReadRequest {
                operation,
                pair_binding: pair_binding.clone(),
                transcript_digest: execution.transcript_digest,
            })
            .await
            .map_err(|_| {
                Refactor93CoordinatorError::ExecutionFailed(Ed25519YaoDeriverRoleV1::DeriverB)
            })?;
        validate_role_result(
            &completed,
            Ed25519YaoDeriverRoleV1::DeriverB,
            pair_binding.pair_digest(),
            Some(execution.transcript_digest),
        )?;

        let signing_worker_receipt = signing_worker
            .deliver_atomic(Refactor93SigningWorkerDeliveryRequest {
                operation,
                pair_binding: pair_binding.clone(),
                transcript_digest: execution.transcript_digest,
                package_a: execution.encrypted_package,
                package_b: completed.encrypted_package,
            })
            .await
            .map_err(|_| Refactor93CoordinatorError::SigningWorkerDeliveryFailed)?;

        Ok(Refactor93CoordinatorResult {
            operation,
            pair_digest: pair_binding.pair_digest(),
            transcript_digest: execution.transcript_digest,
            signing_worker_receipt,
        })
    }
}

fn request_parts(
    request: &RouterEd25519YaoExecuteRequestV1,
) -> Result<
    (
        Ed25519YaoInputPairBindingV1,
        Ed25519YaoEncryptedInputV1,
        Ed25519YaoEncryptedInputV1,
    ),
    Refactor93CoordinatorError,
> {
    match request {
        RouterEd25519YaoExecuteRequestV1::Registration {
            pair_binding,
            deriver_a_input,
            deriver_b_input,
            ..
        }
        | RouterEd25519YaoExecuteRequestV1::Recovery {
            pair_binding,
            deriver_a_input,
            deriver_b_input,
            ..
        }
        | RouterEd25519YaoExecuteRequestV1::Export {
            pair_binding,
            deriver_a_input,
            deriver_b_input,
            ..
        } => Ok((
            pair_binding.clone(),
            deriver_a_input.clone(),
            deriver_b_input.clone(),
        )),
    }
}

fn validate_readiness(
    receipt: &Ed25519YaoRoleReadinessReceiptV1,
    pair_binding: &Ed25519YaoInputPairBindingV1,
    now_ms: u64,
    expected_role: Ed25519YaoDeriverRoleV1,
) -> Result<(), Refactor93CoordinatorError> {
    if receipt.role() != expected_role
        || receipt.validate_for_pair(pair_binding).is_err()
        || receipt.validate_at(now_ms).is_err()
    {
        return Err(Refactor93CoordinatorError::ReadinessMismatch(expected_role));
    }
    Ok(())
}

fn validate_role_result(
    result: &Refactor93RoleResult,
    expected_role: Ed25519YaoDeriverRoleV1,
    expected_pair_digest: PublicDigest32,
    expected_transcript_digest: Option<PublicDigest32>,
) -> Result<(), Refactor93CoordinatorError> {
    if result.role != expected_role
        || result.pair_digest != expected_pair_digest
        || expected_transcript_digest.is_some_and(|digest| result.transcript_digest != digest)
    {
        return Err(Refactor93CoordinatorError::ResultMismatch(expected_role));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use router_ab_core::{
        Ed25519YaoCeremonyBindingV1, Ed25519YaoSessionIdV1, Ed25519YaoStableKeyContextBindingV1,
        ExpensiveWorkKindV1, LifecycleScopeV1, RootShareEpoch, RouterAdmittedExecutionAuthorityV1,
    };
    use std::cell::RefCell;
    use std::rc::Rc;

    #[derive(Default)]
    struct FakeState {
        prepare_started: usize,
        prepare_calls: usize,
        execute_calls: usize,
        completed_read_calls: usize,
        delivered_calls: usize,
    }

    struct FakeRole {
        state: Rc<RefCell<FakeState>>,
        execution: Result<Refactor93RoleResult, Refactor93CoordinatorError>,
        completed: Result<Refactor93RoleResult, Refactor93CoordinatorError>,
        preparation: Option<Result<Ed25519YaoRoleReadinessReceiptV1, Refactor93CoordinatorError>>,
    }

    impl Refactor93RolePort for FakeRole {
        fn prepare_pair<'a>(
            &'a mut self,
            _request: Refactor93RolePrepareRequest,
        ) -> LocalBoxFuture<'a, Result<Ed25519YaoRoleReadinessReceiptV1, Refactor93CoordinatorError>>
        {
            let state = self.state.clone();
            let preparation = self
                .preparation
                .take()
                .expect("fake preparation called once");
            Box::pin(async move {
                state.borrow_mut().prepare_started += 1;
                state.borrow_mut().prepare_calls += 1;
                preparation
            })
        }

        fn execute_pair<'a>(
            &'a mut self,
            _request: Refactor93RoleExecuteRequest,
        ) -> LocalBoxFuture<'a, Result<Refactor93RoleResult, Refactor93CoordinatorError>> {
            let state = self.state.clone();
            let execution = self.execution.clone();
            Box::pin(async move {
                state.borrow_mut().execute_calls += 1;
                execution
            })
        }

        fn read_completed_pair<'a>(
            &'a mut self,
            _request: Refactor93CompletedReadRequest,
        ) -> LocalBoxFuture<'a, Result<Refactor93RoleResult, Refactor93CoordinatorError>> {
            let state = self.state.clone();
            let completed = self.completed.clone();
            Box::pin(async move {
                state.borrow_mut().completed_read_calls += 1;
                completed
            })
        }
    }

    struct FakeSigningWorker {
        state: Rc<RefCell<FakeState>>,
        result: Result<Vec<u8>, Refactor93CoordinatorError>,
    }

    impl Refactor93SigningWorkerPort for FakeSigningWorker {
        fn deliver_atomic<'a>(
            &'a mut self,
            _request: Refactor93SigningWorkerDeliveryRequest,
        ) -> LocalBoxFuture<'a, Result<Vec<u8>, Refactor93CoordinatorError>> {
            let state = self.state.clone();
            let result = self.result.clone();
            Box::pin(async move {
                state.borrow_mut().delivered_calls += 1;
                result
            })
        }
    }

    fn binding() -> Ed25519YaoCeremonyBindingV1 {
        Ed25519YaoCeremonyBindingV1::new(
            LifecycleScopeV1::new(
                "lifecycle-1",
                ExpensiveWorkKindV1::RegistrationPrepare,
                RootShareEpoch::new("epoch-1").expect("epoch"),
                "account-1",
                "session-1",
                "signer-set-1",
                "server-1",
            )
            .expect("lifecycle"),
            Ed25519YaoOperationV1::Registration,
            Ed25519YaoSessionIdV1::new([1; 32]).expect("session"),
            Ed25519YaoStableKeyContextBindingV1::new([2; 32]),
        )
        .expect("binding")
    }

    fn input(role: Ed25519YaoDeriverRoleV1, fill: u8) -> Ed25519YaoEncryptedInputV1 {
        Ed25519YaoEncryptedInputV1::new(
            router_ab_core::Ed25519YaoInputKindV1::Activation,
            role,
            Ed25519YaoOperationV1::Registration,
            [1; 32],
            [2; 32],
            [3; 32],
            vec![fill; 32],
        )
        .expect("input")
    }

    fn request() -> (
        RouterEd25519YaoExecuteRequestV1,
        Ed25519YaoInputPairBindingV1,
    ) {
        let binding = binding();
        let ceremony = router_ab_core::Ed25519YaoCeremonyIdentityV1::from_binding(binding.clone())
            .expect("identity");
        let a = input(Ed25519YaoDeriverRoleV1::DeriverA, 4);
        let b = input(Ed25519YaoDeriverRoleV1::DeriverB, 5);
        let pair = Ed25519YaoInputPairBindingV1::from_inputs(
            ceremony,
            &a,
            &b,
            PublicDigest32::new([6; 32]),
            PublicDigest32::new([7; 32]),
        )
        .expect("pair");
        let authority =
            RouterAdmittedExecutionAuthorityV1::new(PublicDigest32::new([8; 32]), 10, 100)
                .expect("authority");
        (
            RouterEd25519YaoExecuteRequestV1::registration(authority, binding, pair.clone(), a, b)
                .expect("request"),
            pair,
        )
    }

    fn receipt(
        role: Ed25519YaoDeriverRoleV1,
        pair: &Ed25519YaoInputPairBindingV1,
        pair_digest: PublicDigest32,
    ) -> Ed25519YaoRoleReadinessReceiptV1 {
        let local_digest = match role {
            Ed25519YaoDeriverRoleV1::DeriverA => pair.deriver_a_input_digest(),
            Ed25519YaoDeriverRoleV1::DeriverB => pair.deriver_b_input_digest(),
        };
        Ed25519YaoRoleReadinessReceiptV1::new(
            role,
            pair.ceremony().binding().session_id,
            pair_digest,
            local_digest,
            PublicDigest32::new([9; 32]),
            10,
            100,
            router_ab_core::Ed25519YaoRoleSignatureV1::new(
                router_ab_core::Ed25519YaoRoleSignatureSchemeV1::Ed25519V1,
                [10 + role.wire_tag(); 64],
            )
            .expect("signature"),
        )
        .expect("receipt")
    }

    fn role_result(
        role: Ed25519YaoDeriverRoleV1,
        pair: &Ed25519YaoInputPairBindingV1,
        transcript_digest: PublicDigest32,
    ) -> Refactor93RoleResult {
        Refactor93RoleResult {
            role,
            pair_digest: pair.pair_digest(),
            transcript_digest,
            encrypted_package: vec![role.wire_tag(); 4],
        }
    }

    fn fake_role(
        _role: Ed25519YaoDeriverRoleV1,
        state: Rc<RefCell<FakeState>>,
        receipt: Ed25519YaoRoleReadinessReceiptV1,
        execution: Result<Refactor93RoleResult, Refactor93CoordinatorError>,
        completed: Result<Refactor93RoleResult, Refactor93CoordinatorError>,
    ) -> FakeRole {
        FakeRole {
            state,
            execution,
            completed,
            preparation: Some(Ok(receipt)),
        }
    }

    #[test]
    fn preparation_overlaps_and_delivery_is_atomic() {
        let (request, pair) = request();
        let state_a = Rc::new(RefCell::new(FakeState::default()));
        let state_b = Rc::new(RefCell::new(FakeState::default()));
        let state_s = Rc::new(RefCell::new(FakeState::default()));
        let transcript = PublicDigest32::new([11; 32]);
        let mut deriver_a = fake_role(
            Ed25519YaoDeriverRoleV1::DeriverA,
            state_a.clone(),
            receipt(Ed25519YaoDeriverRoleV1::DeriverA, &pair, pair.pair_digest()),
            Ok(role_result(
                Ed25519YaoDeriverRoleV1::DeriverA,
                &pair,
                transcript,
            )),
            Err(Refactor93CoordinatorError::ExecutionFailed(
                Ed25519YaoDeriverRoleV1::DeriverA,
            )),
        );
        let mut deriver_b = fake_role(
            Ed25519YaoDeriverRoleV1::DeriverB,
            state_b.clone(),
            receipt(Ed25519YaoDeriverRoleV1::DeriverB, &pair, pair.pair_digest()),
            Err(Refactor93CoordinatorError::ExecutionFailed(
                Ed25519YaoDeriverRoleV1::DeriverB,
            )),
            Ok(role_result(
                Ed25519YaoDeriverRoleV1::DeriverB,
                &pair,
                transcript,
            )),
        );
        let mut signing_worker = FakeSigningWorker {
            state: state_s.clone(),
            result: Ok(vec![42]),
        };

        let result = futures::executor::block_on(Refactor93Coordinator::execute(
            request,
            50,
            &mut deriver_a,
            &mut deriver_b,
            &mut signing_worker,
        ))
        .expect("coordinator result");

        assert_eq!(result.operation, Ed25519YaoOperationV1::Registration);
        assert_eq!(result.pair_digest, pair.pair_digest());
        assert_eq!(result.transcript_digest, transcript);
        assert_eq!(result.signing_worker_receipt, vec![42]);
        assert_eq!(state_a.borrow().prepare_calls, 1);
        assert_eq!(state_b.borrow().prepare_calls, 1);
        assert_eq!(state_a.borrow().execute_calls, 1);
        assert_eq!(state_b.borrow().completed_read_calls, 1);
        assert_eq!(state_s.borrow().delivered_calls, 1);
    }

    #[test]
    fn mismatched_readiness_stops_before_execution() {
        let (request, pair) = request();
        let state_a = Rc::new(RefCell::new(FakeState::default()));
        let state_b = Rc::new(RefCell::new(FakeState::default()));
        let state_s = Rc::new(RefCell::new(FakeState::default()));
        let mut deriver_a = fake_role(
            Ed25519YaoDeriverRoleV1::DeriverA,
            state_a.clone(),
            receipt(Ed25519YaoDeriverRoleV1::DeriverA, &pair, pair.pair_digest()),
            Err(Refactor93CoordinatorError::ExecutionFailed(
                Ed25519YaoDeriverRoleV1::DeriverA,
            )),
            Err(Refactor93CoordinatorError::ExecutionFailed(
                Ed25519YaoDeriverRoleV1::DeriverA,
            )),
        );
        let mut deriver_b = fake_role(
            Ed25519YaoDeriverRoleV1::DeriverB,
            state_b.clone(),
            receipt(
                Ed25519YaoDeriverRoleV1::DeriverB,
                &pair,
                PublicDigest32::new([99; 32]),
            ),
            Err(Refactor93CoordinatorError::ExecutionFailed(
                Ed25519YaoDeriverRoleV1::DeriverB,
            )),
            Err(Refactor93CoordinatorError::ExecutionFailed(
                Ed25519YaoDeriverRoleV1::DeriverB,
            )),
        );
        let mut signing_worker = FakeSigningWorker {
            state: state_s.clone(),
            result: Ok(vec![42]),
        };

        let error = futures::executor::block_on(Refactor93Coordinator::execute(
            request,
            50,
            &mut deriver_a,
            &mut deriver_b,
            &mut signing_worker,
        ))
        .expect_err("mismatched readiness must fail");
        assert_eq!(
            error,
            Refactor93CoordinatorError::ReadinessMismatch(Ed25519YaoDeriverRoleV1::DeriverB)
        );
        assert_eq!(state_a.borrow().execute_calls, 0);
        assert_eq!(state_s.borrow().delivered_calls, 0);
    }

    #[test]
    fn transcript_mismatch_stops_before_signing_worker() {
        let (request, pair) = request();
        let state_a = Rc::new(RefCell::new(FakeState::default()));
        let state_b = Rc::new(RefCell::new(FakeState::default()));
        let state_s = Rc::new(RefCell::new(FakeState::default()));
        let mut deriver_a = fake_role(
            Ed25519YaoDeriverRoleV1::DeriverA,
            state_a,
            receipt(Ed25519YaoDeriverRoleV1::DeriverA, &pair, pair.pair_digest()),
            Ok(role_result(
                Ed25519YaoDeriverRoleV1::DeriverA,
                &pair,
                PublicDigest32::new([11; 32]),
            )),
            Err(Refactor93CoordinatorError::ExecutionFailed(
                Ed25519YaoDeriverRoleV1::DeriverA,
            )),
        );
        let mut deriver_b = fake_role(
            Ed25519YaoDeriverRoleV1::DeriverB,
            state_b,
            receipt(Ed25519YaoDeriverRoleV1::DeriverB, &pair, pair.pair_digest()),
            Err(Refactor93CoordinatorError::ExecutionFailed(
                Ed25519YaoDeriverRoleV1::DeriverB,
            )),
            Ok(role_result(
                Ed25519YaoDeriverRoleV1::DeriverB,
                &pair,
                PublicDigest32::new([12; 32]),
            )),
        );
        let mut signing_worker = FakeSigningWorker {
            state: state_s.clone(),
            result: Ok(vec![42]),
        };

        let error = futures::executor::block_on(Refactor93Coordinator::execute(
            request,
            50,
            &mut deriver_a,
            &mut deriver_b,
            &mut signing_worker,
        ))
        .expect_err("transcript mismatch must fail");
        assert_eq!(
            error,
            Refactor93CoordinatorError::ResultMismatch(Ed25519YaoDeriverRoleV1::DeriverB)
        );
        assert_eq!(state_s.borrow().delivered_calls, 0);
    }
}
