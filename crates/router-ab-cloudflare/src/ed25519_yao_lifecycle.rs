use core::{fmt, future::Future};
use std::time::Duration;

#[path = "ed25519_yao_role_d1.rs"]
mod role_d1;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use futures::future::{select, Either};
use router_ab_core::{
    ed25519_yao_encrypted_input_digest_v1, Ed25519YaoCircuitFamilyV1,
    Ed25519YaoDeriverAPrefaceInFlightV2, Ed25519YaoDeriverAToBTargetProofPayloadV2,
    Ed25519YaoDeriverBPrefaceInFlightV2, Ed25519YaoDeriverBToATargetProofPayloadV2,
    Ed25519YaoDeriverRoleV1, Ed25519YaoEncryptedInputV1, Ed25519YaoExecutionIdV1,
    Ed25519YaoInputKindV1, Ed25519YaoInputPairBindingV1, Ed25519YaoOperationV1,
    Ed25519YaoOuterBindingV2, Ed25519YaoRoleReadinessReceiptV1, Ed25519YaoRoleSignatureSchemeV1,
    Ed25519YaoRoleStartAcceptanceV1, Ed25519YaoSessionIdV1, LifecycleScopeV1, PublicDigest32,
    RouterAbProtocolError, RouterAbProtocolErrorCode, RouterAbProtocolResult,
    TenantRootCustodyBindingV1, TwoPartyDeriverRole, VerifiedTenantRootOnlineRoleShareV1,
};
use router_ab_ed25519_yao::{
    build_product_activation_deriver_a_v1, build_product_activation_deriver_b_v1,
    build_product_export_deriver_a_v1, build_product_export_deriver_b_v1,
    build_product_lane_deriver_a_v1, build_product_lane_deriver_b_v1,
    duplex::{
        run_activation_deriver_a, run_activation_deriver_b_open, run_export_deriver_a,
        run_export_deriver_b_open, run_lane_materialization_deriver_a,
        run_lane_materialization_deriver_b_open,
    },
    open_ed25519_yao_activation_deriver_a_input_v1, open_ed25519_yao_activation_deriver_b_input_v1,
    open_ed25519_yao_export_deriver_a_input_v1, open_ed25519_yao_export_deriver_b_input_v1,
    open_ed25519_yao_lane_deriver_a_input_v1, open_ed25519_yao_lane_deriver_b_input_v1,
    seal_ed25519_yao_activation_deriver_a_execution_v1,
    seal_ed25519_yao_activation_deriver_b_execution_v1,
    seal_ed25519_yao_export_deriver_a_execution_v1, seal_ed25519_yao_export_deriver_b_execution_v1,
    seal_ed25519_yao_lane_deriver_a_execution_v1, seal_ed25519_yao_lane_deriver_b_execution_v1,
    AdapterError, Ed25519YaoRecipientPrivateKeyV1, Ed25519YaoRoleExecutionV1,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use signer_core::ed25519_yao_derivation::{
    derive_ed25519_yao_deriver_a_server_contribution_v1,
    derive_ed25519_yao_deriver_b_server_contribution_v1, Ed25519YaoDeriverADerivationRootV1,
    Ed25519YaoDeriverAServerContributionV1, Ed25519YaoDeriverBDerivationRootV1,
    Ed25519YaoDeriverBServerContributionV1, Ed25519YaoStableKeyDerivationContextV1,
};
use threshold_prf::{
    prepare_ed25519_deriver_a_target_v1, prepare_ed25519_deriver_b_target_v1,
    SigningRootShareCommitment,
};
use worker::{Context, Delay, Env, Request, Response, WebSocketPair};
use zeroize::Zeroize;

use crate::{
    decode_cloudflare_signer_envelope_hpke_private_key_secret_v1,
    load_cloudflare_root_share_wire_secret_v1, parse_cloudflare_trace_id_from_request_v1,
    CloudflareDeriverAWorkerRuntimeV1, CloudflareDeriverBWorkerRuntimeV1,
    CloudflareEd25519YaoCircuitV1, CloudflareEd25519YaoPairExecuteRequestV1,
    CloudflareEd25519YaoPairExecuteResponseV1, CloudflareEd25519YaoPairLookupRequestV1,
    CloudflareEd25519YaoPairPrepareRequestV1, CloudflareEd25519YaoPairStartRequestV1,
    CloudflareEd25519YaoPairStatusResponseV1, CloudflareEd25519YaoWebSocketBindingV1,
    CloudflareEd25519YaoWebSocketTransportV1, CloudflareHpkeGetrandomRngV1,
    CloudflareSignerPeerVerifyingKeySetV1, CloudflareTraceIdV1, CloudflareWorkerRoleV1,
    EXECUTION_ID_HEADER, START_ACCEPTANCE_HEADER,
};

pub const CLOUDFLARE_DERIVER_B_ED25519_YAO_DUPLEX_PATH: &str =
    "/router-ab/deriver-b/ed25519-yao/duplex";
pub const CLOUDFLARE_DERIVER_A_ED25519_YAO_PREPARE_PAIR_PATH: &str =
    "/router-ab/deriver-a/ed25519-yao/prepare-pair";
pub const CLOUDFLARE_DERIVER_A_ED25519_YAO_EXECUTE_PAIR_PATH: &str =
    "/router-ab/deriver-a/ed25519-yao/execute-pair";
pub const CLOUDFLARE_DERIVER_A_ED25519_YAO_READ_PAIR_STATUS_PATH: &str =
    "/router-ab/deriver-a/ed25519-yao/read-pair-status";
pub const CLOUDFLARE_DERIVER_A_ED25519_YAO_BURN_PAIR_PATH: &str =
    "/router-ab/deriver-a/ed25519-yao/burn-pair";
pub const CLOUDFLARE_DERIVER_B_ED25519_YAO_PREPARE_PAIR_PATH: &str =
    "/router-ab/deriver-b/ed25519-yao/prepare-pair";
pub const CLOUDFLARE_DERIVER_B_ED25519_YAO_READ_PAIR_STATUS_PATH: &str =
    "/router-ab/deriver-b/ed25519-yao/read-pair-status";
pub const CLOUDFLARE_DERIVER_B_ED25519_YAO_BURN_PAIR_PATH: &str =
    "/router-ab/deriver-b/ed25519-yao/burn-pair";

const PAIR_SESSION_RECORD_STORAGE_KEY: &str = "pair-session-record-v1";
const YAO_CEREMONY_TIMEOUT: Duration = Duration::from_secs(15);
const YAO_PREPARED_INPUT_LIFETIME_MS: u64 = 60_000;
const YAO_RUNNING_LIFETIME_MS: u64 = 20_000;
// Worker clocks expose the last I/O time, so a nested peer handoff can arrive slightly "future".
const YAO_READINESS_RECEIPT_MAX_FUTURE_SKEW_MS: u64 = 1_000;
const YAO_START_ACCEPTANCE_MAX_FUTURE_SKEW_MS: u64 = 1_000;
const ROLE_SPAN_EVENT_V1: &str = "router_ab_yao_role_span_v1";

type RoleTraceContextV1 = Option<CloudflareTraceIdV1>;

#[derive(Serialize)]
struct RoleSpanEventV1 {
    event: &'static str,
    span: &'static str,
    role: &'static str,
    operation: &'static str,
    outcome: &'static str,
    duration_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_code: Option<RouterAbProtocolErrorCode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    adapter_code: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    trace_id: Option<String>,
}

fn emit_role_span_v1(
    trace_id: RoleTraceContextV1,
    span: &'static str,
    role: &'static str,
    operation: &'static str,
    started_at_ms: u64,
    outcome: &'static str,
) {
    emit_role_span_with_error_code_v1(
        trace_id,
        span,
        role,
        operation,
        started_at_ms,
        outcome,
        None,
        None,
    );
}

fn emit_role_span_error_v1(
    trace_id: RoleTraceContextV1,
    span: &'static str,
    role: &'static str,
    operation: &'static str,
    started_at_ms: u64,
    error: &RouterAbProtocolError,
) {
    emit_role_span_with_error_code_v1(
        trace_id,
        span,
        role,
        operation,
        started_at_ms,
        "failure",
        Some(error.code()),
        None,
    );
}

fn emit_role_adapter_error_v1(
    trace_id: RoleTraceContextV1,
    span: &'static str,
    operation: &'static str,
    started_at_ms: u64,
    error: AdapterError,
) {
    emit_role_span_with_error_code_v1(
        trace_id,
        span,
        "deriver_b",
        operation,
        started_at_ms,
        "failure",
        Some(RouterAbProtocolErrorCode::InvalidLifecycleState),
        Some(adapter_error_code_v1(error)),
    );
}

fn emit_role_stage_result_v1<T>(
    trace_id: RoleTraceContextV1,
    span: &'static str,
    operation: &'static str,
    started_at_ms: u64,
    result: &RouterAbProtocolResult<T>,
) {
    match result {
        Ok(_) => emit_role_span_v1(
            trace_id,
            span,
            "deriver_b",
            operation,
            started_at_ms,
            "success",
        ),
        Err(error) => {
            emit_role_span_error_v1(trace_id, span, "deriver_b", operation, started_at_ms, error)
        }
    }
}

fn emit_role_span_with_error_code_v1(
    trace_id: RoleTraceContextV1,
    span: &'static str,
    role: &'static str,
    operation: &'static str,
    started_at_ms: u64,
    outcome: &'static str,
    error_code: Option<RouterAbProtocolErrorCode>,
    adapter_code: Option<&'static str>,
) {
    let ended_at_ms = cloudflare_yao_now_unix_ms().unwrap_or(started_at_ms);
    let event = RoleSpanEventV1 {
        event: ROLE_SPAN_EVENT_V1,
        span,
        role,
        operation,
        outcome,
        duration_ms: ended_at_ms.saturating_sub(started_at_ms),
        error_code,
        adapter_code,
        trace_id: trace_id.map(CloudflareTraceIdV1::as_hex),
    };
    if let Ok(serialized) = serde_json::to_string(&event) {
        worker::console_log!("{serialized}");
    }
}

fn role_span_started_at_ms() -> u64 {
    cloudflare_yao_now_unix_ms().unwrap_or_default()
}

/// Pair-bound role state used by the Router-owned lifecycle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum PairYaoSessionRecordV1 {
    Prepared {
        pair_digest: [u8; 32],
        input_digest: [u8; 32],
        root_metadata_digest: [u8; 32],
        expires_at_ms: u64,
        input: Box<Ed25519YaoEncryptedInputV1>,
        work: crate::CloudflareEd25519YaoPairWorkV1,
        receipt: Box<Ed25519YaoRoleReadinessReceiptV1>,
    },
    Running {
        pair_digest: [u8; 32],
        input_digest: [u8; 32],
        root_metadata_digest: [u8; 32],
        execution_id: [u8; 32],
        started_at_ms: u64,
        input: Box<Ed25519YaoEncryptedInputV1>,
        work: crate::CloudflareEd25519YaoPairWorkV1,
    },
    Completed {
        pair_digest: [u8; 32],
        input_digest: [u8; 32],
        root_metadata_digest: [u8; 32],
        execution: Box<Ed25519YaoRoleExecutionV1>,
    },
    Burned {
        pair_digest: [u8; 32],
        input_digest: [u8; 32],
        execution_id: [u8; 32],
    },
    Expired {
        pair_digest: [u8; 32],
        input_digest: [u8; 32],
    },
}

impl PairYaoSessionRecordV1 {
    fn pair_digest(&self) -> [u8; 32] {
        match self {
            Self::Prepared { pair_digest, .. }
            | Self::Running { pair_digest, .. }
            | Self::Completed { pair_digest, .. }
            | Self::Burned { pair_digest, .. }
            | Self::Expired { pair_digest, .. } => *pair_digest,
        }
    }

    fn input_digest(&self) -> [u8; 32] {
        match self {
            Self::Prepared { input_digest, .. }
            | Self::Running { input_digest, .. }
            | Self::Completed { input_digest, .. }
            | Self::Burned { input_digest, .. }
            | Self::Expired { input_digest, .. } => *input_digest,
        }
    }
}

enum PairCompletionExpectation {
    DeriverA { execution_id: [u8; 32] },
    DeriverB { input_digest: [u8; 32] },
}

/// Computes the only valid completion transition for a pair-bound role.
///
/// The caller supplies the identity observed before entering the storage
/// transaction. A's claim/complete path adds its execution id; B's completion
/// path adds the input digest from its initial running-state read.
fn completed_pair_record_if_running(
    current: &PairYaoSessionRecordV1,
    pair_digest: [u8; 32],
    expectation: PairCompletionExpectation,
    execution: &Ed25519YaoRoleExecutionV1,
    now_ms: u64,
) -> Option<PairYaoSessionRecordV1> {
    let PairYaoSessionRecordV1::Running {
        pair_digest: stored_pair,
        input_digest,
        root_metadata_digest,
        execution_id,
        started_at_ms,
        input,
        ..
    } = current
    else {
        return None;
    };
    let identity_matches = match expectation {
        PairCompletionExpectation::DeriverA {
            execution_id: expected,
        } => expected == *execution_id,
        PairCompletionExpectation::DeriverB {
            input_digest: expected,
        } => expected == *input_digest,
    };
    if *stored_pair != pair_digest || !identity_matches || execution.session() != input.session() {
        return None;
    }
    if now_ms.saturating_sub(*started_at_ms) >= YAO_RUNNING_LIFETIME_MS {
        return Some(PairYaoSessionRecordV1::Burned {
            pair_digest,
            input_digest: *input_digest,
            execution_id: *execution_id,
        });
    }
    Some(PairYaoSessionRecordV1::Completed {
        pair_digest: *stored_pair,
        input_digest: *input_digest,
        root_metadata_digest: *root_metadata_digest,
        execution: Box::new(execution.clone()),
    })
}

fn yao_execution_id() -> worker::Result<[u8; 32]> {
    let bytes = crate::cloudflare_random_bytes_v1(32)
        .map_err(|error| worker::Error::RustError(error.message().to_owned()))?;
    let mut execution_id = [0_u8; 32];
    execution_id.copy_from_slice(&bytes);
    Ok(execution_id)
}

async fn expire_prepared_pair_if_current(
    storage: &role_d1::RolePairD1StorageV1,
    pair_digest: [u8; 32],
    input_digest: [u8; 32],
    now_ms: u64,
) -> worker::Result<bool> {
    storage
        .transaction(move |transaction| async move {
            let current = match transaction
                .get::<PairYaoSessionRecordV1>(PAIR_SESSION_RECORD_STORAGE_KEY)
                .await
            {
                Ok(record) => record,
                Err(worker::Error::JsError(message)) if message == "No such value in storage." => {
                    return Ok(());
                }
                Err(error) => return Err(error),
            };
            match current {
                PairYaoSessionRecordV1::Prepared {
                    pair_digest: stored_pair,
                    input_digest: stored_input,
                    expires_at_ms,
                    ..
                } if stored_pair == pair_digest
                    && stored_input == input_digest
                    && now_ms >= expires_at_ms =>
                {
                    transaction
                        .put(
                            PAIR_SESSION_RECORD_STORAGE_KEY,
                            PairYaoSessionRecordV1::Expired {
                                pair_digest,
                                input_digest,
                            },
                        )
                        .await?;
                    Ok(())
                }
                PairYaoSessionRecordV1::Expired {
                    pair_digest: stored_pair,
                    input_digest: stored_input,
                } if stored_pair == pair_digest && stored_input == input_digest => Ok(()),
                _ => Ok(()),
            }
        })
        .await?;
    Ok(matches!(
        storage
            .get::<PairYaoSessionRecordV1>(PAIR_SESSION_RECORD_STORAGE_KEY)
            .await?,
        Some(PairYaoSessionRecordV1::Expired {
            pair_digest: stored_pair,
            input_digest: stored_input,
        }) if stored_pair == pair_digest && stored_input == input_digest
    ))
}

async fn burn_running_pair_if_expired(
    storage: &role_d1::RolePairD1StorageV1,
    pair_digest: [u8; 32],
    input_digest: [u8; 32],
    execution_id: [u8; 32],
    started_at_ms: u64,
    now_ms: u64,
) -> worker::Result<bool> {
    if now_ms.saturating_sub(started_at_ms) < YAO_RUNNING_LIFETIME_MS {
        return Ok(false);
    }
    storage
        .transaction(move |transaction| async move {
            let current = match transaction
                .get::<PairYaoSessionRecordV1>(PAIR_SESSION_RECORD_STORAGE_KEY)
                .await
            {
                Ok(record) => record,
                Err(worker::Error::JsError(message)) if message == "No such value in storage." => {
                    return Ok(())
                }
                Err(error) => return Err(error),
            };
            if matches!(
                current,
                PairYaoSessionRecordV1::Running {
                    pair_digest: stored_pair,
                    input_digest: stored_input,
                    execution_id: stored_execution_id,
                    started_at_ms: stored_started_at,
                    ..
                } if stored_pair == pair_digest
                    && stored_input == input_digest
                    && stored_execution_id == execution_id
                    && stored_started_at == started_at_ms
            ) {
                transaction
                    .put(
                        PAIR_SESSION_RECORD_STORAGE_KEY,
                        PairYaoSessionRecordV1::Burned {
                            pair_digest,
                            input_digest,
                            execution_id,
                        },
                    )
                    .await?;
            }
            Ok(())
        })
        .await?;
    Ok(matches!(
        storage
            .get::<PairYaoSessionRecordV1>(PAIR_SESSION_RECORD_STORAGE_KEY)
            .await?,
        Some(PairYaoSessionRecordV1::Burned {
            pair_digest: stored_pair,
            input_digest: stored_input,
            execution_id: stored_execution_id,
        }) if stored_pair == pair_digest
            && stored_input == input_digest
            && stored_execution_id == execution_id
    ))
}

impl CloudflareEd25519YaoPairPrepareRequestV1 {
    fn validate_for_role(
        &self,
        role: Ed25519YaoDeriverRoleV1,
        expected_kind: Ed25519YaoInputKindV1,
    ) -> RouterAbProtocolResult<([u8; 32], [u8; 32])> {
        self.pair_binding.validate()?;
        validate_pair_work_v1(&self.work, &self.pair_binding, &self.input)?;
        validate_deriver_input(&self.input, role, expected_kind)?;
        let input_digest = ed25519_yao_encrypted_input_digest_v1(&self.input)?.bytes;
        let expected_digest = match role {
            Ed25519YaoDeriverRoleV1::DeriverA => self.pair_binding.deriver_a_input_digest(),
            Ed25519YaoDeriverRoleV1::DeriverB => self.pair_binding.deriver_b_input_digest(),
        };
        if input_digest != expected_digest.bytes {
            return Err(invalid_lifecycle(
                "pair preparation input does not match its canonical pair digest",
            ));
        }
        if self.input.session() != self.pair_binding.session() {
            return Err(invalid_lifecycle(
                "pair preparation input does not match its ceremony session",
            ));
        }
        Ok((self.pair_binding.pair_digest().bytes, input_digest))
    }
}

impl CloudflareEd25519YaoPairExecuteRequestV1 {
    fn validate(&self) -> RouterAbProtocolResult<()> {
        self.pair_binding.validate()?;
        self.local_receipt.validate_for_pair(&self.pair_binding)?;
        self.peer_receipt.validate_for_pair(&self.pair_binding)?;
        let expected_kind = input_kind_for_circuit(self.pair_binding.binding().circuit_family());
        let (_, input_digest) = CloudflareEd25519YaoPairPrepareRequestV1 {
            pair_binding: self.pair_binding.clone(),
            work: self.work.clone(),
            input: self.input.clone(),
        }
        .validate_for_role(Ed25519YaoDeriverRoleV1::DeriverA, expected_kind)?;
        if self.local_receipt.role() != Ed25519YaoDeriverRoleV1::DeriverA
            || self.local_receipt.local_input_digest().bytes != input_digest
        {
            return Err(invalid_lifecycle(
                "Deriver A execute-pair requires its exact readiness receipt",
            ));
        }
        if self.peer_receipt.role() != Ed25519YaoDeriverRoleV1::DeriverB {
            return Err(invalid_lifecycle(
                "Deriver A execute-pair requires a Deriver B readiness receipt",
            ));
        }
        Ok(())
    }
}

fn validate_pair_work_v1(
    work: &crate::CloudflareEd25519YaoPairWorkV1,
    pair_binding: &Ed25519YaoInputPairBindingV1,
    input: &Ed25519YaoEncryptedInputV1,
) -> RouterAbProtocolResult<()> {
    match work {
        crate::CloudflareEd25519YaoPairWorkV1::Ceremony => {
            if input.kind() == Ed25519YaoInputKindV1::LaneMaterialization {
                return Err(invalid_lifecycle(
                    "lane-materialization input requires an admitted lane job",
                ));
            }
        }
        crate::CloudflareEd25519YaoPairWorkV1::Lane { job } => {
            job.validate()?;
            if input.kind() != Ed25519YaoInputKindV1::LaneMaterialization
                || input.operation() != job.yao_request_kind.operation()
                || input.session() != job.session_v1()?
                || input.stable_context_binding() != job.stable_context_binding_v1()?
                || pair_binding.binding().operation != job.yao_request_kind.operation()
                || pair_binding.binding().session_id.into_bytes() != job.session_v1()?
                || pair_binding
                    .binding()
                    .stable_key_context_binding
                    .into_bytes()
                    != job.stable_context_binding_v1()?
                || pair_binding.binding().material_activation() != &job.source.material_activation
                || pair_binding.authorization_digest()
                    != PublicDigest32::new(job.transcript_digest_v1()?)
            {
                return Err(invalid_lifecycle(
                    "lane pair context does not match its admitted job",
                ));
            }
        }
    }
    Ok(())
}

impl CloudflareEd25519YaoPairStartRequestV1 {
    fn validate(&self) -> RouterAbProtocolResult<()> {
        self.pair_binding.validate()?;
        self.acceptance.validate_for_pair(&self.pair_binding)?;
        if self.acceptance.role() != Ed25519YaoDeriverRoleV1::DeriverB
            || self.acceptance.execution_id() != self.execution_id
        {
            return Err(invalid_lifecycle(
                "Deriver B start acceptance does not match the requested execution",
            ));
        }
        Ok(())
    }
}

impl CloudflareEd25519YaoPairLookupRequestV1 {
    fn validate(&self) -> RouterAbProtocolResult<()> {
        if self.session.iter().all(|byte| *byte == 0)
            || self.pair_digest.iter().all(|byte| *byte == 0)
        {
            return Err(invalid_lifecycle(
                "completed pair lookup requires nonzero session and pair digests",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
enum DeriverAYaoSessionCommandV1 {
    PreparePair {
        pair_binding: Ed25519YaoInputPairBindingV1,
        work: crate::CloudflareEd25519YaoPairWorkV1,
        input: Ed25519YaoEncryptedInputV1,
    },
    StartPair {
        pair_binding: Ed25519YaoInputPairBindingV1,
        execution_id: Ed25519YaoExecutionIdV1,
        acceptance: Ed25519YaoRoleStartAcceptanceV1,
        local_receipt: Ed25519YaoRoleReadinessReceiptV1,
        peer_receipt: Ed25519YaoRoleReadinessReceiptV1,
    },
    CompletePair {
        pair_digest: [u8; 32],
        execution_id: [u8; 32],
        execution: Box<Ed25519YaoRoleExecutionV1>,
    },
    ReadPairStatus {
        session: [u8; 32],
        pair_digest: [u8; 32],
    },
    BurnPair {
        session: [u8; 32],
        pair_digest: [u8; 32],
    },
}

impl DeriverAYaoSessionCommandV1 {
    fn validate(&self) -> RouterAbProtocolResult<()> {
        match self {
            Self::PreparePair {
                pair_binding,
                work,
                input,
            } => {
                let expected_kind = input_kind_for_circuit(pair_binding.binding().circuit_family());
                CloudflareEd25519YaoPairPrepareRequestV1 {
                    pair_binding: pair_binding.clone(),
                    work: work.clone(),
                    input: input.clone(),
                }
                .validate_for_role(Ed25519YaoDeriverRoleV1::DeriverA, expected_kind)?;
            }
            Self::StartPair {
                pair_binding,
                execution_id,
                acceptance,
                local_receipt,
                peer_receipt,
            } => {
                CloudflareEd25519YaoPairStartRequestV1 {
                    pair_binding: pair_binding.clone(),
                    execution_id: *execution_id,
                    acceptance: acceptance.clone(),
                }
                .validate()?;
                local_receipt.validate_for_pair(pair_binding)?;
                peer_receipt.validate_for_pair(pair_binding)?;
                if local_receipt.role() != Ed25519YaoDeriverRoleV1::DeriverA
                    || peer_receipt.role() != Ed25519YaoDeriverRoleV1::DeriverB
                {
                    return Err(invalid_lifecycle(
                        "Deriver A start requires the exact A/B readiness pair",
                    ));
                }
            }
            Self::CompletePair {
                pair_digest,
                execution_id,
                execution,
            } => {
                if pair_digest.iter().all(|byte| *byte == 0)
                    || execution_id.iter().all(|byte| *byte == 0)
                {
                    return Err(invalid_lifecycle(
                        "Deriver A pair completion requires nonzero identity digests",
                    ));
                }
                execution.validate()?;
                if execution.deriver() != Ed25519YaoDeriverRoleV1::DeriverA {
                    return Err(invalid_lifecycle(
                        "Deriver A pair storage accepts only Deriver A execution",
                    ));
                }
            }
            Self::ReadPairStatus { pair_digest, .. } | Self::BurnPair { pair_digest, .. } => {
                if pair_digest.iter().all(|byte| *byte == 0) {
                    return Err(invalid_lifecycle("pair digest must be nonzero"));
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case", deny_unknown_fields)]
enum DeriverAYaoSessionResponseV1 {
    #[serde(rename = "pair_started")]
    Started {
        session: [u8; 32],
        pair_digest: [u8; 32],
        execution_id: Ed25519YaoExecutionIdV1,
    },
    #[serde(rename = "pair_completed")]
    Completed {
        execution: Box<Ed25519YaoRoleExecutionV1>,
    },
    #[serde(rename = "pair_burned")]
    Burned {
        session: [u8; 32],
        pair_digest: [u8; 32],
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
enum DeriverBYaoSessionCommandV1 {
    PreparePair {
        pair_binding: Box<Ed25519YaoInputPairBindingV1>,
        work: crate::CloudflareEd25519YaoPairWorkV1,
        input: Box<Ed25519YaoEncryptedInputV1>,
    },
    BeginPair {
        session: [u8; 32],
        pair_digest: [u8; 32],
        execution_id: Ed25519YaoExecutionIdV1,
        peer_receipt: Box<Ed25519YaoRoleReadinessReceiptV1>,
    },
    CompletePair {
        pair_digest: [u8; 32],
        execution: Box<Ed25519YaoRoleExecutionV1>,
    },
    FailPair {
        session: [u8; 32],
        pair_digest: [u8; 32],
    },
    ReadPairStatus {
        session: [u8; 32],
        pair_digest: [u8; 32],
    },
}

impl DeriverBYaoSessionCommandV1 {
    fn operation(&self) -> &'static str {
        match self {
            Self::PreparePair { .. } => "prepare_pair",
            Self::BeginPair { .. } => "begin_pair",
            Self::CompletePair { .. } => "complete_pair",
            Self::FailPair { .. } => "fail_pair",
            Self::ReadPairStatus { .. } => "read_pair_status",
        }
    }

    fn session(&self) -> [u8; 32] {
        match self {
            Self::PreparePair { input, .. } => input.session(),
            Self::BeginPair { session, .. } | Self::FailPair { session, .. } => *session,
            Self::ReadPairStatus { session, .. } => *session,
            Self::CompletePair { execution, .. } => execution.session(),
        }
    }

    fn validate(&self) -> RouterAbProtocolResult<()> {
        let session = self.session();
        if session.iter().all(|byte| *byte == 0) {
            return Err(invalid_lifecycle("Ed25519 Yao session must be nonzero"));
        }
        match self {
            Self::PreparePair {
                pair_binding,
                work,
                input,
            } => {
                let expected_kind = input_kind_for_circuit(pair_binding.binding().circuit_family());
                CloudflareEd25519YaoPairPrepareRequestV1 {
                    pair_binding: *pair_binding.clone(),
                    work: work.clone(),
                    input: *input.clone(),
                }
                .validate_for_role(Ed25519YaoDeriverRoleV1::DeriverB, expected_kind)?;
            }
            Self::CompletePair {
                pair_digest,
                execution,
            } => {
                if pair_digest.iter().all(|byte| *byte == 0) {
                    return Err(invalid_lifecycle("pair digest must be nonzero"));
                }
                execution.validate()?;
                if execution.deriver() != Ed25519YaoDeriverRoleV1::DeriverB {
                    return Err(invalid_lifecycle(
                        "Deriver B pair storage accepts only Deriver B execution",
                    ));
                }
            }
            Self::BeginPair { pair_digest, .. }
            | Self::FailPair { pair_digest, .. }
            | Self::ReadPairStatus { pair_digest, .. } => {
                if pair_digest.iter().all(|byte| *byte == 0) {
                    return Err(invalid_lifecycle("pair digest must be nonzero"));
                }
                if let Self::BeginPair { execution_id, .. } = self {
                    if execution_id.into_bytes().iter().all(|byte| *byte == 0) {
                        return Err(invalid_lifecycle("pair execution id must be nonzero"));
                    }
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
enum DeriverBYaoSessionResponseV1 {
    PairPrepared {
        session: [u8; 32],
        pair_digest: [u8; 32],
        root_metadata_digest: [u8; 32],
        input: Box<Ed25519YaoEncryptedInputV1>,
        work: crate::CloudflareEd25519YaoPairWorkV1,
        receipt: Box<Ed25519YaoRoleReadinessReceiptV1>,
    },
    PairPreparedStatus {
        session: [u8; 32],
        pair_digest: [u8; 32],
    },
    PairRunning {
        session: [u8; 32],
        pair_digest: [u8; 32],
    },
    PairStarted {
        session: [u8; 32],
        pair_digest: [u8; 32],
        execution_id: Ed25519YaoExecutionIdV1,
        input: Box<Ed25519YaoEncryptedInputV1>,
        work: crate::CloudflareEd25519YaoPairWorkV1,
        receipt: Box<Ed25519YaoRoleReadinessReceiptV1>,
        root_metadata_digest: [u8; 32],
    },
    PairCompleted {
        session: [u8; 32],
        pair_digest: [u8; 32],
    },
    PairPending {
        session: [u8; 32],
        pair_digest: [u8; 32],
    },
    PairMissing {
        session: [u8; 32],
        pair_digest: [u8; 32],
    },
    PairRoleExecution {
        execution: Box<Ed25519YaoRoleExecutionV1>,
    },
    PairBurned {
        session: [u8; 32],
        pair_digest: [u8; 32],
    },
    PairExpired {
        session: [u8; 32],
        pair_digest: [u8; 32],
    },
}

fn pair_digest_as_public(value: [u8; 32]) -> PublicDigest32 {
    PublicDigest32::new(value)
}

fn root_metadata_digest_v1(
    metadata: &crate::CloudflareRootShareStartupMetadataV1,
) -> RouterAbProtocolResult<[u8; 32]> {
    metadata.validate()?;
    let encoded = serde_json::to_vec(metadata)
        .map_err(|_| invalid_lifecycle("root-share metadata encoding failed"))?;
    let mut hasher = Sha256::new();
    hasher.update(b"seams/router-ab/ed25519-yao/root-metadata/v1");
    hasher.update(encoded);
    Ok(hasher.finalize().into())
}

#[allow(clippy::too_many_arguments)]
fn sign_role_readiness_receipt_v1(
    env: &Env,
    worker_role: CloudflareWorkerRoleV1,
    runtime_signing_key: &crate::CloudflareSignerPeerSigningKeyBindingV1,
    role: Ed25519YaoDeriverRoleV1,
    session: [u8; 32],
    pair_digest: [u8; 32],
    input_digest: [u8; 32],
    root_metadata_digest: [u8; 32],
    prepared_at_ms: u64,
    expires_at_ms: u64,
) -> RouterAbProtocolResult<Ed25519YaoRoleReadinessReceiptV1> {
    let session = Ed25519YaoSessionIdV1::new(session)?;
    let placeholder_signature = router_ab_core::Ed25519YaoRoleSignatureV1::new(
        Ed25519YaoRoleSignatureSchemeV1::Ed25519V1,
        [1_u8; 64],
    )?;
    let unsigned = Ed25519YaoRoleReadinessReceiptV1::new(
        role,
        session,
        pair_digest_as_public(pair_digest),
        pair_digest_as_public(input_digest),
        pair_digest_as_public(root_metadata_digest),
        prepared_at_ms,
        expires_at_ms,
        placeholder_signature,
    )?;
    runtime_signing_key.validate_visible_to(worker_role)?;
    let mut signing_key_bytes =
        crate::load_cloudflare_deriver_peer_signing_key_bytes_v1(env, runtime_signing_key)?;
    let key = SigningKey::from_bytes(&signing_key_bytes);
    let signature = key
        .sign(unsigned.signed_message_digest().as_bytes())
        .to_bytes();
    signing_key_bytes.zeroize();
    let signature = router_ab_core::Ed25519YaoRoleSignatureV1::new(
        Ed25519YaoRoleSignatureSchemeV1::Ed25519V1,
        signature,
    )?;
    Ed25519YaoRoleReadinessReceiptV1::new(
        role,
        session,
        pair_digest_as_public(pair_digest),
        pair_digest_as_public(input_digest),
        pair_digest_as_public(root_metadata_digest),
        prepared_at_ms,
        expires_at_ms,
        signature,
    )
}

pub(crate) fn verify_role_readiness_receipt_v1(
    receipt: &Ed25519YaoRoleReadinessReceiptV1,
    verifying_keys: &CloudflareSignerPeerVerifyingKeySetV1,
) -> RouterAbProtocolResult<()> {
    let verifying_key_bytes = match receipt.role() {
        Ed25519YaoDeriverRoleV1::DeriverA => verifying_keys.deriver_a.verifying_key_bytes,
        Ed25519YaoDeriverRoleV1::DeriverB => verifying_keys.deriver_b.verifying_key_bytes,
    };
    let verifying_key = VerifyingKey::from_bytes(&verifying_key_bytes)
        .map_err(|_| invalid_lifecycle("readiness receipt verifying key is malformed"))?;
    let signature = Signature::from_slice(receipt.signature().bytes())
        .map_err(|_| invalid_lifecycle("readiness receipt signature is malformed"))?;
    verifying_key
        .verify_strict(receipt.signed_message_digest().as_bytes(), &signature)
        .map_err(|_| invalid_lifecycle("readiness receipt signature is invalid"))
}

#[allow(clippy::too_many_arguments)]
fn sign_role_start_acceptance_v1(
    env: &Env,
    worker_role: CloudflareWorkerRoleV1,
    runtime_signing_key: &crate::CloudflareSignerPeerSigningKeyBindingV1,
    session: [u8; 32],
    pair_digest: [u8; 32],
    execution_id: Ed25519YaoExecutionIdV1,
    root_metadata_digest: [u8; 32],
    accepted_at_ms: u64,
    expires_at_ms: u64,
) -> RouterAbProtocolResult<Ed25519YaoRoleStartAcceptanceV1> {
    let session = Ed25519YaoSessionIdV1::new(session)?;
    let placeholder_signature = router_ab_core::Ed25519YaoRoleSignatureV1::new(
        Ed25519YaoRoleSignatureSchemeV1::Ed25519V1,
        [1_u8; 64],
    )?;
    let unsigned = Ed25519YaoRoleStartAcceptanceV1::new(
        Ed25519YaoDeriverRoleV1::DeriverB,
        session,
        pair_digest_as_public(pair_digest),
        execution_id,
        pair_digest_as_public(root_metadata_digest),
        accepted_at_ms,
        expires_at_ms,
        placeholder_signature,
    )?;
    runtime_signing_key.validate_visible_to(worker_role)?;
    let mut signing_key_bytes =
        crate::load_cloudflare_deriver_peer_signing_key_bytes_v1(env, runtime_signing_key)?;
    let key = SigningKey::from_bytes(&signing_key_bytes);
    let signature = key
        .sign(unsigned.signed_message_digest().as_bytes())
        .to_bytes();
    signing_key_bytes.zeroize();
    let signature = router_ab_core::Ed25519YaoRoleSignatureV1::new(
        Ed25519YaoRoleSignatureSchemeV1::Ed25519V1,
        signature,
    )?;
    Ed25519YaoRoleStartAcceptanceV1::new(
        Ed25519YaoDeriverRoleV1::DeriverB,
        session,
        pair_digest_as_public(pair_digest),
        execution_id,
        pair_digest_as_public(root_metadata_digest),
        accepted_at_ms,
        expires_at_ms,
        signature,
    )
}

pub(crate) fn verify_role_start_acceptance_v1(
    acceptance: &Ed25519YaoRoleStartAcceptanceV1,
    verifying_keys: &CloudflareSignerPeerVerifyingKeySetV1,
) -> RouterAbProtocolResult<()> {
    if acceptance.role() != Ed25519YaoDeriverRoleV1::DeriverB {
        return Err(invalid_lifecycle(
            "start acceptance must be signed by Deriver B",
        ));
    }
    let verifying_key = VerifyingKey::from_bytes(&verifying_keys.deriver_b.verifying_key_bytes)
        .map_err(|_| invalid_lifecycle("start acceptance verifying key is malformed"))?;
    let signature = Signature::from_slice(acceptance.signature().bytes())
        .map_err(|_| invalid_lifecycle("start acceptance signature is malformed"))?;
    verifying_key
        .verify_strict(acceptance.signed_message_digest().as_bytes(), &signature)
        .map_err(|_| invalid_lifecycle("start acceptance signature is invalid"))
}

struct DeriverAYaoSessionD1V1 {
    env: Env,
}

impl DeriverAYaoSessionD1V1 {
    fn new(env: Env) -> Self {
        Self { env }
    }

    async fn execute(&self, command: DeriverAYaoSessionCommandV1) -> worker::Result<Response> {
        command
            .validate()
            .map_err(|error| worker::Error::RustError(error.message().to_owned()))?;
        match command {
            DeriverAYaoSessionCommandV1::PreparePair { .. } => {
                self.handle_prepare_pair(command).await
            }
            DeriverAYaoSessionCommandV1::StartPair { .. } => self.handle_start_pair(command).await,
            DeriverAYaoSessionCommandV1::CompletePair { .. } => {
                self.handle_complete_pair(command).await
            }
            DeriverAYaoSessionCommandV1::ReadPairStatus {
                session,
                pair_digest,
            } => self.handle_read_pair_status(session, pair_digest).await,
            DeriverAYaoSessionCommandV1::BurnPair {
                session,
                pair_digest,
            } => self.handle_burn_pair(session, pair_digest).await,
        }
    }
}

impl DeriverAYaoSessionD1V1 {
    async fn handle_read_pair_status(
        &self,
        session: [u8; 32],
        pair_digest: [u8; 32],
    ) -> worker::Result<Response> {
        let storage = role_d1::RolePairD1StorageV1::from_env(&self.env, session)?;
        let Some(record) = storage
            .get::<PairYaoSessionRecordV1>(PAIR_SESSION_RECORD_STORAGE_KEY)
            .await?
        else {
            return Response::from_json(&CloudflareEd25519YaoPairStatusResponseV1::Missing {
                session,
                pair_digest,
            });
        };
        let response = match record {
            PairYaoSessionRecordV1::Prepared {
                pair_digest: stored_pair,
                input,
                expires_at_ms,
                ..
            } if stored_pair == pair_digest && input.session() == session => {
                let input_digest = yao_input_digest(&input);
                let now_ms = cloudflare_yao_now_unix_ms()?;
                if now_ms >= expires_at_ms {
                    if !expire_prepared_pair_if_current(&storage, pair_digest, input_digest, now_ms)
                        .await?
                    {
                        return Response::error("Deriver A pair expiry state changed", 409);
                    }
                    CloudflareEd25519YaoPairStatusResponseV1::Expired {
                        session,
                        pair_digest,
                    }
                } else {
                    CloudflareEd25519YaoPairStatusResponseV1::Prepared {
                        session,
                        pair_digest,
                    }
                }
            }
            PairYaoSessionRecordV1::Running {
                pair_digest: stored_pair,
                input_digest,
                execution_id,
                started_at_ms,
                input,
                ..
            } if stored_pair == pair_digest && input.session() == session => {
                if burn_running_pair_if_expired(
                    &storage,
                    pair_digest,
                    input_digest,
                    execution_id,
                    started_at_ms,
                    cloudflare_yao_now_unix_ms()?,
                )
                .await?
                {
                    CloudflareEd25519YaoPairStatusResponseV1::Burned {
                        session,
                        pair_digest,
                    }
                } else {
                    CloudflareEd25519YaoPairStatusResponseV1::Running {
                        session,
                        pair_digest,
                    }
                }
            }
            PairYaoSessionRecordV1::Completed {
                pair_digest: stored_pair,
                execution,
                ..
            } if stored_pair == pair_digest && execution.session() == session => {
                CloudflareEd25519YaoPairStatusResponseV1::Completed { execution }
            }
            PairYaoSessionRecordV1::Burned {
                pair_digest: stored_pair,
                ..
            } if stored_pair == pair_digest => CloudflareEd25519YaoPairStatusResponseV1::Burned {
                session,
                pair_digest,
            },
            PairYaoSessionRecordV1::Expired {
                pair_digest: stored_pair,
                ..
            } if stored_pair == pair_digest => CloudflareEd25519YaoPairStatusResponseV1::Expired {
                session,
                pair_digest,
            },
            _ => {
                return Response::error("Deriver A pair identity mismatch", 409);
            }
        };
        Response::from_json(&response)
    }

    async fn handle_burn_pair(
        &self,
        session: [u8; 32],
        pair_digest: [u8; 32],
    ) -> worker::Result<Response> {
        let storage = role_d1::RolePairD1StorageV1::from_env(&self.env, session)?;
        let Some(record) = storage
            .get::<PairYaoSessionRecordV1>(PAIR_SESSION_RECORD_STORAGE_KEY)
            .await?
        else {
            return Response::from_json(&CloudflareEd25519YaoPairStatusResponseV1::Missing {
                session,
                pair_digest,
            });
        };
        let response = match record {
            PairYaoSessionRecordV1::Running {
                pair_digest: stored_pair,
                input_digest,
                input,
                ..
            } if stored_pair == pair_digest && input.session() == session => {
                storage
                    .transaction(move |transaction| async move {
                        let current = match transaction
                            .get::<PairYaoSessionRecordV1>(PAIR_SESSION_RECORD_STORAGE_KEY)
                            .await
                        {
                            Ok(record) => record,
                            Err(worker::Error::JsError(message))
                                if message == "No such value in storage." =>
                            {
                                return Ok(())
                            }
                            Err(error) => return Err(error),
                        };
                        if let PairYaoSessionRecordV1::Running {
                            pair_digest: current_pair,
                            input: current_input,
                            execution_id,
                            ..
                        } = current
                        {
                            if current_pair == pair_digest && current_input.session() == session {
                                transaction
                                    .put(
                                        PAIR_SESSION_RECORD_STORAGE_KEY,
                                        PairYaoSessionRecordV1::Burned {
                                            pair_digest,
                                            input_digest,
                                            execution_id,
                                        },
                                    )
                                    .await?;
                            }
                        }
                        Ok(())
                    })
                    .await?;
                let current = storage
                    .get::<PairYaoSessionRecordV1>(PAIR_SESSION_RECORD_STORAGE_KEY)
                    .await?;
                match current {
                    Some(PairYaoSessionRecordV1::Burned {
                        pair_digest: current_pair,
                        ..
                    }) if current_pair == pair_digest => {
                        CloudflareEd25519YaoPairStatusResponseV1::Burned {
                            session,
                            pair_digest,
                        }
                    }
                    Some(PairYaoSessionRecordV1::Completed {
                        pair_digest: current_pair,
                        execution,
                        ..
                    }) if current_pair == pair_digest && execution.session() == session => {
                        CloudflareEd25519YaoPairStatusResponseV1::Completed { execution }
                    }
                    _ => return Response::error("Deriver A pair burn state changed", 409),
                }
            }
            PairYaoSessionRecordV1::Completed {
                pair_digest: stored_pair,
                execution,
                ..
            } if stored_pair == pair_digest && execution.session() == session => {
                CloudflareEd25519YaoPairStatusResponseV1::Completed { execution }
            }
            PairYaoSessionRecordV1::Burned {
                pair_digest: stored_pair,
                ..
            } if stored_pair == pair_digest => CloudflareEd25519YaoPairStatusResponseV1::Burned {
                session,
                pair_digest,
            },
            PairYaoSessionRecordV1::Expired {
                pair_digest: stored_pair,
                ..
            } if stored_pair == pair_digest => CloudflareEd25519YaoPairStatusResponseV1::Expired {
                session,
                pair_digest,
            },
            PairYaoSessionRecordV1::Prepared { .. } => {
                return Response::error("Deriver A pair cannot be burned before running", 409);
            }
            _ => return Response::error("Deriver A pair identity mismatch", 409),
        };
        Response::from_json(&response)
    }
}

impl DeriverAYaoSessionD1V1 {
    async fn handle_prepare_pair(
        &self,
        command: DeriverAYaoSessionCommandV1,
    ) -> worker::Result<Response> {
        let DeriverAYaoSessionCommandV1::PreparePair {
            pair_binding,
            work,
            input,
        } = command
        else {
            return Response::error("invalid Deriver A pair command", 400);
        };
        let request = CloudflareEd25519YaoPairPrepareRequestV1 {
            pair_binding,
            work,
            input,
        };
        let expected_kind = input_kind_for_circuit(request.pair_binding.binding().circuit_family());
        let (pair_digest, input_digest) = request
            .validate_for_role(Ed25519YaoDeriverRoleV1::DeriverA, expected_kind)
            .map_err(|error| worker::Error::RustError(error.message().to_owned()))?;
        let storage = role_d1::RolePairD1StorageV1::from_env(&self.env, request.input.session())?;
        let now_unix_ms = cloudflare_yao_now_unix_ms()?;
        if let Some(existing) = storage
            .get::<PairYaoSessionRecordV1>(PAIR_SESSION_RECORD_STORAGE_KEY)
            .await?
        {
            match existing {
                PairYaoSessionRecordV1::Prepared {
                    pair_digest: existing_pair,
                    input_digest: existing_input,
                    expires_at_ms,
                    receipt,
                    work,
                    ..
                } if existing_pair == pair_digest
                    && existing_input == input_digest
                    && work == request.work
                    && now_unix_ms < expires_at_ms =>
                {
                    return Response::from_json(&*receipt);
                }
                PairYaoSessionRecordV1::Completed {
                    pair_digest: existing_pair,
                    input_digest: existing_input,
                    execution: _,
                    ..
                } if existing_pair == pair_digest && existing_input == input_digest => {
                    return Response::error("Deriver A pair is already completed", 409);
                }
                PairYaoSessionRecordV1::Completed { .. } => {
                    return Response::error("Deriver A pair is terminal", 409);
                }
                record
                    if record.pair_digest() != pair_digest
                        || record.input_digest() != input_digest =>
                {
                    return Response::error("conflicting Deriver A pair preparation", 409);
                }
                PairYaoSessionRecordV1::Prepared {
                    pair_digest: stored_pair,
                    input_digest: stored_input,
                    ..
                } if stored_pair == pair_digest && stored_input == input_digest => {
                    let now_ms = cloudflare_yao_now_unix_ms()?;
                    if !expire_prepared_pair_if_current(&storage, stored_pair, stored_input, now_ms)
                        .await?
                    {
                        return Response::error("Deriver A pair expiry state changed", 409);
                    }
                    return Response::error("Deriver A pair preparation expired", 409);
                }
                PairYaoSessionRecordV1::Running {
                    pair_digest: stored_pair,
                    input_digest: stored_input,
                    ..
                } if stored_pair == pair_digest && stored_input == input_digest => {
                    return Response::error("Deriver A pair is already running", 409);
                }
                PairYaoSessionRecordV1::Burned { .. } | PairYaoSessionRecordV1::Expired { .. } => {
                    return Response::error("Deriver A pair is terminal", 409);
                }
                PairYaoSessionRecordV1::Prepared { .. }
                | PairYaoSessionRecordV1::Running { .. } => {
                    return Response::error("conflicting Deriver A pair preparation", 409);
                }
            }
        }
        let runtime = CloudflareDeriverAWorkerRuntimeV1::from_worker_env(&self.env)
            .map_err(|error| worker::Error::RustError(error.message().to_owned()))?;
        let root_metadata_digest = load_deriver_a_yao_root_metadata_digest(
            &self.env,
            &runtime,
            &request.pair_binding.binding().lifecycle,
        )
        .await
        .map_err(|error| worker::Error::RustError(error.message().to_owned()))?;
        storage.bind_creation_scope(
            &request.pair_binding.binding().lifecycle.signer_set_id,
            request
                .pair_binding
                .binding()
                .lifecycle
                .root_share_epoch
                .as_str(),
            root_metadata_digest,
        )?;
        let prepared_at_ms = cloudflare_yao_now_unix_ms()?;
        if let Some(existing) = storage
            .get::<PairYaoSessionRecordV1>(PAIR_SESSION_RECORD_STORAGE_KEY)
            .await?
        {
            match existing {
                PairYaoSessionRecordV1::Prepared {
                    pair_digest: existing_pair,
                    input_digest: existing_input,
                    expires_at_ms,
                    receipt,
                    ..
                } if existing_pair == pair_digest
                    && existing_input == input_digest
                    && prepared_at_ms < expires_at_ms =>
                {
                    return Response::from_json(&*receipt);
                }
                PairYaoSessionRecordV1::Prepared { .. }
                | PairYaoSessionRecordV1::Running { .. }
                | PairYaoSessionRecordV1::Completed { .. }
                | PairYaoSessionRecordV1::Burned { .. }
                | PairYaoSessionRecordV1::Expired { .. } => {
                    return Response::error("Deriver A pair changed while preparing", 409);
                }
            }
        }
        let expires_at_ms = yao_expiry_from_now(prepared_at_ms, YAO_PREPARED_INPUT_LIFETIME_MS)?;
        let session = request.pair_binding.session();
        let receipt = sign_role_readiness_receipt_v1(
            &self.env,
            CloudflareWorkerRoleV1::DeriverA,
            runtime.peer_signing_key(),
            Ed25519YaoDeriverRoleV1::DeriverA,
            session,
            pair_digest,
            input_digest,
            root_metadata_digest,
            prepared_at_ms,
            expires_at_ms,
        )
        .map_err(|error| worker::Error::RustError(error.message().to_owned()))?;
        let prepared_record = PairYaoSessionRecordV1::Prepared {
            pair_digest,
            input_digest,
            root_metadata_digest,
            expires_at_ms,
            input: Box::new(request.input),
            work: request.work,
            receipt: Box::new(receipt.clone()),
        };
        let record_for_transaction = prepared_record.clone();
        storage
            .transaction(move |transaction| async move {
                let current = match transaction
                    .get::<PairYaoSessionRecordV1>(PAIR_SESSION_RECORD_STORAGE_KEY)
                    .await
                {
                    Ok(record) => Some(record),
                    Err(worker::Error::JsError(message))
                        if message == "No such value in storage." =>
                    {
                        None
                    }
                    Err(error) => return Err(error),
                };
                if current.is_some() {
                    return Ok(());
                }
                transaction
                    .put(PAIR_SESSION_RECORD_STORAGE_KEY, record_for_transaction)
                    .await?;
                Ok(())
            })
            .await?;
        if !matches!(
            storage
                .get::<PairYaoSessionRecordV1>(PAIR_SESSION_RECORD_STORAGE_KEY)
                .await?,
            Some(PairYaoSessionRecordV1::Prepared {
                pair_digest: stored_pair,
                input_digest: stored_input,
                ..
            }) if stored_pair == pair_digest && stored_input == input_digest
        ) {
            return Response::error("Deriver A pair changed while preparing", 409);
        }
        Response::from_json(&receipt)
    }

    async fn handle_start_pair(
        &self,
        command: DeriverAYaoSessionCommandV1,
    ) -> worker::Result<Response> {
        let DeriverAYaoSessionCommandV1::StartPair {
            pair_binding,
            execution_id,
            acceptance,
            local_receipt,
            peer_receipt,
        } = command
        else {
            return Response::error("invalid Deriver A pair command", 400);
        };
        let request = CloudflareEd25519YaoPairStartRequestV1 {
            pair_binding,
            execution_id,
            acceptance,
        };
        request
            .validate()
            .map_err(|error| worker::Error::RustError(error.message().to_owned()))?;
        let runtime = CloudflareDeriverAWorkerRuntimeV1::from_worker_env(&self.env)
            .map_err(|error| worker::Error::RustError(error.message().to_owned()))?;
        validate_cloudflare_start_acceptance_v1(&request.acceptance, cloudflare_yao_now_unix_ms()?)
            .map_err(|error| worker::Error::RustError(error.message().to_owned()))?;
        verify_role_start_acceptance_v1(&request.acceptance, runtime.peer_verifying_keys())
            .map_err(|error| worker::Error::RustError(error.message().to_owned()))?;
        let now_ms = cloudflare_yao_now_unix_ms()?;
        for readiness in [&local_receipt, &peer_receipt] {
            validate_cloudflare_role_readiness_receipt_v1(readiness, now_ms)
                .map_err(|error| worker::Error::RustError(error.message().to_owned()))?;
            verify_role_readiness_receipt_v1(readiness, runtime.peer_verifying_keys())
                .map_err(|error| worker::Error::RustError(error.message().to_owned()))?;
        }
        let pair_digest = request.pair_binding.pair_digest().bytes;
        let input_digest = request.pair_binding.deriver_a_input_digest().bytes;
        let storage =
            role_d1::RolePairD1StorageV1::from_env(&self.env, request.pair_binding.session())?;
        let Some(PairYaoSessionRecordV1::Prepared {
            pair_digest: stored_pair,
            input_digest: stored_input,
            root_metadata_digest,
            expires_at_ms,
            input,
            work,
            receipt: stored_receipt,
        }) = storage
            .get::<PairYaoSessionRecordV1>(PAIR_SESSION_RECORD_STORAGE_KEY)
            .await?
        else {
            return Response::error("Deriver A pair is not prepared", 409);
        };
        if stored_pair != pair_digest || stored_input != input_digest {
            return Response::error("Deriver A pair identity mismatch", 409);
        }
        if now_ms >= expires_at_ms {
            if !expire_prepared_pair_if_current(&storage, pair_digest, input_digest, now_ms).await?
            {
                return Response::error("Deriver A pair expiry state changed", 409);
            }
            return Response::error("Deriver A pair preparation expired", 409);
        }
        if stored_receipt.as_ref() != &local_receipt
            || local_receipt.root_metadata_digest().bytes != root_metadata_digest
            || peer_receipt.root_metadata_digest().bytes
                != request.acceptance.root_metadata_digest().bytes
        {
            return Response::error("Deriver A readiness pair changed before start", 409);
        }
        // The prepared record carries Deriver A's root metadata. The signed
        // acceptance carries Deriver B's role-local metadata, which is
        // validated by B before it emits the acceptance. A validates its own
        // metadata again before opening the stream above.
        let started_at_ms = now_ms;
        let running_record = PairYaoSessionRecordV1::Running {
            pair_digest,
            input_digest,
            root_metadata_digest,
            execution_id: request.execution_id.into_bytes(),
            started_at_ms,
            input,
            work,
        };
        storage
            .transaction(move |transaction| async move {
                let current = match transaction
                    .get::<PairYaoSessionRecordV1>(PAIR_SESSION_RECORD_STORAGE_KEY)
                    .await
                {
                    Ok(record) => record,
                    Err(worker::Error::JsError(message))
                        if message == "No such value in storage." =>
                    {
                        return Ok(())
                    }
                    Err(error) => return Err(error),
                };
                if matches!(
                    current,
                    PairYaoSessionRecordV1::Prepared {
                        pair_digest: stored_pair,
                        input_digest: stored_input,
                        expires_at_ms,
                        ..
                    } if stored_pair == pair_digest
                        && stored_input == input_digest
                        && started_at_ms < expires_at_ms
                ) {
                    transaction
                        .put(PAIR_SESSION_RECORD_STORAGE_KEY, running_record)
                        .await?;
                }
                Ok(())
            })
            .await?;
        if !matches!(
            storage
                .get::<PairYaoSessionRecordV1>(PAIR_SESSION_RECORD_STORAGE_KEY)
                .await?,
            Some(PairYaoSessionRecordV1::Running {
                pair_digest: stored_pair,
                input_digest: stored_input,
                execution_id: stored_execution_id,
                ..
            }) if stored_pair == pair_digest
                && stored_input == input_digest
                && stored_execution_id == request.execution_id.into_bytes()
        ) {
            return Response::error("Deriver A pair execution was already started", 409);
        }
        Response::from_json(&DeriverAYaoSessionResponseV1::Started {
            session: request.pair_binding.session(),
            pair_digest,
            execution_id: request.execution_id,
        })
    }

    async fn handle_complete_pair(
        &self,
        command: DeriverAYaoSessionCommandV1,
    ) -> worker::Result<Response> {
        let DeriverAYaoSessionCommandV1::CompletePair {
            pair_digest,
            execution_id,
            execution,
        } = command
        else {
            return Response::error("invalid Deriver A pair command", 400);
        };
        let session = execution.session();
        let expected_execution = execution.clone();
        let storage = role_d1::RolePairD1StorageV1::from_env(&self.env, session)?;
        storage
            .transaction(move |transaction| async move {
                let current = match transaction
                    .get::<PairYaoSessionRecordV1>(PAIR_SESSION_RECORD_STORAGE_KEY)
                    .await
                {
                    Ok(record) => record,
                    Err(worker::Error::JsError(message))
                        if message == "No such value in storage." =>
                    {
                        return Ok(())
                    }
                    Err(error) => return Err(error),
                };
                let now_unix_ms = cloudflare_yao_now_unix_ms()?;
                if let Some(next) = completed_pair_record_if_running(
                    &current,
                    pair_digest,
                    PairCompletionExpectation::DeriverA { execution_id },
                    &execution,
                    now_unix_ms,
                ) {
                    transaction
                        .put(PAIR_SESSION_RECORD_STORAGE_KEY, next)
                        .await?;
                }
                Ok(())
            })
            .await?;
        let current = storage
            .get::<PairYaoSessionRecordV1>(PAIR_SESSION_RECORD_STORAGE_KEY)
            .await?;
        match current {
            Some(PairYaoSessionRecordV1::Completed {
                pair_digest: stored_pair,
                execution: existing,
                ..
            }) if stored_pair == pair_digest && *existing == *expected_execution => {
                Response::from_json(&DeriverAYaoSessionResponseV1::Completed {
                    execution: existing,
                })
            }
            Some(PairYaoSessionRecordV1::Burned {
                pair_digest: stored_pair,
                ..
            }) if stored_pair == pair_digest => {
                Response::from_json(&DeriverAYaoSessionResponseV1::Burned {
                    session,
                    pair_digest,
                })
            }
            _ => Response::error("Deriver A pair completion state changed", 409),
        }
    }
}

struct DeriverBYaoSessionD1V1 {
    env: Env,
}

impl DeriverBYaoSessionD1V1 {
    fn new(env: Env) -> Self {
        Self { env }
    }

    async fn execute(&self, command: DeriverBYaoSessionCommandV1) -> worker::Result<Response> {
        command
            .validate()
            .map_err(|error| worker::Error::RustError(error.message().to_owned()))?;
        self.handle_pair_command(command).await
    }
}

impl DeriverBYaoSessionD1V1 {
    async fn handle_pair_command(
        &self,
        command: DeriverBYaoSessionCommandV1,
    ) -> worker::Result<Response> {
        match command {
            DeriverBYaoSessionCommandV1::PreparePair {
                pair_binding,
                work,
                input,
            } => self.handle_prepare_pair(*pair_binding, work, *input).await,
            DeriverBYaoSessionCommandV1::BeginPair {
                session,
                pair_digest,
                execution_id,
                peer_receipt,
            } => {
                self.handle_begin_pair(session, pair_digest, execution_id, *peer_receipt)
                    .await
            }
            DeriverBYaoSessionCommandV1::CompletePair {
                pair_digest,
                execution,
            } => self.handle_complete_pair(pair_digest, *execution).await,
            DeriverBYaoSessionCommandV1::FailPair {
                session,
                pair_digest,
            } => self.handle_fail_pair(session, pair_digest).await,
            DeriverBYaoSessionCommandV1::ReadPairStatus {
                session,
                pair_digest,
            } => self.handle_read_pair_status(session, pair_digest).await,
        }
    }

    async fn handle_prepare_pair(
        &self,
        pair_binding: Ed25519YaoInputPairBindingV1,
        work: crate::CloudflareEd25519YaoPairWorkV1,
        input: Ed25519YaoEncryptedInputV1,
    ) -> worker::Result<Response> {
        let request = CloudflareEd25519YaoPairPrepareRequestV1 {
            pair_binding,
            work,
            input,
        };
        let expected_kind = input_kind_for_circuit(request.pair_binding.binding().circuit_family());
        let (pair_digest, input_digest) = request
            .validate_for_role(Ed25519YaoDeriverRoleV1::DeriverB, expected_kind)
            .map_err(|error| worker::Error::RustError(error.message().to_owned()))?;
        let storage = role_d1::RolePairD1StorageV1::from_env(&self.env, request.input.session())?;
        let now_unix_ms = cloudflare_yao_now_unix_ms()?;
        if let Some(existing) = storage
            .get::<PairYaoSessionRecordV1>(PAIR_SESSION_RECORD_STORAGE_KEY)
            .await?
        {
            match existing {
                PairYaoSessionRecordV1::Prepared {
                    pair_digest: stored_pair,
                    input_digest: stored_input,
                    expires_at_ms,
                    root_metadata_digest,
                    input,
                    work,
                    receipt,
                } if stored_pair == pair_digest
                    && stored_input == input_digest
                    && work == request.work
                    && now_unix_ms < expires_at_ms =>
                {
                    return Response::from_json(&DeriverBYaoSessionResponseV1::PairPrepared {
                        session: input.session(),
                        pair_digest: stored_pair,
                        root_metadata_digest,
                        input,
                        work,
                        receipt,
                    });
                }
                PairYaoSessionRecordV1::Completed {
                    pair_digest: stored_pair,
                    input_digest: stored_input,
                    ..
                } if stored_pair == pair_digest && stored_input == input_digest => {
                    return Response::from_json(&DeriverBYaoSessionResponseV1::PairCompleted {
                        session: request.input.session(),
                        pair_digest,
                    });
                }
                PairYaoSessionRecordV1::Running {
                    pair_digest: stored_pair,
                    input_digest: stored_input,
                    ..
                } if stored_pair == pair_digest && stored_input == input_digest => {
                    return Response::from_json(&DeriverBYaoSessionResponseV1::PairRunning {
                        session: request.input.session(),
                        pair_digest,
                    });
                }
                record
                    if record.pair_digest() != pair_digest
                        || record.input_digest() != input_digest =>
                {
                    return Response::error("conflicting Deriver B pair preparation", 409);
                }
                PairYaoSessionRecordV1::Prepared { .. }
                | PairYaoSessionRecordV1::Running { .. }
                | PairYaoSessionRecordV1::Completed { .. }
                | PairYaoSessionRecordV1::Burned { .. }
                | PairYaoSessionRecordV1::Expired { .. } => {
                    return Response::error("Deriver B pair is terminal or expired", 409);
                }
            }
        }
        let runtime = CloudflareDeriverBWorkerRuntimeV1::from_worker_env(&self.env)
            .map_err(|error| worker::Error::RustError(error.message().to_owned()))?;
        let root_metadata_digest = load_deriver_b_yao_root_metadata_digest(
            &self.env,
            &runtime,
            &request.pair_binding.binding().lifecycle,
        )
        .await
        .map_err(|error| worker::Error::RustError(error.message().to_owned()))?;
        storage.bind_creation_scope(
            &request.pair_binding.binding().lifecycle.signer_set_id,
            request
                .pair_binding
                .binding()
                .lifecycle
                .root_share_epoch
                .as_str(),
            root_metadata_digest,
        )?;
        let prepared_at_ms = cloudflare_yao_now_unix_ms()?;
        if let Some(existing) = storage
            .get::<PairYaoSessionRecordV1>(PAIR_SESSION_RECORD_STORAGE_KEY)
            .await?
        {
            match existing {
                PairYaoSessionRecordV1::Prepared {
                    pair_digest: stored_pair,
                    input_digest: stored_input,
                    expires_at_ms,
                    root_metadata_digest,
                    input,
                    work,
                    receipt,
                } if stored_pair == pair_digest
                    && stored_input == input_digest
                    && work == request.work
                    && prepared_at_ms < expires_at_ms =>
                {
                    return Response::from_json(&DeriverBYaoSessionResponseV1::PairPrepared {
                        session: input.session(),
                        pair_digest: stored_pair,
                        root_metadata_digest,
                        input,
                        work,
                        receipt,
                    });
                }
                PairYaoSessionRecordV1::Prepared { .. }
                | PairYaoSessionRecordV1::Running { .. }
                | PairYaoSessionRecordV1::Completed { .. }
                | PairYaoSessionRecordV1::Burned { .. }
                | PairYaoSessionRecordV1::Expired { .. } => {
                    return Response::error("Deriver B pair changed while preparing", 409);
                }
            }
        }
        let expires_at_ms = yao_expiry_from_now(prepared_at_ms, YAO_PREPARED_INPUT_LIFETIME_MS)?;
        let receipt = sign_role_readiness_receipt_v1(
            &self.env,
            CloudflareWorkerRoleV1::DeriverB,
            runtime.peer_signing_key(),
            Ed25519YaoDeriverRoleV1::DeriverB,
            request.pair_binding.session(),
            pair_digest,
            input_digest,
            root_metadata_digest,
            prepared_at_ms,
            expires_at_ms,
        )
        .map_err(|error| worker::Error::RustError(error.message().to_owned()))?;
        let input = request.input;
        let prepared_record = PairYaoSessionRecordV1::Prepared {
            pair_digest,
            input_digest,
            root_metadata_digest,
            expires_at_ms,
            input: Box::new(input.clone()),
            work: request.work.clone(),
            receipt: Box::new(receipt.clone()),
        };
        let record_for_transaction = prepared_record.clone();
        storage
            .transaction(move |transaction| async move {
                let current = match transaction
                    .get::<PairYaoSessionRecordV1>(PAIR_SESSION_RECORD_STORAGE_KEY)
                    .await
                {
                    Ok(record) => Some(record),
                    Err(worker::Error::JsError(message))
                        if message == "No such value in storage." =>
                    {
                        None
                    }
                    Err(error) => return Err(error),
                };
                if current.is_some() {
                    return Ok(());
                }
                transaction
                    .put(PAIR_SESSION_RECORD_STORAGE_KEY, record_for_transaction)
                    .await?;
                Ok(())
            })
            .await?;
        if !matches!(
            storage
                .get::<PairYaoSessionRecordV1>(PAIR_SESSION_RECORD_STORAGE_KEY)
                .await?,
            Some(PairYaoSessionRecordV1::Prepared {
                pair_digest: stored_pair,
                input_digest: stored_input,
                ..
            }) if stored_pair == pair_digest && stored_input == input_digest
        ) {
            return Response::error("Deriver B pair changed while preparing", 409);
        }
        Response::from_json(&DeriverBYaoSessionResponseV1::PairPrepared {
            session: input.session(),
            pair_digest,
            root_metadata_digest,
            input: Box::new(input),
            work: request.work,
            receipt: Box::new(receipt),
        })
    }

    async fn handle_begin_pair(
        &self,
        session: [u8; 32],
        pair_digest: [u8; 32],
        execution_id: Ed25519YaoExecutionIdV1,
        peer_receipt: Ed25519YaoRoleReadinessReceiptV1,
    ) -> worker::Result<Response> {
        let runtime = CloudflareDeriverBWorkerRuntimeV1::from_worker_env(&self.env)
            .map_err(|error| worker::Error::RustError(error.message().to_owned()))?;
        let now_unix_ms = cloudflare_yao_now_unix_ms()?;
        validate_cloudflare_role_readiness_receipt_v1(&peer_receipt, now_unix_ms)
            .map_err(|error| worker::Error::RustError(error.message().to_owned()))?;
        verify_role_readiness_receipt_v1(&peer_receipt, runtime.peer_verifying_keys())
            .map_err(|error| worker::Error::RustError(error.message().to_owned()))?;
        if peer_receipt.role() != Ed25519YaoDeriverRoleV1::DeriverA
            || peer_receipt.pair_digest().bytes != pair_digest
            || peer_receipt.session_bytes() != session
        {
            return Response::error("Deriver A readiness receipt does not match pair", 409);
        }
        let storage = role_d1::RolePairD1StorageV1::from_env(&self.env, session)?;
        let Some(record) = storage
            .get::<PairYaoSessionRecordV1>(PAIR_SESSION_RECORD_STORAGE_KEY)
            .await?
        else {
            return Response::from_json(&DeriverBYaoSessionResponseV1::PairMissing {
                session,
                pair_digest,
            });
        };
        let PairYaoSessionRecordV1::Prepared {
            pair_digest: stored_pair,
            input_digest,
            root_metadata_digest,
            expires_at_ms,
            input,
            work,
            receipt,
        } = record
        else {
            return Response::error("Deriver B pair is not prepared", 409);
        };
        if stored_pair != pair_digest || input.session() != session {
            return Response::error("Deriver B pair identity mismatch", 409);
        }
        if now_unix_ms >= expires_at_ms {
            if !expire_prepared_pair_if_current(&storage, pair_digest, input_digest, now_unix_ms)
                .await?
            {
                return Response::error("Deriver B pair expiry state changed", 409);
            }
            return Response::error("Deriver B pair preparation expired", 409);
        }
        validate_cloudflare_role_readiness_receipt_v1(&receipt, now_unix_ms)
            .map_err(|error| worker::Error::RustError(error.message().to_owned()))?;
        verify_role_readiness_receipt_v1(&receipt, runtime.peer_verifying_keys())
            .map_err(|error| worker::Error::RustError(error.message().to_owned()))?;
        if receipt.root_metadata_digest().bytes != root_metadata_digest {
            return Response::error(
                "Deriver B readiness root does not match prepared state",
                409,
            );
        }
        let started_at_ms = now_unix_ms;
        let response_input = input.clone();
        let response_work = work.clone();
        let response_receipt = receipt.clone();
        let running_record = PairYaoSessionRecordV1::Running {
            pair_digest,
            input_digest,
            root_metadata_digest,
            execution_id: execution_id.into_bytes(),
            started_at_ms,
            input,
            work,
        };
        storage
            .transaction(move |transaction| async move {
                let current = match transaction
                    .get::<PairYaoSessionRecordV1>(PAIR_SESSION_RECORD_STORAGE_KEY)
                    .await
                {
                    Ok(record) => record,
                    Err(worker::Error::JsError(message))
                        if message == "No such value in storage." =>
                    {
                        return Ok(())
                    }
                    Err(error) => return Err(error),
                };
                if matches!(
                    current,
                    PairYaoSessionRecordV1::Prepared {
                        pair_digest: stored_pair,
                        input_digest: stored_input,
                        expires_at_ms,
                        ..
                    } if stored_pair == pair_digest
                        && stored_input == input_digest
                        && started_at_ms < expires_at_ms
                ) {
                    transaction
                        .put(PAIR_SESSION_RECORD_STORAGE_KEY, running_record)
                        .await?;
                }
                Ok(())
            })
            .await?;
        let current = storage
            .get::<PairYaoSessionRecordV1>(PAIR_SESSION_RECORD_STORAGE_KEY)
            .await?;
        if !matches!(
            current,
            Some(PairYaoSessionRecordV1::Running {
                pair_digest: stored_pair,
                input_digest: stored_input,
                execution_id: stored_execution_id,
                ..
            }) if stored_pair == pair_digest
                && stored_input == input_digest
                && stored_execution_id == execution_id.into_bytes()
        ) {
            return Response::error("Deriver B pair was already claimed", 409);
        }
        Response::from_json(&DeriverBYaoSessionResponseV1::PairStarted {
            session,
            pair_digest,
            execution_id,
            input: response_input,
            work: response_work,
            receipt: response_receipt,
            root_metadata_digest,
        })
    }

    async fn handle_complete_pair(
        &self,
        pair_digest: [u8; 32],
        execution: Ed25519YaoRoleExecutionV1,
    ) -> worker::Result<Response> {
        let session = execution.session();
        let storage = role_d1::RolePairD1StorageV1::from_env(&self.env, session)?;
        let record = storage
            .get::<PairYaoSessionRecordV1>(PAIR_SESSION_RECORD_STORAGE_KEY)
            .await?
            .ok_or_else(|| worker::Error::RustError("Deriver B pair is missing".into()))?;
        let expected_execution = execution.clone();
        match record {
            PairYaoSessionRecordV1::Running {
                pair_digest: stored_pair,
                input_digest,
                input,
                ..
            } if stored_pair == pair_digest && input.session() == session => {
                storage
                    .transaction(move |transaction| async move {
                        let current = match transaction
                            .get::<PairYaoSessionRecordV1>(PAIR_SESSION_RECORD_STORAGE_KEY)
                            .await
                        {
                            Ok(record) => record,
                            Err(worker::Error::JsError(message))
                                if message == "No such value in storage." =>
                            {
                                return Ok(())
                            }
                            Err(error) => return Err(error),
                        };
                        let now_unix_ms = cloudflare_yao_now_unix_ms()?;
                        if let Some(next) = completed_pair_record_if_running(
                            &current,
                            pair_digest,
                            PairCompletionExpectation::DeriverB { input_digest },
                            &execution,
                            now_unix_ms,
                        ) {
                            transaction
                                .put(PAIR_SESSION_RECORD_STORAGE_KEY, next)
                                .await?;
                        }
                        Ok(())
                    })
                    .await?;
                let current = storage
                    .get::<PairYaoSessionRecordV1>(PAIR_SESSION_RECORD_STORAGE_KEY)
                    .await?;
                match current {
                    Some(PairYaoSessionRecordV1::Completed {
                        pair_digest: stored_pair,
                        execution: existing,
                        ..
                    }) if stored_pair == pair_digest
                        && existing.session() == session
                        && *existing == expected_execution =>
                    {
                        Response::from_json(&DeriverBYaoSessionResponseV1::PairCompleted {
                            session,
                            pair_digest,
                        })
                    }
                    Some(PairYaoSessionRecordV1::Burned {
                        pair_digest: stored_pair,
                        ..
                    }) if stored_pair == pair_digest => {
                        Response::from_json(&DeriverBYaoSessionResponseV1::PairBurned {
                            session,
                            pair_digest,
                        })
                    }
                    Some(PairYaoSessionRecordV1::Completed { .. }) => {
                        Response::error("conflicting Deriver B execution", 409)
                    }
                    _ => Response::error("Deriver B pair completion is invalid", 409),
                }
            }
            PairYaoSessionRecordV1::Completed {
                pair_digest: stored_pair,
                execution: existing,
                ..
            } if stored_pair == pair_digest && *existing == expected_execution => {
                Response::from_json(&DeriverBYaoSessionResponseV1::PairCompleted {
                    session,
                    pair_digest,
                })
            }
            PairYaoSessionRecordV1::Burned {
                pair_digest: stored_pair,
                ..
            } if stored_pair == pair_digest => {
                Response::from_json(&DeriverBYaoSessionResponseV1::PairBurned {
                    session,
                    pair_digest,
                })
            }
            _ => Response::error("Deriver B pair completion is invalid", 409),
        }
    }

    async fn handle_fail_pair(
        &self,
        session: [u8; 32],
        pair_digest: [u8; 32],
    ) -> worker::Result<Response> {
        let storage = role_d1::RolePairD1StorageV1::from_env(&self.env, session)?;
        let record = storage
            .get::<PairYaoSessionRecordV1>(PAIR_SESSION_RECORD_STORAGE_KEY)
            .await?
            .ok_or_else(|| worker::Error::RustError("Deriver B pair is missing".into()))?;
        let response = match record {
            PairYaoSessionRecordV1::Running {
                pair_digest: stored_pair,
                input_digest,
                input,
                ..
            } if stored_pair == pair_digest && input.session() == session => {
                storage
                    .transaction(move |transaction| async move {
                        let current = match transaction
                            .get::<PairYaoSessionRecordV1>(PAIR_SESSION_RECORD_STORAGE_KEY)
                            .await
                        {
                            Ok(record) => record,
                            Err(worker::Error::JsError(message))
                                if message == "No such value in storage." =>
                            {
                                return Ok(())
                            }
                            Err(error) => return Err(error),
                        };
                        if let PairYaoSessionRecordV1::Running {
                            pair_digest: current_pair,
                            input: current_input,
                            execution_id,
                            ..
                        } = current
                        {
                            if current_pair == pair_digest && current_input.session() == session {
                                transaction
                                    .put(
                                        PAIR_SESSION_RECORD_STORAGE_KEY,
                                        PairYaoSessionRecordV1::Burned {
                                            pair_digest,
                                            input_digest,
                                            execution_id,
                                        },
                                    )
                                    .await?;
                            }
                        }
                        Ok(())
                    })
                    .await?;
                let current = storage
                    .get::<PairYaoSessionRecordV1>(PAIR_SESSION_RECORD_STORAGE_KEY)
                    .await?;
                match current {
                    Some(PairYaoSessionRecordV1::Burned {
                        pair_digest: current_pair,
                        ..
                    }) if current_pair == pair_digest => DeriverBYaoSessionResponseV1::PairBurned {
                        session,
                        pair_digest,
                    },
                    Some(PairYaoSessionRecordV1::Completed {
                        pair_digest: current_pair,
                        execution,
                        ..
                    }) if current_pair == pair_digest && execution.session() == session => {
                        DeriverBYaoSessionResponseV1::PairCompleted {
                            session,
                            pair_digest,
                        }
                    }
                    _ => return Response::error("Deriver B pair failure state changed", 409),
                }
            }
            PairYaoSessionRecordV1::Burned {
                pair_digest: stored_pair,
                ..
            } if stored_pair == pair_digest => DeriverBYaoSessionResponseV1::PairBurned {
                session,
                pair_digest,
            },
            PairYaoSessionRecordV1::Completed {
                pair_digest: stored_pair,
                execution,
                ..
            } if stored_pair == pair_digest && execution.session() == session => {
                DeriverBYaoSessionResponseV1::PairCompleted {
                    session,
                    pair_digest,
                }
            }
            _ => return Response::error("Deriver B pair cannot be burned", 409),
        };
        Response::from_json(&response)
    }

    async fn handle_read_pair_status(
        &self,
        session: [u8; 32],
        pair_digest: [u8; 32],
    ) -> worker::Result<Response> {
        let storage = role_d1::RolePairD1StorageV1::from_env(&self.env, session)?;
        let Some(record) = storage
            .get::<PairYaoSessionRecordV1>(PAIR_SESSION_RECORD_STORAGE_KEY)
            .await?
        else {
            return Response::from_json(&DeriverBYaoSessionResponseV1::PairMissing {
                session,
                pair_digest,
            });
        };
        let response = match record {
            PairYaoSessionRecordV1::Prepared {
                pair_digest: stored_pair,
                input,
                expires_at_ms,
                input_digest,
                ..
            } if stored_pair == pair_digest && input.session() == session => {
                let now_ms = cloudflare_yao_now_unix_ms()?;
                if now_ms >= expires_at_ms {
                    if !expire_prepared_pair_if_current(&storage, pair_digest, input_digest, now_ms)
                        .await?
                    {
                        return Response::error("Deriver B pair expiry state changed", 409);
                    }
                    DeriverBYaoSessionResponseV1::PairExpired {
                        session,
                        pair_digest,
                    }
                } else {
                    DeriverBYaoSessionResponseV1::PairPreparedStatus {
                        session,
                        pair_digest,
                    }
                }
            }
            PairYaoSessionRecordV1::Running {
                pair_digest: stored_pair,
                input_digest,
                execution_id,
                started_at_ms,
                input,
                ..
            } if stored_pair == pair_digest && input.session() == session => {
                if burn_running_pair_if_expired(
                    &storage,
                    pair_digest,
                    input_digest,
                    execution_id,
                    started_at_ms,
                    cloudflare_yao_now_unix_ms()?,
                )
                .await?
                {
                    DeriverBYaoSessionResponseV1::PairBurned {
                        session,
                        pair_digest,
                    }
                } else {
                    DeriverBYaoSessionResponseV1::PairRunning {
                        session,
                        pair_digest,
                    }
                }
            }
            PairYaoSessionRecordV1::Completed {
                pair_digest: stored_pair,
                execution,
                ..
            } if stored_pair == pair_digest && execution.session() == session => {
                DeriverBYaoSessionResponseV1::PairRoleExecution { execution }
            }
            PairYaoSessionRecordV1::Burned {
                pair_digest: stored_pair,
                ..
            } if stored_pair == pair_digest => DeriverBYaoSessionResponseV1::PairBurned {
                session,
                pair_digest,
            },
            PairYaoSessionRecordV1::Expired {
                pair_digest: stored_pair,
                ..
            } if stored_pair == pair_digest => DeriverBYaoSessionResponseV1::PairExpired {
                session,
                pair_digest,
            },
            _ => return Response::error("Deriver B pair identity mismatch", 409),
        };
        Response::from_json(&response)
    }
}

pub async fn handle_cloudflare_ed25519_yao_deriver_a_prepare_pair_v1(
    mut request: Request,
    env: &Env,
) -> RouterAbProtocolResult<Response> {
    let trace_id = parse_cloudflare_trace_id_from_request_v1(&request)?;
    let request = parse_request::<CloudflareEd25519YaoPairPrepareRequestV1>(&mut request).await?;
    let expected_kind = input_kind_for_circuit(request.pair_binding.binding().circuit_family());
    request.validate_for_role(Ed25519YaoDeriverRoleV1::DeriverA, expected_kind)?;
    let receipt = execute_deriver_a_pair_prepare(env, request, trace_id).await?;
    json_response(&receipt)
}

pub async fn handle_cloudflare_ed25519_yao_deriver_a_execute_pair_v1(
    mut request: Request,
    env: &Env,
) -> RouterAbProtocolResult<Response> {
    let trace_id = parse_cloudflare_trace_id_from_request_v1(&request)?;
    let request = parse_request::<CloudflareEd25519YaoPairExecuteRequestV1>(&mut request).await?;
    request.validate()?;
    let pair_binding = request.pair_binding.clone();
    let session = pair_binding.session();
    let pair_digest = pair_binding.pair_digest().bytes;
    let execution_id = Ed25519YaoExecutionIdV1::new(
        yao_execution_id().map_err(|_| invalid_lifecycle("Yao execution id generation failed"))?,
    )?;
    let runtime = CloudflareDeriverAWorkerRuntimeV1::from_worker_env(env)?;
    let now_ms =
        cloudflare_yao_now_unix_ms().map_err(|_| invalid_lifecycle("Yao clock is unavailable"))?;
    for readiness in [&request.local_receipt, &request.peer_receipt] {
        validate_cloudflare_role_readiness_receipt_v1(readiness, now_ms)?;
        verify_role_readiness_receipt_v1(readiness, runtime.peer_verifying_keys())?;
    }
    let pair_execution = DeriverAPairExecutionContextV1 {
        expected_root_metadata_digest: request.local_receipt.root_metadata_digest().bytes,
        pair_binding: &pair_binding,
        work: request.work,
        pair_digest,
        execution_id,
        peer_receipt: &request.peer_receipt,
        local_receipt: &request.local_receipt,
    };
    let execution =
        execute_deriver_a_role(env, &runtime, request.input, trace_id, pair_execution).await;
    let execution = match execution {
        Ok(execution) => execution,
        Err(error) => {
            let _ = execute_deriver_a_pair_command(
                env,
                DeriverAYaoSessionCommandV1::BurnPair {
                    session,
                    pair_digest,
                },
                trace_id,
            )
            .await;
            let _ = execute_deriver_b_session_command(
                env,
                DeriverBYaoSessionCommandV1::FailPair {
                    session,
                    pair_digest,
                },
                trace_id,
            )
            .await;
            return Err(error);
        }
    };
    let DeriverAPairRoleExecutionV1 {
        deriver_a_execution,
        deriver_b_sealed_execution_json,
    } = execution;
    let execution = complete_deriver_a_pair(
        env,
        pair_digest,
        execution_id.into_bytes(),
        deriver_a_execution,
        trace_id,
    )
    .await?;
    json_response(&CloudflareEd25519YaoPairExecuteResponseV1 {
        deriver_a_execution: execution,
        deriver_b_sealed_execution_json,
    })
}

pub async fn handle_cloudflare_ed25519_yao_deriver_a_read_pair_status_v1(
    mut request: Request,
    env: &Env,
) -> RouterAbProtocolResult<Response> {
    let trace_id = parse_cloudflare_trace_id_from_request_v1(&request)?;
    let request = parse_request::<CloudflareEd25519YaoPairLookupRequestV1>(&mut request).await?;
    request.validate()?;
    let mut response = execute_deriver_a_pair_command(
        env,
        DeriverAYaoSessionCommandV1::ReadPairStatus {
            session: request.session,
            pair_digest: request.pair_digest,
        },
        trace_id,
    )
    .await?;
    response
        .json::<CloudflareEd25519YaoPairStatusResponseV1>()
        .await
        .map_err(|_| invalid_lifecycle("Deriver A pair status response is malformed"))
        .and_then(|status| json_response(&status))
}

pub async fn handle_cloudflare_ed25519_yao_deriver_a_burn_pair_v1(
    mut request: Request,
    env: &Env,
) -> RouterAbProtocolResult<Response> {
    let trace_id = parse_cloudflare_trace_id_from_request_v1(&request)?;
    let request = parse_request::<CloudflareEd25519YaoPairLookupRequestV1>(&mut request).await?;
    request.validate()?;
    let mut response = execute_deriver_a_pair_command(
        env,
        DeriverAYaoSessionCommandV1::BurnPair {
            session: request.session,
            pair_digest: request.pair_digest,
        },
        trace_id,
    )
    .await?;
    response
        .json::<CloudflareEd25519YaoPairStatusResponseV1>()
        .await
        .map_err(|_| invalid_lifecycle("Deriver A pair burn response is malformed"))
        .and_then(|status| json_response(&status))
}

struct DeriverAPairExecutionContextV1<'a> {
    expected_root_metadata_digest: [u8; 32],
    pair_binding: &'a Ed25519YaoInputPairBindingV1,
    work: crate::CloudflareEd25519YaoPairWorkV1,
    pair_digest: [u8; 32],
    execution_id: Ed25519YaoExecutionIdV1,
    peer_receipt: &'a Ed25519YaoRoleReadinessReceiptV1,
    local_receipt: &'a Ed25519YaoRoleReadinessReceiptV1,
}

struct DeriverAPairRoleExecutionV1 {
    deriver_a_execution: Ed25519YaoRoleExecutionV1,
    deriver_b_sealed_execution_json: String,
}

async fn execute_deriver_a_role(
    env: &Env,
    runtime: &CloudflareDeriverAWorkerRuntimeV1,
    input: Ed25519YaoEncryptedInputV1,
    trace_id: RoleTraceContextV1,
    pair_execution: DeriverAPairExecutionContextV1<'_>,
) -> RouterAbProtocolResult<DeriverAPairRoleExecutionV1> {
    let now_unix_ms =
        cloudflare_yao_now_unix_ms().map_err(|_| invalid_lifecycle("Yao clock is unavailable"))?;
    if pair_execution.peer_receipt.role() != Ed25519YaoDeriverRoleV1::DeriverB {
        return Err(invalid_lifecycle(
            "Deriver A execution requires a Deriver B readiness receipt",
        ));
    }
    validate_cloudflare_role_readiness_receipt_v1(pair_execution.peer_receipt, now_unix_ms)?;
    verify_role_readiness_receipt_v1(pair_execution.peer_receipt, runtime.peer_verifying_keys())?;
    if pair_execution.local_receipt.role() != Ed25519YaoDeriverRoleV1::DeriverA {
        return Err(invalid_lifecycle(
            "Deriver A execution requires a Deriver A readiness receipt",
        ));
    }
    validate_cloudflare_role_readiness_receipt_v1(pair_execution.local_receipt, now_unix_ms)?;
    verify_role_readiness_receipt_v1(pair_execution.local_receipt, runtime.peer_verifying_keys())?;
    let circuit = circuit_for_input(&input);
    let private_key =
        load_deriver_input_private_key(env, &runtime.envelope_decrypt_key().current.binding_name)?;
    let session = input.session();
    let websocket_binding = CloudflareEd25519YaoWebSocketBindingV1::with_pair_digest(
        circuit,
        session,
        pair_execution.pair_digest,
    )
    .map_err(map_websocket_error)?;
    let (execution, peer_sealed_completion) = match input.kind() {
        Ed25519YaoInputKindV1::Activation => {
            let role_request =
                open_ed25519_yao_activation_deriver_a_input_v1(&input, &private_key)?;
            let (root_with_digest, socket, acceptance) = load_deriver_a_pair_root_before_connect(
                env,
                runtime,
                &role_request.binding.lifecycle,
                trace_id,
                websocket_binding,
                &pair_execution,
            )
            .await?;
            let (root, root_metadata_digest) = root_with_digest;
            validate_expected_root_metadata_digest(
                pair_execution.expected_root_metadata_digest,
                root_metadata_digest,
            )?;
            confirm_deriver_a_pair_start(
                env,
                pair_execution.pair_binding.clone(),
                pair_execution.execution_id,
                acceptance,
                pair_execution.local_receipt.clone(),
                pair_execution.peer_receipt.clone(),
                trace_id,
            )
            .await?;
            let transport = CloudflareEd25519YaoWebSocketTransportV1::deriver_a(&socket, session)
                .map_err(map_websocket_error)?;
            let recipients = role_request.recipients;
            let (binding, role) =
                build_product_activation_deriver_a_v1(root, role_request).map_err(map_adapter)?;
            let protocol_started_at_ms = role_span_started_at_ms();
            let completion_result =
                with_yao_ceremony_timeout(run_activation_deriver_a(role, transport)).await;
            emit_role_span_v1(
                trace_id,
                "deriver_a.yao_protocol",
                "deriver_a",
                "activation",
                protocol_started_at_ms,
                if completion_result.is_ok() {
                    "success"
                } else {
                    "failure"
                },
            );
            let completion = completion_result?;
            (
                seal_ed25519_yao_activation_deriver_a_execution_v1(
                    &mut CloudflareHpkeGetrandomRngV1,
                    binding,
                    recipients,
                    &completion.role,
                )?,
                completion.transport.peer_sealed_completion,
            )
        }
        Ed25519YaoInputKindV1::Export => {
            let role_request = open_ed25519_yao_export_deriver_a_input_v1(&input, &private_key)?;
            let (root_with_digest, socket, acceptance) = load_deriver_a_pair_root_before_connect(
                env,
                runtime,
                &role_request.binding.lifecycle,
                trace_id,
                websocket_binding,
                &pair_execution,
            )
            .await?;
            let (root, root_metadata_digest) = root_with_digest;
            validate_expected_root_metadata_digest(
                pair_execution.expected_root_metadata_digest,
                root_metadata_digest,
            )?;
            confirm_deriver_a_pair_start(
                env,
                pair_execution.pair_binding.clone(),
                pair_execution.execution_id,
                acceptance,
                pair_execution.local_receipt.clone(),
                pair_execution.peer_receipt.clone(),
                trace_id,
            )
            .await?;
            let transport = CloudflareEd25519YaoWebSocketTransportV1::deriver_a(&socket, session)
                .map_err(map_websocket_error)?;
            let recipient = role_request.recipients;
            let (binding, role) =
                build_product_export_deriver_a_v1(root, role_request).map_err(map_adapter)?;
            let protocol_started_at_ms = role_span_started_at_ms();
            let completion_result =
                with_yao_ceremony_timeout(run_export_deriver_a(role, transport)).await;
            emit_role_span_v1(
                trace_id,
                "deriver_a.yao_protocol",
                "deriver_a",
                "export",
                protocol_started_at_ms,
                if completion_result.is_ok() {
                    "success"
                } else {
                    "failure"
                },
            );
            let completion = completion_result?;
            (
                seal_ed25519_yao_export_deriver_a_execution_v1(
                    &mut CloudflareHpkeGetrandomRngV1,
                    binding,
                    recipient,
                    &completion.role,
                )?,
                completion.transport.peer_sealed_completion,
            )
        }
        Ed25519YaoInputKindV1::LaneMaterialization => {
            let crate::CloudflareEd25519YaoPairWorkV1::Lane { job: expected_job } =
                &pair_execution.work
            else {
                return Err(invalid_lifecycle(
                    "Deriver A lane input is missing its admitted job",
                ));
            };
            let role_request =
                open_ed25519_yao_lane_deriver_a_input_v1(&input, expected_job, &private_key)?;
            let lifecycle = role_request.binding.lifecycle.clone();
            let (root_with_digest, socket, acceptance) = load_deriver_a_pair_root_before_connect(
                env,
                runtime,
                &lifecycle,
                trace_id,
                websocket_binding,
                &pair_execution,
            )
            .await?;
            let (root, root_metadata_digest) = root_with_digest;
            validate_expected_root_metadata_digest(
                pair_execution.expected_root_metadata_digest,
                root_metadata_digest,
            )?;
            confirm_deriver_a_pair_start(
                env,
                pair_execution.pair_binding.clone(),
                pair_execution.execution_id,
                acceptance,
                pair_execution.local_receipt.clone(),
                pair_execution.peer_receipt.clone(),
                trace_id,
            )
            .await?;
            let transport = CloudflareEd25519YaoWebSocketTransportV1::deriver_a(&socket, session)
                .map_err(map_websocket_error)?;
            let (binding, job, role) = build_product_lane_deriver_a_v1(
                root,
                role_request,
                &mut CloudflareHpkeGetrandomRngV1,
            )
            .map_err(map_adapter)?;
            if &binding != pair_execution.pair_binding.binding()
                || router_ab_core::PublicDigest32::new(job.transcript_digest_v1()?)
                    != pair_execution.pair_binding.authorization_digest()
            {
                return Err(invalid_lifecycle(
                    "Deriver A lane input does not match the Router pair binding",
                ));
            }
            let protocol_started_at_ms = role_span_started_at_ms();
            let completion_result =
                with_yao_ceremony_timeout(run_lane_materialization_deriver_a(role, transport))
                    .await;
            emit_role_span_v1(
                trace_id,
                "deriver_a.yao_protocol",
                "deriver_a",
                "lane_materialization",
                protocol_started_at_ms,
                if completion_result.is_ok() {
                    "success"
                } else {
                    "failure"
                },
            );
            let completion = completion_result?;
            (
                Ed25519YaoRoleExecutionV1::Lane(seal_ed25519_yao_lane_deriver_a_execution_v1(
                    &mut CloudflareHpkeGetrandomRngV1,
                    job,
                    &completion.role,
                )?),
                completion.transport.peer_sealed_completion,
            )
        }
    };
    let peer_sealed_completion = peer_sealed_completion.ok_or_else(|| {
        invalid_lifecycle("Deriver B did not return its sealed execution over the pair channel")
    })?;
    let deriver_b_sealed_execution_json = String::from_utf8(peer_sealed_completion)
        .map_err(|_| invalid_lifecycle("Deriver B sealed execution is not UTF-8 JSON"))?;
    Ok(DeriverAPairRoleExecutionV1 {
        deriver_a_execution: execution,
        deriver_b_sealed_execution_json,
    })
}

async fn load_deriver_a_pair_root_before_connect(
    env: &Env,
    runtime: &CloudflareDeriverAWorkerRuntimeV1,
    lifecycle: &LifecycleScopeV1,
    trace_id: RoleTraceContextV1,
    websocket_binding: CloudflareEd25519YaoWebSocketBindingV1,
    pair_execution: &DeriverAPairExecutionContextV1<'_>,
) -> RouterAbProtocolResult<(
    ([u8; 32], [u8; 32]),
    worker::WebSocket,
    Ed25519YaoRoleStartAcceptanceV1,
)> {
    let root_with_digest =
        load_deriver_a_yao_root_with_metadata_digest(env, runtime, lifecycle, trace_id).await?;
    validate_expected_root_metadata_digest(
        pair_execution.expected_root_metadata_digest,
        root_with_digest.1,
    )?;
    let (socket, acceptance) = connect_deriver_b(
        env,
        websocket_binding,
        trace_id,
        pair_execution.local_receipt,
        pair_execution.execution_id,
    )
    .await?;
    Ok((root_with_digest, socket, acceptance))
}

async fn connect_deriver_b(
    env: &Env,
    binding: CloudflareEd25519YaoWebSocketBindingV1,
    trace_id: RoleTraceContextV1,
    peer_receipt: &Ed25519YaoRoleReadinessReceiptV1,
    execution_id: Ed25519YaoExecutionIdV1,
) -> RouterAbProtocolResult<(worker::WebSocket, Ed25519YaoRoleStartAcceptanceV1)> {
    let started_at_ms = role_span_started_at_ms();
    let result = crate::connect_cloudflare_ed25519_yao_deriver_b_with_start_acceptance_v1(
        env,
        binding,
        trace_id,
        peer_receipt,
        execution_id,
    )
    .await
    .map(|connection| (connection.socket, connection.acceptance))
    .map_err(map_websocket_error);
    emit_role_span_v1(
        trace_id,
        "deriver_a.websocket_connect",
        "deriver_a",
        "websocket",
        started_at_ms,
        if result.is_ok() { "success" } else { "failure" },
    );
    result
}

pub async fn handle_cloudflare_ed25519_yao_deriver_b_prepare_pair_v1(
    mut request: Request,
    env: &Env,
) -> RouterAbProtocolResult<Response> {
    let trace_id = parse_cloudflare_trace_id_from_request_v1(&request)?;
    let request = parse_request::<CloudflareEd25519YaoPairPrepareRequestV1>(&mut request).await?;
    let expected_kind = input_kind_for_circuit(request.pair_binding.binding().circuit_family());
    request.validate_for_role(Ed25519YaoDeriverRoleV1::DeriverB, expected_kind)?;
    let response = execute_deriver_b_session_command(
        env,
        DeriverBYaoSessionCommandV1::PreparePair {
            pair_binding: Box::new(request.pair_binding),
            work: request.work,
            input: Box::new(request.input),
        },
        trace_id,
    )
    .await?;
    match response {
        DeriverBYaoSessionResponseV1::PairPrepared { receipt, .. } => json_response(&*receipt),
        _ => Err(invalid_lifecycle(
            "Deriver B pair preparation returned the wrong response",
        )),
    }
}

pub async fn handle_cloudflare_ed25519_yao_deriver_b_read_pair_status_v1(
    mut request: Request,
    env: &Env,
) -> RouterAbProtocolResult<Response> {
    let trace_id = parse_cloudflare_trace_id_from_request_v1(&request)?;
    let request = parse_request::<CloudflareEd25519YaoPairLookupRequestV1>(&mut request).await?;
    request.validate()?;
    let response = execute_deriver_b_session_command(
        env,
        DeriverBYaoSessionCommandV1::ReadPairStatus {
            session: request.session,
            pair_digest: request.pair_digest,
        },
        trace_id,
    )
    .await?;
    let status = match response {
        DeriverBYaoSessionResponseV1::PairPrepared {
            session,
            pair_digest,
            ..
        }
        | DeriverBYaoSessionResponseV1::PairPreparedStatus {
            session,
            pair_digest,
        } => CloudflareEd25519YaoPairStatusResponseV1::Prepared {
            session,
            pair_digest,
        },
        DeriverBYaoSessionResponseV1::PairRunning {
            session,
            pair_digest,
        } => CloudflareEd25519YaoPairStatusResponseV1::Running {
            session,
            pair_digest,
        },
        DeriverBYaoSessionResponseV1::PairRoleExecution { execution } => {
            CloudflareEd25519YaoPairStatusResponseV1::Completed { execution }
        }
        DeriverBYaoSessionResponseV1::PairBurned {
            session,
            pair_digest,
        } => CloudflareEd25519YaoPairStatusResponseV1::Burned {
            session,
            pair_digest,
        },
        DeriverBYaoSessionResponseV1::PairExpired {
            session,
            pair_digest,
        } => CloudflareEd25519YaoPairStatusResponseV1::Expired {
            session,
            pair_digest,
        },
        DeriverBYaoSessionResponseV1::PairMissing {
            session,
            pair_digest,
        } => CloudflareEd25519YaoPairStatusResponseV1::Missing {
            session,
            pair_digest,
        },
        _ => {
            return Err(invalid_lifecycle(
                "Deriver B pair status response is malformed",
            ))
        }
    };
    json_response(&status)
}

pub async fn handle_cloudflare_ed25519_yao_deriver_b_burn_pair_v1(
    mut request: Request,
    env: &Env,
) -> RouterAbProtocolResult<Response> {
    let trace_id = parse_cloudflare_trace_id_from_request_v1(&request)?;
    let request = parse_request::<CloudflareEd25519YaoPairLookupRequestV1>(&mut request).await?;
    request.validate()?;
    let _ = execute_deriver_b_session_command(
        env,
        DeriverBYaoSessionCommandV1::FailPair {
            session: request.session,
            pair_digest: request.pair_digest,
        },
        trace_id,
    )
    .await?;
    let response = execute_deriver_b_session_command(
        env,
        DeriverBYaoSessionCommandV1::ReadPairStatus {
            session: request.session,
            pair_digest: request.pair_digest,
        },
        trace_id,
    )
    .await?;
    let status = match response {
        DeriverBYaoSessionResponseV1::PairPrepared {
            session,
            pair_digest,
            ..
        }
        | DeriverBYaoSessionResponseV1::PairPreparedStatus {
            session,
            pair_digest,
        } => CloudflareEd25519YaoPairStatusResponseV1::Prepared {
            session,
            pair_digest,
        },
        DeriverBYaoSessionResponseV1::PairRunning {
            session,
            pair_digest,
        } => CloudflareEd25519YaoPairStatusResponseV1::Running {
            session,
            pair_digest,
        },
        DeriverBYaoSessionResponseV1::PairRoleExecution { execution } => {
            CloudflareEd25519YaoPairStatusResponseV1::Completed { execution }
        }
        DeriverBYaoSessionResponseV1::PairBurned {
            session,
            pair_digest,
        } => CloudflareEd25519YaoPairStatusResponseV1::Burned {
            session,
            pair_digest,
        },
        DeriverBYaoSessionResponseV1::PairExpired {
            session,
            pair_digest,
        } => CloudflareEd25519YaoPairStatusResponseV1::Expired {
            session,
            pair_digest,
        },
        DeriverBYaoSessionResponseV1::PairMissing {
            session,
            pair_digest,
        } => CloudflareEd25519YaoPairStatusResponseV1::Missing {
            session,
            pair_digest,
        },
        _ => {
            return Err(invalid_lifecycle(
                "Deriver B pair burn response is malformed",
            ))
        }
    };
    json_response(&status)
}

fn validate_deriver_input(
    input: &Ed25519YaoEncryptedInputV1,
    expected_deriver: Ed25519YaoDeriverRoleV1,
    expected_kind: Ed25519YaoInputKindV1,
) -> RouterAbProtocolResult<()> {
    input.validate()?;
    if input.deriver() != expected_deriver {
        return Err(invalid_lifecycle(
            "Ed25519 Yao input was delivered to the wrong Deriver",
        ));
    }
    if input.kind() != expected_kind {
        return Err(invalid_lifecycle(
            "Ed25519 Yao input family does not match the route",
        ));
    }
    Ok(())
}

pub async fn handle_cloudflare_ed25519_yao_deriver_b_websocket_v1(
    request: Request,
    env: Env,
    runtime: CloudflareDeriverBWorkerRuntimeV1,
    context: Context,
) -> RouterAbProtocolResult<Response> {
    let trace_id = parse_cloudflare_trace_id_from_request_v1(&request)?;
    let protocol = request
        .headers()
        .get("Sec-WebSocket-Protocol")
        .map_err(|_| invalid_lifecycle("WebSocket protocol header could not be read"))?
        .ok_or_else(|| invalid_lifecycle("WebSocket protocol header is missing"))?;
    let binding = CloudflareEd25519YaoWebSocketBindingV1::parse_protocol(&protocol)
        .map_err(map_websocket_error)?;
    if binding.pair_digest.iter().all(|byte| *byte == 0) {
        return Err(invalid_lifecycle(
            "Deriver B WebSocket requires a pair-bound protocol",
        ));
    }
    handle_pair_bound_deriver_b_websocket(
        request, env, runtime, context, trace_id, protocol, binding,
    )
    .await
}

async fn handle_pair_bound_deriver_b_websocket(
    request: Request,
    env: Env,
    runtime: CloudflareDeriverBWorkerRuntimeV1,
    context: Context,
    trace_id: RoleTraceContextV1,
    protocol: String,
    binding: CloudflareEd25519YaoWebSocketBindingV1,
) -> RouterAbProtocolResult<Response> {
    let serialized_receipt = request
        .headers()
        .get("x-seams-yao-readiness-receipt")
        .map_err(|_| invalid_lifecycle("readiness receipt header could not be read"))?
        .ok_or_else(|| invalid_lifecycle("pair-bound WebSocket readiness receipt is missing"))?;
    let peer_receipt = serde_json::from_str::<Ed25519YaoRoleReadinessReceiptV1>(
        &serialized_receipt,
    )
    .map_err(|_| invalid_lifecycle("pair-bound WebSocket readiness receipt is malformed"))?;
    let serialized_execution_id = request
        .headers()
        .get(EXECUTION_ID_HEADER)
        .map_err(|_| invalid_lifecycle("execution id header could not be read"))?
        .ok_or_else(|| invalid_lifecycle("pair-bound WebSocket execution id is missing"))?;
    let execution_id = Ed25519YaoExecutionIdV1::new(decode_hex_32(&serialized_execution_id)?)?;
    validate_cloudflare_role_readiness_receipt_v1(
        &peer_receipt,
        cloudflare_yao_now_unix_ms().map_err(|_| invalid_lifecycle("Yao clock is unavailable"))?,
    )
    .map_err(|error| invalid_lifecycle(error.message()))?;
    if peer_receipt.role() != Ed25519YaoDeriverRoleV1::DeriverA
        || peer_receipt.session_bytes() != binding.session
        || peer_receipt.pair_digest().bytes != binding.pair_digest
    {
        return Err(invalid_lifecycle(
            "Deriver A readiness receipt does not match WebSocket binding",
        ));
    }
    verify_role_readiness_receipt_v1(&peer_receipt, runtime.peer_verifying_keys())?;
    let pair = WebSocketPair::new()
        .map_err(|_| invalid_lifecycle("Deriver B WebSocket pair could not be created"))?;
    let running = execute_deriver_b_session_command(
        &env,
        DeriverBYaoSessionCommandV1::BeginPair {
            session: binding.session,
            pair_digest: binding.pair_digest,
            execution_id,
            peer_receipt: Box::new(peer_receipt),
        },
        trace_id,
    )
    .await?;
    let DeriverBYaoSessionResponseV1::PairStarted {
        execution_id,
        input,
        work,
        receipt,
        root_metadata_digest,
        ..
    } = running
    else {
        return Err(invalid_lifecycle(
            "Deriver B pair did not enter its running state",
        ));
    };
    if receipt.role() != Ed25519YaoDeriverRoleV1::DeriverB
        || receipt.pair_digest().bytes != binding.pair_digest
        || receipt.session_bytes() != binding.session
        || receipt.root_metadata_digest().bytes != root_metadata_digest
    {
        return Err(invalid_lifecycle(
            "Deriver B readiness root does not match prepared state",
        ));
    }
    validate_cloudflare_role_readiness_receipt_v1(
        &receipt,
        cloudflare_yao_now_unix_ms().map_err(|_| invalid_lifecycle("Yao clock is unavailable"))?,
    )
    .map_err(|error| invalid_lifecycle(error.message()))?;
    verify_role_readiness_receipt_v1(&receipt, runtime.peer_verifying_keys())?;
    if circuit_for_input(&input) != binding.circuit {
        return Err(invalid_lifecycle(
            "Deriver B prepared circuit does not match WebSocket binding",
        ));
    }
    let accepted_at_ms =
        cloudflare_yao_now_unix_ms().map_err(|_| invalid_lifecycle("Yao clock is unavailable"))?;
    let expires_at_ms = yao_expiry_from_now(accepted_at_ms, YAO_RUNNING_LIFETIME_MS)
        .map_err(|_| invalid_lifecycle("Yao acceptance expiry is invalid"))?;
    let acceptance = sign_role_start_acceptance_v1(
        &env,
        CloudflareWorkerRoleV1::DeriverB,
        runtime.peer_signing_key(),
        binding.session,
        binding.pair_digest,
        execution_id,
        root_metadata_digest,
        accepted_at_ms,
        expires_at_ms,
    )?;
    let headers = worker::Headers::new();
    headers
        .set("Sec-WebSocket-Protocol", &protocol)
        .map_err(|_| invalid_lifecycle("WebSocket response protocol could not be set"))?;
    let serialized_acceptance = serde_json::to_string(&acceptance)
        .map_err(|_| invalid_lifecycle("start acceptance could not be serialized"))?;
    headers
        .set(START_ACCEPTANCE_HEADER, &serialized_acceptance)
        .map_err(|_| invalid_lifecycle("start acceptance header could not be set"))?;
    let response = Response::from_websocket(pair.client)
        .map(|response| response.with_headers(headers))
        .map_err(|_| invalid_lifecycle("WebSocket upgrade response could not be created"))?;
    let server = pair.server;
    let server_for_error = server.clone();
    let session = binding.session;
    let pair_digest = binding.pair_digest;
    context.wait_until(async move {
        let role_started_at_ms = role_span_started_at_ms();
        let result = execute_deriver_b_role(
            &env,
            &runtime,
            *input,
            server,
            trace_id,
            root_metadata_digest,
            pair_digest,
            work,
        )
        .await;
        match &result {
            Ok(_) => emit_role_span_v1(
                trace_id,
                "deriver_b.role_execution",
                "deriver_b",
                "yao",
                role_started_at_ms,
                "success",
            ),
            Err(error) => emit_role_span_error_v1(
                trace_id,
                "deriver_b.role_execution",
                "deriver_b",
                "yao",
                role_started_at_ms,
                error,
            ),
        }
        if result.is_err() {
            let _ignored = execute_deriver_b_session_command(
                &env,
                DeriverBYaoSessionCommandV1::FailPair {
                    session,
                    pair_digest,
                },
                trace_id,
            )
            .await;
            let _ignored = server_for_error.close(Some(1011), Some("yao-pair-lifecycle-failed"));
        }
    });
    Ok(response)
}

async fn execute_deriver_b_role(
    env: &Env,
    runtime: &CloudflareDeriverBWorkerRuntimeV1,
    input: Ed25519YaoEncryptedInputV1,
    socket: worker::WebSocket,
    trace_id: RoleTraceContextV1,
    expected_root_metadata_digest: [u8; 32],
    pair_digest: [u8; 32],
    work: crate::CloudflareEd25519YaoPairWorkV1,
) -> RouterAbProtocolResult<()> {
    let private_key_started_at_ms = role_span_started_at_ms();
    let private_key_result =
        load_deriver_input_private_key(env, &runtime.envelope_decrypt_key().current.binding_name);
    emit_role_stage_result_v1(
        trace_id,
        "deriver_b.input_private_key",
        "yao",
        private_key_started_at_ms,
        &private_key_result,
    );
    let private_key = private_key_result?;
    let session = input.session();
    let transport_started_at_ms = role_span_started_at_ms();
    let transport_result = CloudflareEd25519YaoWebSocketTransportV1::deriver_b(&socket, session)
        .map_err(map_websocket_error);
    emit_role_stage_result_v1(
        trace_id,
        "deriver_b.transport",
        "yao",
        transport_started_at_ms,
        &transport_result,
    );
    let transport = transport_result?;
    let (execution, transport) = match input.kind() {
        Ed25519YaoInputKindV1::Activation => {
            let role_request =
                open_ed25519_yao_activation_deriver_b_input_v1(&input, &private_key)?;
            let (root, root_metadata_digest) = load_deriver_b_yao_root_with_metadata_digest(
                env,
                runtime,
                &role_request.binding.lifecycle,
                trace_id,
            )
            .await?;
            validate_expected_root_metadata_digest(
                expected_root_metadata_digest,
                root_metadata_digest,
            )?;
            let recipients = role_request.recipients;
            let (binding, role) =
                build_product_activation_deriver_b_v1(root, role_request).map_err(map_adapter)?;
            let protocol_started_at_ms = role_span_started_at_ms();
            let completion_result =
                with_yao_ceremony_timeout(run_activation_deriver_b_open(role, transport)).await;
            emit_role_span_v1(
                trace_id,
                "deriver_b.yao_protocol",
                "deriver_b",
                "activation",
                protocol_started_at_ms,
                if completion_result.is_ok() {
                    "success"
                } else {
                    "failure"
                },
            );
            let completion = completion_result?;
            (
                seal_ed25519_yao_activation_deriver_b_execution_v1(
                    &mut CloudflareHpkeGetrandomRngV1,
                    binding,
                    recipients,
                    &completion.role,
                )?,
                completion.transport,
            )
        }
        Ed25519YaoInputKindV1::Export => {
            let role_request = open_ed25519_yao_export_deriver_b_input_v1(&input, &private_key)?;
            let (root, root_metadata_digest) = load_deriver_b_yao_root_with_metadata_digest(
                env,
                runtime,
                &role_request.binding.lifecycle,
                trace_id,
            )
            .await?;
            validate_expected_root_metadata_digest(
                expected_root_metadata_digest,
                root_metadata_digest,
            )?;
            let recipient = role_request.recipients;
            let (binding, role) =
                build_product_export_deriver_b_v1(root, role_request).map_err(map_adapter)?;
            let protocol_started_at_ms = role_span_started_at_ms();
            let completion_result =
                with_yao_ceremony_timeout(run_export_deriver_b_open(role, transport)).await;
            emit_role_span_v1(
                trace_id,
                "deriver_b.yao_protocol",
                "deriver_b",
                "export",
                protocol_started_at_ms,
                if completion_result.is_ok() {
                    "success"
                } else {
                    "failure"
                },
            );
            let completion = completion_result?;
            (
                seal_ed25519_yao_export_deriver_b_execution_v1(
                    &mut CloudflareHpkeGetrandomRngV1,
                    binding,
                    recipient,
                    &completion.role,
                )?,
                completion.transport,
            )
        }
        Ed25519YaoInputKindV1::LaneMaterialization => {
            let crate::CloudflareEd25519YaoPairWorkV1::Lane { job: expected_job } = &work else {
                return Err(invalid_lifecycle(
                    "Deriver B lane input is missing its admitted job",
                ));
            };
            let input_open_started_at_ms = role_span_started_at_ms();
            let role_request_result =
                open_ed25519_yao_lane_deriver_b_input_v1(&input, expected_job, &private_key);
            emit_role_stage_result_v1(
                trace_id,
                "deriver_b.input_open",
                "lane_materialization",
                input_open_started_at_ms,
                &role_request_result,
            );
            let role_request = role_request_result?;
            let lifecycle = role_request.binding.lifecycle.clone();
            let (root, root_metadata_digest) =
                load_deriver_b_yao_root_with_metadata_digest(env, runtime, &lifecycle, trace_id)
                    .await?;
            validate_expected_root_metadata_digest(
                expected_root_metadata_digest,
                root_metadata_digest,
            )?;
            let role_build_started_at_ms = role_span_started_at_ms();
            let role_build_result = build_product_lane_deriver_b_v1(
                root,
                role_request,
                &mut CloudflareHpkeGetrandomRngV1,
            );
            match &role_build_result {
                Ok(_) => emit_role_span_v1(
                    trace_id,
                    "deriver_b.role_build",
                    "deriver_b",
                    "lane_materialization",
                    role_build_started_at_ms,
                    "success",
                ),
                Err(error) => emit_role_adapter_error_v1(
                    trace_id,
                    "deriver_b.role_build",
                    "lane_materialization",
                    role_build_started_at_ms,
                    *error,
                ),
            }
            let role_build_result = role_build_result.map_err(map_adapter);
            let (binding, job, role) = role_build_result?;
            let session_check_result = if binding.session_id.into_bytes() == session {
                Ok(())
            } else {
                Err(invalid_lifecycle(
                    "Deriver B lane input does not match the pair session",
                ))
            };
            emit_role_stage_result_v1(
                trace_id,
                "deriver_b.session_check",
                "lane_materialization",
                role_build_started_at_ms,
                &session_check_result,
            );
            session_check_result?;
            let protocol_started_at_ms = role_span_started_at_ms();
            let completion_result =
                with_yao_ceremony_timeout(run_lane_materialization_deriver_b_open(role, transport))
                    .await;
            emit_role_span_v1(
                trace_id,
                "deriver_b.yao_protocol",
                "deriver_b",
                "lane_materialization",
                protocol_started_at_ms,
                if completion_result.is_ok() {
                    "success"
                } else {
                    "failure"
                },
            );
            let completion = completion_result?;
            let seal_started_at_ms = role_span_started_at_ms();
            let sealed_result = seal_ed25519_yao_lane_deriver_b_execution_v1(
                &mut CloudflareHpkeGetrandomRngV1,
                job,
                &completion.role,
            );
            emit_role_stage_result_v1(
                trace_id,
                "deriver_b.output_seal",
                "lane_materialization",
                seal_started_at_ms,
                &sealed_result,
            );
            (
                Ed25519YaoRoleExecutionV1::Lane(sealed_result?),
                completion.transport,
            )
        }
    };
    let serialization_started_at_ms = role_span_started_at_ms();
    let serialized_execution = serde_json::to_vec(&execution)
        .map_err(|_| invalid_lifecycle("Deriver B sealed execution could not be serialized"))?;
    emit_role_span_v1(
        trace_id,
        "deriver_b.output_serialization",
        "deriver_b",
        "yao",
        serialization_started_at_ms,
        "success",
    );
    execute_deriver_b_session_command(
        env,
        DeriverBYaoSessionCommandV1::CompletePair {
            pair_digest,
            execution: Box::new(execution),
        },
        trace_id,
    )
    .await?;
    transport
        .finish_with_local_sealed_completion(&serialized_execution)
        .await
        .map_err(map_websocket_error)?;
    Ok(())
}

async fn execute_deriver_b_session_command(
    env: &Env,
    command: DeriverBYaoSessionCommandV1,
    trace_id: RoleTraceContextV1,
) -> RouterAbProtocolResult<DeriverBYaoSessionResponseV1> {
    command.validate()?;
    let operation = command.operation();
    let started_at_ms = role_span_started_at_ms();
    let response_result = DeriverBYaoSessionD1V1::new(env.clone())
        .execute(command)
        .await
        .map_err(|error| {
            invalid_lifecycle(format!("Deriver B Yao session D1 command failed: {error}"))
        });
    let mut response = match response_result {
        Ok(response) => response,
        Err(error) => {
            emit_role_span_v1(
                trace_id,
                "deriver_b.session_d1",
                "deriver_b",
                operation,
                started_at_ms,
                "failure",
            );
            return Err(error);
        }
    };
    if !(200..=299).contains(&response.status_code()) {
        let status = response.status_code();
        emit_role_span_v1(
            trace_id,
            "deriver_b.session_d1",
            "deriver_b",
            operation,
            started_at_ms,
            "failure",
        );
        let message = response
            .text()
            .await
            .unwrap_or_else(|_| "response body unavailable".to_owned());
        return Err(invalid_lifecycle(format!(
            "Deriver B Yao session D1 command was rejected with HTTP {status}: {message}"
        )));
    }
    let result = response
        .json::<DeriverBYaoSessionResponseV1>()
        .await
        .map_err(|_| invalid_lifecycle("Deriver B Yao session response is malformed"));
    emit_role_span_v1(
        trace_id,
        "deriver_b.session_d1",
        "deriver_b",
        operation,
        started_at_ms,
        if result.is_ok() { "success" } else { "failure" },
    );
    result
}

async fn execute_deriver_a_pair_prepare(
    env: &Env,
    request: CloudflareEd25519YaoPairPrepareRequestV1,
    trace_id: RoleTraceContextV1,
) -> RouterAbProtocolResult<Ed25519YaoRoleReadinessReceiptV1> {
    let command = DeriverAYaoSessionCommandV1::PreparePair {
        pair_binding: request.pair_binding,
        work: request.work,
        input: request.input,
    };
    let mut response = execute_deriver_a_pair_command(env, command, trace_id).await?;
    response
        .json::<Ed25519YaoRoleReadinessReceiptV1>()
        .await
        .map_err(|_| invalid_lifecycle("Deriver A readiness receipt is malformed"))
}

async fn complete_deriver_a_pair(
    env: &Env,
    pair_digest: [u8; 32],
    execution_id: [u8; 32],
    execution: Ed25519YaoRoleExecutionV1,
    trace_id: RoleTraceContextV1,
) -> RouterAbProtocolResult<Ed25519YaoRoleExecutionV1> {
    let mut response = execute_deriver_a_pair_command(
        env,
        DeriverAYaoSessionCommandV1::CompletePair {
            pair_digest,
            execution_id,
            execution: Box::new(execution.clone()),
        },
        trace_id,
    )
    .await?;
    match response
        .json::<DeriverAYaoSessionResponseV1>()
        .await
        .map_err(|_| invalid_lifecycle("Deriver A pair completion response is malformed"))?
    {
        DeriverAYaoSessionResponseV1::Completed { execution } => Ok(*execution),
        DeriverAYaoSessionResponseV1::Burned { .. } => {
            Err(invalid_lifecycle("Deriver A pair execution was burned"))
        }
        DeriverAYaoSessionResponseV1::Started { .. } => Err(invalid_lifecycle(
            "Deriver A pair completion returned a start response",
        )),
    }
}

async fn confirm_deriver_a_pair_start(
    env: &Env,
    pair_binding: Ed25519YaoInputPairBindingV1,
    execution_id: Ed25519YaoExecutionIdV1,
    acceptance: Ed25519YaoRoleStartAcceptanceV1,
    local_receipt: Ed25519YaoRoleReadinessReceiptV1,
    peer_receipt: Ed25519YaoRoleReadinessReceiptV1,
    trace_id: RoleTraceContextV1,
) -> RouterAbProtocolResult<()> {
    if acceptance.root_metadata_digest().bytes != peer_receipt.root_metadata_digest().bytes {
        return Err(invalid_lifecycle(
            "Deriver B start acceptance root does not match its readiness receipt",
        ));
    }
    let mut response = execute_deriver_a_pair_command(
        env,
        DeriverAYaoSessionCommandV1::StartPair {
            pair_binding,
            execution_id,
            acceptance,
            local_receipt,
            peer_receipt,
        },
        trace_id,
    )
    .await?;
    match response
        .json::<DeriverAYaoSessionResponseV1>()
        .await
        .map_err(|_| invalid_lifecycle("Deriver A pair start response is malformed"))?
    {
        DeriverAYaoSessionResponseV1::Started { .. }
        | DeriverAYaoSessionResponseV1::Completed { .. } => Ok(()),
        DeriverAYaoSessionResponseV1::Burned { .. } => {
            Err(invalid_lifecycle("Deriver A pair start was burned"))
        }
    }
}

async fn execute_deriver_a_pair_command(
    env: &Env,
    command: DeriverAYaoSessionCommandV1,
    trace_id: RoleTraceContextV1,
) -> RouterAbProtocolResult<Response> {
    command.validate()?;
    let started_at_ms = role_span_started_at_ms();
    let mut response = DeriverAYaoSessionD1V1::new(env.clone())
        .execute(command)
        .await
        .map_err(|error| invalid_lifecycle(format!("Deriver A pair D1 command failed: {error}")))?;
    if !(200..=299).contains(&response.status_code()) {
        emit_role_span_v1(
            trace_id,
            "deriver_a.session_d1",
            "deriver_a",
            "pair",
            started_at_ms,
            "failure",
        );
        let message = response
            .text()
            .await
            .unwrap_or_else(|_| "response body unavailable".to_owned());
        return Err(invalid_lifecycle(format!(
            "Deriver A pair D1 command was rejected with HTTP {}: {message}",
            response.status_code()
        )));
    }
    emit_role_span_v1(
        trace_id,
        "deriver_a.session_d1",
        "deriver_a",
        "pair",
        started_at_ms,
        "success",
    );
    Ok(response)
}

async fn load_deriver_a_yao_root_metadata_digest(
    env: &Env,
    runtime: &CloudflareDeriverAWorkerRuntimeV1,
    lifecycle: &LifecycleScopeV1,
) -> RouterAbProtocolResult<[u8; 32]> {
    lifecycle.validate()?;
    let metadata = runtime.root_share_wire_secret().startup_metadata(
        lifecycle.signer_set_id.clone(),
        runtime.peer_signing_key().key_epoch.clone(),
        lifecycle.root_share_epoch.clone(),
    )?;
    load_yao_root_metadata_digest(
        env,
        CloudflareWorkerRoleV1::DeriverA,
        runtime.root_share_wire_secret(),
        metadata,
    )
    .await
}

async fn load_deriver_a_yao_root_with_metadata_digest(
    env: &Env,
    runtime: &CloudflareDeriverAWorkerRuntimeV1,
    lifecycle: &LifecycleScopeV1,
    trace_id: RoleTraceContextV1,
) -> RouterAbProtocolResult<([u8; 32], [u8; 32])> {
    lifecycle.validate()?;
    let metadata = runtime.root_share_wire_secret().startup_metadata(
        lifecycle.signer_set_id.clone(),
        runtime.peer_signing_key().key_epoch.clone(),
        lifecycle.root_share_epoch.clone(),
    )?;
    let started_at_ms = role_span_started_at_ms();
    let result = load_yao_root_with_metadata_digest(
        env,
        CloudflareWorkerRoleV1::DeriverA,
        runtime.root_share_wire_secret(),
        metadata,
        b"deriver-a",
    )
    .await;
    emit_role_span_v1(
        trace_id,
        "deriver_a.root_share",
        "deriver_a",
        "worker_secret",
        started_at_ms,
        if result.is_ok() { "success" } else { "failure" },
    );
    result
}

async fn load_deriver_b_yao_root_metadata_digest(
    env: &Env,
    runtime: &CloudflareDeriverBWorkerRuntimeV1,
    lifecycle: &LifecycleScopeV1,
) -> RouterAbProtocolResult<[u8; 32]> {
    lifecycle.validate()?;
    let metadata = runtime.root_share_wire_secret().startup_metadata(
        lifecycle.signer_set_id.clone(),
        runtime.peer_signing_key().key_epoch.clone(),
        lifecycle.root_share_epoch.clone(),
    )?;
    load_yao_root_metadata_digest(
        env,
        CloudflareWorkerRoleV1::DeriverB,
        runtime.root_share_wire_secret(),
        metadata,
    )
    .await
}

async fn load_deriver_b_yao_root_with_metadata_digest(
    env: &Env,
    runtime: &CloudflareDeriverBWorkerRuntimeV1,
    lifecycle: &LifecycleScopeV1,
    trace_id: RoleTraceContextV1,
) -> RouterAbProtocolResult<([u8; 32], [u8; 32])> {
    lifecycle.validate()?;
    let metadata = runtime.root_share_wire_secret().startup_metadata(
        lifecycle.signer_set_id.clone(),
        runtime.peer_signing_key().key_epoch.clone(),
        lifecycle.root_share_epoch.clone(),
    )?;
    let started_at_ms = role_span_started_at_ms();
    let result = load_yao_root_with_metadata_digest(
        env,
        CloudflareWorkerRoleV1::DeriverB,
        runtime.root_share_wire_secret(),
        metadata,
        b"deriver-b",
    )
    .await;
    emit_role_span_v1(
        trace_id,
        "deriver_b.root_share",
        "deriver_b",
        "worker_secret",
        started_at_ms,
        if result.is_ok() { "success" } else { "failure" },
    );
    result
}

/// Prepares the V2 role-target preface from the authenticated Deriver A share.
///
/// The returned state owns only A's local threshold-PRF partial. Its outbound
/// plaintext is the fixed B-target proof exposed by
/// [`Ed25519YaoDeriverAPrefaceInFlightV2::outbound_plaintext`].
pub(crate) fn prepare_cloudflare_ed25519_yao_deriver_a_target_v2(
    role_share: VerifiedTenantRootOnlineRoleShareV1,
    custody_binding: &TenantRootCustodyBindingV1,
    outer_binding: Ed25519YaoOuterBindingV2,
    stable_context: &Ed25519YaoStableKeyDerivationContextV1,
) -> RouterAbProtocolResult<Ed25519YaoDeriverAPrefaceInFlightV2> {
    validate_cloudflare_ed25519_yao_v2_binding(&outer_binding, custody_binding, stable_context)?;
    let (role_binding, share_wire) = role_share.into_parts();
    validate_cloudflare_ed25519_yao_v2_role_share(
        &role_binding,
        custody_binding,
        TwoPartyDeriverRole::DeriverA,
    )?;
    let share = share_wire
        .to_share()
        .map_err(map_cloudflare_ed25519_yao_v2_threshold_error)?;
    let expected_peer_commitment = SigningRootShareCommitment::from_slice(
        custody_binding.commitments().deriver_b().as_bytes(),
    )
    .map_err(map_cloudflare_ed25519_yao_v2_threshold_error)?;
    let stable_context_bytes = stable_context.encode();
    let mut rng = crate::CloudflareSignerProofGetrandomRngV1;
    let (prepared, outbound) = prepare_ed25519_deriver_a_target_v1(
        &share,
        expected_peer_commitment,
        &stable_context_bytes,
        &mut rng,
    )
    .map_err(map_cloudflare_ed25519_yao_v2_threshold_error)?;
    Ed25519YaoDeriverAPrefaceInFlightV2::new(outer_binding, prepared, outbound)
}

/// Completes the V2 Deriver A preface and feeds its target root into the
/// unchanged role-local contribution KDF.
pub(crate) fn complete_cloudflare_ed25519_yao_deriver_a_target_v2(
    preface: Ed25519YaoDeriverAPrefaceInFlightV2,
    incoming: &Ed25519YaoDeriverBToATargetProofPayloadV2,
    incoming_plaintext: &[u8],
    expected_outer_binding: &Ed25519YaoOuterBindingV2,
    stable_context: &Ed25519YaoStableKeyDerivationContextV1,
) -> RouterAbProtocolResult<Ed25519YaoDeriverAServerContributionV1> {
    let ready = preface
        .complete(incoming, incoming_plaintext)
        .map_err(|error| invalid_lifecycle(error.message()))?;
    if ready.binding() != expected_outer_binding
        || stable_context.binding_digest() != ready.binding().stable_context_binding().into_bytes()
    {
        return Err(invalid_lifecycle(
            "Ed25519 Yao V2 Deriver A completion binding does not match the stable context",
        ));
    }
    let target_root = ready.into_threshold_prf_root().into_secret_bytes();
    derive_ed25519_yao_deriver_a_server_contribution_v1(
        &Ed25519YaoDeriverADerivationRootV1::from_secret_bytes(*target_root),
        stable_context,
    )
    .map_err(|error| {
        invalid_lifecycle(format!(
            "Ed25519 Yao Deriver A contribution failed: {error}"
        ))
    })
}

/// Prepares the V2 role-target preface from the authenticated Deriver B share.
///
/// The returned state owns only B's local threshold-PRF partial. Its outbound
/// plaintext is the fixed A-target proof exposed by
/// [`Ed25519YaoDeriverBPrefaceInFlightV2::outbound_plaintext`].
pub(crate) fn prepare_cloudflare_ed25519_yao_deriver_b_target_v2(
    role_share: VerifiedTenantRootOnlineRoleShareV1,
    custody_binding: &TenantRootCustodyBindingV1,
    outer_binding: Ed25519YaoOuterBindingV2,
    stable_context: &Ed25519YaoStableKeyDerivationContextV1,
) -> RouterAbProtocolResult<Ed25519YaoDeriverBPrefaceInFlightV2> {
    validate_cloudflare_ed25519_yao_v2_binding(&outer_binding, custody_binding, stable_context)?;
    let (role_binding, share_wire) = role_share.into_parts();
    validate_cloudflare_ed25519_yao_v2_role_share(
        &role_binding,
        custody_binding,
        TwoPartyDeriverRole::DeriverB,
    )?;
    let share = share_wire
        .to_share()
        .map_err(map_cloudflare_ed25519_yao_v2_threshold_error)?;
    let expected_peer_commitment = SigningRootShareCommitment::from_slice(
        custody_binding.commitments().deriver_a().as_bytes(),
    )
    .map_err(map_cloudflare_ed25519_yao_v2_threshold_error)?;
    let stable_context_bytes = stable_context.encode();
    let mut rng = crate::CloudflareSignerProofGetrandomRngV1;
    let (prepared, outbound) = prepare_ed25519_deriver_b_target_v1(
        &share,
        expected_peer_commitment,
        &stable_context_bytes,
        &mut rng,
    )
    .map_err(map_cloudflare_ed25519_yao_v2_threshold_error)?;
    Ed25519YaoDeriverBPrefaceInFlightV2::new(outer_binding, prepared, outbound)
}

/// Completes the V2 Deriver B preface and feeds its target root into the
/// unchanged role-local contribution KDF.
pub(crate) fn complete_cloudflare_ed25519_yao_deriver_b_target_v2(
    preface: Ed25519YaoDeriverBPrefaceInFlightV2,
    incoming: &Ed25519YaoDeriverAToBTargetProofPayloadV2,
    incoming_plaintext: &[u8],
    expected_outer_binding: &Ed25519YaoOuterBindingV2,
    stable_context: &Ed25519YaoStableKeyDerivationContextV1,
) -> RouterAbProtocolResult<Ed25519YaoDeriverBServerContributionV1> {
    let ready = preface
        .complete(incoming, incoming_plaintext)
        .map_err(|error| invalid_lifecycle(error.message()))?;
    if ready.binding() != expected_outer_binding
        || stable_context.binding_digest() != ready.binding().stable_context_binding().into_bytes()
    {
        return Err(invalid_lifecycle(
            "Ed25519 Yao V2 Deriver B completion binding does not match the stable context",
        ));
    }
    let target_root = ready.into_threshold_prf_root().into_secret_bytes();
    derive_ed25519_yao_deriver_b_server_contribution_v1(
        &Ed25519YaoDeriverBDerivationRootV1::from_secret_bytes(*target_root),
        stable_context,
    )
    .map_err(|error| {
        invalid_lifecycle(format!(
            "Ed25519 Yao Deriver B contribution failed: {error}"
        ))
    })
}

fn validate_cloudflare_ed25519_yao_v2_binding(
    outer_binding: &Ed25519YaoOuterBindingV2,
    custody_binding: &TenantRootCustodyBindingV1,
    stable_context: &Ed25519YaoStableKeyDerivationContextV1,
) -> RouterAbProtocolResult<()> {
    outer_binding
        .validate_at(
            cloudflare_yao_now_unix_ms().map_err(|_| {
                invalid_lifecycle("Ed25519 Yao V2 outer binding clock is unavailable")
            })?,
        )
        .map_err(|error| invalid_lifecycle(error.message()))?;
    custody_binding
        .validate()
        .map_err(|error| invalid_lifecycle(error.message()))?;
    if stable_context.binding_digest() != outer_binding.stable_context_binding().into_bytes() {
        return Err(invalid_lifecycle(
            "Ed25519 Yao V2 outer binding does not match the stable context",
        ));
    }
    let custody_digest = custody_binding
        .digest()
        .map_err(|error| invalid_lifecycle(error.message()))?;
    if outer_binding.custody_binding_digest() != PublicDigest32::new(custody_digest.into_bytes()) {
        return Err(invalid_lifecycle(
            "Ed25519 Yao V2 outer binding does not match the custody binding",
        ));
    }
    Ok(())
}

fn validate_cloudflare_ed25519_yao_v2_role_share(
    role_binding: &router_ab_core::TenantRootOnlineRoleShareBindingV1,
    custody_binding: &TenantRootCustodyBindingV1,
    role: TwoPartyDeriverRole,
) -> RouterAbProtocolResult<()> {
    if role_binding.role() != role
        || role_binding.identity_digest() != custody_binding.identity_digest()
        || role_binding.custody_lineage() != custody_binding.custody_lineage()
        || role_binding.epoch() != custody_binding.epoch()
    {
        return Err(invalid_lifecycle(
            "Ed25519 Yao V2 role share does not match the custody binding",
        ));
    }
    let expected_commitment = match role {
        TwoPartyDeriverRole::DeriverA => custody_binding.commitments().deriver_a(),
        TwoPartyDeriverRole::DeriverB => custody_binding.commitments().deriver_b(),
    };
    if role_binding.share_commitment() != expected_commitment {
        return Err(invalid_lifecycle(
            "Ed25519 Yao V2 role share commitment does not match the custody binding",
        ));
    }
    Ok(())
}

fn map_cloudflare_ed25519_yao_v2_threshold_error(
    error: threshold_prf::ThresholdPrfError,
) -> RouterAbProtocolError {
    invalid_lifecycle(format!("Ed25519 Yao V2 target proof failed: {error}"))
}

async fn load_yao_root_metadata_digest(
    env: &Env,
    worker_role: CloudflareWorkerRoleV1,
    root_share_secret: &crate::CloudflareRootShareWireSecretBindingV1,
    metadata: crate::CloudflareRootShareStartupMetadataV1,
) -> RouterAbProtocolResult<[u8; 32]> {
    load_cloudflare_root_share_wire_secret_v1(env, worker_role, root_share_secret, &metadata)?;
    root_metadata_digest_v1(&metadata)
}

async fn load_yao_root_with_metadata_digest(
    env: &Env,
    worker_role: CloudflareWorkerRoleV1,
    root_share_secret: &crate::CloudflareRootShareWireSecretBindingV1,
    metadata: crate::CloudflareRootShareStartupMetadataV1,
    role_label: &[u8],
) -> RouterAbProtocolResult<([u8; 32], [u8; 32])> {
    let root_metadata_digest = root_metadata_digest_v1(&metadata)?;
    let wire =
        load_cloudflare_root_share_wire_secret_v1(env, worker_role, root_share_secret, &metadata)?;
    let signing_root_share_wire = wire.signing_root_share_wire();
    let mut hasher = Sha256::new();
    hasher.update(b"seams/router-ab/ed25519-yao/derivation-root/v1");
    hasher.update(role_label);
    hasher.update(signing_root_share_wire.as_bytes());
    Ok((hasher.finalize().into(), root_metadata_digest))
}

fn validate_expected_root_metadata_digest(
    expected: [u8; 32],
    actual: [u8; 32],
) -> RouterAbProtocolResult<()> {
    if expected != actual {
        return Err(invalid_lifecycle(
            "root-share metadata changed after pair preparation",
        ));
    }
    Ok(())
}

fn load_deriver_input_private_key(
    env: &Env,
    binding_name: &str,
) -> RouterAbProtocolResult<Ed25519YaoRecipientPrivateKeyV1> {
    let secret = env
        .secret(binding_name)
        .map_err(|_| invalid_lifecycle("Deriver input HPKE secret binding is missing"))?;
    let mut encoded = secret.to_string();
    let result = decode_cloudflare_signer_envelope_hpke_private_key_secret_v1(&encoded)
        .map(Ed25519YaoRecipientPrivateKeyV1::from_bytes);
    encoded.zeroize();
    result
}

fn circuit_for_input(input: &Ed25519YaoEncryptedInputV1) -> CloudflareEd25519YaoCircuitV1 {
    match input.kind() {
        Ed25519YaoInputKindV1::Activation => CloudflareEd25519YaoCircuitV1::Activation,
        Ed25519YaoInputKindV1::Export => CloudflareEd25519YaoCircuitV1::Export,
        Ed25519YaoInputKindV1::LaneMaterialization => {
            CloudflareEd25519YaoCircuitV1::LaneMaterialization
        }
    }
}

fn input_kind_for_circuit(family: Ed25519YaoCircuitFamilyV1) -> Ed25519YaoInputKindV1 {
    match family {
        Ed25519YaoCircuitFamilyV1::Activation => Ed25519YaoInputKindV1::Activation,
        Ed25519YaoCircuitFamilyV1::Export => Ed25519YaoInputKindV1::Export,
        Ed25519YaoCircuitFamilyV1::LaneMaterialization => {
            Ed25519YaoInputKindV1::LaneMaterialization
        }
    }
}

async fn parse_request<T>(request: &mut Request) -> RouterAbProtocolResult<T>
where
    T: serde::de::DeserializeOwned,
{
    request
        .json::<T>()
        .await
        .map_err(|_| invalid_lifecycle("Ed25519 Yao request JSON is malformed"))
}

fn json_response<T>(value: &T) -> RouterAbProtocolResult<Response>
where
    T: Serialize,
{
    Response::from_json(value)
        .map_err(|_| invalid_lifecycle("Ed25519 Yao response JSON could not be encoded"))
}

fn map_adapter(error: router_ab_ed25519_yao::AdapterError) -> RouterAbProtocolError {
    invalid_lifecycle(format!("Ed25519 Yao role construction failed: {error}"))
}

fn adapter_error_code_v1(error: AdapterError) -> &'static str {
    match error {
        AdapterError::InvalidDerivationContext => "invalid_derivation_context",
        AdapterError::CircuitFamilyMismatch => "circuit_family_mismatch",
        AdapterError::RoleProtocol => "role_protocol",
        AdapterError::LifecycleContributionMismatch => "lifecycle_contribution_mismatch",
        AdapterError::ServerContributionDerivation => "server_contribution_derivation",
    }
}

async fn with_yao_ceremony_timeout<T, E, F>(future: F) -> RouterAbProtocolResult<T>
where
    E: fmt::Display,
    F: Future<Output = Result<T, E>>,
{
    let execution = Box::pin(future);
    let timeout = Box::pin(Delay::from(YAO_CEREMONY_TIMEOUT));
    match select(execution, timeout).await {
        Either::Left((result, _)) => result.map_err(|error| {
            invalid_lifecycle(format!("Ed25519 Yao role execution failed: {error}"))
        }),
        Either::Right(_) => Err(invalid_lifecycle("Ed25519 Yao ceremony timed out")),
    }
}

fn map_websocket_error(_: crate::CloudflareEd25519YaoWebSocketErrorV1) -> RouterAbProtocolError {
    invalid_lifecycle("Ed25519 Yao Service Binding WebSocket failed")
}

fn invalid_lifecycle(message: impl Into<String>) -> RouterAbProtocolError {
    RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::InvalidLifecycleState,
        message.into(),
    )
}

fn cloudflare_yao_now_unix_ms() -> worker::Result<u64> {
    crate::cloudflare_now_unix_ms_v1()
        .map_err(|error| worker::Error::RustError(error.message().to_owned()))
}

fn yao_expiry_from_now(now_unix_ms: u64, lifetime_ms: u64) -> worker::Result<u64> {
    now_unix_ms
        .checked_add(lifetime_ms)
        .ok_or_else(|| worker::Error::RustError("Yao session expiry overflowed".into()))
}

fn validate_cloudflare_start_acceptance_v1(
    acceptance: &Ed25519YaoRoleStartAcceptanceV1,
    now_unix_ms: u64,
) -> RouterAbProtocolResult<()> {
    acceptance
        .validate_at_with_max_future_skew(now_unix_ms, YAO_START_ACCEPTANCE_MAX_FUTURE_SKEW_MS)
}

pub(crate) fn validate_cloudflare_role_readiness_receipt_v1(
    receipt: &Ed25519YaoRoleReadinessReceiptV1,
    now_unix_ms: u64,
) -> RouterAbProtocolResult<()> {
    receipt.validate_at_with_max_future_skew(now_unix_ms, YAO_READINESS_RECEIPT_MAX_FUTURE_SKEW_MS)
}

fn yao_input_digest(input: &Ed25519YaoEncryptedInputV1) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"seams/router-ab/ed25519-yao/session-input/v1");
    hasher.update([input.kind().wire_tag()]);
    hasher.update([input.deriver().wire_tag()]);
    hasher.update([match input.operation() {
        Ed25519YaoOperationV1::Registration => 1,
        Ed25519YaoOperationV1::Recovery => 2,
        Ed25519YaoOperationV1::Refresh => 3,
        Ed25519YaoOperationV1::Export => 4,
        Ed25519YaoOperationV1::LaneProvisioning => 5,
        Ed25519YaoOperationV1::LaneRefresh => 6,
    }]);
    hasher.update(input.session());
    hasher.update(input.stable_context_binding());
    hasher.update(input.encapsulated_key());
    hasher.update((input.ciphertext().len() as u64).to_be_bytes());
    hasher.update(input.ciphertext());
    hasher.finalize().into()
}

fn decode_hex_32(value: &str) -> RouterAbProtocolResult<[u8; 32]> {
    if value.len() != 64 {
        return Err(invalid_lifecycle("execution id header must be 32-byte hex"));
    }
    let mut bytes = [0_u8; 32];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = decode_hex_nibble(chunk[0])?;
        let low = decode_hex_nibble(chunk[1])?;
        bytes[index] = (high << 4) | low;
    }
    Ok(bytes)
}

fn decode_hex_nibble(byte: u8) -> RouterAbProtocolResult<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(invalid_lifecycle("execution id header must be hex")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CloudflareEd25519YaoRoleFailureResponseV1;
    use router_ab_core::{
        Ed25519YaoCeremonyBindingV1, Ed25519YaoEncryptedPackageV1, Ed25519YaoInputPairBindingV1,
        Ed25519YaoPackageKindV1, Ed25519YaoRoleReadinessReceiptV1, Ed25519YaoRoleSignatureSchemeV1,
        Ed25519YaoRoleSignatureV1, Ed25519YaoSessionIdV1, Ed25519YaoStableKeyContextBindingV1,
        ExpensiveWorkKindV1, LifecycleScopeV1, MpcMaterialActivationRefV1, PublicDigest32,
        RootShareEpoch, RouterEd25519YaoExecuteFailureCodeV1,
    };
    use router_ab_ed25519_yao::Ed25519YaoActivationRoleExecutionV1;

    fn encrypted_input(ciphertext_byte: u8) -> Ed25519YaoEncryptedInputV1 {
        Ed25519YaoEncryptedInputV1::new(
            Ed25519YaoInputKindV1::Activation,
            Ed25519YaoDeriverRoleV1::DeriverB,
            Ed25519YaoOperationV1::Registration,
            [1; 32],
            [2; 32],
            [3; 32],
            vec![ciphertext_byte; 16],
        )
        .expect("test input is valid")
    }

    fn pair_for_completion() -> (Ed25519YaoInputPairBindingV1, Ed25519YaoEncryptedInputV1) {
        let input_b = encrypted_input(4);
        let input_a = Ed25519YaoEncryptedInputV1::new(
            Ed25519YaoInputKindV1::Activation,
            Ed25519YaoDeriverRoleV1::DeriverA,
            Ed25519YaoOperationV1::Registration,
            [1; 32],
            [2; 32],
            [3; 32],
            vec![5; 16],
        )
        .expect("Deriver A input");
        let lifecycle = LifecycleScopeV1::new(
            "completion-test",
            ExpensiveWorkKindV1::RegistrationPrepare,
            RootShareEpoch::new("epoch").expect("epoch"),
            "account",
            "session",
            "signer-set",
            "server",
        )
        .expect("lifecycle");
        let binding = Ed25519YaoCeremonyBindingV1::new(
            lifecycle,
            Ed25519YaoOperationV1::Registration,
            Ed25519YaoSessionIdV1::new([1; 32]).expect("session"),
            Ed25519YaoStableKeyContextBindingV1::new([2; 32]),
            MpcMaterialActivationRefV1::new(
                "activation",
                "near-ed25519-yao",
                "account",
                "key-binding",
                "lifecycle-binding",
                "server",
            )
            .expect("material activation"),
        )
        .expect("binding");
        let pair = Ed25519YaoInputPairBindingV1::from_ceremony_binding(
            binding,
            &input_a,
            &input_b,
            PublicDigest32::new([13; 32]),
            PublicDigest32::new([14; 32]),
        )
        .expect("pair");
        (pair, input_a)
    }

    fn role_execution_for_pair(pair: &Ed25519YaoInputPairBindingV1) -> Ed25519YaoRoleExecutionV1 {
        let session = pair.session();
        let client_package = Ed25519YaoEncryptedPackageV1::new(
            Ed25519YaoPackageKindV1::ActivationClient,
            Ed25519YaoDeriverRoleV1::DeriverA,
            session,
            [4; 32],
            [5; 32],
            vec![6; 16],
        )
        .expect("client package");
        let signing_worker_package = Ed25519YaoEncryptedPackageV1::new(
            Ed25519YaoPackageKindV1::ActivationSigningWorker,
            Ed25519YaoDeriverRoleV1::DeriverA,
            session,
            [4; 32],
            [7; 32],
            vec![8; 16],
        )
        .expect("SigningWorker package");
        Ed25519YaoRoleExecutionV1::Activation(Ed25519YaoActivationRoleExecutionV1 {
            binding: pair.binding().clone(),
            deriver: Ed25519YaoDeriverRoleV1::DeriverA,
            transcript: [4; 32],
            client_commitment: [5; 32],
            signing_worker_commitment: [6; 32],
            client_package,
            signing_worker_package,
        })
    }

    #[test]
    fn session_input_digest_binds_the_exact_ciphertext() {
        let first = encrypted_input(4);
        let same = encrypted_input(4);
        let different = encrypted_input(5);

        assert_eq!(yao_input_digest(&first), yao_input_digest(&same));
        assert_ne!(yao_input_digest(&first), yao_input_digest(&different));
    }

    #[test]
    fn session_expiry_uses_checked_arithmetic() {
        assert_eq!(yao_expiry_from_now(10, 20).expect("expiry fits"), 30);
        assert!(yao_expiry_from_now(u64::MAX, 1).is_err());
    }

    #[test]
    fn cloudflare_readiness_receipt_allows_only_bounded_future_skew() {
        let receipt = Ed25519YaoRoleReadinessReceiptV1::new(
            Ed25519YaoDeriverRoleV1::DeriverB,
            Ed25519YaoSessionIdV1::new([1; 32]).expect("session"),
            PublicDigest32::new([2; 32]),
            PublicDigest32::new([3; 32]),
            PublicDigest32::new([4; 32]),
            10_000,
            30_000,
            Ed25519YaoRoleSignatureV1::new(Ed25519YaoRoleSignatureSchemeV1::Ed25519V1, [5; 64])
                .expect("signature"),
        )
        .expect("receipt");

        assert!(receipt.validate_at(9_999).is_err());
        validate_cloudflare_role_readiness_receipt_v1(&receipt, 9_000)
            .expect("maximum future skew is accepted");
        assert!(validate_cloudflare_role_readiness_receipt_v1(&receipt, 8_999).is_err());
        assert!(validate_cloudflare_role_readiness_receipt_v1(&receipt, 30_000).is_err());
    }

    #[test]
    fn cloudflare_start_acceptance_allows_only_bounded_future_skew() {
        let acceptance = Ed25519YaoRoleStartAcceptanceV1::new(
            Ed25519YaoDeriverRoleV1::DeriverB,
            Ed25519YaoSessionIdV1::new([1; 32]).expect("session"),
            PublicDigest32::new([2; 32]),
            Ed25519YaoExecutionIdV1::new([3; 32]).expect("execution"),
            PublicDigest32::new([4; 32]),
            10_000,
            30_000,
            Ed25519YaoRoleSignatureV1::new(Ed25519YaoRoleSignatureSchemeV1::Ed25519V1, [5; 64])
                .expect("signature"),
        )
        .expect("acceptance");

        validate_cloudflare_start_acceptance_v1(&acceptance, 9_000)
            .expect("maximum future skew is accepted");
        assert!(validate_cloudflare_start_acceptance_v1(&acceptance, 8_999).is_err());
        assert!(validate_cloudflare_start_acceptance_v1(&acceptance, 30_000).is_err());
    }

    #[test]
    fn role_failure_mapping_preserves_only_sanitized_retry_class() {
        let expired = CloudflareEd25519YaoRoleFailureResponseV1::from_protocol_error(
            &RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::PairPreparationExpired,
                "diagnostic text is not part of the classification contract",
            ),
        );
        assert_eq!(
            expired,
            CloudflareEd25519YaoRoleFailureResponseV1::RecoverableFailure {
                code: RouterEd25519YaoExecuteFailureCodeV1::CeremonyExpired,
                retry_after_ms: 1_000,
            }
        );

        let missing = CloudflareEd25519YaoRoleFailureResponseV1::from_protocol_error(
            &RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MissingPairPreparation,
                "diagnostic text is not part of the classification contract",
            ),
        );
        assert_eq!(
            missing,
            CloudflareEd25519YaoRoleFailureResponseV1::Rejected {
                code: RouterEd25519YaoExecuteFailureCodeV1::MissingPreparation,
            }
        );

        let conflicting = CloudflareEd25519YaoRoleFailureResponseV1::from_protocol_error(
            &RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ConflictingPair,
                "the diagnostic is not part of the classification contract",
            ),
        );
        assert_eq!(
            conflicting,
            CloudflareEd25519YaoRoleFailureResponseV1::Rejected {
                code: RouterEd25519YaoExecuteFailureCodeV1::ConflictingPair,
            }
        );

        let untyped_conflict = CloudflareEd25519YaoRoleFailureResponseV1::from_protocol_error(
            &RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLifecycleState,
                "Deriver B pair is already running",
            ),
        );
        assert_eq!(
            untyped_conflict,
            CloudflareEd25519YaoRoleFailureResponseV1::Rejected {
                code: RouterEd25519YaoExecuteFailureCodeV1::TerminalRoleFailure,
            }
        );
    }

    #[test]
    fn pair_completion_transition_is_forward_only() {
        let (pair, input) = pair_for_completion();
        let input_digest = yao_input_digest(&input);
        let pair_digest = [9; 32];
        let execution_id = [10; 32];
        let execution = role_execution_for_pair(&pair);
        let running = PairYaoSessionRecordV1::Running {
            pair_digest,
            input_digest,
            root_metadata_digest: [15; 32],
            execution_id,
            started_at_ms: 100,
            input: Box::new(input),
            work: crate::CloudflareEd25519YaoPairWorkV1::Ceremony,
        };
        let completed = completed_pair_record_if_running(
            &running,
            pair_digest,
            PairCompletionExpectation::DeriverA { execution_id },
            &execution,
            101,
        )
        .expect("running pair completes before its deadline");
        assert!(matches!(
            completed,
            PairYaoSessionRecordV1::Completed { .. }
        ));
        assert!(
            completed_pair_record_if_running(
                &completed,
                pair_digest,
                PairCompletionExpectation::DeriverA { execution_id },
                &execution,
                102,
            )
            .is_none(),
            "an exact completion replay cannot rewrite a terminal record"
        );
        assert!(matches!(
            completed_pair_record_if_running(
                &running,
                pair_digest,
                PairCompletionExpectation::DeriverA { execution_id },
                &execution,
                100 + YAO_RUNNING_LIFETIME_MS,
            ),
            Some(PairYaoSessionRecordV1::Burned { .. })
        ));
        let burned = PairYaoSessionRecordV1::Burned {
            pair_digest,
            input_digest,
            execution_id,
        };
        assert!(completed_pair_record_if_running(
            &burned,
            pair_digest,
            PairCompletionExpectation::DeriverA { execution_id },
            &execution,
            101,
        )
        .is_none());
        assert!(completed_pair_record_if_running(
            &running,
            pair_digest,
            PairCompletionExpectation::DeriverA {
                execution_id: [16; 32],
            },
            &execution,
            101,
        )
        .is_none());
        assert!(completed_pair_record_if_running(
            &running,
            pair_digest,
            PairCompletionExpectation::DeriverB {
                input_digest: [17; 32],
            },
            &execution,
            101,
        )
        .is_none());
    }

    #[test]
    fn readiness_receipts_enforce_pair_identity_and_lifetime() {
        let (pair, _) = pair_for_completion();
        let receipt = Ed25519YaoRoleReadinessReceiptV1::new(
            Ed25519YaoDeriverRoleV1::DeriverA,
            Ed25519YaoSessionIdV1::new(pair.session()).expect("session"),
            pair.pair_digest(),
            pair.deriver_a_input_digest(),
            PublicDigest32::new([15; 32]),
            100,
            200,
            Ed25519YaoRoleSignatureV1::new(Ed25519YaoRoleSignatureSchemeV1::Ed25519V1, [1; 64])
                .expect("signature"),
        )
        .expect("receipt");

        receipt
            .validate_for_pair(&pair)
            .expect("receipt belongs to the exact pair");
        receipt
            .validate_at(100)
            .expect("receipt starts at issuance");
        assert!(receipt.validate_at(99).is_err());
        assert!(receipt.validate_at(200).is_err());

        let wrong_pair = Ed25519YaoInputPairBindingV1::new(
            pair.ceremony().clone(),
            pair.deriver_a_input_digest(),
            pair.deriver_b_input_digest(),
            PublicDigest32::new([16; 32]),
            pair.authorization_digest(),
        )
        .expect("alternate pair");
        assert!(receipt.validate_for_pair(&wrong_pair).is_err());
    }
}
