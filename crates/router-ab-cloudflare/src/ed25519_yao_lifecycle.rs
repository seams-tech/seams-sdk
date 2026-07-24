use core::{fmt, future::Future};
use std::time::Duration;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use futures::future::{select, Either};
use router_ab_core::{
    ed25519_yao_encrypted_input_digest_v1, Ed25519YaoCircuitFamilyV1, Ed25519YaoDeriverRoleV1,
    Ed25519YaoEncryptedInputV1, Ed25519YaoInputKindV1, Ed25519YaoInputPairBindingV1,
    Ed25519YaoOperationV1, Ed25519YaoRoleReadinessReceiptV1, Ed25519YaoRoleSignatureSchemeV1,
    Ed25519YaoSessionIdV1, LifecycleScopeV1, PublicDigest32, RouterAbProtocolError,
    RouterAbProtocolErrorCode, RouterAbProtocolResult,
};
use router_ab_ed25519_yao::{
    build_product_activation_deriver_a_v1, build_product_activation_deriver_b_v1,
    build_product_export_deriver_a_v1, build_product_export_deriver_b_v1,
    duplex::{
        run_activation_deriver_a, run_activation_deriver_b, run_export_deriver_a,
        run_export_deriver_b,
    },
    open_ed25519_yao_activation_deriver_a_input_v1, open_ed25519_yao_activation_deriver_b_input_v1,
    open_ed25519_yao_export_deriver_a_input_v1, open_ed25519_yao_export_deriver_b_input_v1,
    seal_ed25519_yao_activation_deriver_a_execution_v1,
    seal_ed25519_yao_activation_deriver_b_execution_v1,
    seal_ed25519_yao_export_deriver_a_execution_v1, seal_ed25519_yao_export_deriver_b_execution_v1,
    Ed25519YaoRecipientPrivateKeyV1, Ed25519YaoRoleExecutionV1,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use worker::{Context, Delay, Env, Method, Request, Response, State, WebSocketPair};
use zeroize::Zeroize;

use crate::{
    decode_cloudflare_signer_envelope_hpke_private_key_secret_v1,
    execute_cloudflare_durable_object_call_v1, load_cloudflare_root_share_wire_secret_v1,
    parse_cloudflare_trace_id_from_request_v1, set_cloudflare_trace_id_header_v1,
    CloudflareDeriverAWorkerRuntimeV1, CloudflareDeriverBWorkerRuntimeV1,
    CloudflareDurableObjectResponseV1, CloudflareEd25519YaoCircuitV1,
    CloudflareEd25519YaoWebSocketBindingV1, CloudflareEd25519YaoWebSocketTransportV1,
    CloudflareHpkeGetrandomRngV1, CloudflareSignerPeerVerifyingKeySetV1, CloudflareTraceIdV1,
    CloudflareWorkerRoleV1,
};

pub const CLOUDFLARE_DERIVER_A_ED25519_YAO_ACTIVATION_START_PATH: &str =
    "/router-ab/deriver-a/ed25519-yao/activation/start";
pub const CLOUDFLARE_DERIVER_A_ED25519_YAO_EXPORT_START_PATH: &str =
    "/router-ab/deriver-a/ed25519-yao/export/start";
pub const CLOUDFLARE_DERIVER_B_ED25519_YAO_ACTIVATION_STAGE_PATH: &str =
    "/router-ab/deriver-b/ed25519-yao/activation/stage";
pub const CLOUDFLARE_DERIVER_B_ED25519_YAO_ACTIVATION_RESULT_PATH: &str =
    "/router-ab/deriver-b/ed25519-yao/activation/result";
pub const CLOUDFLARE_DERIVER_B_ED25519_YAO_EXPORT_STAGE_PATH: &str =
    "/router-ab/deriver-b/ed25519-yao/export/stage";
pub const CLOUDFLARE_DERIVER_B_ED25519_YAO_EXPORT_RESULT_PATH: &str =
    "/router-ab/deriver-b/ed25519-yao/export/result";
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
pub const CLOUDFLARE_DERIVER_B_ED25519_YAO_READ_COMPLETED_PAIR_PATH: &str =
    "/router-ab/deriver-b/ed25519-yao/read-completed-pair";
pub const CLOUDFLARE_DERIVER_B_ED25519_YAO_READ_PAIR_STATUS_PATH: &str =
    "/router-ab/deriver-b/ed25519-yao/read-pair-status";
pub const CLOUDFLARE_DERIVER_B_ED25519_YAO_BURN_PAIR_PATH: &str =
    "/router-ab/deriver-b/ed25519-yao/burn-pair";

const DERIVER_A_YAO_SESSION_DO_BINDING: &str = "DERIVER_A_YAO_SESSION_DO";
const DERIVER_A_YAO_SESSION_DO_URL: &str = "https://deriver-a-yao-session.internal/execute";
const DERIVER_B_YAO_SESSION_DO_BINDING: &str = "DERIVER_B_YAO_SESSION_DO";
const DERIVER_B_YAO_SESSION_DO_URL: &str = "https://deriver-b-yao-session.internal/command";
const SESSION_RECORD_STORAGE_KEY: &str = "session-record-v1";
const PAIR_SESSION_RECORD_STORAGE_KEY: &str = "pair-session-record-v1";
const YAO_CEREMONY_TIMEOUT: Duration = Duration::from_secs(15);
const YAO_STAGED_INPUT_LIFETIME_MS: u64 = 60_000;
const YAO_RUNNING_LIFETIME_MS: u64 = 20_000;
const YAO_RESULT_WAIT_INTERVAL: Duration = Duration::from_millis(5);
const YAO_RESULT_WAIT_ATTEMPTS: usize = 100;
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
    let ended_at_ms = cloudflare_yao_now_unix_ms().unwrap_or(started_at_ms);
    let event = RoleSpanEventV1 {
        event: ROLE_SPAN_EVENT_V1,
        span,
        role,
        operation,
        outcome,
        duration_ms: ended_at_ms.saturating_sub(started_at_ms),
        trace_id: trace_id.map(CloudflareTraceIdV1::as_hex),
    };
    if let Ok(serialized) = serde_json::to_string(&event) {
        worker::console_log!("{serialized}");
    }
}

fn role_span_started_at_ms() -> u64 {
    cloudflare_yao_now_unix_ms().unwrap_or_default()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum YaoSessionRecordV1 {
    Staged {
        input_digest: [u8; 32],
        expires_at_ms: u64,
        input: Box<Ed25519YaoEncryptedInputV1>,
    },
    Running {
        input_digest: [u8; 32],
        expires_at_ms: u64,
    },
    Completed {
        input_digest: [u8; 32],
        execution: Box<Ed25519YaoRoleExecutionV1>,
    },
    Failed {
        input_digest: [u8; 32],
    },
    Expired {
        input_digest: [u8; 32],
    },
}

impl YaoSessionRecordV1 {
    fn input_digest(&self) -> [u8; 32] {
        match self {
            Self::Staged { input_digest, .. }
            | Self::Running { input_digest, .. }
            | Self::Completed { input_digest, .. }
            | Self::Failed { input_digest }
            | Self::Expired { input_digest } => *input_digest,
        }
    }
}

/// Pair-bound role state used by the Router-owned lifecycle. Existing request
/// records remain separate during the boundary migration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum PairYaoSessionRecordV1 {
    Prepared {
        pair_digest: [u8; 32],
        input_digest: [u8; 32],
        root_metadata_digest: [u8; 32],
        expires_at_ms: u64,
        input: Box<Ed25519YaoEncryptedInputV1>,
        receipt: Box<Ed25519YaoRoleReadinessReceiptV1>,
    },
    Running {
        pair_digest: [u8; 32],
        input_digest: [u8; 32],
        root_metadata_digest: [u8; 32],
        execution_id: [u8; 32],
        started_at_ms: u64,
        input: Box<Ed25519YaoEncryptedInputV1>,
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

/// Computes the only valid completion transition for a pair-bound role.
///
/// The caller supplies the identity observed before entering the storage
/// transaction. A's claim/complete path adds its execution id; B's completion
/// path adds the input digest from its initial running-state read.
fn completed_pair_record_if_running(
    current: &PairYaoSessionRecordV1,
    pair_digest: [u8; 32],
    expected_input_digest: Option<[u8; 32]>,
    expected_execution_id: Option<[u8; 32]>,
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
    } = current
    else {
        return None;
    };
    if *stored_pair != pair_digest
        || expected_input_digest.is_some_and(|expected| expected != *input_digest)
        || expected_execution_id.is_some_and(|expected| expected != *execution_id)
        || execution.session() != input.session()
    {
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
    storage: &worker::Storage,
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
    storage: &worker::Storage,
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

/// Exact pair and role envelope sent to one private prepare-pair route.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareEd25519YaoPairPrepareRequestV1 {
    pub pair_binding: Ed25519YaoInputPairBindingV1,
    pub input: Ed25519YaoEncryptedInputV1,
}

/// Exact pair and peer receipt sent to the A execute-pair route.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareEd25519YaoPairExecuteRequestV1 {
    pub pair_binding: Ed25519YaoInputPairBindingV1,
    pub peer_receipt: Ed25519YaoRoleReadinessReceiptV1,
}

/// Exact pair lookup sent to the B completed-result route.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareEd25519YaoReadCompletedPairRequestV1 {
    pub session: [u8; 32],
    pub pair_digest: [u8; 32],
}

/// The B role's completed-result read is an explicit acknowledgement that its
/// pair state committed the exact role execution before the Router consumes it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case", deny_unknown_fields)]
pub enum CloudflareEd25519YaoPairCompletionAcknowledgementV1 {
    Completed {
        session: [u8; 32],
        pair_digest: [u8; 32],
        execution: Box<Ed25519YaoRoleExecutionV1>,
    },
}

impl CloudflareEd25519YaoPairCompletionAcknowledgementV1 {
    pub(crate) fn validate_for_request(
        &self,
        request: &CloudflareEd25519YaoReadCompletedPairRequestV1,
    ) -> RouterAbProtocolResult<Ed25519YaoRoleExecutionV1> {
        let Self::Completed {
            session,
            pair_digest,
            execution,
        } = self;
        if *session != request.session || *pair_digest != request.pair_digest {
            return Err(invalid_lifecycle(
                "Deriver B completion acknowledgement identity is invalid",
            ));
        }
        execution.validate()?;
        if execution.deriver() != Ed25519YaoDeriverRoleV1::DeriverB
            || execution.session() != request.session
        {
            return Err(invalid_lifecycle(
                "Deriver B completion acknowledgement execution is invalid",
            ));
        }
        Ok((**execution).clone())
    }
}

/// Sanitized role-local state returned only to the MPC Router for exact replay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum CloudflareEd25519YaoPairStatusResponseV1 {
    Missing {
        session: [u8; 32],
        pair_digest: [u8; 32],
    },
    Prepared {
        session: [u8; 32],
        pair_digest: [u8; 32],
    },
    Running {
        session: [u8; 32],
        pair_digest: [u8; 32],
    },
    Completed {
        execution: Box<Ed25519YaoRoleExecutionV1>,
    },
    Burned {
        session: [u8; 32],
        pair_digest: [u8; 32],
    },
    Expired {
        session: [u8; 32],
        pair_digest: [u8; 32],
    },
}

impl CloudflareEd25519YaoPairPrepareRequestV1 {
    fn validate_for_role(
        &self,
        role: Ed25519YaoDeriverRoleV1,
        expected_kind: Ed25519YaoInputKindV1,
    ) -> RouterAbProtocolResult<([u8; 32], [u8; 32])> {
        self.pair_binding.validate()?;
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
        self.peer_receipt.validate_for_pair(&self.pair_binding)?;
        if self.peer_receipt.role() != Ed25519YaoDeriverRoleV1::DeriverB {
            return Err(invalid_lifecycle(
                "Deriver A execute-pair requires a Deriver B readiness receipt",
            ));
        }
        Ok(())
    }
}

impl CloudflareEd25519YaoReadCompletedPairRequestV1 {
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
    Execute {
        input: Ed25519YaoEncryptedInputV1,
    },
    PreparePair {
        pair_binding: Ed25519YaoInputPairBindingV1,
        input: Ed25519YaoEncryptedInputV1,
    },
    ClaimPair {
        pair_binding: Ed25519YaoInputPairBindingV1,
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
            Self::Execute { input } => {
                input.validate()?;
                if input.deriver() != Ed25519YaoDeriverRoleV1::DeriverA {
                    return Err(invalid_lifecycle(
                        "Deriver A session storage accepts only Deriver A input",
                    ));
                }
            }
            Self::PreparePair {
                pair_binding,
                input,
            } => {
                let expected_kind = input_kind_for_circuit(pair_binding.binding().circuit_family());
                CloudflareEd25519YaoPairPrepareRequestV1 {
                    pair_binding: pair_binding.clone(),
                    input: input.clone(),
                }
                .validate_for_role(Ed25519YaoDeriverRoleV1::DeriverA, expected_kind)?;
            }
            Self::ClaimPair {
                pair_binding,
                peer_receipt,
            } => {
                CloudflareEd25519YaoPairExecuteRequestV1 {
                    pair_binding: pair_binding.clone(),
                    peer_receipt: peer_receipt.clone(),
                }
                .validate()?;
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
    PairClaimed {
        session: [u8; 32],
        pair_digest: [u8; 32],
        execution_id: [u8; 32],
        root_metadata_digest: [u8; 32],
        input: Box<Ed25519YaoEncryptedInputV1>,
        receipt: Box<Ed25519YaoRoleReadinessReceiptV1>,
    },
    PairCompleted {
        execution: Box<Ed25519YaoRoleExecutionV1>,
    },
    PairBurned {
        session: [u8; 32],
        pair_digest: [u8; 32],
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "family", rename_all = "snake_case", deny_unknown_fields)]
pub enum CloudflareEd25519YaoResultRequestV1 {
    Activation { session_id: [u8; 32] },
    Export { session_id: [u8; 32] },
}

impl CloudflareEd25519YaoResultRequestV1 {
    fn session_id(self) -> [u8; 32] {
        match self {
            Self::Activation { session_id } | Self::Export { session_id } => session_id,
        }
    }

    fn input_kind(&self) -> Ed25519YaoInputKindV1 {
        match self {
            Self::Activation { .. } => Ed25519YaoInputKindV1::Activation,
            Self::Export { .. } => Ed25519YaoInputKindV1::Export,
        }
    }

    fn validate(&self) -> RouterAbProtocolResult<()> {
        let session_id = match self {
            Self::Activation { session_id } | Self::Export { session_id } => session_id,
        };
        if session_id.iter().all(|byte| *byte == 0) {
            return Err(invalid_lifecycle("Ed25519 Yao session must be nonzero"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
enum DeriverBYaoSessionCommandV1 {
    Stage {
        input: Box<Ed25519YaoEncryptedInputV1>,
    },
    ReadStaged {
        session: [u8; 32],
    },
    Begin {
        session: [u8; 32],
    },
    Complete {
        execution: Box<Ed25519YaoRoleExecutionV1>,
    },
    Fail {
        session: [u8; 32],
    },
    ReadResult {
        session: [u8; 32],
    },
    PreparePair {
        pair_binding: Ed25519YaoInputPairBindingV1,
        input: Box<Ed25519YaoEncryptedInputV1>,
    },
    ReadPairPrepared {
        session: [u8; 32],
        pair_digest: [u8; 32],
    },
    BeginPair {
        session: [u8; 32],
        pair_digest: [u8; 32],
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
    ReadCompletedPair {
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
            Self::Stage { .. } => "stage",
            Self::ReadStaged { .. } => "read_staged",
            Self::Begin { .. } => "begin",
            Self::Complete { .. } => "complete",
            Self::Fail { .. } => "fail",
            Self::ReadResult { .. } => "read_result",
            Self::PreparePair { .. } => "prepare_pair",
            Self::ReadPairPrepared { .. } => "read_pair_prepared",
            Self::BeginPair { .. } => "begin_pair",
            Self::CompletePair { .. } => "complete_pair",
            Self::FailPair { .. } => "fail_pair",
            Self::ReadCompletedPair { .. } => "read_completed_pair",
            Self::ReadPairStatus { .. } => "read_pair_status",
        }
    }

    fn session(&self) -> [u8; 32] {
        match self {
            Self::Stage { input } => input.session(),
            Self::ReadStaged { session }
            | Self::Begin { session }
            | Self::Fail { session }
            | Self::ReadResult { session } => *session,
            Self::Complete { execution } => execution.session(),
            Self::PreparePair { input, .. } => input.session(),
            Self::ReadPairPrepared { session, .. }
            | Self::BeginPair { session, .. }
            | Self::FailPair { session, .. }
            | Self::ReadCompletedPair { session, .. } => *session,
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
            Self::Stage { input } => {
                input.validate()?;
                if input.deriver() != Ed25519YaoDeriverRoleV1::DeriverB {
                    return Err(invalid_lifecycle(
                        "Deriver B session storage accepts only Deriver B input",
                    ));
                }
            }
            Self::Complete { execution } => {
                execution.validate()?;
                if execution.deriver() != Ed25519YaoDeriverRoleV1::DeriverB {
                    return Err(invalid_lifecycle(
                        "Deriver B session storage accepts only Deriver B execution",
                    ));
                }
            }
            Self::PreparePair {
                pair_binding,
                input,
            } => {
                let expected_kind = input_kind_for_circuit(pair_binding.binding().circuit_family());
                CloudflareEd25519YaoPairPrepareRequestV1 {
                    pair_binding: pair_binding.clone(),
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
            Self::ReadPairPrepared { pair_digest, .. }
            | Self::BeginPair { pair_digest, .. }
            | Self::FailPair { pair_digest, .. }
            | Self::ReadCompletedPair { pair_digest, .. }
            | Self::ReadPairStatus { pair_digest, .. } => {
                if pair_digest.iter().all(|byte| *byte == 0) {
                    return Err(invalid_lifecycle("pair digest must be nonzero"));
                }
            }
            Self::ReadStaged { .. }
            | Self::Begin { .. }
            | Self::Fail { .. }
            | Self::ReadResult { .. } => {}
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
enum DeriverBYaoSessionResponseV1 {
    Staged {
        session: [u8; 32],
    },
    StagedInput {
        input: Box<Ed25519YaoEncryptedInputV1>,
    },
    Running {
        session: [u8; 32],
    },
    Completed {
        session: [u8; 32],
    },
    Pending {
        session: [u8; 32],
    },
    Failed {
        session: [u8; 32],
    },
    Expired {
        session: [u8; 32],
    },
    RoleExecution {
        execution: Box<Ed25519YaoRoleExecutionV1>,
    },
    PairPrepared {
        session: [u8; 32],
        pair_digest: [u8; 32],
        root_metadata_digest: [u8; 32],
        input: Box<Ed25519YaoEncryptedInputV1>,
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
        .verify(receipt.signed_message_digest().as_bytes(), &signature)
        .map_err(|_| invalid_lifecycle("readiness receipt signature is invalid"))
}

#[worker::durable_object(fetch)]
pub struct RouterAbDeriverAYaoSessionDurableObject {
    state: State,
    env: Env,
}

impl worker::DurableObject for RouterAbDeriverAYaoSessionDurableObject {
    fn new(state: State, env: Env) -> Self {
        Self { state, env }
    }

    async fn fetch(&self, mut request: Request) -> worker::Result<Response> {
        if request.method() != Method::Post {
            return Response::error("method not allowed", 405);
        }
        let trace_id = parse_role_trace_context(&request)?;
        let command = request.json::<DeriverAYaoSessionCommandV1>().await?;
        if let Err(error) = command.validate() {
            return Response::error(error.message(), 400);
        }
        match &command {
            DeriverAYaoSessionCommandV1::PreparePair { .. } => {
                return self.handle_prepare_pair(command).await;
            }
            DeriverAYaoSessionCommandV1::ClaimPair { .. } => {
                return self.handle_claim_pair(command).await;
            }
            DeriverAYaoSessionCommandV1::CompletePair { .. } => {
                return self.handle_complete_pair(command).await;
            }
            DeriverAYaoSessionCommandV1::ReadPairStatus {
                session,
                pair_digest,
            } => {
                return self.handle_read_pair_status(*session, *pair_digest).await;
            }
            DeriverAYaoSessionCommandV1::BurnPair {
                session,
                pair_digest,
            } => {
                return self.handle_burn_pair(*session, *pair_digest).await;
            }
            DeriverAYaoSessionCommandV1::Execute { .. } => {}
        }
        let DeriverAYaoSessionCommandV1::Execute { input } = command else {
            unreachable!("pair commands are handled before the legacy command path")
        };
        let storage = self.state.storage();
        if storage
            .get::<PairYaoSessionRecordV1>(PAIR_SESSION_RECORD_STORAGE_KEY)
            .await?
            .is_some()
        {
            return Response::error(
                "Deriver A pair lifecycle owns this session; legacy execution is closed",
                409,
            );
        }
        let now_unix_ms = cloudflare_yao_now_unix_ms()?;
        let input_digest = yao_input_digest(&input);
        let existing = storage
            .get::<YaoSessionRecordV1>(SESSION_RECORD_STORAGE_KEY)
            .await?;
        match existing {
            Some(YaoSessionRecordV1::Completed {
                input_digest: existing_digest,
                execution,
            }) if existing_digest == input_digest => return Response::from_json(&execution),
            Some(record) if record.input_digest() != input_digest => {
                return Response::error("conflicting Deriver A session input", 409);
            }
            Some(YaoSessionRecordV1::Running { expires_at_ms, .. })
                if now_unix_ms >= expires_at_ms =>
            {
                storage
                    .put(
                        SESSION_RECORD_STORAGE_KEY,
                        YaoSessionRecordV1::Expired { input_digest },
                    )
                    .await?;
                return Response::error("Deriver A session expired", 409);
            }
            Some(YaoSessionRecordV1::Running { .. }) => {
                return Response::error(
                    "Deriver A session is already running and cannot be re-evaluated",
                    409,
                );
            }
            Some(YaoSessionRecordV1::Failed { .. }) => {
                return Response::error("Deriver A session failed", 409);
            }
            Some(YaoSessionRecordV1::Expired { .. }) => {
                return Response::error("Deriver A session expired", 409);
            }
            Some(YaoSessionRecordV1::Staged { .. })
            | Some(YaoSessionRecordV1::Completed { .. }) => {
                return Response::error("Deriver A session state is invalid", 409);
            }
            None => {}
        }
        let expires_at_ms = yao_expiry_from_now(now_unix_ms, YAO_RUNNING_LIFETIME_MS)?;
        storage
            .put(
                SESSION_RECORD_STORAGE_KEY,
                YaoSessionRecordV1::Running {
                    input_digest,
                    expires_at_ms,
                },
            )
            .await?;
        let runtime = match CloudflareDeriverAWorkerRuntimeV1::from_worker_env(&self.env) {
            Ok(runtime) => runtime,
            Err(error) => {
                storage
                    .put(
                        SESSION_RECORD_STORAGE_KEY,
                        YaoSessionRecordV1::Failed { input_digest },
                    )
                    .await?;
                return Response::error(error.message(), 500);
            }
        };
        let role_started_at_ms = role_span_started_at_ms();
        let execution = match execute_deriver_a_role(
            &self.env, &runtime, input, trace_id, None, None, None, None,
        )
        .await
        {
            Ok(execution) => execution,
            Err(error) => {
                emit_role_span_v1(
                    trace_id,
                    "deriver_a.role_execution",
                    "deriver_a",
                    "yao",
                    role_started_at_ms,
                    "failure",
                );
                let current = storage
                    .get::<YaoSessionRecordV1>(SESSION_RECORD_STORAGE_KEY)
                    .await?;
                if matches!(
                    current,
                    Some(YaoSessionRecordV1::Running {
                        input_digest: current_digest,
                        ..
                    }) if current_digest == input_digest
                ) {
                    storage
                        .put(
                            SESSION_RECORD_STORAGE_KEY,
                            YaoSessionRecordV1::Failed { input_digest },
                        )
                        .await?;
                }
                return Response::error(error.message(), 500);
            }
        };
        emit_role_span_v1(
            trace_id,
            "deriver_a.role_execution",
            "deriver_a",
            "yao",
            role_started_at_ms,
            "success",
        );
        let now_unix_ms = cloudflare_yao_now_unix_ms()?;
        let current = storage
            .get::<YaoSessionRecordV1>(SESSION_RECORD_STORAGE_KEY)
            .await?;
        match current {
            Some(YaoSessionRecordV1::Running {
                input_digest: current_digest,
                expires_at_ms,
            }) if current_digest == input_digest && now_unix_ms < expires_at_ms => {}
            Some(YaoSessionRecordV1::Running {
                input_digest: current_digest,
                ..
            }) if current_digest == input_digest => {
                storage
                    .put(
                        SESSION_RECORD_STORAGE_KEY,
                        YaoSessionRecordV1::Expired { input_digest },
                    )
                    .await?;
                return Response::error("Deriver A session expired", 409);
            }
            Some(YaoSessionRecordV1::Running { .. }) | Some(YaoSessionRecordV1::Failed { .. }) => {
                return Response::error("Deriver A session failed", 409);
            }
            Some(YaoSessionRecordV1::Expired { .. }) => {
                return Response::error("Deriver A session expired", 409);
            }
            Some(YaoSessionRecordV1::Completed {
                input_digest: current_digest,
                execution,
            }) if current_digest == input_digest => return Response::from_json(&execution),
            Some(YaoSessionRecordV1::Staged { .. })
            | Some(YaoSessionRecordV1::Completed { .. })
            | None => return Response::error("Deriver A session state is invalid", 409),
        }
        storage
            .put(
                SESSION_RECORD_STORAGE_KEY,
                YaoSessionRecordV1::Completed {
                    input_digest,
                    execution: Box::new(execution.clone()),
                },
            )
            .await?;
        Response::from_json(&execution)
    }
}

impl RouterAbDeriverAYaoSessionDurableObject {
    async fn handle_read_pair_status(
        &self,
        session: [u8; 32],
        pair_digest: [u8; 32],
    ) -> worker::Result<Response> {
        let storage = self.state.storage();
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
        let storage = self.state.storage();
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

impl RouterAbDeriverAYaoSessionDurableObject {
    async fn handle_prepare_pair(
        &self,
        command: DeriverAYaoSessionCommandV1,
    ) -> worker::Result<Response> {
        let DeriverAYaoSessionCommandV1::PreparePair {
            pair_binding,
            input,
        } = command
        else {
            return Response::error("invalid Deriver A pair command", 400);
        };
        let request = CloudflareEd25519YaoPairPrepareRequestV1 {
            pair_binding,
            input,
        };
        let expected_kind = input_kind_for_circuit(request.pair_binding.binding().circuit_family());
        let (pair_digest, input_digest) = request
            .validate_for_role(Ed25519YaoDeriverRoleV1::DeriverA, expected_kind)
            .map_err(|error| worker::Error::RustError(error.message().to_owned()))?;
        let storage = self.state.storage();
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
                    ..
                } if existing_pair == pair_digest
                    && existing_input == input_digest
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
        if storage
            .get::<YaoSessionRecordV1>(SESSION_RECORD_STORAGE_KEY)
            .await?
            .is_some()
        {
            return Response::error(
                "Deriver A legacy lifecycle owns this session; pair preparation is closed",
                409,
            );
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
        let expires_at_ms = yao_expiry_from_now(prepared_at_ms, YAO_STAGED_INPUT_LIFETIME_MS)?;
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
                if current.is_none() {
                    transaction
                        .put(PAIR_SESSION_RECORD_STORAGE_KEY, record_for_transaction)
                        .await?;
                }
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

    async fn handle_claim_pair(
        &self,
        command: DeriverAYaoSessionCommandV1,
    ) -> worker::Result<Response> {
        let DeriverAYaoSessionCommandV1::ClaimPair {
            pair_binding,
            peer_receipt,
        } = command
        else {
            return Response::error("invalid Deriver A pair command", 400);
        };
        let request = CloudflareEd25519YaoPairExecuteRequestV1 {
            pair_binding,
            peer_receipt,
        };
        request
            .validate()
            .map_err(|error| worker::Error::RustError(error.message().to_owned()))?;
        let runtime = CloudflareDeriverAWorkerRuntimeV1::from_worker_env(&self.env)
            .map_err(|error| worker::Error::RustError(error.message().to_owned()))?;
        verify_role_readiness_receipt_v1(&request.peer_receipt, runtime.peer_verifying_keys())
            .map_err(|error| worker::Error::RustError(error.message().to_owned()))?;
        let pair_digest = request.pair_binding.pair_digest().bytes;
        let input_digest = request.pair_binding.deriver_a_input_digest().bytes;
        let storage = self.state.storage();
        let record = storage
            .get::<PairYaoSessionRecordV1>(PAIR_SESSION_RECORD_STORAGE_KEY)
            .await?
            .ok_or_else(|| worker::Error::RustError("Deriver A pair is not prepared".into()))?;
        let (root_metadata_digest, input, local_receipt) = match record {
            PairYaoSessionRecordV1::Prepared {
                pair_digest: stored_pair,
                input_digest: stored_input,
                expires_at_ms,
                root_metadata_digest,
                input,
                receipt,
            } if stored_pair == pair_digest
                && stored_input == input_digest
                && cloudflare_yao_now_unix_ms()? < expires_at_ms =>
            {
                (root_metadata_digest, input, receipt)
            }
            PairYaoSessionRecordV1::Completed {
                pair_digest: stored_pair,
                input_digest: stored_input,
                execution,
                ..
            } if stored_pair == pair_digest && stored_input == input_digest => {
                return Response::from_json(&DeriverAYaoSessionResponseV1::PairCompleted {
                    execution,
                });
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
            PairYaoSessionRecordV1::Prepared { .. } | PairYaoSessionRecordV1::Running { .. } => {
                return Response::error("Deriver A pair is already active", 409);
            }
            _ => return Response::error("Deriver A pair is not prepared", 409),
        };
        local_receipt
            .validate_for_pair(&request.pair_binding)
            .map_err(|error| worker::Error::RustError(error.message().to_owned()))?;
        local_receipt
            .validate_at(cloudflare_yao_now_unix_ms()?)
            .map_err(|error| worker::Error::RustError(error.message().to_owned()))?;
        verify_role_readiness_receipt_v1(&local_receipt, runtime.peer_verifying_keys())
            .map_err(|error| worker::Error::RustError(error.message().to_owned()))?;
        if local_receipt.role() != Ed25519YaoDeriverRoleV1::DeriverA
            || local_receipt.root_metadata_digest().bytes != root_metadata_digest
        {
            return Response::error(
                "Deriver A readiness root does not match prepared state",
                409,
            );
        }
        let started_at_ms = cloudflare_yao_now_unix_ms()?;
        let execution_id = yao_execution_id()?;
        let running_record = PairYaoSessionRecordV1::Running {
            pair_digest,
            input_digest,
            root_metadata_digest,
            execution_id,
            started_at_ms,
            input: input.clone(),
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
                && stored_execution_id == execution_id
        ) {
            return Response::error("Deriver A pair execution was already claimed", 409);
        }
        Response::from_json(&DeriverAYaoSessionResponseV1::PairClaimed {
            session: request.pair_binding.session(),
            pair_digest,
            execution_id,
            root_metadata_digest,
            input,
            receipt: local_receipt,
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
        let storage = self.state.storage();
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
                    None,
                    Some(execution_id),
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
                Response::from_json(&DeriverAYaoSessionResponseV1::PairCompleted {
                    execution: existing,
                })
            }
            Some(PairYaoSessionRecordV1::Burned {
                pair_digest: stored_pair,
                ..
            }) if stored_pair == pair_digest => {
                Response::from_json(&DeriverAYaoSessionResponseV1::PairBurned {
                    session,
                    pair_digest,
                })
            }
            _ => Response::error("Deriver A pair completion state changed", 409),
        }
    }
}

#[worker::durable_object(fetch)]
pub struct RouterAbDeriverBYaoSessionDurableObject {
    state: State,
    env: Env,
}

impl worker::DurableObject for RouterAbDeriverBYaoSessionDurableObject {
    fn new(state: State, env: Env) -> Self {
        Self { state, env }
    }

    async fn fetch(&self, mut request: Request) -> worker::Result<Response> {
        if request.method() != Method::Post {
            return Response::error("method not allowed", 405);
        }
        let _trace_id = parse_role_trace_context(&request)?;
        let command = request.json::<DeriverBYaoSessionCommandV1>().await?;
        if let Err(error) = command.validate() {
            return Response::error(error.message(), 400);
        }
        if matches!(
            &command,
            DeriverBYaoSessionCommandV1::PreparePair { .. }
                | DeriverBYaoSessionCommandV1::ReadPairPrepared { .. }
                | DeriverBYaoSessionCommandV1::BeginPair { .. }
                | DeriverBYaoSessionCommandV1::CompletePair { .. }
                | DeriverBYaoSessionCommandV1::FailPair { .. }
                | DeriverBYaoSessionCommandV1::ReadCompletedPair { .. }
                | DeriverBYaoSessionCommandV1::ReadPairStatus { .. }
        ) {
            return self.handle_pair_command(command).await;
        }
        let storage = self.state.storage();
        if storage
            .get::<PairYaoSessionRecordV1>(PAIR_SESSION_RECORD_STORAGE_KEY)
            .await?
            .is_some()
        {
            return Response::error(
                "Deriver B pair lifecycle owns this session; legacy execution is closed",
                409,
            );
        }
        let now_unix_ms = cloudflare_yao_now_unix_ms()?;
        let response = match command {
            DeriverBYaoSessionCommandV1::Stage { input } => {
                let input_digest = yao_input_digest(&input);
                let existing = storage
                    .get::<YaoSessionRecordV1>(SESSION_RECORD_STORAGE_KEY)
                    .await?;
                match existing {
                    Some(YaoSessionRecordV1::Staged {
                        input_digest: existing_digest,
                        expires_at_ms,
                        ..
                    }) if now_unix_ms >= expires_at_ms => {
                        storage
                            .put(
                                SESSION_RECORD_STORAGE_KEY,
                                YaoSessionRecordV1::Expired {
                                    input_digest: existing_digest,
                                },
                            )
                            .await?;
                        return Response::error("Deriver B staged session expired", 409);
                    }
                    Some(YaoSessionRecordV1::Staged {
                        input_digest: existing_digest,
                        ..
                    }) if existing_digest == input_digest => {}
                    Some(record) if record.input_digest() != input_digest => {
                        return Response::error("conflicting staged Deriver B input", 409);
                    }
                    Some(YaoSessionRecordV1::Running { .. })
                    | Some(YaoSessionRecordV1::Completed { .. })
                    | Some(YaoSessionRecordV1::Failed { .. })
                    | Some(YaoSessionRecordV1::Expired { .. }) => {
                        return Response::error(
                            "Deriver B session is terminal or already running",
                            409,
                        );
                    }
                    Some(YaoSessionRecordV1::Staged { .. }) => {
                        return Response::error("conflicting staged Deriver B input", 409);
                    }
                    None => {
                        let expires_at_ms =
                            yao_expiry_from_now(now_unix_ms, YAO_STAGED_INPUT_LIFETIME_MS)?;
                        storage
                            .put(
                                SESSION_RECORD_STORAGE_KEY,
                                YaoSessionRecordV1::Staged {
                                    input_digest,
                                    expires_at_ms,
                                    input: input.clone(),
                                },
                            )
                            .await?;
                    }
                }
                DeriverBYaoSessionResponseV1::Staged {
                    session: input.session(),
                }
            }
            DeriverBYaoSessionCommandV1::ReadStaged { session } => {
                let record = storage
                    .get::<YaoSessionRecordV1>(SESSION_RECORD_STORAGE_KEY)
                    .await?
                    .ok_or_else(|| worker::Error::RustError("Yao session is missing".into()))?;
                match record {
                    YaoSessionRecordV1::Staged {
                        input_digest,
                        expires_at_ms,
                        input: _,
                    } if now_unix_ms >= expires_at_ms => {
                        storage
                            .put(
                                SESSION_RECORD_STORAGE_KEY,
                                YaoSessionRecordV1::Expired { input_digest },
                            )
                            .await?;
                        DeriverBYaoSessionResponseV1::Expired { session }
                    }
                    YaoSessionRecordV1::Staged { input, .. } => {
                        if input.session() != session {
                            return Response::error("staged input session mismatch", 409);
                        }
                        DeriverBYaoSessionResponseV1::StagedInput { input }
                    }
                    YaoSessionRecordV1::Running { .. } => {
                        DeriverBYaoSessionResponseV1::Running { session }
                    }
                    YaoSessionRecordV1::Completed { .. } => {
                        DeriverBYaoSessionResponseV1::Completed { session }
                    }
                    YaoSessionRecordV1::Failed { .. } => {
                        DeriverBYaoSessionResponseV1::Failed { session }
                    }
                    YaoSessionRecordV1::Expired { .. } => {
                        DeriverBYaoSessionResponseV1::Expired { session }
                    }
                }
            }
            DeriverBYaoSessionCommandV1::Begin { session } => {
                let record = storage
                    .get::<YaoSessionRecordV1>(SESSION_RECORD_STORAGE_KEY)
                    .await?
                    .ok_or_else(|| worker::Error::RustError("Yao session is missing".into()))?;
                match record {
                    YaoSessionRecordV1::Staged {
                        input_digest,
                        expires_at_ms,
                        input,
                    } if now_unix_ms < expires_at_ms && input.session() == session => {
                        let expires_at_ms =
                            yao_expiry_from_now(now_unix_ms, YAO_RUNNING_LIFETIME_MS)?;
                        storage
                            .put(
                                SESSION_RECORD_STORAGE_KEY,
                                YaoSessionRecordV1::Running {
                                    input_digest,
                                    expires_at_ms,
                                },
                            )
                            .await?;
                        DeriverBYaoSessionResponseV1::Running { session }
                    }
                    YaoSessionRecordV1::Staged { input, .. } if input.session() != session => {
                        return Response::error("staged input session mismatch", 409);
                    }
                    YaoSessionRecordV1::Staged { input_digest, .. } => {
                        storage
                            .put(
                                SESSION_RECORD_STORAGE_KEY,
                                YaoSessionRecordV1::Expired { input_digest },
                            )
                            .await?;
                        DeriverBYaoSessionResponseV1::Expired { session }
                    }
                    YaoSessionRecordV1::Running { .. } | YaoSessionRecordV1::Completed { .. } => {
                        return Response::error(
                            "Deriver B session cannot be evaluated more than once",
                            409,
                        );
                    }
                    YaoSessionRecordV1::Failed { .. } => {
                        DeriverBYaoSessionResponseV1::Failed { session }
                    }
                    YaoSessionRecordV1::Expired { .. } => {
                        DeriverBYaoSessionResponseV1::Expired { session }
                    }
                }
            }
            DeriverBYaoSessionCommandV1::Complete { execution } => {
                let session = execution.session();
                let record = storage
                    .get::<YaoSessionRecordV1>(SESSION_RECORD_STORAGE_KEY)
                    .await?
                    .ok_or_else(|| worker::Error::RustError("Yao session is missing".into()))?;
                match record {
                    YaoSessionRecordV1::Running {
                        input_digest,
                        expires_at_ms,
                    } if now_unix_ms < expires_at_ms => {
                        storage
                            .put(
                                SESSION_RECORD_STORAGE_KEY,
                                YaoSessionRecordV1::Completed {
                                    input_digest,
                                    execution,
                                },
                            )
                            .await?;
                        DeriverBYaoSessionResponseV1::Completed { session }
                    }
                    YaoSessionRecordV1::Running { input_digest, .. } => {
                        storage
                            .put(
                                SESSION_RECORD_STORAGE_KEY,
                                YaoSessionRecordV1::Expired { input_digest },
                            )
                            .await?;
                        DeriverBYaoSessionResponseV1::Expired { session }
                    }
                    YaoSessionRecordV1::Completed {
                        execution: existing,
                        ..
                    } if existing == execution => {
                        DeriverBYaoSessionResponseV1::Completed { session }
                    }
                    YaoSessionRecordV1::Completed { .. } => {
                        return Response::error("conflicting Deriver B execution", 409);
                    }
                    YaoSessionRecordV1::Failed { .. } => {
                        DeriverBYaoSessionResponseV1::Failed { session }
                    }
                    YaoSessionRecordV1::Expired { .. } => {
                        DeriverBYaoSessionResponseV1::Expired { session }
                    }
                    YaoSessionRecordV1::Staged { .. } => {
                        return Response::error(
                            "Deriver B execution completed outside its running session",
                            409,
                        );
                    }
                }
            }
            DeriverBYaoSessionCommandV1::Fail { session } => {
                let record = storage
                    .get::<YaoSessionRecordV1>(SESSION_RECORD_STORAGE_KEY)
                    .await?
                    .ok_or_else(|| worker::Error::RustError("Yao session is missing".into()))?;
                match record {
                    YaoSessionRecordV1::Running { input_digest, .. } => {
                        storage
                            .put(
                                SESSION_RECORD_STORAGE_KEY,
                                YaoSessionRecordV1::Failed { input_digest },
                            )
                            .await?;
                        DeriverBYaoSessionResponseV1::Failed { session }
                    }
                    YaoSessionRecordV1::Failed { .. } => {
                        DeriverBYaoSessionResponseV1::Failed { session }
                    }
                    YaoSessionRecordV1::Expired { .. } => {
                        DeriverBYaoSessionResponseV1::Expired { session }
                    }
                    YaoSessionRecordV1::Completed { .. } => {
                        DeriverBYaoSessionResponseV1::Completed { session }
                    }
                    YaoSessionRecordV1::Staged { .. } => {
                        return Response::error(
                            "Deriver B session failed outside its running state",
                            409,
                        );
                    }
                }
            }
            DeriverBYaoSessionCommandV1::ReadResult { session } => {
                let record = storage
                    .get::<YaoSessionRecordV1>(SESSION_RECORD_STORAGE_KEY)
                    .await?
                    .ok_or_else(|| worker::Error::RustError("Yao session is missing".into()))?;
                match record {
                    YaoSessionRecordV1::Staged {
                        input_digest,
                        expires_at_ms,
                        ..
                    }
                    | YaoSessionRecordV1::Running {
                        input_digest,
                        expires_at_ms,
                    } if now_unix_ms >= expires_at_ms => {
                        storage
                            .put(
                                SESSION_RECORD_STORAGE_KEY,
                                YaoSessionRecordV1::Expired { input_digest },
                            )
                            .await?;
                        DeriverBYaoSessionResponseV1::Expired { session }
                    }
                    YaoSessionRecordV1::Staged { .. } | YaoSessionRecordV1::Running { .. } => {
                        DeriverBYaoSessionResponseV1::Pending { session }
                    }
                    YaoSessionRecordV1::Completed { execution, .. } => {
                        if execution.session() != session {
                            return Response::error("role execution session mismatch", 409);
                        }
                        DeriverBYaoSessionResponseV1::RoleExecution { execution }
                    }
                    YaoSessionRecordV1::Failed { .. } => {
                        DeriverBYaoSessionResponseV1::Failed { session }
                    }
                    YaoSessionRecordV1::Expired { .. } => {
                        DeriverBYaoSessionResponseV1::Expired { session }
                    }
                }
            }
            DeriverBYaoSessionCommandV1::PreparePair { .. }
            | DeriverBYaoSessionCommandV1::ReadPairPrepared { .. }
            | DeriverBYaoSessionCommandV1::BeginPair { .. }
            | DeriverBYaoSessionCommandV1::CompletePair { .. }
            | DeriverBYaoSessionCommandV1::FailPair { .. }
            | DeriverBYaoSessionCommandV1::ReadCompletedPair { .. }
            | DeriverBYaoSessionCommandV1::ReadPairStatus { .. } => {
                unreachable!("pair commands are dispatched before the legacy match")
            }
        };
        Response::from_json(&response)
    }
}

impl RouterAbDeriverBYaoSessionDurableObject {
    async fn handle_pair_command(
        &self,
        command: DeriverBYaoSessionCommandV1,
    ) -> worker::Result<Response> {
        match command {
            DeriverBYaoSessionCommandV1::PreparePair {
                pair_binding,
                input,
            } => self.handle_prepare_pair(pair_binding, *input).await,
            DeriverBYaoSessionCommandV1::ReadPairPrepared {
                session,
                pair_digest,
            } => self.handle_read_pair_prepared(session, pair_digest).await,
            DeriverBYaoSessionCommandV1::BeginPair {
                session,
                pair_digest,
                peer_receipt,
            } => {
                self.handle_begin_pair(session, pair_digest, *peer_receipt)
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
            DeriverBYaoSessionCommandV1::ReadCompletedPair {
                session,
                pair_digest,
            } => self.handle_read_completed_pair(session, pair_digest).await,
            DeriverBYaoSessionCommandV1::ReadPairStatus {
                session,
                pair_digest,
            } => self.handle_read_pair_status(session, pair_digest).await,
            _ => Response::error("invalid Deriver B pair command", 400),
        }
    }

    async fn handle_prepare_pair(
        &self,
        pair_binding: Ed25519YaoInputPairBindingV1,
        input: Ed25519YaoEncryptedInputV1,
    ) -> worker::Result<Response> {
        let request = CloudflareEd25519YaoPairPrepareRequestV1 {
            pair_binding,
            input,
        };
        let expected_kind = input_kind_for_circuit(request.pair_binding.binding().circuit_family());
        let (pair_digest, input_digest) = request
            .validate_for_role(Ed25519YaoDeriverRoleV1::DeriverB, expected_kind)
            .map_err(|error| worker::Error::RustError(error.message().to_owned()))?;
        let storage = self.state.storage();
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
                    receipt,
                } if stored_pair == pair_digest
                    && stored_input == input_digest
                    && now_unix_ms < expires_at_ms =>
                {
                    return Response::from_json(&DeriverBYaoSessionResponseV1::PairPrepared {
                        session: input.session(),
                        pair_digest: stored_pair,
                        root_metadata_digest,
                        input,
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
        if storage
            .get::<YaoSessionRecordV1>(SESSION_RECORD_STORAGE_KEY)
            .await?
            .is_some()
        {
            return Response::error(
                "Deriver B legacy lifecycle owns this session; pair preparation is closed",
                409,
            );
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
                    receipt,
                } if stored_pair == pair_digest
                    && stored_input == input_digest
                    && prepared_at_ms < expires_at_ms =>
                {
                    return Response::from_json(&DeriverBYaoSessionResponseV1::PairPrepared {
                        session: input.session(),
                        pair_digest: stored_pair,
                        root_metadata_digest,
                        input,
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
        let expires_at_ms = yao_expiry_from_now(prepared_at_ms, YAO_STAGED_INPUT_LIFETIME_MS)?;
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
                if current.is_none() {
                    transaction
                        .put(PAIR_SESSION_RECORD_STORAGE_KEY, record_for_transaction)
                        .await?;
                }
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
            receipt: Box::new(receipt),
        })
    }

    async fn handle_read_pair_prepared(
        &self,
        session: [u8; 32],
        pair_digest: [u8; 32],
    ) -> worker::Result<Response> {
        let record = self
            .state
            .storage()
            .get::<PairYaoSessionRecordV1>(PAIR_SESSION_RECORD_STORAGE_KEY)
            .await?
            .ok_or_else(|| worker::Error::RustError("Deriver B pair is missing".into()))?;
        let response = match record {
            PairYaoSessionRecordV1::Prepared {
                pair_digest: stored_pair,
                input,
                root_metadata_digest,
                receipt,
                ..
            } if stored_pair == pair_digest && input.session() == session => {
                DeriverBYaoSessionResponseV1::PairPrepared {
                    session,
                    pair_digest,
                    root_metadata_digest,
                    input,
                    receipt,
                }
            }
            PairYaoSessionRecordV1::Running {
                pair_digest: stored_pair,
                ..
            } if stored_pair == pair_digest => DeriverBYaoSessionResponseV1::PairRunning {
                session,
                pair_digest,
            },
            PairYaoSessionRecordV1::Completed {
                pair_digest: stored_pair,
                ..
            } if stored_pair == pair_digest => DeriverBYaoSessionResponseV1::PairCompleted {
                session,
                pair_digest,
            },
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

    async fn handle_begin_pair(
        &self,
        session: [u8; 32],
        pair_digest: [u8; 32],
        peer_receipt: Ed25519YaoRoleReadinessReceiptV1,
    ) -> worker::Result<Response> {
        let runtime = CloudflareDeriverBWorkerRuntimeV1::from_worker_env(&self.env)
            .map_err(|error| worker::Error::RustError(error.message().to_owned()))?;
        verify_role_readiness_receipt_v1(&peer_receipt, runtime.peer_verifying_keys())
            .map_err(|error| worker::Error::RustError(error.message().to_owned()))?;
        if peer_receipt.role() != Ed25519YaoDeriverRoleV1::DeriverA
            || peer_receipt.pair_digest().bytes != pair_digest
            || peer_receipt.session_bytes() != session
        {
            return Response::error("Deriver A readiness receipt does not match pair", 409);
        }
        let storage = self.state.storage();
        let now_unix_ms = cloudflare_yao_now_unix_ms()?;
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
        receipt
            .validate_at(now_unix_ms)
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
        let execution_id = yao_execution_id()?;
        let running_record = PairYaoSessionRecordV1::Running {
            pair_digest,
            input_digest,
            root_metadata_digest,
            execution_id,
            started_at_ms,
            input,
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
                && stored_execution_id == execution_id
        ) {
            return Response::error("Deriver B pair was already claimed", 409);
        }
        Response::from_json(&DeriverBYaoSessionResponseV1::PairRunning {
            session,
            pair_digest,
        })
    }

    async fn handle_complete_pair(
        &self,
        pair_digest: [u8; 32],
        execution: Ed25519YaoRoleExecutionV1,
    ) -> worker::Result<Response> {
        let session = execution.session();
        let storage = self.state.storage();
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
                            Some(input_digest),
                            None,
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
        let storage = self.state.storage();
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
            PairYaoSessionRecordV1::Completed { execution, .. }
                if execution.session() == session =>
            {
                DeriverBYaoSessionResponseV1::PairCompleted {
                    session,
                    pair_digest,
                }
            }
            _ => return Response::error("Deriver B pair cannot be burned", 409),
        };
        Response::from_json(&response)
    }

    async fn handle_read_completed_pair(
        &self,
        session: [u8; 32],
        pair_digest: [u8; 32],
    ) -> worker::Result<Response> {
        let storage = self.state.storage();
        let record = storage
            .get::<PairYaoSessionRecordV1>(PAIR_SESSION_RECORD_STORAGE_KEY)
            .await?
            .ok_or_else(|| worker::Error::RustError("Deriver B pair is missing".into()))?;
        if let PairYaoSessionRecordV1::Running {
            pair_digest: stored_pair,
            input_digest,
            execution_id,
            started_at_ms,
            input,
            ..
        } = &record
        {
            if *stored_pair == pair_digest && input.session() == session {
                if burn_running_pair_if_expired(
                    &storage,
                    pair_digest,
                    *input_digest,
                    *execution_id,
                    *started_at_ms,
                    cloudflare_yao_now_unix_ms()?,
                )
                .await?
                {
                    return Response::from_json(&DeriverBYaoSessionResponseV1::PairBurned {
                        session,
                        pair_digest,
                    });
                }
            }
        }
        let response = match record {
            PairYaoSessionRecordV1::Prepared {
                pair_digest: stored_pair,
                ..
            }
            | PairYaoSessionRecordV1::Running {
                pair_digest: stored_pair,
                ..
            } if stored_pair == pair_digest => DeriverBYaoSessionResponseV1::PairPending {
                session,
                pair_digest,
            },
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

    async fn handle_read_pair_status(
        &self,
        session: [u8; 32],
        pair_digest: [u8; 32],
    ) -> worker::Result<Response> {
        let storage = self.state.storage();
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

pub async fn handle_cloudflare_ed25519_yao_deriver_a_start_v1(
    mut request: Request,
    env: &Env,
    expected_kind: Ed25519YaoInputKindV1,
) -> RouterAbProtocolResult<Response> {
    let trace_id = parse_cloudflare_trace_id_from_request_v1(&request)?;
    let input = parse_request::<Ed25519YaoEncryptedInputV1>(&mut request).await?;
    validate_deriver_input(&input, Ed25519YaoDeriverRoleV1::DeriverA, expected_kind)?;
    let execution = execute_deriver_a_session(env, input, trace_id).await?;
    json_response(&execution)
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
    let response = execute_deriver_a_pair_claim(env, request.clone(), trace_id).await?;
    let execution = match response {
        DeriverAYaoSessionResponseV1::PairCompleted { execution } => *execution,
        DeriverAYaoSessionResponseV1::PairBurned { .. } => {
            return Err(invalid_lifecycle("Deriver A pair execution was burned"));
        }
        DeriverAYaoSessionResponseV1::PairClaimed {
            session,
            pair_digest,
            execution_id,
            root_metadata_digest,
            input,
            receipt,
        } => {
            if session != pair_binding.session() || pair_digest != pair_binding.pair_digest().bytes
            {
                return Err(invalid_lifecycle(
                    "Deriver A pair claim response identity is invalid",
                ));
            }
            receipt.validate_for_pair(&pair_binding)?;
            receipt.validate_at(
                cloudflare_yao_now_unix_ms()
                    .map_err(|_| invalid_lifecycle("Yao clock is unavailable"))?,
            )?;
            let runtime = CloudflareDeriverAWorkerRuntimeV1::from_worker_env(env)?;
            verify_role_readiness_receipt_v1(&receipt, runtime.peer_verifying_keys())?;
            if receipt.role() != Ed25519YaoDeriverRoleV1::DeriverA
                || receipt.root_metadata_digest().bytes != root_metadata_digest
            {
                return Err(invalid_lifecycle(
                    "Deriver A pair claim readiness root is invalid",
                ));
            }
            let execution = execute_deriver_a_role(
                env,
                &runtime,
                *input,
                trace_id,
                Some(root_metadata_digest),
                Some(pair_digest),
                Some(&request.peer_receipt),
                Some(&receipt),
            )
            .await;
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
            complete_deriver_a_pair(env, pair_digest, execution_id, execution, trace_id).await?
        }
    };
    json_response(&execution)
}

pub async fn handle_cloudflare_ed25519_yao_deriver_a_read_pair_status_v1(
    mut request: Request,
    env: &Env,
) -> RouterAbProtocolResult<Response> {
    let trace_id = parse_cloudflare_trace_id_from_request_v1(&request)?;
    let request =
        parse_request::<CloudflareEd25519YaoReadCompletedPairRequestV1>(&mut request).await?;
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
    let request =
        parse_request::<CloudflareEd25519YaoReadCompletedPairRequestV1>(&mut request).await?;
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

async fn execute_deriver_a_role(
    env: &Env,
    runtime: &CloudflareDeriverAWorkerRuntimeV1,
    input: Ed25519YaoEncryptedInputV1,
    trace_id: RoleTraceContextV1,
    expected_root_metadata_digest: Option<[u8; 32]>,
    pair_digest: Option<[u8; 32]>,
    peer_receipt: Option<&Ed25519YaoRoleReadinessReceiptV1>,
    local_receipt: Option<&Ed25519YaoRoleReadinessReceiptV1>,
) -> RouterAbProtocolResult<Ed25519YaoRoleExecutionV1> {
    if pair_digest.is_some() && (peer_receipt.is_none() || local_receipt.is_none()) {
        return Err(invalid_lifecycle(
            "pair-bound Deriver A execution requires both readiness receipts",
        ));
    }
    let now_unix_ms = if pair_digest.is_some() {
        Some(
            cloudflare_yao_now_unix_ms()
                .map_err(|_| invalid_lifecycle("Yao clock is unavailable"))?,
        )
    } else {
        None
    };
    if let Some(peer_receipt) = peer_receipt {
        if peer_receipt.role() != Ed25519YaoDeriverRoleV1::DeriverB {
            return Err(invalid_lifecycle(
                "Deriver A execution requires a Deriver B readiness receipt",
            ));
        }
        if let Some(now_unix_ms) = now_unix_ms {
            peer_receipt.validate_at(now_unix_ms)?;
        }
        verify_role_readiness_receipt_v1(peer_receipt, runtime.peer_verifying_keys())?;
    }
    if let Some(local_receipt) = local_receipt {
        if local_receipt.role() != Ed25519YaoDeriverRoleV1::DeriverA {
            return Err(invalid_lifecycle(
                "Deriver A execution requires a Deriver A readiness receipt",
            ));
        }
        if let Some(now_unix_ms) = now_unix_ms {
            local_receipt.validate_at(now_unix_ms)?;
        }
        verify_role_readiness_receipt_v1(local_receipt, runtime.peer_verifying_keys())?;
    }
    let circuit = circuit_for_input(&input);
    let private_key =
        load_deriver_input_private_key(env, &runtime.envelope_decrypt_key().current.binding_name)?;
    let session = input.session();
    let websocket_binding = match pair_digest {
        Some(pair_digest) => {
            CloudflareEd25519YaoWebSocketBindingV1::with_pair_digest(circuit, session, pair_digest)
        }
        None => CloudflareEd25519YaoWebSocketBindingV1::new(circuit, session),
    }
    .map_err(map_websocket_error)?;
    let execution = match input.kind() {
        Ed25519YaoInputKindV1::Activation => {
            let role_request =
                open_ed25519_yao_activation_deriver_a_input_v1(&input, &private_key)?;
            let (root_with_digest, socket) = if pair_digest.is_some() {
                load_deriver_a_pair_root_before_connect(
                    env,
                    runtime,
                    &role_request.binding.lifecycle,
                    trace_id,
                    websocket_binding,
                    local_receipt,
                    expected_root_metadata_digest,
                )
                .await?
            } else {
                futures::try_join!(
                    load_deriver_a_yao_root_with_metadata_digest(
                        env,
                        runtime,
                        &role_request.binding.lifecycle,
                        trace_id,
                    ),
                    connect_deriver_b(env, websocket_binding, trace_id, local_receipt),
                )?
            };
            let (root, root_metadata_digest) = root_with_digest;
            validate_expected_root_metadata_digest(
                expected_root_metadata_digest,
                root_metadata_digest,
            )?;
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
            seal_ed25519_yao_activation_deriver_a_execution_v1(
                &mut CloudflareHpkeGetrandomRngV1,
                binding,
                recipients,
                &completion.role,
            )?
        }
        Ed25519YaoInputKindV1::Export => {
            let role_request = open_ed25519_yao_export_deriver_a_input_v1(&input, &private_key)?;
            let (root_with_digest, socket) = if pair_digest.is_some() {
                load_deriver_a_pair_root_before_connect(
                    env,
                    runtime,
                    &role_request.binding.lifecycle,
                    trace_id,
                    websocket_binding,
                    local_receipt,
                    expected_root_metadata_digest,
                )
                .await?
            } else {
                futures::try_join!(
                    load_deriver_a_yao_root_with_metadata_digest(
                        env,
                        runtime,
                        &role_request.binding.lifecycle,
                        trace_id,
                    ),
                    connect_deriver_b(env, websocket_binding, trace_id, local_receipt),
                )?
            };
            let (root, root_metadata_digest) = root_with_digest;
            validate_expected_root_metadata_digest(
                expected_root_metadata_digest,
                root_metadata_digest,
            )?;
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
            seal_ed25519_yao_export_deriver_a_execution_v1(
                &mut CloudflareHpkeGetrandomRngV1,
                binding,
                recipient,
                &completion.role,
            )?
        }
    };
    Ok(execution)
}

async fn load_deriver_a_pair_root_before_connect(
    env: &Env,
    runtime: &CloudflareDeriverAWorkerRuntimeV1,
    lifecycle: &LifecycleScopeV1,
    trace_id: RoleTraceContextV1,
    websocket_binding: CloudflareEd25519YaoWebSocketBindingV1,
    local_receipt: Option<&Ed25519YaoRoleReadinessReceiptV1>,
    expected_root_metadata_digest: Option<[u8; 32]>,
) -> RouterAbProtocolResult<(([u8; 32], [u8; 32]), worker::WebSocket)> {
    let root_with_digest =
        load_deriver_a_yao_root_with_metadata_digest(env, runtime, lifecycle, trace_id).await?;
    validate_expected_root_metadata_digest(expected_root_metadata_digest, root_with_digest.1)?;
    let socket = connect_deriver_b(env, websocket_binding, trace_id, local_receipt).await?;
    Ok((root_with_digest, socket))
}

async fn connect_deriver_b(
    env: &Env,
    binding: CloudflareEd25519YaoWebSocketBindingV1,
    trace_id: RoleTraceContextV1,
    peer_receipt: Option<&Ed25519YaoRoleReadinessReceiptV1>,
) -> RouterAbProtocolResult<worker::WebSocket> {
    let started_at_ms = role_span_started_at_ms();
    let result = crate::connect_cloudflare_ed25519_yao_deriver_b_with_receipt_v1(
        env,
        binding,
        trace_id,
        peer_receipt,
    )
    .await
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

pub async fn handle_cloudflare_ed25519_yao_deriver_b_stage_v1(
    mut request: Request,
    env: &Env,
    expected_kind: Ed25519YaoInputKindV1,
) -> RouterAbProtocolResult<Response> {
    let trace_id = parse_cloudflare_trace_id_from_request_v1(&request)?;
    let input = parse_request::<Ed25519YaoEncryptedInputV1>(&mut request).await?;
    validate_deriver_input(&input, Ed25519YaoDeriverRoleV1::DeriverB, expected_kind)?;
    let response = execute_deriver_b_session_command(
        env,
        DeriverBYaoSessionCommandV1::Stage {
            input: Box::new(input),
        },
        trace_id,
    )
    .await?;
    json_response(&response)
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
            pair_binding: request.pair_binding,
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

pub async fn handle_cloudflare_ed25519_yao_deriver_b_read_completed_pair_v1(
    mut request: Request,
    env: &Env,
) -> RouterAbProtocolResult<Response> {
    let trace_id = parse_cloudflare_trace_id_from_request_v1(&request)?;
    let request =
        parse_request::<CloudflareEd25519YaoReadCompletedPairRequestV1>(&mut request).await?;
    request.validate()?;
    let response = execute_deriver_b_session_command(
        env,
        DeriverBYaoSessionCommandV1::ReadCompletedPair {
            session: request.session,
            pair_digest: request.pair_digest,
        },
        trace_id,
    )
    .await?;
    match response {
        DeriverBYaoSessionResponseV1::PairRoleExecution { execution } => {
            let acknowledgement = CloudflareEd25519YaoPairCompletionAcknowledgementV1::Completed {
                session: request.session,
                pair_digest: request.pair_digest,
                execution,
            };
            acknowledgement.validate_for_request(&request)?;
            json_response(&acknowledgement)
        }
        DeriverBYaoSessionResponseV1::PairBurned { .. } => {
            Err(invalid_lifecycle("Deriver B pair execution failed"))
        }
        DeriverBYaoSessionResponseV1::PairExpired { .. } => {
            Err(invalid_lifecycle("Deriver B pair execution expired"))
        }
        DeriverBYaoSessionResponseV1::PairPending { .. } => Err(invalid_lifecycle(
            "Deriver B pair execution is not complete",
        )),
        _ => Err(invalid_lifecycle(
            "Deriver B completed pair returned the wrong response",
        )),
    }
}

pub async fn handle_cloudflare_ed25519_yao_deriver_b_read_pair_status_v1(
    mut request: Request,
    env: &Env,
) -> RouterAbProtocolResult<Response> {
    let trace_id = parse_cloudflare_trace_id_from_request_v1(&request)?;
    let request =
        parse_request::<CloudflareEd25519YaoReadCompletedPairRequestV1>(&mut request).await?;
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
    let request =
        parse_request::<CloudflareEd25519YaoReadCompletedPairRequestV1>(&mut request).await?;
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

pub async fn handle_cloudflare_ed25519_yao_deriver_b_result_v1(
    mut request: Request,
    env: &Env,
    expected_kind: Ed25519YaoInputKindV1,
) -> RouterAbProtocolResult<Response> {
    let trace_id = parse_cloudflare_trace_id_from_request_v1(&request)?;
    let request = parse_request::<CloudflareEd25519YaoResultRequestV1>(&mut request).await?;
    request.validate()?;
    if request.input_kind() != expected_kind {
        return Err(invalid_lifecycle(
            "Ed25519 Yao result family does not match the route",
        ));
    }
    let session_id = request.session_id();
    let wait_started_at_ms = role_span_started_at_ms();
    for attempt in 0..YAO_RESULT_WAIT_ATTEMPTS {
        let response = match execute_deriver_b_session_command(
            env,
            DeriverBYaoSessionCommandV1::ReadResult {
                session: session_id,
            },
            trace_id,
        )
        .await
        {
            Ok(response) => response,
            Err(error) => {
                emit_role_span_v1(
                    trace_id,
                    "deriver_b.result_wait",
                    "deriver_b",
                    "result",
                    wait_started_at_ms,
                    "failure",
                );
                return Err(error);
            }
        };
        match response {
            DeriverBYaoSessionResponseV1::RoleExecution { execution } => {
                emit_role_span_v1(
                    trace_id,
                    "deriver_b.result_wait",
                    "deriver_b",
                    "result",
                    wait_started_at_ms,
                    "success",
                );
                return json_response(&execution);
            }
            DeriverBYaoSessionResponseV1::Pending { .. }
                if attempt + 1 < YAO_RESULT_WAIT_ATTEMPTS =>
            {
                Delay::from(YAO_RESULT_WAIT_INTERVAL).await;
            }
            DeriverBYaoSessionResponseV1::Pending { .. } => {
                emit_role_span_v1(
                    trace_id,
                    "deriver_b.result_wait",
                    "deriver_b",
                    "result",
                    wait_started_at_ms,
                    "failure",
                );
                return Err(invalid_lifecycle(
                    "Deriver B role execution did not complete before result timeout",
                ));
            }
            DeriverBYaoSessionResponseV1::Failed { .. } => {
                emit_role_span_v1(
                    trace_id,
                    "deriver_b.result_wait",
                    "deriver_b",
                    "result",
                    wait_started_at_ms,
                    "failure",
                );
                return Err(invalid_lifecycle("Deriver B role execution failed"));
            }
            DeriverBYaoSessionResponseV1::Expired { .. } => {
                emit_role_span_v1(
                    trace_id,
                    "deriver_b.result_wait",
                    "deriver_b",
                    "result",
                    wait_started_at_ms,
                    "failure",
                );
                return Err(invalid_lifecycle("Deriver B role execution expired"));
            }
            DeriverBYaoSessionResponseV1::Staged { .. }
            | DeriverBYaoSessionResponseV1::StagedInput { .. }
            | DeriverBYaoSessionResponseV1::Running { .. }
            | DeriverBYaoSessionResponseV1::Completed { .. }
            | DeriverBYaoSessionResponseV1::PairPrepared { .. }
            | DeriverBYaoSessionResponseV1::PairPreparedStatus { .. }
            | DeriverBYaoSessionResponseV1::PairRunning { .. }
            | DeriverBYaoSessionResponseV1::PairCompleted { .. }
            | DeriverBYaoSessionResponseV1::PairPending { .. }
            | DeriverBYaoSessionResponseV1::PairRoleExecution { .. }
            | DeriverBYaoSessionResponseV1::PairBurned { .. }
            | DeriverBYaoSessionResponseV1::PairExpired { .. }
            | DeriverBYaoSessionResponseV1::PairMissing { .. } => {
                emit_role_span_v1(
                    trace_id,
                    "deriver_b.result_wait",
                    "deriver_b",
                    "result",
                    wait_started_at_ms,
                    "failure",
                );
                return Err(invalid_lifecycle(
                    "Deriver B result lookup returned the wrong response",
                ));
            }
        }
    }
    emit_role_span_v1(
        trace_id,
        "deriver_b.result_wait",
        "deriver_b",
        "result",
        wait_started_at_ms,
        "failure",
    );
    Err(invalid_lifecycle(
        "Deriver B role execution did not complete before result timeout",
    ))
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
    if binding.pair_digest.iter().any(|byte| *byte != 0) {
        return handle_pair_bound_deriver_b_websocket(
            request, env, runtime, context, trace_id, protocol, binding,
        )
        .await;
    }
    let staged = execute_deriver_b_session_command(
        &env,
        DeriverBYaoSessionCommandV1::ReadStaged {
            session: binding.session,
        },
        trace_id,
    )
    .await?;
    let DeriverBYaoSessionResponseV1::StagedInput { input } = staged else {
        return Err(invalid_lifecycle(
            "Deriver B staged lookup returned the wrong response",
        ));
    };
    if circuit_for_input(&input) != binding.circuit {
        return Err(invalid_lifecycle(
            "Deriver B staged circuit does not match WebSocket binding",
        ));
    }
    let pair = WebSocketPair::new()
        .map_err(|_| invalid_lifecycle("Deriver B WebSocket pair could not be created"))?;
    let headers = worker::Headers::new();
    headers
        .set("Sec-WebSocket-Protocol", &protocol)
        .map_err(|_| invalid_lifecycle("WebSocket response protocol could not be set"))?;
    let response = Response::from_websocket(pair.client)
        .map(|response| response.with_headers(headers))
        .map_err(|_| invalid_lifecycle("WebSocket upgrade response could not be created"))?;
    let running = execute_deriver_b_session_command(
        &env,
        DeriverBYaoSessionCommandV1::Begin {
            session: binding.session,
        },
        trace_id,
    )
    .await?;
    if running
        != (DeriverBYaoSessionResponseV1::Running {
            session: binding.session,
        })
    {
        return Err(invalid_lifecycle(
            "Deriver B session did not enter its one-use running state",
        ));
    }
    let server = pair.server;
    let server_for_error = server.clone();
    let session = binding.session;
    context.wait_until(async move {
        let role_started_at_ms = role_span_started_at_ms();
        let result =
            execute_deriver_b_role(&env, &runtime, *input, server, trace_id, None, None).await;
        emit_role_span_v1(
            trace_id,
            "deriver_b.role_execution",
            "deriver_b",
            "yao",
            role_started_at_ms,
            if result.is_ok() { "success" } else { "failure" },
        );
        if result.is_err() {
            worker::console_error!(
                "Deriver B Ed25519 Yao role execution failed for trace {}",
                trace_id
                    .map(CloudflareTraceIdV1::as_hex)
                    .unwrap_or_else(|| "unavailable".to_owned())
            );
            let _ignored = execute_deriver_b_session_command(
                &env,
                DeriverBYaoSessionCommandV1::Fail { session },
                trace_id,
            )
            .await;
            let _ignored = server_for_error.close(Some(1011), Some("yao-lifecycle-failed"));
        }
    });
    Ok(response)
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
    let pair_prepared = execute_deriver_b_session_command(
        &env,
        DeriverBYaoSessionCommandV1::ReadPairPrepared {
            session: binding.session,
            pair_digest: binding.pair_digest,
        },
        trace_id,
    )
    .await?;
    let DeriverBYaoSessionResponseV1::PairPrepared {
        input,
        receipt,
        root_metadata_digest,
        ..
    } = pair_prepared
    else {
        return Err(invalid_lifecycle(
            "Deriver B pair preparation is missing or terminal",
        ));
    };
    peer_receipt
        .validate_at(
            cloudflare_yao_now_unix_ms()
                .map_err(|_| invalid_lifecycle("Yao clock is unavailable"))?,
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
    if receipt.role() != Ed25519YaoDeriverRoleV1::DeriverB
        || receipt.pair_digest().bytes != binding.pair_digest
        || receipt.session_bytes() != binding.session
        || receipt.root_metadata_digest().bytes != root_metadata_digest
    {
        return Err(invalid_lifecycle(
            "Deriver B readiness root does not match prepared state",
        ));
    }
    receipt
        .validate_at(
            cloudflare_yao_now_unix_ms()
                .map_err(|_| invalid_lifecycle("Yao clock is unavailable"))?,
        )
        .map_err(|error| invalid_lifecycle(error.message()))?;
    verify_role_readiness_receipt_v1(&peer_receipt, runtime.peer_verifying_keys())?;
    verify_role_readiness_receipt_v1(&receipt, runtime.peer_verifying_keys())?;
    if circuit_for_input(&input) != binding.circuit {
        return Err(invalid_lifecycle(
            "Deriver B prepared circuit does not match WebSocket binding",
        ));
    }
    let pair = WebSocketPair::new()
        .map_err(|_| invalid_lifecycle("Deriver B WebSocket pair could not be created"))?;
    let headers = worker::Headers::new();
    headers
        .set("Sec-WebSocket-Protocol", &protocol)
        .map_err(|_| invalid_lifecycle("WebSocket response protocol could not be set"))?;
    let response = Response::from_websocket(pair.client)
        .map(|response| response.with_headers(headers))
        .map_err(|_| invalid_lifecycle("WebSocket upgrade response could not be created"))?;
    let running = execute_deriver_b_session_command(
        &env,
        DeriverBYaoSessionCommandV1::BeginPair {
            session: binding.session,
            pair_digest: binding.pair_digest,
            peer_receipt: Box::new(peer_receipt),
        },
        trace_id,
    )
    .await?;
    if running
        != (DeriverBYaoSessionResponseV1::PairRunning {
            session: binding.session,
            pair_digest: binding.pair_digest,
        })
    {
        return Err(invalid_lifecycle(
            "Deriver B pair did not enter its running state",
        ));
    }
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
            Some(root_metadata_digest),
            Some(pair_digest),
        )
        .await;
        emit_role_span_v1(
            trace_id,
            "deriver_b.role_execution",
            "deriver_b",
            "yao",
            role_started_at_ms,
            if result.is_ok() { "success" } else { "failure" },
        );
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
    expected_root_metadata_digest: Option<[u8; 32]>,
    pair_digest: Option<[u8; 32]>,
) -> RouterAbProtocolResult<()> {
    let private_key =
        load_deriver_input_private_key(env, &runtime.envelope_decrypt_key().current.binding_name)?;
    let session = input.session();
    let transport = CloudflareEd25519YaoWebSocketTransportV1::deriver_b(&socket, session)
        .map_err(map_websocket_error)?;
    let execution = match input.kind() {
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
                with_yao_ceremony_timeout(run_activation_deriver_b(role, transport)).await;
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
            seal_ed25519_yao_activation_deriver_b_execution_v1(
                &mut CloudflareHpkeGetrandomRngV1,
                binding,
                recipients,
                &completion.role,
            )?
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
                with_yao_ceremony_timeout(run_export_deriver_b(role, transport)).await;
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
            seal_ed25519_yao_export_deriver_b_execution_v1(
                &mut CloudflareHpkeGetrandomRngV1,
                binding,
                recipient,
                &completion.role,
            )?
        }
    };
    if let Some(pair_digest) = pair_digest {
        execute_deriver_b_session_command(
            env,
            DeriverBYaoSessionCommandV1::CompletePair {
                pair_digest,
                execution: Box::new(execution),
            },
            trace_id,
        )
        .await?;
    } else {
        execute_deriver_b_session_command(
            env,
            DeriverBYaoSessionCommandV1::Complete {
                execution: Box::new(execution),
            },
            trace_id,
        )
        .await?;
    }
    Ok(())
}

async fn execute_deriver_b_session_command(
    env: &Env,
    command: DeriverBYaoSessionCommandV1,
    trace_id: RoleTraceContextV1,
) -> RouterAbProtocolResult<DeriverBYaoSessionResponseV1> {
    command.validate()?;
    let operation = command.operation();
    let namespace = env
        .durable_object(DERIVER_B_YAO_SESSION_DO_BINDING)
        .map_err(|_| {
            invalid_lifecycle("Deriver B Yao session Durable Object binding is missing")
        })?;
    let stub = namespace
        .get_by_name(&encode_hex(command.session()))
        .map_err(|_| invalid_lifecycle("Deriver B Yao session Durable Object lookup failed"))?;
    let body = serde_json::to_string(&command)
        .map_err(|_| invalid_lifecycle("Deriver B Yao session command encoding failed"))?;
    let mut init = worker::RequestInit::new();
    init.with_method(Method::Post)
        .with_body(Some(worker::wasm_bindgen::JsValue::from_str(&body)));
    let request = Request::new_with_init(DERIVER_B_YAO_SESSION_DO_URL, &init)
        .map_err(|_| invalid_lifecycle("Deriver B Yao session request construction failed"))?;
    if let Some(trace_id) = trace_id {
        set_cloudflare_trace_id_header_v1(request.headers(), trace_id)?;
    }
    let started_at_ms = role_span_started_at_ms();
    let response_result = stub
        .fetch_with_request(request)
        .await
        .map_err(|_| invalid_lifecycle("Deriver B Yao session Durable Object request failed"));
    let mut response = match response_result {
        Ok(response) => response,
        Err(error) => {
            emit_role_span_v1(
                trace_id,
                "deriver_b.session_do",
                "deriver_b",
                operation,
                started_at_ms,
                "failure",
            );
            return Err(error);
        }
    };
    if !(200..=299).contains(&response.status_code()) {
        emit_role_span_v1(
            trace_id,
            "deriver_b.session_do",
            "deriver_b",
            operation,
            started_at_ms,
            "failure",
        );
        return Err(invalid_lifecycle(
            "Deriver B Yao session Durable Object rejected the command",
        ));
    }
    let result = response
        .json::<DeriverBYaoSessionResponseV1>()
        .await
        .map_err(|_| invalid_lifecycle("Deriver B Yao session response is malformed"));
    emit_role_span_v1(
        trace_id,
        "deriver_b.session_do",
        "deriver_b",
        operation,
        started_at_ms,
        if result.is_ok() { "success" } else { "failure" },
    );
    result
}

async fn execute_deriver_a_session(
    env: &Env,
    input: Ed25519YaoEncryptedInputV1,
    trace_id: RoleTraceContextV1,
) -> RouterAbProtocolResult<Ed25519YaoRoleExecutionV1> {
    let session = input.session();
    let command = DeriverAYaoSessionCommandV1::Execute { input };
    command.validate()?;
    let namespace = env
        .durable_object(DERIVER_A_YAO_SESSION_DO_BINDING)
        .map_err(|_| {
            invalid_lifecycle("Deriver A Yao session Durable Object binding is missing")
        })?;
    let stub = namespace
        .get_by_name(&encode_hex(session))
        .map_err(|_| invalid_lifecycle("Deriver A Yao session Durable Object lookup failed"))?;
    let body = serde_json::to_string(&command)
        .map_err(|_| invalid_lifecycle("Deriver A Yao session command encoding failed"))?;
    let mut init = worker::RequestInit::new();
    init.with_method(Method::Post)
        .with_body(Some(worker::wasm_bindgen::JsValue::from_str(&body)));
    let request = Request::new_with_init(DERIVER_A_YAO_SESSION_DO_URL, &init)
        .map_err(|_| invalid_lifecycle("Deriver A Yao session request construction failed"))?;
    if let Some(trace_id) = trace_id {
        set_cloudflare_trace_id_header_v1(request.headers(), trace_id)?;
    }
    let started_at_ms = role_span_started_at_ms();
    let response_result = stub
        .fetch_with_request(request)
        .await
        .map_err(|_| invalid_lifecycle("Deriver A Yao session Durable Object request failed"));
    let mut response = match response_result {
        Ok(response) => response,
        Err(error) => {
            emit_role_span_v1(
                trace_id,
                "deriver_a.session_do",
                "deriver_a",
                "durable_object",
                started_at_ms,
                "failure",
            );
            return Err(error);
        }
    };
    let status = response.status_code();
    if !(200..=299).contains(&status) {
        emit_role_span_v1(
            trace_id,
            "deriver_a.session_do",
            "deriver_a",
            "durable_object",
            started_at_ms,
            "failure",
        );
        let message = response
            .text()
            .await
            .unwrap_or_else(|_| "response body unavailable".to_owned());
        return Err(invalid_lifecycle(format!(
            "Deriver A Yao session Durable Object rejected the command with HTTP {status}: {message}"
        )));
    }
    let result = response
        .json::<Ed25519YaoRoleExecutionV1>()
        .await
        .map_err(|_| invalid_lifecycle("Deriver A Yao session response is malformed"));
    emit_role_span_v1(
        trace_id,
        "deriver_a.session_do",
        "deriver_a",
        "durable_object",
        started_at_ms,
        if result.is_ok() { "success" } else { "failure" },
    );
    let execution = result?;
    execution.validate()?;
    if execution.deriver() != Ed25519YaoDeriverRoleV1::DeriverA || execution.session() != session {
        return Err(invalid_lifecycle(
            "Deriver A Yao session response identity is invalid",
        ));
    }
    Ok(execution)
}

async fn execute_deriver_a_pair_prepare(
    env: &Env,
    request: CloudflareEd25519YaoPairPrepareRequestV1,
    trace_id: RoleTraceContextV1,
) -> RouterAbProtocolResult<Ed25519YaoRoleReadinessReceiptV1> {
    let command = DeriverAYaoSessionCommandV1::PreparePair {
        pair_binding: request.pair_binding,
        input: request.input,
    };
    let mut response = execute_deriver_a_pair_command(env, command, trace_id).await?;
    response
        .json::<Ed25519YaoRoleReadinessReceiptV1>()
        .await
        .map_err(|_| invalid_lifecycle("Deriver A readiness receipt is malformed"))
}

async fn execute_deriver_a_pair_claim(
    env: &Env,
    request: CloudflareEd25519YaoPairExecuteRequestV1,
    trace_id: RoleTraceContextV1,
) -> RouterAbProtocolResult<DeriverAYaoSessionResponseV1> {
    let command = DeriverAYaoSessionCommandV1::ClaimPair {
        pair_binding: request.pair_binding,
        peer_receipt: request.peer_receipt,
    };
    let mut response = execute_deriver_a_pair_command(env, command, trace_id).await?;
    response
        .json::<DeriverAYaoSessionResponseV1>()
        .await
        .map_err(|_| invalid_lifecycle("Deriver A pair claim response is malformed"))
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
        DeriverAYaoSessionResponseV1::PairCompleted { execution } => Ok(*execution),
        DeriverAYaoSessionResponseV1::PairBurned { .. } => {
            Err(invalid_lifecycle("Deriver A pair execution was burned"))
        }
        DeriverAYaoSessionResponseV1::PairClaimed { .. } => Err(invalid_lifecycle(
            "Deriver A pair completion returned a claim response",
        )),
    }
}

async fn execute_deriver_a_pair_command(
    env: &Env,
    command: DeriverAYaoSessionCommandV1,
    trace_id: RoleTraceContextV1,
) -> RouterAbProtocolResult<Response> {
    command.validate()?;
    let session = match &command {
        DeriverAYaoSessionCommandV1::Execute { input }
        | DeriverAYaoSessionCommandV1::PreparePair { input, .. } => input.session(),
        DeriverAYaoSessionCommandV1::ClaimPair { pair_binding, .. } => pair_binding.session(),
        DeriverAYaoSessionCommandV1::CompletePair { execution, .. } => execution.session(),
        DeriverAYaoSessionCommandV1::ReadPairStatus { session, .. }
        | DeriverAYaoSessionCommandV1::BurnPair { session, .. } => *session,
    };
    let namespace = env
        .durable_object(DERIVER_A_YAO_SESSION_DO_BINDING)
        .map_err(|_| {
            invalid_lifecycle("Deriver A Yao session Durable Object binding is missing")
        })?;
    let stub = namespace
        .get_by_name(&encode_hex(session))
        .map_err(|_| invalid_lifecycle("Deriver A Yao session Durable Object lookup failed"))?;
    let body = serde_json::to_string(&command)
        .map_err(|_| invalid_lifecycle("Deriver A pair command encoding failed"))?;
    let mut init = worker::RequestInit::new();
    init.with_method(Method::Post)
        .with_body(Some(worker::wasm_bindgen::JsValue::from_str(&body)));
    let request = Request::new_with_init(DERIVER_A_YAO_SESSION_DO_URL, &init)
        .map_err(|_| invalid_lifecycle("Deriver A pair request construction failed"))?;
    if let Some(trace_id) = trace_id {
        set_cloudflare_trace_id_header_v1(request.headers(), trace_id)?;
    }
    let started_at_ms = role_span_started_at_ms();
    let mut response = stub
        .fetch_with_request(request)
        .await
        .map_err(|_| invalid_lifecycle("Deriver A pair Durable Object request failed"))?;
    if !(200..=299).contains(&response.status_code()) {
        emit_role_span_v1(
            trace_id,
            "deriver_a.session_do",
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
            "Deriver A pair Durable Object rejected the command with HTTP {}: {message}",
            response.status_code()
        )));
    }
    emit_role_span_v1(
        trace_id,
        "deriver_a.session_do",
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
    let metadata_call = runtime.root_share_startup_metadata_call(
        lifecycle.signer_set_id.clone(),
        lifecycle.root_share_epoch.clone(),
    )?;
    load_yao_root_metadata_digest(
        env,
        CloudflareWorkerRoleV1::DeriverA,
        runtime.root_share_wire_secret(),
        metadata_call,
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
    let metadata_call = runtime.root_share_startup_metadata_call(
        lifecycle.signer_set_id.clone(),
        lifecycle.root_share_epoch.clone(),
    )?;
    let started_at_ms = role_span_started_at_ms();
    let result = load_yao_root_with_metadata_digest(
        env,
        CloudflareWorkerRoleV1::DeriverA,
        runtime.root_share_wire_secret(),
        metadata_call,
        b"deriver-a",
    )
    .await;
    emit_role_span_v1(
        trace_id,
        "deriver_a.root_share",
        "deriver_a",
        "durable_object",
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
    let metadata_call = runtime.root_share_startup_metadata_call(
        lifecycle.signer_set_id.clone(),
        lifecycle.root_share_epoch.clone(),
    )?;
    load_yao_root_metadata_digest(
        env,
        CloudflareWorkerRoleV1::DeriverB,
        runtime.root_share_wire_secret(),
        metadata_call,
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
    let metadata_call = runtime.root_share_startup_metadata_call(
        lifecycle.signer_set_id.clone(),
        lifecycle.root_share_epoch.clone(),
    )?;
    let started_at_ms = role_span_started_at_ms();
    let result = load_yao_root_with_metadata_digest(
        env,
        CloudflareWorkerRoleV1::DeriverB,
        runtime.root_share_wire_secret(),
        metadata_call,
        b"deriver-b",
    )
    .await;
    emit_role_span_v1(
        trace_id,
        "deriver_b.root_share",
        "deriver_b",
        "durable_object",
        started_at_ms,
        if result.is_ok() { "success" } else { "failure" },
    );
    result
}

async fn load_yao_root_metadata_digest(
    env: &Env,
    worker_role: CloudflareWorkerRoleV1,
    root_share_secret: &crate::CloudflareRootShareWireSecretBindingV1,
    metadata_call: crate::CloudflareDurableObjectCallV1,
) -> RouterAbProtocolResult<[u8; 32]> {
    let response = execute_cloudflare_durable_object_call_v1(env, &metadata_call).await?;
    let CloudflareDurableObjectResponseV1::RootShareStartupMetadata { metadata } = response else {
        return Err(invalid_lifecycle(
            "root-share metadata initialization returned the wrong response",
        ));
    };
    load_cloudflare_root_share_wire_secret_v1(env, worker_role, root_share_secret, &metadata)?;
    root_metadata_digest_v1(&metadata)
}

async fn load_yao_root_with_metadata_digest(
    env: &Env,
    worker_role: CloudflareWorkerRoleV1,
    root_share_secret: &crate::CloudflareRootShareWireSecretBindingV1,
    metadata_call: crate::CloudflareDurableObjectCallV1,
    role_label: &[u8],
) -> RouterAbProtocolResult<([u8; 32], [u8; 32])> {
    let response = execute_cloudflare_durable_object_call_v1(env, &metadata_call).await?;
    let CloudflareDurableObjectResponseV1::RootShareStartupMetadata { metadata } = response else {
        return Err(invalid_lifecycle(
            "root-share metadata initialization returned the wrong response",
        ));
    };
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
    expected: Option<[u8; 32]>,
    actual: [u8; 32],
) -> RouterAbProtocolResult<()> {
    if let Some(expected) = expected {
        if expected != actual {
            return Err(invalid_lifecycle(
                "root-share metadata changed after pair preparation",
            ));
        }
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
    }
}

fn input_kind_for_circuit(family: Ed25519YaoCircuitFamilyV1) -> Ed25519YaoInputKindV1 {
    match family {
        Ed25519YaoCircuitFamilyV1::Activation => Ed25519YaoInputKindV1::Activation,
        Ed25519YaoCircuitFamilyV1::Export => Ed25519YaoInputKindV1::Export,
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

fn parse_role_trace_context(request: &Request) -> worker::Result<RoleTraceContextV1> {
    parse_cloudflare_trace_id_from_request_v1(request)
        .map_err(|error| worker::Error::RustError(error.message().to_owned()))
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
    }]);
    hasher.update(input.session());
    hasher.update(input.stable_context_binding());
    hasher.update(input.encapsulated_key());
    hasher.update((input.ciphertext().len() as u64).to_be_bytes());
    hasher.update(input.ciphertext());
    hasher.finalize().into()
}

fn encode_hex(bytes: [u8; 32]) -> String {
    const ALPHABET: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in bytes {
        output.push(char::from(ALPHABET[usize::from(byte >> 4)]));
        output.push(char::from(ALPHABET[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use router_ab_core::{
        Ed25519YaoCeremonyBindingV1, Ed25519YaoEncryptedPackageV1, Ed25519YaoInputPairBindingV1,
        Ed25519YaoPackageKindV1, Ed25519YaoSessionIdV1, Ed25519YaoStableKeyContextBindingV1,
        ExpensiveWorkKindV1, LifecycleScopeV1, PublicDigest32, RootShareEpoch,
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
    fn running_and_terminal_records_retain_no_staged_ciphertext() {
        let input = encrypted_input(4);
        let input_digest = yao_input_digest(&input);
        let staged = serde_json::to_value(YaoSessionRecordV1::Staged {
            input_digest,
            expires_at_ms: 70_000,
            input: Box::new(input),
        })
        .expect("staged record serializes");
        let running = serde_json::to_value(YaoSessionRecordV1::Running {
            input_digest,
            expires_at_ms: 30_000,
        })
        .expect("running record serializes");
        let failed = serde_json::to_value(YaoSessionRecordV1::Failed { input_digest })
            .expect("failed record serializes");
        let expired = serde_json::to_value(YaoSessionRecordV1::Expired { input_digest })
            .expect("expired record serializes");

        assert!(staged.get("input").is_some());
        assert!(running.get("input").is_none());
        assert!(failed.get("input").is_none());
        assert!(expired.get("input").is_none());
        assert_eq!(
            failed.get("status").and_then(|value| value.as_str()),
            Some("failed")
        );
        assert_eq!(
            expired.get("status").and_then(|value| value.as_str()),
            Some("expired")
        );
    }

    #[test]
    fn session_expiry_uses_checked_arithmetic() {
        assert_eq!(yao_expiry_from_now(10, 20).expect("expiry fits"), 30);
        assert!(yao_expiry_from_now(u64::MAX, 1).is_err());
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
        };
        assert!(matches!(
            completed_pair_record_if_running(
                &running,
                pair_digest,
                Some(input_digest),
                Some(execution_id),
                &execution,
                101,
            ),
            Some(PairYaoSessionRecordV1::Completed { .. })
        ));
        assert!(matches!(
            completed_pair_record_if_running(
                &running,
                pair_digest,
                Some(input_digest),
                Some(execution_id),
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
            Some(input_digest),
            Some(execution_id),
            &execution,
            101,
        )
        .is_none());
        assert!(completed_pair_record_if_running(
            &running,
            pair_digest,
            Some(input_digest),
            Some([16; 32]),
            &execution,
            101,
        )
        .is_none());
        assert!(completed_pair_record_if_running(
            &running,
            pair_digest,
            Some([17; 32]),
            None,
            &execution,
            101,
        )
        .is_none());
    }
}
