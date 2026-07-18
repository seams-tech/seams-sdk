use core::{fmt, future::Future};
use std::time::Duration;

use futures::future::{select, Either};
use router_ab_core::{
    Ed25519YaoDeriverRoleV1, Ed25519YaoEncryptedInputV1, Ed25519YaoInputKindV1,
    Ed25519YaoOperationV1, LifecycleScopeV1, RouterAbProtocolError, RouterAbProtocolErrorCode,
    RouterAbProtocolResult,
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
    CloudflareDeriverAWorkerRuntimeV1, CloudflareDeriverBWorkerRuntimeV1,
    CloudflareDurableObjectResponseV1, CloudflareEd25519YaoCircuitV1,
    CloudflareEd25519YaoWebSocketBindingV1, CloudflareEd25519YaoWebSocketTransportV1,
    CloudflareHpkeGetrandomRngV1, CloudflareWorkerRoleV1,
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

const DERIVER_A_YAO_SESSION_DO_BINDING: &str = "DERIVER_A_YAO_SESSION_DO";
const DERIVER_A_YAO_SESSION_DO_URL: &str = "https://deriver-a-yao-session.internal/execute";
const DERIVER_B_YAO_SESSION_DO_BINDING: &str = "DERIVER_B_YAO_SESSION_DO";
const DERIVER_B_YAO_SESSION_DO_URL: &str = "https://deriver-b-yao-session.internal/command";
const SESSION_RECORD_STORAGE_KEY: &str = "session-record-v1";
const YAO_CEREMONY_TIMEOUT: Duration = Duration::from_secs(15);
const YAO_STAGED_INPUT_LIFETIME_MS: u64 = 60_000;
const YAO_RUNNING_LIFETIME_MS: u64 = 20_000;
const YAO_RESULT_WAIT_INTERVAL: Duration = Duration::from_millis(5);
const YAO_RESULT_WAIT_ATTEMPTS: usize = 100;

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
enum DeriverAYaoSessionCommandV1 {
    Execute { input: Ed25519YaoEncryptedInputV1 },
}

impl DeriverAYaoSessionCommandV1 {
    fn input(&self) -> &Ed25519YaoEncryptedInputV1 {
        match self {
            Self::Execute { input } => input,
        }
    }

    fn validate(&self) -> RouterAbProtocolResult<()> {
        let input = self.input();
        input.validate()?;
        if input.deriver() != Ed25519YaoDeriverRoleV1::DeriverA {
            return Err(invalid_lifecycle(
                "Deriver A session storage accepts only Deriver A input",
            ));
        }
        Ok(())
    }
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
}

impl DeriverBYaoSessionCommandV1 {
    fn session(&self) -> [u8; 32] {
        match self {
            Self::Stage { input } => input.session(),
            Self::ReadStaged { session }
            | Self::Begin { session }
            | Self::Fail { session }
            | Self::ReadResult { session } => *session,
            Self::Complete { execution } => execution.session(),
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
        let command = request.json::<DeriverAYaoSessionCommandV1>().await?;
        if let Err(error) = command.validate() {
            return Response::error(error.message(), 400);
        }
        let DeriverAYaoSessionCommandV1::Execute { input } = command;
        let storage = self.state.storage();
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
        let execution = match execute_deriver_a_role(&self.env, &runtime, input).await {
            Ok(execution) => execution,
            Err(error) => {
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

#[worker::durable_object(fetch)]
pub struct RouterAbDeriverBYaoSessionDurableObject {
    state: State,
}

impl worker::DurableObject for RouterAbDeriverBYaoSessionDurableObject {
    fn new(state: State, _env: Env) -> Self {
        Self { state }
    }

    async fn fetch(&self, mut request: Request) -> worker::Result<Response> {
        if request.method() != Method::Post {
            return Response::error("method not allowed", 405);
        }
        let command = request.json::<DeriverBYaoSessionCommandV1>().await?;
        if let Err(error) = command.validate() {
            return Response::error(error.message(), 400);
        }
        let storage = self.state.storage();
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
        };
        Response::from_json(&response)
    }
}

pub async fn handle_cloudflare_ed25519_yao_deriver_a_start_v1(
    mut request: Request,
    env: &Env,
    expected_kind: Ed25519YaoInputKindV1,
) -> RouterAbProtocolResult<Response> {
    let input = parse_request::<Ed25519YaoEncryptedInputV1>(&mut request).await?;
    validate_deriver_input(&input, Ed25519YaoDeriverRoleV1::DeriverA, expected_kind)?;
    let execution = execute_deriver_a_session(env, input).await?;
    json_response(&execution)
}

async fn execute_deriver_a_role(
    env: &Env,
    runtime: &CloudflareDeriverAWorkerRuntimeV1,
    input: Ed25519YaoEncryptedInputV1,
) -> RouterAbProtocolResult<Ed25519YaoRoleExecutionV1> {
    let circuit = circuit_for_input(&input);
    let private_key =
        load_deriver_input_private_key(env, &runtime.envelope_decrypt_key().current.binding_name)?;
    let session = input.session();
    let binding = CloudflareEd25519YaoWebSocketBindingV1::new(circuit, session)
        .map_err(map_websocket_error)?;
    let socket = crate::connect_cloudflare_ed25519_yao_deriver_b_v1(env, binding)
        .await
        .map_err(map_websocket_error)?;
    let transport = CloudflareEd25519YaoWebSocketTransportV1::deriver_a(&socket, session)
        .map_err(map_websocket_error)?;
    let execution = match input.kind() {
        Ed25519YaoInputKindV1::Activation => {
            let role_request =
                open_ed25519_yao_activation_deriver_a_input_v1(&input, &private_key)?;
            let root =
                load_deriver_a_yao_root(env, runtime, &role_request.binding.lifecycle).await?;
            let recipients = role_request.recipients;
            let (binding, role) =
                build_product_activation_deriver_a_v1(root, role_request).map_err(map_adapter)?;
            let completion =
                with_yao_ceremony_timeout(run_activation_deriver_a(role, transport)).await?;
            seal_ed25519_yao_activation_deriver_a_execution_v1(
                &mut CloudflareHpkeGetrandomRngV1,
                binding,
                recipients,
                &completion.role,
            )?
        }
        Ed25519YaoInputKindV1::Export => {
            let role_request = open_ed25519_yao_export_deriver_a_input_v1(&input, &private_key)?;
            let root =
                load_deriver_a_yao_root(env, runtime, &role_request.binding.lifecycle).await?;
            let recipient = role_request.recipients;
            let (binding, role) =
                build_product_export_deriver_a_v1(root, role_request).map_err(map_adapter)?;
            let completion =
                with_yao_ceremony_timeout(run_export_deriver_a(role, transport)).await?;
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

pub async fn handle_cloudflare_ed25519_yao_deriver_b_stage_v1(
    mut request: Request,
    env: &Env,
    expected_kind: Ed25519YaoInputKindV1,
) -> RouterAbProtocolResult<Response> {
    let input = parse_request::<Ed25519YaoEncryptedInputV1>(&mut request).await?;
    validate_deriver_input(&input, Ed25519YaoDeriverRoleV1::DeriverB, expected_kind)?;
    let response = execute_deriver_b_session_command(
        env,
        DeriverBYaoSessionCommandV1::Stage {
            input: Box::new(input),
        },
    )
    .await?;
    json_response(&response)
}

pub async fn handle_cloudflare_ed25519_yao_deriver_b_result_v1(
    mut request: Request,
    env: &Env,
    expected_kind: Ed25519YaoInputKindV1,
) -> RouterAbProtocolResult<Response> {
    let request = parse_request::<CloudflareEd25519YaoResultRequestV1>(&mut request).await?;
    request.validate()?;
    if request.input_kind() != expected_kind {
        return Err(invalid_lifecycle(
            "Ed25519 Yao result family does not match the route",
        ));
    }
    let session_id = request.session_id();
    for attempt in 0..YAO_RESULT_WAIT_ATTEMPTS {
        let response = execute_deriver_b_session_command(
            env,
            DeriverBYaoSessionCommandV1::ReadResult {
                session: session_id,
            },
        )
        .await?;
        match response {
            DeriverBYaoSessionResponseV1::RoleExecution { execution } => {
                return json_response(&execution);
            }
            DeriverBYaoSessionResponseV1::Pending { .. }
                if attempt + 1 < YAO_RESULT_WAIT_ATTEMPTS =>
            {
                Delay::from(YAO_RESULT_WAIT_INTERVAL).await;
            }
            DeriverBYaoSessionResponseV1::Pending { .. } => {
                return Err(invalid_lifecycle(
                    "Deriver B role execution did not complete before result timeout",
                ));
            }
            DeriverBYaoSessionResponseV1::Failed { .. } => {
                return Err(invalid_lifecycle("Deriver B role execution failed"));
            }
            DeriverBYaoSessionResponseV1::Expired { .. } => {
                return Err(invalid_lifecycle("Deriver B role execution expired"));
            }
            DeriverBYaoSessionResponseV1::Staged { .. }
            | DeriverBYaoSessionResponseV1::StagedInput { .. }
            | DeriverBYaoSessionResponseV1::Running { .. }
            | DeriverBYaoSessionResponseV1::Completed { .. } => {
                return Err(invalid_lifecycle(
                    "Deriver B result lookup returned the wrong response",
                ));
            }
        }
    }
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
    let protocol = request
        .headers()
        .get("Sec-WebSocket-Protocol")
        .map_err(|_| invalid_lifecycle("WebSocket protocol header could not be read"))?
        .ok_or_else(|| invalid_lifecycle("WebSocket protocol header is missing"))?;
    let binding = CloudflareEd25519YaoWebSocketBindingV1::parse_protocol(&protocol)
        .map_err(map_websocket_error)?;
    let staged = execute_deriver_b_session_command(
        &env,
        DeriverBYaoSessionCommandV1::ReadStaged {
            session: binding.session,
        },
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
        let result = execute_deriver_b_role(&env, &runtime, *input, server).await;
        if let Err(error) = result {
            worker::console_error!(
                "Deriver B Ed25519 Yao role execution failed for session {}: {}",
                encode_hex(session),
                error
            );
            let _ignored = execute_deriver_b_session_command(
                &env,
                DeriverBYaoSessionCommandV1::Fail { session },
            )
            .await;
            let _ignored = server_for_error.close(Some(1011), Some("yao-lifecycle-failed"));
        }
    });
    Ok(response)
}

async fn execute_deriver_b_role(
    env: &Env,
    runtime: &CloudflareDeriverBWorkerRuntimeV1,
    input: Ed25519YaoEncryptedInputV1,
    socket: worker::WebSocket,
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
            let root =
                load_deriver_b_yao_root(env, runtime, &role_request.binding.lifecycle).await?;
            let recipients = role_request.recipients;
            let (binding, role) =
                build_product_activation_deriver_b_v1(root, role_request).map_err(map_adapter)?;
            let completion =
                with_yao_ceremony_timeout(run_activation_deriver_b(role, transport)).await?;
            seal_ed25519_yao_activation_deriver_b_execution_v1(
                &mut CloudflareHpkeGetrandomRngV1,
                binding,
                recipients,
                &completion.role,
            )?
        }
        Ed25519YaoInputKindV1::Export => {
            let role_request = open_ed25519_yao_export_deriver_b_input_v1(&input, &private_key)?;
            let root =
                load_deriver_b_yao_root(env, runtime, &role_request.binding.lifecycle).await?;
            let recipient = role_request.recipients;
            let (binding, role) =
                build_product_export_deriver_b_v1(root, role_request).map_err(map_adapter)?;
            let completion =
                with_yao_ceremony_timeout(run_export_deriver_b(role, transport)).await?;
            seal_ed25519_yao_export_deriver_b_execution_v1(
                &mut CloudflareHpkeGetrandomRngV1,
                binding,
                recipient,
                &completion.role,
            )?
        }
    };
    execute_deriver_b_session_command(
        env,
        DeriverBYaoSessionCommandV1::Complete {
            execution: Box::new(execution),
        },
    )
    .await?;
    Ok(())
}

async fn execute_deriver_b_session_command(
    env: &Env,
    command: DeriverBYaoSessionCommandV1,
) -> RouterAbProtocolResult<DeriverBYaoSessionResponseV1> {
    command.validate()?;
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
    let mut response = stub
        .fetch_with_request(request)
        .await
        .map_err(|_| invalid_lifecycle("Deriver B Yao session Durable Object request failed"))?;
    if !(200..=299).contains(&response.status_code()) {
        return Err(invalid_lifecycle(
            "Deriver B Yao session Durable Object rejected the command",
        ));
    }
    response
        .json::<DeriverBYaoSessionResponseV1>()
        .await
        .map_err(|_| invalid_lifecycle("Deriver B Yao session response is malformed"))
}

async fn execute_deriver_a_session(
    env: &Env,
    input: Ed25519YaoEncryptedInputV1,
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
    let mut response = stub
        .fetch_with_request(request)
        .await
        .map_err(|_| invalid_lifecycle("Deriver A Yao session Durable Object request failed"))?;
    let status = response.status_code();
    if !(200..=299).contains(&status) {
        let message = response
            .text()
            .await
            .unwrap_or_else(|_| "response body unavailable".to_owned());
        return Err(invalid_lifecycle(format!(
            "Deriver A Yao session Durable Object rejected the command with HTTP {status}: {message}"
        )));
    }
    let execution = response
        .json::<Ed25519YaoRoleExecutionV1>()
        .await
        .map_err(|_| invalid_lifecycle("Deriver A Yao session response is malformed"))?;
    execution.validate()?;
    if execution.deriver() != Ed25519YaoDeriverRoleV1::DeriverA || execution.session() != session {
        return Err(invalid_lifecycle(
            "Deriver A Yao session response identity is invalid",
        ));
    }
    Ok(execution)
}

async fn load_deriver_a_yao_root(
    env: &Env,
    runtime: &CloudflareDeriverAWorkerRuntimeV1,
    lifecycle: &LifecycleScopeV1,
) -> RouterAbProtocolResult<[u8; 32]> {
    lifecycle.validate()?;
    let metadata_call = runtime.root_share_startup_metadata_call(
        lifecycle.signer_set_id.clone(),
        lifecycle.root_share_epoch.clone(),
    )?;
    load_yao_root(
        env,
        CloudflareWorkerRoleV1::DeriverA,
        runtime.root_share_wire_secret(),
        metadata_call,
        b"deriver-a",
    )
    .await
}

async fn load_deriver_b_yao_root(
    env: &Env,
    runtime: &CloudflareDeriverBWorkerRuntimeV1,
    lifecycle: &LifecycleScopeV1,
) -> RouterAbProtocolResult<[u8; 32]> {
    lifecycle.validate()?;
    let metadata_call = runtime.root_share_startup_metadata_call(
        lifecycle.signer_set_id.clone(),
        lifecycle.root_share_epoch.clone(),
    )?;
    load_yao_root(
        env,
        CloudflareWorkerRoleV1::DeriverB,
        runtime.root_share_wire_secret(),
        metadata_call,
        b"deriver-b",
    )
    .await
}

async fn load_yao_root(
    env: &Env,
    worker_role: CloudflareWorkerRoleV1,
    root_share_secret: &crate::CloudflareRootShareWireSecretBindingV1,
    metadata_call: crate::CloudflareDurableObjectCallV1,
    role_label: &[u8],
) -> RouterAbProtocolResult<[u8; 32]> {
    let response = execute_cloudflare_durable_object_call_v1(env, &metadata_call).await?;
    let CloudflareDurableObjectResponseV1::RootShareStartupMetadata { metadata } = response else {
        return Err(invalid_lifecycle(
            "root-share metadata initialization returned the wrong response",
        ));
    };
    let wire =
        load_cloudflare_root_share_wire_secret_v1(env, worker_role, root_share_secret, &metadata)?;
    let signing_root_share_wire = wire.signing_root_share_wire();
    let mut hasher = Sha256::new();
    hasher.update(b"seams/router-ab/ed25519-yao/derivation-root/v1");
    hasher.update(role_label);
    hasher.update(signing_root_share_wire.as_bytes());
    Ok(hasher.finalize().into())
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
}
