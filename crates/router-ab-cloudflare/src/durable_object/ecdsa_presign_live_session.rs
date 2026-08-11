use std::cell::RefCell;
use std::collections::BTreeMap;

use router_ab_ecdsa_presign::session::{
    derive_presign_pair_context, PresignSessionEvent, PresignSessionStage,
    SigningWorkerPresignSession,
};
use router_ab_ecdsa_presign::AdditiveKeyShare;
use router_ab_ecdsa_wire::{CompressedPointBytes, ScalarBytes};
use router_ab_core::{
    RouterAbEcdsaDerivationLinkedDeviceEvmDigestSigningPrepareResponseV1,
    RouterAbEcdsaDerivationSignatureSchemeV1,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{
    durable_object_error_status, RouterAbProtocolError, RouterAbProtocolErrorCode,
    RouterAbProtocolResult, CloudflareSigningWorkerEcdsaPresignatureRecordV1,
};
use crate::{
    ActiveSigningWorkerStateV1,
    cloudflare_now_unix_ms_v1, decode_base64url_bytes_v1, decode_base64url_fixed_32_v1,
    decode_base64url_fixed_33_v1, encode_base64url_bytes_v1, CloudflareSignerProofGetrandomRngV1,
    CloudflareSigningWorkerEcdsaPresignRequestedStageV1,
    CloudflareSigningWorkerEcdsaPresignSessionInitRequestV1,
    CloudflareSigningWorkerEcdsaPresignSessionStepRequestV1,
    CloudflareSigningWorkerLinkedDeviceEcdsaPresignSessionInitRequestV1,
    CloudflareSigningWorkerLinkedDeviceEcdsaPresignSessionStepRequestV1,
    CloudflareSigningWorkerRouterAbEcdsaDerivationPresignaturePoolPutRequestV1,
    RouterAbEcdsaDerivationLinkedDeviceNormalSigningScopeV1,
    RouterAbEcdsaDerivationNormalSigningScopeV1,
    CLOUDFLARE_SIGNING_WORKER_ECDSA_PRESIGN_SESSION_DO_INIT_PATH,
    CLOUDFLARE_SIGNING_WORKER_ECDSA_PRESIGN_SESSION_DO_STEP_PATH,
    CLOUDFLARE_SIGNING_WORKER_LINKED_ECDSA_PRESIGN_SESSION_DO_INIT_PATH,
    CLOUDFLARE_SIGNING_WORKER_LINKED_ECDSA_PRESIGN_SESSION_DO_STEP_PATH,
    CLOUDFLARE_SIGNING_WORKER_LINKED_ECDSA_PRESIGNATURE_DO_CONSUME_PATH,
    require_non_empty,
    require_positive_ms,
};

pub(super) struct CloudflareSigningWorkerEcdsaPresignLiveSessionV1 {
    scope: RouterAbEcdsaDerivationNormalSigningScopeV1,
    expires_at_ms: u64,
    session: SigningWorkerPresignSession,
}

pub(super) type CloudflareSigningWorkerEcdsaPresignLiveSessionsV1 =
    RefCell<BTreeMap<String, CloudflareSigningWorkerEcdsaPresignLiveSessionV1>>;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CloudflareSigningWorkerEcdsaPresignSessionDoInitRequestV1 {
    pub(crate) request: CloudflareSigningWorkerEcdsaPresignSessionInitRequestV1,
    pub(crate) relayer_share32_b64u: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum CloudflareSigningWorkerEcdsaPresignSessionDoProgressV1 {
    Continue {
        presign_session_id: String,
        stage: String,
        event: String,
        outgoing_messages_b64u: Vec<String>,
    },
    Complete {
        pool_put_request:
            CloudflareSigningWorkerRouterAbEcdsaDerivationPresignaturePoolPutRequestV1,
    },
}

pub(super) struct CloudflareSigningWorkerLinkedDeviceEcdsaPresignLiveSessionV1 {
    request: router_ab_core::RouterAbEcdsaDerivationLinkedDeviceEvmDigestSigningRequestV1,
    scope: RouterAbEcdsaDerivationLinkedDeviceNormalSigningScopeV1,
    expires_at_ms: u64,
    request_digest: router_ab_core::PublicDigest32,
    signing_digest: router_ab_core::PublicDigest32,
    active_signing_worker_state: ActiveSigningWorkerStateV1,
    session: SigningWorkerPresignSession,
}

pub(super) type CloudflareSigningWorkerLinkedDeviceEcdsaPresignLiveSessionsV1 =
    RefCell<BTreeMap<String, CloudflareSigningWorkerLinkedDeviceEcdsaPresignLiveSessionV1>>;

pub(super) struct CloudflareSigningWorkerLinkedDeviceEcdsaCompletedPresignatureRecordV1 {
    scope_digest: router_ab_core::PublicDigest32,
    record: CloudflareSigningWorkerEcdsaPresignatureRecordV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CloudflareSigningWorkerLinkedDeviceEcdsaPresignSessionDoInitRequestV1 {
    pub(crate) request: CloudflareSigningWorkerLinkedDeviceEcdsaPresignSessionInitRequestV1,
    pub(crate) active_signing_worker_state: ActiveSigningWorkerStateV1,
    pub(crate) relayer_share32_b64u: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CloudflareSigningWorkerLinkedDeviceEcdsaPresignatureDoConsumeRequestV1 {
    pub(crate) server_presignature_id: String,
    pub(crate) scope_digest: router_ab_core::PublicDigest32,
    pub(crate) request_digest: router_ab_core::PublicDigest32,
    pub(crate) signing_digest: router_ab_core::PublicDigest32,
    pub(crate) now_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum CloudflareSigningWorkerLinkedDeviceEcdsaPresignSessionDoProgressV1 {
    Continue {
        presign_session_id: String,
        stage: String,
        event: String,
        outgoing_messages_b64u: Vec<String>,
    },
    Complete {
        presign_session_id: String,
        server_presignature_id: String,
        server_big_r33_b64u: String,
        signing_worker_rerandomization_contribution32_b64u: String,
        prepared_response: RouterAbEcdsaDerivationLinkedDeviceEvmDigestSigningPrepareResponseV1,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CloudflareSigningWorkerLinkedDeviceEcdsaPresignatureDoConsumeResponseV1 {
    pub(crate) record: CloudflareSigningWorkerEcdsaPresignatureRecordV1,
}

#[cfg(feature = "workers-rs")]
pub(super) async fn handle_cloudflare_signing_worker_ecdsa_presign_session_do_fetch_v1(
    mut request: worker::Request,
    sessions: &CloudflareSigningWorkerEcdsaPresignLiveSessionsV1,
) -> worker::Result<worker::Response> {
    if request.method() != worker::Method::Post {
        return worker::Response::error("SigningWorker ECDSA presign session requires POST", 405);
    }
    let now_unix_ms = match cloudflare_now_unix_ms_v1() {
        Ok(value) => value,
        Err(error) => return presign_do_error_response(error),
    };
    let result = match request.path().as_str() {
        CLOUDFLARE_SIGNING_WORKER_ECDSA_PRESIGN_SESSION_DO_INIT_PATH => {
            let parsed = match request
                .json::<CloudflareSigningWorkerEcdsaPresignSessionDoInitRequestV1>()
                .await
            {
                Ok(value) => value,
                Err(error) => {
                    return worker::Response::error(
                        format!("SigningWorker ECDSA presign init JSON parse failed: {error}"),
                        400,
                    );
                }
            };
            create_presign_session(parsed, sessions, now_unix_ms)
        }
        CLOUDFLARE_SIGNING_WORKER_ECDSA_PRESIGN_SESSION_DO_STEP_PATH => {
            let parsed = match request
                .json::<CloudflareSigningWorkerEcdsaPresignSessionStepRequestV1>()
                .await
            {
                Ok(value) => value,
                Err(error) => {
                    return worker::Response::error(
                        format!("SigningWorker ECDSA presign step JSON parse failed: {error}"),
                        400,
                    );
                }
            };
            step_presign_session(parsed, sessions, now_unix_ms)
        }
        _ => {
            return worker::Response::error("SigningWorker ECDSA presign DO route not found", 404);
        }
    };
    match result {
        Ok(progress) => worker::Response::from_json(&progress),
        Err(error) => presign_do_error_response(error),
    }
}

fn create_presign_session(
    input: CloudflareSigningWorkerEcdsaPresignSessionDoInitRequestV1,
    sessions: &CloudflareSigningWorkerEcdsaPresignLiveSessionsV1,
    now_unix_ms: u64,
) -> RouterAbProtocolResult<CloudflareSigningWorkerEcdsaPresignSessionDoProgressV1> {
    input.request.validate_at(now_unix_ms)?;
    let relayer_share = decode_base64url_fixed_32_v1(
        "SigningWorker ECDSA presign relayer share",
        &input.relayer_share32_b64u,
    )?;
    let wallet_public_key = decode_base64url_fixed_33_v1(
        "SigningWorker ECDSA presign threshold public key",
        &input
            .request
            .scope
            .public_identity
            .threshold_public_key33_b64u,
    )?;
    let context = derive_presign_pair_context(
        CompressedPointBytes::new(wallet_public_key),
        &input.request.presign_session_id,
    )
    .map_err(presign_protocol_error)?;
    let key_share = AdditiveKeyShare::from_bytes(ScalarBytes::new(relayer_share))
        .map_err(presign_protocol_error)?;
    let session = SigningWorkerPresignSession::new(
        context,
        key_share,
        CompressedPointBytes::new(wallet_public_key),
        &mut CloudflareSignerProofGetrandomRngV1,
    )
    .map_err(presign_protocol_error)?;
    let mut sessions = sessions.borrow_mut();
    sessions.retain(|_, entry| entry.expires_at_ms > now_unix_ms);
    if sessions.contains_key(&input.request.presign_session_id) {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ReplayedLocalRequest,
            "SigningWorker ECDSA presign session id already exists",
        ));
    }
    let mut entry = CloudflareSigningWorkerEcdsaPresignLiveSessionV1 {
        scope: input.request.scope,
        expires_at_ms: input.request.expires_at_ms,
        session,
    };
    let progress = continue_progress(&input.request.presign_session_id, entry.session.poll());
    sessions.insert(input.request.presign_session_id, entry);
    Ok(progress)
}

fn step_presign_session(
    input: CloudflareSigningWorkerEcdsaPresignSessionStepRequestV1,
    sessions: &CloudflareSigningWorkerEcdsaPresignLiveSessionsV1,
    now_unix_ms: u64,
) -> RouterAbProtocolResult<CloudflareSigningWorkerEcdsaPresignSessionDoProgressV1> {
    input.validate_at(now_unix_ms)?;
    let mut entry = sessions
        .borrow_mut()
        .remove(&input.presign_session_id)
        .ok_or_else(|| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ExpiredLocalRequest,
                "SigningWorker ECDSA presign session is missing; restart pool fill",
            )
        })?;
    if entry.expires_at_ms <= now_unix_ms
        || entry.expires_at_ms != input.expires_at_ms
        || entry.scope != input.scope
    {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ExpiredLocalRequest,
            "SigningWorker ECDSA presign session scope or expiry mismatch",
        ));
    }

    let current_stage = entry.session.stage();
    match (input.requested_stage, current_stage) {
        (
            CloudflareSigningWorkerEcdsaPresignRequestedStageV1::Triples,
            PresignSessionStage::TriplesDone,
        ) => {
            let response = CloudflareSigningWorkerEcdsaPresignSessionDoProgressV1::Continue {
                presign_session_id: input.presign_session_id.clone(),
                stage: "triples_done".to_owned(),
                event: "triples_done".to_owned(),
                outgoing_messages_b64u: Vec::new(),
            };
            sessions
                .borrow_mut()
                .insert(input.presign_session_id, entry);
            return Ok(response);
        }
        (
            CloudflareSigningWorkerEcdsaPresignRequestedStageV1::Presign,
            PresignSessionStage::TriplesDone,
        ) => entry
            .session
            .start_presign()
            .map_err(presign_protocol_error)?,
        (
            CloudflareSigningWorkerEcdsaPresignRequestedStageV1::Presign,
            PresignSessionStage::Triples,
        ) => {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "SigningWorker ECDSA presign session has not finished triples",
            ));
        }
        (
            CloudflareSigningWorkerEcdsaPresignRequestedStageV1::Triples,
            PresignSessionStage::Triples,
        )
        | (
            CloudflareSigningWorkerEcdsaPresignRequestedStageV1::Presign,
            PresignSessionStage::Presign,
        ) => {}
        _ => {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "SigningWorker ECDSA presign session stage regression",
            ));
        }
    }

    for message_b64u in &input.outgoing_messages_b64u {
        let message =
            decode_base64url_bytes_v1("SigningWorker ECDSA presign message", message_b64u)?;
        entry
            .session
            .message(&message, &mut CloudflareSignerProofGetrandomRngV1)
            .map_err(presign_protocol_error)?;
    }
    let progress = entry.session.poll();
    if progress.event == PresignSessionEvent::PresignDone
        || progress.stage == PresignSessionStage::Done
    {
        let presignature = entry
            .session
            .take_presignature_97()
            .map_err(presign_protocol_error)?;
        if presignature.len() != 97 {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "SigningWorker ECDSA presign output must contain 97 bytes",
            ));
        }
        let big_r = &presignature[..33];
        let k_share = &presignature[33..65];
        let sigma_share = &presignature[65..97];
        let presignature_id = format!(
            "presig-{}",
            encode_base64url_bytes_v1(Sha256::digest(big_r).as_slice())
        );
        let pool_put_request =
            CloudflareSigningWorkerRouterAbEcdsaDerivationPresignaturePoolPutRequestV1::new(
                entry.scope,
                presignature_id,
                encode_base64url_bytes_v1(big_r),
                encode_base64url_bytes_v1(k_share),
                encode_base64url_bytes_v1(sigma_share),
                entry.expires_at_ms,
            )?;
        return Ok(
            CloudflareSigningWorkerEcdsaPresignSessionDoProgressV1::Complete { pool_put_request },
        );
    }
    let response = continue_progress(&input.presign_session_id, progress);
    sessions
        .borrow_mut()
        .insert(input.presign_session_id, entry);
    Ok(response)
}

fn continue_progress(
    presign_session_id: &str,
    progress: router_ab_ecdsa_presign::session::PresignSessionProgress,
) -> CloudflareSigningWorkerEcdsaPresignSessionDoProgressV1 {
    CloudflareSigningWorkerEcdsaPresignSessionDoProgressV1::Continue {
        presign_session_id: presign_session_id.to_owned(),
        stage: progress.stage.as_str().to_owned(),
        event: progress.event.as_str().to_owned(),
        outgoing_messages_b64u: progress
            .outgoing
            .iter()
            .map(|message| encode_base64url_bytes_v1(message))
            .collect(),
    }
}

#[cfg(feature = "workers-rs")]
pub(super) async fn handle_cloudflare_signing_worker_linked_ecdsa_presign_session_do_fetch_v1(
    mut request: worker::Request,
    sessions: &CloudflareSigningWorkerLinkedDeviceEcdsaPresignLiveSessionsV1,
    completed_records: &std::cell::RefCell<
        BTreeMap<String, CloudflareSigningWorkerLinkedDeviceEcdsaCompletedPresignatureRecordV1>,
    >,
) -> worker::Result<worker::Response> {
    if request.method() != worker::Method::Post {
        return worker::Response::error(
            "SigningWorker linked ECDSA presign session requires POST",
            405,
        );
    }
    let now_unix_ms = match cloudflare_now_unix_ms_v1() {
        Ok(value) => value,
        Err(error) => return presign_do_error_response(error),
    };
    if request.path().as_str() == CLOUDFLARE_SIGNING_WORKER_LINKED_ECDSA_PRESIGNATURE_DO_CONSUME_PATH {
        let parsed = match request
            .json::<CloudflareSigningWorkerLinkedDeviceEcdsaPresignatureDoConsumeRequestV1>()
            .await
        {
            Ok(value) => value,
            Err(error) => {
                return worker::Response::error(
                    format!("SigningWorker linked ECDSA presign consume JSON parse failed: {error}"),
                    400,
                );
            }
        };
        return match consume_linked_presignature(parsed, completed_records) {
            Ok(response) => worker::Response::from_json(&response),
            Err(error) => presign_do_error_response(error),
        };
    }
    let result = match request.path().as_str() {
        CLOUDFLARE_SIGNING_WORKER_LINKED_ECDSA_PRESIGN_SESSION_DO_INIT_PATH => {
            let parsed = match request
                .json::<CloudflareSigningWorkerLinkedDeviceEcdsaPresignSessionDoInitRequestV1>()
                .await
            {
                Ok(value) => value,
                Err(error) => {
                    return worker::Response::error(
                        format!("SigningWorker linked ECDSA presign init JSON parse failed: {error}"),
                        400,
                    );
                }
            };
            create_linked_presign_session(parsed, sessions, now_unix_ms)
        }
        CLOUDFLARE_SIGNING_WORKER_LINKED_ECDSA_PRESIGN_SESSION_DO_STEP_PATH => {
            let parsed = match request
                .json::<CloudflareSigningWorkerLinkedDeviceEcdsaPresignSessionStepRequestV1>()
                .await
            {
                Ok(value) => value,
                Err(error) => {
                    return worker::Response::error(
                        format!("SigningWorker linked ECDSA presign step JSON parse failed: {error}"),
                        400,
                    );
                }
            };
            step_linked_presign_session(parsed, sessions, completed_records, now_unix_ms)
        }
        _ => {
            return worker::Response::error(
                "SigningWorker linked ECDSA presign DO route not found",
                404,
            );
        }
    };
    match result {
        Ok(progress) => worker::Response::from_json(&progress),
        Err(error) => presign_do_error_response(error),
    }
}

fn create_linked_presign_session(
    input: CloudflareSigningWorkerLinkedDeviceEcdsaPresignSessionDoInitRequestV1,
    sessions: &CloudflareSigningWorkerLinkedDeviceEcdsaPresignLiveSessionsV1,
    now_unix_ms: u64,
) -> RouterAbProtocolResult<CloudflareSigningWorkerLinkedDeviceEcdsaPresignSessionDoProgressV1> {
    input.request.validate_at(now_unix_ms)?;
    let relayer_share = decode_base64url_fixed_32_v1(
        "linked SigningWorker ECDSA presign relayer share",
        &input.relayer_share32_b64u,
    )?;
    let wallet_public_key = decode_base64url_fixed_33_v1(
        "linked SigningWorker ECDSA presign threshold public key",
        &input.request.request.scope.threshold_public_key33_b64u,
    )?;
    let context = derive_presign_pair_context(
        CompressedPointBytes::new(wallet_public_key),
        &input.request.presign_session_id,
    )
    .map_err(presign_protocol_error)?;
    let key_share = AdditiveKeyShare::from_bytes(ScalarBytes::new(relayer_share))
        .map_err(presign_protocol_error)?;
    let session = SigningWorkerPresignSession::new(
        context,
        key_share,
        CompressedPointBytes::new(wallet_public_key),
        &mut CloudflareSignerProofGetrandomRngV1,
    )
    .map_err(presign_protocol_error)?;
    let request_digest = input.request.request.request_digest()?;
    let signing_digest = input.request.request.signing_digest()?;
    let linked_request = input.request.request;
    let scope = linked_request.scope.clone();
    let mut sessions = sessions.borrow_mut();
    sessions.retain(|_, entry| entry.expires_at_ms > now_unix_ms);
    if sessions.contains_key(&input.request.presign_session_id) {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ReplayedLocalRequest,
            "SigningWorker linked ECDSA presign session id already exists",
        ));
    }
    let session_id = input.request.presign_session_id.clone();
    let mut entry = CloudflareSigningWorkerLinkedDeviceEcdsaPresignLiveSessionV1 {
        request: linked_request,
        scope,
        expires_at_ms: input.request.expires_at_ms,
        request_digest,
        signing_digest,
        active_signing_worker_state: input.active_signing_worker_state,
        session,
    };
    let progress = linked_continue_progress(&session_id, entry.session.poll());
    sessions.insert(session_id, entry);
    Ok(progress)
}

fn step_linked_presign_session(
    input: CloudflareSigningWorkerLinkedDeviceEcdsaPresignSessionStepRequestV1,
    sessions: &CloudflareSigningWorkerLinkedDeviceEcdsaPresignLiveSessionsV1,
    completed_records: &std::cell::RefCell<
        BTreeMap<String, CloudflareSigningWorkerLinkedDeviceEcdsaCompletedPresignatureRecordV1>,
    >,
    now_unix_ms: u64,
) -> RouterAbProtocolResult<CloudflareSigningWorkerLinkedDeviceEcdsaPresignSessionDoProgressV1> {
    input.validate_at(now_unix_ms)?;
    let mut entry = sessions
        .borrow_mut()
        .remove(&input.presign_session_id)
        .ok_or_else(|| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ExpiredLocalRequest,
                "SigningWorker linked ECDSA presign session is missing; restart presign",
            )
        })?;
    if entry.expires_at_ms <= now_unix_ms
        || entry.expires_at_ms != input.expires_at_ms
        || entry.scope != input.request.scope
        || entry.request != input.request
        || entry.request_digest != input.request.request_digest()?
        || entry.signing_digest != input.request.signing_digest()?
    {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ExpiredLocalRequest,
            "SigningWorker linked ECDSA presign session binding does not match request",
        ));
    }

    let current_stage = entry.session.stage();
    match (input.requested_stage, current_stage) {
        (
            CloudflareSigningWorkerEcdsaPresignRequestedStageV1::Triples,
            PresignSessionStage::TriplesDone,
        ) => {
            let response = CloudflareSigningWorkerLinkedDeviceEcdsaPresignSessionDoProgressV1::Continue {
                presign_session_id: input.presign_session_id.clone(),
                stage: "triples_done".to_owned(),
                event: "triples_done".to_owned(),
                outgoing_messages_b64u: Vec::new(),
            };
            sessions.borrow_mut().insert(input.presign_session_id, entry);
            return Ok(response);
        }
        (
            CloudflareSigningWorkerEcdsaPresignRequestedStageV1::Presign,
            PresignSessionStage::TriplesDone,
        ) => entry
            .session
            .start_presign()
            .map_err(presign_protocol_error)?,
        (
            CloudflareSigningWorkerEcdsaPresignRequestedStageV1::Presign,
            PresignSessionStage::Triples,
        ) => {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "SigningWorker linked ECDSA presign session has not finished triples",
            ));
        }
        (
            CloudflareSigningWorkerEcdsaPresignRequestedStageV1::Triples,
            PresignSessionStage::Triples,
        )
        | (
            CloudflareSigningWorkerEcdsaPresignRequestedStageV1::Presign,
            PresignSessionStage::Presign,
        ) => {}
        _ => {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "SigningWorker linked ECDSA presign session stage regression",
            ));
        }
    }

    for message_b64u in &input.outgoing_messages_b64u {
        let message = decode_base64url_bytes_v1("linked ECDSA presign message", message_b64u)?;
        entry
            .session
            .message(&message, &mut CloudflareSignerProofGetrandomRngV1)
            .map_err(presign_protocol_error)?;
    }
    let progress = entry.session.poll();
    if progress.event == PresignSessionEvent::PresignDone
        || progress.stage == PresignSessionStage::Done
    {
        let presignature = entry
            .session
            .take_presignature_97()
            .map_err(presign_protocol_error)?;
        if presignature.len() != 97 {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "SigningWorker linked ECDSA presign output must contain 97 bytes",
            ));
        }
        let mut contribution = [0_u8; 32];
        getrandom::getrandom(&mut contribution).map_err(|_| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "SigningWorker linked ECDSA rerandomization RNG failed",
            )
        })?;
        let server_big_r33_b64u = encode_base64url_bytes_v1(&presignature[..33]);
        let server_presignature_id = entry.request.client_presignature_id.clone();
        let signing_worker_rerandomization_contribution32_b64u =
            encode_base64url_bytes_v1(&contribution);
        let record = CloudflareSigningWorkerEcdsaPresignatureRecordV1::new(
            entry.active_signing_worker_state.clone(),
            server_presignature_id.clone(),
            entry.request_digest,
            entry.signing_digest,
            server_big_r33_b64u.clone(),
            signing_worker_rerandomization_contribution32_b64u.clone(),
            encode_base64url_bytes_v1(&presignature[33..65]),
            encode_base64url_bytes_v1(&presignature[65..97]),
            now_unix_ms,
            entry.expires_at_ms,
        )?;
        let mut completed_records = completed_records.borrow_mut();
        completed_records.retain(|_, record| record.record.expires_at_ms > now_unix_ms);
        if completed_records.contains_key(&server_presignature_id) {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ReplayedLocalRequest,
                "linked ECDSA server presignature id already exists",
            ));
        }
        completed_records.insert(
            server_presignature_id.clone(),
            CloudflareSigningWorkerLinkedDeviceEcdsaCompletedPresignatureRecordV1 {
                scope_digest: entry.scope.scope_digest()?,
                record,
            },
        );
        let prepared_response =
            RouterAbEcdsaDerivationLinkedDeviceEvmDigestSigningPrepareResponseV1 {
                scope: entry.scope.clone(),
                request_id: entry.request.request_id.clone(),
                request_digest: entry.request_digest,
                signing_digest: entry.signing_digest,
                server_presignature_id: server_presignature_id.clone(),
                server_big_r33_b64u: server_big_r33_b64u.clone(),
                signing_worker_rerandomization_contribution32_b64u:
                    signing_worker_rerandomization_contribution32_b64u.clone(),
                signature_scheme:
                    RouterAbEcdsaDerivationSignatureSchemeV1::EcdsaSecp256k1RecoverableV1,
                prepared_at_ms: now_unix_ms,
                expires_at_ms: entry.expires_at_ms,
            };
        return Ok(
            CloudflareSigningWorkerLinkedDeviceEcdsaPresignSessionDoProgressV1::Complete {
                presign_session_id: input.presign_session_id,
                server_presignature_id,
                server_big_r33_b64u,
                signing_worker_rerandomization_contribution32_b64u,
                prepared_response,
            },
        );
    }
    let response = linked_continue_progress(&input.presign_session_id, progress);
    sessions
        .borrow_mut()
        .insert(input.presign_session_id, entry);
    Ok(response)
}

fn linked_continue_progress(
    presign_session_id: &str,
    progress: router_ab_ecdsa_presign::session::PresignSessionProgress,
) -> CloudflareSigningWorkerLinkedDeviceEcdsaPresignSessionDoProgressV1 {
    CloudflareSigningWorkerLinkedDeviceEcdsaPresignSessionDoProgressV1::Continue {
        presign_session_id: presign_session_id.to_owned(),
        stage: progress.stage.as_str().to_owned(),
        event: progress.event.as_str().to_owned(),
        outgoing_messages_b64u: progress
            .outgoing
            .iter()
            .map(|message| encode_base64url_bytes_v1(message))
            .collect(),
    }
}

fn consume_linked_presignature(
    input: CloudflareSigningWorkerLinkedDeviceEcdsaPresignatureDoConsumeRequestV1,
    completed_records: &std::cell::RefCell<
        BTreeMap<String, CloudflareSigningWorkerLinkedDeviceEcdsaCompletedPresignatureRecordV1>,
    >,
) -> RouterAbProtocolResult<CloudflareSigningWorkerLinkedDeviceEcdsaPresignatureDoConsumeResponseV1>
{
    require_non_empty("linked ECDSA server presignature id", &input.server_presignature_id)?;
    require_positive_ms("linked ECDSA presignature consume now_unix_ms", input.now_unix_ms)?;
    let mut records = completed_records.borrow_mut();
    records.retain(|_, record| record.record.expires_at_ms > input.now_unix_ms);
    let candidate = records.get(&input.server_presignature_id).ok_or_else(|| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ExpiredLocalRequest,
                "linked ECDSA presignature record is missing or already consumed",
            )
        })?;
    if candidate.scope_digest != input.scope_digest {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidGateDecision,
            "linked ECDSA presignature scope digest does not match finalize request",
        ));
    }
    candidate.record.validate_for_request(
        &candidate.record.active_signing_worker_state,
        &input.server_presignature_id,
        input.request_digest,
        input.signing_digest,
        input.now_unix_ms,
    )?;
    let record = records
        .remove(&input.server_presignature_id)
        .expect("validated linked ECDSA presignature record disappeared");
    Ok(CloudflareSigningWorkerLinkedDeviceEcdsaPresignatureDoConsumeResponseV1 {
        record: record.record,
    })
}

fn presign_protocol_error(error: impl std::fmt::Display) -> RouterAbProtocolError {
    RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::MalformedWirePayload,
        format!("SigningWorker ECDSA presign protocol rejected input: {error}"),
    )
}

#[cfg(feature = "workers-rs")]
fn presign_do_error_response(error: RouterAbProtocolError) -> worker::Result<worker::Response> {
    worker::Response::error(
        format!("{:?}: {}", error.code(), error.message()),
        durable_object_error_status(error.code()),
    )
}
