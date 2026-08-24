use super::*;
use crate::hpke::{
    parse_cloudflare_hpke_x25519_public_key_v1, CloudflareHpkeGetrandomRngV1, CloudflareHpkeKemV1,
    CloudflareHpkeSuiteV1,
};
use hpke_ng::Kem;
use serde::de::DeserializeOwned;
use wasm_bindgen::JsValue;
use worker::{D1Database, D1DatabaseSession, D1SessionConstraint, Env, Method, Request, Response};

pub const SIGNING_WORKER_PRIVATE_D1_BINDING_V1: &str = "SIGNING_WORKER_PRIVATE_DB";
pub const SIGNING_WORKER_PRIVATE_D1_KEK_SECRET_V1: &str = "SIGNING_WORKER_PRIVATE_D1_KEK";
pub const SIGNING_WORKER_PRIVATE_D1_KEK_VERSION_ENV_V1: &str =
    "SIGNING_WORKER_PRIVATE_D1_KEK_VERSION";
pub const SIGNING_WORKER_PRIVATE_D1_KEK_PUBLIC_KEY_ENV_V1: &str =
    "SIGNING_WORKER_PRIVATE_D1_KEK_PUBLIC_KEY";
pub const SIGNING_WORKER_PRIVATE_D1_ENVIRONMENT_ENV_V1: &str =
    "SIGNING_WORKER_PRIVATE_D1_ENVIRONMENT";
const SIGNING_WORKER_PRIVATE_D1_HPKE_INFO_V1: &[u8] = b"seams/signing-worker/private-d1/hpke/v1";
const SIGNING_WORKER_PRIVATE_D1_SCHEMA_LABEL_V1: &str = "signing-worker-private-d1/v1";

pub const SIGNING_WORKER_PRIVATE_D1_SCHEMA_V1: &str = r#"
CREATE TABLE IF NOT EXISTS signing_worker_activations (
  material_key TEXT PRIMARY KEY,
  active_key TEXT NOT NULL UNIQUE,
  record_json TEXT NOT NULL,
  active_state_json TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS signing_worker_activation_revocation_fences (
  active_key TEXT PRIMARY KEY
);
CREATE TABLE IF NOT EXISTS signing_worker_round1 (
  record_key TEXT PRIMARY KEY,
  record_json TEXT NOT NULL,
  expires_at_ms INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS signing_worker_round1_expiry
  ON signing_worker_round1(expires_at_ms);
CREATE TABLE IF NOT EXISTS signing_worker_ecdsa_pool (
  record_key TEXT PRIMARY KEY,
  record_json TEXT NOT NULL,
  version INTEGER NOT NULL,
  cleanup_deadline_ms INTEGER
);
CREATE INDEX IF NOT EXISTS signing_worker_ecdsa_pool_expiry
  ON signing_worker_ecdsa_pool(cleanup_deadline_ms);
CREATE TABLE IF NOT EXISTS signing_worker_terminal_responses (
  operation_key TEXT PRIMARY KEY,
  request_digest_hex TEXT NOT NULL,
  response_json TEXT NOT NULL,
  committed_at_ms INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS signing_worker_effect_claims (
  operation_key TEXT PRIMARY KEY,
  authorization_key TEXT NOT NULL UNIQUE,
  request_digest_hex TEXT NOT NULL,
  authorization_json TEXT NOT NULL,
  claimed_at_ms INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS signing_worker_secret_states (
  purpose TEXT NOT NULL,
  record_key TEXT NOT NULL,
  ciphertext_json TEXT NOT NULL,
  version INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY(purpose, record_key)
);
CREATE TABLE IF NOT EXISTS signing_worker_lane_material (
  operation_key TEXT PRIMARY KEY,
  activation_id TEXT NOT NULL UNIQUE,
  wallet_key_id TEXT NOT NULL,
  target_lane_id TEXT NOT NULL,
  target_lane_share_epoch TEXT NOT NULL,
  identity_digest_b64u TEXT NOT NULL,
  record_json TEXT NOT NULL,
  version INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  UNIQUE(wallet_key_id, target_lane_id, target_lane_share_epoch)
);"#;

#[derive(Debug, Deserialize)]
struct ActivationRowV1 {
    record_json: String,
    active_state_json: String,
}

#[derive(Debug, Deserialize)]
struct JsonRowV1 {
    record_json: String,
}

#[derive(Debug, Deserialize)]
struct VersionedJsonRowV1 {
    record_json: String,
    version: i64,
}

#[derive(Debug, Deserialize)]
struct VersionedSecretJsonRowV1 {
    record_json: String,
    version: i64,
    updated_at_ms: u64,
}

#[derive(Debug, Deserialize)]
struct TerminalResponseRowV1 {
    request_digest_hex: String,
    response_json: String,
}

#[derive(Debug, Deserialize)]
struct EffectClaimRowV1 {
    operation_key: String,
    request_digest_hex: String,
    authorization_json: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CloudflareSigningWorkerTerminalResponseCommitV1 {
    Committed,
    Replay { response_json: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CloudflareSigningWorkerNearEffectClaimV1 {
    Claimed,
    InProgress,
    Replay { terminal_json: String },
}

pub(crate) struct CloudflareSigningWorkerPrivateD1VersionedSecretV1<T> {
    pub(crate) value: T,
    pub(crate) version: i64,
    pub(crate) updated_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SigningWorkerPrivateD1CiphertextV1 {
    key_version: String,
    ciphertext_b64u: String,
}

struct SigningWorkerPrivateD1CipherV1 {
    environment: String,
    key_version: String,
    public_key: <CloudflareHpkeKemV1 as Kem>::PublicKey,
    private_key: <CloudflareHpkeKemV1 as Kem>::PrivateKey,
}

impl SigningWorkerPrivateD1CipherV1 {
    fn from_env(env: &Env) -> RouterAbProtocolResult<Self> {
        let environment = required_env_var_v1(env, SIGNING_WORKER_PRIVATE_D1_ENVIRONMENT_ENV_V1)?;
        let key_version = required_env_var_v1(env, SIGNING_WORKER_PRIVATE_D1_KEK_VERSION_ENV_V1)?;
        let encoded_public_key =
            required_env_var_v1(env, SIGNING_WORKER_PRIVATE_D1_KEK_PUBLIC_KEY_ENV_V1)?;
        let public_key = parse_cloudflare_hpke_x25519_public_key_v1(&encoded_public_key)?;
        let secret = env
            .secret(SIGNING_WORKER_PRIVATE_D1_KEK_SECRET_V1)
            .map_err(|error| {
                map_d1_error("SigningWorker private D1 KEK secret is missing", error)
            })?;
        let mut encoded_private_key = secret.to_string();
        let mut private_key_bytes =
            decode_cloudflare_server_output_hpke_private_key_secret_v1(&encoded_private_key)?;
        encoded_private_key.zeroize();
        let private_key_result = CloudflareHpkeKemV1::sk_from_bytes(&private_key_bytes)
            .map_err(|error| d1_error(format!("SigningWorker private D1 KEK is invalid: {error}")));
        private_key_bytes.zeroize();
        let private_key = private_key_result?;
        Ok(Self {
            environment,
            key_version,
            public_key,
            private_key,
        })
    }

    fn seal<T: Serialize>(
        &self,
        purpose: &'static str,
        identity: &str,
        value: &T,
    ) -> RouterAbProtocolResult<String> {
        let mut plaintext = encode_json("SigningWorker private D1 secret", value)?;
        let aad = self.aad(purpose, identity);
        let mut rng = CloudflareHpkeGetrandomRngV1;
        let sealed = CloudflareHpkeSuiteV1::seal_base(
            &mut rng,
            &self.public_key,
            SIGNING_WORKER_PRIVATE_D1_HPKE_INFO_V1,
            aad.as_bytes(),
            plaintext.as_bytes(),
        );
        plaintext.zeroize();
        let (encapped_key, ciphertext) = sealed.map_err(|error| {
            d1_error(format!(
                "SigningWorker private D1 secret encryption failed: {error}"
            ))
        })?;
        let mut payload = Vec::with_capacity(encapped_key.as_ref().len() + ciphertext.len());
        payload.extend_from_slice(encapped_key.as_ref());
        payload.extend_from_slice(&ciphertext);
        encode_json(
            "SigningWorker private D1 ciphertext",
            &SigningWorkerPrivateD1CiphertextV1 {
                key_version: self.key_version.clone(),
                ciphertext_b64u: encode_base64url_bytes_v1(&payload),
            },
        )
    }

    fn open<T: DeserializeOwned>(
        &self,
        purpose: &'static str,
        identity: &str,
        encoded: &str,
    ) -> RouterAbProtocolResult<T> {
        let envelope = decode_json::<SigningWorkerPrivateD1CiphertextV1>(
            "SigningWorker private D1 ciphertext",
            encoded,
        )?;
        if envelope.key_version != self.key_version {
            return Err(d1_error(
                "SigningWorker private D1 ciphertext key version is unavailable",
            ));
        }
        let payload = decode_base64url_bytes_v1(
            "SigningWorker private D1 ciphertext",
            &envelope.ciphertext_b64u,
        )?;
        if payload.len() <= CloudflareHpkeKemV1::ENCAPPED_KEY_LEN {
            return Err(d1_error("SigningWorker private D1 ciphertext is truncated"));
        }
        let (encapped_key, ciphertext) = payload.split_at(CloudflareHpkeKemV1::ENCAPPED_KEY_LEN);
        let encapped_key = CloudflareHpkeKemV1::enc_from_bytes(encapped_key).map_err(|error| {
            d1_error(format!(
                "SigningWorker private D1 encapsulated key is invalid: {error}"
            ))
        })?;
        let aad = self.aad(purpose, identity);
        let plaintext = CloudflareHpkeSuiteV1::open_base(
            &encapped_key,
            &self.private_key,
            SIGNING_WORKER_PRIVATE_D1_HPKE_INFO_V1,
            aad.as_bytes(),
            ciphertext,
        )
        .map_err(|error| {
            d1_error(format!(
                "SigningWorker private D1 secret decryption failed: {error}"
            ))
        })?;
        let mut plaintext = String::from_utf8(plaintext)
            .map_err(|_| d1_error("SigningWorker private D1 plaintext is not UTF-8"))?;
        let decoded = decode_json("SigningWorker private D1 secret", &plaintext);
        plaintext.zeroize();
        decoded
    }

    fn aad(&self, purpose: &'static str, identity: &str) -> String {
        format!(
            "environment={};purpose={};schema={};identity={}",
            self.environment, purpose, SIGNING_WORKER_PRIVATE_D1_SCHEMA_LABEL_V1, identity
        )
    }
}

fn required_env_var_v1(env: &Env, name: &'static str) -> RouterAbProtocolResult<String> {
    let value = env
        .var(name)
        .map_err(|error| map_d1_error("SigningWorker private D1 config is missing", error))?
        .to_string();
    require_non_empty(name, &value)?;
    Ok(value)
}

fn d1_error(message: impl Into<String>) -> RouterAbProtocolError {
    RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
        message,
    )
}

fn map_d1_error(context: &'static str, error: worker::Error) -> RouterAbProtocolError {
    d1_error(format!("{context}: {error}"))
}

fn encode_json<T: Serialize>(label: &'static str, value: &T) -> RouterAbProtocolResult<String> {
    serde_json::to_string(value)
        .map_err(|error| d1_error(format!("{label} serialization failed: {error}")))
}

fn decode_json<T: DeserializeOwned>(label: &'static str, value: &str) -> RouterAbProtocolResult<T> {
    serde_json::from_str(value)
        .map_err(|error| d1_error(format!("{label} decoding failed: {error}")))
}

fn js_string(value: &str) -> JsValue {
    JsValue::from_str(value)
}

fn js_u64(label: &'static str, value: u64) -> RouterAbProtocolResult<JsValue> {
    let value = i64::try_from(value)
        .map_err(|_| d1_error(format!("{label} exceeds the D1 INTEGER range")))?;
    Ok(JsValue::from_f64(value as f64))
}

fn private_d1_digest_hex_v1(digest: PublicDigest32) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(64);
    for byte in digest.as_bytes() {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn d1_changes(result: &worker::D1Result) -> RouterAbProtocolResult<usize> {
    result
        .meta()
        .map_err(|error| map_d1_error("SigningWorker private D1 metadata read failed", error))?
        .and_then(|meta| meta.changes)
        .ok_or_else(|| d1_error("SigningWorker private D1 result omitted change metadata"))
}

pub fn signing_worker_private_d1_from_env_v1(env: &Env) -> RouterAbProtocolResult<D1Database> {
    env.d1(SIGNING_WORKER_PRIVATE_D1_BINDING_V1)
        .map_err(|error| map_d1_error("SigningWorker private D1 binding is missing", error))
}

pub async fn commit_cloudflare_signing_worker_terminal_response_v1(
    env: &Env,
    operation_key: &str,
    request_digest: PublicDigest32,
    response_json: &str,
    committed_at_ms: u64,
) -> RouterAbProtocolResult<CloudflareSigningWorkerTerminalResponseCommitV1> {
    require_non_empty("SigningWorker terminal operation_key", operation_key)?;
    require_non_empty("SigningWorker terminal response_json", response_json)?;
    require_positive_ms("SigningWorker terminal committed_at_ms", committed_at_ms)?;
    let request_digest_hex = private_d1_digest_hex_v1(request_digest);
    let database = signing_worker_private_d1_from_env_v1(env)?;
    let session = database
        .with_session_constraint(D1SessionConstraint::FirstPrimary)
        .map_err(|error| map_d1_error("SigningWorker private D1 primary session failed", error))?;
    let result = session
        .prepare(
            "INSERT OR IGNORE INTO signing_worker_terminal_responses
             (operation_key, request_digest_hex, response_json, committed_at_ms)
             VALUES (?1, ?2, ?3, ?4)",
        )
        .bind(&[
            js_string(operation_key),
            js_string(&request_digest_hex),
            js_string(response_json),
            js_u64("SigningWorker terminal timestamp", committed_at_ms)?,
        ])
        .map_err(|error| map_d1_error("SigningWorker terminal insert bind failed", error))?
        .run()
        .await
        .map_err(|error| map_d1_error("SigningWorker terminal insert failed", error))?;
    if d1_changes(&result)? == 1 {
        return Ok(CloudflareSigningWorkerTerminalResponseCommitV1::Committed);
    }
    let stored = session
        .prepare(
            "SELECT request_digest_hex, response_json
             FROM signing_worker_terminal_responses
             WHERE operation_key = ?1",
        )
        .bind(&[js_string(operation_key)])
        .map_err(|error| map_d1_error("SigningWorker terminal replay query bind failed", error))?
        .first::<TerminalResponseRowV1>(None)
        .await
        .map_err(|error| map_d1_error("SigningWorker terminal replay query failed", error))?
        .ok_or_else(|| d1_error("SigningWorker terminal conflict has no stored response"))?;
    if stored.request_digest_hex != request_digest_hex {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ReplayedLocalRequest,
            "SigningWorker terminal operation key was reused for different request material",
        ));
    }
    Ok(CloudflareSigningWorkerTerminalResponseCommitV1::Replay {
        response_json: stored.response_json,
    })
}

async fn load_cloudflare_signing_worker_terminal_response_v1(
    session: &D1DatabaseSession,
    operation_key: &str,
    request_digest_hex: &str,
) -> RouterAbProtocolResult<Option<String>> {
    let stored = session
        .prepare(
            "SELECT request_digest_hex, response_json
             FROM signing_worker_terminal_responses
             WHERE operation_key = ?1",
        )
        .bind(&[js_string(operation_key)])
        .map_err(|error| map_d1_error("SigningWorker terminal lookup bind failed", error))?
        .first::<TerminalResponseRowV1>(None)
        .await
        .map_err(|error| map_d1_error("SigningWorker terminal lookup failed", error))?;
    let Some(stored) = stored else {
        return Ok(None);
    };
    if stored.request_digest_hex != request_digest_hex {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ReplayedLocalRequest,
            "SigningWorker terminal operation key was reused for different request material",
        ));
    }
    Ok(Some(stored.response_json))
}

/// Reads an exact terminal result before applying fresh-request checks.
pub async fn replay_cloudflare_signing_worker_near_terminal_v1(
    env: &Env,
    request: &CloudflareSigningWorkerAdmittedNormalSigningFinalizeRequestV2,
) -> RouterAbProtocolResult<Option<String>> {
    request.validate()?;
    let operation_key = request.effect_operation_key()?;
    let request_digest_hex = private_d1_digest_hex_v1(request.effect_request_digest()?);
    let database = signing_worker_private_d1_from_env_v1(env)?;
    let session = database
        .with_session_constraint(D1SessionConstraint::FirstPrimary)
        .map_err(|error| map_d1_error("SigningWorker effect replay session failed", error))?;
    load_cloudflare_signing_worker_terminal_response_v1(
        &session,
        &operation_key,
        &request_digest_hex,
    )
    .await
}

async fn claim_cloudflare_signing_worker_authorization_effect_v1(
    session: &D1DatabaseSession,
    operation_key: &str,
    authorization_key: &str,
    request_digest_hex: &str,
    authorization_json: &str,
    claimed_at_ms: u64,
) -> RouterAbProtocolResult<CloudflareSigningWorkerNearEffectClaimV1> {
    let result = session
        .prepare(
            "INSERT OR IGNORE INTO signing_worker_effect_claims
             (operation_key, authorization_key, request_digest_hex, authorization_json, claimed_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5)",
        )
        .bind(&[
            js_string(operation_key),
            js_string(authorization_key),
            js_string(request_digest_hex),
            js_string(authorization_json),
            js_u64("SigningWorker effect claim timestamp", claimed_at_ms)?,
        ])
        .map_err(|error| map_d1_error("SigningWorker effect claim bind failed", error))?
        .run()
        .await
        .map_err(|error| map_d1_error("SigningWorker effect claim failed", error))?;
    if d1_changes(&result)? == 1 {
        return Ok(CloudflareSigningWorkerNearEffectClaimV1::Claimed);
    }
    let stored = session
        .prepare(
            "SELECT operation_key, request_digest_hex, authorization_json
             FROM signing_worker_effect_claims
             WHERE authorization_key = ?1 OR operation_key = ?2
             LIMIT 1",
        )
        .bind(&[js_string(authorization_key), js_string(operation_key)])
        .map_err(|error| map_d1_error("SigningWorker effect replay bind failed", error))?
        .first::<EffectClaimRowV1>(None)
        .await
        .map_err(|error| map_d1_error("SigningWorker effect replay failed", error))?
        .ok_or_else(|| d1_error("SigningWorker effect conflict has no stored claim"))?;
    if stored.operation_key == operation_key
        && stored.request_digest_hex == request_digest_hex
        && stored.authorization_json == authorization_json
    {
        return Ok(CloudflareSigningWorkerNearEffectClaimV1::InProgress);
    }
    Err(RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::ReplayedLocalRequest,
        "SigningWorker effect operation key was reused for different request material",
    ))
}

/// Claims one NEAR signing effect before any cryptographic state is consumed.
pub async fn claim_cloudflare_signing_worker_near_effect_v1(
    env: &Env,
    request: &CloudflareSigningWorkerAdmittedNormalSigningFinalizeRequestV2,
    claimed_at_ms: u64,
) -> RouterAbProtocolResult<CloudflareSigningWorkerNearEffectClaimV1> {
    request.validate()?;
    require_positive_ms("SigningWorker effect claimed_at_ms", claimed_at_ms)?;
    let operation_key = request.effect_operation_key()?;
    let request_digest_hex = private_d1_digest_hex_v1(request.effect_request_digest()?);
    let database = signing_worker_private_d1_from_env_v1(env)?;
    let session = database
        .with_session_constraint(D1SessionConstraint::FirstPrimary)
        .map_err(|error| map_d1_error("SigningWorker effect primary session failed", error))?;
    if let Some(response_json) = load_cloudflare_signing_worker_terminal_response_v1(
        &session,
        &operation_key,
        &request_digest_hex,
    )
    .await?
    {
        return Ok(CloudflareSigningWorkerNearEffectClaimV1::Replay {
            terminal_json: response_json,
        });
    }
    request.request.validate_at(claimed_at_ms)?;
    match &request.effect_claim {
        CloudflareSigningWorkerNormalSigningEffectClaimV1::ReusableWalletSession { claim } => {
            let authorization_json =
                encode_json("SigningWorker effect authorization", &request.effect_claim)?;
            let authorization_key = format!(
                "reusable-wallet-session/{}/{}/{}/{}/{}",
                claim.authorization_id,
                claim.wallet_session_id,
                claim.authorized_operation_id,
                claim.operation_id,
                claim.operation_fingerprint_digest
            );
            claim_cloudflare_signing_worker_authorization_effect_v1(
                &session,
                &operation_key,
                &authorization_key,
                &request_digest_hex,
                &authorization_json,
                claimed_at_ms,
            )
            .await
        }
        CloudflareSigningWorkerNormalSigningEffectClaimV1::OperationStepUp {
            authorization_session_id,
            authorized_operation_id,
            operation_id,
            operation_fingerprint_digest,
            ..
        } => {
            let authorization_json =
                encode_json("SigningWorker effect authorization", &request.effect_claim)?;
            let authorization_key =
                format!(
                    "operation-step-up/{authorization_session_id}/{authorized_operation_id}/{operation_id}/{operation_fingerprint_digest}"
                );
            claim_cloudflare_signing_worker_authorization_effect_v1(
                &session,
                &operation_key,
                &authorization_key,
                &request_digest_hex,
                &authorization_json,
                claimed_at_ms,
            )
            .await
        }
    }
}

/// Reads an exact ECDSA terminal result before applying fresh-request checks.
pub async fn replay_cloudflare_signing_worker_ecdsa_terminal_v1(
    env: &Env,
    request: &CloudflareSigningWorkerAdmittedRouterAbEcdsaDerivationEvmDigestFinalizeRequestV1,
) -> RouterAbProtocolResult<Option<String>> {
    request.validate()?;
    let operation_key = request.effect_operation_key()?;
    let request_digest_hex = private_d1_digest_hex_v1(request.effect_request_digest()?);
    let database = signing_worker_private_d1_from_env_v1(env)?;
    let session = database
        .with_session_constraint(D1SessionConstraint::FirstPrimary)
        .map_err(|error| map_d1_error("SigningWorker ECDSA effect replay session failed", error))?;
    load_cloudflare_signing_worker_terminal_response_v1(
        &session,
        &operation_key,
        &request_digest_hex,
    )
    .await
}

/// Claims one ECDSA signing effect before presignature material is consumed.
pub async fn claim_cloudflare_signing_worker_ecdsa_effect_v1(
    env: &Env,
    request: &CloudflareSigningWorkerAdmittedRouterAbEcdsaDerivationEvmDigestFinalizeRequestV1,
    claimed_at_ms: u64,
) -> RouterAbProtocolResult<CloudflareSigningWorkerNearEffectClaimV1> {
    request.validate()?;
    require_positive_ms("SigningWorker ECDSA effect claimed_at_ms", claimed_at_ms)?;
    let operation_key = request.effect_operation_key()?;
    let request_digest_hex = private_d1_digest_hex_v1(request.effect_request_digest()?);
    let database = signing_worker_private_d1_from_env_v1(env)?;
    let session = database
        .with_session_constraint(D1SessionConstraint::FirstPrimary)
        .map_err(|error| {
            map_d1_error("SigningWorker ECDSA effect primary session failed", error)
        })?;
    if let Some(response_json) = load_cloudflare_signing_worker_terminal_response_v1(
        &session,
        &operation_key,
        &request_digest_hex,
    )
    .await?
    {
        return Ok(CloudflareSigningWorkerNearEffectClaimV1::Replay {
            terminal_json: response_json,
        });
    }
    request.request.validate_at(claimed_at_ms)?;
    let authorization_json = encode_json(
        "SigningWorker ECDSA effect authorization",
        &request.effect_claim,
    )?;
    let authorization_key = match &request.effect_claim {
        CloudflareSigningWorkerNormalSigningEffectClaimV1::ReusableWalletSession { claim } => {
            format!(
                "ecdsa-reusable-wallet-session/{}/{}/{}/{}/{}",
                claim.authorization_id,
                claim.wallet_session_id,
                claim.authorized_operation_id,
                claim.operation_id,
                claim.operation_fingerprint_digest
            )
        }
        CloudflareSigningWorkerNormalSigningEffectClaimV1::OperationStepUp {
            authorization_session_id,
            authorized_operation_id,
            operation_id,
            operation_fingerprint_digest,
            ..
        } => format!(
            "ecdsa-operation-step-up/{authorization_session_id}/{authorized_operation_id}/{operation_id}/{operation_fingerprint_digest}"
        ),
    };
    claim_cloudflare_signing_worker_authorization_effect_v1(
        &session,
        &operation_key,
        &authorization_key,
        &request_digest_hex,
        &authorization_json,
        claimed_at_ms,
    )
    .await
}

pub async fn put_cloudflare_signing_worker_output_activation_record_v1(
    env: &Env,
    record: &CloudflareSigningWorkerOutputActivationRecordV1,
    created_at_ms: u64,
) -> RouterAbProtocolResult<bool> {
    record.validate()?;
    let active_state = record.active_signing_worker_state();
    let material_key = active_state.signing_worker_material_handle.clone();
    let active_key = format!(
        "active-signing-worker/{}/{}/{}",
        active_state.account_id,
        active_state.material_activation.activation_id,
        active_state.signing_worker.server_id
    );
    let database = signing_worker_private_d1_from_env_v1(env)?;
    let session = database
        .with_session_constraint(D1SessionConstraint::FirstPrimary)
        .map_err(|error| map_d1_error("SigningWorker private D1 primary session failed", error))?;
    let cipher = SigningWorkerPrivateD1CipherV1::from_env(env)?;
    let record_json = cipher.seal("activation", &material_key, record)?;
    let active_state_json = encode_json("SigningWorker active state", active_state)?;
    let inserted = session
        .prepare(
            "INSERT OR IGNORE INTO signing_worker_activations
             (material_key, active_key, record_json, active_state_json, created_at_ms)
             SELECT ?1, ?2, ?3, ?4, ?5
             WHERE NOT EXISTS (
               SELECT 1
               FROM signing_worker_activation_revocation_fences
               WHERE active_key = ?2
             )",
        )
        .bind(&[
            js_string(&material_key),
            js_string(&active_key),
            js_string(&record_json),
            js_string(&active_state_json),
            js_u64("SigningWorker activation timestamp", created_at_ms)?,
        ])
        .map_err(|error| map_d1_error("SigningWorker activation insert bind failed", error))?
        .run()
        .await
        .map_err(|error| map_d1_error("SigningWorker activation insert failed", error))?;
    let activated = d1_changes(&inserted)? == 1;
    if activated {
        return Ok(true);
    }
    if activation_revocation_fence_exists_v1(&session, &active_key).await? {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ReplayedLocalRequest,
            "SigningWorker activation is fenced by an exact deactivation",
        ));
    }
    let stored = activation_row_by_material_key_v1(&session, &material_key)
        .await?
        .ok_or_else(|| d1_error("SigningWorker activation insert did not produce a record"))?;
    let stored_record = cipher.open::<CloudflareSigningWorkerOutputActivationRecordV1>(
        "activation",
        &material_key,
        &stored.record_json,
    )?;
    let stored_active_state_json = encode_json(
        "SigningWorker stored active state",
        stored_record.active_signing_worker_state(),
    )?;
    if !stored_record.matches_activation_and_material(record)
        || stored.active_state_json != stored_active_state_json
    {
        return Err(d1_error(
            "server-output activation conflicts with existing activation or material",
        ));
    }
    Ok(false)
}

/// Deletes one exact active output row for a lifecycle deactivation. Missing
/// rows are an idempotent replay; callers validate the durable lifecycle fence.
pub(crate) async fn delete_cloudflare_signing_worker_output_activation_by_active_key_v1(
    env: &Env,
    active_key: &str,
    expected_material_activation: &MpcMaterialActivationRefV1,
) -> RouterAbProtocolResult<bool> {
    require_non_empty("SigningWorker activation active_key", active_key)?;
    expected_material_activation.validate()?;
    let database = signing_worker_private_d1_from_env_v1(env)?;
    let session = database
        .with_session_constraint(D1SessionConstraint::FirstPrimary)
        .map_err(|error| map_d1_error("SigningWorker activation primary session failed", error))?;
    if let Some(row) = activation_row_by_active_key_v1(&session, active_key).await? {
        let active_state = decode_json::<ActiveSigningWorkerStateV1>(
            "SigningWorker active state",
            &row.active_state_json,
        )?;
        if active_state.material_activation != *expected_material_activation {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ConflictingPair,
                "SigningWorker activation identity conflicts with the exact material activation",
            ));
        }
    }
    session
        .prepare(
            "INSERT OR IGNORE INTO signing_worker_activation_revocation_fences
             (active_key) VALUES (?1)",
        )
        .bind(&[js_string(active_key)])
        .map_err(|error| map_d1_error("SigningWorker activation fence bind failed", error))?
        .run()
        .await
        .map_err(|error| map_d1_error("SigningWorker activation fence failed", error))?;
    let result = session
        .prepare("DELETE FROM signing_worker_activations WHERE active_key = ?1")
        .bind(&[js_string(active_key)])
        .map_err(|error| map_d1_error("SigningWorker activation delete bind failed", error))?
        .run()
        .await
        .map_err(|error| map_d1_error("SigningWorker activation delete failed", error))?;
    Ok(d1_changes(&result)? == 1)
}

async fn activation_revocation_fence_exists_v1(
    db: &D1DatabaseSession,
    active_key: &str,
) -> RouterAbProtocolResult<bool> {
    #[derive(Debug, Deserialize)]
    struct ActivationRevocationFenceRowV1 {
        #[serde(rename = "active_key")]
        _active_key: String,
    }

    Ok(db
        .prepare(
            "SELECT active_key
             FROM signing_worker_activation_revocation_fences
             WHERE active_key = ?1",
        )
        .bind(&[js_string(active_key)])
        .map_err(|error| map_d1_error("SigningWorker activation fence query bind failed", error))?
        .first::<ActivationRevocationFenceRowV1>(None)
        .await
        .map_err(|error| map_d1_error("SigningWorker activation fence query failed", error))?
        .is_some())
}

pub(crate) async fn load_cloudflare_signing_worker_private_d1_secret_v1<T>(
    env: &Env,
    purpose: &'static str,
    record_key: &str,
) -> RouterAbProtocolResult<Option<CloudflareSigningWorkerPrivateD1VersionedSecretV1<T>>>
where
    T: DeserializeOwned,
{
    require_non_empty("SigningWorker private D1 secret record_key", record_key)?;
    let database = signing_worker_private_d1_from_env_v1(env)?;
    let session = database
        .with_session_constraint(D1SessionConstraint::FirstPrimary)
        .map_err(|error| map_d1_error("SigningWorker private D1 primary session failed", error))?;
    let row = session
        .prepare(
            "SELECT ciphertext_json AS record_json, version, updated_at_ms
             FROM signing_worker_secret_states
             WHERE purpose = ?1 AND record_key = ?2",
        )
        .bind(&[js_string(purpose), js_string(record_key)])
        .map_err(|error| map_d1_error("SigningWorker secret-state query bind failed", error))?
        .first::<VersionedSecretJsonRowV1>(None)
        .await
        .map_err(|error| map_d1_error("SigningWorker secret-state query failed", error))?;
    let Some(row) = row else {
        return Ok(None);
    };
    let cipher = SigningWorkerPrivateD1CipherV1::from_env(env)?;
    Ok(Some(CloudflareSigningWorkerPrivateD1VersionedSecretV1 {
        value: cipher.open(purpose, record_key, &row.record_json)?,
        version: row.version,
        updated_at_ms: row.updated_at_ms,
    }))
}

pub(crate) async fn compare_and_set_cloudflare_signing_worker_private_d1_secret_v1<T>(
    env: &Env,
    purpose: &'static str,
    record_key: &str,
    expected_version: Option<i64>,
    value: &T,
    updated_at_ms: u64,
) -> RouterAbProtocolResult<()>
where
    T: Serialize,
{
    require_non_empty("SigningWorker private D1 secret record_key", record_key)?;
    require_positive_ms(
        "SigningWorker private D1 secret updated_at_ms",
        updated_at_ms,
    )?;
    let database = signing_worker_private_d1_from_env_v1(env)?;
    let session = database
        .with_session_constraint(D1SessionConstraint::FirstPrimary)
        .map_err(|error| map_d1_error("SigningWorker private D1 primary session failed", error))?;
    let cipher = SigningWorkerPrivateD1CipherV1::from_env(env)?;
    let ciphertext = cipher.seal(purpose, record_key, value)?;
    let result = match expected_version {
        None => session
            .prepare(
                "INSERT OR IGNORE INTO signing_worker_secret_states
                 (purpose, record_key, ciphertext_json, version, updated_at_ms)
                 VALUES (?1, ?2, ?3, 1, ?4)",
            )
            .bind(&[
                js_string(purpose),
                js_string(record_key),
                js_string(&ciphertext),
                js_u64("SigningWorker secret-state timestamp", updated_at_ms)?,
            ]),
        Some(version) => session
            .prepare(
                "UPDATE signing_worker_secret_states
                 SET ciphertext_json = ?1, version = version + 1, updated_at_ms = ?2
                 WHERE purpose = ?3 AND record_key = ?4 AND version = ?5",
            )
            .bind(&[
                js_string(&ciphertext),
                js_u64("SigningWorker secret-state timestamp", updated_at_ms)?,
                js_string(purpose),
                js_string(record_key),
                JsValue::from_f64(version as f64),
            ]),
    }
    .map_err(|error| map_d1_error("SigningWorker secret-state write bind failed", error))?
    .run()
    .await
    .map_err(|error| map_d1_error("SigningWorker secret-state write failed", error))?;
    if d1_changes(&result)? != 1 {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ConflictingPair,
            "SigningWorker private D1 secret state changed concurrently",
        ));
    }
    Ok(())
}

async fn signing_worker_lane_material_row_v1(
    db: &D1DatabaseSession,
    operation_key: &str,
) -> RouterAbProtocolResult<Option<VersionedJsonRowV1>> {
    db.prepare(
        "SELECT record_json, version
         FROM signing_worker_lane_material
         WHERE operation_key = ?1",
    )
    .bind(&[js_string(operation_key)])
    .map_err(|error| map_d1_error("SigningWorker lane material query bind failed", error))?
    .first(None)
    .await
    .map_err(|error| map_d1_error("SigningWorker lane material query failed", error))
}

async fn load_signing_worker_lane_material_record_v1(
    db: &D1DatabaseSession,
    cipher: &SigningWorkerPrivateD1CipherV1,
    identity: &CloudflareSigningWorkerLaneMaterialIdentityV1,
) -> RouterAbProtocolResult<CloudflareSigningWorkerLaneMaterialRecordV1> {
    identity.validate()?;
    let row = signing_worker_lane_material_row_v1(db, &identity.operation_id)
        .await?
        .ok_or_else(|| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MissingLocalBinding,
                "SigningWorker lane material is missing",
            )
        })?;
    let record = cipher.open::<CloudflareSigningWorkerLaneMaterialRecordV1>(
        "lane_material",
        &identity.operation_id,
        &row.record_json,
    )?;
    record.validate()?;
    if record.identity != *identity {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ReplayedLocalRequest,
            "SigningWorker lane operation was reused for different identity material",
        ));
    }
    Ok(record)
}

/// Loads the exact holder-only redelivery payload for an authenticated claim.
pub async fn load_cloudflare_signing_worker_lane_holder_redelivery_v1(
    env: &Env,
    identity: &CloudflareSigningWorkerLaneMaterialIdentityV1,
) -> RouterAbProtocolResult<CloudflareSigningWorkerLaneHolderRedeliveryV1> {
    let database = signing_worker_private_d1_from_env_v1(env)?;
    let db = database
        .with_session_constraint(D1SessionConstraint::FirstPrimary)
        .map_err(|error| map_d1_error("SigningWorker lane primary session failed", error))?;
    let cipher = SigningWorkerPrivateD1CipherV1::from_env(env)?;
    load_signing_worker_lane_material_record_v1(&db, &cipher, identity)
        .await?
        .holder_redelivery()
}

/// Loads active server material only while the exact lane is active and unretired.
pub async fn load_cloudflare_signing_worker_active_lane_material_v1(
    env: &Env,
    identity: &CloudflareSigningWorkerLaneMaterialIdentityV1,
) -> RouterAbProtocolResult<(CloudflareSigningWorkerLaneArtifactV1, u64)> {
    let database = signing_worker_private_d1_from_env_v1(env)?;
    let db = database
        .with_session_constraint(D1SessionConstraint::FirstPrimary)
        .map_err(|error| map_d1_error("SigningWorker lane primary session failed", error))?;
    let cipher = SigningWorkerPrivateD1CipherV1::from_env(env)?;
    load_signing_worker_lane_material_record_v1(&db, &cipher, identity)
        .await?
        .active_server_material_with_activation()
}

/// Loads an encrypted lane record by operation before any replayed crypto runs.
pub async fn load_cloudflare_signing_worker_lane_material_record_by_operation_v1(
    env: &Env,
    operation_id: &str,
) -> RouterAbProtocolResult<Option<CloudflareSigningWorkerLaneMaterialRecordV1>> {
    require_non_empty("SigningWorker lane replay operation_id", operation_id)?;
    let database = signing_worker_private_d1_from_env_v1(env)?;
    let db = database
        .with_session_constraint(D1SessionConstraint::FirstPrimary)
        .map_err(|error| map_d1_error("SigningWorker lane primary session failed", error))?;
    let Some(row) = signing_worker_lane_material_row_v1(&db, operation_id).await? else {
        return Ok(None);
    };
    let cipher = SigningWorkerPrivateD1CipherV1::from_env(env)?;
    let record = cipher.open::<CloudflareSigningWorkerLaneMaterialRecordV1>(
        "lane_material",
        operation_id,
        &row.record_json,
    )?;
    record.validate()?;
    Ok(Some(record))
}

/// Resolves one original registration activation into its exact private share.
pub async fn load_cloudflare_signing_worker_registration_active_material_v1(
    env: &Env,
    lookup: &CloudflareActiveSigningWorkerStateLookupV1,
) -> RouterAbProtocolResult<CloudflareServerOutputMaterialRecordV1> {
    lookup.validate()?;
    let database = signing_worker_private_d1_from_env_v1(env)?;
    let db = database
        .with_session_constraint(D1SessionConstraint::FirstPrimary)
        .map_err(|error| map_d1_error("SigningWorker activation primary session failed", error))?;
    let active_key = format!(
        "active-signing-worker/{}/{}/{}",
        lookup.account_id, lookup.material_activation_id, lookup.signing_worker_id
    );
    let row = activation_row_by_active_key_v1(&db, &active_key)
        .await?
        .ok_or_else(|| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MissingLocalBinding,
                "active ECDSA registration source material is missing",
            )
        })?;
    let active_state = decode_json::<ActiveSigningWorkerStateV1>(
        "SigningWorker active state",
        &row.active_state_json,
    )?;
    lookup.validate_active_state(&active_state)?;
    crate::ordinary_inactive_signer_material::require_ecdsa_material_active_v1(
        env,
        &active_state.material_activation,
    )
    .await?;
    crate::ed25519_yao_signing_worker::require_ed25519_material_active_v1(
        env,
        &active_state.material_activation,
    )
    .await?;
    let cipher = SigningWorkerPrivateD1CipherV1::from_env(env)?;
    let record = cipher.open::<CloudflareSigningWorkerOutputActivationRecordV1>(
        "activation",
        &active_state.signing_worker_material_handle,
        &row.record_json,
    )?;
    record.validate()?;
    if record.active_signing_worker_state() != &active_state {
        return Err(d1_error(
            "ECDSA registration source material does not match its active state",
        ));
    }
    Ok(record.into_material())
}

/// Resolves an admitted normal-signing lookup through the active-lane fence.
pub async fn load_cloudflare_signing_worker_normal_signing_lane_material_v1(
    env: &Env,
    lookup: &CloudflareSigningWorkerNormalSigningLaneMaterialLookupV1,
) -> RouterAbProtocolResult<(CloudflareSigningWorkerLaneArtifactV1, u64)> {
    lookup.validate()?;
    load_cloudflare_signing_worker_active_lane_material_v1(env, &lookup.identity).await
}

/// Applies one exact lane-material command against SigningWorker-private D1.
pub async fn execute_cloudflare_signing_worker_lane_material_command_v1(
    env: &Env,
    command: &CloudflareSigningWorkerLaneMaterialCommandV1,
) -> RouterAbProtocolResult<CloudflareSigningWorkerLaneMaterialEffectV1> {
    command.validate()?;
    let identity = command.identity();
    let identity_digest_b64u = identity.digest_b64u()?;
    let operation_key = identity.operation_id.clone();
    let database = signing_worker_private_d1_from_env_v1(env)?;
    let db = database
        .with_session_constraint(D1SessionConstraint::FirstPrimary)
        .map_err(|error| map_d1_error("SigningWorker lane primary session failed", error))?;
    let cipher = SigningWorkerPrivateD1CipherV1::from_env(env)?;
    for _ in 0..4 {
        let current = signing_worker_lane_material_row_v1(&db, &operation_key).await?;
        let current_record = current
            .as_ref()
            .map(|row| {
                cipher.open::<CloudflareSigningWorkerLaneMaterialRecordV1>(
                    "lane_material",
                    &operation_key,
                    &row.record_json,
                )
            })
            .transpose()?;
        let mutation = apply_cloudflare_signing_worker_lane_material_command_v1(
            current_record,
            command.clone(),
        )?;
        if !mutation.changed {
            return project_cloudflare_signing_worker_lane_material_effect_v1(&mutation, command);
        }
        let record_json = cipher.seal("lane_material", &operation_key, &mutation.record)?;
        let write = match current {
            None => db
                .prepare(
                    "INSERT OR IGNORE INTO signing_worker_lane_material
                     (operation_key, activation_id, wallet_key_id, target_lane_id,
                      target_lane_share_epoch, identity_digest_b64u, record_json, version,
                      updated_at_ms)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1, ?8)",
                )
                .bind(&[
                    js_string(&operation_key),
                    js_string(&identity.target_material_activation_id),
                    js_string(&identity.wallet_key_id),
                    js_string(&identity.target_lane_id),
                    js_string(&identity.target_lane_share_epoch),
                    js_string(&identity_digest_b64u),
                    js_string(&record_json),
                    js_u64(
                        "SigningWorker lane material timestamp",
                        command.updated_at_ms(),
                    )?,
                ]),
            Some(row) => db
                .prepare(
                    "UPDATE signing_worker_lane_material
                     SET record_json = ?1, version = version + 1, updated_at_ms = ?2
                     WHERE operation_key = ?3 AND identity_digest_b64u = ?4 AND version = ?5",
                )
                .bind(&[
                    js_string(&record_json),
                    js_u64(
                        "SigningWorker lane material timestamp",
                        command.updated_at_ms(),
                    )?,
                    js_string(&operation_key),
                    js_string(&identity_digest_b64u),
                    JsValue::from_f64(row.version as f64),
                ]),
        }
        .map_err(|error| map_d1_error("SigningWorker lane material write bind failed", error))?
        .run()
        .await
        .map_err(|error| map_d1_error("SigningWorker lane material write failed", error))?;
        if d1_changes(&write)? == 1 {
            return project_cloudflare_signing_worker_lane_material_effect_v1(&mutation, command);
        }
        if signing_worker_lane_material_row_v1(&db, &operation_key)
            .await?
            .is_none()
        {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ReplayedLocalRequest,
                "SigningWorker lane activation or lane epoch is already owned by another operation",
            ));
        }
    }
    Err(RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::ConflictingPair,
        "SigningWorker lane material changed concurrently",
    ))
}

/// Applies one authenticated private lane-material command and returns its
/// receipt-only effect projection.
pub async fn handle_cloudflare_signing_worker_lane_material_command_private_fetch_v1(
    mut request: Request,
    env: &Env,
) -> worker::Result<Response> {
    if let Err(error) = crate::require_cloudflare_internal_service_auth_request_v1(&request, env) {
        return crate::cloudflare_private_service_auth_error_response_v1(error);
    }
    if request.method() != Method::Post {
        return Response::error(
            "SigningWorker lane-material command route requires POST",
            405,
        );
    }
    let command = match request
        .json::<CloudflareSigningWorkerLaneMaterialCommandV1>()
        .await
    {
        Ok(command) => command,
        Err(error) => {
            return Response::error(
                format!("SigningWorker lane-material command JSON is malformed: {error}"),
                400,
            )
        }
    };
    match execute_cloudflare_signing_worker_lane_material_command_v1(env, &command).await {
        Ok(effect) => Response::from_json(&effect),
        Err(error) => Response::error(
            format!("{:?}: {}", error.code(), error.message()),
            crate::cloudflare_router_error_status(error.code()),
        ),
    }
}

async fn activation_row_by_material_key_v1(
    db: &D1DatabaseSession,
    material_key: &str,
) -> RouterAbProtocolResult<Option<ActivationRowV1>> {
    db.prepare(
        "SELECT record_json, active_state_json
         FROM signing_worker_activations
         WHERE material_key = ?1",
    )
    .bind(&[js_string(material_key)])
    .map_err(|error| map_d1_error("SigningWorker activation query bind failed", error))?
    .first(None)
    .await
    .map_err(|error| map_d1_error("SigningWorker activation query failed", error))
}

async fn activation_row_by_active_key_v1(
    db: &D1DatabaseSession,
    active_key: &str,
) -> RouterAbProtocolResult<Option<ActivationRowV1>> {
    db.prepare(
        "SELECT record_json, active_state_json
         FROM signing_worker_activations
         WHERE active_key = ?1",
    )
    .bind(&[js_string(active_key)])
    .map_err(|error| map_d1_error("SigningWorker active-state query bind failed", error))?
    .first(None)
    .await
    .map_err(|error| map_d1_error("SigningWorker active-state query failed", error))
}

async fn activate_output_v1(
    db: &D1DatabaseSession,
    cipher: &SigningWorkerPrivateD1CipherV1,
    request: &CloudflareSigningWorkerPrivateD1RequestV1,
    activation: &CloudflareSigningWorkerRecipientProofBundleActivationRequestV1,
    material: &CloudflareServerOutputMaterialRecordV1,
    activated_at_ms: u64,
) -> RouterAbProtocolResult<CloudflareSigningWorkerPrivateD1ResponseV1> {
    let material_key = request.storage_key();
    let active_key = request.active_state_index_key()?;
    let active_state = cloudflare_active_signing_worker_state_from_activation_request_v1(
        activation,
        activation.material_activation.clone(),
        material_key.clone(),
        activated_at_ms,
    )?;
    let record = CloudflareSigningWorkerOutputActivationRecordV1::new(
        activation.clone(),
        active_state.clone(),
        material.clone(),
    )?;
    let record_json = cipher.seal("activation", &material_key, &record)?;
    let active_state_json = encode_json("SigningWorker active state", &active_state)?;
    let inserted = db
        .prepare(
            "INSERT OR IGNORE INTO signing_worker_activations
             (material_key, active_key, record_json, active_state_json, created_at_ms)
             SELECT ?1, ?2, ?3, ?4, ?5
             WHERE NOT EXISTS (
               SELECT 1
               FROM signing_worker_activation_revocation_fences
               WHERE active_key = ?2
             )",
        )
        .bind(&[
            js_string(&material_key),
            js_string(&active_key),
            js_string(&record_json),
            js_string(&active_state_json),
            js_u64("SigningWorker activation timestamp", activated_at_ms)?,
        ])
        .map_err(|error| map_d1_error("SigningWorker activation insert bind failed", error))?
        .run()
        .await
        .map_err(|error| map_d1_error("SigningWorker activation insert failed", error))?;
    let activated = d1_changes(&inserted)? == 1;
    let activation_context = &activation.activation_context;
    let selected_server = &activation_context.signer_set().selected_server;
    if !activated && activation_revocation_fence_exists_v1(db, &active_key).await? {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ReplayedLocalRequest,
            "SigningWorker activation is fenced by an exact deactivation",
        ));
    }
    if activated {
        return Ok(
            CloudflareSigningWorkerPrivateD1ResponseV1::OutputActivated {
                receipt: CloudflareSigningWorkerOutputActivationReceiptV1::new(
                    activation_context.lifecycle().lifecycle_id.clone(),
                    selected_server.server_id.clone(),
                    activation_context.transcript_digest(),
                    active_state,
                    true,
                )?,
            },
        );
    }
    let stored = activation_row_by_material_key_v1(db, &material_key)
        .await?
        .ok_or_else(|| d1_error("SigningWorker activation insert did not produce a record"))?;
    let stored_record = cipher.open::<CloudflareSigningWorkerOutputActivationRecordV1>(
        "activation",
        &material_key,
        &stored.record_json,
    )?;
    let stored_active_state = stored_record.active_signing_worker_state().clone();
    let stored_active_state_json =
        encode_json("SigningWorker stored active state", &stored_active_state)?;
    if !stored_record.matches_activation_and_material(&record)
        || stored.active_state_json != stored_active_state_json
    {
        return Err(d1_error(
            "server-output activation conflicts with existing activation or material",
        ));
    }
    Ok(
        CloudflareSigningWorkerPrivateD1ResponseV1::OutputActivated {
            receipt: CloudflareSigningWorkerOutputActivationReceiptV1::new(
                activation_context.lifecycle().lifecycle_id.clone(),
                selected_server.server_id.clone(),
                activation_context.transcript_digest(),
                stored_active_state,
                false,
            )?,
        },
    )
}

async fn active_state_get_v1(
    db: &D1DatabaseSession,
    request: &CloudflareSigningWorkerPrivateD1RequestV1,
    lookup: &CloudflareActiveSigningWorkerStateLookupV1,
) -> RouterAbProtocolResult<CloudflareSigningWorkerPrivateD1ResponseV1> {
    lookup.validate()?;
    let active_key = request.active_state_index_key()?;
    let row = activation_row_by_active_key_v1(db, &active_key)
        .await?
        .ok_or_else(|| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MissingLocalBinding,
                "active SigningWorker state is missing",
            )
        })?;
    let active_state = decode_json::<ActiveSigningWorkerStateV1>(
        "SigningWorker active state",
        &row.active_state_json,
    )?;
    lookup.validate_active_state(&active_state)?;
    Ok(CloudflareSigningWorkerPrivateD1ResponseV1::ActiveState { active_state })
}

async fn output_material_get_v1(
    env: &Env,
    db: &D1DatabaseSession,
    cipher: &SigningWorkerPrivateD1CipherV1,
    request: &CloudflareSigningWorkerPrivateD1RequestV1,
    lookup: &CloudflareSigningWorkerOutputMaterialLookupV1,
) -> RouterAbProtocolResult<CloudflareSigningWorkerPrivateD1ResponseV1> {
    lookup.validate()?;
    let row = activation_row_by_material_key_v1(db, &request.storage_key())
        .await?
        .ok_or_else(|| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MissingLocalBinding,
                "SigningWorker-output material is missing",
            )
        })?;
    let record = cipher.open::<CloudflareSigningWorkerOutputActivationRecordV1>(
        "activation",
        &request.storage_key(),
        &row.record_json,
    )?;
    record.validate()?;
    let material_activation = &record.active_signing_worker_state().material_activation;
    crate::ordinary_inactive_signer_material::require_ecdsa_material_active_v1(
        env,
        material_activation,
    )
    .await?;
    crate::ed25519_yao_signing_worker::require_ed25519_material_active_v1(env, material_activation)
        .await?;
    if record.active_signing_worker_state() != &lookup.active_signing_worker_state {
        return Err(d1_error(
            "SigningWorker-output material active state does not match lookup",
        ));
    }
    lookup.validate_material(record.material())?;
    Ok(CloudflareSigningWorkerPrivateD1ResponseV1::OutputMaterial {
        material: record.into_material(),
    })
}

async fn round1_put_v1(
    db: &D1DatabaseSession,
    cipher: &SigningWorkerPrivateD1CipherV1,
    request: &CloudflareSigningWorkerPrivateD1RequestV1,
    record: &CloudflareSigningWorkerRound1RecordV1,
) -> RouterAbProtocolResult<CloudflareSigningWorkerPrivateD1ResponseV1> {
    record.validate()?;
    let key = request.storage_key();
    let record_json = cipher.seal("round1", &key, record)?;
    let inserted = db
        .prepare(
            "INSERT OR IGNORE INTO signing_worker_round1
             (record_key, record_json, expires_at_ms) VALUES (?1, ?2, ?3)",
        )
        .bind(&[
            js_string(&key),
            js_string(&record_json),
            js_u64("SigningWorker round-1 expiry", record.expires_at_ms)?,
        ])
        .map_err(|error| map_d1_error("SigningWorker round-1 insert bind failed", error))?
        .run()
        .await
        .map_err(|error| map_d1_error("SigningWorker round-1 insert failed", error))?;
    let stored = d1_changes(&inserted)? == 1;
    let existing = db
        .prepare("SELECT record_json FROM signing_worker_round1 WHERE record_key = ?1")
        .bind(&[js_string(&key)])
        .map_err(|error| map_d1_error("SigningWorker round-1 query bind failed", error))?
        .first::<JsonRowV1>(None)
        .await
        .map_err(|error| map_d1_error("SigningWorker round-1 query failed", error))?
        .ok_or_else(|| d1_error("SigningWorker round-1 insert did not produce a record"))?;
    let existing_record = cipher.open::<CloudflareSigningWorkerRound1RecordV1>(
        "round1",
        &key,
        &existing.record_json,
    )?;
    if existing_record != *record {
        return Err(d1_error(
            "SigningWorker round-1 handle is already stored for different material",
        ));
    }
    Ok(CloudflareSigningWorkerPrivateD1ResponseV1::Round1Stored {
        receipt: CloudflareSigningWorkerRound1PutReceiptV1::from_record(record, stored)?,
    })
}

async fn round1_take_v1(
    db: &D1DatabaseSession,
    cipher: &SigningWorkerPrivateD1CipherV1,
    request: &CloudflareSigningWorkerPrivateD1RequestV1,
    lookup: &CloudflareSigningWorkerRound1LookupV1,
) -> RouterAbProtocolResult<CloudflareSigningWorkerPrivateD1ResponseV1> {
    lookup.validate()?;
    let row = db
        .prepare(
            "DELETE FROM signing_worker_round1
             WHERE record_key = ?1
             RETURNING record_json",
        )
        .bind(&[js_string(&request.storage_key())])
        .map_err(|error| map_d1_error("SigningWorker round-1 take bind failed", error))?
        .first::<JsonRowV1>(None)
        .await
        .map_err(|error| map_d1_error("SigningWorker round-1 take failed", error))?
        .ok_or_else(|| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MissingLocalBinding,
                "SigningWorker round-1 nonce material is missing",
            )
        })?;
    let record = cipher.open::<CloudflareSigningWorkerRound1RecordV1>(
        "round1",
        &request.storage_key(),
        &row.record_json,
    )?;
    record.validate_for_lookup(lookup)?;
    Ok(CloudflareSigningWorkerPrivateD1ResponseV1::Round1Taken { record })
}

async fn round1_cleanup_v1(
    db: &D1DatabaseSession,
    cleanup: &CloudflareExpiredStateCleanupRequestV1,
) -> RouterAbProtocolResult<CloudflareSigningWorkerPrivateD1ResponseV1> {
    cleanup.validate()?;
    let result = db
        .prepare("DELETE FROM signing_worker_round1 WHERE expires_at_ms <= ?1")
        .bind(&[js_u64(
            "SigningWorker round-1 cleanup timestamp",
            cleanup.now_unix_ms,
        )?])
        .map_err(|error| map_d1_error("SigningWorker round-1 cleanup bind failed", error))?
        .run()
        .await
        .map_err(|error| map_d1_error("SigningWorker round-1 cleanup failed", error))?;
    Ok(
        CloudflareSigningWorkerPrivateD1ResponseV1::Round1ExpiredCleaned {
            report: CloudflareExpiredStateCleanupReportV1::new(
                cleanup.now_unix_ms,
                d1_changes(&result)? as u64,
                0,
            )?,
        },
    )
}

async fn ecdsa_pool_mutate_v1(
    db: &D1DatabaseSession,
    cipher: &SigningWorkerPrivateD1CipherV1,
    request: &CloudflareSigningWorkerPrivateD1RequestV1,
    command: &CloudflareSigningWorkerEcdsaPoolCommandV1,
) -> RouterAbProtocolResult<CloudflareSigningWorkerPrivateD1ResponseV1> {
    command.validate()?;
    let key = request.storage_key();
    for _ in 0..3 {
        let current = db
            .prepare(
                "SELECT record_json, version
                 FROM signing_worker_ecdsa_pool
                 WHERE record_key = ?1",
            )
            .bind(&[js_string(&key)])
            .map_err(|error| map_d1_error("SigningWorker ECDSA pool query bind failed", error))?
            .first::<VersionedJsonRowV1>(None)
            .await
            .map_err(|error| map_d1_error("SigningWorker ECDSA pool query failed", error))?;
        let current_record = current
            .as_ref()
            .map(|row| {
                cipher.open::<CloudflareSigningWorkerEcdsaPoolLifecycleRecordV1>(
                    "ecdsa_pool",
                    &key,
                    &row.record_json,
                )
            })
            .transpose()?;
        let outcome =
            apply_cloudflare_signing_worker_ecdsa_pool_command_v1(current_record, command.clone())?;
        let record_json = cipher.seal("ecdsa_pool", &key, outcome.record())?;
        let cleanup_deadline = outcome
            .record()
            .cleanup_deadline_ms()
            .map(|value| js_u64("SigningWorker ECDSA pool cleanup deadline", value))
            .transpose()?
            .unwrap_or(JsValue::NULL);
        let write = match current {
            None => db
                .prepare(
                    "INSERT OR IGNORE INTO signing_worker_ecdsa_pool
                     (record_key, record_json, version, cleanup_deadline_ms)
                     VALUES (?1, ?2, 1, ?3)",
                )
                .bind(&[js_string(&key), js_string(&record_json), cleanup_deadline]),
            Some(row) => db
                .prepare(
                    "UPDATE signing_worker_ecdsa_pool
                     SET record_json = ?1, version = version + 1, cleanup_deadline_ms = ?2
                     WHERE record_key = ?3 AND version = ?4",
                )
                .bind(&[
                    js_string(&record_json),
                    cleanup_deadline,
                    js_string(&key),
                    JsValue::from_f64(row.version as f64),
                ]),
        }
        .map_err(|error| map_d1_error("SigningWorker ECDSA pool write bind failed", error))?
        .run()
        .await
        .map_err(|error| map_d1_error("SigningWorker ECDSA pool write failed", error))?;
        if d1_changes(&write)? == 1 {
            return Ok(CloudflareSigningWorkerPrivateD1ResponseV1::EcdsaPoolMutated { outcome });
        }
    }
    Err(RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::ConflictingPair,
        "SigningWorker ECDSA pool changed concurrently",
    ))
}

/// Executes one SigningWorker-private D1 operation.
pub async fn execute_cloudflare_signing_worker_private_d1_request_v1(
    env: &Env,
    request: &CloudflareSigningWorkerPrivateD1RequestV1,
) -> RouterAbProtocolResult<CloudflareSigningWorkerPrivateD1ResponseV1> {
    request.validate()?;
    let db = signing_worker_private_d1_from_env_v1(env)?;
    let db = db
        .with_session_constraint(D1SessionConstraint::FirstPrimary)
        .map_err(|error| map_d1_error("SigningWorker private D1 primary session failed", error))?;
    let cipher = SigningWorkerPrivateD1CipherV1::from_env(env)?;
    let response = match request {
        CloudflareSigningWorkerPrivateD1RequestV1::OutputActivate {
            activation,
            material,
            activated_at_ms,
            ..
        } => {
            activate_output_v1(
                &db,
                &cipher,
                request,
                activation,
                material,
                *activated_at_ms,
            )
            .await
        }
        CloudflareSigningWorkerPrivateD1RequestV1::ActiveStateGet { lookup } => {
            active_state_get_v1(&db, request, lookup).await
        }
        CloudflareSigningWorkerPrivateD1RequestV1::OutputMaterialGet { lookup } => {
            output_material_get_v1(env, &db, &cipher, request, lookup).await
        }
        CloudflareSigningWorkerPrivateD1RequestV1::Round1Put { record } => {
            round1_put_v1(&db, &cipher, request, record).await
        }
        CloudflareSigningWorkerPrivateD1RequestV1::Round1Take { lookup } => {
            round1_take_v1(&db, &cipher, request, lookup).await
        }
        CloudflareSigningWorkerPrivateD1RequestV1::Round1CleanupExpired { cleanup } => {
            round1_cleanup_v1(&db, cleanup).await
        }
        CloudflareSigningWorkerPrivateD1RequestV1::EcdsaPoolMutate { command } => {
            ecdsa_pool_mutate_v1(&db, &cipher, request, command).await
        }
    }?;
    response.validate_for_request(request)?;
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::SIGNING_WORKER_PRIVATE_D1_SCHEMA_V1;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum ActivationOutputEventV1 {
        ActivationInsert,
        RevocationFence,
        ActivationDelete,
    }

    #[derive(Default)]
    struct ActivationOutputPersistenceModelV1 {
        fenced: bool,
        output_present: bool,
    }

    impl ActivationOutputPersistenceModelV1 {
        fn apply(&mut self, event: ActivationOutputEventV1) {
            match event {
                ActivationOutputEventV1::ActivationInsert if !self.fenced => {
                    self.output_present = true;
                }
                ActivationOutputEventV1::RevocationFence => self.fenced = true,
                ActivationOutputEventV1::ActivationDelete => self.output_present = false,
                ActivationOutputEventV1::ActivationInsert => {}
            }
        }
    }

    #[test]
    fn activation_output_revocation_fence_interleavings_are_safe_for_both_curves() {
        assert!(SIGNING_WORKER_PRIVATE_D1_SCHEMA_V1
            .contains("signing_worker_activation_revocation_fences"));
        let interleavings = [
            [
                ActivationOutputEventV1::ActivationInsert,
                ActivationOutputEventV1::RevocationFence,
                ActivationOutputEventV1::ActivationDelete,
            ],
            [
                ActivationOutputEventV1::RevocationFence,
                ActivationOutputEventV1::ActivationInsert,
                ActivationOutputEventV1::ActivationDelete,
            ],
            [
                ActivationOutputEventV1::RevocationFence,
                ActivationOutputEventV1::ActivationDelete,
                ActivationOutputEventV1::ActivationInsert,
            ],
        ];
        for curve in ["ecdsa_secp256k1", "ed25519"] {
            for interleaving in interleavings {
                let mut state = ActivationOutputPersistenceModelV1::default();
                for event in interleaving {
                    state.apply(event);
                }
                assert!(
                    state.fenced,
                    "{curve} interleaving did not persist the fence"
                );
                assert!(
                    !state.output_present,
                    "{curve} interleaving left active signer output"
                );
            }
        }
    }
}
