use super::*;
use crate::hpke::{
    parse_cloudflare_hpke_x25519_public_key_v1, CloudflareHpkeGetrandomRngV1, CloudflareHpkeKemV1,
    CloudflareHpkeSuiteV1,
};
use hpke_ng::Kem;
use serde::de::DeserializeOwned;
use wasm_bindgen::JsValue;
use worker::{D1Database, D1DatabaseSession, D1SessionConstraint, Env, Request, Response};

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
CREATE TABLE IF NOT EXISTS signing_worker_wallet_budgets (
  signing_grant_id TEXT PRIMARY KEY,
  record_json TEXT NOT NULL,
  version INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL
);
"#;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SigningWorkerWalletBudgetReservationStatusV1 {
    Reserved,
    Committed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SigningWorkerWalletBudgetReservationV1 {
    reservation_id: String,
    curve: CloudflareRouterWalletBudgetCurveV1,
    threshold_session_id: String,
    signing_worker_id: String,
    operation_id: String,
    request_digest: PublicDigest32,
    signature_uses: u32,
    expires_at_ms: u64,
    status: SigningWorkerWalletBudgetReservationStatusV1,
    remaining_uses_after_commit: u32,
}

impl SigningWorkerWalletBudgetReservationV1 {
    fn from_request(request: &CloudflareRouterWalletBudgetReserveRequestV1) -> Self {
        Self {
            reservation_id: cloudflare_signing_worker_wallet_budget_reservation_id_unchecked_v1(
                request,
            ),
            curve: request.curve,
            threshold_session_id: request.threshold_session_id.clone(),
            signing_worker_id: request.signing_worker_id.clone(),
            operation_id: request.operation_id.clone(),
            request_digest: request.request_digest,
            signature_uses: request.signature_uses,
            expires_at_ms: request.expires_at_ms,
            status: SigningWorkerWalletBudgetReservationStatusV1::Reserved,
            remaining_uses_after_commit: 0,
        }
    }

    fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("wallet budget reservation_id", &self.reservation_id)?;
        require_non_empty(
            "wallet budget threshold_session_id",
            &self.threshold_session_id,
        )?;
        require_non_empty("wallet budget signing_worker_id", &self.signing_worker_id)?;
        require_non_empty("wallet budget operation_id", &self.operation_id)?;
        if self.signature_uses == 0 {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "wallet budget reservation signature_uses must be greater than zero",
            ));
        }
        require_positive_ms(
            "wallet budget reservation expires_at_ms",
            self.expires_at_ms,
        )
    }

    fn validate_identity(
        &self,
        identity: &CloudflareRouterWalletBudgetReservationIdentityV1,
    ) -> RouterAbProtocolResult<()> {
        self.validate()?;
        identity.validate()?;
        if self.reservation_id == identity.reservation_id
            && self.signing_worker_id == identity.signing_worker_id
            && self.operation_id == identity.operation_id
            && self.request_digest == identity.request_digest
        {
            return Ok(());
        }
        Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidGateDecision,
            "wallet budget reservation identity does not match",
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SigningWorkerWalletBudgetRecordV1 {
    signing_grant_id: String,
    wallet_id: String,
    rp_id: String,
    issuer_jwt_id: String,
    authorized_signers: Vec<CloudflareRouterWalletBudgetSignerBindingV1>,
    initial_signature_uses: u32,
    committed_remaining_uses: u32,
    expires_at_ms: u64,
    reservations: std::collections::BTreeMap<String, SigningWorkerWalletBudgetReservationV1>,
    committed_operations: std::collections::BTreeMap<String, String>,
    projection_version: u64,
}

impl SigningWorkerWalletBudgetRecordV1 {
    fn from_put_request(
        request: &CloudflareRouterWalletBudgetPutGrantRequestV1,
    ) -> RouterAbProtocolResult<Self> {
        request.validate()?;
        let record = Self {
            signing_grant_id: request.signing_grant_id.clone(),
            wallet_id: request.wallet_id.clone(),
            rp_id: request.rp_id.clone(),
            issuer_jwt_id: request.issuer_jwt_id.clone(),
            authorized_signers: request.authorized_signers.clone(),
            initial_signature_uses: request.initial_signature_uses,
            committed_remaining_uses: request.initial_signature_uses,
            expires_at_ms: request.expires_at_ms,
            reservations: std::collections::BTreeMap::new(),
            committed_operations: std::collections::BTreeMap::new(),
            projection_version: 1,
        };
        record.validate()?;
        Ok(record)
    }

    fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("wallet budget signing_grant_id", &self.signing_grant_id)?;
        require_non_empty("wallet budget wallet_id", &self.wallet_id)?;
        require_non_empty("wallet budget rp_id", &self.rp_id)?;
        require_non_empty("wallet budget issuer_jwt_id", &self.issuer_jwt_id)?;
        require_non_empty_vec("wallet budget authorized_signers", &self.authorized_signers)?;
        if self.initial_signature_uses == 0 {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "wallet budget initial_signature_uses must be greater than zero",
            ));
        }
        if self.committed_remaining_uses > self.initial_signature_uses {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "wallet budget committed remaining uses exceeds initial uses",
            ));
        }
        for (index, signer) in self.authorized_signers.iter().enumerate() {
            signer.validate()?;
            if self.authorized_signers[..index].contains(signer) {
                return Err(RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::InvalidGateDecision,
                    "wallet budget authorized_signers contains a duplicate binding",
                ));
            }
        }
        for reservation in self.reservations.values() {
            reservation.validate()?;
        }
        require_positive_ms("wallet budget expires_at_ms", self.expires_at_ms)
    }

    fn converge_put_request(
        &mut self,
        request: &CloudflareRouterWalletBudgetPutGrantRequestV1,
    ) -> RouterAbProtocolResult<()> {
        self.validate()?;
        request.validate()?;
        if self.signing_grant_id != request.signing_grant_id
            || self.wallet_id != request.wallet_id
            || self.rp_id != request.rp_id
            || self.issuer_jwt_id != request.issuer_jwt_id
            || self.initial_signature_uses != request.initial_signature_uses
            || self.expires_at_ms > request.expires_at_ms
            || self.expires_at_ms <= request.now_unix_ms
        {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ReplayedLocalRequest,
                "wallet budget grant id is already stored for different material",
            ));
        }

        for (index, signer) in request.authorized_signers.iter().enumerate() {
            if request.authorized_signers[..index].contains(signer) {
                return Err(RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::InvalidGateDecision,
                    "wallet budget authorized_signers contains a duplicate binding",
                ));
            }
        }
        if self
            .authorized_signers
            .iter()
            .any(|signer| !request.authorized_signers.contains(signer))
        {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ReplayedLocalRequest,
                "wallet budget grant update cannot remove an authorized signer",
            ));
        }

        let additional_signers = request
            .authorized_signers
            .iter()
            .filter(|signer| !self.authorized_signers.contains(signer))
            .cloned()
            .collect::<Vec<_>>();
        if !additional_signers.is_empty() {
            self.authorized_signers.extend(additional_signers);
            self.projection_version = self.projection_version.saturating_add(1);
        }
        self.validate()
    }

    fn clean_expired_reservations(&mut self, now_unix_ms: u64) -> RouterAbProtocolResult<()> {
        self.validate()?;
        require_positive_ms("wallet budget now_unix_ms", now_unix_ms)?;
        let before = self.reservations.len();
        self.reservations.retain(|_, reservation| {
            reservation.status == SigningWorkerWalletBudgetReservationStatusV1::Committed
                || reservation.expires_at_ms > now_unix_ms
        });
        if before != self.reservations.len() {
            self.projection_version = self.projection_version.saturating_add(1);
        }
        Ok(())
    }

    fn status_at(
        &self,
        now_unix_ms: u64,
    ) -> RouterAbProtocolResult<CloudflareRouterWalletBudgetStatusV1> {
        self.validate()?;
        require_positive_ms("wallet budget now_unix_ms", now_unix_ms)?;
        if now_unix_ms >= self.expires_at_ms {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ExpiredLocalRequest,
                "wallet budget grant expired",
            ));
        }
        let reserved_uses = self
            .reservations
            .values()
            .filter(|reservation| {
                reservation.status == SigningWorkerWalletBudgetReservationStatusV1::Reserved
                    && reservation.expires_at_ms > now_unix_ms
            })
            .try_fold(0u32, |total, reservation| {
                total
                    .checked_add(reservation.signature_uses)
                    .ok_or_else(|| {
                        RouterAbProtocolError::new(
                            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                            "wallet budget reserved uses overflow",
                        )
                    })
            })?;
        CloudflareRouterWalletBudgetStatusV1::new(
            self.signing_grant_id.clone(),
            self.committed_remaining_uses,
            reserved_uses,
            self.projection_version,
            self.expires_at_ms,
        )
    }

    fn reserve(
        &mut self,
        request: &CloudflareRouterWalletBudgetReserveRequestV1,
    ) -> RouterAbProtocolResult<String> {
        self.clean_expired_reservations(request.now_unix_ms)?;
        request.validate()?;
        if !self.authorized_signers.iter().any(|signer| {
            signer.curve == request.curve
                && signer.threshold_session_id == request.threshold_session_id
                && signer.signing_worker_id == request.signing_worker_id
        }) {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ForbiddenLocalBinding,
                "wallet budget reserve signer is not authorized by grant",
            ));
        }
        let candidate = SigningWorkerWalletBudgetReservationV1::from_request(request);
        let reservation_id = candidate.reservation_id.clone();
        if let Some(existing) = self.reservations.get(&reservation_id) {
            existing.validate()?;
            if existing == &candidate {
                return Ok(reservation_id);
            }
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ReplayedLocalRequest,
                "wallet budget reservation id is already stored for different material",
            ));
        }
        let operation_key = cloudflare_signing_worker_wallet_budget_operation_key_v1(
            &request.signing_worker_id,
            &request.operation_id,
            request.request_digest,
        );
        if self.committed_operations.contains_key(&operation_key) {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ReplayedLocalRequest,
                "wallet budget operation was already committed",
            ));
        }
        if self.status_at(request.now_unix_ms)?.available_uses < request.signature_uses {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "wallet budget exhausted",
            ));
        }
        self.reservations.insert(reservation_id.clone(), candidate);
        self.projection_version = self.projection_version.saturating_add(1);
        Ok(reservation_id)
    }

    fn validate_reservation(
        &mut self,
        identity: &CloudflareRouterWalletBudgetReservationIdentityV1,
    ) -> RouterAbProtocolResult<()> {
        self.clean_expired_reservations(identity.now_unix_ms)?;
        let reservation = self
            .reservations
            .get(&identity.reservation_id)
            .ok_or_else(|| {
                RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::MissingLocalBinding,
                    "wallet budget reservation is missing",
                )
            })?;
        reservation.validate_identity(identity)?;
        if reservation.status == SigningWorkerWalletBudgetReservationStatusV1::Reserved
            && identity.now_unix_ms >= reservation.expires_at_ms
        {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ExpiredLocalRequest,
                "wallet budget reservation expired",
            ));
        }
        Ok(())
    }

    fn commit(
        &mut self,
        identity: &CloudflareRouterWalletBudgetReservationIdentityV1,
    ) -> RouterAbProtocolResult<()> {
        self.validate_reservation(identity)?;
        let reservation = self
            .reservations
            .get_mut(&identity.reservation_id)
            .ok_or_else(|| {
                RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::MissingLocalBinding,
                    "wallet budget reservation is missing",
                )
            })?;
        if reservation.status == SigningWorkerWalletBudgetReservationStatusV1::Committed {
            return Ok(());
        }
        if self.committed_remaining_uses < reservation.signature_uses {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "wallet budget exhausted at commit",
            ));
        }
        self.committed_remaining_uses -= reservation.signature_uses;
        reservation.status = SigningWorkerWalletBudgetReservationStatusV1::Committed;
        reservation.remaining_uses_after_commit = self.committed_remaining_uses;
        self.committed_operations.insert(
            cloudflare_signing_worker_wallet_budget_operation_key_v1(
                &reservation.signing_worker_id,
                &reservation.operation_id,
                reservation.request_digest,
            ),
            reservation.reservation_id.clone(),
        );
        self.projection_version = self.projection_version.saturating_add(1);
        Ok(())
    }

    fn release(
        &mut self,
        request: &CloudflareRouterWalletBudgetReleaseRequestV1,
    ) -> RouterAbProtocolResult<()> {
        self.clean_expired_reservations(request.now_unix_ms)?;
        let release_matches =
            self.reservations
                .get(&request.reservation_id)
                .is_some_and(|reservation| {
                    reservation.status == SigningWorkerWalletBudgetReservationStatusV1::Reserved
                        && reservation.signing_worker_id == request.signing_worker_id
                        && reservation.operation_id == request.operation_id
                        && reservation.request_digest == request.request_digest
                });
        if release_matches && self.reservations.remove(&request.reservation_id).is_some() {
            self.projection_version = self.projection_version.saturating_add(1);
        }
        Ok(())
    }
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
        let private_key_bytes =
            decode_cloudflare_server_output_hpke_private_key_secret_v1(&encoded_private_key)?;
        encoded_private_key.zeroize();
        let private_key =
            CloudflareHpkeKemV1::sk_from_bytes(&private_key_bytes).map_err(|error| {
                d1_error(format!("SigningWorker private D1 KEK is invalid: {error}"))
            })?;
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
        let plaintext = encode_json("SigningWorker private D1 secret", value)?;
        let aad = self.aad(purpose, identity);
        let mut rng = CloudflareHpkeGetrandomRngV1;
        let (encapped_key, ciphertext) = CloudflareHpkeSuiteV1::seal_base(
            &mut rng,
            &self.public_key,
            SIGNING_WORKER_PRIVATE_D1_HPKE_INFO_V1,
            aad.as_bytes(),
            plaintext.as_bytes(),
        )
        .map_err(|error| {
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
        let plaintext = String::from_utf8(plaintext)
            .map_err(|_| d1_error("SigningWorker private D1 plaintext is not UTF-8"))?;
        decode_json("SigningWorker private D1 secret", &plaintext)
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

fn signing_worker_wallet_budget_request_now_v1(
    request: &CloudflareSigningWorkerWalletBudgetRequestV1,
) -> u64 {
    match request {
        CloudflareSigningWorkerWalletBudgetRequestV1::PutGrant { request } => request.now_unix_ms,
        CloudflareSigningWorkerWalletBudgetRequestV1::Reserve { request } => request.now_unix_ms,
        CloudflareSigningWorkerWalletBudgetRequestV1::Validate { identity }
        | CloudflareSigningWorkerWalletBudgetRequestV1::Commit { identity } => identity.now_unix_ms,
        CloudflareSigningWorkerWalletBudgetRequestV1::Release { request } => request.now_unix_ms,
        CloudflareSigningWorkerWalletBudgetRequestV1::Status { request } => request.now_unix_ms,
    }
}

fn signing_worker_wallet_budget_missing_v1() -> RouterAbProtocolError {
    RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::MissingLocalBinding,
        "wallet budget grant is missing",
    )
}

fn apply_signing_worker_wallet_budget_request_v1(
    current: Option<SigningWorkerWalletBudgetRecordV1>,
    request: &CloudflareSigningWorkerWalletBudgetRequestV1,
) -> RouterAbProtocolResult<(
    SigningWorkerWalletBudgetRecordV1,
    CloudflareSigningWorkerWalletBudgetResponseV1,
    bool,
)> {
    request.validate()?;
    let Some(mut record) = current else {
        let CloudflareSigningWorkerWalletBudgetRequestV1::PutGrant { request } = request else {
            return Err(signing_worker_wallet_budget_missing_v1());
        };
        let record = SigningWorkerWalletBudgetRecordV1::from_put_request(request)?;
        let status = record.status_at(request.now_unix_ms)?;
        return Ok((
            record,
            CloudflareSigningWorkerWalletBudgetResponseV1::GrantPut { status },
            true,
        ));
    };
    record.validate()?;
    let before = record.clone();
    let response = match request {
        CloudflareSigningWorkerWalletBudgetRequestV1::PutGrant { request } => {
            record.converge_put_request(request)?;
            CloudflareSigningWorkerWalletBudgetResponseV1::GrantPut {
                status: record.status_at(request.now_unix_ms)?,
            }
        }
        CloudflareSigningWorkerWalletBudgetRequestV1::Reserve { request } => {
            let reservation_id = record.reserve(request)?;
            CloudflareSigningWorkerWalletBudgetResponseV1::Reserved {
                reservation_id,
                status: record.status_at(request.now_unix_ms)?,
            }
        }
        CloudflareSigningWorkerWalletBudgetRequestV1::Validate { identity } => {
            record.validate_reservation(identity)?;
            CloudflareSigningWorkerWalletBudgetResponseV1::Validated {
                reservation_id: identity.reservation_id.clone(),
                status: record.status_at(identity.now_unix_ms)?,
            }
        }
        CloudflareSigningWorkerWalletBudgetRequestV1::Commit { identity } => {
            record.commit(identity)?;
            CloudflareSigningWorkerWalletBudgetResponseV1::Committed {
                reservation_id: identity.reservation_id.clone(),
                status: record.status_at(identity.now_unix_ms)?,
            }
        }
        CloudflareSigningWorkerWalletBudgetRequestV1::Release { request } => {
            record.release(request)?;
            CloudflareSigningWorkerWalletBudgetResponseV1::Released {
                reservation_id: request.reservation_id.clone(),
                status: record.status_at(request.now_unix_ms)?,
            }
        }
        CloudflareSigningWorkerWalletBudgetRequestV1::Status { request } => {
            record.clean_expired_reservations(request.now_unix_ms)?;
            CloudflareSigningWorkerWalletBudgetResponseV1::Status {
                status: record.status_at(request.now_unix_ms)?,
            }
        }
    };
    response.validate_for_request(request)?;
    let changed = record != before;
    Ok((record, response, changed))
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
                "reusable-wallet-session/{}/{}/{}",
                claim.wallet_session_id, claim.grant_id, claim.use_id
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
            grant_id,
            use_id,
            ..
        } => {
            let authorization_json =
                encode_json("SigningWorker effect authorization", &request.effect_claim)?;
            let authorization_key =
                format!("operation-step-up/{authorization_session_id}/{grant_id}/{use_id}");
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
        .map_err(|error| map_d1_error("SigningWorker ECDSA effect primary session failed", error))?;
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
    let authorization_json =
        encode_json("SigningWorker ECDSA effect authorization", &request.effect_claim)?;
    let authorization_key = match &request.effect_claim {
        CloudflareSigningWorkerNormalSigningEffectClaimV1::ReusableWalletSession { claim } => {
            format!(
                "ecdsa-reusable-wallet-session/{}/{}/{}",
                claim.wallet_session_id, claim.grant_id, claim.use_id
            )
        }
        CloudflareSigningWorkerNormalSigningEffectClaimV1::OperationStepUp {
            authorization_session_id,
            grant_id,
            use_id,
            ..
        } => format!(
            "ecdsa-operation-step-up/{authorization_session_id}/{grant_id}/{use_id}"
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
             VALUES (?1, ?2, ?3, ?4, ?5)",
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
            "SELECT ciphertext_json AS record_json, version
             FROM signing_worker_secret_states
             WHERE purpose = ?1 AND record_key = ?2",
        )
        .bind(&[js_string(purpose), js_string(record_key)])
        .map_err(|error| map_d1_error("SigningWorker secret-state query bind failed", error))?
        .first::<VersionedJsonRowV1>(None)
        .await
        .map_err(|error| map_d1_error("SigningWorker secret-state query failed", error))?;
    let Some(row) = row else {
        return Ok(None);
    };
    let cipher = SigningWorkerPrivateD1CipherV1::from_env(env)?;
    Ok(Some(CloudflareSigningWorkerPrivateD1VersionedSecretV1 {
        value: cipher.open(purpose, record_key, &row.record_json)?,
        version: row.version,
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
    let material_activation = match request {
        CloudflareSigningWorkerPrivateD1RequestV1::OutputActivate {
            material_activation, ..
        } => material_activation.clone(),
        _ => {
            return Err(d1_error(
                "SigningWorker activation request kind is invalid",
            ))
        }
    };
    let active_state = cloudflare_active_signing_worker_state_from_activation_request_v1(
        activation,
        material_activation,
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
             VALUES (?1, ?2, ?3, ?4, ?5)",
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

/// Executes one Wallet Session budget operation against SigningWorker-private D1.
pub async fn execute_cloudflare_signing_worker_wallet_budget_private_d1_request_v1(
    env: &Env,
    request: &CloudflareSigningWorkerWalletBudgetRequestV1,
) -> RouterAbProtocolResult<CloudflareSigningWorkerWalletBudgetResponseV1> {
    request.validate()?;
    let signing_grant_id = request.signing_grant_id();
    let updated_at_ms = signing_worker_wallet_budget_request_now_v1(request);
    let database = signing_worker_private_d1_from_env_v1(env)?;
    let session = database
        .with_session_constraint(D1SessionConstraint::FirstPrimary)
        .map_err(|error| map_d1_error("SigningWorker private D1 primary session failed", error))?;
    let cipher = SigningWorkerPrivateD1CipherV1::from_env(env)?;
    for _ in 0..5 {
        let current = session
            .prepare(
                "SELECT record_json, version
                 FROM signing_worker_wallet_budgets
                 WHERE signing_grant_id = ?1",
            )
            .bind(&[js_string(signing_grant_id)])
            .map_err(|error| map_d1_error("SigningWorker wallet-budget query bind failed", error))?
            .first::<VersionedJsonRowV1>(None)
            .await
            .map_err(|error| map_d1_error("SigningWorker wallet-budget query failed", error))?;
        let decoded = current
            .as_ref()
            .map(|row| {
                cipher.open::<SigningWorkerWalletBudgetRecordV1>(
                    "wallet_budget",
                    signing_grant_id,
                    &row.record_json,
                )
            })
            .transpose()?;
        let (record, response, changed) =
            apply_signing_worker_wallet_budget_request_v1(decoded, request)?;
        if !changed {
            return Ok(response);
        }
        let record_json = cipher.seal("wallet_budget", signing_grant_id, &record)?;
        let write = match current {
            None => session
                .prepare(
                    "INSERT OR IGNORE INTO signing_worker_wallet_budgets
                     (signing_grant_id, record_json, version, updated_at_ms)
                     VALUES (?1, ?2, 1, ?3)",
                )
                .bind(&[
                    js_string(signing_grant_id),
                    js_string(&record_json),
                    js_u64("SigningWorker wallet-budget timestamp", updated_at_ms)?,
                ]),
            Some(row) => session
                .prepare(
                    "UPDATE signing_worker_wallet_budgets
                     SET record_json = ?1, version = version + 1, updated_at_ms = ?2
                     WHERE signing_grant_id = ?3 AND version = ?4",
                )
                .bind(&[
                    js_string(&record_json),
                    js_u64("SigningWorker wallet-budget timestamp", updated_at_ms)?,
                    js_string(signing_grant_id),
                    JsValue::from_f64(row.version as f64),
                ]),
        }
        .map_err(|error| map_d1_error("SigningWorker wallet-budget write bind failed", error))?
        .run()
        .await
        .map_err(|error| map_d1_error("SigningWorker wallet-budget write failed", error))?;
        if d1_changes(&write)? == 1 {
            return Ok(response);
        }
    }
    Err(RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::ConflictingPair,
        "SigningWorker wallet budget changed concurrently",
    ))
}

/// Handles the internal SigningWorker Wallet Session budget service route.
pub async fn handle_cloudflare_signing_worker_wallet_budget_private_fetch_v1(
    mut request: Request,
    env: &Env,
) -> RouterAbProtocolResult<Response> {
    if request.path() != CLOUDFLARE_SIGNING_WORKER_WALLET_BUDGET_PATH_V1 {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            format!(
                "SigningWorker wallet-budget request must be served at {}",
                CLOUDFLARE_SIGNING_WORKER_WALLET_BUDGET_PATH_V1
            ),
        ));
    }
    let parsed = match request
        .json::<CloudflareSigningWorkerWalletBudgetRequestV1>()
        .await
    {
        Ok(parsed) => parsed,
        Err(error) => {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                format!("SigningWorker wallet-budget request JSON is invalid: {error}"),
            ))
        }
    };
    let response =
        execute_cloudflare_signing_worker_wallet_budget_private_d1_request_v1(env, &parsed).await?;
    Response::from_json(&response).map_err(|error| {
        d1_error(format!(
            "SigningWorker wallet-budget response failed: {error}"
        ))
    })
}

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
            output_material_get_v1(&db, &cipher, request, lookup).await
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
    use super::*;

    fn wallet_budget_put_request_v1() -> CloudflareRouterWalletBudgetPutGrantRequestV1 {
        CloudflareRouterWalletBudgetPutGrantRequestV1 {
            signing_grant_id: "grant-1".to_owned(),
            wallet_id: "wallet-1".to_owned(),
            rp_id: "example.com".to_owned(),
            authorized_signers: vec![CloudflareRouterWalletBudgetSignerBindingV1::new(
                CloudflareRouterWalletBudgetCurveV1::Ed25519,
                "threshold-1",
                "signing-worker-1",
            )
            .expect("signer binding")],
            initial_signature_uses: 2,
            expires_at_ms: 10_000,
            issuer_jwt_id: "jwt-1".to_owned(),
            now_unix_ms: 1_000,
        }
    }

    fn wallet_budget_reserve_request_v1() -> CloudflareRouterWalletBudgetReserveRequestV1 {
        CloudflareRouterWalletBudgetReserveRequestV1 {
            signing_grant_id: "grant-1".to_owned(),
            curve: CloudflareRouterWalletBudgetCurveV1::Ed25519,
            threshold_session_id: "threshold-1".to_owned(),
            signing_worker_id: "signing-worker-1".to_owned(),
            operation_id: "operation-1".to_owned(),
            request_digest: PublicDigest32::new([0x42; 32]),
            signature_uses: 1,
            expires_at_ms: 5_000,
            now_unix_ms: 1_100,
        }
    }

    fn ecdsa_wallet_budget_signer_v1() -> CloudflareRouterWalletBudgetSignerBindingV1 {
        CloudflareRouterWalletBudgetSignerBindingV1::new(
            CloudflareRouterWalletBudgetCurveV1::RouterAbEcdsaDerivation,
            "threshold-ecdsa-1",
            "signing-worker-ecdsa-1",
        )
        .expect("ECDSA signer binding")
    }

    #[test]
    fn schema_has_one_authority_and_consume_once_round1() {
        assert!(SIGNING_WORKER_PRIVATE_D1_SCHEMA_V1
            .contains("CREATE TABLE IF NOT EXISTS signing_worker_activations"));
        assert!(SIGNING_WORKER_PRIVATE_D1_SCHEMA_V1
            .contains("CREATE TABLE IF NOT EXISTS signing_worker_round1"));
        assert!(SIGNING_WORKER_PRIVATE_D1_SCHEMA_V1
            .contains("CREATE TABLE IF NOT EXISTS signing_worker_ecdsa_pool"));
        assert!(SIGNING_WORKER_PRIVATE_D1_SCHEMA_V1
            .contains("CREATE TABLE IF NOT EXISTS signing_worker_wallet_budgets"));
        assert!(SIGNING_WORKER_PRIVATE_D1_SCHEMA_V1
            .contains("CREATE TABLE IF NOT EXISTS signing_worker_effect_claims"));
        assert!(
            SIGNING_WORKER_PRIVATE_D1_SCHEMA_V1.contains("authorization_key TEXT NOT NULL UNIQUE")
        );
        assert!(!SIGNING_WORKER_PRIVATE_D1_SCHEMA_V1.contains("durable"));
    }

    #[test]
    fn wallet_budget_put_exact_replay_is_unchanged() {
        let request = wallet_budget_put_request_v1();
        let record = SigningWorkerWalletBudgetRecordV1::from_put_request(&request)
            .expect("initial wallet budget");
        let expected = record.clone();
        let put = CloudflareSigningWorkerWalletBudgetRequestV1::PutGrant { request };

        let (replayed, _, changed) =
            apply_signing_worker_wallet_budget_request_v1(Some(record), &put)
                .expect("exact replay");

        assert!(!changed);
        assert_eq!(replayed, expected);
    }

    #[test]
    fn wallet_budget_put_adds_signer_without_resetting_consumption_state() {
        let request = wallet_budget_put_request_v1();
        let record = SigningWorkerWalletBudgetRecordV1::from_put_request(&request)
            .expect("initial wallet budget");
        let reserve_request = wallet_budget_reserve_request_v1();
        let reserve = CloudflareSigningWorkerWalletBudgetRequestV1::Reserve {
            request: reserve_request.clone(),
        };
        let (reserved, response, _) =
            apply_signing_worker_wallet_budget_request_v1(Some(record), &reserve)
                .expect("reserve use");
        let CloudflareSigningWorkerWalletBudgetResponseV1::Reserved { reservation_id, .. } =
            response
        else {
            panic!("reserve response branch");
        };
        let commit = CloudflareSigningWorkerWalletBudgetRequestV1::Commit {
            identity: CloudflareRouterWalletBudgetReservationIdentityV1::new(
                "grant-1",
                reservation_id,
                "signing-worker-1",
                "operation-1",
                reserve_request.request_digest,
                1_200,
            )
            .expect("reservation identity"),
        };
        let (committed, _, _) =
            apply_signing_worker_wallet_budget_request_v1(Some(reserved), &commit)
                .expect("commit use");
        let expected_remaining_uses = committed.committed_remaining_uses;
        let expected_reservations = committed.reservations.clone();
        let expected_operations = committed.committed_operations.clone();
        let expected_projection_version = committed.projection_version;
        let mut additive = request;
        additive
            .authorized_signers
            .push(ecdsa_wallet_budget_signer_v1());
        additive.now_unix_ms = 1_300;
        additive.expires_at_ms = 10_250;
        let put = CloudflareSigningWorkerWalletBudgetRequestV1::PutGrant { request: additive };

        let (merged, _, changed) =
            apply_signing_worker_wallet_budget_request_v1(Some(committed), &put)
                .expect("add signer binding");

        assert!(changed);
        assert_eq!(merged.authorized_signers.len(), 2);
        assert!(merged
            .authorized_signers
            .contains(&ecdsa_wallet_budget_signer_v1()));
        assert_eq!(merged.committed_remaining_uses, expected_remaining_uses);
        assert_eq!(merged.reservations, expected_reservations);
        assert_eq!(merged.committed_operations, expected_operations);
        assert_eq!(merged.expires_at_ms, 10_000);
        assert_eq!(
            merged.projection_version,
            expected_projection_version.saturating_add(1)
        );
    }

    #[test]
    fn wallet_budget_put_rejects_conflicting_immutable_identity() {
        let request = wallet_budget_put_request_v1();
        let record = SigningWorkerWalletBudgetRecordV1::from_put_request(&request)
            .expect("initial wallet budget");
        let mut conflicting = request;
        conflicting.wallet_id = "wallet-2".to_owned();
        let put = CloudflareSigningWorkerWalletBudgetRequestV1::PutGrant {
            request: conflicting,
        };

        let error = apply_signing_worker_wallet_budget_request_v1(Some(record), &put)
            .expect_err("conflicting grant identity must fail");

        assert_eq!(
            error.code(),
            RouterAbProtocolErrorCode::ReplayedLocalRequest
        );
    }

    #[test]
    fn wallet_budget_put_rejects_removing_an_authorized_signer() {
        let mut additive = wallet_budget_put_request_v1();
        additive
            .authorized_signers
            .push(ecdsa_wallet_budget_signer_v1());
        let record = SigningWorkerWalletBudgetRecordV1::from_put_request(&additive)
            .expect("mixed wallet budget");
        let put = CloudflareSigningWorkerWalletBudgetRequestV1::PutGrant {
            request: wallet_budget_put_request_v1(),
        };

        let error = apply_signing_worker_wallet_budget_request_v1(Some(record), &put)
            .expect_err("removing signer binding must fail");

        assert_eq!(
            error.code(),
            RouterAbProtocolErrorCode::ReplayedLocalRequest
        );
    }

    #[test]
    fn wallet_budget_transitions_are_idempotent_and_consume_once() {
        let put = CloudflareSigningWorkerWalletBudgetRequestV1::PutGrant {
            request: wallet_budget_put_request_v1(),
        };
        let (record, _, changed) =
            apply_signing_worker_wallet_budget_request_v1(None, &put).expect("put grant");
        assert!(changed);

        let reserve_request = wallet_budget_reserve_request_v1();
        let reserve = CloudflareSigningWorkerWalletBudgetRequestV1::Reserve {
            request: reserve_request.clone(),
        };
        let (reserved, response, changed) =
            apply_signing_worker_wallet_budget_request_v1(Some(record), &reserve).expect("reserve");
        assert!(changed);
        let CloudflareSigningWorkerWalletBudgetResponseV1::Reserved {
            reservation_id,
            status,
        } = response
        else {
            panic!("reserve response branch");
        };
        assert_eq!(status.available_uses, 1);

        let (reserved_replay, _, changed) =
            apply_signing_worker_wallet_budget_request_v1(Some(reserved), &reserve)
                .expect("reserve replay");
        assert!(!changed);

        let commit = CloudflareSigningWorkerWalletBudgetRequestV1::Commit {
            identity: CloudflareRouterWalletBudgetReservationIdentityV1::new(
                "grant-1",
                reservation_id,
                "signing-worker-1",
                "operation-1",
                reserve_request.request_digest,
                1_200,
            )
            .expect("reservation identity"),
        };
        let (committed, response, changed) =
            apply_signing_worker_wallet_budget_request_v1(Some(reserved_replay), &commit)
                .expect("commit");
        assert!(changed);
        let CloudflareSigningWorkerWalletBudgetResponseV1::Committed { status, .. } = response
        else {
            panic!("commit response branch");
        };
        assert_eq!(status.committed_remaining_uses, 1);

        let (_, replay, changed) =
            apply_signing_worker_wallet_budget_request_v1(Some(committed), &commit)
                .expect("commit replay");
        assert!(!changed);
        let CloudflareSigningWorkerWalletBudgetResponseV1::Committed { status, .. } = replay else {
            panic!("commit replay response branch");
        };
        assert_eq!(status.committed_remaining_uses, 1);
    }
}
