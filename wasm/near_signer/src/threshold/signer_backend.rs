use crate::threshold::participant_ids::{
    normalize_participant_ids, validate_threshold_ed25519_participant_ids_2p,
};
use crate::types::ThresholdSignerConfig;
#[cfg(target_arch = "wasm32")]
use js_sys::Date;
#[cfg(target_arch = "wasm32")]
use std::cell::RefCell;
#[cfg(target_arch = "wasm32")]
use std::collections::BTreeMap;

#[cfg(target_arch = "wasm32")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ThresholdAuthSessionKind {
    Jwt,
    Cookie,
}

#[cfg(target_arch = "wasm32")]
#[derive(Clone, Debug)]
struct CachedThresholdAuthSession {
    kind: ThresholdAuthSessionKind,
    auth_token: Option<String>,
    expires_at_ms: Option<f64>,
}

#[cfg(target_arch = "wasm32")]
thread_local! {
    static THRESHOLD_AUTH_SESSIONS: RefCell<BTreeMap<String, CachedThresholdAuthSession>> =
        RefCell::new(BTreeMap::new());
}

#[cfg(target_arch = "wasm32")]
fn threshold_auth_cache_key(cfg: &ThresholdSignerConfig, near_account_id: &str) -> String {
    let mut out = format!(
        "{}|{}|{}",
        cfg.relayer_url.trim_end_matches('/'),
        cfg.relayer_key_id.trim(),
        near_account_id.trim()
    );

    if let Some(ids) = cfg.participant_ids.as_ref() {
        let mut ids_norm: Vec<u16> = ids.iter().copied().filter(|n| *n > 0).collect();
        ids_norm.sort_unstable();
        ids_norm.dedup();
        if !ids_norm.is_empty() {
            out.push('|');
            out.push_str(
                &ids_norm
                    .iter()
                    .map(|n| n.to_string())
                    .collect::<Vec<_>>()
                    .join(","),
            );
        }
    }

    out
}

#[cfg(target_arch = "wasm32")]
fn normalize_threshold_session_kind(input: Option<&str>) -> ThresholdAuthSessionKind {
    match input.map(|s| s.trim()) {
        Some("cookie") => ThresholdAuthSessionKind::Cookie,
        _ => ThresholdAuthSessionKind::Jwt,
    }
}

#[cfg(target_arch = "wasm32")]
fn trim_nonempty(input: Option<&str>) -> Option<&str> {
    input.map(str::trim).filter(|s| !s.is_empty())
}

#[cfg(target_arch = "wasm32")]
fn is_cached_session_valid(sess: &CachedThresholdAuthSession) -> bool {
    if let Some(expires_at_ms) = sess.expires_at_ms {
        let now = Date::now();
        if now.is_nan() || now >= expires_at_ms {
            return false;
        }
    }
    true
}

#[cfg(target_arch = "wasm32")]
fn get_cached_threshold_auth_session(
    cfg: &ThresholdSignerConfig,
    near_account_id: &str,
) -> Option<CachedThresholdAuthSession> {
    let key = threshold_auth_cache_key(cfg, near_account_id);
    THRESHOLD_AUTH_SESSIONS.with(|m| m.borrow().get(&key).cloned())
}

#[cfg(target_arch = "wasm32")]
fn put_cached_threshold_auth_session(
    cfg: &ThresholdSignerConfig,
    near_account_id: &str,
    session: CachedThresholdAuthSession,
) {
    let key = threshold_auth_cache_key(cfg, near_account_id);
    THRESHOLD_AUTH_SESSIONS.with(|m| {
        m.borrow_mut().insert(key, session);
    });
}

#[cfg(target_arch = "wasm32")]
fn clear_cached_threshold_auth_session(cfg: &ThresholdSignerConfig, near_account_id: &str) {
    let key = threshold_auth_cache_key(cfg, near_account_id);
    THRESHOLD_AUTH_SESSIONS.with(|m| {
        m.borrow_mut().remove(&key);
    });
}

#[cfg(target_arch = "wasm32")]
async fn authorize_mpc_session_id_with_cached_threshold_auth_session_strict(
    transport: &impl super::transport::ThresholdEd25519Transport,
    cfg: &ThresholdSignerConfig,
    near_account_id: &str,
    purpose: &str,
    signing_digest_32: &[u8],
    signing_payload_json: Option<&str>,
    sess: CachedThresholdAuthSession,
) -> Result<String, String> {
    if !is_cached_session_valid(&sess) {
        clear_cached_threshold_auth_session(cfg, near_account_id);
        return Err(
            "threshold-signer: relayer threshold session expired; re-authenticate".to_string(),
        );
    }

    let bearer = match sess.kind {
        ThresholdAuthSessionKind::Jwt => sess.auth_token.as_deref(),
        ThresholdAuthSessionKind::Cookie => None,
    };

    match transport
        .authorize_mpc_session_id_with_threshold_session(
            cfg,
            purpose,
            signing_digest_32,
            signing_payload_json,
            bearer,
        )
        .await
    {
        Ok(id) => Ok(id),
        Err(e) => {
            clear_cached_threshold_auth_session(cfg, near_account_id);
            Err(e)
        }
    }
}

#[cfg(target_arch = "wasm32")]
async fn try_authorize_mpc_session_id_with_cached_threshold_auth_session(
    transport: &impl super::transport::ThresholdEd25519Transport,
    cfg: &ThresholdSignerConfig,
    near_account_id: &str,
    purpose: &str,
    signing_digest_32: &[u8],
    signing_payload_json: Option<&str>,
) -> Option<String> {
    let sess = get_cached_threshold_auth_session(cfg, near_account_id)?;
    if !is_cached_session_valid(&sess) {
        clear_cached_threshold_auth_session(cfg, near_account_id);
        return None;
    }

    let bearer = match sess.kind {
        ThresholdAuthSessionKind::Jwt => sess.auth_token.as_deref(),
        ThresholdAuthSessionKind::Cookie => None,
    };

    match transport
        .authorize_mpc_session_id_with_threshold_session(
            cfg,
            purpose,
            signing_digest_32,
            signing_payload_json,
            bearer,
        )
        .await
    {
        Ok(id) => Some(id),
        Err(_e) => {
            clear_cached_threshold_auth_session(cfg, near_account_id);
            None
        }
    }
}

#[cfg(target_arch = "wasm32")]
async fn resolve_mpc_session_id(
    transport: &impl super::transport::ThresholdEd25519Transport,
    cfg: &ThresholdSignerConfig,
    near_account_id: &str,
    purpose: &str,
    signing_digest_32: &[u8],
    signing_payload_json: Option<&str>,
    credential_json_opt: Option<&str>,
) -> Result<String, String> {
    if let Some(id) = trim_nonempty(cfg.mpc_session_id.as_deref()) {
        return Ok(id.to_string());
    }

    // If the caller provided a threshold session auth token, prefer it
    // over any in-worker cache so session-style authorization works across one-shot signer worker
    // instances.
    if let Some(auth_token) = trim_nonempty(cfg.threshold_session_auth_token.as_deref()) {
        return transport
            .authorize_mpc_session_id_with_threshold_session(
                cfg,
                purpose,
                signing_digest_32,
                signing_payload_json,
                Some(auth_token),
            )
            .await;
    }

    // Prefer a cached relayer session token/cookie when available.
    if let Some(sess) = get_cached_threshold_auth_session(cfg, near_account_id) {
        return authorize_mpc_session_id_with_cached_threshold_auth_session_strict(
            transport,
            cfg,
            near_account_id,
            purpose,
            signing_digest_32,
            signing_payload_json,
            sess,
        )
        .await;
    }

    // No cached session token: mint one if policy JSON is configured, then authorize.
    let policy_json = trim_nonempty(cfg.threshold_session_policy_json.as_deref()).ok_or_else(|| {
        "threshold-signer: missing thresholdSessionAuthToken and no thresholdSessionPolicyJson to mint one".to_string()
    })?;
    let credential_json = credential_json_opt.ok_or_else(|| {
        "threshold-signer: missing credential and no cached threshold session token".to_string()
    })?;

    let kind = normalize_threshold_session_kind(cfg.threshold_session_kind.as_deref());
    let kind_str = match kind {
        ThresholdAuthSessionKind::Cookie => "cookie",
        ThresholdAuthSessionKind::Jwt => "jwt",
    };

    if let Ok(sess) = transport
        .mint_threshold_session(cfg, near_account_id, credential_json, policy_json, kind_str)
        .await
    {
        let expires_at_ms = sess
            .expires_at
            .as_deref()
            .map(Date::parse)
            .filter(|ms| !ms.is_nan());
        let cached = CachedThresholdAuthSession {
            kind,
            auth_token: sess
                .auth_token
                .as_ref()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty()),
            expires_at_ms,
        };
        put_cached_threshold_auth_session(cfg, near_account_id, cached);
    }

    // After session-mint attempt, prefer session authorization if token/cookie is present.
    if let Some(id) = try_authorize_mpc_session_id_with_cached_threshold_auth_session(
        transport,
        cfg,
        near_account_id,
        purpose,
        signing_digest_32,
        signing_payload_json,
    )
    .await
    {
        return Ok(id);
    }

    Err("threshold-signer: missing threshold session token after session mint attempt".to_string())
}

pub struct Ed25519SignerBackend(ThresholdEd25519RelayerSigner);

impl Ed25519SignerBackend {
    pub fn from_threshold_signer_config(
        near_account_id: &str,
        near_public_key_str: &str,
        purpose: &str,
        webauthn_authentication_json: Option<String>,
        authorize_signing_payload_json: Option<String>,
        cfg: &ThresholdSignerConfig,
    ) -> Result<Self, String> {
        Ok(Self(ThresholdEd25519RelayerSigner::new(
            near_account_id,
            near_public_key_str,
            purpose,
            webauthn_authentication_json,
            authorize_signing_payload_json,
            cfg,
        )?))
    }

    pub fn public_key_bytes(&self) -> Result<[u8; 32], String> {
        self.0.public_key_bytes()
    }

    pub async fn sign(&self, message: &[u8]) -> Result<[u8; 64], String> {
        self.0.sign(message).await
    }
}

pub struct ThresholdEd25519RelayerSigner {
    cfg: ThresholdSignerConfig,
    near_account_id: String,
    near_public_key_bytes: [u8; 32],
    client_key_package: frost_ed25519::keys::KeyPackage,
    client_identifier: frost_ed25519::Identifier,
    relayer_identifier: frost_ed25519::Identifier,
    purpose: String,
    webauthn_authentication_json: Option<String>,
    authorize_signing_payload_json: Option<String>,
}

impl ThresholdEd25519RelayerSigner {
    pub fn public_key_bytes(&self) -> Result<[u8; 32], String> {
        Ok(self.near_public_key_bytes)
    }

    pub fn new(
        near_account_id: &str,
        near_public_key_str: &str,
        purpose: &str,
        webauthn_authentication_json: Option<String>,
        authorize_signing_payload_json: Option<String>,
        cfg: &ThresholdSignerConfig,
    ) -> Result<Self, String> {
        let relayer_url = cfg.relayer_url.trim();
        let relayer_key_id = cfg.relayer_key_id.trim();
        let x_client_base_b64u = cfg
            .x_client_base_b64u
            .as_ref()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        if relayer_url.is_empty() {
            return Err("threshold-signer: missing relayerUrl".to_string());
        }
        if relayer_key_id.is_empty() {
            return Err("threshold-signer: missing relayerKeyId".to_string());
        }
        let purpose = purpose.trim();
        if purpose.is_empty() {
            return Err("threshold-signer: missing purpose".to_string());
        }

        let participant_ids_norm = normalize_participant_ids(cfg.participant_ids.as_ref());

        let normalized_mpc_session_id = cfg
            .mpc_session_id
            .as_ref()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        // If we don't have an externally provided mpcSessionId, we must have enough context to
        // authorize using a threshold session token/cookie (session-style).
        //
        // signingPayload is always required so the relayer can recompute digests server-side.
        if normalized_mpc_session_id.is_none()
            && authorize_signing_payload_json
                .as_ref()
                .map(|s| s.trim().is_empty())
                .unwrap_or(true)
        {
            return Err(
                "threshold-signer: missing signingPayload (required to authorize)".to_string(),
            );
        }

        let near_public_key_bytes =
            signer_wasm_core::near_threshold_ed25519::parse_near_public_key_to_bytes(
                near_public_key_str,
            )
            .map_err(|e| e.to_string())?;

        let client_id_opt = cfg.client_participant_id.filter(|n| *n > 0);
        let relayer_id_opt = cfg.relayer_participant_id.filter(|n| *n > 0);
        let (client_id, relayer_id) = validate_threshold_ed25519_participant_ids_2p(
            client_id_opt,
            relayer_id_opt,
            &participant_ids_norm,
        )?;

        let client_identifier: frost_ed25519::Identifier = client_id
            .try_into()
            .map_err(|_| "threshold-signer: invalid client identifier".to_string())?;
        let relayer_identifier: frost_ed25519::Identifier = relayer_id
            .try_into()
            .map_err(|_| "threshold-signer: invalid relayer identifier".to_string())?;

        let x_client_base_b64u = x_client_base_b64u.ok_or_else(|| {
            "threshold-signer: missing xClientBaseB64u; Ed25519 threshold signing now requires single-key HSS base-share reconstruction".to_string()
        })?;
        let key_package =
            crate::threshold::threshold_client_share::key_package_from_client_base_b64u(
                &x_client_base_b64u,
                &near_public_key_bytes,
                client_identifier,
            )?;

        let mut cfg_norm = cfg.clone();
        cfg_norm.mpc_session_id = normalized_mpc_session_id.clone();

        Ok(Self {
            cfg: cfg_norm,
            near_account_id: near_account_id.to_string(),
            near_public_key_bytes,
            client_key_package: key_package,
            client_identifier,
            relayer_identifier,
            purpose: purpose.to_string(),
            webauthn_authentication_json,
            authorize_signing_payload_json,
        })
    }

    pub async fn sign(&self, message: &[u8]) -> Result<[u8; 64], String> {
        let cfg = &self.cfg;
        let near_account_id = self.near_account_id.as_str();
        let purpose = self.purpose.as_str();
        let client_key_package = &self.client_key_package;
        let client_identifier = self.client_identifier;
        let relayer_identifier = self.relayer_identifier;
        let webauthn_authentication_json_opt = &self.webauthn_authentication_json;
        let authorize_signing_payload_json_opt = &self.authorize_signing_payload_json;

        if message.len() != 32 {
            return Err(format!(
                "threshold-signer: signing digest must be 32 bytes, got {}",
                message.len()
            ));
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = cfg;
            let _ = near_account_id;
            let _ = purpose;
            let _ = client_key_package;
            let _ = client_identifier;
            let _ = relayer_identifier;
            let _ = webauthn_authentication_json_opt;
            let _ = authorize_signing_payload_json_opt;
            let _ = message;
            return Err("threshold-signer is only supported in wasm32 builds".to_string());
        }

        #[cfg(target_arch = "wasm32")]
        {
            use super::coordinator;
            use super::transport::HttpThresholdEd25519Transport;

            let transport = HttpThresholdEd25519Transport;

            // Prefer a provided mpcSessionId; otherwise authorize via session/cached WebAuthn.
            let signing_payload_json = authorize_signing_payload_json_opt.as_deref();
            let mpc_session_id = resolve_mpc_session_id(
                &transport,
                cfg,
                near_account_id,
                purpose,
                message,
                signing_payload_json,
                webauthn_authentication_json_opt.as_deref(),
            )
            .await?;

            coordinator::sign_ed25519_2p_v1(
                &transport,
                cfg,
                &mpc_session_id,
                near_account_id,
                message,
                client_key_package,
                client_identifier,
                relayer_identifier,
            )
            .await
        }
    }
}
