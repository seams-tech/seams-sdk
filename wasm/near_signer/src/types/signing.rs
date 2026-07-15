use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ThresholdSignerConfig {
    /// Base URL of the Router API server (e.g. https://router-api.example.com)
    pub relayer_url: String,
    /// Identifies which relayer-held key share to use.
    pub relayer_key_id: String,
    /// Client scalar share produced by Router A/B Yao activation.
    pub client_scalar_share_b64u: String,
    /// FROST participant identifier used for the client share.
    pub client_participant_id: u16,
    /// FROST participant identifier used for the SigningWorker share.
    pub relayer_participant_id: u16,
    /// Exact two-party signer set associated with this threshold key.
    pub participant_ids: Vec<u16>,
    /// Optional short-lived authorization token returned by `/threshold-ed25519/authorize`.
    /// When omitted, the signer worker will call `/threshold-ed25519/authorize` on-demand per signature.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mpc_session_id: Option<String>,
    /// Optional serialized session policy JSON for minting a relayer threshold auth session.
    ///
    /// When present alongside a sessionPolicyDigest32 challenge digest, the signer worker
    /// may call `POST /threshold-ed25519/session` to obtain a short-lived authorization token/cookie.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threshold_session_policy_json: Option<String>,
    /// Preferred session token delivery mechanism for `/threshold-ed25519/session`.
    /// - "jwt" (default): return token in JSON and use Authorization: Bearer on subsequent requests.
    /// - "cookie": set HttpOnly cookie (same-site only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threshold_session_kind: Option<String>,
    /// Optional bearer token returned by `POST /threshold-ed25519/session`.
    /// When present, the signer worker uses it to authenticate `/threshold-ed25519/authorize` requests.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threshold_session_auth_token: Option<String>,
}
