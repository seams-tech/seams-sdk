use base64ct::{Base64UrlUnpadded, Encoding};
use log::debug;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct DeriveThresholdEd25519BootstrapPackageRequest {
    #[wasm_bindgen(getter_with_clone, js_name = "nearAccountId")]
    pub near_account_id: String,
    #[wasm_bindgen(getter_with_clone, js_name = "rpId")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rp_id: Option<String>,
    #[wasm_bindgen(getter_with_clone, js_name = "keyVersion")]
    pub key_version: String,
    #[wasm_bindgen(getter_with_clone, js_name = "sessionId")]
    pub session_id: String,
    #[wasm_bindgen(getter_with_clone, js_name = "prfFirstB64u")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prf_first_b64u: Option<String>,
    #[wasm_bindgen(getter_with_clone, js_name = "recoveryServerShareB64u")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_server_share_b64u: Option<String>,
}

#[wasm_bindgen]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeriveThresholdEd25519BootstrapPackageResult {
    #[wasm_bindgen(getter_with_clone, js_name = "nearAccountId")]
    pub near_account_id: String,
    #[wasm_bindgen(getter_with_clone, js_name = "keyVersion")]
    pub key_version: String,
    #[wasm_bindgen(getter_with_clone, js_name = "recoveryExportCapable")]
    pub recovery_export_capable: bool,
    #[wasm_bindgen(getter_with_clone, js_name = "clientParticipantId")]
    pub client_participant_id: u16,
    #[wasm_bindgen(getter_with_clone, js_name = "relayerParticipantId")]
    pub relayer_participant_id: u16,
    #[wasm_bindgen(getter_with_clone, js_name = "publicKey")]
    pub public_key: String,
    #[wasm_bindgen(getter_with_clone, js_name = "recoveryPublicKey")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_public_key: Option<String>,
    #[wasm_bindgen(getter_with_clone, js_name = "clientVerifyingShareB64u")]
    pub client_verifying_share_b64u: String,
    #[wasm_bindgen(getter_with_clone, js_name = "relayerSigningShareB64u")]
    pub relayer_signing_share_b64u: String,
    #[wasm_bindgen(getter_with_clone, js_name = "relayerVerifyingShareB64u")]
    pub relayer_verifying_share_b64u: String,
}

pub async fn handle_threshold_ed25519_derive_bootstrap_package(
    request: DeriveThresholdEd25519BootstrapPackageRequest,
) -> Result<DeriveThresholdEd25519BootstrapPackageResult, String> {
    let near_account_id = request.near_account_id.trim().to_string();
    if near_account_id.is_empty() {
        return Err("Missing nearAccountId".to_string());
    }
    let key_version = request.key_version.trim().to_string();
    if key_version.is_empty() {
        return Err("Missing keyVersion".to_string());
    }
    let rp_id = request.rp_id.unwrap_or_default().trim().to_string();
    let prf_first_b64u = request.prf_first_b64u.unwrap_or_default().trim().to_string();
    if prf_first_b64u.is_empty() {
        return Err("Missing prfFirstB64u".to_string());
    }

    debug!(
        "[rust wasm]: derive threshold ed25519 Option B bootstrap package for account {} keyVersion {}",
        near_account_id, key_version
    );

    let prf_first = Base64UrlUnpadded::decode_vec(&prf_first_b64u)
        .map_err(|e| format!("Invalid prfFirstB64u: {e}"))?;
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).map_err(|e| format!("Failed to generate seed: {e}"))?;
    let package = signer_platform_web::near_ed25519_recovery::prepare_dual_key_ed25519_bootstrap_package_v1(
        seed,
        &prf_first,
        near_account_id.as_str(),
        key_version.as_str(),
    )
    .map_err(|e| e.to_string())?;
    let recovery_public_key = if rp_id.is_empty() {
        None
    } else {
        let recovery_server_share_b64u = request
            .recovery_server_share_b64u
            .unwrap_or_default()
            .trim()
            .to_string();
        if recovery_server_share_b64u.is_empty() {
            None
        } else {
            let recovery_server_share = Base64UrlUnpadded::decode_vec(&recovery_server_share_b64u)
                .map_err(|e| format!("Invalid recoveryServerShareB64u: {e}"))?;
            let recovery_server_share: [u8; 32] = recovery_server_share
                .as_slice()
                .try_into()
                .map_err(|_| "recoveryServerShareB64u must decode to 32 bytes".to_string())?;
            Some(
                signer_platform_web::near_ed25519_recovery::derive_dual_key_recovery_public_key_v1(
                    &prf_first,
                    recovery_server_share,
                    near_account_id.as_str(),
                    rp_id.as_str(),
                    key_version.as_str(),
                )
                .map_err(|e| e.to_string())?,
            )
        }
    };

    Ok(DeriveThresholdEd25519BootstrapPackageResult {
        near_account_id,
        key_version: package.key_version,
        recovery_export_capable: package.recovery_export_capable,
        client_participant_id: package.client_participant_id,
        relayer_participant_id: package.relayer_participant_id,
        public_key: package.public_key,
        recovery_public_key,
        client_verifying_share_b64u: package.client_verifying_share_b64u,
        relayer_signing_share_b64u: package.relayer_signing_share_b64u,
        relayer_verifying_share_b64u: package.relayer_verifying_share_b64u,
    })
}
