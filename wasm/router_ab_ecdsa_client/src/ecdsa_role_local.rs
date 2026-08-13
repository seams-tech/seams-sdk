use base64ct::{Base64UrlUnpadded, Encoding};
use js_sys::{Array, Object, Reflect, Uint8Array};
use rand_core::OsRng;
use router_ab_ecdsa_client_protocol::EcdsaWalletRecoveryMaterialPossessionChallengeV1;
use router_ab_ecdsa_online::{
    combine_rerandomization_contributions, compute_client_signature_share, ClientPresignMaterial,
    OnlineClientInput,
};
use router_ab_ecdsa_presign::session::{
    derive_presign_pair_context, ClientPresignSession as FixedClientPresignSession,
    PresignSessionError, PresignSessionProgress,
};
use router_ab_ecdsa_presign::{AdditiveKeyShare, PresignOutput};
use router_ab_ecdsa_wire::{CompressedPointBytes, ScalarBytes};
use serde::{Deserialize, Serialize};
use signer_core::ecdsa_role_local_client::command::{
    extract_client_signing_share32_from_ready_state_blob,
    sign_wallet_recovery_material_possession_proof, EcdsaRoleLocalReadyStateBlob,
};
use signer_core::error::{SignerCoreError, SignerCoreErrorCode};
use wasm_bindgen::prelude::*;
use zeroize::{Zeroize, Zeroizing};

const WALLET_RECOVERY_POSSESSION_CHALLENGE_KIND_V1: &str =
    "seams_wallet_recovery_ecdsa_existing_material_possession_challenge_v1";
const WALLET_RECOVERY_POSSESSION_PROOF_KIND_V1: &str = "wallet_recovery_ecdsa_possession_proof_v1";

#[wasm_bindgen]
pub fn prepare_ecdsa_client_bootstrap_v1(input_json: &str) -> Result<String, JsValue> {
    let command: signer_core::commands::PrepareEcdsaClientBootstrapCommandV1 =
        serde_json::from_str(input_json).map_err(js_command_invalid_input_err)?;
    let output = signer_core::commands::prepare_ecdsa_client_bootstrap_command_v1(command)
        .map_err(js_signer_core_err)?;
    serde_json::to_string(&output).map_err(js_command_invalid_input_err)
}

#[wasm_bindgen]
pub fn finalize_ecdsa_client_bootstrap_v1(input_json: &str) -> Result<String, JsValue> {
    let command: signer_core::commands::FinalizeEcdsaClientBootstrapCommandV1 =
        serde_json::from_str(input_json).map_err(js_command_invalid_input_err)?;
    let output = signer_core::commands::finalize_ecdsa_client_bootstrap_command_v1(command)
        .map_err(js_signer_core_err)?;
    serde_json::to_string(&output).map_err(js_command_invalid_input_err)
}

#[wasm_bindgen]
pub struct EcdsaRoleLocalPresignSessionV1 {
    inner: FixedClientPresignSession,
    completed: Option<PresignOutput>,
}

#[wasm_bindgen]
impl EcdsaRoleLocalPresignSessionV1 {
    #[wasm_bindgen(constructor)]
    pub fn new(
        state_blob_b64u: &str,
        group_public_key33: &[u8],
        presign_session_id: &str,
    ) -> Result<Self, JsValue> {
        let ready_state_blob = EcdsaRoleLocalReadyStateBlob {
            state_blob: Base64UrlUnpadded::decode_vec(state_blob_b64u)
                .map_err(|error| JsValue::from_str(&format!("Invalid stateBlobB64u: {error}")))?,
        };
        let signing_share32 = Zeroizing::new(
            extract_client_signing_share32_from_ready_state_blob(&ready_state_blob)
                .map_err(|error| JsValue::from_str(&error.to_string()))?,
        );
        Ok(Self {
            inner: new_presign_session(&signing_share32, group_public_key33, presign_session_id)?,
            completed: None,
        })
    }

    pub fn stage(&self) -> String {
        self.inner.stage().as_str().to_owned()
    }

    pub fn poll(&mut self) -> Result<JsValue, JsValue> {
        progress_to_js(self.inner.poll())
    }

    pub fn message(&mut self, message: &[u8]) -> Result<(), JsValue> {
        self.inner
            .message(message, &mut OsRng)
            .map_err(js_presign_error)
    }

    pub fn start_presign(&mut self) -> Result<(), JsValue> {
        self.inner.start_presign().map_err(js_presign_error)
    }

    pub fn presignature_big_r_33(&mut self) -> Result<Vec<u8>, JsValue> {
        if self.completed.is_none() {
            self.completed = Some(self.inner.take_presignature().map_err(js_presign_error)?);
        }
        Ok(self
            .completed
            .as_ref()
            .expect("completed presignature was just installed")
            .big_r_bytes()
            .as_bytes()
            .to_vec())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn compute_signature_share(
        &mut self,
        group_public_key33: &[u8],
        expected_presign_big_r33: &[u8],
        digest32: &[u8],
        client_rerandomization_contribution32: &[u8],
        signing_worker_rerandomization_contribution32: &[u8],
    ) -> Result<Vec<u8>, JsValue> {
        let output = self
            .completed
            .take()
            .ok_or_else(|| JsValue::from_str("presignature is unavailable"))?;
        compute_online_share(
            output,
            group_public_key33,
            expected_presign_big_r33,
            digest32,
            client_rerandomization_contribution32,
            signing_worker_rerandomization_contribution32,
        )
    }
}

fn compute_online_share(
    output: PresignOutput,
    group_public_key33: &[u8],
    expected_presign_big_r33: &[u8],
    digest32: &[u8],
    client_rerandomization_contribution32: &[u8],
    signing_worker_rerandomization_contribution32: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let (big_r33, k_share32, sigma_share32) = output.into_parts();
    let material = ClientPresignMaterial::from_bytes(
        *big_r33.as_bytes(),
        k_share32.into_bytes(),
        sigma_share32.into_bytes(),
    )
    .map_err(|error| JsValue::from_str(&error.to_string()))?;
    let entropy32 = combine_rerandomization_contributions(
        fixed_bytes(
            client_rerandomization_contribution32,
            "client rerandomization contribution",
        )?,
        fixed_bytes(
            signing_worker_rerandomization_contribution32,
            "signing worker rerandomization contribution",
        )?,
    );
    let input = OnlineClientInput::new(
        fixed_bytes(group_public_key33, "group public key")?,
        fixed_bytes(expected_presign_big_r33, "expected presign R")?,
        fixed_bytes(digest32, "signing digest")?,
        entropy32,
    )
    .map_err(|error| JsValue::from_str(&error.to_string()))?;
    compute_client_signature_share(
        material
            .reserve()
            .commit(input)
            .map_err(|error| JsValue::from_str(&error.to_string()))?,
    )
    .map(|share| share.to_vec())
    .map_err(|error| JsValue::from_str(&error.to_string()))
}

fn fixed_bytes<const N: usize>(bytes: &[u8], label: &str) -> Result<[u8; N], JsValue> {
    bytes
        .try_into()
        .map_err(|_| JsValue::from_str(&format!("{label} must contain {N} bytes")))
}

fn new_presign_session(
    signing_share32: &[u8; 32],
    group_public_key33: &[u8],
    presign_session_id: &str,
) -> Result<FixedClientPresignSession, JsValue> {
    let group_public_key33: [u8; 33] = group_public_key33
        .try_into()
        .map_err(|_| JsValue::from_str("group public key must contain 33 bytes"))?;
    let wallet_public_key = CompressedPointBytes::new(group_public_key33);
    let context = derive_presign_pair_context(wallet_public_key, presign_session_id)
        .map_err(js_presign_error)?;
    let key_share = AdditiveKeyShare::from_bytes(ScalarBytes::new(*signing_share32))
        .map_err(|error| JsValue::from_str(&error.to_string()))?;
    FixedClientPresignSession::new(context, key_share, wallet_public_key, &mut OsRng)
        .map_err(js_presign_error)
}

fn progress_to_js(progress: PresignSessionProgress) -> Result<JsValue, JsValue> {
    let output = Object::new();
    Reflect::set(
        &output,
        &JsValue::from_str("stage"),
        &JsValue::from_str(progress.stage.as_str()),
    )?;
    Reflect::set(
        &output,
        &JsValue::from_str("event"),
        &JsValue::from_str(progress.event.as_str()),
    )?;
    let outgoing = Array::new();
    for message in progress.outgoing {
        outgoing.push(&Uint8Array::from(message.as_slice()));
    }
    Reflect::set(&output, &JsValue::from_str("outgoing"), &outgoing)?;
    Ok(output.into())
}

fn js_presign_error(error: PresignSessionError) -> JsValue {
    JsValue::from_str(&error.to_string())
}

/// Signs a wallet-recovery no-refresh possession challenge from one exact
/// role-local ready-state blob. The client scalar and BIP340 nonce remain in
/// Rust/WASM for the complete operation.
#[wasm_bindgen]
pub fn sign_ecdsa_wallet_recovery_material_possession_proof_v1(
    input_json: &str,
) -> Result<String, JsValue> {
    let input: WalletRecoveryMaterialPossessionProofInputV1 =
        serde_json::from_str(input_json).map_err(js_command_invalid_input_err)?;
    let WalletRecoveryMaterialPossessionProofInputV1 {
        mut state_blob_b64u,
        challenge: challenge_input,
    } = input;
    let challenge = match challenge_input.into_protocol() {
        Ok(challenge) => challenge,
        Err(error) => {
            state_blob_b64u.zeroize();
            return Err(js_signer_core_err(error));
        }
    };
    let state_blob_result = Base64UrlUnpadded::decode_vec(&state_blob_b64u)
        .map_err(|error| js_command_invalid_input_err(format!("Invalid stateBlobB64u: {error}")));
    state_blob_b64u.zeroize();
    let ready_state_blob = EcdsaRoleLocalReadyStateBlob {
        state_blob: state_blob_result?,
    };
    let mut aux_rand32 = [0u8; 32];
    let random_result = getrandom::getrandom(&mut aux_rand32);
    let result = match random_result {
        Ok(()) => sign_wallet_recovery_material_possession_proof(
            &ready_state_blob,
            &challenge,
            &aux_rand32,
        )
        .map_err(js_signer_core_err)
        .and_then(|proof| {
            let challenge_digest = challenge.digest().map_err(|error| {
                js_command_invalid_input_err(format!("Invalid challenge: {error:?}"))
            })?;
            Ok(WalletRecoveryMaterialPossessionProofOutputV1 {
                kind: WALLET_RECOVERY_POSSESSION_PROOF_KIND_V1,
                scheme: proof.scheme.wire_label(),
                signature64_b64u: Base64UrlUnpadded::encode_string(&proof.signature64),
                challenge_digest_b64u: Base64UrlUnpadded::encode_string(&challenge_digest),
                derivation_client_share_public_key33_b64u: Base64UrlUnpadded::encode_string(
                    &challenge.derivation_client_share_public_key33,
                ),
            })
        }),
        Err(error) => Err(js_command_invalid_input_err(format!(
            "Wallet recovery possession worker CSPRNG failed: {error}"
        ))),
    };
    aux_rand32.zeroize();
    result.and_then(|output| serde_json::to_string(&output).map_err(js_command_invalid_input_err))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WalletRecoveryMaterialPossessionProofInputV1 {
    state_blob_b64u: String,
    challenge: WalletRecoveryMaterialPossessionChallengeInputV1,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WalletRecoveryMaterialPossessionChallengeInputV1 {
    kind: String,
    wallet_id: String,
    reservation_id: String,
    replacement_id: String,
    key_set_id: String,
    key_handle: String,
    recorded_key_manifest_digest_b64u: String,
    public_capability_digest_b64u: String,
    authority_ref_digest_b64u: String,
    derivation_client_share_public_key33_b64u: String,
    expected_server_generation: String,
    server_nonce_b64u: String,
    expires_at_ms: u64,
}

impl WalletRecoveryMaterialPossessionChallengeInputV1 {
    fn into_protocol(
        self,
    ) -> Result<EcdsaWalletRecoveryMaterialPossessionChallengeV1, SignerCoreError> {
        if self.kind != WALLET_RECOVERY_POSSESSION_CHALLENGE_KIND_V1 {
            return Err(SignerCoreError::invalid_input(
                "wallet recovery possession challenge kind is invalid",
            ));
        }
        Ok(EcdsaWalletRecoveryMaterialPossessionChallengeV1 {
            wallet_id: require_non_empty(self.wallet_id, "challenge.walletId")?,
            reservation_id: require_non_empty(self.reservation_id, "challenge.reservationId")?,
            replacement_id: require_non_empty(self.replacement_id, "challenge.replacementId")?,
            key_set_id: require_non_empty(self.key_set_id, "challenge.keySetId")?,
            key_handle: require_non_empty(self.key_handle, "challenge.keyHandle")?,
            registered_key_manifest_digest32: decode_fixed_base64(
                &self.recorded_key_manifest_digest_b64u,
                "challenge.recordedKeyManifestDigestB64u",
            )?,
            public_capability_digest32: decode_fixed_base64(
                &self.public_capability_digest_b64u,
                "challenge.publicCapabilityDigestB64u",
            )?,
            authority_ref_digest32: decode_fixed_base64(
                &self.authority_ref_digest_b64u,
                "challenge.authorityRefDigestB64u",
            )?,
            derivation_client_share_public_key33: decode_fixed_base64(
                &self.derivation_client_share_public_key33_b64u,
                "challenge.derivationClientSharePublicKey33B64u",
            )?,
            expected_server_generation: require_non_empty(
                self.expected_server_generation,
                "challenge.expectedServerGeneration",
            )?,
            server_nonce32: decode_fixed_base64(
                &self.server_nonce_b64u,
                "challenge.serverNonceB64u",
            )?,
            expires_at_ms: self.expires_at_ms,
        })
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct WalletRecoveryMaterialPossessionProofOutputV1 {
    kind: &'static str,
    scheme: &'static str,
    signature64_b64u: String,
    challenge_digest_b64u: String,
    derivation_client_share_public_key33_b64u: String,
}

fn require_non_empty(value: String, field_name: &str) -> Result<String, SignerCoreError> {
    let value = value.trim().to_owned();
    if value.is_empty() {
        return Err(SignerCoreError::invalid_input(format!(
            "{field_name} must be non-empty"
        )));
    }
    Ok(value)
}

fn decode_fixed_base64<const N: usize>(
    value: &str,
    field_name: &str,
) -> Result<[u8; N], SignerCoreError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(SignerCoreError::invalid_input(format!(
            "{field_name} must be non-empty"
        )));
    }
    let decoded = Base64UrlUnpadded::decode_vec(trimmed)
        .map_err(|error| SignerCoreError::decode_error(format!("{field_name}: {error}")))?;
    if Base64UrlUnpadded::encode_string(&decoded) != trimmed {
        return Err(SignerCoreError::decode_error(format!(
            "{field_name} must use canonical base64url"
        )));
    }
    if decoded.len() != N {
        return Err(SignerCoreError::invalid_length(format!(
            "{field_name} must decode to {N} bytes"
        )));
    }
    decoded.try_into().map_err(|_| {
        SignerCoreError::invalid_length(format!("{field_name} must decode to {N} bytes"))
    })
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct SignerWorkerErrorWire {
    code: String,
    core_code: String,
    message: String,
}

fn command_core_code_name(code: SignerCoreErrorCode) -> &'static str {
    match code {
        SignerCoreErrorCode::InvalidInput => "InvalidInput",
        SignerCoreErrorCode::InvalidLength => "InvalidLength",
        SignerCoreErrorCode::DecodeError => "DecodeError",
        SignerCoreErrorCode::EncodeError => "EncodeError",
        SignerCoreErrorCode::HkdfError => "HkdfError",
        SignerCoreErrorCode::CryptoError => "CryptoError",
        SignerCoreErrorCode::Utf8Error => "Utf8Error",
        SignerCoreErrorCode::Unsupported => "Unsupported",
        SignerCoreErrorCode::Internal => "Internal",
    }
}

fn command_host_code(code: SignerCoreErrorCode) -> &'static str {
    match code {
        SignerCoreErrorCode::InvalidInput => "SIGNER_INVALID_INPUT",
        SignerCoreErrorCode::InvalidLength => "SIGNER_INVALID_LENGTH",
        SignerCoreErrorCode::DecodeError => "SIGNER_DECODE_ERROR",
        SignerCoreErrorCode::EncodeError => "SIGNER_ENCODE_ERROR",
        SignerCoreErrorCode::HkdfError => "SIGNER_KDF_ERROR",
        SignerCoreErrorCode::CryptoError => "SIGNER_CRYPTO_ERROR",
        SignerCoreErrorCode::Utf8Error => "SIGNER_UTF8_ERROR",
        SignerCoreErrorCode::Unsupported => "SIGNER_UNSUPPORTED",
        SignerCoreErrorCode::Internal => "SIGNER_INTERNAL",
    }
}

fn js_command_error_with_codes(code: &str, core_code: &str, message: String) -> JsValue {
    serde_wasm_bindgen::to_value(&SignerWorkerErrorWire {
        code: code.to_owned(),
        core_code: core_code.to_owned(),
        message,
    })
    .unwrap_or_else(|_| JsValue::from_str("SIGNER_INTERNAL: failed to serialize error"))
}

fn js_signer_core_err(error: SignerCoreError) -> JsValue {
    js_command_error_with_codes(
        command_host_code(error.code),
        command_core_code_name(error.code),
        error.message,
    )
}

fn js_command_invalid_input_err(error: impl core::fmt::Display) -> JsValue {
    js_command_error_with_codes("SIGNER_INVALID_INPUT", "InvalidInput", error.to_string())
}
