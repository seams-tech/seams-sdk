use router_ab_core::{
    RouterAbEd25519YaoActivationAdmissionReceiptV1, RouterAbEd25519YaoActivationResultV1,
    RouterAbEd25519YaoApplicationBindingFactsV1, RouterAbEd25519YaoExportAdmissionReceiptV1,
    RouterAbEd25519YaoExportResultV1,
};
use wasm_bindgen::prelude::*;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    complete_client_activation_v1, complete_client_export_v1, create_client_signing_share_v1,
    prepare_email_otp_client_export_v1, prepare_email_otp_client_recovery_v1,
    prepare_email_otp_client_registration_v1, prepare_passkey_client_export_v1,
    prepare_passkey_client_recovery_v1, prepare_passkey_client_registration_v1,
    ClientActivationEntropyV1, ClientActivationStateV1, ClientExportStateV1,
    ClientSigningRequestV1,
};
use signer_core::near_ed25519_recovery::{
    build_near_ed25519_seed_export_artifact_v1, encode_near_ed25519_public_key_from_seed,
};
use signer_core::near_threshold_ed25519::CommitmentsWire;

/// One-use browser registration session containing only Client-owned secret state.
#[wasm_bindgen]
pub struct WasmClientRegistrationSessionV1 {
    execute_request_json: String,
    state: Option<ClientActivationStateV1>,
}

#[wasm_bindgen]
impl WasmClientRegistrationSessionV1 {
    /// Prepares binding-specific A/B inputs from exact boundary values.
    #[wasm_bindgen(constructor)]
    pub fn new(
        admission_json: &str,
        application_json: &str,
        client_participant_id: u16,
        signing_worker_participant_id: u16,
        passkey_prf_first: &[u8],
        recipient_key_material: &[u8],
        deriver_a_seal_seed: &[u8],
        deriver_b_seal_seed: &[u8],
    ) -> Result<WasmClientRegistrationSessionV1, JsValue> {
        let admission =
            serde_json::from_str::<RouterAbEd25519YaoActivationAdmissionReceiptV1>(admission_json)
                .map_err(js_error)?;
        let application =
            serde_json::from_str::<RouterAbEd25519YaoApplicationBindingFactsV1>(application_json)
                .map_err(js_error)?;
        let passkey_prf_first = Zeroizing::new(parse_32(passkey_prf_first, "passkey PRF.first")?);
        let recipient_key_material =
            Zeroizing::new(parse_32(recipient_key_material, "recipient key material")?);
        let deriver_a_seal_seed =
            Zeroizing::new(parse_32(deriver_a_seal_seed, "Deriver A seal seed")?);
        let deriver_b_seal_seed =
            Zeroizing::new(parse_32(deriver_b_seal_seed, "Deriver B seal seed")?);
        let entropy = ClientActivationEntropyV1::new(
            *recipient_key_material,
            *deriver_a_seal_seed,
            *deriver_b_seal_seed,
        )
        .map_err(js_error)?;
        let prepared = prepare_passkey_client_registration_v1(
            &admission,
            &application,
            [client_participant_id, signing_worker_participant_id],
            *passkey_prf_first,
            entropy,
        )
        .map_err(js_error)?;
        let (execute_request, state) = prepared.into_parts();
        let execute_request_json = serde_json::to_string(&execute_request).map_err(js_error)?;
        Ok(Self {
            execute_request_json,
            state: Some(state),
        })
    }

    /// Returns the canonical opaque Router execution request JSON.
    pub fn execute_request_json(&self) -> String {
        self.execute_request_json.clone()
    }

    /// Opens and verifies a terminal Router result exactly once.
    pub fn complete(&mut self, result_json: &str) -> Result<WasmActivatedClientV1, JsValue> {
        let result = serde_json::from_str::<RouterAbEd25519YaoActivationResultV1>(result_json)
            .map_err(js_error)?;
        let state = self
            .state
            .take()
            .ok_or_else(|| JsValue::from_str("Ed25519 Yao registration session was consumed"))?;
        let activated = complete_client_activation_v1(state, &result).map_err(js_error)?;
        Ok(WasmActivatedClientV1 {
            client_scalar_share: Zeroizing::new(*activated.client_scalar_share()),
            registered_public_key: activated.registered_public_key(),
            state_epoch: activated.state_epoch(),
        })
    }
}

/// One-use browser recovery session containing only Client-owned secret state.
#[wasm_bindgen]
pub struct WasmClientRecoverySessionV1 {
    execute_request_json: String,
    state: Option<ClientActivationStateV1>,
}

#[wasm_bindgen]
impl WasmClientRecoverySessionV1 {
    /// Prepares same-passkey recovery inputs bound to the registered public key.
    #[wasm_bindgen(constructor)]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        admission_json: &str,
        application_json: &str,
        client_participant_id: u16,
        signing_worker_participant_id: u16,
        passkey_prf_first: &[u8],
        expected_registered_public_key: &[u8],
        recipient_key_material: &[u8],
        deriver_a_seal_seed: &[u8],
        deriver_b_seal_seed: &[u8],
    ) -> Result<WasmClientRecoverySessionV1, JsValue> {
        let admission =
            serde_json::from_str::<RouterAbEd25519YaoActivationAdmissionReceiptV1>(admission_json)
                .map_err(js_error)?;
        let application =
            serde_json::from_str::<RouterAbEd25519YaoApplicationBindingFactsV1>(application_json)
                .map_err(js_error)?;
        let passkey_prf_first = Zeroizing::new(parse_32(passkey_prf_first, "passkey PRF.first")?);
        let expected_registered_public_key = parse_32(
            expected_registered_public_key,
            "expected registered public key",
        )?;
        let recipient_key_material =
            Zeroizing::new(parse_32(recipient_key_material, "recipient key material")?);
        let deriver_a_seal_seed =
            Zeroizing::new(parse_32(deriver_a_seal_seed, "Deriver A seal seed")?);
        let deriver_b_seal_seed =
            Zeroizing::new(parse_32(deriver_b_seal_seed, "Deriver B seal seed")?);
        let entropy = ClientActivationEntropyV1::new(
            *recipient_key_material,
            *deriver_a_seal_seed,
            *deriver_b_seal_seed,
        )
        .map_err(js_error)?;
        let prepared = prepare_passkey_client_recovery_v1(
            &admission,
            &application,
            [client_participant_id, signing_worker_participant_id],
            *passkey_prf_first,
            expected_registered_public_key,
            entropy,
        )
        .map_err(js_error)?;
        let (execute_request, state) = prepared.into_parts();
        let execute_request_json = serde_json::to_string(&execute_request).map_err(js_error)?;
        Ok(Self {
            execute_request_json,
            state: Some(state),
        })
    }

    /// Returns the canonical opaque Router execution request JSON.
    pub fn execute_request_json(&self) -> String {
        self.execute_request_json.clone()
    }

    /// Opens and verifies a terminal recovery result exactly once.
    pub fn complete(&mut self, result_json: &str) -> Result<WasmActivatedClientV1, JsValue> {
        let result = serde_json::from_str::<RouterAbEd25519YaoActivationResultV1>(result_json)
            .map_err(js_error)?;
        let state = self
            .state
            .take()
            .ok_or_else(|| JsValue::from_str("Ed25519 Yao recovery session was consumed"))?;
        let activated = complete_client_activation_v1(state, &result).map_err(js_error)?;
        Ok(WasmActivatedClientV1 {
            client_scalar_share: Zeroizing::new(*activated.client_scalar_share()),
            registered_public_key: activated.registered_public_key(),
            state_epoch: activated.state_epoch(),
        })
    }
}

/// One-use Email OTP registration session containing only Client-owned secret state.
#[wasm_bindgen]
pub struct WasmEmailOtpClientRegistrationSessionV1 {
    execute_request_json: String,
    state: Option<ClientActivationStateV1>,
}

#[wasm_bindgen]
impl WasmEmailOtpClientRegistrationSessionV1 {
    /// Prepares binding-specific A/B inputs from an owned Email OTP factor.
    #[wasm_bindgen(constructor)]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        admission_json: &str,
        application_json: &str,
        client_participant_id: u16,
        signing_worker_participant_id: u16,
        email_otp_factor: &[u8],
        recipient_key_material: &[u8],
        deriver_a_seal_seed: &[u8],
        deriver_b_seal_seed: &[u8],
    ) -> Result<WasmEmailOtpClientRegistrationSessionV1, JsValue> {
        let admission =
            serde_json::from_str::<RouterAbEd25519YaoActivationAdmissionReceiptV1>(admission_json)
                .map_err(js_error)?;
        let application =
            serde_json::from_str::<RouterAbEd25519YaoApplicationBindingFactsV1>(application_json)
                .map_err(js_error)?;
        let email_otp_factor =
            Zeroizing::new(parse_32(email_otp_factor, "Email OTP factor secret")?);
        let recipient_key_material =
            Zeroizing::new(parse_32(recipient_key_material, "recipient key material")?);
        let deriver_a_seal_seed =
            Zeroizing::new(parse_32(deriver_a_seal_seed, "Deriver A seal seed")?);
        let deriver_b_seal_seed =
            Zeroizing::new(parse_32(deriver_b_seal_seed, "Deriver B seal seed")?);
        let entropy = ClientActivationEntropyV1::new(
            *recipient_key_material,
            *deriver_a_seal_seed,
            *deriver_b_seal_seed,
        )
        .map_err(js_error)?;
        let prepared = prepare_email_otp_client_registration_v1(
            &admission,
            &application,
            [client_participant_id, signing_worker_participant_id],
            *email_otp_factor,
            entropy,
        )
        .map_err(js_error)?;
        let (execute_request, state) = prepared.into_parts();
        let execute_request_json = serde_json::to_string(&execute_request).map_err(js_error)?;
        Ok(Self {
            execute_request_json,
            state: Some(state),
        })
    }

    /// Returns the canonical opaque Router execution request JSON.
    pub fn execute_request_json(&self) -> String {
        self.execute_request_json.clone()
    }

    /// Opens and verifies a terminal Router result exactly once.
    pub fn complete(&mut self, result_json: &str) -> Result<WasmActivatedClientV1, JsValue> {
        let result = serde_json::from_str::<RouterAbEd25519YaoActivationResultV1>(result_json)
            .map_err(js_error)?;
        let state = self.state.take().ok_or_else(|| {
            JsValue::from_str("Ed25519 Yao Email OTP registration session was consumed")
        })?;
        let activated = complete_client_activation_v1(state, &result).map_err(js_error)?;
        Ok(WasmActivatedClientV1 {
            client_scalar_share: Zeroizing::new(*activated.client_scalar_share()),
            registered_public_key: activated.registered_public_key(),
            state_epoch: activated.state_epoch(),
        })
    }
}

/// One-use Email OTP recovery session containing only Client-owned secret state.
#[wasm_bindgen]
pub struct WasmEmailOtpClientRecoverySessionV1 {
    execute_request_json: String,
    state: Option<ClientActivationStateV1>,
}

#[wasm_bindgen]
impl WasmEmailOtpClientRecoverySessionV1 {
    /// Prepares same-factor recovery inputs bound to the registered public key.
    #[wasm_bindgen(constructor)]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        admission_json: &str,
        application_json: &str,
        client_participant_id: u16,
        signing_worker_participant_id: u16,
        email_otp_factor: &[u8],
        expected_registered_public_key: &[u8],
        recipient_key_material: &[u8],
        deriver_a_seal_seed: &[u8],
        deriver_b_seal_seed: &[u8],
    ) -> Result<WasmEmailOtpClientRecoverySessionV1, JsValue> {
        let admission =
            serde_json::from_str::<RouterAbEd25519YaoActivationAdmissionReceiptV1>(admission_json)
                .map_err(js_error)?;
        let application =
            serde_json::from_str::<RouterAbEd25519YaoApplicationBindingFactsV1>(application_json)
                .map_err(js_error)?;
        let email_otp_factor =
            Zeroizing::new(parse_32(email_otp_factor, "Email OTP factor secret")?);
        let expected_registered_public_key = parse_32(
            expected_registered_public_key,
            "expected registered public key",
        )?;
        let recipient_key_material =
            Zeroizing::new(parse_32(recipient_key_material, "recipient key material")?);
        let deriver_a_seal_seed =
            Zeroizing::new(parse_32(deriver_a_seal_seed, "Deriver A seal seed")?);
        let deriver_b_seal_seed =
            Zeroizing::new(parse_32(deriver_b_seal_seed, "Deriver B seal seed")?);
        let entropy = ClientActivationEntropyV1::new(
            *recipient_key_material,
            *deriver_a_seal_seed,
            *deriver_b_seal_seed,
        )
        .map_err(js_error)?;
        let prepared = prepare_email_otp_client_recovery_v1(
            &admission,
            &application,
            [client_participant_id, signing_worker_participant_id],
            *email_otp_factor,
            expected_registered_public_key,
            entropy,
        )
        .map_err(js_error)?;
        let (execute_request, state) = prepared.into_parts();
        let execute_request_json = serde_json::to_string(&execute_request).map_err(js_error)?;
        Ok(Self {
            execute_request_json,
            state: Some(state),
        })
    }

    /// Returns the canonical opaque Router execution request JSON.
    pub fn execute_request_json(&self) -> String {
        self.execute_request_json.clone()
    }

    /// Opens and verifies a terminal recovery result exactly once.
    pub fn complete(&mut self, result_json: &str) -> Result<WasmActivatedClientV1, JsValue> {
        let result = serde_json::from_str::<RouterAbEd25519YaoActivationResultV1>(result_json)
            .map_err(js_error)?;
        let state = self.state.take().ok_or_else(|| {
            JsValue::from_str("Ed25519 Yao Email OTP recovery session was consumed")
        })?;
        let activated = complete_client_activation_v1(state, &result).map_err(js_error)?;
        Ok(WasmActivatedClientV1 {
            client_scalar_share: Zeroizing::new(*activated.client_scalar_share()),
            registered_public_key: activated.registered_public_key(),
            state_epoch: activated.state_epoch(),
        })
    }
}

/// One-use passkey exact-seed export session containing only Client-owned secret state.
#[wasm_bindgen]
pub struct WasmPasskeyClientExportSessionV1 {
    execute_request_json: String,
    state: Option<ClientExportStateV1>,
}

#[wasm_bindgen]
impl WasmPasskeyClientExportSessionV1 {
    /// Prepares binding-specific export inputs from fresh passkey PRF.first.
    #[wasm_bindgen(constructor)]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        admission_json: &str,
        application_json: &str,
        client_participant_id: u16,
        signing_worker_participant_id: u16,
        passkey_prf_first: &[u8],
        recipient_key_material: &[u8],
        deriver_a_seal_seed: &[u8],
        deriver_b_seal_seed: &[u8],
    ) -> Result<WasmPasskeyClientExportSessionV1, JsValue> {
        let admission =
            serde_json::from_str::<RouterAbEd25519YaoExportAdmissionReceiptV1>(admission_json)
                .map_err(js_error)?;
        let application =
            serde_json::from_str::<RouterAbEd25519YaoApplicationBindingFactsV1>(application_json)
                .map_err(js_error)?;
        let passkey_prf_first = Zeroizing::new(parse_32(passkey_prf_first, "passkey PRF.first")?);
        let recipient_key_material =
            Zeroizing::new(parse_32(recipient_key_material, "recipient key material")?);
        let deriver_a_seal_seed =
            Zeroizing::new(parse_32(deriver_a_seal_seed, "Deriver A seal seed")?);
        let deriver_b_seal_seed =
            Zeroizing::new(parse_32(deriver_b_seal_seed, "Deriver B seal seed")?);
        let entropy = ClientActivationEntropyV1::new(
            *recipient_key_material,
            *deriver_a_seal_seed,
            *deriver_b_seal_seed,
        )
        .map_err(js_error)?;
        let prepared = prepare_passkey_client_export_v1(
            &admission,
            &application,
            [client_participant_id, signing_worker_participant_id],
            *passkey_prf_first,
            entropy,
        )
        .map_err(js_error)?;
        let (execute_request, state) = prepared.into_parts();
        let execute_request_json = serde_json::to_string(&execute_request).map_err(js_error)?;
        Ok(Self {
            execute_request_json,
            state: Some(state),
        })
    }

    /// Returns the canonical opaque Router execution request JSON.
    pub fn execute_request_json(&self) -> String {
        self.execute_request_json.clone()
    }

    /// Opens, reconstructs, and verifies a terminal export exactly once.
    pub fn complete(&mut self, result_json: &str) -> Result<WasmExportedEd25519SeedV1, JsValue> {
        let result = serde_json::from_str::<RouterAbEd25519YaoExportResultV1>(result_json)
            .map_err(js_error)?;
        let state = self
            .state
            .take()
            .ok_or_else(|| JsValue::from_str("Ed25519 Yao export session was consumed"))?;
        let seed = complete_client_export_v1(state, &result).map_err(js_error)?;
        Ok(WasmExportedEd25519SeedV1 {
            seed: Some(Zeroizing::new(seed.into_bytes())),
        })
    }
}

/// One-use Email OTP exact-seed export session containing only Client-owned secret state.
#[wasm_bindgen]
pub struct WasmEmailOtpClientExportSessionV1 {
    execute_request_json: String,
    state: Option<ClientExportStateV1>,
}

#[wasm_bindgen]
impl WasmEmailOtpClientExportSessionV1 {
    /// Prepares binding-specific export inputs from the owned Email OTP factor.
    #[wasm_bindgen(constructor)]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        admission_json: &str,
        application_json: &str,
        client_participant_id: u16,
        signing_worker_participant_id: u16,
        email_otp_factor: &[u8],
        recipient_key_material: &[u8],
        deriver_a_seal_seed: &[u8],
        deriver_b_seal_seed: &[u8],
    ) -> Result<WasmEmailOtpClientExportSessionV1, JsValue> {
        let admission =
            serde_json::from_str::<RouterAbEd25519YaoExportAdmissionReceiptV1>(admission_json)
                .map_err(js_error)?;
        let application =
            serde_json::from_str::<RouterAbEd25519YaoApplicationBindingFactsV1>(application_json)
                .map_err(js_error)?;
        let email_otp_factor =
            Zeroizing::new(parse_32(email_otp_factor, "Email OTP factor secret")?);
        let recipient_key_material =
            Zeroizing::new(parse_32(recipient_key_material, "recipient key material")?);
        let deriver_a_seal_seed =
            Zeroizing::new(parse_32(deriver_a_seal_seed, "Deriver A seal seed")?);
        let deriver_b_seal_seed =
            Zeroizing::new(parse_32(deriver_b_seal_seed, "Deriver B seal seed")?);
        let entropy = ClientActivationEntropyV1::new(
            *recipient_key_material,
            *deriver_a_seal_seed,
            *deriver_b_seal_seed,
        )
        .map_err(js_error)?;
        let prepared = prepare_email_otp_client_export_v1(
            &admission,
            &application,
            [client_participant_id, signing_worker_participant_id],
            *email_otp_factor,
            entropy,
        )
        .map_err(js_error)?;
        let (execute_request, state) = prepared.into_parts();
        let execute_request_json = serde_json::to_string(&execute_request).map_err(js_error)?;
        Ok(Self {
            execute_request_json,
            state: Some(state),
        })
    }

    /// Returns the canonical opaque Router execution request JSON.
    pub fn execute_request_json(&self) -> String {
        self.execute_request_json.clone()
    }

    /// Opens, reconstructs, and verifies a terminal export exactly once.
    pub fn complete(&mut self, result_json: &str) -> Result<WasmExportedEd25519SeedV1, JsValue> {
        let result = serde_json::from_str::<RouterAbEd25519YaoExportResultV1>(result_json)
            .map_err(js_error)?;
        let state = self.state.take().ok_or_else(|| {
            JsValue::from_str("Ed25519 Yao Email OTP export session was consumed")
        })?;
        let seed = complete_client_export_v1(state, &result).map_err(js_error)?;
        Ok(WasmExportedEd25519SeedV1 {
            seed: Some(Zeroizing::new(seed.into_bytes())),
        })
    }
}

/// One-use verified Ed25519 seed returned to the secure export viewer boundary.
#[wasm_bindgen]
pub struct WasmExportedEd25519SeedV1 {
    seed: Option<Zeroizing<[u8; 32]>>,
}

#[wasm_bindgen]
impl WasmExportedEd25519SeedV1 {
    /// Builds the standard verified NEAR export artifact exactly once.
    pub fn take_export_artifact_json(&mut self) -> Result<String, JsValue> {
        let mut seed = self
            .seed
            .take()
            .ok_or_else(|| JsValue::from_str("Ed25519 Yao exported seed was consumed"))?;
        let expected_public_key = encode_near_ed25519_public_key_from_seed(*seed);
        let artifact = build_near_ed25519_seed_export_artifact_v1(*seed, &expected_public_key)
            .map_err(js_error)?;
        seed.zeroize();
        serde_json::to_string(&artifact).map_err(js_error)
    }
}

/// Verified Client activation material retained inside the browser WASM boundary.
#[wasm_bindgen]
pub struct WasmActivatedClientV1 {
    client_scalar_share: Zeroizing<[u8; 32]>,
    registered_public_key: [u8; 32],
    state_epoch: u64,
}

#[wasm_bindgen]
impl WasmActivatedClientV1 {
    /// Returns the verified 32-byte Ed25519 public key.
    pub fn registered_public_key(&self) -> Vec<u8> {
        self.registered_public_key.to_vec()
    }

    /// Returns the activated SigningWorker state epoch.
    pub fn state_epoch(&self) -> u64 {
        self.state_epoch
    }

    /// Creates a signature share while retaining the Client scalar inside WASM.
    #[allow(clippy::too_many_arguments)]
    pub fn create_signing_share(
        &self,
        client_participant_id: u16,
        signing_worker_participant_id: u16,
        admitted_digest: &[u8],
        signing_worker_commitments_json: &str,
        signing_worker_verifying_share: &[u8],
    ) -> Result<WasmClientSigningShareV1, JsValue> {
        build_client_signing_share(
            &self.client_scalar_share,
            &self.registered_public_key,
            client_participant_id,
            signing_worker_participant_id,
            admitted_digest,
            signing_worker_commitments_json,
            signing_worker_verifying_share,
        )
    }
}

/// One Client FROST share created from activated Yao material.
#[wasm_bindgen]
pub struct WasmClientSigningShareV1 {
    client_commitments_json: String,
    client_verifying_share: Vec<u8>,
    client_signature_share_b64u: String,
}

#[wasm_bindgen]
impl WasmClientSigningShareV1 {
    /// Returns the Client FROST commitments as canonical JSON.
    pub fn client_commitments_json(&self) -> String {
        self.client_commitments_json.clone()
    }

    /// Returns the public Client verifying share.
    pub fn client_verifying_share(&self) -> Vec<u8> {
        self.client_verifying_share.clone()
    }

    /// Returns the canonical Client signature share.
    pub fn client_signature_share_b64u(&self) -> String {
        self.client_signature_share_b64u.clone()
    }
}

#[allow(clippy::too_many_arguments)]
fn build_client_signing_share(
    client_scalar_share: &[u8; 32],
    registered_public_key: &[u8; 32],
    client_participant_id: u16,
    signing_worker_participant_id: u16,
    admitted_digest: &[u8],
    signing_worker_commitments_json: &str,
    signing_worker_verifying_share: &[u8],
) -> Result<WasmClientSigningShareV1, JsValue> {
    let admitted_digest = parse_32(admitted_digest, "admitted digest")?;
    let signing_worker_verifying_share = parse_32(
        signing_worker_verifying_share,
        "SigningWorker verifying share",
    )?;
    let signing_worker_commitments =
        serde_json::from_str::<CommitmentsWire>(signing_worker_commitments_json)
            .map_err(js_error)?;
    let output = create_client_signing_share_v1(ClientSigningRequestV1 {
        client_scalar_share,
        registered_public_key,
        participant_ids: [client_participant_id, signing_worker_participant_id],
        admitted_digest: &admitted_digest,
        signing_worker_commitments: &signing_worker_commitments,
        signing_worker_verifying_share: &signing_worker_verifying_share,
    })
    .map_err(js_error)?;
    Ok(WasmClientSigningShareV1 {
        client_commitments_json: serde_json::to_string(output.client_commitments())
            .map_err(js_error)?,
        client_verifying_share: output.client_verifying_share().to_vec(),
        client_signature_share_b64u: output.client_signature_share_b64u().to_owned(),
    })
}

fn parse_32(value: &[u8], label: &str) -> Result<[u8; 32], JsValue> {
    value
        .try_into()
        .map_err(|_| JsValue::from_str(&format!("{label} must contain exactly 32 bytes")))
}

fn js_error(error: impl core::fmt::Display) -> JsValue {
    JsValue::from_str(&error.to_string())
}
